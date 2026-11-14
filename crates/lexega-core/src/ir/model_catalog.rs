// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Model catalog for dbt cross-model schema injection.
//!
//! In dbt, a `{{ ref('stg_orders') }}` reference compiles to a
//! fully-qualified physical table name (e.g.
//! `analytics.staging.stg_orders`). These resolve
//! to upstream **physical base tables** (e.g. `raw.orders`) via
//! `CteColumnSchema.base_tables` before `tables_read` is populated.
//!
//! `ModelCatalog` carries that upstream resolution context in a form
//! the IR lowerer can consume: when `lower_base_table_ref` encounters
//! a table name that resolves in this catalog, it emits
//! [`crate::ir::plan::RelPlan::ModelRef`] with the upstream
//! `base_tables` embedded in
//! [`crate::ir::plan::ResolvedModel::base_tables`] rather than emitting
//! a plain `Scan` against the intermediate model name.
//!
//! This catalog carries the upstream facts — taint labels, lineage,
//! nullability, constraints — that hold at `RelPlan::ModelRef`
//! boundaries.

use std::collections::{BTreeMap, HashMap, HashSet};

use crate::context::node_metadata::{
    ColumnRef, IdentKey, ModelOutputSchema, TableKey, TableRef, TaintLabel,
};
use crate::ir::constraint_types::IrConstraintSet;
use crate::ir::normalize::{keys_read_alike, scoped_folding, NormalizationConfig};

/// Upstream facts for a single dbt model.
///
/// Keyed in [`ModelCatalog`] by the normalized resolved relation name
/// (e.g. `ANALYTICS.STAGING.STG_ORDERS`). When the lowerer encounters
/// a table ref whose canonical form matches this key it emits
/// `RelPlan::ModelRef` with `base_tables` from this entry.
#[derive(Clone, Debug)]
pub struct ModelEntry {
    /// The physical base tables that this model ultimately reads from.
    ///
    /// Corresponds to `CteColumnSchema::base_tables`. May contain
    /// multiple tables when the upstream model itself reads from
    /// multiple base tables (e.g. a model that joins two warehouse
    /// tables).
    ///
    /// Empty when the upstream model's `base_tables` was not resolved
    /// (e.g. the upstream itself reads from another unresolved model).
    pub base_tables: Vec<TableRef>,

    /// Pre-computed taint labels for the upstream model's output
    /// columns, keyed by upstream column name (normalized through
    /// [`IdentKey`]).
    ///
    /// See `lower_base_table_ref`'s `ModelRef`-emit path for how
    /// these are projected onto position-aligned per-output slots
    /// on [`crate::ir::plan::ResolvedModel`].
    pub taint_labels: HashMap<IdentKey, Vec<TaintLabel>>,

    /// Upstream column names whose output is known nullable
    /// (typically from a LEFT JOIN inside the upstream model's
    /// body). Mirrors [`ModelOutputSchema::nullable_columns`]
    /// (sibling field — IR-projected wire-format slot outside
    /// the nested `CteColumnSchema`).
    /// A [`crate::ir::plan::RelPlan::ModelRef`] output `ColumnId` is
    /// nullable when its upstream name appears here.
    pub nullable_columns: HashSet<IdentKey>,

    /// Upstream constraint set — column-level facts the upstream
    /// model's WHERE clauses or projections established (equality
    /// to a constant, range bounds, IS NOT NULL, etc.). Mirrors
    /// [`crate::context::node_metadata::CteColumnSchema::constraint_set`].
    /// Lets cross-model contradiction detection (Q-PROP-CONTRA)
    /// resolve upstream filters through `ref()` boundaries at a
    /// [`crate::ir::plan::RelPlan::ModelRef`].
    pub constraint_set: IrConstraintSet,

    /// Upstream column lineage — per output column name, the
    /// list of upstream source columns it derived from. Mirrors
    /// [`crate::context::node_metadata::CteColumnSchema::column_lineage`].
    /// Lets a downstream column be traced across the model boundary
    /// back to its physical source.
    pub column_lineage: Option<HashMap<IdentKey, Vec<ColumnRef>>>,

    /// Whether the upstream model's body contained any filtering
    /// (WHERE / QUALIFY / HAVING / filter on an ancestor).
    /// Mirrors [`crate::context::node_metadata::CteColumnSchema::has_filter`].
    /// Carried to `RelPlan::ModelRef`, so a query that reads from a
    /// pre-filtered model sees `has_filter = true` even when its own
    /// body has no filter clause.
    pub has_filter: bool,
}

impl ModelEntry {
    /// Build an entry from a projected [`ModelOutputSchema`] — the shared
    /// mapping every schema-driven inserter uses. `taint_labels` /
    /// `nullable_columns` come from the output's siblings; the rest from
    /// its nested `schema`.
    pub fn from_output_schema(output: &ModelOutputSchema) -> Self {
        ModelEntry {
            base_tables: output.schema.base_tables.clone(),
            taint_labels: output.taint_labels.clone(),
            nullable_columns: output.nullable_columns.clone(),
            constraint_set: output.schema.constraint_set.clone(),
            column_lineage: output.schema.column_lineage.clone(),
            has_filter: output.schema.has_filter,
        }
    }
}

/// Cross-model schema catalog for dbt model injection.
///
/// Built once per analysis run from `external_model_schemas` and
/// threaded through the lowering context via
/// `crate::ir::lower::LowerCtx`.  Empty (no model injection) when
/// `external_model_schemas` is `None`, which is the case for all
/// non-dbt analysis paths.
///
/// A catalog [`Self::as_of`] a point of its insertions reads the entries
/// inserted before it, sharing their store with the catalog it was taken
/// from.
#[derive(Clone, Debug, Default)]
pub struct ModelCatalog {
    relations: std::sync::Arc<Relations>,
    /// The insertions this catalog reads: those before this one; all where
    /// `None`.
    horizon: Option<u64>,
}

/// The store of a [`ModelCatalog`].
#[derive(Clone, Debug, Default)]
struct Relations {
    /// Each relation, by its parts each folded, → each entry inserted for
    /// it, in insertion order.
    entries: BTreeMap<TableKey, Vec<Inserted>>,
    /// The keys of the relations of each name, in the order of their first
    /// insertion.
    by_name: HashMap<IdentKey, Vec<TableKey>>,
    /// The folding the keys were made under, from the first key made inside
    /// a dialect scope.
    keyed_under: Option<NormalizationConfig>,
    /// How many entries were inserted.
    inserted: u64,
}

/// One entry inserted for a relation.
#[derive(Clone, Debug)]
struct Inserted {
    /// Its place among the catalog's insertions.
    at: u64,
    /// The relation as written.
    table: TableRef,
    entry: Entry,
}

/// What an insertion holds: an entry, or how to make it.
#[derive(Clone)]
enum Entry {
    Given(ModelEntry),
    /// Made the first time it is read, from the catalog as it stood when it
    /// was inserted; one that makes nothing is not there.
    Deferred(std::sync::Arc<Deferred>),
}

/// An entry made the first time it is read.
struct Deferred {
    made: std::sync::OnceLock<Option<ModelEntry>>,
    make: Box<MakeEntry>,
}

/// How a deferred entry is made, from the catalog as it stood when it was
/// inserted.
type MakeEntry = dyn Fn(&ModelCatalog) -> Option<ModelEntry> + Send + Sync;

impl std::fmt::Debug for Entry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Entry::Given(entry) => f.debug_tuple("Given").field(entry).finish(),
            Entry::Deferred(deferred) => f
                .debug_tuple("Deferred")
                .field(&deferred.made.get())
                .finish(),
        }
    }
}

impl ModelCatalog {
    /// The key of `table`, made under the folding the catalog's keys were
    /// made under; a debug build refuses another.
    fn key(&mut self, table: &TableRef) -> TableKey {
        self.check_folding();
        let relations = self.relations_mut();
        if relations.keyed_under.is_none() {
            relations.keyed_under = scoped_folding();
        }
        TableKey::of(table)
    }

    fn check_folding(&self) {
        debug_assert!(
            keys_read_alike(&self.relations.keyed_under, |folding| *folding),
            "a model catalog was used under a folding its keys were not made under"
        );
    }

    /// The store, this catalog's own to change: copied where another
    /// catalog shares it, without the insertions this one does not read.
    fn relations_mut(&mut self) -> &mut Relations {
        let relations = std::sync::Arc::make_mut(&mut self.relations);
        if let Some(horizon) = self.horizon.take() {
            for inserted in relations.entries.values_mut() {
                inserted.retain(|inserted| inserted.at < horizon);
            }
            relations.entries.retain(|_, inserted| !inserted.is_empty());
            let entries = &relations.entries;
            for keys in relations.by_name.values_mut() {
                keys.retain(|key| entries.contains_key(key));
            }
            relations.by_name.retain(|_, keys| !keys.is_empty());
            relations.inserted = horizon;
        }
        relations
    }

    /// The relation `key` this catalog reads, as written, with its entry:
    /// the last one inserted before its horizon that is there.
    fn read(&self, key: &TableKey) -> Option<(&TableRef, &ModelEntry)> {
        self.relations
            .entries
            .get(key)?
            .iter()
            .rev()
            .filter(|inserted| self.reads(inserted.at))
            .find_map(|inserted| Some((&inserted.table, self.entry_of(inserted)?)))
    }

    /// The entry `inserted` holds, a deferred one made now if it was not
    /// made before; `None` where it makes nothing.
    fn entry_of<'c>(&'c self, inserted: &'c Inserted) -> Option<&'c ModelEntry> {
        match &inserted.entry {
            Entry::Given(entry) => Some(entry),
            Entry::Deferred(deferred) => deferred
                .made
                .get_or_init(|| {
                    (deferred.make)(&Self {
                        relations: std::sync::Arc::clone(&self.relations),
                        horizon: Some(inserted.at),
                    })
                })
                .as_ref(),
        }
    }

    /// Whether this catalog reads the insertion at `at`.
    fn reads(&self, at: u64) -> bool {
        self.horizon.is_none_or(|horizon| at < horizon)
    }

    /// How many entries were inserted into this catalog: the point
    /// [`Self::as_of`] takes for the catalog as it stands now. A deferred
    /// entry counts whether or not it makes an entry.
    pub fn insertions(&self) -> u64 {
        self.horizon.unwrap_or(self.relations.inserted)
    }

    /// This catalog as it stood when `insertions` entries had been inserted
    /// ([`Self::insertions`]): the entries inserted after are not read, and
    /// a relation one of them replaced reads its entry from before. It
    /// shares this catalog's store; inserting into it inserts into a copy.
    pub fn as_of(&self, insertions: u64) -> Self {
        Self {
            relations: std::sync::Arc::clone(&self.relations),
            horizon: Some(insertions.min(self.insertions())),
        }
    }

    /// Build a `ModelCatalog` from the analyzer's `external_model_schemas`.
    ///
    /// Each key in `outputs` is a resolved relation name
    /// (e.g. `"analytics.staging.stg_orders"` or
    /// `"ANALYTICS.STAGING.STG_ORDERS"`), read as its dotted parts
    /// ([`Self::insert`]).
    ///
    /// `nullable_columns` and `taint_labels` are read from
    /// [`ModelOutputSchema`] siblings (they sit outside
    /// the nested [`crate::context::node_metadata::CteColumnSchema`]).
    /// `base_tables`, `constraint_set`, `column_lineage`, and
    /// `has_filter` live on the nested `schema`.
    pub fn from_external_schemas(
        outputs: &std::collections::HashMap<String, ModelOutputSchema>,
    ) -> Self {
        let mut catalog = Self::default();
        for (key, output) in outputs {
            catalog.insert(key, output);
        }
        catalog
    }

    /// Make what a reader of the relation `key` names reads of it, as
    /// [`Self::insert`] reads `key`: its last entry this catalog reads that
    /// is there, each deferred entry it passes over made. A batch caller
    /// makes, before a model is analysed, the entries the model reads.
    pub fn make(&self, key: &str) {
        self.check_folding();
        let _ = self.read(&TableKey::of(&relation_named(key)));
    }

    /// The relation `table` names, as written where it was inserted, with
    /// its entry: the one whose parts are all `table`'s, or, where `table`
    /// names fewer parts, the one relation whose parts include them all;
    /// none where two do.
    pub fn resolve(&self, table: &TableRef) -> Option<(&TableRef, &ModelEntry)> {
        self.check_folding();
        let reader = TableKey::of(table);
        if let Some(read) = self.read(&reader) {
            return Some(read);
        }
        let mut named = self
            .relations
            .by_name
            .get(reader.name())?
            .iter()
            .filter(|key| key.names(&reader))
            .filter_map(|key| self.read(key));
        let (Some(only), None) = (named.next(), named.next()) else {
            return None;
        };
        Some(only)
    }

    /// Returns `true` when nothing was inserted into what this catalog
    /// reads (no model injection context). A deferred entry counts unmade,
    /// so a catalog that is not empty may still resolve no relation.
    pub fn is_empty(&self) -> bool {
        self.insertions() == 0
    }

    /// Iterate every relation, as written, with its entry, in the order of
    /// their folded parts. Used by cross-unit consumers (e.g. the impact
    /// graph) that walk the whole registry. Every deferred entry this
    /// catalog reads is made as the walk reaches it.
    pub fn entries(&self) -> impl Iterator<Item = (&TableRef, &ModelEntry)> + '_ {
        self.relations
            .entries
            .keys()
            .filter_map(|key| self.read(key))
    }

    /// The key of every relation [`Self::entries`] yields, each deferred
    /// entry this catalog reads made to know whether it is there.
    pub fn debug_keys(&self) -> Vec<String> {
        self.relations
            .entries
            .keys()
            .filter(|key| self.read(key).is_some())
            .map(TableKey::to_string)
            .collect()
    }

    /// Insert (or overwrite) one resolved model's schema under the relation
    /// `key` names, its dotted parts read as written. Lets a batch caller
    /// accumulate schemas across files in a single catalog instead of
    /// rebuilding it per file.
    pub fn insert(&mut self, key: &str, output: &ModelOutputSchema) {
        self.insert_at(
            &relation_named(key),
            Entry::Given(ModelEntry::from_output_schema(output)),
        );
    }

    /// Insert (or overwrite) `entry` under the relation `key` names, read
    /// as [`Self::insert`] reads it.
    pub fn insert_named_entry(&mut self, key: &str, entry: ModelEntry) {
        self.insert_at(&relation_named(key), Entry::Given(entry));
    }

    /// Insert, under the relation `key` names as [`Self::insert`] reads it,
    /// an entry made by `make` the first time a reader of the catalog reads
    /// it, from the catalog as it stands now; where `make` makes nothing,
    /// the insertion is not there. A batch caller defers what no model after
    /// it may read.
    pub fn defer(
        &mut self,
        key: &str,
        make: impl Fn(&ModelCatalog) -> Option<ModelEntry> + Send + Sync + 'static,
    ) {
        self.insert_at(
            &relation_named(key),
            Entry::Deferred(std::sync::Arc::new(Deferred {
                made: std::sync::OnceLock::new(),
                make: Box::new(make),
            })),
        );
    }

    /// Insert (or overwrite) a pre-built [`ModelEntry`] for the relation
    /// `table` names, each of its parts as written.
    ///
    /// The dbt-free counterpart to [`Self::insert`]: callers that
    /// synthesize an upstream schema directly (e.g. a producer registry
    /// built from a repo's own `CREATE TABLE` / CTAS statements) supply a
    /// `ModelEntry` without routing through the dbt-specific
    /// [`ModelOutputSchema`].
    pub fn insert_entry(&mut self, table: &TableRef, entry: ModelEntry) {
        self.insert_at(table, Entry::Given(entry));
    }

    /// Insert `entry` for the relation `table` names, each of its parts as
    /// written.
    fn insert_at(&mut self, table: &TableRef, entry: Entry) {
        let key = self.key(table);
        let relations = self.relations_mut();
        if !relations.entries.contains_key(&key) {
            relations
                .by_name
                .entry(key.name().clone())
                .or_default()
                .push(key.clone());
        }
        let at = relations.inserted;
        relations.inserted += 1;
        let inserted = Inserted {
            at,
            table: table.clone(),
            entry,
        };
        // A replaced entry stays: a catalog `as_of` an earlier point reads it.
        relations.entries.entry(key).or_default().push(inserted);
    }
}

/// The relation `key` names, its dotted parts read as written.
fn relation_named(key: &str) -> TableRef {
    let mut parts = crate::ir::lower_ddl::split_qualified(key);
    let name = parts.pop().unwrap_or_default();
    let mut table = TableRef::new(name);
    table.schema = parts.pop();
    table.db = parts.pop();
    table.server = (!parts.is_empty()).then(|| parts.join("."));
    table
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::normalize::set_normalization_dialect;
    use std::panic::{catch_unwind, AssertUnwindSafe};

    fn entry() -> ModelEntry {
        ModelEntry {
            base_tables: Vec::new(),
            taint_labels: HashMap::new(),
            nullable_columns: HashSet::new(),
            constraint_set: IrConstraintSet::new(),
            column_lineage: None,
            has_filter: false,
        }
    }

    /// The table `[[db.]schema.]name` names, each part as written.
    fn table(parts: &[&str]) -> TableRef {
        let (name, qualifiers) = parts.split_last().expect("a name");
        let mut table = TableRef::new(name.to_string());
        let mut qualifiers = qualifiers.iter().rev();
        table.schema = qualifiers.next().map(|part| part.to_string());
        table.db = qualifiers.next().map(|part| part.to_string());
        table
    }

    /// A catalog of one entry per relation of `relations`, each entry's
    /// filter flag telling it apart by its index's parity.
    fn catalog_of(relations: &[&[&str]]) -> ModelCatalog {
        let mut catalog = ModelCatalog::default();
        for (at, parts) in relations.iter().enumerate() {
            let mut marked = entry();
            marked.has_filter = at % 2 == 1;
            catalog.insert_entry(&table(parts), marked);
        }
        catalog
    }

    #[test]
    fn a_model_catalog_is_read_under_the_folding_its_keys_were_made_under() {
        let mut catalog = ModelCatalog::default();
        let postgres = set_normalization_dialect("postgresql");
        catalog.insert_entry(&table(&["prod", "a", "t"]), entry());
        assert!(catalog.resolve(&table(&["PROD", "A", "T"])).is_some());
        drop(postgres);

        let _snowflake = set_normalization_dialect("snowflake");
        let read = catch_unwind(AssertUnwindSafe(|| {
            catalog.resolve(&table(&["prod", "a", "t"])).is_some()
        }));
        let written = catch_unwind(AssertUnwindSafe(|| {
            catalog
                .clone()
                .insert_entry(&table(&["prod", "a", "u"]), entry())
        }));
        assert_eq!(
            (read.is_err(), written.is_err()),
            (cfg!(debug_assertions), cfg!(debug_assertions))
        );
    }

    #[test]
    fn a_reader_of_fewer_parts_resolves_to_the_one_relation_its_parts_name() {
        let _snowflake = set_normalization_dialect("snowflake");
        let filtered = |catalog: &ModelCatalog, parts: &[&str]| {
            catalog
                .resolve(&table(parts))
                .map(|(_, entry)| entry.has_filter)
        };
        let one = catalog_of(&[&["prod", "a", "x"], &["prod", "a", "t"]]);
        assert_eq!(filtered(&one, &["t"]), Some(true));
        assert_eq!(filtered(&one, &["A", "T"]), Some(true));
        assert_eq!(filtered(&one, &["b", "t"]), None);
        assert_eq!(filtered(&one, &["other", "a", "t"]), None);

        // Two relations the parts name: none.
        let two = catalog_of(&[&["prod", "a", "t"], &["prod", "b", "t"]]);
        assert_eq!(filtered(&two, &["t"]), None);
        assert_eq!(filtered(&two, &["b", "t"]), Some(true));
        // A relation of exactly the reader's parts is the one it names.
        let exact = catalog_of(&[&["t"], &["prod", "a", "t"]]);
        assert_eq!(filtered(&exact, &["t"]), Some(false));
    }

    #[test]
    fn a_catalog_as_of_a_point_reads_the_entries_inserted_before_it() {
        let _snowflake = set_normalization_dialect("snowflake");
        let filtered = |catalog: &ModelCatalog, parts: &[&str]| {
            catalog
                .resolve(&table(parts))
                .map(|(_, entry)| entry.has_filter)
        };
        // `t` (no filter), `u` (filter), then `t` replaced (filter).
        let mut catalog = catalog_of(&[&["prod", "a", "t"], &["prod", "a", "u"]]);
        let mut replaced = entry();
        replaced.has_filter = true;
        catalog.insert_entry(&table(&["prod", "a", "t"]), replaced);
        assert_eq!(catalog.insertions(), 3);

        let before = catalog.as_of(1);
        assert!(std::sync::Arc::ptr_eq(
            &before.relations,
            &catalog.relations
        ));
        assert_eq!(filtered(&before, &["t"]), Some(false));
        assert_eq!(filtered(&before, &["u"]), None);
        assert_eq!(before.debug_keys().len(), 1);
        assert_eq!(filtered(&catalog.as_of(2), &["t"]), Some(false));
        assert_eq!(filtered(&catalog.as_of(3), &["t"]), Some(true));
        assert_eq!(filtered(&catalog, &["t"]), Some(true));
        assert!(catalog.as_of(0).is_empty());
        assert_eq!(catalog.as_of(9).insertions(), 3);

        // Inserting into a view inserts into a copy of the catalog as it
        // stood, without the entries inserted after.
        let mut copy = catalog.as_of(1);
        copy.insert_entry(&table(&["prod", "a", "v"]), entry());
        assert!(!std::sync::Arc::ptr_eq(&copy.relations, &catalog.relations));
        assert_eq!(copy.insertions(), 2);
        assert_eq!(filtered(&copy, &["t"]), Some(false));
        assert_eq!(filtered(&copy, &["u"]), None);
        assert_eq!(filtered(&copy, &["v"]), Some(false));
        assert_eq!(filtered(&catalog, &["v"]), None);
    }

    // A deferred entry is made the first time it is read, once, from the
    // catalog as it stood when it was inserted; one never read is never
    // made.
    #[test]
    fn a_deferred_entry_is_made_once_when_first_read_from_the_catalog_before_it() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        let _snowflake = set_normalization_dialect("snowflake");
        let made = Arc::new(AtomicUsize::new(0));
        let mut catalog = catalog_of(&[&["prod", "a", "t"]]);
        let counter = Arc::clone(&made);
        catalog.defer("prod.a.u", move |before: &ModelCatalog| {
            counter.fetch_add(1, Ordering::SeqCst);
            // Reads what was inserted before it, and nothing after.
            let mut made = entry();
            made.has_filter = before.resolve(&table(&["t"])).is_some()
                && before.resolve(&table(&["v"])).is_none();
            Some(made)
        });
        let unread = Arc::new(AtomicUsize::new(0));
        let never = Arc::clone(&unread);
        catalog.defer("prod.a.w", move |_: &ModelCatalog| {
            never.fetch_add(1, Ordering::SeqCst);
            Some(entry())
        });
        catalog.insert_entry(&table(&["prod", "a", "v"]), entry());
        assert_eq!(made.load(Ordering::SeqCst), 0);
        for _ in 0..2 {
            let read = catalog.resolve(&table(&["u"])).map(|(_, e)| e.has_filter);
            assert_eq!(read, Some(true));
        }
        assert_eq!(made.load(Ordering::SeqCst), 1);
        assert_eq!(unread.load(Ordering::SeqCst), 0);
        assert_eq!(catalog.insertions(), 4);
    }

    // Making a relation's entries makes what a reader of it reads, once: a
    // reader after reads them made.
    #[test]
    fn making_a_relations_entries_makes_what_a_reader_reads() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        let _snowflake = set_normalization_dialect("snowflake");
        let made = Arc::new(AtomicUsize::new(0));
        let mut catalog = ModelCatalog::default();
        for filter in [false, true] {
            let counter = Arc::clone(&made);
            catalog.defer("prod.a.t", move |_: &ModelCatalog| {
                counter.fetch_add(1, Ordering::SeqCst);
                let mut made = entry();
                made.has_filter = filter;
                Some(made)
            });
        }
        catalog.make("prod.a.u");
        assert_eq!(made.load(Ordering::SeqCst), 0);
        catalog.make("PROD.A.T");
        assert_eq!(made.load(Ordering::SeqCst), 1);
        let read = catalog.resolve(&table(&["t"])).map(|(_, e)| e.has_filter);
        assert_eq!(read, Some(true));
        assert_eq!(made.load(Ordering::SeqCst), 1);
    }

    // A deferred entry that makes nothing is not there: the relation reads
    // the entry inserted for it before, and a reader of fewer parts reads
    // the one other relation its parts name.
    #[test]
    fn a_deferred_entry_that_makes_nothing_is_not_there() {
        let _snowflake = set_normalization_dialect("snowflake");
        let filtered = |catalog: &ModelCatalog, parts: &[&str]| {
            catalog
                .resolve(&table(parts))
                .map(|(_, entry)| entry.has_filter)
        };
        // `prod.a.t` (no filter), `prod.b.t` (filter).
        let mut catalog = catalog_of(&[&["prod", "a", "t"], &["prod", "b", "t"]]);
        assert_eq!(filtered(&catalog, &["t"]), None);
        catalog.defer("prod.b.t", |_: &ModelCatalog| None);
        assert_eq!(filtered(&catalog, &["b", "t"]), Some(true));
        catalog.defer("prod.c.t", |_: &ModelCatalog| None);
        assert_eq!(filtered(&catalog, &["c", "t"]), None);
        assert_eq!(filtered(&catalog, &["t"]), None);

        let mut one = catalog_of(&[&["prod", "a", "x"]]);
        one.defer("prod.b.x", |_: &ModelCatalog| None);
        assert_eq!(filtered(&one, &["x"]), Some(false));
        assert_eq!(one.debug_keys().len(), 1);
        assert_eq!(one.entries().count(), 1);
    }

    // Counting a catalog's insertions makes no deferred entry, so one that
    // makes nothing counts; walking every relation makes each.
    #[test]
    fn a_deferred_entry_counts_unmade_and_a_walk_of_every_relation_makes_it() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        let _snowflake = set_normalization_dialect("snowflake");
        let made = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&made);
        let mut catalog = ModelCatalog::default();
        catalog.defer("prod.a.t", move |_: &ModelCatalog| {
            counter.fetch_add(1, Ordering::SeqCst);
            None
        });
        assert_eq!((catalog.is_empty(), catalog.insertions()), (false, 1));
        assert_eq!(made.load(Ordering::SeqCst), 0);
        assert_eq!(catalog.entries().count(), 0);
        assert_eq!(made.load(Ordering::SeqCst), 1);
        assert!(catalog.debug_keys().is_empty());
        assert!(catalog.resolve(&table(&["t"])).is_none());
        assert_eq!(made.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn quoted_parts_that_differ_in_case_are_two_relations() {
        for dialect in ["snowflake", "postgresql", "mysql", "bigquery"] {
            let _folding = set_normalization_dialect(dialect);
            let quote = |name: &str| match dialect {
                "mysql" | "bigquery" => format!("`{name}`"),
                _ => format!("\"{name}\""),
            };
            let (mixed, upper) = (quote("MyT"), quote("MYT"));
            let catalog = catalog_of(&[&["prod", "a", &mixed], &["prod", "a", &upper]]);
            assert_eq!(catalog.debug_keys().len(), 2, "{dialect}");
            for (name, filter) in [(&mixed, false), (&upper, true)] {
                assert_eq!(
                    catalog
                        .resolve(&table(&["prod", "a", name]))
                        .map(|(_, entry)| entry.has_filter),
                    Some(filter),
                    "{dialect} {name}"
                );
            }
        }
        // T-SQL compares a quoted part in any case: the two are one.
        let _folding = set_normalization_dialect("mssql");
        let catalog = catalog_of(&[&["prod", "a", "\"MyT\""], &["prod", "a", "\"MYT\""]]);
        assert_eq!(catalog.debug_keys().len(), 1);
    }
}
