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

use std::collections::{HashMap, HashSet};

use crate::context::node_metadata::{ColumnRef, IdentKey, ModelOutputSchema, TableRef, TaintLabel};
use crate::ir::constraint_types::IrConstraintSet;

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
    /// Consumed by the IR `has_any_filter` query at
    /// `RelPlan::ModelRef` boundaries so downstream queries that
    /// read from a pre-filtered model see `has_filter = true` even
    /// when their own body has no filter clause.
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
#[derive(Clone, Debug, Default)]
pub struct ModelCatalog {
    /// Normalized relation name (via [`IdentKey`]) → upstream facts.
    entries: std::collections::HashMap<IdentKey, ModelEntry>,
}

impl ModelCatalog {
    /// Build a `ModelCatalog` from the analyzer's `external_model_schemas`.
    ///
    /// Each key in `outputs` is a resolved relation name
    /// (e.g. `"analytics.staging.stg_orders"` or
    /// `"ANALYTICS.STAGING.STG_ORDERS"`) and is normalized via
    /// [`IdentKey::new`] so lookups are case-insensitive and consistent
    /// with the rest of the analyzer's identifier handling.
    ///
    /// `nullable_columns` and `taint_labels` are read from
    /// [`ModelOutputSchema`] siblings (they sit outside
    /// the nested [`crate::context::node_metadata::CteColumnSchema`]).
    /// `base_tables`, `constraint_set`, `column_lineage`, and
    /// `has_filter` live on the nested `schema`.
    pub fn from_external_schemas(
        outputs: &std::collections::HashMap<String, ModelOutputSchema>,
    ) -> Self {
        let mut entries = std::collections::HashMap::with_capacity(outputs.len());
        for (key, output) in outputs {
            entries.insert(IdentKey::new(key), ModelEntry::from_output_schema(output));
        }
        Self { entries }
    }

    /// Look up a resolved model entry by normalized key.
    pub fn get(&self, key: &IdentKey) -> Option<&ModelEntry> {
        self.entries.get(key)
    }

    /// Returns `true` when no entries are present (no model injection
    /// context).
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Iterate every `(resolved relation key, entry)`. Used by cross-unit
    /// consumers (e.g. the impact graph) that walk the whole registry.
    pub fn entries(&self) -> impl Iterator<Item = (&IdentKey, &ModelEntry)> + '_ {
        self.entries.iter()
    }

    pub fn debug_keys(&self) -> Vec<String> {
        self.entries
            .keys()
            .map(|k| k.as_str().to_string())
            .collect()
    }

    /// Insert (or overwrite) one resolved model's schema, keyed identically to
    /// [`Self::from_external_schemas`]. Lets a batch caller accumulate schemas
    /// across files in a single catalog instead of rebuilding it per file.
    pub fn insert(&mut self, key: &str, output: &ModelOutputSchema) {
        self.entries
            .insert(IdentKey::new(key), ModelEntry::from_output_schema(output));
    }

    /// Insert (or overwrite) a pre-built [`ModelEntry`] under `key`.
    ///
    /// The dbt-free counterpart to [`Self::insert`]: callers that
    /// synthesize an upstream schema directly (e.g. a producer registry
    /// built from a repo's own `CREATE TABLE` / CTAS statements) supply a
    /// `ModelEntry` without routing through the dbt-specific
    /// [`ModelOutputSchema`]. `key` is the resolved relation name,
    /// normalized via [`IdentKey::new`] exactly as the other inserters.
    pub fn insert_entry(&mut self, key: &str, entry: ModelEntry) {
        self.entries.insert(IdentKey::new(key), entry);
    }
}
