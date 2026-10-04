// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Catalog context for IR-keyed analyses.
//!
//! Consumers of the plan key their data by [`ColumnId`]. The
//! authoritative catalog snapshot in [`crate::catalog::CatalogIndex`]
//! is keyed by `CatalogIdent` strings. This module bridges the two
//! domains with a trait-based sidecar: a projection of catalog data
//! into the IR's `ColumnId` space.
//!
//! # Scope (this file)
//!
//! - [`CatalogContext`] trait — the consumer-agnostic surface.
//! - [`EmptyCatalogContext`] — zero-state default; every method
//!   returns `None`. The catalog-less path every IR analysis is
//!   expected to exercise.
//! - [`IndexedCatalogContext`] — buildable sidecar keyed by
//!   [`TableRef`] and [`ColumnId`]. Populated externally (e.g. at
//!   lowering time) via the `insert_*` builder methods.

use std::collections::HashMap;

use crate::context::node_metadata::{IdentKey, TableRef};

use super::column::ColumnId;
use super::scalar::ScalarExpr;

// ────────────────────────────────────────────────────────────────────────
// Lookup result types
// ────────────────────────────────────────────────────────────────────────

/// Ordered + name-keyed column list for a single catalog-resolved
/// table.
///
/// `by_position` matches the source catalog's column order (so
/// positional operations like `INSERT star` / `UPDATE SET *` pair
/// correctly against a source schema of the same arity).
/// `by_name` keys are [`IdentKey`] — normalized identifiers.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TableColumns {
    pub by_position: Vec<ColumnId>,
    pub by_name: HashMap<IdentKey, ColumnId>,
}

impl TableColumns {
    pub fn new() -> Self {
        Self::default()
    }

    /// Convenience constructor: build both maps from a paired list.
    /// Positions and names must align (same length, parallel order).
    pub fn from_pairs(pairs: Vec<(IdentKey, ColumnId)>) -> Self {
        let mut by_position = Vec::with_capacity(pairs.len());
        let mut by_name = HashMap::new();
        for (name, id) in pairs {
            by_position.push(id);
            by_name.insert(name, id);
        }
        Self {
            by_position,
            by_name,
        }
    }

    pub fn len(&self) -> usize {
        self.by_position.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_position.is_empty()
    }
}

/// Metadata for a single catalog-resolved column, projected from
/// [`crate::catalog::CatalogColumn`] and associated catalog records
/// into IR-keyed form.
///
/// Fields are additive: each analysis that needs a new fact
/// extends this struct. The set below seeds nullability,
/// constraints, and taint / policy.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ColumnMetadata {
    /// Tri-state nullability from the catalog.
    ///
    /// - `Some(true)` — catalog says the column is nullable.
    /// - `Some(false)` — catalog says the column is NOT NULL.
    /// - `None` — catalog has no opinion (external table, unresolved
    ///   view, snapshot without nullability info).
    ///
    /// **Consumer rule (nullability):** `None` is treated the same as
    /// `Some(false)`, minimizing false positives when the catalog
    /// cannot vouch.
    pub nullable: Option<bool>,

    /// Optional default-value expression (scaffold for nullability /
    /// constraints). Present but un-populated; consumers
    /// treat `None` as "no default".
    pub default: Option<DefaultExpr>,

    /// Column-level constraints. Populated by the lowerer from
    /// `CatalogTable.constraints` for `PrimaryKey` / `Unique` /
    /// `ForeignKey` entries that mention the column.
    pub constraints: ColumnConstraints,

    /// Tags attached to the column (taint seed).
    pub tags: Vec<TagRef>,

    /// Column-level governance policy (scaffold; un-populated).
    pub policy: Option<PolicyRef>,

    /// Catalog-declared data type, raw display form (e.g.
    /// `"TIMESTAMP_NTZ(9)"`, `"VARCHAR(255)"`). `None` when the
    /// catalog snapshot lacks type information for the column.
    /// A column is classified as temporal or high-cardinality on this
    /// string instead of consulting the upstream `CatalogIndex` at
    /// signal-emit time.
    pub data_type: Option<String>,

    /// Foreign-key target this column declares. `None` when the
    /// catalog has no declared FK from this column. Drives
    /// `Q-JOIN-FKVIOL-CENH`: a join on `(A.x = B.y)` matches an FK
    /// iff `A.x.fk_target == Some(B, y)` (or the symmetric pair).
    pub fk_target: Option<FkTarget>,
}

/// Foreign-key edge declared on a column. The target is identified
/// by the IR-keyed [`TableRef`] (matches scan-time keys) and the
/// referenced column's source-as-written name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FkTarget {
    pub ref_table: TableRef,
    pub ref_column_name: IdentKey,
}

/// Placeholder for a default-value expression. Carries only
/// the raw display text, not a typed [`ScalarExpr`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DefaultExpr {
    pub display: String,
}

/// Placeholder for column-level constraints. Extended
/// additively as constraint propagation lands.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ColumnConstraints {
    pub is_primary_key: bool,
    pub is_unique: bool,
    /// `true` iff the catalog declares a PRIMARY KEY or UNIQUE
    /// constraint whose column list is EXACTLY this column (arity 1).
    /// Distinct from `is_primary_key` / `is_unique`, which are true
    /// when the column is a member of any PK/UNIQUE constraint
    /// regardless of arity. Consumed by fan-out / row-multiplication
    /// detection (`join_pair_unique_key_backed`): a column that
    /// participates only in a composite key does NOT individually
    /// back a unique row identity, so a join on that single column
    /// can still fan out.
    pub is_solo_unique_key: bool,
    /// Display-only check predicate text, not a typed predicate.
    pub check: Option<String>,
}

/// Placeholder for a catalog tag reference (taint seed).
/// Deliberately string-typed.
///
/// `PartialOrd` / `Ord` / `Hash` are derived so [`TagRef`] can be
/// used as a `BTreeSet` key inside taint analysis. Ordering is structural on
/// `(qualified_name, value)`; two refs with the same qualified name
/// and same value compare equal regardless of the column they were
/// attached to.
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TagRef {
    pub qualified_name: String,
    pub value: Option<String>,
}

/// Placeholder for a governance policy reference.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PolicyRef {
    pub qualified_name: String,
    pub kind: PolicyKind,
}

/// Policy kind mirrors [`crate::catalog::CatalogPolicyKind`] in
/// IR-neutral form.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PolicyKind {
    Masking,
    RowAccess,
    Aggregation,
    Projection,
    #[default]
    Unknown,
}

// ────────────────────────────────────────────────────────────────────────
// CatalogContext trait
// ────────────────────────────────────────────────────────────────────────

/// Catalog view projected into the IR's [`ColumnId`] domain.
///
/// All IR-keyed analyses consume this trait. The authoritative
/// loader [`crate::catalog::CatalogIndex`] sits beneath — a
/// [`CatalogContext`] impl is a view over it (or an empty stub).
///
/// # Contract
///
/// - Every method returns an `Option` so a missing catalog binding is
///   a lookup miss, not an error. Callers (analyses) decide whether to
///   treat absence as "silently empty" (permissive
///   mode) or as an opaque-reason marker (strict mode).
/// - Implementations must not panic on unknown keys.
/// - Implementations are expected to be cheap to share (borrowed or
///   `Arc`-wrapped behind the scenes).
pub trait CatalogContext {
    /// Resolve a `TableRef` to its ordered + name-keyed column list.
    ///
    /// Returns `None` when the table is unknown to this context.
    fn resolve_table_columns(&self, table: &TableRef) -> Option<&TableColumns>;

    /// Resolve a qualified column name against a known table.
    ///
    /// Default impl delegates to [`Self::resolve_table_columns`] so
    /// implementations only need to override when they have a more
    /// direct lookup path.
    fn resolve_column_by_name(&self, table: &TableRef, name: &IdentKey) -> Option<ColumnId> {
        self.resolve_table_columns(table)
            .and_then(|cols| cols.by_name.get(name).copied())
    }

    /// Resolve a table-valued function call to its declared output
    /// columns.
    ///
    /// Scaffold for TVF typed-return support.
    /// Default impl returns `None`; implementations populate this when
    /// a catalog exposes typed TVF signatures (dbt macros, UDFs with
    /// declared return schemas). Returning `None` means "TVF outputs
    /// are opaque / fresh sources" — the current IR lineage default.
    fn resolve_tvf_columns(&self, _call: &ScalarExpr) -> Option<&TableColumns> {
        None
    }

    /// Column-level metadata for a resolved [`ColumnId`].
    ///
    /// Returns `None` for ids not sourced from catalog (projection
    /// outputs, aggregates, derived-table outputs, CTE outputs, etc.).
    fn column_metadata(&self, id: ColumnId) -> Option<&ColumnMetadata>;

    /// Table-level tags attached to `table`.
    ///
    /// Table-level tags apply to every column of the table (the
    /// "inherited by all columns" rule). Taint analysis consumes
    /// these at [`super::plan::RelPlan::Scan`] and seeds them onto
    /// every scan output column.
    ///
    /// Default returns an empty slice. Implementations that carry
    /// table-level tags override this. Returning `&[]` is
    /// indistinguishable from "no catalog opinion" — consistent with
    /// the `None` / `Some(false)` convention on [`ColumnMetadata`].
    fn resolve_table_tags(&self, _table: &TableRef) -> &[TagRef] {
        &[]
    }
}

// ────────────────────────────────────────────────────────────────────────
// EmptyCatalogContext — zero-state default
// ────────────────────────────────────────────────────────────────────────

/// No-catalog implementation. Every method returns `None`.
///
/// When callers run without a catalog attached,
/// lineage/nullability/constraint/taint analyses exercise the same
/// code path they would with a populated context, and the absence of
/// catalog data means "no catalog-sourced signals."
#[derive(Debug, Clone, Copy, Default)]
pub struct EmptyCatalogContext;

impl CatalogContext for EmptyCatalogContext {
    fn resolve_table_columns(&self, _table: &TableRef) -> Option<&TableColumns> {
        None
    }

    fn column_metadata(&self, _id: ColumnId) -> Option<&ColumnMetadata> {
        None
    }
}

// ────────────────────────────────────────────────────────────────────────
// IndexedCatalogContext — populated sidecar
// ────────────────────────────────────────────────────────────────────────

/// Catalog projection populated by an external builder (typically the
/// IR lowerer).
///
/// Holds three maps:
/// - `tables` — [`TableRef`] → [`TableColumns`] for base tables.
/// - `tvfs` — function identity key → [`TableColumns`] for TVFs with
///   catalog-known output schemas. The key is the fully-qualified
///   function name in [`IdentKey`] form.
/// - `column_metadata` — [`ColumnId`] → [`ColumnMetadata`] for every
///   catalog-sourced column the builder has observed.
///
/// Build by calling `insert_*` for each catalog-resolved entity, then
/// hand the result to analyses via `&dyn CatalogContext`.
///
/// Duplicate inserts for the same key OVERWRITE the previous entry.
/// The last writer wins; in practice a well-behaved builder inserts
/// each key exactly once.
#[derive(Debug, Clone, Default)]
pub struct IndexedCatalogContext {
    tables: HashMap<TableRef, TableColumns>,
    tvfs: HashMap<IdentKey, TableColumns>,
    column_metadata: HashMap<ColumnId, ColumnMetadata>,
    table_tags: HashMap<TableRef, Vec<TagRef>>,
    /// Per-table catalog-presence outcome recorded at scan-resolution
    /// time. Three states:
    /// - Missing entry: no catalog was attached to the lowering call
    ///   (the table-presence question is unanswerable).
    /// - `Some(true)`: the lowerer consulted the catalog and the table
    ///   was found.
    /// - `Some(false)`: the lowerer consulted the catalog and the
    ///   table was absent (with session-defaults applied for any
    ///   missing db/schema parts).
    ///
    /// Drives `CAT-TBL-UNKNOWN` via the public
    /// [`crate::facts::query::TableEvent::in_catalog`] projection.
    table_in_catalog: HashMap<TableRef, bool>,

    /// Per-table row count estimate from the catalog. Populated at
    /// lowering time alongside `column_metadata`. Consumed by IR
    /// queries (e.g. `is_high_cardinality_column`) so post-attach
    /// emitters never reach back to the upstream `CatalogIndex`.
    table_row_counts: HashMap<TableRef, u64>,
    /// Per-table object kind (base table, view, materialized view,
    /// external table). Populated from `CatalogTable.kind`. Drives
    /// `Q-VIEW-REF-CENH`.
    table_kinds: HashMap<TableRef, IrTableKind>,
    /// Per-table list of declared foreign-key edges. Populated from
    /// `CatalogTable.constraints` (`ForeignKey` entries). Each edge
    /// names the local column on this table, the referenced table,
    /// and the referenced column. Drives `Q-JOIN-FKVIOL-CENH`: a
    /// join on `(this_table.x = other_table.y)` is "Diverges" iff
    /// `this_table` has declared FKs but none of them are
    /// `(x, other_table, y)`.
    table_fks: HashMap<TableRef, Vec<FkEdge>>,
    /// Reverse index from a `ColumnId` allocated to a scan to the
    /// source `(TableRef, column_name)`. Populated by
    /// `seed_catalog_ctx_from_scan` whenever a scan binds a
    /// catalog-resolved column. Consumers (e.g. `Q-JOIN-FKVIOL-CENH`)
    /// use this to walk a join's equi-pair column ids back to their
    /// authoritative source tables without searching every table.
    column_origin: HashMap<ColumnId, (TableRef, IdentKey)>,
    /// Per-column-id catalog-presence outcome recorded at
    /// scan-resolution time, *only* for scans whose `TableRef`
    /// matched a catalog table.
    /// - Missing entry: no catalog attached, the scan's table was
    ///   not in the catalog (in which case `table_in_catalog` carries
    ///   `false`), or the `ColumnId` was not produced by
    ///   `seed_catalog_ctx_from_scan`.
    /// - `Some(true)`: the column's `display_name` matched a
    ///   declared column on the catalog table.
    /// - `Some(false)`: the catalog table is known, but the column
    ///   was alloc-on-first-use for a name the catalog did not
    ///   declare (e.g. `SELECT typo_col FROM users`).
    ///
    /// Drives `CAT-COL-UNKNOWN` via the public
    /// [`crate::facts::query::ColumnReferenceEvent::in_catalog`]
    /// projection.
    column_in_catalog: HashMap<ColumnId, bool>,
    /// Set of `ColumnId`s allocated at the alloc-on-first-use
    /// branch of `lower_column_ref` for *unqualified* references
    /// whose name appears in two or more in-scope catalog-known
    /// tables (`SELECT id FROM users JOIN orders ON …` when both
    /// tables declare `id`). The reference is structurally
    /// ambiguous: no unique source can be inferred, so the
    /// `ColumnId` is orphaned to `current_stmt_node` and the
    /// catalog presence is unanswerable (`in_catalog: None`).
    ///
    /// Drives `CAT-COL-AMBIGUOUS` via the public
    /// [`crate::facts::query::ColumnReferenceEvent::is_ambiguous`]
    /// projection. Only populated when a catalog is attached —
    /// without one, ambiguity cannot be detected.
    column_ambiguous: std::collections::HashSet<ColumnId>,
    /// Per-table flag: does the upstream catalog table declare at
    /// least one temporal-typed (DATE / TIME / TIMESTAMP) column?
    /// Populated by `seed_catalog_ctx_from_scan` from the upstream
    /// `CatalogTable.columns` list (NOT from `column_metadata`,
    /// which only carries the scan-referenced subset). Drives
    /// `Q-JOIN-TEMPORAL-CENH` and `Q-MULTI-TEMPORAL-CENH` so a query that
    /// joins two temporal-typed tables fires even when none of the
    /// temporal columns are projected.
    table_has_temporal_column: HashMap<TableRef, bool>,
    /// Per-table list of temporal-typed (DATE / TIME / TIMESTAMP)
    /// column names declared by the upstream catalog table. Seeded
    /// from the full `CatalogTable.columns` list at scan-resolution
    /// time alongside `table_has_temporal_column`. Empty when the
    /// upstream table has no temporal columns or no catalog is
    /// attached. Surfaced onto the public
    /// `TemporalJoinTable.temporal_column_names`
    /// so per-column sibling rules can compose against it.
    table_temporal_column_names: HashMap<TableRef, Vec<IdentKey>>,
}

/// Declared FK edge on a base table. Mirrors `CatalogConstraint`
/// in IR-keyed form for fast lookup at join-classification time.
///
/// A composite FK declared as
/// `FOREIGN KEY (a, b) REFERENCES other (c, d)` is ingested as
/// two `FkEdge`s — one for each column pair — but every edge
/// carries the FULL local-column tuple of its source constraint in
/// `composite_columns` so per-pair join classification can verify
/// that all sibling columns are also covered by the join's
/// `on_columns`. For a single-column FK, `composite_columns` is a
/// one-element vec containing `local_column_name`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FkEdge {
    pub local_column_name: IdentKey,
    pub ref_table: TableRef,
    pub ref_column_name: IdentKey,
    /// Full local-column tuple of the source constraint, in
    /// declaration order. Length 1 for single-column FKs; length > 1
    /// for composite FKs. Same Vec content across every sibling edge
    /// in the same constraint.
    pub composite_columns: Vec<IdentKey>,
}

/// Catalog-declared object kind, projected to IR-neutral form so
/// the facts layer doesn't depend on `crate::catalog::CatalogTableKind`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IrTableKind {
    Table,
    View,
    MaterializedView,
    ExternalTable,
    /// Session-scoped temporary table. Projection of
    /// `CatalogTableKind::Temporary`. Drives `Q-TBL-TEMP-REF-CENH`.
    Temporary,
    Unknown,
}

impl IndexedCatalogContext {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record the catalog-resolved columns for a base table.
    pub fn insert_table_columns(&mut self, table: TableRef, columns: TableColumns) {
        self.tables.insert(table, columns);
    }

    /// Record the catalog-resolved output columns for a TVF,
    /// keyed by the TVF's fully-qualified function name.
    pub fn insert_tvf_columns(&mut self, func: IdentKey, columns: TableColumns) {
        self.tvfs.insert(func, columns);
    }

    /// Record metadata for a single catalog-sourced column.
    pub fn insert_column_metadata(&mut self, id: ColumnId, meta: ColumnMetadata) {
        self.column_metadata.insert(id, meta);
    }

    /// Record table-level tags attached to a base table. Replaces any
    /// previously-inserted tag list for the same table (last writer
    /// wins). Taint analysis consumes these at
    /// [`super::plan::RelPlan::Scan`].
    pub fn insert_table_tags(&mut self, table: TableRef, tags: Vec<TagRef>) {
        self.table_tags.insert(table, tags);
    }

    /// Record the catalog-presence outcome for a base table. Called
    /// at scan-resolution time by `seed_catalog_ctx_from_scan`:
    /// `true` when the catalog had an entry (after session-defaults
    /// resolution), `false` when it did not. Not called at all when
    /// no catalog is attached to the lowering call.
    pub fn insert_table_in_catalog(&mut self, table: TableRef, in_catalog: bool) {
        self.table_in_catalog.insert(table, in_catalog);
    }

    /// Look up the catalog-presence outcome for a base table.
    /// `None` when no catalog was attached or the table was not
    /// processed by `seed_catalog_ctx_from_scan` (e.g. the scan was
    /// opaque). `Some(true)` / `Some(false)` when the lowerer
    /// recorded a definite outcome.
    pub fn table_in_catalog(&self, table: &TableRef) -> Option<bool> {
        self.table_in_catalog.get(table).copied()
    }

    /// Record the catalog-supplied row count estimate for a base
    /// table. Last writer wins; absent entries mean "the catalog
    /// didn't supply an estimate" (consumers treat as `None`).
    pub fn insert_table_row_count(&mut self, table: TableRef, row_count: u64) {
        self.table_row_counts.insert(table, row_count);
    }

    /// Look up the catalog row count estimate for a base table.
    /// `None` when the catalog had no estimate or the table wasn't
    /// in the lowered scan list.
    pub fn table_row_count(&self, table: &TableRef) -> Option<u64> {
        self.table_row_counts.get(table).copied()
    }

    /// Record the catalog-supplied object kind for a base table.
    /// Drives `Q-VIEW-REF-CENH` and the view-aware optimisations
    /// that flow from "is this scan a materialised relation or a
    /// recomputed view?".
    pub fn insert_table_kind(&mut self, table: TableRef, kind: IrTableKind) {
        self.table_kinds.insert(table, kind);
    }

    /// Look up the catalog-declared kind for a base table.
    /// `None` when the catalog had no entry for the table (treat as
    /// `IrTableKind::Unknown` at the call site).
    pub fn table_kind(&self, table: &TableRef) -> Option<IrTableKind> {
        self.table_kinds.get(table).copied()
    }

    /// Record whether the upstream catalog table for `table` declares
    /// at least one temporal-typed column. Seeded from the full
    /// `CatalogTable.columns` list (not the IR-allocated
    /// `column_metadata` subset, which only sees scan-referenced
    /// columns). Drives `Q-JOIN-TEMPORAL-CENH` / `Q-MULTI-TEMPORAL-CENH`.
    pub fn insert_table_has_temporal_column(&mut self, table: TableRef, flag: bool) {
        self.table_has_temporal_column.insert(table, flag);
    }

    /// Record the catalog-declared temporal column names for a base
    /// table. Seeded from the full `CatalogTable.columns` list at
    /// scan-resolution time. Last writer wins.
    pub fn insert_table_temporal_column_names(&mut self, table: TableRef, names: Vec<IdentKey>) {
        self.table_temporal_column_names.insert(table, names);
    }

    /// Catalog-declared temporal column names for `table`. Empty
    /// when no entry exists or the upstream table has no temporal
    /// columns.
    pub fn table_temporal_column_names(&self, table: &TableRef) -> &[IdentKey] {
        self.table_temporal_column_names
            .get(table)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    /// Look up the catalog-declared "has any temporal column" flag
    /// for a base table. `false` when the catalog had no entry for
    /// the table or the upstream table had no temporal-typed columns.
    pub fn table_declares_temporal_column(&self, table: &TableRef) -> bool {
        self.table_has_temporal_column
            .get(table)
            .copied()
            .unwrap_or(false)
    }

    /// Record the declared FK edges for a base table.
    pub fn insert_table_fks(&mut self, table: TableRef, edges: Vec<FkEdge>) {
        self.table_fks.insert(table, edges);
    }

    /// Look up the declared FK edges for a base table. `&[]` when
    /// the catalog had no FK constraints (or no entry) for the
    /// table; the call site cannot distinguish "no FKs declared"
    /// from "catalog absent" by this accessor alone — pair with
    /// other catalog probes (`resolve_table_columns`) for that.
    pub fn table_fks(&self, table: &TableRef) -> &[FkEdge] {
        self.table_fks
            .get(table)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// Record the authoritative `(source_table, column_name)`
    /// origin for a scan-bound `ColumnId`. Last writer wins.
    pub fn insert_column_origin(&mut self, id: ColumnId, table: TableRef, column_name: IdentKey) {
        self.column_origin.insert(id, (table, column_name));
    }

    /// Resolve a `ColumnId` to its authoritative source
    /// `(TableRef, column_name)`. `None` for derived / projection
    /// outputs / fresh scope columns that were not produced by a
    /// catalog-resolved scan.
    pub fn column_origin(&self, id: ColumnId) -> Option<&(TableRef, IdentKey)> {
        self.column_origin.get(&id)
    }

    /// Record the catalog-presence outcome for a scan-bound
    /// `ColumnId`. Called by `seed_catalog_ctx_from_scan` for every
    /// `ColumnId` attached to a Scan whose `TableRef` resolved in
    /// the catalog: `true` when the column's `display_name`
    /// matched a catalog column, `false` when it did not. Not called
    /// at all when no catalog is attached or the table was absent
    /// from the catalog.
    pub fn insert_column_in_catalog(&mut self, id: ColumnId, in_catalog: bool) {
        self.column_in_catalog.insert(id, in_catalog);
    }

    /// Look up the catalog-presence outcome for a scan-bound
    /// `ColumnId`. `None` when no catalog was attached, the table
    /// was not in the catalog, or the id was not produced by a
    /// scan-resolution step. `Some(true)` / `Some(false)` when the
    /// lowerer recorded a definite outcome.
    pub fn column_in_catalog(&self, id: ColumnId) -> Option<bool> {
        self.column_in_catalog.get(&id).copied()
    }

    /// Mark a freshly-allocated `ColumnId` as catalog-ambiguous: the
    /// reference is unqualified, and the catalog declares the
    /// column name on two or more in-scope source tables. Called
    /// by `lower_column_ref` at the alloc-on-first-use branch.
    pub fn insert_column_ambiguous(&mut self, id: ColumnId) {
        self.column_ambiguous.insert(id);
    }

    /// Whether the given `ColumnId` was recorded as catalog-ambiguous
    /// at lowering time. `false` when no catalog was attached, the
    /// reference resolved uniquely, or the id was not produced by an
    /// unqualified alloc-on-first-use path.
    pub fn column_is_ambiguous(&self, id: ColumnId) -> bool {
        self.column_ambiguous.contains(&id)
    }

    /// Number of tables recorded.
    pub fn table_count(&self) -> usize {
        self.tables.len()
    }

    /// Number of TVFs recorded.
    pub fn tvf_count(&self) -> usize {
        self.tvfs.len()
    }

    /// Number of columns with recorded metadata.
    pub fn column_metadata_count(&self) -> usize {
        self.column_metadata.len()
    }

    /// Iterate over every `(ColumnId, &ColumnMetadata)` pair the
    /// sidecar has recorded. Used by IR queries that need to
    /// resolve a predicate-side `ColumnId` to its origin-
    /// equivalent metadata when direct lookup misses.
    pub fn column_metadata_iter(&self) -> impl Iterator<Item = (ColumnId, &ColumnMetadata)> + '_ {
        self.column_metadata.iter().map(|(k, v)| (*k, v))
    }
}

impl CatalogContext for IndexedCatalogContext {
    fn resolve_table_columns(&self, table: &TableRef) -> Option<&TableColumns> {
        self.tables.get(table)
    }

    fn column_metadata(&self, id: ColumnId) -> Option<&ColumnMetadata> {
        self.column_metadata.get(&id)
    }

    fn resolve_table_tags(&self, table: &TableRef) -> &[TagRef] {
        self.table_tags.get(table).map_or(&[], |v| v.as_slice())
    }

    /// TVF resolution requires extracting the function's identity key
    /// from the call expression. Recognises only
    /// [`ScalarExpr::FuncCall`] with a resolved name; other shapes
    /// (lambdas, opaque calls) return `None`. Extending to further
    /// shapes is additive and does not change this method's signature.
    fn resolve_tvf_columns(&self, call: &ScalarExpr) -> Option<&TableColumns> {
        let key = tvf_key_from_call(call)?;
        self.tvfs.get(&key)
    }
}

/// Derive the lookup key for a TVF call expression.
///
/// Handles [`ScalarExpr::FuncCall`] with an
/// [`ResolvedFunc::Unresolved`] inner, keying on the raw spelling via
/// [`IdentKey`] normalization. Resolved calls require cross-checking
/// against a [`crate::ir::FunctionCatalog`] to recover the display
/// name; they return `None`. Non-call shapes return `None`.
fn tvf_key_from_call(call: &ScalarExpr) -> Option<IdentKey> {
    match call {
        ScalarExpr::FuncCall { func, .. } => match func {
            crate::ir::ResolvedFunc::Unresolved { raw_name, .. } => Some(IdentKey::new(raw_name)),
            // Resolved TVFs need FunctionCatalog access to recover
            // their canonical name. Returns
            // `None` rather than falling back to `display_hint()`
            // (which would yield a synthetic `fn#<id>` tag that no
            // builder would ever have inserted under).
            crate::ir::ResolvedFunc::Resolved { .. } => None,
        },
        _ => None,
    }
}

// ────────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::column::ColumnIdAllocator;
    use crate::ir::scalar::{Lit, ScalarExpr};
    use crate::ir::ResolvedFunc;
    use crate::lexer::Span;

    fn sp() -> Span {
        Span { start: 0, end: 0 }
    }

    fn tref(name: &str) -> TableRef {
        TableRef::new(name.to_string())
    }

    #[test]
    fn empty_context_returns_none_for_every_lookup() {
        let ctx = EmptyCatalogContext;
        let mut alloc = ColumnIdAllocator::new();
        let id = alloc.fresh_test();

        assert!(ctx.resolve_table_columns(&tref("t")).is_none());
        assert!(ctx
            .resolve_column_by_name(&tref("t"), &IdentKey::new("c"))
            .is_none());
        assert!(ctx.column_metadata(id).is_none());

        // TVF scaffold: a well-formed FuncCall still yields None.
        let call = ScalarExpr::FuncCall {
            func: ResolvedFunc::unresolved("flatten", None, sp()),
            args: vec![],
            named_args: vec![],
            distinct: false,
            span: sp(),
        };
        assert!(ctx.resolve_tvf_columns(&call).is_none());
    }

    #[test]
    fn indexed_context_roundtrips_table_columns() {
        let mut alloc = ColumnIdAllocator::new();
        let c_id = alloc.fresh_test();
        let d_id = alloc.fresh_test();

        let mut ctx = IndexedCatalogContext::new();
        ctx.insert_table_columns(
            tref("orders"),
            TableColumns::from_pairs(vec![
                (IdentKey::new("id"), c_id),
                (IdentKey::new("amount"), d_id),
            ]),
        );

        let cols = ctx
            .resolve_table_columns(&tref("orders"))
            .expect("inserted table should resolve");
        assert_eq!(cols.by_position, vec![c_id, d_id]);
        assert_eq!(
            ctx.resolve_column_by_name(&tref("orders"), &IdentKey::new("id")),
            Some(c_id)
        );
        assert_eq!(
            ctx.resolve_column_by_name(&tref("orders"), &IdentKey::new("amount")),
            Some(d_id)
        );
        assert_eq!(
            ctx.resolve_column_by_name(&tref("orders"), &IdentKey::new("nope")),
            None
        );
        assert!(ctx.resolve_table_columns(&tref("other")).is_none());
    }

    #[test]
    fn indexed_context_roundtrips_column_metadata() {
        let mut alloc = ColumnIdAllocator::new();
        let id = alloc.fresh_test();

        let meta = ColumnMetadata {
            nullable: Some(false),
            default: Some(DefaultExpr {
                display: "0".to_string(),
            }),
            constraints: ColumnConstraints {
                is_primary_key: true,
                is_unique: true,
                is_solo_unique_key: true,
                check: None,
            },
            tags: vec![TagRef {
                qualified_name: "DB.SCH.PII".to_string(),
                value: Some("EMAIL".to_string()),
            }],
            policy: Some(PolicyRef {
                qualified_name: "DB.SCH.MASK_EMAIL".to_string(),
                kind: PolicyKind::Masking,
            }),
            data_type: None,
            fk_target: None,
        };

        let mut ctx = IndexedCatalogContext::new();
        ctx.insert_column_metadata(id, meta.clone());

        let got = ctx.column_metadata(id).expect("metadata should resolve");
        assert_eq!(got, &meta);
    }

    #[test]
    fn indexed_context_roundtrips_tvf_columns() {
        let mut alloc = ColumnIdAllocator::new();
        let out_id = alloc.fresh_test();

        let mut ctx = IndexedCatalogContext::new();
        ctx.insert_tvf_columns(
            IdentKey::new("flatten"),
            TableColumns::from_pairs(vec![(IdentKey::new("value"), out_id)]),
        );

        let call = ScalarExpr::FuncCall {
            func: ResolvedFunc::unresolved("flatten", None, sp()),
            args: vec![ScalarExpr::Lit {
                value: Lit::Integer("1".to_string()),
                span: sp(),
            }],
            named_args: vec![],
            distinct: false,
            span: sp(),
        };

        let cols = ctx
            .resolve_tvf_columns(&call)
            .expect("inserted TVF should resolve");
        assert_eq!(cols.by_position, vec![out_id]);
        assert_eq!(
            cols.by_name.get(&IdentKey::new("value")).copied(),
            Some(out_id)
        );
    }

    #[test]
    fn indexed_context_missing_tvf_returns_none() {
        let ctx = IndexedCatalogContext::new();
        let call = ScalarExpr::FuncCall {
            func: ResolvedFunc::unresolved("absent_tvf", None, sp()),
            args: vec![],
            named_args: vec![],
            distinct: false,
            span: sp(),
        };
        assert!(ctx.resolve_tvf_columns(&call).is_none());
    }

    #[test]
    fn indexed_context_tvf_key_derives_from_func_display_name() {
        let mut ctx = IndexedCatalogContext::new();
        let mut alloc = ColumnIdAllocator::new();
        let id = alloc.fresh_test();
        ctx.insert_tvf_columns(
            IdentKey::new("my_udtf"),
            TableColumns::from_pairs(vec![(IdentKey::new("out"), id)]),
        );

        // A FuncCall whose func name matches the inserted key should
        // resolve regardless of how args are shaped.
        let call = ScalarExpr::FuncCall {
            func: ResolvedFunc::unresolved("my_udtf", None, sp()),
            args: vec![ScalarExpr::Lit {
                value: Lit::Bool(true),
                span: sp(),
            }],
            named_args: vec![],
            distinct: false,
            span: sp(),
        };
        assert!(ctx.resolve_tvf_columns(&call).is_some());

        // Non-FuncCall shapes (e.g. bare column reference) are not TVF
        // calls and must return None without panicking.
        let not_a_call = ScalarExpr::Lit {
            value: Lit::Integer("7".to_string()),
            span: sp(),
        };
        assert!(ctx.resolve_tvf_columns(&not_a_call).is_none());
    }

    #[test]
    fn indexed_context_counts_reflect_inserts() {
        let mut alloc = ColumnIdAllocator::new();
        let mut ctx = IndexedCatalogContext::new();
        assert_eq!(ctx.table_count(), 0);
        assert_eq!(ctx.tvf_count(), 0);
        assert_eq!(ctx.column_metadata_count(), 0);

        ctx.insert_table_columns(tref("t"), TableColumns::new());
        ctx.insert_tvf_columns(IdentKey::new("f"), TableColumns::new());
        ctx.insert_column_metadata(alloc.fresh_test(), ColumnMetadata::default());

        assert_eq!(ctx.table_count(), 1);
        assert_eq!(ctx.tvf_count(), 1);
        assert_eq!(ctx.column_metadata_count(), 1);
    }

    #[test]
    fn indexed_context_duplicate_insert_overwrites() {
        let mut alloc = ColumnIdAllocator::new();
        let id_v1 = alloc.fresh_test();
        let id_v2 = alloc.fresh_test();

        let mut ctx = IndexedCatalogContext::new();
        ctx.insert_table_columns(
            tref("t"),
            TableColumns::from_pairs(vec![(IdentKey::new("c"), id_v1)]),
        );
        ctx.insert_table_columns(
            tref("t"),
            TableColumns::from_pairs(vec![(IdentKey::new("c"), id_v2)]),
        );
        let cols = ctx.resolve_table_columns(&tref("t")).unwrap();
        assert_eq!(cols.by_position, vec![id_v2]);
    }

    #[test]
    fn default_catalog_context_is_empty_for_trait_object_consumers() {
        // Exercise &dyn CatalogContext dispatch to ensure the trait is
        // object-safe and both impls satisfy it.
        let empty = EmptyCatalogContext;
        let indexed = IndexedCatalogContext::new();
        let contexts: Vec<&dyn CatalogContext> = vec![&empty, &indexed];
        for ctx in contexts {
            assert!(ctx.resolve_table_columns(&tref("t")).is_none());
        }
    }
}
