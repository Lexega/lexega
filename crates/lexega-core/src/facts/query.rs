// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Query-bearing statement facts: tables read/written, scopes, joins,
//! predicates, projections, aggregates, windows, set operations.
//!
//! `QueryFacts` is populated for query-bearing statements (DML and
//! composite DDL like CTAS / CVAS / CMVAS).
//!
//! The `*_predicates` collections carry typed `PredicateEvent` records.
//! Predicates can match `WHERE func(col) = literal` patterns by
//! traversing into `root.binary_op.left.func_call.name`.

use serde::{Deserialize, Serialize};

#[cfg(feature = "schema")]
use schemars::JsonSchema;

use crate::lexer::token::Span;

use super::catalog::{CatalogTag, ColumnLineage, Nullability, TaintLabel};
use super::expr::Expr;
use super::identity::{ColumnRef, IdentName, ScopeIdentity, TableRef};

/// A literal string argument passed to an `OPENROWSET(...)` call.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct OpenrowsetArgFacts {
    /// The literal string value as written in the SQL source, including
    /// the surrounding single quotes.
    pub value: String,
}

/// A T-SQL `OPENROWSET(...)` table-valued function call observed in a
/// query's FROM clause. `OPENROWSET` is a T-SQL mechanism for reading
/// from an external data source (typically by inline connection string),
/// and is commonly reviewed for embedded credentials and cross-server
/// data movement.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct OpenrowsetCallFacts {
    /// Literal string arguments of the call, in source order. Arguments
    /// that are not string literals (variables, expressions, subqueries)
    /// are omitted from this list.
    pub string_args: Vec<OpenrowsetArgFacts>,
}

/// A `SELECT ... INTO OUTFILE` / `INTO DUMPFILE` file-export target
/// (MySQL). The statement writes its result set to a file on the
/// database server's filesystem — a data-movement channel commonly
/// reviewed alongside external-stage and external-table access.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct FileExportFacts {
    /// Which export form was used.
    pub kind: FileExportTargetKind,
    /// The file-path string literal as written in the SQL source,
    /// including the surrounding quotes.
    pub file_path: String,
}

/// File-export form of a `SELECT ... INTO` file target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum FileExportTargetKind {
    /// `INTO OUTFILE` — formatted text export (supports CHARACTER SET
    /// and FIELDS/LINES options).
    Outfile,
    /// `INTO DUMPFILE` — single-row raw binary export.
    Dumpfile,
}

/// Facts about a query-bearing statement.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct QueryFacts {
    pub reads_table: Vec<TableEvent>,
    pub writes_table: Vec<TableEvent>,
    pub scopes: Vec<ScopeFacts>,
    /// T-SQL `OPENROWSET(...)` calls observed in this query's FROM
    /// clause. Empty for queries that do not reference `OPENROWSET`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub openrowset_calls: Vec<OpenrowsetCallFacts>,
    /// T-SQL `OPENDATASOURCE(...)` ad-hoc remote-source calls observed in
    /// this query's FROM clause (`OPENDATASOURCE('provider', 'connstr')
    /// .db.schema.table`). Same literal-string-arg shape as
    /// [`Self::openrowset_calls`]; the connection string carries inline
    /// credentials. Empty when the query does not reference `OPENDATASOURCE`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub opendatasource_calls: Vec<OpenrowsetCallFacts>,

    /// MySQL `SELECT ... INTO OUTFILE 'file'` / `INTO DUMPFILE 'file'`
    /// targets: the statement writes its result set to a file on the
    /// database server's filesystem. Empty for queries without a file
    /// export target (the grammar allows at most one).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub file_exports: Vec<FileExportFacts>,

    /// Convenience properties — outer-scope-only (equivalent to
    /// `scopes[0].<property>`).
    pub has_where: bool,
    /// Outer-scope WHERE clause contains at least one tautology subexpression (e.g. `1=1`, `TRUE`).
    #[serde(default)]
    pub has_tautology_where: bool,
    pub has_limit: bool,
    pub has_qualify: bool,
    pub has_having: bool,
    pub has_distinct: bool,
    pub has_sample: bool,
    pub has_implicit_cross_join: bool,
    /// Cartesian-product row-count estimate when
    /// `has_implicit_cross_join` is true: the saturating product of
    /// each `reads_table[*].row_count`. Omitted when there is no
    /// implicit cross join or any participating table lacks a catalog
    /// row count.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub implicit_cross_product_estimate: Option<u64>,
    pub has_join_predicate_filters: bool,

    /// Deduplicated schema identifiers across `reads_table` ∪
    /// `writes_table`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub schemas_touched: Vec<IdentName>,

    /// Per-column structural constraint facts: every atomic predicate on a
    /// column (equality, inequality, range bound, IS NULL, IS NOT NULL)
    /// within any predicate scope, plus set-theoretic anomalies detected
    /// over their AND-conjunction. One entry per (scope, column) pair,
    /// aggregated across all scopes (outer query, CTEs, derived tables,
    /// subqueries).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub column_constraints: Vec<ColumnConstraintEvent>,

    /// Per-OR-expression tautology events: an OR-disjunction whose
    /// branches cover the entire value space (e.g., `x = 1 OR x <> 1`,
    /// `x IS NULL OR x IS NOT NULL`), meaning the OR-branch contributes
    /// no filtering.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub or_tautologies: Vec<OrTautologyEvent>,

    /// Source tables referenced by this statement that declare at least
    /// one temporal-typed (DATE / TIME / TIMESTAMP) column in the catalog.
    /// Empty when no catalog is attached. Pairs with
    /// `temporal_gating_expressions` to identify join patterns involving
    /// temporal columns.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub temporal_join_tables: Vec<TemporalJoinTable>,

    /// Predicates in WHERE / JOIN-ON / QUALIFY / MERGE / UPDATE /
    /// DELETE that reference a temporal function or a temporal column
    /// from one of the `temporal_join_tables`. Column-reference entries
    /// require a catalog; function-call entries (e.g. `CURRENT_DATE`)
    /// fire without one.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub temporal_gating_expressions: Vec<TemporalGatingExpression>,

    /// Repeated subquery patterns: two or more scalar or quantified
    /// subqueries sharing a structural fingerprint. EXISTS subqueries
    /// are excluded.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub repeated_subqueries: Vec<RepeatedSubqueryEvent>,

    /// Table references in this statement whose target was dropped or renamed
    /// by an earlier statement in the same script. One entry per
    /// (statement-reference, mutation) pair.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub stale_table_refs: Vec<StaleTableReference>,

    /// Column references in this statement that were removed by an
    /// earlier `ALTER TABLE ... DROP COLUMN` in the same script.
    /// Includes column references in projections, predicates, GROUP BY,
    /// ORDER BY, and UPDATE-SET assignment targets.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub stale_column_refs: Vec<StaleColumnReference>,

    /// Per-statement deduplicated list of base-table column references.
    /// One entry per distinct `(table, column_name)` pair. Derived-table,
    /// CTE, VALUES, and TVF column references are excluded. The
    /// `in_catalog` field reports the catalog-lookup outcome:
    /// `true` — the catalog declared the column on the table;
    /// `false` — the catalog declared the table but not this column;
    /// omitted — no catalog attached or the table was absent from the
    /// catalog.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub references_column: Vec<ColumnReferenceEvent>,

    /// MERGE statement structural facts. Present only for MERGE statements.
    /// Carries `with_schema_evolution: true` when the `WITH SCHEMA EVOLUTION`
    /// clause is present (Databricks/Delta).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub merge: Option<MergeFacts>,

    /// T-SQL table hints applied to a table reference or INSERT target
    /// in this statement. One entry per `WITH (...)` hint occurrence.
    /// Empty when no hint was present or when the statement is not
    /// T-SQL.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub table_hints: Vec<TableHintFact>,
}

/// One T-SQL table hint occurrence.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", schemars(rename = "TableHint"))]
pub struct TableHintFact {
    /// The SQL keyword identifying the hint (e.g. `nolock`, `forceseek`).
    pub kind: MssqlTableHintKind,
    /// Table the hint was attached to (a `FROM`-clause table or an
    /// `INSERT` target).
    pub table: TableRef,
    /// Source span of this individual hint (e.g. `NOLOCK` or
    /// `INDEX(idx1)`).
    pub source_span: Span,
}

/// SQL keyword of a T-SQL table hint. Common hint keywords have a
/// dedicated kind; less-common hints classify as `Other`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", schemars(rename = "MsSqlTableHintType"))]
pub enum MssqlTableHintKind {
    /// `NOLOCK` — reads uncommitted data.
    #[serde(rename = "nolock")]
    NoLock,
    /// `READUNCOMMITTED` — reads uncommitted data.
    #[serde(rename = "read_uncommitted")]
    ReadUncommitted,
    /// `TABLOCKX` — exclusive table-level lock.
    #[serde(rename = "tablockx")]
    TabLockX,
    /// `XLOCK` — exclusive row-level lock held to end of transaction.
    #[serde(rename = "xlock")]
    XLock,
    /// `FORCESCAN`.
    #[serde(rename = "forcescan")]
    ForceScan,
    /// `FORCESEEK [(index(...))]`.
    #[serde(rename = "forceseek")]
    ForceSeek,
    /// `INDEX(...)` / `INDEX = (...)` — optimizer index override.
    #[serde(rename = "index")]
    Index,
    /// Any other T-SQL hint not listed above.
    #[serde(rename = "other")]
    Other,
}

/// Structural facts about a `MERGE` statement.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct MergeFacts {
    /// `MERGE … WITH SCHEMA EVOLUTION` clause present. Databricks/Delta:
    /// target table schema may be automatically altered to match source
    /// columns.
    #[serde(default)]
    pub with_schema_evolution: bool,
    /// The statement's `WHEN …` branches, in source order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub branches: Vec<MergeBranchFacts>,
}

/// One `WHEN …` branch of a `MERGE` statement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", schemars(rename = "MergeStatementBranch"))]
pub struct MergeBranchFacts {
    /// Which match state the branch applies to.
    pub kind: MergeBranchKind,
    /// What the branch does to the affected rows.
    pub action: MergeActionFacts,
    /// An additional `AND <condition>` guard is present on the branch.
    /// When `false`, the action applies to every row in the branch's
    /// match state.
    #[serde(default)]
    pub guarded: bool,
}

/// The action a `MERGE` branch performs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", schemars(rename = "MergeBranchAction"))]
pub enum MergeActionFacts {
    /// Any `INSERT` form (explicit columns, `INSERT *`, or by-name).
    Insert,
    /// Any `UPDATE` form (explicit assignments, `SET *`, or by-name).
    Update,
    /// `DELETE` — the branch removes the affected rows.
    Delete,
    /// `DO NOTHING`.
    DoNothing,
}

/// One group of repeated subquery occurrences sharing a structural shape.
/// `occurrences` lists the source span of each repeated instance.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", schemars(rename = "RepeatedSubquery"))]
pub struct RepeatedSubqueryEvent {
    pub kind: RepeatedSubqueryKind,
    /// Source spans of each repeated occurrence, in plan-walk order.
    pub occurrences: Vec<Span>,
}

/// A table reference in the current statement whose target was mutated
/// (dropped or renamed) by an earlier statement in the same script.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", schemars(rename = "UnresolvedTableReference"))]
pub struct StaleTableReference {
    /// The offending table reference in the current statement.
    pub table: TableRef,
    /// What state the referenced table is in.
    pub state: StaleTableState,
    /// 0-indexed position of the earlier script statement that mutated
    /// the schema. Always strictly less than the current statement's
    /// `script_context.statement_index`.
    pub mutated_at_index: u32,
    /// Source span of the reference site in this statement.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_span: Option<Span>,
}

/// The kind of schema mutation that made a table reference stale.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum StaleTableState {
    /// `DROP TABLE` or `DROP VIEW` by an earlier statement, with no
    /// subsequent `CREATE` cancelling the drop.
    Dropped { object_kind: DroppedObjectKind },
    /// `ALTER TABLE x RENAME TO y` by an earlier statement; this
    /// reference uses the OLD name `x`. `new_name` carries the new
    /// name the customer should switch to.
    Renamed { new_name: IdentName },
}

/// The kind of object that was dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", schemars(rename = "DroppedObjectType"))]
pub enum DroppedObjectKind {
    Table,
    View,
}

/// A column reference in the current statement that was removed by an
/// earlier `ALTER TABLE ... DROP COLUMN` in the same script.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", schemars(rename = "UnresolvedColumnReference"))]
pub struct StaleColumnReference {
    /// Optional table qualifier as it appears in the reference (when
    /// the column was resolved or qualified at the call site).
    pub table: Option<TableRef>,
    /// The column name as referenced in this statement.
    pub column: IdentName,
    /// 0-indexed position of the earlier `ALTER TABLE ... DROP COLUMN`
    /// statement.
    pub mutated_at_index: u32,
    pub source_span: Option<Span>,
}

/// A base-table column reference in the statement, paired with the
/// catalog-lookup outcome. One event per distinct `(table, column_name)`
/// pair. Derived-table, CTE, VALUES, and TVF references are excluded.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", schemars(rename = "ColumnUsage"))]
pub struct ColumnReferenceEvent {
    /// The referenced column. `table` is the catalog-resolved table
    /// the column actually came from (not the syntactic qualifier —
    /// `t.x` and unqualified `x` resolving to the same source table
    /// share the same event); omitted when the column could not be
    /// tied to a catalog-known table.
    pub column: ColumnRef,
    /// Catalog-presence outcome.
    ///
    /// - `true`: the catalog declared this column on its resolved table.
    /// - `false`: the catalog declared the table but not this column.
    /// - omitted: no catalog attached, the table was absent, or the
    ///   column resolved to a derived source (CTE, derived table,
    ///   VALUES, TVF).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub in_catalog: Option<bool>,
    /// `true` when the reference is unqualified and the attached catalog
    /// declares the same column name on two or more in-scope source tables
    /// (e.g. `SELECT id FROM users JOIN orders ON …` when both declare `id`).
    /// Always `false` without an attached catalog or for qualified references.
    #[serde(default, skip_serializing_if = "is_false")]
    pub is_ambiguous: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_span: Option<Span>,
}

fn is_false(b: &bool) -> bool {
    !*b
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", schemars(rename = "RepeatedSubqueryType"))]
pub enum RepeatedSubqueryKind {
    /// Scalar subquery in value position: `SELECT (SELECT …)`.
    Scalar,
    /// `IN (SELECT …)`, `= ANY (SELECT …)`, `< ALL (SELECT …)`, etc.
    Quantified,
}

/// A source table that declares at least one temporal-typed column
/// in the attached catalog.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct TemporalJoinTable {
    pub table: TableRef,
    /// Names of columns on `table` whose catalog `data_type` resolves
    /// to a temporal kind (DATE / TIME / TIMESTAMP / TIMESTAMP_NTZ /
    /// TIMESTAMP_TZ / TIMESTAMP_LTZ, or the dialect's equivalent).
    pub temporal_column_names: Vec<IdentName>,
}

/// A temporal sub-expression inside a predicate (WHERE / JOIN-ON /
/// QUALIFY / MERGE / UPDATE / DELETE) — either a temporal function
/// call or a reference to a temporal column. One entry per temporal
/// sub-expression in any predicate tree.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct TemporalGatingExpression {
    pub source_span: Option<Span>,
    pub kind: TemporalGatingKind,
}

/// The kind of temporal expression gating a predicate.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TemporalGatingKind {
    /// Predicate invokes a function classified `is_temporal` by the
    /// function catalog (CURRENT_DATE, DATE_TRUNC, DATEADD, …).
    FunctionCall { function: IdentName },
    /// Predicate references a temporal column on a table in
    /// [`QueryFacts::temporal_join_tables`].
    ColumnReference { column: ColumnRef },
}

/// One scope (outer SELECT, CTE body, derived table, subquery, etc.).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", schemars(rename = "Scope"))]
pub struct ScopeFacts {
    pub scope_id: ScopeIdentity,
    pub kind: ScopeKind,

    pub tables: Vec<TableEvent>,
    pub joins: Vec<JoinEvent>,

    pub where_predicates: Vec<PredicateEvent>,
    pub join_predicates: Vec<JoinPredicateEvent>,
    pub having_predicates: Vec<PredicateEvent>,

    /// Unified list of every predicate-bearing clause in this scope
    /// (WHERE / HAVING / QUALIFY / JOIN ON), each tagged with the
    /// originating clause via `kind:`. Carries the same
    /// `cross_scope_effects` / `null_effects` shape across all sites
    /// so rules compose orthogonally with `kind:` filters.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub predicates: Vec<PredicateNode>,

    pub projections: Vec<ProjectionEvent>,
    pub group_by: Vec<Expr>,
    pub order_by: Vec<OrderByEvent>,
    pub limit: Option<LimitEvent>,
    pub qualify: Option<Expr>,

    pub aggregates: Vec<AggregateEvent>,
    pub window_functions: Vec<WindowEvent>,
    pub set_operations: Vec<SetOpEvent>,
    pub star_projections: Vec<StarProjectionEvent>,
    pub scalar_subqueries: Vec<SubqueryRef>,
    pub lateral_flattens: Vec<LateralEvent>,

    /// `true` when this scope's output is `SELECT DISTINCT`. Per-scope
    /// analog of `query.has_distinct` (which only reflects the
    /// outermost scope). PostgreSQL `DISTINCT ON` is excluded — it
    /// surfaces as a `group_by` event instead.
    #[serde(default)]
    pub has_distinct: bool,

    /// `true` when this scope contains two or more window functions
    /// whose non-empty PARTITION BY signatures differ.
    #[serde(default)]
    pub has_multiple_partition_schemes: bool,

    /// `true` when at least one GROUP BY key references a catalog column
    /// classified as high-cardinality.
    #[serde(default)]
    pub has_high_cardinality_group_by: bool,

    /// The distinct high-cardinality columns referenced by this scope's
    /// GROUP BY keys, in source order. A single entry is the ordinary
    /// per-entity rollup (`GROUP BY customer_id`); two or more distinct
    /// near-unique keys multiply the group count toward one group per
    /// row. Empty when no GROUP BY key references such a column.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub high_cardinality_group_by_columns: Vec<IdentName>,

    /// Source span identifying where this scope begins — the outer
    /// SELECT keyword for an outer scope, the CTE name for a CTE
    /// scope, the derived-table SELECT for a derived-table scope,
    /// etc. Per-witness emissions use it to anchor signals at the
    /// scope rather than the statement root.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_span: Option<Span>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ScopeKind {
    /// Top-level SELECT or DML scope.
    Outer,
    /// `WITH name AS (...)` CTE body.
    Cte { name: IdentName, recursive: bool },
    /// Derived-table subquery in FROM (`FROM (SELECT ...) alias`).
    DerivedTable { alias: IdentName },
    /// Scalar subquery in projection / WHERE / HAVING.
    ScalarSubquery,
    /// `IN (SELECT ...)` subquery.
    InSubquery,
    /// `EXISTS (SELECT ...)` subquery.
    ExistsSubquery,
    /// `LATERAL (SELECT ...)` subquery.
    LateralSubquery,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", schemars(rename = "TableUsage"))]
pub struct TableEvent {
    pub table: TableRef,
    pub scope_id: ScopeIdentity,
    pub source_span: Option<Span>,
    pub catalog_tags: Vec<CatalogTag>,
    pub row_count: Option<u64>,
    pub column_count: Option<u32>,
    pub access_kind: TableAccessKind,
    /// Catalog-declared object kind. Omitted when no catalog is
    /// attached or the catalog had no entry for the table.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub table_kind: Option<TableKind>,
    /// Catalog-presence outcome. Omitted when no catalog was attached;
    /// `true` when the catalog had an entry for the resolved
    /// `(db, schema, name)` triple; `false` when the catalog was
    /// consulted and the table was not found.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub in_catalog: Option<bool>,
}

/// The catalog-declared kind of a database object.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum TableKind {
    Table,
    View,
    MaterializedView,
    ExternalTable,
    /// Session-scoped temporary table.
    Temporary,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum TableAccessKind {
    Read,
    Written,
    /// MERGE source-and-target case.
    ReadAndWritten,
    DeletedFrom,
    Updated,
    Truncated,
    InsertedInto,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", schemars(rename = "Join"))]
pub struct JoinEvent {
    pub left: TableRef,
    pub right: TableRef,
    pub kind: JoinKind,
    pub on_columns: Vec<JoinColumnPair>,
    pub on_predicate: Option<Expr>,
    pub source_span: Option<Span>,
    /// `true` when ON has a non-equality filter (e.g. `AND active = TRUE`).
    pub filters_join: bool,
    /// `true` when this join was synthesized from a comma-joined FROM
    /// list (`SELECT … FROM a, b`); `false` for every explicit
    /// `JOIN`-keyword path including `CROSS JOIN`. Customer rules
    /// distinguishing explicit-vs-implicit cross-products predicate
    /// against `kind: cross` AND `implicit: <bool>` together.
    #[serde(default)]
    pub implicit: bool,

    /// Catalog row-count estimate for the left operand's principal
    /// base table. Omitted when no catalog is attached or the catalog
    /// has no estimate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub left_row_count: Option<u64>,
    /// Catalog row-count estimate for the right operand's principal
    /// base table.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub right_row_count: Option<u64>,
    /// `left_row_count * right_row_count` (saturating). Present only
    /// when both operand estimates are known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cartesian_estimate: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum JoinKind {
    Inner,
    Left,
    Right,
    FullOuter,
    Cross,
    Lateral,
    Semi,
    Anti,
    /// Snowflake `AS OF JOIN`.
    AsOf,
    NaturalInner,
    NaturalLeft,
    NaturalRight,
    NaturalFullOuter,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct JoinColumnPair {
    pub left: ColumnRef,
    pub right: ColumnRef,
    pub type_compatibility: TypeCompatibility,
    pub fk_relationship: FkRelationshipStatus,
    /// `true` when at least one side of the equi-join pair is a
    /// catalog-declared primary or unique key, meaning that side
    /// cannot produce duplicate rows in the join output.
    #[serde(default)]
    pub unique_key_backed: bool,
    /// `true` when a catalog is attached and `unique_key_backed` reflects
    /// an actual catalog lookup. `false` when no catalog is attached,
    /// in which case `unique_key_backed` is always `false` regardless
    /// of the actual schema.
    #[serde(default)]
    pub unique_key_backing_known: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum TypeCompatibility {
    Compatible,
    /// Implicit cast inferred between the two types.
    ImplicitCast,
    /// Mismatch likely to require explicit cast or cause coercion error.
    Mismatch,
    /// Catalog absent; cannot decide.
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", schemars(rename = "ForeignKeyRelationshipStatus"))]
pub enum FkRelationshipStatus {
    NoFkDefined,
    /// Join columns match a defined FK constraint.
    Matches,
    /// FK exists but join uses different columns.
    Diverges,
    /// Catalog absent; cannot decide.
    Unknown,
}

/// Which `WHEN` clause of a `MERGE` statement a [`PredicateKind::MergeWhen`]
/// originated from. Rules can target a specific branch
/// (e.g. `WHEN NOT MATCHED BY SOURCE` only).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum MergeBranchKind {
    WhenMatched,
    WhenNotMatched,
    /// BigQuery `WHEN NOT MATCHED BY SOURCE`.
    WhenNotMatchedBySource,
}

/// Identifies which SQL clause a predicate originated from. The
/// `join_kind` on `JoinOn` carries the host join's kind so rules can
/// distinguish `INNER JOIN ON p` (constrains both sides) from
/// `LEFT JOIN ON p` (constrains only the right side; null-padded rows
/// still appear).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(tag = "site", rename_all = "snake_case")]
#[cfg_attr(feature = "schema", schemars(rename = "PredicateSite"))]
pub enum PredicateKind {
    /// `WHERE` clause of a `SELECT`.
    Where,
    /// `HAVING` clause.
    Having,
    /// `QUALIFY` clause (Snowflake / BigQuery).
    Qualify,
    /// `JOIN … ON` clause. `join_kind` is the kind of the host join.
    JoinOn { join_kind: JoinKind },
    /// `WHERE` clause of an `UPDATE`. Distinct from
    /// [`PredicateKind::Where`] so rules can target DML-mutating
    /// predicates separately from query filters.
    UpdateWhere,
    /// `WHERE` clause of a `DELETE`.
    DeleteWhere,
    /// `MERGE … ON p` join condition.
    MergeOn,
    /// `WHEN [NOT] MATCHED [BY SOURCE] AND p THEN …` per-branch
    /// predicate of a `MERGE`. `branch_kind` identifies which branch.
    MergeWhen { branch_kind: MergeBranchKind },
    /// `MATCH_CONDITION` clause of a Snowflake `ASOF JOIN`. Distinct
    /// from the join's `ON` clause (which surfaces as `JoinOn { join_kind:
    /// AsOf }`); MATCH_CONDITION is the temporal-ordering predicate.
    AsofMatch,
}

/// One predicate, tagged by its originating clause (`kind:`). Every
/// predicate-bearing clause (WHERE / HAVING / QUALIFY / JOIN ON)
/// appears in the scope's `predicates` list with the same
/// `cross_scope_effects` / `null_effects` shape, so rules compose
/// orthogonally with `kind:` filters.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", schemars(rename = "ScopePredicate"))]
pub struct PredicateNode {
    pub kind: PredicateKind,
    pub root: Expr,
    pub scope_id: ScopeIdentity,
    pub source_span: Option<Span>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub null_effects: Vec<PredicateNullEffect>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cross_scope_effects: Vec<PredicateCrossScopeEffect>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", schemars(rename = "QueryPredicate"))]
pub struct PredicateEvent {
    pub root: Expr,
    pub scope_id: ScopeIdentity,
    pub source_span: Option<Span>,
    /// Per-referenced-column null-handling effects for this predicate.
    /// One entry per column the predicate references, describing how
    /// NULL values interact with the predicate expression.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub null_effects: Vec<PredicateNullEffect>,
    /// Per-referenced-column cross-scope constraint effects for this
    /// predicate. Present when a column resolves through a CTE or
    /// derived table that carries an upstream constraint, enabling
    /// comparison between the upstream constraint and this predicate's
    /// own constraint on the same column.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cross_scope_effects: Vec<PredicateCrossScopeEffect>,
}

/// Cross-scope constraint effect for one (predicate, column) pair.
/// Describes how a predicate's constraint on a column relates to an
/// upstream constraint at a CTE or derived-table boundary.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", schemars(rename = "UpstreamPredicateEffect"))]
pub struct PredicateCrossScopeEffect {
    pub column: ColumnRef,
    /// The upstream CTE, derived table, or model the column resolves through.
    pub upstream: super::algebra::UpstreamFactsRef,
    /// The upstream constraint that holds on `column` at the CTE /
    /// derived-table boundary.
    pub upstream_constraint: super::algebra::UpstreamConstraint,
    /// The consumer-side constraint that this predicate reduces to.
    /// Omitted when the predicate is not a recognized constraint
    /// shape (function call, arbitrary expression); `relationship` is
    /// `consumer_opaque` in that case.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consumer_constraint: Option<super::algebra::UpstreamConstraint>,
    /// Structural relationship between `consumer_constraint` and
    /// `upstream_constraint`. See [`CrossScopeConstraintRelationship`].
    pub relationship: CrossScopeConstraintRelationship,
}

/// Relationship between a predicate's constraint and the upstream constraint
/// on the same column at a CTE or derived-table boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
#[cfg_attr(
    feature = "schema",
    schemars(rename = "UpstreamConstraintRelationship")
)]
pub enum CrossScopeConstraintRelationship {
    /// The consumer-side predicate could not be reduced to a
    /// recognized constraint shape (function call, arbitrary
    /// expression). No comparison against the upstream constraint was
    /// performed.
    ConsumerOpaque,
    /// The predicate's constraint and the upstream constraint are mutually
    /// exclusive — no row admitted by the upstream satisfies the predicate.
    /// A query reading from this upstream will return zero rows.
    Disjoint,
    /// The predicate's constraint and the upstream constraint are compatible
    /// — they share at least one satisfying value.
    NonDisjoint,
}

/// Per-column null-handling properties of a single predicate. Describes
/// how the predicate interacts with NULL values for the referenced column:
/// whether the column can be NULL at the predicate site, whether the
/// predicate silently drops NULL rows, and whether an explicit null guard
/// is present.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", schemars(rename = "PredicateNullHandling"))]
pub struct PredicateNullEffect {
    pub column: ColumnRef,
    pub drops_null_row: bool,
    pub null_addressed: bool,
    pub aggregate_derived: bool,
    /// `true` when the predicate contains a bare `<>` or `!=`
    /// comparison whose left- or right-hand side is the column itself
    /// (not wrapped in a function).
    #[serde(default)]
    pub inequality_compared: bool,
    /// `true` when the column is compared directly to a literal `NULL`
    /// (for example `col = NULL`, `col > NULL`) with a comparison
    /// operator. Such comparisons are always UNKNOWN and match no rows;
    /// `IS NULL` / `IS NOT NULL` is almost always intended. The
    /// null-safe operators (`IS DISTINCT FROM`, `<=>`) do not set this.
    #[serde(default)]
    pub null_literal_compared: bool,
    /// `true` when the column appears on either side of a bare
    /// `Column = Column` equality inside an `INNER JOIN`'s `ON`
    /// clause (or as a `USING` key) feeding into this predicate —
    /// the join eliminates NULL rows, so surviving rows have non-NULL
    /// values regardless of catalog nullability.
    #[serde(default)]
    pub inner_join_key_protected: bool,
    /// Source span of the enclosing predicate (same as the parent
    /// predicate's `source_span`). Lets per-witness emissions walking
    /// `null_effects` anchor the signal at the WHERE / QUALIFY clause
    /// rather than at the statement root.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_span: Option<Span>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", schemars(rename = "JoinCondition"))]
pub struct JoinPredicateEvent {
    pub root: Expr,
    pub scope_id: ScopeIdentity,
    pub source_span: Option<Span>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", schemars(rename = "Projection"))]
pub struct ProjectionEvent {
    pub expr: Expr,
    pub alias: Option<IdentName>,
    pub kind: ProjectionKind,
    pub nullability: Nullability,
    pub taint_labels: Vec<TaintLabel>,
    /// How this column relates to its classified source value (when
    /// tainted): whether it can surface the value or only a collapsed
    /// statistic. `Value` when untainted or value-preserving.
    #[serde(default)]
    pub value_exposure: super::catalog::ValueExposure,
    pub lineage: Option<ColumnLineage>,
    pub source_span: Option<Span>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ProjectionKind {
    Column,
    Expression,
    Aggregate,
    Window,
    StarUnqualified,
    StarQualified {
        table_alias: IdentName,
    },
    StarReplace {
        replacements: Vec<super::expr::StarRename>,
    },
    StarExclude {
        excluded: Vec<IdentName>,
    },
    StarRename {
        renames: Vec<super::expr::StarRename>,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", schemars(rename = "Aggregation"))]
pub struct AggregateEvent {
    pub function: AggregateFunction,
    pub args: Vec<Expr>,
    pub distinct: bool,
    pub filter: Option<Expr>,
    pub within_group: Option<Vec<Expr>>,
    pub scope_id: ScopeIdentity,
    pub source_span: Option<Span>,
    pub on_nullable_argument: bool,
    pub deterministic: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum AggregateFunction {
    Count,
    CountDistinct,
    CountStar,
    Sum,
    Avg,
    Min,
    Max,
    StddevPop,
    StddevSamp,
    VarPop,
    VarSamp,
    ArrayAgg,
    StringAgg,
    ListAgg,
    BoolAnd,
    BoolOr,
    JsonAgg,
    JsonObjectAgg,
    PercentileCont,
    PercentileDisc,
    Median,
    Mode,
    BitAnd,
    BitOr,
    BitXor,
    /// Dialect-specific aggregate. Predicate match against
    /// `function.kind: other` + `function.other.raw: { matches: ... }`.
    Other(IdentName),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", schemars(rename = "WindowFunctionCall"))]
pub struct WindowEvent {
    pub function: super::expr::WindowFunctionName,
    pub args: Vec<Expr>,
    pub partition_by: Vec<Expr>,
    pub order_by: Vec<OrderByEvent>,
    pub frame: Option<WindowFrame>,
    pub deterministic: bool,
    pub partition_high_cardinality: bool,
    pub source_span: Option<Span>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct WindowFrame {
    pub kind: WindowFrameKind,
    pub start: WindowFrameBound,
    pub end: WindowFrameBound,
    pub exclusion: Option<WindowFrameExclusion>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", schemars(rename = "WindowFrameType"))]
pub enum WindowFrameKind {
    Rows,
    Range,
    Groups,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum WindowFrameBound {
    UnboundedPreceding,
    UnboundedFollowing,
    CurrentRow,
    Preceding { offset: Expr },
    Following { offset: Expr },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum WindowFrameExclusion {
    CurrentRow,
    Group,
    Ties,
    NoOthers,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", schemars(rename = "OrderByClause"))]
pub struct OrderByEvent {
    pub expr: Expr,
    pub direction: OrderDirection,
    pub nulls: NullsOrdering,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum OrderDirection {
    Asc,
    Desc,
    /// Engine-defined default for the dialect.
    Default,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum NullsOrdering {
    First,
    Last,
    /// Engine-defined default for the dialect.
    Default,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct LimitEvent {
    pub limit: Option<Expr>,
    pub offset: Option<Expr>,
    pub source_span: Option<Span>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", schemars(rename = "StarProjection"))]
pub struct StarProjectionEvent {
    pub kind: ProjectionKind,
    pub expanded_count: Option<u32>,
    pub source_span: Option<Span>,
}

/// Reference to a subquery in a scope. The full subquery facts live on
/// `Expr::Subquery` when the subquery is part of an expression; this
/// type is the referent on `ScopeFacts.scalar_subqueries`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", schemars(rename = "Subquery"))]
pub struct SubqueryRef {
    pub kind: super::expr::SubqueryKind,
    pub correlated: bool,
    pub scope_id: ScopeIdentity,
    pub source_span: Option<Span>,
    /// Where the subquery sits in the enclosing scope's clause tree.
    /// Rules that target projection-only idioms can match
    /// `position: projection`; rules indifferent to position can omit
    /// the field.
    #[serde(default)]
    pub position: SubqueryPosition,
}

/// Where a subquery sits in the enclosing scope's clause tree.
/// `Other` covers less common positions (LIMIT / OFFSET, ORDER BY,
/// GROUP BY keys, defaults).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum SubqueryPosition {
    /// SELECT-list expression (direct or nested inside a function call
    /// / CASE / etc.).
    Projection,
    /// WHERE-clause expression.
    Where,
    /// HAVING-clause expression.
    Having,
    /// QUALIFY-clause expression (Snowflake / Databricks).
    Qualify,
    /// JOIN ON-clause expression.
    JoinOn,
    /// Any position not listed above.
    #[default]
    Other,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", schemars(rename = "LateralJoin"))]
pub struct LateralEvent {
    pub function: IdentName,
    pub args: Vec<Expr>,
    pub alias: Option<IdentName>,
    pub source_span: Option<Span>,
}

/// Per-column constraint facts. Carries the individual comparisons
/// observed on the column (equality, inequality, range bounds, null
/// checks) and inconsistencies detected when all of those comparisons
/// are taken together. Comparison values are stored as strings.
/// Multiple inconsistencies can co-occur on the same column.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", schemars(rename = "ColumnConstraintChange"))]
pub struct ColumnConstraintEvent {
    pub column: IdentName,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_span: Option<Span>,

    /// `col = lit` comparisons.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub eq_values: Vec<String>,

    /// `col <> lit` / `col != lit` comparisons.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub not_eq_values: Vec<String>,

    /// `col > lit` / `col >= lit` comparisons. Plural because the same
    /// column can carry multiple lower bounds (e.g., `x > 3 AND x > 5`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub lower_bounds: Vec<RangeBoundFact>,

    /// `col < lit` / `col <= lit` comparisons.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub upper_bounds: Vec<RangeBoundFact>,

    /// `true` when the column has an `IS NULL` check.
    #[serde(default)]
    pub is_null_asserted: bool,

    /// `true` when the column has an `IS NOT NULL` check.
    #[serde(default)]
    pub is_not_null_asserted: bool,

    /// Inconsistencies detected when all comparisons on this column
    /// are taken together.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub anomalies: Vec<ColumnConstraintAnomaly>,
}

/// One bound from a column's range list (`lower_bounds` or
/// `upper_bounds`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", schemars(rename = "RangeBound"))]
pub struct RangeBoundFact {
    /// The literal value as a string (compared numerically when
    /// possible by the predicate engine).
    pub value: String,
    /// `true` for `>=` / `<=`; `false` for `>` / `<`.
    pub inclusive: bool,
}

/// An inconsistency detected when all comparisons on a column are
/// taken together.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", schemars(rename = "ColumnConstraintIssue"))]
pub enum ColumnConstraintAnomaly {
    /// Equality or null comparisons on this column have no common
    /// satisfying value (e.g., `x = 1 AND x = 2`, `x = 1 AND x IS
    /// NULL`).
    EqualityDisjoint,
    /// Range bounds describe an empty interval (e.g., `x > 10 AND
    /// x < 5`, `x >= 10 AND x < 10`).
    RangeEmpty,
    /// One comparison on this column is implied by another (e.g.,
    /// `x > 3` is implied by `x > 5`).
    AtomSubsumed,
}

/// One detected OR-branch tautology: the disjunction's branches together
/// cover the entire value space, so the OR-expression contributes no
/// filtering.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", schemars(rename = "RedundantOrClause"))]
pub struct OrTautologyEvent {
    pub column: IdentName,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_span: Option<Span>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", schemars(rename = "SetOperation"))]
pub struct SetOpEvent {
    pub kind: SetOpKind,
    pub branch_count: u32,
    pub source_span: Option<Span>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", schemars(rename = "SetOperationType"))]
pub enum SetOpKind {
    Union,
    UnionAll,
    Intersect,
    IntersectAll,
    Except,
    ExceptAll,
    Minus,
}
