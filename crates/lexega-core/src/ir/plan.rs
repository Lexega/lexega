// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Relational-algebra plan tree.
//!
//! **Types and span accessors only.** No lowering, no analysis.
//!
//! # CLOSED ENUM
//!
//! `RelPlan` and every auxiliary enum in this file (`GroupingSpec`,
//! `FrameBound`, `FrameMode`, `FrameExclusion`, `JoinKind`, `SetOpKind`,
//! `MergeBranchKind`, `MergeAction`, `SampleMethod`, `CteBody`,
//! `TimeTravel`, `NullTreatment`, `OriginHint`) are **closed**: a new
//! variant is a deliberate design change. The exhaustive matches in
//! `schema.rs`, `visitor.rs`, `pretty.rs`, and `outer_refs.rs` fail
//! compilation on drift — that is the enforcement mechanism, not an
//! immutability claim.

use super::column::ColumnId;
use super::invalid_input::InvalidInputKind;
use super::scalar::{ScalarExpr, ScopeId};
use crate::ast::NodeId;
use crate::context::node_metadata::{IdentKey, TableRef, TaintLabel};
use crate::lexer::Span;

// ────────────────────────────────────────────────────────────────────────
// Top-level plan
// ────────────────────────────────────────────────────────────────────────

/// Relational-algebra plan node.
///
/// Every variant carries a `span` (source range) and, where relevant, a
/// `node_id` linking back to the originating AST node so error reports can
/// point at the user's code.
#[derive(Debug, Clone)]
pub enum RelPlan {
    // ── Sources ────────────────────────────────────────────────────────
    /// Base-table or view scan.
    Scan {
        table: TableRef,
        /// Columns materialized by this scan, in physical order. Analyses
        /// key off `ColumnId`, not names.
        columns: Vec<ColumnId>,
        modifier: ScanModifier,
        alias: Option<IdentKey>,
        /// Per-node `/*+ ... */` directives. Default empty.
        /// Distinct from `modifier.hints`, which carries SQL-level table
        /// hints attached to this scan in the source.
        hints: Vec<Hint>,
        node_id: NodeId,
        span: Span,
    },

    /// Row-literal source: `VALUES (…)` or `(SELECT 1)` rewritten to values.
    Values {
        rows: Vec<Vec<ScalarExpr>>,
        columns: Vec<ColumnId>,
        alias: Option<IdentKey>,
        /// Per-node `/*+ ... */` directives. Default empty.
        hints: Vec<Hint>,
        node_id: NodeId,
        span: Span,
    },

    /// Reference to a named CTE, resolved to the binding in some `WithScope`.
    CteRef {
        name: IdentKey,
        scope: ScopeId,
        columns: Vec<ColumnId>,
        /// Columns read through this reference that its binding's body
        /// exposes by star.
        demanded: Vec<DemandedColumn>,
        alias: Option<IdentKey>,
        /// Per-node `/*+ ... */` directives. Default empty.
        hints: Vec<Hint>,
        node_id: NodeId,
        span: Span,
    },

    /// dbt/cross-model reference (e.g. `{{ ref('my_model') }}` lowered).
    ModelRef {
        model: ResolvedModel,
        columns: Vec<ColumnId>,
        alias: Option<IdentKey>,
        /// Per-node `/*+ ... */` directives. Default empty.
        hints: Vec<Hint>,
        node_id: NodeId,
        span: Span,
    },

    // ── Unary relational ops ───────────────────────────────────────────
    /// Project / rename / compute-column.
    Project {
        input: Box<RelPlan>,
        items: Vec<ProjectItem>,
        /// `SELECT DISTINCT`.
        distinct: bool,
        /// Expressions for PostgreSQL `SELECT DISTINCT ON (e1, e2, ...)`.
        /// When non-empty, `distinct` is also `true`. Empty vec means
        /// either no DISTINCT or plain `SELECT DISTINCT` (no ON list).
        distinct_on: Vec<crate::ir::scalar::ScalarExpr>,
        /// Per-node `/*+ ... */` directives. Default empty.
        hints: Vec<Hint>,
        node_id: NodeId,
        span: Span,
    },

    /// `WHERE` or `QUALIFY`; `kind` records which clause produced the
    /// node so that per-clause flags (`has_where`, `has_qualify`)
    /// can be projected faithfully. `HAVING` is folded into
    /// `RelPlan::Aggregate`, not represented as a Filter.
    Filter {
        input: Box<RelPlan>,
        /// Select items the node computes for each input row before its
        /// predicate reads them, in select-list order: the computed aliases a
        /// block's `WHERE` reads where an `Aggregate` or a `Window` stands
        /// between it and the projection, none whose calls in one statement
        /// may differ (the current time is one value). An entry reads the
        /// node's input and the entries before it. Its output is a column of
        /// the node's output after the input's, and no column a star of the
        /// select list above yields. Empty for every other filter.
        computed: Vec<ComputedItem>,
        predicate: ScalarExpr,
        kind: FilterKind,
        /// Per-node `/*+ ... */` directives. Default empty.
        hints: Vec<Hint>,
        node_id: NodeId,
        span: Span,
    },

    /// `GROUP BY` plus aggregate expressions. `grouping` preserves
    /// CUBE / ROLLUP / GROUPING SETS / GROUP BY ALL shape.
    Aggregate {
        input: Box<RelPlan>,
        grouping: GroupingSpec,
        aggregates: Vec<AggregateCall>,
        /// `HAVING`, folded in.
        having: Option<ScalarExpr>,
        /// Output columns: grouping keys first, then aggregates.
        output_columns: Vec<ColumnId>,
        /// Select items the node computes for each input row before its
        /// aggregates read them, in select-list order. An entry reads the
        /// node's input and the entries before it. Its output is a column
        /// of the node's output after `output_columns`, and no column a
        /// star of the select list above yields.
        computed: Vec<ComputedItem>,
        /// Per-node `/*+ ... */` directives. Default empty.
        hints: Vec<Hint>,
        node_id: NodeId,
        span: Span,
    },

    /// A window stage: all window functions sharing the same
    /// `PARTITION BY` / `ORDER BY` / frame computed over `input`.
    ///
    /// **Schema note**: `window_outputs` enumerates only the freshly
    /// allocated `ColumnId`s for the window-function calls. The full
    /// output schema of this node is `input.output_schema() ∪
    /// window_outputs` — a Window operator passes every input row
    /// through and appends the window-call outputs. See
    /// [`RelPlan::output_schema`] in `schema.rs`; every fold over this
    /// node emits the input passthroughs alongside the window outputs.
    /// The outputs of `computed` follow them.
    Window {
        input: Box<RelPlan>,
        windows: Vec<WindowCall>,
        window_outputs: Vec<ColumnId>,
        /// Select items the node computes before its calls read them, in
        /// select-list order. An entry reads the node's input and the
        /// entries before it. Its output is no column a star of the
        /// select list above yields.
        computed: Vec<ComputedItem>,
        /// Per-node `/*+ ... */` directives. Default empty.
        hints: Vec<Hint>,
        node_id: NodeId,
        span: Span,
    },

    // ── Binary relational ops ──────────────────────────────────────────
    Join {
        left: Box<RelPlan>,
        right: Box<RelPlan>,
        kind: JoinKind,
        /// Explicit `ON` predicate. `None` when `USING`/`NATURAL` applies.
        on: Option<ScalarExpr>,
        /// Snowflake `ASOF JOIN MATCH_CONDITION(...)` predicate.
        /// `None` for every non-ASOF join.
        match_condition: Option<ScalarExpr>,
        /// The columns the join merges: the list of `USING (a, b, …)`,
        /// in its order; for a `NATURAL` join, each name both sides are
        /// known to hold, in the left side's order. Where the plan does
        /// not know every column of a side, those are the names it knows
        /// the side holds, and the join may merge names it does not list.
        /// A `NATURAL` join lists no column for a name the catalog shows
        /// several columns of on one side.
        using: Vec<UsingColumn>,
        natural: bool,
        /// Snowflake `DIRECTED` join-order modifier.
        directed: bool,
        /// Set for `CROSS APPLY`, `OUTER APPLY` and `LATERAL` written
        /// before `JOIN`, and for every join of a chain whose first item
        /// is written `LATERAL` (`FROM t, LATERAL (…) s JOIN u ON …`: the
        /// plain `JOIN u`). `JOIN LATERAL (…)` and `, LATERAL (…)` leave
        /// it false: there the keyword is on the right item, which may
        /// read the left side all the same.
        lateral: bool,
        /// Comma-join provenance. `true` when this Join was
        /// synthesized by the FROM-list comma loop (`SELECT … FROM a,
        /// b`); `false` for every explicit JOIN-keyword path including
        /// `CROSS JOIN`. Lowering-only metadata: analyses that care
        /// about cross-product risk should keep keying on
        /// `kind == Cross`. The single consumer is
        /// `derived_facts::has_implicit_cross_join`.
        implicit: bool,
        /// Per-node `/*+ ... */` directives. Default empty.
        hints: Vec<Hint>,
        node_id: NodeId,
        /// Subtree extent — `merge_spans(left.span(), join.span)`. Matches
        /// the `span:` semantic on every other [`RelPlan`] variant: the
        /// full extent covered by this plan node. For chained joins this
        /// grows monotonically with depth, so two sibling joins in the
        /// same FROM clause have the same `span` end. Use `clause_span`
        /// for per-join diagnostic anchors.
        span: Span,
        /// Span of just the join clause itself — for `customers c CROSS
        /// JOIN products p`, this is the span of `CROSS JOIN products p`
        /// (and ON/USING clause). Unlike `span`, this does NOT
        /// encompass the left subtree, so chained joins each carry a
        /// distinct `clause_span` that points at exactly their own
        /// clause. Drives `JoinEvent.source_span` for per-join Q-* rule
        /// diagnostics; predicate-event spans
        /// ([`JoinPredicateEvent`](crate::facts::query::JoinPredicateEvent), [`PredicateKind::JoinOn`](crate::facts::query::PredicateKind::JoinOn)) keep
        /// using `span` because cross-scope analyses identify
        /// predicates by their subtree extent.
        clause_span: Span,
    },

    /// `UNION` / `INTERSECT` / `EXCEPT` (and `ALL` / `DISTINCT`).
    SetOp {
        op: SetOpKind,
        inputs: Vec<Box<RelPlan>>,
        /// SQL:2011 `CORRESPONDING [BY (…)]`.
        corresponding: Option<Vec<IdentKey>>,
        /// Unified output columns. Each `ColumnId` has `ColumnOrigin::SetOp`.
        output_columns: Vec<ColumnId>,
        /// Per-node `/*+ ... */` directives. Default empty.
        hints: Vec<Hint>,
        node_id: NodeId,
        span: Span,
    },

    // ── Ordering / limiting ────────────────────────────────────────────
    Sort {
        input: Box<RelPlan>,
        keys: Vec<SortKey>,
        /// Per-node `/*+ ... */` directives. Default empty.
        hints: Vec<Hint>,
        node_id: NodeId,
        span: Span,
    },

    Limit {
        input: Box<RelPlan>,
        limit: Option<ScalarExpr>,
        offset: Option<ScalarExpr>,
        kind: LimitKind,
        /// `FETCH FIRST n ROWS WITH TIES`.
        with_ties: bool,
        /// Per-node `/*+ ... */` directives. Default empty.
        hints: Vec<Hint>,
        node_id: NodeId,
        span: Span,
    },

    // ── DML ─────────────────────────────────────────────────────────────
    /// `INSERT INTO target [(cols)] <source> [ON CONFLICT …]
    /// [RETURNING …] [OUTPUT …]`.
    ///
    /// `target_columns` is the ordered list of fresh [`ColumnId`]s the
    /// lowerer synthesized for the declared column list (one per name in
    /// the `(col1, col2, …)` clause; empty when no column list is given).
    /// Names are carried on the corresponding [`ColumnBinding`](crate::ir::column::ColumnBinding) side-table
    /// entry populated during lowering.
    ///
    /// `source` is a typed [`InsertSource`] — not a raw `RelPlan` — so
    /// `VALUES`, query-based inserts, and PostgreSQL `DEFAULT VALUES`
    /// stay distinguishable without a string blob. `on_conflict` is
    /// likewise a typed [`OnConflict`] rather than a string
    /// (stringly-typed fields are a silent-wrong-answer vector for taint
    /// analysis).
    Insert {
        target: TableRef,
        /// Node id of the target, shared with no other source or target;
        /// the target's columns are allocated on it.
        target_node: NodeId,
        target_columns: Vec<ColumnId>,
        /// Columns an INSERT with no column list writes, each read by
        /// name through the row it proposes or returns. No position of
        /// the source is known for them.
        unplaced_columns: Vec<ColumnId>,
        /// Columns of the row the INSERT proposes that it does not write:
        /// each holds the target column's default, a value of no source.
        defaulted_columns: Vec<ColumnId>,
        /// The target's columns the statement reads, each allocated on
        /// `target_node`.
        target_read_columns: Vec<ColumnId>,
        source: InsertSource,
        /// PostgreSQL `ON CONFLICT …` or, via alternate lowering,
        /// MySQL `ON DUPLICATE KEY UPDATE`.
        on_conflict: Option<OnConflict>,
        /// Snowflake / Databricks `INSERT OVERWRITE`: what it replaces.
        overwrite: Option<OverwriteScope>,
        /// Databricks `INSERT REPLACE INTO`.
        replace_into: bool,
        /// PostgreSQL `OVERRIDING { SYSTEM | USER } VALUE`.
        overriding: Option<OverridingValue>,
        /// PostgreSQL `RETURNING …`.
        returning: Option<Returning>,
        /// The columns `returning` reads under an updating conflict
        /// action: each holds what the inserted row has under its name or
        /// what the row the conflict update left has, a column the update
        /// writes or the target's stored one.
        returned_merges: Vec<ReturnedMerge>,
        /// T-SQL `OUTPUT … [INTO …]`.
        output: Option<DmlOutput>,
        /// MSSQL `INSERT INTO t WITH (TABLOCK)` table hints on the
        /// target. Shares the typed [`ScanTableHint`] / closed-enum
        /// [`ScanTableHintKind`] shape with FROM-clause scans: the
        /// underlying T-SQL grammar is the same (only argument-bearing
        /// hints rarely appear here, but representing both with one
        /// type lets analyses dispatch uniformly).
        target_hints: Vec<ScanTableHint>,
        /// Per-node `/*+ ... */` directives. Default empty.
        /// Distinct from `target_hints`, which models MSSQL `WITH (...)`
        /// table hints attached to the target relation.
        hints: Vec<Hint>,
        node_id: NodeId,
        span: Span,
    },

    Update {
        target: TableRef,
        /// Node id of the target, shared with no other source or target;
        /// the target's columns are allocated on it.
        target_node: NodeId,
        /// The target's columns the statement reads, each allocated on
        /// `target_node`.
        target_read_columns: Vec<ColumnId>,
        /// PostgreSQL `UPDATE ONLY parent`: the rows of the table alone,
        /// none of a table that inherits from it. Span covers `ONLY`.
        only: Option<Span>,
        assignments: Vec<Assignment>,
        /// Optional join / FROM clause lowered as a scan + filter.
        from: Option<Box<RelPlan>>,
        /// The FROM source that is the target's row, where the statement
        /// names its target by one; `None` where the target is a source of
        /// its own beside the FROM list, or there is none.
        target_row: Option<NodeId>,
        predicate: Option<ScalarExpr>,
        /// The cap on the rows it writes: T-SQL `UPDATE TOP (n) [PERCENT]`,
        /// MySQL `UPDATE … LIMIT n`.
        top: Option<DmlTop>,
        /// PostgreSQL `RETURNING …`.
        returning: Option<Returning>,
        /// T-SQL `OUTPUT … [INTO …]`.
        output: Option<DmlOutput>,
        /// Per-node `/*+ ... */` directives. Default empty.
        hints: Vec<Hint>,
        node_id: NodeId,
        span: Span,
    },

    Delete {
        target: TableRef,
        /// Node id of the target, shared with no other source or target;
        /// the target's columns are allocated on it.
        target_node: NodeId,
        /// The target's columns the statement reads, each allocated on
        /// `target_node`.
        target_read_columns: Vec<ColumnId>,
        /// Optional `USING` clause.
        using: Option<Box<RelPlan>>,
        /// The `USING` / FROM source that is the target's row, where the
        /// statement names its target by one; `None` otherwise.
        target_row: Option<NodeId>,
        /// The `USING` / FROM sources beside the target's row whose rows
        /// the statement deletes too: MySQL's further targets written
        /// before `FROM` (`DELETE t1, t2 FROM …`), each the source it names.
        deleted_sources: Vec<NodeId>,
        predicate: Option<ScalarExpr>,
        /// The cap on the rows it deletes: T-SQL `DELETE TOP (n) [PERCENT]`,
        /// MySQL `DELETE … LIMIT n`.
        top: Option<DmlTop>,
        /// PostgreSQL `RETURNING …`.
        returning: Option<Returning>,
        /// T-SQL `OUTPUT … [INTO …]`.
        output: Option<DmlOutput>,
        /// Per-node `/*+ ... */` directives. Default empty.
        hints: Vec<Hint>,
        node_id: NodeId,
        span: Span,
    },

    /// `MERGE INTO … USING …` with one or more branches.
    Merge {
        target: TableRef,
        /// Node id of the target, shared with no other source or target;
        /// the target's columns are allocated on it.
        target_node: NodeId,
        /// The target's columns the statement reads, each allocated on
        /// `target_node`.
        target_read_columns: Vec<ColumnId>,
        /// PostgreSQL `MERGE INTO ONLY parent`: the rows of the table
        /// alone, none of a table that inherits from it. Span covers
        /// `ONLY`.
        only: Option<Span>,
        source: Box<RelPlan>,
        on: ScalarExpr,
        branches: Vec<MergeBranch>,
        /// Databricks Delta `WITH SCHEMA EVOLUTION`.
        with_schema_evolution: bool,
        /// T-SQL `OUTPUT … [INTO …]`.
        output: Option<DmlOutput>,
        /// PostgreSQL `RETURNING …`.
        returning: Option<Returning>,
        /// The columns `returning` reads under a name the branches write:
        /// each holds what one of the branches writes under it, or the
        /// stored column where a branch writes none.
        returned_merges: Vec<ReturnedMerge>,
        /// Per-node `/*+ ... */` directives. Default empty.
        hints: Vec<Hint>,
        node_id: NodeId,
        span: Span,
    },

    /// Oracle / Snowflake `INSERT ALL` / `INSERT FIRST` with a trailing
    /// sub-query source. Distinct from [`RelPlan::Insert`] because the
    /// shape is one-source-to-N-targets and each target may have a WHEN
    /// guard; folding into `Insert` would conflate their taint/lineage
    /// semantics.
    MultiInsert {
        mode: MultiInsertMode,
        /// Top-level unconditional `INTO` clauses (unconditional variant).
        unconditional_clauses: Vec<MultiInsertTarget>,
        /// `WHEN cond THEN INTO …` blocks (conditional variants).
        when_clauses: Vec<MultiInsertWhen>,
        /// `ELSE INTO …` fallbacks (conditional variants only).
        else_clauses: Vec<MultiInsertTarget>,
        /// The source query feeding every target.
        source: Box<RelPlan>,
        /// Per-node `/*+ ... */` directives. Default empty.
        hints: Vec<Hint>,
        node_id: NodeId,
        span: Span,
    },

    /// PostgreSQL `EXPLAIN [ANALYZE] [VERBOSE] [(options)] <stmt>`.
    /// Wraps any DML/SELECT body; analyses can inspect the body while
    /// recognizing the statement is a plan request, not execution.
    Explain {
        body: Box<RelPlan>,
        options: ExplainOptions,
        /// Per-node `/*+ ... */` directives. Default empty.
        hints: Vec<Hint>,
        node_id: NodeId,
        span: Span,
    },

    // ── Create-as-query DDL ─────────────────────────────────────────────
    /// A DDL statement that materializes a named object from a query
    /// body: `CREATE [MATERIALIZED] VIEW`, `CREATE TABLE … AS SELECT`,
    /// `CREATE DYNAMIC [ICEBERG] TABLE`. The relational shape is
    /// identical across all three — `target + body + kind-specific
    /// options` — so they are unified into one variant discriminated
    /// by [`CreateAsKind`] rather than split into three. Kind-specific
    /// flags live on `CreateAsKind`; dialect-specific side options
    /// that do not change the semantics of `body` (warehouse,
    /// target_lag, refresh_mode, partition_by, cluster_by, row
    /// access policies, copy_grants, tags, comments, BigQuery
    /// REPLICA OF, …) travel in `side_options` as typed
    /// [`CreateSideOption`] entries so baseline diffs distinguish
    /// which option changed without parsing string blobs.
    CreateAsQuery {
        target: TableRef,
        kind: CreateAsKind,
        /// Declared column list, e.g. `CREATE VIEW v (c1, c2) AS …`.
        /// `None` when no explicit list was written.
        columns: Option<Vec<IdentKey>>,
        /// Lowered inner SELECT / SetSelect / WITH when the statement
        /// has a relational body.
        ///
        /// Replica-only materialized-view forms such as BigQuery
        /// `AS REPLICA OF ...` have no query body and therefore carry
        /// `None` here while still preserving their typed side option.
        body: Option<Box<RelPlan>>,
        or_replace: bool,
        /// T-SQL `CREATE OR ALTER VIEW`.
        or_alter: bool,
        if_not_exists: bool,
        /// Snowflake `COPY GRANTS` (applies to view, CTAS, and
        /// dynamic table; meaning differs per object but the flag is
        /// boolean-shaped in each).
        copy_grants: bool,
        /// Typed-span side options. See [`CreateSideOption`].
        side_options: Vec<CreateSideOption>,
        /// Per-node `/*+ ... */` directives. Default empty.
        hints: Vec<Hint>,
        node_id: NodeId,
        span: Span,
    },

    // ── Non-query-bearing DDL ───────────────────────────────────────────
    /// A `CREATE TABLE` statement whose variant does not carry a query body.
    ///
    /// `CreateAsQuery` handles `CTAS` / `CREATE VIEW` / `CREATE DYNAMIC TABLE`
    /// (all query-bearing). This variant covers the remaining discriminants
    /// of [`crate::ast::AstCreateTableVariant`]: `Plain`, `Like`, `Clone`,
    /// `UsingTemplate`, `FromArchive`, `FromSnapshotSet`.
    ///
    /// Non-query-bearing means the plan tree has no inner `RelPlan` child,
    /// so all analyses produce empty/no-op results for this node. The `target`
    /// carries the table name so rules that audit DDL targets can still
    /// observe it.
    CreateTableForm {
        target: TableRef,
        /// Which non-query-bearing variant this statement is.
        kind: CreateTableFormKind,
        /// Declared column list (e.g. `CREATE TABLE t (a INT, b TEXT)`).
        /// `None` for `LIKE`/`Clone` forms that inherit columns from source.
        columns: Option<Vec<IdentKey>>,
        /// Source table for `LIKE` and `Clone` forms. `None` for `Plain`,
        /// `UsingTemplate`, `FromArchive`, `FromSnapshotSet`.
        source: Option<TableRef>,
        or_replace: bool,
        if_not_exists: bool,
        /// Per-node `/*+ ... */` directives. Default empty.
        hints: Vec<Hint>,
        stmt_node_id: NodeId,
        span: Span,
    },

    // ── CTE scoping ─────────────────────────────────────────────────────
    /// `WITH … SELECT …` / `WITH … INSERT …` etc. Body may be any `RelPlan`
    /// (not only queries).
    WithScope {
        ctes: Vec<CteBinding>,
        body: Box<RelPlan>,
        recursive: bool,
        /// Per-node `/*+ ... */` directives. Default empty.
        hints: Vec<Hint>,
        node_id: NodeId,
        span: Span,
    },

    /// `FROM (SELECT …) alias` — derived-table scope boundary.
    ///
    /// Wraps the lowered inner plan so fact projection and lineage
    /// treat the subquery as a closed scope: inner WHERE / joins /
    /// aggregates do not leak into the enclosing plan's flat facts,
    /// while `tables_read` and CTE references still propagate.
    /// `columns` are fresh outer-scope [`ColumnId`]s the lineage
    /// pass wires back to the corresponding slot in
    /// `input.output_schema()`; `alias` is the outer-scope binding
    /// name (required by ANSI SQL for derived tables, but lowering
    /// tolerates `None` for dialects that relax it).
    DerivedTable {
        input: Box<RelPlan>,
        alias: Option<IdentKey>,
        columns: Vec<ColumnId>,
        /// Declared column-list rename (`AS t(c1, c2, …)`). Empty
        /// when the user wrote no rename. Carried separately from
        /// `columns` (which holds outer-scope `ColumnId`s) so that
        /// downstream projections (e.g. the
        /// `derived_tables` shape) can surface the
        /// raw declared names without round-tripping through the
        /// `BindingTable`. Mirrors `CteBinding.declared_columns`.
        alias_columns: Vec<IdentKey>,
        /// The body column each of `columns` is, by position in `columns`;
        /// `None` where it cannot be known.
        body_columns: Vec<Option<ColumnId>>,
        /// Per-node `/*+ ... */` directives. Default empty.
        hints: Vec<Hint>,
        node_id: NodeId,
        span: Span,
    },

    /// Table-valued function as a FROM source — `FROM TABLE(my_udtf(x))`,
    /// `FROM FLATTEN(input => arr) f`, `FROM UNNEST(@arr) u(val)`.
    ///
    /// `call` is the function call as a [`ScalarExpr`] so argument
    /// subqueries, correlated refs, and inline `TABLE(ident)` object
    /// references propagate through the normal scalar walk. The
    /// function name itself is *not* a base-table reference (arguments
    /// are walked, but the function name is excluded from
    /// `tables_read`).
    ///
    /// `output_columns` carries the [`ColumnId`]s the enclosing block
    /// reads from this TVF, listed once the statement is lowered. True
    /// arity is catalog-dependent; this keeps whatever names the outer
    /// scope bound.
    ///
    /// `lateral` records whether `LATERAL` was present. Snowflake
    /// requires it for correlation; BigQuery / T-SQL allow implicit
    /// correlation; PostgreSQL requires it.
    ///
    /// `modifier` follows the same layout as [`Scan`](Self::Scan)'s modifier: it
    /// carries time travel, changes, stage options, sample, with_offset,
    /// only, table_hints, and tvf_schema. Snowflake permits time-travel
    /// and changes on TVF outputs; T-SQL OPENJSON carries `tvf_schema`;
    /// BigQuery UNNEST carries `with_offset`. Having a single typed slot
    /// means analyses don't need separate TVF-specific paths.
    TableFunction {
        call: ScalarExpr,
        alias: Option<IdentKey>,
        output_columns: Vec<ColumnId>,
        lateral: bool,
        modifier: ScanModifier,
        /// Per-node `/*+ ... */` directives. Default empty.
        hints: Vec<Hint>,
        node_id: NodeId,
        span: Span,
    },

    // ── Dialect-exotic typed variants ───────────────────────────────────
    /// `CROSS JOIN UNNEST(array)` / lateral table-valued `FLATTEN`.
    Unnest {
        input: Box<RelPlan>,
        array: ScalarExpr,
        value_column: ColumnId,
        ordinality_column: Option<ColumnId>,
        /// `WITH OFFSET` / `OUTER UNNEST` etc.
        with_offset: bool,
        preserve_nulls: bool,
        /// Per-node `/*+ ... */` directives. Default empty.
        hints: Vec<Hint>,
        node_id: NodeId,
        span: Span,
    },

    Pivot {
        input: Box<RelPlan>,
        /// Non-empty; order-preserving. `PIVOT` grammar permits
        /// multiple comma-separated aggregates.
        aggregates: Vec<AggregateCall>,
        pivot_column: ColumnId,
        /// `FOR col IN (…)` — the shape of the IN list. Closed enum;
        /// covers the four parser shapes.
        pivot_values: PivotValues,
        output_columns: Vec<ColumnId>,
        /// `DEFAULT ON NULL(<expr>)` (Snowflake).
        default_on_null: Option<ScalarExpr>,
        /// Per-node `/*+ ... */` directives. Default empty.
        hints: Vec<Hint>,
        node_id: NodeId,
        span: Span,
    },

    Unpivot {
        input: Box<RelPlan>,
        /// `UNPIVOT (<value_columns>)` — length ≥ 1; equal to each
        /// tuple length in `unpivoted_columns`.
        value_columns: Vec<ColumnId>,
        name_column: ColumnId,
        /// Tuple-shaped source-column groups.
        unpivoted_columns: Vec<UnpivotColumn>,
        include_nulls: bool,
        /// Per-node `/*+ ... */` directives. Default empty.
        hints: Vec<Hint>,
        node_id: NodeId,
        span: Span,
    },

    /// `MATCH_RECOGNIZE` pattern matching (Snowflake/Oracle).
    MatchRecognize {
        input: Box<RelPlan>,
        /// Fully typed body — partition keys, ordering, measures,
        /// pattern (parsed to `PatternExpr` at lowering), and
        /// `DEFINE` predicates.
        body: MatchRecognizeBody,
        output_columns: Vec<ColumnId>,
        /// Per-node `/*+ ... */` directives. Default empty.
        hints: Vec<Hint>,
        node_id: NodeId,
        span: Span,
    },

    /// `CONNECT BY` hierarchical query (Oracle), over the rows of its
    /// block's FROM, below the block's `WHERE`.
    ConnectBy {
        input: Box<RelPlan>,
        start_with: Option<ScalarExpr>,
        connect: ScalarExpr,
        nocycle: bool,
        /// The input's columns, then `pseudo_columns`.
        output_columns: Vec<ColumnId>,
        /// The columns the block reads of the values the traversal makes
        /// for each row (`LEVEL`, `CONNECT_BY_ISLEAF`,
        /// `CONNECT_BY_ISCYCLE`), in the order first read: numbers, never
        /// NULL, computed by this node.
        pseudo_columns: Vec<ColumnId>,
        /// Per-node `/*+ ... */` directives. Default empty.
        hints: Vec<Hint>,
        node_id: NodeId,
        span: Span,
    },

    /// `TABLESAMPLE` / `SAMPLE`.
    TableSample {
        input: Box<RelPlan>,
        sample: TableSample,
        /// Per-node `/*+ ... */` directives. Default empty.
        hints: Vec<Hint>,
        node_id: NodeId,
        span: Span,
    },

    // ── Ill-formed-input terminal ──────────────────────────────────────
    /// User input that survived parsing but is semantically ill-formed
    /// in its enclosing context. Captures the failure shape as a typed
    /// terminal so every analysis still walks the surrounding plan and
    /// the ill-formedness is visible to rules. Distinct from `Opaque`:
    /// `InvalidInput` is the typed answer, not a coverage gap.
    InvalidInput {
        stmt_node_id: NodeId,
        kind: InvalidInputKind,
        /// Per-node `/*+ ... */` directives. Default empty.
        hints: Vec<Hint>,
        span: Span,
    },

    // ── Parser-recovery terminals ──────────────────────────────────────
    /// A fragment the parser recovered from but could not structure
    /// for lowering. Unlike `Opaque` this is not a coverage gap — it
    /// is the typed diagnosis of a parser-level failure preserved so
    /// surrounding analyses can still walk the rest of the plan tree.
    ParseRecovery {
        stmt_node_id: NodeId,
        /// Per-node `/*+ ... */` directives. Default empty.
        hints: Vec<Hint>,
        span: Span,
    },

    // ── Opaque fallback ────────────────────────────────────────────────
    /// Statement or fragment the parser could not structure. Preserved so
    /// the formatter round-trips and so baseline parity can exclude these.
    Opaque {
        stmt_node_id: NodeId,
        reason: super::strict::OpaqueReason,
        /// Per-node `/*+ ... */` directives. Default empty.
        hints: Vec<Hint>,
        span: Span,
    },
}

impl RelPlan {
    /// Node id of this plan node: its own `node_id`, or the statement's
    /// for the variants that carry only `stmt_node_id`.
    pub fn node_id(&self) -> NodeId {
        match self {
            RelPlan::Scan { node_id, .. }
            | RelPlan::Values { node_id, .. }
            | RelPlan::CteRef { node_id, .. }
            | RelPlan::ModelRef { node_id, .. }
            | RelPlan::Project { node_id, .. }
            | RelPlan::Filter { node_id, .. }
            | RelPlan::Aggregate { node_id, .. }
            | RelPlan::Window { node_id, .. }
            | RelPlan::Join { node_id, .. }
            | RelPlan::SetOp { node_id, .. }
            | RelPlan::Sort { node_id, .. }
            | RelPlan::Limit { node_id, .. }
            | RelPlan::Insert { node_id, .. }
            | RelPlan::Update { node_id, .. }
            | RelPlan::Delete { node_id, .. }
            | RelPlan::Merge { node_id, .. }
            | RelPlan::MultiInsert { node_id, .. }
            | RelPlan::Explain { node_id, .. }
            | RelPlan::CreateAsQuery { node_id, .. }
            | RelPlan::WithScope { node_id, .. }
            | RelPlan::DerivedTable { node_id, .. }
            | RelPlan::TableFunction { node_id, .. }
            | RelPlan::Unnest { node_id, .. }
            | RelPlan::Pivot { node_id, .. }
            | RelPlan::Unpivot { node_id, .. }
            | RelPlan::MatchRecognize { node_id, .. }
            | RelPlan::ConnectBy { node_id, .. }
            | RelPlan::TableSample { node_id, .. } => *node_id,
            RelPlan::CreateTableForm { stmt_node_id, .. }
            | RelPlan::InvalidInput { stmt_node_id, .. }
            | RelPlan::ParseRecovery { stmt_node_id, .. }
            | RelPlan::Opaque { stmt_node_id, .. } => *stmt_node_id,
        }
    }

    /// Source span of this plan node.
    pub fn span(&self) -> Span {
        match self {
            RelPlan::Scan { span, .. }
            | RelPlan::Values { span, .. }
            | RelPlan::CteRef { span, .. }
            | RelPlan::ModelRef { span, .. }
            | RelPlan::Project { span, .. }
            | RelPlan::Filter { span, .. }
            | RelPlan::Aggregate { span, .. }
            | RelPlan::Window { span, .. }
            | RelPlan::Join { span, .. }
            | RelPlan::SetOp { span, .. }
            | RelPlan::Sort { span, .. }
            | RelPlan::Limit { span, .. }
            | RelPlan::Insert { span, .. }
            | RelPlan::Update { span, .. }
            | RelPlan::Delete { span, .. }
            | RelPlan::Merge { span, .. }
            | RelPlan::MultiInsert { span, .. }
            | RelPlan::Explain { span, .. }
            | RelPlan::CreateAsQuery { span, .. }
            | RelPlan::CreateTableForm { span, .. }
            | RelPlan::WithScope { span, .. }
            | RelPlan::DerivedTable { span, .. }
            | RelPlan::TableFunction { span, .. }
            | RelPlan::Unnest { span, .. }
            | RelPlan::Pivot { span, .. }
            | RelPlan::Unpivot { span, .. }
            | RelPlan::MatchRecognize { span, .. }
            | RelPlan::ConnectBy { span, .. }
            | RelPlan::TableSample { span, .. }
            | RelPlan::InvalidInput { span, .. }
            | RelPlan::ParseRecovery { span, .. }
            | RelPlan::Opaque { span, .. } => *span,
        }
    }

    /// Per-node `/*+ ... */` query hints attached to this plan node.
    /// Returns an empty slice when no hint was present in the source.
    /// Exhaustive over every `RelPlan` variant — adding a new variant
    /// fails compilation here.
    ///
    /// This slot is the per-node hint surface every `RelPlan` variant
    /// carries. `RelPlan::Scan` additionally has a `modifier.hints`
    /// slot for SQL-level table hints; those are reachable
    /// via the `Scan` destructure and are *not* unioned in here.
    pub fn hints(&self) -> &[Hint] {
        match self {
            RelPlan::Scan { hints, .. }
            | RelPlan::Values { hints, .. }
            | RelPlan::CteRef { hints, .. }
            | RelPlan::ModelRef { hints, .. }
            | RelPlan::Project { hints, .. }
            | RelPlan::Filter { hints, .. }
            | RelPlan::Aggregate { hints, .. }
            | RelPlan::Window { hints, .. }
            | RelPlan::Join { hints, .. }
            | RelPlan::SetOp { hints, .. }
            | RelPlan::Sort { hints, .. }
            | RelPlan::Limit { hints, .. }
            | RelPlan::Insert { hints, .. }
            | RelPlan::Update { hints, .. }
            | RelPlan::Delete { hints, .. }
            | RelPlan::Merge { hints, .. }
            | RelPlan::MultiInsert { hints, .. }
            | RelPlan::Explain { hints, .. }
            | RelPlan::CreateAsQuery { hints, .. }
            | RelPlan::CreateTableForm { hints, .. }
            | RelPlan::WithScope { hints, .. }
            | RelPlan::DerivedTable { hints, .. }
            | RelPlan::TableFunction { hints, .. }
            | RelPlan::Unnest { hints, .. }
            | RelPlan::Pivot { hints, .. }
            | RelPlan::Unpivot { hints, .. }
            | RelPlan::MatchRecognize { hints, .. }
            | RelPlan::ConnectBy { hints, .. }
            | RelPlan::TableSample { hints, .. }
            | RelPlan::InvalidInput { hints, .. }
            | RelPlan::ParseRecovery { hints, .. }
            | RelPlan::Opaque { hints, .. } => hints.as_slice(),
        }
    }

    /// If this plan is a CTE-body-shaped pure `SELECT *` over a single
    /// upstream input, return that input. Otherwise `None`.
    ///
    /// "Pure star-passthrough" is decidable purely from plan shape: the
    /// top-level node is a [`RelPlan::Project`] whose every item is a
    /// vanilla unqualified [`ProjectItem::Star`] — no qualifier, no
    /// `EXCLUDE` / `REPLACE` / `RENAME` / `ILIKE` modifiers. Mixed bags
    /// (any `ProjectItem::Expr`, or any modifier-bearing star, or a
    /// non-`Unqualified` qualifier) yield `None` and force callers to
    /// fall back to the standard [`Self::output_schema`] path.
    ///
    /// This is the **structural definition** of `*`: when the projection
    /// contains nothing but vanilla stars, the SQL semantics is "every
    /// column of the input, in order". The IR does not pre-expand the
    /// `Star` variant at lowering time, so
    /// downstream consumers consult this method to realize the binding's
    /// *effective* arity and per-slot deps without touching the plan
    /// tree.
    pub fn cte_body_star_passthrough_input(&self) -> Option<&RelPlan> {
        let RelPlan::Project { items, input, .. } = self else {
            return None;
        };
        if items.is_empty() {
            return None;
        }
        for it in items {
            let s = match it {
                ProjectItem::Star(s) => s,
                ProjectItem::Expr(_) => return None,
            };
            if !matches!(s.qualifier, StarQualifier::Unqualified) {
                return None;
            }
            if !s.exclude.is_empty()
                || !s.replace.is_empty()
                || !s.rename.is_empty()
                || s.ilike.is_some()
            {
                return None;
            }
        }
        Some(input.as_ref())
    }

    /// If this plan is a CTE body of the shape
    /// `SELECT * [FROM <single-source>]` — possibly wrapped through
    /// pure-passthrough operators (`Filter` / `Sort` / `Limit` /
    /// `TableSample`) — and the single source is a [`RelPlan::Scan`],
    /// return the leaf Scan's `node_id`. Otherwise `None`.
    ///
    /// Such a body lists no visible columns of its own
    /// ([`Self::cte_visible_output_schema`]): the scan's listed columns
    /// are the ones the statement read, not the table's width, and a
    /// column read through a reference to the body is demanded from it
    /// instead.
    ///
    /// Recursion only descends through `Filter` / `Sort` / `Limit` /
    /// `TableSample` / `Window` (operators that preserve every input
    /// column 1-to-1 and never drop or reorder). `Window` adds new
    /// output columns to the row schema but does not modify or
    /// shadow the inputs, so an unqualified column reference through
    /// a CTE wrapping `Window { Scan }` resolves identically to a
    /// reference through the bare Scan; the dbt snapshot pattern
    /// `SELECT * FROM t QUALIFY ROW_NUMBER() OVER (...) = 1` lowers
    /// to `Project[Star] → Filter(Qualify) → Window → Scan` and
    /// relies on this. Joins, set-ops, and nested CteRefs are
    /// explicitly excluded — those shapes have either multiple
    /// sources or a non-Scan leaf and require the generic
    /// positional path.
    pub fn cte_body_star_passthrough_leaf_scan_node(&self) -> Option<NodeId> {
        let inner = self.cte_body_star_passthrough_input()?;
        let mut cursor = inner;
        loop {
            match cursor {
                RelPlan::Scan { node_id, .. } => return Some(*node_id),
                RelPlan::Filter { input, .. }
                | RelPlan::Sort { input, .. }
                | RelPlan::Limit { input, .. }
                | RelPlan::TableSample { input, .. }
                | RelPlan::Window { input, .. } => {
                    cursor = input.as_ref();
                }
                // Every other variant disqualifies the cursor.
                // Listed exhaustively so a future RelPlan variant
                // surfaces here for explicit classification rather
                // than silently being swallowed by a catch-all.
                RelPlan::Values { .. }
                | RelPlan::CteRef { .. }
                | RelPlan::ModelRef { .. }
                | RelPlan::Project { .. }
                | RelPlan::Aggregate { .. }
                | RelPlan::Join { .. }
                | RelPlan::SetOp { .. }
                | RelPlan::Insert { .. }
                | RelPlan::Update { .. }
                | RelPlan::Delete { .. }
                | RelPlan::Merge { .. }
                | RelPlan::MultiInsert { .. }
                | RelPlan::Explain { .. }
                | RelPlan::CreateAsQuery { .. }
                | RelPlan::CreateTableForm { .. }
                | RelPlan::WithScope { .. }
                | RelPlan::DerivedTable { .. }
                | RelPlan::TableFunction { .. }
                | RelPlan::Unnest { .. }
                | RelPlan::Pivot { .. }
                | RelPlan::Unpivot { .. }
                | RelPlan::MatchRecognize { .. }
                | RelPlan::ConnectBy { .. }
                | RelPlan::InvalidInput { .. }
                | RelPlan::ParseRecovery { .. }
                | RelPlan::Opaque { .. } => return None,
            }
        }
    }

    /// The `RETURNING` list of the `INSERT`, `UPDATE`, `DELETE` or `MERGE`
    /// this plan is, under any `WithScope`: the rows a binding over the
    /// plan hands its references. `None` for any other plan and for a
    /// statement with no list.
    pub(crate) fn returned_at_root(&self) -> Option<&Returning> {
        let mut cursor = self;
        loop {
            match cursor {
                RelPlan::WithScope { body, .. } => cursor = body.as_ref(),
                RelPlan::Insert { returning, .. }
                | RelPlan::Update { returning, .. }
                | RelPlan::Delete { returning, .. }
                | RelPlan::Merge { returning, .. } => return returning.as_ref(),
                RelPlan::Scan { .. }
                | RelPlan::Values { .. }
                | RelPlan::CteRef { .. }
                | RelPlan::ModelRef { .. }
                | RelPlan::Project { .. }
                | RelPlan::Filter { .. }
                | RelPlan::Aggregate { .. }
                | RelPlan::Window { .. }
                | RelPlan::Join { .. }
                | RelPlan::SetOp { .. }
                | RelPlan::Sort { .. }
                | RelPlan::Limit { .. }
                | RelPlan::MultiInsert { .. }
                | RelPlan::Explain { .. }
                | RelPlan::CreateAsQuery { .. }
                | RelPlan::CreateTableForm { .. }
                | RelPlan::DerivedTable { .. }
                | RelPlan::TableFunction { .. }
                | RelPlan::Unnest { .. }
                | RelPlan::Pivot { .. }
                | RelPlan::Unpivot { .. }
                | RelPlan::MatchRecognize { .. }
                | RelPlan::ConnectBy { .. }
                | RelPlan::TableSample { .. }
                | RelPlan::InvalidInput { .. }
                | RelPlan::ParseRecovery { .. }
                | RelPlan::Opaque { .. } => return None,
            }
        }
    }

    /// The select list that names the columns of the query this plan is,
    /// under any `WithScope`, `Sort` or `Limit`: its outermost `Project`'s
    /// items, or those of a set operation's first branch, which name its
    /// columns by position; and that `Project`'s input. `None` for any
    /// other plan, and for a set operation that pairs its branches'
    /// columns by name (`CORRESPONDING`).
    pub(crate) fn naming_select_at_root(&self) -> Option<(&RelPlan, &[ProjectItem])> {
        let mut cursor = self;
        loop {
            match cursor {
                RelPlan::WithScope { body, .. } => cursor = body.as_ref(),
                RelPlan::Sort { input, .. } | RelPlan::Limit { input, .. } => {
                    cursor = input.as_ref()
                }
                RelPlan::SetOp {
                    inputs,
                    corresponding: None,
                    ..
                } => cursor = inputs.first()?.as_ref(),
                RelPlan::Project { input, items, .. } => return Some((input.as_ref(), items)),
                RelPlan::SetOp {
                    corresponding: Some(_),
                    ..
                }
                | RelPlan::Scan { .. }
                | RelPlan::Values { .. }
                | RelPlan::CteRef { .. }
                | RelPlan::ModelRef { .. }
                | RelPlan::Filter { .. }
                | RelPlan::Aggregate { .. }
                | RelPlan::Window { .. }
                | RelPlan::Join { .. }
                | RelPlan::Insert { .. }
                | RelPlan::Update { .. }
                | RelPlan::Delete { .. }
                | RelPlan::Merge { .. }
                | RelPlan::MultiInsert { .. }
                | RelPlan::Explain { .. }
                | RelPlan::CreateAsQuery { .. }
                | RelPlan::CreateTableForm { .. }
                | RelPlan::DerivedTable { .. }
                | RelPlan::TableFunction { .. }
                | RelPlan::Unnest { .. }
                | RelPlan::Pivot { .. }
                | RelPlan::Unpivot { .. }
                | RelPlan::MatchRecognize { .. }
                | RelPlan::ConnectBy { .. }
                | RelPlan::TableSample { .. }
                | RelPlan::InvalidInput { .. }
                | RelPlan::ParseRecovery { .. }
                | RelPlan::Opaque { .. } => return None,
            }
        }
    }

    /// The item with output `column` that a block computes before its
    /// calls or its `WHERE`, where `self` is the input of the block's
    /// `Project`: looked for in the block's filters, `Window` and
    /// `Aggregate`, and in the `WHERE` under the `Aggregate`.
    pub fn computed_before_calls(&self, column: ColumnId) -> Option<&ComputedItem> {
        self.computed_before_calls_at(column).map(|(_, item)| item)
    }

    /// [`Self::computed_before_calls`], with the node that computes it.
    pub(crate) fn computed_before_calls_at(
        &self,
        column: ColumnId,
    ) -> Option<(&RelPlan, &ComputedItem)> {
        let mut cursor = self;
        loop {
            let node = cursor;
            let computed = match cursor {
                RelPlan::Filter {
                    input, computed, ..
                }
                | RelPlan::Window {
                    input, computed, ..
                } => {
                    cursor = input.as_ref();
                    computed
                }
                // Below an `Aggregate` only the block's `WHERE` computes
                // any.
                RelPlan::Aggregate {
                    input, computed, ..
                } => {
                    let mut found = computed
                        .iter()
                        .find(|item| item.output == column)
                        .map(|item| (node, item));
                    let mut below = input.as_ref();
                    while let (
                        None,
                        RelPlan::Filter {
                            input, computed, ..
                        },
                    ) = (found, below)
                    {
                        found = computed
                            .iter()
                            .find(|item| item.output == column)
                            .map(|item| (below, item));
                        below = input.as_ref();
                    }
                    return found;
                }
                RelPlan::Scan { .. }
                | RelPlan::Values { .. }
                | RelPlan::CteRef { .. }
                | RelPlan::ModelRef { .. }
                | RelPlan::Project { .. }
                | RelPlan::Join { .. }
                | RelPlan::SetOp { .. }
                | RelPlan::Sort { .. }
                | RelPlan::Limit { .. }
                | RelPlan::Insert { .. }
                | RelPlan::Update { .. }
                | RelPlan::Delete { .. }
                | RelPlan::Merge { .. }
                | RelPlan::MultiInsert { .. }
                | RelPlan::Explain { .. }
                | RelPlan::CreateAsQuery { .. }
                | RelPlan::CreateTableForm { .. }
                | RelPlan::WithScope { .. }
                | RelPlan::DerivedTable { .. }
                | RelPlan::TableFunction { .. }
                | RelPlan::Unnest { .. }
                | RelPlan::Pivot { .. }
                | RelPlan::Unpivot { .. }
                | RelPlan::MatchRecognize { .. }
                | RelPlan::ConnectBy { .. }
                | RelPlan::TableSample { .. }
                | RelPlan::InvalidInput { .. }
                | RelPlan::ParseRecovery { .. }
                | RelPlan::Opaque { .. } => return None,
            };
            if let Some(item) = computed.iter().find(|item| item.output == column) {
                return Some((node, item));
            }
        }
    }
}

// ────────────────────────────────────────────────────────────────────────
// Supporting types
// ────────────────────────────────────────────────────────────────────────

/// Which clause produced a `RelPlan::Filter`. All three share the
/// same relational shape (a predicate over a sub-plan) but are
/// exposed as distinct flags to analyses / rules. `HAVING`
/// remains folded into `RelPlan::Aggregate.having` for predicates
/// whose column refs all resolve through the Aggregate's output
/// schema; the `Having` variant is reserved for HAVING predicates
/// that reference SELECT-list aliases and are therefore lifted as
/// a separate `Filter` *above* `Project`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FilterKind {
    /// `WHERE`.
    Where,
    /// `QUALIFY`.
    Qualify,
    /// `HAVING` lifted above `Project` because its predicate
    /// references SELECT-list aliases. Non-alias HAVING stays in
    /// `Aggregate.having`.
    Having,
}

/// One output item of a `Project` node — either a computed column or a
/// star expansion.
///
/// Closed enum: every consumer matches exhaustively; no `_ =>`.
#[derive(Debug, Clone)]
pub enum ProjectItem {
    /// `<expr> [AS <alias>]` — a single computed output column.
    Expr(ProjectExpr),
    /// `* | <qual>.* | <expr>.*` with optional Snowflake / BigQuery
    /// modifiers. Column enumeration is catalog-dependent and happens
    /// after lowering; the IR preserves the structural information
    /// `StarProjectionInfo` records so its shape is exact without
    /// requiring a catalog.
    Star(ProjectStar),
}

impl ProjectItem {
    /// Source span of this projection item.
    pub fn span(&self) -> Span {
        match self {
            ProjectItem::Expr(e) => e.span,
            ProjectItem::Star(s) => s.span,
        }
    }
}

/// A column a `Window` or an `Aggregate` computes before its calls: the
/// expression of a select item one of those calls reads through its
/// alias, where the expression holds a nested plan or a call to a
/// volatile function, or reads another such column, and so is in the
/// plan once. The select item is a bare read of `output`. A `Filter`
/// computes one before its predicate reads it.
#[derive(Debug, Clone)]
pub struct ComputedItem {
    pub output: ColumnId,
    pub expr: ScalarExpr,
}

/// A single computed output column `<expr> [AS <alias>]`.
#[derive(Debug, Clone)]
pub struct ProjectExpr {
    /// The `ColumnId` this item produces in the output.
    pub output: ColumnId,
    pub expr: ScalarExpr,
    pub alias: Option<IdentKey>,
    pub span: Span,
}

impl ProjectExpr {
    /// The expression the query wrote for the item, where the item's own
    /// is a bare read of what its block computes before its calls: that
    /// [`ComputedItem`]'s expression, and the item's own otherwise.
    /// `input` is the input of the item's `Project`.
    pub fn as_written<'p>(&'p self, input: &'p RelPlan) -> &'p ScalarExpr {
        match &self.expr {
            ScalarExpr::Column { column, .. } => input
                .computed_before_calls(*column)
                .map_or(&self.expr, |item| &item.expr),
            ScalarExpr::OuterRef { .. }
            | ScalarExpr::PatternVarRef { .. }
            | ScalarExpr::Lit { .. }
            | ScalarExpr::Opaque { .. }
            | ScalarExpr::BinOp { .. }
            | ScalarExpr::LogicalChain { .. }
            | ScalarExpr::OperatorChain { .. }
            | ScalarExpr::UnaryOp { .. }
            | ScalarExpr::FuncCall { .. }
            | ScalarExpr::Case { .. }
            | ScalarExpr::Cast { .. }
            | ScalarExpr::InList { .. }
            | ScalarExpr::Between { .. }
            | ScalarExpr::Like { .. }
            | ScalarExpr::Exists { .. }
            | ScalarExpr::ScalarSubquery { .. }
            | ScalarExpr::QuantifiedCmp { .. }
            | ScalarExpr::RowCmp { .. }
            | ScalarExpr::WindowFn { .. }
            | ScalarExpr::FieldAccess { .. }
            | ScalarExpr::Lambda { .. } => &self.expr,
        }
    }
}

/// A star projection with Snowflake / BigQuery-style modifiers.
///
/// The `Star` variant is deliberately *not* expanded to a list of
/// concrete `ColumnId`s at lowering time — that requires the catalog.
/// Lowering captures the qualifier and modifier bag faithfully so the
/// flat `StarProjectionInfo` can be reconstructed from the IR.
#[derive(Debug, Clone)]
pub struct ProjectStar {
    pub qualifier: StarQualifier,
    /// `* EXCLUDE (c1, c2)` / `* EXCLUDE c`. Each entry preserves the
    /// source span so fact projection can recover quote/case-preserving
    /// text via `slice_span`.
    pub exclude: Vec<StarExclude>,
    /// `* REPLACE (<expr> AS <col>, …)` — per-column expression
    /// overrides. Scalar expressions are lowered so nested subqueries
    /// / correlated refs propagate through the normal visitor walk.
    pub replace: Vec<StarReplace>,
    /// `* RENAME (<from> AS <to>, …)` — per-column output-name renames.
    pub rename: Vec<StarRename>,
    /// BigQuery-style `* ILIKE '<pat>'` name filter. Stored with the
    /// SQL-string semantics applied (enclosing quotes stripped, `''`→`'`
    /// unescape) so it matches what `extract_string_literal_value`
    /// produces.
    pub ilike: Option<String>,
    /// True iff this `ProjectStar` originated from a top-level pure-star
    /// projection (`SELECT *` / `SELECT t.*`), as opposed to an inline
    /// star in a mixed projection list (`SELECT a, t.*, b`).
    /// `star_projections` is populated only for the pure case.
    pub top_level_pure: bool,
    /// The sources every column of which the star's expansion considered,
    /// in the order considered, each once: each column became an item
    /// unless a modifier of the star left it out. Never an open source: an
    /// uncatalogued scan, a reference with an unexpanded star at its
    /// body's root, a table function with no declared outputs. A
    /// reference whose body lists items beside an unexpanded star has
    /// its listed columns produced as items and is still absent here, as
    /// is a table whose catalog names some of its columns without
    /// listing them all.
    /// Nor a recursive binding's reference to itself: a star over it in
    /// the step is unexpanded, and the body is open.
    pub enumerated: Vec<NodeId>,
    /// The columns the star's expansion produced an item for that no
    /// source of `enumerated` lists: what a `PIVOT`, `UNPIVOT` or
    /// `MATCH_RECOGNIZE` over a FROM item defines, and what it lists of
    /// an open source under it. A wrapper carries the node id of the
    /// source it wraps, so its columns are recorded one by one.
    pub itemized: Vec<ColumnId>,
    /// Whether the items the star's expansion produced are every column
    /// the star yields, in the star's order: it enumerated each source
    /// it ranges over, and the plan knows the order of what a join of
    /// them merges.
    pub complete: bool,
    /// How many of the items directly before the star its expansion
    /// produced at positions the plan does not know. None for a
    /// complete star. Otherwise every item it produced, less the leading
    /// ones: the columns of its first sources, in FROM order, for as
    /// long as each lists every column, then the first columns of the
    /// next source as far as that source places them.
    pub unplaced: usize,
    pub span: Span,
}

/// One `EXCLUDE` entry in a star projection. The span lets analyses
/// recover quote/case-preserving source text without re-tokenizing.
#[derive(Debug, Clone)]
pub struct StarExclude {
    pub name: IdentKey,
    pub span: Span,
}

/// Qualifier form of a star projection.
#[derive(Debug, Clone)]
pub enum StarQualifier {
    /// Bare `*`.
    Unqualified,
    /// `<name>.*` where `name` is a dot-joined identifier path
    /// (table alias, CTE name, `schema.table`, `db.schema.table`).
    /// Stored as the path parts so lineage analysis can resolve
    /// against either a relation or a struct column without
    /// re-parsing the source. Each part carries its source span so
    /// fact projection can recover quote/case-preserving text.
    Named(Vec<StarPathPart>),
    /// `<expr>.*` — struct / object-valued expression unpacking
    /// (Snowflake VARIANT, BigQuery STRUCT). The expression is
    /// lowered like any other scalar.
    FromExpr(Box<ScalarExpr>),
}

/// One identifier in a `StarQualifier::Named` path.
#[derive(Debug, Clone)]
pub struct StarPathPart {
    pub name: IdentKey,
    pub span: Span,
}

/// `* REPLACE (<expr> AS <column>)` entry.
#[derive(Debug, Clone)]
pub struct StarReplace {
    pub column: IdentKey,
    pub expr: ScalarExpr,
    pub span: Span,
}

/// `* RENAME (<from> AS <to>)` entry. Both `from_span` and `to_span`
/// are preserved so fact projection can recover the user-written
/// text on each side of the rename.
#[derive(Debug, Clone)]
pub struct StarRename {
    pub from: IdentKey,
    pub to: IdentKey,
    pub from_span: Span,
    pub to_span: Span,
}

/// Scan modifier — changes feeds, time travel, alias / sample applied at
/// scan time, etc.
#[derive(Debug, Clone, Default)]
pub struct ScanModifier {
    pub changes: Option<ChangesClause>,
    pub time_travel: Option<TimeTravel>,
    pub hints: Vec<Hint>,
    /// Stage-file options for `FROM @stage (FILE_FORMAT => …, PATTERN => …)`.
    /// Preserved opaquely as the source span (options grammar is
    /// Snowflake-specific and not structurally decomposed).
    pub stage_options: Option<Span>,
    /// Origin of this scan (e.g. `ref()` vs. direct table) — preserved so
    /// cross-model analyses survive resolution.
    pub origin: OriginHint,
    /// `TABLESAMPLE` / `SAMPLE` clause. When
    /// present the Scan is wrapped in a [`RelPlan::TableSample`]
    /// node and this field carries the typed descriptor for
    /// scan-local consumers (lineage, governance) that prefer
    /// not to walk the wrapper.
    pub sample: Option<TableSample>,
    /// BigQuery `WITH OFFSET [AS alias]` for `UNNEST`.
    pub with_offset: Option<WithOffset>,
    /// PostgreSQL `FROM ONLY parent_table` qualifier.
    /// Span covers the `ONLY` keyword.
    pub only: Option<Span>,
    /// T-SQL `WITH (NOLOCK, INDEX(idx_date), …)` table-hint
    /// clause. Empty when no clause is present.
    /// `RelPlan::Insert.target_hints` shares this same typed shape
    /// (the underlying T-SQL grammar is unified).
    pub table_hints: Vec<ScanTableHint>,
    /// T-SQL TVF schema clause `WITH (col TYPE [path], …)`.
    /// Preserved-text span; no typed decomposition.
    pub tvf_schema: Option<Span>,
}

/// `CHANGES(INFORMATION => …)` (Snowflake).
///
/// `information` is a closed enum: the AST
/// already discriminates between `DEFAULT` and `APPEND_ONLY`.
#[derive(Debug, Clone)]
pub struct ChangesClause {
    pub information: ChangesInformation,
    pub at: Option<TimeTravel>,
    pub end: Option<TimeTravel>,
}

/// Closed enum for `CHANGES(INFORMATION => …)` argument.
/// Snowflake grammar accepts only these two values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangesInformation {
    /// `INFORMATION => DEFAULT` — full delta with inserts,
    /// updates, and deletes.
    Default,
    /// `INFORMATION => APPEND_ONLY` — inserts only, no join.
    AppendOnly,
}

/// `AT(OFFSET => …)` / `BEFORE(STATEMENT => …)` / `FOR SYSTEM_TIME AS OF …`
/// and dialect-specific extensions.
///
/// Closed enum — every consumer matches exhaustively; no catch-all
/// arms.
#[derive(Debug, Clone)]
pub enum TimeTravel {
    // ── Snowflake `AT|BEFORE ( <kind> => <expr> )` ───────────────────
    AtTimestamp(ScalarExpr),
    AtOffset(ScalarExpr),
    AtStatement(ScalarExpr),
    AtStream(ScalarExpr),
    BeforeTimestamp(ScalarExpr),
    BeforeOffset(ScalarExpr),
    BeforeStatement(ScalarExpr),
    BeforeStream(ScalarExpr),

    // ── BigQuery `FOR SYSTEM_TIME [AS OF <expr>]` ────────────────────
    /// `FOR SYSTEM_TIME AS OF <expr>`.
    ForSystemTimeAsOf(ScalarExpr),
    /// `FOR SYSTEM_TIME` with no `AS OF` argument (parser emits
    /// `AstForSystemTime { expr: None }` for `ALL`, `FROM … TO …`,
    /// `BETWEEN … AND …`, `CONTAINED IN (…)` — none of which are
    /// structurally modeled in the AST today). Span points at the
    /// full clause.
    ForSystemTimeBare {
        span: Span,
    },

    // ── Databricks Delta Lake ────────────────────────────────────────
    DatabricksTimestampAsOf(ScalarExpr),
    DatabricksVersionAsOf(ScalarExpr),
    /// `table@v123` / `table@20190101`. The value is the expression
    /// following the `@`.
    DatabricksAtSign(ScalarExpr),
}

/// Shape of `PIVOT … IN (…)` list. Closed enum — every consumer
/// matches exhaustively.
#[derive(Debug, Clone)]
pub enum PivotValues {
    /// Explicit list: `IN (v1, v2, …)`. Order-preserving.
    ValueList(Vec<ScalarExpr>),
    /// Snowflake `IN (ANY [ORDER BY …])`. `order_by` empty when
    /// there is no trailing `ORDER BY`.
    Any { order_by: Vec<SortKey> },
    /// `IN (SELECT …)` — lowered subquery body.
    Subquery(Box<RelPlan>),
    /// Jinja-shaped list: value slot contains `{% for … %}` or
    /// similar templating that the renderer could not pre-resolve.
    /// Kept opaque per the `ScanModifier::stage_options` discipline.
    Opaque { span: Span },
}

impl PivotValues {
    /// Number of distinct value slots. For `Any` and `Opaque`
    /// shapes the concrete count is not known statically; callers
    /// that need a conservative lower bound should treat these as
    /// at least one slot.
    pub fn len(&self) -> usize {
        match self {
            PivotValues::ValueList(v) => v.len(),
            PivotValues::Subquery(_) | PivotValues::Any { .. } | PivotValues::Opaque { .. } => 0,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// One column of a `USING` clause: the column the join exposes and the
/// column of each side it merges.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UsingColumn {
    pub merged: ColumnId,
    pub left: ColumnId,
    pub right: ColumnId,
}

/// One source-column group in an `UNPIVOT`.
///
/// Snowflake permits tuple forms like
/// `UNPIVOT ((v1, v2) FOR name IN ((c1, c2) AS 'a', (c3, c4) AS 'b'))`
/// where each group in the `IN` list is itself a tuple that must match
/// the `value_columns` arity.
#[derive(Debug, Clone)]
pub struct UnpivotColumn {
    /// Source columns in this group — length equals the enclosing
    /// `Unpivot.value_columns` length.
    pub columns: Vec<ColumnId>,
    /// Optional `AS '<label>'`.
    pub alias: Option<IdentKey>,
    pub span: Span,
}

/// Query hint: `/*+ … */` etc. Preserved as raw text for round-tripping;
/// only a handful of analyses will interpret these.
#[derive(Debug, Clone)]
pub struct Hint {
    pub text: String,
    pub span: Span,
}

/// Where a scan came from before resolution.
#[derive(Debug, Clone, Default)]
pub enum OriginHint {
    #[default]
    Direct,
    DbtRef {
        macro_span: Span,
        target: String,
    },
    DbtSource {
        macro_span: Span,
        source: String,
        name: String,
    },
}

/// Resolved cross-model target (dbt `ref()` / `source()`).
///
/// Carries every per-upstream fact the IR analyses need at
/// `RelPlan::ModelRef` boundaries — base tables, taint labels,
/// nullable column set, constraint set, column lineage. All of
/// it is recorded at lowering time from the
/// [`crate::ir::model_catalog::ModelCatalog`] so analyses
/// need no other state to resolve cross-model references.
#[derive(Debug, Clone)]
pub struct ResolvedModel {
    pub package: Option<String>,
    pub name: String,
    /// Physical base tables that this model ultimately reads from.
    pub base_tables: Vec<TableRef>,
    /// Pre-computed taint labels keyed by upstream column name.
    pub taint_labels: std::collections::HashMap<IdentKey, Vec<TaintLabel>>,
    /// Upstream column names whose output is known nullable
    /// (typically from a LEFT JOIN inside the upstream model's
    /// body). A `ModelRef` output `ColumnId` is nullable when its
    /// upstream display name appears here.
    pub nullable_columns: std::collections::HashSet<IdentKey>,
    /// Upstream constraint set — column-level facts the upstream
    /// model established, projected onto this reference's per-output
    /// `ColumnId`s for cross-model contradiction detection.
    pub constraint_set: crate::ir::constraint_types::IrConstraintSet,
    /// Upstream column lineage, for tracing a downstream column
    /// across the model boundary back to its physical source.
    pub column_lineage:
        Option<std::collections::HashMap<IdentKey, Vec<crate::context::node_metadata::ColumnRef>>>,
    /// Whether the upstream model's body had any filter
    /// (WHERE / QUALIFY / HAVING / transitively filtered source).
    /// A `ModelRef` of a model that has one reads only the rows that
    /// passed it.
    pub has_filter: bool,
    pub node_id: NodeId,
}

/// Resolved function identity.
///
/// Two variants:
///
/// - [`ResolvedFunc::Resolved`] — the call's name was found in the
///   lowering session's [`crate::ir::FunctionCatalog`]. All semantic
///   facts (kind, null-strictness, determinism, argument shape) are
///   read from the catalog; downstream analyses never pattern-match
///   on the raw name.
/// - [`ResolvedFunc::Unresolved`] — the call shape is well-formed but
///   the name was not found in the active catalog. The raw spelling
///   round-trips for permissive-mode rendering; strict-IR mode
///   rejects unresolved calls via
///   [`crate::ir::OpaqueReason::UnknownFunction`]. For shape purposes
///   an unresolved call behaves identically to a known
///   [`crate::ir::FunctionKind::Scalar`] — no aggregate /
///   window / null-strictness inference is attempted.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ResolvedFunc {
    Resolved {
        id: super::catalog::FunctionId,
        span: Span,
    },
    Unresolved {
        raw_name: String,
        namespace: Option<String>,
        span: Span,
    },
}

impl ResolvedFunc {
    /// Construct an [`ResolvedFunc::Unresolved`] for a call whose name
    /// is not in the catalog. The raw spelling is preserved verbatim
    /// so permissive-mode rendering is lossless.
    pub fn unresolved(raw_name: impl Into<String>, namespace: Option<String>, span: Span) -> Self {
        ResolvedFunc::Unresolved {
            raw_name: raw_name.into(),
            namespace,
            span,
        }
    }

    /// Source span of the function *name* (not the whole call).
    pub fn span(&self) -> Span {
        match self {
            ResolvedFunc::Resolved { span, .. } => *span,
            ResolvedFunc::Unresolved { span, .. } => *span,
        }
    }

    /// Display spelling suitable for diagnostics. For resolved calls
    /// the caller must go through the catalog to get the canonical
    /// display name; this helper only surfaces what the IR itself
    /// carries locally (the raw spelling for unresolved, a synthetic
    /// `fn#<id>` tag for resolved).
    pub fn display_hint(&self) -> String {
        match self {
            ResolvedFunc::Resolved { id, .. } => format!("{id}"),
            ResolvedFunc::Unresolved { raw_name, .. } => raw_name.clone(),
        }
    }
}

/// `GROUP BY` shape, preserving CUBE / ROLLUP / GROUPING SETS.
#[derive(Debug, Clone)]
pub enum GroupingSpec {
    /// No `GROUP BY`.
    None,
    /// Plain `GROUP BY a, b, c`.
    Standard(Vec<GroupKey>),
    /// `GROUP BY CUBE(a, b)`.
    Cube(Vec<GroupKey>),
    /// `GROUP BY ROLLUP(a, b)`.
    Rollup(Vec<GroupKey>),
    /// `GROUP BY GROUPING SETS ((a), (a, b), ())`, and a grouping whose
    /// sets are written out: a grouping-element list
    /// (`GROUP BY a, ROLLUP(b)`), and a `ROLLUP` or `CUBE` that names one
    /// select item twice or beside an alias of it.
    GroupingSets(GroupingSets),
    /// Snowflake / BigQuery `GROUP BY ALL`. Resolution of the key list
    /// happens during lowering — the resolved keys are stored here.
    All {
        keys: Vec<GroupKey>,
        /// Whether `keys` is every key the clause groups by. False where
        /// a star of the select list does not list all of its columns:
        /// the ones it leaves out are keys the plan does not hold.
        complete: bool,
    },
}

/// The key columns of a grouping by sets, and the sets. A key column
/// holds its key's value in the rows of the sets that group by it and
/// NULL in the rows of the others.
#[derive(Debug, Clone, Default)]
pub struct GroupingSets {
    /// Each distinct key, once. Two keys are one where they have one
    /// output.
    pub keys: Vec<GroupKey>,
    /// Key columns over the expression of a key of `keys`.
    pub repeats: Vec<RepeatedGroupKey>,
    /// Each grouping set. Where the clause denotes more sets than are
    /// written out, two stand for them: one of every key column, and one
    /// of the key columns every set has.
    pub sets: Vec<GroupingSet>,
}

impl GroupingSets {
    /// Every key column: its output, and the key whose expression it
    /// holds.
    pub fn columns(&self) -> impl Iterator<Item = (ColumnId, &GroupKey)> + '_ {
        let keys = self.keys.iter().map(|key| (key.output, key));
        let repeats = self
            .repeats
            .iter()
            .filter_map(|repeat| Some((repeat.output, self.keys.get(repeat.key)?)));
        keys.chain(repeats)
    }
}

/// A second key column over one key's expression: a select-list alias of
/// a keyed item, grouped on its own beside the item.
#[derive(Debug, Clone)]
pub struct RepeatedGroupKey {
    /// Index in [`GroupingSets::keys`] of the key whose expression this
    /// column holds.
    pub key: usize,
    pub output: ColumnId,
    pub span: Span,
}

/// One grouping set: the key columns it groups by, each at most once.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GroupingSet {
    /// Indices into [`GroupingSets::keys`].
    pub keys: Vec<usize>,
    /// Indices into [`GroupingSets::repeats`].
    pub repeats: Vec<usize>,
}

/// One grouping key.
#[derive(Debug, Clone)]
pub struct GroupKey {
    /// The expression being grouped on. In the common case this is a plain
    /// `ScalarExpr::Column`; it can also be an arbitrary expression.
    pub expr: ScalarExpr,
    /// The `ColumnId` allocated to hold the group's key value in the
    /// aggregate's output.
    pub output: ColumnId,
    pub span: Span,
    /// What the query wrote at each read of `output` above the aggregate
    /// that it wrote as `expr`, in the order lowered: that occurrence,
    /// which is the same expression as `expr` with the spans of where it
    /// stands. Its span is the read's. A read by a select alias, and the
    /// select item that gave the key its expression, have none. No walk
    /// of the plan visits these: they say how a read was written, and
    /// the read is of `output`.
    pub written_again: Vec<ScalarExpr>,
}

/// One aggregate call in an `Aggregate` node.
#[derive(Debug, Clone)]
pub struct AggregateCall {
    pub func: ResolvedFunc,
    pub args: Vec<ScalarExpr>,
    /// Named (`kwarg => value`) arguments. Mirrors the slot on
    /// [`ScalarExpr::FuncCall`]. Snowflake permits named arguments on
    /// aggregate UDF calls; the name is part of the call's identity
    /// for overload resolution and is walked by the visitor and the
    /// derived-facts projector so column references
    /// inside named-argument expressions reach lineage / taint /
    /// tables-read, just like positional args.
    pub named_args: Vec<(IdentKey, ScalarExpr)>,
    pub distinct: bool,
    /// Redshift `APPROXIMATE` aggregate modifier (`APPROXIMATE COUNT(DISTINCT x)`,
    /// `APPROXIMATE PERCENTILE_DISC(...)`). Trades exactness for a HyperLogLog-style
    /// estimate — an analyzable accuracy property, not just surface syntax.
    pub approximate: bool,
    /// `FILTER (WHERE …)`.
    pub filter: Option<ScalarExpr>,
    /// PostgreSQL-style inline `ORDER BY` inside the function's
    /// argument list: `string_agg(x, ',' ORDER BY y)`. Semantically
    /// distinct from [`within_group_order`](Self::within_group_order): inline `ORDER BY`
    /// orders the aggregate's *input rows*, whereas `WITHIN GROUP`
    /// is an ordered-set aggregate's ordering expression. A single
    /// call MUST NOT populate both; the lowerer enforces this with
    /// `OpaqueReason::ConflictingAggregateOrderings`.
    pub arg_order: Vec<SortKey>,
    /// `WITHIN GROUP (ORDER BY …)` for ordered-set aggregates.
    pub within_group_order: Vec<SortKey>,
    /// `RESPECT NULLS` / `IGNORE NULLS`.
    pub null_treatment: NullTreatment,
    /// The `ColumnId` this aggregate produces.
    pub output: ColumnId,
    pub span: Span,
}

/// `RESPECT NULLS` / `IGNORE NULLS` (mostly window functions, some aggregates).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum NullTreatment {
    #[default]
    Default,
    Respect,
    Ignore,
}

/// One window-function call.
#[derive(Debug, Clone)]
pub struct WindowCall {
    pub func: ResolvedFunc,
    pub args: Vec<ScalarExpr>,
    pub distinct: bool,
    pub null_treatment: NullTreatment,
    pub partition_by: Vec<ScalarExpr>,
    pub order_by: Vec<SortKey>,
    pub frame: Option<WindowFrame>,
    /// Optional named window reference (`OVER w1`).
    pub named_window: Option<IdentKey>,
    pub output: ColumnId,
    pub span: Span,
}

/// Window frame: `ROWS|RANGE|GROUPS BETWEEN … AND …` with exclusions.
#[derive(Debug, Clone)]
pub struct WindowFrame {
    pub mode: FrameMode,
    pub start: FrameBound,
    pub end: FrameBound,
    pub exclusion: FrameExclusion,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameMode {
    Rows,
    Range,
    Groups,
}

#[derive(Debug, Clone)]
pub enum FrameBound {
    UnboundedPreceding,
    Preceding(ScalarExpr),
    CurrentRow,
    Following(ScalarExpr),
    UnboundedFollowing,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FrameExclusion {
    #[default]
    NoOthers,
    CurrentRow,
    Group,
    Ties,
}

/// Join kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JoinKind {
    Inner,
    LeftOuter,
    RightOuter,
    FullOuter,
    Cross,
    /// Snowflake `ASOF JOIN`.
    Asof,
    /// Snowflake / BigQuery `SEMI JOIN`.
    LeftSemi,
    RightSemi,
    LeftAnti,
    RightAnti,
}

/// Row-cap kind for [`RelPlan::Limit`].
///
/// `Rows` covers `LIMIT`, ANSI `FETCH`, and T-SQL `TOP (n)`.
/// `Percent` covers T-SQL `TOP (n) PERCENT`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LimitKind {
    Rows,
    Percent,
}

/// Set-op kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetOpKind {
    UnionAll,
    UnionDistinct,
    IntersectAll,
    IntersectDistinct,
    ExceptAll,
    ExceptDistinct,
}

/// One `ORDER BY` key.
#[derive(Debug, Clone)]
pub struct SortKey {
    pub expr: ScalarExpr,
    pub ascending: bool,
    /// `NULLS FIRST` / `NULLS LAST`. `None` means dialect default.
    pub nulls_first: Option<bool>,
    pub span: Span,
}

/// `TABLESAMPLE` / `SAMPLE` descriptor.
///
/// `method_keyword` is the dialect-level discriminator
/// (`BERNOULLI` / `SYSTEM` / `BLOCK` / `ROW`); `size` is the
/// independent percent-vs-row-count axis.
#[derive(Debug, Clone)]
pub struct TableSample {
    /// Sampling-strategy keyword as written in the source.
    /// `None` when the dialect's default applies (e.g.
    /// Snowflake's bare `SAMPLE (10)`).
    pub method_keyword: Option<SampleKeyword>,
    pub size: SampleSize,
    pub seed: Option<ScalarExpr>,
    pub repeatable: Option<ScalarExpr>,
    pub span: Span,
}

/// Closed enum for the SAMPLE method keyword. `Bernoulli`
/// and `Row` are equivalent in Snowflake; `System` and
/// `Block` are equivalent. We preserve the source keyword so
/// formatter round-trip stays exact and future analyses can
/// distinguish dialect-style.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SampleKeyword {
    Bernoulli,
    System,
    Block,
    Row,
}

/// Closed enum for the SAMPLE size argument.
#[derive(Debug, Clone)]
pub enum SampleSize {
    /// `SAMPLE (10)` — percentage 0..=100.
    Probability(ScalarExpr),
    /// `SAMPLE (1000 ROWS)` — fixed row count.
    Rows(ScalarExpr),
}

/// BigQuery `WITH OFFSET [AS alias]` UNNEST modifier.
/// Adds an ordinal-position column when unnesting an array.
#[derive(Debug, Clone)]
pub struct WithOffset {
    /// Optional alias for the offset column (`WITH OFFSET AS pos`).
    pub alias: Option<IdentKey>,
    /// Span covering the full `WITH OFFSET [AS alias]` clause.
    pub span: Span,
}

/// One T-SQL table hint in a FROM-clause `WITH (...)` or
/// INSERT-target `WITH (...)` clause. The kind
/// discriminates each documented simple-keyword form (NOLOCK,
/// UPDLOCK, TABLOCK, …) plus argument-bearing hints (INDEX,
/// FORCESEEK, key=value).
#[derive(Debug, Clone)]
pub struct ScanTableHint {
    pub kind: ScanTableHintKind,
    /// Span covering this individual hint (e.g. `NOLOCK` or
    /// `INDEX(idx1, idx2)`).
    pub span: Span,
}

/// Closed enum mirroring the AST [`crate::ast::AstTableHintKind`]:
/// preserves typed structure so post-parse
/// analyses dispatch on closed-enum variants rather than
/// re-inferring keyword identity from source text. Each
/// documented T-SQL simple-keyword hint is its own variant;
/// `OtherSimple` is the permissive parser fallback for
/// unrecognized keyword forms.
#[derive(Debug, Clone)]
pub enum ScanTableHintKind {
    // ── Isolation-level / dirty-read keyword hints ──────────────────────
    /// `NOLOCK` — read without acquiring shared locks (dirty reads).
    NoLock,
    /// `READUNCOMMITTED` — equivalent dirty-read semantics to NOLOCK.
    ReadUncommitted,
    /// `READCOMMITTED` — default isolation; named hint for explicitness.
    ReadCommitted,
    /// `READCOMMITTEDLOCK` — READ COMMITTED with locking semantics.
    ReadCommittedLock,
    /// `REPEATABLEREAD` — repeatable-read isolation level.
    RepeatableRead,
    /// `SERIALIZABLE` — serializable isolation level.
    Serializable,
    /// `SNAPSHOT` — snapshot isolation level.
    Snapshot,
    // ── Locking-mode keyword hints ─────────────────────────────────────
    /// `UPDLOCK` — update lock acquisition.
    UpdLock,
    /// `HOLDLOCK` — hold locks until end of transaction.
    HoldLock,
    /// `ROWLOCK` — row-level locking granularity.
    RowLock,
    /// `PAGLOCK` — page-level locking granularity.
    PagLock,
    /// `TABLOCK` — table-level shared lock.
    TabLock,
    /// `TABLOCKX` — table-level exclusive lock.
    TabLockX,
    /// `XLOCK` — exclusive lock.
    XLock,
    /// `READPAST` — skip locked rows rather than block.
    ReadPast,
    /// `NOWAIT` — fail rather than wait for locks.
    NoWait,
    // ── Optimizer keyword hints ────────────────────────────────────────
    /// `NOEXPAND` — disable indexed-view expansion.
    NoExpand,
    /// `FORCESCAN` — force a full table scan.
    ForceScan,
    // ── DML-semantics keyword hints ────────────────────────────────────
    /// `KEEPIDENTITY` — preserve source identity values during INSERT.
    KeepIdentity,
    /// `KEEPDEFAULTS` — preserve column defaults rather than NULL on INSERT.
    KeepDefaults,
    /// `IGNORE_CONSTRAINTS` — bypass constraint checks (BULK INSERT).
    IgnoreConstraints,
    /// `IGNORE_TRIGGERS` — bypass trigger firing (BULK INSERT).
    IgnoreTriggers,
    /// Any other simple-keyword hint admitted by the permissive
    /// parser but not classified above. The [`ScanTableHint::span`]
    /// preserves the source for byte-exact formatter output;
    /// consumers that need finer dispatch add a new typed variant.
    OtherSimple,
    // ── Argument-bearing hints ─────────────────────────────────────────
    /// `INDEX(value [, ...])` / `INDEX = (value)`. Each entry
    /// is the span of one index name or numeric id.
    Index { values: Vec<Span> },
    /// `FORCESEEK` or `FORCESEEK(index_name(col [, ...]))`.
    ForceSeek {
        index_name: Option<Span>,
        columns: Vec<Span>,
    },
    /// `key = value` hints (e.g.
    /// `SPATIAL_WINDOW_MAX_CELLS = 1024`).
    KeyValue { key_span: Span, value_span: Span },
}

// ── CTE bindings ─────────────────────────────────────────────────────────

/// One CTE binding in a `WithScope`.
#[derive(Debug, Clone)]
pub struct CteBinding {
    pub name: IdentKey,
    /// Scope id assigned to this CTE's body.
    pub scope: ScopeId,
    /// Optional explicit column list `WITH cte(a, b) AS (…)`.
    pub declared_columns: Option<Vec<IdentKey>>,
    pub body: CteBody,
    pub output_columns: Vec<ColumnId>,
    /// The body column each slot is, by slot; `None` where it cannot be known.
    pub slot_columns: Vec<Option<ColumnId>>,
    pub node_id: NodeId,
    pub span: Span,
}

/// A column read through a reference whose body exposes it by star.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DemandedColumn {
    pub slot: u32,
    pub column: ColumnId,
}

/// CTE body: recursive CTEs split anchor/step.
#[derive(Debug, Clone)]
pub enum CteBody {
    NonRecursive(Box<RelPlan>),
    Recursive {
        anchor: Box<RelPlan>,
        step: Box<RelPlan>,
        /// Which set-op joins them (`UNION ALL` / `UNION DISTINCT`).
        union_kind: SetOpKind,
    },
}

// ── MERGE branches ──────────────────────────────────────────────────────

/// One `WHEN …` branch of a `MERGE` statement.
#[derive(Debug, Clone)]
pub struct MergeBranch {
    pub kind: MergeBranchKind,
    pub predicate: Option<ScalarExpr>,
    pub action: MergeAction,
    pub span: Span,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MergeBranchKind {
    WhenMatched,
    WhenNotMatched,
    /// BigQuery `WHEN NOT MATCHED BY SOURCE`.
    WhenNotMatchedBySource,
}

#[derive(Debug, Clone)]
pub enum MergeAction {
    /// `INSERT (c1, c2, …) VALUES (e1, e2, …)` — explicit column list
    /// (empty vec ⇒ no column list, positional by target schema).
    Insert {
        target_columns: Vec<ColumnId>,
        values: Vec<ScalarExpr>,
    },
    /// Databricks `INSERT *` — insert every column of the target from
    /// the source's column of the same name. No explicit column list or
    /// values. `columns` holds one entry per column the catalog declares
    /// for the target; empty where the catalog does not resolve it.
    InsertStar {
        columns: Vec<MergeStarColumn>,
    },
    /// Snowflake `INSERT ALL BY NAME` — match source and target columns
    /// by name. `columns` is as for [`MergeAction::InsertStar`].
    InsertAllByName {
        columns: Vec<MergeStarColumn>,
    },
    /// `UPDATE SET c1 = e1, c2 = e2, …` — explicit assignments.
    Update {
        assignments: Vec<Assignment>,
    },
    /// Databricks `UPDATE SET *` — set every column of the target from
    /// the source's column of the same name. `columns` is as for
    /// [`MergeAction::InsertStar`].
    UpdateSetStar {
        columns: Vec<MergeStarColumn>,
    },
    /// Snowflake `UPDATE ALL BY NAME` — match and update by name.
    /// `columns` is as for [`MergeAction::InsertStar`].
    UpdateAllByName {
        columns: Vec<MergeStarColumn>,
    },
    Delete,
    /// `DO NOTHING` / BigQuery `WHEN NOT MATCHED THEN DO NOTHING`.
    DoNothing,
}

/// One target column a MERGE action over every target column writes.
#[derive(Debug, Clone)]
pub struct MergeStarColumn {
    /// The column written: defined by the `Merge` node and named for
    /// the target column.
    pub written: ColumnId,
    /// The source's column of the target column's name; `None` where
    /// the source is not known to have one.
    pub source: Option<ColumnId>,
}

/// One assignment of an `UPDATE`, of a `MERGE`'s update action or of an
/// upsert's update action.
#[derive(Debug, Clone)]
pub struct Assignment {
    /// The node of the source whose row the assignment writes: the
    /// statement's target, or a table an `UPDATE` lists before `SET`.
    pub written_node: NodeId,
    /// The columns written, in the order the assignment names them; each
    /// defined by the statement's node.
    pub columns: Vec<ColumnId>,
    pub value: AssignedValue,
}

/// What an assignment's columns take: column `i` takes position `i`.
#[derive(Debug, Clone)]
pub enum AssignedValue {
    /// One expression per position: `SET c = e`, `SET (a, b) = (e1, e2)`,
    /// `SET (a, b) = ROW(e1, e2)`. A column past the end takes nothing.
    Row(Vec<ScalarExpr>),
    /// The one row a query yields, by its `positional_columns()`:
    /// `SET (a, b) = (SELECT x, y …)`.
    Query {
        subquery: Box<RelPlan>,
        correlates_with: Vec<ColumnId>,
        span: Span,
    },
}

// ── MATCH_RECOGNIZE typed body ──────────────────────────────────
//
// Every sub-expression that can reference an input column
// (PARTITION BY / ORDER BY / MEASURES / DEFINE) is a `ScalarExpr`,
// so column-keyed analyses (lineage, nullability, constraints,
// taint) walk through MATCH_RECOGNIZE the same way they walk through
// any other relational node.
//
// `pattern_text` from the AST is parsed at lowering time into
// `PatternExpr` (`src/ir/match_recognize_pattern.rs`). Pattern
// variables live in a per-node `SymbolTable`; they do not leak into
// the `ColumnId` namespace.

/// Typed body for `RelPlan::MatchRecognize`.
#[derive(Debug, Clone)]
pub struct MatchRecognizeBody {
    pub partition_by: Vec<ScalarExpr>,
    pub order_by: Vec<SortKey>,
    pub measures: Vec<MatchRecognizeMeasure>,
    pub rows_per_match: RowsPerMatch,
    pub after_match_skip: AfterMatchSkip,
    pub pattern: PatternExpr,
    pub define: Vec<MatchRecognizeDefine>,
    /// Symbols referenced by `pattern` and / or defined in `define`,
    /// scoped to this single MATCH_RECOGNIZE node. Index by
    /// `SymbolId.0`.
    pub symbols: SymbolTable,
    pub raw_span: Span,
}

/// One `MEASURES` entry. The aliased output column is allocated
/// during lowering and surfaces in `output_columns`.
#[derive(Debug, Clone)]
pub struct MatchRecognizeMeasure {
    pub output: ColumnId,
    pub modifier: Option<MeasureModifier>,
    pub expr: ScalarExpr,
    pub alias: IdentKey,
    pub span: Span,
}

/// `RUNNING` / `FINAL` semantic modifier on a `MEASURES` entry.
///
/// Closed enum — every consumer matches exhaustively.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MeasureModifier {
    Running,
    Final,
}

/// `ONE ROW PER MATCH` vs. `ALL ROWS PER MATCH […]`.
///
/// Closed enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RowsPerMatch {
    OneRow,
    AllRows(AllRowsMode),
}

/// Sub-modifier on `ALL ROWS PER MATCH`.
///
/// Closed enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AllRowsMode {
    /// Default: only matched rows.
    Default,
    /// `ALL ROWS PER MATCH SHOW EMPTY MATCHES`.
    ShowEmpty,
    /// `ALL ROWS PER MATCH OMIT EMPTY MATCHES`.
    OmitEmpty,
    /// `ALL ROWS PER MATCH WITH UNMATCHED ROWS`.
    WithUnmatched,
}

/// `AFTER MATCH SKIP …` clause.
///
/// Closed enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AfterMatchSkip {
    /// Default if omitted: `PAST LAST ROW`.
    PastLastRow,
    ToNextRow,
    ToFirst(SymbolId),
    ToLast(SymbolId),
}

/// Typed row pattern. Result of parsing the AST's `pattern_text`
/// against Snowflake / Oracle row-pattern grammar.
///
/// Closed enum.
#[derive(Debug, Clone)]
pub enum PatternExpr {
    /// A pattern variable reference.
    Symbol(SymbolId),
    /// `^` or `$` row-position anchor.
    Anchor(PatternAnchor),
    /// Concatenation of two or more sub-patterns. Length ≥ 2 by
    /// construction (single elements are unwrapped during parsing).
    Concat(Vec<PatternExpr>),
    /// Alternation `a | b [| …]`. Length ≥ 2 by construction.
    Alternation(Vec<PatternExpr>),
    /// `inner` followed by a quantifier.
    Quantified {
        inner: Box<PatternExpr>,
        kind: PatternQuantKind,
        /// `false` if the trailing `?` reluctant marker was set.
        greedy: bool,
    },
    /// Oracle `PERMUTE(p1, p2, …)` — dialect-permissive.
    Permute(Vec<PatternExpr>),
    /// Oracle `{- p -}` exclusion — dialect-permissive.
    Exclude(Box<PatternExpr>),
    /// The empty pattern. Produced for empty alternation arms
    /// (e.g. `(A|)`) and for permissive-mode parse-failure recovery.
    Empty,
}

/// Quantifier shape for `PatternExpr::Quantified`.
///
/// Closed enum. Covers Snowflake / Oracle row-pattern
/// quantifiers; missing bounds (`{n,}` / `{,m}`) become `AtLeast` /
/// `AtMost` respectively.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PatternQuantKind {
    /// `?`
    ZeroOrOne,
    /// `*`
    ZeroOrMore,
    /// `+`
    OneOrMore,
    /// `{n}`
    Exact(u32),
    /// `{n,}`
    AtLeast(u32),
    /// `{,m}`
    AtMost(u32),
    /// `{n,m}`. Invariant `n <= m` enforced at parse time.
    Range(u32, u32),
}

/// `^` (start-of-match-window) or `$` (end-of-match-window) anchor.
///
/// Closed enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PatternAnchor {
    Start,
    End,
}

/// One `DEFINE <symbol> AS <predicate>` entry.
#[derive(Debug, Clone)]
pub struct MatchRecognizeDefine {
    pub symbol: SymbolId,
    pub predicate: ScalarExpr,
    pub span: Span,
}

/// Per-MATCH_RECOGNIZE-node identifier for a pattern variable.
///
/// Newtype rather than a stringly-typed ID. Symbols
/// are scoped strictly to one `MatchRecognizeBody`; `SymbolId(0)` in
/// one body has no relationship to `SymbolId(0)` in another.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SymbolId(pub u32);

/// Symbol table for one MATCH_RECOGNIZE node.
///
/// `entries[i]` is the symbol with `SymbolId(i as u32)`. Order is
/// the order the parser first encountered the symbol (PATTERN
/// appearance + `DEFINE`).
#[derive(Debug, Clone, Default)]
pub struct SymbolTable {
    pub entries: Vec<SymbolEntry>,
}

/// One row in [`SymbolTable`].
#[derive(Debug, Clone)]
pub struct SymbolEntry {
    /// Normalized identifier key for case-insensitive lookup.
    pub key: IdentKey,
    /// Original case-preserved name as it appeared in source.
    pub display: String,
    /// Span pointing at the first occurrence in source.
    pub first_seen: Span,
}

impl SymbolTable {
    /// Look up a symbol by normalized key. Returns the assigned id
    /// if the symbol is already present; otherwise `None`.
    pub fn lookup(&self, key: &IdentKey) -> Option<SymbolId> {
        self.entries
            .iter()
            .position(|e| &e.key == key)
            .map(|i| SymbolId(i as u32))
    }

    /// Look up by normalized key, inserting a fresh entry if absent.
    pub fn intern(&mut self, key: IdentKey, display: String, first_seen: Span) -> SymbolId {
        if let Some(id) = self.lookup(&key) {
            return id;
        }
        let id = SymbolId(self.entries.len() as u32);
        self.entries.push(SymbolEntry {
            key,
            display,
            first_seen,
        });
        id
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn get(&self, id: SymbolId) -> Option<&SymbolEntry> {
        self.entries.get(id.0 as usize)
    }
}

// ── Scripting reservation ───────────────────────────────────────────────

/// Placeholder for multi-statement scripts: a sequence of plans plus the
/// variable bindings that flow between them. Reserved in the enum universe
/// so adding scripting support later is not a breaking change.
///
/// The type exists but is not referenced by any `RelPlan` variant.
#[derive(Debug, Clone)]
pub struct ScriptPlan {
    pub statements: Vec<RelPlan>,
    pub span: Span,
}

// ── DML support types ───────────────────────────────────────────────────
//
// Typed slots for clauses that lowering exposes: ON CONFLICT, RETURNING,
// OUTPUT [INTO], table hints, multi-insert shape, and EXPLAIN wrapper.
// Nothing here uses String payloads to paper over structural gaps.

/// PostgreSQL `INSERT … DEFAULT VALUES` vs `VALUES (…)` vs query-sourced.
/// Keeping these distinguishable in the IR is required for correctness
/// of constraint / default-propagation analyses.
#[derive(Debug, Clone)]
pub enum InsertSource {
    /// `VALUES (…), (…)` — the inner plan is always a [`RelPlan::Values`].
    Values(Box<RelPlan>),
    /// `SELECT …` / `WITH … SELECT …` / set-op query.
    Query(Box<RelPlan>),
    /// PostgreSQL `DEFAULT VALUES` — produce one row where every column
    /// takes its declared default.
    DefaultValues,
}

/// PostgreSQL `OVERRIDING { SYSTEM | USER } VALUE`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverridingValue {
    /// Override the database's system-generated value with the provided one.
    System,
    /// Keep the system-generated value even if a user value was supplied.
    User,
}

/// What an `INSERT OVERWRITE` replaces (Snowflake, Databricks).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverwriteScope {
    /// Every row of the target.
    Table,
    /// The rows of the partitions its `PARTITION (…)` clause names.
    Partitions,
}

/// PostgreSQL `ON CONFLICT` (aka "upsert") — typed, not a string blob.
#[derive(Debug, Clone)]
pub struct OnConflict {
    pub target: ConflictTarget,
    pub action: ConflictAction,
    /// Optional `WHERE` predicate on the inferred conflict target.
    pub where_clause: Option<ScalarExpr>,
    pub span: Span,
}

/// Which constraint the `ON CONFLICT` clause targets.
#[derive(Debug, Clone)]
pub enum ConflictTarget {
    /// No target specified — applies to any unique violation.
    Unspecified,
    /// Inferred by a list of target columns (an index expression inference).
    Columns(Vec<ColumnId>),
    /// `ON CONFLICT ((LOWER(email)), col2)` — index inference on one
    /// or more expressions. Used whenever any target item is not a
    /// plain column; plain-column items inside a mixed list lower to
    /// [`ScalarExpr::Column`] entries in the same vec so the whole
    /// list round-trips without an auxiliary "kind" tag.
    Expressions(Vec<ScalarExpr>),
    /// `ON CONSTRAINT <name>` — named unique/exclusion constraint.
    Constraint(IdentKey),
}

/// What to do when the conflict target matches.
#[derive(Debug, Clone)]
pub enum ConflictAction {
    /// `ON CONFLICT … DO NOTHING`.
    DoNothing,
    /// `ON CONFLICT … DO UPDATE SET …`. `EXCLUDED.c` in `assignments`
    /// and `where_clause` reads the column the INSERT writes under `c`,
    /// else the target's.
    DoUpdate {
        assignments: Vec<Assignment>,
        where_clause: Option<ScalarExpr>,
    },
    /// MySQL `ON DUPLICATE KEY UPDATE` — semantically equivalent to
    /// `DoUpdate` with `Unspecified` target, kept distinct so the
    /// renderer can round-trip.
    MySqlDuplicateKeyUpdate { assignments: Vec<Assignment> },
}

/// A column a `RETURNING` list reads that holds, per row, the value of
/// one of several columns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReturnedMerge {
    /// The column the list reads.
    pub column: ColumnId,
    /// The columns it is one of.
    pub alternatives: Vec<ColumnId>,
}

/// PostgreSQL `RETURNING …` clause. Applies to INSERT/UPDATE/DELETE.
#[derive(Debug, Clone)]
pub struct Returning {
    pub items: Vec<ReturningItem>,
    pub span: Span,
}

impl Returning {
    /// The column of each item that has one, in the list's order.
    pub(crate) fn columns(&self) -> Vec<ColumnId> {
        self.items
            .iter()
            .filter_map(|item| match item {
                ReturningItem::Expr { output, .. } => *output,
                ReturningItem::Star(_) => None,
            })
            .collect()
    }
}

/// A star in a `RETURNING` list.
#[derive(Debug, Clone)]
pub struct ReturnedStar {
    /// What the star ranges over.
    pub range: ReturnedStarRange,
    /// `* EXCLUDE (…)` / `* EXCEPT (…)`: the columns the star leaves out.
    pub exclude: Vec<StarExclude>,
    /// `* REPLACE (<expr> AS <col>)`: the names whose column is the
    /// expression. An item made for the star holds each expression.
    pub replaced: Vec<IdentKey>,
    /// `* RENAME (<from> AS <to>)`: the columns the star yields under
    /// another name.
    pub rename: Vec<StarRename>,
    /// Whether the items made for the star hold every column it yields,
    /// in its order.
    pub complete: bool,
    /// How many of the items directly before the star, made for it, are
    /// at no position the plan knows. For a star that is not complete,
    /// its columns at positions the plan does not know. For a complete
    /// one, what is none of its columns: a name read through it that
    /// it does not list, a `REPLACE` of a name it does not list.
    pub unplaced: usize,
    pub span: Span,
}

/// What a star in a `RETURNING` list ranges over.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReturnedStarRange {
    /// `*`: the returned row, then the columns of each other source of
    /// the statement, in the order written.
    Statement,
    /// The target's name or alias: the returned row.
    Row,
    /// `old.*`: the row as stored before the statement.
    Stored,
    /// `new.*`: the row the statement leaves.
    Written,
    /// A source's alias: that source's columns.
    Source(NodeId),
    /// A qualifier that names nothing the list reads, or `expr.*`.
    Unresolved,
}

/// One item in a `RETURNING` / `OUTPUT` list.
#[derive(Debug, Clone)]
pub enum ReturningItem {
    /// A star, bare or qualified. It has no column of its own: its
    /// columns are the `Expr` items made for it, directly before it.
    Star(ReturnedStar),
    /// A scalar expression with optional alias and synthesized output id.
    Expr {
        expr: ScalarExpr,
        alias: Option<IdentKey>,
        output: Option<ColumnId>,
    },
}

/// T-SQL `OUTPUT … [INTO target [(cols)]]`.
///
/// Distinct from [`Returning`] because OUTPUT can reference the
/// pseudo-tables `inserted.*` and `deleted.*` and, optionally, pipe
/// rows into an `INTO` target. Both features are absent from PG
/// `RETURNING`.
#[derive(Debug, Clone)]
pub struct DmlOutput {
    pub items: Vec<ReturningItem>,
    pub into_target: Option<TableRef>,
    pub into_columns: Vec<ColumnId>,
    pub span: Span,
}

/// The cap on the rows an `UPDATE` or a `DELETE` writes: T-SQL `TOP (n)
/// [PERCENT]`, MySQL's single-table `LIMIT n` (never a percentage).
#[derive(Debug, Clone)]
pub struct DmlTop {
    pub count: ScalarExpr,
    pub percent: bool,
    pub span: Span,
}

/// Oracle / Snowflake multi-insert conditional/unconditional mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MultiInsertMode {
    /// `INSERT ALL INTO t1 … INTO t2 … SELECT …` — every target
    /// receives every source row.
    UnconditionalAll,
    /// `INSERT FIRST WHEN c1 THEN INTO … WHEN c2 THEN INTO … ELSE …` —
    /// each row goes to the first matching WHEN only.
    ConditionalFirst,
    /// `INSERT ALL WHEN c1 THEN INTO … WHEN c2 THEN INTO … ELSE …` —
    /// each row goes to every matching WHEN.
    ConditionalAll,
}

/// One `INTO table [(cols)] VALUES (…)` clause inside an
/// [`RelPlan::MultiInsert`]. `values` holds the rows the clause writes;
/// it is empty when the clause is `INTO t (cols)` and the positional
/// columns come from the trailing sub-query.
#[derive(Debug, Clone)]
pub struct MultiInsertTarget {
    pub target: TableRef,
    /// Node id of the target, shared with no other source or target.
    pub target_node: NodeId,
    pub target_columns: Vec<ColumnId>,
    /// The target's columns the statement reads, each allocated on
    /// `target_node`.
    pub target_read_columns: Vec<ColumnId>,
    /// The rows `VALUES` writes, each in the order of `target_columns`.
    pub values: Vec<Vec<ScalarExpr>>,
    pub span: Span,
}

/// One `WHEN cond THEN INTO …` block inside an [`RelPlan::MultiInsert`].
#[derive(Debug, Clone)]
pub struct MultiInsertWhen {
    pub condition: ScalarExpr,
    pub targets: Vec<MultiInsertTarget>,
    pub span: Span,
}

/// PostgreSQL `EXPLAIN` options. All booleans default false; `format`
/// defaults to `TEXT` when the statement was written without an option
/// list.
#[derive(Debug, Clone, Default)]
pub struct ExplainOptions {
    pub analyze: bool,
    pub verbose: bool,
    pub costs: Option<bool>,
    pub buffers: Option<bool>,
    pub timing: Option<bool>,
    pub settings: Option<bool>,
    pub summary: Option<bool>,
    pub format: ExplainFormat,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ExplainFormat {
    #[default]
    Text,
    Xml,
    Json,
    Yaml,
}

// ── Create-as-query support types ───────────────────────────────────────

/// Which create-as-query family a [`RelPlan::CreateAsQuery`] represents.
///
/// Kind-specific flags travel here rather than on the outer variant so
/// analyses that need the distinction (e.g. "is this a view or a
/// table?") match on `kind`; analyses that only care about the body
/// traverse through and never look at the kind at all.
#[derive(Debug, Clone)]
pub enum CreateAsKind {
    /// `CREATE [OR REPLACE] [TEMP|LOCAL|GLOBAL] [RECURSIVE] [SECURE]
    /// [MATERIALIZED] VIEW …`.
    View {
        materialized: bool,
        recursive: bool,
        secure: bool,
        temp: bool,
    },
    /// `CREATE TABLE … AS SELECT …` (CTAS). `temp` / `transient`
    /// mirror the corresponding `CREATE TABLE` modifiers.
    Table { transient: bool, temp: bool },
    /// `CREATE [OR REPLACE] [TRANSIENT] DYNAMIC [ICEBERG] TABLE …`.
    /// The structural (`TARGET_LAG`, `WAREHOUSE`, `REFRESH_MODE`, …)
    /// options travel in the outer `side_options` because they are
    /// span-only on the AST today; only boolean shape flags live here.
    DynamicTable { iceberg: bool, transient: bool },
}

/// One dialect/object-specific option on a [`RelPlan::CreateAsQuery`].
///
/// Each option is `kind + span` (the source text is recoverable via the
/// span). This is the typed equivalent of the per-object `Option<Span>`
/// fields on the AST nodes. Baseline diff tooling can ask "did the
/// `TargetLag` entry's span-sliced text change?" without parsing string
/// blobs or depending on AST-level names.
///
/// The enum is intentionally wider than any single object's option set
/// so view, CTAS, and dynamic-table side options share one list type.
/// Unknown or not-yet-modeled dialect options route to
/// [`CreateSideOptionKind::Unknown`] so round-trip parity stays honest.
#[derive(Debug, Clone)]
pub struct CreateSideOption {
    pub kind: CreateSideOptionKind,
    pub span: Span,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CreateSideOptionKind {
    // ── View / materialized view ────────────────────────────────────
    WithCheckOption,
    Comment,
    RowAccessPolicy,
    AggregationPolicy,
    JoinPolicy,
    ProjectionPolicy,
    MaskingPolicy,
    Tag,
    Contact,
    ChangeTracking,
    PartitionBy,
    ClusterBy,
    /// BigQuery `OPTIONS(...)` block.
    BigQueryOptions,
    /// BigQuery `AS REPLICA OF source_view` (materialized view
    /// replica). When present the view has no query body; lowering
    /// preserves the form as `CreateAsQuery { body: None, .. }`.
    ReplicaOf,
    // ── CTAS-specific ──────────────────────────────────────────────
    TableOptions,
    Retention,
    DataRetentionTimeInDays,
    MaxDataExtensionTimeInDays,
    DefaultDdlCollation,
    StorageLifecyclePolicy,
    EnableSchemaEvolution,
    WithRowAccessPolicy,
    UsingTemplate,
    FromArchive,
    FromSnapshotSet,
    CopyTags,
    /// `AT(OFFSET => …)` / `BEFORE(STATEMENT => …)` / `FOR SYSTEM_TIME
    /// AS OF …`. CTAS inherits time-travel from the `LIKE`/`CLONE`
    /// source table today; kept as a span so future rewire can
    /// parse into the existing `TimeTravel` type.
    TimeTravel,
    // ── Dynamic-table-specific ─────────────────────────────────────
    TargetLag,
    Warehouse,
    InitializationWarehouse,
    RefreshMode,
    Initialize,
    RequireUser,
    ImmutableWhere,
    BackfillFrom,
    // ── Fallback ───────────────────────────────────────────────────
    /// A span that the lowerer recognized was attached but did not
    /// classify. Keeps round-trip parity without silently dropping the
    /// option.
    Unknown,
}

// ────────────────────────────────────────────────────────────────────────
// CreateTableForm supporting type
// ────────────────────────────────────────────────────────────────────────

/// Discriminant for a non-query-bearing `CREATE TABLE` variant. Each
/// variant maps to one `AstCreateTableVariant` discriminant; `Ctas` is
/// absent because that variant lowers to [`RelPlan::CreateAsQuery`]
/// instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CreateTableFormKind {
    /// `CREATE TABLE t (col type, …)` — blank table definition.
    Plain,
    /// `CREATE TABLE t LIKE source` — inherits column list from
    /// an existing table (no query body; catalog-dependent arity).
    Like,
    /// `CREATE TABLE t CLONE source` — shallow/deep clone of an
    /// existing table (Snowflake / Databricks). May carry a
    /// `DEEP`/`SHALLOW` qualifier and a temporal `AT`/`BEFORE`
    /// specification (surfaced as spans on the AST; not yet
    /// decomposed into typed sub-fields).
    Clone,
    /// `CREATE TABLE t USING TEMPLATE (SELECT …)` — Snowflake-specific
    /// form that derives the schema from a `INFER_SCHEMA` query.
    /// The template query is stored as a span on the AST but is *not*
    /// a relational body of this table's definition (it is used only
    /// to derive the schema at DDL time).
    UsingTemplate,
    /// `CREATE TABLE t FROM ARCHIVE <url>` — archive-based table
    /// creation (Snowflake). Non-query-bearing.
    FromArchive,
    /// `CREATE TABLE t FROM SNAPSHOT SET <name>` — snapshot-set-based
    /// table creation (Snowflake). Non-query-bearing.
    FromSnapshotSet,
}

impl CreateTableFormKind {
    /// Stable snake_case label for pretty-printing / harness output.
    /// Exhaustive — adding a variant fails compilation here.
    pub fn as_str(self) -> &'static str {
        match self {
            CreateTableFormKind::Plain => "plain",
            CreateTableFormKind::Like => "like",
            CreateTableFormKind::Clone => "clone",
            CreateTableFormKind::UsingTemplate => "using_template",
            CreateTableFormKind::FromArchive => "from_archive",
            CreateTableFormKind::FromSnapshotSet => "from_snapshot_set",
        }
    }
}
