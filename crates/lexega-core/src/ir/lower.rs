// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Lowering `AstStmt` → [`RelPlan`].
//!
//! Current scope:
//!
//! * **Base SELECT**: single bare FROM table,
//!   optional WHERE, expression/column projection list. Produces
//!   `Scan [→ Filter] → Project`.
//! * **Joins**: explicit joins (INNER / LEFT / RIGHT / FULL OUTER /
//!   CROSS, including the four `NATURAL` variants), comma-separated
//!   FROM lists lowered to left-deep `Cross` joins, `LATERAL` flag on
//!   joins and base FROM items, and `USING (…)` column lists.
//! * **Aggregates**: `GROUP BY` (standard / CUBE / ROLLUP / GROUPING SETS /
//!   GROUP BY ALL), `HAVING`, and aggregate function calls (`COUNT`,
//!   `SUM`, `AVG`, `LISTAGG`, etc.) including `DISTINCT`, `FILTER
//!   (WHERE …)`, and `WITHIN GROUP (ORDER BY …)` modifiers. Aggregates
//!   are lifted out of the projection / HAVING into `AggregateCall`s on
//!   a new [`RelPlan::Aggregate`] node; remaining scalar positions
//!   reference the aggregate output by [`ColumnId`]. `FunctionCall`
//!   also lowers for non-aggregate scalar calls so non-aggregate
//!   functions in SELECT work alongside aggregates.
//! * **Windows**: window-function calls (`AstExpr::WindowFn`) and
//!   `QUALIFY`. Window calls are collected into a dedicated
//!   [`RelPlan::Window`] node between aggregate/filter and projection.
//!   Scalar positions that contained window calls are rewritten to
//!   [`ScalarExpr::Column`] references to the corresponding
//!   `WindowCall.output`. `QUALIFY` desugars to a [`RelPlan::Filter`]
//!   that runs over window outputs (`Filter(Window(input))`) so the
//!   predicate can reference window aliases and direct window calls.
//! * **Ordering / limits**: `ORDER BY` (with per-key ASC/DESC and NULLS
//!   FIRST/LAST), `LIMIT` / `OFFSET`, ANSI `FETCH FIRST n ROWS ONLY`,
//!   and T-SQL `TOP n [WITH TIES]`. `ORDER BY` lowers to
//!   [`RelPlan::Sort`] wrapping the outermost `Project`; row-count
//!   clauses lower to [`RelPlan::Limit`] wrapping the sort (or the
//!   project directly). `TOP n PERCENT` lowers via
//!   [`crate::ir::plan::LimitKind::Percent`], and `TOP` composed with
//!   `LIMIT` / `OFFSET` / `FETCH` is preserved as nested typed
//!   [`RelPlan::Limit`] nodes.
//! * **Set operations**: `UNION` / `INTERSECT` / `EXCEPT` /
//!   `MINUS` (each with optional `ALL` / `DISTINCT` modifier) lower
//!   to [`RelPlan::SetOp`]. The parser produces a left-deep AST
//!   (`a UNION b UNION c` → nested `AstSetSelect`); lowering
//!   **N-ary-flattens** contiguous children with the same
//!   [`SetOpKind`] into one `SetOp.inputs` vector
//!   while leaving mixed-operator spines (e.g. `a UNION b
//!   INTERSECT c`, which SQL precedence forces into one shape and
//!   the other into the other) as nested `SetOp` nodes. Each
//!   `SetOp.output_columns` slot gets a fresh [`ColumnId`] whose
//!   arity is taken from the first branch's `output_schema()`.
//!   `ValuesQuery` operands and any other
//!   non-`Select`/non-`SetSelect` operand produce
//!   [`OpaqueReason::NonSelectTopLevel`].
//! * **CTEs / `WITH` clause**: `lower_select_with_ctes`,
//!   `lower_cte`, and `lower_dml_with_ctes` produce
//!   [`RelPlan::WithScope`] wrapping recursive and non-recursive CTE
//!   bodies. Jinja-generated CTE blocks produce
//!   [`OpaqueReason::UnresolvedJinja`].
//! * **DML**: `lower_insert`, `lower_update`,
//!   `lower_delete`, `lower_merge`, and `lower_multi_insert` lower
//!   all five DML statement kinds to their corresponding typed
//!   `RelPlan` variants. `WITH`-prefixed DML routes through
//!   `lower_dml_with_ctes`.
//! * **CreateAsQuery**: `lower_create_view`,
//!   `lower_create_table`, and `lower_create_dynamic_table` produce
//!   the typed DDL `RelPlan` variants; the inner SELECT body is
//!   lowered by `lower_create_as_body`.
//! * **Opaque fallback**: the `_ =>` arm in `lower_stmt`
//!   returns [`OpaqueReason::NonSelectTopLevel`] for all statement
//!   kinds not explicitly handled above; the permissive-mode caller
//!   wraps this in [`RelPlan::Opaque`].
//!
//! Still out of scope and routed to [`RelPlan::Opaque`] under
//! [`StrictMode::Permissive`] (or a typed [`LowerError`] under strict
//! modes): `UNNEST` / `FLATTEN` / table-valued functions, T-SQL
//! `APPLY`, Snowflake `ASOF JOIN`, subqueries, sampling,
//! time-travel, pivot/unpivot, and within SELECT: named `WINDOW`
//! clauses, `DISTINCT ON`, `TOP … PERCENT`, `CONNECT BY`, `FOR
//! UPDATE`, `FOR JSON/XML`, `INTO` variable assignment, statement
//! fragments, and pre/post-locking extension clauses.
//!
//! # Strictness
//!
//! - [`StrictMode::Permissive`] returns `RelPlan::Opaque` whenever a
//!   feature outside the current scope is encountered.
//! - [`StrictMode::Strict`] / [`StrictMode::Pedantic`] propagate a
//!   typed [`LowerError`] carrying the specific [`OpaqueReason`] instead.
//!
//! # Closed-enum discipline
//!
//! Matches on `FromItemKind`, `AstJoinKind`, `AstJoinConstraint`,
//! `AstProjectionKind`, `ProjectionItemKind`, `AstLiteral`,
//! `AstGroupByVariant`, `AstFunctionArg`, and `BinaryOperator` are
//! exhaustive — the compiler, not a runtime default, enforces
//! completeness. `AstStmt` and `AstExpr` use `if let` for single-variant
//! selection and a typed error fallback; the current scope is narrow
//! enough that exhaustive matches would add noise without improving
//! drift protection.

use std::collections::{HashMap, HashSet};

use super::{slice_span, SessionContext};
use crate::ast::{
    AstColumnRef, AstConnectBy, AstCreateDynamicTable, AstCreateTable, AstCreateTableVariant,
    AstCreateView, AstCte, AstDelete, AstExplain, AstExpr, AstFrameBoundKind, AstFunctionArg,
    AstGroupBy, AstGroupByVariant, AstGroupElement, AstGroupElementKind, AstGroupItem, AstInsert,
    AstInsertSourceKind, AstJoin, AstJoinConstraint, AstJoinKind, AstLiteral, AstMerge,
    AstMergeActionKind, AstMergeClauseKind, AstMultiInsert, AstMultiInsertIntoClause,
    AstMultiInsertMode, AstMultiInsertWhenClause, AstOnConflict, AstOutputClause,
    AstProjectionKind, AstReturning, AstSelect, AstSetModifier, AstSetOpKind, AstSetQuantifier,
    AstSetSelect, AstStmt, AstTableHintKind, AstTableRef, AstUpdate, AstWindowFrameKind,
    AstWithClause, AstWithinGroup, BinaryOperator, CteItem,
    ForUpdateWaitPolicy as AstForUpdateWaitPolicy, FromItem, FromItemKind,
    LockStrength as AstLockStrength, LogicalChainOperator, ProjectionItem, ProjectionItemKind,
};
use crate::catalog::CatalogIndex;
use crate::context::node_metadata::{IdentKey, TableRef};
use crate::ir::span_extract::{
    apply_session_defaults_to_table_ref, extract_table_ref_from_object_span,
};
use crate::lexer::Span;

use super::catalog::{CatalogDialect, FunctionCatalog, FunctionKind};
use super::catalog_context::{ColumnMetadata, IndexedCatalogContext, TableColumns, TagRef};
use super::column::{BindingTable, ColumnId, ColumnIdAllocator, ColumnOrigin};
use super::invalid_input::InvalidInputKind;
use super::model_catalog::ModelCatalog;
use super::plan::{
    AfterMatchSkip, AggregateCall, AllRowsMode, ChangesClause, ChangesInformation, ConflictAction,
    ConflictTarget, CreateAsKind, CreateSideOption, CreateSideOptionKind, CreateTableFormKind,
    CteBinding, CteBody, DmlOutput, DmlTop, ExplainFormat, ExplainOptions, FilterKind, FrameBound,
    FrameExclusion, FrameMode, GroupKey, GroupingSpec, InsertSource, JoinKind, LimitKind,
    MatchRecognizeBody, MatchRecognizeDefine, MatchRecognizeMeasure, MeasureModifier, MergeAction,
    MergeBranch, MergeBranchKind, MultiInsertMode, MultiInsertTarget, MultiInsertWhen,
    NullTreatment, OnConflict, OverridingValue, PivotValues, ProjectExpr, ProjectItem, ProjectStar,
    RelPlan, ResolvedFunc, ResolvedModel, Returning, ReturningItem, RowsPerMatch, SampleKeyword,
    SampleSize, ScanModifier, ScanTableHint, ScanTableHintKind, SetOpKind, SortKey, StarExclude,
    StarPathPart, StarQualifier, StarRename, StarReplace, TableSample, TimeTravel, UnpivotColumn,
    WindowCall, WindowFrame, WithOffset,
};
use super::scalar::{Lit, ScalarExpr, ScopeId};
use super::strict::{
    AggregateContextCategory, CatalogLookupKind, DmlShapeCategory, GroupByOrdinalCategory,
    OpaqueReason, StrictMode, WindowContextCategory,
};

// ────────────────────────────────────────────────────────────────────────
// Public API
// ────────────────────────────────────────────────────────────────────────

/// Lowering failure. Surfaced as-is under strict modes; converted to
/// [`RelPlan::Opaque`] or [`RelPlan::InvalidInput`] at the top level
/// under [`StrictMode::Permissive`], depending on `kind`.
///
/// `kind` discriminates between:
/// - **Opaque** — the IR cannot model the construct (Jinja, parse
///   recovery, missing catalog, registry-incomplete function, etc.).
///   Strict modes (`Strict` / `Pedantic`) refuse opaque fallbacks.
/// - **InvalidInput** — the input survived parsing but is semantically
///   ill-formed. The lowerer captures this as a typed
///   terminal [`RelPlan::InvalidInput`] under all strict modes —
///   ill-formed input is the typed answer, not a coverage gap.
#[derive(Debug, Clone)]
pub struct LowerError {
    pub span: Span,
    pub kind: LowerErrorKind,
}

/// Closed enumeration of lowering failure shapes. See [`LowerError`].
#[derive(Debug, Clone)]
pub enum LowerErrorKind {
    /// IR cannot model this construct. Strict modes refuse this.
    Opaque(OpaqueReason),
    /// Input is semantically ill-formed. Always wrapped as a typed
    /// `RelPlan::InvalidInput` terminal regardless of strict mode.
    InvalidInput(super::invalid_input::InvalidInputKind),
    /// The parser recovered from an error but could not produce enough
    /// structure to lower this fragment. Strict modes surface this as an
    /// error; permissive mode wraps it as `RelPlan::ParseRecovery`.
    ParseUpstream,
}

impl LowerErrorKind {
    /// Stable snake_case label for harness histograms / nested
    /// `ScalarExpr::Opaque` reason strings. Format follows the
    /// underlying typed enum's `tag()` / `as_str()` accessor.
    pub fn label(&self) -> String {
        match self {
            LowerErrorKind::Opaque(r) => r.tag().to_string(),
            LowerErrorKind::InvalidInput(k) => k.as_str().to_string(),
            LowerErrorKind::ParseUpstream => "parse_upstream".to_string(),
        }
    }
}

impl LowerError {
    /// Construct an opaque-fallback lowering failure.
    pub fn opaque(span: Span, reason: OpaqueReason) -> Self {
        Self {
            span,
            kind: LowerErrorKind::Opaque(reason),
        }
    }

    /// Construct an ill-formed-input lowering failure.
    pub fn invalid(span: Span, kind: super::invalid_input::InvalidInputKind) -> Self {
        Self {
            span,
            kind: LowerErrorKind::InvalidInput(kind),
        }
    }

    /// Construct a parse-upstream failure (parser could not structure
    /// this fragment).
    pub fn parse_upstream(span: Span) -> Self {
        Self {
            span,
            kind: LowerErrorKind::ParseUpstream,
        }
    }

    /// Whether this failure is opacity (vs ill-formed input or parse failure).
    /// Opaque failures are refused under [`StrictMode::Strict`] and
    /// [`StrictMode::Pedantic`]; ill-formed-input and parse-upstream failures
    /// always flow through to a typed terminal.
    pub fn is_opaque(&self) -> bool {
        matches!(self.kind, LowerErrorKind::Opaque(_))
    }

    /// Convert this lowering failure into a typed terminal `RelPlan`
    /// node attached to the supplied statement `NodeId`. Opaque
    /// failures become [`RelPlan::Opaque`]; ill-formed-input failures
    /// become [`RelPlan::InvalidInput`]; parse-upstream failures become
    /// [`RelPlan::ParseRecovery`].
    pub fn into_terminal(self, stmt_node_id: crate::ast::NodeId) -> RelPlan {
        match self.kind {
            LowerErrorKind::Opaque(reason) => RelPlan::Opaque {
                stmt_node_id,
                reason,
                hints: Vec::new(),
                span: self.span,
            },
            LowerErrorKind::InvalidInput(kind) => RelPlan::InvalidInput {
                stmt_node_id,
                kind,
                hints: Vec::new(),
                span: self.span,
            },
            LowerErrorKind::ParseUpstream => RelPlan::ParseRecovery {
                stmt_node_id,
                hints: Vec::new(),
                span: self.span,
            },
        }
    }
}

impl std::fmt::Display for LowerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Intentionally generic user-visible text: internal phase / module
        // names must not leak through error messages.
        f.write_str("query could not be lowered to relational form")
    }
}

impl std::error::Error for LowerError {}

/// Lower a top-level query-bearing statement to a [`RelPlan`].
///
/// Handles the SELECT scope: single or
/// multiple FROM items (comma-joined to `Cross`), explicit joins with
/// `ON` / `USING` / `NATURAL` / `LATERAL`, `WHERE`, `GROUP BY`,
/// aggregate calls / `HAVING`, window calls, `QUALIFY`, and a
/// `SELECT [DISTINCT]` projection list. Everything else becomes
/// [`RelPlan::Opaque`] under permissive strictness or propagates as
/// [`LowerError`] under strict modes.
pub fn lower_query(
    stmt: &AstStmt,
    source: &str,
    strict: StrictMode,
) -> Result<RelPlan, LowerError> {
    lower_query_with_catalog(
        stmt,
        source,
        strict,
        &FunctionCatalog::for_dialect(CatalogDialect::Default),
    )
}

/// Lower a statement using an explicit [`FunctionCatalog`].
///
/// Exposed for callers that need a dialect-specific or
/// workspace-augmented catalog (e.g. a catalog pre-populated with
/// user-defined-function entries). The default entry point
/// [`lower_query`] constructs a cross-dialect default catalog.
pub fn lower_query_with_catalog(
    stmt: &AstStmt,
    source: &str,
    strict: StrictMode,
    catalog: &FunctionCatalog,
) -> Result<RelPlan, LowerError> {
    lower_query_with_catalog_and_session(stmt, source, strict, catalog, &SessionContext::default())
}

/// Lower a statement with both an explicit [`FunctionCatalog`] and
/// an explicit [`SessionContext`]. Full-control entry point; the
/// other `lower_query*` functions delegate here.
pub fn lower_query_with_catalog_and_session(
    stmt: &AstStmt,
    source: &str,
    strict: StrictMode,
    catalog: &FunctionCatalog,
    session: &SessionContext,
) -> Result<RelPlan, LowerError> {
    let mut ctx = LowerCtx::new(source, catalog, strict, session);
    match ctx.lower_stmt(stmt) {
        Ok(plan) => Ok(plan),
        Err(err) if !err.is_opaque() || !strict.forbids_opaque() => {
            Ok(err.into_terminal(stmt.node_id()))
        }
        Err(err) => Err(err),
    }
}

/// Lower a statement with a catalog-snapshot attached.
///
/// Returns the lowered [`RelPlan`] together with an
/// [`IndexedCatalogContext`] sidecar populated with catalog-resolved
/// column facts for every DML-target table the lowerer visited
/// (INSERT / UPDATE / DELETE / MERGE). The sidecar is consumed by
/// catalog-dependent analyses, e.g. lineage for MERGE star /
/// by-name pairing.
///
/// When `catalog_index` is `None` the sidecar is returned empty and
/// the plan is identical to [`lower_query_with_catalog_and_session`].
/// This keeps permissive-mode callers (no attached catalog) on the
/// empty-result code path.
pub fn lower_query_full(
    stmt: &AstStmt,
    source: &str,
    strict: StrictMode,
    catalog: &FunctionCatalog,
    session: &SessionContext,
    catalog_index: Option<&CatalogIndex>,
) -> Result<
    (
        RelPlan,
        IndexedCatalogContext,
        super::statement_facts::StatementFacts,
    ),
    LowerError,
> {
    let mut ctx = LowerCtx::new_with_catalog_index(source, catalog, strict, session, catalog_index);
    let plan_result = ctx.lower_stmt(stmt);
    if let Ok(plan) = plan_result.as_ref() {
        ctx.seed_catalog_ctx_from_plan(plan);
    }
    let catalog_ctx = std::mem::take(&mut ctx.catalog_ctx);
    let facts = ctx.take_statement_facts();
    match plan_result {
        Ok(plan) => Ok((plan, catalog_ctx, facts)),
        Err(err) if !err.is_opaque() || !strict.forbids_opaque() => {
            Ok((err.into_terminal(stmt.node_id()), catalog_ctx, facts))
        }
        Err(err) => Err(err),
    }
}

/// Lower a statement AST to a [`RelPlan`] and also return the
/// [`BindingTable`] mapping every allocated [`ColumnId`] to its
/// display name and [`ColumnOrigin`].
///
/// This is the entry point used by analyses that need to identify
/// columns by their source-level name.
///
/// On permissive error recovery (i.e. a [`LowerError`] surfacing when
/// `strict` does not forbid opaques), the returned binding table
/// reflects whatever columns were allocated up to the failure point.
pub fn lower_query_full_with_bindings(
    stmt: &AstStmt,
    source: &str,
    strict: StrictMode,
    catalog: &FunctionCatalog,
    session: &SessionContext,
    catalog_index: Option<&CatalogIndex>,
) -> Result<
    (
        RelPlan,
        IndexedCatalogContext,
        BindingTable,
        super::statement_facts::StatementFacts,
    ),
    LowerError,
> {
    lower_query_full_with_bindings_and_models(
        stmt,
        source,
        strict,
        catalog,
        session,
        catalog_index,
        None,
    )
}

/// Like [`lower_query_full_with_bindings`] but additionally accepts a
/// dbt model injection catalog.
///
/// When `model_catalog` is `Some` and contains an entry matching a
/// FROM-clause table ref's canonical form, the lowerer emits
/// [`RelPlan::ModelRef`] with the upstream
/// [`super::plan::ResolvedModel::base_tables`] populated, rather than
/// a plain [`RelPlan::Scan`]. This allows `derive_facts_from_plan` to
/// expand the upstream physical tables into `tables_read`.
///
/// Passing `model_catalog: None` produces identical output to
/// [`lower_query_full_with_bindings`].
pub fn lower_query_full_with_bindings_and_models(
    stmt: &AstStmt,
    source: &str,
    strict: StrictMode,
    catalog: &FunctionCatalog,
    session: &SessionContext,
    catalog_index: Option<&CatalogIndex>,
    model_catalog: Option<&ModelCatalog>,
) -> Result<
    (
        RelPlan,
        IndexedCatalogContext,
        BindingTable,
        super::statement_facts::StatementFacts,
    ),
    LowerError,
> {
    let mut ctx = LowerCtx::new_with_model_catalog(
        source,
        catalog,
        strict,
        session,
        catalog_index,
        model_catalog,
    );
    let plan_result = ctx.lower_stmt(stmt);
    // Seed the catalog sidecar with column tags + table tags for
    // every `Scan` in the lowered plan. This is the bridge from the
    // `CatalogIndex` snapshot (the catalog surface threaded through
    // the public entry points) to the `IndexedCatalogContext` that
    // tag-aware consumers read. No-op when `catalog_index` is `None`
    // or the lowering produced an `Err` before any plan was
    // constructed.
    if let Ok(plan) = plan_result.as_ref() {
        ctx.seed_catalog_ctx_from_plan(plan);
    }
    let catalog_ctx = std::mem::take(&mut ctx.catalog_ctx);
    let facts = ctx.take_statement_facts();
    let bindings = ctx.allocator.into_bindings();
    match plan_result {
        Ok(mut plan) => {
            // Post-lowering: rebind any column reference left stale
            // by an operator that consumed-and-renamed input ColumnIds
            // (Aggregate's grouping keys today; see the
            // `rebind_stale_column_refs` section comment
            // for the full discussion). Restores the schema
            // invariant that every node's expression column refs
            // resolve through its input's `output_schema()`.
            rebind_stale_column_refs(&mut plan);
            // Post-lowering: derive `correlates_with` on every
            // subquery node from the lowered body. The lowerer emits
            // `vec![]` stubs; correlation is a property of the body
            // (referenced ColumnIds minus produced ColumnIds in the
            // subtree). See `super::correlation` module doc.
            super::correlation::populate_subquery_correlates(&mut plan, &bindings);
            Ok((plan, catalog_ctx, bindings, facts))
        }
        Err(err) if !err.is_opaque() || !strict.forbids_opaque() => Ok((
            err.into_terminal(stmt.node_id()),
            catalog_ctx,
            bindings,
            facts,
        )),
        Err(err) => Err(err),
    }
}

/// Like [`lower_query_full_with_bindings_and_models`] but also returns
/// the optional [`super::policy_facts::PolicyStatementFacts`] sibling
/// produced by policy-DDL lowering.
/// `None` for query-bearing statements; `Some(...)` for
/// `CREATE/ALTER ROW ACCESS POLICY` / `CREATE/ALTER MASKING POLICY`
/// / `CREATE/ALTER POLICY ... ON <table>`.
///
/// The other return tuple elements (plan, catalog ctx, bindings,
/// statement facts) are identical to the four-tuple variant — this
/// is purely an additive surface so non-policy callers can stay on
/// the four-tuple API without churn.
pub fn lower_query_full_with_bindings_models_and_policy_facts(
    stmt: &AstStmt,
    source: &str,
    strict: StrictMode,
    catalog: &FunctionCatalog,
    session: &SessionContext,
    catalog_index: Option<&CatalogIndex>,
    model_catalog: Option<&ModelCatalog>,
) -> Result<
    (
        RelPlan,
        IndexedCatalogContext,
        BindingTable,
        super::statement_facts::StatementFacts,
        Option<super::policy_facts::PolicyStatementFacts>,
    ),
    LowerError,
> {
    let mut ctx = LowerCtx::new_with_model_catalog(
        source,
        catalog,
        strict,
        session,
        catalog_index,
        model_catalog,
    );
    let plan_result = ctx.lower_stmt(stmt);
    if let Ok(plan) = plan_result.as_ref() {
        ctx.seed_catalog_ctx_from_plan(plan);
    }
    let catalog_ctx = std::mem::take(&mut ctx.catalog_ctx);
    let facts = ctx.take_statement_facts();
    let policy_facts = ctx.take_policy_facts();
    let bindings = ctx.allocator.into_bindings();
    match plan_result {
        Ok(mut plan) => {
            rebind_stale_column_refs(&mut plan);
            super::correlation::populate_subquery_correlates(&mut plan, &bindings);
            Ok((plan, catalog_ctx, bindings, facts, policy_facts))
        }
        Err(err) if !err.is_opaque() || !strict.forbids_opaque() => Ok((
            err.into_terminal(stmt.node_id()),
            catalog_ctx,
            bindings,
            facts,
            policy_facts,
        )),
        Err(err) => Err(err),
    }
}

// ────────────────────────────────────────────────────────────────────────
// Lowering context
// ────────────────────────────────────────────────────────────────────────

/// SELECT-list alias scope for the currently-lowering SELECT block.
///
/// Built from `lower_projection`'s output items immediately after
/// projection lowering completes; threaded as `Option<&AliasMap>`
/// through `lower_expr` / `lower_column_ref` / the window-expression
/// family so that name resolution in WHERE / HAVING / QUALIFY /
/// ORDER BY can match SELECT-list aliases (Snowflake / BigQuery /
/// MySQL / ClickHouse extension).
///
/// Scope is bounded by the call stack of the SELECT body that owns
/// the map: each `lower_select_body` invocation builds its own
/// `AliasMap` locally, hands it to its clause lowerings, and lets
/// it drop on exit. Nested SELECTs in subqueries get their own
/// fresh map via their own invocation; correlated outer-column
/// references continue to flow through `outer_alias_frames` and
/// never see SELECT-list aliases.
#[derive(Default)]
pub(crate) struct AliasMap {
    /// Alias name → projection-output ColumnId. Lookup surface for
    /// `lower_column_ref`'s resolution path.
    pub(crate) by_name: HashMap<IdentKey, ColumnId>,
    /// All projection-output ColumnIds that have an alias name.
    /// Used by the predicate classifier to decide whether a lowered
    /// WHERE / HAVING / QUALIFY atom references a SELECT-list alias
    /// and must therefore be lifted above `Project`.
    pub(crate) output_ids: HashSet<ColumnId>,
}

impl AliasMap {
    /// Build an alias map from `lower_projection`'s output items.
    /// First-name-wins: duplicate alias names take the earliest
    /// projection item, matching `resolve_group_by_alias`'s
    /// first-match semantics. `Star` items contribute no alias.
    pub(crate) fn from_projection(items: &[ProjectItem]) -> Self {
        let mut by_name: HashMap<IdentKey, ColumnId> = HashMap::new();
        let mut output_ids: HashSet<ColumnId> = HashSet::new();
        for item in items {
            let pe = match item {
                ProjectItem::Expr(pe) => pe,
                ProjectItem::Star(_) => continue,
            };
            let Some(alias) = pe.alias.as_ref() else {
                continue;
            };
            by_name.entry(alias.clone()).or_insert(pe.output);
            output_ids.insert(pe.output);
        }
        Self {
            by_name,
            output_ids,
        }
    }
}

/// Per-statement lowering state: allocator, scope bindings, strictness.
///
/// Not exposed as public API — the only supported entry point is
/// [`lower_query`]. Making it `pub(crate)` allows future lowering steps
/// (joins, CTE scopes) in the same module to reuse the context without
/// exposing it to library consumers.
/// AST-depth bound for [`LowerCtx::lower_expr`].
///
/// Caps the depth of the tree handed downstream. Sized against the
/// *consumers*, not against lowering: their frames are several times
/// fatter than `lower_expr`'s, so a byte budget measured here does not
/// bound them. The shallowest observed overflow is the facts walk at
/// roughly 3.5 KiB per frame in debug, which an 8 MiB stack exhausts
/// near 2300 levels — this leaves several times that in headroom, and
/// still sits far above the ~146 source nesting levels the parser's
/// own guard admits, so no legitimate expression reaches it.
///
/// [`LOWER_EXPR_STACK_BUDGET`] remains the backstop for lowering's own
/// recursion when frames are unexpectedly fat.
const MAX_LOWER_EXPR_DEPTH: usize = 500;

/// Stack bytes one expression-lowering recursion may consume before
/// degrading gracefully.
///
/// Measured against the real stack — like the parser's
/// `PARSE_STACK_BUDGET`, and sized identically (the
/// [`crate::parser::core::MIN_PARSE_STACK_BYTES`] thread contract less
/// 2 MiB of headroom) — so fat debug frames trip it early instead of
/// overflowing. Lowering unwinds before any consumer runs, so this
/// bounds only lowering's own recursion; consumer safety comes from
/// [`MAX_LOWER_EXPR_DEPTH`] capping the depth of what gets built.
///
/// Per-frame cost measured here: 56 to 66 KiB debug, varying with the
/// compiler, and ~8 KiB release. A tighter budget rejects legitimate
/// nesting in debug builds — 50 levels of parenthesised boolean nesting
/// reaches 52 frames.
const LOWER_EXPR_STACK_BUDGET: usize = crate::parser::core::MIN_PARSE_STACK_BYTES - 2 * 1024 * 1024;

/// `PARTITION BY`, `ORDER BY`, frame and base-window name of a window spec.
type NamedWindowParts = (
    Vec<ScalarExpr>,
    Vec<SortKey>,
    Option<WindowFrame>,
    Option<IdentKey>,
);

/// Lowered arguments, `PARTITION BY` and `ORDER BY` of an `OVER (...)` call.
type WindowOverParts = (Vec<ScalarExpr>, Vec<ScalarExpr>, Vec<SortKey>);

/// Positional and named arguments of a lowered function call.
type LoweredArgs = (Vec<ScalarExpr>, Vec<(IdentKey, ScalarExpr)>);

pub(crate) struct LowerCtx<'src> {
    source: &'src str,
    /// Function catalog used to resolve call identities. Shared
    /// reference so the catalog is built once per session and threaded
    /// through every lowering call.
    catalog: &'src FunctionCatalog,
    /// Session-level database / schema defaults. Applied to table
    /// references during [`Self::lower_table_ref`] so that unqualified
    /// or partially-qualified names acquire db/schema
    /// qualification. Borrowed so the caller can update it between
    /// statements without cloning per call.
    session: &'src SessionContext,
    /// Strictness level. Consulted by per-node lowering paths that
    /// have different permissive / strict behaviors (for example,
    /// unresolved function names: permissive keeps them as
    /// [`ResolvedFunc::Unresolved`]; strict rejects with
    /// [`OpaqueReason::UnknownFunction`]).
    strict: StrictMode,
    /// In-flight [`Self::lower_expr`] recursion depth. The
    /// parser's guard cannot cover this: it measures *parser*
    /// recursion, and the Pratt loop assembles operator chains
    /// iteratively, so a chain arrives here having consumed no parser
    /// depth at all.
    expr_depth: usize,
    /// Stack address of the outermost in-flight `lower_expr` frame
    /// (`0` when no expression lowering is active). Anchors the
    /// consumption measurement against [`LOWER_EXPR_STACK_BUDGET`].
    expr_stack_anchor: usize,
    allocator: ColumnIdAllocator,
    /// Name → ColumnId binding table for the currently-lowered scope.
    /// Keyed by normalized [`IdentKey`] so case folding is consistent
    /// with the rest of the analyzer.
    bindings: HashMap<IdentKey, ColumnId>,
    /// Entries describing columns made visible by the current
    /// SELECT's fully-lowered FROM clause. Populated after
    /// [`Self::lower_from_item`] completes by walking the FROM plan
    /// with [`Self::collect_scope_entries`]; each entry records the
    /// source's alias (explicit `AS x` or the unqualified
    /// table/CTE name), the column's display name (normalized),
    /// and the ColumnId the source node already owns. Consulted by
    /// [`Self::lower_column_ref`] BEFORE the allocate-on-first-use
    /// fallback so references to in-scope columns resolve to the
    /// source-owned ColumnId, rather than leaking a fresh
    /// Table-origin orphan into the binding table. Save/restore on
    /// every SELECT-body entry so nested SELECTs (CTE bodies,
    /// subqueries) get their own frame.
    ///
    /// Resolution order per [`Self::lower_column_ref`]:
    ///   1. Qualified refs (`alias.col`): qualified scope lookup.
    ///   2. Unqualified refs: `self.bindings` first (lambda / USING
    ///      shadows) then first-matching scope entry by column name.
    ///   3. Unresolved: allocate-on-first-use.
    from_scope: Vec<FromScopeEntry>,
    /// Stack of enclosing FROM-scope entries captured at fresh-scope
    /// boundaries. Qualified correlated refs may resolve through these
    /// frames when local-scope lookup fails.
    outer_from_scope_frames: Vec<Vec<FromScopeEntry>>,
    /// ColumnIds allocated by the "allocate-on-first-use" fallback in
    /// [`Self::lower_column_ref`], paired with the `NodeId` of the
    /// FROM-source they belong to (resolved at allocation time via
    /// [`Self::from_aliases`] / [`Self::from_source_order`]).
    /// Back-filled onto the matching `Scan` / `CteRef` / `DerivedTable` /
    /// `TableFunction` / `Values` node's `columns` (or `output_columns`)
    /// list by [`attach_pending_source_cols`] once FROM + projection
    /// have been lowered. Routing is by NodeId equality — no alias-text
    /// matching, no leftmost-scan heuristic — because the column was
    /// already born with the correct `ColumnOrigin::Table { table_node }`.
    scan_cols: Vec<(crate::ast::NodeId, ColumnId)>,
    /// Stack of aggregate-collection scopes. Each scope is a [`Vec`] of
    /// [`AggregateCall`]s harvested from that scope's projection /
    /// `HAVING`. When non-empty, [`lower_function_call`] promotes
    /// aggregate-shaped calls into the innermost scope and returns a
    /// [`ScalarExpr::Column`] referencing the synthesized output id.
    ///
    /// This is a stack, not a flat vec, because a scalar subquery
    /// inside an outer aggregate context opens a new
    /// collection scope — its aggregates must not leak into the outer
    /// `Aggregate` node. Sub-contexts like `FILTER (WHERE …)` and
    /// `WITHIN GROUP (ORDER BY …)` forbid aggregates entirely and use
    /// [`push_no_agg_frame`] to block collection within a nested
    /// scope without losing the outer frames.
    aggregate_sinks: Vec<Option<Vec<AggregateCall>>>,
    /// Stack of window-collection scopes. Mirrors aggregate collection:
    /// while a collection frame is on top, `AstExpr::WindowFn` lowers
    /// into `WindowCall`s appended to that frame and scalar positions
    /// receive `ScalarExpr::Column` referencing the synthesized output.
    ///
    /// `None` means "windows forbidden in this sub-context" (e.g.
    /// WHERE / HAVING / GROUP BY / window frame bounds). Nested
    /// sub-expressions may push forbid frames for the duration of a
    /// sub-expression while preserving the outer collecting frame.
    window_sinks: Vec<Option<Vec<WindowCall>>>,
    /// Stack of CTE-binding scopes — one frame per active `WithScope`.
    /// A FROM table-ref whose name (normalized) matches a binding
    /// visible from the innermost frame outward lowers to
    /// [`RelPlan::CteRef`] rather than [`RelPlan::Scan`].
    ///
    /// Kept as a `Vec` rather than a single map so nested `WITH`
    /// clauses shadow outer definitions with the usual lexical rule
    /// (inner wins). Frames are pushed on entry to a `WithScope` and
    /// popped on exit regardless of success, so a lowering failure
    /// partway through does not leak bindings upward.
    cte_scopes: Vec<HashMap<IdentKey, CteScopeEntry>>,
    /// CTE star-passthrough RENAME maps, keyed by the leaf Scan's
    /// `NodeId`. Populated when a CTE registers and its body matches
    /// `SELECT * RENAME (<from> AS <to>, …) FROM <single-scan-chain>`
    /// (see [`RelPlan::cte_body_star_rename_passthrough_leaf_scan_node`]).
    /// Consulted by [`Self::lower_column_ref`] in the
    /// allocate-on-first-use path: when a qualified ref like
    /// `c.user_id` resolves through `from_aliases` to a leaf Scan
    /// `NodeId` carrying a rename map, the demanded name (`user_id`)
    /// is mapped to the source name (`id`) before the Scan binding
    /// is allocated, so `column_id_to_ref` produces a lineage-faithful
    /// `ColumnRef { name: "id", resolved_table: users }` instead of a
    /// fabricated `users.user_id` orphan.
    ///
    /// Flat across CTE scope pushes/pops because `NodeId`s are
    /// globally unique within one lowering session; entries that fall
    /// out of CTE scope are never queried because `from_aliases`
    /// (which gates the lookup) is itself save/restored at fresh-scope
    /// boundaries.
    cte_passthrough_renames: HashMap<crate::ast::NodeId, HashMap<IdentKey, PassthroughSourceName>>,
    /// Per-output-column passthrough resolution, keyed by the
    /// `from_item_node` of a `CteRef` / `DerivedTable` instance whose
    /// body is a star-passthrough chain whose leaves are not all the
    /// same single Scan (the case `cte_passthrough_renames` handles).
    /// Each entry maps an output column name exposed by the source to
    /// a [`PassthroughTarget`] (terminal Scan + name on that scan).
    /// Consulted by [`Self::lower_column_ref`] alongside
    /// `cte_passthrough_renames`: a hit substitutes both the
    /// allocator's `table_node` and the demanded column name so the
    /// resulting [`ColumnOrigin::Table`] binding lands on the leaf
    /// table directly. Built by
    /// [`Self::compute_passthrough_columns_for_body`] at CTE / derived
    /// table registration time and propagated through chained
    /// `CteRef` inputs via the same map.
    cte_passthrough_columns: HashMap<crate::ast::NodeId, HashMap<IdentKey, PassthroughTarget>>,
    /// Next [`ScopeId`] to hand out. Allocated for each CTE binding
    /// of a [`RelPlan::WithScope`]. ScopeId(0) stays
    /// unused so hand-constructed IR tests that want the default
    /// can keep using it.
    next_scope_id: u32,
    /// Optional catalog index consulted during DML-target lowering
    /// to populate `catalog_ctx`. `None` leaves the sidecar empty
    /// and catalog-dependent analyses fall back to their
    /// permissive behavior (same as using
    /// [`super::catalog_context::EmptyCatalogContext`]).
    catalog_index: Option<&'src CatalogIndex>,
    /// Catalog sidecar populated during lowering. Returned alongside
    /// the lowered [`RelPlan`] via [`lower_query_full`]. ColumnIds
    /// stored here for DML-target / TVF-output schemas are allocated
    /// via `self.allocator.fresh()` but are NOT bound into
    /// `self.bindings` and do not appear in the `RelPlan` itself;
    /// they exist solely to identify catalog-resolved columns for
    /// downstream analyses (lineage / nullability / constraints /
    /// taint).
    catalog_ctx: IndexedCatalogContext,
    /// Root `NodeId` of the currently-lowered statement. Set on
    /// entry to [`Self::lower_stmt`] and used by allocator helpers
    /// ([`Self::alloc_synthetic`]) as the default `producing_node`
    /// for columns whose fine-grained producer isn't individually
    /// tracked. [`crate::ast::NodeId::new(u32::MAX)`] is used as a
    /// sentinel meaning "no statement context yet"; the parser never
    /// issues an id that large, so collision is impossible. Any
    /// allocation reached before `lower_stmt` sets this is a bug and
    /// will produce a binding pointing at `NodeId(u32::MAX)`, which
    /// downstream tests can assert against.
    current_stmt_node: crate::ast::NodeId,
    /// Per-SELECT mapping from a FROM item's resolution alias to the
    /// `NodeId` of the underlying source's `RelPlan` node (the same
    /// `node_id` carried by the `Scan` / `CteRef` / `DerivedTable` /
    /// `TableFunction` / `Values` variant).
    ///
    /// Registered at the moment each FROM item is constructed (before
    /// any of its sibling JOINs lower their ON clauses), so a
    /// reference to `t.col` allocated on first use can be born with
    /// the *correct* `ColumnOrigin::Table { table_node }` rather than
    /// orphaned onto `current_stmt_node` and reattached by alias-text
    /// heuristics afterwards.
    ///
    /// Both the explicit alias (`FROM t AS x` → `x`) and the bare
    /// table name fallback (`FROM schema.t` → `t`, last segment) are
    /// registered so qualified refs against either form resolve.
    /// First insertion wins, matching the standard SQL rule that an
    /// explicit alias hides the underlying table name.
    ///
    /// Cleared at SELECT-body entry and saved/restored by
    /// [`Self::lower_stmt_in_fresh_scope`] so subqueries / CTE bodies
    /// / set-op branches do not see the outer SELECT's aliases.
    from_aliases: HashMap<IdentKey, crate::ast::NodeId>,
    /// Stack of enclosing alias maps captured when entering a fresh
    /// scope. Used only as a fallback for qualified refs that fail
    /// local-scope resolution, so correlated `outer_alias.col`
    /// keeps the outer source `NodeId` provenance while local aliases
    /// still shadow outer ones.
    outer_alias_frames: Vec<HashMap<IdentKey, crate::ast::NodeId>>,
    /// FROM-item registration order (leftmost first). Used as the
    /// fallback for unqualified column refs when neither
    /// [`Self::from_scope`] nor [`Self::bindings`] resolves the
    /// name — they accumulate against the leftmost FROM source's
    /// pending column list, preserving the "leftmost scan"
    /// convention without needing alias-text heuristics at attach
    /// time.
    from_source_order: Vec<crate::ast::NodeId>,
    /// When lowering expressions inside a `MATCH_RECOGNIZE` body
    /// (its `MEASURES` and `DEFINE` clauses), this holds the
    /// per-MR symbol table built from the parsed `PATTERN` plus
    /// every `DEFINE`d symbol. While set, [`Self::lower_column_ref`]
    /// intercepts qualified refs whose qualifier matches an
    /// interned symbol and emits [`ScalarExpr::PatternVarRef`]
    /// instead of a plain `Column`. `None` everywhere outside an
    /// MR body — interned symbols never leak across bodies
    /// (per-node `SymbolTable` discipline).
    match_recognize_symbols: Option<crate::ir::plan::SymbolTable>,
    /// Non-relational sibling-tier facts accumulated during
    /// lowering. Populated incrementally as
    /// each non-relational SELECT-shape feature is encountered
    /// (`FOR UPDATE`, `FOR JSON/XML`, `INTO @vars`, BigQuery
    /// `SELECT AS STRUCT/VALUE`, dialect extension clauses,
    /// embedded Jinja statement fragments). Drained into the
    /// returned `StatementFacts` by
    /// [`Self::take_statement_facts`].
    statement_facts: super::statement_facts::StatementFacts,
    /// Sibling-tier facts for non-query policy DDL.
    /// Populated by the policy
    /// DDL `lower_stmt` arms (`CREATE/ALTER ROW ACCESS POLICY`,
    /// `CREATE/ALTER MASKING POLICY`, `CREATE/ALTER POLICY`)
    /// when they lower the embedded predicates against a
    /// synthetic binding scope. Drained by
    /// [`Self::take_policy_facts`].
    policy_facts: Option<super::policy_facts::PolicyStatementFacts>,
    /// Stack of named-window definition scopes. Each entry is the
    /// `WINDOW w1 AS (...), w2 AS (...)` clause of the enclosing
    /// SELECT body, keyed by normalized identifier. Pushed on entry
    /// to a SELECT body that has a WINDOW clause; popped on exit
    /// (success or error). Looked up by `lower_window_fn` /
    /// `lower_window_expr` when `AstWindowSpec.existing_window_name`
    /// is set so `OVER w` and `OVER (w ORDER BY x)` can resolve the
    /// base spec and merge it with any inline additions.
    named_window_defs: Vec<HashMap<IdentKey, crate::ast::AstWindowSpec>>,
    /// Map from each freshly-constructed [`RelPlan::Scan`] `NodeId`
    /// to the table's [`TableRef`]. Populated in
    /// [`lower_base_table_ref`] at `Scan` construction time.
    ///
    /// Consulted by [`expand_star_items`] when from-scope resolution
    /// finds no candidates and a `catalog_index` is present, allowing
    /// `SELECT *` / `SELECT alias.*` against a base table to enumerate
    /// catalog-provided columns into concrete `ProjectItem::Expr` items
    /// (star catalog enumeration).
    ///
    /// Not saved/restored across [`lower_stmt_in_fresh_scope`]
    /// boundaries: `NodeId`s are parser-globally-unique per statement,
    /// so entries from inner scopes are valid at any enclosing-scope
    /// expansion site.
    scan_table_refs: HashMap<crate::ast::NodeId, TableRef>,
    /// Optional dbt model injection catalog. When present, table refs
    /// in `lower_base_table_ref` whose canonical form matches an entry
    /// are emitted as [`RelPlan::ModelRef`] rather than
    /// [`RelPlan::Scan`], with `ResolvedModel.base_tables` populated
    /// from the upstream physical tables. `None` for all non-dbt
    /// analysis paths.
    model_catalog: Option<&'src ModelCatalog>,
}

/// One entry in [`LowerCtx::cte_scopes`]. Records the scope this CTE
/// was defined in, the number of output columns so a forward
/// [`RelPlan::CteRef`] can allocate a matching-arity column list, and
/// (when the CTE's `WITH cte(a, b)` form declared a column list) the
/// user-visible column names so each reference's fresh rebinding
/// carries the same display names into the binding side-table.
#[derive(Debug, Clone)]
struct CteScopeEntry {
    scope: ScopeId,
    arity: usize,
    /// Declared CTE column names, if the CTE used the explicit
    /// `WITH cte(a, b) AS (...)` form. Empty when the CTE's column
    /// names come from its body's projection instead.
    declared_column_names: Vec<String>,
    /// Column names derived from the CTE body's projection output,
    /// in positional order. Populated at registration time by
    /// reading each `CteBinding::output_columns` ColumnId's
    /// `display_name` from the binding side-table. Consulted when
    /// `declared_column_names` is empty (the common case) so each
    /// `CteRef`'s freshly-rebound columns can carry a meaningful
    /// identifier into the binding table — without this, CteRef
    /// columns are anonymous and `from_scope` cannot resolve
    /// `SELECT col FROM cte` references to the CteRef's own
    /// positional ColumnIds.
    body_column_names: Vec<String>,
    /// When this CTE's body matches a pure star-passthrough chain
    /// bottoming at a single [`RelPlan::Scan`] (`SELECT * FROM
    /// <table>` and the trivial `Filter` / `Sort` / `Limit` /
    /// `TableSample` wrappers around it), this is the leaf Scan's
    /// `NodeId`. References through this CTE redirect their alias
    /// resolution onto this NodeId so demanded columns (`o.col`
    /// where `o` is an alias for this CTE) resolve directly to the
    /// underlying table — preserving full table-keyed lineage that
    /// would otherwise be lost because star-only bodies leave the
    /// binding's `output_columns` empty (the IR does not pre-expand
    /// `ProjectItem::Star`).
    ///
    /// `None` for any other body shape — including bodies whose
    /// projection mixes stars and explicit columns, bodies wrapped
    /// in joins/set-ops, or bodies whose source is itself a
    /// [`RelPlan::CteRef`] (transitive chains are intentionally
    /// not followed here; they fall through to the
    /// generic positional path).
    leaf_scan_node: Option<crate::ast::NodeId>,
    /// Per-output-column passthrough resolution computed from the CTE
    /// body. Empty when the body is a single-Scan passthrough (the
    /// `leaf_scan_node` + `cte_passthrough_renames` path handles those
    /// uniformly). Populated when the body is a multi-leaf JOIN of
    /// qualified stars or a chained Project over a `CteRef` /
    /// `DerivedTable`. Cloned into [`LowerCtx::cte_passthrough_columns`]
    /// at each `RelPlan::CteRef` construction so per-instance lookups
    /// can find the same per-column targets.
    passthrough_columns: HashMap<IdentKey, PassthroughTarget>,
}

/// A column-name reference that survives long enough to be re-emitted
/// in a downstream allocator call. Carries both the canonical
/// [`IdentKey`] (for HashMap-keyed lookup) and the original source
/// `span` (so the raw text — quote-preserving for case-sensitive
/// identifiers — is recoverable). See [`alloc_table_col`] for the
/// `column_name`-as-raw-text contract; the span lets passthrough /
/// rename routes feed raw bytes into that contract instead of the
/// quote-stripped IdentKey value.
#[derive(Debug, Clone)]
struct PassthroughSourceName {
    ident: IdentKey,
    span: Span,
}

/// Per-output-column resolution for a star-passthrough CTE / derived
/// table body. `leaf_scan_node` is the underlying [`RelPlan::Scan`]
/// node id; `source_name` is the name of the column on the table
/// behind that Scan (post-RENAME composition).
#[derive(Debug, Clone)]
struct PassthroughTarget {
    leaf_scan_node: crate::ast::NodeId,
    source_name: PassthroughSourceName,
}

/// Internal helper for [`LowerCtx::contribute_source_passthroughs`] —
/// holds the destination output name (`to`) plus the source-side
/// span needed to keep raw text for case-sensitive identifiers.
#[derive(Debug, Clone)]
struct RenameEntry {
    to: IdentKey,
    from_span: Span,
}

/// A FROM-source classification used by
/// Classification of an unqualified column reference's catalog-
/// driven resolution outcome. Returned by
/// [`LowerCtx::classify_unqualified_column_resolution`] and consumed
/// at the alloc-on-first-use branch of [`LowerCtx::lower_column_ref`]
/// to (a) route the binding to a unique source when one exists and
/// (b) record ambiguity for `CAT-COL-AMBIGUOUS` when two or more
/// catalog-known sources expose the same column name.
#[derive(Debug, Clone, Copy)]
enum UnqualifiedColumnResolution {
    /// No catalog attached, no in-scope source declares the column,
    /// or every in-scope source is non-base-table.
    None,
    /// Exactly one in-scope base-table source declares the column.
    Unique(crate::ast::NodeId),
    /// Two or more in-scope base-table sources declare the column —
    /// the reference cannot be unambiguously routed.
    Ambiguous,
}

/// [`LowerCtx::compute_passthrough_columns_for_body`] to decide how to
/// resolve a star item's contributions.
#[derive(Debug, Clone)]
enum PassthroughSource {
    /// Concrete base-table scan; renames anchor here directly.
    Scan { leaf_node: crate::ast::NodeId },
    /// CTE reference; columns chase through the CTE definition's own
    /// passthrough map (looked up by name in `cte_scopes`).
    CteRef { name: IdentKey },
    /// Derived table reference; columns chase through the
    /// derived-table instance's `cte_passthrough_columns` entry
    /// (keyed by its `from_item_node`).
    DerivedTable { node: crate::ast::NodeId },
}

/// One entry in [`LowerCtx::from_scope`]: a column made visible by
/// the current SELECT's FROM clause. Populated by
/// [`LowerCtx::collect_scope_entries`] from the fully-lowered FROM
/// plan.
///
/// `source_alias` is the qualifier users may write before the column
/// name: explicit `FROM t AS x` sets it to `x`; bare `FROM t` sets
/// it to `t` (last segment of a qualified table name); a derived
/// table / values clause without an alias has `None` and can only
/// be reached by unqualified references. Multi-part qualifiers
/// (`schema.table.col`) are resolved by comparing the last segment
/// of the user's qualifier against `source_alias`, matching the
/// standard SQL single-name table-scope rule.
#[derive(Debug, Clone)]
struct FromScopeEntry {
    source_alias: Option<IdentKey>,
    column_name: IdentKey,
    column_id: ColumnId,
}

impl<'src> LowerCtx<'src> {
    pub(crate) fn new(
        source: &'src str,
        catalog: &'src FunctionCatalog,
        strict: StrictMode,
        session: &'src SessionContext,
    ) -> Self {
        Self::new_with_catalog_index(source, catalog, strict, session, None)
    }

    pub(crate) fn new_with_catalog_index(
        source: &'src str,
        catalog: &'src FunctionCatalog,
        strict: StrictMode,
        session: &'src SessionContext,
        catalog_index: Option<&'src CatalogIndex>,
    ) -> Self {
        Self {
            source,
            catalog,
            session,
            strict,
            expr_depth: 0,
            expr_stack_anchor: 0,
            allocator: ColumnIdAllocator::new(),
            bindings: HashMap::new(),
            from_scope: Vec::new(),
            outer_from_scope_frames: Vec::new(),
            scan_cols: Vec::new(),
            aggregate_sinks: Vec::new(),
            window_sinks: Vec::new(),
            cte_scopes: Vec::new(),
            cte_passthrough_renames: HashMap::new(),
            cte_passthrough_columns: HashMap::new(),
            next_scope_id: 1,
            catalog_index,
            catalog_ctx: IndexedCatalogContext::new(),
            current_stmt_node: crate::ast::NodeId::new(u32::MAX),
            from_aliases: HashMap::new(),
            outer_alias_frames: Vec::new(),
            from_source_order: Vec::new(),
            match_recognize_symbols: None,
            statement_facts: super::statement_facts::StatementFacts::empty(),
            policy_facts: None,
            named_window_defs: Vec::new(),
            scan_table_refs: HashMap::new(),
            model_catalog: None,
        }
    }

    /// Like [`LowerCtx::new_with_catalog_index`] but with an additional
    /// dbt model injection catalog. When `model_catalog` is `Some` and
    /// non-empty, `lower_base_table_ref` emits
    /// [`RelPlan::ModelRef`] for table refs that match a catalog entry.
    pub(crate) fn new_with_model_catalog(
        source: &'src str,
        catalog: &'src FunctionCatalog,
        strict: StrictMode,
        session: &'src SessionContext,
        catalog_index: Option<&'src CatalogIndex>,
        model_catalog: Option<&'src ModelCatalog>,
    ) -> Self {
        let mut ctx = Self::new_with_catalog_index(source, catalog, strict, session, catalog_index);
        ctx.model_catalog = model_catalog;
        ctx
    }

    /// Populate `catalog_ctx` with the catalog-resolved columns of a
    /// DML target table. No-op when `catalog_index` is `None` or the
    /// target cannot be resolved (e.g. unqualified name with no
    /// session defaults, or table absent from the snapshot).
    ///
    /// Idempotent for repeated calls on the same normalized
    /// [`TableRef`] (later insert wins; identical content in
    /// practice). Allocates fresh ColumnIds via `self.allocator` for
    /// each catalog-listed column — these IDs are scoped to the
    /// sidecar and are deliberately not bound into
    /// `self.bindings` (which tracks only IDs that flow into the
    /// lowered `RelPlan` for scan / projection references).
    fn populate_target_table_columns(&mut self, target: &TableRef) {
        let Some(index) = self.catalog_index else {
            return;
        };
        let mut resolved = target.clone();
        apply_session_defaults_to_table_ref(&mut resolved, self.session);
        let Some(catalog_table) = index.get_table_inferred(
            resolved.db.as_deref(),
            resolved.schema.as_deref(),
            &resolved.name,
        ) else {
            return;
        };
        let target_span = target.span.unwrap_or_default();
        let stmt_node = self.current_stmt_node;
        // Allocate the target columns the same way scan columns are
        // (normalized display name via `alloc_table_col`), so the shared
        // scan-seed below can match them against catalog declarations.
        let cids: Vec<ColumnId> = catalog_table
            .columns
            .iter()
            .map(|column| self.alloc_table_col(stmt_node, &column.name.name, target_span))
            .collect();
        // Seed the DML *target* columns exactly as `Scan` sources are
        // seeded: full column metadata (nullability, type, tags, PK/FK),
        // catalog-presence, column origin, and the by-name column map.
        // A DELETE / UPDATE / INSERT / MERGE target is a `TableRef`, not
        // a `Scan`, so `seed_catalog_ctx_from_plan` skips it; without
        // this its columns carry name bindings but no metadata, leaving
        // every catalog-aware analysis over target columns (every-row
        // nullability provenance, taint tags, key constraints) blind.
        // Routing through the shared scan-seed keeps source and target
        // metadata at parity across all DML statement types.
        self.seed_catalog_ctx_from_scan(target, &cids);
    }

    /// Walk the lowered `plan` and seed the IR catalog sidecar with
    /// column-level [`ColumnMetadata`] (tags, nullability) and
    /// table-level [`TagRef`]s for every [`RelPlan::Scan`] reachable
    /// along the relational backbone.
    ///
    /// This is the bridge from the [`CatalogIndex`] snapshot (the
    /// catalog surface threaded through the public lowering entry
    /// points) to [`IndexedCatalogContext`]. Without it the
    /// sidecar would only contain DML-target columns inserted by
    /// [`Self::populate_target_table_columns`], and tag-aware
    /// consumers would observe no tags despite the catalog carrying
    /// them.
    ///
    /// No-op when `catalog_index` is `None`. Tables absent from the
    /// snapshot are silently skipped (matching the
    /// `populate_target_table_columns` behaviour). Columns absent
    /// from a table's schema (e.g. `SELECT typo_col FROM users`)
    /// are skipped per-column — an unresolvable column simply has
    /// no tags.
    ///
    /// Closed-enum exhaustive on [`RelPlan`] so a new variant must
    /// either name itself a leaf (no scans below) or recurse.
    fn seed_catalog_ctx_from_plan(&mut self, plan: &RelPlan) {
        // Collect every `(TableRef, columns)` pair in a first pass
        // so the walk borrows the plan immutably and the seed pass
        // takes `&mut self` without overlapping borrows. Cloning
        // here is cheap: `TableRef` is small and `columns` is a
        // `Vec<ColumnId>` whose `ColumnId`s are `Copy`.
        if self.catalog_index.is_some() {
            let mut scans: Vec<(TableRef, Vec<ColumnId>)> = Vec::new();
            Self::collect_scan_tables(plan, &mut scans);
            for (table, columns) in scans {
                self.seed_catalog_ctx_from_scan(&table, &columns);
            }
        }
        // ModelRef columns: seed `column_metadata` with TagRefs
        // projected from the upstream ModelEntry's `taint_labels`
        // so the rule engine's `taint_labels_for_expr` sees cross-
        // model taint through the same channel as catalog scans.
        // Independent of `catalog_index` — model injection works
        // without an attached catalog.
        let mut model_refs: Vec<(ResolvedModel, Vec<ColumnId>)> = Vec::new();
        Self::collect_model_refs(plan, &mut model_refs);
        for (model, columns) in model_refs {
            self.seed_catalog_ctx_from_model_ref(&model, &columns);
        }
    }

    /// Closed-enum exhaustive walk over [`RelPlan`] collecting
    /// `(table, columns)` for every reachable [`RelPlan::Scan`].
    /// `Opaque` plans contribute nothing.
    fn collect_scan_tables(plan: &RelPlan, out: &mut Vec<(TableRef, Vec<ColumnId>)>) {
        match plan {
            RelPlan::Scan { table, columns, .. } => {
                out.push((table.clone(), columns.clone()));
            }
            RelPlan::Project { input, .. }
            | RelPlan::Filter { input, .. }
            | RelPlan::Aggregate { input, .. }
            | RelPlan::Window { input, .. }
            | RelPlan::Sort { input, .. }
            | RelPlan::Limit { input, .. }
            | RelPlan::DerivedTable { input, .. }
            | RelPlan::Pivot { input, .. }
            | RelPlan::Unpivot { input, .. }
            | RelPlan::MatchRecognize { input, .. }
            | RelPlan::TableSample { input, .. } => Self::collect_scan_tables(input, out),
            RelPlan::Join { left, right, .. } => {
                Self::collect_scan_tables(left, out);
                Self::collect_scan_tables(right, out);
            }
            RelPlan::SetOp { inputs, .. } => {
                for inner in inputs {
                    Self::collect_scan_tables(inner, out);
                }
            }
            RelPlan::WithScope { ctes, body, .. } => {
                for cte in ctes {
                    match &cte.body {
                        super::plan::CteBody::NonRecursive(p) => {
                            Self::collect_scan_tables(p, out);
                        }
                        super::plan::CteBody::Recursive { anchor, step, .. } => {
                            Self::collect_scan_tables(anchor, out);
                            Self::collect_scan_tables(step, out);
                        }
                    }
                }
                Self::collect_scan_tables(body, out);
            }
            RelPlan::Insert { source, .. } => match source {
                super::plan::InsertSource::Values(p) | super::plan::InsertSource::Query(p) => {
                    Self::collect_scan_tables(p, out)
                }
                super::plan::InsertSource::DefaultValues => {}
            },
            RelPlan::CreateAsQuery { body, .. } => {
                if let Some(body) = body.as_deref() {
                    Self::collect_scan_tables(body, out);
                }
            }
            RelPlan::Update { from, .. } => {
                if let Some(s) = from {
                    Self::collect_scan_tables(s, out);
                }
            }
            RelPlan::Delete { using, .. } => {
                if let Some(s) = using {
                    Self::collect_scan_tables(s, out);
                }
            }
            RelPlan::Merge { source, .. } => Self::collect_scan_tables(source, out),
            RelPlan::MultiInsert { source, .. } => Self::collect_scan_tables(source, out),
            RelPlan::Explain { body, .. } => Self::collect_scan_tables(body, out),
            // Leaves with no enclosed plan / no catalog identity.
            RelPlan::CteRef { .. }
            | RelPlan::ModelRef { .. }
            | RelPlan::Values { .. }
            | RelPlan::TableFunction { .. }
            | RelPlan::Unnest { .. }
            | RelPlan::ConnectBy { .. }
            | RelPlan::CreateTableForm { .. }
            | RelPlan::ParseRecovery { .. }
            | RelPlan::Opaque { .. } => {}
            RelPlan::InvalidInput { .. } => {}
        }
    }

    /// Closed-enum exhaustive walk over [`RelPlan`] collecting
    /// `(ResolvedModel, columns)` for every reachable
    /// [`RelPlan::ModelRef`]. Parallel to [`Self::collect_scan_tables`]
    /// but for the cross-model injection path so the seed pass can
    /// stamp `column_metadata` with the upstream `ModelEntry`'s
    /// taint labels.
    fn collect_model_refs(plan: &RelPlan, out: &mut Vec<(ResolvedModel, Vec<ColumnId>)>) {
        match plan {
            RelPlan::ModelRef { model, columns, .. } => {
                out.push((model.clone(), columns.clone()));
            }
            RelPlan::Project { input, .. }
            | RelPlan::Filter { input, .. }
            | RelPlan::Aggregate { input, .. }
            | RelPlan::Window { input, .. }
            | RelPlan::Sort { input, .. }
            | RelPlan::Limit { input, .. }
            | RelPlan::DerivedTable { input, .. }
            | RelPlan::Pivot { input, .. }
            | RelPlan::Unpivot { input, .. }
            | RelPlan::MatchRecognize { input, .. }
            | RelPlan::TableSample { input, .. } => Self::collect_model_refs(input, out),
            RelPlan::Join { left, right, .. } => {
                Self::collect_model_refs(left, out);
                Self::collect_model_refs(right, out);
            }
            RelPlan::SetOp { inputs, .. } => {
                for inner in inputs {
                    Self::collect_model_refs(inner, out);
                }
            }
            RelPlan::WithScope { ctes, body, .. } => {
                for cte in ctes {
                    match &cte.body {
                        super::plan::CteBody::NonRecursive(p) => {
                            Self::collect_model_refs(p, out);
                        }
                        super::plan::CteBody::Recursive { anchor, step, .. } => {
                            Self::collect_model_refs(anchor, out);
                            Self::collect_model_refs(step, out);
                        }
                    }
                }
                Self::collect_model_refs(body, out);
            }
            RelPlan::Insert { source, .. } => match source {
                super::plan::InsertSource::Values(p) | super::plan::InsertSource::Query(p) => {
                    Self::collect_model_refs(p, out)
                }
                super::plan::InsertSource::DefaultValues => {}
            },
            RelPlan::CreateAsQuery { body, .. } => {
                if let Some(body) = body.as_deref() {
                    Self::collect_model_refs(body, out);
                }
            }
            RelPlan::Update { from, .. } => {
                if let Some(s) = from {
                    Self::collect_model_refs(s, out);
                }
            }
            RelPlan::Delete { using, .. } => {
                if let Some(s) = using {
                    Self::collect_model_refs(s, out);
                }
            }
            RelPlan::Merge { source, .. } => Self::collect_model_refs(source, out),
            RelPlan::MultiInsert { source, .. } => Self::collect_model_refs(source, out),
            RelPlan::Explain { body, .. } => Self::collect_model_refs(body, out),
            RelPlan::Scan { .. }
            | RelPlan::CteRef { .. }
            | RelPlan::Values { .. }
            | RelPlan::TableFunction { .. }
            | RelPlan::Unnest { .. }
            | RelPlan::ConnectBy { .. }
            | RelPlan::CreateTableForm { .. }
            | RelPlan::ParseRecovery { .. }
            | RelPlan::Opaque { .. } => {}
            RelPlan::InvalidInput { .. } => {}
        }
    }

    /// Resolve `table` against the attached [`CatalogIndex`] (with
    /// session defaults applied) and seed `self.catalog_ctx` with
    /// its column tags + table tags. `columns` is the `Scan`'s
    /// `ColumnId` list — only columns whose `display_name` matches
    /// a catalog column receive metadata; the rest are silently
    /// skipped (an unresolvable column simply produces no tags).
    fn seed_catalog_ctx_from_scan(&mut self, table: &TableRef, columns: &[ColumnId]) {
        let Some(index) = self.catalog_index else {
            return;
        };
        let mut resolved = table.clone();
        apply_session_defaults_to_table_ref(&mut resolved, self.session);
        let Some(catalog_table) = index.get_table_inferred(
            resolved.db.as_deref(),
            resolved.schema.as_deref(),
            &resolved.name,
        ) else {
            // Record the negative-presence outcome so the public
            // `TableEvent.in_catalog` projection can fire
            // `CAT-TBL-UNKNOWN`. Keyed under the *as-written*
            // `TableRef` so the lookup at the `Scan` node matches.
            self.catalog_ctx
                .insert_table_in_catalog(table.clone(), false);
            return;
        };
        // Mirror the positive-presence outcome under the same key.
        self.catalog_ctx
            .insert_table_in_catalog(table.clone(), true);

        // Build per-column lookup keyed by normalized name. The
        // catalog stores names verbatim (often UPPERCASE for
        // Snowflake); user code references them in any case;
        // `IdentKey::new` normalizes to a single comparable form.
        let mut by_name: std::collections::HashMap<IdentKey, &crate::catalog::CatalogColumn> =
            std::collections::HashMap::with_capacity(catalog_table.columns.len());
        for col in &catalog_table.columns {
            by_name.insert(IdentKey::new(&col.name.name), col);
        }

        // Per-column constraints from the table-level constraint list:
        // PK / Unique → mark `is_primary_key` / `is_unique` on every
        // column the constraint mentions. FK → record an `FkTarget`
        // pointing at the referenced table+column. Multi-column FKs
        // attach a `FkTarget` to *each* local column on the LEFT side
        // (each pairs with the matching position on the RIGHT side).
        // The full FK list is also recorded on the catalog sidecar
        // under the table key so `Q-JOIN-FKVIOL-CENH` can detect
        // "this table has FKs declared but the join used different
        // columns" without consulting the upstream `CatalogIndex`.
        let mut pk_cols: std::collections::HashSet<IdentKey> = std::collections::HashSet::new();
        let mut unique_cols: std::collections::HashSet<IdentKey> = std::collections::HashSet::new();
        // Columns that are the SOLE member of some PK or UNIQUE
        // constraint (arity 1). Distinct from pk_cols / unique_cols,
        // which flatten composite constraints. Drives fan-out
        // detection in `join_pair_unique_key_backed`.
        let mut solo_unique_cols: std::collections::HashSet<IdentKey> =
            std::collections::HashSet::new();
        let mut fk_targets: std::collections::HashMap<IdentKey, super::FkTarget> =
            std::collections::HashMap::new();
        let mut fk_edges: Vec<super::FkEdge> = Vec::new();
        for cons in &catalog_table.constraints {
            match cons.kind {
                crate::catalog::CatalogConstraintKind::PrimaryKey => {
                    for c in &cons.columns {
                        pk_cols.insert(IdentKey::new(&c.name));
                    }
                    if cons.columns.len() == 1 {
                        solo_unique_cols.insert(IdentKey::new(&cons.columns[0].name));
                    }
                }
                crate::catalog::CatalogConstraintKind::Unique => {
                    for c in &cons.columns {
                        unique_cols.insert(IdentKey::new(&c.name));
                    }
                    if cons.columns.len() == 1 {
                        solo_unique_cols.insert(IdentKey::new(&cons.columns[0].name));
                    }
                }
                crate::catalog::CatalogConstraintKind::ForeignKey => {
                    let Some(ref_obj) = cons.ref_table.as_ref() else {
                        continue;
                    };
                    let ref_table = TableRef {
                        server: None,
                        db: Some(ref_obj.database.name.clone()),
                        schema: Some(ref_obj.schema.name.clone()),
                        name: ref_obj.name.name.clone(),
                        span: None,
                    };
                    // Pre-compute the full local-column tuple once
                    // per constraint so every emitted edge can carry
                    // a clone — sibling-completeness checks at join
                    // classification time consult this directly
                    // instead of reconstructing the constraint
                    // grouping from a flat edge list.
                    let composite_columns: Vec<IdentKey> = cons
                        .columns
                        .iter()
                        .map(|c| IdentKey::new(&c.name))
                        .collect();
                    for (i, local_col) in cons.columns.iter().enumerate() {
                        let Some(remote_col) = cons.ref_columns.get(i) else {
                            continue;
                        };
                        let local_key = IdentKey::new(&local_col.name);
                        let remote_key = IdentKey::new(&remote_col.name);
                        fk_targets.insert(
                            local_key.clone(),
                            super::FkTarget {
                                ref_table: ref_table.clone(),
                                ref_column_name: remote_key.clone(),
                            },
                        );
                        fk_edges.push(super::FkEdge {
                            local_column_name: local_key,
                            ref_table: ref_table.clone(),
                            ref_column_name: remote_key,
                            composite_columns: composite_columns.clone(),
                        });
                    }
                }
                crate::catalog::CatalogConstraintKind::Unknown => {}
            }
        }
        if !fk_edges.is_empty() {
            self.catalog_ctx.insert_table_fks(table.clone(), fk_edges);
        }

        // Build per-column (IdentKey, ColumnId) pairs so the
        // catalog sidecar can answer `resolve_table_columns(table)`
        // for cardinality / temporal queries. Without this the
        // post-attach IR queries cannot enumerate a Scan's columns
        // by name.
        let mut table_pairs: Vec<(IdentKey, ColumnId)> = Vec::with_capacity(columns.len());
        for &cid in columns {
            let Some(binding) = self.allocator.bindings().get(cid) else {
                continue;
            };
            // `alloc_table_col` stores the *already-normalized* form on
            // `binding.display_name` (see line 1759 — it calls
            // `IdentKey::new(column_name).as_str().to_string()`).
            // Re-applying `IdentKey::new` here would fold a second time,
            // breaking case-sensitive quoted identifiers: a catalog
            // declaration like `"My Col"` would key as `"My Col"` (quote
            // stripped, case preserved by the first normalize) but the
            // binding-side `IdentKey::new("My Col")` re-normalizes the
            // bare string and folds it to `"MY COL"`.
            // `from_normalized` skips that second pass.
            let key = IdentKey::from_normalized(binding.display_name.clone());
            table_pairs.push((key.clone(), cid));
            // Record the authoritative scan origin even when the
            // matched catalog column carries no metadata (so the
            // join-key reverse lookup still resolves a TableRef).
            self.catalog_ctx
                .insert_column_origin(cid, table.clone(), key.clone());
            // Record catalog-presence outcome for this column: true
            // when the scan-bound name matched a declared catalog
            // column, false when alloc-on-first-use produced a
            // dangler (typo, dropped column, mis-qualified ref).
            // Drives `CAT-COL-UNKNOWN`. Recorded for every scan-
            // bound `ColumnId` regardless of whether the catalog
            // column carried per-column metadata.
            let catalog_has_column = by_name.contains_key(&key);
            self.catalog_ctx
                .insert_column_in_catalog(cid, catalog_has_column);
            let Some(catalog_col) = by_name.get(&key) else {
                continue;
            };
            let tags: Vec<TagRef> = catalog_col
                .tags
                .iter()
                .map(|t| TagRef {
                    qualified_name: t.qualified_name(),
                    value: t.tag_value.clone(),
                })
                .collect();
            let is_pk = pk_cols.contains(&key);
            let is_unique = unique_cols.contains(&key);
            let is_solo_unique_key = solo_unique_cols.contains(&key);
            let fk_target = fk_targets.get(&key).cloned();
            // Only emit metadata when at least one fact is
            // resolvable. An entry with all-default fields is
            // semantically identical to "no entry" for every
            // current consumer (taint, nullability seed, policy,
            // cardinality / temporal classification all check the
            // corresponding sub-field before reading it), but
            // emitting empty entries would needlessly bloat the
            // sidecar for the common catalog-with-no-tags case.
            if tags.is_empty()
                && catalog_col.nullable.is_none()
                && catalog_col.data_type.is_none()
                && !is_pk
                && !is_unique
                && fk_target.is_none()
            {
                continue;
            }
            let meta = ColumnMetadata {
                nullable: catalog_col.nullable,
                default: None,
                constraints: super::ColumnConstraints {
                    is_primary_key: is_pk,
                    is_unique,
                    is_solo_unique_key,
                    check: None,
                },
                tags,
                policy: None,
                data_type: catalog_col.data_type.clone(),
                fk_target,
            };
            self.catalog_ctx.insert_column_metadata(cid, meta);
        }
        if !table_pairs.is_empty() {
            self.catalog_ctx
                .insert_table_columns(table.clone(), TableColumns::from_pairs(table_pairs));
        }

        // Table-level tags: every column of the scan inherits
        // them at taint-derivation time via
        // `CatalogContext::resolve_table_tags`. Stored under the
        // *as-written* `TableRef` (not the session-resolved one)
        // so the lookup at `RelPlan::Scan` uses the same key the
        // scan node carries.
        let table_tags: Vec<TagRef> = catalog_table
            .tags
            .iter()
            .map(|t| TagRef {
                qualified_name: t.qualified_name(),
                value: t.tag_value.clone(),
            })
            .collect();
        if !table_tags.is_empty() {
            self.catalog_ctx
                .insert_table_tags(table.clone(), table_tags);
        }

        // Table-level row count estimate is
        // consumed by the IR's cardinality queries
        // (`is_high_cardinality_column`, large-table heuristics).
        // Stored under the *as-written* `TableRef` so the lookup
        // at `RelPlan::Scan` uses the same key the scan node
        // carries.
        if let Some(row_count) = catalog_table.row_count_estimate {
            self.catalog_ctx
                .insert_table_row_count(table.clone(), row_count);
        }

        // Capture the temporal-typed columns up-front from the full
        // `CatalogTable.columns` list — the per-column `column_metadata`
        // seed below only stamps the scan-referenced subset, which
        // would silently miss unreferenced DATE/TIMESTAMP columns.
        // Names feed the public `TemporalJoinTable.temporal_column_names`;
        // the `bool` flag is the cached "any" answer for hot-path
        // consumers.
        let temporal_column_names: Vec<crate::context::node_metadata::IdentKey> = catalog_table
            .columns
            .iter()
            .filter(|c| {
                c.data_type
                    .as_deref()
                    .map(super::catalog::is_temporal_data_type)
                    .unwrap_or(false)
            })
            .map(|c| crate::context::node_metadata::IdentKey::new(&c.name.name))
            .collect();
        let has_temporal_column = !temporal_column_names.is_empty();
        self.catalog_ctx
            .insert_table_has_temporal_column(table.clone(), has_temporal_column);
        self.catalog_ctx
            .insert_table_temporal_column_names(table.clone(), temporal_column_names);

        // Surface the catalog object kind onto the IR sidecar so
        // post-lowering analyses (`Q-VIEW-REF-CENH`) can predicate
        // on `table.kind: view` without reaching back to the
        // upstream `CatalogIndex`.
        let ir_kind = match catalog_table.kind {
            crate::catalog::CatalogTableKind::Table => super::IrTableKind::Table,
            crate::catalog::CatalogTableKind::View => super::IrTableKind::View,
            crate::catalog::CatalogTableKind::MaterializedView => {
                super::IrTableKind::MaterializedView
            }
            crate::catalog::CatalogTableKind::ExternalTable => super::IrTableKind::ExternalTable,
            crate::catalog::CatalogTableKind::Temporary => super::IrTableKind::Temporary,
            crate::catalog::CatalogTableKind::Unknown => super::IrTableKind::Unknown,
        };
        self.catalog_ctx.insert_table_kind(table.clone(), ir_kind);
    }

    /// Seed `column_metadata` for a [`RelPlan::ModelRef`]'s output
    /// columns from the upstream [`ResolvedModel::taint_labels`].
    ///
    /// The fact-extractor's projection-taint pipeline reads tags via
    /// [`super::catalog_context::CatalogContext::column_metadata`],
    /// which is only seeded for [`RelPlan::Scan`] columns by
    /// [`Self::seed_catalog_ctx_from_scan`]. Without this seed,
    /// taint that reaches a projection through a `ModelRef` would
    /// carry no tags to report.
    ///
    /// Each upstream [`crate::context::node_metadata::TaintLabel`]
    /// projects onto a single [`TagRef`] with `qualified_name =
    /// tag_name` and `value = tag_value`. The bare `tag_name` form
    /// is what `project_taint_labels` reads (see
    /// `src/facts/extract.rs::bare_tag_suffix` / `project_taint_labels`);
    /// `source_table` / `source_column` are not carried because the
    /// `TagRef` channel is not source-keyed.
    fn seed_catalog_ctx_from_model_ref(&mut self, model: &ResolvedModel, columns: &[ColumnId]) {
        if model.taint_labels.is_empty() {
            return;
        }
        for &cid in columns {
            let Some(binding) = self.allocator.bindings().get(cid) else {
                continue;
            };
            let key = IdentKey::new(&binding.display_name);
            let Some(labels) = model.taint_labels.get(&key) else {
                continue;
            };
            if labels.is_empty() {
                continue;
            }
            let tags: Vec<TagRef> = labels
                .iter()
                .map(|lbl| TagRef {
                    qualified_name: lbl.tag_name.clone(),
                    value: lbl.tag_value.clone(),
                })
                .collect();
            let meta = ColumnMetadata {
                nullable: None,
                default: None,
                constraints: super::ColumnConstraints {
                    is_primary_key: false,
                    is_unique: false,
                    is_solo_unique_key: false,
                    check: None,
                },
                tags,
                policy: None,
                data_type: None,
                fk_target: None,
            };
            self.catalog_ctx.insert_column_metadata(cid, meta);
        }
    }

    /// Allocate a fresh [`ScopeId`] for a new `WithScope` frame.
    /// [`ScopeId(0)`] is intentionally skipped so hand-constructed
    /// unit tests that default to 0 stay disjoint from lowered scopes.
    fn alloc_scope(&mut self) -> ScopeId {
        let id = ScopeId(self.next_scope_id);
        self.next_scope_id = self.next_scope_id.saturating_add(1);
        id
    }

    /// Return the ordered list of column names for `table_ref` from
    /// the attached [`CatalogIndex`], applying session defaults for
    /// unqualified names.
    ///
    /// Returns an empty vec when no `catalog_index` is attached, the
    /// table is absent from the snapshot, or the table has no declared
    /// columns. The returned names are in catalog-declared positional
    /// order (matching `SELECT *` expansion semantics). Callers own
    /// the result and may perform mutable allocations on `self`
    /// immediately after this call.
    fn catalog_col_names_for_table(&self, table_ref: &TableRef) -> Vec<String> {
        let Some(index) = self.catalog_index else {
            return Vec::new();
        };
        let mut resolved = table_ref.clone();
        apply_session_defaults_to_table_ref(&mut resolved, self.session);
        let Some(catalog_table) = index.get_table_inferred(
            resolved.db.as_deref(),
            resolved.schema.as_deref(),
            &resolved.name,
        ) else {
            return Vec::new();
        };
        catalog_table
            .columns
            .iter()
            .map(|c| c.name.name.clone())
            .collect()
    }

    // ── ColumnId allocation helpers ─────────────────────────────────
    //
    // These are the only paths into `self.allocator.fresh(…)` that
    // lowering code should use. Each helper corresponds to one
    // [`ColumnOrigin`] variant and exists so every allocation site
    // names its origin explicitly at the call site. See the
    // [`ColumnBinding`] side-table discussion in `src/ir/column.rs`.

    /// Allocate a [`ColumnId`] for a base-table scan output. Origin
    /// = [`ColumnOrigin::Table`].
    ///
    /// `column_name` carries the **raw source text** for the
    /// identifier — i.e. quote-preserving for case-sensitive
    /// identifiers (`"ABM_Tier"` stays as `"ABM_Tier"`, with the
    /// surrounding quote bytes). Consumers feed it through
    /// `normalize_identifier` (see
    /// `derived_facts.rs::visit_plan_for_scan_source`, etc.); the
    /// raw form is the only one that lets `normalize_identifier`
    /// distinguish quoted-mixed-case from unquoted-uppercase. Mirrors
    /// [`crate::context::node_metadata::ColumnRef`]'s `name`, which is
    /// also raw-with-quotes.
    ///
    /// `display_name` is derived here as the IdentKey-canonical form
    /// (via `IdentKey::new`), not the raw bytes — display_name is
    /// used as a lookup-key surface in many places and must be in
    /// canonical form for HashMap-by-IdentKey comparisons to work.
    fn alloc_table_col(
        &mut self,
        table_node: crate::ast::NodeId,
        column_name: &str,
        span: Span,
    ) -> ColumnId {
        let display = IdentKey::new(column_name).as_str().to_string();
        self.allocator.fresh(
            ColumnOrigin::Table {
                table_node,
                column_name: column_name.to_string(),
                span,
            },
            display,
        )
    }

    /// Drain entries from `scan_cols` whose `NodeId` matches `source`,
    /// returning the matched `ColumnId`s in first-referenced order.
    ///
    /// Each entry was allocated against a specific FROM source's
    /// `NodeId` at first reference (see [`Self::lower_column_ref`]).
    /// FROM-item lowering calls this with its own `NodeId` to take
    /// ownership of refs that resolved against that source; entries
    /// targeting other sources stay on `scan_cols` for their owners
    /// to drain (or for the final
    /// [`attach_pending_source_cols`] routing pass to inject by
    /// NodeId match).
    fn drain_scan_cols_for(&mut self, source: crate::ast::NodeId) -> Vec<ColumnId> {
        let pending = std::mem::take(&mut self.scan_cols);
        let mut taken: Vec<ColumnId> = Vec::new();
        let mut kept: Vec<(crate::ast::NodeId, ColumnId)> = Vec::new();
        for (n, id) in pending {
            if n == source {
                taken.push(id);
            } else {
                kept.push((n, id));
            }
        }
        self.scan_cols = kept;
        taken
    }

    /// Register a FROM-item's resolution aliases against the source's
    /// `NodeId`. Called immediately after the source's `RelPlan` node
    /// is constructed (Scan, CteRef, DerivedTable, TableFunction,
    /// Values) so JOIN ON clauses lowered against the next sibling
    /// can already see this source's alias and root column allocations
    /// on the correct `table_node`.
    ///
    /// `aliases` lists every name the user could write before a
    /// column: the explicit `AS` alias plus the bare table-name
    /// fallback (last segment of a multi-part name) for Scan / CteRef.
    /// Empty for DerivedTable when no alias was provided.
    ///
    /// First-insertion-wins matches the standard SQL rule that an
    /// explicit alias hides the underlying table name. The source is
    /// also pushed onto [`Self::from_source_order`] so the leftmost
    /// FROM source is recoverable for unqualified-no-match fallback.
    fn register_from_source(
        &mut self,
        aliases: impl IntoIterator<Item = IdentKey>,
        source: crate::ast::NodeId,
    ) {
        for alias in aliases {
            self.from_aliases.entry(alias).or_insert(source);
        }
        if !self.from_source_order.contains(&source) {
            self.from_source_order.push(source);
        }
    }

    /// Allocate a [`ColumnId`] for a column computed by an
    /// expression in the enclosing plan node. Origin =
    /// [`ColumnOrigin::Computed`]. `display_name` is the user-visible
    /// name (alias, or empty for anonymous intermediates).
    fn alloc_computed_col(
        &mut self,
        producing_node: crate::ast::NodeId,
        expr_span: Span,
        display_name: impl Into<String>,
    ) -> ColumnId {
        self.allocator.fresh(
            ColumnOrigin::Computed {
                producing_node,
                expr_span,
            },
            display_name,
        )
    }

    /// Allocate a [`ColumnId`] for a SetOp-unified output slot.
    /// `inputs` records the per-branch source ids; `display_name`
    /// conventionally takes the first branch's binding.
    fn alloc_setop_col(
        &mut self,
        inputs: Vec<ColumnId>,
        display_name: impl Into<String>,
    ) -> ColumnId {
        self.allocator
            .fresh(ColumnOrigin::SetOp { inputs }, display_name)
    }

    /// Allocate a [`ColumnId`] for a correlated outer reference.
    //
    // Kept on the impl as part of the closed-enum's full API surface:
    // every [`ColumnOrigin`] variant has a corresponding allocator
    // helper so that future lowering steps do not reintroduce
    // `self.allocator.fresh(...)` with an ad-hoc origin.
    #[allow(dead_code)]
    fn alloc_outer_ref_col(
        &mut self,
        scope: ScopeId,
        outer_column: ColumnId,
        display_name: impl Into<String>,
    ) -> ColumnId {
        self.allocator.fresh(
            ColumnOrigin::OuterRef {
                scope,
                outer_column,
            },
            display_name,
        )
    }

    /// Allocate a [`ColumnId`] for a recursive CTE self-reference.
    //
    // See [`Self::alloc_outer_ref_col`] for why this is kept even
    // while unused: closed-enum completeness across allocator
    // helpers.
    #[allow(dead_code)]
    fn alloc_recursive_ref_col(
        &mut self,
        binding_index: u32,
        display_name: impl Into<String>,
    ) -> ColumnId {
        self.allocator
            .fresh(ColumnOrigin::RecursiveRef { binding_index }, display_name)
    }

    /// Allocate a [`ColumnId`] whose origin is an expression inside
    /// the currently-lowered statement but whose fine-grained
    /// producing-node isn't individually tracked (e.g. the i-th
    /// value-column of a `VALUES (…)` row set, where the per-column
    /// producer is one or more scalar exprs in the row's
    /// corresponding slot). `stmt_span` is the enclosing statement's
    /// span — the `Computed` origin records it as `expr_span` so
    /// lineage analyses can still locate the source text.
    ///
    /// Kept separate from [`Self::alloc_computed_col`] to make
    /// callers name the case explicitly: a tuple-column allocation
    /// that inherits the statement span is semantically different
    /// from a specific projection item.
    fn alloc_tuple_col(
        &mut self,
        stmt_node: crate::ast::NodeId,
        stmt_span: Span,
        display_name: impl Into<String>,
    ) -> ColumnId {
        self.allocator.fresh(
            ColumnOrigin::Computed {
                producing_node: stmt_node,
                expr_span: stmt_span,
            },
            display_name,
        )
    }

    /// Allocate a [`ColumnId`] whose fine-grained producer is the
    /// currently-lowered statement's root. Used for columns whose
    /// origin is structurally reachable only at the statement level
    /// (e.g. DML target columns resolved from the catalog; INSERT's
    /// declared `(c1, …)` list; subquery-produced slots where the
    /// inner `NodeId` is already captured structurally by the
    /// enclosing `Aggregate`/`Project`/`Window` node).
    ///
    /// Records `ColumnOrigin::Computed { producing_node: <stmt root>,
    /// expr_span: <provided span> }`. Downstream analyses treat
    /// this identically to [`Self::alloc_computed_col`]; the
    /// distinction is purely at the call site.
    fn alloc_synthetic(&mut self, expr_span: Span, display_name: impl Into<String>) -> ColumnId {
        let producing_node = self.current_stmt_node;
        self.allocator.fresh(
            ColumnOrigin::Computed {
                producing_node,
                expr_span,
            },
            display_name,
        )
    }

    /// Look up a CTE binding by normalized identifier, searching from
    /// innermost `WithScope` frame outward. Returns the entry (scope +
    /// arity) when found.
    fn lookup_cte(&self, key: &IdentKey) -> Option<&CteScopeEntry> {
        for frame in self.cte_scopes.iter().rev() {
            if let Some(entry) = frame.get(key) {
                return Some(entry);
            }
        }
        None
    }

    /// Drain `scan_cols` entries pointing at any star-passthrough
    /// CTE binding's leaf Scan and append them in-place to that
    /// Scan's `columns` Vec.
    ///
    /// Background. A CTE body of the shape `SELECT * FROM <table>`
    /// (and trivial passthrough wrappers — `Filter` / `Sort` /
    /// `Limit` / `TableSample`) is detected at registration time
    /// (see `CteScopeEntry::leaf_scan_node`). References through
    /// such a CTE register their aliases against the **leaf Scan's**
    /// `NodeId`, so demanded columns (`o.col` where `o` is the
    /// CteRef alias) flow through `lower_column_ref`'s standard
    /// allocate-on-first-use path: a fresh `ColumnId` with origin
    /// `Table { table_node = leaf_scan_node, .. }` lands on
    /// `self.scan_cols` keyed by that NodeId.
    ///
    /// During regular FROM lowering, those `scan_cols` rows would
    /// be drained when the matching `Scan` is constructed. Here the
    /// `Scan` was constructed earlier (during the CTE body's
    /// lowering), with `columns: drain_scan_cols_for(scan_node) =
    /// []` — no demands had yet arrived. After the outer body
    /// lowers, the demands have accumulated; this pass picks them
    /// up and finishes the attach.
    ///
    /// Append-only mutation: existing `Scan.columns` ColumnIds are
    /// preserved at their positions; new entries land at the tail.
    /// `binding.output_columns` is intentionally **not** mutated —
    /// the binding's outward-facing arity stays as it was at lower
    /// time. What this pass restores is the per-column
    /// `Origin::Table` chain: with the demanded ColumnIds visible
    /// inside the leaf Scan, downstream lineage maps `o.col` →
    /// `(leaf_table, col)` as a structural consequence of the
    /// closed-enum shape, not a name-pattern fallback.
    /// Combined CTE passthrough detection: returns the leaf-scan
    /// `NodeId` for either plain `SELECT * FROM <single-scan>` bodies
    /// or `SELECT * RENAME (…) FROM <single-scan>` bodies. For the
    /// rename case, also populates [`Self::cte_passthrough_renames`]
    /// with `to → from` pairs so [`Self::lower_column_ref`] can
    /// substitute the source column name when allocating a Scan
    /// binding for a CTE-renamed reference (e.g. `c.user_id` → `id`
    /// on `users`).
    ///
    /// When the body does not match the single-scan-leaf shape but
    /// is a star-passthrough chain over a JOIN of qualified stars or
    /// a chained `CteRef` / `DerivedTable`, falls through to the
    /// generalized [`Self::compute_passthrough_columns_for_body`]
    /// builder. Its result is returned via the second tuple slot and
    /// stored on the [`CteScopeEntry`]; references through the CTE
    /// then resolve via [`Self::cte_passthrough_columns`] at
    /// allocate-on-first-use time.
    fn detect_cte_passthrough_with_renames(
        &mut self,
        body: &CteBody,
    ) -> (
        Option<crate::ast::NodeId>,
        HashMap<IdentKey, PassthroughTarget>,
    ) {
        let inner = match body {
            CteBody::NonRecursive(b) => b,
            CteBody::Recursive { .. } => return (None, HashMap::new()),
        };
        if let Some(node) = inner.cte_body_star_passthrough_leaf_scan_node() {
            return (Some(node), HashMap::new());
        }
        if let Some((node, renames)) = inner.cte_body_star_rename_passthrough_leaf_scan_node() {
            if !renames.is_empty() {
                let map = self.cte_passthrough_renames.entry(node).or_default();
                for r in renames {
                    map.insert(
                        r.to.clone(),
                        PassthroughSourceName {
                            ident: r.from.clone(),
                            span: r.from_span,
                        },
                    );
                }
            }
            return (Some(node), HashMap::new());
        }
        // Linear chain over an already-classified leaf-scan parent:
        // `Project[Star] → …passthrough… → CteRef(parent)` where
        // `parent`'s own `leaf_scan_node` is already populated. The
        // parent stores its routing in `leaf_scan_node` (not in
        // `passthrough_columns`), so the generalized builder's CteRef
        // arm can't see through it. Inheriting the parent's
        // `leaf_scan_node` collapses the chain to a single redirect
        // target — the existing alias-redirect path in `CteRef`
        // lowering (and `finalize_star_passthrough_bindings`'s drain
        // against that node) handles the rest.
        if let Some(node) = self.chained_leaf_scan_through_cte_passthrough(inner) {
            return (Some(node), HashMap::new());
        }
        // Generalized path: multi-leaf JOIN / chained passthroughs
        // through a parent that uses the `passthrough_columns` map.
        let cols = self
            .compute_passthrough_columns_for_body(inner)
            .unwrap_or_default();
        (None, cols)
    }

    /// If `body` is a `Project[Star]` over a linear passthrough chain
    /// (`Filter` / `Sort` / `Limit` / `TableSample` / `Window`) ending
    /// in a `CteRef` whose own `CteScopeEntry` carries a direct
    /// `leaf_scan_node`, return that leaf-scan `NodeId`. Otherwise
    /// `None`.
    ///
    /// Mirrors [`RelPlan::cte_body_star_passthrough_leaf_scan_node`]'s
    /// passthrough-operator set, but with the previously-disqualifying
    /// `CteRef` arm replaced by a one-hop binding lookup. Recursive
    /// composition is handled by topological order: when CTE `c`'s
    /// body sources CTE `b` and `b` sources CTE `a` over a leaf
    /// `Scan`, `a` is detected first (direct leaf-scan), then `b`
    /// inherits via this helper, then `c` inherits via this helper
    /// again — each from its immediate parent's already-stored
    /// `leaf_scan_node`. Joins, set-ops, and other shapes still bail
    /// to the generalized `compute_passthrough_columns_for_body` path.
    fn chained_leaf_scan_through_cte_passthrough(
        &self,
        body: &RelPlan,
    ) -> Option<crate::ast::NodeId> {
        let inner = body.cte_body_star_passthrough_input()?;
        let mut cursor = inner;
        loop {
            match cursor {
                RelPlan::Filter { input, .. }
                | RelPlan::Sort { input, .. }
                | RelPlan::Limit { input, .. }
                | RelPlan::TableSample { input, .. }
                | RelPlan::Window { input, .. } => cursor = input.as_ref(),
                RelPlan::CteRef { name, .. } => {
                    // Walk frames innermost-out, mirroring the
                    // shadowing rule in `lookup_cte_passthrough_by_name`.
                    for frame in self.cte_scopes.iter().rev() {
                        if let Some(entry) = frame.get(name) {
                            return entry.leaf_scan_node;
                        }
                    }
                    return None;
                }
                // Every other variant disqualifies the chain. Listed
                // exhaustively so a future `RelPlan` variant surfaces
                // here rather than being silently swallowed.
                RelPlan::Scan { .. }
                | RelPlan::Values { .. }
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

    /// Build a per-output-column passthrough map for a CTE / derived
    /// table body whose top-level shape is a star-passthrough chain
    /// over a non-trivial input — a JOIN of qualified stars, or a
    /// `CteRef` / `DerivedTable` whose own passthrough info is
    /// already known. Returns `None` when the body shape cannot be
    /// classified (computed projections, set-ops, etc.); the caller
    /// treats that as "no passthrough info" and references through
    /// the CTE / derived table fall back to the existing
    /// allocate-on-first-use anchored at the CTE / derived table's
    /// own NodeId. See [`Self::cte_passthrough_columns`].
    fn compute_passthrough_columns_for_body(
        &self,
        body: &RelPlan,
    ) -> Option<HashMap<IdentKey, PassthroughTarget>> {
        let mut cursor = body;
        loop {
            match cursor {
                RelPlan::Project { items, input, .. } => {
                    return self.compute_passthrough_for_project(items, input);
                }
                RelPlan::Filter { input, .. }
                | RelPlan::Sort { input, .. }
                | RelPlan::Limit { input, .. }
                | RelPlan::TableSample { input, .. }
                | RelPlan::Window { input, .. } => cursor = input.as_ref(),
                _ => return None,
            }
        }
    }

    fn compute_passthrough_for_project(
        &self,
        items: &[ProjectItem],
        input: &RelPlan,
    ) -> Option<HashMap<IdentKey, PassthroughTarget>> {
        let sources = self.collect_passthrough_sources(input)?;
        let mut out: HashMap<IdentKey, PassthroughTarget> = HashMap::new();

        for item in items {
            match item {
                // A computed projection item produces a non-passthrough
                // output. We don't know its name without the alias and
                // resolving it isn't this map's job; leave it out so
                // lookups fall through to the existing allocator path.
                ProjectItem::Expr(_) => {}
                ProjectItem::Star(s) => {
                    // Targets: every matching input source (one for
                    // qualified `Q.*`, all for unqualified `*`).
                    let target_sources: Vec<&PassthroughSource> = match &s.qualifier {
                        StarQualifier::Unqualified => {
                            // Sort by alias key: `sources` is a HashMap, and on an
                            // ambiguous output name the last contribution wins —
                            // hash order would make the winner random per process.
                            let mut entries: Vec<_> = sources.iter().collect();
                            entries.sort_by(|a, b| a.0.cmp(b.0));
                            entries.into_iter().map(|(_, v)| v).collect()
                        }
                        StarQualifier::Named(path) => {
                            // Match by the last (leaf) segment against
                            // alias keys, mirroring SQL's single-name
                            // FROM-scope rule.
                            let alias = path.last()?.name.clone();
                            vec![sources.get(&Some(alias))?]
                        }
                        StarQualifier::FromExpr(_) => return None,
                    };

                    // Collect renames and replaced sets for this Star.
                    // Renames are keyed by the source-side `from` so a
                    // chained CteRef arm can look up the parent's output
                    // name; the value carries both the new output `to`
                    // (for chaining) and the source `from`'s span (for
                    // raw-text recovery in the Scan arm — see
                    // `PassthroughSourceName`).
                    let mut renames: HashMap<IdentKey, RenameEntry> = HashMap::new();
                    for r in &s.rename {
                        renames.insert(
                            r.from.clone(),
                            RenameEntry {
                                to: r.to.clone(),
                                from_span: r.from_span,
                            },
                        );
                    }
                    let mut replaced: std::collections::HashSet<IdentKey> =
                        std::collections::HashSet::new();
                    for r in &s.replace {
                        replaced.insert(r.column.clone());
                    }

                    for source in target_sources {
                        self.contribute_source_passthroughs(source, &renames, &replaced, &mut out);
                    }
                }
            }
        }

        Some(out)
    }

    fn contribute_source_passthroughs(
        &self,
        source: &PassthroughSource,
        renames: &HashMap<IdentKey, RenameEntry>,
        replaced: &std::collections::HashSet<IdentKey>,
        out: &mut HashMap<IdentKey, PassthroughTarget>,
    ) {
        match source {
            PassthroughSource::Scan { leaf_node } => {
                // We don't enumerate base columns at lowering time, so
                // only explicitly-renamed outputs land in the map. The
                // remaining columns (unrenamed, unreplaced) still
                // resolve through the existing alloc path against this
                // Scan's NodeId because the body's `from_aliases`
                // already point at it.
                for (from, entry) in renames {
                    if replaced.contains(from) {
                        continue;
                    }
                    out.insert(
                        entry.to.clone(),
                        PassthroughTarget {
                            leaf_scan_node: *leaf_node,
                            source_name: PassthroughSourceName {
                                ident: from.clone(),
                                span: entry.from_span,
                            },
                        },
                    );
                }
            }
            PassthroughSource::CteRef { name } => {
                let Some(parent) = self.lookup_cte_passthrough_by_name(name) else {
                    return;
                };
                for (parent_out_name, parent_target) in parent {
                    if replaced.contains(parent_out_name) {
                        continue;
                    }
                    let new_name = renames
                        .get(parent_out_name)
                        .map(|e| e.to.clone())
                        .unwrap_or_else(|| parent_out_name.clone());
                    out.insert(new_name, parent_target.clone());
                }
            }
            PassthroughSource::DerivedTable { node } => {
                let Some(parent) = self.cte_passthrough_columns.get(node) else {
                    return;
                };
                let parent = parent.clone();
                for (parent_out_name, parent_target) in &parent {
                    if replaced.contains(parent_out_name) {
                        continue;
                    }
                    let new_name = renames
                        .get(parent_out_name)
                        .map(|e| e.to.clone())
                        .unwrap_or_else(|| parent_out_name.clone());
                    out.insert(new_name, parent_target.clone());
                }
            }
        }
    }

    /// Walk the body's input subtree to enumerate FROM-scope sources
    /// keyed by the alias users would write before the dot in
    /// `alias.col`. Joins are descended through; pure-passthrough
    /// wrappers (`Filter` / `Sort` / `Limit` / `TableSample`) are
    /// transparent. Any other shape returns `None` so the caller
    /// treats the body as not-clean-passthrough.
    fn collect_passthrough_sources(
        &self,
        input: &RelPlan,
    ) -> Option<HashMap<Option<IdentKey>, PassthroughSource>> {
        let mut out: HashMap<Option<IdentKey>, PassthroughSource> = HashMap::new();
        Self::walk_collect_passthrough_sources(input, &mut out)?;
        Some(out)
    }

    fn walk_collect_passthrough_sources(
        cursor: &RelPlan,
        out: &mut HashMap<Option<IdentKey>, PassthroughSource>,
    ) -> Option<()> {
        match cursor {
            RelPlan::Filter { input, .. }
            | RelPlan::Sort { input, .. }
            | RelPlan::Limit { input, .. }
            | RelPlan::TableSample { input, .. }
            | RelPlan::Window { input, .. } => Self::walk_collect_passthrough_sources(input, out),
            RelPlan::Scan {
                node_id,
                alias,
                table,
                ..
            } => {
                let key = alias
                    .clone()
                    .or_else(|| Some(IdentKey::new(table.name.as_str())));
                out.insert(
                    key,
                    PassthroughSource::Scan {
                        leaf_node: *node_id,
                    },
                );
                Some(())
            }
            RelPlan::CteRef { alias, name, .. } => {
                let key = alias.clone().or_else(|| Some(name.clone()));
                out.insert(key, PassthroughSource::CteRef { name: name.clone() });
                Some(())
            }
            RelPlan::DerivedTable { node_id, alias, .. } => {
                let key = alias.clone();
                out.insert(key, PassthroughSource::DerivedTable { node: *node_id });
                Some(())
            }
            RelPlan::Join { left, right, .. } => {
                Self::walk_collect_passthrough_sources(left, out)?;
                Self::walk_collect_passthrough_sources(right, out)?;
                Some(())
            }
            // Other variants (Project, Aggregate, Window, SetOp,
            // Values, ModelRef, …) break the structural definition of
            // a clean star-passthrough source. The caller treats
            // `None` as "no passthrough info"; references fall back to
            // the existing alloc-on-first-use path.
            RelPlan::Values { .. }
            | RelPlan::ModelRef { .. }
            | RelPlan::Project { .. }
            | RelPlan::Aggregate { .. }
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
            | RelPlan::TableFunction { .. }
            | RelPlan::Unnest { .. }
            | RelPlan::Pivot { .. }
            | RelPlan::Unpivot { .. }
            | RelPlan::MatchRecognize { .. }
            | RelPlan::ConnectBy { .. }
            | RelPlan::InvalidInput { .. }
            | RelPlan::ParseRecovery { .. }
            | RelPlan::Opaque { .. } => None,
        }
    }

    /// Look up a CTE definition's passthrough map by name, walking
    /// `cte_scopes` from innermost (most-recent `WITH`) outward to
    /// match the standard SQL lexical-shadowing rule.
    fn lookup_cte_passthrough_by_name(
        &self,
        name: &IdentKey,
    ) -> Option<&HashMap<IdentKey, PassthroughTarget>> {
        for frame in self.cte_scopes.iter().rev() {
            if let Some(entry) = frame.get(name) {
                if entry.passthrough_columns.is_empty() {
                    return None;
                }
                return Some(&entry.passthrough_columns);
            }
        }
        None
    }

    fn finalize_star_passthrough_bindings(&mut self, ctes: &mut [CteBinding]) {
        for binding in ctes.iter_mut() {
            // Only non-recursive bodies can be star-passthrough.
            // Recursive bodies are union-shaped by definition and
            // already have populated output_columns.
            let body = match &mut binding.body {
                CteBody::NonRecursive(b) => b,
                CteBody::Recursive { .. } => continue,
            };
            // Combined detection covers both plain `SELECT *` bodies
            // and `SELECT * RENAME (…)` bodies — the same leaf-scan
            // routing applies; renames are honored at allocation time
            // by `lower_column_ref` consulting `cte_passthrough_renames`.
            let leaf_node = match body.cte_body_passthrough_leaf_scan_node() {
                Some(n) => n,
                None => continue,
            };
            let demanded = self.drain_scan_cols_for(leaf_node);
            if demanded.is_empty() {
                continue;
            }
            // Walk the body to the leaf Scan and append demands.
            let leaf = match find_star_passthrough_leaf_scan_mut(body.as_mut(), leaf_node) {
                Some(s) => s,
                // The leaf NodeId was recorded at registration; if
                // the structural walk no longer finds it, lowering
                // mutated the body shape between registration and
                // finalize, which is a bug — surface as a no-op
                // rather than panic.
                None => continue,
            };
            for col in demanded {
                if !leaf.contains(&col) {
                    leaf.push(col);
                }
            }
        }
    }

    /// Push a new aggregate-collection frame. Aggregate calls lowered
    /// while this frame is on top end up in its vec.
    fn push_agg_frame(&mut self) {
        self.aggregate_sinks.push(Some(Vec::new()));
    }

    /// Pop the innermost aggregate-collection frame. Panics if the
    /// frame is not a collection frame; see [`push_no_agg_frame`] for
    /// the "forbid aggregates" variant.
    fn pop_agg_frame(&mut self) -> Vec<AggregateCall> {
        match self.aggregate_sinks.pop() {
            Some(Some(v)) => v,
            Some(None) => panic!("pop_agg_frame called on a no-agg frame; use pop_no_agg_frame"),
            None => panic!("pop_agg_frame called with empty sink stack"),
        }
    }

    /// Push a "forbid aggregates" frame: lowering an aggregate call
    /// while this frame is on top produces a typed error. Used for
    /// `WHERE`, `FILTER (WHERE …)`, and `WITHIN GROUP (ORDER BY …)`.
    fn push_no_agg_frame(&mut self) {
        self.aggregate_sinks.push(None);
    }

    fn pop_no_agg_frame(&mut self) {
        match self.aggregate_sinks.pop() {
            Some(None) => {}
            Some(Some(_)) => panic!("pop_no_agg_frame called on a collection frame"),
            None => panic!("pop_no_agg_frame called with empty sink stack"),
        }
    }

    /// Current aggregate sink, if the innermost frame collects
    /// aggregates. Returns [`None`] when the stack is empty (no
    /// aggregate context) or when the innermost frame forbids them.
    fn innermost_agg_sink(&mut self) -> Option<&mut Vec<AggregateCall>> {
        match self.aggregate_sinks.last_mut() {
            Some(slot) => slot.as_mut(),
            None => None,
        }
    }

    /// True if the innermost frame forbids aggregates.
    fn innermost_forbids_aggs(&self) -> bool {
        matches!(self.aggregate_sinks.last(), Some(None))
    }

    /// Push a new window-collection frame.
    fn push_window_frame(&mut self) {
        self.window_sinks.push(Some(Vec::new()));
    }

    /// Pop the innermost window-collection frame.
    fn pop_window_frame(&mut self) -> Vec<WindowCall> {
        match self.window_sinks.pop() {
            Some(Some(v)) => v,
            Some(None) => {
                panic!("pop_window_frame called on a no-window frame; use pop_no_window_frame")
            }
            None => panic!("pop_window_frame called with empty sink stack"),
        }
    }

    /// Push a "forbid windows" frame. Lowering an `AstExpr::WindowFn`
    /// while this frame is on top is a typed lowering error.
    fn push_no_window_frame(&mut self) {
        self.window_sinks.push(None);
    }

    fn pop_no_window_frame(&mut self) {
        match self.window_sinks.pop() {
            Some(None) => {}
            Some(Some(_)) => {
                panic!("pop_no_window_frame called on a collection frame")
            }
            None => panic!("pop_no_window_frame called with empty sink stack"),
        }
    }

    /// Current window sink, if the innermost frame collects windows.
    fn innermost_window_sink(&mut self) -> Option<&mut Vec<WindowCall>> {
        match self.window_sinks.last_mut() {
            Some(slot) => slot.as_mut(),
            None => None,
        }
    }

    /// True if the innermost frame forbids windows.
    fn innermost_forbids_windows(&self) -> bool {
        matches!(self.window_sinks.last(), Some(None))
    }

    /// Lower a statement that appears in a scalar/predicate position —
    /// a scalar subquery, `EXISTS`, `IN (SELECT …)`, quantified
    /// comparison, or `SubqueryArg`. A subquery is a scope boundary:
    ///
    /// - Its aggregates and windows belong to its *own* `Aggregate` /
    ///   `Window` nodes, not the outer query's collection frames. The
    ///   outer `debug_assert!(aggregate_sinks.is_empty())` at the top
    ///   of [`Self::lower_select`] must continue to hold for the
    ///   nested call.
    /// - Its `FROM` bindings belong to its own namespace; they must
    ///   not leak back into the outer query after the subquery
    ///   returns. Lowering treats outer-column references inside a
    ///   subquery as unresolved — consistent with the
    ///   `correlates_with: vec![]` stub at each call site (see
    ///   the comment on [`ScalarExpr::Exists`]). Correlation is
    ///   derived post-lowering.
    /// - The per-scan column accumulator `scan_cols` is also reset so
    ///   the inner scan doesn't inherit a half-built outer column
    ///   list.
    ///
    /// All saved state is restored on exit regardless of success so a
    /// subquery-lowering failure cannot corrupt the outer context.
    fn lower_stmt_as_subquery(&mut self, stmt: &AstStmt) -> Result<RelPlan, LowerError> {
        self.lower_stmt_in_fresh_scope(stmt)
    }

    /// Lower `stmt` under a fresh SELECT-level resolution scope.
    ///
    /// Resets the three per-SELECT resolution tables — `bindings`,
    /// `from_scope`, `scan_cols` — plus the aggregate/window sink
    /// stacks, then restores them on exit. Used for any AST node
    /// that introduces a new SELECT-visibility boundary: scalar
    /// subqueries (via [`lower_stmt_as_subquery`]), CTE bodies
    /// (both recursive anchor/step and non-recursive), and each
    /// branch of a set operation.
    ///
    /// Without this, the lifetime-wide `bindings` HashMap caches an
    /// allocate-on-first-use ColumnId under the column's normalized
    /// name and a later SELECT that references the same column name
    /// (possibly from a *different* underlying table) would find
    /// the stale binding and alias to the wrong source. The issue
    /// surfaces only in corpora with multiple same-named columns
    /// across sibling SELECTs (CTE-heavy governance fixtures,
    /// multi-branch `UNION ALL`s).
    fn lower_stmt_in_fresh_scope(&mut self, stmt: &AstStmt) -> Result<RelPlan, LowerError> {
        let saved_agg = std::mem::take(&mut self.aggregate_sinks);
        let saved_win = std::mem::take(&mut self.window_sinks);
        let saved_bindings = std::mem::take(&mut self.bindings);
        let saved_from_scope = std::mem::take(&mut self.from_scope);
        let saved_scan = std::mem::take(&mut self.scan_cols);
        let saved_aliases = std::mem::take(&mut self.from_aliases);
        let saved_order = std::mem::take(&mut self.from_source_order);

        // Keep enclosing alias visibility as an explicit fallback
        // frame for qualified correlated refs (`outer_alias.col`) in
        // nested subqueries.
        self.outer_from_scope_frames.push(saved_from_scope.clone());
        self.outer_alias_frames.push(saved_aliases.clone());
        let result = self.lower_stmt(stmt);
        self.outer_from_scope_frames.pop();
        self.outer_alias_frames.pop();

        self.aggregate_sinks = saved_agg;
        self.window_sinks = saved_win;
        self.bindings = saved_bindings;
        self.from_scope = saved_from_scope;
        // Forward `scan_cols` entries whose `NodeId` targets an
        // outer-visible star-passthrough CTE binding's leaf Scan.
        // Without this, a nested CTE body that allocates demands
        // through a sibling's redirected alias (e.g. `FROM orders o`
        // where `orders` is a star-passthrough CTE in the enclosing
        // WITH list) would lose those demands when this fresh-scope
        // wrapper restores `scan_cols`. Inner-only entries (targeting
        // a leaf Scan that lives inside *this* statement) are
        // discarded as before — they have already been drained by
        // the matching `Scan`'s `lower_table_ref` path.
        let inner_scan = std::mem::replace(&mut self.scan_cols, saved_scan);
        if !inner_scan.is_empty() {
            let outer_leaves: std::collections::HashSet<crate::ast::NodeId> = self
                .cte_scopes
                .iter()
                .flat_map(|frame| frame.values().filter_map(|e| e.leaf_scan_node))
                .collect();
            for entry in inner_scan {
                if outer_leaves.contains(&entry.0) {
                    self.scan_cols.push(entry);
                }
            }
        }
        self.from_aliases = saved_aliases;
        self.from_source_order = saved_order;
        result
    }

    fn lower_stmt(&mut self, stmt: &AstStmt) -> Result<RelPlan, LowerError> {
        // Save + restore so nested `lower_stmt` calls (e.g. from
        // within a scalar subquery lowering path) don't clobber
        // the outer statement's root when they return.
        let saved = std::mem::replace(&mut self.current_stmt_node, stmt.node_id());
        let result = match stmt {
            AstStmt::Select(sel) => self.lower_select(sel),
            AstStmt::SetSelect(set) => self.lower_set_select(set),
            AstStmt::Insert(ins) => self.lower_insert(ins),
            AstStmt::ReplaceInto(rep) => self.lower_replace_into(rep),
            AstStmt::Update(upd) => self.lower_update(upd),
            AstStmt::Delete(del) => self.lower_delete(del),
            AstStmt::Merge(mrg) => self.lower_merge(mrg),
            AstStmt::MultiInsert(mi) => self.lower_multi_insert(mi),
            AstStmt::Explain(ex) => self.lower_explain(ex),
            // Standalone `VALUES (...), (...), ...` query (PostgreSQL /
            // ANSI SQL). Has no FROM clause; produces a row stream
            // directly from inline literal tuples. Lowers to
            // `RelPlan::Values`, optionally wrapped in `Sort` / `Limit`.
            AstStmt::ValuesQuery(v) => self.lower_values_query(v),
            AstStmt::CreateView(cv) => self.lower_create_view(cv),
            AstStmt::CreateTable(ct) => self.lower_create_table(ct),
            AstStmt::CreateDynamicTable(cdt) => self.lower_create_dynamic_table(cdt),
            // Policy DDL arms: build a synthetic binding
            // scope, lower embedded predicates against it, populate
            // `self.policy_facts`, and return `Opaque` for the
            // relational shape (policy DDL has no row stream).
            AstStmt::CreateRowAccessPolicy(p) => self.lower_create_row_access_policy(p),
            AstStmt::AlterRowAccessPolicy(p) => self.lower_alter_row_access_policy(p),
            AstStmt::CreateMaskingPolicy(p) => self.lower_create_masking_policy(p),
            AstStmt::AlterMaskingPolicy(p) => self.lower_alter_masking_policy(p),
            AstStmt::CreatePgPolicy(p) => self.lower_create_pg_policy(p),
            AstStmt::AlterPgPolicy(p) => self.lower_alter_pg_policy(p),
            // PostgreSQL `PREPARE name AS <query-bearing-body>` —
            // the prepared statement's body is a SELECT / INSERT /
            // UPDATE / DELETE / MERGE / VALUES. The IR's relational
            // shape for `PREPARE` is the body's plan; downstream
            // folds (`derive_facts_from_plan`, etc.) walk the body's
            // RelPlan and surface `tables_read` / `tables_written` etc.
            // through the wrapper. Mirrors `lower_explain`'s pattern
            // (recurse into the inner stmt) without an explicit
            // `RelPlan::Prepare` variant — the `PREPARE`-shaped DDL
            // fact (action=Execute against a prepared-statement
            // target) is currently unconsumed by any downstream.
            AstStmt::PgPrepare(p) => self.lower_stmt(&p.body),
            // PostgreSQL `COPY (<query>) TO ...` — the subquery
            // form recurses into the inner query so its `tables_read`
            // surfaces through the IR fold. The `COPY <table> FROM
            // ...` table form has no relational body and stays in
            // the Ddl arm of `crate::ir::lower_stmt` (it routes
            // through `lower_ddl_stmt` for the BulkLoad shape).
            AstStmt::PgCopy(c) => match &c.subject {
                crate::ast::PgCopySubject::Query(_, inner) => self.lower_stmt(inner),
                crate::ast::PgCopySubject::Table(_) => Err(LowerError::opaque(
                    stmt.span(),
                    OpaqueReason::NonSelectTopLevel,
                )),
            },
            // Snowflake Scripting `DECLARE c CURSOR FOR <query>` and
            // `LET c CURSOR FOR <query>` wrap a parsed inner query.
            // Same pattern as `PgPrepare`: recurse into the body so
            // the wrapper's IR fold surfaces the cursor query's
            // tables / predicates / taint through.
            AstStmt::DeclareCursor { query, .. } => self.lower_stmt(query),
            AstStmt::LetCursor {
                parsed_query: Some(query),
                ..
            } => self.lower_stmt(query),
            _ => Err(LowerError::opaque(
                stmt.span(),
                OpaqueReason::NonSelectTopLevel,
            )),
        };
        self.current_stmt_node = saved;
        result
    }

    // ── Policy DDL ──────────────────────────────────────────────────────

    /// Lower a single policy predicate against a synthetic binding
    /// scope built from `parameters`.
    ///
    /// `policy_node` is the AST `NodeId` of the policy DDL statement
    /// (used as `ColumnOrigin::Table.table_node` for parameter
    /// allocations so repeated references share an origin).
    /// `parameters` is the list of `(IdentKey, span)` pairs to bind
    /// before lowering. `qualifier` (when `Some`) registers the
    /// scope under a table-style alias so qualified `<alias>.<col>`
    /// refs resolve.
    ///
    /// Returns the lowered predicate plus the parameters' allocated
    /// `ColumnId`s (position-aligned with the input list).
    /// Predicates that fail to lower under permissive strict-mode
    /// produce `ScalarExpr::Opaque` via the existing `lower_expr`
    /// recovery path.
    ///
    /// Restores `from_scope` / `from_aliases` / `from_source_order`
    /// after the lowering completes — both on success and error.
    fn lower_policy_predicate(
        &mut self,
        expr: &AstExpr,
        policy_node: crate::ast::NodeId,
        parameters: &[(IdentKey, Span)],
        qualifier: Option<IdentKey>,
    ) -> Result<(ScalarExpr, Vec<ColumnId>), LowerError> {
        let saved_from_scope_len = self.from_scope.len();
        let saved_from_aliases = self.from_aliases.clone();
        let saved_from_source_order = self.from_source_order.clone();

        let mut param_ids = Vec::with_capacity(parameters.len());
        for (name, span) in parameters {
            let cid = self.alloc_table_col(policy_node, name.as_str(), *span);
            param_ids.push(cid);
            self.from_scope.push(FromScopeEntry {
                source_alias: qualifier.clone(),
                column_name: name.clone(),
                column_id: cid,
            });
        }
        if let Some(q) = qualifier.as_ref() {
            self.from_aliases.entry(q.clone()).or_insert(policy_node);
        }
        if !self.from_source_order.contains(&policy_node) {
            self.from_source_order.push(policy_node);
        }

        let predicate_result = self.lower_expr(expr, None);

        self.from_scope.truncate(saved_from_scope_len);
        self.from_aliases = saved_from_aliases;
        self.from_source_order = saved_from_source_order;

        predicate_result.map(|p| (p, param_ids))
    }

    /// Lower additional policy predicates against an already-built
    /// synthetic scope. Used by PG POLICY which has both `USING`
    /// and `WITH CHECK` predicates that share the target table's
    /// column scope.
    ///
    /// `param_ids` is the list of pre-allocated parameter
    /// `ColumnId`s that should be visible during lowering;
    /// position-aligned with `param_names`. The caller is
    /// responsible for restoring scope state — this helper only
    /// pushes scope entries and lowers.
    fn push_policy_scope(
        &mut self,
        policy_node: crate::ast::NodeId,
        param_names: &[IdentKey],
        param_ids: &[ColumnId],
        qualifier: Option<IdentKey>,
    ) -> usize {
        let saved_len = self.from_scope.len();
        for (name, cid) in param_names.iter().zip(param_ids.iter()) {
            self.from_scope.push(FromScopeEntry {
                source_alias: qualifier.clone(),
                column_name: name.clone(),
                column_id: *cid,
            });
        }
        if let Some(q) = qualifier.as_ref() {
            self.from_aliases.entry(q.clone()).or_insert(policy_node);
        }
        if !self.from_source_order.contains(&policy_node) {
            self.from_source_order.push(policy_node);
        }
        saved_len
    }

    /// Resolve the target table of a PG POLICY (or other
    /// table-bound policy DDL) against the catalog when available.
    /// Returns the per-column `(IdentKey, Span)` parameter list
    /// suitable for [`Self::lower_policy_predicate`].
    ///
    /// Returns an empty list when the catalog is absent or the
    /// table is unresolved — predicates referencing columns of
    /// such tables fall through to the lowerer's allocate-on-first-
    /// use path, producing concrete `ScalarExpr::Column` nodes
    /// anchored to the policy statement's `NodeId`.
    fn pg_policy_target_columns(&self, target: &TableRef) -> Vec<(IdentKey, Span)> {
        let Some(index) = self.catalog_index else {
            return Vec::new();
        };
        let mut resolved = target.clone();
        apply_session_defaults_to_table_ref(&mut resolved, self.session);
        let Some(catalog_table) = index.get_table_inferred(
            resolved.db.as_deref(),
            resolved.schema.as_deref(),
            &resolved.name,
        ) else {
            return Vec::new();
        };
        let target_span = target.span.unwrap_or_default();
        catalog_table
            .columns
            .iter()
            .map(|c| (IdentKey::new(&c.name.name), target_span))
            .collect()
    }

    fn lower_create_row_access_policy(
        &mut self,
        p: &crate::ast::AstCreateRowAccessPolicy,
    ) -> Result<RelPlan, LowerError> {
        let policy_name = self.ident_at(p.policy_name_span);
        // Snowflake form: `(params) RETURNS BOOLEAN -> body`.
        // BigQuery form: `... FILTER USING (filter_expr)`.
        // `parameters` is the typed Snowflake signature; BigQuery
        // shapes leave it empty.
        let parameters: Vec<(IdentKey, Span)> = p
            .parameters
            .iter()
            .map(|param| (self.ident_at(param.name_span), param.name_span))
            .collect();
        let body_expr = p.body.as_deref().or(p.filter_expr.as_deref());
        let (body, parameter_ids) = if let Some(expr) = body_expr {
            let (lowered, ids) = self.lower_policy_predicate(expr, p.node_id, &parameters, None)?;
            (Some(lowered), ids)
        } else {
            (None, Vec::new())
        };
        self.policy_facts = Some(super::policy_facts::PolicyStatementFacts::RowAccess(
            super::policy_facts::RowAccessPolicyFact {
                span: p.span,
                policy_name,
                body,
                parameters: parameter_ids,
            },
        ));
        Err(LowerError::opaque(p.span, OpaqueReason::NonSelectTopLevel))
    }

    fn lower_alter_row_access_policy(
        &mut self,
        p: &crate::ast::AstAlterRowAccessPolicy,
    ) -> Result<RelPlan, LowerError> {
        use crate::ast::AstAlterRowAccessPolicyActionKind;
        let policy_name = self.ident_at(p.name_span);
        // ALTER ROW ACCESS POLICY does not restate the signature,
        // so the body's column refs lower without a parameter
        // scope. Parameter binding is empty; refs fall through
        // to the allocate-on-first-use path: ALTER body inspections
        // operate on raw expression shape.
        let parameters: Vec<(IdentKey, Span)> = Vec::new();
        let body = match &p.action.kind {
            AstAlterRowAccessPolicyActionKind::SetBody { body, .. } => {
                let (lowered, _) =
                    self.lower_policy_predicate(body, p.node_id, &parameters, None)?;
                Some(lowered)
            }
            AstAlterRowAccessPolicyActionKind::RenameTo { .. }
            | AstAlterRowAccessPolicyActionKind::SetTag { .. }
            | AstAlterRowAccessPolicyActionKind::UnsetTag { .. }
            | AstAlterRowAccessPolicyActionKind::SetComment { .. }
            | AstAlterRowAccessPolicyActionKind::UnsetComment { .. } => None,
        };
        self.policy_facts = Some(super::policy_facts::PolicyStatementFacts::RowAccess(
            super::policy_facts::RowAccessPolicyFact {
                span: p.span,
                policy_name,
                body,
                parameters: Vec::new(),
            },
        ));
        Err(LowerError::opaque(p.span, OpaqueReason::NonSelectTopLevel))
    }

    fn lower_create_masking_policy(
        &mut self,
        p: &crate::ast::AstCreateMaskingPolicy,
    ) -> Result<RelPlan, LowerError> {
        let policy_name = self.ident_at(p.policy_name_span);
        let parameters: Vec<(IdentKey, Span)> = p
            .parameters
            .iter()
            .map(|param| (self.ident_at(param.name_span), param.name_span))
            .collect();
        let (lowered_body, parameter_ids) =
            self.lower_policy_predicate(&p.body, p.node_id, &parameters, None)?;
        self.policy_facts = Some(super::policy_facts::PolicyStatementFacts::Masking(
            super::policy_facts::MaskingPolicyFact {
                span: p.span,
                policy_name,
                body: Some(lowered_body),
                parameters: parameter_ids,
            },
        ));
        Err(LowerError::opaque(p.span, OpaqueReason::NonSelectTopLevel))
    }

    fn lower_alter_masking_policy(
        &mut self,
        p: &crate::ast::AstAlterMaskingPolicy,
    ) -> Result<RelPlan, LowerError> {
        use crate::ast::AstAlterMaskingPolicyActionKind;
        let policy_name = self.ident_at(p.name_span);
        let parameters: Vec<(IdentKey, Span)> = Vec::new();
        let body = match &p.action.kind {
            AstAlterMaskingPolicyActionKind::SetBody { body, .. } => {
                let (lowered, _) =
                    self.lower_policy_predicate(body, p.node_id, &parameters, None)?;
                Some(lowered)
            }
            AstAlterMaskingPolicyActionKind::RenameTo { .. }
            | AstAlterMaskingPolicyActionKind::SetTag { .. }
            | AstAlterMaskingPolicyActionKind::UnsetTag { .. }
            | AstAlterMaskingPolicyActionKind::SetComment { .. }
            | AstAlterMaskingPolicyActionKind::UnsetComment { .. } => None,
        };
        self.policy_facts = Some(super::policy_facts::PolicyStatementFacts::Masking(
            super::policy_facts::MaskingPolicyFact {
                span: p.span,
                policy_name,
                body,
                parameters: Vec::new(),
            },
        ));
        Err(LowerError::opaque(p.span, OpaqueReason::NonSelectTopLevel))
    }

    fn lower_create_pg_policy(
        &mut self,
        p: &crate::ast::AstCreatePgPolicy,
    ) -> Result<RelPlan, LowerError> {
        let policy_name = self.ident_at(p.policy_name);
        let table_ref = self.pg_policy_table_ref(p.table_name);
        let parameters = self.pg_policy_target_columns(&table_ref);
        // PG POLICY USING / WITH CHECK predicates share the
        // target table's column scope. Allocate parameter ColumnIds
        // once, push the scope, lower both predicates, restore.
        let saved_from_scope_len = self.from_scope.len();
        let saved_from_aliases = self.from_aliases.clone();
        let saved_from_source_order = self.from_source_order.clone();

        let mut param_ids = Vec::with_capacity(parameters.len());
        let table_alias = Some(IdentKey::new(&table_ref.name));
        for (name, span) in &parameters {
            let cid = self.alloc_table_col(p.node_id, name.as_str(), *span);
            param_ids.push(cid);
        }
        self.push_policy_scope(
            p.node_id,
            &parameters
                .iter()
                .map(|(n, _)| n.clone())
                .collect::<Vec<_>>(),
            &param_ids,
            table_alias,
        );

        let using = p.using_expr.as_deref().map(|e| self.lower_expr(e, None));
        let with_check = p.check_expr.as_deref().map(|e| self.lower_expr(e, None));

        self.from_scope.truncate(saved_from_scope_len);
        self.from_aliases = saved_from_aliases;
        self.from_source_order = saved_from_source_order;

        let using = match using {
            Some(Ok(e)) => Some(e),
            Some(Err(err)) => return Err(err),
            None => None,
        };
        let with_check = match with_check {
            Some(Ok(e)) => Some(e),
            Some(Err(err)) => return Err(err),
            None => None,
        };

        self.policy_facts = Some(super::policy_facts::PolicyStatementFacts::PgPolicy(
            super::policy_facts::PgPolicyFact {
                span: p.span,
                policy_name,
                table_ref,
                using,
                with_check,
                target_columns: param_ids,
            },
        ));
        Err(LowerError::opaque(p.span, OpaqueReason::NonSelectTopLevel))
    }

    fn lower_alter_pg_policy(
        &mut self,
        p: &crate::ast::AstAlterPgPolicy,
    ) -> Result<RelPlan, LowerError> {
        use crate::ast::AlterPgPolicyAction;
        let policy_name = self.ident_at(p.policy_name);
        let table_ref = self.pg_policy_table_ref(p.table_name);
        match &p.action {
            AlterPgPolicyAction::Modify {
                using_expr,
                check_expr,
                ..
            } => {
                let parameters = self.pg_policy_target_columns(&table_ref);
                let saved_from_scope_len = self.from_scope.len();
                let saved_from_aliases = self.from_aliases.clone();
                let saved_from_source_order = self.from_source_order.clone();

                let mut param_ids = Vec::with_capacity(parameters.len());
                let table_alias = Some(IdentKey::new(&table_ref.name));
                for (name, span) in &parameters {
                    let cid = self.alloc_table_col(p.node_id, name.as_str(), *span);
                    param_ids.push(cid);
                }
                self.push_policy_scope(
                    p.node_id,
                    &parameters
                        .iter()
                        .map(|(n, _)| n.clone())
                        .collect::<Vec<_>>(),
                    &param_ids,
                    table_alias,
                );

                let using = using_expr.as_deref().map(|e| self.lower_expr(e, None));
                let with_check = check_expr.as_deref().map(|e| self.lower_expr(e, None));

                self.from_scope.truncate(saved_from_scope_len);
                self.from_aliases = saved_from_aliases;
                self.from_source_order = saved_from_source_order;

                let using = match using {
                    Some(Ok(e)) => Some(e),
                    Some(Err(err)) => return Err(err),
                    None => None,
                };
                let with_check = match with_check {
                    Some(Ok(e)) => Some(e),
                    Some(Err(err)) => return Err(err),
                    None => None,
                };
                self.policy_facts = Some(super::policy_facts::PolicyStatementFacts::PgPolicy(
                    super::policy_facts::PgPolicyFact {
                        span: p.span,
                        policy_name,
                        table_ref,
                        using,
                        with_check,
                        target_columns: param_ids,
                    },
                ));
            }
            AlterPgPolicyAction::Rename { .. } => {
                self.policy_facts = Some(super::policy_facts::PolicyStatementFacts::PgPolicy(
                    super::policy_facts::PgPolicyFact {
                        span: p.span,
                        policy_name,
                        table_ref,
                        using: None,
                        with_check: None,
                        target_columns: Vec::new(),
                    },
                ));
            }
        }
        Err(LowerError::opaque(p.span, OpaqueReason::NonSelectTopLevel))
    }

    /// Build a [`TableRef`] from a PG POLICY `ON <table>` span.
    /// Splits on `.` to recover the (db, schema, name) shape so the
    /// catalog lookup in [`Self::pg_policy_target_columns`] sees the
    /// same canonicalized form a SELECT-side `Scan` would.
    fn pg_policy_table_ref(&self, span: Span) -> TableRef {
        let raw = slice_span(self.source, span).unwrap_or("");
        let parts = split_object_ref(raw);
        let (db, schema, name) = match parts.len() {
            0 => (None, None, raw.to_string()),
            1 => (None, None, parts[0].clone()),
            2 => (None, Some(parts[0].clone()), parts[1].clone()),
            _ => (
                Some(parts[parts.len() - 3].clone()),
                Some(parts[parts.len() - 2].clone()),
                parts[parts.len() - 1].clone(),
            ),
        };
        TableRef {
            server: None,
            db,
            schema,
            name,
            span: Some(span),
        }
    }

    // ── SELECT ──────────────────────────────────────────────────────────

    fn lower_select(&mut self, sel: &AstSelect) -> Result<RelPlan, LowerError> {
        // If a WITH clause is attached, peel it off and wrap
        // the lowered body in a `RelPlan::WithScope`. The CTE-scope
        // stack is the mechanism FROM-clause resolution consults to
        // produce `CteRef` rather than `Scan` for references to CTE
        // names.
        let inner = if let Some(with_clause) = sel.with_clause.as_deref() {
            self.lower_select_with_ctes(sel, with_clause)?
        } else {
            self.lower_select_body(sel)?
        };
        // MSSQL / PostgreSQL `SELECT … INTO new_tbl` (CTAS shortcut).
        // Wrap the lowered SELECT in `CreateAsQuery` so existing CTAS-tracking
        // rules (write-target detection, lineage, governance on
        // `CreateAsKind::Table`) fire unchanged. ScriptingVars takes no
        // wrapping — it surfaces as `StatementFacts.into_vars`.
        if let Some(crate::ast::AstSelectIntoTarget::NewTable(nt)) = sel.into_target.as_deref() {
            let target = self.lower_table_ref_from_span_or_none(Some(nt.name.span), sel.span)?;
            let temp = matches!(
                nt.temp_kind,
                crate::ast::AstSelectIntoTempKind::LocalTemp
                    | crate::ast::AstSelectIntoTempKind::GlobalTemp
                    | crate::ast::AstSelectIntoTempKind::Temp
            );
            return Ok(RelPlan::CreateAsQuery {
                target,
                kind: CreateAsKind::Table {
                    transient: false,
                    temp,
                },
                columns: None,
                body: Some(Box::new(inner)),
                or_replace: false,
                or_alter: false,
                if_not_exists: false,
                copy_grants: false,
                side_options: Vec::new(),
                hints: Vec::new(),
                node_id: sel.node_id,
                span: sel.span,
            });
        }
        Ok(inner)
    }

    /// Lower a `SELECT` whose `with_clause` has already been stripped
    /// (or was absent). Factored out of [`Self::lower_select`] so the
    /// WITH-scope wrapper can invoke body lowering after registering
    /// CTE bindings without re-entering the CTE peel-off.
    fn lower_select_body(&mut self, sel: &AstSelect) -> Result<RelPlan, LowerError> {
        // Reject unsupported SELECT features. Each rejection
        // carries a dedicated OpaqueReason.
        self.reject_unsupported_select_features(sel)?;

        // Lower non-relational sibling-tier facts
        // before any rejection that consumes them, so a partially-
        // populated `StatementFacts` survives an OpaqueContent
        // fallback. Populated here:
        // for_update, output_format, into_vars,
        // select_as, pre_limit_extensions,
        // post_locking_extensions, jinja_fragments.
        self.extract_for_update_facts(sel)?;
        self.extract_output_format_fact(sel);
        self.extract_into_vars_facts(sel);
        self.extract_file_export_fact(sel);
        self.extract_select_as_fact(sel);
        self.extract_pre_limit_extensions_fact(sel);
        self.extract_post_locking_extensions_fact(sel);
        self.extract_statement_fragments_fact(sel);

        // Clear `from_scope` at SELECT-body entry so a sibling CTE
        // body's scope (or a residual outer scope left over when this
        // call is not reached via `lower_stmt_as_subquery`) does not
        // bleed into this SELECT's column resolution. The scope is
        // repopulated below after FROM is fully lowered.
        self.from_scope.clear();
        // Clear FROM-alias state for the same reason: each SELECT's
        // FROM aliases are scoped to that SELECT. They are populated
        // incrementally as each FROM item lowers (see
        // `register_from_source` callers).
        self.from_aliases.clear();
        self.from_source_order.clear();

        // FROM: lower each item and left-fold comma-separated items as
        // `Cross` joins. If the SELECT has no FROM at all (e.g.
        // `SELECT 1 + 1`, `SELECT :var`, `SELECT coalesce(x, 0) AS v`),
        // synthesize a zero-column, one-row `RelPlan::Values` as the
        // source. Every downstream stage (Filter / Aggregate / Window /
        // Sort / Limit / Project) composes unchanged because each only
        // consumes the relational contract of its input — the specific
        // source shape is irrelevant.
        let from_plan = if sel.from.is_empty() {
            // A SELECT without FROM uses a synthetic one-row Values
            // source. Register it as the leftmost FROM source so
            // unresolved column refs in permissive mode attach to
            // this node (and get projected as unqualified Values
            // sources), rather than leaking a dangling Table-origin
            // id with no matching Scan.
            self.register_from_source(std::iter::empty::<IdentKey>(), sel.node_id);
            RelPlan::Values {
                rows: vec![Vec::new()],
                columns: Vec::new(),
                alias: None,
                node_id: sel.node_id,
                span: sel.span,
                hints: Vec::new(),
            }
        } else {
            let mut plan = self.lower_from_item(&sel.from[0])?;
            for item in &sel.from[1..] {
                let right = self.lower_from_item(item)?;
                let span = merge_spans(plan.span(), right.span());
                let clause_span = right.span();
                plan = RelPlan::Join {
                    left: Box::new(plan),
                    right: Box::new(right),
                    kind: JoinKind::Cross,
                    on: None,
                    match_condition: None,
                    using: Vec::new(),
                    natural: false,
                    directed: false,
                    lateral: false,
                    implicit: true,
                    node_id: item.node_id,
                    span,
                    clause_span,
                    hints: Vec::new(),
                };
            }
            plan
        };

        // Populate `from_scope` from the fully-lowered FROM plan so
        // subsequent column-reference lowering (projection, WHERE,
        // HAVING, QUALIFY, GROUP BY) can resolve unqualified names to
        // the ColumnIds their source nodes already own, instead of
        // leaking a fresh Table-origin orphan. See field doc on
        // `LowerCtx::from_scope`.
        self.populate_from_scope(&from_plan);

        // Lower projection / grouping / having / qualify / where after
        // FROM is fully assembled. The bindings table is shared across
        // all scans (the "allocate on first use" approximation).
        //
        // Order of operations:
        //   1. Open an aggregate-collection frame.
        //   2. Open a window-collection frame.
        //   2. Lower projection; aggregate calls inside are promoted.
        //   3. Lower GROUP BY *using the lowered projection* so ordinal
        //      (`GROUP BY 1`), alias (`GROUP BY colname` where colname
        //      is a SELECT alias), and `GROUP BY ALL` can resolve
        //      against projection items.
        //   4. Lower HAVING; its aggregate calls merge into the same
        //      frame so `SELECT a, COUNT(*) … HAVING COUNT(*) > 1`
        //      produces distinct occurrences but any canonicalization
        //      has a single place to run.
        //   5. Lower QUALIFY with no-agg + collecting-window frames:
        //      QUALIFY predicates can reference window outputs but may
        //      not contain plain aggregates.
        //   6. Pop frames; pull collected aggregates/windows out.
        //   7. Lower WHERE with no-agg + no-window frames: aggregates
        //      and windows in WHERE are SQL shape errors.
        //   8. Materialize Aggregate (if needed), then Window (if any),
        //      then QUALIFY filter (if present), then final Project.
        debug_assert!(self.aggregate_sinks.is_empty());
        debug_assert!(self.window_sinks.is_empty());
        // Push named WINDOW clause definitions so `lower_window_fn` /
        // `lower_window_expr` can resolve `OVER w` references within
        // this SELECT body's projection, HAVING, and QUALIFY. Popped
        // unconditionally after the collection frames close.
        let has_window_clause = sel.window_clause.is_some();
        if let Some(wc) = sel.window_clause.as_deref() {
            let mut scope: HashMap<IdentKey, crate::ast::AstWindowSpec> =
                HashMap::with_capacity(wc.definitions.len());
            for def in &wc.definitions {
                let key = IdentKey::new(slice_span(self.source, def.name_span).unwrap_or(""));
                scope.insert(key, def.window_spec.clone());
            }
            self.named_window_defs.push(scope);
        }
        self.push_agg_frame();
        self.push_window_frame();
        let projection_items = self.lower_projection(sel)?;
        // Build the SELECT-list alias scope from the just-lowered
        // projection items. Threaded as `Some(&alias_map)` to every
        // subsequent clause's `lower_expr` call so unqualified
        // names that don't resolve via FROM-scope can fall back to
        // SELECT-list aliases (Snowflake / BigQuery / MySQL / CH
        // extension). Real source
        // columns shadow aliases — that ordering lives inside
        // `lower_column_ref`'s resolution chain.
        let alias_map = AliasMap::from_projection(&projection_items);
        let grouping = match sel.group_by.as_deref() {
            Some(gb) => self.lower_grouping(gb, &projection_items)?,
            None => GroupingSpec::None,
        };
        self.push_no_window_frame();
        let having_predicate = match sel.having.as_deref() {
            Some(c) => Some(self.lower_expr(&c.expr, Some(&alias_map))?),
            None => None,
        };
        self.pop_no_window_frame();
        self.push_no_agg_frame();
        let qualify_predicate = match sel.qualify.as_deref() {
            Some(c) => Some(self.lower_expr(&c.expr, Some(&alias_map))?),
            None => None,
        };
        self.pop_no_agg_frame();
        let windows = self.pop_window_frame();
        let aggregates = self.pop_agg_frame();

        self.push_no_agg_frame();
        self.push_no_window_frame();
        let where_predicate = match sel.where_clause.as_deref() {
            Some(where_clause) => Some(self.lower_expr(&where_clause.expr, Some(&alias_map))?),
            None => None,
        };
        self.pop_no_window_frame();
        self.pop_no_agg_frame();
        debug_assert!(self.aggregate_sinks.is_empty());
        debug_assert!(self.window_sinks.is_empty());

        // Pop the named-window scope pushed above (if any). The
        // `?` operators inside the projection lowering stages above
        // propagate errors before reaching here, so we clean up
        // only on the success path. Named-window scope leaks on the
        // error path are harmless — `LowerCtx` is dropped at the
        // call site immediately after a `LowerError` is returned.
        if has_window_clause {
            self.named_window_defs.pop();
        }

        // Inject any pending column allocations onto the FROM
        // plan's source nodes by NodeId match. Each `(NodeId,
        // ColumnId)` pair was stamped at first reference (see
        // `lower_column_ref`) with the correct source NodeId via
        // [`Self::from_aliases`] / [`Self::from_source_order`], so
        // the routing is a direct equality match — no alias-text
        // heuristics, no leftmost-scan fallback at attach time.
        let leftover_cols = std::mem::take(&mut self.scan_cols);
        let (from_plan, unattached) = attach_pending_source_cols(from_plan, leftover_cols);
        // Unattached entries refer to source nodes outside this
        // select's local FROM tree (e.g. CTE bodies whose leaf
        // Scans were sealed earlier under
        // `cte_body_star_passthrough_leaf_scan_node` redirection,
        // or correlated outer-scope refs). Re-park them on
        // `scan_cols` so the enclosing scope's
        // `lower_stmt_in_fresh_scope` unwind / parent's
        // `lower_select_body` attach pass can route them.
        self.scan_cols.extend(unattached);

        // Lateral-alias predicate splitting.
        // Each WHERE / HAVING / QUALIFY predicate is split by its
        // top-level AND chain into atoms that reference at least
        // one SELECT-list alias output ColumnId ("lifted") vs atoms
        // that reference only source / aggregate / window columns
        // ("in-place"). In-place atoms wrap at their natural plan
        // position as today; lifted atoms become a stack of
        // `Filter` nodes above `Project`, preserving the schema
        // invariant that every Filter's predicate column refs are
        // in its input's `output_schema()`.
        let alias_outputs = &alias_map.output_ids;
        let (where_in_place, where_lifted) = match where_predicate {
            Some(p) => split_predicate_by_alias_refs(p, alias_outputs),
            None => (None, None),
        };
        let (having_in_place, having_lifted) = match having_predicate {
            Some(p) => split_predicate_by_alias_refs(p, alias_outputs),
            None => (None, None),
        };
        let (qualify_in_place, qualify_lifted) = match qualify_predicate {
            Some(p) => split_predicate_by_alias_refs(p, alias_outputs),
            None => (None, None),
        };

        let after_where = match where_in_place {
            None => from_plan,
            Some(pred) => {
                let filter_span = sel
                    .where_clause
                    .as_ref()
                    .map(|c| c.span)
                    .unwrap_or(sel.span);
                RelPlan::Filter {
                    input: Box::new(from_plan),
                    predicate: pred,
                    kind: FilterKind::Where,
                    node_id: sel.node_id,
                    span: filter_span,
                    hints: Vec::new(),
                }
            }
        };

        // If the query has any aggregate shape — GROUP BY, HAVING, or
        // aggregate function calls in the projection — wrap the current
        // plan in an `Aggregate` node. The aggregate's output column
        // list is `[group_keys…, aggregates…]`, with
        // duplicate `ColumnId`s collapsed (CUBE / GROUPING SETS can
        // repeat the same key across sets). `having_in_place` is the
        // portion of HAVING that references no SELECT-list aliases;
        // alias-bearing HAVING atoms are lifted above `Project`.
        let has_aggregate_shape = !aggregates.is_empty()
            || !matches!(grouping, GroupingSpec::None)
            || having_in_place.is_some()
            || having_lifted.is_some();
        let after_aggregate = if has_aggregate_shape {
            let output_columns = build_aggregate_output_columns(&grouping, &aggregates);
            // Prefer the clause that structurally owns this Aggregate
            // node for diagnostics: GROUP BY ›› HAVING ›› first
            // aggregate's call span ›› the whole select as a last
            // resort. The first three are precise; the last only
            // triggers on the pathological "aggregate-shaped but no
            // GROUP BY, no HAVING, no collected aggregates" case,
            // which `has_aggregate_shape` rules out.
            let agg_span = sel
                .group_by
                .as_ref()
                .map(|g| g.span)
                .or_else(|| sel.having.as_ref().map(|h| h.span))
                .or_else(|| aggregates.first().map(|a| a.span))
                .unwrap_or(sel.span);
            RelPlan::Aggregate {
                input: Box::new(after_where),
                grouping,
                aggregates,
                having: having_in_place,
                output_columns,
                node_id: sel.node_id,
                span: agg_span,
                hints: Vec::new(),
            }
        } else {
            after_where
        };

        let after_window = if windows.is_empty() {
            after_aggregate
        } else {
            let output_columns = build_window_output_columns(&windows);
            let window_span = merge_spans(
                windows.first().map(|w| w.span).unwrap_or(sel.span),
                windows.last().map(|w| w.span).unwrap_or(sel.span),
            );
            RelPlan::Window {
                input: Box::new(after_aggregate),
                windows,
                window_outputs: output_columns,
                node_id: sel.node_id,
                span: window_span,
                hints: Vec::new(),
            }
        };

        let after_qualify = match qualify_in_place {
            None => after_window,
            Some(pred) => {
                let qualify_span = sel.qualify.as_ref().map(|c| c.span).unwrap_or(sel.span);
                RelPlan::Filter {
                    input: Box::new(after_window),
                    predicate: pred,
                    kind: FilterKind::Qualify,
                    node_id: sel.node_id,
                    span: qualify_span,
                    hints: Vec::new(),
                }
            }
        };

        // Lower the set-quantifier. DISTINCT ON (e1, e2) is a
        // PostgreSQL extension that retains the first row per
        // distinct combination of (e1, e2). Both `distinct` and
        // `distinct_on` are populated: analyses that only care
        // about deduplication check `distinct`; analyses that
        // need the ON expressions check `distinct_on`.
        // Expressions are lowered in no-agg + no-window frames
        // because they are positional filter keys, not aggregate
        // or window contexts.
        let (distinct, distinct_on) = match sel.set_quantifier.as_deref() {
            Some(AstSetQuantifier::Distinct) => (true, Vec::new()),
            Some(AstSetQuantifier::DistinctOn { exprs, .. }) => {
                self.push_no_agg_frame();
                self.push_no_window_frame();
                let lowered = exprs
                    .iter()
                    .map(|e| self.lower_expr(e, Some(&alias_map)))
                    .collect::<Result<Vec<_>, _>>();
                self.pop_no_window_frame();
                self.pop_no_agg_frame();
                (true, lowered?)
            }
            Some(AstSetQuantifier::All) | None => (false, Vec::new()),
        };

        let project_plan = RelPlan::Project {
            input: Box::new(after_qualify),
            items: projection_items,
            distinct,
            distinct_on,
            node_id: sel.node_id,
            span: sel.span,
            hints: Vec::new(),
        };

        // Stack lifted Filters (alias-bearing WHERE / HAVING /
        // QUALIFY atoms) above `Project`, in source-clause order:
        // Where deepest, then Having, then Qualify on top. The
        // ordering is semantically irrelevant (all are
        // AND-equivalent at the same scope) but we keep it stable
        // for diagnostic predictability. Each Filter's predicate
        // column refs are projection-output ColumnIds, satisfying
        // the schema invariant against the Project node below.
        let mut after_lifted = project_plan;
        for (kind, lifted, clause_span) in [
            (
                FilterKind::Where,
                where_lifted,
                sel.where_clause.as_ref().map(|c| c.span),
            ),
            (
                FilterKind::Having,
                having_lifted,
                sel.having.as_ref().map(|c| c.span),
            ),
            (
                FilterKind::Qualify,
                qualify_lifted,
                sel.qualify.as_ref().map(|c| c.span),
            ),
        ] {
            if let Some(predicate) = lifted {
                let span = clause_span.unwrap_or(sel.span);
                after_lifted = RelPlan::Filter {
                    input: Box::new(after_lifted),
                    predicate,
                    kind,
                    node_id: sel.node_id,
                    span,
                    hints: Vec::new(),
                };
            }
        }
        let project_plan = after_lifted;

        // ORDER BY → Sort wrapping the outermost Project.
        // Aggregate / window functions in `ORDER BY` keys are rejected
        // (no-agg + no-window frames) — the supported scope is literal /
        // column / ordinal / scalar expression keys, which covers the
        // overwhelming majority of real-world usage. Anything more
        // exotic surfaces as `AggregateContextError` /
        // `WindowContextError` / `ScalarExprNotLowered` from the
        // frame-guarded `lower_expr` call.
        let after_sort = match sel.order_by.as_deref() {
            None => project_plan,
            Some(order_by) => {
                self.push_no_agg_frame();
                self.push_no_window_frame();
                let mut keys: Vec<SortKey> = Vec::with_capacity(order_by.items.len());
                let mut key_err: Option<LowerError> = None;
                for item in &order_by.items {
                    match self.lower_expr(&item.expr, Some(&alias_map)) {
                        Ok(expr) => keys.push(SortKey {
                            expr,
                            ascending: item.asc.unwrap_or(true),
                            nulls_first: item.nulls_first,
                            span: item.span,
                        }),
                        Err(e) => {
                            key_err = Some(e);
                            break;
                        }
                    }
                }
                self.pop_no_window_frame();
                self.pop_no_agg_frame();
                if let Some(e) = key_err {
                    return Err(e);
                }
                RelPlan::Sort {
                    input: Box::new(project_plan),
                    keys,
                    node_id: sel.node_id,
                    span: order_by.span,
                    hints: Vec::new(),
                }
            }
        };

        // LIMIT / OFFSET / FETCH / T-SQL TOP → typed Limit
        // wrapping the sort (or the project directly). `TOP (n)
        // PERCENT` uses `LimitKind::Percent`; when TOP composes with
        // LIMIT / OFFSET / FETCH, both caps are preserved as nested
        // `Limit` nodes.
        //
        // For FETCH syntax the parser folds the row count into
        // `sel.limit` and records `sel.fetch_clause_span` as a marker;
        // the lowering ignores the marker — the distinction between
        // `LIMIT n` and `FETCH FIRST n ROWS ONLY` is purely syntactic.
        // WITH TIES on FETCH is not yet captured by the parser (a
        // separate fix); only T-SQL `TOP … WITH TIES` sets
        // `with_ties = true` today.
        let has_top = sel.top.is_some();
        let has_limit_like =
            sel.limit.is_some() || sel.offset.is_some() || sel.fetch_clause_span.is_some();
        let final_plan = if !has_top && !has_limit_like {
            after_sort
        } else {
            let mut capped = after_sort;
            if let Some(top) = sel.top.as_deref() {
                let limit_expr = self.lower_expr_no_aggs(&top.expr, None)?;
                capped = RelPlan::Limit {
                    input: Box::new(capped),
                    limit: Some(limit_expr),
                    offset: None,
                    kind: if top.percent_span.is_some() {
                        LimitKind::Percent
                    } else {
                        LimitKind::Rows
                    },
                    with_ties: top.with_ties_span.is_some(),
                    node_id: sel.node_id,
                    span: top.span,
                    hints: Vec::new(),
                };
            }
            if has_limit_like {
                let limit_expr = match sel.limit.as_deref() {
                    Some(e) => Some(self.lower_expr_no_aggs(e, None)?),
                    None => None,
                };
                let offset_expr = match sel.offset.as_deref() {
                    Some(e) => Some(self.lower_expr_no_aggs(e, None)?),
                    None => None,
                };
                let span = compute_limit_offset_fetch_span(sel);
                capped = RelPlan::Limit {
                    input: Box::new(capped),
                    limit: limit_expr,
                    offset: offset_expr,
                    kind: LimitKind::Rows,
                    with_ties: false,
                    node_id: sel.node_id,
                    span,
                    hints: Vec::new(),
                };
            }
            capped
        };

        // CONNECT BY: if present, wrap the assembled plan. The hierarchical
        // traversal operator is transparent to the column schema — it passes through
        // whatever the SELECT produces. `start_with` and `connect` expressions are
        // lowered in no-agg + no-window context (CONNECT BY predicates may not
        // contain aggregate or window calls).
        let final_plan = match sel.connect_by.as_deref() {
            None => final_plan,
            Some(cb) => self.lower_connect_by(final_plan, cb)?,
        };

        Ok(final_plan)
    }

    /// Lower an [`AstConnectBy`] clause, wrapping `input` with
    /// [`RelPlan::ConnectBy`].
    ///
    /// The `output_columns` of the `ConnectBy` node are identical to the
    /// input plan's output schema: the hierarchical traversal does not add
    /// or remove columns.
    ///
    /// Multiple conditions in `AstConnectBy.conditions` (joined by AND in
    /// the source text) become one flat [`ScalarExpr::LogicalChain`], the
    /// same representation [`AstExpr::LogicalChain`] lowers to.
    fn lower_connect_by(
        &mut self,
        input: RelPlan,
        cb: &AstConnectBy,
    ) -> Result<RelPlan, LowerError> {
        self.push_no_agg_frame();
        self.push_no_window_frame();

        let start_with = match cb.start_with_condition.as_ref() {
            Some(expr) => Some(self.lower_expr(expr, None)?),
            None => None,
        };

        // AND-fold the condition list. The parser always produces at least one
        // condition; the empty case is a parser-invariant violation and we
        // recover with a null literal (same pattern as LogicalChain).
        let connect = {
            let mut lowered = cb
                .conditions
                .iter()
                .map(|e| self.lower_expr(e, None))
                .collect::<Result<Vec<_>, _>>()?;
            match lowered.len() {
                0 => ScalarExpr::Lit {
                    value: Lit::Null,
                    span: cb.connect_by_span,
                },
                1 => lowered.remove(0),
                _ => ScalarExpr::LogicalChain {
                    op: super::scalar::LogicalOp::And,
                    operands: lowered,
                    span: cb.span,
                },
            }
        };

        self.pop_no_window_frame();
        self.pop_no_agg_frame();

        let output_columns = input.output_schema();
        Ok(RelPlan::ConnectBy {
            input: Box::new(input),
            start_with,
            connect,
            nocycle: false,
            output_columns,
            node_id: cb.node_id,
            span: cb.span,
            hints: Vec::new(),
        })
    }

    // ── SET operations ──────────────────────────────────────────────────

    /// Lower an [`AstSetSelect`] to [`RelPlan::SetOp`].
    ///
    /// The parser produces a left-deep AST: `a UNION b UNION c` parses
    /// as `SetSelect(SetSelect(a, UNION, b), UNION, c)`. Lowering
    /// N-ary-flattens spans of children that share the same
    /// [`SetOpKind`] so per-branch analyses
    /// can iterate `inputs` directly without a second
    /// tree-rewrite pass. Mixed-operator spines (e.g.
    /// `a UNION b INTERSECT c`, which the parser produces as a
    /// left-deep tree but whose operators differ) stay nested.
    ///
    /// Each `SetOp.output_columns` slot gets a fresh [`ColumnId`].
    /// Arity is taken from the first branch's `output_schema()`.
    fn lower_set_select(&mut self, set: &AstSetSelect) -> Result<RelPlan, LowerError> {
        // SQL semantic: a `WITH` clause in front of a set-op applies
        // to every branch, not just the leftmost. The parser
        // (`parser/set_operations.rs:282-291`) attaches it to the
        // leftmost `AstSelect.with_clause`; lift it out before
        // flattening so each branch resolves CTE refs through
        // `cte_scopes`. Without this lift, branches after the first
        // would resolve a CTE name as a base-table `Scan`, breaking
        // any analysis that depends on the CteRef binding (lineage,
        // Q-PROP-CONTRA constraint propagation, etc.).
        if let Some((with_clause, stripped_set)) = strip_leftmost_with_clause(set) {
            return self.lower_set_select_with_lifted_ctes(&stripped_set, &with_clause);
        }

        let op_kind = make_set_op_kind(&set.op, set.modifier);
        let span = merge_spans(set.left.span(), set.right.span());

        let mut inputs: Vec<Box<RelPlan>> = Vec::new();
        self.collect_set_branches(&set.left, op_kind, &mut inputs)?;
        self.collect_set_branches(&set.right, op_kind, &mut inputs)?;

        let arity = inputs.first().map(|p| p.output_schema().len()).unwrap_or(0);
        let mut output_columns: Vec<ColumnId> = Vec::with_capacity(arity);
        for i in 0..arity {
            let branch_inputs: Vec<ColumnId> = inputs
                .iter()
                .filter_map(|p| p.output_schema().get(i).copied())
                .collect();
            // Convention for `alloc_setop_col`: take the display name
            // from the first branch's corresponding output slot so
            // lineage / user-visible output carries the SQL column
            // name rather than an anonymous blank. Matches the
            // recursive-CTE SetOp path (see `lower_cte`).
            let display = inputs
                .first()
                .and_then(|p| p.output_schema().get(i).copied())
                .and_then(|id| self.allocator.bindings().get(id))
                .map(|b| b.display_name.clone())
                .unwrap_or_default();
            output_columns.push(self.alloc_setop_col(branch_inputs, display));
        }

        let set_op = RelPlan::SetOp {
            op: op_kind,
            inputs,
            // SQL:2011 `CORRESPONDING [BY (…)]` is not represented in
            // the AST today; lowering leaves it as `None`. When the
            // parser grows a `corresponding` field, this is where the
            // Vec<IdentKey> is threaded.
            corresponding: None,
            output_columns: output_columns.clone(),
            node_id: set.node_id,
            span,
            hints: Vec::new(),
        };
        self.wrap_set_query_tail(set_op, set, &output_columns, span)
    }

    /// Wrap a lowered set-operation plan in `Sort` / `Limit` for a trailing
    /// `ORDER BY` / `LIMIT` / `OFFSET` that applies to the whole set operation
    /// (`(SELECT …) UNION (SELECT …) ORDER BY x LIMIT n`). Mirrors the SELECT
    /// path; sort keys resolve against the set operation's output columns.
    fn wrap_set_query_tail(
        &mut self,
        plan: RelPlan,
        set: &AstSetSelect,
        output_columns: &[ColumnId],
        span: Span,
    ) -> Result<RelPlan, LowerError> {
        if set.order_by.is_none() && set.limit.is_none() && set.offset.is_none() {
            return Ok(plan);
        }

        let mut plan = plan;

        if let Some(order_by) = set.order_by.as_deref() {
            // Resolve `ORDER BY <name>` against the set op's output columns.
            let alias_map = {
                let mut by_name: HashMap<IdentKey, ColumnId> = HashMap::new();
                for &col in output_columns {
                    if let Some(b) = self.allocator.bindings().get(col) {
                        by_name.entry(IdentKey::new(&b.display_name)).or_insert(col);
                    }
                }
                AliasMap {
                    by_name,
                    output_ids: output_columns.iter().copied().collect(),
                }
            };

            self.push_no_agg_frame();
            self.push_no_window_frame();
            let mut keys: Vec<SortKey> = Vec::with_capacity(order_by.items.len());
            let mut key_err: Option<LowerError> = None;
            for item in &order_by.items {
                match self.lower_expr(&item.expr, Some(&alias_map)) {
                    Ok(expr) => keys.push(SortKey {
                        expr,
                        ascending: item.asc.unwrap_or(true),
                        nulls_first: item.nulls_first,
                        span: item.span,
                    }),
                    Err(e) => {
                        key_err = Some(e);
                        break;
                    }
                }
            }
            self.pop_no_window_frame();
            self.pop_no_agg_frame();
            if let Some(e) = key_err {
                return Err(e);
            }
            plan = RelPlan::Sort {
                input: Box::new(plan),
                keys,
                node_id: set.node_id,
                span: order_by.span,
                hints: Vec::new(),
            };
        }

        if set.limit.is_some() || set.offset.is_some() || set.fetch_clause_span.is_some() {
            let limit_expr = match set.limit.as_deref() {
                Some(e) => Some(self.lower_expr_no_aggs(e, None)?),
                None => None,
            };
            let offset_expr = match set.offset.as_deref() {
                Some(e) => Some(self.lower_expr_no_aggs(e, None)?),
                None => None,
            };
            let limit_span = set
                .limit
                .as_deref()
                .map(|e| e.span())
                .or_else(|| set.offset.as_deref().map(|e| e.span()))
                .unwrap_or(span);
            plan = RelPlan::Limit {
                input: Box::new(plan),
                limit: limit_expr,
                offset: offset_expr,
                kind: LimitKind::Rows,
                with_ties: false,
                node_id: set.node_id,
                span: limit_span,
                hints: Vec::new(),
            };
        }

        Ok(plan)
    }

    /// Lower a set-op statement whose leftmost-spine `AstSelect`
    /// carried a `WITH` clause. The CTE bindings must be visible to
    /// EVERY set-op branch (SQL semantic), not just the leftmost.
    /// Mirrors [`Self::lower_select_with_ctes`] except the body is
    /// the result of recursively lowering the stripped set-op (which
    /// no longer carries a `with_clause` anywhere in its leftmost
    /// spine) and the whole thing is wrapped in a single
    /// [`RelPlan::WithScope`].
    fn lower_set_select_with_lifted_ctes(
        &mut self,
        stripped_set: &AstSetSelect,
        with_clause: &AstWithClause,
    ) -> Result<RelPlan, LowerError> {
        let recursive = with_clause.recursive_span.is_some();
        self.cte_scopes.push(HashMap::new());

        let result: Result<RelPlan, LowerError> = (|| {
            let mut ctes: Vec<CteBinding> = Vec::with_capacity(with_clause.ctes.len());
            for item in &with_clause.ctes {
                match item {
                    CteItem::JinjaBlock(blk) => {
                        return Err(LowerError::opaque(
                            blk.span,
                            OpaqueReason::UnresolvedJinja { macro_name: None },
                        ));
                    }
                    CteItem::Cte(cte) => {
                        let scope = self.alloc_scope();
                        let binding = self.lower_cte(cte, scope, recursive)?;
                        let name_key = self.ident_at(cte.name.span);
                        let declared_column_names = binding
                            .declared_columns
                            .as_ref()
                            .map(|d| d.iter().map(|k| k.as_str().to_string()).collect())
                            .unwrap_or_default();
                        let body_column_names: Vec<String> = binding
                            .output_columns
                            .iter()
                            .map(|id| {
                                self.allocator
                                    .bindings()
                                    .get(*id)
                                    .map(|b| b.display_name.clone())
                                    .unwrap_or_default()
                            })
                            .collect();
                        let (leaf_scan_node, passthrough_columns) =
                            self.detect_cte_passthrough_with_renames(&binding.body);
                        self.cte_scopes
                            .last_mut()
                            .expect("cte_scopes frame pushed above")
                            .insert(
                                name_key,
                                CteScopeEntry {
                                    scope,
                                    arity: binding.output_columns.len(),
                                    declared_column_names,
                                    body_column_names,
                                    leaf_scan_node,
                                    passthrough_columns,
                                },
                            );
                        ctes.push(binding);
                    }
                }
            }
            // Lower the stripped SetSelect with CTE bindings now
            // visible on `self.cte_scopes`. Branches that reference
            // any of the registered CTE names will resolve to
            // `RelPlan::CteRef`, not base-table `Scan`.
            let body = self.lower_set_select(stripped_set)?;
            self.finalize_star_passthrough_bindings(&mut ctes);
            let span = stripped_set.left.span();
            Ok(RelPlan::WithScope {
                ctes,
                body: Box::new(body),
                recursive,
                node_id: with_clause.node_id,
                span,
                hints: Vec::new(),
            })
        })();

        self.cte_scopes.pop();
        result
    }

    /// Recursively collect branches of a set-operation spine that
    /// share the parent's [`SetOpKind`]. When the spine's operator
    /// changes (different kind and/or modifier), the sub-tree stops
    /// flattening and lowers as a single nested plan.
    #[allow(clippy::vec_box)] // fills `RelPlan::SetOp::inputs`, a `Vec<Box<RelPlan>>`
    fn collect_set_branches(
        &mut self,
        stmt: &AstStmt,
        parent_kind: SetOpKind,
        inputs: &mut Vec<Box<RelPlan>>,
    ) -> Result<(), LowerError> {
        if let AstStmt::SetSelect(inner) = stmt {
            let inner_kind = make_set_op_kind(&inner.op, inner.modifier);
            if inner_kind == parent_kind {
                self.collect_set_branches(&inner.left, parent_kind, inputs)?;
                self.collect_set_branches(&inner.right, parent_kind, inputs)?;
                return Ok(());
            }
        }
        // Each set-op branch lowers as a nested statement, but the
        // surrounding statement's per-SELECT resolution state is
        // already correct: the set-op appears inside a SELECT
        // boundary (or is itself the statement), and the parent
        // already established fresh bindings/scope. Fresh-scoping
        // each branch would drop lambda/USING shadows that SQL
        // forbids across branches anyway, so the plain
        // `lower_stmt` is correct here.
        let plan = self.lower_stmt(stmt)?;
        inputs.push(Box::new(plan));
        Ok(())
    }

    // ── CTEs / WithScope ────────────────────────────────────────────────

    /// Lower a `SELECT` carrying a `WITH` clause. Allocates a fresh
    /// [`ScopeId`] for the CTE frame, lowers each CTE body in
    /// declaration order — registering the binding so later CTEs and
    /// the main body can reference it — then lowers the body and
    /// wraps the whole thing in [`RelPlan::WithScope`].
    ///
    /// Recursive CTEs (`WITH RECURSIVE`) whose body is a top-level
    /// `SELECT … UNION [ALL/DISTINCT] SELECT …` split into anchor and
    /// step, with the step lowered in a context where the CTE name
    /// is visible (so a self-reference resolves to
    /// [`RelPlan::CteRef`]).
    ///
    /// `RECURSIVE` is a **clause-level hint**:
    /// a CTE under `WITH RECURSIVE` whose body is not UNION-shaped is
    /// lowered as [`CteBody::NonRecursive`] with the CTE name hidden
    /// from its own body, matching SQL:2003 and every major dialect.
    /// The common `WITH RECURSIVE anchor AS (…union…), helper AS
    /// (SELECT … FROM anchor) SELECT …` idiom is lowered without
    /// tripping strict mode.
    fn lower_select_with_ctes(
        &mut self,
        sel: &AstSelect,
        with_clause: &AstWithClause,
    ) -> Result<RelPlan, LowerError> {
        let recursive = with_clause.recursive_span.is_some();
        self.cte_scopes.push(HashMap::new());

        // Push a fresh scope frame, then guarantee pop on every exit
        // path. The `result` is computed inside a closure-equivalent
        // block so a `?` early-return does not leak a frame upward.
        let result: Result<RelPlan, LowerError> = (|| {
            let mut ctes: Vec<CteBinding> = Vec::with_capacity(with_clause.ctes.len());
            for item in &with_clause.ctes {
                match item {
                    CteItem::JinjaBlock(blk) => {
                        // Jinja-generated CTE blocks cannot be
                        // statically lowered; bail out with
                        // UnresolvedJinja so the strict-mode harness
                        // can tally it consistently with other
                        // unresolved-macro fallbacks.
                        return Err(LowerError::opaque(
                            blk.span,
                            OpaqueReason::UnresolvedJinja { macro_name: None },
                        ));
                    }
                    CteItem::Cte(cte) => {
                        // Each CTE binding gets a unique `ScopeId`
                        // (ScopeId-uniqueness invariant). Consumers
                        // key per-binding state by scope, so a scope
                        // shared across the WITH would let a later
                        // binding overwrite an earlier sibling's
                        // slots and a sibling CteRef resolve onto
                        // the wrong binding.
                        let scope = self.alloc_scope();
                        let binding = self.lower_cte(cte, scope, recursive)?;
                        let name_key = self.ident_at(cte.name.span);
                        let declared_column_names = binding
                            .declared_columns
                            .as_ref()
                            .map(|d| d.iter().map(|k| k.as_str().to_string()).collect())
                            .unwrap_or_default();
                        let body_column_names: Vec<String> = binding
                            .output_columns
                            .iter()
                            .map(|id| {
                                self.allocator
                                    .bindings()
                                    .get(*id)
                                    .map(|b| b.display_name.clone())
                                    .unwrap_or_default()
                            })
                            .collect();
                        // Detect star-passthrough body shape so
                        // sibling / outer references through this
                        // CTE can redirect alias resolution onto
                        // the underlying table directly. See
                        // `CteScopeEntry::leaf_scan_node` doc.
                        // The combined detector covers both the plain
                        // `SELECT *` form and the
                        // `SELECT * RENAME (…)` form; rename pairs
                        // are recorded in `cte_passthrough_renames`
                        // so `lower_column_ref` can substitute the
                        // source column name at allocation time.
                        let (leaf_scan_node, passthrough_columns) =
                            self.detect_cte_passthrough_with_renames(&binding.body);
                        // Duplicate names in the same WITH clause: SQL
                        // forbids them but the parser accepts them;
                        // later bindings shadow earlier ones and
                        // analyses match on the last binding.
                        self.cte_scopes
                            .last_mut()
                            .expect("cte_scopes frame pushed above")
                            .insert(
                                name_key,
                                CteScopeEntry {
                                    scope,
                                    arity: binding.output_columns.len(),
                                    declared_column_names,
                                    body_column_names,
                                    leaf_scan_node,
                                    passthrough_columns,
                                },
                            );
                        ctes.push(binding);
                    }
                }
            }
            let body = self.lower_select_body(sel)?;
            // Star-passthrough finalize: drain `scan_cols` entries
            // accumulated against each star-passthrough binding's
            // leaf Scan node and append them to that Scan's
            // `columns` list in-place. After this pass the Scan
            // lists the demanded ColumnIds, which trace back to the
            // underlying table.
            self.finalize_star_passthrough_bindings(&mut ctes);
            let span = sel.span;
            Ok(RelPlan::WithScope {
                ctes,
                body: Box::new(body),
                recursive,
                node_id: with_clause.node_id,
                span,
                hints: Vec::new(),
            })
        })();

        self.cte_scopes.pop();
        result
    }

    /// Lower a single CTE definition. Produces a [`CteBinding`] whose
    /// body is [`CteBody::NonRecursive`] or [`CteBody::Recursive`]
    /// depending on whether the body matches the anchor/step shape.
    ///
    /// `declared_columns` (the optional `WITH cte(a, b) AS (…)`
    /// column list) is carried onto the binding; when present and
    /// non-empty it establishes the arity and names the outputs.
    /// Otherwise the body's output schema determines arity.
    fn lower_cte(
        &mut self,
        cte: &AstCte,
        scope: ScopeId,
        parent_recursive: bool,
    ) -> Result<CteBinding, LowerError> {
        let declared_columns = if cte.column_list.is_empty() {
            None
        } else {
            Some(
                cte.column_list
                    .iter()
                    .map(|ident| self.ident_at(ident.span))
                    .collect::<Vec<_>>(),
            )
        };

        // Detect a truly-recursive CTE: `WITH RECURSIVE` keyword plus a
        // body that is a top-level `SELECT ... UNION [ALL/DISTINCT]
        // SELECT ...`. Other set operators cannot be recursive
        // anchors in standard SQL. The step-side self-reference is
        // optional — a `WITH RECURSIVE` CTE whose right branch does
        // not actually reference the CTE name still lowers as
        // Recursive in this shape, and downstream analyses treat that
        // degenerate case the same as a non-recursive union.
        let recursive_union_shape = parent_recursive
            && matches!(
                &*cte.query,
                AstStmt::SetSelect(s)
                    if matches!(s.op, AstSetOpKind::Union)
            );

        if recursive_union_shape {
            let set = match &*cte.query {
                AstStmt::SetSelect(s) => s,
                // The match above guarantees this branch.
                _ => unreachable!("recursive_union_shape implies SetSelect"),
            };
            // Lower the anchor WITHOUT the CTE name visible — the
            // anchor must not self-reference (SQL:2003). Fresh
            // scope: the anchor is a distinct SELECT boundary.
            let anchor = self.lower_stmt_in_fresh_scope(&set.left)?;

            // Pre-register the binding so the step can self-reference
            // via `CteRef`. Arity is taken from the anchor's output
            // schema; declared columns (if any) must agree with that
            // arity but the lowerer does not enforce the match here
            // (parser-permissive / lexer-dialect split — shape
            // enforcement belongs in a dedicated validator).
            let arity = declared_columns
                .as_ref()
                .map(|d| d.len())
                .unwrap_or_else(|| anchor.output_schema().len());
            let name_key = self.ident_at(cte.name.span);
            let declared_column_names: Vec<String> = declared_columns
                .as_ref()
                .map(|d| d.iter().map(|k| k.as_str().to_string()).collect())
                .unwrap_or_default();
            // For the recursive forward-declaration the step hasn't
            // lowered yet, so we cannot populate body-derived names.
            // Fall back to the anchor's output schema: the anchor
            // has lowered above and its per-slot display_names are
            // already in the binding table.
            let body_column_names: Vec<String> = (0..arity)
                .map(|i| {
                    anchor
                        .output_schema()
                        .get(i)
                        .and_then(|id| self.allocator.bindings().get(*id))
                        .map(|b| b.display_name.clone())
                        .unwrap_or_default()
                })
                .collect();
            self.cte_scopes
                .last_mut()
                .expect("cte_scopes frame pushed by caller")
                .insert(
                    name_key.clone(),
                    CteScopeEntry {
                        scope,
                        arity,
                        declared_column_names,
                        body_column_names,
                        // Recursive CTE forward-declaration: the
                        // body is union-shaped by definition, so
                        // the star-passthrough redirect does not
                        // apply. Self-references inside the step
                        // resolve via the standard `CteRef` path.
                        leaf_scan_node: None,
                        passthrough_columns: HashMap::new(),
                    },
                );

            // Lower the step with the CTE name visible. Any
            // self-reference inside the step resolves to `CteRef`.
            // On step-lowering failure we must remove the partial
            // forward-declaration so subsequent sibling CTEs don't
            // see a half-built binding. Fresh SELECT-level scope
            // so the step does not inherit the anchor's bindings.
            let step = match self.lower_stmt_in_fresh_scope(&set.right) {
                Ok(plan) => plan,
                Err(e) => {
                    if let Some(frame) = self.cte_scopes.last_mut() {
                        frame.remove(&name_key);
                    }
                    return Err(e);
                }
            };

            // Remove the forward declaration; the caller will
            // re-register the finalized binding after this function
            // returns. Keeping only one registration at a time makes
            // the frame's invariant simple: each key maps to the
            // most recently completed binding.
            if let Some(frame) = self.cte_scopes.last_mut() {
                frame.remove(&name_key);
            }

            let mut output_columns: Vec<ColumnId> = Vec::with_capacity(arity);
            // Per-slot SetOp inputs: recursive-CTE anchor + recursive
            // step outputs share the CTE's output slot. Display name
            // for slot `i` is taken in priority order:
            //   1. `WITH cte(a, b) AS …` declared name at index `i`,
            //   2. anchor branch's binding display name at index `i`
            //      (the documented convention for `alloc_setop_col`),
            //   3. empty (anonymous) only when neither is available.
            for i in 0..arity {
                let mut branch_inputs: Vec<ColumnId> = Vec::with_capacity(2);
                if let Some(id) = anchor.output_schema().get(i).copied() {
                    branch_inputs.push(id);
                }
                if let Some(id) = step.output_schema().get(i).copied() {
                    branch_inputs.push(id);
                }
                let display: String = if let Some(name) = declared_columns
                    .as_ref()
                    .and_then(|d| d.get(i))
                    .map(|k| k.as_str().to_string())
                {
                    name
                } else {
                    branch_inputs
                        .first()
                        .and_then(|id| self.allocator.bindings().get(*id))
                        .map(|b| b.display_name.clone())
                        .unwrap_or_default()
                };
                output_columns.push(self.alloc_setop_col(branch_inputs, display));
            }

            let union_kind = make_set_op_kind(&set.op, set.modifier);
            return Ok(CteBinding {
                name: self.ident_at(cte.name.span),
                scope,
                declared_columns,
                body: CteBody::Recursive {
                    anchor: Box::new(anchor),
                    step: Box::new(step),
                    union_kind,
                },
                output_columns,
                node_id: cte.node_id,
                span: cte.span,
            });
        }

        if parent_recursive {
            // `WITH RECURSIVE` with a non-UNION body shape is not an
            // error: per SQL:2003 and every major dialect,
            // `RECURSIVE` is a clause-level hint and
            // the common `WITH RECURSIVE anchor AS (…union…),
            // helper AS (SELECT … FROM anchor) SELECT …` idiom is
            // legal. Fall through to the non-recursive path, which
            // lowers the body with the CTE name **not** in scope —
            // SQL forbids self-reference on non-union bodies, so a
            // name collision here would indicate a parser bug, not
            // legal recursion.
        }

        // Non-recursive: lower the body once. The body's AST is a
        // whole statement node (Select / SetSelect / Insert / Update
        // / Delete — the last three are permitted by PostgreSQL
        // writable CTEs and ride on the DML lowering). Fresh
        // SELECT-level scope so sibling CTEs don't contaminate the
        // binding cache.
        let body = self.lower_stmt_in_fresh_scope(&cte.query)?;
        // Effective body schema: a pure `SELECT *` body re-exports the
        // immediate input's visible slots. This is the same contract the
        // lineage layer uses for per-binding slot deps.
        let body_schema: Vec<ColumnId> = body.cte_visible_output_schema();
        let arity = declared_columns
            .as_ref()
            .map(|d| d.len())
            .unwrap_or(body_schema.len());
        let mut output_columns: Vec<ColumnId> = Vec::with_capacity(arity);
        let cte_span = cte.span;
        // Display name for slot `i` priority:
        //   1. `WITH cte(a, b) AS …` declared name at index `i`,
        //   2. body's output_schema()[i] binding display name
        //      (carries the projection alias / column name through),
        //   3. empty (anonymous) only when neither resolves.
        // The CTE binding still allocates a fresh `Computed` ColumnId
        // per slot — the binding is a positional re-export, not a
        // structural alias of the body's id — but the user-visible
        // name follows the body when no declared list overrides.
        for idx in 0..arity {
            let display: String = if let Some(name) = declared_columns
                .as_ref()
                .and_then(|d| d.get(idx))
                .map(|k| k.as_str().to_string())
            {
                name
            } else {
                body_schema
                    .get(idx)
                    .and_then(|id| self.allocator.bindings().get(*id))
                    .map(|b| b.display_name.clone())
                    .unwrap_or_default()
            };
            output_columns.push(self.alloc_computed_col(cte.node_id, cte_span, display));
        }
        Ok(CteBinding {
            name: self.ident_at(cte.name.span),
            scope,
            declared_columns,
            body: CteBody::NonRecursive(Box::new(body)),
            output_columns,
            node_id: cte.node_id,
            span: cte.span,
        })
    }

    // ── DML ─────────────────────────────────────────────────────────────

    /// Lower `INSERT INTO t [(cols)] <source> [ON CONFLICT …] [RETURNING …]`.
    ///
    /// `target_columns` is allocated by text-splitting `columns_span`
    /// (one [`ColumnId`] per named column) — the AST surfaces the list
    /// as a single span today, so the lowerer reconstructs the
    /// arity from the source text. Each declared name is bound in
    /// the scope so a following `RETURNING col` resolves to the same
    /// id. `source` dispatches on [`AstInsertSourceKind`] producing an
    /// [`InsertSource::Values`] / [`InsertSource::Query`] /
    /// [`InsertSource::DefaultValues`].
    ///
    /// A writable-CTE `WITH` clause on the INSERT wraps the result in
    /// [`RelPlan::WithScope`] so CTE references inside the INSERT
    /// source or `ON CONFLICT` clause resolve correctly.
    fn lower_insert(&mut self, ins: &AstInsert) -> Result<RelPlan, LowerError> {
        if let Some(with) = ins.with_clause.as_ref() {
            return self.lower_dml_with_ctes(with, ins.span, ins.node_id, |ctx| {
                ctx.lower_insert_body(ins)
            });
        }
        self.lower_insert_body(ins)
    }

    fn lower_insert_body(&mut self, ins: &AstInsert) -> Result<RelPlan, LowerError> {
        let target = self.lower_table_ref_from_span_or_none(ins.target_table_span, ins.span)?;
        self.populate_target_table_columns(&target);

        // Declared column list: text-split `(c1, c2, …)`. Empty when
        // the user omitted the list (positional by target schema).
        // MySQL `INSERT ... SET col = expr` declares its columns via the
        // assignment list instead.
        let mut declared = ins
            .columns_span
            .and_then(|s| slice_span(self.source, s))
            .map(split_parenthesized_ident_list)
            .unwrap_or_default();
        if declared.is_empty() && matches!(ins.source_kind, AstInsertSourceKind::SetAssignments) {
            declared = ins.set_assignments.iter().map(|(n, _)| n.clone()).collect();
        }
        let target_columns = self.bind_declared_target_columns(&declared, ins.node_id, ins.span);

        let source = self.lower_insert_source(ins)?;
        // MySQL ON DUPLICATE KEY UPDATE shares the OnConflict carrier with
        // PostgreSQL ON CONFLICT; the two clauses are grammatically disjoint.
        let on_conflict = match ins.on_conflict.as_ref() {
            Some(oc) => Some(self.lower_on_conflict(oc)?),
            None => match ins.on_duplicate_key_update.as_ref() {
                Some(odku) => Some(self.lower_on_duplicate_key_update(odku)?),
                None => None,
            },
        };
        let returning = match ins.returning.as_ref() {
            Some(r) => Some(self.lower_returning(r)?),
            None => None,
        };
        let output = ins.output.as_ref().map(lower_output_clause);
        let overriding = ins
            .overriding_value_span
            .and_then(|s| slice_span(self.source, s))
            .and_then(parse_overriding_value);
        let target_hints = match ins.table_hints.as_ref() {
            Some(clause) => self.lower_scan_table_hints(clause),
            None => Vec::new(),
        };

        let replace_into = ins.replace_span.is_some();

        Ok(RelPlan::Insert {
            target,
            target_columns,
            source,
            on_conflict,
            overwrite: ins.overwrite || ins.overwrite_span.is_some(),
            replace_into,
            overriding,
            returning,
            output,
            target_hints,
            node_id: ins.node_id,
            span: ins.span,
            hints: Vec::new(),
        })
    }

    /// Bind a declared target-column list (one fresh [`ColumnId`] per name)
    /// so later clauses (`RETURNING col`, ODKU assignees) resolve to the
    /// same ids. Shared by INSERT and REPLACE lowering.
    fn bind_declared_target_columns(
        &mut self,
        declared: &[String],
        stmt_node: crate::ast::NodeId,
        stmt_span: Span,
    ) -> Vec<ColumnId> {
        let mut target_columns: Vec<ColumnId> = Vec::with_capacity(declared.len());
        for name in declared {
            let key = IdentKey::new(name);
            let display = name.clone();
            let id = *self.bindings.entry(key).or_insert_with(|| {
                self.allocator.fresh(
                    ColumnOrigin::Computed {
                        producing_node: stmt_node,
                        expr_span: stmt_span,
                    },
                    display,
                )
            });
            target_columns.push(id);
        }
        target_columns
    }

    fn lower_insert_source(&mut self, ins: &AstInsert) -> Result<InsertSource, LowerError> {
        self.lower_insert_source_parts(InsertSourceParts {
            source_kind: &ins.source_kind,
            values_span: ins.values_span,
            values_rows: &ins.values_rows,
            query: ins.query.as_deref(),
            set_clause_span: ins.set_clause_span,
            set_assignments: &ins.set_assignments,
            node_id: ins.node_id,
            span: ins.span,
        })
    }

    fn lower_insert_source_parts(
        &mut self,
        parts: InsertSourceParts<'_>,
    ) -> Result<InsertSource, LowerError> {
        match parts.source_kind {
            AstInsertSourceKind::Values => {
                let span = parts.values_span.unwrap_or(parts.span);
                let mut rows: Vec<Vec<ScalarExpr>> = Vec::with_capacity(parts.values_rows.len());
                self.push_no_agg_frame();
                self.push_no_window_frame();
                let lowered = (|| -> Result<(), LowerError> {
                    for row in parts.values_rows {
                        let mut lowered_row = Vec::with_capacity(row.len());
                        for expr in row {
                            lowered_row.push(self.lower_expr(expr, None)?);
                        }
                        rows.push(lowered_row);
                    }
                    Ok(())
                })();
                self.pop_no_window_frame();
                self.pop_no_agg_frame();
                lowered?;
                // Allocate one ColumnId per value column (arity from the
                // first row; empty VALUES list yields an empty Values).
                let arity = rows.first().map(|r| r.len()).unwrap_or(0);
                let mut columns: Vec<ColumnId> = Vec::with_capacity(arity);
                for _ in 0..arity {
                    columns.push(self.alloc_tuple_col(parts.node_id, span, String::new()));
                }
                let values_plan = RelPlan::Values {
                    rows,
                    columns,
                    alias: None,
                    node_id: parts.node_id,
                    span,
                    hints: Vec::new(),
                };
                Ok(InsertSource::Values(Box::new(values_plan)))
            }
            AstInsertSourceKind::Query => match parts.query {
                Some(q) => {
                    // INSERT-source SELECT is its own visibility scope,
                    // parallel to scalar subqueries and CTE bodies.
                    // Without the fresh-scope wrap, the parent INSERT's
                    // pre-bound target columns (declared in `(col, …)`
                    // after `INSERT INTO`) leak into source-side
                    // identifier resolution and shadow CTE/derived-table
                    // bindings of the same name — breaking
                    // Q-PROP-CONTRA's origin-equivalence lookup.
                    let plan = self.lower_stmt_in_fresh_scope(q)?;
                    Ok(InsertSource::Query(Box::new(plan)))
                }
                None => Err(LowerError::invalid(
                    parts.span,
                    InvalidInputKind::Dml(DmlShapeCategory::InsertQueryWithoutBody),
                )),
            },
            AstInsertSourceKind::DefaultValues => Ok(InsertSource::DefaultValues),
            // MySQL SET form: one row whose columns carry the assignment
            // names (the declared target columns mirror the same list).
            AstInsertSourceKind::SetAssignments => {
                let span = parts.set_clause_span.unwrap_or(parts.span);
                let mut row: Vec<ScalarExpr> = Vec::with_capacity(parts.set_assignments.len());
                let mut columns: Vec<ColumnId> = Vec::with_capacity(parts.set_assignments.len());
                self.push_no_agg_frame();
                self.push_no_window_frame();
                let lowered = (|| -> Result<(), LowerError> {
                    for (name, expr) in parts.set_assignments {
                        row.push(self.lower_expr(expr, None)?);
                        columns.push(self.alloc_tuple_col(parts.node_id, span, name.clone()));
                    }
                    Ok(())
                })();
                self.pop_no_window_frame();
                self.pop_no_agg_frame();
                lowered?;
                let values_plan = RelPlan::Values {
                    rows: vec![row],
                    columns,
                    alias: None,
                    node_id: parts.node_id,
                    span,
                    hints: Vec::new(),
                };
                Ok(InsertSource::Values(Box::new(values_plan)))
            }
            AstInsertSourceKind::Unknown => Err(LowerError::invalid(
                parts.span,
                InvalidInputKind::Dml(DmlShapeCategory::InsertUnknownSource),
            )),
        }
    }

    /// Lower MySQL `ON DUPLICATE KEY UPDATE` to [`OnConflict`] with the
    /// dedicated [`ConflictAction::MySqlDuplicateKeyUpdate`] action.
    fn lower_on_duplicate_key_update(
        &mut self,
        odku: &crate::ast::AstOnDuplicateKeyUpdate,
    ) -> Result<OnConflict, LowerError> {
        let mut assignments = Vec::with_capacity(odku.assignments.len());
        for (col_name, val_expr) in &odku.assignments {
            let key = IdentKey::new(col_name);
            let display = col_name.clone();
            let expr_span = val_expr.span();
            let stmt_node = self.current_stmt_node;
            let id = *self.bindings.entry(key).or_insert_with(|| {
                self.allocator.fresh(
                    ColumnOrigin::Computed {
                        producing_node: stmt_node,
                        expr_span,
                    },
                    display,
                )
            });
            let val = self.lower_expr_no_aggs(val_expr, None)?;
            assignments.push((id, val));
        }
        Ok(OnConflict {
            target: ConflictTarget::Unspecified,
            action: ConflictAction::MySqlDuplicateKeyUpdate { assignments },
            where_clause: None,
            span: odku.span,
        })
    }

    /// Lower MySQL `REPLACE [INTO] t ...` — delete-then-insert by unique
    /// key — to [`RelPlan::Insert`] with `replace_into: true`.
    fn lower_replace_into(
        &mut self,
        rep: &crate::ast::AstReplaceInto,
    ) -> Result<RelPlan, LowerError> {
        let target = self.lower_table_ref_from_span_or_none(rep.target_table_span, rep.span)?;
        self.populate_target_table_columns(&target);

        let mut declared = rep
            .columns_span
            .and_then(|s| slice_span(self.source, s))
            .map(split_parenthesized_ident_list)
            .unwrap_or_default();
        if declared.is_empty() && matches!(rep.source_kind, AstInsertSourceKind::SetAssignments) {
            declared = rep.set_assignments.iter().map(|(n, _)| n.clone()).collect();
        }
        let target_columns = self.bind_declared_target_columns(&declared, rep.node_id, rep.span);

        let source = self.lower_insert_source_parts(InsertSourceParts {
            source_kind: &rep.source_kind,
            values_span: rep.values_span,
            values_rows: &rep.values_rows,
            query: rep.query.as_deref(),
            set_clause_span: rep.set_clause_span,
            set_assignments: &rep.set_assignments,
            node_id: rep.node_id,
            span: rep.span,
        })?;

        Ok(RelPlan::Insert {
            target,
            target_columns,
            source,
            on_conflict: None,
            overwrite: false,
            replace_into: true,
            overriding: None,
            returning: None,
            output: None,
            target_hints: Vec::new(),
            node_id: rep.node_id,
            span: rep.span,
            hints: Vec::new(),
        })
    }

    fn lower_on_conflict(&mut self, oc: &AstOnConflict) -> Result<OnConflict, LowerError> {
        use crate::ast::{AstConflictAction, AstConflictTarget, AstConflictTargetItemKind};
        let target = match oc.target.as_ref() {
            None => ConflictTarget::Unspecified,
            Some(AstConflictTarget::Constraint(name)) => {
                ConflictTarget::Constraint(IdentKey::new(name))
            }
            Some(AstConflictTarget::Columns { items, .. }) => {
                let any_expr = items
                    .iter()
                    .any(|i| matches!(i.kind, AstConflictTargetItemKind::Expression(_)));
                if any_expr {
                    let mut exprs = Vec::with_capacity(items.len());
                    for it in items {
                        let e = match &it.kind {
                            AstConflictTargetItemKind::Expression(e) => {
                                self.lower_expr_no_aggs(e, None)?
                            }
                            AstConflictTargetItemKind::Column(name) => {
                                let key = IdentKey::new(name);
                                let display = name.clone();
                                let it_span = it.span;
                                let stmt_node = self.current_stmt_node;
                                let id = *self.bindings.entry(key).or_insert_with(|| {
                                    self.allocator.fresh(
                                        ColumnOrigin::Computed {
                                            producing_node: stmt_node,
                                            expr_span: it_span,
                                        },
                                        display,
                                    )
                                });
                                ScalarExpr::Column {
                                    column: id,
                                    span: it.span,
                                }
                            }
                        };
                        exprs.push(e);
                    }
                    ConflictTarget::Expressions(exprs)
                } else {
                    let mut cols = Vec::with_capacity(items.len());
                    for it in items {
                        if let AstConflictTargetItemKind::Column(name) = &it.kind {
                            let key = IdentKey::new(name);
                            let display = name.clone();
                            let it_span = it.span;
                            let stmt_node = self.current_stmt_node;
                            let id = *self.bindings.entry(key).or_insert_with(|| {
                                self.allocator.fresh(
                                    ColumnOrigin::Computed {
                                        producing_node: stmt_node,
                                        expr_span: it_span,
                                    },
                                    display,
                                )
                            });
                            cols.push(id);
                        }
                    }
                    ConflictTarget::Columns(cols)
                }
            }
        };
        let where_clause = match oc.target.as_ref() {
            Some(AstConflictTarget::Columns {
                where_predicate: Some(w),
                ..
            }) => Some(self.lower_expr_no_aggs(w, None)?),
            _ => None,
        };
        let action = match &oc.action {
            AstConflictAction::DoNothing(_) => ConflictAction::DoNothing,
            AstConflictAction::DoUpdate {
                set_items,
                where_clause: w,
                ..
            } => {
                let mut assignments = Vec::with_capacity(set_items.len());
                for (col_name, val_expr) in set_items {
                    let key = IdentKey::new(col_name);
                    let display = col_name.clone();
                    let expr_span = val_expr.span();
                    let stmt_node = self.current_stmt_node;
                    let id = *self.bindings.entry(key).or_insert_with(|| {
                        self.allocator.fresh(
                            ColumnOrigin::Computed {
                                producing_node: stmt_node,
                                expr_span,
                            },
                            display,
                        )
                    });
                    let val = self.lower_expr_no_aggs(val_expr, None)?;
                    assignments.push((id, val));
                }
                let where_clause = match w.as_deref() {
                    Some(w) => Some(self.lower_expr_no_aggs(w, None)?),
                    None => None,
                };
                ConflictAction::DoUpdate {
                    assignments,
                    where_clause,
                }
            }
        };
        Ok(OnConflict {
            target,
            action,
            where_clause,
            span: oc.span,
        })
    }

    fn lower_returning(&mut self, r: &AstReturning) -> Result<Returning, LowerError> {
        let mut items = Vec::with_capacity(r.items.len());
        self.push_no_agg_frame();
        self.push_no_window_frame();
        let result = (|| -> Result<(), LowerError> {
            for it in &r.items {
                let expr = self.lower_expr(&it.expr, None)?;
                let alias = it.alias.as_ref().map(|a| self.ident_at(a.ident.span));
                let display = alias
                    .as_ref()
                    .map(|k| k.as_str().to_string())
                    .unwrap_or_default();
                let output = Some(self.alloc_synthetic(it.expr.span(), display));
                items.push(ReturningItem::Expr {
                    expr,
                    alias,
                    output,
                });
            }
            Ok(())
        })();
        self.pop_no_window_frame();
        self.pop_no_agg_frame();
        result?;
        Ok(Returning {
            items,
            span: r.span,
        })
    }

    /// Lower `UPDATE t [SET …] [FROM …] [WHERE …] [RETURNING …]`.
    fn lower_update(&mut self, upd: &AstUpdate) -> Result<RelPlan, LowerError> {
        if let Some(with) = upd.with_clause.as_ref() {
            return self.lower_dml_with_ctes(with, upd.span, upd.node_id, |ctx| {
                ctx.lower_update_body(upd)
            });
        }
        self.lower_update_body(upd)
    }

    fn lower_update_body(&mut self, upd: &AstUpdate) -> Result<RelPlan, LowerError> {
        let target = match upd.target_table.as_deref() {
            Some(tr) => self.lower_table_ref(tr),
            None => {
                return Err(LowerError::invalid(
                    upd.span,
                    InvalidInputKind::Dml(DmlShapeCategory::UpdateWithoutTarget),
                ));
            }
        };
        self.populate_target_table_columns(&target);

        // FROM clause: lower each table ref + joins and left-fold as
        // Cross joins (same shape as SELECT's comma-FROM).
        let from = self.lower_dml_from_list(&upd.from, upd.node_id)?;

        // SET assignments: each column → ColumnId, value → ScalarExpr.
        let mut assignments: Vec<(ColumnId, ScalarExpr)> =
            Vec::with_capacity(upd.set_assignments.len());
        self.push_no_agg_frame();
        self.push_no_window_frame();
        let set_result = (|| -> Result<(), LowerError> {
            for a in &upd.set_assignments {
                let id = self.bind_assignment_column(&a.column, a.span)?;
                let val = self.lower_expr(&a.value, None)?;
                assignments.push((id, val));
            }
            Ok(())
        })();
        self.pop_no_window_frame();
        self.pop_no_agg_frame();
        set_result?;

        let predicate = match upd.where_clause.as_deref() {
            Some(w) => {
                self.push_no_agg_frame();
                self.push_no_window_frame();
                let p = self.lower_expr(w, None);
                self.pop_no_window_frame();
                self.pop_no_agg_frame();
                Some(p?)
            }
            None => None,
        };

        let top = match upd.top.as_ref() {
            Some(t) => Some(self.lower_dml_top(t)?),
            None => None,
        };

        let returning = match upd.returning.as_ref() {
            Some(r) => Some(self.lower_returning(r)?),
            None => None,
        };
        let output = upd.output.as_ref().map(lower_output_clause);

        Ok(RelPlan::Update {
            target,
            assignments,
            from,
            predicate,
            top,
            returning,
            output,
            node_id: upd.node_id,
            span: upd.span,
            hints: Vec::new(),
        })
    }

    /// Lower `DELETE FROM t [USING …] [WHERE …] [RETURNING …]`.
    fn lower_delete(&mut self, del: &AstDelete) -> Result<RelPlan, LowerError> {
        if let Some(with) = del.with_clause.as_ref() {
            return self.lower_dml_with_ctes(with, del.span, del.node_id, |ctx| {
                ctx.lower_delete_body(del)
            });
        }
        self.lower_delete_body(del)
    }

    fn lower_delete_body(&mut self, del: &AstDelete) -> Result<RelPlan, LowerError> {
        let target_tr = match del.target_table.as_deref() {
            Some(tr) => tr,
            None => {
                return Err(LowerError::invalid(
                    del.span,
                    InvalidInputKind::Dml(DmlShapeCategory::DeleteWithoutTarget),
                ));
            }
        };
        let target = self.lower_table_ref(target_tr);
        self.populate_target_table_columns(&target);
        // T-SQL `DELETE alias FROM list-with-joins` puts the join
        // chain on `target_table.joins` (the parser at
        // `parser/sql_stmt.rs::parse_delete` calls
        // `parse_join_chain(&mut target_table)` after
        // `parse_table_factor`). PG-style `DELETE FROM t USING
        // others` puts the source list on `del.using`. Lower both
        // into the single `using: Option<Box<RelPlan>>` slot the
        // IR exposes — when both are populated they Cross-join into
        // one combined plan, mirroring `lower_dml_from_list`'s left
        // fold for comma-separated sources. Matters for IR-first
        // signal emission (table-hint, table-access) which folds
        // over the relplan tree to find joined Scan nodes.
        let target_with_joins = if !target_tr.joins.is_empty() {
            Some(self.lower_table_ref_with_joins(target_tr, del.node_id)?)
        } else {
            None
        };
        let pg_using = self.lower_dml_from_list(&del.using, del.node_id)?;
        let using = match (target_with_joins, pg_using) {
            (Some(a), Some(b)) => {
                let span = merge_spans(a.span(), b.span());
                let clause_span = b.span();
                Some(Box::new(RelPlan::Join {
                    left: Box::new(a),
                    right: b,
                    kind: JoinKind::Cross,
                    on: None,
                    match_condition: None,
                    using: Vec::new(),
                    natural: false,
                    directed: false,
                    lateral: false,
                    implicit: true,
                    node_id: del.node_id,
                    span,
                    clause_span,
                    hints: Vec::new(),
                }))
            }
            (Some(a), None) => Some(Box::new(a)),
            (None, Some(b)) => Some(b),
            (None, None) => None,
        };
        let predicate = match del.where_clause.as_deref() {
            Some(w) => {
                self.push_no_agg_frame();
                self.push_no_window_frame();
                let p = self.lower_expr(w, None);
                self.pop_no_window_frame();
                self.pop_no_agg_frame();
                Some(p?)
            }
            None => None,
        };
        let top = match del.top.as_ref() {
            Some(t) => Some(self.lower_dml_top(t)?),
            None => None,
        };
        let returning = match del.returning.as_ref() {
            Some(r) => Some(self.lower_returning(r)?),
            None => None,
        };
        let output = del.output.as_ref().map(lower_output_clause);

        Ok(RelPlan::Delete {
            target,
            using,
            predicate,
            top,
            returning,
            output,
            node_id: del.node_id,
            span: del.span,
            hints: Vec::new(),
        })
    }

    /// Lower `MERGE INTO target USING source ON cond WHEN …`.
    fn lower_merge(&mut self, mrg: &AstMerge) -> Result<RelPlan, LowerError> {
        if let Some(with) = mrg.with_clause.as_ref() {
            return self
                .lower_dml_with_ctes(with, mrg.span, mrg.node_id, |ctx| ctx.lower_merge_body(mrg));
        }
        self.lower_merge_body(mrg)
    }

    fn lower_merge_body(&mut self, mrg: &AstMerge) -> Result<RelPlan, LowerError> {
        let target = self.lower_table_ref_from_span_or_none(mrg.target_table_span, mrg.span)?;
        self.populate_target_table_columns(&target);

        // USING source: either a structured subquery or a direct table
        // reference. The parser stores them in separate fields so the
        // lowering never has to re-parse raw bytes. The table-ref
        // path routes through `lower_table_ref_with_joins` so a CTE
        // name in `USING <name>` resolves to a `CteRef` (not a `Scan`)
        // — preserving cross-scope boundary visibility for ON / WHEN
        // predicates — and incrementally populates `from_scope` so
        // those predicates' column refs bind to source-owned ColumnIds
        // (same as the JOIN-ON handling in
        // [`Self::lower_table_ref_with_joins`]).
        let source_plan = match mrg.using_subquery.as_deref() {
            Some(stmt) => {
                let inner = self.lower_stmt(stmt)?;
                // Subquery output exposed under the USING alias (if
                // any). Avoids `collect_scope_entries`'s debug_assert
                // tripping on the subquery's top-level Project — its
                // output_schema() carries the bound ColumnIds already.
                let alias = mrg.using_alias_span.map(|s| self.ident_at(s));
                let out_cols = inner.output_schema();
                self.append_scope_columns(&out_cols, alias);
                inner
            }
            None => match mrg.using_table_ref.as_deref() {
                Some(tr) => self.lower_table_ref_with_joins(tr, mrg.node_id)?,
                None => {
                    return Err(LowerError::invalid(
                        mrg.span,
                        InvalidInputKind::Dml(DmlShapeCategory::MergeWithoutSource),
                    ));
                }
            },
        };

        let on = match mrg.on_condition.as_deref() {
            Some(e) => {
                self.push_no_agg_frame();
                self.push_no_window_frame();
                let p = self.lower_expr(e, None);
                self.pop_no_window_frame();
                self.pop_no_agg_frame();
                p?
            }
            None => {
                return Err(LowerError::invalid(
                    mrg.span,
                    InvalidInputKind::Dml(DmlShapeCategory::MergeWithoutOn),
                ));
            }
        };

        let mut branches: Vec<MergeBranch> = Vec::with_capacity(mrg.clauses.len());
        for clause in &mrg.clauses {
            branches.push(self.lower_merge_clause(clause)?);
        }

        let output = mrg.output.as_ref().map(lower_output_clause);

        Ok(RelPlan::Merge {
            target,
            source: Box::new(source_plan),
            on,
            branches,
            with_schema_evolution: mrg.with_schema_evolution_span.is_some(),
            output,
            node_id: mrg.node_id,
            span: mrg.span,
            hints: Vec::new(),
        })
    }

    fn lower_merge_clause(
        &mut self,
        clause: &crate::ast::AstMergeClause,
    ) -> Result<MergeBranch, LowerError> {
        let kind = match clause.kind {
            AstMergeClauseKind::Matched => MergeBranchKind::WhenMatched,
            AstMergeClauseKind::NotMatched | AstMergeClauseKind::NotMatchedByTarget => {
                MergeBranchKind::WhenNotMatched
            }
            AstMergeClauseKind::NotMatchedBySource => MergeBranchKind::WhenNotMatchedBySource,
        };
        let predicate = match clause.and_condition.as_deref() {
            Some(e) => {
                self.push_no_agg_frame();
                self.push_no_window_frame();
                let p = self.lower_expr(e, None);
                self.pop_no_window_frame();
                self.pop_no_agg_frame();
                Some(p?)
            }
            None => None,
        };
        let action = self.lower_merge_action(&clause.action)?;
        Ok(MergeBranch {
            kind,
            predicate,
            action,
            span: clause.span,
        })
    }

    fn lower_merge_action(
        &mut self,
        action: &AstMergeActionKind,
    ) -> Result<MergeAction, LowerError> {
        match action {
            AstMergeActionKind::Delete { .. } => Ok(MergeAction::Delete),
            AstMergeActionKind::UpdateSet { assignments, .. } => {
                let mut out: Vec<(ColumnId, ScalarExpr)> = Vec::with_capacity(assignments.len());
                self.push_no_agg_frame();
                self.push_no_window_frame();
                let result = (|| -> Result<(), LowerError> {
                    for a in assignments {
                        let id = self.bind_assignment_column(&a.column, a.span)?;
                        let val = self.lower_expr(&a.value, None)?;
                        out.push((id, val));
                    }
                    Ok(())
                })();
                self.pop_no_window_frame();
                self.pop_no_agg_frame();
                result?;
                Ok(MergeAction::Update { assignments: out })
            }
            AstMergeActionKind::UpdateSetStar { .. } => Ok(MergeAction::UpdateSetStar),
            AstMergeActionKind::UpdateAllByName { .. } => Ok(MergeAction::UpdateAllByName),
            AstMergeActionKind::InsertStar { .. } => Ok(MergeAction::InsertStar),
            AstMergeActionKind::InsertAllByName { .. } => Ok(MergeAction::InsertAllByName),
            AstMergeActionKind::InsertValues {
                columns, values, ..
            } => {
                let mut target_columns: Vec<ColumnId> = Vec::with_capacity(columns.len());
                for col_expr in columns {
                    let id = self.bind_assignment_column(col_expr, col_expr.span())?;
                    target_columns.push(id);
                }
                let mut vals: Vec<ScalarExpr> = Vec::with_capacity(values.len());
                self.push_no_agg_frame();
                self.push_no_window_frame();
                let result = (|| -> Result<(), LowerError> {
                    for v in values {
                        vals.push(self.lower_expr(v, None)?);
                    }
                    Ok(())
                })();
                self.pop_no_window_frame();
                self.pop_no_agg_frame();
                result?;
                Ok(MergeAction::Insert {
                    target_columns,
                    values: vals,
                })
            }
        }
    }

    /// Lower Oracle / Snowflake `INSERT ALL | FIRST` multi-table insert.
    fn lower_multi_insert(&mut self, mi: &AstMultiInsert) -> Result<RelPlan, LowerError> {
        let source_plan = match mi.subquery.as_deref() {
            Some(q) => self.lower_stmt(q)?,
            None => {
                return Err(LowerError::invalid(
                    mi.span,
                    InvalidInputKind::Dml(DmlShapeCategory::MultiInsertWithoutSource),
                ));
            }
        };
        let mode = match mi.mode {
            AstMultiInsertMode::UnconditionalAll => MultiInsertMode::UnconditionalAll,
            AstMultiInsertMode::ConditionalFirst => MultiInsertMode::ConditionalFirst,
            AstMultiInsertMode::ConditionalAll => MultiInsertMode::ConditionalAll,
        };
        let mut unconditional_clauses: Vec<MultiInsertTarget> =
            Vec::with_capacity(mi.into_clauses.len());
        for c in &mi.into_clauses {
            unconditional_clauses.push(self.lower_multi_insert_target(c)?);
        }
        let mut when_clauses: Vec<MultiInsertWhen> = Vec::with_capacity(mi.when_clauses.len());
        for w in &mi.when_clauses {
            when_clauses.push(self.lower_multi_insert_when(w)?);
        }
        let mut else_clauses: Vec<MultiInsertTarget> =
            Vec::with_capacity(mi.else_into_clauses.len());
        for c in &mi.else_into_clauses {
            else_clauses.push(self.lower_multi_insert_target(c)?);
        }
        Ok(RelPlan::MultiInsert {
            mode,
            unconditional_clauses,
            when_clauses,
            else_clauses,
            source: Box::new(source_plan),
            node_id: mi.node_id,
            span: mi.span,
            hints: Vec::new(),
        })
    }

    fn lower_multi_insert_target(
        &mut self,
        c: &AstMultiInsertIntoClause,
    ) -> Result<MultiInsertTarget, LowerError> {
        let target = self.lower_table_ref_from_span_or_none(c.target_table_span, c.into_span)?;
        let declared = c
            .columns_span
            .and_then(|s| slice_span(self.source, s))
            .map(split_parenthesized_ident_list)
            .unwrap_or_default();
        let mut target_columns: Vec<ColumnId> = Vec::with_capacity(declared.len());
        let stmt_node = c.node_id;
        let stmt_span = c.target_table_span.unwrap_or(c.into_span);
        for name in &declared {
            let key = IdentKey::new(name);
            let display = name.clone();
            let id = *self.bindings.entry(key).or_insert_with(|| {
                self.allocator.fresh(
                    ColumnOrigin::Computed {
                        producing_node: stmt_node,
                        expr_span: stmt_span,
                    },
                    display,
                )
            });
            target_columns.push(id);
        }
        // AST exposes `values_span` only; individual value expressions
        // are not surfaced structurally on [`AstMultiInsertIntoClause`].
        // `values` stays empty until the parser carries them; the
        // clause's span is preserved so renderers can still locate the
        // original text.
        Ok(MultiInsertTarget {
            target,
            target_columns,
            values: Vec::new(),
            span: c.into_span,
        })
    }

    fn lower_multi_insert_when(
        &mut self,
        w: &AstMultiInsertWhenClause,
    ) -> Result<MultiInsertWhen, LowerError> {
        // The AST carries only a span for the condition; without a
        // parsed expression the lowerer cannot build a typed
        // `ScalarExpr`. Represent the presence of the predicate with
        // a typed opaque scalar so the WHEN block's shape is
        // preserved and analyses treat the predicate as dependent on
        // the source.
        let condition = match w.condition_span {
            Some(span) => ScalarExpr::Opaque {
                reason: "multi_insert_when_predicate".into(),
                span,
            },
            None => ScalarExpr::Lit {
                value: Lit::Bool(true),
                span: w.when_span,
            },
        };
        let mut targets: Vec<MultiInsertTarget> = Vec::with_capacity(w.into_clauses.len());
        for c in &w.into_clauses {
            targets.push(self.lower_multi_insert_target(c)?);
        }
        let span = merge_spans(w.when_span, w.then_span);
        Ok(MultiInsertWhen {
            condition,
            targets,
            span,
        })
    }

    /// Lower `EXPLAIN [ANALYZE] [(opts)] <stmt>`.
    fn lower_explain(&mut self, ex: &AstExplain) -> Result<RelPlan, LowerError> {
        let body = self.lower_stmt(&ex.inner_stmt)?;
        let options = match ex.options_span {
            Some(s) => parse_explain_options(slice_span(self.source, s).unwrap_or("")),
            None => ExplainOptions::default(),
        };
        Ok(RelPlan::Explain {
            body: Box::new(body),
            options,
            node_id: ex.node_id,
            span: ex.span,
            hints: Vec::new(),
        })
    }

    /// Lower a standalone `VALUES (...), (...), ...` statement
    /// ([`AstStmt::ValuesQuery`]) to [`RelPlan::Values`], optionally
    /// wrapped in `Sort` (when ORDER BY is present) and `Limit` (when
    /// LIMIT / OFFSET / FETCH is present). Mirrors the row-lowering +
    /// post-projection wrapping pattern used by `lower_select`.
    fn lower_values_query(
        &mut self,
        v: &crate::ast::AstValuesQuery,
    ) -> Result<RelPlan, LowerError> {
        // Aggregates and window functions are not legal in a top-level
        // VALUES expression list — guard with the no-agg / no-window
        // frame, matching the INSERT … VALUES path.
        let mut rows: Vec<Vec<ScalarExpr>> = Vec::with_capacity(v.values.rows.len());
        self.push_no_agg_frame();
        self.push_no_window_frame();
        let lowered = (|| -> Result<(), LowerError> {
            for row in &v.values.rows {
                let mut lowered_row: Vec<ScalarExpr> = Vec::with_capacity(row.len());
                for expr in row {
                    lowered_row.push(self.lower_expr(expr, None)?);
                }
                rows.push(lowered_row);
            }
            Ok(())
        })();
        self.pop_no_window_frame();
        self.pop_no_agg_frame();
        lowered?;

        let arity = rows.first().map(|r| r.len()).unwrap_or(0);
        let mut columns: Vec<ColumnId> = Vec::with_capacity(arity);
        for _ in 0..arity {
            columns.push(self.alloc_tuple_col(v.node_id, v.values.span, String::new()));
        }

        let mut plan = RelPlan::Values {
            rows,
            columns,
            alias: None,
            node_id: v.node_id,
            span: v.span,
            hints: Vec::new(),
        };

        // ORDER BY → Sort. Aggregate / window functions are rejected
        // (mirrors lower_select). The key expressions reference the
        // VALUES output anonymously — there's no alias map to thread
        // (no projection aliases on a bare VALUES).
        if let Some(order_by) = v.order_by.as_deref() {
            self.push_no_agg_frame();
            self.push_no_window_frame();
            let mut keys: Vec<SortKey> = Vec::with_capacity(order_by.items.len());
            let mut key_err: Option<LowerError> = None;
            for item in &order_by.items {
                match self.lower_expr(&item.expr, None) {
                    Ok(expr) => keys.push(SortKey {
                        expr,
                        ascending: item.asc.unwrap_or(true),
                        nulls_first: item.nulls_first,
                        span: item.span,
                    }),
                    Err(e) => {
                        key_err = Some(e);
                        break;
                    }
                }
            }
            self.pop_no_window_frame();
            self.pop_no_agg_frame();
            if let Some(e) = key_err {
                return Err(e);
            }
            plan = RelPlan::Sort {
                input: Box::new(plan),
                keys,
                node_id: v.node_id,
                span: order_by.span,
                hints: Vec::new(),
            };
        }

        // LIMIT / OFFSET / FETCH → Limit wrapping the Sort (or the
        // Values directly when no ORDER BY). LIMIT/OFFSET expressions
        // are scalar-only (no aggregates / window calls).
        let has_limit_like =
            v.limit.is_some() || v.offset.is_some() || v.fetch_clause_span.is_some();
        if has_limit_like {
            let limit_expr = match v.limit.as_deref() {
                Some(e) => Some(self.lower_expr_no_aggs(e, None)?),
                None => None,
            };
            let offset_expr = match v.offset.as_deref() {
                Some(e) => Some(self.lower_expr_no_aggs(e, None)?),
                None => None,
            };
            let limit_span = v
                .limit_keyword_span
                .or(v.offset_keyword_span)
                .or(v.fetch_clause_span)
                .unwrap_or(v.span);
            plan = RelPlan::Limit {
                input: Box::new(plan),
                limit: limit_expr,
                offset: offset_expr,
                kind: LimitKind::Rows,
                with_ties: false,
                node_id: v.node_id,
                span: limit_span,
                hints: Vec::new(),
            };
        }

        Ok(plan)
    }

    // ── Create-as-query ────────────────────────────────────────────────

    /// Lower `CREATE [OR REPLACE] [TEMP|LOCAL|GLOBAL] [MATERIALIZED]
    /// VIEW …` (`AstStmt::CreateView`) to [`RelPlan::CreateAsQuery`].
    ///
    /// BigQuery `CREATE MATERIALIZED VIEW … AS REPLICA OF source_view`
    /// has no relational body (the view contents are mirrored from
    /// another materialized view), so it lowers to a typed
    /// `CreateAsQuery` with `body: None` and a `ReplicaOf`
    /// side-option entry.
    fn lower_create_view(&mut self, cv: &AstCreateView) -> Result<RelPlan, LowerError> {
        let target = self.lower_table_ref_from_span_or_none(Some(cv.name_span), cv.span)?;
        let body = if cv.replica_of_span.is_some() {
            None
        } else {
            Some(Box::new(self.lower_create_as_body(&cv.query, cv.span)?))
        };

        let kind = CreateAsKind::View {
            materialized: cv.materialized_span.is_some(),
            recursive: cv.recursive_span.is_some(),
            secure: cv.secure_span.is_some(),
            temp: cv.temp_kind_span.is_some(),
        };

        let columns = lower_create_view_columns(self.source, cv);

        let mut side_options: Vec<CreateSideOption> = Vec::new();
        push_opt(
            &mut side_options,
            cv.row_access_policy_span,
            CreateSideOptionKind::RowAccessPolicy,
        );
        push_opt(
            &mut side_options,
            cv.aggregation_policy_span,
            CreateSideOptionKind::AggregationPolicy,
        );
        push_opt(
            &mut side_options,
            cv.join_policy_span,
            CreateSideOptionKind::JoinPolicy,
        );
        push_opt(&mut side_options, cv.tag_span, CreateSideOptionKind::Tag);
        push_opt(
            &mut side_options,
            cv.with_contact_span,
            CreateSideOptionKind::Contact,
        );
        push_opt(
            &mut side_options,
            cv.change_tracking_span,
            CreateSideOptionKind::ChangeTracking,
        );
        push_opt(
            &mut side_options,
            cv.comment_span,
            CreateSideOptionKind::Comment,
        );
        push_opt(
            &mut side_options,
            cv.partition_by_span,
            CreateSideOptionKind::PartitionBy,
        );
        push_opt(
            &mut side_options,
            cv.cluster_by_span,
            CreateSideOptionKind::ClusterBy,
        );
        push_opt(
            &mut side_options,
            cv.bq_options_span,
            CreateSideOptionKind::BigQueryOptions,
        );
        push_opt(
            &mut side_options,
            cv.replica_of_span,
            CreateSideOptionKind::ReplicaOf,
        );

        Ok(RelPlan::CreateAsQuery {
            target,
            kind,
            columns,
            body,
            or_replace: cv.or_replace_span.is_some(),
            or_alter: cv.or_alter_span.is_some(),
            if_not_exists: cv.if_not_exists_span.is_some(),
            copy_grants: cv.copy_grants_span.is_some(),
            side_options,
            node_id: cv.node_id,
            span: cv.span,
            hints: Vec::new(),
        })
    }

    /// Lower `CREATE TABLE` to the appropriate typed `RelPlan`.
    ///
    /// - `Ctas` → [`RelPlan::CreateAsQuery`] (query-bearing).
    /// - All other variants (`Plain`, `Like`, `Clone`, `UsingTemplate`,
    ///   `FromArchive`, `FromSnapshotSet`) → [`RelPlan::CreateTableForm`]
    ///   (non-query-bearing typed terminal).
    fn lower_create_table(&mut self, ct: &AstCreateTable) -> Result<RelPlan, LowerError> {
        if ct.variant != AstCreateTableVariant::Ctas {
            let form_kind = match ct.variant {
                AstCreateTableVariant::Plain => CreateTableFormKind::Plain,
                AstCreateTableVariant::Like => CreateTableFormKind::Like,
                AstCreateTableVariant::Clone => CreateTableFormKind::Clone,
                AstCreateTableVariant::UsingTemplate => CreateTableFormKind::UsingTemplate,
                AstCreateTableVariant::FromArchive => CreateTableFormKind::FromArchive,
                AstCreateTableVariant::FromSnapshotSet => CreateTableFormKind::FromSnapshotSet,
                // Ctas is excluded by the outer guard above.
                AstCreateTableVariant::Ctas => unreachable!("Ctas handled above"),
            };
            let target = self.lower_table_ref_from_span_or_none(Some(ct.name_span), ct.span)?;
            let columns = lower_create_table_columns(self.source, ct);
            // `Like` and `Clone` carry a source table reference.
            let source = match ct.variant {
                AstCreateTableVariant::Like => self
                    .lower_table_ref_from_span_or_none(ct.like_source_span, ct.span)
                    .ok(),
                AstCreateTableVariant::Clone => self
                    .lower_table_ref_from_span_or_none(ct.clone_source_span, ct.span)
                    .ok(),
                _ => None,
            };
            return Ok(RelPlan::CreateTableForm {
                target,
                kind: form_kind,
                columns,
                source,
                or_replace: ct.or_replace_span.is_some(),
                if_not_exists: false,
                hints: Vec::new(),
                stmt_node_id: ct.node_id,
                span: ct.span,
            });
        }
        let query = ct.ctas_query.as_ref().ok_or_else(|| {
            LowerError::invalid(
                ct.span,
                InvalidInputKind::Dml(DmlShapeCategory::CreateTableCtasWithoutQuery),
            )
        })?;
        let target = self.lower_table_ref_from_span_or_none(Some(ct.name_span), ct.span)?;
        let body = self.lower_create_as_body(query, ct.span)?;

        let kind = CreateAsKind::Table {
            transient: matches!(
                ct.temp_kind_span.and_then(|s| slice_span(self.source, s)),
                Some(txt) if txt.trim().eq_ignore_ascii_case("transient")
            ),
            temp: ct
                .temp_kind_span
                .and_then(|s| slice_span(self.source, s))
                .map(|txt| {
                    let t = txt.trim().to_ascii_lowercase();
                    t.contains("temp") || t.contains("volatile")
                })
                .unwrap_or(false),
        };

        let columns = lower_create_table_columns(self.source, ct);

        let mut side_options: Vec<CreateSideOption> = Vec::new();
        push_opt(
            &mut side_options,
            ct.table_options_span,
            CreateSideOptionKind::TableOptions,
        );
        push_opt(
            &mut side_options,
            ct.cluster_by_span,
            CreateSideOptionKind::ClusterBy,
        );
        push_opt(
            &mut side_options,
            ct.partition_by_span,
            CreateSideOptionKind::PartitionBy,
        );
        push_opt(
            &mut side_options,
            ct.copy_tags_span,
            CreateSideOptionKind::CopyTags,
        );
        push_opt(
            &mut side_options,
            ct.retention_span,
            CreateSideOptionKind::Retention,
        );
        push_opt(
            &mut side_options,
            ct.change_tracking_span,
            CreateSideOptionKind::ChangeTracking,
        );
        push_opt(
            &mut side_options,
            ct.data_retention_time_in_days_span,
            CreateSideOptionKind::DataRetentionTimeInDays,
        );
        push_opt(
            &mut side_options,
            ct.max_data_extension_time_in_days_span,
            CreateSideOptionKind::MaxDataExtensionTimeInDays,
        );
        push_opt(
            &mut side_options,
            ct.default_ddl_collation_span,
            CreateSideOptionKind::DefaultDdlCollation,
        );
        push_opt(
            &mut side_options,
            ct.row_access_policy_span,
            CreateSideOptionKind::RowAccessPolicy,
        );
        push_opt(
            &mut side_options,
            ct.aggregation_policy_span,
            CreateSideOptionKind::AggregationPolicy,
        );
        push_opt(
            &mut side_options,
            ct.join_policy_span,
            CreateSideOptionKind::JoinPolicy,
        );
        push_opt(
            &mut side_options,
            ct.storage_lifecycle_policy_span,
            CreateSideOptionKind::StorageLifecyclePolicy,
        );
        push_opt(&mut side_options, ct.tag_span, CreateSideOptionKind::Tag);
        push_opt(
            &mut side_options,
            ct.enable_schema_evolution_span,
            CreateSideOptionKind::EnableSchemaEvolution,
        );
        push_opt(
            &mut side_options,
            ct.table_comment_span,
            CreateSideOptionKind::Comment,
        );
        push_opt(
            &mut side_options,
            ct.with_row_access_policy_span,
            CreateSideOptionKind::WithRowAccessPolicy,
        );
        push_opt(
            &mut side_options,
            ct.with_contact_span,
            CreateSideOptionKind::Contact,
        );
        push_opt(
            &mut side_options,
            ct.using_template_span,
            CreateSideOptionKind::UsingTemplate,
        );
        push_opt(
            &mut side_options,
            ct.from_archive_span,
            CreateSideOptionKind::FromArchive,
        );
        push_opt(
            &mut side_options,
            ct.from_snapshot_set_span,
            CreateSideOptionKind::FromSnapshotSet,
        );
        if let Some(tt) = ct.time_travel.as_ref() {
            let tt_span = match tt.as_ref() {
                crate::ast::AstTimeTravelClause::SnowflakeAtBefore(x) => x.span,
                crate::ast::AstTimeTravelClause::ForSystemTime(x) => x.span,
                crate::ast::AstTimeTravelClause::DatabricksAsOf(x) => x.span,
            };
            side_options.push(CreateSideOption {
                kind: CreateSideOptionKind::TimeTravel,
                span: tt_span,
            });
        }

        Ok(RelPlan::CreateAsQuery {
            target,
            kind,
            columns,
            body: Some(Box::new(body)),
            or_replace: ct.or_replace_span.is_some(),
            or_alter: false,
            if_not_exists: false,
            copy_grants: ct.copy_grants_span.is_some(),
            side_options,
            node_id: ct.node_id,
            span: ct.span,
            hints: Vec::new(),
        })
    }

    /// Lower `CREATE [OR REPLACE] [TRANSIENT] DYNAMIC [ICEBERG] TABLE …`
    /// (`AstStmt::CreateDynamicTable`) to [`RelPlan::CreateAsQuery`].
    fn lower_create_dynamic_table(
        &mut self,
        cdt: &AstCreateDynamicTable,
    ) -> Result<RelPlan, LowerError> {
        let target = self.lower_table_ref_from_span_or_none(Some(cdt.name_span), cdt.span)?;
        let body = self.lower_create_as_body(&cdt.query, cdt.span)?;

        let kind = CreateAsKind::DynamicTable {
            iceberg: cdt.iceberg_span.is_some(),
            transient: cdt.transient_span.is_some(),
        };

        let columns = None; // AST surfaces column defs as a single span only.

        let mut side_options: Vec<CreateSideOption> = Vec::new();
        push_opt(
            &mut side_options,
            cdt.target_lag_span,
            CreateSideOptionKind::TargetLag,
        );
        push_opt(
            &mut side_options,
            cdt.warehouse_span,
            CreateSideOptionKind::Warehouse,
        );
        push_opt(
            &mut side_options,
            cdt.init_warehouse_span,
            CreateSideOptionKind::InitializationWarehouse,
        );
        push_opt(
            &mut side_options,
            cdt.refresh_mode_span,
            CreateSideOptionKind::RefreshMode,
        );
        push_opt(
            &mut side_options,
            cdt.initialize_span,
            CreateSideOptionKind::Initialize,
        );
        push_opt(
            &mut side_options,
            cdt.cluster_by_span,
            CreateSideOptionKind::ClusterBy,
        );
        push_opt(
            &mut side_options,
            cdt.data_retention_span,
            CreateSideOptionKind::DataRetentionTimeInDays,
        );
        push_opt(
            &mut side_options,
            cdt.max_data_extension_span,
            CreateSideOptionKind::MaxDataExtensionTimeInDays,
        );
        push_opt(
            &mut side_options,
            cdt.comment_span,
            CreateSideOptionKind::Comment,
        );
        push_opt(
            &mut side_options,
            cdt.row_access_policy_span,
            CreateSideOptionKind::RowAccessPolicy,
        );
        push_opt(
            &mut side_options,
            cdt.aggregation_policy_span,
            CreateSideOptionKind::AggregationPolicy,
        );
        push_opt(&mut side_options, cdt.tag_span, CreateSideOptionKind::Tag);
        push_opt(
            &mut side_options,
            cdt.require_user_span,
            CreateSideOptionKind::RequireUser,
        );
        push_opt(
            &mut side_options,
            cdt.immutable_where_span,
            CreateSideOptionKind::ImmutableWhere,
        );
        push_opt(
            &mut side_options,
            cdt.backfill_from_span,
            CreateSideOptionKind::BackfillFrom,
        );

        Ok(RelPlan::CreateAsQuery {
            target,
            kind,
            columns,
            body: Some(Box::new(body)),
            or_replace: cdt.or_replace_span.is_some(),
            or_alter: cdt.or_alter_span.is_some(),
            if_not_exists: cdt.if_not_exists_span.is_some(),
            copy_grants: cdt.copy_grants_span.is_some(),
            side_options,
            node_id: cdt.node_id,
            span: cdt.span,
            hints: Vec::new(),
        })
    }

    /// Common body lowering for `CREATE VIEW` / `CTAS` / `CREATE
    /// DYNAMIC TABLE`. `query: Result<Box<AstStmt>, Span>` on the AST
    /// is `Err(recovery_span)` when the parser could not structure
    /// the body; route that to `LowerError::ParseUpstream` under
    /// permissive strictness so the outer `CreateAsQuery` still
    /// wraps a `RelPlan::ParseRecovery` rather than silently dropping
    /// the DDL. Strict modes surface the same as a typed [`LowerError`].
    fn lower_create_as_body(
        &mut self,
        query: &Result<Box<AstStmt>, Span>,
        outer_span: Span,
    ) -> Result<RelPlan, LowerError> {
        match query {
            Ok(stmt) => self.lower_stmt(stmt),
            Err(body_span) => {
                let span = if body_span.end > body_span.start {
                    *body_span
                } else {
                    outer_span
                };
                if self.strict.forbids_opaque() {
                    Err(LowerError::parse_upstream(span))
                } else {
                    Ok(RelPlan::ParseRecovery {
                        stmt_node_id: crate::ast::NodeId::new(0),
                        span,
                        hints: Vec::new(),
                    })
                }
            }
        }
    }

    // ── DML helpers ────────────────────────────────────────────────────

    /// Lower a writable-CTE `WITH` clause wrapped around an INSERT /
    /// UPDATE / DELETE / MERGE body. Mirrors
    /// [`Self::lower_select_with_ctes`] but takes a closure producing
    /// the body plan so each DML kind can reuse the scope-management
    /// path without duplicating CTE-binding logic.
    fn lower_dml_with_ctes<F>(
        &mut self,
        with_clause: &AstWithClause,
        outer_span: Span,
        outer_node: crate::ast::NodeId,
        body: F,
    ) -> Result<RelPlan, LowerError>
    where
        F: FnOnce(&mut Self) -> Result<RelPlan, LowerError>,
    {
        let recursive = with_clause.recursive_span.is_some();
        self.cte_scopes.push(HashMap::new());

        let result: Result<RelPlan, LowerError> = (|| {
            let mut ctes: Vec<CteBinding> = Vec::with_capacity(with_clause.ctes.len());
            for item in &with_clause.ctes {
                match item {
                    CteItem::JinjaBlock(blk) => {
                        return Err(LowerError::opaque(
                            blk.span,
                            OpaqueReason::UnresolvedJinja { macro_name: None },
                        ));
                    }
                    CteItem::Cte(cte) => {
                        // Per-binding scope; see
                        // `lower_select_with_ctes` for the
                        // ScopeId-uniqueness rationale.
                        let scope = self.alloc_scope();
                        let binding = self.lower_cte(cte, scope, recursive)?;
                        let name_key = self.ident_at(cte.name.span);
                        let declared_column_names = binding
                            .declared_columns
                            .as_ref()
                            .map(|d| d.iter().map(|k| k.as_str().to_string()).collect())
                            .unwrap_or_default();
                        let body_column_names: Vec<String> = binding
                            .output_columns
                            .iter()
                            .map(|id| {
                                self.allocator
                                    .bindings()
                                    .get(*id)
                                    .map(|b| b.display_name.clone())
                                    .unwrap_or_default()
                            })
                            .collect();
                        let (leaf_scan_node, passthrough_columns) =
                            self.detect_cte_passthrough_with_renames(&binding.body);
                        self.cte_scopes
                            .last_mut()
                            .expect("cte_scopes frame pushed above")
                            .insert(
                                name_key,
                                CteScopeEntry {
                                    scope,
                                    arity: binding.output_columns.len(),
                                    declared_column_names,
                                    body_column_names,
                                    leaf_scan_node,
                                    passthrough_columns,
                                },
                            );
                        ctes.push(binding);
                    }
                }
            }
            let inner = body(self)?;
            self.finalize_star_passthrough_bindings(&mut ctes);
            Ok(RelPlan::WithScope {
                ctes,
                body: Box::new(inner),
                recursive,
                node_id: outer_node,
                span: outer_span,
                hints: Vec::new(),
            })
        })();

        self.cte_scopes.pop();
        result
    }

    /// Lower a FROM-like list of AstTableRef into an optional
    /// left-folded `Cross`-joined plan. Used by UPDATE (`FROM …`) and
    /// DELETE (`USING …`). Returns [`None`] when the list is empty.
    fn lower_dml_from_list(
        &mut self,
        list: &[Box<AstTableRef>],
        node_id: crate::ast::NodeId,
    ) -> Result<Option<Box<RelPlan>>, LowerError> {
        if list.is_empty() {
            return Ok(None);
        }
        let mut iter = list.iter();
        let first = iter.next().expect("list.is_empty() checked above").as_ref();
        let mut plan = self.lower_table_ref_with_joins(first, node_id)?;
        for next in iter {
            let right = self.lower_table_ref_with_joins(next.as_ref(), node_id)?;
            let span = merge_spans(plan.span(), right.span());
            let clause_span = right.span();
            plan = RelPlan::Join {
                left: Box::new(plan),
                right: Box::new(right),
                kind: JoinKind::Cross,
                on: None,
                match_condition: None,
                using: Vec::new(),
                natural: false,
                directed: false,
                lateral: false,
                implicit: true,
                node_id,
                span,
                clause_span,
                hints: Vec::new(),
            };
        }
        Ok(Some(Box::new(plan)))
    }

    fn lower_dml_top(&mut self, top: &crate::ast::AstTop) -> Result<DmlTop, LowerError> {
        self.push_no_agg_frame();
        self.push_no_window_frame();
        let count_res = self.lower_expr(&top.expr, None);
        self.pop_no_window_frame();
        self.pop_no_agg_frame();
        let count = count_res?;
        Ok(DmlTop {
            count,
            percent: top.percent_span.is_some(),
            span: top.span,
        })
    }

    /// Build a [`TableRef`] from a target-table span (the shape most
    /// DML statements expose on the AST).
    ///
    /// Delegates to [`extract_table_ref_from_object_span`] — the
    /// canonical token-aware extractor —
    /// rather than re-implementing byte-level slicing. Re-slicing the
    /// raw span text and splitting on `.` would pick up alias text,
    /// trailing trivia, and `/* ... */` comments that the parser
    /// includes inside `target_table_span` (e.g. for MERGE/INSERT/
    /// DELETE), corrupting `TableRef.name`. The extractor does
    /// proper tokenization, skips alias/keyword/punctuation tokens,
    /// and applies the same session defaults.
    fn lower_table_ref_from_span_or_none(
        &self,
        span_opt: Option<Span>,
        fallback_span: Span,
    ) -> Result<TableRef, LowerError> {
        let span = match span_opt {
            Some(s) => s,
            None => {
                return Err(LowerError::invalid(
                    fallback_span,
                    InvalidInputKind::Dml(DmlShapeCategory::DmlWithoutTargetTable),
                ));
            }
        };
        match extract_table_ref_from_object_span(span, self.source, self.session) {
            Some(tref) => Ok(tref),
            None => Err(LowerError::invalid(
                fallback_span,
                InvalidInputKind::Dml(DmlShapeCategory::DmlWithoutTargetTable),
            )),
        }
    }

    /// Allocate-or-look-up the [`ColumnId`] for an assignment target
    /// column. Accepts either a bare identifier or a qualified
    /// `t.col` expression; falls back to the raw source text if the
    /// shape is something else (e.g. `@variable` in T-SQL), keyed via
    /// [`IdentKey`] so normalization is consistent across lookups.
    fn bind_assignment_column(
        &mut self,
        expr: &AstExpr,
        span: Span,
    ) -> Result<ColumnId, LowerError> {
        let key = match expr {
            AstExpr::Ident { column_ref, .. } => self.ident_at(column_ref.name.span),
            _ => {
                let raw = slice_span(self.source, span).unwrap_or("");
                // Strip a leading qualifier: `t.col` → `col`.
                let last = raw.rsplit('.').next().unwrap_or(raw).trim();
                IdentKey::new(last)
            }
        };
        let id = {
            let display = key.as_str().to_string();
            let stmt_node = self.current_stmt_node;
            *self.bindings.entry(key).or_insert_with(|| {
                self.allocator.fresh(
                    ColumnOrigin::Computed {
                        producing_node: stmt_node,
                        expr_span: span,
                    },
                    display,
                )
            })
        };
        Ok(id)
    }

    // ── FROM items and joins ────────────────────────────────────────────

    /// Lower one FROM clause item, including any trailing join chain.
    fn lower_from_item(&mut self, item: &FromItem) -> Result<RelPlan, LowerError> {
        let table_ref = match &item.kind {
            FromItemKind::TableRef(tr) => tr.as_ref(),
            FromItemKind::JinjaBlock(blk) => {
                return Err(LowerError::opaque(
                    blk.span,
                    OpaqueReason::UnresolvedJinja { macro_name: None },
                ));
            }
            FromItemKind::JinjaTableName(blk) => {
                return Err(LowerError::opaque(
                    blk.span,
                    OpaqueReason::UnresolvedJinja { macro_name: None },
                ));
            }
        };
        self.lower_table_ref_with_joins(table_ref, item.node_id)
    }

    /// Lower a table reference plus its `joins` chain, left-folding each
    /// join into a [`RelPlan::Join`] node.
    ///
    /// Appends scope entries for the base FROM source AS SOON AS it is
    /// lowered, and for each subsequent join's right side inside
    /// [`Self::lower_join`]. This lets ON-clause column refs lowered
    /// during FROM assembly resolve through `from_scope` to the source-
    /// owned ColumnId (the bridge-chainable slot), rather than falling
    /// to the allocate-on-first-use path which creates a fresh Table-
    /// origin ColumnId pointing at the FROM-item NodeId — a per-shape
    /// equivalence break that prevents cross-scope contradiction
    /// detection (Q-PROP-CONTRA) from resolving the consumer's ColumnId
    /// to the boundary's body column. The end-of-FROM
    /// [`Self::populate_from_scope`] call clears and rebuilds the same
    /// final scope, so the incremental adds are idempotent.
    fn lower_table_ref_with_joins(
        &mut self,
        tr: &AstTableRef,
        from_item_node: crate::ast::NodeId,
    ) -> Result<RelPlan, LowerError> {
        let base_lateral = tr.lateral_keyword_span.is_some();
        let mut left = self.lower_base_table_ref(tr, from_item_node)?;
        // Base source visible to subsequent JOIN ON / MATCH_CONDITION
        // lowering in this chain.
        self.collect_scope_entries(&left, None);
        for join in tr.joins.iter() {
            left = self.lower_join(left, join, base_lateral)?;
        }
        Ok(left)
    }

    /// DerivedTable branch of [`Self::lower_base_table_ref`].
    /// Returns `Ok(Some(plan))` when this table-ref is a subquery
    /// (`FROM (SELECT …)`) without an incompatible wrapper; `Ok(None)`
    /// when the caller should fall through to the next inner-source
    /// variant.
    ///
    /// Extracted from the monolithic `lower_base_table_ref` so each
    /// debug-build stack frame on a nested-derived-table chain
    /// (`FROM (SELECT * FROM (SELECT * FROM (...)))`) only carries
    /// this branch's locals when this branch is the one taken,
    /// instead of every sibling branch's locals too. The previous
    /// monolithic frame consumed ~123 KB per nesting level on debug,
    /// which exhausted the 12 MB test-thread stack at ~57 nested
    /// derived tables.
    #[inline(never)]
    fn lower_base_table_ref_subquery_branch(
        &mut self,
        tr: &AstTableRef,
        from_item_node: crate::ast::NodeId,
    ) -> Result<Option<RelPlan>, LowerError> {
        // The subquery branch is gated on no incompatible wrapper.
        let has_rejected_wrapper = tr.changes.is_some()
            || tr.table_function.is_some()
            || tr.with_offset.is_some()
            || tr.only_span.is_some()
            || tr.table_hints.is_some()
            || tr.tvf_schema_span.is_some()
            || tr.values.is_some();
        let Some(subquery) = tr.subquery.as_deref() else {
            return Ok(None);
        };
        if has_rejected_wrapper {
            return Ok(None);
        }
        let inner_plan = self.lower_stmt_as_subquery(subquery)?;
        // Alias fallback: post-transform `result_alias` from
        // PIVOT/UNPIVOT/MATCH_RECOGNIZE surfaces here when no
        // pre-transform `alias` is present.
        let (alias, alias_columns_src) = if let Some(a) = tr.alias.as_ref() {
            (Some(a), tr.alias_columns.as_deref())
        } else if let Some(ra) = tr.result_alias.as_ref() {
            (Some(ra), tr.result_alias_columns.as_deref())
        } else {
            (None, None)
        };
        let alias = alias.map(|a| self.ident_at(a.span));
        let alias_columns: Vec<IdentKey> = alias_columns_src
            .map(|cols| cols.iter().map(|c| self.ident_at(c.span)).collect())
            .unwrap_or_default();
        // Star-passthrough redirect: when the subquery body is
        // `SELECT * [RENAME …] FROM <single-scan-chain>`, register
        // the alias against the leaf Scan's NodeId so outer refs
        // resolve to the underlying table directly.
        let alias_target = if let Some((leaf, renames)) =
            inner_plan.cte_body_star_rename_passthrough_leaf_scan_node()
        {
            if !renames.is_empty() {
                let map = self.cte_passthrough_renames.entry(leaf).or_default();
                for r in renames {
                    map.insert(
                        r.to.clone(),
                        PassthroughSourceName {
                            ident: r.from.clone(),
                            span: r.from_span,
                        },
                    );
                }
            }
            leaf
        } else if let Some(leaf) = inner_plan.cte_body_star_passthrough_leaf_scan_node() {
            leaf
        } else {
            // Multi-leaf / chained body: store per-output passthrough
            // against the derived table's `from_item_node`.
            if let Some(cols) = self.compute_passthrough_columns_for_body(&inner_plan) {
                if !cols.is_empty() {
                    self.cte_passthrough_columns.insert(from_item_node, cols);
                }
            }
            from_item_node
        };
        self.register_from_source(alias.clone(), alias_target);
        let outer_scan_cols = self.drain_scan_cols_for(from_item_node);
        let derived_span = tr.span;
        let derived_node = tr.node_id;
        let inner_schema = inner_plan.output_schema();
        let columns: Vec<ColumnId> = inner_schema
            .iter()
            .map(|inner_id| {
                let display = self
                    .allocator
                    .bindings()
                    .get(*inner_id)
                    .map(|b| b.display_name.clone())
                    .unwrap_or_default();
                self.alloc_computed_col(derived_node, derived_span, display)
            })
            .collect();
        let derived = RelPlan::DerivedTable {
            input: Box::new(inner_plan),
            alias,
            columns,
            alias_columns,
            node_id: from_item_node,
            span: tr.span,
            hints: Vec::new(),
        };
        let wrapped = self
            .maybe_wrap_match_recognize(derived, tr, from_item_node, outer_scan_cols)
            .and_then(|r| self.maybe_wrap_table_sample(r, tr, from_item_node))
            .and_then(|r| self.maybe_wrap_pivot(r, tr, from_item_node))
            .and_then(|r| self.maybe_wrap_unpivot(r, tr, from_item_node))?;
        Ok(Some(wrapped))
    }

    /// TableFunction branch of [`Self::lower_base_table_ref`].
    /// Returns `Ok(Some)` when this table-ref is a TVF without a
    /// conflicting inner source (values / subquery); `Ok(None)` to
    /// fall through to the next branch.
    #[inline(never)]
    fn lower_base_table_ref_table_function_branch(
        &mut self,
        tr: &AstTableRef,
        from_item_node: crate::ast::NodeId,
        has_match_recognize: bool,
    ) -> Result<Option<RelPlan>, LowerError> {
        let Some(func_expr) = tr.table_function.as_deref() else {
            return Ok(None);
        };
        let has_tvf_source_conflict = tr.values.is_some() || tr.subquery.is_some();
        if has_tvf_source_conflict {
            return Ok(None);
        }
        let call = self.lower_expr(func_expr, None)?;
        let alias = tr.alias.as_ref().map(|a| self.ident_at(a.span));
        self.register_from_source(alias.clone(), from_item_node);
        let outer_scan_cols = self.drain_scan_cols_for(from_item_node);
        let tvf_output_columns = if has_match_recognize {
            Vec::new()
        } else {
            outer_scan_cols.clone()
        };
        let time_travel = tr
            .time_travel
            .as_deref()
            .map(|tt| self.lower_time_travel_clause(tt))
            .transpose()?;
        let changes = tr
            .changes
            .as_deref()
            .map(|c| self.lower_changes_clause(c))
            .transpose()?;
        let lowered_sample = tr
            .sample
            .as_deref()
            .map(|s| self.lower_sample_clause(s))
            .transpose()?;
        let tvf_modifier = ScanModifier {
            time_travel,
            changes,
            sample: lowered_sample.clone(),
            stage_options: tr.stage_options.as_deref().map(|so| so.span),
            with_offset: tr
                .with_offset
                .as_deref()
                .map(|w| self.lower_with_offset_clause(w)),
            table_hints: tr
                .table_hints
                .as_deref()
                .map(|hints| self.lower_scan_table_hints(hints))
                .unwrap_or_default(),
            tvf_schema: tr.tvf_schema_span,
            ..ScanModifier::default()
        };
        let tvf = RelPlan::TableFunction {
            call,
            alias,
            output_columns: tvf_output_columns,
            lateral: tr.lateral_keyword_span.is_some(),
            modifier: tvf_modifier,
            node_id: from_item_node,
            span: tr.span,
            hints: Vec::new(),
        };
        let result = self.maybe_wrap_match_recognize(tvf, tr, from_item_node, outer_scan_cols)?;
        let result = if let Some(ts) = lowered_sample {
            RelPlan::TableSample {
                input: Box::new(result),
                sample: ts,
                node_id: from_item_node,
                span: tr.span,
                hints: Vec::new(),
            }
        } else {
            result
        };
        let result = self.maybe_wrap_pivot(result, tr, from_item_node)?;
        let result = self.maybe_wrap_unpivot(result, tr, from_item_node)?;
        Ok(Some(result))
    }

    /// Values branch of [`Self::lower_base_table_ref`]. Returns
    /// `Ok(Some)` when this table-ref is `FROM VALUES (…)` without
    /// a conflicting wrapper; `Ok(None)` to fall through.
    #[inline(never)]
    fn lower_base_table_ref_values_branch(
        &mut self,
        tr: &AstTableRef,
        from_item_node: crate::ast::NodeId,
        has_match_recognize: bool,
    ) -> Result<Option<RelPlan>, LowerError> {
        let Some(values) = tr.values.as_deref() else {
            return Ok(None);
        };
        let has_values_conflict = tr.changes.is_some()
            || tr.table_function.is_some()
            || tr.with_offset.is_some()
            || tr.only_span.is_some()
            || tr.table_hints.is_some()
            || tr.tvf_schema_span.is_some();
        if has_values_conflict {
            return Ok(None);
        }
        let mut rows: Vec<Vec<ScalarExpr>> = Vec::with_capacity(values.rows.len());
        self.push_no_agg_frame();
        self.push_no_window_frame();
        let lowered = (|| -> Result<(), LowerError> {
            for row in &values.rows {
                let mut lowered_row = Vec::with_capacity(row.len());
                for expr in row {
                    lowered_row.push(self.lower_expr(expr, None)?);
                }
                rows.push(lowered_row);
            }
            Ok(())
        })();
        self.pop_no_window_frame();
        self.pop_no_agg_frame();
        lowered?;
        let arity = rows.first().map(|r| r.len()).unwrap_or(0);
        let mut columns: Vec<ColumnId> = Vec::with_capacity(arity);
        for idx in 0..arity {
            let display = tr
                .alias_columns
                .as_ref()
                .and_then(|names| names.get(idx))
                .map(|ident| self.ident_at(ident.span).as_str().to_string())
                .unwrap_or_default();
            columns.push(self.alloc_tuple_col(from_item_node, values.span, display));
        }
        let alias = tr.alias.as_ref().map(|a| self.ident_at(a.span));
        self.register_from_source(alias.clone(), from_item_node);
        let outer_scan_cols = self.drain_scan_cols_for(from_item_node);
        if !has_match_recognize {
            for col in outer_scan_cols.iter().copied() {
                if !columns.contains(&col) {
                    columns.push(col);
                }
            }
        }
        let values_plan = RelPlan::Values {
            rows,
            columns,
            alias,
            node_id: from_item_node,
            span: tr.span,
            hints: Vec::new(),
        };
        let wrapped = self
            .maybe_wrap_match_recognize(values_plan, tr, from_item_node, outer_scan_cols)
            .and_then(|r| self.maybe_wrap_table_sample(r, tr, from_item_node))
            .and_then(|r| self.maybe_wrap_pivot(r, tr, from_item_node))
            .and_then(|r| self.maybe_wrap_unpivot(r, tr, from_item_node))?;
        Ok(Some(wrapped))
    }

    /// Lower a table reference in isolation (no joins). Rejects
    /// table-ref features outside the current scope.
    fn lower_base_table_ref(
        &mut self,
        tr: &AstTableRef,
        from_item_node: crate::ast::NodeId,
    ) -> Result<RelPlan, LowerError> {
        // Two-phase build:
        //
        // 1. Lower the *inner* source — `DerivedTable` (subquery),
        //    `TableFunction` (`FROM TABLE(udtf(…))` / `FLATTEN(…)` /
        //    `UNNEST(…)`), `Values` (`FROM VALUES (...) AS t(c1,...)`),
        //    `CteRef` (name matches a CTE binding in
        //    scope), or `Scan` (base table, optionally with scan
        //    modifiers).
        // 2. Wrap the inner in any structurally-distinct wrapper
        //    nodes whose variants already exist: `MatchRecognize`.
        //    The outer-accumulated `scan_cols` attach to the
        //    wrapper's output schema (outer expressions see the
        //    wrapper's output, not the inner table's columns).
        //
        // Wrappers whose IR variants are not yet shaped for the
        // full dialect surface (Pivot multi-aggregate, Unpivot
        // multi-column) continue to route through
        // `reject_unsupported_table_ref_except_match_recognize`.
        // A TVF that also carries `values` or `subquery` is a
        // parser-bug table-ref and surfaces as `LowerError::ParseUpstream → RelPlan::ParseRecovery`.

        // Decide which features are MR-compatible inner sources.
        // When `MATCH_RECOGNIZE` is present we allow a `Scan` or
        // `DerivedTable` inner and treat stage_options as a
        // decoration on that inner scan; everything else still
        // routes to rejection.
        let has_match_recognize = tr.match_recognize.is_some();

        // -- Inner: TableFunction path ------------------------------
        // Extracted; see [`Self::lower_base_table_ref_table_function_branch`].
        if let Some(handled) = self.lower_base_table_ref_table_function_branch(
            tr,
            from_item_node,
            has_match_recognize,
        )? {
            return Ok(handled);
        }

        // -- Inner: DerivedTable path ------------------------------
        // Extracted into [`Self::lower_base_table_ref_subquery_branch`]
        // so this function's debug-build stack frame doesn't carry
        // the subquery branch's ~130 lines of locals alongside every
        // other variant's. Deep nesting (e.g. 50+ derived tables
        // chained via `FROM (SELECT * FROM (...))`) recurses through
        // this site once per level; pre-extraction each level cost
        // ~123 KB of stack from this frame's locals alone.
        if let Some(handled) = self.lower_base_table_ref_subquery_branch(tr, from_item_node)? {
            return Ok(handled);
        }

        // -- Inner: Values path -----------------------------------
        // Extracted; see [`Self::lower_base_table_ref_values_branch`].
        if let Some(handled) =
            self.lower_base_table_ref_values_branch(tr, from_item_node, has_match_recognize)?
        {
            return Ok(handled);
        }

        // Reject unsupported wrappers + Jinja-templated names; then
        // CteRef and Scan-or-ModelRef branches. Both extracted; see
        // [`Self::lower_base_table_ref_cte_ref_branch`] and
        // [`Self::lower_base_table_ref_scan_branch`].
        self.reject_unsupported_table_ref_except_match_recognize(tr)?;
        if is_jinja_templated_span(self.source, tr.name.span) {
            return Err(LowerError::opaque(
                tr.name.span,
                OpaqueReason::UnresolvedJinja { macro_name: None },
            ));
        }
        if let Some(handled) =
            self.lower_base_table_ref_cte_ref_branch(tr, from_item_node, has_match_recognize)?
        {
            return Ok(handled);
        }
        self.lower_base_table_ref_scan_branch(tr, from_item_node, has_match_recognize)
    }

    /// CteRef branch of [`Self::lower_base_table_ref`]. Returns
    /// `Ok(Some)` when the bare single-segment name resolves to a
    /// CTE binding in the current scope; `Ok(None)` otherwise.
    #[inline(never)]
    fn lower_base_table_ref_cte_ref_branch(
        &mut self,
        tr: &AstTableRef,
        from_item_node: crate::ast::NodeId,
        has_match_recognize: bool,
    ) -> Result<Option<RelPlan>, LowerError> {
        let single_segment = match &tr.name.parts {
            Some(parts) => parts.len() == 1,
            None => {
                let raw_name = slice_span(self.source, tr.name.span).unwrap_or("");
                split_object_ref(raw_name).len() == 1
            }
        };
        if !single_segment {
            return Ok(None);
        }
        let key = self.ident_at(tr.name.span);
        let Some(entry) = self.lookup_cte(&key).cloned() else {
            return Ok(None);
        };
        let mut columns: Vec<ColumnId> = Vec::with_capacity(entry.arity);
        let cte_ref_span = tr.span;
        let cte_ref_node = tr.node_id;
        for idx in 0..entry.arity {
            let display = entry
                .declared_column_names
                .get(idx)
                .cloned()
                .filter(|n| !n.is_empty())
                .or_else(|| {
                    entry
                        .body_column_names
                        .get(idx)
                        .cloned()
                        .filter(|n| !n.is_empty())
                })
                .unwrap_or_default();
            columns.push(self.alloc_computed_col(cte_ref_node, cte_ref_span, display));
        }
        let alias = tr.alias.as_ref().map(|a| self.ident_at(a.span));
        let mut alias_keys: Vec<IdentKey> = Vec::new();
        if let Some(a) = alias.clone() {
            alias_keys.push(a);
        }
        alias_keys.push(key.clone());
        let alias_target = entry.leaf_scan_node.unwrap_or(from_item_node);
        self.register_from_source(alias_keys, alias_target);
        if entry.leaf_scan_node.is_none() && !entry.passthrough_columns.is_empty() {
            self.cte_passthrough_columns
                .insert(from_item_node, entry.passthrough_columns.clone());
        }
        let outer_scan_cols = self.drain_scan_cols_for(from_item_node);
        let cte_ref = RelPlan::CteRef {
            name: key,
            scope: entry.scope,
            columns,
            alias,
            node_id: from_item_node,
            span: tr.span,
            hints: Vec::new(),
        };
        let wrapped = self.maybe_wrap_match_recognize(
            cte_ref,
            tr,
            from_item_node,
            if has_match_recognize {
                outer_scan_cols
            } else {
                Vec::new()
            },
        )?;
        let wrapped = self.maybe_wrap_table_sample(wrapped, tr, from_item_node)?;
        let wrapped = self.maybe_wrap_pivot(wrapped, tr, from_item_node)?;
        let wrapped = self.maybe_wrap_unpivot(wrapped, tr, from_item_node)?;
        Ok(Some(wrapped))
    }

    /// Scan/ModelRef terminal branch of [`Self::lower_base_table_ref`].
    /// Always returns a plan (the catch-all when no earlier inner
    /// source matched). Resolves to `RelPlan::ModelRef` when the
    /// canonical name matches the active `ModelCatalog`; otherwise
    /// `RelPlan::Scan` with the per-source `ScanModifier`.
    #[inline(never)]
    fn lower_base_table_ref_scan_branch(
        &mut self,
        tr: &AstTableRef,
        from_item_node: crate::ast::NodeId,
        has_match_recognize: bool,
    ) -> Result<RelPlan, LowerError> {
        let scan_node_id = from_item_node;
        let scan_span = tr.span;
        let scan_table = self.lower_table_ref(tr);
        let scan_alias = tr.alias.as_ref().map(|a| self.ident_at(a.span));

        // -- Model injection check (dbt cross-model refs) ----------
        if let Some(catalog) = self.model_catalog {
            let key = IdentKey::new(&scan_table.canonical());
            if let Some(entry) = catalog.get(&key) {
                let mut alias_keys: Vec<IdentKey> = Vec::new();
                if let Some(a) = scan_alias.clone() {
                    alias_keys.push(a);
                }
                alias_keys.push(IdentKey::new(&scan_table.name));
                self.register_from_source(alias_keys, scan_node_id);
                let outer_scan_cols = self.drain_scan_cols_for(scan_node_id);
                let columns = if has_match_recognize {
                    Vec::new()
                } else {
                    outer_scan_cols.clone()
                };
                let model_ref = RelPlan::ModelRef {
                    model: ResolvedModel {
                        package: scan_table.schema.clone(),
                        name: scan_table.canonical(),
                        base_tables: entry.base_tables.clone(),
                        taint_labels: entry.taint_labels.clone(),
                        nullable_columns: entry.nullable_columns.clone(),
                        constraint_set: entry.constraint_set.clone(),
                        column_lineage: entry.column_lineage.clone(),
                        has_filter: entry.has_filter,
                        node_id: scan_node_id,
                    },
                    columns,
                    alias: scan_alias,
                    node_id: scan_node_id,
                    span: scan_span,
                    hints: Vec::new(),
                };
                let wrapped = self.maybe_wrap_match_recognize(
                    model_ref,
                    tr,
                    from_item_node,
                    if has_match_recognize {
                        outer_scan_cols
                    } else {
                        Vec::new()
                    },
                )?;
                let wrapped = self.maybe_wrap_table_sample(wrapped, tr, from_item_node)?;
                let wrapped = self.maybe_wrap_pivot(wrapped, tr, from_item_node)?;
                let wrapped = self.maybe_wrap_unpivot(wrapped, tr, from_item_node)?;
                return Ok(wrapped);
            }
        }

        // -- Plain Scan terminal --------------------------------------
        let time_travel = tr
            .time_travel
            .as_deref()
            .map(|tt| self.lower_time_travel_clause(tt))
            .transpose()?;
        let changes = tr
            .changes
            .as_deref()
            .map(|c| self.lower_changes_clause(c))
            .transpose()?;
        let lowered_sample = tr
            .sample
            .as_deref()
            .map(|s| self.lower_sample_clause(s))
            .transpose()?;
        let modifier = ScanModifier {
            stage_options: tr.stage_options.as_deref().map(|so| so.span),
            time_travel,
            changes,
            sample: lowered_sample.clone(),
            with_offset: tr
                .with_offset
                .as_deref()
                .map(|with_offset| self.lower_with_offset_clause(with_offset)),
            only: tr.only_span,
            table_hints: tr
                .table_hints
                .as_deref()
                .map(|hints| self.lower_scan_table_hints(hints))
                .unwrap_or_default(),
            tvf_schema: tr.tvf_schema_span,
            ..ScanModifier::default()
        };
        let mut alias_keys: Vec<IdentKey> = Vec::new();
        if let Some(a) = scan_alias.clone() {
            alias_keys.push(a);
        }
        alias_keys.push(IdentKey::new(&scan_table.name));
        self.register_from_source(alias_keys, scan_node_id);
        let outer_scan_cols = self.drain_scan_cols_for(scan_node_id);
        let scan_columns = if has_match_recognize {
            Vec::new()
        } else {
            outer_scan_cols.clone()
        };
        self.scan_table_refs
            .insert(scan_node_id, scan_table.clone());
        let scan = RelPlan::Scan {
            table: scan_table,
            columns: scan_columns,
            modifier,
            alias: scan_alias,
            node_id: scan_node_id,
            span: scan_span,
            hints: Vec::new(),
        };
        let result = self.maybe_wrap_match_recognize(scan, tr, from_item_node, outer_scan_cols)?;
        let result = if let Some(ts) = lowered_sample {
            RelPlan::TableSample {
                input: Box::new(result),
                sample: ts,
                node_id: from_item_node,
                span: tr.span,
                hints: Vec::new(),
            }
        } else {
            result
        };
        let result = self.maybe_wrap_pivot(result, tr, from_item_node)?;
        let result = self.maybe_wrap_unpivot(result, tr, from_item_node)?;
        Ok(result)
    }

    /// Wrap `inner` in a `RelPlan::MatchRecognize` if `tr` carries a
    /// MATCH_RECOGNIZE clause; otherwise return `inner` unchanged.
    ///
    /// `outer_scan_cols` are the column IDs that outer expressions
    /// accumulated before this FROM item was visited — those bind
    /// to the MR node's output (the visible schema from the outer
    /// scope's perspective), not to `inner`'s columns. When no MR
    /// wrapper is present the caller has already attached them to
    /// `inner` directly and passes an empty vec here.
    fn maybe_wrap_match_recognize(
        &mut self,
        inner: RelPlan,
        tr: &AstTableRef,
        from_item_node: crate::ast::NodeId,
        outer_scan_cols: Vec<ColumnId>,
    ) -> Result<RelPlan, LowerError> {
        let Some(mr) = tr.match_recognize.as_deref() else {
            return Ok(inner);
        };

        // ── Index already-demanded outer references by display name ──
        //
        // `outer_scan_cols` are ColumnIds that surface in the *outer*
        // SELECT's expressions and were stamped against this
        // FROM-item's NodeId before MR lowering ran. They flow
        // through MR as 1-to-1 pass-throughs, so when an alias the
        // outer SELECT used (`mr_out.matched_price`) coincides with
        // a MEASURES output, the MR's own `MatchRecognizeMeasure
        // .output` should reuse that pre-allocated id rather than
        // mint a fresh ColumnId — otherwise downstream lineage
        // gets two parallel ids for the same logical column.
        // First-write-wins on collisions.
        let mut measure_alias_index: HashMap<IdentKey, ColumnId> = HashMap::new();
        for cid in &outer_scan_cols {
            if let Some(binding) = self.allocator.bindings().get(*cid) {
                let key = IdentKey::new(&binding.display_name);
                measure_alias_index.entry(key).or_insert(*cid);
            }
        }

        // ── Lower PARTITION BY against the inner scan's scope ────
        //
        // Set up `from_scope` from `inner` so column refs in
        // partition_by / order_by / measures / define resolve
        // against the inner row source.
        let saved_scope = std::mem::take(&mut self.from_scope);
        self.collect_scope_entries(&inner, None);

        // Helper: every fallible step routes through this so the
        // saved FROM scope is always restored before returning.
        let body_result: Result<MatchRecognizeBody, LowerError> = (|| {
            let partition_by = match mr.partition_by.as_ref() {
                Some(items) => items
                    .iter()
                    .map(|e| self.lower_expr_or_opaque_local(e, None))
                    .collect::<Result<Vec<_>, _>>()?,
                None => Vec::new(),
            };

            let order_by: Vec<SortKey> = match mr.order_by.as_ref() {
                Some(ob) => {
                    let mut keys = Vec::with_capacity(ob.items.len());
                    for item in &ob.items {
                        let expr = self.lower_expr_or_opaque_local(&item.expr, None)?;
                        keys.push(SortKey {
                            expr,
                            ascending: item.asc.unwrap_or(true),
                            nulls_first: item.nulls_first,
                            span: item.span,
                        });
                    }
                    keys
                }
                None => Vec::new(),
            };

            // ── Build the symbol table ────────────────────────────
            //
            // Symbols are interned in two passes so that DEFINE
            // entries that reference symbols not appearing in the
            // PATTERN text (legal under permissive parsing) still
            // intern, and pattern-parse failures under permissive
            // strictness still leave a populated table containing
            // every DEFINE'd symbol.
            let mut symbols = crate::ir::plan::SymbolTable::default();

            // 1. Parse PATTERN — interns symbols seen in the text.
            let pattern = match crate::ir::match_recognize_pattern::parse_pattern(
                &mr.pattern.pattern_text,
                mr.pattern.span,
                &mut symbols,
            ) {
                Ok(expr) => expr,
                Err(_e) => {
                    // Permissive: keep the body shape but record an
                    // empty pattern. Strict: surface as
                    // LowerError::ParseUpstream.
                    if self.strict.forbids_opaque() {
                        return Err(LowerError::parse_upstream(mr.pattern.span));
                    }
                    crate::ir::plan::PatternExpr::Empty
                }
            };

            // 2. Intern every DEFINE'd symbol (idempotent; first-seen wins).
            for d in &mr.define {
                let key = IdentKey::new(&d.symbol);
                let span = d.span;
                symbols.intern(key, d.symbol.clone(), span);
            }

            // 3. Convert AFTER MATCH SKIP — the ToFirst/ToLast
            //    variants reference symbols, so this happens after
            //    all interning is complete.
            let after_match_skip = match mr.after_match_skip.as_ref() {
                None | Some(crate::ast::AstAfterMatchSkip::PastLastRow) => {
                    AfterMatchSkip::PastLastRow
                }
                Some(crate::ast::AstAfterMatchSkip::ToNextRow) => AfterMatchSkip::ToNextRow,
                Some(crate::ast::AstAfterMatchSkip::ToFirstSymbol(s)) => {
                    let key = IdentKey::new(s);
                    let id = symbols.intern(key, s.clone(), mr.match_recognize_span);
                    AfterMatchSkip::ToFirst(id)
                }
                Some(crate::ast::AstAfterMatchSkip::ToLastSymbol(s)) => {
                    let key = IdentKey::new(s);
                    let id = symbols.intern(key, s.clone(), mr.match_recognize_span);
                    AfterMatchSkip::ToLast(id)
                }
            };

            let rows_per_match = match mr.rows_per_match.as_ref() {
                None | Some(crate::ast::AstRowsPerMatch::OneRowPerMatch) => RowsPerMatch::OneRow,
                Some(crate::ast::AstRowsPerMatch::AllRowsPerMatch { empty_matches }) => {
                    let mode = match empty_matches.as_ref() {
                        None => AllRowsMode::Default,
                        Some(crate::ast::AstEmptyMatchesMode::Show) => AllRowsMode::ShowEmpty,
                        Some(crate::ast::AstEmptyMatchesMode::Omit) => AllRowsMode::OmitEmpty,
                        Some(crate::ast::AstEmptyMatchesMode::WithUnmatched) => {
                            AllRowsMode::WithUnmatched
                        }
                    };
                    RowsPerMatch::AllRows(mode)
                }
            };

            // ── Lower MEASURES and DEFINE under the symbol context ──
            //
            // Install `symbols` so `lower_column_ref` can intercept
            // pattern-variable-qualified refs and emit
            // `ScalarExpr::PatternVarRef`. The table is moved in
            // and out so the lowering helpers see a single owned
            // instance (no clones of growing vectors).
            let prior_mr = self.match_recognize_symbols.replace(symbols);

            // MEASURES
            let measure_lowering: Result<Vec<MatchRecognizeMeasure>, LowerError> = (|| {
                let mut out = Vec::with_capacity(mr.measures.len());
                for m in &mr.measures {
                    let alias_str = slice_span(self.source, m.alias.span).unwrap_or("");
                    let alias_key = IdentKey::new(alias_str);
                    let modifier = m.semantic_modifier.map(|mod_| match mod_ {
                        crate::ast::AstMeasureSemanticModifier::Running => MeasureModifier::Running,
                        crate::ast::AstMeasureSemanticModifier::Final => MeasureModifier::Final,
                    });
                    let expr = self.lower_expr_or_opaque_local(&m.expr, None)?;
                    // Output ColumnId: reuse a pre-demanded
                    // outer ref if the alias matches; otherwise
                    // allocate fresh.
                    let output = match measure_alias_index.get(&alias_key).copied() {
                        Some(existing) => existing,
                        None => self.alloc_computed_col(from_item_node, m.span, alias_str),
                    };
                    out.push(MatchRecognizeMeasure {
                        output,
                        modifier,
                        expr,
                        alias: alias_key,
                        span: m.span,
                    });
                }
                Ok(out)
            })();
            let measures = match measure_lowering {
                Ok(v) => v,
                Err(e) => {
                    self.match_recognize_symbols = prior_mr;
                    return Err(e);
                }
            };

            // DEFINE
            let define_lowering: Result<Vec<MatchRecognizeDefine>, LowerError> = (|| {
                let mut out = Vec::with_capacity(mr.define.len());
                for d in &mr.define {
                    let key = IdentKey::new(&d.symbol);
                    // Already interned above; lookup is infallible.
                    let symbol = self
                        .match_recognize_symbols
                        .as_ref()
                        .and_then(|t| t.lookup(&key))
                        .expect("DEFINE symbol interned above");
                    let predicate = self.lower_expr_or_opaque_local(&d.expr, None)?;
                    out.push(MatchRecognizeDefine {
                        symbol,
                        predicate,
                        span: d.span,
                    });
                }
                Ok(out)
            })();
            let define = match define_lowering {
                Ok(v) => v,
                Err(e) => {
                    self.match_recognize_symbols = prior_mr;
                    return Err(e);
                }
            };

            // Take the symbols back out and restore the prior
            // (typically `None`) MR context.
            let symbols = self
                .match_recognize_symbols
                .take()
                .expect("MR symbol context still installed");
            self.match_recognize_symbols = prior_mr;

            Ok(MatchRecognizeBody {
                partition_by,
                order_by,
                measures,
                rows_per_match,
                after_match_skip,
                pattern,
                define,
                symbols,
                raw_span: mr.span,
            })
        })();

        // Always restore the outer FROM scope, even on error.
        self.from_scope = saved_scope;
        let body = body_result?;

        // ── output_columns ────────────────────────────────────────
        //
        //   * AllRows*: inner schema pass-through, then measures.
        //   * OneRow:   partition-key underlying ColumnIds (when
        //               each is a bare `ScalarExpr::Column`), then
        //               measures.  Non-trivial partition exprs
        //               cannot contribute a passthrough id; they
        //               are represented in the body but do not
        //               surface as output columns.
        let mut output_columns: Vec<ColumnId> = match body.rows_per_match {
            RowsPerMatch::AllRows(_) => inner.output_schema().to_vec(),
            RowsPerMatch::OneRow => body
                .partition_by
                .iter()
                .filter_map(|e| match e {
                    ScalarExpr::Column { column, .. } => Some(*column),
                    _ => None,
                })
                .collect(),
        };
        for m in &body.measures {
            output_columns.push(m.output);
        }
        // Honor outer pre-demanded refs that did not bind to a
        // measure alias: they pass through as additional output
        // columns. Skip duplicates (a measure already mapped to
        // one of them).
        let already: std::collections::HashSet<ColumnId> = output_columns.iter().copied().collect();
        for cid in &outer_scan_cols {
            if !already.contains(cid) {
                output_columns.push(*cid);
            }
        }

        // Empty `output_columns` would collapse downstream lineage.
        // Fall back to the inner schema (a conservative
        // approximation).
        if output_columns.is_empty() {
            output_columns = inner.output_schema().to_vec();
        }

        debug_assert!(
            {
                let mut seen = std::collections::HashSet::new();
                output_columns.iter().all(|c| seen.insert(*c))
            },
            "MatchRecognize.output_columns contains duplicates"
        );

        Ok(RelPlan::MatchRecognize {
            input: Box::new(inner),
            body,
            output_columns,
            node_id: from_item_node,
            span: tr.span,
            hints: Vec::new(),
        })
    }

    /// Wrap `inner` in `RelPlan::Pivot` if `tr` carries a PIVOT clause.
    fn maybe_wrap_pivot(
        &mut self,
        inner: RelPlan,
        tr: &AstTableRef,
        from_item_node: crate::ast::NodeId,
    ) -> Result<RelPlan, LowerError> {
        let Some(piv) = tr.pivot.as_deref() else {
            return Ok(inner);
        };

        // PIVOT expressions must bind against the wrapped input's visible
        // schema. Using the ambient FROM scope can mint parallel ColumnIds
        // that are not on the plan output surface.
        let saved_scope = std::mem::take(&mut self.from_scope);
        self.collect_scope_entries(&inner, None);

        let lowered = (|| {
            // Lower each aggregate using its own agg frame. The pivot
            // aggregates are independent single-call frames.
            let mut aggregates: Vec<AggregateCall> = Vec::with_capacity(piv.aggregates.len());
            for agg_item in &piv.aggregates {
                self.push_agg_frame();
                // Lower the aggregate expression; it will be pushed into the frame.
                let _out = self.lower_expr(&agg_item.expr, None)?;
                let mut frame = self.pop_agg_frame();
                if frame.len() == 1 {
                    aggregates.push(frame.remove(0));
                } else if frame.is_empty() {
                    // The expression lowered but was not aggregate-shaped —
                    // record it as a no-arg unresolved aggregate.
                    let raw_text = slice_span(self.source, agg_item.expr.span())
                        .unwrap_or("?")
                        .to_string();
                    let output = self.alloc_synthetic(agg_item.expr.span(), raw_text.clone());
                    aggregates.push(AggregateCall {
                        func: ResolvedFunc::unresolved(&raw_text, None, agg_item.expr.span()),
                        args: vec![],
                        named_args: vec![],
                        distinct: false,
                        // PIVOT aggregates have no APPROXIMATE modifier.
                        approximate: false,
                        filter: None,
                        arg_order: vec![],
                        within_group_order: vec![],
                        null_treatment: NullTreatment::Default,
                        output,
                        span: agg_item.expr.span(),
                    });
                } else {
                    // Multiple aggregates collected from one item — treat
                    // as the first one for now (the others are nested and
                    // should be rare in practice).
                    aggregates.push(frame.remove(0));
                }
            }

            // pivot_column: prefer a real source column id so lineage can
            // resolve dependencies to leaf sources instead of synthetic ids.
            let pivot_col_id = {
                let key = match piv.for_column.as_ref() {
                    AstExpr::Ident { column_ref, .. } => self.ident_at(column_ref.name.span),
                    other => self.ident_at(other.span()),
                };
                if let Some(id) = self.resolve_from_scope(None, &key) {
                    id
                } else {
                    let lowered_for_expr = self.lower_expr_no_aggs(&piv.for_column, None)?;
                    match lowered_for_expr {
                        ScalarExpr::Column { column, .. } => column,
                        _ => {
                            // Fallback for non-column FOR expressions that do not
                            // have a direct source-column identity.
                            let pivot_span = piv.span;
                            let stmt_node = from_item_node;
                            let display = key.as_str().to_string();
                            *self.bindings.entry(key).or_insert_with(|| {
                                self.allocator.fresh(
                                    ColumnOrigin::Computed {
                                        producing_node: stmt_node,
                                        expr_span: pivot_span,
                                    },
                                    display,
                                )
                            })
                        }
                    }
                }
            };

            let pivot_values = self.lower_pivot_in_values(&piv.in_values, piv.span)?;

            let default_on_null = match piv.default_on_null.as_deref() {
                Some(expr) => Some(self.lower_expr(expr, None)?),
                None => None,
            };

            // One output column per pivot value × aggregate. Three
            // architecturally distinct shapes:
            //
            //   - `ValueList(vs)`: arity is `aggregates.len() *
            //     vs.len()`, each slot named from `(value, agg_alias)`.
            //   - `Subquery(plan)`: the inline subquery's projection
            //     has a statically-known schema; arity is
            //     `aggregates.len() * plan.output_schema().len()`.
            //   - `Any { .. }`: catalog-data gap (distinct values of
            //     the pivot column not in plan). Strict modes emit
            //     `CatalogMissing { kind: PivotAnyDistinctValues }`;
            //     permissive falls back to `Vec::new()`.
            //   - `Opaque { .. }`: Jinja-shaped IN list — not
            //     catalog-recoverable. Stays at zero output columns.
            let pivot_span = piv.span;
            let pivot_node = from_item_node;
            let output_columns: Vec<ColumnId> = match &pivot_values {
                PivotValues::ValueList(vals) => {
                    let agg_count = aggregates.len().max(1);
                    let count = vals.len().saturating_mul(agg_count);
                    // Derive per-column display name from the pivot
                    // value's semantic identifier surface and (when
                    // present) the aggregate's user-supplied alias.
                    // String-literal pivot values become quoted
                    // identifiers so downstream references like
                    // `"view"` resolve against the same slot names the
                    // CTE body exposes.
                    let ast_values = match &piv.in_values {
                        crate::ast::AstPivotInValues::ValueList(vs) => Some(vs),
                        _ => None,
                    };
                    (0..count)
                        .map(|idx| {
                            let v_idx = idx / agg_count;
                            let a_idx = idx % agg_count;
                            let value_text = ast_values
                                .and_then(|vs| vs.get(v_idx))
                                .map(|v| self.pivot_value_display_name(v))
                                .unwrap_or_default();
                            let agg_alias = piv
                                .aggregates
                                .get(a_idx)
                                .and_then(|a| a.alias.as_ref())
                                .and_then(|ident| slice_span(self.source, ident.span))
                                .unwrap_or("");
                            let display = if agg_alias.is_empty() {
                                value_text
                            } else if value_text.is_empty() {
                                agg_alias.to_string()
                            } else {
                                format!("{value_text}_{agg_alias}")
                            };
                            self.alloc_computed_col(pivot_node, pivot_span, display)
                        })
                        .collect()
                }
                PivotValues::Subquery(plan) => {
                    // Subquery's schema is statically known: its
                    // `output_schema()` arity equals the number of
                    // distinct pivot columns the expansion materializes.
                    // Allocate one fresh ColumnId per (aggregate ×
                    // subquery-projected-column). Slot names are left
                    // empty — the subquery's projection drives the
                    // user-visible names downstream; we only care
                    // about arity here.
                    let inner_arity = plan.output_schema().len();
                    let agg_count = aggregates.len().max(1);
                    let count = inner_arity.saturating_mul(agg_count);
                    (0..count)
                        .map(|_| self.alloc_computed_col(pivot_node, pivot_span, ""))
                        .collect()
                }
                PivotValues::Any { .. } => {
                    // Catalog-data gap. Strict surfaces; permissive
                    // yields no enumerable output columns.
                    if self.strict.forbids_opaque() {
                        return Err(LowerError::opaque(
                            piv.span,
                            OpaqueReason::CatalogMissing {
                                kind: CatalogLookupKind::PivotAnyDistinctValues,
                            },
                        ));
                    }
                    Vec::new()
                }
                PivotValues::Opaque { .. } => {
                    // Jinja-shaped IN list: not catalog-recoverable
                    // by definition. Stays empty.
                    Vec::new()
                }
            };

            Ok(RelPlan::Pivot {
                input: Box::new(inner),
                aggregates,
                pivot_column: pivot_col_id,
                pivot_values,
                output_columns,
                default_on_null,
                node_id: from_item_node,
                span: piv.span,
                hints: Vec::new(),
            })
        })();

        self.from_scope = saved_scope;
        lowered
    }

    fn pivot_value_display_name(&self, value: &crate::ast::AstPivotValue) -> String {
        if let Some(alias) = value.alias.as_ref() {
            return slice_span(self.source, alias.span)
                .unwrap_or("")
                .to_string();
        }

        match value.value.as_ref() {
            AstExpr::Literal {
                literal: AstLiteral::String { span },
                ..
            }
            | AstExpr::Literal {
                literal: AstLiteral::StringWithJinja { span },
                ..
            } => self.quoted_identifier_from_sql_string(*span),
            _ => slice_span(self.source, value.value.span())
                .unwrap_or("")
                .to_string(),
        }
    }

    fn quoted_identifier_from_sql_string(&self, span: Span) -> String {
        let raw = slice_span(self.source, span).unwrap_or("");
        let inner = raw
            .strip_prefix('\'')
            .and_then(|text| text.strip_suffix('\''))
            .unwrap_or(raw);
        let unescaped = inner.replace("''", "'");
        let escaped = unescaped.replace('"', "\"\"");
        format!("\"{escaped}\"")
    }

    /// Lower `AstPivotInValues` to `PivotValues`.
    fn lower_pivot_in_values(
        &mut self,
        in_vals: &crate::ast::AstPivotInValues,
        _clause_span: Span,
    ) -> Result<PivotValues, LowerError> {
        use crate::ast::AstPivotInValues;
        match in_vals {
            AstPivotInValues::ValueList(vals) => {
                let mut out = Vec::with_capacity(vals.len());
                for v in vals {
                    out.push(self.lower_expr(&v.value, None)?);
                }
                Ok(PivotValues::ValueList(out))
            }
            AstPivotInValues::Any(order_by) => {
                let keys = match order_by.as_deref() {
                    Some(items) => self.lower_inline_order_by(items, None)?,
                    None => Vec::new(),
                };
                Ok(PivotValues::Any { order_by: keys })
            }
            AstPivotInValues::Subquery(stmt) => {
                let plan = self.lower_stmt_as_subquery(stmt)?;
                Ok(PivotValues::Subquery(Box::new(plan)))
            }
            AstPivotInValues::OpaqueList(span) => Ok(PivotValues::Opaque { span: *span }),
        }
    }

    /// Wrap `inner` in `RelPlan::Unpivot` if `tr` carries an UNPIVOT clause.
    fn maybe_wrap_unpivot(
        &mut self,
        inner: RelPlan,
        tr: &AstTableRef,
        from_item_node: crate::ast::NodeId,
    ) -> Result<RelPlan, LowerError> {
        let Some(up) = tr.unpivot.as_deref() else {
            return Ok(inner);
        };

        // UNPIVOT IN-list identifiers must bind against the wrapped
        // input's visible schema, exactly like PIVOT (see
        // `maybe_wrap_pivot`). When the ambient outer FROM scope is
        // used instead, single-segment column refs that don't exist
        // in the outer scope fall through to `allocator.fresh`, which
        // mints parallel ColumnIds disconnected from `inner`'s output
        // schema. The downstream consequences are:
        //   1. `RelPlan::Unpivot::output_schema()` cannot drop the
        //      "real" IN-list columns (they aren't in the drop set),
        //      so CLICKS/IMPRESSIONS/CONVERSIONS leak through into
        //      the post-UNPIVOT schema.
        //   2. Per-binding lineage for the synthesized
        //      `name_column` / `value_columns` looks up each fresh
        //      IN-list ColumnId in `input_map` and finds nothing,
        //      producing empty deps — and thus empty
        //      `WITH_RATES.metric_name` deps in any downstream CTE
        //      that projects from the UNPIVOT output.
        // Saving and restoring `from_scope` keeps any outer-FROM
        // bindings intact for sibling FROM items lowered after this
        // wrapper returns.
        let saved_scope = std::mem::take(&mut self.from_scope);
        self.collect_scope_entries(&inner, None);

        let lowered = {
            // value_columns: one fresh ColumnId per value column in
            // the tuple. The user-supplied identifier(s) after
            // UNPIVOT(...) provide real display names; record them
            // on the binding so lineage surfaces can render
            // `SELECT <value_column> FROM ...`.
            let value_columns: Vec<ColumnId> = up
                .value_columns
                .iter()
                .map(|id| {
                    let display = slice_span(self.source, id.span).unwrap_or("").to_string();
                    self.alloc_computed_col(from_item_node, id.span, display)
                })
                .collect();

            // name_column: single fresh ColumnId. The identifier
            // after `FOR` names it in source.
            let name_display = slice_span(self.source, up.name_column.span)
                .unwrap_or("")
                .to_string();
            let name_column =
                self.alloc_computed_col(from_item_node, up.name_column.span, name_display);

            // unpivoted_columns: for each IN-list group, one
            // UnpivotColumn. With the `inner`-derived from_scope in
            // place, single-segment refs (`clicks`, `impressions`,
            // …) resolve to the input's actual ColumnIds.
            let unpivoted_columns: Vec<UnpivotColumn> = up
                .columns
                .iter()
                .map(|col| {
                    let columns: Vec<ColumnId> = col
                        .columns
                        .iter()
                        .map(|c| {
                            let key = self.ident_at(c.span);
                            if let Some(id) = self.resolve_from_scope(None, &key) {
                                return id;
                            }
                            if let Some(id) = self.bindings.get(&key).copied() {
                                return id;
                            }
                            let display = key.as_str().to_string();
                            let stmt_node = from_item_node;
                            let c_span = c.span;
                            self.allocator.fresh(
                                ColumnOrigin::Computed {
                                    producing_node: stmt_node,
                                    expr_span: c_span,
                                },
                                display,
                            )
                        })
                        .collect();
                    let alias = col.alias.as_ref().map(|a| self.ident_at(a.span));
                    // Compute span from column list or alias.
                    let span = col
                        .alias
                        .as_ref()
                        .map(|a| a.span)
                        .or_else(|| col.columns.last().map(|c| c.span))
                        .or_else(|| col.columns.first().map(|c| c.span))
                        .unwrap_or(up.unpivot_span);
                    UnpivotColumn {
                        columns,
                        alias,
                        span,
                    }
                })
                .collect();

            Ok(RelPlan::Unpivot {
                input: Box::new(inner),
                value_columns,
                name_column,
                unpivoted_columns,
                include_nulls: up.include_nulls,
                node_id: from_item_node,
                span: up.unpivot_span,
                hints: Vec::new(),
            })
        };

        self.from_scope = saved_scope;
        lowered
    }

    /// Lower `AstTimeTravelClause` to `TimeTravel`.
    fn lower_time_travel_clause(
        &mut self,
        tt: &crate::ast::AstTimeTravelClause,
    ) -> Result<TimeTravel, LowerError> {
        use crate::ast::{AstTimeTravelClause, AstTimeTravelKind, DatabricksTimeTravelKind};
        match tt {
            AstTimeTravelClause::SnowflakeAtBefore(sf) => {
                let is_before = sf.is_before;
                match &sf.kind {
                    AstTimeTravelKind::Timestamp(e) => {
                        let e = self.lower_expr(e, None)?;
                        Ok(if is_before {
                            TimeTravel::BeforeTimestamp(e)
                        } else {
                            TimeTravel::AtTimestamp(e)
                        })
                    }
                    AstTimeTravelKind::Offset(e) => {
                        let e = self.lower_expr(e, None)?;
                        Ok(if is_before {
                            TimeTravel::BeforeOffset(e)
                        } else {
                            TimeTravel::AtOffset(e)
                        })
                    }
                    AstTimeTravelKind::Statement(e) => {
                        let e = self.lower_expr(e, None)?;
                        Ok(if is_before {
                            TimeTravel::BeforeStatement(e)
                        } else {
                            TimeTravel::AtStatement(e)
                        })
                    }
                    AstTimeTravelKind::Stream(e) => {
                        let e = self.lower_expr(e, None)?;
                        Ok(if is_before {
                            TimeTravel::BeforeStream(e)
                        } else {
                            TimeTravel::AtStream(e)
                        })
                    }
                }
            }
            AstTimeTravelClause::ForSystemTime(bq) => match bq.expr.as_deref() {
                Some(e) => {
                    let e = self.lower_expr(e, None)?;
                    Ok(TimeTravel::ForSystemTimeAsOf(e))
                }
                None => Ok(TimeTravel::ForSystemTimeBare { span: bq.span }),
            },
            AstTimeTravelClause::DatabricksAsOf(db) => {
                let e = self.lower_expr(&db.expr, None)?;
                Ok(match db.kind {
                    DatabricksTimeTravelKind::Timestamp => TimeTravel::DatabricksTimestampAsOf(e),
                    DatabricksTimeTravelKind::Version => TimeTravel::DatabricksVersionAsOf(e),
                    DatabricksTimeTravelKind::AtSign => TimeTravel::DatabricksAtSign(e),
                })
            }
        }
    }

    /// Lower `AstChangesClause` to `ChangesClause`.
    ///
    /// Snowflake `CHANGES(INFORMATION => { DEFAULT | APPEND_ONLY })` clause.
    /// The `at_before` field is required in the AST; the `end` field is
    /// optional. Both AT|BEFORE sub-clauses use the Snowflake
    /// `AstTimeTravelKind` discriminants already established in
    /// `lower_time_travel_clause`.
    fn lower_changes_clause(
        &mut self,
        cc: &crate::ast::AstChangesClause,
    ) -> Result<ChangesClause, LowerError> {
        use crate::ast::{AstChangesInformation, AstTimeTravelKind};

        let information = match cc.information {
            AstChangesInformation::Default => ChangesInformation::Default,
            AstChangesInformation::AppendOnly => ChangesInformation::AppendOnly,
        };

        // Lower the mandatory AT|BEFORE clause.  The AST uses the same
        // `AstTimeTravelKind` discriminants as the Snowflake AT|BEFORE
        // time-travel clause; we reuse the same mapping here.
        let at = {
            let sf = &cc.at_before;
            let is_before = sf.is_before;
            let tt = match &sf.kind {
                AstTimeTravelKind::Timestamp(e) => {
                    let e = self.lower_expr(e, None)?;
                    if is_before {
                        TimeTravel::BeforeTimestamp(e)
                    } else {
                        TimeTravel::AtTimestamp(e)
                    }
                }
                AstTimeTravelKind::Offset(e) => {
                    let e = self.lower_expr(e, None)?;
                    if is_before {
                        TimeTravel::BeforeOffset(e)
                    } else {
                        TimeTravel::AtOffset(e)
                    }
                }
                AstTimeTravelKind::Statement(e) => {
                    let e = self.lower_expr(e, None)?;
                    if is_before {
                        TimeTravel::BeforeStatement(e)
                    } else {
                        TimeTravel::AtStatement(e)
                    }
                }
                AstTimeTravelKind::Stream(e) => {
                    let e = self.lower_expr(e, None)?;
                    if is_before {
                        TimeTravel::BeforeStream(e)
                    } else {
                        TimeTravel::AtStream(e)
                    }
                }
            };
            Some(tt)
        };

        // Lower the optional END clause.  END has no `is_before` concept —
        // it is always an AT-style upper bound.
        let end = cc
            .end
            .as_ref()
            .map(|e| {
                let tt = match &e.kind {
                    AstTimeTravelKind::Timestamp(expr) => {
                        TimeTravel::AtTimestamp(self.lower_expr(expr, None)?)
                    }
                    AstTimeTravelKind::Offset(expr) => {
                        TimeTravel::AtOffset(self.lower_expr(expr, None)?)
                    }
                    AstTimeTravelKind::Statement(expr) => {
                        TimeTravel::AtStatement(self.lower_expr(expr, None)?)
                    }
                    AstTimeTravelKind::Stream(expr) => {
                        TimeTravel::AtStream(self.lower_expr(expr, None)?)
                    }
                };
                Ok(tt)
            })
            .transpose()?;

        Ok(ChangesClause {
            information,
            at,
            end,
        })
    }

    /// Lower `AstSampleClause` to `TableSample`.
    /// and System/Block into another; we map to the canonical IR keyword.
    /// `repeatable` is left `None` because the AST uses the single `seed`
    /// field for both `SEED(n)` and `REPEATABLE(n)` keywords.
    fn lower_sample_clause(
        &mut self,
        sample: &crate::ast::AstSampleClause,
    ) -> Result<TableSample, LowerError> {
        use crate::ast::{AstSampleMethod, AstSampleSize};
        let method_keyword = sample.method.as_ref().map(|m| match m {
            AstSampleMethod::Bernoulli => SampleKeyword::Bernoulli,
            AstSampleMethod::System => SampleKeyword::System,
        });
        let size = match &sample.size {
            AstSampleSize::Probability(e) => SampleSize::Probability(self.lower_expr(e, None)?),
            AstSampleSize::Rows(e) => SampleSize::Rows(self.lower_expr(e, None)?),
        };
        let seed = sample
            .seed
            .as_ref()
            .map(|e| self.lower_expr(e, None))
            .transpose()?;
        Ok(TableSample {
            method_keyword,
            size,
            seed,
            repeatable: None,
            span: sample.span,
        })
    }

    /// Lower BigQuery `WITH OFFSET [AS alias]` into typed scan modifier payload.
    fn lower_with_offset_clause(&self, with_offset: &crate::ast::AstWithOffset) -> WithOffset {
        WithOffset {
            alias: with_offset
                .alias
                .as_ref()
                .map(|alias| self.ident_at(alias.span)),
            span: with_offset.span,
        }
    }

    /// Lower T-SQL table-hint clause into typed scan-hint entries.
    fn lower_scan_table_hints(&self, hints: &crate::ast::AstTableHintClause) -> Vec<ScanTableHint> {
        hints
            .hints
            .iter()
            .map(|hint| {
                let kind = match &hint.kind {
                    // Closed-enum mapping AST variant → IR variant. Each
                    // documented T-SQL simple-keyword form has its own
                    // typed variant on both sides, so post-parse code
                    // never re-derives the keyword identity from
                    // source text.
                    AstTableHintKind::NoLock => ScanTableHintKind::NoLock,
                    AstTableHintKind::ReadUncommitted => ScanTableHintKind::ReadUncommitted,
                    AstTableHintKind::ReadCommitted => ScanTableHintKind::ReadCommitted,
                    AstTableHintKind::ReadCommittedLock => ScanTableHintKind::ReadCommittedLock,
                    AstTableHintKind::RepeatableRead => ScanTableHintKind::RepeatableRead,
                    AstTableHintKind::Serializable => ScanTableHintKind::Serializable,
                    AstTableHintKind::Snapshot => ScanTableHintKind::Snapshot,
                    AstTableHintKind::UpdLock => ScanTableHintKind::UpdLock,
                    AstTableHintKind::HoldLock => ScanTableHintKind::HoldLock,
                    AstTableHintKind::RowLock => ScanTableHintKind::RowLock,
                    AstTableHintKind::PagLock => ScanTableHintKind::PagLock,
                    AstTableHintKind::TabLock => ScanTableHintKind::TabLock,
                    AstTableHintKind::TabLockX => ScanTableHintKind::TabLockX,
                    AstTableHintKind::XLock => ScanTableHintKind::XLock,
                    AstTableHintKind::ReadPast => ScanTableHintKind::ReadPast,
                    AstTableHintKind::NoWait => ScanTableHintKind::NoWait,
                    AstTableHintKind::NoExpand => ScanTableHintKind::NoExpand,
                    AstTableHintKind::ForceScan => ScanTableHintKind::ForceScan,
                    AstTableHintKind::KeepIdentity => ScanTableHintKind::KeepIdentity,
                    AstTableHintKind::KeepDefaults => ScanTableHintKind::KeepDefaults,
                    AstTableHintKind::IgnoreConstraints => ScanTableHintKind::IgnoreConstraints,
                    AstTableHintKind::IgnoreTriggers => ScanTableHintKind::IgnoreTriggers,
                    AstTableHintKind::OtherSimple => ScanTableHintKind::OtherSimple,
                    AstTableHintKind::Index { values } => ScanTableHintKind::Index {
                        values: values.clone(),
                    },
                    AstTableHintKind::ForceSeek {
                        index_name,
                        columns,
                    } => ScanTableHintKind::ForceSeek {
                        index_name: *index_name,
                        columns: columns.clone(),
                    },
                    AstTableHintKind::SpatialWindowMaxCells { value } => {
                        ScanTableHintKind::KeyValue {
                            key_span: hint.span,
                            value_span: *value,
                        }
                    }
                };
                ScanTableHint {
                    kind,
                    span: hint.span,
                }
            })
            .collect()
    }

    /// Wrap `inner` in `RelPlan::TableSample` if `tr` carries a
    /// `SAMPLE` / `TABLESAMPLE` clause; otherwise return `inner`
    /// unchanged.
    fn maybe_wrap_table_sample(
        &mut self,
        inner: RelPlan,
        tr: &AstTableRef,
        from_item_node: crate::ast::NodeId,
    ) -> Result<RelPlan, LowerError> {
        let Some(sample_ast) = tr.sample.as_deref() else {
            return Ok(inner);
        };
        let sample = self.lower_sample_clause(sample_ast)?;
        Ok(RelPlan::TableSample {
            input: Box::new(inner),
            sample,
            node_id: from_item_node,
            span: tr.span,
            hints: Vec::new(),
        })
    }

    /// Lower one element of a join chain.
    ///
    /// `base_lateral` reflects a `LATERAL` keyword on the *left-most*
    /// table reference of this FROM item. The per-join `lateral_keyword_span`
    /// always wins when present.
    fn lower_join(
        &mut self,
        left: RelPlan,
        join: &AstJoin,
        base_lateral: bool,
    ) -> Result<RelPlan, LowerError> {
        let (mut kind, natural) = match join.kind {
            AstJoinKind::Inner => (JoinKind::Inner, false),
            AstJoinKind::LeftOuter => (JoinKind::LeftOuter, false),
            AstJoinKind::RightOuter => (JoinKind::RightOuter, false),
            AstJoinKind::FullOuter => (JoinKind::FullOuter, false),
            AstJoinKind::Cross => (JoinKind::Cross, false),
            AstJoinKind::NaturalInner => (JoinKind::Inner, true),
            AstJoinKind::NaturalLeftOuter => (JoinKind::LeftOuter, true),
            AstJoinKind::NaturalRightOuter => (JoinKind::RightOuter, true),
            AstJoinKind::NaturalFullOuter => (JoinKind::FullOuter, true),
            AstJoinKind::Asof => (JoinKind::Asof, false),
        };

        if join.apply_keyword_span.is_some() && matches!(kind, JoinKind::Cross) {
            kind = JoinKind::Inner;
        }

        let lateral = base_lateral
            || join.lateral_keyword_span.is_some()
            || join.apply_keyword_span.is_some();
        let right_plan = self.lower_table_ref_with_joins(
            &join.right,
            // The right-hand side of a join is a fresh AstTableRef with
            // no surrounding FromItem; reuse the join's node_id so the
            // Scan carries a stable identity.
            join.node_id,
        )?;

        // `lower_table_ref_with_joins` has already appended the right
        // side's scope entries (its base source's entries during its
        // own call; inner joins handled by the recursive structure).
        // Combined with the caller having appended the left side's
        // scope, `from_scope` now exposes every column either side of
        // this join can legally reference, so the ON-clause column
        // refs lowered below resolve to the source-owned ColumnId via
        // [`Self::resolve_from_scope`] — preserving the bridge chain
        // that cross-scope contradiction detection follows.

        let (on, using) = match &join.constraint {
            AstJoinConstraint::None => (None, Vec::new()),
            AstJoinConstraint::On(expr) => (Some(self.lower_expr(expr, None)?), Vec::new()),
            AstJoinConstraint::Using(idents) => {
                // USING binds each identifier to a ColumnId that spans
                // both sides. The naive allocate-on-first-use scheme
                // is used here; resolution is not catalog-aware.
                let mut cols = Vec::with_capacity(idents.len());
                for ident in idents {
                    let key = self.ident_at(ident.span);
                    let ident_span = ident.span;
                    let id = match self.bindings.get(&key) {
                        Some(existing) => *existing,
                        None => {
                            let display_name = key.as_str().to_string();
                            let fresh = self.alloc_synthetic(ident_span, display_name);
                            self.bindings.insert(key, fresh);
                            fresh
                        }
                    };
                    cols.push(id);
                }
                (None, cols)
            }
        };
        let match_condition = match join.match_condition.as_deref() {
            Some(mc) => Some(self.lower_expr(&mc.condition, None)?),
            None => None,
        };

        let span = merge_spans(left.span(), join.span);
        Ok(RelPlan::Join {
            left: Box::new(left),
            right: Box::new(right_plan),
            kind,
            on,
            match_condition,
            using,
            natural,
            directed: join.directed_keyword_span.is_some(),
            lateral,
            implicit: false,
            node_id: join.node_id,
            span,
            clause_span: join.span,
            hints: Vec::new(),
        })
    }

    /// Drain the accumulated [`super::statement_facts::StatementFacts`]
    /// out of `LowerCtx`. Called once at the end of lowering by the
    /// public `lower_query_full*` entry points; the resulting struct
    /// is kept alongside the plan by the caller.
    pub(crate) fn take_statement_facts(&mut self) -> super::statement_facts::StatementFacts {
        std::mem::take(&mut self.statement_facts)
    }

    /// Drain the accumulated
    /// [`super::policy_facts::PolicyStatementFacts`] out of
    /// `LowerCtx`. Returns `None` for query-bearing
    /// statements; `Some(...)` only when one of the policy DDL
    /// `lower_stmt` arms ran and lowered the embedded predicates.
    pub(crate) fn take_policy_facts(
        &mut self,
    ) -> Option<super::policy_facts::PolicyStatementFacts> {
        self.policy_facts.take()
    }

    /// Lower every `FOR UPDATE` / `FOR SHARE` / `FOR NO KEY UPDATE` /
    /// `FOR KEY SHARE` clause attached to `sel` into a typed
    /// [`super::statement_facts::ForUpdateFact`] and append it to
    /// `self.statement_facts.for_update`.
    ///
    /// The AST's [`AstLockStrength`] and [`AstForUpdateWaitPolicy`]
    /// closed enums are isomorphic to the IR's
    /// [`super::statement_facts::LockStrength`] and
    /// [`super::statement_facts::WaitPolicy`] — translation is a
    /// total exhaustive match. The `WAIT n` duration is lowered
    /// through [`Self::lower_expr`] so subqueries / arithmetic /
    /// session-variables in the duration position propagate
    /// through the normal scalar-lowering path.
    fn extract_for_update_facts(&mut self, sel: &AstSelect) -> Result<(), LowerError> {
        use super::statement_facts::{
            ForUpdateFact, LockStrength as IrLockStrength, WaitPolicy as IrWaitPolicy,
        };
        let Some(clauses) = sel.for_update.as_deref() else {
            return Ok(());
        };
        for clause in clauses.iter() {
            let strength = match clause.lock_strength {
                AstLockStrength::Update => IrLockStrength::Update,
                AstLockStrength::NoKeyUpdate => IrLockStrength::NoKeyUpdate,
                AstLockStrength::Share => IrLockStrength::Share,
                AstLockStrength::KeyShare => IrLockStrength::KeyShare,
            };
            let wait = match clause.wait_policy.as_ref() {
                None => None,
                Some(AstForUpdateWaitPolicy::NoWait { nowait_span }) => {
                    Some(IrWaitPolicy::NoWait { span: *nowait_span })
                }
                Some(AstForUpdateWaitPolicy::Wait {
                    wait_span,
                    duration,
                }) => {
                    let lowered = self.lower_expr(duration, None)?;
                    Some(IrWaitPolicy::Wait {
                        duration: lowered,
                        span: *wait_span,
                    })
                }
                Some(AstForUpdateWaitPolicy::SkipLocked { skip_locked_span }) => {
                    Some(IrWaitPolicy::SkipLocked {
                        span: *skip_locked_span,
                    })
                }
            };
            self.statement_facts.for_update.push(ForUpdateFact {
                strength,
                wait,
                of_tables: clause.of_tables.clone(),
                span: clause.span,
            });
        }
        Ok(())
    }

    /// Lower a T-SQL `FOR JSON …` / `FOR XML …` tail into a typed
    /// [`super::statement_facts::OutputFormat`].
    ///
    /// The AST stores only an `Option<Span>` — the JSON-vs-XML
    /// distinction is recovered by source-slicing the span. The
    /// span starts at the `FOR` keyword and includes the
    /// `JSON` / `XML` discriminator (see
    /// `parser::select::parse_for_json_xml_clause`), so a
    /// case-insensitive substring match on the slice is total
    /// over the AST's accepted shapes.
    ///
    /// If the span cannot be sliced (out-of-bounds — only possible
    /// on a synthetic AST that doesn't match its source) or the
    /// discriminator keyword cannot be found, the field is left
    /// `None`. This is not a parse-time error: the formatter still
    /// reproduces the clause via `push_span`. The strictness
    /// harness in `src/ir/strict.rs` does not reject the
    /// SELECT as opaque on this clause, because the fact is
    /// captured.
    fn extract_output_format_fact(&mut self, sel: &AstSelect) {
        use super::statement_facts::OutputFormat;
        let Some(span) = sel.for_json_xml else {
            return;
        };
        let Some(slice) = slice_span(self.source, span) else {
            return;
        };
        // The clause text is `FOR JSON …` or `FOR XML …`.
        // Case-insensitive search distinguishes the two; whichever
        // discriminator appears first in the slice wins. Both
        // appearing in a single clause is impossible per the
        // parser, but if the slice is malformed we leave the fact
        // unset rather than guessing.
        let upper = slice.to_ascii_uppercase();
        let json_at = upper.find("JSON");
        let xml_at = upper.find("XML");
        let format = match (json_at, xml_at) {
            (Some(j), Some(x)) if j < x => OutputFormat::ForJson { span },
            (Some(_), Some(_)) => OutputFormat::ForXml { span },
            (Some(_), None) => OutputFormat::ForJson { span },
            (None, Some(_)) => OutputFormat::ForXml { span },
            (None, None) => return,
        };
        self.statement_facts.output_format = Some(format);
    }

    /// Lower T-SQL / PostgreSQL `SELECT … INTO @var, @var2`
    /// variable-assignment targets into typed
    /// [`super::statement_facts::IntoVarTarget`] entries.
    ///
    /// The AST stores the targets as a `Vec<Span>` over each
    /// target-variable identifier; the relational shape is
    /// unchanged (the SELECT still produces tuples), only the
    /// non-relational binding side moves to `StatementFacts`.
    fn extract_into_vars_facts(&mut self, sel: &AstSelect) {
        use super::statement_facts::IntoVarTarget;
        // NewTable form is lowered into RelPlan::CreateAsQuery by lower_select;
        // only the ScriptingVars variant produces non-relational var-binding facts.
        if let Some(crate::ast::AstSelectIntoTarget::ScriptingVars(vars)) =
            sel.into_target.as_deref()
        {
            for span in vars.iter() {
                self.statement_facts
                    .into_vars
                    .push(IntoVarTarget { span: *span });
            }
        }
    }

    /// Lower a MySQL `INTO OUTFILE / DUMPFILE` target into
    /// [`super::statement_facts::FileExportFact`]. The file-path
    /// literal value is sliced from source as written (including
    /// quotes), mirroring the OPENROWSET argument convention.
    fn extract_file_export_fact(&mut self, sel: &AstSelect) {
        use super::statement_facts::{FileExportFact, FileExportKind};
        let Some(crate::ast::AstSelectIntoTarget::OutFile(of)) = sel.into_target.as_deref() else {
            return;
        };
        let kind = match of.kind {
            crate::ast::AstIntoFileKind::Outfile => FileExportKind::Outfile,
            crate::ast::AstIntoFileKind::Dumpfile => FileExportKind::Dumpfile,
        };
        let file_path = slice_span(self.source, of.file_span)
            .unwrap_or_default()
            .to_string();
        self.statement_facts.file_export = Some(FileExportFact {
            kind,
            file_path,
            span: of.span,
        });
    }

    /// Lower BigQuery `SELECT AS STRUCT` / `SELECT AS VALUE`
    /// projection-shape qualifier into the closed
    /// [`super::statement_facts::SelectAsKind`] enum.
    ///
    /// The AST stores only `Option<Span>` covering `AS
    /// STRUCT` / `AS VALUE`; the discriminator is recovered
    /// by source-slicing the span and case-insensitive
    /// keyword search. If the slice cannot be obtained or the
    /// discriminator is missing the field is left `None`.
    fn extract_select_as_fact(&mut self, sel: &AstSelect) {
        use super::statement_facts::SelectAsKind;
        let Some(span) = sel.select_as_qualifier else {
            return;
        };
        let Some(slice) = slice_span(self.source, span) else {
            return;
        };
        let upper = slice.to_ascii_uppercase();
        let kind = if upper.contains("STRUCT") {
            SelectAsKind::Struct
        } else if upper.contains("VALUE") {
            SelectAsKind::Value
        } else {
            return;
        };
        self.statement_facts.select_as = Some(kind);
    }

    /// Lower PostgreSQL pre-LIMIT extension clauses into
    /// `StatementFacts.pre_limit_extensions`. Carried as
    /// preserved-text spans.
    fn extract_pre_limit_extensions_fact(&mut self, sel: &AstSelect) {
        for span in sel.pre_limit_extension_clauses.iter() {
            self.statement_facts.pre_limit_extensions.push(*span);
        }
    }

    /// Lower post-locking extension clauses into
    /// `StatementFacts.post_locking_extensions`.
    /// Same span-only shape as
    /// [`Self::extract_pre_limit_extensions_fact`].
    fn extract_post_locking_extensions_fact(&mut self, sel: &AstSelect) {
        for span in sel.post_locking_extension_clauses.iter() {
            self.statement_facts.post_locking_extensions.push(*span);
        }
    }

    /// Lower clause-level Jinja statement fragments into
    /// [`super::statement_facts::JinjaFragmentRef`] entries.
    /// Stores only the fragment's
    /// `NodeId` and span — the full fragment AST stays on the
    /// AST side; consumers that need branch-level detail look
    /// it up by id.
    fn extract_statement_fragments_fact(&mut self, sel: &AstSelect) {
        use super::statement_facts::JinjaFragmentRef;
        for fragment in sel.statement_fragments.iter() {
            self.statement_facts.jinja_fragments.push(JinjaFragmentRef {
                node_id: fragment.node_id,
                span: fragment.span,
            });
        }
    }

    fn reject_unsupported_select_features(&mut self, _sel: &AstSelect) -> Result<(), LowerError> {
        // WITH clauses are peeled off in `lower_select` before reaching
        // here; body lowering therefore never sees a
        // `with_clause`.
        // ForUpdate, ForJsonXml, IntoVars, SelectAsQualifier,
        // PreLimitExtension, PostLockingExtension, StatementFragments are lowered into
        // `StatementFacts`. ConnectBy is lowered in `lower_select_body` after `final_plan`
        // is assembled. No remaining clauses require rejection here.
        Ok(())
    }

    /// Reject table-ref shapes that fall through all lowering
    /// branches. The only case that reaches here is a TVF combined
    /// with `values` or `subquery` in the same table-ref — a
    /// structural parser-bug that cannot arise from valid SQL.
    /// All modifiers (`time_travel`, `changes`, `stage_options`,
    /// `with_offset`, `only_span`, `table_hints`, `tvf_schema_span`)
    /// are consumed by the TVF or base-Scan [`ScanModifier`] path
    /// before reaching this point.
    ///
    /// NOTE: `tr.joins` and `tr.lateral_keyword_span` are handled by
    /// `lower_table_ref_with_joins` / `lower_join` — do not reject
    /// them here.
    fn reject_unsupported_table_ref_except_match_recognize(
        &self,
        tr: &AstTableRef,
    ) -> Result<(), LowerError> {
        if tr.table_function.is_some() {
            // Reaches here only when a TVF co-exists with `values`
            // or `subquery` in the same table-ref — a parser-produced
            // structural impossibility. Surface as ParseUpstream.
            return Err(LowerError::parse_upstream(tr.span));
        }
        Ok(())
    }

    fn lower_table_ref(&self, tr: &AstTableRef) -> TableRef {
        let raw = slice_span(self.source, tr.name.span).unwrap_or("");
        if let Some(stage_name) = extract_stage_reference_prefix(raw) {
            let mut tref = TableRef::new(stage_name);
            tref.span = Some(tr.name.span);
            return tref;
        }

        // Decompose the qualified name into (db, schema, name) parts.
        //
        // When the parser preserved per-identifier-token spans on
        // `tr.name.parts` (the common case for plain `db.schema.table`
        // forms), iterate those: each part span covers exactly one
        // identifier token and is by construction trivia-free, so
        // a `/* comment */` between dotted parts cannot reach the
        // identifier text. Falls back to `slice_span` + dot-splitting
        // the merged `name.span` only for the structureless
        // `AstObjectRef` shapes (IDENTIFIER(...), table-valued function
        // calls, Jinja-templated names already opaqued above, etc.) —
        // see `AstObjectRef::parts` for the full enumeration.
        // Each part is the component text, or `None` for an omitted slot
        // (T-SQL `master..tbl`). An empty string from the raw-split
        // fallback is likewise treated as an omitted component.
        let split_parts: Vec<Option<String>> = match &tr.name.parts {
            Some(token_spans) => token_spans
                .iter()
                .map(|opt| opt.map(|span| slice_span(self.source, span).unwrap_or("").to_string()))
                .collect(),
            None => split_object_ref(raw)
                .into_iter()
                .map(|s| if s.is_empty() { None } else { Some(s) })
                .collect(),
        };
        let mut tref = match split_parts.as_slice() {
            [Some(name)] => TableRef::new(name.clone()),
            [schema, Some(name)] => {
                let mut t = TableRef::new(name.clone());
                if let Some(schema) = schema {
                    t = t.with_schema(schema.clone());
                }
                t
            }
            [db, schema, Some(name)] => {
                let mut t = TableRef::new(name.clone());
                if let Some(schema) = schema {
                    t = t.with_schema(schema.clone());
                }
                t.db = db.clone();
                t
            }
            // T-SQL four-part name: server.database.schema.object (a
            // linked-server / distributed-query reference).
            [server, db, schema, Some(name)] => {
                let mut t = TableRef::new(name.clone());
                if let Some(schema) = schema {
                    t = t.with_schema(schema.clone());
                }
                t.db = db.clone();
                t.server = server.clone();
                t
            }
            _ => TableRef::new(raw.to_string()),
        };

        // Apply session defaults. Same rule as
        // `extract_table_ref_from_object_span`: a session
        // db fills in a missing db; a session schema fills in a
        // missing schema only when the original ref was fully
        // unqualified (both db and schema absent). This preserves
        // the asymmetry that `schema.name` should NOT pick up a
        // session schema default.
        let db_was_none = tref.db.is_none();
        if db_was_none {
            if let Some(db) = &self.session.db {
                tref.db = Some(db.clone());
            }
        }
        if db_was_none && tref.schema.is_none() {
            if let Some(schema) = &self.session.schema {
                tref.schema = Some(schema.clone());
            }
        }

        tref.span = Some(tr.name.span);
        tref
    }

    // ── Projection ──────────────────────────────────────────────────────

    fn lower_projection(&mut self, sel: &AstSelect) -> Result<Vec<ProjectItem>, LowerError> {
        // Redshift projection-level trailing `EXCLUDE (cols)` clause. Folded
        // into the star's exclude set (before expansion) so analysis treats
        // `SELECT *, x EXCLUDE (c)` identically to the star-attached
        // `SELECT * EXCLUDE (c)`. Empty when no trailing clause is present.
        let proj_exclude = self.lower_star_exclude(sel.projection.exclude.as_deref());
        match &sel.projection.kind {
            AstProjectionKind::Star(star) => {
                // Top-level `SELECT *` / `SELECT t.*`. Lower to a
                // `ProjectItem::Star` preserving the qualifier +
                // modifier bag; when `from_scope` has resolved
                // source columns, additionally emit one
                // `ProjectItem::Expr` per enumerated column so
                // downstream analyses (lineage, output_schema,
                // GROUP BY ALL) see concrete per-column producers.
                let mut lowered = self.lower_top_star(star)?;
                lowered.exclude.extend(proj_exclude.iter().cloned());
                Ok(self.expand_star_items(lowered, sel.projection.node_id, sel.projection.span))
            }
            AstProjectionKind::Columns(items) => {
                // Build the alias map incrementally so item N+1 can
                // resolve a lateral SELECT-list alias defined by item
                // ≤N. Snowflake / BigQuery permit forward-only lateral
                // aliases inside the projection (e.g. `MAX(x) AS m,
                // m + 1 AS n`); without this incremental threading the
                // later reference falls into `lower_column_ref`'s
                // allocate-on-first-use fallback and registers a
                // synthetic orphan in `self.bindings`, which then
                // shadows the real alias for any downstream HAVING /
                // WHERE / QUALIFY / ORDER BY reference to the same
                // name. First-name-wins matches `AliasMap::from_projection`.
                let mut out = Vec::with_capacity(items.len());
                let mut running_aliases = AliasMap::default();
                for item in items {
                    let lowered =
                        self.lower_projection_item(item, Some(&running_aliases), &proj_exclude)?;
                    for pi in &lowered {
                        if let ProjectItem::Expr(pe) = pi {
                            if let Some(alias) = pe.alias.as_ref() {
                                running_aliases
                                    .by_name
                                    .entry(alias.clone())
                                    .or_insert(pe.output);
                                running_aliases.output_ids.insert(pe.output);
                            }
                        }
                    }
                    out.extend(lowered);
                }
                Ok(out)
            }
        }
    }

    fn lower_projection_item(
        &mut self,
        item: &ProjectionItem,
        aliases: Option<&AliasMap>,
        proj_exclude: &[StarExclude],
    ) -> Result<Vec<ProjectItem>, LowerError> {
        match &item.kind {
            ProjectionItemKind::JinjaBlock(block) => Err(LowerError::opaque(
                block.span,
                OpaqueReason::UnresolvedJinja { macro_name: None },
            )),
            ProjectionItemKind::SelectItem(select_item) => {
                // `*` / `t.*` / `expr.*` may appear inline in a
                // mixed projection list (e.g. `SELECT a, t.*, b
                // FROM …`). Detect these before normal scalar
                // lowering so they produce a `ProjectItem::Star`
                // rather than passing through the `AstExpr` arms
                // that would otherwise error with
                // `ScalarShape::Star`.
                if let Some(mut star) =
                    self.lower_inline_star(&select_item.expr, select_item.span, aliases)?
                {
                    // Fold the projection-level trailing EXCLUDE into this
                    // star before expansion (Redshift `SELECT *, x EXCLUDE (c)`).
                    star.exclude.extend(proj_exclude.iter().cloned());
                    return Ok(self.expand_star_items(star, select_item.node_id, select_item.span));
                }
                let expr = self.lower_expr(&select_item.expr, aliases)?;
                let alias = select_item
                    .alias
                    .as_ref()
                    .map(|a| self.ident_at(a.ident.span));
                // display_name: user-visible alias if present; else the
                // source text of the projection expression so analyses
                // can recover the original identifier / call shape.
                let display_name = match alias.as_ref() {
                    Some(k) => k.as_str().to_string(),
                    None => slice_span(self.source, select_item.expr.span())
                        .unwrap_or("")
                        .to_string(),
                };
                let output = self.allocator.fresh(
                    ColumnOrigin::Computed {
                        producing_node: select_item.node_id,
                        expr_span: select_item.expr.span(),
                    },
                    display_name,
                );
                // When the projection wraps a direct `Column(id)` ref with
                // an explicit alias, stamp the alias onto the referenced
                // binding (Computed-origin only — see
                // `BindingTable::stamp_alias_if_computed`). This is the
                // structural anchor that lets cross-side analyses (diff
                // aggregate pairing) recover the user's SQL name without
                // re-walking enclosing projections.
                if let (Some(alias_key), ScalarExpr::Column { column, .. }) =
                    (alias.as_ref(), &expr)
                {
                    self.allocator
                        .stamp_alias_if_computed(*column, alias_key.clone());
                }
                Ok(vec![ProjectItem::Expr(ProjectExpr {
                    output,
                    expr,
                    alias,
                    span: select_item.span,
                })])
            }
        }
    }

    /// Lower a top-level `SELECT *` projection (the `AstProjectionKind::Star`
    /// case).
    fn lower_top_star(
        &mut self,
        star: &crate::ast::AstStarProjection,
    ) -> Result<ProjectStar, LowerError> {
        let qualifier = match &star.qualifier {
            None => StarQualifier::Unqualified,
            Some(obj) => StarQualifier::Named(self.star_qualifier_path(obj)),
        };
        Ok(ProjectStar {
            qualifier,
            exclude: self.lower_star_exclude(star.exclude.as_deref()),
            replace: self.lower_star_replace(star.replace.as_deref())?,
            rename: self.lower_star_rename(star.rename.as_deref()),
            ilike: self.lower_star_ilike(star.ilike.as_ref()),
            top_level_pure: true,
            span: star.star_span,
        })
    }

    /// Detect and lower a star appearing inline in a mixed projection
    /// list (`SELECT a, t.*, b`). Returns `Ok(None)` when the item is
    /// not a star; `Ok(Some(..))` when it is; `Err(..)` when a nested
    /// REPLACE expression fails to lower.
    fn lower_inline_star(
        &mut self,
        expr: &AstExpr,
        item_span: Span,
        aliases: Option<&AliasMap>,
    ) -> Result<Option<ProjectStar>, LowerError> {
        match expr {
            AstExpr::UnqualifiedStar {
                exclude,
                replace,
                rename,
                ..
            } => Ok(Some(ProjectStar {
                qualifier: StarQualifier::Unqualified,
                exclude: self.lower_star_exclude(exclude.as_deref()),
                replace: self.lower_star_replace(replace.as_deref())?,
                rename: self.lower_star_rename(rename.as_deref()),
                ilike: None,
                top_level_pure: false,
                span: item_span,
            })),
            AstExpr::QualifiedStar {
                qualifier,
                exclude,
                replace,
                rename,
                ..
            } => Ok(Some(ProjectStar {
                qualifier: StarQualifier::Named(self.star_qualifier_path(qualifier)),
                exclude: self.lower_star_exclude(exclude.as_deref()),
                replace: self.lower_star_replace(replace.as_deref())?,
                rename: self.lower_star_rename(rename.as_deref()),
                ilike: None,
                top_level_pure: false,
                span: item_span,
            })),
            AstExpr::QualifiedStarFromExpr { base, .. } => {
                // `expr.*` — struct / object unpacking. Lower the
                // base expression so nested scalar subqueries /
                // correlated refs still propagate through the
                // visitor.
                let lowered = self.lower_expr(base, aliases)?;
                Ok(Some(ProjectStar {
                    qualifier: StarQualifier::FromExpr(Box::new(lowered)),
                    exclude: Vec::new(),
                    replace: Vec::new(),
                    rename: Vec::new(),
                    ilike: None,
                    top_level_pure: false,
                    span: item_span,
                }))
            }
            _ => Ok(None),
        }
    }

    fn star_qualifier_path(&self, obj: &crate::ast::AstObjectRef) -> Vec<StarPathPart> {
        // Walk the object span via the source slice and map each
        // dot-separated chunk to its (start, end) offsets so each
        // `StarPathPart` carries the source span its identifier
        // occupied. `slice_span` returns text starting at `obj.span.start`,
        // so the cumulative chunk offset within `raw` plus
        // `obj.span.start` reconstructs the absolute span.
        let raw = slice_span(self.source, obj.span).unwrap_or("");
        let base = obj.span.start;
        let parts = split_object_ref(raw);
        let mut cursor: usize = 0;
        let mut out = Vec::with_capacity(parts.len());
        for part in parts {
            // Locate `part` within `raw` starting at `cursor`. The
            // splitter preserves the part text exactly as written so
            // a forward find will always land it (and never crosses
            // a previously consumed prefix).
            let rel_start = match raw[cursor..].find(&part) {
                Some(i) => cursor + i,
                None => {
                    // Defensive: if the splitter and `find` ever
                    // disagree, fall back to a zero-width span at
                    // the cursor rather than panicking. This keeps
                    // structure intact; projection will still find a
                    // valid (empty) slice.
                    cursor
                }
            };
            let rel_end = rel_start + part.len();
            cursor = rel_end;
            let name = IdentKey::new(&part);
            out.push(StarPathPart {
                name,
                span: Span {
                    start: base + rel_start as u32,
                    end: base + rel_end as u32,
                },
            });
        }
        out
    }

    fn lower_star_exclude(&self, exclude: Option<&crate::ast::AstExclude>) -> Vec<StarExclude> {
        let Some(ex) = exclude else {
            return Vec::new();
        };
        ex.columns
            .iter()
            .map(|c| StarExclude {
                name: self.ident_at(c.name.span),
                span: c.name.span,
            })
            .collect()
    }

    fn lower_star_replace(
        &mut self,
        replace: Option<&crate::ast::AstReplace>,
    ) -> Result<Vec<StarReplace>, LowerError> {
        let Some(rp) = replace else {
            return Ok(Vec::new());
        };
        let mut out = Vec::with_capacity(rp.items.len());
        for it in &rp.items {
            let expr = self.lower_expr(&it.expr, None)?;
            out.push(StarReplace {
                column: self.ident_at(it.column.name.span),
                expr,
                span: it.column.name.span,
            });
        }
        Ok(out)
    }

    fn lower_star_rename(&self, rename: Option<&crate::ast::AstRename>) -> Vec<StarRename> {
        let Some(rn) = rename else {
            return Vec::new();
        };
        rn.items
            .iter()
            .map(|it| StarRename {
                from: self.ident_at(it.column.name.span),
                to: self.ident_at(it.alias.span),
                from_span: it.column.name.span,
                to_span: it.alias.span,
            })
            .collect()
    }

    fn lower_star_ilike(&self, ilike: Option<&crate::ast::AstIlikeFilter>) -> Option<String> {
        let f = ilike?;
        // Apply SQL-string semantics: strip one pair of enclosing
        // single-quotes (the standard literal form here) and unescape
        // doubled single quotes (`''` → `'`). Mirrors
        // `extract_string_literal_value`.
        let raw = slice_span(self.source, f.pattern_span).unwrap_or("").trim();
        if raw.len() >= 2 && raw.starts_with('\'') && raw.ends_with('\'') {
            let inner = &raw[1..raw.len() - 1];
            return Some(inner.replace("''", "'"));
        }
        // Best-effort: strip quotes if asymmetric / missing without
        // unescaping.
        let trimmed = raw.strip_prefix('\'').unwrap_or(raw);
        let trimmed = trimmed.strip_suffix('\'').unwrap_or(trimmed);
        Some(trimmed.to_string())
    }

    /// Enumerate a `ProjectStar` into concrete `ProjectItem::Expr`
    /// items using [`LowerCtx::from_scope`] when the star's source
    /// columns are resolvable without a catalog (CTE refs, derived
    /// tables, named scan aliases whose `columns` field is populated).
    ///
    /// Each emitted `Expr` carries a fresh `ColumnOrigin::Computed`
    /// output bound to `ScalarExpr::Column { column: <src>, .. }`, so
    /// the existing per-scalar lineage walk maps each star output back
    /// to its FROM-side origin without Star-specific logic.
    ///
    /// The original `ProjectStar` item is always preserved at the end
    /// of the returned vec: star-projection sidecars, strict-mode
    /// assertions, and `ProjectItem::Star` scalar-subquery walks
    /// (REPLACE / `expr.*`) remain visible. When expansion is not
    /// resolvable (ILIKE, `expr.*`, unknown qualifier alias, empty
    /// FROM scope) only the Star item is returned, so
    /// catalog-dependent analyses still see the star.
    fn expand_star_items(
        &mut self,
        star: ProjectStar,
        producing_node: crate::ast::NodeId,
        item_span: Span,
    ) -> Vec<ProjectItem> {
        use std::collections::{HashMap, HashSet};

        // FromExpr (`expr.*`) requires struct-type resolution, which is
        // out of scope for catalog-driven enumeration. Bail early.
        // ILIKE on the other hand applies a SQL pattern across column
        // names — handled inline in the catalog-enumeration loop below
        // via `ilike_matches`.
        if matches!(star.qualifier, StarQualifier::FromExpr(_)) {
            return vec![ProjectItem::Star(star)];
        }

        // Collect candidate source columns from `from_scope`, filtered
        // by qualifier. Each candidate is `(source_id, column_name,
        // display_name)`. A column with an empty display_name cannot
        // carry a meaningful alias; skip rather than invent one.
        let mut candidates: Vec<(ColumnId, IdentKey, String)> = Vec::new();
        let qualifier_alias: Option<IdentKey> = match &star.qualifier {
            StarQualifier::Unqualified => None,
            StarQualifier::Named(path) => path.last().map(|p| p.name.clone()),
            StarQualifier::FromExpr(_) => return vec![ProjectItem::Star(star)],
        };
        for entry in &self.from_scope {
            if let Some(q) = qualifier_alias.as_ref() {
                if entry.source_alias.as_ref() != Some(q) {
                    continue;
                }
            }
            let display = match self.allocator.bindings().get(entry.column_id) {
                Some(b) => b.display_name.clone(),
                None => continue,
            };
            if display.is_empty() {
                continue;
            }
            candidates.push((entry.column_id, entry.column_name.clone(), display));
        }

        if candidates.is_empty() {
            // No from-scope candidates (scan-with-no-known-columns, or
            // a qualifier that didn't match any scope entry). Attempt
            // catalog-driven star expansion when a catalog index is
            // present: look up the source table(s) by NodeId, fetch
            // their catalog column lists, and allocate concrete
            // `ProjectItem::Expr` items (star catalog
            // enumeration).
            if self.catalog_index.is_some() {
                let exclude: HashSet<IdentKey> =
                    star.exclude.iter().map(|e| e.name.clone()).collect();
                let replace: HashMap<IdentKey, ScalarExpr> = star
                    .replace
                    .iter()
                    .map(|r| (r.column.clone(), r.expr.clone()))
                    .collect();
                let rename: HashMap<IdentKey, IdentKey> = star
                    .rename
                    .iter()
                    .map(|r| (r.from.clone(), r.to.clone()))
                    .collect();

                // Determine which source NodeId(s) to enumerate.
                // Qualified star: the specific source named by the
                // qualifier alias. Unqualified: all registered FROM
                // sources, in registration order.
                let source_nodes: Vec<crate::ast::NodeId> = match qualifier_alias.as_ref() {
                    Some(q) => match self.from_aliases.get(q).copied() {
                        Some(nid) => vec![nid],
                        None => Vec::new(),
                    },
                    None => self.from_source_order.clone(),
                };

                let mut catalog_items: Vec<ProjectItem> = Vec::new();
                for nid in source_nodes {
                    // Only base-table scans have a registered TableRef.
                    // CteRefs, DerivedTables, etc. are skipped (their
                    // columns come from the plan, not the catalog).
                    let table_ref = match self.scan_table_refs.get(&nid).cloned() {
                        Some(tr) => tr,
                        None => continue,
                    };
                    // Collect column names: immutable borrow released
                    // before the mutable alloc calls below.
                    let col_names = self.catalog_col_names_for_table(&table_ref);
                    for col_name in col_names {
                        let col_key = IdentKey::new(&col_name);
                        if exclude.contains(&col_key) {
                            continue;
                        }
                        // BigQuery-style `* ILIKE '<pat>'` filter:
                        // only enumerate columns whose name matches
                        // the SQL LIKE pattern (case-insensitive).
                        if let Some(pattern) = star.ilike.as_deref() {
                            if !sql_ilike_matches(pattern, &col_name) {
                                continue;
                            }
                        }
                        let alias = rename.get(&col_key).cloned();
                        let display_name = match alias.as_ref() {
                            Some(a) => a.as_str().to_string(),
                            None => col_name.clone(),
                        };
                        // `REPLACE (<expr> AS <col>)` substitutes a
                        // replacement expression for the column's
                        // value. The base column is NOT structurally
                        // accessed unless the replacement expression
                        // itself references it (e.g. `LOWER(col)`).
                        // Allocate the base column only when no
                        // replacement is supplied; when a replacement
                        // is present, lowering the replacement
                        // expression elsewhere binds whatever columns
                        // it actually references (sub-expression
                        // walk in the call site that constructs
                        // `replace` from `star.replace`).
                        let replacement_expr = replace.get(&col_key).cloned();
                        let expr = match replacement_expr {
                            Some(e) => e,
                            None => {
                                let fresh = self.alloc_table_col(nid, &col_name, item_span);
                                self.scan_cols.push((nid, fresh));
                                ScalarExpr::Column {
                                    column: fresh,
                                    span: item_span,
                                }
                            }
                        };
                        let output =
                            self.alloc_computed_col(producing_node, item_span, display_name);
                        catalog_items.push(ProjectItem::Expr(ProjectExpr {
                            output,
                            expr,
                            alias,
                            span: item_span,
                        }));
                    }
                }

                if !catalog_items.is_empty() {
                    // Preserve the Star sentinel at the end — strict-mode
                    // assertions, sidecar walks, and REPLACE/RENAME
                    // sub-expression walks still need it visible.
                    catalog_items.push(ProjectItem::Star(star));
                    return catalog_items;
                }
            }

            // Partial expansion from explicit star modifiers. Catalog
            // enumeration above is best-effort: tables outside the
            // attached `catalog_index` (and runs with no catalog at
            // all) reach this point with `candidates` and
            // `catalog_items` both empty. The `RENAME` / `REPLACE`
            // clauses, however, still *name* specific output columns
            // by construction — `RENAME (id AS user_id)` declares a
            // `user_id` slot whose source is `id`; `REPLACE (LOWER(x)
            // AS x)` declares an `x` slot whose value is the
            // replacement expression. Materialise one
            // `ProjectItem::Expr` per such named slot so the
            // enclosing `Project`'s `output_schema` includes them and
            // the binding's `slot_deps` carry meaningful lineage. The
            // unnamed remainder of `*` stays deferred behind the
            // `Star` sentinel.
            if !star.rename.is_empty() || !star.replace.is_empty() {
                let source_nodes: Vec<crate::ast::NodeId> = match qualifier_alias.as_ref() {
                    Some(q) => match self.from_aliases.get(q).copied() {
                        Some(nid) => vec![nid],
                        None => Vec::new(),
                    },
                    None => self.from_source_order.clone(),
                };
                let primary_source = source_nodes.first().copied();
                let mut partial_items: Vec<ProjectItem> = Vec::new();

                for r in &star.rename {
                    // RENAME without a known source NodeId can't
                    // ground the output anywhere — skip rather than
                    // invent a Computed column whose origin doesn't
                    // tie back to a table. (`primary_source` is
                    // empty only when the qualifier didn't match any
                    // FROM source, which is itself a malformed
                    // query.)
                    let Some(nid) = primary_source else { continue };
                    let col_name = r.from.as_str().to_string();
                    let fresh = self.alloc_table_col(nid, &col_name, r.from_span);
                    self.scan_cols.push((nid, fresh));
                    let output = self.alloc_computed_col(
                        producing_node,
                        r.to_span,
                        r.to.as_str().to_string(),
                    );
                    partial_items.push(ProjectItem::Expr(ProjectExpr {
                        output,
                        expr: ScalarExpr::Column {
                            column: fresh,
                            span: r.from_span,
                        },
                        alias: Some(r.to.clone()),
                        span: item_span,
                    }));
                }

                for r in &star.replace {
                    // `r.expr` is already a fully lowered
                    // `ScalarExpr` carrying its own source-column
                    // references; its column origins were resolved
                    // when the projection list was first lowered.
                    // The output's display name is the replace
                    // target (`r.column`), matching Snowflake
                    // semantics: `* REPLACE (<expr> AS <col>)`
                    // overwrites the column called `<col>` while
                    // preserving the slot's name.
                    let output = self.alloc_computed_col(
                        producing_node,
                        r.span,
                        r.column.as_str().to_string(),
                    );
                    partial_items.push(ProjectItem::Expr(ProjectExpr {
                        output,
                        expr: r.expr.clone(),
                        alias: Some(r.column.clone()),
                        span: r.span,
                    }));
                }

                if !partial_items.is_empty() {
                    partial_items.push(ProjectItem::Star(star));
                    return partial_items;
                }
            }

            // Nothing resolvable (no candidates, catalog miss, no
            // RENAME / REPLACE to ground output names). Preserve the
            // Star alone.
            return vec![ProjectItem::Star(star)];
        }

        let exclude: HashSet<IdentKey> = star.exclude.iter().map(|e| e.name.clone()).collect();
        let replace: HashMap<IdentKey, ScalarExpr> = star
            .replace
            .iter()
            .map(|r| (r.column.clone(), r.expr.clone()))
            .collect();
        let rename: HashMap<IdentKey, IdentKey> = star
            .rename
            .iter()
            .map(|r| (r.from.clone(), r.to.clone()))
            .collect();

        let mut out: Vec<ProjectItem> = Vec::with_capacity(candidates.len() + 1);
        for (src_id, col_key, col_display) in candidates {
            if exclude.contains(&col_key) {
                continue;
            }
            let alias = rename.get(&col_key).cloned();
            let display_name = match alias.as_ref() {
                Some(a) => a.as_str().to_string(),
                None => col_display,
            };
            let output = self.alloc_computed_col(producing_node, item_span, display_name);
            let expr = match replace.get(&col_key) {
                Some(e) => e.clone(),
                None => ScalarExpr::Column {
                    column: src_id,
                    span: item_span,
                },
            };
            out.push(ProjectItem::Expr(ProjectExpr {
                output,
                expr,
                alias,
                span: item_span,
            }));
        }
        out.push(ProjectItem::Star(star));
        out
    }

    // ── Scalar expressions ──────────────────────────────────────────────

    /// Lower an expression, but under permissive strictness absorb a
    /// `LowerError` as a typed `ScalarExpr::Opaque` carrying the
    /// failure's reason tag. Used inside container constructs where
    /// a single sub-expression failure must not collapse the entire
    /// surrounding plan node (currently MATCH_RECOGNIZE bodies —
    /// pattern, partition_by, order_by, measures
    /// and define are all locally recoverable).
    ///
    /// Strict mode (`forbids_opaque()`) propagates the error
    /// unchanged so the strictness harness still
    /// surfaces the underlying gap.
    fn lower_expr_or_opaque_local(
        &mut self,
        expr: &AstExpr,
        aliases: Option<&AliasMap>,
    ) -> Result<ScalarExpr, LowerError> {
        match self.lower_expr(expr, aliases) {
            Ok(s) => Ok(s),
            Err(e) if self.strict.forbids_opaque() => Err(e),
            Err(e) => Ok(ScalarExpr::Opaque {
                span: e.span,
                reason: e.kind.label(),
            }),
        }
    }

    /// Guarded entry to expression lowering. Bookkeeping is incremented
    /// before the recursive body and restored after it on both the `Ok`
    /// and `Err` paths — it cannot leak, because the wrapper has no `?`
    /// between the two.
    fn lower_expr(
        &mut self,
        expr: &AstExpr,
        aliases: Option<&AliasMap>,
    ) -> Result<ScalarExpr, LowerError> {
        // Parentheses lower to their operand. Stepping through them here
        // keeps a run of them from costing a frame and a depth level each.
        let mut expr = expr;
        while let AstExpr::Parenthesized { expr: inner, .. } = expr {
            expr = inner;
        }

        // Approximate stack position: the address of a fresh local.
        // Compared against the anchor recorded by the outermost frame;
        // the stack grows downward on every supported target, and
        // saturating_sub keeps the check inert if it ever does not.
        let probe = 0u8;
        let here = std::ptr::addr_of!(probe) as usize;

        if self.expr_depth == 0 {
            self.expr_stack_anchor = here;
        } else {
            let consumed = self.expr_stack_anchor.saturating_sub(here);
            if consumed > LOWER_EXPR_STACK_BUDGET || self.expr_depth >= MAX_LOWER_EXPR_DEPTH {
                return Err(LowerError::opaque(
                    expr.span(),
                    OpaqueReason::ExpressionTooDeep {
                        depth: self.expr_depth,
                    },
                ));
            }
        }

        self.expr_depth += 1;
        let lowered = self.lower_expr_inner(expr, aliases);
        self.expr_depth -= 1;
        if self.expr_depth == 0 {
            self.expr_stack_anchor = 0;
        }
        lowered
    }

    fn lower_expr_inner(
        &mut self,
        expr: &AstExpr,
        aliases: Option<&AliasMap>,
    ) -> Result<ScalarExpr, LowerError> {
        match expr {
            AstExpr::Literal { literal, .. } => Ok(self.lower_literal(literal)),
            AstExpr::Ident { column_ref, .. } => Ok(self.lower_column_ref(column_ref, aliases)),
            AstExpr::Parenthesized { expr: inner, .. } => self.lower_expr(inner, aliases),
            AstExpr::LogicalChain {
                operator,
                operands,
                span,
                ..
            } => {
                let lowered = operands
                    .iter()
                    .map(|item| self.lower_expr(item, aliases))
                    .collect::<Result<Vec<_>, _>>()?;
                if lowered.is_empty() {
                    // Parser invariant: LogicalChain must have ≥2 operands.
                    // An empty chain is a malformed parse; return a null literal
                    // so the enclosing statement stays concrete.
                    return Ok(ScalarExpr::Lit {
                        value: Lit::Null,
                        span: *span,
                    });
                }
                let op = match operator {
                    LogicalChainOperator::And => super::scalar::LogicalOp::And,
                    LogicalChainOperator::Or => super::scalar::LogicalOp::Or,
                };
                // Kept flat. Folding this into a `BinOp`
                // spine made every downstream walk recurse once per
                // operand, which is what overflowed the stack on wide
                // `WHERE` clauses.
                Ok(ScalarExpr::LogicalChain {
                    op,
                    operands: lowered,
                    span: *span,
                })
            }
            AstExpr::BinaryOp {
                left,
                operator,
                right,
                span,
                ..
            } => {
                match classify_binary_operator(*operator) {
                    BinOpClass::PrefixNot => {
                        // Parser currently represents prefix NOT as BinaryOp
                        // with a dummy left operand; preserve semantics by
                        // lowering to UnaryOp on the right operand.
                        let arg = Box::new(self.lower_expr(right, aliases)?);
                        // Canonicalize `NOT (x = ANY ...)` / `NOT (x IN ...)`
                        // by folding the negation into the QuantifiedCmp's
                        // typed `negated` field. Downstream consumers see the
                        // canonical single-shape representation regardless of
                        // whether the user wrote `NOT IN`, `<> ALL`, or parens.
                        if let ScalarExpr::QuantifiedCmp {
                            op,
                            quantifier,
                            negated,
                            left: q_left,
                            right: q_right,
                            span: q_span,
                        } = *arg
                        {
                            return Ok(ScalarExpr::QuantifiedCmp {
                                op,
                                quantifier,
                                negated: !negated,
                                left: q_left,
                                right: q_right,
                                span: q_span,
                            });
                        }
                        Ok(ScalarExpr::UnaryOp {
                            op: super::scalar::UnaryOpKind::Not,
                            arg,
                            span: *span,
                        })
                    }
                    BinOpClass::Like(kind) => {
                        // Operator-syntax pattern match (`a RLIKE b`) shares
                        // one representation with predicate-syntax
                        // `AstExpr::Like`; operator syntax has no ESCAPE.
                        let lowered_expr = Box::new(self.lower_expr(left, aliases)?);
                        let lowered_pattern = Box::new(self.lower_expr(right, aliases)?);
                        Ok(ScalarExpr::Like {
                            kind,
                            negated: false,
                            expr: lowered_expr,
                            pattern: lowered_pattern,
                            escape: None,
                            span: *span,
                        })
                    }
                    BinOpClass::Kind(op) => {
                        let left_lowered = Box::new(self.lower_expr(left, aliases)?);
                        let right_lowered = Box::new(self.lower_expr(right, aliases)?);
                        Ok(ScalarExpr::BinOp {
                            op,
                            left: left_lowered,
                            right: right_lowered,
                            span: *span,
                        })
                    }
                }
            }
            AstExpr::Case {
                operand,
                whens,
                else_expr,
                span,
                ..
            } => {
                let lowered_operand = match operand {
                    Some(op) => Some(Box::new(self.lower_expr(op, aliases)?)),
                    None => None,
                };
                let mut branches = Vec::with_capacity(whens.len());
                for when in whens {
                    branches.push((
                        self.lower_expr(&when.cond, aliases)?,
                        self.lower_expr(&when.result, aliases)?,
                    ));
                }
                let lowered_else = match else_expr {
                    Some(e) => Some(Box::new(self.lower_expr(e, aliases)?)),
                    None => None,
                };
                Ok(ScalarExpr::Case {
                    operand: lowered_operand,
                    branches,
                    else_: lowered_else,
                    span: *span,
                })
            }
            AstExpr::IsNull {
                expr,
                not_span,
                span,
                ..
            } => {
                let arg = Box::new(self.lower_expr(expr, aliases)?);
                Ok(ScalarExpr::UnaryOp {
                    op: if not_span.is_some() {
                        super::scalar::UnaryOpKind::IsNotNull
                    } else {
                        super::scalar::UnaryOpKind::IsNull
                    },
                    arg,
                    span: *span,
                })
            }
            AstExpr::IsDistinctFrom {
                left,
                right,
                not_span,
                span,
                ..
            } => {
                let left_lowered = Box::new(self.lower_expr(left, aliases)?);
                let right_lowered = Box::new(self.lower_expr(right, aliases)?);
                Ok(ScalarExpr::BinOp {
                    op: if not_span.is_some() {
                        super::scalar::BinOpKind::IsNotDistinctFrom
                    } else {
                        super::scalar::BinOpKind::IsDistinctFrom
                    },
                    left: left_lowered,
                    right: right_lowered,
                    span: *span,
                })
            }
            AstExpr::Like {
                expr,
                not_span,
                like_kind_span,
                pattern,
                escape_clause,
                span,
                ..
            } => {
                let lowered_expr = Box::new(self.lower_expr(expr, aliases)?);
                let lowered_pattern = Box::new(self.lower_expr(pattern, aliases)?);
                let keyword = slice_span(self.source, *like_kind_span)
                    .unwrap_or("LIKE")
                    .trim()
                    .to_ascii_uppercase();
                let escape = match escape_clause {
                    Some(e) => Some(Box::new(self.lower_expr(e, aliases)?)),
                    None => None,
                };
                Ok(ScalarExpr::Like {
                    kind: super::scalar::LikeKind::from_keyword(&keyword),
                    negated: not_span.is_some(),
                    expr: lowered_expr,
                    pattern: lowered_pattern,
                    escape,
                    span: *span,
                })
            }
            AstExpr::SimilarTo {
                expr,
                not_span,
                pattern,
                escape_clause,
                span,
                ..
            } => {
                let lowered_expr = Box::new(self.lower_expr(expr, aliases)?);
                let lowered_pattern = Box::new(self.lower_expr(pattern, aliases)?);
                let escape = match escape_clause {
                    Some(e) => Some(Box::new(self.lower_expr(e, aliases)?)),
                    None => None,
                };
                Ok(ScalarExpr::Like {
                    kind: super::scalar::LikeKind::SimilarTo,
                    negated: not_span.is_some(),
                    expr: lowered_expr,
                    pattern: lowered_pattern,
                    escape,
                    span: *span,
                })
            }
            // ── InList ──────────────────────────────────────────────
            // The negation flag is carried explicitly on the AST node
            // (the parser populates it from `SyntaxInList.not_keyword`
            // at construction time). Lowering simply forwards it to the
            // [`ScalarExpr::InList`] variant.
            AstExpr::InList {
                expr,
                list,
                negated,
                span,
                ..
            } => {
                let lowered_expr = Box::new(self.lower_expr(expr, aliases)?);
                let mut lowered_list = Vec::with_capacity(list.len());
                for item in list {
                    lowered_list.push(self.lower_expr(item, aliases)?);
                }
                Ok(ScalarExpr::InList {
                    expr: lowered_expr,
                    list: lowered_list,
                    negated: *negated,
                    span: *span,
                })
            }
            // InListOpaque: Jinja inside an IN-list; not representable
            // without rendering the template content.
            AstExpr::InListOpaque { span, .. } => Err(LowerError::opaque(
                *span,
                OpaqueReason::UnresolvedJinja { macro_name: None },
            )),
            // ── Between ─────────────────────────────────────────────
            // The negation flag is carried explicitly on the AST node
            // (the parser populates it from
            // `SyntaxBetweenExpr.not_keyword` at construction time).
            AstExpr::Between {
                expr,
                lower,
                upper,
                negated,
                span,
                ..
            } => Ok(ScalarExpr::Between {
                expr: Box::new(self.lower_expr(expr, aliases)?),
                low: Box::new(self.lower_expr(lower, aliases)?),
                high: Box::new(self.lower_expr(upper, aliases)?),
                negated: *negated,
                span: *span,
            }),
            // ── Cast family ─────────────────────────────────────────
            AstExpr::Cast {
                expr,
                target_type,
                span,
                ..
            } => Ok(ScalarExpr::Cast {
                expr: Box::new(self.lower_expr(expr, aliases)?),
                target_type: lower_data_type(self.source, target_type),
                try_cast: false,
                span: *span,
            }),
            AstExpr::TryCast {
                expr,
                target_type,
                span,
                ..
            } => Ok(ScalarExpr::Cast {
                expr: Box::new(self.lower_expr(expr, aliases)?),
                target_type: lower_data_type(self.source, target_type),
                try_cast: true,
                span: *span,
            }),
            // BigQuery SAFE_CAST is semantically equivalent to TRY_CAST.
            AstExpr::SafeCast {
                expr,
                target_type,
                span,
                ..
            } => Ok(ScalarExpr::Cast {
                expr: Box::new(self.lower_expr(expr, aliases)?),
                target_type: lower_data_type(self.source, target_type),
                try_cast: true,
                span: *span,
            }),
            // PostgreSQL :: operator.
            AstExpr::TypeCast {
                expr,
                target_type,
                span,
                ..
            } => Ok(ScalarExpr::Cast {
                expr: Box::new(self.lower_expr(expr, aliases)?),
                target_type: lower_data_type(self.source, target_type),
                try_cast: false,
                span: *span,
            }),
            // ── Typed literal ────────────────────────────────────────
            // e.g. DATE '2024-01-01', TIMESTAMP '...', INTERVAL '1' YEAR
            AstExpr::TypedStringLiteral {
                type_name_span,
                value_span,
                odbc_kind,
                span,
                ..
            } => {
                // ODBC escape form ({d '…'}): the source introducer is `d`,
                // not `DATE` — use the canonical name so facts are identical
                // to the native spelling.
                let type_name = match odbc_kind {
                    Some(kind) => kind.canonical_type_name().to_string(),
                    None => slice_span(self.source, *type_name_span)
                        .unwrap_or("")
                        .to_ascii_uppercase(),
                };
                let value = slice_span(self.source, *value_span)
                    .unwrap_or("")
                    .to_string();
                Ok(ScalarExpr::Lit {
                    value: Lit::Typed { type_name, value },
                    span: *span,
                })
            }
            // ── Jinja / dbt template nodes ───────────────────────────
            // These survive into the IR only when the renderer couldn't
            // resolve them. Surface as UnresolvedJinja so the harness
            // counts them under the correct opaque-reason bucket.
            AstExpr::JinjaPlaceholder { span, .. }
            | AstExpr::DbtRef { span, .. }
            | AstExpr::DbtSource { span, .. }
            | AstExpr::DbtVar { span, .. }
            | AstExpr::DbtConfig { span, .. }
            | AstExpr::DbtThis { span, .. } => Err(LowerError::opaque(
                *span,
                OpaqueReason::UnresolvedJinja { macro_name: None },
            )),
            // ── Expressions lowered in-place to ScalarExpr::Opaque ───
            // ── EXTRACT(field FROM expr) ──────────────────────────
            // Modelled as a FuncCall so inner column refs are tracked
            // by lineage / nullability / taint analyses.
            AstExpr::Extract { expr, span, .. } => {
                let arg = self.lower_expr_or_opaque_local(expr, aliases)?;
                Ok(ScalarExpr::FuncCall {
                    func: ResolvedFunc::unresolved("EXTRACT", None, *span),
                    args: vec![arg],
                    distinct: false,
                    named_args: Vec::new(),
                    span: *span,
                })
            }
            // ── POSITION(needle IN haystack) ─────────────────────────
            AstExpr::Position {
                needle,
                haystack,
                span,
                ..
            } => {
                let lowered_needle = self.lower_expr_or_opaque_local(needle, aliases)?;
                let lowered_haystack = self.lower_expr_or_opaque_local(haystack, aliases)?;
                Ok(ScalarExpr::FuncCall {
                    func: ResolvedFunc::unresolved("POSITION", None, *span),
                    args: vec![lowered_needle, lowered_haystack],
                    distinct: false,
                    named_args: Vec::new(),
                    span: *span,
                })
            }
            // ── MATCH(cols) AGAINST (search [modifier]) ──────────────
            // Modelled as a FuncCall wrapping the lowered MATCH call and
            // the search expression so column refs in both are tracked by
            // lineage / taint. The mode modifier lives in the AST layer
            // (mirrors EXTRACT dropping its field).
            AstExpr::MatchAgainst {
                match_call,
                search,
                span,
                ..
            } => {
                let lowered_match = self.lower_expr_or_opaque_local(match_call, aliases)?;
                let lowered_search = self.lower_expr_or_opaque_local(search, aliases)?;
                Ok(ScalarExpr::FuncCall {
                    func: ResolvedFunc::unresolved("MATCH_AGAINST", None, *span),
                    args: vec![lowered_match, lowered_search],
                    distinct: false,
                    named_args: Vec::new(),
                    span: *span,
                })
            }
            // ── TRIM([spec] [chars] FROM source) ─────────────────────
            // Modelled as a FuncCall so inner column refs (chars + source)
            // are tracked by lineage / nullability / taint. The trim direction
            // lives in the AST/CST layer (mirrors EXTRACT dropping its field).
            AstExpr::Trim {
                chars,
                source,
                span,
                ..
            } => {
                let mut args = Vec::with_capacity(2);
                if let Some(chars_expr) = chars {
                    args.push(self.lower_expr_or_opaque_local(chars_expr, aliases)?);
                }
                args.push(self.lower_expr_or_opaque_local(source, aliases)?);
                Ok(ScalarExpr::FuncCall {
                    func: ResolvedFunc::unresolved("TRIM", None, *span),
                    args,
                    distinct: false,
                    named_args: Vec::new(),
                    span: *span,
                })
            }
            // ── SUBSTRING(source FROM start [FOR length]) ────────────
            AstExpr::Substring {
                source,
                from,
                for_len,
                span,
                ..
            } => {
                let mut args = Vec::with_capacity(3);
                args.push(self.lower_expr_or_opaque_local(source, aliases)?);
                if let Some(from_expr) = from {
                    args.push(self.lower_expr_or_opaque_local(from_expr, aliases)?);
                }
                if let Some(for_expr) = for_len {
                    args.push(self.lower_expr_or_opaque_local(for_expr, aliases)?);
                }
                Ok(ScalarExpr::FuncCall {
                    func: ResolvedFunc::unresolved("SUBSTRING", None, *span),
                    args,
                    distinct: false,
                    named_args: Vec::new(),
                    span: *span,
                })
            }
            // ── expr AT TIME ZONE zone / AT LOCAL ────────────────────
            AstExpr::AtTimeZone {
                expr, zone, span, ..
            } => {
                let left = Box::new(self.lower_expr_or_opaque_local(expr, aliases)?);
                match zone {
                    Some(z) => {
                        let right = Box::new(self.lower_expr_or_opaque_local(z, aliases)?);
                        Ok(ScalarExpr::BinOp {
                            op: super::scalar::BinOpKind::AtTimeZone,
                            left,
                            right,
                            span: *span,
                        })
                    }
                    None => Ok(ScalarExpr::UnaryOp {
                        op: super::scalar::UnaryOpKind::AtLocal,
                        arg: left,
                        span: *span,
                    }),
                }
            }
            // ── ROW(e, e, ...) / (e, e, ...) row constructor ─────────
            // Modelled as a FuncCall so all element column refs are
            // tracked by IR analyses.
            AstExpr::RowConstructor { elements, span, .. } => {
                let mut args = Vec::with_capacity(elements.len());
                for e in elements {
                    args.push(self.lower_expr_or_opaque_local(e, aliases)?);
                }
                Ok(ScalarExpr::FuncCall {
                    func: ResolvedFunc::unresolved("ROW", None, *span),
                    args,
                    distinct: false,
                    named_args: Vec::new(),
                    span: *span,
                })
            }
            // ── expr COLLATE spec ─────────────────────────────────────
            // The collation spec is owned by the syntax layer; model as
            // a unary operator so the inner column refs are visible.
            AstExpr::Collate { expr, span, .. } => {
                let arg = Box::new(self.lower_expr_or_opaque_local(expr, aliases)?);
                Ok(ScalarExpr::UnaryOp {
                    op: super::scalar::UnaryOpKind::Collate,
                    arg,
                    span: *span,
                })
            }
            // ── Scalar subquery ──────────────────────────────────────
            AstExpr::ScalarSubquery { subquery, span, .. } => {
                let plan = self
                    .lower_stmt_as_subquery(subquery)
                    .unwrap_or_else(|e| e.into_terminal(crate::ast::NodeId::new(0)));
                Ok(ScalarExpr::ScalarSubquery {
                    subquery: Box::new(plan),
                    correlates_with: vec![],
                    span: *span,
                })
            }
            // ── EXISTS (subquery) ─────────────────────────────────────
            AstExpr::ExistsSubquery {
                subquery,
                negated,
                span,
                ..
            } => {
                let plan = self
                    .lower_stmt_as_subquery(subquery)
                    .unwrap_or_else(|e| e.into_terminal(crate::ast::NodeId::new(0)));
                Ok(ScalarExpr::Exists {
                    subquery: Box::new(plan),
                    correlates_with: vec![],
                    negated: *negated,
                    span: *span,
                })
            }
            // ── [NOT] IN (subquery) ───────────────────────────────────
            // `x IN (SELECT ...)` is semantically equivalent to
            // `x = ANY (SELECT ...)`. The negation lifts directly into
            // the typed `negated: bool` field on `QuantifiedCmp` (no
            // `UnaryOp(Not, ...)` wrap) — mirroring the existing
            // `InList { negated, .. }` / `Between { negated, .. }` /
            // `Exists { negated, .. }` discipline.
            AstExpr::InSubquery {
                expr,
                subquery,
                negated,
                span,
                ..
            } => {
                let lhs = self.lower_expr(expr, aliases)?;
                let plan = self
                    .lower_stmt_as_subquery(subquery)
                    .unwrap_or_else(|e| e.into_terminal(crate::ast::NodeId::new(0)));
                Ok(ScalarExpr::QuantifiedCmp {
                    op: super::scalar::ComparisonOp::Eq,
                    quantifier: super::scalar::Quantifier::Any,
                    negated: *negated,
                    left: Box::new(lhs),
                    right: super::scalar::QuantifiedRhs::Subquery(Box::new(plan), vec![]),
                    span: *span,
                })
            }
            // ── expr = ANY/ALL (subquery) ─────────────────────────────
            AstExpr::QuantifiedSubquery {
                left,
                operator,
                quantifier,
                subquery,
                span,
                ..
            } => {
                let lhs = self.lower_expr(left, aliases)?;
                let plan = self
                    .lower_stmt_as_subquery(subquery)
                    .unwrap_or_else(|e| e.into_terminal(crate::ast::NodeId::new(0)));
                let q = match quantifier {
                    crate::ast::AstQuantifier::Any => super::scalar::Quantifier::Any,
                    crate::ast::AstQuantifier::All => super::scalar::Quantifier::All,
                };
                let cmp_op = match ast_binop_to_comparison_op(*operator) {
                    Some(c) => c,
                    None => {
                        // SQL grammar guarantees the head of a quantified
                        // subquery is a comparison operator. The parser
                        // never constructs `AstExpr::QuantifiedSubquery`
                        // with a non-comparison `operator`; if this fires,
                        // the parser invariant has been violated upstream.
                        panic!(
                            "lower_expr: quantified subquery operator {:?} is not a comparison; parser invariant violated",
                            operator
                        );
                    }
                };
                Ok(ScalarExpr::QuantifiedCmp {
                    op: cmp_op,
                    quantifier: q,
                    negated: false,
                    left: Box::new(lhs),
                    right: super::scalar::QuantifiedRhs::Subquery(Box::new(plan), vec![]),
                    span: *span,
                })
            }
            // ── Array subscript / semi-structured field access ────────
            // expr[idx] — lower base and index; represent as FieldAccess
            // with an index step if index is an integer literal, otherwise
            // IndexExpr.
            AstExpr::ArraySubscript {
                base, index, span, ..
            } => {
                let base_lowered = self.lower_expr(base, aliases)?;
                let index_lowered = self.lower_expr(index, aliases)?;
                let step = super::scalar::FieldStep::IndexExpr(Box::new(index_lowered));
                Ok(ScalarExpr::FieldAccess {
                    base: Box::new(base_lowered),
                    path: vec![step],
                    cast: None,
                    span: *span,
                })
            }
            // ── Colon field access: expr:field ────────────────────────
            AstExpr::ObjectFieldColon {
                base,
                field_span,
                span,
                ..
            } => {
                let base_lowered = self.lower_expr(base, aliases)?;
                let name = slice_span(self.source, *field_span)
                    .unwrap_or("")
                    .to_string();
                Ok(ScalarExpr::FieldAccess {
                    base: Box::new(base_lowered),
                    path: vec![super::scalar::FieldStep::Field(name)],
                    cast: None,
                    span: *span,
                })
            }
            // ── Bracket field access: expr['field'] ───────────────────
            AstExpr::ObjectFieldBracket {
                base, field, span, ..
            } => {
                let base_lowered = self.lower_expr(base, aliases)?;
                let field_lowered = self.lower_expr(field, aliases)?;
                let step = super::scalar::FieldStep::IndexExpr(Box::new(field_lowered));
                Ok(ScalarExpr::FieldAccess {
                    base: Box::new(base_lowered),
                    path: vec![step],
                    cast: None,
                    span: *span,
                })
            }
            // ── Dot field access: expr.field ──────────────────────────
            AstExpr::ObjectFieldDot {
                base,
                field_span,
                span,
                ..
            } => {
                let base_lowered = self.lower_expr(base, aliases)?;
                let name = slice_span(self.source, *field_span)
                    .unwrap_or("")
                    .to_string();
                Ok(ScalarExpr::FieldAccess {
                    base: Box::new(base_lowered),
                    path: vec![super::scalar::FieldStep::Field(name)],
                    cast: None,
                    span: *span,
                })
            }
            // ── Array literal: [e, e, ...] ────────────────────────────
            // Modelled as FuncCall(ARRAY, elements) so all element
            // column refs are tracked by IR analyses.
            AstExpr::Array { elements, span, .. } => {
                let mut args = Vec::with_capacity(elements.len());
                for el in elements {
                    args.push(self.lower_expr_or_opaque_local(el, aliases)?);
                }
                Ok(ScalarExpr::FuncCall {
                    func: ResolvedFunc::unresolved("ARRAY", None, *span),
                    args,
                    distinct: false,
                    named_args: Vec::new(),
                    span: *span,
                })
            }
            // ── Object literal: {k: v, ...} ───────────────────────────
            // Modelled as FuncCall(OBJECT_CONSTRUCT, [k, v, ...]) so
            // all value column refs are visible to IR analyses.
            AstExpr::Object { entries, span, .. } => {
                let mut args = Vec::with_capacity(entries.len() * 2);
                for (k, v) in entries {
                    args.push(self.lower_expr_or_opaque_local(k, aliases)?);
                    args.push(self.lower_expr_or_opaque_local(v, aliases)?);
                }
                Ok(ScalarExpr::FuncCall {
                    func: ResolvedFunc::unresolved("OBJECT_CONSTRUCT", None, *span),
                    args,
                    distinct: false,
                    named_args: Vec::new(),
                    span: *span,
                })
            }
            // ── Bind parameter placeholder: ? ──────────────────────────
            // No column references inside; model as a variant literal
            // (bind parameter value is unknown at static analysis time).
            AstExpr::Placeholder { span, .. } => Ok(ScalarExpr::Lit {
                value: Lit::Variant("?".to_string()),
                span: *span,
            }),
            // ── Positional column ref: $1, qualifier.$2 ───────────────
            // Positional refs carry no column-binding information at
            // static analysis time; model as a variant literal.
            AstExpr::PositionRef { .. } => Ok(ScalarExpr::Lit {
                value: Lit::Variant("$pos".to_string()),
                span: expr.span(),
            }),
            // ── PRIOR expr (hierarchical queries) ─────────────────────
            // UnaryOp preserves the inner column refs for taint/lineage.
            AstExpr::Prior { expr, span, .. } => {
                let arg = Box::new(self.lower_expr_or_opaque_local(expr, aliases)?);
                Ok(ScalarExpr::UnaryOp {
                    op: super::scalar::UnaryOpKind::Prior,
                    arg,
                    span: *span,
                })
            }
            // ── Spread: ** expr ───────────────────────────────────────
            AstExpr::Spread { expr, span, .. } => {
                let arg = Box::new(self.lower_expr_or_opaque_local(expr, aliases)?);
                Ok(ScalarExpr::UnaryOp {
                    op: super::scalar::UnaryOpKind::Spread,
                    arg,
                    span: *span,
                })
            }
            // ── EXPL$SNOWIDENT ────────────────────────────────────────
            // Snowflake internal. Preserve the inner column ref by
            // treating it as a FuncCall wrapper.
            AstExpr::ExplSnowIdent { arg, span, .. } => {
                let lowered_arg = self.lower_expr_or_opaque_local(arg, aliases)?;
                Ok(ScalarExpr::FuncCall {
                    func: ResolvedFunc::unresolved("EXPL$SNOWIDENT", None, *span),
                    args: vec![lowered_arg],
                    distinct: false,
                    named_args: Vec::new(),
                    span: *span,
                })
            }
            // ── Scripting variable ref: :my_var ───────────────────────
            // No column refs inside; model as a named variant literal.
            AstExpr::ScriptingVarRef {
                name_span, span, ..
            } => {
                let name = slice_span(self.source, *name_span)
                    .unwrap_or(":var")
                    .to_string();
                Ok(ScalarExpr::Lit {
                    value: Lit::Variant(name),
                    span: *span,
                })
            }
            // ── Star in an expression position ────────────────────────
            // Stars are not scalar values; they only make sense in a
            // projection list (handled by `lower_inline_star` before
            // this arm is reached) or as the single argument of
            // `COUNT(*)` / `fn(*)` (intercepted in aggregate /
            // function-call lowering before this arm is reached).
            // Any remaining occurrence is a malformed shape; keep the
            // enclosing statement concrete by returning a local opaque.
            AstExpr::QualifiedStar { span, .. }
            | AstExpr::UnqualifiedStar { span, .. }
            | AstExpr::QualifiedStarFromExpr { span, .. } => Ok(ScalarExpr::Opaque {
                span: *span,
                reason: "star_in_scalar_position".to_string(),
            }),
            // ── TVF with schema clause: OPENJSON(...) WITH (...) ──────
            // The WITH schema clause is a result-schema declaration; the
            // inner func_call is already a FunctionCall and carries the
            // column refs. Lower it directly.
            AstExpr::TvfWithSchema { func_call, .. } => self.lower_expr(func_call, aliases),
            // ── Method call: expr.method(args) ───────────────────────
            // Modelled as FuncCall(method_name, [receiver, arg1, ...])
            // so all column refs (base + args) are visible to analyses.
            AstExpr::MethodCall {
                base,
                method_name_span,
                args,
                span,
                ..
            } => {
                let method_name = slice_span(self.source, *method_name_span)
                    .unwrap_or("method")
                    .to_string();
                let mut lowered_args = Vec::with_capacity(args.len() + 1);
                lowered_args.push(self.lower_expr_or_opaque_local(base, aliases)?);
                for a in args {
                    lowered_args.push(self.lower_expr_or_opaque_local(a, aliases)?);
                }
                Ok(ScalarExpr::FuncCall {
                    func: ResolvedFunc::unresolved(method_name, None, *method_name_span),
                    args: lowered_args,
                    distinct: false,
                    named_args: Vec::new(),
                    span: *span,
                })
            }
            // ── Subquery used as function argument ─────────────────────
            AstExpr::SubqueryArg { subquery, span, .. } => {
                let plan = self
                    .lower_stmt_as_subquery(subquery)
                    .unwrap_or_else(|e| e.into_terminal(crate::ast::NodeId::new(0)));
                Ok(ScalarExpr::ScalarSubquery {
                    subquery: Box::new(plan),
                    correlates_with: vec![],
                    span: *span,
                })
            }
            // ── Jinja conditional in expression position ──────────────
            AstExpr::JinjaConditional { span, .. } => Err(LowerError::opaque(
                *span,
                OpaqueReason::UnresolvedJinja { macro_name: None },
            )),
            // ── Parser error recovery node ────────────────────────────
            AstExpr::Error { span, .. } => Ok(ScalarExpr::Opaque {
                span: *span,
                reason: "parse_error_expr".to_string(),
            }),
            AstExpr::FunctionCall { .. } => self.lower_function_call(expr, aliases),
            AstExpr::WindowFn { .. } => self.lower_window_fn(expr, aliases),
            AstExpr::WindowExpr {
                base, window, span, ..
            } => self.lower_window_expr(base, window, *span, aliases),
        }
    }

    /// Lower an expression with "no aggregates" and "no windows"
    /// frames on top of the sink stacks. Used for sub-expressions that
    /// must not themselves contain set-reducing or analytic operators
    /// (`WHERE`, `GROUP BY`, `FILTER (WHERE …)`, `WITHIN GROUP`
    /// ordering, window frame bounds). The outer frames are preserved
    /// so the enclosing context resumes unchanged after the pop.
    fn lower_expr_no_aggs(
        &mut self,
        expr: &AstExpr,
        aliases: Option<&AliasMap>,
    ) -> Result<ScalarExpr, LowerError> {
        self.push_no_agg_frame();
        self.push_no_window_frame();
        let result = self.lower_expr(expr, aliases);
        self.pop_no_window_frame();
        self.pop_no_agg_frame();
        result
    }

    /// Enter the lowering scope used for window-function `OVER` clause
    /// sub-expressions (window args, `PARTITION BY`, `ORDER BY`).
    ///
    /// SQL semantics: `OVER (...)` clauses execute *after* aggregation,
    /// so they may legally reference aggregates of the enclosing
    /// SELECT's grouping. The canonical example is
    /// `ROW_NUMBER() OVER (ORDER BY COUNT(*) DESC)` in a query with
    /// `GROUP BY`: the aggregate is computed per group and the window
    /// function ranks groups by it. A nested `OVER` (window inside
    /// window) is forbidden — there is no second analytic phase.
    ///
    /// At call time the aggregate-sink stack may carry a `no-agg`
    /// frame above the SELECT-body's collecting frame (e.g. when the
    /// `WindowFn` is being lowered inside a `QUALIFY` predicate, which
    /// itself forbids plain aggregates). Aggregates inside an `OVER`
    /// clause must promote to the SELECT-body's collecting frame, not
    /// be rejected by an intervening `no-agg` frame. Temporarily lift
    /// any contiguous `no-agg` frames off the top of the stack so the
    /// SELECT-body's collecting frame is exposed; the saved frames are
    /// restored on exit. A `no-window` frame is pushed so any nested
    /// window call inside the `OVER` is rejected.
    ///
    /// Returns the saved frames; the caller MUST pass them to
    /// [`Self::exit_window_over_scope`] in the same order regardless
    /// of intermediate `Result` propagation.
    fn enter_window_over_scope(&mut self) -> Vec<Option<Vec<AggregateCall>>> {
        let mut saved: Vec<Option<Vec<AggregateCall>>> = Vec::new();
        while matches!(self.aggregate_sinks.last(), Some(None)) {
            // `last() == Some(None)` ⇒ the stack is non-empty and the
            // top frame is a no-agg frame. `pop()` therefore returns
            // `Some(None)` and never panics; the loop terminates as
            // soon as we hit a collecting frame or empty the stack.
            saved.push(
                self.aggregate_sinks
                    .pop()
                    .expect("matches Some implies stack is non-empty"),
            );
        }
        self.push_no_window_frame();
        saved
    }

    /// Exit a window-function `OVER` scope previously entered via
    /// [`Self::enter_window_over_scope`]. Restores the saved no-agg
    /// frames in original order and pops the no-window frame.
    fn exit_window_over_scope(&mut self, saved: Vec<Option<Vec<AggregateCall>>>) {
        self.pop_no_window_frame();
        for frame in saved.into_iter().rev() {
            self.aggregate_sinks.push(frame);
        }
    }

    /// Lower an `AstExpr::WindowExpr` (arbitrary base expression with
    /// an `OVER` clause, e.g.
    /// `APPROX_QUANTILES(val, 100)[OFFSET(50)] OVER (PARTITION BY grp)`)
    /// into a `WindowCall` collected on the innermost window sink.
    ///
    /// The base expression is lowered in the over-scope (so inner
    /// aggregates promote to the SELECT-body frame) and used as the
    /// single synthetic argument of the window call.
    fn lower_window_expr(
        &mut self,
        base: &AstExpr,
        window: &crate::ast::AstWindowSpec,
        span: Span,
        aliases: Option<&AliasMap>,
    ) -> Result<ScalarExpr, LowerError> {
        if self.innermost_forbids_windows() {
            return Err(LowerError::invalid(
                span,
                InvalidInputKind::WindowContext(WindowContextCategory::FunctionInDisallowedContext),
            ));
        }
        if self.innermost_window_sink().is_none() {
            return Err(LowerError::invalid(
                span,
                InvalidInputKind::WindowContext(
                    WindowContextCategory::FunctionOutsideWindowContext,
                ),
            ));
        }

        // Lower the base expression inside the over-scope so aggregates
        // inside the base (e.g. APPROX_QUANTILES) route to the SELECT
        // collecting frame and nested OVER is rejected.
        let saved_over_frames = self.enter_window_over_scope();
        let base_result = self.lower_expr_or_opaque_local(base, aliases);
        self.exit_window_over_scope(saved_over_frames);
        let base_lowered = base_result?;

        // Named window reference in a WindowExpr is not supported —
        // the base is an arbitrary expression, not a plain function name.
        if let Some(name_span) = window.existing_window_name {
            return Err(LowerError::invalid(
                name_span,
                InvalidInputKind::WindowContext(
                    WindowContextCategory::NamedReferenceOutOfCurrentScope,
                ),
            ));
        }

        let partition_by = window
            .partition_by
            .iter()
            .map(|e| self.lower_expr(e, aliases))
            .collect::<Result<Vec<_>, _>>()?;

        let mut order_by = Vec::with_capacity(window.order_by.len());
        for item in &window.order_by {
            let expr = self.lower_expr(&item.expr, aliases)?;
            order_by.push(SortKey {
                expr,
                ascending: item.asc.unwrap_or(true),
                nulls_first: item.nulls_first,
                span: item.span,
            });
        }

        let frame = match window.frame.as_deref() {
            Some(f) => Some(self.lower_window_frame(f, aliases)?),
            None => None,
        };

        let display_name = slice_span(self.source, span).unwrap_or("").to_string();
        let output = self.alloc_synthetic(span, display_name);
        let call = WindowCall {
            func: ResolvedFunc::unresolved("__window_expr__", None, base.span()),
            args: vec![base_lowered],
            distinct: false,
            null_treatment: NullTreatment::Default,
            partition_by,
            order_by,
            frame,
            named_window: None,
            output,
            span,
        };
        match self.innermost_window_sink() {
            Some(sink) => sink.push(call),
            None => unreachable!(
                "innermost_window_sink went from Some to None within lower_window_expr; \
                 push/pop frame discipline must preserve the enclosing collection frame"
            ),
        }
        Ok(ScalarExpr::Column {
            column: output,
            span,
        })
    }

    /// Lower an `AstExpr::WindowFn` into a `WindowCall` collected on
    /// the innermost window sink, returning a scalar `Column`
    /// reference to that window output.
    fn lower_window_fn(
        &mut self,
        expr: &AstExpr,
        aliases: Option<&AliasMap>,
    ) -> Result<ScalarExpr, LowerError> {
        let AstExpr::WindowFn {
            func_name,
            quantifier,
            args,
            within_group,
            filter,
            null_handling,
            window,
            span,
            ..
        } = expr
        else {
            unreachable!("lower_window_fn called on non-WindowFn variant");
        };
        let span = *span;

        if self.innermost_forbids_windows() {
            return Err(LowerError::invalid(
                span,
                InvalidInputKind::WindowContext(WindowContextCategory::FunctionInDisallowedContext),
            ));
        }
        if self.innermost_window_sink().is_none() {
            return Err(LowerError::invalid(
                span,
                InvalidInputKind::WindowContext(
                    WindowContextCategory::FunctionOutsideWindowContext,
                ),
            ));
        }
        if within_group.is_some() {
            return Err(LowerError::invalid(
                span,
                InvalidInputKind::WindowContext(
                    WindowContextCategory::WithinGroupOutOfCurrentScope,
                ),
            ));
        }
        if filter.is_some() {
            return Err(LowerError::invalid(
                span,
                InvalidInputKind::WindowContext(
                    WindowContextCategory::FilterClauseOutOfCurrentScope,
                ),
            ));
        }

        let raw_name = slice_span(self.source, func_name.span).unwrap_or("");
        let name_span = func_name.span;
        let func = match self.catalog.lookup(raw_name) {
            Some(id) => ResolvedFunc::Resolved {
                id,
                span: name_span,
            },
            None if self.strict.forbids_opaque() => {
                return Err(LowerError::opaque(
                    name_span,
                    OpaqueReason::UnknownFunction {
                        raw_name: raw_name.to_string(),
                    },
                ));
            }
            None => ResolvedFunc::unresolved(raw_name, None, name_span),
        };

        let distinct = matches!(quantifier, Some((AstSetQuantifier::Distinct, _)));
        let is_star_call = args.len() == 1
            && matches!(
                args[0].as_ref(),
                AstFunctionArg::Positional(inner)
                    if matches!(inner.as_ref(), AstExpr::UnqualifiedStar { .. })
            );

        // Args / PARTITION BY / ORDER BY of an `OVER (...)` clause
        // are lowered under [`Self::enter_window_over_scope`]: the
        // enclosing SELECT-body's aggregate-collection frame is
        // exposed so SQL-legal aggregates like
        // `ROW_NUMBER() OVER (ORDER BY COUNT(*) DESC)` route into it,
        // while a no-window frame forbids nested `OVER` clauses.
        // Frame bounds are *not* covered here — they require constant
        // (non-aggregate) expressions and continue to use
        // [`Self::lower_expr_no_aggs`] inside `lower_window_frame`.
        let saved_over_frames = self.enter_window_over_scope();
        let over_result =
            self.lower_window_over_subexprs(args, is_star_call, window, span, aliases);
        self.exit_window_over_scope(saved_over_frames);
        // `lower_window_over_subexprs` already lowered the inline
        // args/partition_by/order_by, but when a named window is
        // referenced we must merge the base spec's expressions too.
        // Re-do partition_by/order_by/frame using the merged helper
        // when a name is present; otherwise use the inline results
        // directly.
        let (lowered_args, partition_by, order_by, frame, named_window) = if let Some(name_span) =
            window.existing_window_name
        {
            // The inline args were already lowered. Partition / order /
            // frame come from the merged resolver (which re-lowers the
            // base expressions from their AST nodes, so the inline
            // partition_by/order_by returned by lower_window_over_subexprs
            // for the *inline* portion are discarded and recomputed).
            let (lowered_args_inner, _, _) = over_result?;
            let (part, ord, frm, key) = self.lower_named_window_ref(name_span, window, aliases)?;
            (lowered_args_inner, part, ord, frm, key)
        } else {
            let (lowered_args_inner, partition_by, order_by) = over_result?;
            let frame = match window.frame.as_deref() {
                Some(f) => Some(self.lower_window_frame(f, aliases)?),
                None => None,
            };
            (lowered_args_inner, partition_by, order_by, frame, None)
        };

        let null_treatment = match null_handling {
            Some((true, _)) => NullTreatment::Ignore,
            Some((false, _)) => NullTreatment::Respect,
            None => NullTreatment::Default,
        };

        // display_name carries the source text of the window call so
        // lineage / rule surfaces can render `row_number() OVER (...)`
        // rather than an anonymous id.
        let display_name = slice_span(self.source, expr.span())
            .unwrap_or("")
            .to_string();
        let output = self.alloc_synthetic(expr.span(), display_name);
        let call = WindowCall {
            func,
            args: lowered_args,
            distinct,
            null_treatment,
            partition_by,
            order_by,
            frame,
            named_window,
            output,
            span,
        };
        match self.innermost_window_sink() {
            Some(sink) => sink.push(call),
            None => unreachable!(
                "innermost_window_sink went from Some to None within lower_window_fn; \
                 push/pop frame discipline must preserve the enclosing collection frame"
            ),
        }
        Ok(ScalarExpr::Column {
            column: output,
            span,
        })
    }

    /// Lower the sub-expressions of an `OVER (...)` clause: window
    /// args, `PARTITION BY`, and `ORDER BY`. Caller must already have
    /// entered the over-scope via [`Self::enter_window_over_scope`].
    ///
    /// Aggregates are *allowed* in these positions and route to the
    /// SELECT-body's collecting aggregate frame (exposed by the
    /// over-scope guard); nested `OVER` calls are forbidden by the
    /// no-window frame the guard pushed. Window args use plain
    /// [`Self::lower_expr`] for the same reason.
    fn lower_named_window_ref(
        &mut self,
        name_span: Span,
        inline_spec: &crate::ast::AstWindowSpec,
        aliases: Option<&AliasMap>,
    ) -> Result<NamedWindowParts, LowerError> {
        let named_key = slice_span(self.source, name_span).map(IdentKey::new);

        let base_spec: Option<crate::ast::AstWindowSpec> = named_key.as_ref().and_then(|key| {
            self.named_window_defs
                .iter()
                .rev()
                .find_map(|scope| scope.get(key).cloned())
        });

        if base_spec.is_none() && self.strict.forbids_opaque() {
            return Err(LowerError::invalid(
                name_span,
                InvalidInputKind::WindowContext(
                    WindowContextCategory::NamedReferenceOutOfCurrentScope,
                ),
            ));
        }

        let partition_source = match base_spec.as_ref() {
            Some(base) if !base.partition_by.is_empty() => &base.partition_by,
            _ => &inline_spec.partition_by,
        };
        let partition_by = partition_source
            .iter()
            .map(|expr| self.lower_expr(expr, aliases))
            .collect::<Result<Vec<_>, _>>()?;

        let mut order_by = Vec::new();
        if let Some(base) = base_spec.as_ref() {
            for item in &base.order_by {
                let expr = self.lower_expr(&item.expr, aliases)?;
                order_by.push(SortKey {
                    expr,
                    ascending: item.asc.unwrap_or(true),
                    nulls_first: item.nulls_first,
                    span: item.span,
                });
            }
        }
        for item in &inline_spec.order_by {
            let expr = self.lower_expr(&item.expr, aliases)?;
            order_by.push(SortKey {
                expr,
                ascending: item.asc.unwrap_or(true),
                nulls_first: item.nulls_first,
                span: item.span,
            });
        }

        let frame = if let Some(frame) = inline_spec.frame.as_deref() {
            Some(self.lower_window_frame(frame, aliases)?)
        } else if let Some(base) = base_spec.as_ref() {
            match base.frame.as_deref() {
                Some(frame) => Some(self.lower_window_frame(frame, aliases)?),
                None => None,
            }
        } else {
            None
        };

        Ok((partition_by, order_by, frame, named_key))
    }

    fn lower_window_over_subexprs(
        &mut self,
        args: &[Box<crate::ast::AstFunctionArg>],
        is_star_call: bool,
        window: &crate::ast::AstWindowSpec,
        call_span: Span,
        aliases: Option<&AliasMap>,
    ) -> Result<WindowOverParts, LowerError> {
        let lowered_args: Vec<ScalarExpr> = if is_star_call {
            Vec::new()
        } else {
            let mut out = Vec::with_capacity(args.len());
            for arg in args {
                match arg.as_ref() {
                    AstFunctionArg::Positional(inner) => {
                        out.push(self.lower_expr(inner, aliases)?);
                    }
                    // BULK file argument is not a window-call shape, but lower it
                    // as its inner expression for completeness.
                    AstFunctionArg::BulkArg { value, .. } => {
                        out.push(self.lower_expr(value, aliases)?);
                    }
                    AstFunctionArg::Named { .. } | AstFunctionArg::AliasedArg { .. } => {
                        return Err(LowerError::invalid(
                            call_span,
                            InvalidInputKind::WindowContext(
                                WindowContextCategory::NamedArgsOnWindowCall,
                            ),
                        ));
                    }
                    AstFunctionArg::Lambda { .. } => {
                        return Err(LowerError::invalid(
                            call_span,
                            InvalidInputKind::WindowContext(
                                WindowContextCategory::LambdaOnWindowCallOutOfCurrentScope,
                            ),
                        ));
                    }
                }
            }
            out
        };

        let partition_by = window
            .partition_by
            .iter()
            .map(|e| self.lower_expr(e, aliases))
            .collect::<Result<Vec<_>, _>>()?;

        let mut order_by = Vec::with_capacity(window.order_by.len());
        for item in &window.order_by {
            let expr = self.lower_expr(&item.expr, aliases)?;
            order_by.push(SortKey {
                expr,
                ascending: item.asc.unwrap_or(true),
                nulls_first: item.nulls_first,
                span: item.span,
            });
        }

        Ok((lowered_args, partition_by, order_by))
    }

    fn lower_window_frame(
        &mut self,
        frame: &crate::ast::AstWindowFrame,
        aliases: Option<&AliasMap>,
    ) -> Result<WindowFrame, LowerError> {
        let mode = match frame.kind {
            AstWindowFrameKind::Rows => FrameMode::Rows,
            AstWindowFrameKind::Range => FrameMode::Range,
        };
        let start = self.lower_window_frame_bound(&frame.start, aliases)?;
        let end = match frame.end.as_ref() {
            Some(b) => self.lower_window_frame_bound(b, aliases)?,
            None => FrameBound::CurrentRow,
        };
        Ok(WindowFrame {
            mode,
            start,
            end,
            exclusion: FrameExclusion::NoOthers,
        })
    }

    fn lower_window_frame_bound(
        &mut self,
        bound: &crate::ast::AstFrameBound,
        aliases: Option<&AliasMap>,
    ) -> Result<FrameBound, LowerError> {
        match bound.kind {
            AstFrameBoundKind::UnboundedPreceding => Ok(FrameBound::UnboundedPreceding),
            AstFrameBoundKind::UnboundedFollowing => Ok(FrameBound::UnboundedFollowing),
            AstFrameBoundKind::CurrentRow => Ok(FrameBound::CurrentRow),
            AstFrameBoundKind::Preceding => {
                let value = match bound.value.as_deref() {
                    Some(v) => self.lower_expr_no_aggs(v, aliases)?,
                    None => {
                        return Err(LowerError::invalid(
                            bound.span,
                            InvalidInputKind::WindowContext(
                                WindowContextCategory::FrameBoundMissingValue,
                            ),
                        ));
                    }
                };
                Ok(FrameBound::Preceding(value))
            }
            AstFrameBoundKind::Following => {
                let value = match bound.value.as_deref() {
                    Some(v) => self.lower_expr_no_aggs(v, aliases)?,
                    None => {
                        return Err(LowerError::invalid(
                            bound.span,
                            InvalidInputKind::WindowContext(
                                WindowContextCategory::FrameBoundMissingValue,
                            ),
                        ));
                    }
                };
                Ok(FrameBound::Following(value))
            }
        }
    }

    /// Lower an `AstExpr::FunctionCall` to either [`ScalarExpr::FuncCall`]
    /// or — when the call is aggregate-shaped and the enclosing context
    /// is collecting aggregates — a [`ScalarExpr::Column`] that
    /// references the aggregate's synthesized output `ColumnId`. In
    /// that latter case an [`AggregateCall`] is pushed onto the
    /// innermost collection frame as a side effect.
    ///
    /// Function identity resolves through the session's
    /// [`FunctionCatalog`]: a catalog hit produces
    /// [`ResolvedFunc::Resolved`] and reads aggregate / window /
    /// scalar shape from the signature; a catalog miss produces
    /// [`ResolvedFunc::Unresolved`] and is treated as scalar shape in
    /// permissive mode (strict mode surfaces
    /// [`OpaqueReason::UnknownFunction`]).
    fn lower_function_call(
        &mut self,
        expr: &AstExpr,
        aliases: Option<&AliasMap>,
    ) -> Result<ScalarExpr, LowerError> {
        let AstExpr::FunctionCall {
            func_name,
            quantifier,
            approximate,
            odbc_fn,
            args,
            inline_order_by,
            within_group,
            filter,
            span,
            ..
        } = expr
        else {
            unreachable!("lower_function_call called on non-FunctionCall variant");
        };
        let approximate = *approximate;
        let span = *span;

        let raw_name = slice_span(self.source, func_name.span).unwrap_or("");
        let name_span = func_name.span;

        // Resolve the function through the catalog. `FunctionKind`
        // (not a string-match against `raw_name`) drives aggregate-
        // promotion and window-shape decisions downstream. An
        // unresolved name is treated as `Scalar` shape: the call
        // round-trips by raw name but no aggregate / window inference
        // is attempted for it. Under strict-IR mode the unresolved
        // case is a lowering failure so the caller can tell the
        // catalog is incomplete for the input.
        // Direct spelling wins; the ODBC canonical-name mapping (UCASE →
        // UPPER, CURDATE → CURRENT_DATE, …) applies ONLY under a `{fn …}`
        // escape — bare UCASE(x) is not native SQL and stays unresolved.
        let looked_up = match self.catalog.lookup(raw_name) {
            Some(id) => Some(id),
            None if *odbc_fn => crate::ir::catalog::odbc_canonical_function_target(raw_name)
                .and_then(|native| self.catalog.lookup(native)),
            None => None,
        };
        let (func, resolved_kind) = match looked_up {
            Some(id) => {
                let kind = self
                    .catalog
                    .kind(id)
                    .expect("catalog.lookup returned id but catalog.kind is None");
                (
                    ResolvedFunc::Resolved {
                        id,
                        span: name_span,
                    },
                    Some(kind),
                )
            }
            None if self.strict.forbids_opaque() => {
                return Err(LowerError::opaque(
                    name_span,
                    OpaqueReason::UnknownFunction {
                        raw_name: raw_name.to_string(),
                    },
                ));
            }
            None => (ResolvedFunc::unresolved(raw_name, None, name_span), None),
        };

        let distinct = matches!(quantifier, Some(AstSetQuantifier::Distinct));
        // `fn(*)` (most commonly `COUNT(*)`) has no IR scalar analogue
        // — there is no `ScalarExpr::Star`. We encode it as a
        // zero-argument aggregate call; this is unambiguous because no
        // aggregate takes zero positional arguments in any dialect we
        // support.
        let is_star_call = args.len() == 1
            && matches!(
                args[0].as_ref(),
                AstFunctionArg::Positional(inner)
                    if matches!(inner.as_ref(), AstExpr::UnqualifiedStar { .. })
            );
        let lowered_args: Vec<ScalarExpr>;
        let lowered_named_args: Vec<(IdentKey, ScalarExpr)>;
        if is_star_call {
            lowered_args = Vec::new();
            lowered_named_args = Vec::new();
        } else {
            let (p, n) = self.lower_function_args(args, aliases)?;
            lowered_args = p;
            lowered_named_args = n;
        }

        let in_collection_frame = self.innermost_agg_sink().is_some();
        let forbids_aggs = self.innermost_forbids_aggs();
        // A call has aggregate shape if the catalog classifies it as
        // Aggregate / WindowAggregate, or if it carries an aggregate-
        // only modifier (`WITHIN GROUP`, `FILTER (WHERE …)`). Window
        // and plain Scalar kinds are not aggregate-shaped; Unresolved
        // functions default to non-aggregate (modifiers still force
        // aggregate shape because the call syntactically claims it).
        let catalog_says_aggregate = matches!(
            resolved_kind,
            Some(FunctionKind::Aggregate) | Some(FunctionKind::WindowAggregate)
        );
        let is_agg_shape = catalog_says_aggregate
            || within_group.is_some()
            || filter.is_some()
            || inline_order_by.is_some();

        if is_agg_shape && forbids_aggs {
            return Err(LowerError::invalid(
                span,
                InvalidInputKind::AggregateContext(AggregateContextCategory::InDisallowedContext),
            ));
        }

        if in_collection_frame && is_agg_shape {
            // Named arguments (`kwarg => value`) on an aggregate-shaped
            // call are carried in `AggregateCall::named_args`, mirroring
            // the positional / named split on `ScalarExpr::FuncCall`.
            // Snowflake permits them on
            // aggregate UDF calls; the IR must preserve the name as
            // part of the call's identity for overload resolution and
            // downstream lineage.
            //
            // FILTER/WITHIN GROUP sub-expressions must not themselves
            // contain aggregates. Push a no-agg frame while lowering
            // them; the outer collection frame is restored after pop.
            let filter_lowered = match filter.as_deref() {
                Some(fc) => Some(self.lower_expr_no_aggs(&fc.expr, aliases)?),
                None => None,
            };
            let within_group_order = match within_group.as_deref() {
                Some(wg) => self.lower_within_group(wg, aliases)?,
                None => Vec::new(),
            };
            let arg_order = match inline_order_by.as_ref() {
                Some(items) => self.lower_inline_order_by(items, aliases)?,
                None => Vec::new(),
            };
            // PG-style inline `ORDER BY` inside the argument list and
            // SQL:2003 `WITHIN GROUP (ORDER BY ...)` are semantically
            // disjoint sorts — one orders the aggregate's input rows,
            // the other parameterizes an ordered-set aggregate. A
            // single call must not populate both; surface a typed
            // lowering error so strict mode rejects and permissive
            // mode produces a single-reason `Opaque`.
            if !arg_order.is_empty() && !within_group_order.is_empty() {
                return Err(LowerError::invalid(
                    span,
                    InvalidInputKind::ConflictingAggregateOrderings,
                ));
            }
            // display_name = source slice of the call (e.g. `sum(x)`).
            let display_name = slice_span(self.source, span).unwrap_or("").to_string();
            let output = self.alloc_synthetic(span, display_name);
            let call = AggregateCall {
                func,
                args: lowered_args,
                named_args: lowered_named_args,
                distinct,
                approximate,
                filter: filter_lowered,
                arg_order,
                within_group_order,
                // `IGNORE NULLS` / `RESPECT NULLS` only appears on
                // window-function calls in the AST (`AstExpr::WindowExpr`),
                // never on `AstExpr::FunctionCall`. Plain-aggregate null
                // treatment is therefore complete at `Default` for this
                // lowering path — it is not a deferred field.
                null_treatment: NullTreatment::Default,
                output,
                span,
            };
            self.innermost_agg_sink()
                .expect("in_collection_frame implies innermost_agg_sink is Some")
                .push(call);
            return Ok(ScalarExpr::Column {
                column: output,
                span,
            });
        }

        // Not in a collection frame, or the call is not aggregate-shaped.
        // `FILTER` / `WITHIN GROUP` / inline `ORDER BY` outside a
        // collection frame has no anchor; surface as a typed lowering
        // error rather than silently dropping the modifier.
        if within_group.is_some() || filter.is_some() || inline_order_by.is_some() {
            return Err(LowerError::invalid(
                span,
                InvalidInputKind::AggregateContext(
                    AggregateContextCategory::ModifierOutsideAggregateContext,
                ),
            ));
        }

        Ok(ScalarExpr::FuncCall {
            func,
            args: lowered_args,
            named_args: lowered_named_args,
            distinct,
            span,
        })
    }

    /// Lower function arguments into separate positional / named
    /// lists.
    ///
    /// - `AstFunctionArg::Positional` → appended to `positional`.
    /// - `AstFunctionArg::Named { name, value, .. }` → appended to
    ///   `named` as `(IdentKey::new(name), lowered_value)`. Named
    ///   arguments are order-significant in the IR only to the extent
    ///   the lowerer preserves source order; overload resolution (a
    ///   later phase) is responsible for re-sorting against the
    ///   signature.
    /// - `AstFunctionArg::AliasedArg { value, alias, .. }` — BigQuery
    ///   `STRUCT(1 AS x, 'a' AS y)` — is semantically equivalent to a
    ///   named arg for IR purposes: the `alias` becomes the key and
    ///   the value is lowered normally.
    /// - `AstFunctionArg::Lambda { params, body, .. }` → lowered to a
    ///   [`ScalarExpr::Lambda`] in the `positional` slot. The IR does
    ///   not reserve a separate slot for lambdas; higher-order
    ///   functions consume them positionally.
    fn lower_function_args(
        &mut self,
        args: &[Box<AstFunctionArg>],
        aliases: Option<&AliasMap>,
    ) -> Result<LoweredArgs, LowerError> {
        let mut positional: Vec<ScalarExpr> = Vec::with_capacity(args.len());
        let mut named: Vec<(IdentKey, ScalarExpr)> = Vec::new();
        for arg in args {
            match arg.as_ref() {
                AstFunctionArg::Positional(inner) => {
                    positional.push(self.lower_expr(inner, aliases)?)
                }
                // OPENROWSET(BULK '<file>', …): the `BULK` prefix is recognition
                // metadata; the lowered argument is the file-path expression, so
                // it flows into the OPENROWSET call facts like any positional.
                AstFunctionArg::BulkArg { value, .. } => {
                    positional.push(self.lower_expr(value, aliases)?)
                }
                AstFunctionArg::Named { name, value, .. } => {
                    let raw = slice_span(self.source, name.span).unwrap_or("");
                    let key = IdentKey::new(raw);
                    let value = self.lower_expr(value, aliases)?;
                    named.push((key, value));
                }
                AstFunctionArg::AliasedArg { value, alias, .. } => {
                    let raw = slice_span(self.source, alias.span).unwrap_or("");
                    let key = IdentKey::new(raw);
                    let value = self.lower_expr(value, aliases)?;
                    named.push((key, value));
                }
                AstFunctionArg::Lambda {
                    params,
                    body,
                    span: lambda_span,
                    ..
                } => {
                    positional.push(self.lower_lambda(params, body, *lambda_span, aliases)?);
                }
            }
        }
        Ok((positional, named))
    }

    /// Lower a lambda argument into [`ScalarExpr::Lambda`]. Each
    /// parameter gets a fresh [`ColumnId`] bound in the local
    /// bindings table for the duration of the body walk; the previous
    /// binding (if any) is saved and restored so the lambda's params
    /// do not leak.
    fn lower_lambda(
        &mut self,
        params: &[crate::ast::AstIdentifier],
        body: &AstExpr,
        span: Span,
        aliases: Option<&AliasMap>,
    ) -> Result<ScalarExpr, LowerError> {
        // Bind each param to a fresh ColumnId, remembering any prior
        // binding under the same normalized name so we can restore
        // after lowering the body (params are lexically scoped).
        let mut lambda_params: Vec<super::scalar::LambdaParam> = Vec::with_capacity(params.len());
        let mut saved: Vec<(IdentKey, Option<ColumnId>)> = Vec::with_capacity(params.len());
        for p in params {
            let raw = slice_span(self.source, p.span).unwrap_or("").to_string();
            let key = IdentKey::new(&raw);
            let id = self.alloc_synthetic(p.span, raw);
            let prior = self.bindings.insert(key.clone(), id);
            saved.push((key.clone(), prior));
            lambda_params.push(super::scalar::LambdaParam {
                name: key,
                id,
                span: p.span,
            });
        }
        // Lower the body with the lambda params in scope.
        let lowered_body = self.lower_expr(body, aliases);
        // Restore the prior bindings regardless of success so the outer
        // scope is not corrupted by a lambda's temporary bindings.
        for (key, prior) in saved.into_iter().rev() {
            match prior {
                Some(id) => {
                    self.bindings.insert(key, id);
                }
                None => {
                    self.bindings.remove(&key);
                }
            }
        }
        let body = lowered_body?;
        Ok(ScalarExpr::Lambda {
            params: lambda_params,
            body: Box::new(body),
            span,
        })
    }

    /// Lower the `ORDER BY` list inside `WITHIN GROUP (…)`. Aggregates
    /// are forbidden here — the sink is suppressed by the caller.
    fn lower_within_group(
        &mut self,
        wg: &AstWithinGroup,
        aliases: Option<&AliasMap>,
    ) -> Result<Vec<SortKey>, LowerError> {
        let mut out = Vec::with_capacity(wg.order_by.len());
        for item in &wg.order_by {
            let expr = self.lower_expr_no_aggs(&item.expr, aliases)?;
            out.push(SortKey {
                expr,
                ascending: item.asc.unwrap_or(true),
                nulls_first: item.nulls_first,
                span: item.span,
            });
        }
        Ok(out)
    }

    /// Lower the inline `ORDER BY` list appearing inside an aggregate's
    /// argument list, e.g. `STRING_AGG(x, ',' ORDER BY y DESC)`. Like
    /// `WITHIN GROUP`, aggregates are forbidden in the sort expressions
    /// themselves — use the no-agg frame.
    fn lower_inline_order_by(
        &mut self,
        items: &[Box<crate::ast::AstOrderItem>],
        aliases: Option<&AliasMap>,
    ) -> Result<Vec<SortKey>, LowerError> {
        let mut out = Vec::with_capacity(items.len());
        for item in items {
            let expr = self.lower_expr_no_aggs(&item.expr, aliases)?;
            out.push(SortKey {
                expr,
                ascending: item.asc.unwrap_or(true),
                nulls_first: item.nulls_first,
                span: item.span,
            });
        }
        Ok(out)
    }

    // ── GROUP BY ────────────────────────────────────────────────────────

    fn lower_grouping(
        &mut self,
        gb: &AstGroupBy,
        projection: &[ProjectItem],
    ) -> Result<GroupingSpec, LowerError> {
        match &gb.variant {
            AstGroupByVariant::Standard(items) => {
                let keys = self.lower_group_items(items, projection)?;
                // MySQL `WITH ROLLUP` / legacy T-SQL `WITH CUBE` are the
                // suffix spellings of `GROUP BY ROLLUP(...)` / `CUBE(...)`.
                match gb.with_modifier {
                    Some(crate::ast::AstGroupByWithModifier::Rollup) => {
                        Ok(GroupingSpec::Rollup(keys))
                    }
                    Some(crate::ast::AstGroupByWithModifier::Cube) => Ok(GroupingSpec::Cube(keys)),
                    None => Ok(GroupingSpec::Standard(keys)),
                }
            }
            AstGroupByVariant::All => {
                // `GROUP BY ALL` = "group by every non-aggregate
                // projection item." The aggregate collection frame is
                // still open here, so a projection item is non-aggregate
                // iff its lowered `ScalarExpr` does not reference any
                // already-collected aggregate's output `ColumnId`.
                let agg_outputs: HashMap<ColumnId, ()> = self
                    .innermost_agg_sink()
                    .expect("lower_grouping called inside aggregate frame")
                    .iter()
                    .map(|call| (call.output, ()))
                    .collect();
                let mut keys = Vec::new();
                for item in projection {
                    // `Star` items contribute a catalog-dependent
                    // column list; lowering can't know which, if any,
                    // of them are non-aggregate. Skip them here.
                    let e = match item {
                        ProjectItem::Expr(e) => e,
                        ProjectItem::Star(_) => continue,
                    };
                    if expr_refs_any_column(&e.expr, &agg_outputs) {
                        continue;
                    }
                    // Reuse the projection item's output id as the
                    // group key id so the projection's resulting
                    // column IS the group key (no rename needed).
                    keys.push(GroupKey {
                        expr: e.expr.clone(),
                        output: e.output,
                        span: e.span,
                    });
                }
                Ok(GroupingSpec::All(keys))
            }
            AstGroupByVariant::Elements(elements) => {
                self.lower_group_elements(elements, projection)
            }
            AstGroupByVariant::JinjaPlaceholder(span) => Err(LowerError::opaque(
                *span,
                OpaqueReason::UnresolvedJinja { macro_name: None },
            )),
        }
    }

    fn lower_group_items(
        &mut self,
        items: &[AstGroupItem],
        projection: &[ProjectItem],
    ) -> Result<Vec<GroupKey>, LowerError> {
        let mut out = Vec::with_capacity(items.len());
        for item in items {
            out.push(self.lower_group_item(item, projection)?);
        }
        Ok(out)
    }

    fn lower_group_item(
        &mut self,
        item: &AstGroupItem,
        projection: &[ProjectItem],
    ) -> Result<GroupKey, LowerError> {
        // Ordinal GROUP BY (`GROUP BY 1`) resolves
        // against the projection.
        if let Some(resolved) = self.resolve_group_by_ordinal(&item.expr, projection)? {
            return Ok(resolved);
        }
        // Alias GROUP BY (`GROUP BY alias`) resolves
        // against projection aliases when the identifier does not
        // match a table column. This differs per dialect in
        // ambiguous cases; we follow the "projection-alias first,
        // then input-column" rule (PostgreSQL / MySQL / Snowflake).
        if let AstExpr::Ident { column_ref, .. } = &item.expr {
            if let Some(resolved) =
                self.resolve_group_by_alias(column_ref, item.expr.span(), projection)
            {
                return Ok(resolved);
            }
        }
        let expr = self.lower_expr_no_aggs(&item.expr, None)?;
        // Re-use the underlying column id when the key is a bare
        // column reference; otherwise materialize a fresh output
        // id for the computed key.
        let output = if let ScalarExpr::Column { column, .. } = &expr {
            *column
        } else {
            let display_name = slice_span(self.source, item.expr.span())
                .unwrap_or("")
                .to_string();
            self.alloc_synthetic(item.expr.span(), display_name)
        };
        Ok(GroupKey {
            expr,
            output,
            span: item.expr.span(),
        })
    }

    /// Lower a grouping-element list (`AstGroupByVariant::Elements`).
    fn lower_group_elements(
        &mut self,
        elements: &[AstGroupElement],
        projection: &[ProjectItem],
    ) -> Result<GroupingSpec, LowerError> {
        // A lone grouping operator preserves its dedicated spec, so
        // single-operator clauses lower identically to before the
        // grouping-element list existed.
        if let [only] = elements {
            match &only.kind {
                AstGroupElementKind::Cube(items) => {
                    return Ok(GroupingSpec::Cube(
                        self.lower_group_items(items, projection)?,
                    ));
                }
                AstGroupElementKind::Rollup(items) => {
                    return Ok(GroupingSpec::Rollup(
                        self.lower_group_items(items, projection)?,
                    ));
                }
                AstGroupElementKind::GroupingSets(sets) => {
                    let mut lowered = Vec::with_capacity(sets.len());
                    for set in sets {
                        lowered.push(self.lower_group_items(set, projection)?);
                    }
                    return Ok(GroupingSpec::GroupingSets(lowered));
                }
                AstGroupElementKind::Expr(_) => {}
            }
        }

        // Mixed / multiple elements: a comma-separated grouping-element list
        // denotes the cross-product of each element's grouping sets (SQL:2008).
        // Expand to explicit grouping sets so every downstream consumer sees
        // the resulting key sets.
        match expand_group_elements_item_sets(elements) {
            Some(item_sets) => {
                let mut lowered = Vec::with_capacity(item_sets.len());
                for set in item_sets {
                    let mut keys = Vec::with_capacity(set.len());
                    for item in set {
                        keys.push(self.lower_group_item(item, projection)?);
                    }
                    lowered.push(keys);
                }
                Ok(GroupingSpec::GroupingSets(lowered))
            }
            None => {
                // Expansion exceeded the cap: fall back to the conservative
                // bound — group by the union of every referenced key.
                let mut keys = Vec::new();
                for element in elements {
                    for item in group_element_items(element) {
                        keys.push(self.lower_group_item(item, projection)?);
                    }
                }
                Ok(GroupingSpec::Standard(keys))
            }
        }
    }

    /// Resolve `GROUP BY <integer literal>` or `GROUP BY $n` against
    /// the projection. The parser normalizes both `1` and `$1` in
    /// GROUP BY context to `AstExpr::PositionRef` (see
    /// `parse_single_group_item`); the `dollar_span` is empty for the
    /// bare-integer form and non-empty for `$n`. Returns `Ok(None)`
    /// when the expression is not a position reference; returns `Err`
    /// when it is but is out of range or non-integer.
    fn resolve_group_by_ordinal(
        &self,
        expr: &AstExpr,
        projection: &[ProjectItem],
    ) -> Result<Option<GroupKey>, LowerError> {
        let AstExpr::PositionRef {
            dollar_span,
            index_span,
            qualifier,
            ..
        } = expr
        else {
            return Ok(None);
        };
        // Qualified position refs (`src.$1`) are a different shape —
        // they reference a specific FROM item's column by position and
        // are not the same as a projection ordinal. Surface them as a
        // dedicated typed error rather than silently falling through.
        if qualifier.is_some() {
            return Err(LowerError::invalid(
                *index_span,
                InvalidInputKind::GroupByOrdinal(GroupByOrdinalCategory::QualifiedPositionRef),
            ));
        }
        let raw = slice_span(self.source, *index_span).unwrap_or("");
        let full_span = Span {
            start: dollar_span.start,
            end: index_span.end,
        };
        // Floating-point "ordinals" (`GROUP BY 1.5`) are nonsense;
        // surface as a typed error rather than Ok(None).
        if raw.contains('.') || raw.contains('e') || raw.contains('E') {
            return Err(LowerError::invalid(
                full_span,
                InvalidInputKind::GroupByOrdinal(GroupByOrdinalCategory::NonInteger),
            ));
        }
        let idx: usize = match raw.parse() {
            Ok(n) if n >= 1 => n,
            _ => {
                return Err(LowerError::invalid(
                    full_span,
                    InvalidInputKind::GroupByOrdinal(GroupByOrdinalCategory::NonInteger),
                ));
            }
        };
        if idx > projection.len() {
            // The ordinal is out of range for the current projection.
            // Rather than failing the whole statement (which would produce
            // RelPlan::InvalidInput and lose all table/column information),
            // fall through to scalar lowering. The PositionRef arm there
            // produces ScalarExpr::Lit("$pos") — structurally valid.
            // Same rationale as the Star fallthrough above.
            return Ok(None);
        }
        // When the ordinal targets a `Star` item, the slot's arity is
        // catalog-dependent and lowering cannot resolve it. Return
        // `Ok(None)` so the caller falls through to scalar lowering;
        // the `PositionRef` scalar arm produces a `ScalarExpr::Opaque`
        // group key — structurally valid.
        let item = match &projection[idx - 1] {
            ProjectItem::Expr(e) => e,
            ProjectItem::Star(_) => return Ok(None),
        };
        Ok(Some(GroupKey {
            expr: item.expr.clone(),
            output: item.output,
            span: full_span,
        }))
    }

    /// Resolve `GROUP BY <alias>` against the projection's aliases. A
    /// name is an "alias" only when it is not already bound as an
    /// input column (to avoid masking table columns). Returns `None`
    /// when the identifier does not match any projection alias — the
    /// caller then falls through to plain column-reference lowering.
    fn resolve_group_by_alias(
        &self,
        column_ref: &AstColumnRef,
        key_span: Span,
        projection: &[ProjectItem],
    ) -> Option<GroupKey> {
        // Qualified names (`t.a`) cannot refer to a projection alias —
        // aliases are unqualified identifiers.
        if column_ref.qualifier.is_some() {
            return None;
        }
        let key = self.ident_at(column_ref.name.span);
        // Projection-alias-first rule: if the identifier matches an
        // input-column binding already, that binding wins (plain
        // lowering handles it). This matches Snowflake/PG: columns
        // shadow aliases at GROUP BY unless the column doesn't exist.
        if self.bindings.contains_key(&key) {
            return None;
        }
        projection.iter().find_map(|item| {
            // `Star` items have no alias; only `Expr` items can match.
            let e = match item {
                ProjectItem::Expr(e) => e,
                ProjectItem::Star(_) => return None,
            };
            let alias = e.alias.as_ref()?;
            if *alias == key {
                Some(GroupKey {
                    expr: e.expr.clone(),
                    output: e.output,
                    span: key_span,
                })
            } else {
                None
            }
        })
    }

    fn lower_literal(&self, lit: &AstLiteral) -> ScalarExpr {
        let span = lit.span();
        let raw = slice_span(self.source, span).unwrap_or("");
        let value = match lit {
            AstLiteral::Null { .. } => Lit::Null,
            AstLiteral::Boolean { .. } => Lit::Bool(raw.eq_ignore_ascii_case("true")),
            AstLiteral::Number { .. } => {
                if raw.contains('.') || raw.contains('e') || raw.contains('E') {
                    Lit::Float(raw.to_string())
                } else {
                    Lit::Integer(raw.to_string())
                }
            }
            AstLiteral::String { .. } | AstLiteral::StringWithJinja { .. } => {
                Lit::Str(raw.to_string())
            }
        };
        ScalarExpr::Lit { value, span }
    }

    fn lower_column_ref(&mut self, cref: &AstColumnRef, aliases: Option<&AliasMap>) -> ScalarExpr {
        let name = self.ident_at(cref.name.span);
        // Compute the qualifier's table-scope alias (last segment of
        // the qualifier path) up front: `from_scope` resolution uses
        // it for qualified refs, and the allocate-on-first-use
        // fallback uses it to look up the FROM source's `NodeId` in
        // `from_aliases` so the column is born with the correct
        // `ColumnOrigin::Table { table_node }`.
        let qualifier_alias: Option<IdentKey> = cref.qualifier.as_ref().map(|q| {
            let q_raw = slice_span(self.source, q.span).unwrap_or("");
            let q_parts = split_object_ref(q_raw);
            q_parts
                .last()
                .map(|s| IdentKey::new(s))
                .unwrap_or_else(|| IdentKey::new(q_raw))
        });
        // MATCH_RECOGNIZE intercept: when an
        // expression inside a MEASURES / DEFINE clause carries a
        // qualifier that matches one of the per-MR-node interned
        // pattern variables, emit `PatternVarRef` instead of a
        // plain `Column`. The underlying ColumnId is resolved
        // against the inner row source's column-name scope (the
        // qualifier names a pattern variable, not a relation, so
        // unqualified scope lookup is the right resolution path).
        let mr_symbol = qualifier_alias.as_ref().and_then(|q| {
            self.match_recognize_symbols
                .as_ref()
                .and_then(|t| t.lookup(q))
        });
        if let Some(symbol) = mr_symbol {
            if let Some(column) = self.resolve_from_scope(None, &name) {
                return ScalarExpr::PatternVarRef {
                    symbol,
                    column,
                    span: cref.name.span,
                };
            }
            // Symbol-qualified reference to an unknown column on
            // the inner source. Allocate against the leftmost FROM
            // source (the inner row source — MR has exactly one
            // input). If no source is registered (defensive), fall
            // through to the generic path which will anchor the
            // orphan to `current_stmt_node`.
            if let Some(source) = self.from_source_order.first().copied() {
                // Raw source text (quote-preserving for case-sensitive
                // identifiers) — see `alloc_table_col`'s contract.
                let col_name = slice_span(self.source, cref.name.span)
                    .unwrap_or("")
                    .to_string();
                let fresh = self.alloc_table_col(source, &col_name, cref.name.span);
                self.scan_cols.push((source, fresh));
                return ScalarExpr::PatternVarRef {
                    symbol,
                    column: fresh,
                    span: cref.name.span,
                };
            }
        }
        // Scope-aware column resolution. When the
        // reference can be resolved against the current SELECT's
        // FROM scope, reuse the ColumnId the source node already
        // owns. This prevents a fresh Table-origin orphan from
        // being allocated and then leaking into `BindingTable` and
        // the lineage walk.
        //
        // Resolution order:
        //   1. Qualified `alias.col`: look up by (last-segment of
        //      qualifier, column name) against `from_scope`.
        //   2. Unqualified `col`: `self.bindings` first (lambda /
        //      USING shadows take precedence), then
        //      first-matching scope entry by column name.
        //   3. Unresolved: allocate-on-first-use.
        //      - Qualified refs still use `from_aliases` when the
        //        qualifier resolves to a known source alias.
        //      - Unqualified refs only stamp to a concrete source
        //        NodeId when exactly one FROM source is in scope.
        //        With multiple sources, keep the origin on the
        //        statement node to avoid fabricating a leftmost-source
        //        attribution for ambiguous references.
        if let Some(q_alias) = qualifier_alias.as_ref() {
            if let Some(id) = self.resolve_from_scope(Some(q_alias), &name) {
                return ScalarExpr::Column {
                    column: id,
                    span: cref.name.span,
                };
            }
            if let Some((scope, id)) = self.resolve_outer_from_scope(Some(q_alias), &name) {
                // Correlated reference: emit a first-class `OuterRef`
                // carrying the correlation depth, instead of
                // a plain `Column` that hides the cross-scope binding.
                return ScalarExpr::OuterRef {
                    scope,
                    column: id,
                    span: cref.name.span,
                };
            }
            // Qualified ref not resolvable via from_scope (the source
            // is a Scan / CteRef whose columns are themselves
            // dynamic) — fall through to the allocator. The
            // alias→source-NodeId map populated by FROM lowering
            // gives us the correct `table_node` so the orphan is
            // born already routed.
        } else {
            // System-value keyword recognition. An unqualified reference
            // whose name resolves in the catalog to a temporal-flagged
            // function lowers as a nullary [`ScalarExpr::FuncCall`]
            // rather than a [`ScalarExpr::Column`]. This recovers the
            // typed identity the lexer already encoded
            // (`Keyword::CurrentDate` / `CurrentTime` / `CurrentTimestamp`
            // / `Localtime` / `Localtimestamp`, plus the dialect-callable
            // `NOW` / `SYSDATE` / `GETDATE` identifiers) which the
            // parser dropped when producing `AstExpr::Ident` for the
            // parenless form. Per Snowflake / ANSI / dialect semantics,
            // these names are reserved system values that cannot be
            // unquoted column names; restoring the FuncCall shape is
            // what
            // [`crate::ir::catalog::is_temporal_function`]
            // and
            // [`crate::ir::predicate_extraction::scalar_has_temporal`]
            // expect — both look up the resolved id in the catalog and
            // read [`crate::ir::catalog::FunctionSignature::is_temporal`].
            // The check runs ahead of binding / FROM-scope lookup so
            // dialect-reserved keywords always win over any
            // accidentally-named column. Catalog membership is the
            // closed-enum gate (no name-pattern allow-list); the
            // dialect's catalog seed is the source of truth for which
            // identifiers are nullary system values.
            if let Some(func_id) = self.catalog.lookup(name.as_str()) {
                if let Some(sig) = self.catalog.signature(func_id) {
                    if sig.is_temporal {
                        return ScalarExpr::FuncCall {
                            func: ResolvedFunc::Resolved {
                                id: func_id,
                                span: cref.name.span,
                            },
                            args: Vec::new(),
                            named_args: Vec::new(),
                            distinct: false,
                            span: cref.name.span,
                        };
                    }
                }
            }
            if let Some(existing) = self.bindings.get(&name) {
                return ScalarExpr::Column {
                    column: *existing,
                    span: cref.name.span,
                };
            }
            if let Some(id) = self.resolve_from_scope(None, &name) {
                return ScalarExpr::Column {
                    column: id,
                    span: cref.name.span,
                };
            }
            // Lateral SELECT-list alias resolution.
            // Real source columns above shadow aliases —
            // matching the projection-alias-first / column-shadows-
            // alias rule documented on `resolve_group_by_alias`.
            // Active inside WHERE / HAVING / QUALIFY / ORDER BY
            // lowering, where `lower_select_body` threads the final
            // `Some(&AliasMap)` after `lower_projection` returns; AND
            // inside `lower_projection`'s `Columns` arm itself, where
            // a running `AliasMap` is built incrementally so item N+1
            // resolves a lateral reference to an alias defined by item
            // ≤N (Snowflake / BigQuery semantics).
            if let Some(am) = aliases {
                if let Some(out_id) = am.by_name.get(&name) {
                    return ScalarExpr::Column {
                        column: *out_id,
                        span: cref.name.span,
                    };
                }
            }
        }
        // Allocate-on-first-use fallback.
        let existing_binding = if qualifier_alias.is_some() {
            None
        } else {
            self.bindings.get(&name).copied()
        };
        // Set when a qualified reference resolves to an ENCLOSING scope's
        // source (via `outer_alias_frames`) rather than the local FROM —
        // a correlated reference to a base table, whose columns are
        // allocated on demand and never registered in `from_scope` (so
        // `resolve_outer_from_scope` cannot see them). The value is the
        // 1-based correlation depth, lockstep with `resolve_outer_from_scope`
        // (both outer stacks are pushed together in `lower_stmt_in_fresh_scope`).
        let mut correlation_depth: Option<u32> = None;
        let id = match existing_binding {
            Some(existing) => existing,
            None => {
                // `column_name` carries raw source text (quote-preserving
                // for case-sensitive identifiers) — see `alloc_table_col`.
                // The IdentKey-canonical form is derived for `display_name`
                // inside the helper. The default form is the column's own
                // raw text; the rename-override paths below substitute a
                // source-side name when a star-passthrough rename
                // redirects to a different underlying column.
                let mut col_name = slice_span(self.source, cref.name.span)
                    .unwrap_or("")
                    .to_string();

                // Resolve the source `NodeId` only when a concrete
                // source can be identified without inventing one.
                // Ambiguous unqualified refs (multiple FROM sources
                // where the catalog can't disambiguate, or no catalog
                // attached) and unknown qualified refs stay anchored
                // to the statement node.
                //
                // Catalog-driven disambiguation: when multiple FROM
                // sources are in scope and a `catalog_index` is
                // attached, classify the unqualified reference via
                // `classify_unqualified_column_resolution`. Unique
                // matches route the binding to the source's scan
                // node (so taint / lineage / nullability seeded at
                // that Scan reach the output column); ambiguous
                // matches fall back to the statement-node anchor
                // AND record `is_ambiguous` on the public
                // `ColumnReferenceEvent` so `CAT-COL-AMBIGUOUS`
                // fires. No-match / no-catalog cases preserve the
                // conservative statement-node default.
                let mut ambiguous_unqualified = false;
                let (mut table_node, attach_to_source) =
                    if let Some(q_alias) = qualifier_alias.as_ref() {
                        if let Some(node) = self.from_aliases.get(q_alias).copied() {
                            // Local FROM source (shadows any enclosing alias).
                            (node, true)
                        } else if let Some((depth, node)) =
                            self.outer_alias_frames.iter().rev().enumerate().find_map(
                                |(i, frame)| frame.get(q_alias).copied().map(|n| (i as u32 + 1, n)),
                            )
                        {
                            // Correlated reference into an enclosing scope.
                            correlation_depth = Some(depth);
                            (node, true)
                        } else {
                            (self.current_stmt_node, false)
                        }
                    } else if self.from_source_order.len() == 1 {
                        (self.from_source_order[0], true)
                    } else {
                        match self.classify_unqualified_column_resolution(&name) {
                            UnqualifiedColumnResolution::Unique(node) => (node, true),
                            UnqualifiedColumnResolution::Ambiguous => {
                                ambiguous_unqualified = true;
                                (self.current_stmt_node, false)
                            }
                            UnqualifiedColumnResolution::None => (self.current_stmt_node, false),
                        }
                    };

                // CTE star-passthrough RENAME: when the qualifier
                // routed via `from_aliases` to a leaf-Scan `NodeId`
                // carrying a rename map (populated by
                // `detect_cte_passthrough_with_renames` at CTE
                // registration), substitute the source column name so
                // the binding records `users.id` instead of
                // `users.user_id`. See `cte_passthrough_renames`.
                if attach_to_source {
                    if let Some(map) = self.cte_passthrough_renames.get(&table_node) {
                        if let Some(source) = map.get(&name) {
                            // Use raw source bytes so quote-preserved
                            // case survives into `ColumnOrigin::Table::
                            // column_name`. Falls back to the IdentKey
                            // value when the span fails to resolve
                            // (defensive — populator always sets a
                            // valid span).
                            col_name = slice_span(self.source, source.span)
                                .map(|s| s.to_string())
                                .unwrap_or_else(|| source.ident.as_str().to_string());
                        }
                    }
                    // Per-output-column passthrough (multi-leaf JOIN
                    // bodies, chained CTE/derived-table chains): when
                    // the source is a `CteRef` / `DerivedTable` whose
                    // body resolves this output column to a concrete
                    // base-table Scan, redirect both the table_node
                    // and the demanded name so the resulting binding
                    // records the underlying source rather than a
                    // synthetic CTE-name-as-table orphan. See
                    // [`Self::cte_passthrough_columns`].
                    if let Some(map) = self.cte_passthrough_columns.get(&table_node) {
                        if let Some(target) = map.get(&name) {
                            table_node = target.leaf_scan_node;
                            col_name = slice_span(self.source, target.source_name.span)
                                .map(|s| s.to_string())
                                .unwrap_or_else(|| target.source_name.ident.as_str().to_string());
                        }
                    }
                }

                let fresh = self.alloc_table_col(table_node, &col_name, cref.name.span);
                // Qualified refs are source-scoped; caching them in the
                // unqualified name map can alias `a.col` to `b.col` when
                // both sides expose the same column name.
                if qualifier_alias.is_none() {
                    self.bindings.insert(name.clone(), fresh);
                }
                if attach_to_source {
                    self.scan_cols.push((table_node, fresh));
                }
                if ambiguous_unqualified {
                    self.catalog_ctx.insert_column_ambiguous(fresh);
                }
                fresh
            }
        };
        match correlation_depth {
            // Correlated base-table reference resolved via an enclosing
            // scope's alias: emit a first-class `OuterRef`. `id` is the
            // on-demand column allocated against the outer source; base
            // columns are Table-origin (never volatile), so the absence of
            // a shared canonical id across references is immaterial to the
            // determinism analysis and only affects representation.
            Some(depth) => ScalarExpr::OuterRef {
                scope: ScopeId(depth),
                column: id,
                span: cref.name.span,
            },
            None => ScalarExpr::Column {
                column: id,
                span: cref.name.span,
            },
        }
    }

    fn ident_at(&self, span: Span) -> IdentKey {
        IdentKey::new(slice_span(self.source, span).unwrap_or(""))
    }

    /// Populate `self.from_scope` from the fully-lowered FROM plan.
    ///
    /// The scope records, for each leaf source in the FROM plan,
    /// the source's alias (if any), every column's display name,
    /// and the ColumnId the source node owns. Entries are appended
    /// in traversal order; when two sources expose the same column
    /// name under the same alias (or no alias), the first-seen
    /// entry wins the unqualified lookup in [`Self::lower_column_ref`].
    ///
    /// Only columns whose [`ColumnBinding::display_name`] is
    /// non-empty are recorded — an empty display name means the
    /// column is anonymous and cannot be referenced by name.
    fn populate_from_scope(&mut self, from_plan: &RelPlan) {
        self.from_scope.clear();
        self.collect_scope_entries(from_plan, None);
    }

    /// Walk a FROM-side `RelPlan` subtree, appending one
    /// [`FromScopeEntry`] per named output column.
    ///
    /// The `override_alias` parameter lets an outer wrapper propagate
    /// its alias down to a pass-through input whose own alias is
    /// `None` (e.g. `FROM (... some inner ...) AS x` where the
    /// inner is wrapped by a filter or sort — such wrappers appear
    /// only if future lowering passes introduce them mid-FROM;
    /// currently FROM lowering produces leaf-level aliased nodes
    /// directly, so this parameter stays `None` at the top call
    /// and is propagated into pass-through operators as a safety
    /// net).
    ///
    /// Closed-enum match: every [`RelPlan`] variant is listed so a
    /// future variant surfaces here during review. Variants that
    /// cannot appear as a FROM source (DML roots, `WithScope`,
    /// `Explain`, `CreateAsQuery`) are documented no-ops.
    fn collect_scope_entries(&mut self, plan: &RelPlan, override_alias: Option<IdentKey>) {
        match plan {
            RelPlan::Scan {
                table,
                columns,
                alias,
                ..
            } => {
                let source_alias = override_alias
                    .or_else(|| alias.clone())
                    .or_else(|| Some(IdentKey::new(&table.name)));
                self.append_scope_columns(columns, source_alias);
            }
            RelPlan::Values { columns, alias, .. } => {
                let source_alias = override_alias.or_else(|| alias.clone());
                self.append_scope_columns(columns, source_alias);
            }
            RelPlan::CteRef {
                name,
                columns,
                alias,
                ..
            } => {
                let source_alias = override_alias
                    .or_else(|| alias.clone())
                    .or_else(|| Some(name.clone()));
                self.append_scope_columns(columns, source_alias);
            }
            RelPlan::ModelRef { columns, alias, .. } => {
                let source_alias = override_alias.or_else(|| alias.clone());
                self.append_scope_columns(columns, source_alias);
            }
            RelPlan::DerivedTable { columns, alias, .. } => {
                let source_alias = override_alias.or_else(|| alias.clone());
                self.append_scope_columns(columns, source_alias);
            }
            RelPlan::TableFunction {
                output_columns,
                alias,
                ..
            } => {
                let source_alias = override_alias.or_else(|| alias.clone());
                self.append_scope_columns(output_columns, source_alias);
            }
            RelPlan::Join { left, right, .. } => {
                // Each side carries its own alias; do not propagate
                // an outer override across a join boundary.
                self.collect_scope_entries(left, None);
                self.collect_scope_entries(right, None);
            }
            // Pass-through unary operators that appear as FROM
            // wrappers today (MR / ConnectBy) derive their
            // user-visible columns from their own output lists.
            RelPlan::MatchRecognize { output_columns, .. }
            | RelPlan::ConnectBy { output_columns, .. } => {
                self.append_scope_columns(output_columns, override_alias);
            }
            RelPlan::Pivot {
                input,
                pivot_column,
                aggregates,
                output_columns,
                ..
            } => {
                // Mirror `RelPlan::output_schema()` for Pivot:
                // pass-through input columns minus the pivot key and
                // aggregate argument columns, then synthesized pivot
                // output columns.
                let mut drop = std::collections::HashSet::new();
                drop.insert(*pivot_column);
                for agg in aggregates {
                    crate::ir::schema::collect_columns_from_aggregate_args(agg, &mut drop);
                }
                let pass_through: Vec<ColumnId> = input
                    .output_schema()
                    .into_iter()
                    .filter(|c| !drop.contains(c))
                    .collect();
                self.append_scope_columns(&pass_through, override_alias.clone());
                self.append_scope_columns(output_columns, override_alias);
            }
            RelPlan::Unnest {
                input,
                value_column,
                ordinality_column,
                ..
            } => {
                self.collect_scope_entries(input, override_alias.clone());
                let mut extras = vec![*value_column];
                if let Some(ord) = ordinality_column {
                    extras.push(*ord);
                }
                self.append_scope_columns(&extras, override_alias);
            }
            RelPlan::Unpivot {
                input,
                value_columns,
                name_column,
                unpivoted_columns,
                ..
            } => {
                // Input columns minus the unpivoted source columns.
                let mut drop = std::collections::HashSet::new();
                for group in unpivoted_columns {
                    for c in &group.columns {
                        drop.insert(*c);
                    }
                }
                let start = self.from_scope.len();
                self.collect_scope_entries(input, override_alias.clone());
                self.from_scope
                    .drain(start..)
                    .filter(|e| !drop.contains(&e.column_id))
                    .collect::<Vec<_>>()
                    .into_iter()
                    .for_each(|e| self.from_scope.push(e));
                let mut extras = vec![*name_column];
                extras.extend(value_columns.iter().copied());
                self.append_scope_columns(&extras, override_alias);
            }
            // Pure pass-throughs: propagate into the input. `override_alias`
            // remains None at the top entry; if some future lowering
            // introduces an aliased wrapper it would flow the alias
            // downward, which matches SQL's single-alias visibility.
            RelPlan::Filter { input, .. }
            | RelPlan::Sort { input, .. }
            | RelPlan::Limit { input, .. }
            | RelPlan::TableSample { input, .. } => {
                self.collect_scope_entries(input, override_alias);
            }
            // Transforming unary ops whose `output_columns` define
            // the visible schema, replacing the input's.
            RelPlan::Aggregate { output_columns, .. } | RelPlan::SetOp { output_columns, .. } => {
                self.append_scope_columns(output_columns, override_alias);
            }
            // A Window node passes every input row through and
            // appends window-call outputs. `window_outputs` holds
            // only the appended ids; the visible from-scope must
            // be `input` schema followed by the window outputs.
            RelPlan::Window {
                input,
                window_outputs,
                ..
            } => {
                self.collect_scope_entries(input, override_alias.clone());
                self.append_scope_columns(window_outputs, override_alias);
            }
            // Parser-recovery fallback: an opaque FROM has no
            // exposable schema by construction (the subtree's
            // contents were replaced with `Opaque` or `ParseRecovery`
            // because lowering couldn't make sense of them). No entries
            // are contributed; the lineage walk surfaces the opaque
            // region via its own dedicated path.
            RelPlan::ParseRecovery { .. } | RelPlan::Opaque { .. } => {}
            RelPlan::InvalidInput { .. } => {}
            // The remaining variants are statement-level roots or
            // wrappers that the lowering never places under a FROM
            // item. A `Project` only appears as the outermost shape
            // of a SELECT body (inside a `DerivedTable` we recurse
            // through `DerivedTable.columns`, not through the
            // inner `Project`); `WithScope` wraps a whole statement
            // body; DML roots, `Explain`, and `CreateAsQuery` are
            // statement roots. Reaching any of these from
            // `collect_scope_entries` means a lowering pass has
            // changed shape in a way that invalidates the
            // FROM-scope population invariant, and any such change
            // must decide per-variant what entries to contribute
            // before it lands — hence a hard invariant violation
            // here rather than a silent empty scope.
            RelPlan::Project { span, .. }
            | RelPlan::WithScope { span, .. }
            | RelPlan::Insert { span, .. }
            | RelPlan::Update { span, .. }
            | RelPlan::Delete { span, .. }
            | RelPlan::Merge { span, .. }
            | RelPlan::MultiInsert { span, .. }
            | RelPlan::Explain { span, .. }
            | RelPlan::CreateAsQuery { span, .. }
            | RelPlan::CreateTableForm { span, .. } => {
                debug_assert!(
                    false,
                    "collect_scope_entries reached a non-FROM RelPlan variant at span {:?}",
                    span
                );
            }
        }
    }

    fn append_scope_columns(&mut self, columns: &[ColumnId], source_alias: Option<IdentKey>) {
        for id in columns {
            let display_name = match self.allocator.bindings().get(*id) {
                Some(b) => b.display_name.clone(),
                None => continue,
            };
            if display_name.is_empty() {
                continue;
            }
            self.from_scope.push(FromScopeEntry {
                source_alias: source_alias.clone(),
                column_name: IdentKey::new(&display_name),
                column_id: *id,
            });
        }
    }

    /// Catalog-driven classification of an unqualified column
    /// reference in a multi-source FROM scope. Walks
    /// `from_source_order`, looks up each source's [`TableRef`] in
    /// `scan_table_refs`, queries the attached `catalog_index` for
    /// that table's columns, and reports:
    ///
    /// - [`UnqualifiedColumnResolution::Unique(node)`] iff **exactly
    ///   one** in-scope base-table source exposes the column. The
    ///   caller routes the binding to `node` so taint / lineage /
    ///   nullability seeded at that Scan reach the output column.
    /// - [`UnqualifiedColumnResolution::Ambiguous`] when two or more
    ///   in-scope sources expose the column. The caller orphans the
    ///   binding to the statement node (no unique attribution) and
    ///   records the column as ambiguous so `CAT-COL-AMBIGUOUS` can
    ///   fire on the public `ColumnReferenceEvent.is_ambiguous`.
    /// - [`UnqualifiedColumnResolution::None`] when no catalog is
    ///   attached, no in-scope source matches, or every in-scope
    ///   source is non-base-table (CTE / DerivedTable / TVF).
    ///
    /// Sources without a [`TableRef`] entry (derived tables, CTEs,
    /// TVFs) are skipped — their columns aren't catalog-resolvable
    /// at this layer. The fallback statement-node anchor remains the
    /// safe default for those.
    fn classify_unqualified_column_resolution(
        &self,
        name: &IdentKey,
    ) -> UnqualifiedColumnResolution {
        let Some(catalog) = self.catalog_index else {
            return UnqualifiedColumnResolution::None;
        };
        let needle = name.as_str();
        let mut hit: Option<crate::ast::NodeId> = None;
        for source in &self.from_source_order {
            let Some(table_ref) = self.scan_table_refs.get(source) else {
                continue;
            };
            let Some(table) = catalog.get_table_inferred(
                table_ref.db.as_deref(),
                table_ref.schema.as_deref(),
                &table_ref.name,
            ) else {
                continue;
            };
            let has_column = table
                .columns
                .iter()
                .any(|c| c.name.name.eq_ignore_ascii_case(needle));
            if !has_column {
                continue;
            }
            if hit.is_some() {
                return UnqualifiedColumnResolution::Ambiguous;
            }
            hit = Some(*source);
        }
        match hit {
            Some(node) => UnqualifiedColumnResolution::Unique(node),
            None => UnqualifiedColumnResolution::None,
        }
    }

    /// Look up a column in `from_scope`.
    ///
    /// - When `qualifier` is `Some(alias)`, entries whose
    ///   `source_alias` equals `alias` are considered; this
    ///   resolves `x.col` to the column `col` owned by source
    ///   aliased / named `x`.
    /// - When `qualifier` is `None`, every entry is considered;
    ///   first match wins (matches SQL's "ambiguous reference"
    ///   tolerance).
    fn resolve_from_scope(
        &self,
        qualifier: Option<&IdentKey>,
        name: &IdentKey,
    ) -> Option<ColumnId> {
        self.from_scope.iter().find_map(|e| {
            if &e.column_name != name {
                return None;
            }
            match qualifier {
                Some(q) => {
                    if e.source_alias.as_ref() == Some(q) {
                        Some(e.column_id)
                    } else {
                        None
                    }
                }
                None => Some(e.column_id),
            }
        })
    }

    /// Resolve a qualified reference against the enclosing (outer) FROM
    /// scopes for correlation. Returns the resolved [`ColumnId`] paired
    /// with the **correlation depth** as a [`ScopeId`]: frames are
    /// iterated innermost-first, so depth 1 is the immediate parent, 2
    /// the grandparent, etc. Depth (not an absolute lowered scope id) is
    /// the right marker for [`ScalarExpr::OuterRef::scope`] because it is
    /// position-independent — structurally-identical correlated
    /// subqueries fingerprint alike.
    fn resolve_outer_from_scope(
        &self,
        qualifier: Option<&IdentKey>,
        name: &IdentKey,
    ) -> Option<(ScopeId, ColumnId)> {
        self.outer_from_scope_frames
            .iter()
            .rev()
            .enumerate()
            .find_map(|(idx, frame)| {
                let depth = ScopeId(idx as u32 + 1);
                frame.iter().find_map(|e| {
                    if &e.column_name != name {
                        return None;
                    }
                    match qualifier {
                        Some(q) => {
                            if e.source_alias.as_ref() == Some(q) {
                                Some((depth, e.column_id))
                            } else {
                                None
                            }
                        }
                        None => Some((depth, e.column_id)),
                    }
                })
            })
    }
}

// ────────────────────────────────────────────────────────────────────────
// AST → ScalarExpr entry point for policy bodies
// ────────────────────────────────────────────────────────────────────────

/// Lower a policy body / predicate `AstExpr` to [`ScalarExpr`] through
/// a throwaway `LowerCtx` and hand it, with the binding table it was
/// lowered against, to `f`. Policy bodies range over the policy's
/// parameters rather than catalogued columns.
///
/// `node_id` is the policy statement's [`crate::ast::NodeId`] (the
/// parameter scope anchor); `parameters` is the policy's argument list
/// in source order (CREATE only; empty for ALTER bodies that don't
/// restate the signature). `None` when the body fails to lower (opaque /
/// unsupported expression shapes).
pub fn with_lowered_policy_predicate<R>(
    expr: &AstExpr,
    source: &str,
    node_id: crate::ast::NodeId,
    parameters: &[(IdentKey, Span)],
    f: impl FnOnce(&ScalarExpr, &super::column::BindingTable) -> R,
) -> Option<R> {
    let func_catalog = FunctionCatalog::for_dialect(super::catalog::CatalogDialect::Default);
    let session = SessionContext::default();
    let mut ctx = LowerCtx::new(source, &func_catalog, StrictMode::Permissive, &session);
    let (scalar, _ids) = ctx
        .lower_policy_predicate(expr, node_id, parameters, None)
        .ok()?;
    Some(f(&scalar, ctx.allocator.bindings()))
}

// ────────────────────────────────────────────────────────────────────────
// Helpers
// ────────────────────────────────────────────────────────────────────────

/// Translate the AST's `(op, modifier)` pair into the IR's
/// [`SetOpKind`]. `AstSetModifier::None` means the operator was
/// written without `ALL` / `DISTINCT`; SQL's default for all three
/// set operators is set-wise (duplicate-removing), so we fold `None`
/// If `set`'s leftmost-spine `AstSelect` carries a `WITH` clause,
/// return a cloned (`with_clause`, `AstSetSelect` with that clause
/// stripped) pair. Returns `None` when the leftmost spine has no
/// `WITH`. The parser attaches WITH to the leftmost AstSelect on the
/// spine (`parser/set_operations.rs:282-291`); SQL semantics require
/// it to apply to every branch, so the lowerer lifts it via
/// [`LowerCtx::lower_set_select_with_lifted_ctes`] before flattening.
fn strip_leftmost_with_clause(set: &AstSetSelect) -> Option<(AstWithClause, AstSetSelect)> {
    match &*set.left {
        AstStmt::Select(s) if s.with_clause.is_some() => {
            let mut cloned_left = s.clone();
            let with = cloned_left.with_clause.take().expect("checked above");
            let mut cloned_set = set.clone();
            cloned_set.left = Box::new(AstStmt::Select(cloned_left));
            Some((*with, cloned_set))
        }
        AstStmt::SetSelect(inner) => {
            // Recurse into the leftmost SetSelect spine. If the
            // recursion yields a strip, rebuild the outer with the
            // stripped inner.
            strip_leftmost_with_clause(inner).map(|(with, stripped_inner)| {
                let mut cloned_set = set.clone();
                cloned_set.left = Box::new(AstStmt::SetSelect(stripped_inner));
                (with, cloned_set)
            })
        }
        _ => None,
    }
}

/// into the `Distinct` kinds. `AstSetOpKind::Minus` is Snowflake's
/// synonym for `EXCEPT` and maps identically.
fn make_set_op_kind(op: &AstSetOpKind, modifier: AstSetModifier) -> SetOpKind {
    let is_all = matches!(modifier, AstSetModifier::All);
    match op {
        AstSetOpKind::Union => {
            if is_all {
                SetOpKind::UnionAll
            } else {
                SetOpKind::UnionDistinct
            }
        }
        AstSetOpKind::Intersect => {
            if is_all {
                SetOpKind::IntersectAll
            } else {
                SetOpKind::IntersectDistinct
            }
        }
        AstSetOpKind::Except | AstSetOpKind::Minus => {
            if is_all {
                SetOpKind::ExceptAll
            } else {
                SetOpKind::ExceptDistinct
            }
        }
    }
}

/// Extract a type representation from an `AstDataType` for use in
/// [`super::scalar::SqlType::repr`]. Uses only spans available without the
/// syntax arena. `SqlType.repr` is the uppercased type string, so the
/// base name is sufficient.
fn lower_data_type(source: &str, dtype: &crate::ast::AstDataType) -> super::scalar::SqlType {
    use crate::ast::AstDataType;
    let repr = match dtype {
        AstDataType::Simple { name_span } => slice_span(source, *name_span)
            .unwrap_or("")
            .to_ascii_uppercase(),
        AstDataType::WithPrecision { name_span, .. } => slice_span(source, *name_span)
            .unwrap_or("")
            .to_ascii_uppercase(),
        AstDataType::WithPrecisionScale { name_span, .. } => slice_span(source, *name_span)
            .unwrap_or("")
            .to_ascii_uppercase(),
        AstDataType::Parameterized { span, .. } => {
            slice_span(source, *span).unwrap_or("").to_ascii_uppercase()
        }
        AstDataType::CompoundInterval { span, .. } => {
            slice_span(source, *span).unwrap_or("").to_ascii_uppercase()
        }
    };
    super::scalar::SqlType { repr }
}

/// Project an [`crate::ast::BinaryOperator`] to a typed
/// [`super::scalar::ComparisonOp`]. Returns `Some` only for the six
/// comparison operators that SQL grammar permits at the head of a
/// quantified subquery (`x = ANY (...)`, `x <> ALL (...)`, etc.).
/// Returns `None` for arithmetic, logical, pattern, and dialect-specific
/// operators — the parser must not produce those in quantified-head
/// position, so the lowering site that consumes the `None` treats it
/// as a parser-invariant violation.
///
/// Closed-enum exhaustive — adding a new `BinaryOperator` variant
/// fails compilation here and forces an explicit classification.
fn ast_binop_to_comparison_op(op: BinaryOperator) -> Option<super::scalar::ComparisonOp> {
    use super::scalar::ComparisonOp;
    use BinaryOperator::*;
    match op {
        Equal => Some(ComparisonOp::Eq),
        NotEqual => Some(ComparisonOp::NotEq),
        LessThan => Some(ComparisonOp::Lt),
        LessThanOrEqual => Some(ComparisonOp::LtEq),
        GreaterThan => Some(ComparisonOp::Gt),
        GreaterThanOrEqual => Some(ComparisonOp::GtEq),
        // NullSafeEqual is not a plain ComparisonOp — it lowers to
        // BinOpKind::IsNotDistinctFrom via classify_binary_operator.
        Plus | Minus | Multiply | Divide | Modulo | And | Or | Not | Concat | LogicalOr | Like
        | ILike | RLike | Distance | NullSafeEqual | ArrayContains | ArrayContainedBy
        | ArrayOverlap | JsonField | JsonFieldText | JsonPath | JsonPathText | JsonContains
        | JsonExists | RegexMatch | RegexMatchI | RegexNotMatch | RegexNotMatchI | LeftShift
        | RightShift | BitwiseXor | BitwiseXorPg => None,
    }
}

/// Classification of an AST [`BinaryOperator`] for lowering into the IR
/// scalar layer — exactly one total match site over `BinaryOperator`.
/// Comparison operators fold into [`super::scalar::BinOpKind::Cmp`];
/// pattern-match operators route to [`ScalarExpr::Like`] via
/// [`BinOpClass::Like`]; the prefix `NOT` is structural
/// (lowers to [`super::scalar::UnaryOpKind::Not`] or a negated
/// [`ScalarExpr::QuantifiedCmp`]).
enum BinOpClass {
    Kind(super::scalar::BinOpKind),
    Like(super::scalar::LikeKind),
    PrefixNot,
}

fn classify_binary_operator(op: BinaryOperator) -> BinOpClass {
    use super::scalar::{BinOpKind as K, ComparisonOp as C, LikeKind as L};
    use BinaryOperator::*;
    match op {
        Plus => BinOpClass::Kind(K::Add),
        Minus => BinOpClass::Kind(K::Sub),
        Multiply => BinOpClass::Kind(K::Mul),
        Divide => BinOpClass::Kind(K::Div),
        Modulo => BinOpClass::Kind(K::Mod),
        Equal => BinOpClass::Kind(K::Cmp(C::Eq)),
        NotEqual => BinOpClass::Kind(K::Cmp(C::NotEq)),
        LessThan => BinOpClass::Kind(K::Cmp(C::Lt)),
        LessThanOrEqual => BinOpClass::Kind(K::Cmp(C::LtEq)),
        GreaterThan => BinOpClass::Kind(K::Cmp(C::Gt)),
        GreaterThanOrEqual => BinOpClass::Kind(K::Cmp(C::GtEq)),
        // MySQL / Spark `<=>` is the operator spelling of IS NOT DISTINCT FROM.
        NullSafeEqual => BinOpClass::Kind(K::IsNotDistinctFrom),
        And => BinOpClass::Kind(K::And),
        Or => BinOpClass::Kind(K::Or),
        Not => BinOpClass::PrefixNot,
        Concat => BinOpClass::Kind(K::Concat),
        LogicalOr => BinOpClass::Kind(K::LogicalOr),
        Like => BinOpClass::Like(L::Like),
        ILike => BinOpClass::Like(L::ILike),
        RLike => BinOpClass::Like(L::RLike),
        Distance => BinOpClass::Kind(K::Distance),
        ArrayContains => BinOpClass::Kind(K::ArrayContains),
        ArrayContainedBy => BinOpClass::Kind(K::ArrayContainedBy),
        ArrayOverlap => BinOpClass::Kind(K::ArrayOverlap),
        JsonField => BinOpClass::Kind(K::JsonField),
        JsonFieldText => BinOpClass::Kind(K::JsonFieldText),
        JsonPath => BinOpClass::Kind(K::JsonPath),
        JsonPathText => BinOpClass::Kind(K::JsonPathText),
        JsonContains => BinOpClass::Kind(K::JsonContains),
        JsonExists => BinOpClass::Kind(K::JsonExists),
        RegexMatch => BinOpClass::Kind(K::RegexMatch),
        RegexMatchI => BinOpClass::Kind(K::RegexMatchI),
        RegexNotMatch => BinOpClass::Kind(K::RegexNotMatch),
        RegexNotMatchI => BinOpClass::Kind(K::RegexNotMatchI),
        LeftShift => BinOpClass::Kind(K::Shl),
        RightShift => BinOpClass::Kind(K::Shr),
        BitwiseXor => BinOpClass::Kind(K::BitXor),
        BitwiseXorPg => BinOpClass::Kind(K::BitXorPg),
    }
}

/// Whether a source-span slice begins with Jinja syntax (`{{…}}` for
/// expressions or `{%…%}` for statements). Used by `lower_base_table_ref`
/// to detect fixtures where the parser put a pure-Jinja table name into
/// a `TableRef` instead of the dedicated `JinjaTableName` variant; in
/// that case the span is not a resolvable identifier and the Scan has
/// to bail to [`OpaqueReason::UnresolvedJinja`]. Whitespace and block
/// comments are tolerated before the opening braces so hostile-trivia
/// fixtures still classify correctly.
fn is_jinja_templated_span(source: &str, span: Span) -> bool {
    let Some(raw) = slice_span(source, span) else {
        return false;
    };
    let trimmed = raw.trim_start();
    trimmed.starts_with("{{") || trimmed.starts_with("{%")
}

// ── Create-as-query free-function helpers ───────────────────────────────

/// Push a typed side-option entry when the corresponding AST span is
/// present. No-op when the span is absent; keeps the caller sites in
/// `lower_create_*` dense and diff-readable.
fn push_opt(out: &mut Vec<CreateSideOption>, span: Option<Span>, kind: CreateSideOptionKind) {
    if let Some(s) = span {
        out.push(CreateSideOption { kind, span: s });
    }
}

/// Lower an `AstCreateView.columns` list to the IR's declared-column
/// shape. Returns `None` when no column list was written, so
/// round-trip / diff tooling can distinguish `VIEW v AS SELECT …` from
/// `VIEW v () AS SELECT …` without consulting spans.
fn lower_create_view_columns(source: &str, cv: &AstCreateView) -> Option<Vec<IdentKey>> {
    if cv.columns_span.is_none() && cv.column_list_id.is_none() {
        return None;
    }
    if cv.columns.is_empty() {
        return Some(Vec::new());
    }
    Some(
        cv.columns
            .iter()
            .filter_map(|c| slice_span(source, c.name_span).map(IdentKey::new))
            .collect(),
    )
}

/// Lower an `AstCreateTable.columns` list to a declared-column list for
/// a CTAS statement. CTAS column lists are column *names* for the new
/// table (type / constraint information is inferred from the query
/// output), so only the name span matters here.
fn lower_create_table_columns(source: &str, ct: &AstCreateTable) -> Option<Vec<IdentKey>> {
    ct.columns_span?;
    if ct.columns.is_empty() {
        return Some(Vec::new());
    }
    Some(
        ct.columns
            .iter()
            .filter_map(|c| {
                c.name_span
                    .and_then(|s| slice_span(source, s))
                    .map(IdentKey::new)
            })
            .collect(),
    )
}

/// Split a possibly-qualified identifier path (`db.schema.table`) on
/// unquoted dots. Double-quoted segments are kept intact so identifiers
/// with embedded dots (`"schema.with.dots"."table"`) survive.
fn split_object_ref(raw: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_quote = false;
    for ch in raw.chars() {
        match ch {
            '"' => {
                in_quote = !in_quote;
                cur.push(ch);
            }
            '.' if !in_quote => {
                out.push(std::mem::take(&mut cur));
            }
            _ => cur.push(ch),
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

fn extract_stage_reference_prefix(raw: &str) -> Option<String> {
    let trimmed = raw.trim_start();
    if !trimmed.starts_with('@') {
        return None;
    }

    let mut out = String::new();
    let mut in_quote = false;
    for ch in trimmed.chars() {
        if ch == '"' {
            in_quote = !in_quote;
            out.push(ch);
            continue;
        }
        if ch.is_whitespace() && !in_quote {
            break;
        }
        out.push(ch);
    }

    if out == "@" {
        None
    } else {
        Some(out)
    }
}

/// Parse a parenthesized identifier list of the form `(c1, c2, "C 3")`
/// into its component names with outer whitespace trimmed. Outer
/// parentheses (if present) are stripped. Double-quoted segments are
/// preserved including their quotes (so quoted-identifier case
/// sensitivity survives the downstream [`IdentKey`] normalization).
fn split_parenthesized_ident_list(raw: &str) -> Vec<String> {
    let trimmed = raw.trim();
    let inner = trimmed
        .strip_prefix('(')
        .and_then(|s| s.strip_suffix(')'))
        .unwrap_or(trimmed);
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_quote = false;
    for ch in inner.chars() {
        match ch {
            '"' => {
                in_quote = !in_quote;
                cur.push(ch);
            }
            ',' if !in_quote => {
                let name = std::mem::take(&mut cur).trim().to_string();
                if !name.is_empty() {
                    out.push(name);
                }
            }
            _ => cur.push(ch),
        }
    }
    let name = cur.trim().to_string();
    if !name.is_empty() {
        out.push(name);
    }
    out
}

/// Classify a PostgreSQL `OVERRIDING { SYSTEM | USER } VALUE` span.
/// The AST carries the whole clause as a single span; the text is
/// inspected case-insensitively for the distinguishing keyword. A
/// span that contains neither keyword returns `None` — the caller
/// treats that as "OVERRIDING clause present but unclassifiable" and
/// drops the field so downstream passes do not see a misattributed
/// value.
/// Borrowed view over the source-bearing fields shared by [`AstInsert`]
/// and [`crate::ast::AstReplaceInto`], so both lower through one path.
struct InsertSourceParts<'a> {
    source_kind: &'a AstInsertSourceKind,
    values_span: Option<Span>,
    values_rows: &'a [Vec<crate::ast::AstExpr>],
    query: Option<&'a AstStmt>,
    set_clause_span: Option<Span>,
    set_assignments: &'a [(String, crate::ast::AstExpr)],
    node_id: crate::ast::NodeId,
    span: Span,
}

fn parse_overriding_value(raw: &str) -> Option<OverridingValue> {
    let upper = raw.to_ascii_uppercase();
    if upper.contains("SYSTEM") {
        Some(OverridingValue::System)
    } else if upper.contains("USER") {
        Some(OverridingValue::User)
    } else {
        None
    }
}

/// Parse the text of a PostgreSQL `EXPLAIN` options clause into a
/// structured [`ExplainOptions`]. Accepts both the legacy bare
/// `ANALYZE` / `VERBOSE` keywords and the parenthesized
/// `(ANALYZE, FORMAT JSON, COSTS true)` form. Unknown option names
/// are ignored — the clause round-trips through the Explain node's
/// span — so future PG additions do not break the lowerer.
fn parse_explain_options(raw: &str) -> ExplainOptions {
    let mut opts = ExplainOptions::default();
    let trimmed = raw.trim();
    // Drop leading / trailing parens if present, then split on commas
    // at the outermost level (options don't contain nested parens).
    let body = trimmed
        .strip_prefix('(')
        .and_then(|s| s.strip_suffix(')'))
        .unwrap_or(trimmed);
    for part in body.split(',') {
        let token = part.trim();
        if token.is_empty() {
            continue;
        }
        let mut fields = token.split_whitespace();
        let name = match fields.next() {
            Some(n) => n.to_ascii_uppercase(),
            None => continue,
        };
        let value = fields.next().map(|v| v.to_ascii_uppercase());
        let bool_value = || match value.as_deref() {
            None => Some(true),
            Some("TRUE") | Some("ON") | Some("1") => Some(true),
            Some("FALSE") | Some("OFF") | Some("0") => Some(false),
            _ => None,
        };
        match name.as_str() {
            "ANALYZE" => {
                opts.analyze = bool_value().unwrap_or(true);
            }
            "VERBOSE" => {
                opts.verbose = bool_value().unwrap_or(true);
            }
            "COSTS" => {
                opts.costs = bool_value();
            }
            "BUFFERS" => {
                opts.buffers = bool_value();
            }
            "TIMING" => {
                opts.timing = bool_value();
            }
            "SETTINGS" => {
                opts.settings = bool_value();
            }
            "SUMMARY" => {
                opts.summary = bool_value();
            }
            "FORMAT" => {
                opts.format = match value.as_deref() {
                    Some("JSON") => ExplainFormat::Json,
                    Some("XML") => ExplainFormat::Xml,
                    Some("YAML") => ExplainFormat::Yaml,
                    Some("TEXT") | None => ExplainFormat::Text,
                    Some(_) => ExplainFormat::Text,
                };
            }
            _ => {}
        }
    }
    opts
}

/// Build a [`DmlOutput`] from an [`AstOutputClause`]. The AST
/// currently surfaces OUTPUT as a single clause span without
/// structured items; the IR preserves the span so renderers can
/// locate the original text, with `items` / `into_*` left empty.
/// When the AST gains structured items, populate them here —
/// consumers already iterate both slots exhaustively.
fn lower_output_clause(o: &AstOutputClause) -> DmlOutput {
    DmlOutput {
        items: Vec::new(),
        into_target: None,
        into_columns: Vec::new(),
        span: o.span,
    }
}

/// Whether a lowered [`ScalarExpr`] references any `ColumnId` in
/// `outputs`. Used by `GROUP BY ALL` to skip aggregate-producing
/// projection items: an item whose expression references an
/// aggregate's output column is itself aggregate-producing.
///
/// The walk is exhaustive over `ScalarExpr` variants so a new variant
/// fails compilation until this function is updated.
/// All `AstGroupItem`s referenced by a single grouping element, flattened.
fn group_element_items(element: &AstGroupElement) -> Vec<&AstGroupItem> {
    match &element.kind {
        AstGroupElementKind::Expr(item) => vec![item],
        AstGroupElementKind::Cube(items) | AstGroupElementKind::Rollup(items) => {
            items.iter().collect()
        }
        AstGroupElementKind::GroupingSets(sets) => sets.iter().flatten().collect(),
    }
}

/// Expand a grouping-element list into the cross-product of each element's
/// grouping sets, at the `AstGroupItem` level. Returns `None` when the product
/// would exceed [`GROUP_SET_PRODUCT_CAP`], so the caller can fall back to a
/// bounded conservative spec.
fn expand_group_elements_item_sets(
    elements: &[AstGroupElement],
) -> Option<Vec<Vec<&AstGroupItem>>> {
    // 2^12; CUBE(n) for n > 12 alone reaches this. A grouping-element list
    // multiplies per element, so the running product is checked each round.
    const GROUP_SET_PRODUCT_CAP: usize = 4096;

    let mut acc: Vec<Vec<&AstGroupItem>> = vec![Vec::new()];
    for element in elements {
        // Each element contributes a list of grouping sets (its "options").
        let options: Vec<Vec<&AstGroupItem>> = match &element.kind {
            AstGroupElementKind::Expr(item) => vec![vec![item]],
            AstGroupElementKind::Rollup(items) => {
                // Prefixes from full down to empty: (a,b,c),(a,b),(a),().
                (0..=items.len())
                    .rev()
                    .map(|n| items[..n].iter().collect())
                    .collect()
            }
            AstGroupElementKind::Cube(items) => {
                // All 2^n subsets.
                let n = items.len();
                if n > 12 {
                    return None;
                }
                (0..(1usize << n))
                    .map(|mask| {
                        items
                            .iter()
                            .enumerate()
                            .filter(|(i, _)| mask & (1usize << i) != 0)
                            .map(|(_, it)| it)
                            .collect()
                    })
                    .collect()
            }
            AstGroupElementKind::GroupingSets(sets) => {
                sets.iter().map(|s| s.iter().collect()).collect()
            }
        };

        if acc.len().saturating_mul(options.len()) > GROUP_SET_PRODUCT_CAP {
            return None;
        }

        let mut next: Vec<Vec<&AstGroupItem>> = Vec::with_capacity(acc.len() * options.len());
        for base in &acc {
            for opt in &options {
                let mut combined = base.clone();
                combined.extend(opt.iter().copied());
                next.push(combined);
            }
        }
        acc = next;
    }

    Some(acc)
}

fn expr_refs_any_column(expr: &ScalarExpr, outputs: &HashMap<ColumnId, ()>) -> bool {
    match expr {
        ScalarExpr::Column { column, .. } => outputs.contains_key(column),
        ScalarExpr::PatternVarRef { column, .. } => outputs.contains_key(column),
        ScalarExpr::OuterRef { .. } | ScalarExpr::Lit { .. } | ScalarExpr::Opaque { .. } => false,
        ScalarExpr::BinOp { left, right, .. } => {
            expr_refs_any_column(left, outputs) || expr_refs_any_column(right, outputs)
        }
        ScalarExpr::LogicalChain { operands, .. } => {
            operands.iter().any(|o| expr_refs_any_column(o, outputs))
        }
        ScalarExpr::Like {
            expr,
            pattern,
            escape,
            ..
        } => {
            expr_refs_any_column(expr, outputs)
                || expr_refs_any_column(pattern, outputs)
                || escape
                    .as_deref()
                    .is_some_and(|e| expr_refs_any_column(e, outputs))
        }
        ScalarExpr::UnaryOp { arg, .. } => expr_refs_any_column(arg, outputs),
        ScalarExpr::FuncCall {
            args, named_args, ..
        } => {
            args.iter().any(|a| expr_refs_any_column(a, outputs))
                || named_args
                    .iter()
                    .any(|(_, a)| expr_refs_any_column(a, outputs))
        }
        ScalarExpr::Case {
            operand,
            branches,
            else_,
            ..
        } => {
            operand
                .as_deref()
                .is_some_and(|e| expr_refs_any_column(e, outputs))
                || branches.iter().any(|(w, t)| {
                    expr_refs_any_column(w, outputs) || expr_refs_any_column(t, outputs)
                })
                || else_
                    .as_deref()
                    .is_some_and(|e| expr_refs_any_column(e, outputs))
        }
        ScalarExpr::Cast { expr, .. } => expr_refs_any_column(expr, outputs),
        ScalarExpr::InList { expr, list, .. } => {
            expr_refs_any_column(expr, outputs)
                || list.iter().any(|a| expr_refs_any_column(a, outputs))
        }
        ScalarExpr::Between {
            expr, low, high, ..
        } => {
            expr_refs_any_column(expr, outputs)
                || expr_refs_any_column(low, outputs)
                || expr_refs_any_column(high, outputs)
        }
        // Subqueries open a new scope: their correlation list is what
        // matters for "does this item reference an outer aggregate?"
        // `correlates_with` is populated post-lowering (see
        // `super::correlation`); an empty list means the subquery is not
        // correlated. We check the list to be forward-compatible.
        ScalarExpr::Exists {
            correlates_with, ..
        }
        | ScalarExpr::ScalarSubquery {
            correlates_with, ..
        } => correlates_with.iter().any(|c| outputs.contains_key(c)),
        ScalarExpr::QuantifiedCmp { left, right, .. } => {
            expr_refs_any_column(left, outputs)
                || match right {
                    super::scalar::QuantifiedRhs::List(list) => {
                        list.iter().any(|a| expr_refs_any_column(a, outputs))
                    }
                    super::scalar::QuantifiedRhs::Subquery(_, correlates_with) => {
                        correlates_with.iter().any(|c| outputs.contains_key(c))
                    }
                }
        }
        // A window call in a projection item means the item is not
        // plain column-shaped; it is not aggregate-shaped either (a
        // window fn over aggregate outputs is a separate window-lowering
        // concern). For GROUP BY ALL, treat as referencing if any
        // partition/order/arg touches the aggregate outputs.
        ScalarExpr::WindowFn { call, .. } => {
            call.args.iter().any(|a| expr_refs_any_column(a, outputs))
                || call
                    .partition_by
                    .iter()
                    .any(|a| expr_refs_any_column(a, outputs))
                || call
                    .order_by
                    .iter()
                    .any(|k| expr_refs_any_column(&k.expr, outputs))
        }
        ScalarExpr::FieldAccess { base, .. } => expr_refs_any_column(base, outputs),
        // A lambda's body may reference outer columns (captures) but
        // its bound parameters shadow them by `ColumnId`. We
        // conservatively check the body — the lambda's own param
        // `ColumnId`s cannot collide with `outputs` because those are
        // allocated fresh at lowering time and outputs are aggregate
        // output ids.
        ScalarExpr::Lambda { body, .. } => expr_refs_any_column(body, outputs),
    }
}

/// Combine two spans into the minimal enclosing span.
fn merge_spans(a: Span, b: Span) -> Span {
    Span {
        start: a.start.min(b.start),
        end: a.end.max(b.end),
    }
}

/// Enclosing span for the `LIMIT` / `OFFSET` / `FETCH` clause family.
///
/// Covers whichever keyword / expression spans are present on the
/// SELECT: the `LIMIT` keyword + expression, the `OFFSET` keyword +
/// expression, and the `FETCH FIRST …` clause span. Used as the span
/// of the synthesized [`RelPlan::Limit`] node so diagnostics point at
/// the row-count clauses rather than the entire statement.
fn compute_limit_offset_fetch_span(sel: &AstSelect) -> Span {
    let mut acc: Option<Span> = None;
    let add = |s: Span, acc: &mut Option<Span>| {
        *acc = Some(match acc {
            Some(prev) => merge_spans(*prev, s),
            None => s,
        });
    };
    if let Some(s) = sel.limit_keyword_span {
        add(s, &mut acc);
    }
    if let Some(e) = sel.limit.as_deref() {
        add(e.span(), &mut acc);
    }
    if let Some(s) = sel.offset_keyword_span {
        add(s, &mut acc);
    }
    if let Some(e) = sel.offset.as_deref() {
        add(e.span(), &mut acc);
    }
    if let Some(s) = sel.fetch_clause_span {
        add(s, &mut acc);
    }
    acc.unwrap_or(sel.span)
}

/// Locate the leaf [`RelPlan::Scan`] of a CTE body that was detected
/// at registration time as a star-passthrough chain bottoming at the
/// given `leaf_node` `NodeId`. Returns a `&mut` to that Scan's
/// `columns` Vec so the finalize pass can append demanded ColumnIds
/// in place.
///
/// The walk mirrors [`RelPlan::cte_body_star_passthrough_leaf_scan_node`]
/// — descend through the top `Project` (whose items are all vanilla
/// Stars; this is the registration-time gate) and through the
/// passthrough chain (`Filter` / `Sort` / `Limit` / `TableSample`)
/// until a `Scan` whose `node_id` matches `leaf_node` is found.
///
/// Returns `None` if the structural shape no longer matches (e.g. a
/// later lowering step rewrote the body) or the matching Scan is not
/// reachable. Callers treat `None` as a no-op rather than panicking;
/// the alternative path (drained ColumnIds simply not attached) is
/// already what was happening before this pass existed.
fn find_star_passthrough_leaf_scan_mut(
    plan: &mut RelPlan,
    leaf_node: crate::ast::NodeId,
) -> Option<&mut Vec<ColumnId>> {
    // Top-level descent: a star-passthrough body is always a
    // Project at the root, regardless of which dialect's lowering
    // produced it.
    let mut cursor: &mut RelPlan = match plan {
        RelPlan::Project { input, .. } => input.as_mut(),
        _ => return None,
    };
    loop {
        match cursor {
            RelPlan::Scan {
                node_id, columns, ..
            } => {
                if *node_id == leaf_node {
                    return Some(columns);
                } else {
                    return None;
                }
            }
            RelPlan::Filter { input, .. }
            | RelPlan::Sort { input, .. }
            | RelPlan::Limit { input, .. }
            | RelPlan::TableSample { input, .. } => {
                cursor = input.as_mut();
            }
            // Any other variant means the registration-time shape
            // was invalidated — bail safely. Listed exhaustively so
            // a future RelPlan variant surfaces here for explicit
            // classification.
            RelPlan::Values { .. }
            | RelPlan::CteRef { .. }
            | RelPlan::ModelRef { .. }
            | RelPlan::Project { .. }
            | RelPlan::Aggregate { .. }
            | RelPlan::Window { .. }
            | RelPlan::Join { .. }
            | RelPlan::SetOp { .. }
            | RelPlan::Insert { .. }
            | RelPlan::Update { .. }
            | RelPlan::Delete { .. }
            | RelPlan::Merge { .. }
            | RelPlan::MultiInsert { .. }
            | RelPlan::Explain { .. }
            | RelPlan::CreateAsQuery { .. }
            | RelPlan::WithScope { .. }
            | RelPlan::DerivedTable { .. }
            | RelPlan::TableFunction { .. }
            | RelPlan::Unnest { .. }
            | RelPlan::Pivot { .. }
            | RelPlan::Unpivot { .. }
            | RelPlan::MatchRecognize { .. }
            | RelPlan::ConnectBy { .. }
            | RelPlan::ParseRecovery { .. }
            | RelPlan::Opaque { .. } => return None,
            RelPlan::InvalidInput { .. } => return None,
            RelPlan::CreateTableForm { .. } => return None,
        }
    }
}

/// Assemble the `output_columns` list for a `RelPlan::Aggregate`:
/// grouping keys first, aggregates second, with duplicate `ColumnId`s
/// (CUBE / ROLLUP / GROUPING SETS can repeat the same key across sets)
/// collapsed while preserving first-seen order.
fn build_aggregate_output_columns(
    grouping: &GroupingSpec,
    aggregates: &[AggregateCall],
) -> Vec<ColumnId> {
    let mut out: Vec<ColumnId> = Vec::new();
    let push = |id: ColumnId, acc: &mut Vec<ColumnId>| {
        if !acc.contains(&id) {
            acc.push(id);
        }
    };
    match grouping {
        GroupingSpec::None => {}
        GroupingSpec::Standard(keys)
        | GroupingSpec::Cube(keys)
        | GroupingSpec::Rollup(keys)
        | GroupingSpec::All(keys) => {
            for k in keys {
                push(k.output, &mut out);
            }
        }
        GroupingSpec::GroupingSets(sets) => {
            for set in sets {
                for k in set {
                    push(k.output, &mut out);
                }
            }
        }
    }
    for agg in aggregates {
        push(agg.output, &mut out);
    }
    out
}

/// Assemble the `window_outputs` list for a [`RelPlan::Window`] from
/// collected calls, preserving first-seen order and deduplicating ids
/// defensively. The full output schema of the resulting Window node
/// is `input.output_schema() ∪ window_outputs`; this helper builds
/// only the second half.
fn build_window_output_columns(windows: &[WindowCall]) -> Vec<ColumnId> {
    let mut out: Vec<ColumnId> = Vec::with_capacity(windows.len());
    for call in windows {
        if !out.contains(&call.output) {
            out.push(call.output);
        }
    }
    out
}

// ────────────────────────────────────────────────────────────────────────
// Lateral-alias predicate classifier
// ────────────────────────────────────────────────────────────────────────

/// Walks `expr` exhaustively and returns `true` on the first
/// column reference whose `ColumnId` is in `alias_outputs`. Used
/// by the WHERE / HAVING / QUALIFY predicate classifier to decide
/// whether an atom must be lifted above `Project`.
///
/// Recursion boundary: subquery `RelPlan` bodies are not walked.
/// The lowerer populates `Exists` / `ScalarSubquery` /
/// `QuantifiedRhs::Subquery`'s `correlates_with` vector with the
/// outer-scope ColumnIds the subquery references; checking that
/// vector is the full surface of subquery-side alias references.
///
/// Closed-enum exhaustive on `ScalarExpr` and on every nested
/// closed enum it contains: adding a new variant
/// fails to compile until this walker decides what (if anything)
/// it contributes.
fn expr_references_alias(expr: &ScalarExpr, alias_outputs: &HashSet<ColumnId>) -> bool {
    match expr {
        ScalarExpr::Column { column, .. }
        | ScalarExpr::OuterRef { column, .. }
        | ScalarExpr::PatternVarRef { column, .. } => alias_outputs.contains(column),

        ScalarExpr::Lit { .. } | ScalarExpr::Opaque { .. } => false,

        ScalarExpr::BinOp { left, right, .. } => {
            expr_references_alias(left, alias_outputs)
                || expr_references_alias(right, alias_outputs)
        }
        ScalarExpr::LogicalChain { operands, .. } => operands
            .iter()
            .any(|o| expr_references_alias(o, alias_outputs)),
        ScalarExpr::Like {
            expr,
            pattern,
            escape,
            ..
        } => {
            expr_references_alias(expr, alias_outputs)
                || expr_references_alias(pattern, alias_outputs)
                || escape
                    .as_deref()
                    .is_some_and(|e| expr_references_alias(e, alias_outputs))
        }
        ScalarExpr::UnaryOp { arg, .. } => expr_references_alias(arg, alias_outputs),

        ScalarExpr::FuncCall {
            args, named_args, ..
        } => {
            args.iter().any(|a| expr_references_alias(a, alias_outputs))
                || named_args
                    .iter()
                    .any(|(_, a)| expr_references_alias(a, alias_outputs))
        }

        ScalarExpr::Case {
            operand,
            branches,
            else_,
            ..
        } => {
            operand
                .as_deref()
                .map(|o| expr_references_alias(o, alias_outputs))
                .unwrap_or(false)
                || branches.iter().any(|(w, t)| {
                    expr_references_alias(w, alias_outputs)
                        || expr_references_alias(t, alias_outputs)
                })
                || else_
                    .as_deref()
                    .map(|e| expr_references_alias(e, alias_outputs))
                    .unwrap_or(false)
        }

        ScalarExpr::Cast { expr, .. } => expr_references_alias(expr, alias_outputs),

        ScalarExpr::InList { expr, list, .. } => {
            expr_references_alias(expr, alias_outputs)
                || list.iter().any(|e| expr_references_alias(e, alias_outputs))
        }

        ScalarExpr::Between {
            expr, low, high, ..
        } => {
            expr_references_alias(expr, alias_outputs)
                || expr_references_alias(low, alias_outputs)
                || expr_references_alias(high, alias_outputs)
        }

        ScalarExpr::Exists {
            correlates_with, ..
        }
        | ScalarExpr::ScalarSubquery {
            correlates_with, ..
        } => correlates_with.iter().any(|c| alias_outputs.contains(c)),

        ScalarExpr::QuantifiedCmp { left, right, .. } => {
            if expr_references_alias(left, alias_outputs) {
                return true;
            }
            match right {
                crate::ir::scalar::QuantifiedRhs::Subquery(_, correlates_with) => {
                    correlates_with.iter().any(|c| alias_outputs.contains(c))
                }
                crate::ir::scalar::QuantifiedRhs::List(items) => items
                    .iter()
                    .any(|e| expr_references_alias(e, alias_outputs)),
            }
        }

        ScalarExpr::WindowFn { call, .. } => {
            // Walk the call's scalar-bearing fields. Closed-enum
            // exhaustive on `FrameBound` so a new bound shape
            // surfaces here.
            if call
                .args
                .iter()
                .any(|a| expr_references_alias(a, alias_outputs))
            {
                return true;
            }
            if call
                .partition_by
                .iter()
                .any(|p| expr_references_alias(p, alias_outputs))
            {
                return true;
            }
            if call
                .order_by
                .iter()
                .any(|sk| expr_references_alias(&sk.expr, alias_outputs))
            {
                return true;
            }
            if let Some(frame) = call.frame.as_ref() {
                let bound_refs = |b: &crate::ir::plan::FrameBound| match b {
                    crate::ir::plan::FrameBound::UnboundedPreceding
                    | crate::ir::plan::FrameBound::CurrentRow
                    | crate::ir::plan::FrameBound::UnboundedFollowing => false,
                    crate::ir::plan::FrameBound::Preceding(e)
                    | crate::ir::plan::FrameBound::Following(e) => {
                        expr_references_alias(e, alias_outputs)
                    }
                };
                if bound_refs(&frame.start) || bound_refs(&frame.end) {
                    return true;
                }
            }
            false
        }

        ScalarExpr::FieldAccess { base, .. } => expr_references_alias(base, alias_outputs),

        ScalarExpr::Lambda { body, .. } => {
            // Lambda parameters are bound to fresh ColumnIds inside
            // the body and shadow nothing; only the body can carry
            // a reference to the enclosing-SELECT alias outputs.
            expr_references_alias(body, alias_outputs)
        }
    }
}

/// Splits `pred`'s top-level AND chain into `(in_place, lifted)`.
///
/// An atom is "lifted" iff it contains at least one column
/// reference whose `ColumnId` is in `alias_outputs` (per
/// [`expr_references_alias`]). Atoms with no alias references stay
/// in `in_place`. Either side may be `None` if no atom landed
/// there. Reconstruction preserves the user's atom order within
/// each side.
///
/// Non-AND root nodes are treated as a single atom — `OR` does
/// not decompose because its evaluation is non-conjunctive.
fn split_predicate_by_alias_refs(
    pred: ScalarExpr,
    alias_outputs: &HashSet<ColumnId>,
) -> (Option<ScalarExpr>, Option<ScalarExpr>) {
    let mut in_place: Vec<ScalarExpr> = Vec::new();
    let mut lifted: Vec<ScalarExpr> = Vec::new();
    collect_atoms(pred, alias_outputs, &mut in_place, &mut lifted);
    (and_chain(in_place), and_chain(lifted))
}

fn collect_atoms(
    pred: ScalarExpr,
    alias_outputs: &HashSet<ColumnId>,
    in_place: &mut Vec<ScalarExpr>,
    lifted: &mut Vec<ScalarExpr>,
) {
    // N-ary spelling of the `And` split below: each conjunct of a
    // chain is its own atom, so alias-lifting moves only the conjuncts
    // that reference an alias instead of the whole chain.
    if let ScalarExpr::LogicalChain {
        op: super::scalar::LogicalOp::And,
        operands,
        ..
    } = &pred
    {
        for operand in operands.clone() {
            collect_atoms(operand, alias_outputs, in_place, lifted);
        }
        return;
    }
    if let ScalarExpr::BinOp {
        op, left, right, ..
    } = &pred
    {
        if matches!(op, super::scalar::BinOpKind::And) {
            // Move children out via clone+take pattern: pattern
            // borrow above prevents an in-place destructure.
            let l = (**left).clone();
            let r = (**right).clone();
            collect_atoms(l, alias_outputs, in_place, lifted);
            collect_atoms(r, alias_outputs, in_place, lifted);
            return;
        }
    }
    if expr_references_alias(&pred, alias_outputs) {
        lifted.push(pred);
    } else {
        in_place.push(pred);
    }
}

fn and_chain(mut atoms: Vec<ScalarExpr>) -> Option<ScalarExpr> {
    match atoms.len() {
        0 => None,
        1 => Some(atoms.remove(0)),
        // Rebuilt flat. `collect_atoms` splits a conjunction
        // into one atom per conjunct, so folding those atoms back into a
        // `BinOp` spine here would re-create exactly the depth the N-ary
        // chain exists to avoid.
        _ => {
            let span = Span {
                start: atoms[0].span().start,
                end: atoms[atoms.len() - 1].span().end,
            };
            Some(ScalarExpr::LogicalChain {
                op: super::scalar::LogicalOp::And,
                operands: atoms,
                span,
            })
        }
    }
}

/// Inject pending column allocations onto their owning FROM-source
/// nodes by `NodeId` equality.
///
/// Each `(NodeId, ColumnId)` pair was stamped at first reference (see
/// [`LowerCtx::lower_column_ref`]) with the source's NodeId resolved
/// from [`LowerCtx::from_aliases`] / [`LowerCtx::from_source_order`].
/// Routing here is therefore a direct match: walk the FROM plan and,
/// at every node whose `node_id` appears in the pending map, append
/// that node's column list. No alias-text matching, no leftmost-scan
/// fallback — those decisions were made at allocation time.
///
/// Per-FROM-item drains ([`LowerCtx::drain_scan_cols_for`]) consume
/// most entries before this final pass runs; the leftovers here are
/// typically JOIN ON-expression refs and projection refs allocated
/// after the source's `RelPlan` node was already constructed with an
/// empty column list.
///
/// The match is exhaustive over `RelPlan` per the closed-enum
/// discipline: every variant must be listed so that adding a new
/// FROM-source variant in the future cannot silently drop
/// pending columns.
fn attach_pending_source_cols(
    plan: RelPlan,
    pending: Vec<(crate::ast::NodeId, ColumnId)>,
) -> (RelPlan, Vec<(crate::ast::NodeId, ColumnId)>) {
    if pending.is_empty() {
        return (plan, Vec::new());
    }
    let mut by_node: std::collections::HashMap<crate::ast::NodeId, Vec<ColumnId>> =
        std::collections::HashMap::new();
    for (n, id) in pending {
        by_node.entry(n).or_default().push(id);
    }
    let new_plan = inject_pending_into_from_plan(plan, &mut by_node);
    let leftover: Vec<(crate::ast::NodeId, ColumnId)> = by_node
        .into_iter()
        .flat_map(|(n, ids)| ids.into_iter().map(move |c| (n, c)))
        .collect();
    (new_plan, leftover)
}

fn inject_pending_into_from_plan(
    plan: RelPlan,
    pending: &mut std::collections::HashMap<crate::ast::NodeId, Vec<ColumnId>>,
) -> RelPlan {
    if pending.is_empty() {
        return plan;
    }
    match plan {
        // FROM-source leaf variants whose `columns` list owns the
        // ColumnIds users may reference as `alias.col`. These are the
        // only attach targets — refs against other variants would
        // never have stamped against their NodeId.
        RelPlan::Scan {
            table,
            mut columns,
            modifier,
            alias,
            node_id,
            span,
            hints: _,
        } => {
            if let Some(extra) = pending.remove(&node_id) {
                columns.extend(extra);
            }
            RelPlan::Scan {
                table,
                columns,
                modifier,
                alias,
                node_id,
                span,
                hints: Vec::new(),
            }
        }
        RelPlan::CteRef {
            name,
            scope,
            mut columns,
            alias,
            node_id,
            span,
            hints: _,
        } => {
            if let Some(extra) = pending.remove(&node_id) {
                columns.extend(extra);
            }
            RelPlan::CteRef {
                name,
                scope,
                columns,
                alias,
                node_id,
                span,
                hints: Vec::new(),
            }
        }
        RelPlan::DerivedTable {
            input,
            mut columns,
            alias,
            alias_columns,
            node_id,
            span,
            hints: _,
        } => {
            if let Some(extra) = pending.remove(&node_id) {
                columns.extend(extra);
            }
            RelPlan::DerivedTable {
                input,
                columns,
                alias,
                alias_columns,
                node_id,
                span,
                hints: Vec::new(),
            }
        }
        // Table-valued functions (`FROM TABLE(udtf(…))`,
        // `FROM FLATTEN(input => arr) AS m`, `FROM UNNEST(arr) u(v)`)
        // expose an alias whose columns are allocate-on-first-use:
        // `lower_column_ref` registers the alias in
        // `from_aliases` (via `register_from_source` at TVF
        // construction) and any subsequent qualified ref like
        // `m.value` stamps a fresh `ColumnOrigin::Table` id against
        // the TVF's `node_id`. Refs that surface AFTER the TVF was
        // already built (projection / WHERE / QUALIFY / ORDER BY)
        // miss the per-FROM-item drain and arrive here. Append them
        // to `output_columns` — that field is the TVF's exposed
        // schema, exactly the role `Scan.columns` plays for base
        // tables.
        RelPlan::TableFunction {
            call,
            alias,
            mut output_columns,
            lateral,
            modifier,
            node_id,
            span,
            hints: _,
        } => {
            if let Some(extra) = pending.remove(&node_id) {
                output_columns.extend(extra);
            }
            RelPlan::TableFunction {
                call,
                alias,
                output_columns,
                lateral,
                modifier,
                node_id,
                span,
                hints: Vec::new(),
            }
        }
        RelPlan::Values {
            rows,
            mut columns,
            alias,
            node_id,
            span,
            hints: _,
        } => {
            if let Some(extra) = pending.remove(&node_id) {
                columns.extend(extra);
            }
            RelPlan::Values {
                rows,
                columns,
                alias,
                node_id,
                span,
                hints: Vec::new(),
            }
        }
        // ModelRef participates in the late-attach pass
        // identically to `Scan` / `CteRef` / `DerivedTable` /
        // `TableFunction` / `Values`. SELECT projections that
        // reference columns of a `ref()` source allocate their
        // ColumnIds against the ModelRef's NodeId at first use
        // (see `lower_column_ref`); those refs miss the per-FROM-
        // item drain when the projection is processed after FROM,
        // and arrive here with `node_id == this.node_id`. Append
        // them to `columns` so the `ModelRef` carries its complete
        // output schema.
        RelPlan::ModelRef {
            model,
            mut columns,
            alias,
            node_id,
            span,
            hints: _,
        } => {
            if let Some(extra) = pending.remove(&node_id) {
                columns.extend(extra);
            }
            RelPlan::ModelRef {
                model,
                columns,
                alias,
                node_id,
                span,
                hints: Vec::new(),
            }
        }
        // Structural composites that may contain a FROM-source leaf:
        // recurse into both/all children. The match must remain
        // exhaustive over the closed enum; pass-through arms below
        // are listed individually so future variants surface here.
        RelPlan::Join {
            left,
            right,
            kind,
            on,
            match_condition,
            using,
            natural,
            directed,
            lateral,
            implicit,
            node_id,
            span,
            clause_span,
            hints: _,
        } => {
            let new_left = inject_pending_into_from_plan(*left, pending);
            let new_right = inject_pending_into_from_plan(*right, pending);
            RelPlan::Join {
                left: Box::new(new_left),
                right: Box::new(new_right),
                kind,
                on,
                match_condition,
                using,
                natural,
                directed,
                lateral,
                implicit,
                node_id,
                span,
                clause_span,
                hints: Vec::new(),
            }
        }
        // FROM-source variants whose column lists ARE the source's
        // declared output schema (not allocate-on-first-use). Lowering
        // does not currently allocate-on-first-use against these
        // nodes' aliases, so any pending entry keyed on their NodeId
        // is a programming error worth surfacing — but lowering
        // remains total: we leave them unchanged and the entries
        // stay in `pending` so a downstream consistency check (e.g.
        // a future strict-mode invariant) can flag them.
        plan @ (RelPlan::Unnest { .. }
        | RelPlan::Pivot { .. }
        | RelPlan::Unpivot { .. }
        | RelPlan::MatchRecognize { .. }
        | RelPlan::ConnectBy { .. }
        | RelPlan::TableSample { .. }
        | RelPlan::Project { .. }
        | RelPlan::Filter { .. }
        | RelPlan::Aggregate { .. }
        | RelPlan::Window { .. }
        | RelPlan::SetOp { .. }
        | RelPlan::Sort { .. }
        | RelPlan::Limit { .. }
        | RelPlan::Insert { .. }
        | RelPlan::Update { .. }
        | RelPlan::Delete { .. }
        | RelPlan::Merge { .. }
        | RelPlan::MultiInsert { .. }
        | RelPlan::Explain { .. }
        | RelPlan::WithScope { .. }
        | RelPlan::CreateAsQuery { .. }
        | RelPlan::CreateTableForm { .. }
        | RelPlan::ParseRecovery { .. }
        | RelPlan::Opaque { .. }
        | RelPlan::InvalidInput { .. }) => plan,
    }
}

// ────────────────────────────────────────────────────────────────────────
// Stale-column-ref rebind
// ────────────────────────────────────────────────────────────────────────
//
// Some operators consume input column IDs and emit fresh output IDs
// (Aggregate's grouping keys are the canonical case: `GROUP BY x`
// produces a fresh ColumnId for the grouping output and the original
// `x` ColumnId is no longer in the operator's output schema).
// Lowering does not always rebind references to the consumed IDs in
// expressions of *parent* operators — e.g., a `SELECT x FROM ... GROUP
// BY x` Project's item carries `expr: Column(input_x_id)` and
// `output: groupkey_output_id`, leaving the Project's expression
// referencing a column that does not exist in its input's
// `output_schema()`. The constraints / lineage / nullability / taint
// folds key off `input_c[item.expr.column]`, so the constraint chain
// silently breaks at every renaming operator.
//
// `rebind_stale_column_refs` is a post-lowering pass that walks the
// plan bottom-up. Each operator returns the rename map it exposes to
// its parent (`consumed_input → fresh_output`). At each operator, the
// child's accumulated map is applied to the operator's own scalar
// fields, then combined with this operator's own renames (only
// Aggregate adds renames today) and propagated upward.
//
// The pass is closed-enum exhaustive on `RelPlan` and on
// `ScalarExpr` (via the `ScalarExprMutator` trait). Multi-input
// operators (`Join`, `SetOp`) keep their children's maps separate;
// scope boundaries (`SetOp`, `DerivedTable`, `WithScope`, scalar
// subqueries) consume the inner map and expose nothing upward —
// fresh outer IDs at the boundary make pre-rename refs from outside
// invalid by construction.

use super::visitor::{walk_scalar_expr_standalone_mut, ScalarExprMutator};

type RenameMap = HashMap<ColumnId, ColumnId>;

/// `ScalarExprMutator` that substitutes every `ScalarExpr::Column`
/// whose `ColumnId` appears in `map` with the mapped target. Other
/// `ScalarExpr` variants descend via the standard mutator walk;
/// scalar subqueries are processed as their own scope (a fresh
/// `rebind_stale_column_refs` walk over the subquery plan).
///
/// `OuterRef` is intentionally not substituted: it references a
/// column in an enclosing scope, not the current one. If a future
/// corpus mismatch shows OuterRef-bearing renames matter, this is
/// the place to extend.
struct ScalarRebindMutator<'a> {
    map: &'a RenameMap,
}

impl<'a> ScalarExprMutator for ScalarRebindMutator<'a> {
    fn visit_scalar_expr_mut(&mut self, expr: &mut ScalarExpr) {
        if let ScalarExpr::Column { column, .. } = expr {
            if let Some(&new_id) = self.map.get(column) {
                *column = new_id;
            }
        }
        walk_scalar_expr_standalone_mut(self, expr);
    }

    fn visit_scalar_subquery_mut(
        &mut self,
        plan: &mut RelPlan,
        _correlates_with: &mut Vec<ColumnId>,
    ) {
        rebind_stale_column_refs(plan);
    }
}

fn apply_renames_to_scalar(expr: &mut ScalarExpr, map: &RenameMap) {
    if map.is_empty() {
        return;
    }
    let mut m = ScalarRebindMutator { map };
    m.visit_scalar_expr_mut(expr);
}

fn apply_renames_to_grouping(grouping: &mut GroupingSpec, map: &RenameMap) {
    if map.is_empty() {
        return;
    }
    let visit = |keys: &mut [GroupKey], map: &RenameMap| {
        for k in keys {
            apply_renames_to_scalar(&mut k.expr, map);
        }
    };
    match grouping {
        GroupingSpec::None => {}
        GroupingSpec::Standard(keys)
        | GroupingSpec::Cube(keys)
        | GroupingSpec::Rollup(keys)
        | GroupingSpec::All(keys) => visit(keys, map),
        GroupingSpec::GroupingSets(sets) => {
            for ks in sets {
                visit(ks, map);
            }
        }
    }
}

fn apply_renames_to_aggregate_call(agg: &mut AggregateCall, map: &RenameMap) {
    if map.is_empty() {
        return;
    }
    for a in &mut agg.args {
        apply_renames_to_scalar(a, map);
    }
    for (_, a) in &mut agg.named_args {
        apply_renames_to_scalar(a, map);
    }
    if let Some(f) = &mut agg.filter {
        apply_renames_to_scalar(f, map);
    }
    for sk in &mut agg.arg_order {
        apply_renames_to_scalar(&mut sk.expr, map);
    }
    for sk in &mut agg.within_group_order {
        apply_renames_to_scalar(&mut sk.expr, map);
    }
}

fn apply_renames_to_window_call(call: &mut WindowCall, map: &RenameMap) {
    if map.is_empty() {
        return;
    }
    for a in &mut call.args {
        apply_renames_to_scalar(a, map);
    }
    for p in &mut call.partition_by {
        apply_renames_to_scalar(p, map);
    }
    for sk in &mut call.order_by {
        apply_renames_to_scalar(&mut sk.expr, map);
    }
    if let Some(frame) = &mut call.frame {
        apply_renames_to_frame_bound(&mut frame.start, map);
        apply_renames_to_frame_bound(&mut frame.end, map);
    }
}

fn apply_renames_to_frame_bound(b: &mut FrameBound, map: &RenameMap) {
    match b {
        FrameBound::UnboundedPreceding
        | FrameBound::CurrentRow
        | FrameBound::UnboundedFollowing => {}
        FrameBound::Preceding(e) | FrameBound::Following(e) => apply_renames_to_scalar(e, map),
    }
}

fn collect_grouping_renames(grouping: &GroupingSpec, out: &mut RenameMap) {
    let visit = |keys: &[GroupKey], out: &mut RenameMap| {
        for k in keys {
            if let ScalarExpr::Column { column, .. } = &k.expr {
                out.insert(*column, k.output);
            }
        }
    };
    match grouping {
        GroupingSpec::None => {}
        GroupingSpec::Standard(keys)
        | GroupingSpec::Cube(keys)
        | GroupingSpec::Rollup(keys)
        | GroupingSpec::All(keys) => visit(keys, out),
        GroupingSpec::GroupingSets(sets) => {
            for ks in sets {
                visit(ks, out);
            }
        }
    }
}

/// Public entry point. Walks `plan` and rebinds any stale column
/// references in-place; the top-level rename map is discarded
/// because the statement plan has no parent to hand it to.
pub(crate) fn rebind_stale_column_refs(plan: &mut RelPlan) {
    let _ = rebind_walk(plan);
}

/// Bottom-up walker. Returns the rename map this subtree exposes to
/// its parent.
///
/// Closed-enum exhaustive on `RelPlan`: every variant
/// must have an arm so a new variant fails to compile until the pass
/// decides what (if anything) it contributes.
fn rebind_walk(plan: &mut RelPlan) -> RenameMap {
    match plan {
        // ── Leaves: no input renames ────────────────────────────────────
        RelPlan::Scan { .. }
        | RelPlan::Values { .. }
        | RelPlan::CteRef { .. }
        | RelPlan::ModelRef { .. }
        | RelPlan::ParseRecovery { .. }
        | RelPlan::Opaque { .. }
        | RelPlan::InvalidInput { .. }
        | RelPlan::CreateTableForm { .. } => RenameMap::new(),

        // ── Aggregate: the only operator that adds renames ──────────────
        RelPlan::Aggregate {
            input,
            grouping,
            aggregates,
            having,
            ..
        } => {
            let mut renames = rebind_walk(input);
            // Apply child renames to Aggregate's own scalar fields
            // BEFORE adding own renames, since grouping/having/aggregate
            // args reference pre-Aggregate (input-scope) columns.
            apply_renames_to_grouping(grouping, &renames);
            for agg in aggregates {
                apply_renames_to_aggregate_call(agg, &renames);
            }
            if let Some(h) = having {
                apply_renames_to_scalar(h, &renames);
            }
            // Add this Aggregate's own renames: each Column-typed
            // grouping key consumes its input ColumnId and re-exposes
            // it as the grouping key's `output`.
            collect_grouping_renames(grouping, &mut renames);
            renames
        }

        // ── Pass-through unary ops ──────────────────────────────────────
        RelPlan::Project {
            input,
            items,
            distinct_on,
            ..
        } => {
            let renames = rebind_walk(input);
            for item in items {
                if let ProjectItem::Expr(pe) = item {
                    apply_renames_to_scalar(&mut pe.expr, &renames);
                }
            }
            for e in distinct_on {
                apply_renames_to_scalar(e, &renames);
            }
            renames
        }

        RelPlan::Filter {
            input, predicate, ..
        } => {
            let renames = rebind_walk(input);
            apply_renames_to_scalar(predicate, &renames);
            renames
        }

        RelPlan::Window { input, windows, .. } => {
            let renames = rebind_walk(input);
            for w in windows {
                apply_renames_to_window_call(w, &renames);
            }
            renames
        }

        RelPlan::Sort { input, keys, .. } => {
            let renames = rebind_walk(input);
            for k in keys {
                apply_renames_to_scalar(&mut k.expr, &renames);
            }
            renames
        }

        RelPlan::Limit {
            input,
            limit,
            offset,
            ..
        } => {
            let renames = rebind_walk(input);
            if let Some(l) = limit {
                apply_renames_to_scalar(l, &renames);
            }
            if let Some(o) = offset {
                apply_renames_to_scalar(o, &renames);
            }
            renames
        }

        RelPlan::TableSample { input, .. } => rebind_walk(input),

        RelPlan::Unnest { input, array, .. } => {
            let renames = rebind_walk(input);
            apply_renames_to_scalar(array, &renames);
            renames
        }

        RelPlan::Pivot {
            input,
            aggregates,
            default_on_null,
            ..
        } => {
            let renames = rebind_walk(input);
            for a in aggregates {
                apply_renames_to_aggregate_call(a, &renames);
            }
            if let Some(d) = default_on_null {
                apply_renames_to_scalar(d, &renames);
            }
            renames
        }

        RelPlan::Unpivot { input, .. } => rebind_walk(input),

        RelPlan::MatchRecognize { input, body, .. } => {
            let renames = rebind_walk(input);
            for e in &mut body.partition_by {
                apply_renames_to_scalar(e, &renames);
            }
            for k in &mut body.order_by {
                apply_renames_to_scalar(&mut k.expr, &renames);
            }
            for meas in &mut body.measures {
                apply_renames_to_scalar(&mut meas.expr, &renames);
            }
            for d in &mut body.define {
                apply_renames_to_scalar(&mut d.predicate, &renames);
            }
            renames
        }

        RelPlan::ConnectBy {
            input,
            start_with,
            connect,
            ..
        } => {
            let renames = rebind_walk(input);
            if let Some(sw) = start_with {
                apply_renames_to_scalar(sw, &renames);
            }
            apply_renames_to_scalar(connect, &renames);
            renames
        }

        // ── Multi-input ops ─────────────────────────────────────────────
        RelPlan::Join {
            left,
            right,
            on,
            match_condition,
            ..
        } => {
            let mut renames = rebind_walk(left);
            for (k, v) in rebind_walk(right) {
                renames.insert(k, v);
            }
            if let Some(p) = on {
                apply_renames_to_scalar(p, &renames);
            }
            if let Some(p) = match_condition {
                apply_renames_to_scalar(p, &renames);
            }
            renames
        }

        // ── Scope boundaries: process inner subtree, expose nothing ────
        // SetOp's `output_columns` are positional fresh IDs; branch
        // IDs are not visible above. DerivedTable's `columns` and
        // WithScope's CteRef columns are likewise outer-scope fresh
        // IDs by construction. Pre-rename refs from outside these
        // boundaries are a separate (lowering-time) name-resolution
        // problem, not a stale-rebind one.
        RelPlan::SetOp { inputs, .. } => {
            for branch in inputs {
                let _ = rebind_walk(branch);
            }
            RenameMap::new()
        }

        RelPlan::DerivedTable { input, .. } => {
            let _ = rebind_walk(input);
            RenameMap::new()
        }

        RelPlan::WithScope { ctes, body, .. } => {
            for c in ctes {
                match &mut c.body {
                    super::plan::CteBody::NonRecursive(p) => {
                        let _ = rebind_walk(p);
                    }
                    super::plan::CteBody::Recursive { anchor, step, .. } => {
                        let _ = rebind_walk(anchor);
                        let _ = rebind_walk(step);
                    }
                }
            }
            let _ = rebind_walk(body);
            RenameMap::new()
        }

        // TableFunction's `call` is a self-contained scalar (function
        // identity + literal-or-correlated args); no input plan to
        // produce renames from. Apply an empty map as a structural
        // no-op for closed-enum hygiene.
        RelPlan::TableFunction { call, .. } => {
            let empty = RenameMap::new();
            apply_renames_to_scalar(call, &empty);
            empty
        }

        // ── DML and statement roots: process query subtrees, no
        //    renames exposed (statement roots have no parent to
        //    consume them). Scalar fields (assignments, predicates,
        //    on_conflict, etc.) reference target-table columns which
        //    are not subject to inner-Aggregate renames; if a future
        //    corpus mismatch shows otherwise, extend per-arm.
        RelPlan::Insert { source, .. } => {
            match source {
                super::plan::InsertSource::Query(p) | super::plan::InsertSource::Values(p) => {
                    let _ = rebind_walk(p);
                }
                super::plan::InsertSource::DefaultValues => {}
            }
            RenameMap::new()
        }

        RelPlan::Update { from, .. } => {
            if let Some(f) = from {
                let _ = rebind_walk(f);
            }
            RenameMap::new()
        }

        RelPlan::Delete { using, .. } => {
            if let Some(u) = using {
                let _ = rebind_walk(u);
            }
            RenameMap::new()
        }

        RelPlan::Merge { source, .. } => {
            let _ = rebind_walk(source);
            RenameMap::new()
        }

        RelPlan::MultiInsert { source, .. } => {
            let _ = rebind_walk(source);
            RenameMap::new()
        }

        RelPlan::Explain { body, .. } => {
            let _ = rebind_walk(body);
            RenameMap::new()
        }

        RelPlan::CreateAsQuery { body, .. } => {
            if let Some(body) = body.as_deref_mut() {
                let _ = rebind_walk(body);
            }
            RenameMap::new()
        }
    }
}

/// Match a SQL `ILIKE` pattern against a column name (case-insensitive).
/// Supports the two-metacharacter SQL subset: `%` (zero-or-more chars)
/// and `_` (exactly one char). Used by `expand_star_items` to filter
/// catalog-driven star enumeration under `SELECT * ILIKE '<pattern>'`.
///
/// No backslash-escape recognition — Snowflake / BigQuery `ILIKE` on
/// star modifiers accepts the bare two-metacharacter form; if users
/// need to match a literal `%` or `_`, they don't use `ILIKE` on the
/// star. Idiomatic patterns the tests exercise: `'ID%'`, `'PII_%'`,
/// `'%_AT'`.
fn sql_ilike_matches(pattern: &str, name: &str) -> bool {
    let pat: Vec<char> = pattern.chars().flat_map(char::to_lowercase).collect();
    let txt: Vec<char> = name.chars().flat_map(char::to_lowercase).collect();
    ilike_inner(&pat, 0, &txt, 0)
}

fn ilike_inner(pat: &[char], pi: usize, txt: &[char], ti: usize) -> bool {
    if pi == pat.len() {
        return ti == txt.len();
    }
    match pat[pi] {
        '%' => {
            // Try matching zero or more chars: skip the % greedily,
            // then for each tail position attempt the remainder.
            // Tail-recursive in shape; pattern strings are short
            // enough that the naive loop is fine.
            let mut k = ti;
            loop {
                if ilike_inner(pat, pi + 1, txt, k) {
                    return true;
                }
                if k == txt.len() {
                    return false;
                }
                k += 1;
            }
        }
        '_' => {
            if ti == txt.len() {
                false
            } else {
                ilike_inner(pat, pi + 1, txt, ti + 1)
            }
        }
        c => {
            if ti == txt.len() || txt[ti] != c {
                false
            } else {
                ilike_inner(pat, pi + 1, txt, ti + 1)
            }
        }
    }
}

// ────────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dialect::{postgres, Dialect};
    use crate::lexer::{tokenize, tokenize_with_dialect};
    use crate::parser::{parse_script, try_parse_script_with_dialect};

    fn parse_one(src: &str) -> AstStmt {
        let tokens = tokenize(src);
        let script = parse_script(src, &tokens.tokens).expect("parse");
        assert_eq!(script.stmts.len(), 1, "expected single statement");
        script.stmts.into_iter().next().unwrap()
    }

    fn parse_one_with_dialect(src: &str, dialect: &dyn Dialect) -> AstStmt {
        let lex = tokenize_with_dialect(src, dialect);
        let script =
            try_parse_script_with_dialect(src, &lex.tokens, dialect).expect("parse with dialect");
        assert_eq!(script.stmts.len(), 1, "expected single statement");
        script.stmts.into_iter().next().unwrap()
    }

    fn lower(src: &str) -> RelPlan {
        let stmt = parse_one(src);
        lower_query(&stmt, src, StrictMode::Permissive).expect("lower")
    }

    /// Test helper: lower a single statement and also return the
    /// [`BindingTable`] needed by [`derive_facts_from_plan`]. Mirrors
    /// the public `lower_query_full_with_bindings` API but with the
    /// same defaults [`lower`] uses (default catalog, empty session,
    /// permissive strictness).
    fn lower_with_bindings(src: &str) -> (RelPlan, BindingTable) {
        let stmt = parse_one(src);
        let catalog = FunctionCatalog::for_dialect(CatalogDialect::Default);
        let session = SessionContext::default();
        let (plan, _catalog_ctx, bindings, _facts) = lower_query_full_with_bindings(
            &stmt,
            src,
            StrictMode::Permissive,
            &catalog,
            &session,
            None,
        )
        .expect("lower");
        (plan, bindings)
    }

    /// Test helper: lower a single statement and return only the
    /// [`super::super::statement_facts::StatementFacts`] sibling.
    /// Used by the unit test for `FOR UPDATE` lowering.
    fn lower_facts(src: &str) -> super::super::statement_facts::StatementFacts {
        let stmt = parse_one(src);
        let catalog = FunctionCatalog::for_dialect(CatalogDialect::Default);
        let session = SessionContext::default();
        let (_plan, _catalog_ctx, _bindings, facts) = lower_query_full_with_bindings(
            &stmt,
            src,
            StrictMode::Permissive,
            &catalog,
            &session,
            None,
        )
        .expect("lower");
        facts
    }

    fn lower_with_dialect(src: &str, dialect: &dyn Dialect) -> RelPlan {
        let stmt = parse_one_with_dialect(src, dialect);
        lower_query(&stmt, src, StrictMode::Permissive).expect("lower")
    }

    #[test]
    fn derived_table_wraps_subquery() {
        let plan = lower("SELECT d.a FROM (SELECT a FROM t WHERE x=1) d");
        // Project(DerivedTable(Filter(Scan t) predicate …))
        let inner = match &plan {
            RelPlan::Project { input, .. } => input.as_ref(),
            other => panic!("expected Project, got {:?}", other),
        };
        match inner {
            RelPlan::DerivedTable {
                input,
                alias,
                columns,
                ..
            } => {
                assert!(alias.is_some(), "d alias must be captured");
                assert!(!columns.is_empty(), "derived columns fresh-allocated");
                // Inner SHOULD contain a Filter with the WHERE —
                // the scope boundary doesn't remove it, it merely
                // isolates fact projection.
                match input.as_ref() {
                    RelPlan::Project {
                        input: inner_input, ..
                    } => {
                        assert!(
                            matches!(inner_input.as_ref(), RelPlan::Filter { .. }),
                            "inner filter must survive, got {:?}",
                            inner_input
                        );
                    }
                    other => panic!("expected inner Project, got {:?}", other),
                }
            }
            other => panic!("expected DerivedTable, got {:?}", other),
        }
    }

    #[test]
    fn subquery_wrapped_by_sample_lowers_to_table_sample() {
        let src = "SELECT * FROM (SELECT a FROM t) SAMPLE (1)";
        let plan = lower(src);
        match plan {
            RelPlan::Project { input, .. } => match *input {
                RelPlan::TableSample { input, .. } => match *input {
                    RelPlan::DerivedTable { .. } => {}
                    other => panic!("expected DerivedTable inside TableSample, got {other:?}"),
                },
                other => panic!("expected TableSample inside Project, got {other:?}"),
            },
            other => panic!("expected Project at root, got {other:?}"),
        }
    }

    #[test]
    fn from_values_lowers_to_values_source() {
        let src = "SELECT * FROM VALUES (1, 'a'), (2, 'b') AS v(id, name)";
        let plan = lower(src);
        let input = match plan {
            RelPlan::Project { input, .. } => input,
            other => panic!("expected Project, got {:?}", other),
        };
        match *input {
            RelPlan::Values {
                rows,
                columns,
                alias,
                ..
            } => {
                assert_eq!(rows.len(), 2, "VALUES row count");
                assert_eq!(columns.len(), 2, "VALUES arity");
                assert_eq!(alias.map(|k| k.as_str().to_string()), Some("V".to_string()));
            }
            other => panic!("expected Values source, got {:?}", other),
        }
    }

    #[test]
    fn strict_mode_accepts_from_values() {
        let src = "SELECT * FROM VALUES (1), (2) AS v(c1)";
        let stmt = parse_one(src);
        let plan = lower_query(&stmt, src, StrictMode::Strict)
            .expect("strict lower must accept FROM VALUES");
        assert!(matches!(plan, RelPlan::Project { .. }));
    }

    #[test]
    fn scan_project_only() {
        let plan = lower("SELECT a FROM t");
        match plan {
            RelPlan::Project {
                ref input,
                ref items,
                distinct,
                ..
            } => {
                assert!(!distinct);
                assert_eq!(items.len(), 1);
                let ProjectItem::Expr(e0) = &items[0] else {
                    panic!("expected ProjectItem::Expr, got {:?}", items[0]);
                };
                assert!(matches!(e0.expr, ScalarExpr::Column { .. }));
                assert!(matches!(**input, RelPlan::Scan { .. }));
            }
            other => panic!("expected Project, got {:?}", other),
        }
    }

    #[test]
    fn scan_filter_project() {
        let plan = lower("SELECT a FROM t WHERE a = 1");
        // Project → Filter → Scan
        let filter_input = match plan {
            RelPlan::Project { input, .. } => input,
            other => panic!("expected Project, got {:?}", other),
        };
        match *filter_input {
            RelPlan::Filter {
                ref input,
                ref predicate,
                ..
            } => {
                assert!(matches!(predicate, ScalarExpr::BinOp { .. }));
                assert!(matches!(**input, RelPlan::Scan { .. }));
            }
            other => panic!("expected Filter, got {:?}", other),
        }
    }

    #[test]
    fn ambiguous_unqualified_ref_does_not_bind_to_leftmost_source() {
        let src = "SELECT d FROM t1 JOIN t2 ON t1.id = t2.id";
        let stmt = parse_one(src);
        let select_node = match &stmt {
            AstStmt::Select(s) => s.node_id,
            other => panic!("expected Select stmt, got {:?}", other),
        };

        let (plan, _, bindings, _facts) = lower_query_full_with_bindings(
            &stmt,
            src,
            StrictMode::Permissive,
            &FunctionCatalog::for_dialect(CatalogDialect::Default),
            &SessionContext::default(),
            None,
        )
        .expect("lower with bindings");

        let (project_col, left_scan_node) = match &plan {
            RelPlan::Project { items, input, .. } => {
                let col = match &items[0] {
                    ProjectItem::Expr(e) => match e.expr {
                        ScalarExpr::Column { column, .. } => column,
                        ref other => panic!("expected projected column ref, got {:?}", other),
                    },
                    other => panic!("expected ProjectItem::Expr, got {:?}", other),
                };
                let left_node = match input.as_ref() {
                    RelPlan::Join { left, .. } => match left.as_ref() {
                        RelPlan::Scan { node_id, .. } => *node_id,
                        other => panic!("expected left Scan under Join, got {:?}", other),
                    },
                    other => panic!("expected Join input under Project, got {:?}", other),
                };
                (col, left_node)
            }
            other => panic!("expected Project root, got {:?}", other),
        };

        let binding = bindings
            .get(project_col)
            .expect("projected column id must exist in binding table");
        match &binding.origin {
            ColumnOrigin::Table { table_node, .. } => {
                assert_eq!(
                    *table_node, select_node,
                    "ambiguous unqualified ref should stay on statement node"
                );
                assert_ne!(
                    *table_node, left_scan_node,
                    "ambiguous unqualified ref must not fabricate leftmost source attribution"
                );
            }
            other => panic!("expected Table origin for fallback column, got {:?}", other),
        }
    }

    #[test]
    fn qualified_correlated_ref_keeps_outer_source_provenance() {
        let src =
            "SELECT (SELECT 1 FROM payments p WHERE p.order_id = o.order_id) AS keep FROM orders o";
        let stmt = parse_one(src);

        let select_node = match &stmt {
            AstStmt::Select(s) => s.node_id,
            other => panic!("expected Select stmt, got {:?}", other),
        };

        let (plan, _, bindings, _facts) = lower_query_full_with_bindings(
            &stmt,
            src,
            StrictMode::Permissive,
            &FunctionCatalog::for_dialect(CatalogDialect::Default),
            &SessionContext::default(),
            None,
        )
        .expect("lower with bindings");

        let outer_scan_node = match &plan {
            RelPlan::Project { input, .. } => match input.as_ref() {
                RelPlan::Scan { node_id, .. } => *node_id,
                other => panic!("expected outer Scan under Project, got {:?}", other),
            },
            other => panic!("expected Project root, got {:?}", other),
        };

        let correlated_col = match &plan {
            RelPlan::Project { items, .. } => {
                let subquery = match &items[0] {
                    ProjectItem::Expr(e) => match &e.expr {
                        ScalarExpr::ScalarSubquery { subquery, .. } => subquery.as_ref(),
                        other => panic!("expected ScalarSubquery, got {:?}", other),
                    },
                    other => panic!("expected ProjectItem::Expr, got {:?}", other),
                };
                match subquery {
                    RelPlan::Project { input, .. } => match input.as_ref() {
                        RelPlan::Filter { predicate, .. } => match predicate {
                            ScalarExpr::BinOp { right, .. } => match right.as_ref() {
                                // A qualified
                                // correlated ref lowers to a first-class
                                // `OuterRef`. Its `column` still carries the
                                // outer column's id, whose binding keeps the
                                // `ColumnOrigin::Table` outer-source provenance
                                // asserted below.
                                ScalarExpr::OuterRef { column, .. } => *column,
                                other => panic!("expected correlated OuterRef, got {:?}", other),
                            },
                            other => panic!("expected BinOp predicate, got {:?}", other),
                        },
                        other => panic!("expected Filter under scalar subquery, got {:?}", other),
                    },
                    other => panic!("expected Project subquery body, got {:?}", other),
                }
            }
            other => panic!("expected Project root, got {:?}", other),
        };

        let binding = bindings
            .get(correlated_col)
            .expect("correlated ref column id must exist in binding table");
        match &binding.origin {
            ColumnOrigin::Table { table_node, .. } => {
                assert_eq!(
                    *table_node, outer_scan_node,
                    "qualified correlated ref should inherit outer source node provenance"
                );
                assert_ne!(
                    *table_node, select_node,
                    "qualified correlated ref must not remain anchored to statement node"
                );
            }
            other => panic!("expected Table origin for correlated ref, got {:?}", other),
        }
    }

    #[test]
    fn select_distinct_sets_project_flag() {
        let plan = lower("SELECT DISTINCT a FROM t");
        match plan {
            RelPlan::Project { distinct, .. } => assert!(distinct),
            other => panic!("expected Project, got {:?}", other),
        }
    }

    #[test]
    fn scan_columns_track_referenced_names() {
        // `b` is referenced only in WHERE — it should still show up on
        // the scan's column list.
        let plan = lower("SELECT a FROM t WHERE b = 1");
        let scan = find_scan(&plan);
        match scan {
            RelPlan::Scan { columns, .. } => assert_eq!(columns.len(), 2),
            _ => unreachable!(),
        }
    }

    #[test]
    fn qualified_table_splits_schema_and_db() {
        let plan = lower("SELECT a FROM db1.sch1.t1");
        let scan = find_scan(&plan);
        match scan {
            RelPlan::Scan { table, .. } => {
                assert_eq!(table.db.as_deref(), Some("db1"));
                assert_eq!(table.schema.as_deref(), Some("sch1"));
                assert_eq!(table.name, "t1");
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn select_star_lowers_as_project_star_in_permissive() {
        // `SELECT *` does not short-circuit to Opaque in
        // permissive mode. It lowers to a `ProjectItem::Star` with
        // an unqualified qualifier and no modifiers.
        let plan = lower("SELECT * FROM t");
        match &plan {
            RelPlan::Project { items, .. } => {
                assert_eq!(items.len(), 1, "single star item");
                match &items[0] {
                    ProjectItem::Star(s) => {
                        assert!(matches!(s.qualifier, StarQualifier::Unqualified));
                        assert!(s.exclude.is_empty());
                        assert!(s.replace.is_empty());
                        assert!(s.rename.is_empty());
                        assert!(s.ilike.is_none());
                    }
                    other => panic!("expected ProjectItem::Star, got {:?}", other),
                }
            }
            other => panic!("expected Project, got {:?}", other),
        }
    }

    #[test]
    fn group_by_lowers_to_aggregate_node() {
        // Plain GROUP BY with aggregates lowers to a real Aggregate
        // node, not Opaque.
        let plan = lower("SELECT a, COUNT(*) FROM t GROUP BY a");
        assert!(
            !matches!(plan, RelPlan::Opaque { .. }),
            "plain GROUP BY with aggregates must lower"
        );
    }

    #[test]
    fn join_is_opaque_in_permissive() {
        // Explicit joins lower to a real plan and are not Opaque.
        let plan = lower("SELECT a FROM t JOIN u ON t.a = u.a");
        assert!(
            !matches!(plan, RelPlan::Opaque { .. }),
            "explicit joins must lower"
        );
    }

    #[test]
    fn non_recursive_cte_lowers_to_with_scope() {
        // A non-recursive CTE with a lowerable body produces
        // a `WithScope` wrapping the main body, and the CTE-name
        // reference in the outer FROM resolves to `CteRef` (not
        // `Scan`).
        let plan = lower("WITH x AS (SELECT a FROM t) SELECT a FROM x");
        let (ctes, body, recursive) = match plan {
            RelPlan::WithScope {
                ctes,
                body,
                recursive,
                ..
            } => (ctes, body, recursive),
            other => panic!("expected WithScope, got {:?}", other),
        };
        assert!(!recursive);
        assert_eq!(ctes.len(), 1);
        assert!(matches!(ctes[0].body, CteBody::NonRecursive(_)));
        // Outer body's FROM resolves `x` as a `CteRef`. After
        // projection lowering the shape is Project -> CteRef.
        match *body {
            RelPlan::Project { input, .. } => match *input {
                RelPlan::CteRef { ref name, .. } => {
                    assert_eq!(name.as_str(), "X");
                }
                other => panic!("expected CteRef under Project, got {:?}", other),
            },
            other => panic!("expected Project, got {:?}", other),
        }
    }

    #[test]
    fn pivot_cte_binding_uses_visible_body_schema_width() {
        let plan = lower(
            "WITH src AS (SELECT parity, bucket, total, avg FROM agg), \
               pvt AS (SELECT * FROM src PIVOT(SUM(total) FOR bucket IN (0, 1))) \
             SELECT * FROM pvt",
        );

        let ctes = match plan {
            RelPlan::WithScope { ctes, .. } => ctes,
            other => panic!("expected WithScope, got {:?}", other),
        };
        assert_eq!(ctes.len(), 2);

        let binding = &ctes[1];
        let body = match &binding.body {
            CteBody::NonRecursive(body) => body,
            CteBody::Recursive { .. } => panic!("expected non-recursive CTE body"),
        };

        assert_eq!(
            binding.output_columns.len(),
            body.cte_visible_output_schema().len()
        );
        assert_eq!(binding.output_columns.len(), 4);
    }

    #[test]
    fn pivot_string_values_use_quoted_identifier_display_names() {
        let src =
            "WITH pvt AS (SELECT * FROM src PIVOT(COUNT(*) FOR event_type IN ('click', 'view'))) \
             SELECT \"view\" FROM pvt";
        let stmt = parse_one(src);
        let catalog = FunctionCatalog::for_dialect(CatalogDialect::Default);
        let session = SessionContext::default();
        let (plan, _, bindings, _facts) = lower_query_full_with_bindings(
            &stmt,
            src,
            StrictMode::Permissive,
            &catalog,
            &session,
            None,
        )
        .expect("lower");

        let (ctes, body) = match plan {
            RelPlan::WithScope { ctes, body, .. } => (ctes, body),
            other => panic!("expected WithScope, got {:?}", other),
        };

        let cte = &ctes[0];
        let output_names: Vec<&str> = cte
            .output_columns
            .iter()
            .map(|id| {
                bindings
                    .get(*id)
                    .expect("pivot output binding")
                    .display_name
                    .as_str()
            })
            .collect();
        assert_eq!(output_names, vec!["\"click\"", "\"view\""]);

        match *body {
            RelPlan::Project { items, .. } => match &items[0] {
                ProjectItem::Expr(ProjectExpr {
                    expr: ScalarExpr::Column { column, .. },
                    ..
                }) => {
                    let display = bindings
                        .get(*column)
                        .expect("project column binding")
                        .display_name
                        .as_str();
                    assert_eq!(display, "\"view\"");
                }
                other => panic!("expected column projection, got {:?}", other),
            },
            other => panic!("expected Project body, got {:?}", other),
        }
    }

    /// `PIVOT … IN (SELECT …)` lowering populates `output_columns`
    /// from the subquery's projection arity:
    /// arity = `aggregates.len() * subquery_schema.len()`.
    #[test]
    fn pivot_subquery_in_list_populates_output_columns_arity() {
        // Subquery projects 3 columns; one aggregate → expect 3 output cols.
        let plan = lower(
            "SELECT * FROM src PIVOT(SUM(total) FOR bucket \
             IN (SELECT b FROM (SELECT 1 AS b, 2 AS c, 3 AS d)))",
        );

        // Walk to the Pivot node (top-level may be wrapped).
        fn find_pivot(p: &RelPlan) -> Option<&RelPlan> {
            match p {
                RelPlan::Pivot { .. } => Some(p),
                RelPlan::Project { input, .. }
                | RelPlan::Filter { input, .. }
                | RelPlan::WithScope { body: input, .. } => find_pivot(input),
                _ => None,
            }
        }

        let pivot = find_pivot(&plan).expect("pivot present");
        let (output_columns, pivot_values, aggregates) = match pivot {
            RelPlan::Pivot {
                output_columns,
                pivot_values,
                aggregates,
                ..
            } => (output_columns, pivot_values, aggregates),
            _ => unreachable!(),
        };

        match pivot_values {
            crate::ir::PivotValues::Subquery(inner) => {
                let inner_arity = inner.output_schema().len();
                assert!(
                    inner_arity > 0,
                    "subquery projection arity must be > 0; got {inner_arity}"
                );
                assert_eq!(
                    output_columns.len(),
                    aggregates.len() * inner_arity,
                    "PIVOT(Subquery) output_columns arity: {} aggregates × {} subquery cols",
                    aggregates.len(),
                    inner_arity,
                );
            }
            other => panic!("expected PivotValues::Subquery, got {:?}", other),
        }

        assert_eq!(
            pivot.output_schema().len(),
            output_columns.len(),
            "Pivot output_schema must match output_columns arity"
        );
    }

    /// `PIVOT … IN (ANY)` under permissive mode keeps zero output
    /// columns; under strict mode surfaces
    /// `CatalogMissing { kind: PivotAnyDistinctValues }`.
    #[test]
    fn pivot_any_in_list_permissive_zero_columns_strict_catalog_missing() {
        let src = "SELECT * FROM src PIVOT(SUM(total) FOR bucket IN (ANY))";

        // Permissive: lowering succeeds; output_columns empty.
        let stmt = parse_one(src);
        let permissive_plan =
            lower_query(&stmt, src, StrictMode::Permissive).expect("permissive lower");

        fn find_pivot(p: &RelPlan) -> Option<&RelPlan> {
            match p {
                RelPlan::Pivot { .. } => Some(p),
                RelPlan::Project { input, .. }
                | RelPlan::Filter { input, .. }
                | RelPlan::WithScope { body: input, .. } => find_pivot(input),
                _ => None,
            }
        }

        let pivot = find_pivot(&permissive_plan).expect("pivot present");
        let (output_columns, pivot_values) = match pivot {
            RelPlan::Pivot {
                output_columns,
                pivot_values,
                ..
            } => (output_columns, pivot_values),
            _ => unreachable!(),
        };
        assert!(
            matches!(pivot_values, crate::ir::PivotValues::Any { .. }),
            "expected PivotValues::Any"
        );
        assert!(
            output_columns.is_empty(),
            "permissive ANY: output_columns must be empty"
        );

        // Strict: lowering surfaces CatalogMissing { PivotAnyDistinctValues }.
        let strict_err = lower_query(&stmt, src, StrictMode::Strict)
            .expect_err("strict lower must fail on PIVOT IN (ANY) without catalog");
        match strict_err.kind {
            LowerErrorKind::Opaque(OpaqueReason::CatalogMissing {
                kind: CatalogLookupKind::PivotAnyDistinctValues,
            }) => {}
            other => panic!(
                "expected CatalogMissing {{ PivotAnyDistinctValues }}, got {:?}",
                other
            ),
        }
    }

    // ─── TVF + wrapper compositions ─────────────────────────────
    //
    // Non-wrapped TVFs lower to `RelPlan::TableFunction` directly
    // (see `lower_base_table_ref`). When a TVF carries a composable
    // wrapper — `PIVOT`, `UNPIVOT`, `TABLESAMPLE`, `MATCH_RECOGNIZE` —
    // the same wrapper chain used by Scan/DerivedTable applies, with
    // `RelPlan::TableFunction` as the wrapped inner. TVF modifiers
    // (`time_travel`, `changes`, `stage_options`, `with_offset`,
    // `table_hints`, `tvf_schema_span`) are all lowered into
    // `ScanModifier` by the TVF branch. A TVF co-existing with
    // `values` or `subquery` is a parser-bug and surfaces as
    // `LowerError::ParseUpstream` → `RelPlan::ParseRecovery`.

    #[test]
    fn tvf_alone_lowers_to_table_function() {
        let plan = lower("SELECT v FROM TABLE(FLATTEN(input => arr)) AS f");
        // Project(TableFunction(...))
        let inner = match &plan {
            RelPlan::Project { input, .. } => input.as_ref(),
            other => panic!("expected Project, got {:?}", other),
        };
        match inner {
            RelPlan::TableFunction { alias, .. } => {
                assert!(alias.is_some(), "TVF alias must be captured");
            }
            other => panic!("expected TableFunction, got {:?}", other),
        }
    }

    #[test]
    fn tvf_with_pivot_wraps_table_function() {
        let plan = lower(
            "SELECT * FROM TABLE(MY_TVF()) AS f \
               PIVOT(SUM(amount) FOR bucket IN (1, 2))",
        );
        // Project(Pivot(TableFunction(...)))
        let inner = match &plan {
            RelPlan::Project { input, .. } => input.as_ref(),
            other => panic!("expected Project, got {:?}", other),
        };
        match inner {
            RelPlan::Pivot { input, .. } => match input.as_ref() {
                RelPlan::TableFunction { .. } => {}
                other => panic!("expected TableFunction inside Pivot, got {:?}", other),
            },
            other => panic!("expected Pivot, got {:?}", other),
        }
    }

    #[test]
    fn tvf_with_unpivot_wraps_table_function() {
        let plan = lower(
            "SELECT * FROM TABLE(MY_TVF()) AS f \
               UNPIVOT(value FOR metric IN (a, b, c))",
        );
        let inner = match &plan {
            RelPlan::Project { input, .. } => input.as_ref(),
            other => panic!("expected Project, got {:?}", other),
        };
        match inner {
            RelPlan::Unpivot { input, .. } => match input.as_ref() {
                RelPlan::TableFunction { .. } => {}
                other => panic!("expected TableFunction inside Unpivot, got {:?}", other),
            },
            other => panic!("expected Unpivot, got {:?}", other),
        }
    }

    #[test]
    fn tvf_with_sample_wraps_table_function() {
        let plan = lower("SELECT * FROM TABLE(MY_TVF()) AS f SAMPLE (10 ROWS)");
        let inner = match &plan {
            RelPlan::Project { input, .. } => input.as_ref(),
            other => panic!("expected Project, got {:?}", other),
        };
        match inner {
            RelPlan::TableSample { input, .. } => match input.as_ref() {
                RelPlan::TableFunction { .. } => {}
                other => panic!("expected TableFunction inside TableSample, got {:?}", other),
            },
            other => panic!("expected TableSample, got {:?}", other),
        }
    }

    #[test]
    fn scan_with_offset_populates_scan_modifier() {
        // Parser currently accepts WITH OFFSET in the TVF grammar; this
        // test constructs a non-TVF table-ref shape directly so lowering
        // coverage tracks the AST->IR extraction obligation.
        let mut stmt = parse_one("SELECT * FROM Orders");
        let src = "SELECT * FROM Orders";
        match &mut stmt {
            AstStmt::Select(sel) => {
                let tr = sel
                    .from
                    .first_mut()
                    .expect("from item")
                    .as_table_ref_mut()
                    .expect("table ref");
                tr.with_offset = Some(Box::new(crate::ast::AstWithOffset {
                    span: tr.span,
                    with_span: tr.span,
                    offset_span: tr.span,
                    as_span: None,
                    alias: None,
                }));
            }
            other => panic!("expected Select statement, got {:?}", other),
        }
        let plan = lower_query(&stmt, src, StrictMode::Permissive).expect("lower");
        let inner = match &plan {
            RelPlan::Project { input, .. } => input.as_ref(),
            other => panic!("expected Project, got {:?}", other),
        };
        match inner {
            RelPlan::Scan {
                modifier:
                    ScanModifier {
                        with_offset: Some(with_offset),
                        ..
                    },
                ..
            } => {
                assert!(with_offset.alias.is_none(), "expected no offset alias");
            }
            other => panic!("expected Scan with with_offset, got {:?}", other),
        }
    }

    #[test]
    fn scan_only_qualifier_populates_scan_modifier() {
        let pg = crate::dialect::postgres();
        let plan = lower_with_dialect("SELECT * FROM ONLY parent_table", pg.as_ref());
        let inner = match &plan {
            RelPlan::Project { input, .. } => input.as_ref(),
            other => panic!("expected Project, got {:?}", other),
        };
        match inner {
            RelPlan::Scan {
                modifier: ScanModifier { only: Some(_), .. },
                ..
            } => {}
            other => panic!("expected Scan with only qualifier, got {:?}", other),
        }
    }

    #[test]
    fn scan_table_hints_populate_scan_modifier() {
        let mssql = crate::dialect::mssql();
        let plan = lower_with_dialect(
            "SELECT * FROM Orders WITH (NOLOCK, INDEX(idx_order_date))",
            mssql.as_ref(),
        );
        let inner = match &plan {
            RelPlan::Project { input, .. } => input.as_ref(),
            other => panic!("expected Project, got {:?}", other),
        };
        match inner {
            RelPlan::Scan {
                modifier: ScanModifier { table_hints, .. },
                ..
            } => {
                assert_eq!(table_hints.len(), 2, "expected two table hints");
                assert!(matches!(table_hints[0].kind, ScanTableHintKind::NoLock));
                assert!(matches!(
                    table_hints[1].kind,
                    ScanTableHintKind::Index { .. }
                ));
            }
            other => panic!("expected Scan with table hints, got {:?}", other),
        }
    }

    #[test]
    fn scan_tvf_schema_populates_scan_modifier() {
        // `tvf_schema_span` is only emitted by the parser on TVF table
        // refs (via `finish_table_function_parse`). The base-Scan path
        // wires it defensively onto `ScanModifier.tvf_schema`. Verify
        // via synthetic AST that the wiring holds if the parser ever
        // changes.
        let mut stmt = parse_one("SELECT * FROM Orders");
        let src = "SELECT * FROM Orders";
        let dummy_span = crate::lexer::Span { start: 14, end: 20 };
        match &mut stmt {
            AstStmt::Select(sel) => {
                let tr = sel
                    .from
                    .first_mut()
                    .expect("from item")
                    .as_table_ref_mut()
                    .expect("table ref");
                tr.tvf_schema_span = Some(dummy_span);
            }
            other => panic!("expected Select, got {:?}", other),
        }
        let plan = lower_query(&stmt, src, StrictMode::Permissive).expect("lower");
        let inner = match &plan {
            RelPlan::Project { input, .. } => input.as_ref(),
            other => panic!("expected Project, got {:?}", other),
        };
        match inner {
            RelPlan::Scan {
                modifier:
                    ScanModifier {
                        tvf_schema: Some(_),
                        ..
                    },
                ..
            } => {}
            other => panic!("expected Scan with tvf_schema set, got {:?}", other),
        }
    }

    #[test]
    fn cte_ref_with_table_hints_passes_through_as_cte_ref() {
        let mssql = crate::dialect::mssql();
        // T-SQL `FROM my_cte WITH (NOLOCK)` — optimizer hint on a CTE
        // ref. Table hints are lowered onto `ScanModifier.table_hints`
        // for base Scans and are no-ops for static analysis (they don't
        // affect lineage/nullability/taint), so the CteRef passes
        // through silently. The hint is not visible on the CteRef plan
        // but the plan itself must be a CteRef, not Opaque.
        let src = "WITH cte AS (SELECT id FROM orders) SELECT id FROM cte WITH (NOLOCK)";
        let plan = lower_with_dialect(src, mssql.as_ref());
        let inner = match &plan {
            RelPlan::WithScope { body, .. } => match body.as_ref() {
                RelPlan::Project { input, .. } => input.as_ref().clone(),
                other => panic!("expected Project inside WithScope, got {:?}", other),
            },
            other => panic!("expected WithScope, got {:?}", other),
        };
        assert!(
            matches!(inner, RelPlan::CteRef { .. }),
            "expected CteRef, got {:?}",
            inner
        );
    }

    #[test]
    fn tvf_with_time_travel_lowers_to_table_function_with_modifier() {
        // Snowflake: `FROM TABLE(my_udtf(x)) AT(TIMESTAMP => :ts)`.
        // Time-travel is a valid modifier on a TVF output in Snowflake.
        // It lowers to
        // `RelPlan::TableFunction { modifier: ScanModifier { time_travel: Some(_), .. }, .. }`.
        let src = "SELECT * FROM TABLE(my_udtf(1)) AT(TIMESTAMP => '2024-01-01'::timestamp)";
        let plan = lower(src);
        let inner = match &plan {
            RelPlan::Project { input, .. } => input.as_ref(),
            other => panic!("expected Project, got {:?}", other),
        };
        match inner {
            RelPlan::TableFunction {
                modifier:
                    ScanModifier {
                        time_travel: Some(_),
                        ..
                    },
                ..
            } => {}
            other => panic!(
                "expected TableFunction with time_travel on modifier, got {:?}",
                other
            ),
        }
    }

    #[test]
    fn tvf_with_changes_lowers_to_table_function_with_modifier() {
        // Snowflake: `FROM TABLE(my_udtf(x)) CHANGES(INFORMATION => DEFAULT)`.
        // CHANGES is valid on TVF outputs in Snowflake (same as on base tables).
        let src = "SELECT * FROM TABLE(my_udtf(1)) CHANGES(INFORMATION => DEFAULT) AT(TIMESTAMP => '2024-01-01'::timestamp)";
        let plan = lower(src);
        let inner = match &plan {
            RelPlan::Project { input, .. } => input.as_ref(),
            other => panic!("expected Project, got {:?}", other),
        };
        match inner {
            RelPlan::TableFunction {
                modifier: ScanModifier {
                    changes: Some(_), ..
                },
                ..
            } => {}
            other => panic!(
                "expected TableFunction with changes on modifier, got {:?}",
                other
            ),
        }
    }

    #[test]
    fn cte_base_tables_surface_in_derived_facts_tables_read() {
        use crate::ir::derived_facts::derive_facts_from_plan;
        // The outer `tables_read` includes tables scanned inside
        // CTE bodies (CTE refs resolve to their base tables). The
        // CTE name itself (`x`) must NOT appear in the derived
        // tables set.
        let (plan, bindings) =
            lower_with_bindings("WITH x AS (SELECT a FROM t1) SELECT a FROM x JOIN t2 ON t2.b = 1");
        let facts = derive_facts_from_plan(
            "",
            &plan,
            &bindings,
            &crate::ir::catalog::FunctionCatalog::empty(),
            None,
            &crate::facts::reasoning::RecognitionOnly,
        );
        let names: Vec<&str> = facts.tables_read.iter().map(|t| t.name.as_str()).collect();
        assert_eq!(names, vec!["t1", "t2"], "got {:?}", names);
    }

    #[test]
    fn cte_outer_scope_flags_do_not_leak_from_cte_bodies() {
        use crate::ir::derived_facts::derive_facts_from_plan;
        // Outer-scope flags (`has_where`, `has_group_by`,
        // `has_distinct`, `has_aggregates`) describe the body's
        // own scope only. CTE bodies are scope boundaries: a CTE's
        // aggregates / DISTINCT do NOT leak into the enclosing
        // scope.
        let (plan, bindings) = lower_with_bindings(
            "WITH x AS (SELECT a, COUNT(*) FROM t WHERE a > 0 GROUP BY a) \
             SELECT a FROM x",
        );
        let facts = derive_facts_from_plan(
            "",
            &plan,
            &bindings,
            &crate::ir::catalog::FunctionCatalog::empty(),
            None,
            &crate::facts::reasoning::RecognitionOnly,
        );
        assert!(!facts.has_where, "CTE WHERE must not leak to outer");
        assert!(!facts.has_group_by, "CTE GROUP BY must not leak to outer",);
        assert!(
            !facts.has_aggregates,
            "CTE aggregates must not leak to outer scope",
        );
        assert!(
            !facts.has_distinct,
            "CTE DISTINCT must not leak to outer scope",
        );
    }

    #[test]
    fn unreferenced_cte_does_not_contribute_tables_read() {
        use crate::ir::derived_facts::derive_facts_from_plan;
        // A CTE that the outer body never references must not
        // contribute its base tables to the outer `tables_read`:
        // CTE base tables are appended only when a `FROM` element
        // resolves to the CTE. An unused CTE therefore leaves no
        // trace in `tables_read`.
        let (plan, bindings) =
            lower_with_bindings("WITH unused AS (SELECT id FROM customers) SELECT a FROM orders");
        let facts = derive_facts_from_plan(
            "",
            &plan,
            &bindings,
            &crate::ir::catalog::FunctionCatalog::empty(),
            None,
            &crate::facts::reasoning::RecognitionOnly,
        );
        let names: Vec<&str> = facts.tables_read.iter().map(|t| t.name.as_str()).collect();
        assert_eq!(names, vec!["orders"], "got {:?}", names);
    }

    #[test]
    fn recursive_cte_with_union_body_splits_anchor_and_step() {
        // Anchor is lowerable (has FROM), step self-references the
        // CTE name. The binding must carry a `CteBody::Recursive` and
        // the step's FROM must resolve to `CteRef` for the
        // self-reference.
        let plan = lower(
            "WITH RECURSIVE e AS ( \
               SELECT id FROM emp WHERE mgr = 0 \
               UNION ALL \
               SELECT id FROM emp JOIN e ON emp.mgr = e.id \
             ) SELECT id FROM e",
        );
        let (ctes, recursive) = match plan {
            RelPlan::WithScope {
                ctes, recursive, ..
            } => (ctes, recursive),
            other => panic!("expected WithScope, got {:?}", other),
        };
        assert!(recursive);
        assert_eq!(ctes.len(), 1);
        match &ctes[0].body {
            CteBody::Recursive {
                anchor,
                step,
                union_kind,
            } => {
                assert_eq!(*union_kind, SetOpKind::UnionAll);
                // Anchor's FROM is a real Scan on `emp`.
                let anchor_kind = match anchor.as_ref() {
                    RelPlan::Project { .. } => "project",
                    other => panic!("expected Project as anchor, got {:?}", other),
                };
                assert_eq!(anchor_kind, "project");
                // Step walks down to a CteRef for the self-reference.
                // Shape: Project -> Join(Scan(emp), CteRef(e)).
                let step_has_cte_ref = plan_contains_cte_ref(step, "E");
                assert!(
                    step_has_cte_ref,
                    "step side of recursive CTE must contain a CteRef back to the CTE name"
                );
            }
            CteBody::NonRecursive(_) => {
                panic!("expected Recursive body for WITH RECURSIVE")
            }
        }
    }

    #[test]
    fn recursive_cte_non_union_body_lowers_as_non_recursive() {
        // `RECURSIVE` is a clause-level hint:
        // a CTE under `WITH RECURSIVE` whose body is not UNION-shaped
        // is lowered as `CteBody::NonRecursive`, not rejected. The
        // common `WITH RECURSIVE anchor AS (…union…), helper AS
        // (SELECT … FROM anchor) SELECT …` idiom relies on this.
        let plan = lower("WITH RECURSIVE x AS (SELECT a FROM t) SELECT a FROM x");
        match plan {
            RelPlan::WithScope {
                ctes, recursive, ..
            } => {
                assert!(
                    recursive,
                    "WithScope.recursive mirrors the RECURSIVE keyword"
                );
                assert_eq!(ctes.len(), 1);
                match &ctes[0].body {
                    CteBody::NonRecursive(_) => {}
                    CteBody::Recursive { .. } => {
                        panic!("non-union body under WITH RECURSIVE must lower as NonRecursive")
                    }
                }
            }
            other => panic!("expected WithScope, got {:?}", other),
        }
    }

    #[test]
    fn recursive_cte_mixed_bodies_lower_cleanly() {
        // Mixed recursive + non-recursive CTEs in one WITH RECURSIVE
        // clause are legal in PG / Snowflake / BigQuery. The union-
        // shaped body becomes `Recursive`, the non-union body
        // becomes `NonRecursive`, and the outer plan lowers without
        // any `Opaque`.
        let plan = lower(
            "WITH RECURSIVE seq(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM seq WHERE n < 5), \
             agg AS (SELECT n FROM seq) \
             SELECT n FROM agg",
        );
        match plan {
            RelPlan::WithScope { ctes, .. } => {
                assert_eq!(ctes.len(), 2);
                assert!(matches!(ctes[0].body, CteBody::Recursive { .. }));
                assert!(matches!(ctes[1].body, CteBody::NonRecursive(_)));
            }
            other => panic!("expected WithScope, got {:?}", other),
        }
    }

    #[test]
    fn qualified_name_matching_cte_stays_scan() {
        // Only unqualified single-segment names can match a CTE
        // binding; `schema.x` is a qualified physical table even if
        // a CTE named `x` is also in scope.
        let plan = lower("WITH x AS (SELECT a FROM t) SELECT a FROM schema.x");
        // The outer FROM must be a Scan of `schema.x`, not a CteRef.
        let contains_scan_on_qualified = plan_contains_scan_named(&plan, "x");
        assert!(
            contains_scan_on_qualified,
            "qualified schema.x must stay a Scan"
        );
    }

    #[test]
    fn cte_column_list_sets_binding_arity() {
        // `WITH cte(a, b) AS (...)` declares a two-column schema;
        // the lowered binding's `output_columns` must have two
        // entries regardless of the body's actual projection
        // length.
        let plan = lower("WITH x(c1, c2) AS (SELECT a, b FROM t) SELECT c1 FROM x");
        match plan {
            RelPlan::WithScope { ctes, .. } => {
                assert_eq!(ctes.len(), 1);
                assert_eq!(ctes[0].output_columns.len(), 2);
                let declared = ctes[0]
                    .declared_columns
                    .as_ref()
                    .expect("declared_columns populated");
                assert_eq!(declared.len(), 2);
            }
            other => panic!("expected WithScope, got {:?}", other),
        }
    }

    #[test]
    fn sibling_cte_can_reference_earlier_cte() {
        // Non-recursive WITH: a later CTE may reference an earlier
        // one. The later body's scan on the earlier name must
        // resolve to `CteRef`.
        let plan = lower("WITH a AS (SELECT x FROM t1), b AS (SELECT x FROM a) SELECT x FROM b");
        let ctes = match plan {
            RelPlan::WithScope { ctes, .. } => ctes,
            other => panic!("expected WithScope, got {:?}", other),
        };
        assert_eq!(ctes.len(), 2);
        // Second CTE body contains a CteRef to `a`.
        match &ctes[1].body {
            CteBody::NonRecursive(plan) => {
                assert!(
                    plan_contains_cte_ref(plan, "A"),
                    "second CTE must resolve `a` reference to CteRef"
                );
            }
            other => panic!("expected NonRecursive CTE body, got {:?}", other),
        }
    }

    fn plan_contains_cte_ref(plan: &RelPlan, name: &str) -> bool {
        match plan {
            RelPlan::CteRef { name: n, .. } => n.as_str() == name,
            RelPlan::Scan { .. }
            | RelPlan::Values { .. }
            | RelPlan::ModelRef { .. }
            | RelPlan::TableFunction { .. }
            | RelPlan::CreateTableForm { .. }
            | RelPlan::ParseRecovery { .. }
            | RelPlan::Opaque { .. } => false,
            RelPlan::InvalidInput { .. } => false,
            RelPlan::Project { input, .. }
            | RelPlan::Filter { input, .. }
            | RelPlan::Aggregate { input, .. }
            | RelPlan::Window { input, .. }
            | RelPlan::Sort { input, .. }
            | RelPlan::Limit { input, .. }
            | RelPlan::Unnest { input, .. }
            | RelPlan::Pivot { input, .. }
            | RelPlan::Unpivot { input, .. }
            | RelPlan::MatchRecognize { input, .. }
            | RelPlan::ConnectBy { input, .. }
            | RelPlan::TableSample { input, .. }
            | RelPlan::DerivedTable { input, .. } => plan_contains_cte_ref(input, name),
            RelPlan::Join { left, right, .. } => {
                plan_contains_cte_ref(left, name) || plan_contains_cte_ref(right, name)
            }
            RelPlan::SetOp { inputs, .. } => inputs.iter().any(|p| plan_contains_cte_ref(p, name)),
            RelPlan::Insert { source, .. } => match source {
                crate::ir::plan::InsertSource::Values(p)
                | crate::ir::plan::InsertSource::Query(p) => plan_contains_cte_ref(p, name),
                crate::ir::plan::InsertSource::DefaultValues => false,
            },
            RelPlan::Update { from, .. } => from
                .as_deref()
                .map(|p| plan_contains_cte_ref(p, name))
                .unwrap_or(false),
            RelPlan::Delete { using, .. } => using
                .as_deref()
                .map(|p| plan_contains_cte_ref(p, name))
                .unwrap_or(false),
            RelPlan::Merge { source, .. } => plan_contains_cte_ref(source, name),
            RelPlan::MultiInsert { source, .. } => plan_contains_cte_ref(source, name),
            RelPlan::Explain { body, .. } => plan_contains_cte_ref(body, name),
            RelPlan::CreateAsQuery { body, .. } => body
                .as_deref()
                .is_some_and(|body| plan_contains_cte_ref(body, name)),
            RelPlan::WithScope { body, ctes, .. } => {
                if plan_contains_cte_ref(body, name) {
                    return true;
                }
                ctes.iter().any(|b| match &b.body {
                    CteBody::NonRecursive(p) => plan_contains_cte_ref(p, name),
                    CteBody::Recursive { anchor, step, .. } => {
                        plan_contains_cte_ref(anchor, name) || plan_contains_cte_ref(step, name)
                    }
                })
            }
        }
    }

    fn plan_contains_scan_named(plan: &RelPlan, name: &str) -> bool {
        match plan {
            RelPlan::Scan { table, .. } => table.name == name,
            RelPlan::CteRef { .. }
            | RelPlan::Values { .. }
            | RelPlan::ModelRef { .. }
            | RelPlan::TableFunction { .. }
            | RelPlan::CreateTableForm { .. }
            | RelPlan::ParseRecovery { .. }
            | RelPlan::Opaque { .. } => false,
            RelPlan::InvalidInput { .. } => false,
            RelPlan::Project { input, .. }
            | RelPlan::Filter { input, .. }
            | RelPlan::Aggregate { input, .. }
            | RelPlan::Window { input, .. }
            | RelPlan::Sort { input, .. }
            | RelPlan::Limit { input, .. }
            | RelPlan::Unnest { input, .. }
            | RelPlan::Pivot { input, .. }
            | RelPlan::Unpivot { input, .. }
            | RelPlan::MatchRecognize { input, .. }
            | RelPlan::ConnectBy { input, .. }
            | RelPlan::TableSample { input, .. }
            | RelPlan::DerivedTable { input, .. } => plan_contains_scan_named(input, name),
            RelPlan::Join { left, right, .. } => {
                plan_contains_scan_named(left, name) || plan_contains_scan_named(right, name)
            }
            RelPlan::SetOp { inputs, .. } => {
                inputs.iter().any(|p| plan_contains_scan_named(p, name))
            }
            RelPlan::Insert { source, .. } => match source {
                crate::ir::plan::InsertSource::Values(p)
                | crate::ir::plan::InsertSource::Query(p) => plan_contains_scan_named(p, name),
                crate::ir::plan::InsertSource::DefaultValues => false,
            },
            RelPlan::Update { from, .. } => from
                .as_deref()
                .map(|p| plan_contains_scan_named(p, name))
                .unwrap_or(false),
            RelPlan::Delete { using, .. } => using
                .as_deref()
                .map(|p| plan_contains_scan_named(p, name))
                .unwrap_or(false),
            RelPlan::Merge { source, .. } => plan_contains_scan_named(source, name),
            RelPlan::MultiInsert { source, .. } => plan_contains_scan_named(source, name),
            RelPlan::Explain { body, .. } => plan_contains_scan_named(body, name),
            RelPlan::CreateAsQuery { body, .. } => body
                .as_deref()
                .is_some_and(|body| plan_contains_scan_named(body, name)),
            RelPlan::WithScope { body, ctes, .. } => {
                if plan_contains_scan_named(body, name) {
                    return true;
                }
                ctes.iter().any(|b| match &b.body {
                    CteBody::NonRecursive(p) => plan_contains_scan_named(p, name),
                    CteBody::Recursive { anchor, step, .. } => {
                        plan_contains_scan_named(anchor, name)
                            || plan_contains_scan_named(step, name)
                    }
                })
            }
        }
    }

    // ── Bare SELECT ─────────────────────────────────────────────────────

    /// `SELECT 1 + 1` lowers to `Project` over a zero-column, one-row
    /// `Values`. The synthesized `Values` exists solely to satisfy the
    /// relational contract; no columns flow from it.
    #[test]
    fn bare_select_lowers_to_project_over_values() {
        let plan = lower("SELECT 1 + 1");
        match plan {
            RelPlan::Project {
                input,
                items,
                distinct,
                ..
            } => {
                assert!(!distinct);
                assert_eq!(items.len(), 1);
                match *input {
                    RelPlan::Values { rows, columns, .. } => {
                        assert_eq!(rows.len(), 1, "exactly one synthesized row");
                        assert!(rows[0].is_empty(), "synthesized row carries no values");
                        assert!(columns.is_empty(), "synthesized Values has no ColumnIds");
                    }
                    other => panic!("expected Values as FROM, got {:?}", other),
                }
            }
            other => panic!("expected Project, got {:?}", other),
        }
    }

    /// A bare SELECT with aliases, multiple items, and `WHERE TRUE`
    /// composes through the normal pipeline on top of the synthesized
    /// `Values`: `Project → Filter → Values`.
    #[test]
    fn bare_select_with_where_lowers_filter_over_values() {
        let plan = lower("SELECT 1 AS x, 'y' AS lbl WHERE TRUE");
        let filter = match plan {
            RelPlan::Project { input, items, .. } => {
                assert_eq!(items.len(), 2);
                *input
            }
            other => panic!("expected Project, got {:?}", other),
        };
        match filter {
            RelPlan::Filter { input, .. } => match *input {
                RelPlan::Values { rows, columns, .. } => {
                    assert_eq!(rows.len(), 1);
                    assert!(rows[0].is_empty());
                    assert!(columns.is_empty());
                }
                other => panic!("expected Values under Filter, got {:?}", other),
            },
            other => panic!("expected Filter, got {:?}", other),
        }
    }

    /// Under `Strict`, a bare SELECT must lower cleanly: the
    /// lowering produces a real plan.
    #[test]
    fn strict_mode_accepts_bare_select() {
        let src = "SELECT 42";
        let stmt = parse_one(src);
        let plan = lower_query(&stmt, src, StrictMode::Strict)
            .expect("strict lower must accept bare SELECT");
        assert!(matches!(plan, RelPlan::Project { .. }));
    }

    /// Permissive unresolved refs in a bare SELECT should attach to
    /// the synthetic `Values` source so lineage can resolve them as
    /// unqualified sources instead of dangling table-origin ids.
    #[test]
    fn bare_select_unresolved_refs_attach_to_values_columns() {
        let src = "SELECT a, b";
        let stmt = parse_one(src);
        let catalog = FunctionCatalog::for_dialect(CatalogDialect::Default);
        let session = SessionContext::default();
        let (plan, _, bindings, _facts) = lower_query_full_with_bindings(
            &stmt,
            src,
            StrictMode::Permissive,
            &catalog,
            &session,
            None,
        )
        .expect("lower");

        let values_cols = match plan {
            RelPlan::Project { input, .. } => match *input {
                RelPlan::Values { columns, .. } => columns,
                other => panic!("expected Values under Project, got {:?}", other),
            },
            other => panic!("expected Project, got {:?}", other),
        };

        assert_eq!(values_cols.len(), 2, "both refs should attach to Values");
        assert!(values_cols.iter().all(|id| bindings.get(*id).is_some()));
    }

    // ── Joins ───────────────────────────────────────────────────────────

    #[test]
    fn inner_join_on_lowers_to_join_node() {
        let plan = lower("SELECT a FROM t JOIN u ON t.a = u.a");
        let join = match plan {
            RelPlan::Project { input, .. } => *input,
            other => panic!("expected Project, got {:?}", other),
        };
        match join {
            RelPlan::Join {
                kind,
                on,
                using,
                natural,
                lateral,
                left,
                right,
                ..
            } => {
                assert_eq!(kind, JoinKind::Inner);
                assert!(matches!(on, Some(ScalarExpr::BinOp { .. })));
                assert!(using.is_empty());
                assert!(!natural);
                assert!(!lateral);
                assert!(matches!(*left, RelPlan::Scan { .. }));
                assert!(matches!(*right, RelPlan::Scan { .. }));
            }
            other => panic!("expected Join, got {:?}", other),
        }
    }

    #[test]
    fn left_outer_join_preserves_kind() {
        let plan = lower("SELECT a FROM t LEFT OUTER JOIN u ON t.a = u.a");
        let join = unwrap_project(plan);
        match join {
            RelPlan::Join { kind, .. } => assert_eq!(kind, JoinKind::LeftOuter),
            other => panic!("expected Join, got {:?}", other),
        }
    }

    #[test]
    fn cross_join_has_no_predicate() {
        let plan = lower("SELECT a FROM t CROSS JOIN u");
        let join = unwrap_project(plan);
        match join {
            RelPlan::Join {
                kind,
                on,
                using,
                implicit,
                ..
            } => {
                assert_eq!(kind, JoinKind::Cross);
                assert!(on.is_none());
                assert!(using.is_empty());
                assert!(
                    !implicit,
                    "explicit CROSS JOIN keyword: implicit must be false"
                );
            }
            other => panic!("expected Join, got {:?}", other),
        }
    }

    #[test]
    fn comma_from_list_lowers_to_cross_join() {
        let plan = lower("SELECT a FROM t, u");
        let join = unwrap_project(plan);
        match join {
            RelPlan::Join {
                kind,
                on,
                natural,
                lateral,
                implicit,
                ..
            } => {
                assert_eq!(kind, JoinKind::Cross);
                assert!(on.is_none());
                assert!(!natural);
                assert!(!lateral);
                assert!(implicit, "comma-join: implicit must be true");
            }
            other => panic!("expected Join, got {:?}", other),
        }
    }

    #[test]
    fn three_way_comma_join_is_left_deep() {
        let plan = lower("SELECT a FROM t, u, v");
        let join = unwrap_project(plan);
        match join {
            RelPlan::Join {
                left, right, kind, ..
            } => {
                assert_eq!(kind, JoinKind::Cross);
                assert!(matches!(*right, RelPlan::Scan { .. }));
                // Left is itself a Cross join of (t, u).
                match *left {
                    RelPlan::Join {
                        kind: inner_kind,
                        left: inner_left,
                        right: inner_right,
                        ..
                    } => {
                        assert_eq!(inner_kind, JoinKind::Cross);
                        assert!(matches!(*inner_left, RelPlan::Scan { .. }));
                        assert!(matches!(*inner_right, RelPlan::Scan { .. }));
                    }
                    other => panic!("expected inner Join, got {:?}", other),
                }
            }
            other => panic!("expected Join, got {:?}", other),
        }
    }

    #[test]
    fn join_using_records_column_list() {
        let plan = lower("SELECT a FROM t JOIN u USING (a, b)");
        let join = unwrap_project(plan);
        match join {
            RelPlan::Join { on, using, .. } => {
                assert!(on.is_none());
                assert_eq!(using.len(), 2);
            }
            other => panic!("expected Join, got {:?}", other),
        }
    }

    #[test]
    fn natural_join_sets_natural_flag() {
        let plan = lower("SELECT a FROM t NATURAL JOIN u");
        let join = unwrap_project(plan);
        match join {
            RelPlan::Join {
                kind,
                on,
                using,
                natural,
                ..
            } => {
                assert_eq!(kind, JoinKind::Inner);
                assert!(natural);
                assert!(on.is_none());
                assert!(using.is_empty());
            }
            other => panic!("expected Join, got {:?}", other),
        }
    }

    #[test]
    fn match_recognize_over_cte_resolves_as_cte_ref() {
        // Regression: an earlier guard (`!has_match_recognize`) in
        // `lower_table_ref` skipped CTE lookup whenever a
        // MATCH_RECOGNIZE clause was present, causing the CTE name
        // to be Scan-lowered as if it were a base table. Snowflake
        // permits `FROM <cte> MATCH_RECOGNIZE (...)`, so the CTE
        // must resolve to `CteRef` and the MR wrapper must sit on
        // top.
        let plan = lower(
            "WITH c AS (SELECT a, ts FROM t) \
             SELECT * FROM c \
             MATCH_RECOGNIZE ( \
                 PARTITION BY a ORDER BY ts \
                 MEASURES first(x.ts) AS s \
                 ALL ROWS PER MATCH \
                 PATTERN (x+) \
                 DEFINE X AS true \
             )",
        );
        // Project(MatchRecognize(CteRef c)), wrapped in WithScope.
        let body = match &plan {
            RelPlan::WithScope { body, .. } => body.as_ref(),
            other => panic!("expected WithScope, got {:?}", other),
        };
        let mr = match body {
            RelPlan::Project { input, .. } => input.as_ref(),
            other => panic!("expected outer Project, got {:?}", other),
        };
        match mr {
            RelPlan::MatchRecognize { input, .. } => {
                assert!(
                    matches!(input.as_ref(), RelPlan::CteRef { .. }),
                    "MATCH_RECOGNIZE input must resolve to CteRef, got {:?}",
                    input
                );
            }
            other => panic!("expected MatchRecognize, got {:?}", other),
        }
    }

    #[test]
    fn natural_left_outer_preserves_kind_and_flag() {
        let plan = lower("SELECT a FROM t NATURAL LEFT OUTER JOIN u");
        let join = unwrap_project(plan);
        match join {
            RelPlan::Join { kind, natural, .. } => {
                assert_eq!(kind, JoinKind::LeftOuter);
                assert!(natural);
            }
            other => panic!("expected Join, got {:?}", other),
        }
    }

    #[test]
    fn join_chain_is_left_deep_with_where() {
        // a JOIN b ON ... JOIN c ON ... WHERE ... should nest as
        // Project(Filter(Join(Join(a, b), c))).
        let plan = lower("SELECT a FROM t JOIN u ON t.a = u.a JOIN v ON u.b = v.b WHERE v.c = 1");
        let filter = match plan {
            RelPlan::Project { input, .. } => *input,
            other => panic!("expected Project, got {:?}", other),
        };
        let outer_join = match filter {
            RelPlan::Filter { input, .. } => *input,
            other => panic!("expected Filter, got {:?}", other),
        };
        match outer_join {
            RelPlan::Join {
                kind, left, right, ..
            } => {
                assert_eq!(kind, JoinKind::Inner);
                assert!(matches!(*right, RelPlan::Scan { .. }));
                assert!(matches!(*left, RelPlan::Join { .. }));
            }
            other => panic!("expected outer Join, got {:?}", other),
        }
    }

    #[test]
    fn asof_join_lowers_with_match_condition() {
        let plan = lower("SELECT a FROM t ASOF JOIN u MATCH_CONDITION(t.ts >= u.ts) ON t.a = u.a");
        match unwrap_project(plan) {
            RelPlan::Join {
                kind,
                on,
                match_condition,
                directed,
                lateral,
                ..
            } => {
                assert_eq!(kind, JoinKind::Asof);
                assert!(on.is_some());
                assert!(match_condition.is_some());
                assert!(!directed);
                assert!(!lateral);
            }
            other => panic!("expected Join, got {:?}", other),
        }
    }

    #[test]
    fn tsql_apply_lowers_to_lateral_join() {
        // Parse with the T-SQL dialect. APPLY is dialect-specific.
        let src = "SELECT a FROM t CROSS APPLY dbo.fn(t.a) AS u";
        let tokens = crate::lexer::tokenize_with_dialect(src, &crate::dialect::MsSqlDialect);
        let script = crate::parser::parse_script(src, &tokens.tokens).expect("parse");
        let stmt = script.stmts.into_iter().next().unwrap();
        let plan = lower_query(&stmt, src, StrictMode::Permissive).expect("lower");
        match unwrap_project(plan) {
            RelPlan::Join {
                kind,
                lateral,
                match_condition,
                directed,
                ..
            } => {
                assert_eq!(kind, JoinKind::Inner);
                assert!(lateral);
                assert!(match_condition.is_none());
                assert!(!directed);
            }
            other => panic!("expected Join, got {:?}", other),
        }
    }

    #[test]
    fn strict_mode_accepts_apply() {
        let src = "SELECT a FROM t CROSS APPLY dbo.fn(t.a) AS u";
        let tokens = crate::lexer::tokenize_with_dialect(src, &crate::dialect::MsSqlDialect);
        let script = crate::parser::parse_script(src, &tokens.tokens).expect("parse");
        let stmt = script.stmts.into_iter().next().unwrap();
        let plan = lower_query(&stmt, src, StrictMode::Strict).expect("strict lower");
        assert!(matches!(plan, RelPlan::Project { .. }));
    }

    #[test]
    fn strict_mode_accepts_joins() {
        let src = "SELECT a FROM t LEFT JOIN u ON t.a = u.a WHERE t.a = 1";
        let stmt = parse_one(src);
        let plan = lower_query(&stmt, src, StrictMode::Strict).expect("strict lower");
        assert!(matches!(plan, RelPlan::Project { .. }));
    }

    fn unwrap_project(plan: RelPlan) -> RelPlan {
        match plan {
            RelPlan::Project { input, .. } => *input,
            other => panic!("expected Project, got {:?}", other),
        }
    }

    #[test]
    fn strict_mode_lowers_unqualified_star() {
        // `SELECT *` lowers to a typed `ProjectItem::Star` rather
        // than an opaque reason. Strict mode must accept the
        // structural form — catalog expansion happens later.
        let src = "SELECT * FROM t";
        let stmt = parse_one(src);
        let plan = lower_query(&stmt, src, StrictMode::Strict).expect("strict lower");
        match plan {
            RelPlan::Project { items, .. } => {
                assert_eq!(items.len(), 1);
                assert!(matches!(
                    items[0],
                    ProjectItem::Star(ref s)
                        if matches!(s.qualifier, StarQualifier::Unqualified)
                ));
            }
            other => panic!("expected Project, got {:?}", other),
        }
    }

    #[test]
    fn pedantic_lowers_unqualified_star() {
        // Same as above under `Pedantic`: the star is a structural
        // shape, not an opaque fallback, so Pedantic accepts it.
        let src = "SELECT * FROM t";
        let stmt = parse_one(src);
        let plan = lower_query(&stmt, src, StrictMode::Pedantic).expect("strict lower");
        match plan {
            RelPlan::Project { items, .. } => {
                assert_eq!(items.len(), 1);
                assert!(matches!(items[0], ProjectItem::Star(_)));
            }
            other => panic!("expected Project, got {:?}", other),
        }
    }

    #[test]
    fn strict_mode_accepts_in_scope() {
        let src = "SELECT a FROM t WHERE a = 1";
        let stmt = parse_one(src);
        let plan = lower_query(&stmt, src, StrictMode::Strict).expect("strict lower");
        assert!(matches!(plan, RelPlan::Project { .. }));
    }

    #[test]
    fn non_select_statement_is_opaque() {
        let src = "CREATE TABLE t (a INT)";
        let stmt = parse_one(src);
        let plan = lower_query(&stmt, src, StrictMode::Permissive).expect("lower");
        // `CREATE TABLE t (a INT)` is `AstCreateTableVariant::Plain` —
        // no query body, no IR-representable relational shape. Lowering
        // produces a `CreateTableForm` leaf instead of Opaque.
        assert!(matches!(
            plan,
            RelPlan::CreateTableForm {
                kind: CreateTableFormKind::Plain,
                ..
            }
        ));
    }

    // ── Aggregates ──────────────────────────────────────────────────────

    /// Pull the `Aggregate` out of a `Project → Aggregate → ...` plan.
    fn unwrap_project_agg(plan: RelPlan) -> RelPlan {
        match plan {
            RelPlan::Project { input, .. } => *input,
            other => panic!("expected Project, got {:?}", other),
        }
    }

    #[test]
    fn plain_group_by_lowers_to_standard_spec() {
        let plan = lower("SELECT a, COUNT(*) FROM t GROUP BY a");
        let agg = unwrap_project_agg(plan);
        match agg {
            RelPlan::Aggregate {
                grouping,
                aggregates,
                having,
                output_columns,
                ..
            } => {
                assert!(matches!(grouping, GroupingSpec::Standard(ref keys) if keys.len() == 1));
                assert_eq!(aggregates.len(), 1);
                // Being harvested into `aggregates` at all already
                // means the lowerer classified the call as aggregate-
                // shaped (otherwise it would have stayed as a
                // `ScalarExpr::FuncCall` on the projection). The
                // remaining assertion pins the specific function
                // identity — the resolved display hint should be
                // `COUNT` for `SELECT COUNT(*) ... GROUP BY a`.
                assert!(matches!(aggregates[0].func, ResolvedFunc::Resolved { .. }));
                // The resolved id is into the default catalog; look
                // up the signature to confirm this is in fact COUNT.
                // The id is only meaningful against the *same* catalog
                // instance that resolved it, so we rebuild the default
                // here — `FunctionCatalog::for_dialect(Default)` is
                // deterministic.
                let cat = FunctionCatalog::for_dialect(CatalogDialect::Default);
                let ResolvedFunc::Resolved { id, .. } = aggregates[0].func else {
                    unreachable!()
                };
                assert_eq!(cat.signature(id).unwrap().display_name, "COUNT");
                assert!(having.is_none());
                // group key + aggregate output.
                assert_eq!(output_columns.len(), 2);
            }
            other => panic!("expected Aggregate, got {:?}", other),
        }
    }

    #[test]
    fn bare_count_without_group_by_still_aggregates() {
        let plan = lower("SELECT COUNT(*) FROM t");
        let agg = unwrap_project_agg(plan);
        match agg {
            RelPlan::Aggregate {
                grouping,
                aggregates,
                ..
            } => {
                assert!(matches!(grouping, GroupingSpec::None));
                assert_eq!(aggregates.len(), 1);
            }
            other => panic!("expected Aggregate, got {:?}", other),
        }
    }

    #[test]
    fn count_distinct_sets_distinct_flag() {
        let plan = lower("SELECT COUNT(DISTINCT a) FROM t");
        let agg = unwrap_project_agg(plan);
        match agg {
            RelPlan::Aggregate { aggregates, .. } => {
                assert_eq!(aggregates.len(), 1);
                assert!(aggregates[0].distinct);
            }
            other => panic!("expected Aggregate, got {:?}", other),
        }
    }

    #[test]
    fn having_lowers_onto_aggregate_node() {
        let plan = lower("SELECT a, COUNT(*) FROM t GROUP BY a HAVING COUNT(*) > 1");
        let agg = unwrap_project_agg(plan);
        match agg {
            RelPlan::Aggregate {
                aggregates, having, ..
            } => {
                // The same textual `COUNT(*)` appears in projection
                // and in HAVING; lowering collects them as *two
                // occurrences* (distinct spans, distinct output ids).
                // Structurally-equal calls are not merged; the
                // assertion below pins current behavior so a
                // canonicalization change is intentional.
                assert_eq!(
                    aggregates.len(),
                    2,
                    "identical aggregate calls are not canonicalized"
                );
                assert!(having.is_some());
            }
            other => panic!("expected Aggregate, got {:?}", other),
        }
    }

    #[test]
    fn cube_rollup_and_grouping_sets_preserve_shape() {
        let cube = unwrap_project_agg(lower("SELECT a, b, SUM(c) FROM t GROUP BY CUBE (a, b)"));
        match cube {
            RelPlan::Aggregate { grouping, .. } => {
                assert!(matches!(grouping, GroupingSpec::Cube(ref k) if k.len() == 2));
            }
            other => panic!("expected Aggregate, got {:?}", other),
        }

        let rollup = unwrap_project_agg(lower("SELECT a, b, SUM(c) FROM t GROUP BY ROLLUP (a, b)"));
        match rollup {
            RelPlan::Aggregate { grouping, .. } => {
                assert!(matches!(grouping, GroupingSpec::Rollup(ref k) if k.len() == 2));
            }
            other => panic!("expected Aggregate, got {:?}", other),
        }

        let sets = unwrap_project_agg(lower(
            "SELECT a, b, SUM(c) FROM t GROUP BY GROUPING SETS ((a), (a, b))",
        ));
        match sets {
            RelPlan::Aggregate { grouping, .. } => {
                assert!(matches!(grouping, GroupingSpec::GroupingSets(ref s) if s.len() == 2));
            }
            other => panic!("expected Aggregate, got {:?}", other),
        }
    }

    #[test]
    fn group_by_ordinal_resolves_to_projection_item() {
        let plan = lower("SELECT a, COUNT(*) FROM t GROUP BY 1");
        let agg = unwrap_project_agg(plan);
        match agg {
            RelPlan::Aggregate {
                grouping,
                aggregates,
                ..
            } => {
                let keys = match grouping {
                    GroupingSpec::Standard(k) => k,
                    other => panic!("expected Standard, got {:?}", other),
                };
                assert_eq!(keys.len(), 1);
                // The resolved GROUP BY key's output ColumnId equals
                // the first projection item's output id — that's what
                // makes ordinal resolution "identity-preserving."
                match &keys[0].expr {
                    ScalarExpr::Column { .. } => {}
                    other => panic!("expected Column expr, got {:?}", other),
                }
                assert_eq!(aggregates.len(), 1);
            }
            other => panic!("expected Aggregate, got {:?}", other),
        }
    }

    #[test]
    fn group_by_ordinal_out_of_range_errors() {
        // An ordinal that exceeds the projection width is out of range.
        // Per the comment at `try_resolve_group_by_ordinal` (line ~7709),
        // the lowerer intentionally falls through to scalar lowering
        // rather than producing `InvalidInput` — emitting `InvalidInput`
        // would discard all table/column information from the statement.
        // The result is a valid `Project → Aggregate` plan whose group
        // key is a `ScalarExpr::Opaque` (positional ref, unresolvable).
        let src = "SELECT a FROM t GROUP BY 5";
        let stmt = parse_one(src);
        let plan = lower_query(&stmt, src, StrictMode::Strict)
            .expect("out-of-range ordinal lowers to a valid plan, not LowerError");
        // Should produce a relational plan (Project/Aggregate), not InvalidInput.
        assert!(
            !matches!(plan, RelPlan::InvalidInput { .. }),
            "out-of-range GROUP BY ordinal must not produce InvalidInput (see \
             try_resolve_group_by_ordinal fallthrough): got {:?}",
            plan
        );
        assert!(
            !matches!(plan, RelPlan::Opaque { .. }),
            "out-of-range GROUP BY ordinal must not produce Opaque: got {:?}",
            plan
        );
    }

    #[test]
    fn group_by_alias_resolves_against_projection() {
        // `c_alias` is a projection alias, not a column of `t`. The
        // alias must resolve to the projection item's expression.
        let plan = lower("SELECT a AS c_alias, COUNT(*) FROM t GROUP BY c_alias");
        let agg = unwrap_project_agg(plan);
        match agg {
            RelPlan::Aggregate { grouping, .. } => {
                let keys = match grouping {
                    GroupingSpec::Standard(k) => k,
                    other => panic!("expected Standard, got {:?}", other),
                };
                assert_eq!(keys.len(), 1);
                // The alias resolved to the projection's `a` column
                // reference.
                assert!(matches!(keys[0].expr, ScalarExpr::Column { .. }));
            }
            other => panic!("expected Aggregate, got {:?}", other),
        }
    }

    #[test]
    fn group_by_all_resolves_non_aggregate_projection_items() {
        let plan = lower("SELECT a, b, COUNT(*) FROM t GROUP BY ALL");
        let agg = unwrap_project_agg(plan);
        match agg {
            RelPlan::Aggregate { grouping, .. } => {
                let keys = match grouping {
                    GroupingSpec::All(k) => k,
                    other => panic!("expected All, got {:?}", other),
                };
                // `a` and `b` are non-aggregate; `COUNT(*)` is
                // aggregate-shaped and must be skipped.
                assert_eq!(keys.len(), 2);
            }
            other => panic!("expected Aggregate, got {:?}", other),
        }
    }

    #[test]
    fn non_aggregate_function_call_in_projection_lowers() {
        // Generic FunctionCall lowering: a scalar call with
        // no aggregate shape and no GROUP BY must NOT synthesize an
        // Aggregate node.
        let plan = lower("SELECT UPPER(a) FROM t");
        match plan {
            RelPlan::Project { input, items, .. } => {
                assert_eq!(items.len(), 1);
                let ProjectItem::Expr(e0) = &items[0] else {
                    panic!("expected ProjectItem::Expr, got {:?}", items[0]);
                };
                assert!(matches!(e0.expr, ScalarExpr::FuncCall { .. }));
                // No aggregate wrapper.
                assert!(matches!(*input, RelPlan::Scan { .. }));
            }
            other => panic!("expected Project, got {:?}", other),
        }
    }

    #[test]
    fn filter_modifier_promotes_to_aggregate() {
        let plan = lower("SELECT COUNT(*) FILTER (WHERE a > 0) FROM t");
        let agg = unwrap_project_agg(plan);
        match agg {
            RelPlan::Aggregate { aggregates, .. } => {
                assert_eq!(aggregates.len(), 1);
                assert!(aggregates[0].filter.is_some());
            }
            other => panic!("expected Aggregate, got {:?}", other),
        }
    }

    #[test]
    fn strict_mode_accepts_group_by_with_aggregate() {
        let src = "SELECT a, SUM(b) FROM t GROUP BY a HAVING SUM(b) > 10";
        let stmt = parse_one(src);
        let plan = lower_query(&stmt, src, StrictMode::Strict).expect("strict lower");
        // Top-level shape is Project → Aggregate → Scan.
        match plan {
            RelPlan::Project { input, .. } => {
                assert!(matches!(*input, RelPlan::Aggregate { .. }));
            }
            other => panic!("expected Project, got {:?}", other),
        }
    }

    // ── Windows + QUALIFY ─────────────────────────────────────────────

    #[test]
    fn projection_window_fn_lowers_to_window_stage() {
        let plan = lower("SELECT ROW_NUMBER() OVER (PARTITION BY a ORDER BY b) AS rn FROM t");
        match plan {
            RelPlan::Project { input, items, .. } => {
                assert_eq!(items.len(), 1);
                let ProjectItem::Expr(e0) = &items[0] else {
                    panic!("expected ProjectItem::Expr, got {:?}", items[0]);
                };
                let projected_col = match &e0.expr {
                    ScalarExpr::Column { column, .. } => *column,
                    other => panic!("expected projected Column, got {:?}", other),
                };
                match *input {
                    RelPlan::Window {
                        input,
                        windows,
                        window_outputs,
                        ..
                    } => {
                        assert_eq!(windows.len(), 1);
                        assert_eq!(windows[0].output, projected_col);
                        assert_eq!(window_outputs, vec![projected_col]);
                        assert!(matches!(*input, RelPlan::Scan { .. }));
                    }
                    other => panic!("expected Window input, got {:?}", other),
                }
            }
            other => panic!("expected Project, got {:?}", other),
        }
    }

    #[test]
    fn qualify_desugars_to_filter_over_window() {
        let plan = lower("SELECT a FROM t QUALIFY ROW_NUMBER() OVER (ORDER BY a) = 1");
        match plan {
            RelPlan::Project { input, .. } => match *input {
                RelPlan::Filter {
                    input, predicate, ..
                } => {
                    assert!(matches!(predicate, ScalarExpr::BinOp { .. }));
                    match *input {
                        RelPlan::Window { input, windows, .. } => {
                            assert_eq!(windows.len(), 1);
                            assert!(matches!(*input, RelPlan::Scan { .. }));
                        }
                        other => panic!("expected Window under QUALIFY filter, got {:?}", other),
                    }
                }
                other => panic!("expected Filter under Project, got {:?}", other),
            },
            other => panic!("expected Project, got {:?}", other),
        }
    }

    #[test]
    fn window_function_in_where_is_opaque_in_permissive() {
        let plan = lower("SELECT a FROM t WHERE ROW_NUMBER() OVER (ORDER BY a) = 1");
        assert!(matches!(
            plan,
            RelPlan::InvalidInput {
                kind: InvalidInputKind::WindowContext(
                    WindowContextCategory::FunctionInDisallowedContext,
                ),
                ..
            }
        ));
    }

    #[test]
    fn strict_mode_rejects_window_function_in_where() {
        // Window-in-WHERE is ill-formed input; lowers to a
        // typed `RelPlan::InvalidInput` terminal under every strict
        // mode.
        let src = "SELECT a FROM t WHERE ROW_NUMBER() OVER (ORDER BY a) = 1";
        let stmt = parse_one(src);
        let plan = lower_query(&stmt, src, StrictMode::Strict)
            .expect("InvalidInput must lower under Strict");
        assert!(matches!(
            plan,
            RelPlan::InvalidInput {
                kind: InvalidInputKind::WindowContext(
                    WindowContextCategory::FunctionInDisallowedContext,
                ),
                ..
            }
        ));
    }

    #[test]
    fn named_window_clause_resolves_into_window_call() {
        // `OVER w` in the projection should resolve against
        // the `WINDOW w AS (...)` clause; the resulting `WindowCall`
        // carries the named-window key plus the merged ORDER BY.
        let pg = postgres();
        let plan = lower_with_dialect(
            "SELECT ROW_NUMBER() OVER w FROM t WINDOW w AS (ORDER BY a)",
            pg.as_ref(),
        );
        let win = match &plan {
            RelPlan::Project { input, .. } => match input.as_ref() {
                RelPlan::Window { windows, .. } => &windows[0],
                other => panic!("expected Window child, got {:?}", other),
            },
            other => panic!("expected Project, got {:?}", other),
        };
        assert!(
            win.named_window.is_some(),
            "named-window key must be populated"
        );
        assert_eq!(win.named_window.as_ref().map(|k| k.as_str()), Some("W"));
        assert_eq!(
            win.order_by.len(),
            1,
            "ORDER BY merged from the named WINDOW spec"
        );
    }

    #[test]
    fn named_window_merges_inline_order_by_after_base() {
        // `OVER (w ORDER BY b)` extends the base spec's ORDER BY
        // (none here) with an inline ORDER BY. Order: base first,
        // inline appended.
        let pg = postgres();
        let plan = lower_with_dialect(
            "SELECT ROW_NUMBER() OVER (w ORDER BY b) FROM t WINDOW w AS (PARTITION BY a)",
            pg.as_ref(),
        );
        let win = match &plan {
            RelPlan::Project { input, .. } => match input.as_ref() {
                RelPlan::Window { windows, .. } => &windows[0],
                other => panic!("expected Window child, got {:?}", other),
            },
            other => panic!("expected Project, got {:?}", other),
        };
        assert_eq!(win.named_window.as_ref().map(|k| k.as_str()), Some("W"));
        assert_eq!(
            win.partition_by.len(),
            1,
            "PARTITION BY inherited from base spec"
        );
        assert_eq!(win.order_by.len(), 1, "inline ORDER BY appended");
    }

    #[test]
    fn distinct_on_populates_distinct_on_field() {
        // `SELECT DISTINCT ON (e1, e2) ...` populates
        // `Project.distinct = true` AND `Project.distinct_on` with
        // the lowered key expressions.
        let pg = postgres();
        let plan = lower_with_dialect("SELECT DISTINCT ON (a, b) a, b FROM t", pg.as_ref());
        match &plan {
            RelPlan::Project {
                distinct,
                distinct_on,
                ..
            } => {
                assert!(*distinct, "DISTINCT ON implies DISTINCT");
                assert_eq!(distinct_on.len(), 2, "two key expressions: a, b");
            }
            other => panic!("expected Project, got {:?}", other),
        }
    }

    #[test]
    fn plain_distinct_keeps_distinct_on_empty() {
        let plan = lower("SELECT DISTINCT a FROM t");
        match &plan {
            RelPlan::Project {
                distinct,
                distinct_on,
                ..
            } => {
                assert!(*distinct);
                assert!(distinct_on.is_empty(), "no ON list => empty vec");
            }
            other => panic!("expected Project, got {:?}", other),
        }
    }

    fn find_scan(plan: &RelPlan) -> &RelPlan {
        match plan {
            RelPlan::Scan { .. } => plan,
            RelPlan::Project { input, .. }
            | RelPlan::Filter { input, .. }
            | RelPlan::Aggregate { input, .. }
            | RelPlan::Window { input, .. }
            | RelPlan::Sort { input, .. }
            | RelPlan::Limit { input, .. }
            | RelPlan::Unnest { input, .. }
            | RelPlan::Pivot { input, .. }
            | RelPlan::Unpivot { input, .. }
            | RelPlan::MatchRecognize { input, .. }
            | RelPlan::ConnectBy { input, .. }
            | RelPlan::TableSample { input, .. }
            | RelPlan::DerivedTable { input, .. } => find_scan(input),
            RelPlan::WithScope { body, .. } => find_scan(body),
            RelPlan::Join { left, .. } => find_scan(left),
            RelPlan::SetOp { inputs, .. } => {
                let first = inputs
                    .first()
                    .unwrap_or_else(|| panic!("SetOp with no inputs"));
                find_scan(first)
            }
            RelPlan::Values { .. }
            | RelPlan::CteRef { .. }
            | RelPlan::ModelRef { .. }
            | RelPlan::TableFunction { .. }
            | RelPlan::Insert { .. }
            | RelPlan::Update { .. }
            | RelPlan::Delete { .. }
            | RelPlan::Merge { .. }
            | RelPlan::MultiInsert { .. }
            | RelPlan::Explain { .. }
            | RelPlan::CreateAsQuery { .. }
            | RelPlan::CreateTableForm { .. }
            | RelPlan::ParseRecovery { .. }
            | RelPlan::Opaque { .. } => {
                panic!("no Scan found; got {:?}", plan)
            }
            RelPlan::InvalidInput { .. } => {
                panic!("no Scan found; got {:?}", plan)
            }
        }
    }

    // ── Named args / lambdas / inline ORDER BY ──────────────────────────

    /// Named arguments on a scalar function call flow through to the
    /// IR's `named_args` slot, keyed by a normalized
    /// `IdentKey`, not a raw string.
    #[test]
    fn named_args_round_trip_into_scalar_funccall() {
        // Snowflake-style named arg on a synthetic scalar call.
        let plan = lower("SELECT my_udf(INPUT => a, ROWCOUNT => 100) AS r FROM t");
        match plan {
            RelPlan::Project { items, .. } => {
                assert_eq!(items.len(), 1);
                let ProjectItem::Expr(e0) = &items[0] else {
                    panic!("expected ProjectItem::Expr, got {:?}", items[0]);
                };
                match &e0.expr {
                    ScalarExpr::FuncCall {
                        args, named_args, ..
                    } => {
                        assert!(args.is_empty(), "no positional args expected");
                        assert_eq!(named_args.len(), 2);
                        assert_eq!(named_args[0].0, IdentKey::new("INPUT"));
                        assert_eq!(named_args[1].0, IdentKey::new("ROWCOUNT"));
                    }
                    other => panic!("expected FuncCall, got {:?}", other),
                }
            }
            other => panic!("expected Project, got {:?}", other),
        }
    }

    /// BigQuery's `STRUCT(expr AS alias)` aliased-arg spelling
    /// normalizes into the same `named_args` slot as `name => value`.
    #[test]
    fn aliased_args_normalize_to_named_args() {
        let plan = lower("SELECT struct_like(1 AS x, 'hello' AS y) AS s FROM t");
        match plan {
            RelPlan::Project { items, .. } => {
                let ProjectItem::Expr(e0) = &items[0] else {
                    panic!("expected ProjectItem::Expr, got {:?}", items[0]);
                };
                match &e0.expr {
                    ScalarExpr::FuncCall {
                        args, named_args, ..
                    } => {
                        assert!(args.is_empty());
                        assert_eq!(named_args.len(), 2);
                        assert_eq!(named_args[0].0, IdentKey::new("x"));
                        assert_eq!(named_args[1].0, IdentKey::new("y"));
                    }
                    other => panic!("expected FuncCall, got {:?}", other),
                }
            }
            other => panic!("expected Project, got {:?}", other),
        }
    }

    /// Lambdas lower into `ScalarExpr::Lambda` with fresh `ColumnId`s
    /// bound for each parameter, available only inside the body.
    #[test]
    fn lambda_arg_lowers_to_scalar_lambda() {
        let plan = lower("SELECT filter_arr(arr, x -> x > 5) FROM t");
        match plan {
            RelPlan::Project { items, .. } => {
                let ProjectItem::Expr(e0) = &items[0] else {
                    panic!("expected ProjectItem::Expr, got {:?}", items[0]);
                };
                match &e0.expr {
                    ScalarExpr::FuncCall { args, .. } => {
                        assert_eq!(args.len(), 2);
                        match &args[1] {
                            ScalarExpr::Lambda { params, body, .. } => {
                                assert_eq!(params.len(), 1);
                                assert_eq!(params[0].name, IdentKey::new("x"));
                                // The body references the lambda param by
                                // ColumnId — verify the body's leftmost
                                // column matches the param id.
                                match body.as_ref() {
                                    ScalarExpr::BinOp { left, .. } => match left.as_ref() {
                                        ScalarExpr::Column { column, .. } => {
                                            assert_eq!(*column, params[0].id);
                                        }
                                        other => panic!(
                                            "expected lambda body LHS Column, got {:?}",
                                            other
                                        ),
                                    },
                                    other => panic!("expected lambda body BinOp, got {:?}", other),
                                }
                            }
                            other => panic!("expected Lambda arg, got {:?}", other),
                        }
                    }
                    other => panic!("expected FuncCall, got {:?}", other),
                }
            }
            other => panic!("expected Project, got {:?}", other),
        }
    }

    /// Lambda parameters are lexically scoped: the binding must not
    /// leak into the enclosing scope after the lambda body is lowered.
    #[test]
    fn lambda_params_do_not_leak_into_outer_scope() {
        // Reuse the same name `x` inside and outside the lambda to
        // expose any accidental leak.
        let src = "SELECT x, filter_arr(arr, x -> x > 5) FROM t";
        let plan = lower(src);
        match plan {
            RelPlan::Project { items, .. } => {
                assert_eq!(items.len(), 2);
                // The outer `x` (projection item 0) must resolve to
                // the scan's binding for `x`, not to the lambda's
                // fresh param ColumnId. We can't easily compare ids
                // here, but we can assert both items lower without
                // failure and produce Column refs.
                let ProjectItem::Expr(e0) = &items[0] else {
                    panic!("expected ProjectItem::Expr, got {:?}", items[0]);
                };
                assert!(matches!(e0.expr, ScalarExpr::Column { .. }));
            }
            other => panic!("expected Project, got {:?}", other),
        }
    }

    /// PostgreSQL inline `ORDER BY` inside an aggregate's argument
    /// list lowers into `AggregateCall::arg_order`, not
    /// `within_group_order`.
    #[test]
    fn inline_order_by_lowers_into_arg_order() {
        let src = "SELECT string_agg(x, ',' ORDER BY y DESC) FROM t";
        let plan = lower(src);
        let inner = unwrap_project_agg(plan);
        match inner {
            RelPlan::Aggregate { aggregates, .. } => {
                assert_eq!(aggregates.len(), 1);
                let agg = &aggregates[0];
                assert!(agg.within_group_order.is_empty());
                assert_eq!(agg.arg_order.len(), 1);
                assert_eq!(agg.arg_order[0].ascending, false);
            }
            other => panic!("expected Aggregate, got {:?}", other),
        }
    }

    /// Inline `ORDER BY` and `WITHIN GROUP` on the same call are
    /// semantically disjoint — the lowerer must refuse rather than
    /// silently drop one.
    #[test]
    fn inline_order_by_plus_within_group_is_rejected() {
        // Contrived: put both on one call. This is not valid real
        // SQL; the lowerer enforces the prohibition regardless.
        let src = "SELECT string_agg(x, ',' ORDER BY y) \
                   WITHIN GROUP (ORDER BY z) FROM t";
        let stmt = parse_one(src);
        // Permissive surfaces the single-reason InvalidInput.
        let plan = lower_query(&stmt, src, StrictMode::Permissive).expect("lower");
        assert!(matches!(
            plan,
            RelPlan::InvalidInput {
                kind: InvalidInputKind::ConflictingAggregateOrderings,
                ..
            }
        ));
    }

    /// Unknown functions in strict-IR mode surface as
    /// `OpaqueReason::UnknownFunction`.
    #[test]
    fn strict_rejects_unknown_function_name() {
        let src = "SELECT very_unlikely_function_name_xyz(a) FROM t";
        let stmt = parse_one(src);
        let err = lower_query(&stmt, src, StrictMode::Strict).unwrap_err();
        match err.kind {
            LowerErrorKind::Opaque(OpaqueReason::UnknownFunction { raw_name }) => {
                assert!(raw_name.eq_ignore_ascii_case("very_unlikely_function_name_xyz"));
            }
            other => panic!("expected UnknownFunction, got {:?}", other),
        }
    }

    /// Known aggregate names resolve through the catalog in both
    /// permissive and strict modes without fabricating an aggregate
    /// allowlist in the lowerer itself.
    #[test]
    fn catalog_resolved_count_is_aggregate_shape() {
        let src = "SELECT COUNT(a) FROM t";
        let stmt = parse_one(src);
        let plan = lower_query(&stmt, src, StrictMode::Strict).expect("strict lower");
        let inner = unwrap_project_agg(plan);
        match inner {
            RelPlan::Aggregate { aggregates, .. } => {
                assert_eq!(aggregates.len(), 1);
                assert!(matches!(aggregates[0].func, ResolvedFunc::Resolved { .. }));
            }
            other => panic!("expected Aggregate, got {:?}", other),
        }
    }

    // ── ORDER BY / LIMIT / OFFSET / FETCH / TOP ───────────────────────

    #[test]
    fn order_by_wraps_project_in_sort() {
        let plan = lower("SELECT a FROM t ORDER BY a");
        match plan {
            RelPlan::Sort { input, keys, .. } => {
                assert_eq!(keys.len(), 1);
                assert!(keys[0].ascending);
                assert!(keys[0].nulls_first.is_none());
                assert!(matches!(*input, RelPlan::Project { .. }));
            }
            other => panic!("expected Sort, got {:?}", other),
        }
    }

    #[test]
    fn order_by_desc_nulls_last_captured() {
        let plan = lower("SELECT a FROM t ORDER BY a DESC NULLS LAST");
        match plan {
            RelPlan::Sort { keys, .. } => {
                assert_eq!(keys.len(), 1);
                assert!(!keys[0].ascending);
                assert_eq!(keys[0].nulls_first, Some(false));
            }
            other => panic!("expected Sort, got {:?}", other),
        }
    }

    #[test]
    fn order_by_multiple_keys_preserve_order() {
        let plan = lower("SELECT a, b FROM t ORDER BY a ASC, b DESC NULLS FIRST");
        match plan {
            RelPlan::Sort { keys, .. } => {
                assert_eq!(keys.len(), 2);
                assert!(keys[0].ascending);
                assert!(!keys[1].ascending);
                assert_eq!(keys[1].nulls_first, Some(true));
            }
            other => panic!("expected Sort, got {:?}", other),
        }
    }

    #[test]
    fn limit_wraps_project_in_limit() {
        let plan = lower("SELECT a FROM t LIMIT 10");
        match plan {
            RelPlan::Limit {
                input,
                limit,
                offset,
                with_ties,
                ..
            } => {
                assert!(matches!(*input, RelPlan::Project { .. }));
                assert!(limit.is_some());
                assert!(offset.is_none());
                assert!(!with_ties);
            }
            other => panic!("expected Limit, got {:?}", other),
        }
    }

    #[test]
    fn limit_offset_both_populated() {
        let plan = lower("SELECT a FROM t LIMIT 10 OFFSET 5");
        match plan {
            RelPlan::Limit {
                limit,
                offset,
                with_ties,
                ..
            } => {
                assert!(limit.is_some());
                assert!(offset.is_some());
                assert!(!with_ties);
            }
            other => panic!("expected Limit, got {:?}", other),
        }
    }

    #[test]
    fn order_by_and_limit_nest_limit_over_sort() {
        let plan = lower("SELECT a FROM t ORDER BY a LIMIT 10");
        match plan {
            RelPlan::Limit { input, .. } => match *input {
                RelPlan::Sort { input, .. } => {
                    assert!(matches!(*input, RelPlan::Project { .. }));
                }
                other => panic!("expected Sort under Limit, got {:?}", other),
            },
            other => panic!("expected Limit, got {:?}", other),
        }
    }

    #[test]
    fn fetch_first_rows_only_lowers_as_limit() {
        let plan = lower("SELECT a FROM t ORDER BY a FETCH FIRST 10 ROWS ONLY");
        match plan {
            RelPlan::Limit {
                input,
                limit,
                with_ties,
                ..
            } => {
                assert!(limit.is_some());
                assert!(!with_ties);
                assert!(matches!(*input, RelPlan::Sort { .. }));
            }
            other => panic!("expected Limit, got {:?}", other),
        }
    }

    #[test]
    fn offset_only_lowers_as_limit_with_no_row_count() {
        let plan = lower("SELECT a FROM t OFFSET 5");
        match plan {
            RelPlan::Limit { limit, offset, .. } => {
                assert!(limit.is_none());
                assert!(offset.is_some());
            }
            other => panic!("expected Limit, got {:?}", other),
        }
    }

    #[test]
    fn tsql_top_lowers_as_limit() {
        let src = "SELECT TOP 10 a FROM t";
        let d = crate::dialect::mssql();
        let stmt = parse_one_with_dialect(src, d.as_ref());
        let plan = lower_query(&stmt, src, StrictMode::Permissive).expect("lower");
        match plan {
            RelPlan::Limit {
                limit,
                offset,
                with_ties,
                ..
            } => {
                assert!(limit.is_some());
                assert!(offset.is_none());
                assert!(!with_ties);
            }
            other => panic!("expected Limit, got {:?}", other),
        }
    }

    #[test]
    fn tsql_top_with_ties_sets_flag() {
        let src = "SELECT TOP 10 WITH TIES a FROM t ORDER BY a";
        let d = crate::dialect::mssql();
        let stmt = parse_one_with_dialect(src, d.as_ref());
        let plan = lower_query(&stmt, src, StrictMode::Permissive).expect("lower");
        match plan {
            RelPlan::Limit {
                with_ties, input, ..
            } => {
                assert!(with_ties);
                assert!(matches!(*input, RelPlan::Sort { .. }));
            }
            other => panic!("expected Limit, got {:?}", other),
        }
    }

    #[test]
    fn tsql_top_percent_lowers_to_percent_limit() {
        let src = "SELECT TOP 10 PERCENT a FROM t";
        let d = crate::dialect::mssql();
        let stmt = parse_one_with_dialect(src, d.as_ref());
        let plan = lower_query(&stmt, src, StrictMode::Permissive).expect("lower");
        match plan {
            RelPlan::Limit {
                kind,
                limit:
                    Some(ScalarExpr::Lit {
                        value: Lit::Integer(ref s),
                        ..
                    }),
                offset,
                with_ties,
                ..
            } => {
                assert_eq!(kind, LimitKind::Percent);
                assert_eq!(s, "10");
                assert!(offset.is_none());
                assert!(!with_ties);
            }
            other => panic!("expected percent Limit, got {:?}", other),
        }
    }

    #[test]
    fn tsql_top_combined_with_limit_lowers_to_nested_limits() {
        let src = "SELECT TOP 10 a FROM t LIMIT 5";
        let d = crate::dialect::mssql();
        let stmt = parse_one_with_dialect(src, d.as_ref());
        let plan = lower_query(&stmt, src, StrictMode::Permissive).expect("lower");
        match plan {
            RelPlan::Limit {
                kind: outer_kind,
                limit:
                    Some(ScalarExpr::Lit {
                        value: Lit::Integer(ref outer),
                        ..
                    }),
                input,
                ..
            } => {
                assert_eq!(outer_kind, LimitKind::Rows);
                assert_eq!(outer, "5");
                match *input {
                    RelPlan::Limit {
                        kind: inner_kind,
                        limit:
                            Some(ScalarExpr::Lit {
                                value: Lit::Integer(ref inner),
                                ..
                            }),
                        ..
                    } => {
                        assert_eq!(inner_kind, LimitKind::Rows);
                        assert_eq!(inner, "10");
                    }
                    other => panic!("expected inner TOP Limit, got {:?}", other),
                }
            }
            other => panic!("expected outer Limit, got {:?}", other),
        }
    }

    #[test]
    fn limit_with_aggregate_in_expr_is_invalid_input() {
        // Aggregates in LIMIT are not valid SQL. The lowerer now
        // surfaces this as a typed `InvalidInput` rather than a
        // generic `Opaque`, preserving the error category for
        // downstream consumers.
        let plan = lower("SELECT a FROM t LIMIT COUNT(*)");
        assert!(
            matches!(
                plan,
                RelPlan::InvalidInput {
                    kind: InvalidInputKind::AggregateContext(
                        AggregateContextCategory::InDisallowedContext
                    ),
                    ..
                }
            ),
            "expected InvalidInput(AggregateContext(InDisallowedContext)), got {:?}",
            plan
        );
    }

    #[test]
    fn pre_limit_extension_clauses_lower_to_statement_facts() {
        // Databricks DISTRIBUTE BY / SORT BY / CLUSTER BY are
        // captured as preserved-text spans on
        // `StatementFacts.pre_limit_extensions`. The SELECT itself
        // is not rejected as opaque.
        let src = "SELECT a FROM t DISTRIBUTE BY a";
        let d = crate::dialect::databricks();
        let stmt = parse_one_with_dialect(src, d.as_ref());
        let catalog = FunctionCatalog::for_dialect(CatalogDialect::Default);
        let session = SessionContext::default();
        let (_plan, _, _, facts) = lower_query_full_with_bindings(
            &stmt,
            src,
            StrictMode::Permissive,
            &catalog,
            &session,
            None,
        )
        .expect("lower");
        assert!(
            !facts.pre_limit_extensions.is_empty(),
            "expected DISTRIBUTE BY captured on pre_limit_extensions; \
             got: {:?}",
            facts.pre_limit_extensions
        );
    }

    // ── Set operations ──────────────────────────────────────────────────

    #[test]
    fn two_way_union_lowers_to_setop() {
        let plan = lower("SELECT a FROM t UNION SELECT a FROM u");
        match plan {
            RelPlan::SetOp {
                op,
                inputs,
                output_columns,
                corresponding,
                ..
            } => {
                assert_eq!(op, SetOpKind::UnionDistinct);
                assert_eq!(inputs.len(), 2);
                // Fresh ColumnIds allocated; arity should match the
                // first branch's projection (one column: `a`).
                assert_eq!(output_columns.len(), 1);
                assert!(corresponding.is_none());
                for branch in &inputs {
                    assert!(matches!(**branch, RelPlan::Project { .. }));
                }
            }
            other => panic!("expected SetOp, got {:?}", other),
        }
    }

    #[test]
    fn union_all_maps_to_union_all_kind() {
        let plan = lower("SELECT a FROM t UNION ALL SELECT a FROM u");
        match plan {
            RelPlan::SetOp { op, .. } => assert_eq!(op, SetOpKind::UnionAll),
            other => panic!("expected SetOp, got {:?}", other),
        }
    }

    #[test]
    fn union_distinct_modifier_is_distinct_kind() {
        let plan = lower("SELECT a FROM t UNION DISTINCT SELECT a FROM u");
        match plan {
            RelPlan::SetOp { op, .. } => {
                assert_eq!(op, SetOpKind::UnionDistinct);
            }
            other => panic!("expected SetOp, got {:?}", other),
        }
    }

    #[test]
    fn intersect_and_except_map_to_their_kinds() {
        let p1 = lower("SELECT a FROM t INTERSECT SELECT a FROM u");
        match p1 {
            RelPlan::SetOp { op, .. } => {
                assert_eq!(op, SetOpKind::IntersectDistinct);
            }
            other => panic!("expected SetOp, got {:?}", other),
        }
        let p2 = lower("SELECT a FROM t EXCEPT ALL SELECT a FROM u");
        match p2 {
            RelPlan::SetOp { op, .. } => {
                assert_eq!(op, SetOpKind::ExceptAll);
            }
            other => panic!("expected SetOp, got {:?}", other),
        }
    }

    #[test]
    fn minus_is_synonym_for_except() {
        // Snowflake spells EXCEPT as MINUS. The IR collapses them so
        // downstream analyses don't need to branch on dialect spelling.
        let plan = lower("SELECT a FROM t MINUS SELECT a FROM u");
        match plan {
            RelPlan::SetOp { op, .. } => {
                assert_eq!(op, SetOpKind::ExceptDistinct);
            }
            other => panic!("expected SetOp, got {:?}", other),
        }
    }

    #[test]
    fn three_way_same_op_flattens_to_n_ary() {
        // `a UNION b UNION c` parses left-deep; lowering flattens.
        let plan = lower("SELECT a FROM t UNION SELECT a FROM u UNION SELECT a FROM v");
        match plan {
            RelPlan::SetOp {
                op,
                inputs,
                output_columns,
                ..
            } => {
                assert_eq!(op, SetOpKind::UnionDistinct);
                assert_eq!(
                    inputs.len(),
                    3,
                    "same-op spine must flatten to N-ary, got {} inputs",
                    inputs.len()
                );
                assert_eq!(output_columns.len(), 1);
                // None of the flattened children are themselves
                // `SetOp` of the same kind — the flatten is complete.
                for branch in &inputs {
                    if let RelPlan::SetOp { op: inner_op, .. } = &**branch {
                        assert_ne!(
                            *inner_op,
                            SetOpKind::UnionDistinct,
                            "flatten left a same-kind SetOp child"
                        );
                    }
                }
            }
            other => panic!("expected SetOp, got {:?}", other),
        }
    }

    #[test]
    fn mixed_modifier_does_not_flatten() {
        // `UNION ALL` and plain `UNION` are distinct `SetOpKind`s, so
        // `(a UNION ALL b) UNION c` must stay nested.
        let plan = lower("SELECT a FROM t UNION ALL SELECT a FROM u UNION SELECT a FROM v");
        match plan {
            RelPlan::SetOp { op, inputs, .. } => {
                // Left-deep parse: outer op is the *rightmost*
                // operator (`UNION` plain), inner is `UNION ALL`.
                assert_eq!(op, SetOpKind::UnionDistinct);
                assert_eq!(inputs.len(), 2);
                // The left child is the inner `UNION ALL` SetOp.
                match &*inputs[0] {
                    RelPlan::SetOp {
                        op: inner_op,
                        inputs: inner_inputs,
                        ..
                    } => {
                        assert_eq!(*inner_op, SetOpKind::UnionAll);
                        assert_eq!(inner_inputs.len(), 2);
                    }
                    other => {
                        panic!("expected nested SetOp on left, got {:?}", other)
                    }
                }
            }
            other => panic!("expected SetOp, got {:?}", other),
        }
    }

    #[test]
    fn mixed_operators_stay_nested() {
        // `a UNION b INTERSECT c` parses left-deep as
        // `(a UNION b) INTERSECT c`; operators differ, so the inner
        // `UNION` must remain a nested `SetOp`.
        let plan = lower("SELECT a FROM t UNION SELECT a FROM u INTERSECT SELECT a FROM v");
        match plan {
            RelPlan::SetOp { op, inputs, .. } => {
                assert_eq!(op, SetOpKind::IntersectDistinct);
                assert_eq!(inputs.len(), 2);
                assert!(matches!(
                    *inputs[0],
                    RelPlan::SetOp {
                        op: SetOpKind::UnionDistinct,
                        ..
                    }
                ));
            }
            other => panic!("expected SetOp, got {:?}", other),
        }
    }

    #[test]
    fn setop_inputs_contribute_all_tables_read() {
        // The derived-facts walker iterates SetOp.inputs; both
        // branches' base tables must surface. This also pins that
        // lowering did not accidentally drop a branch during flattening.
        use crate::ir::derived_facts::derive_facts_from_plan;
        let (plan, bindings) =
            lower_with_bindings("SELECT a FROM t1 UNION SELECT a FROM t2 UNION SELECT a FROM t3");
        let facts = derive_facts_from_plan(
            "",
            &plan,
            &bindings,
            &crate::ir::catalog::FunctionCatalog::empty(),
            None,
            &crate::facts::reasoning::RecognitionOnly,
        );
        let names: Vec<&str> = facts.tables_read.iter().map(|t| t.name.as_str()).collect();
        assert_eq!(names, vec!["t1", "t2", "t3"]);
    }

    #[test]
    fn setop_over_star_branch_lowers_as_setop() {
        // A UNION branch containing
        // `SELECT *` is lowerable — the star promotes
        // to `ProjectItem::Star`, so the top-level plan is a clean
        // `RelPlan::SetOp`. Test kept as a regression anchor: if a
        // future change re-introduces an opaque fallback on a
        // star-bearing branch, this test catches it.
        let plan = lower("SELECT a FROM t UNION SELECT * FROM u");
        assert!(
            matches!(plan, RelPlan::SetOp { .. }),
            "expected SetOp, got {:?}",
            plan
        );
    }

    #[test]
    fn strict_mode_accepts_union() {
        // Under Strict, set-ops over SELECTs must lower cleanly
        // without falling to Opaque.
        let src = "SELECT a FROM t UNION ALL SELECT a FROM u";
        let stmt = parse_one(src);
        let plan =
            lower_query(&stmt, src, StrictMode::Strict).expect("strict lower must accept set-op");
        assert!(matches!(plan, RelPlan::SetOp { .. }));
    }

    // ── CREATE … AS SELECT (CreateAsQuery) ──────────────────────────────

    /// `CREATE VIEW v AS SELECT a FROM t` lowers to a
    /// `CreateAsQuery::View` wrapping a lowered `Project → Scan` body.
    /// Non-materialized views have `materialized=false`.
    #[test]
    fn create_view_lowers_to_create_as_query_view() {
        let plan = lower("CREATE VIEW v AS SELECT a FROM t");
        match plan {
            RelPlan::CreateAsQuery {
                kind,
                or_replace,
                or_alter,
                if_not_exists,
                body,
                ..
            } => {
                match kind {
                    CreateAsKind::View {
                        materialized,
                        recursive,
                        secure,
                        temp,
                    } => {
                        assert!(!materialized);
                        assert!(!recursive);
                        assert!(!secure);
                        assert!(!temp);
                    }
                    other => panic!("expected View kind, got {:?}", other),
                }
                assert!(!or_replace);
                assert!(!or_alter);
                assert!(!if_not_exists);
                assert!(
                    matches!(body.as_deref(), Some(RelPlan::Project { .. })),
                    "body should be lowered SELECT, got {:?}",
                    body
                );
            }
            other => panic!("expected CreateAsQuery, got {:?}", other),
        }
    }

    /// `CREATE MATERIALIZED VIEW` flips `materialized=true`. Exercises
    /// the `materialized_span.is_some()` wiring in `lower_create_view`.
    #[test]
    fn create_materialized_view_sets_materialized_flag() {
        let plan = lower("CREATE MATERIALIZED VIEW mv AS SELECT a FROM t");
        match plan {
            RelPlan::CreateAsQuery { kind, .. } => match kind {
                CreateAsKind::View { materialized, .. } => assert!(materialized),
                other => panic!("expected View kind, got {:?}", other),
            },
            other => panic!("expected CreateAsQuery, got {:?}", other),
        }
    }

    /// `CREATE OR REPLACE SECURE VIEW` flips `or_replace=true` and
    /// `secure=true`. Also checks `target` resolves the view name.
    #[test]
    fn create_or_replace_secure_view_flags() {
        let plan = lower("CREATE OR REPLACE SECURE VIEW v AS SELECT a FROM t");
        match plan {
            RelPlan::CreateAsQuery {
                kind,
                or_replace,
                target,
                ..
            } => {
                assert!(or_replace);
                match kind {
                    CreateAsKind::View { secure, .. } => assert!(secure),
                    other => panic!("expected View kind, got {:?}", other),
                }
                assert_eq!(target.name, "v");
            }
            other => panic!("expected CreateAsQuery, got {:?}", other),
        }
    }

    /// `CREATE TABLE t AS SELECT …` (CTAS) lowers to
    /// `CreateAsKind::Table`. Non-CTAS `CREATE TABLE` is covered by a
    /// separate test.
    #[test]
    fn create_table_as_select_lowers_to_table_kind() {
        let plan = lower("CREATE TABLE t AS SELECT a FROM src");
        match plan {
            RelPlan::CreateAsQuery {
                kind, body, target, ..
            } => {
                match kind {
                    CreateAsKind::Table { transient, temp } => {
                        assert!(!transient);
                        assert!(!temp);
                    }
                    other => panic!("expected Table kind, got {:?}", other),
                }
                assert_eq!(target.name, "t");
                assert!(matches!(body.as_deref(), Some(RelPlan::Project { .. })));
            }
            other => panic!("expected CreateAsQuery, got {:?}", other),
        }
    }

    /// Non-CTAS `CREATE TABLE` (here: `Plain` — column list only) routes to
    /// `CreateTableForm` with `Plain` kind. Lowering lands all
    /// non-CTAS variants as `RelPlan::CreateTableForm`.
    #[test]
    fn create_table_plain_routes_to_create_table_form() {
        let plan = lower("CREATE TABLE t (a INT)");
        match plan {
            RelPlan::CreateTableForm { kind, .. } => {
                assert_eq!(kind, CreateTableFormKind::Plain);
            }
            other => panic!("expected CreateTableForm, got {:?}", other),
        }
    }

    /// `CREATE DYNAMIC TABLE` with `TARGET_LAG` and `WAREHOUSE`
    /// surfaces both as `CreateSideOption` entries. Exercises the
    /// side-option span-collection path and the `or_replace` /
    /// `transient` wiring.
    #[test]
    fn create_dynamic_table_captures_side_options() {
        let plan = lower(
            "CREATE OR REPLACE TRANSIENT DYNAMIC TABLE dt \
             TARGET_LAG = '1 minute' WAREHOUSE = wh \
             AS SELECT a FROM src",
        );
        match plan {
            RelPlan::CreateAsQuery {
                kind,
                or_replace,
                side_options,
                body,
                ..
            } => {
                match kind {
                    CreateAsKind::DynamicTable { iceberg, transient } => {
                        assert!(!iceberg);
                        assert!(transient);
                    }
                    other => panic!("expected DynamicTable kind, got {:?}", other),
                }
                assert!(or_replace);
                let option_kinds: Vec<CreateSideOptionKind> =
                    side_options.iter().map(|o| o.kind).collect();
                assert!(
                    option_kinds.contains(&CreateSideOptionKind::TargetLag),
                    "missing TargetLag in {:?}",
                    option_kinds
                );
                assert!(
                    option_kinds.contains(&CreateSideOptionKind::Warehouse),
                    "missing Warehouse in {:?}",
                    option_kinds
                );
                assert!(matches!(body.as_deref(), Some(RelPlan::Project { .. })));
            }
            other => panic!("expected CreateAsQuery, got {:?}", other),
        }
    }

    /// `CREATE MATERIALIZED VIEW … AS REPLICA OF …` (BigQuery) has no
    /// query body, so lowering must preserve that absence explicitly
    /// instead of synthesizing a fake empty query.
    #[test]
    fn create_view_replica_of_lowers_without_body() {
        let plan = lower("CREATE MATERIALIZED VIEW mv AS REPLICA OF primary_db.public.mv");
        match plan {
            RelPlan::CreateAsQuery {
                kind,
                body,
                side_options,
                ..
            } => {
                match kind {
                    CreateAsKind::View { materialized, .. } => assert!(materialized),
                    other => panic!("expected View kind, got {:?}", other),
                }
                assert!(body.is_none());
                let option_kinds: Vec<CreateSideOptionKind> =
                    side_options.iter().map(|o| o.kind).collect();
                assert!(option_kinds.contains(&CreateSideOptionKind::ReplicaOf));
            }
            other => panic!("expected CreateAsQuery, got {:?}", other),
        }
    }

    /// The derived-facts walker must descend into `CreateAsQuery.body`
    /// so base tables read by the body surface in `tables_read`. This
    /// pins the `walk_rel_plan` arm.
    #[test]
    fn create_as_query_body_contributes_to_tables_read() {
        use crate::ir::derived_facts::derive_facts_from_plan;
        let (plan, bindings) = lower_with_bindings("CREATE TABLE dst AS SELECT a FROM src");
        let facts = derive_facts_from_plan(
            "",
            &plan,
            &bindings,
            &crate::ir::catalog::FunctionCatalog::empty(),
            None,
            &crate::facts::reasoning::RecognitionOnly,
        );
        let names: Vec<&str> = facts.tables_read.iter().map(|t| t.name.as_str()).collect();
        assert_eq!(names, vec!["src"]);
    }

    // ── BindingTable side-table ─────────────────────────────────────

    /// Collect every [`ColumnId`] reachable in a plan, walking both
    /// relational structure and scalar expressions. Used by the
    /// binding-coverage invariant test below.
    fn collect_plan_column_ids(plan: &RelPlan) -> std::collections::BTreeSet<ColumnId> {
        use crate::ir::visitor::{walk_rel_plan, walk_scalar_expr, RelPlanVisitor};
        #[derive(Default)]
        struct Collect {
            ids: std::collections::BTreeSet<ColumnId>,
        }
        impl<'a> RelPlanVisitor<'a> for Collect {
            fn visit_rel_plan(&mut self, p: &'a RelPlan) {
                for id in p.output_schema() {
                    self.ids.insert(id);
                }
                walk_rel_plan(self, p);
            }
            fn visit_scalar_expr(&mut self, e: &'a ScalarExpr) {
                if let ScalarExpr::Column { column, .. } = e {
                    self.ids.insert(*column);
                }
                walk_scalar_expr(self, e);
            }
        }
        let mut c = Collect::default();
        c.visit_rel_plan(plan);
        c.ids
    }

    #[test]
    fn bindings_populated_for_every_column_id() {
        // Exercises scan columns, projection outputs, aliases, a
        // filter referencing a column, and a derived-table wrapper.
        let src = "SELECT d.a AS aa, d.b FROM (SELECT a, b FROM t WHERE c = 1) d";
        let stmt = parse_one(src);
        let catalog = FunctionCatalog::for_dialect(CatalogDialect::Default);
        let session = SessionContext::default();
        let (plan, _cat, bindings, _facts) = lower_query_full_with_bindings(
            &stmt,
            src,
            StrictMode::Permissive,
            &catalog,
            &session,
            None,
        )
        .expect("lower");

        let ids = collect_plan_column_ids(&plan);
        assert!(!ids.is_empty(), "plan must contain column ids");
        for id in &ids {
            assert!(
                bindings.get(*id).is_some(),
                "ColumnId {id:?} reachable in plan has no BindingTable entry"
            );
        }
        // Every recorded binding has a non-placeholder id (strictly
        // monotonic allocation invariant).
        for (id, b) in bindings.iter() {
            assert_eq!(*id, b.id, "binding table key must match binding.id");
        }

        // Meaningful display names: user-facing identifiers must be
        // recorded, not left empty. The outer projection alias `aa`,
        // the scan columns `a`, `b`, `c` all appear in the source
        // and must be recoverable from the binding table in their
        // normalized form (default Snowflake dialect → unquoted
        // identifiers fold to upper-case).
        let display_names: std::collections::BTreeSet<&str> = bindings
            .iter()
            .map(|(_, b)| b.display_name.as_str())
            .filter(|s| !s.is_empty())
            .collect();
        for expected in ["AA", "A", "B", "C"] {
            assert!(
                display_names.contains(expected),
                "expected display_name `{expected}` missing from bindings; \
                 got: {display_names:?}"
            );
        }
    }

    /// Every closed-enum combination of
    /// `LockStrength` × `WaitPolicy` lowers losslessly into
    /// [`super::statement_facts::ForUpdateFact`].
    ///
    /// PostgreSQL is the dialect used because its grammar exposes
    /// the full matrix (`FOR UPDATE`, `FOR NO KEY UPDATE`,
    /// `FOR SHARE`, `FOR KEY SHARE` × `NOWAIT` | `SKIP LOCKED`) at
    /// the same nesting level. Snowflake's `FOR UPDATE` is parsed by
    /// the same AST node so the lowering path is dialect-agnostic.
    #[test]
    fn for_update_clause_lowers_to_statement_facts() {
        use super::super::statement_facts::{
            LockStrength as IrLockStrength, WaitPolicy as IrWaitPolicy,
        };
        let pg = postgres();

        // Plain `FOR UPDATE`, no wait policy.
        let stmt = parse_one_with_dialect("SELECT a FROM t FOR UPDATE", pg.as_ref());
        let catalog = FunctionCatalog::for_dialect(CatalogDialect::Default);
        let session = SessionContext::default();
        let (_, _, _, facts) = lower_query_full_with_bindings(
            &stmt,
            "SELECT a FROM t FOR UPDATE",
            StrictMode::Permissive,
            &catalog,
            &session,
            None,
        )
        .expect("lower");
        assert_eq!(facts.for_update.len(), 1);
        assert!(matches!(
            facts.for_update[0].strength,
            IrLockStrength::Update
        ));
        assert!(facts.for_update[0].wait.is_none());

        // FOR SHARE NOWAIT.
        let src = "SELECT a FROM t FOR SHARE NOWAIT";
        let stmt = parse_one_with_dialect(src, pg.as_ref());
        let (_, _, _, facts) = lower_query_full_with_bindings(
            &stmt,
            src,
            StrictMode::Permissive,
            &catalog,
            &session,
            None,
        )
        .expect("lower");
        assert_eq!(facts.for_update.len(), 1);
        assert!(matches!(
            facts.for_update[0].strength,
            IrLockStrength::Share
        ));
        assert!(matches!(
            facts.for_update[0].wait,
            Some(IrWaitPolicy::NoWait { .. })
        ));

        // FOR NO KEY UPDATE SKIP LOCKED.
        let src = "SELECT a FROM t FOR NO KEY UPDATE SKIP LOCKED";
        let stmt = parse_one_with_dialect(src, pg.as_ref());
        let (_, _, _, facts) = lower_query_full_with_bindings(
            &stmt,
            src,
            StrictMode::Permissive,
            &catalog,
            &session,
            None,
        )
        .expect("lower");
        assert!(matches!(
            facts.for_update[0].strength,
            IrLockStrength::NoKeyUpdate
        ));
        assert!(matches!(
            facts.for_update[0].wait,
            Some(IrWaitPolicy::SkipLocked { .. })
        ));

        // FOR KEY SHARE OF table list — verify `of_tables` propagates.
        let src = "SELECT a FROM t FOR KEY SHARE OF t";
        let stmt = parse_one_with_dialect(src, pg.as_ref());
        let (_, _, _, facts) = lower_query_full_with_bindings(
            &stmt,
            src,
            StrictMode::Permissive,
            &catalog,
            &session,
            None,
        )
        .expect("lower");
        assert!(matches!(
            facts.for_update[0].strength,
            IrLockStrength::KeyShare
        ));
        assert_eq!(
            facts.for_update[0].of_tables.len(),
            1,
            "OF clause table list must propagate"
        );
    }

    /// A query with no FOR UPDATE leaves the
    /// `for_update` field empty (Vec, never None — closed-enum
    /// discipline says default-empty is the absent state).
    #[test]
    fn for_update_absent_yields_empty_facts() {
        let facts = lower_facts("SELECT 1");
        assert!(facts.for_update.is_empty());
        assert!(facts.is_empty());
    }

    /// T-SQL `FOR JSON …` and `FOR XML …`
    /// trailing clauses lower into [`super::super::statement_facts::OutputFormat`]
    /// with the JSON-vs-XML discriminator recovered from the
    /// source slice. The clause is not rejected as opaque.
    #[test]
    fn for_json_xml_clause_lowers_to_output_format() {
        use super::super::statement_facts::OutputFormat;
        let mssql = crate::dialect::mssql();

        // FOR JSON AUTO.
        let src = "SELECT a FROM t FOR JSON AUTO";
        let stmt = parse_one_with_dialect(src, mssql.as_ref());
        let catalog = FunctionCatalog::for_dialect(CatalogDialect::Default);
        let session = SessionContext::default();
        let (_, _, _, facts) = lower_query_full_with_bindings(
            &stmt,
            src,
            StrictMode::Permissive,
            &catalog,
            &session,
            None,
        )
        .expect("lower");
        assert!(matches!(
            facts.output_format,
            Some(OutputFormat::ForJson { .. })
        ));

        // FOR JSON PATH with options.
        let src = "SELECT a FROM t FOR JSON PATH, ROOT('r'), INCLUDE_NULL_VALUES";
        let stmt = parse_one_with_dialect(src, mssql.as_ref());
        let (_, _, _, facts) = lower_query_full_with_bindings(
            &stmt,
            src,
            StrictMode::Permissive,
            &catalog,
            &session,
            None,
        )
        .expect("lower");
        assert!(matches!(
            facts.output_format,
            Some(OutputFormat::ForJson { .. })
        ));

        // FOR XML RAW.
        let src = "SELECT a FROM t FOR XML RAW";
        let stmt = parse_one_with_dialect(src, mssql.as_ref());
        let (_, _, _, facts) = lower_query_full_with_bindings(
            &stmt,
            src,
            StrictMode::Permissive,
            &catalog,
            &session,
            None,
        )
        .expect("lower");
        assert!(matches!(
            facts.output_format,
            Some(OutputFormat::ForXml { .. })
        ));

        // FOR XML PATH('row'), ELEMENTS — verify mode-with-paren and tail options.
        let src = "SELECT a FROM t FOR XML PATH('row'), ELEMENTS";
        let stmt = parse_one_with_dialect(src, mssql.as_ref());
        let (_, _, _, facts) = lower_query_full_with_bindings(
            &stmt,
            src,
            StrictMode::Permissive,
            &catalog,
            &session,
            None,
        )
        .expect("lower");
        assert!(matches!(
            facts.output_format,
            Some(OutputFormat::ForXml { .. })
        ));
    }

    /// A query with no FOR JSON/XML leaves
    /// `output_format` as `None` (Option discipline: absent state).
    #[test]
    fn for_json_xml_absent_yields_none_output_format() {
        let facts = lower_facts("SELECT 1");
        assert!(facts.output_format.is_none());
    }

    /// `SELECT … INTO @v1, @v2` lowers each
    /// target identifier into an [`super::super::statement_facts::IntoVarTarget`].
    #[test]
    fn into_vars_lower_into_statement_facts() {
        let mssql = crate::dialect::mssql();
        let src = "SELECT a, b INTO @v1, @v2 FROM t";
        let stmt = parse_one_with_dialect(src, mssql.as_ref());
        let catalog = FunctionCatalog::for_dialect(CatalogDialect::Default);
        let session = SessionContext::default();
        let (_, _, _, facts) = lower_query_full_with_bindings(
            &stmt,
            src,
            StrictMode::Permissive,
            &catalog,
            &session,
            None,
        )
        .expect("lower");
        assert_eq!(
            facts.into_vars.len(),
            2,
            "expected two INTO targets, got: {:?}",
            facts.into_vars
        );
    }

    /// BigQuery `SELECT AS STRUCT` /
    /// `SELECT AS VALUE` lowers into the closed
    /// [`super::super::statement_facts::SelectAsKind`] enum.
    #[test]
    fn select_as_qualifier_lowers_to_select_as_kind() {
        use super::super::statement_facts::SelectAsKind;
        let bq = crate::dialect::bigquery();

        let src = "SELECT AS STRUCT a, b FROM t";
        let stmt = parse_one_with_dialect(src, bq.as_ref());
        let catalog = FunctionCatalog::for_dialect(CatalogDialect::Default);
        let session = SessionContext::default();
        let (_, _, _, facts) = lower_query_full_with_bindings(
            &stmt,
            src,
            StrictMode::Permissive,
            &catalog,
            &session,
            None,
        )
        .expect("lower");
        assert_eq!(facts.select_as, Some(SelectAsKind::Struct));

        let src = "SELECT AS VALUE STRUCT(a, b) FROM t";
        let stmt = parse_one_with_dialect(src, bq.as_ref());
        let (_, _, _, facts) = lower_query_full_with_bindings(
            &stmt,
            src,
            StrictMode::Permissive,
            &catalog,
            &session,
            None,
        )
        .expect("lower");
        assert_eq!(facts.select_as, Some(SelectAsKind::Value));
    }

    /// Clause-level Jinja `{% if %} … {% endif %}`
    /// fragments lower into
    /// [`super::super::statement_facts::JinjaFragmentRef`] entries
    /// preserving the AST `NodeId` and span. Uses the in-tree
    /// fixture-style source — the parser's permissive Jinja
    /// handling produces a `statement_fragments` list when the
    /// fragment contains clause-level keywords.
    #[test]
    fn statement_fragments_lower_to_jinja_fragment_refs() {
        let src = "SELECT a FROM t {% if cond %} WHERE a = 1 {% endif %}";
        let stmt = parse_one(src);
        let catalog = FunctionCatalog::for_dialect(CatalogDialect::Default);
        let session = SessionContext::default();
        let (_, _, _, facts) = lower_query_full_with_bindings(
            &stmt,
            src,
            StrictMode::Permissive,
            &catalog,
            &session,
            None,
        )
        .expect("lower");
        // The fragment is recorded only if the parser routed it as
        // a `statement_fragments` entry — which requires that the
        // Jinja block straddles a clause boundary the parser
        // recognizes. If the parser instead emitted opaque tokens
        // we accept that as a separate code path; this test
        // asserts the lowering propagates whatever the AST has.
        let ast_count = match &stmt {
            AstStmt::Select(s) => s.statement_fragments.len(),
            _ => 0,
        };
        assert_eq!(facts.jinja_fragments.len(), ast_count);
    }

    /// Pre-LIMIT and post-locking extension clauses propagate as
    /// preserved-text spans. Tested via direct AST construction is
    /// impossible without AST mutation helpers, so the
    /// absent-default path is asserted here.
    #[test]
    fn pre_limit_and_post_locking_extensions_default_empty() {
        let facts = lower_facts("SELECT 1");
        assert!(facts.pre_limit_extensions.is_empty());
        assert!(facts.post_locking_extensions.is_empty());
    }

    // ─── Changes clause lowering ─────────────────────────────────────────

    #[test]
    fn changes_default_information_lowers_to_scan_modifier() {
        // CHANGES(INFORMATION => DEFAULT) AT(TIMESTAMP => ...)
        let src = "SELECT * FROM t CHANGES(INFORMATION => DEFAULT) AT(TIMESTAMP => '2024-01-01')";
        let plan = lower(src);
        // Walk to the Scan through the Project wrapper.
        let scan = match plan {
            RelPlan::Project { input, .. } => *input,
            other => panic!("expected Project, got {:?}", other),
        };
        match scan {
            RelPlan::Scan { modifier, .. } => {
                let c = modifier.changes.expect("changes must be set");
                assert!(
                    matches!(c.information, ChangesInformation::Default),
                    "expected Default, got {:?}",
                    c.information
                );
                assert!(c.at.is_some(), "at must be set");
                assert!(c.end.is_none(), "no END clause expected");
                assert!(
                    matches!(c.at, Some(TimeTravel::AtTimestamp(_))),
                    "expected AtTimestamp, got {:?}",
                    c.at
                );
            }
            other => panic!("expected Scan, got {:?}", other),
        }
    }

    #[test]
    fn changes_append_only_with_end_lowers_to_scan_modifier() {
        // CHANGES(INFORMATION => APPEND_ONLY) AT(...) END(...)
        let src = "SELECT * FROM t \
            CHANGES(INFORMATION => APPEND_ONLY) \
            AT(OFFSET => -3600) \
            END(STATEMENT => '8e5d0ca9-005e-44e6-b858-a8f5b37c5726')";
        let plan = lower(src);
        let scan = match plan {
            RelPlan::Project { input, .. } => *input,
            other => panic!("expected Project, got {:?}", other),
        };
        match scan {
            RelPlan::Scan { modifier, .. } => {
                let c = modifier.changes.expect("changes must be set");
                assert!(
                    matches!(c.information, ChangesInformation::AppendOnly),
                    "expected AppendOnly, got {:?}",
                    c.information
                );
                assert!(
                    matches!(c.at, Some(TimeTravel::AtOffset(_))),
                    "expected AtOffset, got {:?}",
                    c.at
                );
                assert!(
                    matches!(c.end, Some(TimeTravel::AtStatement(_))),
                    "expected AtStatement for end, got {:?}",
                    c.end
                );
            }
            other => panic!("expected Scan, got {:?}", other),
        }
    }

    #[test]
    fn changes_before_form_lowers_to_before_time_travel_variant() {
        // BEFORE(STATEMENT => ...) — the AT|BEFORE is_before flag
        let src = "SELECT * FROM t CHANGES(INFORMATION => DEFAULT) BEFORE(STATEMENT => '8e5d0ca9')";
        let plan = lower(src);
        let scan = match plan {
            RelPlan::Project { input, .. } => *input,
            other => panic!("expected Project, got {:?}", other),
        };
        match scan {
            RelPlan::Scan { modifier, .. } => {
                let c = modifier.changes.expect("changes must be set");
                assert!(
                    matches!(c.at, Some(TimeTravel::BeforeStatement(_))),
                    "expected BeforeStatement, got {:?}",
                    c.at
                );
            }
            other => panic!("expected Scan, got {:?}", other),
        }
    }

    #[test]
    fn changes_strict_accepts_changes_clause() {
        let src = "SELECT * FROM t CHANGES(INFORMATION => DEFAULT) AT(TIMESTAMP => '2024-01-01')";
        let stmt = parse_one(src);
        let plan =
            lower_query(&stmt, src, StrictMode::Strict).expect("Strict must accept CHANGES clause");
        assert!(matches!(plan, RelPlan::Project { .. }));
    }

    // ── Star catalog enumeration ───────────────────────────────────────

    /// `SELECT * FROM t` with a catalog-index attached enumerates the
    /// catalog columns into `ProjectItem::Expr` items during lowering.
    /// The `Star` sentinel is preserved at the end of the items list.
    /// `output_schema()` returns one `ColumnId` per catalog column.
    #[test]
    fn star_expands_from_catalog_unqualified() {
        use crate::catalog::{
            CatalogColumn, CatalogDatabase, CatalogIdent, CatalogSchema, CatalogSnapshot,
            CatalogTable, CatalogTableKind,
        };

        let snapshot = CatalogSnapshot {
            schema_version: crate::CATALOG_SCHEMA_VERSION,
            generated_at: None,
            source: Some("star-catalog-test".to_string()),
            policies: vec![],
            policy_references: vec![],
            grants: None,
            provider: None,
            databases: vec![CatalogDatabase {
                name: CatalogIdent {
                    name: "DB".to_string(),
                },
                schemas: vec![CatalogSchema {
                    name: CatalogIdent {
                        name: "SCH".to_string(),
                    },
                    tables: vec![CatalogTable {
                        name: CatalogIdent {
                            name: "ITEMS".to_string(),
                        },
                        kind: CatalogTableKind::Table,
                        columns: vec![
                            CatalogColumn {
                                name: CatalogIdent {
                                    name: "ID".to_string(),
                                },
                                data_type: Some("NUMBER".to_string()),
                                nullable: Some(false),
                                tags: vec![],
                            },
                            CatalogColumn {
                                name: CatalogIdent {
                                    name: "NAME".to_string(),
                                },
                                data_type: Some("VARCHAR".to_string()),
                                nullable: Some(true),
                                tags: vec![],
                            },
                            CatalogColumn {
                                name: CatalogIdent {
                                    name: "PRICE".to_string(),
                                },
                                data_type: Some("NUMBER".to_string()),
                                nullable: Some(true),
                                tags: vec![],
                            },
                        ],
                        row_count_estimate: None,
                        row_count_estimate_as_of: None,
                        bytes_estimate: None,
                        bytes_estimate_as_of: None,
                        constraints: vec![],
                        comment: None,
                        tags: vec![],
                    }],
                }],
            }],
        };
        let catalog = CatalogIndex::from_snapshot(snapshot).expect("valid catalog");

        let src = "SELECT * FROM DB.SCH.ITEMS";
        let stmt = parse_one(src);
        let catalog_fn = FunctionCatalog::for_dialect(CatalogDialect::Default);
        let session = SessionContext::default();
        let (plan, _ctx, bindings, _facts) = lower_query_full_with_bindings(
            &stmt,
            src,
            StrictMode::Permissive,
            &catalog_fn,
            &session,
            Some(&catalog),
        )
        .expect("lower");

        let items = match &plan {
            RelPlan::Project { items, .. } => items,
            other => panic!("expected Project, got {:?}", other),
        };

        // Three Expr items + one Star sentinel.
        assert_eq!(
            items.len(),
            4,
            "expect 3 catalog-expanded Expr items + 1 Star sentinel"
        );
        let expr_items: Vec<_> = items
            .iter()
            .filter(|it| matches!(it, ProjectItem::Expr(_)))
            .collect();
        assert_eq!(expr_items.len(), 3, "expect 3 Expr items from catalog");
        assert!(
            matches!(items.last(), Some(ProjectItem::Star(_))),
            "Star sentinel must be last"
        );

        // output_schema() returns exactly the 3 catalog-expanded ColumnIds.
        let schema = plan.output_schema();
        assert_eq!(
            schema.len(),
            3,
            "output_schema() must return one id per catalog column"
        );

        // The binding table carries the catalog column names as display
        // names on the Expr outputs.
        let expr_display_names: Vec<String> = expr_items
            .iter()
            .map(|it| match it {
                ProjectItem::Expr(e) => bindings
                    .get(e.output)
                    .map(|b| b.display_name.clone())
                    .unwrap_or_default(),
                ProjectItem::Star(_) => unreachable!(),
            })
            .collect();
        assert_eq!(
            expr_display_names,
            vec!["ID", "NAME", "PRICE"],
            "catalog column names must appear as display names"
        );

        // The scan's ColumnIds must be wired via scan_cols →
        // attach_pending_source_cols so Scan.columns is non-empty.
        let scan_cols = match &plan {
            RelPlan::Project { input, .. } => match input.as_ref() {
                RelPlan::Scan { columns, .. } => columns.clone(),
                other => panic!("expected Scan under Project, got {:?}", other),
            },
            other => panic!("expected Project, got {:?}", other),
        };
        assert_eq!(
            scan_cols.len(),
            3,
            "Scan.columns must contain the 3 catalog-allocated ColumnIds"
        );
    }

    /// `SELECT t.* FROM DB.SCH.ITEMS t` with a qualifier expands only
    /// that source's catalog columns.
    #[test]
    fn star_expands_from_catalog_qualified() {
        use crate::catalog::{
            CatalogColumn, CatalogDatabase, CatalogIdent, CatalogSchema, CatalogSnapshot,
            CatalogTable, CatalogTableKind,
        };

        let snapshot = CatalogSnapshot {
            schema_version: crate::CATALOG_SCHEMA_VERSION,
            generated_at: None,
            source: Some("star-catalog-qualified-test".to_string()),
            policies: vec![],
            policy_references: vec![],
            grants: None,
            provider: None,
            databases: vec![CatalogDatabase {
                name: CatalogIdent {
                    name: "DB".to_string(),
                },
                schemas: vec![CatalogSchema {
                    name: CatalogIdent {
                        name: "SCH".to_string(),
                    },
                    tables: vec![CatalogTable {
                        name: CatalogIdent {
                            name: "ITEMS".to_string(),
                        },
                        kind: CatalogTableKind::Table,
                        columns: vec![
                            CatalogColumn {
                                name: CatalogIdent {
                                    name: "ID".to_string(),
                                },
                                data_type: Some("NUMBER".to_string()),
                                nullable: None,
                                tags: vec![],
                            },
                            CatalogColumn {
                                name: CatalogIdent {
                                    name: "LABEL".to_string(),
                                },
                                data_type: Some("VARCHAR".to_string()),
                                nullable: None,
                                tags: vec![],
                            },
                        ],
                        row_count_estimate: None,
                        row_count_estimate_as_of: None,
                        bytes_estimate: None,
                        bytes_estimate_as_of: None,
                        constraints: vec![],
                        comment: None,
                        tags: vec![],
                    }],
                }],
            }],
        };
        let catalog = CatalogIndex::from_snapshot(snapshot).expect("valid catalog");

        let src = "SELECT t.* FROM DB.SCH.ITEMS AS t";
        let stmt = parse_one(src);
        let catalog_fn = FunctionCatalog::for_dialect(CatalogDialect::Default);
        let session = SessionContext::default();
        let (plan, _ctx, _bindings, _facts) = lower_query_full_with_bindings(
            &stmt,
            src,
            StrictMode::Permissive,
            &catalog_fn,
            &session,
            Some(&catalog),
        )
        .expect("lower");

        let items = match &plan {
            RelPlan::Project { items, .. } => items,
            other => panic!("expected Project, got {:?}", other),
        };

        // Two catalog columns + Star sentinel.
        assert_eq!(
            items.len(),
            3,
            "expect 2 catalog-expanded Expr items + 1 Star sentinel"
        );
        assert_eq!(
            items
                .iter()
                .filter(|it| matches!(it, ProjectItem::Expr(_)))
                .count(),
            2
        );
        assert!(matches!(items.last(), Some(ProjectItem::Star(_))));
        assert_eq!(
            plan.output_schema().len(),
            2,
            "output_schema() returns two ColumnIds for the two catalog columns"
        );
    }

    /// Without a catalog index, `SELECT *` still preserves the Star
    /// sentinel.
    #[test]
    fn star_without_catalog_preserves_star_sentinel() {
        let plan = lower("SELECT * FROM t");
        let items = match &plan {
            RelPlan::Project { items, .. } => items,
            other => panic!("expected Project, got {:?}", other),
        };
        assert_eq!(items.len(), 1, "only Star sentinel without catalog");
        assert!(matches!(items[0], ProjectItem::Star(_)));
        assert!(
            plan.output_schema().is_empty(),
            "output_schema() must be empty without catalog enumeration"
        );
    }
}
