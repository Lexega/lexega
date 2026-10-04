// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! IR-native flat-fact projection from [`RelPlan`].
//!
//! This module computes the flat per-statement fact view directly
//! from a statement's lowered [`RelPlan`]. The IR is canonical: every
//! field's semantics are defined on the [`DerivedFacts`] field itself.
//!
//! ## What `derive_facts_from_plan` returns
//!
//! A [`DerivedFacts`]. Each field has one of three scope
//! dispositions:
//!
//! - **Outer-only** — set by the outermost owning node along the
//!   scope-preserving spine (e.g. `has_where`, `has_distinct`,
//!   `group_by`, `order_by`, `limit_offset`,
//!   `select_output_columns`, `star_projections`).
//! - **Any-scope (OR over the tree)** — true iff some node anywhere
//!   in the plan satisfies the predicate (`has_implicit_cross_join`,
//!   `has_join_predicate_filters`, `has_any_filter`, `has_sample`).
//! - **Per-scope-set (flat union)** — every contribution from every
//!   scope (`tables_read`, `tables_written`, `aggregates`,
//!   `window_functions`, `column_refs`, predicate facts, etc.).
//!
//! ## Non-goals
//!
//! - Not a full `diff` baseline.
//! - Not an analysis; no constraint / taint / nullability reasoning.
//! - Not user-visible; this is internal projection infrastructure.
//!
//! ## Closed-enum discipline
//!
//! The walk over [`RelPlan`] / [`ScalarExpr`] here is exhaustive —
//! every variant is listed explicitly. Adding a new variant fails
//! to compile until this projection decides what the variant
//! contributes. Without exhaustiveness, contract drift is silent.

use std::cell::RefCell;
use std::collections::{BTreeSet, HashMap, HashSet};

use crate::context::node_metadata::{
    AggregateFact, ColumnRef, GroupByFact, HavingFact, IdentKey, IdentName, JoinEdge,
    JoinKind as MetadataJoinKind, LimitFact, NullsOrdering, OrderByFact, PredicateFact,
    ProjectionItemFact, ProjectionItemKind, ScopedPredicateFact, SetOperation, SetOperationFact,
    StarProjectionInfo, StarRenameMapping, TableRef, WindowFunctionFact,
};
use crate::ir::column::{BindingTable, ColumnId};
use crate::ir::expression_fact::{build_scan_index, scalar_to_expression_fact, ScanIndex};
use crate::ir::normalize_identifier;
use crate::ir::plan::{
    AggregateCall, ChangesClause, ChangesInformation, CteBody, FilterKind, FrameBound, FrameMode,
    GroupKey, GroupingSpec, InsertSource, JoinKind, OriginHint, ProjectItem, ProjectStar, RelPlan,
    ScanModifier, SetOpKind, StarQualifier, TimeTravel, WindowCall,
};
use crate::ir::predicate_extraction::{column_id_to_ref, resolved_func_name, span_text};
use crate::ir::scalar::{FieldStep, Lit, QuantifiedRhs, ScalarExpr};
use crate::lexer::Span;

/// Plan-level read-only context threaded through [`walk`] for
/// projecting [`ScalarExpr`] sub-expressions onto
/// [`crate::context::node_metadata::ExpressionFact`] when needed
/// (e.g. [`JoinEdge::on_clause`] in the Join arm). Bundled into a
/// single struct so the walk signature does not grow further.
///
/// `agg_acc` accumulates `AggregateFact`s from every `RelPlan::Aggregate`
/// node encountered during the walk, including those inside CTE bodies.
/// The list is flat across all scopes.
///
/// `alias_map` maps each aggregate `output: ColumnId` to the alias
/// string from the enclosing `Project` item, populated by a pre-pass
/// over all `ProjectItem::Expr` entries in the plan tree.
///
/// `wf_acc` accumulates `WindowFunctionFact`s from every
/// `RelPlan::Window` node encountered during the walk, flat across all
/// scopes.
struct WalkCtx<'a> {
    bindings: &'a BindingTable,
    scan_index: &'a ScanIndex,
    source: &'a str,
    agg_acc: RefCell<Vec<AggregateFact>>,
    wf_acc: RefCell<Vec<WindowFunctionFact>>,
    alias_map: HashMap<ColumnId, Option<String>>,
}
/// The flat per-statement facts derived from [`RelPlan`].
///
/// Field semantics are defined per-field below; values are derived
/// solely by [`derive_facts_from_plan`].
///
/// ## Scope-disposition summary
///
/// - **Outer-only** booleans/structs (`has_where`, `has_distinct`,
///   `has_group_by`, `has_qualify`, `has_limit`, `limit_value`,
///   `order_by`, `limit_offset`, `group_by`, `having`,
///   `has_aggregates`, `immediate_join_count`,
///   `select_output_columns`, `star_projections`) — set by the
///   outermost owning node along the scope-preserving spine.
///   Sub-scopes (CTE bodies, derived tables, scalar subqueries,
///   set-op branches, DML sub-sources) do not contribute.
/// - **Any-scope** booleans (`has_implicit_cross_join`,
///   `has_tautology_where`) — true iff some node anywhere in the
///   plan satisfies the predicate. `has_tautology_where` has a
///   narrow form (top-level DML only).
/// - **Per-scope-set** lists (`tables_read`, `tables_written`,
///   `cte_names`, `set_operations`, `join_edges`,
///   `where_predicates`, `having_predicates`, `scoped_predicates`,
///   `aggregates`, `window_functions`, `column_refs`) — collected
///   across all scopes via shared accumulators in `walk`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerivedFacts {
    /// Base-table reads, sorted and deduplicated. `TableRef::eq` is
    /// case-normalized so matching is quote-aware.
    pub tables_read: Vec<TableRef>,

    /// DML write targets, sorted and deduplicated using the same
    /// case-normalized [`TableRef`] equality as [`tables_read`](Self::tables_read).
    /// Populated for [`RelPlan::Insert`] / [`RelPlan::Update`] /
    /// [`RelPlan::Delete`] / [`RelPlan::Merge`] / [`RelPlan::MultiInsert`]
    /// targets and propagated up through enclosing scopes
    /// (`WithScope`, `Explain`, `DerivedTable`, `SetOp` branches)
    /// the same way [`tables_read`](Self::tables_read) is.
    ///
    /// CREATE-as-query DDL targets are intentionally **not** included.
    pub tables_written: Vec<TableRef>,

    /// True iff the query has a `WHERE` clause. `HAVING` is a distinct
    /// concept and tracked by [`has_aggregates`](Self::has_aggregates) / [`has_group_by`](Self::has_group_by).
    pub has_where: bool,

    /// True iff the query has a `QUALIFY` clause. `QUALIFY` shares the
    /// `RelPlan::Filter` relational shape with `WHERE`; the two are
    /// disambiguated by `FilterKind` so signal rules can key on one vs
    /// the other.
    pub has_qualify: bool,

    /// True iff the query has a `GROUP BY` clause (any variant —
    /// standard, CUBE, ROLLUP, GROUPING SETS, ALL).
    pub has_group_by: bool,

    /// True iff the immediate query scope contains a row-count
    /// cap (`LIMIT n`, `FETCH FIRST n ROWS`, T-SQL `TOP n`). All
    /// three lower to [`RelPlan::Limit`]; the distinction between
    /// syntactic forms is purely lexical and not preserved here.
    /// Scope propagation matches the other
    /// scalar flags: a `Limit` inside a CTE body / `SetOp` branch /
    /// `DerivedTable` does not set the enclosing scope's flag.
    pub has_limit: bool,

    /// The literal `LIMIT` value if it parses as a non-negative
    /// integer (e.g. `LIMIT 10`, `FETCH FIRST 50 ROWS ONLY`,
    /// `TOP 100`). `None` when:
    ///   - The scope has no `Limit` node ([`has_limit`](Self::has_limit) is false);
    ///   - The limit is an expression rather than a literal
    ///     (e.g. `LIMIT :n`, `LIMIT a + b`, `LIMIT @rows`);
    ///   - The literal does not parse as a [`u64`] (overflow, sign
    ///     prefix already rejected at parse time but defensive).
    ///
    /// Same shape as [`LimitFact`]'s `limit_value`.
    pub limit_value: Option<u64>,

    /// Structured `ORDER BY` fact for the outer query scope.
    pub order_by: Option<OrderByFact>,

    /// Structured `LIMIT/OFFSET` fact for the outer query scope.
    pub limit_offset: Option<LimitFact>,

    /// True iff the projection is `SELECT DISTINCT`.
    pub has_distinct: bool,

    /// True iff the plan contains an implicit cross-join (comma-FROM
    /// cartesian: `SELECT … FROM a, b`) on a non-LATERAL right-hand
    /// source. Discriminated from explicit `CROSS JOIN` keyword joins
    /// by the `RelPlan::Join.implicit` field and from
    /// `FROM a, LATERAL (...)` by the `lateral` field. The RHS may
    /// be any source variant (Scan, CteRef, Project-wrapped,
    /// DerivedTable, etc.) — the cartesian-product cost is per-row
    /// and does not depend on what wraps the RHS.
    pub has_implicit_cross_join: bool,

    /// True iff some `RelPlan::Join.on` clause anywhere in the plan
    /// tree contains a column-vs-literal comparison (a "filter
    /// predicate" rather than a "table tie"). Comparison set: `=`,
    /// `<>`, `<`, `<=`, `>`, `>=`. AND-chains are descended; OR is not.
    /// Used by `Q-SCAN-NOFILT` to distinguish unfiltered cross-table
    /// scans from joins that carry real filtering. See
    /// `compute_combined_post_walk_facts`.
    pub has_join_predicate_filters: bool,

    /// True iff the statement's outer-scope WHERE / ON predicate is a
    /// syntactic tautology — `WHERE 1=1`, `WHERE TRUE`,
    /// `WHERE x IS NOT NULL OR x IS NULL`, etc. Set for every
    /// query-bearing kind: UPDATE / DELETE's `WHERE`, MERGE's `ON`,
    /// and SELECT / INSERT…SELECT / CTAS / CVAS / CMVAS's outer
    /// `Filter { kind: Where }`. Subqueries, CTE bodies, and
    /// derived-table bodies are not considered.
    pub has_tautology_where: bool,

    /// True iff the query contains any aggregate calls (either via an
    /// explicit `GROUP BY` or implicit aggregation like
    /// `SELECT COUNT(*) FROM t`).
    pub has_aggregates: bool,

    /// Count of `JOIN` nodes in the *top-level* query scope (not
    /// inside subqueries, CTEs, or `SetOp` branches). Lowering
    /// does not descend into subquery FROM items, and
    /// `walk` treats each `SetOp` branch as an independent scope,
    /// so the "immediate" qualifier is automatically satisfied.
    pub immediate_join_count: usize,

    /// Names of CTEs visible at the outer query scope, sorted for
    /// set-equality comparison. **Per-scope-set** disposition with
    /// outer-scope provenance.
    ///
    /// Scope rules:
    /// a CTE definition contributes iff it appears in a
    /// [`RelPlan::WithScope`] reachable through scope-preserving
    /// wrappers from the root, *or* through `SetOp.inputs[i]`
    /// branches (UNION arms share a CTE definition scope).
    /// CTEs defined inside a [`RelPlan::DerivedTable`] input,
    /// inside another CTE's body, inside a scalar subquery, or
    /// inside a DML sub-source do NOT propagate — those are scope
    /// boundaries.
    pub cte_names: Vec<String>,

    /// Pairwise set-operation events in document order.
    /// **Per-scope-set** disposition.
    ///
    /// Each [`RelPlan::SetOp`] of arity `n` contributes `n - 1`
    /// [`SetOperationFact`] entries with `branch_count: 2`.
    /// (`A UNION B UNION C` lowered to a single `SetOp` of arity 3
    /// expands to two pairwise events. The truthful arity stays
    /// available on the IR for direct consumers.)
    ///
    /// Order discipline: branches are walked first so nested
    /// set-ops appear in document order before the enclosing
    /// operator's own events.
    ///
    /// Scope rules: shared accumulator across all scopes; nested
    /// set-ops inside CTE bodies / derived tables / DML
    /// sub-sources contribute alongside the outer scope's events.
    pub set_operations: Vec<SetOperationFact>,

    /// Pairwise base-table join edges in document order.
    /// **Per-scope-set** disposition with `containing_cte`
    /// provenance.
    ///
    /// Each [`RelPlan::Join`] contributes one [`JoinEdge`] iff both
    /// `left` and `right` resolve to a single principal base-table
    /// reference (via `principal_table`); joins over TVFs,
    /// `VALUES`, derived tables, etc. emit no edge. `containing_cte`
    /// is set from the immediately enclosing [`RelPlan::WithScope`]
    /// binding when the join lives inside a CTE body. `on_clause`
    /// is projected through
    /// [`crate::ir::expression_fact::scalar_to_expression_fact`].
    /// `union_branch_index` is `None` on IR-projected edges (not
    /// derivable from the flattened IR `SetOp` spine).
    ///
    /// Scope rules: shared accumulator across all scopes — joins
    /// inside CTE bodies / derived tables / DML sub-sources fold
    /// into the outer statement's edge set, distinguished only by
    /// `containing_cte`.
    pub join_edges: Vec<JoinEdge>,

    /// Predicates extracted from `WHERE` clauses.
    /// **Per-scope-set** disposition. Populated by
    /// [`crate::ir::predicate_extraction::extract_predicates_from_plan`].
    ///
    /// `PartialEq` on [`PredicateFact`] compares the semantically
    /// stable subset — see that type's `PartialEq` impl for the
    /// excluded fields.
    pub where_predicates: Vec<PredicateFact>,

    /// Predicates extracted from `HAVING` clauses.
    /// **Per-scope-set** disposition.
    pub having_predicates: Vec<PredicateFact>,

    /// Scope-aware predicates (main query + CTE bodies + derived
    /// tables + subqueries). **Per-scope-set** disposition with
    /// scope provenance.
    pub scoped_predicates: Vec<ScopedPredicateFact>,

    /// Aggregate function calls, flat across every scope (top
    /// level, CTE bodies, derived tables, set-op branches, DML
    /// sub-sources). **Per-scope-set** disposition. Used by the
    /// diff engine for alias-matched script-level changes — *not*
    /// a "is this an aggregating query?" signal (that role is
    /// `immediate_has_aggregates`).
    ///
    /// `PartialEq` on [`AggregateFact`] compares the semantically
    /// stable subset.
    pub aggregates: Vec<AggregateFact>,

    /// `GROUP BY` fact for the outer query scope only.
    /// **Outer-only** disposition. `None` when the outer query has
    /// no `GROUP BY` clause (implicit aggregation or no aggregation).
    ///
    /// `PartialEq` on [`GroupByFact`] uses sorted-set comparison
    /// for the column/expression lists.
    pub group_by: Option<GroupByFact>,

    /// `HAVING` fact for the outer query scope only.
    /// **Outer-only** disposition. `None` when no `HAVING` clause is
    /// present.
    ///
    /// `PartialEq` on [`HavingFact`] compares `expression` and
    /// `aggregate_functions`; `columns` is excluded (structural
    /// gap — see `HavingFact::PartialEq` doc).
    pub having: Option<HavingFact>,

    /// Window function calls, flat across every scope.
    /// **Per-scope-set** disposition.
    /// `PartialEq` on [`WindowFunctionFact`] compares the
    /// semantically stable subset.
    pub window_functions: Vec<WindowFunctionFact>,

    /// Star projections (`SELECT *` / `SELECT t.*`) on the outer
    /// query's pure-star projection items. **Outer-only**
    /// disposition.
    ///
    /// Owned by the outer-most `Project` node. Inline stars in
    /// mixed projection lists (`SELECT a, t.*, b`) are excluded
    /// (`top_level_pure: false` on the IR side filters them out)
    /// because they are scope-local syntactic sugar that does not
    /// participate in output-schema diffing. Stars inside CTE
    /// bodies / derived tables / subqueries / set-op branches do
    /// not propagate to the outer scope; the canonical
    /// "stars seen anywhere" view is provided by `column_refs`'s
    /// per-scope `*` markers.
    ///
    /// Per-entry shape: `qualifier` slices the first identifier of
    /// the qualifier path's source span (preserving quotes and case);
    /// `excluded_columns`, `replaced_columns`, and `renames` slice
    /// their respective spans the same way; `ilike_pattern` is the
    /// SQL-string-decoded pattern (enclosing single-quotes stripped,
    /// `''`→`'` unescaped). `resolved_table` is set when the
    /// qualifier matches a base-table `Scan`'s alias (or its
    /// table-name's last component when unaliased) reachable
    /// through scope-preserving wrappers below the outer `Project`.
    pub star_projections: Vec<StarProjectionInfo>,

    /// Every `ColumnRef` syntactically appearing anywhere in the
    /// plan tree, plus a synthetic `*` marker per pure-star
    /// projection per scope. **Per-scope-set** disposition.
    ///
    /// The walk descends through every relational child (CTE
    /// bodies, derived tables, set-op branches, DML sub-sources)
    /// and into every `ScalarExpr` (subqueries, aggregate args,
    /// window args, ON / USING / RETURNING). For every scope
    /// containing a pure-star `Project.items[i] = Star { top_level_pure: true, .. }`,
    /// one synthetic `ColumnRef { name: "*", qualifier,
    /// resolved_table }` marker is pushed.
    ///
    /// This is the canonical "syntactic mentions across the whole
    /// statement" view. A risk rule asking *"is `password`
    /// referenced anywhere in this query?"* answers yes when the
    /// column appears in any scope — including inside a CTE body,
    /// derived table, subquery, or any clause.
    ///
    /// Entries compare via `ColumnRef::PartialEq` (normalized name +
    /// canonical resolved-table or normalized qualifier). The list
    /// is not deduplicated: per-encounter pushes may repeat an entry.
    pub column_refs: Vec<ColumnRef>,

    /// Output columns of the outer SELECT's projection items —
    /// not WHERE / JOIN / GROUP BY / etc. **Outer-only**
    /// disposition. Used by the diff engine for
    /// `ColumnAdded` / `ColumnRemoved` signals.
    ///
    /// Star projection items expand against inner schemas
    /// (`RelPlan::CteRef.columns`, `DerivedTable.columns`,
    /// `SetOp.output_columns`, `Aggregate.output_columns`).
    /// Catalog-driven base-table star enumeration is **not** part
    /// of this field.
    pub select_output_columns: Vec<ColumnRef>,

    /// Typed projection-item facts for the outermost `Project` node.
    /// **Outer-only** disposition. One entry per projection item in
    /// source order; each non-Star item carries the `ColumnId`
    /// allocated by lowering for that output slot, so the diff
    /// substrate can pair items by stable identity (the same identity
    /// the per-output analyses events — `NullabilityChanged` /
    /// `LineageChanged` / `TaintChanged` — already key on).
    ///
    /// Distinct from [`Self::select_output_columns`] (which is
    /// narrowed to projection items resolving to a `ColumnRef`) and
    /// from [`Self::star_projections`] (which captures only star
    /// items): `projection_items` is the *complete* typed view of
    /// what the outermost SELECT projects. Literal projections
    /// (`SELECT 1`), function-call projections (`SELECT now()`), and
    /// arbitrary expression projections (`SELECT a + b`) all flow
    /// through here, giving the diff engine a structural signal for
    /// the projection's content that the other two fields can't
    /// produce.
    pub projection_items: Vec<ProjectionItemFact>,

    /// FROM-list aliases for the outer query scope only. **Outer-only**
    /// disposition. Each [`RelPlan::Scan`] reachable through
    /// scope-preserving wrappers and [`RelPlan::Join`] children of the
    /// outer scope contributes one entry: key is `alias` when set,
    /// otherwise the [`TableRef::name`] (last-component bare name);
    /// value is the [`TableRef`] itself. Non-table sources
    /// (`Values` / `CteRef` / `ModelRef` / `TableFunction` /
    /// `DerivedTable`), `SetOp` branches, and any DML / DDL roots are
    /// scope boundaries — they do not contribute.
    pub table_aliases: HashMap<IdentKey, TableRef>,

    /// Tables on the nullable side of an outer join, anywhere in the
    /// plan tree. **Per-scope-set** disposition. Each
    /// [`RelPlan::Join`] contributes per
    /// [`JoinKind`]: `LeftOuter` adds the right subtree's identifier;
    /// `RightOuter` adds the leftmost-source identifier of the left
    /// subtree (the FROM-list anchor for chained
    /// joins); `FullOuter` adds both. Identifiers are
    /// case-normalized (alias when set, otherwise the source's bare
    /// name).
    pub nullable_tables: HashSet<String>,

    /// Columns appearing inside `IS NULL` (not `IS NOT NULL`) checks
    /// in any `Filter { kind: Where }` predicate, anywhere in the
    /// plan tree. **Per-scope-set** disposition. Stored
    /// in both unqualified (`name`) and qualified (`qualifier.name`)
    /// forms — the qualified form is added only when the user
    /// originally wrote a qualifier (detected by source-text slicing
    /// of [`ScalarExpr::Column`]'s span). Walks `BinOp` recursively
    /// inside the predicate; non-binary-non-IsNull operators do not
    /// contribute.
    pub columns_in_is_null: HashSet<String>,

    /// `(qualifier, column)` pairs from `IS NOT NULL` checks under
    /// AND-only chains in any `Filter { kind: Where }`,
    /// anywhere in the plan tree. **Per-scope-set** disposition.
    /// Qualifier is the case-normalized
    /// qualifier-as-written (full path for multi-part references,
    /// empty string for unqualified). Inside an OR branch an
    /// `IS NOT NULL` does NOT contribute — the AND-only semantic
    /// avoids claiming non-NULL guarantees that don't hold.
    pub columns_filtered_not_null: HashSet<(String, String)>,
}

impl DerivedFacts {
    pub fn empty() -> Self {
        Self {
            tables_read: Vec::new(),
            tables_written: Vec::new(),
            has_where: false,
            has_qualify: false,
            has_group_by: false,
            has_limit: false,
            limit_value: None,
            order_by: None,
            limit_offset: None,
            has_distinct: false,
            has_implicit_cross_join: false,
            has_join_predicate_filters: false,
            has_tautology_where: false,
            has_aggregates: false,
            immediate_join_count: 0,
            cte_names: Vec::new(),
            set_operations: Vec::new(),
            join_edges: Vec::new(),
            where_predicates: Vec::new(),
            having_predicates: Vec::new(),
            scoped_predicates: Vec::new(),
            aggregates: Vec::new(),
            group_by: None,
            having: None,
            window_functions: Vec::new(),
            star_projections: Vec::new(),
            column_refs: Vec::new(),
            select_output_columns: Vec::new(),
            projection_items: Vec::new(),
            table_aliases: HashMap::new(),
            nullable_tables: HashSet::new(),
            columns_in_is_null: HashSet::new(),
            columns_filtered_not_null: HashSet::new(),
        }
    }
}

/// Project a lowered [`RelPlan`] to the IR-native flat-fact view.
///
/// Each output field is outer-only, any-scope, or per-scope-set (see
/// [`DerivedFacts`]). The walk classifies each `RelPlan` variant:
/// scope-preserving wrappers carry outer-only context, scope
/// boundaries reset it.
///
/// Per-scope-set fields (`tables_read`, `tables_written`,
/// `aggregates`, `window_functions`, `set_operations`, `join_edges`,
/// `cte_names`, predicate facts) collect across every relational
/// scope including CTE bodies, derived tables, set-op branches, and
/// DML sub-sources — and via `walk_scalar` into every `ScalarExpr`
/// subquery (`Exists`, `ScalarSubquery`, `QuantifiedCmp::Subquery`).
/// Outer-only fields are set only at the outermost owning node and
/// are computed against scratch [`DerivedFacts`] inside sub-scopes
/// so their flag-state never leaks out.
pub fn derive_facts_from_plan(
    source: &str,
    plan: &RelPlan,
    bindings: &BindingTable,
    func_catalog: &crate::ir::catalog::FunctionCatalog,
    catalog: Option<&dyn crate::ir::catalog_context::CatalogContext>,
    reasoning: &dyn crate::facts::reasoning::Reasoning,
) -> DerivedFacts {
    let mut out = DerivedFacts::empty();
    let mut tables: BTreeSet<TableKey> = BTreeSet::new();
    let mut tables_written: BTreeSet<TableKey> = BTreeSet::new();
    let mut cte_refs: HashSet<IdentKey> = HashSet::new();
    let mut cte_names: HashSet<IdentKey> = HashSet::new();
    let mut set_operations: Vec<SetOperationFact> = Vec::new();
    let mut join_edges: Vec<JoinEdge> = Vec::new();
    let scan_index = build_scan_index(plan);
    let alias_map = build_alias_map(plan);
    let ctx = WalkCtx {
        bindings,
        scan_index: &scan_index,
        source,
        agg_acc: RefCell::new(Vec::new()),
        wf_acc: RefCell::new(Vec::new()),
        alias_map,
    };
    walk(
        plan,
        &mut out,
        &mut tables,
        &mut tables_written,
        &mut cte_refs,
        &mut cte_names,
        &mut set_operations,
        &mut join_edges,
        None,
        &ctx,
    );
    out.tables_read = finalize_table_set(tables);
    out.tables_written = finalize_table_set(tables_written);
    out.cte_names = cte_names
        .into_iter()
        .map(|k| k.as_str().to_string())
        .collect();
    out.cte_names.sort();
    out.cte_names.dedup();
    out.set_operations = set_operations;
    out.join_edges = join_edges;
    let preds = crate::ir::predicate_extraction::extract_predicates_from_plan(
        source,
        plan,
        bindings,
        &scan_index,
        func_catalog,
    );
    out.where_predicates = preds.where_predicates;
    out.having_predicates = preds.having_predicates;
    out.scoped_predicates = preds.scoped_predicates;
    out.aggregates = ctx.agg_acc.into_inner();
    out.window_functions = ctx.wf_acc.into_inner();
    let (order_by, limit_offset) = project_outer_order_limit(source, plan, bindings, &scan_index);
    out.order_by = order_by;
    out.limit_offset = limit_offset.clone();
    out.limit_value = limit_offset.and_then(|lf| lf.limit_value);
    // One fused full-plan walk computes `has_implicit_cross_join`,
    // `has_join_predicate_filters`, `nullable_tables`,
    // `columns_in_is_null`, and `columns_filtered_not_null`.
    compute_combined_post_walk_facts(plan, source, bindings, &mut out);
    let proof = reasoning.non_null_proof(plan, bindings, catalog);
    out.has_tautology_where =
        super::always_true::has_tautology_where(plan, source, bindings, proof.as_deref());
    out.star_projections = compute_star_projections(plan, source);
    out.column_refs = compute_column_refs(plan, bindings, &scan_index);
    out.select_output_columns = compute_select_output_columns(plan, bindings, &scan_index);
    out.projection_items =
        compute_projection_items(plan, source, bindings, &scan_index, func_catalog);
    out.table_aliases = compute_table_aliases(plan);
    out
}

/// Project [`DerivedFacts::star_projections`] from `plan`.
///
/// Walks scope-preserving wrappers down from the root to find the
/// outer query's `Project` items (the immediate scope), then collects
/// every `ProjectItem::Star` whose `top_level_pure` is `true` — the
/// inline stars in mixed projection lists set the flag to `false` and
/// are excluded.
///
/// The walk does NOT descend into:
///   - `SetOp` branches: each branch is an independent scope and
///     `star_projections` does not propagate up across the union. The
///     combined statement therefore has empty `star_projections`.
///   - DML `source` / `from` / `using` sub-plans: INSERT / UPDATE /
///     DELETE / MERGE / MultiInsert / CreateAsQuery all surface as
///     empty at the top level even when the inner query has stars.
///   - `DerivedTable` inputs and scalar-subquery descents: scope
///     boundaries.
fn compute_star_projections(plan: &RelPlan, source: &str) -> Vec<StarProjectionInfo> {
    let Some((items, scope_input)) = find_outer_project(plan) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for item in items {
        if let ProjectItem::Star(s) = item {
            if !s.top_level_pure {
                continue;
            }
            out.push(project_star_info(s, source, scope_input));
        }
    }
    out
}

/// Project the outermost `Project` node's `items` to a list of typed
/// [`ProjectionItemFact`]s, in source order. One entry per projection
/// item — `Expr` items carry the lowering-allocated output `ColumnId`
/// and a typed [`ExpressionFact`] for the projection expression;
/// `Star` items embed the same [`StarProjectionInfo`] used by
/// [`DerivedFacts::star_projections`].
///
/// Returns the empty vec for statements whose outer relational shape
/// is not a `Project` (DML, set-operations, source-only, opaque, etc.)
/// — matching the disposition of [`compute_star_projections`] and
/// [`compute_select_output_columns`]. The diff substrate consumes this
/// at the `Project` granularity when pairing projection items.
/// Replace any `fn#<id>` placeholder names in a projected
/// [`ExpressionFact`] tree with the catalog's resolved
/// `display_name` (or the unchanged input when the id is forged or
/// not registered). Recursive; preserves all other variants verbatim.
fn resolve_function_names_in_expression_fact(
    expr: crate::context::node_metadata::ExpressionFact,
    catalog: &crate::ir::catalog::FunctionCatalog,
) -> crate::context::node_metadata::ExpressionFact {
    use crate::context::node_metadata::{CaseWhenFact, ExpressionFact};
    match expr {
        ExpressionFact::Function {
            name,
            args,
            is_distinct,
        } => {
            let resolved_name = resolve_fn_placeholder(&name, catalog).unwrap_or(name);
            ExpressionFact::Function {
                name: resolved_name,
                args: args
                    .into_iter()
                    .map(|a| resolve_function_names_in_expression_fact(a, catalog))
                    .collect(),
                is_distinct,
            }
        }
        ExpressionFact::Case {
            when_branches,
            else_expr,
        } => ExpressionFact::Case {
            when_branches: when_branches
                .into_iter()
                .map(|b| CaseWhenFact {
                    condition: Box::new(resolve_function_names_in_expression_fact(
                        *b.condition,
                        catalog,
                    )),
                    result: Box::new(resolve_function_names_in_expression_fact(
                        *b.result, catalog,
                    )),
                })
                .collect(),
            else_expr: else_expr
                .map(|e| Box::new(resolve_function_names_in_expression_fact(*e, catalog))),
        },
        ExpressionFact::BinaryOp {
            left,
            operator,
            right,
        } => ExpressionFact::BinaryOp {
            left: Box::new(resolve_function_names_in_expression_fact(*left, catalog)),
            operator,
            right: Box::new(resolve_function_names_in_expression_fact(*right, catalog)),
        },
        ExpressionFact::UnaryOp { operator, operand } => ExpressionFact::UnaryOp {
            operator,
            operand: Box::new(resolve_function_names_in_expression_fact(*operand, catalog)),
        },
        ExpressionFact::LogicalChain { operator, operands } => ExpressionFact::LogicalChain {
            operator,
            operands: operands
                .into_iter()
                .map(|o| resolve_function_names_in_expression_fact(o, catalog))
                .collect(),
        },
        ExpressionFact::InList {
            expr,
            values,
            negated,
        } => ExpressionFact::InList {
            expr: Box::new(resolve_function_names_in_expression_fact(*expr, catalog)),
            values: values
                .into_iter()
                .map(|v| resolve_function_names_in_expression_fact(v, catalog))
                .collect(),
            negated,
        },
        ExpressionFact::Like {
            kind,
            negated,
            expr,
            pattern,
            escape,
        } => ExpressionFact::Like {
            kind,
            negated,
            expr: Box::new(resolve_function_names_in_expression_fact(*expr, catalog)),
            pattern: Box::new(resolve_function_names_in_expression_fact(*pattern, catalog)),
            escape: escape
                .map(|e| Box::new(resolve_function_names_in_expression_fact(*e, catalog))),
        },
        ExpressionFact::Cast { expr, target_type } => ExpressionFact::Cast {
            expr: Box::new(resolve_function_names_in_expression_fact(*expr, catalog)),
            target_type,
        },
        ExpressionFact::Access { base, accessor } => ExpressionFact::Access {
            base: Box::new(resolve_function_names_in_expression_fact(*base, catalog)),
            accessor,
        },
        other @ (ExpressionFact::Column(_)
        | ExpressionFact::Literal { .. }
        | ExpressionFact::Subquery { .. }
        | ExpressionFact::Opaque { .. }) => other,
    }
}

/// Parse `FN#<id>` (case-insensitive) — the
/// [`ResolvedFunc::display_hint`] placeholder for catalog-resolved
/// function calls — and look up the catalog's display name. Returns
/// `None` for any other input or when the id is not registered.
fn resolve_fn_placeholder(
    name: &str,
    catalog: &crate::ir::catalog::FunctionCatalog,
) -> Option<String> {
    let stripped = name
        .strip_prefix("FN#")
        .or_else(|| name.strip_prefix("fn#"))?;
    let id_n: u32 = stripped.parse().ok()?;
    let id = crate::ir::catalog::FunctionId::from_index(id_n);
    catalog.signature(id).map(|sig| sig.display_name.clone())
}

fn compute_projection_items(
    plan: &RelPlan,
    source: &str,
    bindings: &BindingTable,
    scan_index: &ScanIndex,
    func_catalog: &crate::ir::catalog::FunctionCatalog,
) -> Vec<ProjectionItemFact> {
    let Some((items, scope_input)) = find_outer_project(plan) else {
        return Vec::new();
    };
    let mut out: Vec<ProjectionItemFact> = Vec::with_capacity(items.len());
    for item in items {
        match item {
            ProjectItem::Expr(e) => {
                let expression = scalar_to_expression_fact(&e.expr, bindings, scan_index);
                let expression =
                    resolve_function_names_in_expression_fact(expression, func_catalog);
                out.push(ProjectionItemFact {
                    column_id: Some(e.output),
                    alias: e.alias.clone(),
                    kind: ProjectionItemKind::Expr { expression },
                    span: e.span,
                });
            }
            ProjectItem::Star(s) => {
                let star_info = project_star_info(s, source, scope_input);
                out.push(ProjectionItemFact {
                    column_id: None,
                    alias: None,
                    kind: ProjectionItemKind::Star { star_info },
                    span: s.span,
                });
            }
        }
    }
    out
}

/// Walk the plan from the root through scope-preserving wrappers and
/// return the outer query's `Project` items along with the relational
/// input below the `Project` (used for resolving qualifier aliases
/// against in-scope sources). Returns `None` when the root of this
/// scope is not a `Project` — DML, set-operation, source-only, or
/// opaque shapes have no projection list.
fn find_outer_project(plan: &RelPlan) -> Option<(&[ProjectItem], &RelPlan)> {
    match plan {
        RelPlan::Project { items, input, .. } => Some((items.as_slice(), input.as_ref())),
        RelPlan::Filter { input, .. }
        | RelPlan::Aggregate { input, .. }
        | RelPlan::Window { input, .. }
        | RelPlan::Sort { input, .. }
        | RelPlan::Limit { input, .. }
        | RelPlan::TableSample { input, .. }
        | RelPlan::Pivot { input, .. }
        | RelPlan::Unpivot { input, .. }
        | RelPlan::MatchRecognize { input, .. }
        | RelPlan::ConnectBy { input, .. }
        | RelPlan::Unnest { input, .. } => find_outer_project(input),
        RelPlan::WithScope { body, .. } => find_outer_project(body),
        RelPlan::Explain { body, .. } => find_outer_project(body),
        // DerivedTable and Join are scope shapes that don't host a
        // top-level SELECT projection list directly. SetOp's branches
        // are independent scopes whose star_projections do not
        // propagate. Source-only nodes have no projection.
        RelPlan::Scan { .. }
        | RelPlan::Values { .. }
        | RelPlan::CteRef { .. }
        | RelPlan::ModelRef { .. }
        | RelPlan::Join { .. }
        | RelPlan::SetOp { .. }
        | RelPlan::DerivedTable { .. }
        | RelPlan::TableFunction { .. }
        | RelPlan::CreateTableForm { .. }
        | RelPlan::ParseRecovery { .. }
        | RelPlan::Opaque { .. }
        | RelPlan::InvalidInput { .. }
        | RelPlan::Insert { .. }
        | RelPlan::Update { .. }
        | RelPlan::Delete { .. }
        | RelPlan::Merge { .. }
        | RelPlan::MultiInsert { .. }
        | RelPlan::CreateAsQuery { .. } => None,
    }
}

/// Build a [`StarProjectionInfo`] for one `ProjectStar`. Identifiers
/// come from the source slice (preserving quotes and case); the ILIKE
/// pattern is already SQL-decoded by `lower_star_ilike`;
/// `has_replace` / `has_rename` reflect modifier presence;
/// `resolved_table` is set when the qualifier alias matches a
/// base-table `Scan` reachable from the projection's relational input.
fn project_star_info(s: &ProjectStar, source: &str, scope_input: &RelPlan) -> StarProjectionInfo {
    let qualifier_text = match &s.qualifier {
        StarQualifier::Unqualified | StarQualifier::FromExpr(_) => None,
        StarQualifier::Named(path) => path
            .first()
            .and_then(|p| crate::ir::slice_span(source, p.span).map(|t| t.trim().to_string())),
    };

    let ilike_pattern = s.ilike.clone();

    let excluded_columns: Vec<IdentName> = s
        .exclude
        .iter()
        .filter_map(|e| {
            crate::ir::slice_span(source, e.span).map(|t| IdentName {
                name: t.trim().to_string(),
            })
        })
        .collect();

    let replaced_columns: Vec<IdentName> = s
        .replace
        .iter()
        .filter_map(|r| {
            crate::ir::slice_span(source, r.span).map(|t| IdentName {
                name: t.trim().to_string(),
            })
        })
        .collect();

    let renames: Vec<StarRenameMapping> = s
        .rename
        .iter()
        .filter_map(|r| {
            let from = crate::ir::slice_span(source, r.from_span)?
                .trim()
                .to_string();
            let to = crate::ir::slice_span(source, r.to_span)?.trim().to_string();
            Some(StarRenameMapping {
                from: IdentName { name: from },
                to: IdentName { name: to },
            })
        })
        .collect();

    let has_replace = !s.replace.is_empty();
    let has_rename = !s.rename.is_empty();

    let resolved_table = qualifier_text
        .as_ref()
        .map(|q| IdentKey::new(q))
        .and_then(|q_key| resolve_alias_to_table_ref(scope_input, &q_key));

    StarProjectionInfo {
        qualifier: qualifier_text,
        ilike_pattern,
        excluded_columns,
        replaced_columns,
        renames,
        has_replace,
        has_rename,
        resolved_table,
    }
}

/// Resolve a qualifier identifier to a base-table [`TableRef`] by
/// walking the scope's input subtree. Only `RelPlan::Scan` sources
/// reachable through scope-preserving arms resolve; CTE /
/// derived-table / TVF / ModelRef qualifiers fall through to `None`.
/// Walks stop at scope boundaries
/// (`DerivedTable` input, `SetOp` branches, scalar subqueries) so an
/// inner SELECT's tables do not leak out.
fn resolve_alias_to_table_ref(plan: &RelPlan, qual: &IdentKey) -> Option<TableRef> {
    match plan {
        RelPlan::Scan { table, alias, .. } => {
            // Match by explicit alias first; if absent, fall back to
            // the table's bare name (last path component): both
            // `FROM users u` (alias=u) and `FROM users` (no alias,
            // "users" → TableRef) resolve.
            let local: IdentKey = match alias {
                Some(a) => a.clone(),
                None => IdentKey::new(&table.name),
            };
            if &local == qual {
                Some(table.clone())
            } else {
                None
            }
        }
        RelPlan::Join { left, right, .. } => resolve_alias_to_table_ref(left, qual)
            .or_else(|| resolve_alias_to_table_ref(right, qual)),
        // Scope-preserving wrappers between Project and the FROM list.
        RelPlan::Filter { input, .. }
        | RelPlan::Aggregate { input, .. }
        | RelPlan::Window { input, .. }
        | RelPlan::Sort { input, .. }
        | RelPlan::Limit { input, .. }
        | RelPlan::TableSample { input, .. }
        | RelPlan::Pivot { input, .. }
        | RelPlan::Unpivot { input, .. }
        | RelPlan::MatchRecognize { input, .. }
        | RelPlan::ConnectBy { input, .. }
        | RelPlan::Unnest { input, .. }
        | RelPlan::Project { input, .. } => resolve_alias_to_table_ref(input, qual),
        // Boundaries / non-table sources: do not resolve.
        RelPlan::CteRef { .. }
        | RelPlan::ModelRef { .. }
        | RelPlan::Values { .. }
        | RelPlan::TableFunction { .. }
        | RelPlan::DerivedTable { .. }
        | RelPlan::SetOp { .. }
        | RelPlan::WithScope { .. }
        | RelPlan::Explain { .. }
        | RelPlan::CreateTableForm { .. }
        | RelPlan::ParseRecovery { .. }
        | RelPlan::Opaque { .. }
        | RelPlan::InvalidInput { .. }
        | RelPlan::Insert { .. }
        | RelPlan::Update { .. }
        | RelPlan::Delete { .. }
        | RelPlan::Merge { .. }
        | RelPlan::MultiInsert { .. }
        | RelPlan::CreateAsQuery { .. } => None,
    }
}

/// Project [`DerivedFacts::table_aliases`] from `plan`.
///
/// Outer-only disposition.
///
/// Walks scope-preserving wrappers (`Project`, `Filter`, `Aggregate`,
/// `Window`, `Sort`, `Limit`, `TableSample`, `Pivot`, `Unpivot`,
/// `MatchRecognize`, `ConnectBy`, `Unnest`, `WithScope.body`,
/// `Explain.body`) and through the outer scope's `Join` chain,
/// collecting one entry per [`RelPlan::Scan`]. The key is `alias` when
/// set, otherwise [`TableRef::name`] (the last-component bare name).
/// Non-table sources (`Values`, `CteRef`,
/// `ModelRef`, `TableFunction`, `DerivedTable`) and scope boundaries
/// (`SetOp` branches, scalar-subquery sources, DML / DDL roots) are
/// not descended and contribute nothing.
fn compute_table_aliases(plan: &RelPlan) -> HashMap<IdentKey, TableRef> {
    let mut out: HashMap<IdentKey, TableRef> = HashMap::new();
    collect_outer_scan_aliases(plan, &mut out);
    out
}

fn collect_outer_scan_aliases(plan: &RelPlan, out: &mut HashMap<IdentKey, TableRef>) {
    match plan {
        RelPlan::Scan { table, alias, .. } => {
            let key = match alias {
                Some(a) => a.clone(),
                None => IdentKey::new(&table.name),
            };
            out.insert(key, table.clone());
        }
        RelPlan::Join { left, right, .. } => {
            collect_outer_scan_aliases(left, out);
            collect_outer_scan_aliases(right, out);
        }
        // Scope-preserving wrappers: descend into the input.
        RelPlan::Filter { input, .. }
        | RelPlan::Aggregate { input, .. }
        | RelPlan::Window { input, .. }
        | RelPlan::Sort { input, .. }
        | RelPlan::Limit { input, .. }
        | RelPlan::TableSample { input, .. }
        | RelPlan::Pivot { input, .. }
        | RelPlan::Unpivot { input, .. }
        | RelPlan::MatchRecognize { input, .. }
        | RelPlan::ConnectBy { input, .. }
        | RelPlan::Unnest { input, .. }
        | RelPlan::Project { input, .. } => collect_outer_scan_aliases(input, out),
        RelPlan::WithScope { body, .. } => collect_outer_scan_aliases(body, out),
        RelPlan::Explain { body, .. } => collect_outer_scan_aliases(body, out),
        // Non-table sources: no Scan to contribute, do not descend.
        // Scope boundaries (DML / DDL roots, SetOp branches): their
        // aliases do not merge upward.
        RelPlan::Values { .. }
        | RelPlan::CteRef { .. }
        | RelPlan::ModelRef { .. }
        | RelPlan::TableFunction { .. }
        | RelPlan::DerivedTable { .. }
        | RelPlan::SetOp { .. }
        | RelPlan::CreateTableForm { .. }
        | RelPlan::ParseRecovery { .. }
        | RelPlan::Opaque { .. }
        | RelPlan::InvalidInput { .. }
        | RelPlan::Insert { .. }
        | RelPlan::Update { .. }
        | RelPlan::Delete { .. }
        | RelPlan::Merge { .. }
        | RelPlan::MultiInsert { .. }
        | RelPlan::CreateAsQuery { .. } => {}
    }
}

/// Fused full-plan walk that collects five facts in one traversal:
/// `has_implicit_cross_join`, `has_join_predicate_filters`,
/// `nullable_tables`, `columns_in_is_null`,
/// `columns_filtered_not_null`. The per-arm work is small enough that
/// fusing them avoids the dominant recursion overhead of separate
/// passes on deep CTE/join plans.
///
/// Subquery descent is delegated to the visitor framework
/// (`visit_subquery` → `visit_rel_plan`), so embedded subqueries are
/// reached exactly once regardless of which fact's arm triggered the
/// recursion.
fn compute_combined_post_walk_facts(
    plan: &RelPlan,
    source: &str,
    bindings: &BindingTable,
    out: &mut DerivedFacts,
) {
    use crate::ir::plan::{FilterKind, JoinKind};
    use crate::ir::visitor::{walk_rel_plan, RelPlanVisitor};

    struct Combined<'a> {
        has_implicit_cross_join: bool,
        has_join_predicate_filters: bool,
        nullable_tables: HashSet<String>,
        columns_in_is_null: HashSet<String>,
        columns_filtered_not_null: HashSet<(String, String)>,
        source: &'a str,
        bindings: &'a BindingTable,
    }

    impl<'a> RelPlanVisitor<'a> for Combined<'a> {
        fn visit_rel_plan(&mut self, plan: &'a RelPlan) {
            if let RelPlan::Join {
                left,
                right,
                kind,
                implicit,
                lateral,
                on,
                ..
            } = plan
            {
                // Implicit cross (comma-FROM cartesian) hazard exists
                // regardless of what RelPlan variant wraps the right
                // source — CteRef, Project, DerivedTable, SetOp, and
                // raw Scan all carry the same `|left| × |right|` cost.
                // Restricting to a Scan RHS would silently FN on
                // `FROM cte_a, cte_b` (CteRef RHS), DT-wrapped
                // `FROM a, (SELECT ...) b`, and any post-staging
                // implicit cross. The `lateral` discriminator already
                // separates `FROM a, LATERAL (...)` (which is
                // correlated, not cartesian) from true comma-FROM, so
                // honoring it here is sufficient.
                if matches!(kind, JoinKind::Cross) && *implicit && !*lateral {
                    self.has_implicit_cross_join = true;
                }
                if let Some(expr) = on {
                    if scalar_has_filter_predicate(expr) {
                        self.has_join_predicate_filters = true;
                    }
                }
                match kind {
                    JoinKind::LeftOuter => {
                        if let Some(id) = relplan_source_identifier(right) {
                            self.nullable_tables.insert(id);
                        }
                    }
                    JoinKind::RightOuter => {
                        if let Some(id) = leftmost_join_source_identifier(left) {
                            self.nullable_tables.insert(id);
                        }
                    }
                    JoinKind::FullOuter => {
                        if let Some(id) = leftmost_join_source_identifier(left) {
                            self.nullable_tables.insert(id);
                        }
                        if let Some(id) = relplan_source_identifier(right) {
                            self.nullable_tables.insert(id);
                        }
                    }
                    JoinKind::Inner
                    | JoinKind::Cross
                    | JoinKind::Asof
                    | JoinKind::LeftSemi
                    | JoinKind::RightSemi
                    | JoinKind::LeftAnti
                    | JoinKind::RightAnti => {}
                }
            }
            if let RelPlan::Filter {
                predicate, kind, ..
            } = plan
            {
                if matches!(kind, FilterKind::Where) {
                    walk_predicate_for_isnull(
                        predicate,
                        self.source,
                        self.bindings,
                        &mut self.columns_in_is_null,
                    );
                    walk_predicate_for_isnotnull(
                        predicate,
                        self.source,
                        self.bindings,
                        &mut self.columns_filtered_not_null,
                    );
                }
            }
            walk_rel_plan(self, plan);
        }
    }

    let mut acc = Combined {
        has_implicit_cross_join: false,
        has_join_predicate_filters: false,
        nullable_tables: HashSet::new(),
        columns_in_is_null: HashSet::new(),
        columns_filtered_not_null: HashSet::new(),
        source,
        bindings,
    };
    acc.visit_rel_plan(plan);

    out.has_implicit_cross_join = acc.has_implicit_cross_join;
    out.has_join_predicate_filters = acc.has_join_predicate_filters;
    out.nullable_tables = acc.nullable_tables;
    out.columns_in_is_null = acc.columns_in_is_null;
    out.columns_filtered_not_null = acc.columns_filtered_not_null;
}

/// Returns `true` iff `expr` contains a `column ⊕ literal` comparison
/// (where `⊕ ∈ {=, <>, <, <=, >, >=}`) at the top level or under an
/// AND-chain. OR-chains are not descended — under an OR the filter
/// is not guaranteed, so it doesn't count as a join-predicate filter.
///
/// Closed-enum exhaustive over [`ScalarExpr`].
fn scalar_has_filter_predicate(expr: &ScalarExpr) -> bool {
    match expr {
        ScalarExpr::BinOp {
            op, left, right, ..
        } => {
            let op_upper = op.as_sql_str();
            if matches!(op_upper, "=" | "<>" | "<" | "<=" | ">" | ">=") {
                let left_col = is_column_ref(left);
                let right_col = is_column_ref(right);
                let left_lit = is_literal_scalar(left);
                let right_lit = is_literal_scalar(right);
                if (left_col && right_lit) || (left_lit && right_col) {
                    return true;
                }
                return false;
            }
            if op_upper == "AND" {
                return scalar_has_filter_predicate(left) || scalar_has_filter_predicate(right);
            }
            false
        }
        // N-ary spelling of the `AND` recursion above. `OR` also
        // recurses: a disjunct that is a column-vs-literal comparison
        // is still a filter predicate, which is what the `BinOp` arm
        // concludes for the nested spelling via its own `AND` walk.
        ScalarExpr::LogicalChain { operands, .. } => {
            operands.iter().any(scalar_has_filter_predicate)
        }
        // A pattern match is not a column-vs-literal filter predicate.
        ScalarExpr::Like { .. } => false,
        ScalarExpr::Column { .. }
        | ScalarExpr::OuterRef { .. }
        | ScalarExpr::Lit { .. }
        | ScalarExpr::UnaryOp { .. }
        | ScalarExpr::FuncCall { .. }
        | ScalarExpr::Case { .. }
        | ScalarExpr::Cast { .. }
        | ScalarExpr::InList { .. }
        | ScalarExpr::Between { .. }
        | ScalarExpr::Exists { .. }
        | ScalarExpr::ScalarSubquery { .. }
        | ScalarExpr::QuantifiedCmp { .. }
        | ScalarExpr::WindowFn { .. }
        | ScalarExpr::FieldAccess { .. }
        | ScalarExpr::Lambda { .. }
        | ScalarExpr::PatternVarRef { .. }
        | ScalarExpr::Opaque { .. } => false,
    }
}

/// Whether `expr` is a column reference (`Column` or correlated
/// `OuterRef`): both same-scope and outer-scope column references
/// count.
fn is_column_ref(expr: &ScalarExpr) -> bool {
    matches!(
        expr,
        ScalarExpr::Column { .. } | ScalarExpr::OuterRef { .. }
    )
}

/// Whether `expr` is a literal value: plain literal, parenthesized
/// literal (already lifted in IR), or a unary-arithmetic-sign over a
/// literal (e.g. `-1`, `+1`). The IR encodes `-x` as
/// `UnaryOp { op: UnaryOpKind::Neg, arg: x }`, so we descend through it.
/// Closed-enum exhaustive.
fn is_literal_scalar(expr: &ScalarExpr) -> bool {
    use crate::ir::scalar::UnaryOpKind;
    match expr {
        ScalarExpr::Lit { .. } => true,
        ScalarExpr::UnaryOp {
            op: UnaryOpKind::Neg | UnaryOpKind::Plus,
            arg,
            ..
        } => is_literal_scalar(arg),
        ScalarExpr::UnaryOp { .. }
        | ScalarExpr::Column { .. }
        | ScalarExpr::OuterRef { .. }
        | ScalarExpr::BinOp { .. }
        | ScalarExpr::LogicalChain { .. }
        | ScalarExpr::FuncCall { .. }
        | ScalarExpr::Case { .. }
        | ScalarExpr::Cast { .. }
        | ScalarExpr::InList { .. }
        | ScalarExpr::Between { .. }
        | ScalarExpr::Like { .. }
        | ScalarExpr::Exists { .. }
        | ScalarExpr::ScalarSubquery { .. }
        | ScalarExpr::QuantifiedCmp { .. }
        | ScalarExpr::WindowFn { .. }
        | ScalarExpr::FieldAccess { .. }
        | ScalarExpr::Lambda { .. }
        | ScalarExpr::PatternVarRef { .. }
        | ScalarExpr::Opaque { .. } => false,
    }
}

// ── column_refs / select_output_columns projection ───────────────────────────
//
// `column_refs` is flat across every relational scope;
// `select_output_columns` covers outer SELECT projection items
// only, with star expansion via inner CTE / derived-table schemas.
//
// Equality is element-wise via [`ColumnRef::PartialEq`] which compares
// normalized name + resolved-table-or-qualifier. Catalog-driven star
// expansion of base tables is not performed here.

/// Top-level entry: project [`DerivedFacts::column_refs`] from `plan`.
fn compute_column_refs(
    plan: &RelPlan,
    bindings: &BindingTable,
    scan_index: &ScanIndex,
) -> Vec<ColumnRef> {
    let mut acc: Vec<ColumnRef> = Vec::new();
    visit_plan_for_column_refs(plan, bindings, scan_index, &mut acc);
    acc
}

/// Top-level entry: project [`DerivedFacts::select_output_columns`].
///
/// Outer-scope only — descends through scope-preserving wrappers to the
/// outer `Project` and collects columns from each item. `SELECT *` is
/// expanded via inner CTE / derived-table / set-op / aggregate output
/// column lists when reachable from the projection's relational input.
/// Inline stars in mixed projection lists (`top_level_pure: false`) do
/// not contribute to `select_output_columns` — only
/// `Project.items[*] == Expr` plus `Star { top_level_pure: true }`
/// expansion do.
fn compute_select_output_columns(
    plan: &RelPlan,
    bindings: &BindingTable,
    scan_index: &ScanIndex,
) -> Vec<ColumnRef> {
    let Some((items, scope_input)) = find_outer_project(plan) else {
        return Vec::new();
    };
    // The IR lifts `Window` and `Aggregate` operators out of the
    // projection list into their own `RelPlan` nodes between the
    // outer `Project` and its sources. A projection item like
    // `ROW_NUMBER() OVER (ORDER BY id) AS rn` becomes a `Window`
    // node carrying the `WindowCall` plus a `Project` item that
    // references the synthesized output `ColumnId`. The
    // synthesized aliases are *not* base-column reads and must be
    // filtered from the items walk; the calls' own inner exprs are
    // walked separately below to recover the real source-column
    // reads (e.g., `id` from `ORDER BY id` in the OVER clause).
    let synthesized = collect_outer_scope_synthesized_outputs(scope_input);
    let mut out: Vec<ColumnRef> = Vec::new();
    for item in items {
        match item {
            ProjectItem::Expr(e) => {
                if is_synthesized_column_ref(&e.expr, &synthesized) {
                    continue;
                }
                let start_idx = out.len();
                collect_column_refs_in_scalar(&e.expr, bindings, scan_index, &mut out);
                if let Some(alias) = &e.alias {
                    let alias_text = alias.as_str().to_string();
                    for col in &mut out[start_idx..] {
                        col.output_alias = Some(alias_text.clone());
                    }
                }
            }
            ProjectItem::Star(s) => {
                if !s.top_level_pure {
                    continue;
                }
                expand_star_for_output(s, scope_input, bindings, &mut out);
            }
        }
    }
    walk_outer_scope_synthesizers_for_select(scope_input, bindings, scan_index, &mut out);
    out
}

/// Returns `true` when `expr` is a top-level `Column` / `OuterRef` /
/// `PatternVarRef` whose `ColumnId` is in the outer-scope synthesized
/// set — i.e., a window/aggregate output alias rather than a base
/// column read. Used by [`compute_select_output_columns`] and the
/// `Project` arm of [`visit_plan_for_column_refs`] to skip these
/// references at the projection-list level.
fn is_synthesized_column_ref(expr: &ScalarExpr, synthesized: &HashSet<ColumnId>) -> bool {
    match expr {
        ScalarExpr::Column { column, .. }
        | ScalarExpr::OuterRef { column, .. }
        | ScalarExpr::PatternVarRef { column, .. } => synthesized.contains(column),
        ScalarExpr::Lit { .. }
        | ScalarExpr::Opaque { .. }
        | ScalarExpr::BinOp { .. }
        | ScalarExpr::LogicalChain { .. }
        | ScalarExpr::UnaryOp { .. }
        | ScalarExpr::Cast { .. }
        | ScalarExpr::FuncCall { .. }
        | ScalarExpr::Case { .. }
        | ScalarExpr::InList { .. }
        | ScalarExpr::Between { .. }
        | ScalarExpr::Like { .. }
        | ScalarExpr::FieldAccess { .. }
        | ScalarExpr::Lambda { .. }
        | ScalarExpr::Exists { .. }
        | ScalarExpr::ScalarSubquery { .. }
        | ScalarExpr::QuantifiedCmp { .. }
        | ScalarExpr::WindowFn { .. } => false,
    }
}

/// Collect the `ColumnId`s synthesized by `Window` / `Aggregate`
/// operators reachable from `plan` through scope-preserving wrappers
/// (i.e., within the same outer scope as the calling `Project`). Stops
/// at scope boundaries (`Scan`, `Values`, `CteRef`, `ModelRef`,
/// `Join`, `SetOp`, `DerivedTable`, `TableFunction`, DML / DDL roots,
/// terminal leaves) — those start new scopes and have their own
/// synthesized sets.
///
/// Closed-enum exhaustive over [`RelPlan`].
fn collect_outer_scope_synthesized_outputs(plan: &RelPlan) -> HashSet<ColumnId> {
    let mut out = HashSet::new();
    walk_collect_synthesized(plan, &mut out);
    out
}

fn walk_collect_synthesized(plan: &RelPlan, out: &mut HashSet<ColumnId>) {
    match plan {
        RelPlan::Window {
            input,
            window_outputs,
            ..
        } => {
            out.extend(window_outputs.iter().copied());
            walk_collect_synthesized(input, out);
        }
        RelPlan::Aggregate {
            input,
            output_columns,
            ..
        } => {
            out.extend(output_columns.iter().copied());
            walk_collect_synthesized(input, out);
        }
        RelPlan::Filter { input, .. }
        | RelPlan::Sort { input, .. }
        | RelPlan::Limit { input, .. }
        | RelPlan::TableSample { input, .. }
        | RelPlan::Pivot { input, .. }
        | RelPlan::Unpivot { input, .. }
        | RelPlan::MatchRecognize { input, .. }
        | RelPlan::ConnectBy { input, .. }
        | RelPlan::Unnest { input, .. } => {
            walk_collect_synthesized(input, out);
        }
        RelPlan::WithScope { body, .. } | RelPlan::Explain { body, .. } => {
            walk_collect_synthesized(body, out);
        }
        // Scope boundaries / leaves: stop. Inner scopes compute
        // their own synthesized sets at their own outer `Project`s.
        RelPlan::Project { .. }
        | RelPlan::Scan { .. }
        | RelPlan::Values { .. }
        | RelPlan::CteRef { .. }
        | RelPlan::ModelRef { .. }
        | RelPlan::Join { .. }
        | RelPlan::SetOp { .. }
        | RelPlan::DerivedTable { .. }
        | RelPlan::TableFunction { .. }
        | RelPlan::CreateTableForm { .. }
        | RelPlan::ParseRecovery { .. }
        | RelPlan::Opaque { .. }
        | RelPlan::InvalidInput { .. }
        | RelPlan::Insert { .. }
        | RelPlan::Update { .. }
        | RelPlan::Delete { .. }
        | RelPlan::Merge { .. }
        | RelPlan::MultiInsert { .. }
        | RelPlan::CreateAsQuery { .. } => {}
    }
}

/// Walk outer-scope-preserving wrappers between a `Project` and the
/// next scope boundary, collecting column refs from `Window` /
/// `Aggregate` calls' inner expressions. This is the second surface
/// of `select_output_columns`: the projection items
/// walk skips synthesized output aliases, and this walk recovers the
/// base-column reads inside the producing calls (e.g., `id` in
/// `ROW_NUMBER() OVER (ORDER BY id)`).
///
/// HAVING is *not* walked (it is not part of the SELECT list); WHERE
/// (`Filter.predicate`), `Sort.keys`, and `Limit.{limit, offset}` are
/// also not walked here for the same reason.
///
/// Closed-enum exhaustive over [`RelPlan`].
fn walk_outer_scope_synthesizers_for_select(
    plan: &RelPlan,
    bindings: &BindingTable,
    scan_index: &ScanIndex,
    acc: &mut Vec<ColumnRef>,
) {
    match plan {
        RelPlan::Window { input, windows, .. } => {
            for call in windows {
                collect_column_refs_in_window_call(call, bindings, scan_index, acc);
            }
            walk_outer_scope_synthesizers_for_select(input, bindings, scan_index, acc);
        }
        RelPlan::Aggregate {
            input,
            grouping,
            aggregates,
            ..
        } => {
            for_each_grouping_key(grouping, |gk| {
                collect_column_refs_in_scalar(&gk.expr, bindings, scan_index, acc);
            });
            for call in aggregates {
                collect_column_refs_in_aggregate_call(call, bindings, scan_index, acc);
            }
            walk_outer_scope_synthesizers_for_select(input, bindings, scan_index, acc);
        }
        RelPlan::Filter { input, .. }
        | RelPlan::Sort { input, .. }
        | RelPlan::Limit { input, .. }
        | RelPlan::TableSample { input, .. }
        | RelPlan::Pivot { input, .. }
        | RelPlan::Unpivot { input, .. }
        | RelPlan::MatchRecognize { input, .. }
        | RelPlan::ConnectBy { input, .. }
        | RelPlan::Unnest { input, .. } => {
            walk_outer_scope_synthesizers_for_select(input, bindings, scan_index, acc);
        }
        RelPlan::WithScope { body, .. } | RelPlan::Explain { body, .. } => {
            walk_outer_scope_synthesizers_for_select(body, bindings, scan_index, acc);
        }
        // Scope boundaries / leaves: stop.
        RelPlan::Project { .. }
        | RelPlan::Scan { .. }
        | RelPlan::Values { .. }
        | RelPlan::CteRef { .. }
        | RelPlan::ModelRef { .. }
        | RelPlan::Join { .. }
        | RelPlan::SetOp { .. }
        | RelPlan::DerivedTable { .. }
        | RelPlan::TableFunction { .. }
        | RelPlan::CreateTableForm { .. }
        | RelPlan::ParseRecovery { .. }
        | RelPlan::Opaque { .. }
        | RelPlan::InvalidInput { .. }
        | RelPlan::Insert { .. }
        | RelPlan::Update { .. }
        | RelPlan::Delete { .. }
        | RelPlan::Merge { .. }
        | RelPlan::MultiInsert { .. }
        | RelPlan::CreateAsQuery { .. } => {}
    }
}

/// Walk every relational scope of `plan` and accumulate every column
/// reference reachable through any clause-bearing position, including
/// nested scopes' column_refs.
///
/// Closed-enum exhaustive: every [`RelPlan`] variant is listed.
fn visit_plan_for_column_refs(
    plan: &RelPlan,
    bindings: &BindingTable,
    scan_index: &ScanIndex,
    acc: &mut Vec<ColumnRef>,
) {
    match plan {
        RelPlan::Scan { .. }
        | RelPlan::Values { .. }
        | RelPlan::CteRef { .. }
        | RelPlan::ModelRef { .. } => {}

        RelPlan::Project {
            input,
            items,
            distinct_on,
            ..
        } => {
            // Skip top-level Project items that are direct refs to
            // window/aggregate output aliases synthesized in this
            // scope. The producing `Window` / `Aggregate` arms
            // below walk those calls' inner exprs, so the source
            // column reads still surface; this filter prevents the
            // synthesized alias (`rn`, etc.) from showing up as a
            // base column.
            let synthesized = collect_outer_scope_synthesized_outputs(input);
            for item in items {
                match item {
                    ProjectItem::Expr(e) => {
                        if is_synthesized_column_ref(&e.expr, &synthesized) {
                            continue;
                        }
                        collect_column_refs_in_scalar(&e.expr, bindings, scan_index, acc);
                    }
                    ProjectItem::Star(s) => {
                        // Star modifiers carry scalar subexpressions that
                        // can reference outer columns: REPLACE (e AS c),
                        // and the rare expr.* form. Walk both.
                        if let StarQualifier::FromExpr(e) = &s.qualifier {
                            collect_column_refs_in_scalar(e, bindings, scan_index, acc);
                        }
                        for r in &s.replace {
                            collect_column_refs_in_scalar(&r.expr, bindings, scan_index, acc);
                        }
                        // Pure star → push the `*` marker. Nested SELECTs
                        // each push their own marker, so the outer flat
                        // list contains markers from every nested
                        // pure-star SELECT.
                        if s.top_level_pure {
                            acc.push(make_star_marker(s, input));
                        }
                    }
                }
            }
            for e in distinct_on {
                collect_column_refs_in_scalar(e, bindings, scan_index, acc);
            }
            visit_plan_for_column_refs(input, bindings, scan_index, acc);
        }

        RelPlan::Filter {
            input, predicate, ..
        } => {
            collect_column_refs_in_scalar(predicate, bindings, scan_index, acc);
            visit_plan_for_column_refs(input, bindings, scan_index, acc);
        }

        RelPlan::Aggregate {
            input,
            grouping,
            aggregates,
            having,
            ..
        } => {
            for_each_grouping_key(grouping, |gk| {
                collect_column_refs_in_scalar(&gk.expr, bindings, scan_index, acc);
            });
            for call in aggregates {
                collect_column_refs_in_aggregate_call(call, bindings, scan_index, acc);
            }
            if let Some(h) = having {
                collect_column_refs_in_scalar(h, bindings, scan_index, acc);
            }
            visit_plan_for_column_refs(input, bindings, scan_index, acc);
        }

        RelPlan::Window { input, windows, .. } => {
            for call in windows {
                collect_column_refs_in_window_call(call, bindings, scan_index, acc);
            }
            visit_plan_for_column_refs(input, bindings, scan_index, acc);
        }

        RelPlan::Join {
            left,
            right,
            on,
            match_condition,
            ..
        } => {
            if let Some(p) = on {
                collect_column_refs_in_scalar(p, bindings, scan_index, acc);
            }
            if let Some(p) = match_condition {
                collect_column_refs_in_scalar(p, bindings, scan_index, acc);
            }
            visit_plan_for_column_refs(left, bindings, scan_index, acc);
            visit_plan_for_column_refs(right, bindings, scan_index, acc);
        }

        RelPlan::SetOp { inputs, .. } => {
            for branch in inputs {
                visit_plan_for_column_refs(branch, bindings, scan_index, acc);
            }
        }

        RelPlan::Sort { input, keys, .. } => {
            for sk in keys {
                collect_column_refs_in_scalar(&sk.expr, bindings, scan_index, acc);
            }
            visit_plan_for_column_refs(input, bindings, scan_index, acc);
        }

        RelPlan::Limit {
            input,
            limit,
            offset,
            ..
        } => {
            if let Some(e) = limit {
                collect_column_refs_in_scalar(e, bindings, scan_index, acc);
            }
            if let Some(e) = offset {
                collect_column_refs_in_scalar(e, bindings, scan_index, acc);
            }
            visit_plan_for_column_refs(input, bindings, scan_index, acc);
        }

        RelPlan::WithScope { ctes, body, .. } => {
            for cte in ctes {
                match &cte.body {
                    CteBody::NonRecursive(b) => {
                        visit_plan_for_column_refs(b, bindings, scan_index, acc);
                    }
                    CteBody::Recursive { anchor, step, .. } => {
                        visit_plan_for_column_refs(anchor, bindings, scan_index, acc);
                        visit_plan_for_column_refs(step, bindings, scan_index, acc);
                    }
                }
            }
            visit_plan_for_column_refs(body, bindings, scan_index, acc);
        }

        RelPlan::DerivedTable { input, .. } => {
            visit_plan_for_column_refs(input, bindings, scan_index, acc);
        }

        RelPlan::Explain { body, .. } => {
            visit_plan_for_column_refs(body, bindings, scan_index, acc);
        }

        RelPlan::TableFunction { call, .. } => {
            collect_column_refs_in_scalar(call, bindings, scan_index, acc);
        }

        RelPlan::Unnest { input, array, .. } => {
            collect_column_refs_in_scalar(array, bindings, scan_index, acc);
            visit_plan_for_column_refs(input, bindings, scan_index, acc);
        }

        RelPlan::Pivot {
            input,
            aggregates,
            default_on_null,
            ..
        } => {
            for call in aggregates {
                collect_column_refs_in_aggregate_call(call, bindings, scan_index, acc);
            }
            if let Some(e) = default_on_null {
                collect_column_refs_in_scalar(e, bindings, scan_index, acc);
            }
            visit_plan_for_column_refs(input, bindings, scan_index, acc);
        }

        RelPlan::Unpivot { input, .. } => {
            visit_plan_for_column_refs(input, bindings, scan_index, acc);
        }

        RelPlan::MatchRecognize { input, .. } => {
            // MATCH_RECOGNIZE body internals (measures / DEFINE
            // predicates) live behind a typed body; column_refs
            // inside it are not collected. Only the input is descended.
            visit_plan_for_column_refs(input, bindings, scan_index, acc);
        }

        RelPlan::ConnectBy {
            input,
            start_with,
            connect,
            ..
        } => {
            if let Some(e) = start_with {
                collect_column_refs_in_scalar(e, bindings, scan_index, acc);
            }
            collect_column_refs_in_scalar(connect, bindings, scan_index, acc);
            visit_plan_for_column_refs(input, bindings, scan_index, acc);
        }

        RelPlan::TableSample { input, sample, .. } => {
            if let Some(e) = &sample.seed {
                collect_column_refs_in_scalar(e, bindings, scan_index, acc);
            }
            if let Some(e) = &sample.repeatable {
                collect_column_refs_in_scalar(e, bindings, scan_index, acc);
            }
            visit_plan_for_column_refs(input, bindings, scan_index, acc);
        }

        RelPlan::Insert {
            source: insert_src,
            on_conflict,
            returning,
            ..
        } => {
            match insert_src {
                InsertSource::Values(rows_plan) | InsertSource::Query(rows_plan) => {
                    visit_plan_for_column_refs(rows_plan, bindings, scan_index, acc);
                }
                InsertSource::DefaultValues => {}
            }
            if let Some(oc) = on_conflict {
                if let Some(p) = &oc.where_clause {
                    collect_column_refs_in_scalar(p, bindings, scan_index, acc);
                }
                match &oc.action {
                    crate::ir::plan::ConflictAction::DoNothing => {}
                    crate::ir::plan::ConflictAction::DoUpdate {
                        assignments,
                        where_clause,
                    } => {
                        for (_, e) in assignments {
                            collect_column_refs_in_scalar(e, bindings, scan_index, acc);
                        }
                        if let Some(p) = where_clause {
                            collect_column_refs_in_scalar(p, bindings, scan_index, acc);
                        }
                    }
                    crate::ir::plan::ConflictAction::MySqlDuplicateKeyUpdate { assignments } => {
                        for (_, e) in assignments {
                            collect_column_refs_in_scalar(e, bindings, scan_index, acc);
                        }
                    }
                }
            }
            collect_column_refs_in_returning(returning.as_ref(), bindings, scan_index, acc);
        }

        RelPlan::Update {
            assignments,
            from,
            predicate,
            returning,
            ..
        } => {
            for (_, e) in assignments {
                collect_column_refs_in_scalar(e, bindings, scan_index, acc);
            }
            if let Some(f) = from {
                visit_plan_for_column_refs(f, bindings, scan_index, acc);
            }
            if let Some(p) = predicate {
                collect_column_refs_in_scalar(p, bindings, scan_index, acc);
            }
            collect_column_refs_in_returning(returning.as_ref(), bindings, scan_index, acc);
        }

        RelPlan::Delete {
            using,
            predicate,
            returning,
            ..
        } => {
            if let Some(u) = using {
                visit_plan_for_column_refs(u, bindings, scan_index, acc);
            }
            if let Some(p) = predicate {
                collect_column_refs_in_scalar(p, bindings, scan_index, acc);
            }
            collect_column_refs_in_returning(returning.as_ref(), bindings, scan_index, acc);
        }

        RelPlan::Merge {
            source: merge_src,
            on,
            branches,
            ..
        } => {
            collect_column_refs_in_scalar(on, bindings, scan_index, acc);
            visit_plan_for_column_refs(merge_src, bindings, scan_index, acc);
            for branch in branches {
                if let Some(p) = &branch.predicate {
                    collect_column_refs_in_scalar(p, bindings, scan_index, acc);
                }
                match &branch.action {
                    crate::ir::plan::MergeAction::Insert { values, .. } => {
                        for v in values {
                            collect_column_refs_in_scalar(v, bindings, scan_index, acc);
                        }
                    }
                    crate::ir::plan::MergeAction::Update { assignments } => {
                        for (_, e) in assignments {
                            collect_column_refs_in_scalar(e, bindings, scan_index, acc);
                        }
                    }
                    crate::ir::plan::MergeAction::InsertStar
                    | crate::ir::plan::MergeAction::InsertAllByName
                    | crate::ir::plan::MergeAction::UpdateSetStar
                    | crate::ir::plan::MergeAction::UpdateAllByName
                    | crate::ir::plan::MergeAction::Delete
                    | crate::ir::plan::MergeAction::DoNothing => {}
                }
            }
        }

        RelPlan::MultiInsert {
            unconditional_clauses,
            when_clauses,
            else_clauses,
            source: mi_src,
            ..
        } => {
            for t in unconditional_clauses {
                for v in &t.values {
                    collect_column_refs_in_scalar(v, bindings, scan_index, acc);
                }
            }
            for w in when_clauses {
                collect_column_refs_in_scalar(&w.condition, bindings, scan_index, acc);
                for t in &w.targets {
                    for v in &t.values {
                        collect_column_refs_in_scalar(v, bindings, scan_index, acc);
                    }
                }
            }
            for t in else_clauses {
                for v in &t.values {
                    collect_column_refs_in_scalar(v, bindings, scan_index, acc);
                }
            }
            visit_plan_for_column_refs(mi_src, bindings, scan_index, acc);
        }

        RelPlan::CreateAsQuery { body, .. } => {
            if let Some(b) = body {
                visit_plan_for_column_refs(b, bindings, scan_index, acc);
            }
        }

        RelPlan::CreateTableForm { .. }
        | RelPlan::ParseRecovery { .. }
        | RelPlan::Opaque { .. }
        | RelPlan::InvalidInput { .. } => {}
    }
}

/// Walk a [`ScalarExpr`] and append a [`ColumnRef`] for every
/// `Column` / `OuterRef` / `PatternVarRef` encountered. Recurses into
/// subqueries (`Exists`, `ScalarSubquery`, `QuantifiedCmp::Subquery`) so
/// the flat-cross-scope semantics of `column_refs` are preserved.
///
/// Closed-enum exhaustive over [`ScalarExpr`].
fn collect_column_refs_in_scalar(
    expr: &ScalarExpr,
    bindings: &BindingTable,
    scan_index: &ScanIndex,
    acc: &mut Vec<ColumnRef>,
) {
    match expr {
        ScalarExpr::Column { column, .. }
        | ScalarExpr::OuterRef { column, .. }
        | ScalarExpr::PatternVarRef { column, .. } => {
            acc.push(column_id_to_ref(*column, bindings, scan_index));
        }
        ScalarExpr::Lit { .. } | ScalarExpr::Opaque { .. } => {}
        ScalarExpr::Like {
            expr,
            pattern,
            escape,
            ..
        } => {
            collect_column_refs_in_scalar(expr, bindings, scan_index, acc);
            collect_column_refs_in_scalar(pattern, bindings, scan_index, acc);
            if let Some(e) = escape {
                collect_column_refs_in_scalar(e, bindings, scan_index, acc);
            }
        }
        ScalarExpr::BinOp { left, right, .. } => {
            collect_column_refs_in_scalar(left, bindings, scan_index, acc);
            collect_column_refs_in_scalar(right, bindings, scan_index, acc);
        }
        ScalarExpr::LogicalChain { operands, .. } => {
            for operand in operands {
                collect_column_refs_in_scalar(operand, bindings, scan_index, acc);
            }
        }
        ScalarExpr::UnaryOp { arg, .. } => {
            collect_column_refs_in_scalar(arg, bindings, scan_index, acc);
        }
        ScalarExpr::Cast { expr, .. } => {
            collect_column_refs_in_scalar(expr, bindings, scan_index, acc);
        }
        ScalarExpr::FuncCall {
            args, named_args, ..
        } => {
            for a in args {
                collect_column_refs_in_scalar(a, bindings, scan_index, acc);
            }
            for (_, v) in named_args {
                collect_column_refs_in_scalar(v, bindings, scan_index, acc);
            }
        }
        ScalarExpr::Case {
            operand,
            branches,
            else_,
            ..
        } => {
            if let Some(op) = operand {
                collect_column_refs_in_scalar(op, bindings, scan_index, acc);
            }
            for (cond, result) in branches {
                collect_column_refs_in_scalar(cond, bindings, scan_index, acc);
                collect_column_refs_in_scalar(result, bindings, scan_index, acc);
            }
            if let Some(e) = else_ {
                collect_column_refs_in_scalar(e, bindings, scan_index, acc);
            }
        }
        ScalarExpr::InList { expr, list, .. } => {
            collect_column_refs_in_scalar(expr, bindings, scan_index, acc);
            for v in list {
                collect_column_refs_in_scalar(v, bindings, scan_index, acc);
            }
        }
        ScalarExpr::Between {
            expr, low, high, ..
        } => {
            collect_column_refs_in_scalar(expr, bindings, scan_index, acc);
            collect_column_refs_in_scalar(low, bindings, scan_index, acc);
            collect_column_refs_in_scalar(high, bindings, scan_index, acc);
        }
        ScalarExpr::FieldAccess { base, .. } => {
            collect_column_refs_in_scalar(base, bindings, scan_index, acc);
        }
        ScalarExpr::Lambda { body, .. } => {
            collect_column_refs_in_scalar(body, bindings, scan_index, acc);
        }
        ScalarExpr::Exists { subquery, .. } | ScalarExpr::ScalarSubquery { subquery, .. } => {
            // Recurse into subquery RelPlan so inner column_refs
            // propagate to the flat list.
            visit_plan_for_column_refs(subquery, bindings, scan_index, acc);
        }
        ScalarExpr::QuantifiedCmp { left, right, .. } => {
            collect_column_refs_in_scalar(left, bindings, scan_index, acc);
            match right {
                QuantifiedRhs::Subquery(plan, _) => {
                    visit_plan_for_column_refs(plan, bindings, scan_index, acc);
                }
                QuantifiedRhs::List(values) => {
                    for v in values {
                        collect_column_refs_in_scalar(v, bindings, scan_index, acc);
                    }
                }
            }
        }
        ScalarExpr::WindowFn { call, .. } => {
            collect_column_refs_in_window_call(call, bindings, scan_index, acc);
        }
    }
}

fn collect_column_refs_in_aggregate_call(
    call: &AggregateCall,
    bindings: &BindingTable,
    scan_index: &ScanIndex,
    acc: &mut Vec<ColumnRef>,
) {
    for a in &call.args {
        collect_column_refs_in_scalar(a, bindings, scan_index, acc);
    }
    for (_, v) in &call.named_args {
        collect_column_refs_in_scalar(v, bindings, scan_index, acc);
    }
    if let Some(f) = &call.filter {
        collect_column_refs_in_scalar(f, bindings, scan_index, acc);
    }
    for sk in &call.arg_order {
        collect_column_refs_in_scalar(&sk.expr, bindings, scan_index, acc);
    }
    for sk in &call.within_group_order {
        collect_column_refs_in_scalar(&sk.expr, bindings, scan_index, acc);
    }
}

fn collect_column_refs_in_window_call(
    call: &WindowCall,
    bindings: &BindingTable,
    scan_index: &ScanIndex,
    acc: &mut Vec<ColumnRef>,
) {
    for a in &call.args {
        collect_column_refs_in_scalar(a, bindings, scan_index, acc);
    }
    for p in &call.partition_by {
        collect_column_refs_in_scalar(p, bindings, scan_index, acc);
    }
    for sk in &call.order_by {
        collect_column_refs_in_scalar(&sk.expr, bindings, scan_index, acc);
    }
    if let Some(frame) = &call.frame {
        collect_column_refs_in_frame_bound(&frame.start, bindings, scan_index, acc);
        collect_column_refs_in_frame_bound(&frame.end, bindings, scan_index, acc);
    }
}

fn collect_column_refs_in_frame_bound(
    bound: &FrameBound,
    bindings: &BindingTable,
    scan_index: &ScanIndex,
    acc: &mut Vec<ColumnRef>,
) {
    match bound {
        FrameBound::UnboundedPreceding
        | FrameBound::UnboundedFollowing
        | FrameBound::CurrentRow => {}
        FrameBound::Preceding(e) | FrameBound::Following(e) => {
            collect_column_refs_in_scalar(e, bindings, scan_index, acc);
        }
    }
}

fn collect_column_refs_in_returning(
    returning: Option<&crate::ir::plan::Returning>,
    bindings: &BindingTable,
    scan_index: &ScanIndex,
    acc: &mut Vec<ColumnRef>,
) {
    let Some(r) = returning else {
        return;
    };
    for item in &r.items {
        match item {
            crate::ir::plan::ReturningItem::Star => {}
            crate::ir::plan::ReturningItem::Expr { expr, .. } => {
                collect_column_refs_in_scalar(expr, bindings, scan_index, acc);
            }
        }
    }
}

fn for_each_grouping_key(grouping: &GroupingSpec, mut f: impl FnMut(&GroupKey)) {
    match grouping {
        GroupingSpec::None => {}
        GroupingSpec::Standard(keys)
        | GroupingSpec::Cube(keys)
        | GroupingSpec::Rollup(keys)
        | GroupingSpec::All(keys) => {
            for k in keys {
                f(k);
            }
        }
        GroupingSpec::GroupingSets(sets) => {
            for set in sets {
                for k in set {
                    f(k);
                }
            }
        }
    }
}

/// Build the synthetic `*` marker [`ColumnRef`] pushed for every
/// pure-star projection. Mirrors the qualifier + resolved-table
/// extraction in `project_star_info`, populating the
/// equality-relevant fields (name, qualifier, resolved_table).
fn make_star_marker(s: &ProjectStar, scope_input: &RelPlan) -> ColumnRef {
    let qualifier_text = match &s.qualifier {
        StarQualifier::Unqualified | StarQualifier::FromExpr(_) => None,
        StarQualifier::Named(path) => path.first().map(|p| p.name.as_str().to_string()),
    };
    let resolved_table = qualifier_text
        .as_ref()
        .map(|q| IdentKey::new(q))
        .and_then(|q_key| resolve_alias_to_table_ref(scope_input, &q_key));
    let mut col = ColumnRef::new("*".to_string());
    if let Some(q) = qualifier_text {
        col.qualifier = Some(q);
    }
    if let Some(t) = resolved_table {
        col = col.with_resolved_table(t);
    }
    col
}

/// Expand a top-level pure star into output columns by walking `scope_input`
/// to find inner CTE / DerivedTable / SetOp / Aggregate output column
/// lists. Catalog-driven base-table star expansion is intentionally
/// not performed here.
fn expand_star_for_output(
    star: &ProjectStar,
    scope_input: &RelPlan,
    bindings: &BindingTable,
    out: &mut Vec<ColumnRef>,
) {
    let qualifier_norm = match &star.qualifier {
        StarQualifier::Named(path) => path.first().map(|p| normalize_identifier(p.name.as_str())),
        _ => None,
    };
    let mut visited: HashSet<usize> = HashSet::new();
    let scan_index: ScanIndex = build_scan_index(scope_input);
    expand_star_visit(
        scope_input,
        qualifier_norm.as_deref(),
        bindings,
        &scan_index,
        &mut visited,
        out,
    );
}

fn expand_star_visit(
    plan: &RelPlan,
    qualifier_norm: Option<&str>,
    bindings: &BindingTable,
    scan_index: &ScanIndex,
    visited: &mut HashSet<usize>,
    out: &mut Vec<ColumnRef>,
) {
    // Guard against pathological cycles (defensive — RelPlan is a DAG).
    let key = plan as *const RelPlan as usize;
    if !visited.insert(key) {
        return;
    }
    match plan {
        // Output-column-list bearing wrappers below the outer Project.
        RelPlan::CteRef {
            name,
            columns,
            alias,
            ..
        } => {
            // Match qualifier against the alias / CTE name.
            if let Some(qn) = qualifier_norm {
                let local_norm = match alias {
                    Some(a) => normalize_identifier(a.as_str()),
                    None => normalize_identifier(name.as_str()),
                };
                if local_norm != qn {
                    return;
                }
            }
            for cid in columns {
                out.push(column_id_to_ref(*cid, bindings, scan_index));
            }
        }
        RelPlan::DerivedTable {
            columns,
            alias,
            input,
            ..
        } => {
            if let Some(qn) = qualifier_norm {
                let Some(a) = alias else {
                    return;
                };
                if normalize_identifier(a.as_str()) != qn {
                    return;
                }
            }
            // Use the DerivedTable's own column ids (these are
            // outer-scope ids whose display_name is the CTE/derived
            // column alias). When the derived table has no explicit
            // column list, fall back to walking the inner plan's outer
            // schema via the same mechanism.
            if !columns.is_empty() {
                for cid in columns {
                    out.push(column_id_to_ref(*cid, bindings, scan_index));
                }
            } else {
                // No explicit columns — descend into the inner plan
                // and pick up its outermost schema.
                expand_star_visit(input, None, bindings, scan_index, visited, out);
            }
        }
        RelPlan::SetOp { output_columns, .. } => {
            // SetOp arms are scope boundaries; the outer-visible schema
            // is `output_columns`.
            for cid in output_columns {
                out.push(column_id_to_ref(*cid, bindings, scan_index));
            }
        }
        RelPlan::Aggregate {
            output_columns,
            input,
            ..
        } => {
            // GROUP BY exposes group keys + aggregate outputs; star at
            // a level above an Aggregate sees those.
            if !output_columns.is_empty() {
                for cid in output_columns {
                    out.push(column_id_to_ref(*cid, bindings, scan_index));
                }
            } else {
                expand_star_visit(input, qualifier_norm, bindings, scan_index, visited, out);
            }
        }
        RelPlan::Window {
            window_outputs,
            input,
            ..
        } => {
            // Window passes input rows through and appends outputs.
            // For star expansion, we want input schema first, then
            // appended outputs. Recurse into input then append.
            expand_star_visit(input, qualifier_norm, bindings, scan_index, visited, out);
            if qualifier_norm.is_none() {
                for cid in window_outputs {
                    out.push(column_id_to_ref(*cid, bindings, scan_index));
                }
            }
        }
        // Scope-preserving wrappers descend transparently.
        RelPlan::Project { input, .. }
        | RelPlan::Filter { input, .. }
        | RelPlan::Sort { input, .. }
        | RelPlan::Limit { input, .. }
        | RelPlan::TableSample { input, .. }
        | RelPlan::Pivot { input, .. }
        | RelPlan::Unpivot { input, .. }
        | RelPlan::MatchRecognize { input, .. }
        | RelPlan::ConnectBy { input, .. }
        | RelPlan::Unnest { input, .. } => {
            expand_star_visit(input, qualifier_norm, bindings, scan_index, visited, out);
        }
        RelPlan::WithScope { body, .. } => {
            expand_star_visit(body, qualifier_norm, bindings, scan_index, visited, out);
        }
        RelPlan::Explain { body, .. } => {
            expand_star_visit(body, qualifier_norm, bindings, scan_index, visited, out);
        }
        RelPlan::Join { left, right, .. } => {
            // Without a qualifier, a star enumerates every reachable
            // source; with a qualifier, only the matching side. Walk
            // both children — the qualifier match in CteRef/DerivedTable
            // arms filters to the right one.
            expand_star_visit(left, qualifier_norm, bindings, scan_index, visited, out);
            expand_star_visit(right, qualifier_norm, bindings, scan_index, visited, out);
        }
        // Sources without an outer-visible schema we can reproduce
        // without a catalog.
        RelPlan::Scan { .. }
        | RelPlan::Values { .. }
        | RelPlan::ModelRef { .. }
        | RelPlan::TableFunction { .. } => {}
        // Terminals that don't contribute to a SELECT projection.
        RelPlan::Insert { .. }
        | RelPlan::Update { .. }
        | RelPlan::Delete { .. }
        | RelPlan::Merge { .. }
        | RelPlan::MultiInsert { .. }
        | RelPlan::CreateAsQuery { .. }
        | RelPlan::CreateTableForm { .. }
        | RelPlan::ParseRecovery { .. }
        | RelPlan::Opaque { .. }
        | RelPlan::InvalidInput { .. } => {}
    }
}

fn project_outer_order_limit(
    source: &str,
    plan: &RelPlan,
    bindings: &BindingTable,
    scan_index: &ScanIndex,
) -> (Option<OrderByFact>, Option<LimitFact>) {
    let mut order_by: Option<OrderByFact> = None;
    let mut limit_offset: Option<LimitFact> = None;
    let mut current = plan;
    loop {
        match current {
            RelPlan::WithScope { body, .. } => current = body,
            RelPlan::Explain { body, .. } => current = body,
            RelPlan::Project { input, .. }
            | RelPlan::Filter { input, .. }
            | RelPlan::Aggregate { input, .. }
            | RelPlan::Window { input, .. }
            | RelPlan::TableSample { input, .. }
            | RelPlan::ConnectBy { input, .. }
            | RelPlan::Unnest { input, .. }
            | RelPlan::Pivot { input, .. }
            | RelPlan::Unpivot { input, .. }
            | RelPlan::MatchRecognize { input, .. }
            | RelPlan::DerivedTable { input, .. } => {
                current = input;
            }
            RelPlan::Sort { input, keys, .. } => {
                if order_by.is_none() {
                    order_by = Some(project_order_by_fact(source, keys, bindings, scan_index));
                }
                current = input;
            }
            RelPlan::Limit {
                input,
                limit,
                offset,
                ..
            } => {
                if limit_offset.is_none() && limit.is_some() {
                    limit_offset = Some(project_limit_fact(limit.as_ref(), offset.as_ref()));
                }
                current = input;
            }
            RelPlan::SetOp { .. }
            | RelPlan::Join { .. }
            | RelPlan::Scan { .. }
            | RelPlan::CteRef { .. }
            | RelPlan::ModelRef { .. }
            | RelPlan::Values { .. }
            | RelPlan::TableFunction { .. }
            | RelPlan::CreateAsQuery { .. }
            | RelPlan::CreateTableForm { .. }
            | RelPlan::Insert { .. }
            | RelPlan::Update { .. }
            | RelPlan::Delete { .. }
            | RelPlan::Merge { .. }
            | RelPlan::MultiInsert { .. }
            | RelPlan::ParseRecovery { .. }
            | RelPlan::Opaque { .. }
            | RelPlan::InvalidInput { .. } => break,
        }
    }
    (order_by, limit_offset)
}

fn project_order_by_fact(
    source: &str,
    keys: &[crate::ir::plan::SortKey],
    bindings: &BindingTable,
    scan_index: &ScanIndex,
) -> OrderByFact {
    let mut ordering_columns = Vec::new();
    let mut ordering_expressions = Vec::new();
    let mut directions = Vec::new();
    let mut nulls_ordering = Vec::new();
    for key in keys {
        match &key.expr {
            ScalarExpr::Column { column, .. } => {
                ordering_columns.push(column_id_to_ref(*column, bindings, scan_index));
            }
            _ => {
                let expr_text = span_text(source, key.expr.span()).to_string();
                ordering_expressions.push(expr_text);
            }
        }
        directions.push(!key.ascending);
        nulls_ordering.push(match key.nulls_first {
            Some(true) => Some(NullsOrdering::First),
            Some(false) => Some(NullsOrdering::Last),
            None => None,
        });
    }
    OrderByFact {
        ordering_columns,
        ordering_expressions,
        directions,
        nulls_ordering,
    }
}

fn scalar_u64_value_and_kind(expr: &ScalarExpr) -> (Option<u64>, bool) {
    match expr {
        ScalarExpr::Lit {
            value: Lit::Integer(s),
            ..
        }
        | ScalarExpr::Lit {
            value: Lit::Float(s),
            ..
        } => (s.parse::<u64>().ok(), false),
        _ => (None, true),
    }
}

fn project_limit_fact(limit: Option<&ScalarExpr>, offset: Option<&ScalarExpr>) -> LimitFact {
    let (limit_value, limit_is_expression) = match limit {
        Some(expr) => scalar_u64_value_and_kind(expr),
        None => (None, false),
    };
    let (offset_value, offset_is_expression) = match offset {
        Some(expr) => scalar_u64_value_and_kind(expr),
        None => (None, false),
    };
    LimitFact {
        limit_value,
        offset_value,
        limit_is_expression,
        offset_is_expression,
    }
}

/// Resolve the principal base-table reference of an IR plan for
/// join-edge projection. A JOIN's left/right side resolves to:
///
///   - the underlying base table at a [`RelPlan::Scan`];
///   - the CTE's name as a `TableRef` (no schema/db) at a
///     [`RelPlan::CteRef`];
///   - the principal of the inner plan for scope-preserving
///     wrappers ([`Project`], [`Filter`], [`Aggregate`], [`Window`],
///     [`Sort`], [`Limit`], [`TableSample`], [`Pivot`], [`Unpivot`],
///     [`MatchRecognize`], [`ConnectBy`], [`Unnest`], [`DerivedTable`]);
///   - the principal of the **right** subtree at a nested
///     [`RelPlan::Join`] — after each join the
///     right-hand table becomes the new left for the next join in
///     the chain. So `A JOIN B JOIN C` (lowered as `Join(Join(A,B), C)`)
///     emits edges `(A, B)` and `(B, C)`, not `(A, C)`.
///   - the first input's principal at a [`RelPlan::SetOp`].
///
/// Returns `None` for plans that have no single base-table
/// representative (DML statements, table-valued functions,
/// `VALUES`, `Opaque`, etc.). Callers MUST skip emitting an edge
/// when either side resolves to `None` — join_edges are omitted
/// for unresolvable references rather than emitting placeholder
/// rows.
///
/// [`Project`]: RelPlan::Project
/// [`Filter`]: RelPlan::Filter
/// [`Aggregate`]: RelPlan::Aggregate
/// [`Window`]: RelPlan::Window
/// [`Sort`]: RelPlan::Sort
/// [`Limit`]: RelPlan::Limit
/// [`TableSample`]: RelPlan::TableSample
/// [`Pivot`]: RelPlan::Pivot
/// [`Unpivot`]: RelPlan::Unpivot
/// [`MatchRecognize`]: RelPlan::MatchRecognize
/// [`ConnectBy`]: RelPlan::ConnectBy
/// [`Unnest`]: RelPlan::Unnest
/// [`DerivedTable`]: RelPlan::DerivedTable
fn principal_table(plan: &RelPlan) -> Option<TableRef> {
    match plan {
        RelPlan::Scan { table, .. } => Some(table.clone()),
        RelPlan::CteRef { name, .. } => Some(TableRef::new(name.as_str().to_string())),
        RelPlan::ModelRef { model, .. } => model.base_tables.first().cloned(),
        RelPlan::Join { right, .. } => principal_table(right),
        RelPlan::SetOp { inputs, .. } => inputs.first().and_then(|p| principal_table(p)),
        RelPlan::Project { input, .. }
        | RelPlan::Filter { input, .. }
        | RelPlan::Aggregate { input, .. }
        | RelPlan::Window { input, .. }
        | RelPlan::Sort { input, .. }
        | RelPlan::Limit { input, .. }
        | RelPlan::TableSample { input, .. }
        | RelPlan::Pivot { input, .. }
        | RelPlan::Unpivot { input, .. }
        | RelPlan::MatchRecognize { input, .. }
        | RelPlan::ConnectBy { input, .. }
        | RelPlan::Unnest { input, .. }
        | RelPlan::DerivedTable { input, .. } => principal_table(input),
        RelPlan::Explain { body, .. } => principal_table(body),
        RelPlan::CreateAsQuery { body, .. } => body.as_deref().and_then(principal_table),
        RelPlan::WithScope { body, .. } => principal_table(body),
        RelPlan::Values { .. }
        | RelPlan::TableFunction { .. }
        | RelPlan::CreateTableForm { .. }
        | RelPlan::Insert { .. }
        | RelPlan::Update { .. }
        | RelPlan::Delete { .. }
        | RelPlan::Merge { .. }
        | RelPlan::MultiInsert { .. }
        | RelPlan::ParseRecovery { .. }
        | RelPlan::Opaque { .. } => None,
        RelPlan::InvalidInput { .. } => None,
    }
}

/// Map an IR [`JoinKind`] to the smaller [`MetadataJoinKind`]
/// alphabet. The IR distinguishes Semi/Anti flavors that
/// [`MetadataJoinKind`] lacks; they collapse to `Inner`.
fn ir_to_metadata_join_kind(kind: JoinKind) -> MetadataJoinKind {
    match kind {
        JoinKind::Inner => MetadataJoinKind::Inner,
        JoinKind::LeftOuter => MetadataJoinKind::Left,
        JoinKind::RightOuter => MetadataJoinKind::Right,
        JoinKind::FullOuter => MetadataJoinKind::Full,
        JoinKind::Cross => MetadataJoinKind::Cross,
        JoinKind::Asof => MetadataJoinKind::Left,
        JoinKind::LeftSemi | JoinKind::RightSemi | JoinKind::LeftAnti | JoinKind::RightAnti => {
            MetadataJoinKind::Inner
        }
    }
}

/// Map an IR [`SetOpKind`] to the [`SetOperation`]
/// alphabet. The IR distinguishes ALL vs DISTINCT for every set
/// operation; [`SetOperation`] only distinguishes `Union` vs
/// `UnionAll`. INTERSECT / EXCEPT collapse to a single variant
/// regardless of modifier.
fn set_op_kind_to_operation(kind: SetOpKind) -> SetOperation {
    match kind {
        SetOpKind::UnionAll => SetOperation::UnionAll,
        SetOpKind::UnionDistinct => SetOperation::Union,
        SetOpKind::IntersectAll | SetOpKind::IntersectDistinct => SetOperation::Intersect,
        SetOpKind::ExceptAll | SetOpKind::ExceptDistinct => SetOperation::Except,
    }
}

/// Convert a `(db, schema, name)` accumulator into a sorted /
/// deduped `Vec<TableRef>`. Shared by both `tables_read` and
/// `tables_written` finalization so their normalization rules
/// stay identical.
/// Dedup key for a collected table reference: `(server, db, schema, name)`.
/// `TableRef` lacks `Ord`, so a tuple keys the `BTreeSet`. The linked-server
/// component is included so four-part references survive collection.
pub type TableKey = (Option<String>, Option<String>, Option<String>, String);

fn finalize_table_set(set: BTreeSet<TableKey>) -> Vec<TableRef> {
    let mut v: Vec<TableRef> = set
        .into_iter()
        .map(|(server, db, schema, name)| {
            let mut t = TableRef::new(name);
            t.server = server;
            t.db = db;
            t.schema = schema;
            t
        })
        .collect();
    sort_and_dedup_tables(&mut v);
    v
}

/// Sort a vector of [`TableRef`] by `(db, schema, name)` and dedup
/// using `TableRef`'s case-normalized [`PartialEq`]. `TableRef` does
/// not implement [`Ord`]; `Vec::sort_by` over the triple is the
/// canonical ordering used in baseline outputs elsewhere.
pub fn sort_and_dedup_tables(tables: &mut Vec<TableRef>) {
    tables.sort_by(|a, b| {
        (
            a.server.as_deref(),
            a.db.as_deref(),
            a.schema.as_deref(),
            a.name.as_str(),
        )
            .cmp(&(
                b.server.as_deref(),
                b.db.as_deref(),
                b.schema.as_deref(),
                b.name.as_str(),
            ))
    });
    tables.dedup();
}

// ── Aggregate / GroupBy / Having projection helpers ─────────────────────────
//
// Use the canonical helpers from `predicate_extraction` (now pub(crate))
// rather than parallel reimplementations.

/// Walk a `ScalarExpr` and collect any nested `FunctionCallFact`s
/// (regular function calls appearing inside aggregate arguments, e.g.
/// `DATE_TRUNC` inside `SUM(DATE_TRUNC('day', col))`).
fn collect_agg_call_function_facts(
    source: &str,
    expr: &ScalarExpr,
    out: &mut Vec<crate::context::node_metadata::FunctionCallFact>,
) {
    use crate::context::node_metadata::FunctionCallFact;
    match expr {
        ScalarExpr::FuncCall {
            func,
            args,
            named_args,
            span,
            ..
        } => {
            out.push(FunctionCallFact {
                name: resolved_func_name(func),
                expression: span_text(source, *span).to_string(),
                span: *span,
            });
            for a in args {
                collect_agg_call_function_facts(source, a, out);
            }
            for (_, v) in named_args {
                collect_agg_call_function_facts(source, v, out);
            }
        }
        ScalarExpr::Like {
            expr,
            pattern,
            escape,
            ..
        } => {
            collect_agg_call_function_facts(source, expr, out);
            collect_agg_call_function_facts(source, pattern, out);
            if let Some(e) = escape {
                collect_agg_call_function_facts(source, e, out);
            }
        }
        ScalarExpr::BinOp { left, right, .. } => {
            collect_agg_call_function_facts(source, left, out);
            collect_agg_call_function_facts(source, right, out);
        }
        ScalarExpr::LogicalChain { operands, .. } => {
            for operand in operands {
                collect_agg_call_function_facts(source, operand, out);
            }
        }
        ScalarExpr::UnaryOp { arg, .. } => {
            collect_agg_call_function_facts(source, arg, out);
        }
        ScalarExpr::Case {
            operand,
            branches,
            else_,
            ..
        } => {
            if let Some(op) = operand {
                collect_agg_call_function_facts(source, op, out);
            }
            for (cond, result) in branches {
                collect_agg_call_function_facts(source, cond, out);
                collect_agg_call_function_facts(source, result, out);
            }
            if let Some(e) = else_ {
                collect_agg_call_function_facts(source, e, out);
            }
        }
        ScalarExpr::Lit { .. }
        | ScalarExpr::Column { .. }
        | ScalarExpr::OuterRef { .. }
        | ScalarExpr::PatternVarRef { .. }
        | ScalarExpr::Opaque { .. }
        | ScalarExpr::WindowFn { .. }
        | ScalarExpr::ScalarSubquery { .. }
        | ScalarExpr::Exists { .. }
        | ScalarExpr::QuantifiedCmp { .. } => {}
        ScalarExpr::InList { expr, list, .. } => {
            collect_agg_call_function_facts(source, expr, out);
            for e in list {
                collect_agg_call_function_facts(source, e, out);
            }
        }
        ScalarExpr::Between {
            expr, low, high, ..
        } => {
            collect_agg_call_function_facts(source, expr, out);
            collect_agg_call_function_facts(source, low, out);
            collect_agg_call_function_facts(source, high, out);
        }
        ScalarExpr::Cast { expr, .. } => collect_agg_call_function_facts(source, expr, out),
        ScalarExpr::FieldAccess { base, .. } => {
            collect_agg_call_function_facts(source, base, out);
        }
        ScalarExpr::Lambda { body, .. } => {
            collect_agg_call_function_facts(source, body, out);
        }
    }
}

/// Build a `HashMap<ColumnId, Option<String>>` mapping each aggregate
/// output `ColumnId` to its alias from the enclosing `Project` node.
/// A pre-pass over the full plan tree is used so aliases are available
/// when the `Aggregate` arm runs during the main walk.
fn build_alias_map(plan: &RelPlan) -> HashMap<ColumnId, Option<String>> {
    let mut map = HashMap::new();
    collect_aliases(plan, &mut map);
    map
}

fn collect_aliases(plan: &RelPlan, map: &mut HashMap<ColumnId, Option<String>>) {
    match plan {
        RelPlan::Project { items, input, .. } => {
            for item in items {
                if let ProjectItem::Expr(e) = item {
                    // If this ProjectItem's expression is a direct Column
                    // reference, the ColumnId is an aggregate output whose
                    // alias should be recorded.
                    if let ScalarExpr::Column { column, .. } = &e.expr {
                        map.insert(*column, e.alias.as_ref().map(|k| k.as_str().to_string()));
                    }
                }
            }
            collect_aliases(input, map);
        }
        // Scope-preserving wrappers — recurse into their child.
        RelPlan::Filter { input, .. }
        | RelPlan::Aggregate { input, .. }
        | RelPlan::Window { input, .. }
        | RelPlan::Sort { input, .. }
        | RelPlan::Limit { input, .. }
        | RelPlan::TableSample { input, .. }
        | RelPlan::Pivot { input, .. }
        | RelPlan::Unpivot { input, .. }
        | RelPlan::MatchRecognize { input, .. }
        | RelPlan::ConnectBy { input, .. }
        | RelPlan::Unnest { input, .. }
        | RelPlan::DerivedTable { input, .. } => collect_aliases(input, map),
        RelPlan::Join { left, right, .. } => {
            collect_aliases(left, map);
            collect_aliases(right, map);
        }
        RelPlan::SetOp { inputs, .. } => {
            for b in inputs {
                collect_aliases(b, map);
            }
        }
        RelPlan::WithScope { ctes, body, .. } => {
            for binding in ctes {
                match &binding.body {
                    CteBody::NonRecursive(p) => collect_aliases(p, map),
                    CteBody::Recursive { anchor, step, .. } => {
                        collect_aliases(anchor, map);
                        collect_aliases(step, map);
                    }
                }
            }
            collect_aliases(body, map);
        }
        RelPlan::Explain { body, .. } => collect_aliases(body, map),
        RelPlan::CreateAsQuery { body, .. } => {
            if let Some(b) = body.as_deref() {
                collect_aliases(b, map);
            }
        }
        RelPlan::Insert { source, .. } => match source {
            InsertSource::Values(p) | InsertSource::Query(p) => collect_aliases(p, map),
            InsertSource::DefaultValues => {}
        },
        RelPlan::Update { from, .. } => {
            if let Some(f) = from {
                collect_aliases(f, map);
            }
        }
        RelPlan::Delete { .. }
        | RelPlan::Merge { .. }
        | RelPlan::MultiInsert { .. }
        | RelPlan::Scan { .. }
        | RelPlan::CteRef { .. }
        | RelPlan::ModelRef { .. }
        | RelPlan::TableFunction { .. }
        | RelPlan::Values { .. }
        | RelPlan::CreateTableForm { .. }
        | RelPlan::ParseRecovery { .. }
        | RelPlan::Opaque { .. }
        | RelPlan::InvalidInput { .. } => {}
    }
}

/// Project one `AggregateCall` to a metadata `AggregateFact`.
fn project_one_aggregate(
    source: &str,
    call: &AggregateCall,
    bindings: &BindingTable,
    scan_index: &ScanIndex,
    alias_map: &HashMap<ColumnId, Option<String>>,
) -> AggregateFact {
    let function_name = resolved_func_name(&call.func);
    let is_distinct = call.distinct;
    // Resolve output alias from the enclosing Project (pre-pass).
    let output_alias = alias_map.get(&call.output).and_then(|v| v.clone());
    // First positional argument → argument_column / argument_expr.
    let (argument_column, argument_expr) = if call.args.is_empty() {
        // COUNT(*) and similar zero-arg aggregates.
        (None, Some("*".to_string()))
    } else {
        let first = &call.args[0];
        let col = if let ScalarExpr::Column { column, .. } = first {
            Some(column_id_to_ref(*column, bindings, scan_index))
        } else {
            None
        };
        let expr_text = span_text(source, first.span()).to_string();
        let expr_opt = if expr_text.is_empty() {
            None
        } else {
            Some(expr_text)
        };
        (col, expr_opt)
    };
    // Collect nested function calls from all args.
    let mut argument_function_calls = Vec::new();
    for a in &call.args {
        collect_agg_call_function_facts(source, a, &mut argument_function_calls);
    }
    // Structured expression fact from the first arg (if present).
    // `argument_fact` is excluded from `AggregateFact::PartialEq` but is
    // populated here for completeness so consumers can use it.
    let argument_fact = if call.args.is_empty() {
        None
    } else {
        Some(scalar_to_expression_fact(
            &call.args[0],
            bindings,
            scan_index,
        ))
    };
    AggregateFact {
        function_name,
        argument_column,
        argument_expr,
        argument_fact,
        output_alias,
        is_distinct,
        argument_function_calls,
        span: call.span,
    }
}

/// Format one IR [`FrameBound`] as text. Literal-valued bounds use the
/// raw source span text.
fn format_ir_frame_bound(source: &str, bound: &FrameBound) -> String {
    match bound {
        FrameBound::UnboundedPreceding => "UNBOUNDED PRECEDING".to_string(),
        FrameBound::UnboundedFollowing => "UNBOUNDED FOLLOWING".to_string(),
        FrameBound::CurrentRow => "CURRENT ROW".to_string(),
        FrameBound::Preceding(expr) => {
            let text = span_text(source, expr.span()).to_string();
            format!("{} PRECEDING", text)
        }
        FrameBound::Following(expr) => {
            let text = span_text(source, expr.span()).to_string();
            format!("{} FOLLOWING", text)
        }
    }
}

/// Project one IR [`WindowCall`] to a metadata [`WindowFunctionFact`].
fn project_window_call(source: &str, call: &WindowCall) -> WindowFunctionFact {
    use crate::context::node_metadata::FunctionCallFact;

    let function_name = resolved_func_name(&call.func);

    let partition_by = call
        .partition_by
        .iter()
        .map(|expr| span_text(source, expr.span()).to_string())
        .collect::<Vec<_>>();

    let order_by = call
        .order_by
        .iter()
        .map(|key| {
            let text = span_text(source, key.expr.span()).to_string();
            let is_desc = !key.ascending;
            (text, is_desc)
        })
        .collect::<Vec<_>>();

    let has_frame = call.frame.is_some();

    let frame_spec = call.frame.as_ref().map(|frame| {
        let kind = match frame.mode {
            FrameMode::Rows => "ROWS",
            FrameMode::Range => "RANGE",
            FrameMode::Groups => "GROUPS",
        };
        let start = format_ir_frame_bound(source, &frame.start);
        let end = format_ir_frame_bound(source, &frame.end);
        format!("{} BETWEEN {} AND {}", kind, start, end)
    });

    // Collect nested function calls from partition_by / order_by exprs.
    let mut partition_function_calls: Vec<FunctionCallFact> = Vec::new();
    for expr in &call.partition_by {
        collect_agg_call_function_facts(source, expr, &mut partition_function_calls);
    }
    let mut order_function_calls: Vec<FunctionCallFact> = Vec::new();
    for key in &call.order_by {
        collect_agg_call_function_facts(source, &key.expr, &mut order_function_calls);
    }

    WindowFunctionFact {
        function_name,
        partition_by,
        order_by,
        has_frame,
        span: Some(call.span),
        frame_spec,
        partition_function_calls,
        order_function_calls,
    }
}

/// Flatten all `GroupKey`s from a `GroupingSpec` into a single vec
/// (regardless of CUBE/ROLLUP/GROUPING SETS shape). Returns the flat
/// key list and the three modifier flags.
fn grouping_spec_keys(spec: &GroupingSpec) -> (Vec<&GroupKey>, bool, bool, bool, bool) {
    match spec {
        GroupingSpec::None => (vec![], false, false, false, false),
        GroupingSpec::Standard(keys) => (keys.iter().collect(), false, false, false, false),
        GroupingSpec::Cube(keys) => (keys.iter().collect(), false, true, false, false),
        GroupingSpec::Rollup(keys) => (keys.iter().collect(), false, false, true, false),
        GroupingSpec::GroupingSets(sets) => {
            let flat: Vec<&GroupKey> = sets.iter().flat_map(|s| s.iter()).collect();
            (flat, false, false, false, true)
        }
        GroupingSpec::All(keys) => (keys.iter().collect(), true, false, false, false),
    }
}

/// Project `GroupingSpec` + `AggregateCall` list to a metadata
/// `GroupByFact`. Returns `None` for `GroupingSpec::None` (implicit
/// aggregation has no GROUP BY clause).
fn project_group_by(
    source: &str,
    grouping: &GroupingSpec,
    bindings: &BindingTable,
    scan_index: &ScanIndex,
) -> Option<GroupByFact> {
    if matches!(grouping, GroupingSpec::None) {
        return None;
    }
    let (keys, is_group_by_all, has_cube, has_rollup, has_grouping_sets) =
        grouping_spec_keys(grouping);
    let mut grouping_columns = Vec::new();
    let mut grouping_expressions = Vec::new();
    for key in keys {
        match &key.expr {
            ScalarExpr::Column { column, .. } => {
                grouping_columns.push(column_id_to_ref(*column, bindings, scan_index));
            }
            ScalarExpr::Lit {
                value: Lit::Integer(s),
                ..
            } => {
                // GROUP BY ordinal — add as expression text.
                grouping_expressions.push(s.clone());
            }
            // All remaining variants are expression-based GROUP BY keys
            // (function calls, arithmetic, CASE, semi-structured paths, etc.).
            // Record the source-text span as the expression string
            // stored in `grouping_expressions`.
            ScalarExpr::OuterRef { span, .. }
            | ScalarExpr::Lit { span, .. }
            | ScalarExpr::BinOp { span, .. }
            | ScalarExpr::LogicalChain { span, .. }
            | ScalarExpr::UnaryOp { span, .. }
            | ScalarExpr::FuncCall { span, .. }
            | ScalarExpr::Case { span, .. }
            | ScalarExpr::Cast { span, .. }
            | ScalarExpr::InList { span, .. }
            | ScalarExpr::Between { span, .. }
            | ScalarExpr::Like { span, .. }
            | ScalarExpr::Exists { span, .. }
            | ScalarExpr::ScalarSubquery { span, .. }
            | ScalarExpr::QuantifiedCmp { span, .. }
            | ScalarExpr::WindowFn { span, .. }
            | ScalarExpr::FieldAccess { span, .. }
            | ScalarExpr::Lambda { span, .. }
            | ScalarExpr::PatternVarRef { span, .. }
            | ScalarExpr::Opaque { span, .. } => {
                let text = span_text(source, *span).to_string();
                if !text.is_empty() {
                    grouping_expressions.push(text);
                }
            }
        }
    }
    Some(GroupByFact {
        grouping_columns,
        grouping_expressions,
        is_group_by_all,
        has_rollup,
        has_cube,
        has_grouping_sets,
    })
}

/// Collect aggregate function names referenced in the HAVING expression
/// by matching `ColumnId` references to `AggregateCall` outputs.
fn having_aggregate_functions(
    having_expr: &ScalarExpr,
    aggregates: &[AggregateCall],
) -> Vec<String> {
    // Collect all ColumnId refs in the having expression.
    let mut col_ids: Vec<ColumnId> = Vec::new();
    collect_column_ids(having_expr, &mut col_ids);
    // Match those IDs to aggregate outputs.
    let mut funcs: Vec<String> = aggregates
        .iter()
        .filter(|a| col_ids.contains(&a.output))
        .map(|a| resolved_func_name(&a.func))
        .collect();
    funcs.sort();
    funcs.dedup();
    funcs
}

fn collect_column_ids(expr: &ScalarExpr, out: &mut Vec<ColumnId>) {
    match expr {
        ScalarExpr::Column { column, .. } => out.push(*column),
        ScalarExpr::OuterRef { column, .. } => out.push(*column),
        ScalarExpr::Like {
            expr,
            pattern,
            escape,
            ..
        } => {
            collect_column_ids(expr, out);
            collect_column_ids(pattern, out);
            if let Some(e) = escape {
                collect_column_ids(e, out);
            }
        }
        ScalarExpr::BinOp { left, right, .. } => {
            collect_column_ids(left, out);
            collect_column_ids(right, out);
        }
        ScalarExpr::LogicalChain { operands, .. } => {
            for operand in operands {
                collect_column_ids(operand, out);
            }
        }
        ScalarExpr::UnaryOp { arg, .. } => collect_column_ids(arg, out),
        ScalarExpr::FuncCall {
            args, named_args, ..
        } => {
            for a in args {
                collect_column_ids(a, out);
            }
            for (_, v) in named_args {
                collect_column_ids(v, out);
            }
        }
        ScalarExpr::Case {
            operand,
            branches,
            else_,
            ..
        } => {
            if let Some(op) = operand {
                collect_column_ids(op, out);
            }
            for (cond, result) in branches {
                collect_column_ids(cond, out);
                collect_column_ids(result, out);
            }
            if let Some(e) = else_ {
                collect_column_ids(e, out);
            }
        }
        ScalarExpr::InList { expr, list, .. } => {
            collect_column_ids(expr, out);
            for e in list {
                collect_column_ids(e, out);
            }
        }
        ScalarExpr::Between {
            expr, low, high, ..
        } => {
            collect_column_ids(expr, out);
            collect_column_ids(low, out);
            collect_column_ids(high, out);
        }
        ScalarExpr::Cast { expr, .. } => collect_column_ids(expr, out),
        ScalarExpr::FieldAccess { base, .. } => collect_column_ids(base, out),
        ScalarExpr::Lambda { body, .. } => collect_column_ids(body, out),
        ScalarExpr::PatternVarRef { column, .. } => out.push(*column),
        ScalarExpr::Lit { .. }
        | ScalarExpr::Opaque { .. }
        | ScalarExpr::WindowFn { .. }
        | ScalarExpr::ScalarSubquery { .. }
        | ScalarExpr::Exists { .. }
        | ScalarExpr::QuantifiedCmp { .. } => {}
    }
}

/// Project `Aggregate.having` + `Aggregate.aggregates` to a metadata
/// `HavingFact`. Returns `None` when no HAVING clause is present.
fn project_having(
    source: &str,
    having_expr: &ScalarExpr,
    aggregates: &[AggregateCall],
) -> HavingFact {
    let expression = span_text(source, having_expr.span()).to_string();
    let aggregate_functions = having_aggregate_functions(having_expr, aggregates);
    // `columns` intentionally left empty: see `HavingFact::PartialEq` doc.
    HavingFact {
        columns: Vec::new(),
        aggregate_functions,
        expression,
        expression_fact: None,
        span: having_expr.span(),
    }
}

/// Exhaustive walk over [`RelPlan`]. Every variant must contribute
/// explicitly — no `_ =>` arm.
///
/// `cte_refs` accumulates the names encountered at [`RelPlan::CteRef`]
/// sites. The [`RelPlan::WithScope`] arm uses this to determine which
/// CTE bindings were actually referenced by the outer scope — only
/// referenced CTEs contribute their `tables_read` (and
/// `tables_written`) to the shared accumulator (a CTE's `base_tables`
/// are only appended when a table-ref resolves to it).
///
/// `tables_written` accumulates DML target tables. The IR `Insert`,
/// `Update`, `Delete`, `Merge`, and `MultiInsert` arms push their
/// target(s) at entry; recursion into `WithScope`, `Explain`,
/// `DerivedTable`, and `SetOp` branches threads the same accumulator
/// so writes performed inside CTE bodies (e.g. PostgreSQL
/// `WITH x AS (DELETE … RETURNING) …`) propagate up to the outer
/// scope.
///
/// `cte_names` accumulates names of CTE bindings introduced by
/// [`RelPlan::WithScope`] in scopes that contribute to the outer
/// statement's visible CTE set. It is shared across scope-preserving
/// arms (Project/Filter/Sort/Limit/Aggregate/Join/SetOp branches and
/// DML sub-sources) and scratched at true scope boundaries
/// ([`RelPlan::DerivedTable`] inputs and per-CTE binding bodies), so
/// inner subquery CTE definitions never fold into the outer
/// statement's set.
fn walk(
    plan: &RelPlan,
    facts: &mut DerivedFacts,
    tables: &mut BTreeSet<TableKey>,
    tables_written: &mut BTreeSet<TableKey>,
    cte_refs: &mut HashSet<IdentKey>,
    cte_names: &mut HashSet<IdentKey>,
    set_operations: &mut Vec<SetOperationFact>,
    join_edges: &mut Vec<JoinEdge>,
    containing_cte: Option<&str>,
    ctx: &WalkCtx<'_>,
) {
    match plan {
        RelPlan::Scan { table, .. } => {
            // Normalize to a (db, schema, name) triple so the set
            // dedupes case-variant spellings. We round-trip through
            // the same normalization `TableRef` equality uses.
            tables.insert((
                table.server.clone(),
                table.db.clone(),
                table.schema.clone(),
                table.name.clone(),
            ));
        }
        RelPlan::CteRef { name, .. } => {
            // The reference itself contributes no table; record the
            // name so the enclosing `WithScope` can decide whether
            // the binding's `tables_read` should propagate.
            cte_refs.insert(name.clone());
        }
        RelPlan::ModelRef { model, .. } => {
            // Expand the upstream physical base tables into the
            // accumulator rather than the model's own relation name.
            for base in &model.base_tables {
                tables.insert((
                    base.server.clone(),
                    base.db.clone(),
                    base.schema.clone(),
                    base.name.clone(),
                ));
            }
        }
        RelPlan::Project {
            input,
            items,
            distinct,
            distinct_on,
            ..
        } => {
            if *distinct {
                facts.has_distinct = true;
            }
            // Descend into each projection expression so scalar
            // subqueries (`SELECT (SELECT x FROM t)`) contribute their
            // tables to the outer statement's `tables_read`.
            for item in items {
                match item {
                    crate::ir::plan::ProjectItem::Expr(e) => {
                        walk_scalar(&e.expr, tables, tables_written, cte_refs, ctx);
                    }
                    crate::ir::plan::ProjectItem::Star(s) => {
                        // Star items carry scalar subexpressions in
                        // `REPLACE (expr AS col)` and in the rare
                        // `expr.*` shape; walk both so any nested
                        // scalar subqueries propagate their
                        // `tables_read` to the enclosing scope.
                        match &s.qualifier {
                            crate::ir::plan::StarQualifier::Unqualified
                            | crate::ir::plan::StarQualifier::Named(_) => {}
                            crate::ir::plan::StarQualifier::FromExpr(e) => {
                                walk_scalar(e, tables, tables_written, cte_refs, ctx);
                            }
                        }
                        for r in &s.replace {
                            walk_scalar(&r.expr, tables, tables_written, cte_refs, ctx);
                        }
                    }
                }
            }
            // PostgreSQL `DISTINCT ON (e1, e2, \u2026)` key expressions
            // — walked alongside `items` so any scalar subqueries
            // inside an ON key contribute their tables to
            // `tables_read`.
            for expr in distinct_on {
                walk_scalar(expr, tables, tables_written, cte_refs, ctx);
            }
            walk(
                input,
                facts,
                tables,
                tables_written,
                cte_refs,
                cte_names,
                set_operations,
                join_edges,
                containing_cte,
                ctx,
            );
        }
        RelPlan::Filter {
            input,
            predicate,
            kind,
            ..
        } => {
            match kind {
                FilterKind::Where => facts.has_where = true,
                FilterKind::Qualify => facts.has_qualify = true,
                FilterKind::Having => {
                    // Lifted HAVING above Project (alias-bearing
                    // predicate). The
                    // statement's HAVING facts (`having`,
                    // `having_predicates`) are projected from
                    // `Aggregate.having` and the having extractor;
                    // the lift is a structural placement and
                    // contributes no additional flag here.
                }
            }
            // Predicates are the most common home of subqueries
            // (`WHERE x IN (SELECT …)`, `WHERE EXISTS (…)`).
            walk_scalar(predicate, tables, tables_written, cte_refs, ctx);
            walk(
                input,
                facts,
                tables,
                tables_written,
                cte_refs,
                cte_names,
                set_operations,
                join_edges,
                containing_cte,
                ctx,
            );
        }
        RelPlan::Aggregate {
            input,
            grouping,
            aggregates,
            having,
            ..
        } => {
            // `GroupingSpec::None` is the "implicit aggregation" case
            // (e.g. `SELECT COUNT(*) FROM t` with no GROUP BY); it
            // does not count as a GROUP BY clause.
            if !matches!(grouping, GroupingSpec::None) {
                facts.has_group_by = true;
            }
            if !aggregates.is_empty() {
                facts.has_aggregates = true;
            }
            for call in aggregates {
                walk_aggregate_call(call, tables, tables_written, cte_refs, ctx);
            }
            if let Some(h) = having {
                walk_scalar(h, tables, tables_written, cte_refs, ctx);
            }
            // Project structured aggregate facts into the shared
            // accumulator (flat across all scopes).
            {
                let mut acc = ctx.agg_acc.borrow_mut();
                for call in aggregates {
                    acc.push(project_one_aggregate(
                        ctx.source,
                        call,
                        ctx.bindings,
                        ctx.scan_index,
                        &ctx.alias_map,
                    ));
                }
            }
            // `group_by` and `having` are outer-scope-only: set them
            // in `facts` only when this is the outermost Aggregate
            // node (CTE body walks use a scratch DerivedFacts, so
            // their Aggregate arms write to scratch.group_by which
            // is then discarded).
            if facts.group_by.is_none() {
                facts.group_by =
                    project_group_by(ctx.source, grouping, ctx.bindings, ctx.scan_index);
            }
            if facts.having.is_none() {
                if let Some(h) = having {
                    facts.having = Some(project_having(ctx.source, h, aggregates));
                }
            }
            walk(
                input,
                facts,
                tables,
                tables_written,
                cte_refs,
                cte_names,
                set_operations,
                join_edges,
                containing_cte,
                ctx,
            );
        }
        RelPlan::Window { input, windows, .. } => {
            for call in windows {
                // Accumulate window function facts flat across all
                // scopes.
                ctx.wf_acc
                    .borrow_mut()
                    .push(project_window_call(ctx.source, call));
                // A WindowCall holds its own scalars; reuse the
                // WindowFn-arm walk to traverse them.
                let synthetic = ScalarExpr::WindowFn {
                    call: Box::new((*call).clone()),
                    span: call.span,
                };
                walk_scalar(&synthetic, tables, tables_written, cte_refs, ctx);
            }
            walk(
                input,
                facts,
                tables,
                tables_written,
                cte_refs,
                cte_names,
                set_operations,
                join_edges,
                containing_cte,
                ctx,
            );
        }
        RelPlan::Join {
            left,
            right,
            kind,
            on,
            match_condition,
            span,
            ..
        } => {
            facts.immediate_join_count += 1;
            // Project a `JoinEdge` whenever both sides resolve to a
            // single principal base-table reference. No edge is
            // emitted when either side cannot be resolved (e.g.
            // a TVF or `VALUES` source). `on_clause` is projected
            // through the `ScalarExpr → ExpressionFact` bridge in
            // `crate::ir::expression_fact`; `union_branch_index` has
            // no IR-side analog on the flattened `SetOp` spine and is
            // intentionally left `None`.
            if let (Some(left_ref), Some(right_ref)) =
                (principal_table(left), principal_table(right))
            {
                join_edges.push(JoinEdge {
                    left: left_ref,
                    right: right_ref,
                    kind: ir_to_metadata_join_kind(*kind),
                    span: Some(*span),
                    containing_cte: containing_cte.map(|s| s.to_string()),
                    union_branch_index: None,
                    on_clause: on
                        .as_ref()
                        .map(|p| scalar_to_expression_fact(p, ctx.bindings, ctx.scan_index)),
                });
            }
            if let Some(pred) = on {
                walk_scalar(pred, tables, tables_written, cte_refs, ctx);
            }
            if let Some(pred) = match_condition {
                walk_scalar(pred, tables, tables_written, cte_refs, ctx);
            }
            walk(
                left,
                facts,
                tables,
                tables_written,
                cte_refs,
                cte_names,
                set_operations,
                join_edges,
                containing_cte,
                ctx,
            );
            walk(
                right,
                facts,
                tables,
                tables_written,
                cte_refs,
                cte_names,
                set_operations,
                join_edges,
                containing_cte,
                ctx,
            );
        }
        RelPlan::SetOp { op, inputs, .. } => {
            // Each branch of a SET operation is an independent query
            // scope. Scalar flags
            // (has_where / has_group_by / has_distinct /
            // has_aggregates / immediate_join_count) describe the
            // *outer* query only; a top-level set operation has no
            // outer WHERE/GROUP/etc., so those flags stay false
            // even when individual branches contain them. Collect
            // `tables_read` /
            // `tables_written` and CTE references across branches
            // but do *not* propagate the scalar flags out of a
            // branch. The `facts` we pass to the recursive walk is
            // a scratch instance that gets discarded; the table /
            // cte_refs accumulators are shared.
            for branch in inputs {
                let mut scratch = DerivedFacts::empty();
                // `cte_names` IS shared across SetOp branches, so a
                // `WITH x AS (…) SELECT … UNION SELECT …` surfaces
                // `x` at the set-operation level.
                walk(
                    branch,
                    &mut scratch,
                    tables,
                    tables_written,
                    cte_refs,
                    cte_names,
                    set_operations,
                    join_edges,
                    containing_cte,
                    ctx,
                );
            }
            // Un-flatten the IR's flattened spine into pairwise
            // syntactic events. The IR collapses
            // `A UNION B UNION C` into a single `SetOp` of arity 3;
            // the fact list carries one `SetOperationFact` per
            // syntactic set operator, i.e. two pairwise
            // events with `branch_count: 2`. The IR's truthful arity
            // stays available on the plan itself for downstream
            // consumers. Branches are walked
            // FIRST above so nested set-op events appear in
            // document order ahead of the enclosing operator.
            let pairs = inputs.len().saturating_sub(1);
            if pairs > 0 {
                let operation = set_op_kind_to_operation(*op);
                for _ in 0..pairs {
                    set_operations.push(SetOperationFact {
                        operation,
                        branch_count: 2,
                    });
                }
            }
        }
        RelPlan::Sort { input, keys, .. } => {
            for k in keys {
                walk_scalar(&k.expr, tables, tables_written, cte_refs, ctx);
            }
            walk(
                input,
                facts,
                tables,
                tables_written,
                cte_refs,
                cte_names,
                set_operations,
                join_edges,
                containing_cte,
                ctx,
            );
        }
        RelPlan::Limit {
            input,
            limit,
            offset,
            kind,
            ..
        } => {
            facts.has_limit = true;
            // Extract the literal value when the limit is a bare
            // non-negative integer literal. Anything else
            // (parameters, expressions, function calls) leaves
            // `limit_value = None`.
            if matches!(kind, crate::ir::plan::LimitKind::Rows) && facts.limit_value.is_none() {
                if let Some(crate::ir::scalar::ScalarExpr::Lit {
                    value: crate::ir::scalar::Lit::Integer(s),
                    ..
                }) = limit
                {
                    if let Ok(v) = s.parse::<u64>() {
                        facts.limit_value = Some(v);
                    }
                }
            }
            if let Some(l) = limit {
                walk_scalar(l, tables, tables_written, cte_refs, ctx);
            }
            if let Some(o) = offset {
                walk_scalar(o, tables, tables_written, cte_refs, ctx);
            }
            walk(
                input,
                facts,
                tables,
                tables_written,
                cte_refs,
                cte_names,
                set_operations,
                join_edges,
                containing_cte,
                ctx,
            );
        }
        RelPlan::Values { rows, .. } => {
            // VALUES rows may hold scalar subqueries on some dialects
            // (rare, but keep the walk honest).
            for row in rows {
                for e in row {
                    walk_scalar(e, tables, tables_written, cte_refs, ctx);
                }
            }
        }
        RelPlan::Insert {
            target,
            target_columns: _,
            source,
            on_conflict,
            overwrite: _,
            replace_into: _,
            overriding: _,
            returning,
            output,
            target_hints: _,
            node_id: _,
            span: _,
            hints: _,
        } => {
            // DML target → tables_written.
            tables_written.insert((
                target.server.clone(),
                target.db.clone(),
                target.schema.clone(),
                target.name.clone(),
            ));
            // INSERT is a DML root whose source is a sub-source
            // scope. Outer-only flat fields (`immediate_join_count`,
            // `has_group_by`, `has_aggregates`, `has_distinct`, ...)
            // do not cross the boundary. `has_where` is surfaced from
            // the source because INSERT has no top-level predicate of
            // its own, so any filter on the data flowing in lives
            // only in the source query.
            use crate::ir::plan::InsertSource;
            match source {
                InsertSource::Values(p) | InsertSource::Query(p) => {
                    let mut scratch = DerivedFacts::empty();
                    let mut scratch_cte_names: HashSet<IdentKey> = HashSet::new();
                    let mut scratch_set_operations: Vec<SetOperationFact> = Vec::new();
                    walk(
                        p,
                        &mut scratch,
                        tables,
                        tables_written,
                        cte_refs,
                        &mut scratch_cte_names,
                        &mut scratch_set_operations,
                        join_edges,
                        containing_cte,
                        ctx,
                    );
                    if scratch.has_where {
                        facts.has_where = true;
                    }
                }
                InsertSource::DefaultValues => {}
            }
            // ON CONFLICT clause: scalar-bearing fields (target
            // expression list, action assignments / where, outer
            // where) are walked so that subqueries inside upserts
            // contribute to `tables_read`.
            if let Some(oc) = on_conflict {
                walk_on_conflict(oc, tables, tables_written, cte_refs, ctx);
            }
            // RETURNING / OUTPUT items may contain scalar subqueries.
            if let Some(r) = returning {
                walk_returning_items(&r.items, tables, tables_written, cte_refs, ctx);
            }
            if let Some(o) = output {
                walk_returning_items(&o.items, tables, tables_written, cte_refs, ctx);
            }
            // INSERT target hints (`INSERT INTO t WITH (TABLOCK)` etc.)
            // carry no scalar children — their typed
            // [`ScanTableHintKind`] variants are keyword-only or carry
            // span-only payloads. Nothing to walk for `tables_read`
            // contribution.
        }
        RelPlan::Update {
            target,
            assignments,
            from,
            predicate,
            top,
            returning,
            output,
            node_id: _,
            span: _,
            hints: _,
        } => {
            tables_written.insert((
                target.server.clone(),
                target.db.clone(),
                target.schema.clone(),
                target.name.clone(),
            ));
            // `has_where` reflects the UPDATE's own WHERE clause.
            // The other scalar flags are NOT set from the FROM
            // clause or assignments.
            if predicate.is_some() {
                facts.has_where = true;
            }
            // Walk SET assignment RHS and the predicate as scalar
            // exprs — these contribute to `tables` / `cte_refs`
            // through nested subqueries (already scratch-scoped
            // inside `walk_scalar`).
            for (_, rhs) in assignments {
                walk_scalar(rhs, tables, tables_written, cte_refs, ctx);
            }
            if let Some(p) = predicate {
                walk_scalar(p, tables, tables_written, cte_refs, ctx);
            }
            // FROM clause is a sub-source scope: it contributes to
            // per-scope-set fields (`tables_read`, `join_edges`,
            // ...) via the shared accumulators, but outer-only flat
            // fields (`immediate_join_count`, `has_group_by`, ...)
            // do not cross the boundary.
            if let Some(f) = from {
                let mut scratch = DerivedFacts::empty();
                let mut scratch_cte_names: HashSet<IdentKey> = HashSet::new();
                let mut scratch_set_operations: Vec<SetOperationFact> = Vec::new();
                walk(
                    f,
                    &mut scratch,
                    tables,
                    tables_written,
                    cte_refs,
                    &mut scratch_cte_names,
                    &mut scratch_set_operations,
                    join_edges,
                    containing_cte,
                    ctx,
                );
            }
            if let Some(t) = top {
                walk_scalar(&t.count, tables, tables_written, cte_refs, ctx);
            }
            if let Some(r) = returning {
                walk_returning_items(&r.items, tables, tables_written, cte_refs, ctx);
            }
            if let Some(o) = output {
                walk_returning_items(&o.items, tables, tables_written, cte_refs, ctx);
            }
        }
        RelPlan::Delete {
            target,
            using,
            predicate,
            top,
            returning,
            output,
            node_id: _,
            span: _,
            hints: _,
        } => {
            tables_written.insert((
                target.server.clone(),
                target.db.clone(),
                target.schema.clone(),
                target.name.clone(),
            ));
            // `has_where` reflects the DELETE's own WHERE clause.
            // Same scoping rules as UPDATE.
            if predicate.is_some() {
                facts.has_where = true;
            }
            if let Some(p) = predicate {
                walk_scalar(p, tables, tables_written, cte_refs, ctx);
            }
            // USING clause is a sub-source scope (same shape as
            // UPDATE.from); per-scope-set fields propagate via the
            // shared accumulators, outer-only flat fields do not.
            if let Some(u) = using {
                let mut scratch = DerivedFacts::empty();
                let mut scratch_cte_names: HashSet<IdentKey> = HashSet::new();
                let mut scratch_set_operations: Vec<SetOperationFact> = Vec::new();
                walk(
                    u,
                    &mut scratch,
                    tables,
                    tables_written,
                    cte_refs,
                    &mut scratch_cte_names,
                    &mut scratch_set_operations,
                    join_edges,
                    containing_cte,
                    ctx,
                );
            }
            if let Some(t) = top {
                walk_scalar(&t.count, tables, tables_written, cte_refs, ctx);
            }
            if let Some(r) = returning {
                walk_returning_items(&r.items, tables, tables_written, cte_refs, ctx);
            }
            if let Some(o) = output {
                walk_returning_items(&o.items, tables, tables_written, cte_refs, ctx);
            }
        }
        RelPlan::Merge {
            target,
            source,
            on,
            branches,
            with_schema_evolution: _,
            output,
            node_id: _,
            span: _,
            hints: _,
        } => {
            tables_written.insert((
                target.server.clone(),
                target.db.clone(),
                target.schema.clone(),
                target.name.clone(),
            ));
            // `has_where` is set unconditionally: a MERGE always has
            // an ON condition, so the statement is treated as
            // bounded by definition.
            facts.has_where = true;
            walk_scalar(on, tables, tables_written, cte_refs, ctx);
            for branch in branches {
                if let Some(pred) = &branch.predicate {
                    walk_scalar(pred, tables, tables_written, cte_refs, ctx);
                }
                use crate::ir::plan::MergeAction;
                match &branch.action {
                    MergeAction::Insert { values, .. } => {
                        for v in values {
                            walk_scalar(v, tables, tables_written, cte_refs, ctx);
                        }
                    }
                    MergeAction::Update { assignments } => {
                        for (_, rhs) in assignments {
                            walk_scalar(rhs, tables, tables_written, cte_refs, ctx);
                        }
                    }
                    MergeAction::InsertStar
                    | MergeAction::InsertAllByName
                    | MergeAction::UpdateSetStar
                    | MergeAction::UpdateAllByName
                    | MergeAction::Delete
                    | MergeAction::DoNothing => {}
                }
            }
            // USING source is a sub-source scope (subquery-shaped): its
            // joins / GROUP BY / aggregates / other outer-only flat
            // fields do not propagate. Per-scope-set fields
            // contribute via the shared accumulators.
            let mut scratch = DerivedFacts::empty();
            let mut scratch_cte_names: HashSet<IdentKey> = HashSet::new();
            let mut scratch_set_operations: Vec<SetOperationFact> = Vec::new();
            walk(
                source,
                &mut scratch,
                tables,
                tables_written,
                cte_refs,
                &mut scratch_cte_names,
                &mut scratch_set_operations,
                join_edges,
                containing_cte,
                ctx,
            );
            if let Some(o) = output {
                walk_returning_items(&o.items, tables, tables_written, cte_refs, ctx);
            }
        }
        RelPlan::MultiInsert {
            unconditional_clauses,
            when_clauses,
            else_clauses,
            source,
            ..
        } => {
            // Every clause in a MultiInsert names a target table.
            // The walk populates `tables_written` for every
            // reachable target so that nested MultiInsert (e.g.
            // inside a CTE in some dialect) projects correctly.
            for clause in unconditional_clauses {
                tables_written.insert((
                    clause.target.server.clone(),
                    clause.target.db.clone(),
                    clause.target.schema.clone(),
                    clause.target.name.clone(),
                ));
                for v in &clause.values {
                    walk_scalar(v, tables, tables_written, cte_refs, ctx);
                }
            }
            for when in when_clauses {
                walk_scalar(&when.condition, tables, tables_written, cte_refs, ctx);
                for clause in &when.targets {
                    tables_written.insert((
                        clause.target.server.clone(),
                        clause.target.db.clone(),
                        clause.target.schema.clone(),
                        clause.target.name.clone(),
                    ));
                    for v in &clause.values {
                        walk_scalar(v, tables, tables_written, cte_refs, ctx);
                    }
                }
            }
            for clause in else_clauses {
                tables_written.insert((
                    clause.target.server.clone(),
                    clause.target.db.clone(),
                    clause.target.schema.clone(),
                    clause.target.name.clone(),
                ));
                for v in &clause.values {
                    walk_scalar(v, tables, tables_written, cte_refs, ctx);
                }
            }
            walk(
                source,
                facts,
                tables,
                tables_written,
                cte_refs,
                cte_names,
                set_operations,
                join_edges,
                containing_cte,
                ctx,
            );
        }
        RelPlan::Explain { body, .. } => {
            walk(
                body,
                facts,
                tables,
                tables_written,
                cte_refs,
                cte_names,
                set_operations,
                join_edges,
                containing_cte,
                ctx,
            );
        }
        RelPlan::CreateAsQuery { body, .. } => {
            // CREATE VIEW / CTAS / CREATE DYNAMIC TABLE: the wrapped
            // `body` is the relational source whose tables / CTE
            // references feed the new object. The walk goes straight
            // through without treating the outer DDL node as a data
            // source.
            //
            // This arm stays uniformly silent on `tables_written`:
            // no target is pushed for any CreateAsQuery kind.
            if let Some(body) = body.as_deref() {
                walk(
                    body,
                    facts,
                    tables,
                    tables_written,
                    cte_refs,
                    cte_names,
                    set_operations,
                    join_edges,
                    containing_cte,
                    ctx,
                );
            }
        }
        RelPlan::CreateTableForm { .. } => {
            // Non-query-bearing DDL: no relational facts to derive.
        }
        RelPlan::WithScope { ctes, body, .. } => {
            // `WithScope` introduces CTE bindings visible to `body`
            // and to each other:
            //
            //   (a) Scalar flags (`has_distinct`, `has_aggregates`,
            //   `has_where`, `has_group_by`, `immediate_join_count`)
            //   describe the body's outer scope only. CTE bodies
            //   are scope boundaries — their flags do NOT propagate
            //   into the enclosing scope.
            //
            //   (b) A CTE's `base_tables` are appended to `tables_read`
            //   only when a table-ref actually resolves to that CTE. So
            //   `tables_read` propagates only from CTEs reachable
            //   (transitively) from `body`. The same reachability
            //   gate applies to `tables_written`: a DML inside an
            //   unreferenced CTE binding has no observable effect
            //   on the outer query and therefore must not enter
            //   the outer write-set.
            walk(
                body,
                facts,
                tables,
                tables_written,
                cte_refs,
                cte_names,
                set_operations,
                join_edges,
                containing_cte,
                ctx,
            );

            // Each binding name visible at this scope contributes
            // to the outer `cte_names` set.
            for binding in ctes {
                cte_names.insert(binding.name.clone());
            }

            // Per-CTE: collect its own tables and CTE references in
            // scratch buffers. Scalar flags are walked into a
            // discarded scratch instance — they belong to the CTE's
            // own scope, not the enclosing one. Store per-CTE
            // results for the reachability closure below.
            type TableTriple = TableKey;
            type CteInfo = (
                IdentKey,
                BTreeSet<TableTriple>,
                BTreeSet<TableTriple>,
                HashSet<IdentKey>,
            );
            let mut cte_infos: Vec<CteInfo> = Vec::with_capacity(ctes.len());
            // Index name → position in `cte_infos` so the reachability
            // fixpoint below can look up `own_refs` in O(1) instead of
            // scanning `cte_infos` linearly per worklist pop. First-match
            // semantics via `entry().or_insert(...)` if the same
            // CTE name appears twice (invalid SQL; first match wins).
            let mut cte_index: HashMap<IdentKey, usize> = HashMap::with_capacity(ctes.len());
            for binding in ctes {
                let mut cte_tables: BTreeSet<TableTriple> = BTreeSet::new();
                let mut cte_writes: BTreeSet<TableTriple> = BTreeSet::new();
                let mut cte_own_refs: HashSet<IdentKey> = HashSet::new();
                let mut scratch = DerivedFacts::empty();
                // CTE bodies are scope boundaries for `cte_names`:
                // a nested `WITH` defined inside this binding's
                // body is invisible to the outer statement, so
                // each binding gets its own discarded
                // `scratch_cte_names`.
                let mut scratch_cte_names: HashSet<IdentKey> = HashSet::new();
                // CTE bodies are also scope boundaries for
                // `set_operations`: a `UNION` inside a binding's
                // body is the binding's own scope, not the
                // enclosing statement's.
                let mut scratch_set_operations: Vec<SetOperationFact> = Vec::new();
                match &binding.body {
                    CteBody::NonRecursive(plan) => {
                        walk(
                            plan,
                            &mut scratch,
                            &mut cte_tables,
                            &mut cte_writes,
                            &mut cte_own_refs,
                            &mut scratch_cte_names,
                            &mut scratch_set_operations,
                            join_edges,
                            Some(binding.name.as_str()),
                            ctx,
                        );
                    }
                    CteBody::Recursive { anchor, step, .. } => {
                        walk(
                            anchor,
                            &mut scratch,
                            &mut cte_tables,
                            &mut cte_writes,
                            &mut cte_own_refs,
                            &mut scratch_cte_names,
                            &mut scratch_set_operations,
                            join_edges,
                            Some(binding.name.as_str()),
                            ctx,
                        );
                        let mut scratch_step = DerivedFacts::empty();
                        walk(
                            step,
                            &mut scratch_step,
                            &mut cte_tables,
                            &mut cte_writes,
                            &mut cte_own_refs,
                            &mut scratch_cte_names,
                            &mut scratch_set_operations,
                            join_edges,
                            Some(binding.name.as_str()),
                            ctx,
                        );
                    }
                }
                cte_index
                    .entry(binding.name.clone())
                    .or_insert(cte_infos.len());
                cte_infos.push((binding.name.clone(), cte_tables, cte_writes, cte_own_refs));
            }

            // Reachability fixpoint: a CTE's `tables_read` /
            // `tables_written` contributes iff it is referenced from
            // `body` or from another reachable CTE's body.
            // Self-references within a recursive CTE do not count as
            // making the CTE reachable — the outer scope must reach it.
            let mut reachable: HashSet<IdentKey> = HashSet::new();
            let mut worklist: Vec<IdentKey> = cte_refs.iter().cloned().collect();
            while let Some(name) = worklist.pop() {
                if !reachable.insert(name.clone()) {
                    continue;
                }
                if let Some(&i) = cte_index.get(&name) {
                    let own_refs = &cte_infos[i].3;
                    for r in own_refs {
                        if !reachable.contains(r) {
                            worklist.push(r.clone());
                        }
                    }
                }
            }
            for (name, cte_tables, cte_writes, _) in cte_infos {
                if reachable.contains(&name) {
                    for t in cte_tables {
                        tables.insert(t);
                    }
                    for t in cte_writes {
                        tables_written.insert(t);
                    }
                }
            }
        }
        RelPlan::Unnest { input, array, .. } => {
            walk_scalar(array, tables, tables_written, cte_refs, ctx);
            walk(
                input,
                facts,
                tables,
                tables_written,
                cte_refs,
                cte_names,
                set_operations,
                join_edges,
                containing_cte,
                ctx,
            );
        }
        RelPlan::Pivot {
            input,
            aggregates,
            pivot_values,
            default_on_null,
            ..
        } => {
            for a in aggregates {
                walk_aggregate_call(a, tables, tables_written, cte_refs, ctx);
            }
            match pivot_values {
                crate::ir::PivotValues::ValueList(values) => {
                    for v in values {
                        walk_scalar(v, tables, tables_written, cte_refs, ctx);
                    }
                }
                crate::ir::PivotValues::Any { order_by } => {
                    for k in order_by {
                        walk_scalar(&k.expr, tables, tables_written, cte_refs, ctx);
                    }
                }
                crate::ir::PivotValues::Subquery(plan) => {
                    walk(
                        plan,
                        facts,
                        tables,
                        tables_written,
                        cte_refs,
                        cte_names,
                        set_operations,
                        join_edges,
                        containing_cte,
                        ctx,
                    );
                }
                crate::ir::PivotValues::Opaque { .. } => {}
            }
            if let Some(d) = default_on_null {
                walk_scalar(d, tables, tables_written, cte_refs, ctx);
            }
            walk(
                input,
                facts,
                tables,
                tables_written,
                cte_refs,
                cte_names,
                set_operations,
                join_edges,
                containing_cte,
                ctx,
            );
        }
        RelPlan::Unpivot { input, .. } | RelPlan::MatchRecognize { input, .. } => {
            walk(
                input,
                facts,
                tables,
                tables_written,
                cte_refs,
                cte_names,
                set_operations,
                join_edges,
                containing_cte,
                ctx,
            );
        }
        RelPlan::ConnectBy {
            input,
            start_with,
            connect,
            ..
        } => {
            if let Some(s) = start_with {
                walk_scalar(s, tables, tables_written, cte_refs, ctx);
            }
            walk_scalar(connect, tables, tables_written, cte_refs, ctx);
            walk(
                input,
                facts,
                tables,
                tables_written,
                cte_refs,
                cte_names,
                set_operations,
                join_edges,
                containing_cte,
                ctx,
            );
        }
        RelPlan::TableSample { input, sample, .. } => {
            if let Some(s) = &sample.seed {
                walk_scalar(s, tables, tables_written, cte_refs, ctx);
            }
            if let Some(r) = &sample.repeatable {
                walk_scalar(r, tables, tables_written, cte_refs, ctx);
            }
            walk(
                input,
                facts,
                tables,
                tables_written,
                cte_refs,
                cte_names,
                set_operations,
                join_edges,
                containing_cte,
                ctx,
            );
        }
        RelPlan::ParseRecovery { .. } => {
            // ParseRecovery suppresses fact derivation inside its scope,
            // same as Opaque. The fragment's structure was not parseable.
        }
        RelPlan::Opaque { .. } => {
            // Opaque subtrees intentionally suppress fact derivation
            // inside their scope. Nested Opaque is rare (all current
            // rejections bubble to the top-level plan).
        }
        RelPlan::InvalidInput { .. } => {
            // Opaque subtrees intentionally suppress fact derivation
            // inside their scope. Nested Opaque is rare (all current
            // rejections bubble to the top-level plan).
        }
        RelPlan::DerivedTable { input, .. } => {
            // Derived tables are scope boundaries: the outer plan
            // sees them as a table reference, not as an inlined
            // source of predicates / joins / aggregates. Mirror the
            // SetOp / scalar-subquery pattern — use scratch facts
            // for the inner walk so scalar flags (`has_where`,
            // `has_group_by`, `immediate_join_count`, …) stay inside
            // the boundary, while `tables_read` / `tables_written`
            // and CTE references share the outer accumulators so
            // base-table reads, DML writes, and CTE reachability
            // still propagate. `cte_names` is also scratch here:
            // a `WITH` defined inside a derived table belongs to
            // the subquery's scope, not the outer statement's.
            let mut scratch = DerivedFacts::empty();
            let mut scratch_cte_names: HashSet<IdentKey> = HashSet::new();
            let mut scratch_set_operations: Vec<SetOperationFact> = Vec::new();
            walk(
                input,
                &mut scratch,
                tables,
                tables_written,
                cte_refs,
                &mut scratch_cte_names,
                &mut scratch_set_operations,
                join_edges,
                containing_cte,
                ctx,
            );
        }
        RelPlan::TableFunction { call, .. } => {
            // A TVF is not a base-table read — the function name
            // itself must never enter `tables_read`. But its
            // arguments may contain subqueries whose inner
            // `tables_read` / CTE references do propagate. Walking
            // the call's scalar is exactly that: `walk_scalar`
            // pierces `ScalarSubquery` / `Exists` / `QuantifiedCmp`
            // and recurses through the wrapped `RelPlan` with the
            // outer accumulators.
            walk_scalar(call, tables, tables_written, cte_refs, ctx);
        }
    }
    // The match above is exhaustive by design. A compile error here
    // when a new variant is added is the forcing function that
    // protects against silent drift — do not add a `_ =>` arm.
    let _: fn(&JoinKind) = |_| {};
}

/// Exhaustive walk over a [`ScalarExpr`], collecting any tables /
/// CTE references reachable through embedded subqueries.
///
/// Scalar-position subqueries (e.g. `SELECT (SELECT x FROM t)`,
/// `WHERE x IN (SELECT …)`, `EXISTS (…)`, `x = ANY (SELECT …)`)
/// contribute their `tables_read` to the outer statement's. Those
/// subqueries lower to [`ScalarExpr::ScalarSubquery`] /
/// [`ScalarExpr::Exists`] / [`ScalarExpr::QuantifiedCmp`] with a
/// [`QuantifiedRhs::Subquery`], so the [`RelPlan`] walk alone does not
/// reach them — it only recurses through relational children. This
/// helper closes that gap.
///
/// Scoping matches the [`RelPlan::SetOp`] precedent: a subquery is
/// its own query scope, so its scalar flags (`has_where`,
/// `has_group_by`, `immediate_join_count`, `has_distinct`,
/// `has_aggregates`) must NOT propagate into the outer [`DerivedFacts`].
/// The walk into a subquery therefore uses a discarded scratch
/// instance for `facts`, while sharing the outer `tables` /
/// `cte_refs` accumulators.
///
/// Every [`ScalarExpr`] variant is listed explicitly — a new variant
/// must decide what it contributes, mirroring the closed-enum
/// discipline used by [`walk`].
fn walk_scalar(
    expr: &ScalarExpr,
    tables: &mut BTreeSet<TableKey>,
    tables_written: &mut BTreeSet<TableKey>,
    cte_refs: &mut HashSet<IdentKey>,
    ctx: &WalkCtx<'_>,
) {
    match expr {
        ScalarExpr::Column { .. }
        | ScalarExpr::PatternVarRef { .. }
        | ScalarExpr::OuterRef { .. }
        | ScalarExpr::Lit { .. }
        | ScalarExpr::Opaque { .. } => {
            // Leaf nodes — no nested expressions or subqueries.
        }
        ScalarExpr::Like {
            expr,
            pattern,
            escape,
            ..
        } => {
            walk_scalar(expr, tables, tables_written, cte_refs, ctx);
            walk_scalar(pattern, tables, tables_written, cte_refs, ctx);
            if let Some(e) = escape {
                walk_scalar(e, tables, tables_written, cte_refs, ctx);
            }
        }
        ScalarExpr::BinOp { left, right, .. } => {
            walk_scalar(left, tables, tables_written, cte_refs, ctx);
            walk_scalar(right, tables, tables_written, cte_refs, ctx);
        }
        ScalarExpr::LogicalChain { operands, .. } => {
            for operand in operands {
                walk_scalar(operand, tables, tables_written, cte_refs, ctx);
            }
        }
        ScalarExpr::UnaryOp { arg, .. } => {
            walk_scalar(arg, tables, tables_written, cte_refs, ctx);
        }
        ScalarExpr::FuncCall {
            args, named_args, ..
        } => {
            for a in args {
                walk_scalar(a, tables, tables_written, cte_refs, ctx);
            }
            for (_, a) in named_args {
                walk_scalar(a, tables, tables_written, cte_refs, ctx);
            }
        }
        ScalarExpr::Case {
            operand,
            branches,
            else_,
            ..
        } => {
            if let Some(op) = operand {
                walk_scalar(op, tables, tables_written, cte_refs, ctx);
            }
            for (cond, val) in branches {
                walk_scalar(cond, tables, tables_written, cte_refs, ctx);
                walk_scalar(val, tables, tables_written, cte_refs, ctx);
            }
            if let Some(e) = else_ {
                walk_scalar(e, tables, tables_written, cte_refs, ctx);
            }
        }
        ScalarExpr::Cast { expr, .. } => {
            walk_scalar(expr, tables, tables_written, cte_refs, ctx);
        }
        ScalarExpr::InList { expr, list, .. } => {
            walk_scalar(expr, tables, tables_written, cte_refs, ctx);
            for item in list {
                walk_scalar(item, tables, tables_written, cte_refs, ctx);
            }
        }
        ScalarExpr::Between {
            expr, low, high, ..
        } => {
            walk_scalar(expr, tables, tables_written, cte_refs, ctx);
            walk_scalar(low, tables, tables_written, cte_refs, ctx);
            walk_scalar(high, tables, tables_written, cte_refs, ctx);
        }
        ScalarExpr::Exists { subquery, .. } | ScalarExpr::ScalarSubquery { subquery, .. } => {
            let mut scratch = DerivedFacts::empty();
            let mut scratch_cte_names: HashSet<IdentKey> = HashSet::new();
            let mut scratch_set_operations: Vec<SetOperationFact> = Vec::new();
            let mut scratch_join_edges: Vec<JoinEdge> = Vec::new();
            walk(
                subquery,
                &mut scratch,
                tables,
                tables_written,
                cte_refs,
                &mut scratch_cte_names,
                &mut scratch_set_operations,
                &mut scratch_join_edges,
                None,
                ctx,
            );
        }
        ScalarExpr::QuantifiedCmp { left, right, .. } => {
            walk_scalar(left, tables, tables_written, cte_refs, ctx);
            match right {
                QuantifiedRhs::List(list) => {
                    for e in list {
                        walk_scalar(e, tables, tables_written, cte_refs, ctx);
                    }
                }
                QuantifiedRhs::Subquery(plan, _) => {
                    let mut scratch = DerivedFacts::empty();
                    let mut scratch_cte_names: HashSet<IdentKey> = HashSet::new();
                    let mut scratch_set_operations: Vec<SetOperationFact> = Vec::new();
                    let mut scratch_join_edges: Vec<JoinEdge> = Vec::new();
                    walk(
                        plan,
                        &mut scratch,
                        tables,
                        tables_written,
                        cte_refs,
                        &mut scratch_cte_names,
                        &mut scratch_set_operations,
                        &mut scratch_join_edges,
                        None,
                        ctx,
                    );
                }
            }
        }
        ScalarExpr::WindowFn { call, .. } => {
            for a in &call.args {
                walk_scalar(a, tables, tables_written, cte_refs, ctx);
            }
            for p in &call.partition_by {
                walk_scalar(p, tables, tables_written, cte_refs, ctx);
            }
            for k in &call.order_by {
                walk_scalar(&k.expr, tables, tables_written, cte_refs, ctx);
            }
            if let Some(frame) = &call.frame {
                walk_frame_bound(&frame.start, tables, tables_written, cte_refs, ctx);
                walk_frame_bound(&frame.end, tables, tables_written, cte_refs, ctx);
            }
        }
        ScalarExpr::FieldAccess { base, path, .. } => {
            walk_scalar(base, tables, tables_written, cte_refs, ctx);
            for step in path {
                match step {
                    FieldStep::Field(_) | FieldStep::Index(_) => {}
                    FieldStep::IndexExpr(e) => {
                        walk_scalar(e, tables, tables_written, cte_refs, ctx);
                    }
                }
            }
        }
        ScalarExpr::Lambda { body, .. } => {
            walk_scalar(body, tables, tables_written, cte_refs, ctx);
        }
    }
}

/// Walk a window-frame bound for embedded scalar expressions.
fn walk_frame_bound(
    bound: &crate::ir::plan::FrameBound,
    tables: &mut BTreeSet<TableKey>,
    tables_written: &mut BTreeSet<TableKey>,
    cte_refs: &mut HashSet<IdentKey>,
    ctx: &WalkCtx<'_>,
) {
    use crate::ir::plan::FrameBound;
    match bound {
        FrameBound::UnboundedPreceding
        | FrameBound::CurrentRow
        | FrameBound::UnboundedFollowing => {}
        FrameBound::Preceding(e) | FrameBound::Following(e) => {
            walk_scalar(e, tables, tables_written, cte_refs, ctx);
        }
    }
}

/// Walk every [`ScalarExpr`] attached to an [`AggregateCall`].
fn walk_aggregate_call(
    call: &crate::ir::plan::AggregateCall,
    tables: &mut BTreeSet<TableKey>,
    tables_written: &mut BTreeSet<TableKey>,
    cte_refs: &mut HashSet<IdentKey>,
    ctx: &WalkCtx<'_>,
) {
    for a in &call.args {
        walk_scalar(a, tables, tables_written, cte_refs, ctx);
    }
    for (_name, a) in &call.named_args {
        walk_scalar(a, tables, tables_written, cte_refs, ctx);
    }
    if let Some(f) = &call.filter {
        walk_scalar(f, tables, tables_written, cte_refs, ctx);
    }
    for k in &call.arg_order {
        walk_scalar(&k.expr, tables, tables_written, cte_refs, ctx);
    }
    for k in &call.within_group_order {
        walk_scalar(&k.expr, tables, tables_written, cte_refs, ctx);
    }
}

/// Walk every [`ScalarExpr`] attached to a `RETURNING` / `OUTPUT`
/// item list. `Star` items have no scalar payload; `Expr` items
/// carry one. The OUTPUT-INTO target itself is intentionally not
/// pushed into `tables_written` here: OUTPUT-INTO destinations are
/// not tracked as additional writes.
fn walk_returning_items(
    items: &[crate::ir::plan::ReturningItem],
    tables: &mut BTreeSet<TableKey>,
    tables_written: &mut BTreeSet<TableKey>,
    cte_refs: &mut HashSet<IdentKey>,
    ctx: &WalkCtx<'_>,
) {
    use crate::ir::plan::ReturningItem;
    for item in items {
        match item {
            ReturningItem::Star => {}
            ReturningItem::Expr { expr, .. } => {
                walk_scalar(expr, tables, tables_written, cte_refs, ctx);
            }
        }
    }
}

/// Walk every [`ScalarExpr`] embedded in an [`OnConflict`] clause.
/// Covers expression-form conflict targets, the optional outer
/// `WHERE` predicate, and both action variants (`DO UPDATE` and
/// MySQL-flavored `ON DUPLICATE KEY UPDATE`). `DoNothing` carries no
/// scalars. Nested subqueries inside any of these expressions
/// contribute to `tables_read` via `walk_scalar`'s scratch-scoped
/// recursion into `Exists` / `ScalarSubquery`.
fn walk_on_conflict(
    oc: &crate::ir::plan::OnConflict,
    tables: &mut BTreeSet<TableKey>,
    tables_written: &mut BTreeSet<TableKey>,
    cte_refs: &mut HashSet<IdentKey>,
    ctx: &WalkCtx<'_>,
) {
    use crate::ir::plan::{ConflictAction, ConflictTarget};
    match &oc.target {
        ConflictTarget::Unspecified
        | ConflictTarget::Columns(_)
        | ConflictTarget::Constraint(_) => {}
        ConflictTarget::Expressions(exprs) => {
            for e in exprs {
                walk_scalar(e, tables, tables_written, cte_refs, ctx);
            }
        }
    }
    if let Some(w) = &oc.where_clause {
        walk_scalar(w, tables, tables_written, cte_refs, ctx);
    }
    match &oc.action {
        ConflictAction::DoNothing => {}
        ConflictAction::DoUpdate {
            assignments,
            where_clause,
        } => {
            for (_, rhs) in assignments {
                walk_scalar(rhs, tables, tables_written, cte_refs, ctx);
            }
            if let Some(w) = where_clause {
                walk_scalar(w, tables, tables_written, cte_refs, ctx);
            }
        }
        ConflictAction::MySqlDuplicateKeyUpdate { assignments } => {
            for (_, rhs) in assignments {
                walk_scalar(rhs, tables, tables_written, cte_refs, ctx);
            }
        }
    }
}

// ────────────────────────────────────────────────────────────────────────
// ScanModifier projection
// ────────────────────────────────────────────────────────────────────────
//
// The `ScanModifier` slots (`time_travel`, `changes`, `hints`,
// `stage_options`, `origin`) are **consumed** by the IR-side
// rather than left as carry-only fields. This is the canonical typed
// projection: every [`RelPlan::Scan`] reachable through the standard
// scope-preserving walk contributes one [`ScanModifierFact`].
//
// Closed-enum exhaustiveness is enforced two ways:
//
//  1. [`project_scan_modifier_fact`] destructures every field of
//     [`ScanModifier`] by name (no `..`); a new sub-field on
//     `ScanModifier` fails to compile here until the projection
//     decides what it contributes.
//  2. [`project_time_travel`] / [`project_origin`] match the source
//     enums exhaustively; a new [`TimeTravel`] / [`OriginHint`]
//     variant fails to compile here until a corresponding tag lands.
//
// `ScanModifierFact` is intentionally **not** a field of
// [`DerivedFacts`]. This projection lets downstream consumers (taint
// stage seeding, semantic diff, hint signal re-emission) be wired
// against a typed contract rather than walking the plan ad-hoc.

/// Per-`Scan` projection of [`ScanModifier`].
///
/// One entry per [`RelPlan::Scan`] reachable through the standard
/// scope-preserving walk (descends into `WithScope` bindings and
/// body, `Explain` / `CreateAsQuery` body, `DerivedTable` input,
/// `SetOp` branches, `Join` left/right, every single-input wrapper,
/// and DML sub-sources). Entries appear in plan-walk order; no
/// dedup (two scans of the same table with different modifiers
/// remain distinct entries).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanModifierFact {
    pub table: TableRef,
    pub alias: Option<IdentKey>,
    pub time_travel: Option<TimeTravelTag>,
    pub changes: Option<ChangesTag>,
    /// Number of `/*+ ... */` (or dialect-equivalent) hints attached
    /// to this scan. Hint *text* is intentionally not projected, and
    /// `ScanModifier.table_hints` is not projected here either. The
    /// count alone is enough for "did the hint set change" diff
    /// observability.
    pub hint_count: usize,
    /// `FROM @stage (FILE_FORMAT => …, PATTERN => …)` presence.
    /// Stored as a boolean because [`ScanModifier::stage_options`]
    /// itself is currently an opaque source span; the boolean is the
    /// honest projection of "do we know there are stage options".
    pub has_stage_options: bool,
    pub origin: OriginTag,
    pub span: Span,
}

/// Closed-enum projection of [`crate::ir::plan::TimeTravel`].
///
/// Mirrors the source enum 1-to-1. Adding a `TimeTravel` variant
/// requires a corresponding tag here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeTravelTag {
    AtTimestamp,
    AtOffset,
    AtStatement,
    AtStream,
    BeforeTimestamp,
    BeforeOffset,
    BeforeStatement,
    BeforeStream,
    ForSystemTimeAsOf,
    ForSystemTimeBare,
    DatabricksTimestampAsOf,
    DatabricksVersionAsOf,
    DatabricksAtSign,
}

/// Closed-struct projection of [`crate::ir::plan::ChangesClause`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangesTag {
    /// Closed-enum mirror of [`ChangesInformation`].
    pub information: ChangesInformation,
    pub at: Option<TimeTravelTag>,
    pub end: Option<TimeTravelTag>,
}

/// Closed-enum projection of [`crate::ir::plan::OriginHint`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OriginTag {
    Direct,
    DbtRef,
    DbtSource,
}

fn project_time_travel(tt: &TimeTravel) -> TimeTravelTag {
    match tt {
        TimeTravel::AtTimestamp(_) => TimeTravelTag::AtTimestamp,
        TimeTravel::AtOffset(_) => TimeTravelTag::AtOffset,
        TimeTravel::AtStatement(_) => TimeTravelTag::AtStatement,
        TimeTravel::AtStream(_) => TimeTravelTag::AtStream,
        TimeTravel::BeforeTimestamp(_) => TimeTravelTag::BeforeTimestamp,
        TimeTravel::BeforeOffset(_) => TimeTravelTag::BeforeOffset,
        TimeTravel::BeforeStatement(_) => TimeTravelTag::BeforeStatement,
        TimeTravel::BeforeStream(_) => TimeTravelTag::BeforeStream,
        TimeTravel::ForSystemTimeAsOf(_) => TimeTravelTag::ForSystemTimeAsOf,
        TimeTravel::ForSystemTimeBare { .. } => TimeTravelTag::ForSystemTimeBare,
        TimeTravel::DatabricksTimestampAsOf(_) => TimeTravelTag::DatabricksTimestampAsOf,
        TimeTravel::DatabricksVersionAsOf(_) => TimeTravelTag::DatabricksVersionAsOf,
        TimeTravel::DatabricksAtSign(_) => TimeTravelTag::DatabricksAtSign,
    }
}

fn project_changes(c: &ChangesClause) -> ChangesTag {
    let ChangesClause {
        information,
        at,
        end,
    } = c;
    ChangesTag {
        information: *information,
        at: at.as_ref().map(project_time_travel),
        end: end.as_ref().map(project_time_travel),
    }
}

fn project_origin(o: &OriginHint) -> OriginTag {
    match o {
        OriginHint::Direct => OriginTag::Direct,
        OriginHint::DbtRef { .. } => OriginTag::DbtRef,
        OriginHint::DbtSource { .. } => OriginTag::DbtSource,
    }
}

fn project_scan_modifier_fact(
    table: &TableRef,
    alias: &Option<IdentKey>,
    modifier: &ScanModifier,
    span: Span,
) -> ScanModifierFact {
    // Exhaustive destructure — adding a `ScanModifier` field fails
    // to compile here until the projection decides its contribution.
    let ScanModifier {
        changes,
        time_travel,
        hints,
        stage_options,
        origin,
        // Lowered to IR but not projected into ScanModifierFact.
        sample: _,
        with_offset: _,
        only: _,
        table_hints: _,
        tvf_schema: _,
    } = modifier;
    ScanModifierFact {
        table: table.clone(),
        alias: alias.clone(),
        time_travel: time_travel.as_ref().map(project_time_travel),
        changes: changes.as_ref().map(project_changes),
        hint_count: hints.len(),
        has_stage_options: stage_options.is_some(),
        origin: project_origin(origin),
        span,
    }
}

/// Walk a [`RelPlan`] tree and collect one [`ScanModifierFact`] per
/// reachable [`RelPlan::Scan`].
///
/// The walk is exhaustive on every `RelPlan` variant — variants
/// that introduce no `Scan` (Values / CteRef / ModelRef /
/// TableFunction / Opaque) contribute nothing; every wrapper and
/// composite recurses through its sub-plan(s).
pub fn derive_scan_modifier_facts(plan: &RelPlan) -> Vec<ScanModifierFact> {
    let mut out = Vec::new();
    walk_for_scan_modifiers(plan, &mut out);
    out
}

fn walk_for_scan_modifiers(plan: &RelPlan, out: &mut Vec<ScanModifierFact>) {
    match plan {
        RelPlan::Scan {
            table,
            columns: _,
            modifier,
            alias,
            node_id: _,
            span,
            hints: _,
        } => {
            out.push(project_scan_modifier_fact(table, alias, modifier, *span));
        }
        RelPlan::Values { .. }
        | RelPlan::CteRef { .. }
        | RelPlan::ModelRef { .. }
        | RelPlan::TableFunction { .. }
        | RelPlan::CreateTableForm { .. }
        | RelPlan::ParseRecovery { .. }
        | RelPlan::Opaque { .. } => {}
        RelPlan::InvalidInput { .. } => {}
        RelPlan::Project { input, .. }
        | RelPlan::Filter { input, .. }
        | RelPlan::Aggregate { input, .. }
        | RelPlan::Window { input, .. }
        | RelPlan::Sort { input, .. }
        | RelPlan::Limit { input, .. }
        | RelPlan::TableSample { input, .. }
        | RelPlan::Pivot { input, .. }
        | RelPlan::Unpivot { input, .. }
        | RelPlan::MatchRecognize { input, .. }
        | RelPlan::ConnectBy { input, .. }
        | RelPlan::Unnest { input, .. }
        | RelPlan::DerivedTable { input, .. } => {
            walk_for_scan_modifiers(input, out);
        }
        RelPlan::Join { left, right, .. } => {
            walk_for_scan_modifiers(left, out);
            walk_for_scan_modifiers(right, out);
        }
        RelPlan::SetOp { inputs, .. } => {
            for inp in inputs {
                walk_for_scan_modifiers(inp, out);
            }
        }
        RelPlan::WithScope { ctes, body, .. } => {
            for cte in ctes {
                match &cte.body {
                    CteBody::NonRecursive(b) => walk_for_scan_modifiers(b, out),
                    CteBody::Recursive { anchor, step, .. } => {
                        walk_for_scan_modifiers(anchor, out);
                        walk_for_scan_modifiers(step, out);
                    }
                }
            }
            walk_for_scan_modifiers(body, out);
        }
        RelPlan::Explain { body, .. } => {
            walk_for_scan_modifiers(body, out);
        }
        RelPlan::CreateAsQuery { body, .. } => {
            if let Some(body) = body.as_deref() {
                walk_for_scan_modifiers(body, out);
            }
        }
        RelPlan::Insert { source, .. } => match source {
            InsertSource::Values(p) | InsertSource::Query(p) => {
                walk_for_scan_modifiers(p, out);
            }
            InsertSource::DefaultValues => {}
        },
        RelPlan::Update { from, .. } => {
            if let Some(f) = from {
                walk_for_scan_modifiers(f, out);
            }
        }
        RelPlan::Delete { using, .. } => {
            if let Some(u) = using {
                walk_for_scan_modifiers(u, out);
            }
        }
        RelPlan::Merge { source, .. } | RelPlan::MultiInsert { source, .. } => {
            walk_for_scan_modifiers(source, out);
        }
    }
}

/// Identifier of a [`RelPlan`] source (for `nullable_tables` / join
/// analysis): `alias` when set, otherwise the source's bare name.
/// Returns `None` for sources without a stable name (aliasless
/// `Values` / `DerivedTable` / `TableFunction`): entries that
/// cannot be keyed are skipped.
///
/// Closed-enum exhaustive over the source variants; non-source
/// variants return `None`.
fn relplan_source_identifier(plan: &RelPlan) -> Option<String> {
    match plan {
        RelPlan::Scan { table, alias, .. } => Some(match alias {
            Some(a) => a.as_str().to_string(),
            None => normalize_identifier(&table.name),
        }),
        RelPlan::CteRef { name, alias, .. } => Some(match alias {
            Some(a) => a.as_str().to_string(),
            None => name.as_str().to_string(),
        }),
        RelPlan::ModelRef { model, alias, .. } => Some(match alias {
            Some(a) => a.as_str().to_string(),
            None => normalize_identifier(&model.name),
        }),
        RelPlan::DerivedTable { alias, .. }
        | RelPlan::TableFunction { alias, .. }
        | RelPlan::Values { alias, .. } => alias.as_ref().map(|a| a.as_str().to_string()),
        // Wrapping operators surface their input's identifier — a
        // `LEFT JOIN (Project)` over `Scan(t)` should still surface
        // `t` as the right side's identifier.
        RelPlan::Filter { input, .. }
        | RelPlan::Project { input, .. }
        | RelPlan::Aggregate { input, .. }
        | RelPlan::Window { input, .. }
        | RelPlan::Sort { input, .. }
        | RelPlan::Limit { input, .. }
        | RelPlan::TableSample { input, .. }
        | RelPlan::Pivot { input, .. }
        | RelPlan::Unpivot { input, .. }
        | RelPlan::MatchRecognize { input, .. }
        | RelPlan::ConnectBy { input, .. }
        | RelPlan::Unnest { input, .. } => relplan_source_identifier(input),
        RelPlan::Join { left, .. } => relplan_source_identifier(left),
        RelPlan::SetOp { .. }
        | RelPlan::WithScope { .. }
        | RelPlan::Explain { .. }
        | RelPlan::CreateAsQuery { .. }
        | RelPlan::CreateTableForm { .. }
        | RelPlan::ParseRecovery { .. }
        | RelPlan::Opaque { .. }
        | RelPlan::InvalidInput { .. }
        | RelPlan::Insert { .. }
        | RelPlan::Update { .. }
        | RelPlan::Delete { .. }
        | RelPlan::Merge { .. }
        | RelPlan::MultiInsert { .. } => None,
    }
}

/// Walk down `Join.left` chains until a non-Join node is reached,
/// then return its identifier. For `RightOuter` joins the nullable
/// side is the FROM-list anchor (always the leftmost
/// from-item), independent of how many joins precede the right-outer
/// in the chain — this function performs that anchor traversal in
/// the IR.
fn leftmost_join_source_identifier(plan: &RelPlan) -> Option<String> {
    let mut cur = plan;
    loop {
        match cur {
            RelPlan::Join { left, .. } => cur = left.as_ref(),
            _ => return relplan_source_identifier(cur),
        }
    }
}

/// over the inner expression.
fn walk_predicate_for_isnull(
    expr: &ScalarExpr,
    source: &str,
    bindings: &BindingTable,
    out: &mut HashSet<String>,
) {
    use crate::ir::scalar::UnaryOpKind;
    match expr {
        ScalarExpr::UnaryOp {
            op: UnaryOpKind::IsNull,
            arg,
            ..
        } => {
            collect_column_names_in_isnull_arg(arg, source, bindings, out);
        }
        ScalarExpr::BinOp { left, right, .. } => {
            walk_predicate_for_isnull(left, source, bindings, out);
            walk_predicate_for_isnull(right, source, bindings, out);
        }
        ScalarExpr::LogicalChain { operands, .. } => {
            for operand in operands {
                walk_predicate_for_isnull(operand, source, bindings, out);
            }
        }
        ScalarExpr::Like {
            expr,
            pattern,
            escape,
            ..
        } => {
            walk_predicate_for_isnull(expr, source, bindings, out);
            walk_predicate_for_isnull(pattern, source, bindings, out);
            if let Some(e) = escape {
                walk_predicate_for_isnull(e, source, bindings, out);
            }
        }
        // Everything else: stop here. Don't recurse into
        // FuncCall, Case, Cast, InList, etc. — `WHERE COALESCE(x, 0)
        // IS NULL` contributes nothing because the Ident `x`
        // sits inside a FuncCall arg.
        _ => {}
    }
}

/// Extract column names from inside an `IS NULL` argument, recursing
/// through `BinOp` only, inserting both the unqualified name and the
/// qualified `qualifier.name` form when the column reference was
/// syntactically qualified in the source.
fn collect_column_names_in_isnull_arg(
    expr: &ScalarExpr,
    source: &str,
    bindings: &BindingTable,
    out: &mut HashSet<String>,
) {
    match expr {
        ScalarExpr::Column { column, span, .. } | ScalarExpr::OuterRef { column, span, .. } => {
            let Some(binding) = bindings.get(*column) else {
                return;
            };
            let name_norm = normalize_identifier(&binding.display_name);
            out.insert(name_norm.clone());
            if let Some(qual) = qualifier_from_span(source, *span) {
                out.insert(format!("{}.{}", qual, name_norm));
            }
        }
        ScalarExpr::BinOp { left, right, .. } => {
            collect_column_names_in_isnull_arg(left, source, bindings, out);
            collect_column_names_in_isnull_arg(right, source, bindings, out);
        }
        ScalarExpr::Like {
            expr,
            pattern,
            escape,
            ..
        } => {
            collect_column_names_in_isnull_arg(expr, source, bindings, out);
            collect_column_names_in_isnull_arg(pattern, source, bindings, out);
            if let Some(e) = escape {
                collect_column_names_in_isnull_arg(e, source, bindings, out);
            }
        }
        // Other constructs do not contribute.
        _ => {}
    }
}

/// Inspect the source text covered by a column-reference `span` and
/// return the qualifier-as-written (everything before the rightmost
/// `.` separator outside of quotes), case-normalized. Returns `None`
/// when the reference was unqualified or when the span text cannot
/// be sliced. For 3+ part references this function returns the full
/// path-without-trailing-name.
fn qualifier_from_span(source: &str, span: crate::lexer::Span) -> Option<String> {
    let start = span.start as usize;
    let end = span.end as usize;
    if source.is_empty() || end > source.len() || start > end {
        return None;
    }
    let text = &source[start..end];
    let last_dot = find_unquoted_dot_from_end(text)?;
    let qual_text = text[..last_dot].trim();
    if qual_text.is_empty() {
        return None;
    }
    Some(normalize_identifier(qual_text))
}

/// Find the byte index of the last `.` in `text` that is not inside
/// a quoted-identifier delimiter pair (`"…"` / `` `…` `` / `[…]`).
/// Returns `None` if no unquoted dot exists. Used to split a column
/// reference's source span into (qualifier, name) without ambiguity
/// from quoted identifiers that may contain dots.
fn find_unquoted_dot_from_end(text: &str) -> Option<usize> {
    let bytes = text.as_bytes();
    let mut last: Option<usize> = None;
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        match b {
            b'"' => {
                i += 1;
                while i < bytes.len() && bytes[i] != b'"' {
                    i += 1;
                }
                if i < bytes.len() {
                    i += 1;
                }
            }
            b'`' => {
                i += 1;
                while i < bytes.len() && bytes[i] != b'`' {
                    i += 1;
                }
                if i < bytes.len() {
                    i += 1;
                }
            }
            b'[' => {
                i += 1;
                while i < bytes.len() && bytes[i] != b']' {
                    i += 1;
                }
                if i < bytes.len() {
                    i += 1;
                }
            }
            b'.' => {
                last = Some(i);
                i += 1;
            }
            _ => i += 1,
        }
    }
    last
}

/// AND-only descent. `BinOp { op == "AND" }` recurses into both
/// children; `UnaryOp { op == "IS NOT NULL" }` collects qualified
/// column refs from the inner expression. Other operators (OR,
/// comparison, arithmetic) terminate the descent — an `IS NOT NULL`
/// in an OR branch does NOT guarantee the column is non-NULL.
fn walk_predicate_for_isnotnull(
    expr: &ScalarExpr,
    source: &str,
    bindings: &BindingTable,
    out: &mut HashSet<(String, String)>,
) {
    use crate::ir::scalar::UnaryOpKind;
    match expr {
        ScalarExpr::UnaryOp {
            op: UnaryOpKind::IsNotNull,
            arg,
            ..
        } => {
            collect_qualified_refs_for_isnotnull(arg, source, bindings, out);
        }
        ScalarExpr::BinOp {
            op: crate::ir::scalar::BinOpKind::And,
            left,
            right,
            ..
        } => {
            walk_predicate_for_isnotnull(left, source, bindings, out);
            walk_predicate_for_isnotnull(right, source, bindings, out);
        }
        // N-ary spelling of the `And` recursion above; the `_` arm
        // below would otherwise drop every guard in a chained
        // predicate.
        ScalarExpr::LogicalChain {
            op: crate::ir::scalar::LogicalOp::And,
            operands,
            ..
        } => {
            for operand in operands {
                walk_predicate_for_isnotnull(operand, source, bindings, out);
            }
        }
        _ => {}
    }
}

/// From inside an `IS NOT NULL`, gather every column reference and
/// store `(qualifier, name)` pairs. Recurses through `BinOp`
/// regardless of operator (no filtering inside the IS NOT NULL
/// argument).
fn collect_qualified_refs_for_isnotnull(
    expr: &ScalarExpr,
    source: &str,
    bindings: &BindingTable,
    out: &mut HashSet<(String, String)>,
) {
    match expr {
        ScalarExpr::Column { column, span, .. } | ScalarExpr::OuterRef { column, span, .. } => {
            let Some(binding) = bindings.get(*column) else {
                return;
            };
            let name_norm = normalize_identifier(&binding.display_name);
            let qual = qualifier_from_span(source, *span).unwrap_or_default();
            out.insert((qual, name_norm));
        }
        ScalarExpr::BinOp { left, right, .. } => {
            collect_qualified_refs_for_isnotnull(left, source, bindings, out);
            collect_qualified_refs_for_isnotnull(right, source, bindings, out);
        }
        ScalarExpr::Like {
            expr,
            pattern,
            escape,
            ..
        } => {
            collect_qualified_refs_for_isnotnull(expr, source, bindings, out);
            collect_qualified_refs_for_isnotnull(pattern, source, bindings, out);
            if let Some(e) = escape {
                collect_qualified_refs_for_isnotnull(e, source, bindings, out);
            }
        }
        _ => {}
    }
}

/// Take the bare last `.`-segment of a (possibly fully-qualified) tag
/// name.
pub fn bare_tag_suffix(name: &str) -> String {
    match name.rfind('.') {
        Some(idx) => name[idx + 1..].to_string(),
        None => name.to_string(),
    }
}

/// Walk the plan and populate `out` with `(ColumnId → (table_bare,
/// column_normalized))` for every column that originates at a
/// [`RelPlan::Scan`]. Closed-enum exhaustive over [`RelPlan`].
pub fn visit_plan_for_scan_source(
    plan: &RelPlan,
    bindings: &BindingTable,
    out: &mut HashMap<ColumnId, (String, String)>,
) {
    use crate::ir::column::ColumnOrigin;
    match plan {
        RelPlan::Scan { table, columns, .. } => {
            let table_name = table.name.clone();
            for cid in columns {
                let column_name = bindings
                    .get(*cid)
                    .map(|b| match &b.origin {
                        // Prefer origin's column_name (raw catalog
                        // identifier) over display_name, since
                        // display_name can be aliased by the lowerer
                        // for SetOp unification etc.
                        ColumnOrigin::Table { column_name, .. } => column_name.clone(),
                        ColumnOrigin::Computed { .. }
                        | ColumnOrigin::SetOp { .. }
                        | ColumnOrigin::OuterRef { .. }
                        | ColumnOrigin::RecursiveRef { .. } => b.display_name.clone(),
                    })
                    .unwrap_or_default();
                out.insert(
                    *cid,
                    (table_name.clone(), normalize_identifier(&column_name)),
                );
            }
        }
        RelPlan::Values { .. }
        | RelPlan::CteRef { .. }
        | RelPlan::ModelRef { .. }
        | RelPlan::TableFunction { .. }
        | RelPlan::CreateTableForm { .. }
        | RelPlan::ParseRecovery { .. }
        | RelPlan::Opaque { .. }
        | RelPlan::InvalidInput { .. } => {}
        RelPlan::Project { input, .. }
        | RelPlan::Filter { input, .. }
        | RelPlan::Aggregate { input, .. }
        | RelPlan::Window { input, .. }
        | RelPlan::Sort { input, .. }
        | RelPlan::Limit { input, .. }
        | RelPlan::TableSample { input, .. }
        | RelPlan::Pivot { input, .. }
        | RelPlan::Unpivot { input, .. }
        | RelPlan::MatchRecognize { input, .. }
        | RelPlan::ConnectBy { input, .. }
        | RelPlan::Unnest { input, .. }
        | RelPlan::DerivedTable { input, .. } => {
            visit_plan_for_scan_source(input, bindings, out);
        }
        RelPlan::Join { left, right, .. } => {
            visit_plan_for_scan_source(left, bindings, out);
            visit_plan_for_scan_source(right, bindings, out);
        }
        RelPlan::SetOp { inputs, .. } => {
            for inp in inputs {
                visit_plan_for_scan_source(inp, bindings, out);
            }
        }
        RelPlan::WithScope { ctes, body, .. } => {
            for cte in ctes {
                match &cte.body {
                    CteBody::NonRecursive(b) => visit_plan_for_scan_source(b, bindings, out),
                    CteBody::Recursive { anchor, step, .. } => {
                        visit_plan_for_scan_source(anchor, bindings, out);
                        visit_plan_for_scan_source(step, bindings, out);
                    }
                }
            }
            visit_plan_for_scan_source(body, bindings, out);
        }
        RelPlan::Explain { body, .. } => {
            visit_plan_for_scan_source(body, bindings, out);
        }
        RelPlan::CreateAsQuery { body, .. } => {
            if let Some(body) = body.as_deref() {
                visit_plan_for_scan_source(body, bindings, out);
            }
        }
        RelPlan::Insert { source, .. } => match source {
            InsertSource::Values(p) | InsertSource::Query(p) => {
                visit_plan_for_scan_source(p, bindings, out);
            }
            InsertSource::DefaultValues => {}
        },
        RelPlan::Update { from, .. } => {
            if let Some(f) = from {
                visit_plan_for_scan_source(f, bindings, out);
            }
        }
        RelPlan::Delete { using, .. } => {
            if let Some(u) = using {
                visit_plan_for_scan_source(u, bindings, out);
            }
        }
        RelPlan::Merge { source, .. } | RelPlan::MultiInsert { source, .. } => {
            visit_plan_for_scan_source(source, bindings, out);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::catalog::{CatalogDialect, FunctionCatalog};
    use crate::ir::lower::lower_query_full_with_bindings;
    use crate::ir::strict::StrictMode;
    use crate::ir::SessionContext;
    use crate::parse_stmt_from_str;

    fn facts_for(sql: &str) -> DerivedFacts {
        let stmt = parse_stmt_from_str(sql).expect("parse");
        let catalog = FunctionCatalog::for_dialect(CatalogDialect::Default);
        let session = SessionContext::default();
        let (plan, _catalog_ctx, bindings, _facts) = lower_query_full_with_bindings(
            &stmt,
            sql,
            StrictMode::Permissive,
            &catalog,
            &session,
            None,
        )
        .expect("lower");
        match &plan {
            RelPlan::ParseRecovery { .. } => {
                panic!("expected lowered plan, got ParseRecovery");
            }
            RelPlan::Opaque { reason, .. } => {
                panic!("expected lowered plan, got Opaque: {reason:?}");
            }
            RelPlan::InvalidInput { kind, .. } => {
                panic!("expected lowered plan, got InvalidInput: {kind:?}");
            }
            _ => {}
        }
        derive_facts_from_plan(
            "",
            &plan,
            &bindings,
            &crate::ir::catalog::FunctionCatalog::empty(),
            None,
            &crate::facts::reasoning::RecognitionOnly,
        )
    }

    #[test]
    fn simple_select_has_no_flags() {
        let f = facts_for("SELECT a FROM t");
        assert_eq!(f.tables_read.len(), 1);
        assert_eq!(f.tables_read[0].name, "t");
        assert!(!f.has_where);
        assert!(!f.has_group_by);
        assert!(!f.has_distinct);
        assert!(!f.has_aggregates);
        assert_eq!(f.immediate_join_count, 0);
    }

    #[test]
    fn where_sets_has_where() {
        let f = facts_for("SELECT a FROM t WHERE a > 1");
        assert!(f.has_where);
    }

    #[test]
    fn distinct_sets_has_distinct() {
        let f = facts_for("SELECT DISTINCT a FROM t");
        assert!(f.has_distinct);
    }

    #[test]
    fn group_by_sets_has_group_by_and_has_aggregates() {
        let f = facts_for("SELECT a, COUNT(*) FROM t GROUP BY a");
        assert!(f.has_group_by);
        assert!(f.has_aggregates);
    }

    #[test]
    fn implicit_aggregation_sets_has_aggregates_only() {
        let f = facts_for("SELECT COUNT(*) FROM t");
        assert!(!f.has_group_by);
        assert!(f.has_aggregates);
    }

    #[test]
    fn join_count_counts_each_join_node() {
        let f = facts_for("SELECT a.x FROM a JOIN b ON a.x = b.x JOIN c ON b.y = c.y");
        assert_eq!(f.immediate_join_count, 2);
        assert_eq!(f.tables_read.len(), 3);
    }

    #[test]
    fn comma_from_counts_as_join() {
        let f = facts_for("SELECT a.x FROM a, b, c");
        assert_eq!(f.immediate_join_count, 2);
        assert_eq!(f.tables_read.len(), 3);
    }

    #[test]
    fn tables_read_is_sorted_and_dedup() {
        let f = facts_for("SELECT t.x FROM s.t JOIN s.t t2 ON t.x = t2.x");
        // Same physical table referenced twice via alias — one entry.
        assert_eq!(f.tables_read.len(), 1);
        assert_eq!(f.tables_read[0].name, "t");
        assert_eq!(f.tables_read[0].schema.as_deref(), Some("s"));
    }

    #[test]
    fn setop_does_not_propagate_scalar_flags_from_branches() {
        // Every branch has a WHERE; the outer SetSelect has no
        // outer WHERE/GROUP/etc., so `has_where` etc. must be false
        // ("immediate scope" semantics).
        // Only `tables_read` accumulates across branches.
        let f = facts_for(
            "SELECT a FROM t1 WHERE a > 1 \
             UNION ALL SELECT a FROM t2 WHERE a < 10 \
             UNION ALL SELECT a FROM t3 WHERE a = 0",
        );
        assert!(!f.has_where);
        assert!(!f.has_group_by);
        assert!(!f.has_distinct);
        assert!(!f.has_aggregates);
        assert_eq!(f.immediate_join_count, 0);
        assert_eq!(f.tables_read.len(), 3);
    }
}
