// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Structural query methods on `RelPlan`.
//!
//! These are pure functions of plan shape. Every per-statement fact
//! that can be answered by walking the plan tree lives here as an
//! `impl RelPlan` method — `has_where`, `has_distinct`,
//! `immediate_join_count`, etc. — instead of as a stored field:
//! `RelPlan` is the source of truth.
//!
//! # Scope: immediate vs anywhere
//!
//! - **Immediate** — only the current statement's outermost scope.
//!   Stops at scope boundaries: subqueries reached via
//!   `ScalarExpr::Exists` / `ScalarSubquery` / `QuantifiedCmp`,
//!   `WithScope.ctes[*].body` CTE bodies, and `DerivedTable.input`
//!   derived-table bodies. Examples: `has_where` (the SELECT body's
//!   WHERE), `immediate_join_count` (top-level joins).
//!
//! - **Anywhere** — full recursive walk including subqueries / CTE
//!   bodies / derived tables. Examples: `has_sample`,
//!   `tables_read`.
//!
//! # Implementation
//!
//! Both walks reuse `super::visitor::walk_rel_plan` (the canonical
//! exhaustive walker). The "anywhere" walk uses default visitor
//! behaviour: subqueries are entered via the default `visit_subquery`,
//! CTE bindings and derived-table bodies via `walk_rel_plan` default
//! arms. The "immediate" walk overrides `visit_subquery` to no-op and
//! overrides `visit_rel_plan` to skip CTE binding bodies and
//! derived-table bodies while continuing to walk all other arms.
//!
//! Every match on [`RelPlan`] / [`FilterKind`] / [`JoinKind`] inherits
//! the visitor's exhaustive arms — no `_ =>` arms in this file either.
#![allow(dead_code)]

use super::column::BindingTable;
use super::plan::{CteBody, FilterKind, GroupingSpec, JoinKind, LimitKind, RelPlan, SetOpKind};
use super::scalar::{Lit, ScalarExpr, ScopeId};
use super::visitor::{walk_rel_plan, walk_scalar_expr, RelPlanVisitor};
use crate::ast::NodeId;
use crate::context::node_metadata::{IdentKey, TableRef};

// ────────────────────────────────────────────────────────────────────────
// Public methods on RelPlan
// ────────────────────────────────────────────────────────────────────────

impl RelPlan {
    // ── Boolean structural queries ────────────────────────────────

    /// True iff a `WHERE`-shaped predicate is present in the
    /// immediate scope:
    ///
    /// - SELECT-shape: a [`RelPlan::Filter`] with
    ///   [`FilterKind::Where`].
    /// - UPDATE / DELETE: the variant's `predicate: Option<ScalarExpr>`
    ///   field is `Some`.
    /// - MERGE: always `true`. MERGE's `ON` clause is mandatory and
    ///   bounds the operation (only matched / unmatched rows are
    ///   touched) — "blast-radius-bounding" predicates count as
    ///   WHERE for the
    ///   `DML-WRITE-UNBOUNDED` rule. Tautology detection on the ON
    ///   clause is handled separately via `has_tautology_where`.
    ///
    /// For INSERT, the source query's WHERE is reachable because the
    /// immediate walker descends into `InsertSource::Query` (no scope
    /// boundary). The `Insert` arm itself returns `false`; any
    /// `Filter::Where` inside the source plan is found by the
    /// recursive walk.
    ///
    /// Does NOT recurse into subqueries, CTE bodies, or
    /// derived-table bodies — those have their own scopes.
    pub fn has_where(&self) -> bool {
        any_immediate(self, |p| match p {
            RelPlan::Filter {
                kind: FilterKind::Where,
                ..
            } => true,
            // Filter with non-Where kind: not a WHERE clause.
            RelPlan::Filter { .. } => false,
            // DML predicate-as-WHERE.
            RelPlan::Update { predicate, .. } => predicate.is_some(),
            RelPlan::Delete { predicate, .. } => predicate.is_some(),
            // MERGE: ON clause bounds the operation.
            RelPlan::Merge { .. } => true,
            // Sources: no WHERE.
            RelPlan::Scan { .. }
            | RelPlan::Values { .. }
            | RelPlan::CteRef { .. }
            | RelPlan::ModelRef { .. } => false,
            // Other unary / binary / wrapper variants: walker continues
            // into their inputs via `for_each_immediate`; the variant
            // itself contributes no WHERE.
            RelPlan::Project { .. }
            | RelPlan::Aggregate { .. }
            | RelPlan::Window { .. }
            | RelPlan::Sort { .. }
            | RelPlan::Limit { .. }
            | RelPlan::Join { .. }
            | RelPlan::SetOp { .. }
            | RelPlan::WithScope { .. }
            | RelPlan::DerivedTable { .. }
            | RelPlan::TableFunction { .. }
            | RelPlan::TableSample { .. }
            | RelPlan::Pivot { .. }
            | RelPlan::Unpivot { .. }
            | RelPlan::MatchRecognize { .. }
            | RelPlan::ConnectBy { .. }
            | RelPlan::Unnest { .. }
            | RelPlan::Insert { .. }
            | RelPlan::MultiInsert { .. }
            | RelPlan::Explain { .. }
            | RelPlan::CreateAsQuery { .. }
            | RelPlan::CreateTableForm { .. }
            | RelPlan::InvalidInput { .. }
            | RelPlan::ParseRecovery { .. }
            | RelPlan::Opaque { .. } => false,
        })
    }

    /// True iff a [`RelPlan::Filter`] with [`FilterKind::Qualify`] is
    /// present in the immediate scope.
    pub fn has_qualify(&self) -> bool {
        any_immediate(self, |p| {
            matches!(
                p,
                RelPlan::Filter {
                    kind: FilterKind::Qualify,
                    ..
                }
            )
        })
    }

    /// True iff the immediate scope's outermost [`RelPlan::Project`]
    /// has `distinct: true`. Walks through Sort / Limit / Filter /
    /// Window wrappers that can sit above the top Project.
    pub fn has_distinct(&self) -> bool {
        let mut cursor = self;
        loop {
            match cursor {
                RelPlan::Project { distinct, .. } => return *distinct,
                RelPlan::Sort { input, .. }
                | RelPlan::Limit { input, .. }
                | RelPlan::Filter { input, .. }
                | RelPlan::Window { input, .. } => {
                    cursor = input;
                }
                RelPlan::Explain { body, .. } | RelPlan::WithScope { body, .. } => {
                    cursor = body;
                }
                _ => return false,
            }
        }
    }

    /// True iff a `Scan` with a sample modifier or a `TableSample`
    /// node appears anywhere in the plan tree.
    pub fn has_sample(&self) -> bool {
        any_anywhere(self, |p| match p {
            RelPlan::TableSample { .. } => true,
            RelPlan::Scan { modifier, .. } => modifier.sample.is_some(),
            _ => false,
        })
    }

    /// True iff a [`RelPlan::Limit`] node is present in the immediate
    /// scope. Walks through Sort / Filter / Window wrappers that can
    /// sit above the top Limit: the outer query's own
    /// LIMIT, not LIMIT inside subqueries / CTE bodies.
    pub fn has_limit(&self) -> bool {
        any_immediate(self, |p| matches!(p, RelPlan::Limit { .. }))
    }

    /// True iff a `Join` with `kind == JoinKind::Cross` and
    /// `implicit == true` (comma-separated FROM list) appears in the
    /// immediate scope.
    pub fn has_implicit_cross_join(&self) -> bool {
        any_immediate(self, |p| {
            matches!(
                p,
                RelPlan::Join {
                    kind: JoinKind::Cross,
                    implicit: true,
                    ..
                }
            )
        })
    }

    /// True iff the immediate scope contains an [`RelPlan::Aggregate`]
    /// node: the outer query's own aggregates, NOT aggregates
    /// inside subqueries / CTE bodies.
    pub fn immediate_has_aggregates(&self) -> bool {
        any_immediate(self, |p| matches!(p, RelPlan::Aggregate { .. }))
    }

    // ── Counts ─────────────────────────────────────────────────────

    /// Number of [`RelPlan::Join`] nodes in the immediate scope.
    /// Excludes joins inside subqueries / CTE bodies / derived
    /// tables.
    pub fn immediate_join_count(&self) -> usize {
        let mut n = 0usize;
        for_each_immediate(self, |p| {
            if matches!(p, RelPlan::Join { .. }) {
                n += 1;
            }
        });
        n
    }

    /// Number of [`RelPlan::Scan`] nodes in the immediate scope.
    /// Excludes scans inside subqueries / CTE bodies / derived
    /// tables.
    pub fn immediate_table_count(&self) -> usize {
        let mut n = 0usize;
        for_each_immediate(self, |p| {
            if matches!(p, RelPlan::Scan { .. }) {
                n += 1;
            }
        });
        n
    }
}

/// One step between a query and the one table each of its rows is a row
/// of ([`RelPlan::one_table_steps`]), outermost first.
#[derive(Debug, Clone, Copy)]
pub(crate) enum RowStep<'p> {
    /// A `WHERE` keeps the rows its predicate passes.
    Where(&'p ScalarExpr),
    /// A row cap (`LIMIT`, `TOP`, `FETCH`, `OFFSET`): at most `count` rows,
    /// or that percentage of them under `percent`, after skipping those an
    /// `OFFSET` names. No `count` where only an `OFFSET` is written.
    Limit {
        count: Option<&'p ScalarExpr>,
        percent: bool,
    },
    /// The rows are those of the CTE `name` of `scope`, a query the caller
    /// resolves.
    Cte { name: &'p IdentKey, scope: ScopeId },
    /// The rows are this table's.
    Table(&'p TableRef),
}

/// Whether a lateral right side yields a row for each row to its left, by
/// its shape alone ([`RelPlan::row_yield`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RowYield {
    /// It yields a row for every row to its left: `VALUES`, a select with
    /// no `FROM`, an aggregate with no grouping and no `HAVING`; or what
    /// can drop its rows reads no row to its left, so it keeps a row for
    /// every one of them or for none.
    AtLeastOne,
    /// It can yield none for some rows to its left and not for others: a
    /// filter, a join condition or a cap that reads the row to its left
    /// and is not always true. A cap of no rows, which yields none for
    /// any, is one too.
    MayBeNone,
    /// Neither is shown: the rows of a table or a table function.
    Undecided,
}

impl RowYield {
    /// The yield of a product of queries yielding `self` and `other`.
    fn product(self, other: RowYield) -> RowYield {
        match (self, other) {
            (RowYield::MayBeNone, _) | (_, RowYield::MayBeNone) => RowYield::MayBeNone,
            (RowYield::AtLeastOne, RowYield::AtLeastOne) => RowYield::AtLeastOne,
            (RowYield::Undecided, _) | (_, RowYield::Undecided) => RowYield::Undecided,
        }
    }

    /// The yield of a union of queries yielding `self` and `other`.
    fn union(self, other: RowYield) -> RowYield {
        match (self, other) {
            (RowYield::AtLeastOne, _) | (_, RowYield::AtLeastOne) => RowYield::AtLeastOne,
            (RowYield::MayBeNone, RowYield::MayBeNone) => RowYield::MayBeNone,
            (RowYield::Undecided, _) | (_, RowYield::Undecided) => RowYield::Undecided,
        }
    }

    /// The yield of `self` where something that reads no row to the left
    /// may drop every row: it stays none for some rows only where it was.
    fn or_none(self) -> RowYield {
        self.product(RowYield::Undecided)
    }
}

/// The rows to the left of a lateral right side: the columns its nodes
/// introduce and its sources, by which a read of them is known.
pub(crate) struct LeftRows<'p> {
    columns: std::collections::HashSet<super::column::ColumnId>,
    sources: std::collections::HashSet<NodeId>,
    bindings: &'p BindingTable,
}

impl<'p> LeftRows<'p> {
    /// The rows of `left`, the left side of a join.
    pub(crate) fn of(left: &RelPlan, bindings: &'p BindingTable) -> Self {
        Self {
            columns: super::correlation::produced_columns(left),
            sources: super::correlation::source_nodes(left),
            bindings,
        }
    }

    /// The rows of `join`, a join one of whose sides, `side`, has these
    /// rows: these, and those its other side and its condition introduce.
    pub(crate) fn joined(mut self, join: &RelPlan, side: &RelPlan) -> Self {
        self.columns
            .extend(super::correlation::produced_columns_except(join, side));
        if let RelPlan::Join { left, right, .. } = join {
            let other = match std::ptr::eq(left.as_ref(), side) {
                true => right,
                false => left,
            };
            self.sources.extend(super::correlation::source_nodes(other));
        }
        self
    }

    /// Whether `column` is a column of these rows: one a node of them
    /// introduces, a column of one of their sources, or an outer
    /// reference to either.
    fn holds(&self, column: super::column::ColumnId) -> bool {
        use super::column::ColumnOrigin;
        if self.columns.contains(&column) {
            return true;
        }
        match self.bindings.get(column).map(|binding| &binding.origin) {
            Some(ColumnOrigin::Table { table_node, .. }) => self.sources.contains(table_node),
            Some(ColumnOrigin::OuterRef { outer_column, .. }) => {
                self.columns.contains(outer_column)
            }
            Some(
                ColumnOrigin::Computed { .. }
                | ColumnOrigin::Merged { .. }
                | ColumnOrigin::SetOp { .. }
                | ColumnOrigin::RecursiveRef { .. }
                | ColumnOrigin::Unattributed { .. },
            )
            | None => false,
        }
    }

    /// Whether `expr`, its subqueries included, reads these rows.
    fn read_by(&self, expr: &ScalarExpr) -> bool {
        super::correlation::expr_referenced_columns(expr)
            .into_iter()
            .any(|column| self.holds(column))
    }

    /// Whether `plan`, at any depth, reads these rows.
    fn read_in(&self, plan: &RelPlan) -> bool {
        super::correlation::plan_referenced_columns(plan)
            .into_iter()
            .any(|column| self.holds(column))
    }
}

impl RelPlan {
    /// Whether this query, the right side of a join read once for each row
    /// of `left`, yields a row for each, by its shape: a filter, a join
    /// condition or a cap drops a row to the left only where it reads that
    /// row and is not judged always true, by its shape alone, against
    /// `source` and `bindings`. One that reads no row to the left keeps
    /// every row to the left or none. Serves a lateral right side (`CROSS
    /// APPLY`, `LATERAL`), and a derived table that reads nothing to its
    /// left, alike.
    pub(crate) fn row_yield(
        &self,
        left: &LeftRows<'_>,
        source: &str,
        bindings: &BindingTable,
    ) -> RowYield {
        let filters = |predicate: &ScalarExpr| {
            !super::always_true::is_always_true(predicate, source, None, bindings, None)
        };
        // A predicate drops a row to the left where it reads it.
        let drops = |predicate: &ScalarExpr| filters(predicate) && left.read_by(predicate);
        match self {
            RelPlan::Values { rows, .. } => match rows.is_empty() {
                true => RowYield::MayBeNone,
                false => RowYield::AtLeastOne,
            },
            RelPlan::Project { input, .. }
            | RelPlan::Sort { input, .. }
            | RelPlan::Window { input, .. }
            | RelPlan::DerivedTable { input, .. } => input.row_yield(left, source, bindings),
            RelPlan::WithScope { body, .. } => body.row_yield(left, source, bindings),
            RelPlan::Filter {
                input, predicate, ..
            } => match drops(predicate) {
                true => RowYield::MayBeNone,
                false => input.row_yield(left, source, bindings),
            },
            RelPlan::Limit {
                input,
                limit,
                offset,
                ..
            } => {
                let input = input.row_yield(left, source, bindings);
                let skips = offset.as_ref().filter(|offset| !is_zero(offset));
                match (limit.as_ref(), skips) {
                    // A cap of no rows yields none for any row.
                    (Some(count), _) if is_zero(count) => RowYield::MayBeNone,
                    (count, skips)
                        if count
                            .into_iter()
                            .chain(skips)
                            .any(|bound| left.read_by(bound)) =>
                    {
                        RowYield::MayBeNone
                    }
                    (_, Some(_)) => input.or_none(),
                    (Some(count), None) if !is_literal(count) => input.or_none(),
                    (Some(_) | None, None) => input,
                }
            }
            RelPlan::Aggregate {
                input,
                grouping,
                having,
                ..
            } => {
                let input = input.row_yield(left, source, bindings);
                // A `HAVING` judges groups whose rows vary with the row to
                // the left where its input may be none for some.
                let having_drops = having.as_ref().is_some_and(|having| {
                    drops(having) || (filters(having) && input == RowYield::MayBeNone)
                });
                if having_drops {
                    return RowYield::MayBeNone;
                }
                match grouping {
                    // A grand total is a row over no rows.
                    GroupingSpec::None | GroupingSpec::Rollup(_) | GroupingSpec::Cube(_) => {
                        RowYield::AtLeastOne
                    }
                    GroupingSpec::Standard(_) | GroupingSpec::All { .. } => input,
                    // A set of no keys yields a row over no rows.
                    GroupingSpec::GroupingSets(_) => match input {
                        RowYield::AtLeastOne => RowYield::AtLeastOne,
                        RowYield::MayBeNone | RowYield::Undecided => RowYield::Undecided,
                    },
                }
            }
            RelPlan::Join {
                left: first,
                right: second,
                kind,
                on,
                match_condition,
                ..
            } => {
                // `USING` and `NATURAL` compare two columns of the right
                // side itself: they read no row to its left.
                let dropping = on.as_ref().or(match_condition.as_ref()).is_some_and(drops);
                let (first, second) = (
                    first.row_yield(left, source, bindings),
                    second.row_yield(left, source, bindings),
                );
                match kind {
                    JoinKind::Inner
                    | JoinKind::LeftSemi
                    | JoinKind::RightSemi
                    | JoinKind::LeftAnti
                    | JoinKind::RightAnti
                        if dropping =>
                    {
                        RowYield::MayBeNone
                    }
                    JoinKind::Inner
                    | JoinKind::LeftSemi
                    | JoinKind::RightSemi
                    | JoinKind::Cross => first.product(second),
                    JoinKind::LeftAnti => first.or_none(),
                    JoinKind::RightAnti => second.or_none(),
                    JoinKind::LeftOuter | JoinKind::Asof => first,
                    JoinKind::RightOuter => second,
                    JoinKind::FullOuter => first.union(second),
                }
            }
            RelPlan::SetOp { op, inputs, .. } => match op {
                SetOpKind::UnionAll | SetOpKind::UnionDistinct => inputs
                    .iter()
                    .map(|input| input.row_yield(left, source, bindings))
                    .reduce(RowYield::union)
                    .unwrap_or(RowYield::MayBeNone),
                // The rows compared vary with the row to the left where a
                // branch reads it.
                SetOpKind::IntersectAll
                | SetOpKind::IntersectDistinct
                | SetOpKind::ExceptAll
                | SetOpKind::ExceptDistinct => match left.read_in(self) {
                    true => RowYield::MayBeNone,
                    false => inputs
                        .first()
                        .map_or(RowYield::MayBeNone, |first| {
                            first.row_yield(left, source, bindings)
                        })
                        .or_none(),
                },
            },
            RelPlan::Scan { .. }
            | RelPlan::CteRef { .. }
            | RelPlan::ModelRef { .. }
            | RelPlan::TableFunction { .. }
            | RelPlan::Unnest { .. }
            | RelPlan::Pivot { .. }
            | RelPlan::Unpivot { .. }
            | RelPlan::MatchRecognize { .. }
            | RelPlan::ConnectBy { .. }
            | RelPlan::TableSample { .. }
            | RelPlan::Insert { .. }
            | RelPlan::Update { .. }
            | RelPlan::Delete { .. }
            | RelPlan::Merge { .. }
            | RelPlan::MultiInsert { .. }
            | RelPlan::Explain { .. }
            | RelPlan::CreateAsQuery { .. }
            | RelPlan::CreateTableForm { .. }
            | RelPlan::InvalidInput { .. }
            | RelPlan::ParseRecovery { .. }
            | RelPlan::Opaque { .. } => RowYield::Undecided,
        }
    }

    /// The source `node` among the FROM sources this plan joins.
    pub(crate) fn joined_source(&self, node: NodeId) -> Option<&RelPlan> {
        // A comma join carries its right item's id: look below it first.
        if let RelPlan::Join { left, right, .. } = self {
            return left
                .joined_source(node)
                .or_else(|| right.joined_source(node));
        }
        (self.node_id() == node).then_some(self)
    }

    /// The steps from this query to the one table each row it returns is
    /// one row of: through a `Project` without `DISTINCT`, a `WHERE`, a
    /// `Sort`, a `Limit`, a `Window` and a derived table, ending at a
    /// `Scan` or a CTE reference. `None` for a query of any other shape (a
    /// join, a set operation, an aggregate, a `QUALIFY`, `VALUES`), whose
    /// rows are no one table's.
    pub(crate) fn one_table_steps(&self) -> Option<Vec<RowStep<'_>>> {
        let mut steps = Vec::new();
        let mut plan = self;
        loop {
            match plan {
                RelPlan::Project {
                    input, distinct, ..
                } => {
                    if *distinct {
                        return None;
                    }
                    plan = input;
                }
                RelPlan::Filter {
                    input,
                    predicate,
                    kind,
                    ..
                } => match kind {
                    FilterKind::Where => {
                        steps.push(RowStep::Where(predicate));
                        plan = input;
                    }
                    FilterKind::Qualify | FilterKind::Having => return None,
                },
                // A window function adds a column to each row it keeps.
                RelPlan::Sort { input, .. }
                | RelPlan::DerivedTable { input, .. }
                | RelPlan::Window { input, .. } => plan = input,
                RelPlan::Limit {
                    input, limit, kind, ..
                } => {
                    steps.push(RowStep::Limit {
                        count: limit.as_ref(),
                        percent: match kind {
                            LimitKind::Rows => false,
                            LimitKind::Percent => true,
                        },
                    });
                    plan = input;
                }
                RelPlan::Scan { table, .. } => {
                    steps.push(RowStep::Table(table));
                    return Some(steps);
                }
                RelPlan::CteRef { name, scope, .. } => {
                    steps.push(RowStep::Cte {
                        name,
                        scope: *scope,
                    });
                    return Some(steps);
                }
                RelPlan::Values { .. }
                | RelPlan::ModelRef { .. }
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
}

/// Whether `expr` is a numeric literal.
fn is_literal(expr: &ScalarExpr) -> bool {
    matches!(
        expr,
        ScalarExpr::Lit {
            value: Lit::Integer(_) | Lit::Float(_),
            ..
        }
    )
}

/// Whether `expr` is a numeric literal of zero.
fn is_zero(expr: &ScalarExpr) -> bool {
    let ScalarExpr::Lit {
        value: Lit::Integer(text) | Lit::Float(text),
        ..
    } = expr
    else {
        return false;
    };
    text.parse::<f64>().is_ok_and(|count| count == 0.0)
}

// ────────────────────────────────────────────────────────────────────────
// Walk helpers — built on RelPlanVisitor
// ────────────────────────────────────────────────────────────────────────

/// Visitor that observes every plan node anywhere in the tree.
/// Default trait behaviour walks all subtrees including subqueries
/// inside scalars (via `visit_subquery`) and CTE bindings inside
/// `WithScope.ctes` (via `walk_rel_plan`'s WithScope arm).
struct AnywhereObserver<F: FnMut(&RelPlan)> {
    observe: F,
}

impl<'a, F: FnMut(&RelPlan)> RelPlanVisitor<'a> for AnywhereObserver<F> {
    fn visit_rel_plan(&mut self, plan: &'a RelPlan) {
        (self.observe)(plan);
        walk_rel_plan(self, plan);
    }
}

/// Visit every plan node anywhere in the tree.
fn for_each_anywhere<F: FnMut(&RelPlan)>(plan: &RelPlan, observe: F) {
    let mut v = AnywhereObserver { observe };
    v.visit_rel_plan(plan);
}

/// Short-circuit `for_each_anywhere`. Returns `true` as soon as
/// `pred(node)` is true on any visited node.
fn any_anywhere<F: FnMut(&RelPlan) -> bool>(plan: &RelPlan, mut pred: F) -> bool {
    let mut found = false;
    for_each_anywhere(plan, |p| {
        if !found && pred(p) {
            found = true;
        }
    });
    found
}

/// Visitor that observes every plan node in the immediate scope only.
/// Skips scope boundaries:
/// - `visit_subquery` is overridden to no-op (don't enter subqueries).
/// - `visit_rel_plan` is overridden to special-case `WithScope`
///   (skip CTE binding bodies, walk only the outer body) and
///   `DerivedTable` (skip the inner body entirely).
struct ImmediateObserver<F: FnMut(&RelPlan)> {
    observe: F,
}

impl<'a, F: FnMut(&RelPlan)> RelPlanVisitor<'a> for ImmediateObserver<F> {
    fn visit_rel_plan(&mut self, plan: &'a RelPlan) {
        (self.observe)(plan);
        match plan {
            RelPlan::WithScope { body, .. } => {
                // Skip CTE binding bodies; descend only into the
                // outer body (the immediate-scope query).
                self.visit_rel_plan(body);
            }
            RelPlan::DerivedTable { .. } => {
                // Body is a separate scope — do not descend.
            }
            _ => walk_rel_plan(self, plan),
        }
    }

    fn visit_subquery(
        &mut self,
        _plan: &'a RelPlan,
        _correlates_with: &'a [super::column::ColumnId],
    ) {
        // Subqueries inside scalars are separate scopes — do not
        // enter.
    }
}

/// Visit every plan node in the immediate scope only.
pub fn for_each_immediate<F: FnMut(&RelPlan)>(plan: &RelPlan, observe: F) {
    let mut v = ImmediateObserver { observe };
    v.visit_rel_plan(plan);
}

/// Short-circuit `for_each_immediate`.
fn any_immediate<F: FnMut(&RelPlan) -> bool>(plan: &RelPlan, mut pred: F) -> bool {
    let mut found = false;
    for_each_immediate(plan, |p| {
        if !found && pred(p) {
            found = true;
        }
    });
    found
}

// Suppress unused warnings for helpers that will be consumed by
// the next sub-step's collection methods.
#[allow(dead_code)]
fn _unused_walk_scalar_marker(expr: &ScalarExpr) {
    // walk_scalar_expr requires a RelPlanVisitor; this is a marker
    // that the import is used by the AnywhereObserver default
    // traversal at compile time.
    let _ = walk_scalar_expr::<AnywhereObserver<fn(&RelPlan)>>;
    let _ = expr;
}

#[allow(dead_code)]
fn _unused_cte_body_marker(b: &CteBody) {
    let _ = b;
}

// ────────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::plan::{
        FilterKind, JoinKind, ProjectItem, ProjectStar, RelPlan, ScanModifier, StarQualifier,
    };
    use crate::ir::scalar::Lit;
    use crate::lexer::Span;

    fn nid(n: u32) -> crate::ast::NodeId {
        crate::ast::NodeId::new(n)
    }
    fn span() -> Span {
        Span { start: 0, end: 0 }
    }

    fn dummy_table(name: &str) -> crate::context::node_metadata::TableRef {
        crate::context::node_metadata::TableRef {
            server: None,
            db: None,
            schema: None,
            name: name.to_string(),
            span: Some(span()),
        }
    }

    fn scan(name: &str, id: u32) -> RelPlan {
        RelPlan::Scan {
            table: dummy_table(name),
            columns: Vec::new(),
            modifier: ScanModifier::default(),
            alias: None,
            hints: Vec::new(),
            node_id: nid(id),
            span: span(),
        }
    }

    fn lit_true() -> ScalarExpr {
        ScalarExpr::Lit {
            value: Lit::Bool(true),
            span: span(),
        }
    }

    /// The rows of a join grown from one side's are the rows read of the
    /// whole join, at every join of a chain, whichever side holds the row.
    #[test]
    fn rows_grown_side_by_side_are_the_rows_of_the_join() {
        use crate::ir::catalog::{CatalogDialect, FunctionCatalog};
        let _folding = crate::ir::normalize::default_folding();
        for src in [
            "SELECT 1 FROM a JOIN b ON b.k = a.k JOIN c USING (k) CROSS JOIN d",
            "SELECT 1 FROM a, (SELECT x FROM s WHERE s.y = 1) v JOIN e ON e.k = (SELECT MAX(z) FROM w)",
            "SELECT 1 FROM a LEFT JOIN (b JOIN c ON c.k = b.k) ON b.k = a.k NATURAL JOIN f",
        ] {
            let stmt = crate::parse_stmt_from_str(src).expect("parse");
            let catalog = FunctionCatalog::for_dialect(CatalogDialect::Default);
            let session = crate::ir::SessionContext::default();
            let (plan, _, bindings, _) = crate::ir::lower::lower_query_full_with_bindings(
                &stmt,
                src,
                crate::ir::StrictMode::Permissive,
                &catalog,
                &session,
                None,
            )
            .expect("lower");
            let mut joins = Vec::new();
            let mut stack = vec![&plan];
            while let Some(node) = stack.pop() {
                if let RelPlan::Join { left, right, .. } = node {
                    joins.push((node, left, right));
                    stack.push(left);
                    stack.push(right);
                } else if let RelPlan::Project { input, .. }
                | RelPlan::Filter { input, .. }
                | RelPlan::DerivedTable { input, .. } = node
                {
                    stack.push(input);
                }
            }
            assert!(joins.len() > 1, "{src}");
            for (join, left, right) in joins {
                let whole = LeftRows::of(join, &bindings);
                for side in [left.as_ref(), right.as_ref()] {
                    let grown = LeftRows::of(side, &bindings).joined(join, side);
                    assert_eq!(grown.columns, whole.columns, "{src}");
                    assert_eq!(grown.sources, whole.sources, "{src}");
                }
            }
        }
    }

    /// `has_where` finds Filter::Where in immediate scope.
    #[test]
    fn has_where_immediate() {
        let plan = RelPlan::Filter {
            computed: Vec::new(),
            input: Box::new(scan("t", 1)),
            predicate: lit_true(),
            kind: FilterKind::Where,
            hints: Vec::new(),
            node_id: nid(2),
            span: span(),
        };
        assert!(plan.has_where());
        assert!(!plan.has_qualify());
    }

    /// `has_where` does NOT recurse into derived-table bodies.
    #[test]
    fn has_where_does_not_cross_derived_table() {
        let inner_filter = RelPlan::Filter {
            computed: Vec::new(),
            input: Box::new(scan("t", 1)),
            predicate: lit_true(),
            kind: FilterKind::Where,
            hints: Vec::new(),
            node_id: nid(2),
            span: span(),
        };
        let outer = RelPlan::DerivedTable {
            input: Box::new(inner_filter),
            alias: None,
            columns: Vec::new(),
            alias_columns: Vec::new(),
            body_columns: Vec::new(),
            hints: Vec::new(),
            node_id: nid(3),
            span: span(),
        };
        assert!(!outer.has_where());
    }

    /// `has_distinct` walks through Sort/Limit/Filter to find the top
    /// Project's distinct flag.
    #[test]
    fn has_distinct_through_sort_limit() {
        let project = RelPlan::Project {
            input: Box::new(scan("t", 1)),
            items: vec![ProjectItem::Star(ProjectStar {
                qualifier: StarQualifier::Unqualified,
                exclude: Vec::new(),
                replace: Vec::new(),
                rename: Vec::new(),
                ilike: None,
                top_level_pure: true,
                enumerated: Vec::new(),
                itemized: Vec::new(),
                complete: false,
                unplaced: 0,
                span: span(),
            })],
            distinct: true,
            distinct_on: Vec::new(),
            hints: Vec::new(),
            node_id: nid(2),
            span: span(),
        };
        let sorted = RelPlan::Sort {
            input: Box::new(project),
            keys: Vec::new(),
            hints: Vec::new(),
            node_id: nid(3),
            span: span(),
        };
        assert!(sorted.has_distinct());
    }

    /// `has_implicit_cross_join` finds comma-join (Cross + implicit).
    #[test]
    fn has_implicit_cross_join_finds_comma_join() {
        let join = RelPlan::Join {
            left: Box::new(scan("a", 1)),
            right: Box::new(scan("b", 2)),
            kind: JoinKind::Cross,
            on: None,
            match_condition: None,
            using: Vec::new(),
            natural: false,
            directed: false,
            lateral: false,
            implicit: true,
            hints: Vec::new(),
            node_id: nid(3),
            span: span(),
            clause_span: span(),
        };
        assert!(join.has_implicit_cross_join());

        let explicit = RelPlan::Join {
            left: Box::new(scan("a", 1)),
            right: Box::new(scan("b", 2)),
            kind: JoinKind::Cross,
            on: None,
            match_condition: None,
            using: Vec::new(),
            natural: false,
            directed: false,
            lateral: false,
            implicit: false,
            hints: Vec::new(),
            node_id: nid(3),
            span: span(),
            clause_span: span(),
        };
        assert!(!explicit.has_implicit_cross_join());
    }

    /// `immediate_join_count` and `immediate_table_count` count
    /// nodes in the immediate scope only.
    #[test]
    fn counts_immediate_only() {
        let join = RelPlan::Join {
            left: Box::new(scan("a", 1)),
            right: Box::new(scan("b", 2)),
            kind: JoinKind::Inner,
            on: None,
            match_condition: None,
            using: Vec::new(),
            natural: false,
            directed: false,
            lateral: false,
            implicit: false,
            hints: Vec::new(),
            node_id: nid(3),
            span: span(),
            clause_span: span(),
        };
        assert_eq!(join.immediate_join_count(), 1);
        assert_eq!(join.immediate_table_count(), 2);
    }
}
