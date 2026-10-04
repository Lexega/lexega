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
//!   bodies / derived tables. Examples: `has_any_filter`,
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

use super::plan::{CteBody, FilterKind, JoinKind, RelPlan};
use super::scalar::ScalarExpr;
use super::visitor::{walk_rel_plan, walk_scalar_expr, RelPlanVisitor};

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

    /// True iff any [`RelPlan::Filter`] (any kind) is present anywhere
    /// in the plan tree, including subqueries, CTE bodies, and
    /// derived-table bodies, OR any [`RelPlan::ModelRef`] whose
    /// upstream `ResolvedModel::has_filter` is `true` (a downstream
    /// reading from a pre-filtered cross-model upstream inherits
    /// the filter for has_filter purposes).
    pub fn has_any_filter(&self) -> bool {
        any_anywhere(self, |p| match p {
            RelPlan::Filter { .. } => true,
            RelPlan::ModelRef { model, .. } => model.has_filter,
            _ => false,
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

    /// `has_where` finds Filter::Where in immediate scope.
    #[test]
    fn has_where_immediate() {
        let plan = RelPlan::Filter {
            input: Box::new(scan("t", 1)),
            predicate: lit_true(),
            kind: FilterKind::Where,
            hints: Vec::new(),
            node_id: nid(2),
            span: span(),
        };
        assert!(plan.has_where());
        assert!(!plan.has_qualify());
        assert!(plan.has_any_filter());
    }

    /// `has_where` does NOT recurse into derived-table bodies.
    #[test]
    fn has_where_does_not_cross_derived_table() {
        let inner_filter = RelPlan::Filter {
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
            hints: Vec::new(),
            node_id: nid(3),
            span: span(),
        };
        assert!(!outer.has_where());
        assert!(outer.has_any_filter());
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
