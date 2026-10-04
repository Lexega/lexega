// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Post-lowering pass that populates `correlates_with` on every
//! subquery node in a [`RelPlan`].
//!
//! ## Why this is a derived property
//!
//! The lowerer emits [`ScalarExpr::ScalarSubquery`],
//! [`ScalarExpr::Exists`], and
//! [`super::scalar::QuantifiedRhs::Subquery`] with
//! `correlates_with: vec![]` as a stub (see `lower.rs`). Name
//! resolution inside a subquery body that hits an enclosing FROM scope
//! returns a [`ScalarExpr::Column`] carrying the outer scope's
//! [`ColumnId`] — *not* a [`ScalarExpr::OuterRef`]. Correlation is
//! therefore not encoded in the expression's tag but is a derived
//! property of the subquery body: a referenced [`ColumnId`] that no
//! node within the subquery's subtree introduces must have come from
//! an enclosing scope.
//!
//! This pass computes that derived property once after lowering and
//! materializes it on each subquery node so downstream consumers
//! (fact extraction, projection-position N+1 rules, etc.) can read
//! `correlates_with` without re-walking the body.
//!
//! ## Algorithm
//!
//! For each subquery node encountered while traversing the plan,
//! recurse into the inner plan first (bottom-up), then compute the
//! subquery's correlation as `referenced(body) \ produced(body)`,
//! where:
//!
//! - `produced(body)` is the union of every node's
//!   [`RelPlan::output_schema`] inside the subquery's subtree
//!   (including nested subqueries' Scans, Projects, Aggregates, etc.).
//! - `referenced(body)` is every [`ColumnId`] referenced via
//!   [`ScalarExpr::Column`], [`ScalarExpr::OuterRef`], or
//!   [`ScalarExpr::PatternVarRef`] anywhere in the subtree (including
//!   inside nested subqueries' scalar expressions).
//!
//! Columns produced inside a nested subquery still count as
//! "produced" by the outer subquery — they cancel against the nested
//! subquery's own internal references, leaving only truly external
//! references (those bound in an enclosing scope) in the difference.
//!
//! ## Closed-enum discipline
//!
//! Uses [`RelPlanMutator`] / [`RelPlanVisitor`] / [`ScalarExprVisitor`]
//! from `super::visitor`, which are themselves closed-enum exhaustive
//! over [`RelPlan`] and [`ScalarExpr`]. A new variant on either enum
//! fails to compile in the visitor module before reaching this pass.

use std::collections::HashSet;

use super::column::ColumnId;
use super::plan::RelPlan;
use super::scalar::ScalarExpr;
use super::visitor::{
    walk_rel_plan, walk_rel_plan_mut, walk_scalar_expr_standalone, RelPlanMutator, RelPlanVisitor,
    ScalarExprVisitor,
};

/// Public entry point. Walks `plan` and fills `correlates_with` on
/// every subquery node in place.
pub(crate) fn populate_subquery_correlates(
    plan: &mut RelPlan,
    bindings: &super::column::BindingTable,
) {
    // Pre-collect, for every CTE binding, the closure of source-node
    // NodeIds (`Scan`, `CteRef`, `DerivedTable`, `ModelRef`,
    // `TableFunction`, `Values`) reachable through that CTE's body.
    // This is needed because the lowerer redirects column
    // allocations on unresolved-star CTE references to the CTE
    // body's leaf-scan NodeId (see `lower.rs::register_from_source`
    // / `cte_passthrough_renames`). Without walking through the CTE
    // body, a subquery that references a CTE whose body contains
    // `FROM raw.t` would mis-classify columns rooted at `raw.t` as
    // correlated — they're "local" in the sense that the subquery's
    // own FROM-clause reaches them.
    //
    // Precomputed as `Vec<NodeId>` (owned data) rather than `&RelPlan`
    // borrows so the mutable walk below can take `&mut plan` without
    // borrow-checker conflicts.
    let cte_source_closure = precompute_cte_source_closure(plan);
    let mut m = CorrelationPopulator {
        bindings,
        cte_source_closure: &cte_source_closure,
    };
    m.visit_rel_plan_mut(plan);
}

/// Build, for every CTE binding's `ScopeId`, the transitive closure
/// of source-node NodeIds reachable from the CTE body (including
/// through nested CteRef references inside the body). Owned data so
/// the caller can mutate the plan afterward.
fn precompute_cte_source_closure(
    plan: &RelPlan,
) -> std::collections::BTreeMap<super::scalar::ScopeId, HashSet<crate::ast::NodeId>> {
    // Phase 1: scope → CTE body reference.
    let mut bodies: std::collections::BTreeMap<super::scalar::ScopeId, &RelPlan> =
        std::collections::BTreeMap::new();
    walk_for_cte_bodies(plan, &mut bodies);

    // Phase 2: for each CTE body, compute the source-node closure
    // (following CteRef into other CTEs' bodies recursively).
    let mut out: std::collections::BTreeMap<super::scalar::ScopeId, HashSet<crate::ast::NodeId>> =
        std::collections::BTreeMap::new();
    for (scope, body) in bodies.iter() {
        let mut nodes: HashSet<crate::ast::NodeId> = HashSet::new();
        let mut visited: HashSet<super::scalar::ScopeId> = HashSet::new();
        visited.insert(*scope);
        walk_source_nodes(body, &bodies, &mut nodes, &mut visited);
        out.insert(*scope, nodes);
    }
    out
}

fn walk_source_nodes<'a>(
    plan: &'a RelPlan,
    bodies: &std::collections::BTreeMap<super::scalar::ScopeId, &'a RelPlan>,
    out: &mut HashSet<crate::ast::NodeId>,
    visited: &mut HashSet<super::scalar::ScopeId>,
) {
    match plan {
        RelPlan::Scan { node_id, .. }
        | RelPlan::ModelRef { node_id, .. }
        | RelPlan::TableFunction { node_id, .. }
        | RelPlan::Values { node_id, .. } => {
            out.insert(*node_id);
        }
        RelPlan::CteRef { node_id, scope, .. } => {
            out.insert(*node_id);
            if visited.insert(*scope) {
                if let Some(b) = bodies.get(scope) {
                    walk_source_nodes(b, bodies, out, visited);
                }
            }
        }
        RelPlan::DerivedTable { node_id, input, .. } => {
            out.insert(*node_id);
            walk_source_nodes(input, bodies, out, visited);
        }
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
        | RelPlan::TableSample { input, .. } => {
            walk_source_nodes(input, bodies, out, visited);
        }
        RelPlan::Join { left, right, .. } => {
            walk_source_nodes(left, bodies, out, visited);
            walk_source_nodes(right, bodies, out, visited);
        }
        RelPlan::SetOp { inputs, .. } => {
            for inp in inputs {
                walk_source_nodes(inp, bodies, out, visited);
            }
        }
        RelPlan::WithScope { ctes, body, .. } => {
            for cte in ctes {
                let body_plan: &RelPlan = match &cte.body {
                    super::plan::CteBody::NonRecursive(b) => b,
                    super::plan::CteBody::Recursive { anchor, .. } => anchor,
                };
                walk_source_nodes(body_plan, bodies, out, visited);
            }
            walk_source_nodes(body, bodies, out, visited);
        }
        RelPlan::Insert { source, .. } => match source {
            super::plan::InsertSource::Values(p) | super::plan::InsertSource::Query(p) => {
                walk_source_nodes(p, bodies, out, visited)
            }
            super::plan::InsertSource::DefaultValues => {}
        },
        RelPlan::Update { from, .. } => {
            if let Some(f) = from {
                walk_source_nodes(f, bodies, out, visited);
            }
        }
        RelPlan::Delete { using, .. } => {
            if let Some(u) = using {
                walk_source_nodes(u, bodies, out, visited);
            }
        }
        RelPlan::Merge { source, .. } => walk_source_nodes(source, bodies, out, visited),
        RelPlan::MultiInsert { source, .. } => walk_source_nodes(source, bodies, out, visited),
        RelPlan::Explain { body, .. } => walk_source_nodes(body, bodies, out, visited),
        RelPlan::CreateAsQuery { body, .. } => {
            if let Some(b) = body {
                walk_source_nodes(b, bodies, out, visited);
            }
        }
        RelPlan::InvalidInput { .. }
        | RelPlan::ParseRecovery { .. }
        | RelPlan::CreateTableForm { .. }
        | RelPlan::Opaque { .. } => {}
    }
}

fn walk_for_cte_bodies<'a>(
    plan: &'a RelPlan,
    out: &mut std::collections::BTreeMap<super::scalar::ScopeId, &'a RelPlan>,
) {
    match plan {
        RelPlan::WithScope { ctes, body, .. } => {
            for cte in ctes {
                let body_plan: &RelPlan = match &cte.body {
                    super::plan::CteBody::NonRecursive(b) => b,
                    super::plan::CteBody::Recursive { anchor, .. } => anchor,
                };
                out.insert(cte.scope, body_plan);
                walk_for_cte_bodies(body_plan, out);
            }
            walk_for_cte_bodies(body, out);
        }
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
        | RelPlan::DerivedTable { input, .. } => walk_for_cte_bodies(input, out),
        RelPlan::Join { left, right, .. } => {
            walk_for_cte_bodies(left, out);
            walk_for_cte_bodies(right, out);
        }
        RelPlan::SetOp { inputs, .. } => {
            for inp in inputs {
                walk_for_cte_bodies(inp, out);
            }
        }
        RelPlan::Insert { source, .. } => match source {
            super::plan::InsertSource::Values(p) | super::plan::InsertSource::Query(p) => {
                walk_for_cte_bodies(p, out)
            }
            super::plan::InsertSource::DefaultValues => {}
        },
        RelPlan::Update { from, .. } => {
            if let Some(f) = from {
                walk_for_cte_bodies(f, out);
            }
        }
        RelPlan::Delete { using, .. } => {
            if let Some(u) = using {
                walk_for_cte_bodies(u, out);
            }
        }
        RelPlan::Merge { source, .. } => walk_for_cte_bodies(source, out),
        RelPlan::MultiInsert { source, .. } => walk_for_cte_bodies(source, out),
        RelPlan::Explain { body, .. } => walk_for_cte_bodies(body, out),
        RelPlan::CreateAsQuery { body, .. } => {
            if let Some(b) = body {
                walk_for_cte_bodies(b, out);
            }
        }
        RelPlan::Scan { .. }
        | RelPlan::Values { .. }
        | RelPlan::CteRef { .. }
        | RelPlan::ModelRef { .. }
        | RelPlan::TableFunction { .. }
        | RelPlan::InvalidInput { .. }
        | RelPlan::ParseRecovery { .. }
        | RelPlan::CreateTableForm { .. }
        | RelPlan::Opaque { .. } => {}
    }
}

struct CorrelationPopulator<'a> {
    bindings: &'a super::column::BindingTable,
    cte_source_closure:
        &'a std::collections::BTreeMap<super::scalar::ScopeId, HashSet<crate::ast::NodeId>>,
}

impl<'a> RelPlanMutator for CorrelationPopulator<'a> {
    fn visit_subquery_mut(&mut self, plan: &mut RelPlan, correlates_with: &mut Vec<ColumnId>) {
        // Recurse first so nested subqueries are populated bottom-up.
        // (The actual correlation calculation below is independent of
        // nested `correlates_with` values, so the order is only a
        // matter of debugging clarity, not correctness.)
        walk_rel_plan_mut(self, plan);
        *correlates_with = compute_correlation(plan, self.bindings, self.cte_source_closure);
    }
}

fn compute_correlation(
    body: &RelPlan,
    bindings: &super::column::BindingTable,
    cte_source_closure: &std::collections::BTreeMap<
        super::scalar::ScopeId,
        HashSet<crate::ast::NodeId>,
    >,
) -> Vec<ColumnId> {
    let mut produced: HashSet<ColumnId> = HashSet::new();
    let mut produced_collector = ProducedColumns { out: &mut produced };
    produced_collector.visit_rel_plan(body);

    // Also collect the NodeIds of every source node (`Scan`,
    // `CteRef`, `DerivedTable`, `ModelRef`, `TableFunction`, `Values`)
    // inside the body. A `ColumnOrigin::Table { table_node }` whose
    // `table_node` is in this set is locally produced — even when
    // the source's `columns` Vec doesn't enumerate it (which happens
    // for catalog-unresolved `SELECT *` CteRef bodies, where
    // `CteRef.columns` stays empty but the lowerer still allocates
    // fresh Table-origin ColumnIds against the CteRef's NodeId for
    // each column reference).
    //
    // Crucially, this collection follows `CteRef.scope` into the CTE
    // bodies the subquery references — the lowerer's `leaf_scan_node`
    // redirect (see `lower.rs::register_from_source` for
    // unresolved-star CTE refs) routes column allocations to the CTE
    // body's underlying scan node, not the CteRef's own NodeId.
    // Without walking through, those `Table { table_node: <leaf_scan> }`
    // columns appear non-local, producing a category-wide FP on
    // `Q-SUBQ-CORR-SEL` / `Q-SUBQ-CORR-WHERE` for uncorrelated
    // scalar subqueries over CTE-resolved tables.
    let mut local_source_nodes: HashSet<crate::ast::NodeId> = HashSet::new();
    collect_local_source_nodes(body, cte_source_closure, &mut local_source_nodes);

    let mut referenced: HashSet<ColumnId> = HashSet::new();
    let mut ref_collector = ReferencedColumns {
        out: &mut referenced,
    };
    ref_collector.visit_rel_plan(body);

    let mut diff: Vec<ColumnId> = referenced
        .iter()
        .copied()
        .filter(|c| {
            if produced.contains(c) {
                return false;
            }
            // Table-origin column allocated against a local source
            // node — locally produced even if not in the source's
            // `columns` Vec.
            if let Some(binding) = bindings.get(*c) {
                if let super::column::ColumnOrigin::Table { table_node, .. } = &binding.origin {
                    if local_source_nodes.contains(table_node) {
                        return false;
                    }
                }
            }
            true
        })
        .collect();
    diff.sort_by_key(|c| c.as_u32());
    diff
}

/// Recursively collect the NodeIds of every source-position node
/// (`Scan`, `CteRef`, `DerivedTable`, `ModelRef`, `TableFunction`,
/// `Values`) reachable from `plan` through clause-level wrappers,
/// joins, set-ops, DML sources, AND through `CteRef.scope` lookups
/// into CTE bodies in `cte_bodies`. Nested subqueries are NOT
/// traversed — they're their own scope.
fn collect_local_source_nodes(
    plan: &RelPlan,
    cte_source_closure: &std::collections::BTreeMap<
        super::scalar::ScopeId,
        HashSet<crate::ast::NodeId>,
    >,
    out: &mut HashSet<crate::ast::NodeId>,
) {
    match plan {
        RelPlan::Scan { node_id, .. }
        | RelPlan::ModelRef { node_id, .. }
        | RelPlan::TableFunction { node_id, .. }
        | RelPlan::Values { node_id, .. } => {
            out.insert(*node_id);
        }
        RelPlan::CteRef { node_id, scope, .. } => {
            out.insert(*node_id);
            // Union the CTE body's precomputed source-node closure
            // so columns the lowerer redirected to the body's leaf
            // scan node are recognized as local.
            if let Some(extra) = cte_source_closure.get(scope) {
                for n in extra {
                    out.insert(*n);
                }
            }
        }
        RelPlan::DerivedTable { node_id, input, .. } => {
            out.insert(*node_id);
            collect_local_source_nodes(input, cte_source_closure, out);
        }
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
        | RelPlan::TableSample { input, .. } => {
            collect_local_source_nodes(input, cte_source_closure, out);
        }
        RelPlan::Join { left, right, .. } => {
            collect_local_source_nodes(left, cte_source_closure, out);
            collect_local_source_nodes(right, cte_source_closure, out);
        }
        RelPlan::SetOp { inputs, .. } => {
            for inp in inputs {
                collect_local_source_nodes(inp, cte_source_closure, out);
            }
        }
        RelPlan::WithScope { ctes, body, .. } => {
            for cte in ctes {
                let body_plan: &RelPlan = match &cte.body {
                    super::plan::CteBody::NonRecursive(b) => b,
                    super::plan::CteBody::Recursive { anchor, .. } => anchor,
                };
                collect_local_source_nodes(body_plan, cte_source_closure, out);
            }
            collect_local_source_nodes(body, cte_source_closure, out);
        }
        RelPlan::Insert { source, .. } => match source {
            super::plan::InsertSource::Values(p) | super::plan::InsertSource::Query(p) => {
                collect_local_source_nodes(p, cte_source_closure, out)
            }
            super::plan::InsertSource::DefaultValues => {}
        },
        RelPlan::Update { from, .. } => {
            if let Some(f) = from {
                collect_local_source_nodes(f, cte_source_closure, out);
            }
        }
        RelPlan::Delete { using, .. } => {
            if let Some(u) = using {
                collect_local_source_nodes(u, cte_source_closure, out);
            }
        }
        RelPlan::Merge { source, .. } => {
            collect_local_source_nodes(source, cte_source_closure, out)
        }
        RelPlan::MultiInsert { source, .. } => {
            collect_local_source_nodes(source, cte_source_closure, out)
        }
        RelPlan::Explain { body, .. } => collect_local_source_nodes(body, cte_source_closure, out),
        RelPlan::CreateAsQuery { body, .. } => {
            if let Some(b) = body {
                collect_local_source_nodes(b, cte_source_closure, out);
            }
        }
        RelPlan::InvalidInput { .. }
        | RelPlan::ParseRecovery { .. }
        | RelPlan::CreateTableForm { .. }
        | RelPlan::Opaque { .. } => {}
    }
}

/// Collects every [`ColumnId`] introduced anywhere in the subtree by
/// taking the union of every node's [`RelPlan::output_schema`]. Walks
/// into nested subqueries so their internally-bound scan columns are
/// included.
struct ProducedColumns<'a> {
    out: &'a mut HashSet<ColumnId>,
}

impl<'a, 'p> RelPlanVisitor<'p> for ProducedColumns<'a> {
    fn visit_rel_plan(&mut self, plan: &'p RelPlan) {
        for c in plan.output_schema() {
            self.out.insert(c);
        }
        walk_rel_plan(self, plan);
    }
}

/// Collects every [`ColumnId`] referenced by a scalar expression
/// anywhere in the subtree. Walks into nested subqueries' scalar
/// expressions so transitively-correlated references are visible to
/// the enclosing subquery's correlation calculation.
struct ReferencedColumns<'a> {
    out: &'a mut HashSet<ColumnId>,
}

impl<'a, 'p> RelPlanVisitor<'p> for ReferencedColumns<'a> {
    fn visit_scalar_expr(&mut self, expr: &'p ScalarExpr) {
        match expr {
            ScalarExpr::Column { column, .. }
            | ScalarExpr::OuterRef { column, .. }
            | ScalarExpr::PatternVarRef { column, .. } => {
                self.out.insert(*column);
            }
            _ => {}
        }
        // Walk children: scalar substructure plus any nested subquery
        // plans (which route through `visit_subquery` below).
        let mut bridge = ScalarRefBridge { out: self.out };
        walk_scalar_expr_standalone(&mut bridge, expr);
    }

    fn visit_subquery(&mut self, plan: &'p RelPlan, _correlates_with: &'p [ColumnId]) {
        self.visit_rel_plan(plan);
    }
}

/// Bridge visitor that walks the scalar substructure for
/// [`ReferencedColumns`]. The plan-attached `RelPlanVisitor` routes
/// nested subquery plans through `visit_subquery`; this standalone
/// scalar walker handles the per-expression children below the
/// subquery boundary so the bridge needs to forward subquery hops
/// back to the same column collector by recursing into the inner
/// plan.
struct ScalarRefBridge<'a> {
    out: &'a mut HashSet<ColumnId>,
}

impl<'a, 'p> ScalarExprVisitor<'p> for ScalarRefBridge<'a> {
    fn visit_scalar_expr(&mut self, expr: &'p ScalarExpr) {
        match expr {
            ScalarExpr::Column { column, .. }
            | ScalarExpr::OuterRef { column, .. }
            | ScalarExpr::PatternVarRef { column, .. } => {
                self.out.insert(*column);
            }
            _ => {}
        }
        super::visitor::walk_scalar_expr_standalone(self, expr);
    }

    fn visit_scalar_subquery(&mut self, plan: &'p RelPlan, _correlates_with: &'p [ColumnId]) {
        // Recurse into the nested subquery's plan so any
        // outer-bound column references inside it are still
        // collected at the enclosing-subquery's correlation
        // computation level.
        let mut v = ReferencedColumns { out: self.out };
        v.visit_rel_plan(plan);
    }
}

// ────────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::NodeId;
    use crate::context::node_metadata::TableRef;
    use crate::ir::column::ColumnIdAllocator;
    use crate::ir::plan::{
        AggregateCall, FilterKind, GroupingSpec, NullTreatment, ProjectExpr, ProjectItem,
        ResolvedFunc, ScanModifier,
    };
    use crate::ir::scalar::{Lit, ScalarExpr};
    use crate::lexer::Span;

    fn sp() -> Span {
        Span { start: 0, end: 0 }
    }
    fn nid() -> NodeId {
        NodeId::new(0)
    }

    fn scan(name: &str, columns: Vec<ColumnId>) -> RelPlan {
        RelPlan::Scan {
            table: TableRef::new(name.to_string()),
            columns,
            modifier: ScanModifier::default(),
            alias: None,
            node_id: nid(),
            span: sp(),
            hints: Vec::new(),
        }
    }

    /// `SELECT a FROM t WHERE (SELECT 1 FROM u WHERE u.x = t.a)`
    ///
    /// The scalar subquery references `t.a` (outer column) from its
    /// WHERE predicate. The pass should populate
    /// `correlates_with: [t_a]`.
    #[test]
    fn scalar_subquery_picks_up_outer_column() {
        let mut alloc = ColumnIdAllocator::new();
        let t_a = alloc.fresh_test();
        let u_x = alloc.fresh_test();
        let sub_out = alloc.fresh_test();

        // Subquery body: SELECT 1 FROM u WHERE u.x = t.a
        let sub_body = RelPlan::Project {
            input: Box::new(RelPlan::Filter {
                input: Box::new(scan("u", vec![u_x])),
                predicate: ScalarExpr::BinOp {
                    op: crate::ir::scalar::BinOpKind::Cmp(crate::ir::scalar::ComparisonOp::Eq),
                    left: Box::new(ScalarExpr::Column {
                        column: u_x,
                        span: sp(),
                    }),
                    right: Box::new(ScalarExpr::Column {
                        column: t_a,
                        span: sp(),
                    }),
                    span: sp(),
                },
                kind: FilterKind::Where,
                node_id: nid(),
                span: sp(),
                hints: Vec::new(),
            }),
            items: vec![ProjectItem::Expr(ProjectExpr {
                output: sub_out,
                expr: ScalarExpr::Lit {
                    value: Lit::Integer("1".into()),
                    span: sp(),
                },
                alias: None,
                span: sp(),
            })],
            distinct: false,
            distinct_on: Vec::new(),
            node_id: nid(),
            span: sp(),
            hints: Vec::new(),
        };

        // Outer: SELECT a FROM t WHERE (...)
        let outer_out = alloc.fresh_test();
        let mut outer = RelPlan::Project {
            input: Box::new(RelPlan::Filter {
                input: Box::new(scan("t", vec![t_a])),
                predicate: ScalarExpr::ScalarSubquery {
                    subquery: Box::new(sub_body),
                    correlates_with: vec![],
                    span: sp(),
                },
                kind: FilterKind::Where,
                node_id: nid(),
                span: sp(),
                hints: Vec::new(),
            }),
            items: vec![ProjectItem::Expr(ProjectExpr {
                output: outer_out,
                expr: ScalarExpr::Column {
                    column: t_a,
                    span: sp(),
                },
                alias: None,
                span: sp(),
            })],
            distinct: false,
            distinct_on: Vec::new(),
            node_id: nid(),
            span: sp(),
            hints: Vec::new(),
        };

        populate_subquery_correlates(&mut outer, &super::super::column::BindingTable::new());

        let correlation = find_first_scalar_subquery_correlates(&outer);
        assert_eq!(correlation, vec![t_a]);
    }

    /// Subquery that references only its own scan columns must have
    /// empty `correlates_with`.
    #[test]
    fn uncorrelated_subquery_stays_empty() {
        let mut alloc = ColumnIdAllocator::new();
        let u_x = alloc.fresh_test();
        let sub_out = alloc.fresh_test();

        let sub_body = RelPlan::Project {
            input: Box::new(scan("u", vec![u_x])),
            items: vec![ProjectItem::Expr(ProjectExpr {
                output: sub_out,
                expr: ScalarExpr::Column {
                    column: u_x,
                    span: sp(),
                },
                alias: None,
                span: sp(),
            })],
            distinct: false,
            distinct_on: Vec::new(),
            node_id: nid(),
            span: sp(),
            hints: Vec::new(),
        };

        let mut outer = RelPlan::Filter {
            input: Box::new(scan("t", vec![alloc.fresh_test()])),
            predicate: ScalarExpr::ScalarSubquery {
                subquery: Box::new(sub_body),
                correlates_with: vec![],
                span: sp(),
            },
            kind: FilterKind::Where,
            node_id: nid(),
            span: sp(),
            hints: Vec::new(),
        };

        populate_subquery_correlates(&mut outer, &super::super::column::BindingTable::new());

        let correlation = find_first_scalar_subquery_correlates(&outer);
        assert!(
            correlation.is_empty(),
            "uncorrelated subquery should have empty correlates_with, got {:?}",
            correlation
        );
    }

    /// Subquery body uses an aggregate (`MAX(login_time)`) and a
    /// correlated WHERE predicate — mirrors the test_complex_rule_scenarios
    /// `enriched` CTE's last_login subquery shape.
    #[test]
    fn correlated_aggregate_subquery_populates_outer_ref() {
        let mut alloc = ColumnIdAllocator::new();
        let s_user_id = alloc.fresh_test(); // outer
        let sess_user_id = alloc.fresh_test(); // inner scan
        let login_time = alloc.fresh_test(); // inner scan
        let max_login = alloc.fresh_test(); // aggregate output

        // SELECT MAX(login_time) FROM sessions WHERE sess.user_id = s.user_id
        let sub_body = RelPlan::Aggregate {
            input: Box::new(RelPlan::Filter {
                input: Box::new(scan("sessions", vec![sess_user_id, login_time])),
                predicate: ScalarExpr::BinOp {
                    op: crate::ir::scalar::BinOpKind::Cmp(crate::ir::scalar::ComparisonOp::Eq),
                    left: Box::new(ScalarExpr::Column {
                        column: sess_user_id,
                        span: sp(),
                    }),
                    right: Box::new(ScalarExpr::Column {
                        column: s_user_id,
                        span: sp(),
                    }),
                    span: sp(),
                },
                kind: FilterKind::Where,
                node_id: nid(),
                span: sp(),
                hints: Vec::new(),
            }),
            grouping: GroupingSpec::None,
            aggregates: vec![AggregateCall {
                func: ResolvedFunc::unresolved("MAX", None, sp()),
                args: vec![ScalarExpr::Column {
                    column: login_time,
                    span: sp(),
                }],
                named_args: Vec::new(),
                distinct: false,
                approximate: false,
                filter: None,
                arg_order: Vec::new(),
                within_group_order: Vec::new(),
                output: max_login,
                null_treatment: NullTreatment::Default,
                span: sp(),
            }],
            having: None,
            output_columns: vec![max_login],
            hints: Vec::new(),
            node_id: nid(),
            span: sp(),
        };

        let mut outer = RelPlan::Filter {
            input: Box::new(scan("users", vec![s_user_id])),
            predicate: ScalarExpr::ScalarSubquery {
                subquery: Box::new(sub_body),
                correlates_with: vec![],
                span: sp(),
            },
            kind: FilterKind::Where,
            node_id: nid(),
            span: sp(),
            hints: Vec::new(),
        };

        populate_subquery_correlates(&mut outer, &super::super::column::BindingTable::new());

        let correlation = find_first_scalar_subquery_correlates(&outer);
        assert_eq!(correlation, vec![s_user_id]);
    }

    /// Helper: dig the first encountered ScalarSubquery's
    /// `correlates_with` out of a populated plan.
    fn find_first_scalar_subquery_correlates(plan: &RelPlan) -> Vec<ColumnId> {
        struct Finder {
            found: Option<Vec<ColumnId>>,
        }
        impl<'p> RelPlanVisitor<'p> for Finder {
            fn visit_scalar_expr(&mut self, expr: &'p ScalarExpr) {
                if self.found.is_some() {
                    return;
                }
                if let ScalarExpr::ScalarSubquery {
                    correlates_with, ..
                } = expr
                {
                    self.found = Some(correlates_with.clone());
                    return;
                }
                walk_scalar_expr_standalone(
                    &mut FinderScalar {
                        found: &mut self.found,
                    },
                    expr,
                );
            }
        }
        struct FinderScalar<'a> {
            found: &'a mut Option<Vec<ColumnId>>,
        }
        impl<'a, 'p> ScalarExprVisitor<'p> for FinderScalar<'a> {
            fn visit_scalar_expr(&mut self, expr: &'p ScalarExpr) {
                if self.found.is_some() {
                    return;
                }
                if let ScalarExpr::ScalarSubquery {
                    correlates_with, ..
                } = expr
                {
                    *self.found = Some(correlates_with.clone());
                    return;
                }
                super::super::visitor::walk_scalar_expr_standalone(self, expr);
            }
        }
        let mut f = Finder { found: None };
        f.visit_rel_plan(plan);
        f.found.unwrap_or_default()
    }
}
