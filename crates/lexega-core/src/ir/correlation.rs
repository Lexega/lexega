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
//! `correlates_with: vec![]` as a stub (see `lower.rs`). Correlation is
//! a derived property of the subquery body: a referenced [`ColumnId`]
//! that no node within the subquery's subtree introduces must have come
//! from an enclosing scope. A column of no source
//! ([`super::column::ColumnOrigin::Unattributed`]) is introduced by no
//! node, so the body states where it comes from: it is an enclosing
//! scope's where the body reads it through a [`ScalarExpr::OuterRef`]
//! whose scope reaches past the body.
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
//! A column of no source stays in it only where an outer reference to
//! it has a scope greater than the number of nested blocks between the
//! body's root and the reference: the blocks lowering counts, which are
//! subqueries, derived tables, CTE bodies, an `INSERT`'s query and a
//! pivot's `IN` subquery.
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
    walk_rel_plan, walk_rel_plan_mut, walk_scalar_expr, walk_scalar_expr_standalone,
    RelPlanMutator, RelPlanVisitor, ScalarExprVisitor,
};

/// Public entry point. Walks `plan` and fills `correlates_with` on
/// every subquery node in place.
pub(crate) fn populate_subquery_correlates(
    plan: &mut RelPlan,
    bindings: &super::column::BindingTable,
) {
    // Pre-collect, for every CTE binding, the source-node NodeIds
    // (`Scan`, `CteRef`, `DerivedTable`, `ModelRef`, `TableFunction`,
    // `Values`) its body reaches, and the bindings it refers to: a
    // table column of a source inside a CTE body the subquery's own
    // FROM clause reaches is local to the subquery, not correlated.
    //
    // Owned data rather than `&RelPlan` borrows so the mutable walk
    // below can take `&mut plan`.
    let cte_sources = precompute_cte_sources(plan);
    let mut m = CorrelationPopulator {
        bindings,
        cte_sources: &cte_sources,
    };
    m.visit_rel_plan_mut(plan);
}

/// What one CTE body reaches without following its references.
#[derive(Default)]
struct BodySources {
    /// The source nodes of its own FROM clauses.
    nodes: Vec<crate::ast::NodeId>,
    /// The bindings its `CteRef`s name.
    refers_to: Vec<super::scalar::ScopeId>,
}

type CteSources = std::collections::BTreeMap<super::scalar::ScopeId, BodySources>;

/// Build, for every CTE binding's `ScopeId`, the source nodes its body
/// reaches and the bindings it refers to: each body is walked once,
/// and what a reference reaches is followed when a subquery asks.
fn precompute_cte_sources(plan: &RelPlan) -> CteSources {
    let mut bodies: std::collections::BTreeMap<super::scalar::ScopeId, &RelPlan> =
        std::collections::BTreeMap::new();
    walk_for_cte_bodies(plan, &mut bodies);
    bodies
        .into_iter()
        .map(|(scope, body)| {
            let mut sources = BodySources::default();
            walk_source_nodes(body, &mut sources);
            (scope, sources)
        })
        .collect()
}

/// Adds to `out` the source nodes the body of `scope` reaches, and
/// those of every body it refers to, transitively. `followed` holds the
/// bindings already followed; none is followed twice.
fn reach_cte_sources(
    scope: super::scalar::ScopeId,
    cte_sources: &CteSources,
    followed: &mut HashSet<super::scalar::ScopeId>,
    out: &mut HashSet<crate::ast::NodeId>,
) {
    if !cte_sources.contains_key(&scope) || !followed.insert(scope) {
        return;
    }
    let mut pending = vec![scope];
    while let Some(next) = pending.pop() {
        let Some(sources) = cte_sources.get(&next) else {
            continue;
        };
        out.extend(sources.nodes.iter().copied());
        pending.extend(
            sources
                .refers_to
                .iter()
                .copied()
                .filter(|refers_to| followed.insert(*refers_to)),
        );
    }
}

fn walk_source_nodes(plan: &RelPlan, out: &mut BodySources) {
    match plan {
        RelPlan::Scan { node_id, .. }
        | RelPlan::ModelRef { node_id, .. }
        | RelPlan::TableFunction { node_id, .. }
        | RelPlan::Values { node_id, .. } => {
            out.nodes.push(*node_id);
        }
        RelPlan::CteRef { node_id, scope, .. } => {
            out.nodes.push(*node_id);
            out.refers_to.push(*scope);
        }
        RelPlan::DerivedTable { node_id, input, .. } => {
            out.nodes.push(*node_id);
            walk_source_nodes(input, out);
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
            walk_source_nodes(input, out);
        }
        RelPlan::Join { left, right, .. } => {
            walk_source_nodes(left, out);
            walk_source_nodes(right, out);
        }
        RelPlan::SetOp { inputs, .. } => {
            for inp in inputs {
                walk_source_nodes(inp, out);
            }
        }
        RelPlan::WithScope { ctes, body, .. } => {
            for cte in ctes {
                let body_plan: &RelPlan = match &cte.body {
                    super::plan::CteBody::NonRecursive(b) => b,
                    super::plan::CteBody::Recursive { anchor, .. } => anchor,
                };
                walk_source_nodes(body_plan, out);
            }
            walk_source_nodes(body, out);
        }
        RelPlan::Insert { source, .. } => match source {
            super::plan::InsertSource::Values(p) | super::plan::InsertSource::Query(p) => {
                walk_source_nodes(p, out)
            }
            super::plan::InsertSource::DefaultValues => {}
        },
        RelPlan::Update { from, .. } => {
            if let Some(f) = from {
                walk_source_nodes(f, out);
            }
        }
        RelPlan::Delete { using, .. } => {
            if let Some(u) = using {
                walk_source_nodes(u, out);
            }
        }
        RelPlan::Merge { source, .. } => walk_source_nodes(source, out),
        RelPlan::MultiInsert { source, .. } => walk_source_nodes(source, out),
        RelPlan::Explain { body, .. } => walk_source_nodes(body, out),
        RelPlan::CreateAsQuery { body, .. } => {
            if let Some(b) = body {
                walk_source_nodes(b, out);
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
    cte_sources: &'a CteSources,
}

impl<'a> RelPlanMutator for CorrelationPopulator<'a> {
    fn visit_subquery_mut(&mut self, plan: &mut RelPlan, correlates_with: &mut Vec<ColumnId>) {
        // Recurse first so nested subqueries are populated bottom-up.
        // (The actual correlation calculation below is independent of
        // nested `correlates_with` values, so the order is only a
        // matter of debugging clarity, not correctness.)
        walk_rel_plan_mut(self, plan);
        *correlates_with = compute_correlation(plan, self.bindings, self.cte_sources);
    }
}

fn compute_correlation(
    body: &RelPlan,
    bindings: &super::column::BindingTable,
    cte_sources: &CteSources,
) -> Vec<ColumnId> {
    let produced = produced_columns(body);

    // Also collect the NodeIds of every source node (`Scan`,
    // `CteRef`, `DerivedTable`, `ModelRef`, `TableFunction`, `Values`)
    // inside the body, following `CteRef.scope` into the CTE bodies
    // the subquery references. A `ColumnOrigin::Table { table_node }`
    // whose `table_node` is in this set is locally produced even when
    // no node of the subquery lists it. A column read through a
    // `CteRef` is the reference's own and is listed in its output
    // schema, so `produced` already holds it.
    let mut local_source_nodes: HashSet<crate::ast::NodeId> = HashSet::new();
    collect_local_source_nodes(
        body,
        cte_sources,
        &mut HashSet::new(),
        &mut local_source_nodes,
    );

    let mut referenced: HashSet<ColumnId> = HashSet::new();
    let mut ref_collector = ReferencedColumns {
        out: &mut referenced,
    };
    ref_collector.visit_rel_plan(body);

    let mut stated = StatedOuterReferences::default();
    stated.visit_rel_plan(body);

    let mut diff: Vec<ColumnId> = referenced
        .iter()
        .copied()
        .filter(|c| {
            if produced.contains(c) {
                return false;
            }
            match bindings.get(*c).map(|binding| &binding.origin) {
                // Table-origin column allocated against a local source
                // node — locally produced even if not in the source's
                // `columns` Vec.
                Some(super::column::ColumnOrigin::Table { table_node, .. }) => {
                    !local_source_nodes.contains(table_node)
                }
                // A column of no source is produced by no node: it is
                // outer where an outer reference to it leaves the body.
                Some(super::column::ColumnOrigin::Unattributed { .. }) => stated.outer.contains(c),
                Some(
                    super::column::ColumnOrigin::Computed { .. }
                    | super::column::ColumnOrigin::Merged { .. }
                    | super::column::ColumnOrigin::SetOp { .. }
                    | super::column::ColumnOrigin::OuterRef { .. }
                    | super::column::ColumnOrigin::RecursiveRef { .. },
                )
                | None => true,
            }
        })
        .collect();
    diff.sort_by_key(|c| c.as_u32());
    diff
}

/// Every column a node of `plan` introduces, its nested subqueries'
/// included.
pub(crate) fn produced_columns(plan: &RelPlan) -> HashSet<ColumnId> {
    let mut out = HashSet::new();
    ProducedColumns {
        out: &mut out,
        skipped: None,
    }
    .visit_rel_plan(plan);
    out
}

/// As [`produced_columns`], the nodes of `skipped`, a subtree of `plan`,
/// aside.
pub(crate) fn produced_columns_except(plan: &RelPlan, skipped: &RelPlan) -> HashSet<ColumnId> {
    let mut out = HashSet::new();
    ProducedColumns {
        out: &mut out,
        skipped: Some(skipped),
    }
    .visit_rel_plan(plan);
    out
}

/// Every column `plan` reads, in its expressions and its nested
/// subqueries'.
pub(crate) fn plan_referenced_columns(plan: &RelPlan) -> HashSet<ColumnId> {
    let mut out = HashSet::new();
    ReferencedColumns { out: &mut out }.visit_rel_plan(plan);
    out
}

/// Every column `expr` reads, in its nested subqueries too.
pub(crate) fn expr_referenced_columns(expr: &ScalarExpr) -> HashSet<ColumnId> {
    let mut out = HashSet::new();
    ScalarRefBridge { out: &mut out }.visit_scalar_expr(expr);
    out
}

/// The NodeIds of every source-position node of `plan` (not of its
/// nested subqueries, nor inside the CTE bodies its `CteRef`s name).
pub(crate) fn source_nodes(plan: &RelPlan) -> HashSet<crate::ast::NodeId> {
    let mut out = HashSet::new();
    collect_local_source_nodes(plan, &CteSources::new(), &mut HashSet::new(), &mut out);
    out
}

/// Recursively collect the NodeIds of every source-position node
/// (`Scan`, `CteRef`, `DerivedTable`, `ModelRef`, `TableFunction`,
/// `Values`) reachable from `plan` through clause-level wrappers,
/// joins, set-ops, DML sources, AND through `CteRef.scope` lookups
/// into the CTE bodies `cte_sources` describes, each followed once
/// (`followed`). Nested subqueries are NOT traversed — they're their
/// own scope.
fn collect_local_source_nodes(
    plan: &RelPlan,
    cte_sources: &CteSources,
    followed: &mut HashSet<super::scalar::ScopeId>,
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
            // Table columns of the sources the CTE body reaches count
            // as local.
            reach_cte_sources(*scope, cte_sources, followed, out);
        }
        RelPlan::DerivedTable { node_id, input, .. } => {
            out.insert(*node_id);
            collect_local_source_nodes(input, cte_sources, followed, out);
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
            collect_local_source_nodes(input, cte_sources, followed, out);
        }
        RelPlan::Join { left, right, .. } => {
            collect_local_source_nodes(left, cte_sources, followed, out);
            collect_local_source_nodes(right, cte_sources, followed, out);
        }
        RelPlan::SetOp { inputs, .. } => {
            for inp in inputs {
                collect_local_source_nodes(inp, cte_sources, followed, out);
            }
        }
        RelPlan::WithScope { ctes, body, .. } => {
            for cte in ctes {
                let body_plan: &RelPlan = match &cte.body {
                    super::plan::CteBody::NonRecursive(b) => b,
                    super::plan::CteBody::Recursive { anchor, .. } => anchor,
                };
                collect_local_source_nodes(body_plan, cte_sources, followed, out);
            }
            collect_local_source_nodes(body, cte_sources, followed, out);
        }
        RelPlan::Insert { source, .. } => match source {
            super::plan::InsertSource::Values(p) | super::plan::InsertSource::Query(p) => {
                collect_local_source_nodes(p, cte_sources, followed, out)
            }
            super::plan::InsertSource::DefaultValues => {}
        },
        RelPlan::Update { from, .. } => {
            if let Some(f) = from {
                collect_local_source_nodes(f, cte_sources, followed, out);
            }
        }
        RelPlan::Delete { using, .. } => {
            if let Some(u) = using {
                collect_local_source_nodes(u, cte_sources, followed, out);
            }
        }
        RelPlan::Merge { source, .. } => {
            collect_local_source_nodes(source, cte_sources, followed, out)
        }
        RelPlan::MultiInsert { source, .. } => {
            collect_local_source_nodes(source, cte_sources, followed, out)
        }
        RelPlan::Explain { body, .. } => {
            collect_local_source_nodes(body, cte_sources, followed, out)
        }
        RelPlan::CreateAsQuery { body, .. } => {
            if let Some(b) = body {
                collect_local_source_nodes(b, cte_sources, followed, out);
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
struct ProducedColumns<'a, 's> {
    out: &'a mut HashSet<ColumnId>,
    /// A subtree whose nodes are left out.
    skipped: Option<&'s RelPlan>,
}

impl<'a, 's, 'p> RelPlanVisitor<'p> for ProducedColumns<'a, 's> {
    fn visit_rel_plan(&mut self, plan: &'p RelPlan) {
        if self
            .skipped
            .is_some_and(|skipped| std::ptr::eq(skipped, plan))
        {
            return;
        }
        // A join's list is its sides' and the columns `USING` merges: its
        // sides' are theirs to add, so a chain of joins is read once.
        if let RelPlan::Join { using, .. } = plan {
            self.out.extend(using.iter().map(|column| column.merged));
        } else {
            self.out.extend(plan.output_schema());
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

/// The columns a body reads through an outer reference that leaves it:
/// one whose scope, the number of blocks out its column is, exceeds the
/// number of nested blocks between the body's root and the reference.
#[derive(Default)]
struct StatedOuterReferences<'p> {
    outer: HashSet<ColumnId>,
    /// The plans being walked, innermost last.
    open: Vec<&'p RelPlan>,
    /// Nested blocks entered below the body's root.
    depth: u32,
    /// Set while a subquery's root is entered.
    entering_subquery: bool,
}

impl<'p> RelPlanVisitor<'p> for StatedOuterReferences<'p> {
    fn visit_rel_plan(&mut self, plan: &'p RelPlan) {
        let nested = std::mem::take(&mut self.entering_subquery)
            || self
                .open
                .last()
                .is_some_and(|parent| opens_block(parent, plan));
        if nested {
            self.depth += 1;
        }
        self.open.push(plan);
        walk_rel_plan(self, plan);
        self.open.pop();
        if nested {
            self.depth -= 1;
        }
    }

    fn visit_scalar_expr(&mut self, expr: &'p ScalarExpr) {
        if let ScalarExpr::OuterRef { scope, column, .. } = expr {
            if scope.0 > self.depth {
                self.outer.insert(*column);
            }
        }
        walk_scalar_expr(self, expr);
    }

    fn visit_subquery(&mut self, plan: &'p RelPlan, _correlates_with: &'p [ColumnId]) {
        self.entering_subquery = true;
        self.visit_rel_plan(plan);
    }
}

/// Whether `child`, a plan `parent` holds, is a block nested in the
/// block `parent` is part of: a derived table's input, a CTE's body, the
/// query an `INSERT` reads, a pivot's `IN` subquery. A subquery of an
/// expression is one too, entered through `visit_subquery`; a branch of a
/// set operation is none.
fn opens_block(parent: &RelPlan, child: &RelPlan) -> bool {
    match parent {
        RelPlan::DerivedTable { input, .. } => std::ptr::eq(input.as_ref(), child),
        RelPlan::WithScope { body, .. } => !std::ptr::eq(body.as_ref(), child),
        RelPlan::Insert { source, .. } => match source {
            super::plan::InsertSource::Query(query) => std::ptr::eq(query.as_ref(), child),
            super::plan::InsertSource::Values(_) | super::plan::InsertSource::DefaultValues => {
                false
            }
        },
        RelPlan::MultiInsert { source, .. } => std::ptr::eq(source.as_ref(), child),
        RelPlan::Pivot { pivot_values, .. } => match pivot_values {
            super::plan::PivotValues::Subquery(query) => std::ptr::eq(query.as_ref(), child),
            super::plan::PivotValues::ValueList(_)
            | super::plan::PivotValues::Any { .. }
            | super::plan::PivotValues::Opaque { .. } => false,
        },
        RelPlan::Scan { .. }
        | RelPlan::Values { .. }
        | RelPlan::CteRef { .. }
        | RelPlan::ModelRef { .. }
        | RelPlan::Project { .. }
        | RelPlan::Filter { .. }
        | RelPlan::Aggregate { .. }
        | RelPlan::Window { .. }
        | RelPlan::Join { .. }
        | RelPlan::Sort { .. }
        | RelPlan::Limit { .. }
        | RelPlan::SetOp { .. }
        | RelPlan::Update { .. }
        | RelPlan::Delete { .. }
        | RelPlan::Merge { .. }
        | RelPlan::Explain { .. }
        | RelPlan::CreateAsQuery { .. }
        | RelPlan::CreateTableForm { .. }
        | RelPlan::TableFunction { .. }
        | RelPlan::Unnest { .. }
        | RelPlan::Unpivot { .. }
        | RelPlan::MatchRecognize { .. }
        | RelPlan::ConnectBy { .. }
        | RelPlan::TableSample { .. }
        | RelPlan::InvalidInput { .. }
        | RelPlan::ParseRecovery { .. }
        | RelPlan::Opaque { .. } => false,
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
                computed: Vec::new(),
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
                computed: Vec::new(),
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
            computed: Vec::new(),
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
                computed: Vec::new(),
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
            computed: Vec::new(),
            hints: Vec::new(),
            node_id: nid(),
            span: sp(),
        };

        let mut outer = RelPlan::Filter {
            computed: Vec::new(),
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

    /// `WITH c0 AS (SELECT a FROM t), c1 AS (SELECT a + 1 AS a FROM c0),
    /// … SELECT a FROM c<last>`, lowered with its bindings.
    fn chain_of_bindings(bindings: usize) -> RelPlan {
        use crate::ir::{
            lower_query_full_with_bindings, CatalogDialect, FunctionCatalog, SessionContext,
            StrictMode,
        };
        use crate::lexer::tokenize;
        use crate::parser::parse_script;

        let mut sql = String::from("WITH c0 AS (SELECT a FROM t)");
        for n in 1..bindings {
            sql.push_str(&format!(", c{n} AS (SELECT a + 1 AS a FROM c{})", n - 1));
        }
        sql.push_str(&format!(" SELECT a FROM c{}", bindings - 1));
        let tokens = tokenize(&sql);
        let script = parse_script(&sql, &tokens.tokens).expect("parse");
        let catalog = FunctionCatalog::for_dialect(CatalogDialect::Default);
        let (plan, _catalog_ctx, _bindings, _facts) = lower_query_full_with_bindings(
            &script.stmts[0],
            &sql,
            StrictMode::Permissive,
            &catalog,
            &SessionContext::default(),
            None,
        )
        .expect("lowers");
        plan
    }

    #[test]
    fn a_chain_of_bindings_is_lowered_holding_each_body_s_sources_once() {
        const BINDINGS: usize = 4_000;
        let _folding = crate::ir::normalize::default_folding();
        let plan = chain_of_bindings(BINDINGS);
        let RelPlan::WithScope { ctes, .. } = &plan else {
            panic!("expected a scope");
        };
        assert_eq!(ctes.len(), BINDINGS);
        // The first body's scan; each later body's reference to the one
        // before, and that binding.
        let held: usize = precompute_cte_sources(&plan)
            .values()
            .map(|sources| sources.nodes.len() + sources.refers_to.len())
            .sum();
        assert_eq!(held, 2 * BINDINGS - 1);
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
