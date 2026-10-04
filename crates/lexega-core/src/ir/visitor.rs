// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Traversal traits for [`RelPlan`] and [`ScalarExpr`].
//!
//! Two pairs of traits, read-only and mutating:
//!
//! - [`RelPlanVisitor`] / [`RelPlanMutator`] — descend a plan tree,
//!   dispatching per variant. Subqueries inside scalars are reached via
//!   the scalar visitor.
//! - [`ScalarExprVisitor`] / [`ScalarExprMutator`] — descend a scalar
//!   expression. Subqueries (`Exists`, `ScalarSubquery`, `QuantifiedCmp`)
//!   call back into the plan visitor.
//!
//! Style: `syn`-style default methods. Each trait's `visit_*` method has a
//! default body that calls the associated free `walk_*` function. Override
//! `visit_*` to observe or rewrite; call `walk_*` from the override to
//! continue the descent, omit the call to prune.
//!
//! # Closed-enum discipline
//!
//! Every `walk_*` function matches exhaustively on its enum with no
//! `_ =>` arm. Adding a [`RelPlan`] or [`ScalarExpr`] variant — or any
//! auxiliary enum touched here — will fail to compile until every walker
//! is updated. That's the point.
//!
//! # Scope
//!
//! - Types and default traversal only. Analyses live in their own
//!   modules and consume these traits.
//! - No caching, no memoization, no parallelism.

use super::column::ColumnId;
// `FilterKind` is re-exported to the in-file `#[cfg(test)]` module
// via `use super::*;`; it is unused in the lib-only build path.
#[cfg_attr(not(test), allow(unused_imports))]
use super::plan::{
    AggregateCall, ChangesClause, CteBinding, CteBody, FilterKind, FrameBound, GroupKey,
    GroupingSpec, Hint, MergeAction, MergeBranch, ProjectItem, ProjectStar, RelPlan, SampleSize,
    ScanModifier, SortKey, StarQualifier, StarReplace, TableSample, TimeTravel, WindowCall,
    WindowFrame,
};
use super::scalar::{FieldStep, QuantifiedRhs, ScalarExpr};

// ────────────────────────────────────────────────────────────────────────
// Read-only traits
// ────────────────────────────────────────────────────────────────────────

/// Immutable plan traversal.
///
/// The trait is parameterized by the lifetime of the borrowed plan so
/// visitors can accumulate borrowed `ColumnId`s / names without cloning.
pub trait RelPlanVisitor<'a>: Sized {
    /// Entry point. Default body walks the whole subtree by delegating to
    /// the per-variant visitors via [`walk_rel_plan`].
    fn visit_rel_plan(&mut self, plan: &'a RelPlan) {
        walk_rel_plan(self, plan);
    }

    /// Called for every scalar expression encountered in the plan tree.
    fn visit_scalar_expr(&mut self, expr: &'a ScalarExpr) {
        walk_scalar_expr(self, expr);
    }

    /// Called when entering a subquery plan reached from a scalar
    /// (`Exists` / `ScalarSubquery` / `QuantifiedCmp::Subquery`). Default
    /// delegates to [`visit_rel_plan`](Self::visit_rel_plan); override to distinguish.
    fn visit_subquery(&mut self, plan: &'a RelPlan, correlates_with: &'a [ColumnId]) {
        let _ = correlates_with;
        self.visit_rel_plan(plan);
    }
}

/// Immutable scalar-expression traversal.
///
/// Useful when an analysis only wants to walk scalar trees (e.g. collect
/// all `ColumnId`s referenced by a predicate) without a surrounding plan.
pub trait ScalarExprVisitor<'a>: Sized {
    fn visit_scalar_expr(&mut self, expr: &'a ScalarExpr) {
        walk_scalar_expr_standalone(self, expr);
    }

    /// Called when the scalar walk encounters a subquery. Default is a
    /// no-op — plain scalar visitors that don't care about nested plans
    /// inherit a safe default. Override to recurse.
    fn visit_scalar_subquery(&mut self, plan: &'a RelPlan, correlates_with: &'a [ColumnId]) {
        let _ = (plan, correlates_with);
    }
}

// ────────────────────────────────────────────────────────────────────────
// Mutating traits
// ────────────────────────────────────────────────────────────────────────

/// Mutating plan traversal.
///
/// Shape mirrors [`RelPlanVisitor`] with `&mut` borrows. Mutators may
/// rewrite plan nodes in place; structural invariants (`ColumnId` stability
/// across unchanged subtrees) are the mutator's responsibility.
pub trait RelPlanMutator: Sized {
    fn visit_rel_plan_mut(&mut self, plan: &mut RelPlan) {
        walk_rel_plan_mut(self, plan);
    }

    fn visit_scalar_expr_mut(&mut self, expr: &mut ScalarExpr) {
        walk_scalar_expr_mut(self, expr);
    }

    fn visit_subquery_mut(&mut self, plan: &mut RelPlan, correlates_with: &mut Vec<ColumnId>) {
        let _ = correlates_with;
        self.visit_rel_plan_mut(plan);
    }
}

/// Mutating scalar-expression traversal.
pub trait ScalarExprMutator: Sized {
    fn visit_scalar_expr_mut(&mut self, expr: &mut ScalarExpr) {
        walk_scalar_expr_standalone_mut(self, expr);
    }

    fn visit_scalar_subquery_mut(
        &mut self,
        plan: &mut RelPlan,
        correlates_with: &mut Vec<ColumnId>,
    ) {
        let _ = (plan, correlates_with);
    }
}

// ════════════════════════════════════════════════════════════════════════
// Read-only walkers
// ════════════════════════════════════════════════════════════════════════

/// Structural descent into `plan`, dispatching each child to `v`.
pub fn walk_rel_plan<'a, V: RelPlanVisitor<'a>>(v: &mut V, plan: &'a RelPlan) {
    match plan {
        // ── Sources ─────────────────────────────────────────────────────
        RelPlan::Scan { modifier, .. } => walk_scan_modifier(v, modifier),

        RelPlan::Values { rows, .. } => {
            for row in rows {
                for cell in row {
                    v.visit_scalar_expr(cell);
                }
            }
        }

        RelPlan::CteRef { .. } | RelPlan::ModelRef { .. } => {}

        // ── Unary ops ───────────────────────────────────────────────────
        RelPlan::Project {
            input,
            items,
            distinct_on,
            ..
        } => {
            v.visit_rel_plan(input);
            for item in items {
                match item {
                    ProjectItem::Expr(e) => v.visit_scalar_expr(&e.expr),
                    ProjectItem::Star(s) => walk_project_star(v, s),
                }
            }
            // PostgreSQL `SELECT DISTINCT ON (e1, e2, …)` keys.
            // Walked so column refs / scalar subqueries inside the
            // ON list are visible to outer-ref / lineage / taint /
            // tables_read analyses.
            for expr in distinct_on {
                v.visit_scalar_expr(expr);
            }
        }

        RelPlan::Filter {
            input, predicate, ..
        } => {
            v.visit_rel_plan(input);
            v.visit_scalar_expr(predicate);
        }

        RelPlan::Aggregate {
            input,
            grouping,
            aggregates,
            having,
            ..
        } => {
            v.visit_rel_plan(input);
            walk_grouping(v, grouping);
            for agg in aggregates {
                walk_aggregate_call(v, agg);
            }
            if let Some(h) = having {
                v.visit_scalar_expr(h);
            }
        }

        RelPlan::Window { input, windows, .. } => {
            v.visit_rel_plan(input);
            for w in windows {
                walk_window_call(v, w);
            }
        }

        // ── Binary op ───────────────────────────────────────────────────
        RelPlan::Join {
            left,
            right,
            on,
            match_condition,
            ..
        } => {
            v.visit_rel_plan(left);
            v.visit_rel_plan(right);
            if let Some(predicate) = on {
                v.visit_scalar_expr(predicate);
            }
            if let Some(predicate) = match_condition {
                v.visit_scalar_expr(predicate);
            }
        }

        RelPlan::SetOp { inputs, .. } => {
            for branch in inputs {
                v.visit_rel_plan(branch);
            }
        }

        // ── Ordering / limiting ─────────────────────────────────────────
        RelPlan::Sort { input, keys, .. } => {
            v.visit_rel_plan(input);
            for k in keys {
                walk_sort_key(v, k);
            }
        }

        RelPlan::Limit {
            input,
            limit,
            offset,
            ..
        } => {
            v.visit_rel_plan(input);
            if let Some(l) = limit {
                v.visit_scalar_expr(l);
            }
            if let Some(o) = offset {
                v.visit_scalar_expr(o);
            }
        }

        // ── DML ─────────────────────────────────────────────────────────
        RelPlan::Insert {
            source,
            on_conflict,
            returning,
            output,
            ..
        } => {
            // `target_hints` carries no scalar children — the typed
            // [`ScanTableHintKind`] variants are either keyword-only
            // (`NoLock`, `TabLock`, …) or carry only spans
            // (`Index { values }`, `ForceSeek { … }`, `KeyValue { … }`),
            // so there is nothing for the visitor to recurse into.
            walk_insert_source(v, source);
            if let Some(oc) = on_conflict {
                walk_on_conflict(v, oc);
            }
            if let Some(r) = returning {
                walk_returning(v, r);
            }
            if let Some(o) = output {
                walk_dml_output(v, o);
            }
        }

        RelPlan::Update {
            assignments,
            from,
            predicate,
            top,
            returning,
            output,
            ..
        } => {
            if let Some(f) = from {
                v.visit_rel_plan(f);
            }
            for (_, expr) in assignments {
                v.visit_scalar_expr(expr);
            }
            if let Some(p) = predicate {
                v.visit_scalar_expr(p);
            }
            if let Some(t) = top {
                v.visit_scalar_expr(&t.count);
            }
            if let Some(r) = returning {
                walk_returning(v, r);
            }
            if let Some(o) = output {
                walk_dml_output(v, o);
            }
        }

        RelPlan::Delete {
            using,
            predicate,
            top,
            returning,
            output,
            ..
        } => {
            if let Some(u) = using {
                v.visit_rel_plan(u);
            }
            if let Some(p) = predicate {
                v.visit_scalar_expr(p);
            }
            if let Some(t) = top {
                v.visit_scalar_expr(&t.count);
            }
            if let Some(r) = returning {
                walk_returning(v, r);
            }
            if let Some(o) = output {
                walk_dml_output(v, o);
            }
        }

        RelPlan::Merge {
            source,
            on,
            branches,
            output,
            ..
        } => {
            v.visit_rel_plan(source);
            v.visit_scalar_expr(on);
            for b in branches {
                walk_merge_branch(v, b);
            }
            if let Some(o) = output {
                walk_dml_output(v, o);
            }
        }

        RelPlan::MultiInsert {
            unconditional_clauses,
            when_clauses,
            else_clauses,
            source,
            ..
        } => {
            for c in unconditional_clauses {
                for val in &c.values {
                    v.visit_scalar_expr(val);
                }
            }
            for w in when_clauses {
                v.visit_scalar_expr(&w.condition);
                for c in &w.targets {
                    for val in &c.values {
                        v.visit_scalar_expr(val);
                    }
                }
            }
            for c in else_clauses {
                for val in &c.values {
                    v.visit_scalar_expr(val);
                }
            }
            v.visit_rel_plan(source);
        }

        RelPlan::Explain { body, .. } => v.visit_rel_plan(body),

        // ── Create-as-query ─────────────────────────────────────────────
        RelPlan::CreateAsQuery { body, .. } => {
            if let Some(body) = body.as_deref() {
                v.visit_rel_plan(body);
            }
        }

        // ── Non-query-bearing DDL ───────────────────────────────────────
        RelPlan::CreateTableForm { .. } => {}

        // ── CTE scoping ─────────────────────────────────────────────────
        RelPlan::WithScope { ctes, body, .. } => {
            for c in ctes {
                walk_cte_binding(v, c);
            }
            v.visit_rel_plan(body);
        }

        // Derived table wraps an inner scope; the inner plan is the
        // only child that needs walking. `columns` are outer-scope
        // column ids with no internal expression content.
        RelPlan::DerivedTable { input, .. } => v.visit_rel_plan(input),

        // Table-valued function: the call is a scalar expression
        // whose arguments may contain subqueries / correlated refs.
        // Walking the scalar is how argument subqueries propagate
        // into derived facts.
        RelPlan::TableFunction { call, .. } => v.visit_scalar_expr(call),

        // ── Dialect-exotic ──────────────────────────────────────────────
        RelPlan::Unnest { input, array, .. } => {
            v.visit_rel_plan(input);
            v.visit_scalar_expr(array);
        }

        RelPlan::Pivot {
            input,
            aggregates,
            pivot_values,
            default_on_null,
            ..
        } => {
            v.visit_rel_plan(input);
            for a in aggregates {
                walk_aggregate_call(v, a);
            }
            walk_pivot_values(v, pivot_values);
            if let Some(d) = default_on_null {
                v.visit_scalar_expr(d);
            }
        }

        RelPlan::Unpivot { input, .. } => v.visit_rel_plan(input),

        RelPlan::MatchRecognize { input, body, .. } => {
            v.visit_rel_plan(input);
            for e in &body.partition_by {
                v.visit_scalar_expr(e);
            }
            for k in &body.order_by {
                walk_sort_key(v, k);
            }
            for m in &body.measures {
                v.visit_scalar_expr(&m.expr);
            }
            for d in &body.define {
                v.visit_scalar_expr(&d.predicate);
            }
        }

        RelPlan::ConnectBy {
            input,
            start_with,
            connect,
            ..
        } => {
            v.visit_rel_plan(input);
            if let Some(sw) = start_with {
                v.visit_scalar_expr(sw);
            }
            v.visit_scalar_expr(connect);
        }

        RelPlan::TableSample { input, sample, .. } => {
            v.visit_rel_plan(input);
            walk_table_sample(v, sample);
        }

        // ── Parser recovery ─────────────────────────────────────────────
        RelPlan::ParseRecovery { .. } => {}
        RelPlan::Opaque { .. } => {}
        RelPlan::InvalidInput { .. } => {}
    }
}

/// Structural descent into a scalar expression reached **from a plan** —
/// subqueries route through [`RelPlanVisitor::visit_subquery`].
pub fn walk_scalar_expr<'a, V: RelPlanVisitor<'a>>(v: &mut V, expr: &'a ScalarExpr) {
    match expr {
        ScalarExpr::Column { .. }
        | ScalarExpr::PatternVarRef { .. }
        | ScalarExpr::OuterRef { .. }
        | ScalarExpr::Lit { .. } => {}

        ScalarExpr::BinOp { left, right, .. } => {
            v.visit_scalar_expr(left);
            v.visit_scalar_expr(right);
        }

        ScalarExpr::LogicalChain { operands, .. } => {
            for operand in operands {
                v.visit_scalar_expr(operand);
            }
        }

        ScalarExpr::Like {
            expr,
            pattern,
            escape,
            ..
        } => {
            v.visit_scalar_expr(expr);
            v.visit_scalar_expr(pattern);
            if let Some(e) = escape {
                v.visit_scalar_expr(e);
            }
        }

        ScalarExpr::UnaryOp { arg, .. } => v.visit_scalar_expr(arg),

        ScalarExpr::FuncCall {
            args, named_args, ..
        } => {
            for a in args {
                v.visit_scalar_expr(a);
            }
            for (_, a) in named_args {
                v.visit_scalar_expr(a);
            }
        }

        ScalarExpr::Case {
            operand,
            branches,
            else_,
            ..
        } => {
            if let Some(op) = operand {
                v.visit_scalar_expr(op);
            }
            for (cond, then) in branches {
                v.visit_scalar_expr(cond);
                v.visit_scalar_expr(then);
            }
            if let Some(e) = else_ {
                v.visit_scalar_expr(e);
            }
        }

        ScalarExpr::Cast { expr, .. } => v.visit_scalar_expr(expr),

        ScalarExpr::InList { expr, list, .. } => {
            v.visit_scalar_expr(expr);
            for e in list {
                v.visit_scalar_expr(e);
            }
        }

        ScalarExpr::Between {
            expr, low, high, ..
        } => {
            v.visit_scalar_expr(expr);
            v.visit_scalar_expr(low);
            v.visit_scalar_expr(high);
        }

        ScalarExpr::Exists {
            subquery,
            correlates_with,
            ..
        } => v.visit_subquery(subquery, correlates_with),

        ScalarExpr::ScalarSubquery {
            subquery,
            correlates_with,
            ..
        } => v.visit_subquery(subquery, correlates_with),

        ScalarExpr::QuantifiedCmp { left, right, .. } => {
            v.visit_scalar_expr(left);
            match right {
                QuantifiedRhs::Subquery(plan, correlates_with) => {
                    v.visit_subquery(plan, correlates_with)
                }
                QuantifiedRhs::List(items) => {
                    for e in items {
                        v.visit_scalar_expr(e);
                    }
                }
            }
        }

        ScalarExpr::WindowFn { call, .. } => walk_window_call(v, call),

        ScalarExpr::FieldAccess { base, path, .. } => {
            v.visit_scalar_expr(base);
            for step in path {
                match step {
                    FieldStep::Field(_) | FieldStep::Index(_) => {}
                    FieldStep::IndexExpr(e) => v.visit_scalar_expr(e),
                }
            }
        }

        ScalarExpr::Lambda { body, .. } => v.visit_scalar_expr(body),

        ScalarExpr::Opaque { .. } => {}
    }
}

/// Standalone scalar walk — used by [`ScalarExprVisitor`] where no plan
/// visitor is available.
pub fn walk_scalar_expr_standalone<'a, V: ScalarExprVisitor<'a>>(v: &mut V, expr: &'a ScalarExpr) {
    match expr {
        ScalarExpr::Column { .. }
        | ScalarExpr::PatternVarRef { .. }
        | ScalarExpr::OuterRef { .. }
        | ScalarExpr::Lit { .. } => {}

        ScalarExpr::BinOp { left, right, .. } => {
            v.visit_scalar_expr(left);
            v.visit_scalar_expr(right);
        }

        ScalarExpr::LogicalChain { operands, .. } => {
            for operand in operands {
                v.visit_scalar_expr(operand);
            }
        }

        ScalarExpr::Like {
            expr,
            pattern,
            escape,
            ..
        } => {
            v.visit_scalar_expr(expr);
            v.visit_scalar_expr(pattern);
            if let Some(e) = escape {
                v.visit_scalar_expr(e);
            }
        }

        ScalarExpr::UnaryOp { arg, .. } => v.visit_scalar_expr(arg),

        ScalarExpr::FuncCall {
            args, named_args, ..
        } => {
            for a in args {
                v.visit_scalar_expr(a);
            }
            for (_, a) in named_args {
                v.visit_scalar_expr(a);
            }
        }

        ScalarExpr::Case {
            operand,
            branches,
            else_,
            ..
        } => {
            if let Some(op) = operand {
                v.visit_scalar_expr(op);
            }
            for (cond, then) in branches {
                v.visit_scalar_expr(cond);
                v.visit_scalar_expr(then);
            }
            if let Some(e) = else_ {
                v.visit_scalar_expr(e);
            }
        }

        ScalarExpr::Cast { expr, .. } => v.visit_scalar_expr(expr),

        ScalarExpr::InList { expr, list, .. } => {
            v.visit_scalar_expr(expr);
            for e in list {
                v.visit_scalar_expr(e);
            }
        }

        ScalarExpr::Between {
            expr, low, high, ..
        } => {
            v.visit_scalar_expr(expr);
            v.visit_scalar_expr(low);
            v.visit_scalar_expr(high);
        }

        ScalarExpr::Exists {
            subquery,
            correlates_with,
            ..
        } => v.visit_scalar_subquery(subquery, correlates_with),

        ScalarExpr::ScalarSubquery {
            subquery,
            correlates_with,
            ..
        } => v.visit_scalar_subquery(subquery, correlates_with),

        ScalarExpr::QuantifiedCmp { left, right, .. } => {
            v.visit_scalar_expr(left);
            match right {
                QuantifiedRhs::Subquery(plan, correlates_with) => {
                    v.visit_scalar_subquery(plan, correlates_with)
                }
                QuantifiedRhs::List(items) => {
                    for e in items {
                        v.visit_scalar_expr(e);
                    }
                }
            }
        }

        ScalarExpr::WindowFn { call, .. } => walk_window_call_standalone(v, call),

        ScalarExpr::FieldAccess { base, path, .. } => {
            v.visit_scalar_expr(base);
            for step in path {
                match step {
                    FieldStep::Field(_) | FieldStep::Index(_) => {}
                    FieldStep::IndexExpr(e) => v.visit_scalar_expr(e),
                }
            }
        }

        ScalarExpr::Lambda { body, .. } => v.visit_scalar_expr(body),

        ScalarExpr::Opaque { .. } => {}
    }
}

// ── Read-only auxiliary walkers ─────────────────────────────────────────

fn walk_project_star<'a, V: RelPlanVisitor<'a>>(v: &mut V, s: &'a ProjectStar) {
    let ProjectStar {
        qualifier,
        exclude: _,
        replace,
        rename: _,
        ilike: _,
        top_level_pure: _,
        span: _,
    } = s;
    match qualifier {
        StarQualifier::Unqualified | StarQualifier::Named(_) => {}
        StarQualifier::FromExpr(e) => v.visit_scalar_expr(e),
    }
    for StarReplace { expr, .. } in replace {
        v.visit_scalar_expr(expr);
    }
}

fn walk_scan_modifier<'a, V: RelPlanVisitor<'a>>(v: &mut V, modifier: &'a ScanModifier) {
    let ScanModifier {
        changes,
        time_travel,
        hints,
        stage_options: _,
        origin: _,
        sample,
        with_offset: _,
        only: _,
        table_hints: _,
        tvf_schema: _,
    } = modifier;
    if let Some(c) = changes {
        walk_changes_clause(v, c);
    }
    if let Some(tt) = time_travel {
        walk_time_travel(v, tt);
    }
    for Hint { .. } in hints {}
    if let Some(ts) = sample {
        walk_table_sample(v, ts);
    }
}

fn walk_changes_clause<'a, V: RelPlanVisitor<'a>>(v: &mut V, c: &'a ChangesClause) {
    let ChangesClause {
        information: _,
        at,
        end,
    } = c;
    if let Some(at) = at {
        walk_time_travel(v, at);
    }
    if let Some(end) = end {
        walk_time_travel(v, end);
    }
}

fn walk_time_travel<'a, V: RelPlanVisitor<'a>>(v: &mut V, tt: &'a TimeTravel) {
    match tt {
        TimeTravel::AtTimestamp(e)
        | TimeTravel::AtOffset(e)
        | TimeTravel::AtStatement(e)
        | TimeTravel::AtStream(e)
        | TimeTravel::BeforeTimestamp(e)
        | TimeTravel::BeforeOffset(e)
        | TimeTravel::BeforeStatement(e)
        | TimeTravel::BeforeStream(e)
        | TimeTravel::ForSystemTimeAsOf(e)
        | TimeTravel::DatabricksTimestampAsOf(e)
        | TimeTravel::DatabricksVersionAsOf(e)
        | TimeTravel::DatabricksAtSign(e) => v.visit_scalar_expr(e),
        TimeTravel::ForSystemTimeBare { .. } => {}
    }
}

fn walk_grouping<'a, V: RelPlanVisitor<'a>>(v: &mut V, g: &'a GroupingSpec) {
    match g {
        GroupingSpec::None => {}
        GroupingSpec::Standard(keys)
        | GroupingSpec::Cube(keys)
        | GroupingSpec::Rollup(keys)
        | GroupingSpec::All(keys) => {
            for k in keys {
                walk_group_key(v, k);
            }
        }
        GroupingSpec::GroupingSets(sets) => {
            for set in sets {
                for k in set {
                    walk_group_key(v, k);
                }
            }
        }
    }
}

fn walk_group_key<'a, V: RelPlanVisitor<'a>>(v: &mut V, k: &'a GroupKey) {
    v.visit_scalar_expr(&k.expr);
}

fn walk_aggregate_call<'a, V: RelPlanVisitor<'a>>(v: &mut V, a: &'a AggregateCall) {
    for arg in &a.args {
        v.visit_scalar_expr(arg);
    }
    for (_name, arg) in &a.named_args {
        v.visit_scalar_expr(arg);
    }
    if let Some(f) = &a.filter {
        v.visit_scalar_expr(f);
    }
    for k in &a.within_group_order {
        walk_sort_key(v, k);
    }
}

fn walk_window_call<'a, V: RelPlanVisitor<'a>>(v: &mut V, w: &'a WindowCall) {
    for arg in &w.args {
        v.visit_scalar_expr(arg);
    }
    for p in &w.partition_by {
        v.visit_scalar_expr(p);
    }
    for k in &w.order_by {
        walk_sort_key(v, k);
    }
    if let Some(frame) = &w.frame {
        walk_window_frame(v, frame);
    }
}

/// Standalone analogue for [`ScalarExprVisitor`] — a `WindowFn` reached
/// while walking scalars still needs its args/partitions/frame visited.
fn walk_window_call_standalone<'a, V: ScalarExprVisitor<'a>>(v: &mut V, w: &'a WindowCall) {
    for arg in &w.args {
        v.visit_scalar_expr(arg);
    }
    for p in &w.partition_by {
        v.visit_scalar_expr(p);
    }
    for k in &w.order_by {
        v.visit_scalar_expr(&k.expr);
    }
    if let Some(frame) = &w.frame {
        match &frame.start {
            FrameBound::UnboundedPreceding
            | FrameBound::CurrentRow
            | FrameBound::UnboundedFollowing => {}
            FrameBound::Preceding(e) | FrameBound::Following(e) => v.visit_scalar_expr(e),
        }
        match &frame.end {
            FrameBound::UnboundedPreceding
            | FrameBound::CurrentRow
            | FrameBound::UnboundedFollowing => {}
            FrameBound::Preceding(e) | FrameBound::Following(e) => v.visit_scalar_expr(e),
        }
    }
}

fn walk_window_frame<'a, V: RelPlanVisitor<'a>>(v: &mut V, frame: &'a WindowFrame) {
    match &frame.start {
        FrameBound::UnboundedPreceding
        | FrameBound::CurrentRow
        | FrameBound::UnboundedFollowing => {}
        FrameBound::Preceding(e) | FrameBound::Following(e) => v.visit_scalar_expr(e),
    }
    match &frame.end {
        FrameBound::UnboundedPreceding
        | FrameBound::CurrentRow
        | FrameBound::UnboundedFollowing => {}
        FrameBound::Preceding(e) | FrameBound::Following(e) => v.visit_scalar_expr(e),
    }
}

fn walk_sort_key<'a, V: RelPlanVisitor<'a>>(v: &mut V, k: &'a SortKey) {
    v.visit_scalar_expr(&k.expr);
}

fn walk_table_sample<'a, V: RelPlanVisitor<'a>>(v: &mut V, ts: &'a TableSample) {
    match &ts.size {
        SampleSize::Probability(expr) | SampleSize::Rows(expr) => v.visit_scalar_expr(expr),
    }
    if let Some(s) = &ts.seed {
        v.visit_scalar_expr(s);
    }
    if let Some(r) = &ts.repeatable {
        v.visit_scalar_expr(r);
    }
}

fn walk_merge_branch<'a, V: RelPlanVisitor<'a>>(v: &mut V, b: &'a MergeBranch) {
    if let Some(p) = &b.predicate {
        v.visit_scalar_expr(p);
    }
    match &b.action {
        MergeAction::Insert { values, .. } => {
            for val in values {
                v.visit_scalar_expr(val);
            }
        }
        MergeAction::Update { assignments } => {
            for (_, expr) in assignments {
                v.visit_scalar_expr(expr);
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

fn walk_insert_source<'a, V: RelPlanVisitor<'a>>(
    v: &mut V,
    src: &'a crate::ir::plan::InsertSource,
) {
    use crate::ir::plan::InsertSource;
    match src {
        InsertSource::Values(plan) | InsertSource::Query(plan) => v.visit_rel_plan(plan),
        InsertSource::DefaultValues => {}
    }
}

fn walk_on_conflict<'a, V: RelPlanVisitor<'a>>(v: &mut V, oc: &'a crate::ir::plan::OnConflict) {
    use crate::ir::plan::{ConflictAction, ConflictTarget};
    match &oc.target {
        ConflictTarget::Unspecified
        | ConflictTarget::Columns(_)
        | ConflictTarget::Constraint(_) => {}
        ConflictTarget::Expressions(exprs) => {
            for e in exprs {
                v.visit_scalar_expr(e);
            }
        }
    }
    if let Some(w) = &oc.where_clause {
        v.visit_scalar_expr(w);
    }
    match &oc.action {
        ConflictAction::DoNothing => {}
        ConflictAction::DoUpdate {
            assignments,
            where_clause,
        } => {
            for (_, e) in assignments {
                v.visit_scalar_expr(e);
            }
            if let Some(w) = where_clause {
                v.visit_scalar_expr(w);
            }
        }
        ConflictAction::MySqlDuplicateKeyUpdate { assignments } => {
            for (_, e) in assignments {
                v.visit_scalar_expr(e);
            }
        }
    }
}

fn walk_returning<'a, V: RelPlanVisitor<'a>>(v: &mut V, r: &'a crate::ir::plan::Returning) {
    use crate::ir::plan::ReturningItem;
    for it in &r.items {
        match it {
            ReturningItem::Star => {}
            ReturningItem::Expr { expr, .. } => v.visit_scalar_expr(expr),
        }
    }
}

fn walk_dml_output<'a, V: RelPlanVisitor<'a>>(v: &mut V, o: &'a crate::ir::plan::DmlOutput) {
    use crate::ir::plan::ReturningItem;
    for it in &o.items {
        match it {
            ReturningItem::Star => {}
            ReturningItem::Expr { expr, .. } => v.visit_scalar_expr(expr),
        }
    }
}

fn walk_cte_binding<'a, V: RelPlanVisitor<'a>>(v: &mut V, c: &'a CteBinding) {
    match &c.body {
        CteBody::NonRecursive(p) => v.visit_rel_plan(p),
        CteBody::Recursive { anchor, step, .. } => {
            v.visit_rel_plan(anchor);
            v.visit_rel_plan(step);
        }
    }
}

// ════════════════════════════════════════════════════════════════════════
// Mutating walkers
// ════════════════════════════════════════════════════════════════════════

/// Mutating structural descent. Mirrors [`walk_rel_plan`].
pub fn walk_rel_plan_mut<M: RelPlanMutator>(m: &mut M, plan: &mut RelPlan) {
    match plan {
        RelPlan::Scan { modifier, .. } => walk_scan_modifier_mut(m, modifier),

        RelPlan::Values { rows, .. } => {
            for row in rows {
                for cell in row {
                    m.visit_scalar_expr_mut(cell);
                }
            }
        }

        RelPlan::CteRef { .. } | RelPlan::ModelRef { .. } => {}

        RelPlan::Project {
            input,
            items,
            distinct_on,
            ..
        } => {
            m.visit_rel_plan_mut(input);
            for item in items {
                match item {
                    ProjectItem::Expr(e) => m.visit_scalar_expr_mut(&mut e.expr),
                    ProjectItem::Star(s) => walk_project_star_mut(m, s),
                }
            }
            for expr in distinct_on {
                m.visit_scalar_expr_mut(expr);
            }
        }

        RelPlan::Filter {
            input, predicate, ..
        } => {
            m.visit_rel_plan_mut(input);
            m.visit_scalar_expr_mut(predicate);
        }

        RelPlan::Aggregate {
            input,
            grouping,
            aggregates,
            having,
            ..
        } => {
            m.visit_rel_plan_mut(input);
            walk_grouping_mut(m, grouping);
            for agg in aggregates {
                walk_aggregate_call_mut(m, agg);
            }
            if let Some(h) = having {
                m.visit_scalar_expr_mut(h);
            }
        }

        RelPlan::Window { input, windows, .. } => {
            m.visit_rel_plan_mut(input);
            for w in windows {
                walk_window_call_mut(m, w);
            }
        }

        RelPlan::Join {
            left,
            right,
            on,
            match_condition,
            ..
        } => {
            m.visit_rel_plan_mut(left);
            m.visit_rel_plan_mut(right);
            if let Some(predicate) = on {
                m.visit_scalar_expr_mut(predicate);
            }
            if let Some(predicate) = match_condition {
                m.visit_scalar_expr_mut(predicate);
            }
        }

        RelPlan::SetOp { inputs, .. } => {
            for branch in inputs {
                m.visit_rel_plan_mut(branch);
            }
        }

        RelPlan::Sort { input, keys, .. } => {
            m.visit_rel_plan_mut(input);
            for k in keys {
                walk_sort_key_mut(m, k);
            }
        }

        RelPlan::Limit {
            input,
            limit,
            offset,
            ..
        } => {
            m.visit_rel_plan_mut(input);
            if let Some(l) = limit {
                m.visit_scalar_expr_mut(l);
            }
            if let Some(o) = offset {
                m.visit_scalar_expr_mut(o);
            }
        }

        RelPlan::Insert {
            source,
            on_conflict,
            returning,
            output,
            ..
        } => {
            // No scalar children inside `target_hints` — typed
            // [`ScanTableHintKind`] variants carry either no payload
            // or span-only payloads (see read-only walker for the
            // same rationale).
            walk_insert_source_mut(m, source);
            if let Some(oc) = on_conflict {
                walk_on_conflict_mut(m, oc);
            }
            if let Some(r) = returning {
                walk_returning_mut(m, r);
            }
            if let Some(o) = output {
                walk_dml_output_mut(m, o);
            }
        }

        RelPlan::Update {
            assignments,
            from,
            predicate,
            top,
            returning,
            output,
            ..
        } => {
            if let Some(f) = from {
                m.visit_rel_plan_mut(f);
            }
            for (_, expr) in assignments {
                m.visit_scalar_expr_mut(expr);
            }
            if let Some(p) = predicate {
                m.visit_scalar_expr_mut(p);
            }
            if let Some(t) = top {
                m.visit_scalar_expr_mut(&mut t.count);
            }
            if let Some(r) = returning {
                walk_returning_mut(m, r);
            }
            if let Some(o) = output {
                walk_dml_output_mut(m, o);
            }
        }

        RelPlan::Delete {
            using,
            predicate,
            top,
            returning,
            output,
            ..
        } => {
            if let Some(u) = using {
                m.visit_rel_plan_mut(u);
            }
            if let Some(p) = predicate {
                m.visit_scalar_expr_mut(p);
            }
            if let Some(t) = top {
                m.visit_scalar_expr_mut(&mut t.count);
            }
            if let Some(r) = returning {
                walk_returning_mut(m, r);
            }
            if let Some(o) = output {
                walk_dml_output_mut(m, o);
            }
        }

        RelPlan::Merge {
            source,
            on,
            branches,
            output,
            ..
        } => {
            m.visit_rel_plan_mut(source);
            m.visit_scalar_expr_mut(on);
            for b in branches {
                walk_merge_branch_mut(m, b);
            }
            if let Some(o) = output {
                walk_dml_output_mut(m, o);
            }
        }

        RelPlan::MultiInsert {
            unconditional_clauses,
            when_clauses,
            else_clauses,
            source,
            ..
        } => {
            for c in unconditional_clauses {
                for val in &mut c.values {
                    m.visit_scalar_expr_mut(val);
                }
            }
            for w in when_clauses {
                m.visit_scalar_expr_mut(&mut w.condition);
                for c in &mut w.targets {
                    for val in &mut c.values {
                        m.visit_scalar_expr_mut(val);
                    }
                }
            }
            for c in else_clauses {
                for val in &mut c.values {
                    m.visit_scalar_expr_mut(val);
                }
            }
            m.visit_rel_plan_mut(source);
        }

        RelPlan::Explain { body, .. } => m.visit_rel_plan_mut(body),

        RelPlan::CreateAsQuery { body, .. } => {
            if let Some(body) = body.as_deref_mut() {
                m.visit_rel_plan_mut(body);
            }
        }

        RelPlan::CreateTableForm { .. } => {}

        RelPlan::WithScope { ctes, body, .. } => {
            for c in ctes {
                walk_cte_binding_mut(m, c);
            }
            m.visit_rel_plan_mut(body);
        }

        RelPlan::DerivedTable { input, .. } => m.visit_rel_plan_mut(input),

        RelPlan::TableFunction { call, .. } => m.visit_scalar_expr_mut(call),

        RelPlan::Unnest { input, array, .. } => {
            m.visit_rel_plan_mut(input);
            m.visit_scalar_expr_mut(array);
        }

        RelPlan::Pivot {
            input,
            aggregates,
            pivot_values,
            default_on_null,
            ..
        } => {
            m.visit_rel_plan_mut(input);
            for a in aggregates {
                walk_aggregate_call_mut(m, a);
            }
            walk_pivot_values_mut(m, pivot_values);
            if let Some(d) = default_on_null {
                m.visit_scalar_expr_mut(d);
            }
        }

        RelPlan::Unpivot { input, .. } => m.visit_rel_plan_mut(input),

        RelPlan::MatchRecognize { input, body, .. } => {
            m.visit_rel_plan_mut(input);
            for e in &mut body.partition_by {
                m.visit_scalar_expr_mut(e);
            }
            for k in &mut body.order_by {
                walk_sort_key_mut(m, k);
            }
            for meas in &mut body.measures {
                m.visit_scalar_expr_mut(&mut meas.expr);
            }
            for d in &mut body.define {
                m.visit_scalar_expr_mut(&mut d.predicate);
            }
        }

        RelPlan::ConnectBy {
            input,
            start_with,
            connect,
            ..
        } => {
            m.visit_rel_plan_mut(input);
            if let Some(sw) = start_with {
                m.visit_scalar_expr_mut(sw);
            }
            m.visit_scalar_expr_mut(connect);
        }

        RelPlan::TableSample { input, sample, .. } => {
            m.visit_rel_plan_mut(input);
            walk_table_sample_mut(m, sample);
        }

        RelPlan::ParseRecovery { .. } => {}
        RelPlan::Opaque { .. } => {}
        RelPlan::InvalidInput { .. } => {}
    }
}

pub fn walk_scalar_expr_mut<M: RelPlanMutator>(m: &mut M, expr: &mut ScalarExpr) {
    match expr {
        ScalarExpr::Column { .. }
        | ScalarExpr::PatternVarRef { .. }
        | ScalarExpr::OuterRef { .. }
        | ScalarExpr::Lit { .. } => {}

        ScalarExpr::BinOp { left, right, .. } => {
            m.visit_scalar_expr_mut(left);
            m.visit_scalar_expr_mut(right);
        }

        ScalarExpr::LogicalChain { operands, .. } => {
            for operand in operands {
                m.visit_scalar_expr_mut(operand);
            }
        }

        ScalarExpr::Like {
            expr,
            pattern,
            escape,
            ..
        } => {
            m.visit_scalar_expr_mut(expr);
            m.visit_scalar_expr_mut(pattern);
            if let Some(e) = escape {
                m.visit_scalar_expr_mut(e);
            }
        }

        ScalarExpr::UnaryOp { arg, .. } => m.visit_scalar_expr_mut(arg),

        ScalarExpr::FuncCall {
            args, named_args, ..
        } => {
            for a in args {
                m.visit_scalar_expr_mut(a);
            }
            for (_, a) in named_args {
                m.visit_scalar_expr_mut(a);
            }
        }

        ScalarExpr::Case {
            operand,
            branches,
            else_,
            ..
        } => {
            if let Some(op) = operand {
                m.visit_scalar_expr_mut(op);
            }
            for (cond, then) in branches {
                m.visit_scalar_expr_mut(cond);
                m.visit_scalar_expr_mut(then);
            }
            if let Some(e) = else_ {
                m.visit_scalar_expr_mut(e);
            }
        }

        ScalarExpr::Cast { expr, .. } => m.visit_scalar_expr_mut(expr),

        ScalarExpr::InList { expr, list, .. } => {
            m.visit_scalar_expr_mut(expr);
            for e in list {
                m.visit_scalar_expr_mut(e);
            }
        }

        ScalarExpr::Between {
            expr, low, high, ..
        } => {
            m.visit_scalar_expr_mut(expr);
            m.visit_scalar_expr_mut(low);
            m.visit_scalar_expr_mut(high);
        }

        ScalarExpr::Exists {
            subquery,
            correlates_with,
            ..
        } => m.visit_subquery_mut(subquery, correlates_with),

        ScalarExpr::ScalarSubquery {
            subquery,
            correlates_with,
            ..
        } => m.visit_subquery_mut(subquery, correlates_with),

        ScalarExpr::QuantifiedCmp { left, right, .. } => {
            m.visit_scalar_expr_mut(left);
            match right {
                QuantifiedRhs::Subquery(plan, correlates_with) => {
                    m.visit_subquery_mut(plan, correlates_with)
                }
                QuantifiedRhs::List(items) => {
                    for e in items {
                        m.visit_scalar_expr_mut(e);
                    }
                }
            }
        }

        ScalarExpr::WindowFn { call, .. } => walk_window_call_mut(m, call),

        ScalarExpr::FieldAccess { base, path, .. } => {
            m.visit_scalar_expr_mut(base);
            for step in path {
                match step {
                    FieldStep::Field(_) | FieldStep::Index(_) => {}
                    FieldStep::IndexExpr(e) => m.visit_scalar_expr_mut(e),
                }
            }
        }

        ScalarExpr::Lambda { body, .. } => m.visit_scalar_expr_mut(body),

        ScalarExpr::Opaque { .. } => {}
    }
}

pub fn walk_scalar_expr_standalone_mut<M: ScalarExprMutator>(m: &mut M, expr: &mut ScalarExpr) {
    match expr {
        ScalarExpr::Column { .. }
        | ScalarExpr::PatternVarRef { .. }
        | ScalarExpr::OuterRef { .. }
        | ScalarExpr::Lit { .. } => {}

        ScalarExpr::BinOp { left, right, .. } => {
            m.visit_scalar_expr_mut(left);
            m.visit_scalar_expr_mut(right);
        }

        ScalarExpr::LogicalChain { operands, .. } => {
            for operand in operands {
                m.visit_scalar_expr_mut(operand);
            }
        }

        ScalarExpr::Like {
            expr,
            pattern,
            escape,
            ..
        } => {
            m.visit_scalar_expr_mut(expr);
            m.visit_scalar_expr_mut(pattern);
            if let Some(e) = escape {
                m.visit_scalar_expr_mut(e);
            }
        }

        ScalarExpr::UnaryOp { arg, .. } => m.visit_scalar_expr_mut(arg),

        ScalarExpr::FuncCall {
            args, named_args, ..
        } => {
            for a in args {
                m.visit_scalar_expr_mut(a);
            }
            for (_, a) in named_args {
                m.visit_scalar_expr_mut(a);
            }
        }

        ScalarExpr::Case {
            operand,
            branches,
            else_,
            ..
        } => {
            if let Some(op) = operand {
                m.visit_scalar_expr_mut(op);
            }
            for (cond, then) in branches {
                m.visit_scalar_expr_mut(cond);
                m.visit_scalar_expr_mut(then);
            }
            if let Some(e) = else_ {
                m.visit_scalar_expr_mut(e);
            }
        }

        ScalarExpr::Cast { expr, .. } => m.visit_scalar_expr_mut(expr),

        ScalarExpr::InList { expr, list, .. } => {
            m.visit_scalar_expr_mut(expr);
            for e in list {
                m.visit_scalar_expr_mut(e);
            }
        }

        ScalarExpr::Between {
            expr, low, high, ..
        } => {
            m.visit_scalar_expr_mut(expr);
            m.visit_scalar_expr_mut(low);
            m.visit_scalar_expr_mut(high);
        }

        ScalarExpr::Exists {
            subquery,
            correlates_with,
            ..
        } => m.visit_scalar_subquery_mut(subquery, correlates_with),

        ScalarExpr::ScalarSubquery {
            subquery,
            correlates_with,
            ..
        } => m.visit_scalar_subquery_mut(subquery, correlates_with),

        ScalarExpr::QuantifiedCmp { left, right, .. } => {
            m.visit_scalar_expr_mut(left);
            match right {
                QuantifiedRhs::Subquery(plan, correlates_with) => {
                    m.visit_scalar_subquery_mut(plan, correlates_with)
                }
                QuantifiedRhs::List(items) => {
                    for e in items {
                        m.visit_scalar_expr_mut(e);
                    }
                }
            }
        }

        ScalarExpr::WindowFn { call, .. } => walk_window_call_standalone_mut(m, call),

        ScalarExpr::FieldAccess { base, path, .. } => {
            m.visit_scalar_expr_mut(base);
            for step in path {
                match step {
                    FieldStep::Field(_) | FieldStep::Index(_) => {}
                    FieldStep::IndexExpr(e) => m.visit_scalar_expr_mut(e),
                }
            }
        }

        ScalarExpr::Lambda { body, .. } => m.visit_scalar_expr_mut(body),

        ScalarExpr::Opaque { .. } => {}
    }
}

// ── Mutating auxiliary walkers ──────────────────────────────────────────

fn walk_project_star_mut<M: RelPlanMutator>(m: &mut M, s: &mut ProjectStar) {
    let ProjectStar {
        qualifier,
        exclude: _,
        replace,
        rename: _,
        ilike: _,
        top_level_pure: _,
        span: _,
    } = s;
    match qualifier {
        StarQualifier::Unqualified | StarQualifier::Named(_) => {}
        StarQualifier::FromExpr(e) => m.visit_scalar_expr_mut(e),
    }
    for StarReplace { expr, .. } in replace {
        m.visit_scalar_expr_mut(expr);
    }
}

fn walk_scan_modifier_mut<M: RelPlanMutator>(m: &mut M, modifier: &mut ScanModifier) {
    let ScanModifier {
        changes,
        time_travel,
        hints,
        stage_options: _,
        origin: _,
        sample,
        with_offset: _,
        only: _,
        table_hints: _,
        tvf_schema: _,
    } = modifier;
    if let Some(c) = changes {
        walk_changes_clause_mut(m, c);
    }
    if let Some(tt) = time_travel {
        walk_time_travel_mut(m, tt);
    }
    for Hint { .. } in hints {}
    if let Some(ts) = sample {
        walk_table_sample_mut(m, ts);
    }
}

fn walk_changes_clause_mut<M: RelPlanMutator>(m: &mut M, c: &mut ChangesClause) {
    let ChangesClause {
        information: _,
        at,
        end,
    } = c;
    if let Some(at) = at {
        walk_time_travel_mut(m, at);
    }
    if let Some(end) = end {
        walk_time_travel_mut(m, end);
    }
}

fn walk_pivot_values<'a, V: RelPlanVisitor<'a>>(v: &mut V, pv: &'a super::plan::PivotValues) {
    use super::plan::PivotValues;
    match pv {
        PivotValues::ValueList(values) => {
            for e in values {
                v.visit_scalar_expr(e);
            }
        }
        PivotValues::Any { order_by } => {
            for k in order_by {
                v.visit_scalar_expr(&k.expr);
            }
        }
        PivotValues::Subquery(plan) => v.visit_rel_plan(plan),
        PivotValues::Opaque { .. } => {}
    }
}

fn walk_pivot_values_mut<M: RelPlanMutator>(m: &mut M, pv: &mut super::plan::PivotValues) {
    use super::plan::PivotValues;
    match pv {
        PivotValues::ValueList(values) => {
            for e in values {
                m.visit_scalar_expr_mut(e);
            }
        }
        PivotValues::Any { order_by } => {
            for k in order_by {
                m.visit_scalar_expr_mut(&mut k.expr);
            }
        }
        PivotValues::Subquery(plan) => m.visit_rel_plan_mut(plan),
        PivotValues::Opaque { .. } => {}
    }
}

fn walk_time_travel_mut<M: RelPlanMutator>(m: &mut M, tt: &mut TimeTravel) {
    match tt {
        TimeTravel::AtTimestamp(e)
        | TimeTravel::AtOffset(e)
        | TimeTravel::AtStatement(e)
        | TimeTravel::AtStream(e)
        | TimeTravel::BeforeTimestamp(e)
        | TimeTravel::BeforeOffset(e)
        | TimeTravel::BeforeStatement(e)
        | TimeTravel::BeforeStream(e)
        | TimeTravel::ForSystemTimeAsOf(e)
        | TimeTravel::DatabricksTimestampAsOf(e)
        | TimeTravel::DatabricksVersionAsOf(e)
        | TimeTravel::DatabricksAtSign(e) => m.visit_scalar_expr_mut(e),
        TimeTravel::ForSystemTimeBare { .. } => {}
    }
}

fn walk_grouping_mut<M: RelPlanMutator>(m: &mut M, g: &mut GroupingSpec) {
    match g {
        GroupingSpec::None => {}
        GroupingSpec::Standard(keys)
        | GroupingSpec::Cube(keys)
        | GroupingSpec::Rollup(keys)
        | GroupingSpec::All(keys) => {
            for k in keys {
                m.visit_scalar_expr_mut(&mut k.expr);
            }
        }
        GroupingSpec::GroupingSets(sets) => {
            for set in sets {
                for k in set {
                    m.visit_scalar_expr_mut(&mut k.expr);
                }
            }
        }
    }
}

fn walk_aggregate_call_mut<M: RelPlanMutator>(m: &mut M, a: &mut AggregateCall) {
    for arg in &mut a.args {
        m.visit_scalar_expr_mut(arg);
    }
    for (_name, arg) in &mut a.named_args {
        m.visit_scalar_expr_mut(arg);
    }
    if let Some(f) = &mut a.filter {
        m.visit_scalar_expr_mut(f);
    }
    for k in &mut a.within_group_order {
        walk_sort_key_mut(m, k);
    }
}

fn walk_window_call_mut<M: RelPlanMutator>(m: &mut M, w: &mut WindowCall) {
    for arg in &mut w.args {
        m.visit_scalar_expr_mut(arg);
    }
    for p in &mut w.partition_by {
        m.visit_scalar_expr_mut(p);
    }
    for k in &mut w.order_by {
        walk_sort_key_mut(m, k);
    }
    if let Some(frame) = &mut w.frame {
        walk_window_frame_mut(m, frame);
    }
}

fn walk_window_call_standalone_mut<M: ScalarExprMutator>(m: &mut M, w: &mut WindowCall) {
    for arg in &mut w.args {
        m.visit_scalar_expr_mut(arg);
    }
    for p in &mut w.partition_by {
        m.visit_scalar_expr_mut(p);
    }
    for k in &mut w.order_by {
        m.visit_scalar_expr_mut(&mut k.expr);
    }
    if let Some(frame) = &mut w.frame {
        match &mut frame.start {
            FrameBound::UnboundedPreceding
            | FrameBound::CurrentRow
            | FrameBound::UnboundedFollowing => {}
            FrameBound::Preceding(e) | FrameBound::Following(e) => m.visit_scalar_expr_mut(e),
        }
        match &mut frame.end {
            FrameBound::UnboundedPreceding
            | FrameBound::CurrentRow
            | FrameBound::UnboundedFollowing => {}
            FrameBound::Preceding(e) | FrameBound::Following(e) => m.visit_scalar_expr_mut(e),
        }
    }
}

fn walk_window_frame_mut<M: RelPlanMutator>(m: &mut M, frame: &mut WindowFrame) {
    match &mut frame.start {
        FrameBound::UnboundedPreceding
        | FrameBound::CurrentRow
        | FrameBound::UnboundedFollowing => {}
        FrameBound::Preceding(e) | FrameBound::Following(e) => m.visit_scalar_expr_mut(e),
    }
    match &mut frame.end {
        FrameBound::UnboundedPreceding
        | FrameBound::CurrentRow
        | FrameBound::UnboundedFollowing => {}
        FrameBound::Preceding(e) | FrameBound::Following(e) => m.visit_scalar_expr_mut(e),
    }
}

fn walk_sort_key_mut<M: RelPlanMutator>(m: &mut M, k: &mut SortKey) {
    m.visit_scalar_expr_mut(&mut k.expr);
}

fn walk_table_sample_mut<M: RelPlanMutator>(m: &mut M, ts: &mut TableSample) {
    match &mut ts.size {
        SampleSize::Probability(expr) | SampleSize::Rows(expr) => m.visit_scalar_expr_mut(expr),
    }
    if let Some(s) = &mut ts.seed {
        m.visit_scalar_expr_mut(s);
    }
    if let Some(r) = &mut ts.repeatable {
        m.visit_scalar_expr_mut(r);
    }
}

fn walk_merge_branch_mut<M: RelPlanMutator>(m: &mut M, b: &mut MergeBranch) {
    if let Some(p) = &mut b.predicate {
        m.visit_scalar_expr_mut(p);
    }
    match &mut b.action {
        MergeAction::Insert { values, .. } => {
            for val in values {
                m.visit_scalar_expr_mut(val);
            }
        }
        MergeAction::Update { assignments } => {
            for (_, expr) in assignments {
                m.visit_scalar_expr_mut(expr);
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

fn walk_insert_source_mut<M: RelPlanMutator>(m: &mut M, src: &mut crate::ir::plan::InsertSource) {
    use crate::ir::plan::InsertSource;
    match src {
        InsertSource::Values(plan) | InsertSource::Query(plan) => m.visit_rel_plan_mut(plan),
        InsertSource::DefaultValues => {}
    }
}

fn walk_on_conflict_mut<M: RelPlanMutator>(m: &mut M, oc: &mut crate::ir::plan::OnConflict) {
    use crate::ir::plan::{ConflictAction, ConflictTarget};
    match &mut oc.target {
        ConflictTarget::Unspecified
        | ConflictTarget::Columns(_)
        | ConflictTarget::Constraint(_) => {}
        ConflictTarget::Expressions(exprs) => {
            for e in exprs {
                m.visit_scalar_expr_mut(e);
            }
        }
    }
    if let Some(w) = &mut oc.where_clause {
        m.visit_scalar_expr_mut(w);
    }
    match &mut oc.action {
        ConflictAction::DoNothing => {}
        ConflictAction::DoUpdate {
            assignments,
            where_clause,
        } => {
            for (_, e) in assignments {
                m.visit_scalar_expr_mut(e);
            }
            if let Some(w) = where_clause {
                m.visit_scalar_expr_mut(w);
            }
        }
        ConflictAction::MySqlDuplicateKeyUpdate { assignments } => {
            for (_, e) in assignments {
                m.visit_scalar_expr_mut(e);
            }
        }
    }
}

fn walk_returning_mut<M: RelPlanMutator>(m: &mut M, r: &mut crate::ir::plan::Returning) {
    use crate::ir::plan::ReturningItem;
    for it in &mut r.items {
        match it {
            ReturningItem::Star => {}
            ReturningItem::Expr { expr, .. } => m.visit_scalar_expr_mut(expr),
        }
    }
}

fn walk_dml_output_mut<M: RelPlanMutator>(m: &mut M, o: &mut crate::ir::plan::DmlOutput) {
    use crate::ir::plan::ReturningItem;
    for it in &mut o.items {
        match it {
            ReturningItem::Star => {}
            ReturningItem::Expr { expr, .. } => m.visit_scalar_expr_mut(expr),
        }
    }
}

fn walk_cte_binding_mut<M: RelPlanMutator>(m: &mut M, c: &mut CteBinding) {
    match &mut c.body {
        CteBody::NonRecursive(p) => m.visit_rel_plan_mut(p),
        CteBody::Recursive { anchor, step, .. } => {
            m.visit_rel_plan_mut(anchor);
            m.visit_rel_plan_mut(step);
        }
    }
}

// ════════════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::NodeId;
    use crate::context::node_metadata::TableRef;
    use crate::ir::column::ColumnIdAllocator;
    use crate::ir::plan::{
        AggregateCall, JoinKind, NullTreatment, ProjectExpr, ProjectItem, ResolvedFunc,
        ScanModifier,
    };
    use crate::ir::scalar::{Lit, ScalarExpr, ScopeId};
    use crate::lexer::token::Span;

    fn sp() -> Span {
        Span { start: 0, end: 0 }
    }

    fn nid() -> NodeId {
        NodeId::new(0)
    }

    fn tref(name: &str) -> TableRef {
        TableRef::new(name.to_string())
    }

    fn lit(n: i64) -> ScalarExpr {
        ScalarExpr::Lit {
            value: Lit::Integer(n.to_string()),
            span: sp(),
        }
    }

    fn col(id: ColumnId) -> ScalarExpr {
        ScalarExpr::Column {
            column: id,
            span: sp(),
        }
    }

    /// `Project(Filter(Scan(t)))` with a predicate that references one
    /// column and a project item that references another.
    fn make_plan(alloc: &mut ColumnIdAllocator) -> (RelPlan, ColumnId, ColumnId) {
        let c0 = alloc.fresh_test();
        let c1 = alloc.fresh_test();
        let scan = RelPlan::Scan {
            table: tref("t"),
            columns: vec![c0, c1],
            modifier: ScanModifier::default(),
            alias: None,
            node_id: nid(),
            span: sp(),
            hints: Vec::new(),
        };
        let filter = RelPlan::Filter {
            input: Box::new(scan),
            predicate: ScalarExpr::BinOp {
                op: crate::ir::scalar::BinOpKind::Cmp(crate::ir::scalar::ComparisonOp::Eq),
                left: Box::new(col(c0)),
                right: Box::new(lit(1)),
                span: sp(),
            },
            kind: FilterKind::Where,
            node_id: nid(),
            span: sp(),
            hints: Vec::new(),
        };
        let p_out = alloc.fresh_test();
        let project = RelPlan::Project {
            input: Box::new(filter),
            items: vec![ProjectItem::Expr(ProjectExpr {
                output: p_out,
                expr: col(c1),
                alias: None,
                span: sp(),
            })],
            distinct: false,
            distinct_on: Vec::new(),
            node_id: nid(),
            span: sp(),
            hints: Vec::new(),
        };
        (project, c0, c1)
    }

    // ── RelPlanVisitor ──────────────────────────────────────────────────

    #[derive(Default)]
    struct Counter {
        plans: usize,
        scalars: usize,
        columns_seen: Vec<ColumnId>,
    }

    impl<'a> RelPlanVisitor<'a> for Counter {
        fn visit_rel_plan(&mut self, plan: &'a RelPlan) {
            self.plans += 1;
            walk_rel_plan(self, plan);
        }
        fn visit_scalar_expr(&mut self, expr: &'a ScalarExpr) {
            self.scalars += 1;
            if let ScalarExpr::Column { column, .. } = expr {
                self.columns_seen.push(*column);
            }
            walk_scalar_expr(self, expr);
        }
    }

    #[test]
    fn visitor_reaches_every_plan_and_every_scalar() {
        let mut alloc = ColumnIdAllocator::new();
        let (plan, c0, c1) = make_plan(&mut alloc);
        let mut v = Counter::default();
        v.visit_rel_plan(&plan);
        // Three plan nodes: Project, Filter, Scan.
        assert_eq!(v.plans, 3);
        // Five scalar visits: predicate `=`, `c0`, `1`; project item `c1`.
        // Breakdown: BinOp(1) + Column(1) + Lit(1) + Column(1) = 4 — plus
        // the top-level visit of the BinOp itself. The walker dispatches
        // BinOp first (counted), then its two children (counted), then
        // the project item's Column (counted): 4 total.
        assert_eq!(v.scalars, 4);
        assert!(v.columns_seen.contains(&c0));
        assert!(v.columns_seen.contains(&c1));
    }

    #[test]
    fn visitor_reaches_subquery_through_exists() {
        let mut alloc = ColumnIdAllocator::new();
        let c = alloc.fresh_test();
        let inner = RelPlan::Scan {
            table: tref("inner"),
            columns: vec![c],
            modifier: ScanModifier::default(),
            alias: None,
            node_id: nid(),
            span: sp(),
            hints: Vec::new(),
        };
        let outer = RelPlan::Filter {
            input: Box::new(RelPlan::Scan {
                table: tref("outer"),
                columns: vec![alloc.fresh_test()],
                modifier: ScanModifier::default(),
                alias: None,
                node_id: nid(),
                span: sp(),
                hints: Vec::new(),
            }),
            predicate: ScalarExpr::Exists {
                subquery: Box::new(inner),
                correlates_with: vec![],
                negated: false,
                span: sp(),
            },
            kind: FilterKind::Where,
            node_id: nid(),
            span: sp(),
            hints: Vec::new(),
        };
        let mut v = Counter::default();
        v.visit_rel_plan(&outer);
        // Filter + outer Scan + inner Scan = 3
        assert_eq!(v.plans, 3);
    }

    // ── ScalarExprVisitor ──────────────────────────────────────────────

    #[derive(Default)]
    struct ColumnCollector(Vec<ColumnId>);

    impl<'a> ScalarExprVisitor<'a> for ColumnCollector {
        fn visit_scalar_expr(&mut self, expr: &'a ScalarExpr) {
            if let ScalarExpr::Column { column, .. } = expr {
                self.0.push(*column);
            }
            walk_scalar_expr_standalone(self, expr);
        }
    }

    #[test]
    fn scalar_visitor_collects_columns() {
        let mut alloc = ColumnIdAllocator::new();
        let c0 = alloc.fresh_test();
        let c1 = alloc.fresh_test();
        let expr = ScalarExpr::BinOp {
            op: crate::ir::scalar::BinOpKind::Add,
            left: Box::new(col(c0)),
            right: Box::new(ScalarExpr::UnaryOp {
                op: crate::ir::scalar::UnaryOpKind::Neg,
                arg: Box::new(col(c1)),
                span: sp(),
            }),
            span: sp(),
        };
        let mut v = ColumnCollector::default();
        v.visit_scalar_expr(&expr);
        assert_eq!(v.0, vec![c0, c1]);
    }

    // ── RelPlanMutator ─────────────────────────────────────────────────

    /// Rewrites every integer literal `n` to `n + 1` by mutating the inner
    /// string. Verifies mutators reach every scalar.
    struct IncrementLits;

    impl RelPlanMutator for IncrementLits {
        fn visit_scalar_expr_mut(&mut self, expr: &mut ScalarExpr) {
            if let ScalarExpr::Lit {
                value: Lit::Integer(s),
                ..
            } = expr
            {
                let n: i64 = s.parse().unwrap_or(0);
                *s = (n + 1).to_string();
            }
            walk_scalar_expr_mut(self, expr);
        }
    }

    #[test]
    fn mutator_rewrites_scalar_in_place() {
        let mut alloc = ColumnIdAllocator::new();
        let (mut plan, _, _) = make_plan(&mut alloc);
        IncrementLits.visit_rel_plan_mut(&mut plan);

        // Walk the mutated plan and confirm the `1` became `2`.
        struct FindLit(Option<String>);
        impl<'a> RelPlanVisitor<'a> for FindLit {
            fn visit_scalar_expr(&mut self, expr: &'a ScalarExpr) {
                if let ScalarExpr::Lit {
                    value: Lit::Integer(s),
                    ..
                } = expr
                {
                    self.0 = Some(s.clone());
                }
                walk_scalar_expr(self, expr);
            }
        }
        let mut f = FindLit(None);
        f.visit_rel_plan(&plan);
        assert_eq!(f.0.as_deref(), Some("2"));
    }

    // ── Join + aggregate regression: make sure auxiliary walkers fire. ─

    #[test]
    fn visitor_reaches_join_on_and_aggregate_args() {
        let mut alloc = ColumnIdAllocator::new();
        let l_col = alloc.fresh_test();
        let r_col = alloc.fresh_test();
        let agg_out = alloc.fresh_test();
        let l = RelPlan::Scan {
            table: tref("l"),
            columns: vec![l_col],
            modifier: ScanModifier::default(),
            alias: None,
            node_id: nid(),
            span: sp(),
            hints: Vec::new(),
        };
        let r = RelPlan::Scan {
            table: tref("r"),
            columns: vec![r_col],
            modifier: ScanModifier::default(),
            alias: None,
            node_id: nid(),
            span: sp(),
            hints: Vec::new(),
        };
        let join = RelPlan::Join {
            left: Box::new(l),
            right: Box::new(r),
            kind: JoinKind::Inner,
            on: Some(ScalarExpr::BinOp {
                op: crate::ir::scalar::BinOpKind::Cmp(crate::ir::scalar::ComparisonOp::Eq),
                left: Box::new(col(l_col)),
                right: Box::new(col(r_col)),
                span: sp(),
            }),
            match_condition: None,
            using: vec![],
            natural: false,
            directed: false,
            lateral: false,
            implicit: false,
            node_id: nid(),
            span: sp(),
            clause_span: sp(),
            hints: Vec::new(),
        };
        let agg = RelPlan::Aggregate {
            input: Box::new(join),
            grouping: crate::ir::plan::GroupingSpec::None,
            aggregates: vec![AggregateCall {
                func: ResolvedFunc::unresolved("SUM", None, sp()),
                args: vec![col(l_col)],
                named_args: vec![],
                distinct: false,
                approximate: false,
                filter: Some(ScalarExpr::BinOp {
                    op: crate::ir::scalar::BinOpKind::Cmp(crate::ir::scalar::ComparisonOp::Gt),
                    left: Box::new(col(r_col)),
                    right: Box::new(lit(0)),
                    span: sp(),
                }),
                arg_order: vec![],
                within_group_order: vec![],
                null_treatment: NullTreatment::Default,
                output: agg_out,
                span: sp(),
            }],
            having: None,
            output_columns: vec![agg_out],
            node_id: nid(),
            span: sp(),
            hints: Vec::new(),
        };

        let mut v = Counter::default();
        v.visit_rel_plan(&agg);

        // Columns referenced: l_col (in ON and in agg arg), r_col (in ON and
        // in filter). Collector pushes each time Column is visited.
        assert!(v.columns_seen.iter().filter(|c| **c == l_col).count() >= 2);
        assert!(v.columns_seen.iter().filter(|c| **c == r_col).count() >= 2);
    }

    // Needed to satisfy the import — `ScalarExprMutator` has no test above,
    // and clippy would flag unused_imports without this touch.
    struct _MutatorWitness;
    impl ScalarExprMutator for _MutatorWitness {}

    // Silence the `ScopeId` import warning: used transitively by
    // `ScalarExpr::OuterRef` reachability but no test constructs one.
    #[allow(dead_code)]
    fn _scope_witness() -> ScopeId {
        ScopeId(0)
    }
}
