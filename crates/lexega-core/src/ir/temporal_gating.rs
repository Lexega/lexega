// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Temporal sub-expressions that gate a predicate.

use super::catalog::{is_temporal_function, FunctionCatalog};
use super::column::ColumnId;
use super::plan::{CteBody, InsertSource, RelPlan, ResolvedFunc};
use super::scalar::{QuantifiedRhs, ScalarExpr};
use crate::lexer::token::Span;

/// Walk `plan` invoking `visit` on every `Filter.predicate`,
/// `Join.on`, `Join.match_condition`, `Update.predicate`,
/// `Delete.predicate`, and `Merge.on`. CTE bodies, derived-table
/// bodies, and SetOp branches recurse — temporal-gated CTE
/// predicates count toward outer-scope gating.
///
/// Closed-enum exhaustive over [`RelPlan`].
pub fn walk_plan_predicates(plan: &RelPlan, visit: &mut dyn FnMut(&ScalarExpr)) {
    match plan {
        RelPlan::Filter {
            predicate, input, ..
        } => {
            visit(predicate);
            walk_plan_predicates(input, visit);
        }
        RelPlan::Join {
            left,
            right,
            on,
            match_condition,
            ..
        } => {
            if let Some(cond) = on {
                visit(cond);
            }
            if let Some(cond) = match_condition {
                visit(cond);
            }
            walk_plan_predicates(left, visit);
            walk_plan_predicates(right, visit);
        }
        RelPlan::Project { input, .. }
        | RelPlan::Aggregate { input, .. }
        | RelPlan::Window { input, .. }
        | RelPlan::Sort { input, .. }
        | RelPlan::Limit { input, .. }
        | RelPlan::DerivedTable { input, .. }
        | RelPlan::Pivot { input, .. }
        | RelPlan::Unpivot { input, .. }
        | RelPlan::MatchRecognize { input, .. }
        | RelPlan::TableSample { input, .. }
        | RelPlan::ConnectBy { input, .. }
        | RelPlan::Unnest { input, .. } => walk_plan_predicates(input, visit),
        RelPlan::SetOp { inputs, .. } => {
            for inner in inputs {
                walk_plan_predicates(inner, visit);
            }
        }
        RelPlan::WithScope { ctes, body, .. } => {
            for cte in ctes {
                match &cte.body {
                    CteBody::NonRecursive(p) => walk_plan_predicates(p, visit),
                    CteBody::Recursive { anchor, step, .. } => {
                        walk_plan_predicates(anchor, visit);
                        walk_plan_predicates(step, visit);
                    }
                }
            }
            walk_plan_predicates(body, visit);
        }
        RelPlan::Explain { body, .. } => walk_plan_predicates(body, visit),
        RelPlan::CreateAsQuery {
            body: Some(body), ..
        } => walk_plan_predicates(body, visit),
        RelPlan::Insert { source, .. } => match source {
            InsertSource::Values(p) | InsertSource::Query(p) => walk_plan_predicates(p, visit),
            InsertSource::DefaultValues => {}
        },
        RelPlan::Update {
            predicate, from, ..
        } => {
            if let Some(p) = predicate {
                visit(p);
            }
            if let Some(s) = from {
                walk_plan_predicates(s, visit);
            }
        }
        RelPlan::Delete {
            predicate, using, ..
        } => {
            if let Some(p) = predicate {
                visit(p);
            }
            if let Some(u) = using {
                walk_plan_predicates(u, visit);
            }
        }
        RelPlan::Merge { on, source, .. } => {
            visit(on);
            walk_plan_predicates(source, visit);
        }
        RelPlan::MultiInsert { source, .. } => {
            walk_plan_predicates(source, visit);
        }
        // Leaves and terminals: no predicates.
        RelPlan::Scan { .. }
        | RelPlan::ModelRef { .. }
        | RelPlan::CteRef { .. }
        | RelPlan::Values { .. }
        | RelPlan::TableFunction { .. }
        | RelPlan::CreateAsQuery { body: None, .. }
        | RelPlan::CreateTableForm { .. }
        | RelPlan::ParseRecovery { .. }
        | RelPlan::Opaque { .. }
        | RelPlan::InvalidInput { .. } => {}
    }
}

/// One temporal sub-expression that gates a predicate in the plan.
/// Projected to the public `TemporalGatingExpression` at the facts
/// boundary.
#[derive(Debug, Clone)]
pub struct IrTemporalGatingExpression {
    /// Span of the gating sub-expression itself (the FuncCall span
    /// or the Column reference span), not of the enclosing
    /// predicate.
    pub source_span: Option<Span>,
    pub kind: IrTemporalGatingKind,
}

/// Closed enum: which structural shape of the gating sub-expression
/// fired the temporal classification. New variants are non-breaking
/// minor additions.
#[derive(Debug, Clone)]
pub enum IrTemporalGatingKind {
    /// A function call whose `FunctionSignature::is_temporal` is
    /// `true` in the function catalog. `display_name` is the
    /// catalog's canonical spelling (for `Resolved` calls) or the
    /// raw call name (for `Unresolved` calls — the catalog had no
    /// entry but the call was nevertheless walked into).
    FunctionCall { display_name: String },
    /// A column reference the caller's column test accepted as
    /// temporal.
    ColumnReference { column: ColumnId },
}

/// Walk `plan`'s predicate sites collecting one
/// [`IrTemporalGatingExpression`] per temporal sub-expression found
/// anywhere in any predicate tree: every call to a function the
/// catalog marks temporal, and every column reference
/// `is_temporal_column` accepts.
///
/// Order: plan-walk order, then in-expression-tree pre-order within
/// each predicate.
pub fn collect_temporal_gating_expressions(
    plan: &RelPlan,
    func_catalog: &FunctionCatalog,
    is_temporal_column: &dyn Fn(ColumnId) -> bool,
) -> Vec<IrTemporalGatingExpression> {
    let mut out = Vec::new();
    walk_plan_predicates(plan, &mut |pred| {
        walk_expr_for_gating(pred, func_catalog, is_temporal_column, &mut out);
    });
    out
}

/// Pre-order walk over a `ScalarExpr` collecting every temporal
/// function call and every temporal column reference into `out`.
/// Closed-enum exhaustive over [`ScalarExpr`].
fn walk_expr_for_gating(
    expr: &ScalarExpr,
    func_catalog: &FunctionCatalog,
    is_temporal_column: &dyn Fn(ColumnId) -> bool,
    out: &mut Vec<IrTemporalGatingExpression>,
) {
    match expr {
        ScalarExpr::FuncCall {
            func,
            args,
            named_args,
            span,
            ..
        } => {
            if is_temporal_function(func, func_catalog) {
                out.push(IrTemporalGatingExpression {
                    source_span: Some(*span),
                    kind: IrTemporalGatingKind::FunctionCall {
                        display_name: function_display_name(func, func_catalog),
                    },
                });
            }
            for a in args {
                walk_expr_for_gating(a, func_catalog, is_temporal_column, out);
            }
            for (_, a) in named_args {
                walk_expr_for_gating(a, func_catalog, is_temporal_column, out);
            }
        }
        ScalarExpr::WindowFn { call, span } => {
            if is_temporal_function(&call.func, func_catalog) {
                out.push(IrTemporalGatingExpression {
                    source_span: Some(*span),
                    kind: IrTemporalGatingKind::FunctionCall {
                        display_name: function_display_name(&call.func, func_catalog),
                    },
                });
            }
            for a in &call.args {
                walk_expr_for_gating(a, func_catalog, is_temporal_column, out);
            }
        }
        ScalarExpr::Column { column, span } | ScalarExpr::PatternVarRef { column, span, .. } => {
            if is_temporal_column(*column) {
                out.push(IrTemporalGatingExpression {
                    source_span: Some(*span),
                    kind: IrTemporalGatingKind::ColumnReference { column: *column },
                });
            }
        }
        ScalarExpr::UnaryOp { arg, .. } => {
            walk_expr_for_gating(arg, func_catalog, is_temporal_column, out);
        }
        ScalarExpr::BinOp { left, right, .. } => {
            walk_expr_for_gating(left, func_catalog, is_temporal_column, out);
            walk_expr_for_gating(right, func_catalog, is_temporal_column, out);
        }
        ScalarExpr::LogicalChain { operands, .. } => {
            for operand in operands {
                walk_expr_for_gating(operand, func_catalog, is_temporal_column, out);
            }
        }
        ScalarExpr::Like {
            expr,
            pattern,
            escape,
            ..
        } => {
            walk_expr_for_gating(expr, func_catalog, is_temporal_column, out);
            walk_expr_for_gating(pattern, func_catalog, is_temporal_column, out);
            if let Some(e) = escape {
                walk_expr_for_gating(e, func_catalog, is_temporal_column, out);
            }
        }
        ScalarExpr::Cast { expr, .. } => {
            walk_expr_for_gating(expr, func_catalog, is_temporal_column, out);
        }
        ScalarExpr::Case {
            operand,
            branches,
            else_,
            ..
        } => {
            if let Some(op) = operand {
                walk_expr_for_gating(op, func_catalog, is_temporal_column, out);
            }
            for (c, v) in branches {
                walk_expr_for_gating(c, func_catalog, is_temporal_column, out);
                walk_expr_for_gating(v, func_catalog, is_temporal_column, out);
            }
            if let Some(e) = else_ {
                walk_expr_for_gating(e, func_catalog, is_temporal_column, out);
            }
        }
        ScalarExpr::InList { expr, list, .. } => {
            walk_expr_for_gating(expr, func_catalog, is_temporal_column, out);
            for e in list {
                walk_expr_for_gating(e, func_catalog, is_temporal_column, out);
            }
        }
        ScalarExpr::Between {
            expr, low, high, ..
        } => {
            walk_expr_for_gating(expr, func_catalog, is_temporal_column, out);
            walk_expr_for_gating(low, func_catalog, is_temporal_column, out);
            walk_expr_for_gating(high, func_catalog, is_temporal_column, out);
        }
        ScalarExpr::QuantifiedCmp { left, right, .. } => {
            walk_expr_for_gating(left, func_catalog, is_temporal_column, out);
            match right {
                QuantifiedRhs::List(items) => {
                    for i in items {
                        walk_expr_for_gating(i, func_catalog, is_temporal_column, out);
                    }
                }
                // A subquery RHS is its own scope and is not walked.
                QuantifiedRhs::Subquery(_, _) => {}
            }
        }
        ScalarExpr::FieldAccess { base, .. } => {
            walk_expr_for_gating(base, func_catalog, is_temporal_column, out);
        }
        ScalarExpr::Lambda { body, .. } => {
            walk_expr_for_gating(body, func_catalog, is_temporal_column, out);
        }
        // Subqueries are evaluated in their own scope; correlation-
        // crossing temporal expressions are not surfaced here.
        ScalarExpr::Exists { .. } | ScalarExpr::ScalarSubquery { .. } => {}
        // Leaves with no temporal content.
        ScalarExpr::OuterRef { .. } | ScalarExpr::Lit { .. } | ScalarExpr::Opaque { .. } => {}
    }
}

/// Resolve a [`ResolvedFunc`] to a display name. Falls back to the
/// raw unresolved spelling when the function id has no entry in the
/// catalog.
fn function_display_name(func: &ResolvedFunc, catalog: &FunctionCatalog) -> String {
    match func {
        ResolvedFunc::Resolved { id, .. } => catalog
            .signature(*id)
            .map(|sig| sig.display_name.clone())
            .unwrap_or_else(|| func.display_hint()),
        ResolvedFunc::Unresolved { raw_name, .. } => raw_name.clone(),
    }
}
