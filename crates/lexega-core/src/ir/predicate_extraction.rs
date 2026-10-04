// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! IR-side predicate extraction — `ScalarExpr → PredicateFact`.
//!
//! Projects the predicate `ScalarExpr` trees carried on
//! [`RelPlan::Filter`] (`WHERE` / `QUALIFY`) and
//! [`RelPlan::Aggregate`] (`HAVING`) nodes onto the
//! [`crate::context::node_metadata::PredicateFact`] surface.
//!
//! ## Scope semantics
//!
//! [`extract_predicates_from_plan`] applies this scope
//! discipline for `where_predicates` /
//! `having_predicates` / `scoped_predicates`:
//!
//! - The walk descends through scope-preserving operators (`Filter`,
//!   `Project`, `Aggregate`, `Window`, `Sort`, `Limit`, `TableSample`,
//!   `Pivot`, `Unpivot`, `MatchRecognize`, `ConnectBy`, `Unnest`,
//!   `Join`) without changing scope.
//! - `WithScope` CTE bodies contribute their predicates with the CTE
//!   name tagged in `scoped_predicates`, and CTE predicate lists
//!   merge into the outer statement's set.
//! - `DerivedTable` is a scope boundary: its inner predicates are
//!   collected into `scoped_predicates` under `ScopeKind::DerivedTable`
//!   but do NOT flow into `where_predicates` or `having_predicates`.
//! - `SetOp` branches are walked with a fresh scope for
//!   `scoped_predicates`; their predicates do NOT propagate into the
//!   outer `where_predicates`.
//! - DML (`Update`, `Delete`, `Merge`) predicate fields are walked for
//!   `where_predicates`.
//!
//! ## Column resolution
//!
//! Uses [`BindingTable`] + [`ScanIndex`] to convert `ColumnId` →
//! `ColumnRef` with a resolved table, matching
//! [`crate::ir::expression_fact::scalar_to_expression_fact`]'s model.
//!
//! ## Closed-enum discipline
//!
//! Every [`ScalarExpr`] variant is matched exhaustively. No `_ =>`
//! catch-all. Adding a new variant fails compilation here, requiring
//! an explicit classification.

use crate::context::node_metadata::{
    ColumnRef, ColumnSourceType, FunctionCallFact, LogicalOperator, PredicateContext,
    PredicateFact, PredicateOp, PredicateQuantifier, ScopeDescriptor, ScopeKind,
    ScopedPredicateFact, TableRef,
};
use crate::ir::column::{BindingTable, ColumnId, ColumnOrigin};
use crate::ir::expression_fact::ScanIndex;
use crate::ir::plan::{CteBody, InsertSource, JoinKind, ProjectItem, RelPlan, ResolvedFunc};
use crate::ir::scalar::{Lit, QuantifiedRhs, Quantifier, ScalarExpr};

// ── Temporal function classification ─────────────────────────────────────────

/// True iff the resolved call is a temporal-returning function per the
/// catalog's typed [`crate::ir::catalog::FunctionSignature::is_temporal`]
/// flag. A name-string match would never fire for
/// `ResolvedFunc::Resolved` because `resolved_func_name` returns the
/// synthetic `fn#NNN` display, not the source spelling — closed-enum
/// catalog lookup is the IR-canonical form.
#[inline]
fn is_temporal_func(
    func: &super::plan::ResolvedFunc,
    catalog: &crate::ir::catalog::FunctionCatalog,
) -> bool {
    crate::ir::catalog::is_temporal_function(func, catalog)
}

// ── Column resolution ────────────────────────────────────────────────────────

/// Resolve a `ColumnId` to a [`ColumnRef`] using the binding table and
/// scan index.  Mirrors the resolution in
/// [`crate::ir::expression_fact::scalar_to_expression_fact`] for
/// `ScalarExpr::Column`.
pub(crate) fn column_id_to_ref(
    col: ColumnId,
    bindings: &BindingTable,
    scan_index: &ScanIndex,
) -> ColumnRef {
    match bindings.get(col) {
        Some(binding) => {
            let resolved_table = match &binding.origin {
                ColumnOrigin::Table { table_node, .. } => scan_index.get(table_node).cloned(),
                ColumnOrigin::Computed { .. }
                | ColumnOrigin::SetOp { .. }
                | ColumnOrigin::OuterRef { .. }
                | ColumnOrigin::RecursiveRef { .. } => None,
            };
            // `source_type` is paired with `resolved_table`: only Table-origin
            // bindings produce a base-table read for downstream consumers
            // (e.g., catalog validation at lib.rs:707 requires BaseTable to
            // emit DATA_ACCESS:COLUMN:UNKNOWN). Non-Table origins resolve to
            // `Unknown`, matching the absence of a `resolved_table`.
            let source_type = match &binding.origin {
                ColumnOrigin::Table { .. } => ColumnSourceType::BaseTable,
                ColumnOrigin::Computed { .. }
                | ColumnOrigin::SetOp { .. }
                | ColumnOrigin::OuterRef { .. }
                | ColumnOrigin::RecursiveRef { .. } => ColumnSourceType::Unknown,
            };
            let mut col_ref =
                ColumnRef::new(binding.display_name.clone()).with_source_type(source_type);
            if let Some(t) = resolved_table {
                col_ref = col_ref.with_resolved_table(t);
            }
            col_ref
        }
        None => ColumnRef::new(String::new()),
    }
}

// ── Literal → string ─────────────────────────────────────────────────────────

/// Convert a `Lit` to the predicate literal-value string.  `Null`
/// maps to `None` (no `PredicateFact` is emitted for `= NULL`; those
/// are caught by `IS NULL`/`IS NOT NULL` rather than equality tests).
/// Parse the raw `ScalarExpr::BinOp.op` string into a typed
/// [`PredicateOp::Compare`] variant. Returns `None` when the operator
/// is not a comparison (e.g. concatenation, arithmetic, dialect-specific
/// operators) so the caller can skip emitting a predicate atom for that
/// shape.
fn parse_predicate_binop(op: crate::ir::scalar::BinOpKind) -> Option<PredicateOp> {
    // Only comparison operators yield a predicate atom; every other
    // `BinOpKind` (arithmetic, logical, dialect-specific) returns `None`.
    if let crate::ir::scalar::BinOpKind::Cmp(cmp) = op {
        Some(PredicateOp::Compare(cmp))
    } else {
        None
    }
}

fn lit_to_predicate_value(lit: &Lit) -> Option<String> {
    match lit {
        Lit::Null => None,
        Lit::Bool(b) => Some(b.to_string()),
        Lit::Integer(s) | Lit::Float(s) | Lit::Str(s) => Some(s.clone()),
        Lit::Bytes { value, .. } | Lit::Typed { value, .. } | Lit::Variant(value) => {
            Some(value.clone())
        }
    }
}

// ── Function-name extraction ─────────────────────────────────────────────────

pub(crate) fn resolved_func_name(func: &ResolvedFunc) -> String {
    match func {
        ResolvedFunc::Resolved { id, .. } => format!("{id}").to_uppercase(),
        ResolvedFunc::Unresolved { raw_name, .. } => raw_name.to_uppercase(),
    }
}

/// Extract a source-text slice for `span`, returning an empty string when
/// `source` is empty (callers without source bytes pass `""`).
#[inline]
pub(crate) fn span_text(source: &str, span: crate::lexer::Span) -> &str {
    let start = span.start as usize;
    let end = span.end as usize;
    if source.is_empty() || end > source.len() || start > end {
        return "";
    }
    &source[start..end]
}

/// Collect [`FunctionCallFact`]s from a scalar expression tree.
/// Does not descend into subquery plans.
fn collect_function_calls(source: &str, expr: &ScalarExpr, out: &mut Vec<FunctionCallFact>) {
    match expr {
        ScalarExpr::FuncCall {
            func,
            args,
            named_args,
            span,
            ..
        } => {
            let name = resolved_func_name(func);
            out.push(FunctionCallFact {
                name,
                expression: span_text(source, *span).to_string(),
                span: *span,
            });
            for a in args {
                collect_function_calls(source, a, out);
            }
            for (_k, v) in named_args {
                collect_function_calls(source, v, out);
            }
        }
        ScalarExpr::Column { .. }
        | ScalarExpr::OuterRef { .. }
        | ScalarExpr::Lit { .. }
        | ScalarExpr::Opaque { .. } => {}
        ScalarExpr::BinOp { left, right, .. } => {
            collect_function_calls(source, left, out);
            collect_function_calls(source, right, out);
        }
        ScalarExpr::LogicalChain { operands, .. } => {
            for operand in operands {
                collect_function_calls(source, operand, out);
            }
        }
        ScalarExpr::Like {
            expr,
            pattern,
            escape,
            ..
        } => {
            collect_function_calls(source, expr, out);
            collect_function_calls(source, pattern, out);
            if let Some(e) = escape {
                collect_function_calls(source, e, out);
            }
        }
        ScalarExpr::UnaryOp { arg, .. } => collect_function_calls(source, arg, out),
        ScalarExpr::Cast { expr, .. } => collect_function_calls(source, expr, out),
        ScalarExpr::Case {
            operand,
            branches,
            else_,
            ..
        } => {
            if let Some(op) = operand {
                collect_function_calls(source, op, out);
            }
            for (cond, result) in branches {
                collect_function_calls(source, cond, out);
                collect_function_calls(source, result, out);
            }
            if let Some(e) = else_ {
                collect_function_calls(source, e, out);
            }
        }
        ScalarExpr::InList { expr, list, .. } => {
            collect_function_calls(source, expr, out);
            for v in list {
                collect_function_calls(source, v, out);
            }
        }
        ScalarExpr::Between {
            expr, low, high, ..
        } => {
            collect_function_calls(source, expr, out);
            collect_function_calls(source, low, out);
            collect_function_calls(source, high, out);
        }
        ScalarExpr::FieldAccess { base, .. } => collect_function_calls(source, base, out),
        ScalarExpr::Lambda { body, .. } => collect_function_calls(source, body, out),
        ScalarExpr::PatternVarRef { .. } | ScalarExpr::WindowFn { .. } => {}
        // Subqueries: do not descend into the plan — only collect
        // from the scalar parts.
        ScalarExpr::Exists { .. }
        | ScalarExpr::ScalarSubquery { .. }
        | ScalarExpr::QuantifiedCmp { .. } => {}
    }
}

// ── Temporal / subquery presence ─────────────────────────────────────────────

fn scalar_has_temporal(expr: &ScalarExpr, catalog: &crate::ir::catalog::FunctionCatalog) -> bool {
    match expr {
        ScalarExpr::FuncCall {
            func,
            args,
            named_args,
            ..
        } => {
            if is_temporal_func(func, catalog) {
                return true;
            }
            args.iter().any(|a| scalar_has_temporal(a, catalog))
                || named_args
                    .iter()
                    .any(|(_k, v)| scalar_has_temporal(v, catalog))
        }
        ScalarExpr::BinOp { left, right, .. } => {
            scalar_has_temporal(left, catalog) || scalar_has_temporal(right, catalog)
        }
        ScalarExpr::LogicalChain { operands, .. } => {
            operands.iter().any(|o| scalar_has_temporal(o, catalog))
        }
        ScalarExpr::Like {
            expr,
            pattern,
            escape,
            ..
        } => {
            scalar_has_temporal(expr, catalog)
                || scalar_has_temporal(pattern, catalog)
                || escape
                    .as_deref()
                    .is_some_and(|e| scalar_has_temporal(e, catalog))
        }
        ScalarExpr::UnaryOp { arg, .. } => scalar_has_temporal(arg, catalog),
        ScalarExpr::Cast { expr, .. } => scalar_has_temporal(expr, catalog),
        ScalarExpr::Case {
            operand,
            branches,
            else_,
            ..
        } => {
            operand
                .as_deref()
                .map(|e| scalar_has_temporal(e, catalog))
                .unwrap_or(false)
                || branches.iter().any(|(c, r)| {
                    scalar_has_temporal(c, catalog) || scalar_has_temporal(r, catalog)
                })
                || else_
                    .as_deref()
                    .map(|e| scalar_has_temporal(e, catalog))
                    .unwrap_or(false)
        }
        ScalarExpr::InList { expr, list, .. } => {
            scalar_has_temporal(expr, catalog)
                || list.iter().any(|e| scalar_has_temporal(e, catalog))
        }
        ScalarExpr::Between {
            expr, low, high, ..
        } => {
            scalar_has_temporal(expr, catalog)
                || scalar_has_temporal(low, catalog)
                || scalar_has_temporal(high, catalog)
        }
        ScalarExpr::FieldAccess { base, .. } => scalar_has_temporal(base, catalog),
        ScalarExpr::Column { .. }
        | ScalarExpr::OuterRef { .. }
        | ScalarExpr::Lit { .. }
        | ScalarExpr::Lambda { .. }
        | ScalarExpr::PatternVarRef { .. }
        | ScalarExpr::WindowFn { .. }
        | ScalarExpr::Exists { .. }
        | ScalarExpr::ScalarSubquery { .. }
        | ScalarExpr::QuantifiedCmp { .. }
        | ScalarExpr::Opaque { .. } => false,
    }
}

fn scalar_has_subquery(expr: &ScalarExpr) -> bool {
    match expr {
        ScalarExpr::Exists { .. }
        | ScalarExpr::ScalarSubquery { .. }
        | ScalarExpr::QuantifiedCmp { .. } => true,
        ScalarExpr::BinOp { left, right, .. } => {
            scalar_has_subquery(left) || scalar_has_subquery(right)
        }
        ScalarExpr::LogicalChain { operands, .. } => operands.iter().any(scalar_has_subquery),
        ScalarExpr::Like {
            expr,
            pattern,
            escape,
            ..
        } => {
            scalar_has_subquery(expr)
                || scalar_has_subquery(pattern)
                || escape.as_deref().is_some_and(scalar_has_subquery)
        }
        ScalarExpr::UnaryOp { arg, .. } => scalar_has_subquery(arg),
        ScalarExpr::Cast { expr, .. } => scalar_has_subquery(expr),
        ScalarExpr::Case {
            operand,
            branches,
            else_,
            ..
        } => {
            operand.as_deref().map(scalar_has_subquery).unwrap_or(false)
                || branches
                    .iter()
                    .any(|(c, r)| scalar_has_subquery(c) || scalar_has_subquery(r))
                || else_.as_deref().map(scalar_has_subquery).unwrap_or(false)
        }
        ScalarExpr::InList { expr, list, .. } => {
            scalar_has_subquery(expr) || list.iter().any(scalar_has_subquery)
        }
        ScalarExpr::Between {
            expr, low, high, ..
        } => scalar_has_subquery(expr) || scalar_has_subquery(low) || scalar_has_subquery(high),
        ScalarExpr::FuncCall {
            args, named_args, ..
        } => {
            args.iter().any(scalar_has_subquery)
                || named_args.iter().any(|(_k, v)| scalar_has_subquery(v))
        }
        ScalarExpr::FieldAccess { base, .. } => scalar_has_subquery(base),
        ScalarExpr::Column { .. }
        | ScalarExpr::OuterRef { .. }
        | ScalarExpr::Lit { .. }
        | ScalarExpr::Lambda { .. }
        | ScalarExpr::PatternVarRef { .. }
        | ScalarExpr::WindowFn { .. }
        | ScalarExpr::Opaque { .. } => false,
    }
}

// ── Outer-correlation lift infrastructure ────────────────────────────────────
//
// When an inner subquery's WHERE has an atom referencing an OUTER scope's
// column (a correlated reference — represented as `ScalarExpr::Column` whose
// `ColumnId` resolves through `BindingTable` to a column owned by an outer
// plan subtree), and the subquery sits in conjunctive-non-negated position
// relative to the outer's WHERE, the atom semantically constrains the
// outer's row alongside the outer's own predicates. The lift pass emits a
// duplicate `PredicateFact` tagged with the outer's `scope_id` so a
// per-scope grouping by column puts it with the outer's own atoms and
// Q-PRED-CONTRA fires correctly on the combined disjoint-equality set.
//
// Subquery-kind eligibility (whether descent into the body supports the
// lift):
//   - `EXISTS` (negated=false)               → lift OK
//   - `EXISTS` (negated=true / NOT EXISTS)   → no lift
//   - `QuantifiedCmp` `= ANY` / `IN` positive → lift OK
//   - `QuantifiedCmp` `<> ALL` / `NOT IN`    → no lift
//   - `QuantifiedCmp` `ALL`-quantifier any op → no lift (empty subquery is TRUE
//     for ALL; doesn't require body atoms to hold)
//   - `ScalarSubquery` inside a comparison's `=` arm at conjunctive position
//                                            → lift OK
//   - `ScalarSubquery` elsewhere (projection, comparison with `<>`, etc.)
//                                            → no lift
//
// Outer-position eligibility (whether the subquery's surrounding expression
// supports the lift): AND-only conjunctive position, non-negated. Any OR
// or NOT on the path from the outer WHERE root to the subquery breaks the
// chain.
//
// Multi-level: the chain accumulates. If inner-inner sits inside a
// `NOT EXISTS` inside an `EXISTS`, the inner-inner's `lift_chain_ok` is
// `false` because the middle `NOT EXISTS` breaks it. The outermost scope
// is `true` by convention.

/// One subquery occurrence within a scalar expression tree, with the
/// lift-descent eligibility of THIS descent (subquery-kind eligible AND
/// outer-position AND-conjunctive non-negated). Computed by
/// [`collect_subquery_plans_with_lift_info`]; consumed by
/// [`walk_subquery_predicates_in_expr`] to populate
/// [`PlanPredicates::scope_lift_eligibility`].
struct SubqueryLiftSite<'a> {
    plan: &'a RelPlan,
    /// True iff this single descent is lift-eligible. Cumulative
    /// eligibility for the inner scope = parent's cumulative
    /// eligibility AND this descent's eligibility.
    lift_eligible_descent: bool,
}

/// Walk `expr` and collect every embedded subquery [`RelPlan`] along
/// with whether the descent into that subquery body is lift-eligible.
///
/// `outer_is_negated` and `outer_in_or` carry the surrounding
/// boolean context propagated by the caller. A subquery sitting under
/// any OR or NOT in the outer expression is NOT in lift-eligible
/// outer position.
///
/// `outer_parent_is_eq_comparison` tracks whether the immediate
/// scalar-expression parent of a subquery is the RHS of an `=`
/// comparison — this matters only for `ScalarSubquery`, which is
/// lift-eligible only in that position.
fn collect_subquery_plans_with_lift_info<'a>(
    expr: &'a ScalarExpr,
    outer_is_negated: bool,
    outer_in_or: bool,
    outer_parent_is_eq_comparison: bool,
    out: &mut Vec<SubqueryLiftSite<'a>>,
) {
    match expr {
        ScalarExpr::Exists {
            subquery, negated, ..
        } => {
            let descent_ok = !outer_is_negated && !outer_in_or && !*negated;
            out.push(SubqueryLiftSite {
                plan: subquery,
                lift_eligible_descent: descent_ok,
            });
        }
        ScalarExpr::ScalarSubquery { subquery, .. } => {
            // Eligible only when the scalar subquery sits as the RHS
            // of an `=` comparison at outer-conjunctive non-negated
            // position. Anywhere else (projection list, `<>`, function
            // arg, CASE branch, etc.) it's a value-producer whose
            // body atoms don't constrain the outer row in a way the
            // lift can soundly capture.
            let descent_ok = !outer_is_negated && !outer_in_or && outer_parent_is_eq_comparison;
            out.push(SubqueryLiftSite {
                plan: subquery,
                lift_eligible_descent: descent_ok,
            });
        }
        ScalarExpr::QuantifiedCmp {
            op,
            quantifier,
            negated,
            left,
            right,
            ..
        } => {
            // Recurse into `left` for nested subqueries (rare but
            // possible — e.g. `(SELECT ...) = ANY (SELECT ...)`).
            collect_subquery_plans_with_lift_info(left, outer_is_negated, outer_in_or, false, out);
            match right {
                QuantifiedRhs::Subquery(plan, _) => {
                    // `IN (subq)` ≡ `= ANY (subq)` — lift OK positive.
                    // `NOT IN (subq)` ≡ `<> ALL (subq)` — no lift.
                    // `= ANY` positive — lift OK.
                    // `<> ALL` positive — no lift.
                    // `ALL` quantifier with any op — no lift (empty
                    // subquery makes ALL trivially TRUE).
                    let kind_ok = matches!(
                        (op, quantifier, negated),
                        (crate::ir::scalar::ComparisonOp::Eq, Quantifier::Any, false,)
                    );
                    let descent_ok = !outer_is_negated && !outer_in_or && kind_ok;
                    out.push(SubqueryLiftSite {
                        plan,
                        lift_eligible_descent: descent_ok,
                    });
                }
                QuantifiedRhs::List(items) => {
                    for e in items {
                        collect_subquery_plans_with_lift_info(
                            e,
                            outer_is_negated,
                            outer_in_or,
                            false,
                            out,
                        );
                    }
                }
            }
        }
        ScalarExpr::BinOp {
            op, left, right, ..
        } => {
            if matches!(op, crate::ir::scalar::BinOpKind::And) {
                collect_subquery_plans_with_lift_info(
                    left,
                    outer_is_negated,
                    outer_in_or,
                    false,
                    out,
                );
                collect_subquery_plans_with_lift_info(
                    right,
                    outer_is_negated,
                    outer_in_or,
                    false,
                    out,
                );
            } else if matches!(op, crate::ir::scalar::BinOpKind::Or) {
                // Past an OR: any subquery below is in disjunctive
                // outer position — not lift-eligible.
                collect_subquery_plans_with_lift_info(left, outer_is_negated, true, false, out);
                collect_subquery_plans_with_lift_info(right, outer_is_negated, true, false, out);
            } else if matches!(
                op,
                crate::ir::scalar::BinOpKind::Cmp(crate::ir::scalar::ComparisonOp::Eq)
            ) {
                // Mark each side as "parent is = comparison" so a
                // ScalarSubquery on either side becomes lift-eligible.
                collect_subquery_plans_with_lift_info(
                    left,
                    outer_is_negated,
                    outer_in_or,
                    true,
                    out,
                );
                collect_subquery_plans_with_lift_info(
                    right,
                    outer_is_negated,
                    outer_in_or,
                    true,
                    out,
                );
            } else {
                collect_subquery_plans_with_lift_info(
                    left,
                    outer_is_negated,
                    outer_in_or,
                    false,
                    out,
                );
                collect_subquery_plans_with_lift_info(
                    right,
                    outer_is_negated,
                    outer_in_or,
                    false,
                    out,
                );
            }
        }
        // N-ary spelling of the `And` / `Or` branches above: `AND`
        // leaves conjunctive position intact, `OR` puts every operand
        // in disjunctive outer position.
        ScalarExpr::LogicalChain { op, operands, .. } => {
            let in_or = outer_in_or || matches!(op, crate::ir::scalar::LogicalOp::Or);
            for operand in operands {
                collect_subquery_plans_with_lift_info(operand, outer_is_negated, in_or, false, out);
            }
        }
        ScalarExpr::UnaryOp { op, arg, .. } => {
            if matches!(op, crate::ir::scalar::UnaryOpKind::Not) {
                collect_subquery_plans_with_lift_info(
                    arg,
                    !outer_is_negated,
                    outer_in_or,
                    false,
                    out,
                );
            } else {
                collect_subquery_plans_with_lift_info(
                    arg,
                    outer_is_negated,
                    outer_in_or,
                    false,
                    out,
                );
            }
        }
        ScalarExpr::Cast { expr, .. } => {
            collect_subquery_plans_with_lift_info(expr, outer_is_negated, outer_in_or, false, out)
        }
        ScalarExpr::Case {
            operand,
            branches,
            else_,
            ..
        } => {
            // CASE branches are conditional — subqueries inside
            // don't sit in unconditional conjunctive position.
            if let Some(op_e) = operand {
                collect_subquery_plans_with_lift_info(op_e, outer_is_negated, true, false, out);
            }
            for (c, r) in branches {
                collect_subquery_plans_with_lift_info(c, outer_is_negated, true, false, out);
                collect_subquery_plans_with_lift_info(r, outer_is_negated, true, false, out);
            }
            if let Some(e) = else_ {
                collect_subquery_plans_with_lift_info(e, outer_is_negated, true, false, out);
            }
        }
        ScalarExpr::InList { expr, list, .. } => {
            collect_subquery_plans_with_lift_info(expr, outer_is_negated, outer_in_or, false, out);
            for e in list {
                collect_subquery_plans_with_lift_info(e, outer_is_negated, outer_in_or, false, out);
            }
        }
        ScalarExpr::Between {
            expr, low, high, ..
        } => {
            collect_subquery_plans_with_lift_info(expr, outer_is_negated, outer_in_or, false, out);
            collect_subquery_plans_with_lift_info(low, outer_is_negated, outer_in_or, false, out);
            collect_subquery_plans_with_lift_info(high, outer_is_negated, outer_in_or, false, out);
        }
        ScalarExpr::Like {
            expr,
            pattern,
            escape,
            ..
        } => {
            collect_subquery_plans_with_lift_info(expr, outer_is_negated, outer_in_or, false, out);
            collect_subquery_plans_with_lift_info(
                pattern,
                outer_is_negated,
                outer_in_or,
                false,
                out,
            );
            if let Some(e) = escape {
                collect_subquery_plans_with_lift_info(e, outer_is_negated, outer_in_or, false, out);
            }
        }
        ScalarExpr::FuncCall {
            args, named_args, ..
        } => {
            for a in args {
                collect_subquery_plans_with_lift_info(a, outer_is_negated, outer_in_or, false, out);
            }
            for (_, a) in named_args {
                collect_subquery_plans_with_lift_info(a, outer_is_negated, outer_in_or, false, out);
            }
        }
        ScalarExpr::FieldAccess { base, .. } => {
            collect_subquery_plans_with_lift_info(base, outer_is_negated, outer_in_or, false, out)
        }
        ScalarExpr::Lambda { body, .. } => {
            collect_subquery_plans_with_lift_info(body, outer_is_negated, outer_in_or, false, out)
        }
        ScalarExpr::Column { .. }
        | ScalarExpr::OuterRef { .. }
        | ScalarExpr::Lit { .. }
        | ScalarExpr::PatternVarRef { .. }
        | ScalarExpr::WindowFn { .. }
        | ScalarExpr::Opaque { .. } => {}
    }
}

/// Collect every `ColumnId` AND scan-source `NodeId` (from `Scan` /
/// `Values` / `CteRef` / `ModelRef` nodes) produced by `plan`'s
/// subtree that belongs to THIS scope. Stops descent at nested scope
/// boundaries: `DerivedTable` bodies, `WithScope` CTE bodies, and
/// scalar subqueries inside `Exists` / `ScalarSubquery` /
/// `QuantifiedCmp::Subquery`. Those nested scopes own their own
/// identity sets, populated separately when `walk_plan` enters them.
///
/// The scan-NodeId set is the lift pass's primary lookup key:
/// correlated inner-atom columns have binding origin
/// `ColumnOrigin::Table { table_node }` where `table_node` matches
/// the outer's Scan node — but the lowerer allocates a FRESH
/// `ColumnId` for the correlated reference, so direct ColumnId
/// equality against the outer's `output_schema` misses.
fn collect_scope_owned_identities(
    plan: &RelPlan,
    cols: &mut std::collections::BTreeSet<ColumnId>,
    scan_nodes: &mut std::collections::BTreeSet<crate::ast::NodeId>,
) {
    use crate::ir::plan::InsertSource;
    match plan {
        RelPlan::Scan {
            columns, node_id, ..
        }
        | RelPlan::Values {
            columns, node_id, ..
        }
        | RelPlan::CteRef {
            columns, node_id, ..
        }
        | RelPlan::ModelRef {
            columns, node_id, ..
        } => {
            cols.extend(columns.iter().copied());
            scan_nodes.insert(*node_id);
        }
        RelPlan::Project { items, input, .. } => {
            for it in items {
                if let ProjectItem::Expr(e) = it {
                    cols.insert(e.output);
                }
            }
            collect_scope_owned_identities(input, cols, scan_nodes);
        }
        RelPlan::Filter { input, .. }
        | RelPlan::Sort { input, .. }
        | RelPlan::Limit { input, .. }
        | RelPlan::TableSample { input, .. }
        | RelPlan::Unnest { input, .. } => collect_scope_owned_identities(input, cols, scan_nodes),
        RelPlan::Aggregate {
            input,
            output_columns,
            ..
        } => {
            cols.extend(output_columns.iter().copied());
            collect_scope_owned_identities(input, cols, scan_nodes);
        }
        RelPlan::Window {
            input,
            window_outputs,
            ..
        } => {
            cols.extend(window_outputs.iter().copied());
            collect_scope_owned_identities(input, cols, scan_nodes);
        }
        RelPlan::SetOp {
            output_columns,
            inputs,
            ..
        } => {
            cols.extend(output_columns.iter().copied());
            for inp in inputs {
                collect_scope_owned_identities(inp, cols, scan_nodes);
            }
        }
        RelPlan::Join { left, right, .. } => {
            collect_scope_owned_identities(left, cols, scan_nodes);
            collect_scope_owned_identities(right, cols, scan_nodes);
        }
        RelPlan::Pivot {
            input,
            output_columns,
            ..
        } => {
            cols.extend(output_columns.iter().copied());
            collect_scope_owned_identities(input, cols, scan_nodes);
        }
        RelPlan::Unpivot {
            input,
            value_columns,
            ..
        } => {
            cols.extend(value_columns.iter().copied());
            collect_scope_owned_identities(input, cols, scan_nodes);
        }
        RelPlan::MatchRecognize {
            input,
            output_columns,
            ..
        } => {
            cols.extend(output_columns.iter().copied());
            collect_scope_owned_identities(input, cols, scan_nodes);
        }
        RelPlan::ConnectBy {
            input,
            output_columns,
            ..
        } => {
            cols.extend(output_columns.iter().copied());
            collect_scope_owned_identities(input, cols, scan_nodes);
        }
        // Scope boundaries: own the alias-side columns exposed to
        // this scope; the body is a separate scope and contributes
        // nothing here.
        RelPlan::DerivedTable { columns, .. } => {
            cols.extend(columns.iter().copied());
        }
        // WithScope's body is logically this scope; CTE bodies are
        // separate scopes (each gets its own scope_id at walk).
        RelPlan::WithScope { body, .. } => collect_scope_owned_identities(body, cols, scan_nodes),
        // DML: predicates reference the target's columns and any FROM/USING.
        RelPlan::Insert { source, .. } => match source {
            InsertSource::Values(p) | InsertSource::Query(p) => {
                collect_scope_owned_identities(p, cols, scan_nodes)
            }
            InsertSource::DefaultValues => {}
        },
        RelPlan::Update { from, .. } => {
            if let Some(f) = from {
                collect_scope_owned_identities(f, cols, scan_nodes);
            }
        }
        RelPlan::Delete { using, .. } => {
            if let Some(u) = using {
                collect_scope_owned_identities(u, cols, scan_nodes);
            }
        }
        RelPlan::Merge { source, .. } => collect_scope_owned_identities(source, cols, scan_nodes),
        RelPlan::MultiInsert { source, .. } => {
            collect_scope_owned_identities(source, cols, scan_nodes)
        }
        RelPlan::Explain { body, .. } => collect_scope_owned_identities(body, cols, scan_nodes),
        RelPlan::CreateAsQuery { body, .. } => {
            if let Some(b) = body {
                collect_scope_owned_identities(b, cols, scan_nodes);
            }
        }
        // Terminal / opaque variants own no observable identities.
        RelPlan::TableFunction { .. }
        | RelPlan::CreateTableForm { .. }
        | RelPlan::InvalidInput { .. }
        | RelPlan::ParseRecovery { .. }
        | RelPlan::Opaque { .. } => {}
    }
}

/// Post-extraction pass: for each `ScopedPredicateFact` whose column
/// resolves to an outer scope's owned-columns set AND the atom sits at
/// AND-conjunctive non-negated position within the inner scope AND the
/// inner scope's `scope_lift_eligibility` is `true`, emit a duplicate
/// `ScopedPredicateFact` tagged with the outer scope's `scope_id`.
/// The duplicate lands in the outer scope's bucket under a
/// `(scope_id, col_key)` grouping,
/// enabling Q-PRED-CONTRA to detect contradictions that span the
/// outer/inner correlation boundary.
///
/// Idempotent for atoms whose columns are owned by the current scope:
/// no outer match, no emission.
fn apply_correlation_lift(result: &mut PlanPredicates, bindings: &BindingTable) {
    if result.scope_owned_scan_nodes.is_empty() || result.scope_lift_eligibility.is_empty() {
        return;
    }
    let mut lifted: Vec<ScopedPredicateFact> = Vec::new();
    for sp in &result.scoped_predicates {
        // Inner-position gate: the lift only carries up atoms in the
        // inner's AND-conjunctive non-negated position.
        if sp.predicate.is_negated || sp.predicate.or_branch_id != 0 {
            continue;
        }
        // Chain-from-outermost gate: the inner scope itself must be
        // reachable from the outermost via lift-eligible descents.
        if !result
            .scope_lift_eligibility
            .get(&sp.scope_id)
            .copied()
            .unwrap_or(false)
        {
            continue;
        }
        let Some(col_id) = sp.predicate.column_id else {
            continue;
        };
        // Resolve the column's origin to its source scan node.
        // The lowerer allocates fresh ColumnIds for correlated refs
        // but preserves the source Scan's NodeId on the binding's
        // `ColumnOrigin::Table { table_node }`. For nested OuterRef
        // chains, follow `outer_column` until a Table origin (or
        // exhaustion).
        let Some(source_node) = resolve_column_source_scan_node(col_id, bindings) else {
            continue;
        };
        // Find the outer scope that owns this scan node.
        let mut owner: Option<u32> = None;
        for (outer_scope_id, owned_scans) in &result.scope_owned_scan_nodes {
            if *outer_scope_id == sp.scope_id {
                continue;
            }
            if owned_scans.contains(&source_node) {
                owner = Some(*outer_scope_id);
                break;
            }
        }
        let Some(outer_scope_id) = owner else {
            continue;
        };
        // Also confirm via ColumnId membership when possible — for
        // CTE-aliased columns the inner reference's ColumnId may
        // directly match the outer's `CteRef.columns[i]`, in which
        // case the scan-node match alone could under-attribute.
        // Prefer the ColumnId-matching outer scope when one exists
        // distinct from the scan-node match.
        if let Some(col_owner) = result
            .scope_owned_columns
            .iter()
            .find(|(sid, owned)| **sid != sp.scope_id && owned.contains(&col_id))
            .map(|(sid, _)| *sid)
        {
            // Direct ColumnId ownership wins (matches CTE / aliased
            // direct references precisely).
            let mut clone = sp.clone();
            clone.scope_id = col_owner;
            clone.predicate.scope_id = col_owner;
            lifted.push(clone);
            continue;
        }
        let mut clone = sp.clone();
        clone.scope_id = outer_scope_id;
        clone.predicate.scope_id = outer_scope_id;
        lifted.push(clone);
    }
    result.scoped_predicates.extend(lifted);
}

/// Follow a `ColumnId`'s binding origin chain to its underlying source
/// `Scan` / `Values` / `CteRef` / `ModelRef` NodeId. Returns `None`
/// when the chain terminates at a `Computed` / `SetOp` / `RecursiveRef`
/// origin (no single source scan), or when the column has no binding.
fn resolve_column_source_scan_node(
    col: ColumnId,
    bindings: &BindingTable,
) -> Option<crate::ast::NodeId> {
    let mut current = col;
    for _ in 0..32 {
        let binding = bindings.get(current)?;
        match &binding.origin {
            ColumnOrigin::Table { table_node, .. } => return Some(*table_node),
            ColumnOrigin::OuterRef { outer_column, .. } => current = *outer_column,
            ColumnOrigin::Computed { .. }
            | ColumnOrigin::SetOp { .. }
            | ColumnOrigin::RecursiveRef { .. } => return None,
        }
    }
    None
}

// ── IN-list values ────────────────────────────────────────────────────────────

/// If every item in `list` is a plain literal, return the string forms.
/// Returns `None` if any item is non-literal.
fn in_list_literal_values(list: &[ScalarExpr]) -> Option<Vec<String>> {
    let mut out = Vec::with_capacity(list.len());
    for item in list {
        match item {
            ScalarExpr::Lit { value, .. } => out.push(lit_to_predicate_value(value)?),
            _ => return None,
        }
    }
    Some(out)
}

// ── Null-safe function detection ─────────────────────────────────────────────

/// Returns `true` if `expr` is a call to a null-handling function
/// whose output is non-NULL even when an input is NULL — `COALESCE`-
/// like, `NVL2`-like (`ConditionalAfterFirst`), or never-null.
///
/// The classification comes from the catalog-resident
/// [`crate::ir::catalog::FunctionSignature::null_behavior`], honouring
/// the architectural rule that analyses receive a [`FunctionId`](crate::ir::catalog::FunctionId) and
/// consult the catalog rather than reaching back through the resolved
/// id to recover the raw display name.
/// [`crate::ir::catalog::NullBehavior::Unknown`] / `Strict` are
/// conservative non-matches; `Unresolved` calls are also treated as
/// non-matches because we can't prove non-null output without
/// catalog backing.
pub fn is_null_safe_scalar_func(
    expr: &ScalarExpr,
    func_catalog: &crate::ir::catalog::FunctionCatalog,
) -> bool {
    use crate::ir::catalog::NullBehavior;
    match expr {
        ScalarExpr::FuncCall { func, .. } => match func {
            ResolvedFunc::Resolved { id, .. } => match func_catalog.signature(*id) {
                Some(sig) => matches!(
                    sig.null_behavior,
                    NullBehavior::CoalesceLike
                        | NullBehavior::ConditionalAfterFirst
                        | NullBehavior::NeverNull
                ),
                None => false,
            },
            ResolvedFunc::Unresolved { .. } => false,
        },
        _ => false,
    }
}

// ── RHS text reconstruction ───────────────────────────────────────────────────

/// Reconstruct `rhs_text` from an IR RHS expression.
///
/// - Literals: the canonical literal text from the IR value.
/// - Column refs: "table.column" or "column".
/// - All other expressions: the raw source bytes at the expression's span
///   when `source` is non-empty; `None` when `source` is `""`.
fn rhs_as_text(
    source: &str,
    rhs: &ScalarExpr,
    bindings: &BindingTable,
    scan_index: &ScanIndex,
) -> Option<String> {
    match rhs {
        ScalarExpr::Lit { value, .. } => lit_to_predicate_value(value),
        ScalarExpr::Column { column, .. } => {
            let col_ref = column_id_to_ref(*column, bindings, scan_index);
            Some(if let Some(t) = &col_ref.resolved_table {
                format!("{}.{}", t.name, col_ref.name)
            } else if let Some(q) = &col_ref.qualifier {
                format!("{}.{}", q, col_ref.name)
            } else {
                col_ref.name.clone()
            })
        }
        // For complex expressions (functions, arithmetic, casts, etc.),
        // read the original source bytes via the span.
        _ => {
            let text = span_text(source, rhs.span());
            if text.is_empty() {
                None
            } else {
                Some(text.to_string())
            }
        }
    }
}

// ── Outer-ref detection ───────────────────────────────────────────────────────

/// Returns `true` if `col` has `ColumnOrigin::OuterRef` in the binding table —
/// meaning this column was introduced by an outer-scope correlation.
fn is_outer_ref_column(col: ColumnId, bindings: &BindingTable) -> bool {
    matches!(
        bindings.get(col),
        Some(b) if matches!(b.origin, ColumnOrigin::OuterRef { .. })
    )
}

// ── Subquery column / table extraction ───────────────────────────────────────

/// Walk `plan` to find the first base-table scan and return its [`TableRef`].
/// This is the `subquery_table` for IN/ANY subqueries.
fn first_scan_table_from_plan(plan: &RelPlan) -> Option<TableRef> {
    match plan {
        RelPlan::Scan { table, .. } => Some(table.clone()),
        RelPlan::CteRef { name, .. } => Some(TableRef::new(name.as_str().to_string())),
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
        | RelPlan::Unnest { input, .. }
        | RelPlan::DerivedTable { input, .. } => first_scan_table_from_plan(input),
        RelPlan::Join { left, .. } => first_scan_table_from_plan(left),
        RelPlan::SetOp { inputs, .. } => inputs.first().and_then(|b| first_scan_table_from_plan(b)),
        RelPlan::WithScope { body, .. } => first_scan_table_from_plan(body),
        RelPlan::Explain { body, .. } => first_scan_table_from_plan(body),
        RelPlan::CreateAsQuery { body, .. } => body.as_deref().and_then(first_scan_table_from_plan),
        RelPlan::Insert { .. }
        | RelPlan::Update { .. }
        | RelPlan::Delete { .. }
        | RelPlan::Merge { .. }
        | RelPlan::MultiInsert { .. }
        | RelPlan::Values { .. }
        | RelPlan::ModelRef { .. }
        | RelPlan::TableFunction { .. }
        | RelPlan::CreateTableForm { .. }
        | RelPlan::ParseRecovery { .. }
        | RelPlan::InvalidInput { .. }
        | RelPlan::Opaque { .. } => None,
    }
}

/// Extract the first projected column and source table from a subquery plan.
/// Used to populate `subquery_column` and `subquery_table` on
/// [`PredicateFact`].
fn subquery_column_and_table_from_plan(
    plan: &RelPlan,
    bindings: &BindingTable,
) -> (Option<ColumnRef>, Option<TableRef>) {
    let schema = plan.output_schema();
    let first_col_id = match schema.first().copied() {
        Some(id) => id,
        None => return (None, None),
    };
    let col_ref = match bindings.get(first_col_id) {
        Some(binding) => ColumnRef::new(binding.display_name.clone()),
        None => return (None, None),
    };
    let table_ref = first_scan_table_from_plan(plan);
    (Some(col_ref), table_ref)
}

// ── ScalarExpr → PredicateFact extraction ────────────────────────────────────

/// A [`PredicateFact`] together with the outer-scope column refs found in
/// the predicate's LHS column.  Used to populate `ScopedPredicateFact`
/// without requiring callers to carry extra state.
pub(crate) struct PredWithCorr {
    fact: PredicateFact,
    /// Columns from this predicate that reference outer scopes (i.e., whose
    /// `ColumnId` has `ColumnOrigin::OuterRef`).  Non-empty iff the predicate
    /// is correlated.
    outer_refs: Vec<ColumnRef>,
}

impl PredWithCorr {
    fn new(fact: PredicateFact, outer_refs: Vec<ColumnRef>) -> Self {
        Self { fact, outer_refs }
    }
}

/// Walk a scalar expression tree and collect [`PredicateFact`]s.
///
/// - `context`: `Where` or `Having` (or `JoinCondition` for ON clauses,
///   not called from here directly).
/// - `scope_id`: enclosing scope depth counter (0 = main query).
/// - `or_counter`: monotonically incremented each time an OR branch is
///   entered; drives `or_branch_id` tracking.
/// - `not_isolation_counter`: monotonically incremented each time a
///   `NOT` is entered. Used to generate fresh `not_isolation_id`s so
///   the constraint-detection algebra can treat each NOT subtree
///   opaquely without polluting the OR-branch id (which the diff
///   layer's `PredicateFact` multiset equality keys on).
/// - `current_not_isolation`: the `not_isolation_id` of the enclosing
///   NOT subtree; `0` outside any NOT.
/// - `is_negated`: whether this sub-tree is inside a `NOT`.
/// - `parent_logical_op`: `AND`/`OR` connector from the enclosing
///   logical expression.
pub(crate) fn extract_scalar_predicates(
    source: &str,
    expr: &ScalarExpr,
    bindings: &BindingTable,
    scan_index: &ScanIndex,
    func_catalog: &crate::ir::catalog::FunctionCatalog,
    context: PredicateContext,
    scope_id: u32,
    or_counter: &mut u32,
    not_isolation_counter: &mut u32,
    current_not_isolation: u32,
    is_negated: bool,
    parent_logical_op: Option<LogicalOperator>,
    out: &mut Vec<PredWithCorr>,
) {
    match expr {
        // ── Logical AND: recurse both sides, keep the same or_branch_id
        ScalarExpr::BinOp {
            op: crate::ir::scalar::BinOpKind::And,
            left,
            right,
            ..
        } => {
            extract_scalar_predicates(
                source,
                left,
                bindings,
                scan_index,
                func_catalog,
                context,
                scope_id,
                or_counter,
                not_isolation_counter,
                current_not_isolation,
                is_negated,
                Some(LogicalOperator::And),
                out,
            );
            extract_scalar_predicates(
                source,
                right,
                bindings,
                scan_index,
                func_catalog,
                context,
                scope_id,
                or_counter,
                not_isolation_counter,
                current_not_isolation,
                is_negated,
                Some(LogicalOperator::And),
                out,
            );
        }

        // ── Logical OR: each branch gets a fresh or_branch_id
        ScalarExpr::BinOp {
            op: crate::ir::scalar::BinOpKind::Or,
            left,
            right,
            ..
        } => {
            extract_scalar_predicates(
                source,
                left,
                bindings,
                scan_index,
                func_catalog,
                context,
                scope_id,
                or_counter,
                not_isolation_counter,
                current_not_isolation,
                is_negated,
                Some(LogicalOperator::Or),
                out,
            );
            *or_counter += 1;
            extract_scalar_predicates(
                source,
                right,
                bindings,
                scan_index,
                func_catalog,
                context,
                scope_id,
                or_counter,
                not_isolation_counter,
                current_not_isolation,
                is_negated,
                Some(LogicalOperator::Or),
                out,
            );
        }

        // ── N-ary spelling of the two arms above. `AND` keeps one
        // or_branch_id across all conjuncts; `OR` opens a fresh one
        // before every operand after the first. That reproduces the
        // exact id sequence the left-nested `BinOp` walk assigns to
        // `a OR b OR c`, which the diff layer's `PredicateFact`
        // multiset equality keys on.
        ScalarExpr::LogicalChain { op, operands, .. } => {
            let logical_op = match op {
                crate::ir::scalar::LogicalOp::And => LogicalOperator::And,
                crate::ir::scalar::LogicalOp::Or => LogicalOperator::Or,
            };
            let is_or = matches!(op, crate::ir::scalar::LogicalOp::Or);
            for (idx, operand) in operands.iter().enumerate() {
                if is_or && idx > 0 {
                    *or_counter += 1;
                }
                extract_scalar_predicates(
                    source,
                    operand,
                    bindings,
                    scan_index,
                    func_catalog,
                    context,
                    scope_id,
                    or_counter,
                    not_isolation_counter,
                    current_not_isolation,
                    is_negated,
                    Some(logical_op),
                    out,
                );
            }
        }

        // ── NOT: flip `is_negated` and open a fresh NOT-isolation
        // subtree id for the negated atom(s). Each NOT structurally
        // isolates its argument: even though `NOT NOT X ≡ X`
        // cancellation-wise, each NOT is an opaque boundary so a
        // doubly-NOTted positive atom does not get AND-combined with
        // outer atoms (see [`no_false_positive_double_not`]). Single
        // NOT surfaces as `is_negated: true` with a non-zero
        // `not_isolation_id`; a subtree holding exactly one negated
        // atom reads as the inverted atom (`NOT a='Y'` as `a<>'Y'`),
        // so `a='X' AND NOT a='Y'` stays consistent. The bump is on
        // `not_isolation_counter`, **not** `or_counter`: the diff
        // layer's `PredicateFact` multiset equality keys on
        // `or_branch_id` and must remain stable across `NOT (cmp)` ↔
        // `inv-cmp` rewrites (gap5a semantic-equivalence pin in
        // `test_diff_semantic_equivalence`).
        ScalarExpr::UnaryOp {
            op: crate::ir::scalar::UnaryOpKind::Not,
            arg,
            ..
        } => {
            *not_isolation_counter += 1;
            let new_isolation = *not_isolation_counter;
            extract_scalar_predicates(
                source,
                arg,
                bindings,
                scan_index,
                func_catalog,
                context,
                scope_id,
                or_counter,
                not_isolation_counter,
                new_isolation,
                !is_negated,
                parent_logical_op,
                out,
            );
        }

        // ── IS NULL / IS NOT NULL: lowered as a unary postfix op on
        //    the column. Surface as a predicate fact carrying the
        //    typed null-test operator.
        ScalarExpr::UnaryOp { op, arg, span }
            if matches!(
                op,
                crate::ir::scalar::UnaryOpKind::IsNull
                    | crate::ir::scalar::UnaryOpKind::IsNotNull
            ) =>
        {
            if let ScalarExpr::Column { column, .. } | ScalarExpr::OuterRef { column, .. } =
                arg.as_ref()
            {
                let col_ref = column_id_to_ref(*column, bindings, scan_index);
                let op_kind = match op {
                    crate::ir::scalar::UnaryOpKind::IsNull => PredicateOp::IsNull,
                    crate::ir::scalar::UnaryOpKind::IsNotNull => PredicateOp::IsNotNull,
                    _ => unreachable!("guarded by matches! above"),
                };
                let outer_refs = if is_outer_ref_column(*column, bindings) {
                    vec![col_ref.clone()]
                } else {
                    vec![]
                };
                out.push(PredWithCorr::new(
                    PredicateFact {
                        column_id: Some(*column),
                        column: col_ref,
                        operator: op_kind,
                        literal_value: None,
                        rhs_text: None,
                        has_temporal: false,
                        has_subquery: false,
                        subquery_column: None,
                        subquery_table: None,
                        function_calls: Vec::new(),
                        in_list_values: None,
                        context,
                        logical_operator: parent_logical_op,
                        or_branch_id: *or_counter,
                        not_isolation_id: current_not_isolation,
                        scope_id,
                        join_scope_id: 0,
                        is_negated,
                        is_reflexive: false,
                        between_bounds: None,
                        span: *span,
                    },
                    outer_refs,
                ));
            }
        }

        // ── Comparison: column op value
        ScalarExpr::BinOp { op, left, right, span } => {
            // Recognise comparison operators only; non-comparison BinOps at
            // predicate atom level (e.g. `||`, dialect-specific) don't
            // contribute a typed `PredicateFact`.
            let Some(op_kind) = parse_predicate_binop(*op) else {
                return;
            };
            if let ScalarExpr::Column { column, .. } | ScalarExpr::OuterRef { column, .. } =
                left.as_ref()
            {
                let col_ref = column_id_to_ref(*column, bindings, scan_index);
                let literal_value = match right.as_ref() {
                    ScalarExpr::Lit { value, .. } => lit_to_predicate_value(value),
                    _ => None,
                };
                // Reflexive `x = x`: RHS is the same column id as the LHS.
                // Recorded as a typed flag because the RHS column identity
                // is not otherwise preserved on the emitted fact.
                let is_reflexive = matches!(op_kind, PredicateOp::Compare(_))
                    && matches!(
                        right.as_ref(),
                        ScalarExpr::Column { column: rc, .. } | ScalarExpr::OuterRef { column: rc, .. }
                            if rc == column
                    );
                let rhs_text = rhs_as_text(source, right, bindings, scan_index);
                let has_temporal = scalar_has_temporal(right, func_catalog);
                let has_subquery = scalar_has_subquery(right);
                let mut function_calls = Vec::new();
                collect_function_calls(source, left, &mut function_calls);
                collect_function_calls(source, right, &mut function_calls);
                let outer_refs = if is_outer_ref_column(*column, bindings) {
                    vec![col_ref.clone()]
                } else {
                    vec![]
                };
                out.push(PredWithCorr::new(
                    PredicateFact {
                        column_id: Some(*column),
                        column: col_ref,
                        operator: op_kind,
                        literal_value,
                        rhs_text,
                        has_temporal,
                        has_subquery,
                        subquery_column: None,
                        subquery_table: None,
                        function_calls,
                        in_list_values: None,
                        between_bounds: None,
                        context,
                        logical_operator: parent_logical_op,
                        or_branch_id: *or_counter,
                        not_isolation_id: current_not_isolation,
                        scope_id,
                        join_scope_id: 0,
                        is_negated,
                        is_reflexive,
                        span: *span,
                    },
                    outer_refs,
                ));
            }
            // Only left-is-column is handled; the mirrored
            // (literal op column) form is skipped.
        }

        // Pattern match: a LIKE predicate does not contribute a
        // typed comparison `PredicateFact`.
        ScalarExpr::Like { .. } => {}

        // ── IN / NOT IN list
        ScalarExpr::InList { expr, list, negated, span } => {
            if let ScalarExpr::Column { column, .. } | ScalarExpr::OuterRef { column, .. } =
                expr.as_ref()
            {
                let col_ref = column_id_to_ref(*column, bindings, scan_index);
                let in_list_values = in_list_literal_values(list);
                let operator = if *negated { PredicateOp::NotIn } else { PredicateOp::In };
                let has_subquery = false;
                let has_temporal = list.iter().any(|e| scalar_has_temporal(e, func_catalog));
                let mut function_calls = Vec::new();
                for v in list {
                    collect_function_calls(source, v, &mut function_calls);
                }
                let outer_refs = if is_outer_ref_column(*column, bindings) {
                    vec![col_ref.clone()]
                } else {
                    vec![]
                };
                out.push(PredWithCorr::new(
                    PredicateFact {
                        column_id: Some(*column),
                        column: col_ref,
                        operator,
                        literal_value: None,
                        rhs_text: None,
                        has_temporal,
                        has_subquery,
                        subquery_column: None,
                        subquery_table: None,
                        function_calls,
                        in_list_values,
                        context,
                        logical_operator: parent_logical_op,
                        or_branch_id: *or_counter,
                        not_isolation_id: current_not_isolation,
                        scope_id,
                        // `is_negated` is the outer-NOT context, not the
                        // AST's own `NOT IN` flag — the latter is already
                        // encoded in `operator: PredicateOp::NotIn`.
                        // Using `*negated` here would double-negate
                        // `col NOT IN (...)` (op=NotIn AND is_negated=true),
                        // which reads as `IN` and produces spurious
                        // contradictions when two `NOT IN` clauses on the
                        // same column have disjoint value sets.
                        is_negated,
                        is_reflexive: false,
                        between_bounds: None,
                        join_scope_id: 0,
                        span: *span,
                    },
                    outer_refs,
                ));
            }
        }

        // ── BETWEEN / NOT BETWEEN
        //
        // Positive BETWEEN is the AND-conjunction `col >= low AND col <= high`.
        // When both bounds are literal we decompose into two `PredicateFact`s
        // sharing the BETWEEN span so within-scope analyses (Q-PRED-CONTRA /
        // REDUNDANT / TAUTOLOGY) can compose the decomposed bounds with
        // sibling `>=` / `>` / `<=` / `<` atoms. An opaque `BETWEEN`
        // atom carries no comparable bound, so emitting that form would
        // make sibling-comparison rules skip the BETWEEN bound entirely.
        //
        // `NOT BETWEEN` is OR-disjunctive (`< low OR > high`) and stays
        // emitted as a single opaque `NOT BETWEEN` fact for this pass;
        // OR-branching atom emission requires `or_counter` plumbing the
        // BETWEEN arm doesn't currently set up. Non-literal bounds also
        // fall back to the opaque form.
        ScalarExpr::Between { expr, low, high, negated, span } => {
            if let ScalarExpr::Column { column, .. } | ScalarExpr::OuterRef { column, .. } =
                expr.as_ref()
            {
                let col_ref = column_id_to_ref(*column, bindings, scan_index);
                let has_temporal = scalar_has_temporal(low, func_catalog)
                    || scalar_has_temporal(high, func_catalog);
                let mut function_calls = Vec::new();
                collect_function_calls(source, low, &mut function_calls);
                collect_function_calls(source, high, &mut function_calls);
                let outer_refs = if is_outer_ref_column(*column, bindings) {
                    vec![col_ref.clone()]
                } else {
                    vec![]
                };
                let low_lit = match low.as_ref() {
                    ScalarExpr::Lit { value, .. } => lit_to_predicate_value(value),
                    _ => None,
                };
                let high_lit = match high.as_ref() {
                    ScalarExpr::Lit { value, .. } => lit_to_predicate_value(value),
                    _ => None,
                };
                // Closed interval bounds, when both ends are literals —
                // consumed by the BETWEEN/NOT-BETWEEN complement tautology
                // pattern. Computed before the decomposition branch moves
                // `low_lit` / `high_lit` into the Compare atoms.
                let between_bounds = match (&low_lit, &high_lit) {
                    (Some(l), Some(h)) => Some(crate::context::node_metadata::BetweenBounds {
                        low: l.clone(),
                        high: h.clone(),
                    }),
                    _ => None,
                };
                if !*negated && low_lit.is_some() && high_lit.is_some() {
                    // Lower bound atom: col >= low
                    out.push(PredWithCorr::new(
                        PredicateFact {
                            column_id: Some(*column),
                            column: col_ref.clone(),
                            operator: PredicateOp::Compare(
                                crate::ir::scalar::ComparisonOp::GtEq,
                            ),
                            literal_value: low_lit,
                            rhs_text: None,
                            has_temporal,
                            has_subquery: false,
                            subquery_column: None,
                            subquery_table: None,
                            function_calls: function_calls.clone(),
                            in_list_values: None,
                            context,
                            logical_operator: parent_logical_op,
                            or_branch_id: *or_counter,
                            not_isolation_id: current_not_isolation,
                            scope_id,
                            join_scope_id: 0,
                            is_negated: false,
                            is_reflexive: false,
                            between_bounds: None,
                            span: *span,
                        },
                        outer_refs.clone(),
                    ));
                    // Upper bound atom: col <= high
                    out.push(PredWithCorr::new(
                        PredicateFact {
                            column_id: Some(*column),
                            column: col_ref,
                            operator: PredicateOp::Compare(
                                crate::ir::scalar::ComparisonOp::LtEq,
                            ),
                            literal_value: high_lit,
                            rhs_text: None,
                            has_temporal,
                            has_subquery: false,
                            subquery_column: None,
                            subquery_table: None,
                            function_calls,
                            in_list_values: None,
                            context,
                            logical_operator: parent_logical_op,
                            or_branch_id: *or_counter,
                            not_isolation_id: current_not_isolation,
                            scope_id,
                            join_scope_id: 0,
                            is_negated: false,
                            is_reflexive: false,
                            between_bounds: None,
                            span: *span,
                        },
                        outer_refs,
                    ));
                } else {
                    let operator = if *negated {
                        PredicateOp::NotBetween
                    } else {
                        PredicateOp::Between
                    };
                    out.push(PredWithCorr::new(
                        PredicateFact {
                            column_id: Some(*column),
                            column: col_ref,
                            operator,
                            literal_value: None,
                            rhs_text: None,
                            has_temporal,
                            has_subquery: false,
                            subquery_column: None,
                            subquery_table: None,
                            function_calls,
                            in_list_values: None,
                            between_bounds,
                            context,
                            logical_operator: parent_logical_op,
                            or_branch_id: *or_counter,
                            not_isolation_id: current_not_isolation,
                            scope_id,
                            join_scope_id: 0,
                            is_negated: *negated,
                            is_reflexive: false,
                            span: *span,
                        },
                        outer_refs,
                    ));
                }
            }
        }

        // ── [NOT] IN (subquery) / QuantifiedCmp
        ScalarExpr::QuantifiedCmp {
            op,
            left,
            right,
            span,
            quantifier,
            negated,
        } => {
            use crate::ir::scalar::ComparisonOp;
            if let ScalarExpr::Column { column, .. } | ScalarExpr::OuterRef { column, .. } =
                left.as_ref()
            {
                let col_ref = column_id_to_ref(*column, bindings, scan_index);
                // Compose the typed predicate-op variant from `(op, quantifier,
                // effective_negated)`. `(Eq, Any)` and `(NotEq, All)` normalize
                // to [`PredicateOp::In`] / [`PredicateOp::NotIn`] under the
                // semantic equivalences `col = ANY(s) ≡ col IN s` and
                // `col <> ALL(s) ≡ col NOT IN s`. Outer-NOT-wrap propagation
                // lives in `is_negated`, the node's own `negated` field
                // carries the surface `NOT IN` lift, and their XOR is the
                // effective negation.
                let effective_negated = is_negated ^ *negated;
                let predicate_quantifier = match quantifier {
                    Quantifier::Any => PredicateQuantifier::Any,
                    Quantifier::All => PredicateQuantifier::All,
                };
                let operator = match (op, quantifier) {
                    (ComparisonOp::Eq, Quantifier::Any) => {
                        if effective_negated {
                            PredicateOp::NotIn
                        } else {
                            PredicateOp::In
                        }
                    }
                    (ComparisonOp::NotEq, Quantifier::All) => {
                        if effective_negated {
                            PredicateOp::In
                        } else {
                            PredicateOp::NotIn
                        }
                    }
                    _ => PredicateOp::Quantified {
                        op: *op,
                        quantifier: predicate_quantifier,
                    },
                };
                let has_subquery = matches!(right, QuantifiedRhs::Subquery(..));
                let (subquery_column, subquery_table) = match right {
                    QuantifiedRhs::Subquery(plan, _) => {
                        subquery_column_and_table_from_plan(plan, bindings)
                    }
                    QuantifiedRhs::List(_) => (None, None),
                };
                let outer_refs = if is_outer_ref_column(*column, bindings) {
                    vec![col_ref.clone()]
                } else {
                    vec![]
                };
                out.push(PredWithCorr::new(
                    PredicateFact {
                        column_id: Some(*column),
                        column: col_ref,
                        operator,
                        literal_value: None,
                        rhs_text: None,
                        has_temporal: false,
                        has_subquery,
                        subquery_column,
                        subquery_table,
                        function_calls: Vec::new(),
                        in_list_values: None,
                        context,
                        logical_operator: parent_logical_op,
                        or_branch_id: *or_counter,
                        not_isolation_id: current_not_isolation,
                        scope_id,
                        join_scope_id: 0,
                        is_negated: effective_negated,
                        is_reflexive: false,
                        between_bounds: None,
                        span: *span,
                    },
                    outer_refs,
                ));
            }
        }

        // ── Leaf / non-predicate scalars — do not emit PredicateFact
        ScalarExpr::Column { .. }
        | ScalarExpr::OuterRef { .. }
        | ScalarExpr::Lit { .. }
        | ScalarExpr::Cast { .. }
        | ScalarExpr::Case { .. }
        | ScalarExpr::FuncCall { .. }
        | ScalarExpr::WindowFn { .. }
        | ScalarExpr::FieldAccess { .. }
        | ScalarExpr::Lambda { .. }
        | ScalarExpr::PatternVarRef { .. }
        | ScalarExpr::Exists { .. }
        | ScalarExpr::ScalarSubquery { .. }
        // Non-NOT unary operators (e.g. unary minus): no predicate.
        | ScalarExpr::UnaryOp { .. }
        | ScalarExpr::Opaque { .. } => {}
    }
}

// ── ScopedPredicateFact wrapping ─────────────────────────────────────────────

fn wrap_in_scope(
    predicates: &[PredWithCorr],
    scope_path: Vec<ScopeDescriptor>,
    scope_id: u32,
    parent_scope_id: u32,
) -> Vec<ScopedPredicateFact> {
    predicates
        .iter()
        .map(|p| ScopedPredicateFact {
            predicate: p.fact.clone(),
            scope_path: scope_path.clone(),
            scope_id,
            parent_scope_id,
            is_correlated: !p.outer_refs.is_empty(),
            outer_column_refs: p.outer_refs.clone(),
        })
        .collect()
}

// ── Plan walk ────────────────────────────────────────────────────────────────

/// Result of the plan-level predicate walk. All three vecs are in
/// document order (depth-first): outer-scope predicates come before
/// inner-scope predicates.
pub struct PlanPredicates {
    pub where_predicates: Vec<PredicateFact>,
    pub having_predicates: Vec<PredicateFact>,
    pub scoped_predicates: Vec<ScopedPredicateFact>,
    /// Per walk-plan scope_id, the set of `ColumnId`s owned by that
    /// scope's plan subtree (stopping at nested scope boundaries:
    /// subqueries inside `Exists`/`ScalarSubquery`/`QuantifiedCmp::Subquery`,
    /// `DerivedTable` bodies, `WithScope` CTE bodies). Populated by
    /// `walk_plan` at each scope-entry point and consumed by the
    /// post-extraction correlation-lift pass in
    /// `extract_predicates_from_plan`. Internal — not part of the
    /// public extraction contract.
    pub(crate) scope_owned_columns:
        std::collections::BTreeMap<u32, std::collections::BTreeSet<ColumnId>>,
    /// Per walk-plan scope_id, the set of AST `NodeId`s of `Scan` /
    /// `Values` / `CteRef` / `ModelRef` nodes in that scope's plan
    /// subtree (stopping at nested scope boundaries). Used by the
    /// correlation-lift pass to identify the owning scope of an
    /// inner-atom column whose binding origin is
    /// `ColumnOrigin::Table { table_node }` — the lowerer allocates
    /// fresh `ColumnId`s for correlated refs (so direct ColumnId
    /// lookup against `scope_owned_columns` misses), but the
    /// underlying scan NodeId is stable and unambiguously identifies
    /// the source scope.
    pub(crate) scope_owned_scan_nodes:
        std::collections::BTreeMap<u32, std::collections::BTreeSet<crate::ast::NodeId>>,
    /// Per walk-plan scope_id, `true` iff the chain of subquery
    /// descents from the outermost scope to this scope was uniformly
    /// lift-eligible — i.e., every intermediate descent was via
    /// `EXISTS`-positive / `IN`-positive / `= ANY`-positive / scalar
    /// subquery in `=` comparison position, AND each intermediate
    /// subquery sat in outer AND-conjunctive non-negated position.
    /// The outermost scope is always `true` (no descent).
    /// Populated by `walk_subquery_predicates_in_expr` / `walk_plan`
    /// and consumed by the lift post-pass.
    pub(crate) scope_lift_eligibility: std::collections::BTreeMap<u32, bool>,
}

/// Extract [`PredicateFact`] and [`ScopedPredicateFact`] from a
/// lowered plan.
///
/// `source` is the original SQL text; used to populate `rhs_text` for
/// complex RHS expressions and `FunctionCallFact::expression`. Pass `""`
/// when source bytes are not available (e.g. in unit tests).
///
/// `scan_index` must be built for the same plan via
/// [`crate::ir::expression_fact::build_scan_index`] before calling
/// this function; it is required for column-to-table resolution.
pub fn extract_predicates_from_plan(
    source: &str,
    plan: &RelPlan,
    bindings: &BindingTable,
    scan_index: &ScanIndex,
    func_catalog: &crate::ir::catalog::FunctionCatalog,
) -> PlanPredicates {
    let mut result = PlanPredicates {
        where_predicates: Vec::new(),
        having_predicates: Vec::new(),
        scoped_predicates: Vec::new(),
        scope_owned_columns: std::collections::BTreeMap::new(),
        scope_owned_scan_nodes: std::collections::BTreeMap::new(),
        scope_lift_eligibility: std::collections::BTreeMap::new(),
    };
    let main_scope = vec![ScopeDescriptor::new(ScopeKind::MainQuery, 0)];
    let mut or_counter = 0u32;
    let mut not_isolation_counter = 0u32;
    let mut scope_id_gen = 1u32;
    let mut join_scope_counter = 0u32;

    // Seed the outermost scope's owned columns + scan_nodes + lift
    // eligibility. The outermost is always lift-eligible from itself
    // (chain length 0).
    let mut outer_owned_cols = std::collections::BTreeSet::new();
    let mut outer_owned_scans = std::collections::BTreeSet::new();
    collect_scope_owned_identities(plan, &mut outer_owned_cols, &mut outer_owned_scans);
    result.scope_owned_columns.insert(0, outer_owned_cols);
    result.scope_owned_scan_nodes.insert(0, outer_owned_scans);
    result.scope_lift_eligibility.insert(0, true);

    walk_plan(
        source,
        plan,
        bindings,
        scan_index,
        func_catalog,
        &main_scope,
        0, // scope_id
        0, // parent_scope_id
        &mut or_counter,
        &mut not_isolation_counter,
        &mut scope_id_gen,
        &mut join_scope_counter,
        &mut result,
    );

    // Post-extraction correlation lift: emit duplicate
    // `ScopedPredicateFact`s tagged with the outer scope's id for each
    // inner atom that references an outer-owned column at lift-eligible
    // position. See [`apply_correlation_lift`] for the contract.
    apply_correlation_lift(&mut result, bindings);

    result
}

/// Recursive plan walk for predicate extraction.
///
/// - `source`: original SQL text for `rhs_text` / `expression` reconstruction.
/// - `scope_path`: current scope stack (for `ScopedPredicateFact.scope_path`).
/// - `scope_id`: scope identifier for the current level.
/// - `parent_scope_id`: parent's scope identifier.
/// - `or_counter`: shared OR-branch counter (reset per-scope).
/// - `not_isolation_counter`: shared monotonic NOT-subtree id counter.
/// - `scope_id_gen`: monotonic scope-id generator.
/// - `join_scope_counter`: monotonic counter incremented at each JOIN
///   node; predicates extracted from a JOIN's ON clause are stamped
///   with the incremented value so within-scope contradiction analysis
///   keeps sibling JOIN ONs in separate buckets.
#[allow(clippy::too_many_arguments)]
fn walk_plan(
    source: &str,
    plan: &RelPlan,
    bindings: &BindingTable,
    scan_index: &ScanIndex,
    func_catalog: &crate::ir::catalog::FunctionCatalog,
    scope_path: &[ScopeDescriptor],
    scope_id: u32,
    parent_scope_id: u32,
    or_counter: &mut u32,
    not_isolation_counter: &mut u32,
    scope_id_gen: &mut u32,
    join_scope_counter: &mut u32,
    result: &mut PlanPredicates,
) {
    match plan {
        // ── WHERE / QUALIFY Filter ────────────────────────────────────────
        RelPlan::Filter {
            input,
            predicate,
            kind,
            ..
        } => {
            use crate::ir::plan::FilterKind;
            // QUALIFY predicates are not `where_predicates`;
            // they're emitted on `has_qualify`. Skip extraction for QUALIFY.
            if matches!(kind, FilterKind::Where) {
                let mut local_preds: Vec<PredWithCorr> = Vec::new();
                let mut local_or = *or_counter;
                extract_scalar_predicates(
                    source,
                    predicate,
                    bindings,
                    scan_index,
                    func_catalog,
                    PredicateContext::Where,
                    scope_id,
                    &mut local_or,
                    not_isolation_counter,
                    0,
                    false,
                    None,
                    &mut local_preds,
                );
                *or_counter = local_or;

                // `where_predicates` only collects from the immediate scope (scope_id == 0
                // means main query or CTE body being merged into the outer list).
                result
                    .where_predicates
                    .extend(local_preds.iter().map(|p| p.fact.clone()));
                result.scoped_predicates.extend(wrap_in_scope(
                    &local_preds,
                    scope_path.to_vec(),
                    scope_id,
                    parent_scope_id,
                ));
                walk_subquery_predicates_in_expr(
                    source,
                    predicate,
                    bindings,
                    scan_index,
                    func_catalog,
                    scope_path,
                    scope_id,
                    scope_id_gen,
                    join_scope_counter,
                    result,
                );
            }
            walk_plan(
                source,
                input,
                bindings,
                scan_index,
                func_catalog,
                scope_path,
                scope_id,
                parent_scope_id,
                or_counter,
                not_isolation_counter,
                scope_id_gen,
                join_scope_counter,
                result,
            );
        }

        // ── HAVING (inside Aggregate) ─────────────────────────────────────
        RelPlan::Aggregate { input, having, .. } => {
            if let Some(having_expr) = having {
                let mut local_preds: Vec<PredWithCorr> = Vec::new();
                let mut local_or = 0u32;
                extract_scalar_predicates(
                    source,
                    having_expr,
                    bindings,
                    scan_index,
                    func_catalog,
                    PredicateContext::Having,
                    scope_id,
                    &mut local_or,
                    not_isolation_counter,
                    0,
                    false,
                    None,
                    &mut local_preds,
                );

                result
                    .having_predicates
                    .extend(local_preds.iter().map(|p| p.fact.clone()));
                result.scoped_predicates.extend(wrap_in_scope(
                    &local_preds,
                    scope_path.to_vec(),
                    scope_id,
                    parent_scope_id,
                ));
                walk_subquery_predicates_in_expr(
                    source,
                    having_expr,
                    bindings,
                    scan_index,
                    func_catalog,
                    scope_path,
                    scope_id,
                    scope_id_gen,
                    join_scope_counter,
                    result,
                );
            }
            walk_plan(
                source,
                input,
                bindings,
                scan_index,
                func_catalog,
                scope_path,
                scope_id,
                parent_scope_id,
                or_counter,
                not_isolation_counter,
                scope_id_gen,
                join_scope_counter,
                result,
            );
        }

        // ── CTE scoping: merge CTE body predicates into outer scope ───────
        RelPlan::WithScope { ctes, body, .. } => {
            // Walk CTE bodies: each contributes its predicates with a
            // `ScopeKind::Cte` tag in `scoped_predicates` but flows into
            // the outer `where_predicates` / `having_predicates`.
            for cte in ctes {
                let cte_name = cte.name.as_str().to_string();
                let cte_scope_id = {
                    let id = *scope_id_gen;
                    *scope_id_gen += 1;
                    id
                };
                // Populate scope identity + lift eligibility maps for
                // this CTE body. CTE bodies are not correlated to the
                // enclosing scope (no outer-ref lift from inside).
                let mut cte_cols = std::collections::BTreeSet::new();
                let mut cte_scans = std::collections::BTreeSet::new();
                match &cte.body {
                    CteBody::NonRecursive(b) => {
                        collect_scope_owned_identities(b, &mut cte_cols, &mut cte_scans)
                    }
                    CteBody::Recursive { anchor, .. } => {
                        collect_scope_owned_identities(anchor, &mut cte_cols, &mut cte_scans)
                    }
                }
                result.scope_owned_columns.insert(cte_scope_id, cte_cols);
                result
                    .scope_owned_scan_nodes
                    .insert(cte_scope_id, cte_scans);
                result.scope_lift_eligibility.insert(cte_scope_id, false);
                let cte_scope = {
                    let mut path = scope_path.to_vec();
                    path.push(ScopeDescriptor::new(
                        ScopeKind::Cte { cte_name },
                        path.len() as u32,
                    ));
                    path
                };
                let mut cte_or = 0u32;
                let mut cte_not_iso = 0u32;
                walk_cte_body(
                    source,
                    &cte.body,
                    bindings,
                    scan_index,
                    func_catalog,
                    &cte_scope,
                    cte_scope_id,
                    scope_id,
                    &mut cte_or,
                    &mut cte_not_iso,
                    scope_id_gen,
                    join_scope_counter,
                    result,
                );
            }
            walk_plan(
                source,
                body,
                bindings,
                scan_index,
                func_catalog,
                scope_path,
                scope_id,
                parent_scope_id,
                or_counter,
                not_isolation_counter,
                scope_id_gen,
                join_scope_counter,
                result,
            );
        }

        // ── DerivedTable: scope boundary ──────────────────────────────────
        RelPlan::DerivedTable { input, alias, .. } => {
            let alias_str = alias.as_ref().map(|a| a.as_str().to_string());
            let derived_scope_id = {
                let id = *scope_id_gen;
                *scope_id_gen += 1;
                id
            };
            // Populate scope maps. DerivedTables are not correlated
            // subquery boundaries (standard FROM-derived tables; LATERAL
            // is a separate construct), so lift_eligibility = false.
            let mut dt_cols = std::collections::BTreeSet::new();
            let mut dt_scans = std::collections::BTreeSet::new();
            collect_scope_owned_identities(input, &mut dt_cols, &mut dt_scans);
            result.scope_owned_columns.insert(derived_scope_id, dt_cols);
            result
                .scope_owned_scan_nodes
                .insert(derived_scope_id, dt_scans);
            result
                .scope_lift_eligibility
                .insert(derived_scope_id, false);
            let derived_scope = {
                let mut path = scope_path.to_vec();
                path.push(ScopeDescriptor::new(
                    ScopeKind::DerivedTable { alias: alias_str },
                    path.len() as u32,
                ));
                path
            };
            let mut inner_or = 0u32;
            let mut inner_not_iso = 0u32;
            // Inner predicates go to scoped_predicates only — NOT
            // into where_predicates / having_predicates.
            let mut inner_result = PlanPredicates {
                where_predicates: Vec::new(),
                having_predicates: Vec::new(),
                scoped_predicates: Vec::new(),
                scope_owned_columns: std::collections::BTreeMap::new(),
                scope_owned_scan_nodes: std::collections::BTreeMap::new(),
                scope_lift_eligibility: std::collections::BTreeMap::new(),
            };
            walk_plan(
                source,
                input,
                bindings,
                scan_index,
                func_catalog,
                &derived_scope,
                derived_scope_id,
                scope_id,
                &mut inner_or,
                &mut inner_not_iso,
                scope_id_gen,
                join_scope_counter,
                &mut inner_result,
            );
            // Merge scoped_predicates only.
            result
                .scoped_predicates
                .extend(inner_result.scoped_predicates);
        }

        // ── DML predicates ────────────────────────────────────────────────
        RelPlan::Update {
            from, predicate, ..
        } => {
            if let Some(pred) = predicate {
                walk_subquery_predicates_in_expr(
                    source,
                    pred,
                    bindings,
                    scan_index,
                    func_catalog,
                    scope_path,
                    scope_id,
                    scope_id_gen,
                    join_scope_counter,
                    result,
                );
                let mut local_preds: Vec<PredWithCorr> = Vec::new();
                let mut local_or = *or_counter;
                extract_scalar_predicates(
                    source,
                    pred,
                    bindings,
                    scan_index,
                    func_catalog,
                    PredicateContext::Where,
                    scope_id,
                    &mut local_or,
                    not_isolation_counter,
                    0,
                    false,
                    None,
                    &mut local_preds,
                );
                *or_counter = local_or;
                result
                    .where_predicates
                    .extend(local_preds.iter().map(|p| p.fact.clone()));
                result.scoped_predicates.extend(wrap_in_scope(
                    &local_preds,
                    scope_path.to_vec(),
                    scope_id,
                    parent_scope_id,
                ));
            }
            if let Some(f) = from {
                walk_plan(
                    source,
                    f,
                    bindings,
                    scan_index,
                    func_catalog,
                    scope_path,
                    scope_id,
                    parent_scope_id,
                    or_counter,
                    not_isolation_counter,
                    scope_id_gen,
                    join_scope_counter,
                    result,
                );
            }
        }

        RelPlan::Delete {
            using, predicate, ..
        } => {
            if let Some(pred) = predicate {
                walk_subquery_predicates_in_expr(
                    source,
                    pred,
                    bindings,
                    scan_index,
                    func_catalog,
                    scope_path,
                    scope_id,
                    scope_id_gen,
                    join_scope_counter,
                    result,
                );
                let mut local_preds: Vec<PredWithCorr> = Vec::new();
                let mut local_or = *or_counter;
                extract_scalar_predicates(
                    source,
                    pred,
                    bindings,
                    scan_index,
                    func_catalog,
                    PredicateContext::Where,
                    scope_id,
                    &mut local_or,
                    not_isolation_counter,
                    0,
                    false,
                    None,
                    &mut local_preds,
                );
                *or_counter = local_or;
                result
                    .where_predicates
                    .extend(local_preds.iter().map(|p| p.fact.clone()));
                result.scoped_predicates.extend(wrap_in_scope(
                    &local_preds,
                    scope_path.to_vec(),
                    scope_id,
                    parent_scope_id,
                ));
            }
            if let Some(u) = using {
                walk_plan(
                    source,
                    u,
                    bindings,
                    scan_index,
                    func_catalog,
                    scope_path,
                    scope_id,
                    parent_scope_id,
                    or_counter,
                    not_isolation_counter,
                    scope_id_gen,
                    join_scope_counter,
                    result,
                );
            }
        }

        RelPlan::Merge {
            source: merge_source,
            on,
            branches,
            ..
        } => {
            // MERGE ON atoms describe the row-matching condition. They
            // get a dedicated scope_id so ON-internal contradictions
            // (e.g. `ON tgt.x = 'A' AND tgt.x = 'B'`) get detected by
            // Q-PRED-CONTRA on their own bucket. ON atoms emit to
            // `scoped_predicates` only (not `where_predicates`) so
            // downstream consumers that read `where_predicates`
            // (diff facts, etc.) see the unchanged set.
            use crate::ir::plan::MergeBranchKind;
            let merge_on_scope_id = {
                let id = *scope_id_gen;
                *scope_id_gen += 1;
                id
            };
            let mut on_preds: Vec<PredWithCorr> = Vec::new();
            let mut on_or = 0u32;
            extract_scalar_predicates(
                source,
                on,
                bindings,
                scan_index,
                func_catalog,
                PredicateContext::Where,
                merge_on_scope_id,
                &mut on_or,
                not_isolation_counter,
                0,
                false,
                None,
                &mut on_preds,
            );
            result.scoped_predicates.extend(wrap_in_scope(
                &on_preds,
                scope_path.to_vec(),
                merge_on_scope_id,
                scope_id,
            ));
            walk_subquery_predicates_in_expr(
                source,
                on,
                bindings,
                scan_index,
                func_catalog,
                scope_path,
                merge_on_scope_id,
                scope_id_gen,
                join_scope_counter,
                result,
            );

            // WHEN clause conditions: each WHEN branch is a logically
            // independent execution context (only one fires per row),
            // so allocate a fresh `scope_id` per branch. Within a
            // branch, `or_counter` starts at 0 so AND-chain atoms
            // share `or_branch_id = 0` and the within-scope
            // contradiction / range / redundant detectors pick them
            // up. Cross-branch contradictions are out of scope —
            // disjoint scope ids enforce that boundary structurally.
            for branch in branches {
                if let Some(ref cond) = branch.predicate {
                    let branch_scope_id = {
                        let id = *scope_id_gen;
                        *scope_id_gen += 1;
                        id
                    };
                    let mut local_preds: Vec<PredWithCorr> = Vec::new();
                    let mut local_or = 0u32;
                    extract_scalar_predicates(
                        source,
                        cond,
                        bindings,
                        scan_index,
                        func_catalog,
                        PredicateContext::Where,
                        branch_scope_id,
                        &mut local_or,
                        not_isolation_counter,
                        0,
                        false,
                        None,
                        &mut local_preds,
                    );
                    result
                        .where_predicates
                        .extend(local_preds.iter().map(|p| p.fact.clone()));
                    result.scoped_predicates.extend(wrap_in_scope(
                        &local_preds,
                        scope_path.to_vec(),
                        branch_scope_id,
                        scope_id,
                    ));
                    // For WhenMatched branches: ALSO conjoin ON atoms
                    // into the branch's scope so the matched row's
                    // combined ON + WHEN MATCHED constraint set forms
                    // one Q-PRED-CONTRA bucket. WhenNotMatched* are
                    // intentionally excluded — the ON equality side
                    // didn't match for those branches, so the matched-
                    // row constraint semantics don't apply.
                    if matches!(branch.kind, MergeBranchKind::WhenMatched) {
                        let mut on_into_branch: Vec<PredWithCorr> = Vec::new();
                        let mut branch_on_or = 0u32;
                        extract_scalar_predicates(
                            source,
                            on,
                            bindings,
                            scan_index,
                            func_catalog,
                            PredicateContext::Where,
                            branch_scope_id,
                            &mut branch_on_or,
                            not_isolation_counter,
                            0,
                            false,
                            None,
                            &mut on_into_branch,
                        );
                        // Emit to scoped_predicates only (avoid
                        // duplicate ON atoms in where_predicates).
                        result.scoped_predicates.extend(wrap_in_scope(
                            &on_into_branch,
                            scope_path.to_vec(),
                            branch_scope_id,
                            scope_id,
                        ));
                    }
                    walk_subquery_predicates_in_expr(
                        source,
                        cond,
                        bindings,
                        scan_index,
                        func_catalog,
                        scope_path,
                        branch_scope_id,
                        scope_id_gen,
                        join_scope_counter,
                        result,
                    );
                }
            }
            walk_plan(
                source,
                merge_source,
                bindings,
                scan_index,
                func_catalog,
                scope_path,
                scope_id,
                parent_scope_id,
                or_counter,
                not_isolation_counter,
                scope_id_gen,
                join_scope_counter,
                result,
            );
        }

        // ── Project: walk subquery plans embedded in projection items
        // (scalar subquery `(SELECT … FROM … WHERE …)` carries its own
        // body whose predicates Q-PRED-* / Q-NULL-* should see), then
        // walk input.
        RelPlan::Project { input, items, .. } => {
            for item in items {
                if let ProjectItem::Expr(e) = item {
                    walk_subquery_predicates_in_expr(
                        source,
                        &e.expr,
                        bindings,
                        scan_index,
                        func_catalog,
                        scope_path,
                        scope_id,
                        scope_id_gen,
                        join_scope_counter,
                        result,
                    );
                }
            }
            walk_plan(
                source,
                input,
                bindings,
                scan_index,
                func_catalog,
                scope_path,
                scope_id,
                parent_scope_id,
                or_counter,
                not_isolation_counter,
                scope_id_gen,
                join_scope_counter,
                result,
            );
        }

        // ── Scope-preserving single-input operators ───────────────────────
        RelPlan::Window { input, .. }
        | RelPlan::Sort { input, .. }
        | RelPlan::Limit { input, .. }
        | RelPlan::TableSample { input, .. }
        | RelPlan::Pivot { input, .. }
        | RelPlan::Unpivot { input, .. }
        | RelPlan::MatchRecognize { input, .. }
        | RelPlan::ConnectBy { input, .. }
        | RelPlan::Unnest { input, .. } => {
            walk_plan(
                source,
                input,
                bindings,
                scan_index,
                func_catalog,
                scope_path,
                scope_id,
                parent_scope_id,
                or_counter,
                not_isolation_counter,
                scope_id_gen,
                join_scope_counter,
                result,
            );
        }

        // ── Join: walk both sides + extract `on` predicates ───────────────
        //
        // Many shops put filter conditions in JOIN ON clauses rather than
        // WHERE (`ON s.status = 'CANCELLED' AND s.customer_id = c.id`).
        // Without this extraction the IR-fold view of `where_predicates`
        // silently drops those filters and downstream consumers (e.g.
        // `cross_scope_contra_signals`) miss real contradictions.
        //
        // Predicates from ALL join kinds are extracted uniformly with
        // `PredicateContext::JoinCondition`. Outer-join semantics (a
        // predicate on the null-padded side does not constrain that
        // side's rows) are enforced at *consumption time* — consumers
        // already filter via `derived_facts.nullable_tables`.
        RelPlan::Join {
            left,
            right,
            on,
            kind,
            ..
        } => {
            walk_plan(
                source,
                left,
                bindings,
                scan_index,
                func_catalog,
                scope_path,
                scope_id,
                parent_scope_id,
                or_counter,
                not_isolation_counter,
                scope_id_gen,
                join_scope_counter,
                result,
            );
            walk_plan(
                source,
                right,
                bindings,
                scan_index,
                func_catalog,
                scope_path,
                scope_id,
                parent_scope_id,
                or_counter,
                not_isolation_counter,
                scope_id_gen,
                join_scope_counter,
                result,
            );
            if let Some(on_expr) = on {
                let mut local_preds: Vec<PredWithCorr> = Vec::new();
                let mut local_or = *or_counter;
                extract_scalar_predicates(
                    source,
                    on_expr,
                    bindings,
                    scan_index,
                    func_catalog,
                    PredicateContext::JoinCondition,
                    scope_id,
                    &mut local_or,
                    not_isolation_counter,
                    0,
                    false,
                    None,
                    &mut local_preds,
                );
                *or_counter = local_or;
                // INNER JOIN ON predicates are row filters at the
                // query scope (non-matching rows are dropped),
                // semantically identical to WHERE — they merge with
                // sibling INNER ONs and WHERE atoms via
                // `join_scope_id = 0`.
                //
                // OUTER joins (LEFT / RIGHT / FULL) and ASOF only
                // gate which right-side rows MATCH; non-matching
                // left rows survive with NULLs on the right. Sibling
                // OUTER ONs are independent gates, so each gets a
                // fresh non-zero `join_scope_id` to isolate its
                // atoms from siblings (without losing intra-ON
                // contradictions like `ON a=1 AND a=2`).
                //
                // SEMI / ANTI ON predicates have existence
                // semantics; the safe conservative choice is to
                // isolate them too — sibling SEMI joins do merge
                // semantically, but the existence-pattern is not a
                // value-domain constraint,
                // so isolating avoids edge-case FPs on the ANTI
                // (negated-existence) side without giving up real
                // detection (SEMI's existence-based contradiction
                // is not what Q-PRED-CONTRA targets).
                let merges_with_where = matches!(kind, JoinKind::Inner);
                let this_join_id = if merges_with_where {
                    0
                } else {
                    *join_scope_counter += 1;
                    *join_scope_counter
                };
                for p in &mut local_preds {
                    p.fact.join_scope_id = this_join_id;
                }
                result
                    .where_predicates
                    .extend(local_preds.iter().map(|p| p.fact.clone()));
                result.scoped_predicates.extend(wrap_in_scope(
                    &local_preds,
                    scope_path.to_vec(),
                    scope_id,
                    parent_scope_id,
                ));
                walk_subquery_predicates_in_expr(
                    source,
                    on_expr,
                    bindings,
                    scan_index,
                    func_catalog,
                    scope_path,
                    scope_id,
                    scope_id_gen,
                    join_scope_counter,
                    result,
                );
            }
        }

        // ── SetOp: independent scopes — not merged into outer where_predicates
        RelPlan::SetOp { inputs, .. } => {
            for branch in inputs {
                let branch_scope_id = {
                    let id = *scope_id_gen;
                    *scope_id_gen += 1;
                    id
                };
                let mut branch_or = 0u32;
                let mut branch_not_iso = 0u32;
                let mut branch_result = PlanPredicates {
                    where_predicates: Vec::new(),
                    having_predicates: Vec::new(),
                    scoped_predicates: Vec::new(),
                    scope_owned_columns: std::collections::BTreeMap::new(),
                    scope_owned_scan_nodes: std::collections::BTreeMap::new(),
                    scope_lift_eligibility: std::collections::BTreeMap::new(),
                };
                walk_plan(
                    source,
                    branch,
                    bindings,
                    scan_index,
                    func_catalog,
                    scope_path,
                    branch_scope_id,
                    scope_id,
                    &mut branch_or,
                    &mut branch_not_iso,
                    scope_id_gen,
                    join_scope_counter,
                    &mut branch_result,
                );
                // Merge scoped_predicates only — where/having do not propagate.
                result
                    .scoped_predicates
                    .extend(branch_result.scoped_predicates);
            }
        }

        // ── Explain wrapper ───────────────────────────────────────────────
        RelPlan::Explain { body, .. } => {
            walk_plan(
                source,
                body,
                bindings,
                scan_index,
                func_catalog,
                scope_path,
                scope_id,
                parent_scope_id,
                or_counter,
                not_isolation_counter,
                scope_id_gen,
                join_scope_counter,
                result,
            );
        }

        // ── CreateAsQuery: walk the body ──────────────────────────────────
        RelPlan::CreateAsQuery { body, .. } => {
            if let Some(b) = body.as_deref() {
                walk_plan(
                    source,
                    b,
                    bindings,
                    scan_index,
                    func_catalog,
                    scope_path,
                    scope_id,
                    parent_scope_id,
                    or_counter,
                    not_isolation_counter,
                    scope_id_gen,
                    join_scope_counter,
                    result,
                );
            }
        }

        // ── Insert ───────────────────────────────────────────────────────
        RelPlan::Insert {
            source: insert_source,
            ..
        } => {
            walk_insert_source(
                source,
                insert_source,
                bindings,
                scan_index,
                func_catalog,
                scope_path,
                scope_id,
                parent_scope_id,
                or_counter,
                not_isolation_counter,
                scope_id_gen,
                join_scope_counter,
                result,
            );
        }

        RelPlan::MultiInsert {
            source: multi_source,
            ..
        } => {
            walk_plan(
                source,
                multi_source,
                bindings,
                scan_index,
                func_catalog,
                scope_path,
                scope_id,
                parent_scope_id,
                or_counter,
                not_isolation_counter,
                scope_id_gen,
                join_scope_counter,
                result,
            );
        }

        // ── Terminals: no predicates ──────────────────────────────────────
        RelPlan::Scan { .. }
        | RelPlan::Values { .. }
        | RelPlan::CteRef { .. }
        | RelPlan::ModelRef { .. }
        | RelPlan::TableFunction { .. }
        | RelPlan::CreateTableForm { .. }
        | RelPlan::InvalidInput { .. }
        | RelPlan::ParseRecovery { .. }
        | RelPlan::Opaque { .. } => {}
    }
}

#[allow(clippy::too_many_arguments)]
fn walk_cte_body(
    source: &str,
    body: &CteBody,
    bindings: &BindingTable,
    scan_index: &ScanIndex,
    func_catalog: &crate::ir::catalog::FunctionCatalog,
    scope_path: &[ScopeDescriptor],
    scope_id: u32,
    parent_scope_id: u32,
    or_counter: &mut u32,
    not_isolation_counter: &mut u32,
    scope_id_gen: &mut u32,
    join_scope_counter: &mut u32,
    result: &mut PlanPredicates,
) {
    match body {
        CteBody::NonRecursive(plan) => {
            walk_plan(
                source,
                plan,
                bindings,
                scan_index,
                func_catalog,
                scope_path,
                scope_id,
                parent_scope_id,
                or_counter,
                not_isolation_counter,
                scope_id_gen,
                join_scope_counter,
                result,
            );
        }
        CteBody::Recursive { anchor, step, .. } => {
            walk_plan(
                source,
                anchor,
                bindings,
                scan_index,
                func_catalog,
                scope_path,
                scope_id,
                parent_scope_id,
                or_counter,
                not_isolation_counter,
                scope_id_gen,
                join_scope_counter,
                result,
            );
            walk_plan(
                source,
                step,
                bindings,
                scan_index,
                func_catalog,
                scope_path,
                scope_id,
                parent_scope_id,
                or_counter,
                not_isolation_counter,
                scope_id_gen,
                join_scope_counter,
                result,
            );
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn walk_insert_source(
    sql: &str,
    source: &InsertSource,
    bindings: &BindingTable,
    scan_index: &ScanIndex,
    func_catalog: &crate::ir::catalog::FunctionCatalog,
    scope_path: &[ScopeDescriptor],
    scope_id: u32,
    parent_scope_id: u32,
    or_counter: &mut u32,
    not_isolation_counter: &mut u32,
    scope_id_gen: &mut u32,
    join_scope_counter: &mut u32,
    result: &mut PlanPredicates,
) {
    match source {
        InsertSource::Query(plan) | InsertSource::Values(plan) => {
            walk_plan(
                sql,
                plan,
                bindings,
                scan_index,
                func_catalog,
                scope_path,
                scope_id,
                parent_scope_id,
                or_counter,
                not_isolation_counter,
                scope_id_gen,
                join_scope_counter,
                result,
            );
        }
        InsertSource::DefaultValues => {}
    }
}

/// Walk every subquery [`RelPlan`] embedded in a predicate's scalar
/// tree (`EXISTS`, scalar subquery, `x IN (SELECT …)` quantified-RHS)
/// with a fresh scope id per subquery so within-subquery
/// `WHERE`/`HAVING` atoms get their own bucket in the per-(scope,
/// column) constraint map. Only `scoped_predicates` merge into the
/// outer result — the subquery body's atoms never leak into the
/// caller's `where_predicates` / `having_predicates`, matching the
/// `DerivedTable` / `SetOp` isolation pattern.
#[allow(clippy::too_many_arguments)]
fn walk_subquery_predicates_in_expr(
    source: &str,
    expr: &ScalarExpr,
    bindings: &BindingTable,
    scan_index: &ScanIndex,
    func_catalog: &crate::ir::catalog::FunctionCatalog,
    outer_scope_path: &[ScopeDescriptor],
    outer_scope_id: u32,
    scope_id_gen: &mut u32,
    join_scope_counter: &mut u32,
    result: &mut PlanPredicates,
) {
    let mut sites: Vec<SubqueryLiftSite<'_>> = Vec::new();
    collect_subquery_plans_with_lift_info(expr, false, false, false, &mut sites);
    // Outer scope's cumulative lift-eligibility from the outermost.
    // For the lift chain to extend INTO a child subquery, this must
    // be true (parent reachable) AND the descent must be lift-eligible.
    let outer_lift_ok = result
        .scope_lift_eligibility
        .get(&outer_scope_id)
        .copied()
        .unwrap_or(false);
    for site in sites {
        let subquery_scope_id = {
            let id = *scope_id_gen;
            *scope_id_gen += 1;
            id
        };
        let sub_scope = {
            let mut path = outer_scope_path.to_vec();
            path.push(ScopeDescriptor::new(
                ScopeKind::ScalarSubquery,
                path.len() as u32,
            ));
            path
        };
        // Cumulative lift-eligibility for this subquery scope.
        let child_lift_ok = outer_lift_ok && site.lift_eligible_descent;
        // Populate scope identity + eligibility maps for the child
        // subquery scope BEFORE the recursive walk, so any further
        // descents from inside it can read the parent's eligibility.
        let mut sub_cols = std::collections::BTreeSet::new();
        let mut sub_scans = std::collections::BTreeSet::new();
        collect_scope_owned_identities(site.plan, &mut sub_cols, &mut sub_scans);
        result
            .scope_owned_columns
            .insert(subquery_scope_id, sub_cols);
        result
            .scope_owned_scan_nodes
            .insert(subquery_scope_id, sub_scans);
        result
            .scope_lift_eligibility
            .insert(subquery_scope_id, child_lift_ok);

        let mut sub_or = 0u32;
        let mut sub_not_iso = 0u32;
        let mut sub_result = PlanPredicates {
            where_predicates: Vec::new(),
            having_predicates: Vec::new(),
            scoped_predicates: Vec::new(),
            scope_owned_columns: std::collections::BTreeMap::new(),
            scope_owned_scan_nodes: std::collections::BTreeMap::new(),
            scope_lift_eligibility: std::collections::BTreeMap::new(),
        };
        // Seed the sub_result's maps so the inner walk's nested
        // descents see the chain. The outer map already carries
        // entries for every scope we've allocated; mirror the entries
        // relevant to the inner walk into sub_result so its own
        // `walk_subquery_predicates_in_expr` calls (for nested
        // subqueries) can compute cumulative eligibility correctly.
        sub_result
            .scope_lift_eligibility
            .insert(subquery_scope_id, child_lift_ok);
        sub_result.scope_owned_columns.insert(
            subquery_scope_id,
            result
                .scope_owned_columns
                .get(&subquery_scope_id)
                .cloned()
                .unwrap_or_default(),
        );
        sub_result.scope_owned_scan_nodes.insert(
            subquery_scope_id,
            result
                .scope_owned_scan_nodes
                .get(&subquery_scope_id)
                .cloned()
                .unwrap_or_default(),
        );

        walk_plan(
            source,
            site.plan,
            bindings,
            scan_index,
            func_catalog,
            &sub_scope,
            subquery_scope_id,
            outer_scope_id,
            &mut sub_or,
            &mut sub_not_iso,
            scope_id_gen,
            join_scope_counter,
            &mut sub_result,
        );
        // Merge inner's scoped_predicates AND inner's scope maps back
        // into the outer result so the lift post-pass sees every
        // scope's owned-columns and eligibility.
        result
            .scoped_predicates
            .extend(sub_result.scoped_predicates);
        for (sid, owned) in sub_result.scope_owned_columns {
            result.scope_owned_columns.entry(sid).or_insert(owned);
        }
        for (sid, scans) in sub_result.scope_owned_scan_nodes {
            result.scope_owned_scan_nodes.entry(sid).or_insert(scans);
        }
        for (sid, elig) in sub_result.scope_lift_eligibility {
            result.scope_lift_eligibility.entry(sid).or_insert(elig);
        }
    }
}
