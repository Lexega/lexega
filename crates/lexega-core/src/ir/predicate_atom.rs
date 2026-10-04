// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Predicate atoms: a bare comparison, null test, `IN` list or `BETWEEN`
//! over one column, as a [`PredicateFact`].

use super::column::{BindingTable, ColumnId, ColumnOrigin};
use super::scalar::{Lit, ScalarExpr, UnaryOpKind};
use crate::context::node_metadata::{
    ColumnRef, ColumnSourceType, LogicalOperator, PredicateContext, PredicateFact, PredicateOp,
};
use crate::lexer::Span;

/// The column reference a bound column presents at `span`.
pub fn column_ref_for(bindings: &BindingTable, id: ColumnId, span: Span) -> ColumnRef {
    match bindings.get(id) {
        Some(binding) => {
            let mut col_ref = ColumnRef::new(binding.display_name.clone()).with_span(span);
            match &binding.origin {
                ColumnOrigin::Table { .. } => {
                    col_ref = col_ref.with_source_type(ColumnSourceType::BaseTable);
                }
                ColumnOrigin::Computed { .. } => {
                    col_ref = col_ref.with_source_type(ColumnSourceType::Unknown);
                }
                ColumnOrigin::SetOp { .. }
                | ColumnOrigin::OuterRef { .. }
                | ColumnOrigin::RecursiveRef { .. } => {}
            }
            col_ref
        }
        None => ColumnRef::new(String::new()).with_span(span),
    }
}

/// Classify a bare `column <cmp> literal` / `literal <cmp> column` /
/// `column IS [NOT] NULL` / `column [NOT] IN (literals)` leaf into a
/// synthetic [`PredicateFact`] (field set mirrors the extraction side,
/// scope/branch ids zeroed — callers stamp their own). Single source of
/// truth for leaf→atom classification. Returns `None` for any other
/// shape.
pub fn expr_to_simple_fact(
    expr: &ScalarExpr,
    bindings: &BindingTable,
    is_negated: bool,
) -> Option<(ColumnId, PredicateFact)> {
    match expr {
        ScalarExpr::BinOp {
            op,
            left,
            right,
            span,
        } => {
            // (`x IS NULL` / `x IS NOT NULL` lower to `UnaryOp`, never
            // a `BinOp`, so no IS-operator handling is needed here.)
            let cmp = comparison_op_to_kind(*op)?;
            // Reflexive `x <op> x`: same column both sides, no literal.
            // The tautology detector's reflexive pattern keys on
            // `is_reflexive`. Must precede the column/literal match, which
            // requires exactly one operand to be a literal.
            if let (
                ScalarExpr::Column {
                    column: lc,
                    span: lspan,
                },
                ScalarExpr::Column { column: rc, .. },
            ) = (left.as_ref(), right.as_ref())
            {
                if lc == rc {
                    let column_ref = column_ref_for(bindings, *lc, *lspan);
                    return Some((
                        *lc,
                        PredicateFact {
                            column: column_ref,
                            operator: PredicateOp::Compare(cmp),
                            literal_value: None,
                            rhs_text: None,
                            has_temporal: false,
                            has_subquery: false,
                            subquery_column: None,
                            subquery_table: None,
                            function_calls: Vec::new(),
                            context: PredicateContext::Where,
                            logical_operator: Some(LogicalOperator::And),
                            or_branch_id: 0,
                            not_isolation_id: 0,
                            scope_id: 0,
                            join_scope_id: 0,
                            in_list_values: None,
                            between_bounds: None,
                            is_negated,
                            is_reflexive: true,
                            span: *span,
                            column_id: Some(*lc),
                        },
                    ));
                }
            }
            let (col_id, col_span, literal, swapped) =
                if let (ScalarExpr::Column { column, span }, ScalarExpr::Lit { value, .. }) =
                    (left.as_ref(), right.as_ref())
                {
                    (*column, *span, lit_to_value(value)?, false)
                } else if let (ScalarExpr::Lit { value, .. }, ScalarExpr::Column { column, span }) =
                    (left.as_ref(), right.as_ref())
                {
                    (*column, *span, lit_to_value(value)?, true)
                } else {
                    return None;
                };
            let cmp = if swapped {
                swap_comparison_operator(cmp)
            } else {
                cmp
            };
            let column_ref = column_ref_for(bindings, col_id, col_span);
            Some((
                col_id,
                PredicateFact {
                    column: column_ref,
                    operator: PredicateOp::Compare(cmp),
                    literal_value: Some(literal),
                    rhs_text: None,
                    has_temporal: false,
                    has_subquery: false,
                    subquery_column: None,
                    subquery_table: None,
                    function_calls: Vec::new(),
                    context: PredicateContext::Where,
                    logical_operator: Some(LogicalOperator::And),
                    or_branch_id: 0,
                    not_isolation_id: 0,
                    scope_id: 0,
                    join_scope_id: 0,
                    in_list_values: None,
                    is_negated,
                    is_reflexive: false,
                    between_bounds: None,
                    span: *span,
                    column_id: Some(col_id),
                },
            ))
        }
        ScalarExpr::UnaryOp { op, arg, span }
            if matches!(op, UnaryOpKind::IsNull | UnaryOpKind::IsNotNull) =>
        {
            let ScalarExpr::Column {
                column: col_id,
                span: col_span,
            } = arg.as_ref()
            else {
                return None;
            };
            let (col_id, col_span) = (*col_id, *col_span);
            let column_ref = column_ref_for(bindings, col_id, col_span);
            let op_kind = match op {
                UnaryOpKind::IsNull => PredicateOp::IsNull,
                UnaryOpKind::IsNotNull => PredicateOp::IsNotNull,
                // Arm guard admits only IsNull / IsNotNull.
                UnaryOpKind::Not
                | UnaryOpKind::Neg
                | UnaryOpKind::Plus
                | UnaryOpKind::AtLocal
                | UnaryOpKind::Collate
                | UnaryOpKind::Prior
                | UnaryOpKind::Spread => return None,
            };
            Some((
                col_id,
                PredicateFact {
                    column: column_ref,
                    operator: op_kind,
                    literal_value: None,
                    rhs_text: None,
                    has_temporal: false,
                    has_subquery: false,
                    subquery_column: None,
                    subquery_table: None,
                    function_calls: Vec::new(),
                    context: PredicateContext::Where,
                    logical_operator: Some(LogicalOperator::And),
                    or_branch_id: 0,
                    not_isolation_id: 0,
                    scope_id: 0,
                    join_scope_id: 0,
                    in_list_values: None,
                    is_negated,
                    is_reflexive: false,
                    between_bounds: None,
                    span: *span,
                    column_id: Some(col_id),
                },
            ))
        }
        // `col [NOT] IN (lit, …)` — all-literal list. The tautology
        // detector pairs `IN`/`NOT IN` over an identical set as a
        // complement (Pattern 3c). A non-literal element makes the set
        // unknowable → no fact.
        ScalarExpr::InList {
            expr,
            list,
            negated,
            span,
        } => {
            let (ScalarExpr::Column {
                column: col_id,
                span: col_span,
            }
            | ScalarExpr::OuterRef {
                column: col_id,
                span: col_span,
                ..
            }) = expr.as_ref()
            else {
                return None;
            };
            let (col_id, col_span) = (*col_id, *col_span);
            let mut vals = Vec::with_capacity(list.len());
            for item in list {
                let ScalarExpr::Lit { value, .. } = item else {
                    return None;
                };
                vals.push(lit_to_value(value)?);
            }
            let column_ref = column_ref_for(bindings, col_id, col_span);
            let operator = if *negated {
                PredicateOp::NotIn
            } else {
                PredicateOp::In
            };
            Some((
                col_id,
                PredicateFact {
                    column: column_ref,
                    operator,
                    literal_value: None,
                    rhs_text: None,
                    has_temporal: false,
                    has_subquery: false,
                    subquery_column: None,
                    subquery_table: None,
                    function_calls: Vec::new(),
                    context: PredicateContext::Where,
                    logical_operator: Some(LogicalOperator::And),
                    or_branch_id: 0,
                    not_isolation_id: 0,
                    scope_id: 0,
                    join_scope_id: 0,
                    in_list_values: Some(vals),
                    between_bounds: None,
                    is_negated,
                    is_reflexive: false,
                    span: *span,
                    column_id: Some(col_id),
                },
            ))
        }

        // `col [NOT] BETWEEN lo AND hi` — both bounds literal. The
        // tautology detector pairs `BETWEEN`/`NOT BETWEEN` over an
        // identical interval as a complement (Pattern 3e).
        ScalarExpr::Between {
            expr,
            low,
            high,
            negated,
            span,
        } => {
            let (ScalarExpr::Column {
                column: col_id,
                span: col_span,
            }
            | ScalarExpr::OuterRef {
                column: col_id,
                span: col_span,
                ..
            }) = expr.as_ref()
            else {
                return None;
            };
            let (col_id, col_span) = (*col_id, *col_span);
            let (ScalarExpr::Lit { value: lo, .. }, ScalarExpr::Lit { value: hi, .. }) =
                (low.as_ref(), high.as_ref())
            else {
                return None;
            };
            let bounds = crate::context::node_metadata::BetweenBounds {
                low: lit_to_value(lo)?,
                high: lit_to_value(hi)?,
            };
            let column_ref = column_ref_for(bindings, col_id, col_span);
            let operator = if *negated {
                PredicateOp::NotBetween
            } else {
                PredicateOp::Between
            };
            Some((
                col_id,
                PredicateFact {
                    column: column_ref,
                    operator,
                    literal_value: None,
                    rhs_text: None,
                    has_temporal: false,
                    has_subquery: false,
                    subquery_column: None,
                    subquery_table: None,
                    function_calls: Vec::new(),
                    context: PredicateContext::Where,
                    logical_operator: Some(LogicalOperator::And),
                    or_branch_id: 0,
                    not_isolation_id: 0,
                    scope_id: 0,
                    join_scope_id: 0,
                    in_list_values: None,
                    between_bounds: Some(bounds),
                    is_negated,
                    is_reflexive: false,
                    span: *span,
                    column_id: Some(col_id),
                },
            ))
        }

        ScalarExpr::Lit { .. }
        | ScalarExpr::Column { .. }
        | ScalarExpr::OuterRef { .. }
        // A chain is boolean structure, not an atom — callers descend
        // it before reaching here.
        | ScalarExpr::LogicalChain { .. }
        | ScalarExpr::UnaryOp { .. }
        | ScalarExpr::FuncCall { .. }
        | ScalarExpr::Case { .. }
        | ScalarExpr::Cast { .. }
        | ScalarExpr::Like { .. }
        | ScalarExpr::Exists { .. }
        | ScalarExpr::ScalarSubquery { .. }
        | ScalarExpr::QuantifiedCmp { .. }
        | ScalarExpr::WindowFn { .. }
        | ScalarExpr::FieldAccess { .. }
        | ScalarExpr::Lambda { .. }
        | ScalarExpr::PatternVarRef { .. }
        | ScalarExpr::Opaque { .. } => None,
    }
}

/// The comparison a binary operator performs, when it is one.
pub fn comparison_op_to_kind(
    op: crate::ir::scalar::BinOpKind,
) -> Option<crate::ir::scalar::ComparisonOp> {
    if let crate::ir::scalar::BinOpKind::Cmp(c) = op {
        Some(c)
    } else {
        None
    }
}

/// The operator that holds once a comparison's operands are swapped.
pub fn swap_comparison_operator(
    op: crate::ir::scalar::ComparisonOp,
) -> crate::ir::scalar::ComparisonOp {
    use crate::ir::scalar::ComparisonOp;
    match op {
        ComparisonOp::Eq => ComparisonOp::Eq,
        ComparisonOp::NotEq => ComparisonOp::NotEq,
        ComparisonOp::Lt => ComparisonOp::Gt,
        ComparisonOp::LtEq => ComparisonOp::GtEq,
        ComparisonOp::Gt => ComparisonOp::Lt,
        ComparisonOp::GtEq => ComparisonOp::LtEq,
    }
}

/// A literal's value text; `None` for `NULL`.
pub fn lit_to_value(lit: &Lit) -> Option<String> {
    match lit {
        Lit::Null => None,
        Lit::Bool(b) => Some(b.to_string()),
        Lit::Integer(s) | Lit::Float(s) | Lit::Str(s) => Some(s.clone()),
        Lit::Bytes { value, .. } | Lit::Typed { value, .. } | Lit::Variant(value) => {
            Some(value.clone())
        }
    }
}
