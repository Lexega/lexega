// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Volatility of a lowered scalar expression: whether it calls a
//! function the catalog marks volatile, or references a column already
//! known to carry a volatile value.

use std::collections::BTreeSet;

use super::catalog::{Determinism, FunctionCatalog};
use super::column::ColumnId;
use super::plan::ResolvedFunc;
use super::scalar::{QuantifiedRhs, ScalarExpr};

/// True iff `func` resolves to a catalog entry tagged
/// [`Determinism::Volatile`]. Unresolved functions are conservatively
/// treated as non-volatile so user-defined functions outside the
/// catalog are not flagged as non-deterministic by default.
///
/// The single leaf check shared by this fold and the aggregate / window
/// witness determinism in `src/facts/extract.rs`.
pub fn resolved_func_is_volatile(func: &ResolvedFunc, catalog: &FunctionCatalog) -> bool {
    match func {
        ResolvedFunc::Resolved { id, .. } => catalog
            .signature(*id)
            .map(|s| s.determinism == Determinism::Volatile)
            .unwrap_or(false),
        ResolvedFunc::Unresolved { .. } => false,
    }
}

/// True iff `func` is volatile and its calls in one statement may
/// return different values: volatile, and not one the catalog says
/// returns one value per statement.
fn resolved_func_varies_per_call(func: &ResolvedFunc, catalog: &FunctionCatalog) -> bool {
    match func {
        ResolvedFunc::Resolved { id, .. } => {
            resolved_func_is_volatile(func, catalog) && !catalog.is_statement_stable(*id)
        }
        ResolvedFunc::Unresolved { .. } => false,
    }
}

/// True iff `expr` directly reaches a volatile catalog function, or
/// references a column in `volatile`, a correlated reference included.
/// Column references resolve against the precomputed volatile set
/// instead of re-walking the plan.
///
/// Subquery bodies (`Exists`, `ScalarSubquery`, `QuantifiedCmp` over a
/// subquery RHS) are intentionally NOT descended into: volatility inside
/// a subquery affects that subquery's own determinism (computed when its
/// own scope is folded), not the containing scalar expression here.
pub fn expr_is_volatile(
    expr: &ScalarExpr,
    volatile: &BTreeSet<ColumnId>,
    catalog: &FunctionCatalog,
) -> bool {
    reaches(expr, volatile, &|func| {
        resolved_func_is_volatile(func, catalog)
    })
}

/// As [`expr_is_volatile`], for a value that may differ between two
/// evaluations in one statement: a call to a volatile function the
/// catalog does not say returns one value per statement, or a column of
/// `varying`.
pub(crate) fn expr_varies_per_row(
    expr: &ScalarExpr,
    varying: &BTreeSet<ColumnId>,
    catalog: &FunctionCatalog,
) -> bool {
    reaches(expr, varying, &|func| {
        resolved_func_varies_per_call(func, catalog)
    })
}

/// Whether `expr`, outside its nested plans, calls a function `called`
/// holds of or reads a column of `columns`.
fn reaches(
    expr: &ScalarExpr,
    columns: &BTreeSet<ColumnId>,
    called: &dyn Fn(&ResolvedFunc) -> bool,
) -> bool {
    let walk = |e: &ScalarExpr| reaches(e, columns, called);
    match expr {
        ScalarExpr::FuncCall {
            func,
            args,
            named_args,
            ..
        } => called(func) || args.iter().any(walk) || named_args.iter().any(|(_, a)| walk(a)),
        ScalarExpr::Like {
            expr,
            pattern,
            escape,
            ..
        } => walk(expr) || walk(pattern) || escape.as_deref().is_some_and(walk),
        ScalarExpr::BinOp { left, right, .. } => walk(left) || walk(right),
        ScalarExpr::LogicalChain { operands, .. } | ScalarExpr::OperatorChain { operands, .. } => {
            operands.iter().any(walk)
        }
        ScalarExpr::UnaryOp { arg, .. } => walk(arg),
        ScalarExpr::Case {
            operand,
            branches,
            else_,
            ..
        } => {
            operand.as_deref().is_some_and(walk)
                || branches.iter().any(|(c, r)| walk(c) || walk(r))
                || else_.as_deref().is_some_and(walk)
        }
        ScalarExpr::Cast { expr, .. } => walk(expr),
        ScalarExpr::InList { expr, list, .. } => walk(expr) || list.iter().any(walk),
        ScalarExpr::Between {
            expr, low, high, ..
        } => walk(expr) || walk(low) || walk(high),
        ScalarExpr::QuantifiedCmp { left, right, .. } => {
            walk(left)
                || match right {
                    QuantifiedRhs::List(items) => items.iter().any(walk),
                    QuantifiedRhs::Subquery(_, _) => false,
                }
        }
        ScalarExpr::RowCmp { left, .. } => left.iter().any(walk),
        ScalarExpr::WindowFn { call, .. } => {
            called(&call.func)
                || call.args.iter().any(walk)
                || call.partition_by.iter().any(walk)
                || call.order_by.iter().any(|k| walk(&k.expr))
        }
        ScalarExpr::FieldAccess { base, .. } => walk(base),
        ScalarExpr::Lambda { body, .. } => walk(body),
        ScalarExpr::Column { column, .. } | ScalarExpr::OuterRef { column, .. } => {
            columns.contains(column)
        }
        ScalarExpr::Lit { .. }
        | ScalarExpr::PatternVarRef { .. }
        | ScalarExpr::Exists { .. }
        | ScalarExpr::ScalarSubquery { .. }
        | ScalarExpr::Opaque { .. } => false,
    }
}
