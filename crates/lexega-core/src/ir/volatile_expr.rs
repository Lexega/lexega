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

/// True iff `expr` directly reaches a volatile catalog function, or
/// references a column that is volatile (per `input` for a local column,
/// or `outer` for a correlated one). Column references resolve
/// against the precomputed volatile sets instead of re-walking the plan.
///
/// Subquery bodies (`Exists`, `ScalarSubquery`, `QuantifiedCmp` over a
/// subquery RHS) are intentionally NOT descended into: volatility inside
/// a subquery affects that subquery's own determinism (computed when its
/// own scope is folded), not the containing scalar expression here.
pub fn expr_is_volatile(
    expr: &ScalarExpr,
    local: &BTreeSet<ColumnId>,
    outer: &BTreeSet<ColumnId>,
    catalog: &FunctionCatalog,
) -> bool {
    match expr {
        ScalarExpr::FuncCall {
            func,
            args,
            named_args,
            ..
        } => {
            resolved_func_is_volatile(func, catalog)
                || args
                    .iter()
                    .any(|a| expr_is_volatile(a, local, outer, catalog))
                || named_args
                    .iter()
                    .any(|(_, a)| expr_is_volatile(a, local, outer, catalog))
        }
        ScalarExpr::Like {
            expr,
            pattern,
            escape,
            ..
        } => {
            expr_is_volatile(expr, local, outer, catalog)
                || expr_is_volatile(pattern, local, outer, catalog)
                || escape
                    .as_deref()
                    .is_some_and(|e| expr_is_volatile(e, local, outer, catalog))
        }
        ScalarExpr::BinOp { left, right, .. } => {
            expr_is_volatile(left, local, outer, catalog)
                || expr_is_volatile(right, local, outer, catalog)
        }
        ScalarExpr::LogicalChain { operands, .. } => operands
            .iter()
            .any(|o| expr_is_volatile(o, local, outer, catalog)),
        ScalarExpr::UnaryOp { arg, .. } => expr_is_volatile(arg, local, outer, catalog),
        ScalarExpr::Case {
            operand,
            branches,
            else_,
            ..
        } => {
            operand
                .as_ref()
                .is_some_and(|o| expr_is_volatile(o, local, outer, catalog))
                || branches.iter().any(|(c, r)| {
                    expr_is_volatile(c, local, outer, catalog)
                        || expr_is_volatile(r, local, outer, catalog)
                })
                || else_
                    .as_ref()
                    .is_some_and(|e| expr_is_volatile(e, local, outer, catalog))
        }
        ScalarExpr::Cast { expr, .. } => expr_is_volatile(expr, local, outer, catalog),
        ScalarExpr::InList { expr, list, .. } => {
            expr_is_volatile(expr, local, outer, catalog)
                || list
                    .iter()
                    .any(|e| expr_is_volatile(e, local, outer, catalog))
        }
        ScalarExpr::Between {
            expr, low, high, ..
        } => {
            expr_is_volatile(expr, local, outer, catalog)
                || expr_is_volatile(low, local, outer, catalog)
                || expr_is_volatile(high, local, outer, catalog)
        }
        ScalarExpr::QuantifiedCmp { left, right, .. } => {
            expr_is_volatile(left, local, outer, catalog)
                || match right {
                    QuantifiedRhs::List(items) => items
                        .iter()
                        .any(|e| expr_is_volatile(e, local, outer, catalog)),
                    QuantifiedRhs::Subquery(_, _) => false,
                }
        }
        ScalarExpr::WindowFn { call, .. } => {
            resolved_func_is_volatile(&call.func, catalog)
                || call
                    .args
                    .iter()
                    .any(|a| expr_is_volatile(a, local, outer, catalog))
                || call
                    .partition_by
                    .iter()
                    .any(|p| expr_is_volatile(p, local, outer, catalog))
                || call
                    .order_by
                    .iter()
                    .any(|k| expr_is_volatile(&k.expr, local, outer, catalog))
        }
        ScalarExpr::FieldAccess { base, .. } => expr_is_volatile(base, local, outer, catalog),
        ScalarExpr::Lambda { body, .. } => expr_is_volatile(body, local, outer, catalog),
        // A local reference resolves against this scope's volatile set; a
        // correlated reference (an outer id carried by `Column`, or an
        // `OuterRef`) resolves against the enclosing-scope set.
        ScalarExpr::Column { column, .. } | ScalarExpr::OuterRef { column, .. } => {
            local.contains(column) || outer.contains(column)
        }
        ScalarExpr::Lit { .. }
        | ScalarExpr::PatternVarRef { .. }
        | ScalarExpr::Exists { .. }
        | ScalarExpr::ScalarSubquery { .. }
        | ScalarExpr::Opaque { .. } => false,
    }
}
