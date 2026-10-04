// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Whether a predicate holds for every row.
//!
//! [`is_always_true`] judges one boolean expression by its shape: constant
//! comparisons, boolean structure over them, and disjunctions that exhaust
//! a column's value domain. [`has_tautology_where`] applies it to the
//! predicate that bounds a statement — a DML `WHERE`, a `MERGE … ON`, the
//! immediate scope's `WHERE`.
//!
//! Three shapes are every-row only when a column holds no NULLs:
//! `col IS NOT NULL`, reflexive `x = x`, and a domain-exhausting
//! disjunction with no `IS NULL` arm. They escalate only when the caller
//! supplies a [`NonNullProof`]; without one they stay bounded.

use super::column::{BindingTable, ColumnId, ColumnOrigin};
use super::plan::{FilterKind, ProjectItem, RelPlan};
use super::queries::for_each_immediate;
use super::scalar::{BinOpKind, ComparisonOp, Lit, QuantifiedRhs, ScalarExpr};
use crate::ast::{AstExpr, NodeId};
use crate::context::node_metadata::{IdentKey, TableRef};
use crate::lexer::Span;

/// Proof that a column holds no NULLs.
pub trait NonNullProof {
    /// Whether `col` is proven non-null. `target` is the statement's DML
    /// target, when it has one: a reference to one of its columns may
    /// carry an id of its own, and is then resolved against the target
    /// by name.
    fn proven_not_null(&self, col: ColumnId, target: Option<&TableRef>) -> bool;
}

/// Whether the statement's outer-scope WHERE / ON predicate holds for every row.
///
/// Returns `true` when the statement's outer-scope WHERE / ON
/// predicate is a syntactic tautology (per [`is_always_true`]):
///
/// - **UPDATE / DELETE**: the explicit `WHERE` expression.
/// - **MERGE**: the `ON` expression (the MERGE-bounding predicate;
///   `is_always_true` is invoked with `target = None` so the
///   IN-subquery self-reference branch is suppressed).
/// - **SELECT / INSERT…SELECT / CTAS / CVAS / CMVAS and every
///   other query-bearing shape**: any `Filter { kind: Where }`
///   present in the immediate scope (walked via
///   [`for_each_immediate`]; subqueries, CTE bodies, and
///   derived-table bodies are excluded).
///
/// `Explain` and `WithScope` wrappers transparently delegate to
/// their inner body.
pub fn has_tautology_where(
    plan: &RelPlan,
    source: &str,
    bindings: &BindingTable,
    proof: Option<&dyn NonNullProof>,
) -> bool {
    match plan {
        RelPlan::Update {
            target,
            predicate: Some(pred),
            ..
        } => is_always_true(pred, source, Some(target), bindings, proof),
        RelPlan::Delete {
            target,
            predicate: Some(pred),
            ..
        } => is_always_true(pred, source, Some(target), bindings, proof),
        // MERGE passes `target: None`: the ON predicate's
        // every-row judgment must NOT enable the IN-subquery
        // self-reference branch (which keys on the DML target), and the
        // realistic MERGE footgun (`ON 1=1` / `ON TRUE` / domain
        // exhaustion) is caught via the constant / coverage paths that
        // need no target. Reflexive `t.col = t.col` over an aliased
        // MERGE target is an obscure shape left as a sound under-call.
        RelPlan::Merge { on, .. } => is_always_true(on, source, None, bindings, proof),
        RelPlan::Explain { body, .. } => has_tautology_where(body, source, bindings, proof),
        RelPlan::WithScope { body, .. } => has_tautology_where(body, source, bindings, proof),

        RelPlan::Update {
            predicate: None, ..
        }
        | RelPlan::Delete {
            predicate: None, ..
        } => false,

        // Query-bearing shapes: walk the immediate scope for a
        // WHERE Filter whose predicate is always-true. INSERT…SELECT
        // and CTAS reach through `for_each_immediate` to their
        // source SELECT's Filter the same way `has_where()` does.
        RelPlan::Scan { .. }
        | RelPlan::Values { .. }
        | RelPlan::CteRef { .. }
        | RelPlan::ModelRef { .. }
        | RelPlan::Project { .. }
        | RelPlan::Filter { .. }
        | RelPlan::Aggregate { .. }
        | RelPlan::Window { .. }
        | RelPlan::Sort { .. }
        | RelPlan::Limit { .. }
        | RelPlan::Join { .. }
        | RelPlan::SetOp { .. }
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
        | RelPlan::CreateAsQuery { .. }
        | RelPlan::CreateTableForm { .. } => {
            let mut found = false;
            for_each_immediate(plan, |p| {
                if found {
                    return;
                }
                if let RelPlan::Filter {
                    kind: FilterKind::Where,
                    predicate,
                    ..
                } = p
                {
                    if is_always_true(predicate, source, None, bindings, proof) {
                        found = true;
                    }
                }
            });
            found
        }

        RelPlan::ParseRecovery { .. } | RelPlan::Opaque { .. } | RelPlan::InvalidInput { .. } => {
            false
        }
    }
}

/// Whether a policy body or predicate holds for every row. Policy
/// parameters carry no non-null proof, so the verdict rests on
/// constants, structure and domain exhaustion alone.
///
/// `node_id` and `parameters` are the policy statement's parameter scope,
/// as [`super::lower::with_lowered_policy_predicate`] takes them.
pub fn policy_body_is_always_true(
    expr: &AstExpr,
    source: &str,
    node_id: NodeId,
    parameters: &[(IdentKey, Span)],
) -> bool {
    super::lower::with_lowered_policy_predicate(
        expr,
        source,
        node_id,
        parameters,
        |scalar, bindings| is_always_true(scalar, source, None, bindings, None),
    )
    .unwrap_or(false)
}

/// Flatten an OR-chain (`Or(Or(a, b), c)` and any associativity) into
/// its disjunct leaves.
fn collect_or_leaves<'a>(expr: &'a ScalarExpr, out: &mut Vec<&'a ScalarExpr>) {
    match expr {
        ScalarExpr::BinOp {
            op: BinOpKind::Or,
            left,
            right,
            ..
        } => {
            collect_or_leaves(left, out);
            collect_or_leaves(right, out);
        }
        // The N-ary spelling of the same OR chain. Descending here is
        // load-bearing: treating the chain as one opaque leaf would
        // hide every disjunct from the domain-exhaustion analysis and
        // silently stop `is_always_true` firing on `a OR b OR 1=1`.
        // An `AND` chain is not a disjunct — it stays a leaf, exactly
        // as a `BinOp { And }` does in the fall-through group below.
        ScalarExpr::LogicalChain {
            op: crate::ir::scalar::LogicalOp::Or,
            operands,
            ..
        } => {
            for operand in operands {
                collect_or_leaves(operand, out);
            }
        }
        ScalarExpr::Column { .. }
        | ScalarExpr::OuterRef { .. }
        | ScalarExpr::Lit { .. }
        | ScalarExpr::LogicalChain { .. }
        | ScalarExpr::BinOp { .. }
        | ScalarExpr::UnaryOp { .. }
        | ScalarExpr::FuncCall { .. }
        | ScalarExpr::Case { .. }
        | ScalarExpr::Cast { .. }
        | ScalarExpr::InList { .. }
        | ScalarExpr::Between { .. }
        | ScalarExpr::Like { .. }
        | ScalarExpr::Exists { .. }
        | ScalarExpr::ScalarSubquery { .. }
        | ScalarExpr::QuantifiedCmp { .. }
        | ScalarExpr::WindowFn { .. }
        | ScalarExpr::FieldAccess { .. }
        | ScalarExpr::Lambda { .. }
        | ScalarExpr::PatternVarRef { .. }
        | ScalarExpr::Opaque { .. } => out.push(expr),
    }
}

/// True iff `or_expr`'s disjuncts provably exhaust a column's value
/// domain — the disjunctive arm of [`is_always_true`].
///
/// Each disjunct that is a bare atom (`col <cmp> lit` /
/// `col IS [NOT] NULL`, via
/// [`super::predicate_atom::expr_to_simple_fact`]) becomes a
/// synthetic `PredicateFact` in its own OR branch; the chain is then
/// judged by the canonical tautology detector
/// ([`super::constraint_types::detect_tautologies_in_scope`]).
///
/// A witness is accepted only when an `IS NULL` atom exists on the
/// same column key: the detector's eq/neq and complementary-range
/// patterns cover every non-NULL value, and the `IS NULL` disjunct
/// covers the NULL row, so the whole chain is TRUE for every row
/// under three-valued logic. Non-atom disjuncts contribute no atoms
/// and cannot weaken the proof — OR is monotone.
fn or_chain_domain_exhaustion(
    or_expr: &ScalarExpr,
    bindings: &BindingTable,
    target: Option<&TableRef>,
    proof: Option<&dyn NonNullProof>,
) -> bool {
    use super::constraint_types::{detect_tautologies_in_scope, pred_to_col_key};
    use super::predicate_atom::expr_to_simple_fact;
    use crate::context::node_metadata::{LogicalOperator, PredicateOp};

    let mut leaves = Vec::new();
    collect_or_leaves(or_expr, &mut leaves);
    if leaves.len() < 2 {
        return false;
    }
    let mut facts = Vec::new();
    for (branch, leaf) in leaves.iter().enumerate() {
        if let Some((_, mut fact)) = expr_to_simple_fact(leaf, bindings, false) {
            fact.or_branch_id = branch as u32;
            fact.logical_operator = Some(LogicalOperator::Or);
            facts.push(fact);
        }
    }
    if facts.is_empty() {
        return false;
    }
    let findings = detect_tautologies_in_scope(&facts, bindings, 0, 0);
    findings.iter().any(|finding| {
        // The detected tautology covers every non-NULL row. It is
        // every-row iff the NULL row is also covered: either by an
        // explicit `IS NULL` disjunct on the same column, or because the
        // column is *proven* non-null (no NULL row exists to spare) — the
        // same proof that escalates reflexive `x = x` and
        // `col IS NOT NULL`.
        let null_disjunct = facts.iter().any(|f| {
            matches!(f.operator, PredicateOp::IsNull)
                && pred_to_col_key(f, bindings).as_str() == finding.column
        });
        if null_disjunct {
            return true;
        }
        match proof {
            Some(p) => facts.iter().any(|f| {
                pred_to_col_key(f, bindings).as_str() == finding.column
                    && f.column_id
                        .is_some_and(|cid| p.proven_not_null(cid, target))
            }),
            None => false,
        }
    })
}

/// True iff `predicate` is a syntactic tautology — a SQL always-true
/// shape, including the disjunctive domain-exhaustion arm below.
/// Both [`has_tautology_where`] and [`policy_body_is_always_true`]
/// consume this answer.
///
/// The check is **structural**: it matches specific syntactic shapes:
///
/// - `TRUE` literal (case-insensitive textual check against
///   `source` so `true` and `TRUE` both qualify).
/// - `<lit> = <lit>` over identical literal source text (modulo
///   case for booleans).
/// - `IS NOT NULL` over any non-NULL literal or any column.
/// - `IS NULL` over a NULL literal.
/// - `AND` of always-true expressions; `OR` with at least one
///   always-true operand.
/// - `CASE WHEN … THEN …` with every branch — including `ELSE`
///   — provably always-true.
/// - `EXISTS (SELECT … no FROM)`: synthetic Bare-SELECT shape.
/// - `<col> = ANY(<self-referential subquery>)` over an UPDATE /
///   DELETE target column (encoded as `IN (SELECT col FROM
///   target)` after lowering).
/// - `COALESCE(<lit>, …) = <same-lit>` (and `NVL` / `IFNULL`
///   spellings).
/// - An OR-chain whose bare atoms exhaust a column's value domain
///   across distinct disjuncts (`x = lit OR x <> lit`,
///   `x IS NULL OR x IS NOT NULL`, complementary ranges, boolean
///   exhaustion), witnessed by the same detector that powers the
///   analyzer's tautology warnings
///   (`super::constraint_types::detect_tautologies_in_scope`).
///   Accepted only when an `x IS NULL` disjunct covers the NULL row,
///   so the proof holds under three-valued logic — decoy disjuncts
///   cannot un-prove it (OR is monotone). See
///   `or_chain_domain_exhaustion`.
///
/// `source` is the original SQL text — required for case-
/// insensitive boolean literal comparison and for raw-text
/// equality on numeric / string literals (a
/// span-text comparison; `1` vs `1.0` are unequal even when
/// numerically equal). `target` is the DML target table
/// ([`has_tautology_where`] passes `None` for MERGE),
/// used by the IN-subquery self-reference branch. `bindings` is
/// the lowering's `BindingTable`, used to resolve column names.
///
/// Closed-enum exhaustive over [`ScalarExpr`].
pub fn is_always_true(
    predicate: &ScalarExpr,
    source: &str,
    target: Option<&TableRef>,
    bindings: &BindingTable,
    proof: Option<&dyn NonNullProof>,
) -> bool {
    match predicate {
        ScalarExpr::Lit { value, span } => match value {
            Lit::Bool(true) => {
                let text = span_text(source, *span).to_ascii_uppercase();
                text == "TRUE"
            }
            Lit::Bool(false) => false,
            Lit::Null
            | Lit::Integer(_)
            | Lit::Float(_)
            | Lit::Str(_)
            | Lit::Bytes { .. }
            | Lit::Typed { .. }
            | Lit::Variant(_) => false,
        },

        ScalarExpr::BinOp {
            op, left, right, ..
        } => {
            if matches!(op, BinOpKind::And) {
                is_always_true(left, source, target, bindings, proof)
                    && is_always_true(right, source, target, bindings, proof)
            } else if matches!(op, BinOpKind::Or) {
                is_always_true(left, source, target, bindings, proof)
                    || is_always_true(right, source, target, bindings, proof)
                    || or_chain_domain_exhaustion(predicate, bindings, target, proof)
            } else if let BinOpKind::Cmp(cmp) = op {
                comparison_is_always_true(*cmp, left, right, source, target, proof)
            } else {
                false
            }
        }

        // N-ary spelling of the `And` / `Or` arms above. The `Or` case
        // keeps the domain-exhaustion probe on the whole chain so
        // `a OR b OR 1=1` stays every-row; `collect_or_leaves`
        // descends the chain to supply its disjuncts.
        ScalarExpr::LogicalChain { op, operands, .. } => match op {
            crate::ir::scalar::LogicalOp::And => operands
                .iter()
                .all(|o| is_always_true(o, source, target, bindings, proof)),
            crate::ir::scalar::LogicalOp::Or => {
                operands
                    .iter()
                    .any(|o| is_always_true(o, source, target, bindings, proof))
                    || or_chain_domain_exhaustion(predicate, bindings, target, proof)
            }
        },

        ScalarExpr::UnaryOp { op, arg, .. } => match op {
            crate::ir::scalar::UnaryOpKind::IsNotNull => match arg.as_ref() {
                ScalarExpr::Lit {
                    value: Lit::Null, ..
                } => false,
                ScalarExpr::Lit { .. } => true,
                // `col IS NOT NULL` filters out the rows where `col` is
                // NULL, so it is every-row only when `col` is *proven*
                // non-null: with a proof it escalates to every-row (no
                // NULL rows to spare), without one it stays bounded
                // (`DELETE FROM t WHERE deleted_at IS NOT NULL` keeps
                // the rows that were never deleted).
                ScalarExpr::Column { column, .. } => {
                    proof.is_some_and(|p| p.proven_not_null(*column, target))
                }
                ScalarExpr::OuterRef { .. }
                | ScalarExpr::LogicalChain { .. }
                | ScalarExpr::BinOp { .. }
                | ScalarExpr::UnaryOp { .. }
                | ScalarExpr::FuncCall { .. }
                | ScalarExpr::Case { .. }
                | ScalarExpr::Cast { .. }
                | ScalarExpr::InList { .. }
                | ScalarExpr::Between { .. }
                | ScalarExpr::Like { .. }
                | ScalarExpr::Exists { .. }
                | ScalarExpr::ScalarSubquery { .. }
                | ScalarExpr::QuantifiedCmp { .. }
                | ScalarExpr::WindowFn { .. }
                | ScalarExpr::FieldAccess { .. }
                | ScalarExpr::Lambda { .. }
                | ScalarExpr::PatternVarRef { .. }
                | ScalarExpr::Opaque { .. } => false,
            },
            crate::ir::scalar::UnaryOpKind::IsNull => matches!(
                arg.as_ref(),
                ScalarExpr::Lit {
                    value: Lit::Null,
                    ..
                }
            ),
            // `NOT <always-false>` is always true (`NOT FALSE`, `NOT (1 = 2)`).
            crate::ir::scalar::UnaryOpKind::Not => {
                is_always_false(arg, source, target, bindings, proof)
            }
            crate::ir::scalar::UnaryOpKind::Neg
            | crate::ir::scalar::UnaryOpKind::Plus
            | crate::ir::scalar::UnaryOpKind::AtLocal
            | crate::ir::scalar::UnaryOpKind::Collate
            | crate::ir::scalar::UnaryOpKind::Prior
            | crate::ir::scalar::UnaryOpKind::Spread => false,
        },

        ScalarExpr::Case {
            branches, else_, ..
        } => {
            if branches.is_empty() {
                return false;
            }
            let all_branches_true = branches
                .iter()
                .all(|(_, result)| is_always_true(result, source, target, bindings, proof));
            let else_true = match else_ {
                None => false,
                Some(e) => is_always_true(e, source, target, bindings, proof),
            };
            all_branches_true && else_true
        }

        // A pattern match is never statically always-true.
        ScalarExpr::Like { .. } => false,

        ScalarExpr::Exists {
            subquery, negated, ..
        } => {
            if *negated {
                false
            } else {
                exists_subquery_is_always_true(subquery)
            }
        }

        ScalarExpr::QuantifiedCmp {
            op,
            quantifier,
            negated,
            left,
            right,
            ..
        } => {
            // `x IN (subq)` is `op: Eq, quantifier: Any, negated: false`.
            // Any other shape (NOT IN, <> ALL, <, etc.) isn't covered by
            // this self-referential identity check.
            if !matches!(op, crate::ir::scalar::ComparisonOp::Eq) {
                return false;
            }
            if !matches!(quantifier, super::scalar::Quantifier::Any) {
                return false;
            }
            if *negated {
                return false;
            }
            let QuantifiedRhs::Subquery(plan, _) = right else {
                return false;
            };
            in_subquery_is_self_referential(left, plan, target, bindings)
        }

        // `COALESCE(<always-true>, …)` / `NVL` / `IFNULL`: the first argument
        // is non-null and true, so the call returns it regardless of the rest.
        ScalarExpr::FuncCall { func, args, .. } => {
            let name = span_text(source, func.span()).to_ascii_uppercase();
            if name == "COALESCE" || name == "NVL" || name == "IFNULL" {
                match args.first() {
                    Some(first) => is_always_true(first, source, target, bindings, proof),
                    None => false,
                }
            } else {
                false
            }
        }

        // `<lit> [NOT] IN (<lit>, …)` folds to a known value (`1 IN (1, 2)`).
        ScalarExpr::InList {
            expr,
            list,
            negated,
            ..
        } => in_list_static_truth(expr, list, *negated, source) == Some(true),

        ScalarExpr::Column { .. }
        | ScalarExpr::OuterRef { .. }
        | ScalarExpr::Cast { .. }
        | ScalarExpr::Between { .. }
        | ScalarExpr::ScalarSubquery { .. }
        | ScalarExpr::WindowFn { .. }
        | ScalarExpr::FieldAccess { .. }
        | ScalarExpr::Lambda { .. }
        | ScalarExpr::PatternVarRef { .. }
        | ScalarExpr::Opaque { .. } => false,
    }
}

fn equality_is_always_true(
    left: &ScalarExpr,
    right: &ScalarExpr,
    source: &str,
    target: Option<&TableRef>,
    proof: Option<&dyn NonNullProof>,
) -> bool {
    if is_null_lit(left) && is_null_lit(right) {
        return false;
    }

    if let (
        ScalarExpr::Lit {
            value: lv,
            span: ls,
        },
        ScalarExpr::Lit {
            value: rv,
            span: rs,
        },
    ) = (left, right)
    {
        return literals_equal(lv, *ls, rv, *rs, source);
    }

    if coalesce_equality_always_true(left, right, source) {
        return true;
    }
    if coalesce_equality_always_true(right, left, source) {
        return true;
    }

    // Reflexive column equality `x = x`. Under three-valued logic
    // `NULL = NULL` is UNKNOWN, so the NULL row is unmatched and the
    // predicate is every-row ONLY when `x` is *proven* non-null —
    // then there are no NULL rows to spare. Without that proof it is
    // merely a non-NULL tautology, surfaced as the Medium
    // `Q-PRED-TAUTOLOGY` by `detect_tautologies_in_scope`, not the
    // every-row Critical.
    if let (ScalarExpr::Column { column: lcol, .. }, ScalarExpr::Column { column: rcol, .. }) =
        (left, right)
    {
        if lcol == rcol {
            return proof.is_some_and(|p| p.proven_not_null(*lcol, target));
        }
    }

    false
}

fn is_null_lit(expr: &ScalarExpr) -> bool {
    matches!(
        expr,
        ScalarExpr::Lit {
            value: Lit::Null,
            ..
        }
    )
}

fn literals_equal(l: &Lit, l_span: Span, r: &Lit, r_span: Span, source: &str) -> bool {
    let same_text = || span_text(source, l_span) == span_text(source, r_span);
    match l {
        Lit::Bool(_) => {
            matches!(r, Lit::Bool(_))
                && span_text(source, l_span).eq_ignore_ascii_case(span_text(source, r_span))
        }
        Lit::Integer(_) => matches!(r, Lit::Integer(_)) && same_text(),
        Lit::Float(_) => matches!(r, Lit::Float(_)) && same_text(),
        Lit::Str(_) => matches!(r, Lit::Str(_)) && same_text(),
        Lit::Null | Lit::Bytes { .. } | Lit::Typed { .. } | Lit::Variant(_) => false,
    }
}

/// `COALESCE(<lit>, …) = <same-lit>` always-true check.
///
/// The function name is read from `func.span()` rather than via
/// the resolver, because [`ResolvedFunc::Resolved`]'s `Display`
/// formats the synthetic id (`fn#<n>`) instead of the canonical
/// spelling — it would never match `"COALESCE"`.
fn coalesce_equality_always_true(expr: &ScalarExpr, other: &ScalarExpr, source: &str) -> bool {
    let ScalarExpr::FuncCall { func, args, .. } = expr else {
        return false;
    };
    let name = span_text(source, func.span()).to_ascii_uppercase();
    if name != "COALESCE" && name != "NVL" && name != "IFNULL" {
        return false;
    }
    let Some(first) = args.first() else {
        return false;
    };
    let ScalarExpr::Lit {
        value: first_val,
        span: first_span,
    } = first
    else {
        return false;
    };
    if matches!(first_val, Lit::Null) {
        return false;
    }
    let ScalarExpr::Lit {
        value: other_val,
        span: other_span,
    } = other
    else {
        return false;
    };
    literals_equal(first_val, *first_span, other_val, *other_span, source)
}

/// Dual of [`is_always_true`], bounded to the shapes needed to resolve
/// `NOT <expr>`: a `FALSE` literal, the De Morgan duals of `AND`/`OR`,
/// `NOT <always-true>`, and a constant comparison that folds to false.
/// Anything else is not provably false (so `NOT` over it is not a tautology).
fn is_always_false(
    predicate: &ScalarExpr,
    source: &str,
    target: Option<&TableRef>,
    bindings: &BindingTable,
    proof: Option<&dyn NonNullProof>,
) -> bool {
    if let ScalarExpr::Lit {
        value: Lit::Bool(false),
        span,
    } = predicate
    {
        return span_text(source, *span).eq_ignore_ascii_case("FALSE");
    }
    // `col IS NULL` is always FALSE when `col` is proven non-null, so
    // `NOT (col IS NULL)` (≡ `col IS NOT NULL`) is every-row on a
    // catalog-NOT-NULL column. Symmetric with the `IS NOT NULL` arm of
    // `is_always_true`.
    if let ScalarExpr::UnaryOp {
        op: crate::ir::scalar::UnaryOpKind::IsNull,
        arg,
        ..
    } = predicate
    {
        if let ScalarExpr::Column { column, .. } = arg.as_ref() {
            return proof.is_some_and(|p| p.proven_not_null(*column, target));
        }
    }
    if let ScalarExpr::UnaryOp {
        op: crate::ir::scalar::UnaryOpKind::Not,
        arg,
        ..
    } = predicate
    {
        return is_always_true(arg, source, target, bindings, proof);
    }
    // N-ary spelling of the `And` / `Or` cases below. This is an
    // `if let` chain, not an exhaustive match, so nothing forces this
    // arm — without it a chained predicate silently answers `false`.
    if let ScalarExpr::LogicalChain { op, operands, .. } = predicate {
        return match op {
            crate::ir::scalar::LogicalOp::And => operands
                .iter()
                .any(|o| is_always_false(o, source, target, bindings, proof)),
            crate::ir::scalar::LogicalOp::Or => operands
                .iter()
                .all(|o| is_always_false(o, source, target, bindings, proof)),
        };
    }
    if let ScalarExpr::BinOp {
        op, left, right, ..
    } = predicate
    {
        if matches!(op, BinOpKind::And) {
            return is_always_false(left, source, target, bindings, proof)
                || is_always_false(right, source, target, bindings, proof);
        }
        if matches!(op, BinOpKind::Or) {
            return is_always_false(left, source, target, bindings, proof)
                && is_always_false(right, source, target, bindings, proof);
        }
        if let BinOpKind::Cmp(cmp) = op {
            return literal_comparison(*cmp, left, right, source) == Some(false);
        }
        return false;
    }
    if let ScalarExpr::InList {
        expr,
        list,
        negated,
        ..
    } = predicate
    {
        return in_list_static_truth(expr, list, *negated, source) == Some(false);
    }
    false
}

/// Static truth of `<lit> [NOT] IN (<lit>, …)` when the needle and every list
/// element are constant literals. Three-valued: a non-matching needle with a
/// NULL in the list is SQL `NULL` → `None` (not provably true or false). Also
/// `None` when any operand is non-constant.
fn in_list_static_truth(
    expr: &ScalarExpr,
    list: &[ScalarExpr],
    negated: bool,
    source: &str,
) -> Option<bool> {
    let ScalarExpr::Lit {
        value: needle,
        span: needle_span,
    } = expr
    else {
        return None;
    };
    if matches!(needle, Lit::Null) {
        return None;
    }
    let mut matched = false;
    let mut has_null = false;
    for item in list {
        let ScalarExpr::Lit {
            value: iv,
            span: ispan,
        } = item
        else {
            return None; // a non-literal member → not statically decidable
        };
        if matches!(iv, Lit::Null) {
            has_null = true;
        } else if literals_equal(needle, *needle_span, iv, *ispan, source) {
            matched = true;
        }
    }
    // `x IN (...)` before negation: TRUE on a match; NULL (unknown) on no match
    // with a NULL present; FALSE on no match with no NULL.
    let in_truth = if matched {
        Some(true)
    } else if has_null {
        None
    } else {
        Some(false)
    };
    match in_truth {
        Some(t) if negated => Some(!t),
        other => other,
    }
}

/// Static truth of a comparison: `<lit> <cmp> <lit>` folds to a known value,
/// and `col = col` self-equality is always true. Non-constant operands (other
/// than the column-identity case) are not provably true.
fn comparison_is_always_true(
    op: ComparisonOp,
    left: &ScalarExpr,
    right: &ScalarExpr,
    source: &str,
    target: Option<&TableRef>,
    proof: Option<&dyn NonNullProof>,
) -> bool {
    match op {
        ComparisonOp::Eq => equality_is_always_true(left, right, source, target, proof),
        ComparisonOp::NotEq
        | ComparisonOp::Lt
        | ComparisonOp::LtEq
        | ComparisonOp::Gt
        | ComparisonOp::GtEq => literal_comparison(op, left, right, source) == Some(true),
    }
}

/// Evaluate a comparison between two constant literals. `None` when either
/// side is not a (non-NULL) literal or the types are not statically ordered —
/// i.e. the result is not known before execution.
fn literal_comparison(
    op: ComparisonOp,
    left: &ScalarExpr,
    right: &ScalarExpr,
    source: &str,
) -> Option<bool> {
    if let (
        ScalarExpr::Lit {
            value: lv,
            span: ls,
        },
        ScalarExpr::Lit {
            value: rv,
            span: rs,
        },
    ) = (left, right)
    {
        if matches!(lv, Lit::Null) || matches!(rv, Lit::Null) {
            return None; // NULL comparison is unknown — never provably true/false.
        }
        return match op {
            ComparisonOp::Eq => Some(literals_equal(lv, *ls, rv, *rs, source)),
            ComparisonOp::NotEq => Some(!literals_equal(lv, *ls, rv, *rs, source)),
            ComparisonOp::Lt => {
                numeric_ordering(lv, *ls, rv, *rs, source).map(|o| o == std::cmp::Ordering::Less)
            }
            ComparisonOp::LtEq => {
                numeric_ordering(lv, *ls, rv, *rs, source).map(|o| o != std::cmp::Ordering::Greater)
            }
            ComparisonOp::Gt => {
                numeric_ordering(lv, *ls, rv, *rs, source).map(|o| o == std::cmp::Ordering::Greater)
            }
            ComparisonOp::GtEq => {
                numeric_ordering(lv, *ls, rv, *rs, source).map(|o| o != std::cmp::Ordering::Less)
            }
        };
    }
    None
}

/// Numeric ordering of two literals by parsed value, so `10 > 2` compares
/// numerically rather than lexically. `None` for non-numeric literals.
fn numeric_ordering(
    l: &Lit,
    ls: Span,
    r: &Lit,
    rs: Span,
    source: &str,
) -> Option<std::cmp::Ordering> {
    numeric_lit_f64(l, ls, source)?.partial_cmp(&numeric_lit_f64(r, rs, source)?)
}

fn numeric_lit_f64(v: &Lit, span: Span, source: &str) -> Option<f64> {
    match v {
        Lit::Integer(_) | Lit::Float(_) => span_text(source, span).trim().parse::<f64>().ok(),
        Lit::Null
        | Lit::Bool(_)
        | Lit::Str(_)
        | Lit::Bytes { .. }
        | Lit::Typed { .. }
        | Lit::Variant(_) => None,
    }
}

fn exists_subquery_is_always_true(plan: &RelPlan) -> bool {
    let mut current = plan;
    loop {
        match current {
            RelPlan::WithScope { body, .. } | RelPlan::Explain { body, .. } => current = body,
            RelPlan::Project { input, .. }
            | RelPlan::Sort { input, .. }
            | RelPlan::Window { input, .. }
            | RelPlan::DerivedTable { input, .. } => current = input,
            RelPlan::Filter { .. }
            | RelPlan::Aggregate { .. }
            | RelPlan::Limit { .. }
            | RelPlan::Join { .. }
            | RelPlan::SetOp { .. }
            | RelPlan::Scan { .. }
            | RelPlan::CteRef { .. }
            | RelPlan::ModelRef { .. }
            | RelPlan::TableFunction { .. }
            | RelPlan::TableSample { .. }
            | RelPlan::Pivot { .. }
            | RelPlan::Unpivot { .. }
            | RelPlan::MatchRecognize { .. }
            | RelPlan::ConnectBy { .. }
            | RelPlan::Unnest { .. }
            | RelPlan::Insert { .. }
            | RelPlan::Update { .. }
            | RelPlan::Delete { .. }
            | RelPlan::Merge { .. }
            | RelPlan::MultiInsert { .. }
            | RelPlan::CreateAsQuery { .. }
            | RelPlan::CreateTableForm { .. }
            | RelPlan::ParseRecovery { .. }
            | RelPlan::Opaque { .. }
            | RelPlan::InvalidInput { .. } => return false,
            RelPlan::Values { rows, columns, .. } => {
                return rows.len() == 1 && rows[0].is_empty() && columns.is_empty();
            }
        }
    }
}

fn in_subquery_is_self_referential(
    outer: &ScalarExpr,
    plan: &RelPlan,
    target: Option<&TableRef>,
    bindings: &BindingTable,
) -> bool {
    let Some(target) = target else {
        return false;
    };
    let ScalarExpr::Column {
        column: outer_col, ..
    } = outer
    else {
        return false;
    };
    let Some(outer_binding) = bindings.get(*outer_col) else {
        return false;
    };
    let outer_name = match &outer_binding.origin {
        ColumnOrigin::Table { column_name, .. } => column_name.clone(),
        ColumnOrigin::Computed { .. }
        | ColumnOrigin::SetOp { .. }
        | ColumnOrigin::OuterRef { .. }
        | ColumnOrigin::RecursiveRef { .. } => return false,
    };
    let outer_name_norm = normalize_ident(&outer_name);

    let mut current = plan;
    let mut project_items: Option<&Vec<ProjectItem>> = None;
    loop {
        match current {
            RelPlan::WithScope { body, .. } | RelPlan::Explain { body, .. } => current = body,
            RelPlan::Project {
                input,
                items,
                distinct,
                ..
            } => {
                if *distinct {
                    return false;
                }
                if project_items.is_some() {
                    return false;
                }
                project_items = Some(items);
                current = input;
            }
            RelPlan::Scan { table, .. } => {
                let Some(items) = project_items else {
                    return false;
                };
                if table != target {
                    return false;
                }
                if items.len() != 1 {
                    return false;
                }
                let ProjectItem::Expr(inner_proj) = &items[0] else {
                    return false;
                };
                let ScalarExpr::Column {
                    column: inner_col, ..
                } = &inner_proj.expr
                else {
                    return false;
                };
                let Some(inner_binding) = bindings.get(*inner_col) else {
                    return false;
                };
                let inner_name = match &inner_binding.origin {
                    ColumnOrigin::Table { column_name, .. } => column_name.clone(),
                    ColumnOrigin::Computed { .. }
                    | ColumnOrigin::SetOp { .. }
                    | ColumnOrigin::OuterRef { .. }
                    | ColumnOrigin::RecursiveRef { .. } => return false,
                };
                return normalize_ident(&inner_name) == outer_name_norm;
            }
            RelPlan::Filter { .. }
            | RelPlan::Limit { .. }
            | RelPlan::Aggregate { .. }
            | RelPlan::Sort { .. }
            | RelPlan::Join { .. }
            | RelPlan::SetOp { .. }
            | RelPlan::Window { .. }
            | RelPlan::CteRef { .. }
            | RelPlan::ModelRef { .. }
            | RelPlan::Values { .. }
            | RelPlan::TableFunction { .. }
            | RelPlan::TableSample { .. }
            | RelPlan::Pivot { .. }
            | RelPlan::Unpivot { .. }
            | RelPlan::MatchRecognize { .. }
            | RelPlan::ConnectBy { .. }
            | RelPlan::Unnest { .. }
            | RelPlan::DerivedTable { .. }
            | RelPlan::Insert { .. }
            | RelPlan::Update { .. }
            | RelPlan::Delete { .. }
            | RelPlan::Merge { .. }
            | RelPlan::MultiInsert { .. }
            | RelPlan::CreateAsQuery { .. }
            | RelPlan::CreateTableForm { .. }
            | RelPlan::ParseRecovery { .. }
            | RelPlan::Opaque { .. }
            | RelPlan::InvalidInput { .. } => return false,
        }
    }
}

#[inline]
fn span_text(source: &str, span: Span) -> &str {
    let start = span.start as usize;
    let end = span.end as usize;
    if start <= end && end <= source.len() {
        &source[start..end]
    } else {
        ""
    }
}

#[inline]
fn normalize_ident(s: &str) -> String {
    crate::ir::normalize_identifier(s)
}
