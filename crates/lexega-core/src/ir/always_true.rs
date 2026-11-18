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
//! supplies a [`NonNullProof`]; without one they stay bounded. Counting
//! [`RowsCounted::ExceptNullCompared`], the last two hold without a proof:
//! the rows they spare are those in which the column they compare is NULL.

use super::column::{BindingTable, ColumnId, ColumnOrigin};
use super::plan::{FilterKind, ProjectItem, RelPlan};
use super::queries::for_each_immediate;
use super::scalar::{
    BinOpKind, ComparisonOp, FieldPath, FieldStep, IsPredicate, Lit, QuantifiedRhs, ScalarExpr,
    SqlType,
};
use crate::ast::{AstExpr, NodeId};
use crate::context::node_metadata::{IdentKey, TableRef};
use crate::facts::catalog::Nullability;
use crate::facts::reasoning::{QueryReasoning, ReadAt, ReadSite};
use crate::ir::normalize::NameKind;
use crate::lexer::Span;

/// Proof that a column holds no NULLs where one predicate reads it.
pub trait NonNullProof {
    /// Whether `col` is proven non-null at the predicate's site.
    fn proven_not_null(&self, col: ColumnId) -> bool;
}

/// The proof at one predicate's node: a column the catalog declares
/// NOT NULL where the node's predicate reads it. Nothing else proves.
struct DeclaredAt<'r> {
    reasoning: &'r dyn QueryReasoning,
    node: &'r RelPlan,
}

impl NonNullProof for DeclaredAt<'_> {
    fn proven_not_null(&self, col: ColumnId) -> bool {
        let site = ReadSite {
            node: self.node,
            at: ReadAt::Context,
        };
        matches!(
            self.reasoning.nullability(site, col),
            Nullability::CatalogNonNullable
        )
    }
}

/// The rows a predicate must hold on to hold "for every row".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RowsCounted {
    /// Every row.
    All,
    /// Every row but one in which a column the predicate compares with
    /// itself (`x = x`), or whose values its disjuncts cover
    /// (`x = 1 OR x <> 1`), is NULL. A test of NULL itself
    /// (`x IS NOT NULL`) is judged as under [`RowsCounted::All`].
    ExceptNullCompared,
}

/// What one judgment knows of NULLs: the proof of columns that hold none,
/// and the rows it counts.
#[derive(Clone, Copy)]
struct Nulls<'p> {
    proof: Option<&'p dyn NonNullProof>,
    counted: RowsCounted,
}

impl Nulls<'_> {
    fn proven_not_null(&self, col: ColumnId) -> bool {
        self.proof.is_some_and(|p| p.proven_not_null(col))
    }

    /// Whether the rows in which `col`, compared with itself or with every
    /// value, is NULL need not be matched.
    fn compared_null_rows_spared(&self, col: Option<ColumnId>) -> bool {
        match self.counted {
            RowsCounted::ExceptNullCompared => true,
            RowsCounted::All => col.is_some_and(|col| self.proven_not_null(col)),
        }
    }
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
///
/// `reasoning` answers whether a column is never NULL where a
/// predicate reads it: at the predicate's `Filter`, or at the node of
/// the statement that writes. Without it nothing is proven non-null.
/// `counted` is the rows the predicate must hold on.
pub fn has_tautology_where(
    plan: &RelPlan,
    source: &str,
    bindings: &BindingTable,
    reasoning: Option<&dyn QueryReasoning>,
    counted: RowsCounted,
) -> bool {
    let judged = |pred: &ScalarExpr, target: Option<&TableRef>, node: &RelPlan| {
        let proof = reasoning.map(|reasoning| DeclaredAt { reasoning, node });
        let proof = proof.as_ref().map(|proof| proof as &dyn NonNullProof);
        constant_truth(pred, source, target, bindings, Nulls { proof, counted }) == Some(true)
    };
    match plan {
        RelPlan::Update {
            target,
            predicate: Some(pred),
            ..
        }
        | RelPlan::Delete {
            target,
            predicate: Some(pred),
            ..
        } => judged(pred, Some(target), plan),
        // MERGE passes `target: None`: the ON predicate's
        // every-row judgment must NOT enable the IN-subquery
        // self-reference branch (which keys on the DML target), and the
        // realistic MERGE footgun (`ON 1=1` / `ON TRUE` / domain
        // exhaustion) is caught via the constant / coverage paths that
        // need no target. Reflexive `t.col = t.col` over an aliased
        // MERGE target is an obscure shape left as a sound under-call.
        RelPlan::Merge { on, .. } => judged(on, None, plan),
        RelPlan::Explain { body, .. } | RelPlan::WithScope { body, .. } => {
            has_tautology_where(body, source, bindings, reasoning, counted)
        }

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
                    found = judged(predicate, None, p);
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
        | ScalarExpr::OperatorChain { .. }
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
        | ScalarExpr::RowCmp { .. }
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
    nulls: Nulls<'_>,
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
        // column's NULL row is spared — it is *proven* non-null, as for
        // reflexive `x = x` and `col IS NOT NULL`, or the judgment does
        // not count it.
        let null_disjunct = facts.iter().any(|f| {
            matches!(f.operator, PredicateOp::IsNull)
                && pred_to_col_key(f, bindings).as_str() == finding.column
        });
        null_disjunct
            || facts.iter().any(|f| {
                pred_to_col_key(f, bindings).as_str() == finding.column
                    && nulls.compared_null_rows_spared(f.column_id)
            })
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
///   always-true operand; `XOR` of an always-true and an always-false
///   operand.
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
    let nulls = Nulls {
        proof,
        counted: RowsCounted::All,
    };
    constant_truth(predicate, source, target, bindings, nulls) == Some(true)
}

/// Whether `predicate` is true on every row (`Some(true)`), false on
/// every row (`Some(false)`), or neither is proven (`None`).
///
/// The always-false side is bounded to what `NOT <expr>` and a side of
/// `XOR` need: a `FALSE` literal, `col IS NULL` over a column proven
/// non-null, a constant comparison or `IN` list that folds to false, and
/// the connectives over those.
///
/// Each operand of a connective is judged once, whichever answer the
/// caller is after, so the cost is linear in the size of the predicate.
/// The depth of the recursion is the depth of the expression, which
/// lowering bounds; a long `AND` / `OR` is one N-ary chain node.
///
/// Closed-enum exhaustive over [`ScalarExpr`].
fn constant_truth(
    predicate: &ScalarExpr,
    source: &str,
    target: Option<&TableRef>,
    bindings: &BindingTable,
    nulls: Nulls<'_>,
) -> Option<bool> {
    // A predicate that reads nothing of the row has one value on every row.
    if let Some(value) = fold(predicate, source) {
        return value.truth();
    }
    let truth = |operand: &ScalarExpr| constant_truth(operand, source, target, bindings, nulls);
    match predicate {
        ScalarExpr::Lit { value, span } => match value {
            Lit::Bool(true) => span_text(source, *span)
                .eq_ignore_ascii_case("TRUE")
                .then_some(true),
            Lit::Bool(false) => span_text(source, *span)
                .eq_ignore_ascii_case("FALSE")
                .then_some(false),
            Lit::Null
            | Lit::Integer(_)
            | Lit::Float(_)
            | Lit::Str(_)
            | Lit::Bytes { .. }
            | Lit::Typed { .. }
            | Lit::Variant(_)
            | Lit::Variable { .. } => None,
        },

        ScalarExpr::BinOp {
            op, left, right, ..
        } => {
            if matches!(op, BinOpKind::And) {
                conjunction_truth([left.as_ref(), right.as_ref()], truth)
            } else if matches!(op, BinOpKind::Or) {
                disjunction_truth([left.as_ref(), right.as_ref()], truth, || {
                    or_chain_domain_exhaustion(predicate, bindings, nulls)
                })
            } else if matches!(op, BinOpKind::Xor) {
                // True where exactly one side is.
                match (truth(left), truth(right)) {
                    (Some(left), Some(right)) => Some(left != right),
                    (None, _) | (_, None) => None,
                }
            } else if let BinOpKind::Cmp(cmp) = op {
                if comparison_is_always_true(*cmp, left, right, source, nulls) {
                    Some(true)
                } else if literal_comparison(*cmp, left, right, source) == Some(false) {
                    Some(false)
                } else {
                    None
                }
            } else {
                None
            }
        }

        // N-ary spelling of the `And` / `Or` arms above. The `Or` case
        // keeps the domain-exhaustion probe on the whole chain so
        // `a OR b OR 1=1` stays every-row; `collect_or_leaves`
        // descends the chain to supply its disjuncts.
        ScalarExpr::LogicalChain { op, operands, .. } => match op {
            crate::ir::scalar::LogicalOp::And => conjunction_truth(operands, truth),
            crate::ir::scalar::LogicalOp::Or => disjunction_truth(operands, truth, || {
                or_chain_domain_exhaustion(predicate, bindings, nulls)
            }),
        },

        // The left fold of the `Xor` arm above; a run of any other
        // operator has no truth.
        ScalarExpr::OperatorChain {
            operands,
            operators,
            ..
        } => {
            if operators.iter().any(|op| *op != BinOpKind::Xor) {
                return None;
            }
            ScalarExpr::fold_chain(operands, operators, truth, |folded, _, operand| {
                folded
                    .zip(truth(operand))
                    .map(|(left, right)| left != right)
            })
            .flatten()
        }

        ScalarExpr::UnaryOp { op, arg, .. } => match op {
            crate::ir::scalar::UnaryOpKind::IsNotNull => match arg.as_ref() {
                ScalarExpr::Lit {
                    value: Lit::Null, ..
                } => None,
                ScalarExpr::Lit { .. } => Some(true),
                // `col IS NOT NULL` filters out the rows where `col` is
                // NULL, so it is every-row only when `col` is *proven*
                // non-null: with a proof it escalates to every-row (no
                // NULL rows to spare), without one it stays bounded
                // (`DELETE FROM t WHERE deleted_at IS NOT NULL` keeps
                // the rows that were never deleted).
                ScalarExpr::Column { column, .. } => nulls.proven_not_null(*column).then_some(true),
                ScalarExpr::OuterRef { .. }
                | ScalarExpr::LogicalChain { .. }
                | ScalarExpr::OperatorChain { .. }
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
                | ScalarExpr::RowCmp { .. }
                | ScalarExpr::WindowFn { .. }
                | ScalarExpr::FieldAccess { .. }
                | ScalarExpr::Lambda { .. }
                | ScalarExpr::PatternVarRef { .. }
                | ScalarExpr::Opaque { .. } => None,
            },
            crate::ir::scalar::UnaryOpKind::IsNull => match arg.as_ref() {
                ScalarExpr::Lit {
                    value: Lit::Null, ..
                } => Some(true),
                // `col IS NULL` is always FALSE when `col` is proven
                // non-null, so `NOT (col IS NULL)` is every-row on a
                // catalog-NOT-NULL column. Symmetric with the
                // `IS NOT NULL` arm.
                ScalarExpr::Column { column, .. } => {
                    nulls.proven_not_null(*column).then_some(false)
                }
                ScalarExpr::Lit { .. }
                | ScalarExpr::OuterRef { .. }
                | ScalarExpr::LogicalChain { .. }
                | ScalarExpr::OperatorChain { .. }
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
                | ScalarExpr::RowCmp { .. }
                | ScalarExpr::WindowFn { .. }
                | ScalarExpr::FieldAccess { .. }
                | ScalarExpr::Lambda { .. }
                | ScalarExpr::PatternVarRef { .. }
                | ScalarExpr::Opaque { .. } => None,
            },
            // `NOT FALSE`, `NOT (1 = 2)`; and `NOT TRUE` is always false.
            crate::ir::scalar::UnaryOpKind::Not => truth(arg).map(|always| !always),
            crate::ir::scalar::UnaryOpKind::Neg
            | crate::ir::scalar::UnaryOpKind::Plus
            | crate::ir::scalar::UnaryOpKind::AtLocal
            | crate::ir::scalar::UnaryOpKind::Collate
            | crate::ir::scalar::UnaryOpKind::Prior
            | crate::ir::scalar::UnaryOpKind::Spread
            | crate::ir::scalar::UnaryOpKind::BitwiseNot
            | crate::ir::scalar::UnaryOpKind::SquareRoot
            | crate::ir::scalar::UnaryOpKind::AbsoluteValue
            | crate::ir::scalar::UnaryOpKind::Is(_)
            | crate::ir::scalar::UnaryOpKind::IsNot(_) => None,
        },

        ScalarExpr::Case {
            branches, else_, ..
        } => {
            if branches.is_empty() {
                return None;
            }
            let all_branches_true = branches
                .iter()
                .all(|(_, result)| truth(result) == Some(true));
            let else_true = match else_ {
                None => false,
                Some(e) => truth(e) == Some(true),
            };
            (all_branches_true && else_true).then_some(true)
        }

        // A pattern match is never statically always-true.
        ScalarExpr::Like { .. } => None,

        ScalarExpr::Exists {
            subquery, negated, ..
        } => (!*negated && exists_subquery_is_always_true(subquery)).then_some(true),

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
                return None;
            }
            if !matches!(quantifier, super::scalar::Quantifier::Any) {
                return None;
            }
            if *negated {
                return None;
            }
            let QuantifiedRhs::Subquery(plan, _) = right else {
                return None;
            };
            in_subquery_is_self_referential(left, plan, target, bindings).then_some(true)
        }

        // `COALESCE(<always-true>, …)` / `NVL` / `IFNULL`: the first argument
        // is non-null and true, so the call returns it regardless of the rest.
        ScalarExpr::FuncCall { func, args, .. } => {
            let name = span_text(source, func.span()).to_ascii_uppercase();
            if name == "COALESCE" || name == "NVL" || name == "IFNULL" {
                match args.first() {
                    Some(first) => (truth(first) == Some(true)).then_some(true),
                    None => None,
                }
            } else {
                None
            }
        }

        // `<lit> [NOT] IN (<lit>, …)` folds to a known value (`1 IN (1, 2)`).
        ScalarExpr::InList {
            expr,
            list,
            negated,
            ..
        } => in_list_static_truth(expr, list, *negated, source),

        ScalarExpr::Column { .. }
        | ScalarExpr::OuterRef { .. }
        | ScalarExpr::Cast { .. }
        | ScalarExpr::Between { .. }
        | ScalarExpr::ScalarSubquery { .. }
        | ScalarExpr::RowCmp { .. }
        | ScalarExpr::WindowFn { .. }
        | ScalarExpr::FieldAccess { .. }
        | ScalarExpr::Lambda { .. }
        | ScalarExpr::PatternVarRef { .. }
        | ScalarExpr::Opaque { .. } => None,
    }
}

/// The value of an expression that reads nothing of the row: no column,
/// subquery, variable or function whose result can vary.
#[derive(Debug, Clone, PartialEq)]
enum Const {
    Null,
    Bool(bool),
    /// A number, and whether it is whole by type: written as an integer
    /// and kept whole by the arithmetic over it.
    Num {
        value: f64,
        whole: bool,
    },
    /// A string's text, its quotes removed and `''` read as `'`.
    Str(String),
}

/// Numbers larger than this are not compared exactly as `f64`.
const EXACT_LIMIT: f64 = 9.0e15;

impl Const {
    /// The value as a condition: a non-zero number is true where a number
    /// stands as one (MySQL); NULL and a string prove nothing.
    fn truth(&self) -> Option<bool> {
        match self {
            Const::Bool(b) => Some(*b),
            Const::Num { value, .. } => Some(*value != 0.0),
            Const::Null | Const::Str(_) => None,
        }
    }

    /// Three-valued logic: `None` is NULL; a string has no truth value
    /// this reading decides, so the whole is unknown (`Err`).
    fn logic(&self) -> Result<Option<bool>, ()> {
        match self {
            Const::Null => Ok(None),
            Const::Bool(_) | Const::Num { .. } => Ok(self.truth()),
            Const::Str(_) => Err(()),
        }
    }
}

fn from_logic(value: Option<bool>) -> Const {
    value.map_or(Const::Null, Const::Bool)
}

/// The value `expr` has on every row, where it reads nothing of the row
/// and its value does not depend on the dialect, the collation or the
/// session. `None` where it does, or where it is not decided here.
///
/// Closed-enum exhaustive over [`ScalarExpr`].
fn fold(expr: &ScalarExpr, source: &str) -> Option<Const> {
    let fold_one = |operand: &ScalarExpr| fold(operand, source);
    match expr {
        ScalarExpr::Lit { value, span } => match value {
            Lit::Null => Some(Const::Null),
            Lit::Bool(b) => {
                let text = span_text(source, *span);
                let written = if *b { "TRUE" } else { "FALSE" };
                text.eq_ignore_ascii_case(written)
                    .then_some(Const::Bool(*b))
            }
            Lit::Integer(_) => span_text(source, *span)
                .trim()
                .parse::<f64>()
                .ok()
                .map(|value| Const::Num { value, whole: true }),
            Lit::Float(_) => span_text(source, *span)
                .trim()
                .parse::<f64>()
                .ok()
                .map(|value| Const::Num {
                    value,
                    whole: false,
                }),
            Lit::Str(raw) => string_text(raw).map(Const::Str),
            Lit::Bytes { .. } | Lit::Typed { .. } | Lit::Variant(_) | Lit::Variable { .. } => None,
        },

        ScalarExpr::UnaryOp { op, arg, .. } => {
            use crate::ir::scalar::UnaryOpKind as U;
            let value = fold_one(arg)?;
            match op {
                U::Not => Some(from_logic(value.logic().ok()?.map(|b| !b))),
                U::Neg | U::Plus => match value {
                    Const::Null => Some(Const::Null),
                    Const::Num { value, whole } => Some(Const::Num {
                        value: if matches!(op, U::Neg) { -value } else { value },
                        whole,
                    }),
                    Const::Bool(_) | Const::Str(_) => None,
                },
                U::IsNull => Some(Const::Bool(value == Const::Null)),
                U::IsNotNull => Some(Const::Bool(value != Const::Null)),
                U::Is(IsPredicate::True) => Some(Const::Bool(value.logic().ok()? == Some(true))),
                U::Is(IsPredicate::False) => Some(Const::Bool(value.logic().ok()? == Some(false))),
                U::IsNot(IsPredicate::True) => Some(Const::Bool(value.logic().ok()? != Some(true))),
                U::IsNot(IsPredicate::False) => {
                    Some(Const::Bool(value.logic().ok()? != Some(false)))
                }
                U::Is(_)
                | U::IsNot(_)
                | U::AtLocal
                | U::Collate
                | U::Prior
                | U::Spread
                | U::BitwiseNot
                | U::SquareRoot
                | U::AbsoluteValue => None,
            }
        }

        ScalarExpr::BinOp {
            op, left, right, ..
        } => fold_binary(*op, fold_one(left)?, fold_one(right)?),

        ScalarExpr::LogicalChain { op, operands, .. } => {
            let values: Option<Vec<Const>> = operands.iter().map(fold_one).collect();
            let op = match op {
                crate::ir::scalar::LogicalOp::And => BinOpKind::And,
                crate::ir::scalar::LogicalOp::Or => BinOpKind::Or,
            };
            values?
                .into_iter()
                .try_fold(None, |folded: Option<Const>, value| match folded {
                    None => Some(Some(value)),
                    Some(left) => fold_binary(op, left, value).map(Some),
                })
                .flatten()
        }

        ScalarExpr::OperatorChain {
            operands,
            operators,
            ..
        } => {
            let mut values = operands.iter().map(fold_one);
            let mut folded = values.next()??;
            for (op, value) in operators.iter().zip(values) {
                folded = fold_binary(*op, folded, value?)?;
            }
            Some(folded)
        }

        ScalarExpr::Between {
            expr,
            low,
            high,
            negated,
            ..
        } => {
            let (value, low, high) = (fold_one(expr)?, fold_one(low)?, fold_one(high)?);
            let above = compare(ComparisonOp::GtEq, &value, &low)?;
            let below = compare(ComparisonOp::LtEq, &value, &high)?;
            let within = fold_binary(BinOpKind::And, above, below)?;
            if *negated {
                Some(from_logic(within.logic().ok()?.map(|b| !b)))
            } else {
                Some(within)
            }
        }

        ScalarExpr::InList {
            expr,
            list,
            negated,
            ..
        } => {
            let needle = fold_one(expr)?;
            let mut found = Const::Bool(false);
            for item in list {
                let equal = compare(ComparisonOp::Eq, &needle, &fold_one(item)?)?;
                found = fold_binary(BinOpKind::Or, found, equal)?;
            }
            if *negated {
                Some(from_logic(found.logic().ok()?.map(|b| !b)))
            } else {
                Some(found)
            }
        }

        ScalarExpr::Like {
            kind,
            negated,
            expr,
            pattern,
            escape,
            ..
        } => {
            if escape.is_some() {
                return None;
            }
            let matched = match (fold_one(expr)?, fold_one(pattern)?) {
                (Const::Null, _) | (_, Const::Null) => return Some(Const::Null),
                (Const::Str(text), Const::Str(pattern)) => like(kind, &text, &pattern)?,
                (Const::Bool(_) | Const::Num { .. } | Const::Str(_), _) => return None,
            };
            Some(Const::Bool(matched != *negated))
        }

        ScalarExpr::Case {
            operand,
            branches,
            else_,
            ..
        } => {
            let subject = match operand {
                Some(operand) => Some(fold_one(operand)?),
                None => None,
            };
            for (when, then) in branches {
                let condition = fold_one(when)?;
                let taken = match &subject {
                    Some(subject) => compare(ComparisonOp::Eq, subject, &condition)?
                        .logic()
                        .ok()?,
                    None => condition.logic().ok()?,
                };
                if taken == Some(true) {
                    return fold_one(then);
                }
            }
            match else_ {
                Some(else_) => fold_one(else_),
                None => Some(Const::Null),
            }
        }

        ScalarExpr::Cast {
            expr, target_type, ..
        } => cast(fold_one(expr)?, target_type),

        ScalarExpr::FuncCall { func, args, .. } => {
            let name = span_text(source, func.span()).to_ascii_uppercase();
            match (name.as_str(), args.as_slice()) {
                ("COALESCE" | "NVL" | "IFNULL", _) | ("ISNULL", [_, _]) => {
                    for arg in args {
                        let value = fold_one(arg)?;
                        if value != Const::Null {
                            return Some(value);
                        }
                    }
                    Some(Const::Null)
                }
                ("ISNULL", [arg]) => Some(Const::Bool(fold_one(arg)? == Const::Null)),
                ("NULLIF", [left, right]) => {
                    let left = fold_one(left)?;
                    match compare(ComparisonOp::Eq, &left, &fold_one(right)?)?
                        .logic()
                        .ok()?
                    {
                        Some(true) => Some(Const::Null),
                        Some(false) | None => Some(left),
                    }
                }
                ("IF" | "IIF" | "IFF", [condition, then, otherwise]) => {
                    match fold_one(condition)?.logic().ok()? {
                        Some(true) => fold_one(then),
                        Some(false) | None => fold_one(otherwise),
                    }
                }
                _ => None,
            }
        }

        ScalarExpr::Column { .. }
        | ScalarExpr::OuterRef { .. }
        | ScalarExpr::Exists { .. }
        | ScalarExpr::ScalarSubquery { .. }
        | ScalarExpr::QuantifiedCmp { .. }
        | ScalarExpr::RowCmp { .. }
        | ScalarExpr::WindowFn { .. }
        | ScalarExpr::FieldAccess { .. }
        | ScalarExpr::Lambda { .. }
        | ScalarExpr::PatternVarRef { .. }
        | ScalarExpr::Opaque { .. } => None,
    }
}

/// `left op right` over two constants.
fn fold_binary(op: BinOpKind, left: Const, right: Const) -> Option<Const> {
    let number = |value: &Const| match value {
        Const::Num { value, whole } => Some((*value, *whole)),
        Const::Null | Const::Bool(_) | Const::Str(_) => None,
    };
    let either_null = left == Const::Null || right == Const::Null;
    match op {
        BinOpKind::And => {
            let (l, r) = (left.logic().ok()?, right.logic().ok()?);
            Some(match (l, r) {
                (Some(false), _) | (_, Some(false)) => Const::Bool(false),
                (Some(true), Some(true)) => Const::Bool(true),
                (None, _) | (_, None) => Const::Null,
            })
        }
        BinOpKind::Or | BinOpKind::LogicalOr => {
            let (l, r) = (left.logic().ok()?, right.logic().ok()?);
            Some(match (l, r) {
                (Some(true), _) | (_, Some(true)) => Const::Bool(true),
                (Some(false), Some(false)) => Const::Bool(false),
                (None, _) | (_, None) => Const::Null,
            })
        }
        BinOpKind::Xor => {
            let (l, r) = (left.logic().ok()?, right.logic().ok()?);
            Some(from_logic(l.zip(r).map(|(l, r)| l != r)))
        }
        BinOpKind::Cmp(cmp) => compare(cmp, &left, &right),
        BinOpKind::IsDistinctFrom | BinOpKind::IsNotDistinctFrom => {
            let same = match (&left, &right) {
                (Const::Null, Const::Null) => true,
                (Const::Null, _) | (_, Const::Null) => false,
                _ => compare(ComparisonOp::Eq, &left, &right)?.logic().ok()??,
            };
            Some(Const::Bool(
                same == matches!(op, BinOpKind::IsNotDistinctFrom),
            ))
        }
        BinOpKind::Add
        | BinOpKind::Sub
        | BinOpKind::Mul
        | BinOpKind::Div
        | BinOpKind::Mod
        | BinOpKind::IntDiv => {
            if either_null {
                return Some(Const::Null);
            }
            let ((l, l_whole), (r, r_whole)) = (number(&left)?, number(&right)?);
            let whole = l_whole && r_whole;
            let value = match op {
                BinOpKind::Add => l + r,
                BinOpKind::Sub => l - r,
                BinOpKind::Mul => l * r,
                // Whole numbers divide to a whole number in some dialects
                // and to a fraction in others: only an exact quotient is
                // the same everywhere.
                BinOpKind::Div if r == 0.0 => return None,
                BinOpKind::Div if whole && l % r != 0.0 => return None,
                BinOpKind::Div => l / r,
                BinOpKind::Mod | BinOpKind::IntDiv if r == 0.0 || !whole => return None,
                BinOpKind::Mod => l % r,
                BinOpKind::IntDiv => (l / r).trunc(),
                _ => return None,
            };
            (value.is_finite() && value.abs() < EXACT_LIMIT).then_some(Const::Num { value, whole })
        }
        BinOpKind::Concat => match (left, right) {
            (Const::Null, _) | (_, Const::Null) => Some(Const::Null),
            (Const::Str(l), Const::Str(r)) => Some(Const::Str(l + &r)),
            (Const::Bool(_) | Const::Num { .. } | Const::Str(_), _) => None,
        },
        _ => None,
    }
}

/// `left cmp right` over two constants, where every dialect and collation
/// agrees: numbers by value, strings that are equal byte for byte or
/// differ in more than case and trailing spaces, booleans for equality.
fn compare(cmp: ComparisonOp, left: &Const, right: &Const) -> Option<Const> {
    use std::cmp::Ordering;
    let ordering = match (left, right) {
        (Const::Null, _) | (_, Const::Null) => return Some(Const::Null),
        (Const::Num { value: l, .. }, Const::Num { value: r, .. }) => {
            if l.abs() >= EXACT_LIMIT || r.abs() >= EXACT_LIMIT {
                return None;
            }
            l.partial_cmp(r)?
        }
        (Const::Str(l), Const::Str(r)) => {
            let equal = if l == r {
                true
            } else if !l.is_ascii()
                || !r.is_ascii()
                || l.eq_ignore_ascii_case(r)
                || l.trim_end_matches(' ') == r.trim_end_matches(' ')
            {
                return None;
            } else {
                false
            };
            return match cmp {
                ComparisonOp::Eq => Some(Const::Bool(equal)),
                ComparisonOp::NotEq => Some(Const::Bool(!equal)),
                ComparisonOp::Lt | ComparisonOp::LtEq | ComparisonOp::Gt | ComparisonOp::GtEq => {
                    None
                }
            };
        }
        (Const::Bool(l), Const::Bool(r)) => {
            return match cmp {
                ComparisonOp::Eq => Some(Const::Bool(l == r)),
                ComparisonOp::NotEq => Some(Const::Bool(l != r)),
                ComparisonOp::Lt | ComparisonOp::LtEq | ComparisonOp::Gt | ComparisonOp::GtEq => {
                    None
                }
            };
        }
        (Const::Num { .. } | Const::Str(_) | Const::Bool(_), _) => return None,
    };
    Some(Const::Bool(match cmp {
        ComparisonOp::Eq => ordering == Ordering::Equal,
        ComparisonOp::NotEq => ordering != Ordering::Equal,
        ComparisonOp::Lt => ordering == Ordering::Less,
        ComparisonOp::LtEq => ordering != Ordering::Greater,
        ComparisonOp::Gt => ordering == Ordering::Greater,
        ComparisonOp::GtEq => ordering != Ordering::Less,
    }))
}

/// A cast of a constant, where every dialect casts it alike.
fn cast(value: Const, target: &SqlType) -> Option<Const> {
    const WHOLE: &[&str] = &[
        "INT", "INTEGER", "BIGINT", "SMALLINT", "TINYINT", "INT2", "INT4", "INT8", "BYTEINT",
    ];
    const FRACTIONAL: &[&str] = &[
        "NUMBER", "NUMERIC", "DECIMAL", "FLOAT", "FLOAT4", "FLOAT8", "DOUBLE", "REAL",
    ];
    const TEXT: &[&str] = &["VARCHAR", "CHAR", "TEXT", "STRING", "NVARCHAR", "NCHAR"];
    let name = target.repr.split(['(', ' ']).next().unwrap_or_default();
    let whole_target = WHOLE.contains(&name);
    match value {
        Const::Null => Some(Const::Null),
        // A fraction cast to a whole number is truncated in some dialects
        // and rounded in others.
        Const::Num { value, .. } if whole_target => {
            (value.fract() == 0.0).then_some(Const::Num { value, whole: true })
        }
        Const::Num { value, whole } if FRACTIONAL.contains(&name) => {
            Some(Const::Num { value, whole })
        }
        Const::Str(text) if whole_target || FRACTIONAL.contains(&name) => {
            let value = text.trim().parse::<f64>().ok()?;
            (!whole_target || value.fract() == 0.0).then_some(Const::Num {
                value,
                whole: whole_target,
            })
        }
        Const::Str(text) if TEXT.contains(&name) && target.params.is_empty() => {
            Some(Const::Str(text))
        }
        Const::Bool(b) if matches!(name, "BOOLEAN" | "BOOL") => Some(Const::Bool(b)),
        Const::Num { .. } | Const::Str(_) | Const::Bool(_) => None,
    }
}

/// A string literal's text as written between single quotes, `''` read
/// as `'`. `None` for a prefixed literal or one holding a backslash, which
/// dialects read differently.
fn string_text(raw: &str) -> Option<String> {
    let inner = raw.strip_prefix('\'')?.strip_suffix('\'')?;
    if inner.contains('\\') {
        return None;
    }
    Some(inner.replace("''", "'"))
}

/// Whether `text` matches `pattern`, where every collation agrees: ASCII
/// text with no trailing space, matched alike with case and without (or
/// without, for `ILIKE`).
fn like(kind: &crate::ir::scalar::LikeKind, text: &str, pattern: &str) -> Option<bool> {
    use crate::ir::scalar::LikeKind;
    if !text.is_ascii() || !pattern.is_ascii() || text.ends_with(' ') || pattern.ends_with(' ') {
        return None;
    }
    let exact = like_matches(text.as_bytes(), pattern.as_bytes(), false);
    let folded = like_matches(text.as_bytes(), pattern.as_bytes(), true);
    match kind {
        LikeKind::Like => (exact == folded).then_some(exact),
        LikeKind::ILike => Some(folded),
        LikeKind::RLike | LikeKind::SimilarTo => None,
    }
}

/// `%` matches any run of characters, `_` one character.
fn like_matches(text: &[u8], pattern: &[u8], fold_case: bool) -> bool {
    let same = |a: u8, b: u8| {
        if fold_case {
            a.eq_ignore_ascii_case(&b)
        } else {
            a == b
        }
    };
    let (mut t, mut p) = (0usize, 0usize);
    let mut resume: Option<(usize, usize)> = None;
    while t < text.len() {
        match pattern.get(p) {
            Some(b'%') => {
                resume = Some((p, t));
                p += 1;
            }
            Some(&c) if c == b'_' || same(c, text[t]) => {
                t += 1;
                p += 1;
            }
            Some(_) | None => match resume {
                Some((star, matched)) => {
                    p = star + 1;
                    t = matched + 1;
                    resume = Some((star, matched + 1));
                }
                None => return false,
            },
        }
    }
    pattern[p..].iter().all(|&c| c == b'%')
}

/// `AND` of `operands`, each judged once: always false where one is,
/// always true where all are.
fn conjunction_truth<'a>(
    operands: impl IntoIterator<Item = &'a ScalarExpr>,
    truth: impl Fn(&'a ScalarExpr) -> Option<bool>,
) -> Option<bool> {
    let mut all_true = true;
    for operand in operands {
        match truth(operand) {
            Some(false) => return Some(false),
            Some(true) => {}
            None => all_true = false,
        }
    }
    all_true.then_some(true)
}

/// `OR` of `operands`, each judged once: always true where one is, or
/// where `exhausts_the_domain` says the disjuncts cover every row;
/// always false where all are.
fn disjunction_truth<'a>(
    operands: impl IntoIterator<Item = &'a ScalarExpr>,
    truth: impl Fn(&'a ScalarExpr) -> Option<bool>,
    exhausts_the_domain: impl FnOnce() -> bool,
) -> Option<bool> {
    let mut all_false = true;
    for operand in operands {
        match truth(operand) {
            Some(true) => return Some(true),
            Some(false) => {}
            None => all_false = false,
        }
    }
    if exhausts_the_domain() {
        Some(true)
    } else {
        all_false.then_some(false)
    }
}

fn equality_is_always_true(
    left: &ScalarExpr,
    right: &ScalarExpr,
    source: &str,
    nulls: Nulls<'_>,
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

    reflexive_holds(left, right, nulls)
}

/// Whether `x = x`, `x <= x` or `x >= x` holds on every row counted.
/// Under three-valued logic `NULL = NULL` is UNKNOWN, so the NULL row is
/// unmatched: it holds only when `x` is *proven* non-null, or the rows
/// where `x` is NULL are not counted.
fn reflexive_holds(left: &ScalarExpr, right: &ScalarExpr, nulls: Nulls<'_>) -> bool {
    if let (ScalarExpr::Column { column: lcol, .. }, ScalarExpr::Column { column: rcol, .. }) =
        (left, right)
    {
        lcol == rcol && nulls.compared_null_rows_spared(Some(*lcol))
    } else {
        false
    }
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
        Lit::Null
        | Lit::Bytes { .. }
        | Lit::Typed { .. }
        | Lit::Variant(_)
        | Lit::Variable { .. } => false,
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
/// and `col = col`, `col <= col`, `col >= col` hold as [`reflexive_holds`]
/// says. Other non-constant operands are not provably true.
fn comparison_is_always_true(
    op: ComparisonOp,
    left: &ScalarExpr,
    right: &ScalarExpr,
    source: &str,
    nulls: Nulls<'_>,
) -> bool {
    match op {
        ComparisonOp::Eq => equality_is_always_true(left, right, source, nulls),
        ComparisonOp::LtEq | ComparisonOp::GtEq => {
            reflexive_holds(left, right, nulls)
                || literal_comparison(op, left, right, source) == Some(true)
        }
        ComparisonOp::NotEq | ComparisonOp::Lt | ComparisonOp::Gt => {
            literal_comparison(op, left, right, source) == Some(true)
        }
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
        | Lit::Variant(_)
        | Lit::Variable { .. } => None,
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

/// The name a column read from a table is compared under: a table
/// column's name, and an unattributed column's qualifier, segment by
/// segment, and name, so one written through a qualifier equals no bare
/// column. `None` for any other column.
fn compared_name(origin: &ColumnOrigin) -> Option<(Vec<IdentKey>, IdentKey)> {
    match origin {
        ColumnOrigin::Table { column_name, .. } => {
            Some((Vec::new(), IdentKey::new_as(column_name, NameKind::Column)))
        }
        ColumnOrigin::Unattributed {
            qualifier, name, ..
        } => Some(super::lower::unattributed_key(qualifier.as_deref(), name)),
        ColumnOrigin::Computed { .. }
        | ColumnOrigin::Merged { .. }
        | ColumnOrigin::SetOp { .. }
        | ColumnOrigin::OuterRef { .. }
        | ColumnOrigin::RecursiveRef { .. } => None,
    }
}

/// What an operand of a self-referential `IN` reads.
#[derive(PartialEq)]
pub(crate) struct ComparedOperand {
    /// The column's [`compared_name`].
    name: (Vec<IdentKey>, IdentKey),
    /// The field path a field access reads below the column; empty for
    /// the column itself.
    path: FieldPath,
    /// The cast of that field access.
    cast: Option<SqlType>,
}

/// What an operand of a self-referential `IN` reads: the compared name
/// of a column, with the field path and cast of a field access over
/// it. `None` for any other operand, and for a path with a computed
/// index, which names no one field.
fn compared_operand(expr: &ScalarExpr, bindings: &BindingTable) -> Option<ComparedOperand> {
    let (column, path, cast) = match expr {
        ScalarExpr::Column { column, .. } => (*column, FieldPath::empty(), None),
        ScalarExpr::FieldAccess {
            base, path, cast, ..
        } => {
            let ScalarExpr::Column { column, .. } = base.as_ref() else {
                return None;
            };
            if path
                .iter()
                .any(|step| matches!(step, FieldStep::IndexExpr(_)))
            {
                return None;
            }
            (*column, FieldPath::from_field_steps(path), cast.clone())
        }
        ScalarExpr::OuterRef { .. }
        | ScalarExpr::Lit { .. }
        | ScalarExpr::BinOp { .. }
        | ScalarExpr::LogicalChain { .. }
        | ScalarExpr::OperatorChain { .. }
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
        | ScalarExpr::RowCmp { .. }
        | ScalarExpr::WindowFn { .. }
        | ScalarExpr::Lambda { .. }
        | ScalarExpr::PatternVarRef { .. }
        | ScalarExpr::Opaque { .. } => return None,
    };
    let name = compared_name(&bindings.get(column)?.origin)?;
    Some(ComparedOperand { name, path, cast })
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
    let Some(outer_name) = compared_operand(outer, bindings) else {
        return false;
    };

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
                return compared_operand(&inner_proj.expr, bindings)
                    .is_some_and(|inner| inner == outer_name);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{
        lower_query_full_with_bindings, CatalogDialect, FunctionCatalog, SessionContext, StrictMode,
    };
    use crate::lexer::{tokenize, tokenize_with_dialect};
    use crate::parser::{parse_script, try_parse_script_with_dialect};

    /// Whether the `WHERE` of the one statement `src` is always true.
    fn tautology(src: &str) -> bool {
        let tokens = tokenize(src);
        let script = parse_script(src, &tokens.tokens).expect("parse");
        tautology_of(src, &script)
    }

    /// As [`tautology`], with `src` read as MySQL.
    fn mysql_tautology(src: &str) -> bool {
        let mysql = crate::dialect::mysql();
        let tokens = tokenize_with_dialect(src, mysql.as_ref());
        let script =
            try_parse_script_with_dialect(src, &tokens.tokens, mysql.as_ref()).expect("parse");
        assert_eq!(script.stmts.len(), 1, "{src}");
        tautology_of(src, &script)
    }

    fn tautology_of(src: &str, script: &crate::ast::AstScript) -> bool {
        let (plan, _catalog_ctx, bindings, _facts) = lower_query_full_with_bindings(
            &script.stmts[0],
            src,
            StrictMode::Permissive,
            &FunctionCatalog::for_dialect(CatalogDialect::Default),
            &SessionContext::default(),
            None,
        )
        .expect("lower");
        has_tautology_where(&plan, src, &bindings, None, RowsCounted::All)
    }

    /// Whether the `WHERE` of `src` holds on every row but those where a
    /// column it compares is NULL.
    fn non_null_tautology(src: &str) -> bool {
        let tokens = tokenize(src);
        let script = parse_script(src, &tokens.tokens).expect("parse");
        let (plan, _catalog_ctx, bindings, _facts) = lower_query_full_with_bindings(
            &script.stmts[0],
            src,
            StrictMode::Permissive,
            &FunctionCatalog::for_dialect(CatalogDialect::Default),
            &SessionContext::default(),
            None,
        )
        .expect("lower");
        has_tautology_where(&plan, src, &bindings, None, RowsCounted::ExceptNullCompared)
    }

    #[test]
    fn a_comparison_of_a_column_with_itself_spares_only_its_null_rows() {
        let _folding = crate::ir::normalize::default_folding();
        for spares_nulls in [
            "DELETE FROM t WHERE x = x",
            "DELETE FROM t WHERE x >= x",
            "DELETE FROM t WHERE x <= x",
            "DELETE FROM t WHERE x = 1 OR x <> 1",
            "DELETE FROM t WHERE x < 10 OR x > 5",
            "DELETE FROM t WHERE x = x OR c > 0",
            "DELETE FROM t WHERE NOT (NOT (x = x))",
        ] {
            assert!(!tautology(spares_nulls), "{spares_nulls}");
            assert!(non_null_tautology(spares_nulls), "{spares_nulls}");
        }
        assert!(non_null_tautology("UPDATE t SET a = 1 WHERE 1 = 1"));
        for bounded in [
            // A test of NULL itself is a filter.
            "DELETE FROM t WHERE x IS NOT NULL",
            "DELETE FROM t WHERE NOT (x IS NULL)",
            "DELETE FROM t WHERE x = x AND c > 0",
            "DELETE FROM t WHERE x <> x",
            "DELETE FROM t WHERE x < x",
            "DELETE FROM t WHERE x = y",
            "DELETE FROM t WHERE x < 5 OR x > 10",
        ] {
            assert!(!non_null_tautology(bounded), "{bounded}");
        }
    }

    #[test]
    fn a_predicate_that_reads_nothing_of_the_row_is_judged_by_its_value() {
        let _folding = crate::ir::normalize::default_folding();
        for every_row in [
            "DELETE FROM t WHERE 1 BETWEEN 0 AND 2",
            "DELETE FROM t WHERE 'x' LIKE '%'",
            "DELETE FROM t WHERE 'abc' LIKE 'a_c'",
            "DELETE FROM t WHERE 2 > 1 AND 'a' = 'a'",
            "DELETE FROM t WHERE 1 + 1 = 2",
            "DELETE FROM t WHERE 1 = 1.0",
            "DELETE FROM t WHERE 6 / 3 = 2",
            "DELETE FROM t WHERE CAST('1' AS INT) = 1",
            "DELETE FROM t WHERE COALESCE(NULL, 1) = 1",
            "DELETE FROM t WHERE NULLIF(1, 2) = 1",
            "DELETE FROM t WHERE CASE WHEN 1 = 1 THEN TRUE ELSE FALSE END",
            "DELETE FROM t WHERE CASE 2 WHEN 1 THEN FALSE WHEN 2 THEN TRUE END",
            "DELETE FROM t WHERE 1 IN (3, 2, 1)",
            "DELETE FROM t WHERE 4 NOT IN (3, 2, 1)",
            "DELETE FROM t WHERE NOT 1 = 2",
            "DELETE FROM t WHERE NULL IS NULL",
            "DELETE FROM t WHERE 'a' || 'b' = 'ab'",
            "UPDATE t SET a = 1 WHERE -1 < 0 OR c > 0",
        ] {
            assert!(tautology(every_row), "{every_row}");
        }
        for bounded in [
            "DELETE FROM t WHERE 1 BETWEEN 2 AND 3",
            "DELETE FROM t WHERE c BETWEEN 0 AND 2",
            // NULL holds for no row.
            "DELETE FROM t WHERE NULL = NULL",
            "DELETE FROM t WHERE 1 BETWEEN NULL AND 2",
            "DELETE FROM t WHERE 1 IN (2, NULL)",
            // Collations differ on case and trailing spaces.
            "DELETE FROM t WHERE 'a' = 'A'",
            "DELETE FROM t WHERE 'ab' LIKE 'A%'",
            "DELETE FROM t WHERE 'a' = 'a '",
            // Dialects divide whole numbers apart, and cast a fraction
            // to a whole number apart.
            "DELETE FROM t WHERE 5 / 2 = 2",
            "DELETE FROM t WHERE CAST(1.5 AS INT) = 1",
            // A string's truth is not read.
            "DELETE FROM t WHERE 'yes'",
            "DELETE FROM t WHERE 1 / 0 = 1",
        ] {
            assert!(!tautology(bounded), "{bounded}");
        }
    }

    #[test]
    fn a_number_or_a_truth_test_stands_as_a_condition() {
        let _folding = crate::ir::normalize::default_folding();
        for every_row in [
            "DELETE FROM t WHERE 1",
            "DELETE FROM t WHERE 1 IS TRUE",
            "DELETE FROM t WHERE 0 IS NOT TRUE",
            "DELETE FROM t WHERE NULL IS NOT TRUE",
            "DELETE FROM t WHERE (1 = 2) IS FALSE",
        ] {
            assert!(mysql_tautology(every_row), "{every_row}");
        }
        for bounded in ["DELETE FROM t WHERE 0", "DELETE FROM t WHERE NULL IS TRUE"] {
            assert!(!mysql_tautology(bounded), "{bounded}");
        }
    }

    #[test]
    fn an_exclusive_or_of_a_true_side_and_a_false_side_is_always_true() {
        let _folding = crate::ir::normalize::default_folding();
        for every_row in [
            "DELETE FROM t WHERE 1 = 1 XOR 1 = 2",
            "DELETE FROM t WHERE 1 = 2 XOR 1 = 1",
            "DELETE FROM t WHERE TRUE XOR FALSE",
            "DELETE FROM t WHERE FALSE XOR TRUE",
            "DELETE FROM t WHERE NOT (1 = 1) XOR TRUE",
            // `AND` binds tighter, and is false whatever `c` is.
            "DELETE FROM t WHERE 1 = 1 XOR 1 = 2 AND c > 0",
            "UPDATE t SET a = 1 WHERE (1 = 1 XOR 1 = 1) XOR TRUE",
        ] {
            assert!(mysql_tautology(every_row), "{every_row}");
        }
        for bounded in [
            // A side that depends on the row.
            "DELETE FROM t WHERE 1 = 1 XOR c > 0",
            "DELETE FROM t WHERE c > 0 XOR 1 = 2",
            // Always false: both sides true, or both false.
            "DELETE FROM t WHERE 1 = 1 XOR 1 = 1",
            "DELETE FROM t WHERE FALSE XOR 1 = 2",
            "DELETE FROM t WHERE NOT (1 = 1 XOR 1 = 2)",
        ] {
            assert!(!mysql_tautology(bounded), "{bounded}");
        }
        // And its negation where it is always false.
        assert!(mysql_tautology("DELETE FROM t WHERE NOT (1 = 1 XOR 1 = 1)"));
    }

    #[test]
    fn a_long_xor_chain_is_judged_in_linear_time() {
        let _folding = crate::ir::normalize::default_folding();
        // Each operand depends on its row: not every row matches. Lowering
        // keeps the chain no deeper than it keeps any expression.
        let operands: Vec<String> = (0..2_000).map(|i| format!("c{i} > 0")).collect();
        assert!(!mysql_tautology(&format!(
            "DELETE FROM t WHERE {}",
            operands.join(" XOR ")
        )));
        // A run of operands that are each always true is always true
        // where their number is odd, and always false where it is even.
        let run = |operands: usize| vec!["1 = 1"; operands].join(" XOR ");
        assert!(mysql_tautology(&format!("DELETE FROM t WHERE {}", run(51))));
        assert!(!mysql_tautology(&format!(
            "DELETE FROM t WHERE {}",
            run(50)
        )));
        assert!(mysql_tautology(&format!(
            "DELETE FROM t WHERE NOT ({})",
            run(50)
        )));
    }

    #[test]
    fn a_self_referential_in_compares_a_qualifier_segment_by_segment() {
        let _folding = crate::ir::normalize::default_folding();
        assert!(tautology(
            "DELETE FROM t WHERE zz.s.id IN (SELECT zz.s.id FROM t)"
        ));
        // A quoted segment is the unquoted one it normalizes to.
        assert!(tautology(
            "DELETE FROM t WHERE \"ZZ\".s.id IN (SELECT zz.s.id FROM t)"
        ));
        assert!(!tautology(
            "DELETE FROM t WHERE \"zz\".s.id IN (SELECT zz.s.id FROM t)"
        ));
        assert!(!tautology(
            "DELETE FROM t WHERE yy.s.id IN (SELECT zz.s.id FROM t)"
        ));
    }
}
