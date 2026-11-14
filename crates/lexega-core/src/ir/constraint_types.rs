// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Value-domain constraint types.
//!
//! The wire shapes that describe what a predicate says about one column's
//! values, and the detector for OR-branch patterns that are always true.
//!
//! ## Surface
//!
//! - [`IrRangeBound`] — a bound (inclusive flag + value-as-string).
//! - [`IrConstraint`] — closed enum over the seven modelled constraint
//!   shapes.
//! - [`IrColumnConstraints`] — the constraints recorded for one column.
//! - [`IrConstraintSet`] — `IdentKey`-keyed map of column constraints,
//!   the wire shape carried on `CteColumnSchema.constraint_set` /
//!   `DerivedTableSchema.constraint_set` / `ResolvedModel.constraint_set`.
//! - [`pred_to_col_key`] — the binding-aware key predicates are bucketed
//!   by.
//! - [`detect_tautologies_in_scope`] — always-true OR-branch patterns,
//!   reported as [`TautologyFinding`]s.
//! - [`literal_equality`] — whether two literal values are equal in the
//!   dialect in force.

use std::collections::BTreeMap;

use crate::context::node_metadata::{IdentKey, PredicateFact};
use crate::ir::column::BindingTable;
use crate::ir::normalize_identifier;
use crate::lexer::Span;

// ────────────────────────────────────────────────────────────────────────
// Core types
// ────────────────────────────────────────────────────────────────────────

/// A bound in a range constraint.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct IrRangeBound {
    /// The literal value as a string (compared numerically when possible).
    pub value: String,
    /// True if the bound is inclusive (>=, <=), false if exclusive (>, <).
    pub inclusive: bool,
}

/// A single constraint on a column's value domain.
///
/// Closed enum over the seven modelled shapes. Constraint kinds outside
/// this set (`LIKE`, `BETWEEN`, structural sub-path equality) have no
/// representation here.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum IrConstraint {
    /// Column equals a specific literal: `col = 'X'`.
    Eq(String),
    /// Column does not equal a specific literal: `col <> 'X'`.
    NotEq(String),
    /// Column is in a set of literals: `col IN ('A', 'B', 'C')`.
    InSet(Vec<String>),
    /// Column is not in a set: `col NOT IN ('A', 'B')`.
    NotInSet(Vec<String>),
    /// Column satisfies a range: `col > 3 AND col < 10`.
    Range {
        lower: Option<IrRangeBound>,
        upper: Option<IrRangeBound>,
    },
    /// Column IS NULL.
    IsNull,
    /// Column IS NOT NULL.
    IsNotNull,
}

/// All constraints on a single column (AND-connected within the same scope).
///
/// Carries both the recorded [`IrConstraint`] entries (the only
/// representation of `NotEq` / `NotInSet` facts) and a denormalised
/// summary (eq / in-set / range / null flags). A writer keeps the two in
/// step.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct IrColumnConstraints {
    /// The recorded constraints, in insertion order.
    #[serde(default)]
    pub constraints: Vec<IrConstraint>,

    // Serialization-friendly summaries for CTE/DT schema storage:
    /// Equality value, if column is constrained to a single value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub eq_value: Option<String>,
    /// IN-set values, if column is constrained to a set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub in_values: Option<Vec<String>>,
    /// Lower bound (inclusive flag stored separately).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lower_bound: Option<String>,
    #[serde(default)]
    pub lower_inclusive: bool,
    /// Upper bound.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upper_bound: Option<String>,
    #[serde(default)]
    pub upper_inclusive: bool,
    /// IS NULL constraint.
    #[serde(default)]
    pub is_null: bool,
    /// IS NOT NULL constraint.
    #[serde(default)]
    pub is_not_null: bool,
    /// The rows these are said of hold none: a filter contradicted what
    /// its input held of the column. What the summary says is that
    /// filter's claim; no row holds a value a reader could contradict.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub holds_no_row: bool,
}

impl IrColumnConstraints {
    pub fn new() -> Self {
        Self::default()
    }
}

// ────────────────────────────────────────────────────────────────────────
// IrConstraintSet — IdentKey-keyed surface (CTE / DT / model wire shape)
// ────────────────────────────────────────────────────────────────────────

/// Constraints for all columns visible at a CTE / derived-table / model
/// boundary. Wire-shape for `CteColumnSchema.constraint_set` /
/// `DerivedTableSchema.constraint_set` / `ResolvedModel.constraint_set` /
/// `ModelEntry.constraint_set`.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct IrConstraintSet {
    /// Per-column constraints (AND-connected within same OR branch).
    columns: BTreeMap<IdentKey, IrColumnConstraints>,
}

impl IrConstraintSet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_empty(&self) -> bool {
        self.columns.is_empty()
    }

    pub fn get(&self, col: &IdentKey) -> Option<&IrColumnConstraints> {
        self.columns.get(col)
    }

    pub fn insert(&mut self, col: IdentKey, constraints: IrColumnConstraints) {
        self.columns.insert(col, constraints);
    }

    pub fn iter(&self) -> impl Iterator<Item = (&IdentKey, &IrColumnConstraints)> {
        self.columns.iter()
    }

    pub fn get_mut(&mut self, col: &IdentKey) -> Option<&mut IrColumnConstraints> {
        self.columns.get_mut(col)
    }

    /// The constraints recorded for `col`, inserting an empty entry when
    /// there is none.
    pub fn get_or_insert_default(&mut self, col: IdentKey) -> &mut IrColumnConstraints {
        self.columns.entry(col).or_default()
    }
}

// ────────────────────────────────────────────────────────────────────────
// Column keys
// ────────────────────────────────────────────────────────────────────────

/// Build a binding-aware column key from a [`PredicateFact`]. The
/// IR's projection sets `column.resolved_table` whenever the column
/// binds to a base-table scan, which is the structural identity that
/// distinguishes `u.status` (resolved to `users`) from `o.status`
/// (resolved to `orders`) even when neither carries a literal
/// qualifier on the [`crate::context::node_metadata::ColumnRef`].
///
/// Order of preference (strictest first):
///
///   1. `resolved_table` (set by `ir::predicate_extraction::column_id_to_ref`
///      when the binding origin is [`crate::ir::column::ColumnOrigin::Table`]).
///   2. The literal `qualifier` string captured at AST construction.
///   3. The bare column name.
///
/// All three layers normalize via [`normalize_identifier`] so the
/// resulting [`IdentKey`] is the case-folded canonical form; every
/// consumer that buckets predicates by column uses this one key.
///
/// An atom over a field of a column keys by the column id followed by
/// its path, so it shares a bucket with neither the bare column nor
/// another path.
pub fn pred_to_col_key(pred: &PredicateFact, bindings: &BindingTable) -> IdentKey {
    // A variable's atom is keyed by the variable, apart from every column.
    if let Some(variable) = &pred.variable {
        return IdentKey::from_normalized(format!("var:{}", variable.as_str()));
    }
    match column_id_to_col_key(pred.column_id, bindings) {
        Some(key) if pred.field_path.is_empty() => key,
        Some(key) => {
            IdentKey::from_normalized(format!("{}{}", key.as_str(), pred.field_path.suffix_text()))
        }
        None => IdentKey::new(&pred_column_identity(&pred.column)),
    }
}

/// Canonicalize a `ColumnId` to a bucket key.
///
/// The id is the identity: every reference to a column of a source
/// carries the source's one id for it, and a computed, set-operation,
/// outer or recursive id each represents a distinct synthesized value.
/// Two aliases of one table (`t AS a`, `t AS b`) are distinct sources
/// with distinct ids.
///
/// Returns `None` when there is no id; callers fall back to a
/// text-based identity for those edge paths.
pub fn column_id_to_col_key(
    column_id: Option<crate::ir::column::ColumnId>,
    _bindings: &BindingTable,
) -> Option<IdentKey> {
    column_id.map(|cid| IdentKey::new(&format!("cid:{}", cid.as_u32())))
}

/// User-visible column display string. `T.col` when the column
/// resolves to a base table; falls back to `alias.col` / `col` when
/// the lineage didn't reach a base table. Used for the `column`
/// field on the customer-facing `ColumnConstraintEvent`.
pub fn pred_column_identity(col: &crate::context::node_metadata::ColumnRef) -> String {
    let name = normalize_identifier(&col.name);
    if let Some(t) = &col.resolved_table {
        let tkey = resolved_table_identity(t);
        return format!("{}.{}", tkey, name);
    }
    if let Some(q) = &col.qualifier {
        return format!("{}.{}", normalize_identifier(q), name);
    }
    name
}

fn resolved_table_identity(t: &crate::context::node_metadata::TableRef) -> String {
    let name = normalize_identifier(&t.name);
    match (&t.db, &t.schema) {
        (Some(d), Some(s)) => format!(
            "{}.{}.{}",
            normalize_identifier(d),
            normalize_identifier(s),
            name
        ),
        (None, Some(s)) => format!("{}.{}", normalize_identifier(s), name),
        (Some(d), None) => format!("{}..{}", normalize_identifier(d), name),
        (None, None) => name,
    }
}

// ────────────────────────────────────────────────────────────────────────
// Always-true OR-branch patterns
// ────────────────────────────────────────────────────────────────────────

/// One always-true OR-branch pattern found by
/// [`detect_tautologies_in_scope`].
#[derive(Debug, Clone)]
pub struct TautologyFinding {
    /// Human-readable description.
    pub message: String,
    /// Bucket key of the column the pattern sits on ([`pred_to_col_key`]).
    pub column: String,
    /// Typed identity of that column, when the predicates carry one.
    pub column_id: Option<crate::ir::column::ColumnId>,
    /// Leftmost witness predicate.
    pub span: Span,
}

/// Earlier-by-start-position span between two witness predicates of an
/// OR-branch tautology. Picking the leftmost witness keeps the
/// emitted `:line:col` stable when the predicate-list order shifts
/// under refactoring.
fn witness_span(a: Span, b: Span) -> Span {
    if a.start <= b.start {
        a
    } else {
        b
    }
}

/// What [`detect_tautologies_in_scope`] buckets atoms by: a column's
/// key, or the variable a reflexive variable atom reads.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
enum AtomKey {
    Column(String),
    Variable(IdentKey),
}

/// Detect tautological predicate patterns across OR branches, among the
/// predicates of one scope.
///
/// Returns one [`TautologyFinding`] per detected tautology. Patterns:
/// - `x = lit OR x <> lit` (equality + opposite negation)
/// - `x IS NULL OR x IS NOT NULL`
/// - `x >= N OR x < N` / `x > N OR x <= N` (complementary ranges)
///
/// Only predicates whose `scope_id` and `join_scope_id` match the targets
/// are considered. `column` carries the column's bucket key and `span` the
/// leftmost witness predicate.
pub fn detect_tautologies_in_scope(
    predicates: &[PredicateFact],
    bindings: &BindingTable,
    target_scope_id: u32,
    target_join_scope_id: u32,
) -> Vec<TautologyFinding> {
    let mut findings = Vec::new();

    let mut by_column: BTreeMap<AtomKey, Vec<&PredicateFact>> = BTreeMap::new();
    for pred in predicates {
        if pred.scope_id != target_scope_id || pred.join_scope_id != target_join_scope_id {
            continue;
        }
        // Bucket by the binding-aware column key, so tautology
        // detection across multi-alias self-joins doesn't conflate
        // predicates that sit on separate scans; a variable's atom by
        // the variable.
        let key = match &pred.variable {
            Some(variable) => AtomKey::Variable(variable.clone()),
            None => AtomKey::Column(pred_to_col_key(pred, bindings).as_str().to_string()),
        };
        by_column.entry(key).or_default().push(pred);
    }

    use crate::context::node_metadata::PredicateOp;
    use crate::ir::scalar::ComparisonOp;
    for (key, preds) in &by_column {
        // A column's findings carry its bucket key; a variable's its name
        // as written.
        let col = match key {
            AtomKey::Column(col) => col.as_str(),
            AtomKey::Variable(_) => preds.first().map_or("", |p| p.column.name.as_str()),
        };
        // All predicates in this bucket are equivalent under
        // `pred_to_col_key`'s BindingTable-driven canonicalization;
        // pick any predicate's `column_id` to stamp on emitted
        // findings — a consumer re-derives the bucket key through
        // the same `pred_to_col_key` path.
        let col_id = preds.first().and_then(|p| p.column_id);
        // Pattern 1: x = 'A' OR x <> 'A' (or x != 'A')
        let eq_preds: Vec<&&PredicateFact> = preds
            .iter()
            .filter(|p| {
                matches!(p.operator, PredicateOp::Compare(ComparisonOp::Eq))
                    && p.literal_value.is_some()
            })
            .collect();
        let neq_preds: Vec<&&PredicateFact> = preds
            .iter()
            .filter(|p| {
                matches!(p.operator, PredicateOp::Compare(ComparisonOp::NotEq))
                    && p.literal_value.is_some()
            })
            .collect();

        for eq in &eq_preds {
            for neq in &neq_preds {
                if eq.or_branch_id != neq.or_branch_id {
                    if let (Some(ref ev), Some(ref nv)) = (&eq.literal_value, &neq.literal_value) {
                        if literal_equality(ev, nv) == LiteralEquality::Equal {
                            findings.push(TautologyFinding {
                                message: format!(
                                    "{} = '{}' OR {} <> '{}' is always true (tautology)",
                                    col, ev, col, nv
                                ),
                                column: col.to_string(),
                                column_id: col_id,
                                span: witness_span(eq.span, neq.span),
                            });
                        }
                    }
                }
            }
        }

        // Pattern 2: x IS NULL OR x IS NOT NULL
        let null_preds: Vec<&&PredicateFact> = preds
            .iter()
            .filter(|p| matches!(p.operator, PredicateOp::IsNull))
            .collect();
        let not_null_preds: Vec<&&PredicateFact> = preds
            .iter()
            .filter(|p| matches!(p.operator, PredicateOp::IsNotNull))
            .collect();

        if !null_preds.is_empty() && !not_null_preds.is_empty() {
            for null_p in &null_preds {
                for not_null_p in &not_null_preds {
                    if null_p.or_branch_id != not_null_p.or_branch_id {
                        findings.push(TautologyFinding {
                            message: format!(
                                "{} IS NULL OR {} IS NOT NULL is always true (tautology)",
                                col, col
                            ),
                            column: col.to_string(),
                            column_id: col_id,
                            span: witness_span(null_p.span, not_null_p.span),
                        });
                        break;
                    }
                }
            }
        }

        // Pattern 3: range-union domain cover.
        //
        // A lower-bound disjunct (`x > B` / `x >= B`) together with an
        // upper-bound disjunct (`x < A` / `x <= A`) in a DISTINCT OR
        // branch covers every non-NULL value iff the two half-lines
        // leave no gap: `A > B`, or `A == B` with at least one bound
        // inclusive. This subsumes the complementary-at-same-literal
        // forms (`x >= N OR x < N`, `x > N OR x <= N`) and additionally
        // catches overlapping covers with distinct literals
        // (`x < 10 OR x > 5`). Ordering uses `compare_values` (numeric
        // first, lexical fallback). NULL is not covered (no `IS NULL`
        // disjunct), so this is a non-NULL tautology only.
        let lower_preds: Vec<&&PredicateFact> = preds
            .iter()
            .filter(|p| {
                matches!(
                    p.operator,
                    PredicateOp::Compare(ComparisonOp::Gt | ComparisonOp::GtEq)
                ) && p.literal_value.is_some()
            })
            .collect();
        let upper_preds: Vec<&&PredicateFact> = preds
            .iter()
            .filter(|p| {
                matches!(
                    p.operator,
                    PredicateOp::Compare(ComparisonOp::Lt | ComparisonOp::LtEq)
                ) && p.literal_value.is_some()
            })
            .collect();

        'range_union: for lo in &lower_preds {
            for up in &upper_preds {
                if lo.or_branch_id == up.or_branch_id {
                    continue;
                }
                let (Some(b_val), Some(a_val)) =
                    (lo.literal_value.as_deref(), up.literal_value.as_deref())
                else {
                    continue;
                };
                let lo_incl = matches!(lo.operator, PredicateOp::Compare(ComparisonOp::GtEq));
                let up_incl = matches!(up.operator, PredicateOp::Compare(ComparisonOp::LtEq));
                let covered = match compare_values(a_val, b_val) {
                    std::cmp::Ordering::Greater => true,
                    std::cmp::Ordering::Equal => lo_incl || up_incl,
                    std::cmp::Ordering::Less => false,
                };
                if covered {
                    findings.push(TautologyFinding {
                        message: format!(
                            "{} {} {} OR {} {} {} is always true (tautology)",
                            col,
                            if up_incl { "<=" } else { "<" },
                            a_val,
                            col,
                            if lo_incl { ">=" } else { ">" },
                            b_val
                        ),
                        column: col.to_string(),
                        column_id: col_id,
                        span: witness_span(up.span, lo.span),
                    });
                    break 'range_union;
                }
            }
        }

        // Pattern 3c: IN / NOT IN complement over an identical value set.
        //   `x IN (a, b) OR x NOT IN (a, b)`
        // covers every non-NULL value: any non-NULL `x` is either in the
        // set or not. Requires the two disjuncts to range over the SAME
        // literal set (compared as sets — order/duplicates ignored) and
        // sit in distinct OR branches. A differing set (`IN (1,2) OR
        // NOT IN (1,2,3)`) leaves a gap and is not a tautology. NULL is
        // not covered (`NULL IN (...)` and `NULL NOT IN (...)` are both
        // UNKNOWN), so this is a non-NULL tautology only.
        let in_preds: Vec<&&PredicateFact> = preds
            .iter()
            .filter(|p| matches!(p.operator, PredicateOp::In) && p.in_list_values.is_some())
            .collect();
        let not_in_preds: Vec<&&PredicateFact> = preds
            .iter()
            .filter(|p| matches!(p.operator, PredicateOp::NotIn) && p.in_list_values.is_some())
            .collect();

        // Every value of each set equal to a value of the other.
        let covers = |of: &[String], by: &[String]| {
            of.iter().all(|value| {
                by.iter()
                    .any(|other| literal_equality(value, other) == LiteralEquality::Equal)
            })
        };
        'in_complement: for inp in &in_preds {
            for notinp in &not_in_preds {
                if inp.or_branch_id == notinp.or_branch_id {
                    continue;
                }
                let (Some(iv), Some(nv)) = (&inp.in_list_values, &notinp.in_list_values) else {
                    continue;
                };
                if covers(iv, nv) && covers(nv, iv) {
                    findings.push(TautologyFinding {
                        message: format!(
                            "{} IN (...) OR {} NOT IN (...) over the same set is always true (tautology)",
                            col, col
                        ),
                        column: col.to_string(),
                        column_id: col_id,
                        span: witness_span(inp.span, notinp.span),
                    });
                    break 'in_complement;
                }
            }
        }

        // Pattern 3d: reflexive self-comparison (`x = x`, `x >= x`,
        // `x <= x`, and negated forms like `NOT (x <> x)`). `x <op> x`
        // has a constant truth value for every non-NULL `x`: TRUE for
        // `=` / `>=` / `<=`, FALSE for `<>` / `<` / `>`; an enclosing
        // NOT flips it. A non-NULL-true reflexive atom is a tautology
        // that provides no filtering. NULL is not covered
        // (`NULL <op> NULL` is UNKNOWN), so this is a non-NULL tautology
        // only — `x = x` never drives the every-row unbounded-write
        // verdict unless the column is independently proven non-null.
        if let Some(rp) = preds.iter().find(|p| {
            let PredicateOp::Compare(c) = p.operator else {
                return false;
            };
            if !p.is_reflexive {
                return false;
            }
            let true_for_non_null = matches!(
                c,
                ComparisonOp::Eq | ComparisonOp::GtEq | ComparisonOp::LtEq
            );
            true_for_non_null ^ p.is_negated
        }) {
            findings.push(TautologyFinding {
                message: format!(
                    "{} compared to itself is always true for non-NULL rows (tautology)",
                    col
                ),
                column: col.to_string(),
                column_id: col_id,
                span: rp.span,
            });
        }

        // Pattern 3e: BETWEEN / NOT-BETWEEN complement over an identical
        // closed interval.
        //   `x BETWEEN lo AND hi OR x NOT BETWEEN lo AND hi`
        // covers every non-NULL value — any non-NULL `x` is inside the
        // interval or outside it. The positive side is recognised in
        // either representation: a `Between` atom carrying `between_bounds`
        // (the synthetic OR-chain path), or the live extraction's
        // decomposition into a `>= lo` AND `<= hi` Compare pair sharing one
        // OR branch. The negative side is a `NotBetween` atom carrying the
        // same bounds. Bounds compare numerically (`compare_values`), so
        // `1` and `1.0` describe the same interval. Distinct OR branches
        // required. NULL is not covered, so this is a non-NULL tautology
        // only.
        let bounds_eq =
            |a: &str, b: &str| matches!(compare_values(a, b), std::cmp::Ordering::Equal);
        let positive_covers = |lo: &str, hi: &str, exclude_branch: u32| -> bool {
            // Direct `Between` atom with matching bounds, distinct branch.
            let direct = preds.iter().any(|p| {
                matches!(p.operator, PredicateOp::Between)
                    && p.or_branch_id != exclude_branch
                    && p.between_bounds
                        .as_ref()
                        .is_some_and(|b| bounds_eq(&b.low, lo) && bounds_eq(&b.high, hi))
            });
            if direct {
                return true;
            }
            // Decomposed `>= lo` AND `<= hi` sharing one distinct branch.
            preds.iter().any(|p| {
                p.or_branch_id != exclude_branch
                    && preds.iter().any(|q| {
                        q.or_branch_id == p.or_branch_id
                            && matches!(q.operator, PredicateOp::Compare(ComparisonOp::GtEq))
                            && q.literal_value.as_deref().is_some_and(|v| bounds_eq(v, lo))
                    })
                    && preds.iter().any(|q| {
                        q.or_branch_id == p.or_branch_id
                            && matches!(q.operator, PredicateOp::Compare(ComparisonOp::LtEq))
                            && q.literal_value.as_deref().is_some_and(|v| bounds_eq(v, hi))
                    })
            })
        };
        'between_complement: for nb in preds {
            if !matches!(nb.operator, PredicateOp::NotBetween) {
                continue;
            }
            let Some(b) = &nb.between_bounds else {
                continue;
            };
            if positive_covers(&b.low, &b.high, nb.or_branch_id) {
                findings.push(TautologyFinding {
                    message: format!(
                        "{} BETWEEN {} AND {} OR {} NOT BETWEEN {} AND {} is always true (tautology)",
                        col, b.low, b.high, col, b.low, b.high
                    ),
                    column: col.to_string(),
                    column_id: col_id,
                    span: nb.span,
                });
                break 'between_complement;
            }
        }

        // Pattern 4: boolean-domain exhaustion
        //   x = TRUE OR x = FALSE OR x IS NULL
        // covers the full SQL boolean+NULL value domain. Boolean is the
        // sole SQL type whose entire domain is enumerable from literal
        // atoms alone (no catalog lookup needed). Requires all three
        // witnesses in distinct OR branches — if any two share a
        // branch they're AND'd at that level and don't form the
        // disjunctive cover.
        let bool_true_preds: Vec<&&PredicateFact> = preds
            .iter()
            .filter(|p| {
                matches!(p.operator, PredicateOp::Compare(ComparisonOp::Eq))
                    && p.literal_value
                        .as_deref()
                        .is_some_and(|v| v.eq_ignore_ascii_case("true"))
            })
            .collect();
        let bool_false_preds: Vec<&&PredicateFact> = preds
            .iter()
            .filter(|p| {
                matches!(p.operator, PredicateOp::Compare(ComparisonOp::Eq))
                    && p.literal_value
                        .as_deref()
                        .is_some_and(|v| v.eq_ignore_ascii_case("false"))
            })
            .collect();

        'pat4: for t in &bool_true_preds {
            for f in &bool_false_preds {
                for n in &null_preds {
                    if t.or_branch_id != f.or_branch_id
                        && t.or_branch_id != n.or_branch_id
                        && f.or_branch_id != n.or_branch_id
                    {
                        let leftmost = witness_span(witness_span(t.span, f.span), n.span);
                        findings.push(TautologyFinding {
                            message: format!(
                                "{} = TRUE OR {} = FALSE OR {} IS NULL is always true (tautology)",
                                col, col, col
                            ),
                            column: col.to_string(),
                            column_id: col_id,
                            span: leftmost,
                        });
                        break 'pat4;
                    }
                }
            }
        }
    }

    findings
}

// ────────────────────────────────────────────────────────────────────────
// Literal comparison
// ────────────────────────────────────────────────────────────────────────

/// Whether two literal values one operand is compared with are equal, as
/// the dialect in force compares them by default.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LiteralEquality {
    /// Equal under every collation the dialect may compare them by.
    Equal,
    /// Different under every such collation.
    Distinct,
    /// Not decided: literals of different kinds, which the operand reads
    /// through a cast, or strings the dialect's default collation may
    /// compare equal.
    Undecided,
}

/// Whether the literal values `a` and `b`, as an atom carries them, are
/// equal: numbers by value, strings by the dialect's default collation.
pub fn literal_equality(a: &str, b: &str) -> LiteralEquality {
    let equal_if = |same: bool| {
        if same {
            LiteralEquality::Equal
        } else {
            LiteralEquality::Distinct
        }
    };
    match (LiteralValue::of(a), LiteralValue::of(b)) {
        (LiteralValue::Str(a), LiteralValue::Str(b)) => string_equality(&a, &b),
        (LiteralValue::Number(a), LiteralValue::Number(b)) => equal_if(a == b),
        (LiteralValue::Bool(a), LiteralValue::Bool(b)) => equal_if(a == b),
        (LiteralValue::Other(a), LiteralValue::Other(b)) if a == b => LiteralEquality::Equal,
        (
            LiteralValue::Str(_)
            | LiteralValue::Number(_)
            | LiteralValue::Bool(_)
            | LiteralValue::Other(_),
            _,
        ) => LiteralEquality::Undecided,
    }
}

/// A literal value as an atom carries it, by kind.
enum LiteralValue<'a> {
    /// A string literal's value.
    Str(String),
    Number(Decimal),
    Bool(bool),
    /// Any other literal, as written.
    Other(&'a str),
}

impl<'a> LiteralValue<'a> {
    fn of(text: &'a str) -> Self {
        if let Some(value) = super::span_extract::string_literal_value(text) {
            return Self::Str(value);
        }
        let text = text.trim();
        if let Some(number) = Decimal::parse(text) {
            Self::Number(number)
        } else if text.eq_ignore_ascii_case("true") {
            Self::Bool(true)
        } else if text.eq_ignore_ascii_case("false") {
            Self::Bool(false)
        } else {
            Self::Other(text)
        }
    }
}

/// A decimal number written in digits, exactly: `0.digits × 10^exponent`,
/// `digits` without leading or trailing zeros; zero has no digits.
#[derive(PartialEq, Eq)]
struct Decimal {
    negative: bool,
    digits: String,
    exponent: i64,
}

impl Decimal {
    /// `[+-]digits[.digits][(e|E)[+-]digits]`.
    fn parse(text: &str) -> Option<Self> {
        let (negative, unsigned) = match text.strip_prefix('-') {
            Some(rest) => (true, rest),
            None => (false, text.strip_prefix('+').unwrap_or(text)),
        };
        let (mantissa, scale) = match unsigned.find(['e', 'E']) {
            Some(at) => (&unsigned[..at], unsigned[at + 1..].parse::<i64>().ok()?),
            None => (unsigned, 0),
        };
        let (whole, fraction) = mantissa.split_once('.').unwrap_or((mantissa, ""));
        let is_digits = |part: &str| part.bytes().all(|b| b.is_ascii_digit());
        if (whole.is_empty() && fraction.is_empty()) || !is_digits(whole) || !is_digits(fraction) {
            return None;
        }
        let all = format!("{whole}{fraction}");
        let significant = all.trim_start_matches('0');
        let leading = all.len() - significant.len();
        let digits = significant.trim_end_matches('0');
        if digits.is_empty() {
            return Some(Self {
                negative: false,
                digits: String::new(),
                exponent: 0,
            });
        }
        let exponent = i64::try_from(whole.len())
            .ok()?
            .checked_sub(i64::try_from(leading).ok()?)?
            .checked_add(scale)?;
        Some(Self {
            negative,
            digits: digits.to_string(),
            exponent,
        })
    }
}

/// Whether two string values are equal under the dialect in force's
/// default collation. Where it may ignore case, strings equal but for case
/// are undecided, as are strings with other than ASCII characters, which
/// such a collation may fold as well; where it ignores trailing spaces
/// (PAD SPACE), strings equal but for those are undecided.
fn string_equality(a: &str, b: &str) -> LiteralEquality {
    use crate::ir::CatalogDialect as D;
    if a == b {
        return LiteralEquality::Equal;
    }
    let (case, trailing_spaces) =
        match D::from_dialect_name(crate::ir::normalize::dialect_in_force().name()) {
            D::PostgreSql | D::Snowflake | D::BigQuery | D::Databricks => (false, false),
            D::Redshift => (false, true),
            D::MySql | D::MsSql | D::Default => (true, true),
        };
    if case && (!a.is_ascii() || !b.is_ascii()) {
        return LiteralEquality::Undecided;
    }
    let (a, b) = if trailing_spaces {
        (a.trim_end_matches(' '), b.trim_end_matches(' '))
    } else {
        (a, b)
    };
    if a == b || (case && a.eq_ignore_ascii_case(b)) {
        LiteralEquality::Undecided
    } else {
        LiteralEquality::Distinct
    }
}

/// Compare two values, trying numeric first, falling back to string; a
/// string literal compares by its value.
pub fn compare_values(a: &str, b: &str) -> std::cmp::Ordering {
    let a_clean = super::span_extract::literal_value_or_name(a);
    let b_clean = super::span_extract::literal_value_or_name(b);

    match (a_clean.parse::<f64>(), b_clean.parse::<f64>()) {
        (Ok(na), Ok(nb)) => na.partial_cmp(&nb).unwrap_or(std::cmp::Ordering::Equal),
        _ => a_clean.cmp(&b_clean),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::node_metadata::{ColumnRef, PredicateContext, PredicateOp};
    use crate::ir::normalize::NameKind;
    use crate::ir::scalar::ComparisonOp;

    /// An atom on a column `name` the plan gave no id, in OR branch
    /// `branch`.
    fn atom(name: &str, operator: PredicateOp, branch: u32) -> PredicateFact {
        PredicateFact {
            column: ColumnRef::new(name.to_string()),
            operator,
            literal_value: None,
            rhs_text: None,
            has_temporal: false,
            has_subquery: false,
            subquery_column: None,
            subquery_table: None,
            function_calls: Vec::new(),
            context: PredicateContext::Where,
            logical_operator: None,
            or_branch_id: branch,
            not_isolation_id: 0,
            scope_id: 0,
            join_scope_id: 0,
            in_list_values: None,
            between_bounds: None,
            is_negated: false,
            is_reflexive: false,
            span: Span::default(),
            column_id: None,
            variable: None,
            field_path: crate::ir::scalar::FieldPath::empty(),
        }
    }

    #[test]
    fn a_field_path_keys_apart_from_its_column_and_other_paths() {
        use crate::ir::column::ColumnId;
        use crate::ir::scalar::{FieldPath, FieldStep};
        let _folding = crate::ir::normalize::default_folding();
        let on = |path: &[&str]| PredicateFact {
            column_id: Some(ColumnId::new(3)),
            field_path: FieldPath::from_field_steps(
                &path
                    .iter()
                    .map(|field| FieldStep::Field((*field).to_string()))
                    .collect::<Vec<_>>(),
            ),
            ..atom("addr", PredicateOp::IsNull, 0)
        };
        let bindings = BindingTable::default();
        let key = |path: &[&str]| pred_to_col_key(&on(path), &bindings);
        assert_eq!(
            key(&[]),
            column_id_to_col_key(Some(ColumnId::new(3)), &bindings).expect("an id keys")
        );
        assert_eq!(key(&["zip"]), key(&["ZIP"]));
        assert_ne!(key(&["zip"]), key(&[]));
        assert_ne!(key(&["zip"]), key(&["city"]));
        assert_ne!(key(&["zip"]), key(&["zip", "code"]));
    }

    #[test]
    fn literal_values_compare_by_value_kind_and_the_dialects_collation() {
        use LiteralEquality::{Distinct, Equal, Undecided};
        let rows: &[(&str, &str, &str, LiteralEquality)] = &[
            ("snowflake", "1", "1.0", Equal),
            ("snowflake", "1.50", "1.5", Equal),
            ("snowflake", "10", "1e1", Equal),
            ("snowflake", "0.05", "5E-2", Equal),
            ("snowflake", "0", "0.000", Equal),
            ("snowflake", "1", "2", Distinct),
            (
                "snowflake",
                "12345678901234567890",
                "12345678901234567891",
                Distinct,
            ),
            ("snowflake", "'1.0'", "1", Undecided),
            ("snowflake", "true", "'true'", Undecided),
            ("snowflake", "true", "TRUE", Equal),
            ("postgresql", "'a'", "'A'", Distinct),
            ("postgresql", "'a'", "'a '", Distinct),
            ("snowflake", "'a'", "'A'", Distinct),
            ("bigquery", "'a'", "'A'", Distinct),
            ("databricks", "'a'", "'A'", Distinct),
            ("redshift", "'a'", "'A'", Distinct),
            ("snowflake", "'é'", "'e'", Distinct),
            ("snowflake", "'a'", "'a '", Distinct),
            ("redshift", "'a'", "'a '", Undecided),
            ("mysql", "'a'", "'a '", Undecided),
            ("mssql", "'A'", "'a  '", Undecided),
            ("mysql", "'é'", "'e'", Undecided),
            ("postgresql", "'é'", "'e'", Distinct),
            ("mysql", "'active'", "'inactive'", Distinct),
            ("mysql", "'a'", "'a'", Equal),
        ];
        for (dialect, a, b, expected) in rows {
            let _dialect = crate::ir::normalize::set_normalization_dialect(dialect);
            assert_eq!(literal_equality(a, b), *expected, "[{dialect}] {a} and {b}");
        }
    }

    #[test]
    fn a_variable_compared_with_itself_is_kept_apart_from_a_column_of_its_name() {
        let _folding = crate::ir::normalize::default_folding();
        let variable = PredicateFact {
            is_reflexive: true,
            variable: Some(IdentKey::new_as("id", NameKind::Column)),
            ..atom("id", PredicateOp::Compare(ComparisonOp::Eq), 0)
        };
        let predicates = [
            variable,
            atom("id", PredicateOp::IsNull, 1),
            atom("id", PredicateOp::IsNotNull, 2),
        ];
        let findings = detect_tautologies_in_scope(&predicates, &BindingTable::default(), 0, 0);
        let mut columns: Vec<&str> = findings.iter().map(|f| f.column.as_str()).collect();
        columns.sort_unstable();
        assert_eq!(columns, vec!["ID", "id"], "{findings:#?}");
        // A column atom compared with itself is not the variable's.
        let column = PredicateFact {
            is_reflexive: true,
            ..atom("id", PredicateOp::Compare(ComparisonOp::Eq), 0)
        };
        let findings = detect_tautologies_in_scope(&[column], &BindingTable::default(), 0, 0);
        let columns: Vec<&str> = findings.iter().map(|f| f.column.as_str()).collect();
        assert_eq!(columns, vec!["ID"], "{findings:#?}");
    }
}
