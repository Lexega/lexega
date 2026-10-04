// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Derive a rule's [`RuleCategory`] from the recognition surface its
//! predicate reads — the statement kind it gates on and the fact families
//! its top-level paths reference. Computed once at compile time (see
//! [`super::compile::compile`]) and stored on the compiled rule; never
//! authored on the rule itself.
//!
//! This is the fact-family-aware half of category derivation, layered over
//! [`crate::facts::category_of_kind`]: it catches rules with no statement-kind
//! gate (e.g. query-shape rules read `query.*`), routes the `diff` family to
//! change-safety, and lets a coarse `alter_table` rule that reads a table
//! policy-attachment fact resolve to data-protection.

use super::predicate::{FieldName, FieldPath, Predicate, PredicateLiteral, ScalarOp};
use crate::facts::{category_of_kind, RuleCategory, StatementKind};

/// `ddl.table` fact fields that signal a data-protection (policy-attachment)
/// concern even though the coarse statement kind is `alter_table`.
const TABLE_POLICY_FIELDS: &[&str] = &[
    "row_access_policy_added",
    "row_access_policy_removed",
    "masking_policy_added",
    "masking_policy_removed",
    "aggregation_policy_removed",
    "drop_all_row_access_policies",
];

/// Top-level fact families mapped to a category, used only when a rule carries
/// no statement-kind gate. Order is precedence (first match wins).
const FAMILY_FALLBACK: &[(&str, RuleCategory)] = &[
    ("privilege", RuleCategory::AccessControl),
    ("pg_default_privileges", RuleCategory::AccessControl),
    ("policy_attachment", RuleCategory::DataProtection),
    ("policy", RuleCategory::DataProtection),
    ("integration", RuleCategory::Integration),
    ("query", RuleCategory::Query),
    ("algebra", RuleCategory::Query),
    ("use_stmt", RuleCategory::AccessControl),
    ("pg_copy", RuleCategory::DataMovement),
];

/// The recognition surface gathered from one walk of a rule's predicate:
/// the statement kinds it positively gates on, and the named segments of
/// every top-level (statement-root) fact path it reads.
#[derive(Default)]
struct Surface {
    kinds: Vec<StatementKind>,
    paths: Vec<Vec<String>>,
}

/// Recognition-derived category of a rule.
///
/// Precedence: the `diff` family (a change-safety concern whose gated kind is
/// the underlying statement) and `ddl.table` policy-attachment facts (a
/// confidentiality concern the coarse `alter_table` kind hides) override the
/// statement kind; otherwise the statement kind decides; rules with no kind
/// gate fall back to the fact family they read; anything unresolved is
/// [`RuleCategory::Unclassified`].
pub(crate) fn category_of_rule(p: &Predicate) -> RuleCategory {
    let mut s = Surface::default();
    walk(p, false, &mut s);

    if s.paths.iter().any(|segs| root_is(segs, "diff")) {
        return RuleCategory::ChangeSafety;
    }
    if s.paths.iter().any(|segs| is_table_policy_path(segs)) {
        return RuleCategory::DataProtection;
    }
    if let Some(kind) = s.kinds.first() {
        return category_of_kind(*kind);
    }
    for (root, cat) in FAMILY_FALLBACK {
        if s.paths.iter().any(|segs| root_is(segs, root)) {
            return *cat;
        }
    }
    RuleCategory::Unclassified
}

/// Walk the predicate tree collecting the recognition surface. Mirrors the
/// root-path traversal used by `validate_root_field_paths` /
/// `predicate_kind_gate`: recurse `all_of` / `any_of` / `not`, but treat a
/// relational quantifier body as element-relative — its inner paths are not
/// statement-root fact families, so only the relation's own path is recorded.
fn walk(p: &Predicate, negated: bool, out: &mut Surface) {
    match p {
        Predicate::AllOf(parts) | Predicate::AnyOf(parts) => {
            for c in parts {
                walk(c, negated, out);
            }
        }
        Predicate::Not(inner) => walk(inner, !negated, out),
        Predicate::Scalar(s) => {
            record_path(&s.path, out);
            // A negated `kind:` ("kind is not X") does not positively gate the
            // statement kind, so only collect kinds from positive contexts.
            if !negated {
                collect_kinds(&s.path, &s.op, out);
            }
        }
        Predicate::Relational(r) => record_path(&r.path, out),
    }
}

fn record_path(path: &FieldPath, out: &mut Surface) {
    let segs: Vec<String> = path
        .segments
        .iter()
        .filter_map(|seg| match seg {
            FieldName::Named(n) => Some(n.clone()),
            FieldName::Index(_) => None,
        })
        .collect();
    if !segs.is_empty() {
        out.paths.push(segs);
    }
}

fn collect_kinds(path: &FieldPath, op: &ScalarOp, out: &mut Surface) {
    if !is_statement_kind_path(path) {
        return;
    }
    match op {
        ScalarOp::Eq(lit) | ScalarOp::EqExplicit(lit) => {
            if let Some(k) = kind_from_literal(lit) {
                out.kinds.push(k);
            }
        }
        ScalarOp::In(lits) => {
            for lit in lits {
                if let Some(k) = kind_from_literal(lit) {
                    out.kinds.push(k);
                }
            }
        }
        // Complement / range / presence ops don't bind the kind to a positive
        // statement-kind set; nothing to collect.
        ScalarOp::Neq(_)
        | ScalarOp::Gt(_)
        | ScalarOp::Lt(_)
        | ScalarOp::Gte(_)
        | ScalarOp::Lte(_)
        | ScalarOp::Matches(_)
        | ScalarOp::NotIn(_)
        | ScalarOp::Contains(_)
        | ScalarOp::ContainsAny(_)
        | ScalarOp::ContainsAll(_)
        | ScalarOp::Exists(_)
        | ScalarOp::IsNull(_)
        | ScalarOp::Range { .. } => {}
    }
}

/// True iff the path is exactly the top-level scalar `kind` field — the
/// statement-kind discriminant (not a nested `…​.kind` of some element).
fn is_statement_kind_path(path: &FieldPath) -> bool {
    matches!(path.segments.as_slice(), [FieldName::Named(name)] if name == "kind")
}

fn kind_from_literal(lit: &PredicateLiteral) -> Option<StatementKind> {
    match lit {
        // A `kind:` literal that is not a StatementKind (e.g. a DiffEvent kind
        // used inside a quantifier body) never reaches here — bodies aren't
        // walked — so an unresolved string simply yields `None`.
        PredicateLiteral::String(s) => {
            serde_json::from_value(serde_json::Value::String(s.clone())).ok()
        }
        PredicateLiteral::Bool(_)
        | PredicateLiteral::Integer(_)
        | PredicateLiteral::Float(_)
        | PredicateLiteral::Null
        | PredicateLiteral::Typed(_) => None,
    }
}

fn is_table_policy_path(segs: &[String]) -> bool {
    match segs {
        [a, b, c, ..] => a == "ddl" && b == "table" && TABLE_POLICY_FIELDS.contains(&c.as_str()),
        _ => false,
    }
}

fn root_is(segs: &[String], name: &str) -> bool {
    segs.first().map(String::as_str) == Some(name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::predicate::{Quantifier, RelationalMatch, ScalarMatch};

    fn scalar(path: &str, op: ScalarOp) -> Predicate {
        Predicate::Scalar(ScalarMatch {
            path: FieldPath::parse(path),
            op,
        })
    }

    fn kind_eq(k: &str) -> Predicate {
        scalar(
            "kind",
            ScalarOp::Eq(PredicateLiteral::String(k.to_string())),
        )
    }

    #[test]
    fn grant_rule_is_access_control() {
        // GRT-TO-PUBLIC shape: kind grant + privilege.grantees relation.
        let p = Predicate::AllOf(vec![
            kind_eq("grant"),
            Predicate::Relational(RelationalMatch {
                path: FieldPath::parse("privilege.grantees"),
                quantifier: Quantifier::Exists(Box::new(scalar(
                    "name.normalized",
                    ScalarOp::In(vec![PredicateLiteral::String("PUBLIC".to_string())]),
                ))),
            }),
        ]);
        assert_eq!(category_of_rule(&p), RuleCategory::AccessControl);
    }

    #[test]
    fn query_rule_without_kind_falls_back_to_family() {
        // Q-PRED-CONTRA shape: no kind gate, reads query.*.
        let p = Predicate::Relational(RelationalMatch {
            path: FieldPath::parse("query.column_constraints"),
            quantifier: Quantifier::Each(Box::new(scalar(
                "anomalies",
                ScalarOp::Contains(PredicateLiteral::String("equality_disjoint".to_string())),
            ))),
        });
        assert_eq!(category_of_rule(&p), RuleCategory::Query);
    }

    #[test]
    fn diff_family_overrides_kind() {
        // DIFF-WRITE-WHERE-RMV shape: top-level diff.events; the inner `kind:`
        // is a DiffEvent inside the quantifier body, never walked.
        let p = Predicate::Relational(RelationalMatch {
            path: FieldPath::parse("diff.events"),
            quantifier: Quantifier::Each(Box::new(Predicate::AllOf(vec![
                kind_eq("write_boundedness_changed"),
                scalar(
                    "direction",
                    ScalarOp::Eq(PredicateLiteral::String("unbounded".to_string())),
                ),
            ]))),
        });
        assert_eq!(category_of_rule(&p), RuleCategory::ChangeSafety);
    }

    #[test]
    fn alter_table_masking_removal_is_data_protection() {
        // TBL-MASK-RMV: kind alter_table, but reads a table policy fact.
        let p = Predicate::AllOf(vec![
            kind_eq("alter_table"),
            scalar(
                "ddl.table.masking_policy_removed",
                ScalarOp::Eq(PredicateLiteral::Bool(true)),
            ),
        ]);
        assert_eq!(category_of_rule(&p), RuleCategory::DataProtection);
    }

    #[test]
    fn plain_alter_table_is_schema_design() {
        let p = Predicate::AllOf(vec![
            kind_eq("alter_table"),
            scalar(
                "ddl.table.column_dropped",
                ScalarOp::Eq(PredicateLiteral::Bool(true)),
            ),
        ]);
        assert_eq!(category_of_rule(&p), RuleCategory::SchemaDesign);
    }

    #[test]
    fn masking_policy_kind_is_data_protection() {
        assert_eq!(
            category_of_rule(&kind_eq("create_masking_policy")),
            RuleCategory::DataProtection
        );
    }

    #[test]
    fn no_recognizable_surface_is_unclassified() {
        let p = scalar("source_span", ScalarOp::Exists(true));
        assert_eq!(category_of_rule(&p), RuleCategory::Unclassified);
    }
}
