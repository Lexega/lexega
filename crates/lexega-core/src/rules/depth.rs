// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Whether a rule's predicate reads a fact a reasoning provider supplies.
//! Computed once at compile time (see [`super::compile::compile`]) and
//! stored on the compiled rule; never authored on the rule itself.

use super::predicate::{FieldName, FieldPath, Predicate, Quantifier};
use crate::facts::reasoning::is_reasoning_field;

/// True iff any path in `p` names one of
/// [`crate::facts::reasoning::REASONING_FIELDS`].
pub(crate) fn reads_reasoning(p: &Predicate) -> bool {
    reads(p, "")
}

/// `enclosing` is the fact key the predicate's paths are relative to:
/// empty at the statement root, the relation's own key inside a
/// quantifier body.
fn reads(p: &Predicate, enclosing: &str) -> bool {
    match p {
        Predicate::AllOf(parts) | Predicate::AnyOf(parts) => {
            parts.iter().any(|c| reads(c, enclosing))
        }
        Predicate::Not(inner) => reads(inner, enclosing),
        Predicate::Scalar(s) => path_reads(&s.path, enclosing).0,
        Predicate::Relational(r) => {
            let (hit, element_key) = path_reads(&r.path, enclosing);
            hit || match &r.quantifier {
                Quantifier::Exists(body)
                | Quantifier::All(body)
                | Quantifier::None(body)
                | Quantifier::Each(body) => reads(body, element_key),
                Quantifier::Count(_) => false,
            }
        }
    }
}

/// Whether `path` names a reasoning field, and the key its last named
/// segment leaves enclosing whatever follows.
fn path_reads<'a>(path: &'a FieldPath, enclosing: &'a str) -> (bool, &'a str) {
    let mut key = enclosing;
    let mut hit = false;
    for segment in &path.segments {
        match segment {
            FieldName::Named(name) => {
                hit |= is_reasoning_field(key, name);
                key = name;
            }
            FieldName::Index(_) => {}
        }
    }
    (hit, key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::predicate::parse_predicate;

    fn p(yaml: &str) -> Predicate {
        let v: serde_json::Value = serde_yaml_ng::from_str(yaml).expect("yaml parses");
        parse_predicate(&v).expect("predicate parses")
    }

    #[test]
    fn structural_paths_do_not_read_reasoning() {
        assert!(!reads_reasoning(&p("kind: delete")));
        assert!(!reads_reasoning(&p(
            "all_of:\n  - kind: delete\n  - query.has_where: false"
        )));
        assert!(!reads_reasoning(&p(
            "privilege.grantees:\n  exists:\n    kind: role"
        )));
    }

    #[test]
    fn a_field_listed_under_any_key_is_found_at_any_depth() {
        assert!(reads_reasoning(&p("query.has_tautology_where: true")));
        assert!(reads_reasoning(&p(
            "query.scopes:\n  each:\n    projections:\n      exists:\n        nullability:\n          not_in: [catalog_non_nullable]"
        )));
        assert!(reads_reasoning(&p(
            "not:\n  query.repeated_subqueries:\n    count: { eq: 0 }"
        )));
    }

    #[test]
    fn a_field_listed_under_one_key_needs_that_key() {
        assert!(reads_reasoning(&p(
            "dynamic_sql_calls:\n  exists:\n    argument: concat"
        )));
        assert!(reads_reasoning(&p(
            "ddl.procedure.body.dynamic_sql_calls:\n  exists:\n    argument: concat"
        )));
        // `argument` under any other key is an ordinary field.
        assert!(!reads_reasoning(&p(
            "mssql_exec.calls:\n  exists:\n    argument: concat"
        )));
        assert!(reads_reasoning(&p(
            "privilege.role_grant_impact.affected_users: { gte: 20 }"
        )));
    }
}
