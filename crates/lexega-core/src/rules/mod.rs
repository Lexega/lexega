// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! V1 rule engine — predicate language + closure compiler + evaluator.
//!
//! Module map:
//! - [`finding`]  — v1 `Finding` output type, `FindingEvidence`, `EmissionMode`.
//! - [`predicate`] — parsed `Predicate` AST + YAML/JSON parser.
//! - [`mod@compile`]  — closure compiler; produces `CompiledPredicate`.
//! - [`engine`]   — `Rule` + `evaluate_rules` runtime.
//! - [`aliases`]  — statement-kind aliases (`any_dml`, `any_policy_ddl`, …).

pub mod aliases;
pub mod builtin_rules;
pub(crate) mod category;
pub mod compile;
pub(crate) mod depth;
pub mod engine;
pub(crate) mod explain;
pub mod finding;
pub mod lists;
pub mod loader;
pub mod predicate;
pub mod schema;

pub use builtin_rules::{all_builtin_rules, canonical_rule_id, former_ids_for};
pub use compile::{compile, CompileError, CompiledPredicate};
pub use engine::{
    evaluate_rules, evaluate_rules_with_explain, rule_holds, MessageTemplate, Rule, TriggersDigest,
};
pub use finding::{EmissionMode, FactWitness, Finding, FindingEvidence, RuleExplanation};
pub use lists::{ListChanges, ValueList, ValueLists};
pub use loader::{
    load_v1_rules, load_v1_rules_from_json, load_v1_rules_from_toml, FormerIdOverride, ListField,
    ListShapeProblem, LoadError, LoadedEntry, LoadedRuleset, PartialRuleOverride,
};
pub use predicate::{parse_predicate, FieldName, FieldPath, ParseError, Predicate};
pub use schema::{MaskingPolicy, ShownColumnTag};

/// Typed error for [`build_v1_rule_corpus`] failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MergeError {
    /// A partial override entry referenced a rule id that does not
    /// exist in the built-in corpus. Either the customer mistyped the
    /// id or the entry was meant to be a full rule and is missing
    /// required fields. Diagnostic carries the offending id.
    UnresolvedPartialOverride { rule_id: String },
    /// A partial override entry was supplied alongside `include_builtins
    /// = false` (e.g. the customer ran `--no-builtin --custom-rules
    /// partial.yaml`). With no built-in corpus to inherit from, there
    /// is nothing the partial entry can resolve against.
    PartialOverrideWithoutBuiltins { rule_id: String },
    /// The embedded built-in rule corpus failed to load. Strictly a
    /// build-time programming error (the YAML is `include_str!`d), but
    /// propagated through the merge layer rather than panicked so
    /// callers receive a typed surface and can produce a structured
    /// diagnostic.
    BuiltinCorpusFailed(LoadError),
}

impl std::fmt::Display for MergeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnresolvedPartialOverride { rule_id } => write!(
                f,
                "partial override '{}' does not match any built-in rule id — \
                 either correct the id, or restate the full rule (with `triggers`)",
                rule_id
            ),
            Self::PartialOverrideWithoutBuiltins { rule_id } => write!(
                f,
                "partial override '{}' was supplied with built-in rules disabled; \
                 partial overlays require the built-in corpus to inherit from",
                rule_id
            ),
            Self::BuiltinCorpusFailed(err) => write!(
                f,
                "built-in rule corpus failed to load (build artifact bug): {}",
                err
            ),
        }
    }
}

impl std::error::Error for MergeError {}

impl From<LoadError> for MergeError {
    fn from(err: LoadError) -> Self {
        Self::BuiltinCorpusFailed(err)
    }
}

/// Build a customer-facing rule corpus by layering `loaded` over the
/// optional built-in corpus.
///
/// Semantics:
/// - `include_builtins == true`: start from [`all_builtin_rules`]
///   (the default behaviour).
/// - `include_builtins == false`: start from an empty corpus
///   (`--no-builtin`).
/// - Each [`LoadedEntry::Full`] in `loaded` overrides the built-in
///   entry with the same `rule_id` wholesale (last-write-wins on the
///   merge), so customers can replace any built-in's behaviour by
///   re-stating its `id` with their own predicate / message / risk
///   level. A full rule under a former id of a built-in takes that
///   built-in's current `id` (keeping the former id as an alias), with
///   or without built-ins.
/// - Each [`LoadedEntry::Partial`] is a per-field overlay on the
///   built-in with the same `id`, or the one a former `id` resolves
///   to. The built-in's `triggers` / `emission` / `per_statement` are
///   inherited verbatim; the partial entry's `risk_level` / `message` /
///   `enabled` fields replace the built-in's only where set. A partial
///   entry that does not match any built-in id returns
///   [`MergeError::UnresolvedPartialOverride`].
/// - When `loaded` extends or replaces a built-in list and built-ins
///   are included, the built-in rules that name a list are rebuilt
///   against `loaded`'s lists first; full rules and partial overrides
///   then merge over the rebuilt rules. Corpus order is unchanged.
/// - The file's own rules resolved against its lists at load time, so
///   they hold under `include_builtins == false` as well.
///
/// The returned `Vec<Rule>` is owned and can be stored on the
/// `AnalysisConfig.custom_rules` field; [`evaluate_rules`] is invoked
/// against `&[Rule]` at every per-statement seam.
///
/// In-process callers who hold a pre-materialized `Vec<Rule>` (i.e.
/// no Partial entries) should call [`merge_full_rule_corpus`] instead
/// — its signature is infallible, removing the need for the caller to
/// handle a `MergeError` arm that cannot occur.
pub fn build_v1_rule_corpus(
    loaded: LoadedRuleset,
    include_builtins: bool,
) -> Result<Vec<Rule>, MergeError> {
    use std::collections::HashMap;
    // Order is part of the contract: evaluation order matches authoring
    // order (see `load_v1_rules`), and emission order must be identical
    // across runs. Merge in place — built-ins keep corpus order, an
    // override replaces the rule at its existing position, net-new
    // customer rules append in authoring order. The map is an
    // id → position index only; the corpus is never collected from
    // hash-iteration order.
    let mut corpus: Vec<Rule> = Vec::new();
    let mut index_by_id: HashMap<String, usize> = HashMap::new();
    if include_builtins {
        let mut rebuilt = if loaded.changes_builtin_lists() {
            loader::recompile_builtin_list_rules(loaded.lists())?
        } else {
            HashMap::new()
        };
        for r in all_builtin_rules()? {
            index_by_id.insert(r.id.clone(), corpus.len());
            corpus.push(rebuilt.remove(&r.id).unwrap_or_else(|| r.clone()));
        }
    }
    for entry in loaded.into_entries() {
        match entry {
            LoadedEntry::Full(mut rule) => {
                // A rule under a former id takes the id of the built-in
                // that absorbed it, and keeps the former id as an alias.
                let canonical = canonical_rule_id(&rule.id).to_string();
                if canonical != rule.id {
                    let former = std::mem::replace(&mut rule.id, canonical);
                    if !rule.former_ids.contains(&former) {
                        rule.former_ids.push(former);
                    }
                }
                match index_by_id.get(&rule.id) {
                    Some(&i) => corpus[i] = rule,
                    None => {
                        index_by_id.insert(rule.id.clone(), corpus.len());
                        corpus.push(rule);
                    }
                }
            }
            LoadedEntry::Partial(overlay) => {
                // A former id overlays the rule that absorbed it.
                let existing = index_by_id.get(canonical_rule_id(&overlay.id)).copied();
                match existing {
                    Some(i) => {
                        let base = corpus[i].clone();
                        corpus[i] = apply_partial_overlay(base, overlay);
                    }
                    None => {
                        // No built-in matched. If built-ins were excluded
                        // wholesale, the customer ran `--no-builtin` with
                        // partial overrides — there's no corpus to inherit
                        // from. Otherwise, the id simply doesn't exist.
                        return Err(if include_builtins {
                            MergeError::UnresolvedPartialOverride {
                                rule_id: overlay.id,
                            }
                        } else {
                            MergeError::PartialOverrideWithoutBuiltins {
                                rule_id: overlay.id,
                            }
                        });
                    }
                }
            }
        }
    }
    Ok(corpus)
}

/// Merge a pre-materialized `Vec<Rule>` with the optional built-in
/// corpus (every entry is a full rule — no partial overrides are
/// expressible at this signature, so the only failure mode is a
/// malformed built-in corpus).
///
/// Semantics match [`build_v1_rule_corpus`] for the all-Full case:
/// built-ins (when `include_builtins`) underlie; customer rules
/// override by `id`, last-write-wins. Takes no list table and never
/// sees a list change: the built-ins hold the built-in lists.
///
/// Use this from in-process integration paths where the caller holds
/// owned `Rule` values rather than a `LoadedRuleset` and would
/// otherwise wrap each `MergeError` arm — most of which cannot occur
/// here.
pub fn merge_full_rule_corpus(
    custom_rules: Vec<Rule>,
    include_builtins: bool,
) -> Result<Vec<Rule>, LoadError> {
    use std::collections::HashMap;
    // Same order contract as `build_v1_rule_corpus`: built-ins keep
    // corpus order, overrides replace in place, net-new rules append in
    // authoring order — never hash-iteration order.
    let mut corpus: Vec<Rule> = Vec::new();
    let mut index_by_id: HashMap<String, usize> = HashMap::new();
    if include_builtins {
        for r in all_builtin_rules()? {
            index_by_id.insert(r.id.clone(), corpus.len());
            corpus.push(r.clone());
        }
    }
    for r in custom_rules {
        match index_by_id.get(&r.id) {
            Some(&i) => corpus[i] = r,
            None => {
                index_by_id.insert(r.id.clone(), corpus.len());
                corpus.push(r);
            }
        }
    }
    Ok(corpus)
}

/// Layer a partial override's fields onto the built-in rule. The
/// built-in's `triggers` / `emission` / `per_statement` are inherited
/// verbatim — the loader guarantees a partial entry never sets those.
/// SHA-256, in hex, of what `rules` evaluate, in evaluation order: each
/// rule's id, former ids, level, message, switches and triggers. Two
/// corpora with one digest report the same findings on every statement.
pub fn corpus_sha256(rules: &[Rule]) -> String {
    use sha2::{Digest, Sha256};

    use crate::facts::RiskLevel;

    fn feed(hasher: &mut Sha256, bytes: &[u8]) {
        hasher.update((bytes.len() as u64).to_le_bytes());
        hasher.update(bytes);
    }

    let mut hasher = Sha256::new();
    for rule in rules {
        feed(&mut hasher, rule.id.as_bytes());
        hasher.update((rule.former_ids.len() as u64).to_le_bytes());
        for former in &rule.former_ids {
            feed(&mut hasher, former.as_bytes());
        }
        feed(&mut hasher, rule.description.as_bytes());
        match &rule.message_template {
            Some(template) => feed(&mut hasher, template.raw.as_bytes()),
            None => hasher.update([0xff]),
        }
        hasher.update([
            match rule.risk_level {
                RiskLevel::Info => 0,
                RiskLevel::Low => 1,
                RiskLevel::Medium => 2,
                RiskLevel::High => 3,
                RiskLevel::Critical => 4,
            },
            u8::from(rule.enabled),
            match rule.emission {
                EmissionMode::Once => 0,
                EmissionMode::PerWitness => 1,
            },
            u8::from(rule.per_statement),
        ]);
        hasher.update(rule.triggers_digest.as_bytes());
    }
    format!("{:x}", hasher.finalize())
}

fn apply_partial_overlay(base: Rule, overlay: PartialRuleOverride) -> Rule {
    let Rule {
        id,
        former_ids,
        description,
        risk_level,
        enabled,
        triggers,
        triggers_digest,
        message_template,
        emission,
        per_statement,
    } = base;
    let new_description = overlay.message.clone().unwrap_or(description);
    let new_message_template = match overlay.message {
        Some(m) => Some(MessageTemplate::new(m)),
        None => message_template,
    };
    Rule {
        id,
        // A partial override inherits the canonical rule's aliases verbatim.
        former_ids,
        description: new_description,
        risk_level: overlay.risk_level.unwrap_or(risk_level),
        enabled: overlay.enabled.unwrap_or(enabled),
        triggers,
        triggers_digest,
        message_template: new_message_template,
        emission,
        per_statement,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::builtin_rules::builtin_list_rule_ids;
    use super::loader::recompile_builtin_list_rules;
    use super::*;
    use crate::facts::RiskLevel;

    const EXTEND_REFERENCES: &str = r#"
lists:
  credential_references:
    extend: {values: [From_Pipeline]}
"#;

    /// Whether `rule` matches a `CREATE USER` whose password is `password`.
    fn fires_on_password(rule: &Rule, password: &str) -> bool {
        rule.triggers
            .evaluate_value(&serde_json::json!({
                "kind": "create_user",
                "ddl": {"principal": {"password_literal": password}},
            }))
            .is_match()
    }

    fn ids(rules: &[Rule]) -> Vec<&str> {
        rules.iter().map(|r| r.id.as_str()).collect()
    }

    const ONE_RULE: &str = r#"
rules:
  - id: X-1
    risk_level: high
    message: unbounded delete
    triggers:
      all_of:
        - kind: delete
        - query.has_where: false
"#;

    fn digest(yaml: &str) -> String {
        corpus_sha256(&corpus(yaml, false))
    }

    #[test]
    fn a_corpus_digest_ignores_how_the_file_is_written() {
        let reordered = r#"
# the same rule, its keys in another order
rules:
  - triggers: {all_of: [{kind: delete}, {"query.has_where": false}]}
    message: unbounded delete
    id: X-1
    risk_level: high
"#;
        assert_eq!(digest(ONE_RULE), digest(reordered));

        let json = r#"{"rules": [{"id": "X-1", "risk_level": "high",
            "message": "unbounded delete",
            "triggers": {"all_of": [{"kind": "delete"}, {"query.has_where": false}]}}]}"#;
        let from_json = load_v1_rules_from_json(json.as_bytes()).expect("rule file loads");
        let from_json = build_v1_rule_corpus(from_json, false).expect("corpus builds");
        assert_eq!(digest(ONE_RULE), corpus_sha256(&from_json));
    }

    #[test]
    fn a_corpus_digest_changes_with_each_part_of_a_rule() {
        let base = digest(ONE_RULE);
        for (from, to) in [
            ("kind: delete", "kind: update"),
            ("risk_level: high", "risk_level: critical"),
            ("message: unbounded delete", "message: delete of every row"),
            ("id: X-1", "id: X-2"),
            ("    triggers:", "    enabled: false\n    triggers:"),
            ("    triggers:", "    per_statement: true\n    triggers:"),
        ] {
            assert!(ONE_RULE.contains(from), "{from}");
            assert_ne!(base, digest(&ONE_RULE.replace(from, to)), "{from} -> {to}");
        }
        let second = ONE_RULE.replace("X-1", "X-2");
        let two = format!(
            "{ONE_RULE}{}",
            second.trim_start().trim_start_matches("rules:")
        );
        assert_eq!(corpus(&two, false).len(), 2);
        assert_ne!(base, digest(&two));
    }

    #[test]
    fn a_corpus_digest_follows_a_list_a_rule_names() {
        let with_list = |values: &str| {
            format!(
                r#"
lists:
  watched: {{values: [{values}]}}
rules:
  - id: X-1
    risk_level: high
    message: watched role
    triggers:
      privilege.target.name.canonical: {{in_list: watched}}
  - id: X-2
    risk_level: high
    message: any grant
    triggers:
      kind: grant
"#
            )
        };
        let one = corpus(&with_list("ADMIN"), false);
        let other = corpus(&with_list("ADMIN, OWNER"), false);
        assert_ne!(one[0].triggers_digest, other[0].triggers_digest);
        assert_eq!(one[1].triggers_digest, other[1].triggers_digest);
        assert_ne!(corpus_sha256(&one), corpus_sha256(&other));
    }

    #[test]
    fn an_override_changes_the_builtin_corpus_digest() {
        let builtins = all_builtin_rules().expect("built-in corpus loads");
        let (_, first) = builtin(builtins[0].id.as_str());
        let overridden = corpus(
            &format!("rules:\n  - id: {}\n    enabled: false\n", first.id),
            true,
        );
        assert_eq!(overridden.len(), builtins.len());
        assert_ne!(corpus_sha256(builtins), corpus_sha256(&overridden));
        assert_eq!(
            corpus_sha256(builtins),
            corpus_sha256(&corpus("lists: {}", true))
        );
    }

    fn builtin_ids() -> Vec<&'static str> {
        ids(all_builtin_rules().expect("built-in corpus loads"))
    }

    fn corpus(yaml: &str, include_builtins: bool) -> Vec<Rule> {
        let loaded = load_v1_rules(yaml).expect("rule file loads");
        build_v1_rule_corpus(loaded, include_builtins).expect("corpus builds")
    }

    /// The built-in rule `id` and its position in the corpus.
    fn builtin(id: &str) -> (usize, &'static Rule) {
        all_builtin_rules()
            .expect("built-in corpus loads")
            .iter()
            .enumerate()
            .find(|(_, r)| r.id == id)
            .expect("built-in rule exists")
    }

    #[test]
    fn extend_recompiles_only_list_rules() {
        let loaded = load_v1_rules(EXTEND_REFERENCES).expect("rule file loads");
        assert!(loaded.changes_builtin_lists());
        let recompiled = recompile_builtin_list_rules(loaded.lists()).expect("recompiles");
        let list_rule_ids = builtin_list_rule_ids().expect("built-in corpus loads");
        assert!(!list_rule_ids.is_empty());
        assert_eq!(
            recompiled.keys().cloned().collect::<BTreeSet<_>>(),
            *list_rule_ids
        );
        let merged = build_v1_rule_corpus(loaded, true).expect("corpus builds");
        assert_eq!(ids(&merged), builtin_ids());
    }

    #[test]
    fn full_rule_replacement_wins_over_list_recompile() {
        let yaml = format!(
            "{EXTEND_REFERENCES}rules:\n  - id: CRED-PWD-LEAK\n    risk_level: low\n    message: \"custom\"\n    triggers:\n      kind: grant\n"
        );
        let merged = corpus(&yaml, true);
        let (at, _) = builtin("CRED-PWD-LEAK");
        assert_eq!(ids(&merged), builtin_ids());
        assert_eq!(merged[at].description, "custom");
        assert_eq!(merged[at].risk_level, RiskLevel::Low);
    }

    #[test]
    fn partial_override_overlays_the_recompiled_rule() {
        let yaml =
            format!("{EXTEND_REFERENCES}rules:\n  - id: CRED-PWD-LEAK\n    risk_level: high\n");
        let merged = corpus(&yaml, true);
        let (at, original) = builtin("CRED-PWD-LEAK");
        assert_eq!(ids(&merged), builtin_ids());
        assert_eq!(merged[at].risk_level, RiskLevel::High);
        assert_eq!(merged[at].description, original.description);
        assert!(fires_on_password(&merged[at], "S3cret!"));
        assert!(!fires_on_password(&merged[at], "REPLACE_ME"));
        assert!(!fires_on_password(&merged[at], "FROM_PIPELINE"));
    }

    #[test]
    fn no_builtin_with_extend_loads() {
        let yaml = format!(
            "{EXTEND_REFERENCES}rules:\n  - id: TEST-REF\n    risk_level: low\n    message: \"m\"\n    triggers:\n      use_stmt.target.raw: {{ in_list: credential_references }}\n"
        );
        assert_eq!(ids(&corpus(&yaml, false)), ["TEST-REF"]);
    }
}
