// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Loader for v1 fact-based YAML rule files.
//!
//! The same loader serves built-in rules (embedded via `include_str!`)
//! and customer rule files. Built-ins are always **full** rules; the
//! customer YAML may additionally contain **partial overrides** that
//! re-state a built-in `id` with a different `risk_level` / `message` /
//! `enabled` flag and inherit `triggers` from the built-in.
//!
//! YAML schema:
//!
//! ```yaml
//! rules:
//!   # Full rule — `triggers` present. May create a brand-new rule or
//!   # wholly replace a built-in with the same id.
//!   - id: <stable-id>
//!     risk_level: high
//!     message: "..."
//!     triggers:
//!       <predicate>
//!     enabled: true        # optional; default true
//!     emission: once       # optional; default derived from triggers
//!
//!   # Partial override — `triggers` absent. Must match a built-in `id`
//!   # at merge time. May set any of `risk_level` / `message` / `enabled`.
//!   - id: <existing-builtin-id>
//!     risk_level: low
//! ```
//!
//! Classification & validation happens here at load time; merging the
//! resulting [`LoadedRuleset`] against the built-in corpus happens in
//! [`crate::rules::build_v1_rule_corpus`].

use crate::facts::RiskLevel;

use super::compile::compile;
use super::engine::{MessageTemplate, Rule};
use super::predicate::{parse_predicate, Predicate, Quantifier, RelationalMatch};
use super::schema::V1RulesFile;
use super::signal::EmissionMode;

/// Typed error for v1 rule-file load failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoadError {
    /// Top-level YAML syntax / shape error.
    Yaml(String),
    /// Top-level syntax / shape error deserializing the build-time
    /// precompiled JSON corpus blob (built-in rules only).
    Json(String),
    /// `triggers:` predicate could not be parsed for the named rule.
    PredicateParse { rule_id: String, message: String },
    /// `triggers:` predicate parsed but failed to compile to a closure.
    PredicateCompile { rule_id: String, message: String },
    /// Two rule entries share the same `id`.
    DuplicateRuleId(String),
    /// Entry has `triggers` (so it's a full rule definition) but is
    /// missing one of the other required full-rule fields. The
    /// `missing_field` is one of `"risk_level"` or `"message"`.
    IncompleteFullRule {
        rule_id: String,
        missing_field: &'static str,
    },
    /// Entry has no `triggers` (so it's a partial override) but sets
    /// one of the fields that partial overrides are not allowed to
    /// touch: `emission` or `per_statement`. `triggers` itself is
    /// classified out of this variant — its presence makes the entry
    /// Full, not Partial.
    DisallowedFieldOnPartialOverride {
        rule_id: String,
        field: &'static str,
    },
    /// Partial override entry that sets none of the override-able
    /// fields (`risk_level`, `message`, `enabled`). A pure `id`-only
    /// entry is a no-op restate of the built-in and almost certainly a
    /// typo for either a full rule (forgot the body) or an intended
    /// override (forgot the field).
    EmptyPartialOverride { rule_id: String },
    /// A partial override (no `triggers`) declared `former_ids`.
    /// Deprecated-id aliases belong to a rule's canonical definition,
    /// not to an override of it.
    FormerIdsOnPartialOverride { rule_id: String },
    /// A `former_ids` entry duplicates a live rule `id`. A deprecated id
    /// must not shadow a rule that is still active, or a reference would
    /// be ambiguous.
    FormerIdCollidesWithLiveId { former_id: String, rule_id: String },
    /// Two rules claim the same `former_ids` entry — a deprecated id can
    /// only resolve to one canonical rule.
    DuplicateFormerId { former_id: String },
}

impl std::fmt::Display for LoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Yaml(msg) => write!(f, "rule file yaml error: {}", msg),
            Self::Json(msg) => write!(f, "rule file json error: {}", msg),
            Self::PredicateParse { rule_id, message } => write!(
                f,
                "rule '{}': triggers predicate parse error: {}",
                rule_id, message
            ),
            Self::PredicateCompile { rule_id, message } => write!(
                f,
                "rule '{}': triggers predicate compile error: {}",
                rule_id, message
            ),
            Self::DuplicateRuleId(id) => write!(f, "duplicate rule id: '{}'", id),
            Self::IncompleteFullRule {
                rule_id,
                missing_field,
            } => write!(
                f,
                "rule '{}': has `triggers` (full rule shape) but is missing required field `{}`",
                rule_id, missing_field
            ),
            Self::DisallowedFieldOnPartialOverride { rule_id, field } => write!(
                f,
                "rule '{}': partial override (no `triggers`) cannot set `{}` — partial overrides may only set `risk_level`, `message`, and `enabled`",
                rule_id, field
            ),
            Self::EmptyPartialOverride { rule_id } => write!(
                f,
                "rule '{}': partial override sets none of `risk_level`, `message`, `enabled` — nothing to override",
                rule_id
            ),
            Self::FormerIdsOnPartialOverride { rule_id } => write!(
                f,
                "rule '{}': partial override (no `triggers`) cannot set `former_ids` — deprecated-id aliases belong to the canonical rule definition",
                rule_id
            ),
            Self::FormerIdCollidesWithLiveId { former_id, rule_id } => write!(
                f,
                "rule '{}': former id '{}' collides with a live rule id",
                rule_id, former_id
            ),
            Self::DuplicateFormerId { former_id } => {
                write!(f, "former id '{}' is claimed by more than one rule", former_id)
            }
        }
    }
}

impl std::error::Error for LoadError {}

/// A partial override of a built-in rule. Holds only the override-able
/// fields the customer YAML provided; whichever fields are `None` are
/// inherited from the built-in at merge time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartialRuleOverride {
    /// Must match a built-in rule's `id` at merge time.
    pub id: String,
    /// New severity, or `None` to inherit the built-in's.
    pub risk_level: Option<RiskLevel>,
    /// New customer-facing message, or `None` to inherit.
    pub message: Option<String>,
    /// New enabled flag, or `None` to inherit. Set to `Some(false)` to
    /// suppress a built-in via the override path.
    pub enabled: Option<bool>,
}

/// One classified entry from a loaded rule YAML.
#[derive(Debug, Clone)]
pub enum LoadedEntry {
    /// A fully-specified rule. May still override a built-in with the
    /// same `id` (whole-rule replacement, last-write-wins).
    Full(Rule),
    /// A partial override that inherits the built-in's `triggers` (and
    /// other engine-shape fields) and only changes severity / message /
    /// enabled.
    Partial(PartialRuleOverride),
}

impl LoadedEntry {
    /// The id this entry will merge against.
    pub fn id(&self) -> &str {
        match self {
            Self::Full(r) => &r.id,
            Self::Partial(p) => &p.id,
        }
    }
}

/// Parsed-and-classified rule file. Each entry is either a full rule
/// or a partial override that requires resolution against the built-in
/// corpus. See [`crate::rules::build_v1_rule_corpus`].
#[derive(Debug, Clone, Default)]
pub struct LoadedRuleset {
    entries: Vec<LoadedEntry>,
}

impl LoadedRuleset {
    /// Construct a ruleset from already-materialized full rules. Used
    /// by callers that hold `Vec<Rule>` (e.g. in-process integrations)
    /// and want to feed them through [`crate::rules::build_v1_rule_corpus`]
    /// alongside built-ins.
    pub fn from_full_rules(rules: Vec<Rule>) -> Self {
        Self {
            entries: rules.into_iter().map(LoadedEntry::Full).collect(),
        }
    }

    pub fn entries(&self) -> &[LoadedEntry] {
        &self.entries
    }

    pub fn into_entries(self) -> Vec<LoadedEntry> {
        self.entries
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Materialize this ruleset as `Vec<Rule>`, rejecting any partial
    /// overrides. Used by the built-in corpus loader, where partial
    /// entries would be self-referential and are never valid.
    pub fn into_strict_rules(self) -> Result<Vec<Rule>, LoadError> {
        let mut rules = Vec::with_capacity(self.entries.len());
        for entry in self.entries {
            match entry {
                LoadedEntry::Full(r) => rules.push(r),
                LoadedEntry::Partial(p) => {
                    return Err(LoadError::IncompleteFullRule {
                        rule_id: p.id,
                        missing_field: "triggers",
                    });
                }
            }
        }
        Ok(rules)
    }
}

/// Parse a v1 rule-file YAML string and produce a classified
/// [`LoadedRuleset`].
///
/// Used by both the built-in corpus (`rules/builtin_rules.yaml`, see
/// [`crate::rules::all_builtin_rules`]) and customer rule-file loaders.
/// The returned entries preserve source order — rule evaluation order
/// matches authoring order, which lets customers reason about emission
/// interleaving without consulting an implicit sort key.
pub fn load_v1_rules(yaml: &str) -> Result<LoadedRuleset, LoadError> {
    let file: V1RulesFile =
        serde_yaml_ng::from_str(yaml).map_err(|e| LoadError::Yaml(e.to_string()))?;
    build_ruleset_from_file(file)
}

/// Load rules from the build-time-precompiled JSON blob (see `build.rs`).
///
/// Identical post-processing to [`load_v1_rules`]; only the wire format
/// differs. The built-in corpus is deserialized on every process start,
/// where YAML parsing dominated startup — so the corpus is transcoded to
/// JSON at build time and parsed from that blob at runtime instead.
pub fn load_v1_rules_from_json(json: &[u8]) -> Result<LoadedRuleset, LoadError> {
    let file: V1RulesFile =
        serde_json::from_slice(json).map_err(|e| LoadError::Json(e.to_string()))?;
    build_ruleset_from_file(file)
}

/// Shared post-processing: classify each entry (full rule vs partial
/// override) and enforce the id / former-id invariants. Format-agnostic —
/// callers parse `V1RulesFile` from YAML (customer files) or the
/// precompiled JSON blob (built-ins).
fn build_ruleset_from_file(file: V1RulesFile) -> Result<LoadedRuleset, LoadError> {
    let mut seen_ids = std::collections::HashSet::with_capacity(file.rules.len());
    let mut entries = Vec::with_capacity(file.rules.len());
    // (former_id, declaring_rule_id) — validated once every live id is
    // known, so a former id can be checked against the whole corpus.
    let mut former_claims: Vec<(String, String)> = Vec::new();

    for entry in file.rules {
        if !seen_ids.insert(entry.id.clone()) {
            return Err(LoadError::DuplicateRuleId(entry.id));
        }
        for former in &entry.former_ids {
            former_claims.push((former.clone(), entry.id.clone()));
        }

        // Classification is `triggers`-driven. Presence of `triggers`
        // means full rule (with the other required fields enforced
        // post-classification); absence means partial override.
        let loaded = match entry.triggers {
            Some(triggers) => classify_full(
                entry.id,
                entry.former_ids,
                entry.risk_level,
                entry.message,
                entry.enabled,
                entry.emission,
                entry.per_statement,
                triggers,
            )?,
            None => {
                if !entry.former_ids.is_empty() {
                    return Err(LoadError::FormerIdsOnPartialOverride { rule_id: entry.id });
                }
                classify_partial(
                    entry.id,
                    entry.risk_level,
                    entry.message,
                    entry.enabled,
                    entry.emission,
                    entry.per_statement,
                )?
            }
        };
        entries.push(loaded);
    }

    // A former id may neither shadow a live rule id nor be claimed by two
    // rules — either would make a policy/exception reference ambiguous.
    let mut seen_formers = std::collections::HashSet::with_capacity(former_claims.len());
    for (former, declaring) in former_claims {
        if seen_ids.contains(&former) {
            return Err(LoadError::FormerIdCollidesWithLiveId {
                former_id: former,
                rule_id: declaring,
            });
        }
        if !seen_formers.insert(former.clone()) {
            return Err(LoadError::DuplicateFormerId { former_id: former });
        }
    }

    Ok(LoadedRuleset { entries })
}

#[allow(clippy::too_many_arguments)]
fn classify_full(
    id: String,
    former_ids: Vec<String>,
    risk_level: Option<RiskLevel>,
    message: Option<String>,
    enabled: Option<bool>,
    emission: Option<EmissionMode>,
    per_statement: Option<bool>,
    triggers: serde_json::Value,
) -> Result<LoadedEntry, LoadError> {
    let risk_level = risk_level.ok_or_else(|| LoadError::IncompleteFullRule {
        rule_id: id.clone(),
        missing_field: "risk_level",
    })?;
    let message = message.ok_or_else(|| LoadError::IncompleteFullRule {
        rule_id: id.clone(),
        missing_field: "message",
    })?;

    let parsed = parse_predicate(&triggers).map_err(|e| LoadError::PredicateParse {
        rule_id: id.clone(),
        message: format!("{}", e),
    })?;
    let compiled = compile(&parsed).map_err(|e| LoadError::PredicateCompile {
        rule_id: id.clone(),
        message: format!("{}", e),
    })?;

    // A rule containing an `each:` quantifier anywhere in its trigger
    // AST is per-witness by intent — the quantifier name IS the emission
    // decision. Honor an explicit `emission:` override if the rule
    // author set one; otherwise derive from the predicate shape.
    let resolved_emission = emission.unwrap_or_else(|| {
        if predicate_has_each_quantifier(&parsed) {
            EmissionMode::PerWitness
        } else {
            EmissionMode::Once
        }
    });

    Ok(LoadedEntry::Full(Rule {
        id,
        former_ids,
        description: message.clone(),
        risk_level,
        enabled: enabled.unwrap_or(true),
        triggers: compiled,
        message_template: Some(MessageTemplate::new(message)),
        emission: resolved_emission,
        per_statement: per_statement.unwrap_or(false),
    }))
}

fn classify_partial(
    id: String,
    risk_level: Option<RiskLevel>,
    message: Option<String>,
    enabled: Option<bool>,
    emission: Option<EmissionMode>,
    per_statement: Option<bool>,
) -> Result<LoadedEntry, LoadError> {
    // Partial overrides can ONLY change severity / message / enabled.
    // Rejecting `emission` / `per_statement` at load time keeps the
    // semantics narrow: the built-in's predicate-shape decisions are
    // inherited verbatim. A customer who wants to change emission
    // semantics restates the full rule.
    if emission.is_some() {
        return Err(LoadError::DisallowedFieldOnPartialOverride {
            rule_id: id,
            field: "emission",
        });
    }
    if per_statement.is_some() {
        return Err(LoadError::DisallowedFieldOnPartialOverride {
            rule_id: id,
            field: "per_statement",
        });
    }
    if risk_level.is_none() && message.is_none() && enabled.is_none() {
        return Err(LoadError::EmptyPartialOverride { rule_id: id });
    }
    Ok(LoadedEntry::Partial(PartialRuleOverride {
        id,
        risk_level,
        message,
        enabled,
    }))
}

/// Walk the parsed predicate AST and return `true` if any
/// [`Quantifier::Each`] node is present. Used at load time to derive
/// the default emission mode: a rule whose trigger uses `each:`
/// somewhere intends per-witness emission, full stop. Customer rule
/// authors only need to choose the quantifier — the engine reads
/// emission semantics from that single decision.
fn predicate_has_each_quantifier(predicate: &Predicate) -> bool {
    match predicate {
        Predicate::AllOf(preds) | Predicate::AnyOf(preds) => {
            preds.iter().any(predicate_has_each_quantifier)
        }
        Predicate::Not(inner) => predicate_has_each_quantifier(inner),
        Predicate::Scalar(_) => false,
        Predicate::Relational(RelationalMatch { quantifier, .. }) => match quantifier {
            Quantifier::Each(_) => true,
            Quantifier::Exists(inner) | Quantifier::All(inner) | Quantifier::None(inner) => {
                predicate_has_each_quantifier(inner)
            }
            Quantifier::Count(_) => false,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn first_full_rule(rs: LoadedRuleset) -> Rule {
        match rs.into_entries().into_iter().next() {
            Some(LoadedEntry::Full(r)) => r,
            other => panic!("expected Full entry, got {:?}", other),
        }
    }

    #[test]
    fn loads_minimal_rule() {
        let yaml = r#"
rules:
  - id: TEST-1
    risk_level: high
    message: "test"
    triggers:
      kind: grant
"#;
        let rs = load_v1_rules(yaml).expect("loads");
        assert_eq!(rs.len(), 1);
        let rule = first_full_rule(rs);
        assert_eq!(rule.id, "TEST-1");
        assert!(rule.enabled);
        assert_eq!(rule.emission, EmissionMode::Once);
        assert!(rule.former_ids.is_empty());
    }

    #[test]
    fn loads_former_ids() {
        let yaml = r#"
rules:
  - id: ROLE-NEW-T
    former_ids: [OLD-ROLE-NEW, ANCIENT-ROLE-NEW]
    risk_level: medium
    message: "test"
    triggers:
      kind: create_role
"#;
        let rule = first_full_rule(load_v1_rules(yaml).expect("loads"));
        assert_eq!(
            rule.former_ids,
            vec!["OLD-ROLE-NEW".to_string(), "ANCIENT-ROLE-NEW".to_string()]
        );
    }

    #[test]
    fn rejects_former_id_colliding_with_live_id() {
        let yaml = r#"
rules:
  - id: LIVE-RULE
    risk_level: high
    message: "a"
    triggers:
      kind: grant
  - id: OTHER-RULE
    former_ids: [LIVE-RULE]
    risk_level: high
    message: "b"
    triggers:
      kind: revoke
"#;
        assert!(matches!(
            load_v1_rules(yaml),
            Err(LoadError::FormerIdCollidesWithLiveId { .. })
        ));
    }

    #[test]
    fn rejects_duplicate_former_id() {
        let yaml = r#"
rules:
  - id: RULE-A
    former_ids: [SHARED-OLD]
    risk_level: high
    message: "a"
    triggers:
      kind: grant
  - id: RULE-B
    former_ids: [SHARED-OLD]
    risk_level: high
    message: "b"
    triggers:
      kind: revoke
"#;
        assert!(matches!(
            load_v1_rules(yaml),
            Err(LoadError::DuplicateFormerId { .. })
        ));
    }

    #[test]
    fn rejects_former_ids_on_partial_override() {
        let yaml = r#"
rules:
  - id: SOME-BUILTIN
    former_ids: [OLD-ID]
    risk_level: low
"#;
        assert!(matches!(
            load_v1_rules(yaml),
            Err(LoadError::FormerIdsOnPartialOverride { .. })
        ));
    }

    #[test]
    fn rejects_duplicate_rule_id() {
        let yaml = r#"
rules:
  - id: TEST-DUP
    risk_level: high
    message: "first"
    triggers:
      kind: grant
  - id: TEST-DUP
    risk_level: high
    message: "second"
    triggers:
      kind: revoke
"#;
        let err = load_v1_rules(yaml).expect_err("rejects dup");
        assert_eq!(err, LoadError::DuplicateRuleId("TEST-DUP".to_string()));
    }

    #[test]
    fn surfaces_per_rule_predicate_parse_error() {
        let yaml = r#"
rules:
  - id: TEST-EMPTY-PRED
    risk_level: high
    message: "empty"
    triggers: {}
"#;
        let err = load_v1_rules(yaml).expect_err("rejects empty predicate");
        match err {
            LoadError::PredicateParse { rule_id, .. } => {
                assert_eq!(rule_id, "TEST-EMPTY-PRED");
            }
            other => panic!("expected PredicateParse, got {:?}", other),
        }
    }

    #[test]
    fn surfaces_yaml_top_level_error() {
        let yaml = "this is not yaml: : :";
        let err = load_v1_rules(yaml).expect_err("rejects malformed YAML");
        assert!(matches!(err, LoadError::Yaml(_)));
    }

    #[test]
    fn empty_rules_section_loads_to_empty_ruleset() {
        let yaml = "rules: []";
        let rs = load_v1_rules(yaml).expect("loads");
        assert!(rs.is_empty());
    }

    #[test]
    fn enabled_default_is_true_on_full_rule() {
        let yaml = r#"
rules:
  - id: TEST-ENABLED-DEFAULT
    risk_level: low
    message: "default enabled"
    triggers:
      kind: grant
"#;
        let rs = load_v1_rules(yaml).expect("loads");
        assert!(first_full_rule(rs).enabled);
    }

    #[test]
    fn enabled_false_is_respected_on_full_rule() {
        let yaml = r#"
rules:
  - id: TEST-DISABLED
    risk_level: low
    message: "explicitly disabled"
    enabled: false
    triggers:
      kind: grant
"#;
        let rs = load_v1_rules(yaml).expect("loads");
        assert!(!first_full_rule(rs).enabled);
    }

    #[test]
    fn each_quantifier_implies_per_witness_emission() {
        let yaml = r#"
rules:
  - id: TEST-EACH
    risk_level: medium
    message: "fan out per matching event"
    triggers:
      diff.events:
        each:
          kind: aggregate_added
"#;
        let rs = load_v1_rules(yaml).expect("loads");
        assert_eq!(first_full_rule(rs).emission, EmissionMode::PerWitness);
    }

    #[test]
    fn preserves_source_order() {
        let yaml = r#"
rules:
  - id: A
    risk_level: low
    message: "a"
    triggers:
      kind: grant
  - id: B
    risk_level: low
    message: "b"
    triggers:
      kind: grant
  - id: C
    risk_level: low
    message: "c"
    triggers:
      kind: grant
"#;
        let rs = load_v1_rules(yaml).expect("loads");
        let ids: Vec<&str> = rs.entries().iter().map(|e| e.id()).collect();
        assert_eq!(ids, vec!["A", "B", "C"]);
    }

    // ── Partial-override classification tests ───────────────────────

    #[test]
    fn entry_without_triggers_is_classified_as_partial_override() {
        let yaml = r#"
rules:
  - id: SOME-BUILTIN
    risk_level: low
"#;
        let rs = load_v1_rules(yaml).expect("partial loads");
        match &rs.entries()[0] {
            LoadedEntry::Partial(p) => {
                assert_eq!(p.id, "SOME-BUILTIN");
                assert_eq!(p.risk_level, Some(RiskLevel::Low));
                assert_eq!(p.message, None);
                assert_eq!(p.enabled, None);
            }
            other => panic!("expected Partial, got {:?}", other),
        }
    }

    #[test]
    fn full_rule_missing_risk_level_is_rejected_at_load() {
        let yaml = r#"
rules:
  - id: HAS-TRIGGERS-NO-RL
    message: "broken full rule"
    triggers:
      kind: grant
"#;
        match load_v1_rules(yaml).expect_err("rejects incomplete full") {
            LoadError::IncompleteFullRule {
                rule_id,
                missing_field,
            } => {
                assert_eq!(rule_id, "HAS-TRIGGERS-NO-RL");
                assert_eq!(missing_field, "risk_level");
            }
            other => panic!("expected IncompleteFullRule, got {:?}", other),
        }
    }

    #[test]
    fn full_rule_missing_message_is_rejected_at_load() {
        let yaml = r#"
rules:
  - id: HAS-TRIGGERS-NO-MSG
    risk_level: high
    triggers:
      kind: grant
"#;
        match load_v1_rules(yaml).expect_err("rejects incomplete full") {
            LoadError::IncompleteFullRule {
                rule_id,
                missing_field,
            } => {
                assert_eq!(rule_id, "HAS-TRIGGERS-NO-MSG");
                assert_eq!(missing_field, "message");
            }
            other => panic!("expected IncompleteFullRule, got {:?}", other),
        }
    }

    #[test]
    fn partial_override_rejecting_emission_field() {
        let yaml = r#"
rules:
  - id: PARTIAL-WITH-EMISSION
    risk_level: low
    emission: per_witness
"#;
        match load_v1_rules(yaml).expect_err("rejects emission on partial") {
            LoadError::DisallowedFieldOnPartialOverride { rule_id, field } => {
                assert_eq!(rule_id, "PARTIAL-WITH-EMISSION");
                assert_eq!(field, "emission");
            }
            other => panic!("expected DisallowedFieldOnPartialOverride, got {:?}", other),
        }
    }

    #[test]
    fn partial_override_rejecting_per_statement_field() {
        let yaml = r#"
rules:
  - id: PARTIAL-WITH-PER-STMT
    risk_level: low
    per_statement: true
"#;
        match load_v1_rules(yaml).expect_err("rejects per_statement on partial") {
            LoadError::DisallowedFieldOnPartialOverride { rule_id, field } => {
                assert_eq!(rule_id, "PARTIAL-WITH-PER-STMT");
                assert_eq!(field, "per_statement");
            }
            other => panic!("expected DisallowedFieldOnPartialOverride, got {:?}", other),
        }
    }

    #[test]
    fn partial_override_with_only_id_is_rejected() {
        let yaml = r#"
rules:
  - id: ID-ONLY
"#;
        match load_v1_rules(yaml).expect_err("rejects id-only entry") {
            LoadError::EmptyPartialOverride { rule_id } => assert_eq!(rule_id, "ID-ONLY"),
            other => panic!("expected EmptyPartialOverride, got {:?}", other),
        }
    }

    #[test]
    fn into_strict_rules_rejects_partial_entries() {
        let yaml = r#"
rules:
  - id: NORMAL
    risk_level: low
    message: "ok"
    triggers:
      kind: grant
  - id: PARTIAL
    risk_level: low
"#;
        let rs = load_v1_rules(yaml).expect("loads");
        match rs
            .into_strict_rules()
            .expect_err("strict materialization rejects partial")
        {
            LoadError::IncompleteFullRule {
                rule_id,
                missing_field,
            } => {
                assert_eq!(rule_id, "PARTIAL");
                assert_eq!(missing_field, "triggers");
            }
            other => panic!("unexpected error: {:?}", other),
        }
    }
}
