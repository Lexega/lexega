// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Custom-rules override semantics.
//!
//! Two override shapes:
//!
//! 1. **Full override** — customer re-states the built-in `rule_id` in
//!    `--custom-rules` YAML with a complete rule body (predicate,
//!    message, severity). [`lexega_core::rules::build_v1_rule_corpus`]
//!    treats this as last-write-wins on `rule_id`: the whole built-in
//!    Rule is replaced.
//!
//! 2. **Partial override** — customer lists the built-in `rule_id` and
//!    omits `triggers`, supplying only the fields they want to change
//!    (`risk_level`, `message`, `enabled`). The merge step inherits
//!    `triggers` / `emission` / `per_statement` from the built-in and
//!    overlays only the provided fields.
//!
//! The merged corpus is handed to the analyzer via
//! `AnalysisConfig::custom_rules`. These tests pin both shapes
//! end-to-end: the override survives every conversion seam between
//! YAML and `RuleMatch::risk_level()` / `.message()`.

use lexega_core::analyzer::{AnalysisConfig, RiskLevel};
use lexega_core::api::{analyze_risk, analyze_risk_with_policy_config};
use lexega_core::rules::{all_builtin_rules, build_v1_rule_corpus, load_v1_rules, MergeError};

const TRUNCATE_SQL: &str = "TRUNCATE TABLE my_table;";
const TRUNCATE_RULE_ID: &str = "TBL-TRUNCATE";

/// Build a config whose corpus is built-ins overlaid with `custom_yaml`.
/// Mirrors what the CLI does for `--custom-rules` without `--no-builtin`.
fn config_with_overlay(custom_yaml: &str) -> AnalysisConfig {
    let custom = load_v1_rules(custom_yaml).expect("custom rules parse");
    let merged = build_v1_rule_corpus(custom, /* include_builtins = */ true)
        .expect("merge against built-ins succeeds");
    let mut config = AnalysisConfig::default();
    config.custom_rules = Some(merged);
    config
}

fn truncate_signal(
    report: &lexega_core::analyzer::AnalysisReport,
) -> &lexega_core::analyzer::RuleMatch {
    let matches: Vec<_> = report
        .signals
        .iter()
        .filter(|s| s.rule_id() == Some(TRUNCATE_RULE_ID))
        .collect();
    assert_eq!(
        matches.len(),
        1,
        "expected exactly one TBL-TRUNCATE signal (no override-double-fire); got {}",
        matches.len()
    );
    matches[0]
}

// ────────────────────────────────────────────────────────────────────
// Baseline: the built-in TBL-TRUNCATE rule fires at `critical` without
// any override applied. If this baseline ever shifts, the override
// tests below need to compare against the new baseline.
// ────────────────────────────────────────────────────────────────────

#[test]
fn baseline_builtin_truncate_fires_at_critical() {
    let report = analyze_risk(TRUNCATE_SQL).expect("analyze succeeds");
    let signal = truncate_signal(&report);
    assert_eq!(
        signal.risk_level(),
        RiskLevel::Critical,
        "built-in TBL-TRUNCATE risk_level baseline must be Critical \
         (override tests pivot off this); update both this test and the \
         override tests below if the built-in changes"
    );
}

/// Helper for tests that need to read off the built-in TBL-TRUNCATE
/// rule directly (e.g. confirming message-inheritance). Centralizes
/// the `.expect()` on the new Result-returning `all_builtin_rules`
/// API so individual tests don't repeat the boilerplate.
fn builtin_truncate_rule() -> &'static lexega_core::rules::Rule {
    all_builtin_rules()
        .expect("built-in corpus loads")
        .iter()
        .find(|r| r.id == TRUNCATE_RULE_ID)
        .expect("TBL-TRUNCATE present in built-ins")
}

// ────────────────────────────────────────────────────────────────────
// 1. Severity override surfaces end-to-end
// ────────────────────────────────────────────────────────────────────

#[test]
fn custom_rule_overrides_builtin_severity_end_to_end() {
    // Re-state TBL-TRUNCATE with a lower severity + distinct message.
    // The trigger predicate is the same shape as the built-in
    // (`kind: truncate`) so behavioural firing semantics don't change —
    // only the severity / message that customers read off the signal.
    let custom_yaml = r#"
rules:
  - id: TBL-TRUNCATE
    risk_level: low
    message: "OVERRIDDEN: TRUNCATE downgraded by policy"
    triggers:
      kind: truncate
"#;
    let config = config_with_overlay(custom_yaml);
    let report = analyze_risk_with_policy_config(TRUNCATE_SQL, &config)
        .expect("analyze with overlay succeeds");

    let signal = truncate_signal(&report);
    assert_eq!(
        signal.risk_level(),
        RiskLevel::Low,
        "custom rule's risk_level must win over built-in (built-in is Critical)"
    );
    assert_eq!(
        signal.message(),
        "OVERRIDDEN: TRUNCATE downgraded by policy",
        "custom message must replace built-in message on override"
    );
}

#[test]
fn custom_rule_can_upgrade_as_well_as_downgrade() {
    // Symmetry: the merge is last-write-wins regardless of direction.
    // We pick an info-tier rule (TBL-LOCK is high; instead use a low
    // built-in if available). Easier: pick a low-severity rule and
    // upgrade to critical via override. Use INFO-DB-NEW if present;
    // otherwise reverse-prove via TBL-TRUNCATE → critical (already
    // critical), which would be a tautology — so we instead override
    // TBL-TRUNCATE down then back up across two configs.
    //
    // Practically: just confirm we can land *every* RiskLevel value on
    // the same built-in id via override.
    for level_yaml in ["info", "low", "medium", "high", "critical"] {
        let yaml = format!(
            r#"
rules:
  - id: TBL-TRUNCATE
    risk_level: {level_yaml}
    message: "override → {level_yaml}"
    triggers:
      kind: truncate
"#
        );
        let config = config_with_overlay(&yaml);
        let report = analyze_risk_with_policy_config(TRUNCATE_SQL, &config)
            .unwrap_or_else(|e| panic!("analyze({level_yaml}) failed: {e:?}"));
        let signal = truncate_signal(&report);
        let observed = signal.risk_level();
        let expected = match level_yaml {
            "info" => RiskLevel::Info,
            "low" => RiskLevel::Low,
            "medium" => RiskLevel::Medium,
            "high" => RiskLevel::High,
            "critical" => RiskLevel::Critical,
            _ => unreachable!(),
        };
        assert_eq!(
            observed, expected,
            "override({level_yaml}) → emitted signal risk_level should match"
        );
    }
}

// ────────────────────────────────────────────────────────────────────
// 2. Override is scoped by rule_id
// ────────────────────────────────────────────────────────────────────

#[test]
fn unrelated_builtin_keeps_its_severity_when_a_different_rule_is_overridden() {
    // Override an unrelated rule_id. TBL-TRUNCATE must still fire at
    // its built-in severity (Critical) — the merge is by `rule_id`,
    // not a global tier shift.
    let custom_yaml = r#"
rules:
  - id: SOME-UNRELATED-CUSTOM-RULE-001
    risk_level: low
    message: "custom rule that targets SELECTs"
    triggers:
      kind: select
"#;
    let config = config_with_overlay(custom_yaml);
    let report = analyze_risk_with_policy_config(TRUNCATE_SQL, &config)
        .expect("analyze with unrelated overlay succeeds");
    let signal = truncate_signal(&report);
    assert_eq!(
        signal.risk_level(),
        RiskLevel::Critical,
        "TBL-TRUNCATE built-in severity must be untouched when a \
         different rule_id is overridden"
    );
}

// ────────────────────────────────────────────────────────────────────
// 3. Merge does not mutate the global built-in cache
// ────────────────────────────────────────────────────────────────────

#[test]
fn build_v1_rule_corpus_does_not_mutate_global_builtin_cache() {
    use lexega_core::facts::RiskLevel as FactsRiskLevel;

    // Snapshot built-in TBL-TRUNCATE severity before the merge.
    let before = builtin_truncate_rule().risk_level;
    assert_eq!(
        before,
        FactsRiskLevel::Critical,
        "built-in TBL-TRUNCATE baseline (facts::RiskLevel) is Critical"
    );

    // Build a merged corpus that downgrades TBL-TRUNCATE.
    let custom_yaml = r#"
rules:
  - id: TBL-TRUNCATE
    risk_level: info
    message: "downgraded"
    triggers:
      kind: truncate
"#;
    let custom = load_v1_rules(custom_yaml).expect("parse");
    let merged = build_v1_rule_corpus(custom, true).expect("merge succeeds");

    let merged_rl = merged
        .iter()
        .find(|r| r.id == TRUNCATE_RULE_ID)
        .expect("merged corpus must still contain TBL-TRUNCATE")
        .risk_level;
    assert_eq!(
        merged_rl,
        FactsRiskLevel::Info,
        "merged corpus reflects the override"
    );

    // Re-fetch from the global cache: must still be the original.
    let after = builtin_truncate_rule().risk_level;
    assert_eq!(
        after, before,
        "merge must not have leaked into the global built-in cache"
    );
}

// ────────────────────────────────────────────────────────────────────
// 4. Suppression-style override (enabled: false) silences a built-in
//    via the same merge path — useful negative-confirmation of the
//    "the merged Rule wholly replaces the built-in" semantics.
// ────────────────────────────────────────────────────────────────────

// ────────────────────────────────────────────────────────────────────
// 5. Partial override: severity-only inheritance
//
// Customer specifies just `id` + `risk_level`; the merged rule
// inherits the built-in's `triggers` and `message` verbatim and only
// the severity changes.
// ────────────────────────────────────────────────────────────────────

#[test]
fn partial_override_id_and_risk_level_only_inherits_triggers_and_message() {
    // The built-in's stock message (verified up to a `{...}` template
    // slot, since the built-in does not template at this rule).
    let builtin_msg = builtin_truncate_rule().description.clone();

    let custom_yaml = r#"
rules:
  - id: TBL-TRUNCATE
    risk_level: low
"#;
    let config = config_with_overlay(custom_yaml);
    let report = analyze_risk_with_policy_config(TRUNCATE_SQL, &config)
        .expect("analyze with partial overlay succeeds");
    let signal = truncate_signal(&report);

    assert_eq!(
        signal.risk_level(),
        RiskLevel::Low,
        "partial override should land Low on the emitted signal \
         (built-in is Critical)"
    );
    assert_eq!(
        signal.message(),
        builtin_msg,
        "partial override that omits `message` must inherit the built-in's \
         message verbatim — no field-level loss"
    );
}

// ────────────────────────────────────────────────────────────────────
// 6. Partial override: message-only inheritance
//
// Customer overrides only the message; severity stays Critical and
// the predicate is inherited unchanged.
// ────────────────────────────────────────────────────────────────────

#[test]
fn partial_override_message_only_keeps_builtin_severity_and_triggers() {
    let custom_yaml = r#"
rules:
  - id: TBL-TRUNCATE
    message: "Custom guidance: see runbook RB-42 before approving TRUNCATE"
"#;
    let config = config_with_overlay(custom_yaml);
    let report = analyze_risk_with_policy_config(TRUNCATE_SQL, &config)
        .expect("analyze with message-only overlay succeeds");
    let signal = truncate_signal(&report);

    assert_eq!(
        signal.risk_level(),
        RiskLevel::Critical,
        "message-only override must NOT change severity"
    );
    assert_eq!(
        signal.message(),
        "Custom guidance: see runbook RB-42 before approving TRUNCATE",
        "message-only override must land the new message"
    );
}

// ────────────────────────────────────────────────────────────────────
// 7. Partial override: enabled: false suppresses the built-in
//
// The customer-facing way to disable a built-in is `id + enabled: false`.
// Mirrors the historic suppression-via-full-restate path but without
// requiring the customer to duplicate the predicate.
// ────────────────────────────────────────────────────────────────────

#[test]
fn partial_override_enabled_false_suppresses_builtin() {
    let custom_yaml = r#"
rules:
  - id: TBL-TRUNCATE
    enabled: false
"#;
    let config = config_with_overlay(custom_yaml);
    let report = analyze_risk_with_policy_config(TRUNCATE_SQL, &config)
        .expect("analyze with enabled-false overlay succeeds");
    let matches: Vec<_> = report
        .signals
        .iter()
        .filter(|s| s.rule_id() == Some(TRUNCATE_RULE_ID))
        .collect();
    assert!(
        matches.is_empty(),
        "partial override `enabled: false` should suppress the built-in; \
         got {} TBL-TRUNCATE signal(s)",
        matches.len()
    );
}

// ────────────────────────────────────────────────────────────────────
// 8. Partial override: severity + message together (no triggers)
// ────────────────────────────────────────────────────────────────────

#[test]
fn partial_override_severity_and_message_together() {
    let custom_yaml = r#"
rules:
  - id: TBL-TRUNCATE
    risk_level: medium
    message: "Policy: TRUNCATE allowed in staging only"
"#;
    let config = config_with_overlay(custom_yaml);
    let report = analyze_risk_with_policy_config(TRUNCATE_SQL, &config)
        .expect("analyze with severity+message overlay succeeds");
    let signal = truncate_signal(&report);
    assert_eq!(signal.risk_level(), RiskLevel::Medium);
    assert_eq!(signal.message(), "Policy: TRUNCATE allowed in staging only");
}

// ────────────────────────────────────────────────────────────────────
// 9. Partial override with an unknown rule_id is rejected at merge.
//
// A customer who mistypes the built-in id — or who tries to define a
// new rule but forgets the body — gets a clear error pointing at the
// offending id.
// ────────────────────────────────────────────────────────────────────

#[test]
fn partial_override_with_unknown_id_is_rejected_at_merge() {
    let yaml = r#"
rules:
  - id: DEFINITELY-NOT-A-BUILTIN-RULE-ID
    risk_level: low
"#;
    let loaded = load_v1_rules(yaml).expect("partial entry parses fine");
    let err = build_v1_rule_corpus(loaded, true)
        .expect_err("merge must reject partial that doesn't match any built-in");
    match err {
        MergeError::UnresolvedPartialOverride { rule_id } => {
            assert_eq!(rule_id, "DEFINITELY-NOT-A-BUILTIN-RULE-ID");
        }
        other => panic!("expected UnresolvedPartialOverride, got {:?}", other),
    }
}

// ────────────────────────────────────────────────────────────────────
// 10. Partial override + `--no-builtin` is rejected at merge.
//
// With built-ins disabled, there is no corpus to inherit from. The
// merge surfaces a typed error rather than silently producing an
// empty / partially-shaped corpus.
// ────────────────────────────────────────────────────────────────────

#[test]
fn partial_override_with_no_builtin_is_rejected_at_merge() {
    let yaml = r#"
rules:
  - id: TBL-TRUNCATE
    risk_level: low
"#;
    let loaded = load_v1_rules(yaml).expect("partial entry parses fine");
    let err = build_v1_rule_corpus(loaded, /* include_builtins = */ false)
        .expect_err("merge must reject partial when built-ins disabled");
    match err {
        MergeError::PartialOverrideWithoutBuiltins { rule_id } => {
            assert_eq!(rule_id, TRUNCATE_RULE_ID);
        }
        other => panic!("expected PartialOverrideWithoutBuiltins, got {:?}", other),
    }
}

// ────────────────────────────────────────────────────────────────────
// 11. Partial overrides cannot change `triggers` / `emission` / `per_statement`
//
// These are load-time rejections — the loader classifies any entry
// without `triggers` as a partial override, then immediately rejects
// `emission` / `per_statement` siblings (the partial-override surface
// is severity + message + enabled only). Pinning these here keeps the
// override scope decision visible to anyone editing the override
// semantics later.
// ────────────────────────────────────────────────────────────────────

#[test]
fn partial_override_cannot_set_emission() {
    use lexega_core::rules::LoadError;
    let yaml = r#"
rules:
  - id: TBL-TRUNCATE
    risk_level: low
    emission: per_witness
"#;
    match load_v1_rules(yaml).expect_err("emission disallowed on partial") {
        LoadError::DisallowedFieldOnPartialOverride { rule_id, field } => {
            assert_eq!(rule_id, TRUNCATE_RULE_ID);
            assert_eq!(field, "emission");
        }
        other => panic!("expected DisallowedFieldOnPartialOverride, got {:?}", other),
    }
}

#[test]
fn partial_override_cannot_set_per_statement() {
    use lexega_core::rules::LoadError;
    let yaml = r#"
rules:
  - id: TBL-TRUNCATE
    risk_level: low
    per_statement: true
"#;
    match load_v1_rules(yaml).expect_err("per_statement disallowed on partial") {
        LoadError::DisallowedFieldOnPartialOverride { rule_id, field } => {
            assert_eq!(rule_id, TRUNCATE_RULE_ID);
            assert_eq!(field, "per_statement");
        }
        other => panic!("expected DisallowedFieldOnPartialOverride, got {:?}", other),
    }
}

#[test]
fn custom_rule_with_enabled_false_suppresses_builtin() {
    let custom_yaml = r#"
rules:
  - id: TBL-TRUNCATE
    risk_level: critical
    message: "disabled by policy"
    enabled: false
    triggers:
      kind: truncate
"#;
    let config = config_with_overlay(custom_yaml);
    let report = analyze_risk_with_policy_config(TRUNCATE_SQL, &config)
        .expect("analyze with disable-override succeeds");
    let matches: Vec<_> = report
        .signals
        .iter()
        .filter(|s| s.rule_id() == Some(TRUNCATE_RULE_ID))
        .collect();
    assert!(
        matches.is_empty(),
        "an `enabled: false` override should suppress the built-in; \
         got {} TBL-TRUNCATE signal(s)",
        matches.len()
    );
}
