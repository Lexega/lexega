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
use lexega_core::facts::RiskLevel as RuleRisk;
use lexega_core::rules::{all_builtin_rules, build_v1_rule_corpus, load_v1_rules, MergeError};

const TRUNCATE_SQL: &str = "TRUNCATE TABLE my_table;";
const TRUNCATE_RULE_ID: &str = "TBL-TRUNCATE";

/// Build a config whose corpus is built-ins overlaid with `custom_yaml`.
/// Mirrors what the CLI does for `--custom-rules` without `--no-builtin`.
fn config_with_overlay(custom_yaml: &str) -> AnalysisConfig {
    let custom = load_v1_rules(custom_yaml).expect("custom rules parse");
    let merged = build_v1_rule_corpus(custom, /* include_builtins = */ true)
        .expect("merge against built-ins succeeds");

    AnalysisConfig {
        custom_rules: Some(merged.into()),
        ..Default::default()
    }
}

fn truncate_finding(
    report: &lexega_core::analyzer::AnalysisReport,
) -> &lexega_core::analyzer::RuleMatch {
    let matches: Vec<_> = report
        .entries()
        .filter(|s| s.rule_id() == Some(TRUNCATE_RULE_ID))
        .collect();
    assert_eq!(
        matches.len(),
        1,
        "expected exactly one TBL-TRUNCATE finding (no override-double-fire); got {}",
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
    let finding = truncate_finding(&report);
    assert_eq!(
        finding.risk_level(),
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
    // only the severity / message that customers read off the finding.
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

    let finding = truncate_finding(&report);
    assert_eq!(
        finding.risk_level(),
        RiskLevel::Low,
        "custom rule's risk_level must win over built-in (built-in is Critical)"
    );
    assert_eq!(
        finding.message(),
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
        let finding = truncate_finding(&report);
        let observed = finding.risk_level();
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
            "override({level_yaml}) → emitted finding risk_level should match"
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
    let finding = truncate_finding(&report);
    assert_eq!(
        finding.risk_level(),
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
    let finding = truncate_finding(&report);

    assert_eq!(
        finding.risk_level(),
        RiskLevel::Low,
        "partial override should land Low on the emitted finding \
         (built-in is Critical)"
    );
    assert_eq!(
        finding.message(),
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
    let finding = truncate_finding(&report);

    assert_eq!(
        finding.risk_level(),
        RiskLevel::Critical,
        "message-only override must NOT change severity"
    );
    assert_eq!(
        finding.message(),
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
        .entries()
        .filter(|s| s.rule_id() == Some(TRUNCATE_RULE_ID))
        .collect();
    assert!(
        matches.is_empty(),
        "partial override `enabled: false` should suppress the built-in; \
         got {} TBL-TRUNCATE finding(s)",
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
    let finding = truncate_finding(&report);
    assert_eq!(finding.risk_level(), RiskLevel::Medium);
    assert_eq!(
        finding.message(),
        "Policy: TRUNCATE allowed in staging only"
    );
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
        .entries()
        .filter(|s| s.rule_id() == Some(TRUNCATE_RULE_ID))
        .collect();
    assert!(
        matches.is_empty(),
        "an `enabled: false` override should suppress the built-in; \
         got {} TBL-TRUNCATE finding(s)",
        matches.len()
    );
}

// A partial override of a former id overlays the rule that absorbed it.

const FORMER_ID: &str = "SNW-PWDPOL-EXPIRY-STALE";
const ABSORBING_ID: &str = "SNW-PWDPOL-EXPIRY-LONG";

fn merged_rule(yaml: &str, id: &str) -> lexega_core::rules::Rule {
    let loaded = load_v1_rules(yaml).expect("parses");
    let corpus = build_v1_rule_corpus(loaded, true).expect("merges");
    corpus
        .into_iter()
        .find(|r| r.id == id)
        .expect("rule in corpus")
}

#[test]
fn disabling_a_former_id_disables_the_rule_that_absorbed_it() {
    let rule = merged_rule(
        &format!("rules:\n  - id: {FORMER_ID}\n    enabled: false\n"),
        ABSORBING_ID,
    );
    assert!(!rule.enabled);
}

#[test]
fn a_risk_level_on_a_former_id_reaches_the_rule_that_absorbed_it() {
    let rule = merged_rule(
        &format!("rules:\n  - id: {FORMER_ID}\n    risk_level: critical\n"),
        ABSORBING_ID,
    );
    assert_eq!(rule.risk_level, RuleRisk::Critical);
}

#[test]
fn a_former_id_is_matched_without_regard_to_case() {
    let rule = merged_rule(
        "rules:\n  - id: snw-pwdpol-expiry-stale\n    enabled: false\n",
        ABSORBING_ID,
    );
    assert!(!rule.enabled);
}

#[test]
fn a_former_id_override_adds_no_rule_to_the_corpus() {
    let loaded = load_v1_rules(&format!(
        "rules:\n  - id: {FORMER_ID}\n    enabled: false\n"
    ))
    .expect("parses");
    let corpus = build_v1_rule_corpus(loaded, true).expect("merges");
    let builtin = all_builtin_rules().expect("built-ins");
    assert_eq!(corpus.len(), builtin.len());
    assert!(!corpus.iter().any(|r| r.id == FORMER_ID));
}

#[test]
fn a_later_entry_wins_between_a_former_id_and_its_live_id() {
    let yaml = format!(
        "rules:\n  - id: {FORMER_ID}\n    risk_level: critical\n  - id: {ABSORBING_ID}\n    risk_level: info\n"
    );
    assert_eq!(merged_rule(&yaml, ABSORBING_ID).risk_level, RuleRisk::Info);
    let yaml = format!(
        "rules:\n  - id: {ABSORBING_ID}\n    risk_level: info\n  - id: {FORMER_ID}\n    risk_level: critical\n"
    );
    assert_eq!(
        merged_rule(&yaml, ABSORBING_ID).risk_level,
        RuleRisk::Critical
    );
}

const FULL_RULE_UNDER_FORMER_ID: &str = "rules:\n  - id: SNW-PWDPOL-EXPIRY-STALE\n    risk_level: high\n    message: \"mine\"\n    triggers:\n      kind: grant\n";

#[test]
fn a_full_rule_under_a_former_id_replaces_the_rule_that_absorbed_it() {
    let builtin = all_builtin_rules().expect("built-ins");
    let position = builtin
        .iter()
        .position(|r| r.id == ABSORBING_ID)
        .expect("absorbing rule");
    let loaded = load_v1_rules(FULL_RULE_UNDER_FORMER_ID).expect("parses");
    let corpus = build_v1_rule_corpus(loaded, true).expect("merges");
    assert_eq!(corpus.len(), builtin.len());
    assert!(!corpus.iter().any(|r| r.id == FORMER_ID));
    let rule = &corpus[position];
    assert_eq!(rule.id, ABSORBING_ID);
    assert_eq!(rule.description, "mine");
    assert_eq!(rule.risk_level, RuleRisk::High);
    assert!(rule.former_ids.iter().any(|f| f == FORMER_ID));
}

#[test]
fn a_full_rule_under_a_former_id_takes_the_canonical_id_without_builtins() {
    let loaded = load_v1_rules(FULL_RULE_UNDER_FORMER_ID).expect("parses");
    let corpus = build_v1_rule_corpus(loaded, false).expect("merges");
    assert_eq!(corpus.len(), 1);
    assert_eq!(corpus[0].id, ABSORBING_ID);
}

#[test]
fn a_loaded_file_lists_the_entries_that_name_a_former_id() {
    use lexega_core::rules::FormerIdOverride;
    let yaml = format!(
        "rules:\n  - id: {FORMER_ID}\n    enabled: false\n  - id: TBL-TRUNCATE\n    enabled: false\n"
    );
    let loaded = load_v1_rules(&yaml).expect("parses");
    assert_eq!(
        loaded.former_id_overrides(),
        [FormerIdOverride {
            former_id: FORMER_ID.to_string(),
            canonical_id: ABSORBING_ID.to_string(),
        }]
    );
    let loaded = load_v1_rules(FULL_RULE_UNDER_FORMER_ID).expect("parses");
    assert_eq!(loaded.former_id_overrides().len(), 1);

    // Rules handed over already built list the same entries.
    let rules: Vec<lexega_core::rules::Rule> = loaded
        .into_entries()
        .into_iter()
        .filter_map(|entry| match entry {
            lexega_core::rules::LoadedEntry::Full(rule) => Some(rule),
            lexega_core::rules::LoadedEntry::Partial(_) => None,
        })
        .collect();
    let built = lexega_core::rules::LoadedRuleset::from_full_rules(rules);
    assert_eq!(
        built.former_id_overrides(),
        [FormerIdOverride {
            former_id: FORMER_ID.to_string(),
            canonical_id: ABSORBING_ID.to_string(),
        }]
    );
}

#[test]
fn a_former_id_override_without_builtins_keeps_its_error() {
    let loaded = load_v1_rules(&format!(
        "rules:\n  - id: {FORMER_ID}\n    enabled: false\n"
    ))
    .expect("parses");
    match build_v1_rule_corpus(loaded, false) {
        Err(MergeError::PartialOverrideWithoutBuiltins { rule_id }) => {
            assert_eq!(rule_id, FORMER_ID)
        }
        other => panic!("expected PartialOverrideWithoutBuiltins, got {other:?}"),
    }
}

/// A configuration built per file from the run's one holds that corpus,
/// not a copy of it: cloning the configuration copies no rule.
#[test]
fn a_cloned_configuration_shares_its_corpus() {
    let config = config_with_overlay("rules:\n  - id: TBL-TRUNCATE\n    risk_level: low\n");
    let per_file = config.clone();
    let (Some(run), Some(file)) = (&config.custom_rules, &per_file.custom_rules) else {
        panic!("both configurations hold the corpus");
    };
    assert!(std::sync::Arc::ptr_eq(run, file));
}

/// Whether a corpus of the built-ins and `custom_yaml` raises `rule` on
/// `sql`, read in `dialect`.
fn custom_rule_fires(
    custom_yaml: &str,
    dialect: lexega_core::dialect::DialectRef,
    rule: &str,
    sql: &str,
) -> bool {
    let config = AnalysisConfig {
        dialect: Some(dialect),
        ..config_with_overlay(custom_yaml)
    };
    analyze_risk_with_policy_config(sql, &config)
        .expect("analyze succeeds")
        .entries()
        .any(|entry| entry.rule_id() == Some(rule))
}

/// A custom rule that allows only named procedures to be called reads the
/// procedure as Snowflake names it: any spelling of an approved name
/// passes, a quoted name keeps its case, and a call it cannot read, or one
/// made in a block, is held to the list too.
#[test]
fn a_call_allowlist_reads_the_procedure_as_the_database_names_it() {
    const RULES: &str = r#"
rules:
  - id: ORG-CALL-ALLOWLIST
    risk_level: critical
    message: "Only approved stored procedures may be called."
    triggers:
      all_of:
        - kind: call
        - any_of:
            - ddl.target:
                exists: false
            - ddl.target.name.canonical:
                not_in: [PROD.CORE.REFRESH_ORDERS]
"#;
    let fires = |sql: &str| {
        custom_rule_fires(
            RULES,
            lexega_core::dialect::snowflake(),
            "ORG-CALL-ALLOWLIST",
            sql,
        )
    };
    for sql in [
        "CALL prod.core.refresh_orders('2024-01-01');",
        "call PROD.Core.Refresh_Orders();",
        r#"CALL "PROD"."CORE"."REFRESH_ORDERS"();"#,
    ] {
        assert!(!fires(sql), "{sql}");
    }
    for sql in [
        "CALL prod.core.purge_all();",
        r#"CALL "prod"."core"."refresh_orders"();"#,
        "CALL refresh_orders();",
        "BEGIN CALL prod.core.purge_all(); END;",
    ] {
        assert!(fires(sql), "{sql}");
    }
}

/// A quoted name keeps the case the dialect gives it in the facts a custom
/// rule reads: PostgreSQL folds `MyDomain` to `mydomain` and keeps
/// `"MyDomain"`. A rule's literal on a `normalized` name folds the same
/// way, so the quoted literal names the case-sensitive domain.
#[test]
fn a_custom_rule_reads_a_quoted_name_with_its_case() {
    const RULES: &str = r#"
rules:
  - id: ORG-DOMAIN-GUARD
    risk_level: high
    message: "The MyDomain domain is protected."
    triggers:
      all_of:
        - kind: pg_drop_domain
        - ddl.target.name.name.normalized: '"MyDomain"'
"#;
    let fires = |sql: &str| {
        custom_rule_fires(
            RULES,
            lexega_core::dialect::postgres(),
            "ORG-DOMAIN-GUARD",
            sql,
        )
    };
    assert!(fires(r#"DROP DOMAIN "MyDomain";"#));
    assert!(!fires("DROP DOMAIN MyDomain;"));
}

/// A custom rule on the arguments a statement passes to the routine it
/// calls holds across dialects: Snowflake's `CALL` and T-SQL's `EXEC`
/// carry the routine in `ddl.target` and each argument in
/// `call.arguments`, by position and name, with its value's shape. A value
/// the rule cannot read, or an argument left out, is held to it too.
#[test]
fn a_custom_rule_reads_the_arguments_of_a_call_in_any_dialect() {
    const RULES: &str = r#"
rules:
  - id: ORG-PURGE-RETENTION
    risk_level: critical
    message: "purge_orders must keep at least 7 days."
    triggers:
      all_of:
        - kind:
            in: [call, mssql_exec]
        - ddl.target.name.name.normalized: PURGE_ORDERS
        - any_of:
            - call.arguments:
                exists: false
            - call.arguments:
                exists:
                  all_of:
                    - position: 0
                    - any_of:
                        - value_kind:
                            not_in: [number]
                        - value_number:
                            lt: 7
"#;
    let fires = |dialect, sql: &str| custom_rule_fires(RULES, dialect, "ORG-PURGE-RETENTION", sql);
    let snowflake = lexega_core::dialect::snowflake;
    let mssql = lexega_core::dialect::mssql;
    assert!(!fires(snowflake(), "CALL prod.core.purge_orders(30);"));
    assert!(fires(snowflake(), "CALL prod.core.purge_orders(0);"));
    assert!(fires(
        snowflake(),
        "CALL prod.core.purge_orders(days => 3);"
    ));
    assert!(fires(snowflake(), "CALL prod.core.purge_orders(:days);"));
    assert!(fires(snowflake(), "CALL prod.core.purge_orders();"));
    assert!(!fires(snowflake(), "CALL prod.core.refresh_orders(0);"));
    assert!(!fires(mssql(), "EXEC dbo.purge_orders 30;"));
    assert!(fires(mssql(), "EXEC dbo.purge_orders 0;"));
    assert!(fires(mssql(), "EXEC dbo.purge_orders @days = 2;"));
    assert!(fires(mssql(), "EXEC [dbo].[PURGE_ORDERS] @days;"));
}

/// A custom rule reads the stage a `GET` or `REMOVE` names, and the path
/// within it: files may not be fetched from an export stage, and may be
/// removed only under `/tmp/`, a REMOVE of a whole stage included.
#[test]
fn a_custom_rule_reads_the_stage_and_path_a_file_command_names() {
    const RULES: &str = r#"
rules:
  - id: ORG-NO-EXPORT-GET
    risk_level: critical
    message: "Files may not be fetched from an export stage."
    triggers:
      all_of:
        - kind: stage_get
        - ddl.target.name.canonical:
            in: [PROD.CORE.EXPORTS]
  - id: ORG-REMOVE-TMP-ONLY
    risk_level: critical
    message: "Files may be removed only under /tmp/."
    triggers:
      all_of:
        - kind: stage_remove
        - not:
            ddl.stage.path:
              matches: "/tmp/*"
"#;
    let fires =
        |rule, sql: &str| custom_rule_fires(RULES, lexega_core::dialect::snowflake(), rule, sql);
    assert!(fires(
        "ORG-NO-EXPORT-GET",
        "GET @prod.core.exports/q3/ file:///tmp/out/;"
    ));
    assert!(fires(
        "ORG-NO-EXPORT-GET",
        "GET @PROD.CORE.EXPORTS file:///tmp/out/;"
    ));
    assert!(!fires(
        "ORG-NO-EXPORT-GET",
        "GET @prod.core.landing/q3/ file:///tmp/out/;"
    ));
    assert!(!fires(
        "ORG-REMOVE-TMP-ONLY",
        "REMOVE @prod.core.raw/tmp/old.csv;"
    ));
    assert!(fires(
        "ORG-REMOVE-TMP-ONLY",
        "REMOVE @prod.core.raw/2024/old/;"
    ));
    assert!(fires("ORG-REMOVE-TMP-ONLY", "REMOVE @prod.core.raw;"));
}

/// A named list read against an identifier's folded name folds each item
/// as a literal does: a list allowlist passes every spelling of an approved
/// procedure and holds a quoted, case-sensitive one to the list, as `not_in`
/// does; a pattern item folds the same way.
#[test]
fn a_named_list_reads_an_identifier_as_a_literal_does() {
    const RULES: &str = r#"
lists:
  approved_procs:
    values: [prod.core.refresh_orders]
    patterns: ["PROD.REPORTING.*"]
rules:
  - id: ORG-CALL-LIST
    risk_level: critical
    message: "Only approved stored procedures may be called."
    triggers:
      all_of:
        - kind: call
        - any_of:
            - ddl.target:
                exists: false
            - ddl.target.name.canonical:
                not_in_list: approved_procs
"#;
    let fires = |sql: &str| {
        custom_rule_fires(
            RULES,
            lexega_core::dialect::snowflake(),
            "ORG-CALL-LIST",
            sql,
        )
    };
    for sql in [
        "CALL prod.core.refresh_orders();",
        "call PROD.Core.Refresh_Orders();",
        r#"CALL "PROD"."CORE"."REFRESH_ORDERS"();"#,
        "CALL prod.reporting.daily_totals();",
    ] {
        assert!(!fires(sql), "{sql}");
    }
    for sql in [
        r#"CALL "prod"."core"."refresh_orders"();"#,
        "CALL prod.core.purge_all();",
        "CALL refresh_orders();",
    ] {
        assert!(fires(sql), "{sql}");
    }
}

/// A custom rule reads the object a statement acts on in `ddl.target`
/// where it lives in no family of its own: every table a `LOCK TABLE`
/// names, the table a column comment is on, the database a T-SQL backup
/// reads, the kind of what a `REINDEX` rebuilds.
#[test]
fn a_custom_rule_reads_the_object_a_statement_acts_on() {
    const RULES: &str = r#"
rules:
  - id: ORG-LOCK
    risk_level: high
    message: "Orders may not be locked."
    triggers:
      all_of:
        - kind: pg_lock_table
        - ddl.targets:
            exists:
              name.canonical: { in: [prod.orders] }
  - id: ORG-COMMENT
    risk_level: low
    message: "Orders' comments are owned by the data team."
    triggers:
      all_of:
        - kind: comment
        - ddl.target.name.canonical: { in: [PROD.CORE.ORDERS] }
  - id: ORG-BACKUP
    risk_level: high
    message: "The sales database is backed up by the platform team."
    triggers:
      all_of:
        - kind: mssql_backup
        - ddl.target.name.name.normalized: SALES
  - id: ORG-REINDEX-TABLE
    risk_level: low
    message: "Reindex an index, not a whole table."
    triggers:
      all_of:
        - kind: pg_reindex
        - ddl.target.kind: table
"#;
    let fires = |dialect, rule, sql: &str| custom_rule_fires(RULES, dialect, rule, sql);
    let (pg, sf, ms) = (
        lexega_core::dialect::postgres,
        lexega_core::dialect::snowflake,
        lexega_core::dialect::mssql,
    );
    assert!(fires(
        pg(),
        "ORG-LOCK",
        "LOCK TABLE prod.audit, prod.orders IN EXCLUSIVE MODE;"
    ));
    assert!(!fires(
        pg(),
        "ORG-LOCK",
        "LOCK TABLE prod.audit IN EXCLUSIVE MODE;"
    ));
    assert!(fires(
        sf(),
        "ORG-COMMENT",
        "COMMENT ON COLUMN prod.core.orders.amount IS 'x';"
    ));
    assert!(fires(
        sf(),
        "ORG-COMMENT",
        "COMMENT ON TABLE prod.core.orders IS 'x';"
    ));
    assert!(!fires(
        sf(),
        "ORG-COMMENT",
        "COMMENT ON TABLE prod.core.items IS 'x';"
    ));
    assert!(fires(
        ms(),
        "ORG-BACKUP",
        "BACKUP DATABASE [sales] TO DISK = 'D:\\b\\s.bak';"
    ));
    assert!(fires(
        pg(),
        "ORG-REINDEX-TABLE",
        "REINDEX TABLE prod.orders;"
    ));
    assert!(!fires(
        pg(),
        "ORG-REINDEX-TABLE",
        "REINDEX INDEX prod.orders_pk;"
    ));
}

/// A custom rule reads the variables a `DECLARE` makes, and the cursor,
/// channel or savepoint a statement names.
#[test]
fn a_custom_rule_reads_declared_variables_and_session_names() {
    const RULES: &str = r#"
rules:
  - id: ORG-DECLARE-LITERAL
    risk_level: low
    message: "Variables take their values from parameters, not literals."
    triggers:
      all_of:
        - kind: declare
        - declare.variables:
            exists:
              default: string_literal
  - id: ORG-NOTIFY
    risk_level: low
    message: "Only the orders channel is notified."
    triggers:
      all_of:
        - kind: pg_notify
        - not:
            ddl.target.name.name.normalized: orders_changed
  - id: ORG-CURSOR
    risk_level: low
    message: "The purge cursor may not be opened."
    triggers:
      all_of:
        - kind: open_cursor
        - ddl.target.name.name.normalized: PURGE_CURSOR
"#;
    let fires = |dialect, rule, sql: &str| custom_rule_fires(RULES, dialect, rule, sql);
    let (pg, ms) = (lexega_core::dialect::postgres, lexega_core::dialect::mssql);
    assert!(fires(
        ms(),
        "ORG-DECLARE-LITERAL",
        "DECLARE @key NVARCHAR(50) = N'x';"
    ));
    assert!(!fires(ms(), "ORG-DECLARE-LITERAL", "DECLARE @n INT = 1;"));
    assert!(fires(pg(), "ORG-NOTIFY", "NOTIFY payroll_changed;"));
    assert!(!fires(pg(), "ORG-NOTIFY", "NOTIFY orders_changed;"));
    assert!(fires(ms(), "ORG-CURSOR", "OPEN purge_cursor;"));
    assert!(!fires(ms(), "ORG-CURSOR", "OPEN report_cursor;"));
}

/// A one-part quoted name holding dots is not the name of its parts, and a
/// rule's quoted, dotted literal or list item names the object its parts
/// name: the allowlist holds against both.
#[test]
fn a_quoted_name_holding_dots_is_not_the_name_of_its_parts() {
    const RULES: &str = r#"
lists:
  approved_procs:
    values: ['"analytics".ops.refresh_orders', "[dbo].[usp_rebuild_stats]"]
rules:
  - id: ORG-CALL-ALLOWLIST
    risk_level: critical
    message: "Only approved stored procedures may be called."
    triggers:
      all_of:
        - kind: call
        - ddl.target.name.canonical: { not_in: [ANALYTICS.OPS.REFRESH_ORDERS] }
  - id: ORG-CALL-LISTED
    risk_level: low
    message: "A listed procedure."
    triggers:
      all_of:
        - kind: { in: [call, mssql_exec] }
        - ddl.target.name.canonical: { in_list: approved_procs }
"#;
    let fires = |dialect, rule, sql: &str| custom_rule_fires(RULES, dialect, rule, sql);
    let (sf, ms) = (lexega_core::dialect::snowflake, lexega_core::dialect::mssql);
    for sql in [
        r#"CALL "ANALYTICS.OPS.REFRESH_ORDERS"(30);"#,
        r#"CALL ANALYTICS."OPS.REFRESH_ORDERS"(30);"#,
        r#"CALL "analytics".ops.refresh_orders(30);"#,
    ] {
        assert!(fires(sf(), "ORG-CALL-ALLOWLIST", sql), "{sql}");
    }
    assert!(!fires(
        sf(),
        "ORG-CALL-ALLOWLIST",
        "CALL analytics.ops.refresh_orders(30);"
    ));
    assert!(fires(
        sf(),
        "ORG-CALL-LISTED",
        r#"CALL "analytics".OPS.Refresh_Orders();"#
    ));
    assert!(!fires(
        sf(),
        "ORG-CALL-LISTED",
        "CALL analytics.ops.refresh_orders();"
    ));
    assert!(fires(
        ms(),
        "ORG-CALL-LISTED",
        "EXEC dbo.usp_rebuild_stats @days = 7;"
    ));
    assert!(!fires(
        ms(),
        "ORG-CALL-LISTED",
        "EXEC [dbo.usp_rebuild_stats] @days = 7;"
    ));
}

/// A rule whose path names no fact, below its first field or in a
/// quantifier's body, or reads a list's elements without naming one, is
/// refused when it loads; so is a combinator that shares its mapping with
/// another condition, which would go unread.
#[test]
fn a_rule_that_would_read_nothing_is_refused_when_it_loads() {
    let refusal = |triggers: &str| {
        let yaml = format!(
            "rules:\n  - id: ORG-T\n    risk_level: low\n    message: t\n    triggers:\n{triggers}"
        );
        match load_v1_rules(&yaml) {
            Ok(_) => panic!("loaded:\n{triggers}"),
            Err(error) => error.to_string(),
        }
    };
    let typo = refusal("      ddl.taget.name.canonical: { in: [A.B.C] }\n");
    assert!(typo.contains("did you mean 'target'"), "{typo}");
    let body = refusal("      call.arguments: { exists: { value_numbr: { lt: 7 } } }\n");
    assert!(body.contains("did you mean 'value_number'"), "{body}");
    let through = refusal("      call.arguments.value_number: { lt: 7 }\n");
    assert!(through.contains("a list"), "{through}");
    let beside = refusal(
        "      not:\n        ddl.target.name.canonical: { in: [A.B.C] }\n        any_of: [ { kind: call } ]\n",
    );
    assert!(beside.contains("must stand alone"), "{beside}");
    for valid in [
        "      call.arguments: { exists: { value_number: { lt: 7 } } }\n",
        "      call.arguments.0.value_number: { lt: 7 }\n",
        "      ddl.target: { exists: false }\n",
        "      query.scopes: { each: { where_predicates: { each: { root.kind: column } } } }\n",
    ] {
        assert!(
            load_v1_rules(&format!(
            "rules:\n  - id: ORG-T\n    risk_level: low\n    message: t\n    triggers:\n{valid}"
        ))
            .is_ok(),
            "{valid}"
        );
    }
}

/// A floor on a numeric argument reads the number however it is written:
/// a decimal, an exponent or a sign.
#[test]
fn a_numeric_argument_floor_reads_every_spelling_of_the_number() {
    const RULES: &str = r#"
rules:
  - id: ORG-RETENTION-FLOOR
    risk_level: critical
    message: "Retention must be at least 7 days."
    triggers:
      all_of:
        - kind: { in: [call, mssql_exec] }
        - call.arguments:
            exists:
              all_of:
                - any_of: [ { position: 0 }, { name: days } ]
                - value_number: { lt: 7 }
  - id: ORG-RETENTION-ONE
    risk_level: low
    message: "One day."
    triggers:
      call.arguments: { exists: { value_number: 1 } }
"#;
    let fires = |dialect, rule, sql: &str| custom_rule_fires(RULES, dialect, rule, sql);
    let (sf, ms) = (lexega_core::dialect::snowflake, lexega_core::dialect::mssql);
    for sql in [
        "CALL ops.purge(3);",
        "CALL ops.purge(3.0);",
        "CALL ops.purge(3e0);",
        "CALL ops.purge(6.5);",
        "CALL ops.purge(-1);",
    ] {
        assert!(fires(sf(), "ORG-RETENTION-FLOOR", sql), "{sql}");
    }
    for sql in [
        "CALL ops.purge(30);",
        "CALL ops.purge(7.0);",
        "CALL ops.purge(7e1);",
    ] {
        assert!(!fires(sf(), "ORG-RETENTION-FLOOR", sql), "{sql}");
    }
    assert!(fires(
        ms(),
        "ORG-RETENTION-FLOOR",
        "EXEC ops.purge @days = 3.0;"
    ));
    assert!(fires(sf(), "ORG-RETENTION-ONE", "CALL ops.purge(1.0);"));
}

/// A statement that names its target by text (MySQL `LOAD DATA`, a BigQuery
/// path in backticks) names it by its parts, so a rule on its `canonical`
/// name matches the dotted name; a BigQuery path keeps its case, as a
/// quoted literal names it.
#[test]
fn a_target_named_by_text_is_named_by_its_parts() {
    const RULES: &str = r#"
rules:
  - id: ORG-NO-LOAD-ORDERS
    risk_level: high
    message: "Orders are not bulk loaded."
    triggers:
      ddl.target.name.canonical: { in: [prod.orders, '`prod.core.orders`'] }
"#;
    let fires = |dialect, sql: &str| custom_rule_fires(RULES, dialect, "ORG-NO-LOAD-ORDERS", sql);
    assert!(fires(
        lexega_core::dialect::mysql(),
        "LOAD DATA INFILE '/tmp/o.csv' INTO TABLE prod.orders FIELDS TERMINATED BY ',';"
    ));
    assert!(fires(
        lexega_core::dialect::bigquery(),
        "LOAD DATA INTO `prod.core.orders` FROM FILES (format = 'CSV', uris = ['gs://b/o.csv']);"
    ));
    assert!(!fires(
        lexega_core::dialect::mysql(),
        "LOAD DATA INFILE '/tmp/o.csv' INTO TABLE `prod.orders` FIELDS TERMINATED BY ',';"
    ));
}
