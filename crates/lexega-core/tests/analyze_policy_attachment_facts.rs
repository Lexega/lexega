// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

// SNW-AUTHPOL-ON / SNW-AUTHPOL-OFF.
//
// Pipeline: parse → IR PolicyAttachmentPlan → derive_facts → evaluate_rules
//   → Signal { rule_id }
//
// The rules track the principal-binding lifecycle: enable == ALTER
// USER/ACCOUNT SET AUTHENTICATION POLICY = …; disable == ALTER
// USER/ACCOUNT UNSET AUTHENTICATION POLICY.
//
// Contract checked by `assert_v1_fires` below: the pipeline fires on
// attachment SQL and stays silent on non-attachment SQL.

use lexega_core::api::analyze_policy_attachment_facts;

fn fact_rule_ids(sql: &str) -> Vec<String> {
    let signals = analyze_policy_attachment_facts(sql).expect("fact pipeline succeeds");
    signals.into_iter().map(|s| s.rule_id).collect()
}

// ─────────────────────────────────────────────────────────────────────
// SNW-AUTHPOL-ON firing tests.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn snw_authpol_on_fires_on_alter_user_set() {
    let ids = fact_rule_ids("ALTER USER alice SET AUTHENTICATION POLICY = my_pol;");
    assert!(ids.contains(&"SNW-AUTHPOL-ON".to_string()), "ids={:?}", ids);
}

#[test]
fn snw_authpol_on_fires_on_alter_user_set_with_if_exists() {
    let ids = fact_rule_ids("ALTER USER IF EXISTS alice SET AUTHENTICATION POLICY = my_pol;");
    assert!(ids.contains(&"SNW-AUTHPOL-ON".to_string()), "ids={:?}", ids);
}

#[test]
fn snw_authpol_on_fires_on_alter_user_set_with_qualified_policy() {
    let ids =
        fact_rule_ids("ALTER USER alice SET AUTHENTICATION POLICY = sec.policies.strict_pol;");
    assert!(ids.contains(&"SNW-AUTHPOL-ON".to_string()), "ids={:?}", ids);
}

#[test]
fn snw_authpol_on_fires_on_alter_account_set() {
    let ids = fact_rule_ids("ALTER ACCOUNT SET AUTHENTICATION POLICY = acct_pol;");
    assert!(ids.contains(&"SNW-AUTHPOL-ON".to_string()), "ids={:?}", ids);
}

// Canonical Snowflake attach syntax has no `=` between POLICY and the name.
// The attach parse must accept this form rather than skip the statement.

#[test]
fn snw_authpol_on_fires_on_alter_user_set_without_eq() {
    let ids = fact_rule_ids("ALTER USER alice SET AUTHENTICATION POLICY my_pol;");
    assert!(ids.contains(&"SNW-AUTHPOL-ON".to_string()), "ids={:?}", ids);
}

#[test]
fn snw_authpol_on_fires_on_alter_account_set_without_eq() {
    let ids = fact_rule_ids("ALTER ACCOUNT SET AUTHENTICATION POLICY acct_pol;");
    assert!(ids.contains(&"SNW-AUTHPOL-ON".to_string()), "ids={:?}", ids);
}

#[test]
fn snw_authpol_on_silent_on_alter_user_unset() {
    let ids = fact_rule_ids("ALTER USER alice UNSET AUTHENTICATION POLICY;");
    assert!(
        !ids.contains(&"SNW-AUTHPOL-ON".to_string()),
        "ids={:?}",
        ids
    );
}

#[test]
fn snw_authpol_on_silent_on_unrelated_alter_user() {
    // ALTER USER … SET DEFAULT_ROLE falls through to AlterPrincipal —
    // no policy-attachment statement is produced.
    let ids = fact_rule_ids("ALTER USER alice SET DEFAULT_ROLE = analyst;");
    assert!(
        !ids.contains(&"SNW-AUTHPOL-ON".to_string()),
        "ids={:?}",
        ids
    );
}

// ─────────────────────────────────────────────────────────────────────
// SNW-AUTHPOL-OFF firing tests.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn snw_authpol_off_fires_on_alter_user_unset() {
    let ids = fact_rule_ids("ALTER USER alice UNSET AUTHENTICATION POLICY;");
    assert!(
        ids.contains(&"SNW-AUTHPOL-OFF".to_string()),
        "ids={:?}",
        ids
    );
}

#[test]
fn snw_authpol_off_fires_on_alter_user_unset_with_if_exists() {
    let ids = fact_rule_ids("ALTER USER IF EXISTS alice UNSET AUTHENTICATION POLICY;");
    assert!(
        ids.contains(&"SNW-AUTHPOL-OFF".to_string()),
        "ids={:?}",
        ids
    );
}

#[test]
fn snw_authpol_off_fires_on_alter_account_unset() {
    let ids = fact_rule_ids("ALTER ACCOUNT UNSET AUTHENTICATION POLICY;");
    assert!(
        ids.contains(&"SNW-AUTHPOL-OFF".to_string()),
        "ids={:?}",
        ids
    );
}

#[test]
fn snw_authpol_off_silent_on_alter_user_set() {
    let ids = fact_rule_ids("ALTER USER alice SET AUTHENTICATION POLICY = my_pol;");
    assert!(
        !ids.contains(&"SNW-AUTHPOL-OFF".to_string()),
        "ids={:?}",
        ids
    );
}

#[test]
fn snw_authpol_off_silent_on_alter_user_unrelated() {
    let ids = fact_rule_ids("ALTER USER alice SET DEFAULT_ROLE = analyst;");
    assert!(
        !ids.contains(&"SNW-AUTHPOL-OFF".to_string()),
        "ids={:?}",
        ids
    );
}

// ─────────────────────────────────────────────────────────────────────
// Pipeline scope.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn pipeline_skips_non_attachment_statements() {
    let signals = analyze_policy_attachment_facts("SELECT 1;").expect("parses");
    assert!(signals.is_empty(), "got {:?}", signals);
}

#[test]
fn pipeline_skips_alter_authentication_policy_definition() {
    // Modifying the policy definition itself is unrelated to attachment.
    let sql = "ALTER AUTHENTICATION POLICY my_pol SET MFA_ENROLLMENT = REQUIRED;";
    let ids = fact_rule_ids(sql);
    assert!(
        !ids.contains(&"SNW-AUTHPOL-ON".to_string())
            && !ids.contains(&"SNW-AUTHPOL-OFF".to_string()),
        "ids={:?}",
        ids
    );
}

#[test]
fn multi_statement_collects_per_attachment() {
    let sql = "
        ALTER USER alice SET AUTHENTICATION POLICY = my_pol;
        ALTER ACCOUNT UNSET AUTHENTICATION POLICY;
        SELECT 1;
    ";
    let ids = fact_rule_ids(sql);
    assert!(ids.contains(&"SNW-AUTHPOL-ON".to_string()), "ids={:?}", ids);
    assert!(
        ids.contains(&"SNW-AUTHPOL-OFF".to_string()),
        "ids={:?}",
        ids
    );
}

#[test]
fn signal_carries_source_span_for_attachment() {
    let signals =
        analyze_policy_attachment_facts("ALTER USER alice SET AUTHENTICATION POLICY = my_pol;")
            .expect("parses");
    let on = signals
        .iter()
        .find(|s| s.rule_id == "SNW-AUTHPOL-ON")
        .expect("SNW-AUTHPOL-ON emitted");
    let span = on
        .source_span
        .as_ref()
        .expect("source_span populated by rule engine");
    assert!(span.start < span.end);
}

// ─────────────────────────────────────────────────────────────────────
// v1 firing contract.
//
// SNW-AUTHPOL-ON / OFF route through the typed AUTHPOL-attachment
// substrate: the pipeline fires on attachment SQL and stays silent
// otherwise.
// ─────────────────────────────────────────────────────────────────────

fn assert_v1_fires(sql: &str, rule_id: &str, expect_v1_fires: bool) {
    // Asserts the v1 fact pipeline's firing semantics.
    let fact_ids = fact_rule_ids(sql);
    let fact_has = fact_ids.contains(&rule_id.to_string());
    if expect_v1_fires {
        assert!(
            fact_has,
            "{}: v1 fact pipeline should fire on {:?}; fact ids={:?}",
            rule_id, sql, fact_ids
        );
    } else {
        assert!(
            !fact_has,
            "{}: v1 fact pipeline should stay silent on {:?}; fact ids={:?}",
            rule_id, sql, fact_ids
        );
    }
}

#[test]
fn parity_snw_authpol_on() {
    assert_v1_fires(
        "ALTER USER alice SET AUTHENTICATION POLICY = my_pol;",
        "SNW-AUTHPOL-ON",
        true,
    );
    assert_v1_fires(
        "ALTER ACCOUNT SET AUTHENTICATION POLICY = acct_pol;",
        "SNW-AUTHPOL-ON",
        true,
    );
    assert_v1_fires(
        "ALTER USER alice UNSET AUTHENTICATION POLICY;",
        "SNW-AUTHPOL-ON",
        false,
    );
}

#[test]
fn parity_snw_authpol_off() {
    assert_v1_fires(
        "ALTER USER alice UNSET AUTHENTICATION POLICY;",
        "SNW-AUTHPOL-OFF",
        true,
    );
    assert_v1_fires(
        "ALTER ACCOUNT UNSET AUTHENTICATION POLICY;",
        "SNW-AUTHPOL-OFF",
        true,
    );
    assert_v1_fires(
        "ALTER USER alice SET AUTHENTICATION POLICY = my_pol;",
        "SNW-AUTHPOL-OFF",
        false,
    );
}
