// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Secret-redaction invariant: a credential value (password, credential key,
//! secret string) must never appear in any source-quoting output surface
//! (finding preview / evidence / serialized report). The facts layer is
//! least-leak; this verifies the evidence layer honors the same rule.

use lexega_core::analyzer::RuleMatch;
use lexega_core::api::analyze_risk;
use lexega_core::redact_secrets_for_display;
use std::collections::HashSet;

/// Serialize the full analysis report — this is the shape that gets written to
/// JSON / SARIF / dashboards, so a secret here is a real leak.
fn report_json(sql: &str) -> String {
    let report = analyze_risk(sql).expect("should analyze");
    serde_json::to_string(&report).expect("report serializes")
}

fn rule_ids(sql: &str) -> HashSet<String> {
    analyze_risk(sql)
        .expect("should analyze")
        .signals
        .iter()
        .filter_map(|s| match s {
            RuleMatch::Analysis(g) => Some(g.matched_rule.clone()),
        })
        .collect()
}

#[test]
fn test_user_password_redacted() {
    let json = report_json("CREATE USER bob PASSWORD = 'hunter2_topsecret';");
    assert!(
        !json.contains("hunter2_topsecret"),
        "password leaked into report"
    );
}

#[test]
fn test_secret_object_password_redacted() {
    let json = report_json(
        "CREATE SECRET s TYPE = PASSWORD USERNAME = 'u' PASSWORD = 'sneaky_secret_val';",
    );
    assert!(
        !json.contains("sneaky_secret_val"),
        "secret leaked into report"
    );
}

#[test]
fn test_managed_account_admin_password_redacted() {
    let json = report_json(
        "CREATE MANAGED ACCOUNT ra ADMIN_NAME = u ADMIN_PASSWORD = 'manacct_secret_x' TYPE = READER;",
    );
    assert!(!json.contains("manacct_secret_x"), "admin password leaked");
}

#[test]
fn test_create_account_admin_password_redacted() {
    let json = report_json(
        "CREATE ACCOUNT acc ADMIN_NAME = u ADMIN_PASSWORD = 'orgacct_secret_y' EDITION = STANDARD;",
    );
    assert!(!json.contains("orgacct_secret_y"), "admin password leaked");
}

#[test]
fn test_stage_credentials_redacted() {
    let json = report_json(
        "ALTER STAGE st SET CREDENTIALS = (AWS_KEY_ID = 'AKIA1' AWS_SECRET_KEY = 'stagecred_secret_z');",
    );
    assert!(
        !json.contains("stagecred_secret_z"),
        "stage credential leaked"
    );
}

#[test]
fn test_redaction_is_targeted_not_blanket() {
    // The secret is masked, but a non-credential value on the same statement
    // (TYPE = READER) stays visible — redaction is targeted recognition, not a
    // blanket wipe.
    // TYPE first so it is within the 80-char preview window (the masked
    // password trails it).
    let json =
        report_json("CREATE MANAGED ACCOUNT ra TYPE = READER ADMIN_PASSWORD = 'secret_pw_neg';");
    assert!(!json.contains("secret_pw_neg"), "secret must be masked");
    assert!(json.contains("READER"), "non-secret TYPE must stay visible");
}

#[test]
fn test_redaction_does_not_suppress_findings() {
    // Masking the value must not change which rules fire — the hardcoded
    // password is still detected, just not reproduced.
    let rules = rule_ids("CREATE USER bob PASSWORD = 'hunter2_topsecret';");
    assert!(
        rules.contains("CRED-PWD-LEAK"),
        "the hardcoded-password finding must still fire, got {rules:?}"
    );
}

#[test]
fn test_redact_helper_offset_preserving() {
    let sql = "CREATE USER bob PASSWORD = 'pw12345';";
    let redacted = redact_secrets_for_display(sql);
    assert_eq!(
        redacted.len(),
        sql.len(),
        "redaction must preserve byte length (offsets)"
    );
    assert!(!redacted.contains("pw12345"), "secret masked");
    assert!(
        redacted.contains("CREATE USER bob PASSWORD"),
        "non-secret structure intact: {redacted}"
    );
}

#[test]
fn test_redact_helper_no_secret_is_identity() {
    let sql = "SELECT a, b FROM t WHERE c = 1;";
    assert_eq!(redact_secrets_for_display(sql), sql);
}

#[test]
fn test_redaction_survives_jinja_rendering() {
    // Jinja ahead of the credential collapses on render (24 bytes here).
    // Redaction spans, the line index, and previews are all computed against
    // the rendered text the parser saw — so the output surface must quote
    // that same rendered text. Handing the pre-render source to the core
    // would shift the mask off the secret, leak Jinja text into previews,
    // and misreport line numbers.
    let json = report_json(
        "SELECT {% if true %}1{% endif %} FROM t;\nCREATE USER bob PASSWORD = 'jinja_secret_pw1';",
    );
    assert!(
        !json.contains("jinja_secret_pw1"),
        "password leaked into report for Jinja-bearing source"
    );

    let report: serde_json::Value = serde_json::from_str(&json).expect("report parses");
    let cred_signal = report["signals"]
        .as_array()
        .expect("signals array")
        .iter()
        .find(|s| s["matched_rule"] == "CRED-PWD-LEAK")
        .expect("hardcoded-password finding fires");
    let evidence = &cred_signal["evidence"][0];
    assert_eq!(
        evidence["line_number"], 2,
        "CREATE USER is on line 2 of the rendered SQL"
    );
    let preview = evidence["statement_preview"]
        .as_str()
        .expect("preview present");
    assert!(
        !preview.contains("{%"),
        "Jinja source text leaked into a rendered-space preview: {preview}"
    );
}
