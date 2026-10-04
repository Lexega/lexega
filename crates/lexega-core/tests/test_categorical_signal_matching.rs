// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

// Signal matching — end-to-end SQL tests verifying that statement-level
// security/governance signals fire (or don't) for the expected rule IDs.

use lexega_core::api::analyze_risk;

fn rule_ids(sql: &str) -> Vec<String> {
    let report = analyze_risk(sql).expect("analyze_risk");
    report
        .signals
        .iter()
        .filter_map(|s| s.rule_id().map(String::from))
        .collect()
}

// Security:Encryption:Disabled — SNW-STG-ENC-OFF must fire.
#[test]
fn test_encryption_disabled_fires() {
    let sql = "ALTER STAGE my_stage SET ENCRYPTION = (TYPE = 'NONE');";
    let fired = rule_ids(sql);
    assert!(
        fired.contains(&"SNW-STG-ENC-OFF".to_string()),
        "SNW-STG-ENC-OFF must fire for ENCRYPTION NONE. Got: {:?}",
        fired
    );
    assert!(
        !fired.contains(&"SNW-STG-ENC-ON".to_string()),
        "SNW-STG-ENC-ON must NOT fire when encryption is disabled. Got: {:?}",
        fired
    );
}

// Security:Encryption:Enabled — SNW-STG-ENC-ON must fire, OFF must not.
#[test]
fn test_encryption_enabled_fires() {
    let sql = "ALTER STAGE my_stage SET ENCRYPTION = (TYPE = 'AWS_SSE_KMS' KMS_KEY_ID = 'my-key');";
    let fired = rule_ids(sql);
    assert!(
        fired.contains(&"SNW-STG-ENC-ON".to_string()),
        "SNW-STG-ENC-ON must fire when KMS encryption is set. Got: {:?}",
        fired
    );
    assert!(
        !fired.contains(&"SNW-STG-ENC-OFF".to_string()),
        "SNW-STG-ENC-OFF must NOT fire when encryption is enabled. Got: {:?}",
        fired
    );
}

// Security:Credentials:Changed — SNW-STG-CRED-CHG must fire on credential update.
#[test]
fn test_credential_change_fires() {
    let sql = r#"
        ALTER STAGE my_stage
        SET CREDENTIALS = (AWS_KEY_ID = 'AKIAIOSFODNN7EXAMPLE'
                           AWS_SECRET_KEY = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY');
    "#;
    let fired = rule_ids(sql);
    assert!(
        fired.contains(&"SNW-STG-CRED-CHG".to_string()),
        "SNW-STG-CRED-CHG must fire when credentials are updated. Got: {:?}",
        fired
    );
}

// Wildcard: any encryption-surface signal fires for both enc-on and enc-off SQL,
// but not for unrelated statements (e.g. a SELECT).
#[test]
fn test_encryption_surface_not_on_unrelated_stmt() {
    let sql = "SELECT id, name FROM users WHERE id = 1;";
    let fired = rule_ids(sql);
    assert!(
        !fired.contains(&"SNW-STG-ENC-OFF".to_string()),
        "SNW-STG-ENC-OFF must NOT fire on a plain SELECT. Got: {:?}",
        fired
    );
    assert!(
        !fired.contains(&"SNW-STG-ENC-ON".to_string()),
        "SNW-STG-ENC-ON must NOT fire on a plain SELECT. Got: {:?}",
        fired
    );
}

// Cross-category: a GRANT fires governance/privilege rules, not encryption rules.
#[test]
fn test_governance_signal_not_encryption() {
    let sql = "GRANT ALL PRIVILEGES ON DATABASE prod TO ROLE PUBLIC;";
    let fired = rule_ids(sql);
    let has_governance = fired
        .iter()
        .any(|r| r.starts_with("GRT-") || r.starts_with("SNW-GRT-"));
    assert!(
        has_governance,
        "GRANT to PUBLIC must fire a governance rule. Got: {:?}",
        fired
    );
    assert!(
        !fired.contains(&"SNW-STG-ENC-OFF".to_string()),
        "Encryption rule must NOT fire on a GRANT statement. Got: {:?}",
        fired
    );
}
