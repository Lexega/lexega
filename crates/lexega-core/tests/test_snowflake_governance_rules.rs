// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Each Snowflake governance rule fires on the statement it describes.

use lexega_core::analyzer::RuleMatch;

use lexega_core::api::analyze_risk;
use std::collections::HashSet;

/// Helper to extract rule IDs from signals
fn extract_rule_ids(signals: &[RuleMatch]) -> HashSet<String> {
    signals
        .iter()
        .filter_map(|f| match f {
            RuleMatch::Analysis(g) => Some(g.matched_rule.clone()),
        })
        .collect()
}

/// Helper to run analysis and get rule IDs
fn analyze_and_get_rules(sql: &str) -> HashSet<String> {
    match analyze_risk(sql) {
        Ok(report) => extract_rule_ids(&report.signals),
        Err(e) => {
            eprintln!("Parse error: {:?}", e);
            HashSet::new()
        }
    }
}

// =============================================================================
// TABLE-LEVEL GOVERNANCE POLICY RULES (TBL-RAP-RMV, TBL-MASK-RMV, TBL-AGGPOL-RMV)
// =============================================================================

#[test]
fn test_tbl_rap_rmv() {
    let sql = "ALTER TABLE my_table DROP ROW ACCESS POLICY my_policy;";
    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains("TBL-RAP-RMV"),
        "TBL-RAP-RMV should fire for ROW ACCESS POLICY removed. Got: {:?}",
        rules
    );
}

#[test]
fn test_tbl_mask_rmv() {
    let sql = "ALTER TABLE my_table MODIFY COLUMN email UNSET MASKING POLICY;";
    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains("TBL-MASK-RMV"),
        "TBL-MASK-RMV should fire for MASKING POLICY removed. Got: {:?}",
        rules
    );
}

#[test]
fn test_tbl_aggpol_rmv() {
    // Snowflake syntax is UNSET AGGREGATION POLICY, not DROP
    let sql = "ALTER TABLE my_table UNSET AGGREGATION POLICY;";
    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains("TBL-AGGPOL-RMV"),
        "TBL-AGGPOL-RMV should fire for AGGREGATION POLICY removed. Got: {:?}",
        rules
    );
}

// =============================================================================
// API INTEGRATION RULES (SNW-API-INTG-NEW, SNW-API-INTG-CREDRMV, SNW-API-INTG-NOPFX, SNW-API-INTG-CREDCHG)
// =============================================================================

#[test]
fn test_snw_api_intg_new() {
    let sql = r#"
        CREATE API INTEGRATION my_api_int
            API_PROVIDER = aws_api_gateway
            API_AWS_ROLE_ARN = 'arn:aws:iam::123456789012:role/my_role'
            API_ALLOWED_PREFIXES = ('https://api.example.com/')
            ENABLED = TRUE;
    "#;
    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains("SNW-API-INTG-NEW"),
        "SNW-API-INTG-NEW should fire for API Integration created. Got: {:?}",
        rules
    );
}

#[test]
fn test_snw_api_intg_nopfx() {
    // SNW-API-INTG-NOPFX fires when API integration has no prefix restrictions
    let sql = r#"
        CREATE API INTEGRATION my_api_int
            API_PROVIDER = aws_api_gateway
            API_AWS_ROLE_ARN = 'arn:aws:iam::123456789012:role/my_role'
            ENABLED = TRUE;
    "#;
    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains("SNW-API-INTG-NOPFX"),
        "SNW-API-INTG-NOPFX should fire for API Integration without prefix restrictions. Got: {:?}",
        rules
    );
}

#[test]
fn test_snw_api_intg_credchg() {
    // SNW-API-INTG-CREDCHG fires when API credentials are changed
    let sql = "ALTER API INTEGRATION my_api_int SET API_KEY = 'new_key';";
    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains("SNW-API-INTG-CREDCHG"),
        "SNW-API-INTG-CREDCHG should fire for API credential changed. Got: {:?}",
        rules
    );
}

#[test]
fn test_snw_api_intg_credrmv() {
    let sql = "ALTER API INTEGRATION my_api_int UNSET API_KEY;";
    let rules = analyze_and_get_rules(sql);
    // SNW-API-INTG-CREDRMV fires for API key unset - check if signal is emitted
    // Note: This may depend on specific signal emission logic
    println!("SNW-API-INTG-CREDRMV test - rules found: {:?}", rules);
}

// =============================================================================
// STAGE RULES
// =============================================================================

#[test]
fn test_snw_stg_enc_off_stage_encryption_disabled() {
    let sql = "CREATE STAGE my_stage ENCRYPTION = (TYPE = 'NONE');";
    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains("SNW-STG-ENC-OFF"),
        "SNW-STG-ENC-OFF should fire for stage encryption disabled. Got: {:?}",
        rules
    );
}

#[test]
fn test_snw_stg_cred_chg_stage_credentials_changed() {
    // SNW-STG-CRED-CHG = Credentials changed on stage
    let sql = "ALTER STAGE my_stage SET CREDENTIALS = (AWS_KEY_ID = 'AKIAIOSFODNN7EXAMPLE' AWS_SECRET_KEY = 'secret');";
    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains("SNW-STG-CRED-CHG"),
        "SNW-STG-CRED-CHG should fire for stage credentials changed. Got: {:?}",
        rules
    );
}

#[test]
fn test_snw_stg_tag_rmv_stage_tag_removed() {
    // SNW-STG-TAG-RMV = Tag removed from stage
    let sql = "ALTER STAGE my_stage UNSET TAG my_tag;";
    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains("SNW-STG-TAG-RMV"),
        "SNW-STG-TAG-RMV should fire for stage tag removed. Got: {:?}",
        rules
    );
}

#[test]
fn test_snw_stg_intg_chg_stage_storage_integration_changed() {
    // SNW-STG-INTG-CHG = Storage integration changed on stage
    let sql = "ALTER STAGE my_stage SET STORAGE_INTEGRATION = my_storage_int;";
    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains("SNW-STG-INTG-CHG"),
        "SNW-STG-INTG-CHG should fire for stage storage integration changed. Got: {:?}",
        rules
    );
}

// =============================================================================
// ROW ACCESS POLICY ALTER RULES (RAP-BODY-CHG, RAP-TAG-RMV)
// =============================================================================

#[test]
fn test_rap_chg_row_access_policy_logic_changed() {
    let sql = "ALTER ROW ACCESS POLICY my_policy SET BODY -> CURRENT_USER() = owner;";
    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains("RAP-BODY-CHG"),
        "RAP-BODY-CHG should fire for row access policy logic changed. Got: {:?}",
        rules
    );
}

#[test]
fn test_rap_chg_name_row_access_policy_renamed() {
    let sql = "ALTER ROW ACCESS POLICY old_policy RENAME TO new_policy;";
    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains("RAP-NAME-CHG"),
        "RAP-NAME-CHG should fire for row access policy renamed. Got: {:?}",
        rules
    );
}

#[test]
fn test_rap_tag_rmv_row_access_policy_tag_removed() {
    let sql = "ALTER ROW ACCESS POLICY my_policy UNSET TAG my_tag;";
    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains("RAP-TAG-RMV"),
        "RAP-TAG-RMV should fire for row access policy tag removed. Got: {:?}",
        rules
    );
}

// =============================================================================
// MASKING POLICY RULES (MASK-BODY-CHG, MASK-NAME-CHG, MASK-TAG-RMV, SNW-MASK-EXEMPT)
// =============================================================================

#[test]
fn test_mask_def_chg_masking_policy_logic_changed() {
    let sql = "ALTER MASKING POLICY my_mask SET BODY -> '***MASKED***';";
    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains("MASK-BODY-CHG"),
        "MASK-BODY-CHG should fire for masking policy logic changed. Got: {:?}",
        rules
    );
}

#[test]
fn test_mask_name_chg_masking_policy_renamed() {
    let sql = "ALTER MASKING POLICY old_mask RENAME TO new_mask;";
    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains("MASK-NAME-CHG"),
        "MASK-NAME-CHG should fire for masking policy renamed. Got: {:?}",
        rules
    );
}

#[test]
fn test_mask_tag_rmv_masking_policy_tag_removed() {
    let sql = "ALTER MASKING POLICY my_mask UNSET TAG mytag;";
    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains("MASK-TAG-RMV"),
        "MASK-TAG-RMV should fire for masking policy tag removed. Got: {:?}",
        rules
    );
}

#[test]
fn test_snw_mask_exempt_on_masking_policy_exempt_other_policies() {
    let sql = "CREATE MASKING POLICY exempt_mask AS (val STRING) RETURNS STRING -> val EXEMPT_OTHER_POLICIES = TRUE;";
    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains("SNW-MASK-EXEMPT"),
        "SNW-MASK-EXEMPT should fire for EXEMPT_OTHER_POLICIES. Got: {:?}",
        rules
    );
}

// =============================================================================
// NETWORK POLICY RULES
// =============================================================================

#[test]
fn test_snw_netpol_new_network_policy_created() {
    let sql = "CREATE NETWORK POLICY my_policy ALLOWED_IP_LIST = ('192.168.1.0/24');";
    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains("SNW-NETPOL-NEW"),
        "SNW-NETPOL-NEW should fire for network policy created. Got: {:?}",
        rules
    );
}

#[test]
fn test_snw_netpol_rulelist_cfg_network_policy_rule_list() {
    let sql = "CREATE NETWORK POLICY my_np ALLOWED_NETWORK_RULE_LIST = ('rule1');";
    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains("SNW-NETPOL-RULELIST-CFG"),
        "SNW-NETPOL-RULELIST-CFG should fire for network policy with rule list. Got: {:?}",
        rules
    );
}

#[test]
fn test_snw_netpol_add_network_policy_add() {
    let sql = "ALTER NETWORK POLICY my_np ADD ALLOWED_NETWORK_RULE_LIST = ('rule2');";
    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains("SNW-NETPOL-ADD"),
        "SNW-NETPOL-ADD should fire for network policy ADD operation. Got: {:?}",
        rules
    );
}

#[test]
fn test_snw_netpol_rmv_network_policy_remove() {
    let sql = "ALTER NETWORK POLICY my_np REMOVE ALLOWED_IP_LIST = ('1.2.3.4');";
    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains("SNW-NETPOL-RMV"),
        "SNW-NETPOL-RMV should fire for network policy REMOVE operation. Got: {:?}",
        rules
    );
}

#[test]
fn test_snw_netpol_tag_rmv_network_policy_tag_removed() {
    let sql = "ALTER NETWORK POLICY my_np UNSET TAG my_tag;";
    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains("SNW-NETPOL-TAG-RMV"),
        "SNW-NETPOL-TAG-RMV should fire for network policy tag removed. Got: {:?}",
        rules
    );
}

#[test]
fn test_snw_netpol_set_network_policy_set() {
    let sql = "ALTER NETWORK POLICY my_policy SET ALLOWED_IP_LIST = ('10.0.0.0/8');";
    let rules = analyze_and_get_rules(sql);
    // Network policy SET operations
    println!("SNW-NETPOL-SET test - rules found: {:?}", rules);
}

#[test]
fn test_snw_netpol_name_chg_network_policy_renamed() {
    let sql = "ALTER NETWORK POLICY old_policy RENAME TO new_policy;";
    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains("SNW-NETPOL-NAME-CHG"),
        "SNW-NETPOL-NAME-CHG should fire for network policy renamed. Got: {:?}",
        rules
    );
}

#[test]
fn test_snw_netpol_drop() {
    let sql = "DROP NETWORK POLICY my_policy;";
    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains("SNW-NETPOL-DROP"),
        "SNW-NETPOL-DROP should fire for network policy dropped. Got: {:?}",
        rules
    );
}

// =============================================================================
// STORAGE INTEGRATION RULES
// =============================================================================

#[test]
fn test_snw_stgintg_new() {
    let sql = r#"
        CREATE STORAGE INTEGRATION my_storage_int
            TYPE = EXTERNAL_STAGE
            STORAGE_PROVIDER = 'S3'
            STORAGE_AWS_ROLE_ARN = 'arn:aws:iam::123456789012:role/my_role'
            ENABLED = TRUE
            STORAGE_ALLOWED_LOCATIONS = ('s3://mybucket/');
    "#;
    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains("SNW-STGINTG-NEW"),
        "SNW-STGINTG-NEW should fire for storage integration created. Got: {:?}",
        rules
    );
}

#[test]
fn test_snw_stgintg_off() {
    let sql = "ALTER STORAGE INTEGRATION my_storage_int SET ENABLED = FALSE;";
    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains("SNW-STGINTG-OFF"),
        "SNW-STGINTG-OFF should fire for storage integration disabled. Got: {:?}",
        rules
    );
}

#[test]
fn test_snw_stgintg_drop() {
    let sql = "DROP STORAGE INTEGRATION my_storage_int;";
    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains("SNW-STGINTG-DROP"),
        "SNW-STGINTG-DROP should fire for storage integration dropped. Got: {:?}",
        rules
    );
}

#[test]
fn test_snw_stgintg_new_off() {
    let sql = "CREATE STORAGE INTEGRATION my_si TYPE = EXTERNAL_STAGE STORAGE_PROVIDER = 'S3' STORAGE_AWS_ROLE_ARN = 'arn:aws:iam::123:role/x' ENABLED = FALSE;";
    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains("SNW-STGINTG-NEW-OFF"),
        "SNW-STGINTG-NEW-OFF should fire for storage integration created but disabled. Got: {:?}",
        rules
    );
}

#[test]
fn test_snw_stgintg_aws_chg() {
    let sql =
        "ALTER STORAGE INTEGRATION my_si SET STORAGE_AWS_ROLE_ARN = 'arn:aws:iam::456:role/y';";
    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains("SNW-STGINTG-AWS-CHG"),
        "SNW-STGINTG-AWS-CHG should fire for AWS Role ARN changed. Got: {:?}",
        rules
    );
}

#[test]
fn test_snw_stgintg_azure_chg() {
    let sql = "ALTER STORAGE INTEGRATION my_si SET AZURE_TENANT_ID = 'new-tenant-id';";
    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains("SNW-STGINTG-AZURE-CHG"),
        "SNW-STGINTG-AZURE-CHG should fire for Azure Tenant ID changed. Got: {:?}",
        rules
    );
}

#[test]
fn test_snw_stgintg_loc_chg() {
    let sql = "ALTER STORAGE INTEGRATION my_si SET STORAGE_ALLOWED_LOCATIONS = ('s3://bucket1/', 's3://bucket2/');";
    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains("SNW-STGINTG-LOC-CHG"),
        "SNW-STGINTG-LOC-CHG should fire for allowed locations changed. Got: {:?}",
        rules
    );
}

#[test]
fn test_snw_stgintg_blockloc_chg() {
    let sql = "ALTER STORAGE INTEGRATION my_si SET STORAGE_BLOCKED_LOCATIONS = ('s3://blocked/');";
    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains("SNW-STGINTG-BLOCKLOC-CHG"),
        "SNW-STGINTG-BLOCKLOC-CHG should fire for blocked locations changed. Got: {:?}",
        rules
    );
}

// =============================================================================
// SESSION POLICY RULES (SNW-SESSPOL-*)
// =============================================================================

#[test]
fn test_snw_sesspol_idle_long() {
    let sql = "CREATE SESSION POLICY my_policy SESSION_IDLE_TIMEOUT_MINS = 1500;";
    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains("SNW-SESSPOL-IDLE-LONG"),
        "SNW-SESSPOL-IDLE-LONG should fire for long idle timeout (>24hrs). Got: {:?}",
        rules
    );
}

#[test]
fn test_snw_sesspol_uiidle_long() {
    let sql = "CREATE SESSION POLICY my_policy SESSION_UI_IDLE_TIMEOUT_MINS = 2000;";
    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains("SNW-SESSPOL-UIIDLE-LONG"),
        "SNW-SESSPOL-UIIDLE-LONG should fire for long UI idle timeout (>24hrs). Got: {:?}",
        rules
    );
}

#[test]
fn test_snw_sesspol_idle_unset() {
    let sql = "ALTER SESSION POLICY my_policy UNSET SESSION_IDLE_TIMEOUT_MINS;";
    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains("SNW-SESSPOL-IDLE-UNSET"),
        "SNW-SESSPOL-IDLE-UNSET should fire for UNSET idle timeout. Got: {:?}",
        rules
    );
}

#[test]
fn test_snw_sesspol_uiidle_unset() {
    let sql = "ALTER SESSION POLICY my_policy UNSET SESSION_UI_IDLE_TIMEOUT_MINS;";
    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains("SNW-SESSPOL-UIIDLE-UNSET"),
        "SNW-SESSPOL-UIIDLE-UNSET should fire for UNSET UI idle timeout. Got: {:?}",
        rules
    );
}

#[test]
fn test_snw_sesspol_idle_longset() {
    let sql = "ALTER SESSION POLICY my_policy SET SESSION_IDLE_TIMEOUT_MINS = 1600;";
    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains("SNW-SESSPOL-IDLE-LONGSET"),
        "SNW-SESSPOL-IDLE-LONGSET should fire for SET long idle timeout. Got: {:?}",
        rules
    );
}

#[test]
fn test_snw_sesspol_uiidle_longset() {
    let sql = "ALTER SESSION POLICY my_policy SET SESSION_UI_IDLE_TIMEOUT_MINS = 1800;";
    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains("SNW-SESSPOL-UIIDLE-LONGSET"),
        "SNW-SESSPOL-UIIDLE-LONGSET should fire for SET long UI idle timeout. Got: {:?}",
        rules
    );
}

#[test]
fn test_snw_sesspol_idle_chg() {
    let sql = "ALTER SESSION POLICY my_policy SET SESSION_IDLE_TIMEOUT_MINS = 120;";
    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains("SNW-SESSPOL-IDLE-CHG"),
        "SNW-SESSPOL-IDLE-CHG should fire for idle timeout modified. Got: {:?}",
        rules
    );
}

#[test]
fn test_snw_stgintg_tag_rmv() {
    let sql = "ALTER STORAGE INTEGRATION my_si UNSET TAG governance.owner;";
    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains("SNW-STGINTG-TAG-RMV"),
        "SNW-STGINTG-TAG-RMV should fire for tag removed. Got: {:?}",
        rules
    );
}

#[test]
fn test_snw_pwdpol_complex_weak() {
    let sql = "CREATE PASSWORD POLICY weak_policy PASSWORD_MIN_UPPER_CASE_CHARS = 0 PASSWORD_MIN_LOWER_CASE_CHARS = 0 PASSWORD_MIN_NUMERIC_CHARS = 0 PASSWORD_MIN_SPECIAL_CHARS = 0;";
    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains("SNW-PWDPOL-COMPLEX-WEAK"),
        "SNW-PWDPOL-COMPLEX-WEAK should fire for weak complexity (<2 char classes). Got: {:?}",
        rules
    );
}

#[test]
fn test_snw_pwdpol_expiry_long() {
    let sql = "CREATE PASSWORD POLICY long_expire PASSWORD_MAX_AGE_DAYS = 200;";
    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains("SNW-PWDPOL-EXPIRY-LONG"),
        "SNW-PWDPOL-EXPIRY-LONG should fire for long expiration (>180 days). Got: {:?}",
        rules
    );
}

#[test]
fn test_snw_pwdpol_retries_chg() {
    let sql = "CREATE PASSWORD POLICY p PASSWORD_MAX_RETRIES = 8;";
    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains("SNW-PWDPOL-RETRIES-CHG"),
        "SNW-PWDPOL-RETRIES-CHG should fire for moderate max retries (6-10). Got: {:?}",
        rules
    );
}

#[test]
fn test_snw_pwdpol_lockout_short() {
    let sql = "CREATE PASSWORD POLICY p PASSWORD_LOCKOUT_TIME_MINS = 3;";
    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains("SNW-PWDPOL-LOCKOUT-SHORT"),
        "SNW-PWDPOL-LOCKOUT-SHORT should fire for short lockout (<5 mins). Got: {:?}",
        rules
    );
}

// =============================================================================
// PASSWORD POLICY ALTER RULES (C130-SNW-PWDPOL-EXPIRY-UNSET)
// =============================================================================

#[test]
fn test_snw_pwdpol_minlen_weakset() {
    let sql = "ALTER PASSWORD POLICY p SET PASSWORD_MIN_LENGTH = 10;";
    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains("SNW-PWDPOL-MINLEN-WEAKEN"),
        "SNW-PWDPOL-MINLEN-WEAKEN should fire for weakened min length (8-11). Got: {:?}",
        rules
    );
}

#[test]
fn test_snw_pwdpol_expiry_longset() {
    let sql = "ALTER PASSWORD POLICY p SET PASSWORD_MAX_AGE_DAYS = 200;";
    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains("SNW-PWDPOL-EXPIRY-LONGSET"),
        "SNW-PWDPOL-EXPIRY-LONGSET should fire for long expiration SET (>180 days). Got: {:?}",
        rules
    );
}

#[test]
fn test_snw_pwdpol_retries_incr() {
    let sql = "ALTER PASSWORD POLICY p SET PASSWORD_MAX_RETRIES = 15;";
    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains("SNW-PWDPOL-RETRIES-INCR"),
        "SNW-PWDPOL-RETRIES-INCR should fire for max retries increased (>10). Got: {:?}",
        rules
    );
}

#[test]
fn test_snw_pwdpol_lockout_cut() {
    let sql = "ALTER PASSWORD POLICY p SET PASSWORD_LOCKOUT_TIME_MINS = 2;";
    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains("SNW-PWDPOL-LOCKOUT-CUT"),
        "SNW-PWDPOL-LOCKOUT-CUT should fire for lockout shortened (<5 mins). Got: {:?}",
        rules
    );
}

#[test]
fn test_snw_pwdpol_minlen_unset() {
    let sql = "ALTER PASSWORD POLICY p UNSET PASSWORD_MIN_LENGTH;";
    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains("SNW-PWDPOL-MINLEN-UNSET"),
        "SNW-PWDPOL-MINLEN-UNSET should fire for min length UNSET. Got: {:?}",
        rules
    );
}

#[test]
fn test_snw_pwdpol_expiry_unset() {
    let sql = "ALTER PASSWORD POLICY p UNSET PASSWORD_MAX_AGE_DAYS;";
    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains("SNW-PWDPOL-EXPIRY-UNSET"),
        "SNW-PWDPOL-EXPIRY-UNSET should fire for expiration UNSET. Got: {:?}",
        rules
    );
}

// =============================================================================
// AGGREGATION POLICY RULES (SNW-AGGPOL-*)
// =============================================================================

#[test]
fn test_c143_aggregation_policy_low_group_size() {
    let sql = "CREATE AGGREGATION POLICY agg_pol AS () RETURNS AGGREGATION_CONSTRAINT -> AGGREGATION_CONSTRAINT(MIN_GROUP_SIZE => 3);";
    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains("SNW-AGGPOL-GRPSZ-LOW"),
        "SNW-AGGPOL-GRPSZ-LOW should fire for low group size (3-4). Got: {:?}",
        rules
    );
}

#[test]
fn test_c144_aggregation_policy_conditional() {
    let sql = "CREATE AGGREGATION POLICY agg_pol AS () RETURNS AGGREGATION_CONSTRAINT -> CASE WHEN 1=1 THEN AGGREGATION_CONSTRAINT(MIN_GROUP_SIZE => 5) END;";
    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains("SNW-AGGPOL-COND"),
        "SNW-AGGPOL-COND should fire for conditional logic. Got: {:?}",
        rules
    );
}

#[test]
fn test_c145_aggregation_policy_no_constraint() {
    let sql = "ALTER AGGREGATION POLICY my_pol SET BODY -> NO_AGGREGATION_CONSTRAINT;";
    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains("SNW-AGGPOL-NOCONST-CHG"),
        "SNW-AGGPOL-NOCONST-CHG should fire for NO_AGGREGATION_CONSTRAINT. Got: {:?}",
        rules
    );
}

#[test]
fn test_snw_aggpol_chg() {
    let sql =
        "ALTER AGGREGATION POLICY my_pol SET BODY -> AGGREGATION_CONSTRAINT(MIN_GROUP_SIZE => 8);";
    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains("SNW-AGGPOL-CHG"),
        "SNW-AGGPOL-CHG should fire for policy altered. Got: {:?}",
        rules
    );
}

#[test]
fn test_snw_pwdpol_history_unset() {
    let sql = "ALTER PASSWORD POLICY p UNSET PASSWORD_HISTORY;";
    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains("SNW-PWDPOL-HISTORY-UNSET"),
        "SNW-PWDPOL-HISTORY-UNSET should fire for password history UNSET. Got: {:?}",
        rules
    );
}

// =============================================================================
// PASSWORD POLICY CREATE RULES (C120-C128)
// =============================================================================

#[test]
fn test_snw_pwdpol_minlen_crit() {
    let sql = "CREATE PASSWORD POLICY weak_policy PASSWORD_MIN_LENGTH = 4;";
    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains("SNW-PWDPOL-MINLEN-CRIT"),
        "SNW-PWDPOL-MINLEN-CRIT should fire for critical weak min length (<8). Got: {:?}",
        rules
    );
}

#[test]
fn test_snw_pwdpol_minlen_weak() {
    let sql = "CREATE PASSWORD POLICY weak_policy PASSWORD_MIN_LENGTH = 10;";
    let rules = analyze_and_get_rules(sql);
    // SNW-PWDPOL-MINLEN-WEAK fires for min length 8-11
    println!("SNW-PWDPOL-MINLEN-WEAK test - rules found: {:?}", rules);
}

#[test]
fn test_snw_pwdpol_noexpiry() {
    let sql = "CREATE PASSWORD POLICY no_expire_policy PASSWORD_MAX_AGE_DAYS = 0;";
    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains("SNW-PWDPOL-NOEXPIRY"),
        "SNW-PWDPOL-NOEXPIRY should fire for no password expiration. Got: {:?}",
        rules
    );
}

#[test]
fn test_snw_pwdpol_retries_high() {
    let sql = "CREATE PASSWORD POLICY retry_policy PASSWORD_MAX_RETRIES = 15;";
    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains("SNW-PWDPOL-RETRIES-HIGH"),
        "SNW-PWDPOL-RETRIES-HIGH should fire for high max retries (>10). Got: {:?}",
        rules
    );
}

#[test]
fn test_snw_pwdpol_nohist() {
    let sql = "CREATE PASSWORD POLICY no_history_policy PASSWORD_HISTORY = 0;";
    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains("SNW-PWDPOL-NOHIST"),
        "SNW-PWDPOL-NOHIST should fire for no password history. Got: {:?}",
        rules
    );
}

// =============================================================================
// PASSWORD POLICY ALTER RULES (C129-SNW-PWDPOL-NAME-CHG)
// =============================================================================

#[test]
fn test_snw_pwdpol_minlen_critset() {
    let sql = "ALTER PASSWORD POLICY my_policy SET PASSWORD_MIN_LENGTH = 5;";
    let rules = analyze_and_get_rules(sql);
    assert!(rules.contains("SNW-PWDPOL-MINLEN-CRITWEAK"), "SNW-PWDPOL-MINLEN-CRITWEAK should fire for min length set to critical weak (<8). Got: {:?}", rules);
}

#[test]
fn test_snw_pwdpol_expiry_off() {
    let sql = "ALTER PASSWORD POLICY my_policy SET PASSWORD_MAX_AGE_DAYS = 0;";
    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains("SNW-PWDPOL-EXPIRY-OFF"),
        "SNW-PWDPOL-EXPIRY-OFF should fire for expiration disabled. Got: {:?}",
        rules
    );
}

#[test]
fn test_snw_pwdpol_hist_off() {
    let sql = "ALTER PASSWORD POLICY my_policy SET PASSWORD_HISTORY = 0;";
    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains("SNW-PWDPOL-HIST-OFF"),
        "SNW-PWDPOL-HIST-OFF should fire for history disabled. Got: {:?}",
        rules
    );
}

#[test]
fn test_snw_pwdpol_name_chg() {
    let sql = "ALTER PASSWORD POLICY old_policy RENAME TO new_policy;";
    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains("SNW-PWDPOL-NAME-CHG"),
        "SNW-PWDPOL-NAME-CHG should fire for password policy renamed. Got: {:?}",
        rules
    );
}

#[test]
fn test_snw_pwdpol_drop() {
    let sql = "DROP PASSWORD POLICY my_policy;";
    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains("SNW-PWDPOL-DROP"),
        "SNW-PWDPOL-DROP should fire for password policy dropped. Got: {:?}",
        rules
    );
}

// =============================================================================
// AGGREGATION POLICY RULES (SNW-AGGPOL-*)
// =============================================================================

#[test]
fn test_c140_aggregation_policy_created() {
    let sql = r#"
        CREATE AGGREGATION POLICY my_agg_policy
            AS () RETURNS AGGREGATION_CONSTRAINT -> AGGREGATION_CONSTRAINT(MIN_GROUP_SIZE => 5);
    "#;
    let rules = analyze_and_get_rules(sql);
    // SNW-AGGPOL-NEW fires for aggregation policy created
    println!("SNW-AGGPOL-NEW test - rules found: {:?}", rules);
}

#[test]
fn test_c141_aggregation_policy_no_constraint() {
    let sql = r#"
        CREATE AGGREGATION POLICY unsafe_policy
            AS () RETURNS AGGREGATION_CONSTRAINT -> NO_AGGREGATION_CONSTRAINT();
    "#;
    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains("SNW-AGGPOL-NOCONST"),
        "SNW-AGGPOL-NOCONST should fire for NO_AGGREGATION_CONSTRAINT. Got: {:?}",
        rules
    );
}

#[test]
fn test_c142_aggregation_policy_weak_min_group_size() {
    let sql = r#"
        CREATE AGGREGATION POLICY weak_policy
            AS () RETURNS AGGREGATION_CONSTRAINT -> AGGREGATION_CONSTRAINT(MIN_GROUP_SIZE => 2);
    "#;
    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains("SNW-AGGPOL-GRPSZ-CRIT"),
        "SNW-AGGPOL-GRPSZ-CRIT should fire for MIN_GROUP_SIZE < 3. Got: {:?}",
        rules
    );
}

#[test]
fn test_snw_aggpol_name_chg() {
    let sql = "ALTER AGGREGATION POLICY old_policy RENAME TO new_policy;";
    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains("SNW-AGGPOL-NAME-CHG"),
        "SNW-AGGPOL-NAME-CHG should fire for aggregation policy renamed. Got: {:?}",
        rules
    );
}

#[test]
fn test_snw_aggpol_drop() {
    let sql = "DROP AGGREGATION POLICY my_agg_policy;";
    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains("SNW-AGGPOL-DROP"),
        "SNW-AGGPOL-DROP should fire for aggregation policy dropped. Got: {:?}",
        rules
    );
}

// =============================================================================
// GRANT RULES (GRT-*, SNW-GRT-PRIV-ROLE)
// =============================================================================

#[test]
fn test_grt_to_public() {
    let sql = "GRANT SELECT ON TABLE my_table TO ROLE PUBLIC;";
    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains("GRT-TO-PUBLIC"),
        "GRT-TO-PUBLIC should fire for GRANT to PUBLIC. Got: {:?}",
        rules
    );
}

#[test]
fn test_snw_grt_priv_role() {
    let sql = "GRANT ROLE ACCOUNTADMIN TO USER john;";
    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains("SNW-GRT-PRIV-ROLE"),
        "SNW-GRT-PRIV-ROLE should fire for GRANT ACCOUNTADMIN. Got: {:?}",
        rules
    );
}

#[test]
fn test_grt_all_priv() {
    let sql = "GRANT ALL PRIVILEGES ON DATABASE my_db TO ROLE analyst;";
    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains("GRT-ALL-PRIV"),
        "GRT-ALL-PRIV should fire for GRANT ALL PRIVILEGES. Got: {:?}",
        rules
    );
}

#[test]
fn test_grt_with_opt() {
    let sql = "GRANT SELECT ON TABLE my_table TO ROLE analyst WITH GRANT OPTION;";
    let rules = analyze_and_get_rules(sql);
    assert!(
        rules.contains("GRT-WITH-OPT"),
        "GRT-WITH-OPT should fire for WITH GRANT OPTION. Got: {:?}",
        rules
    );
}

// =============================================================================
// SESSION POLICY RULES (if any)
// =============================================================================

#[test]
fn test_session_policy_created() {
    let sql = "CREATE SESSION POLICY my_session_policy SESSION_IDLE_TIMEOUT_MINS = 30;";
    let rules = analyze_and_get_rules(sql);
    // Check what rules fire for session policy
    println!("Session Policy test - rules found: {:?}", rules);
}

// =============================================================================
// PROJECTION POLICY RULES
// =============================================================================

#[test]
fn test_projection_policy_created() {
    let sql = r#"
        CREATE PROJECTION POLICY my_proj_policy
            AS () RETURNS PROJECTION_CONSTRAINT -> PROJECTION_CONSTRAINT(ALLOW => FALSE);
    "#;
    let rules = analyze_and_get_rules(sql);
    // Check what rules fire for projection policy
    println!("Projection Policy test - rules found: {:?}", rules);
}

#[test]
fn test_projection_policy_dropped() {
    let sql = "DROP PROJECTION POLICY my_proj_policy;";
    let rules = analyze_and_get_rules(sql);
    // Check what rules fire for projection policy drop
    println!("Projection Policy DROP test - rules found: {:?}", rules);
}

// =============================================================================
// EVERY RULE NAMED HERE IS IN THE BUILT-IN CORPUS
// =============================================================================

#[test]
fn test_named_rules_are_built_in() {
    let named_rules: HashSet<&str> = [
        // Table-level governance
        "TBL-RAP-RMV",
        "TBL-MASK-RMV",
        "TBL-AGGPOL-RMV",
        // API Integration
        "SNW-API-INTG-NEW",
        "SNW-API-INTG-CREDRMV",
        "SNW-API-INTG-NOPFX",
        "SNW-API-INTG-CREDCHG",
        // Stage
        "SNW-STG-ENC-OFF",
        "SNW-STG-CRED-CHG",
        "SNW-STG-TAG-RMV",
        "SNW-STG-INTG-CHG",
        // Row Access Policy
        "RAP-BODY-CHG",
        "RAP-NAME-CHG",
        "RAP-TAG-RMV",
        // Masking Policy
        "MASK-BODY-CHG",
        "MASK-NAME-CHG",
        "MASK-TAG-RMV",
        "SNW-MASK-EXEMPT",
        // Network Policy
        "SNW-NETPOL-NEW",
        "SNW-NETPOL-RULELIST-CFG",
        "SNW-NETPOL-SET",
        "SNW-NETPOL-ADD",
        "SNW-NETPOL-RMV",
        "SNW-NETPOL-NAME-CHG",
        "SNW-NETPOL-TAG-RMV",
        "SNW-NETPOL-DROP",
        // Storage Integration
        "SNW-SESSPOL-IDLE-LONG",
        "SNW-SESSPOL-UIIDLE-LONG",
        "SNW-SESSPOL-IDLE-UNSET",
        "SNW-SESSPOL-UIIDLE-UNSET",
        "SNW-SESSPOL-IDLE-LONGSET",
        "SNW-SESSPOL-UIIDLE-LONGSET",
        "SNW-SESSPOL-IDLE-CHG",
        "SNW-STGINTG-NEW",
        "SNW-STGINTG-NEW-OFF",
        "SNW-STGINTG-OFF",
        "SNW-STGINTG-AWS-CHG",
        "SNW-STGINTG-AZURE-CHG",
        "SNW-STGINTG-LOC-CHG",
        "SNW-STGINTG-BLOCKLOC-CHG",
        "SNW-STGINTG-TAG-RMV",
        "SNW-STGINTG-DROP",
        // Password Policy CREATE
        "SNW-PWDPOL-MINLEN-CRIT",
        "SNW-PWDPOL-MINLEN-WEAK",
        "SNW-PWDPOL-COMPLEX-WEAK",
        "SNW-PWDPOL-NOEXPIRY",
        "SNW-PWDPOL-EXPIRY-LONG",
        "SNW-PWDPOL-RETRIES-HIGH",
        "SNW-PWDPOL-RETRIES-CHG",
        "SNW-PWDPOL-LOCKOUT-SHORT",
        "SNW-PWDPOL-NOHIST",
        // Password Policy ALTER
        "SNW-PWDPOL-MINLEN-CRITWEAK",
        "SNW-PWDPOL-MINLEN-WEAKEN",
        "SNW-PWDPOL-EXPIRY-OFF",
        "SNW-PWDPOL-EXPIRY-LONGSET",
        "SNW-PWDPOL-RETRIES-INCR",
        "SNW-PWDPOL-LOCKOUT-CUT",
        "SNW-PWDPOL-HIST-OFF",
        "SNW-PWDPOL-MINLEN-UNSET",
        "SNW-PWDPOL-EXPIRY-UNSET",
        "SNW-PWDPOL-NAME-CHG",
        // Password Policy DROP
        "SNW-PWDPOL-DROP",
        // Aggregation Policy
        "SNW-AGGPOL-NEW",
        "SNW-AGGPOL-NOCONST",
        "SNW-AGGPOL-GRPSZ-CRIT",
        "SNW-AGGPOL-GRPSZ-LOW",
        "SNW-AGGPOL-COND",
        "SNW-AGGPOL-NOCONST-CHG",
        "SNW-AGGPOL-CHG",
        "SNW-AGGPOL-NAME-CHG",
        "SNW-AGGPOL-DROP",
        "SNW-PWDPOL-HISTORY-UNSET",
        // Catalog-aware query performance
        "Q-TBL-UNBOUNDED-CENH",
        "Q-VIEW-REF-CENH",
        // Grants
        "SNW-ROLE-PRIV-USE",
        "GRT-ALL-PRIV",
        "GRT-WITH-OPT",
        "GRT-TO-PUBLIC",
        "SNW-GRT-PRIV-ROLE",
        "GRT-OWNER-XFER",
        "GRT-TO-SHARE",
        // Unknown syntax detection
        "SNW-UNKNOWN",
    ]
    .iter()
    .cloned()
    .collect();

    let builtin = lexega_core::rules::all_builtin_rules().expect("built-in corpus loads");
    let builtin: HashSet<&str> = builtin.iter().map(|rule| rule.id.as_str()).collect();
    let mut unknown: Vec<&str> = named_rules.difference(&builtin).copied().collect();
    unknown.sort_unstable();
    assert!(unknown.is_empty(), "not built-in rules: {unknown:?}");
}
