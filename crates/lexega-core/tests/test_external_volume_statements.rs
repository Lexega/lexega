// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Tests for Snowflake `CREATE EXTERNAL VOLUME` governance: structured
//! extraction of the `STORAGE_LOCATIONS` cloud config (provider, role ARN,
//! encryption type) and `ALLOW_WRITES` into `ddl.volume` facts, the three
//! SNW-EXTVOL-* rules, byte-exact formatting, and no regression on the
//! Databricks `LOCATION`-style volume.

use lexega_core::{
    analyzer::RuleMatch, format_sql_with_config, verify_formatting_safe, FormatterConfig,
};

use lexega_core::api::analyze_risk;
use std::collections::HashSet;

fn extract_rule_ids(signals: &[RuleMatch]) -> HashSet<String> {
    signals
        .iter()
        .filter_map(|f| match f {
            RuleMatch::Analysis(g) => Some(g.matched_rule.clone()),
        })
        .collect()
}

fn analyze_and_get_rules(sql: &str) -> HashSet<String> {
    let report = analyze_risk(sql).expect("should analyze successfully");
    extract_rule_ids(&report.signals)
}

fn assert_formats_safe(sql: &str) {
    let formatted =
        format_sql_with_config(sql, &FormatterConfig::default()).expect("should format");
    verify_formatting_safe(sql, &formatted).expect("should preserve semantics");
}

const FULL: &str = "CREATE EXTERNAL VOLUME v STORAGE_LOCATIONS = ((NAME='l1' \
    STORAGE_PROVIDER='S3' STORAGE_BASE_URL='s3://b/' \
    STORAGE_AWS_ROLE_ARN='arn:aws:iam::1:role/r' ENCRYPTION=(TYPE='NONE'))) \
    ALLOW_WRITES=TRUE;";

#[test]
fn test_external_volume_full_fires_all_three() {
    let rules = analyze_and_get_rules(FULL);
    assert!(rules.contains("SNW-EXTVOL-CLOUD-ACCESS"), "got {rules:?}");
    assert!(rules.contains("SNW-EXTVOL-WRITABLE"), "got {rules:?}");
    assert!(rules.contains("SNW-EXTVOL-ENC-NONE"), "got {rules:?}");
}

#[test]
fn test_external_volume_readonly_encrypted_fires_only_cloud_access() {
    // ALLOW_WRITES=FALSE + ENCRYPTION TYPE=AWS_SSE_S3: the recognition/policy
    // split means only the cloud-access recognition fires — flipping the
    // values reverses the writable/encryption verdicts with no recompile.
    let rules = analyze_and_get_rules(
        "CREATE EXTERNAL VOLUME v STORAGE_LOCATIONS=((NAME='l' STORAGE_PROVIDER='S3' \
         STORAGE_BASE_URL='s3://b/' STORAGE_AWS_ROLE_ARN='arn:x' \
         ENCRYPTION=(TYPE='AWS_SSE_S3'))) ALLOW_WRITES=FALSE;",
    );
    assert!(rules.contains("SNW-EXTVOL-CLOUD-ACCESS"), "got {rules:?}");
    assert!(!rules.contains("SNW-EXTVOL-WRITABLE"), "got {rules:?}");
    assert!(!rules.contains("SNW-EXTVOL-ENC-NONE"), "got {rules:?}");
}

#[test]
fn test_external_volume_multiple_locations() {
    // Two storage locations; one writable encryption-less S3, one GCS.
    let rules = analyze_and_get_rules(
        "CREATE EXTERNAL VOLUME v STORAGE_LOCATIONS=(\
         (NAME='a' STORAGE_PROVIDER='S3' STORAGE_AWS_ROLE_ARN='arn:x' ENCRYPTION=(TYPE='NONE')),\
         (NAME='b' STORAGE_PROVIDER='GCS' STORAGE_BASE_URL='gcs://b/'));",
    );
    assert!(rules.contains("SNW-EXTVOL-CLOUD-ACCESS"), "got {rules:?}");
    assert!(rules.contains("SNW-EXTVOL-ENC-NONE"), "got {rules:?}");
}

#[test]
fn test_databricks_location_volume_fires_no_snw_rules() {
    // Databricks LOCATION-style external volume carries no storage_locations
    // / allow_writes facts, so none of the Snowflake rules apply.
    let rules =
        analyze_and_get_rules("CREATE EXTERNAL VOLUME cat.sch.v LOCATION 's3://bucket/path';");
    assert!(!rules.contains("SNW-EXTVOL-CLOUD-ACCESS"), "got {rules:?}");
    assert!(!rules.contains("SNW-EXTVOL-WRITABLE"), "got {rules:?}");
    assert!(!rules.contains("SNW-EXTVOL-ENC-NONE"), "got {rules:?}");
}

#[test]
fn test_external_volume_formats_safe() {
    assert_formats_safe(FULL);
    assert_formats_safe("CREATE EXTERNAL VOLUME cat.sch.v LOCATION 's3://bucket/path';");
}
