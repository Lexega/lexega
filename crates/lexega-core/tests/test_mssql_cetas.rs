// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! T-SQL CETAS — `CREATE EXTERNAL TABLE … WITH (…) AS <query>`.
//!
//! CETAS writes the results of a query out to an external location (S3 / Azure
//! blob / HDFS via a PolyBase data source) — a data-egress surface. The `AS`
//! query is parsed into a sub-statement, the whole thing is one statement
//! (byte-exact round-trip), and the egress query is flattened into rule
//! evaluation so its reads/predicates reach the corpus. Read-only external
//! tables (BigQuery / Snowflake / Redshift / plain PolyBase) carry no `AS`
//! query and are unaffected.

use lexega_core::analyzer::{AnalysisConfig, RuleMatch};
use lexega_core::api::analyze_risk_with_policy_config;
use lexega_core::rules::{build_v1_rule_corpus, load_v1_rules};
use lexega_core::{
    dialect, format_sql_with_config, verify_formatting_safe_with_dialect, FormatterConfig,
};

fn mssql_cfg() -> AnalysisConfig {
    AnalysisConfig {
        dialect: Some(dialect::mssql()),
        ..Default::default()
    }
}

fn mssql_cfg_with_overlay(custom_yaml: &str) -> AnalysisConfig {
    let custom = load_v1_rules(custom_yaml).expect("custom rules parse");
    let merged = build_v1_rule_corpus(custom, /* include_builtins = */ true)
        .expect("merge against built-ins succeeds");
    AnalysisConfig {
        dialect: Some(dialect::mssql()),
        custom_rules: Some(merged),
        ..Default::default()
    }
}

fn rule_ids_with(sql: &str, cfg: &AnalysisConfig) -> Vec<String> {
    let report = analyze_risk_with_policy_config(sql, cfg).expect("should analyze");
    report
        .signals
        .iter()
        .map(|RuleMatch::Analysis(a)| a.matched_rule.clone())
        .collect()
}

fn rule_ids(sql: &str) -> Vec<String> {
    rule_ids_with(sql, &mssql_cfg())
}

const CETAS: &str = "CREATE EXTERNAL TABLE ext.tbl \
WITH (LOCATION = '/out/', DATA_SOURCE = ds, FILE_FORMAT = ff) \
AS SELECT id, secret FROM dbo.secrets;";

// ── Recognition: one statement, byte-exact, not fragmented ────────────────

#[test]
fn test_cetas_is_one_byte_exact_statement() {
    let mut config = FormatterConfig::default();
    config.dialect = dialect::mssql();
    let out = format_sql_with_config(CETAS, &config).expect("should format");
    // A fragmented parse would insert an inter-statement blank line between the
    // external-table head and the `AS SELECT`; a single statement round-trips
    // byte-exact under the span-only (Pattern A) formatter.
    assert_eq!(
        out, CETAS,
        "CETAS must round-trip as one byte-exact statement"
    );
    verify_formatting_safe_with_dialect(CETAS, &out, config.dialect.as_ref())
        .expect("should preserve tokens");

    let report = analyze_risk_with_policy_config(CETAS, &mssql_cfg()).expect("should analyze");
    assert_eq!(report.summary.statements_skipped, 0, "must not be skipped");
}

#[test]
fn test_following_statement_not_disrupted() {
    // CETAS is consumed as one statement, so a following DROP is analyzed
    // normally.
    let sql = format!("{CETAS}\nDROP TABLE dbo.old;");
    let ids = rule_ids(&sql);
    assert!(
        ids.iter().any(|r| r.contains("DROP")),
        "the statement after CETAS must still be analyzed. Got: {ids:?}"
    );
}

// ── Governance: the external destination still fires (WITH-bag composition) ─

#[test]
fn test_external_destination_rules_fire() {
    let ids = rule_ids(CETAS);
    assert!(
        ids.contains(&"MSSQL-POLYBASE-EXTERNAL-TABLE".to_string()),
        "the PolyBase external-data-source rule must fire on CETAS. Got: {ids:?}"
    );
}

// ── The egress query is flattened into rule evaluation ────────────────────

const SELECT_PROBE_RULE: &str = r#"
rules:
  - id: TEST-SELECT-REACHED
    risk_level: info
    message: "a SELECT statement was rule-evaluated"
    triggers:
      all_of:
        - kind: select
"#;

#[test]
fn test_egress_query_is_rule_evaluated() {
    let cfg = mssql_cfg_with_overlay(SELECT_PROBE_RULE);

    // Baseline: the rule fires on a standalone SELECT.
    let standalone = rule_ids_with("SELECT id, secret FROM dbo.secrets;", &cfg);
    assert!(
        standalone.contains(&"TEST-SELECT-REACHED".to_string()),
        "sanity: the probe rule must fire on a standalone SELECT. Got: {standalone:?}"
    );

    // The CETAS egress query must reach the same rule — proving it is parsed
    // and flattened, not skipped.
    let ids = rule_ids_with(CETAS, &cfg);
    assert!(
        ids.contains(&"TEST-SELECT-REACHED".to_string()),
        "the CETAS `AS` query must be rule-evaluated (flattened). Got: {ids:?}"
    );
}

#[test]
fn test_unparseable_egress_body_keeps_head_recognized() {
    // A malformed `AS` body must not abort recognition of the external-table
    // head (mirrors `ctas_query`'s Err-span fallback): the destination rules
    // still fire.
    let sql = "CREATE EXTERNAL TABLE ext.tbl \
        WITH (LOCATION = '/out/', DATA_SOURCE = ds, FILE_FORMAT = ff) \
        AS SELECT FROM WHERE );";
    let ids = rule_ids(sql);
    assert!(
        ids.contains(&"MSSQL-POLYBASE-EXTERNAL-TABLE".to_string()),
        "a malformed egress body must not lose the external-table head. Got: {ids:?}"
    );
}

// ── Soundness: read-only external tables carry no AS query ─────────────────

#[test]
fn test_read_only_external_table_unaffected() {
    // A plain PolyBase external table (no AS query) still parses as one
    // statement and is not treated as CETAS.
    let read_only = "CREATE EXTERNAL TABLE ext.tbl \
        WITH (LOCATION = '/in/', DATA_SOURCE = ds, FILE_FORMAT = ff);";
    let mut config = FormatterConfig::default();
    config.dialect = dialect::mssql();
    let out = format_sql_with_config(read_only, &config).expect("should format");
    assert_eq!(
        out, read_only,
        "read-only external table must round-trip byte-exact"
    );

    let report = analyze_risk_with_policy_config(read_only, &mssql_cfg()).expect("should analyze");
    assert_eq!(report.summary.statements_skipped, 0, "must not be skipped");
}
