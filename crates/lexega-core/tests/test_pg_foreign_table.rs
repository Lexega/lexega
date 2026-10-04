// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! SQL/MED `CREATE FOREIGN TABLE` (PostgreSQL FDW).
//!
//! Covers recognition (parse + byte-exact round-trip, not skipped) across the
//! column-list and `PARTITION OF` forms, governance (the federated-data signal
//! fires), and the non-regression of the Databricks `CREATE FOREIGN CATALOG`
//! form (which this parser must not intercept — it gates on the `TABLE`
//! keyword).

use lexega_core::analyzer::{AnalysisConfig, RuleMatch};
use lexega_core::api::analyze_risk_with_policy_config;
use lexega_core::{
    dialect, format_sql_with_config, verify_formatting_safe_with_dialect, FormatterConfig,
};

fn pg_cfg() -> AnalysisConfig {
    AnalysisConfig {
        dialect: Some(dialect::postgres()),
        ..Default::default()
    }
}

fn rule_ids(sql: &str) -> Vec<String> {
    let report = analyze_risk_with_policy_config(sql, &pg_cfg()).expect("should analyze");
    report
        .signals
        .iter()
        .map(|RuleMatch::Analysis(a)| a.matched_rule.clone())
        .collect()
}

fn roundtrip_not_skipped(sql: &str) {
    let mut config = FormatterConfig::default();
    config.dialect = dialect::postgres();
    let out = format_sql_with_config(sql, &config).expect("should format");
    verify_formatting_safe_with_dialect(sql, &out, config.dialect.as_ref())
        .expect("should preserve tokens");
    let report = analyze_risk_with_policy_config(sql, &pg_cfg()).expect("should analyze");
    assert_eq!(
        report.summary.statements_skipped, 0,
        "must be analyzed, not skipped: {sql}"
    );
}

// ── Recognition ─────────────────────────────────────────────────────────

#[test]
fn test_column_list_form_recognized() {
    roundtrip_not_skipped(
        "CREATE FOREIGN TABLE ft (a int, b text) SERVER s \
         OPTIONS (schema_name 'public', table_name 't');",
    );
    // IF NOT EXISTS + qualified name + column constraint + no OPTIONS.
    roundtrip_not_skipped(
        "CREATE FOREIGN TABLE IF NOT EXISTS sch.ft2 (id bigint NOT NULL) SERVER s;",
    );
    // Empty column list (allowed — columns inherited from a foreign schema).
    roundtrip_not_skipped("CREATE FOREIGN TABLE ft3 () SERVER s;");
}

#[test]
fn test_partition_form_recognized() {
    roundtrip_not_skipped(
        "CREATE FOREIGN TABLE pt PARTITION OF parent FOR VALUES IN (1) SERVER s \
         OPTIONS (table_name 'p1');",
    );
    roundtrip_not_skipped("CREATE FOREIGN TABLE pt2 PARTITION OF parent DEFAULT SERVER s;");
}

#[test]
fn test_multi_statement_roundtrip() {
    roundtrip_not_skipped(
        "CREATE FOREIGN TABLE a (x int) SERVER s1;\n\
         CREATE FOREIGN TABLE b (y text) SERVER s2 OPTIONS (table_name 't');\n\
         CREATE FOREIGN TABLE c PARTITION OF p FOR VALUES IN (1) SERVER s3;",
    );
}

// ── Governance ──────────────────────────────────────────────────────────

#[test]
fn test_foreign_table_fires_signal() {
    for sql in [
        "CREATE FOREIGN TABLE ft (a int) SERVER s;",
        "CREATE FOREIGN TABLE pt PARTITION OF parent FOR VALUES IN (1) SERVER s;",
    ] {
        let ids = rule_ids(sql);
        assert!(
            ids.contains(&"INFO-PG-FDW-FOREIGN-TABLE".to_string()),
            "a foreign table should fire the federated-data signal for {sql}. Got: {ids:?}"
        );
    }
}

// ── Non-regression: Databricks CREATE FOREIGN CATALOG ───────────────────

#[test]
fn test_foreign_catalog_not_hijacked() {
    // `CREATE FOREIGN CATALOG` (Databricks) shares the FOREIGN keyword but is
    // not a foreign TABLE — the branch gates on the TABLE keyword, so the
    // catalog parser still handles it and no foreign-table signal fires.
    let cfg = AnalysisConfig {
        dialect: Some(dialect::databricks()),
        ..Default::default()
    };
    let sql = "CREATE FOREIGN CATALOG fc USING CONNECTION c OPTIONS (database 'db');";
    let report = analyze_risk_with_policy_config(sql, &cfg).expect("should analyze");
    assert_eq!(
        report.summary.statements_skipped, 0,
        "CREATE FOREIGN CATALOG must still be analyzed: {sql}"
    );
    let ids: Vec<String> = report
        .signals
        .iter()
        .map(|RuleMatch::Analysis(a)| a.matched_rule.clone())
        .collect();
    assert!(
        !ids.contains(&"INFO-PG-FDW-FOREIGN-TABLE".to_string()),
        "CREATE FOREIGN CATALOG must not fire a foreign-table signal: {ids:?}"
    );
}
