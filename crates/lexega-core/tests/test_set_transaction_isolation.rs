// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! T-SQL `SET TRANSACTION ISOLATION LEVEL <level>`.
//!
//! Covers recognition (parse + byte-exact round-trip, not skipped) and the
//! governance rules — including the soundness check that REPEATABLE READ is
//! not mistaken for READ UNCOMMITTED (both contain the word READ).

use lexega_core::analyzer::{AnalysisConfig, RuleMatch};
use lexega_core::api::analyze_risk_with_policy_config;
use lexega_core::{
    dialect, format_sql_with_config, verify_formatting_safe_with_dialect, FormatterConfig,
};

fn mssql_cfg() -> AnalysisConfig {
    AnalysisConfig {
        dialect: Some(dialect::mssql()),
        ..Default::default()
    }
}

fn rule_ids(sql: &str) -> Vec<String> {
    let report = analyze_risk_with_policy_config(sql, &mssql_cfg()).expect("should analyze");
    report
        .signals
        .iter()
        .filter_map(|s| match s {
            RuleMatch::Analysis(a) => Some(a.matched_rule.clone()),
        })
        .collect()
}

fn roundtrip_not_skipped(sql: &str) {
    let mut config = FormatterConfig::default();
    config.dialect = dialect::mssql();
    let out = format_sql_with_config(sql, &config).expect("should format");
    verify_formatting_safe_with_dialect(sql, &out, config.dialect.as_ref())
        .expect("should preserve tokens");

    let report = analyze_risk_with_policy_config(sql, &mssql_cfg()).expect("should analyze");
    assert_eq!(
        report.summary.statements_skipped, 0,
        "must be analyzed, not skipped: {sql}"
    );
}

// ── Recognition ─────────────────────────────────────────────────────────

#[test]
fn test_all_levels_recognized() {
    roundtrip_not_skipped("SET TRANSACTION ISOLATION LEVEL READ UNCOMMITTED;");
    roundtrip_not_skipped("SET TRANSACTION ISOLATION LEVEL READ COMMITTED;");
    roundtrip_not_skipped("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ;");
    roundtrip_not_skipped("SET TRANSACTION ISOLATION LEVEL SNAPSHOT;");
    roundtrip_not_skipped("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE;");
}

#[test]
fn test_other_set_options_unaffected() {
    roundtrip_not_skipped("SET NOCOUNT ON;");
    roundtrip_not_skipped("SET IDENTITY_INSERT dbo.t ON;");
    roundtrip_not_skipped("SET LOCK_TIMEOUT 30000;");
}

// ── Governance ──────────────────────────────────────────────────────────

#[test]
fn test_read_uncommitted_fires_dirty_read_rule() {
    let ids = rule_ids("SET TRANSACTION ISOLATION LEVEL READ UNCOMMITTED;");
    assert!(
        ids.contains(&"MSSQL-ISOLATION-READ-UNCOMMITTED".to_string()),
        "READ UNCOMMITTED should fire the dirty-read rule. Got: {ids:?}"
    );
}

#[test]
fn test_isolation_level_info_fires_for_all() {
    for sql in [
        "SET TRANSACTION ISOLATION LEVEL SNAPSHOT;",
        "SET TRANSACTION ISOLATION LEVEL SERIALIZABLE;",
    ] {
        let ids = rule_ids(sql);
        assert!(
            ids.contains(&"INFO-MSSQL-ISOLATION-LEVEL".to_string()),
            "INFO-MSSQL-ISOLATION-LEVEL should fire for {sql}. Got: {ids:?}"
        );
    }
}

#[test]
fn test_repeatable_read_not_misread_as_read_uncommitted() {
    // Soundness: "REPEATABLE READ" and "READ UNCOMMITTED" both contain READ; the
    // typed level must distinguish them so the dirty-read rule stays silent here.
    let ids = rule_ids("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ;");
    assert!(
        !ids.contains(&"MSSQL-ISOLATION-READ-UNCOMMITTED".to_string()),
        "REPEATABLE READ must NOT fire the dirty-read rule. Got: {ids:?}"
    );
}

#[test]
fn test_serializable_not_dirty_read() {
    let ids = rule_ids("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE;");
    assert!(
        !ids.contains(&"MSSQL-ISOLATION-READ-UNCOMMITTED".to_string()),
        "SERIALIZABLE must NOT fire the dirty-read rule. Got: {ids:?}"
    );
}
