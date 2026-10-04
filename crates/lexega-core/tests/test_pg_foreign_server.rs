// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! SQL/MED `CREATE SERVER … FOREIGN DATA WRAPPER` (PostgreSQL FDW).
//!
//! Covers recognition (parse + byte-exact round-trip, not skipped), governance
//! — including the soundness check that the remote-endpoint rule fires only
//! for a known network / file wrapper — and the non-regression of the
//! Databricks `CREATE SERVER` / `CREATE CONNECTION` forms (which lack `FOREIGN
//! DATA` and must not be hijacked).

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

fn rule_ids_cfg(sql: &str, cfg: &AnalysisConfig) -> Vec<String> {
    let report = analyze_risk_with_policy_config(sql, cfg).expect("should analyze");
    report
        .signals
        .iter()
        .map(|RuleMatch::Analysis(a)| a.matched_rule.clone())
        .collect()
}

fn rule_ids(sql: &str) -> Vec<String> {
    rule_ids_cfg(sql, &pg_cfg())
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
fn test_wrappers_and_clauses_recognized() {
    roundtrip_not_skipped(
        "CREATE SERVER s1 FOREIGN DATA WRAPPER postgres_fdw \
         OPTIONS (host 'remote', dbname 'db', port '5432');",
    );
    // file_fdw, no OPTIONS.
    roundtrip_not_skipped("CREATE SERVER film FOREIGN DATA WRAPPER file_fdw;");
    // IF NOT EXISTS + TYPE + VERSION.
    roundtrip_not_skipped(
        "CREATE SERVER IF NOT EXISTS s2 TYPE 'oracle' VERSION '12.0' \
         FOREIGN DATA WRAPPER oracle_fdw OPTIONS (dbserver '//host:1521/orcl');",
    );
    // Quoted name.
    roundtrip_not_skipped("CREATE SERVER \"my server\" FOREIGN DATA WRAPPER postgres_fdw;");
}

#[test]
fn test_multi_statement_roundtrip() {
    roundtrip_not_skipped(
        "CREATE SERVER a FOREIGN DATA WRAPPER postgres_fdw OPTIONS (host 'h1');\n\
         CREATE SERVER b FOREIGN DATA WRAPPER file_fdw;\n\
         CREATE SERVER c TYPE 'x' FOREIGN DATA WRAPPER mysql_fdw OPTIONS (host 'h2', port '3306');",
    );
}

// ── Governance ──────────────────────────────────────────────────────────

#[test]
fn test_known_wrapper_fires_remote_rule() {
    for sql in [
        "CREATE SERVER s FOREIGN DATA WRAPPER postgres_fdw OPTIONS (host 'h');",
        "CREATE SERVER s FOREIGN DATA WRAPPER file_fdw;",
        "CREATE SERVER s FOREIGN DATA WRAPPER oracle_fdw;",
    ] {
        let ids = rule_ids(sql);
        assert!(
            ids.contains(&"PG-FDW-SERVER-REMOTE".to_string()),
            "a known network/file wrapper should fire the remote rule for {sql}. Got: {ids:?}"
        );
    }
}

#[test]
fn test_unknown_wrapper_does_not_fire_remote_rule() {
    // Soundness: the remote rule keys on a YAML wrapper-name set, not on the
    // mere presence of a wrapper — an unrecognized in-house wrapper stays
    // silent (recognition vs policy: flipping the YAML list reverses this).
    let ids = rule_ids("CREATE SERVER s FOREIGN DATA WRAPPER my_inhouse_wrapper;");
    assert!(
        !ids.contains(&"PG-FDW-SERVER-REMOTE".to_string()),
        "an unknown wrapper must NOT fire the remote rule. Got: {ids:?}"
    );
}

#[test]
fn test_info_fires_for_every_wrapper() {
    for sql in [
        "CREATE SERVER s FOREIGN DATA WRAPPER postgres_fdw;",
        "CREATE SERVER s FOREIGN DATA WRAPPER my_inhouse_wrapper;",
    ] {
        let ids = rule_ids(sql);
        assert!(
            ids.contains(&"INFO-PG-FDW-SERVER".to_string()),
            "INFO-PG-FDW-SERVER should fire for {sql}. Got: {ids:?}"
        );
    }
}

#[test]
fn test_remote_and_info_compose() {
    let ids = rule_ids("CREATE SERVER s FOREIGN DATA WRAPPER postgres_fdw OPTIONS (host 'h');");
    assert!(
        ids.contains(&"PG-FDW-SERVER-REMOTE".to_string())
            && ids.contains(&"INFO-PG-FDW-SERVER".to_string()),
        "a known wrapper should fire both the remote and info rules. Got: {ids:?}"
    );
}

// ── ALTER SERVER (lifecycle) ────────────────────────────────────────────

#[test]
fn test_alter_server_forms_recognized() {
    roundtrip_not_skipped("ALTER SERVER s OPTIONS (SET host 'newhost', ADD dbname 'db');");
    roundtrip_not_skipped("ALTER SERVER s VERSION '9.6';");
    roundtrip_not_skipped("ALTER SERVER s OWNER TO newowner;");
    roundtrip_not_skipped("ALTER SERVER s RENAME TO snew;");
    roundtrip_not_skipped("ALTER SERVER \"my server\" OPTIONS (DROP dbname);");
}

#[test]
fn test_alter_options_fires_options_modified_and_info() {
    let ids = rule_ids("ALTER SERVER s OPTIONS (SET host 'newhost');");
    assert!(
        ids.contains(&"PG-FDW-SERVER-OPTIONS-MODIFIED".to_string())
            && ids.contains(&"INFO-PG-FDW-SERVER-ALTER".to_string()),
        "an OPTIONS-modifying ALTER should fire both the options-modified and info rules. Got: {ids:?}"
    );
}

#[test]
fn test_alter_without_options_fires_info_only() {
    // Recognition vs policy: the repoint verdict keys on OPTIONS presence, not
    // on the statement being an ALTER. VERSION / OWNER / RENAME stay info-only.
    for sql in [
        "ALTER SERVER s VERSION '9.6';",
        "ALTER SERVER s OWNER TO r;",
        "ALTER SERVER s RENAME TO snew;",
    ] {
        let ids = rule_ids(sql);
        assert!(
            ids.contains(&"INFO-PG-FDW-SERVER-ALTER".to_string()),
            "INFO-PG-FDW-SERVER-ALTER should fire for {sql}. Got: {ids:?}"
        );
        assert!(
            !ids.contains(&"PG-FDW-SERVER-OPTIONS-MODIFIED".to_string()),
            "a non-OPTIONS ALTER must NOT fire the options-modified rule: {sql}. Got: {ids:?}"
        );
    }
}

#[test]
fn test_alter_does_not_fire_create_rules() {
    // ALTER cannot change the wrapper, so the CREATE-time remote/info rules
    // must not be re-emitted for an ALTER.
    let ids = rule_ids("ALTER SERVER s OPTIONS (SET host 'h');");
    assert!(
        !ids.contains(&"PG-FDW-SERVER-REMOTE".to_string())
            && !ids.contains(&"INFO-PG-FDW-SERVER".to_string()),
        "ALTER SERVER must not fire the CREATE-time rules. Got: {ids:?}"
    );
}

// ── Non-regression: Databricks CREATE SERVER / CONNECTION ───────────────

#[test]
fn test_databricks_server_and_connection_not_hijacked() {
    // These lack `FOREIGN DATA`, so the FDW guard must not intercept them —
    // they stay on the Databricks connection parser and raise no FDW finding.
    let mut config = FormatterConfig::default();
    config.dialect = dialect::databricks();
    let dbx_cfg = AnalysisConfig {
        dialect: Some(dialect::databricks()),
        ..Default::default()
    };

    for sql in [
        "CREATE SERVER s TYPE mysql OPTIONS (host 'h');",
        "CREATE CONNECTION mc TYPE mysql OPTIONS (host 'h', port '3306');",
    ] {
        let out = format_sql_with_config(sql, &config).expect("should format");
        verify_formatting_safe_with_dialect(sql, &out, config.dialect.as_ref())
            .expect("should preserve tokens");
        let report = analyze_risk_with_policy_config(sql, &dbx_cfg).expect("should analyze");
        assert_eq!(
            report.summary.statements_skipped, 0,
            "Databricks server/connection must still be analyzed: {sql}"
        );
        let ids = rule_ids_cfg(sql, &dbx_cfg);
        assert!(
            !ids.iter()
                .any(|id| id.starts_with("PG-FDW-SERVER") || id == "INFO-PG-FDW-SERVER"),
            "Databricks server/connection must not fire an FDW finding: {sql}. Got: {ids:?}"
        );
    }
}
