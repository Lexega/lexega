// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! SQL/MED `IMPORT FOREIGN SCHEMA remote [{LIMIT TO|EXCEPT} (tables)]
//! FROM SERVER srv INTO local [OPTIONS (…)]` (PostgreSQL FDW bulk import).
//!
//! Covers recognition (parse + byte-exact round-trip, not skipped), and the
//! governance soundness boundary: the broad-exposure rule fires for the
//! unbounded (`all`) and near-unbounded (`except`) imports but stays silent
//! for a scoped `LIMIT TO` allow-list.

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
fn test_all_forms_recognized() {
    roundtrip_not_skipped("IMPORT FOREIGN SCHEMA remote FROM SERVER fs INTO local;");
    roundtrip_not_skipped(
        "IMPORT FOREIGN SCHEMA remote LIMIT TO (t1, t2) FROM SERVER fs INTO local;",
    );
    roundtrip_not_skipped(
        "IMPORT FOREIGN SCHEMA remote EXCEPT (secret_t) FROM SERVER fs INTO local;",
    );
    // With OPTIONS bag.
    roundtrip_not_skipped(
        "IMPORT FOREIGN SCHEMA remote FROM SERVER fs INTO local \
         OPTIONS (import_default 'true', import_collate 'false');",
    );
    // Quoted identifiers.
    roundtrip_not_skipped(
        "IMPORT FOREIGN SCHEMA \"My Remote\" LIMIT TO (\"T 1\") FROM SERVER \"my fs\" INTO \"loc\";",
    );
}

#[test]
fn test_multi_statement_roundtrip() {
    roundtrip_not_skipped(
        "IMPORT FOREIGN SCHEMA a FROM SERVER fs INTO l1;\n\
         IMPORT FOREIGN SCHEMA b LIMIT TO (t) FROM SERVER fs INTO l2;\n\
         IMPORT FOREIGN SCHEMA c EXCEPT (s) FROM SERVER fs INTO l3;",
    );
}

#[test]
fn test_bare_import_identifier_not_hijacked() {
    // `IMPORT` is an ordinary identifier in other contexts — a SELECT of a
    // column named `import` must not be intercepted by the FDW dispatch.
    let sql = "SELECT import FROM t;";
    let report = analyze_risk_with_policy_config(sql, &pg_cfg()).expect("should analyze");
    assert_eq!(
        report.summary.statements_skipped, 0,
        "should analyze: {sql}"
    );
    let ids = rule_ids(sql);
    assert!(
        !ids.iter().any(|id| id.contains("IMPORT-FOREIGN-SCHEMA")),
        "a column named `import` must not fire an import-foreign-schema finding: {ids:?}"
    );
}

// ── Governance: broad-exposure soundness ────────────────────────────────

#[test]
fn test_unbounded_import_fires_broad() {
    // No filter → the entire remote schema is exposed → broad rule fires.
    let ids = rule_ids("IMPORT FOREIGN SCHEMA remote FROM SERVER fs INTO local;");
    assert!(
        ids.contains(&"PG-FDW-IMPORT-FOREIGN-SCHEMA-BROAD".to_string()),
        "an unbounded import should fire the broad-exposure rule. Got: {ids:?}"
    );
}

#[test]
fn test_except_import_fires_broad() {
    // EXCEPT imports all-but-a-few → still near-unbounded → broad rule fires.
    let ids = rule_ids("IMPORT FOREIGN SCHEMA remote EXCEPT (s) FROM SERVER fs INTO local;");
    assert!(
        ids.contains(&"PG-FDW-IMPORT-FOREIGN-SCHEMA-BROAD".to_string()),
        "an EXCEPT import should fire the broad-exposure rule. Got: {ids:?}"
    );
}

#[test]
fn test_limit_to_does_not_fire_broad() {
    // Soundness: a scoped LIMIT TO allow-list is the bounded form — the broad
    // rule keys on the typed filter mode, so it must stay silent.
    let ids = rule_ids("IMPORT FOREIGN SCHEMA remote LIMIT TO (t1, t2) FROM SERVER fs INTO local;");
    assert!(
        !ids.contains(&"PG-FDW-IMPORT-FOREIGN-SCHEMA-BROAD".to_string()),
        "a scoped LIMIT TO import must NOT fire the broad-exposure rule. Got: {ids:?}"
    );
}

#[test]
fn test_info_fires_for_every_import() {
    for sql in [
        "IMPORT FOREIGN SCHEMA remote FROM SERVER fs INTO local;",
        "IMPORT FOREIGN SCHEMA remote LIMIT TO (t1) FROM SERVER fs INTO local;",
        "IMPORT FOREIGN SCHEMA remote EXCEPT (s) FROM SERVER fs INTO local;",
    ] {
        let ids = rule_ids(sql);
        assert!(
            ids.contains(&"INFO-PG-FDW-IMPORT-FOREIGN-SCHEMA".to_string()),
            "INFO-PG-FDW-IMPORT-FOREIGN-SCHEMA should fire for {sql}. Got: {ids:?}"
        );
    }
}
