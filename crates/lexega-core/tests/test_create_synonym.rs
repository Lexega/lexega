// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Tests for T-SQL `CREATE SYNONYM name FOR object`.
//!
//! Covers recognition (parse + byte-exact format), governance facts
//! (`ddl.synonym.*`), and the two rules INFO-SYNONYM-NEW / SYNONYM-REMOTE-REFERENT.

use lexega_core::analyzer::RuleMatch;
use lexega_core::api::analyze_risk;
use lexega_core::{format_sql_with_config, verify_formatting_safe, FormatterConfig};

fn rule_ids(signals: &[RuleMatch]) -> Vec<String> {
    signals
        .iter()
        .filter_map(|s| match s {
            RuleMatch::Analysis(a) => Some(a.matched_rule.clone()),
        })
        .collect()
}

fn fmt(sql: &str) -> String {
    let out = format_sql_with_config(sql, &FormatterConfig::default()).expect("should format");
    verify_formatting_safe(sql, &out).expect("should preserve tokens");
    out
}

// ── Recognition (parse + byte-exact round-trip) ─────────────────────────

#[test]
fn test_synonym_basic_roundtrip() {
    fmt("CREATE SYNONYM s FOR dbo.t;");
    fmt("CREATE SYNONYM myschema.s FOR otherdb.dbo.t;");
    fmt("CREATE SYNONYM s FOR server.db.schema.obj;");
}

#[test]
fn test_synonym_quoted_identifiers() {
    fmt("CREATE SYNONYM [My Syn] FOR [My DB].[dbo].[My Table];");
}

#[test]
fn test_synonym_multi_statement() {
    let sql = "CREATE SYNONYM a FOR dbo.t1;\nCREATE SYNONYM b FOR dbo.t2;\nSELECT 1;";
    fmt(sql);
}

#[test]
fn test_synonym_reaches_analyzer_not_skipped() {
    let report = analyze_risk("CREATE SYNONYM s FOR dbo.t;").expect("should analyze");
    assert_eq!(
        report.summary.statements_skipped, 0,
        "CREATE SYNONYM must be analyzed, not skipped (OpaqueContent)"
    );
}

// ── Governance rules ────────────────────────────────────────────────────

#[test]
fn test_synonym_info_fires() {
    let report = analyze_risk("CREATE SYNONYM s FOR dbo.t;").expect("should analyze");
    let ids = rule_ids(&report.signals);
    assert!(
        ids.contains(&"INFO-SYNONYM-NEW".to_string()),
        "INFO-SYNONYM-NEW should fire. Got: {:?}",
        ids
    );
}

#[test]
fn test_synonym_server_qualified_fires_remote_rule() {
    // Four-part referent = server.database.schema.object → linked/remote server.
    let report = analyze_risk("CREATE SYNONYM s FOR linkedsrv.db.dbo.t;").expect("should analyze");
    let ids = rule_ids(&report.signals);
    assert!(
        ids.contains(&"SYNONYM-REMOTE-REFERENT".to_string()),
        "SYNONYM-REMOTE-REFERENT should fire for a four-part referent. Got: {:?}",
        ids
    );
}

#[test]
fn test_synonym_local_referent_no_remote_rule() {
    // Two-part referent (schema.object) is local — the remote rule must NOT fire.
    let report = analyze_risk("CREATE SYNONYM s FOR dbo.t;").expect("should analyze");
    let ids = rule_ids(&report.signals);
    assert!(
        !ids.contains(&"SYNONYM-REMOTE-REFERENT".to_string()),
        "SYNONYM-REMOTE-REFERENT must NOT fire for a local referent. Got: {:?}",
        ids
    );
}
