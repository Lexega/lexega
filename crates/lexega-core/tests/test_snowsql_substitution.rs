// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Integration tests for SnowSQL `&var` variable substitution (the Snowflake
//! CLI client-driver syntax). These verify the substitution pre-pass wires
//! through the analysis path end to end: a `&var`-parameterized script analyzes
//! identically to its already-substituted literal, undefined refs still parse,
//! and the behavior is gated to the Snowflake dialect.
//!
//! The substitution transform itself (escaping, line preservation, intent
//! gating) is unit-tested in `src/template/snowsql.rs`.

use lexega_core::{
    analyzer::{AnalysisConfig, ConfidenceLevel, RuleMatch},
    PostgresDialect,
};

use lexega_core::api::{analyze_risk, analyze_risk_with_policy_config};
use std::collections::HashSet;
use std::sync::Arc;

fn extract_rule_ids(signals: &[RuleMatch]) -> HashSet<String> {
    signals
        .iter()
        .filter_map(|f| match f {
            RuleMatch::Analysis(g) => Some(g.matched_rule.clone()),
        })
        .collect()
}

/// `analyze_risk` has no explicit dialect, so it uses the documented Snowflake
/// default — substitution is active.
fn snow_rules(sql: &str) -> HashSet<String> {
    let report = analyze_risk(sql).expect("snowflake analyze");
    extract_rule_ids(&report.signals)
}

fn pg_rules(sql: &str) -> HashSet<String> {
    let mut config = AnalysisConfig::default();
    config.dialect = Some(Arc::new(PostgresDialect));
    let report = analyze_risk_with_policy_config(sql, &config).expect("postgres analyze");
    extract_rule_ids(&report.signals)
}

#[test]
fn defined_var_substitutes_to_equivalent_literal() {
    let via_snowsql = snow_rules("!define t=USERS\nDROP TABLE &t;\n");
    let literal = snow_rules("DROP TABLE USERS;\n");
    assert!(!literal.is_empty(), "DROP TABLE should fire a rule");
    assert_eq!(
        via_snowsql, literal,
        "a &var script must analyze identically to its substituted literal"
    );
}

#[test]
fn braced_var_substitutes_to_equivalent_literal() {
    let via_snowsql = snow_rules("!define t=USERS\nDROP TABLE &{t};\n");
    let literal = snow_rules("DROP TABLE USERS;\n");
    assert!(!literal.is_empty());
    assert_eq!(via_snowsql, literal);
}

#[test]
fn undefined_var_still_parses_via_identifier_placeholder() {
    // `&ghost` is undefined; the `!define` marker activates substitution and the
    // undefined ref becomes the bare identifier `ghost`, so the DROP still parses.
    let via_snowsql = snow_rules("!define other=x\nDROP TABLE &ghost;\n");
    let literal = snow_rules("DROP TABLE ghost;\n");
    assert!(!literal.is_empty());
    assert_eq!(via_snowsql, literal);
}

#[test]
fn substitution_is_gated_to_snowflake_dialect() {
    // GRANT-TO-PUBLIC keys on the grantee VALUE, so substitution is observable
    // (a DROP rule keys only on the action and fires regardless of the target).
    // Snowflake substitutes `&p` → PUBLIC, so the &var form fires the same rule
    // as the literal; PostgreSQL performs no SnowSQL substitution, so `&p` stays
    // unparsed and the rule does not fire — differing from its literal.
    let snow_sub = snow_rules("!define p=PUBLIC\nGRANT SELECT ON t TO &p;\n");
    let snow_lit = snow_rules("GRANT SELECT ON t TO PUBLIC;\n");
    assert!(!snow_lit.is_empty(), "GRANT TO PUBLIC should fire a rule");
    assert_eq!(snow_sub, snow_lit, "snowflake substitutes &p → PUBLIC");

    let pg_sub = pg_rules("!define p=PUBLIC\nGRANT SELECT ON t TO &p;\n");
    let pg_lit = pg_rules("GRANT SELECT ON t TO PUBLIC;\n");
    assert_ne!(
        pg_sub, pg_lit,
        "postgresql performs no SnowSQL substitution"
    );
}

#[test]
fn undefined_var_lowers_analysis_confidence() {
    // `&ghost` is unresolved (the `!define a=1` only activates substitution); the
    // placeholder it leaves behind must drop confidence below High.
    let report = analyze_risk("!define a=1\nDROP TABLE &ghost;\n").expect("analyze");
    assert_ne!(
        report.summary.analysis_confidence,
        ConfidenceLevel::High,
        "an unresolved &var must lower analysis confidence"
    );
}

#[test]
fn resolved_var_keeps_high_confidence() {
    // A fully-resolved script has no placeholders → confidence stays High.
    let report = analyze_risk("!define t=USERS\nDROP TABLE &t;\n").expect("analyze");
    assert_eq!(report.summary.analysis_confidence, ConfidenceLevel::High);
}
