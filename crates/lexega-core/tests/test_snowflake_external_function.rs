// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Tests for Snowflake `CREATE EXTERNAL FUNCTION` recognition and the
//! SNW-EXTFUNC-* rules. An external function ships row data to an external
//! HTTPS endpoint via an API integration (a data-egress surface). Recognition
//! emits the endpoint URL + scheme, API integration, SECURE flag, and
//! translators under `ddl.external_function.*`; the danger verdict is YAML —
//! SNW-EXTFUNC-NON-TLS gates on `endpoint_scheme: http`, so switching the
//! endpoint to https reverses the finding without a recompile.

use lexega_core::analyzer::RuleMatch;
use lexega_core::api::analyze_risk;
use lexega_core::{format_sql_with_config, verify_formatting_safe, FormatterConfig};
use std::collections::HashSet;

fn analyze_and_get_rules(sql: &str) -> HashSet<String> {
    match analyze_risk(sql) {
        Ok(report) => report
            .signals
            .iter()
            .map(|RuleMatch::Analysis(g)| g.matched_rule.clone())
            .collect(),
        Err(e) => {
            eprintln!("Parse error: {:?}", e);
            HashSet::new()
        }
    }
}

fn skipped(sql: &str) -> usize {
    analyze_risk(sql)
        .expect("should analyze")
        .summary
        .statements_skipped
}

// ── Recognition / coverage ──────────────────────────────────────────────

#[test]
fn external_function_is_analyzed_not_opaque() {
    assert_eq!(
        skipped("CREATE EXTERNAL FUNCTION ef(x INT) RETURNS INT API_INTEGRATION = i AS 'https://x.test/y';"),
        0
    );
}

#[test]
fn secure_or_replace_qualified_form_is_analyzed() {
    assert_eq!(
        skipped(
            "CREATE OR REPLACE SECURE EXTERNAL FUNCTION db.sch.ef(a VARCHAR) RETURNS VARIANT \
             API_INTEGRATION = my_int HEADERS = ('x-key' = 'v') MAX_BATCH_ROWS = 100 \
             AS 'https://api.example.com/run';"
        ),
        0
    );
}

#[test]
fn translator_form_is_analyzed() {
    assert_eq!(
        skipped(
            "CREATE EXTERNAL FUNCTION ef() RETURNS INT API_INTEGRATION = i \
             REQUEST_TRANSLATOR = db.req RESPONSE_TRANSLATOR = db.resp AS 'https://x.test/y';"
        ),
        0
    );
}

// ── SNW-EXTFUNC-NEW (egress-surface recognition) ────────────────────────

#[test]
fn external_function_flags_egress_surface() {
    let rules = analyze_and_get_rules(
        "CREATE EXTERNAL FUNCTION ef(x INT) RETURNS INT API_INTEGRATION = i AS 'https://x.test/y';",
    );
    assert!(
        rules.contains("SNW-EXTFUNC-NEW"),
        "external function should be recognized as an egress surface — if absent, parser may have produced OpaqueContent"
    );
}

// ── SNW-EXTFUNC-NON-TLS (policy-as-data: scheme gate) ───────────────────

#[test]
fn http_endpoint_flags_non_tls() {
    let rules = analyze_and_get_rules(
        "CREATE EXTERNAL FUNCTION ef(x INT) RETURNS INT API_INTEGRATION = i AS 'http://x.test/y';",
    );
    assert!(rules.contains("SNW-EXTFUNC-NON-TLS"));
    assert!(rules.contains("SNW-EXTFUNC-NEW"));
}

#[test]
fn https_endpoint_does_not_flag_non_tls() {
    // The non-TLS rule gates on `endpoint_scheme: http`; an https endpoint
    // must not fire it.
    let rules = analyze_and_get_rules(
        "CREATE EXTERNAL FUNCTION ef(x INT) RETURNS INT API_INTEGRATION = i AS 'https://x.test/y';",
    );
    assert!(!rules.contains("SNW-EXTFUNC-NON-TLS"));
}

#[test]
fn secure_http_still_flags_non_tls() {
    let rules = analyze_and_get_rules(
        "CREATE SECURE EXTERNAL FUNCTION ef(x INT) RETURNS INT API_INTEGRATION = i AS 'http://x.test/y';",
    );
    assert!(rules.contains("SNW-EXTFUNC-NON-TLS"));
}

// ── Negative: a regular (code-bearing) UDF must not fire EXTFUNC rules ───

#[test]
fn regular_function_does_not_flag_extfunc() {
    let rules =
        analyze_and_get_rules("CREATE FUNCTION f(x INT) RETURNS INT LANGUAGE SQL AS 'x + 1';");
    assert!(!rules.contains("SNW-EXTFUNC-NEW"));
    assert!(!rules.contains("SNW-EXTFUNC-NON-TLS"));
}

// ── Formatting: byte-exact round-trip ───────────────────────────────────

fn assert_format_safe(sql: &str) {
    let formatted =
        format_sql_with_config(sql, &FormatterConfig::default()).expect("should format");
    verify_formatting_safe(sql, &formatted).expect("should preserve semantics");
}

#[test]
fn format_basic() {
    assert_format_safe(
        "CREATE EXTERNAL FUNCTION ef(x INT) RETURNS INT API_INTEGRATION = i AS 'https://x.test/y';",
    );
}

#[test]
fn format_all_clauses() {
    assert_format_safe(
        "CREATE OR REPLACE SECURE EXTERNAL FUNCTION db.sch.ef(a VARCHAR) RETURNS VARIANT \
         API_INTEGRATION = my_int HEADERS = ('x-key' = 'v') MAX_BATCH_ROWS = 100 \
         AS 'http://insecure.example.com/run';",
    );
}

#[test]
fn format_multi_statement() {
    assert_format_safe(
        "CREATE EXTERNAL FUNCTION a() RETURNS INT API_INTEGRATION = i AS 'https://a/x';\n\
         CREATE EXTERNAL FUNCTION b() RETURNS INT API_INTEGRATION = j AS 'https://b/y';\n",
    );
}
