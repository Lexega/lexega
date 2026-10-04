// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! MySQL constructs that must be recognised whole.
//!
//! Each construct below must parse as one statement and round-trip:
//! RENAME TABLE, CREATE FULLTEXT/SPATIAL INDEX, DROP INDEX ... ON,
//! post-column USING BTREE, CREATE DATABASE/SCHEMA charset tails, trailing
//! WITH [CASCADED|LOCAL] CHECK OPTION, GROUP BY ... WITH ROLLUP, the `<=>`
//! null-safe-equality operator (one token), named WINDOW definitions with a
//! frame clause (in every dialect), and column-level AUTO_INCREMENT after
//! NOT NULL (kept by the formatter).

use lexega_core::analyzer::AnalysisConfig;
use lexega_core::api::analyze_risk_with_policy_config;
use lexega_core::{
    dialect, format_sql_with_config, verify_formatting_safe_with_dialect, FormatterConfig,
};

fn mysql_cfg() -> AnalysisConfig {
    AnalysisConfig {
        dialect: Some(dialect::mysql()),
        ..Default::default()
    }
}

/// Parses (no opaque fallback, no phantom split) and round-trips token-safe.
fn parses_token_safe(sql: &str) -> String {
    let mut config = FormatterConfig::default();
    config.dialect = dialect::mysql();
    let out = format_sql_with_config(sql, &config).expect("should format");
    verify_formatting_safe_with_dialect(sql, &out, config.dialect.as_ref())
        .expect("formatter must preserve all tokens");
    let report = analyze_risk_with_policy_config(sql, &mysql_cfg()).expect("should analyze");
    assert_eq!(
        report.summary.statements_skipped, 0,
        "statement must be parsed whole, not split/skipped: {sql}"
    );
    out
}

// ── RENAME TABLE ──────────────────────────────────────────────────────────

#[test]
fn test_rename_table_single() {
    parses_token_safe("RENAME TABLE orders_archive TO orders_archive_old;");
}

#[test]
fn test_rename_table_multi_qualified() {
    let out = parses_token_safe("RENAME TABLE a TO b, sch.c TO sch.d;");
    assert!(out.contains("sch.c TO sch.d"), "all pairs preserved: {out}");
}

// ── Index DDL ─────────────────────────────────────────────────────────────

#[test]
fn test_create_fulltext_index() {
    parses_token_safe("CREATE FULLTEXT INDEX ftx_notes ON orders (notes);");
}

#[test]
fn test_create_spatial_index() {
    parses_token_safe("CREATE SPATIAL INDEX sx ON geo (pt);");
}

#[test]
fn test_drop_index_on_table() {
    parses_token_safe("DROP INDEX idx_total ON orders;");
}

#[test]
fn test_create_index_using_btree_after_columns() {
    parses_token_safe("CREATE INDEX idx_total ON orders (total) USING BTREE;");
}

// ── CREATE DATABASE / SCHEMA charset tails ────────────────────────────────

#[test]
fn test_create_database_charset_collate() {
    parses_token_safe(
        "CREATE DATABASE app_db DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci;",
    );
    parses_token_safe("CREATE DATABASE d2 CHARSET = latin1;");
    parses_token_safe("CREATE DATABASE d3 DEFAULT ENCRYPTION = 'Y';");
}

#[test]
fn test_create_schema_charset() {
    parses_token_safe("CREATE SCHEMA s1 DEFAULT CHARACTER SET utf8mb4;");
}

// ── CREATE VIEW ... WITH CHECK OPTION ─────────────────────────────────────

#[test]
fn test_view_with_check_option() {
    parses_token_safe(
        "CREATE VIEW active_customers AS SELECT id FROM customers WHERE active = 1 WITH CHECK OPTION;",
    );
    parses_token_safe("CREATE VIEW v2 AS SELECT a FROM t WHERE a > 0 WITH CASCADED CHECK OPTION;");
    parses_token_safe("CREATE VIEW v3 AS SELECT a FROM t WHERE a > 0 WITH LOCAL CHECK OPTION;");
}

// ── GROUP BY ... WITH ROLLUP ──────────────────────────────────────────────

#[test]
fn test_group_by_with_rollup() {
    parses_token_safe(
        "SELECT category, region, SUM(amount) FROM sales GROUP BY category, region WITH ROLLUP;",
    );
}

#[test]
fn test_group_by_with_rollup_then_having() {
    parses_token_safe("SELECT a, COUNT(*) FROM t GROUP BY a WITH ROLLUP HAVING COUNT(*) > 1;");
}

#[test]
fn test_group_by_then_cte_statement_unaffected() {
    // WITH after GROUP BY that is NOT a modifier belongs to the next statement.
    parses_token_safe("SELECT a FROM t GROUP BY a;\nWITH c AS (SELECT 1 AS x) SELECT * FROM c;");
}

// ── <=> null-safe equality ────────────────────────────────────────────────

#[test]
fn test_null_safe_equality_operator() {
    let out = parses_token_safe("SELECT id FROM customers WHERE loyalty_points <=> NULL;");
    assert!(out.contains("<=>"), "operator preserved: {out}");
}

#[test]
fn test_null_safe_eq_with_index_hint() {
    // The golden-file shape: DISTINCT + USE INDEX + <=> in one statement.
    parses_token_safe(
        "SELECT DISTINCT c.id, c.email FROM customers c USE INDEX (idx_status_created) WHERE c.loyalty_points <=> NULL;",
    );
}

#[test]
fn test_le_operator_unaffected() {
    let out = parses_token_safe("SELECT a <= b FROM t;");
    assert!(out.contains("<="), "plain <= preserved: {out}");
    assert!(!out.contains("<=>"), "no false <=> match: {out}");
}

// ── Named WINDOW with frame clause ────────────────────────────────────────

#[test]
fn test_named_window_with_rows_frame() {
    parses_token_safe(
        "SELECT id, SUM(amount) OVER w AS running_total FROM orders WINDOW w AS (PARTITION BY customer_id ORDER BY created_at ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW);",
    );
}

#[test]
fn test_named_window_with_range_interval_frame() {
    parses_token_safe(
        "SELECT a, AVG(b) OVER w2 FROM t WINDOW w2 AS (ORDER BY c RANGE BETWEEN INTERVAL '1' DAY PRECEDING AND CURRENT ROW);",
    );
}

// ── AUTO_INCREMENT column tail (formatter drop) ───────────────────────────

#[test]
fn test_auto_increment_survives_formatting() {
    for sql in [
        "CREATE TABLE t1 (id INT NOT NULL AUTO_INCREMENT PRIMARY KEY);",
        "CREATE TABLE t2 (id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT, PRIMARY KEY (id));",
        "CREATE TABLE t3 (id INT AUTO_INCREMENT PRIMARY KEY);",
    ] {
        let out = parses_token_safe(sql);
        assert!(
            out.to_uppercase().contains("AUTO_INCREMENT"),
            "AUTO_INCREMENT must survive formatting: {out}"
        );
    }
}
