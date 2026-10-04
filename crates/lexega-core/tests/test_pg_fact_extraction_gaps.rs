// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Tests for PostgreSQL fact extraction.
//!
//! Validates that the facts surface:
//! 1. Writable CTEs (WITH ... DELETE/INSERT/UPDATE ... SELECT FROM cte)
//! 2. ON CONFLICT subqueries (DO UPDATE SET x = (SELECT ...))
//! 3. RETURNING clause expressions
//! 4. EXPLAIN inner statement table extraction
//! 5. PREPARE body table extraction
//! 6. COPY table directionality (FROM → written, TO → read)
//! 7. INSERT/UPDATE/DELETE WITH clause CTE propagation
//!
//! Asserts on `StatementFacts.query.{reads,writes}_table` (per-stmt)
//! and `StatementFacts.ddl.target` (for `COPY <table> FROM/TO …`).

use lexega_core::{analyzer::AnalysisConfig, PostgresDialect};

use lexega_core::api::analyze_risk_with_policy_config;
use std::sync::Arc;

fn pg_analyze(sql: &str) -> lexega_core::analyzer::AnalysisReport {
    let config = AnalysisConfig {
        dialect: Some(Arc::new(PostgresDialect)),
        trace_mode: true,
        ..Default::default()
    };
    analyze_risk_with_policy_config(sql, &config).expect("analysis should succeed")
}

/// Union of `reads_table` + `writes_table` (query facts) and
/// `ddl.target.name` (DDL facts) across every per-statement fact
/// carrier in the report.
fn tables_accessed_list(report: &lexega_core::analyzer::AnalysisReport) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for stmt in &report.statement_signals {
        let Some(facts) = stmt.facts.as_ref() else {
            continue;
        };
        if let Some(query) = facts.query.as_ref() {
            for te in &query.reads_table {
                out.push(te.table.name.normalized.to_uppercase());
            }
            for te in &query.writes_table {
                out.push(te.table.name.normalized.to_uppercase());
            }
        }
        if let Some(ddl) = facts.ddl.as_ref() {
            if let Some(target) = ddl.target.as_ref() {
                out.push(target.name.name.normalized.to_uppercase());
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

fn has_table_accessed(report: &lexega_core::analyzer::AnalysisReport, table_name: &str) -> bool {
    tables_accessed_list(report)
        .iter()
        .any(|t| t.eq_ignore_ascii_case(table_name))
}

// ============================================================================
// 1. Writable CTEs
// ============================================================================

#[test]
fn test_writable_cte_delete_returning_into_insert() {
    // Classic row-migration: DELETE from old table, INSERT into new table
    let sql = r#"
        WITH moved AS (
            DELETE FROM old_data RETURNING *
        )
        INSERT INTO new_data SELECT * FROM moved;
    "#;
    let report = pg_analyze(sql);

    // old_data is both read (RETURNING) and written (DELETE)
    // new_data is written (INSERT)
    assert!(
        report.summary.tables_written >= 1,
        "Should detect tables written. tables_written={}, tables_read={}",
        report.summary.tables_written,
        report.summary.tables_read
    );
    assert!(
        has_table_accessed(&report, "old_data"),
        "old_data should be in tables_accessed. Found: {:?}",
        tables_accessed_list(&report)
    );
    assert!(
        has_table_accessed(&report, "new_data"),
        "new_data should be in tables_accessed. Found: {:?}",
        tables_accessed_list(&report)
    );
}

#[test]
fn test_writable_cte_update_returning() {
    let sql = r#"
        WITH updated AS (
            UPDATE inventory SET qty = qty - 1 WHERE qty > 0 RETURNING product_id, qty
        )
        SELECT product_id, qty FROM updated;
    "#;
    let report = pg_analyze(sql);

    assert!(
        has_table_accessed(&report, "inventory"),
        "inventory should be in tables_accessed. Found: {:?}",
        tables_accessed_list(&report)
    );
    // The writable CTE body (UPDATE) writes `inventory`; the outer
    // statement is a SELECT and `summary.tables_written` only counts
    // DML_WRITE-classified top-level statements. The write surface
    // is exposed via the per-statement
    // `StatementFacts.query.writes_table` carrier — verify
    // `inventory` appears there.
    let has_write_signal = report.statement_signals.iter().any(|s| {
        s.facts
            .as_ref()
            .and_then(|f| f.query.as_ref())
            .map(|q| {
                q.writes_table
                    .iter()
                    .any(|te| te.table.name.normalized.eq_ignore_ascii_case("INVENTORY"))
            })
            .unwrap_or(false)
    });
    assert!(
        has_write_signal,
        "inventory write should surface on query.writes_table"
    );
}

#[test]
fn test_writable_cte_insert_returning() {
    let sql = r#"
        WITH inserted AS (
            INSERT INTO audit_log (action) VALUES ('test') RETURNING id
        )
        SELECT id FROM inserted;
    "#;
    let report = pg_analyze(sql);

    assert!(
        has_table_accessed(&report, "audit_log"),
        "audit_log should be in tables_accessed. Found: {:?}",
        tables_accessed_list(&report)
    );
}

// ============================================================================
// 2. INSERT ... WITH clause CTE propagation
// ============================================================================

#[test]
fn test_insert_with_cte_reads_source() {
    let sql = r#"
        WITH src AS (SELECT id, name FROM staging_table WHERE active)
        INSERT INTO prod_table SELECT * FROM src;
    "#;
    let report = pg_analyze(sql);

    assert!(
        has_table_accessed(&report, "staging_table"),
        "staging_table should be extracted from CTE body. Found: {:?}",
        tables_accessed_list(&report)
    );
    assert!(
        has_table_accessed(&report, "prod_table"),
        "prod_table should be in tables_accessed (INSERT target). Found: {:?}",
        tables_accessed_list(&report)
    );
}

#[test]
fn test_update_with_cte_reads_source() {
    let sql = r#"
        WITH latest AS (SELECT user_id, max(score) as best FROM scores GROUP BY user_id)
        UPDATE users SET best_score = latest.best
        FROM latest WHERE users.id = latest.user_id;
    "#;
    let report = pg_analyze(sql);

    assert!(
        has_table_accessed(&report, "scores"),
        "scores should be extracted from CTE body. Found: {:?}",
        tables_accessed_list(&report)
    );
    assert!(
        has_table_accessed(&report, "users"),
        "users should be in tables_accessed (UPDATE target). Found: {:?}",
        tables_accessed_list(&report)
    );
}

#[test]
fn test_delete_with_cte_reads_source() {
    let sql = r#"
        WITH stale AS (SELECT id FROM sessions WHERE last_active < NOW() - INTERVAL '30 days')
        DELETE FROM sessions WHERE id IN (SELECT id FROM stale);
    "#;
    let report = pg_analyze(sql);

    assert!(
        has_table_accessed(&report, "sessions"),
        "sessions should be in tables_accessed. Found: {:?}",
        tables_accessed_list(&report)
    );
}

// ============================================================================
// 3. ON CONFLICT subquery tracking
// ============================================================================

#[test]
fn test_on_conflict_do_update_with_subquery() {
    let sql = r#"
        INSERT INTO products (id, price)
        VALUES (1, 100)
        ON CONFLICT (id) DO UPDATE
        SET price = (SELECT max(price) FROM price_history WHERE product_id = EXCLUDED.id);
    "#;
    let report = pg_analyze(sql);

    assert!(
        has_table_accessed(&report, "products"),
        "products should be in tables_accessed (INSERT target). Found: {:?}",
        tables_accessed_list(&report)
    );
    assert!(
        has_table_accessed(&report, "price_history"),
        "price_history should be in tables_accessed (ON CONFLICT subquery). Found: {:?}",
        tables_accessed_list(&report)
    );
}

#[test]
fn test_on_conflict_do_update_where_subquery() {
    let sql = r#"
        INSERT INTO kv_store (key, value)
        VALUES ('k', 'v')
        ON CONFLICT (key) DO UPDATE
        SET value = EXCLUDED.value
        WHERE kv_store.updated_at < (SELECT max(ts) FROM change_log);
    "#;
    let report = pg_analyze(sql);

    assert!(
        has_table_accessed(&report, "kv_store"),
        "kv_store should be in tables_accessed. Found: {:?}",
        tables_accessed_list(&report)
    );
    // The WHERE clause subquery references change_log
    assert!(
        has_table_accessed(&report, "change_log"),
        "change_log should be in tables_accessed (ON CONFLICT WHERE subquery). Found: {:?}",
        tables_accessed_list(&report)
    );
}

// ============================================================================
// 4. RETURNING clause
// ============================================================================

#[test]
fn test_delete_returning_basic() {
    let sql = "DELETE FROM expired_tokens WHERE expires_at < NOW() RETURNING token_id;";
    let report = pg_analyze(sql);

    assert!(
        has_table_accessed(&report, "expired_tokens"),
        "expired_tokens should be in tables_accessed. Found: {:?}",
        tables_accessed_list(&report)
    );
    assert!(
        report.summary.tables_written >= 1,
        "DELETE should count as table written"
    );
}

#[test]
fn test_insert_returning_basic() {
    let sql = "INSERT INTO users (name) VALUES ('Alice') RETURNING id, created_at;";
    let report = pg_analyze(sql);

    assert!(
        has_table_accessed(&report, "users"),
        "users should be in tables_accessed. Found: {:?}",
        tables_accessed_list(&report)
    );
}

#[test]
fn test_update_returning_basic() {
    let sql = "UPDATE accounts SET balance = balance + 100 WHERE id = 1 RETURNING id, balance;";
    let report = pg_analyze(sql);

    assert!(
        has_table_accessed(&report, "accounts"),
        "accounts should be in tables_accessed. Found: {:?}",
        tables_accessed_list(&report)
    );
}

// ============================================================================
// 5. EXPLAIN
// ============================================================================

#[test]
fn test_explain_select_extracts_tables() {
    let sql = "EXPLAIN SELECT * FROM customers WHERE region = 'US';";
    let report = pg_analyze(sql);

    assert!(
        has_table_accessed(&report, "customers"),
        "EXPLAIN should extract tables from inner SELECT. Found: {:?}",
        tables_accessed_list(&report)
    );
    assert!(
        report.summary.tables_read >= 1,
        "EXPLAIN SELECT should count tables_read"
    );
}

#[test]
fn test_explain_analyze_select() {
    let sql = "EXPLAIN ANALYZE SELECT o.id FROM orders o JOIN products p ON o.product_id = p.id;";
    let report = pg_analyze(sql);

    assert!(
        has_table_accessed(&report, "orders"),
        "EXPLAIN ANALYZE should extract 'orders'. Found: {:?}",
        tables_accessed_list(&report)
    );
    assert!(
        has_table_accessed(&report, "products"),
        "EXPLAIN ANALYZE should extract 'products'. Found: {:?}",
        tables_accessed_list(&report)
    );
}

#[test]
fn test_explain_insert() {
    let sql = "EXPLAIN INSERT INTO archive SELECT * FROM recent_data WHERE age > 365;";
    let report = pg_analyze(sql);

    assert!(
        has_table_accessed(&report, "archive"),
        "EXPLAIN INSERT should extract target table 'archive'. Found: {:?}",
        tables_accessed_list(&report)
    );
    assert!(
        has_table_accessed(&report, "recent_data"),
        "EXPLAIN INSERT should extract source table 'recent_data'. Found: {:?}",
        tables_accessed_list(&report)
    );
}

// ============================================================================
// 6. PREPARE / EXECUTE
// ============================================================================

#[test]
fn test_prepare_select_extracts_tables() {
    let sql = "PREPARE user_query AS SELECT * FROM users WHERE id = $1;";
    let report = pg_analyze(sql);

    assert!(
        has_table_accessed(&report, "users"),
        "PREPARE should extract tables from body SELECT. Found: {:?}",
        tables_accessed_list(&report)
    );
}

#[test]
fn test_prepare_insert_extracts_tables() {
    let sql = "PREPARE add_user AS INSERT INTO users (name) VALUES ($1);";
    let report = pg_analyze(sql);

    assert!(
        has_table_accessed(&report, "users"),
        "PREPARE INSERT should extract target table. Found: {:?}",
        tables_accessed_list(&report)
    );
}

#[test]
fn test_execute_is_recognized() {
    let sql = "EXECUTE user_query(42);";
    let report = pg_analyze(sql);

    // EXECUTE doesn't reference tables directly, but should be analyzed (not skipped)
    assert_eq!(
        report.summary.statements_analyzed, 1,
        "EXECUTE should be analyzed, not skipped. analyzed={}, skipped={}",
        report.summary.statements_analyzed, report.summary.statements_skipped
    );
}

#[test]
fn test_deallocate_is_recognized() {
    let sql = "DEALLOCATE user_query;";
    let report = pg_analyze(sql);

    assert_eq!(
        report.summary.statements_analyzed, 1,
        "DEALLOCATE should be analyzed, not skipped. analyzed={}, skipped={}",
        report.summary.statements_analyzed, report.summary.statements_skipped
    );
}

// ============================================================================
// 7. PG COPY table directionality
// ============================================================================

#[test]
fn test_copy_from_file_writes_table() {
    let sql = "COPY employees FROM '/tmp/employees.csv' WITH (FORMAT csv, HEADER true);";
    let report = pg_analyze(sql);

    assert!(
        has_table_accessed(&report, "employees"),
        "COPY FROM should track 'employees'. Found: {:?}",
        tables_accessed_list(&report)
    );
    assert!(
        report.summary.tables_written >= 1,
        "COPY FROM should count as table written. tables_written={}",
        report.summary.tables_written
    );
}

#[test]
fn test_copy_to_file_reads_table() {
    let sql = "COPY employees TO '/tmp/employees_export.csv' WITH (FORMAT csv, HEADER true);";
    let report = pg_analyze(sql);

    assert!(
        has_table_accessed(&report, "employees"),
        "COPY TO should track 'employees'. Found: {:?}",
        tables_accessed_list(&report)
    );
    assert!(
        report.summary.tables_read >= 1,
        "COPY TO should count as table read. tables_read={}",
        report.summary.tables_read
    );
}

#[test]
fn test_copy_qualified_table() {
    let sql = "COPY myschema.employees FROM '/tmp/data.csv';";
    let report = pg_analyze(sql);

    assert!(
        has_table_accessed(&report, "employees"),
        "COPY with qualified name should extract table 'employees'. Found: {:?}",
        tables_accessed_list(&report)
    );
}

// ============================================================================
// 8. VALUES standalone
// ============================================================================

#[test]
fn test_values_query_standalone() {
    let sql = "VALUES (1, 'a'), (2, 'b'), (3, 'c');";
    let report = pg_analyze(sql);

    // VALUES doesn't reference any tables
    assert_eq!(
        report.summary.statements_analyzed, 1,
        "VALUES should be analyzed, not skipped. analyzed={}, skipped={}",
        report.summary.statements_analyzed, report.summary.statements_skipped
    );
}

// ============================================================================
// 9. Multi-statement coverage (catch NodeId collision bugs)
// ============================================================================

#[test]
fn test_multi_explain_no_collision() {
    let sql = r#"
        EXPLAIN SELECT * FROM table_a;
        EXPLAIN SELECT * FROM table_b;
        EXPLAIN SELECT * FROM table_c;
    "#;
    let report = pg_analyze(sql);

    assert!(
        report.summary.statements_analyzed >= 3,
        "All 3 EXPLAIN statements should be analyzed. analyzed={}, skipped={}",
        report.summary.statements_analyzed,
        report.summary.statements_skipped
    );
    assert!(
        has_table_accessed(&report, "table_a"),
        "table_a should be extracted"
    );
    assert!(
        has_table_accessed(&report, "table_b"),
        "table_b should be extracted"
    );
    assert!(
        has_table_accessed(&report, "table_c"),
        "table_c should be extracted"
    );
}

#[test]
fn test_multi_prepare_no_collision() {
    let sql = r#"
        PREPARE q1 AS SELECT * FROM alpha;
        PREPARE q2 AS SELECT * FROM beta;
    "#;
    let report = pg_analyze(sql);

    assert!(
        report.summary.statements_analyzed >= 2,
        "Both PREPARE statements should be analyzed. analyzed={}, skipped={}",
        report.summary.statements_analyzed,
        report.summary.statements_skipped
    );
    assert!(
        has_table_accessed(&report, "alpha"),
        "alpha should be extracted from PREPARE q1"
    );
    assert!(
        has_table_accessed(&report, "beta"),
        "beta should be extracted from PREPARE q2"
    );
}

#[test]
fn test_mixed_pg_statements_no_collision() {
    let sql = r#"
        COPY src_table TO '/tmp/export.csv';
        EXPLAIN SELECT count(*) FROM metrics;
        PREPARE ins AS INSERT INTO logs (msg) VALUES ($1);
        EXECUTE ins('hello');
        DEALLOCATE ins;
    "#;
    let report = pg_analyze(sql);

    assert!(
        report.summary.statements_analyzed >= 5,
        "All 5 statements should be analyzed. analyzed={}, skipped={}",
        report.summary.statements_analyzed,
        report.summary.statements_skipped
    );
    assert!(
        has_table_accessed(&report, "src_table"),
        "src_table should be extracted from COPY TO"
    );
    assert!(
        has_table_accessed(&report, "metrics"),
        "metrics should be extracted from EXPLAIN SELECT"
    );
    assert!(
        has_table_accessed(&report, "logs"),
        "logs should be extracted from PREPARE INSERT"
    );
}
