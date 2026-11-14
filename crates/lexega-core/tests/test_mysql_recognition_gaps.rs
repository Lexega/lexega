// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! MySQL constructs that must be recognised whole.
//!
//! Each construct below must parse as one statement and round-trip:
//! RENAME TABLE, CREATE FULLTEXT/SPATIAL INDEX, DROP INDEX ... ON,
//! post-column USING BTREE, CREATE DATABASE/SCHEMA charset tails, trailing
//! WITH [CASCADED|LOCAL] CHECK OPTION, GROUP BY ... WITH ROLLUP, the `<=>`
//! null-safe-equality operator (one token), named WINDOW definitions with a
//! frame clause (in every dialect), column-level AUTO_INCREMENT after
//! NOT NULL (kept by the formatter), and an account name (`user@host`) in
//! every spelling.

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
    let config = FormatterConfig {
        dialect: dialect::mysql(),
        ..Default::default()
    };
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

// ── Account names ─────────────────────────────────────────────────────────

/// Each statement that names an account, with the account written in each
/// spelling MySQL accepts (an unquoted host runs through its dots and
/// digits), is one statement and leaves the next one analysed.
#[test]
fn an_account_name_is_read_whole_in_every_spelling() {
    let accounts = [
        "root@localhost",
        "root@127.0.0.1",
        "root@db1.example.com",
        "root@h_1$x",
        "'root'@localhost",
        "`root`@localhost",
        "'root'@127.0.0.1",
        "root@'localhost'",
        "'root'@'%'",
        "\"root\"@\"localhost\"",
        "''@localhost",
        "root @ localhost",
    ];
    for account in accounts {
        for shape in [
            format!("CREATE USER {account} IDENTIFIED BY 'x';"),
            format!("ALTER USER {account} ACCOUNT LOCK;"),
            format!("DROP USER {account};"),
            format!("DROP USER IF EXISTS {account}, b@localhost;"),
            format!("GRANT SELECT ON db.* TO {account};"),
            format!("SET PASSWORD FOR {account} = 'x';"),
            format!("CREATE DEFINER = {account} VIEW v AS SELECT 1 AS c;"),
            format!(
                "CREATE DEFINER = {account} TRIGGER trg BEFORE INSERT ON t \
                 FOR EACH ROW SET NEW.c = 1;"
            ),
            format!(
                "CREATE DEFINER = {account} EVENT e ON SCHEDULE EVERY 1 DAY \
                 DO DELETE FROM t2;"
            ),
        ] {
            parses_token_safe(&format!("{shape}\nSELECT id FROM zz_src;"));
        }
    }
}

#[test]
fn a_set_password_value_is_read_whole_in_every_literal_spelling() {
    for value in [
        "'x'",
        "\"x\"",
        "_utf8mb4'x'",
        "_utf8mb4 'x'",
        "_latin1\"x\"",
        "N'x'",
        "n'x'",
        "X'4142'",
        "0x4142",
        "b'0101'",
        "0b0101",
        "_binary X'4142'",
        "_binary 0x4142",
        "'a' 'b'",
        "_utf8mb4'a' \"b\"",
    ] {
        for shape in [
            format!("SET PASSWORD = {value};"),
            format!("SET PASSWORD FOR root@localhost = {value};"),
            format!("SET PASSWORD FOR 'zz'@'%' = {value}"),
        ] {
            parses_token_safe(&format!("{shape}\nSELECT id FROM zz_src;"));
        }
    }
}

// ── LOCK TABLES / UNLOCK TABLES ─────────────────────────────────────────

#[test]
fn a_table_lock_and_its_release_are_each_read_whole() {
    for sql in [
        "UNLOCK TABLES;",
        "UNLOCK TABLE;",
        "unlock tables",
        "LOCK TABLES zz_t READ, zz_u AS u LOW_PRIORITY WRITE, zz_v READ LOCAL;\n\
         INSERT INTO zz_t VALUES (1);\nUNLOCK TABLES;\nDROP TABLE zz_t;",
    ] {
        parses_token_safe(sql);
    }
    let report = analyze_risk_with_policy_config(
        "LOCK TABLES `zz_t` WRITE;\nDELETE FROM zz_t;\nUNLOCK TABLES;\nSELECT id FROM zz_t;",
        &mysql_cfg(),
    )
    .expect("should analyze");
    let summary = &report.summary;
    assert_eq!(
        (
            summary.statements_parsed,
            summary.statements_analyzed,
            summary.statements_skipped
        ),
        (4, 4, 0)
    );
}

/// The published facts of `sql`'s first statement, read as MySQL.
fn mysql_facts(sql: &str) -> serde_json::Value {
    let config = AnalysisConfig {
        trace_mode: true,
        ..mysql_cfg()
    };
    let report = analyze_risk_with_policy_config(sql, &config).expect("should analyze");
    let json = serde_json::to_value(&report).expect("report serializes");
    json["statement_traces"][0]["facts"].clone()
}

// An account or role written as a string is published as written: only a
// select item's alias is read as a name of the string's value.
#[test]
fn an_account_or_role_written_as_a_string_keeps_its_quotes() {
    for (sql, grantee) in [
        ("GRANT ALL PRIVILEGES ON *.* TO 'root'@'%'", "'ROOT'@'%'"),
        (
            "GRANT SELECT ON zz.t TO 'App'@'localhost'",
            "'APP'@'LOCALHOST'",
        ),
        ("GRANT ALL ON *.* TO 'zz'@'%' WITH GRANT OPTION", "'ZZ'@'%'"),
    ] {
        let facts = mysql_facts(sql);
        assert_eq!(
            facts["privilege"]["grantees"][0]["name"]["normalized"], grantee,
            "{sql}"
        );
    }
    for (sql, target) in [
        ("CREATE USER 'Zz'@'%' IDENTIFIED BY 'x'", "'ZZ'"),
        ("DROP USER 'zz'@'%'", "'ZZ'"),
        ("ALTER USER 'root'@'localhost' IDENTIFIED BY 'x'", "'ROOT'"),
        ("CREATE ROLE 'Admin'", "'ADMIN'"),
    ] {
        let facts = mysql_facts(sql);
        assert_eq!(facts["ddl"]["target"]["name"]["canonical"], target, "{sql}");
    }
}

// ── Administration statements ─────────────────────────────────────────────

/// Each administration statement is read whole and has its own kind.
#[test]
fn test_admin_statements_have_their_kinds() {
    use lexega_core::analyzer::RuleMatch;
    use lexega_core::rules::{build_v1_rule_corpus, load_v1_rules};
    for (sql, kind) in [
        ("ANALYZE TABLE orders;", "analyze_stmt"),
        (
            "ANALYZE NO_WRITE_TO_BINLOG TABLE orders UPDATE HISTOGRAM ON total WITH 16 BUCKETS;",
            "analyze_stmt",
        ),
        (
            "ANALYZE TABLE db1.t DROP HISTOGRAM ON a, b;",
            "analyze_stmt",
        ),
        ("OPTIMIZE LOCAL TABLE audit_log, orders;", "optimize_table"),
        ("CHECK TABLE orders FOR UPGRADE QUICK;", "check_table"),
        ("CHECKSUM TABLE orders EXTENDED;", "checksum_table"),
        ("REPAIR TABLE a, b QUICK USE_FRM;", "repair_table"),
        ("FLUSH PRIVILEGES;", "flush"),
        ("FLUSH LOCAL RELAY LOGS FOR CHANNEL c1, STATUS;", "flush"),
        ("FLUSH TABLES customers, orders WITH READ LOCK;", "flush"),
        ("FLUSH TABLES WITH READ LOCK;", "flush"),
        ("KILL QUERY 12345;", "kill"),
        ("KILL CONNECTION @pid;", "kill"),
        ("ALTER INSTANCE ROTATE INNODB MASTER KEY;", "alter_instance"),
        (
            "ALTER INSTANCE RELOAD TLS FOR CHANNEL mysql_admin NO ROLLBACK ON ERROR;",
            "alter_instance",
        ),
        ("XA START 'txn-1';", "xa_transaction"),
        (
            "XA END 'txn-1', 'b', 1 SUSPEND FOR MIGRATE;",
            "xa_transaction",
        ),
        ("XA COMMIT 'txn-1' ONE PHASE;", "xa_transaction"),
        ("XA RECOVER CONVERT XID;", "xa_transaction"),
        (
            "RENAME USER 'reporter'@'localhost' TO 'analyst'@'localhost', bob TO robert@'%';",
            "rename_user",
        ),
    ] {
        parses_token_safe(sql);
        let custom = load_v1_rules(&format!(
            r#"
rules:
  - id: TEST-ADMIN-KIND
    risk_level: info
    message: "kind"
    triggers:
      all_of:
        - kind: {kind}
"#
        ))
        .expect("rules parse");
        let cfg = AnalysisConfig {
            dialect: Some(dialect::mysql()),
            custom_rules: Some(build_v1_rule_corpus(custom, false).expect("corpus").into()),
            ..Default::default()
        };
        let report = analyze_risk_with_policy_config(sql, &cfg).expect("should analyze");
        let ids: Vec<String> = report
            .entries()
            .map(|RuleMatch::Analysis(a)| a.matched_rule.clone())
            .collect();
        assert_eq!(ids, ["TEST-ADMIN-KIND"], "{sql} is {kind}");
    }
    // The statements inside a routine's body.
    parses_token_safe(
        "CREATE PROCEDURE p() BEGIN FLUSH PRIVILEGES; KILL QUERY 5; ANALYZE TABLE t; END;",
    );
}

/// A form another dialect writes keeps that dialect's reader.
#[test]
fn test_admin_shapes_leave_other_dialects_forms() {
    for (sql, d) in [
        ("REPAIR TABLE t SYNC PARTITIONS;", dialect::databricks()),
        ("REPAIR TABLE t;", dialect::databricks()),
        ("KILL 53;", dialect::mssql()),
        (
            "KILL QUERY NOTIFICATION SUBSCRIPTION ALL;",
            dialect::mssql(),
        ),
        ("ANALYZE orders;", dialect::postgres()),
    ] {
        let cfg = AnalysisConfig {
            dialect: Some(d),
            ..Default::default()
        };
        let report = analyze_risk_with_policy_config(sql, &cfg).expect("should analyze");
        assert_eq!(report.summary.statements_skipped, 0, "{sql}");
    }
}

/// `START TRANSACTION` with MySQL's characteristics, at the top level, and
/// EXPLAIN's `FORMAT =`.
#[test]
fn test_start_transaction_characteristics_and_explain_format() {
    parses_token_safe("START TRANSACTION WITH CONSISTENT SNAPSHOT, READ WRITE;");
    parses_token_safe("START TRANSACTION READ ONLY;");
    parses_token_safe("START TRANSACTION;");
    parses_token_safe("EXPLAIN FORMAT=JSON SELECT id FROM orders WHERE total > 10;");
    parses_token_safe("EXPLAIN ANALYZE FORMAT = TREE SELECT 1;");
}

// ── The client's DELIMITER ────────────────────────────────────────────────

/// A routine written between `DELIMITER $$` and `DELIMITER ;` is read whole
/// and its body analyzed.
#[test]
fn test_delimiter_wrapped_routine_is_analyzed() {
    use lexega_core::analyzer::RuleMatch;
    let sql = "DELIMITER $$\nCREATE PROCEDURE p(IN s VARCHAR(64))\nBEGIN\n  SET @q = CONCAT('SELECT * FROM t_', s);\n  PREPARE stmt FROM @q;\n  EXECUTE stmt;\nEND$$\nDELIMITER ;\nSELECT 1;\n";
    parses_token_safe(sql);
    let report = analyze_risk_with_policy_config(sql, &mysql_cfg()).expect("should analyze");
    let ids: Vec<String> = report
        .entries()
        .map(|RuleMatch::Analysis(a)| a.matched_rule.clone())
        .collect();
    // The body's PREPARE runs a concatenation: PROC-DYNSQL where `@q` is not
    // resolved, DYNSQL-CONCAT where analysis resolves it.
    assert!(
        ids.iter()
            .any(|id| id == "PROC-DYNSQL" || id == "DYNSQL-CONCAT"),
        "{ids:?}"
    );
}
