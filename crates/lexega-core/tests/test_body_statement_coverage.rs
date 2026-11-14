// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Invariant: rule evaluation enumerates EVERY statement at EVERY nesting depth,
//! uniformly across rule families and across all body-bearing constructs.
//!
//! Three things have to hold: (A) the privilege and policy-attachment rule
//! families see a GRANT / REVOKE / DENY inside any body, not only top-level
//! `script.stmts`; (B) `CREATE TASK` and MSSQL `CREATE TRIGGER` bodies are
//! enumerated for every family; (C) the scripting-block statement dispatcher
//! parses every statement type (GRANT / REVOKE / DENY / …) inside a
//! `BEGIN … END` block.
//!
//! Each test puts a statement that DOES fire a rule inside a body and asserts
//! the rule fires — i.e. the inner statement was both parsed and rule-evaluated.

use lexega_core::analyzer::{AnalysisConfig, RuleMatch};
use lexega_core::api::analyze_risk_with_policy_config;
use lexega_core::dialect;

fn rule_ids(sql: &str, d: lexega_core::DialectRef) -> Vec<String> {
    let cfg = AnalysisConfig {
        dialect: Some(d),
        ..Default::default()
    };
    let report = analyze_risk_with_policy_config(sql, &cfg).expect("should analyze");
    report
        .findings
        .iter()
        .map(|RuleMatch::Analysis(a)| a.matched_rule.clone())
        .collect()
}

fn assert_fires(sql: &str, d: lexega_core::DialectRef, rule: &str) {
    let ids = rule_ids(sql, d);
    assert!(
        ids.contains(&rule.to_string()),
        "expected {rule} to fire (inner statement must be parsed + analyzed). Got: {ids:?}\nSQL: {sql}"
    );
}

// A data-modifying CTE runs its write whatever the query around it reads:
// an unbounded one is reported at the write, a bounded one is not.
#[test]
fn test_unbounded_write_in_a_data_modifying_cte_fires() {
    for sql in [
        "WITH d AS (DELETE FROM users RETURNING *) SELECT * FROM d;",
        "WITH u AS (UPDATE users SET active = false RETURNING id) SELECT count(*) FROM u;",
        "WITH d AS (DELETE FROM users RETURNING *) INSERT INTO archive SELECT * FROM d;",
    ] {
        assert_fires(sql, dialect::postgres(), "DML-WRITE-UNBOUNDED");
    }
    let ids = rule_ids(
        "WITH d AS (DELETE FROM users WHERE id = 1 RETURNING *) SELECT * FROM d;",
        dialect::postgres(),
    );
    assert!(!ids.contains(&"DML-WRITE-UNBOUNDED".to_string()), "{ids:?}");
}

// The query around a data-modifying CTE already reads the write's tables:
// a missing one is reported once, not again for the write.
#[test]
fn a_finding_in_a_data_modifying_cte_is_reported_once() {
    use lexega_core::api::analyze_risk_with_policy_config_and_catalog_index;
    use lexega_core::catalog::{CatalogIndex, CatalogSnapshot};
    let snapshot: CatalogSnapshot = serde_json::from_str(
        r#"{"schema_version": 2, "databases": [{"name": "ANALYTICS", "schemas": [{"name": "PUBLIC",
            "tables": [{"name": "USERS", "kind": "Table", "columns": [{"name": "ID"}]}]}]}]}"#,
    )
    .expect("snapshot");
    let catalog = CatalogIndex::from_snapshot(snapshot).expect("index");
    let cfg = AnalysisConfig {
        dialect: Some(dialect::postgres()),
        ..Default::default()
    };
    let report = analyze_risk_with_policy_config_and_catalog_index(
        "WITH d AS (DELETE FROM analytics.public.users USING analytics.public.absent a \
         WHERE a.id = users.id RETURNING users.id) SELECT id FROM d;",
        &cfg,
        &catalog,
    )
    .expect("should analyze");
    let unknown: Vec<_> = report
        .findings
        .iter()
        .map(|RuleMatch::Analysis(a)| a)
        .filter(|a| a.matched_rule == "CAT-TBL-UNKNOWN")
        .collect();
    assert_eq!(unknown.len(), 1, "{unknown:?}");
    assert!(
        unknown[0].findings_merged.unwrap_or(1) == 1,
        "{:?}",
        unknown[0].message
    );
    // A write reads the CTEs before it in its clause: `c` is no table.
    let report = analyze_risk_with_policy_config_and_catalog_index(
        "WITH c AS (SELECT id FROM analytics.public.users), \
         w AS (DELETE FROM analytics.public.users USING c WHERE c.id = users.id RETURNING users.id) \
         SELECT id FROM w;",
        &cfg,
        &catalog,
    )
    .expect("should analyze");
    let rules: Vec<_> = report
        .findings
        .iter()
        .map(|RuleMatch::Analysis(a)| a.matched_rule.as_str())
        .collect();
    assert!(!rules.contains(&"CAT-TBL-UNKNOWN"), "{rules:?}");
}

// ── (A) Privilege family enumerates bodies ───────────────────────────────

#[test]
fn test_grant_in_mysql_procedure_body_fires() {
    assert_fires(
        "CREATE PROCEDURE p() BEGIN GRANT ALL ON db.* TO 'x'@'%'; END;",
        dialect::mysql(),
        "GRT-ALL-PRIV",
    );
}

#[test]
fn test_grant_in_mysql_trigger_body_fires() {
    assert_fires(
        "CREATE TRIGGER t AFTER INSERT ON u FOR EACH ROW \
         BEGIN GRANT ALL ON db.* TO 'x'@'%'; END;",
        dialect::mysql(),
        "GRT-ALL-PRIV",
    );
}

#[test]
fn test_grant_in_mysql_event_body_fires() {
    assert_fires(
        "CREATE EVENT e ON SCHEDULE EVERY 1 DAY DO GRANT ALL ON db.* TO 'x'@'%';",
        dialect::mysql(),
        "GRT-ALL-PRIV",
    );
}

#[test]
fn test_grant_in_nested_control_flow_fires() {
    assert_fires(
        "CREATE PROCEDURE p() BEGIN IF 1 = 1 THEN GRANT ALL ON db.* TO 'x'@'%'; END IF; END;",
        dialect::mysql(),
        "GRT-ALL-PRIV",
    );
}

#[test]
fn test_grant_in_snowflake_task_body_fires() {
    assert_fires(
        "CREATE TASK t WAREHOUSE = w SCHEDULE = '1 minute' AS GRANT ALL ON DATABASE d TO ROLE r;",
        dialect::snowflake(),
        "GRT-ALL-PRIV",
    );
}

// ── (B) Body-bearing statement types recurse for DDL too ─────────────────

#[test]
fn test_drop_in_snowflake_task_body_fires() {
    assert_fires(
        "CREATE TASK t WAREHOUSE = w SCHEDULE = '1 minute' AS DROP TABLE audit_log;",
        dialect::snowflake(),
        "TBL-DROP",
    );
}

#[test]
fn test_drop_in_mssql_trigger_body_fires() {
    assert_fires(
        "CREATE TRIGGER tr ON dbo.t AFTER INSERT AS BEGIN DROP TABLE shadow; END;",
        dialect::mssql(),
        "TBL-DROP",
    );
}

// ── (C) Block dispatcher recognizes every statement type (no opacity) ────

#[test]
fn test_block_body_statements_not_skipped() {
    // The privilege statement inside the block must be analyzed, not dropped as
    // opaque.
    let cfg = AnalysisConfig {
        dialect: Some(dialect::mysql()),
        ..Default::default()
    };
    // A privilege statement and a DDL statement in the same block body — both
    // must be analyzed.
    let report = analyze_risk_with_policy_config(
        "CREATE PROCEDURE p() BEGIN GRANT ALL ON db.* TO 'x'@'%'; DROP TABLE staging; END;",
        &cfg,
    )
    .expect("should analyze");
    assert_eq!(
        report.summary.statements_skipped, 0,
        "no statement in the block body may be skipped as opaque"
    );
}

// ── MySQL REVOKE `user@host` grantee parity (grant/revoke) ───────────────
//
// GRANT routes to a MySQL-aware grantee reader that consumes the `@host`
// suffix; the generic REVOKE path did not, so `REVOKE … FROM 'u'@'h'` went
// opaque (at top level and inside bodies). Both forms must now parse.

fn assert_not_skipped(sql: &str, d: lexega_core::DialectRef) {
    let cfg = AnalysisConfig {
        dialect: Some(d),
        ..Default::default()
    };
    let report = analyze_risk_with_policy_config(sql, &cfg).expect("should analyze");
    assert_eq!(
        report.summary.statements_skipped, 0,
        "statement must be parsed, not skipped: {sql}"
    );
}

#[test]
fn test_mysql_revoke_user_at_host_quoted() {
    assert_not_skipped("REVOKE SELECT ON db.t FROM 'y'@'%';", dialect::mysql());
}

#[test]
fn test_mysql_revoke_user_at_host_unquoted() {
    assert_not_skipped("REVOKE ALL ON db.* FROM y@localhost;", dialect::mysql());
}

#[test]
fn test_mysql_revoke_user_at_host_in_body() {
    assert_not_skipped(
        "CREATE PROCEDURE p() BEGIN REVOKE SELECT ON db.t FROM 'y'@'%'; END;",
        dialect::mysql(),
    );
}

// ── A declaration that does not parse is skipped, never silent ───────────

#[test]
fn a_declaration_that_does_not_parse_is_skipped_and_the_body_after_it_is_read() {
    let cases = [
        (
            "CREATE OR REPLACE PROCEDURE p(n INT) RETURNS TABLE() LANGUAGE SQL AS $$ \
             DECLARE res RESULTSET DEFAULT (SELECT id FROM zz_users WHERE WHERE); \
             BEGIN DELETE FROM zz_orders; RETURN TABLE(res); END $$;",
            dialect::snowflake(),
        ),
        (
            "CREATE OR REPLACE PROCEDURE p() RETURNS INT LANGUAGE SQL AS $$ \
             DECLARE x INT DEFAULT 1 +; y INT DEFAULT 2; \
             BEGIN DELETE FROM zz_orders; RETURN 1; END $$;",
            dialect::snowflake(),
        ),
        (
            "DECLARE x INT DEFAULT 1; res RESULTSET DEFAULT (SELECT id FROM zz_users WHERE WHERE); \
             BEGIN DELETE FROM zz_orders; END;",
            dialect::snowflake(),
        ),
        (
            "DO $$ DECLARE n int := (SELECT id FROM zz_users WHERE WHERE); \
             BEGIN DELETE FROM zz_orders; END $$;",
            dialect::postgres(),
        ),
        (
            "CREATE FUNCTION f() RETURNS void LANGUAGE plpgsql AS $$ \
             DECLARE c CURSOR FOR SELECT id FROM zz_users WHERE WHERE; \
             BEGIN DELETE FROM zz_orders; END $$;",
            dialect::postgres(),
        ),
        (
            "DO $$ DECLARE n int DEFAULT 1 +; m int := 2; BEGIN DELETE FROM zz_orders; END $$;",
            dialect::postgres(),
        ),
        (
            "DECLARE x INT64 DEFAULT (SELECT COUNT(*) FROM d.zz_users WHERE WHERE);\n\
             DELETE FROM d.zz_orders WHERE TRUE;",
            dialect::bigquery(),
        ),
        (
            "DECLARE @x INT = 1, @y INT = (SELECT id FROM dbo.zz_users WHERE WHERE)\n\
             DELETE FROM dbo.zz_orders",
            dialect::mssql(),
        ),
    ];
    for (sql, d) in cases {
        let cfg = AnalysisConfig {
            dialect: Some(d),
            ..Default::default()
        };
        let report = analyze_risk_with_policy_config(sql, &cfg).expect("should analyze");
        assert!(
            report.summary.statements_skipped > 0,
            "the declaration that does not parse must be skipped: {sql}"
        );
        assert!(
            report.summary.tables_written > 0,
            "the DELETE after it must be read: {sql}"
        );
    }
}

// ── A body part that does not parse is skipped, and the rest is read ─────

/// (skipped, tables written, routine bodies analysed) of `sql`.
fn body_counts(sql: &str, d: lexega_core::DialectRef) -> (usize, usize, usize) {
    let cfg = AnalysisConfig {
        dialect: Some(d),
        ..Default::default()
    };
    let report = analyze_risk_with_policy_config(sql, &cfg).expect("should analyze");
    (
        report.summary.statements_skipped,
        report.summary.tables_written,
        report.summary.procedure_bodies_analyzed,
    )
}

#[test]
fn a_body_part_that_does_not_parse_is_skipped_and_the_rest_is_read() {
    let sf_proc = |body: &str| {
        format!("CREATE OR REPLACE PROCEDURE p() RETURNS INT LANGUAGE SQL AS $$ {body} $$;")
    };
    let cases = [
        // A control-flow statement whose condition does not parse.
        (
            sf_proc("BEGIN IF (1 = ) THEN RETURN 1; END IF; DELETE FROM zz_orders; RETURN 1; END"),
            dialect::snowflake(),
            1,
        ),
        (
            sf_proc(
                "BEGIN WHILE (1 = ) DO DELETE FROM zz_archive; END WHILE; \
                 DELETE FROM zz_orders; RETURN 1; END",
            ),
            dialect::snowflake(),
            2,
        ),
        (
            sf_proc(
                "BEGIN CASE (1 = ) WHEN 1 THEN RETURN 1; END CASE; \
                 DELETE FROM zz_orders; RETURN 1; END",
            ),
            dialect::snowflake(),
            1,
        ),
        (
            sf_proc(
                "DECLARE x INT DEFAULT 1; BEGIN IF (1 = ) THEN RETURN 1; \
                 ELSEIF (2 = 2) THEN RETURN 2; ELSE RETURN 3; END IF; \
                 DELETE FROM zz_orders; RETURN 1; END",
            ),
            dialect::snowflake(),
            1,
        ),
        // Nested in a branch and in an inner block.
        (
            sf_proc(
                "BEGIN IF (1 = 1) THEN IF (1 = ) THEN RETURN 1; END IF; END IF; \
                 DELETE FROM zz_orders; RETURN 1; END",
            ),
            dialect::snowflake(),
            1,
        ),
        (
            sf_proc(
                "BEGIN BEGIN IF (1 = ) THEN RETURN 1; END IF; DELETE FROM zz_archive; END; \
                 DELETE FROM zz_orders; RETURN 1; END",
            ),
            dialect::snowflake(),
            2,
        ),
        // In an exception handler.
        (
            sf_proc(
                "BEGIN DELETE FROM zz_orders; RETURN 1; EXCEPTION WHEN OTHER THEN \
                 IF (1 = ) THEN RETURN 0; END IF; DELETE FROM zz_archive; RETURN 0; END",
            ),
            dialect::snowflake(),
            2,
        ),
        // A declaration without its `;`, last before BEGIN.
        (
            sf_proc("DECLARE x INT DEFAULT 1 + BEGIN DELETE FROM zz_orders; RETURN 1; END"),
            dialect::snowflake(),
            1,
        ),
        (
            "DO $$ DECLARE n int := 1 + BEGIN DELETE FROM zz_orders; END $$;".to_string(),
            dialect::postgres(),
            1,
        ),
        (
            "DO $$ BEGIN IF (1 = ) THEN NULL; END IF; DELETE FROM zz_orders; END $$;".to_string(),
            dialect::postgres(),
            1,
        ),
        (
            "DO $$ BEGIN WHILE (1 = ) LOOP DELETE FROM zz_archive; END LOOP; \
             DELETE FROM zz_orders; END $$;"
                .to_string(),
            dialect::postgres(),
            2,
        ),
        (
            "CREATE FUNCTION f() RETURNS void LANGUAGE plpgsql AS $$ BEGIN \
             CASE WHEN (1 = ) THEN NULL; END CASE; DELETE FROM zz_orders; END $$;"
                .to_string(),
            dialect::postgres(),
            1,
        ),
        (
            "DO $$ <<outer>> DECLARE n int := 1 +; BEGIN DELETE FROM zz_orders; END outer $$;"
                .to_string(),
            dialect::postgres(),
            1,
        ),
        (
            "DO $$ BEGIN DELETE FROM zz_orders; EXCEPTION WHEN others THEN \
             SELECT FROM WHERE; DELETE FROM zz_archive; END $$;"
                .to_string(),
            dialect::postgres(),
            2,
        ),
        (
            "CREATE PROCEDURE p() BEGIN IF (1 = ) THEN SELECT 1; END IF; \
             DELETE FROM zz_orders; END"
                .to_string(),
            dialect::mysql(),
            1,
        ),
    ];
    for (sql, d, written) in cases {
        let (skipped, tables_written, _) = body_counts(&sql, d);
        assert!(
            skipped > 0,
            "the part that does not parse must be skipped: {sql}"
        );
        assert_eq!(
            tables_written, written,
            "the rest of the body must be read: {sql}"
        );
    }
}

#[test]
fn a_routine_body_that_does_not_parse_as_a_whole_is_skipped() {
    let (skipped, _, bodies) = body_counts(
        "CREATE OR REPLACE PROCEDURE p() RETURNS INT LANGUAGE SQL AS $$ \
         BEGIN DELETE FROM zz_orders; RETURN 1; $$;",
        dialect::snowflake(),
    );
    assert!(skipped > 0, "the body must be counted as not parsed");
    assert_eq!(
        bodies, 0,
        "a body that does not parse is not an analysed body"
    );
}

#[test]
fn a_routine_body_written_without_dollar_quotes_that_does_not_parse_is_skipped() {
    // (dialect, script, tables written): the body, to its first `;`, is the
    // piece not parsed, and what follows it is read.
    for (d, sql, written) in [
        (
            dialect::mysql(),
            "CREATE PROCEDURE p() BEGIN DELETE FROM zz_orders;",
            0,
        ),
        (
            dialect::mysql(),
            "CREATE PROCEDURE p() BEGIN DELETE FROM zz_orders;\nDELETE FROM zz_archive;",
            1,
        ),
        (
            dialect::snowflake(),
            "CREATE OR REPLACE PROCEDURE p() RETURNS INT LANGUAGE SQL AS BEGIN \
             DELETE FROM zz_orders;",
            0,
        ),
    ] {
        let cfg = AnalysisConfig {
            dialect: Some(d),
            ..Default::default()
        };
        let report = analyze_risk_with_policy_config(sql, &cfg).expect("should analyze");
        let skipped: Vec<&str> = report
            .skipped_details
            .iter()
            .map(|s| s.statement_prefix.as_str())
            .collect();
        // Body text the parser did not read as SQL is quoted by the
        // keywords it starts with, the rest masked.
        assert_eq!(skipped.len(), 1, "{sql}");
        assert!(
            skipped[0].starts_with("BEGIN DELETE FROM "),
            "{sql}: {skipped:?}"
        );
        assert!(!skipped[0].contains("zz_orders"), "{sql}: {skipped:?}");
        assert_eq!(report.summary.tables_written, written, "{sql}");
        assert_eq!(report.summary.procedure_bodies_analyzed, 0, "{sql}");
    }
}

#[test]
fn a_labelled_plpgsql_block_is_read() {
    let cases = [
        "DO $$ <<outer>> DECLARE n int := 1; BEGIN DELETE FROM zz_orders; END outer $$;",
        "DO $$ <<outer>> BEGIN DELETE FROM zz_orders; END $$;",
        "CREATE FUNCTION f() RETURNS void LANGUAGE plpgsql AS $$ <<blk>> DECLARE n int := 1; \
         BEGIN DELETE FROM zz_orders; END blk $$;",
        "DO $$ BEGIN <<inner>> BEGIN DELETE FROM zz_orders; END inner; END $$;",
        "DO $$ BEGIN <<inner>> DECLARE m int := 1; BEGIN DELETE FROM zz_orders; END inner; END $$;",
    ];
    for sql in cases {
        let (skipped, tables_written, _) = body_counts(sql, dialect::postgres());
        assert_eq!(skipped, 0, "a labelled block is valid: {sql}");
        assert_eq!(
            tables_written, 1,
            "the labelled block's body must be read: {sql}"
        );
    }
}

#[test]
fn a_for_loop_whose_range_or_query_does_not_parse_is_skipped_and_the_rest_is_read() {
    let sf_proc = |body: &str| {
        format!("CREATE OR REPLACE PROCEDURE p() RETURNS INT LANGUAGE SQL AS $$ {body} $$;")
    };
    let cases = [
        (
            sf_proc(
                "BEGIN FOR i IN 1 TO ) DO DELETE FROM zz_archive; END FOR; \
                 DELETE FROM zz_orders; RETURN 1; END",
            ),
            dialect::snowflake(),
        ),
        (
            sf_proc(
                "BEGIN FOR i IN DO DELETE FROM zz_archive; END FOR; \
                 DELETE FROM zz_orders; RETURN 1; END",
            ),
            dialect::snowflake(),
        ),
        (
            sf_proc(
                "BEGIN FOR i IN 1 10 DO DELETE FROM zz_archive; END FOR; \
                 DELETE FROM zz_orders; RETURN 1; END",
            ),
            dialect::snowflake(),
        ),
        (
            "BEGIN FOR i IN 1 TO ) DO DELETE FROM zz_archive; END FOR; \
             DELETE FROM zz_orders; END;"
                .to_string(),
            dialect::snowflake(),
        ),
        (
            "DO $$ BEGIN FOR r IN SELECT FROM WHERE LOOP DELETE FROM zz_archive; END LOOP; \
             DELETE FROM zz_orders; END $$;"
                .to_string(),
            dialect::postgres(),
        ),
        (
            "CREATE FUNCTION f() RETURNS void LANGUAGE plpgsql AS $$ BEGIN \
             FOR i IN 1 .. LOOP DELETE FROM zz_archive; END LOOP; DELETE FROM zz_orders; END $$;"
                .to_string(),
            dialect::postgres(),
        ),
        (
            "DO $$ BEGIN FOR r IN EXECUTE LOOP DELETE FROM zz_archive; END LOOP; \
             DELETE FROM zz_orders; END $$;"
                .to_string(),
            dialect::postgres(),
        ),
        (
            "DO $$ BEGIN FOR r IN SELECT id FROM zz_users WHERE LOOP DELETE FROM zz_archive; \
             END LOOP; DELETE FROM zz_orders; END $$;"
                .to_string(),
            dialect::postgres(),
        ),
        (
            "BEGIN FOR x IN (SELECT id FROM zz_users WHERE) DO DELETE FROM zz_archive \
             WHERE true; END FOR; DELETE FROM zz_orders WHERE true; END;"
                .to_string(),
            dialect::bigquery(),
        ),
        (
            "BEGIN FOR r AS SELECT FROM WHERE DO DELETE FROM zz_archive; END FOR; \
             DELETE FROM zz_orders; END;"
                .to_string(),
            dialect::databricks(),
        ),
    ];
    for (sql, d) in cases {
        let (skipped, tables_written, _) = body_counts(&sql, d);
        assert_eq!(skipped, 1, "the loop's header does not parse: {sql}");
        assert_eq!(
            tables_written, 2,
            "the loop's body and the rest of the routine must be read: {sql}"
        );
    }
}

#[test]
fn a_valid_for_loop_is_read() {
    let sf_proc = |body: &str| {
        format!("CREATE OR REPLACE PROCEDURE p(n INT) RETURNS INT LANGUAGE SQL AS $$ {body} $$;")
    };
    let cases = [
        (
            sf_proc("BEGIN FOR i IN 1 TO 10 DO DELETE FROM zz_archive; END FOR; RETURN 1; END"),
            dialect::snowflake(),
        ),
        (
            sf_proc(
                "BEGIN FOR i IN REVERSE 1 TO :n DO DELETE FROM zz_archive; END FOR; \
                 RETURN 1; END",
            ),
            dialect::snowflake(),
        ),
        (
            sf_proc(
                "DECLARE c1 CURSOR FOR SELECT id FROM zz_users; BEGIN FOR r IN c1 DO \
                 DELETE FROM zz_archive; END FOR; RETURN 1; END",
            ),
            dialect::snowflake(),
        ),
        (
            "DO $$ BEGIN FOR i IN 1..10 LOOP DELETE FROM zz_archive; END LOOP; END $$;".to_string(),
            dialect::postgres(),
        ),
        (
            "DO $$ BEGIN FOR i IN REVERSE 10 .. 1 BY 2 LOOP DELETE FROM zz_archive; END LOOP; \
             END $$;"
                .to_string(),
            dialect::postgres(),
        ),
        (
            "DO $$ DECLARE r record; BEGIN FOR r IN SELECT id FROM zz_users u WHERE id > 0 \
             ORDER BY id LIMIT 5 LOOP DELETE FROM zz_archive; END LOOP; END $$;"
                .to_string(),
            dialect::postgres(),
        ),
        (
            "DO $$ DECLARE r record; BEGIN FOR r IN SELECT 1 LOOP DELETE FROM zz_archive; \
             END LOOP; END $$;"
                .to_string(),
            dialect::postgres(),
        ),
        (
            "CREATE FUNCTION f(q text, x int) RETURNS void LANGUAGE plpgsql AS $$ \
             DECLARE r record; BEGIN FOR r IN EXECUTE q USING x LOOP DELETE FROM zz_archive; \
             END LOOP; END $$;"
                .to_string(),
            dialect::postgres(),
        ),
        (
            "DO $$ DECLARE a int[] := ARRAY[1,2]; BEGIN FOR i IN 1..array_length(a, 1) LOOP \
             DELETE FROM zz_archive; END LOOP; END $$;"
                .to_string(),
            dialect::postgres(),
        ),
        (
            "DO $$ DECLARE c CURSOR (k int) FOR SELECT id FROM zz_users WHERE id = k; \
             r record; BEGIN FOR r IN c(5) LOOP DELETE FROM zz_archive; END LOOP; END $$;"
                .to_string(),
            dialect::postgres(),
        ),
        (
            "DO $$ DECLARE r record; BEGIN FOR r IN WITH q AS (SELECT id FROM zz_users) \
             SELECT id FROM q LOOP DELETE FROM zz_archive; END LOOP; END $$;"
                .to_string(),
            dialect::postgres(),
        ),
        (
            "BEGIN FOR x IN (SELECT id FROM zz_users) DO DELETE FROM zz_archive WHERE true; \
             END FOR; END;"
                .to_string(),
            dialect::bigquery(),
        ),
        (
            "BEGIN FOR r AS SELECT id FROM zz_users DO DELETE FROM zz_archive; END FOR; END;"
                .to_string(),
            dialect::databricks(),
        ),
    ];
    for (sql, d) in cases {
        let (skipped, tables_written, _) = body_counts(&sql, d);
        assert_eq!(skipped, 0, "a valid loop: {sql}");
        assert_eq!(tables_written, 1, "the loop's body must be read: {sql}");
    }
}

#[test]
fn reading_for_loop_headers_is_linear_in_the_source() {
    // Each header is read once, by a parser over its own tokens.
    let measure = |n: usize| {
        let loops: String = (0..n)
            .map(|i| {
                format!(
                    "FOR r IN SELECT id FROM zz_users WHERE id > {i} LOOP NULL; END LOOP; \
                     FOR i IN 1 .. {i} + 2 * {i} BY 2 LOOP NULL; END LOOP; "
                )
            })
            .collect();
        let sql = format!("DO $$ DECLARE r record; BEGIN {loops}DELETE FROM zz_orders; END $$;");
        let started = std::time::Instant::now();
        let (skipped, tables_written, _) = body_counts(&sql, dialect::postgres());
        assert_eq!(skipped, 0);
        assert_eq!(tables_written, 1);
        started.elapsed()
    };
    let small = measure(250);
    let large = measure(1000);
    assert!(
        large < small * 8 + std::time::Duration::from_millis(500),
        "four times the input took {large:?} against {small:?}"
    );
}

#[test]
fn a_compound_statement_whose_header_does_not_parse_keeps_its_body() {
    // (dialect, the routine with `{}` where the statement goes, the statement
    // whose header does not parse with `{}` where its body goes, the header).
    let sf_proc = "CREATE OR REPLACE PROCEDURE p() RETURNS INT LANGUAGE SQL AS $$ \
                   DECLARE x INT DEFAULT 0; BEGIN {} DELETE FROM zz_orders; RETURN 1; END $$;";
    let sf_block = "BEGIN {} DELETE FROM zz_orders; END;";
    let pg_do = "DO $$ DECLARE x int := 0; r record; BEGIN {} DELETE FROM zz_orders; END $$;";
    let pg_fn = "CREATE FUNCTION f() RETURNS void LANGUAGE plpgsql AS $$ DECLARE x int := 0; \
                 BEGIN {} DELETE FROM zz_orders; END $$;";
    let bq = "DECLARE x INT64 DEFAULT 0; BEGIN {} DELETE FROM zz_orders WHERE true; END;";
    let dbx = "BEGIN DECLARE x INT DEFAULT 0; {} DELETE FROM zz_orders; END;";
    let my = "CREATE PROCEDURE p() BEGIN DECLARE x INT DEFAULT 0; {} DELETE FROM zz_orders; END";
    let cases = [
        (
            dialect::snowflake(),
            sf_proc,
            "FOR i IN 1 TO ) DO {} END FOR;",
            "**** TO )",
        ),
        (
            dialect::snowflake(),
            sf_block,
            "FOR i IN 1 TO ) DO {} END FOR;",
            "**** TO )",
        ),
        (
            dialect::snowflake(),
            sf_proc,
            "IF (x = ) THEN {} END IF;",
            "(x = )",
        ),
        (
            dialect::snowflake(),
            sf_block,
            "IF (x = ) THEN {} END IF;",
            "(x = )",
        ),
        (
            dialect::snowflake(),
            sf_proc,
            "IF (x = 1) THEN SELECT 1; ELSEIF (x = ) THEN {} END IF;",
            "(x = )",
        ),
        (
            dialect::snowflake(),
            sf_proc,
            "WHILE (x < ) DO {} END WHILE;",
            "(x < )",
        ),
        (
            dialect::snowflake(),
            sf_block,
            "CASE WHEN x = THEN {} END CASE;",
            "x =",
        ),
        (
            dialect::postgres(),
            pg_do,
            "FOR r IN SELECT FROM WHERE LOOP {} END LOOP;",
            "SELECT FROM WHERE",
        ),
        (
            dialect::postgres(),
            pg_fn,
            "FOR i IN 1 .. LOOP {} END LOOP;",
            "**** ..",
        ),
        (dialect::postgres(), pg_do, "IF x = THEN {} END IF;", "x ="),
        (
            dialect::postgres(),
            pg_fn,
            "IF x = 1 THEN NULL; ELSIF x = THEN {} END IF;",
            "x =",
        ),
        (
            dialect::postgres(),
            pg_do,
            "WHILE x < LOOP {} END LOOP;",
            "x <",
        ),
        (
            dialect::postgres(),
            pg_fn,
            "CASE WHEN x = THEN {} END CASE;",
            "x =",
        ),
        (
            dialect::bigquery(),
            bq,
            "FOR r IN (SELECT id FROM zz_users WHERE) DO {} END FOR;",
            "(SELECT id FROM zz_users WHERE)",
        ),
        (dialect::bigquery(), bq, "IF x = THEN {} END IF;", "x ="),
        (dialect::bigquery(), bq, "WHILE x < DO {} END WHILE;", "x <"),
        (
            dialect::databricks(),
            dbx,
            "FOR r AS SELECT FROM WHERE DO {} END FOR;",
            "SELECT FROM WHERE",
        ),
        (dialect::databricks(), dbx, "IF x = THEN {} END IF;", "x ="),
        (
            dialect::databricks(),
            dbx,
            "CASE WHEN x = THEN {} END CASE;",
            "x =",
        ),
        (dialect::mysql(), my, "IF x = THEN {} END IF;", "x ="),
        (dialect::mysql(), my, "WHILE x < DO {} END WHILE;", "x <"),
        (
            dialect::mysql(),
            my,
            "CASE WHEN x = THEN {} END CASE;",
            "x =",
        ),
        (
            dialect::snowflake(),
            sf_block,
            "REPEAT {} UNTIL (x = ) END REPEAT;",
            "(x = )",
        ),
        (
            dialect::snowflake(),
            sf_proc,
            "REPEAT {} UNTIL (x = ) END REPEAT;",
            "(x = )",
        ),
        (
            dialect::bigquery(),
            bq,
            "REPEAT {} UNTIL x = END REPEAT;",
            "x =",
        ),
        (
            dialect::databricks(),
            dbx,
            "REPEAT {} UNTIL x = END REPEAT;",
            "x =",
        ),
        (
            dialect::mysql(),
            my,
            "REPEAT {} UNTIL x = END REPEAT;",
            "x =",
        ),
        (
            dialect::snowflake(),
            sf_block,
            "CASE (x +) WHEN 1 THEN {} END CASE;",
            "(x +)",
        ),
        (
            dialect::snowflake(),
            sf_proc,
            "CASE (x +) WHEN 1 THEN {} END CASE;",
            "(x +)",
        ),
        (
            dialect::postgres(),
            pg_do,
            "CASE x + WHEN 1 THEN {} END CASE;",
            "x +",
        ),
        (
            dialect::postgres(),
            pg_fn,
            "CASE (x +) WHEN 1 THEN {} END CASE;",
            "(x +)",
        ),
        (
            dialect::bigquery(),
            bq,
            "CASE x + WHEN 1 THEN {} END CASE;",
            "x +",
        ),
        (
            dialect::databricks(),
            dbx,
            "CASE x + WHEN 1 THEN {} END CASE;",
            "x +",
        ),
        (
            dialect::mysql(),
            my,
            "CASE x + WHEN 1 THEN {} END CASE;",
            "x +",
        ),
        (
            dialect::postgres(),
            pg_fn,
            "CASE x WHEN 1, (2 +) THEN {} END CASE;",
            "****, (**** +)",
        ),
        (
            dialect::postgres(),
            pg_do,
            "CASE x WHEN 1, THEN {} END CASE;",
            "****,",
        ),
        (
            dialect::postgres(),
            pg_fn,
            "CASE WHEN x = 1, x = 2 THEN {} END CASE;",
            "x = ****, x = ****",
        ),
    ];
    for (d, routine, statement, header) in cases {
        let body = if routine == bq {
            "DELETE FROM zz_archive WHERE true;"
        } else {
            "DELETE FROM zz_archive;"
        };
        let sql = routine.replacen("{}", &statement.replacen("{}", body, 1), 1);
        let cfg = AnalysisConfig {
            dialect: Some(d),
            ..Default::default()
        };
        let report = analyze_risk_with_policy_config(&sql, &cfg).expect("should analyze");
        let skipped: Vec<&str> = report
            .skipped_details
            .iter()
            .map(|s| s.statement_prefix.as_str())
            .collect();
        assert_eq!(
            skipped,
            [header],
            "the header is the one piece not parsed: {sql}"
        );
        assert_eq!(report.summary.statements_skipped, 1, "{sql}");
        assert_eq!(
            report.summary.tables_written, 2,
            "the body and the statement after it are read: {sql}"
        );
    }
}

#[test]
fn a_compound_statement_missing_its_header_keyword_keeps_its_body() {
    // (dialect, the routine with `{}` where the statement goes, the statement
    // with `{}` where its body goes, the header up to the body's first
    // statement).
    let sf_proc = "CREATE OR REPLACE PROCEDURE p() RETURNS INT LANGUAGE SQL AS $$ \
                   DECLARE x INT DEFAULT 0; BEGIN {} DELETE FROM zz_orders; RETURN 1; END $$;";
    let sf_block = "BEGIN {} DELETE FROM zz_orders; END;";
    let pg_do = "DO $$ DECLARE x int := 0; BEGIN {} DELETE FROM zz_orders; END $$;";
    let pg_fn = "CREATE FUNCTION f() RETURNS void LANGUAGE plpgsql AS $$ DECLARE x int := 0; \
                 BEGIN {} DELETE FROM zz_orders; END $$;";
    let bq = "DECLARE x INT64 DEFAULT 0; BEGIN {} DELETE FROM zz_orders WHERE true; END;";
    let dbx = "BEGIN DECLARE x INT DEFAULT 0; {} DELETE FROM zz_orders; END;";
    let my = "CREATE PROCEDURE p() BEGIN DECLARE x INT DEFAULT 0; {} DELETE FROM zz_orders; END";
    let cases = [
        (
            dialect::snowflake(),
            sf_proc,
            "IF (x = 1) {} END IF;",
            "(x = ****)",
        ),
        (
            dialect::snowflake(),
            sf_block,
            "IF (x = 1) {} END IF;",
            "(x = ****)",
        ),
        (
            dialect::snowflake(),
            sf_block,
            "IF (x = 1) THEN SELECT 1; ELSEIF (x = 2) {} END IF;",
            "(x = ****)",
        ),
        (
            dialect::snowflake(),
            sf_proc,
            "WHILE (x = 1) {} END WHILE;",
            "(x = ****)",
        ),
        (
            dialect::snowflake(),
            sf_block,
            "WHILE (x = 1) {} END WHILE;",
            "(x = ****)",
        ),
        (
            dialect::snowflake(),
            sf_block,
            "FOR i IN 1 TO 3 {} END FOR;",
            "**** TO ****",
        ),
        (
            dialect::snowflake(),
            sf_proc,
            "FOR i IN 1 TO 3 {} END FOR;",
            "**** TO ****",
        ),
        (
            dialect::snowflake(),
            sf_block,
            "CASE WHEN x = 1 {} END CASE;",
            "x = ****",
        ),
        (
            dialect::snowflake(),
            sf_block,
            "CASE x WHEN 1 {} END CASE;",
            "****",
        ),
        (
            dialect::postgres(),
            pg_do,
            "IF x = 1 {} END IF;",
            "x = ****",
        ),
        (
            dialect::postgres(),
            pg_fn,
            "IF x = 1 THEN NULL; ELSIF x = 2 {} END IF;",
            "x = ****",
        ),
        (
            dialect::postgres(),
            pg_fn,
            "WHILE x < 1 {} END LOOP;",
            "x < ****",
        ),
        (
            dialect::postgres(),
            pg_do,
            "FOR i IN 1 .. 3 {} END LOOP;",
            "**** .. ****",
        ),
        (
            dialect::postgres(),
            pg_fn,
            "CASE WHEN x = 1 {} END CASE;",
            "x = ****",
        ),
        (dialect::bigquery(), bq, "IF x = 1 {} END IF;", "x = ****"),
        (
            dialect::bigquery(),
            bq,
            "WHILE x < 1 {} END WHILE;",
            "x < ****",
        ),
        (
            dialect::bigquery(),
            bq,
            "IF x = 1 THEN SELECT 1; ELSEIF x = 2 {} END IF;",
            "x = ****",
        ),
        (
            dialect::databricks(),
            dbx,
            "IF x = 1 {} END IF;",
            "x = ****",
        ),
        (
            dialect::databricks(),
            dbx,
            "WHILE x < 1 {} END WHILE;",
            "x < ****",
        ),
        (
            dialect::databricks(),
            dbx,
            "CASE WHEN x = 1 {} END CASE;",
            "x = ****",
        ),
        (dialect::mysql(), my, "IF x = 1 {} END IF;", "x = ****"),
        (
            dialect::mysql(),
            my,
            "WHILE x < 1 {} END WHILE;",
            "x < ****",
        ),
        (
            dialect::mysql(),
            my,
            "CASE WHEN x = 1 {} END CASE;",
            "x = ****",
        ),
        (dialect::mysql(), my, "CASE x WHEN 1 {} END CASE;", "****"),
        // No UNTIL: the condition is one empty piece at the loop's END.
        (dialect::snowflake(), sf_block, "REPEAT {} END REPEAT;", ""),
        (dialect::snowflake(), sf_proc, "REPEAT {} END REPEAT;", ""),
        (dialect::bigquery(), bq, "REPEAT {} END REPEAT;", ""),
        (dialect::databricks(), dbx, "REPEAT {} END REPEAT;", ""),
        (dialect::mysql(), my, "REPEAT {} END REPEAT;", ""),
    ];
    for (d, routine, statement, header) in cases {
        let body = if routine == bq {
            "DELETE FROM zz_archive WHERE true;"
        } else {
            "DELETE FROM zz_archive;"
        };
        let sql = routine.replacen("{}", &statement.replacen("{}", body, 1), 1);
        let cfg = AnalysisConfig {
            dialect: Some(d),
            ..Default::default()
        };
        let report = analyze_risk_with_policy_config(&sql, &cfg).expect("should analyze");
        let skipped: Vec<&str> = report
            .skipped_details
            .iter()
            .map(|s| s.statement_prefix.as_str())
            .collect();
        assert_eq!(
            skipped,
            [header],
            "the header is the one piece not parsed: {sql}"
        );
        assert_eq!(report.summary.statements_skipped, 1, "{sql}");
        assert_eq!(
            report.summary.tables_written, 2,
            "the body and the statement after it are read: {sql}"
        );
    }
}

#[test]
fn the_end_of_a_block_after_a_statement_with_no_semicolon_is_never_its_alias() {
    // (dialect, script, tables written): every DELETE is read, the block
    // closing at its own END.
    let cases = [
        (
            dialect::mysql(),
            "CREATE PROCEDURE p() BEGIN DELETE FROM zz_orders; SELECT id FROM zz_users END;\n\
             DELETE FROM zz_archive;",
            2,
        ),
        (
            dialect::mysql(),
            "CREATE PROCEDURE p() BEGIN DELETE FROM zz_orders; SELECT id FROM zz_users END",
            1,
        ),
        (
            dialect::snowflake(),
            "CREATE OR REPLACE PROCEDURE p() RETURNS INT LANGUAGE SQL AS $$ BEGIN \
             DELETE FROM zz_orders; SELECT id FROM zz_users END; $$;\nDELETE FROM zz_archive;",
            2,
        ),
        (
            dialect::snowflake(),
            "BEGIN DELETE FROM zz_orders WHERE id = 1; SELECT id FROM zz_users END;\n\
             DELETE FROM zz_archive;",
            2,
        ),
        (
            dialect::databricks(),
            "BEGIN DELETE FROM zz_orders; SELECT id FROM zz_users END;\nDELETE FROM zz_archive;",
            2,
        ),
    ];
    for (d, sql, written) in cases {
        let (_, tables_written, _) = body_counts(sql, d);
        assert_eq!(tables_written, written, "{sql}");
    }
    // Outside a block a bare `end` is a column alias, as it was.
    let cfg = AnalysisConfig {
        dialect: Some(dialect::mysql()),
        ..Default::default()
    };
    let report =
        analyze_risk_with_policy_config("SELECT MIN(id) start, MAX(id) end FROM zz_users;", &cfg)
            .expect("should analyze");
    assert_eq!(report.summary.statements_parsed, 1);
    assert_eq!(report.summary.statements_skipped, 0);
}

#[test]
fn the_end_of_a_block_is_never_a_select_item_s_label() {
    // (dialect, script, statements skipped, tables written): the block closes
    // at its own END and what follows is read.
    let cases = [
        (
            dialect::mysql(),
            "CREATE PROCEDURE p() BEGIN DELETE FROM zz_orders; SELECT MAX(id) END;\n\
             DELETE FROM zz_archive;",
            0,
            2,
        ),
        (
            dialect::snowflake(),
            "BEGIN DELETE FROM zz_orders WHERE id = 1; SELECT MAX(id) END;\n\
             DELETE FROM zz_archive;",
            0,
            2,
        ),
        (
            dialect::databricks(),
            "BEGIN DELETE FROM zz_orders; SELECT MAX(id) END;\nDELETE FROM zz_archive;",
            0,
            2,
        ),
        // In a body, `end` followed by the item's FROM is its label.
        (
            dialect::mysql(),
            "CREATE PROCEDURE p() BEGIN SELECT MAX(id) end FROM zz_users; DELETE FROM zz_orders; END",
            0,
            1,
        ),
    ];
    for (d, sql, skipped, written) in cases {
        let (statements_skipped, tables_written, _) = body_counts(sql, d);
        assert_eq!(
            (statements_skipped, tables_written),
            (skipped, written),
            "{sql}"
        );
    }
}

#[test]
fn a_label_is_a_word_the_dialect_s_keyword_list_allows_there() {
    // (dialect, a select item's or table's label, statements skipped)
    let cases = [
        // PostgreSQL takes any keyword as a column label after AS.
        (
            dialect::postgres(),
            "SELECT MAX(id) AS end FROM zz_users",
            0,
        ),
        (
            dialect::postgres(),
            "SELECT MAX(id) AS from FROM zz_users",
            0,
        ),
        (dialect::postgres(), "SELECT MAX(id) AS to FROM zz_users", 0),
        // Other dialects only a word they do not reserve.
        (
            dialect::snowflake(),
            "SELECT MAX(id) AS from FROM zz_users",
            1,
        ),
        // A word the dialect reserves is no table alias, written as a keyword
        // or not.
        (dialect::mysql(), "SELECT id FROM zz_users rank", 1),
        (dialect::mssql(), "SELECT id FROM zz_users plan", 1),
        (dialect::mysql(), "SELECT id rank FROM zz_users", 1),
        // A word it does not reserve is one.
        (dialect::postgres(), "SELECT id FROM zz_users delete", 0),
        (dialect::mysql(), "SELECT id FROM zz_users following", 0),
    ];
    for (d, sql, skipped) in cases {
        let (statements_skipped, _, _) = body_counts(sql, d);
        assert_eq!(statements_skipped, skipped, "{sql}");
    }
}

#[test]
fn reading_headers_with_no_keyword_is_linear_in_the_source() {
    // Each header ends at its body's first statement, found from the header
    // on: compound statements one after another, and nested in one another.
    let measure = |n: usize| {
        let flat: String = (0..n)
            .map(|_| "IF (x = 1) NULL; END IF; WHILE (x < 1) NULL; END WHILE; ")
            .collect();
        let nested = format!(
            "{}NULL; {}",
            "IF (x = 1) ".repeat(10),
            "END IF; ".repeat(10)
        );
        let nests = nested.repeat(n / 10);
        let sql = format!(
            "CREATE OR REPLACE PROCEDURE p() RETURNS INT LANGUAGE SQL AS $$ DECLARE x INT \
             DEFAULT 0; BEGIN {flat}{nests}DELETE FROM zz_orders; RETURN 1; END $$;"
        );
        let started = std::time::Instant::now();
        let (skipped, tables_written, _) = body_counts(&sql, dialect::snowflake());
        assert_eq!(skipped, 3 * n);
        assert_eq!(tables_written, 1);
        started.elapsed()
    };
    let small = measure(500);
    let large = measure(2000);
    assert!(
        large < small * 8 + std::time::Duration::from_millis(500),
        "four times the input took {large:?} against {small:?}"
    );
}

#[test]
fn reading_compound_headers_that_do_not_parse_is_linear_in_the_source() {
    // Each header that does not parse ends at its own keyword, found from
    // the header on (20,000 branches of one IF).
    let measure = |n: usize| {
        let branches: String = (0..10 * n).map(|_| "ELSEIF (x = ) THEN NULL; ").collect();
        let ifs: String = (0..n)
            .map(|_| "IF (x = ) THEN NULL; END IF; WHILE (x < ) DO NULL; END WHILE; ")
            .collect();
        let sql = format!(
            "CREATE OR REPLACE PROCEDURE p() RETURNS INT LANGUAGE SQL AS $$ DECLARE x INT \
             DEFAULT 0; BEGIN IF (x = 1) THEN NULL; {branches}END IF; {ifs}DELETE FROM \
             zz_orders; RETURN 1; END $$;"
        );
        let started = std::time::Instant::now();
        let (skipped, tables_written, _) = body_counts(&sql, dialect::snowflake());
        assert_eq!(skipped, 12 * n);
        assert_eq!(tables_written, 1);
        started.elapsed()
    };
    let small = measure(500);
    let large = measure(2000);
    assert!(
        large < small * 8 + std::time::Duration::from_millis(500),
        "four times the input took {large:?} against {small:?}"
    );
}

#[test]
fn reading_until_conditions_that_do_not_parse_is_linear_in_the_source() {
    // Each condition that does not parse ends at its own END REPEAT, nested
    // loops included.
    let measure = |n: usize| {
        let loops: String = (0..n)
            .map(|_| "REPEAT REPEAT NULL; UNTIL (x = ) END REPEAT; UNTIL (x < ) END REPEAT; ")
            .collect();
        let sql = format!("BEGIN {loops}DELETE FROM zz_orders; END;");
        let started = std::time::Instant::now();
        let (skipped, tables_written, _) = body_counts(&sql, dialect::snowflake());
        assert_eq!(skipped, 2 * n);
        assert_eq!(tables_written, 1);
        started.elapsed()
    };
    let small = measure(1250);
    let large = measure(5000);
    assert!(
        large < small * 8 + std::time::Duration::from_millis(500),
        "four times the input took {large:?} against {small:?}"
    );
}

#[test]
fn reading_case_operands_that_do_not_parse_is_linear_in_the_source() {
    // Each operand that does not parse ends at its own CASE's first WHEN,
    // past a CASE expression nested in it.
    let measure = |n: usize| {
        let cases: String = (0..n)
            .map(|_| "CASE (CASE WHEN x = 1 THEN 1 END +) WHEN 1 THEN NULL; END CASE; ")
            .collect();
        let sql = format!("BEGIN {cases}DELETE FROM zz_orders; END;");
        let started = std::time::Instant::now();
        let (skipped, tables_written, _) = body_counts(&sql, dialect::snowflake());
        assert_eq!(skipped, n);
        assert_eq!(tables_written, 1);
        started.elapsed()
    };
    let small = measure(1250);
    let large = measure(5000);
    assert!(
        large < small * 8 + std::time::Duration::from_millis(500),
        "four times the input took {large:?} against {small:?}"
    );
}

#[test]
fn a_simple_case_with_several_values_in_a_when_is_read_whole() {
    let pg_fn = "CREATE FUNCTION f(x int) RETURNS void LANGUAGE plpgsql AS $$ \
                 BEGIN {} DELETE FROM zz_orders; END $$;";
    let pg_do = "DO $$ DECLARE x int := 0; BEGIN {} DELETE FROM zz_orders; END $$;";
    let statements = [
        "CASE x WHEN 1, 2 THEN DELETE FROM zz_archive; END CASE;",
        "CASE x WHEN 0 THEN NULL; WHEN 1, 2, 3 THEN DELETE FROM zz_archive; \
         ELSE NULL; END CASE;",
        "CASE x + 1 WHEN (1), CASE WHEN x > 0 THEN 2 END, abs(-3) THEN \
         DELETE FROM zz_archive; END CASE;",
    ];
    for routine in [pg_fn, pg_do] {
        for statement in statements {
            let sql = routine.replacen("{}", statement, 1);
            let cfg = AnalysisConfig {
                dialect: Some(dialect::postgres()),
                ..Default::default()
            };
            let report = analyze_risk_with_policy_config(&sql, &cfg).expect("should analyze");
            let skipped: Vec<&str> = report
                .skipped_details
                .iter()
                .map(|s| s.statement_prefix.as_str())
                .collect();
            assert!(skipped.is_empty(), "nothing is skipped: {sql}: {skipped:?}");
            assert_eq!(report.summary.statements_skipped, 0, "{sql}");
            assert_eq!(report.summary.statements_partial, 0, "{sql}");
            assert_eq!(
                report.summary.tables_written, 2,
                "the branch's body and the statement after the CASE are read: {sql}"
            );
        }
    }
}

#[test]
fn reading_when_lists_is_linear_in_the_source() {
    // One WHEN of 20,000 values, and 2,000 CASE statements of three values.
    let measure = |n: usize| {
        let values: String = (0..10 * n).map(|i| format!("{i}, ")).collect();
        let cases: String = (0..n)
            .map(|i| format!("CASE x WHEN {i}, {i} + 1, -{i} THEN NULL; END CASE; "))
            .collect();
        let sql = format!(
            "DO $$ DECLARE x int := 0; BEGIN CASE x WHEN {values}0 THEN NULL; END CASE; \
             {cases}DELETE FROM zz_orders; END $$;"
        );
        let started = std::time::Instant::now();
        let (skipped, tables_written, _) = body_counts(&sql, dialect::postgres());
        assert_eq!(skipped, 0);
        assert_eq!(tables_written, 1);
        started.elapsed()
    };
    let small = measure(500);
    let large = measure(2000);
    assert!(
        large < small * 8 + std::time::Duration::from_millis(500),
        "four times the input took {large:?} against {small:?}"
    );
}

/// The rule ids a statement raises, as findings or context (each once), and
/// the tables it reads and writes.
fn findings_and_tables(
    sql: &str,
    d: lexega_core::DialectRef,
) -> (
    std::collections::BTreeSet<String>,
    std::collections::BTreeSet<String>,
    std::collections::BTreeSet<String>,
) {
    let cfg = AnalysisConfig {
        dialect: Some(d),
        ..Default::default()
    };
    let report = analyze_risk_with_policy_config(sql, &cfg).expect("should analyze");
    let rules = report
        .entries()
        .map(|RuleMatch::Analysis(a)| a.matched_rule.clone())
        .collect();
    let read = report.summary.tables_read_names.iter().cloned().collect();
    let written = report
        .summary
        .tables_written_names
        .iter()
        .cloned()
        .collect();
    (rules, read, written)
}

#[test]
fn a_for_loops_query_raises_what_the_same_query_raises_in_the_body() {
    // (dialect, the routine with `{}` where the statement goes, the loop
    // over `{}`, the query).
    let pg_do = "DO $$ DECLARE r record; BEGIN {} NULL; END $$;";
    let pg_fn = "CREATE FUNCTION f(v text) RETURNS void LANGUAGE plpgsql AS $$ \
                 DECLARE r record; BEGIN {} NULL; END $$;";
    let pg_loop = "FOR r IN {} LOOP NULL; END LOOP;";
    let cases = [
        (
            dialect::postgres(),
            pg_do,
            pg_loop,
            "SELECT id FROM zz_users WHERE id > 0",
        ),
        (
            dialect::postgres(),
            pg_do,
            pg_loop,
            "DELETE FROM zz_users RETURNING id",
        ),
        (
            dialect::postgres(),
            pg_do,
            pg_loop,
            "WITH q AS (SELECT id FROM zz_users) SELECT id FROM q",
        ),
        (
            dialect::postgres(),
            pg_do,
            pg_loop,
            "EXECUTE 'DELETE FROM zz_users'",
        ),
        (
            dialect::postgres(),
            pg_fn,
            pg_loop,
            "EXECUTE 'DELETE FROM ' || v",
        ),
        (
            dialect::bigquery(),
            "BEGIN {} SELECT 1; END;",
            "FOR x IN ({}) DO SELECT 1; END FOR;",
            "SELECT id FROM zz_users",
        ),
        (
            dialect::databricks(),
            "BEGIN {} SELECT 1; END;",
            "FOR r AS {} DO SELECT 1; END FOR;",
            "SELECT id FROM zz_users",
        ),
    ];
    for (d, routine, for_loop, query) in cases {
        let in_body = routine.replacen("{}", &format!("{query};"), 1);
        let in_loop = routine.replacen("{}", &for_loop.replacen("{}", query, 1), 1);
        let standalone = findings_and_tables(&in_body, d.clone());
        assert!(
            !standalone.0.is_empty() || !standalone.1.is_empty(),
            "the query must raise or read something: {in_body}"
        );
        assert_eq!(
            findings_and_tables(&in_loop, d),
            standalone,
            "the loop's query must be analysed as the statement is:\n{in_loop}\n{in_body}"
        );
    }
}

#[test]
fn a_query_an_assignment_takes_raises_what_it_raises_written_as_a_statement() {
    // (dialect, the script with `{q}` assigned, the same script with `{q}`
    // as a statement of its own).
    let cases = [
        (dialect::snowflake(), "SET x = ({q});", "{q};"),
        (
            dialect::snowflake(),
            "SET (a, b) = (SELECT 1, max(id) FROM zz_users);",
            "SELECT 1, max(id) FROM zz_users;",
        ),
        (
            dialect::snowflake(),
            "BEGIN LET x INT := 0; x := ({q}); END;",
            "BEGIN LET x INT := 0; {q}; END;",
        ),
        (
            dialect::snowflake(),
            "BEGIN LET x INT := 0; x := 1 + ({q}); END;",
            "BEGIN LET x INT := 0; {q}; END;",
        ),
        (
            dialect::snowflake(),
            "BEGIN LET x INT := ({q}); END;",
            "BEGIN {q}; END;",
        ),
        (
            dialect::snowflake(),
            "DECLARE x INT DEFAULT ({q}); BEGIN RETURN x; END;",
            "DECLARE x INT DEFAULT 0; BEGIN {q}; RETURN x; END;",
        ),
        (
            dialect::bigquery(),
            "DECLARE x INT64; SET x = ({q});",
            "DECLARE x INT64; {q};",
        ),
        (
            dialect::bigquery(),
            "DECLARE x INT64 DEFAULT ({q});",
            "DECLARE x INT64; {q};",
        ),
        (
            dialect::databricks(),
            "BEGIN DECLARE x INT; SET VAR x = ({q}); SELECT x; END;",
            "BEGIN DECLARE x INT; {q}; SELECT x; END;",
        ),
        (
            dialect::databricks(),
            "DECLARE VARIABLE x INT; SET VARIABLE x = ({q});",
            "DECLARE VARIABLE x INT; {q};",
        ),
        (dialect::mysql(), "SET @x = ({q});", "{q};"),
        (
            dialect::mysql(),
            "CREATE PROCEDURE p() BEGIN DECLARE x INT; SET x = ({q}); END",
            "CREATE PROCEDURE p() BEGIN DECLARE x INT; {q}; END",
        ),
        (
            dialect::mysql(),
            "CREATE PROCEDURE p() BEGIN DECLARE x INT DEFAULT ({q}); END",
            "CREATE PROCEDURE p() BEGIN DECLARE x INT; {q}; END",
        ),
        (
            dialect::postgres(),
            "DO $$ DECLARE x int; BEGIN x := ({q}); END $$;",
            "DO $$ DECLARE x int; BEGIN {q}; END $$;",
        ),
        (
            dialect::postgres(),
            "DO $$ DECLARE x int := ({q}); BEGIN NULL; END $$;",
            "DO $$ DECLARE x int; BEGIN {q}; NULL; END $$;",
        ),
        (
            dialect::mssql(),
            "DECLARE @x INT; SET @x = ({q});",
            "DECLARE @x INT; {q};",
        ),
        (
            dialect::mssql(),
            "DECLARE @x INT = ({q});",
            "DECLARE @x INT; {q};",
        ),
        (
            dialect::mssql(),
            "DECLARE @x INT = 0; SET @x += ({q});",
            "DECLARE @x INT = 0; {q};",
        ),
    ];
    let q = "SELECT max(id) FROM zz_users";
    for (d, assigned, statement) in cases {
        let assigned = assigned.replace("{q}", q);
        let statement = statement.replace("{q}", q);
        let standalone = findings_and_tables(&statement, d.clone());
        assert!(
            standalone.1.contains("zz_users") || standalone.1.contains("ZZ_USERS"),
            "the query reads its table: {statement}: {standalone:?}"
        );
        assert_eq!(
            findings_and_tables(&assigned, d),
            standalone,
            "the assigned query must be analysed as the statement is:\n{assigned}\n{statement}"
        );
    }
}

#[test]
fn reading_the_queries_an_assignment_takes_is_linear_in_the_source() {
    // One value holding 2,000 queries: each is read once, as a statement.
    let measure = |n: usize| {
        let queries: Vec<String> = (0..n)
            .map(|i| format!("(SELECT max(id) FROM zz_users WHERE id > {i})"))
            .collect();
        let sql = format!(
            "BEGIN LET x INT := 0; x := GREATEST({}); DELETE FROM zz_orders; END;",
            queries.join(", ")
        );
        let cfg = AnalysisConfig {
            dialect: Some(dialect::snowflake()),
            ..Default::default()
        };
        let started = std::time::Instant::now();
        let report = analyze_risk_with_policy_config(&sql, &cfg).expect("should analyze");
        assert_eq!(report.summary.statements_parsed, n + 3);
        assert_eq!(report.summary.statements_skipped, 0);
        assert_eq!(report.summary.tables_written, 1);
        started.elapsed()
    };
    let small = measure(500);
    let large = measure(2000);
    assert!(
        large < small * 8 + std::time::Duration::from_millis(500),
        "four times the input took {large:?} against {small:?}"
    );
}

// ── A statement of SQL a script runs that does not parse is skipped ──────

#[test]
fn a_statement_of_executed_sql_that_does_not_parse_is_skipped() {
    let unparsed = [
        (
            "EXECUTE IMMEDIATE $$ DELETE FROM zz_orders; SELECT FROM WHERE; $$;",
            dialect::snowflake(),
        ),
        (
            "EXECUTE IMMEDIATE 'SELECT FROM WHERE';",
            dialect::snowflake(),
        ),
        (
            "EXECUTE IMMEDIATE $$ BEGIN IF (1 = ) THEN RETURN 1; END IF; \
             DELETE FROM zz_orders; END $$;",
            dialect::snowflake(),
        ),
        (
            "EXECUTE IMMEDIATE $$ DECLARE res RESULTSET DEFAULT \
             (SELECT id FROM zz_users WHERE WHERE); BEGIN DELETE FROM zz_orders; END; $$;",
            dialect::snowflake(),
        ),
        (
            "EXEC ('DELETE FROM dbo.zz_orders; SELECT FROM WHERE')",
            dialect::mssql(),
        ),
        (
            "EXEC sp_executesql N'DELETE FROM dbo.zz_orders; SELECT FROM WHERE'",
            dialect::mssql(),
        ),
        (
            "DECLARE @s NVARCHAR(MAX) = N'DELETE FROM dbo.zz_orders; SELECT FROM WHERE'; \
             EXEC (@s)",
            dialect::mssql(),
        ),
        (
            "DO $$ BEGIN EXECUTE 'DELETE FROM zz_orders; SELECT FROM WHERE'; END $$;",
            dialect::postgres(),
        ),
        (
            "PREPARE st FROM 'DELETE FROM zz_orders WHERE WHERE'; EXECUTE st;",
            dialect::mysql(),
        ),
        (
            "EXECUTE IMMEDIATE 'SELECT FROM WHERE';",
            dialect::bigquery(),
        ),
        (
            "EXECUTE IMMEDIATE 'DELETE FROM zz_orders; SELECT FROM WHERE';",
            dialect::databricks(),
        ),
    ];
    for (sql, d) in unparsed {
        let (skipped, _, _) = body_counts(sql, d);
        assert_eq!(
            skipped, 1,
            "the statement run that does not parse is skipped: {sql}"
        );
    }
    let parsed = [
        "EXECUTE IMMEDIATE 'DELETE FROM zz_orders; DELETE FROM zz_archive';",
        "EXECUTE IMMEDIATE $$ DELETE FROM zz_orders $$;",
    ];
    for sql in parsed {
        let (skipped, _, _) = body_counts(sql, dialect::snowflake());
        assert_eq!(skipped, 0, "every statement run parses: {sql}");
    }
    // A literal a variable is built from is a piece of the statement run.
    let built = [
        "DECLARE @sql NVARCHAR(MAX) = N'DELETE FROM dbo.zz_orders WHERE '\n\
         SET @sql += N'id = 1'\nEXEC (@sql)",
        "DECLARE @a NVARCHAR(MAX) = N'DELETE FROM dbo.zz_orders WHERE '\n\
         DECLARE @b NVARCHAR(MAX) = N'id = 1'\nEXEC (@a + @b)",
    ];
    for sql in built {
        let (skipped, _, _) = body_counts(sql, dialect::mssql());
        assert_eq!(skipped, 0, "the statement run is built whole: {sql}");
    }
    // A statement prepared with parameters.
    let prepared = [
        (
            "PREPARE s FROM 'DELETE FROM zz_orders WHERE id = ?';",
            dialect::mysql(),
        ),
        (
            "EXECUTE IMMEDIATE 'SELECT id FROM zz_users WHERE id = ?' USING (x);",
            dialect::snowflake(),
        ),
        (
            "EXECUTE IMMEDIATE 'SELECT id FROM zz_users WHERE id = :1' USING (x);",
            dialect::snowflake(),
        ),
        (
            "EXECUTE IMMEDIATE 'SELECT id FROM d.zz_users WHERE id = ?' USING 1;",
            dialect::bigquery(),
        ),
    ];
    for (sql, d) in prepared {
        let (skipped, _, _) = body_counts(sql, d);
        assert_eq!(
            skipped, 0,
            "a statement with parameters is not counted: {sql}"
        );
    }
}

#[test]
fn a_statement_run_with_positional_binds_is_counted() {
    // A text holding `:1` is a statement run: what does not parse in it is
    // skipped, and what parses is not.
    for (sql, expected) in [
        (
            "EXECUTE IMMEDIATE 'DELETE FROM zz_orders WHERE id = :1; SELECT FROM WHERE' USING (x);",
            1,
        ),
        (
            "CREATE OR REPLACE PROCEDURE p(x INT) RETURNS INT LANGUAGE SQL AS $$ BEGIN \
             EXECUTE IMMEDIATE 'SELECT FROM WHERE; UPDATE zz_orders SET a = :1' USING (x); \
             RETURN 1; END $$;",
            1,
        ),
        (
            "EXECUTE IMMEDIATE 'SELECT id FROM zz_users WHERE id = :1; UPDATE zz_orders SET a = :2' \
             USING (x, x);",
            0,
        ),
    ] {
        let (skipped, _, _) = body_counts(sql, dialect::snowflake());
        assert_eq!(skipped, expected, "{sql}");
    }
}
