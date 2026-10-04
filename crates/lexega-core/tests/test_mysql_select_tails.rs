// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! MySQL SELECT-tail parser coverage.
//!
//! Covers:
//!   1. Format round-trip safety for every construct
//!   2. AST structure: index hints, LIMIT comma form, LOCK IN SHARE MODE,
//!      INTO OUTFILE/DUMPFILE, named windows, MATCH...AGAINST, @v := and
//!      GROUP_CONCAT SEPARATOR
//!   3. Dialect gating: MySQL-only surface stays rejected under Snowflake
//!   4. Analysis pipeline smoke (parse → lower → facts) for the new shapes

use lexega_core::analyzer::RuleMatch;
use lexega_core::ast::{
    AstIndexHintKind, AstIndexHintScope, AstIntoFileKind, AstSelectIntoTarget, AstStmt,
    AstTextSearchModifierKind, LockStrength,
};
use lexega_core::dialect::{mysql, snowflake};
use lexega_core::{format_sql_with_config, parse_sql_with_dialect, FormatterConfig};
use std::collections::HashSet;

// ============================================================================
// Helpers
// ============================================================================

fn mysql_config() -> FormatterConfig {
    let mut config = FormatterConfig::default();
    config.dialect = mysql();
    config
}

fn format_and_verify(sql: &str) {
    let config = mysql_config();
    let formatted =
        format_sql_with_config(sql, &config).unwrap_or_else(|e| panic!("Format failed: {}", e));
    lexega_core::verify_formatting_safe_with_dialect(sql, &formatted, config.dialect.as_ref())
        .unwrap_or_else(|e| panic!("MySQL formatting verification failed: {}", e));
}

fn parse_mysql(sql: &str) -> lexega_core::ast::AstScript {
    parse_sql_with_dialect(sql, mysql().as_ref())
        .unwrap_or_else(|e| panic!("MySQL parse failed for {:?}: {:?}", sql, e))
}

fn single_select(sql: &str) -> Box<lexega_core::ast::AstSelect> {
    let mut script = parse_mysql(sql);
    assert_eq!(
        script.stmts.len(),
        1,
        "expected one statement for {:?}",
        sql
    );
    match script.stmts.remove(0) {
        AstStmt::Select(sel) => sel,
        other => panic!("expected Select for {:?}, got {}", sql, stmt_name(&other)),
    }
}

fn mysql_analysis_config() -> lexega_core::analyzer::AnalysisConfig {
    let mut config = lexega_core::analyzer::AnalysisConfig::default();
    config.dialect = Some(mysql());
    config
}

/// Variant name from Debug output — avoids a `_ =>` arm on `AstStmt`.
fn stmt_name(stmt: &AstStmt) -> String {
    let dbg = format!("{:?}", stmt);
    dbg.split(|c: char| c == '(' || c == '{' || c.is_whitespace())
        .next()
        .unwrap_or("Unknown")
        .to_string()
}

// ============================================================================
// 1. Format round-trip safety
// ============================================================================

#[test]
fn test_mysql_index_hints_roundtrip() {
    format_and_verify("SELECT * FROM orders USE INDEX (idx_created) WHERE created_at > '2026';");
    format_and_verify("SELECT * FROM orders USE INDEX FOR JOIN (idx_a, idx_b) WHERE id = 1;");
    format_and_verify("SELECT * FROM orders FORCE INDEX (PRIMARY) WHERE id = 1;");
    format_and_verify("SELECT * FROM orders IGNORE INDEX FOR ORDER BY (idx_c) ORDER BY id;");
    format_and_verify("SELECT * FROM orders USE KEY (idx_created) WHERE id = 1;");
    format_and_verify("SELECT * FROM orders USE INDEX () WHERE id = 1;");
    format_and_verify("SELECT * FROM t USE INDEX (i1) IGNORE INDEX FOR GROUP BY (i2) WHERE x = 1;");
}

#[test]
fn test_mysql_index_hint_on_join_table_roundtrip() {
    format_and_verify(
        "SELECT o.id FROM orders o USE INDEX (idx_a) \
         JOIN customers c FORCE INDEX (idx_b) ON o.cid = c.id;",
    );
}

#[test]
fn test_mysql_limit_comma_roundtrip() {
    format_and_verify("SELECT * FROM t LIMIT 10, 20;");
    format_and_verify("SELECT * FROM t ORDER BY id LIMIT 0, 50;");
}

#[test]
fn test_mysql_lock_in_share_mode_roundtrip() {
    format_and_verify("SELECT * FROM accounts WHERE id = 1 LOCK IN SHARE MODE;");
    format_and_verify("SELECT * FROM t LOCK IN SHARE MODE;");
}

#[test]
fn test_mysql_into_outfile_roundtrip() {
    format_and_verify(
        "SELECT id, name INTO OUTFILE '/tmp/out.csv' \
         FIELDS TERMINATED BY ',' ENCLOSED BY '\"' LINES TERMINATED BY '\\n' FROM users;",
    );
    format_and_verify("SELECT id INTO DUMPFILE '/tmp/blob.bin' FROM files WHERE id = 1;");
    format_and_verify("SELECT * FROM users INTO OUTFILE '/tmp/u.csv';");
    format_and_verify("SELECT id FROM t LIMIT 5 INTO OUTFILE '/tmp/x.csv';");
    format_and_verify("SELECT id INTO OUTFILE '/x.csv' CHARACTER SET utf8mb4 FROM t;");
}

#[test]
fn test_mysql_named_window_roundtrip() {
    format_and_verify(
        "SELECT id, SUM(amount) OVER w AS running, RANK() OVER w AS rnk \
         FROM sales WINDOW w AS (PARTITION BY region ORDER BY sold_at) ORDER BY id;",
    );
    format_and_verify("SELECT id, AVG(x) OVER (w ORDER BY y) FROM t WINDOW w AS (PARTITION BY g);");
    format_and_verify(
        "SELECT a, COUNT(*) OVER w1, COUNT(*) OVER w2 FROM t \
         WINDOW w1 AS (PARTITION BY a), w2 AS (w1 ORDER BY b);",
    );
}

#[test]
fn test_mysql_match_against_roundtrip() {
    format_and_verify("SELECT * FROM articles WHERE MATCH(title, body) AGAINST('database');");
    format_and_verify(
        "SELECT * FROM articles WHERE MATCH(title) AGAINST('+mysql -oracle' IN BOOLEAN MODE);",
    );
    format_and_verify(
        "SELECT id, MATCH(body) AGAINST('search' IN NATURAL LANGUAGE MODE) AS score FROM articles;",
    );
    format_and_verify(
        "SELECT * FROM articles WHERE MATCH(body) AGAINST('expand' WITH QUERY EXPANSION);",
    );
}

#[test]
fn test_mysql_var_assign_projection_roundtrip() {
    format_and_verify(
        "SELECT @rownum := @rownum + 1 AS rn, t.* FROM t, (SELECT @rownum := 0) init;",
    );
    format_and_verify("SELECT @total := SUM(amount) FROM orders;");
}

#[test]
fn test_mysql_group_concat_separator_roundtrip() {
    format_and_verify("SELECT g, GROUP_CONCAT(name SEPARATOR ', ') FROM t GROUP BY g;");
    format_and_verify(
        "SELECT g, GROUP_CONCAT(DISTINCT name ORDER BY name DESC SEPARATOR '|') FROM t GROUP BY g;",
    );
    format_and_verify("SELECT GROUP_CONCAT(a, b SEPARATOR '-') FROM t;");
}

// ============================================================================
// 2. AST structure
// ============================================================================

#[test]
fn test_index_hint_ast_structure() {
    let sel = single_select("SELECT * FROM orders USE INDEX FOR JOIN (idx_a, idx_b) WHERE id = 1;");
    let table = sel.from[0]
        .as_table_ref()
        .expect("FROM item should be a table ref");
    let hints = table.index_hints.as_ref().expect("index hints expected");
    assert_eq!(hints.len(), 1);
    let hint = &hints[0];
    assert_eq!(hint.kind, AstIndexHintKind::Use);
    assert!(matches!(hint.scope, Some((AstIndexHintScope::Join, _))));
    assert_eq!(hint.index_name_spans.len(), 2);
}

#[test]
fn test_index_hint_empty_list_and_multiple_hints() {
    let sel = single_select("SELECT * FROM t USE INDEX () WHERE x = 1;");
    let table = sel.from[0].as_table_ref().expect("table ref");
    let hints = table.index_hints.as_ref().expect("hints");
    assert!(hints[0].index_name_spans.is_empty());

    let sel = single_select("SELECT * FROM t USE INDEX (i1) IGNORE INDEX FOR GROUP BY (i2);");
    let table = sel.from[0].as_table_ref().expect("table ref");
    let hints = table.index_hints.as_ref().expect("hints");
    assert_eq!(hints.len(), 2);
    assert_eq!(hints[0].kind, AstIndexHintKind::Use);
    assert_eq!(hints[1].kind, AstIndexHintKind::Ignore);
    assert!(matches!(
        hints[1].scope,
        Some((AstIndexHintScope::GroupBy, _))
    ));
}

#[test]
fn test_index_hint_force_on_join_table() {
    let sel = single_select(
        "SELECT o.id FROM orders o USE INDEX (idx_a) \
         JOIN customers c FORCE INDEX (idx_b) ON o.cid = c.id;",
    );
    let table = sel.from[0].as_table_ref().expect("table ref");
    assert!(table.index_hints.is_some(), "base table hint missing");
    let join = &table.joins[0];
    let join_hints = join
        .right
        .index_hints
        .as_ref()
        .expect("join-table hint missing");
    assert_eq!(join_hints[0].kind, AstIndexHintKind::Force);
}

#[test]
fn test_limit_comma_ast_structure() {
    let sel = single_select("SELECT * FROM t LIMIT 10, 20;");
    assert!(sel.limit_offset_comma_span.is_some(), "comma span missing");
    // Comma form: first expr is the offset, second the count.
    let offset = sel.offset.as_ref().expect("offset expected");
    let limit = sel.limit.as_ref().expect("limit expected");
    assert!(
        offset.span().start < limit.span().start,
        "offset precedes count in source"
    );
    // Statement span must cover the count expression.
    assert!(sel.span.end >= limit.span().end);
}

#[test]
fn test_lock_in_share_mode_ast_structure() {
    let sel = single_select("SELECT * FROM accounts WHERE id = 1 LOCK IN SHARE MODE;");
    let locks = sel.for_update.as_ref().expect("locking clause expected");
    assert_eq!(locks.len(), 1);
    assert_eq!(locks[0].lock_strength, LockStrength::Share);
    assert!(locks[0].wait_policy.is_none());
    assert!(locks[0].of_tables.is_empty());
}

#[test]
fn test_into_outfile_ast_structure() {
    let sel =
        single_select("SELECT id INTO OUTFILE '/tmp/o.csv' FIELDS TERMINATED BY ',' FROM users;");
    let target = sel.into_target.as_deref().expect("into target expected");
    match target {
        AstSelectIntoTarget::OutFile(of) => {
            assert_eq!(of.kind, AstIntoFileKind::Outfile);
            assert!(of.options_span.is_some(), "export options expected");
        }
        AstSelectIntoTarget::ScriptingVars(_) | AstSelectIntoTarget::NewTable(_) => {
            panic!("expected OutFile target")
        }
    }
}

#[test]
fn test_into_dumpfile_and_trailing_position() {
    let sel = single_select("SELECT id INTO DUMPFILE '/tmp/b.bin' FROM files;");
    match sel.into_target.as_deref().expect("target") {
        AstSelectIntoTarget::OutFile(of) => {
            assert_eq!(of.kind, AstIntoFileKind::Dumpfile);
            assert!(of.options_span.is_none(), "DUMPFILE takes no options");
        }
        AstSelectIntoTarget::ScriptingVars(_) | AstSelectIntoTarget::NewTable(_) => {
            panic!("expected OutFile target")
        }
    }

    // Trailing position: span must cover the INTO tail.
    let sel = single_select("SELECT id FROM t LIMIT 5 INTO OUTFILE '/tmp/x.csv';");
    let target = sel.into_target.as_deref().expect("trailing target");
    let end = target.end_pos().expect("end pos");
    assert!(
        sel.span.end >= end,
        "statement span must cover trailing INTO"
    );
}

#[test]
fn test_named_window_ast_structure() {
    let sel = single_select(
        "SELECT a, COUNT(*) OVER w1 FROM t WINDOW w1 AS (PARTITION BY a), w2 AS (w1 ORDER BY b);",
    );
    let wc = sel.window_clause.as_ref().expect("window clause expected");
    assert_eq!(wc.definitions.len(), 2);
}

#[test]
fn test_match_against_ast_structure() {
    use lexega_core::ast::AstExpr;
    let sel =
        single_select("SELECT MATCH(body) AGAINST('q' IN BOOLEAN MODE) AS score FROM articles;");
    let lexega_core::ast::AstProjectionKind::Columns(items) = &sel.projection.kind else {
        panic!("expected column projection");
    };
    let lexega_core::ast::ProjectionItemKind::SelectItem(item) = &items[0].kind else {
        panic!("expected select item");
    };
    match &item.expr {
        AstExpr::MatchAgainst {
            modifier,
            match_call,
            ..
        } => {
            assert!(matches!(match_call.as_ref(), AstExpr::FunctionCall { .. }));
            let m = modifier.as_ref().expect("modifier expected");
            assert_eq!(m.kind, AstTextSearchModifierKind::Boolean);
        }
        other => panic!("expected MatchAgainst, got {:?}", other.span()),
    }
}

#[test]
fn test_var_assign_projection_ast_structure() {
    let sel = single_select("SELECT @total := SUM(amount) FROM orders;");
    let lexega_core::ast::AstProjectionKind::Columns(items) = &sel.projection.kind else {
        panic!("expected column projection");
    };
    let lexega_core::ast::ProjectionItemKind::SelectItem(item) = &items[0].kind else {
        panic!("expected select item");
    };
    let at = item.assign_target.as_ref().expect("assign target expected");
    // assign_op_span covers `:=` (two bytes).
    assert_eq!(at.assign_op_span.end - at.assign_op_span.start, 2);
}

#[test]
fn test_group_concat_separator_ast_structure() {
    use lexega_core::ast::AstExpr;
    let sel = single_select("SELECT GROUP_CONCAT(name ORDER BY name SEPARATOR '|') FROM t;");
    let lexega_core::ast::AstProjectionKind::Columns(items) = &sel.projection.kind else {
        panic!("expected column projection");
    };
    let lexega_core::ast::ProjectionItemKind::SelectItem(item) = &items[0].kind else {
        panic!("expected select item");
    };
    match &item.expr {
        AstExpr::FunctionCall {
            separator_span,
            order_by_span,
            ..
        } => {
            assert!(separator_span.is_some(), "separator span expected");
            assert!(order_by_span.is_some(), "order by span expected");
        }
        other => panic!("expected FunctionCall, got {:?}", other.span()),
    }
}

// ============================================================================
// 3. Dialect gating — MySQL-only surface degrades under Snowflake
// ============================================================================

fn assert_snowflake_opaque(sql: &str) {
    let script = parse_sql_with_dialect(sql, snowflake().as_ref())
        .unwrap_or_else(|e| panic!("script-level parse should not hard-fail: {:?}", e));
    assert!(
        script
            .stmts
            .iter()
            .any(|s| matches!(s, AstStmt::OpaqueContent { .. })),
        "Snowflake should degrade {:?} (at least one opaque), got {:?}",
        sql,
        script.stmts.iter().map(stmt_name).collect::<Vec<_>>()
    );
}

#[test]
fn test_snowflake_rejects_limit_comma() {
    assert_snowflake_opaque("SELECT * FROM t LIMIT 10, 20;");
}

#[test]
fn test_snowflake_rejects_group_concat_separator() {
    assert_snowflake_opaque("SELECT GROUP_CONCAT(name SEPARATOR ', ') FROM t;");
}

#[test]
fn test_snowflake_rejects_into_outfile() {
    assert_snowflake_opaque("SELECT id INTO OUTFILE '/tmp/x.csv' FROM t;");
}

#[test]
fn test_snowflake_does_not_parse_index_hints() {
    // Snowflake: FORCE becomes the table alias; INDEX (...) tail degrades.
    let script = parse_sql_with_dialect(
        "SELECT * FROM orders FORCE INDEX (PRIMARY) WHERE id = 1;",
        snowflake().as_ref(),
    )
    .expect("script-level parse should not hard-fail");
    assert!(
        script
            .stmts
            .iter()
            .any(|s| matches!(s, AstStmt::OpaqueContent { .. })),
        "Snowflake must not absorb MySQL index hints"
    );
}

// ============================================================================
// 4. Analysis pipeline smoke
// ============================================================================

fn mysql_rule_ids(sql: &str) -> HashSet<String> {
    let report = lexega_core::api::analyze_risk_with_policy_config(sql, &mysql_analysis_config())
        .unwrap_or_else(|e| panic!("analysis failed for {:?}: {:?}", sql, e));
    report
        .signals
        .iter()
        .filter_map(|m| match m {
            RuleMatch::Analysis(g) => Some(g.matched_rule.clone()),
        })
        .collect()
}

#[test]
fn test_into_outfile_fires_governance_rule() {
    // OUTFILE, DUMPFILE, and trailing-position INTO all fire MYSQL-INTO-OUTFILE.
    for sql in [
        "SELECT id, email INTO OUTFILE '/tmp/export.csv' FIELDS TERMINATED BY ',' FROM customers;",
        "SELECT id INTO DUMPFILE '/tmp/blob.bin' FROM files WHERE id = 1;",
        "SELECT id FROM t LIMIT 5 INTO OUTFILE '/tmp/x.csv';",
    ] {
        assert!(
            mysql_rule_ids(sql).contains("MYSQL-INTO-OUTFILE"),
            "expected MYSQL-INTO-OUTFILE for {:?}",
            sql
        );
    }
}

#[test]
fn test_plain_select_does_not_fire_outfile_rule() {
    // No file target → rule stays silent (presence-based predicate).
    assert!(
        !mysql_rule_ids("SELECT id, email FROM customers WHERE id = 1;")
            .contains("MYSQL-INTO-OUTFILE"),
        "MYSQL-INTO-OUTFILE must not fire without a file-export target"
    );
}

#[test]
fn test_mysql_select_tails_analysis_smoke() {
    let sql = "SELECT * FROM orders USE INDEX (idx_created) WHERE id = 1;\n\
               SELECT * FROM t LIMIT 10, 20;\n\
               SELECT * FROM accounts WHERE id = 1 LOCK IN SHARE MODE;\n\
               SELECT id INTO OUTFILE '/tmp/o.csv' FROM users;\n\
               SELECT id, SUM(x) OVER w FROM t WINDOW w AS (PARTITION BY g);\n\
               SELECT * FROM a WHERE MATCH(b) AGAINST('q' IN BOOLEAN MODE);\n\
               SELECT @v := COUNT(*) FROM t;\n\
               SELECT GROUP_CONCAT(name SEPARATOR ', ') FROM t;";
    // The pipeline (parse → lower → facts → rules) must not error on any
    // of these shapes.
    let _report = lexega_core::api::analyze_risk_with_policy_config(sql, &mysql_analysis_config())
        .expect("analysis should succeed on MySQL SELECT tails");
}
