// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

// Tests for dialect-dependent || operator semantics:
// - Snowflake/PostgreSQL/BigQuery/MSSQL: || is string concatenation (arithmetic precedence)
// - MySQL: || is logical OR (same precedence as OR keyword)

use lexega_syntax::ast::{AstExpr, AstProjectionKind, BinaryOperator, ProjectionItemKind};
use lexega_syntax::dialect::{bigquery, mssql, mysql, postgres, snowflake, Dialect};
use lexega_syntax::lexer::tokenize_with_dialect;
use lexega_syntax::parser::try_parse_script_with_dialect;
use lexega_syntax::AstStmt;

// ============================================================================
// Helper: extract the expression from the first projection column
// ============================================================================

fn extract_first_expr(sql: &str, dialect: &dyn Dialect) -> AstExpr {
    let result = tokenize_with_dialect(sql, dialect);
    let script = try_parse_script_with_dialect(sql, &result.tokens, dialect).expect("should parse");
    assert_eq!(script.stmts.len(), 1, "expected 1 statement");
    match &script.stmts[0] {
        AstStmt::Select(sel) => match &sel.projection.kind {
            AstProjectionKind::Columns(items) => {
                assert!(!items.is_empty(), "expected at least one projection item");
                match &items[0].kind {
                    ProjectionItemKind::SelectItem(si) => si.expr.clone(),
                    other => panic!(
                        "expected SelectItem, got {:?}",
                        std::mem::discriminant(other)
                    ),
                }
            }
            AstProjectionKind::Star(_) => panic!("expected Columns projection, got Star"),
        },
        other => panic!("expected Select, got {:?}", std::mem::discriminant(other)),
    }
}

fn top_operator(sql: &str, dialect: &dyn Dialect) -> BinaryOperator {
    let expr = extract_first_expr(sql, dialect);
    match &expr {
        AstExpr::BinaryOp { operator, .. } => operator.clone(),
        other => panic!(
            "expected BinaryOp at top level, got {:?}",
            std::mem::discriminant(other)
        ),
    }
}

/// Parse SQL and return the full expression tree of the first projection
fn first_projection_expr(sql: &str, dialect: &dyn Dialect) -> AstExpr {
    extract_first_expr(sql, dialect)
}

// ============================================================================
// Core semantics: || means different things per dialect
// ============================================================================

#[test]
fn test_snowflake_pipe_pipe_is_concat() {
    let op = top_operator("SELECT a || b", &*snowflake());
    assert_eq!(
        op,
        BinaryOperator::Concat,
        "Snowflake should parse || as Concat"
    );
}

#[test]
fn test_postgres_pipe_pipe_is_concat() {
    let op = top_operator("SELECT a || b", &*postgres());
    assert_eq!(
        op,
        BinaryOperator::Concat,
        "PostgreSQL should parse || as Concat"
    );
}

#[test]
fn test_mysql_pipe_pipe_is_logical_or() {
    let op = top_operator("SELECT a || b", &*mysql());
    assert_eq!(
        op,
        BinaryOperator::LogicalOr,
        "MySQL should parse || as LogicalOr"
    );
}

// ============================================================================
// Precedence: || as concat binds tighter than comparison;
//             || as logical OR binds looser than comparison
// ============================================================================

#[test]
fn test_snowflake_concat_precedence_tighter_than_comparison() {
    // In Snowflake: a || b = c  parses as  (a || b) = c
    // Because concat (40) > comparison (30)
    let expr = first_projection_expr("SELECT a || b = c", &*snowflake());
    match &expr {
        AstExpr::BinaryOp {
            operator: BinaryOperator::Equal,
            left,
            ..
        } => {
            // Left should be the concat
            match left.as_ref() {
                AstExpr::BinaryOp {
                    operator: BinaryOperator::Concat,
                    ..
                } => {
                    // Correct: (a || b) = c
                }
                other => panic!(
                    "Expected Concat on left of Equal, got {:?}",
                    std::mem::discriminant(other)
                ),
            }
        }
        other => panic!(
            "Expected Equal at top level for Snowflake, got {:?}",
            std::mem::discriminant(other)
        ),
    }
}

#[test]
fn test_mysql_logical_or_precedence_looser_than_comparison() {
    // In MySQL: a = 1 || b = 2  parses as  (a = 1) || (b = 2)
    // Because logical OR (10) < comparison (30)
    let expr = first_projection_expr("SELECT a = 1 || b = 2", &*mysql());
    match &expr {
        AstExpr::BinaryOp {
            operator: BinaryOperator::LogicalOr,
            left,
            right,
            ..
        } => {
            // Left should be a = 1
            match left.as_ref() {
                AstExpr::BinaryOp {
                    operator: BinaryOperator::Equal,
                    ..
                } => {}
                other => panic!(
                    "Expected Equal on left of LogicalOr, got {:?}",
                    std::mem::discriminant(other)
                ),
            }
            // Right should be b = 2
            match right.as_ref() {
                AstExpr::BinaryOp {
                    operator: BinaryOperator::Equal,
                    ..
                } => {}
                other => panic!(
                    "Expected Equal on right of LogicalOr, got {:?}",
                    std::mem::discriminant(other)
                ),
            }
        }
        other => panic!(
            "Expected LogicalOr at top level for MySQL, got {:?}",
            std::mem::discriminant(other)
        ),
    }
}

#[test]
fn test_snowflake_concat_in_arithmetic_context() {
    // In Snowflake: a || b || c  chains as concat
    let expr = first_projection_expr("SELECT a || b || c", &*snowflake());
    match &expr {
        AstExpr::BinaryOp {
            operator: BinaryOperator::Concat,
            left,
            ..
        } => {
            match left.as_ref() {
                AstExpr::BinaryOp {
                    operator: BinaryOperator::Concat,
                    ..
                } => {
                    // Correct: left-associative concat chain
                }
                other => panic!(
                    "Expected nested Concat, got {:?}",
                    std::mem::discriminant(other)
                ),
            }
        }
        other => panic!(
            "Expected Concat at top, got {:?}",
            std::mem::discriminant(other)
        ),
    }
}

#[test]
fn test_mysql_logical_or_chain() {
    // In MySQL: a || b || c  chains as logical OR
    let expr = first_projection_expr("SELECT a || b || c", &*mysql());
    match &expr {
        AstExpr::BinaryOp {
            operator: BinaryOperator::LogicalOr,
            left,
            ..
        } => {
            match left.as_ref() {
                AstExpr::BinaryOp {
                    operator: BinaryOperator::LogicalOr,
                    ..
                } => {
                    // Correct: left-associative logical OR chain
                }
                other => panic!(
                    "Expected nested LogicalOr, got {:?}",
                    std::mem::discriminant(other)
                ),
            }
        }
        other => panic!(
            "Expected LogicalOr at top, got {:?}",
            std::mem::discriminant(other)
        ),
    }
}

// ============================================================================
// Mixed operators: || interacts differently with AND per dialect
// ============================================================================

#[test]
fn test_mysql_and_binds_tighter_than_pipe_pipe() {
    // In MySQL: a || b AND c  parses as  a || (b AND c)
    // Because AND (20) > OR (10)
    let expr = first_projection_expr("SELECT a || b AND c", &*mysql());
    match &expr {
        AstExpr::BinaryOp {
            operator: BinaryOperator::LogicalOr,
            right,
            ..
        } => {
            match right.as_ref() {
                AstExpr::BinaryOp {
                    operator: BinaryOperator::And,
                    ..
                } => {
                    // Correct: a || (b AND c)
                }
                other => panic!(
                    "Expected And on right of LogicalOr, got {:?}",
                    std::mem::discriminant(other)
                ),
            }
        }
        other => panic!(
            "Expected LogicalOr at top for MySQL, got {:?}",
            std::mem::discriminant(other)
        ),
    }
}

#[test]
fn test_snowflake_concat_binds_tighter_than_and() {
    // In Snowflake: a || b AND c  parses as  (a || b) AND c
    // Because concat (40) > AND (20)
    let expr = first_projection_expr("SELECT a || b AND c", &*snowflake());
    match &expr {
        AstExpr::BinaryOp {
            operator: BinaryOperator::And,
            left,
            ..
        } => {
            match left.as_ref() {
                AstExpr::BinaryOp {
                    operator: BinaryOperator::Concat,
                    ..
                } => {
                    // Correct: (a || b) AND c
                }
                other => panic!(
                    "Expected Concat on left of And, got {:?}",
                    std::mem::discriminant(other)
                ),
            }
        }
        other => panic!(
            "Expected And at top for Snowflake, got {:?}",
            std::mem::discriminant(other)
        ),
    }
}

// ============================================================================
// Real-world patterns
// ============================================================================

#[test]
fn test_mysql_where_clause_with_logical_or() {
    // MySQL real-world: WHERE status = 'active' || role = 'admin'
    let sql = "SELECT id FROM users WHERE status = 'active' || role = 'admin'";
    let d = mysql();
    let result = tokenize_with_dialect(sql, &*d);
    let script = try_parse_script_with_dialect(sql, &result.tokens, &*d)
        .expect("should parse MySQL WHERE with ||");
    assert_eq!(script.stmts.len(), 1);
}

#[test]
fn test_snowflake_concat_in_select() {
    // Snowflake real-world: SELECT first_name || ' ' || last_name
    let sql = "SELECT first_name || ' ' || last_name FROM employees";
    let d = snowflake();
    let result = tokenize_with_dialect(sql, &*d);
    let script = try_parse_script_with_dialect(sql, &result.tokens, &*d)
        .expect("should parse Snowflake concat");
    assert_eq!(script.stmts.len(), 1);
}

#[test]
fn test_postgres_concat_in_select() {
    // PostgreSQL real-world: SELECT 'Hello' || ' ' || 'World'
    let sql = "SELECT 'Hello' || ' ' || 'World'";
    let d = postgres();
    let result = tokenize_with_dialect(sql, &*d);
    let script =
        try_parse_script_with_dialect(sql, &result.tokens, &*d).expect("should parse PG concat");
    assert_eq!(script.stmts.len(), 1);
}

// ============================================================================
// Formatting round-trip: || should be preserved regardless of semantics
// ============================================================================

fn format_and_verify_dialect(sql: &str, dialect: lexega_syntax::dialect::DialectRef) {
    let mut config = lexega_syntax::FormatterConfig::default();
    config.dialect = dialect.clone();
    let formatted = lexega_syntax::format_sql_with_config(sql, &config)
        .unwrap_or_else(|e| panic!("Format failed for {}: {}", dialect.name(), e));
    lexega_syntax::verify_formatting_safe_with_dialect(sql, &formatted, dialect.as_ref())
        .unwrap_or_else(|e| {
            panic!(
                "{} || formatting verification failed: {}",
                dialect.name(),
                e
            )
        });
}

#[test]
fn test_mysql_pipe_pipe_preserved_in_formatting() {
    // Even though MySQL treats || as logical OR, the token text should be preserved
    format_and_verify_dialect("SELECT a || b", mysql());
}

#[test]
fn test_snowflake_pipe_pipe_format_roundtrip() {
    format_and_verify_dialect(
        "SELECT first_name || ' ' || last_name FROM employees",
        snowflake(),
    );
}

#[test]
fn test_postgres_pipe_pipe_format_roundtrip() {
    format_and_verify_dialect("SELECT 'Hello' || ' ' || 'World'", postgres());
}

#[test]
fn test_bigquery_pipe_pipe_is_concat() {
    let op = top_operator("SELECT a || b", &*bigquery());
    assert_eq!(
        op,
        BinaryOperator::Concat,
        "BigQuery should parse || as Concat"
    );
}

#[test]
fn test_bigquery_pipe_pipe_format_roundtrip() {
    format_and_verify_dialect("SELECT a || b || c", bigquery());
}

#[test]
fn test_mssql_pipe_pipe_is_concat() {
    let op = top_operator("SELECT a || b", &*mssql());
    assert_eq!(
        op,
        BinaryOperator::Concat,
        "MSSQL should parse || as Concat"
    );
}

#[test]
fn test_mssql_pipe_pipe_format_roundtrip() {
    format_and_verify_dialect("SELECT a || b || c", mssql());
}

// ============================================================================
// Cross-dialect divergence: same SQL, different parse trees
// ============================================================================

#[test]
fn test_cross_dialect_pipe_pipe_diverges() {
    let sql = "SELECT x || y";

    let sf_op = top_operator(sql, &*snowflake());
    let pg_op = top_operator(sql, &*postgres());
    let my_op = top_operator(sql, &*mysql());
    let bq_op = top_operator(sql, &*bigquery());
    let ms_op = top_operator(sql, &*mssql());

    assert_eq!(sf_op, BinaryOperator::Concat, "Snowflake: ||=Concat");
    assert_eq!(pg_op, BinaryOperator::Concat, "PostgreSQL: ||=Concat");
    assert_eq!(my_op, BinaryOperator::LogicalOr, "MySQL: ||=LogicalOr");
    assert_eq!(bq_op, BinaryOperator::Concat, "BigQuery: ||=Concat");
    assert_eq!(ms_op, BinaryOperator::Concat, "MSSQL: ||=Concat");
}

#[test]
fn test_cross_dialect_precedence_diverges() {
    // a + b || c
    // Snowflake: a + (b || c) — NO, || is same precedence as +, so left-assoc: (a + b) || c
    // Actually both are (40,41), so left-associative: (a + b) || c
    // MySQL: (a + b) || c — but || is (10,11), so this is: (a + b) || c too
    // The difference shows with comparisons:

    // Snowflake: a = (b || c) = d — but = is (30,31) and || is (40,41)
    // So: a = ((b || c) = d)? No — = is left-assoc at 30, || at 40 binds tighter
    // Parse: first we get 'a', then '=' at bp 30, rhs parses 'b || c = d'
    // In rhs: 'b', then '||' at bp 40 > 30, so binds: 'b || c', then '=' at 30 = min_bp 31? No, 30 < 31
    // So rhs is 'b || c', then back to outer '=', full: a = (b || c), then '=' tries again but 30 < 31
    // Hmm, this gets into multi-comparison territory. Let me use a simpler test.

    // Simpler: SELECT a || b > c
    let sql2 = "SELECT a || b > c";

    // Snowflake: || (40) > comparison (30), so: (a || b) > c
    let sf_expr = first_projection_expr(sql2, &*snowflake());
    match &sf_expr {
        AstExpr::BinaryOp {
            operator: BinaryOperator::GreaterThan,
            ..
        } => {
            // Top is >, meaning (a || b) > c — concat bound tighter
        }
        other => panic!(
            "Snowflake: expected > at top, got {:?}",
            std::mem::discriminant(other)
        ),
    }

    // MySQL: || (10) < comparison (30), so: a || (b > c)
    let my_expr = first_projection_expr(sql2, &*mysql());
    match &my_expr {
        AstExpr::BinaryOp {
            operator: BinaryOperator::LogicalOr,
            ..
        } => {
            // Top is ||, meaning a || (b > c) — comparison bound tighter
        }
        other => panic!(
            "MySQL: expected LogicalOr at top, got {:?}",
            std::mem::discriminant(other)
        ),
    }
}
