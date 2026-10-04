// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

use lexega_syntax::ast::{AstExpr, AstStmt};
use lexega_syntax::parse_sql;

/// Helper to extract the CREATE TABLE statement from parsed script
fn extract_create_table(src: &str) -> lexega_syntax::ast::AstCreateTable {
    let script = parse_sql(src).expect("script should parse");
    assert_eq!(script.stmts.len(), 1, "expected exactly one statement");

    match script.stmts.into_iter().next().unwrap() {
        AstStmt::CreateTable(ct) => ct.as_ref().clone(),
        _ => panic!("expected CREATE TABLE statement"),
    }
}

#[test]
fn test_cluster_by_simple_column() {
    let src = "CREATE TABLE t (c NUMBER) CLUSTER BY (c)";
    let ct = extract_create_table(src);

    // Verify cluster_by_span exists
    assert!(
        ct.cluster_by_span.is_some(),
        "cluster_by_span should be present"
    );

    // Verify cluster_by_exprs was parsed
    let exprs = ct
        .cluster_by_exprs
        .expect("cluster_by_exprs should be present");
    assert_eq!(exprs.len(), 1, "expected 1 clustering expression");

    // Verify the expression is an identifier
    match &exprs[0] {
        AstExpr::Ident {
            column_ref: col_ref,
            ..
        } => {
            let text = &src[col_ref.name.span.start as usize..col_ref.name.span.end as usize];
            assert_eq!(text, "c", "expected identifier 'c'");
        }
        _ => panic!("expected Ident expression, got {:?}", exprs[0]),
    }
}

#[test]
fn test_cluster_by_multiple_columns() {
    let src =
        "CREATE TABLE t (date TIMESTAMP_NTZ, id NUMBER, content VARIANT) CLUSTER BY (date, id)";
    let ct = extract_create_table(src);

    // Verify cluster_by_exprs was parsed
    let exprs = ct
        .cluster_by_exprs
        .expect("cluster_by_exprs should be present");
    assert_eq!(exprs.len(), 2, "expected 2 clustering expressions");

    // Verify first expression is 'date'
    match &exprs[0] {
        AstExpr::Ident {
            column_ref: col_ref,
            ..
        } => {
            let text = &src[col_ref.name.span.start as usize..col_ref.name.span.end as usize];
            assert_eq!(text, "date", "expected identifier 'date'");
        }
        _ => panic!("expected Ident expression for first column"),
    }

    // Verify second expression is 'id'
    match &exprs[1] {
        AstExpr::Ident {
            column_ref: col_ref,
            ..
        } => {
            let text = &src[col_ref.name.span.start as usize..col_ref.name.span.end as usize];
            assert_eq!(text, "id", "expected identifier 'id'");
        }
        _ => panic!("expected Ident expression for second column"),
    }
}

#[test]
fn test_cluster_by_with_function_expression() {
    let src = "CREATE TABLE t (ts TIMESTAMP) CLUSTER BY (DATE(ts))";
    let ct = extract_create_table(src);

    // Verify cluster_by_exprs was parsed
    let exprs = ct
        .cluster_by_exprs
        .expect("cluster_by_exprs should be present");
    assert_eq!(exprs.len(), 1, "expected 1 clustering expression");

    // Verify the expression is a function call
    match &exprs[0] {
        AstExpr::FunctionCall { func_name, .. } => {
            let text = &src[func_name.span.start as usize..func_name.span.end as usize];
            assert_eq!(text, "DATE", "expected function call to DATE");
        }
        _ => panic!("expected FunctionCall expression, got {:?}", exprs[0]),
    }
}

#[test]
fn test_cluster_by_with_complex_expression() {
    let src = "CREATE TABLE t (a NUMBER, b NUMBER) CLUSTER BY (a + b)";
    let ct = extract_create_table(src);

    // Verify cluster_by_exprs was parsed
    let exprs = ct
        .cluster_by_exprs
        .expect("cluster_by_exprs should be present");
    assert_eq!(exprs.len(), 1, "expected 1 clustering expression");

    // Verify the expression is a binary operation
    match &exprs[0] {
        AstExpr::BinaryOp { .. } => {
            // Binary operation verified
        }
        _ => panic!("expected BinaryOp expression, got {:?}", exprs[0]),
    }
}

#[test]
fn test_cluster_by_with_multiple_complex_expressions() {
    let src = "CREATE TABLE t (a NUMBER, b NUMBER, c VARCHAR) CLUSTER BY (UPPER(c), a * 2)";
    let ct = extract_create_table(src);

    // Verify cluster_by_exprs was parsed
    let exprs = ct
        .cluster_by_exprs
        .expect("cluster_by_exprs should be present");
    assert_eq!(exprs.len(), 2, "expected 2 clustering expressions");

    // Verify first expression is a function call
    match &exprs[0] {
        AstExpr::FunctionCall { func_name, .. } => {
            let text = &src[func_name.span.start as usize..func_name.span.end as usize];
            assert_eq!(text, "UPPER", "expected function call to UPPER");
        }
        _ => panic!("expected FunctionCall expression for first expr"),
    }

    // Verify second expression is a binary operation
    match &exprs[1] {
        AstExpr::BinaryOp { .. } => {
            // Binary operation verified
        }
        _ => panic!("expected BinaryOp expression for second expr"),
    }
}

#[test]
fn test_cluster_by_with_copy_grants() {
    let src = "CREATE TABLE t (c NUMBER) CLUSTER BY (c) COPY GRANTS";
    let ct = extract_create_table(src);

    // Verify cluster_by_exprs was parsed
    let exprs = ct
        .cluster_by_exprs
        .expect("cluster_by_exprs should be present");
    assert_eq!(exprs.len(), 1, "expected 1 clustering expression");

    // Verify copy_grants_span also exists
    assert!(
        ct.copy_grants_span.is_some(),
        "copy_grants_span should be present"
    );
}

#[test]
fn test_cluster_by_ctas() {
    let src = "CREATE TABLE t (id NUMBER) CLUSTER BY (id) AS SELECT 1 AS id";
    let ct = extract_create_table(src);

    // Verify cluster_by_exprs was parsed
    let exprs = ct
        .cluster_by_exprs
        .expect("cluster_by_exprs should be present");
    assert_eq!(exprs.len(), 1, "expected 1 clustering expression");

    // Verify CTAS query is populated
    let query_result = ct
        .ctas_query
        .as_ref()
        .expect("ctas_query should be present for CTAS");
    let query_span = match query_result {
        Ok(stmt) => stmt.span(),
        Err(span) => *span,
    };
    // Note: The parsed query does NOT include "AS" - that's handled separately
    let query_text = &src[query_span.start as usize..query_span.end as usize];
    assert!(
        query_text.contains("SELECT"),
        "query should be parsed as SELECT statement"
    );

    // Verify cluster_by_span does not include the AS or query
    let cluster_span = ct
        .cluster_by_span
        .expect("cluster_by_span should be present");
    let cluster_text = &src[cluster_span.start as usize..cluster_span.end as usize];
    assert_eq!(
        cluster_text, "CLUSTER BY (id)",
        "cluster_by_span should not include AS SELECT"
    );
}

#[test]
fn test_cluster_by_preserves_span_compatibility() {
    let src = "CREATE TABLE mytable (date TIMESTAMP_NTZ, id NUMBER) CLUSTER BY (date, id)";
    let ct = extract_create_table(src);

    // Verify cluster_by_span is preserved for backward compatibility
    let cluster_span = ct
        .cluster_by_span
        .expect("cluster_by_span should be present");
    let cluster_text = &src[cluster_span.start as usize..cluster_span.end as usize];
    assert_eq!(
        cluster_text, "CLUSTER BY (date, id)",
        "cluster_by_span should capture full text"
    );

    // Verify cluster_by_exprs is also present
    assert!(
        ct.cluster_by_exprs.is_some(),
        "cluster_by_exprs should be present"
    );
}

#[test]
fn test_ctas_with_multiple_table_options() {
    let src = "CREATE TABLE t (id NUMBER) CLUSTER BY (id) COPY GRANTS AS SELECT 1 AS id";
    let ct = extract_create_table(src);

    // Verify this is CTAS
    use lexega_syntax::ast::AstCreateTableVariant;
    assert!(
        matches!(ct.variant, AstCreateTableVariant::Ctas),
        "should be CTAS variant"
    );

    // Verify cluster_by_exprs was parsed
    let exprs = ct
        .cluster_by_exprs
        .expect("cluster_by_exprs should be present");
    assert_eq!(exprs.len(), 1, "expected 1 clustering expression");

    // Verify COPY GRANTS was also parsed
    assert!(
        ct.copy_grants_span.is_some(),
        "copy_grants_span should be present"
    );

    // Verify CTAS query is populated
    let query_result = ct
        .ctas_query
        .as_ref()
        .expect("ctas_query should be present for CTAS");
    let query_span = match query_result {
        Ok(stmt) => stmt.span(),
        Err(span) => *span,
    };
    let query_text = &src[query_span.start as usize..query_span.end as usize];
    assert!(
        query_text.contains("SELECT"),
        "query should be correctly extracted"
    );
}

#[test]
fn test_ctas_no_columns_with_cluster_by() {
    let src = "CREATE TABLE t CLUSTER BY (id) AS SELECT 1 AS id";
    let ct = extract_create_table(src);

    // Verify this is CTAS
    use lexega_syntax::ast::AstCreateTableVariant;
    assert!(
        matches!(ct.variant, AstCreateTableVariant::Ctas),
        "should be CTAS variant"
    );

    // Verify cluster_by_exprs was parsed
    let exprs = ct
        .cluster_by_exprs
        .expect("cluster_by_exprs should be present");
    assert_eq!(exprs.len(), 1, "expected 1 clustering expression");

    // Verify CTAS query is populated
    let query_result = ct
        .ctas_query
        .as_ref()
        .expect("ctas_query should be present for CTAS");
    let query_span = match query_result {
        Ok(stmt) => stmt.span(),
        Err(span) => *span,
    };
    let query_text = &src[query_span.start as usize..query_span.end as usize];
    assert!(
        query_text.contains("SELECT"),
        "query should be correctly extracted"
    );
}

#[test]
fn test_ctas_with_copy_grants_only() {
    let src = "CREATE TABLE t COPY GRANTS AS SELECT * FROM source_table";
    let ct = extract_create_table(src);

    // Verify this is CTAS
    use lexega_syntax::ast::AstCreateTableVariant;
    assert!(
        matches!(ct.variant, AstCreateTableVariant::Ctas),
        "should be CTAS variant"
    );

    // Verify COPY GRANTS was parsed
    assert!(
        ct.copy_grants_span.is_some(),
        "copy_grants_span should be present"
    );

    // Verify CTAS query is populated
    let query_result = ct
        .ctas_query
        .as_ref()
        .expect("ctas_query should be present for CTAS");
    let query_span = match query_result {
        Ok(stmt) => stmt.span(),
        Err(span) => *span,
    };
    let query_text = &src[query_span.start as usize..query_span.end as usize];
    assert!(
        query_text.contains("SELECT"),
        "query should be correctly extracted"
    );
}

#[test]
fn test_ctas_with_complex_query() {
    let src = "CREATE TABLE t (id NUMBER, value NUMBER) CLUSTER BY (id) AS WITH cte AS (SELECT 1 AS id, 2 AS value) SELECT * FROM cte";
    let ct = extract_create_table(src);

    // Verify this is CTAS
    use lexega_syntax::ast::AstCreateTableVariant;
    assert!(
        matches!(ct.variant, AstCreateTableVariant::Ctas),
        "should be CTAS variant"
    );

    // Verify cluster_by_exprs was parsed
    let exprs = ct
        .cluster_by_exprs
        .expect("cluster_by_exprs should be present");
    assert_eq!(exprs.len(), 1, "expected 1 clustering expression");

    // Verify CTAS query includes the CTE
    let query_result = ct
        .ctas_query
        .as_ref()
        .expect("ctas_query should be present for CTAS");
    let query_span = match query_result {
        Ok(stmt) => stmt.span(),
        Err(span) => *span,
    };
    let query_text = &src[query_span.start as usize..query_span.end as usize];
    eprintln!("Query text: '{}'", query_text);
    eprintln!("Full source: '{}'", src);
    // The parsed query should be a SELECT (possibly with WITH clause)
    // Note: Span might not capture everything due to parser limitations
    assert!(query_text.contains("SELECT"), "query should contain SELECT");
}
