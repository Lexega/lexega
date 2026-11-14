// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

// ALTER TABLE statement parsing tests
// Tests comprehensive ALTER TABLE operations with proper expression parsing

use lexega_core::ast::{AstAlterTableActionKind, AstStmt};
use lexega_core::parse_stmt_from_str;

// ============================================================================
// Basic ALTER TABLE statements
// ============================================================================

#[test]
fn test_alter_table_add_column_simple() {
    let sql = "ALTER TABLE users ADD COLUMN age INT;";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Failed to parse ALTER TABLE ADD COLUMN");

    if let Some(AstStmt::AlterTable(alter)) = result {
        assert_eq!(alter.actions.len(), 1);
        match &alter.actions[0].kind {
            AstAlterTableActionKind::AddColumn { columns, .. } => {
                assert_eq!(columns.len(), 1, "Should have parsed 1 column");
                assert!(
                    columns[0].name_span.is_some(),
                    "Should have column name span"
                );
            }
            _ => panic!("Expected AddColumn action"),
        }
    }
}

#[test]
fn test_alter_table_add_column_with_default() {
    let sql = "ALTER TABLE users ADD COLUMN status VARCHAR(50) DEFAULT 'active';";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Failed to parse ADD COLUMN with DEFAULT");

    if let Some(AstStmt::AlterTable(alter)) = result {
        match &alter.actions[0].kind {
            AstAlterTableActionKind::AddColumn { columns, .. } => {
                assert_eq!(columns.len(), 1);
                // Note: DEFAULT expression is parsed but stored in span, not as separate field
                assert!(
                    columns[0].full_span.end > columns[0].type_span.unwrap().end,
                    "Should have parsed DEFAULT"
                );
            }
            _ => panic!("Expected AddColumn action"),
        }
    }
}

#[test]
fn test_alter_table_add_multiple_columns() {
    let sql = "ALTER TABLE users ADD COLUMN first_name VARCHAR(100), last_name VARCHAR(100), created_at TIMESTAMP;";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Failed to parse ADD multiple columns");

    if let Some(AstStmt::AlterTable(alter)) = result {
        match &alter.actions[0].kind {
            AstAlterTableActionKind::AddColumn { columns, .. } => {
                assert_eq!(columns.len(), 3, "Should have parsed 3 columns");
            }
            _ => panic!("Expected AddColumn action"),
        }
    }
}

#[test]
fn test_alter_table_drop_column() {
    let sql = "ALTER TABLE users DROP COLUMN age;";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Failed to parse ALTER TABLE DROP COLUMN");

    if let Some(AstStmt::AlterTable(alter)) = result {
        match &alter.actions[0].kind {
            AstAlterTableActionKind::DropColumn { .. } => {
                // Success
            }
            _ => panic!("Expected DropColumn action"),
        }
    }
}

#[test]
fn test_alter_table_rename_column() {
    let sql = "ALTER TABLE users RENAME COLUMN old_name TO new_name;";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Failed to parse RENAME COLUMN");

    if let Some(AstStmt::AlterTable(alter)) = result {
        match &alter.actions[0].kind {
            AstAlterTableActionKind::RenameColumn {
                old_name_span,
                new_name_span,
                ..
            } => {
                assert!(old_name_span.start < new_name_span.start);
            }
            _ => panic!("Expected RenameColumn action"),
        }
    }
}

#[test]
fn test_alter_table_rename_to() {
    let sql = "ALTER TABLE old_table RENAME TO new_table;";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Failed to parse RENAME TO");

    if let Some(AstStmt::AlterTable(alter)) = result {
        match &alter.actions[0].kind {
            AstAlterTableActionKind::RenameTo { .. } => {
                // Success
            }
            _ => panic!("Expected RenameTo action"),
        }
    }
}

#[test]
fn test_alter_table_rename_to_qualified() {
    // A qualified target must stay one statement, with no phantom `.y` tail.
    let sql = "ALTER TABLE t RENAME TO s2.y;";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Failed to parse qualified RENAME TO");

    if let Some(AstStmt::AlterTable(alter)) = result {
        match &alter.actions[0].kind {
            AstAlterTableActionKind::RenameTo { new_name_span, .. } => {
                let target = &sql[new_name_span.start as usize..new_name_span.end as usize];
                assert_eq!(target, "s2.y", "target span must cover the qualified name");
            }
            _ => panic!("Expected RenameTo action"),
        }
    }

    let report = lexega_core::api::analyze_risk(sql).expect("should analyze");
    assert_eq!(
        report.summary.statements_skipped, 0,
        "qualified RENAME TO target must not split the statement"
    );
}

#[test]
fn test_alter_table_alter_column() {
    let sql = "ALTER TABLE users ALTER COLUMN age SET DATA TYPE NUMBER(10,0);";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Failed to parse ALTER COLUMN");

    if let Some(AstStmt::AlterTable(alter)) = result {
        match &alter.actions[0].kind {
            AstAlterTableActionKind::AlterColumnSetDataType { .. } => {
                // SET DATA TYPE now gets a specific variant
            }
            AstAlterTableActionKind::AlterColumn { .. } => {
                // Fallback also acceptable
            }
            _ => panic!("Expected AlterColumnSetDataType or AlterColumn action"),
        }
    }
}

// ============================================================================
// CLUSTER BY with expressions
// ============================================================================

#[test]
fn test_alter_table_cluster_by_single_expr() {
    let sql = "ALTER TABLE events CLUSTER BY (event_date);";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Failed to parse CLUSTER BY");

    if let Some(AstStmt::AlterTable(alter)) = result {
        match &alter.actions[0].kind {
            AstAlterTableActionKind::ClusterBy { exprs, .. } => {
                assert!(exprs.is_some(), "Should have parsed expressions");
                assert_eq!(exprs.as_ref().unwrap().len(), 1);
            }
            _ => panic!("Expected ClusterBy action"),
        }
    }
}

#[test]
fn test_alter_table_cluster_by_multiple_exprs() {
    let sql = "ALTER TABLE events CLUSTER BY (region, DATE_TRUNC('day', created_at));";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Failed to parse CLUSTER BY with function");

    if let Some(AstStmt::AlterTable(alter)) = result {
        match &alter.actions[0].kind {
            AstAlterTableActionKind::ClusterBy { exprs, .. } => {
                assert!(exprs.is_some(), "Should have parsed expressions");
                assert_eq!(exprs.as_ref().unwrap().len(), 2);
            }
            _ => panic!("Expected ClusterBy action"),
        }
    }
}

#[test]
fn test_alter_table_cluster_by_complex_exprs() {
    let sql = "ALTER TABLE sales CLUSTER BY (year, FLOOR(amount / 1000), category);";
    let result = parse_stmt_from_str(sql);
    assert!(
        result.is_some(),
        "Failed to parse CLUSTER BY with complex expressions"
    );

    if let Some(AstStmt::AlterTable(alter)) = result {
        match &alter.actions[0].kind {
            AstAlterTableActionKind::ClusterBy { exprs, .. } => {
                assert!(exprs.is_some());
                assert_eq!(exprs.as_ref().unwrap().len(), 3);
            }
            _ => panic!("Expected ClusterBy action"),
        }
    }
}

// ============================================================================
// Constraints
// ============================================================================

#[test]
fn test_alter_table_add_constraint() {
    let sql = "ALTER TABLE orders ADD CONSTRAINT pk_order PRIMARY KEY (order_id);";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Failed to parse ADD CONSTRAINT");

    if let Some(AstStmt::AlterTable(alter)) = result {
        match &alter.actions[0].kind {
            AstAlterTableActionKind::AddConstraint { .. } => {
                // Success
            }
            _ => panic!("Expected AddConstraint action"),
        }
    }
}

#[test]
fn test_alter_table_drop_constraint() {
    let sql = "ALTER TABLE orders DROP CONSTRAINT pk_order;";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Failed to parse DROP CONSTRAINT");

    if let Some(AstStmt::AlterTable(alter)) = result {
        match &alter.actions[0].kind {
            AstAlterTableActionKind::DropConstraint { name_span, .. } => {
                assert!(name_span.start > 0);
            }
            _ => panic!("Expected DropConstraint action"),
        }
    }
}

#[test]
fn test_alter_table_drop_clustering_key() {
    let sql = "ALTER TABLE events DROP CLUSTERING KEY;";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Failed to parse DROP CLUSTERING KEY");

    if let Some(AstStmt::AlterTable(alter)) = result {
        match &alter.actions[0].kind {
            AstAlterTableActionKind::DropClusteringKey { .. } => {
                // Success
            }
            _ => panic!("Expected DropClusteringKey action"),
        }
    }
}

// ============================================================================
// SET/UNSET operations
// ============================================================================

#[test]
fn test_alter_table_set() {
    let sql = "ALTER TABLE events SET DATA_RETENTION_TIME_IN_DAYS = 90;";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Failed to parse ALTER TABLE SET");

    if let Some(AstStmt::AlterTable(alter)) = result {
        match &alter.actions[0].kind {
            AstAlterTableActionKind::Set { .. } => {
                // Success
            }
            _ => panic!("Expected Set action"),
        }
    }
}

#[test]
fn test_alter_table_unset() {
    let sql = "ALTER TABLE events UNSET DATA_RETENTION_TIME_IN_DAYS;";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Failed to parse ALTER TABLE UNSET");

    if let Some(AstStmt::AlterTable(alter)) = result {
        match &alter.actions[0].kind {
            AstAlterTableActionKind::Unset { .. } => {
                // Success
            }
            _ => panic!("Expected Unset action"),
        }
    }
}

#[test]
fn test_alter_table_set_multiple_params() {
    let sql = "ALTER TABLE events SET DATA_RETENTION_TIME_IN_DAYS = 90, CHANGE_TRACKING = TRUE;";
    let result = parse_stmt_from_str(sql);
    assert!(
        result.is_some(),
        "Failed to parse SET with multiple parameters"
    );
}

// ============================================================================
// SWAP, SUSPEND, RESUME
// ============================================================================

#[test]
fn test_alter_table_swap_with() {
    let sql = "ALTER TABLE table1 SWAP WITH table2;";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Failed to parse SWAP WITH");

    if let Some(AstStmt::AlterTable(alter)) = result {
        match &alter.actions[0].kind {
            AstAlterTableActionKind::SwapWith {
                other_table_span, ..
            } => {
                assert!(other_table_span.start > 0);
            }
            _ => panic!("Expected SwapWith action"),
        }
    }
}

#[test]
fn test_alter_table_swap_with_qualified_name() {
    // The swap target may be a qualified name `db.schema.table`; the parser
    // must consume the whole dotted name, not just the first identifier
    // (which would leave `.schema.table` as an unparsed opaque fragment).
    let sql = "ALTER TABLE a.b.c SWAP WITH prod_db.staging.customers_new;";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Failed to parse SWAP WITH qualified name");

    if let Some(AstStmt::AlterTable(alter)) = result {
        match &alter.actions[0].kind {
            AstAlterTableActionKind::SwapWith {
                other_table_span, ..
            } => {
                let target = &sql[other_table_span.start as usize..other_table_span.end as usize];
                assert_eq!(
                    target, "prod_db.staging.customers_new",
                    "swap target span must cover the full qualified name"
                );
            }
            _ => panic!("Expected SwapWith action"),
        }
    } else {
        panic!("Expected AlterTable statement");
    }
}

#[test]
fn test_alter_table_suspend_recluster() {
    let sql = "ALTER TABLE events SUSPEND RECLUSTER;";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Failed to parse SUSPEND RECLUSTER");

    if let Some(AstStmt::AlterTable(alter)) = result {
        match &alter.actions[0].kind {
            AstAlterTableActionKind::SuspendRecluster { .. } => {
                // Success
            }
            _ => panic!("Expected SuspendRecluster action"),
        }
    }
}

#[test]
fn test_alter_table_resume_recluster() {
    let sql = "ALTER TABLE events RESUME RECLUSTER;";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Failed to parse RESUME RECLUSTER");

    if let Some(AstStmt::AlterTable(alter)) = result {
        match &alter.actions[0].kind {
            AstAlterTableActionKind::ResumeRecluster { .. } => {
                // Success
            }
            _ => panic!("Expected ResumeRecluster action"),
        }
    }
}

// ============================================================================
// IF EXISTS clause
// ============================================================================

#[test]
fn test_alter_table_if_exists() {
    let sql = "ALTER TABLE IF EXISTS users ADD COLUMN age INT;";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Failed to parse ALTER TABLE IF EXISTS");

    if let Some(AstStmt::AlterTable(alter)) = result {
        assert!(alter.if_exists_span.is_some(), "Should have IF EXISTS span");
    }
}

// ============================================================================
// Multiple actions
// ============================================================================

#[test]
fn test_alter_table_multiple_actions() {
    let sql = "ALTER TABLE users ADD COLUMN age INT, DROP COLUMN old_field;";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Failed to parse multiple actions");

    if let Some(AstStmt::AlterTable(alter)) = result {
        assert_eq!(alter.actions.len(), 2, "Should have 2 actions");
    }
}

#[test]
fn test_alter_table_three_actions() {
    let sql =
        "ALTER TABLE users ADD COLUMN age INT, RENAME COLUMN name TO full_name, DROP COLUMN temp;";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Failed to parse 3 actions");

    if let Some(AstStmt::AlterTable(alter)) = result {
        assert_eq!(alter.actions.len(), 3, "Should have 3 actions");
    }
}

// ============================================================================
// Qualified table names
// ============================================================================

#[test]
fn test_alter_table_qualified_name() {
    let sql = "ALTER TABLE db.schema.users ADD COLUMN age INT;";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Failed to parse qualified table name");
}

#[test]
fn test_alter_table_schema_qualified() {
    let sql = "ALTER TABLE schema.users ADD COLUMN age INT;";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Failed to parse schema-qualified name");
}

// ============================================================================
// Complex data types
// ============================================================================

#[test]
fn test_alter_table_add_column_complex_types() {
    let sql = "ALTER TABLE users ADD COLUMN data VARIANT, metadata OBJECT, tags ARRAY;";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Failed to parse semi-structured types");
}

#[test]
fn test_alter_table_add_column_number_precision() {
    let sql = "ALTER TABLE sales ADD COLUMN amount NUMBER(18,2);";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Failed to parse NUMBER with precision");
}

#[test]
fn test_alter_table_add_column_varchar_length() {
    let sql = "ALTER TABLE users ADD COLUMN name VARCHAR(255);";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Failed to parse VARCHAR with length");
}

// ============================================================================
// Complex DEFAULT expressions
// ============================================================================

#[test]
fn test_alter_table_add_column_default_function() {
    let sql = "ALTER TABLE events ADD COLUMN created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP();";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Failed to parse DEFAULT with function");

    if let Some(AstStmt::AlterTable(alter)) = result {
        match &alter.actions[0].kind {
            AstAlterTableActionKind::AddColumn { columns, .. } => {
                // Parsed expression is in span, not a separate field
                assert!(columns[0].full_span.end > 0);
            }
            _ => panic!("Expected AddColumn"),
        }
    }
}

#[test]
fn test_alter_table_add_column_default_expression() {
    let sql = "ALTER TABLE orders ADD COLUMN total DECIMAL(10,2) DEFAULT 0.00;";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Failed to parse DEFAULT with expression");
}

#[test]
fn test_alter_table_add_column_default_case() {
    let sql =
        "ALTER TABLE users ADD COLUMN status VARCHAR(20) DEFAULT CASE WHEN 1=1 THEN 'active' END;";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Failed to parse DEFAULT with CASE");

    if let Some(AstStmt::AlterTable(alter)) = result {
        match &alter.actions[0].kind {
            AstAlterTableActionKind::AddColumn { columns, .. } => {
                // CASE expression is parsed (within full_span)
                assert!(
                    columns[0].full_span.end > columns[0].type_span.unwrap().end,
                    "Should parse CASE expression"
                );
            }
            _ => panic!("Expected AddColumn"),
        }
    }
}

// ============================================================================
// Jinja integration
// ============================================================================

#[test]
fn test_alter_table_with_jinja_table_name() {
    let sql = "ALTER TABLE {{ table_name }} ADD COLUMN age INT;";
    let result = parse_stmt_from_str(sql);
    assert!(
        result.is_some(),
        "Failed to parse ALTER TABLE with Jinja in table name"
    );

    if let Some(AstStmt::AlterTable(alter)) = result {
        assert_eq!(alter.actions.len(), 1, "Should have 1 action");
    }
}

#[test]
fn test_alter_table_with_jinja_column_name() {
    let sql = "ALTER TABLE users ADD COLUMN {{ col_name }} INT;";
    let result = parse_stmt_from_str(sql);
    assert!(
        result.is_some(),
        "Failed to parse with Jinja in column name"
    );

    if let Some(AstStmt::AlterTable(alter)) = result {
        assert_eq!(alter.actions.len(), 1, "Should have 1 action");
    }
}

#[test]
fn test_alter_table_with_jinja_default() {
    let sql = "ALTER TABLE users ADD COLUMN status VARCHAR(50) DEFAULT {{ default_status }};";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Failed to parse with Jinja in DEFAULT");

    if let Some(AstStmt::AlterTable(alter)) = result {
        assert_eq!(alter.actions.len(), 1, "Should have 1 action");
    }
}

#[test]
fn test_alter_table_with_jinja_if_statement() {
    let sql = r#"ALTER TABLE users 
{% if add_age %}
ADD COLUMN age INT
{% endif %};"#;
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Failed to parse with Jinja IF statement");

    // Jinja conditionals may or may not produce actions depending on
    // rendering; parsing without error is what is checked.
}

// ============================================================================
// Governance actions
// ============================================================================

#[test]
fn test_alter_table_set_tag() {
    let sql = "ALTER TABLE users SET TAG cost_center = 'engineering';";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Failed to parse SET TAG");
}

#[test]
fn test_alter_table_add_search_optimization() {
    let sql = "ALTER TABLE events ADD SEARCH OPTIMIZATION;";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Failed to parse ADD SEARCH OPTIMIZATION");
}

#[test]
fn test_alter_table_comment() {
    let sql = "ALTER TABLE users SET COMMENT = 'User information table';";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Failed to parse SET COMMENT");
}

// ============================================================================
// Edge cases and error handling
// ============================================================================

#[test]
fn test_alter_table_empty_action_list() {
    let sql = "ALTER TABLE users;";
    let result = parse_stmt_from_str(sql);
    // Should parse but have empty action list
    assert!(result.is_some());
}

#[test]
fn test_alter_table_trailing_comma() {
    let sql = "ALTER TABLE users ADD COLUMN age INT,;";
    let result = parse_stmt_from_str(sql);
    // Should handle gracefully (semicolon left unconsumed is okay)
    assert!(result.is_some(), "Failed to parse with trailing comma");

    if let Some(AstStmt::AlterTable(alter)) = result {
        assert_eq!(alter.actions.len(), 1, "Should have 1 action");
        match &alter.actions[0].kind {
            AstAlterTableActionKind::AddColumn { columns, .. } => {
                assert_eq!(
                    columns.len(),
                    1,
                    "Should have 1 column despite trailing comma"
                );
            }
            _ => panic!("Expected AddColumn action"),
        }
    }
}

#[test]
fn test_alter_table_no_column_keyword() {
    // Some Snowflake ALTER TABLE variants allow omitting COLUMN
    let sql = "ALTER TABLE users ADD age INT;";
    let result = parse_stmt_from_str(sql);
    // Should still parse (handled as Unknown action)
    assert!(result.is_some());
}

// ============================================================================
// Roundtrip preservation
// ============================================================================

#[test]
fn test_alter_table_roundtrip_add_column() {
    let sql = "ALTER TABLE users ADD COLUMN age INT DEFAULT 0;";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Failed to parse ALTER TABLE with DEFAULT");

    // Verify we can format it back (basic smoke test)
    if let Some(AstStmt::AlterTable(alter)) = result {
        assert_eq!(alter.actions.len(), 1);
        match &alter.actions[0].kind {
            AstAlterTableActionKind::AddColumn { columns, .. } => {
                assert_eq!(columns.len(), 1);
            }
            _ => panic!("Expected AddColumn action"),
        }
    }
}

#[test]
fn test_alter_table_preserves_spans() {
    let sql = "ALTER TABLE db.schema.tbl ADD COLUMN x INT;";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Failed to parse ALTER TABLE");

    if let Some(AstStmt::AlterTable(alter)) = result {
        // Verify spans are contiguous
        assert!(alter.span.start < alter.span.end);
        assert!(alter.name.span.start >= alter.table_span.end);
        assert!(alter.actions_span.start >= alter.name.span.end);
    }
}

// ============================================================================
// Real-world patterns
// ============================================================================

#[test]
fn test_alter_table_realistic_migration() {
    let sql = r#"ALTER TABLE production.analytics.user_events 
    ADD COLUMN session_id VARCHAR(64),
    ADD COLUMN device_type VARCHAR(50) DEFAULT 'unknown',
    DROP COLUMN deprecated_field;"#;
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Failed to parse realistic migration");

    if let Some(AstStmt::AlterTable(alter)) = result {
        assert_eq!(alter.actions.len(), 3);
    }
}

#[test]
fn test_alter_table_performance_tuning() {
    let sql = "ALTER TABLE fact_sales CLUSTER BY (sale_date, region_id, product_id);";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Failed to parse performance tuning ALTER");

    if let Some(AstStmt::AlterTable(alter)) = result {
        match &alter.actions[0].kind {
            AstAlterTableActionKind::ClusterBy { exprs, .. } => {
                assert_eq!(exprs.as_ref().unwrap().len(), 3);
            }
            _ => panic!("Expected ClusterBy"),
        }
    }
}

#[test]
fn test_alter_table_data_retention() {
    let sql = "ALTER TABLE sensitive_data SET DATA_RETENTION_TIME_IN_DAYS = 7;";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Failed to parse data retention setting");
}

// ============================================================================
// Row Access Policy Tests (Governance Features)
// ============================================================================

#[test]
fn test_alter_table_add_row_access_policy() {
    let sql = "ALTER TABLE sensitive_data ADD ROW ACCESS POLICY rls_policy ON (user_id);";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Failed to parse ADD ROW ACCESS POLICY");

    if let Some(AstStmt::AlterTable(alter)) = result {
        assert_eq!(alter.actions.len(), 1);
        match &alter.actions[0].kind {
            AstAlterTableActionKind::AddRowAccessPolicy(action) => {
                assert!(action.add_span.is_some());
                assert!(action.row_span.is_some());
                assert!(action.access_span.is_some());
                assert!(action.policy_span.is_some());
                assert_eq!(action.columns.len(), 1, "Should have 1 column");
            }
            _ => panic!(
                "Expected AddRowAccessPolicy action, got {:?}",
                alter.actions[0].kind
            ),
        }
    }
}

#[test]
fn test_alter_table_add_row_access_policy_multiple_columns() {
    let sql =
        "ALTER TABLE orders ADD ROW ACCESS POLICY order_policy ON (customer_id, region, status);";
    let result = parse_stmt_from_str(sql);
    assert!(
        result.is_some(),
        "Failed to parse ADD ROW ACCESS POLICY with multiple columns"
    );

    if let Some(AstStmt::AlterTable(alter)) = result {
        match &alter.actions[0].kind {
            AstAlterTableActionKind::AddRowAccessPolicy(action) => {
                assert_eq!(action.columns.len(), 3, "Should have 3 columns");
            }
            _ => panic!("Expected AddRowAccessPolicy action"),
        }
    }
}

#[test]
fn test_alter_table_drop_row_access_policy() {
    let sql = "ALTER TABLE sensitive_data DROP ROW ACCESS POLICY rls_policy;";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Failed to parse DROP ROW ACCESS POLICY");

    if let Some(AstStmt::AlterTable(alter)) = result {
        assert_eq!(alter.actions.len(), 1);
        match &alter.actions[0].kind {
            AstAlterTableActionKind::DropRowAccessPolicy {
                drop_span,
                row_span,
                access_span,
                policy_span,
                policy_name_span,
                if_exists_span,
            } => {
                assert!(drop_span.is_some());
                assert!(row_span.is_some());
                assert!(access_span.is_some());
                assert!(policy_span.is_some());
                assert!(
                    policy_name_span.start < policy_name_span.end,
                    "Should have policy name span"
                );
                assert!(if_exists_span.is_none(), "Should not have IF EXISTS");
            }
            _ => panic!(
                "Expected DropRowAccessPolicy action, got {:?}",
                alter.actions[0].kind
            ),
        }
    }
}

#[test]
fn test_alter_table_drop_row_access_policy_if_exists() {
    let sql = "ALTER TABLE users DROP ROW ACCESS POLICY IF EXISTS old_policy;";
    let result = parse_stmt_from_str(sql);
    assert!(
        result.is_some(),
        "Failed to parse DROP ROW ACCESS POLICY with IF EXISTS"
    );

    if let Some(AstStmt::AlterTable(alter)) = result {
        match &alter.actions[0].kind {
            AstAlterTableActionKind::DropRowAccessPolicy { if_exists_span, .. } => {
                assert!(if_exists_span.is_some(), "Should have IF EXISTS");
            }
            _ => panic!("Expected DropRowAccessPolicy action"),
        }
    }
}

#[test]
fn test_alter_table_drop_all_row_access_policies() {
    let sql = "ALTER TABLE secure_table DROP ALL ROW ACCESS POLICIES;";
    let result = parse_stmt_from_str(sql);
    assert!(
        result.is_some(),
        "Failed to parse DROP ALL ROW ACCESS POLICIES"
    );

    if let Some(AstStmt::AlterTable(alter)) = result {
        assert_eq!(alter.actions.len(), 1);
        match &alter.actions[0].kind {
            AstAlterTableActionKind::DropAllRowAccessPolicies {
                drop_span,
                all_span,
                row_span,
                access_span,
                policies_span,
            } => {
                assert!(drop_span.is_some());
                assert!(all_span.is_some());
                assert!(row_span.is_some());
                assert!(access_span.is_some());
                assert!(policies_span.is_some());
            }
            _ => panic!(
                "Expected DropAllRowAccessPolicies action, got {:?}",
                alter.actions[0].kind
            ),
        }
    }
}

#[test]
fn test_alter_table_multiple_row_access_policy_actions() {
    let sql = "ALTER TABLE users ADD ROW ACCESS POLICY new_policy ON (user_id), DROP ROW ACCESS POLICY old_policy;";
    let result = parse_stmt_from_str(sql);
    assert!(
        result.is_some(),
        "Failed to parse multiple row access policy actions"
    );

    if let Some(AstStmt::AlterTable(alter)) = result {
        assert_eq!(alter.actions.len(), 2, "Should have 2 actions");

        match &alter.actions[0].kind {
            AstAlterTableActionKind::AddRowAccessPolicy(_) => {}
            _ => panic!("First action should be AddRowAccessPolicy"),
        }

        match &alter.actions[1].kind {
            AstAlterTableActionKind::DropRowAccessPolicy { .. } => {}
            _ => panic!("Second action should be DropRowAccessPolicy"),
        }
    }
}

#[test]
fn test_alter_table_row_access_policy_with_other_actions() {
    let sql = "ALTER TABLE users ADD COLUMN age INT, ADD ROW ACCESS POLICY user_policy ON (user_id), DROP COLUMN temp_col;";
    let result = parse_stmt_from_str(sql);
    assert!(
        result.is_some(),
        "Failed to parse mixed actions including row access policy"
    );

    if let Some(AstStmt::AlterTable(alter)) = result {
        assert_eq!(alter.actions.len(), 3, "Should have 3 actions");

        match &alter.actions[0].kind {
            AstAlterTableActionKind::AddColumn { .. } => {}
            _ => panic!("First action should be AddColumn"),
        }

        match &alter.actions[1].kind {
            AstAlterTableActionKind::AddRowAccessPolicy(_) => {}
            _ => panic!("Second action should be AddRowAccessPolicy"),
        }

        match &alter.actions[2].kind {
            AstAlterTableActionKind::DropColumn { .. } => {}
            _ => panic!("Third action should be DropColumn"),
        }
    }
}

// ============================================================================
// Column Masking Policy Tests (Governance Features - Priority 2)
// ============================================================================

#[test]
fn test_alter_table_set_column_masking_policy() {
    let sql = "ALTER TABLE sensitive_data ALTER COLUMN ssn SET MASKING POLICY ssn_mask;";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Failed to parse SET MASKING POLICY");

    if let Some(AstStmt::AlterTable(alter)) = result {
        assert_eq!(alter.actions.len(), 1);
        match &alter.actions[0].kind {
            AstAlterTableActionKind::SetColumnMaskingPolicy(action) => {
                assert!(action.alter_span.is_some());
                assert!(action.column_span.is_some());
                assert!(action.set_span.is_some());
                assert!(action.masking_span.is_some());
                assert!(action.policy_span.is_some());
                assert!(action.using_span.is_none(), "Should not have USING");
                assert!(action.force_span.is_none(), "Should not have FORCE");
            }
            _ => panic!(
                "Expected SetColumnMaskingPolicy action, got {:?}",
                alter.actions[0].kind
            ),
        }
    }
}

#[test]
fn test_alter_table_set_column_masking_policy_with_using() {
    let sql = "ALTER TABLE customers ALTER COLUMN email SET MASKING POLICY email_mask USING (email, customer_type);";
    let result = parse_stmt_from_str(sql);
    assert!(
        result.is_some(),
        "Failed to parse SET MASKING POLICY with USING"
    );

    if let Some(AstStmt::AlterTable(alter)) = result {
        match &alter.actions[0].kind {
            AstAlterTableActionKind::SetColumnMaskingPolicy(action) => {
                assert!(action.using_span.is_some(), "Should have USING");
            }
            _ => panic!("Expected SetColumnMaskingPolicy action"),
        }
    }
}

#[test]
fn test_alter_table_set_column_masking_policy_with_force() {
    let sql = "ALTER TABLE employees ALTER COLUMN salary SET MASKING POLICY salary_mask FORCE;";
    let result = parse_stmt_from_str(sql);
    assert!(
        result.is_some(),
        "Failed to parse SET MASKING POLICY with FORCE"
    );

    if let Some(AstStmt::AlterTable(alter)) = result {
        match &alter.actions[0].kind {
            AstAlterTableActionKind::SetColumnMaskingPolicy(action) => {
                assert!(action.force_span.is_some(), "Should have FORCE");
            }
            _ => panic!("Expected SetColumnMaskingPolicy action"),
        }
    }
}

#[test]
fn test_alter_table_set_column_masking_policy_full() {
    let sql =
        "ALTER TABLE hr_data ALTER COLUMN ssn SET MASKING POLICY pii_mask USING (ssn, role) FORCE;";
    let result = parse_stmt_from_str(sql);
    assert!(
        result.is_some(),
        "Failed to parse SET MASKING POLICY with USING and FORCE"
    );

    if let Some(AstStmt::AlterTable(alter)) = result {
        match &alter.actions[0].kind {
            AstAlterTableActionKind::SetColumnMaskingPolicy(action) => {
                assert!(action.using_span.is_some(), "Should have USING");
                assert!(action.force_span.is_some(), "Should have FORCE");
            }
            _ => panic!("Expected SetColumnMaskingPolicy action"),
        }
    }
}

#[test]
fn test_alter_table_unset_column_masking_policy() {
    let sql = "ALTER TABLE sensitive_data ALTER COLUMN ssn UNSET MASKING POLICY;";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Failed to parse UNSET MASKING POLICY");

    if let Some(AstStmt::AlterTable(alter)) = result {
        assert_eq!(alter.actions.len(), 1);
        match &alter.actions[0].kind {
            AstAlterTableActionKind::UnsetColumnMaskingPolicy {
                alter_span,
                column_span,
                column_name_span,
                unset_span,
                masking_span,
                policy_span,
            } => {
                assert!(alter_span.is_some());
                assert!(column_span.is_some());
                assert!(
                    column_name_span.start < column_name_span.end,
                    "Should have column name span"
                );
                assert!(unset_span.is_some());
                assert!(masking_span.is_some());
                assert!(policy_span.is_some());
            }
            _ => panic!(
                "Expected UnsetColumnMaskingPolicy action, got {:?}",
                alter.actions[0].kind
            ),
        }
    }
}

// ============================================================================
// Column Projection Policy Tests (Governance Features - Priority 2)
// ============================================================================

#[test]
fn test_alter_table_set_column_projection_policy() {
    let sql = "ALTER TABLE analytics_data ALTER COLUMN user_data SET PROJECTION POLICY projection_policy;";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Failed to parse SET PROJECTION POLICY");

    if let Some(AstStmt::AlterTable(alter)) = result {
        assert_eq!(alter.actions.len(), 1);
        match &alter.actions[0].kind {
            AstAlterTableActionKind::SetColumnProjectionPolicy(action) => {
                assert!(action.alter_span.is_some());
                assert!(action.column_span.is_some());
                assert!(action.set_span.is_some());
                assert!(action.projection_span.is_some());
                assert!(action.policy_span.is_some());
                assert!(action.force_span.is_none(), "Should not have FORCE");
            }
            _ => panic!(
                "Expected SetColumnProjectionPolicy action, got {:?}",
                alter.actions[0].kind
            ),
        }
    }
}

#[test]
fn test_alter_table_set_column_projection_policy_with_force() {
    let sql =
        "ALTER TABLE reports ALTER COLUMN metrics SET PROJECTION POLICY metric_projection FORCE;";
    let result = parse_stmt_from_str(sql);
    assert!(
        result.is_some(),
        "Failed to parse SET PROJECTION POLICY with FORCE"
    );

    if let Some(AstStmt::AlterTable(alter)) = result {
        match &alter.actions[0].kind {
            AstAlterTableActionKind::SetColumnProjectionPolicy(action) => {
                assert!(action.force_span.is_some(), "Should have FORCE");
            }
            _ => panic!("Expected SetColumnProjectionPolicy action"),
        }
    }
}

#[test]
fn test_alter_table_unset_column_projection_policy() {
    let sql = "ALTER TABLE analytics_data ALTER COLUMN user_data UNSET PROJECTION POLICY;";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Failed to parse UNSET PROJECTION POLICY");

    if let Some(AstStmt::AlterTable(alter)) = result {
        assert_eq!(alter.actions.len(), 1);
        match &alter.actions[0].kind {
            AstAlterTableActionKind::UnsetColumnProjectionPolicy {
                alter_span,
                column_span,
                column_name_span,
                unset_span,
                projection_span,
                policy_span,
            } => {
                assert!(alter_span.is_some());
                assert!(column_span.is_some());
                assert!(
                    column_name_span.start < column_name_span.end,
                    "Should have column name span"
                );
                assert!(unset_span.is_some());
                assert!(projection_span.is_some());
                assert!(policy_span.is_some());
            }
            _ => panic!(
                "Expected UnsetColumnProjectionPolicy action, got {:?}",
                alter.actions[0].kind
            ),
        }
    }
}

#[test]
fn test_alter_table_mixed_column_policies() {
    let sql = "ALTER TABLE secure_table ALTER COLUMN ssn SET MASKING POLICY ssn_mask, ALTER COLUMN email SET PROJECTION POLICY email_proj;";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Failed to parse mixed column policies");

    if let Some(AstStmt::AlterTable(alter)) = result {
        assert_eq!(alter.actions.len(), 2, "Should have 2 actions");

        match &alter.actions[0].kind {
            AstAlterTableActionKind::SetColumnMaskingPolicy(_) => {}
            _ => panic!("First action should be SetColumnMaskingPolicy"),
        }

        match &alter.actions[1].kind {
            AstAlterTableActionKind::SetColumnProjectionPolicy(_) => {}
            _ => panic!("Second action should be SetColumnProjectionPolicy"),
        }
    }
}

#[test]
fn test_alter_table_column_policies_with_ddl() {
    let sql = "ALTER TABLE users ADD COLUMN temp INT, ALTER COLUMN ssn SET MASKING POLICY ssn_mask, DROP COLUMN old_col;";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Failed to parse column policies with DDL");

    if let Some(AstStmt::AlterTable(alter)) = result {
        assert_eq!(alter.actions.len(), 3, "Should have 3 actions");

        match &alter.actions[0].kind {
            AstAlterTableActionKind::AddColumn { .. } => {}
            _ => panic!("First action should be AddColumn"),
        }

        match &alter.actions[1].kind {
            AstAlterTableActionKind::SetColumnMaskingPolicy(_) => {}
            _ => panic!("Second action should be SetColumnMaskingPolicy"),
        }

        match &alter.actions[2].kind {
            AstAlterTableActionKind::DropColumn { .. } => {}
            _ => panic!("Third action should be DropColumn"),
        }
    }
}
// ============================================================================
// Table-Level Policy Tests (Priority 3)
// ============================================================================

#[test]
fn test_alter_table_set_aggregation_policy() {
    let sql = "ALTER TABLE financial_data SET AGGREGATION POLICY agg_policy;";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Failed to parse SET AGGREGATION POLICY");

    if let Some(AstStmt::AlterTable(alter)) = result {
        assert_eq!(alter.actions.len(), 1);
        match &alter.actions[0].kind {
            AstAlterTableActionKind::SetAggregationPolicy {
                set_span,
                aggregation_span,
                policy_span,
                policy_name_span,
                entity_key_span,
                entity_key_columns,
                force_span,
            } => {
                assert!(set_span.is_some());
                assert!(aggregation_span.is_some());
                assert!(policy_span.is_some());
                assert!(policy_name_span.start > 0);
                assert!(entity_key_span.is_none(), "Should not have ENTITY KEY");
                assert_eq!(
                    entity_key_columns.len(),
                    0,
                    "Should have no entity key columns"
                );
                assert!(force_span.is_none(), "Should not have FORCE");
            }
            _ => panic!(
                "Expected SetAggregationPolicy action, got {:?}",
                alter.actions[0].kind
            ),
        }
    }
}

#[test]
fn test_alter_table_set_aggregation_policy_with_entity_key() {
    let sql =
        "ALTER TABLE sales SET AGGREGATION POLICY sales_agg ENTITY KEY (customer_id, region);";
    let result = parse_stmt_from_str(sql);
    assert!(
        result.is_some(),
        "Failed to parse SET AGGREGATION POLICY with ENTITY KEY"
    );

    if let Some(AstStmt::AlterTable(alter)) = result {
        match &alter.actions[0].kind {
            AstAlterTableActionKind::SetAggregationPolicy {
                entity_key_span,
                entity_key_columns,
                ..
            } => {
                assert!(entity_key_span.is_some(), "Should have ENTITY KEY span");
                assert_eq!(
                    entity_key_columns.len(),
                    2,
                    "Should have 2 entity key columns"
                );
            }
            _ => panic!("Expected SetAggregationPolicy action"),
        }
    }
}

#[test]
fn test_alter_table_set_aggregation_policy_with_force() {
    let sql = "ALTER TABLE analytics SET AGGREGATION POLICY agg_policy2 FORCE;";
    let result = parse_stmt_from_str(sql);
    assert!(
        result.is_some(),
        "Failed to parse SET AGGREGATION POLICY with FORCE"
    );

    if let Some(AstStmt::AlterTable(alter)) = result {
        match &alter.actions[0].kind {
            AstAlterTableActionKind::SetAggregationPolicy { force_span, .. } => {
                assert!(force_span.is_some(), "Should have FORCE keyword");
            }
            _ => panic!("Expected SetAggregationPolicy action"),
        }
    }
}

#[test]
fn test_alter_table_set_aggregation_policy_full() {
    let sql = "ALTER TABLE metrics SET AGGREGATION POLICY full_agg ENTITY KEY (user_id, session_id, timestamp) FORCE;";
    let result = parse_stmt_from_str(sql);
    assert!(
        result.is_some(),
        "Failed to parse SET AGGREGATION POLICY with all options"
    );

    if let Some(AstStmt::AlterTable(alter)) = result {
        match &alter.actions[0].kind {
            AstAlterTableActionKind::SetAggregationPolicy {
                entity_key_span,
                entity_key_columns,
                force_span,
                ..
            } => {
                assert!(entity_key_span.is_some(), "Should have ENTITY KEY");
                assert_eq!(
                    entity_key_columns.len(),
                    3,
                    "Should have 3 entity key columns"
                );
                assert!(force_span.is_some(), "Should have FORCE");
            }
            _ => panic!("Expected SetAggregationPolicy action"),
        }
    }
}

#[test]
fn test_alter_table_unset_aggregation_policy() {
    let sql = "ALTER TABLE financial_data UNSET AGGREGATION POLICY;";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Failed to parse UNSET AGGREGATION POLICY");

    if let Some(AstStmt::AlterTable(alter)) = result {
        assert_eq!(alter.actions.len(), 1);
        match &alter.actions[0].kind {
            AstAlterTableActionKind::UnsetAggregationPolicy {
                unset_span,
                aggregation_span,
                policy_span,
            } => {
                assert!(unset_span.is_some());
                assert!(aggregation_span.is_some());
                assert!(policy_span.is_some());
            }
            _ => panic!(
                "Expected UnsetAggregationPolicy action, got {:?}",
                alter.actions[0].kind
            ),
        }
    }
}

#[test]
fn test_alter_table_set_join_policy() {
    let sql = "ALTER TABLE confidential_data SET JOIN POLICY join_policy_name;";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Failed to parse SET JOIN POLICY");

    if let Some(AstStmt::AlterTable(alter)) = result {
        assert_eq!(alter.actions.len(), 1);
        match &alter.actions[0].kind {
            AstAlterTableActionKind::SetJoinPolicy {
                set_span,
                join_span,
                policy_span,
                policy_name_span,
                force_span,
            } => {
                assert!(set_span.is_some());
                assert!(join_span.is_some());
                assert!(policy_span.is_some());
                assert!(policy_name_span.start > 0);
                assert!(force_span.is_none(), "Should not have FORCE");
            }
            _ => panic!(
                "Expected SetJoinPolicy action, got {:?}",
                alter.actions[0].kind
            ),
        }
    }
}

#[test]
fn test_alter_table_set_join_policy_with_force() {
    let sql = "ALTER TABLE secure_table SET JOIN POLICY restrictive_join FORCE;";
    let result = parse_stmt_from_str(sql);
    assert!(
        result.is_some(),
        "Failed to parse SET JOIN POLICY with FORCE"
    );

    if let Some(AstStmt::AlterTable(alter)) = result {
        match &alter.actions[0].kind {
            AstAlterTableActionKind::SetJoinPolicy { force_span, .. } => {
                assert!(force_span.is_some(), "Should have FORCE keyword");
            }
            _ => panic!("Expected SetJoinPolicy action"),
        }
    }
}

#[test]
fn test_alter_table_unset_join_policy() {
    let sql = "ALTER TABLE confidential_data UNSET JOIN POLICY;";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Failed to parse UNSET JOIN POLICY");

    if let Some(AstStmt::AlterTable(alter)) = result {
        assert_eq!(alter.actions.len(), 1);
        match &alter.actions[0].kind {
            AstAlterTableActionKind::UnsetJoinPolicy {
                unset_span,
                join_span,
                policy_span,
            } => {
                assert!(unset_span.is_some());
                assert!(join_span.is_some());
                assert!(policy_span.is_some());
            }
            _ => panic!(
                "Expected UnsetJoinPolicy action, got {:?}",
                alter.actions[0].kind
            ),
        }
    }
}

#[test]
fn test_alter_table_mixed_table_policies() {
    let sql = "ALTER TABLE data_warehouse SET AGGREGATION POLICY agg1 ENTITY KEY (user_id), SET JOIN POLICY join1;";
    let result = parse_stmt_from_str(sql);
    assert!(
        result.is_some(),
        "Failed to parse mixed table-level policies"
    );

    if let Some(AstStmt::AlterTable(alter)) = result {
        assert_eq!(alter.actions.len(), 2, "Should have 2 actions");

        match &alter.actions[0].kind {
            AstAlterTableActionKind::SetAggregationPolicy {
                entity_key_columns, ..
            } => {
                assert_eq!(
                    entity_key_columns.len(),
                    1,
                    "Should have 1 entity key column"
                );
            }
            _ => panic!("First action should be SetAggregationPolicy"),
        }

        match &alter.actions[1].kind {
            AstAlterTableActionKind::SetJoinPolicy { .. } => {}
            _ => panic!("Second action should be SetJoinPolicy"),
        }
    }
}

// ============================================================================
// ROW LEVEL SECURITY toggle (PG)
// ============================================================================

fn rls_mode(sql: &str) -> lexega_core::ast::AstRowLevelSecurityMode {
    match parse_stmt_from_str(sql) {
        Some(AstStmt::AlterTable(alter)) => {
            assert_eq!(
                alter.actions.len(),
                1,
                "expected exactly one action for {sql:?}"
            );
            match &alter.actions[0].kind {
                AstAlterTableActionKind::RowLevelSecurity { mode, .. } => *mode,
                other => panic!("expected RowLevelSecurity for {sql:?}, got {other:?}"),
            }
        }
        other => panic!("expected AlterTable for {sql:?}, got {other:?}"),
    }
}

#[test]
fn test_alter_table_row_level_security_modes() {
    use lexega_core::ast::AstRowLevelSecurityMode as M;
    assert_eq!(
        rls_mode("ALTER TABLE t ENABLE ROW LEVEL SECURITY;"),
        M::Enable
    );
    assert_eq!(
        rls_mode("ALTER TABLE t DISABLE ROW LEVEL SECURITY;"),
        M::Disable
    );
    assert_eq!(
        rls_mode("ALTER TABLE t FORCE ROW LEVEL SECURITY;"),
        M::Force
    );
    assert_eq!(
        rls_mode("ALTER TABLE t NO FORCE ROW LEVEL SECURITY;"),
        M::NoForce
    );
}

#[test]
fn test_alter_table_rls_schema_qualified_name() {
    // Regression: parse_table_name must stop at the mode keyword and not
    // swallow ROW LEVEL SECURITY into the table name.
    use lexega_core::ast::AstRowLevelSecurityMode as M;
    assert_eq!(
        rls_mode("ALTER TABLE myschema.t DISABLE ROW LEVEL SECURITY;"),
        M::Disable
    );
}

/// The text `span` covers in `sql`.
fn spanned(sql: &str, span: lexega_core::lexer::Span) -> &str {
    &sql[span.start as usize..span.end as usize]
}

/// Format `sql` under `dialect` and check no token is lost.
fn formats_safely(sql: &str, dialect: lexega_core::dialect::DialectRef) {
    let config = lexega_core::FormatterConfig {
        dialect,
        ..Default::default()
    };
    let out = lexega_core::format_sql_with_config(sql, &config).expect("should format");
    lexega_core::verify_formatting_safe_with_dialect(sql, &out, config.dialect.as_ref())
        .expect("should preserve tokens");
}

#[test]
fn a_rename_of_a_column_without_the_column_keyword_is_a_column_rename() {
    let sql = "ALTER TABLE users RENAME email TO \"Mail\";";
    let Some(AstStmt::AlterTable(alter)) = parse_stmt_from_str(sql) else {
        panic!("ALTER TABLE expected: {sql}");
    };
    let AstAlterTableActionKind::RenameColumn {
        column_span,
        old_name_span,
        new_name_span,
        ..
    } = &alter.actions[0].kind
    else {
        panic!("RENAME COLUMN expected: {:?}", alter.actions[0].kind);
    };
    assert!(column_span.is_none());
    assert_eq!(spanned(sql, *old_name_span), "email");
    assert_eq!(spanned(sql, *new_name_span), "\"Mail\"");
    formats_safely(sql, lexega_core::dialect::postgres());
    // An index, a key or a constraint renamed, and the table renamed, are not.
    for sql in [
        "ALTER TABLE users RENAME INDEX a TO b;",
        "ALTER TABLE users RENAME CONSTRAINT a TO b;",
        "ALTER TABLE users RENAME TO people;",
    ] {
        let Some(AstStmt::AlterTable(alter)) = parse_stmt_from_str(sql) else {
            panic!("ALTER TABLE expected: {sql}");
        };
        assert!(
            !matches!(
                alter.actions[0].kind,
                AstAlterTableActionKind::RenameColumn { .. }
            ),
            "{sql}: {:?}",
            alter.actions[0].kind
        );
    }
}

#[test]
fn a_change_of_a_column_reads_both_names_and_keeps_the_definition() {
    let cases = [
        (
            "ALTER TABLE users CHANGE COLUMN a b BIGINT;",
            true,
            "a",
            "b",
            "BIGINT",
        ),
        (
            "ALTER TABLE users CHANGE email mail VARCHAR(100) NOT NULL AFTER id, ADD COLUMN c INT;",
            false,
            "email",
            "mail",
            "VARCHAR(100) NOT NULL AFTER id",
        ),
    ];
    for (sql, column, old, new, definition) in cases {
        let Some(AstStmt::AlterTable(alter)) = parse_stmt_from_str(sql) else {
            panic!("ALTER TABLE expected: {sql}");
        };
        let AstAlterTableActionKind::ChangeColumn {
            column_span,
            old_name_span,
            new_name_span,
            definition_span,
            ..
        } = &alter.actions[0].kind
        else {
            panic!("CHANGE expected: {sql}: {:?}", alter.actions[0].kind);
        };
        assert_eq!(column_span.is_some(), column, "{sql}");
        assert_eq!(spanned(sql, *old_name_span), old, "{sql}");
        assert_eq!(spanned(sql, *new_name_span), new, "{sql}");
        assert_eq!(spanned(sql, *definition_span), definition, "{sql}");
        formats_safely(sql, lexega_core::dialect::mysql());
        formats_safely(sql, lexega_core::dialect::databricks());
    }
}

/// The first statement of `sql`, parsed under `dialect`.
fn first_statement(sql: &str, dialect: &lexega_core::dialect::DialectRef) -> Option<AstStmt> {
    lexega_core::parse_sql_with_dialect(sql, dialect.as_ref())
        .ok()?
        .stmts
        .into_iter()
        .next()
}

#[test]
fn an_action_kept_as_written_is_named_by_its_leading_words() {
    use lexega_core::ast::AstNamedTableAction as N;
    use lexega_core::dialect::{databricks, mssql, mysql, postgres, redshift, snowflake};
    let cases = [
        (
            "DROP CONSTRAINT IF EXISTS c1",
            N::DropConstraint,
            postgres(),
        ),
        ("DROP CONSTRAINT c1 CASCADE", N::DropConstraint, postgres()),
        ("DROP INDEX i1", N::DropIndex, mysql()),
        ("DROP FOREIGN KEY fk1", N::DropForeignKey, mysql()),
        ("DROP CHECK c1", N::DropCheck, mysql()),
        ("ADD INDEX i1 (email)", N::AddIndex, mysql()),
        ("ADD DEFAULT 0 FOR id", N::AddDefault, mssql()),
        (
            "WITH CHECK CHECK CONSTRAINT ALL",
            N::CheckConstraint,
            mssql(),
        ),
        ("NOCHECK CONSTRAINT fk1", N::NocheckConstraint, mssql()),
        ("REBUILD", N::Rebuild, mssql()),
        ("RENAME INDEX i1 TO i2", N::RenameIndex, mysql()),
        (
            "RENAME CONSTRAINT c1 TO c2",
            N::RenameConstraint,
            postgres(),
        ),
        ("ALTER INDEX i1 INVISIBLE", N::AlterIndex, mysql()),
        (
            "ALTER CONSTRAINT c1 DEFERRABLE",
            N::AlterConstraint,
            postgres(),
        ),
        ("VALIDATE CONSTRAINT c1", N::ValidateConstraint, postgres()),
        ("ENGINE = InnoDB", N::TableOption, mysql()),
        ("CONVERT TO CHARACTER SET utf8mb4", N::TableOption, mysql()),
        ("COMMENT = 'x'", N::TableOption, mysql()),
        ("INHERIT parent", N::Inherit, postgres()),
        ("NO INHERIT public.parent", N::NoInherit, postgres()),
        ("REPLICA IDENTITY FULL", N::ReplicaIdentity, postgres()),
        ("FORCE", N::TableOption, mysql()),
        ("ORDER BY id", N::TableOption, mysql()),
        ("TRUNCATE PARTITION p0", N::PartitionMaintenance, mysql()),
        ("ALTER DISTKEY id", N::Distribution, redshift()),
        ("ALTER SORTKEY (id)", N::Distribution, redshift()),
        ("ENABLE RULE r1", N::RuleState, postgres()),
        ("RECOVER PARTITIONS", N::PartitionMaintenance, databricks()),
        (
            "ADD SEARCH OPTIMIZATION",
            N::SearchOptimization,
            snowflake(),
        ),
        (
            "ADD SEARCH OPTIMIZATION ON EQUALITY(email)",
            N::SearchOptimization,
            snowflake(),
        ),
        (
            "DROP SEARCH OPTIMIZATION",
            N::SearchOptimization,
            snowflake(),
        ),
        ("DROP UNIQUE (email)", N::DropUnique, snowflake()),
        ("RESET (fillfactor)", N::ResetOptions, postgres()),
        ("ROW LEVEL SECURITY ON", N::RowLevelSecurity, redshift()),
        (
            "ROW LEVEL SECURITY OFF FOR DATASHARES",
            N::RowLevelSecurity,
            redshift(),
        ),
        ("ENABLE KEYS", N::KeysState, mysql()),
        ("DISABLE KEYS", N::KeysState, mysql()),
        ("DROP FEATURE deletionVectors", N::DropFeature, databricks()),
        (
            "ENABLE PREDICTIVE OPTIMIZATION",
            N::PredictiveOptimization,
            databricks(),
        ),
        (
            "INHERIT PREDICTIVE OPTIMIZATION",
            N::PredictiveOptimization,
            databricks(),
        ),
        (
            "PREDICTIVE OPTIMIZATION ENABLE",
            N::PredictiveOptimization,
            databricks(),
        ),
    ];
    for (action, named, dialect) in cases {
        let sql = format!("ALTER TABLE users {action};");
        let Some(AstStmt::AlterTable(alter)) = first_statement(&sql, &dialect) else {
            panic!("ALTER TABLE expected: {sql}");
        };
        let AstAlterTableActionKind::NamedAction { kind, span, .. } = &alter.actions[0].kind else {
            panic!(
                "a named action expected: {sql}: {:?}",
                alter.actions[0].kind
            );
        };
        assert_eq!(*kind, named, "{sql}");
        assert_eq!(spanned(&sql, *span), action, "{sql}");
        formats_safely(&sql, dialect);
    }
    // A key added without `CONSTRAINT` is read as the constraint it is.
    for (sql, dialect, unique, name, column) in [
        (
            "ALTER TABLE users ADD PRIMARY KEY (id);",
            mysql(),
            false,
            None,
            "id",
        ),
        (
            "ALTER TABLE users ADD UNIQUE (email);",
            mysql(),
            true,
            None,
            "email",
        ),
        (
            "ALTER TABLE users ADD UNIQUE KEY uq_email (email);",
            mysql(),
            true,
            Some("uq_email"),
            "email",
        ),
        (
            "ALTER TABLE dbo.users ADD UNIQUE NONCLUSTERED (email);",
            mssql(),
            true,
            None,
            "email",
        ),
    ] {
        let Some(AstStmt::AlterTable(alter)) = first_statement(sql, &dialect) else {
            panic!("ALTER TABLE expected: {sql}");
        };
        let AstAlterTableActionKind::AddConstraint {
            details: Some(details),
            ..
        } = &alter.actions[0].kind
        else {
            panic!("a constraint expected: {sql}: {:?}", alter.actions[0].kind);
        };
        let columns = match &details.kind {
            lexega_core::ast::AstConstraintKind::Unique { columns } => {
                assert!(unique, "{sql}");
                columns
            }
            lexega_core::ast::AstConstraintKind::PrimaryKey { columns } => {
                assert!(!unique, "{sql}");
                columns
            }
            lexega_core::ast::AstConstraintKind::ForeignKey { .. } => panic!("{sql}"),
        };
        assert_eq!(details.name.map(|span| spanned(sql, span)), name, "{sql}");
        assert_eq!(columns.len(), 1, "{sql}");
        assert_eq!(spanned(sql, columns[0]), column, "{sql}");
        formats_safely(sql, dialect);
    }
    // `[NO] INHERIT` names its parent table.
    for (sql, parent) in [
        ("ALTER TABLE c INHERIT p;", "p"),
        ("ALTER TABLE c NO INHERIT app.p;", "app.p"),
    ] {
        let Some(AstStmt::AlterTable(alter)) = first_statement(sql, &postgres()) else {
            panic!("ALTER TABLE expected: {sql}");
        };
        let AstAlterTableActionKind::NamedAction {
            name_span: Some(name),
            ..
        } = &alter.actions[0].kind
        else {
            panic!("a parent expected: {sql}: {:?}", alter.actions[0].kind);
        };
        assert_eq!(spanned(sql, *name), parent, "{sql}");
    }
    // `{ENABLE | DISABLE} TRIGGER` on a table is a statement of its own.
    for sql in [
        "ALTER TABLE users ENABLE TRIGGER ALL;",
        "ALTER TABLE users DISABLE TRIGGER t1;",
    ] {
        assert!(
            matches!(
                first_statement(sql, &mssql()),
                Some(AstStmt::PgAlterTableTriggerState(_))
            ),
            "{sql}"
        );
    }
    // A column, `COLUMN` left out, is an altered column.
    for (sql, column) in [
        ("ALTER TABLE users ALTER email TYPE TEXT;", "email"),
        ("ALTER TABLE users MODIFY email TEXT NOT NULL;", "email"),
    ] {
        let Some(AstStmt::AlterTable(alter)) = parse_stmt_from_str(sql) else {
            panic!("ALTER TABLE expected: {sql}");
        };
        let AstAlterTableActionKind::AlterColumn {
            column_span,
            column_name_span,
            ..
        } = &alter.actions[0].kind
        else {
            panic!("ALTER COLUMN expected: {sql}: {:?}", alter.actions[0].kind);
        };
        assert!(column_span.is_none(), "{sql}");
        assert_eq!(spanned(sql, *column_name_span), column, "{sql}");
        formats_safely(sql, postgres());
    }
    // A later `COLUMN` item of a T-SQL `DROP` list is a dropped column.
    let sql = "ALTER TABLE users DROP CONSTRAINT IF EXISTS df1, COLUMN IF EXISTS c, d;";
    let Some(AstStmt::AlterTable(alter)) = first_statement(sql, &mssql()) else {
        panic!("ALTER TABLE expected: {sql}");
    };
    let AstAlterTableActionKind::DropColumn {
        drop_span, columns, ..
    } = &alter.actions[1].kind
    else {
        panic!("DROP COLUMN expected: {sql}: {:?}", alter.actions[1].kind);
    };
    assert!(drop_span.is_none());
    let names: Vec<&str> = columns.iter().map(|c| spanned(sql, *c)).collect();
    assert_eq!(names, ["c", "d"]);
    formats_safely(sql, mssql());
}

/// Format `sql` under `dialect`, check no token is lost, and check that
/// formatting the output again changes nothing; the output.
fn formats_stably(sql: &str, dialect: lexega_core::dialect::DialectRef) -> String {
    let config = lexega_core::FormatterConfig {
        dialect,
        ..Default::default()
    };
    let once = lexega_core::format_sql_with_config(sql, &config).expect("should format");
    lexega_core::verify_formatting_safe_with_dialect(sql, &once, config.dialect.as_ref())
        .expect("should preserve tokens");
    let twice = lexega_core::format_sql_with_config(&once, &config).expect("should format");
    assert_eq!(once, twice, "formatting twice changes {sql:?}");
    once
}

#[test]
fn a_column_altered_or_dropped_formats_the_same_twice() {
    use lexega_core::dialect::{bigquery, databricks, mssql, mysql, postgres, redshift, snowflake};
    let forms = [
        "ALTER TABLE users MODIFY email text;",
        "ALTER TABLE users ALTER email TYPE text;",
        "ALTER TABLE users ALTER email SET DEFAULT 'x';",
        "ALTER TABLE users ALTER email DROP NOT NULL;",
        "ALTER TABLE users ALTER COLUMN email TYPE text;",
        "ALTER TABLE users DROP COLUMN a;",
        "ALTER TABLE users DROP COLUMN IF EXISTS a;",
        "ALTER TABLE users DROP COLUMN a, COLUMN b;",
        "ALTER TABLE users DROP CONSTRAINT IF EXISTS df_c, COLUMN IF EXISTS c;",
    ];
    for dialect in [
        snowflake(),
        postgres(),
        mysql(),
        mssql(),
        databricks(),
        redshift(),
        bigquery(),
    ] {
        for sql in forms {
            formats_stably(sql, dialect.clone());
        }
        // Formatted text is formatted already.
        for formatted in [
            "ALTER TABLE users\n    MODIFY email text;",
            "ALTER TABLE users\n    ALTER email TYPE text;",
            "ALTER TABLE users\n    ALTER email SET DEFAULT 'x';",
            "ALTER TABLE users\n    ALTER email DROP NOT NULL;",
        ] {
            assert_eq!(
                formats_stably(formatted, dialect.clone()),
                formatted,
                "{}",
                dialect.name()
            );
        }
    }
}

#[test]
fn a_table_action_formats_the_same_twice() {
    use lexega_core::dialect::{bigquery, databricks, mssql, mysql, postgres, redshift, snowflake};
    let forms = [
        "ALTER TABLE users ADD CONSTRAINT c UNIQUE (a);",
        "ALTER TABLE users ADD CONSTRAINT pk PRIMARY KEY (id);",
        "ALTER TABLE users ADD CONSTRAINT fk FOREIGN KEY (a) REFERENCES t (b);",
        "ALTER TABLE users ADD CONSTRAINT c CHECK (a > 0), ADD CONSTRAINT d UNIQUE (b);",
        "ALTER TABLE users ADD FOREIGN KEY (a) REFERENCES t (b);",
        "ALTER TABLE dbo.zz_t ADD CONSTRAINT df DEFAULT (getdate()) FOR c;",
        "ALTER TABLE dbo.zz_t ADD CONSTRAINT uq UNIQUE NONCLUSTERED (a ASC, b DESC);",
        "ALTER TABLE dbo.zz_t WITH NOCHECK ADD CONSTRAINT ck_a CHECK (a > 0);",
        "ALTER TABLE [dbo].[zz_t] WITH CHECK ADD CONSTRAINT [fk_c] FOREIGN KEY([a]) REFERENCES [dbo].[zz_p] ([id]);",
        "ALTER TABLE users SET COMMENT = 'x';",
        "ALTER TABLE events SET DATA_RETENTION_TIME_IN_DAYS = 90, CHANGE_TRACKING = TRUE;",
        "ALTER TABLE dbo.zz_t SET (LOCK_ESCALATION = AUTO);",
        "ALTER TABLE users SET SCHEMA s2;",
        "ALTER TABLE crm.o SET SCHEMA \"ARCHIVE X\";",
        "ALTER TABLE crm.c DROP COLUMN a, DROP COLUMN b, SET SCHEMA archive;",
        "ALTER TABLE crm.o SET SCHEMA;",
        "ALTER TABLE users SET TBLPROPERTIES ('a' = 'b');",
        "ALTER TABLE users SET OPTIONS (description = 'x');",
        "ALTER TABLE users SET TAG t = 'v';",
        "ALTER TABLE users UNSET COMMENT;",
        "ALTER TABLE users UNSET DATA_RETENTION_TIME_IN_DAYS, COMMENT;",
        "ALTER TABLE users UNSET TAG t;",
        "ALTER TABLE users UNSET TBLPROPERTIES IF EXISTS ('a');",
        "ALTER TABLE users CLUSTER BY (a, b);",
        "ALTER TABLE sales CLUSTER BY (year, FLOOR(amount / 1000), category);",
        "ALTER TABLE users CLUSTER BY NONE;",
        "ALTER TABLE users CHANGE COLUMN email mail text;",
        "ALTER TABLE users CHANGE COLUMN email COMMENT 'x';",
        "ALTER TABLE users RENAME email TO mail;",
        "ALTER TABLE users DROP CONSTRAINT c1 CASCADE;",
        "ALTER TABLE users NOCHECK CONSTRAINT ALL;",
        "ALTER TABLE users ADD INDEX i1 (email);",
        "ALTER TABLE users ENGINE = InnoDB;",
        "ALTER TABLE users REPLICA IDENTITY FULL;",
        "ALTER TABLE users ALTER DISTKEY id;",
        "ALTER TABLE users VALIDATE CONSTRAINT c1;",
        "ALTER TABLE users WITH CHECK CHECK CONSTRAINT ALL;",
        "ALTER TABLE users TRUNCATE PARTITION p0;",
    ];
    for dialect in [
        snowflake(),
        postgres(),
        mysql(),
        mssql(),
        databricks(),
        redshift(),
        bigquery(),
    ] {
        for sql in forms {
            formats_stably(sql, dialect.clone());
        }
        // Formatted text is formatted already.
        for formatted in [
            "ALTER TABLE users\n    ADD CONSTRAINT c UNIQUE (a);",
            "ALTER TABLE users\n    SET COMMENT = 'x';",
            "ALTER TABLE users\n    SET SCHEMA s2;",
            "ALTER TABLE users\n    UNSET COMMENT;",
            "ALTER TABLE users\n    CLUSTER BY (a, b);",
        ] {
            assert_eq!(
                formats_stably(formatted, dialect.clone()),
                formatted,
                "{}",
                dialect.name()
            );
        }
    }
}

#[test]
fn a_databricks_change_of_a_column_clause_alters_the_column() {
    use lexega_core::dialect::databricks;
    let altered = [
        (
            "CHANGE COLUMN email COMMENT 'Customer e-mail'",
            "email",
            "COMMENT 'Customer e-mail'",
        ),
        ("CHANGE email COMMENT 'x'", "email", "COMMENT 'x'"),
        (
            "CHANGE COLUMN `email` COMMENT 'x'",
            "`email`",
            "COMMENT 'x'",
        ),
        ("CHANGE COLUMN email FIRST", "email", "FIRST"),
        ("CHANGE COLUMN email AFTER id", "email", "AFTER id"),
        ("CHANGE COLUMN email TYPE STRING", "email", "TYPE STRING"),
        ("CHANGE COLUMN email SET NOT NULL", "email", "SET NOT NULL"),
        (
            "CHANGE COLUMN email DROP NOT NULL",
            "email",
            "DROP NOT NULL",
        ),
        (
            "CHANGE COLUMN email SET DEFAULT 'x'",
            "email",
            "SET DEFAULT 'x'",
        ),
        ("CHANGE COLUMN email DROP DEFAULT", "email", "DROP DEFAULT"),
        ("CHANGE COLUMN email SET MASK m", "email", "SET MASK m"),
        ("CHANGE COLUMN email DROP MASK", "email", "DROP MASK"),
        ("CHANGE COLUMN id SYNC IDENTITY", "id", "SYNC IDENTITY"),
    ];
    for (action, column, operation) in altered {
        let sql = format!("ALTER TABLE users {action};");
        let Some(AstStmt::AlterTable(alter)) = first_statement(&sql, &databricks()) else {
            panic!("ALTER TABLE expected: {sql}");
        };
        let AstAlterTableActionKind::AlterColumn {
            column_name_span,
            operation_span,
            ..
        } = &alter.actions[0].kind
        else {
            panic!("ALTER COLUMN expected: {sql}: {:?}", alter.actions[0].kind);
        };
        assert_eq!(spanned(&sql, *column_name_span), column, "{sql}");
        assert_eq!(spanned(&sql, *operation_span), operation, "{sql}");
        formats_stably(&sql, databricks());
    }
    // Two names and a definition rename the column.
    for (action, new) in [
        ("CHANGE a b BIGINT", "b"),
        ("CHANGE a comment VARCHAR(10)", "comment"),
        ("CHANGE a first INT", "first"),
    ] {
        let sql = format!("ALTER TABLE users {action};");
        let Some(AstStmt::AlterTable(alter)) = first_statement(&sql, &databricks()) else {
            panic!("ALTER TABLE expected: {sql}");
        };
        let AstAlterTableActionKind::ChangeColumn { new_name_span, .. } = &alter.actions[0].kind
        else {
            panic!("CHANGE expected: {sql}: {:?}", alter.actions[0].kind);
        };
        assert_eq!(spanned(&sql, *new_name_span), new, "{sql}");
    }
}

#[test]
fn a_column_added_if_not_exists_or_in_parentheses_is_read() {
    use lexega_core::dialect::{bigquery, databricks, mysql, postgres, snowflake};
    let cases = [
        (
            "ADD COLUMN IF NOT EXISTS phone STRING",
            snowflake(),
            vec!["phone"],
        ),
        (
            "ADD COLUMN IF NOT EXISTS phone TEXT",
            postgres(),
            vec!["phone"],
        ),
        ("ADD IF NOT EXISTS phone TEXT", postgres(), vec!["phone"]),
        (
            "ADD COLUMN IF NOT EXISTS phone TEXT",
            mysql(),
            vec!["phone"],
        ),
        (
            "ADD COLUMN IF NOT EXISTS phone STRING",
            databricks(),
            vec!["phone"],
        ),
        (
            "ADD COLUMN IF NOT EXISTS phone STRING",
            bigquery(),
            vec!["phone"],
        ),
        (
            "ADD COLUMNS (phone STRING, fax INT)",
            databricks(),
            vec!["phone", "fax"],
        ),
        (
            "ADD COLUMNS (phone STRING COMMENT 'p')",
            databricks(),
            vec!["phone"],
        ),
    ];
    for (action, dialect, names) in cases {
        let sql = format!("ALTER TABLE users {action};");
        let Some(AstStmt::AlterTable(alter)) = first_statement(&sql, &dialect) else {
            panic!("ALTER TABLE expected: {sql}");
        };
        let AstAlterTableActionKind::AddColumn { columns, .. } = &alter.actions[0].kind else {
            panic!("ADD COLUMN expected: {sql}: {:?}", alter.actions[0].kind);
        };
        let read: Vec<&str> = columns
            .iter()
            .filter_map(|c| c.name_span.map(|span| spanned(&sql, span)))
            .collect();
        assert_eq!(read, names, "{sql}");
        formats_stably(&sql, dialect);
    }
    // The statements after a parenthesised list are each read.
    let sql = "ALTER TABLE users ADD COLUMNS (phone STRING, fax INT);\n\
               SELECT 1;\nSELECT 2;\nSELECT 3;";
    let script = lexega_core::parse_sql_with_dialect(sql, databricks().as_ref()).expect("parses");
    assert_eq!(script.stmts.len(), 4, "{:?}", script.stmts);
    assert!(
        !script
            .stmts
            .iter()
            .any(|s| matches!(s, AstStmt::OpaqueContent { .. })),
        "{:?}",
        script.stmts
    );
}

/// The column an action that alters one names.
fn altered_column(kind: &AstAlterTableActionKind) -> Option<lexega_core::lexer::Span> {
    use AstAlterTableActionKind as K;
    if let K::AlterColumn {
        column_name_span, ..
    }
    | K::AlterColumnDropNotNull {
        column_name_span, ..
    }
    | K::AlterColumnSetDataType {
        column_name_span, ..
    }
    | K::AlterColumnSetDefault {
        column_name_span, ..
    }
    | K::AlterColumnDropDefault {
        column_name_span, ..
    } = kind
    {
        return Some(*column_name_span);
    }
    None
}

#[test]
fn a_column_alteration_lists_each_column() {
    use lexega_core::dialect::{databricks, snowflake};
    // Bare `ALTER col <clause>`.
    for (action, dialect) in [
        ("ALTER email COMMENT 'x'", snowflake()),
        ("ALTER email UNSET COMMENT", snowflake()),
        ("ALTER email FIRST", databricks()),
        ("ALTER email AFTER id", databricks()),
        ("ALTER email VARCHAR(100)", snowflake()),
    ] {
        let sql = format!("ALTER TABLE users {action};");
        let Some(AstStmt::AlterTable(alter)) = first_statement(&sql, &dialect) else {
            panic!("ALTER TABLE expected: {sql}");
        };
        let AstAlterTableActionKind::AlterColumn {
            column_name_span, ..
        } = &alter.actions[0].kind
        else {
            panic!("ALTER COLUMN expected: {sql}: {:?}", alter.actions[0].kind);
        };
        assert_eq!(spanned(&sql, *column_name_span), "email", "{sql}");
        formats_stably(&sql, dialect);
    }
    // A comma list alters a column per item.
    for action in [
        "ALTER email COMMENT 'x', name SET NOT NULL",
        "ALTER COLUMN email SET NOT NULL, COLUMN name DROP NOT NULL",
        "MODIFY COLUMN email SET NOT NULL, name DROP NOT NULL",
        "ALTER email SET DATA TYPE VARCHAR(100), name VARCHAR(50)",
    ] {
        let sql = format!("ALTER TABLE users {action};");
        let Some(AstStmt::AlterTable(alter)) = first_statement(&sql, &snowflake()) else {
            panic!("ALTER TABLE expected: {sql}");
        };
        let names: Vec<&str> = alter
            .actions
            .iter()
            .map(|action| {
                let column = altered_column(&action.kind);
                spanned(
                    &sql,
                    column.unwrap_or_else(|| panic!("{sql}: {:?}", action.kind)),
                )
            })
            .collect();
        assert_eq!(names, ["email", "name"], "{sql}");
        formats_stably(&sql, snowflake());
    }
    // So does a parenthesised one.
    for action in [
        "ALTER (COLUMN email SET NOT NULL, COLUMN name DROP NOT NULL)",
        "MODIFY (email DROP DEFAULT, name SET NOT NULL)",
        "ALTER (email VARCHAR(100), name SET NOT NULL)",
    ] {
        let sql = format!("ALTER TABLE users {action};");
        let Some(AstStmt::AlterTable(alter)) = first_statement(&sql, &snowflake()) else {
            panic!("ALTER TABLE expected: {sql}");
        };
        let AstAlterTableActionKind::AlterColumnList { columns, .. } = &alter.actions[0].kind
        else {
            panic!("a column list expected: {sql}: {:?}", alter.actions[0].kind);
        };
        let names: Vec<&str> = columns.iter().map(|c| spanned(&sql, *c)).collect();
        assert_eq!(names, ["email", "name"], "{sql}");
        formats_stably(&sql, snowflake());
    }
}

/// A Snowflake column tag list ends before the next item of a list of
/// column alterations, which tags or untags its own column.
#[test]
fn a_column_tag_list_ends_before_the_next_column_item() {
    use lexega_core::dialect::snowflake;
    for (action, expected) in [
        (
            "MODIFY COLUMN email SET TAG pii = 'a', COLUMN name SET TAG pii = 'b'",
            [("email", "SET", "pii"), ("name", "SET", "pii")],
        ),
        (
            "ALTER COLUMN email SET TAG pii = 'a', COLUMN name UNSET TAG pii",
            [("email", "SET", "pii"), ("name", "UNSET", "pii")],
        ),
        (
            "MODIFY COLUMN email UNSET TAG pii, COLUMN name UNSET TAG pii",
            [("email", "UNSET", "pii"), ("name", "UNSET", "pii")],
        ),
        (
            "MODIFY COLUMN email UNSET TAG pii, name UNSET TAG pii",
            [("email", "UNSET", "pii"), ("name", "UNSET", "pii")],
        ),
        (
            "ALTER email SET TAG a.b.pii = 'a', t2 = 'c', name UNSET TAG pii, t2",
            [("email", "SET", "a.b.pii"), ("name", "UNSET", "pii")],
        ),
    ] {
        let sql = format!("ALTER TABLE users {action};");
        let Some(AstStmt::AlterTable(alter)) = first_statement(&sql, &snowflake()) else {
            panic!("ALTER TABLE expected: {sql}");
        };
        let items: Vec<(&str, &str, &str)> = alter
            .actions
            .iter()
            .map(|action| match &action.kind {
                AstAlterTableActionKind::SetColumnTag {
                    column_name_span,
                    tags,
                    ..
                } => (
                    spanned(&sql, *column_name_span),
                    "SET",
                    spanned(&sql, tags[0].name.span),
                ),
                AstAlterTableActionKind::UnsetColumnTag {
                    column_name_span,
                    tags,
                    ..
                } => (
                    spanned(&sql, *column_name_span),
                    "UNSET",
                    spanned(&sql, tags[0].name.span),
                ),
                other => panic!("{sql}: a column tag action expected: {other:?}"),
            })
            .collect();
        assert_eq!(items, expected, "{sql}");
        formats_stably(&sql, snowflake());
    }
}

/// The variant of `kind` and the column it names, as written.
fn column_action<'s>(
    sql: &'s str,
    kind: &AstAlterTableActionKind,
) -> (std::mem::Discriminant<AstAlterTableActionKind>, &'s str) {
    let variant = std::mem::discriminant(kind);
    let debug = format!("{kind:?}");
    let at = debug
        .find("column_name_span: Span { start: ")
        .unwrap_or_else(|| panic!("{sql}: no column name: {debug}"));
    let numbers: Vec<u32> = debug[at..]
        .split(|c: char| !c.is_ascii_digit())
        .filter(|n| !n.is_empty())
        .take(2)
        .map(|n| n.parse().expect("a number"))
        .collect();
    let span = lexega_core::lexer::Span {
        start: numbers[0],
        end: numbers[1],
    };
    (variant, spanned(sql, span))
}

/// A column alteration written without `COLUMN` is the action its `COLUMN`
/// form is, alone or as an item of a list.
#[test]
fn a_column_alteration_without_the_column_keyword_is_the_same_action() {
    use lexega_core::dialect::{databricks, mysql, snowflake};
    let operations = [
        ("SET MASKING POLICY gov.p.mask_email", snowflake()),
        (
            "SET MASKING POLICY gov.p.mask_email USING (email, id) FORCE",
            snowflake(),
        ),
        ("UNSET MASKING POLICY", snowflake()),
        ("SET PROJECTION POLICY gov.p.pp", snowflake()),
        ("SET PROJECTION POLICY gov.p.pp FORCE", snowflake()),
        ("UNSET PROJECTION POLICY", snowflake()),
        ("SET TAG pii = 'a'", snowflake()),
        ("SET TAG pii = 'a', t2 = 'b'", snowflake()),
        ("UNSET TAG pii", snowflake()),
        ("UNSET TAG pii, t2", snowflake()),
        ("SET NOT NULL", snowflake()),
        ("DROP NOT NULL", snowflake()),
        ("SET DEFAULT 1", snowflake()),
        ("DROP DEFAULT", mysql()),
        ("SET DATA TYPE VARCHAR(100)", snowflake()),
        ("SET MASK gov.p.mask_fn", databricks()),
        ("DROP MASK", databricks()),
        ("COMMENT 'x'", snowflake()),
    ];
    for (operation, dialect) in operations {
        for verb in ["ALTER", "MODIFY"] {
            let with = format!("ALTER TABLE users {verb} COLUMN email {operation};");
            let without = format!("ALTER TABLE users {verb} email {operation};");
            let actions = |sql: &str| {
                let Some(AstStmt::AlterTable(alter)) = first_statement(sql, &dialect) else {
                    panic!("ALTER TABLE expected: {sql}");
                };
                alter.actions
            };
            let (with_actions, without_actions) = (actions(&with), actions(&without));
            assert_eq!(with_actions.len(), 1, "{with}: {with_actions:?}");
            assert_eq!(without_actions.len(), 1, "{without}: {without_actions:?}");
            assert_eq!(
                column_action(&with, &with_actions[0].kind),
                column_action(&without, &without_actions[0].kind),
                "{with} / {without}"
            );
            formats_stably(&without, dialect.clone());
        }
    }
    // Later items of a list, with and without `COLUMN`.
    let with = "ALTER TABLE users ALTER COLUMN email UNSET MASKING POLICY, \
                COLUMN name SET PROJECTION POLICY gov.p.pp, COLUMN id UNSET TAG pii;";
    let without = "ALTER TABLE users ALTER email UNSET MASKING POLICY, \
                   name SET PROJECTION POLICY gov.p.pp, id UNSET TAG pii;";
    let items = |sql: &'static str| -> Vec<(
        std::mem::Discriminant<AstAlterTableActionKind>,
        &'static str,
    )> {
        let Some(AstStmt::AlterTable(alter)) = first_statement(sql, &snowflake()) else {
            panic!("ALTER TABLE expected: {sql}");
        };
        alter
            .actions
            .iter()
            .map(|action| column_action(sql, &action.kind))
            .collect()
    };
    assert_eq!(items(with), items(without));
    assert_eq!(items(with).len(), 3, "{with}");
    // Each item starts its own line at the actions' indentation.
    for sql in [with, without] {
        let out = formats_stably(sql, snowflake());
        assert!(
            out.lines().skip(1).all(|line| line.starts_with("    ")),
            "{out}"
        );
    }
}

/// A conditional masking policy (`USING (…)`) formats, with `COLUMN` or
/// without, in every dialect.
#[test]
fn a_conditional_masking_policy_formats_in_either_form() {
    use lexega_core::dialect::{bigquery, databricks, mssql, mysql, postgres, redshift, snowflake};
    for dialect in [
        snowflake(),
        bigquery(),
        postgres(),
        databricks(),
        mysql(),
        mssql(),
        redshift(),
    ] {
        for lead in ["ALTER COLUMN email", "ALTER email", "MODIFY email"] {
            for tail in ["", " FORCE"] {
                let sql = format!(
                    "ALTER TABLE users {lead} SET MASKING POLICY p USING (email, id){tail};"
                );
                let out = formats_stably(&sql, dialect.clone());
                assert!(out.contains("USING (email, id)"), "{sql}: {out}");
            }
        }
    }
}

/// A line comment after a column's name keeps the next line indented.
#[test]
fn a_line_comment_after_a_column_name_keeps_the_next_line_indented() {
    for sql in [
        "ALTER TABLE users ALTER email -- why\n  SET TAG pii = 'a';",
        "ALTER TABLE users ALTER COLUMN email -- why\n  SET MASKING POLICY p;",
        "ALTER TABLE users ALTER email -- why\n  UNSET PROJECTION POLICY;",
    ] {
        let out = formats_stably(sql, lexega_core::dialect::snowflake());
        let after = out
            .split_once(" -- why\n")
            .map(|(_, rest)| rest)
            .expect("the comment is kept");
        assert!(after.starts_with(' '), "{out}");
    }
}

#[test]
fn a_line_comment_after_if_not_exists_or_set_keeps_the_next_line_indented() {
    for sql in [
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS -- why\n  phone STRING;",
        "ALTER TABLE users SET -- c\n  COMMENT = 'x';",
        "ALTER TABLE users UNSET -- c\n  COMMENT;",
    ] {
        let out = formats_stably(sql, lexega_core::dialect::snowflake());
        let after = out
            .split_once(" -- ")
            .and_then(|(_, rest)| rest.split_once('\n'))
            .map(|(_, rest)| rest)
            .expect("the comment is kept");
        assert!(after.starts_with(' '), "{out}");
    }
}

#[test]
fn a_comment_inside_a_change_keeps_the_next_line_indented() {
    let sql = "alter table users change email -- why\n  mail text, add index i (mail);";
    let out = formats_stably(sql, lexega_core::dialect::mysql());
    let after = out
        .split_once("-- why\n")
        .map(|(_, rest)| rest)
        .expect("the comment is kept");
    assert!(after.starts_with(' '), "{out}");
}
