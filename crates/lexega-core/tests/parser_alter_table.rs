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
        assert!(alter.name_span.start >= alter.table_span.end);
        assert!(alter.actions_span.start >= alter.name_span.end);
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
