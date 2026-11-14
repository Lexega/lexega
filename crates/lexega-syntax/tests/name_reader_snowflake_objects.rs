// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! The shapes other Snowflake objects are written in, each read whole as the name it is.

mod name_shapes;

use lexega_syntax::ast::{
    AlterCatalogActionKind, AstAccountPolicyKind, AstAlterAccountActionKind,
    AstAlterAggregationPolicyActionKind, AstAlterApiIntegrationActionKind,
    AstAlterAuthenticationPolicyActionKind, AstAlterDatabaseActionKind,
    AstAlterDynamicTableActionKind, AstAlterExternalAccessIntegrationActionKind,
    AstAlterFunctionActionKind, AstAlterJoinPolicyActionKind, AstAlterMaskingPolicyActionKind,
    AstAlterNetworkPolicyActionKind, AstAlterNotificationIntegrationActionKind,
    AstAlterPasswordPolicyActionKind, AstAlterPipeActionKind, AstAlterProcedureActionKind,
    AstAlterProjectionPolicyActionKind, AstAlterRowAccessPolicyActionKind,
    AstAlterSchemaActionKind, AstAlterSessionPolicyActionKind, AstAlterShareActionKind,
    AstAlterStageActionKind, AstAlterStorageIntegrationActionKind, AstAlterStreamActionKind,
    AstAlterTableActionKind, AstAlterTaskActionKind, AstAlterViewActionKind,
    AstAlterWarehouseActionKind, AstColumnPolicyUnset, AstCreateTable, AstCreateView,
    AstDescribeKind, AstObjectRef, AstShareObjectKind, AstSnowflakeUserOptions, AstStageRef,
    AstTableNameKind, AstTagRef, FromItemKind,
};
use lexega_syntax::dialect;
use lexega_syntax::{
    format_sql_with_config, parse_sql_with_dialect, verify_formatting_safe_with_dialect, AstStmt,
    DialectRef, FormatterConfig, Span,
};
use name_shapes::reads_whole;

#[test]
fn snowflake_alter_dynamic_table_add_row_access_policy_name() {
    reads_whole(
        &dialect::snowflake(),
        &[
            "ALTER DYNAMIC TABLE crm.dt_orders ADD ROW ACCESS POLICY «IDENTIFIER('d1.s1.rap_region')» ON (region);",
        ],
    );
}

#[test]
fn snowflake_alter_dynamic_table_alter_column_c_set_masking_policy_name() {
    reads_whole(
        &dialect::snowflake(),
        &[
            "ALTER DYNAMIC TABLE crm.dt_orders ALTER COLUMN email SET MASKING POLICY «IDENTIFIER('d1.s1.mask_email')»;",
        ],
    );
}

#[test]
fn snowflake_alter_dynamic_table_alter_column_c_set_tag_name() {
    reads_whole(
        &dialect::snowflake(),
        &[
            "ALTER DYNAMIC TABLE crm.dt_orders ALTER COLUMN email SET TAG «IDENTIFIER('d1.s1.sensitivity')» = 'high';",
        ],
    );
}

#[test]
fn snowflake_alter_dynamic_table_rename_to_name() {
    reads_whole(
        &dialect::snowflake(),
        &["ALTER DYNAMIC TABLE crm.dt_orders RENAME TO «IDENTIFIER('d1.s1.dt2')»;"],
    );
}

#[test]
fn snowflake_alter_dynamic_table_set_aggregation_policy_name() {
    reads_whole(
        &dialect::snowflake(),
        &[
            "ALTER DYNAMIC TABLE crm.dt_orders SET AGGREGATION POLICY «IDENTIFIER('d1.s1.ap_min')»;",
        ],
    );
}

#[test]
fn snowflake_alter_dynamic_table_set_tag_name() {
    reads_whole(
        &dialect::snowflake(),
        &["ALTER DYNAMIC TABLE crm.dt_orders SET TAG «IDENTIFIER('d1.s1.sensitivity')» = 'high';"],
    );
}

#[test]
fn snowflake_alter_dynamic_table_swap_with_name() {
    reads_whole(
        &dialect::snowflake(),
        &["ALTER DYNAMIC TABLE crm.dt_orders SWAP WITH «IDENTIFIER('d1.s1.dt2')»;"],
    );
}

#[test]
fn snowflake_alter_dynamic_table_unset_tag_name() {
    reads_whole(
        &dialect::snowflake(),
        &["ALTER DYNAMIC TABLE crm.dt_orders UNSET TAG «IDENTIFIER('d1.s1.sensitivity')»;"],
    );
}

#[test]
fn snowflake_alter_api_integration_integration_name() {
    reads_whole(
        &dialect::snowflake(),
        &["ALTER API INTEGRATION «IDENTIFIER('api_int')» SET ENABLED = FALSE;"],
    );
}

#[test]
fn snowflake_create_api_integration_integration_name() {
    reads_whole(
        &dialect::snowflake(),
        &[
            "CREATE API INTEGRATION «IDENTIFIER('api_int')» API_PROVIDER = aws_api_gateway API_AWS_ROLE_ARN = 'arn:aws:iam::1:role/r' API_ALLOWED_PREFIXES = ('https://x') ENABLED = TRUE;",
        ],
    );
}

#[test]
fn snowflake_alter_view_rename_to_name() {
    reads_whole(
        &dialect::snowflake(),
        &["ALTER VIEW crm.v_orders RENAME TO IDENTIFIER('d1.s1.v_orders2');"],
    );
}

#[test]
fn snowflake_comment_on_column_tbl_col() {
    reads_whole(
        &dialect::snowflake(),
        &["COMMENT ON COLUMN IDENTIFIER('d1.s1.orders').email IS 'x';"],
    );
}

#[test]
fn snowflake_create_database_clone_name() {
    reads_whole(
        &dialect::snowflake(),
        &["CREATE DATABASE analytics CLONE «IDENTIFIER('analytics_src')»;"],
    );
}

#[test]
fn snowflake_create_database_database_name() {
    reads_whole(
        &dialect::snowflake(),
        &["CREATE DATABASE «IDENTIFIER('analytics')»;"],
    );
}

#[test]
fn snowflake_drop_database_database_name() {
    reads_whole(
        &dialect::snowflake(),
        &["DROP DATABASE «IDENTIFIER('analytics')»;"],
    );
}

#[test]
fn snowflake_alter_database_rename_to_name() {
    reads_whole(
        &dialect::snowflake(),
        &["ALTER DATABASE analytics RENAME TO «IDENTIFIER('analytics2')»;"],
    );
}

#[test]
fn snowflake_create_database_as_replica_of_org_acct_db() {
    reads_whole(
        &dialect::snowflake(),
        &["CREATE DATABASE analytics_rep AS REPLICA OF «IDENTIFIER('d1.s1.analytics')»;"],
    );
}

#[test]
fn snowflake_create_database_from_share_acct_share() {
    reads_whole(
        &dialect::snowflake(),
        &["CREATE DATABASE partner_db FROM SHARE «IDENTIFIER('s1.sh_partner')»;"],
    );
}

#[test]
fn snowflake_drop_integration_integration_name() {
    reads_whole(
        &dialect::snowflake(),
        &["DROP INTEGRATION «IDENTIFIER('s3_int')»;"],
    );
}

#[test]
fn snowflake_drop_pipe_pipe_name() {
    reads_whole(
        &dialect::snowflake(),
        &["DROP PIPE «IDENTIFIER('d1.s1.p_ingest')»;"],
    );
}

#[test]
fn snowflake_drop_stream_stream_name() {
    reads_whole(
        &dialect::snowflake(),
        &["DROP STREAM «IDENTIFIER('d1.s1.s_orders')»;"],
    );
}

#[test]
fn snowflake_alter_external_access_integration_integration_name() {
    reads_whole(
        &dialect::snowflake(),
        &["ALTER EXTERNAL ACCESS INTEGRATION «IDENTIFIER('eai_ext')» SET ENABLED = FALSE;"],
    );
}

#[test]
fn snowflake_alter_external_access_integration_set_tag_name() {
    reads_whole(
        &dialect::snowflake(),
        &[
            "ALTER EXTERNAL ACCESS INTEGRATION eai_ext SET TAG «IDENTIFIER('d1.s1.sensitivity')» = 'high';",
        ],
    );
}

#[test]
fn snowflake_alter_file_format_format_name() {
    reads_whole(
        &dialect::snowflake(),
        &["ALTER FILE FORMAT «IDENTIFIER('d1.s1.ff_csv')» SET COMMENT = 'x';"],
    );
}

#[test]
fn snowflake_alter_file_format_rename_to_name() {
    reads_whole(
        &dialect::snowflake(),
        &["ALTER FILE FORMAT crm.ff_csv RENAME TO «IDENTIFIER('d1.s1.ff2')»;"],
    );
}

#[test]
fn snowflake_alter_function_function_name() {
    reads_whole(
        &dialect::snowflake(),
        &["ALTER FUNCTION «IDENTIFIER('d1.s1.f_hash')»(STRING) SET SECURE;"],
    );
}

#[test]
fn snowflake_alter_function_rename_to_name() {
    reads_whole(
        &dialect::snowflake(),
        &["ALTER FUNCTION crm.f_hash(STRING) RENAME TO «IDENTIFIER('d1.s1.f_hash2')»;"],
    );
}

#[test]
fn snowflake_alter_function_set_tag_name() {
    reads_whole(
        &dialect::snowflake(),
        &["ALTER FUNCTION crm.f_hash(STRING) SET TAG «IDENTIFIER('d1.s1.sensitivity')» = 'high';"],
    );
}

#[test]
fn snowflake_grant_role_to_user_name() {
    reads_whole(
        &dialect::snowflake(),
        &["GRANT ROLE analyst TO USER «IDENTIFIER('alice')»;"],
    );
}

#[test]
fn snowflake_grant_to_share_name() {
    reads_whole(
        &dialect::snowflake(),
        &["GRANT SELECT ON TABLE crm.orders TO SHARE «IDENTIFIER('sh_partner')»;"],
    );
}

#[test]
fn snowflake_grant_to_database_role_name() {
    reads_whole(
        &dialect::snowflake(),
        &["GRANT SELECT ON TABLE crm.orders TO DATABASE ROLE «IDENTIFIER('s1.reader')»;"],
    );
}

#[test]
fn snowflake_grant_to_role_name() {
    reads_whole(
        &dialect::snowflake(),
        &["GRANT SELECT ON TABLE crm.orders TO ROLE «IDENTIFIER('analyst')»;"],
    );
}

#[test]
fn snowflake_insert_into_name() {
    reads_whole(
        &dialect::snowflake(),
        &["INSERT INTO «IDENTIFIER('d1.s1.orders')» (id) VALUES (1);"],
    );
}

#[test]
fn snowflake_alter_network_rule_rule_name() {
    reads_whole(
        &dialect::snowflake(),
        &[
            "ALTER NETWORK RULE «IDENTIFIER('d1.s1.rule_api')» SET VALUE_LIST = ('api.example.com');",
        ],
    );
}

#[test]
fn snowflake_create_notification_integration_integration_name() {
    reads_whole(
        &dialect::snowflake(),
        &[
            "CREATE NOTIFICATION INTEGRATION «IDENTIFIER('notif_int')» ENABLED = TRUE TYPE = QUEUE NOTIFICATION_PROVIDER = AWS_SNS AWS_SNS_TOPIC_ARN = 'arn:aws:sns:us-east-1:1:t' AWS_SNS_ROLE_ARN = 'arn:aws:iam::1:role/r';",
        ],
    );
}

#[test]
fn snowflake_alter_procedure_procedure_name() {
    reads_whole(
        &dialect::snowflake(),
        &["ALTER PROCEDURE «IDENTIFIER('d1.s1.p_load')»() SET COMMENT = 'x';"],
    );
}

#[test]
fn snowflake_alter_procedure_set_tag_name() {
    reads_whole(
        &dialect::snowflake(),
        &["ALTER PROCEDURE crm.p_load() SET TAG «IDENTIFIER('d1.s1.sensitivity')» = 'high';"],
    );
}

#[test]
fn snowflake_create_schema_clone_name() {
    reads_whole(
        &dialect::snowflake(),
        &["CREATE SCHEMA analytics.crm CLONE «IDENTIFIER('s1.crm_src')»;"],
    );
}

#[test]
fn snowflake_create_schema_schema_name() {
    reads_whole(
        &dialect::snowflake(),
        &["CREATE SCHEMA «IDENTIFIER('s1.crm')»;"],
    );
}

#[test]
fn snowflake_drop_schema_schema_name() {
    reads_whole(
        &dialect::snowflake(),
        &["DROP SCHEMA «IDENTIFIER('s1.crm')»;"],
    );
}

#[test]
fn snowflake_alter_schema_rename_to_name() {
    reads_whole(
        &dialect::snowflake(),
        &["ALTER SCHEMA analytics.crm RENAME TO «IDENTIFIER('s1.crm2')»;"],
    );
}

#[test]
fn snowflake_alter_schema_swap_with_name() {
    reads_whole(
        &dialect::snowflake(),
        &["ALTER SCHEMA analytics.crm SWAP WITH «IDENTIFIER('s1.crm2')»;"],
    );
}

#[test]
fn snowflake_undrop_schema_schema_name() {
    reads_whole(
        &dialect::snowflake(),
        &["UNDROP SCHEMA «IDENTIFIER('s1.crm')»;"],
    );
}

#[test]
fn snowflake_alter_secret_secret_name() {
    reads_whole(
        &dialect::snowflake(),
        &["ALTER SECRET «IDENTIFIER('d1.s1.sec_api')» SET COMMENT = 'x';"],
    );
}

#[test]
fn snowflake_create_share_share_name() {
    reads_whole(
        &dialect::snowflake(),
        &["CREATE SHARE «IDENTIFIER('sh_partner')»;"],
    );
}

#[test]
fn snowflake_alter_storage_integration_integration_name() {
    reads_whole(
        &dialect::snowflake(),
        &["ALTER STORAGE INTEGRATION «IDENTIFIER('s3_int')» SET ENABLED = FALSE;"],
    );
}

#[test]
fn snowflake_create_storage_integration_integration_name() {
    reads_whole(
        &dialect::snowflake(),
        &[
            "CREATE STORAGE INTEGRATION «IDENTIFIER('s3_int')» TYPE = EXTERNAL_STAGE STORAGE_PROVIDER = 'S3' ENABLED = TRUE STORAGE_AWS_ROLE_ARN = 'arn:aws:iam::1:role/r' STORAGE_ALLOWED_LOCATIONS = ('s3://bucket/');",
        ],
    );
}

#[test]
fn snowflake_alter_stage_rename_to_name() {
    reads_whole(
        &dialect::snowflake(),
        &[
            "ALTER STAGE stg_raw RENAME TO «d1.stage.stg2»;",
            "ALTER STAGE stg_raw RENAME TO «IDENTIFIER('d1.s1.stg2')»;",
        ],
    );
}

#[test]
fn snowflake_alter_stream_stream_name() {
    reads_whole(
        &dialect::snowflake(),
        &["ALTER STREAM «IDENTIFIER('d1.s1.s_orders')» SET COMMENT = 'x';"],
    );
}

#[test]
fn snowflake_create_stream_stream_name() {
    reads_whole(
        &dialect::snowflake(),
        &["CREATE STREAM «IDENTIFIER('d1.s1.s_orders')» ON TABLE crm.orders;"],
    );
}

#[test]
fn snowflake_create_stream_on_table_name() {
    reads_whole(
        &dialect::snowflake(),
        &["CREATE STREAM crm.s_orders ON TABLE «IDENTIFIER('d1.s1.orders')»;"],
    );
}

#[test]
fn snowflake_alter_task_add_after_name() {
    reads_whole(
        &dialect::snowflake(),
        &["ALTER TASK crm.t_load ADD AFTER «IDENTIFIER('d1.s1.t_root')»;"],
    );
}

#[test]
fn snowflake_drop_task_task_name() {
    reads_whole(
        &dialect::snowflake(),
        &["DROP TASK «IDENTIFIER('d1.s1.t_load')»;"],
    );
}

#[test]
fn snowflake_alter_task_set_tag_name() {
    reads_whole(
        &dialect::snowflake(),
        &["ALTER TASK crm.t_load SET TAG «IDENTIFIER('d1.s1.sensitivity')» = 'high';"],
    );
}

#[test]
fn snowflake_undrop_table_table_name() {
    reads_whole(
        &dialect::snowflake(),
        &["UNDROP TABLE «IDENTIFIER('d1.s1.orders')»;"],
    );
}

#[test]
fn snowflake_use_database_database_name() {
    reads_whole(
        &dialect::snowflake(),
        &["USE DATABASE «IDENTIFIER('analytics')»;"],
    );
}

#[test]
fn snowflake_use_role_role_name() {
    reads_whole(
        &dialect::snowflake(),
        &["USE ROLE «IDENTIFIER('analyst')»;"],
    );
}

#[test]
fn snowflake_use_schema_schema_name() {
    reads_whole(
        &dialect::snowflake(),
        &[
            "USE SCHEMA «stage.crm»;",
            "USE SCHEMA «IDENTIFIER('s1.crm')»;",
        ],
    );
}

#[test]
fn snowflake_use_warehouse_warehouse_name() {
    reads_whole(
        &dialect::snowflake(),
        &["USE WAREHOUSE «IDENTIFIER('wh_etl')»;"],
    );
}

#[test]
fn snowflake_drop_warehouse_warehouse_name() {
    reads_whole(
        &dialect::snowflake(),
        &["DROP WAREHOUSE «IDENTIFIER('wh_etl')»;"],
    );
}

#[test]
fn snowflake_alter_warehouse_rename_to_name() {
    reads_whole(
        &dialect::snowflake(),
        &["ALTER WAREHOUSE wh_etl RENAME TO «IDENTIFIER('wh2')»;"],
    );
}

// ---------------------------------------------------------------------------
// Tag lists: each tag keeps its name as an object name and its value.
// ---------------------------------------------------------------------------

/// The tags of the one tag-list clause `stmt` holds.
fn tags_of(stmt: &AstStmt) -> &[AstTagRef] {
    match stmt {
        AstStmt::AlterRowAccessPolicy(s) => match &s.action.kind {
            AstAlterRowAccessPolicyActionKind::SetTag { tags, .. }
            | AstAlterRowAccessPolicyActionKind::UnsetTag { tags, .. } => tags,
            other => panic!("not a tag action: {other:?}"),
        },
        AstStmt::AlterTable(s) => match &s.actions[0].kind {
            AstAlterTableActionKind::SetTag { tags, .. }
            | AstAlterTableActionKind::UnsetTag { tags, .. }
            | AstAlterTableActionKind::SetColumnTag { tags, .. }
            | AstAlterTableActionKind::UnsetColumnTag { tags, .. } => tags,
            other => panic!("not a tag action: {other:?}"),
        },
        AstStmt::AlterView(s) => match &s.action.kind {
            AstAlterViewActionKind::SetTag { tags, .. }
            | AstAlterViewActionKind::UnsetTag { tags, .. } => tags,
            other => panic!("not a tag action: {other:?}"),
        },
        AstStmt::AlterStage(s) => match &s.action.kind {
            AstAlterStageActionKind::SetTag(action) => &action.tags,
            AstAlterStageActionKind::UnsetTag(action) => &action.tags,
            other => panic!("not a tag action: {other:?}"),
        },
        AstStmt::AlterStorageIntegration(s) => match &s.actions[0].kind {
            AstAlterStorageIntegrationActionKind::SetTag { tags, .. }
            | AstAlterStorageIntegrationActionKind::UnsetTag { tags, .. } => tags,
            other => panic!("not a tag action: {other:?}"),
        },
        AstStmt::AlterSchema(s) => match &s.action.kind {
            AstAlterSchemaActionKind::SetTag { tags, .. }
            | AstAlterSchemaActionKind::UnsetTag { tags, .. } => tags,
            other => panic!("not a tag action: {other:?}"),
        },
        AstStmt::AlterDatabase(s) => match &s.action.kind {
            AstAlterDatabaseActionKind::SetTag { tags, .. }
            | AstAlterDatabaseActionKind::UnsetTag { tags, .. } => tags,
            other => panic!("not a tag action: {other:?}"),
        },
        AstStmt::AlterWarehouse(s) => match &s.action.kind {
            AstAlterWarehouseActionKind::SetTag { tags, .. }
            | AstAlterWarehouseActionKind::UnsetTag { tags, .. } => tags,
            other => panic!("not a tag action: {other:?}"),
        },
        AstStmt::AlterStream(s) => match &s.action.kind {
            AstAlterStreamActionKind::SetTag { tags, .. }
            | AstAlterStreamActionKind::UnsetTag { tags, .. } => tags,
            other => panic!("not a tag action: {other:?}"),
        },
        AstStmt::AlterPipe(s) => match &s.action.kind {
            AstAlterPipeActionKind::SetTag { tags, .. }
            | AstAlterPipeActionKind::UnsetTag { tags, .. } => tags,
            other => panic!("not a tag action: {other:?}"),
        },
        AstStmt::AlterJoinPolicy(s) => match &s.action.kind {
            AstAlterJoinPolicyActionKind::SetTag { tags, .. }
            | AstAlterJoinPolicyActionKind::UnsetTag { tags, .. } => tags,
            other => panic!("not a tag action: {other:?}"),
        },
        AstStmt::CreateTable(s) => match s.columns.iter().find(|column| !column.tags.is_empty()) {
            Some(column) => &column.tags,
            None => &s.tags,
        },
        AstStmt::CreateView(s) => match s.columns.iter().find(|column| !column.tags.is_empty()) {
            Some(column) => &column.tags,
            None => &s.tags,
        },
        AstStmt::AlterTask(s) => match &s.action.kind {
            AstAlterTaskActionKind::SetTag { tags, .. }
            | AstAlterTaskActionKind::UnsetTag { tags, .. } => tags,
            other => panic!("not a tag action: {other:?}"),
        },
        AstStmt::AlterDynamicTable(s) => match &s.action.kind {
            AstAlterDynamicTableActionKind::SetTag { tags, .. }
            | AstAlterDynamicTableActionKind::UnsetTag { tags, .. }
            | AstAlterDynamicTableActionKind::SetColumnTag { tags, .. }
            | AstAlterDynamicTableActionKind::UnsetColumnTag { tags, .. } => tags,
            other => panic!("not a tag action: {other:?}"),
        },
        AstStmt::AlterFunction(s) => match &s.action.kind {
            AstAlterFunctionActionKind::SetTag { tags, .. }
            | AstAlterFunctionActionKind::UnsetTag { tags, .. } => tags,
            other => panic!("not a tag action: {other:?}"),
        },
        AstStmt::AlterProcedure(s) => match &s.action.kind {
            AstAlterProcedureActionKind::SetTag { tags, .. }
            | AstAlterProcedureActionKind::UnsetTag { tags, .. } => tags,
            other => panic!("not a tag action: {other:?}"),
        },
        AstStmt::AlterMaskingPolicy(s) => match &s.action.kind {
            AstAlterMaskingPolicyActionKind::SetTag { tags, .. }
            | AstAlterMaskingPolicyActionKind::UnsetTag { tags, .. } => tags,
            other => panic!("not a tag action: {other:?}"),
        },
        AstStmt::AlterNetworkPolicy(s) => match &s.action.kind {
            AstAlterNetworkPolicyActionKind::SetTag { tags, .. }
            | AstAlterNetworkPolicyActionKind::UnsetTag { tags, .. } => tags,
            other => panic!("not a tag action: {other:?}"),
        },
        AstStmt::AlterSessionPolicy(s) => match &s.actions[0].kind {
            AstAlterSessionPolicyActionKind::SetTag { tags, .. }
            | AstAlterSessionPolicyActionKind::UnsetTag { tags, .. } => tags,
            other => panic!("not a tag action: {other:?}"),
        },
        AstStmt::AlterApiIntegration(s) => match &s.actions[0].kind {
            AstAlterApiIntegrationActionKind::SetTag { tags, .. }
            | AstAlterApiIntegrationActionKind::UnsetTag { tags, .. } => tags,
            other => panic!("not a tag action: {other:?}"),
        },
        AstStmt::AlterNotificationIntegration(s) => match &s.actions[0].kind {
            AstAlterNotificationIntegrationActionKind::SetTag { tags, .. }
            | AstAlterNotificationIntegrationActionKind::UnsetTag { tags, .. } => tags,
            other => panic!("not a tag action: {other:?}"),
        },
        AstStmt::AlterPasswordPolicy(s) => match &s.actions[0].kind {
            AstAlterPasswordPolicyActionKind::SetTag { tags, .. }
            | AstAlterPasswordPolicyActionKind::UnsetTag { tags, .. } => tags,
            other => panic!("not a tag action: {other:?}"),
        },
        AstStmt::AlterAggregationPolicy(s) => match &s.actions[0].kind {
            AstAlterAggregationPolicyActionKind::SetTag { tags, .. }
            | AstAlterAggregationPolicyActionKind::UnsetTag { tags, .. } => tags,
            other => panic!("not a tag action: {other:?}"),
        },
        AstStmt::AlterProjectionPolicy(s) => match &s.action.kind {
            AstAlterProjectionPolicyActionKind::SetTag { tags, .. }
            | AstAlterProjectionPolicyActionKind::UnsetTag { tags, .. } => tags,
            other => panic!("not a tag action: {other:?}"),
        },
        AstStmt::AlterExternalAccessIntegration(s) => match &s.actions[0].kind {
            AstAlterExternalAccessIntegrationActionKind::SetTag { tags, .. }
            | AstAlterExternalAccessIntegrationActionKind::UnsetTag { tags, .. } => tags,
            other => panic!("not a tag action: {other:?}"),
        },
        AstStmt::CreateTask(s) => &s.tags,
        AstStmt::CreateDynamicTable(s) => &s.tags,
        AstStmt::CreateWarehouse(s) => &s.tags,
        AstStmt::CreateSchema(s) => &s.tags,
        AstStmt::CreateDatabase(s) => &s.tags,
        AstStmt::CreateExternalTable(s) => &s.tags,
        other => panic!("not a statement with a tag list: {other:?}"),
    }
}

/// The ways a tag list is written: one tag in each name shape, then two.
const TAG_LISTS: [&str; 6] = [
    "sensitivity",
    "s1.sensitivity",
    "d1.s1.sensitivity",
    "\"D1\".\"S 1\".\"SENSITIVITY X\"",
    "IDENTIFIER('d1.s1.sensitivity')",
    "gov.pii.sensitivity, cost_center",
];

/// Each of `TAG_LISTS` written between `before` and `after`, with
/// `name = 'high'` assignments where `assigned`: the statement keeps each tag's
/// name as written and its value, and is formatted without losing a token.
fn reads_tag_lists(before: &str, after: &str, assigned: bool) {
    for list in TAG_LISTS {
        let written: Vec<String> = list
            .split(", ")
            .map(|name| {
                if assigned {
                    format!("{name} = 'high'")
                } else {
                    name.to_string()
                }
            })
            .collect();
        let sql = format!("{before}{}{after}", written.join(", "));
        let script = parse_sql_with_dialect(&sql, &*dialect::snowflake())
            .unwrap_or_else(|e| panic!("{sql}: {e:?}"));
        let [stmt] = script.stmts.as_slice() else {
            panic!("{sql}: expected one statement, got {:?}", script.stmts);
        };
        let tags = tags_of(stmt);
        let names: Vec<&str> = list.split(", ").collect();
        assert_eq!(tags.len(), names.len(), "{sql}");
        for (tag, name) in tags.iter().zip(names) {
            let at = |span: Span| &sql[span.start as usize..span.end as usize];
            assert_eq!(at(tag.name.span), name, "{sql}");
            assert_eq!(tag.value.map(at), assigned.then_some("'high'"), "{sql}");
        }
        let config = FormatterConfig::default();
        let formatted =
            format_sql_with_config(&sql, &config).unwrap_or_else(|e| panic!("{sql}: {e:?}"));
        verify_formatting_safe_with_dialect(&sql, &formatted, config.dialect.as_ref())
            .unwrap_or_else(|e| panic!("{sql}: {e}"));
    }
}

#[test]
fn snowflake_alter_row_access_policy_set_tag_names() {
    reads_tag_lists(
        "ALTER ROW ACCESS POLICY gov.sec.rap_region SET TAG ",
        ";",
        true,
    );
}

#[test]
fn snowflake_alter_table_set_tag_names() {
    reads_tag_lists("ALTER TABLE crm.orders SET TAG ", ";", true);
}

#[test]
fn snowflake_alter_table_unset_tag_names() {
    reads_tag_lists("ALTER TABLE crm.orders UNSET TAG ", ";", false);
}

#[test]
fn snowflake_alter_table_alter_column_set_tag_names() {
    reads_tag_lists(
        "ALTER TABLE crm.customers ALTER COLUMN email SET TAG ",
        ";",
        true,
    );
}

#[test]
fn snowflake_alter_table_modify_column_unset_tag_names() {
    reads_tag_lists(
        "ALTER TABLE crm.customers MODIFY COLUMN email UNSET TAG ",
        ";",
        false,
    );
}

#[test]
fn snowflake_alter_view_set_tag_names() {
    reads_tag_lists("ALTER VIEW crm.v_customers SET TAG ", ";", true);
}

#[test]
fn snowflake_alter_view_unset_tag_names() {
    reads_tag_lists("ALTER VIEW crm.v_customers UNSET TAG ", ";", false);
}

#[test]
fn snowflake_alter_stage_set_tag_names() {
    reads_tag_lists("ALTER STAGE stg_raw SET TAG ", ";", true);
}

#[test]
fn snowflake_alter_stage_unset_tag_names() {
    reads_tag_lists("ALTER STAGE stg_raw UNSET TAG ", ";", false);
}

#[test]
fn snowflake_alter_storage_integration_set_tag_names() {
    reads_tag_lists("ALTER STORAGE INTEGRATION s3_int SET TAG ", ";", true);
}

#[test]
fn snowflake_alter_schema_set_tag_names() {
    reads_tag_lists("ALTER SCHEMA analytics.crm SET TAG ", ";", true);
}

#[test]
fn snowflake_alter_database_set_tag_names() {
    reads_tag_lists("ALTER DATABASE analytics SET TAG ", ";", true);
}

#[test]
fn snowflake_alter_warehouse_set_tag_names() {
    reads_tag_lists("ALTER WAREHOUSE wh_etl SET TAG ", ";", true);
}

#[test]
fn snowflake_alter_stream_set_tag_names() {
    reads_tag_lists("ALTER STREAM crm.s_orders SET TAG ", ";", true);
}

#[test]
fn snowflake_alter_pipe_set_tag_names() {
    reads_tag_lists("ALTER PIPE crm.p_ingest SET TAG ", ";", true);
}

#[test]
fn snowflake_alter_join_policy_set_tag_names() {
    reads_tag_lists("ALTER JOIN POLICY jp SET TAG ", ";", true);
}

#[test]
fn snowflake_alter_join_policy_unset_tag_names() {
    reads_tag_lists("ALTER JOIN POLICY jp UNSET TAG ", ";", false);
}

#[test]
fn snowflake_create_table_with_tag_names() {
    reads_tag_lists("CREATE TABLE crm.orders (id INT) WITH TAG (", ");", true);
}

#[test]
fn snowflake_create_table_column_with_tag_names() {
    reads_tag_lists(
        "CREATE TABLE crm.customers (id INT, email STRING WITH TAG (",
        "));",
        true,
    );
}

#[test]
fn snowflake_create_view_with_tag_names() {
    reads_tag_lists(
        "CREATE VIEW crm.v_customers WITH TAG (",
        ") AS SELECT id FROM crm.customers;",
        true,
    );
}

#[test]
fn snowflake_alter_table_column_tag_actions_are_typed() {
    let script = parse_sql_with_dialect(
        "ALTER TABLE crm.customers ALTER COLUMN email SET TAG t = 'v';\n\
         ALTER TABLE crm.customers MODIFY COLUMN email UNSET TAG t;",
        &*dialect::snowflake(),
    )
    .expect("parses");
    let kinds: Vec<&AstAlterTableActionKind> = script
        .stmts
        .iter()
        .map(|stmt| match stmt {
            AstStmt::AlterTable(table) => &table.actions[0].kind,
            other => panic!("not ALTER TABLE: {other:?}"),
        })
        .collect();
    assert!(matches!(
        kinds[0],
        AstAlterTableActionKind::SetColumnTag { .. }
    ));
    assert!(matches!(
        kinds[1],
        AstAlterTableActionKind::UnsetColumnTag { .. }
    ));
}

#[test]
fn snowflake_alter_statements_beside_the_tag_list_positions_keep_tag_names() {
    for (before, assigned) in [
        ("ALTER TASK crm.t_load SET TAG ", true),
        ("ALTER TASK crm.t_load UNSET TAG ", false),
        ("ALTER DYNAMIC TABLE crm.dt_orders SET TAG ", true),
        ("ALTER DYNAMIC TABLE crm.dt_orders UNSET TAG ", false),
        (
            "ALTER DYNAMIC TABLE crm.dt_orders ALTER COLUMN email SET TAG ",
            true,
        ),
        (
            "ALTER DYNAMIC TABLE crm.dt_orders ALTER COLUMN email UNSET TAG ",
            false,
        ),
        ("ALTER FUNCTION crm.f_hash(STRING) SET TAG ", true),
        ("ALTER FUNCTION crm.f_hash(STRING) UNSET TAG ", false),
        ("ALTER PROCEDURE crm.p_load() SET TAG ", true),
        ("ALTER PROCEDURE crm.p_load() UNSET TAG ", false),
        ("ALTER MASKING POLICY gov.pii.mask_email SET TAG ", true),
        ("ALTER MASKING POLICY gov.pii.mask_email UNSET TAG ", false),
        ("ALTER NETWORK POLICY np_corp SET TAG ", true),
        ("ALTER NETWORK POLICY np_corp UNSET TAG ", false),
        ("ALTER SESSION POLICY sp_corp SET TAG ", true),
        ("ALTER SESSION POLICY sp_corp UNSET TAG ", false),
        ("ALTER API INTEGRATION api_int SET TAG ", true),
        ("ALTER API INTEGRATION api_int UNSET TAG ", false),
        ("ALTER NOTIFICATION INTEGRATION ni_int SET TAG ", true),
        ("ALTER NOTIFICATION INTEGRATION ni_int UNSET TAG ", false),
        ("ALTER PASSWORD POLICY pp_corp SET TAG ", true),
        ("ALTER PASSWORD POLICY pp_corp UNSET TAG ", false),
        ("ALTER AGGREGATION POLICY ap_corp SET TAG ", true),
        ("ALTER AGGREGATION POLICY ap_corp UNSET TAG ", false),
        ("ALTER PROJECTION POLICY pr_corp SET TAG ", true),
        ("ALTER PROJECTION POLICY pr_corp UNSET TAG ", false),
        ("ALTER EXTERNAL ACCESS INTEGRATION eai_ext SET TAG ", true),
        (
            "ALTER EXTERNAL ACCESS INTEGRATION eai_ext UNSET TAG ",
            false,
        ),
    ] {
        reads_tag_lists(before, ";", assigned);
    }
}

#[test]
fn snowflake_create_statements_beside_the_tag_list_positions_keep_tag_names() {
    for (before, after) in [
        ("CREATE TASK crm.t_load WITH TAG (", ") AS SELECT 1;"),
        ("CREATE TASK crm.t_load TAG (", ") AS SELECT 1;"),
        (
            "CREATE DYNAMIC TABLE crm.dt_orders TARGET_LAG = '1 hour' WAREHOUSE = wh_etl WITH TAG (",
            ") AS SELECT id FROM crm.orders;",
        ),
        ("CREATE WAREHOUSE wh_etl TAG (", ");"),
        ("CREATE SCHEMA analytics.crm WITH TAG (", ");"),
        ("CREATE DATABASE analytics WITH TAG (", ");"),
        (
            "CREATE VIEW crm.v_customers (id, email WITH TAG (",
            ")) AS SELECT id, email FROM crm.customers;",
        ),
    ] {
        reads_tag_lists(before, after, true);
    }
}

#[test]
fn a_tag_value_runs_to_the_next_tag_or_the_end() {
    // A value is whatever is written up to the next `,` or the end: a
    // signed number, a bind, an expression; each name is still kept.
    let sf = dialect::snowflake();
    reads_whole(
        &sf,
        &[
            "ALTER TABLE t SET TAG «gov.tags.level» = -1;",
            "ALTER TABLE t SET TAG «gov.tags.level» = :v;",
            "ALTER TABLE t SET TAG «a» = 'x' || 'y', b = 'z';",
            "ALTER TABLE t SET TAG a = 'x' || 'y', «b» = 'z';",
            "ALTER TABLE t SET TAG «a» = {{ var('x', 'y') }};",
            "CREATE TABLE t (id INT) WITH TAG («a» = CONCAT('x', 'y'), b = 'z');",
        ],
    );
}

// ---------------------------------------------------------------------------
// Policies named in a CREATE / ALTER clause: the statement keeps the policy's
// name as an object name, and the columns of the list written after it.
// ---------------------------------------------------------------------------

/// The ways a policy's name is written.
const POLICY_NAMES: [&str; 6] = [
    "rap_region",
    "s1.rap_region",
    "d1.s1.rap_region",
    "\"D1\".\"S 1\".\"RAP X\"",
    "IDENTIFIER('d1.s1.rap_region')",
    "gov.comment.rap_region",
];

/// The policy a statement keeps.
type PolicyOf = for<'a> fn(&'a AstStmt) -> Option<&'a AstObjectRef>;

fn create_table(stmt: &AstStmt) -> &AstCreateTable {
    match stmt {
        AstStmt::CreateTable(table) => table,
        other => panic!("not CREATE TABLE: {other:?}"),
    }
}

fn create_view(stmt: &AstStmt) -> &AstCreateView {
    match stmt {
        AstStmt::CreateView(view) => view,
        other => panic!("not CREATE VIEW: {other:?}"),
    }
}

fn alter_view_action(stmt: &AstStmt) -> &AstAlterViewActionKind {
    match stmt {
        AstStmt::AlterView(view) => &view.action.kind,
        other => panic!("not ALTER VIEW: {other:?}"),
    }
}

fn one_statement(sql: &str, dialect: &DialectRef) -> AstStmt {
    let script = parse_sql_with_dialect(sql, &**dialect).unwrap_or_else(|e| panic!("{sql}: {e:?}"));
    let [stmt] = <[AstStmt; 1]>::try_from(script.stmts)
        .unwrap_or_else(|stmts| panic!("{sql}: expected one statement, got {stmts:?}"));
    stmt
}

fn at(sql: &str, span: Span) -> &str {
    &sql[span.start as usize..span.end as usize]
}

fn texts<'a>(sql: &'a str, spans: &[Span]) -> Vec<&'a str> {
    spans.iter().map(|&span| at(sql, span)).collect()
}

/// `sql` formatted under `dialect` loses no token.
fn formats_without_loss(sql: &str, dialect: &DialectRef) {
    let config = FormatterConfig {
        dialect: dialect.clone(),
        ..FormatterConfig::default()
    };
    let formatted = format_sql_with_config(sql, &config).unwrap_or_else(|e| panic!("{sql}: {e:?}"));
    verify_formatting_safe_with_dialect(sql, &formatted, config.dialect.as_ref())
        .unwrap_or_else(|e| panic!("{sql}: {e}"));
}

/// The ways a Databricks policy or function name is written.
const DATABRICKS_POLICY_NAMES: [&str; 5] = [
    "rf_region",
    "s1.rf_region",
    "d1.s1.rf_region",
    "`D1`.`S 1`.`RF X`",
    "d1.stage.rf_region",
];

/// Each of `POLICY_NAMES` written where `template` has `@@`: `pick` finds
/// the policy the statement keeps, whose span is the name as written, and
/// the statement is formatted without losing a token.
fn reads_policy_names(dialect: &DialectRef, template: &str, pick: PolicyOf) {
    reads_names_in(dialect, &POLICY_NAMES, template, pick, true);
}

/// [`reads_policy_names`] for a form the formatter does not yet keep whole:
/// the name is kept, the output is not checked.
fn reads_policy_names_beside_formatter_gap(dialect: &DialectRef, template: &str, pick: PolicyOf) {
    reads_names_in(dialect, &POLICY_NAMES, template, pick, false);
}

fn reads_names_in(
    dialect: &DialectRef,
    names: &[&str],
    template: &str,
    pick: PolicyOf,
    formatted: bool,
) {
    for name in names {
        let sql = template.replace("@@", name);
        let stmt = one_statement(&sql, dialect);
        let policy = pick(&stmt).unwrap_or_else(|| panic!("{sql}: no policy kept: {stmt:?}"));
        assert_eq!(at(&sql, policy.span), *name, "{sql}");
        if formatted {
            formats_without_loss(&sql, dialect);
        }
    }
}

fn column_masking_policy(stmt: &AstStmt) -> Option<&AstObjectRef> {
    create_table(stmt)
        .columns
        .iter()
        .find_map(|column| column.masking_policy.as_ref())
}

#[test]
fn snowflake_create_table_column_masking_policy_name() {
    let sf = dialect::snowflake();
    for template in [
        "CREATE TABLE crm.customers (id INT, email STRING WITH MASKING POLICY @@);",
        "CREATE TABLE crm.customers (id INT, email STRING MASKING POLICY @@);",
        "CREATE TABLE crm.customers (id INT, region STRING, email STRING WITH MASKING POLICY @@ USING (email, region));",
    ] {
        reads_policy_names(&sf, template, column_masking_policy);
    }
    reads_policy_names_beside_formatter_gap(
        &sf,
        "CREATE TABLE crm.customers (id INT, email STRING WITH MASKING POLICY @@ NOT NULL COMMENT 'x');",
        column_masking_policy,
    );
}

#[test]
fn snowflake_create_table_column_masking_policy_using_columns() {
    let sf = dialect::snowflake();
    for sql in [
        "CREATE TABLE crm.customers (id INT, region STRING, email STRING WITH MASKING POLICY mask_email USING (email, region));",
        "CREATE TABLE crm.customers (id INT, region STRING, email STRING MASKING POLICY mask_email USING (email, region) COMMENT 'x');",
        "CREATE TABLE crm.customers (id INT, region STRING, email STRING MASKING POLICY mask_email USING (email, region) NOT NULL);",
    ] {
        let stmt = one_statement(sql, &sf);
        let column = create_table(&stmt)
            .columns
            .iter()
            .find(|column| column.masking_policy.is_some())
            .unwrap_or_else(|| panic!("{sql}: no masking policy"));
        assert_eq!(texts(sql, &column.masking_policy_using), ["email", "region"]);
    }
}

#[test]
fn snowflake_create_table_column_projection_policy_name() {
    let sf = dialect::snowflake();
    let pick: PolicyOf = |stmt| {
        create_table(stmt)
            .columns
            .iter()
            .find_map(|column| column.projection_policy.as_ref())
    };
    for template in [
        "CREATE TABLE crm.customers (id INT, ssn STRING WITH PROJECTION POLICY @@);",
        "CREATE TABLE crm.customers (id INT, ssn STRING PROJECTION POLICY @@);",
    ] {
        reads_policy_names(&sf, template, pick);
    }
    reads_policy_names_beside_formatter_gap(
        &sf,
        "CREATE TABLE crm.customers (id INT, ssn STRING NOT NULL PROJECTION POLICY @@);",
        pick,
    );
}

#[test]
fn snowflake_create_table_row_access_policy_name() {
    let sf = dialect::snowflake();
    for template in [
        "CREATE TABLE crm.customers (id INT, region STRING) WITH ROW ACCESS POLICY @@ ON (region);",
        "CREATE TABLE crm.customers (id INT, region STRING) ROW ACCESS POLICY @@ ON (region);",
        "CREATE TABLE crm.customers (id INT, region STRING) WITH ROW ACCESS POLICY @@ ON (region) COMMENT = 'x';",
        "CREATE TABLE crm.customers (id INT, region STRING) ROW ACCESS POLICY @@ ON (region, id) DATA_RETENTION_TIME_IN_DAYS = 1;",
    ] {
        reads_policy_names(&sf, template, |stmt| {
            create_table(stmt).row_access_policy.as_ref()
        });
    }
    let sql = "CREATE TABLE crm.customers (id INT, region STRING) WITH ROW ACCESS POLICY p ON (region, id) COMMENT = 'x';";
    let stmt = one_statement(sql, &sf);
    assert_eq!(
        texts(sql, &create_table(&stmt).row_access_policy_columns),
        ["region", "id"]
    );
}

#[test]
fn snowflake_create_table_aggregation_policy_name() {
    let sf = dialect::snowflake();
    for template in [
        "CREATE TABLE crm.orders (id INT, customer_id INT) WITH AGGREGATION POLICY @@;",
        "CREATE TABLE crm.orders (id INT, customer_id INT) AGGREGATION POLICY @@ COMMENT = 'x';",
    ] {
        reads_policy_names(&sf, template, |stmt| {
            create_table(stmt).aggregation_policy.as_ref()
        });
    }
}

#[test]
fn snowflake_create_table_join_policy_name() {
    let sf = dialect::snowflake();
    for template in [
        "CREATE TABLE crm.orders (id INT, customer_id INT) WITH JOIN POLICY @@;",
        "CREATE TABLE crm.orders (id INT, customer_id INT) JOIN POLICY @@ COMMENT = 'x';",
    ] {
        reads_policy_names(&sf, template, |stmt| {
            create_table(stmt).join_policy.as_ref()
        });
    }
}

#[test]
fn a_with_written_before_a_create_table_clause_belongs_to_that_clause() {
    let sf = dialect::snowflake();
    let sql = "CREATE TABLE t (id INT) WITH ROW ACCESS POLICY p ON (id) COMMENT = 'x';";
    let stmt = one_statement(sql, &sf);
    let table = create_table(&stmt);
    assert_eq!(
        at(sql, table.with_row_access_policy_span.expect("clause span")),
        "WITH ROW ACCESS POLICY p ON (id)"
    );
    assert_eq!(table.row_access_policy_span, None);
    assert_eq!(table.with_contact_span, None);
    assert_eq!(table.tag_span, None);

    for (sql, clause) in [
        (
            "CREATE TABLE t (id INT) WITH AGGREGATION POLICY p COMMENT = 'x';",
            "WITH AGGREGATION POLICY p",
        ),
        (
            "CREATE TABLE t (id INT) WITH JOIN POLICY p COMMENT = 'x';",
            "WITH JOIN POLICY p",
        ),
    ] {
        let stmt = one_statement(sql, &sf);
        let table = create_table(&stmt);
        let span = table.aggregation_policy_span.or(table.join_policy_span);
        assert_eq!(at(sql, span.expect("clause span")), clause, "{sql}");
        assert_eq!(table.with_contact_span, None, "{sql}");
        assert_eq!(table.tag_span, None, "{sql}");
        assert_eq!(table.with_row_access_policy_span, None, "{sql}");
    }

    // A `WITH` that introduces another option is that option's.
    let sql = "CREATE TABLE t (id INT) WITH CONTACT = 'me' WITH ROW ACCESS POLICY p ON (id);";
    let stmt = one_statement(sql, &sf);
    let table = create_table(&stmt);
    assert_eq!(
        at(sql, table.with_contact_span.expect("contact span")),
        "WITH CONTACT = 'me'"
    );
    assert_eq!(
        at(sql, table.with_row_access_policy_span.expect("clause span")),
        "WITH ROW ACCESS POLICY p ON (id)"
    );
    formats_without_loss(sql, &sf);
}

#[test]
fn snowflake_create_view_column_masking_policy_name() {
    let sf = dialect::snowflake();
    for template in [
        "CREATE VIEW crm.v_customers (id, email WITH MASKING POLICY @@) AS SELECT id, email FROM crm.customers;",
        "CREATE VIEW crm.v_customers (id, email MASKING POLICY @@ COMMENT 'x') AS SELECT id, email FROM crm.customers;",
        "CREATE VIEW crm.v_customers (id, region, email WITH MASKING POLICY @@ USING (email, region)) AS SELECT id, region, email FROM crm.customers;",
    ] {
        // A view column's policy name is formatted as one token.
        reads_policy_names_beside_formatter_gap(&sf, template, |stmt| {
            create_view(stmt)
                .columns
                .iter()
                .find_map(|column| column.masking_policy.as_ref())
        });
    }
    let sql = "CREATE VIEW crm.v (region, email WITH MASKING POLICY m USING (email, region)) AS SELECT region, email FROM crm.c;";
    let stmt = one_statement(sql, &sf);
    assert_eq!(
        texts(sql, &create_view(&stmt).columns[1].masking_policy_using),
        ["email", "region"]
    );
}

#[test]
fn snowflake_create_view_column_projection_policy_name() {
    let sf = dialect::snowflake();
    for template in [
        "CREATE VIEW crm.v_customers (id, ssn WITH PROJECTION POLICY @@) AS SELECT id, ssn FROM crm.customers;",
        "CREATE VIEW crm.v_customers (id, ssn PROJECTION POLICY @@ COMMENT 'x') AS SELECT id, ssn FROM crm.customers;",
    ] {
        reads_policy_names_beside_formatter_gap(&sf, template, |stmt| {
            create_view(stmt)
                .columns
                .iter()
                .find_map(|column| column.projection_policy.as_ref())
        });
    }
}

#[test]
fn snowflake_create_view_row_access_policy_name() {
    let sf = dialect::snowflake();
    for template in [
        "CREATE VIEW crm.v_customers WITH ROW ACCESS POLICY @@ ON (region) AS SELECT id, region FROM crm.customers;",
        "CREATE VIEW crm.v_customers ROW ACCESS POLICY @@ ON (region) COMMENT = 'x' AS SELECT id, region FROM crm.customers;",
    ] {
        reads_policy_names(&sf, template, |stmt| {
            create_view(stmt).row_access_policy.as_ref()
        });
    }
    let sql = "CREATE VIEW crm.v WITH ROW ACCESS POLICY p ON (region, id) AS SELECT id, region FROM crm.c;";
    let stmt = one_statement(sql, &sf);
    assert_eq!(
        texts(sql, &create_view(&stmt).row_access_policy_columns),
        ["region", "id"]
    );
}

#[test]
fn snowflake_create_view_aggregation_and_join_policy_names() {
    let sf = dialect::snowflake();
    // The formatter does not write the `WITH` of a view's policy clause.
    reads_policy_names_beside_formatter_gap(
        &sf,
        "CREATE VIEW crm.v_orders WITH AGGREGATION POLICY @@ AS SELECT id FROM crm.orders;",
        |stmt| create_view(stmt).aggregation_policy.as_ref(),
    );
    reads_policy_names_beside_formatter_gap(
        &sf,
        "CREATE VIEW crm.v_orders WITH JOIN POLICY @@ AS SELECT id FROM crm.orders;",
        |stmt| create_view(stmt).join_policy.as_ref(),
    );
}

#[test]
fn snowflake_alter_view_add_row_access_policy_name() {
    let sf = dialect::snowflake();
    for template in [
        "ALTER VIEW crm.v_customers ADD ROW ACCESS POLICY @@ ON (region);",
        "ALTER VIEW crm.v_customers ADD ROW ACCESS POLICY @@ ON (region, id), DROP ROW ACCESS POLICY old_rap;",
    ] {
        reads_policy_names(&sf, template, |stmt| match alter_view_action(stmt) {
            AstAlterViewActionKind::AddRowAccessPolicy { policy, .. } => policy.as_ref(),
            other => panic!("not ADD ROW ACCESS POLICY: {other:?}"),
        });
    }
    let sql = "ALTER VIEW crm.v ADD ROW ACCESS POLICY p ON (region, id);";
    let stmt = one_statement(sql, &sf);
    let AstAlterViewActionKind::AddRowAccessPolicy { columns, .. } = alter_view_action(&stmt)
    else {
        panic!("{sql}: not ADD ROW ACCESS POLICY");
    };
    assert_eq!(texts(sql, columns), ["region", "id"]);
}

#[test]
fn snowflake_alter_view_drop_row_access_policy_name() {
    let sf = dialect::snowflake();
    reads_policy_names(
        &sf,
        "ALTER VIEW crm.v_customers DROP ROW ACCESS POLICY @@;",
        |stmt| match alter_view_action(stmt) {
            AstAlterViewActionKind::DropRowAccessPolicy { policy, .. } => policy.as_ref(),
            other => panic!("not DROP ROW ACCESS POLICY: {other:?}"),
        },
    );
}

#[test]
fn snowflake_alter_view_alter_column_policy_names() {
    let sf = dialect::snowflake();
    for template in [
        "ALTER VIEW crm.v_customers ALTER COLUMN email SET MASKING POLICY @@;",
        "ALTER VIEW crm.v_customers MODIFY COLUMN email SET MASKING POLICY @@ USING (email, id) FORCE;",
    ] {
        reads_policy_names(&sf, template, |stmt| match alter_view_action(stmt) {
            AstAlterViewActionKind::AlterColumn { masking_policy, .. } => masking_policy.as_ref(),
            other => panic!("not ALTER COLUMN: {other:?}"),
        });
    }
    reads_policy_names(
        &sf,
        "ALTER VIEW crm.v_customers ALTER COLUMN ssn SET PROJECTION POLICY @@;",
        |stmt| match alter_view_action(stmt) {
            AstAlterViewActionKind::AlterColumn {
                projection_policy, ..
            } => projection_policy.as_ref(),
            other => panic!("not ALTER COLUMN: {other:?}"),
        },
    );

    let sql = "ALTER VIEW crm.v ALTER COLUMN email SET MASKING POLICY m USING (email, id) FORCE;";
    let stmt = one_statement(sql, &sf);
    let AstAlterViewActionKind::AlterColumn {
        column,
        masking_policy_using,
        ..
    } = alter_view_action(&stmt)
    else {
        panic!("{sql}: not ALTER COLUMN");
    };
    assert_eq!(at(sql, column.expect("column")), "email");
    assert_eq!(texts(sql, masking_policy_using), ["email", "id"]);
}

#[test]
fn snowflake_alter_view_alter_column_unset_policies() {
    let sf = dialect::snowflake();
    for (sql, masking, projection) in [
        (
            "ALTER VIEW v ALTER COLUMN c UNSET MASKING POLICY;",
            true,
            false,
        ),
        (
            "ALTER VIEW v MODIFY COLUMN c UNSET PROJECTION POLICY;",
            false,
            true,
        ),
        ("ALTER VIEW v ALTER COLUMN c UNSET TAG t;", false, false),
    ] {
        let stmt = one_statement(sql, &sf);
        let AstAlterViewActionKind::AlterColumn { policy_unset, .. } = alter_view_action(&stmt)
        else {
            panic!("{sql}: not ALTER COLUMN");
        };
        match policy_unset {
            Some(AstColumnPolicyUnset::Masking { span }) => {
                assert!(masking, "{sql}");
                assert_eq!(at(sql, *span), "UNSET MASKING POLICY");
            }
            Some(AstColumnPolicyUnset::Projection { span }) => {
                assert!(projection, "{sql}");
                assert_eq!(at(sql, *span), "UNSET PROJECTION POLICY");
            }
            None => assert!(!masking && !projection, "{sql}"),
        }
    }
}

#[test]
fn snowflake_alter_view_alter_column_tag_names() {
    let sf = dialect::snowflake();
    for (sql, expected) in [
        (
            "ALTER VIEW crm.v ALTER COLUMN email SET TAG d1.s1.sensitivity = 'high', cost_center = 'a';",
            vec!["d1.s1.sensitivity", "cost_center"],
        ),
        (
            "ALTER VIEW crm.v ALTER COLUMN email UNSET TAG d1.s1.sensitivity, cost_center;",
            vec!["d1.s1.sensitivity", "cost_center"],
        ),
    ] {
        let stmt = one_statement(sql, &sf);
        let AstAlterViewActionKind::AlterColumn { tags, .. } = alter_view_action(&stmt) else {
            panic!("{sql}: not ALTER COLUMN");
        };
        let names: Vec<&str> = tags.iter().map(|tag| at(sql, tag.name.span)).collect();
        assert_eq!(names, expected, "{sql}");
    }
}

#[test]
fn snowflake_create_dynamic_table_row_access_policy_name() {
    let sf = dialect::snowflake();
    let pick: PolicyOf = |stmt| match stmt {
        AstStmt::CreateDynamicTable(dt) => dt.row_access_policy.as_ref(),
        other => panic!("not CREATE DYNAMIC TABLE: {other:?}"),
    };
    reads_policy_names(
        &sf,
        "CREATE DYNAMIC TABLE crm.dt_orders (id INT, region STRING) TARGET_LAG = '1 hour' WAREHOUSE = wh_etl WITH ROW ACCESS POLICY @@ ON (region) AS SELECT id, region FROM crm.orders;",
        pick,
    );
    // The formatter writes a dynamic table's options in a fixed order.
    reads_policy_names_beside_formatter_gap(
        &sf,
        "CREATE DYNAMIC TABLE crm.dt_orders (id INT, region STRING) TARGET_LAG = '1 hour' WAREHOUSE = wh_etl ROW ACCESS POLICY @@ ON (region) COMMENT = 'x' AS SELECT id, region FROM crm.orders;",
        pick,
    );
    // The `WITH` is the clause's, not a tag clause of its own.
    let sql = "CREATE DYNAMIC TABLE dt TARGET_LAG = '1 hour' WAREHOUSE = wh WITH ROW ACCESS POLICY p ON (region, id) AS SELECT 1 AS c;";
    let AstStmt::CreateDynamicTable(dt) = one_statement(sql, &sf) else {
        panic!("{sql}: not CREATE DYNAMIC TABLE");
    };
    assert_eq!(
        at(sql, dt.row_access_policy_span.expect("clause span")),
        "WITH ROW ACCESS POLICY p ON (region, id)"
    );
    assert_eq!(texts(sql, &dt.row_access_policy_columns), ["region", "id"]);
    assert_eq!(dt.tag_span, None);
}

#[test]
fn snowflake_create_dynamic_table_aggregation_policy_name() {
    let sf = dialect::snowflake();
    let pick: PolicyOf = |stmt| match stmt {
        AstStmt::CreateDynamicTable(dt) => dt.aggregation_policy.as_ref(),
        other => panic!("not CREATE DYNAMIC TABLE: {other:?}"),
    };
    reads_policy_names(
        &sf,
        "CREATE DYNAMIC TABLE dt TARGET_LAG = '1 minute' WAREHOUSE = wh WITH AGGREGATION POLICY @@ AS SELECT 1 AS c;",
        pick,
    );
    // The formatter writes a dynamic table's options in a fixed order.
    reads_policy_names_beside_formatter_gap(
        &sf,
        "CREATE DYNAMIC TABLE dt TARGET_LAG = '1 minute' WAREHOUSE = wh AGGREGATION POLICY @@ COMMENT = 'x' AS SELECT 1 AS c;",
        pick,
    );
}

#[test]
fn snowflake_create_external_table_row_access_policy_name() {
    let sf = dialect::snowflake();
    for template in [
        "CREATE EXTERNAL TABLE ext_t WITH LOCATION = @s1.stg/path/ FILE_FORMAT = (TYPE = PARQUET) WITH ROW ACCESS POLICY @@ ON (VALUE);",
        "CREATE EXTERNAL TABLE ext_t WITH LOCATION = @s1.stg/path/ FILE_FORMAT = (TYPE = PARQUET) ROW ACCESS POLICY @@ ON (VALUE, other);",
    ] {
        reads_policy_names(&sf, template, |stmt| match stmt {
            AstStmt::CreateExternalTable(table) => table.row_access_policy.as_ref(),
            other => panic!("not CREATE EXTERNAL TABLE: {other:?}"),
        });
    }
    let sql = "CREATE EXTERNAL TABLE ext_t WITH LOCATION = @s1.stg/path/ FILE_FORMAT = (TYPE = PARQUET) WITH ROW ACCESS POLICY p ON (VALUE, other);";
    let AstStmt::CreateExternalTable(table) = one_statement(sql, &sf) else {
        panic!("{sql}: not CREATE EXTERNAL TABLE");
    };
    assert_eq!(
        texts(sql, &table.row_access_policy_columns),
        ["VALUE", "other"]
    );
}

#[test]
fn snowflake_alter_table_add_column_masking_policy_name_and_tags() {
    let sf = dialect::snowflake();
    for template in [
        "ALTER TABLE crm.customers ADD COLUMN email2 STRING WITH MASKING POLICY @@;",
        "ALTER TABLE crm.customers ADD COLUMN email2 STRING MASKING POLICY @@ USING (email2, id) NOT NULL;",
        "ALTER TABLE crm.customers ADD COLUMN email2 STRING WITH MASKING POLICY @@ WITH TAG (sensitivity = 'high');",
    ] {
        reads_policy_names(&sf, template, |stmt| match stmt {
            AstStmt::AlterTable(table) => match &table.actions[0].kind {
                AstAlterTableActionKind::AddColumn { columns, .. } => {
                    columns[0].masking_policy.as_ref()
                }
                other => panic!("not ADD COLUMN: {other:?}"),
            },
            other => panic!("not ALTER TABLE: {other:?}"),
        });
    }
    let sql = "ALTER TABLE crm.customers ADD COLUMN email2 STRING WITH MASKING POLICY m USING (email2, id) WITH TAG (d1.s1.sensitivity = 'high', cost_center = 'a');";
    let AstStmt::AlterTable(table) = one_statement(sql, &sf) else {
        panic!("{sql}: not ALTER TABLE");
    };
    let AstAlterTableActionKind::AddColumn { columns, .. } = &table.actions[0].kind else {
        panic!("{sql}: not ADD COLUMN");
    };
    assert_eq!(
        texts(sql, &columns[0].masking_policy_using),
        ["email2", "id"]
    );
    let names: Vec<&str> = columns[0]
        .tags
        .iter()
        .map(|tag| at(sql, tag.name.span))
        .collect();
    assert_eq!(names, ["d1.s1.sensitivity", "cost_center"]);
    formats_without_loss(sql, &sf);
}

#[test]
fn databricks_create_table_column_mask_function_name() {
    let dbx = dialect::databricks();
    for template in [
        "CREATE TABLE main.crm.customers (id INT, email STRING MASK @@);",
        "CREATE TABLE main.crm.customers (id INT, email STRING MASK @@ USING COLUMNS (id) COMMENT 'x');",
    ] {
        reads_names_in(
            &dbx,
            &DATABRICKS_POLICY_NAMES,
            template,
            column_masking_policy,
            true,
        );
    }
    // The formatter does not write a clause that follows another one.
    reads_names_in(
        &dbx,
        &DATABRICKS_POLICY_NAMES,
        "CREATE TABLE main.crm.customers (id INT, email STRING NOT NULL MASK @@);",
        column_masking_policy,
        false,
    );
    let sql = "CREATE TABLE main.crm.customers (id INT, region STRING, email STRING MASK f USING COLUMNS (id, region));";
    let stmt = one_statement(sql, &dbx);
    let column = create_table(&stmt)
        .columns
        .iter()
        .find(|column| column.masking_policy.is_some())
        .expect("masked column");
    assert_eq!(texts(sql, &column.masking_policy_using), ["id", "region"]);
}

#[test]
fn databricks_create_table_row_filter_function_name() {
    let dbx = dialect::databricks();
    for template in [
        "CREATE TABLE main.crm.customers (id INT, region STRING) WITH ROW FILTER @@ ON (region);",
        "CREATE TABLE main.crm.customers (id INT, region STRING) ROW FILTER @@ ON (region) COMMENT 'x';",
        "CREATE TABLE main.crm.customers (id INT, region STRING) WITH ROW FILTER @@ ON (region) TBLPROPERTIES ('a' = 'b');",
    ] {
        reads_names_in(
            &dbx,
            &DATABRICKS_POLICY_NAMES,
            template,
            |stmt| create_table(stmt).row_filter_function.as_ref(),
            true,
        );
    }
    let sql = "CREATE TABLE main.crm.customers (id INT, region STRING) WITH ROW FILTER rf ON (region, id);";
    let stmt = one_statement(sql, &dbx);
    assert_eq!(
        texts(sql, &create_table(&stmt).row_filter_columns),
        ["region", "id"]
    );
}

// ---------------------------------------------------------------------------
// Account and user policy attachments: the policy keeps its name as an object
// name.
// ---------------------------------------------------------------------------

fn alter_account_action(stmt: &AstStmt) -> &AstAlterAccountActionKind {
    match stmt {
        AstStmt::AlterAccount(account) => &account.action.kind,
        other => panic!("not ALTER ACCOUNT: {other:?}"),
    }
}

fn user_options(stmt: &AstStmt) -> &AstSnowflakeUserOptions {
    match stmt {
        AstStmt::AlterPrincipal(principal) => principal
            .options
            .snowflake_user
            .as_ref()
            .unwrap_or_else(|| panic!("no user options: {principal:?}")),
        other => panic!("not ALTER USER: {other:?}"),
    }
}

#[test]
fn snowflake_alter_account_set_policy_names() {
    let sf = dialect::snowflake();
    for (words, expected) in [
        ("PASSWORD", AstAccountPolicyKind::Password),
        ("SESSION", AstAccountPolicyKind::Session),
        ("PACKAGES", AstAccountPolicyKind::Packages),
    ] {
        for name in POLICY_NAMES {
            let sql = format!("ALTER ACCOUNT SET {words} POLICY {name};");
            let stmt = one_statement(&sql, &sf);
            let AstAlterAccountActionKind::SetPolicy { kind, policy } = alter_account_action(&stmt)
            else {
                panic!("{sql}: not SET POLICY: {stmt:?}");
            };
            assert_eq!(*kind, expected, "{sql}");
            assert_eq!(at(&sql, policy.span), name, "{sql}");
            formats_without_loss(&sql, &sf);
        }
    }
}

#[test]
fn snowflake_alter_account_set_policy_leaves_what_follows_it() {
    let sf = dialect::snowflake();
    let sql = "ALTER ACCOUNT SET SESSION POLICY s1.sess_std; SELECT 1;";
    let script = parse_sql_with_dialect(sql, &*sf).unwrap_or_else(|e| panic!("{sql}: {e:?}"));
    let [first, second] = script.stmts.as_slice() else {
        panic!("{sql}: {:?}", script.stmts);
    };
    assert!(matches!(
        alter_account_action(first),
        AstAlterAccountActionKind::SetPolicy { .. }
    ));
    assert!(matches!(second, AstStmt::Select(_)), "{second:?}");
    // Words after the name that are no part of the clause keep the property
    // reading.
    for sql in [
        "ALTER ACCOUNT SET PASSWORD POLICY pwp_std FORCE;",
        "ALTER ACCOUNT SET PASSWORD POLICY;",
    ] {
        let stmt = one_statement(sql, &sf);
        assert!(
            matches!(
                alter_account_action(&stmt),
                AstAlterAccountActionKind::Set { .. }
            ),
            "{sql}: {stmt:?}"
        );
    }
}

#[test]
fn snowflake_alter_user_set_policy_names() {
    let sf = dialect::snowflake();
    for name in POLICY_NAMES {
        let sql = format!("ALTER USER alice SET PASSWORD POLICY {name};");
        let stmt = one_statement(&sql, &sf);
        let options = user_options(&stmt);
        let policy = options
            .password_policy
            .as_ref()
            .unwrap_or_else(|| panic!("{sql}: no password policy: {options:?}"));
        assert_eq!(at(&sql, policy.span), name, "{sql}");
        assert!(options.session_policy.is_none(), "{sql}");
        formats_without_loss(&sql, &sf);

        let sql = format!("ALTER USER IF EXISTS alice SET SESSION POLICY {name};");
        let stmt = one_statement(&sql, &sf);
        let options = user_options(&stmt);
        let policy = options
            .session_policy
            .as_ref()
            .unwrap_or_else(|| panic!("{sql}: no session policy: {options:?}"));
        assert_eq!(at(&sql, policy.span), name, "{sql}");
        assert!(options.password_policy.is_none(), "{sql}");
        formats_without_loss(&sql, &sf);
    }
}

#[test]
fn snowflake_alter_user_password_assignment_is_no_policy() {
    let sf = dialect::snowflake();
    let stmt = one_statement(
        "ALTER USER alice SET PASSWORD = 'x' MUST_CHANGE_PASSWORD = TRUE;",
        &sf,
    );
    let options = user_options(&stmt);
    assert!(options.password_policy.is_none(), "{options:?}");
    assert!(options.session_policy.is_none(), "{options:?}");
}

// ---------------------------------------------------------------------------
// Parenthesised name lists: each name of the list is kept; `ALL`, `NONE` and
// an empty list name nothing.
// ---------------------------------------------------------------------------

/// The text of each name in `names`, as the statement spells them.
fn name_texts<'a>(sql: &'a str, names: &[AstObjectRef]) -> Vec<&'a str> {
    names.iter().map(|name| at(sql, name.span)).collect()
}

#[test]
fn snowflake_create_authentication_policy_security_integrations_names() {
    let sf = dialect::snowflake();
    for name in POLICY_NAMES {
        let sql = format!(
            "CREATE AUTHENTICATION POLICY gov.sec.auth_std SECURITY_INTEGRATIONS = ({name}, other_int) \
             COMMENT = 'x';"
        );
        let AstStmt::CreateAuthenticationPolicy(policy) = one_statement(&sql, &sf) else {
            panic!("{sql}: not CREATE AUTHENTICATION POLICY");
        };
        assert_eq!(
            name_texts(&sql, &policy.security_integrations),
            [name, "other_int"],
            "{sql}"
        );
        formats_without_loss(&sql, &sf);
    }
    for value in ["ALL", "NONE", "()", "(all)", "(none)"] {
        let sql = format!(
            "CREATE AUTHENTICATION POLICY gov.sec.auth_std SECURITY_INTEGRATIONS = {value};"
        );
        let AstStmt::CreateAuthenticationPolicy(policy) = one_statement(&sql, &sf) else {
            panic!("{sql}: not CREATE AUTHENTICATION POLICY");
        };
        assert!(policy.security_integrations.is_empty(), "{sql}");
        assert!(policy.security_integrations_span.is_some(), "{sql}");
    }
}

#[test]
fn snowflake_alter_authentication_policy_set_security_integrations_names() {
    let sf = dialect::snowflake();
    for name in POLICY_NAMES {
        let sql = format!(
            "ALTER AUTHENTICATION POLICY gov.sec.auth_std SET SECURITY_INTEGRATIONS = ({name}, other_int);"
        );
        let AstStmt::AlterAuthenticationPolicy(policy) = one_statement(&sql, &sf) else {
            panic!("{sql}: not ALTER AUTHENTICATION POLICY");
        };
        let AstAlterAuthenticationPolicyActionKind::SetSecurityIntegrations {
            integrations, ..
        } = &policy.action.kind
        else {
            panic!("{sql}: not SET SECURITY_INTEGRATIONS");
        };
        assert_eq!(name_texts(&sql, integrations), [name, "other_int"], "{sql}");
        formats_without_loss(&sql, &sf);
    }
    let sql = "ALTER AUTHENTICATION POLICY gov.sec.auth_std SET SECURITY_INTEGRATIONS = ALL;";
    let AstStmt::AlterAuthenticationPolicy(policy) = one_statement(sql, &sf) else {
        panic!("{sql}: not ALTER AUTHENTICATION POLICY");
    };
    let AstAlterAuthenticationPolicyActionKind::SetSecurityIntegrations { integrations, .. } =
        &policy.action.kind
    else {
        panic!("{sql}: not SET SECURITY_INTEGRATIONS");
    };
    assert!(integrations.is_empty());
}

#[test]
fn snowflake_create_external_access_integration_name_lists() {
    let sf = dialect::snowflake();
    for name in POLICY_NAMES {
        let sql = format!(
            "CREATE EXTERNAL ACCESS INTEGRATION eai_ext ALLOWED_NETWORK_RULES = ({name}, rule_b) \
             ALLOWED_API_AUTHENTICATION_INTEGRATIONS = ({name}) \
             ALLOWED_AUTHENTICATION_SECRETS = ({name}, sec_b) ENABLED = TRUE;"
        );
        let AstStmt::CreateExternalAccessIntegration(eai) = one_statement(&sql, &sf) else {
            panic!("{sql}: not CREATE EXTERNAL ACCESS INTEGRATION");
        };
        assert_eq!(
            name_texts(&sql, &eai.allowed_network_rules),
            [name, "rule_b"],
            "{sql}"
        );
        assert_eq!(
            name_texts(&sql, &eai.allowed_api_authentication_integrations),
            [name],
            "{sql}"
        );
        assert_eq!(
            name_texts(&sql, &eai.allowed_authentication_secrets),
            [name, "sec_b"],
            "{sql}"
        );
        formats_without_loss(&sql, &sf);
    }
    for value in ["()", "(all)", "(none)"] {
        let sql = format!(
            "CREATE EXTERNAL ACCESS INTEGRATION eai_ext ALLOWED_NETWORK_RULES = (r) \
             ALLOWED_API_AUTHENTICATION_INTEGRATIONS = {value} \
             ALLOWED_AUTHENTICATION_SECRETS = {value} ENABLED = TRUE;"
        );
        let AstStmt::CreateExternalAccessIntegration(eai) = one_statement(&sql, &sf) else {
            panic!("{sql}: not CREATE EXTERNAL ACCESS INTEGRATION");
        };
        assert!(
            eai.allowed_api_authentication_integrations.is_empty(),
            "{sql}"
        );
        assert!(eai.allowed_authentication_secrets.is_empty(), "{sql}");
        assert!(eai.allowed_authentication_secrets_span.is_some(), "{sql}");
    }
}

#[test]
fn snowflake_alter_external_access_integration_set_name_lists() {
    let sf = dialect::snowflake();
    for name in POLICY_NAMES {
        for (property, other) in [
            ("ALLOWED_NETWORK_RULES", "rule_b"),
            ("ALLOWED_API_AUTHENTICATION_INTEGRATIONS", "int_b"),
            ("ALLOWED_AUTHENTICATION_SECRETS", "sec_b"),
        ] {
            let sql = format!(
                "ALTER EXTERNAL ACCESS INTEGRATION eai_ext SET {property} = ({name}, {other});"
            );
            let AstStmt::AlterExternalAccessIntegration(eai) = one_statement(&sql, &sf) else {
                panic!("{sql}: not ALTER EXTERNAL ACCESS INTEGRATION");
            };
            let listed = match &eai.actions[0].kind {
                AstAlterExternalAccessIntegrationActionKind::SetAllowedNetworkRules {
                    rules,
                    ..
                } => rules,
                AstAlterExternalAccessIntegrationActionKind::SetAllowedApiAuthenticationIntegrations {
                    integrations,
                    ..
                } => integrations,
                AstAlterExternalAccessIntegrationActionKind::SetAllowedAuthenticationSecrets {
                    secrets,
                    ..
                } => secrets,
                other => panic!("{sql}: not a name list: {other:?}"),
            };
            assert_eq!(name_texts(&sql, listed), [name, other], "{sql}");
            formats_without_loss(&sql, &sf);
        }
    }
    let sql =
        "ALTER EXTERNAL ACCESS INTEGRATION eai_ext SET ALLOWED_AUTHENTICATION_SECRETS = (all);";
    let AstStmt::AlterExternalAccessIntegration(eai) = one_statement(sql, &sf) else {
        panic!("{sql}: not ALTER EXTERNAL ACCESS INTEGRATION");
    };
    let AstAlterExternalAccessIntegrationActionKind::SetAllowedAuthenticationSecrets {
        secrets,
        ..
    } = &eai.actions[0].kind
    else {
        panic!("{sql}: not SET ALLOWED_AUTHENTICATION_SECRETS");
    };
    assert!(secrets.is_empty());
}

/// The ways a stage's name is written.
const STAGE_NAMES: [&str; 7] = [
    "stg_raw",
    "s1.stg_raw",
    "d1.s1.stg_raw",
    "\"D1\".\"S 1\".\"STG X\"",
    "IDENTIFIER('d1.s1.stg_raw')",
    "d1.stage.stg_raw",
    "{{ target.schema }}.stg_raw",
];

/// The ways a file format's name is written.
const FORMAT_NAMES: [&str; 7] = [
    "ff_csv",
    "s1.ff_csv",
    "d1.s1.ff_csv",
    "\"D1\".\"S 1\".\"FF X\"",
    "IDENTIFIER('d1.s1.ff_csv')",
    "d1.stage.ff_csv",
    "{{ target.schema }}.ff_csv",
];

/// `stage` names `name`, the path `path` written against it (or none).
fn assert_stage(sql: &str, stage: Option<&AstStageRef>, name: &str, path: Option<&str>) {
    let stage = stage.unwrap_or_else(|| panic!("{sql}: no stage"));
    assert_eq!(at(sql, stage.name.span), name, "{sql}");
    assert_eq!(stage.name.name_kind, AstTableNameKind::Stage, "{sql}");
    assert_eq!(stage.path.map(|span| at(sql, span)), path, "{sql}");
}

fn copy_into_table(sql: &str, dialect: &DialectRef) -> (Option<AstStageRef>, Option<AstObjectRef>) {
    match one_statement(sql, dialect) {
        AstStmt::CopyIntoTable {
            from_stage,
            file_format_name,
            ..
        } => (
            from_stage.map(|stage| *stage),
            file_format_name.map(|name| *name),
        ),
        other => panic!("{sql}: not COPY INTO <table>: {other:?}"),
    }
}

fn copy_into_location(
    sql: &str,
    dialect: &DialectRef,
) -> (Option<AstStageRef>, Option<AstObjectRef>) {
    match one_statement(sql, dialect) {
        AstStmt::CopyIntoLocation {
            into_stage,
            file_format_name,
            ..
        } => (
            into_stage.map(|stage| *stage),
            file_format_name.map(|name| *name),
        ),
        other => panic!("{sql}: not COPY INTO <location>: {other:?}"),
    }
}

#[test]
fn snowflake_copy_into_table_from_stage_name() {
    let sf = dialect::snowflake();
    for name in STAGE_NAMES {
        for (written, path) in [("", None), ("/2026/a.csv", Some("/2026/a.csv"))] {
            let sql = format!(
                "COPY INTO crm.orders FROM @{name}{written} FILE_FORMAT = (TYPE = CSV) \
                 ON_ERROR = CONTINUE;"
            );
            let (stage, format) = copy_into_table(&sql, &sf);
            assert_stage(&sql, stage.as_ref(), name, path);
            assert!(format.is_none(), "{sql}");
            formats_without_loss(&sql, &sf);
        }
    }
    // A stage followed by a statement, a user stage, a table stage, a
    // query and an external location.
    let sql = "COPY INTO crm.orders FROM @stg_raw/p; SELECT 1;";
    let script = parse_sql_with_dialect(sql, &*sf).expect("parses");
    assert_eq!(script.stmts.len(), 2);
    let AstStmt::CopyIntoTable { from_stage, .. } = &script.stmts[0] else {
        panic!("{sql}: not COPY INTO <table>");
    };
    assert_stage(sql, from_stage.as_deref(), "stg_raw", Some("/p"));
    for sql in [
        "COPY INTO crm.orders FROM @~/p FILE_FORMAT = (TYPE = CSV);",
        "COPY INTO crm.orders FROM @%orders;",
        "COPY INTO crm.orders FROM (SELECT $1 FROM @stg_raw/p);",
        "COPY INTO crm.orders FROM 's3://bucket/raw/' CREDENTIALS = (AWS_KEY_ID = 'k');",
    ] {
        let (stage, _) = copy_into_table(sql, &sf);
        assert!(stage.is_none(), "{sql}");
        formats_without_loss(sql, &sf);
    }
}

#[test]
fn snowflake_copy_into_location_stage_name() {
    let sf = dialect::snowflake();
    for name in STAGE_NAMES {
        for (written, path) in [("", None), ("/out/", Some("/out/"))] {
            let sql =
                format!("COPY INTO @{name}{written} FROM crm.orders FILE_FORMAT = (TYPE = CSV);");
            let (stage, format) = copy_into_location(&sql, &sf);
            assert_stage(&sql, stage.as_ref(), name, path);
            assert!(format.is_none(), "{sql}");
            formats_without_loss(&sql, &sf);
        }
    }
    for sql in [
        "COPY INTO @~/out FROM crm.orders;",
        "COPY INTO @%orders FROM crm.orders;",
        "COPY INTO 's3://bucket/out/' FROM crm.orders STORAGE_INTEGRATION = s3_int;",
    ] {
        let (stage, _) = copy_into_location(sql, &sf);
        assert!(stage.is_none(), "{sql}");
        formats_without_loss(sql, &sf);
    }
}

#[test]
fn snowflake_copy_into_file_format_name() {
    let sf = dialect::snowflake();
    for name in FORMAT_NAMES {
        for tail in ["", " TYPE = CSV", " ON_ERROR = CONTINUE PURGE = TRUE"] {
            let load = format!(
                "COPY INTO crm.orders FROM @stg_raw FILE_FORMAT = (FORMAT_NAME = {name}{tail}) \
                 ON_ERROR = CONTINUE;"
            );
            let (_, format) = copy_into_table(&load, &sf);
            let format = format.unwrap_or_else(|| panic!("{load}: no file format"));
            assert_eq!(at(&load, format.span), name, "{load}");
            formats_without_loss(&load, &sf);

            let unload = format!(
                "COPY INTO @stg_out FROM crm.orders FILE_FORMAT = (FORMAT_NAME = {name}{tail});"
            );
            let (_, format) = copy_into_location(&unload, &sf);
            let format = format.unwrap_or_else(|| panic!("{unload}: no file format"));
            assert_eq!(at(&unload, format.span), name, "{unload}");
            formats_without_loss(&unload, &sf);
        }
    }
    // A name written as a string keeps the string's span; a format given
    // by its type, or by a nested list, names none.
    let sql = "COPY INTO crm.orders FROM @stg_raw FILE_FORMAT = (FORMAT_NAME = 'd1.s1.ff_csv');";
    let (_, format) = copy_into_table(sql, &sf);
    let format = format.expect("a string names a format");
    assert_eq!(at(sql, format.span), "'d1.s1.ff_csv'");
    for sql in [
        "COPY INTO crm.orders FROM @stg_raw FILE_FORMAT = (TYPE = CSV NULL_IF = ('FORMAT_NAME'));",
        "COPY INTO crm.orders FROM @stg_raw FILE_FORMAT = (TYPE = CSV);",
        "COPY INTO crm.orders FROM @stg_raw;",
    ] {
        let (_, format) = copy_into_table(sql, &sf);
        assert!(format.is_none(), "{sql}");
    }
}

#[test]
fn snowflake_create_stage_file_format_name() {
    let sf = dialect::snowflake();
    for name in FORMAT_NAMES {
        let sql = format!(
            "CREATE STAGE stg_raw URL = 's3://bucket/raw/' FILE_FORMAT = (FORMAT_NAME = {name}) \
             COMMENT = 'x';"
        );
        let AstStmt::CreateStage(stage) = one_statement(&sql, &sf) else {
            panic!("{sql}: not CREATE STAGE");
        };
        let clause = stage.file_format_clause.expect("a file format clause");
        let format = clause.file_format_name.expect("a file format name");
        assert_eq!(at(&sql, format.span), name, "{sql}");
        formats_without_loss(&sql, &sf);
    }
    let sql = "CREATE STAGE stg_raw FILE_FORMAT = (FORMAT_NAME = 'ff_csv');";
    let AstStmt::CreateStage(stage) = one_statement(sql, &sf) else {
        panic!("{sql}: not CREATE STAGE");
    };
    let format = stage
        .file_format_clause
        .and_then(|clause| clause.file_format_name)
        .expect("a string names a format");
    assert_eq!(at(sql, format.span), "'ff_csv'");
    let sql = "CREATE STAGE stg_raw FILE_FORMAT = (TYPE = CSV);";
    let AstStmt::CreateStage(stage) = one_statement(sql, &sf) else {
        panic!("{sql}: not CREATE STAGE");
    };
    let clause = stage.file_format_clause.expect("a file format clause");
    assert!(clause.file_format_name.is_none());
}

#[test]
fn snowflake_stage_file_command_stage_name() {
    let sf = dialect::snowflake();
    for name in STAGE_NAMES {
        for (written, path) in [("", None), ("/2026/a.csv", Some("/2026/a.csv"))] {
            for template in [
                "LIST @@{}",
                "LS @@{}",
                "REMOVE @@{}",
                "RM @@{}",
                "PUT file:///tmp/data.csv @@{}",
                "GET @@{} file:///tmp/out/",
            ] {
                let sql = template.replace("@@{}", &format!("@{name}{written}")) + ";";
                let AstStmt::StageFileCommand(command) = one_statement(&sql, &sf) else {
                    panic!("{sql}: not a stage file command");
                };
                assert_stage(&sql, command.stage.as_ref(), name, path);
                assert!(command.stage_ref_span.is_some(), "{sql}");
                formats_without_loss(&sql, &sf);
            }
        }
    }
    // A stage followed by a statement; a user stage and a table stage keep
    // the reference's span and no stage.
    let sql = "LIST @stg_raw/p; SELECT 1;";
    let script = parse_sql_with_dialect(sql, &*sf).expect("parses");
    assert_eq!(script.stmts.len(), 2);
    let AstStmt::StageFileCommand(command) = &script.stmts[0] else {
        panic!("{sql}: not LIST");
    };
    assert_stage(sql, command.stage.as_ref(), "stg_raw", Some("/p"));
    for sql in ["LIST @~/p;", "REMOVE @%orders;"] {
        let AstStmt::StageFileCommand(command) = one_statement(sql, &sf) else {
            panic!("{sql}: not a stage file command");
        };
        assert!(command.stage.is_none(), "{sql}");
        assert!(command.stage_ref_span.is_some(), "{sql}");
        formats_without_loss(sql, &sf);
    }
}

#[test]
fn snowflake_from_stage_name() {
    let sf = dialect::snowflake();
    for name in STAGE_NAMES {
        for (written, path) in [("", None), ("/f.csv", Some("/f.csv"))] {
            let sql = format!("SELECT $1 FROM @{name}{written} s;");
            let AstStmt::Select(select) = one_statement(&sql, &sf) else {
                panic!("{sql}: not a SELECT");
            };
            let FromItemKind::TableRef(table) = &select.from[0].kind else {
                panic!("{sql}: not a table");
            };
            assert_stage(&sql, table.stage.as_deref(), name, path);
            assert_eq!(
                at(&sql, table.name.span),
                format!("@{name}{written}"),
                "{sql}"
            );
            formats_without_loss(&sql, &sf);
        }
    }
    let sql = "SELECT $1 FROM @stg_raw/f.csv (FILE_FORMAT => 'ff') s;";
    let AstStmt::Select(select) = one_statement(sql, &sf) else {
        panic!("{sql}: not a SELECT");
    };
    let FromItemKind::TableRef(table) = &select.from[0].kind else {
        panic!("{sql}: not a table");
    };
    assert_stage(sql, table.stage.as_deref(), "stg_raw", Some("/f.csv"));
    assert!(table.stage_options.is_some());
    let sql = "SELECT * FROM orders o;";
    let AstStmt::Select(select) = one_statement(sql, &sf) else {
        panic!("{sql}: not a SELECT");
    };
    let FromItemKind::TableRef(table) = &select.from[0].kind else {
        panic!("{sql}: not a table");
    };
    assert!(table.stage.is_none());
}

#[test]
fn snowflake_user_network_policy_names() {
    let sf = dialect::snowflake();
    for name in POLICY_NAMES {
        for sql in [
            format!("ALTER USER alice SET NETWORK_POLICY = {name};"),
            format!("ALTER USER alice SET NETWORK_POLICY = {name} DISABLED = TRUE;"),
            format!("CREATE USER bob NETWORK_POLICY = {name} DEFAULT_ROLE = analyst;"),
        ] {
            let stmt = match one_statement(&sql, &sf) {
                stmt @ (AstStmt::AlterPrincipal(_) | AstStmt::CreatePrincipal(_)) => stmt,
                other => panic!("{sql}: {other:?}"),
            };
            let options = match &stmt {
                AstStmt::AlterPrincipal(user) => user.options.snowflake_user.as_ref(),
                AstStmt::CreatePrincipal(user) => user.options.snowflake_user.as_ref(),
                other => panic!("{sql}: {other:?}"),
            }
            .unwrap_or_else(|| panic!("{sql}: no user options"));
            let policy = options
                .network_policy
                .as_ref()
                .unwrap_or_else(|| panic!("{sql}: no network policy: {options:?}"));
            assert_eq!(at(&sql, policy.span), name, "{sql}");
            formats_without_loss(&sql, &sf);
        }
    }
}

#[test]
fn snowflake_user_network_policy_string_value_is_still_read() {
    let sf = dialect::snowflake();
    let sql = "ALTER USER alice SET NETWORK_POLICY = 'np_corp';";
    let stmt = one_statement(sql, &sf);
    let policy = user_options(&stmt)
        .network_policy
        .as_ref()
        .expect("network policy");
    assert_eq!(at(sql, policy.span), "'np_corp'");
}

#[test]
fn snowflake_user_unset_network_policy_is_no_policy() {
    let sf = dialect::snowflake();
    let stmt = one_statement("ALTER USER alice UNSET NETWORK_POLICY;", &sf);
    assert!(matches!(stmt, AstStmt::AlterPrincipal(_)), "{stmt:?}");
    if let AstStmt::AlterPrincipal(user) = &stmt {
        assert!(
            user.options
                .snowflake_user
                .as_ref()
                .is_none_or(|options| options.network_policy.is_none()),
            "{user:?}"
        );
    }
}

#[test]
fn databricks_alter_catalog_owner_keeps_the_principal() {
    let dbx = dialect::databricks();
    for (principal, owner) in [
        ("new_owner", "new_owner"),
        ("`new.owner@corp.com`", "`new.owner@corp.com`"),
        ("`new_owner`", "`new_owner`"),
    ] {
        for sql in [
            format!("ALTER CATALOG c OWNER TO {principal};"),
            format!("ALTER CATALOG c SET OWNER TO {principal};"),
            format!("ALTER CATALOG OWNER TO {principal};"),
        ] {
            let AstStmt::AlterCatalog(catalog) = one_statement(&sql, &dbx) else {
                panic!("{sql}: not ALTER CATALOG");
            };
            let AlterCatalogActionKind::OwnerTo { principal } = catalog.action_kind else {
                panic!("{sql}: {:?}", catalog.action_kind);
            };
            assert_eq!(at(&sql, principal), owner, "{sql}");
            formats_without_loss(&sql, &dbx);
        }
    }
}

/// The ways a warehouse or a user is named.
const WAREHOUSE_NAMES: [&str; 4] = [
    "wh_etl",
    "\"WH_ETL X\"",
    "wh_etl_{{ var('env') }}",
    "IDENTIFIER('wh_etl')",
];

#[test]
fn snowflake_dynamic_table_warehouse_names() {
    let sf = dialect::snowflake();
    for name in WAREHOUSE_NAMES {
        let sql = format!(
            "CREATE DYNAMIC TABLE crm.dt TARGET_LAG = '1 hour' WAREHOUSE = {name} \
             INITIALIZATION_WAREHOUSE = {name} AS SELECT id FROM crm.orders;"
        );
        let AstStmt::CreateDynamicTable(dt) = one_statement(&sql, &sf) else {
            panic!("{sql}: not a dynamic table");
        };
        let warehouse = dt
            .warehouse
            .unwrap_or_else(|| panic!("{sql}: no warehouse"));
        let init = dt
            .init_warehouse
            .unwrap_or_else(|| panic!("{sql}: no initialization warehouse"));
        assert_eq!(at(&sql, warehouse), name, "{sql}");
        assert_eq!(at(&sql, init), name, "{sql}");
        assert_eq!(
            at(&sql, dt.warehouse_span.expect("clause")),
            format!("WAREHOUSE = {name}"),
            "{sql}"
        );
        formats_without_loss(&sql, &sf);
    }
}

#[test]
fn snowflake_task_warehouse_names() {
    let sf = dialect::snowflake();
    for name in WAREHOUSE_NAMES {
        let sql =
            format!("CREATE TASK crm.t_load WAREHOUSE = {name} SCHEDULE = '5 MINUTE' AS SELECT 1;");
        let AstStmt::CreateTask(task) = one_statement(&sql, &sf) else {
            panic!("{sql}: not a task");
        };
        let warehouse = task
            .warehouse
            .unwrap_or_else(|| panic!("{sql}: no warehouse"));
        assert_eq!(at(&sql, warehouse), name, "{sql}");
        assert!(task.schedule_span.is_some() && task.body.is_some(), "{sql}");
        formats_without_loss(&sql, &sf);
    }
}

#[test]
fn snowflake_warehouse_given_as_a_string_is_no_name() {
    let sf = dialect::snowflake();
    let sql = "CREATE TASK t WAREHOUSE = 'wh_etl' SCHEDULE = '5 MINUTE' AS SELECT 1;";
    let AstStmt::CreateTask(task) = one_statement(sql, &sf) else {
        panic!("{sql}: not a task");
    };
    assert!(task.warehouse.is_none(), "{task:?}");
    assert_eq!(
        at(sql, task.warehouse_span.expect("clause")),
        "WAREHOUSE = 'wh_etl'"
    );
    assert!(task.schedule_span.is_some() && task.body.is_some());
}

#[test]
fn snowflake_task_after_names() {
    let sf = dialect::snowflake();
    for names in [
        vec!["t_root"],
        vec!["s1.t_root", "\"D1\".\"S 1\".\"T_ROOT X\""],
        vec![
            "IDENTIFIER('d1.s1.t_root')",
            "{{ target.schema }}.t_b",
            "d1.stage.t_c",
        ],
    ] {
        let list = names.join(", ");
        let sql = format!("CREATE TASK crm.t_load WAREHOUSE = wh_etl AFTER {list} AS SELECT 1;");
        let AstStmt::CreateTask(task) = one_statement(&sql, &sf) else {
            panic!("{sql}: not a task");
        };
        let read: Vec<&str> = task.after.iter().map(|name| at(&sql, name.span)).collect();
        assert_eq!(read, names, "{sql}");
        assert_eq!(
            at(&sql, task.after_span.expect("clause")),
            format!("AFTER {list}"),
            "{sql}"
        );
        assert!(task.body.is_some(), "{sql}");
        formats_without_loss(&sql, &sf);
    }
}

#[test]
fn snowflake_task_clone_source_names() {
    let sf = dialect::snowflake();
    for name in [
        "source_task",
        "s1.source_task",
        "\"D1\".\"S 1\".\"SOURCE X\"",
        "IDENTIFIER('d1.s1.source_task')",
        "d1.stage.source_task",
    ] {
        let sql = format!("CREATE TASK my_clone CLONE {name};");
        let AstStmt::CreateTask(task) = one_statement(&sql, &sf) else {
            panic!("{sql}: not a task");
        };
        let source = task
            .clone_source
            .as_ref()
            .unwrap_or_else(|| panic!("{sql}: no clone source"));
        assert_eq!(at(&sql, source.span), name, "{sql}");
        assert_eq!(
            at(&sql, task.clone_span.expect("clause")),
            format!("CLONE {name}"),
            "{sql}"
        );
        formats_without_loss(&sql, &sf);
    }
}

#[test]
fn snowflake_task_execute_as_user_names() {
    let sf = dialect::snowflake();
    for name in ["svc_user", "\"SVC USER\"", "IDENTIFIER('svc_user')"] {
        let sql = format!(
            "CREATE TASK t WAREHOUSE = wh SCHEDULE = '5 MINUTE' EXECUTE AS USER {name} \
             AS SELECT 1;"
        );
        let AstStmt::CreateTask(task) = one_statement(&sql, &sf) else {
            panic!("{sql}: not a task");
        };
        let user = task
            .execute_as_user
            .unwrap_or_else(|| panic!("{sql}: no user"));
        assert_eq!(at(&sql, user), name, "{sql}");
        assert!(task.body.is_some(), "{sql}");
        formats_without_loss(&sql, &sf);
    }
    for mode in ["OWNER", "CALLER"] {
        let sql = format!("CREATE TASK t EXECUTE AS {mode} AS SELECT 1;");
        let AstStmt::CreateTask(task) = one_statement(&sql, &sf) else {
            panic!("{sql}: not a task");
        };
        assert!(task.execute_as_span.is_some() && task.execute_as_user.is_none());
    }
}

/// The ways an object is named after an object word.
const OBJECT_NAMES: [&str; 6] = [
    "orders",
    "s1.orders",
    "\"D1\".\"S 1\".\"ORDERS X\"",
    "{{ target.schema }}.orders",
    "d1.stage.orders",
    "IDENTIFIER('d1.s1.orders')",
];

#[test]
fn snowflake_describe_keeps_the_object_and_its_kind() {
    let sf = dialect::snowflake();
    for (words, kind) in [
        ("TABLE", AstDescribeKind::Table),
        ("VIEW", AstDescribeKind::View),
        ("MATERIALIZED VIEW", AstDescribeKind::MaterializedView),
        ("DYNAMIC TABLE", AstDescribeKind::DynamicTable),
        ("MASKING POLICY", AstDescribeKind::MaskingPolicy),
        ("ROW ACCESS POLICY", AstDescribeKind::RowAccessPolicy),
        ("NETWORK POLICY", AstDescribeKind::NetworkPolicy),
        ("STORAGE INTEGRATION", AstDescribeKind::Integration),
        ("STAGE", AstDescribeKind::Stage),
        ("WAREHOUSE", AstDescribeKind::Warehouse),
        (
            "SEARCH OPTIMIZATION ON",
            AstDescribeKind::SearchOptimization,
        ),
    ] {
        for name in OBJECT_NAMES {
            for keyword in ["DESCRIBE", "DESC"] {
                let sql = format!("{keyword} {words} {name};");
                let AstStmt::Describe(describe) = one_statement(&sql, &sf) else {
                    panic!("{sql}: not DESCRIBE");
                };
                assert_eq!(describe.kind, kind, "{sql}");
                let object = describe
                    .object
                    .as_ref()
                    .unwrap_or_else(|| panic!("{sql}: no object"));
                assert_eq!(at(&sql, object.span), name, "{sql}");
                assert_eq!(
                    at(&sql, describe.object_span.expect("phrase")),
                    format!("{words} {name}"),
                    "{sql}"
                );
                formats_without_loss(&sql, &sf);
            }
        }
    }
}

#[test]
fn snowflake_describe_function_object_leaves_the_signature_out() {
    let sf = dialect::snowflake();
    for words in ["FUNCTION", "PROCEDURE"] {
        let sql = format!("DESCRIBE {words} s1.f_hash(NUMBER, VARCHAR);");
        let AstStmt::Describe(describe) = one_statement(&sql, &sf) else {
            panic!("{sql}: not DESCRIBE");
        };
        let object = describe.object.expect("object");
        assert_eq!(at(&sql, object.span), "s1.f_hash", "{sql}");
        assert_eq!(
            at(&sql, describe.object_span.expect("phrase")),
            format!("{words} s1.f_hash(NUMBER, VARCHAR)"),
            "{sql}"
        );
        formats_without_loss(&sql, &sf);
    }
}

#[test]
fn describe_type_clause_ends_the_object() {
    let sf = dialect::snowflake();
    let sql = "DESCRIBE TABLE s1.orders TYPE = COLUMNS;";
    let AstStmt::Describe(describe) = one_statement(sql, &sf) else {
        panic!("{sql}: not DESCRIBE");
    };
    assert_eq!(at(sql, describe.object.expect("object").span), "s1.orders");
    assert_eq!(
        at(sql, describe.type_clause_span.expect("clause")),
        "TYPE = COLUMNS"
    );
    formats_without_loss(sql, &sf);
}

#[test]
fn describe_without_an_object_word_names_the_table_and_extended_is_no_name() {
    for (dialect, sql, name) in [
        (dialect::mysql(), "DESC orders id;", "orders"),
        (dialect::databricks(), "DESCRIBE s1.orders;", "s1.orders"),
        (
            dialect::databricks(),
            "DESCRIBE EXTENDED d1.s1.orders;",
            "d1.s1.orders",
        ),
        (
            dialect::databricks(),
            "DESCRIBE TABLE EXTENDED `D1`.`S 1`.`ORDERS X`;",
            "`D1`.`S 1`.`ORDERS X`",
        ),
    ] {
        let AstStmt::Describe(describe) = one_statement(sql, &dialect) else {
            panic!("{sql}: not DESCRIBE");
        };
        let object = describe.object.expect("object");
        assert_eq!(at(sql, object.span), name, "{sql}");
        formats_without_loss(sql, &dialect);
    }
    let sql = "DESCRIBE EXTENDED;";
    let AstStmt::Describe(describe) = one_statement(sql, &dialect::databricks()) else {
        panic!("{sql}: not DESCRIBE");
    };
    assert_eq!(at(sql, describe.object.expect("object").span), "EXTENDED");
}

#[test]
fn snowflake_describe_without_an_object_names_none() {
    let sf = dialect::snowflake();
    for (sql, kind) in [
        ("DESCRIBE RESULT LAST_QUERY_ID();", AstDescribeKind::Result),
        ("DESC RESULT '01a2b3c4';", AstDescribeKind::Result),
        ("DESCRIBE TRANSACTION 12345;", AstDescribeKind::Transaction),
    ] {
        let AstStmt::Describe(describe) = one_statement(sql, &sf) else {
            panic!("{sql}: not DESCRIBE");
        };
        assert_eq!(describe.kind, kind, "{sql}");
        assert!(describe.object.is_none(), "{sql}: {describe:?}");
        assert!(describe.object_span.is_some(), "{sql}");
        formats_without_loss(sql, &sf);
    }
}

#[test]
fn snowflake_drop_routine_keeps_each_target_apart_from_its_signature() {
    let sf = dialect::snowflake();
    for routine in ["FUNCTION", "PROCEDURE"] {
        for name in OBJECT_NAMES {
            let sql = format!("DROP {routine} IF EXISTS {name}(STRING, NUMBER);");
            let AstStmt::Drop(drop) = one_statement(&sql, &sf) else {
                panic!("{sql}: not DROP");
            };
            let [target] = drop.targets.as_slice() else {
                panic!("{sql}: {:?}", drop.targets);
            };
            assert_eq!(at(&sql, target.name.span), name, "{sql}");
            assert_eq!(
                at(&sql, target.signature.expect("signature")),
                "(STRING, NUMBER)",
                "{sql}"
            );
            assert_eq!(
                at(&sql, drop.target_name.as_ref().expect("whole").span),
                format!("{name}(STRING, NUMBER)"),
                "{sql}"
            );
            formats_without_loss(&sql, &sf);
        }
    }
}

#[test]
fn snowflake_drop_lists_keep_every_target() {
    let sf = dialect::snowflake();
    let sql = "DROP FUNCTION s1.f_hash(STRING), \"D1\".\"S 1\".\"G X\"(), h CASCADE;";
    let AstStmt::Drop(drop) = one_statement(sql, &sf) else {
        panic!("{sql}: not DROP");
    };
    let names: Vec<&str> = drop
        .targets
        .iter()
        .map(|target| at(sql, target.name.span))
        .collect();
    assert_eq!(names, ["s1.f_hash", "\"D1\".\"S 1\".\"G X\"", "h"], "{sql}");
    let signatures: Vec<Option<&str>> = drop
        .targets
        .iter()
        .map(|target| target.signature.map(|span| at(sql, span)))
        .collect();
    assert_eq!(signatures, [Some("(STRING)"), Some("()"), None], "{sql}");
    assert!(drop.cascade_restrict_span.is_some(), "{sql}");
    formats_without_loss(sql, &sf);
}

#[test]
fn snowflake_drop_table_names_every_table() {
    let sf = dialect::snowflake();
    let sql = "DROP TABLE IF EXISTS s1.orders, d1.s1.returns;";
    let AstStmt::Drop(drop) = one_statement(sql, &sf) else {
        panic!("{sql}: not DROP");
    };
    let names: Vec<&str> = drop
        .targets
        .iter()
        .map(|target| at(sql, target.name.span))
        .collect();
    assert_eq!(names, ["s1.orders", "d1.s1.returns"], "{sql}");
    assert!(drop.targets.iter().all(|target| target.signature.is_none()));
}

/// The ways a multi-part relation is written.
const RELATION_NAMES: [&str; 4] = [
    "orders",
    "d1.s1.orders",
    "`D1`.`S 1`.`ORDERS X`",
    "{{ target.schema }}.orders",
];

#[test]
fn databricks_create_flow_keeps_the_name_target_and_source() {
    let dbx = dialect::databricks();
    for name in RELATION_NAMES {
        for head in ["CREATE FLOW", "CREATE OR REFRESH FLOW"] {
            let sql = format!(
                "{head} {name} AS AUTO CDC INTO tgt.t FROM src.s KEYS (id) SEQUENCE BY ts STORED AS SCD TYPE 1;"
            );
            let AstStmt::CreateFlow(flow) = one_statement(&sql, &dbx) else {
                panic!("{sql}: not CREATE FLOW");
            };
            assert_eq!(at(&sql, flow.name.expect("name").span), name, "{sql}");
            assert_eq!(
                at(&sql, flow.target.expect("target").span),
                "tgt.t",
                "{sql}"
            );
            assert_eq!(
                at(&sql, flow.source.expect("source").span),
                "src.s",
                "{sql}"
            );
            formats_without_loss(&sql, &dbx);
        }
    }
}

#[test]
fn databricks_flow_stream_source_keeps_the_name_inside() {
    let dbx = dialect::databricks();
    for source in RELATION_NAMES {
        let create = format!(
            "CREATE FLOW f AS AUTO CDC INTO t FROM STREAM({source}) KEYS (id) COLUMNS * EXCEPT (op);"
        );
        let apply = format!(
            "APPLY CHANGES INTO LIVE.t FROM STREAM({source}) KEYS (id) SEQUENCE BY ts STORED AS SCD TYPE 2;"
        );
        for sql in [create, apply] {
            let AstStmt::CreateFlow(flow) = one_statement(&sql, &dbx) else {
                panic!("{sql}: not a flow");
            };
            assert_eq!(at(&sql, flow.source.expect("source").span), source, "{sql}");
            formats_without_loss(&sql, &dbx);
        }
    }
}

#[test]
fn databricks_apply_changes_keeps_the_target_and_has_no_flow_name() {
    let dbx = dialect::databricks();
    for target in RELATION_NAMES {
        let sql = format!(
            "APPLY CHANGES INTO {target} FROM src KEYS (id) SEQUENCE BY ts APPLY AS DELETE WHEN op = 'D' COLUMNS * EXCEPT (op);"
        );
        let AstStmt::CreateFlow(flow) = one_statement(&sql, &dbx) else {
            panic!("{sql}: not a flow");
        };
        assert!(flow.name.is_none(), "{sql}");
        assert_eq!(at(&sql, flow.target.expect("target").span), target, "{sql}");
        assert_eq!(at(&sql, flow.source.expect("source").span), "src", "{sql}");
        formats_without_loss(&sql, &dbx);
    }
}

#[test]
fn databricks_flow_source_that_is_not_a_name_keeps_none_and_still_parses() {
    let dbx = dialect::databricks();
    let sql = "CREATE FLOW f AS AUTO CDC INTO t FROM STREAM(read_files('/x')) KEYS (id);";
    let AstStmt::CreateFlow(flow) = one_statement(sql, &dbx) else {
        panic!("{sql}: not a flow");
    };
    assert!(flow.source.is_none(), "{sql}");
    assert_eq!(at(sql, flow.target.expect("target").span), "t", "{sql}");
    formats_without_loss(sql, &dbx);
}

#[test]
fn databricks_alter_share_add_and_remove_keep_the_object() {
    let dbx = dialect::databricks();
    for name in RELATION_NAMES {
        for (words, kind, tail) in [
            ("ADD TABLE", AstShareObjectKind::Table, ""),
            ("ADD TABLE", AstShareObjectKind::Table, " AS s1.alias"),
            (
                "ADD TABLE",
                AstShareObjectKind::Table,
                " PARTITION (region = 'eu') WITH HISTORY",
            ),
            ("ADD SCHEMA", AstShareObjectKind::Schema, ""),
            ("ADD VIEW", AstShareObjectKind::View, " COMMENT 'x'"),
            ("ADD VOLUME", AstShareObjectKind::Volume, ""),
            ("ADD MODEL", AstShareObjectKind::Model, ""),
            ("REMOVE TABLE", AstShareObjectKind::Table, ""),
            ("REMOVE SCHEMA", AstShareObjectKind::Schema, ""),
        ] {
            let sql = format!("ALTER SHARE sh_partner {words} {name}{tail};");
            let AstStmt::AlterShare(share) = one_statement(&sql, &dbx) else {
                panic!("{sql}: not ALTER SHARE");
            };
            let (read_kind, object) = match &share.action.kind {
                AstAlterShareActionKind::AddObject { kind, object, .. }
                | AstAlterShareActionKind::RemoveObject { kind, object, .. } => (*kind, object),
                other => panic!("{sql}: {other:?}"),
            };
            assert_eq!(read_kind, kind, "{sql}");
            assert_eq!(at(&sql, object.span), name, "{sql}");
            assert_eq!(
                at(&sql, share.action.span),
                format!("{words} {name}{tail}"),
                "{sql}"
            );
            formats_without_loss(&sql, &dbx);
        }
    }
}

#[test]
fn alter_share_accounts_and_unknown_actions_stay_what_they_were() {
    let sf = dialect::snowflake();
    let sql = "ALTER SHARE s ADD ACCOUNTS = a1, a2;";
    let AstStmt::AlterShare(share) = one_statement(sql, &sf) else {
        panic!("{sql}: not ALTER SHARE");
    };
    assert!(matches!(
        share.action.kind,
        AstAlterShareActionKind::AddAccounts { .. }
    ));
    for sql in ["ALTER SHARE s ADD TABLE;", "ALTER SHARE s ADD THING x;"] {
        let AstStmt::AlterShare(share) = one_statement(sql, &sf) else {
            panic!("{sql}: not ALTER SHARE");
        };
        assert!(
            matches!(share.action.kind, AstAlterShareActionKind::Unknown(_)),
            "{sql}: {:?}",
            share.action.kind
        );
    }
}
