// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! The shapes the policies and functions `ALTER TABLE` attaches are written in, each read whole as the name it is.

mod name_shapes;

use lexega_syntax::dialect;
use name_shapes::reads_whole;

#[test]
fn databricks_alter_table_alter_column_c_set_mask_name() {
    reads_whole(
        &dialect::databricks(),
        &[
            "ALTER TABLE main.crm.customers ALTER COLUMN email SET MASK «s1.mask_email»;",
            "ALTER TABLE main.crm.customers ALTER COLUMN email SET MASK «d1.s1.mask_email»;",
            "ALTER TABLE main.crm.customers ALTER COLUMN email SET MASK «`D1`.`S 1`.`MASK_EMAIL X`»;",
            "ALTER TABLE main.crm.customers ALTER COLUMN email SET MASK «{{ target.schema }}.mask_email»;",
            "ALTER TABLE main.crm.customers ALTER COLUMN email SET MASK «`S 1`.`MASK_EMAIL X`»;",
            "ALTER TABLE main.crm.customers ALTER COLUMN email SET MASK «d1.stage.mask_email»;",
        ],
    );
}

#[test]
fn databricks_alter_table_set_row_filter_name_on() {
    reads_whole(
        &dialect::databricks(),
        &[
            "ALTER TABLE main.crm.customers SET ROW FILTER «s1.rf_region» ON (region);",
            "ALTER TABLE main.crm.customers SET ROW FILTER «d1.s1.rf_region» ON (region);",
            "ALTER TABLE main.crm.customers SET ROW FILTER «`D1`.`S 1`.`RF_REGION X`» ON (region);",
            "ALTER TABLE main.crm.customers SET ROW FILTER «{{ target.schema }}.rf_region» ON (region);",
            "ALTER TABLE main.crm.customers SET ROW FILTER «`S 1`.`RF_REGION X`» ON (region);",
            "ALTER TABLE main.crm.customers SET ROW FILTER «d1.stage.rf_region» ON (region);",
        ],
    );
}

#[test]
fn snowflake_alter_table_add_data_metric_function_name() {
    reads_whole(
        &dialect::snowflake(),
        &[
            "ALTER TABLE crm.orders ADD DATA METRIC FUNCTION «IDENTIFIER('d1.s1.null_count')» ON (customer_id);",
        ],
    );
}

#[test]
fn snowflake_alter_table_add_row_access_policy_name() {
    reads_whole(
        &dialect::snowflake(),
        &[
            "ALTER TABLE crm.customers ADD ROW ACCESS POLICY «s1.rap_region» ON (region);",
            "ALTER TABLE crm.customers ADD ROW ACCESS POLICY «d1.s1.rap_region» ON (region);",
            "ALTER TABLE crm.customers ADD ROW ACCESS POLICY «\"D1\".\"S 1\".\"RAP_REGION X\"» ON (region);",
            "ALTER TABLE crm.customers ADD ROW ACCESS POLICY «{{ target.schema }}.rap_region» ON (region);",
            "ALTER TABLE crm.customers ADD ROW ACCESS POLICY «\"S 1\".\"RAP_REGION X\"» ON (region);",
            "ALTER TABLE crm.customers ADD ROW ACCESS POLICY «d1.stage.rap_region» ON (region);",
            "ALTER TABLE crm.customers ADD ROW ACCESS POLICY «IDENTIFIER('d1.s1.rap_region')» ON (region);",
        ],
    );
}

#[test]
fn snowflake_alter_table_alter_column_c_set_masking_policy_name() {
    reads_whole(
        &dialect::snowflake(),
        &[
            "ALTER TABLE crm.customers ALTER COLUMN email SET MASKING POLICY «s1.mask_email»;",
            "ALTER TABLE crm.customers ALTER COLUMN email SET MASKING POLICY «d1.s1.mask_email»;",
            "ALTER TABLE crm.customers ALTER COLUMN email SET MASKING POLICY «\"D1\".\"S 1\".\"MASK_EMAIL X\"»;",
            "ALTER TABLE crm.customers ALTER COLUMN email SET MASKING POLICY «{{ target.schema }}.mask_email»;",
            "ALTER TABLE crm.customers ALTER COLUMN email SET MASKING POLICY «\"S 1\".\"MASK_EMAIL X\"»;",
            "ALTER TABLE crm.customers ALTER COLUMN email SET MASKING POLICY «d1.stage.mask_email»;",
            "ALTER TABLE crm.customers ALTER COLUMN email SET MASKING POLICY «IDENTIFIER('d1.s1.mask_email')»;",
        ],
    );
}

#[test]
fn snowflake_alter_table_alter_column_c_set_masking_policy_name_force() {
    reads_whole(
        &dialect::snowflake(),
        &[
            "ALTER TABLE crm.customers ALTER COLUMN email SET MASKING POLICY «s1.mask_email» FORCE;",
            "ALTER TABLE crm.customers ALTER COLUMN email SET MASKING POLICY «d1.s1.mask_email» FORCE;",
            "ALTER TABLE crm.customers ALTER COLUMN email SET MASKING POLICY «\"D1\".\"S 1\".\"MASK_EMAIL X\"» FORCE;",
            "ALTER TABLE crm.customers ALTER COLUMN email SET MASKING POLICY «{{ target.schema }}.mask_email» FORCE;",
            "ALTER TABLE crm.customers ALTER COLUMN email SET MASKING POLICY «\"S 1\".\"MASK_EMAIL X\"» FORCE;",
            "ALTER TABLE crm.customers ALTER COLUMN email SET MASKING POLICY «d1.stage.mask_email» FORCE;",
            "ALTER TABLE crm.customers ALTER COLUMN email SET MASKING POLICY «IDENTIFIER('d1.s1.mask_email')» FORCE;",
        ],
    );
}

#[test]
fn snowflake_alter_table_alter_column_c_set_masking_policy_name_using() {
    reads_whole(
        &dialect::snowflake(),
        &[
            "ALTER TABLE crm.customers ALTER COLUMN email SET MASKING POLICY «s1.mask_email» USING (email, region);",
            "ALTER TABLE crm.customers ALTER COLUMN email SET MASKING POLICY «d1.s1.mask_email» USING (email, region);",
            "ALTER TABLE crm.customers ALTER COLUMN email SET MASKING POLICY «\"D1\".\"S 1\".\"MASK_EMAIL X\"» USING (email, region);",
            "ALTER TABLE crm.customers ALTER COLUMN email SET MASKING POLICY «{{ target.schema }}.mask_email» USING (email, region);",
            "ALTER TABLE crm.customers ALTER COLUMN email SET MASKING POLICY «\"S 1\".\"MASK_EMAIL X\"» USING (email, region);",
            "ALTER TABLE crm.customers ALTER COLUMN email SET MASKING POLICY «d1.stage.mask_email» USING (email, region);",
            "ALTER TABLE crm.customers ALTER COLUMN email SET MASKING POLICY «IDENTIFIER('d1.s1.mask_email')» USING (email, region);",
        ],
    );
}

#[test]
fn snowflake_alter_table_alter_column_c_set_projection_policy_name() {
    reads_whole(
        &dialect::snowflake(),
        &[
            "ALTER TABLE crm.customers ALTER COLUMN ssn SET PROJECTION POLICY «s1.pp_hide»;",
            "ALTER TABLE crm.customers ALTER COLUMN ssn SET PROJECTION POLICY «d1.s1.pp_hide»;",
            "ALTER TABLE crm.customers ALTER COLUMN ssn SET PROJECTION POLICY «\"D1\".\"S 1\".\"PP_HIDE X\"»;",
            "ALTER TABLE crm.customers ALTER COLUMN ssn SET PROJECTION POLICY «{{ target.schema }}.pp_hide»;",
            "ALTER TABLE crm.customers ALTER COLUMN ssn SET PROJECTION POLICY «\"S 1\".\"PP_HIDE X\"»;",
            "ALTER TABLE crm.customers ALTER COLUMN ssn SET PROJECTION POLICY «d1.stage.pp_hide»;",
            "ALTER TABLE crm.customers ALTER COLUMN ssn SET PROJECTION POLICY «IDENTIFIER('d1.s1.pp_hide')»;",
        ],
    );
}

#[test]
fn snowflake_alter_table_alter_column_c_set_projection_policy_name_force() {
    reads_whole(
        &dialect::snowflake(),
        &[
            "ALTER TABLE crm.customers MODIFY COLUMN ssn SET PROJECTION POLICY «s1.pp_hide» FORCE;",
            "ALTER TABLE crm.customers MODIFY COLUMN ssn SET PROJECTION POLICY «d1.s1.pp_hide» FORCE;",
            "ALTER TABLE crm.customers MODIFY COLUMN ssn SET PROJECTION POLICY «\"D1\".\"S 1\".\"PP_HIDE X\"» FORCE;",
            "ALTER TABLE crm.customers MODIFY COLUMN ssn SET PROJECTION POLICY «{{ target.schema }}.pp_hide» FORCE;",
            "ALTER TABLE crm.customers MODIFY COLUMN ssn SET PROJECTION POLICY «\"S 1\".\"PP_HIDE X\"» FORCE;",
            "ALTER TABLE crm.customers MODIFY COLUMN ssn SET PROJECTION POLICY «d1.stage.pp_hide» FORCE;",
            "ALTER TABLE crm.customers MODIFY COLUMN ssn SET PROJECTION POLICY «IDENTIFIER('d1.s1.pp_hide')» FORCE;",
        ],
    );
}

#[test]
fn snowflake_alter_table_drop_data_metric_function_name() {
    reads_whole(
        &dialect::snowflake(),
        &[
            "ALTER TABLE crm.orders DROP DATA METRIC FUNCTION «IDENTIFIER('d1.s1.null_count')» ON (customer_id);",
        ],
    );
}

#[test]
fn snowflake_alter_table_drop_row_access_policy_name() {
    reads_whole(
        &dialect::snowflake(),
        &[
            "ALTER TABLE crm.customers DROP ROW ACCESS POLICY «s1.rap_region»;",
            "ALTER TABLE crm.customers DROP ROW ACCESS POLICY «d1.s1.rap_region»;",
            "ALTER TABLE crm.customers DROP ROW ACCESS POLICY «\"D1\".\"S 1\".\"RAP_REGION X\"»;",
            "ALTER TABLE crm.customers DROP ROW ACCESS POLICY «{{ target.schema }}.rap_region»;",
            "ALTER TABLE crm.customers DROP ROW ACCESS POLICY «\"S 1\".\"RAP_REGION X\"»;",
            "ALTER TABLE crm.customers DROP ROW ACCESS POLICY «d1.stage.rap_region»;",
            "ALTER TABLE crm.customers DROP ROW ACCESS POLICY «IDENTIFIER('d1.s1.rap_region')»;",
        ],
    );
}

#[test]
fn snowflake_alter_table_drop_row_access_policy_name_add() {
    reads_whole(
        &dialect::snowflake(),
        &[
            "ALTER TABLE crm.customers DROP ROW ACCESS POLICY «s1.rap_region», ADD ROW ACCESS POLICY rap_new ON (region);",
            "ALTER TABLE crm.customers DROP ROW ACCESS POLICY «d1.s1.rap_region», ADD ROW ACCESS POLICY rap_new ON (region);",
            "ALTER TABLE crm.customers DROP ROW ACCESS POLICY «\"D1\".\"S 1\".\"RAP_REGION X\"», ADD ROW ACCESS POLICY rap_new ON (region);",
            "ALTER TABLE crm.customers DROP ROW ACCESS POLICY «{{ target.schema }}.rap_region», ADD ROW ACCESS POLICY rap_new ON (region);",
            "ALTER TABLE crm.customers DROP ROW ACCESS POLICY «\"S 1\".\"RAP_REGION X\"», ADD ROW ACCESS POLICY rap_new ON (region);",
            "ALTER TABLE crm.customers DROP ROW ACCESS POLICY «d1.stage.rap_region», ADD ROW ACCESS POLICY rap_new ON (region);",
            "ALTER TABLE crm.customers DROP ROW ACCESS POLICY «IDENTIFIER('d1.s1.rap_region')», ADD ROW ACCESS POLICY rap_new ON (region);",
        ],
    );
}

#[test]
fn snowflake_alter_table_modify_column_c_set_masking_policy_name() {
    reads_whole(
        &dialect::snowflake(),
        &[
            "ALTER TABLE crm.customers MODIFY COLUMN email SET MASKING POLICY «s1.mask_email»;",
            "ALTER TABLE crm.customers MODIFY COLUMN email SET MASKING POLICY «d1.s1.mask_email»;",
            "ALTER TABLE crm.customers MODIFY COLUMN email SET MASKING POLICY «\"D1\".\"S 1\".\"MASK_EMAIL X\"»;",
            "ALTER TABLE crm.customers MODIFY COLUMN email SET MASKING POLICY «{{ target.schema }}.mask_email»;",
            "ALTER TABLE crm.customers MODIFY COLUMN email SET MASKING POLICY «\"S 1\".\"MASK_EMAIL X\"»;",
            "ALTER TABLE crm.customers MODIFY COLUMN email SET MASKING POLICY «d1.stage.mask_email»;",
            "ALTER TABLE crm.customers MODIFY COLUMN email SET MASKING POLICY «IDENTIFIER('d1.s1.mask_email')»;",
        ],
    );
}

#[test]
fn snowflake_alter_table_rename_to_name() {
    reads_whole(
        &dialect::snowflake(),
        &["ALTER TABLE crm.customers RENAME TO «IDENTIFIER('d1.s1.customers2')»;"],
    );
}

#[test]
fn snowflake_alter_table_set_aggregation_policy_name() {
    reads_whole(
        &dialect::snowflake(),
        &[
            "ALTER TABLE crm.orders SET AGGREGATION POLICY «s1.ap_min»;",
            "ALTER TABLE crm.orders SET AGGREGATION POLICY «d1.s1.ap_min»;",
            "ALTER TABLE crm.orders SET AGGREGATION POLICY «\"D1\".\"S 1\".\"AP_MIN X\"»;",
            "ALTER TABLE crm.orders SET AGGREGATION POLICY «{{ target.schema }}.ap_min»;",
            "ALTER TABLE crm.orders SET AGGREGATION POLICY «\"S 1\".\"AP_MIN X\"»;",
            "ALTER TABLE crm.orders SET AGGREGATION POLICY «d1.stage.ap_min»;",
            "ALTER TABLE crm.orders SET AGGREGATION POLICY «IDENTIFIER('d1.s1.ap_min')»;",
        ],
    );
}

#[test]
fn snowflake_alter_table_set_aggregation_policy_name_entity_key() {
    reads_whole(
        &dialect::snowflake(),
        &[
            "ALTER TABLE crm.orders SET AGGREGATION POLICY «s1.ap_min» ENTITY KEY (customer_id);",
            "ALTER TABLE crm.orders SET AGGREGATION POLICY «d1.s1.ap_min» ENTITY KEY (customer_id);",
            "ALTER TABLE crm.orders SET AGGREGATION POLICY «\"D1\".\"S 1\".\"AP_MIN X\"» ENTITY KEY (customer_id);",
            "ALTER TABLE crm.orders SET AGGREGATION POLICY «{{ target.schema }}.ap_min» ENTITY KEY (customer_id);",
            "ALTER TABLE crm.orders SET AGGREGATION POLICY «\"S 1\".\"AP_MIN X\"» ENTITY KEY (customer_id);",
            "ALTER TABLE crm.orders SET AGGREGATION POLICY «d1.stage.ap_min» ENTITY KEY (customer_id);",
            "ALTER TABLE crm.orders SET AGGREGATION POLICY «IDENTIFIER('d1.s1.ap_min')» ENTITY KEY (customer_id);",
        ],
    );
}

#[test]
fn snowflake_alter_table_set_aggregation_policy_name_force() {
    reads_whole(
        &dialect::snowflake(),
        &[
            "ALTER TABLE crm.orders SET AGGREGATION POLICY «s1.ap_min» FORCE;",
            "ALTER TABLE crm.orders SET AGGREGATION POLICY «d1.s1.ap_min» FORCE;",
            "ALTER TABLE crm.orders SET AGGREGATION POLICY «\"D1\".\"S 1\".\"AP_MIN X\"» FORCE;",
            "ALTER TABLE crm.orders SET AGGREGATION POLICY «{{ target.schema }}.ap_min» FORCE;",
            "ALTER TABLE crm.orders SET AGGREGATION POLICY «\"S 1\".\"AP_MIN X\"» FORCE;",
            "ALTER TABLE crm.orders SET AGGREGATION POLICY «d1.stage.ap_min» FORCE;",
            "ALTER TABLE crm.orders SET AGGREGATION POLICY «IDENTIFIER('d1.s1.ap_min')» FORCE;",
        ],
    );
}

#[test]
fn snowflake_alter_table_set_join_policy_name() {
    reads_whole(
        &dialect::snowflake(),
        &[
            "ALTER TABLE crm.orders SET JOIN POLICY «s1.jp_req»;",
            "ALTER TABLE crm.orders SET JOIN POLICY «d1.s1.jp_req»;",
            "ALTER TABLE crm.orders SET JOIN POLICY «\"D1\".\"S 1\".\"JP_REQ X\"»;",
            "ALTER TABLE crm.orders SET JOIN POLICY «{{ target.schema }}.jp_req»;",
            "ALTER TABLE crm.orders SET JOIN POLICY «\"S 1\".\"JP_REQ X\"»;",
            "ALTER TABLE crm.orders SET JOIN POLICY «d1.stage.jp_req»;",
            "ALTER TABLE crm.orders SET JOIN POLICY «IDENTIFIER('d1.s1.jp_req')»;",
        ],
    );
}

#[test]
fn snowflake_alter_table_set_join_policy_name_force() {
    reads_whole(
        &dialect::snowflake(),
        &[
            "ALTER TABLE crm.orders SET JOIN POLICY «s1.jp_req» FORCE;",
            "ALTER TABLE crm.orders SET JOIN POLICY «d1.s1.jp_req» FORCE;",
            "ALTER TABLE crm.orders SET JOIN POLICY «\"D1\".\"S 1\".\"JP_REQ X\"» FORCE;",
            "ALTER TABLE crm.orders SET JOIN POLICY «{{ target.schema }}.jp_req» FORCE;",
            "ALTER TABLE crm.orders SET JOIN POLICY «\"S 1\".\"JP_REQ X\"» FORCE;",
            "ALTER TABLE crm.orders SET JOIN POLICY «d1.stage.jp_req» FORCE;",
            "ALTER TABLE crm.orders SET JOIN POLICY «IDENTIFIER('d1.s1.jp_req')» FORCE;",
        ],
    );
}

#[test]
fn snowflake_alter_table_swap_with_name() {
    reads_whole(
        &dialect::snowflake(),
        &["ALTER TABLE crm.customers SWAP WITH «IDENTIFIER('d1.s1.customers2')»;"],
    );
}

#[test]
fn databricks_set_mask_using_columns_reads_its_list() {
    use lexega_syntax::ast::{AstAlterTableActionKind, AstStmt};
    let dbx = dialect::databricks();
    let sql = "ALTER TABLE main.crm.customers ALTER COLUMN email SET MASK mask_email USING COLUMNS (region, 'x')";
    reads_whole(&dbx, &[&format!("{sql};")]);
    let script = lexega_syntax::parse_sql_with_dialect(sql, &*dbx).expect("parses");
    let [AstStmt::AlterTable(alter)] = script.stmts.as_slice() else {
        panic!("{:?}", script.stmts);
    };
    let found = format!("{:?}", alter.actions);
    let Some(AstAlterTableActionKind::SetColumnMask {
        using_columns,
        using_columns_span: Some(span),
        ..
    }) = alter.actions.iter().map(|a| &a.kind).next()
    else {
        panic!("{found}");
    };
    assert_eq!(using_columns.len(), 2);
    assert_eq!(
        &sql[span.start as usize..span.end as usize],
        "USING COLUMNS (region, 'x')"
    );
    let config = lexega_syntax::FormatterConfig {
        dialect: dialect::databricks(),
        ..Default::default()
    };
    let formatted = lexega_syntax::format_sql_with_config(sql, &config).expect("formats");
    lexega_syntax::verify_formatting_safe_with_dialect(sql, &formatted, &*dbx)
        .unwrap_or_else(|e| panic!("{e}\n{formatted}"));
}
