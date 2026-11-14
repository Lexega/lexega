// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Names a statement keeps inside a wider clause are read where they are
//! written: a part named like a clause word does not end the clause, and
//! a position with no name in it is not read.

use lexega_syntax::ast::{
    AstAlterTableActionKind, AstAlterViewActionKind, AstConstraintDetails, AstConstraintKind,
    AstCreateTable, AstCreateTableVariant, AstObjectRef,
};
use lexega_syntax::{
    dialect, format_sql_with_config, parse_sql_with_dialect, verify_formatting_safe_with_dialect,
    AstStmt, DialectRef, FormatterConfig, Span,
};

fn one_statement(sql: &str) -> AstStmt {
    let script = parse_sql_with_dialect(sql, &*lexega_syntax::dialect::snowflake())
        .unwrap_or_else(|e| panic!("{sql}: {e:?}"));
    let [stmt] = <[AstStmt; 1]>::try_from(script.stmts)
        .unwrap_or_else(|stmts| panic!("{sql}: expected one statement, got {stmts:?}"));
    stmt
}

fn text(sql: &str, span: Option<Span>) -> &str {
    let span = span.unwrap_or_else(|| panic!("{sql}: no span"));
    &sql[span.start as usize..span.end as usize]
}

#[test]
fn alter_view_reads_the_policy_and_tag_names_of_its_actions() {
    for (sql, expected) in [
        (
            "ALTER VIEW crm.v ADD ROW ACCESS POLICY d1.stage.rap_region ON (region);",
            "ADD ROW ACCESS POLICY d1.stage.rap_region ON (region)",
        ),
        (
            "ALTER VIEW crm.v ADD ROW ACCESS POLICY IDENTIFIER('d1.s1.rap') ON (region);",
            "ADD ROW ACCESS POLICY IDENTIFIER('d1.s1.rap') ON (region)",
        ),
        (
            "ALTER VIEW crm.v DROP ROW ACCESS POLICY \"S 1\".\"RAP X\";",
            "DROP ROW ACCESS POLICY \"S 1\".\"RAP X\"",
        ),
        (
            "ALTER VIEW crm.v ALTER COLUMN email SET MASKING POLICY {{ target.schema }}.mask;",
            "ALTER COLUMN email SET MASKING POLICY {{ target.schema }}.mask",
        ),
        (
            "ALTER VIEW crm.v SET TAG d1.s1.sensitivity = 'high';",
            "SET TAG d1.s1.sensitivity = 'high'",
        ),
    ] {
        let AstStmt::AlterView(view) = one_statement(sql) else {
            panic!("{sql}: not read as ALTER VIEW");
        };
        let span = match view.action.kind {
            AstAlterViewActionKind::AddRowAccessPolicy { action_span, .. }
            | AstAlterViewActionKind::DropRowAccessPolicy { action_span, .. }
            | AstAlterViewActionKind::AlterColumn { action_span, .. }
            | AstAlterViewActionKind::SetTag { action_span, .. } => action_span,
            other => panic!("{sql}: read as {other:?}"),
        };
        assert_eq!(text(sql, Some(span)), expected);
    }
}

#[test]
fn alter_view_with_no_policy_name_is_not_read() {
    let sql = "ALTER VIEW crm.v ADD ROW ACCESS POLICY 1 ON (region);";
    assert!(
        matches!(one_statement(sql), AstStmt::OpaqueContent { .. }),
        "{sql}"
    );
}

#[test]
fn create_table_reads_a_columns_masking_policy_name_whole() {
    for (sql, expected) in [
        (
            "CREATE TABLE crm.c (email STRING MASKING POLICY gov.comment.mask_email COMMENT 'x');",
            "MASKING POLICY gov.comment.mask_email",
        ),
        (
            "CREATE TABLE crm.c (email STRING WITH MASKING POLICY d1.tag.mask_email NOT NULL);",
            "MASKING POLICY d1.tag.mask_email",
        ),
    ] {
        let AstStmt::CreateTable(table) = one_statement(sql) else {
            panic!("{sql}: not read as CREATE TABLE");
        };
        assert_eq!(text(sql, table.columns[0].masking_policy_span), expected);
    }
}

#[test]
fn create_table_reads_the_names_its_options_hold_whole() {
    let sql = "CREATE TABLE crm.o (id INT) WITH TAG (gov.comment.cost_center = 'x');";
    let AstStmt::CreateTable(table) = one_statement(sql) else {
        panic!("{sql}: not read as CREATE TABLE");
    };
    assert_eq!(
        text(sql, table.tag_span),
        "WITH TAG (gov.comment.cost_center = 'x')"
    );
    assert_eq!(table.table_comment_span, None, "{sql}");
    assert_eq!(table.with_contact_span, None, "{sql}");

    let sql = "CREATE TABLE crm.o (id INT) WITH ROW ACCESS POLICY gov.tag.rap ON (id);";
    let AstStmt::CreateTable(table) = one_statement(sql) else {
        panic!("{sql}: not read as CREATE TABLE");
    };
    assert_eq!(
        text(sql, table.with_row_access_policy_span),
        "WITH ROW ACCESS POLICY gov.tag.rap ON (id)"
    );
    assert_eq!(table.row_access_policy_span, None, "{sql}");
    assert_eq!(table.tag_span, None, "{sql}");
}

#[test]
fn create_table_reads_a_clone_or_like_source_whole() {
    for (sql, expected) in [
        (
            "CREATE TABLE crm.o CLONE d1.copy.orders_src;",
            "CLONE d1.copy.orders_src",
        ),
        (
            "CREATE TABLE crm.o CLONE d1.at.orders_src AT (OFFSET => -60);",
            "CLONE d1.at.orders_src",
        ),
    ] {
        let AstStmt::CreateTable(table) = one_statement(sql) else {
            panic!("{sql}: not read as CREATE TABLE");
        };
        assert_eq!(text(sql, table.clone_source_span), expected);
    }
    let sql = "CREATE TABLE crm.o LIKE d1.tag.orders_src;";
    let AstStmt::CreateTable(table) = one_statement(sql) else {
        panic!("{sql}: not read as CREATE TABLE");
    };
    assert_eq!(text(sql, table.like_source_span), "LIKE d1.tag.orders_src");
}

fn table_in(dialect: &DialectRef, sql: &str) -> AstCreateTable {
    let script = parse_sql_with_dialect(sql, &**dialect).unwrap_or_else(|e| panic!("{sql}: {e:?}"));
    let [AstStmt::CreateTable(table)] = <[AstStmt; 1]>::try_from(script.stmts)
        .unwrap_or_else(|stmts| panic!("{sql}: expected one statement, got {stmts:?}"))
    else {
        panic!("{sql}: not read as CREATE TABLE");
    };
    *table
}

fn name_text<'a>(sql: &'a str, name: Option<&AstObjectRef>) -> &'a str {
    text(sql, name.map(|name| name.span))
}

fn formats_token_safe(dialect: &DialectRef, sql: &str) {
    let config = FormatterConfig {
        dialect: dialect.clone(),
        ..Default::default()
    };
    let formatted = format_sql_with_config(sql, &config).unwrap_or_else(|e| panic!("{sql}: {e:?}"));
    verify_formatting_safe_with_dialect(sql, &formatted, &**dialect)
        .unwrap_or_else(|e| panic!("{sql}: {e}\n{formatted}"));
}

#[test]
fn create_table_keeps_the_table_a_like_or_clone_names() {
    let snowflake = dialect::snowflake();
    for (sql, like, clone) in [
        ("CREATE TABLE crm.o LIKE orders_src;", "orders_src", ""),
        (
            "CREATE TABLE crm.o LIKE d1.s1.orders_src COPY GRANTS;",
            "d1.s1.orders_src",
            "",
        ),
        (
            "CREATE TABLE crm.o LIKE \"D1\".\"S 1\".\"ORDERS_SRC X\";",
            "\"D1\".\"S 1\".\"ORDERS_SRC X\"",
            "",
        ),
        ("CREATE TABLE crm.o CLONE orders_src;", "", "orders_src"),
        (
            "CREATE TABLE crm.o CLONE d1.stage.orders_src;",
            "",
            "d1.stage.orders_src",
        ),
        (
            "CREATE TABLE crm.o CLONE d1.s1.orders_src AT (OFFSET => -60) COPY GRANTS;",
            "",
            "d1.s1.orders_src",
        ),
    ] {
        let table = table_in(&snowflake, sql);
        if like.is_empty() {
            assert!(table.like_source.is_none(), "{sql}");
        } else {
            assert_eq!(name_text(sql, table.like_source.as_ref()), like, "{sql}");
        }
        if clone.is_empty() {
            assert!(table.clone_source.is_none(), "{sql}");
        } else {
            assert_eq!(name_text(sql, table.clone_source.as_ref()), clone, "{sql}");
        }
        assert!(table.copy_source.is_none(), "{sql}");
        formats_token_safe(&snowflake, sql);
    }
}

#[test]
fn create_table_keeps_the_table_a_bigquery_or_mysql_like_or_clone_names() {
    let bigquery = dialect::bigquery();
    for (sql, like, clone) in [
        (
            "CREATE TABLE ds.o LIKE my-proj.s1.orders_src;",
            "my-proj.s1.orders_src",
            "",
        ),
        (
            "CREATE TABLE ds.o LIKE `my-proj.s1.orders_src`;",
            "`my-proj.s1.orders_src`",
            "",
        ),
        (
            "CREATE TABLE ds.o CLONE s1.orders_src;",
            "",
            "s1.orders_src",
        ),
        (
            "CREATE TABLE ds.o CLONE proj1.stage.orders_src;",
            "",
            "proj1.stage.orders_src",
        ),
    ] {
        let table = table_in(&bigquery, sql);
        let held =
            |source: &Option<AstObjectRef>| source.as_ref().map(|name| text(sql, Some(name.span)));
        assert_eq!(held(&table.like_source).unwrap_or(""), like, "{sql}");
        assert_eq!(held(&table.clone_source).unwrap_or(""), clone, "{sql}");
        formats_token_safe(&bigquery, sql);
    }
    let mysql = dialect::mysql();
    for (sql, like) in [
        ("CREATE TABLE shop.o LIKE orders_src;", "orders_src"),
        (
            "CREATE TABLE shop.o LIKE `S 1`.`ORDERS_SRC X`;",
            "`S 1`.`ORDERS_SRC X`",
        ),
        (
            "CREATE TABLE shop.o LIKE stage.orders_src;",
            "stage.orders_src",
        ),
    ] {
        let table = table_in(&mysql, sql);
        assert_eq!(name_text(sql, table.like_source.as_ref()), like, "{sql}");
        formats_token_safe(&mysql, sql);
    }
}

#[test]
fn bigquery_copy_names_the_copied_table_not_copy_grants() {
    let bigquery = dialect::bigquery();
    for (sql, copied) in [
        ("CREATE TABLE ds.o COPY orders_src;", "orders_src"),
        (
            "CREATE TABLE ds.o COPY my-proj.s1.orders_src;",
            "my-proj.s1.orders_src",
        ),
        (
            "CREATE TABLE ds.o COPY `my-proj.s1.orders_src`;",
            "`my-proj.s1.orders_src`",
        ),
        (
            "CREATE TABLE ds.o COPY s1.orders_src OPTIONS (description = 'x');",
            "s1.orders_src",
        ),
    ] {
        let table = table_in(&bigquery, sql);
        assert_eq!(table.variant, AstCreateTableVariant::Copy, "{sql}");
        assert_eq!(name_text(sql, table.copy_source.as_ref()), copied, "{sql}");
        assert_eq!(table.copy_grants_span, None, "{sql}");
        assert_eq!(table.copy_tags_span, None, "{sql}");
        formats_token_safe(&bigquery, sql);
    }
}

#[test]
fn snowflake_copy_grants_and_copy_tags_are_no_copied_table() {
    let snowflake = dialect::snowflake();
    let sql = "CREATE TABLE crm.o (id INT) COPY GRANTS;";
    let table = table_in(&snowflake, sql);
    assert_eq!(table.variant, AstCreateTableVariant::Plain, "{sql}");
    assert_eq!(text(sql, table.copy_grants_span), "COPY GRANTS");
    assert!(table.copy_source.is_none(), "{sql}");

    let sql = "CREATE TABLE crm.o COPY GRANTS AS SELECT 1 AS id;";
    let table = table_in(&snowflake, sql);
    assert_eq!(table.variant, AstCreateTableVariant::Ctas, "{sql}");
    assert_eq!(text(sql, table.copy_grants_span), "COPY GRANTS");
    assert!(table.copy_source.is_none(), "{sql}");

    let sql = "CREATE TABLE crm.o LIKE crm.src COPY TAGS;";
    let table = table_in(&snowflake, sql);
    assert_eq!(table.variant, AstCreateTableVariant::Like, "{sql}");
    assert_eq!(text(sql, table.copy_tags_span), "COPY TAGS");
    assert!(table.copy_source.is_none(), "{sql}");
}

#[test]
fn postgres_partition_of_names_the_parent_and_keeps_the_bound() {
    let postgres = dialect::postgres();
    for (sql, parent, clause) in [
        (
            "CREATE TABLE crm.o_2024 PARTITION OF orders FOR VALUES FROM ('2024-01-01') TO ('2025-01-01');",
            "orders",
            "PARTITION OF orders FOR VALUES FROM ('2024-01-01') TO ('2025-01-01')",
        ),
        (
            "CREATE TABLE crm.o_2024 PARTITION OF d1.s1.orders FOR VALUES IN ('a', 'b');",
            "d1.s1.orders",
            "PARTITION OF d1.s1.orders FOR VALUES IN ('a', 'b')",
        ),
        (
            "CREATE TABLE crm.o_2024 PARTITION OF \"S 1\".\"ORDERS X\" FOR VALUES WITH (MODULUS 4, REMAINDER 0);",
            "\"S 1\".\"ORDERS X\"",
            "PARTITION OF \"S 1\".\"ORDERS X\" FOR VALUES WITH (MODULUS 4, REMAINDER 0)",
        ),
        (
            "CREATE TABLE crm.o_other PARTITION OF crm.orders DEFAULT;",
            "crm.orders",
            "PARTITION OF crm.orders DEFAULT",
        ),
        (
            "CREATE TABLE crm.o_2024 PARTITION OF orders FOR VALUES FROM (1) TO (2) PARTITION BY HASH (id);",
            "orders",
            "PARTITION OF orders FOR VALUES FROM (1) TO (2)",
        ),
    ] {
        let table = table_in(&postgres, sql);
        assert_eq!(name_text(sql, table.partition_of.as_ref()), parent, "{sql}");
        assert!(sql.contains(clause), "{sql}");
        let partition_by = text(sql, table.partition_by_span);
        assert!(partition_by.starts_with(clause), "{sql}: {partition_by}");
        assert_eq!(table.variant, AstCreateTableVariant::Plain, "{sql}");
        assert_eq!(table.with_contact_span, None, "{sql}");
        assert!(table.ctas_query.is_none(), "{sql}");
        formats_token_safe(&postgres, sql);
    }
}

#[test]
fn postgres_partition_by_is_no_partition_of() {
    let postgres = dialect::postgres();
    let sql = "CREATE TABLE crm.o (id INT, ts DATE) PARTITION BY RANGE (ts);";
    let table = table_in(&postgres, sql);
    assert!(table.partition_of.is_none(), "{sql}");
    assert_eq!(
        text(sql, table.partition_by_span),
        "PARTITION BY RANGE (ts)"
    );
}

#[test]
fn postgres_inherits_names_every_parent() {
    let postgres = dialect::postgres();
    for (sql, parents) in [
        (
            "CREATE TABLE crm.o (id INT) INHERITS (base_orders);",
            vec!["base_orders"],
        ),
        (
            "CREATE TABLE crm.o (id INT) INHERITS (d1.s1.base_orders, \"S 1\".\"BASE X\");",
            vec!["d1.s1.base_orders", "\"S 1\".\"BASE X\""],
        ),
        (
            "CREATE TABLE crm.o (id INT) INHERITS (d1.stage.base_orders) WITH (fillfactor = 70);",
            vec!["d1.stage.base_orders"],
        ),
    ] {
        let table = table_in(&postgres, sql);
        let names: Vec<&str> = table
            .inherits
            .iter()
            .map(|name| name_text(sql, Some(name)))
            .collect();
        assert_eq!(names, parents, "{sql}");
        assert_eq!(table.columns.len(), 1, "{sql}");
    }
    let sql = "CREATE TABLE crm.o (id INT) WITH (fillfactor = 70);";
    assert!(table_in(&postgres, sql).inherits.is_empty(), "{sql}");
}

#[test]
fn postgres_like_items_are_tables_not_columns() {
    let postgres = dialect::postgres();
    for (sql, tables) in [
        (
            "CREATE TABLE crm.copy (LIKE orders INCLUDING ALL);",
            vec!["orders"],
        ),
        (
            "CREATE TABLE crm.copy (id INT, LIKE d1.s1.orders EXCLUDING INDEXES, LIKE \"S 1\".\"ORDERS X\", note TEXT);",
            vec!["d1.s1.orders", "\"S 1\".\"ORDERS X\""],
        ),
    ] {
        let table = table_in(&postgres, sql);
        let names: Vec<&str> = table
            .like_elements
            .iter()
            .map(|item| name_text(sql, Some(&item.table)))
            .collect();
        assert_eq!(names, tables, "{sql}");
        let columns: Vec<&str> = table
            .columns
            .iter()
            .map(|column| text(sql, column.name_span))
            .collect();
        assert!(
            columns.iter().all(|column| ["id", "note"].contains(column)),
            "{sql}: {columns:?}"
        );
        assert!(table.like_source.is_none(), "{sql}");
    }
}

#[test]
fn create_stage_keeps_the_stage_a_clone_names() {
    let snowflake = dialect::snowflake();
    for (sql, source) in [
        ("CREATE STAGE s2 CLONE my_s3_stage;", "my_s3_stage"),
        (
            "CREATE STAGE s2 CLONE d1.s1.my_s3_stage;",
            "d1.s1.my_s3_stage",
        ),
        (
            "CREATE STAGE s2 CLONE \"D1\".\"S 1\".\"MY STAGE\" COMMENT = 'x';",
            "\"D1\".\"S 1\".\"MY STAGE\"",
        ),
    ] {
        let script =
            parse_sql_with_dialect(sql, &*snowflake).unwrap_or_else(|e| panic!("{sql}: {e:?}"));
        let [AstStmt::CreateStage(stage)] = script.stmts.as_slice() else {
            panic!("{sql}: not read as CREATE STAGE: {:?}", script.stmts);
        };
        assert_eq!(name_text(sql, stage.clone_source.as_ref()), source, "{sql}");
        assert!(text(sql, stage.clone_clause).starts_with("CLONE"), "{sql}");
        formats_token_safe(&snowflake, sql);
    }
}

/// The columns, referenced table and referenced columns of a foreign key.
fn foreign_key_texts<'a>(
    sql: &'a str,
    details: Option<&AstConstraintDetails>,
) -> (Vec<&'a str>, &'a str, Vec<&'a str>) {
    let AstConstraintKind::ForeignKey {
        columns,
        references_table,
        references_columns,
    } = &details
        .unwrap_or_else(|| panic!("{sql}: no foreign key"))
        .kind
    else {
        panic!("{sql}: not a foreign key");
    };
    let texts =
        |spans: &[Span]| -> Vec<&'a str> { spans.iter().map(|s| text(sql, Some(*s))).collect() };
    (
        texts(columns),
        text(sql, Some(references_table.span)),
        texts(references_columns),
    )
}

#[test]
fn create_table_keeps_the_table_a_columns_references_names() {
    for (dialect, sql, target, referenced) in [
        (
            dialect::snowflake(),
            "CREATE TABLE crm.o (id INT, account_id INT REFERENCES accounts (id));",
            "accounts",
            vec!["id"],
        ),
        (
            dialect::snowflake(),
            "CREATE TABLE crm.o (id INT, account_id INT REFERENCES d1.stage.accounts (id) ON DELETE CASCADE);",
            "d1.stage.accounts",
            vec!["id"],
        ),
        (
            dialect::snowflake(),
            "CREATE TABLE crm.o (id INT, account_id INT REFERENCES \"D1\".\"S 1\".\"ACCOUNTS X\" (id));",
            "\"D1\".\"S 1\".\"ACCOUNTS X\"",
            vec!["id"],
        ),
        (
            dialect::postgres(),
            "CREATE TABLE crm.o (id INT, account_id INT REFERENCES s1.accounts);",
            "s1.accounts",
            vec![],
        ),
        (
            dialect::postgres(),
            "CREATE TABLE crm.o (id INT, account_id INT CONSTRAINT fk_acct REFERENCES {{ target.schema }}.accounts (a, b) ON UPDATE CASCADE);",
            "{{ target.schema }}.accounts",
            vec!["a", "b"],
        ),
    ] {
        let table = table_in(&dialect, sql);
        let column = table
            .columns
            .iter()
            .find(|c| c.foreign_key.is_some())
            .unwrap_or_else(|| panic!("{sql}: no column with a foreign key"));
        let (columns, table_text, referenced_columns) =
            foreign_key_texts(sql, column.foreign_key.as_ref());
        assert_eq!(columns, ["account_id"], "{sql}");
        assert_eq!(table_text, target, "{sql}");
        assert_eq!(referenced_columns, referenced, "{sql}");
        assert!(table.columns[0].foreign_key.is_none(), "{sql}");
        formats_token_safe(&dialect, sql);
    }
}

#[test]
fn a_columns_references_keeps_the_constraint_name() {
    let sql = "CREATE TABLE crm.o (account_id INT CONSTRAINT fk_acct REFERENCES accounts (id));";
    let table = table_in(&dialect::snowflake(), sql);
    let details = table.columns[0].foreign_key.as_ref().expect("foreign key");
    assert_eq!(text(sql, details.name), "fk_acct");
}

#[test]
fn a_table_level_foreign_key_keeps_its_target_with_or_without_a_column_list() {
    for (sql, target, referenced) in [
        (
            "CREATE TABLE crm.o (a INT, FOREIGN KEY (a) REFERENCES d1.s1.accounts (id));",
            "d1.s1.accounts",
            vec!["id"],
        ),
        (
            "CREATE TABLE crm.o (a INT, CONSTRAINT fk FOREIGN KEY (a) REFERENCES \"S 1\".\"ACCOUNTS X\");",
            "\"S 1\".\"ACCOUNTS X\"",
            vec![],
        ),
    ] {
        let table = table_in(&dialect::postgres(), sql);
        let (columns, table_text, referenced_columns) =
            foreign_key_texts(sql, table.constraints[0].details.as_ref());
        assert_eq!(columns, ["a"], "{sql}");
        assert_eq!(table_text, target, "{sql}");
        assert_eq!(referenced_columns, referenced, "{sql}");
    }
}

#[test]
fn alter_table_add_foreign_key_keeps_its_target() {
    for (dialect, sql, target, referenced, constraint) in [
        (
            dialect::snowflake(),
            "ALTER TABLE crm.o ADD CONSTRAINT fk_acct FOREIGN KEY (account_id) REFERENCES accounts (id);",
            "accounts",
            vec!["id"],
            true,
        ),
        (
            dialect::postgres(),
            "ALTER TABLE crm.o ADD CONSTRAINT fk_acct FOREIGN KEY (account_id) REFERENCES d1.stage.accounts (id) ON DELETE SET NULL;",
            "d1.stage.accounts",
            vec!["id"],
            true,
        ),
        (
            dialect::postgres(),
            "ALTER TABLE crm.o ADD CONSTRAINT fk_acct FOREIGN KEY (account_id) REFERENCES \"S 1\".\"ACCOUNTS X\";",
            "\"S 1\".\"ACCOUNTS X\"",
            vec![],
            true,
        ),
        (
            dialect::snowflake(),
            "ALTER TABLE crm.o ADD FOREIGN KEY (account_id) REFERENCES IDENTIFIER('d1.s1.accounts') (id);",
            "IDENTIFIER('d1.s1.accounts')",
            vec!["id"],
            false,
        ),
        (
            dialect::postgres(),
            "ALTER TABLE crm.o ADD FOREIGN KEY (account_id) REFERENCES s1.accounts (id);",
            "s1.accounts",
            vec!["id"],
            false,
        ),
    ] {
        let script =
            parse_sql_with_dialect(sql, &*dialect).unwrap_or_else(|e| panic!("{sql}: {e:?}"));
        let [AstStmt::AlterTable(alter)] = script.stmts.as_slice() else {
            panic!("{sql}: not read as ALTER TABLE: {:?}", script.stmts);
        };
        let [action] = alter.actions.as_slice() else {
            panic!("{sql}: {:?}", alter.actions);
        };
        let AstAlterTableActionKind::AddConstraint {
            constraint_span,
            details,
            ..
        } = &action.kind
        else {
            panic!("{sql}: read as {:?}", action.kind);
        };
        assert_eq!(constraint_span.is_some(), constraint, "{sql}");
        let (columns, table_text, referenced_columns) = foreign_key_texts(sql, details.as_ref());
        assert_eq!(columns, ["account_id"], "{sql}");
        assert_eq!(table_text, target, "{sql}");
        assert_eq!(referenced_columns, referenced, "{sql}");
        formats_token_safe(&dialect, sql);
    }
}

#[test]
fn alter_table_add_column_keeps_the_references_target() {
    let sql = "ALTER TABLE crm.o ADD COLUMN account_id INT REFERENCES d1.s1.accounts (id) ON DELETE CASCADE;";
    let snowflake = dialect::snowflake();
    let script =
        parse_sql_with_dialect(sql, &*snowflake).unwrap_or_else(|e| panic!("{sql}: {e:?}"));
    let [AstStmt::AlterTable(alter)] = script.stmts.as_slice() else {
        panic!("{sql}: not read as ALTER TABLE");
    };
    let AstAlterTableActionKind::AddColumn { columns, .. } = &alter.actions[0].kind else {
        panic!("{sql}: not ADD COLUMN");
    };
    let (key_columns, table_text, referenced) =
        foreign_key_texts(sql, columns[0].foreign_key.as_ref());
    assert_eq!(key_columns, ["account_id"], "{sql}");
    assert_eq!(table_text, "d1.s1.accounts", "{sql}");
    assert_eq!(referenced, ["id"], "{sql}");
    formats_token_safe(&snowflake, sql);
}

fn alter_actions(dialect: &DialectRef, sql: &str) -> Vec<lexega_syntax::ast::AstAlterTableAction> {
    let script = parse_sql_with_dialect(sql, &**dialect).unwrap_or_else(|e| panic!("{sql}: {e:?}"));
    let Some(AstStmt::AlterTable(alter)) = script.stmts.first() else {
        panic!("{sql}: not read as ALTER TABLE: {:?}", script.stmts);
    };
    formats_token_safe(dialect, sql);
    alter.actions.clone()
}

#[test]
fn alter_table_owner_and_schema_actions_keep_the_name() {
    for (dialect, sql, owner, schema) in [
        (
            dialect::postgres(),
            "ALTER TABLE crm.o OWNER TO app_owner;",
            Some("app_owner"),
            None,
        ),
        (
            dialect::postgres(),
            "ALTER TABLE crm.o OWNER TO \"APP OWNER\";",
            Some("\"APP OWNER\""),
            None,
        ),
        (
            dialect::postgres(),
            "ALTER TABLE crm.o OWNER TO CURRENT_USER;",
            None,
            None,
        ),
        (
            dialect::redshift(),
            "ALTER TABLE crm.o OWNER TO app_owner_{{ var('env') }};",
            Some("app_owner_{{ var('env') }}"),
            None,
        ),
        (
            dialect::databricks(),
            "ALTER TABLE main.crm.o OWNER TO `DATA ENG`;",
            Some("`DATA ENG`"),
            None,
        ),
        (
            dialect::postgres(),
            "ALTER TABLE crm.o SET SCHEMA archive;",
            None,
            Some("archive"),
        ),
        (
            dialect::postgres(),
            "ALTER TABLE crm.o SET SCHEMA \"ARCHIVE X\";",
            None,
            Some("\"ARCHIVE X\""),
        ),
        (
            dialect::postgres(),
            "ALTER TABLE crm.o OWNER TO bob, SET SCHEMA archive_{{ var('env') }};",
            Some("bob"),
            Some("archive_{{ var('env') }}"),
        ),
    ] {
        let actions = alter_actions(&dialect, sql);
        let named_owner = actions.iter().find_map(|action| match &action.kind {
            AstAlterTableActionKind::OwnerTo { owner } => Some(text(sql, Some(*owner))),
            _ => None,
        });
        let named_schema = actions.iter().find_map(|action| match &action.kind {
            AstAlterTableActionKind::SetSchema { schema } => Some(text(sql, Some(*schema))),
            _ => None,
        });
        assert_eq!(named_owner, owner, "{sql}");
        assert_eq!(named_schema, schema, "{sql}");
    }
}

#[test]
fn alter_table_owner_or_schema_with_no_name_stays_the_generic_action() {
    let postgres = dialect::postgres();
    for sql in [
        "ALTER TABLE crm.o OWNER TO;",
        "ALTER TABLE crm.o SET SCHEMA;",
    ] {
        for action in alter_actions(&postgres, sql) {
            assert!(
                !matches!(
                    action.kind,
                    AstAlterTableActionKind::OwnerTo { .. }
                        | AstAlterTableActionKind::SetSchema { .. }
                ),
                "{sql}: read as {:?}",
                action.kind
            );
        }
    }
}

#[test]
fn postgres_attach_and_detach_partition_keep_the_partition_and_the_bound() {
    let postgres = dialect::postgres();
    for (sql, partition, bound, mode) in [
        (
            "ALTER TABLE crm.o ATTACH PARTITION o_2024 FOR VALUES FROM ('2024-01-01') TO ('2025-01-01');",
            "o_2024",
            Some("FOR VALUES FROM ('2024-01-01') TO ('2025-01-01')"),
            None,
        ),
        (
            "ALTER TABLE crm.o ATTACH PARTITION d1.s1.o_2024 FOR VALUES IN (1, 2);",
            "d1.s1.o_2024",
            Some("FOR VALUES IN (1, 2)"),
            None,
        ),
        (
            "ALTER TABLE crm.o ATTACH PARTITION \"S 1\".\"O X\" DEFAULT;",
            "\"S 1\".\"O X\"",
            Some("DEFAULT"),
            None,
        ),
        (
            "ALTER TABLE crm.o ATTACH PARTITION {{ target.schema }}.o_h FOR VALUES WITH (MODULUS 4, REMAINDER 0);",
            "{{ target.schema }}.o_h",
            Some("FOR VALUES WITH (MODULUS 4, REMAINDER 0)"),
            None,
        ),
        (
            "ALTER TABLE crm.o DETACH PARTITION s1.o_2024;",
            "s1.o_2024",
            None,
            None,
        ),
        (
            "ALTER TABLE crm.o DETACH PARTITION o_2024 CONCURRENTLY;",
            "o_2024",
            None,
            Some("CONCURRENTLY"),
        ),
        (
            "ALTER TABLE crm.o ATTACH PARTITION p1 FOR VALUES IN (1), ATTACH PARTITION p2 DEFAULT;",
            "p1",
            Some("FOR VALUES IN (1)"),
            None,
        ),
    ] {
        let actions = alter_actions(&postgres, sql);
        let (named, named_bound, named_mode) = match &actions[0].kind {
            AstAlterTableActionKind::AttachPartition { partition, bound } => (
                name_text(sql, Some(partition)),
                Some(text(sql, Some(*bound))),
                None,
            ),
            AstAlterTableActionKind::DetachPartition { partition, mode } => (
                name_text(sql, Some(partition)),
                None,
                mode.map(|mode| text(sql, Some(mode))),
            ),
            other => panic!("{sql}: read as {other:?}"),
        };
        assert_eq!(named, partition, "{sql}");
        assert_eq!(named_bound, bound, "{sql}");
        assert_eq!(named_mode, mode, "{sql}");
    }
}

#[test]
fn tsql_switch_keeps_the_target_table() {
    let mssql = dialect::mssql();
    for (sql, target) in [
        ("ALTER TABLE dbo.o SWITCH TO dbo.archive;", "dbo.archive"),
        (
            "ALTER TABLE dbo.o SWITCH PARTITION 2 TO [dbo].[archive] PARTITION 2;",
            "[dbo].[archive]",
        ),
        (
            "ALTER TABLE dbo.o SWITCH TO db1.dbo.archive WITH (WAIT_AT_LOW_PRIORITY (MAX_DURATION = 1 MINUTES, ABORT_AFTER_WAIT = NONE))\nSELECT 1",
            "db1.dbo.archive",
        ),
    ] {
        let actions = alter_actions(&mssql, sql);
        let AstAlterTableActionKind::SwitchTo { target: named } = &actions[0].kind else {
            panic!("{sql}: read as {:?}", actions[0].kind);
        };
        assert_eq!(name_text(sql, Some(named)), target, "{sql}");
    }
}

#[test]
fn alter_table_drop_column_keeps_every_dropped_name() {
    for (dialect, sql, columns, actions) in [
        (
            dialect::snowflake(),
            "ALTER TABLE crm.c DROP COLUMN email;",
            vec!["email"],
            1,
        ),
        (
            dialect::snowflake(),
            "ALTER TABLE crm.c DROP COLUMN \"EMAIL X\";",
            vec!["\"EMAIL X\""],
            1,
        ),
        (
            dialect::snowflake(),
            "ALTER TABLE crm.c DROP COLUMN IF EXISTS email;",
            vec!["email"],
            1,
        ),
        (
            dialect::snowflake(),
            "ALTER TABLE crm.c DROP COLUMN a, b, c;",
            vec!["a", "b", "c"],
            1,
        ),
        (
            dialect::mssql(),
            "ALTER TABLE dbo.c DROP COLUMN IF EXISTS [a], [b]\nSELECT 1",
            vec!["[a]", "[b]"],
            1,
        ),
        (
            dialect::postgres(),
            "ALTER TABLE crm.c DROP COLUMN a CASCADE;",
            vec!["a"],
            1,
        ),
        (
            dialect::postgres(),
            "ALTER TABLE crm.c DROP COLUMN a, b CASCADE;",
            vec!["a"],
            2,
        ),
        (
            dialect::databricks(),
            "ALTER TABLE main.crm.c DROP COLUMNS (a, `B X`);",
            vec!["a", "`B X`"],
            1,
        ),
    ] {
        let found = alter_actions(&dialect, sql);
        assert_eq!(found.len(), actions, "{sql}");
        let AstAlterTableActionKind::DropColumn { columns: named, .. } = &found[0].kind else {
            panic!("{sql}: read as {:?}", found[0].kind);
        };
        let named: Vec<&str> = named.iter().map(|c| text(sql, Some(*c))).collect();
        assert_eq!(named, columns, "{sql}");
    }
}

#[test]
fn alter_table_actions_ending_the_source_format_token_safe() {
    for (dialect, sql) in [
        (dialect::postgres(), "ALTER TABLE crm.o OWNER TO bob"),
        (dialect::postgres(), "ALTER TABLE crm.o SET SCHEMA archive"),
        (
            dialect::postgres(),
            "ALTER TABLE crm.o ATTACH PARTITION p1 FOR VALUES IN (1)",
        ),
        (
            dialect::postgres(),
            "ALTER TABLE crm.o DETACH PARTITION p1 CONCURRENTLY",
        ),
        (dialect::mssql(), "ALTER TABLE dbo.o SWITCH TO dbo.archive"),
        (dialect::snowflake(), "ALTER TABLE crm.o DROP COLUMN a, b"),
        (
            dialect::databricks(),
            "ALTER TABLE main.crm.o DROP COLUMNS (a, b)",
        ),
    ] {
        alter_actions(&dialect, sql);
    }
}

#[test]
fn alter_table_drop_column_list_ends_where_the_next_action_starts() {
    let postgres = dialect::postgres();
    let sql = "ALTER TABLE crm.c DROP COLUMN a, DROP COLUMN b, SET SCHEMA archive;";
    let found = alter_actions(&postgres, sql);
    let named: Vec<Vec<&str>> = found
        .iter()
        .map(|action| match &action.kind {
            AstAlterTableActionKind::DropColumn { columns, .. } => {
                columns.iter().map(|c| text(sql, Some(*c))).collect()
            }
            AstAlterTableActionKind::SetSchema { .. } => vec!["schema"],
            other => panic!("{sql}: read as {other:?}"),
        })
        .collect();
    assert_eq!(named, [vec!["a"], vec!["b"], vec!["schema"]], "{sql}");
}
