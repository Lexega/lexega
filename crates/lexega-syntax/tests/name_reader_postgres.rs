// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! The shapes PostgreSQL names are written in, each read whole as the name it is.

mod name_shapes;

use lexega_syntax::ast::{AlterDomainAction, AstGrantShape, AstRevokeShape, AstUnloadSource};
use lexega_syntax::dialect;
use lexega_syntax::{
    format_sql_with_config, parse_sql_with_dialect, verify_formatting_safe_with_dialect, AstStmt,
    DialectRef, FormatterConfig, Span,
};
use name_shapes::reads_whole;

fn one_statement(sql: &str, dialect: &DialectRef) -> AstStmt {
    let script = parse_sql_with_dialect(sql, &**dialect).unwrap_or_else(|e| panic!("{sql}: {e:?}"));
    let [stmt] = <[AstStmt; 1]>::try_from(script.stmts)
        .unwrap_or_else(|stmts| panic!("{sql}: expected one statement, got {stmts:?}"));
    stmt
}

fn at(sql: &str, span: Span) -> &str {
    &sql[span.start as usize..span.end as usize]
}

fn formats_without_loss(sql: &str, dialect: &DialectRef) {
    let config = FormatterConfig {
        dialect: dialect.clone(),
        ..FormatterConfig::default()
    };
    let formatted = format_sql_with_config(sql, &config).unwrap_or_else(|e| panic!("{sql}: {e:?}"));
    verify_formatting_safe_with_dialect(sql, &formatted, config.dialect.as_ref())
        .unwrap_or_else(|e| panic!("{sql}: {e}"));
}

/// The ways a one-part name is written.
const ONE_PART_NAMES: [&str; 3] = ["ext_x", "\"EXT X\"", "ext_{{ var('env') }}"];

#[test]
fn postgres_select_cast_x_as_schema_type() {
    reads_whole(
        &dialect::postgres(),
        &[
            "SELECT CAST('a' AS «s1.status_t»);",
            "SELECT CAST('a' AS «\"S 1\".\"STATUS_T X\"»);",
            "SELECT CAST('a' AS «{{ target.schema }}.status_t»);",
            "SELECT CAST('a' AS «stage.status_t»);",
        ],
    );
}

#[test]
fn postgres_alter_domain_domain_name() {
    reads_whole(
        &dialect::postgres(),
        &[
            "ALTER DOMAIN «d1.s1.email_t» SET NOT NULL;",
            "ALTER DOMAIN «\"D1\".\"S 1\".\"EMAIL_T X\"» SET NOT NULL;",
            "ALTER DOMAIN «d1.stage.email_t» SET NOT NULL;",
        ],
    );
}

#[test]
fn postgres_create_domain_domain_name() {
    reads_whole(
        &dialect::postgres(),
        &[
            "CREATE DOMAIN «d1.s1.email_t» AS TEXT CHECK (VALUE LIKE '%@%');",
            "CREATE DOMAIN «\"D1\".\"S 1\".\"EMAIL_T X\"» AS TEXT CHECK (VALUE LIKE '%@%');",
            "CREATE DOMAIN «d1.stage.email_t» AS TEXT CHECK (VALUE LIKE '%@%');",
        ],
    );
}

#[test]
fn postgres_drop_domain_domain_name() {
    reads_whole(
        &dialect::postgres(),
        &[
            "DROP DOMAIN «d1.s1.email_t»;",
            "DROP DOMAIN «\"D1\".\"S 1\".\"EMAIL_T X\"»;",
            "DROP DOMAIN «d1.stage.email_t»;",
        ],
    );
}

#[test]
fn postgres_alter_policy_on_table() {
    reads_whole(
        &dialect::postgres(),
        &[
            "ALTER POLICY p_tenant ON «d1.s1.orders» USING (false);",
            "ALTER POLICY p_tenant ON «\"D1\".\"S 1\".\"ORDERS X\"» USING (false);",
            "ALTER POLICY p_tenant ON «d1.stage.orders» USING (false);",
        ],
    );
}

#[test]
fn postgres_drop_policy_on_table() {
    reads_whole(
        &dialect::postgres(),
        &[
            "DROP POLICY p_tenant ON «d1.s1.orders»;",
            "DROP POLICY p_tenant ON «\"D1\".\"S 1\".\"ORDERS X\"»;",
            "DROP POLICY p_tenant ON «d1.stage.orders»;",
        ],
    );
}

#[test]
fn postgres_create_policy_on_table() {
    reads_whole(
        &dialect::postgres(),
        &[
            "CREATE POLICY p_tenant ON «d1.s1.orders» USING (true);",
            "CREATE POLICY p_tenant ON «\"D1\".\"S 1\".\"ORDERS X\"» USING (true);",
            "CREATE POLICY p_tenant ON «d1.stage.orders» USING (true);",
        ],
    );
}

#[test]
fn postgres_drop_rule_on_table() {
    reads_whole(
        &dialect::postgres(),
        &[
            "DROP RULE r_noins ON «d1.s1.orders»;",
            "DROP RULE r_noins ON «\"D1\".\"S 1\".\"ORDERS X\"»;",
            "DROP RULE r_noins ON «d1.stage.orders»;",
        ],
    );
}

#[test]
fn postgres_create_extension_keeps_the_name_and_the_schema() {
    let pg = dialect::postgres();
    for name in ONE_PART_NAMES {
        let sql = format!(
            "CREATE EXTENSION IF NOT EXISTS {name} WITH SCHEMA {name} VERSION '1.1' CASCADE;"
        );
        let AstStmt::CreateExtension(ext) = one_statement(&sql, &pg) else {
            panic!("{sql}: not CREATE EXTENSION");
        };
        assert_eq!(at(&sql, ext.extension_name), name, "{sql}");
        let schema = ext
            .schema_name
            .unwrap_or_else(|| panic!("{sql}: no schema"));
        assert_eq!(at(&sql, schema), name, "{sql}");
        assert!(ext.cascade, "{sql}");
        formats_without_loss(&sql, &pg);
    }
}

#[test]
fn postgres_create_extension_still_reads_a_name_that_is_a_reserved_word() {
    let pg = dialect::postgres();
    let sql = "CREATE EXTENSION user SCHEMA table;";
    let AstStmt::CreateExtension(ext) = one_statement(sql, &pg) else {
        panic!("{sql}: not CREATE EXTENSION");
    };
    assert_eq!(at(sql, ext.extension_name), "user");
    assert_eq!(at(sql, ext.schema_name.expect("schema")), "table");
}

#[test]
fn postgres_alter_domain_keeps_the_new_name_schema_and_owner() {
    let pg = dialect::postgres();
    for name in ONE_PART_NAMES {
        let sql = format!("ALTER DOMAIN crm.email_t RENAME TO {name};");
        let AstStmt::AlterDomain(domain) = one_statement(&sql, &pg) else {
            panic!("{sql}: not ALTER DOMAIN");
        };
        let AlterDomainAction::RenameTo { new_name, .. } = domain.action else {
            panic!("{sql}: {:?}", domain.action);
        };
        assert_eq!(at(&sql, new_name), name, "{sql}");
        formats_without_loss(&sql, &pg);

        let sql = format!("ALTER DOMAIN crm.email_t SET SCHEMA {name};");
        let AstStmt::AlterDomain(domain) = one_statement(&sql, &pg) else {
            panic!("{sql}: not ALTER DOMAIN");
        };
        let AlterDomainAction::SetSchema { new_schema, .. } = domain.action else {
            panic!("{sql}: {:?}", domain.action);
        };
        assert_eq!(at(&sql, new_schema), name, "{sql}");
        formats_without_loss(&sql, &pg);

        let sql = format!("ALTER DOMAIN crm.email_t OWNER TO {name};");
        let AstStmt::AlterDomain(domain) = one_statement(&sql, &pg) else {
            panic!("{sql}: not ALTER DOMAIN");
        };
        let AlterDomainAction::OwnerTo { new_owner, .. } = domain.action else {
            panic!("{sql}: {:?}", domain.action);
        };
        assert_eq!(at(&sql, new_owner), name, "{sql}");
        formats_without_loss(&sql, &pg);
    }
}

#[test]
fn postgres_alter_domain_owner_may_be_current_user() {
    let pg = dialect::postgres();
    let sql = "ALTER DOMAIN crm.email_t OWNER TO CURRENT_USER;";
    let AstStmt::AlterDomain(domain) = one_statement(sql, &pg) else {
        panic!("{sql}: not ALTER DOMAIN");
    };
    let AlterDomainAction::OwnerTo { new_owner, .. } = domain.action else {
        panic!("{sql}: {:?}", domain.action);
    };
    assert_eq!(at(sql, new_owner), "CURRENT_USER");
}

#[test]
fn postgres_create_schema_keeps_the_authorization_role() {
    let pg = dialect::postgres();
    for name in ["app_owner", "\"APP_OWNER X\"", "app_owner_{{ var('env') }}"] {
        for sql in [
            format!("CREATE SCHEMA crm AUTHORIZATION {name};"),
            format!("CREATE SCHEMA IF NOT EXISTS crm AUTHORIZATION {name}"),
        ] {
            let AstStmt::CreateSchema(schema) = one_statement(&sql, &pg) else {
                panic!("{sql}: not CREATE SCHEMA");
            };
            let role = schema
                .authorization
                .unwrap_or_else(|| panic!("{sql}: no authorization"));
            assert_eq!(at(&sql, role), name, "{sql}");
            assert_eq!(at(&sql, schema.name_span), "crm", "{sql}");
            formats_without_loss(&sql, &pg);
        }
    }
}

#[test]
fn postgres_create_schema_authorization_without_a_schema_name_reads_as_before() {
    let pg = dialect::postgres();
    let sql = "CREATE SCHEMA AUTHORIZATION app_owner;";
    let AstStmt::CreateSchema(schema) = one_statement(sql, &pg) else {
        panic!("{sql}: not CREATE SCHEMA");
    };
    assert_eq!(at(sql, schema.name_span), "AUTHORIZATION");
    assert!(schema.authorization.is_none(), "{schema:?}");
}

#[test]
fn postgres_create_schema_authorization_leaves_the_elements_after_it() {
    let pg = dialect::postgres();
    let sql = "CREATE SCHEMA crm AUTHORIZATION app_owner CREATE TABLE t (a int) CREATE VIEW v AS SELECT 1";
    let script = parse_sql_with_dialect(sql, &*pg).unwrap_or_else(|e| panic!("{sql}: {e:?}"));
    let AstStmt::CreateSchema(schema) = &script.stmts[0] else {
        panic!("{sql}: {:?}", script.stmts);
    };
    assert_eq!(at(sql, schema.authorization.expect("role")), "app_owner");
}

/// The ways a table is named.
const TABLE_NAMES: [&str; 5] = [
    "orders",
    "s1.orders",
    "\"D1\".\"S 1\".\"ORDERS X\"",
    "{{ target.schema }}.orders",
    "d1.stage.orders",
];

/// The ways a one-part name is written.
const CHANNEL_NAMES: [&str; 3] = ["ch_orders", "\"CH_ORDERS X\"", "ch_{{ var('env') }}"];

#[test]
fn postgres_drop_function_keeps_each_target_apart_from_its_signature() {
    let pg = dialect::postgres();
    for name in TABLE_NAMES {
        let sql = format!("DROP FUNCTION IF EXISTS {name}(int, text) CASCADE;");
        let AstStmt::Drop(drop) = one_statement(&sql, &pg) else {
            panic!("{sql}: not DROP");
        };
        let [target] = drop.targets.as_slice() else {
            panic!("{sql}: {:?}", drop.targets);
        };
        assert_eq!(at(&sql, target.name.span), name, "{sql}");
        assert_eq!(
            at(&sql, target.signature.expect("signature")),
            "(int, text)",
            "{sql}"
        );
        assert!(drop.cascade_restrict_span.is_some(), "{sql}");
        formats_without_loss(&sql, &pg);
    }
    let sql = "DROP FUNCTION a(int), s1.b(), c;";
    let AstStmt::Drop(drop) = one_statement(sql, &pg) else {
        panic!("{sql}: not DROP");
    };
    let names: Vec<&str> = drop
        .targets
        .iter()
        .map(|target| at(sql, target.name.span))
        .collect();
    assert_eq!(names, ["a", "s1.b", "c"], "{sql}");
}

#[test]
fn postgres_cluster_keeps_the_table_and_the_index() {
    let pg = dialect::postgres();
    for name in TABLE_NAMES {
        for sql in [
            format!("CLUSTER {name} USING idx_orders_acct;"),
            format!("CLUSTER VERBOSE {name} USING idx_orders_acct;"),
            format!("CLUSTER (VERBOSE) {name} USING idx_orders_acct;"),
        ] {
            let AstStmt::PgCluster(cluster) = one_statement(&sql, &pg) else {
                panic!("{sql}: not CLUSTER");
            };
            let table = cluster.table.as_ref().expect("table");
            assert_eq!(at(&sql, table.span), name, "{sql}");
            let index = cluster.index.as_ref().expect("index");
            assert_eq!(at(&sql, index.span), "idx_orders_acct", "{sql}");
            formats_without_loss(&sql, &pg);
        }
    }
}

#[test]
fn postgres_cluster_without_an_index_or_a_table() {
    let pg = dialect::postgres();
    let sql = "CLUSTER s1.orders;";
    let AstStmt::PgCluster(cluster) = one_statement(sql, &pg) else {
        panic!("{sql}: not CLUSTER");
    };
    assert_eq!(at(sql, cluster.table.expect("table").span), "s1.orders");
    assert!(cluster.index.is_none());
    for sql in ["CLUSTER;", "CLUSTER VERBOSE;"] {
        let AstStmt::PgCluster(cluster) = one_statement(sql, &pg) else {
            panic!("{sql}: not CLUSTER");
        };
        assert!(cluster.table.is_none() && cluster.index.is_none(), "{sql}");
    }
    let sql = "CLUSTER idx_orders_acct ON s1.orders;";
    let AstStmt::PgCluster(cluster) = one_statement(sql, &pg) else {
        panic!("{sql}: not CLUSTER");
    };
    assert_eq!(at(sql, cluster.table.expect("table").span), "s1.orders");
    assert_eq!(
        at(sql, cluster.index.expect("index").span),
        "idx_orders_acct"
    );
}

#[test]
fn postgres_lock_keeps_every_table() {
    let pg = dialect::postgres();
    for name in TABLE_NAMES {
        for sql in [
            format!("LOCK TABLE {name} IN ACCESS EXCLUSIVE MODE;"),
            format!("LOCK {name};"),
            format!("LOCK TABLE ONLY {name} * IN SHARE MODE NOWAIT;"),
        ] {
            let AstStmt::PgLockTable(lock) = one_statement(&sql, &pg) else {
                panic!("{sql}: not LOCK");
            };
            let [table] = lock.tables.as_slice() else {
                panic!("{sql}: {:?}", lock.tables);
            };
            assert_eq!(at(&sql, table.span), name, "{sql}");
            formats_without_loss(&sql, &pg);
        }
    }
    let sql = "LOCK TABLE s1.orders, ONLY d1.s1.returns *, \"T X\" IN ROW SHARE MODE;";
    let AstStmt::PgLockTable(lock) = one_statement(sql, &pg) else {
        panic!("{sql}: not LOCK");
    };
    let names: Vec<&str> = lock
        .tables
        .iter()
        .map(|table| at(sql, table.span))
        .collect();
    assert_eq!(names, ["s1.orders", "d1.s1.returns", "\"T X\""], "{sql}");
}

#[test]
fn mysql_lock_tables_keeps_the_tables_and_instance_lock_none() {
    let mysql = dialect::mysql();
    let sql = "LOCK TABLES orders READ, returns AS r WRITE;";
    let AstStmt::PgLockTable(lock) = one_statement(sql, &mysql) else {
        panic!("{sql}: not LOCK");
    };
    let names: Vec<&str> = lock
        .tables
        .iter()
        .map(|table| at(sql, table.span))
        .collect();
    assert_eq!(names, ["orders", "returns"], "{sql}");
    let sql = "LOCK INSTANCE FOR BACKUP;";
    let AstStmt::PgLockTable(lock) = one_statement(sql, &mysql) else {
        panic!("{sql}: not LOCK");
    };
    assert!(lock.tables.is_empty(), "{sql}");
}

#[test]
fn postgres_listen_notify_unlisten_keep_the_channel() {
    let pg = dialect::postgres();
    for name in CHANNEL_NAMES {
        let sql = format!("LISTEN {name};");
        let AstStmt::PgListen(listen) = one_statement(&sql, &pg) else {
            panic!("{sql}: not LISTEN");
        };
        assert_eq!(at(&sql, listen.channel), name, "{sql}");
        formats_without_loss(&sql, &pg);

        let sql = format!("UNLISTEN {name};");
        let AstStmt::PgUnlisten(unlisten) = one_statement(&sql, &pg) else {
            panic!("{sql}: not UNLISTEN");
        };
        assert_eq!(at(&sql, unlisten.channel.expect("channel")), name, "{sql}");
        formats_without_loss(&sql, &pg);

        let sql = format!("NOTIFY {name}, 'order, shipped';");
        let AstStmt::PgNotify(notify) = one_statement(&sql, &pg) else {
            panic!("{sql}: not NOTIFY");
        };
        assert_eq!(at(&sql, notify.channel.expect("channel")), name, "{sql}");
        assert_eq!(
            at(&sql, notify.payload.expect("payload")),
            "'order, shipped'",
            "{sql}"
        );
        formats_without_loss(&sql, &pg);
    }
}

#[test]
fn postgres_unlisten_star_and_notify_without_a_payload() {
    let pg = dialect::postgres();
    let sql = "UNLISTEN *;";
    let AstStmt::PgUnlisten(unlisten) = one_statement(sql, &pg) else {
        panic!("{sql}: not UNLISTEN");
    };
    assert!(unlisten.channel.is_none(), "{sql}");
    assert_eq!(at(sql, unlisten.span), "UNLISTEN *");
    let sql = "NOTIFY ch_orders;";
    let AstStmt::PgNotify(notify) = one_statement(sql, &pg) else {
        panic!("{sql}: not NOTIFY");
    };
    assert_eq!(at(sql, notify.channel.expect("channel")), "ch_orders");
    assert!(notify.payload.is_none(), "{sql}");
}

#[test]
fn postgres_create_sequence_owned_by_keeps_the_table_and_the_column() {
    let pg = dialect::postgres();
    for name in TABLE_NAMES {
        for column in ["id", "\"ID X\""] {
            let sql = format!(
                "CREATE SEQUENCE crm.seq_id START WITH 5 OWNED BY {name}.{column} CACHE 10;"
            );
            let AstStmt::CreateSequence(sequence) = one_statement(&sql, &pg) else {
                panic!("{sql}: not CREATE SEQUENCE");
            };
            let table = sequence.owned_by_table.as_ref().expect("table");
            assert_eq!(at(&sql, table.span), name, "{sql}");
            assert_eq!(
                at(&sql, sequence.owned_by_column.expect("column")),
                column,
                "{sql}"
            );
            assert!(
                at(&sql, sequence.options_span.expect("options")).contains("OWNED BY"),
                "{sql}"
            );
            formats_without_loss(&sql, &pg);
        }
    }
}

#[test]
fn postgres_create_sequence_owned_by_none_names_nothing() {
    let pg = dialect::postgres();
    for sql in [
        "CREATE SEQUENCE crm.seq_id OWNED BY NONE;",
        "CREATE SEQUENCE crm.seq_id INCREMENT BY 2;",
    ] {
        let AstStmt::CreateSequence(sequence) = one_statement(sql, &pg) else {
            panic!("{sql}: not CREATE SEQUENCE");
        };
        assert!(
            sequence.owned_by_table.is_none() && sequence.owned_by_column.is_none(),
            "{sql}"
        );
    }
}

#[test]
fn postgres_alter_sequence_rename_to_keeps_the_new_name() {
    let pg = dialect::postgres();
    for name in CHANNEL_NAMES {
        let sql = format!("ALTER SEQUENCE IF EXISTS crm.seq_id RENAME TO {name};");
        let AstStmt::AlterSequence(sequence) = one_statement(&sql, &pg) else {
            panic!("{sql}: not ALTER SEQUENCE");
        };
        assert_eq!(
            at(&sql, sequence.rename_to.expect("new name")),
            name,
            "{sql}"
        );
        assert_eq!(at(&sql, sequence.name), "crm.seq_id", "{sql}");
        formats_without_loss(&sql, &pg);
    }
    let sql = "ALTER SEQUENCE crm.seq_id RESTART WITH 1;";
    let AstStmt::AlterSequence(sequence) = one_statement(sql, &pg) else {
        panic!("{sql}: not ALTER SEQUENCE");
    };
    assert!(sequence.rename_to.is_none(), "{sql}");
}

#[test]
fn postgres_grant_role_membership_keeps_the_roles_and_grantees() {
    let pg = dialect::postgres();
    for role in CHANNEL_NAMES {
        for tail in ["", " WITH ADMIN OPTION", " GRANTED BY admin_role"] {
            let sql = format!("GRANT {role}, auditors TO app_user, GROUP legacy{tail};");
            let AstStmt::Grant(grant) = one_statement(&sql, &pg) else {
                panic!("{sql}: not GRANT");
            };
            let AstGrantShape::Membership { roles, grantees } = &grant.shape else {
                panic!("{sql}: {:?}", grant.shape);
            };
            let read: Vec<&str> = roles.iter().map(|&span| at(&sql, span)).collect();
            assert_eq!(read, [role, "auditors"], "{sql}");
            assert_eq!(grantees.len(), 2, "{sql}");
            assert_eq!(at(&sql, grant.span), sql.trim_end_matches(';'), "{sql}");
            formats_without_loss(&sql, &pg);
        }
    }
}

#[test]
fn postgres_revoke_role_membership_keeps_the_roles_and_grantees() {
    let pg = dialect::postgres();
    for role in CHANNEL_NAMES {
        for tail in ["", " CASCADE", " RESTRICT"] {
            let sql = format!("REVOKE {role} FROM app_user{tail};");
            let AstStmt::Revoke(revoke) = one_statement(&sql, &pg) else {
                panic!("{sql}: not REVOKE");
            };
            let AstRevokeShape::Membership { roles, grantees } = &revoke.shape else {
                panic!("{sql}: {:?}", revoke.shape);
            };
            let read: Vec<&str> = roles.iter().map(|&span| at(&sql, span)).collect();
            assert_eq!(read, [role], "{sql}");
            assert_eq!(grantees.len(), 1, "{sql}");
            assert_eq!(revoke.cascade_mode.is_some(), !tail.is_empty(), "{sql}");
            formats_without_loss(&sql, &pg);
        }
    }
}

#[test]
fn grants_that_are_not_membership_stay_what_they_were() {
    let pg = dialect::postgres();
    for (sql, privilege) in [
        ("GRANT SELECT ON TABLE s1.orders TO app_user;", true),
        ("GRANT GIBBERISH NONSENSE FOO BAR;", false),
        (
            "GRANT USAGE ON SCHEMA s1 TO GROUP g WITH GRANT OPTION;",
            true,
        ),
    ] {
        let AstStmt::Grant(grant) = one_statement(sql, &pg) else {
            panic!("{sql}: not GRANT");
        };
        match (&grant.shape, privilege) {
            (AstGrantShape::Privilege(_), true) | (AstGrantShape::Unparsed { .. }, false) => {}
            (shape, _) => panic!("{sql}: {shape:?}"),
        }
    }
}

const UNLOAD_TAIL: &str = " TO 's3://bucket/out/' IAM_ROLE 'arn:aws:iam::1:role/r' PARALLEL OFF;";

/// The query the Redshift `UNLOAD` `sql` reads from its string literal;
/// `None` where it reads none. The statement formats without loss either way.
fn unload_query(sql: &str) -> Option<AstStmt> {
    let rs = dialect::redshift();
    let AstStmt::Unload { source, .. } = one_statement(sql, &rs) else {
        panic!("{sql}: not UNLOAD");
    };
    formats_without_loss(sql, &rs);
    match source {
        Some(AstUnloadSource::Subquery(query)) => Some(*query),
        Some(AstUnloadSource::Table { name_span, .. }) => panic!("{sql}: a table {name_span:?}"),
        None => None,
    }
}

#[test]
fn redshift_unload_reads_its_query_where_it_is_written() {
    let forms = [
        "UNLOAD ('SELECT * FROM «orders»')",
        "UNLOAD ('SELECT * FROM «s1.orders»')",
        "UNLOAD ('SELECT * FROM «d1.s1.orders»')",
        "UNLOAD ('SELECT * FROM «\"D1\".\"S 1\".\"ORDERS X\"»')",
        "UNLOAD ('SELECT * FROM «{{ target.schema }}.orders»')",
        "UNLOAD ('SELECT * FROM «d1.stage.orders»')",
        "UNLOAD ('SELECT id, total FROM «crm.orders» WHERE total > 100 ORDER BY id')",
        "UNLOAD ('SELECT o.id FROM crm.orders o JOIN «crm.users» u ON u.id = o.user_id')",
        "UNLOAD (\n  'SELECT id\n   FROM «crm.orders» -- recent\n   WHERE id > 1'\n)",
    ];
    let forms: Vec<String> = forms.iter().map(|f| format!("{f}{UNLOAD_TAIL}")).collect();
    let forms: Vec<&str> = forms.iter().map(String::as_str).collect();
    reads_whole(&dialect::redshift(), &forms);
    for form in forms {
        let sql = form.replace(['«', '»'], "");
        let query = unload_query(&sql).unwrap_or_else(|| panic!("{sql}: query not read"));
        assert!(matches!(query, AstStmt::Select(_)), "{sql}: {query:?}");
    }
}

#[test]
fn redshift_unload_query_literal_holds_the_text_a_doubled_quote_writes() {
    let sql = format!(
        "UNLOAD ('SELECT id FROM crm.orders WHERE state = ''NV'' AND id > 1'){UNLOAD_TAIL}"
    );
    let query = unload_query(&sql).unwrap_or_else(|| panic!("{sql}: query not read"));
    // The literal's span is the one quote of each doubled pair next to its
    // content: its text there is the literal as the query writes it.
    let at = sql.find("''NV''").expect("the literal") + 1;
    assert_eq!(&sql[at..at + 4], "'NV'");
    let literal = format!("String {{ span: Span {{ start: {at}, end: {} }} }}", at + 4);
    assert!(format!("{query:?}").contains(&literal), "{sql}: {query:?}");
}

#[test]
fn redshift_unload_query_that_does_not_read_whole_is_unread_and_still_parses() {
    for query in [
        // Not one statement that parses whole.
        "'SELECT FROM WHERE ((('",
        "'SELECT 1; SELECT 2'",
        "''",
        // A quote inside an inner literal: no source text reads as it does.
        "'SELECT * FROM orders WHERE note = ''it''''s'''",
        // Not one literal alone.
        "'SELECT 1' || 'x'",
    ] {
        let sql = format!("UNLOAD ({query}){UNLOAD_TAIL}");
        assert!(unload_query(&sql).is_none(), "{sql}");
    }
}

#[test]
fn redshift_unload_in_an_unload_query_is_read_to_the_depth_its_quotes_allow() {
    // The inner UNLOAD's own literal writes a doubled quote's text as it
    // reads, so its query is read too.
    let sql = format!(
        "UNLOAD ('UNLOAD (''SELECT id FROM crm.orders'') TO ''s3://b/in/''') {UNLOAD_TAIL}"
    );
    let Some(AstStmt::Unload {
        source: Some(AstUnloadSource::Subquery(inner)),
        ..
    }) = unload_query(&sql)
    else {
        panic!("{sql}: inner UNLOAD not read");
    };
    let at = sql.find("crm.orders").expect("the table");
    let name = format!("Span {{ start: {at}, end: {} }}", at + "crm.orders".len());
    assert!(format!("{inner:?}").contains(&name), "{sql}: {inner:?}");
    // One level deeper, the middle query's literal holds a quote inside
    // it, so the outer query is not read.
    let sql = format!(
        "UNLOAD ('UNLOAD (''UNLOAD (''''SELECT 1'''') TO ''''s3://b/x/'''''') TO ''s3://b/in/''') {UNLOAD_TAIL}"
    );
    assert!(unload_query(&sql).is_none(), "{sql}");
}

/// A comment between a `CREATE TABLE … AS` name and its clauses leaves no
/// line ending in a space, the clauses start their line as `AS` does, and
/// the statement formats the same twice.
#[test]
fn a_comment_before_a_create_table_clause_keeps_the_layout() {
    let postgres = dialect::postgres();
    let config = FormatterConfig {
        dialect: postgres.clone(),
        ..FormatterConfig::default()
    };
    for sql in [
        "CREATE TABLE t /* x */ WITHOUT OIDS AS SELECT 1 AS id;",
        "CREATE TEMP TABLE t -- c\n  ON COMMIT DROP AS SELECT 1 AS id;",
        "CREATE TEMP TABLE t /* x */ ON COMMIT PRESERVE ROWS AS SELECT 1 AS id;",
    ] {
        let once = format_sql_with_config(sql, &config).unwrap_or_else(|e| panic!("{sql}: {e:?}"));
        verify_formatting_safe_with_dialect(sql, &once, config.dialect.as_ref())
            .unwrap_or_else(|e| panic!("{sql}: {e}"));
        let twice =
            format_sql_with_config(&once, &config).unwrap_or_else(|e| panic!("{once}: {e:?}"));
        assert_eq!(once, twice, "{sql}");
        assert!(!once.lines().any(|line| line.ends_with(' ')), "{once:?}");
        assert!(
            once.lines()
                .any(|line| line.starts_with("WITHOUT OIDS") || line.starts_with("ON COMMIT")),
            "{once:?}"
        );
    }
}

#[test]
fn a_create_table_name_ends_before_the_clauses_written_after_it() {
    let postgres = dialect::postgres();
    for clause in [
        "ON COMMIT PRESERVE ROWS",
        "ON COMMIT DELETE ROWS",
        "ON COMMIT DROP",
        "TABLESPACE fast_disk",
        "WITH (fillfactor = 70)",
        "USING heap",
        "WITHOUT OIDS",
        "WITH OIDS",
        "WITHOUT OIDS ON COMMIT DROP",
        "WITH (fillfactor = 70) ON COMMIT DROP TABLESPACE fast_disk",
    ] {
        for name in ["users", "crm.users"] {
            let sql = format!("CREATE TEMP TABLE {name} {clause} AS SELECT 1 AS id;");
            let AstStmt::CreateTable(table) = one_statement(&sql, &postgres) else {
                panic!("{sql}: CREATE TABLE expected");
            };
            assert_eq!(at(&sql, table.name.span), name, "{sql}");
            formats_without_loss(&sql, &postgres);
        }
    }
}

#[test]
fn set_search_path_lists_the_schemas_it_names() {
    let pg = dialect::postgres();
    let cases: [(&str, &[&str]); 4] = [
        ("SET search_path TO s2, public;", &["s2", "public"]),
        (
            "SET LOCAL search_path = '$user', \"App\";",
            &["'$user'", "\"App\""],
        ),
        ("SET search_path TO DEFAULT;", &[]),
        ("SET work_mem = '64MB';", &[]),
    ];
    for (sql, want) in cases {
        let AstStmt::PgSet(set) = one_statement(sql, &pg) else {
            panic!("{sql}: not a SET");
        };
        let named: Vec<&str> = set.search_path.iter().map(|span| at(sql, *span)).collect();
        assert_eq!(named, want, "{sql}");
    }
}

#[test]
fn a_set_naming_no_parameter_is_no_set() {
    let pg = dialect::postgres();
    // T-SQL's `SET @v = …` read as PostgreSQL names no setting.
    for sql in ["SET @q = N'x';", "SET = 'x';", "RESET @q;"] {
        let stmt = one_statement(sql, &pg);
        assert!(!matches!(stmt, AstStmt::PgSet(_)), "{sql}: {stmt:?}");
    }
    for sql in [
        "SET work_mem = '64MB';",
        "SET LOCAL statement_timeout TO 0;",
    ] {
        assert!(
            matches!(one_statement(sql, &pg), AstStmt::PgSet(_)),
            "{sql}"
        );
    }
}
