// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! The shapes SQL Server names are written in, each read whole as the name it is.

mod name_shapes;

use lexega_syntax::ast::{
    AstGrantObject, AstGrantShape, AstMssqlPrincipalSource, AstObjectKind, AstRevokeShape,
    AstSecurityPredicateKind, PolicyState, SignerKind,
};
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
const ONE_PART_NAMES: [&str; 3] = ["lnk_srv", "[LNK SRV X]", "lnk_srv_{{ var('env') }}"];

#[test]
fn mssql_bulk_insert_table_name() {
    reads_whole(
        &dialect::mssql(),
        &["BULK INSERT «d1..orders» FROM 'C:\\\\data\\\\o.csv' WITH (FIELDTERMINATOR = ',');"],
    );
}

#[test]
fn mssql_create_index_on_table() {
    reads_whole(
        &dialect::mssql(),
        &["CREATE NONCLUSTERED INDEX idx_acct ON «d1..orders» (account_id);"],
    );
}

#[test]
fn mssql_create_synonym_for_name() {
    reads_whole(
        &dialect::mssql(),
        &["CREATE SYNONYM crm.o FOR «d1..orders»;"],
    );
}

#[test]
fn mssql_create_trigger_on_table() {
    reads_whole(
        &dialect::mssql(),
        &["CREATE TRIGGER crm.trg_audit ON «d1..orders» AFTER INSERT AS BEGIN SELECT 1; END;"],
    );
}

#[test]
fn mssql_create_vector_index_on_table() {
    reads_whole(
        &dialect::mssql(),
        &["CREATE VECTOR INDEX vi ON «d1..orders» (embedding) WITH (METRIC = 'cosine');"],
    );
}

#[test]
fn mssql_exec_at_keeps_the_linked_server() {
    let ms = dialect::mssql();
    for name in ONE_PART_NAMES {
        for sql in [
            format!("EXEC ('SELECT 1') AT {name};"),
            format!("EXEC ('SELECT 1') AT {name} WITH RECOMPILE;"),
        ] {
            let AstStmt::MssqlExec(exec) = one_statement(&sql, &ms) else {
                panic!("{sql}: not EXEC");
            };
            let server = exec
                .at_linked_server_span
                .unwrap_or_else(|| panic!("{sql}: no linked server"));
            assert_eq!(at(&sql, server), name, "{sql}");
            formats_without_loss(&sql, &ms);
        }
    }
}

#[test]
fn mssql_exec_at_leaves_the_next_statement() {
    let ms = dialect::mssql();
    let sql = "EXEC ('SELECT 1') AT lnk_srv\nSELECT 2";
    let script = parse_sql_with_dialect(sql, &*ms).unwrap_or_else(|e| panic!("{sql}: {e:?}"));
    let [AstStmt::MssqlExec(exec), AstStmt::Select(_)] = script.stmts.as_slice() else {
        panic!("{sql}: {:?}", script.stmts);
    };
    assert_eq!(
        at(sql, exec.at_linked_server_span.expect("server")),
        "lnk_srv"
    );
}

#[test]
fn mssql_create_user_keeps_the_login() {
    let ms = dialect::mssql();
    for name in ["zz_l", "[ZZ L X]", "\"zz_l\"", "zz_l_{{ var('env') }}"] {
        for words in ["FOR LOGIN", "FROM LOGIN"] {
            let sql = format!("CREATE USER zz_u {words} {name} WITH DEFAULT_SCHEMA = dbo;");
            let AstStmt::CreatePrincipal(user) = one_statement(&sql, &ms) else {
                panic!("{sql}: not CREATE USER");
            };
            let Some(AstMssqlPrincipalSource::ForLogin { login: Some(login) }) =
                user.options.mssql_source
            else {
                panic!("{sql}: {:?}", user.options.mssql_source);
            };
            assert_eq!(at(&sql, login), name, "{sql}");
            formats_without_loss(&sql, &ms);
        }
    }
}

#[test]
fn mssql_alter_user_keeps_the_login() {
    let ms = dialect::mssql();
    let sql = "ALTER USER zz_u FOR LOGIN [ZZ L X];";
    let AstStmt::AlterPrincipal(user) = one_statement(sql, &ms) else {
        panic!("{sql}: not ALTER USER");
    };
    let Some(AstMssqlPrincipalSource::ForLogin { login: Some(login) }) = user.options.mssql_source
    else {
        panic!("{sql}: {:?}", user.options.mssql_source);
    };
    assert_eq!(at(sql, login), "[ZZ L X]");
}

/// The ways a multi-part object is written.
const OBJECT_NAMES: [&str; 5] = [
    "orders",
    "d1..orders",
    "[D1].[S 1].[ORDERS X]",
    "{{ target.schema }}.orders",
    "d1.stage.orders",
];

#[test]
fn mssql_security_policy_keeps_the_name_and_each_predicate() {
    let ms = dialect::mssql();
    for name in OBJECT_NAMES {
        for verb in ["CREATE", "ALTER"] {
            let sql = format!(
                "{verb} SECURITY POLICY {name} ADD FILTER PREDICATE crm.fn_tenant(tenant_id) ON crm.orders, \
                 ADD BLOCK PREDICATE [S 1].[FN B](a, (b + 1)) ON {name} AFTER INSERT WITH (STATE = ON, SCHEMABINDING = OFF);"
            );
            let AstStmt::MssqlSecurityPolicy(policy) = one_statement(&sql, &ms) else {
                panic!("{sql}: not a security policy");
            };
            assert_eq!(at(&sql, policy.name.expect("name").span), name, "{sql}");
            assert!(
                policy.has_filter_predicate && policy.has_block_predicate,
                "{sql}"
            );
            assert_eq!(policy.state, PolicyState::On, "{sql}");
            let [filter, block] = policy.predicates.as_slice() else {
                panic!("{sql}: {:?}", policy.predicates);
            };
            assert_eq!(filter.kind, AstSecurityPredicateKind::Filter, "{sql}");
            assert_eq!(
                at(&sql, filter.function.as_ref().expect("function").span),
                "crm.fn_tenant",
                "{sql}"
            );
            assert_eq!(
                at(&sql, filter.args_span.expect("args")),
                "(tenant_id)",
                "{sql}"
            );
            assert_eq!(
                at(&sql, filter.table.as_ref().expect("table").span),
                "crm.orders",
                "{sql}"
            );
            assert_eq!(block.kind, AstSecurityPredicateKind::Block, "{sql}");
            assert_eq!(
                at(&sql, block.function.as_ref().expect("function").span),
                "[S 1].[FN B]",
                "{sql}"
            );
            assert_eq!(
                at(&sql, block.args_span.expect("args")),
                "(a, (b + 1))",
                "{sql}"
            );
            assert_eq!(
                at(&sql, block.table.as_ref().expect("table").span),
                name,
                "{sql}"
            );
            formats_without_loss(&sql, &ms);
        }
    }
}

#[test]
fn mssql_security_policy_drop_predicate_keeps_the_table_and_no_function() {
    let ms = dialect::mssql();
    let sql = "ALTER SECURITY POLICY sp DROP FILTER PREDICATE ON dbo.orders, DROP BLOCK PREDICATE ON [S 1].[T] AFTER UPDATE;";
    let AstStmt::MssqlSecurityPolicy(policy) = one_statement(sql, &ms) else {
        panic!("{sql}: not a security policy");
    };
    let tables: Vec<(bool, &str)> = policy
        .predicates
        .iter()
        .map(|p| {
            (
                p.function.is_some(),
                at(sql, p.table.as_ref().expect("table").span),
            )
        })
        .collect();
    assert_eq!(
        tables,
        [(false, "dbo.orders"), (false, "[S 1].[T]")],
        "{sql}"
    );
    formats_without_loss(sql, &ms);
}

#[test]
fn mssql_security_policy_without_a_name_or_predicates_still_parses() {
    let ms = dialect::mssql();
    for sql in [
        "CREATE SECURITY POLICY;",
        "ALTER SECURITY POLICY sp WITH (STATE = OFF);",
        "ALTER SECURITY POLICY sp ADD FILTER PREDICATE;",
    ] {
        let AstStmt::MssqlSecurityPolicy(policy) = one_statement(sql, &ms) else {
            panic!("{sql}: not a security policy");
        };
        assert_eq!(
            policy.name.is_some(),
            !sql.starts_with("CREATE SECURITY POLICY;"),
            "{sql}"
        );
        assert!(
            policy
                .predicates
                .iter()
                .all(|p| p.function.is_none() && p.table.is_none()),
            "{sql}"
        );
    }
}

#[test]
fn mssql_add_signature_keeps_the_module_and_each_signer() {
    let ms = dialect::mssql();
    for module in OBJECT_NAMES {
        for (head, class) in [
            ("ADD SIGNATURE TO", None),
            ("ADD COUNTER SIGNATURE TO", None),
            ("ADD SIGNATURE TO OBJECT::", Some("OBJECT")),
            ("ADD SIGNATURE TO ASSEMBLY::", Some("ASSEMBLY")),
        ] {
            let sql = format!(
                "{head}{}{module} BY CERTIFICATE c1 WITH PASSWORD = 'x', ASYMMETRIC KEY [K 1] WITH SIGNATURE = 0x0102, CERTIFICATE d1.c2;",
                if class.is_some() { "" } else { " " }
            );
            let AstStmt::MssqlAddSignature(signature) = one_statement(&sql, &ms) else {
                panic!("{sql}: not ADD SIGNATURE");
            };
            assert_eq!(
                at(&sql, signature.module.expect("module").span),
                module,
                "{sql}"
            );
            assert_eq!(signature.module_class.map(|c| at(&sql, c)), class, "{sql}");
            let signers: Vec<(SignerKind, &str)> = signature
                .signers
                .iter()
                .map(|s| (s.kind, at(&sql, s.name.span)))
                .collect();
            assert_eq!(
                signers,
                [
                    (SignerKind::Certificate, "c1"),
                    (SignerKind::AsymmetricKey, "[K 1]"),
                    (SignerKind::Certificate, "d1.c2")
                ],
                "{sql}"
            );
            assert_eq!(signature.signer_kind, SignerKind::Certificate, "{sql}");
            let passwords: Vec<&str> = signature
                .password_literal_spans
                .iter()
                .map(|s| at(&sql, *s))
                .collect();
            assert_eq!(passwords, ["'x'"], "{sql}");
            formats_without_loss(&sql, &ms);
        }
    }
}

#[test]
fn mssql_add_signature_that_is_not_the_full_form_keeps_what_it_read() {
    let ms = dialect::mssql();
    let sql = "ADD SIGNATURE TO dbo.p BY;";
    let AstStmt::MssqlAddSignature(signature) = one_statement(sql, &ms) else {
        panic!("{sql}: not ADD SIGNATURE");
    };
    assert_eq!(at(sql, signature.module.expect("module").span), "dbo.p");
    assert!(signature.signers.is_empty());
}

#[test]
fn mssql_database_audit_specification_keeps_the_server_audit() {
    let ms = dialect::mssql();
    for audit in [
        "compliance_audit",
        "[Compliance Audit]",
        "audit_{{ var('env') }}",
    ] {
        for (head, tail) in [
            (
                "CREATE DATABASE AUDIT SPECIFICATION dml_spec",
                " ADD (SELECT ON dbo.payroll BY public) WITH (STATE = ON)",
            ),
            (
                "ALTER DATABASE AUDIT SPECIFICATION dml_spec",
                " WITH (STATE = OFF)",
            ),
            (
                "CREATE SERVER AUDIT SPECIFICATION srv_spec",
                " ADD (FAILED_LOGIN_GROUP)",
            ),
        ] {
            let sql = format!("{head} FOR SERVER AUDIT {audit}{tail};");
            let AstStmt::MssqlAuditDdl(ddl) = one_statement(&sql, &ms) else {
                panic!("{sql}: not audit DDL");
            };
            assert_eq!(
                at(&sql, ddl.server_audit.expect("audit").span),
                audit,
                "{sql}"
            );
            assert_eq!(
                at(&sql, ddl.name_span),
                if head.contains("srv_spec") {
                    "srv_spec"
                } else {
                    "dml_spec"
                },
                "{sql}"
            );
            formats_without_loss(&sql, &ms);
        }
    }
    let sql = "CREATE SERVER AUDIT a1 TO FILE (FILEPATH = 'C:\\\\a') WITH (QUEUE_DELAY = 1000);";
    let AstStmt::MssqlAuditDdl(ddl) = one_statement(sql, &ms) else {
        panic!("{sql}: not audit DDL");
    };
    assert!(ddl.server_audit.is_none(), "{sql}");
}

#[test]
fn mssql_deny_keeps_the_object_typed_as_a_grant_types_it() {
    let ms = dialect::mssql();
    for name in OBJECT_NAMES {
        for (class, kind) in [
            (
                "",
                AstObjectKind::Other {
                    lexemes: vec!["OBJECT".to_string()],
                },
            ),
            ("SCHEMA::", AstObjectKind::Schema),
            (
                "OBJECT::",
                AstObjectKind::Other {
                    lexemes: vec!["OBJECT".to_string()],
                },
            ),
        ] {
            for tail in ["", " CASCADE", " CASCADE AS dbo"] {
                let sql = format!("DENY SELECT ON {class}{name} TO app_user{tail};");
                let AstStmt::Deny(deny) = one_statement(&sql, &ms) else {
                    panic!("{sql}: not DENY");
                };
                let object = deny.object_span.expect("object");
                let Some(AstGrantObject::Single {
                    object_kind,
                    name_span,
                    ..
                }) = object.object
                else {
                    panic!("{sql}: {:?}", object.object);
                };
                assert_eq!(object_kind, kind, "{sql}");
                assert_eq!(at(&sql, name_span), name, "{sql}");
                assert_eq!(
                    at(&sql, object.target_span).trim(),
                    format!("{class}{name}"),
                    "{sql}"
                );
                formats_without_loss(&sql, &ms);
            }
        }
    }
}

#[test]
fn mssql_deny_with_a_column_list_or_no_object_still_parses() {
    let ms = dialect::mssql();
    let sql = "DENY SELECT ON dbo.orders (a, b) TO app_user;";
    let AstStmt::Deny(deny) = one_statement(sql, &ms) else {
        panic!("{sql}: not DENY");
    };
    let object = deny.object_span.expect("object");
    assert_eq!(at(sql, object.target_span).trim(), "dbo.orders (a, b)");
    assert!(object.object.is_some());
    assert_eq!(deny.grantees.len(), 1);
    for sql in [
        "DENY CONTROL SERVER TO app_user;",
        "DENY SELECT ON TO app_user;",
    ] {
        let AstStmt::Deny(deny) = one_statement(sql, &ms) else {
            panic!("{sql}: not DENY");
        };
        assert_eq!(deny.grantees.len(), 1, "{sql}");
        assert!(deny.object_span.is_none_or(|o| o.object.is_none()), "{sql}");
    }
}

#[test]
fn mssql_grant_and_revoke_keep_the_as_principal() {
    let ms = dialect::mssql();
    for principal in [
        "dbo_owner",
        "[dbo owner]",
        "d1.grantor",
        "owner_{{ var('env') }}",
    ] {
        let grant = format!("GRANT SELECT ON dbo.t TO u1, u2 WITH GRANT OPTION AS {principal};");
        let AstStmt::Grant(grant_stmt) = one_statement(&grant, &ms) else {
            panic!("{grant}: not GRANT");
        };
        let AstGrantShape::Privilege(body) = &grant_stmt.shape else {
            panic!("{grant}: {:?}", grant_stmt.shape);
        };
        let as_principal = body.as_principal.as_ref().expect("AS principal");
        assert_eq!(
            at(&grant, as_principal.principal_name_span),
            principal,
            "{grant}"
        );
        assert_eq!(at(&grant, as_principal.keyword_span), "AS", "{grant}");
        formats_without_loss(&grant, &ms);

        for tail in ["", " CASCADE"] {
            let revoke =
                format!("REVOKE SELECT ON OBJECT::dbo.t FROM u1, u2{tail} AS {principal};");
            let AstStmt::Revoke(revoke_stmt) = one_statement(&revoke, &ms) else {
                panic!("{revoke}: not REVOKE");
            };
            let AstRevokeShape::Privilege(body) = &revoke_stmt.shape else {
                panic!("{revoke}: {:?}", revoke_stmt.shape);
            };
            let as_principal = body.as_principal.as_ref().expect("AS principal");
            assert_eq!(
                at(&revoke, as_principal.principal_name_span),
                principal,
                "{revoke}"
            );
            assert_eq!(
                revoke_stmt.cascade_mode.is_some(),
                !tail.is_empty(),
                "{revoke}"
            );
            formats_without_loss(&revoke, &ms);
        }
    }
}

#[test]
fn mssql_grant_and_revoke_without_as_keep_none() {
    let ms = dialect::mssql();
    let sql = "GRANT SELECT ON dbo.t TO u1;";
    let AstStmt::Grant(grant) = one_statement(sql, &ms) else {
        panic!("{sql}: not GRANT");
    };
    assert!(matches!(&grant.shape, AstGrantShape::Privilege(b) if b.as_principal.is_none()));
    let sql = "REVOKE SELECT ON dbo.t FROM u1;";
    let AstStmt::Revoke(revoke) = one_statement(sql, &ms) else {
        panic!("{sql}: not REVOKE");
    };
    assert!(matches!(&revoke.shape, AstRevokeShape::Privilege(b) if b.as_principal.is_none()));
}
