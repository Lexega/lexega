// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

// DDL (Data Definition Language) statement tests
// Tests for CREATE TABLE, DROP TABLE, and other DDL operations
use lexega_syntax::parse_sql;
use lexega_syntax::parse_stmt_from_str;

// CREATE TABLE with table type modifiers

#[test]
fn test_create_temp_table() {
    let sql = "CREATE TEMP TABLE test (id INT);";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Failed to parse CREATE TEMP TABLE");
}

#[test]
fn test_create_temporary_table() {
    let sql = "CREATE TEMPORARY TABLE test (id INT);";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Failed to parse CREATE TEMPORARY TABLE");
}

#[test]
fn test_create_local_temp_table() {
    let sql = "CREATE LOCAL TEMP TABLE test (id INT);";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Failed to parse CREATE LOCAL TEMP TABLE");
}

#[test]
fn test_create_global_temporary_table() {
    let sql = "CREATE GLOBAL TEMPORARY TABLE test (id INT);";
    let result = parse_stmt_from_str(sql);
    assert!(
        result.is_some(),
        "Failed to parse CREATE GLOBAL TEMPORARY TABLE"
    );
}

#[test]
fn test_create_volatile_table() {
    let sql = "CREATE VOLATILE TABLE test (id INT);";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Failed to parse CREATE VOLATILE TABLE");
}

#[test]
fn test_create_transient_table() {
    let sql = "CREATE TRANSIENT TABLE test (id INT);";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Failed to parse CREATE TRANSIENT TABLE");
}

#[test]
fn test_create_or_replace_temp_table() {
    let sql = "CREATE OR REPLACE TEMP TABLE test (id INT);";
    let result = parse_stmt_from_str(sql);
    assert!(
        result.is_some(),
        "Failed to parse CREATE OR REPLACE TEMP TABLE"
    );
}

#[test]
fn test_create_or_replace_local_temporary_table() {
    let sql = "CREATE OR REPLACE LOCAL TEMPORARY TABLE test (id INT);";
    let result = parse_stmt_from_str(sql);
    assert!(
        result.is_some(),
        "Failed to parse CREATE OR REPLACE LOCAL TEMPORARY TABLE"
    );
}

// CREATE TABLE in scripting context

#[test]
fn test_create_temporary_table_in_block() {
    let src = r#"
BEGIN
    CREATE TEMPORARY TABLE staging (id INTEGER);
    RETURN 'done';
END;
"#;
    let script = parse_sql(src);
    assert!(
        script.is_ok(),
        "failed to parse CREATE TEMPORARY TABLE in block"
    );
}

#[test]
fn test_create_temp_table_as_select() {
    let src = r#"
BEGIN
    CREATE TEMPORARY TABLE staging AS SELECT * FROM source WHERE 1=0;
    RETURN 'done';
END;
"#;
    let script = parse_sql(src);
    assert!(
        script.is_ok(),
        "failed to parse CREATE TEMPORARY TABLE AS SELECT"
    );
}

#[test]
fn test_create_temporary_table_as_select_full() {
    let src = r#"
BEGIN
    CREATE TEMPORARY TABLE staging AS SELECT * FROM employees;
    RETURN 'done';
END;
"#;
    let script = parse_sql(src);
    assert!(
        script.is_ok(),
        "failed to parse CREATE TEMPORARY TABLE AS SELECT (full)"
    );
}

#[test]
fn test_create_temp_table_with_cte() {
    let src = r#"
BEGIN
    CREATE TEMP TABLE my_temp_tbl AS
    WITH MY_CTE AS (
        SELECT id, name, salary
        FROM employees
        WHERE salary > 50000
    )
    SELECT id, name, salary * 1.1 AS new_salary
    FROM MY_CTE
    WHERE name LIKE 'A%';
    RETURN 'done';
END;
"#;
    let script = parse_sql(src);
    assert!(script.is_ok(), "failed to parse CREATE TEMP TABLE with CTE");
}

// DROP TABLE statements

#[test]
fn test_drop_table_if_exists() {
    let src = r#"
BEGIN
    DROP TABLE IF EXISTS staging;
    RETURN 'done';
END;
"#;
    let script = parse_sql(src);
    assert!(script.is_ok(), "failed to parse DROP TABLE IF EXISTS");
}

/// The statements `src` parses to under `dialect`, each as its kind and the
/// name of the object a `DROP` or `TRUNCATE` names.
fn statements_and_names(
    src: &str,
    dialect: &dyn lexega_syntax::dialect::Dialect,
) -> Vec<(String, Option<String>)> {
    use lexega_syntax::ast::AstStmt;
    let text = |span: Option<lexega_syntax::lexer::Span>| {
        span.map(|s| src[s.start as usize..s.end as usize].to_string())
    };
    lexega_syntax::parse_sql_with_dialect(src, dialect)
        .expect("parses")
        .stmts
        .iter()
        .map(|stmt| match stmt {
            AstStmt::Drop(d) => (
                "DROP".to_string(),
                text(d.target_name.as_ref().map(|n| n.span)),
            ),
            AstStmt::Truncate(t) => (
                "TRUNCATE".to_string(),
                text(t.target_table.as_ref().map(|n| n.span)),
            ),
            AstStmt::Select(_) => ("SELECT".to_string(), None),
            AstStmt::Update(_) => ("UPDATE".to_string(), None),
            AstStmt::CreateTable(_) => ("CREATE TABLE".to_string(), None),
            other => (format!("{other:?}").chars().take(20).collect(), None),
        })
        .collect()
}

#[test]
fn a_tsql_drop_or_truncate_without_a_semicolon_ends_with_its_names() {
    let mssql = lexega_syntax::dialect::mssql();
    let next = "\nSELECT id FROM dbo.zz_src";
    for (stmt, name) in [
        ("DROP TABLE dbo.zz_t", "dbo.zz_t"),
        ("DROP TABLE IF EXISTS dbo.zz_t", "dbo.zz_t"),
        ("DROP TABLE [dbo].[zz_t]", "[dbo].[zz_t]"),
        ("DROP TABLE #t", "#t"),
        ("DROP TABLE dbo.zz_a, dbo.zz_b", "dbo.zz_a, dbo.zz_b"),
        ("DROP VIEW dbo.zz_v", "dbo.zz_v"),
        ("DROP VIEW IF EXISTS dbo.zz_v", "dbo.zz_v"),
        ("DROP PROCEDURE dbo.zz_p", "dbo.zz_p"),
        ("DROP FUNCTION dbo.zz_f", "dbo.zz_f"),
        ("DROP SYNONYM dbo.zz_syn", "dbo.zz_syn"),
        ("DROP STATISTICS dbo.zz_t.st1", "dbo.zz_t.st1"),
        ("DROP EXTERNAL TABLE dbo.zz_e", "dbo.zz_e"),
        ("TRUNCATE TABLE dbo.zz_t", "dbo.zz_t"),
        ("TRUNCATE TABLE dbo.zz_t WITH (PARTITIONS (1))", "dbo.zz_t"),
    ] {
        let src = format!("{stmt}{next}");
        let parsed = statements_and_names(&src, &*mssql);
        let kind = stmt.split(' ').next().unwrap_or_default().to_string();
        assert_eq!(
            parsed,
            vec![(kind, Some(name.to_string())), ("SELECT".to_string(), None)],
            "{src}"
        );
    }
    // After a condition, and before more than one statement.
    let src = "IF OBJECT_ID('dbo.zz_t') IS NOT NULL DROP TABLE dbo.zz_t\n\
               CREATE TABLE dbo.zz_t (id INT)\n\
               DROP TABLE dbo.zz_u\n\
               UPDATE dbo.zz_src SET id = 1 WHERE id = 2";
    let parsed = statements_and_names(src, &*mssql);
    assert_eq!(parsed.len(), 4, "{parsed:?}");
    assert_eq!(parsed[1].0, "CREATE TABLE", "{parsed:?}");
    assert_eq!(
        parsed[2],
        ("DROP".to_string(), Some("dbo.zz_u".to_string()))
    );
    assert_eq!(parsed[3].0, "UPDATE", "{parsed:?}");
}

#[test]
fn a_tsql_declare_or_alter_table_without_a_semicolon_ends_with_its_grammar() {
    let mssql = lexega_syntax::dialect::mssql();
    for (src, count) in [
        ("DECLARE @n INT\nSELECT id FROM dbo.zz_src WHERE a = 1", 2),
        ("DECLARE @n INT\nSET @n = 1\nSELECT id FROM dbo.zz_src", 3),
        (
            "DECLARE @n INT = (SELECT MAX(id) FROM dbo.zz_a)\nSELECT id FROM dbo.zz_src",
            2,
        ),
        (
            "DECLARE @s NVARCHAR(50), @m INT = 1\nSELECT id FROM dbo.zz_src",
            2,
        ),
        (
            "ALTER TABLE dbo.zz_t ADD c INT\nSELECT id FROM dbo.zz_src",
            2,
        ),
        (
            "ALTER TABLE dbo.zz_t ADD c INT NOT NULL DEFAULT 0\nSELECT id FROM dbo.zz_src",
            2,
        ),
        (
            "ALTER TABLE dbo.zz_t DROP COLUMN c\nSELECT id FROM dbo.zz_src",
            2,
        ),
        (
            "ALTER TABLE dbo.zz_t ADD CONSTRAINT pk PRIMARY KEY (id)\nSELECT id FROM dbo.zz_src",
            2,
        ),
        (
            "ALTER TABLE dbo.zz_t ADD CONSTRAINT df DEFAULT 0 FOR c\nSELECT id FROM dbo.zz_src",
            2,
        ),
        (
            "ALTER TABLE dbo.zz_t WITH CHECK ADD CONSTRAINT fk FOREIGN KEY (a) \
             REFERENCES dbo.zz_b (id)\nSELECT id FROM dbo.zz_src",
            2,
        ),
    ] {
        let parsed = statements_and_names(src, &*mssql);
        assert_eq!(parsed.len(), count, "{src}: {parsed:?}");
        assert_eq!(parsed[count - 1].0, "SELECT", "{src}: {parsed:?}");
    }
}

#[test]
fn a_stage_or_policy_option_list_ends_where_a_statement_starts() {
    let snowflake = lexega_syntax::dialect::snowflake();
    for (first, next) in [
        (
            "CREATE STAGE s URL = 's3://bucket/path/'",
            "GRANT USAGE ON STAGE s TO ROLE r",
        ),
        (
            "ALTER ROW ACCESS POLICY p SET TAG env = 'prod'",
            "MERGE INTO t USING s ON t.id = s.id WHEN MATCHED THEN DELETE",
        ),
        (
            "ALTER SESSION POLICY sp SET SESSION_IDLE_TIMEOUT_MINS = 30",
            "GRANT APPLY ON SESSION POLICY sp TO ROLE r",
        ),
    ] {
        let src = format!("{first}\n{next}");
        let starts: Vec<u32> = lexega_syntax::parse_sql_with_dialect(&src, &*snowflake)
            .expect("parses")
            .stmts
            .iter()
            .map(|stmt| stmt.span().start)
            .collect();
        assert_eq!(starts, vec![0, first.len() as u32 + 1], "{src}");
    }
}

/// Each statement `src` parses to under `dialect`: its text, or the kind
/// of a `SELECT` or `INSERT`. `src` also round-trips through the formatter.
fn statement_texts(src: &str, dialect: &lexega_syntax::dialect::DialectRef) -> Vec<String> {
    use lexega_syntax::ast::AstStmt;
    let texts = lexega_syntax::parse_sql_with_dialect(src, &**dialect)
        .expect("parses")
        .stmts
        .iter()
        .map(|stmt| match stmt {
            AstStmt::Select(_) => "SELECT".to_string(),
            AstStmt::Insert(_) => "INSERT".to_string(),
            other => src[other.span().start as usize..other.span().end as usize].to_string(),
        })
        .collect();
    let config = lexega_syntax::FormatterConfig {
        dialect: dialect.clone(),
        ..Default::default()
    };
    let formatted = lexega_syntax::format_sql_with_config(src, &config).expect("formats");
    lexega_syntax::verify_formatting_safe_with_dialect(src, &formatted, &**dialect)
        .unwrap_or_else(|e| panic!("{src} -> {formatted}: {e}"));
    texts
}

#[test]
fn a_tsql_security_or_maintenance_statement_without_a_semicolon_ends_with_its_grammar() {
    let mssql = lexega_syntax::dialect::mssql();
    for statement in [
        "CREATE USER zz_u FOR LOGIN zz_l",
        "CREATE USER zz_u FOR LOGIN zz_l WITH DEFAULT_SCHEMA = dbo",
        "CREATE USER zz_u WITHOUT LOGIN",
        "CREATE USER [a@b.com] FROM EXTERNAL PROVIDER",
        "CREATE USER zz_u WITH PASSWORD = 'x', DEFAULT_SCHEMA = dbo",
        "CREATE LOGIN zz_l WITH PASSWORD = 'x'",
        "CREATE LOGIN zz_l WITH PASSWORD = 'x' MUST_CHANGE, CHECK_EXPIRATION = ON, \
         CHECK_POLICY = OFF, DEFAULT_DATABASE = master",
        "CREATE LOGIN zz_l WITH PASSWORD = 0x0200AB HASHED, SID = 0x1F",
        "CREATE LOGIN [dom\\zz] FROM WINDOWS WITH DEFAULT_DATABASE = master",
        "CREATE LOGIN zz_l FROM CERTIFICATE c1",
        "CREATE ROLE zz_r",
        "CREATE ROLE zz_r AUTHORIZATION dbo",
        "CREATE SERVER ROLE zz_r AUTHORIZATION sa",
        "CREATE APPLICATION ROLE zz_a WITH PASSWORD = 'x', DEFAULT_SCHEMA = dbo",
        "ALTER ROLE zz_r ADD MEMBER zz_u",
        "ALTER ROLE zz_r DROP MEMBER zz_u",
        "ALTER ROLE zz_r WITH NAME = zz_r2",
        "ALTER SERVER ROLE sysadmin ADD MEMBER zz_l",
        "ALTER LOGIN zz_l DISABLE",
        "ALTER LOGIN zz_l WITH PASSWORD = 'n' OLD_PASSWORD = 'o'",
        "ALTER LOGIN zz_l WITH PASSWORD = 'n' UNLOCK, CHECK_POLICY = ON",
        "ALTER LOGIN zz_l ADD CREDENTIAL zz_c",
        "ALTER USER zz_u WITH DEFAULT_SCHEMA = dbo, LOGIN = zz_l",
        "CREATE SCHEMA zz_s AUTHORIZATION dbo",
        "ALTER SCHEMA zz_s TRANSFER dbo.zz_t",
        "ALTER SCHEMA zz_s TRANSFER OBJECT::dbo.zz_t",
        "ALTER SCHEMA zz_s TRANSFER XML SCHEMA COLLECTION::dbo.zz_x",
        "ALTER DATABASE zz_db SET RECOVERY SIMPLE",
        "ALTER DATABASE zz_db SET SINGLE_USER WITH ROLLBACK IMMEDIATE",
        "ALTER DATABASE zz_db SET MULTI_USER",
        "ALTER DATABASE zz_db SET OFFLINE WITH ROLLBACK AFTER 30 SECONDS",
        "ALTER DATABASE zz_db SET ANSI_NULLS ON, QUOTED_IDENTIFIER ON",
        "ALTER DATABASE zz_db SET CHANGE_TRACKING = ON (CHANGE_RETENTION = 2 DAYS, \
         AUTO_CLEANUP = ON)",
        "ALTER DATABASE zz_db SET TARGET_RECOVERY_TIME = 60 SECONDS",
        "ALTER DATABASE zz_db SET PARTNER SAFETY FULL",
        "ALTER DATABASE zz_db SET HADR AVAILABILITY GROUP = zz_ag",
        "ALTER DATABASE zz_db SET QUERY_STORE CLEAR ALL",
        "ALTER DATABASE zz_db SET COMPATIBILITY_LEVEL = 150",
        "ALTER DATABASE zz_db MODIFY NAME = zz_db2",
        "ALTER DATABASE zz_db MODIFY FILE (NAME = f1, SIZE = 5MB)",
        "ALTER DATABASE zz_db MODIFY FILEGROUP fg1 DEFAULT",
        "ALTER DATABASE zz_db ADD FILE (NAME = f1, FILENAME = 'c:\\f1.ndf', SIZE = 5MB, \
         FILEGROWTH = 10%) TO FILEGROUP fg1",
        "ALTER DATABASE zz_db ADD LOG FILE (NAME = l1, FILENAME = 'c:\\l1.ldf')",
        "ALTER DATABASE zz_db ADD FILEGROUP fg2 CONTAINS FILESTREAM",
        "ALTER DATABASE zz_db REMOVE FILE f1",
        "ALTER DATABASE zz_db COLLATE Latin1_General_CI_AS",
        "BACKUP DATABASE zz_db TO DISK = 'c:\\x.bak'",
        "BACKUP DATABASE zz_db TO DISK = 'c:\\x.bak', DISK = 'd:\\y.bak' MIRROR TO \
         DISK = 'e:\\z.bak' WITH INIT, COMPRESSION, STATS = 10",
        "BACKUP LOG zz_db TO URL = 'https://a/b' WITH ENCRYPTION (ALGORITHM = AES_256, \
         SERVER CERTIFICATE = c1)",
        "RESTORE DATABASE zz_db FROM DISK = 'c:\\x.bak'",
        "RESTORE DATABASE zz_db FROM DISK = 'c:\\x.bak' WITH REPLACE, MOVE 'd' TO \
         'c:\\d.mdf', MOVE 'l' TO 'c:\\l.ldf', RECOVERY",
        "RESTORE LOG zz_db FROM DISK = 'c:\\x.trn' WITH STOPATMARK = 'm1' AFTER \
         '2026-01-01', NORECOVERY",
        "RESTORE DATABASE zz_db WITH RECOVERY",
        "RESTORE DATABASE zz_db FILE = 'f1' FROM DISK = 'c:\\x.bak' WITH NORECOVERY",
        "DBCC CHECKDB",
        "DBCC CHECKDB (zz_db) WITH NO_INFOMSGS, ALL_ERRORMSGS",
        "DBCC CHECKIDENT ('dbo.zz_t', RESEED, -1) WITH NO_INFOMSGS",
        "CREATE MASTER KEY ENCRYPTION BY PASSWORD = 'x'",
        "ALTER MASTER KEY FORCE REGENERATE WITH ENCRYPTION BY PASSWORD = 'x'",
        "ALTER MASTER KEY ADD ENCRYPTION BY SERVICE MASTER KEY",
        "OPEN MASTER KEY DECRYPTION BY PASSWORD = 'x'",
        "CLOSE MASTER KEY",
        "DROP DATABASE ENCRYPTION KEY",
        "CREATE SYMMETRIC KEY k WITH ALGORITHM = AES_256 ENCRYPTION BY CERTIFICATE c",
        "CREATE SYMMETRIC KEY k WITH KEY_SOURCE = 'a', ALGORITHM = AES_256, \
         IDENTITY_VALUE = 'b' ENCRYPTION BY PASSWORD = 'x', CERTIFICATE c",
        "ALTER SYMMETRIC KEY k ADD ENCRYPTION BY PASSWORD = 'x'",
        "OPEN SYMMETRIC KEY k DECRYPTION BY CERTIFICATE c WITH PASSWORD = 'p'",
        "CLOSE SYMMETRIC KEY k",
        "CLOSE ALL SYMMETRIC KEYS",
        "SETUSER 'zz_u'",
        "SETUSER N'zz_u' WITH NORESET",
        "SETUSER",
    ] {
        let src = format!(
            "{statement}\nSELECT id FROM dbo.zz_src\nINSERT INTO dbo.zz_dst (id) SELECT id FROM dbo.zz_src"
        );
        assert_eq!(
            statement_texts(&src, &mssql),
            [statement, "SELECT", "INSERT"],
            "{src}"
        );
    }
}

#[test]
fn an_alter_database_of_the_current_database_parses() {
    let mssql = lexega_syntax::dialect::mssql();
    for statement in [
        "ALTER DATABASE CURRENT SET READ_COMMITTED_SNAPSHOT ON",
        "ALTER DATABASE CURRENT MODIFY NAME = zz_db2",
    ] {
        let src = format!("{statement}\nSELECT id FROM dbo.zz_src");
        let script = lexega_syntax::parse_sql_with_dialect(&src, &*mssql).expect("parses");
        assert!(
            matches!(
                script.stmts.first(),
                Some(lexega_syntax::ast::AstStmt::AlterDatabase(_))
            ),
            "{src}: {:?}",
            script.stmts.first()
        );
        assert_eq!(
            statement_texts(&src, &mssql),
            [statement, "SELECT"],
            "{src}"
        );
    }
}

#[test]
fn a_tsql_key_or_certificate_backup_without_a_semicolon_ends_with_its_grammar() {
    let mssql = lexega_syntax::dialect::mssql();
    for statement in [
        "BACKUP CERTIFICATE c TO FILE = 'c:\\c.cer'",
        "BACKUP CERTIFICATE c TO FILE = 'c:\\c.cer' WITH PRIVATE KEY (FILE = 'c:\\c.pvk', \
         ENCRYPTION BY PASSWORD = 'p')",
        "BACKUP MASTER KEY TO FILE = 'c:\\k' ENCRYPTION BY PASSWORD = 'p'",
        "BACKUP MASTER KEY TO URL = 'https://a/k' ENCRYPTION BY PASSWORD = 'p'",
        "BACKUP SERVICE MASTER KEY TO FILE = 'c:\\k' ENCRYPTION BY PASSWORD = 'p'",
        "RESTORE MASTER KEY FROM FILE = 'c:\\k' DECRYPTION BY PASSWORD = 'p' \
         ENCRYPTION BY PASSWORD = 'q' FORCE",
        "RESTORE SERVICE MASTER KEY FROM FILE = 'c:\\k' DECRYPTION BY PASSWORD = 'p'",
    ] {
        let src = format!(
            "{statement}\nSELECT id FROM dbo.zz_src\nINSERT INTO dbo.zz_dst (id) SELECT id FROM dbo.zz_src"
        );
        assert_eq!(
            statement_texts(&src, &mssql),
            [statement, "SELECT", "INSERT"],
            "{src}"
        );
    }
}

#[test]
fn a_tsql_statement_whose_secret_a_template_writes_into_ends_with_its_grammar() {
    use lexega_syntax::ast::AstStmt;
    let mssql = lexega_syntax::dialect::mssql();
    for value in ["'{{ secrets.pw }}'", "'{{ var(\"pw\") }}'", "'a{{ x }}b'"] {
        for statement in [
            format!("OPEN SYMMETRIC KEY k DECRYPTION BY PASSWORD = {value}"),
            format!("OPEN MASTER KEY DECRYPTION BY PASSWORD = {value}"),
            format!("BACKUP MASTER KEY TO FILE = 'f' ENCRYPTION BY PASSWORD = {value}"),
            format!(
                "RESTORE MASTER KEY FROM FILE = 'f' DECRYPTION BY PASSWORD = {value} \
                 ENCRYPTION BY PASSWORD = {value}"
            ),
            format!("ADD SIGNATURE TO dbo.zz_p BY CERTIFICATE zz_c WITH PASSWORD = {value}"),
            format!("ALTER SERVICE MASTER KEY WITH NEW_ACCOUNT = 'a', NEW_PASSWORD = {value}"),
            format!("CREATE MASTER KEY ENCRYPTION BY PASSWORD = {value}"),
            format!("ALTER MASTER KEY ADD ENCRYPTION BY PASSWORD = {value}"),
            format!("CREATE CERTIFICATE zz_c ENCRYPTION BY PASSWORD = {value} WITH SUBJECT = 's'"),
            format!(
                "CREATE SYMMETRIC KEY zz_k WITH ALGORITHM = AES_256 ENCRYPTION BY PASSWORD = {value}"
            ),
            format!("CREATE CREDENTIAL zz_c WITH IDENTITY = 'i', SECRET = {value}"),
            format!("CREATE DATABASE SCOPED CREDENTIAL zz_c WITH IDENTITY = 'i', SECRET = {value}"),
            format!("CREATE LOGIN zz_l WITH PASSWORD = {value}"),
        ] {
            let src = format!("{statement};\nSELECT id FROM dbo.zz_src");
            let script = lexega_syntax::parse_sql_with_dialect(&src, &*mssql).expect("parses");
            assert!(
                !script
                    .stmts
                    .iter()
                    .any(|s| matches!(s, AstStmt::OpaqueContent { .. })),
                "{src}: {:?}",
                script.stmts
            );
            assert_eq!(
                statement_texts(&src, &mssql),
                [statement.as_str(), "SELECT"],
                "{src}"
            );
        }
    }
}

#[test]
fn a_security_statement_with_a_semicolon_keeps_every_token_it_had() {
    use lexega_syntax::dialect::{mssql, mysql, postgres, snowflake};
    for (statement, dialect) in [
        (
            "CREATE USER zz_u PASSWORD = 'x' DEFAULT_ROLE = r1 MUST_CHANGE_PASSWORD = TRUE",
            snowflake(),
        ),
        ("CREATE ROLE zz_r COMMENT = 'c'", snowflake()),
        (
            "ALTER DATABASE zz_db SET DATA_RETENTION_TIME_IN_DAYS = 1, COMMENT = 'c'",
            snowflake(),
        ),
        (
            "CREATE ROLE zz_r WITH LOGIN SUPERUSER PASSWORD 'x'",
            postgres(),
        ),
        ("ALTER ROLE zz_r WITH NOLOGIN", postgres()),
        ("CREATE SCHEMA zz_s AUTHORIZATION zz_r", postgres()),
        ("CREATE USER 'zz_u'@'h' IDENTIFIED BY 'x'", mysql()),
        (
            "CREATE LOGIN zz_l WITH PASSWORD = 'x', CHECK_POLICY = OFF",
            mssql(),
        ),
        (
            "ALTER DATABASE zz_db SET RECOVERY SIMPLE WITH NO_WAIT",
            mssql(),
        ),
    ] {
        let src = format!("{statement};\nSELECT id FROM zz_src;");
        assert_eq!(
            statement_texts(&src, &dialect),
            [statement, "SELECT"],
            "{src}"
        );
    }
}

#[test]
fn a_dropped_truncated_or_altered_table_is_the_name_its_tokens_spell() {
    use lexega_syntax::ast::{AstStmt, AstTableNameKind as K};
    use lexega_syntax::dialect::{mssql, postgres, snowflake};
    // The name's parts as written (`None` where it is no single name), its
    // kind, and its span's text.
    let name_of = |src: &str, dialect: &dyn lexega_syntax::dialect::Dialect| {
        let stmt = lexega_syntax::parse_sql_with_dialect(src, dialect)
            .expect("parses")
            .stmts
            .into_iter()
            .next()
            .expect("one statement");
        let name = match &stmt {
            AstStmt::Drop(d) => d.target_name.clone().expect("a name"),
            AstStmt::Truncate(t) => t.target_table.clone().expect("a name"),
            AstStmt::AlterTable(a) => a.name.clone(),
            other => panic!("{src}: {other:?}"),
        };
        let text =
            |s: lexega_syntax::lexer::Span| src[s.start as usize..s.end as usize].to_string();
        let parts = name.parts.as_ref().map(|parts| {
            parts
                .iter()
                .map(|p| p.as_ref().map(|part| text(part.span())))
                .collect::<Vec<_>>()
        });
        (parts, name.name_kind, text(name.span))
    };
    let some = |parts: &[&str]| Some(parts.iter().map(|p| Some(p.to_string())).collect());
    for (src, dialect, parts, kind, span) in [
        ("DROP TABLE #t", mssql(), some(&["#t"]), K::LocalTemp, "#t"),
        (
            "DROP TABLE IF EXISTS ##g",
            mssql(),
            some(&["##g"]),
            K::GlobalTemp,
            "##g",
        ),
        (
            "DROP TABLE tempdb..#t",
            mssql(),
            Some(vec![
                Some("tempdb".to_string()),
                None,
                Some("#t".to_string()),
            ]),
            K::LocalTemp,
            "tempdb..#t",
        ),
        (
            "TRUNCATE TABLE #t",
            mssql(),
            some(&["#t"]),
            K::LocalTemp,
            "#t",
        ),
        (
            "ALTER TABLE ##g ADD c INT",
            mssql(),
            some(&["##g"]),
            K::GlobalTemp,
            "##g",
        ),
        (
            "ALTER TABLE [dbo].[t] ADD c INT",
            mssql(),
            some(&["[dbo]", "[t]"]),
            K::Catalog,
            "[dbo].[t]",
        ),
        ("DROP TABLE #a, #b", mssql(), None, K::Catalog, "#a, #b"),
        (
            "DROP TABLE \"my.tbl\"",
            snowflake(),
            some(&["\"my.tbl\""]),
            K::Catalog,
            "\"my.tbl\"",
        ),
        (
            "TRUNCATE TABLE a./* c */b.t",
            snowflake(),
            some(&["a", "b", "t"]),
            K::Catalog,
            "a./* c */b.t",
        ),
        (
            "DROP FUNCTION f(INT)",
            postgres(),
            None,
            K::Catalog,
            "f(INT)",
        ),
        // `ONLY` before one table is no part of its name.
        (
            "TRUNCATE ONLY zz_a",
            postgres(),
            some(&["zz_a"]),
            K::Catalog,
            "zz_a",
        ),
        (
            "TRUNCATE ONLY zz_a, zz_b",
            postgres(),
            None,
            K::Catalog,
            "ONLY zz_a, zz_b",
        ),
    ] {
        assert_eq!(
            name_of(src, &*dialect),
            (parts, kind, span.to_string()),
            "{src}"
        );
        let config = lexega_syntax::FormatterConfig {
            dialect: dialect.clone(),
            ..Default::default()
        };
        let formatted = lexega_syntax::format_sql_with_config(src, &config).expect("formats");
        lexega_syntax::verify_formatting_safe_with_dialect(src, &formatted, &*dialect)
            .unwrap_or_else(|e| panic!("{src} -> {formatted}: {e}"));
    }
}

#[test]
fn each_table_a_truncate_lists_is_read_with_its_only() {
    use lexega_syntax::ast::AstStmt;
    use lexega_syntax::dialect::{mssql, postgres, snowflake};
    for (src, dialect, tables) in [
        ("TRUNCATE zz_a", postgres(), vec![(false, "zz_a")]),
        ("TRUNCATE ONLY zz_a *", postgres(), vec![(true, "zz_a")]),
        (
            "TRUNCATE zz_a, zz_b",
            postgres(),
            vec![(false, "zz_a"), (false, "zz_b")],
        ),
        (
            "TRUNCATE TABLE ONLY s.zz_a, zz_b * RESTART IDENTITY CASCADE",
            postgres(),
            vec![(true, "s.zz_a"), (false, "zz_b")],
        ),
        (
            "truncate zz_a, only zz_b",
            postgres(),
            vec![(false, "zz_a"), (true, "zz_b")],
        ),
        ("TRUNCATE TABLE #t", mssql(), vec![(false, "#t")]),
        (
            "TRUNCATE TABLE IF EXISTS a.b.t",
            snowflake(),
            vec![(false, "a.b.t")],
        ),
    ] {
        let stmt = lexega_syntax::parse_sql_with_dialect(src, &*dialect)
            .expect("parses")
            .stmts
            .into_iter()
            .next()
            .expect("one statement");
        let AstStmt::Truncate(truncate) = &stmt else {
            panic!("{src}: {stmt:?}");
        };
        let text = |s: lexega_syntax::lexer::Span| &src[s.start as usize..s.end as usize];
        let read: Vec<(bool, &str)> = truncate
            .tables
            .iter()
            .map(|table| (table.only_span.is_some(), text(table.name.span)))
            .collect();
        assert_eq!(read, tables, "{src}");
        for table in &truncate.tables {
            assert!(table.name.parts.is_some(), "{src}: {table:?}");
        }
    }
}

/// Each parameter as read: its mode, its name where written, its type.
type ReadParam<'a> = (
    lexega_syntax::ast::ProcedureParamMode,
    Option<&'a str>,
    Option<&'a str>,
);

fn read_params<'a>(
    src: &'a str,
    params: &[lexega_syntax::ast::AstProcedureParam],
) -> Vec<ReadParam<'a>> {
    let text = |s: lexega_syntax::lexer::Span| &src[s.start as usize..s.end as usize];
    params
        .iter()
        .map(|p| (p.mode, p.name_span.map(text), p.type_span.map(text)))
        .collect()
}

#[test]
fn each_argument_a_dropped_routine_lists_is_read_as_a_parameter() {
    use lexega_syntax::ast::AstStmt;
    use lexega_syntax::ast::ProcedureParamMode::{In, InOut, Out, Variadic};
    use lexega_syntax::dialect::{postgres, snowflake};
    for (src, dialect, targets) in [
        (
            "DROP PROCEDURE fill(double precision, text)",
            postgres(),
            vec![vec![
                (In, None, Some("double precision")),
                (In, None, Some("text")),
            ]],
        ),
        (
            "DROP PROCEDURE fill(x DOUBLE PRECISION, INOUT s text)",
            postgres(),
            vec![vec![
                (In, Some("x"), Some("DOUBLE PRECISION")),
                (InOut, Some("s"), Some("text")),
            ]],
        ),
        (
            "DROP FUNCTION f(OUT n int, VARIADIC xs int[], character varying(10)), g(), h",
            postgres(),
            vec![
                vec![
                    (Out, Some("n"), Some("int")),
                    (Variadic, Some("xs"), Some("int[]")),
                    (In, None, Some("character varying(10)")),
                ],
                vec![],
                vec![],
            ],
        ),
        (
            "DROP FUNCTION f(timestamp with time zone, date date, numeric(10, 2))",
            postgres(),
            vec![vec![
                (In, None, Some("timestamp with time zone")),
                (In, Some("date"), Some("date")),
                (In, None, Some("numeric(10, 2)")),
            ]],
        ),
        (
            "DROP PROCEDURE p(VARCHAR, DOUBLE PRECISION)",
            snowflake(),
            vec![vec![
                (In, None, Some("VARCHAR")),
                (In, None, Some("DOUBLE PRECISION")),
            ]],
        ),
    ] {
        let stmt = lexega_syntax::parse_sql_with_dialect(src, &*dialect)
            .expect("parses")
            .stmts
            .into_iter()
            .next()
            .expect("one statement");
        let AstStmt::Drop(drop) = &stmt else {
            panic!("{src}: {stmt:?}");
        };
        let read: Vec<Vec<ReadParam>> = drop
            .targets
            .iter()
            .map(|target| read_params(src, &target.params))
            .collect();
        assert_eq!(read, targets, "{src}");
    }
}

#[test]
fn a_parameter_type_of_several_words_is_read_whole() {
    use lexega_syntax::ast::AstStmt;
    use lexega_syntax::ast::ProcedureParamMode::{In, InOut};
    use lexega_syntax::dialect::{postgres, snowflake};
    for (src, dialect, params) in [
        (
            "CREATE PROCEDURE fill(x double precision DEFAULT 1.5, INOUT s character varying) LANGUAGE plpgsql AS $$ BEGIN NULL; END $$",
            postgres(),
            vec![
                (In, Some("x"), Some("double precision")),
                (InOut, Some("s"), Some("character varying")),
            ],
        ),
        (
            "CREATE FUNCTION f(timestamp with time zone, varchar(10) DEFAULT 'a') RETURNS int LANGUAGE sql AS $$ SELECT 1 $$",
            postgres(),
            vec![
                (In, None, Some("timestamp with time zone")),
                (In, None, Some("varchar(10)")),
            ],
        ),
        (
            "CREATE PROCEDURE p(x DOUBLE PRECISION, y VARCHAR DEFAULT 'a') RETURNS INT LANGUAGE SQL AS $$ SELECT 1 $$",
            snowflake(),
            vec![
                (In, Some("x"), Some("DOUBLE PRECISION")),
                (In, Some("y"), Some("VARCHAR")),
            ],
        ),
    ] {
        let stmt = lexega_syntax::parse_sql_with_dialect(src, &*dialect)
            .expect("parses")
            .stmts
            .into_iter()
            .next()
            .expect("one statement");
        let defined = if let AstStmt::CreateProcedure(p) = &stmt {
            &p.params
        } else if let AstStmt::CreateFunction(f) = &stmt {
            &f.params
        } else {
            panic!("{src}: {stmt:?}");
        };
        assert_eq!(read_params(src, defined), params, "{src}");
    }
}

#[test]
fn a_drop_or_truncate_name_leaves_out_the_clauses_after_it() {
    use lexega_syntax::dialect::{databricks, postgres, snowflake};
    for (src, dialect, name) in [
        ("DROP TABLE zz_t PURGE", databricks(), "zz_t"),
        ("DROP TABLE zz_t CASCADE", postgres(), "zz_t"),
        (
            "DROP FUNCTION f(INT, TEXT) CASCADE",
            postgres(),
            "f(INT, TEXT)",
        ),
        ("DROP FUNCTION f(NUMBER)", snowflake(), "f(NUMBER)"),
        ("TRUNCATE zz_t RESTART IDENTITY CASCADE", postgres(), "zz_t"),
        (
            "TRUNCATE ONLY zz_a, zz_b *",
            postgres(),
            "ONLY zz_a, zz_b *",
        ),
        (
            "TRUNCATE TABLE zz_t PARTITION (p = 1)",
            databricks(),
            "zz_t",
        ),
    ] {
        let parsed = statements_and_names(src, &*dialect);
        assert_eq!(parsed.len(), 1, "{src}: {parsed:?}");
        assert_eq!(parsed[0].1.as_deref(), Some(name), "{src}");
        let config = lexega_syntax::FormatterConfig {
            dialect: dialect.clone(),
            ..Default::default()
        };
        let formatted = lexega_syntax::format_sql_with_config(src, &config).expect("formats");
        lexega_syntax::verify_formatting_safe_with_dialect(src, &formatted, &*dialect)
            .unwrap_or_else(|e| panic!("{src} -> {formatted}: {e}"));
    }
}

#[test]
fn a_tsql_alter_table_without_a_semicolon_ends_with_its_action() {
    let mssql = lexega_syntax::dialect::mssql();
    for statement in [
        "ALTER TABLE [dbo].[zz_t]  WITH CHECK ADD  CONSTRAINT [fk_c] FOREIGN KEY([a])\n\
         REFERENCES [dbo].[zz_p] ([id])",
        "ALTER TABLE [dbo].[zz_t] CHECK CONSTRAINT [fk_c]",
        "ALTER TABLE dbo.zz_t NOCHECK CONSTRAINT ALL",
        "ALTER TABLE dbo.zz_t WITH NOCHECK CHECK CONSTRAINT fk_a, fk_b",
        "ALTER TABLE dbo.zz_t WITH NOCHECK ADD CONSTRAINT ck_a CHECK (a > 0)",
        "ALTER TABLE dbo.zz_t ENABLE TRIGGER ALL",
        "ALTER TABLE dbo.zz_t DISABLE TRIGGER trg_a, trg_b",
        "ALTER TABLE dbo.zz_t ENABLE CHANGE_TRACKING WITH (TRACK_COLUMNS_UPDATED = ON)",
        "ALTER TABLE dbo.zz_t DISABLE CHANGE_TRACKING",
        "ALTER TABLE dbo.zz_t ENABLE FILETABLE_NAMESPACE",
        "ALTER TABLE dbo.zz_t SWITCH TO dbo.zz_p",
        "ALTER TABLE dbo.zz_t SWITCH PARTITION 2 TO dbo.zz_p PARTITION 2 \
         WITH (WAIT_AT_LOW_PRIORITY (MAX_DURATION = 1 MINUTES, ABORT_AFTER_WAIT = NONE))",
        "ALTER TABLE dbo.zz_t REBUILD",
        "ALTER TABLE dbo.zz_t REBUILD WITH (DATA_COMPRESSION = PAGE)",
        "ALTER TABLE dbo.zz_t REBUILD PARTITION = ALL WITH (DATA_COMPRESSION = PAGE, ONLINE = ON)",
        "ALTER TABLE dbo.zz_t SET (LOCK_ESCALATION = AUTO)",
        "ALTER TABLE dbo.zz_t SET (SYSTEM_VERSIONING = ON (HISTORY_TABLE = dbo.zz_h))",
        "ALTER TABLE dbo.zz_t ADD c INT CONSTRAINT df_c DEFAULT 0 WITH VALUES",
        "ALTER TABLE dbo.zz_t ALTER COLUMN c INT NOT NULL",
        "ALTER TABLE dbo.zz_t DROP CONSTRAINT fk_c",
        "ALTER TABLE dbo.zz_t DROP COLUMN a, b",
        "ALTER TABLE dbo.zz_t ADD PERIOD FOR SYSTEM_TIME (vf, vt)",
        "ALTER TABLE #t ADD c INT",
        "ALTER TABLE dbo.zz_t ADD c AS a + b",
        "ALTER TABLE dbo.zz_t ADD c AS (a + b) PERSISTED",
        "ALTER TABLE dbo.zz_t ADD c AS CASE WHEN a > 0 THEN 1 ELSE 0 END",
        "ALTER TABLE dbo.zz_t ALTER COLUMN c ADD MASKED WITH (FUNCTION = 'default()')",
        "ALTER TABLE dbo.zz_t DROP CONSTRAINT IF EXISTS fk_a, fk_b",
        "ALTER TABLE dbo.zz_t DROP CONSTRAINT pk WITH (ONLINE = ON)",
        "ALTER TABLE dbo.zz_t ADD CONSTRAINT pk PRIMARY KEY CLUSTERED (id) WITH (ONLINE = ON) \
         ON [PRIMARY]",
        "ALTER TABLE dbo.zz_t ADD CONSTRAINT uq UNIQUE NONCLUSTERED (a ASC, b DESC)",
        "ALTER TABLE dbo.zz_t ADD a INT NULL, b VARCHAR(10) NOT NULL DEFAULT ('x')",
        "ALTER TABLE dbo.zz_t ADD CONSTRAINT df DEFAULT (getdate()) FOR c",
        "ALTER TABLE dbo.zz_t ADD c INT IDENTITY(1, 1) NOT NULL",
        "ALTER TABLE dbo.zz_t ADD vf DATETIME2 GENERATED ALWAYS AS ROW START HIDDEN NOT NULL \
         CONSTRAINT df_vf DEFAULT SYSUTCDATETIME(), vt DATETIME2 GENERATED ALWAYS AS ROW END \
         HIDDEN NOT NULL CONSTRAINT df_vt DEFAULT CONVERT(DATETIME2, '9999-12-31'), \
         PERIOD FOR SYSTEM_TIME (vf, vt)",
        "ALTER TABLE dbo.zz_t DROP PERIOD FOR SYSTEM_TIME",
        "ALTER TABLE dbo.zz_t ALTER COLUMN c ADD ROWGUIDCOL",
        "ALTER TABLE dbo.zz_t ALTER COLUMN c NVARCHAR(10) COLLATE Latin1_General_CI_AS NULL \
         WITH (ONLINE = ON)",
        "ALTER TABLE dbo.zz_t SET (DATA_DELETION = ON (FILTER_COLUMN = d, \
         RETENTION_PERIOD = 1 YEAR))",
    ] {
        for (end, src) in [
            ("", format!("{statement}\nSELECT id FROM dbo.zz_src\nINSERT INTO dbo.zz_dst (id) SELECT id FROM dbo.zz_src")),
            (";", format!("{statement};\nSELECT id FROM dbo.zz_src;\nINSERT INTO dbo.zz_dst (id) SELECT id FROM dbo.zz_src;")),
        ] {
            // An action's span runs to the next token; its tokens are the
            // statement's.
            let texts = statement_texts(&src, &mssql);
            let texts: Vec<&str> = texts.iter().map(|t| t.trim_end()).collect();
            assert_eq!(
                texts,
                [statement, "SELECT", "INSERT"],
                "ending {end:?}: {src}"
            );
        }
    }
}

#[test]
fn a_tsql_foreign_key_ends_with_its_referential_actions() {
    let mssql = lexega_syntax::dialect::mssql();
    let fk = "ALTER TABLE dbo.zz_t ADD CONSTRAINT fk_c FOREIGN KEY (a) REFERENCES dbo.zz_p (id)";
    for statement in [
        format!("{fk} ON DELETE CASCADE"),
        format!("{fk} ON DELETE SET NULL ON UPDATE SET DEFAULT"),
        format!("{fk} ON UPDATE CASCADE ON DELETE NO ACTION NOT FOR REPLICATION"),
        format!("{fk} ON UPDATE SET NULL"),
        "ALTER TABLE dbo.zz_t ADD FOREIGN KEY (a) REFERENCES dbo.zz_p ON DELETE CASCADE"
            .to_string(),
        "ALTER TABLE [dbo].[zz_t]  WITH CHECK ADD  CONSTRAINT [fk_c] FOREIGN KEY([a])\n\
         REFERENCES [dbo].[zz_p] ([id])\nON DELETE CASCADE"
            .to_string(),
        "ALTER TABLE dbo.zz_t ADD p_id INT NULL CONSTRAINT fk_p REFERENCES dbo.zz_p (id) \
         ON DELETE CASCADE"
            .to_string(),
        "ALTER TABLE dbo.zz_t ADD p_id INT REFERENCES dbo.zz_p (id) ON UPDATE SET NULL, \
         q_id INT REFERENCES dbo.zz_q (id) ON DELETE SET DEFAULT"
            .to_string(),
        "ALTER TABLE dbo.zz_t ADD c INT DEFAULT CASE WHEN 1 = 1 THEN 0 END".to_string(),
        "ALTER TABLE dbo.zz_t ADD CONSTRAINT df DEFAULT CASE WHEN 1 = 1 THEN 0 END FOR c"
            .to_string(),
        "CREATE TABLE dbo.zz_n (id INT, p_id INT CONSTRAINT fk_n REFERENCES dbo.zz_p (id) \
         ON DELETE CASCADE, CONSTRAINT fk_m FOREIGN KEY (id) REFERENCES dbo.zz_p (id) \
         ON DELETE SET NULL ON UPDATE CASCADE)"
            .to_string(),
    ] {
        for (end, src) in [
            ("", format!("{statement}\nSELECT id FROM dbo.zz_src\nINSERT INTO dbo.zz_dst (id) SELECT id FROM dbo.zz_src")),
            (";", format!("{statement};\nSELECT id FROM dbo.zz_src;\nINSERT INTO dbo.zz_dst (id) SELECT id FROM dbo.zz_src;")),
        ] {
            let texts = statement_texts(&src, &mssql);
            let texts: Vec<&str> = texts.iter().map(|t| t.trim_end()).collect();
            assert_eq!(
                texts,
                [statement.as_str(), "SELECT", "INSERT"],
                "ending {end:?}: {src}"
            );
        }
    }
}

#[test]
fn a_tsql_statement_start_word_its_grammar_holds_stays_in_the_statement() {
    let mssql = lexega_syntax::dialect::mssql();
    for statement in [
        "ALTER TABLE dbo.zz_t ALTER COLUMN c DROP NOT FOR REPLICATION",
        "DROP ASSEMBLY zz_a WITH NO DEPENDENTS",
        "DECLARE zz_cur CURSOR LOCAL FAST_FORWARD FOR SELECT id FROM dbo.zz_t",
        "DECLARE zz_cur CURSOR STATIC READ_ONLY FOR SELECT id FROM dbo.zz_t",
        "DECLARE zz_cur INSENSITIVE SCROLL CURSOR FOR SELECT id FROM dbo.zz_t",
        "DECLARE zz_cur CURSOR GLOBAL DYNAMIC SCROLL_LOCKS FOR SELECT id FROM dbo.zz_t \
         FOR UPDATE OF c",
        "ALTER TABLE dbo.zz_t DROP COLUMN IF EXISTS c",
        "ALTER TABLE dbo.zz_t DROP COLUMN IF EXISTS c, d",
        "ALTER TABLE dbo.zz_t DROP IF EXISTS df_c",
        "ALTER TABLE dbo.zz_t DROP IF EXISTS pk_c WITH (MOVE TO [SECONDARY])",
        "ALTER TABLE dbo.zz_t DROP CONSTRAINT IF EXISTS df_c, COLUMN IF EXISTS c",
        "ALTER TABLE dbo.zz_t DROP COLUMN IF EXISTS c, CONSTRAINT IF EXISTS df_c, IF EXISTS df_d",
        "ALTER TABLE [dbo].[zz_t] DROP COLUMN IF EXISTS [c]",
    ] {
        for (end, src) in [
            ("", format!("{statement}\nSELECT id FROM dbo.zz_src\nINSERT INTO dbo.zz_dst (id) SELECT id FROM dbo.zz_src")),
            (";", format!("{statement};\nSELECT id FROM dbo.zz_src;\nINSERT INTO dbo.zz_dst (id) SELECT id FROM dbo.zz_src;")),
        ] {
            let texts = statement_texts(&src, &mssql);
            let texts: Vec<&str> = texts.iter().map(|t| t.trim_end()).collect();
            assert_eq!(
                texts,
                [statement, "SELECT", "INSERT"],
                "ending {end:?}: {src}"
            );
        }
        let src = format!("{statement}\nGO\nSELECT id FROM dbo.zz_src\nGO");
        let texts = statement_texts(&src, &mssql);
        let texts: Vec<&str> = texts.iter().map(|t| t.trim_end()).collect();
        assert_eq!(texts, [statement, "GO", "SELECT", "GO"], "{src}");
    }
    // An `IF` that is not a dropped item's guard still starts a statement.
    let alter = "ALTER TABLE dbo.zz_t DROP COLUMN c";
    let guarded = "IF EXISTS (SELECT 1 FROM dbo.zz_src) DELETE FROM dbo.zz_dst";
    let src = format!("{alter}\n{guarded}");
    let texts = statement_texts(&src, &mssql);
    let texts: Vec<&str> = texts.iter().map(|t| t.trim_end()).collect();
    assert_eq!(texts, [alter, guarded], "{src}");
}

#[test]
fn a_tsql_drop_of_a_many_word_object_type_ends_with_its_grammar() {
    let mssql = lexega_syntax::dialect::mssql();
    for (statement, name) in [
        ("DROP PARTITION SCHEME zz_ps", "zz_ps"),
        ("DROP PARTITION FUNCTION zz_pf", "zz_pf"),
        ("DROP XML SCHEMA COLLECTION dbo.zz_x", "dbo.zz_x"),
        ("DROP SECURITY POLICY IF EXISTS dbo.zz_p", "dbo.zz_p"),
        ("DROP EXTERNAL DATA SOURCE zz_s", "zz_s"),
        ("DROP EXTERNAL FILE FORMAT zz_f", "zz_f"),
        ("DROP FULLTEXT CATALOG zz_c", "zz_c"),
        ("DROP FULLTEXT STOPLIST zz_l", "zz_l"),
        ("DROP FULLTEXT INDEX ON dbo.zz_t", "ON dbo.zz_t"),
        ("DROP EVENT NOTIFICATION zz_n, zz_m ON SERVER", "zz_n, zz_m"),
        ("DROP EVENT NOTIFICATION zz_n ON QUEUE dbo.zz_q", "zz_n"),
        ("DROP EVENT SESSION zz_e ON SERVER", "zz_e"),
        ("DROP MESSAGE TYPE zz_m", "zz_m"),
        ("DROP COLUMN MASTER KEY zz_k", "zz_k"),
        ("DROP COLUMN ENCRYPTION KEY zz_k", "zz_k"),
        ("DROP RESOURCE POOL zz_p", "zz_p"),
        ("DROP EXTERNAL RESOURCE POOL zz_p", "zz_p"),
        ("DROP WORKLOAD GROUP zz_g", "zz_g"),
        ("DROP BROKER PRIORITY zz_p", "zz_p"),
        ("DROP REMOTE SERVICE BINDING zz_b", "zz_b"),
        ("DROP CRYPTOGRAPHIC PROVIDER zz_p", "zz_p"),
        ("DROP EXTERNAL LIBRARY zz_l", "zz_l"),
        ("DROP EXTERNAL LIBRARY zz_l AUTHORIZATION dbo", "zz_l"),
        (
            "DROP EXTERNAL LIBRARY [zz_l] AUTHORIZATION [zz_owner]",
            "[zz_l]",
        ),
        (
            "drop external library zz_l /* c */ authorization /* c */ zz_owner",
            "zz_l",
        ),
        ("DROP ASSEMBLY zz_a WITH NO DEPENDENTS", "zz_a"),
        (
            "DROP COUNTER SIGNATURE FROM dbo.zz_p BY CERTIFICATE zz_c",
            "FROM dbo.zz_p BY CERTIFICATE zz_c",
        ),
        (
            "DROP SIGNATURE FROM dbo.zz_p BY CERTIFICATE zz_c, ASYMMETRIC KEY zz_k",
            "FROM dbo.zz_p BY CERTIFICATE zz_c, ASYMMETRIC KEY zz_k",
        ),
        (
            "DROP SENSITIVITY CLASSIFICATION FROM dbo.zz_t.c",
            "FROM dbo.zz_t.c",
        ),
        (
            "DROP SENSITIVITY CLASSIFICATION FROM dbo.zz_t.c, zz_u.d",
            "FROM dbo.zz_t.c, zz_u.d",
        ),
        ("DROP SELECTIVE XML INDEX zz_i ON dbo.zz_t", "zz_i"),
        ("DROP JSON INDEX zz_i ON dbo.zz_t", "zz_i"),
        ("DROP EXTERNAL STREAM zz_s", "zz_s"),
        ("DROP EXTERNAL STREAMING JOB zz_j", "zz_j"),
        ("DROP EXTERNAL LANGUAGE zz_l", "zz_l"),
        ("DROP WORKLOAD CLASSIFIER zz_c", "zz_c"),
    ] {
        for (end, src) in [
            ("", format!("{statement}\nSELECT id FROM dbo.zz_src\nINSERT INTO dbo.zz_dst (id) SELECT id FROM dbo.zz_src")),
            (";", format!("{statement};\nSELECT id FROM dbo.zz_src;\nINSERT INTO dbo.zz_dst (id) SELECT id FROM dbo.zz_src;")),
        ] {
            let texts = statement_texts(&src, &mssql);
            let texts: Vec<&str> = texts.iter().map(|t| t.trim_end()).collect();
            assert_eq!(
                texts,
                [statement, "SELECT", "INSERT"],
                "ending {end:?}: {src}"
            );
        }
        let src = format!("{statement}\nGO\nSELECT id FROM dbo.zz_src\nGO");
        let texts = statement_texts(&src, &mssql);
        let texts: Vec<&str> = texts.iter().map(|t| t.trim_end()).collect();
        assert_eq!(texts, [statement, "GO", "SELECT", "GO"], "{src}");
        let parsed = statements_and_names(statement, &*mssql);
        assert_eq!(parsed.len(), 1, "{statement}: {parsed:?}");
        assert_eq!(parsed[0].1.as_deref(), Some(name), "{statement}");
    }
}

#[test]
fn a_tsql_drop_index_ends_with_its_grammar() {
    let mssql = lexega_syntax::dialect::mssql();
    for statement in [
        "DROP INDEX zz_t.ix_c",
        "DROP INDEX dbo.zz_t.ix_c",
        "DROP INDEX IF EXISTS ix_c ON dbo.zz_t WITH (ONLINE = ON)",
        "DROP INDEX ix_a ON dbo.zz_t, ix_b ON dbo.zz_u WITH (MAXDOP = 1)",
    ] {
        for (end, src) in [
            ("", format!("{statement}\nSELECT id FROM dbo.zz_src\nINSERT INTO dbo.zz_dst (id) SELECT id FROM dbo.zz_src")),
            (";", format!("{statement};\nSELECT id FROM dbo.zz_src;\nINSERT INTO dbo.zz_dst (id) SELECT id FROM dbo.zz_src;")),
        ] {
            let texts = statement_texts(&src, &mssql);
            let texts: Vec<&str> = texts.iter().map(|t| t.trim_end()).collect();
            assert_eq!(
                texts,
                [statement, "SELECT", "INSERT"],
                "ending {end:?}: {src}"
            );
        }
    }
}

#[test]
fn a_tsql_schema_ends_before_the_batch_separator() {
    let mssql = lexega_syntax::dialect::mssql();
    for statement in [
        "CREATE SCHEMA zz_s",
        "CREATE SCHEMA [zz_stg]",
        "CREATE SCHEMA zz_s AUTHORIZATION dbo",
    ] {
        let src = format!("{statement}\nGO\nSELECT id FROM dbo.zz_src\nGO");
        let texts = statement_texts(&src, &mssql);
        let texts: Vec<&str> = texts.iter().map(|t| t.trim_end()).collect();
        assert_eq!(texts, [statement, "GO", "SELECT", "GO"], "{src}");
    }
}

/// Each statement, followed by a `GO` batch and by a `;`, is read as its own
/// statement and the `DELETE` after it as another.
fn assert_tsql_statements_end_before_the_next(statements: &[&str]) {
    let mssql = lexega_syntax::dialect::mssql();
    for &statement in statements {
        for (src, expected) in [
            (
                format!("{statement}\nGO\nDELETE FROM dbo.zz_t\nGO"),
                vec![statement, "GO", "DELETE FROM dbo.zz_t", "GO"],
            ),
            (
                format!("{statement};\nDELETE FROM dbo.zz_t;"),
                vec![statement, "DELETE FROM dbo.zz_t"],
            ),
        ] {
            let texts = statement_texts(&src, &mssql);
            let texts: Vec<&str> = texts.iter().map(|t| t.trim_end()).collect();
            assert_eq!(texts, expected, "{src}");
        }
    }
}

#[test]
fn a_tsql_declaration_list_is_one_statement_with_every_variable() {
    use lexega_syntax::ast::AstStmt;
    let mssql = lexega_syntax::dialect::mssql();
    // (statement, each variable: name, type, initialiser with its operator)
    type Declaration<'a> = (&'a str, &'a [(&'a str, &'a str, &'a str)]);
    let cases: [Declaration<'_>; 7] = [
        (
            "DECLARE @x INT = 1, @y INT = 2",
            &[("@x", "INT", "= 1"), ("@y", "INT", "= 2")],
        ),
        (
            "DECLARE @x INT, @y INT = 2, @z VARCHAR(10)",
            &[
                ("@x", "INT", ""),
                ("@y", "INT", "= 2"),
                ("@z", "VARCHAR(10)", ""),
            ],
        ),
        (
            "DECLARE @x INT = 1, @y INT, @z INT = @x + 1",
            &[
                ("@x", "INT", "= 1"),
                ("@y", "INT", ""),
                ("@z", "INT", "= @x + 1"),
            ],
        ),
        (
            "DECLARE @x INT = 1, @y INT = (SELECT 2)",
            &[("@x", "INT", "= 1"), ("@y", "INT", "= (SELECT 2)")],
        ),
        (
            "DECLARE @x AS INT = 1, @y AS DECIMAL(10, 2) = 2.5",
            &[
                ("@x", "AS INT", "= 1"),
                ("@y", "AS DECIMAL(10, 2)", "= 2.5"),
            ],
        ),
        (
            "DECLARE @c CURSOR, @x INT = COALESCE(@y, 1)",
            &[("@c", "CURSOR", ""), ("@x", "INT", "= COALESCE(@y, 1)")],
        ),
        ("DECLARE @c CURSOR", &[("@c", "CURSOR", "")]),
    ];
    let text = |src: &str, span: Option<lexega_syntax::lexer::Span>| {
        span.map_or(String::new(), |s| {
            src[s.start as usize..s.end as usize].to_string()
        })
    };
    for (statement, expected) in cases {
        let script = lexega_syntax::parse_sql_with_dialect(statement, &*mssql).expect("parses");
        let AstStmt::Declare { variables, .. } = &script.stmts[0] else {
            panic!("{statement}: not a DECLARE");
        };
        let found: Vec<(String, String, String)> = variables
            .iter()
            .map(|v| {
                (
                    text(statement, Some(v.name.span)),
                    text(statement, v.type_span),
                    text(statement, v.default_expr_span),
                )
            })
            .collect();
        let expected: Vec<(String, String, String)> = expected
            .iter()
            .map(|(n, t, d)| (n.to_string(), t.to_string(), d.to_string()))
            .collect();
        assert_eq!(found, expected, "{statement}");
    }
    // Each ends where its last variable does, `;` or not; the formatter
    // writes it as written.
    assert_tsql_statements_end_before_the_next(&cases.map(|(statement, _)| statement));
    let texts = statement_texts(
        "DECLARE @x INT = 1, @y INT = 2\nDELETE FROM dbo.zz_t",
        &mssql,
    );
    assert_eq!(
        texts,
        ["DECLARE @x INT = 1, @y INT = 2", "DELETE FROM dbo.zz_t"]
    );
    // Elsewhere a DECLARE holds one variable, as before.
    for (src, dialect) in [
        (
            "DECLARE x INT DEFAULT 1",
            lexega_syntax::dialect::bigquery(),
        ),
        (
            "DECLARE VARIABLE x INT DEFAULT 1",
            lexega_syntax::dialect::databricks(),
        ),
    ] {
        let script = lexega_syntax::parse_sql_with_dialect(src, &*dialect).expect("parses");
        let AstStmt::Declare { variables, .. } = &script.stmts[0] else {
            panic!("{src}: not a DECLARE");
        };
        assert_eq!(variables.len(), 1, "{src}");
    }
}

#[test]
fn a_tsql_insert_from_exec_holds_the_exec_statement() {
    use lexega_syntax::ast::{AstInsertSourceKind, AstStmt};
    let mssql = lexega_syntax::dialect::mssql();
    // (statement, target, the EXEC as written)
    let cases = [
        (
            "INSERT INTO dbo.zz_t EXEC dbo.zz_p",
            "dbo.zz_t",
            "EXEC dbo.zz_p",
        ),
        (
            "INSERT INTO dbo.zz_t (id, c) EXEC dbo.zz_p @a = 1, @b = N'x'",
            "dbo.zz_t",
            "EXEC dbo.zz_p @a = 1, @b = N'x'",
        ),
        (
            "INSERT INTO #t EXECUTE dbo.zz_p 1",
            "#t",
            "EXECUTE dbo.zz_p 1",
        ),
        ("INSERT INTO @t EXEC (@sql)", "@t", "EXEC (@sql)"),
        (
            "INSERT INTO dbo.zz_t EXECUTE ('SELECT id FROM dbo.zz_src')",
            "dbo.zz_t",
            "EXECUTE ('SELECT id FROM dbo.zz_src')",
        ),
        (
            "INSERT INTO dbo.zz_t WITH (TABLOCK) EXEC sp_executesql @sql",
            "dbo.zz_t",
            "EXEC sp_executesql @sql",
        ),
    ];
    let text = |src: &str, span: lexega_syntax::lexer::Span| {
        src[span.start as usize..span.end as usize].to_string()
    };
    for (statement, target, exec) in cases {
        for (src, count) in [
            (format!("{statement}\nDELETE FROM dbo.zz_r"), 2),
            (format!("{statement};\nDELETE FROM dbo.zz_r;"), 2),
            (format!("{statement}\nGO\nDELETE FROM dbo.zz_r\nGO"), 4),
        ] {
            let script = lexega_syntax::parse_sql_with_dialect(&src, &*mssql).expect("parses");
            assert_eq!(script.stmts.len(), count, "{src}");
            let AstStmt::Insert(insert) = &script.stmts[0] else {
                panic!("{src}: not an INSERT");
            };
            assert!(
                matches!(insert.source_kind, AstInsertSourceKind::Execute),
                "{src}"
            );
            let target_span = insert.target_table.as_ref().expect("a target").span;
            assert_eq!(text(&src, target_span), target, "{src}");
            let executed = insert.execute.as_deref().expect("the EXEC");
            assert!(matches!(executed, AstStmt::MssqlExec(_)), "{src}");
            assert_eq!(text(&src, executed.span()), exec, "{src}");
            assert_eq!(text(&src, insert.span), statement, "{src}");
            let texts = statement_texts(&src, &mssql);
            assert_eq!(
                texts.last().map(String::as_str),
                Some(if count == 4 {
                    "GO"
                } else {
                    "DELETE FROM dbo.zz_r"
                }),
                "{src}"
            );
        }
    }
}

#[test]
fn a_tsql_fetch_reads_its_orientation_and_ends_with_its_variables() {
    use lexega_syntax::ast::{AstFetchOrientation as O, AstStmt};
    let mssql = lexega_syntax::dialect::mssql();
    // (statement, orientation, its text, cursor, INTO variables)
    let cases: [(&str, &str, &str, &str, &[&str]); 10] = [
        ("FETCH c INTO @a, @b", "", "", "c", &["@a", "@b"]),
        (
            "FETCH NEXT FROM c INTO @a, @b",
            "next",
            "NEXT",
            "c",
            &["@a", "@b"],
        ),
        ("FETCH PRIOR FROM c INTO @a", "prior", "PRIOR", "c", &["@a"]),
        ("FETCH FIRST FROM c INTO @a", "first", "FIRST", "c", &["@a"]),
        ("FETCH LAST FROM c INTO @a", "last", "LAST", "c", &["@a"]),
        (
            "FETCH ABSOLUTE 5 FROM c INTO @a",
            "absolute",
            "ABSOLUTE 5",
            "c",
            &["@a"],
        ),
        (
            "FETCH RELATIVE @n FROM c INTO @a",
            "relative",
            "RELATIVE @n",
            "c",
            &["@a"],
        ),
        ("FETCH FROM c INTO @a", "", "", "c", &["@a"]),
        (
            "FETCH NEXT FROM GLOBAL c INTO @a",
            "next",
            "NEXT",
            "c",
            &["@a"],
        ),
        ("FETCH NEXT FROM @cv", "next", "NEXT", "@cv", &[]),
    ];
    let text = |src: &str, span: lexega_syntax::lexer::Span| {
        src[span.start as usize..span.end as usize].to_string()
    };
    for (statement, kind, written, cursor, variables) in cases {
        // Without `;` the next statement starts at its own first word.
        for src in [
            format!("{statement}\nPRINT 'x'"),
            format!("{statement};\nPRINT 'x';"),
            format!("{statement}\nGO\nPRINT 'x'\nGO"),
            format!("BEGIN\n{statement}\nPRINT 'x'\nEND"),
        ] {
            let script = lexega_syntax::parse_sql_with_dialect(&src, &*mssql).expect("parses");
            let fetch = if let AstStmt::Block(b) = &script.stmts[0] {
                &b.body[0]
            } else {
                &script.stmts[0]
            };
            let AstStmt::FetchCursor {
                orientation,
                orientation_span,
                cursor_name_span,
                into_targets,
                ..
            } = fetch
            else {
                panic!("{src}: not a FETCH");
            };
            let found = match orientation {
                None => "",
                Some(O::Next) => "next",
                Some(O::Prior) => "prior",
                Some(O::First) => "first",
                Some(O::Last) => "last",
                Some(O::Absolute(_)) => "absolute",
                Some(O::Relative(_)) => "relative",
                Some(O::All) => "all",
                Some(O::Forward(_)) => "forward",
                Some(O::Backward(_)) => "backward",
            };
            assert_eq!(found, kind, "{src}");
            assert_eq!(
                orientation_span.map_or(String::new(), |s| text(&src, s)),
                written,
                "{src}"
            );
            assert_eq!(text(&src, *cursor_name_span), cursor, "{src}");
            let into: Vec<String> = into_targets.iter().map(|v| text(&src, v.span)).collect();
            assert_eq!(into, variables, "{src}");
            assert_eq!(
                text(&src, fetch.span()).trim_end_matches(';'),
                statement,
                "{src}"
            );
            statement_texts(&src, &mssql);
        }
    }
    // OPEN and CLOSE of a cursor at the top level, as in a block.
    let texts = statement_texts("OPEN c\nCLOSE c\nDEALLOCATE c\nPRINT 'x'", &mssql);
    assert_eq!(texts, ["OPEN c", "CLOSE c", "DEALLOCATE c", "PRINT 'x'"]);
}

#[test]
fn a_postgres_fetch_and_move_read_their_direction() {
    use lexega_syntax::ast::{AstFetchCount as C, AstFetchOrientation as O, AstStmt};
    let pg = lexega_syntax::dialect::postgres();
    let text = |src: &str, span: lexega_syntax::lexer::Span| {
        src[span.start as usize..span.end as usize].to_string()
    };
    fn walk<'a>(stmt: &'a AstStmt, out: &mut Vec<&'a AstStmt>) {
        out.push(stmt);
        for body in stmt.bodies() {
            for s in body.stmts {
                walk(s, out);
            }
        }
    }
    // (statement, direction, its text, cursor, a MOVE)
    let cases = [
        ("FETCH ALL FROM c", "all", "ALL", "c", false),
        (
            "FETCH FORWARD 5 FROM c",
            "forward 5",
            "FORWARD 5",
            "c",
            false,
        ),
        ("FETCH FORWARD FROM c", "forward", "FORWARD", "c", false),
        (
            "FETCH FORWARD ALL IN c",
            "forward all",
            "FORWARD ALL",
            "c",
            false,
        ),
        (
            "FETCH BACKWARD 2 FROM c",
            "backward 2",
            "BACKWARD 2",
            "c",
            false,
        ),
        (
            "FETCH BACKWARD ALL FROM c",
            "backward all",
            "BACKWARD ALL",
            "c",
            false,
        ),
        ("FETCH 3 FROM c", "forward 3", "3", "c", false),
        ("FETCH NEXT IN c", "next", "NEXT", "c", false),
        ("MOVE NEXT FROM c", "next", "NEXT", "c", true),
        ("MOVE FORWARD 5 IN c", "forward 5", "FORWARD 5", "c", true),
        ("MOVE ALL FROM c", "all", "ALL", "c", true),
        ("MOVE c", "", "", "c", true),
    ];
    for (statement, kind, written, cursor, moves) in cases {
        for src in [
            format!("{statement}; DELETE FROM o;"),
            format!(
                "CREATE FUNCTION f() RETURNS void LANGUAGE plpgsql AS $$ BEGIN {statement}; DELETE FROM o; END $$;"
            ),
        ] {
            let script = lexega_syntax::parse_sql_with_dialect(&src, &*pg).expect("parses");
            let mut found = Vec::new();
            for stmt in &script.stmts {
                walk(stmt, &mut found);
            }
            let Some(AstStmt::FetchCursor {
                move_span,
                orientation,
                orientation_span,
                cursor_name_span,
                span,
                ..
            }) = found
                .iter()
                .find(|s| matches!(s, AstStmt::FetchCursor { .. }))
                .copied()
            else {
                panic!("{src}: no FETCH: {found:?}");
            };
            assert_eq!(text(&src, *span).trim_end_matches(';'), statement, "{src}");
            assert_eq!(move_span.is_some(), moves, "{src}");
            let count = |c: &Option<C>| match c {
                None => String::new(),
                Some(C::All) => " all".to_string(),
                Some(C::Count(n)) => format!(" {}", text(&src, n.span())),
            };
            let direction = match orientation {
                None => String::new(),
                Some(O::Next) => "next".to_string(),
                Some(O::All) => "all".to_string(),
                Some(O::Forward(c)) => format!("forward{}", count(c)),
                Some(O::Backward(c)) => format!("backward{}", count(c)),
                Some(other) => format!("{other:?}"),
            };
            assert_eq!(direction, kind, "{src}");
            assert_eq!(
                orientation_span.map_or(String::new(), |s| text(&src, s)),
                written,
                "{src}"
            );
            assert_eq!(text(&src, *cursor_name_span), cursor, "{src}");
            assert!(
                found.iter().any(|s| matches!(s, AstStmt::Delete(_))),
                "{src}: the statement after is read"
            );
            let config = lexega_syntax::FormatterConfig { dialect: lexega_syntax::dialect::postgres(), ..Default::default() };
            let formatted = lexega_syntax::format_sql_with_config(&src, &config).expect("formats");
            lexega_syntax::verify_formatting_safe_with_dialect(&src, &formatted, &*pg)
                .unwrap_or_else(|e| panic!("{src}: {e}\n{formatted}"));
        }
    }
    // `move` written as a name is a name.
    let script = lexega_syntax::parse_sql_with_dialect("SELECT move FROM t", &*pg).expect("parses");
    assert!(matches!(script.stmts.as_slice(), [AstStmt::Select(_)]));
}

#[test]
fn a_cursor_fetch_after_a_query_without_a_semicolon_is_a_statement_of_its_own() {
    use lexega_syntax::ast::AstStmt;
    let mssql = lexega_syntax::dialect::mssql();
    let queries = [
        "SELECT id FROM dbo.zz_s",
        "SELECT id FROM dbo.zz_s s",
        "SELECT * FROM dbo.zz_s",
        "SELECT @b = c FROM dbo.zz_s",
        "SELECT id FROM dbo.zz_s WHERE id = @a",
        "SELECT id FROM dbo.zz_s ORDER BY id",
        "SELECT id FROM dbo.zz_s ORDER BY id OFFSET 0 ROWS",
        "INSERT INTO dbo.zz_t (id) SELECT id FROM dbo.zz_s WHERE id = @a",
        "SELECT 1",
        "SELECT @a = 1",
        "SELECT @n = @n + 1",
    ];
    let fetches = [
        "FETCH NEXT FROM c INTO @a",
        "FETCH FIRST FROM c INTO @a",
        "FETCH PRIOR FROM c INTO @a",
        "FETCH ABSOLUTE 2 FROM c INTO @a",
        "FETCH NEXT FROM GLOBAL c INTO @a",
        "FETCH c INTO @a",
        "FETCH @c INTO @a",
        "FETCH NEXT FROM c",
        "FETCH @c",
    ];
    for query in queries {
        let head = if query.starts_with("INSERT") {
            "INSERT"
        } else {
            "SELECT"
        };
        for fetch in fetches {
            let src = format!("{query}\n{fetch}");
            let texts = statement_texts(&src, &mssql);
            assert_eq!(texts, [head, fetch], "{src}");
            let looped = format!("WHILE @@FETCH_STATUS = 0\nBEGIN\n  {query}\n  {fetch}\nEND");
            let script = lexega_syntax::parse_sql_with_dialect(&looped, &*mssql).expect("parses");
            let Some(AstStmt::MssqlWhile(w)) = script.stmts.first() else {
                panic!("{looped}: {:?}", script.stmts);
            };
            let Some(AstStmt::Block(block)) = w.body.first() else {
                panic!("{looped}: {:?}", w.body);
            };
            assert_eq!(block.body.len(), 2, "{looped}: {:?}", block.body);
            assert!(
                matches!(block.body[1], AstStmt::FetchCursor { .. }),
                "{looped}: {:?}",
                block.body[1]
            );
        }
    }
}

#[test]
fn a_tsql_compound_assignment_assigns_the_variable_with_its_operator() {
    use lexega_syntax::ast::{AstExpr, AstStmt, BinaryOperator};
    let mssql = lexega_syntax::dialect::mssql();
    for (statement, operator) in [
        ("SET @sql += N' WHERE id = 1'", BinaryOperator::Plus),
        ("SET @i -= 1", BinaryOperator::Minus),
        ("SET @i *= 2", BinaryOperator::Multiply),
        ("SET @i /= 2", BinaryOperator::Divide),
        ("SET @i %= 3", BinaryOperator::Modulo),
    ] {
        let src = format!("{statement}\nDELETE FROM dbo.t");
        let script = lexega_syntax::parse_sql_with_dialect(&src, &*mssql).expect("parses");
        let [AstStmt::SetVariable {
            variable_names,
            values,
            ..
        }, AstStmt::Delete(_)] = script.stmts.as_slice()
        else {
            panic!("{src}: {:?}", script.stmts);
        };
        let name = &src[variable_names[0].span.start as usize..variable_names[0].span.end as usize];
        let [AstExpr::BinaryOp {
            left,
            operator: read,
            ..
        }] = values.as_slice()
        else {
            panic!("{src}: {values:?}");
        };
        assert_eq!(*read, operator, "{src}");
        let AstExpr::Ident { column_ref, .. } = left.as_ref() else {
            panic!("{src}: {left:?}");
        };
        let left_name =
            &src[column_ref.name.span.start as usize..column_ref.name.span.end as usize];
        assert_eq!(left_name, name, "{src}");
        statement_texts(&src, &mssql);
    }
}

#[test]
fn set_var_assigns_the_variables_after_its_keyword_in_every_dialect() {
    use lexega_syntax::ast::AstStmt;
    use lexega_syntax::dialect::{bigquery, databricks, mssql, mysql, postgres, snowflake};
    // (dialect, statement, the names it assigns, how many values).
    let cases = [
        (databricks(), "SET VAR x = 1;", vec!["x"], 1),
        (databricks(), "SET VARIABLE x = 1;", vec!["x"], 1),
        (databricks(), "set var x = 1;", vec!["x"], 1),
        (databricks(), "SET VAR x = 1, y = 'a';", vec!["x", "y"], 2),
        (
            databricks(),
            "SET VAR (x, y) = (SELECT 1, 2);",
            vec!["x", "y"],
            1,
        ),
        (databricks(), "SET VAR session.x = 1;", vec!["x"], 1),
        (
            databricks(),
            "SET VAR system.session.x = 1, y = 2;",
            vec!["x", "y"],
            2,
        ),
        (databricks(), "BEGIN SET VAR x = 1; END;", vec!["x"], 1),
        (snowflake(), "SET VAR x = 1;", vec!["x"], 1),
        (bigquery(), "SET VAR x = 1;", vec!["x"], 1),
        (mysql(), "SET VAR x = 1;", vec!["x"], 1),
        (postgres(), "SET VARIABLE x = 1;", vec!["x"], 1),
        (mssql(), "SET VAR x = 1", vec!["x"], 1),
        // The word before `=` is the name.
        (databricks(), "SET var = 1;", vec!["var"], 1),
        (databricks(), "SET VAR = 1;", vec!["VAR"], 1),
        (snowflake(), "SET var = 1;", vec!["var"], 1),
        (bigquery(), "SET variable = 1;", vec!["variable"], 1),
        (snowflake(), "SET (var, x) = (1, 2);", vec!["var", "x"], 2),
    ];
    for (dialect, src, names, values_read) in cases {
        let script = lexega_syntax::parse_sql_with_dialect(src, dialect.as_ref()).expect("parses");
        let mut stmt = &script.stmts[0];
        if let AstStmt::Block(b) = stmt {
            stmt = &b.body[0];
        }
        let AstStmt::SetVariable {
            variable_names,
            values,
            ..
        } = stmt
        else {
            panic!("{src}: {:?}", script.stmts);
        };
        let read: Vec<&str> = variable_names
            .iter()
            .map(|n| &src[n.span.start as usize..n.span.end as usize])
            .collect();
        assert_eq!(read, names, "{src}");
        assert_eq!(values.len(), values_read, "{src}");
    }
    // A dialect's own SET is read as before.
    let script =
        lexega_syntax::parse_sql_with_dialect("SET var = 1;", mysql().as_ref()).expect("parses");
    assert!(
        matches!(script.stmts.as_slice(), [AstStmt::MysqlSet(_)]),
        "{:?}",
        script.stmts
    );
    let script =
        lexega_syntax::parse_sql_with_dialect("SET IDENTITY_INSERT users ON", mssql().as_ref())
            .expect("parses");
    assert!(
        !matches!(script.stmts.as_slice(), [AstStmt::SetVariable { .. }]),
        "{:?}",
        script.stmts
    );
}

#[test]
fn a_literal_assigned_to_a_variable_named_for_a_secret_is_recorded_as_a_secret() {
    let m = "Zq9Mark";
    let cases = [
        (
            lexega_syntax::dialect::mssql(),
            format!("DECLARE @password NVARCHAR(100) = N'{m}'"),
        ),
        (
            lexega_syntax::dialect::mssql(),
            format!("SET @api_key = '{m}'"),
        ),
        (
            lexega_syntax::dialect::mssql(),
            format!("SELECT @pwd = N'{m}'"),
        ),
        (
            lexega_syntax::dialect::snowflake(),
            format!("SET PASSWORD = '{m}'"),
        ),
        (
            lexega_syntax::dialect::snowflake(),
            format!("BEGIN LET secret STRING := '{m}'; my_token := '{m}'; END;"),
        ),
        (
            lexega_syntax::dialect::mysql(),
            format!("SET @password = '{m}'"),
        ),
        (
            lexega_syntax::dialect::mysql(),
            format!("SELECT '{m}' INTO @password"),
        ),
    ];
    for (dialect, src) in &cases {
        let script = lexega_syntax::parse_sql_with_dialect(src, &**dialect).expect("parses");
        let recorded: Vec<&str> = script
            .redaction_spans
            .iter()
            .map(|s| &src[s.start as usize..s.end as usize])
            .collect();
        assert!(!recorded.is_empty(), "{src}");
        assert!(recorded.iter().all(|r| *r == m), "{src}: {recorded:?}");
    }
    let mssql = lexega_syntax::dialect::mssql();
    // Every literal a secret-named variable's value holds is recorded.
    let src = "SET @password = (SELECT p FROM dbo.t WHERE c = 'x' AND d = N'y')";
    let script = lexega_syntax::parse_sql_with_dialect(src, &*mssql).expect("parses");
    let recorded: Vec<&str> = script
        .redaction_spans
        .iter()
        .map(|s| &src[s.start as usize..s.end as usize])
        .collect();
    assert_eq!(recorded, ["x", "y"], "{src}");
    for src in [
        format!("DECLARE @name NVARCHAR(100) = N'{m}'"),
        "SET @password = (SELECT p FROM dbo.t)".to_string(),
        "SET @password = @other".to_string(),
    ] {
        let script = lexega_syntax::parse_sql_with_dialect(&src, &*mssql).expect("parses");
        assert!(
            script.redaction_spans.is_empty(),
            "{src}: {:?}",
            script.redaction_spans
        );
    }
}

#[test]
fn fetch_is_a_bare_column_alias_only_where_the_dialect_does_not_reserve_it() {
    use lexega_syntax::ast::AstStmt;
    let src = "SELECT 1 fetch";
    for dialect in [
        lexega_syntax::dialect::snowflake(),
        lexega_syntax::dialect::databricks(),
    ] {
        let script = lexega_syntax::parse_sql_with_dialect(src, &*dialect).expect("parses");
        let [AstStmt::Select(select)] = script.stmts.as_slice() else {
            panic!("{}: {:?}", dialect.name(), script.stmts);
        };
        assert_eq!(select.span.end as usize, src.len(), "{}", dialect.name());
    }
    // T-SQL and MySQL 8.0 reserve FETCH.
    for dialect in [
        lexega_syntax::dialect::mssql(),
        lexega_syntax::dialect::mysql(),
    ] {
        let script = lexega_syntax::parse_sql_with_dialect(src, &*dialect).expect("parses");
        let Some(AstStmt::Select(select)) = script.stmts.first() else {
            panic!("{}: {:?}", dialect.name(), script.stmts);
        };
        assert_eq!(
            &src[select.span.start as usize..select.span.end as usize],
            "SELECT 1",
            "{}",
            dialect.name()
        );
    }
}

#[test]
fn a_word_the_dialect_does_not_reserve_is_a_bare_column_alias() {
    use lexega_syntax::ast::AstStmt;
    // The first label: Snowflake reserves START.
    let cases = [
        (lexega_syntax::dialect::mysql(), "start", "end"),
        (lexega_syntax::dialect::mysql(), "start", "view"),
        (lexega_syntax::dialect::mysql(), "start", "any"),
        (lexega_syntax::dialect::mysql(), "start", "some"),
        (lexega_syntax::dialect::mysql(), "start", "current"),
        (lexega_syntax::dialect::postgres(), "start", "view"),
        (lexega_syntax::dialect::postgres(), "start", "set"),
        (lexega_syntax::dialect::postgres(), "start", "revoke"),
        (lexega_syntax::dialect::snowflake(), "lo", "end"),
    ];
    for (dialect, first, word) in cases {
        let src = format!("SELECT MIN(id) {first}, MAX(id) {word} FROM users");
        let script = lexega_syntax::parse_sql_with_dialect(&src, &*dialect).expect("parses");
        let [AstStmt::Select(select)] = script.stmts.as_slice() else {
            panic!("{}: {src}: {:?}", dialect.name(), script.stmts);
        };
        assert_eq!(
            select.span.end as usize,
            src.len(),
            "{}: {src}",
            dialect.name()
        );
    }
}

#[test]
fn a_postgresql_keyword_that_needs_no_as_is_a_bare_column_label() {
    use lexega_syntax::ast::AstStmt;
    use lexega_syntax::Dialect;
    let pg = lexega_syntax::dialect::postgres();
    let one_select = |dialect: &dyn Dialect, src: &str| {
        let script = lexega_syntax::parse_sql_with_dialect(src, dialect).expect("parses");
        matches!(
            script.stmts.as_slice(),
            [AstStmt::Select(select)] if select.span.end as usize == src.len()
        )
    };
    for word in [
        "end", "default", "table", "only", "any", "some", "lateral", "all", "distinct", "case",
        "when", "then", "else", "exists", "not", "values", "select", "insert", "update", "delete",
        "alter", "drop",
    ] {
        let src = format!("SELECT MAX(id) {word} FROM users");
        assert!(one_select(&*pg, &src), "postgresql: {src}");
    }
    // The keywords PostgreSQL needs `AS` before end the select item.
    for word in ["fetch", "grant", "for", "create", "with", "to"] {
        let src = format!("SELECT MAX(id) {word} FROM users");
        assert!(!one_select(&*pg, &src), "postgresql: {src}");
    }
    // T-SQL reserves FETCH.
    assert!(!one_select(
        &*lexega_syntax::dialect::mssql(),
        "SELECT MAX(id) fetch FROM users"
    ));
}

#[test]
fn only_postgresql_answers_bare_column_labels_apart_from_identifiers() {
    use lexega_syntax::{Dialect, MsSqlDialect, PostgresDialect, SnowflakeDialect};
    for word in ["END", "DEFAULT", "TABLE", "DELETE", "ONLY", "LATERAL"] {
        assert!(
            PostgresDialect.keyword_can_be_bare_column_label(word),
            "{word}"
        );
    }
    for word in [
        "FETCH", "GRANT", "FOR", "CREATE", "WITH", "TO", "day", "Over",
    ] {
        assert!(
            !PostgresDialect.keyword_can_be_bare_column_label(word),
            "{word}"
        );
    }
    assert!(!MsSqlDialect.keyword_can_be_bare_column_label("FETCH"));
    for word in ["END", "TABLE", "FETCH", "VIEW"] {
        assert_eq!(
            SnowflakeDialect.keyword_can_be_bare_column_label(word),
            SnowflakeDialect.keyword_can_be_unquoted_identifier(word),
            "{word}"
        );
    }
}

#[test]
fn a_statement_word_the_database_does_not_reserve_is_a_bare_column_label() {
    use lexega_syntax::ast::AstStmt;
    use lexega_syntax::{Dialect, MySqlDialect, SnowflakeDialect};
    // Snowflake does not reserve TRUNCATE, MySQL does not reserve DO; both
    // reserve DELETE, INSERT, SELECT and DROP.
    assert!(SnowflakeDialect.keyword_can_be_bare_column_label("truncate"));
    assert!(MySqlDialect.keyword_can_be_bare_column_label("DO"));
    for word in ["DELETE", "INSERT", "SELECT", "DROP"] {
        assert!(
            !SnowflakeDialect.keyword_can_be_bare_column_label(word),
            "{word}"
        );
        assert!(
            !MySqlDialect.keyword_can_be_bare_column_label(word),
            "{word}"
        );
    }
    for (dialect, src) in [
        (
            lexega_syntax::dialect::snowflake(),
            "SELECT MAX(id) truncate FROM users",
        ),
        (
            lexega_syntax::dialect::mysql(),
            "SELECT MAX(id) do FROM users",
        ),
    ] {
        let script = lexega_syntax::parse_sql_with_dialect(src, &*dialect).expect("parses");
        let [AstStmt::Select(select)] = script.stmts.as_slice() else {
            panic!("one query: {src}: {:?}", script.stmts);
        };
        assert_eq!(select.span.end as usize, src.len(), "{src}");
    }
}

#[test]
fn a_keyword_s_answers_are_the_vendor_s_published_class() {
    use lexega_syntax::{
        BigQueryDialect, DatabricksDialect, Dialect, MsSqlDialect, MySqlDialect, PostgresDialect,
        RedshiftDialect, SnowflakeDialect,
    };
    // Snowflake reserves neither MERGE nor TRUNCATE; JOIN and LEFT are no
    // table alias, but a column name and label.
    for word in ["MERGE", "TRUNCATE", "LIMIT", "VIEW", "INDEX"] {
        assert!(!SnowflakeDialect.is_reserved_keyword(word), "{word}");
        assert!(
            SnowflakeDialect.keyword_can_be_bare_column_label(word),
            "{word}"
        );
    }
    for word in ["JOIN", "LEFT"] {
        assert!(
            SnowflakeDialect.keyword_can_be_unquoted_identifier(word),
            "{word}"
        );
        assert!(
            SnowflakeDialect.keyword_can_be_bare_column_label(word),
            "{word}"
        );
        assert!(
            !SnowflakeDialect.keyword_can_be_unquoted_alias(word),
            "{word}"
        );
    }
    for word in ["START", "TRY_CAST", "SAMPLE", "CURRENT_DATE"] {
        assert!(SnowflakeDialect.is_reserved_keyword(word), "{word}");
    }
    // PostgreSQL 17: INSERT and DELETE are unreserved, LEFT a function name,
    // OVER a column name that needs `AS` as a label.
    assert!(!PostgresDialect.is_reserved_keyword("INSERT"));
    assert!(PostgresDialect.keyword_can_be_unquoted_alias("DELETE"));
    assert!(PostgresDialect.is_reserved_keyword("LEFT"));
    assert!(PostgresDialect.keyword_can_be_bare_column_label("LEFT"));
    assert!(PostgresDialect.keyword_can_be_unquoted_alias("OVER"));
    assert!(!PostgresDialect.keyword_can_be_bare_column_label("OVER"));
    // MySQL 8.0 does not reserve PRECEDING, FOLLOWING, UNTIL or OFFSET, and
    // reserves LEFT, KEY and RANK.
    for word in ["PRECEDING", "FOLLOWING", "UNTIL", "UNBOUNDED", "OFFSET"] {
        assert!(!MySqlDialect.is_reserved_keyword(word), "{word}");
    }
    for word in ["LEFT", "KEY", "RANK"] {
        assert!(MySqlDialect.is_reserved_keyword(word), "{word}");
    }
    // Redshift reserves USER, not LANGUAGE.
    assert!(RedshiftDialect.is_reserved_keyword("user"));
    assert!(!RedshiftDialect.is_reserved_keyword("language"));
    // Databricks: MASK is a word a table alias needs backticks for.
    assert!(DatabricksDialect.keyword_can_be_unquoted_identifier("MASK"));
    assert!(!DatabricksDialect.keyword_can_be_unquoted_alias("MASK"));
    assert!(BigQueryDialect.is_reserved_keyword("GRAPH_TABLE"));
    assert!(MsSqlDialect.is_reserved_keyword("TRY_CONVERT"));
    // A word no table holds is an identifier anywhere.
    for dialect in [
        &SnowflakeDialect as &dyn Dialect,
        &PostgresDialect,
        &MySqlDialect,
        &MsSqlDialect,
        &BigQueryDialect,
        &DatabricksDialect,
        &RedshiftDialect,
    ] {
        assert!(!dialect.is_keyword("zz_name"));
        assert!(dialect.keyword_can_be_unquoted_alias("zz_name"));
        assert!(dialect.keyword_can_be_bare_column_label("zz_name"));
    }
}

#[test]
fn a_keyword_the_database_does_not_reserve_is_a_select_item_s_bare_label() {
    use lexega_syntax::ast::AstStmt;
    for (dialect, word) in [
        (lexega_syntax::dialect::snowflake(), "merge"),
        (lexega_syntax::dialect::snowflake(), "view"),
        (lexega_syntax::dialect::mysql(), "preceding"),
        (lexega_syntax::dialect::mysql(), "following"),
        (lexega_syntax::dialect::mysql(), "until"),
        (lexega_syntax::dialect::mysql(), "unbounded"),
    ] {
        let src = format!("SELECT MAX(id) {word} FROM users");
        let script = lexega_syntax::parse_sql_with_dialect(&src, &*dialect).expect("parses");
        let [AstStmt::Select(select)] = script.stmts.as_slice() else {
            panic!("one query: {src}: {:?}", script.stmts);
        };
        assert_eq!(select.span.end as usize, src.len(), "{src}");
    }
}

#[test]
fn a_statement_starts_where_the_one_statement_start_rule_says() {
    let kinds = |dialect: &dyn lexega_syntax::Dialect, src: &str| -> Vec<String> {
        lexega_syntax::parse_sql_with_dialect(src, dialect)
            .expect("parses")
            .stmts
            .iter()
            .map(|stmt| {
                format!("{stmt:?}")
                    .chars()
                    .take_while(char::is_ascii_alphanumeric)
                    .collect()
            })
            .collect()
    };
    // An optional name or an option list ends where any statement an
    // option tail ends at starts: a MERGE after REINDEX's missing name.
    let pg = lexega_syntax::dialect::postgres();
    assert_eq!(
        kinds(
            &*pg,
            "REINDEX DATABASE\nMERGE INTO t USING s ON t.id = s.id WHEN MATCHED THEN DELETE"
        ),
        ["Reindex", "Merge"]
    );
    // A statement that does not parse is skipped to a DESCRIBE.
    let sf = lexega_syntax::dialect::snowflake();
    let skipped = kinds(&*sf, "SELECT FROM WHERE\nDESCRIBE TABLE t");
    assert_eq!(skipped.len(), 2, "{skipped:?}");
    assert_ne!(skipped[1], "OpaqueContent", "{skipped:?}");
}

#[test]
fn every_name_declared_together_is_a_variable_with_the_list_s_type_and_initialiser() {
    use lexega_syntax::ast::AstStmt;
    let text = |src: &str, span: Option<lexega_syntax::lexer::Span>| {
        span.map(|s| src[s.start as usize..s.end as usize].to_string())
    };
    for (dialect, src) in [
        (
            lexega_syntax::dialect::bigquery(),
            "DECLARE a, b, c INT64 DEFAULT 5",
        ),
        (
            lexega_syntax::dialect::databricks(),
            "DECLARE OR REPLACE VARIABLE a, b, c INT64 DEFAULT 5",
        ),
    ] {
        let script = lexega_syntax::parse_sql_with_dialect(src, &*dialect).expect("parses");
        let [AstStmt::Declare { variables, .. }] = script.stmts.as_slice() else {
            panic!("{src}: {:?}", script.stmts);
        };
        let names: Vec<_> = variables
            .iter()
            .map(|v| &src[v.name.span.start as usize..v.name.span.end as usize])
            .collect();
        assert_eq!(names, ["a", "b", "c"], "{src}");
        for (i, variable) in variables.iter().enumerate() {
            assert_eq!(text(src, variable.type_span).as_deref(), Some("INT64"));
            assert_eq!(
                text(src, variable.default_expr_span).as_deref(),
                Some("DEFAULT 5")
            );
            assert_eq!(variable.default_expr.is_some(), i == 0, "{src}");
            assert_eq!(variable.span.end as usize, src.len());
        }
    }
    // T-SQL's list of variables, each with its own type, is as before.
    let src = "DECLARE @x INT = 1, @y VARCHAR(5)";
    let script = lexega_syntax::parse_sql_with_dialect(src, &*lexega_syntax::dialect::mssql())
        .expect("parses");
    let [AstStmt::Declare { variables, .. }] = script.stmts.as_slice() else {
        panic!("{:?}", script.stmts);
    };
    let types: Vec<_> = variables.iter().map(|v| text(src, v.type_span)).collect();
    assert_eq!(
        types,
        [Some("INT".to_string()), Some("VARCHAR(5)".to_string())]
    );
}

#[test]
fn variable_after_declare_is_a_keyword_only_where_the_dialect_writes_it() {
    use lexega_syntax::ast::AstStmt;
    // The first variable's name and the type written after it.
    fn first_variable(stmt: &AstStmt, src: &str) -> Option<(String, Option<String>)> {
        let text =
            |s: lexega_syntax::lexer::Span| src[s.start as usize..s.end as usize].to_string();
        if let AstStmt::Declare { variables, .. } = stmt {
            variables
                .first()
                .map(|v| (text(v.name.span), v.type_span.map(text)))
        } else if let AstStmt::Block(block) = stmt {
            block.decls.iter().find_map(|d| first_variable(d, src))
        } else {
            None
        }
    }
    let cases = [
        (
            lexega_syntax::dialect::databricks(),
            "DECLARE VARIABLE api_key DEFAULT 'x'",
            ("api_key", None),
        ),
        (
            lexega_syntax::dialect::databricks(),
            "DECLARE VARIABLE api_key = 'x'",
            ("api_key", None),
        ),
        (
            lexega_syntax::dialect::databricks(),
            "DECLARE OR REPLACE VAR api_key STRING",
            ("api_key", Some("STRING")),
        ),
        (
            lexega_syntax::dialect::databricks(),
            "DECLARE VARIABLE x INT",
            ("x", Some("INT")),
        ),
        (
            lexega_syntax::dialect::databricks(),
            "DECLARE VARIABLE DEFAULT 1",
            ("VARIABLE", None),
        ),
        (
            lexega_syntax::dialect::databricks(),
            "DECLARE VARIABLE = 1",
            ("VARIABLE", None),
        ),
        (
            lexega_syntax::dialect::bigquery(),
            "DECLARE variable INT64 DEFAULT 1",
            ("variable", Some("INT64")),
        ),
        (
            lexega_syntax::dialect::bigquery(),
            "DECLARE variable STRING",
            ("variable", Some("STRING")),
        ),
        (
            lexega_syntax::dialect::snowflake(),
            "DECLARE variable NUMBER(10, 2) DEFAULT 1; BEGIN RETURN 1; END;",
            ("variable", Some("NUMBER(10, 2)")),
        ),
        (
            lexega_syntax::dialect::mysql(),
            "DECLARE variable INT UNSIGNED DEFAULT 1; BEGIN SELECT 1; END;",
            ("variable", Some("INT UNSIGNED")),
        ),
        (
            lexega_syntax::dialect::postgres(),
            "DECLARE variable CONSTANT integer := 1; BEGIN NULL; END;",
            ("variable", Some("CONSTANT integer")),
        ),
        (
            lexega_syntax::dialect::postgres(),
            "DECLARE variable double precision; BEGIN NULL; END;",
            ("variable", Some("double precision")),
        ),
    ];
    for (dialect, src, (name, data_type)) in cases {
        let script = lexega_syntax::parse_sql_with_dialect(src, &*dialect).expect("parses");
        let read = script
            .stmts
            .first()
            .and_then(|stmt| first_variable(stmt, src));
        assert_eq!(
            read,
            Some((name.to_string(), data_type.map(str::to_string))),
            "{}: {src}",
            dialect.name()
        );
    }
}

#[test]
fn a_long_list_declared_together_is_read_in_linear_time() {
    // The initialiser is parsed once, whatever the number of names.
    let measure = |n: usize| {
        let names: Vec<String> = (0..n).map(|i| format!("v{i}")).collect();
        let value: Vec<String> = (0..n).map(|i| i.to_string()).collect();
        let src = format!(
            "DECLARE {}, password INT64 DEFAULT GREATEST({})",
            names.join(", "),
            value.join(", ")
        );
        let started = std::time::Instant::now();
        let script =
            lexega_syntax::parse_sql_with_dialect(&src, &*lexega_syntax::dialect::bigquery())
                .expect("parses");
        let [lexega_syntax::ast::AstStmt::Declare { variables, .. }] = script.stmts.as_slice()
        else {
            panic!("one declaration");
        };
        assert_eq!(variables.len(), n + 1);
        assert_eq!(
            variables
                .iter()
                .filter(|v| v.default_expr.is_some())
                .count(),
            1
        );
        started.elapsed()
    };
    let small = measure(5_000);
    let large = measure(20_000);
    assert!(
        large < small * 8 + std::time::Duration::from_millis(500),
        "four times the input took {large:?} against {small:?}"
    );
}

#[test]
fn the_value_secret_named_names_share_is_masked_once() {
    // Each literal of the shared initialiser is recorded once, however many
    // of the names name a secret.
    let measure = |n: usize| {
        let names: Vec<String> = (0..n).map(|i| format!("password{i}")).collect();
        let value: Vec<String> = (0..n).map(|i| format!("'s{i}'")).collect();
        let src = format!(
            "DECLARE {} STRING DEFAULT GREATEST({})",
            names.join(", "),
            value.join(", ")
        );
        let started = std::time::Instant::now();
        let script =
            lexega_syntax::parse_sql_with_dialect(&src, &*lexega_syntax::dialect::bigquery())
                .expect("parses");
        assert_eq!(script.redaction_spans.len(), n);
        started.elapsed()
    };
    let small = measure(5_000);
    let large = measure(20_000);
    assert!(
        large < small * 8 + std::time::Duration::from_millis(500),
        "four times the input took {large:?} against {small:?}"
    );
}

#[test]
fn a_query_many_secret_named_variables_take_is_masked_once() {
    // Each literal of the one query the targets take is recorded once,
    // however many of them name a secret.
    let measure = |n: usize| {
        let names: Vec<String> = (0..n).map(|i| format!("password{i}")).collect();
        let value: Vec<String> = (0..n).map(|i| format!("'s{i}'")).collect();
        let src = format!("SET ({}) = (SELECT {})", names.join(", "), value.join(", "));
        let started = std::time::Instant::now();
        let script =
            lexega_syntax::parse_sql_with_dialect(&src, &*lexega_syntax::dialect::snowflake())
                .expect("parses");
        assert_eq!(script.redaction_spans.len(), n);
        started.elapsed()
    };
    let small = measure(5_000);
    let large = measure(20_000);
    assert!(
        large < small * 8 + std::time::Duration::from_millis(500),
        "four times the input took {large:?} against {small:?}"
    );
}

#[test]
fn a_row_limiting_fetch_stays_the_query_clause_in_every_dialect() {
    use lexega_syntax::ast::AstStmt;
    let cases = [
        (
            lexega_syntax::dialect::postgres(),
            "SELECT id FROM users ORDER BY id FETCH FIRST 5 ROWS ONLY",
            "FETCH FIRST 5 ROWS ONLY",
        ),
        (
            lexega_syntax::dialect::postgres(),
            "SELECT id FROM users ORDER BY id OFFSET 2 ROWS FETCH NEXT 5 ROWS ONLY",
            "FETCH NEXT 5 ROWS ONLY",
        ),
        (
            lexega_syntax::dialect::postgres(),
            "SELECT id FROM users ORDER BY id FETCH FIRST ROW ONLY",
            "FETCH FIRST ROW ONLY",
        ),
        (
            lexega_syntax::dialect::postgres(),
            "SELECT id FROM users ORDER BY id FETCH FIRST (2 + 3) ROWS ONLY",
            "FETCH FIRST (2 + 3) ROWS ONLY",
        ),
        (
            lexega_syntax::dialect::postgres(),
            "SELECT id FROM users ORDER BY id FETCH NEXT $1 ROWS ONLY",
            "FETCH NEXT $1 ROWS ONLY",
        ),
        (
            lexega_syntax::dialect::snowflake(),
            "SELECT id FROM users FETCH 5",
            "FETCH 5",
        ),
        (
            lexega_syntax::dialect::snowflake(),
            "SELECT id FROM users u FETCH FIRST 5",
            "FETCH FIRST 5",
        ),
        (
            lexega_syntax::dialect::snowflake(),
            "SELECT id FROM users FETCH NEXT 5 ROWS",
            "FETCH NEXT 5 ROWS",
        ),
        (
            lexega_syntax::dialect::snowflake(),
            "SELECT id FROM users ORDER BY id OFFSET 2 FETCH 5",
            "FETCH 5",
        ),
        (
            lexega_syntax::dialect::snowflake(),
            "SELECT id FROM users ORDER BY id FETCH 5 ROWS ONLY",
            "FETCH 5 ROWS ONLY",
        ),
        (
            lexega_syntax::dialect::mssql(),
            "SELECT id FROM dbo.users ORDER BY id OFFSET 10 ROWS FETCH NEXT 5 ROWS ONLY",
            "FETCH NEXT 5 ROWS ONLY",
        ),
        (
            lexega_syntax::dialect::mssql(),
            "SELECT id FROM dbo.users ORDER BY id OFFSET @o ROWS FETCH NEXT @n ROWS ONLY",
            "FETCH NEXT @n ROWS ONLY",
        ),
        (
            lexega_syntax::dialect::mssql(),
            "SELECT id FROM dbo.users ORDER BY id OFFSET @s - 1 ROWS \
             FETCH NEXT @e - @s + 1 ROWS ONLY",
            "FETCH NEXT @e - @s + 1 ROWS ONLY",
        ),
        (
            lexega_syntax::dialect::mssql(),
            "SELECT id FROM dbo.users ORDER BY id OFFSET 0 ROWS FETCH FIRST (SELECT 5) ROW ONLY",
            "FETCH FIRST (SELECT 5) ROW ONLY",
        ),
    ];
    for (dialect, src, clause) in cases {
        let script = lexega_syntax::parse_sql_with_dialect(src, &*dialect).expect("parses");
        assert_eq!(script.stmts.len(), 1, "{src}: {:?}", script.stmts);
        let AstStmt::Select(select) = &script.stmts[0] else {
            panic!("{src}: {:?}", script.stmts);
        };
        let span = select.fetch_clause_span.expect("a FETCH clause");
        assert_eq!(
            &src[span.start as usize..span.end as usize],
            clause,
            "{src}"
        );
        statement_texts(src, &dialect);
    }
}

#[test]
fn a_row_limiting_fetch_count_is_any_expression() {
    use lexega_syntax::ast::AstStmt;
    let cases = [
        (
            lexega_syntax::dialect::postgres(),
            "SELECT id FROM users ORDER BY id FETCH FIRST abs(-5) ROWS ONLY",
            "FETCH FIRST abs(-5) ROWS ONLY",
        ),
        (
            lexega_syntax::dialect::postgres(),
            "SELECT id FROM users ORDER BY id FETCH FIRST current_setting('x')::int ROWS ONLY",
            "FETCH FIRST current_setting('x')::int ROWS ONLY",
        ),
        (
            lexega_syntax::dialect::postgres(),
            "SELECT id FROM users ORDER BY id FETCH FIRST n ROWS ONLY",
            "FETCH FIRST n ROWS ONLY",
        ),
        (
            lexega_syntax::dialect::postgres(),
            "SELECT id FROM users ORDER BY id OFFSET 1 ROWS FETCH FIRST CAST($1 AS int) ROWS ONLY",
            "FETCH FIRST CAST($1 AS int) ROWS ONLY",
        ),
        (
            lexega_syntax::dialect::snowflake(),
            "SELECT id FROM users ORDER BY id FETCH FIRST $n ROWS ONLY",
            "FETCH FIRST $n ROWS ONLY",
        ),
        (
            lexega_syntax::dialect::snowflake(),
            "SELECT id FROM users ORDER BY id FETCH $n",
            "FETCH $n",
        ),
        (
            lexega_syntax::dialect::snowflake(),
            "SELECT id FROM users ORDER BY id FETCH ABS(-5)",
            "FETCH ABS(-5)",
        ),
        (
            lexega_syntax::dialect::snowflake(),
            "SELECT id FROM users ORDER BY id FETCH NEXT CAST('5' AS INT) ROWS ONLY",
            "FETCH NEXT CAST('5' AS INT) ROWS ONLY",
        ),
        (
            lexega_syntax::dialect::mssql(),
            "SELECT id FROM dbo.users ORDER BY id OFFSET 0 ROWS FETCH NEXT ABS(@n) ROWS ONLY",
            "FETCH NEXT ABS(@n) ROWS ONLY",
        ),
    ];
    for (dialect, src, clause) in cases {
        let script = lexega_syntax::parse_sql_with_dialect(src, &*dialect).expect("parses");
        assert_eq!(script.stmts.len(), 1, "{src}: {:?}", script.stmts);
        let AstStmt::Select(select) = &script.stmts[0] else {
            panic!("{src}: {:?}", script.stmts);
        };
        let span = select.fetch_clause_span.expect("a FETCH clause");
        assert_eq!(
            &src[span.start as usize..span.end as usize],
            clause,
            "{src}"
        );
    }
}

#[test]
fn a_fetch_nested_in_a_fetch_count_is_read_once() {
    use lexega_syntax::ast::AstStmt;
    // (dialect, one level wrapping `{}`, the outer query's clause around `{}`)
    let shapes = [
        (
            lexega_syntax::dialect::postgres(),
            "(SELECT id FROM users ORDER BY id FETCH FIRST {} ROWS ONLY)",
            "SELECT id FROM users ORDER BY id FETCH FIRST {} ROWS ONLY",
        ),
        (
            lexega_syntax::dialect::mssql(),
            "(SELECT id FROM dbo.users ORDER BY id OFFSET 0 ROWS FETCH NEXT {} ROWS ONLY)",
            "SELECT id FROM dbo.users ORDER BY id OFFSET 0 ROWS FETCH NEXT {} ROWS ONLY",
        ),
        (
            lexega_syntax::dialect::snowflake(),
            "(SELECT id FROM users ORDER BY id FETCH {})",
            "SELECT id FROM users ORDER BY id FETCH {}",
        ),
    ];
    for (dialect, level, outer) in shapes {
        let measure = |depth: usize| {
            let mut count = "1".to_string();
            for _ in 0..depth {
                count = level.replace("{}", &count);
            }
            let src = outer.replace("{}", &count);
            let started = std::time::Instant::now();
            let script = lexega_syntax::parse_sql_with_dialect(&src, &*dialect).expect("parses");
            let elapsed = started.elapsed();
            let [AstStmt::Select(select)] = script.stmts.as_slice() else {
                panic!("{}: {:?}", dialect.name(), script.stmts);
            };
            let span = select.fetch_clause_span.expect("a FETCH clause");
            assert_eq!(span.end as usize, src.len(), "{}", dialect.name());
            elapsed
        };
        let small = measure(5);
        let large = measure(20);
        assert!(
            large < small * 8 + std::time::Duration::from_millis(500),
            "{}: four times the nesting took {large:?} against {small:?}",
            dialect.name()
        );
    }
}

#[test]
fn a_snowflake_block_query_with_a_bound_fetch_count_is_read_whole() {
    use lexega_syntax::ast::AstStmt;
    let snowflake = lexega_syntax::dialect::snowflake();
    let name = |src: &str, stmt: &AstStmt| match stmt {
        AstStmt::Select(select) => match select.fetch_clause_span {
            Some(s) => format!("SELECT {}", &src[s.start as usize..s.end as usize]),
            None => "SELECT".to_string(),
        },
        AstStmt::Delete(_) => "DELETE".to_string(),
        AstStmt::Declare { .. } => "DECLARE".to_string(),
        AstStmt::Let { .. } => "LET".to_string(),
        AstStmt::OpaqueContent { .. } => "OPAQUE".to_string(),
        other => format!("{other:?}"),
    };
    // (source, the block's declarations, its body)
    let cases: [(&str, &[&str], &[&str]); 4] = [
        (
            "BEGIN LET n INT := 5; SELECT id FROM users ORDER BY id FETCH :n; DELETE FROM orders; END;",
            &[],
            &["LET", "SELECT FETCH :n", "DELETE"],
        ),
        (
            "BEGIN LET res RESULTSET := (SELECT id FROM users FETCH FIRST :n ROWS ONLY); \
             DELETE FROM orders; END;",
            &[],
            &["LET", "DELETE"],
        ),
        (
            "DECLARE res RESULTSET DEFAULT (SELECT id FROM users FETCH FIRST :n ROWS ONLY); \
             BEGIN DELETE FROM orders; END;",
            &["DECLARE"],
            &["DELETE"],
        ),
        (
            "DECLARE res RESULTSET DEFAULT (SELECT id FROM users FETCH :n); \
             BEGIN DELETE FROM orders; END;",
            &["DECLARE"],
            &["DELETE"],
        ),
    ];
    for (src, decls, body) in cases {
        let script = lexega_syntax::parse_sql_with_dialect(src, &*snowflake).expect("parses");
        let [AstStmt::Block(block)] = script.stmts.as_slice() else {
            panic!("{src}: {:?}", script.stmts);
        };
        let names = |stmts: &[AstStmt]| stmts.iter().map(|s| name(src, s)).collect::<Vec<_>>();
        assert_eq!(names(&block.decls), decls, "{src}");
        assert_eq!(names(&block.body), body, "{src}");
    }
}

#[test]
fn a_savepoint_is_a_statement_of_its_own() {
    use lexega_syntax::ast::{AstSavepointAction as Action, AstStmt};
    use lexega_syntax::dialect::{mssql, mysql, postgres};
    // (statement, dialect, action, keywords, name)
    let cases = [
        ("SAVE TRAN sp1", mssql(), Action::Set, "SAVE TRAN", "sp1"),
        (
            "SAVE TRANSACTION @sp",
            mssql(),
            Action::Set,
            "SAVE TRANSACTION",
            "@sp",
        ),
        ("SAVEPOINT sp1", postgres(), Action::Set, "SAVEPOINT", "sp1"),
        (
            "RELEASE SAVEPOINT sp1",
            postgres(),
            Action::Release,
            "RELEASE SAVEPOINT",
            "sp1",
        ),
        ("RELEASE sp1", postgres(), Action::Release, "RELEASE", "sp1"),
        ("SAVEPOINT sp1", mysql(), Action::Set, "SAVEPOINT", "sp1"),
        (
            "RELEASE SAVEPOINT sp1",
            mysql(),
            Action::Release,
            "RELEASE SAVEPOINT",
            "sp1",
        ),
    ];
    let text = |src: &str, span: lexega_syntax::lexer::Span| {
        src[span.start as usize..span.end as usize].to_string()
    };
    for (statement, dialect, action, keywords, name) in cases {
        let src = format!("{statement};\nDELETE FROM t;");
        let script = lexega_syntax::parse_sql_with_dialect(&src, &*dialect).expect("parses");
        assert_eq!(script.stmts.len(), 2, "{src}");
        let AstStmt::Savepoint(s) = &script.stmts[0] else {
            panic!("{src}: not a savepoint");
        };
        assert_eq!(s.action, action, "{src}");
        assert_eq!(text(&src, s.keyword_span), keywords, "{src}");
        assert_eq!(text(&src, s.name.span), name, "{src}");
        assert_eq!(text(&src, s.span), statement, "{src}");
        statement_texts(&src, &dialect);
    }
    // T-SQL, without `;`, at the top level and in a block.
    let texts = statement_texts(
        "BEGIN TRAN\nSAVE TRAN sp1\nDELETE FROM t\nROLLBACK TRAN sp1",
        &mssql(),
    );
    assert_eq!(
        texts,
        [
            "BEGIN TRAN",
            "SAVE TRAN sp1",
            "DELETE FROM t",
            "ROLLBACK TRAN sp1"
        ]
    );
    let script = lexega_syntax::parse_sql_with_dialect(
        "BEGIN TRY\nSAVE TRANSACTION sp1\nDELETE FROM t\nEND TRY\nBEGIN CATCH\nROLLBACK TRAN sp1\nEND CATCH",
        &*mssql(),
    )
    .expect("parses");
    assert_eq!(script.stmts.len(), 1);
    // ROLLBACK TO [SAVEPOINT] name is a ROLLBACK, read whole.
    for (src, dialect) in [
        ("ROLLBACK TO SAVEPOINT sp1", postgres()),
        ("ROLLBACK WORK TO sp1", mysql()),
    ] {
        let script = lexega_syntax::parse_sql_with_dialect(src, &*dialect).expect("parses");
        assert_eq!(script.stmts.len(), 1, "{src}");
        assert!(
            matches!(&script.stmts[0], AstStmt::Rollback { span, .. } if text(src, *span) == src),
            "{src}"
        );
    }
}

#[test]
fn a_tsql_inline_function_ends_where_its_query_does() {
    assert_tsql_statements_end_before_the_next(&[
        "CREATE FUNCTION dbo.zz_f (@x INT) RETURNS TABLE AS RETURN SELECT a FROM dbo.zz_src",
        "CREATE FUNCTION dbo.zz_f (@x INT)\nRETURNS TABLE\nAS\nRETURN (SELECT a FROM dbo.zz_src WHERE a = @x)",
        "CREATE FUNCTION dbo.zz_f () RETURNS TABLE WITH SCHEMABINDING AS RETURN (SELECT a FROM dbo.zz_src)",
        "CREATE OR ALTER FUNCTION dbo.zz_f () RETURNS TABLE AS RETURN \
         (WITH x AS (SELECT a FROM dbo.zz_src) SELECT a FROM x)",
    ]);
}

#[test]
fn a_tsql_audit_signature_or_availability_group_statement_ends_with_its_grammar() {
    assert_tsql_statements_end_before_the_next(&[
        "CREATE SERVER AUDIT zz_a TO FILE (FILEPATH = 'C:\\a\\', MAXSIZE = 10 MB) \
         WITH (QUEUE_DELAY = 1000, ON_FAILURE = CONTINUE) \
         WHERE object_name = 'x' AND NOT server_principal_name LIKE 'sa%'",
        "CREATE SERVER AUDIT zz_a TO URL WITH (RETENTION_DAYS = 10) \
         WHERE (database_name = 'x' OR database_name <> 'y')",
        "CREATE SERVER AUDIT zz_a TO APPLICATION_LOG",
        "ALTER SERVER AUDIT zz_a WITH (STATE = ON)",
        "ALTER SERVER AUDIT [zz a] TO SECURITY_LOG WITH (ON_FAILURE = SHUTDOWN)",
        "ALTER SERVER AUDIT zz_a MODIFY NAME = zz_b",
        "ALTER SERVER AUDIT zz_a REMOVE WHERE",
        "DROP SERVER AUDIT zz_a",
        "CREATE SERVER AUDIT SPECIFICATION zz_s FOR SERVER AUDIT zz_a \
         ADD (FAILED_LOGIN_GROUP), ADD (SUCCESSFUL_LOGIN_GROUP) WITH (STATE = ON)",
        "ALTER SERVER AUDIT SPECIFICATION zz_s FOR SERVER AUDIT zz_a \
         DROP (FAILED_LOGIN_GROUP) WITH (STATE = OFF)",
        "DROP SERVER AUDIT SPECIFICATION zz_s",
        "CREATE DATABASE AUDIT SPECIFICATION zz_d FOR SERVER AUDIT zz_a \
         ADD (SELECT, INSERT ON OBJECT::dbo.zz_t BY public), \
         ADD (DATABASE_ROLE_MEMBER_CHANGE_GROUP) WITH (STATE = ON)",
        "ALTER DATABASE AUDIT SPECIFICATION zz_d ADD (DELETE ON SCHEMA::dbo BY dbo) WITH (STATE = ON)",
        "DROP DATABASE AUDIT SPECIFICATION zz_d",
        "ADD SIGNATURE TO dbo.zz_p BY CERTIFICATE zz_c WITH PASSWORD = 'x'",
        "ADD COUNTER SIGNATURE TO dbo.zz_p BY CERTIFICATE zz_c",
        "ADD SIGNATURE TO OBJECT::dbo.zz_p BY ASYMMETRIC KEY zz_k WITH SIGNATURE = 0x0102",
        "ADD SIGNATURE TO [dbo].[zz_p] BY CERTIFICATE zz_c, ASYMMETRIC KEY zz_k WITH PASSWORD = 'x'",
        "DROP AVAILABILITY GROUP zz_ag",
        "DROP AVAILABILITY GROUP [zz ag]",
    ]);
}

#[test]
fn a_tsql_revert_with_cookie_or_get_conversation_group_ends_with_its_grammar() {
    assert_tsql_statements_end_before_the_next(&[
        "REVERT WITH COOKIE = @cookie",
        "GET CONVERSATION GROUP @g FROM zz_q",
    ]);
}

#[test]
fn a_tsql_execute_as_with_no_revert_or_a_cookie_ends_with_its_grammar() {
    let statements = [
        "EXECUTE AS USER = 'zz_u' WITH NO REVERT",
        "EXECUTE AS LOGIN = 'zz_l' WITH COOKIE INTO @c",
        "EXEC AS LOGIN = N'zz_l' with cookie into @zz_cookie",
        "EXECUTE AS USER = 'zz_u'",
    ];
    assert_tsql_statements_end_before_the_next(&statements);
    let mssql = lexega_syntax::dialect::mssql();
    for statement in statements {
        let src = format!("{statement}\nDELETE FROM dbo.zz_t");
        let texts = statement_texts(&src, &mssql);
        let texts: Vec<&str> = texts.iter().map(|t| t.trim_end()).collect();
        assert_eq!(texts, vec![statement, "DELETE FROM dbo.zz_t"], "{src}");
    }
}

#[test]
fn a_tsql_transaction_statement_is_read_whole() {
    assert_tsql_statements_end_before_the_next(&[
        "BEGIN TRAN",
        "BEGIN TRAN zz_tx",
        "BEGIN TRANSACTION zz_tx WITH MARK 'nightly load'",
        "BEGIN TRANSACTION @tx",
        "BEGIN DISTRIBUTED TRAN",
        "BEGIN DISTRIBUTED TRANSACTION zz_tx",
        "COMMIT TRAN",
        "COMMIT TRANSACTION zz_tx",
        "COMMIT TRAN WITH (DELAYED_DURABILITY = ON)",
        "ROLLBACK TRAN",
        "ROLLBACK TRANSACTION zz_sp",
        "ROLLBACK TRAN @tx",
    ]);
}

#[test]
fn a_tsql_transaction_is_named_only_after_tran() {
    let mssql = lexega_syntax::dialect::mssql();
    let delete = "DELETE FROM dbo.zz_t";
    for (src, expected) in [
        (
            format!("COMMIT\ndone:\n{delete}"),
            vec!["COMMIT", "done:", delete],
        ),
        (
            format!("ROLLBACK\ndone:\n{delete}"),
            vec!["ROLLBACK", "done:", delete],
        ),
        (
            format!("COMMIT WORK\ndone:\n{delete}"),
            vec!["COMMIT WORK", "done:", delete],
        ),
        (
            format!("BEGIN TRANSACTION\ndone:\n{delete}"),
            vec!["BEGIN TRANSACTION", "done:", delete],
        ),
        (
            format!("ROLLBACK\nREVERT\n{delete}"),
            vec!["ROLLBACK", "REVERT", delete],
        ),
        (
            format!("COMMIT TRAN zz_tx\n{delete}"),
            vec!["COMMIT TRAN zz_tx", delete],
        ),
        (
            format!("COMMIT WITH (DELAYED_DURABILITY = ON)\n{delete}"),
            vec!["COMMIT WITH (DELAYED_DURABILITY = ON)", delete],
        ),
    ] {
        let texts = statement_texts(&src, &mssql);
        let texts: Vec<&str> = texts.iter().map(|t| t.trim_end()).collect();
        assert_eq!(texts, expected, "{src}");
    }
}

#[test]
fn a_transaction_statement_keeps_its_reading_elsewhere() {
    use lexega_syntax::dialect::{postgres, snowflake};
    for (src, dialect, count) in [
        ("BEGIN TRANSACTION NAME t;\nSELECT 1;", snowflake(), 2),
        ("BEGIN;\nSELECT 1;\nCOMMIT;", snowflake(), 3),
        ("BEGIN TRANSACTION;\nSELECT 1;\nCOMMIT WORK;", postgres(), 3),
    ] {
        let texts = statement_texts(src, &dialect);
        assert_eq!(texts.len(), count, "{src}: {texts:?}");
    }
}

#[test]
fn a_tsql_statement_in_a_block_ends_before_the_next_statement() {
    use lexega_syntax::ast::AstStmt;
    let mssql = lexega_syntax::dialect::mssql();
    for statement in [
        "DEALLOCATE zz_cur",
        "DISABLE TRIGGER zz_tr ON dbo.zz_t",
        "CHECKPOINT 10",
        "RECONFIGURE WITH OVERRIDE",
        "REVERT",
        "KILL 52 WITH STATUSONLY",
        "SHUTDOWN WITH NOWAIT",
        "SEND ON CONVERSATION @h MESSAGE TYPE [//zz/m] (@body)",
        "RESTORE VERIFYONLY FROM DISK = 'a.bak' WITH CHECKSUM",
        "ADD SIGNATURE TO dbo.zz_p BY CERTIFICATE zz_c",
        "SAVE TRANSACTION zz_sp",
        "BEGIN TRAN",
        "BEGIN DIALOG CONVERSATION @h FROM SERVICE s TO SERVICE 't'",
        "READTEXT dbo.zz_t.c @ptr 0 10",
    ] {
        let src = format!("IF 1 = 1\nBEGIN\n    {statement}\n    DELETE FROM dbo.zz_t\nEND");
        let texts = statement_texts(&src, &mssql);
        assert_eq!(texts.len(), 1, "{src}: {texts:?}");
        let script = lexega_syntax::parse_sql_with_dialect(&src, &*mssql).expect("parses");
        let AstStmt::MssqlIf(branch) = &script.stmts[0] else {
            panic!("{src}: {:?}", script.stmts[0]);
        };
        let [AstStmt::Block(block)] = branch.then_body.as_slice() else {
            panic!("{src}: {:?}", branch.then_body);
        };
        assert!(
            matches!(block.body.last(), Some(AstStmt::Delete(_))),
            "{src}: {:?}",
            block.body
        );
    }
}

#[test]
fn a_tsql_altered_view_ends_where_its_query_does() {
    assert_tsql_statements_end_before_the_next(&[
        "ALTER VIEW dbo.zz_v AS SELECT a FROM dbo.zz_src",
        "ALTER VIEW dbo.zz_v (a) WITH SCHEMABINDING, VIEW_METADATA AS SELECT a FROM dbo.zz_src",
        "ALTER VIEW dbo.zz_v AS SELECT a FROM dbo.zz_src WHERE a > 0 WITH CHECK OPTION",
        "ALTER VIEW dbo.zz_v AS SELECT a FROM dbo.zz_src UNION ALL SELECT b FROM dbo.zz_src",
        "ALTER VIEW dbo.zz_v AS WITH x AS (SELECT a FROM dbo.zz_src) SELECT a FROM x",
        "ALTER VIEW dbo.zz_v AS (SELECT a FROM dbo.zz_src)",
    ]);
}

#[test]
fn a_view_altered_to_a_new_query_ends_where_the_query_does() {
    use lexega_syntax::dialect::{mysql, snowflake};
    for (src, dialect, first) in [
        (
            "ALTER VIEW zz_v (a) AS SELECT a FROM zz_src WITH CASCADED CHECK OPTION;\nDELETE FROM zz_t;",
            mysql(),
            "ALTER VIEW zz_v (a) AS SELECT a FROM zz_src WITH CASCADED CHECK OPTION",
        ),
        (
            "ALTER VIEW zz_v SET SECURE;\nDELETE FROM zz_t;",
            snowflake(),
            "ALTER VIEW zz_v SET SECURE",
        ),
    ] {
        let texts = statement_texts(src, &dialect);
        assert_eq!(texts, [first, "DELETE FROM zz_t"], "{src}");
    }
}

#[test]
fn a_tsql_view_with_attributes_is_one_statement() {
    let mssql = lexega_syntax::dialect::mssql();
    for statement in [
        "CREATE VIEW dbo.zz_v WITH SCHEMABINDING AS SELECT a FROM dbo.zz_src",
        "CREATE VIEW dbo.zz_v WITH SCHEMABINDING, VIEW_METADATA AS SELECT a FROM dbo.zz_src",
        "CREATE OR ALTER VIEW dbo.zz_v (a) WITH ENCRYPTION AS SELECT a FROM dbo.zz_src",
    ] {
        let src = format!("{statement}\nGO\nSELECT id FROM dbo.zz_src");
        let texts = statement_texts(&src, &mssql);
        assert_eq!(texts.len(), 3, "{src}: {texts:?}");
        assert_eq!(texts[1..], ["GO", "SELECT"], "{src}: {texts:?}");
    }
}

#[test]
fn an_ssms_foreign_key_script_is_read_statement_by_statement() {
    let mssql = lexega_syntax::dialect::mssql();
    let fk = "ALTER TABLE [dbo].[zz_t]  WITH CHECK ADD  CONSTRAINT [fk_c] FOREIGN KEY([a])\n\
              REFERENCES [dbo].[zz_p] ([id])";
    let fk_cascade =
        "ALTER TABLE [dbo].[zz_t]  WITH CHECK ADD  CONSTRAINT [fk_c] FOREIGN KEY([a])\n\
                      REFERENCES [dbo].[zz_p] ([id])\nON DELETE CASCADE";
    let check = "ALTER TABLE [dbo].[zz_t] CHECK CONSTRAINT [fk_c]";
    let nocheck = "ALTER TABLE [dbo].[zz_t] NOCHECK CONSTRAINT [fk_c]";
    let drop = "DROP TABLE dbo.zz_gone";
    for (src, expected) in [
        (
            format!("{fk}\nGO\n{check}\nGO\nSELECT id FROM dbo.zz_src"),
            [fk, "GO", check, "GO", "SELECT"],
        ),
        (
            format!("{fk_cascade}\nGO\n{check}\nGO\nSELECT id FROM dbo.zz_src"),
            [fk_cascade, "GO", check, "GO", "SELECT"],
        ),
        (
            format!("{nocheck}\nGO\n{drop}\nGO\nSELECT id FROM dbo.zz_src"),
            [nocheck, "GO", drop, "GO", "SELECT"],
        ),
    ] {
        let texts = statement_texts(&src, &mssql);
        let texts: Vec<&str> = texts.iter().map(|t| t.trim_end()).collect();
        assert_eq!(texts, expected, "{src}");
    }
}

#[test]
fn an_altered_table_is_named_without_its_action() {
    use lexega_syntax::ast::AstStmt;
    use lexega_syntax::dialect::{databricks, mssql, mysql, postgres, snowflake};
    for (src, dialect, name) in [
        (
            "ALTER TABLE [dbo].[zz_t]  WITH CHECK ADD CONSTRAINT fk FOREIGN KEY (a) REFERENCES p (id)",
            mssql(),
            "[dbo].[zz_t]",
        ),
        ("ALTER TABLE dbo.zz_t SWITCH TO dbo.zz_p", mssql(), "dbo.zz_t"),
        // PostgreSQL's `ONLY` and `*` say which of its children the action
        // reaches: the table's name is the name alone.
        ("ALTER TABLE ONLY zz_t ADD COLUMN c INT", postgres(), "zz_t"),
        ("ALTER TABLE zz_t * ADD COLUMN c INT", postgres(), "zz_t"),
        (
            "ALTER TABLE zz_t ADD CONSTRAINT fk FOREIGN KEY (a) REFERENCES p (id) \
             ON DELETE SET NULL (a) MATCH FULL DEFERRABLE",
            postgres(),
            "zz_t",
        ),
        ("ALTER TABLE zz_t ENGINE = InnoDB", mysql(), "zz_t"),
        (
            "ALTER TABLE zz_t PARTITION (p = 1) SET LOCATION 's3://b/p'",
            databricks(),
            "zz_t",
        ),
        ("ALTER TABLE db.s.zz_t RECLUSTER", snowflake(), "db.s.zz_t"),
    ] {
        let script = lexega_syntax::parse_sql_with_dialect(src, &*dialect).expect("parses");
        assert_eq!(script.stmts.len(), 1, "{src}: {:?}", script.stmts);
        let Some(AstStmt::AlterTable(alter)) = script.stmts.first() else {
            panic!("{src}: {:?}", script.stmts);
        };
        let span = alter.name.span;
        assert_eq!(&src[span.start as usize..span.end as usize], name, "{src}");
        let config = lexega_syntax::FormatterConfig { dialect: dialect.clone(), ..Default::default() };
        let formatted = lexega_syntax::format_sql_with_config(src, &config).expect("formats");
        lexega_syntax::verify_formatting_safe_with_dialect(src, &formatted, &*dialect)
            .unwrap_or_else(|e| panic!("{src} -> {formatted}: {e}"));
    }
}

/// T-SQL procedures whose body is not one `BEGIN … END` block, each with
/// the number of statements its body holds.
const TSQL_PROCEDURES_WITHOUT_A_BLOCK: [(&str, usize); 10] = [
    ("CREATE PROCEDURE dbo.zz_p AS\nSELECT id FROM dbo.zz_src", 1),
    (
        "CREATE PROCEDURE dbo.zz_p AS\nSET NOCOUNT ON\nSELECT id FROM dbo.zz_src\nUPDATE dbo.zz_src SET c = 1",
        3,
    ),
    (
        "CREATE PROCEDURE dbo.zz_p WITH EXECUTE AS OWNER AS\nSELECT id FROM dbo.zz_src;\nUPDATE dbo.zz_src SET c = 1",
        2,
    ),
    (
        "CREATE OR ALTER PROCEDURE dbo.zz_p (@x INT) AS\nIF @x > 0\n  UPDATE dbo.zz_src SET c = 1\nELSE\n  DELETE FROM dbo.zz_src",
        1,
    ),
    (
        "CREATE PROCEDURE dbo.zz_p AS\nBEGIN TRY\n  UPDATE dbo.zz_src SET c = 1\nEND TRY\nBEGIN CATCH\n  SELECT 1\nEND CATCH",
        1,
    ),
    (
        "CREATE PROCEDURE dbo.zz_p AS\nDECLARE @x INT = 1\nDECLARE cur CURSOR FOR SELECT id FROM dbo.zz_src\nOPEN cur\nCLOSE cur\nDEALLOCATE cur",
        5,
    ),
    (
        "CREATE PROCEDURE dbo.zz_p AS\nSET NOCOUNT ON\nBEGIN\n  SELECT id FROM dbo.zz_src\nEND\nWHILE 1 = 1\n  UPDATE dbo.zz_src SET c = 1",
        3,
    ),
    ("CREATE PROCEDURE dbo.zz_p AS\nCHECKPOINT\nUPDATE dbo.zz_src SET c = 1", 2),
    (
        "CREATE PROCEDURE dbo.zz_p AS\nBEGIN TRAN\nUPDATE dbo.zz_src SET c = 1\nCOMMIT",
        3,
    ),
    (
        "CREATE PROCEDURE dbo.zz_p @x INT, @y INT = 2 WITH RECOMPILE, EXECUTE AS CALLER AS\n\
         -- note\nUPDATE dbo.zz_src SET c = @x WHERE id = @y",
        1,
    ),
];

#[test]
fn a_tsql_procedure_body_without_a_block_ends_at_the_batch_separator() {
    let mssql = lexega_syntax::dialect::mssql();
    for (procedure, _) in TSQL_PROCEDURES_WITHOUT_A_BLOCK {
        let src = format!("{procedure}\nGO\nDELETE FROM dbo.zz_t\nGO");
        let texts = statement_texts(&src, &mssql);
        let texts: Vec<&str> = texts.iter().map(|t| t.trim_end()).collect();
        assert_eq!(
            texts,
            [procedure, "GO", "DELETE FROM dbo.zz_t", "GO"],
            "{src}"
        );
        // Without `GO` the body runs to the end of input, `;` or not.
        for src in [
            format!("{procedure}\nDELETE FROM dbo.zz_t"),
            format!("{procedure};\nDELETE FROM dbo.zz_t;"),
        ] {
            let texts = statement_texts(&src, &mssql);
            assert_eq!(texts.len(), 1, "{src}: {texts:?}");
        }
    }
}

#[test]
fn a_tsql_procedure_body_without_a_block_holds_its_statements() {
    use lexega_syntax::ast::AstStmt;
    let mssql = lexega_syntax::dialect::mssql();
    let body = |src: &str| {
        let script = lexega_syntax::parse_sql_with_dialect(src, &*mssql).expect("parses");
        let Some(AstStmt::CreateProcedure(procedure)) = script.stmts.first() else {
            panic!("{src}: {:?}", script.stmts);
        };
        (
            procedure.body_stmt.is_some(),
            procedure.body_statements.len(),
            src[procedure.body_span.start as usize..procedure.body_span.end as usize].to_string(),
        )
    };
    for (procedure, count) in TSQL_PROCEDURES_WITHOUT_A_BLOCK {
        let (has_block, statements, text) = body(&format!("{procedure}\nGO"));
        assert!(!has_block, "{procedure}");
        assert_eq!(statements, count, "{procedure}");
        assert!(procedure.ends_with(&text), "{procedure}: {text}");
        let (_, statements, _) = body(&format!("{procedure};\nDELETE FROM dbo.zz_t;"));
        assert_eq!(statements, count + 1, "{procedure}");
    }
    // A body that is one block keeps it as the body statement.
    let block = "CREATE PROCEDURE dbo.zz_p AS\nBEGIN\n  SELECT id FROM dbo.zz_src\nEND";
    let (has_block, statements, _) = body(block);
    assert!(has_block && statements == 0, "{block}");
    // Elsewhere a body runs to its terminator, as before.
    let snowflake = lexega_syntax::dialect::snowflake();
    let src = "CREATE PROCEDURE zz_p() RETURNS INT LANGUAGE SQL AS 'SELECT 1';\nDELETE FROM zz_t;";
    let script = lexega_syntax::parse_sql_with_dialect(src, &*snowflake).expect("parses");
    let Some(AstStmt::CreateProcedure(procedure)) = script.stmts.first() else {
        panic!("{src}: {:?}", script.stmts);
    };
    assert!(procedure.body_statements.is_empty());
    assert_eq!(script.stmts.len(), 2);
}

/// The variant a statement parses to, and the text of its leading keyword.
fn module_variant(src: &str, dialect: &lexega_syntax::dialect::DialectRef) -> (String, String) {
    use lexega_syntax::ast::AstStmt;
    let script = lexega_syntax::parse_sql_with_dialect(src, &**dialect).expect("parses");
    let stmt = script.stmts.first().unwrap_or_else(|| panic!("{src}"));
    let lead = match stmt {
        AstStmt::CreateProcedure(s) => s.create_span,
        AstStmt::CreateFunction(s) => s.create_span,
        other => other.span(),
    };
    let variant = format!("{stmt:?}");
    let variant = variant
        .split(['(', ' ', '{'])
        .next()
        .unwrap_or("")
        .to_string();
    let lead = src[lead.start as usize..lead.end as usize]
        .split_whitespace()
        .next()
        .unwrap_or("")
        .to_string();
    (variant, lead)
}

#[test]
fn a_tsql_create_proc_or_altered_module_is_read_as_its_create() {
    let mssql = lexega_syntax::dialect::mssql();
    let cases = [
        ("CREATE PROC dbo.zz_p @x INT AS\nUPDATE dbo.zz_src SET c = @x", "CreateProcedure", "CREATE"),
        ("CREATE OR ALTER PROC dbo.zz_p AS\nBEGIN\n  SELECT 1\nEND", "CreateProcedure", "CREATE"),
        ("ALTER PROCEDURE dbo.zz_p AS\nUPDATE dbo.zz_src SET c = 1", "CreateProcedure", "ALTER"),
        ("ALTER PROC dbo.zz_p WITH EXECUTE AS OWNER AS\nSELECT 1", "CreateProcedure", "ALTER"),
        ("ALTER PROCEDURE dbo.zz_p @x INT\nAS\nBEGIN\n  SELECT 1\nEND", "CreateProcedure", "ALTER"),
        (
            "ALTER FUNCTION dbo.zz_f (@x INT) RETURNS TABLE AS RETURN (SELECT a FROM dbo.zz_src WHERE a = @x)",
            "CreateFunction",
            "ALTER",
        ),
        ("ALTER FUNCTION dbo.zz_f (@x INT) RETURNS INT AS BEGIN RETURN @x + 1 END", "CreateFunction", "ALTER"),
        (
            "ALTER FUNCTION dbo.zz_f () RETURNS @t TABLE (id INT) AS\nBEGIN\n  INSERT INTO @t SELECT id FROM dbo.zz_src\n  RETURN\nEND",
            "CreateFunction",
            "ALTER",
        ),
        (
            "ALTER TRIGGER dbo.zz_tr ON dbo.zz_src AFTER INSERT AS\nUPDATE dbo.zz_src SET c = 1 WHERE id = 1",
            "CreateMssqlTrigger",
            "ALTER",
        ),
        ("ALTER TRIGGER dbo.zz_tr ON dbo.zz_src AFTER INSERT AS\nBEGIN\n  SELECT 1\nEND", "CreateMssqlTrigger", "ALTER"),
        ("ALTER TRIGGER zz_ddl ON DATABASE FOR CREATE_TABLE AS\nPRINT 'x'", "CreateMssqlTrigger", "ALTER"),
    ];
    for (statement, variant, lead) in cases {
        assert_eq!(
            module_variant(statement, &mssql),
            (variant.to_string(), lead.to_string()),
            "{statement}"
        );
        let src = format!("{statement}\nGO\nDELETE FROM dbo.zz_t\nGO");
        let texts = statement_texts(&src, &mssql);
        assert!(texts[0].starts_with(statement), "{src}: {texts:?}");
        assert!(
            texts.iter().any(|t| t == "DELETE FROM dbo.zz_t"),
            "{src}: {texts:?}"
        );
    }
    // A function, or a trigger whose body is one statement, ends with its
    // definition, `;` or not.
    assert_tsql_statements_end_before_the_next(&[cases[5].0, cases[8].0, cases[10].0]);
}

#[test]
fn a_module_definition_says_which_statement_defines_it() {
    use lexega_syntax::ast::{AstDefinitionVerb as Verb, AstStmt};
    use lexega_syntax::dialect::{mssql, mysql, postgres, snowflake};
    let cases = [
        ("CREATE PROCEDURE dbo.zz_p AS SELECT 1", mssql(), Verb::Create),
        ("CREATE PROC dbo.zz_p AS SELECT 1", mssql(), Verb::Create),
        ("ALTER PROCEDURE dbo.zz_p AS SELECT 1", mssql(), Verb::Alter),
        ("ALTER PROC dbo.zz_p AS BEGIN SELECT 1 END", mssql(), Verb::Alter),
        ("CREATE OR ALTER PROC dbo.zz_p AS SELECT 1", mssql(), Verb::CreateOrAlter),
        ("CREATE FUNCTION dbo.zz_f () RETURNS INT AS BEGIN RETURN 1 END", mssql(), Verb::Create),
        ("ALTER FUNCTION dbo.zz_f () RETURNS INT AS BEGIN RETURN 1 END", mssql(), Verb::Alter),
        (
            "CREATE OR ALTER FUNCTION dbo.zz_f () RETURNS INT AS BEGIN RETURN 1 END",
            mssql(),
            Verb::CreateOrAlter,
        ),
        ("CREATE TRIGGER dbo.zz_tr ON dbo.zz_t AFTER INSERT AS SELECT 1", mssql(), Verb::Create),
        ("ALTER TRIGGER dbo.zz_tr ON dbo.zz_t AFTER INSERT AS SELECT 1", mssql(), Verb::Alter),
        (
            "CREATE OR ALTER TRIGGER dbo.zz_tr ON dbo.zz_t AFTER INSERT AS SELECT 1",
            mssql(),
            Verb::CreateOrAlter,
        ),
        (
            "CREATE OR REPLACE PROCEDURE zz_p() RETURNS INT LANGUAGE SQL AS $$ BEGIN RETURN 1; END $$",
            snowflake(),
            Verb::Create,
        ),
        (
            "CREATE FUNCTION zz_f(x int) RETURNS int LANGUAGE sql AS $$ SELECT x $$",
            postgres(),
            Verb::Create,
        ),
        ("CREATE PROCEDURE zz_p() BEGIN SELECT 1; END", mysql(), Verb::Create),
    ];
    for (src, dialect, verb) in cases {
        let script = lexega_syntax::parse_sql_with_dialect(src, &*dialect).expect("parses");
        let found = if let AstStmt::CreateProcedure(s) = &script.stmts[0] {
            s.verb
        } else if let AstStmt::CreateFunction(s) = &script.stmts[0] {
            s.verb
        } else if let AstStmt::CreateMssqlTrigger(s) = &script.stmts[0] {
            s.verb
        } else {
            panic!("{src}: not a module definition");
        };
        assert_eq!(found, verb, "{src}");
    }
}

#[test]
fn an_alter_of_a_module_property_keeps_its_reader() {
    use lexega_syntax::dialect::{postgres, snowflake};
    for (src, dialect, variant) in [
        (
            "ALTER PROCEDURE zz_p(INT) EXECUTE AS CALLER",
            snowflake(),
            "AlterProcedure",
        ),
        (
            "ALTER PROCEDURE IF EXISTS zz_p(INT) SET COMMENT = 'as'",
            snowflake(),
            "AlterProcedure",
        ),
        (
            "ALTER PROCEDURE zz_p(INT) RENAME TO zz_q",
            snowflake(),
            "AlterProcedure",
        ),
        (
            "ALTER FUNCTION zz_f(INT) SET SECURE",
            snowflake(),
            "AlterFunction",
        ),
        (
            "ALTER FUNCTION zz_f(int) RENAME TO zz_g",
            postgres(),
            "AlterFunction",
        ),
        (
            "ALTER PROCEDURE zz_p(int) OWNER TO bob",
            postgres(),
            "AlterProcedure",
        ),
        (
            "ALTER TRIGGER zz_t ON zz_x RENAME TO zz_u",
            postgres(),
            "AlterPgTrigger",
        ),
    ] {
        assert_eq!(module_variant(src, &dialect).0, variant, "{src}");
    }
}

#[test]
fn a_tsql_block_ends_at_its_end() {
    let mssql = lexega_syntax::dialect::mssql();
    for (src, expected) in [
        (
            "IF 1 = 1\nBEGIN\n  SELECT 1\nEND\nEXEC dbo.zz_sp @a = 1",
            vec!["IF 1 = 1\nBEGIN\n  SELECT 1\nEND", "EXEC dbo.zz_sp @a = 1"],
        ),
        (
            "WHILE @i < 3\nBEGIN\n  SET @i = @i + 1\nEND\nPRINT 'done'",
            vec![
                "WHILE @i < 3\nBEGIN\n  SET @i = @i + 1\nEND",
                "PRINT 'done'",
            ],
        ),
        (
            "CREATE PROCEDURE dbo.zz_p AS\nBEGIN\n  SELECT 1\nEND\nGO\nDELETE FROM dbo.zz_t\nGO",
            vec![
                "CREATE PROCEDURE dbo.zz_p AS\nBEGIN\n  SELECT 1\nEND",
                "GO",
                "DELETE FROM dbo.zz_t",
                "GO",
            ],
        ),
        (
            "ALTER FUNCTION dbo.zz_f () RETURNS INT\nBEGIN\n  RETURN 1\nEND\nGO",
            vec![
                "ALTER FUNCTION dbo.zz_f () RETURNS INT\nBEGIN\n  RETURN 1\nEND",
                "GO",
            ],
        ),
    ] {
        let texts = statement_texts(src, &mssql);
        let texts: Vec<&str> = texts.iter().map(|t| t.trim_end()).collect();
        assert_eq!(texts, expected, "{src}");
    }
    // Elsewhere a block's end label stays its own.
    let databricks = lexega_syntax::dialect::databricks();
    let src = "lbl: BEGIN\n  SELECT 1;\nEND lbl;\nDELETE FROM zz_t;";
    let texts = statement_texts(src, &databricks);
    assert_eq!(texts.len(), 2, "{src}: {texts:?}");
    assert!(texts[0].ends_with("END lbl"), "{src}: {texts:?}");
}

#[test]
fn a_tsql_break_or_continue_in_a_block_inside_a_while_parses() {
    let mssql = lexega_syntax::dialect::mssql();
    let while_loop =
        "WHILE @i < 3\nBEGIN\n  SET @i = @i + 1\n  IF @i = 2\n  BEGIN\n    BREAK\n  END\n  \
                      CONTINUE\nEND";
    let src = format!("{while_loop}\nDELETE FROM zz_t");
    let texts = statement_texts(&src, &mssql);
    let texts: Vec<&str> = texts.iter().map(|t| t.trim_end()).collect();
    assert_eq!(texts, [while_loop, "DELETE FROM zz_t"], "{src}");
    let script = lexega_syntax::parse_sql_with_dialect(&src, &*mssql).expect("parses");
    let tree = format!("{:?}", script.stmts[0]);
    assert!(
        tree.contains("Break {") && tree.contains("Continue {"),
        "{tree}"
    );
    assert!(!tree.contains("Error {"), "{tree}");
}

#[test]
fn a_function_body_block_without_as_ends_with_its_end() {
    use lexega_syntax::ast::AstStmt;
    use lexega_syntax::dialect::{databricks, mssql, mysql, postgres};
    let mut cases = Vec::new();
    for function in [
        "CREATE FUNCTION dbo.zz_f () RETURNS INT\nBEGIN\n  RETURN 1\nEND",
        "CREATE FUNCTION dbo.zz_f (@x INT) RETURNS INT WITH SCHEMABINDING\nBEGIN\n  RETURN @x\nEND",
        "ALTER FUNCTION dbo.zz_f () RETURNS INT\nBEGIN\n  RETURN 1\nEND",
        "CREATE FUNCTION dbo.zz_f () RETURNS @t TABLE (id INT)\nBEGIN\n  \
         INSERT INTO @t SELECT id FROM dbo.zz_src\n  RETURN\nEND",
    ] {
        cases.push((
            function.to_string(),
            format!("{function}\nDELETE FROM zz_t"),
            mssql(),
        ));
        cases.push((
            function.to_string(),
            format!("{function};\nDELETE FROM zz_t;"),
            mssql(),
        ));
    }
    for (function, dialect) in [
        (
            "CREATE FUNCTION zz_f() RETURNS INT DETERMINISTIC\nBEGIN\n  RETURN 1;\nEND",
            mysql(),
        ),
        (
            "CREATE FUNCTION zz_f() RETURNS INT LANGUAGE SQL BEGIN RETURN 1; END",
            databricks(),
        ),
        (
            "CREATE FUNCTION zz_f() RETURNS int LANGUAGE sql BEGIN ATOMIC SELECT 1; END",
            postgres(),
        ),
    ] {
        cases.push((
            function.to_string(),
            format!("{function};\nDELETE FROM zz_t;"),
            dialect,
        ));
    }
    for (function, src, dialect) in cases {
        let texts = statement_texts(&src, &dialect);
        let texts: Vec<&str> = texts.iter().map(|t| t.trim_end()).collect();
        assert_eq!(texts, [function.as_str(), "DELETE FROM zz_t"], "{src}");
        let script = lexega_syntax::parse_sql_with_dialect(&src, &*dialect).expect("parses");
        let Some(AstStmt::CreateFunction(created)) = script.stmts.first() else {
            panic!("{src}: {:?}", script.stmts);
        };
        assert!(
            matches!(created.body_stmt.as_deref(), Some(AstStmt::Block(_))),
            "{src}: {:?}",
            created.body_stmt
        );
    }
}

#[test]
fn a_tsql_function_with_options_ends_where_its_body_does() {
    use lexega_syntax::ast::AstStmt;
    let block_bodied = [
        "CREATE FUNCTION dbo.zz_f (@x INT) RETURNS INT WITH EXECUTE AS CALLER AS BEGIN RETURN @x END",
        "ALTER FUNCTION dbo.zz_f (@x INT) RETURNS INT WITH EXECUTE AS OWNER AS BEGIN RETURN @x END",
        "ALTER FUNCTION dbo.zz_f (@x INT) RETURNS INT WITH SCHEMABINDING, EXECUTE AS CALLER \
         AS BEGIN RETURN @x END",
        "CREATE FUNCTION dbo.zz_f (@x INT) RETURNS INT WITH EXECUTE AS CALLER BEGIN RETURN @x END",
        "CREATE OR ALTER FUNCTION dbo.zz_f (@x INT) RETURNS INT WITH EXECUTE AS SELF \
         AS BEGIN RETURN @x END",
        "CREATE FUNCTION dbo.zz_f (@x INT) RETURNS INT WITH EXEC AS 'zz_u' AS BEGIN RETURN @x END",
        "CREATE FUNCTION dbo.zz_f (@x INT) RETURNS INT WITH ENCRYPTION, SCHEMABINDING, \
         RETURNS NULL ON NULL INPUT, EXECUTE AS CALLER, INLINE = ON AS BEGIN RETURN @x END",
        "CREATE FUNCTION dbo.zz_f (@x INT)\nRETURNS INT\nWITH EXECUTE AS CALLER\nAS\nBEGIN\n  \
         DECLARE @y INT = @x + 1\n  RETURN @y\nEND",
        "CREATE FUNCTION dbo.zz_f () RETURNS @t TABLE (id INT) WITH EXECUTE AS OWNER AS BEGIN \
         INSERT INTO @t SELECT id FROM dbo.zz_src RETURN END",
    ];
    assert_tsql_statements_end_before_the_next(&block_bodied);
    assert_tsql_statements_end_before_the_next(&[
        "ALTER FUNCTION dbo.zz_f (@x INT) RETURNS TABLE WITH SCHEMABINDING, EXECUTE AS CALLER \
         AS RETURN (SELECT a FROM dbo.zz_src WHERE a = @x)",
    ]);
    let mssql = lexega_syntax::dialect::mssql();
    for function in block_bodied {
        let script = lexega_syntax::parse_sql_with_dialect(function, &*mssql).expect("parses");
        let Some(AstStmt::CreateFunction(created)) = script.stmts.first() else {
            panic!("{function}: {:?}", script.stmts);
        };
        assert!(
            matches!(created.body_stmt.as_deref(), Some(AstStmt::Block(_))),
            "{function}: {:?}",
            created.body_stmt
        );
    }
}

#[test]
fn a_procedure_executing_as_restricted_caller_reads_its_body() {
    use lexega_syntax::ast::{AstStmt, ExecuteAsMode};
    let snowflake = lexega_syntax::dialect::snowflake();
    let procedure = "CREATE OR REPLACE PROCEDURE zz_p() RETURNS VARCHAR LANGUAGE SQL \
                     EXECUTE AS RESTRICTED CALLER AS $$ BEGIN RETURN 'x'; END $$";
    let src = format!("{procedure};\nDELETE FROM zz_t;");
    let texts = statement_texts(&src, &snowflake);
    assert_eq!(texts, [procedure, "DELETE FROM zz_t"], "{src}");
    let script = lexega_syntax::parse_sql_with_dialect(&src, &*snowflake).expect("parses");
    let Some(AstStmt::CreateProcedure(created)) = script.stmts.first() else {
        panic!("{src}: {:?}", script.stmts);
    };
    assert_eq!(
        created.execute_as_mode,
        Some(ExecuteAsMode::RestrictedCaller)
    );
    assert!(created.body_stmt.is_some(), "{src}");
}

#[test]
fn a_tsql_exec_without_arguments_ends_before_the_next_statement() {
    let mssql = lexega_syntax::dialect::mssql();
    let block = "IF 1 = 1\nBEGIN\n  PRINT 'x'\nEND";
    for (src, expected) in [
        (
            "EXEC dbo.zz_p\nTRUNCATE TABLE dbo.zz_t".to_string(),
            vec!["EXEC dbo.zz_p", "TRUNCATE TABLE dbo.zz_t"],
        ),
        (
            "EXECUTE dbo.zz_p\nDROP TABLE dbo.zz_t".to_string(),
            vec!["EXECUTE dbo.zz_p", "DROP TABLE dbo.zz_t"],
        ),
        (
            format!("{block}\nEXEC dbo.zz_p\nTRUNCATE TABLE dbo.zz_t"),
            vec![block, "EXEC dbo.zz_p", "TRUNCATE TABLE dbo.zz_t"],
        ),
        (
            format!("{block}\nEXEC dbo.zz_p\nDROP TABLE dbo.zz_t"),
            vec![block, "EXEC dbo.zz_p", "DROP TABLE dbo.zz_t"],
        ),
        (
            "EXEC dbo.zz_p\nGRANT SELECT ON dbo.zz_t TO zz_r".to_string(),
            vec!["EXEC dbo.zz_p", "GRANT SELECT ON dbo.zz_t TO zz_r"],
        ),
        (
            "EXEC dbo.zz_p\nBEGIN TRAN".to_string(),
            vec!["EXEC dbo.zz_p", "BEGIN TRAN"],
        ),
        (
            "EXEC dbo.zz_p\nEXEC dbo.zz_q".to_string(),
            vec!["EXEC dbo.zz_p", "EXEC dbo.zz_q"],
        ),
        (
            "EXEC dbo.zz_p 1, 'a'\nTRUNCATE TABLE dbo.zz_t".to_string(),
            vec!["EXEC dbo.zz_p 1, 'a'", "TRUNCATE TABLE dbo.zz_t"],
        ),
        (
            "EXEC sp_who active\nTRUNCATE TABLE dbo.zz_t".to_string(),
            vec!["EXEC sp_who active", "TRUNCATE TABLE dbo.zz_t"],
        ),
    ] {
        let texts = statement_texts(&src, &mssql);
        let texts: Vec<&str> = texts.iter().map(|t| t.trim_end()).collect();
        assert_eq!(texts, expected, "{src}");
    }
}

#[test]
fn a_tsql_exec_reads_its_with_options() {
    use lexega_syntax::ast::AstStmt;
    let mssql = lexega_syntax::dialect::mssql();
    let execs = [
        "EXEC dbo.zz_p WITH RECOMPILE",
        "EXECUTE dbo.zz_p @a = 1 WITH RECOMPILE",
        "EXEC dbo.zz_p WITH RESULT SETS ((id INT NOT NULL, c NVARCHAR(10) COLLATE Latin1_General_CI_AS NULL))",
        "EXEC dbo.zz_p WITH RESULT SETS ((id INT), (c INT)), RECOMPILE",
        "EXEC dbo.zz_p WITH RESULT SETS (AS OBJECT dbo.zz_t, AS TYPE dbo.zz_tt, AS FOR XML)",
        "EXEC dbo.zz_p WITH RESULT SETS NONE",
        "EXEC dbo.zz_p WITH RESULT SETS UNDEFINED",
        "EXEC (@sql) WITH RESULT SETS ((id INT))",
    ];
    assert_tsql_statements_end_before_the_next(&execs);
    for exec in execs {
        let inserted = format!("INSERT INTO dbo.zz_a (id) {exec}");
        for (src, expected) in [
            (
                format!("{exec}\nDELETE FROM dbo.zz_t"),
                vec![exec, "DELETE FROM dbo.zz_t"],
            ),
            (
                format!("{inserted}\nDELETE FROM dbo.zz_t"),
                vec!["INSERT", "DELETE FROM dbo.zz_t"],
            ),
            (
                format!("{inserted};\nDELETE FROM dbo.zz_t;"),
                vec!["INSERT", "DELETE FROM dbo.zz_t"],
            ),
            (
                format!("{inserted}\nGO\nDELETE FROM dbo.zz_t\nGO"),
                vec!["INSERT", "GO", "DELETE FROM dbo.zz_t", "GO"],
            ),
        ] {
            let texts = statement_texts(&src, &mssql);
            let texts: Vec<&str> = texts.iter().map(|t| t.trim_end()).collect();
            assert_eq!(texts, expected, "{src}");
        }
        let script = lexega_syntax::parse_sql_with_dialect(&inserted, &*mssql).expect("parses");
        let Some(AstStmt::Insert(insert)) = script.stmts.first() else {
            panic!("{inserted}: {:?}", script.stmts);
        };
        let span = insert.span;
        assert_eq!(&inserted[span.start as usize..span.end as usize], inserted);
        let procedure = format!(
            "CREATE PROCEDURE dbo.zz_q AS\nBEGIN\n  {inserted}\n  DELETE FROM dbo.zz_t\nEND"
        );
        let script = lexega_syntax::parse_sql_with_dialect(&procedure, &*mssql).expect("parses");
        let Some(AstStmt::CreateProcedure(created)) = script.stmts.first() else {
            panic!("{procedure}: {:?}", script.stmts);
        };
        let Some(AstStmt::Block(block)) = created.body_stmt.as_deref() else {
            panic!("{procedure}: {:?}", created.body_stmt);
        };
        assert_eq!(block.body.len(), 2, "{procedure}: {:?}", block.body);
        assert!(matches!(block.body[0], AstStmt::Insert(_)), "{procedure}");
        assert!(matches!(block.body[1], AstStmt::Delete(_)), "{procedure}");
    }
}

#[test]
fn a_tsql_enable_or_disable_trigger_ends_with_its_scope() {
    let mssql = lexega_syntax::dialect::mssql();
    for statement in [
        "DISABLE TRIGGER dbo.zz_tr ON dbo.zz_t",
        "ENABLE TRIGGER zz_a, [zz b] ON [dbo].[zz_t]",
        "DISABLE TRIGGER ALL ON DATABASE",
        "ENABLE TRIGGER ALL ON ALL SERVER",
        "disable trigger /* c */ zz_tr on database",
    ] {
        for (src, next) in [
            (
                format!("{statement}\nTRUNCATE TABLE dbo.zz_t"),
                "TRUNCATE TABLE dbo.zz_t",
            ),
            (
                format!("{statement};\nDELETE FROM dbo.zz_t;"),
                "DELETE FROM dbo.zz_t",
            ),
            (format!("{statement}\nEXEC dbo.zz_p"), "EXEC dbo.zz_p"),
        ] {
            let texts = statement_texts(&src, &mssql);
            let texts: Vec<&str> = texts
                .iter()
                .map(|t| t.trim_end().trim_end_matches(';'))
                .collect();
            assert_eq!(texts, vec![statement, next], "{src}");
        }
        // A statement before it, without a semicolon, ends where it starts.
        for (before, text) in [
            ("SELECT * FROM dbo.zz_t", "SELECT"),
            ("INSERT INTO dbo.zz_t SELECT * FROM dbo.zz_s", "INSERT"),
            ("DELETE FROM dbo.zz_t", "DELETE FROM dbo.zz_t"),
            ("UPDATE dbo.zz_t SET c = 1", "UPDATE dbo.zz_t SET c = 1"),
            ("EXEC dbo.zz_p", "EXEC dbo.zz_p"),
        ] {
            let src = format!("{before}\n{statement}");
            let texts = statement_texts(&src, &mssql);
            let texts: Vec<&str> = texts.iter().map(|t| t.trim_end()).collect();
            assert_eq!(texts, vec![text, statement], "{src}");
        }
    }
    // The word alone is still a name.
    for (src, count) in [
        ("SELECT c disable FROM dbo.zz_t\nDELETE FROM dbo.zz_t", 2),
        ("SELECT enable FROM dbo.zz_t\nDELETE FROM dbo.zz_t", 2),
        ("EXEC dbo.zz_p disable\nDELETE FROM dbo.zz_t", 2),
    ] {
        assert_eq!(statement_texts(src, &mssql).len(), count, "{src}");
    }
}

#[test]
fn a_tsql_statement_led_by_a_reserved_statement_word_ends_the_statement_before_it() {
    let mssql = lexega_syntax::dialect::mssql();
    for statement in [
        "RAISERROR('zz', 0, 1) WITH NOWAIT",
        "WAITFOR DELAY '00:00:01'",
        "DBCC CHECKDB",
        "BACKUP DATABASE zz TO DISK = 'zz.bak'",
        "RESTORE DATABASE zz FROM DISK = 'zz.bak'",
        "CHECKPOINT",
        "SETUSER",
        "GOTO done",
        "KILL 52",
        "DEALLOCATE zz_c",
        "SHUTDOWN WITH NOWAIT",
        "READTEXT dbo.zz_t.c @p 0 0",
        "WRITETEXT dbo.zz_t.c @p 'zz'",
        "UPDATETEXT dbo.zz_t.c @p 0 NULL 'zz'",
    ] {
        for (before, text) in [
            ("SELECT * FROM dbo.zz_t", "SELECT"),
            ("INSERT INTO dbo.zz_t SELECT * FROM dbo.zz_s", "INSERT"),
            ("DELETE FROM dbo.zz_t", "DELETE FROM dbo.zz_t"),
            ("EXEC dbo.zz_p", "EXEC dbo.zz_p"),
        ] {
            let src = format!("{before}\n{statement}");
            let texts = statement_texts(&src, &mssql);
            let texts: Vec<&str> = texts.iter().map(|t| t.trim_end()).collect();
            assert_eq!(texts, vec![text, statement], "{src}");
        }
    }
}

#[test]
fn a_tsql_bulk_insert_ends_the_statement_before_it() {
    let mssql = lexega_syntax::dialect::mssql();
    let bulk = "BULK INSERT dbo.zz_t FROM 'c:\\zz.csv' WITH (FIELDTERMINATOR = ',')";
    for (before, text) in [
        ("SELECT * FROM dbo.zz_t", "SELECT"),
        ("INSERT INTO dbo.zz_t SELECT * FROM dbo.zz_s", "INSERT"),
        ("DELETE FROM dbo.zz_t", "DELETE FROM dbo.zz_t"),
        ("EXEC dbo.zz_p", "EXEC dbo.zz_p"),
    ] {
        let src = format!("{before}\n{bulk}");
        let texts = statement_texts(&src, &mssql);
        let texts: Vec<&str> = texts.iter().map(|t| t.trim_end()).collect();
        assert_eq!(texts, vec![text, bulk], "{src}");
    }
    // `BULK` not followed by `INSERT` starts no statement.
    for (src, expected) in [
        (
            "SELECT * FROM OPENROWSET(BULK 'c:\\zz.csv', SINGLE_CLOB) AS x\nDELETE FROM dbo.zz_t",
            vec!["SELECT", "DELETE FROM dbo.zz_t"],
        ),
        (
            "INSERT INTO dbo.zz_t SELECT * FROM OPENROWSET(BULK 'c:\\zz.csv', \
             FORMATFILE = 'c:\\zz.fmt') AS x\nDELETE FROM dbo.zz_t",
            vec!["INSERT", "DELETE FROM dbo.zz_t"],
        ),
    ] {
        let texts = statement_texts(src, &mssql);
        let texts: Vec<&str> = texts.iter().map(|t| t.trim_end()).collect();
        assert_eq!(texts, expected, "{src}");
    }
}

#[test]
fn a_tsql_enable_or_disable_trigger_names_its_action_triggers_and_scope() {
    use lexega_syntax::ast::types::{MssqlTriggerList, MssqlTriggerScope, MssqlTriggerStateAction};
    use lexega_syntax::ast::AstStmt;
    let mssql = lexega_syntax::dialect::mssql();
    let text = |src: &str, span: lexega_syntax::Span| {
        src[span.start as usize..span.end as usize].to_string()
    };
    for (src, action, triggers, scope) in [
        (
            "DISABLE TRIGGER dbo.zz_tr ON dbo.zz_t",
            MssqlTriggerStateAction::Disable,
            Some(vec!["dbo.zz_tr"]),
            Some("dbo.zz_t"),
        ),
        (
            "ENABLE TRIGGER zz_a, [zz b] ON [dbo].[zz_t]",
            MssqlTriggerStateAction::Enable,
            Some(vec!["zz_a", "[zz b]"]),
            Some("[dbo].[zz_t]"),
        ),
        (
            "disable trigger all on database",
            MssqlTriggerStateAction::Disable,
            None,
            None,
        ),
        (
            "ENABLE TRIGGER ALL ON ALL SERVER",
            MssqlTriggerStateAction::Enable,
            None,
            None,
        ),
    ] {
        let script = lexega_syntax::parse_sql_with_dialect(src, &*mssql).expect("parses");
        let [AstStmt::MssqlTriggerState(stmt)] = script.stmts.as_slice() else {
            panic!("{src}: {:?}", script.stmts);
        };
        assert_eq!(stmt.action, action, "{src}");
        match (&stmt.triggers, triggers) {
            (MssqlTriggerList::Named(names), Some(expected)) => {
                let names: Vec<String> = names.iter().map(|n| text(src, n.span)).collect();
                assert_eq!(names, expected, "{src}");
            }
            (MssqlTriggerList::All, None) => {}
            (MssqlTriggerList::Named(_), None) | (MssqlTriggerList::All, Some(_)) => {
                panic!("{src}: {:?}", stmt.triggers)
            }
        }
        match (&stmt.scope, scope) {
            (MssqlTriggerScope::Object(object), Some(expected)) => {
                assert_eq!(text(src, object.span), expected, "{src}")
            }
            (MssqlTriggerScope::Database, None) => assert!(src.ends_with("database"), "{src}"),
            (MssqlTriggerScope::AllServer, None) => assert!(src.ends_with("ALL SERVER"), "{src}"),
            (MssqlTriggerScope::Object(_), None)
            | (MssqlTriggerScope::Database | MssqlTriggerScope::AllServer, Some(_)) => {
                panic!("{src}: {:?}", stmt.scope)
            }
        }
    }
}

#[test]
fn a_tsql_procedure_executing_as_a_named_user_ends_at_the_batch_separator() {
    use lexega_syntax::ast::{AstStmt, ExecuteAsMode};
    let mssql = lexega_syntax::dialect::mssql();
    for (procedure, mode) in [
        (
            "CREATE PROCEDURE dbo.zz_p WITH EXECUTE AS 'zz_u' AS\nUPDATE dbo.zz_src SET c = 1",
            None,
        ),
        (
            "ALTER PROCEDURE dbo.zz_p WITH EXECUTE AS 'zz_u' AS\nUPDATE dbo.zz_src SET c = 1",
            None,
        ),
        (
            "CREATE PROCEDURE dbo.zz_p @x INT WITH RECOMPILE, EXECUTE AS N'zz_u' AS\n\
             UPDATE dbo.zz_src SET c = @x",
            None,
        ),
        (
            "CREATE OR ALTER PROC dbo.zz_p WITH EXEC AS 'zz_u' AS\nBEGIN\n  \
             UPDATE dbo.zz_src SET c = 1\nEND",
            None,
        ),
        (
            "CREATE PROCEDURE dbo.zz_p WITH EXECUTE AS SELF AS\nUPDATE dbo.zz_src SET c = 1",
            None,
        ),
        (
            "CREATE PROCEDURE dbo.zz_p WITH EXECUTE AS OWNER AS\nUPDATE dbo.zz_src SET c = 1",
            Some(ExecuteAsMode::Owner),
        ),
        (
            "CREATE PROCEDURE dbo.zz_p @x INT WITH RECOMPILE, EXEC AS CALLER AS\n\
             UPDATE dbo.zz_src SET c = @x",
            Some(ExecuteAsMode::Caller),
        ),
    ] {
        let src = format!("{procedure}\nGO\nDELETE FROM dbo.zz_t\nGO");
        let texts = statement_texts(&src, &mssql);
        let texts: Vec<&str> = texts.iter().map(|t| t.trim_end()).collect();
        assert_eq!(
            texts,
            [procedure, "GO", "DELETE FROM dbo.zz_t", "GO"],
            "{src}"
        );
        let script = lexega_syntax::parse_sql_with_dialect(&src, &*mssql).expect("parses");
        let Some(AstStmt::CreateProcedure(created)) = script.stmts.first() else {
            panic!("{src}: {:?}", script.stmts);
        };
        assert_eq!(created.execute_as_mode, mode, "{src}");
        let body = &src[created.body_span.start as usize..created.body_span.end as usize];
        assert!(
            body.starts_with("UPDATE") || body.starts_with("BEGIN"),
            "{src}: {body}"
        );
    }
}

#[test]
fn an_option_list_written_after_a_table_or_view_name_is_not_part_of_the_name() {
    use lexega_syntax::ast::AstStmt;
    use lexega_syntax::dialect::{bigquery, databricks};
    for (src, dialect, name) in [
        (
            "CREATE VIEW d.v OPTIONS (description = 'x') AS SELECT 1",
            bigquery(),
            "d.v",
        ),
        (
            "CREATE TABLE d.t OPTIONS (description = 'x') AS SELECT 1",
            bigquery(),
            "d.t",
        ),
        (
            "CREATE TABLE t TBLPROPERTIES ('a' = 'b') AS SELECT 1",
            databricks(),
            "t",
        ),
        (
            "CREATE VIEW v TBLPROPERTIES ('a' = 'b') AS SELECT 1",
            databricks(),
            "v",
        ),
        (
            "CREATE MATERIALIZED VIEW v TBLPROPERTIES ('a' = 'b') AS SELECT 1",
            databricks(),
            "v",
        ),
        // A name that is one of the words is still the name.
        ("CREATE VIEW d.options AS SELECT 1", bigquery(), "d.options"),
        (
            "CREATE TABLE tblproperties (a INT)",
            databricks(),
            "tblproperties",
        ),
    ] {
        let script = lexega_syntax::parse_sql_with_dialect(src, &*dialect).expect("parses");
        let (read, columns) = match script.stmts.first() {
            Some(AstStmt::CreateView(view)) => (view.name.span, view.columns_span),
            Some(AstStmt::CreateTable(table)) => (table.name.span, table.columns_span),
            other => panic!("{src}: {other:?}"),
        };
        assert_eq!(&src[read.start as usize..read.end as usize], name, "{src}");
        if !src.contains("(a INT)") {
            assert_eq!(columns, None, "{src}");
        }
    }
}

/// The one statement `src` parses to under `dialect`, as a created table:
/// its name's parts as written (`None` where it is no dotted name), its
/// `IDENTIFIER(…)` argument's text, its column count and whether its query
/// was parsed.
fn created_table(
    src: &str,
    dialect: &dyn lexega_syntax::dialect::Dialect,
) -> (Option<Vec<String>>, Option<String>, usize, bool) {
    use lexega_syntax::ast::AstStmt;
    let script = lexega_syntax::parse_sql_with_dialect(src, dialect).expect("parses");
    let [AstStmt::CreateTable(table)] = script.stmts.as_slice() else {
        let kinds: Vec<String> = script
            .stmts
            .iter()
            .map(|s| format!("{s:?}").chars().take(16).collect())
            .collect();
        return (Some(kinds), None, usize::MAX, false);
    };
    let text = |s: lexega_syntax::lexer::Span| src[s.start as usize..s.end as usize].to_string();
    let parts = table.name.parts.as_ref().map(|parts| {
        parts
            .iter()
            .map(|p| p.as_ref().map_or(String::new(), |part| text(part.span())))
            .collect()
    });
    let argument = table
        .name
        .identifier_arg
        .as_ref()
        .map(|arg| text(arg.span()));
    let query = matches!(
        table.ctas_query.as_ref(),
        Some(Ok(q)) if matches!(**q, AstStmt::Select(_) | AstStmt::SetSelect(_))
    );
    (parts, argument, table.columns.len(), query)
}

#[test]
fn a_create_led_by_or_alter_replace_or_streaming_is_one_create_table() {
    use lexega_syntax::dialect::{databricks, snowflake};
    let named = |parts: &[&str]| Some(parts.iter().map(|p| p.to_string()).collect::<Vec<_>>());
    let wrong = [
        (
            "CREATE OR ALTER TABLE zz_t (id INT, email VARCHAR)",
            snowflake(),
            named(&["zz_t"]),
            None,
            2,
            false,
        ),
        (
            "CREATE OR ALTER TABLE analytics.public.zz_t (id INT)",
            snowflake(),
            named(&["analytics", "public", "zz_t"]),
            None,
            1,
            false,
        ),
        (
            "REPLACE TABLE zz_t AS SELECT id FROM zz_src",
            databricks(),
            named(&["zz_t"]),
            None,
            0,
            true,
        ),
        (
            "REPLACE TABLE s1.zz_t (id INT) USING DELTA",
            databricks(),
            named(&["s1", "zz_t"]),
            None,
            1,
            false,
        ),
        (
            "CREATE OR REFRESH STREAMING TABLE zz_t AS SELECT id FROM zz_src",
            databricks(),
            named(&["zz_t"]),
            None,
            0,
            true,
        ),
        (
            "CREATE STREAMING TABLE zz_t (id INT) AS SELECT id FROM zz_src",
            databricks(),
            named(&["zz_t"]),
            None,
            1,
            true,
        ),
        (
            "CREATE OR REFRESH STREAMING LIVE TABLE zz_t AS SELECT id FROM zz_src",
            databricks(),
            named(&["zz_t"]),
            None,
            0,
            true,
        ),
        (
            "CREATE TABLE IDENTIFIER('zz_t') (id INT, email VARCHAR)",
            snowflake(),
            None,
            Some("'zz_t'".to_string()),
            2,
            false,
        ),
        (
            "CREATE OR REPLACE TABLE IDENTIFIER('a.b.zz_t') AS SELECT id FROM zz_src",
            snowflake(),
            None,
            Some("'a.b.zz_t'".to_string()),
            0,
            true,
        ),
        // A table named `identifier` keeps its column list.
        (
            "CREATE TABLE identifier (id INT)",
            snowflake(),
            named(&["identifier"]),
            None,
            1,
            false,
        ),
    ]
    .into_iter()
    .filter_map(|(src, dialect, parts, argument, columns, query)| {
        let read = created_table(src, &*dialect);
        (read != (parts, argument, columns, query)).then(|| format!("{src}: {read:?}"))
    })
    .collect::<Vec<_>>();
    assert!(wrong.is_empty(), "{wrong:#?}");
}

#[test]
fn a_replace_table_records_that_it_replaces_and_formats_its_keyword_once() {
    use lexega_syntax::ast::AstStmt;
    use lexega_syntax::dialect::{databricks, snowflake};
    let mut wrong = Vec::new();
    for (src, dialect, replaces) in [
        (
            "REPLACE TABLE zz_t AS SELECT id FROM zz_src",
            databricks(),
            Some("REPLACE"),
        ),
        (
            "REPLACE TABLE s1.zz_t (id INT) USING DELTA",
            databricks(),
            Some("REPLACE"),
        ),
        (
            "CREATE OR REPLACE TABLE zz_t (id INT)",
            databricks(),
            Some("OR REPLACE"),
        ),
        ("CREATE TABLE zz_t (id INT)", databricks(), None),
        ("CREATE OR ALTER TABLE zz_t (id INT)", snowflake(), None),
    ] {
        let script = lexega_syntax::parse_sql_with_dialect(src, &*dialect).expect("parses");
        let [AstStmt::CreateTable(table)] = script.stmts.as_slice() else {
            wrong.push(format!("{src}: not one create table"));
            continue;
        };
        let read = table
            .or_replace_span
            .map(|s| &src[s.start as usize..s.end as usize]);
        if read != replaces {
            wrong.push(format!("{src}: or_replace_span {read:?}"));
        }
        let config = lexega_syntax::FormatterConfig {
            dialect: dialect.clone(),
            ..lexega_syntax::FormatterConfig::default()
        };
        let formatted = lexega_syntax::format_sql_with_config(src, &config).expect("formats");
        if formatted.to_uppercase().matches("REPLACE").count() != src.matches("REPLACE").count() {
            wrong.push(format!("{src}: formatted as {formatted}"));
        }
        if let Err(e) =
            lexega_syntax::verify_formatting_safe_with_dialect(src, &formatted, &*dialect)
        {
            wrong.push(format!("{src}: formatted as {formatted}: {e:?}"));
        }
    }
    assert!(wrong.is_empty(), "{wrong:#?}");
}

#[test]
fn a_create_table_query_written_without_as_is_its_query() {
    let mysql = lexega_syntax::dialect::mysql();
    let named = |parts: &[&str]| Some(parts.iter().map(|p| p.to_string()).collect::<Vec<_>>());
    let mut wrong = [
        ("CREATE TABLE zz_t SELECT id FROM zz_src", &["zz_t"][..], 0),
        (
            "CREATE TABLE t2 (a INT, b VARCHAR(10)) SELECT id, email FROM users",
            &["t2"],
            2,
        ),
        (
            "CREATE TABLE IF NOT EXISTS zz_t SELECT id FROM zz_src",
            &["zz_t"],
            0,
        ),
        (
            "CREATE TABLE zz_t IGNORE SELECT id FROM zz_src",
            &["zz_t"],
            0,
        ),
        (
            "CREATE TABLE zz_t REPLACE SELECT id FROM zz_src",
            &["zz_t"],
            0,
        ),
        (
            "CREATE TABLE d1.zz_t ENGINE=InnoDB SELECT id FROM zz_src",
            &["d1", "zz_t"],
            0,
        ),
        (
            "CREATE TABLE zz_t ENGINE = InnoDB AS SELECT id FROM zz_src",
            &["zz_t"],
            0,
        ),
        (
            "CREATE TABLE zz_t (a INT) ENGINE=InnoDB IGNORE AS SELECT id FROM zz_src",
            &["zz_t"],
            1,
        ),
    ]
    .into_iter()
    .filter_map(|(src, parts, columns)| {
        let read = created_table(src, &*mysql);
        (read != (named(parts), None, columns, true)).then(|| format!("{src}: {read:?}"))
    })
    .collect::<Vec<_>>();
    // A T-SQL script needs no terminator: the `SELECT` after a create is the
    // next statement.
    let tsql = statements_and_names(
        "CREATE TABLE #t (id INT)\nSELECT id FROM zz_src",
        &*lexega_syntax::dialect::mssql(),
    );
    if tsql
        != [
            ("CREATE TABLE".to_string(), None),
            ("SELECT".to_string(), None),
        ]
    {
        wrong.push(format!("T-SQL: {tsql:?}"));
    }
    assert!(wrong.is_empty(), "{wrong:#?}");
}

#[test]
fn a_foreign_or_snapshot_table_is_named_by_the_parts_it_was_written_with() {
    use lexega_syntax::ast::AstStmt;
    use lexega_syntax::dialect::{bigquery, postgres};
    let cases: [(&str, lexega_syntax::dialect::DialectRef, &[&str]); 9] = [
        (
            "CREATE FOREIGN TABLE zz_t (id INT) SERVER zz_srv",
            postgres(),
            &["zz_t"],
        ),
        (
            "CREATE FOREIGN TABLE IF NOT EXISTS zz_s . /* c */ zz_t (id INT) SERVER zz_db.zz_srv",
            postgres(),
            &["zz_s", "zz_t"],
        ),
        (
            "CREATE FOREIGN TABLE analytics.public.\"my.new\" (id INT) SERVER zz_srv \
             OPTIONS (table_name 't')",
            postgres(),
            &["analytics", "public", "\"my.new\""],
        ),
        (
            "CREATE FOREIGN TABLE zz_s.zz_p PARTITION OF zz_s.zz_parent FOR VALUES IN (1) \
             SERVER zz_srv",
            postgres(),
            &["zz_s", "zz_p"],
        ),
        (
            "CREATE SNAPSHOT TABLE zz_t CLONE zz_src",
            bigquery(),
            &["zz_t"],
        ),
        (
            "CREATE SNAPSHOT TABLE `zz_p.zz_d.zz_t` CLONE zz_d.zz_src",
            bigquery(),
            &["`zz_p.zz_d.zz_t`"],
        ),
        (
            "CREATE SNAPSHOT TABLE `zz_p`.`zz_d`.`zz_t` CLONE zz_d.zz_src",
            bigquery(),
            &["`zz_p`", "`zz_d`", "`zz_t`"],
        ),
        (
            "CREATE SNAPSHOT TABLE zz_d . /* c */ `ZzMixed` CLONE zz_d.zz_src",
            bigquery(),
            &["zz_d", "`ZzMixed`"],
        ),
        (
            "CREATE SNAPSHOT TABLE IF NOT EXISTS zz_d.zz_t CLONE zz_d.zz_src \
             FOR SYSTEM_TIME AS OF CURRENT_TIMESTAMP()",
            bigquery(),
            &["zz_d", "zz_t"],
        ),
    ];
    let wrong: Vec<String> = cases
        .into_iter()
        .filter_map(|(src, dialect, expected)| {
            let script = lexega_syntax::parse_sql_with_dialect(src, &*dialect).expect("parses");
            let (name, name_span) = match script.stmts.as_slice() {
                [AstStmt::CreateForeignTable(s)] => (&s.name, s.name_span),
                [AstStmt::BqCreateSnapshotTable(s)] => (&s.name, s.snapshot_name_span),
                other => return Some(format!("{src}: {other:?}")),
            };
            let text = |s: lexega_syntax::lexer::Span| &src[s.start as usize..s.end as usize];
            let parts: Option<Vec<&str>> = name.parts.as_ref().map(|parts| {
                parts
                    .iter()
                    .map(|p| p.as_ref().map_or("", |part| text(part.span())))
                    .collect()
            });
            (parts.as_deref() != Some(expected) || name.span != name_span)
                .then(|| format!("{src}: {parts:?}, {:?} vs {name_span:?}", name.span))
        })
        .collect();
    assert!(wrong.is_empty(), "{wrong:#?}");
}

#[test]
fn an_alerts_condition_is_read_as_an_expression() {
    use lexega_syntax::ast::AstAlterAlertActionKind;
    use lexega_syntax::AstStmt;
    // (statement, its condition's text where it parses, the condition's
    // span as written)
    let create = [
        (
            "CREATE ALERT a SCHEDULE = '1 MINUTE' IF (EXISTS (SELECT f('x') FROM t)) THEN CALL p();",
            Some("EXISTS (SELECT f('x') FROM t)"),
            "(EXISTS (SELECT f('x') FROM t))",
        ),
        (
            "CREATE ALERT a SCHEDULE = '1 MINUTE' IF (EXISTS (SELECT FROM )) THEN CALL p();",
            None,
            "(EXISTS (SELECT FROM ))",
        ),
    ];
    for (sql, condition, span) in create {
        let script = parse_sql(sql).expect("should parse");
        let AstStmt::CreateAlert(alert) = &script.stmts[0] else {
            panic!("an alert: {:?}", script.stmts[0]);
        };
        let text = |s: lexega_syntax::lexer::Span| &sql[s.start as usize..s.end as usize];
        assert_eq!(
            alert.condition.as_ref().map(|c| text(c.span())),
            condition,
            "{sql}"
        );
        assert_eq!(alert.condition_span.map(text), Some(span), "{sql}");
    }
    // The condition of MODIFY CONDITION: `None` where it does not parse.
    let modify = [
        (
            "ALTER ALERT a MODIFY CONDITION EXISTS (SELECT f('x') FROM t);",
            true,
        ),
        (
            "ALTER ALERT a MODIFY CONDITION EXISTS (SELECT FROM );",
            false,
        ),
    ];
    for (sql, parsed) in modify {
        let script = parse_sql(sql).expect("should parse");
        let AstStmt::AlterAlert(alert) = &script.stmts[0] else {
            panic!("an alert: {:?}", script.stmts[0]);
        };
        let AstAlterAlertActionKind::ModifyCondition {
            condition_span,
            condition,
            ..
        } = &alert.action.kind
        else {
            panic!("a condition: {:?}", alert.action.kind);
        };
        let text = &sql["ALTER ALERT a MODIFY CONDITION ".len()..sql.len() - 1];
        assert_eq!(
            &sql[condition_span.start as usize..condition_span.end as usize],
            text,
            "{sql}"
        );
        assert_eq!(condition.is_some(), parsed, "{sql}");
        if let Some(condition) = condition {
            assert_eq!(condition.span(), *condition_span, "{sql}");
        }
    }
}

#[test]
fn a_create_function_states_what_a_call_returns() {
    use lexega_syntax::ast::{AstFunctionReturns as R, AstStmt};
    use lexega_syntax::dialect::{bigquery, databricks, mssql, mysql, postgres, snowflake};
    let cases = [
        (
            postgres(),
            "CREATE FUNCTION f(x int) RETURNS SETOF int LANGUAGE sql AS $$ SELECT 1 $$",
            R::Set,
        ),
        (
            postgres(),
            "CREATE FUNCTION f(x int) RETURNS setof record AS $$ SELECT 1 $$ LANGUAGE sql",
            R::Set,
        ),
        (
            postgres(),
            "CREATE OR REPLACE FUNCTION s.f(x int) RETURNS TABLE (n int, m text) \
             LANGUAGE sql AS $$ SELECT 1, 'a' $$",
            R::Table,
        ),
        (
            postgres(),
            "CREATE FUNCTION f(x int) RETURNS int LANGUAGE sql IMMUTABLE AS $$ SELECT x $$",
            R::Scalar,
        ),
        (
            mssql(),
            "CREATE FUNCTION dbo.f(@x int) RETURNS TABLE AS RETURN (SELECT 1 AS n)",
            R::Table,
        ),
        (
            mssql(),
            "CREATE FUNCTION dbo.f(@x int) RETURNS @t TABLE (n int) AS BEGIN \
             INSERT @t VALUES (1); RETURN; END",
            R::Table,
        ),
        (
            mssql(),
            "CREATE FUNCTION dbo.f(@x int) RETURNS int WITH SCHEMABINDING AS BEGIN RETURN @x; END",
            R::Scalar,
        ),
        (
            snowflake(),
            "CREATE OR REPLACE FUNCTION f(x NUMBER) RETURNS TABLE (n NUMBER) AS 'SELECT x AS n'",
            R::Table,
        ),
        (
            snowflake(),
            "CREATE FUNCTION f(x NUMBER) RETURNS NUMBER NOT NULL LANGUAGE SQL AS 'x + 1'",
            R::Scalar,
        ),
        (
            bigquery(),
            "CREATE TEMP FUNCTION f(x INT64) RETURNS INT64 AS (x + 1)",
            R::Scalar,
        ),
        (
            databricks(),
            "CREATE FUNCTION f(x INT) RETURNS TABLE (n INT) RETURN SELECT x AS n",
            R::Table,
        ),
        (
            mysql(),
            "CREATE FUNCTION f(x INT) RETURNS INT DETERMINISTIC RETURN x + 1",
            R::Scalar,
        ),
    ];
    for (dialect, sql, returns) in cases {
        let script = lexega_syntax::parse_sql_with_dialect(sql, dialect.as_ref()).expect("parses");
        let [AstStmt::CreateFunction(function)] = script.stmts.as_slice() else {
            panic!("{sql}: {:?}", script.stmts);
        };
        assert_eq!(
            function.returns.map(|clause| clause.kind),
            Some(returns),
            "{sql}"
        );
    }
}

#[test]
fn a_create_function_without_returns_ends_where_it_ends() {
    use lexega_syntax::ast::AstStmt;
    use lexega_syntax::dialect::{bigquery, databricks, postgres};
    let cases = [
        (
            bigquery(),
            "CREATE TEMP FUNCTION f(x INT64) AS (x + 1)",
            "DELETE FROM ds.t WHERE TRUE",
        ),
        (
            postgres(),
            "CREATE FUNCTION f(x int, OUT a int, OUT b int) AS $$ SELECT 1, 2 $$ LANGUAGE sql",
            "DELETE FROM t WHERE TRUE",
        ),
        (
            postgres(),
            "CREATE FUNCTION f(OUT a int) LANGUAGE sql AS $$ SELECT 1 $$",
            "DELETE FROM t WHERE TRUE",
        ),
        (
            databricks(),
            "CREATE FUNCTION f(x INT) RETURN x + 1",
            "DELETE FROM t WHERE TRUE",
        ),
    ];
    let later = "CREATE FUNCTION g(x INT64) RETURNS INT64 AS (x)";
    for (dialect, function_sql, delete_sql) in cases {
        let sql = format!("{function_sql};\n{delete_sql};\n{later};");
        let script = lexega_syntax::parse_sql_with_dialect(&sql, dialect.as_ref()).expect("parses");
        let [AstStmt::CreateFunction(function), AstStmt::Delete(delete), AstStmt::CreateFunction(later_function)] =
            script.stmts.as_slice()
        else {
            panic!("{sql}: {:?}", script.stmts);
        };
        let text = |span: lexega_syntax::lexer::Span| &sql[span.start as usize..span.end as usize];
        assert_eq!(text(function.span), function_sql, "{sql}");
        assert_eq!(function.returns, None, "{sql}");
        assert_eq!(text(delete.span), delete_sql, "{sql}");
        let returns = later_function.returns.expect("RETURNS is written");
        assert_eq!(text(returns.span), "RETURNS INT64", "{sql}");
        assert_eq!(
            returns.kind,
            lexega_syntax::ast::AstFunctionReturns::Scalar,
            "{sql}"
        );
        let config = lexega_syntax::FormatterConfig {
            dialect: dialect.clone(),
            ..Default::default()
        };
        let formatted = lexega_syntax::format_sql_with_config(&sql, &config).expect("formats");
        lexega_syntax::verify_formatting_safe_with_dialect(&sql, &formatted, &*dialect)
            .unwrap_or_else(|e| panic!("{sql} -> {formatted}: {e}"));
    }
}

#[test]
fn password_literal_spans_keep_the_whole_literal() {
    use lexega_syntax::ast::AstStmt;
    use lexega_syntax::lexer::Span;
    fn literal_spans(stmt: &AstStmt) -> &[Span] {
        if let AstStmt::MssqlKeyManagement(s) = stmt {
            &s.password_literal_spans
        } else if let AstStmt::MssqlKeyBackup(s) = stmt {
            &s.password_literal_spans
        } else if let AstStmt::MssqlAddSignature(s) = stmt {
            &s.password_literal_spans
        } else if let AstStmt::MssqlAlterServiceMasterKey(s) = stmt {
            &s.password_literal_spans
        } else {
            panic!("not a T-SQL key statement: {stmt:?}");
        }
    }
    let mssql = lexega_syntax::dialect::mssql();
    for (sql, written) in [
        (
            "OPEN SYMMETRIC KEY k DECRYPTION BY PASSWORD = N'a''b', PASSWORD = 'c'",
            &["N'a''b'", "'c'"][..],
        ),
        (
            "BACKUP MASTER KEY TO FILE = 'f' ENCRYPTION BY PASSWORD = 'p'",
            &["'p'"],
        ),
        (
            "ADD SIGNATURE TO p BY CERTIFICATE c WITH PASSWORD = 'p'",
            &["'p'"],
        ),
        (
            "ALTER SERVICE MASTER KEY WITH NEW_ACCOUNT = 'a', NEW_PASSWORD = 'p'",
            &["'p'"],
        ),
    ] {
        let script = lexega_syntax::parse_sql_with_dialect(sql, &*mssql).expect("parses");
        let [stmt] = script.stmts.as_slice() else {
            panic!("{sql}: {:?}", script.stmts);
        };
        let recorded: Vec<&str> = literal_spans(stmt)
            .iter()
            .map(|s| &sql[s.start as usize..s.end as usize])
            .collect();
        assert_eq!(recorded, written, "{sql}");
    }
    // A rendered placeholder is no literal the author wrote; it is still masked.
    let ph = "__LEXEGA_PH_000001__";
    for (sql, written) in [
        (
            format!("OPEN SYMMETRIC KEY k DECRYPTION BY PASSWORD = '{ph}', PASSWORD = 'c'"),
            &["'c'"][..],
        ),
        (
            format!("BACKUP MASTER KEY TO FILE = 'f' ENCRYPTION BY PASSWORD = '{ph}'"),
            &[],
        ),
        (
            format!("ADD SIGNATURE TO p BY CERTIFICATE c WITH PASSWORD = '{ph}'"),
            &[],
        ),
        (
            format!("ALTER SERVICE MASTER KEY WITH NEW_ACCOUNT = 'a', NEW_PASSWORD = '{ph}'"),
            &[],
        ),
    ] {
        let at = sql.find(ph).expect("placeholder written") as u32;
        let placeholder = Span {
            start: at,
            end: at + ph.len() as u32,
        };
        let tokens = lexega_syntax::lexer::tokenize_with_dialect(&sql, &*mssql).tokens;
        let script = lexega_syntax::parser::try_parse_script_with_placeholders(
            &sql,
            &tokens,
            Some(&*mssql),
            &[placeholder],
        )
        .expect("parses");
        let [stmt] = script.stmts.as_slice() else {
            panic!("{sql}: {:?}", script.stmts);
        };
        let recorded: Vec<&str> = literal_spans(stmt)
            .iter()
            .map(|s| &sql[s.start as usize..s.end as usize])
            .collect();
        assert_eq!(recorded, written, "{sql}");
        assert!(script.redaction_spans.contains(&placeholder), "{sql}");
    }
}

#[test]
fn security_object_literal_overlapping_a_placeholder_is_no_literal() {
    use lexega_syntax::ast::AstStmt;
    use lexega_syntax::lexer::Span;
    let mssql = lexega_syntax::dialect::mssql();
    // The literals each statement records: (password, secret).
    let literals = |sql: &str, placeholders: &[Span]| {
        let tokens = lexega_syntax::lexer::tokenize_with_dialect(sql, &*mssql).tokens;
        let script = lexega_syntax::parser::try_parse_script_with_placeholders(
            sql,
            &tokens,
            Some(&*mssql),
            placeholders,
        )
        .expect("parses");
        let [AstStmt::MssqlSecurityObjectDdl(s)] = script.stmts.as_slice() else {
            panic!("{sql}: {:?}", script.stmts);
        };
        let text =
            |span: Option<Span>| span.map(|s| sql[s.start as usize..s.end as usize].to_string());
        (
            text(s.password_literal),
            text(s.secret_literal),
            script.redaction_spans,
        )
    };
    let ph = "__LEXEGA_PH_000001__";
    for sql in [
        format!("CREATE MASTER KEY ENCRYPTION BY PASSWORD = '{ph}'"),
        format!("CREATE CREDENTIAL c WITH IDENTITY = 'u', SECRET = '{ph}'"),
    ] {
        let at = sql.find(ph).expect("placeholder written") as u32;
        let placeholder = Span {
            start: at,
            end: at + ph.len() as u32,
        };
        let (password, secret, redacted) = literals(&sql, &[placeholder]);
        assert_eq!((password, secret), (None, None), "{sql}");
        assert!(redacted.contains(&placeholder), "{sql}");
    }
    assert_eq!(
        literals("CREATE MASTER KEY ENCRYPTION BY PASSWORD = 'p'", &[]).0,
        Some("p".to_string())
    );
    assert_eq!(
        literals("CREATE CREDENTIAL c WITH IDENTITY = 'u', SECRET = 's'", &[]).1,
        Some("s".to_string())
    );
}

#[test]
fn drop_database_encryption_key_reads_as_its_own_kind_and_round_trips() {
    use lexega_syntax::ast::types::AstMssqlSecurityObjectKind;
    use lexega_syntax::AstStmt;
    let mssql = lexega_syntax::dialect::mssql();
    for src in [
        "DROP DATABASE ENCRYPTION KEY;",
        "drop database encryption key\nSELECT 1",
    ] {
        let script = lexega_syntax::parse_sql_with_dialect(src, &*mssql).expect("parses");
        assert!(
            matches!(
                script.stmts.first(),
                Some(AstStmt::MssqlSecurityObjectDdl(s))
                    if s.object == AstMssqlSecurityObjectKind::DatabaseEncryptionKey
                        && s.name_span.is_none()
            ),
            "{src}: {:?}",
            script.stmts
        );
        let config = lexega_syntax::FormatterConfig {
            dialect: mssql.clone(),
            ..Default::default()
        };
        let formatted = lexega_syntax::format_sql_with_config(src, &config).expect("formats");
        lexega_syntax::verify_formatting_safe_with_dialect(src, &formatted, &*mssql)
            .expect("formatting is safe");
    }
}

/// The statement `sql` parses to under the dialect named `name`.
fn only_statement(name: &str, sql: &str) -> lexega_syntax::AstStmt {
    let dialect = lexega_syntax::dialect_from_name(name).expect("known dialect");
    let mut script = lexega_syntax::parse_sql_with_dialect(sql, dialect.as_ref()).expect("parses");
    assert_eq!(script.stmts.len(), 1, "{sql}");
    script.stmts.remove(0)
}

/// The text `sql` writes at `span`.
fn written(sql: &str, span: lexega_syntax::Span) -> &str {
    &sql[span.start as usize..span.end as usize]
}

#[test]
fn a_definitions_expressions_are_read_as_expressions() {
    use lexega_syntax::AstStmt;
    let sql = "CREATE TABLE app.t (a text NOT NULL DEFAULT 'x', \
               b int GENERATED ALWAYS AS (c + 1) STORED, c int CHECK (c > 0), \
               CONSTRAINT k CHECK (a <> 'v'), \
               EXCLUDE USING gist (f(a) WITH =, c WITH <>) WHERE (c > 1));";
    let AstStmt::CreateTable(create) = only_statement("postgresql", sql) else {
        panic!("{sql}");
    };
    let [a, b, c] = create.columns.as_slice() else {
        panic!("{sql}: {} columns", create.columns.len());
    };
    let span = |expr: &Option<Box<lexega_syntax::AstExpr>>| {
        expr.as_ref().map(|expr| written(sql, expr.span()))
    };
    assert_eq!(span(&a.default_expr), Some("'x'"));
    assert_eq!(span(&b.virtual_expr), Some("(c + 1)"));
    assert_eq!(span(&c.check_expr), Some("(c > 0)"));
    let [check, exclude] = create.constraints.as_slice() else {
        panic!("{sql}: {} constraints", create.constraints.len());
    };
    let texts = |exprs: &Option<Vec<lexega_syntax::AstExpr>>| {
        exprs.as_ref().map(|exprs| {
            exprs
                .iter()
                .map(|e| written(sql, e.span()))
                .collect::<Vec<_>>()
        })
    };
    assert_eq!(texts(&check.expressions), Some(vec!["(a <> 'v')"]));
    assert_eq!(
        texts(&exclude.expressions),
        Some(vec!["f(a)", "c", "(c > 1)"])
    );

    let sql = "CREATE FUNCTION g(p text DEFAULT set_pwd_f('x'), q int = 2) RETURNS int \
               LANGUAGE sql AS 'SELECT 1';";
    let AstStmt::CreateFunction(function) = only_statement("postgresql", sql) else {
        panic!("{sql}");
    };
    let defaults: Vec<Option<&str>> = function
        .params
        .iter()
        .map(|param| param.default_expr.as_ref().map(|e| written(sql, e.span())))
        .collect();
    assert_eq!(defaults, [Some("set_pwd_f('x')"), Some("2")]);

    let sql = "ALTER TABLE app.t ALTER COLUMN c SET DEFAULT nextval('app.seq');";
    let AstStmt::AlterTable(alter) = only_statement("postgresql", sql) else {
        panic!("{sql}");
    };
    let read = alter.actions.iter().find_map(|action| {
        let lexega_syntax::ast::AstAlterTableActionKind::AlterColumnSetDefault { expr, .. } =
            &action.kind
        else {
            return None;
        };
        expr.as_ref().map(|e| written(sql, e.span()))
    });
    assert_eq!(read, Some("nextval('app.seq')"));
}

#[test]
fn a_definition_whose_expressions_are_read_formats_as_written() {
    use lexega_syntax::{format_sql_with_config, verify_formatting_safe_with_dialect};
    for (name, sql) in [
        (
            "postgresql",
            "CREATE TABLE app.t (a text NOT NULL DEFAULT 'x', b int GENERATED ALWAYS AS (c + 1) STORED, \
             c int CHECK (c > 0), CONSTRAINT k CHECK (a <> 'v'), \
             EXCLUDE USING gist (f(a) WITH =) WHERE (c > 1));",
        ),
        (
            "postgresql",
            "CREATE FUNCTION g(p text DEFAULT set_pwd_f('x')) RETURNS int LANGUAGE sql AS 'SELECT 1';",
        ),
        (
            "postgresql",
            "ALTER TABLE app.t ADD COLUMN d text DEFAULT 'y', ALTER COLUMN c SET DEFAULT 0;",
        ),
        (
            "mssql",
            "ALTER TABLE dbo.t ADD CONSTRAINT df DEFAULT N'z' FOR c;",
        ),
    ] {
        let dialect = lexega_syntax::dialect_from_name(name).expect("known dialect");
        let config = lexega_syntax::FormatterConfig {
            dialect: dialect.clone(),
            ..Default::default()
        };
        let formatted = format_sql_with_config(sql, &config).expect("formats");
        verify_formatting_safe_with_dialect(sql, &formatted, dialect.as_ref())
            .unwrap_or_else(|e| panic!("{sql}\n{formatted}\n{e}"));
    }
}

#[test]
fn a_column_default_a_tsql_constraint_names_formats_and_is_read() {
    use lexega_syntax::{format_sql_with_config, verify_formatting_safe_with_dialect, AstStmt};
    let sql = "CREATE TABLE dbo.t (a int CONSTRAINT df DEFAULT (0), b int NOT NULL);";
    let dialect = lexega_syntax::dialect_from_name("mssql").expect("known dialect");
    let config = lexega_syntax::FormatterConfig {
        dialect: dialect.clone(),
        ..Default::default()
    };
    let formatted = format_sql_with_config(sql, &config).expect("formats");
    verify_formatting_safe_with_dialect(sql, &formatted, dialect.as_ref())
        .unwrap_or_else(|e| panic!("{sql}\n{formatted}\n{e}"));
    let AstStmt::CreateTable(create) = only_statement("mssql", sql) else {
        panic!("{sql}");
    };
    let a = &create.columns[0];
    assert_eq!(
        a.default_expr
            .as_ref()
            .map(|expr| written(sql, expr.span())),
        Some("(0)")
    );
}

#[test]
fn a_secret_written_as_a_variable_is_its_place_and_not_its_value() {
    for (name, sql, place) in [
        ("mssql", "ALTER LOGIN app WITH PASSWORD = @pw;", "@pw"),
        ("snowflake", "ALTER USER u SET PASSWORD = :pw;", ":pw"),
    ] {
        let dialect = lexega_syntax::dialect_from_name(name).expect("known dialect");
        let script = lexega_syntax::parse_sql_with_dialect(sql, dialect.as_ref()).expect("parses");
        let places: Vec<&str> = script
            .secret_places
            .iter()
            .map(|s| written(sql, *s))
            .collect();
        assert_eq!(places, [place], "{sql}");
        assert!(script.redaction_spans.is_empty(), "{sql}");
    }
}

#[test]
fn a_template_block_word_is_a_keyword_only_as_a_tags_first_word() {
    use lexega_syntax::lexer::{tokenize, TokenKind};
    let kinds = |sql: &str| -> Vec<TokenKind> {
        tokenize(sql)
            .tokens
            .into_iter()
            .map(|token| token.kind)
            .collect()
    };
    let blocks = kinds("{% filter upper %}c{% endfilter %}{% call m() %}d{% endcall %}");
    for keyword in [
        TokenKind::JinjaFilter,
        TokenKind::JinjaEndFilter,
        TokenKind::JinjaCall,
        TokenKind::JinjaEndCall,
    ] {
        assert!(blocks.contains(&keyword), "{keyword:?}: {blocks:?}");
    }
    // A variable, an attribute or an argument of that name is a name.
    for sql in [
        "{% set filter = 1 %}",
        "{{ x.filter }}",
        "{% if call %}a{% endif %}",
        "{% do adapter.call(filter) %}",
    ] {
        let read = kinds(sql);
        assert!(
            !read.iter().any(|kind| matches!(
                kind,
                TokenKind::JinjaFilter
                    | TokenKind::JinjaEndFilter
                    | TokenKind::JinjaCall
                    | TokenKind::JinjaEndCall
            )),
            "{sql}: {read:?}"
        );
    }
}

#[test]
fn a_template_block_that_holds_or_passes_on_its_text_is_read() {
    use lexega_syntax::ast::TemplateBlockHolds;
    let sql = "{% set q %}select 'a'{% endset %}\n\
               {% set x = 'b' %}\n\
               {%- filter upper -%}c{%- endfilter -%}\n\
               {% call statement('s') %}select 'd'{% endcall %}\n\
               {% set open %}e";
    let script = lexega_syntax::parse_sql(sql).expect("parses");
    let blocks: Vec<(&str, TemplateBlockHolds)> = script
        .template_blocks
        .iter()
        .map(|block| (written(sql, block.body), block.holds))
        .collect();
    assert_eq!(
        blocks,
        [
            ("select 'a'", TemplateBlockHolds::Value),
            ("c", TemplateBlockHolds::Value),
            ("select 'd'", TemplateBlockHolds::Caller),
            ("e", TemplateBlockHolds::Value),
        ],
        "{sql}"
    );
}
