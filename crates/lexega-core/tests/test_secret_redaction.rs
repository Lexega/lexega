// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Secret-redaction invariant: a credential value (password, credential key,
//! secret string) must never appear in any source-quoting output surface
//! (finding preview / evidence / serialized report). The facts layer is
//! least-leak; this verifies the evidence layer honors the same rule.

use lexega_core::analyzer::RuleMatch;
use lexega_core::api::analyze_risk;
use lexega_core::redact_secrets_for_display;
use std::collections::HashSet;

/// Serialize the full analysis report — this is the shape that gets written to
/// JSON / SARIF / dashboards, so a secret here is a real leak.
fn report_json(sql: &str) -> String {
    let report = analyze_risk(sql).expect("should analyze");
    serde_json::to_string(&report).expect("report serializes")
}

fn rule_ids(sql: &str) -> HashSet<String> {
    analyze_risk(sql)
        .expect("should analyze")
        .findings
        .iter()
        .map(|s| match s {
            RuleMatch::Analysis(g) => g.matched_rule.clone(),
        })
        .collect()
}

#[test]
fn test_user_password_redacted() {
    let json = report_json("CREATE USER bob PASSWORD = 'hunter2_topsecret';");
    assert!(
        !json.contains("hunter2_topsecret"),
        "password leaked into report"
    );
}

#[test]
fn test_secret_object_password_redacted() {
    let json = report_json(
        "CREATE SECRET s TYPE = PASSWORD USERNAME = 'u' PASSWORD = 'sneaky_secret_val';",
    );
    assert!(
        !json.contains("sneaky_secret_val"),
        "secret leaked into report"
    );
}

#[test]
fn test_managed_account_admin_password_redacted() {
    let json = report_json(
        "CREATE MANAGED ACCOUNT ra ADMIN_NAME = u ADMIN_PASSWORD = 'manacct_secret_x' TYPE = READER;",
    );
    assert!(!json.contains("manacct_secret_x"), "admin password leaked");
}

#[test]
fn test_create_account_admin_password_redacted() {
    let json = report_json(
        "CREATE ACCOUNT acc ADMIN_NAME = u ADMIN_PASSWORD = 'orgacct_secret_y' EDITION = STANDARD;",
    );
    assert!(!json.contains("orgacct_secret_y"), "admin password leaked");
}

#[test]
fn test_stage_credentials_redacted() {
    let json = report_json(
        "ALTER STAGE st SET CREDENTIALS = (AWS_KEY_ID = 'AKIA1' AWS_SECRET_KEY = 'stagecred_secret_z');",
    );
    assert!(
        !json.contains("stagecred_secret_z"),
        "stage credential leaked"
    );
}

#[test]
fn test_partly_templated_secret_redacted() {
    use lexega_core::analyzer::AnalysisConfig;
    use lexega_core::api::analyze_risk_with_policy_config;
    use lexega_core::dialect;

    let mut leaks = Vec::new();
    for (dialect, sql) in [
        (
            dialect::snowflake(),
            "CREATE USER u PASSWORD = 'tmplpart_a{{ var(\"x\") }}';",
        ),
        (
            dialect::mssql(),
            "CREATE MASTER KEY ENCRYPTION BY PASSWORD = 'tmplpart_a{{ var(\"x\") }}';",
        ),
        (
            dialect::bigquery(),
            "EXPORT DATA OPTIONS(uri='gs://b/*', format='CSV', \
             password='tmplpart_a{{ var(\"x\") }}tmplpart_b') AS SELECT 1",
        ),
        // A doubled quote before a template does not close the string.
        (
            dialect::snowflake(),
            "CREATE USER u PASSWORD = 'tmplpart_a{{ a }}x''{{ b }}tmplpart_b';",
        ),
        (
            dialect::mssql(),
            "OPEN SYMMETRIC KEY k DECRYPTION BY PASSWORD = 'tmplpart_a{{ a }}x''{{ b }}tmplpart_b';",
        ),
        // A template comment is part of the string.
        (
            dialect::snowflake(),
            "CREATE USER u PASSWORD = 'tmplpart_a{{ a }}x''{# c #}tmplpart_b';",
        ),
        (
            dialect::snowflake(),
            "CREATE USER u PASSWORD = 'tmplpart_a{# c #}tmplpart_b';",
        ),
        (
            dialect::snowflake(),
            "CREATE USER u PASSWORD = 'tmplpart_a{{ a }}tmplpart_b{# c #}tmplpart_c';",
        ),
        (
            dialect::mssql(),
            "CREATE MASTER KEY ENCRYPTION BY PASSWORD = 'tmplpart_a{# c #}tmplpart_b';",
        ),
        // MySQL joins strings written one after another into one password.
        (
            dialect::mysql(),
            "CREATE USER 'u'@'h' IDENTIFIED BY 'tmplpart_a{{ a }}' 'tmplpart_b';",
        ),
        (
            dialect::mysql(),
            "CREATE USER 'u'@'h' IDENTIFIED BY 'tmplpart_a' 'tmplpart_b{{ a }}' 'tmplpart_c';",
        ),
        // A prefix the lexer gives as a word before the string.
        (
            dialect::mysql(),
            "CREATE USER 'u'@'h' IDENTIFIED BY N'tmplpart_a{{ a }}tmplpart_b';",
        ),
        (
            dialect::mysql(),
            "CREATE USER 'u'@'h' IDENTIFIED BY N'tmplpart_a{# c #}tmplpart_b';",
        ),
        (
            dialect::mysql(),
            "CREATE USER 'u'@'h' IDENTIFIED BY N'tmplpart_a{{ a }}' 'tmplpart_b';",
        ),
        (
            dialect::mysql(),
            "CREATE USER 'u'@'h' IDENTIFIED BY X'tmplpart_a{{ a }}tmplpart_b';",
        ),
        (
            dialect::mysql(),
            "CREATE USER 'u'@'h' IDENTIFIED BY _utf8mb4'tmplpart_a{{ a }}' 'tmplpart_b';",
        ),
        (
            dialect::bigquery(),
            "EXPORT DATA OPTIONS(uri='gs://b/*', format='CSV', \
             password=r'tmplpart_a{{ a }}tmplpart_b') AS SELECT 1",
        ),
        (
            dialect::bigquery(),
            "EXPORT DATA OPTIONS(uri='gs://b/*', format='CSV', \
             password=rb'tmplpart_a{{ a }}tmplpart_b') AS SELECT 1",
        ),
        (
            dialect::postgres(),
            "CREATE USER u PASSWORD U&'tmplpart_a{{ a }}tmplpart_b';",
        ),
        (
            dialect::postgres(),
            "CREATE USER u PASSWORD E'tmplpart_a{{ a }}tmplpart_b';",
        ),
        (
            dialect::mssql(),
            "CREATE MASTER KEY ENCRYPTION BY PASSWORD = N'tmplpart_a{{ a }}tmplpart_b';",
        ),
        // Strings written one after another: PostgreSQL and Redshift join
        // them across a newline, Snowflake and T-SQL do not.
        (
            dialect::postgres(),
            "CREATE USER u PASSWORD 'tmplpart_a{{ a }}'\n'tmplpart_b';",
        ),
        (
            dialect::postgres(),
            "CREATE USER u PASSWORD 'tmplpart_a'\n'tmplpart_b{{ a }}';",
        ),
        (
            dialect::snowflake(),
            "CREATE USER u PASSWORD = 'tmplpart_a{{ a }}' 'tmplpart_b';",
        ),
        (
            dialect::redshift(),
            "CREATE USER u PASSWORD 'tmplpart_a{{ a }}'\n'tmplpart_b';",
        ),
        (
            dialect::mssql(),
            "CREATE MASTER KEY ENCRYPTION BY PASSWORD = 'tmplpart_a{{ a }}'\n'tmplpart_b';",
        ),
        // A string nothing closes runs to the end of the text.
        (
            dialect::snowflake(),
            "CREATE USER u PASSWORD = 'tmplpart_a{# c tmplpart_b';",
        ),
        (
            dialect::snowflake(),
            "CREATE USER u PASSWORD = 'tmplpart_a{{ a tmplpart_b';",
        ),
        (
            dialect::snowflake(),
            "CREATE USER u PASSWORD = 'tmplpart_a{% a tmplpart_b';",
        ),
        (
            dialect::mssql(),
            "CREATE MASTER KEY ENCRYPTION BY PASSWORD = 'tmplpart_a{{ a tmplpart_b';",
        ),
        (
            dialect::mssql(),
            "CREATE LOGIN l WITH PASSWORD = N'tmplpart_a tmplpart_b",
        ),
        (
            dialect::mysql(),
            "SET PASSWORD = 'tmplpart_a' '{{ x }}tmplpart_b';",
        ),
    ] {
        let cfg = AnalysisConfig {
            dialect: Some(dialect),
            ..Default::default()
        };
        let report = analyze_risk_with_policy_config(sql, &cfg).expect("should analyze");
        let json = serde_json::to_string(&report).expect("report serializes");
        if json.contains("tmplpart") {
            leaks.push(sql);
        }
    }
    assert!(
        leaks.is_empty(),
        "secrets not masked:\n{}",
        leaks.join("\n")
    );
}

#[test]
fn test_partly_templated_tsql_key_password_redacted() {
    use lexega_core::analyzer::AnalysisConfig;
    use lexega_core::api::analyze_risk_with_policy_config;
    use lexega_core::dialect;

    let pw = "'tmplkey_a{{ var(\"x\") }}'";
    let mut leaks = Vec::new();
    for sql in [
        format!("OPEN SYMMETRIC KEY k DECRYPTION BY PASSWORD = {pw}"),
        format!("BACKUP MASTER KEY TO FILE = 'f' ENCRYPTION BY PASSWORD = {pw}"),
        format!("ADD SIGNATURE TO p BY CERTIFICATE c WITH PASSWORD = {pw}"),
        format!("ALTER SERVICE MASTER KEY WITH NEW_ACCOUNT = 'a', NEW_PASSWORD = {pw}"),
    ] {
        let cfg = AnalysisConfig {
            dialect: Some(dialect::mssql()),
            ..Default::default()
        };
        let report = analyze_risk_with_policy_config(&sql, &cfg).expect("should analyze");
        let json = serde_json::to_string(&report).expect("report serializes");
        if json.contains("tmplkey") {
            leaks.push(sql);
        }
    }
    assert!(
        leaks.is_empty(),
        "secrets not masked:\n{}",
        leaks.join("\n")
    );
}

#[test]
fn test_redshift_credentials_redacted() {
    use lexega_core::analyzer::AnalysisConfig;
    use lexega_core::api::analyze_risk_with_policy_config;
    use lexega_core::dialect;

    let mut leaks = Vec::new();
    for sql in [
        "UNLOAD ('SELECT 1') TO 's3://b/p' ACCESS_KEY_ID 'rscred_k' SECRET_ACCESS_KEY 'rscred_s';",
        "UNLOAD ('SELECT 1') TO 's3://b/p' ACCESS_KEY_ID 'k' \
         SECRET_ACCESS_KEY 'rscred_s{{ var(\"x\") }}' SESSION_TOKEN 'rscred_t';",
        "COPY t FROM 's3://b' CREDENTIALS 'aws_access_key_id=rscred_k;aws_secret_access_key=rscred_s';",
        "COPY t FROM 's3://b' CREDENTIALS 'aws_access_key_id=k;aws_secret_access_key=rscred_s{{ x }}';",
        "COPY t FROM 's3://b' CREDENTIALS 'aws_access_key_id=k;aws_secret_access_key=rscred_s{{ a }}x''{{ b }}rscred_t';",
        "COPY t FROM 's3://b' CREDENTIALS X'rscred_x';",
        "COPY t FROM 's3://b' CREDENTIALS E'aws_secret_access_key=rscred_e';",
    ] {
        let cfg = AnalysisConfig {
            dialect: Some(dialect::redshift()),
            ..Default::default()
        };
        let report = analyze_risk_with_policy_config(sql, &cfg).expect("should analyze");
        let json = serde_json::to_string(&report).expect("report serializes");
        if json.contains("rscred") {
            leaks.push(sql);
        }
    }
    assert!(
        leaks.is_empty(),
        "secrets not masked:\n{}",
        leaks.join("\n")
    );
}

#[test]
fn test_storage_credential_access_key_id_redacted() {
    let json = report_json(
        "CREATE STORAGE CREDENTIAL c CLOUDFLARE_API_TOKEN 'acct', 'sccred_keyid_v', 'sccred_secret_v';",
    );
    assert!(
        !json.contains("sccred_keyid_v"),
        "storage credential access key id leaked"
    );
    assert!(!json.contains("acct"), "what no walk shows is masked");
}

#[test]
fn test_storage_credential_secret_after_a_template_redacted() {
    for sql in [
        "CREATE STORAGE CREDENTIAL c CLOUDFLARE_API_TOKEN 'acct', '{{ var(\"k\") }}', 'sccred_secret_w';",
        "CREATE STORAGE CREDENTIAL c AZURE_SERVICE_PRINCIPAL 'tid', '{{ var(\"a\") }}', 'sccred_secret_w';",
    ] {
        let json = report_json(sql);
        assert!(
            !json.contains("sccred_secret_w"),
            "storage credential secret leaked: {sql}"
        );
    }
}

#[test]
fn test_redaction_is_targeted_not_blanket() {
    // The secret is masked, but a non-credential value on the same statement
    // (TYPE = READER) stays visible — redaction is targeted recognition, not a
    // blanket wipe.
    // TYPE first so it is within the 80-char preview window (the masked
    // password trails it).
    let json =
        report_json("CREATE MANAGED ACCOUNT ra TYPE = READER ADMIN_PASSWORD = 'secret_pw_neg';");
    assert!(!json.contains("secret_pw_neg"), "secret must be masked");
    assert!(json.contains("READER"), "non-secret TYPE must stay visible");
}

#[test]
fn test_redaction_does_not_suppress_findings() {
    // Masking the value must not change which rules fire — the hardcoded
    // password is still detected, just not reproduced.
    let rules = rule_ids("CREATE USER bob PASSWORD = 'hunter2_topsecret';");
    assert!(
        rules.contains("CRED-PWD-LEAK"),
        "the hardcoded-password finding must still fire, got {rules:?}"
    );
}

#[test]
fn test_redact_helper_prints_a_mask_of_one_length() {
    let sql = "CREATE USER bob PASSWORD = 'pw12345';";
    let redacted = redact_secrets_for_display(sql, &lexega_core::dialect::snowflake());
    // A masked value tells nothing of its length.
    assert_eq!(redacted, "CREATE USER bob PASSWORD = '****';");
    let longer = redact_secrets_for_display(
        "CREATE USER bob PASSWORD = 'a much longer password';\nSELECT 1;",
        &lexega_core::dialect::snowflake(),
    );
    assert_eq!(longer, "CREATE USER bob PASSWORD = '****';\nSELECT 1;");
    assert!(!redacted.contains("pw12345"), "secret masked");
    assert!(
        redacted.contains("CREATE USER bob PASSWORD"),
        "non-secret structure intact: {redacted}"
    );
}

#[test]
fn test_redact_helper_no_secret_is_identity() {
    let sql = "SELECT a, b FROM t WHERE c = 1;";
    assert_eq!(
        redact_secrets_for_display(sql, &lexega_core::dialect::snowflake()),
        sql
    );
}

#[test]
fn test_redaction_survives_jinja_rendering() {
    // Jinja ahead of the credential collapses on render (24 bytes here).
    // Redaction spans, the line index, and previews are all computed against
    // the rendered text the parser saw — so the output surface must quote
    // that same rendered text. Handing the pre-render source to the core
    // would shift the mask off the secret, leak Jinja text into previews,
    // and misreport line numbers.
    let json = report_json(
        "SELECT {% if true %}1{% endif %} FROM t;\nCREATE USER bob PASSWORD = 'jinja_secret_pw1';",
    );
    assert!(
        !json.contains("jinja_secret_pw1"),
        "password leaked into report for Jinja-bearing source"
    );

    let report: serde_json::Value = serde_json::from_str(&json).expect("report parses");
    let cred_finding = report["findings"]
        .as_array()
        .expect("findings array")
        .iter()
        .find(|s| s["matched_rule"] == "CRED-PWD-LEAK")
        .expect("hardcoded-password finding fires");
    let evidence = &cred_finding["evidence"][0];
    assert_eq!(
        evidence["line_number"], 2,
        "CREATE USER is on line 2 of the rendered SQL"
    );
    let preview = evidence["statement_preview"]
        .as_str()
        .expect("preview present");
    assert!(
        !preview.contains("{%"),
        "Jinja source text leaked into a rendered-space preview: {preview}"
    );
}

const TSQL_MARK: &str = "Zq9SecretMark";

/// T-SQL key, certificate, credential and login statements writing a
/// password or a secret, and the same clauses in text no statement reads.
fn tsql_secret_statements() -> Vec<String> {
    let m = TSQL_MARK;
    let next = "\nSELECT id FROM dbo.zz_src";
    vec![
        format!("CREATE MASTER KEY ENCRYPTION BY PASSWORD = '{m}'"),
        format!("CREATE MASTER KEY ENCRYPTION BY PASSWORD = '{m}';"),
        format!("CREATE MASTER KEY ENCRYPTION BY PASSWORD = '{m}'{next}"),
        format!("ALTER MASTER KEY REGENERATE WITH ENCRYPTION BY PASSWORD = '{m}'"),
        format!("ALTER MASTER KEY FORCE REGENERATE WITH ENCRYPTION BY PASSWORD = '{m}'"),
        format!("ALTER MASTER KEY ADD ENCRYPTION BY PASSWORD = '{m}'"),
        format!("ALTER MASTER KEY DROP ENCRYPTION BY PASSWORD = '{m}'"),
        format!("OPEN MASTER KEY DECRYPTION BY PASSWORD = '{m}'"),
        format!("BACKUP MASTER KEY TO FILE = 'f' ENCRYPTION BY PASSWORD = '{m}'"),
        format!(
            "RESTORE MASTER KEY FROM FILE = 'f' DECRYPTION BY PASSWORD = '{m}' \
             ENCRYPTION BY PASSWORD = '{m}2'"
        ),
        format!("BACKUP SERVICE MASTER KEY TO FILE = 'f' ENCRYPTION BY PASSWORD = '{m}'"),
        format!("RESTORE SERVICE MASTER KEY FROM FILE = 'f' DECRYPTION BY PASSWORD = '{m}'"),
        format!("CREATE CERTIFICATE c ENCRYPTION BY PASSWORD = '{m}' WITH SUBJECT = 's'"),
        format!(
            "CREATE CERTIFICATE c FROM FILE = 'c.cer' WITH PRIVATE KEY \
             (FILE = 'c.pvk', DECRYPTION BY PASSWORD = '{m}')"
        ),
        format!(
            "ALTER CERTIFICATE c WITH PRIVATE KEY \
             (DECRYPTION BY PASSWORD = 'Aa{m}', ENCRYPTION BY PASSWORD = '{m}')"
        ),
        format!(
            "BACKUP CERTIFICATE c TO FILE = 'c.cer' WITH PRIVATE KEY \
             (FILE = 'c.pvk', ENCRYPTION BY PASSWORD = '{m}')"
        ),
        format!("CREATE SYMMETRIC KEY k WITH ALGORITHM = AES_256 ENCRYPTION BY PASSWORD = '{m}'"),
        format!("ALTER SYMMETRIC KEY k ADD ENCRYPTION BY PASSWORD = '{m}'"),
        format!("OPEN SYMMETRIC KEY k DECRYPTION BY PASSWORD = '{m}'"),
        format!("OPEN SYMMETRIC KEY k DECRYPTION BY CERTIFICATE c WITH PASSWORD = '{m}'"),
        format!("CREATE ASYMMETRIC KEY k WITH ALGORITHM = RSA_2048 ENCRYPTION BY PASSWORD = '{m}'"),
        format!(
            "ALTER ASYMMETRIC KEY k WITH PRIVATE KEY \
             (DECRYPTION BY PASSWORD = 'Aa{m}', ENCRYPTION BY PASSWORD = '{m}')"
        ),
        format!("BACKUP ASYMMETRIC KEY k TO FILE = 'k.key' ENCRYPTION BY PASSWORD = '{m}'"),
        format!("CREATE CREDENTIAL zz_c WITH IDENTITY = 'u', SECRET = '{m}'"),
        format!("ALTER CREDENTIAL zz_c WITH IDENTITY = 'u', SECRET = '{m}'"),
        format!(
            "CREATE DATABASE SCOPED CREDENTIAL zz_c WITH IDENTITY = 'SHARED ACCESS SIGNATURE', \
             SECRET = '{m}'"
        ),
        format!("CREATE DATABASE SCOPED CREDENTIAL zz_c WITH IDENTITY = 'u', SECRET = '{m}'{next}"),
        format!("CREATE LOGIN zz WITH PASSWORD = '{m}'"),
        format!("ALTER LOGIN zz WITH PASSWORD = '{m}' OLD_PASSWORD = 'Aa{m}'"),
        format!("ALTER LOGIN zz ZZUNKNOWN WITH PASSWORD = '{m}'{next}"),
        format!("CREATE LOGIN zz WITH PASSWORD = 'pw' ZZUNKNOWN = 1, PASSWORD = '{m}'{next}"),
        format!("CREATE MASTER KEY ZZUNKNOWN ENCRYPTION BY PASSWORD = '{m}'{next}"),
        format!("CREATE CREDENTIAL zz_c ZZUNKNOWN IDENTITY = 'u', SECRET = '{m}'{next}"),
        format!(
            "BACKUP DATABASE zz_db TO DISK = 'a.bak' WITH PASSWORD = '{m}', \
             MEDIAPASSWORD = 'Aa{m}'{next}"
        ),
        format!("BACKUP LOG zz_db TO DISK = 'a.trn' WITH MEDIAPASSWORD = '{m}', INIT;"),
        format!(
            "RESTORE DATABASE zz_db FROM DISK = 'a.bak' WITH PASSWORD = '{m}', \
             MEDIAPASSWORD = 'Aa{m}', REPLACE{next}"
        ),
        format!("RESTORE LOG zz_db FROM DISK = 'a.trn' WITH PASSWORD = N'{m}';"),
        format!("RESTORE FILELISTONLY FROM DISK = 'a.bak' WITH MEDIAPASSWORD = '{m}'{next}"),
        format!("RESTORE HEADERONLY FROM DISK = 'a.bak' WITH PASSWORD = '{m}'"),
        format!("RESTORE VERIFYONLY FROM DISK = 'a.bak' WITH MEDIAPASSWORD = N'{m}';"),
        format!("RESTORE LABELONLY FROM DISK = 'a.bak' WITH MEDIAPASSWORD = '{m}'"),
        format!(
            "IF 1 = 1\nBEGIN\n    BACKUP DATABASE zz_db TO DISK = 'a.bak' WITH PASSWORD = '{m}'\
             {next}\nEND"
        ),
        format!(
            "CREATE PROCEDURE dbo.zz_p AS\nBEGIN\n    BACKUP LOG zz_db TO DISK = 'a.trn' \
             WITH MEDIAPASSWORD = '{m}'\nEND"
        ),
        format!(
            "CREATE SYMMETRIC KEY k WITH ALGORITHM = AES_256, KEY_SOURCE = '{m}', \
             IDENTITY_VALUE = 'Aa{m}' ENCRYPTION BY CERTIFICATE c{next}"
        ),
        format!(
            "CREATE SYMMETRIC KEY k WITH KEY_SOURCE = N'{m}', ALGORITHM = AES_256, \
             IDENTITY_VALUE = N'Aa{m}' ENCRYPTION BY PASSWORD = 'Bb{m}';"
        ),
    ]
}

#[test]
fn a_url_password_in_any_string_literal_is_masked() {
    use lexega_core::analyzer::AnalysisConfig;
    use lexega_core::api::analyze_risk_with_policy_config;
    use lexega_core::{dialect, parse_sql_with_dialect};

    let m = "Zq9UrlPwMark";
    let mut leaks = Vec::new();
    for (dialect, sql) in [
        (
            dialect::snowflake(),
            format!("COPY INTO 's3://AKIAX:wJalr/K7MDENG/{m}@bucket/p/' FROM t;"),
        ),
        (
            dialect::snowflake(),
            format!("COPY INTO 's3://u:pre?{m}#x@b/p/' FROM t;"),
        ),
        (
            dialect::redshift(),
            format!("UNLOAD ('SELECT * FROM t') TO 's3://AKIAX:w/{m}@bucket/o/' IAM_ROLE default;"),
        ),
        (
            dialect::bigquery(),
            format!("EXPORT DATA OPTIONS(uri='gs://u:pre/{m}@b/*.csv',format='CSV') AS SELECT 1;"),
        ),
        (
            dialect::databricks(),
            format!("COMMENT ON STORAGE CREDENTIAL sc IS 'jdbc://a:{m}@h';"),
        ),
        (
            dialect::databricks(),
            format!(
                "CREATE EXTERNAL LOCATION el URL 'abfss://a:{m}@h/p' WITH (STORAGE CREDENTIAL sc);"
            ),
        ),
        (
            dialect::snowflake(),
            format!(
                "CREATE EXTERNAL TABLE et LOCATION=@s COMMENT='pg://a:{m}@h' FILE_FORMAT=(TYPE=CSV);"
            ),
        ),
        (
            dialect::snowflake(),
            format!("COPY INTO @s FROM (SELECT 'ftp://a:{m}@h' FROM t);"),
        ),
        (
            dialect::snowflake(),
            format!("SELECT * FROM t WHERE c = 'mysql://a:{m}@d/x';"),
        ),
        (
            dialect::postgres(),
            format!("SELECT dblink_exec('pg://a:{m}@h/db','DELETE FROM t');"),
        ),
        (
            dialect::postgres(),
            format!("COMMENT ON TABLE t IS $$see pg://a:{m}@h$$;"),
        ),
        (
            dialect::postgres(),
            format!("COMMENT ON TABLE t IS $c$see pg://a:{m}@h$c$;"),
        ),
        (
            dialect::redshift(),
            format!("COMMENT ON TABLE t IS $$see pg://a:{m}@h$$;"),
        ),
        (
            dialect::snowflake(),
            format!("COMMENT ON TABLE t IS $$see pg://a:{m}@h$$;"),
        ),
        (
            dialect::snowflake(),
            format!(
                "CREATE EXTERNAL TABLE et LOCATION=@s COMMENT=$$pg://a:{m}@h$$ FILE_FORMAT=(TYPE=CSV);"
            ),
        ),
        (
            dialect::snowflake(),
            format!("COPY INTO @st FROM (SELECT $$ftp://a:{m}@h$$ AS u FROM t);"),
        ),
    ] {
        let script = parse_sql_with_dialect(&sql, dialect.as_ref()).expect("parses");
        for (at, _) in sql.match_indices(m) {
            let (start, end) = (at as u32, (at + m.len()) as u32);
            if !script
                .redaction_spans
                .iter()
                .any(|s| s.start <= start && end <= s.end)
            {
                leaks.push(format!("not masked at byte {at}: {sql}"));
            }
        }
        let cfg = AnalysisConfig {
            dialect: Some(dialect),
            ..Default::default()
        };
        let report = analyze_risk_with_policy_config(&sql, &cfg).expect("should analyze");
        let json = serde_json::to_string(&report).expect("report serializes");
        if json.contains(&m[..6]) {
            leaks.push(format!("in the report: {sql}"));
        }
    }
    assert!(
        leaks.is_empty(),
        "secrets not masked:\n{}",
        leaks.join("\n")
    );
}

#[test]
fn a_connection_string_password_in_any_string_literal_is_masked() {
    use lexega_core::analyzer::AnalysisConfig;
    use lexega_core::api::analyze_risk_with_policy_config;
    use lexega_core::{dialect, parse_sql_with_dialect};

    let m = "Zq9CsPwMark";
    let mut leaks = Vec::new();
    for (name, sql) in [
        ("postgres", format!("UPDATE t SET c = 'Server=h;Password={m};';")),
        ("postgres", format!("UPDATE t SET c = $$password={m}$$;")),
        ("postgres", format!("UPDATE t SET c = $c$Uid=u; Pwd = \"{m};x\"$c$;")),
        (
            "postgres",
            format!("CREATE FUNCTION f() RETURNS text AS $$ SELECT 'Server=h;Password={m};' $$ LANGUAGE sql;"),
        ),
        (
            "postgres",
            format!("CREATE PROCEDURE p() AS $b$ BEGIN PERFORM 'pwd={{{m}}}'; END $b$ LANGUAGE plpgsql;"),
        ),
        ("postgres", format!("DO $$ BEGIN PERFORM 'password={m}'; END $$;")),
        ("postgres", format!("DO 'BEGIN PERFORM ''Pwd={m}''; END';")),
        (
            "postgres",
            format!("CREATE FUNCTION f() RETURNS text AS 'SELECT ''password={m}''' LANGUAGE sql;"),
        ),
        (
            "snowflake",
            format!("CREATE FUNCTION f() RETURNS TEXT AS 'SELECT ''Server=h;Password={m};''';"),
        ),
        (
            "redshift",
            format!("CREATE PROCEDURE p() AS $$ BEGIN PERFORM 'Pwd={m}'; END $$ LANGUAGE plpgsql;"),
        ),
        ("snowflake", format!("UPDATE t SET c = $$Server=h;Password={m};$$;")),
        (
            "snowflake",
            format!("CREATE PROCEDURE p() RETURNS TEXT LANGUAGE SQL AS $$ BEGIN RETURN 'pwd={m};'; END $$;"),
        ),
        (
            "snowflake",
            format!("CREATE PROCEDURE p() RETURNS TEXT LANGUAGE SQL AS 'BEGIN RETURN ''pwd={m}''; END';"),
        ),
        ("databricks", format!("CREATE FUNCTION f() RETURNS STRING RETURN 'password={m}';")),
        ("mssql", format!("CREATE PROCEDURE p AS BEGIN SELECT N'Server=h;Password={m};' END")),
        (
            "mssql",
            format!("CREATE TRIGGER tr ON t AFTER INSERT AS BEGIN UPDATE t SET c = 'pwd={m};uid=x' END"),
        ),
        ("mysql", format!("CREATE PROCEDURE p() BEGIN SELECT 'Server=h;Password={m};'; END")),
        (
            "mysql",
            format!("CREATE TRIGGER tr BEFORE INSERT ON t FOR EACH ROW BEGIN SET NEW.c = 'password={m}'; END"),
        ),
        ("bigquery", format!("CREATE PROCEDURE ds.p() BEGIN SELECT 'Server=h;Password={m};'; END")),
        ("bigquery", format!("CREATE PROCEDURE ds.p() BEGIN SELECT r\"pwd={m}\"; END")),
    ] {
        let dialect = dialect::dialect_from_name(name).expect("known dialect");
        let script = parse_sql_with_dialect(&sql, dialect.as_ref()).expect("parses");
        for (at, _) in sql.match_indices(m) {
            let (start, end) = (at as u32, (at + m.len()) as u32);
            if !script
                .redaction_spans
                .iter()
                .any(|s| s.start <= start && end <= s.end)
            {
                leaks.push(format!("[{name}] not masked at byte {at}: {sql}"));
            }
        }
        let cfg = AnalysisConfig {
            dialect: Some(dialect),
            ..Default::default()
        };
        let report = analyze_risk_with_policy_config(&sql, &cfg).expect("should analyze");
        let json = serde_json::to_string(&report).expect("report serializes");
        if json.contains(&m[..6]) {
            leaks.push(format!("[{name}] in the report: {sql}"));
        }
    }
    // A key that names no secret keeps its value.
    let sql = format!("UPDATE t SET c = 'Server={m};Uid=u';");
    let script = parse_sql_with_dialect(&sql, dialect::postgres().as_ref()).expect("parses");
    assert!(script.redaction_spans.is_empty(), "{sql}");
    assert!(
        leaks.is_empty(),
        "secrets not masked ({}):\n{}",
        leaks.len(),
        leaks.join("\n")
    );
}

#[test]
fn a_jdbc_azure_or_partial_connection_string_secret_is_masked_where_it_is_written() {
    use lexega_core::{dialect, parse_sql_with_dialect};

    let m = "Zq9CsPwMark";
    let mut unmasked = Vec::new();
    for (name, sql) in [
        (
            "mssql",
            format!("UPDATE t SET c = 'jdbc:sqlserver://h:1;user=sa;password={m};';"),
        ),
        (
            "snowflake",
            format!("UPDATE t SET c = 'jdbc:snowflake://h;user=u;password={m}';"),
        ),
        (
            "mssql",
            format!("UPDATE t SET c = 'AccountName=a;AccountKey={m}==;X=y';"),
        ),
        (
            "mssql",
            format!("UPDATE t SET c = 'SharedAccessSignature=sv=1&sig={m}';"),
        ),
        (
            "mssql",
            format!("UPDATE t SET c = 'User=u;Password={m};Port=1;X;';"),
        ),
        ("mssql", format!("UPDATE t SET c = 'junk;Pwd={m}';")),
        // The value is masked in each literal of a run the dialect joins.
        (
            "mysql",
            format!("UPDATE t SET c = 'Server=h;Password=' '{m};';"),
        ),
        (
            "mysql",
            "UPDATE t SET c = 'Pwd=Zq9' 'CsPwMark';".to_string(),
        ),
        (
            "databricks",
            format!("UPDATE t SET c = \"Server=h;Password=\" \"{m}\";"),
        ),
    ] {
        let dialect = dialect::dialect_from_name(name).expect("known dialect");
        let script = parse_sql_with_dialect(&sql, dialect.as_ref()).expect("parses");
        let masked: String = sql
            .char_indices()
            .map(|(at, c)| {
                let at = at as u32;
                let covered = script
                    .redaction_spans
                    .iter()
                    .any(|s| s.start <= at && at < s.end);
                if covered {
                    '*'
                } else {
                    c
                }
            })
            .collect();
        if masked.contains("Zq9") || masked.contains("CsPwMark") {
            unmasked.push(format!("[{name}] {masked}"));
        }
    }
    // SQL text read as entries keeps its text where a key is several
    // words and a part writes no entry; a joined run that writes no secret
    // keeps its text.
    for (name, sql) in [
        (
            "mssql",
            format!("UPDATE t SET c = 'BEGIN SET password = {m}; END';"),
        ),
        ("mysql", format!("UPDATE t SET c = 'Server=' 'h;Uid={m}';")),
    ] {
        let dialect = dialect::dialect_from_name(name).expect("known dialect");
        let script = parse_sql_with_dialect(&sql, dialect.as_ref()).expect("parses");
        if !script.redaction_spans.is_empty() {
            unmasked.push(format!("[{name}] masked SQL text: {sql}"));
        }
    }
    assert!(unmasked.is_empty(), "{}", unmasked.join("\n"));
}

#[test]
fn a_hashed_tsql_password_or_a_mysql_password_is_masked_everywhere() {
    use lexega_core::analyzer::AnalysisConfig;
    use lexega_core::api::analyze_risk_with_policy_config;
    use lexega_core::{dialect, parse_sql_with_dialect};

    let hash = "0x5EC2E7AB5EC2E7AB";
    let digits = "5EC2E7AB5EC2E7AB";
    let m = TSQL_MARK;
    let next = "\nSELECT id FROM dbo.zz_src";
    let mut leaks = Vec::new();
    for (dialect, sql, mark) in [
        (
            dialect::mssql(),
            format!("CREATE LOGIN zz WITH PASSWORD = {hash} HASHED{next}"),
            digits,
        ),
        (
            dialect::mssql(),
            format!("CREATE LOGIN [zz] WITH PASSWORD = {hash} HASHED, SID = 0x01;"),
            digits,
        ),
        (
            dialect::mssql(),
            format!("ALTER LOGIN zz WITH PASSWORD = {hash} HASHED{next}"),
            digits,
        ),
        (
            dialect::mysql(),
            format!("ALTER USER 'zz'@'%' IDENTIFIED BY 'Aa{m}' REPLACE '{m}'; SELECT 1;"),
            m,
        ),
        (
            dialect::mysql(),
            format!("ALTER USER zz IDENTIFIED BY 'Aa{m}' REPLACE '{m}' RETAIN CURRENT PASSWORD;"),
            m,
        ),
        (
            dialect::mysql(),
            format!("SET PASSWORD FOR 'zz'@'%' = '{m}'; SELECT 1;"),
            m,
        ),
        (dialect::mysql(), format!("SET PASSWORD = '{m}';"), m),
        (
            dialect::mysql(),
            format!("SET PASSWORD FOR CURRENT_USER() = '{m}';"),
            m,
        ),
        (dialect::mysql(), format!("SET PASSWORD FOR zz = '{m}';"), m),
        (
            dialect::mysql(),
            format!("SET PASSWORD FOR 'zz'@'%' = 'Aa{m}' REPLACE '{m}' RETAIN CURRENT PASSWORD;"),
            m,
        ),
        (
            dialect::mysql(),
            format!("CREATE USER 'zz'@'%' IDENTIFIED WITH caching_sha2_password BY '{m}';"),
            m,
        ),
        (
            dialect::mysql(),
            format!("ALTER USER 'zz'@'%' IDENTIFIED WITH mysql_native_password BY '{m}';"),
            m,
        ),
        (
            dialect::mysql(),
            format!("CREATE USER 'zz'@'%' IDENTIFIED WITH mysql_native_password AS '{m}';"),
            m,
        ),
    ] {
        let script = parse_sql_with_dialect(&sql, dialect.as_ref()).expect("parses");
        for (at, _) in sql.match_indices(mark) {
            let (start, end) = (at as u32, (at + mark.len()) as u32);
            if !script
                .redaction_spans
                .iter()
                .any(|s| s.start <= start && end <= s.end)
            {
                leaks.push(format!("not masked at byte {at}: {sql}"));
            }
        }
        let cfg = AnalysisConfig {
            dialect: Some(dialect),
            ..Default::default()
        };
        let report = analyze_risk_with_policy_config(&sql, &cfg).expect("should analyze");
        let json = serde_json::to_string(&report).expect("report serializes");
        if json.contains(&mark[..6]) {
            leaks.push(format!("in the report: {sql}"));
        }
    }
    assert!(
        leaks.is_empty(),
        "secrets not masked:\n{}",
        leaks.join("\n")
    );
}

/// A MySQL account name in each spelling MySQL accepts: unquoted, quoted
/// with `'`, `"` or a backquote, a quoted user with an unquoted host,
/// wildcard and netmask hosts, IPv4 / IPv6, a host name with dots, an
/// anonymous user, no host, spaces around `@`, `CURRENT_USER`.
const MYSQL_ACCOUNTS: &[&str] = &[
    "root@localhost",
    "root@127.0.0.1",
    "root@db1.example.com",
    "root@h_1$x",
    "root@1host",
    "'root'@localhost",
    "`root`@localhost",
    "\"root\"@localhost",
    "'root'@127.0.0.1",
    "root@'localhost'",
    "'root'@'localhost'",
    "`root`@`localhost`",
    "\"root\"@\"localhost\"",
    "'root'@'%'",
    "'root'@'%.example.com'",
    "'root'@'198.51.100.0/255.255.255.0'",
    "'root'@'::1'",
    "''@localhost",
    "'root'",
    "root",
    "root @ localhost",
    "CURRENT_USER",
    "CURRENT_USER()",
];

#[test]
fn a_mysql_password_is_masked_whatever_the_account_name_spelling() {
    use lexega_core::analyzer::AnalysisConfig;
    use lexega_core::api::analyze_risk_with_policy_config;
    use lexega_core::{dialect, parse_sql_with_dialect};

    let m = TSQL_MARK;
    let cfg = AnalysisConfig {
        dialect: Some(dialect::mysql()),
        ..Default::default()
    };
    let mut statements = vec![
        format!("SET PASSWORD = PASSWORD('{m}');"),
        format!("SET PASSWORD = OLD_PASSWORD('{m}');"),
        format!("set password for root@localhost = password('{m}');"),
        format!("SET PASSWORD FOR root@localhost /* c */ = /* c */ PASSWORD( /* c */ '{m}' );"),
        format!(
            "CREATE PROCEDURE p() BEGIN SET PASSWORD FOR root@127.0.0.1 = PASSWORD('{m}'); \
             SELECT 1; END"
        ),
    ];
    for account in MYSQL_ACCOUNTS {
        statements.extend([
            format!("SET PASSWORD FOR {account} = '{m}'; SELECT 1;"),
            format!("SET PASSWORD FOR {account} = PASSWORD('{m}'); SELECT 1;"),
            format!("SET PASSWORD FOR {account} = OLD_PASSWORD('{m}');"),
            format!("ALTER USER {account} IDENTIFIED BY '{m}'; SELECT 1;"),
            format!("CREATE USER {account} IDENTIFIED BY '{m}';"),
            format!("GRANT SELECT ON db.* TO {account} IDENTIFIED BY '{m}';"),
        ]);
    }
    let mut leaks = Vec::new();
    for sql in statements {
        let script = parse_sql_with_dialect(&sql, dialect::mysql().as_ref()).expect("parses");
        for (at, _) in sql.match_indices(m) {
            let (start, end) = (at as u32, (at + m.len()) as u32);
            if !script
                .redaction_spans
                .iter()
                .any(|s| s.start <= start && end <= s.end)
            {
                leaks.push(format!("not masked at byte {at}: {sql}"));
            }
        }
        let report = analyze_risk_with_policy_config(&sql, &cfg).expect("should analyze");
        let json = serde_json::to_string(&report).expect("report serializes");
        if json.contains(&m[..6]) {
            leaks.push(format!("in the report: {sql}"));
        }
    }
    assert!(
        leaks.is_empty(),
        "secrets not masked:\n{}",
        leaks.join("\n")
    );
}

const HEX_MARK: &str = "5EC2E7AB5EC2E7AB";
const BIT_MARK: &str = "0110100101101001011011100110100101101001";

/// `(spelling, the bytes of the written secret)`: each way a dialect's lexer
/// gives a string or a binary literal.
fn literal_spellings(dialect: &str) -> Vec<(String, &'static str)> {
    let (m, h, b) = (TSQL_MARK, HEX_MARK, BIT_MARK);
    let mut spellings = vec![(format!("'{m}'"), m)];
    match dialect {
        "mysql" => spellings.extend([
            (format!("\"{m}\""), m),
            (format!("_utf8mb4'{m}'"), m),
            (format!("_utf8mb4 '{m}'"), m),
            (format!("_utf8mb4/* c */'{m}'"), m),
            (format!("_latin1\"{m}\""), m),
            (format!("_utf8mb4'{m}' COLLATE utf8mb4_bin"), m),
            (format!("N'{m}'"), m),
            (format!("n'{m}'"), m),
            (format!("X'{h}'"), h),
            (format!("x'{h}'"), h),
            (format!("0x{h}"), h),
            (format!("b'{b}'"), b),
            (format!("B'{b}'"), b),
            (format!("0b{b}"), b),
            (format!("_binary X'{h}'"), h),
            (format!("_binary 0x{h}"), h),
            (format!("_binary b'{b}'"), b),
            (format!("'{m}' '{m}'"), m),
            (format!("_utf8mb4'{m}' \"{m}\""), m),
        ]),
        "postgres" => spellings.extend([
            (format!("E'{m}'"), m),
            (format!("e'{m}'"), m),
            (format!("$${m}$$"), m),
            (format!("$$ {m} $$"), m),
            (format!("$pw${m}$pw$"), m),
            (format!("U&'{m}'"), m),
            (format!("N'{m}'"), m),
            (format!("'{m}'\n'{m}'"), m),
            (format!("B'{b}'"), b),
            (format!("X'{h}'"), h),
        ]),
        "redshift" => spellings.extend([
            (format!("'md5{m}'"), m),
            (format!("$${m}$$"), m),
            (format!("$$ {m} $$"), m),
        ]),
        "snowflake" => spellings.extend([
            (format!("$${m}$$"), m),
            (format!("$$ {m} $$"), m),
            (format!("$$a {m}$$"), m),
            (format!("X'{h}'"), h),
        ]),
        "databricks" => spellings.extend([
            (format!("\"{m}\""), m),
            (format!("r'{m}'"), m),
            (format!("R'{m}'"), m),
            (format!("r\"{m}\""), m),
            (format!("X'{h}'"), h),
            (format!("'{m}' \"{m}\""), m),
        ]),
        "mssql" => spellings.extend([
            (format!("N'{m}'"), m),
            (format!("n'{m}'"), m),
            (format!("N'Ab''{m}'"), m),
        ]),
        _ => {}
    }
    spellings
}

/// `(dialect, statement with `{v}` where the secret value is written)`.
fn secret_positions() -> Vec<(&'static str, String)> {
    let next = "\nSELECT id FROM dbo.zz_src";
    let mut positions = vec![
        (
            "mysql",
            "SET PASSWORD FOR root@localhost = {v}; SELECT 1;".to_string(),
        ),
        ("mysql", "SET PASSWORD = {v};".to_string()),
        (
            "mysql",
            "SET PASSWORD FOR 'zz'@'%' = PASSWORD({v});".to_string(),
        ),
        ("mysql", "SET PASSWORD = OLD_PASSWORD({v});".to_string()),
        (
            "mysql",
            "SET PASSWORD FOR 'zz'@'%' = 'Ab1' REPLACE {v} RETAIN CURRENT PASSWORD;".to_string(),
        ),
        (
            "mysql",
            "CREATE USER 'zz'@'%' IDENTIFIED BY {v}; SELECT 1;".to_string(),
        ),
        (
            "mysql",
            "ALTER USER zz@localhost IDENTIFIED BY {v}; SELECT 1;".to_string(),
        ),
        (
            "mysql",
            "CREATE USER 'zz'@'%' IDENTIFIED WITH caching_sha2_password BY {v};".to_string(),
        ),
        (
            "mysql",
            "ALTER USER 'zz'@'%' IDENTIFIED WITH mysql_native_password AS {v};".to_string(),
        ),
        (
            "mysql",
            "ALTER USER 'zz'@'%' IDENTIFIED BY 'Ab1' REPLACE {v} RETAIN CURRENT PASSWORD;"
                .to_string(),
        ),
        (
            "mysql",
            "GRANT SELECT ON db.* TO 'zz'@'%' IDENTIFIED BY {v};".to_string(),
        ),
        (
            "mysql",
            "CREATE USER 'zz'@'%' IDENTIFIED BY PASSWORD {v};".to_string(),
        ),
        (
            "mysql",
            "CREATE PROCEDURE p() BEGIN SET PASSWORD FOR root@localhost = {v}; SELECT 1; END"
                .to_string(),
        ),
        (
            "mysql",
            "START REPLICA USER = 'u' PASSWORD = {v};".to_string(),
        ),
        (
            "postgres",
            "CREATE ROLE zz WITH LOGIN PASSWORD {v}; SELECT 1;".to_string(),
        ),
        (
            "postgres",
            "CREATE USER zz PASSWORD {v}; SELECT 1;".to_string(),
        ),
        (
            "postgres",
            "ALTER ROLE zz WITH PASSWORD {v} VALID UNTIL '2030-01-01'; SELECT 1;".to_string(),
        ),
        ("postgres", "ALTER USER zz PASSWORD {v};".to_string()),
        (
            "postgres",
            "CREATE USER MAPPING FOR zz SERVER s OPTIONS (user 'u', password {v}); SELECT 1;"
                .to_string(),
        ),
        (
            "postgres",
            "ALTER USER MAPPING FOR zz SERVER s OPTIONS (SET password {v});".to_string(),
        ),
        (
            "redshift",
            "CREATE USER zz PASSWORD {v}; SELECT 1;".to_string(),
        ),
        ("redshift", "ALTER USER zz PASSWORD {v};".to_string()),
        (
            "snowflake",
            "CREATE USER zz PASSWORD = {v} DEFAULT_ROLE = r; SELECT 1;".to_string(),
        ),
        (
            "snowflake",
            "ALTER USER zz SET PASSWORD = {v}; SELECT 1;".to_string(),
        ),
        (
            "snowflake",
            "CREATE SECRET s TYPE = PASSWORD USERNAME = 'u' PASSWORD = {v}; SELECT 1;".to_string(),
        ),
        (
            "snowflake",
            "CREATE SECRET s TYPE = GENERIC_STRING SECRET_STRING = {v}; SELECT 1;".to_string(),
        ),
        (
            "snowflake",
            "CREATE STAGE s URL = 's3://b/p' CREDENTIALS = (AWS_KEY_ID = 'id' \
             AWS_SECRET_KEY = {v}); SELECT 1;"
                .to_string(),
        ),
        (
            "databricks",
            "CREATE CONNECTION c TYPE mysql OPTIONS (host 'h', user 'u', password {v});"
                .to_string(),
        ),
        (
            "databricks",
            "ALTER CONNECTION c OPTIONS (host 'h', user 'u', password {v});".to_string(),
        ),
        (
            "databricks",
            "CREATE CONNECTION c TYPE salesforce OPTIONS (client_id 'i', client_secret {v});"
                .to_string(),
        ),
        // A key written as a string, and an `=` between key and value.
        (
            "databricks",
            "CREATE CONNECTION c TYPE mysql OPTIONS (host 'h', password = {v});".to_string(),
        ),
        (
            "databricks",
            "ALTER CONNECTION c OPTIONS (client_secret = {v});".to_string(),
        ),
        (
            "databricks",
            "CREATE CONNECTION c TYPE mysql OPTIONS (host 'h', \"password\" {v});".to_string(),
        ),
        (
            "databricks",
            "CREATE CONNECTION c TYPE mysql OPTIONS ('password' {v});".to_string(),
        ),
        (
            "databricks",
            "ALTER CONNECTION c OPTIONS (\"password\" = {v});".to_string(),
        ),
        (
            "databricks",
            "CREATE CONNECTION c TYPE mysql OPTIONS (host='h',r'password'={v});".to_string(),
        ),
    ];
    // An option or property list naming a password or a secret.
    for (name, statement) in [
        (
            "databricks",
            "CREATE TABLE t USING JDBC OPTIONS (url 'u', password {v});",
        ),
        (
            "databricks",
            "CREATE TABLE t USING JDBC OPTIONS ('password' = {v});",
        ),
        (
            "databricks",
            "CREATE TABLE t (a INT) TBLPROPERTIES ('password' = {v});",
        ),
        (
            "databricks",
            "CREATE TABLE t2 SHALLOW CLONE t TBLPROPERTIES ('password' = {v});",
        ),
        (
            "databricks",
            "ALTER TABLE t SET TBLPROPERTIES ('password' = {v});",
        ),
        (
            "databricks",
            "ALTER VIEW v SET TBLPROPERTIES ('password' = {v});",
        ),
        (
            "databricks",
            "CREATE VIEW v (a) TBLPROPERTIES ('password' = {v}) AS SELECT 1;",
        ),
        (
            "databricks",
            "CREATE VIEW v TBLPROPERTIES ('password' = {v}) AS SELECT 1;",
        ),
        (
            "databricks",
            "CREATE TABLE t TBLPROPERTIES ('password' = {v}) AS SELECT 1;",
        ),
        (
            "bigquery",
            "CREATE VIEW d.v OPTIONS (password = {v}) AS SELECT 1;",
        ),
        (
            "bigquery",
            "CREATE TABLE d.t OPTIONS (password = {v}) AS SELECT 1;",
        ),
        (
            "databricks",
            "CREATE SCHEMA s WITH DBPROPERTIES ('password' = {v});",
        ),
        (
            "databricks",
            "ALTER SCHEMA s SET DBPROPERTIES ('password' = {v});",
        ),
        (
            "databricks",
            "CREATE FOREIGN CATALOG c USING CONNECTION x OPTIONS (password {v});",
        ),
        ("databricks", "ALTER CATALOG c OPTIONS (password {v});"),
        ("databricks", "CACHE TABLE t OPTIONS ('password' {v});"),
        (
            "databricks",
            "COPY INTO t FROM 's3://b' WITH (CREDENTIAL (AWS_SECRET_KEY = {v}));",
        ),
        (
            "databricks",
            "CREATE STORAGE CREDENTIAL c WITH AZURE_SERVICE_PRINCIPAL ('d', 'a', {v});",
        ),
        (
            "databricks",
            "CREATE STORAGE CREDENTIAL c CLOUDFLARE_API_TOKEN ('acct', 'kid', {v});",
        ),
        (
            "bigquery",
            "CREATE TABLE d.t (a INT64) OPTIONS (password = {v});",
        ),
        ("bigquery", "ALTER TABLE d.t SET OPTIONS (password = {v});"),
        ("bigquery", "CREATE SCHEMA d OPTIONS (password = {v});"),
        (
            "bigquery",
            "EXPORT DATA OPTIONS (uri = 'gs://b/*', password = {v}) AS SELECT 1;",
        ),
        (
            "bigquery",
            "LOAD DATA INTO d.t FROM FILES (password = {v});",
        ),
        (
            "bigquery",
            "CREATE EXTERNAL TABLE d.t OPTIONS (password = {v});",
        ),
        (
            "bigquery",
            "ALTER MATERIALIZED VIEW d.v SET OPTIONS (password = {v});",
        ),
        (
            "postgres",
            "CREATE SERVER s FOREIGN DATA WRAPPER w OPTIONS (host 'h', password {v});",
        ),
        ("postgres", "ALTER SERVER s OPTIONS (SET password {v});"),
        (
            "postgres",
            "CREATE FOREIGN TABLE ft (a int) SERVER s OPTIONS (password {v});",
        ),
        (
            "postgres",
            "IMPORT FOREIGN SCHEMA r FROM SERVER s INTO l OPTIONS (password {v});",
        ),
        (
            "mysql",
            "CREATE SERVER s FOREIGN DATA WRAPPER mysql OPTIONS (USER 'u', PASSWORD {v});",
        ),
        // Text no reader parses: a key naming a secret, `=` or not, a literal.
        (
            "databricks",
            "CREATE STREAMING TABLE t TBLPROPERTIES ('password' = {v}) AS SELECT 1;",
        ),
        (
            "databricks",
            "INSERT OVERWRITE DIRECTORY '/p' USING parquet OPTIONS ('client_secret' = {v}) \
             SELECT 1;",
        ),
        (
            "databricks",
            "CREATE SCHEMA s DBPROPERTIES ('client_secret' = {v});",
        ),
        (
            "bigquery",
            "CREATE FUNCTION d.f() AS (1) OPTIONS (client_secret = {v});",
        ),
        (
            "bigquery",
            "ALTER VECTOR INDEX i ON d.t SET OPTIONS (client_secret = {v});",
        ),
        (
            "postgres",
            "ALTER FOREIGN TABLE ft OPTIONS (ADD client_secret {v});",
        ),
        (
            "postgres",
            "CREATE FOREIGN DATA WRAPPER w OPTIONS (client_secret {v});",
        ),
    ] {
        positions.push((name, statement.to_string()));
    }
    for tsql in [
        "CREATE LOGIN zz WITH PASSWORD = {v}",
        "ALTER LOGIN zz WITH PASSWORD = 'Ab1' OLD_PASSWORD = {v}",
        "CREATE USER zz WITH PASSWORD = {v}",
        "CREATE MASTER KEY ENCRYPTION BY PASSWORD = {v}",
        "CREATE CREDENTIAL c WITH IDENTITY = 'u', SECRET = {v}",
        "BACKUP DATABASE d TO DISK = 'a.bak' WITH MEDIAPASSWORD = {v}",
        "ADD SIGNATURE TO dbo.p BY CERTIFICATE c WITH PASSWORD = {v}",
        "ALTER SERVICE MASTER KEY WITH OLD_ACCOUNT = 'a', OLD_PASSWORD = {v}",
        "CREATE SYMMETRIC KEY k WITH KEY_SOURCE = {v}, ALGORITHM = AES_256 \
         ENCRYPTION BY CERTIFICATE c",
        "CREATE APPLICATION ROLE r WITH PASSWORD = {v}",
        "CREATE CERTIFICATE c ENCRYPTION BY PASSWORD = {v} WITH SUBJECT = 's'",
        "OPEN SYMMETRIC KEY k DECRYPTION BY PASSWORD = {v}",
        "BACKUP MASTER KEY TO FILE = 'f' ENCRYPTION BY PASSWORD = {v}",
    ] {
        positions.push(("mssql", format!("{tsql}{next}")));
    }
    positions
}

#[test]
fn a_secret_is_masked_in_every_literal_spelling_of_its_dialect() {
    use lexega_core::analyzer::AnalysisConfig;
    use lexega_core::api::analyze_risk_with_policy_config;
    use lexega_core::{dialect, parse_sql_with_dialect};

    let mut leaks = Vec::new();
    for (name, template) in secret_positions() {
        let dialect = dialect::dialect_from_name(name).expect("known dialect");
        let cfg = AnalysisConfig {
            dialect: Some(dialect.clone()),
            ..Default::default()
        };
        for (value, mark) in literal_spellings(name) {
            let sql = template.replace("{v}", &value);
            let script = parse_sql_with_dialect(&sql, dialect.as_ref()).expect("parses");
            for (at, _) in sql.match_indices(mark) {
                let (start, end) = (at as u32, (at + mark.len()) as u32);
                if !script
                    .redaction_spans
                    .iter()
                    .any(|s| s.start <= start && end <= s.end)
                {
                    leaks.push(format!("[{name}] not masked at byte {at}: {sql}"));
                }
            }
            let report = analyze_risk_with_policy_config(&sql, &cfg).expect("should analyze");
            let json = serde_json::to_string(&report).expect("report serializes");
            if json.contains(&mark[..12]) {
                leaks.push(format!("[{name}] in the report: {sql}"));
            }
        }
    }
    assert!(
        leaks.is_empty(),
        "secrets not masked ({}):\n{}",
        leaks.len(),
        leaks.join("\n")
    );
}

#[test]
fn a_password_written_in_any_string_spelling_raises_the_hardcoded_password_finding() {
    use lexega_core::analyzer::AnalysisConfig;
    use lexega_core::api::analyze_risk_with_policy_config;
    use lexega_core::dialect;

    let raises = |name: &str, sql: &str| {
        let cfg = AnalysisConfig {
            dialect: dialect::dialect_from_name(name),
            ..Default::default()
        };
        analyze_risk_with_policy_config(sql, &cfg)
            .expect("should analyze")
            .findings
            .iter()
            .any(|s| match s {
                RuleMatch::Analysis(g) => g.matched_rule == "CRED-PWD-LEAK",
            })
    };
    let m = TSQL_MARK;
    let h = HEX_MARK;
    let mut missing = Vec::new();
    for statement in [
        "CREATE USER zz IDENTIFIED BY {v};",
        "ALTER USER zz IDENTIFIED BY {v};",
    ] {
        for value in [
            format!("'{m}'"),
            format!("_utf8mb4'{m}'"),
            format!("_utf8mb4 '{m}'"),
            format!("_binary '{m}'"),
            format!("N'{m}'"),
            format!("X'{h}'"),
        ] {
            let sql = statement.replace("{v}", &value);
            if !raises("mysql", &sql) {
                missing.push(sql);
            }
        }
    }
    for (name, sql) in [
        ("snowflake", format!("CREATE USER zz PASSWORD = $${m}$$;")),
        (
            "postgres",
            format!("CREATE ROLE zz LOGIN PASSWORD $${m}$$;"),
        ),
    ] {
        if !raises(name, &sql) {
            missing.push(sql);
        }
    }
    assert!(
        missing.is_empty(),
        "no CRED-PWD-LEAK on:\n{}",
        missing.join("\n")
    );

    // A hashed T-SQL login password is no password written in the clear.
    let hashed = format!("CREATE LOGIN zz WITH PASSWORD = 0x{h} HASHED;");
    assert!(!raises("mssql", &hashed), "{hashed}");
}

#[test]
fn a_mysql_replication_password_is_masked_everywhere() {
    use lexega_core::analyzer::AnalysisConfig;
    use lexega_core::api::analyze_risk_with_policy_config;
    use lexega_core::{dialect, parse_sql_with_dialect};

    let m = TSQL_MARK;
    let cfg = AnalysisConfig {
        dialect: Some(dialect::mysql()),
        ..Default::default()
    };
    let mut leaks = Vec::new();
    for sql in [
        format!("CHANGE MASTER TO MASTER_PASSWORD = '{m}';"),
        format!("CHANGE MASTER TO MASTER_HOST = 'h', MASTER_USER = 'u', MASTER_PASSWORD = '{m}';"),
        format!("change master to master_password='{m}', master_port=3306;"),
        format!("CHANGE REPLICATION SOURCE TO SOURCE_PASSWORD = '{m}';"),
        format!("CHANGE REPLICATION SOURCE TO SOURCE_USER = 'u', SOURCE_PASSWORD = _utf8mb4'{m}';"),
        format!(
            "CHANGE REPLICATION SOURCE TO SOURCE_PASSWORD = \"{m}\" FOR CHANNEL 'c';\nSELECT 1;"
        ),
    ] {
        let script = parse_sql_with_dialect(&sql, dialect::mysql().as_ref()).expect("parses");
        for (at, _) in sql.match_indices(m) {
            let (start, end) = (at as u32, (at + m.len()) as u32);
            if !script
                .redaction_spans
                .iter()
                .any(|s| s.start <= start && end <= s.end)
            {
                leaks.push(format!("not masked at byte {at}: {sql}"));
            }
        }
        let report = analyze_risk_with_policy_config(&sql, &cfg).expect("should analyze");
        let json = serde_json::to_string(&report).expect("report serializes");
        if json.contains(&m[..6]) {
            leaks.push(format!("in the report: {sql}"));
        }
    }
    assert!(
        leaks.is_empty(),
        "secrets not masked:\n{}",
        leaks.join("\n")
    );
}

#[test]
fn a_tsql_key_certificate_credential_or_login_secret_is_masked_everywhere() {
    use lexega_core::analyzer::AnalysisConfig;
    use lexega_core::api::analyze_risk_with_policy_config;
    use lexega_core::{dialect, parse_sql_with_dialect};

    let cfg = AnalysisConfig {
        dialect: Some(dialect::mssql()),
        ..Default::default()
    };
    let mut leaks = Vec::new();
    for sql in tsql_secret_statements() {
        // Every byte of every written secret is a masked byte.
        let script = parse_sql_with_dialect(&sql, dialect::mssql().as_ref()).expect("parses");
        for (at, _) in sql.match_indices(TSQL_MARK) {
            let (start, end) = (at as u32, (at + TSQL_MARK.len()) as u32);
            if !script
                .redaction_spans
                .iter()
                .any(|s| s.start <= start && end <= s.end)
            {
                leaks.push(format!("not masked at byte {at}: {sql}"));
            }
        }
        // No part of it reaches the report.
        let report = analyze_risk_with_policy_config(&sql, &cfg).expect("should analyze");
        let json = serde_json::to_string(&report).expect("report serializes");
        if json.contains(&TSQL_MARK[..6]) {
            leaks.push(format!("in the report: {sql}"));
        }
    }
    assert!(
        leaks.is_empty(),
        "secrets not masked:\n{}",
        leaks.join("\n")
    );
}

#[test]
fn a_secret_in_executed_sql_a_procedure_argument_or_a_connection_string_is_masked() {
    use lexega_core::analyzer::AnalysisConfig;
    use lexega_core::api::analyze_risk_with_policy_config;
    use lexega_core::{dialect, parse_sql_with_dialect};

    let m = TSQL_MARK;
    // Secrets the parser records where it reads them.
    let recorded = [
        ("mssql", format!("EXEC sp_setapprole 'zz_r', '{m}'")),
        ("mssql", format!("EXEC sys.sp_setapprole @rolename = 'zz_r', @password = N'{m}'")),
        ("mssql", format!("EXEC sp_addlinkedsrvlogin 's', 'FALSE', NULL, 'u', '{m}'")),
        ("mssql", format!("EXEC sp_addlogin @loginame = 'zz', @passwd = '{m}'")),
        ("mssql", format!("EXEC [sys].[SP_ADDLOGIN] @loginame = 'zz', @passwd = '{m}'")),
        ("mssql", format!("EXEC [sp_setapprole] 'zz_r', '{m}'")),
        ("mssql", format!("EXEC \"Sp_Password\" '{m}', '{m}', 'zz'")),
        ("mssql", format!("EXEC sp_password '{m}', '{m}', 'zz'")),
        ("mssql", format!("EXEC sp_approlepassword @rolename = 'r', @newpwd = '{m}'")),
        ("mssql", format!("EXEC sp_change_users_login 'Auto_Fix', 'u', NULL, '{m}'")),
        ("mssql", format!("EXEC dbo.zz_proc @password = '{m}'")),
        ("mssql", format!("EXEC sp_addlinkedserver 's', '', 'p', NULL, NULL, 'Server=x;Password={m}'")),
        (
            "mssql",
            format!("SELECT a.* FROM OPENROWSET('MSOLEDBSQL', 'Server=s;Uid=u;Pwd={m};', 'SELECT 1') AS a"),
        ),
        (
            "mssql",
            format!("SELECT a.* FROM OPENROWSET('SQLNCLI', 'Server=s;Password=\"{m};x\"', 'SELECT 1') AS a"),
        ),
        ("mssql", format!("SELECT a.* FROM OPENROWSET('MSDASQL', 's';'u';'{m}', 'SELECT 1') AS a")),
        (
            "mssql",
            format!("SELECT * FROM OPENDATASOURCE('MSOLEDBSQL', 'Data Source=s;Password={m}').d.dbo.t"),
        ),
        ("snowflake", format!("CREATE API INTEGRATION i API_PROVIDER = aws_api_gateway API_KEY = '{m}' ENABLED = TRUE;")),
        ("snowflake", format!("ALTER API INTEGRATION i SET API_KEY = '{m}';")),
        ("databricks", format!("CREATE CONNECTION c TYPE snowflake OPTIONS (host 'h', pem_private_key '{m}');")),
        ("databricks", format!("ALTER CONNECTION c OPTIONS (aws_access_key '{m}');")),
        ("databricks", format!("CREATE CONNECTION c TYPE databricks OPTIONS (host 'h', token '{m}');")),
        ("postgresql", format!("CREATE USER MAPPING FOR u SERVER s OPTIONS (user 'u', token '{m}');")),
    ];
    // Secrets in a string a statement executes.
    let executed = [
        ("mssql", format!("EXEC('CREATE LOGIN zz WITH PASSWORD = ''{m}''')")),
        ("mssql", format!("EXEC (N'ALTER LOGIN zz WITH PASSWORD = ''{m}'' OLD_PASSWORD = ''{m}''')")),
        ("mssql", format!("EXEC('EXEC(''CREATE LOGIN zz WITH PASSWORD = ''''{m}'''''')')")),
        ("mssql", format!("EXEC('CREATE LOGIN zz WITH PASSWORD = ''Ab''''{m}''')")),
        ("mssql", format!("EXEC sp_executesql N'CREATE LOGIN zz WITH PASSWORD = ''{m}'''")),
        ("mssql", format!("EXEC sp_executesql @stmt = N'CREATE CREDENTIAL c WITH IDENTITY = ''u'', SECRET = ''{m}'''")),
        ("mssql", format!("IF 1 = 1\nBEGIN\n    EXEC('CREATE MASTER KEY ENCRYPTION BY PASSWORD = ''{m}''')\nEND")),
        ("snowflake", format!("EXECUTE IMMEDIATE 'CREATE USER zz PASSWORD = ''{m}''';")),
        ("mysql", format!("PREPARE s FROM 'CREATE USER ''u''@''%'' IDENTIFIED BY ''{m}''';")),
        ("postgres", format!("DO $$ BEGIN EXECUTE E'CREATE ROLE zz PASSWORD ''{m}'''; END $$;")),
        (
            "postgres",
            format!("DO $$ BEGIN EXECUTE E'CREATE ROLE zz\\nPASSWORD \\'{m}\\''; END $$;"),
        ),
    ];
    let mut leaks = Vec::new();
    for (name, sql) in recorded.iter().chain(executed.iter()) {
        let dialect = dialect::dialect_from_name(name).expect("known dialect");
        if recorded.iter().any(|(_, r)| r == sql) {
            let script = parse_sql_with_dialect(sql, dialect.as_ref()).expect("parses");
            for (at, _) in sql.match_indices(m) {
                let (start, end) = (at as u32, (at + m.len()) as u32);
                if !script
                    .redaction_spans
                    .iter()
                    .any(|s| s.start <= start && end <= s.end)
                {
                    leaks.push(format!("[{name}] not masked at byte {at}: {sql}"));
                }
            }
        }
        let cfg = AnalysisConfig {
            dialect: Some(dialect),
            ..Default::default()
        };
        let report = analyze_risk_with_policy_config(sql, &cfg).expect("should analyze");
        let json = serde_json::to_string(&report).expect("report serializes");
        if json.contains(&m[..6]) {
            leaks.push(format!("[{name}] in the report: {sql}"));
        }
    }
    // A string no statement executes is not a secret.
    let shown = format!("SELECT 'PASSWORD = ''{m}''' AS s");
    let script = parse_sql_with_dialect(&shown, dialect::mssql().as_ref()).expect("parses");
    assert!(script.redaction_spans.is_empty(), "{shown}");
    assert!(
        leaks.is_empty(),
        "secrets not masked ({}):\n{}",
        leaks.len(),
        leaks.join("\n")
    );
}

/// Whether `mark`, wherever `sql` writes it, is masked in the source as
/// [`redact_secrets_for_display`] shows it under the dialect `name`, and
/// whether the report leaves it out.
fn masked_under(name: &str, sql: &str, mark: &str) -> (bool, bool) {
    use lexega_core::analyzer::AnalysisConfig;
    use lexega_core::api::analyze_risk_with_policy_config;
    use lexega_core::dialect;

    let dialect = dialect::dialect_from_name(name).expect("known dialect");
    let shown = redact_secrets_for_display(sql, &dialect);
    let spanned = !shown.contains(mark);
    let cfg = AnalysisConfig {
        dialect: Some(dialect),
        ..Default::default()
    };
    let report = analyze_risk_with_policy_config(sql, &cfg).expect("should analyze");
    let json = serde_json::to_string(&report).expect("report serializes");
    (spanned, !json.contains(mark))
}

#[test]
fn a_libpq_connection_string_secret_is_masked_in_every_postgresql_spelling() {
    let m = TSQL_MARK;
    // libpq's `key = value` form (a value quoted with `'`, `\'` and `\\`
    // escaped in it) and its URI form.
    let connection_strings = [
        format!("host=h dbname=d password={m}"),
        format!("password = {m} host=h"),
        format!("host=h password='a {m}' dbname=d"),
        format!("host=h password='it\\'s {m}\\\\'"),
        format!("host=h sslkey=k sslpassword={m}"),
        format!("postgresql://u:{m}@h:5432/d"),
        format!("postgres://u@h/d?sslmode=require&password={m}"),
    ];
    // Each PostgreSQL spelling of the SQL string that holds it.
    let spellings = |cs: &str| {
        [
            format!("'{}'", cs.replace('\'', "''")),
            format!("E'{}'", cs.replace('\\', "\\\\").replace('\'', "\\'")),
            format!("$${cs}$$"),
            format!("$c${cs}$c$"),
        ]
    };
    let positions = [
        "CREATE SUBSCRIPTION s CONNECTION {v} PUBLICATION p;",
        "CREATE SUBSCRIPTION s /* c */ CONNECTION {v} PUBLICATION p WITH (enabled = false);",
        "ALTER SUBSCRIPTION s CONNECTION {v};",
        "SELECT dblink_connect({v});",
        "SELECT dblink_connect('c', {v});",
        "SELECT public.dblink_connect_u('c', {v});",
        "SELECT * FROM dblink({v}, 'SELECT 1') AS t(a int);",
        "SELECT dblink_exec({v}, 'UPDATE t SET a = 1', true);",
        // A call PL/pgSQL's `PERFORM` makes, and one in text no reader
        // parses (an unknown statement).
        "DO $d$ BEGIN PERFORM dblink_connect('c', {v}); END $d$;",
        "DO $d$ BEGIN IF true THEN PERFORM public.dblink_exec({v}, 'SELECT 1'); END IF; END $d$;",
        "CREATE FUNCTION f() RETURNS void LANGUAGE plpgsql AS $d$ BEGIN PERFORM dblink_exec({v}, 'SELECT 1'); END $d$;",
        "FROBNICATE dblink_connect({v});",
        // A setting whose value is a connection string.
        "ALTER SYSTEM SET primary_conninfo = {v};",
        "ALTER SYSTEM /* c */ SET PRIMARY_CONNINFO TO {v};",
    ];
    let mut leaks = Vec::new();
    for position in positions {
        for cs in &connection_strings {
            for value in spellings(cs) {
                let sql = position.replace("{v}", &value);
                let (spanned, out_of_report) = masked_under("postgres", &sql, m);
                if !spanned {
                    leaks.push(format!("not masked: {sql}"));
                }
                if !out_of_report {
                    leaks.push(format!("in the report: {sql}"));
                }
            }
        }
    }
    // A connection string no walk shows safe is masked whole, the values
    // whose key names no secret with it.
    for unshown in [
        format!("CREATE SUBSCRIPTION s CONNECTION 'host=h user={m}' PUBLICATION p;"),
        format!("SELECT dblink_connect('c', 'postgresql://{m}@h/d');"),
        format!("ALTER SYSTEM SET primary_slot_name = 'host=h password={m}';"),
        format!("ALTER SYSTEM SET primary_conninfo = 'host=h user={m}';"),
    ] {
        if !masked_under("postgres", &unshown, m).0 {
            leaks.push(format!("printed: {unshown}"));
        }
    }
    // A dblink call's SQL is SQL it runs: its literals are masked as those
    // of the SQL an `EXECUTE` runs.
    for run in [
        format!("SELECT dblink('c', 'SELECT ''password={m}''');"),
        format!("SELECT dblink_exec('UPDATE t SET password = ''{m}''', true);"),
        format!("DO $d$ BEGIN PERFORM dblink_exec('UPDATE t SET p = ''password={m}'''); END $d$;"),
        format!(
            "DO $d$ BEGIN PERFORM dblink_open('c', 'cur', 'SELECT ''password={m}'''); END $d$;"
        ),
    ] {
        let (spanned, out_of_report) = masked_under("postgres", &run, m);
        if !spanned || !out_of_report {
            leaks.push(format!("not masked as SQL it runs: {run}"));
        }
    }
    assert!(
        leaks.is_empty(),
        "connection strings not read ({}):\n{}",
        leaks.len(),
        leaks.join("\n")
    );
}

#[test]
fn unparsed_text_masks_every_literal() {
    let m = TSQL_MARK;
    let st = "CREATE STREAMING TABLE t TBLPROPERTIES";
    let masked = [
        format!("{st} ('a' = ('password' = '{m}')) AS SELECT 1;"),
        format!("{st} (\"client_secret\" \"{m}\") AS SELECT 1;"),
        format!("{st} (token = r'{m}') AS SELECT 1;"),
    ];
    // Whatever key a literal of unparsed text follows, it is masked.
    let unshown = [
        format!("{st} ('comment' = '{m}') AS SELECT 1;"),
        format!("{st} ('password', '{m}') AS SELECT 1;"),
        format!("{st} (password = upper('{m}')) AS SELECT 1;"),
    ];
    let mut wrong = Vec::new();
    for sql in &masked {
        if masked_under("databricks", sql, m) != (true, true) {
            wrong.push(format!("not masked: {sql}"));
        }
    }
    for sql in &unshown {
        if !masked_under("databricks", sql, m).0 {
            wrong.push(format!("printed: {sql}"));
        }
    }
    // Text a statement's reader skips, and a statement a block keeps as
    // written, follow the same rule.
    let skipped = [
        ("postgres", format!("SET app.password = '{m}';")),
        (
            "postgres",
            format!("ALTER SYSTEM SET app.password = '{m}';"),
        ),
        (
            "postgres",
            format!("ALTER TABLESPACE ts SET (secret_key = '{m}');"),
        ),
        (
            "postgres",
            format!("DO $$ BEGIN FROBNICATE x password = '{m}'; END $$;"),
        ),
        (
            "snowflake",
            format!("BEGIN\n  FROBNICATE x SET client_secret = '{m}';\nEND;"),
        ),
        (
            "snowflake",
            format!("ALTER SECURITY INTEGRATION i FROBNICATE OAUTH_CLIENT_SECRET = '{m}';"),
        ),
        (
            "snowflake",
            format!("ALTER STAGE s SET FROBNICATE = (client_secret = '{m}');"),
        ),
        (
            "mysql",
            format!("CREATE PROCEDURE p() BEGIN FROBNICATE x WITH ('password' = '{m}'); END"),
        ),
        (
            "bigquery",
            format!("BEGIN\n  FROBNICATE x OPTIONS (password = '{m}');\nEND;"),
        ),
        (
            "databricks",
            format!("ALTER TABLE t SET SERDEPROPERTIES ('password' = '{m}');"),
        ),
    ];
    for (dialect, sql) in &skipped {
        if masked_under(dialect, sql, m) != (true, true) {
            wrong.push(format!("not masked [{dialect}]: {sql}"));
        }
    }
    // `search_path` is a setting PostgreSQL documents as a schema list.
    let search_path = format!("SET search_path = '{m}';");
    if masked_under("postgres", &search_path, m).0 {
        wrong.push(format!("masked: {search_path}"));
    }
    for (dialect, sql) in [
        ("postgres", format!("ALTER SYSTEM SET app.tenant = '{m}';")),
        (
            "snowflake",
            format!("BEGIN\n  FROBNICATE x SET comment = '{m}';\nEND;"),
        ),
    ] {
        if !masked_under(dialect, &sql, m).0 {
            wrong.push(format!("printed [{dialect}]: {sql}"));
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

#[test]
fn a_setting_given_a_secret_after_equals_or_to_is_masked() {
    let m = TSQL_MARK;
    let mut wrong = Vec::new();
    for op in ["=", "TO"] {
        let masked = [
            format!("SET app.password {op} '{m}';"),
            format!("SET SESSION app.password {op} '{m}';"),
            format!("set local app.password {op} E'{m}\\n';"),
            format!("SET /* c */ \"app.secret\" {op} $${m}$$;"),
            format!("ALTER SYSTEM SET app.password {op} '{m}';"),
            format!("ALTER DATABASE d SET app.password {op} '{m}';"),
            format!("ALTER ROLE r SET app.password {op} '{m}';"),
            format!("ALTER ROLE r IN DATABASE d SET app.password {op} '{m}';"),
            format!("ALTER USER u SET app.api_key {op} '{m}';"),
            format!("ALTER FUNCTION s.f(int) SET app.password {op} '{m}';"),
            format!("ALTER PROCEDURE p() SET app.password {op} '{m}';"),
            format!(
                "CREATE FUNCTION f() RETURNS int LANGUAGE sql SET app.password {op} '{m}' \
                 AS $$SELECT 1$$;"
            ),
            format!(
                "CREATE FUNCTION f() RETURNS int SET app.token {op} '{m}' LANGUAGE sql \
                 AS $$SELECT 1$$;"
            ),
            format!(
                "CREATE PROCEDURE p() LANGUAGE plpgsql SET app.password {op} '{m}' \
                 AS $$BEGIN NULL; END$$;"
            ),
        ];
        for sql in &masked {
            if masked_under("postgres", sql, m) != (true, true) {
                wrong.push(format!("not masked: {sql}"));
            }
        }
        let shown = [
            format!("SET search_path {op} '{m}';"),
            format!("ALTER ROLE r SET search_path {op} '{m}';"),
            format!(
                "CREATE FUNCTION f() RETURNS int LANGUAGE sql SET search_path {op} '{m}' \
                 AS $$SELECT 1$$;"
            ),
        ];
        for sql in &shown {
            if masked_under("postgres", sql, m).0 {
                wrong.push(format!("masked: {sql}"));
            }
        }
        // What no walk shows safe is masked: another setting's value, a
        // literal a query selects.
        let unshown = [
            format!("ALTER DATABASE d SET app.tenant {op} '{m}';"),
            format!("SET app.password {op} DEFAULT; SELECT '{m}';"),
        ];
        for sql in &unshown {
            if !masked_under("postgres", sql, m).0 {
                wrong.push(format!("printed: {sql}"));
            }
        }
    }
    let from_current = format!("ALTER FUNCTION f() SET app.password FROM CURRENT; SELECT '{m}';");
    if !masked_under("postgres", &from_current, m).0 {
        wrong.push(format!("printed: {from_current}"));
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

#[test]
fn an_external_table_option_secret_is_masked_in_the_trace() {
    use lexega_core::analyzer::AnalysisConfig;
    use lexega_core::api::analyze_risk_with_policy_config;
    use lexega_core::dialect;

    let m = TSQL_MARK;
    for (name, sql) in [
        (
            "bigquery",
            format!("CREATE EXTERNAL TABLE d.t OPTIONS (format = 'CSV', password = '{m}');"),
        ),
        (
            "bigquery",
            format!(
                "CREATE EXTERNAL TABLE d.t WITH CONNECTION c \
                 OPTIONS (format = 'CSV', api_key = \"{m}\");"
            ),
        ),
        (
            "mssql",
            format!(
                "CREATE EXTERNAL TABLE t (a INT) WITH (LOCATION = '/p/', \
                 DATA_SOURCE = ds, FILE_FORMAT = ff, secret_key = '{m}');"
            ),
        ),
    ] {
        let cfg = AnalysisConfig {
            dialect: dialect::dialect_from_name(name),
            trace_mode: true,
            ..Default::default()
        };
        let report = analyze_risk_with_policy_config(&sql, &cfg).expect("should analyze");
        let json = serde_json::to_string(&report).expect("report serializes");
        assert!(!json.contains(m), "printed under --trace [{name}]: {sql}");
        // A format written in a slot the dialect shows is published.
        assert!(json.contains("format = 'CSV'") || name == "mssql", "{sql}");
    }
}

#[test]
fn a_secret_in_executed_sql_is_read_with_the_backslash_escapes_of_its_dialect() {
    use lexega_core::analyzer::AnalysisConfig;
    use lexega_core::api::analyze_risk_with_policy_config;
    use lexega_core::dialect;

    let m = TSQL_MARK;
    let forms = [
        (
            "snowflake",
            format!("EXECUTE IMMEDIATE 'CREATE USER u PASSWORD = \\'{m}\\'';"),
        ),
        (
            "snowflake",
            format!(
                "CREATE PROCEDURE p() RETURNS INT LANGUAGE SQL AS $$ BEGIN \
                 EXECUTE IMMEDIATE 'ALTER USER u SET PASSWORD = \\'{m}\\''; RETURN 1; END $$;"
            ),
        ),
        (
            "mysql",
            format!("PREPARE s FROM 'CREATE USER \\'u\\'@\\'h\\' IDENTIFIED BY \\'{m}\\'';"),
        ),
        (
            "bigquery",
            format!(
                "EXECUTE IMMEDIATE 'CREATE EXTERNAL TABLE d.t OPTIONS (password = \\'{m}\\')';"
            ),
        ),
        // A dialect whose plain strings keep a backslash.
        (
            "postgres",
            format!("DO $$ BEGIN EXECUTE E'CREATE ROLE zz PASSWORD \\'{m}\\''; END $$;"),
        ),
        (
            "mssql",
            format!("EXEC('CREATE LOGIN zz WITH PASSWORD = ''a\\{m}''')"),
        ),
        (
            "mssql",
            format!("EXEC sp_executesql N'CREATE LOGIN zz WITH PASSWORD = ''dom\\{m}'''"),
        ),
    ];
    for (name, sql) in &forms {
        let cfg = AnalysisConfig {
            dialect: dialect::dialect_from_name(name),
            trace_mode: true,
            ..Default::default()
        };
        let report = analyze_risk_with_policy_config(sql, &cfg).expect("should analyze");
        let json = serde_json::to_string(&report).expect("report serializes");
        assert!(
            !json.contains(&m[..6]),
            "printed under --trace [{name}]: {sql}"
        );
    }
    let first = dialect::dialect_from_name(forms[0].0).expect("known dialect");
    let shown = redact_secrets_for_display(&forms[0].1, &first);
    assert!(!shown.contains(&m[..6]), "{shown}");
    // Each masked value prints as one mask; every line keeps its number.
    assert_eq!(shown.lines().count(), forms[0].1.lines().count());
}

#[test]
fn a_secret_in_a_string_held_in_an_executed_variable_is_masked() {
    use lexega_core::analyzer::AnalysisConfig;
    use lexega_core::api::analyze_risk_with_policy_config;
    use lexega_core::dialect;

    let m = TSQL_MARK;
    let trace_json = |name: &str, sql: &str| {
        let cfg = AnalysisConfig {
            dialect: dialect::dialect_from_name(name),
            trace_mode: true,
            ..Default::default()
        };
        let report = analyze_risk_with_policy_config(sql, &cfg).expect("should analyze");
        serde_json::to_string(&report).expect("report serializes")
    };
    let masked = [
        (
            "snowflake",
            format!(
                "DECLARE q STRING DEFAULT 'CREATE USER u PASSWORD = ''{m}''';\n\
                 BEGIN\n  EXECUTE IMMEDIATE :q;\nEND;"
            ),
        ),
        (
            "snowflake",
            format!(
                "BEGIN\n  LET q STRING := 'CREATE USER u PASSWORD = \\'{m}\\'';\n  \
                 IF (TRUE) THEN\n    EXECUTE IMMEDIATE :q;\n  END IF;\nEND;"
            ),
        ),
        (
            "snowflake",
            format!(
                "DECLARE q STRING;\nBEGIN\n  q := 'ALTER USER u SET PASSWORD = ''{m}''';\n  \
                 EXECUTE IMMEDIATE q;\nEND;"
            ),
        ),
        (
            "snowflake",
            format!(
                "BEGIN\n  LET Qv STRING := 'CREATE USER u PASSWORD = ''{m}''';\n  \
                 EXECUTE IMMEDIATE :QV;\nEND;"
            ),
        ),
        (
            "snowflake",
            format!(
                "CREATE PROCEDURE p() RETURNS INT LANGUAGE SQL AS $$\nDECLARE\n  \
                 q STRING DEFAULT 'CREATE USER u PASSWORD = ''{m}''';\nBEGIN\n  \
                 EXECUTE IMMEDIATE :q;\n  RETURN 1;\nEND;\n$$;"
            ),
        ),
        (
            "mysql",
            format!(
                "SET @s = 'CREATE USER ''u''@''h'' IDENTIFIED BY ''{m}''';\nPREPARE s FROM @s;"
            ),
        ),
        (
            "mysql",
            format!(
                "SET @s := 'CREATE USER \\'u\\'@\\'h\\' IDENTIFIED BY \\'{m}\\'';\n\
                 PREPARE s FROM @s;\nEXECUTE s;"
            ),
        ),
        (
            "mssql",
            format!(
                "DECLARE @s NVARCHAR(200) = N'CREATE LOGIN zz WITH PASSWORD = ''{m}''';\n\
                 EXEC(@s);"
            ),
        ),
        (
            "mssql",
            format!(
                "CREATE PROCEDURE p AS\nBEGIN\n  DECLARE @S NVARCHAR(200);\n  \
                 SET @S = N'CREATE LOGIN zz WITH PASSWORD = ''{m}''';\n  \
                 EXEC sp_executesql @s;\nEND;"
            ),
        ),
        (
            "bigquery",
            format!(
                "DECLARE q STRING DEFAULT 'CREATE EXTERNAL TABLE d.t OPTIONS (password = \\'{m}\\')';\n\
                 EXECUTE IMMEDIATE q;"
            ),
        ),
        (
            "bigquery",
            format!(
                "DECLARE q STRING;\nSET q = 'CREATE EXTERNAL TABLE d.t OPTIONS (password = ''{m}'')';\n\
                 EXECUTE IMMEDIATE q;"
            ),
        ),
        (
            "postgres",
            format!(
                "DO $$ DECLARE q text := 'CREATE ROLE zz PASSWORD ''{m}''';\n\
                 BEGIN EXECUTE q; END $$;"
            ),
        ),
        (
            "postgres",
            format!(
                "CREATE FUNCTION f() RETURNS void LANGUAGE plpgsql AS $$\nDECLARE q text;\n\
                 BEGIN\n  q := 'CREATE ROLE zz PASSWORD ''{m}''';\n  EXECUTE q;\nEND $$;"
            ),
        ),
    ];
    for (name, sql) in &masked {
        let json = trace_json(name, sql);
        assert!(
            !json.contains(&m[..6]),
            "printed under --trace [{name}]: {sql}"
        );
    }
    // A variable no statement executes keeps its value printed.
    let printed = [
        (
            "snowflake",
            format!(
                "BEGIN\n  LET q STRING := 'CREATE USER u PASSWORD = ''{m}''';\n  \
                 LET r STRING := 'SELECT 1';\n  EXECUTE IMMEDIATE :r;\nEND;"
            ),
            m,
        ),
        (
            "mssql",
            format!(
                "DECLARE @s NVARCHAR(200) = N'CREATE LOGIN zz WITH PASSWORD = ''{m}''';\n\
                 SELECT @s;"
            ),
            m,
        ),
    ];
    for (name, sql, shown) in &printed {
        let json = trace_json(name, sql);
        assert!(
            !json.contains(shown),
            "printed under --trace [{name}]: {sql}"
        );
    }
    let first = dialect::dialect_from_name(masked[0].0).expect("known dialect");
    let shown = redact_secrets_for_display(&masked[0].1, &first);
    assert!(!shown.contains(&m[..6]), "{shown}");
    assert_eq!(shown.lines().count(), masked[0].1.lines().count());
}

#[test]
fn a_secret_in_a_piece_of_concatenated_sql_a_script_runs_is_masked() {
    use lexega_core::analyzer::AnalysisConfig;
    use lexega_core::api::analyze_risk_with_policy_config;
    use lexega_core::dialect;

    let m = TSQL_MARK;
    let report_json = |name: &str, sql: &str| {
        let cfg = AnalysisConfig {
            dialect: dialect::dialect_from_name(name),
            ..Default::default()
        };
        let report = analyze_risk_with_policy_config(sql, &cfg).expect("should analyze");
        serde_json::to_string(&report).expect("report serializes")
    };
    let declare = "DECLARE @n NVARCHAR(50) = 'x'\n";
    let login = format!("N'CREATE LOGIN zz WITH PASSWORD = ''{m}''; DELETE FROM dbo.u WHERE c = '");
    let masked = [
        (
            "mssql",
            format!("{declare}DECLARE @sql NVARCHAR(MAX) = {login} + @n\nEXEC (@sql)"),
        ),
        (
            "mssql",
            format!(
                "{declare}EXEC (N'ALTER LOGIN ' + @n + N' WITH PASSWORD = ''{m}''; \
                 DELETE FROM dbo.u WHERE c = ' + @n)"
            ),
        ),
        (
            "mssql",
            format!(
                "{declare}EXEC (N'DELETE FROM dbo.u; ALTER LOGIN ' + @n + \
                 N' WITH PASSWORD = ''{m}''')"
            ),
        ),
        (
            "mssql",
            format!("{declare}DECLARE @sql NVARCHAR(MAX)\nSELECT @sql = {login} + @n\nEXEC (@sql)"),
        ),
        (
            "mssql",
            format!(
                "{declare}DECLARE @sql NVARCHAR(MAX) = N''\n\
                 SET @sql = @sql + N'CREATE LOGIN zz WITH PASSWORD = ''{m}''; '\n\
                 SET @sql = @sql + N'SELECT ' + @n\nEXEC sp_executesql @sql"
            ),
        ),
        (
            "mssql",
            format!("{declare}DECLARE @sql NVARCHAR(MAX) = CONCAT({login}, @n)\nEXEC (@sql)"),
        ),
        (
            "mssql",
            format!(
                "CREATE PROCEDURE dbo.p @n NVARCHAR(50) AS BEGIN EXEC sp_executesql \
                 N'ALTER LOGIN ' + @n + N' WITH PASSWORD = ''{m}''' END\nGO"
            ),
        ),
        (
            "mssql",
            format!(
                "ALTER TRIGGER dbo.tr ON dbo.t AFTER INSERT AS BEGIN DECLARE @n NVARCHAR(50); \
                 SELECT @n = name FROM inserted; DECLARE @sql NVARCHAR(MAX) = {login} + @n; \
                 EXEC (@sql) END\nGO"
            ),
        ),
        (
            "mssql",
            format!("IF 1 = 1\nBEGIN\n  {declare}  EXEC ({login} + @n)\nEND"),
        ),
        (
            "snowflake",
            format!(
                "CREATE OR REPLACE PROCEDURE p(n STRING) RETURNS STRING LANGUAGE SQL AS $$ \
                 BEGIN EXECUTE IMMEDIATE 'ALTER USER ' || :n || ' SET PASSWORD = ''{m}'''; \
                 RETURN 'ok'; END; $$;"
            ),
        ),
        (
            "snowflake",
            format!(
                "BEGIN LET q := 'CREATE USER u PASSWORD = ''{m}''; SELECT ' || 'x'; \
                 EXECUTE IMMEDIATE :q; END;"
            ),
        ),
        (
            "postgres",
            format!(
                "DO $$ DECLARE n text := 'x'; BEGIN EXECUTE 'CREATE ROLE r PASSWORD ''{m}''; \
                 DELETE FROM u WHERE c = ' || quote_literal(n); END $$;"
            ),
        ),
        (
            "postgres",
            format!(
                "CREATE PROCEDURE pr(n text) LANGUAGE plpgsql AS $$ DECLARE q text; BEGIN \
                 q := 'ALTER ROLE ' || quote_ident(n) || ' PASSWORD ''{m}'''; EXECUTE q; END $$;"
            ),
        ),
        (
            "mysql",
            format!(
                "SET @n = 'x';\nSET @s = CONCAT('CREATE USER u IDENTIFIED BY ''{m}''; \
                 DELETE FROM t WHERE c = ', @n);\nPREPARE st FROM @s;"
            ),
        ),
    ];
    for (name, sql) in &masked {
        let json = report_json(name, sql);
        assert!(!json.contains(&m[..6]), "printed [{name}]: {sql}");
    }
    // A concatenation no statement executes stays printed.
    let printed = [(
        "mssql",
        format!("{declare}DECLARE @msg NVARCHAR(MAX) = N'PASSWORD = ''{m}'' ' + @n\nPRINT @msg"),
        m,
    )];
    for (name, sql, shown) in &printed {
        let json = trace_json_in(name, sql);
        assert!(
            !json.contains(shown),
            "printed under --trace [{name}]: {sql}"
        );
    }
}

#[test]
fn dynamic_sql_an_assignment_runs_is_masked_and_recognised_as_a_statement() {
    use lexega_core::analyzer::AnalysisConfig;
    use lexega_core::api::analyze_risk_with_policy_config;
    use lexega_core::dialect;

    let m = TSQL_MARK;
    let report_of = |sql: &str| {
        let cfg = AnalysisConfig {
            dialect: dialect::dialect_from_name("snowflake"),
            trace_mode: true,
            ..Default::default()
        };
        analyze_risk_with_policy_config(sql, &cfg).expect("should analyze")
    };
    let raised = |sql: &str| -> std::collections::BTreeSet<String> {
        report_of(sql)
            .findings
            .iter()
            .map(|s| match s {
                RuleMatch::Analysis(g) => g.matched_rule.clone(),
            })
            .collect()
    };
    let user = format!("'CREATE USER u PASSWORD = ''{m}'''");
    let forms = [
        format!(
            "DECLARE\n  q STRING DEFAULT {user};\n  res RESULTSET;\nBEGIN\n  \
             res := (EXECUTE IMMEDIATE :q);\n  RETURN TABLE(res);\nEND;"
        ),
        format!(
            "BEGIN\n  LET q STRING := {user};\n  LET res RESULTSET := (EXECUTE IMMEDIATE :q);\n  \
             RETURN TABLE(res);\nEND;"
        ),
        format!(
            "BEGIN\n  LET res RESULTSET := (EXECUTE IMMEDIATE {user});\n  RETURN TABLE(res);\nEND;"
        ),
        format!(
            "DECLARE\n  res RESULTSET DEFAULT (EXECUTE IMMEDIATE {user});\nBEGIN\n  \
             RETURN TABLE(res);\nEND;"
        ),
        format!("BEGIN\n  LET q STRING := {user};\n  RETURN TABLE(EXECUTE IMMEDIATE :q);\nEND;"),
        format!(
            "CREATE PROCEDURE p() RETURNS TABLE() LANGUAGE SQL AS $$\nDECLARE\n  \
             q STRING DEFAULT {user};\n  res RESULTSET;\nBEGIN\n  \
             res := (EXECUTE IMMEDIATE :q);\n  RETURN TABLE(res);\nEND;\n$$;"
        ),
    ];
    for sql in &forms {
        let json = serde_json::to_string(&report_of(sql)).expect("report serializes");
        assert!(!json.contains(&m[..6]), "printed under --trace: {sql}");
    }
    // The statement an assignment runs raises what the same statement
    // written on its own raises: `DYNSQL-NO-PARAM` at recognition depth, the
    // body's `TBL-DROP` with semantic analysis.
    let plain = "BEGIN\n  LET q STRING := 'DROP TABLE zz_x';\n  EXECUTE IMMEDIATE :q;\nEND;";
    let held = "BEGIN\n  LET q STRING := 'DROP TABLE zz_x';\n  \
                LET res RESULTSET := (EXECUTE IMMEDIATE :q);\n  RETURN TABLE(res);\nEND;";
    let assigned = "DECLARE\n  q STRING DEFAULT 'DROP TABLE zz_x';\n  res RESULTSET;\nBEGIN\n  \
                    res := (EXECUTE IMMEDIATE :q);\n  RETURN TABLE(res);\nEND;";
    let expected = raised(plain);
    assert!(
        (expected.contains("DYNSQL-NO-PARAM") && !expected.contains("DYNSQL"))
            || expected.contains("TBL-DROP"),
        "{expected:?}"
    );
    assert_eq!(raised(held), expected, "{held}");
    assert_eq!(raised(assigned), expected, "{assigned}");
}

#[test]
fn a_secret_a_plpgsql_select_assigns_into_strict_or_several_targets_is_masked() {
    use lexega_core::analyzer::AnalysisConfig;
    use lexega_core::api::analyze_risk_with_policy_config;
    use lexega_core::dialect;

    let m = TSQL_MARK;
    let role = format!("'CREATE ROLE zz PASSWORD ''{m}'''");
    let trace_json = |sql: &str| {
        let cfg = AnalysisConfig {
            dialect: dialect::dialect_from_name("postgres"),
            trace_mode: true,
            ..Default::default()
        };
        let report = analyze_risk_with_policy_config(sql, &cfg).expect("should analyze");
        serde_json::to_string(&report).expect("report serializes")
    };
    let masked = [
        format!("DO $$ DECLARE q text; BEGIN SELECT {role} INTO STRICT q; EXECUTE q; END $$;"),
        format!(
            "DO $$ DECLARE n int; q text; BEGIN SELECT 1, {role} INTO n, q; EXECUTE q; END $$;"
        ),
        format!(
            "CREATE FUNCTION f() RETURNS void LANGUAGE plpgsql AS $$ DECLARE q text; \
             BEGIN SELECT {role} INTO STRICT q; EXECUTE q; END $$;"
        ),
        format!(
            "CREATE PROCEDURE p() LANGUAGE plpgsql AS $$ DECLARE n int; q text; \
             BEGIN SELECT 1, {role} INTO n, q; EXECUTE q; END $$;"
        ),
    ];
    for sql in &masked {
        assert!(
            !trace_json(sql).contains(&m[..6]),
            "printed under --trace: {sql}"
        );
    }
    // The string a target no statement executes is printed.
    let printed = format!(
        "DO $$ DECLARE a text; b text; BEGIN SELECT {role}, 'SELECT 1' INTO STRICT a, b; \
         EXECUTE b; END $$;"
    );
    assert!(
        !trace_json(&printed).contains(&m[..6]),
        "what no walk shows is masked: {printed}"
    );
}

#[test]
fn a_secret_in_a_string_a_select_assigns_to_an_executed_variable_is_masked() {
    use lexega_core::analyzer::AnalysisConfig;
    use lexega_core::api::analyze_risk_with_policy_config;
    use lexega_core::dialect;

    let m = TSQL_MARK;
    let trace_json = |name: &str, sql: &str| {
        let cfg = AnalysisConfig {
            dialect: dialect::dialect_from_name(name),
            trace_mode: true,
            ..Default::default()
        };
        let report = analyze_risk_with_policy_config(sql, &cfg).expect("should analyze");
        serde_json::to_string(&report).expect("report serializes")
    };
    let login = format!("N'CREATE LOGIN zz WITH PASSWORD = ''{m}'''");
    let user = format!("'CREATE USER ''u''@''h'' IDENTIFIED BY ''{m}'''");
    let sf_user = format!("'CREATE USER u PASSWORD = ''{m}'''");
    let masked = [
        (
            "mssql",
            format!("DECLARE @s NVARCHAR(200);\nSELECT @s = {login};\nEXEC(@s);"),
        ),
        (
            "mssql",
            format!(
                "DECLARE @s NVARCHAR(200), @n INT;\nSELECT @n = 1, @S = {login};\n\
                 EXEC sp_executesql @s;"
            ),
        ),
        (
            "mssql",
            format!(
                "CREATE PROCEDURE p AS\nBEGIN\n  DECLARE @s NVARCHAR(200);\n  \
                 SELECT @s = {login};\n  EXEC(@s);\nEND;"
            ),
        ),
        ("mysql", format!("SELECT @s := {user};\nPREPARE s FROM @s;")),
        (
            "mysql",
            format!("SELECT {user} INTO @s;\nPREPARE s FROM @s;"),
        ),
        (
            "mysql",
            format!("SELECT 1, {user} INTO @n, @s;\nPREPARE s FROM @s;\nEXECUTE s;"),
        ),
        (
            "snowflake",
            format!(
                "DECLARE q STRING;\nBEGIN\n  SELECT {sf_user} INTO :q;\n  \
                 EXECUTE IMMEDIATE :q;\nEND;"
            ),
        ),
        (
            "postgres",
            format!(
                "DO $$ DECLARE q text;\nBEGIN SELECT 'CREATE ROLE zz PASSWORD ''{m}''' INTO q;\n\
                 EXECUTE q; END $$;"
            ),
        ),
    ];
    for (name, sql) in &masked {
        let json = trace_json(name, sql);
        assert!(
            !json.contains(&m[..6]),
            "printed under --trace [{name}]: {sql}"
        );
    }
    // A string assigned to a variable no statement executes keeps its value
    // printed, also beside one that is executed.
    let printed = [
        (
            "mssql",
            format!("DECLARE @s NVARCHAR(200);\nSELECT @s = {login};\nSELECT @s;"),
        ),
        (
            "mysql",
            format!("SELECT {user}, 'SELECT 1' INTO @a, @b;\nPREPARE s FROM @b;"),
        ),
    ];
    for (name, sql) in &printed {
        let json = trace_json(name, sql);
        assert!(!json.contains(m), "printed under --trace [{name}]: {sql}");
    }
}

#[test]
fn a_secret_in_a_snowflake_session_variable_run_as_dynamic_sql_is_masked() {
    use lexega_core::analyzer::AnalysisConfig;
    use lexega_core::api::analyze_risk_with_policy_config;

    let m = TSQL_MARK;
    let report_of = |sql: &str| {
        let cfg = AnalysisConfig {
            trace_mode: true,
            ..Default::default()
        };
        analyze_risk_with_policy_config(sql, &cfg).expect("should analyze")
    };
    let user = format!("'CREATE USER u PASSWORD = ''{m}'''");
    let masked = [
        format!("SET q = {user};\nEXECUTE IMMEDIATE $q;"),
        format!("SET (a, q) = ('x', {user});\nEXECUTE IMMEDIATE $q;"),
        format!("SET q = {user};\nBEGIN\n  EXECUTE IMMEDIATE $q;\nEND;"),
        format!("SET Q = {user};\nEXECUTE IMMEDIATE $q;"),
        format!(
            "SET q = {user};\nBEGIN\n  LET res RESULTSET := (EXECUTE IMMEDIATE $q);\n  \
             RETURN TABLE(res);\nEND;"
        ),
    ];
    for sql in &masked {
        let json = serde_json::to_string(&report_of(sql)).expect("report serializes");
        assert!(!json.contains(&m[..6]), "printed under --trace: {sql}");
    }
    // A session variable no statement executes keeps its value printed.
    let shown = format!("SET q = {user};\nSELECT $q;");
    let json = serde_json::to_string(&report_of(&shown)).expect("report serializes");
    assert!(!json.contains(m), "printed under --trace: {shown}");
    // Executing one is recognised as before.
    let run = rule_ids("SET q = 'DROP TABLE t';\nEXECUTE IMMEDIATE $q;");
    assert!(
        run.contains("DYNSQL-NO-PARAM") && !run.contains("DYNSQL"),
        "{run:?}"
    );
}

/// The PostgreSQL report of `sql` under `--trace`, serialized.
fn postgres_trace_json(sql: &str) -> String {
    use lexega_core::analyzer::AnalysisConfig;
    use lexega_core::api::analyze_risk_with_policy_config;

    let cfg = AnalysisConfig {
        dialect: lexega_core::dialect::dialect_from_name("postgres"),
        trace_mode: true,
        ..Default::default()
    };
    let report = analyze_risk_with_policy_config(sql, &cfg).expect("should analyze");
    serde_json::to_string(&report).expect("report serializes")
}

#[test]
fn a_dblink_connection_string_secret_is_never_printed_under_trace() {
    let m = TSQL_MARK;
    let cs = format!("'host=h password={m}'");
    let printed: Vec<String> = [
        "SELECT * FROM dblink({cs}, 'SELECT 1') AS t;",
        "SELECT * FROM public.dblink({cs}, 'SELECT 1') AS t;",
        "SELECT * FROM dblink({cs}, 'SELECT 1');",
        "SELECT * FROM dblink_exec({cs}, 'DELETE FROM u') AS t;",
        "SELECT * FROM dblink_connect('c', {cs}) AS t;",
        "SELECT * FROM dblink_connect_u({cs}) AS t;",
        "SELECT * FROM dblink({cs}, 'SELECT 1') t JOIN u ON t.id = u.id;",
        "SELECT * FROM u, LATERAL dblink({cs}, 'SELECT 1') AS t;",
        "DELETE FROM u WHERE id IN (SELECT id FROM dblink({cs}, 'SELECT 1') AS t);",
        "INSERT INTO u SELECT * FROM dblink({cs}, 'SELECT 1') AS t;",
        "SELECT dblink({cs}, 'SELECT 1');",
        "SELECT dblink_exec({cs}, 'DELETE FROM u');",
        "SELECT public.dblink_connect('c', {cs});",
        "SELECT dblink_connect_u({cs});",
        "SELECT x FROM u WHERE dblink_exec({cs}, 'SELECT 1') = 'OK';",
        "SELECT upper(dblink_connect('c', {cs})) FROM u ORDER BY 1;",
        // A column named by the expression's text.
        "SELECT count(*) FILTER (WHERE dblink_exec({cs}, 'x') = 'OK') FROM u;",
        "SELECT row_number() OVER (PARTITION BY dblink_exec({cs}, 'x')) FROM u;",
        "SELECT * FROM u, LATERAL (SELECT dblink_exec({cs}, 'x')) s;",
        // A column definition read without an expression parser.
        "CREATE TABLE z (a text DEFAULT dblink_exec({cs}, 'x'));",
        "CREATE TABLE z (a text CHECK (a <> dblink_exec({cs}, 'x')));",
        "CREATE INDEX i ON z ((dblink_exec({cs}, 'x')));",
        // Given by the parameter's name.
        "SELECT * FROM dblink(connstr => {cs}, sql => 'SELECT 1') AS t;",
        "SELECT dblink_connect(connname => 'c', connstr => {cs});",
        // A literal given to a name that names a secret.
        "SELECT * FROM fn(password => {cs}) AS t;",
    ]
    .iter()
    .map(|position| position.replace("{cs}", &cs))
    .filter(|sql| {
        postgres_trace_json(sql)
            .to_lowercase()
            .contains(&m.to_lowercase())
    })
    .collect();
    assert!(
        printed.is_empty(),
        "printed under --trace:\n{}",
        printed.join("\n")
    );
    // The SQL a dblink call runs is published as SQL an `EXECUTE` runs is:
    // its text, its literals masked.
    let run = format!("SELECT dblink('c', 'SELECT ''{m}'' FROM app.t');");
    let json = postgres_trace_json(&run);
    assert!(json.contains("FROM app.t"), "{run}\n{json}");
    assert!(!json.contains(m), "{run}\n{json}");
}

/// The report of `sql` under `--trace` in the dialect `name`, serialized.
fn trace_json_under(name: &str, sql: &str) -> String {
    use lexega_core::analyzer::AnalysisConfig;
    use lexega_core::api::analyze_risk_with_policy_config;

    let cfg = AnalysisConfig {
        dialect: lexega_core::dialect::dialect_from_name(name),
        trace_mode: true,
        ..Default::default()
    };
    let report = analyze_risk_with_policy_config(sql, &cfg).expect("should analyze");
    serde_json::to_string(&report).expect("report serializes")
}

#[test]
fn a_secret_an_exec_runs_or_is_given_is_never_printed_under_trace() {
    let m = TSQL_MARK;
    let login = format!("CREATE LOGIN zz WITH PASSWORD = ''{m}''");
    let execs = [
        format!("EXEC('{login}')"),
        format!("EXECUTE (N'{login}')"),
        format!("EXEC sp_executesql N'{login}'"),
        format!("EXEC dbo.zz_proc @password = '{m}'"),
        format!("EXEC sp_setapprole 'zz_r', '{m}'"),
    ];
    let mut forms: Vec<String> = Vec::new();
    for exec in &execs {
        forms.push(exec.clone());
        forms.push(format!("INSERT INTO #t {exec}"));
        forms.push(format!("INSERT INTO dbo.zz_t (id) {exec};"));
        forms.push(format!(
            "CREATE PROCEDURE dbo.zz_p AS\nBEGIN\n  INSERT INTO #t {exec}\nEND\nGO"
        ));
    }
    let printed: Vec<&String> = forms
        .iter()
        .filter(|sql| {
            trace_json_under("mssql", sql)
                .to_lowercase()
                .contains(&m.to_lowercase())
        })
        .collect();
    assert!(
        printed.is_empty(),
        "printed under --trace ({}):\n{}",
        printed.len(),
        printed
            .iter()
            .map(|s| s.as_str())
            .collect::<Vec<_>>()
            .join("\n")
    );
    // SQL text an EXEC runs is masked whatever it holds.
    let run = format!("EXEC('SELECT ''{m}'' AS s')");
    assert!(
        !trace_json_under("mssql", &run)
            .to_lowercase()
            .contains(&m.to_lowercase()),
        "printed: {run}"
    );
}

#[test]
fn a_table_function_called_in_from_is_no_table_read() {
    let sql = "SELECT * FROM public.dblink('host=h', 'SELECT 1') AS t;";
    let report: serde_json::Value =
        serde_json::from_str(&postgres_trace_json(sql)).expect("report is JSON");
    let query = &report["statement_traces"][0]["facts"]["query"];
    assert!(
        query["reads_table"].as_array().is_none_or(Vec::is_empty),
        "{query}"
    );
    let function = &query["scopes"][0]["table_functions"][0];
    assert_eq!(function["call"]["name"]["raw"], "public.dblink", "{query}");
    // dblink named in a schema of the user's is a function of the user's,
    // which may run what it is passed: its literals are withheld.
    assert_ne!(
        function["call"]["args"][1]["literal"]["value"], "'SELECT 1'",
        "{query}"
    );
    assert_eq!(function["alias"]["raw"], "t", "{query}");
    // An argument given by name is published with its name, in the order written.
    let sql = "SELECT * FROM dblink(sql => 'SELECT 1', connstr => 'host=h') AS t;";
    let report: serde_json::Value =
        serde_json::from_str(&postgres_trace_json(sql)).expect("report is JSON");
    let call =
        &report["statement_traces"][0]["facts"]["query"]["scopes"][0]["table_functions"][0]["call"];
    assert_eq!(call["named_args"][0]["name"]["normalized"], "sql", "{call}");
    // dblink takes no argument by name: the call fits no form of it, and
    // what it runs of each is withheld.
    assert!(
        call["named_args"][0]["value"]["literal"]["value"].is_string(),
        "{call}"
    );
    assert_ne!(
        call["named_args"][0]["value"]["literal"]["value"], "'SELECT 1'",
        "{call}"
    );
    assert_eq!(
        call["named_args"][1]["name"]["normalized"], "connstr",
        "{call}"
    );
}

/// The report of `sql` under `--trace`, as JSON, in the dialect `name`.
fn trace_json_in(name: &str, sql: &str) -> String {
    use lexega_core::analyzer::AnalysisConfig;
    use lexega_core::api::analyze_risk_with_policy_config;
    let cfg = AnalysisConfig {
        dialect: lexega_core::dialect::dialect_from_name(name),
        trace_mode: true,
        ..Default::default()
    };
    let report = analyze_risk_with_policy_config(sql, &cfg).expect("should analyze");
    serde_json::to_string(&report).expect("report serializes")
}

#[test]
fn a_secret_in_sql_built_by_any_text_function_a_script_runs_is_masked() {
    let m = TSQL_MARK;
    let n = "DECLARE @n SYSNAME = 'x'\n";
    let masked = [
        // `+=` appends a piece.
        (
            "mssql",
            format!(
                "{n}DECLARE @sql NVARCHAR(MAX) = N'ALTER LOGIN ' + @n\n\
                 SET @sql += N' WITH PASSWORD = ''{m}'''\nEXEC (@sql)"
            ),
        ),
        // Variables run as the pieces of a concatenation.
        (
            "mssql",
            format!(
                "DECLARE @a NVARCHAR(MAX) = N'CREATE LOGIN zz WITH PASSWORD = ''{m}''; '\n\
                 DECLARE @b NVARCHAR(MAX) = N'SELECT 1'\nEXEC (@a + @b)"
            ),
        ),
        // CONCAT_WS, its separator a piece too.
        (
            "mssql",
            format!(
                "{n}EXEC (CONCAT_WS(N' ', N'ALTER LOGIN', @n, \
                 N'WITH PASSWORD = ''{m}'''))"
            ),
        ),
        (
            "snowflake",
            format!("EXECUTE IMMEDIATE CONCAT_WS(' ', 'ALTER USER u SET', 'PASSWORD = ''{m}''');"),
        ),
        // A template run through REPLACE.
        (
            "mssql",
            format!(
                "{n}DECLARE @t NVARCHAR(MAX) = N'ALTER LOGIN {{n}} WITH PASSWORD = ''{m}'''\n\
                 EXEC (REPLACE(@t, N'{{n}}', @n))"
            ),
        ),
        // The keyword and its value in neighbouring literals.
        (
            "mssql",
            format!("{n}EXEC (N'ALTER LOGIN ' + @n + N' WITH PASSWORD = ' + N'''{m}''')"),
        ),
        (
            "mssql",
            format!("{n}EXEC (N'ALTER LOGIN ' + @n + N' WITH PASSWORD = N''' + N'{m}' + N'''')"),
        ),
        (
            "postgres",
            format!("DO $$ BEGIN EXECUTE 'ALTER ROLE r PASSWORD ' || '''{m}'''; END $$;"),
        ),
        // PostgreSQL's format: the template's text, and a `%L` argument in
        // its place.
        (
            "postgres",
            format!(
                "DO $$ DECLARE n text := 'x'; BEGIN \
                 EXECUTE format('ALTER ROLE %I PASSWORD ''{m}''', n); END $$;"
            ),
        ),
        (
            "postgres",
            format!(
                "DO $$ DECLARE n text := 'x'; BEGIN \
                 EXECUTE format('ALTER ROLE %I PASSWORD %L', n, '{m}'); END $$;"
            ),
        ),
        // A procedure that takes a password by position, called in a piece.
        (
            "mssql",
            format!(
                "{n}EXEC (N'EXEC sp_addlinkedsrvlogin ''srv'', ''false'', NULL, ''u'', \
                 ''{m}''; SELECT ' + @n)"
            ),
        ),
        // An escape string piece, decoded as the lexer decodes it.
        (
            "postgres",
            format!(
                "DO $$ DECLARE n text := 'x'; BEGIN EXECUTE 'ALTER ROLE ' || quote_ident(n) \
                 || E' PASSWORD \\'{m}\\''; END $$;"
            ),
        ),
    ];
    for (name, sql) in &masked {
        let json = trace_json_in(name, sql);
        assert!(
            !json.contains(&m[..6]),
            "printed under --trace [{name}]: {sql}"
        );
    }
}

#[test]
fn a_literal_assigned_to_a_variable_named_for_a_secret_is_masked() {
    let m = TSQL_MARK;
    let masked = [
        (
            "mssql",
            format!("DECLARE @password NVARCHAR(100) = N'{m}'\nSELECT 1"),
        ),
        (
            "mssql",
            format!("DECLARE @n INT = 1, @token NVARCHAR(100) = N'{m}'\nSELECT 1"),
        ),
        (
            "mssql",
            format!("DECLARE @api_key VARCHAR(100)\nSET @api_key = '{m}'\nSELECT 1"),
        ),
        (
            "mssql",
            format!("DECLARE @pwd NVARCHAR(100)\nSELECT @pwd = N'{m}'\nSELECT 1"),
        ),
        ("snowflake", format!("SET PASSWORD = '{m}';")),
        ("snowflake", format!("SET (a, my_password) = ('x', '{m}');")),
        (
            "snowflake",
            format!("EXECUTE IMMEDIATE ' SET PASSWORD = ''{m}''';"),
        ),
        (
            "snowflake",
            format!("BEGIN LET secret STRING := '{m}'; RETURN 1; END;"),
        ),
        (
            "snowflake",
            format!("BEGIN LET my_password STRING; my_password := '{m}'; RETURN 1; END;"),
        ),
        (
            "postgres",
            format!("DO $$ DECLARE password text := '{m}'; BEGIN NULL; END $$;"),
        ),
        (
            "postgres",
            format!("DO $$ DECLARE api_key text; BEGIN SELECT '{m}' INTO api_key; END $$;"),
        ),
        ("mysql", format!("SET @password = '{m}';")),
        ("mysql", format!("SELECT '{m}' INTO @password;")),
        ("mysql", format!("SELECT @api_key := '{m}';")),
        ("bigquery", format!("DECLARE api_key STRING DEFAULT '{m}';")),
    ];
    for (name, sql) in &masked {
        let json = trace_json_in(name, sql);
        assert!(
            !json.contains(&m[..6]),
            "printed under --trace [{name}]: {sql}"
        );
    }
    // A variable's value is no place a walk shows safe, whatever its name;
    // a comparison's operand is.
    let json = trace_json_in(
        "mssql",
        "DECLARE @hint NVARCHAR(100)\n\
         SET @hint = (SELECT hint FROM dbo.t WHERE note = N'Zq9Open')",
    );
    assert!(json.contains("Zq9Open"), "a compared value is shown");
    let printed = [
        (
            "mssql",
            "DECLARE @name NVARCHAR(100) = N'Zq9Open'\nSELECT @name",
        ),
        ("snowflake", "SET my_var = 'Zq9Open';"),
    ];
    for (name, sql) in &printed {
        let json = trace_json_in(name, sql);
        assert!(
            !json.contains("Zq9Open"),
            "printed under --trace [{name}]: {sql}"
        );
    }
}

#[test]
fn a_secret_literal_in_parentheses_or_after_an_equals_initialiser_is_masked() {
    let m = TSQL_MARK;
    let masked = [
        (
            "postgres",
            format!("DO $$ DECLARE password text = '{m}'; BEGIN NULL; END $$;"),
        ),
        (
            "postgres",
            format!(
                "CREATE FUNCTION f() RETURNS void LANGUAGE plpgsql AS $$ \
                 DECLARE api_key CONSTANT text NOT NULL = '{m}'; BEGIN NULL; END $$;"
            ),
        ),
        (
            "mssql",
            format!("DECLARE @password NVARCHAR(100) = (N'{m}')\nSELECT 1"),
        ),
        (
            "mssql",
            format!("DECLARE @password NVARCHAR(100)\nSET @password = (N'{m}')\nSELECT 1"),
        ),
        (
            "snowflake",
            format!("BEGIN LET my_password STRING; my_password := ('{m}'); RETURN 1; END;"),
        ),
        ("snowflake", format!("SET my_password = (('{m}'));")),
        ("mysql", format!("SET @password = ('{m}');")),
        (
            "postgres",
            format!("DO $$ DECLARE password text; BEGIN password := ('{m}'); END $$;"),
        ),
    ];
    for (name, sql) in &masked {
        let json = trace_json_in(name, sql);
        assert!(
            !json.contains(&m[..6]),
            "printed under --trace [{name}]: {sql}"
        );
    }
    let printed = [
        (
            "postgres",
            "DO $$ DECLARE note text = 'Zq9Open'; BEGIN NULL; END $$;",
        ),
        (
            "mssql",
            "DECLARE @note NVARCHAR(100) = (N'Zq9Open')\nSELECT 1",
        ),
    ];
    for (name, sql) in &printed {
        let json = trace_json_in(name, sql);
        assert!(
            !json.contains("Zq9Open"),
            "printed under --trace [{name}]: {sql}"
        );
    }
}

#[test]
fn a_secret_whose_keyword_another_statement_or_variable_writes_is_masked() {
    let m = TSQL_MARK;
    let masked = [
        (
            "mssql",
            format!(
                "DECLARE @sql NVARCHAR(MAX) = N'ALTER LOGIN x WITH PASSWORD = '\n\
                 SET @sql += N'''{m}'''\nEXEC (@sql)"
            ),
        ),
        (
            "mssql",
            format!(
                "DECLARE @a NVARCHAR(MAX) = N'ALTER LOGIN x WITH PASSWORD = '\n\
                 DECLARE @b NVARCHAR(MAX) = N'''{m}'''\nEXEC (@a + @b)"
            ),
        ),
        (
            "postgres",
            format!(
                "DO $$ DECLARE n text := 'x'; p text := '{m}'; \
                 BEGIN EXECUTE format('ALTER ROLE %I PASSWORD %L', n, p); END $$;"
            ),
        ),
        (
            "snowflake",
            format!(
                "BEGIN LET q STRING := 'ALTER USER u SET PASSWORD = '; \
                 q := q || '''{m}'''; EXECUTE IMMEDIATE :q; END;"
            ),
        ),
        (
            "mysql",
            format!(
                "SET @a = 'ALTER USER u IDENTIFIED BY '; SET @b = '''{m}'''; \
                 SET @s = CONCAT(@a, @b); PREPARE st FROM @s; EXECUTE st;"
            ),
        ),
    ];
    for (name, sql) in &masked {
        let (json, _) = report_json_and_skipped(name, sql);
        assert!(!json.contains(&m[..6]), "printed [{name}]: {sql}");
    }
}

#[test]
fn a_secret_in_a_declaration_that_does_not_parse_is_masked() {
    let m = TSQL_MARK;
    let masked = [
        (
            "snowflake",
            format!("DECLARE password STRING DEFAULT '{m}' ||; BEGIN DELETE FROM zz_o; END;"),
        ),
        (
            "postgres",
            format!("DO $$ DECLARE password text := '{m}' ||; BEGIN DELETE FROM zz_o; END $$;"),
        ),
        (
            "mssql",
            format!("DECLARE @password NVARCHAR(100) = N'{m}' +\nDELETE FROM dbo.zz_o"),
        ),
        // An initialiser that does not start with the literal.
        (
            "snowflake",
            format!(
                "CREATE OR REPLACE PROCEDURE p() RETURNS INT LANGUAGE SQL AS $$ DECLARE password \
                 STRING DEFAULT CONCAT('{m}', ; BEGIN RETURN 1; END $$;"
            ),
        ),
        (
            "snowflake",
            format!(
                "CREATE OR REPLACE PROCEDURE p() RETURNS INT LANGUAGE SQL AS $$ DECLARE password \
                 STRING DEFAULT ('{m}' || ; BEGIN RETURN 1; END $$;"
            ),
        ),
        (
            "snowflake",
            format!(
                "CREATE OR REPLACE PROCEDURE p() RETURNS INT LANGUAGE SQL AS $$ DECLARE a, \
                 password STRING DEFAULT CONCAT('x', '{m}' ; BEGIN RETURN 1; END $$;"
            ),
        ),
        (
            "postgres",
            format!("DO $$ DECLARE password text := upper('{m}') +; BEGIN NULL; END $$;"),
        ),
        (
            "mssql",
            format!("DECLARE @password NVARCHAR(100) = UPPER(N'{m}') +\nSELECT 1"),
        ),
        (
            "mssql",
            format!("DECLARE @a INT = 1, @password NVARCHAR(100) = CONCAT(N'{m}', \nSELECT 1"),
        ),
        (
            "bigquery",
            format!("DECLARE password STRING DEFAULT CONCAT('{m}', ;\nSELECT 1;"),
        ),
        (
            "databricks",
            format!("DECLARE VARIABLE password STRING DEFAULT CONCAT('{m}', ;\nSELECT 1;"),
        ),
    ];
    for (name, sql) in &masked {
        let json = trace_json_in(name, sql);
        assert!(
            !json.contains(&m[..6]),
            "printed under --trace [{name}]: {sql}"
        );
    }
}

#[test]
fn a_databricks_declare_variable_names_the_variable_after_its_keywords() {
    let m = TSQL_MARK;
    let masked = [
        format!("DECLARE OR REPLACE VARIABLE api_key STRING DEFAULT '{m}';\nSELECT 1;"),
        format!("DECLARE VARIABLE api_key STRING DEFAULT '{m}';\nSELECT 1;"),
        format!("DECLARE OR REPLACE api_key STRING = '{m}';\nSELECT 1;"),
        format!("DECLARE OR REPLACE VARIABLE password DECIMAL(10, 2) DEFAULT '{m}';\nSELECT 1;"),
        format!("DECLARE VARIABLE api_key DEFAULT '{m}';\nSELECT 1;"),
        format!("DECLARE VARIABLE api_key = '{m}';\nSELECT 1;"),
        format!("DECLARE OR REPLACE VAR api_key = '{m}';\nSELECT 1;"),
    ];
    for sql in &masked {
        let json = trace_json_in("databricks", sql);
        assert!(!json.contains(&m[..6]), "printed under --trace: {sql}");
    }
    let printed = [
        (
            "databricks",
            "DECLARE VARIABLE note STRING DEFAULT 'Zq9Open';\nSELECT 1;",
        ),
        (
            "bigquery",
            "DECLARE variable STRING DEFAULT 'Zq9Open';\nSELECT 1;",
        ),
    ];
    for (name, sql) in &printed {
        let json = trace_json_in(name, sql);
        assert!(
            !json.contains("Zq9Open"),
            "printed under --trace [{name}]: {sql}"
        );
    }
}

#[test]
fn a_secret_named_variable_anywhere_in_a_declared_list_is_masked() {
    let m = TSQL_MARK;
    let masked = [
        (
            "mysql",
            format!(
                "CREATE PROCEDURE p() BEGIN DECLARE a, password VARCHAR(40) DEFAULT '{m}'; \
                 SELECT a; END"
            ),
        ),
        (
            "mysql",
            format!(
                "CREATE PROCEDURE p() BEGIN DECLARE a, b, api_key VARCHAR(40) DEFAULT ('{m}'); \
                 SELECT a; END"
            ),
        ),
        (
            "bigquery",
            format!("DECLARE a, password STRING DEFAULT '{m}';\nSELECT 1;"),
        ),
        (
            "databricks",
            format!("BEGIN DECLARE a, api_key STRING DEFAULT '{m}'; SELECT 1; END;"),
        ),
        (
            "databricks",
            format!("BEGIN DECLARE a, api_key STRING = '{m}'; SELECT 1; END;"),
        ),
        (
            "databricks",
            format!("DECLARE OR REPLACE VARIABLE a, api_key STRING DEFAULT '{m}';\nSELECT 1;"),
        ),
        (
            "snowflake",
            format!(
                "CREATE OR REPLACE PROCEDURE p() RETURNS INT LANGUAGE SQL AS $$ \
                 DECLARE a, password VARCHAR := '{m}'; BEGIN RETURN 1; END $$;"
            ),
        ),
        (
            "postgres",
            format!("DO $$ DECLARE a, password text = '{m}'; BEGIN NULL; END $$;"),
        ),
    ];
    for (name, sql) in &masked {
        let json = trace_json_in(name, sql);
        assert!(
            !json.contains(&m[..6]),
            "printed under --trace [{name}]: {sql}"
        );
    }
    let json = trace_json_in(
        "mysql",
        "CREATE PROCEDURE p() BEGIN DECLARE a, note VARCHAR(40) DEFAULT 'Zq9Open'; SELECT a; END",
    );
    assert!(!json.contains("Zq9Open"), "what no walk shows is masked");
}

#[test]
fn every_literal_a_secret_named_variables_value_holds_is_masked() {
    let m = TSQL_MARK;
    let masked = [
        (
            "bigquery",
            format!("DECLARE password STRING DEFAULT CONCAT('{m}', 'x');\nSELECT 1;"),
        ),
        (
            "bigquery",
            format!("DECLARE a, password STRING DEFAULT CONCAT('x', '{m}');\nSELECT 1;"),
        ),
        (
            "bigquery",
            format!("DECLARE api_key STRING;\nSET api_key = IF(true, '{m}', 'x');\nSELECT 1;"),
        ),
        (
            "snowflake",
            format!("BEGIN LET password STRING := 'x' || '{m}'; RETURN 1; END;"),
        ),
        (
            "snowflake",
            format!("SET my_password = UPPER(TRIM('{m}'));"),
        ),
        (
            "snowflake",
            format!(
                "CREATE OR REPLACE PROCEDURE p() RETURNS INT LANGUAGE SQL AS $$ \
                 DECLARE api_key VARCHAR DEFAULT COALESCE(NULL, '{m}'); BEGIN RETURN 1; END $$;"
            ),
        ),
        (
            "postgres",
            format!("DO $$ DECLARE password text := 'x' || '{m}'; BEGIN NULL; END $$;"),
        ),
        (
            "postgres",
            format!("DO $$ DECLARE password text = CAST('{m}' AS text); BEGIN NULL; END $$;"),
        ),
        (
            "postgres",
            format!(
                "DO $$ DECLARE password text; BEGIN \
                 password := CASE WHEN true THEN '{m}' ELSE 'y' END; END $$;"
            ),
        ),
        (
            "mssql",
            format!("DECLARE @password NVARCHAR(100) = N'x' + N'{m}'\nSELECT 1"),
        ),
        (
            "mssql",
            format!(
                "DECLARE @password NVARCHAR(100)\nSET @password = CONCAT(N'{m}', N'x')\nSELECT 1"
            ),
        ),
        (
            "mssql",
            format!("DECLARE @password NVARCHAR(100) = N''\nSET @password += N'{m}'\nSELECT 1"),
        ),
        (
            "mssql",
            format!("DECLARE @pwd NVARCHAR(100)\nSELECT @pwd = COALESCE(NULL, N'{m}')\nSELECT 1"),
        ),
        (
            "mssql",
            format!(
                "DECLARE @password_hint NVARCHAR(100)\n\
                 SET @password_hint = (SELECT hint FROM dbo.t WHERE note = N'{m}')"
            ),
        ),
        ("mysql", format!("SET @password = CONCAT('{m}', 'x');")),
        (
            "mysql",
            format!("SELECT CONCAT('{m}', 'x') INTO @password;"),
        ),
        ("mysql", format!("SELECT @api_key := CONCAT('{m}', 'x');")),
        (
            "mysql",
            format!(
                "CREATE PROCEDURE p() BEGIN DECLARE password VARCHAR(40) \
                 DEFAULT CONCAT('{m}', 'x'); SELECT 1; END"
            ),
        ),
        (
            "databricks",
            format!("BEGIN DECLARE api_key STRING DEFAULT concat('{m}', 'x'); SELECT 1; END;"),
        ),
        (
            "databricks",
            format!("BEGIN DECLARE api_key STRING; SET api_key = concat('{m}', 'x'); END;"),
        ),
        // A query the value runs, compared with the literal or bounded by it.
        (
            "snowflake",
            format!("BEGIN LET api_key STRING := (SELECT k FROM t WHERE note = '{m}'); END;"),
        ),
        (
            "postgres",
            format!(
                "DO $$ DECLARE password text; BEGIN \
                 password := (SELECT p FROM t WHERE c <> '{m}'); END $$;"
            ),
        ),
        (
            "databricks",
            format!(
                "BEGIN DECLARE api_key STRING; \
                 SET VAR api_key = (SELECT k FROM t WHERE note = '{m}'); END;"
            ),
        ),
        (
            "mysql",
            format!("SET @password = (SELECT p FROM t WHERE c > '{m}');"),
        ),
        (
            "bigquery",
            format!("DECLARE password STRING;\nSET password = (SELECT p FROM t WHERE c <= '{m}');"),
        ),
    ];
    for (name, sql) in &masked {
        let json = trace_json_in(name, sql);
        assert!(
            !json.contains(&m[..6]),
            "printed under --trace [{name}]: {sql}"
        );
    }
    // A variable's value is no place a walk shows safe, whatever its name;
    // a comparison's operand is, beside a secret-named variable too.
    let json = trace_json_in(
        "mssql",
        "DECLARE @pwd NVARCHAR(100)\nSELECT @pwd = hint FROM dbo.t WHERE note = N'Zq9Open'",
    );
    assert!(json.contains("Zq9Open"), "a compared value is shown");
    let printed = [
        (
            "mssql",
            "DECLARE @note NVARCHAR(100) = N'x' + N'Zq9Open'\nSELECT @note",
        ),
        (
            "bigquery",
            "DECLARE note STRING DEFAULT CONCAT('Zq9Open', 'x');\nSELECT 1;",
        ),
        (
            "mssql",
            "DECLARE @other NVARCHAR(100) = N'Zq9Open'\n\
             DECLARE @password NVARCHAR(100) = @other\nSELECT @password",
        ),
    ];
    for (name, sql) in &printed {
        let json = trace_json_in(name, sql);
        assert!(
            !json.contains("Zq9Open"),
            "printed under --trace [{name}]: {sql}"
        );
    }
}

#[test]
fn a_value_set_var_assigns_to_a_secret_named_variable_is_masked() {
    let m = TSQL_MARK;
    let masked = [
        (
            "databricks",
            format!("DECLARE VARIABLE api_key STRING;\nSET VAR api_key = concat('{m}', 'x');"),
        ),
        (
            "databricks",
            format!("DECLARE VARIABLE api_key STRING;\nSET VARIABLE api_key = upper('{m}');"),
        ),
        (
            "databricks",
            format!(
                "DECLARE VARIABLE api_key STRING; DECLARE VARIABLE note STRING;\n\
                 SET VAR note = 'a', api_key = concat('{m}', 'x'), note = 'c';"
            ),
        ),
        (
            "databricks",
            format!(
                "DECLARE VARIABLE api_key STRING;\nSET VAR session.api_key = concat('{m}', 'x');"
            ),
        ),
        (
            "databricks",
            format!("BEGIN DECLARE api_key STRING; SET VAR api_key = upper('{m}'); SELECT 1; END;"),
        ),
        (
            "snowflake",
            format!("SET VAR api_key = concat('{m}', 'x');"),
        ),
        (
            "bigquery",
            format!("DECLARE api_key STRING; SET VAR api_key = concat('{m}', 'x');"),
        ),
        ("mysql", format!("SET VAR api_key = concat('{m}', 'x');")),
        ("postgres", format!("SET VAR api_key = concat('{m}', 'x');")),
        ("mssql", format!("SET VAR api_key = concat('{m}', 'x')")),
    ];
    for (name, sql) in &masked {
        let json = trace_json_in(name, sql);
        assert!(
            !json.contains(&m[..6]),
            "printed under --trace [{name}]: {sql}"
        );
    }
    // A name naming no secret, and `SET var = …` naming `var`, print.
    let printed = [
        (
            "databricks",
            "DECLARE VARIABLE note STRING;\nSET VAR note = concat('Zq9Open', 'x');",
        ),
        ("databricks", "SET var = concat('Zq9Open', 'x');"),
        ("snowflake", "SET var = concat('Zq9Open', 'x');"),
        (
            "bigquery",
            "DECLARE var STRING; SET var = concat('Zq9Open', 'x');",
        ),
    ];
    for (name, sql) in &printed {
        let json = trace_json_in(name, sql);
        assert!(
            !json.contains("Zq9Open"),
            "printed under --trace [{name}]: {sql}"
        );
    }
}

#[test]
fn a_query_assigned_to_several_variables_one_named_for_a_secret_is_masked() {
    let m = TSQL_MARK;
    let masked = [
        (
            "snowflake",
            format!("SET (note, password) = (SELECT 'a', '{m}');"),
        ),
        (
            "snowflake",
            format!("SET (password, note) = (SELECT '{m}', 'a');"),
        ),
        (
            "bigquery",
            format!(
                "DECLARE note STRING; DECLARE password STRING;\n\
                 SET (note, password) = (SELECT AS STRUCT 'a', '{m}');"
            ),
        ),
        (
            "databricks",
            format!(
                "DECLARE VARIABLE note STRING; DECLARE VARIABLE api_key STRING;\n\
                 SET VAR (note, api_key) = (SELECT 'a', concat('{m}', 'x'));"
            ),
        ),
    ];
    for (name, sql) in &masked {
        let json = trace_json_in(name, sql);
        assert!(
            !json.contains(&m[..6]),
            "printed under --trace [{name}]: {sql}"
        );
    }
    let json = trace_json_in("snowflake", "SET (note, other) = (SELECT 'Zq9Open', 'y');");
    assert!(!json.contains("Zq9Open"), "what no walk shows is masked");
}

#[test]
fn reading_the_text_variables_build_is_linear_in_the_source() {
    // Each value written twice into the next would double the text at
    // every step were a variable's text copied where it is written; a
    // build run after every append would be read once per run.
    use lexega_core::analyzer::AnalysisConfig;
    use lexega_core::api::analyze_risk_with_policy_config;

    let measure = |n: usize| {
        let mut sql = String::from(
            "DECLARE @a NVARCHAR(MAX) = N'ALTER LOGIN x WITH PASSWORD = '\n\
             DECLARE @b NVARCHAR(MAX) = N''\n",
        );
        for _ in 0..n {
            sql.push_str("SET @b = @a + @a\nSET @a = @b + @b\n");
        }
        sql.push_str("EXEC (@a)\nDECLARE @sql NVARCHAR(MAX) = N'SELECT 1'\n");
        for _ in 0..25 * n {
            sql.push_str("SET @sql += N' UNION ALL SELECT 1'\n");
        }
        sql.push_str("EXEC (@sql)\nDECLARE @s NVARCHAR(MAX) = N'SELECT 1'\n");
        for _ in 0..n {
            sql.push_str("SET @s += N' UNION ALL SELECT 1'\nEXEC (@s)\n");
        }
        let cfg = AnalysisConfig {
            dialect: lexega_core::dialect::dialect_from_name("mssql"),
            ..Default::default()
        };
        let started = std::time::Instant::now();
        let report = analyze_risk_with_policy_config(&sql, &cfg).expect("should analyze");
        assert!(report.summary.statements_parsed > 25 * n);
        started.elapsed()
    };
    let small = measure(10);
    let large = measure(40);
    assert!(
        large < small * 8 + std::time::Duration::from_millis(500),
        "four times the input took {large:?} against {small:?}"
    );
}

#[test]
fn a_secret_a_literal_quoter_writes_into_executed_sql_is_masked() {
    let m = TSQL_MARK;
    let masked = [
        (
            "mysql",
            format!(
                "SET @s = CONCAT('ALTER USER u IDENTIFIED BY ', QUOTE('{m}'));\n\
                 PREPARE st FROM @s;"
            ),
        ),
        (
            "postgres",
            format!(
                "DO $$ BEGIN EXECUTE 'ALTER ROLE r PASSWORD ' || quote_literal('{m}'); END $$;"
            ),
        ),
        (
            "postgres",
            format!(
                "DO $$ BEGIN EXECUTE 'ALTER ROLE r PASSWORD ' || quote_nullable('{m}'); END $$;"
            ),
        ),
        (
            "mssql",
            format!("EXEC (N'ALTER LOGIN zz WITH PASSWORD = ' + QUOTENAME(N'{m}', ''''))"),
        ),
    ];
    for (name, sql) in &masked {
        let json = trace_json_in(name, sql);
        assert!(
            !json.contains(&m[..6]),
            "printed under --trace [{name}]: {sql}"
        );
    }
    // An identifier quoted stays printed.
    let printed = [("mssql", "EXEC (N'SELECT * FROM ' + QUOTENAME(N'Zq9Open'))")];
    for (name, sql) in &printed {
        let json = trace_json_in(name, sql);
        assert!(
            !json.contains("Zq9Open"),
            "printed under --trace [{name}]: {sql}"
        );
    }
}

#[test]
fn a_value_assigned_to_a_secret_named_variable_in_text_not_parsed_is_masked() {
    let m = TSQL_MARK;
    // Text no reader parsed: an IF in an EXCEPTION handler, a body that does
    // not close, SQL an EXECUTE runs whose statement does not parse.
    let handler = |assignment: &str| {
        format!(
            "CREATE OR REPLACE PROCEDURE p() RETURNS INT LANGUAGE SQL AS $$ BEGIN RETURN 1; \
             EXCEPTION WHEN OTHER THEN IF (x = 1) THEN {assignment} END IF; RETURN 2; END $$;"
        )
    };
    let masked = [
        ("snowflake", handler(&format!("password := '{m}';"))),
        (
            "snowflake",
            handler(&format!("LET api_key := '{m}' || 'x';")),
        ),
        (
            "snowflake",
            handler(&format!("api_key := CONCAT('x', '{m}');")),
        ),
        (
            "snowflake",
            handler(&format!("SET my_password = CONCAT('x', '{m}');")),
        ),
        (
            "postgres",
            format!(
                "DO $$ BEGIN NULL; EXCEPTION WHEN others THEN IF x = 1 THEN \
                 password := '{m}'; END IF; END $$;"
            ),
        ),
        (
            "postgres",
            format!(
                "DO $$ BEGIN NULL; EXCEPTION WHEN others THEN IF x = 1 THEN \
                 api_key = upper('{m}'); END IF; END $$;"
            ),
        ),
        (
            "postgres",
            format!("DO $$ DECLARE password text DEFAULT '{m}'; BEGIN NULL; $$;"),
        ),
        (
            "postgres",
            format!("DO $$ DECLARE a int; api_key text := 'x' || '{m}'; BEGIN NULL; $$;"),
        ),
        (
            "snowflake",
            format!(
                "CREATE OR REPLACE PROCEDURE p() RETURNS INT LANGUAGE SQL AS $$ \
                 DECLARE a, password STRING DEFAULT '{m}'; BEGIN RETURN 1; $$;"
            ),
        ),
        (
            "snowflake",
            format!("EXECUTE IMMEDIATE 'SET VAR api_key = ''{m}'' FROB';"),
        ),
        (
            "mssql",
            format!("EXEC ('SELECT @password = N''{m}'' + c FROB FROB')"),
        ),
        (
            "mssql",
            format!("EXEC ('SET @password += N''{m}'' FROB FROB')"),
        ),
    ];
    for (name, sql) in &masked {
        let json = trace_json_in(name, sql);
        assert!(
            !json.contains(&m[..6]),
            "printed under --trace [{name}]: {sql}"
        );
    }
}

#[test]
fn a_secret_an_update_assigns_to_a_variable_is_masked() {
    let m = TSQL_MARK;
    let masked = [
        format!(
            "DECLARE @password NVARCHAR(100)\nUPDATE dbo.t SET @password = N'{m}', c = 1 WHERE id = 1"
        ),
        format!("DECLARE @api_key NVARCHAR(100)\nUPDATE dbo.t SET c = 1, @api_key = N'{m}' + c"),
        format!(
            "CREATE PROCEDURE p AS BEGIN DECLARE @pwd NVARCHAR(100); \
             UPDATE dbo.t SET @pwd = UPPER(N'{m}') WHERE id = 1; END"
        ),
    ];
    for sql in &masked {
        let json = trace_json_in("mssql", sql);
        assert!(!json.contains(&m[..6]), "printed under --trace: {sql}");
    }
    // Any variable's value is masked: no catalog types a variable.
    let json = trace_json_in(
        "mssql",
        "DECLARE @note NVARCHAR(100)\nUPDATE dbo.t SET @note = N'Zq9Open' WHERE id = 1",
    );
    assert!(!json.contains("Zq9Open"), "printed under --trace");
}

#[test]
fn reading_assignments_in_text_not_parsed_is_linear_in_the_source() {
    // One `;`-less run of many secret-named names, each assigned, and a
    // declaration list naming many: each value read once.
    let measure = |n: usize| {
        let assignments: String = (0..n)
            .map(|i| format!("password{i} = 'v{i}' AND "))
            .collect();
        let names: String = (0..n).map(|i| format!("api_key{i}, ")).collect();
        let sql = format!(
            "DO $$ BEGIN NULL; EXCEPTION WHEN others THEN IF x = 1 THEN \
             x := {assignments}1; END IF; END $$;\n\
             DO $$ DECLARE {names}z text DEFAULT 'v'; BEGIN NULL; $$;"
        );
        let started = std::time::Instant::now();
        let json = trace_json_in("postgres", &sql);
        assert!(!json.contains(&format!("'v{}'", n - 1)));
        started.elapsed()
    };
    let small = measure(2000);
    let large = measure(8000);
    assert!(
        large < small * 8 + std::time::Duration::from_millis(500),
        "four times the input took {large:?} against {small:?}"
    );
}

#[test]
fn a_variable_written_into_several_runs_is_read_in_each() {
    // A variable's text is read in every run and every variable that
    // writes it, joined with what follows it there.
    let m = TSQL_MARK;
    let masked = [
        (
            "postgres",
            format!(
                "DO $$ DECLARE a text := 'ALTER ROLE r PASSWORD '; BEGIN \
                 EXECUTE a || '''{m}1'''; EXECUTE a || '''{m}2'''; END $$;"
            ),
        ),
        (
            "mssql",
            format!(
                "DECLARE @a NVARCHAR(MAX) = N'ALTER LOGIN zz WITH PASSWORD = '\n\
                 EXEC (@a + N'''{m}1''')\nEXEC (@a + N'''{m}2''')"
            ),
        ),
        (
            "mssql",
            format!(
                "DECLARE @a NVARCHAR(MAX) = N'ALTER LOGIN zz WITH PASSWORD = '\n\
                 DECLARE @b NVARCHAR(MAX) = @a\nSET @a = @a + N'''{m}1'''\nEXEC (@a)"
            ),
        ),
        (
            "mssql",
            format!(
                "DECLARE @a NVARCHAR(MAX) = N'ALTER LOGIN zz WITH PASSWORD = '\n\
                 DECLARE @b NVARCHAR(MAX) = @a + N'''{m}1'''\n\
                 DECLARE @c NVARCHAR(MAX) = @a + N'''{m}2'''\nEXEC (@b)\nEXEC (@c)"
            ),
        ),
    ];
    for (name, sql) in &masked {
        let json = trace_json_in(name, sql);
        assert!(!json.contains(m), "printed under --trace [{name}]: {sql}");
    }
}

#[test]
fn a_value_of_many_literals_named_for_a_secret_is_read_in_linear_time() {
    // Every literal of a secret-named variable's value is a secret the run
    // masks: 64,000 distinct ones are gathered in time linear in their count.
    use lexega_core::analyzer::AnalysisConfig;
    use lexega_core::api::analyze_risk_with_policy_config;

    let measure = |n: usize| {
        let literals: Vec<String> = (0..n).map(|i| format!("'v{i}'")).collect();
        let sql = format!(
            "DECLARE password STRING DEFAULT CONCAT({});\nSELECT password;",
            literals.join(", ")
        );
        let cfg = AnalysisConfig {
            dialect: lexega_core::dialect::dialect_from_name("bigquery"),
            ..Default::default()
        };
        let started = std::time::Instant::now();
        analyze_risk_with_policy_config(&sql, &cfg).expect("should analyze");
        started.elapsed()
    };
    let small = measure(16_000);
    let large = measure(64_000);
    assert!(
        large < small * 8 + std::time::Duration::from_millis(500),
        "four times the input took {large:?} against {small:?}"
    );
}

#[test]
fn a_run_of_many_literals_a_script_runs_is_masked_in_linear_time() {
    // Each operand of one concatenation run as SQL holds a string literal
    // of that SQL: the run's literals are placed on its operands in time
    // linear in their count.
    let measure = |n: usize| {
        let operands: Vec<String> = (0..n).map(|i| format!("N'''v{i}'''")).collect();
        let sql = format!("EXEC (CONCAT({}))", operands.join(", "));
        let started = std::time::Instant::now();
        let (json, _) = report_json_and_skipped("mssql", &sql);
        assert!(
            json.contains("EXEC (CONCAT("),
            "the run's statement is quoted"
        );
        assert!(!json.contains("v0'"), "{json}");
        started.elapsed()
    };
    let small = measure(8_000);
    let large = measure(32_000);
    assert!(
        large < small * 8 + std::time::Duration::from_millis(500),
        "four times the input took {large:?} against {small:?}"
    );
}

#[test]
fn the_text_a_long_build_runs_is_read_in_linear_time() {
    // A concatenation of literals, variables and quoted values, and a
    // template of placeholders: one, four and sixteen times the size each
    // take time linear in it.
    let concat = |n: usize| {
        let operands: Vec<String> = (0..n)
            .map(|i| match i % 3 {
                0 => format!("N'v{i} '"),
                1 => format!("@p{}", i % 7),
                _ => format!("QUOTENAME(@q{}, '''')", i % 5),
            })
            .collect();
        ("mssql", format!("EXEC (CONCAT({}))", operands.join(", ")))
    };
    let template = |n: usize| {
        let template: String = (0..n).map(|i| format!("v{i} %s ")).collect();
        let args: Vec<String> = (0..n).map(|i| format!("p{}", i % 7)).collect();
        (
            "bigquery",
            format!(
                "EXECUTE IMMEDIATE FORMAT('{template}', {});",
                args.join(", ")
            ),
        )
    };
    let builds: [&dyn Fn(usize) -> (&'static str, String); 2] = [&concat, &template];
    for build in builds {
        let measure = |n: usize| {
            let (dialect, sql) = build(n);
            let started = std::time::Instant::now();
            report_json_and_skipped(dialect, &sql);
            started.elapsed()
        };
        let (x1, x4, x16) = (measure(500), measure(2_000), measure(8_000));
        let slack = std::time::Duration::from_millis(500);
        assert!(
            x4 < x1 * 8 + slack && x16 < x4 * 8 + slack,
            "{} took {x1:?}, {x4:?} and {x16:?} at one, four and sixteen times the size",
            build(1).1
        );
    }
}

const UNREAD_MARK: &str = "Zq9UnreadMark";

/// The report of `sql` under the dialect `name`, as JSON, with how many
/// statements it skips.
fn report_json_and_skipped(name: &str, sql: &str) -> (String, usize) {
    use lexega_core::analyzer::AnalysisConfig;
    use lexega_core::api::analyze_risk_with_policy_config;

    let cfg = AnalysisConfig {
        dialect: lexega_core::dialect::dialect_from_name(name),
        ..Default::default()
    };
    let report = analyze_risk_with_policy_config(sql, &cfg).expect("should analyze");
    let skipped = report.summary.statements_skipped;
    (
        serde_json::to_string(&report).expect("report serializes"),
        skipped,
    )
}

#[test]
fn every_string_literal_of_a_statement_not_parsed_is_masked_in_the_report() {
    let m = UNREAD_MARK;
    let handler = |statement: &str| {
        format!(
            "CREATE OR REPLACE PROCEDURE p() RETURNS INT LANGUAGE SQL AS $$ BEGIN RETURN 1; \
             EXCEPTION WHEN OTHER THEN IF (x = 1) THEN {statement} END IF; RETURN 2; END $$;"
        )
    };
    let unread = [
        (
            "snowflake",
            handler(&format!("LET api_key STRING := '{m}' +;")),
        ),
        (
            "snowflake",
            handler(&format!("LET api_key STRING DEFAULT '{m}' +;")),
        ),
        (
            "snowflake",
            handler(&format!("SELECT ('{m}' +) INTO :api_key;")),
        ),
        (
            "snowflake",
            handler(&format!("SET (a, password) = ('x', '{m}' +);")),
        ),
        (
            "snowflake",
            handler(&format!("LET note STRING := '{m}' +;")),
        ),
        (
            "postgres",
            format!(
                "DO $$ BEGIN NULL; EXCEPTION WHEN others THEN IF x = 1 THEN \
                 SELECT ('{m}' +) INTO api_key; END IF; END $$;"
            ),
        ),
        (
            "postgres",
            format!(
                "DO $$ BEGIN NULL; EXCEPTION WHEN others THEN IF x = 1 THEN \
                 SELECT ('{m}' +), 'x' INTO api_key, note; END IF; END $$;"
            ),
        ),
        (
            "snowflake",
            format!("BEGIN CASE (password || '{m}' ||) WHEN 1 THEN DELETE FROM t; END CASE; END;"),
        ),
        (
            "snowflake",
            format!("INSERT INTO creds (password) VALUES ('{m}' +);"),
        ),
        (
            "snowflake",
            format!("INSERT INTO t (note) VALUES ('{m}' +);"),
        ),
        ("snowflake", format!("INSERT INTO t (note) VALUES ('{m}")),
        (
            "mssql",
            format!("DECLARE @note NVARCHAR(100) = N'{m}' +\nDELETE FROM dbo.zz_o"),
        ),
        (
            "snowflake",
            format!("EXECUTE IMMEDIATE 'INSERT INTO t (note) VALUES (''{m}'' +)';"),
        ),
        (
            "postgres",
            format!("DO $$ DECLARE note text DEFAULT '{m}'; BEGIN NULL; $$;"),
        ),
        (
            "databricks",
            format!("DECLARE VARIABLE note STRING DEFAULT CONCAT('{m}', ;\nSELECT 1;"),
        ),
    ];
    let mut printed = Vec::new();
    for (name, sql) in &unread {
        let (json, skipped) = report_json_and_skipped(name, sql);
        assert!(skipped > 0, "nothing skipped [{name}]: {sql}");
        if json.contains(m) {
            printed.push(format!("[{name}] {sql}"));
        }
    }
    assert!(printed.is_empty(), "printed:\n{}", printed.join("\n"));
}

#[test]
fn a_secret_assigned_in_an_exception_handler_branch_is_masked_in_the_report() {
    let m = UNREAD_MARK;
    let handler = |statement: &str| {
        format!(
            "CREATE OR REPLACE PROCEDURE p() RETURNS INT LANGUAGE SQL AS $$ BEGIN RETURN 1; \
             EXCEPTION WHEN OTHER THEN IF (x = 1) THEN {statement} END IF; RETURN 2; END $$;"
        )
    };
    let read = [
        (
            "snowflake",
            handler(&format!("LET api_key STRING := '{m}';")),
        ),
        (
            "snowflake",
            handler(&format!("LET api_key STRING DEFAULT '{m}';")),
        ),
        (
            "snowflake",
            handler(&format!("SELECT '{m}' INTO :api_key;")),
        ),
        (
            "snowflake",
            handler(&format!("SET (a, password) = ('x', '{m}');")),
        ),
        (
            "postgres",
            format!(
                "DO $$ BEGIN NULL; EXCEPTION WHEN others THEN IF x = 1 THEN \
                 SELECT '{m}' INTO api_key; END IF; END $$;"
            ),
        ),
    ];
    let mut printed = Vec::new();
    for (name, sql) in &read {
        let (json, skipped) = report_json_and_skipped(name, sql);
        assert_eq!(skipped, 0, "skipped [{name}]: {sql}");
        if json.contains(m) {
            printed.push(format!("[{name}] {sql}"));
        }
    }
    assert!(printed.is_empty(), "printed:\n{}", printed.join("\n"));
}

#[test]
fn a_dollar_quoted_string_of_text_not_parsed_is_masked_in_the_report() {
    let m = UNREAD_MARK;
    let handler = |open: &str, value: &str| {
        format!(
            "DO {open} BEGIN NULL; EXCEPTION WHEN others THEN IF x = 1 THEN \
             INSERT INTO t VALUES ({value} +); END IF; END {open};"
        )
    };
    let unread = [
        ("postgres", handler("$$", &format!("$q${m}$q$"))),
        ("postgres", handler("$body$", &format!("$${m}$$"))),
        (
            "postgres",
            format!("INSERT INTO t (note) VALUES ($q${m}$q$ +);"),
        ),
        (
            "redshift",
            format!("INSERT INTO t (note) VALUES ($${m}$$ +);"),
        ),
        (
            "snowflake",
            format!("INSERT INTO t (note) VALUES ($${m}$$ +);"),
        ),
        (
            "snowflake",
            format!("INSERT INTO t (note) VALUES ($$ {m} $$ +);"),
        ),
        (
            "snowflake",
            format!("BEGIN CASE ($${m}$$ ||) WHEN 1 THEN DELETE FROM t; END CASE; END;"),
        ),
    ];
    let mut printed = Vec::new();
    for (name, sql) in &unread {
        let (json, skipped) = report_json_and_skipped(name, sql);
        assert!(skipped > 0, "nothing skipped [{name}]: {sql}");
        if json.contains(m) {
            printed.push(format!("[{name}] {sql}"));
        }
    }
    let run = [(
        "postgres",
        format!("DO $$ BEGIN EXECUTE 'UPDATE t SET note = $q${m}$q$'; END $$;"),
    )];
    for (name, sql) in &run {
        let (json, _) = report_json_and_skipped(name, sql);
        if json.contains(m) {
            printed.push(format!("[{name}] {sql}"));
        }
    }
    assert!(printed.is_empty(), "printed:\n{}", printed.join("\n"));
}

#[test]
fn every_string_literal_of_dynamic_sql_a_statement_runs_is_masked_in_the_report() {
    let m = UNREAD_MARK;
    let chain: String = (1..=20)
        .map(|i| format!("DECLARE @b{i} NVARCHAR(MAX) = @b{}\n", i - 1))
        .collect();
    let run = [
        (
            "mssql",
            format!(
                "DECLARE @b0 NVARCHAR(MAX) = N'ALTER LOGIN zz WITH PASSWORD = '\n{chain}\
                 EXEC (@b20 + N'''{m}1''')\nEXEC (@b20 + N'''{m}2''')"
            ),
        ),
        (
            "mssql",
            format!(
                "DECLARE @n SYSNAME = 'x'\n\
                 EXEC (N'ALTER LOGIN ' + @n + N' WITH PASSWORD = N''' + N'{m}' + N'''')"
            ),
        ),
        (
            "mssql",
            format!("EXEC (N'UPDATE dbo.t SET note = ' + N'''{m}''')"),
        ),
        (
            "mssql",
            format!("EXEC (N'UPDATE dbo.t SET note = ''{m}''')"),
        ),
        (
            "snowflake",
            format!("EXECUTE IMMEDIATE 'UPDATE t SET note = ''{m}''';"),
        ),
        (
            "mysql",
            format!("SET @s = 'SELECT ''{m}'' FROM t';\nPREPARE s FROM @s;"),
        ),
        (
            "mssql",
            format!(
                "DECLARE @n SYSNAME = 'x'\n\
                 EXEC (N'DELETE FROM dbo.u WHERE c = ''{m}'' AND d = ' + @n)"
            ),
        ),
        (
            "mssql",
            format!("DECLARE @n SYSNAME = 'x'\nEXEC (N'SELECT ' + N'''{m}''' + N' AS c, ' + @n)"),
        ),
        (
            "mssql",
            format!(
                "DECLARE @n SYSNAME = 'x'\nEXEC (CONCAT_WS(N' ', N'SELECT', N'''{m}''', \
                 N'AS c FROM dbo.t WHERE id =', @n))"
            ),
        ),
        (
            "postgres",
            format!(
                "DO $$ DECLARE n text := 'x'; BEGIN EXECUTE format('SELECT %L, %I', '{m}', n); \
                 END $$;"
            ),
        ),
        (
            "mssql",
            format!(
                "DECLARE @sql NVARCHAR(MAX) = N'SELECT 1'\nSET @sql += N' WHERE c = ''{m}'''\n\
                 EXEC (@sql)"
            ),
        ),
        (
            "mssql",
            format!(
                "DECLARE @sql NVARCHAR(MAX) = N'UPDATE dbo.t SET note = '\n\
                 SET @sql += N'''{m}'''\nEXEC (@sql)"
            ),
        ),
        (
            "mysql",
            format!("SET @s = CONCAT('SELECT ', QUOTE('{m}'));\nPREPARE st FROM @s;"),
        ),
    ];
    let mut printed = Vec::new();
    for (name, sql) in &run {
        let (json, _) = report_json_and_skipped(name, sql);
        if json.contains(m) {
            printed.push(format!("[{name}] {sql}"));
        }
    }
    assert!(printed.is_empty(), "printed:\n{}", printed.join("\n"));
}

#[test]
fn a_value_a_variable_writes_between_quotes_of_sql_a_script_runs_is_masked_in_the_report() {
    let m = UNREAD_MARK;
    let run = [
        (
            "mssql",
            format!(
                "CREATE PROCEDURE zz_p AS BEGIN DECLARE @p NVARCHAR(99) = N'{m}'; \
                 EXEC (N'ALTER LOGIN zz WITH PASSWORD = ''' + @p + N''''); END;"
            ),
        ),
        (
            "mssql",
            format!(
                "CREATE PROCEDURE zz_p AS BEGIN DECLARE @p NVARCHAR(99) = N'{m}'; \
                 DECLARE @s NVARCHAR(99) = N'CREATE LOGIN zz WITH PASSWORD = ''' + @p + N''''; \
                 EXEC (@s); END;"
            ),
        ),
        (
            "mssql",
            format!(
                "CREATE PROCEDURE zz_p AS BEGIN DECLARE @p NVARCHAR(99) = N'{m}'; \
                 EXEC (N'UPDATE dbo.t SET note = ''' + @p + N''''); END;"
            ),
        ),
        (
            "mssql",
            format!(
                "CREATE PROCEDURE zz_p AS BEGIN DECLARE @p NVARCHAR(99) = N'{m}'; \
                 DECLARE @q NVARCHAR(99) = @p; \
                 DECLARE @s NVARCHAR(99) = N'UPDATE dbo.t SET note = ''' + @q + N''''; \
                 EXEC (@s); END;"
            ),
        ),
        (
            "postgres",
            format!(
                "DO $$ DECLARE p text := '{m}'; BEGIN \
                 EXECUTE 'ALTER ROLE zz PASSWORD ''' || p || ''''; END $$;"
            ),
        ),
        (
            "postgres",
            format!(
                "CREATE FUNCTION f() RETURNS void AS $$ DECLARE p text := '{m}'; BEGIN \
                 EXECUTE 'ALTER ROLE zz PASSWORD ''' || p || ''''; END $$ LANGUAGE plpgsql;"
            ),
        ),
        (
            "postgres",
            format!(
                "CREATE FUNCTION f() RETURNS void AS $$ DECLARE p text := '{m}'; BEGIN \
                 EXECUTE 'UPDATE t SET note = ''' || p || ''''; END $$ LANGUAGE plpgsql;"
            ),
        ),
        (
            "mysql",
            format!(
                "CREATE PROCEDURE p() BEGIN SET @p = '{m}'; \
                 SET @s = CONCAT('ALTER USER zz IDENTIFIED BY ''', @p, ''''); \
                 PREPARE st FROM @s; EXECUTE st; END"
            ),
        ),
    ];
    let mut printed = Vec::new();
    for (name, sql) in &run {
        let (json, _) = report_json_and_skipped(name, sql);
        if json.contains(m) {
            printed.push(format!("[{name}] {sql}"));
        }
    }
    assert!(printed.is_empty(), "printed:\n{}", printed.join("\n"));
    // Written outside quotes, a variable's value is SQL, not a string of it.
    let (json, _) = report_json_and_skipped(
        "mssql",
        &format!(
            "CREATE PROCEDURE zz_p AS BEGIN DECLARE @n NVARCHAR(99) = N'{m}'; \
             EXEC (N'SELECT 1 AS ' + @n + N' FROM dbo.t'); END;"
        ),
    );
    assert!(!json.contains(m), "what no walk shows is masked: {json}");
}

#[test]
fn a_value_of_several_pieces_a_variable_writes_between_quotes_is_masked_in_the_report() {
    let m = UNREAD_MARK;
    let run = [
        (
            "postgres",
            format!(
                "DO $$ DECLARE p text := 'a' || '{m}'; BEGIN \
                 EXECUTE 'ALTER ROLE zz PASSWORD ''' || p || ''''; END $$;"
            ),
        ),
        (
            "mssql",
            format!(
                "CREATE PROCEDURE zz_p AS BEGIN DECLARE @p NVARCHAR(99) = N'{m}'; \
                 DECLARE @q NVARCHAR(99) = @p + N'x'; \
                 EXEC (N'ALTER LOGIN zz WITH PASSWORD = ''' + @q + N''''); END;"
            ),
        ),
        (
            "mssql",
            format!(
                "CREATE PROCEDURE zz_p AS BEGIN DECLARE @p NVARCHAR(99) = N'{m}'; \
                 DECLARE @q NVARCHAR(99) = N'x' + @p; \
                 DECLARE @s NVARCHAR(99) = N'UPDATE dbo.t SET note = ''' + @q + N''''; \
                 EXEC (@s); END;"
            ),
        ),
        (
            "mysql",
            format!(
                "CREATE PROCEDURE p() BEGIN SET @p = CONCAT('a', '{m}'); \
                 SET @s = CONCAT('ALTER USER zz IDENTIFIED BY ''', @p, ''''); \
                 PREPARE st FROM @s; EXECUTE st; END"
            ),
        ),
    ];
    let mut printed = Vec::new();
    for (name, sql) in &run {
        let (json, _) = report_json_and_skipped(name, sql);
        if json.contains(m) {
            printed.push(format!("[{name}] {sql}"));
        }
    }
    assert!(printed.is_empty(), "printed:\n{}", printed.join("\n"));
}

#[test]
fn values_built_over_a_chain_of_variables_are_masked_in_linear_time() {
    // Each run writes a variable built on the one before it: its pieces are
    // read in place up to a bound, so the work stays linear in the source.
    let pad = "x".repeat(100);
    let measure = |n: usize| {
        let mut sql = format!(
            "CREATE PROCEDURE zz_p AS BEGIN DECLARE @s0 NVARCHAR(MAX) = N'{UNREAD_MARK}';\n\
             EXEC (N'UPDATE dbo.t SET note = ''' + @s0 + N'''');\n"
        );
        for k in 1..n {
            sql.push_str(&format!(
                "DECLARE @s{k} NVARCHAR(MAX) = @s{} + N'{pad}';\n\
                 EXEC (N'UPDATE dbo.t SET note = ''' + @s{k} + N'''');\n",
                k - 1
            ));
        }
        sql.push_str("END;");
        let started = std::time::Instant::now();
        let (json, _) = report_json_and_skipped("mssql", &sql);
        assert!(!json.contains(UNREAD_MARK), "the value is masked");
        started.elapsed()
    };
    let small = measure(500);
    let large = measure(2_000);
    assert!(
        large < small * 8 + std::time::Duration::from_millis(500),
        "four times the input took {large:?} against {small:?}"
    );
}

const CALL_MARK: &str = "Zq9CallArgMark";
const CALL_PLAIN: &str = "Zq9CallArgPlain";

#[test]
fn the_argument_a_procedure_of_the_script_runs_as_sql_is_masked() {
    // (dialect, script, whether the plain value is printed). The procedure
    // runs a parameter as SQL, so the argument a call passes it in that
    // slot is SQL the script runs; an argument in another slot, or passed
    // to a procedure that runs none, is printed as written.
    let (m, p) = (CALL_MARK, CALL_PLAIN);
    let ms_run = "CREATE PROCEDURE dbo.zz_run @q NVARCHAR(MAX) AS BEGIN EXEC (@q); END;";
    let pg_run = "CREATE PROCEDURE zz_run(q text) LANGUAGE plpgsql AS $$ BEGIN EXECUTE q; END; $$;";
    let my_run =
        "CREATE PROCEDURE zz_run(IN n TEXT, IN q TEXT) BEGIN SET @s = q; PREPARE st FROM @s; EXECUTE st; END;";
    let cases: Vec<(&str, String, bool)> = vec![
        (
            "mssql",
            format!("{ms_run}\nEXEC dbo.zz_run @q = N'ALTER LOGIN zz WITH PASSWORD = ''{m}''';"),
            false,
        ),
        (
            "mssql",
            format!(
                "CREATE PROCEDURE dbo.zz_run @q NVARCHAR(MAX) AS BEGIN EXEC sp_executesql @q; END;\n\
                 EXEC zz_run N'ALTER LOGIN zz WITH PASSWORD = ''{m}''';"
            ),
            false,
        ),
        (
            "mssql",
            format!(
                "CREATE PROCEDURE dbo.zz_run @n NVARCHAR(99), @q NVARCHAR(MAX) AS BEGIN EXEC (@q); END;\n\
                 EXEC dbo.zz_run N'{p}', N'ALTER LOGIN zz WITH PASSWORD = ''{m}''';"
            ),
            false,
        ),
        (
            "mssql",
            format!(
                "{ms_run}\nDECLARE @c NVARCHAR(MAX) = N'ALTER LOGIN zz WITH PASSWORD = ''{m}''';\n\
                 EXEC dbo.zz_run @q = @c;"
            ),
            false,
        ),
        (
            "mssql",
            format!(
                "CREATE PROCEDURE dbo.zz_log @msg NVARCHAR(MAX) AS BEGIN PRINT @msg; END;\n\
                 EXEC dbo.zz_log N'{p}';"
            ),
            false,
        ),
        // Written into the text run: the argument is masked whole.
        (
            "mssql",
            format!(
                "CREATE PROCEDURE dbo.zz_run @q NVARCHAR(MAX) AS BEGIN \
                 EXEC (N'UPDATE dbo.t SET note = ''' + @q + N''''); END;\n\
                 EXEC dbo.zz_run @q = N'{m}';"
            ),
            false,
        ),
        // A procedure that passes its parameter to one that runs it runs it.
        (
            "mssql",
            format!(
                "{ms_run}\nCREATE PROCEDURE dbo.zz_relay @n NVARCHAR(99), @x NVARCHAR(MAX) AS \
                 BEGIN EXEC dbo.zz_run @q = @x; PRINT @n; END;\n\
                 EXEC dbo.zz_relay N'{p}', N'ALTER LOGIN zz WITH PASSWORD = ''{m}''';"
            ),
            false,
        ),
        (
            "postgres",
            format!("{pg_run}\nCALL zz_run('ALTER ROLE zz PASSWORD ''{m}''');"),
            false,
        ),
        (
            "postgres",
            format!("{pg_run}\nCALL zz_run('ALTER ROLE zz PASSWORD ''' || '{m}' || '''');"),
            false,
        ),
        (
            "postgres",
            format!(
                "{pg_run}\nDO $$ DECLARE c text := 'ALTER ROLE zz PASSWORD ''{m}'''; \
                 BEGIN CALL zz_run(c); END $$;"
            ),
            false,
        ),
        (
            "snowflake",
            format!(
                "CREATE PROCEDURE zz_run(q VARCHAR) RETURNS VARCHAR LANGUAGE SQL AS $$ BEGIN \
                 EXECUTE IMMEDIATE :q; RETURN 'x'; END; $$;\n\
                 CALL zz_run('ALTER USER zz SET PASSWORD = ''' || '{m}' || '''');"
            ),
            false,
        ),
        // No finding quotes a MySQL `CALL`.
        (
            "mysql",
            format!("{my_run}\nCALL zz_run('n', 'ALTER USER zz IDENTIFIED BY ''{m}''');"),
            false,
        ),
        (
            "mysql",
            format!(
                "{my_run}\nCALL zz_run('n', CONCAT('ALTER USER zz IDENTIFIED BY ''', '{m}', ''''));"
            ),
            false,
        ),
    ];
    let mut wrong = Vec::new();
    for (dialect, sql, plain_printed) in &cases {
        let (json, _) = report_json_and_skipped(dialect, sql);
        if json.contains(m) {
            wrong.push(format!("[{dialect}] the run argument is printed: {sql}"));
        }
        if json.contains(p) != *plain_printed {
            wrong.push(format!(
                "[{dialect}] the argument not run is {}: {sql}",
                if *plain_printed { "masked" } else { "printed" }
            ));
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

#[test]
fn the_argument_a_plpgsql_perform_passes_to_a_function_that_runs_it_is_masked() {
    // (script, whether the plain value is printed): PL/pgSQL's `PERFORM f(…)`
    // calls the function as `SELECT f(…)` does.
    let (m, p) = (CALL_MARK, CALL_PLAIN);
    let run = "CREATE FUNCTION zz_run(q text) RETURNS void LANGUAGE plpgsql AS $$ BEGIN EXECUTE q; END; $$;";
    let run2 = "CREATE FUNCTION zz_run2(n text, q text) RETURNS void LANGUAGE plpgsql AS $$ \
                BEGIN EXECUTE q; END; $$;";
    let log = "CREATE FUNCTION zz_log(q text) RETURNS void LANGUAGE plpgsql AS $$ \
               BEGIN RAISE NOTICE '%', q; END; $$;";
    let cases = [
        (
            format!("{run}\nDO $$ BEGIN PERFORM zz_run('ALTER ROLE zz PASSWORD ''{m}'''); END $$;"),
            false,
        ),
        (
            format!(
                "{run}\nDO $$ BEGIN IF true THEN PERFORM zz_run('ALTER ROLE zz PASSWORD ''{m}''') \
                 FROM users WHERE id = 1; END IF; END $$;"
            ),
            false,
        ),
        (
            format!(
                "{run}\nDO $$ BEGIN PERFORM zz_run('ALTER ROLE zz PASSWORD ''' || '{m}' || ''''); \
                 END $$;"
            ),
            false,
        ),
        (
            format!(
                "{run2}\nDO $$ BEGIN PERFORM zz_run2('{p}', 'ALTER ROLE zz PASSWORD ''{m}'''); END $$;"
            ),
            false,
        ),
        (format!("{log}\nDO $$ BEGIN PERFORM zz_log('{p}'); END $$;"), false),
    ];
    let mut wrong = Vec::new();
    for (sql, plain_printed) in &cases {
        let (json, skipped) = report_json_and_skipped("postgres", sql);
        assert_eq!(skipped, 0, "a statement skipped in {sql}");
        if json.contains(m) {
            wrong.push(format!("the run argument is printed: {sql}"));
        }
        if json.contains(p) != *plain_printed {
            wrong.push(format!(
                "the argument not run is {}: {sql}",
                if *plain_printed { "masked" } else { "printed" }
            ));
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

#[test]
fn the_argument_a_function_runs_is_masked_wherever_an_expression_calls_it() {
    // (script, whether the plain value is printed): the call is read in any
    // expression a statement evaluates, nested in another call or not.
    let (m, p) = (CALL_MARK, CALL_PLAIN);
    let run = "CREATE FUNCTION zz_fn(q text) RETURNS text LANGUAGE plpgsql AS $$ \
               BEGIN EXECUTE q; RETURN 'x'; END; $$;";
    let run2 = "CREATE FUNCTION zz_fn2(n text, q text) RETURNS text LANGUAGE plpgsql AS $$ \
                BEGIN EXECUTE q; RETURN 'x'; END; $$;";
    let log = "CREATE FUNCTION zz_log(q text) RETURNS text LANGUAGE plpgsql AS $$ \
               BEGIN RAISE NOTICE '%', q; RETURN q; END; $$;";
    let call = format!("zz_fn('ALTER ROLE zz PASSWORD ''{m}''')");
    let cases = [
        (
            format!("{run}\nDO $$ DECLARE r text; BEGIN r := {call}; END $$;"),
            false,
        ),
        (
            format!("{run}\nDO $$ DECLARE r text := {call}; BEGIN NULL; END $$;"),
            false,
        ),
        (
            format!("{run}\nDO $$ BEGIN PERFORM coalesce({call}, 'y'); END $$;"),
            false,
        ),
        (
            format!("{run}\nDO $$ BEGIN IF {call} IS NULL THEN RAISE NOTICE 'x'; END IF; END $$;"),
            false,
        ),
        (
            format!("{run}\nDO $$ BEGIN WHILE {call} = 'y' LOOP NULL; END LOOP; END $$;"),
            false,
        ),
        (
            format!(
                "{run}\nDO $$ BEGIN CASE WHEN {call} = 'x' THEN NULL; ELSE NULL; END CASE; END $$;"
            ),
            false,
        ),
        (
            format!(
                "{run2}\nDO $$ DECLARE r text; BEGIN \
                 r := coalesce(zz_fn2('{p}', 'ALTER ROLE zz PASSWORD ''{m}'''), 'y'); END $$;"
            ),
            false,
        ),
        (
            format!(
                "{log}\nDO $$ DECLARE r text; BEGIN r := zz_log('{p}'); \
                 IF zz_log('{p}') IS NULL THEN NULL; END IF; END $$;"
            ),
            false,
        ),
    ];
    let mut wrong = Vec::new();
    for (sql, plain_printed) in &cases {
        let (json, _) = report_json_and_skipped("postgres", sql);
        if json.contains(m) {
            wrong.push(format!("the run argument is printed: {sql}"));
        }
        if json.contains(p) != *plain_printed {
            wrong.push(format!(
                "the argument not run is {}: {sql}",
                if *plain_printed { "masked" } else { "printed" }
            ));
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

#[test]
fn the_argument_a_function_runs_is_masked_in_every_part_a_statement_holds() {
    // (dialect, script, whether the plain value is printed): an array a
    // loop iterates, the query a statement runs or writes out, an
    // assertion, a time-travel point, a filter, and what a definition holds.
    let (m, p) = (CALL_MARK, CALL_PLAIN);
    let pg_run = "CREATE FUNCTION zz_fn(q text) RETURNS text LANGUAGE plpgsql AS $$ \
                  BEGIN EXECUTE q; RETURN 'x'; END; $$;";
    let pg_log = "CREATE FUNCTION zz_log(q text) RETURNS text LANGUAGE plpgsql AS $$ \
                  BEGIN RAISE NOTICE '%', q; RETURN q; END; $$;";
    let bq_run = "CREATE PROCEDURE d.zz_fn(q STRING) BEGIN EXECUTE IMMEDIATE q; END;";
    let sf_run = "CREATE OR REPLACE PROCEDURE zz_fn(q STRING) RETURNS STRING LANGUAGE SQL AS \
                  BEGIN EXECUTE IMMEDIATE :q; RETURN 'x'; END;";
    let dbx_run =
        "CREATE PROCEDURE zz_fn(q STRING) LANGUAGE SQL AS BEGIN EXECUTE IMMEDIATE q; END;";
    let call = format!("zz_fn('SELECT ''{m}''')");
    let cases: Vec<(&str, String, bool)> = vec![
        (
            "postgres",
            format!("{pg_run}\nDO $$ BEGIN FOREACH x IN ARRAY ARRAY[{call}] LOOP NULL; END LOOP; END $$;"),
            false,
        ),
        ("postgres", format!("{pg_run}\nCOPY (SELECT {call}) TO STDOUT;"), false),
        ("postgres", format!("{pg_run}\nEXPLAIN ANALYZE SELECT {call};"), false),
        (
            "postgres",
            format!("{pg_run}\nCREATE POLICY zz_p ON orders USING ({call} IS NULL);"),
            false,
        ),
        (
            "postgres",
            format!("{pg_run}\nCREATE INDEX zz_i ON orders (id) WHERE {call} IS NULL;"),
            false,
        ),
        (
            "postgres",
            format!("{pg_run}\nDO $$ BEGIN ASSERT {call} IS NOT NULL; END $$;"),
            false,
        ),
        (
            "bigquery",
            format!("{bq_run}\nASSERT d.{call} IS NOT NULL AS 'x';"),
            false,
        ),
        (
            "bigquery",
            format!("{bq_run}\nBEGIN ASSERT d.{call} IS NOT NULL; END;"),
            false,
        ),
        (
            "snowflake",
            format!("{sf_run}\nCOPY INTO @zz_stage FROM (SELECT {call} v);"),
            false,
        ),
        (
            "snowflake",
            format!(
                "{sf_run}\nCREATE DATABASE zz_d2 CLONE zz_d1 AT (TIMESTAMP => {call}::timestamp);"
            ),
            false,
        ),
        ("databricks", format!("{dbx_run}\nCACHE TABLE zz_c AS SELECT {call} v;"), false),
        ("databricks", format!("{dbx_run}\nOPTIMIZE orders WHERE {call} IS NULL;"), false),
        (
            "databricks",
            format!("{dbx_run}\nRESTORE TABLE orders TO TIMESTAMP AS OF {call};"),
            false,
        ),
        (
            "postgres",
            format!(
                "{pg_log}\nDO $$ BEGIN FOREACH x IN ARRAY ARRAY[zz_log('{p}')] LOOP NULL; \
                 END LOOP; END $$;"
            ),
            false,
        ),
        (
            "postgres",
            format!("{pg_log}\nCOPY (SELECT zz_log('{p}')) TO '/tmp/zz_out.csv';"),
            false,
        ),
    ];
    let mut wrong = Vec::new();
    for (dialect, sql, plain_printed) in &cases {
        let (json, _) = report_json_and_skipped(dialect, sql);
        if json.contains(m) {
            wrong.push(format!("the run argument is printed: {sql}"));
        }
        if json.contains(p) != *plain_printed {
            wrong.push(format!(
                "the argument not run is {}: {sql}",
                if *plain_printed { "masked" } else { "printed" }
            ));
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

#[test]
fn the_argument_a_function_runs_is_masked_in_a_raise() {
    // (dialect, script, whether the plain value is printed): a RAISE's
    // format arguments and USING options, and BigQuery's message.
    let (m, p) = (CALL_MARK, CALL_PLAIN);
    let pg_run = "CREATE FUNCTION zz_fn(q text) RETURNS text LANGUAGE plpgsql AS $$ \
                  BEGIN EXECUTE q; RETURN 'x'; END; $$;";
    let pg_log = "CREATE FUNCTION zz_log(q text) RETURNS text LANGUAGE plpgsql AS $$ \
                  BEGIN RAISE NOTICE '%', q; RETURN q; END; $$;";
    let bq_run = "CREATE PROCEDURE d.zz_fn(q STRING) BEGIN EXECUTE IMMEDIATE q; END;";
    let call = format!("zz_fn('SELECT ''{m}''')");
    let cases: Vec<(&str, String, bool)> = vec![
        (
            "postgres",
            format!("{pg_run}\nDO $$ BEGIN RAISE NOTICE '%', {call}; END $$;"),
            false,
        ),
        (
            "postgres",
            format!("{pg_run}\nDO $$ BEGIN RAISE NOTICE '% %', 1, upper({call}); END $$;"),
            false,
        ),
        (
            "postgres",
            format!("{pg_run}\nDO $$ BEGIN RAISE NOTICE 'x' USING DETAIL = {call}; END $$;"),
            false,
        ),
        (
            "postgres",
            format!(
                "{pg_run}\nDO $$ BEGIN RAISE EXCEPTION USING MESSAGE = 'm', HINT := {call}; \
                 END $$;"
            ),
            false,
        ),
        (
            "bigquery",
            format!("{bq_run}\nBEGIN RAISE USING MESSAGE = d.{call}; END;"),
            false,
        ),
        (
            "postgres",
            format!("{pg_log}\nDO $$ BEGIN RAISE NOTICE '%', zz_log('{p}'); END $$;"),
            false,
        ),
        (
            "postgres",
            format!("{pg_log}\nDO $$ BEGIN RAISE NOTICE 'x' USING DETAIL = zz_log('{p}'); END $$;"),
            false,
        ),
    ];
    let mut wrong = Vec::new();
    for (dialect, sql, plain_printed) in &cases {
        let (json, _) = report_json_and_skipped(dialect, sql);
        if json.contains(m) {
            wrong.push(format!("the run argument is printed: {sql}"));
        }
        if json.contains(p) != *plain_printed {
            wrong.push(format!(
                "the argument not run is {}: {sql}",
                if *plain_printed { "masked" } else { "printed" }
            ));
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

#[test]
fn the_argument_a_function_runs_is_masked_in_an_assertions_message() {
    // (script, whether the plain value is printed): PL/pgSQL's `ASSERT
    // condition, message`, the call in the message.
    let (m, p) = (CALL_MARK, CALL_PLAIN);
    let pg_run = "CREATE FUNCTION zz_fn(q text) RETURNS text LANGUAGE plpgsql AS $$ \
                  BEGIN EXECUTE q; RETURN 'x'; END; $$;";
    let pg_log = "CREATE FUNCTION zz_log(q text) RETURNS text LANGUAGE plpgsql AS $$ \
                  BEGIN RAISE NOTICE '%', q; RETURN q; END; $$;";
    let cases = [
        (
            format!("{pg_run}\nDO $$ BEGIN ASSERT 1 = 1, zz_fn('SELECT ''{m}'''); END $$;"),
            false,
        ),
        (
            format!("{pg_log}\nDO $$ BEGIN ASSERT 1 = 1, zz_log('{p}'); END $$;"),
            false,
        ),
    ];
    let mut wrong = Vec::new();
    for (sql, plain_printed) in &cases {
        let (json, skipped) = report_json_and_skipped("postgres", sql);
        if json.contains(m) {
            wrong.push(format!("the run argument is printed: {sql}"));
        }
        if json.contains(p) != *plain_printed {
            wrong.push(format!(
                "the argument not run is {}: {sql}",
                if *plain_printed { "masked" } else { "printed" }
            ));
        }
        if skipped != 0 {
            wrong.push(format!("{skipped} statements not parsed: {sql}"));
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

#[test]
fn the_argument_a_function_runs_is_masked_in_a_tsql_condition() {
    // (script, whether the plain value is printed): a T-SQL IF's and
    // WHILE's condition, in a procedure and a trigger, and a subquery there.
    let (m, p) = (CALL_MARK, CALL_PLAIN);
    // The call sits inside a report's 80-character preview of its statement.
    let run = "CREATE FUNCTION dbo.f (@q NVARCHAR(MAX)) RETURNS INT AS BEGIN \
               EXEC (@q); RETURN 1; END;";
    let log = "CREATE FUNCTION dbo.zz_log (@q NVARCHAR(MAX)) RETURNS INT AS BEGIN \
               RETURN LEN(@q); END;";
    let call = format!("dbo.f(N'SELECT ''{m}''')");
    let cases = [
        (
            format!("{run}\nCREATE PROCEDURE dbo.p AS BEGIN IF {call} = 1 PRINT 'x'; END;"),
            false,
        ),
        (
            format!("{run}\nCREATE PROCEDURE dbo.p AS BEGIN WHILE {call} = 0 BREAK; END;"),
            false,
        ),
        (
            format!("{run}\nCREATE TRIGGER tr ON orders AFTER INSERT AS IF {call} = 1 PRINT 'x';"),
            false,
        ),
        (
            format!(
                "{run}\nCREATE PROCEDURE p AS BEGIN IF EXISTS (SELECT {call} FROM t) \
                 PRINT 'x'; END;"
            ),
            false,
        ),
        (
            format!(
                "{log}\nCREATE PROCEDURE dbo.p AS BEGIN IF dbo.zz_log(N'{p}') = 1 PRINT 'x'; END;"
            ),
            false,
        ),
    ];
    let mut wrong = Vec::new();
    for (sql, plain_printed) in &cases {
        let (json, _) = report_json_and_skipped("mssql", sql);
        if json.contains(m) {
            wrong.push(format!("the run argument is printed: {sql}"));
        }
        if json.contains(p) != *plain_printed {
            wrong.push(format!(
                "the argument not run is {}: {sql}",
                if *plain_printed { "masked" } else { "printed" }
            ));
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

#[test]
fn the_argument_a_function_runs_is_masked_in_a_rule() {
    // (script, whether the plain value is printed): a PostgreSQL rule's
    // command and its condition.
    let (m, p) = (CALL_MARK, CALL_PLAIN);
    let run = "CREATE FUNCTION f(q text) RETURNS text LANGUAGE plpgsql AS $$ \
               BEGIN EXECUTE q; RETURN 'x'; END; $$;";
    let log = "CREATE FUNCTION g(q text) RETURNS text LANGUAGE plpgsql AS $$ \
               BEGIN RAISE NOTICE '%', q; RETURN q; END; $$;";
    let cases = [
        (
            format!("{run}\nCREATE RULE r AS ON INSERT TO t DO ALSO SELECT f('SELECT ''{m}''');"),
            false,
        ),
        (
            format!("{run}\nCREATE RULE r AS ON INSERT TO t WHERE f('SELECT ''{m}''') IS NULL DO NOTHING;"),
            false,
        ),
        (
            format!("{log}\nCREATE RULE r AS ON INSERT TO t DO ALSO SELECT g('{p}');"),
            false,
        ),
        (
            format!("{run}\nCREATE RULE r AS ON INSERT TO t DO (SELECT f('SELECT ''{m}'''); NOTIFY ch);"),
            false,
        ),
        (
            format!("{log}\nCREATE RULE r AS ON INSERT TO t DO (SELECT g('{p}'); NOTIFY ch, 'x');"),
            false,
        ),
    ];
    let mut wrong = Vec::new();
    for (sql, plain_printed) in &cases {
        let (json, _) = report_json_and_skipped("postgres", sql);
        if json.contains(m) {
            wrong.push(format!("the run argument is printed: {sql}"));
        }
        if json.contains(p) != *plain_printed {
            wrong.push(format!(
                "the argument not run is {}: {sql}",
                if *plain_printed { "masked" } else { "printed" }
            ));
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

#[test]
fn the_argument_a_function_runs_is_masked_in_a_trigger_alert_or_index() {
    // (dialect, script, whether the plain value is printed): a trigger's
    // WHEN, an alert's condition and an index's key.
    let (m, p) = (CALL_MARK, CALL_PLAIN);
    let pg_run = "CREATE FUNCTION f(q text) RETURNS text LANGUAGE plpgsql AS $$ \
                  BEGIN EXECUTE q; RETURN 'x'; END; $$;";
    let pg_log = "CREATE FUNCTION g(q text) RETURNS text LANGUAGE plpgsql AS $$ \
                  BEGIN RAISE NOTICE '%', q; RETURN q; END; $$;";
    let sf_run = "CREATE OR REPLACE PROCEDURE f(q STRING) RETURNS STRING LANGUAGE SQL AS \
                  BEGIN EXECUTE IMMEDIATE :q; RETURN 'x'; END;";
    let sf_log = "CREATE OR REPLACE PROCEDURE g(q STRING) RETURNS STRING LANGUAGE SQL AS \
                  BEGIN RETURN q; END;";
    let trigger = |call: &str| {
        format!(
            "CREATE TRIGGER t BEFORE UPDATE ON t FOR EACH ROW WHEN ({call} IS NULL) \
             EXECUTE FUNCTION h();"
        )
    };
    let cases = [
        (
            "postgres",
            format!("{pg_run}\n{}", trigger(&format!("f('SELECT ''{m}''')"))),
            false,
        ),
        ("postgres", format!("{pg_log}\n{}", trigger(&format!("g('{p}')"))), false),
        (
            "postgres",
            format!("{pg_run}\nCREATE INDEX i ON t ((f('SELECT ''{m}''')));"),
            false,
        ),
        (
            "postgres",
            format!(
                "{pg_run}\nCREATE INDEX i ON t (a, lower(f('SELECT ''{m}''')) text_pattern_ops DESC);"
            ),
            false,
        ),
        (
            "postgres",
            format!("{pg_log}\nCREATE INDEX i ON t ((g('{p}')));"),
            false,
        ),
        (
            "snowflake",
            format!(
                "{sf_run}\nCREATE ALERT a IF (EXISTS (SELECT f('SELECT ''{m}'''))) THEN SELECT 1;"
            ),
            false,
        ),
        (
            "snowflake",
            format!(
                "{sf_run}\nALTER ALERT a MODIFY CONDITION EXISTS (SELECT f('SELECT ''{m}'''));"
            ),
            false,
        ),
        (
            "snowflake",
            format!("{sf_log}\nCREATE ALERT a IF (EXISTS (SELECT g('{p}'))) THEN SELECT 1;"),
            false,
        ),
    ];
    let mut wrong = Vec::new();
    for (dialect, sql, plain_printed) in &cases {
        let (json, _) = report_json_and_skipped(dialect, sql);
        if json.contains(m) {
            wrong.push(format!("the run argument is printed: {sql}"));
        }
        if json.contains(p) != *plain_printed {
            wrong.push(format!(
                "the argument not run is {}: {sql}",
                if *plain_printed { "masked" } else { "printed" }
            ));
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

#[test]
fn a_call_argument_is_read_as_the_statements_run_only_where_the_routine_runs_it_whole() {
    // (script, statements not parsed). The routine that runs the argument
    // whole reads it as the statements it runs; one that overwrites the
    // parameter first runs what it wrote, and a bare name over routines of
    // two schemas runs one or the other: there the argument is masked and
    // not read as statements.
    let print = "CREATE PROCEDURE dbo.zz_run @q NVARCHAR(MAX) AS BEGIN PRINT @q; END;";
    let run = "CREATE PROCEDURE audit.zz_run @q NVARCHAR(MAX) AS BEGIN EXEC (@q); END;";
    let overwrite = "CREATE PROCEDURE dbo.zz_run @q NVARCHAR(MAX) AS BEGIN \
                     SET @q = N'SELECT 1'; EXEC (@q); END;";
    let after = "CREATE PROCEDURE dbo.zz_run @q NVARCHAR(MAX) AS BEGIN \
                 EXEC (@q); SET @q = N'SELECT 1'; END;";
    let cases = [
        (
            format!("{print}\n{run}\nEXEC zz_run @q = N'hello world';"),
            0,
        ),
        (
            format!("{overwrite}\nEXEC dbo.zz_run @q = N'nightly cleanup';"),
            0,
        ),
        (
            format!("{run}\nEXEC zz_run @q = N'SELECT 1 FROM t WHERE';"),
            1,
        ),
        (
            format!("{after}\nEXEC dbo.zz_run @q = N'SELECT 1 FROM t WHERE';"),
            1,
        ),
    ];
    let mut wrong = Vec::new();
    for (sql, not_parsed) in &cases {
        let (_, skipped) = report_json_and_skipped("mssql", sql);
        if skipped != *not_parsed {
            wrong.push(format!("{skipped} not parsed, not {not_parsed}: {sql}"));
        }
    }
    let m = CALL_MARK;
    let secret = format!("N'ALTER LOGIN zz WITH PASSWORD = ''{m}'''");
    for sql in [
        format!("{print}\n{run}\nEXEC zz_run @q = {secret};"),
        format!("{overwrite}\nEXEC dbo.zz_run @q = {secret};"),
    ] {
        let (json, _) = report_json_and_skipped("mssql", &sql);
        if json.contains(m) {
            wrong.push(format!("the argument is printed: {sql}"));
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

#[test]
fn a_parameter_any_statement_assigns_before_the_run_is_not_the_calls_text() {
    // (dialect, script with `{t}` for the call's text, whether the routine
    // runs the call's text). Each statement that writes the parameter before
    // the run makes the text run its own, so a call's text that is not SQL
    // adds nothing not parsed to what valid SQL there leaves.
    let cases: Vec<(&str, &str, bool)> = vec![
        (
            "mssql",
            "CREATE PROCEDURE dbo.zz_run @q NVARCHAR(MAX) AS BEGIN DECLARE c CURSOR FOR \
             SELECT cmd FROM dbo.jobs; OPEN c; FETCH NEXT FROM c INTO @q; EXEC (@q); CLOSE c; \
             END;\nEXEC dbo.zz_run @q = N'{t}';",
            false,
        ),
        (
            "mssql",
            "CREATE PROCEDURE dbo.zz_run @q NVARCHAR(MAX) AS BEGIN \
             EXEC dbo.get_cmd @out = @q OUTPUT; EXEC (@q); END;\nEXEC dbo.zz_run @q = N'{t}';",
            false,
        ),
        (
            "mssql",
            "CREATE PROCEDURE dbo.zz_run @q NVARCHAR(MAX) AS BEGIN \
             EXEC sp_executesql N'SELECT @o = cmd FROM dbo.jobs', \
             N'@o NVARCHAR(MAX) OUTPUT', @o = @q OUTPUT; EXEC (@q); END;\n\
             EXEC dbo.zz_run @q = N'{t}';",
            false,
        ),
        (
            "mssql",
            "CREATE PROCEDURE dbo.zz_run @q NVARCHAR(MAX) AS BEGIN EXEC @q = dbo.get_cmd; \
             EXEC (@q); END;\nEXEC dbo.zz_run @q = N'{t}';",
            false,
        ),
        (
            "postgres",
            "CREATE PROCEDURE zz_run(q text) LANGUAGE plpgsql AS $$ DECLARE c refcursor; BEGIN \
             OPEN c FOR SELECT cmd FROM jobs; FETCH c INTO q; EXECUTE q; END $$;\n\
             CALL zz_run('{t}');",
            false,
        ),
        (
            "postgres",
            "CREATE PROCEDURE zz_run(q text) LANGUAGE plpgsql AS $$ BEGIN \
             EXECUTE 'SELECT cmd FROM jobs LIMIT 1' INTO q; EXECUTE q; END $$;\n\
             CALL zz_run('{t}');",
            false,
        ),
        (
            "postgres",
            "CREATE PROCEDURE zz_run(q text) LANGUAGE plpgsql AS $$ BEGIN \
             FOREACH q IN ARRAY ARRAY['SELECT 1'] LOOP EXECUTE q; END LOOP; END $$;\n\
             CALL zz_run('{t}');",
            false,
        ),
        (
            "mysql",
            "CREATE PROCEDURE zz_run(IN q TEXT) BEGIN DECLARE c CURSOR FOR SELECT cmd FROM jobs; \
             OPEN c; FETCH c INTO q; SET @s = q; PREPARE st FROM @s; END;\nCALL zz_run('{t}');",
            false,
        ),
        (
            "mysql",
            "CREATE PROCEDURE zz_run(IN q TEXT) BEGIN SET q = 'SELECT 1'; SET @s = q; \
             PREPARE st FROM @s; END;\nCALL zz_run('{t}');",
            false,
        ),
        (
            "mysql",
            "CREATE PROCEDURE zz_run(IN q TEXT) BEGIN SELECT 'SELECT 1' INTO q; SET @s = q; \
             PREPARE st FROM @s; END;\nCALL zz_run('{t}');",
            false,
        ),
        (
            "postgres",
            "CREATE PROCEDURE zz_run(q text) LANGUAGE plpgsql AS $$ BEGIN \
             FOR q IN SELECT cmd FROM jobs LOOP EXECUTE q; END LOOP; END $$;\n\
             CALL zz_run('{t}');",
            false,
        ),
        (
            "snowflake",
            "CREATE OR REPLACE PROCEDURE zz_run(q STRING) RETURNS STRING LANGUAGE SQL AS BEGIN \
             LET c CURSOR FOR SELECT cmd FROM jobs; OPEN c; FETCH c INTO q; \
             EXECUTE IMMEDIATE :q; RETURN 'x'; END;\nCALL zz_run('{t}');",
            false,
        ),
        (
            "bigquery",
            "CREATE PROCEDURE d.zz_run(q STRING) BEGIN DECLARE n INT64; \
             SET (q, n) = (SELECT AS STRUCT 'SELECT 1', 1); EXECUTE IMMEDIATE q; END;\n\
             CALL d.zz_run('{t}');",
            false,
        ),
        (
            "bigquery",
            "CREATE PROCEDURE d.zz_run(q STRING) BEGIN \
             EXECUTE IMMEDIATE 'SELECT cmd FROM d.jobs LIMIT 1' INTO q; EXECUTE IMMEDIATE q; END;\n\
             CALL d.zz_run('{t}');",
            false,
        ),
        (
            "mssql",
            "CREATE PROCEDURE dbo.zz_run @q NVARCHAR(MAX) AS BEGIN EXEC (@q); \
             EXEC dbo.get_cmd @out = @q OUTPUT; END;\nEXEC dbo.zz_run @q = N'{t}';",
            true,
        ),
        (
            "postgres",
            "CREATE PROCEDURE zz_run(q text) LANGUAGE plpgsql AS $$ BEGIN EXECUTE q; \
             EXECUTE 'SELECT 1' INTO q; END $$;\nCALL zz_run('{t}');",
            true,
        ),
    ];
    let mut wrong = Vec::new();
    for (dialect, script, runs_the_call) in &cases {
        let (_, valid) = report_json_and_skipped(dialect, &script.replace("{t}", "SELECT 1"));
        let (_, prose) =
            report_json_and_skipped(dialect, &script.replace("{t}", "nightly cleanup"));
        if (prose > valid) != *runs_the_call {
            wrong.push(format!(
                "{prose} not parsed against {valid} with valid SQL: {script}"
            ));
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

#[test]
fn text_assigned_in_one_routine_or_batch_is_not_read_as_another_ones_run() {
    // (dialect, script): a variable's text reaches only the statements of
    // the routine or the batch that assigns it, so none of these runs text
    // that is not SQL.
    let cases = [
        (
            "mssql",
            "CREATE PROCEDURE dbo.other @q NVARCHAR(MAX) AS BEGIN SET @q = N'x'; END;\n\
             CREATE PROCEDURE dbo.zz_run @q NVARCHAR(MAX) AS BEGIN EXEC (@q); END;\n\
             EXEC dbo.zz_run @q = N'SELECT 1';",
        ),
        (
            "mssql",
            "CREATE PROCEDURE dbo.other @q NVARCHAR(MAX) AS BEGIN SET @q = N'x'; END;\n\
             CREATE PROCEDURE dbo.zz_run @q NVARCHAR(MAX) AS BEGIN EXEC (@q); END;",
        ),
        (
            "mssql",
            "DECLARE @q NVARCHAR(MAX) = N'nightly cleanup';\n\
             CREATE PROCEDURE dbo.zz_run @q NVARCHAR(MAX) AS BEGIN EXEC (@q); END;",
        ),
        (
            "mssql",
            "CREATE PROCEDURE dbo.a @msg NVARCHAR(MAX) AS BEGIN SET @msg = N'job started'; \
             PRINT @msg; END;\nGO\n\
             CREATE PROCEDURE dbo.b @msg NVARCHAR(MAX) AS BEGIN EXEC (@msg); END;\nGO",
        ),
        (
            "mssql",
            "DECLARE @q NVARCHAR(MAX) = N'nightly cleanup';\nPRINT @q;\nGO\n\
             DECLARE @x INT = 1;\nEXEC (@q);",
        ),
        (
            "postgres",
            "CREATE FUNCTION other(q text) RETURNS void LANGUAGE plpgsql AS $$ \
             BEGIN q := 'nightly cleanup'; END $$;\n\
             CREATE PROCEDURE zz_run(q text) LANGUAGE plpgsql AS $$ BEGIN EXECUTE q; END $$;",
        ),
        (
            "postgres",
            "DO $$ DECLARE q text := 'nightly cleanup'; BEGIN RAISE NOTICE '%', q; END $$;\n\
             DO $$ BEGIN EXECUTE q; END $$;",
        ),
        (
            "snowflake",
            "CREATE OR REPLACE PROCEDURE log_msg(msg STRING) RETURNS STRING LANGUAGE SQL AS \
             BEGIN msg := 'job started'; RETURN msg; END;\n\
             CREATE OR REPLACE PROCEDURE run_it(msg STRING) RETURNS STRING LANGUAGE SQL AS \
             BEGIN EXECUTE IMMEDIATE :msg; RETURN 'x'; END;",
        ),
    ];
    let mut wrong = Vec::new();
    for (dialect, sql) in &cases {
        let (_, skipped) = report_json_and_skipped(dialect, sql);
        if skipped != 0 {
            wrong.push(format!("{skipped} not parsed: {sql}"));
        }
    }
    // Text assigned and run in the same batch or routine is still read.
    let (_, skipped) = report_json_and_skipped(
        "mssql",
        "DECLARE @q NVARCHAR(MAX) = N'SELECT 1 FROM t WHERE';\nEXEC (@q);",
    );
    if skipped != 1 {
        wrong.push(format!(
            "{skipped} not parsed where the batch runs its own text"
        ));
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

#[test]
fn a_session_variable_s_text_reaches_every_routine_and_batch_of_the_script() {
    use lexega_core::analyzer::AnalysisConfig;
    use lexega_core::api::analyze_risk_with_policy_config;

    let m = TSQL_MARK;
    let user = format!("ALTER USER z IDENTIFIED BY ''{m}''");
    let mysql_run = "CREATE PROCEDURE b() BEGIN PREPARE st FROM @s; EXECUTE st; END;";
    let snowflake_run = "CREATE OR REPLACE PROCEDURE b() RETURNS STRING LANGUAGE SQL AS \
                         BEGIN EXECUTE IMMEDIATE $s; RETURN 'x'; END;";
    let masked = [
        (
            "mysql",
            format!("CREATE PROCEDURE a() BEGIN SET @s = '{user}'; CALL b(); END;\n{mysql_run}"),
        ),
        ("mysql", format!("SET @s = '{user}';\n{mysql_run}")),
        (
            "mysql",
            format!(
                "CREATE PROCEDURE a() BEGIN SET @S = '{user}'; END;\nCREATE PROCEDURE c() BEGIN \
                 SET @t = 1; END;\n{mysql_run}"
            ),
        ),
        (
            "snowflake",
            format!(
                "CREATE OR REPLACE PROCEDURE a() RETURNS STRING LANGUAGE SQL AS \
                 BEGIN SET s = '{user}'; RETURN 'x'; END;\n{snowflake_run}"
            ),
        ),
        ("snowflake", format!("SET s = '{user}';\n{snowflake_run}")),
    ];
    for (dialect, sql) in &masked {
        for trace_mode in [false, true] {
            let cfg = AnalysisConfig {
                dialect: lexega_core::dialect::dialect_from_name(dialect),
                trace_mode,
                ..Default::default()
            };
            let report = analyze_risk_with_policy_config(sql, &cfg).expect("should analyze");
            let json = serde_json::to_string(&report).expect("report serializes");
            assert!(
                !json.contains(m),
                "{dialect} prints the secret (trace {trace_mode}): {sql}"
            );
        }
    }
}

#[test]
fn the_value_set_config_gives_a_setting_named_for_a_secret_is_masked() {
    // (script, whether the plain value is printed): `set_config` gives a
    // setting its value as `SET name = value` does.
    let (m, p) = (CALL_MARK, CALL_PLAIN);
    let cases = [
        (
            format!(
                "DO $body$ BEGIN PERFORM set_config('app.password', '{m}', false); END $body$;"
            ),
            false,
        ),
        (
            format!(
                "DO $body$ BEGIN PERFORM pg_catalog.set_config('myapp.api_token', '{m}', true); \
                 END $body$;"
            ),
            false,
        ),
        (
            format!("DO $body$ BEGIN PERFORM set_config('search_path', '{p}', false); END $body$;"),
            false,
        ),
    ];
    let mut wrong = Vec::new();
    for (sql, plain_printed) in &cases {
        let (json, _) = report_json_and_skipped("postgres", sql);
        if json.contains(m) {
            wrong.push(format!("the secret is printed: {sql}"));
        }
        if json.contains(p) != *plain_printed {
            wrong.push(format!(
                "the other setting's value is {}: {sql}",
                if *plain_printed { "masked" } else { "printed" }
            ));
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

#[test]
fn the_value_set_config_gives_is_masked_in_every_spelling_of_the_call() {
    // (statement, whether its value is a plain one): the function's name
    // quoted, spaced or qualified; a setting named for a key; a name or a
    // value that is not one literal. Each is called in a DO block, whose
    // `PERFORM` takes no result, and in an UPDATE, which writes the call's
    // result into a column no catalog types: neither prints either value.
    let (m, p) = (CALL_MARK, CALL_PLAIN);
    let calls = [
        (
            format!("\"set_config\"('app.password', '{m}', false)"),
            false,
        ),
        (
            format!("pg_catalog . set_config('app.password', '{m}', false)"),
            false,
        ),
        (
            format!("pg_catalog.\"set_config\"('app.password', '{m}', false)"),
            false,
        ),
        (
            format!("set_config('app.' || 'password', '{m}', false)"),
            false,
        ),
        (format!("set_config(n, '{m}', false)"), false),
        (
            format!("set_config('app.password', 'x' || '{m}', false)"),
            false,
        ),
        (format!("set_config('app.password', ('{m}'), false)"), false),
        (
            format!("set_config('app.encryption_key', '{m}', false)"),
            false,
        ),
        (format!("set_config('app.key', '{m}', false)"), false),
        (
            format!("set_config('app.signing_key', '{m}', false)"),
            false,
        ),
        (format!("set_config('search_path', '{p}', false)"), true),
        (
            format!("set_config('application_name', '{p}', false)"),
            true,
        ),
        (
            format!("\"set_config\"('application_name', '{p}', false)"),
            true,
        ),
        (
            format!("set_config('search_path', 'x' || '{p}', false)"),
            true,
        ),
    ];
    let mut wrong = Vec::new();
    for (call, plain) in &calls {
        for sql in [
            if call.starts_with("set_config(n,") {
                format!("DO $body$ DECLARE n text; BEGIN PERFORM {call}; END $body$;")
            } else {
                format!("DO $body$ BEGIN PERFORM {call}; END $body$;")
            },
            format!("UPDATE orders SET note = {call};"),
        ] {
            let (json, _) = report_json_and_skipped("postgres", &sql);
            if json.contains(m) {
                wrong.push(format!("the secret is printed: {sql}"));
            }
            if *plain && json.contains(p) {
                wrong.push(format!("the other setting's value is printed: {sql}"));
            }
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

#[test]
fn calls_nested_in_expressions_are_read_in_linear_time() {
    // Each statement calls the function that runs its argument inside an
    // assignment and a condition; every argument is masked, and the work
    // grows with the statements.
    let measure = |n: usize| {
        let mut sql = String::from(
            "CREATE FUNCTION zz_fn(q text) RETURNS text LANGUAGE plpgsql AS $$ \
             BEGIN EXECUTE q; RETURN 'x'; END; $$;\nDO $$ DECLARE r text; BEGIN ",
        );
        for i in 0..n {
            sql.push_str(&format!(
                "r := zz_fn('ALTER ROLE zz PASSWORD ''{CALL_MARK}{i}'''); \
                 PERFORM coalesce(zz_fn('ALTER ROLE zz PASSWORD ''{CALL_MARK}{i}'''), 'y'); \
                 IF zz_fn('ALTER ROLE zz PASSWORD ''{CALL_MARK}{i}''') IS NULL THEN r := 'z'; END IF; "
            ));
        }
        sql.push_str("END $$;");
        let started = std::time::Instant::now();
        let (json, _) = report_json_and_skipped("postgres", &sql);
        let elapsed = started.elapsed();
        assert!(!json.contains(CALL_MARK), "every run argument is masked");
        elapsed
    };
    let x1 = measure(25);
    let x4 = measure(100);
    let x16 = measure(400);
    let slack = std::time::Duration::from_millis(500);
    assert!(
        x4 < x1 * 8 + slack && x16 < x4 * 8 + slack,
        "took {x1:?}, {x4:?} and {x16:?} at one, four and sixteen times the calls"
    );
}

#[test]
fn a_call_argument_run_as_sql_is_masked_where_the_source_is_shown() {
    // A `CALL` and a `SELECT` of the routine, the source shown as a report
    // shows it.
    let m = CALL_MARK;
    let routine = "CREATE PROCEDURE zz_run(q VARCHAR) RETURNS VARCHAR LANGUAGE SQL AS $$ BEGIN \
                   EXECUTE IMMEDIATE :q; RETURN 'x'; END; $$;";
    for call in [
        format!("CALL zz_run('ALTER USER zz SET PASSWORD = ''{m}''');"),
        format!("SELECT zz_run('ALTER USER zz SET PASSWORD = ''{m}''');"),
    ] {
        let shown = redact_secrets_for_display(
            &format!("{routine}\n{call}"),
            &lexega_core::dialect::snowflake(),
        );
        assert!(!shown.contains(m), "{shown}");
        // The SQL text it runs is quoted as its own statements are.
        assert!(
            shown.contains("zz_run('ALTER USER zz SET PASSWORD = ''"),
            "{shown}"
        );
    }
}

#[test]
fn the_arguments_of_many_calls_through_many_procedures_are_masked_in_linear_time() {
    // Each procedure passes its parameter to the one before it, the first
    // runs it, and each is called once: every call's argument is run.
    let measure = |n: usize| {
        let mut sql =
            String::from("CREATE PROCEDURE dbo.zz_p0 @q NVARCHAR(MAX) AS BEGIN EXEC (@q); END;\n");
        for i in 1..n {
            sql.push_str(&format!(
                "CREATE PROCEDURE dbo.zz_p{i} @q NVARCHAR(MAX) AS BEGIN EXEC dbo.zz_p{} @q = @q; END;\n",
                i - 1
            ));
        }
        for i in 0..n {
            sql.push_str(&format!(
                "EXEC dbo.zz_p{i} @q = N'ALTER LOGIN zz WITH PASSWORD = ''{CALL_MARK}{i}''';\n"
            ));
        }
        let started = std::time::Instant::now();
        let (json, _) = report_json_and_skipped("mssql", &sql);
        let elapsed = started.elapsed();
        assert!(!json.contains(CALL_MARK), "every run argument is masked");
        elapsed
    };
    let x1 = measure(40);
    let x4 = measure(160);
    let x16 = measure(640);
    let slack = std::time::Duration::from_millis(500);
    assert!(
        x4 < x1 * 8 + slack && x16 < x4 * 8 + slack,
        "took {x1:?}, {x4:?} and {x16:?} at one, four and sixteen times the procedures and calls"
    );
}

#[test]
fn a_long_value_written_into_many_runs_is_masked_in_linear_time() {
    // A variable's value written between the quotes of many runs is read
    // in each; a long one is read whole once, so the work stays linear in
    // the source however many runs write it.
    let measure = |n: usize| {
        let value = "v".repeat(16 * n);
        let mut sql = format!(
            "CREATE PROCEDURE zz_p AS BEGIN DECLARE @p NVARCHAR(MAX) = N'{UNREAD_MARK}{value}';\n"
        );
        for i in 0..n {
            sql.push_str(&format!(
                "EXEC (N'UPDATE dbo.t{i} SET note = ''' + @p + N'''');\n"
            ));
        }
        sql.push_str("END;");
        let started = std::time::Instant::now();
        let (json, _) = report_json_and_skipped("mssql", &sql);
        assert!(!json.contains(UNREAD_MARK), "the value is masked");
        started.elapsed()
    };
    let small = measure(500);
    let large = measure(2_000);
    assert!(
        large < small * 8 + std::time::Duration::from_millis(500),
        "four times the input took {large:?} against {small:?}"
    );
}

#[test]
fn a_string_written_into_a_credential_named_column_is_masked() {
    let m = TSQL_MARK;
    let all = [
        "postgres",
        "snowflake",
        "mysql",
        "mssql",
        "bigquery",
        "databricks",
    ];
    let merging = ["postgres", "snowflake", "mssql", "bigquery", "databricks"];
    let mut masked: Vec<(&str, String)> = Vec::new();
    for name in all {
        masked.push((name, format!("UPDATE t SET password = '{m}'")));
        masked.push((
            name,
            format!("UPDATE t SET a = 1, t.api_key = '{m}' WHERE id = 1"),
        ));
        masked.push((
            name,
            format!("INSERT INTO t (id, password) VALUES (1, '{m}')"),
        ));
        masked.push((
            name,
            format!(
                "INSERT INTO t (id, secret_token, note) VALUES (1, '{m}', 'n'), (2, '{m}', 'n')"
            ),
        ));
    }
    for name in merging {
        masked.push((
            name,
            format!(
                "MERGE INTO t USING s ON t.id = s.id \
                 WHEN MATCHED THEN UPDATE SET password = '{m}' \
                 WHEN NOT MATCHED THEN INSERT (id, password) VALUES (s.id, '{m}')"
            ),
        ));
    }
    masked.extend([
        ("bigquery", format!("UPDATE my-project.ds.t SET password = '{m}'")),
        ("bigquery", format!("UPDATE t SET `password` = '{m}' WHERE TRUE")),
        ("mysql", format!("UPDATE t SET `Password` = '{m}'")),
        ("postgres", format!("UPDATE t SET \"Password\" = '{m}'")),
        ("snowflake", format!("INSERT INTO t (\"Password\") VALUES ('{m}')")),
        ("mssql", format!("UPDATE t SET [Password] = N'{m}'")),
        (
            "mssql",
            format!(
                "UPDATE u SET u.pwd = N'{m}' FROM dbo.users u JOIN dbo.r r ON r.id = u.id WHERE r.x = 1"
            ),
        ),
        ("postgres", format!("UPDATE t SET password = E'{m}'")),
        ("postgres", format!("UPDATE t SET password = UPPER('{m}')")),
        ("postgres", format!("UPDATE t SET password = '{m}' || x")),
    ]);
    for (name, sql) in &masked {
        assert_eq!(masked_under(name, sql, m), (true, true), "[{name}] {sql}");
    }

    // A string written into another column is masked as well, where no
    // catalog types the column; one the statement compares is not.
    let written = [
        ("postgres", format!("UPDATE t SET status = '{m}'")),
        (
            "postgres",
            format!("INSERT INTO t (id, status) VALUES (1, '{m}')"),
        ),
        (
            "mssql",
            format!("INSERT INTO t (password, status) VALUES (p, '{m}')"),
        ),
        (
            "snowflake",
            format!(
                "MERGE INTO t USING s ON t.id = s.id \
                 WHEN NOT MATCHED THEN INSERT (id, status) VALUES (s.id, '{m}')"
            ),
        ),
    ];
    for (name, sql) in &written {
        assert_eq!(masked_under(name, sql, m), (true, true), "[{name}] {sql}");
    }
    let compared = format!("UPDATE t SET password = UPPER(x) WHERE status = '{m}'");
    assert!(!masked_under("postgres", &compared, m).0, "{compared}");
}

#[test]
fn a_string_written_into_a_credential_named_column_by_an_upsert_replace_or_multi_insert_is_masked()
{
    let m = TSQL_MARK;
    let masked = [
        (
            "mysql",
            format!("INSERT INTO t SET id = 1, password = '{m}'"),
        ),
        ("mysql", format!("INSERT INTO t SET `Password` = '{m}'")),
        ("mysql", format!("REPLACE INTO t SET password = '{m}'")),
        (
            "mysql",
            format!("REPLACE INTO t (id, password) VALUES (1, '{m}'), (2, '{m}')"),
        ),
        (
            "mysql",
            format!("INSERT INTO t (id) VALUES (1) ON DUPLICATE KEY UPDATE password = '{m}'"),
        ),
        (
            "mysql",
            format!("INSERT INTO t SET id = 1 ON DUPLICATE KEY UPDATE api_key = '{m}', n = n + 1"),
        ),
        (
            "postgres",
            format!(
                "INSERT INTO t (id) VALUES (1) ON CONFLICT (id) DO UPDATE SET password = '{m}'"
            ),
        ),
        (
            "postgres",
            format!(
                "INSERT INTO t (id) VALUES (1) ON CONFLICT (id) DO UPDATE SET \"Password\" = '{m}'"
            ),
        ),
        (
            "snowflake",
            format!(
                "INSERT ALL INTO t (id, password) VALUES (id, '{m}') \
                 INTO u (id, api_key) VALUES (id, '{m}') SELECT id FROM s"
            ),
        ),
        (
            "snowflake",
            format!(
                "INSERT FIRST WHEN id > 1 THEN INTO t (id, password) VALUES (id, '{m}') \
                 ELSE INTO u (id, \"PASSWORD\") VALUES (id, '{m}') SELECT id FROM s"
            ),
        ),
        (
            "mysql",
            format!("REPLACE INTO t SET password = CONCAT('{m}', x)"),
        ),
        (
            "snowflake",
            format!("INSERT ALL INTO t (id, password) VALUES (id, '{m}' || x) SELECT id, x FROM s"),
        ),
    ];
    for (name, sql) in &masked {
        assert_eq!(masked_under(name, sql, m), (true, true), "[{name}] {sql}");
    }

    // A string written into another column is masked as well, where no
    // catalog types the column.
    let written = [
        ("mysql", format!("INSERT INTO t SET status = '{m}'")),
        (
            "mysql",
            format!("REPLACE INTO t (password, status) VALUES (p, '{m}')"),
        ),
        (
            "mysql",
            format!("INSERT INTO t (id) VALUES (1) ON DUPLICATE KEY UPDATE status = '{m}'"),
        ),
        (
            "postgres",
            format!("INSERT INTO t (id) VALUES (1) ON CONFLICT (id) DO UPDATE SET status = '{m}'"),
        ),
        (
            "snowflake",
            format!("INSERT ALL INTO t (id, status) VALUES (id, '{m}') SELECT id FROM s"),
        ),
    ];
    for (name, sql) in &written {
        assert_eq!(masked_under(name, sql, m), (true, true), "[{name}] {sql}");
    }
}

// A BigQuery function's `OPTIONS (…)`, written before `AS` or after the
// body, with or without `RETURNS`, masks a secret-named option's value.
#[test]
fn a_secret_in_a_bigquery_function_options_list_is_masked() {
    let m = TSQL_MARK;
    for sql in [
        format!("CREATE FUNCTION d.f() RETURNS INT64 AS (1) OPTIONS (client_secret = '{m}')"),
        format!("CREATE TEMP FUNCTION f(x INT64) AS (x + 1) OPTIONS (client_secret = '{m}')"),
        format!(
            "CREATE TEMP FUNCTION f(x FLOAT64) RETURNS FLOAT64 LANGUAGE js \
             OPTIONS (client_secret = '{m}') AS r\"\"\"return x;\"\"\""
        ),
    ] {
        assert_eq!(masked_under("bigquery", &sql, m), (true, true), "{sql}");
    }
}

// A multi-table INSERT's clause is read with every row it writes: a string
// a later row writes into a credential-named column is masked as the first
// row's is.
#[test]
fn a_string_a_later_multi_insert_row_writes_into_a_credential_named_column_is_masked() {
    let m = TSQL_MARK;
    for sql in [
        format!("INSERT ALL INTO t (id, password) VALUES (id, 'a'), (id, '{m}') SELECT id FROM s"),
        format!(
            "INSERT FIRST WHEN id > 1 THEN INTO t (id, api_key) VALUES (1, 'a'), (2, '{m}') \
             ELSE INTO u (id) VALUES (id) SELECT id FROM s"
        ),
        format!(
            "INSERT ALL INTO u (id) VALUES (id) \
             INTO t (id, password) VALUES (id, 'a'), (id, UPPER('{m}')) SELECT id FROM s"
        ),
    ] {
        assert_eq!(masked_under("snowflake", &sql, m), (true, true), "{sql}");
    }
    // So is one written into another column no catalog types.
    let sql =
        format!("INSERT ALL INTO t (id, status) VALUES (id, 'a'), (id, '{m}') SELECT id FROM s");
    assert_eq!(masked_under("snowflake", &sql, m), (true, true), "{sql}");
}

// PostgreSQL's row assignment writes each value of the row, or each column
// of the query, into the column at its place: every string the value given
// a credential-named column holds is masked, and so is one given any other
// column no catalog types; one the query holds outside its select list is
// not.
#[test]
fn a_string_a_row_assignment_writes_into_a_credential_named_column_is_masked() {
    let m = TSQL_MARK;
    for sql in [
        format!("UPDATE users SET (password, name) = ('{m}', 'n')"),
        format!("UPDATE users SET (name, api_key) = ('n', '{m}') WHERE id = 1"),
        format!("UPDATE users SET a = 1, (u.password, b) = ('{m}', 2)"),
        format!("UPDATE users SET (password, name) = ROW('{m}', 'n')"),
        format!("UPDATE users SET (name, password) = row('n', '{m}') WHERE id = 1"),
        format!("UPDATE users SET (password, name) = (UPPER('{m}'), 'n')"),
        format!("UPDATE users SET (name, password) = (SELECT 'n', CONCAT(x, '{m}') FROM s)"),
        format!(
            "UPDATE users SET (name, password) = \
             (SELECT 'n', '{m}' FROM s UNION ALL SELECT 'o', UPPER('{m}') FROM r)"
        ),
        format!("UPDATE users SET password = (SELECT MAX(x) || '{m}' FROM s)"),
    ] {
        assert_eq!(masked_under("postgres", &sql, m), (true, true), "{sql}");
    }
    for sql in [
        format!("UPDATE users SET (name, password) = ('{m}', 'p')"),
        format!("UPDATE users SET (password, name) = ('p', '{m}')"),
        format!("UPDATE users SET (password, name) = ROW('p', '{m}')"),
        format!("UPDATE users SET (name, password) = (SELECT '{m}', x FROM s)"),
    ] {
        assert_eq!(masked_under("postgres", &sql, m), (true, true), "{sql}");
    }
    let compared =
        format!("UPDATE users SET (name, password) = (SELECT 'n', x FROM s WHERE k = '{m}')");
    assert!(!masked_under("postgres", &compared, m).0, "{compared}");
    // A row of another length, or a column after a star, places no value
    // in a column the statement names: no walk shows it.
    for unplaced in [
        format!("UPDATE users SET (password, name) = COALESCE('{m}', 'n')"),
        format!("UPDATE users SET (name, password) = (SELECT *, '{m}' FROM s)"),
    ] {
        assert!(masked_under("postgres", &unplaced, m).0, "{unplaced}");
    }
}

// An INSERT from a query writes each column of the query into the column at
// its place in the target list, in every branch of a set operation.
#[test]
fn a_string_an_insert_from_a_query_writes_into_a_credential_named_column_is_masked() {
    let m = TSQL_MARK;
    let masked = [
        (
            "postgres",
            format!("INSERT INTO t (id, password) SELECT id, CONCAT(x, '{m}') FROM s"),
        ),
        (
            "postgres",
            format!(
                "INSERT INTO t (id, password) SELECT id, '{m}' FROM s \
                 UNION ALL SELECT id, UPPER('{m}') FROM r"
            ),
        ),
        (
            "postgres",
            format!("INSERT INTO t (id, password) SELECT id, x FROM s UNION ALL VALUES (1, '{m}')"),
        ),
        (
            "mysql",
            format!("REPLACE INTO t (id, password) SELECT id, CONCAT('{m}', x) FROM s"),
        ),
        (
            "mssql",
            format!("INSERT INTO t (id, pwd) SELECT id, N'{m}' + x FROM s"),
        ),
        (
            "postgres",
            format!(
                "INSERT INTO t (id, api_key) WITH c AS (SELECT 1 AS id) SELECT id, '{m}' FROM c"
            ),
        ),
    ];
    for (name, sql) in &masked {
        assert_eq!(masked_under(name, sql, m), (true, true), "[{name}] {sql}");
    }
    let written = format!("INSERT INTO t (status, password) SELECT '{m}', x FROM s");
    assert_eq!(
        masked_under("postgres", &written, m),
        (true, true),
        "{written}"
    );
    let kept = [
        (
            "postgres",
            format!("INSERT INTO t (id, password) SELECT id, x FROM s WHERE k = '{m}'"),
        ),
        (
            "postgres",
            format!("INSERT INTO t (id, password) SELECT * FROM s WHERE k = '{m}'"),
        ),
    ];
    for (name, sql) in &kept {
        assert!(!masked_under(name, sql, m).0, "[{name}] {sql}");
    }
}

// A string compared with a credential-named column is masked under every
// comparison operator, on either side, in every clause a condition is
// written in.
#[test]
fn a_string_compared_with_a_credential_named_column_is_masked() {
    let m = TSQL_MARK;
    let masked = [
        (
            "postgres",
            format!("SELECT id FROM users u WHERE u.password = '{m}'"),
        ),
        (
            "postgres",
            format!("SELECT id FROM users WHERE password <> '{m}'"),
        ),
        (
            "mysql",
            format!("SELECT id FROM users WHERE password != '{m}'"),
        ),
        (
            "postgres",
            format!("SELECT id FROM users WHERE password >= '{m}'"),
        ),
        (
            "postgres",
            format!("SELECT id FROM users WHERE '{m}' = password"),
        ),
        (
            "postgres",
            format!("SELECT id FROM users WHERE password IN ('{m}', '{m}')"),
        ),
        (
            "postgres",
            format!("SELECT id FROM users WHERE password NOT IN ('{m}')"),
        ),
        (
            "postgres",
            format!("SELECT id FROM users WHERE password BETWEEN '{m}' AND '{m}'"),
        ),
        (
            "postgres",
            format!("SELECT id FROM users WHERE password LIKE '{m}%'"),
        ),
        (
            "snowflake",
            format!("SELECT id FROM users WHERE password ILIKE '{m}%'"),
        ),
        (
            "postgres",
            format!("SELECT id FROM users WHERE password ~ '{m}'"),
        ),
        (
            "postgres",
            format!("SELECT id FROM users WHERE password IS DISTINCT FROM '{m}'"),
        ),
        (
            "mysql",
            format!("SELECT id FROM users WHERE password <=> '{m}'"),
        ),
        (
            "postgres",
            format!("SELECT id FROM users WHERE password = UPPER('{m}')"),
        ),
        (
            "mssql",
            format!("SELECT id FROM dbo.users WHERE pwd = N'{m}'"),
        ),
        (
            "bigquery",
            format!("SELECT id FROM users WHERE api_token = '{m}'"),
        ),
        (
            "postgres",
            format!("SELECT password FROM users GROUP BY password HAVING password = '{m}'"),
        ),
        (
            "snowflake",
            format!("SELECT id FROM users QUALIFY password = '{m}'"),
        ),
        (
            "postgres",
            format!(
                "SELECT o.id FROM orders o JOIN users u ON u.id = o.user_id AND u.password = '{m}'"
            ),
        ),
        (
            "postgres",
            format!("SELECT CASE WHEN password = '{m}' THEN 1 ELSE 0 END AS c FROM users"),
        ),
        (
            "postgres",
            format!("SELECT CASE password WHEN '{m}' THEN 1 ELSE 0 END AS c FROM users"),
        ),
        (
            "postgres",
            format!(
                "MERGE INTO archive a USING users u ON a.id = u.id AND u.password = '{m}' \
                 WHEN MATCHED THEN DELETE"
            ),
        ),
        (
            "snowflake",
            format!(
                "MERGE INTO archive a USING users u ON a.id = u.id \
                 WHEN MATCHED AND u.secret <> '{m}' THEN DELETE"
            ),
        ),
        (
            "postgres",
            format!("UPDATE users SET name = 'x' WHERE password = '{m}'"),
        ),
        (
            "postgres",
            format!("DELETE FROM users WHERE secret IN ('{m}')"),
        ),
        (
            "postgres",
            format!("SELECT id FROM users u WHERE (u.id, u.password) = (1, '{m}')"),
        ),
        // A variable named for a secret is compared as a column is.
        (
            "mssql",
            format!("SELECT id FROM dbo.users WHERE @password = N'{m}'"),
        ),
        // A column equated with a credential-named one holds its value, and
        // a string joined with one is part of a value made of it.
        (
            "postgres",
            format!("SELECT id FROM users WHERE password = name AND name = '{m}'"),
        ),
        (
            "postgres",
            format!("SELECT id FROM users WHERE password || '{m}' = name"),
        ),
    ];
    for (name, sql) in &masked {
        assert_eq!(masked_under(name, sql, m), (true, true), "[{name}] {sql}");
    }

    // A string compared with another column is printed.
    let kept = [(
        "postgres",
        format!("SELECT id FROM users WHERE name = '{m}'"),
    )];
    for (name, sql) in &kept {
        assert!(!masked_under(name, sql, m).0, "[{name}] {sql}");
    }
}

// A field whose name is credential-named, or any field of a credential-named
// column, is compared as the column is: Snowflake's `:` and `.` paths,
// PostgreSQL's `(c).f`.
#[test]
fn a_string_compared_with_a_credential_named_field_is_masked() {
    let m = TSQL_MARK;
    let masked = [
        (
            "snowflake",
            format!("SELECT a.id FROM users a WHERE a.password:user = '{m}'"),
        ),
        (
            "snowflake",
            format!("SELECT a.id FROM users a WHERE a.creds:password = '{m}'"),
        ),
        (
            "snowflake",
            format!("SELECT a.id FROM users a WHERE a.creds.password = '{m}'"),
        ),
        (
            "snowflake",
            format!("SELECT a.id FROM users a WHERE creds:auth.api_key IN ('{m}')"),
        ),
        (
            "databricks",
            format!("SELECT a.id FROM users a WHERE a.creds:password = '{m}'"),
        ),
        (
            "postgres",
            format!("SELECT a.id FROM users a WHERE (a.creds).password = '{m}'"),
        ),
    ];
    for (name, sql) in &masked {
        assert_eq!(masked_under(name, sql, m), (true, true), "[{name}] {sql}");
    }
    // A field is no bare column: a value compared with one is masked
    // whatever its name.
    let expressions = [(
        "snowflake",
        format!("SELECT a.id FROM users a WHERE a.creds:user = '{m}'"),
    )];
    // A value compared with an expression, a path or a computed column is
    // masked whatever the name it reads.
    for (name, sql) in &expressions {
        assert!(masked_under(name, sql, m).0, "[{name}] {sql}");
    }
}

// An alias the select list gives a credential-named column or field is
// compared as the column is, in its own query block's WHERE, HAVING and
// QUALIFY; not in a nested block, and not an alias of anything else.
#[test]
fn a_string_compared_with_an_alias_of_a_credential_named_column_is_masked() {
    let m = TSQL_MARK;
    let masked = [
        (
            "snowflake",
            format!("SELECT password AS k, COUNT(*) AS n FROM users GROUP BY k HAVING k = '{m}'"),
        ),
        (
            "snowflake",
            format!("SELECT password AS k FROM users WHERE k = '{m}'"),
        ),
        (
            "snowflake",
            format!("SELECT u.password k FROM users u QUALIFY k IN ('{m}')"),
        ),
        (
            "snowflake",
            format!("SELECT a.creds:token AS t FROM users a WHERE t LIKE '{m}%'"),
        ),
        (
            "postgres",
            format!("SELECT password AS k FROM users GROUP BY password HAVING k = '{m}'"),
        ),
    ];
    for (name, sql) in &masked {
        assert_eq!(masked_under(name, sql, m), (true, true), "[{name}] {sql}");
    }
    let kept = [
        (
            "snowflake",
            format!(
                "SELECT password AS p FROM users WHERE EXISTS (SELECT 1 FROM s WHERE p = '{m}')"
            ),
        ),
        (
            "snowflake",
            format!("SELECT password AS p FROM users WHERE s.p = '{m}'"),
        ),
        (
            "snowflake",
            format!("SELECT password AS p FROM users; SELECT id FROM s WHERE p = '{m}'"),
        ),
    ];
    let expressions = [(
        "snowflake",
        format!("SELECT LOWER(name) AS k, COUNT(*) AS n FROM users GROUP BY k HAVING k = '{m}'"),
    )];
    for (name, sql) in &kept {
        assert!(!masked_under(name, sql, m).0, "[{name}] {sql}");
    }
    // A value compared with an expression, a path or a computed column is
    // masked whatever the name it reads.
    for (name, sql) in &expressions {
        assert!(masked_under(name, sql, m).0, "[{name}] {sql}");
    }
}

// An operand that reads a credential-named column anywhere outside a
// subquery (a cast, a call, a concatenation, a window over it) compares its
// value: every string it is compared with is masked.
#[test]
fn a_string_compared_with_an_operand_reading_a_credential_named_column_is_masked() {
    let m = TSQL_MARK;
    let masked = [
        (
            "postgres",
            format!("SELECT id FROM users u WHERE u.password::text = '{m}'"),
        ),
        (
            "postgres",
            format!("SELECT id FROM users WHERE CAST(password AS VARCHAR) = '{m}'"),
        ),
        (
            "postgres",
            format!("SELECT id FROM users WHERE LOWER(password) = '{m}'"),
        ),
        (
            "postgres",
            format!("SELECT id FROM users WHERE TRIM(u.password) LIKE '{m}%'"),
        ),
        (
            "snowflake",
            format!("SELECT id FROM users WHERE SUBSTR(password, 1, 3) = '{m}'"),
        ),
        (
            "mysql",
            format!("SELECT id FROM users WHERE MD5(password) = '{m}'"),
        ),
        (
            "postgres",
            format!("SELECT id FROM users WHERE CONCAT(name, password) = '{m}'"),
        ),
        (
            "postgres",
            format!("SELECT id FROM users WHERE name || password <> '{m}'"),
        ),
        (
            "postgres",
            format!("SELECT id FROM users WHERE '{m}' = UPPER(password)"),
        ),
        (
            "postgres",
            format!("SELECT id FROM users WHERE COALESCE(api_key, 'x') IN ('{m}')"),
        ),
        (
            "postgres",
            format!("SELECT id FROM users WHERE LOWER(password) BETWEEN '{m}' AND '{m}'"),
        ),
        (
            "postgres",
            format!("SELECT password FROM users GROUP BY password HAVING UPPER(password) = '{m}'"),
        ),
        (
            "postgres",
            format!("SELECT CASE WHEN LOWER(password) = '{m}' THEN 1 END AS c FROM users"),
        ),
        (
            "postgres",
            format!("SELECT CASE MD5(password) WHEN '{m}' THEN 1 END AS c FROM users"),
        ),
        (
            "snowflake",
            format!(
                "MERGE INTO archive a USING users u ON a.id = u.id \
                 WHEN MATCHED AND TRIM(u.secret) = '{m}' THEN DELETE"
            ),
        ),
        (
            "postgres",
            format!("DELETE FROM users WHERE password::text IN ('{m}')"),
        ),
        (
            "snowflake",
            format!("SELECT id FROM users WHERE PARSE_JSON(creds_password):user = '{m}'"),
        ),
        (
            "snowflake",
            format!("SELECT LOWER(password) AS k FROM users WHERE k = '{m}'"),
        ),
        // A scalar subquery inside the operand whose column reads one.
        (
            "postgres",
            format!(
                "SELECT id FROM users WHERE COALESCE((SELECT MAX(password) FROM s), 'y') = '{m}'"
            ),
        ),
    ];
    for (name, sql) in &masked {
        assert_eq!(masked_under(name, sql, m), (true, true), "[{name}] {sql}");
    }

    // An operand that reads no credential-named column and a number compared
    // with one are printed.
    let kept = [(
        "postgres",
        format!("SELECT id FROM users WHERE LENGTH(password) = 5 AND name = '{m}'"),
    )];
    let expressions = [
        (
            "postgres",
            format!("SELECT id FROM users WHERE LOWER(name) = '{m}'"),
        ),
        (
            "postgres",
            format!("SELECT id FROM users WHERE CONCAT(name, 'x') = '{m}'"),
        ),
    ];
    for (name, sql) in &kept {
        assert!(!masked_under(name, sql, m).0, "[{name}] {sql}");
    }
    // A value compared with an expression, a path or a computed column is
    // masked whatever the name it reads.
    for (name, sql) in &expressions {
        assert!(masked_under(name, sql, m).0, "[{name}] {sql}");
    }
}

// `IN (subquery)` and `<op> ANY / ALL (subquery)` compare the operand with
// the subquery's select item: every string of the item at a place compared
// with a credential-named operand is masked, in every set-operation branch;
// one the subquery holds elsewhere is printed.
#[test]
fn a_string_a_subquery_compares_with_a_credential_named_operand_is_masked() {
    let m = TSQL_MARK;
    let masked = [
        (
            "postgres",
            format!("SELECT id FROM users WHERE password IN (SELECT '{m}' FROM s)"),
        ),
        (
            "postgres",
            format!("SELECT id FROM users WHERE password NOT IN (SELECT CONCAT(x, '{m}') FROM s)"),
        ),
        (
            "postgres",
            format!("SELECT id FROM users WHERE password = ANY (SELECT '{m}' FROM s)"),
        ),
        (
            "postgres",
            format!(
                "SELECT id FROM users WHERE secret <> ALL \
                 (SELECT '{m}' FROM s UNION ALL SELECT UPPER('{m}') FROM r)"
            ),
        ),
        (
            "postgres",
            format!("SELECT id FROM users WHERE LOWER(password) IN (SELECT LOWER('{m}') FROM s)"),
        ),
        (
            "postgres",
            format!("SELECT id FROM users WHERE (id, password) IN (SELECT 1, '{m}' FROM s)"),
        ),
        (
            "postgres",
            format!("UPDATE users SET name = 'x' WHERE password IN (SELECT '{m}' FROM s)"),
        ),
    ];
    for (name, sql) in &masked {
        assert_eq!(masked_under(name, sql, m), (true, true), "[{name}] {sql}");
    }
    let kept = [
        (
            "postgres",
            format!("SELECT id FROM users WHERE password IN (SELECT x FROM s WHERE k = '{m}')"),
        ),
        (
            "postgres",
            format!("SELECT id FROM users WHERE name IN (SELECT '{m}' FROM s)"),
        ),
        (
            "postgres",
            format!("SELECT id FROM users WHERE (password, id) IN (SELECT x, '{m}' FROM s)"),
        ),
        (
            "postgres",
            format!("SELECT id FROM users WHERE name = ANY (SELECT '{m}' FROM s)"),
        ),
    ];
    for (name, sql) in &kept {
        assert!(!masked_under(name, sql, m).0, "[{name}] {sql}");
    }
}

#[test]
fn a_secret_in_a_redshift_unload_query_is_masked_whether_or_not_the_query_is_read() {
    let m = TSQL_MARK;
    let tail = "TO 's3://b/o/' IAM_ROLE 'arn:aws:iam::1:role/r';";
    for query in [
        // Read as a statement.
        format!("SELECT id FROM users WHERE password = ''{m}''"),
        // Not read: a quote inside a literal of the query.
        format!("SELECT id FROM users WHERE password = ''{m}'' AND note = ''it''''s''"),
        // Not read: the text does not parse.
        format!("SELECT FROM WHERE password = ''{m}'' ((("),
    ] {
        let sql = format!("UNLOAD ('{query}') {tail}");
        assert_eq!(masked_under("redshift", &sql, m), (true, true), "{sql}");
    }
}

/// A secret a statement reads where telling it is one takes resolving
/// names, written short so a finding's 80-character preview holds it.
const READ_MARK: &str = "Zq9Rd";
/// A value read beside an ordinary column, printed by the same finding.
const READ_PLAIN: &str = "Zq9Pl";

/// A statement under a dialect, writing `{s}` for a name and `{v}` for a
/// value: the name is `secret` beside `READ_MARK` and `ordinary`, as long,
/// beside `READ_PLAIN`, so a preview holding the one holds the other.
struct ReadCase {
    dialect: &'static str,
    template: &'static str,
    secret: &'static str,
    ordinary: &'static str,
}

const fn case(
    dialect: &'static str,
    template: &'static str,
    secret: &'static str,
    ordinary: &'static str,
) -> ReadCase {
    ReadCase {
        dialect,
        template,
        secret,
        ordinary,
    }
}

/// Each case's report prints no `READ_MARK` beside the secret name, and
/// prints `READ_PLAIN` beside the ordinary one.
fn assert_read_secret_masked(cases: &[ReadCase]) {
    let mut wrong = secrets_printed(cases);
    for c in cases {
        let plain = c
            .template
            .replace("{s}", c.ordinary)
            .replace("{v}", READ_PLAIN);
        let (json, _) = report_json_and_skipped(c.dialect, &plain);
        if !json.contains(READ_PLAIN) {
            wrong.push(format!("[{}] not printed: {plain}", c.dialect));
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// Each case's report prints neither `READ_MARK` beside the secret name
/// nor `READ_PLAIN` beside the ordinary one: the value is compared with an
/// expression, a path or a computed column, not a bare column, so it is
/// masked whatever the name.
fn assert_compared_with_an_expression_masked(cases: &[ReadCase]) {
    let mut wrong = secrets_printed(cases);
    for c in cases {
        let plain = c
            .template
            .replace("{s}", c.ordinary)
            .replace("{v}", READ_PLAIN);
        let (json, _) = report_json_and_skipped(c.dialect, &plain);
        if json.contains(READ_PLAIN) {
            wrong.push(format!("[{}] printed: {plain}", c.dialect));
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// Each case's report prints no `READ_MARK` beside the secret name.
fn assert_secret_masked(cases: &[ReadCase]) {
    let wrong = secrets_printed(cases);
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// The cases whose report prints `READ_MARK` beside the secret name.
fn secrets_printed(cases: &[ReadCase]) -> Vec<String> {
    let mut wrong = Vec::new();
    for c in cases {
        let secret = c
            .template
            .replace("{s}", c.secret)
            .replace("{v}", READ_MARK);
        let (json, _) = report_json_and_skipped(c.dialect, &secret);
        // A preview cut short still prints the mark's first characters.
        if json.contains(&READ_MARK[..4]) {
            wrong.push(format!("[{}] printed: {secret}", c.dialect));
        }
    }
    wrong
}

/// Each template's text prints neither `READ_MARK` beside the secret name
/// nor `READ_PLAIN` beside the ordinary one: a value compared with a
/// variable or a computed column, which is no bare column, is masked
/// whatever its name.
fn assert_compared_with_no_bare_column_masked(templates: &[(&str, &str, &str)]) {
    let mut wrong = Vec::new();
    for (template, secret, ordinary) in templates {
        for (name, mark) in [(secret, READ_MARK), (ordinary, READ_PLAIN)] {
            let sql = template.replace("{s}", name).replace("{v}", mark);
            let shown = redact_secrets_for_display(&sql, &lexega_core::dialect::snowflake());
            if shown.contains(mark) {
                wrong.push(format!("printed: {shown}"));
            }
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// As [`assert_read_secret_masked`], for Snowflake statements `(template,
/// secret, ordinary)` shown as [`redact_secrets_for_display`] shows them,
/// whatever their length.
fn assert_shown_secret_masked(templates: &[(&str, &str, &str)]) {
    let mut wrong = Vec::new();
    for (template, secret, ordinary) in templates {
        let sql = template.replace("{s}", secret).replace("{v}", READ_MARK);
        let shown = redact_secrets_for_display(&sql, &lexega_core::dialect::snowflake());
        if shown.contains(READ_MARK) {
            wrong.push(format!("printed: {shown}"));
        }
        let sql = template.replace("{s}", ordinary).replace("{v}", READ_PLAIN);
        let shown = redact_secrets_for_display(&sql, &lexega_core::dialect::snowflake());
        if !shown.contains(READ_PLAIN) {
            wrong.push(format!("not printed: {shown}"));
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

#[test]
fn a_string_another_argument_of_a_call_reading_a_secret_holds_is_masked() {
    // A function the dialect's catalog does not hold shows no argument.
    assert_secret_masked(&[
        case(
            "snowflake",
            "DELETE FROM a.u WHERE EQUAL_NULL({s}, '{v}') AND id IN (SELECT id FROM b.t)",
            "password",
            "username",
        ),
        case(
            "snowflake",
            "DELETE FROM a.u WHERE CONTAINS({s}, '{v}') AND id IN (SELECT id FROM b.t)",
            "password",
            "username",
        ),
        case(
            "mssql",
            "DELETE FROM a.u WHERE CHARINDEX(N'{v}', {s}) > 0 AND id IN (SELECT id FROM b.t)",
            "password",
            "username",
        ),
        case(
            "snowflake",
            "DELETE FROM a.u WHERE STARTSWITH({s}, '{v}') AND id IN (SELECT id FROM b.t)",
            "password",
            "username",
        ),
    ]);
    assert_read_secret_masked(&[
        case(
            "postgres",
            "DELETE FROM a.u WHERE NULLIF({s}, '{v}') IS NULL AND id IN (SELECT id FROM b.t)",
            "password",
            "username",
        ),
        case(
            "snowflake",
            "DELETE FROM a.u WHERE DECODE({s}, '{v}', 1, 0) = 1 AND id IN (SELECT id FROM b.t)",
            "password",
            "username",
        ),
        case(
            "snowflake",
            "DELETE FROM a.u WHERE REGEXP_LIKE({s}, '{v}') AND id IN (SELECT id FROM b.t)",
            "password",
            "username",
        ),
        case(
            "postgres",
            "DELETE FROM a.u WHERE COALESCE({s}, '{v}') = 'x' AND id IN (SELECT id FROM b.t)",
            "password",
            "username",
        ),
    ]);
    // `POSITION` is PostgreSQL's by name alone: its catalog states no
    // signature, so a string passed to it is proven safe beside neither.
    let read = |column: &str| {
        format!(
            "DELETE FROM a.u WHERE POSITION('{READ_MARK}' IN {column}) > 0 AND id IN (SELECT id FROM b.t)"
        )
    };
    let (password, username) = (read("password"), read("username"));
    assert_printed_nowhere(&[
        ("postgresql", &password, READ_MARK),
        ("postgresql", &username, READ_MARK),
    ]);
}

#[test]
fn a_string_on_the_tested_side_of_a_comparison_with_a_secret_is_masked() {
    assert_read_secret_masked(&[
        case(
            "postgres",
            "DELETE FROM a.u WHERE '{v}' IN ({s}, nick) AND id IN (SELECT id FROM b.t)",
            "password",
            "username",
        ),
        case(
            "postgres",
            "DELETE FROM a.u WHERE '{v}' LIKE {s} AND id IN (SELECT id FROM b.t)",
            "password",
            "username",
        ),
        case(
            "postgres",
            "DELETE FROM a.u WHERE '{v}' BETWEEN {s} AND nick AND id IN (SELECT id FROM b.t)",
            "password",
            "username",
        ),
    ]);
}

#[test]
fn a_string_compared_with_a_json_key_named_for_a_secret_is_masked() {
    assert_compared_with_an_expression_masked(&[
        case(
            "postgres",
            "DELETE FROM a.u WHERE creds->>'{s}' = '{v}' AND id IN (SELECT id FROM b.t)",
            "password",
            "username",
        ),
        case(
            "mysql",
            "DELETE FROM a.u WHERE creds->>'$.{s}' = '{v}' AND id IN (SELECT id FROM b.t)",
            "password",
            "username",
        ),
        case(
            "postgres",
            "DELETE FROM a.u WHERE json_extract_path_text(creds, '{s}') = '{v}' \
             AND id IN (SELECT id FROM b.t)",
            "password",
            "username",
        ),
        case(
            "bigquery",
            "DELETE FROM a.u WHERE JSON_VALUE(creds, '$.{s}') = '{v}' AND id IN (SELECT id FROM b.t)",
            "password",
            "username",
        ),
        case(
            "mssql",
            "DELETE FROM a.u WHERE JSON_VALUE(creds, '$.{s}') = N'{v}' AND id IN (SELECT id FROM b.t)",
            "password",
            "username",
        ),
        case(
            "snowflake",
            "DELETE FROM a.u WHERE GET_PATH(creds, '{s}') = '{v}' AND id IN (SELECT id FROM b.t)",
            "password",
            "username",
        ),
        case(
            "snowflake",
            "DELETE FROM a.u WHERE creds:\"{s}\" = '{v}' AND id IN (SELECT id FROM b.t)",
            "password",
            "username",
        ),
    ]);
}

#[test]
fn a_string_paired_with_a_key_named_for_a_secret_in_a_constructor_is_masked() {
    // A value written with no column list lands in no column the
    // statement names: no walk shows it either way.
    assert_secret_masked(&[
        case(
            "snowflake",
            "INSERT INTO a.x SELECT OBJECT_CONSTRUCT('{s}', '{v}') FROM b.t",
            "password",
            "username",
        ),
        case(
            "postgres",
            "INSERT INTO a.x SELECT json_build_object('{s}', '{v}') FROM b.t",
            "password",
            "username",
        ),
        case(
            "databricks",
            "INSERT INTO a.x SELECT MAP('{s}', '{v}') FROM b.t",
            "password",
            "username",
        ),
        case(
            "bigquery",
            "INSERT INTO a.x SELECT STRUCT('{v}' AS {s}) FROM b.t",
            "password",
            "username",
        ),
    ]);
    assert_read_secret_masked(&[]);
}

#[test]
fn a_string_compared_with_a_column_reading_a_secret_through_names_is_masked() {
    assert_compared_with_an_expression_masked(&[
        // An alias of an alias, read in WHERE, in HAVING and beside a window.
        case(
            "snowflake",
            "INSERT INTO a.x SELECT LOWER({s}) a, a||'x' k FROM b.t WHERE k='{v}'",
            "pwd",
            "nom",
        ),
        case(
            "snowflake",
            "INSERT INTO a.x SELECT LOWER({s}) a,a||'x' k FROM b.t GROUP BY 1 HAVING k='{v}'",
            "pwd",
            "nom",
        ),
        case(
            "snowflake",
            "INSERT INTO a.x SELECT LOWER({s}) k, RANK() OVER () r FROM b.t WHERE k='{v}'",
            "pwd",
            "nom",
        ),
        // A scalar subquery's column.
        case(
            "postgres",
            "DELETE FROM a.u WHERE (SELECT {s} FROM b.t LIMIT 1) = '{v}'",
            "pwd",
            "nom",
        ),
        // A variable named for a secret.
        case(
            "mssql",
            "DELETE FROM a.u WHERE @{s} = N'{v}' AND id IN (SELECT id FROM b.t)",
            "password",
            "username",
        ),
    ]);
    // A bare column, through a CTE, a derived table or a USING join.
    assert_read_secret_masked(&[
        case(
            "postgres",
            "WITH c AS(SELECT {s} p FROM b.t)INSERT INTO a.x SELECT p FROM c WHERE p='{v}'",
            "pwd",
            "nom",
        ),
        case(
            "postgres",
            "INSERT INTO a.x SELECT d.p FROM (SELECT {s} p FROM b.t) d WHERE d.p='{v}'",
            "pwd",
            "nom",
        ),
        case(
            "postgres",
            "DELETE FROM a.u USING b.t JOIN b.s USING ({s}) WHERE {s}='{v}'",
            "pwd",
            "nom",
        ),
    ]);
    // A branch of a set operation.
    assert_shown_secret_masked(&[(
        "WITH c AS (SELECT nm AS p FROM t UNION ALL SELECT {s} FROM s) \
         SELECT p FROM c WHERE p = '{v}'",
        "pwd",
        "nik",
    )]);
    // A CTE computing a column from another.
    assert_compared_with_no_bare_column_masked(&[(
        "WITH c AS (SELECT {s} AS p FROM t), d AS (SELECT LOWER(p) AS q FROM c) \
         SELECT q FROM d WHERE q = '{v}'",
        "password",
        "username",
    )]);
}

#[test]
fn a_string_written_into_an_output_column_named_for_a_secret_is_masked() {
    // A column a statement creates is typed by no catalog: what it is
    // given is masked under any name.
    for name in ["password", "username", "api_key", "user_id"] {
        for template in [
            "CREATE TABLE a.x AS SELECT '{v}' AS {s}, id FROM b.t",
            "CREATE VIEW a.v AS SELECT id, UPPER('{v}') AS {s} FROM b.t",
        ] {
            let sql = template.replace("{s}", name).replace("{v}", READ_MARK);
            let shown = redact_secrets_for_display(&sql, &lexega_core::dialect::snowflake());
            assert!(!shown.contains(READ_MARK), "printed: {shown}");
        }
    }
}

#[test]
fn a_string_compared_with_a_variable_named_for_a_secret_outside_a_query_is_masked() {
    assert_compared_with_no_bare_column_masked(&[
        (
            "DECLARE {s} STRING; BEGIN IF ({s} = '{v}') THEN RETURN 1; END IF; END;",
            "pwd",
            "nom",
        ),
        (
            "DECLARE {s} STRING; BEGIN WHILE ({s} <> '{v}') DO {s} := 'x'; END WHILE; END;",
            "pwd",
            "nom",
        ),
        (
            "DECLARE {s} STRING; BEGIN LET b BOOLEAN := ({s} = '{v}'); RETURN b; END;",
            "pwd",
            "nom",
        ),
    ]);
}

#[test]
fn a_string_compared_with_a_source_column_a_secret_alias_shares_a_name_with_is_printed() {
    // A bare name in WHERE reads a column of the block's sources before a
    // select alias: `n` is the derived table's column `d.n`.
    let sql = format!(
        "INSERT INTO a.x SELECT pwd n FROM (SELECT pwd,n FROM b.t)d WHERE n='{READ_PLAIN}'"
    );
    let (json, _) = report_json_and_skipped("postgres", &sql);
    assert!(json.contains(READ_PLAIN), "{sql}");
    let shown = redact_secrets_for_display(
        "SELECT name AS password FROM users WHERE name = 'visible'",
        &lexega_core::dialect::snowflake(),
    );
    assert!(shown.contains("visible"), "{shown}");
}

/// Statements holding a canary in a comment between their first and last
/// token, each `(dialect, sql, canary, text a preview still shows)`: a
/// block comment, a line comment, and a comment in a `$$` and an
/// `AS BEGIN … END` body.
fn comments_inside_statements() -> Vec<(&'static str, &'static str, &'static str, &'static str)> {
    vec![
        (
            "snowflake",
            "DELETE /* password=CMTCANARY_01 */ FROM analytics.public.orders;",
            "CMTCANARY_01",
            "DELETE FROM analytics.public.orders",
        ),
        (
            "snowflake",
            "DELETE FROM -- secret=CMTCANARY_02\n  analytics.public.orders;",
            "CMTCANARY_02",
            "analytics.public.orders",
        ),
        (
            "snowflake",
            "CREATE OR REPLACE PROCEDURE p() RETURNS STRING LANGUAGE SQL AS\n$$\nBEGIN\n  \
             -- previous value was password=CMTCANARY_03\n  DELETE FROM t3;\n  RETURN 'ok';\nEND;\n$$;",
            "CMTCANARY_03",
            "DELETE FROM t3",
        ),
        (
            "postgres",
            "CREATE FUNCTION f() RETURNS void LANGUAGE plpgsql AS $$\nBEGIN\n  \
             /* pwd=CMTCANARY_04 */ DELETE FROM app.events;\nEND;\n$$;",
            "CMTCANARY_04",
            "DELETE FROM app.events",
        ),
        (
            "mssql",
            "CREATE PROCEDURE dbo.p AS\nBEGIN\n  -- old: Password=CMTCANARY_05\n  \
             DELETE FROM dbo.t;\nEND;",
            "CMTCANARY_05",
            "DELETE FROM dbo.t",
        ),
        (
            "mssql",
            "DELETE /* Pwd=CMTCANARY_06 */ FROM dbo.Visits;",
            "CMTCANARY_06",
            "DELETE FROM dbo.Visits",
        ),
    ]
}

/// The report of `sql` under the dialect `name`, with the trace when
/// `trace` is set.
fn traced_report(name: &str, sql: &str, trace: bool) -> lexega_core::analyzer::AnalysisReport {
    use lexega_core::analyzer::AnalysisConfig;
    use lexega_core::api::analyze_risk_with_policy_config;

    let cfg = AnalysisConfig {
        dialect: Some(lexega_core::dialect::dialect_from_name(name).expect("known dialect")),
        trace_mode: trace,
        ..Default::default()
    };
    analyze_risk_with_policy_config(sql, &cfg).expect("should analyze")
}

#[test]
fn a_comment_inside_a_statement_reaches_no_report_json() {
    for (name, sql, canary, shown) in comments_inside_statements() {
        let json = serde_json::to_string(&traced_report(name, sql, false)).expect("serializes");
        assert!(!json.contains(canary), "{name}: {sql}\n{json}");
        assert!(json.contains(shown), "{name}: {sql}\n{json}");
    }
}

#[test]
fn a_comment_inside_a_statement_reaches_no_sarif() {
    use lexega_core::analyzer::{to_sarif, ToolRun};

    let run = ToolRun {
        name: "lexega",
        version: "test",
        base_path: None,
        depth_note: None,
        unrendered_files: &[],
        skipped_files: &[],
        macro_files: &[],
        run_notes: &[],
    };
    for (name, sql, canary, shown) in comments_inside_statements() {
        let report = traced_report(name, sql, false);
        let sarif = serde_json::to_string(&to_sarif(&report, &run)).expect("serializes");
        assert!(!sarif.contains(canary), "{name}: {sql}\n{sarif}");
        assert!(sarif.contains(shown), "{name}: {sql}\n{sarif}");
    }
}

#[test]
fn a_comment_inside_a_statement_reaches_no_trace_report() {
    for (name, sql, canary, shown) in comments_inside_statements() {
        let report = traced_report(name, sql, true);
        let json = serde_json::to_string(&report).expect("serializes");
        assert!(!json.contains(canary), "{name}: {sql}\n{json}");
        assert!(
            report
                .statement_explanations
                .iter()
                .any(|e| e.statement_preview.contains(shown)),
            "{name}: {sql}\n{json}"
        );
    }
}

#[test]
fn a_comment_between_two_tokens_leaves_one_space_in_the_preview() {
    let report = traced_report("snowflake", "DELETE/*x*/FROM t;", false);
    let previews: Vec<String> = report
        .entries()
        .flat_map(|entry| {
            let RuleMatch::Analysis(found) = entry;
            found.evidence.iter().filter_map(|evidence| match evidence {
                lexega_core::analyzer::RiskEvidence::RuleMatch {
                    statement_preview, ..
                } => statement_preview.clone(),
                lexega_core::analyzer::RiskEvidence::TableReference { .. }
                | lexega_core::analyzer::RiskEvidence::PredicateInfo { .. } => None,
            })
        })
        .collect();
    assert!(!previews.is_empty());
    assert!(
        previews.iter().all(|p| p == "DELETE FROM t"),
        "{previews:?}"
    );
}

/// Each `(dialect, script, canary, shown)`: a comment in the SQL text a
/// statement runs, printed nowhere, the statement still shown.
fn comments_inside_run_text() -> Vec<(&'static str, &'static str, &'static str, &'static str)> {
    vec![
        (
            "mssql",
            "EXEC sp_executesql N'DELETE FROM dbo.t /* password=RunCmtA1 */';",
            "RunCmtA1",
            "EXEC sp_executesql",
        ),
        (
            "mssql",
            "EXEC('DELETE FROM dbo.t /* api key RunCmtB2 */');",
            "RunCmtB2",
            "EXEC(",
        ),
        (
            "postgresql",
            "CREATE FUNCTION g(n text) RETURNS void LANGUAGE plpgsql AS $$\nBEGIN\n  \
             EXECUTE 'DELETE FROM t -- RunCmtC3 ' || n;\nEND;\n$$;",
            "RunCmtC3",
            "EXECUTE '",
        ),
        (
            "snowflake",
            "EXECUTE IMMEDIATE 'DELETE /* password=RunCmtD4 */ FROM t';",
            "RunCmtD4",
            "EXECUTE IMMEDIATE",
        ),
        (
            "snowflake",
            "EXECUTE IMMEDIATE $$DELETE /* password=RunCmtE5 */ FROM t$$;",
            "RunCmtE5",
            "EXECUTE IMMEDIATE",
        ),
    ]
}

#[test]
fn a_comment_inside_the_sql_text_a_statement_runs_reaches_no_report() {
    for (name, sql, canary, shown) in comments_inside_run_text() {
        for trace in [false, true] {
            let json = serde_json::to_string(&traced_report(name, sql, trace)).expect("serializes");
            assert!(
                !json.contains(canary),
                "{name} trace={trace}: {sql}\n{json}"
            );
            // The trace previews every statement.
            assert!(
                !trace || json.contains(shown),
                "{name} trace={trace}: {sql}\n{json}"
            );
        }
    }
}

/// Each `(dialect, script, kept)`: a dollar-quoted string that is data,
/// whose text, a comment marker in it included, a preview quotes whole.
fn dollar_quoted_strings() -> Vec<(&'static str, &'static str, &'static str)> {
    vec![
        (
            "snowflake",
            "DELETE FROM t WHERE a = $$x -- KeptDolA1 y$$;",
            "$$x -- KeptDolA1 y$$",
        ),
        (
            "snowflake",
            "DELETE FROM t WHERE a = $$x /* KeptDolB2 */ y$$;",
            "$$x /* KeptDolB2 */ y$$",
        ),
        (
            "snowflake",
            "CREATE OR REPLACE TABLE t2 COMMENT = $$owner -- KeptDolC3$$ AS SELECT * FROM t;",
            "$$owner -- KeptDolC3$$",
        ),
        (
            "postgresql",
            "DELETE FROM t WHERE a = $q$x -- KeptDolD4 y$q$;",
            "$q$x -- KeptDolD4 y$q$",
        ),
        (
            "postgresql",
            "DELETE FROM t WHERE a = 'x' || $$ -- KeptDolE5 $$ || 'kept';",
            "$$ -- KeptDolE5 $$ || 'kept'",
        ),
        (
            "redshift",
            "DELETE FROM t WHERE a = $$x -- KeptDolF6 y$$;",
            "$$x -- KeptDolF6 y$$",
        ),
    ]
}

#[test]
fn a_dollar_quoted_string_is_quoted_whole_in_previews() {
    for (name, sql, kept) in dollar_quoted_strings() {
        let report = traced_report(name, sql, true);
        let previews: Vec<&str> = report
            .statement_explanations
            .iter()
            .map(|e| e.statement_preview.as_str())
            .collect();
        assert!(
            previews.iter().any(|p| p.contains(kept)),
            "{name}: {sql}\n{previews:?}"
        );
    }
}

#[test]
fn a_statement_prefix_is_cut_after_its_comments_are_left_out() {
    let sql = format!(
        "DELETE /* {} */ FROM analytics.public.orders;",
        "x".repeat(70)
    );
    let report = traced_report("snowflake", &sql, true);
    let previews: Vec<&str> = report
        .statement_traces
        .iter()
        .map(|t| t.statement_preview.as_str())
        .collect();
    assert_eq!(previews, ["DELETE FROM analytics.public.orders"], "{sql}");
}

/// Each `(dialect, script, canary, shown)`: a literal passed to a routine
/// the run holds no definition of, masked wherever a report quotes it, the
/// call still shown.
fn literals_passed_to_routines_not_held(
) -> Vec<(&'static str, &'static str, &'static str, &'static str)> {
    vec![
        (
            "mssql",
            "EXEC dbo.usp_Unknown N'NoDefPwA1';",
            "NoDefPwA1",
            "EXEC dbo.usp_Unknown",
        ),
        (
            "mssql",
            "EXEC dbo.usp_Unknown @pwd = N'NoDefPwB2';",
            "NoDefPwB2",
            "EXEC dbo.usp_Unknown @pwd",
        ),
        (
            "mssql",
            "DECLARE @p NVARCHAR(100) = N'NoDefPwC3';\nEXEC dbo.usp_Unknown @p;",
            "NoDefPwC3",
            "EXEC dbo.usp_Unknown @p",
        ),
        (
            "mssql",
            "EXEC [dbo].[usp_Unknown] N'NoDefPwD4';",
            "NoDefPwD4",
            "EXEC [dbo].[usp_Unknown]",
        ),
        (
            "postgresql",
            "CALL set_pwd('NoDefPwE5');",
            "NoDefPwE5",
            "CALL set_pwd",
        ),
        (
            "postgresql",
            "CALL set_pwd(p => 'NoDefPwF6');",
            "NoDefPwF6",
            "CALL set_pwd",
        ),
        (
            "snowflake",
            "CALL set_pwd('NoDefPwG7');",
            "NoDefPwG7",
            "CALL set_pwd",
        ),
        (
            "snowflake",
            "CALL set_pwd(p => 'NoDefPwH8');",
            "NoDefPwH8",
            "CALL set_pwd",
        ),
    ]
}

#[test]
fn a_literal_passed_to_a_routine_the_run_holds_no_definition_of_is_masked() {
    for (name, sql, canary, shown) in literals_passed_to_routines_not_held() {
        for trace in [false, true] {
            let json = serde_json::to_string(&traced_report(name, sql, trace)).expect("serializes");
            assert!(
                !json.contains(canary),
                "{name} trace={trace}: {sql}\n{json}"
            );
            // The trace previews every statement.
            assert!(
                !trace || json.contains(shown),
                "{name} trace={trace}: {sql}\n{json}"
            );
        }
    }
}

#[test]
fn a_literal_passed_to_a_routine_the_script_defines_that_does_not_run_it_is_shown() {
    let sql = "CREATE PROCEDURE dbo.usp_Log @m NVARCHAR(100) AS\nBEGIN\n  \
               INSERT INTO dbo.log_entries (m) VALUES (@m);\nEND;\nGO\n\
               EXEC dbo.usp_Log N'ShownLogA1';\n";
    let json = serde_json::to_string(&traced_report("mssql", sql, true)).expect("serializes");
    assert!(!json.contains("ShownLogA1"), "{json}");
}

#[test]
fn an_argument_a_system_procedure_reads_as_a_name_or_an_option_is_shown() {
    // A login's, a role's, an option's or an object's name.
    for (sql, shown) in [
        ("EXEC sp_addsrvrolemember 'bob', 'sysadmin';", "'sysadmin'"),
        ("EXEC sp_addrolemember 'db_owner', 'bob';", "'db_owner'"),
        (
            "EXEC sp_configure 'xp_cmdshell', 1;",
            "sp_configure 'xp_cmdshell'",
        ),
        (
            "EXEC sp_droprolemember 'db_datareader', 'bob';",
            "'db_datareader'",
        ),
        ("EXEC sp_dropsrvrolemember 'bob', 'sysadmin';", "'sysadmin'"),
        (
            "EXEC master.dbo.sp_addsrvrolemember @loginame = N'bob', @rolename = N'sysadmin';",
            "N'sysadmin'",
        ),
        (
            "EXEC [sys].[sp_addrolemember] N'db_owner', N'bob';",
            "N'db_owner'",
        ),
        ("EXEC sp_rename 'dbo.a', 'b';", "'dbo.a'"),
    ] {
        let json = serde_json::to_string(&traced_report("mssql", sql, true)).expect("serializes");
        assert!(json.contains(shown), "{sql}\n{json}");
    }
    // Any other argument of a system procedure is masked.
    for (sql, shown) in [
        ("EXEC sp_password 'OldPwA1', 'NewPwA2', 'bob';", "'bob'"),
        (
            "EXEC sp_add_jobstep @subsystem = N'CmdExec', @command = N'dir';",
            "N'CmdExec'",
        ),
    ] {
        let json = serde_json::to_string(&traced_report("mssql", sql, true)).expect("serializes");
        assert!(!json.contains(shown), "{sql}\n{json}");
    }
}

#[test]
fn an_argument_a_system_procedure_may_hold_a_credential_in_is_masked() {
    for (sql, canary) in [
        ("EXEC xp_cmdshell 'net user x XpCmdPwB1 /add';", "XpCmdPwB1"),
        (
            "EXEC master..xp_cmdshell N'XpCmdPwB2', no_output;",
            "XpCmdPwB2",
        ),
        ("EXEC sp_password 'OldPwB3', 'NewPwB4', 'bob';", "OldPwB3"),
        ("EXEC sp_password 'OldPwB3', 'NewPwB4', 'bob';", "NewPwB4"),
        (
            "EXEC sp_addlinkedsrvlogin 'srv', 'false', NULL, 'rmt', 'LinkPwB5';",
            "LinkPwB5",
        ),
        (
            "EXEC msdb.dbo.sp_add_jobstep @job_name = N'j', @step_name = N's', \
             @subsystem = N'CmdExec', @command = N'JobCmdPwB6';",
            "JobCmdPwB6",
        ),
        // A position or a name the procedure does not take.
        ("EXEC sp_configure 'a', 1, 'ExtraPwB7';", "ExtraPwB7"),
        (
            "EXEC sp_addrolemember @rolename = 'r', @pwd = 'NamedPwB8';",
            "NamedPwB8",
        ),
    ] {
        for trace in [false, true] {
            let json =
                serde_json::to_string(&traced_report("mssql", sql, trace)).expect("serializes");
            assert!(!json.contains(canary), "{sql} trace={trace}\n{json}");
        }
    }
}

#[test]
fn a_literal_passed_to_a_postgresql_function_the_run_holds_no_definition_of_is_masked() {
    for (sql, canary) in [
        (
            "UPDATE app.audit SET note = set_pwd_f('XpFnA1canary');",
            "XpFnA1canary",
        ),
        ("SELECT set_pwd_f('XpFnB2canary');", "XpFnB2canary"),
        (
            "DELETE FROM app.t WHERE k = set_pwd_f('XpFnC3canary');",
            "XpFnC3canary",
        ),
        // A schema other than the built-ins' names a function of its own.
        ("SELECT app.upper('XpFnD4canary');", "XpFnD4canary"),
        ("SELECT upper(set_pwd_f('XpFnE5canary'));", "XpFnE5canary"),
        (
            "SELECT set_pwd_f(p => 'XpFnF6canary') FROM app.t;",
            "XpFnF6canary",
        ),
    ] {
        for trace in [false, true] {
            let json = serde_json::to_string(&traced_report("postgresql", sql, trace))
                .expect("serializes");
            assert!(!json.contains(canary), "{sql} trace={trace}\n{json}");
        }
    }
}

#[test]
fn a_literal_passed_to_a_snowflake_procedure_selected_from_as_a_table_is_masked() {
    for (sql, canary) in [
        (
            "SELECT * FROM TABLE(set_pwd_tbl('XpTblA1canary'));",
            "XpTblA1canary",
        ),
        (
            "SELECT t.* FROM TABLE(app.set_pwd_tbl(p => 'XpTblB2canary')) t JOIN u ON u.id = t.id;",
            "XpTblB2canary",
        ),
    ] {
        for trace in [false, true] {
            let json =
                serde_json::to_string(&traced_report("snowflake", sql, trace)).expect("serializes");
            assert!(!json.contains(canary), "{sql} trace={trace}\n{json}");
        }
    }
    // A built-in table function keeps its literals.
    for (sql, shown) in [
        (
            "SELECT * FROM TABLE(FLATTEN(input => PARSE_JSON('ShownTblC3')));",
            "ShownTblC3",
        ),
        (
            "SELECT * FROM TABLE(INFORMATION_SCHEMA.QUERY_HISTORY_BY_USER(USER_NAME => 'ShownTblD4'));",
            "ShownTblD4",
        ),
        (
            "SELECT * FROM TABLE(RESULT_SCAN('ShownTblE5'));",
            "ShownTblE5",
        ),
    ] {
        let json =
            serde_json::to_string(&traced_report("snowflake", sql, true)).expect("serializes");
        assert!(!json.contains(shown), "{sql}\n{json}");
    }
}

#[test]
fn a_literal_passed_to_a_built_in_or_a_function_that_runs_no_sql_is_shown() {
    for (dialect, sql, shown) in [
        (
            "postgresql",
            "SELECT upper('ShownFnA1') FROM app.t;",
            "ShownFnA1",
        ),
        (
            "postgresql",
            "SELECT pg_catalog.lower('ShownFnB2') FROM app.t;",
            "ShownFnB2",
        ),
        (
            "postgresql",
            "SELECT lpad(name, 9, 'ShownFnC3') FROM app.t;",
            "ShownFnC3",
        ),
        (
            "postgresql",
            "SELECT nextval('app.ShownFnD4_seq');",
            "ShownFnD4",
        ),
        (
            "postgresql",
            "CREATE FUNCTION log_f(m text) RETURNS void LANGUAGE sql AS $$ \
             INSERT INTO app.log VALUES (m) $$;\nSELECT log_f('ShownFnE5');",
            "ShownFnE5",
        ),
        // Where no function a user defines runs SQL text.
        ("mssql", "SELECT dbo.fn_mask('ShownFnF6');", "ShownFnF6"),
        ("snowflake", "SELECT my_udf('ShownFnG7');", "ShownFnG7"),
        ("mysql", "SELECT my_fn('ShownFnH8');", "ShownFnH8"),
    ] {
        let json = serde_json::to_string(&traced_report(dialect, sql, true)).expect("serializes");
        assert!(!json.contains(shown), "{dialect}: {sql}\n{json}");
    }
}

/// A PostgreSQL procedure that runs its parameter, which T-SQL reads no
/// body of.
const PG_SET_PWD: &str = "\
CREATE PROCEDURE set_pwd(p text) LANGUAGE plpgsql AS $$
DECLARE
  s text;
BEGIN
  s := 'ALTER ROLE app PASSWORD ''' || p || '''';
  EXECUTE s;
END
$$;
";

#[test]
fn a_literal_passed_to_a_routine_whose_body_was_not_read_is_masked() {
    for (call, canary) in [
        ("CALL set_pwd('XpUnreadA1canary');", "XpUnreadA1canary"),
        (
            "DO $$\nBEGIN\n  CALL set_pwd('XpUnreadB2canary');\nEND\n$$;",
            "XpUnreadB2canary",
        ),
        ("EXEC set_pwd N'XpUnreadC3canary';", "XpUnreadC3canary"),
    ] {
        let sql = format!("{PG_SET_PWD}{call}\n");
        for trace in [false, true] {
            let json =
                serde_json::to_string(&traced_report("mssql", &sql, trace)).expect("serializes");
            assert!(!json.contains(canary), "{call} trace={trace}\n{json}");
        }
    }
    // A Snowflake procedure names a language T-SQL writes no routine in.
    let snowflake = "CREATE OR REPLACE PROCEDURE set_pwd(p STRING)\nRETURNS STRING\n\
                     LANGUAGE SQL\nAS\n$$\nDECLARE\n  s STRING;\nBEGIN\n  \
                     s := 'ALTER USER app SET PASSWORD = ''' || :p || '''';\n  \
                     EXECUTE IMMEDIATE :s;\n  RETURN 'x';\nEND;\n$$;\n\
                     CALL set_pwd('XpUnreadD4canary');\n";
    let json = serde_json::to_string(&traced_report("mssql", snowflake, true)).expect("serializes");
    assert!(!json.contains("XpUnreadD4canary"), "{json}");
}

#[test]
fn a_literal_a_variable_holds_where_a_statement_that_does_not_parse_reads_it_is_masked() {
    // T-SQL read as MySQL or BigQuery: the EXEC does not parse, and may run
    // what the variable holds.
    for dialect in ["mysql", "bigquery", "mssql"] {
        for (sql, canary) in [
            (
                "DECLARE @p NVARCHAR(100) = N'XpWrongA1canary';\nEXEC dbo.usp_SetPwd @p;\n",
                "XpWrongA1canary",
            ),
            (
                "SET @q = N'XpWrongB2canary';\nEXEC dbo.usp_SetPwd @pwd = @q;\n",
                "XpWrongB2canary",
            ),
            (
                "SET @q = N'XpWrongC3canary';\nFROBNICATE THE WIDGET WITH @q;\n",
                "XpWrongC3canary",
            ),
            (
                "CREATE OR ALTER PROCEDURE dbo.usp_Rotate AS\nBEGIN\n    \
                 DECLARE @v NVARCHAR(100) = N'XpWrongD4canary';\n    \
                 EXEC dbo.usp_SetPwd @v;\nEND;\n",
                "XpWrongD4canary",
            ),
        ] {
            let json =
                serde_json::to_string(&traced_report(dialect, sql, true)).expect("serializes");
            assert!(!json.contains(canary), "{dialect}: {sql}\n{json}");
        }
    }
}

/// Each canary of `cases` (dialect, SQL, canary) is masked in the report,
/// traced and not.
fn assert_masked(cases: &[(&str, &str, &str)]) {
    for (dialect, sql, canary) in cases {
        for trace in [false, true] {
            let json =
                serde_json::to_string(&traced_report(dialect, sql, trace)).expect("serializes");
            assert!(
                !json.contains(canary),
                "{dialect}: {sql} trace={trace}\n{json}"
            );
        }
    }
}

/// Each text of `cases` (dialect, SQL, text) is shown in the traced report.
fn assert_shown(cases: &[(&str, &str, &str)]) {
    for (dialect, sql, shown) in cases {
        let json = serde_json::to_string(&traced_report(dialect, sql, true)).expect("serializes");
        assert!(json.contains(shown), "{dialect}: {sql}\n{json}");
    }
}

#[test]
fn sql_text_a_routine_of_the_dialect_runs_is_masked_as_sql_it_runs() {
    assert_masked(&[
        (
            "postgresql",
            "SELECT dblink_exec('c', 'ALTER ROLE app PASSWORD ''XpRunA1canary''');",
            "XpRunA1canary",
        ),
        (
            "postgresql",
            "SELECT dblink('c', 'ALTER ROLE app PASSWORD ''XpRunB2canary''');",
            "XpRunB2canary",
        ),
        (
            "postgresql",
            "SELECT dblink_send_query('c', 'CREATE USER u PASSWORD ''XpRunC3canary''');",
            "XpRunC3canary",
        ),
        (
            "postgresql",
            "SELECT dblink_exec('ALTER ROLE app PASSWORD ''XpRunD4canary''');",
            "XpRunD4canary",
        ),
        (
            "postgresql",
            "SELECT * FROM dblink('c', 'SELECT 1; ALTER USER u PASSWORD ''XpRunE5canary''') AS t(x int);",
            "XpRunE5canary",
        ),
        (
            "postgresql",
            "DO $$ BEGIN PERFORM dblink_exec('c', 'ALTER ROLE app PASSWORD ''XpRunF6canary'''); END $$;",
            "XpRunF6canary",
        ),
        (
            "postgresql",
            "DELETE FROM app.t WHERE k = (SELECT dblink_exec('c', 'ALTER ROLE app PASSWORD ''XpRunG7canary'''));",
            "XpRunG7canary",
        ),
        (
            "postgresql",
            "SELECT dblink('c', 'ALTER ROLE app PASSWORD ''XpRunH8canary''', true);",
            "XpRunH8canary",
        ),
        (
            "postgresql",
            "SELECT dblink_open('c', 'cur', 'SELECT 1 WHERE ''XpRunI9canary'' = pw');",
            "XpRunI9canary",
        ),
        (
            "postgresql",
            "SELECT query_to_xml('ALTER ROLE app PASSWORD ''XpRunJ10canary''', true, false, '');",
            "XpRunJ10canary",
        ),
        // Which argument is run is not decided: each is withheld.
        (
            "postgresql",
            "SELECT dblink('ALTER ROLE app PASSWORD ''XpRunK11canary''', f) FROM app.t;",
            "XpRunK11canary",
        ),
        // dblink installed in a schema of the user's is a function of the user's.
        (
            "postgresql",
            "SELECT app.dblink_exec('c', 'XpRunL12canary');",
            "XpRunL12canary",
        ),
        (
            "mssql",
            "SELECT * FROM OPENQUERY(LNK, 'ALTER LOGIN app WITH PASSWORD = ''XpRunM13canary''');",
            "XpRunM13canary",
        ),
        (
            "mssql",
            "SELECT * FROM OPENROWSET('MSOLEDBSQL', 'Server=s;Trusted_Connection=yes;', \
             'ALTER LOGIN app WITH PASSWORD = ''XpRunN14canary''');",
            "XpRunN14canary",
        ),
        (
            "mysql",
            "CALL sys.execute_prepared_stmt('ALTER USER u IDENTIFIED BY ''XpRunO15canary''');",
            "XpRunO15canary",
        ),
        (
            "mssql",
            "EXEC sp_prepexec @h OUTPUT, NULL, N'ALTER LOGIN a WITH PASSWORD = ''XpRunP16canary''';",
            "XpRunP16canary",
        ),
        (
            "mssql",
            "EXEC sp_prepexec @h OUTPUT, N'@p NVARCHAR(50)', N'ALTER LOGIN a WITH PASSWORD = @p', \
             N'XpRunQ17canary';",
            "XpRunQ17canary",
        ),
        (
            "mssql",
            "EXEC sp_cursoropen @c OUTPUT, N'SELECT 1 WHERE ''XpRunR18canary'' = pw';",
            "XpRunR18canary",
        ),
    ]);
}

#[test]
fn what_a_routine_of_the_dialect_reads_as_a_name_or_an_option_is_masked() {
    assert_masked(&[
        (
            "postgresql",
            "SELECT dblink_exec('ShownRunA1', 'DROP TABLE app.t');",
            "ShownRunA1",
        ),
        (
            "postgresql",
            "SELECT * FROM dblink_fetch('ShownRunB2', 10) AS t(x int);",
            "ShownRunB2",
        ),
    ]);
    // The SQL text a routine runs is quoted as its own statements are.
    let shown = redact_secrets_for_display(
        "SELECT dblink_exec('ShownRunA1', 'DROP TABLE app.t');",
        &lexega_core::dialect::postgres(),
    );
    assert!(shown.contains("'DROP TABLE app.t'"), "{shown}");
    assert_quoted(&[(
        "mssql",
        "SELECT * FROM OPENQUERY(LNK, 'SELECT k FROM dbo.ShownRunD4');",
        "'SELECT k FROM dbo.ShownRunD4'",
    )]);
    // A linked server's name is a name, no literal.
    assert_shown(&[(
        "mssql",
        "SELECT * FROM OPENQUERY(ShownRunC3, 'SELECT k FROM dbo.t');",
        "ShownRunC3",
    )]);
}

#[test]
fn a_procedure_named_as_a_system_procedure_in_a_schema_of_the_users_is_masked() {
    assert_masked(&[
        (
            "mssql",
            "EXEC util.sp_configure 'XpSysUsrA1canary';",
            "XpSysUsrA1canary",
        ),
        (
            "mssql",
            "EXEC app.sp_rename @objname = 'XpSysUsrB2canary';",
            "XpSysUsrB2canary",
        ),
        (
            "mssql",
            "EXEC app.sp_executesql N'ALTER LOGIN a WITH PASSWORD = ''XpSysUsrC3canary''';",
            "XpSysUsrC3canary",
        ),
        (
            "mssql",
            "EXEC db.util.sp_addrolemember 'XpSysUsrD4canary', 'bob';",
            "XpSysUsrD4canary",
        ),
    ]);
    // Bare, or in the schema or the database the dialect's own are in: a
    // name the dialect's procedure takes is shown.
    assert_shown(&[
        (
            "mssql",
            "EXEC dbo.sp_configure 'ShownSysA1', 1;",
            "ShownSysA1",
        ),
        (
            "mssql",
            "EXEC master..sp_configure 'ShownSysB2', 1;",
            "ShownSysB2",
        ),
        (
            "mssql",
            "EXEC OtherDb.sys.sp_addrolemember 'ShownSysC3', 'bob';",
            "ShownSysC3",
        ),
        (
            "mssql",
            "EXEC [LNK].[master].[dbo].sp_addrolemember 'ShownSysD4', 'bob';",
            "ShownSysD4",
        ),
    ]);
}

#[test]
fn a_literal_passed_to_a_postgresql_function_in_a_definition_is_masked() {
    assert_masked(&[
        (
            "postgresql",
            "ALTER TABLE app.t ADD COLUMN c text NOT NULL DEFAULT set_pwd_f('XpDdlA1canary');",
            "XpDdlA1canary",
        ),
        (
            "postgresql",
            "ALTER TABLE app.t ALTER COLUMN c SET DEFAULT set_pwd_f('XpDdlB2canary');",
            "XpDdlB2canary",
        ),
        (
            "postgresql",
            "CREATE TABLE app.t2 (c text CHECK (set_pwd_f('XpDdlC3canary') IS NOT NULL));",
            "XpDdlC3canary",
        ),
        (
            "postgresql",
            "CREATE POLICY p ON app.t USING (set_pwd_f('XpDdlD4canary') = 'a');",
            "XpDdlD4canary",
        ),
        (
            "postgresql",
            "CREATE TABLE app.t (c text DEFAULT set_pwd_f('XpDdlE5canary'));",
            "XpDdlE5canary",
        ),
        (
            "postgresql",
            "CREATE TABLE app.t3 (c text GENERATED ALWAYS AS (set_pwd_f('XpDdlF6canary')) STORED);",
            "XpDdlF6canary",
        ),
        (
            "postgresql",
            "ALTER TABLE app.t ADD CONSTRAINT k CHECK (set_pwd_f('XpDdlG7canary') <> c);",
            "XpDdlG7canary",
        ),
        (
            "postgresql",
            "ALTER TABLE app.t ALTER COLUMN c TYPE int USING set_pwd_f('XpDdlH8canary');",
            "XpDdlH8canary",
        ),
        (
            "postgresql",
            "CREATE TABLE app.t4 (c text, CONSTRAINT k CHECK (set_pwd_f('XpDdlJ10canary') <> c));",
            "XpDdlJ10canary",
        ),
        (
            "snowflake",
            "DELETE FROM t WHERE k IN (SELECT c FROM TABLE(IDENTIFIER('db.sch.set_pwd')('XpDdlI9canary')));",
            "XpDdlI9canary",
        ),
    ]);
    // Where no function a user defines runs SQL text.
    assert_masked(&[(
        "mssql",
        "ALTER TABLE dbo.t ADD c NVARCHAR(10) DEFAULT dbo.f('ShownDdlA1');",
        "ShownDdlA1",
    )]);
}

#[test]
fn a_routine_name_is_read_as_the_dialect_compares_one() {
    // BigQuery compares a routine's name and its dataset as written.
    let bigquery = "CREATE PROCEDURE ds.runq(p STRING)\nBEGIN\n  SELECT 1;\nEND;\n";
    let quoted_path = format!("{bigquery}CALL `ds.RunQ`('XpCaseA1canary');\n");
    let bare = format!("{bigquery}CALL ds.RunQ('XpCaseB2canary');\n");
    let parts = format!("{bigquery}CALL `DS`.`runq`('XpCaseC3canary');\n");
    let same = format!("{bigquery}CALL `ds.runq`('ShownCaseA1');\n");
    assert_masked(&[
        ("bigquery", &quoted_path, "XpCaseA1canary"),
        ("bigquery", &bare, "XpCaseB2canary"),
        ("bigquery", &parts, "XpCaseC3canary"),
        // MySQL compares a routine's database as it compares a table's.
        (
            "mysql",
            "CREATE PROCEDURE `db`.log_p(m TEXT) BEGIN INSERT INTO t VALUES (m); END;\n\
             CALL `DB`.log_p('XpCaseD4canary');\n",
            "XpCaseD4canary",
        ),
    ]);
    assert_masked(&[
        ("bigquery", &same, "ShownCaseA1"),
        (
            "mysql",
            "CREATE PROCEDURE `db`.log_p(m TEXT) BEGIN INSERT INTO t VALUES (m); END;\n\
             CALL `db`.LOG_P('ShownCaseB2');\n",
            "ShownCaseB2",
        ),
        // Redshift folds a quoted name as it folds a bare one.
        (
            "redshift",
            "CREATE PROCEDURE log_p(m varchar) AS $$ BEGIN INSERT INTO app.log VALUES (m); END $$ \
             LANGUAGE plpgsql;\nCALL \"LOG_P\"('ShownCaseC3');\n",
            "ShownCaseC3",
        ),
    ]);
}

#[test]
fn a_value_bound_where_the_text_run_takes_a_password_is_masked() {
    assert_masked(&[
        (
            "snowflake",
            "EXECUTE IMMEDIATE 'CREATE USER u PASSWORD = ?' USING ('XpBindA1canary');",
            "XpBindA1canary",
        ),
        (
            "snowflake",
            "DECLARE pw STRING DEFAULT 'XpBindB2canary';\nBEGIN\n  \
             EXECUTE IMMEDIATE 'ALTER USER u SET PASSWORD = ?' USING (pw);\nEND;\n",
            "XpBindB2canary",
        ),
        (
            "mysql",
            "PREPARE st FROM 'ALTER USER u IDENTIFIED BY ?';\nSET @pw = 'XpBindC3canary';\n\
             EXECUTE st USING @pw;\n",
            "XpBindC3canary",
        ),
        (
            "mssql",
            "DECLARE @p NVARCHAR(50) = N'XpBindD4canary';\nEXEC sp_executesql \
             N'ALTER LOGIN app WITH PASSWORD = @p', N'@p NVARCHAR(50)', @p = @p;\n",
            "XpBindD4canary",
        ),
        (
            "mssql",
            "DECLARE @p NVARCHAR(50) = N'XpBindE5canary';\nALTER LOGIN app WITH PASSWORD = @p;\n",
            "XpBindE5canary",
        ),
    ]);
    // A value bound where the text takes no password is masked too: where
    // the text takes it is not read.
    assert_masked(&[(
        "snowflake",
        "EXECUTE IMMEDIATE 'SELECT * FROM t WHERE k = ?' USING ('XpBindF6canary');",
        "XpBindF6canary",
    )]);
}

#[test]
fn each_literal_a_value_may_be_where_a_statement_runs_it_is_masked() {
    assert_masked(&[
        (
            "mssql",
            "SET @s = CASE WHEN @x = 1 THEN N'ALTER LOGIN a WITH PASSWORD = ''XpChoiceA1canary''' \
             ELSE N'SELECT 1' END;\nEXEC (@s);\n",
            "XpChoiceA1canary",
        ),
        (
            "mssql",
            "SET @s = IIF(@x = 1, N'SELECT 1', N'ALTER LOGIN a WITH PASSWORD = ''XpChoiceB2canary''');\n\
             EXEC (@s);\n",
            "XpChoiceB2canary",
        ),
        (
            "mssql",
            "DECLARE @s NVARCHAR(MAX) = COALESCE(@y, N'ALTER LOGIN a WITH PASSWORD = ''XpChoiceC3canary''');\n\
             EXEC ('PRINT 1; ' + @s);\n",
            "XpChoiceC3canary",
        ),
        (
            "mysql",
            "SET @s = IF(@x = 1, 'ALTER USER a IDENTIFIED BY ''XpChoiceD4canary''', 'SELECT 1');\n\
             PREPARE st FROM @s;\nEXECUTE st;\n",
            "XpChoiceD4canary",
        ),
    ]);
}

#[test]
fn a_literal_template_code_passes_where_no_template_is_rendered_is_masked() {
    assert_masked(&[
        (
            "snowflake",
            "{{ rotate_pwd('XpTmplA1canary') }}\nselect 1 as a\n",
            "XpTmplA1canary",
        ),
        (
            "snowflake",
            "select {{ mk(\"XpTmplB2canary\") }} as a from t\n",
            "XpTmplB2canary",
        ),
        (
            "postgresql",
            "{% set pw = 'XpTmplC3canary' %}\ndelete from tgt where k = 1\n",
            "XpTmplC3canary",
        ),
        (
            "snowflake",
            "{{ config(post_hook=\"CALL admin.set_pwd('XpTmplD4canary')\") }}\nselect 1 as a\n",
            "XpTmplD4canary",
        ),
    ]);
    // The relation a reference names is template code too, where no
    // template is rendered.
    let shown = redact_secrets_for_display(
        "select a from {{ ref('ShownTmplA1') }} join {{ source('raw', 'ShownTmplB2') }} using (a)\n",
        &lexega_core::dialect::snowflake(),
    );
    assert!(!shown.contains("ShownTmplA1"), "{shown}");
}

#[test]
fn every_value_bound_to_text_a_statement_runs_is_masked() {
    assert_masked(&[
        (
            "postgresql",
            "DO $$ BEGIN EXECUTE 'UPDATE users SET password = $1' USING 'XpBoundA1canary'; END $$;",
            "XpBoundA1canary",
        ),
        (
            "postgresql",
            "DO $$ BEGIN EXECUTE 'SELECT app.set_pwd($1)' USING 'XpBoundB2canary'; END $$;",
            "XpBoundB2canary",
        ),
        (
            "postgresql",
            "DO $$ BEGIN EXECUTE 'ALTER ROLE a PASSWORD $1' USING 'XpBoundC3canary'; END $$;",
            "XpBoundC3canary",
        ),
        (
            "postgresql",
            "PREPARE p(text) AS SELECT set_pwd_f($1);\nEXECUTE p('XpBoundD4canary');",
            "XpBoundD4canary",
        ),
        (
            "postgresql",
            "PREPARE p(text) AS UPDATE app.users SET password = $1;\nEXECUTE p('XpBoundE5canary');",
            "XpBoundE5canary",
        ),
        // A statement prepared where the script does not show it.
        (
            "postgresql",
            "EXECUTE p('XpBoundF6canary');",
            "XpBoundF6canary",
        ),
        (
            "mysql",
            "PREPARE st FROM 'UPDATE users SET password = ?';\nSET @pw = 'XpBoundG7canary';\n\
             EXECUTE st USING @pw;",
            "XpBoundG7canary",
        ),
        (
            "mysql",
            "PREPARE st FROM 'CREATE USER u IDENTIFIED BY ?';\nEXECUTE st USING 'XpBoundO15canary';",
            "XpBoundO15canary",
        ),
        (
            "bigquery",
            "EXECUTE IMMEDIATE 'CALL ds.p(?)' USING 'XpBoundH8canary';",
            "XpBoundH8canary",
        ),
        (
            "bigquery",
            "EXECUTE IMMEDIATE 'CALL ds.p(@x)' USING 'XpBoundI9canary' AS x;",
            "XpBoundI9canary",
        ),
        (
            "databricks",
            "EXECUTE IMMEDIATE 'CALL cat.sch.p(?)' USING 'XpBoundJ10canary';",
            "XpBoundJ10canary",
        ),
        (
            "snowflake",
            "EXECUTE IMMEDIATE 'CREATE USER u PASSWORD = ?' USING (IFF(TRUE, 'XpBoundK11canary', 'b'));",
            "XpBoundK11canary",
        ),
        (
            "snowflake",
            "EXECUTE IMMEDIATE 'CREATE USER u PASSWORD = :1' USING ('XpBoundL12canary');",
            "XpBoundL12canary",
        ),
        (
            "snowflake",
            "EXECUTE IMMEDIATE 'SELECT * FROM t WHERE k = ?' USING ('XpBoundM13canary');",
            "XpBoundM13canary",
        ),
        (
            "mssql",
            "EXEC sp_executesql N'SELECT * FROM t WHERE k = @k', N'@k NVARCHAR(50)', @k = N'XpBoundN14canary';",
            "XpBoundN14canary",
        ),
    ]);
}

#[test]
fn what_a_variable_written_at_a_password_holds_is_masked_and_its_name_shown() {
    assert_masked(&[(
        "snowflake",
        "BEGIN\n  LET pw STRING := 'XpVarPwA1canary';\n  ALTER USER u SET PASSWORD = :pw;\nEND;\n",
        "XpVarPwA1canary",
    )]);
    assert_shown(&[(
        "mssql",
        "DECLARE @pw NVARCHAR(50) = N'x';\nALTER LOGIN app WITH PASSWORD = @pw;\n",
        "PASSWORD = @pw",
    )]);
}

#[test]
fn every_literal_of_an_expression_run_that_the_value_walk_does_not_read_is_masked() {
    assert_masked(&[
        (
            "postgresql",
            "SELECT dblink_send_query('c', CASE WHEN true THEN 'ALTER ROLE a PASSWORD ''XpUnreadA1canary''' \
             ELSE 'SELECT 1' END);",
            "XpUnreadA1canary",
        ),
        (
            "postgresql",
            "DO $$ BEGIN EXECUTE CASE WHEN random() > 0.5 THEN 'ALTER ROLE a PASSWORD ''XpUnreadB2canary''' \
             ELSE 'SELECT 1' END; END $$;",
            "XpUnreadB2canary",
        ),
        (
            "redshift",
            "CREATE PROCEDURE sp() AS $$ BEGIN EXECUTE CASE WHEN true THEN 'ALTER USER u PASSWORD ''XpUnreadC3canary''' \
             ELSE 'SELECT 1' END; END $$ LANGUAGE plpgsql;",
            "XpUnreadC3canary",
        ),
        (
            "postgresql",
            "SELECT dblink_exec('c', 'ALTER ROLE a PASSWORD ''' || (SELECT 'XpUnreadD4canary') || '''');",
            "XpUnreadD4canary",
        ),
        (
            "mssql",
            "DECLARE @s nvarchar(max);\nSET @s = REPLACE(N'ALTER LOGIN a WITH PASSWORD = ''#''', N'#', N'XpUnreadE5canary');\n\
             EXEC (@s);",
            "XpUnreadE5canary",
        ),
        (
            "mssql",
            "DECLARE @s nvarchar(max);\nSET @s = FORMATMESSAGE(N'ALTER LOGIN a WITH PASSWORD = ''%s''', N'XpUnreadF6canary');\n\
             EXEC (@s);",
            "XpUnreadF6canary",
        ),
    ]);
}

#[test]
fn a_definition_expression_is_read_and_its_literals_masked() {
    assert_masked(&[
        (
            "postgresql",
            "CREATE FUNCTION g(p text DEFAULT set_pwd_f('XpDefnA1canary')) RETURNS int LANGUAGE sql AS 'SELECT 1';",
            "XpDefnA1canary",
        ),
        (
            "postgresql",
            "CREATE OR REPLACE PROCEDURE app.p(pw text DEFAULT set_pwd_f('XpDefnB2canary')) LANGUAGE plpgsql \
             AS $$ BEGIN NULL; END $$;",
            "XpDefnB2canary",
        ),
        (
            "postgresql",
            "CREATE TABLE app.t10 (c text, EXCLUDE USING gist (set_pwd_f('XpDefnC3canary') WITH =));",
            "XpDefnC3canary",
        ),
        (
            "postgresql",
            "CREATE POLICY p ON app.t USING (set_pwd_f('a''XpDefnD4canary') = 'a');",
            "XpDefnD4canary",
        ),
        (
            "postgresql",
            "CREATE POLICY p ON app.t USING (set_pwd_f(E'a\\'XpDefnE5canary') = 'a');",
            "XpDefnE5canary",
        ),
    ]);
    // A definition's expressions are read; a default or a check is no
    // place a walk shows safe.
    assert_masked(&[
        (
            "postgresql",
            "CREATE TABLE app.orders (id int, status text NOT NULL DEFAULT 'ShownDefnA1');",
            "'ShownDefnA1'",
        ),
        (
            "postgresql",
            "ALTER TABLE app.orders ADD CONSTRAINT k CHECK (status <> 'ShownDefnB2');",
            "'ShownDefnB2'",
        ),
        (
            "postgresql",
            "ALTER TABLE app.orders ALTER COLUMN id SET DEFAULT nextval('ShownDefnC3');",
            "'ShownDefnC3'",
        ),
        (
            "postgresql",
            "CREATE FUNCTION g(p text DEFAULT 'ShownDefnD4') RETURNS int LANGUAGE sql AS 'SELECT 1';",
            "'ShownDefnD4'",
        ),
    ]);
}

#[test]
fn a_key_or_passphrase_a_builtin_function_takes_is_masked() {
    assert_masked(&[
        (
            "snowflake",
            "SELECT ENCRYPT('data', 'XpKeyA1canary');",
            "XpKeyA1canary",
        ),
        (
            "snowflake",
            "SELECT DECRYPT(c, 'XpKeyB2canary') FROM t;",
            "XpKeyB2canary",
        ),
        (
            "snowflake",
            "SELECT ENCRYPT_RAW(c, TO_BINARY('XpKeyC3canary', 'UTF-8'), iv) FROM t;",
            "XpKeyC3canary",
        ),
        (
            "mysql",
            "SELECT AES_ENCRYPT('data', 'XpKeyD4canary');",
            "XpKeyD4canary",
        ),
        (
            "mysql",
            "SELECT AES_DECRYPT(c, 'XpKeyE5canary') FROM t;",
            "XpKeyE5canary",
        ),
        (
            "postgresql",
            "SELECT pgp_sym_encrypt('data', 'XpKeyF6canary');",
            "XpKeyF6canary",
        ),
        (
            "postgresql",
            "SELECT hmac('data', 'XpKeyG7canary', 'sha256');",
            "XpKeyG7canary",
        ),
        (
            "mssql",
            "SELECT ENCRYPTBYPASSPHRASE(N'XpKeyH8canary', N'data');",
            "XpKeyH8canary",
        ),
        (
            "mssql",
            "SELECT DECRYPTBYPASSPHRASE(N'XpKeyI9canary', c) FROM t;",
            "XpKeyI9canary",
        ),
    ]);
    // The data a function encrypts is a value a query selects.
    assert_masked(&[(
        "snowflake",
        "SELECT ENCRYPT('ShownKeyA1', k) FROM t;",
        "ShownKeyA1",
    )]);
}

#[test]
fn the_body_of_a_template_set_block_no_template_renders_is_masked() {
    assert_masked(&[
        (
            "snowflake",
            "{% set q %}ALTER USER svc SET PASSWORD = 'XpSetBlkA1canary'{% endset %}\n{% do run_query(q) %}\n\
             select 1 as a\n",
            "XpSetBlkA1canary",
        ),
        (
            "snowflake",
            "{% set pw %}XpSetBlkB2canary{% endset %}\n{{ rotate_pwd(pw) }}\nselect 1 as a\n",
            "XpSetBlkB2canary",
        ),
        (
            "snowflake",
            "{%- set q | trim -%}\nselect 'XpSetBlkC3canary' as k\n{%- endset -%}\nselect 1 as a\n",
            "XpSetBlkC3canary",
        ),
        (
            "snowflake",
            "{% call statement('s') %}select 'XpSetBlkD4canary' as k{% endcall %}\nselect 1 as a\n",
            "XpSetBlkD4canary",
        ),
    ]);
    // Every literal of template code no template renders is masked, a
    // model's configuration too; template code the run does not read may
    // write any column, so the query's comparison is masked with it.
    let shown = redact_secrets_for_display(
        "{{ config(materialized='ShownCfgA1') }}\nselect 1 as a from t where b = 'x'\n",
        &lexega_core::dialect::snowflake(),
    );
    assert!(!shown.contains("ShownCfgA1"), "{shown}");
    assert!(!shown.contains("b = 'x'"), "{shown}");
}

#[test]
fn a_connection_name_an_undecided_dblink_call_takes_is_masked() {
    assert_masked(&[(
        "postgresql",
        "SELECT dblink_exec('ShownConnA1', v_sql) FROM app.jobs;",
        "ShownConnA1",
    )]);
}

/// Custom rules whose messages quote a statement's facts whole.
const QUOTING_RULES: &str = r#"
rules:
  - id: QUOTE-QUERY
    risk_level: critical
    message: "Q {query}"
    triggers:
      query.has_limit: false
  - id: QUOTE-DDL
    risk_level: critical
    message: "D {ddl}"
    triggers:
      kind: create_table
"#;

/// Every surface of the report of `sql` under the dialect `name`: the
/// report and the traced report as JSON and as SARIF, and the traced
/// report under rules whose messages quote the facts; lowercased.
fn every_surface(name: &str, sql: &str) -> String {
    use lexega_core::analyzer::{to_sarif, AnalysisConfig, ToolRun};
    use lexega_core::api::analyze_risk_with_policy_config;
    use lexega_core::rules::{build_v1_rule_corpus, load_v1_rules};

    let run = ToolRun {
        name: "lexega",
        version: "test",
        base_path: None,
        depth_note: None,
        unrendered_files: &[],
        skipped_files: &[],
        macro_files: &[],
        run_notes: &[],
    };
    let mut out = String::new();
    for trace in [false, true] {
        let report = traced_report(name, sql, trace);
        out.push_str(&serde_json::to_string(&report).expect("serializes"));
        out.push_str(&serde_json::to_string(&to_sarif(&report, &run)).expect("serializes"));
    }
    let custom = load_v1_rules(QUOTING_RULES).expect("custom rules parse");
    let cfg = AnalysisConfig {
        dialect: Some(lexega_core::dialect::dialect_from_name(name).expect("known dialect")),
        custom_rules: Some(
            build_v1_rule_corpus(custom, true)
                .expect("corpus builds")
                .into(),
        ),
        trace_mode: true,
        ..Default::default()
    };
    let report = analyze_risk_with_policy_config(sql, &cfg).expect("should analyze");
    out.push_str(&serde_json::to_string(&report).expect("serializes"));
    out.to_lowercase()
}

#[test]
fn a_literal_no_walk_shows_safe_reaches_no_report_surface() {
    let cases: &[(&str, &str, &str)] = &[
        // A choice nested in concatenated run text.
        ("postgresql", "DO $$ BEGIN EXECUTE 'ALTER ROLE a PASSWORD ''' || CASE WHEN true THEN 'XpH03canary' ELSE 'y' END || ''''; END $$;", "XpH03canary"),
        ("postgresql", "DO $$ BEGIN EXECUTE 'ALTER ROLE a PASSWORD ''' || coalesce(NULL, 'XpH04canary') || ''''; END $$;", "XpH04canary"),
        ("postgresql", "SELECT dblink_exec('c', 'ALTER ROLE a PASSWORD ''' || CASE WHEN true THEN 'XpH05canary' ELSE 'y' END || '''');", "XpH05canary"),
        ("redshift", "CREATE PROCEDURE sp() AS $$ BEGIN EXECUTE 'ALTER USER u PASSWORD ''' || CASE WHEN true THEN 'XpH07canary' ELSE 'y' END || ''''; END $$ LANGUAGE plpgsql;", "XpH07canary"),
        ("mssql", "EXEC (N'ALTER LOGIN a WITH PASSWORD = ''' + IIF(1 = 1, N'XpH08canary', N'y') + N'''');", "XpH08canary"),
        ("mysql", "SET @s = CONCAT('ALTER USER u IDENTIFIED BY ''', IF(1 = 1, 'XpH12canary', 'y'), '''');\nPREPARE st FROM @s;\nEXECUTE st;", "XpH12canary"),
        ("snowflake", "EXECUTE IMMEDIATE 'ALTER USER u SET PASSWORD = ''' || IFF(TRUE, 'XpW16canary', 'x') || '''';", "XpW16canary"),
        ("snowflake", "BEGIN\n  LET s STRING := 'ALTER USER u SET PASSWORD = ''' || IFF(TRUE, 'XpH16canary', 'y') || '''';\n  EXECUTE IMMEDIATE :s;\nEND;", "XpH16canary"),
        ("snowflake", "EXECUTE IMMEDIATE 'CALL util.p(''' || IFF(TRUE, 'XpH21canary', 'y') || ''')';", "XpH21canary"),
        // A value stored, read back and run.
        ("mssql", "DECLARE @t TABLE (s nvarchar(max));\nINSERT @t VALUES (N'ALTER LOGIN a WITH PASSWORD = ''XpW30canary''');\nDECLARE @s nvarchar(max);\nSELECT @s = s FROM @t;\nEXEC (@s);", "XpW30canary"),
        ("postgresql", "INSERT INTO jobs (q) VALUES ('ALTER ROLE a PASSWORD ''XpW32canary''');\nDO $$ DECLARE s text; BEGIN SELECT q INTO s FROM jobs; EXECUTE s; END $$;", "XpW32canary"),
        ("redshift", "UNLOAD ('select ''XpRsg05canary''') TO 's3://b/' IAM_ROLE 'arn:aws:iam::1:role/r';", "XpRsg05canary"),
        // A value stored into a credential column by a path not read to it.
        ("mssql", "UPDATE u SET password = s.pw FROM users u JOIN (SELECT 'XpmsC23canary' AS pw) s ON 1 = 1;", "XpmsC23canary"),
        ("mysql", "UPDATE users u JOIN (SELECT 'XpmyC23canary' AS pw) s SET u.password = s.pw;", "XpmyC23canary"),
        ("snowflake", "INSERT INTO users VALUES (1, 'bob', 'XpsnC04canary');", "XpsnC04canary"),
        ("postgresql", "INSERT INTO users VALUES (1, 'bob', 'XppoC04canary');", "XppoC04canary"),
        ("mssql", "INSERT INTO users VALUES (1, 'bob', 'XpmsC04canary');", "XpmsC04canary"),
        ("mysql", "INSERT INTO users VALUES (1, 'bob', 'XpmyC04canary');", "XpmyC04canary"),
        ("snowflake", "CREATE VIEW v_users AS SELECT id, password AS p FROM users;\nUPDATE v_users SET p = 'XpsnC05canary' WHERE id = 1;", "XpsnC05canary"),
        ("mssql", "DECLARE @p nvarchar(50) = N'XpM14canary';\nUPDATE dbo.users SET password = @p WHERE id = 1;", "XpM14canary"),
        ("postgresql", "DO $$ DECLARE v text := 'XpM15canary'; BEGIN UPDATE users SET password = v WHERE id = 1; END $$;", "XpM15canary"),
        ("snowflake", "BEGIN\n  LET v STRING := 'XpM16canary';\n  UPDATE users SET password = :v WHERE id = 1;\nEND;", "XpM16canary"),
        ("mysql", "SET @v = 'XpM17canary';\nUPDATE users SET password = @v WHERE id = 1;", "XpM17canary"),
        ("snowflake", "SET v = 'XpM18canary';\nUPDATE users SET password = $v WHERE id = 1;", "XpM18canary"),
        ("snowflake", "SET pw = 'XpSfg18canary';\nCREATE USER u2 PASSWORD = $pw;", "XpSfg18canary"),
        // A command or a credential in a grammar slot.
        ("postgresql", "COPY t FROM PROGRAM 'curl -u user:XpPgg09canary https://x';", "XpPgg09canary"),
        ("postgresql", "COPY t TO PROGRAM 'gzip > /tmp/XpPgg10canary';", "XpPgg10canary"),
        ("snowflake", "CREATE STAGE st2 URL = 'azure://acct.blob.core.windows.net/c?sv=2020&sig=XpG25canary';", "XpG25canary"),
        // A masked literal the facts hold case-folded.
        ("snowflake", "SELECT * FROM TABLE(IDENTIFIER('db.sch.set_pwd')('XpSfM13canary'));", "XpSfM13canary"),
        ("snowflake", "SELECT DECRYPT(c, 'XpKey01canary') FROM t;", "XpKey01canary"),
        ("postgresql", "SELECT pgp_sym_encrypt('data', 'XpKey13canary');", "XpKey13canary"),
        // A routine body no reader parses.
        ("snowflake", "CREATE PROCEDURE p() RETURNS STRING LANGUAGE JAVASCRIPT AS $$var pw='XpW19canary'$$;", "XpW19canary"),
        ("snowflake", "CREATE PROCEDURE p() RETURNS STRING LANGUAGE JAVASCRIPT AS $$var pw=\"XpW19bcanary\"$$;", "XpW19bcanary"),
        ("postgresql", "CREATE FUNCTION f() RETURNS void LANGUAGE plpython3u AS $$ c(password='XpW20canary') $$;", "XpW20canary"),
        // Template code no reader renders.
        ("snowflake", "select 1 as a\n{{ log('token XpDtA16canary', info=True) }}", "XpDtA16canary"),
        ("snowflake", "select '{{ var(\"pw\", \"XpDtA03canary\") }}' as a", "XpDtA03canary"),
    ];
    let printed: Vec<String> = cases
        .iter()
        .filter(|(name, sql, canary)| every_surface(name, sql).contains(&canary.to_lowercase()))
        .map(|(name, sql, _)| format!("{name}: {sql}"))
        .collect();
    assert!(
        printed.is_empty(),
        "printed ({}):\n{}",
        printed.len(),
        printed.join("\n")
    );
}

#[test]
fn a_literal_shown_safe_is_printed_by_its_own_place() {
    // The same text masked in one statement and shown, as a comparison's
    // operand, in another.
    let sql = "EXECUTE IMMEDIATE 'SELECT 1 FROM t WHERE s = ?' USING ('status');\n\
               SELECT id FROM orders WHERE status = 'active' AND region = 'status';";
    let report = traced_report("snowflake", sql, true);
    let previews: Vec<&str> = report
        .statement_traces
        .iter()
        .map(|t| t.statement_preview.as_str())
        .collect();
    assert!(
        previews.iter().any(|p| p.contains("region = 'status'")),
        "{previews:?}"
    );
    let json = serde_json::to_string(&report).expect("serializes");
    assert!(json.contains("\"value\":\"'status'\""), "{json}");
}

/// Each text of `cases` (dialect, SQL, text) is in the SQL as a report
/// quotes it whole.
fn assert_quoted(cases: &[(&str, &str, &str)]) {
    for (dialect, sql, shown) in cases {
        let quoted = redact_secrets_for_display(
            sql,
            &lexega_core::dialect::dialect_from_name(dialect).expect("known dialect"),
        );
        assert!(quoted.contains(shown), "{dialect}: {sql}\n{quoted}");
    }
}

/// The cases of `cases` (dialect, SQL, canary) whose canary any report
/// surface prints.
fn printed_on_some_surface(cases: &[(&str, &str, &str)]) -> Vec<String> {
    cases
        .iter()
        .filter(|(name, sql, canary)| every_surface(name, sql).contains(&canary.to_lowercase()))
        .map(|(name, sql, _)| format!("{name}: {sql}"))
        .collect()
}

#[test]
fn a_routine_body_in_another_language_is_masked_whole() {
    let cases: &[(&str, &str, &str)] = &[
        // A body that parses as a statement.
        ("postgresql", "CREATE FUNCTION f6() RETURNS text LANGUAGE plpython3u AS $$ return \"XpPyR6canary\" $$;", "XpPyR6canary"),
        ("postgresql", "CREATE FUNCTION f7() RETURNS text LANGUAGE plv8 AS $$ return \"XpJsR7canary\"; $$;", "XpJsR7canary"),
        ("snowflake", "CREATE FUNCTION f3() RETURNS STRING LANGUAGE JAVASCRIPT AS $$ return \"XpJsR3canary\"; $$;", "XpJsR3canary"),
        ("postgresql", "DO LANGUAGE plv8 $$ return \"XpDoV8canary\"; $$;", "XpDoV8canary"),
        // A body after one read as SQL.
        ("postgresql", "CREATE FUNCTION a() RETURNS int LANGUAGE plpgsql AS $$ BEGIN DELETE FROM t; RETURN 1; END $$;\nCREATE FUNCTION b() RETURNS text LANGUAGE plpython3u AS $$ t=\"XpB81canary\" $$;", "XpB81canary"),
        ("redshift", "CREATE PROCEDURE a() AS $$ BEGIN DELETE FROM t; END $$ LANGUAGE plpgsql;\nCREATE FUNCTION b(x int) RETURNS varchar STABLE AS $$ return \"XpB81rcanary\" $$ LANGUAGE plpythonu;", "XpB81rcanary"),
        ("snowflake", "CREATE PROCEDURE a() RETURNS INT LANGUAGE SQL AS $$ BEGIN DELETE FROM t; RETURN 1; END $$;\nCREATE PROCEDURE b() RETURNS STRING LANGUAGE JAVASCRIPT AS $$ var t=\"XpB80canary\"; var type = 'XpB80bcanary'; $$;", "XpB80"),
        ("snowflake", "CREATE PROCEDURE a() RETURNS INT LANGUAGE SQL AS $$ BEGIN DELETE FROM t; END $$;\nCREATE PROCEDURE b() RETURNS INT LANGUAGE JAVASCRIPT AS $$ type = 'XpSl1canary' $$;", "XpSl1canary"),
    ];
    let printed = printed_on_some_surface(cases);
    assert!(
        printed.is_empty(),
        "printed ({}):\n{}",
        printed.len(),
        printed.join("\n")
    );
}

#[test]
fn each_routine_of_a_file_is_quoted_from_its_own_header() {
    let cases: &[(&str, &str, &str)] = &[
        (
            "postgresql",
            "CREATE PROCEDURE add_export() LANGUAGE plpgsql AS $$ BEGIN INSERT INTO e VALUES (1); END $$;\n\
             CREATE FUNCTION trg_r() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN INSERT INTO r VALUES (1); RETURN NEW; END $$;",
            "CREATE FUNCTION trg_r() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN INSERT INTO",
        ),
        (
            "postgresql",
            "DO $$ BEGIN DELETE FROM t; END $$;\nCREATE FUNCTION g() RETURNS int LANGUAGE plpgsql AS $$ BEGIN RETURN 1; END $$;",
            "CREATE FUNCTION g() RETURNS int LANGUAGE plpgsql AS $$ BEGIN RETURN 1; END $$",
        ),
        (
            "snowflake",
            "CREATE PROCEDURE a() RETURNS INT LANGUAGE SQL AS $$ BEGIN DELETE FROM t; RETURN 1; END $$;\n\
             CREATE PROCEDURE b() RETURNS STRING LANGUAGE JAVASCRIPT AS $$ return 1; $$;",
            "CREATE PROCEDURE b() RETURNS STRING LANGUAGE JAVASCRIPT AS $$",
        ),
    ];
    for (name, sql, header) in cases {
        let report = traced_report(name, sql, true);
        let previews: Vec<&str> = report
            .statement_traces
            .iter()
            .map(|t| t.statement_preview.as_str())
            .collect();
        assert!(
            previews.iter().any(|p| p.starts_with(header)),
            "{name}: {sql}\n{previews:?}"
        );
    }
}

#[test]
fn a_key_function_is_read_whatever_the_case_its_name_is_written_in() {
    assert_masked(&[
        (
            "postgresql",
            "UPDATE customers SET ssn_enc = PGP_SYM_ENCRYPT(ssn, 'XpU20canary');",
            "XpU20canary",
        ),
        (
            "postgresql",
            "UPDATE t SET c = Crypt('XpU33canary', gen_salt('bf'));",
            "XpU33canary",
        ),
        (
            "postgresql",
            "SELECT a FROM t WHERE c = ENCRYPT('d', 'XpU01canary', 'aes');",
            "XpU01canary",
        ),
        (
            "postgresql",
            "INSERT INTO t (c) VALUES (PGP_SYM_ENCRYPT('d', 'XpU02canary'));",
            "XpU02canary",
        ),
        (
            "postgresql",
            "INSERT INTO t (c) VALUES (Hmac('d', 'XpU03canary', 'sha256'));",
            "XpU03canary",
        ),
        // Snowflake's `ENCRYPT` read as PostgreSQL.
        (
            "postgresql",
            "SELECT a FROM t WHERE c = ENCRYPT('data', 'XpB40canary');",
            "XpB40canary",
        ),
    ]);
}

#[test]
fn a_credential_under_a_short_or_compound_name_is_masked() {
    let cases: &[(&str, &str, &str)] = &[
        ("snowflake", "UPDATE users SET pw = 'XpB60canary';", "XpB60canary"),
        ("postgresql", "INSERT INTO users (id, pass) VALUES (1, 'XpB61canary');", "XpB61canary"),
        ("mysql", "INSERT INTO users (id, credentials) VALUES (1, 'XpB62canary');", "XpB62canary"),
        ("mssql", "UPDATE dbo.users SET pin = N'XpB63canary';", "XpB63canary"),
        ("postgresql", "INSERT INTO integrations (name, auth_header) VALUES ('x', 'Bearer XpB67canary');", "XpB67canary"),
        ("mysql", "INSERT INTO users (id, otp_seed) VALUES (1, 'XpB68canary');", "XpB68canary"),
        ("snowflake", "CREATE TABLE t AS SELECT 'XpB69canary' AS pw;", "XpB69canary"),
        ("snowflake", "MERGE INTO users u USING (SELECT 1 AS id) s ON u.id = s.id WHEN MATCHED THEN UPDATE SET pw = 'XpB70canary';", "XpB70canary"),
        ("mysql", "UPDATE mysql.user SET authentication_string = 'XpB95canary' WHERE User = 'root';", "XpB95canary"),
        ("mysql", "INSERT INTO users SET id = 1, pw = 'XpB116canary';", "XpB116canary"),
        ("postgresql", "SELECT a FROM users WHERE pw = 'XpB09canary';", "XpB09canary"),
        ("mysql", "SELECT a FROM users WHERE pass = 'XpB10canary';", "XpB10canary"),
        ("mssql", "SELECT a FROM dbo.users WHERE pin = 'XpB11canary';", "XpB11canary"),
        ("snowflake", "SELECT a FROM users WHERE credentials = 'XpB12canary';", "XpB12canary"),
        ("mssql", "SELECT pw = 'XpB104canary' FROM dbo.t;", "XpB104canary"),
        ("postgresql", "SELECT a FROM users WHERE pw_hash = md5('XpB37canary');", "XpB37canary"),
        ("mysql", "SELECT a FROM users WHERE pw_hash = SHA2('XpB39canary', 256);", "XpB39canary"),
        ("postgresql", "UPDATE users SET salt = 'XpSaltA1canary', pepper = 'XpPepperA1canary';", "XpSaltA1canary"),
        ("snowflake", "UPDATE users SET mfa_secret = 'XpMfaA1canary', totpSeed = 'XpTotpA1canary';", "XpTotpA1canary"),
    ];
    let printed = printed_on_some_surface(cases);
    assert!(
        printed.is_empty(),
        "printed ({}):\n{}",
        printed.len(),
        printed.join("\n")
    );
    // A word that only holds one of those names is no credential's: a
    // value compared with it is shown.
    assert_shown(&[
        (
            "postgresql",
            "DELETE FROM books WHERE author = 'ShownAuthorA1';",
            "ShownAuthorA1",
        ),
        (
            "postgresql",
            "DELETE FROM trips WHERE passenger = 'ShownPassengerA1';",
            "ShownPassengerA1",
        ),
        (
            "postgresql",
            "DELETE FROM posts WHERE pinned = 'ShownPinnedA1';",
            "ShownPinnedA1",
        ),
        (
            "postgresql",
            "DELETE FROM users WHERE status = 'ShownStatusA1';",
            "ShownStatusA1",
        ),
    ]);
}

#[test]
fn the_value_a_row_writes_under_a_credentials_name_is_masked() {
    let cases: &[(&str, &str, &str)] = &[
        ("postgresql", "INSERT INTO settings (k, v) VALUES ('smtp_password', 'XpB65canary');", "XpB65canary"),
        ("snowflake", "UPDATE app_config SET value = 'XpB66canary' WHERE name = 'api_key';", "XpB66canary"),
        ("mysql", "INSERT INTO settings (name, value) VALUES ('smtp_host', 'h'), ('smtp_password', 'XpKvA1canary');", "XpKvA1canary"),
        ("postgresql", "INSERT INTO settings (name, value) SELECT 'db.password', 'XpKvB2canary';", "XpKvB2canary"),
        ("mssql", "UPDATE dbo.config SET setting_value = N'XpKvC3canary' WHERE setting_name = N'ApiToken';", "XpKvC3canary"),
    ];
    let printed = printed_on_some_surface(cases);
    assert!(
        printed.is_empty(),
        "printed ({}):\n{}",
        printed.len(),
        printed.join("\n")
    );
    // A row under any other key writes a value no catalog types: masked
    // as well.
    assert_masked(&[
        (
            "postgresql",
            "INSERT INTO settings (k, v) VALUES ('smtp_host', 'MaskedKvA1');",
            "MaskedKvA1",
        ),
        (
            "snowflake",
            "UPDATE app_config SET value = 'MaskedKvB2' WHERE name = 'retention_days';",
            "MaskedKvB2",
        ),
    ]);
}

#[test]
fn a_value_compared_with_or_made_with_a_secret_by_its_source_is_masked() {
    let cases: &[(&str, &str, &str)] = &[
        // A setting read by a secret's name.
        ("postgresql", "DO $$ BEGIN IF current_setting('app.password') = 'XpB113canary' THEN RAISE NOTICE 'x'; END IF; END $$;", "XpB113canary"),
        ("postgresql", "SELECT a FROM t WHERE current_setting('app.api_key') = 'XpCsA1canary';", "XpCsA1canary"),
        ("mssql", "SELECT a FROM dbo.t WHERE SESSION_CONTEXT(N'api_token') = N'XpScA1canary';", "XpScA1canary"),
        ("snowflake", "SELECT a FROM t WHERE GETVARIABLE('DB_PASSWORD') = 'XpGvA1canary';", "XpGvA1canary"),
        // A value equated with a secret column through a join.
        ("postgresql", "SELECT a FROM users u JOIN t ON u.password = t.x WHERE t.x = 'XpB08canary';", "XpB08canary"),
        // A value made with a secret.
        ("postgresql", "SELECT a FROM users WHERE h = md5(password || 'XpB36canary');", "XpB36canary"),
        ("mssql", "SELECT a FROM dbo.users WHERE h = HASHBYTES('SHA2_256', password + N'XpPeA1canary');", "XpPeA1canary"),
    ];
    let printed = printed_on_some_surface(cases);
    assert!(
        printed.is_empty(),
        "printed ({}):\n{}",
        printed.len(),
        printed.join("\n")
    );
    assert_shown(&[
        (
            "postgresql",
            "SELECT a FROM t WHERE current_setting('app.tenant') = 'ShownCsA1';",
            "ShownCsA1",
        ),
        (
            "postgresql",
            "SELECT a FROM users u JOIN t ON u.id = t.x WHERE t.x = 'ShownJoinA1';",
            "ShownJoinA1",
        ),
    ]);
}

#[test]
fn a_value_written_is_masked_whether_or_not_text_a_script_runs_reads_its_table() {
    assert_masked(&[
        (
            "mysql",
            "UPDATE customers SET status = 'XpRunA1canary';\nSET @s = CONCAT('SELECT 1 FROM ', 't');\nPREPARE st FROM @s;\nEXECUTE st;",
            "XpRunA1canary",
        ),
        (
            "postgresql",
            "UPDATE customers SET status = 'XpRunB2canary';\nDO $$ DECLARE s text := 'SELECT 1'; BEGIN EXECUTE s; END $$;",
            "XpRunB2canary",
        ),
        (
            "snowflake",
            "UPDATE customers SET status = 'XpRunC3canary';\nEXECUTE IMMEDIATE :q;",
            "XpRunC3canary",
        ),
        (
            "postgresql",
            "INSERT INTO jobs (q) VALUES ('ALTER ROLE a PASSWORD ''XpRunE5canary''');\nDO $$ DECLARE s text; BEGIN SELECT q INTO s FROM jobs; EXECUTE s; END $$;",
            "XpRunE5canary",
        ),
        (
            "mssql",
            "INSERT INTO dbo.jobs (q) VALUES (N'ALTER LOGIN a WITH PASSWORD = ''XpRunF6canary''');\nDECLARE @s nvarchar(max);\nSELECT @s = q FROM dbo.jobs;\nEXEC (@s);",
            "XpRunF6canary",
        ),
    ]);
    // A value that is no text is shown wherever it is written.
    assert_shown(&[(
        "postgresql",
        "UPDATE jobs SET due = DATE '2024-05-01';\nDO $$ DECLARE s text; BEGIN SELECT q INTO s FROM jobs; EXECUTE s; END $$;",
        "DATE '2024-05-01'",
    )]);
}

#[test]
fn governance_evidence_a_dialect_documents_as_no_secret_is_shown() {
    assert_quoted(&[
        ("snowflake", "CREATE NETWORK POLICY open_np ALLOWED_IP_LIST = ('0.0.0.0/0', '10.0.0.0/8');", "'10.0.0.0/8'"),
        ("snowflake", "ALTER ACCOUNT SET NETWORK_POLICY = 'open_np';", "'open_np'"),
        ("snowflake", "CREATE NETWORK RULE r MODE = EGRESS TYPE = HOST_PORT VALUE_LIST = ('evil.example.com:443');", "'evil.example.com:443'"),
        ("snowflake", "CREATE USER svc PASSWORD = 'XpGovPwcanary' DEFAULT_ROLE = 'ACCOUNTADMIN' DEFAULT_WAREHOUSE = 'WH1';", "DEFAULT_WAREHOUSE = 'WH1'"),
        ("snowflake", "COPY INTO 's3://other-bucket/dump/' FROM prod.core.customers;", "'s3://other-bucket/dump/'"),
        ("snowflake", "CREATE STAGE st2 URL = 'azure://acct.blob.core.windows.net/c?sv=2020&sig=XpGovSigcanary';", "'azure://acct.blob.core.windows.net/c?"),
        ("bigquery", "GRANT `roles/bigquery.dataViewer` ON TABLE ds.t TO 'allUsers';", "'allUsers'"),
        ("bigquery", "EXPORT DATA OPTIONS (uri = 'gs://other-bucket/dump-*.csv', format = 'CSV') AS SELECT * FROM ds.customers;", "'gs://other-bucket/dump-*.csv'"),
        ("databricks", "ALTER TABLE t SET TBLPROPERTIES ('delta.appendOnly' = 'false', 'secret.key' = 'XpGovTblcanary');", "'delta.appendOnly' = 'false'"),
        ("mssql", "EXEC sp_addsrvrolemember 'svc_login', 'sysadmin';", "'svc_login', 'sysadmin'"),
        ("mssql", "EXEC sp_addrolemember 'db_owner', 'svc_user';", "'db_owner', 'svc_user'"),
        ("mssql", "EXEC sp_configure 'xp_cmdshell', 1;", "'xp_cmdshell'"),
        ("mssql", "EXEC sp_rename 'dbo.orders.status', 'state', 'COLUMN';", "'dbo.orders.status', 'state', 'COLUMN'"),
        ("postgresql", "COPY (SELECT * FROM pii.customers) TO '/tmp/customers.csv';", "'/tmp/customers.csv'"),
        ("postgresql", "SELECT lo_export(lo_create(0), '/var/lib/postgresql/.ssh/authorized_keys');", "'/var/lib/postgresql/.ssh/authorized_keys'"),
        ("postgresql", "CREATE POLICY p ON app.t USING (tenant = 'ShownPolA1');", "'ShownPolA1'"),
        ("mysql", "SELECT * FROM pii.customers INTO OUTFILE '/var/lib/mysql-files/dump.csv';", "'/var/lib/mysql-files/dump.csv'"),
        ("mysql", "CREATE FUNCTION sys_exec RETURNS INTEGER SONAME 'lib_mysqludf_sys.so';", "'lib_mysqludf_sys.so'"),
        ("mysql", "DROP USER IF EXISTS 'analyst'@'localhost';", "'analyst'"),
        ("redshift", "UNLOAD ('SELECT * FROM customers') TO 's3://other-bucket/dump/' IAM_ROLE 'arn:aws:iam::1:role/r';", "'s3://other-bucket/dump/'"),
        ("snowflake", "CREATE ROW ACCESS POLICY rap AS (region STRING) RETURNS BOOLEAN -> region = 'ShownRapA1';", "'ShownRapA1'"),
    ]);
    // What such a place may carry of a secret stays masked: a URL's user
    // information and query, a secret property, a password beside them,
    // a command, and a literal only part of a slot's value.
    let cases: &[(&str, &str, &str)] = &[
        ("snowflake", "CREATE USER svc PASSWORD = 'XpGovPwcanary' DEFAULT_ROLE = 'ACCOUNTADMIN';", "XpGovPwcanary"),
        ("snowflake", "CREATE STAGE st2 URL = 'azure://acct.blob.core.windows.net/c?sv=2020&sig=XpGovSigcanary';", "XpGovSigcanary"),
        ("snowflake", "COPY INTO 's3://user:XpGovUicanary@bucket/x/' FROM t;", "XpGovUicanary"),
        ("databricks", "ALTER TABLE t SET TBLPROPERTIES ('delta.appendOnly' = 'false', 'secret.key' = 'XpGovTblcanary');", "XpGovTblcanary"),
        ("postgresql", "COPY t FROM PROGRAM 'curl -u u:XpGovProgcanary h';", "XpGovProgcanary"),
        ("snowflake", "SELECT * FROM IDENTIFIER('db.sch.XpJa01' || 'Jb01canary');", "XpJa01"),
    ];
    let printed = printed_on_some_surface(cases);
    assert!(
        printed.is_empty(),
        "printed ({}):\n{}",
        printed.len(),
        printed.join("\n")
    );
}

#[test]
fn sql_text_a_script_runs_is_quoted_with_its_own_literals_masked() {
    assert_shown(&[
        (
            "snowflake",
            "EXECUTE IMMEDIATE 'DROP TABLE IF EXISTS t1';",
            "EXECUTE IMMEDIATE 'DROP TABLE IF EXISTS t1'",
        ),
        (
            "mssql",
            "EXEC (N'DROP TABLE dbo.x');",
            "EXEC (N'DROP TABLE dbo.x')",
        ),
        (
            "snowflake",
            "EXECUTE IMMEDIATE 'DELETE FROM t WHERE region = ''EU''';",
            "EXECUTE IMMEDIATE 'DELETE FROM t WHERE region = ",
        ),
    ]);
    let cases: &[(&str, &str, &str)] = &[
        ("snowflake", "EXECUTE IMMEDIATE 'ALTER USER u SET PASSWORD = ''XpRunTxA1canary''';", "XpRunTxA1canary"),
        ("mssql", "EXEC sp_executesql N'ALTER LOGIN a WITH PASSWORD = ''XpRunTxB2canary''';", "XpRunTxB2canary"),
        ("postgresql", "DO $$ BEGIN EXECUTE 'ALTER ROLE a PASSWORD ''' || 'XpRunTxC3canary' || ''''; END $$;", "XpRunTxC3canary"),
        ("mysql", "SET @s = CONCAT('ALTER USER u IDENTIFIED BY ''', 'XpRunTxD4canary', '''');\nPREPARE st FROM @s;\nEXECUTE st;", "XpRunTxD4canary"),
    ];
    let printed = printed_on_some_surface(cases);
    assert!(
        printed.is_empty(),
        "printed ({}):\n{}",
        printed.len(),
        printed.join("\n")
    );
}

/// `TEST_DB.PUBLIC.EVENTS`, whose columns the catalog types: `ID INT`,
/// `AT TIMESTAMP_NTZ`, `NOTE VARCHAR`, `PIN NUMBER`, `FLAG BOOLEAN`,
/// `LABEL VARCHAR` and `SCORE NUMBER`, the last classified by a tag.
fn typed_catalog() -> lexega_core::CatalogIndex {
    use lexega_core::catalog::{
        CatalogColumn, CatalogDatabase, CatalogIdent, CatalogSchema, CatalogSnapshot, CatalogTable,
        CatalogTableKind, CatalogTag, CATALOG_SCHEMA_VERSION,
    };
    let ident = |name: &str| CatalogIdent {
        name: name.to_string(),
    };
    let column = |name: &str, ty: &str, tagged: bool| CatalogColumn {
        name: ident(name),
        data_type: Some(ty.to_string()),
        nullable: Some(true),
        tags: if tagged {
            vec![CatalogTag {
                tag_database: None,
                tag_schema: None,
                tag_name: "PII".to_string(),
                tag_value: Some("SCORE".to_string()),
            }]
        } else {
            Vec::new()
        },
    };
    let snapshot = CatalogSnapshot {
        schema_version: CATALOG_SCHEMA_VERSION,
        listing: lexega_core::catalog::CatalogListing::Inventory,
        generated_at: None,
        source: Some("unit-test".to_string()),
        policies: vec![],
        policy_references: vec![],
        grants: None,
        provider: None,
        databases: vec![CatalogDatabase {
            name: ident("TEST_DB"),
            schemas: vec![CatalogSchema {
                name: ident("PUBLIC"),
                tables: vec![CatalogTable {
                    name: ident("EVENTS"),
                    kind: CatalogTableKind::Table,
                    columns: vec![
                        column("ID", "INT", false),
                        column("AT", "TIMESTAMP_NTZ(9)", false),
                        column("NOTE", "VARCHAR(100)", false),
                        column("PIN", "NUMBER(38,0)", false),
                        column("FLAG", "BOOLEAN", false),
                        column("LABEL", "VARCHAR", false),
                        column("SCORE", "NUMBER(38,0)", true),
                    ],
                    row_count_estimate: None,
                    row_count_estimate_as_of: None,
                    bytes_estimate: None,
                    bytes_estimate_as_of: None,
                    constraints: vec![],
                    comment: None,
                    tags: vec![],
                }],
            }],
        }],
    };
    lexega_core::CatalogIndex::from_snapshot(snapshot).expect("valid snapshot")
}

/// The report of `sql` under Snowflake against [`typed_catalog`], plain
/// and traced, as JSON.
fn reported_with_catalog(sql: &str) -> String {
    use lexega_core::analyzer::AnalysisConfig;
    use lexega_core::api::analyze_risk_with_policy_config_and_catalog_index;
    let catalog = typed_catalog();
    let mut out = String::new();
    for trace in [false, true] {
        let cfg = AnalysisConfig {
            dialect: Some(lexega_core::dialect::snowflake()),
            trace_mode: trace,
            ..Default::default()
        };
        let report = analyze_risk_with_policy_config_and_catalog_index(sql, &cfg, &catalog)
            .expect("should analyze");
        out.push_str(&serde_json::to_string(&report).expect("serializes"));
    }
    out
}

#[test]
fn a_string_written_where_no_catalog_types_the_column_is_masked() {
    let cases: &[(&str, &str, &str)] = &[
        ("postgresql", "INSERT INTO kv (key, value) VALUES ('smtp_password', 'XpK1canary');", "XpK1canary"),
        ("postgresql", "UPDATE kv SET value = 'XpK3canary' WHERE key = 'smtp_password';", "XpK3canary"),
        ("postgresql", "INSERT INTO config (config_key, config_value) VALUES ('db.password', 'XpK4canary');", "XpK4canary"),
        ("postgresql", "INSERT INTO kv (key, value) VALUES ('AWS_SECRET_ACCESS_KEY', 'XpS33canary');", "XpS33canary"),
        ("mssql", "INSERT INTO dbo.AppSettings ([Key], [Value]) VALUES (N'Smtp:Password', N'XpS12canary');", "XpS12canary"),
        ("postgresql", "INSERT INTO cfg (k, v) VALUES ('SMTP Password', 'XpS03canary');", "XpS03canary"),
        ("postgresql", "INSERT INTO params (path, val) VALUES ('/prod/db/password', 'XpS04canary');", "XpS04canary"),
        ("postgresql", "UPDATE settings SET value = 'XpS05canary' WHERE name IN ('api_key');", "XpS05canary"),
        ("postgresql", "UPDATE settings SET value = 'XpS06canary' WHERE name LIKE 'api_key';", "XpS06canary"),
        ("postgresql", "INSERT INTO integrations (config) VALUES ('{\"api_key\": \"XpS14canary\"}');", "XpS14canary"),
        ("snowflake", "UPDATE users SET userPw = 'XpC00canary';", "XpC00canary"),
        ("snowflake", "UPDATE customers SET status = 'XpWr1canary';", "XpWr1canary"),
        ("mysql", "INSERT INTO t (id, note) VALUES (1, 'XpWr2canary');", "XpWr2canary"),
        ("snowflake", "MERGE INTO t USING s ON t.id = s.id WHEN MATCHED THEN UPDATE SET note = 'XpWr3canary' WHEN NOT MATCHED THEN INSERT (id, note) VALUES (s.id, 'XpWr4canary');", "XpWr"),
        ("snowflake", "CREATE TABLE t2 AS SELECT 'XpWr5canary' AS note;", "XpWr5canary"),
        ("postgresql", "INSERT INTO t (id, note) SELECT 1, 'XpWr6canary';", "XpWr6canary"),
        ("postgresql", "INSERT INTO t (id, note) VALUES (1, 'XpWr7canary') ON CONFLICT (id) DO UPDATE SET note = 'XpWr8canary';", "XpWr"),
    ];
    let printed = printed_on_some_surface(cases);
    assert!(
        printed.is_empty(),
        "printed ({}):\n{}",
        printed.len(),
        printed.join("\n")
    );
    // A value that is not a string holds no secret, whatever its column.
    assert_shown(&[
        (
            "postgresql",
            "INSERT INTO t (id, at) VALUES (1, DATE '2024-03-01');",
            "DATE '2024-03-01'",
        ),
        (
            "postgresql",
            "UPDATE t SET at = '2024-03-02'::date;",
            "'2024-03-02'::date",
        ),
        (
            "snowflake",
            "UPDATE t SET n = CAST('42' AS INT);",
            "CAST('42' AS INT)",
        ),
    ]);
}

#[test]
fn a_string_written_where_a_catalog_types_the_column_as_holding_no_text_is_shown() {
    let report = reported_with_catalog(
        "INSERT INTO test_db.public.events (at, flag) VALUES ('2024-03-01', 'true');",
    );
    assert!(report.contains("VALUES ('2024-03-01', 'true')"), "{report}");
    let report = reported_with_catalog("UPDATE test_db.public.events SET at = '2024-03-02';");
    assert!(report.contains("SET at = '2024-03-02'"), "{report}");
    // A column whose type holds text is masked; so is one a credential's
    // name, a classification or a string not written whole reaches.
    for (sql, canary) in [
        (
            "INSERT INTO test_db.public.events (note) VALUES ('XpCt1canary');",
            "XpCt1canary",
        ),
        (
            "UPDATE test_db.public.events SET pin = '4242XpCt2canary';",
            "XpCt2canary",
        ),
        (
            "UPDATE test_db.public.events SET score = 'XpCt3canary';",
            "XpCt3canary",
        ),
        (
            "UPDATE test_db.public.events SET label = 'XpCt4canary';",
            "XpCt4canary",
        ),
        (
            "UPDATE test_db.public.events SET id = length('XpCt5canary');",
            "XpCt5canary",
        ),
    ] {
        let report = reported_with_catalog(sql);
        assert!(!report.contains(canary), "{sql}\n{report}");
    }
}

#[test]
fn a_credential_name_in_any_case_style_vetoes_a_compared_value() {
    let cases: &[(&str, &str, &str)] = &[
        (
            "snowflake",
            "SELECT a FROM users WHERE userPw = 'XpCv01canary';",
            "XpCv01canary",
        ),
        (
            "snowflake",
            "SELECT a FROM users WHERE dbPass = 'XpCv02canary';",
            "XpCv02canary",
        ),
        (
            "snowflake",
            "SELECT a FROM users WHERE smtpPass = 'XpCv03canary';",
            "XpCv03canary",
        ),
        (
            "snowflake",
            "SELECT a FROM users WHERE cardPin = 'XpCv04canary';",
            "XpCv04canary",
        ),
        (
            "snowflake",
            "SELECT a FROM users WHERE privKey = 'XpCv05canary';",
            "XpCv05canary",
        ),
        (
            "snowflake",
            "SELECT a FROM users WHERE sshKey = 'XpCv06canary';",
            "XpCv06canary",
        ),
        (
            "snowflake",
            "SELECT a FROM users WHERE encKey = 'XpCv07canary';",
            "XpCv07canary",
        ),
        (
            "snowflake",
            "SELECT a FROM users WHERE PGPASS = 'XpCv08canary';",
            "XpCv08canary",
        ),
        (
            "snowflake",
            "SELECT a FROM users WHERE jwt = 'XpCv09canary';",
            "XpCv09canary",
        ),
        (
            "snowflake",
            "SELECT a FROM users WHERE dsn = 'XpCv10canary';",
            "XpCv10canary",
        ),
        (
            "snowflake",
            "SELECT a FROM users WHERE conn_string = 'XpCv11canary';",
            "XpCv11canary",
        ),
        (
            "snowflake",
            "SELECT a FROM users WHERE connStr = 'XpCv12canary';",
            "XpCv12canary",
        ),
        (
            "snowflake",
            "SELECT a FROM users WHERE db_url = 'XpCv13canary';",
            "XpCv13canary",
        ),
        (
            "snowflake",
            "SELECT a FROM users WHERE session_cookie = 'XpCv14canary';",
            "XpCv14canary",
        ),
        (
            "snowflake",
            "SELECT a FROM users WHERE recovery_code = 'XpCv15canary';",
            "XpCv15canary",
        ),
        (
            "snowflake",
            "SELECT a FROM users WHERE backupCodes = 'XpCv16canary';",
            "XpCv16canary",
        ),
        (
            "snowflake",
            "SELECT a FROM users WHERE refresh_tok = 'XpCv17canary';",
            "XpCv17canary",
        ),
        (
            "snowflake",
            "SELECT a FROM users WHERE bearer = 'XpCv18canary';",
            "XpCv18canary",
        ),
        (
            "snowflake",
            "SELECT a FROM users WHERE SecurityAnswer = 'XpCv20canary';",
            "XpCv20canary",
        ),
        (
            "snowflake",
            "SELECT a FROM users WHERE api2Key = 'XpCv21canary';",
            "XpCv21canary",
        ),
        (
            "mysql",
            "SELECT a FROM users WHERE `user-pw` = 'XpCv22canary';",
            "XpCv22canary",
        ),
    ];
    let printed = printed_on_some_surface(cases);
    assert!(
        printed.is_empty(),
        "printed ({}):\n{}",
        printed.len(),
        printed.join("\n")
    );
    // A word that only holds one of those names is no credential's.
    assert_shown(&[
        (
            "postgresql",
            "SELECT a FROM books WHERE author = 'ShownAuthorB1';",
            "ShownAuthorB1",
        ),
        (
            "postgresql",
            "SELECT a FROM trips WHERE passenger = 'ShownPassengerB1';",
            "ShownPassengerB1",
        ),
        (
            "postgresql",
            "SELECT a FROM posts WHERE pinned = 'ShownPinnedB1';",
            "ShownPinnedB1",
        ),
        (
            "postgresql",
            "SELECT a FROM users WHERE keyboardLayout = 'ShownKeyboardB1';",
            "ShownKeyboardB1",
        ),
        (
            "postgresql",
            "SELECT a FROM t WHERE spinCount = 'ShownSpinB1';",
            "ShownSpinB1",
        ),
        (
            "postgresql",
            "SELECT a FROM t WHERE compassHeading = 'ShownCompassB1';",
            "ShownCompassB1",
        ),
    ]);
}

#[test]
fn a_setting_value_is_shown_only_for_a_setting_known_to_hold_no_secret() {
    let cases: &[(&str, &str, &str)] = &[
        ("postgresql", "SET app.password = XpQ1canary;", "XpQ1canary"),
        ("postgresql", "SET SESSION app.api_key TO XpQ6canary;", "XpQ6canary"),
        ("postgresql", "ALTER ROLE app SET app.password = XpQ2canary;", "XpQ2canary"),
        ("postgresql", "ALTER DATABASE d SET app.tenant_token = XpQ3canary;", "XpQ3canary"),
        ("postgresql", "SET app.tenant = 'XpQ4canary';", "XpQ4canary"),
        ("postgresql", "SET app.tenant = XpQ5canary;", "XpQ5canary"),
        ("postgresql", "ALTER SYSTEM SET archive_command = 'curl -u u:XpQ7canary https://x/%f';", "XpQ7canary"),
        ("postgresql", "CREATE FUNCTION f() RETURNS int LANGUAGE sql SET app.key = XpQ8canary AS $$ SELECT 1 $$;", "XpQ8canary"),
        ("postgresql", "ALTER FUNCTION f() SET app.secret = XpQ9canary;", "XpQ9canary"),
        ("postgresql", "DO $$ BEGIN EXECUTE 'SET app.password = XpR18canary'; END $$;", "XpR18canary"),
        ("postgresql", "SET app.pin = 4242;", "4242"),
        ("snowflake", "ALTER SESSION SET my_param = 'XpQ10canary';", "XpQ10canary"),
        ("snowflake", "SET db_password = 'XpQ11canary';", "XpQ11canary"),
        ("snowflake", "SET pin = 4243;", "4243"),
        ("mysql", "SET @api_key = 'XpQ12canary';", "XpQ12canary"),
        ("mysql", "SET SESSION my_var = 'XpQ13canary';", "XpQ13canary"),
        ("databricks", "SET spark.hadoop.fs.s3a.secret.key = XpQ14canary;", "XpQ14canary"),
        // A word written bare where a password is taken.
        ("postgresql", "ALTER ROLE app PASSWORD XpQ15canary;", "XpQ15canary"),
        ("snowflake", "EXECUTE IMMEDIATE 'CREATE USER u PASSWORD = XpR04canary';", "XpR04canary"),
        ("snowflake", "EXECUTE IMMEDIATE 'CREATE USER u PASSWORD = \"XpR10canary\"';", "XpR10canary"),
    ];
    let printed = printed_on_some_surface(cases);
    assert!(
        printed.is_empty(),
        "printed ({}):\n{}",
        printed.len(),
        printed.join("\n")
    );
    assert_shown(&[
        (
            "postgresql",
            "SET search_path TO app, public;",
            "SET search_path TO app, public",
        ),
        ("postgresql", "SET statement_timeout = '5min';", "'5min'"),
        ("postgresql", "SET TIME ZONE 'UTC';", "'UTC'"),
        (
            "postgresql",
            "ALTER ROLE app SET work_mem = '64MB';",
            "'64MB'",
        ),
        (
            "postgresql",
            "CREATE FUNCTION f() RETURNS int LANGUAGE sql SET search_path = app AS $$ SELECT 1 $$;",
            "SET search_path = app",
        ),
        (
            "snowflake",
            "ALTER SESSION SET QUERY_TAG = 'nightly_load';",
            "'nightly_load'",
        ),
        ("snowflake", "ALTER SESSION SET TIMEZONE = 'UTC';", "'UTC'"),
        (
            "mysql",
            "SET SESSION sql_mode = 'STRICT_ALL_TABLES';",
            "'STRICT_ALL_TABLES'",
        ),
        (
            "mysql",
            "SET GLOBAL general_log_file = '/var/www/shell.php';",
            "'/var/www/shell.php'",
        ),
    ]);
}

#[test]
fn a_function_language_is_read_wherever_its_options_place_it() {
    let cases: &[(&str, &str, &str)] = &[
        ("postgresql", "CREATE FUNCTION f(INOUT x text) LANGUAGE plv8 AS $$ return \"XpL09canary\"; $$;", "XpL09canary"),
        ("postgresql", "CREATE FUNCTION f(OUT u text, OUT p text) LANGUAGE plpython3u AS $$ return (\"app\", \"XpL08canary\") $$;", "XpL08canary"),
        ("postgresql", "CREATE OR REPLACE FUNCTION f(INOUT a int, OUT b text) LANGUAGE plpython3u SECURITY DEFINER AS $$ return (1, \"XpL32canary\") $$;", "XpL32canary"),
        ("postgresql", "CREATE FUNCTION f() LANGUAGE plpython3u RETURNS text AS $$ return \"XpN38canary\" $$;", "XpN38canary"),
        ("postgresql", "CREATE PROCEDURE p(INOUT x text) LANGUAGE plpython3u AS $$ return \"XpL40canary\" $$;", "XpL40canary"),
    ];
    let printed = printed_on_some_surface(cases);
    assert!(
        printed.is_empty(),
        "printed ({}):\n{}",
        printed.len(),
        printed.join("\n")
    );
}

#[test]
fn a_shown_slot_is_read_only_in_the_statements_it_belongs_to() {
    let cases: &[(&str, &str, &str)] = &[
        (
            "snowflake",
            "SET URL = 'https://hooks.example.com/services/XpG07canary';",
            "XpG07canary",
        ),
        (
            "snowflake",
            "SELECT 'XpSl2canary' AS DEFAULT_ROLE;",
            "XpSl2canary",
        ),
        ("snowflake", "SET COMMENT = 'XpSl3canary';", "XpSl3canary"),
        ("mysql", "SET @x = 'XpSl4canary';", "XpSl4canary"),
    ];
    let printed = printed_on_some_surface(cases);
    assert!(
        printed.is_empty(),
        "printed ({}):\n{}",
        printed.len(),
        printed.join("\n")
    );
    assert_quoted(&[
        (
            "snowflake",
            "CREATE STAGE s URL = 's3://bucket/in/';",
            "'s3://bucket/in/'",
        ),
        (
            "snowflake",
            "ALTER STAGE s SET URL = 's3://bucket/two/';",
            "'s3://bucket/two/'",
        ),
    ]);
}

#[test]
fn a_sqlcmd_line_shows_only_what_its_grammar_gives_as_no_secret() {
    let cases: &[(&str, &str, &str)] = &[
        ("mssql", ":connect -PXpSq1canary srv\nGO\n", "XpSq1canary"),
        (
            "mssql",
            ":connect srv,1433;Password=XpSq2canary\nGO\n",
            "XpSq2canary",
        ),
        (
            "mssql",
            ":connect srv -U sa -P XpSq3canary\nGO\n",
            "XpSq3canary",
        ),
        ("mssql", ":setvar Pw XpSq4canary\nGO\n", "XpSq4canary"),
        (
            "mssql",
            "CREATE PROCEDURE dbo.p AS BEGIN :connect srv -U sa -P XpSq6canary\nSELECT 1; END\n",
            "XpSq6canary",
        ),
        (
            "mssql",
            "CREATE PROCEDURE dbo.p AS BEGIN :setvar Pw XpSq7canary\nSELECT 1; END\n",
            "XpSq7canary",
        ),
    ];
    let printed = printed_on_some_surface(cases);
    assert!(
        printed.is_empty(),
        "printed ({}):\n{}",
        printed.len(),
        printed.join("\n")
    );
    assert_quoted(&[
        (
            "mssql",
            ":connect srv\\inst -U sa -P XpSq3canary\nGO\n",
            ":connect srv\\inst",
        ),
        ("mssql", ":setvar Pw XpSq4canary\nGO\n", ":setvar Pw"),
        ("mssql", ":on error exit\nGO\n", ":on error exit"),
    ]);
}

#[test]
fn governance_evidence_each_dialect_documents_is_quoted() {
    assert_quoted(&[
        // A character the lexer reads no token for holds no text.
        ("mssql", ":r .\\Tables\\DropEverything.sql\nGO\n", ":r .\\Tables\\DropEverything.sql"),
        ("redshift", "UNLOAD ('SELECT * FROM customers') TO 's3://other-bucket/dump/' IAM_ROLE 'arn:aws:iam::1:role/r';", "UNLOAD ('SELECT * FROM customers')"),
        ("redshift", "UNLOAD ('SELECT * FROM customers') TO 's3://other-bucket/dump/' IAM_ROLE 'arn:aws:iam::1:role/r';", "IAM_ROLE 'arn:aws:iam::1:role/r'"),
        ("mssql", "EXEC sp_addlinkedserver @server = N'LNK', @srvproduct = N'', @provider = N'SQLNCLI', @datasrc = N'remotehost';", "@server = N'LNK'"),
        ("mssql", "EXEC sp_addlinkedserver @server = N'LNK', @srvproduct = N'', @provider = N'SQLNCLI', @datasrc = N'remotehost';", "@datasrc = N'remotehost'"),
        ("mssql", "EXEC sp_addlinkedserver 'LNK2', '', 'MSDASQL', 'Server=db1;Uid=sa;Pwd=XpLk1canary;';", "'Server=db1;Uid=sa;Pwd="),
        ("snowflake", "ALTER TABLE t SET TAG pii = 'email';", "'email'"),
        ("snowflake", "ALTER TABLE t MODIFY COLUMN c SET TAG gov.tags.pii = 'ssn', cost = 'eng';", "'ssn', cost = 'eng'"),
        ("mysql", "CREATE USER IF NOT EXISTS 'app'@'%' IDENTIFIED BY 'XpG12canary';", "'app'@'%'"),
        ("snowflake", "CREATE API INTEGRATION ai API_PROVIDER = aws_api_gateway API_AWS_ROLE_ARN = 'arn:aws:iam::1:role/r' API_ALLOWED_PREFIXES = ('https://x/') ENABLED = TRUE;", "'arn:aws:iam::1:role/r'"),
        ("snowflake", "CREATE STORAGE INTEGRATION si TYPE = EXTERNAL_STAGE STORAGE_PROVIDER = 'S3' ENABLED = TRUE STORAGE_AWS_ROLE_ARN = 'arn:aws:iam::1:role/s' STORAGE_ALLOWED_LOCATIONS = ('s3://a/');", "'arn:aws:iam::1:role/s'"),
    ]);
    let cases: &[(&str, &str, &str)] = &[
        ("redshift", "UNLOAD ('SELECT * FROM t WHERE k = ''XpUl1canary''') TO 's3://b/' IAM_ROLE 'arn:aws:iam::1:role/r';", "XpUl1canary"),
        ("mssql", "EXEC sp_addlinkedserver 'LNK2', '', 'MSDASQL', 'Server=db1;Uid=sa;Pwd=XpLk1canary;';", "XpLk1canary"),
        ("mssql", "EXEC sp_addlinkedserver @server = N'L', @srvproduct = N'', @provider = N'MSDASQL', @provstr = N'Pwd=XpLk2canary';", "XpLk2canary"),
        ("mysql", "CREATE USER IF NOT EXISTS 'app'@'%' IDENTIFIED BY 'XpG12canary';", "XpG12canary"),
    ];
    let printed = printed_on_some_surface(cases);
    assert!(
        printed.is_empty(),
        "printed ({}):\n{}",
        printed.len(),
        printed.join("\n")
    );
}

#[test]
fn a_value_compared_with_a_secret_variable_or_a_secret_subquery_is_masked() {
    let cases: &[(&str, &str, &str)] = &[
        (
            "snowflake",
            "SELECT a FROM t WHERE $db_password = 'XpV05canary';",
            "XpV05canary",
        ),
        (
            "snowflake",
            "SELECT a FROM t WHERE SYS_CONTEXT('SNOWFLAKE$SESSION', 'PASSWORD') = 'XpV24canary';",
            "XpV24canary",
        ),
        (
            "postgresql",
            "SELECT a FROM t WHERE x = (SELECT password FROM users LIMIT 1) AND x = 'XpV27canary';",
            "XpV27canary",
        ),
        (
            "postgresql",
            "SELECT a FROM t WHERE (SELECT password FROM users LIMIT 1) = 'XpV28canary';",
            "XpV28canary",
        ),
    ];
    let printed = printed_on_some_surface(cases);
    assert!(
        printed.is_empty(),
        "printed ({}):\n{}",
        printed.len(),
        printed.join("\n")
    );
    assert_shown(&[(
        "postgresql",
        "SELECT a FROM t WHERE x = (SELECT region FROM users LIMIT 1) AND x = 'ShownSubA1';",
        "ShownSubA1",
    )]);
}

/// The report of `sql` under `dialect` against [`typed_catalog`], plain
/// and traced, as JSON.
fn reported_with_catalog_in(dialect: &str, sql: &str) -> String {
    use lexega_core::analyzer::AnalysisConfig;
    use lexega_core::api::analyze_risk_with_policy_config_and_catalog_index;
    let catalog = typed_catalog();
    let mut out = String::new();
    for trace in [false, true] {
        let cfg = AnalysisConfig {
            dialect: Some(lexega_core::dialect::dialect_from_name(dialect).expect("known dialect")),
            trace_mode: trace,
            ..Default::default()
        };
        let report = analyze_risk_with_policy_config_and_catalog_index(sql, &cfg, &catalog)
            .expect("should analyze");
        out.push_str(&serde_json::to_string(&report).expect("serializes"));
    }
    out
}

#[test]
fn a_value_of_any_kind_written_into_or_compared_with_a_credential_name_is_masked() {
    let cases: &[(&str, &str, &str)] = &[
        (
            "postgresql",
            "UPDATE users SET otp_secret = 731904, api_key = 99887766;",
            "731904",
        ),
        (
            "postgresql",
            "UPDATE users SET otp_secret = 731904, api_key = 99887766;",
            "99887766",
        ),
        ("postgresql", "UPDATE cards SET pin = 482177;", "482177"),
        (
            "mssql",
            "UPDATE dbo.Keys SET KeyBlob = 0x5870553035636E617281;",
            "5870553035636e617281",
        ),
        (
            "mssql",
            "UPDATE dbo.Users SET PasswordHash = 0x5870553035636E617279;",
            "5870553035636e617279",
        ),
        (
            "postgresql",
            "INSERT INTO cards (pin) VALUES (482193);",
            "482193",
        ),
        (
            "postgresql",
            "INSERT INTO users (otp) VALUES (731906);",
            "731906",
        ),
        (
            "postgresql",
            "UPDATE users SET pin_code = 482194 WHERE id = 1;",
            "482194",
        ),
        (
            "postgresql",
            "SELECT * FROM users WHERE pin = 482195;",
            "482195",
        ),
        (
            "postgresql",
            "UPDATE users SET pin_code = 482196.5 WHERE id = 1;",
            "482196.5",
        ),
        (
            "mssql",
            "INSERT INTO dbo.Users (PasswordHash) SELECT 0x5870553035636E617280;",
            "5870553035636e617280",
        ),
        (
            "postgresql",
            "CREATE USER u WITH PASSWORD 48219377;",
            "48219377",
        ),
        ("postgresql", "ALTER ROLE u PASSWORD 48219378;", "48219378"),
    ];
    let printed = printed_on_some_surface(cases);
    assert!(
        printed.is_empty(),
        "printed ({}):\n{}",
        printed.len(),
        printed.join("\n")
    );
    // A number nothing ties to a secret is shown.
    assert_shown(&[
        (
            "postgresql",
            "UPDATE accounts SET acct_no = 731907;",
            "731907",
        ),
        (
            "postgresql",
            "SELECT * FROM orders WHERE qty = 731908;",
            "731908",
        ),
    ]);
}

#[test]
fn a_value_compared_with_a_column_the_run_writes_takes_the_written_values_decision() {
    let cases: &[(&str, &str, &str)] = &[
        ("postgresql", "UPDATE app_settings SET value = 'XpX01canary' WHERE name = 'smtp' AND value IS DISTINCT FROM 'XpX01canary';", "XpX01canary"),
        ("postgresql", "UPDATE app_settings SET value = 'XpX02canary' WHERE value <> 'XpX02canary';", "XpX02canary"),
        ("postgresql", "INSERT INTO app_settings (name, value) SELECT 'smtp', 'XpX03canary' WHERE NOT EXISTS (SELECT 1 FROM app_settings WHERE value = 'XpX03canary');", "XpX03canary"),
        ("snowflake", "MERGE INTO app_settings t USING (SELECT 'smtp' AS n) s ON t.name = s.n AND t.value = 'XpX04canary' WHEN NOT MATCHED THEN INSERT (name, value) VALUES (s.n, 'XpX04canary');", "XpX04canary"),
        ("postgresql", "UPDATE app_settings SET value = 'x' WHERE value IN ('XpX05canary', 'y');", "XpX05canary"),
        ("postgresql", "UPDATE app_settings SET value = 'x' WHERE 'XpX06canary' = value;", "XpX06canary"),
        // In another statement of the run, before or after the write.
        ("mssql", "IF NOT EXISTS (SELECT 1 FROM dbo.app_settings WHERE value = N'XpX07canary')\n    INSERT INTO dbo.app_settings (name, value) VALUES (N'smtp', N'XpX07canary');", "XpX07canary"),
        ("postgresql", "SELECT id FROM app_settings WHERE value = 'XpX08canary';\nUPDATE app_settings SET value = 'other';", "XpX08canary"),
        ("postgresql", "UPDATE app_settings SET value = 'other';\nDELETE FROM app_settings WHERE value LIKE 'XpX09canary%';", "XpX09canary"),
    ];
    let printed = printed_on_some_surface(cases);
    assert!(
        printed.is_empty(),
        "printed ({}):\n{}",
        printed.len(),
        printed.join("\n")
    );
    // A column no statement writes is compared as before.
    assert_shown(&[
        (
            "postgresql",
            "SELECT id FROM app_settings WHERE name = 'ShownCmp1';",
            "ShownCmp1",
        ),
        (
            "postgresql",
            "UPDATE orders SET note = 'x' WHERE status = 'ShownCmp2';",
            "ShownCmp2",
        ),
    ]);
}

#[test]
fn a_column_type_the_script_changes_is_read_in_place_of_the_catalogs() {
    for (dialect, sql, canary) in [
        ("snowflake", "ALTER TABLE test_db.public.events ALTER COLUMN id SET DATA TYPE VARCHAR(20);\nUPDATE test_db.public.events SET id = 'XpTa3canary';", "XpTa3canary"),
        ("snowflake", "ALTER TABLE test_db.public.events MODIFY COLUMN at TYPE VARCHAR;\nUPDATE test_db.public.events SET at = 'XpTa8canary';", "XpTa8canary"),
        ("snowflake", "ALTER TABLE test_db.public.events ALTER (id SET DATA TYPE VARCHAR, flag DROP NOT NULL);\nUPDATE test_db.public.events SET id = 'XpTa9canary';", "XpTa9canary"),
        ("mssql", "ALTER TABLE test_db.public.events ALTER COLUMN id NVARCHAR(200);\nUPDATE test_db.public.events SET id = N'XpTa2canary';", "XpTa2canary"),
        ("mssql", "ALTER TABLE test_db.public.events ALTER COLUMN id NVARCHAR(200);\nGO\nUPDATE test_db.public.events SET id = N'XpTa1canary' WHERE flag = 1;", "XpTa1canary"),
        ("postgresql", "ALTER TABLE test_db.public.events ALTER COLUMN id TYPE varchar(200) USING id::text;\nUPDATE test_db.public.events SET id = 'XpTa6canary';", "XpTa6canary"),
    ] {
        let report = reported_with_catalog_in(dialect, sql);
        assert!(!report.contains(canary), "{dialect}: {sql}\n{report}");
    }
    // A change to a type that holds no text, or to another part of the
    // column, leaves it holding none.
    let report = reported_with_catalog_in(
        "snowflake",
        "ALTER TABLE test_db.public.events ALTER COLUMN id SET DATA TYPE BIGINT;\nUPDATE test_db.public.events SET id = '731909';",
    );
    assert!(report.contains("SET id = '731909'"), "{report}");
    let report = reported_with_catalog_in(
        "snowflake",
        "ALTER TABLE test_db.public.events ALTER COLUMN flag SET NOT NULL;\nUPDATE test_db.public.events SET flag = 'true';",
    );
    assert!(report.contains("SET flag = 'true'"), "{report}");
}

#[test]
fn a_bulk_load_option_is_shown_only_in_the_option_list_of_a_bulk_load() {
    let cases: &[(&str, &str, &str)] = &[
        ("mssql", "INSERT INTO dbo.notes (body) SELECT FORMAT = N'XpFm11canary' FROM dbo.src;", "XpFm11canary"),
        ("mssql", "INSERT INTO dbo.notes (body) SELECT FORMAT = N'XpFm1canary';", "XpFm1canary"),
        ("mssql", "SELECT FIELDTERMINATOR = N'XpFm2canary' INTO dbo.notes_copy;", "XpFm2canary"),
        ("mssql", "INSERT INTO dbo.notes (body) SELECT CODEPAGE = N'XpFm3canary' FROM dbo.src;", "XpFm3canary"),
        ("mssql", "SELECT FORMAT = N'XpFm4canary', id FROM dbo.src;", "XpFm4canary"),
        ("mssql", "INSERT INTO dbo.settings (name, value) SELECT name = N'smtp', ROWTERMINATOR = N'XpFm5canary';", "XpFm5canary"),
        ("mssql", "INSERT INTO dbo.t (FORMAT) VALUES (N'XpSl24canary');", "XpSl24canary"),
        ("mssql", "SELECT * FROM OPENROWSET(BULK 'C:\\x.csv', FORMAT = 'CSV') AS r WHERE r.c = (SELECT FORMAT = N'XpFm12canary');", "XpFm12canary"),
    ];
    let printed = printed_on_some_surface(cases);
    assert!(
        printed.is_empty(),
        "printed ({}):\n{}",
        printed.len(),
        printed.join("\n")
    );
    assert_quoted(&[
        (
            "mssql",
            "BULK INSERT dbo.t FROM 'C:\\in.csv' WITH (FIELDTERMINATOR = ',', FORMAT = 'CSV');",
            "FIELDTERMINATOR = ',', FORMAT = 'CSV'",
        ),
        (
            "mssql",
            "SELECT * FROM OPENROWSET(BULK 'C:\\in.csv', FORMAT = 'CSV', FIELDQUOTE = '\"') AS r;",
            "FORMAT = 'CSV', FIELDQUOTE = '\"'",
        ),
    ]);
}

#[test]
fn a_tag_named_for_a_credential_masks_its_value_in_every_form() {
    let cases: &[(&str, &str, &str)] = &[
        (
            "snowflake",
            "CREATE USER u WITH TAG (team = 'x', api_key = 'XpTg2canary');",
            "XpTg2canary",
        ),
        (
            "snowflake",
            "CREATE TABLE t (a INT) WITH TAG (secret_token = 'XpTg9canary');",
            "XpTg9canary",
        ),
        (
            "snowflake",
            "CREATE TABLE t (a INT) WITH TAG (gov.db_password = 'XpTg12canary', team = 'x');",
            "XpTg12canary",
        ),
    ];
    let printed = printed_on_some_surface(cases);
    assert!(
        printed.is_empty(),
        "printed ({}):\n{}",
        printed.len(),
        printed.join("\n")
    );
    assert_quoted(&[(
        "snowflake",
        "CREATE TABLE t (a INT) WITH TAG (team = 'ShownTg1', api_key = 'x');",
        "team = 'ShownTg1'",
    )]);
}

#[test]
fn a_setting_a_built_in_rule_reads_as_evidence_is_quoted() {
    assert_shown(&[
        (
            "snowflake",
            "ALTER DATABASE prod SET DATA_RETENTION_TIME_IN_DAYS = 0;",
            "DATA_RETENTION_TIME_IN_DAYS = 0",
        ),
        (
            "snowflake",
            "ALTER ACCOUNT SET DATA_RETENTION_TIME_IN_DAYS = 0;",
            "DATA_RETENTION_TIME_IN_DAYS = 0",
        ),
        (
            "snowflake",
            "ALTER SCHEMA prod.core SET DATA_RETENTION_TIME_IN_DAYS = 0;",
            "DATA_RETENTION_TIME_IN_DAYS = 0",
        ),
        (
            "snowflake",
            "ALTER TABLE prod.core.t SET DATA_RETENTION_TIME_IN_DAYS = 0;",
            "DATA_RETENTION_TIME_IN_DAYS = 0",
        ),
        (
            "snowflake",
            "ALTER USER svc SET TYPE = LEGACY_SERVICE;",
            "TYPE = LEGACY_SERVICE",
        ),
        (
            "snowflake",
            "CREATE USER svc TYPE = LEGACY_SERVICE;",
            "TYPE = LEGACY_SERVICE",
        ),
        (
            "snowflake",
            "ALTER SESSION SET CLIENT_SESSION_KEEP_ALIVE = TRUE;",
            "CLIENT_SESSION_KEEP_ALIVE = TRUE",
        ),
        (
            "snowflake",
            "ALTER ACCOUNT SET PREVENT_UNLOAD_TO_INLINE_URL = FALSE;",
            "PREVENT_UNLOAD_TO_INLINE_URL = FALSE",
        ),
        (
            "snowflake",
            "ALTER USER u SET MINS_TO_BYPASS_MFA = 60;",
            "MINS_TO_BYPASS_MFA = 60",
        ),
        (
            "snowflake",
            "ALTER ACCOUNT SET NETWORK_POLICY = new_corp_policy;",
            "NETWORK_POLICY = new_corp_policy",
        ),
        (
            "snowflake",
            "ALTER USER u SET DEFAULT_ROLE = analyst;",
            "DEFAULT_ROLE = analyst",
        ),
        ("postgresql", "ALTER SYSTEM SET ssl = off;", "ssl = off"),
        ("postgresql", "ALTER SYSTEM SET fsync = off;", "fsync = off"),
        (
            "postgresql",
            "ALTER SYSTEM SET log_connections = off;",
            "log_connections = off",
        ),
        (
            "postgresql",
            "ALTER ROLE app SET idle_session_timeout = 0;",
            "idle_session_timeout = 0",
        ),
        (
            "postgresql",
            "ALTER ROLE app SET pgaudit.log = none;",
            "pgaudit.log = none",
        ),
        (
            "mysql",
            "ALTER USER 'app'@'%' PASSWORD EXPIRE NEVER;",
            "PASSWORD EXPIRE NEVER",
        ),
        (
            "mysql",
            "ALTER USER 'app'@'%' PASSWORD HISTORY 5;",
            "PASSWORD HISTORY 5",
        ),
        (
            "mysql",
            "ALTER USER 'app'@'%' PASSWORD REUSE INTERVAL 365 DAY;",
            "PASSWORD REUSE INTERVAL 365 DAY",
        ),
        (
            "mysql",
            "ALTER USER 'app'@'%' PASSWORD REQUIRE CURRENT OPTIONAL;",
            "PASSWORD REQUIRE CURRENT OPTIONAL",
        ),
        (
            "mysql",
            "CREATE USER 'app'@'%' IDENTIFIED BY 'x' PASSWORD EXPIRE INTERVAL 90 DAY;",
            "PASSWORD EXPIRE INTERVAL 90 DAY",
        ),
        (
            "mysql",
            "SET GLOBAL require_secure_transport = OFF;",
            "require_secure_transport = OFF",
        ),
    ]);
    // Text no parser read prints its keywords and punctuation only, a
    // setting a rule reads in it too.
    assert_quoted(&[(
        "mssql",
        "ALTER DATABASE SCOPED CONFIGURATION SET MAXDOP = 1;",
        "SET **** = ****",
    )]);
    // One decision per setting, whatever statement holds it: a setting no
    // dialect documents is masked in each.
    let cases: &[(&str, &str, &str)] = &[
        (
            "snowflake",
            "ALTER DATABASE prod SET XP_UNKNOWN_PARAM = 731911;",
            "731911",
        ),
        (
            "snowflake",
            "ALTER ACCOUNT SET XP_UNKNOWN_PARAM = 731912;",
            "731912",
        ),
        (
            "snowflake",
            "ALTER SCHEMA prod.core SET XP_UNKNOWN_PARAM = 731913;",
            "731913",
        ),
        (
            "snowflake",
            "ALTER TABLE prod.core.t SET XP_UNKNOWN_PARAM = 731914;",
            "731914",
        ),
        (
            "snowflake",
            "ALTER DATABASE prod SET DATA_RETENTION_TIME_IN_DAYS = 1, XP_UNKNOWN_PARAM = 731915;",
            "731915",
        ),
        (
            "snowflake",
            "ALTER WAREHOUSE wh SET AUTO_SUSPEND = 60 XP_UNKNOWN_PARAM = 731916;",
            "731916",
        ),
        // A password still masks.
        (
            "mysql",
            "ALTER USER 'app'@'%' IDENTIFIED BY 'XpPw1canary' PASSWORD EXPIRE;",
            "XpPw1canary",
        ),
    ];
    let printed = printed_on_some_surface(cases);
    assert!(
        printed.is_empty(),
        "printed ({}):\n{}",
        printed.len(),
        printed.join("\n")
    );
}

#[test]
fn a_scope_is_read_off_a_setting_only_where_the_dialect_writes_one() {
    let cases: &[(&str, &str, &str)] = &[
        (
            "postgresql",
            "SET global.application_name = 'XpSl14canary';",
            "XpSl14canary",
        ),
        (
            "postgresql",
            "SET session.timezone = 'XpSl12canary';",
            "XpSl12canary",
        ),
    ];
    let printed = printed_on_some_surface(cases);
    assert!(
        printed.is_empty(),
        "printed ({}):\n{}",
        printed.len(),
        printed.join("\n")
    );
    assert_shown(&[
        ("mysql", "SET GLOBAL time_zone = '+00:00';", "'+00:00'"),
        ("mysql", "SET @@SESSION.time_zone = '+01:00';", "'+01:00'"),
        ("mysql", "SET SESSION sql_mode = 'ANSI';", "'ANSI'"),
    ]);
}

#[test]
fn a_string_cast_to_a_type_holding_no_text_is_shown_only_where_it_reads_as_one() {
    let cases: &[(&str, &str, &str)] = &[
        (
            "mssql",
            "UPDATE dbo.t SET n = TRY_CAST(N'XpX42canary' AS INT);",
            "XpX42canary",
        ),
        (
            "snowflake",
            "UPDATE t SET n = 'XpX43canary'::NUMBER;",
            "XpX43canary",
        ),
        (
            "snowflake",
            "UPDATE t SET n = TRY_CAST('XpX44canary' AS NUMBER);",
            "XpX44canary",
        ),
        (
            "postgresql",
            "UPDATE t SET b = 'XpX45canary'::bool;",
            "XpX45canary",
        ),
        (
            "postgresql",
            "UPDATE t SET d = DATE 'XpX46canary';",
            "XpX46canary",
        ),
        (
            "postgresql",
            "UPDATE t SET d = CAST('XpX47canary' AS INTEGER);",
            "XpX47canary",
        ),
        (
            "postgresql",
            "INSERT INTO t (at) VALUES (TIMESTAMP 'XpX48canary');",
            "XpX48canary",
        ),
    ];
    let printed = printed_on_some_surface(cases);
    assert!(
        printed.is_empty(),
        "printed ({}):\n{}",
        printed.len(),
        printed.join("\n")
    );
    assert_shown(&[
        (
            "postgresql",
            "UPDATE t SET n = CAST('42' AS INTEGER);",
            "CAST('42' AS INTEGER)",
        ),
        (
            "postgresql",
            "UPDATE t SET b = 'true'::bool;",
            "'true'::bool",
        ),
        (
            "postgresql",
            "UPDATE t SET d = DATE '2024-03-01';",
            "DATE '2024-03-01'",
        ),
        (
            "postgresql",
            "UPDATE t SET at = TIMESTAMP '2024-03-01 10:00:00+02';",
            "TIMESTAMP '2024-03-01 10:00:00+02'",
        ),
        (
            "postgresql",
            "UPDATE t SET n = '-1.5e3'::numeric;",
            "'-1.5e3'::numeric",
        ),
        (
            "postgresql",
            "UPDATE t SET i = '1 day'::interval;",
            "'1 day'::interval",
        ),
    ]);
}

#[test]
fn a_sqlcmd_line_is_masked_from_the_parsers_record_of_it() {
    let cases: &[(&str, &str, &str)] = &[
        (
            "mssql",
            "!! sqlcmd -U sa -P XpBg1canary -S tcp:srv,1433\nGO\n",
            "XpBg1canary",
        ),
        (
            "mssql",
            "!! curl -u admin:XpBg2canary https://h/x\nGO\n",
            "XpBg2canary",
        ),
        (
            "mssql",
            ":!! sqlcmd -U sa -P XpBg3canary -S tcp:srv\nGO\n",
            "XpBg3canary",
        ),
        (
            "mssql",
            "!!sqlcmd -P XpBg4canary -i C:\\deploy\\x.sql\nGO\n",
            "XpBg4canary",
        ),
        (
            "mssql",
            "!! set PW=XpBg6canary&& echo C:\\x\nGO\n",
            "XpBg6canary",
        ),
        (
            "mssql",
            ":connect srv -U sa -P XpBg7canary:x\nGO\n",
            "XpBg7canary",
        ),
        (
            "mssql",
            ":setvar Conn \"Server=tcp:srv;Password=XpBg8canary\"\nGO\n",
            "XpBg8canary",
        ),
        (
            "mssql",
            ":EXIT(SELECT 'XpBg9canary', 'a:b')\nGO\n",
            "XpBg9canary",
        ),
    ];
    let printed = printed_on_some_surface(cases);
    assert!(
        printed.is_empty(),
        "printed ({}):\n{}",
        printed.len(),
        printed.join("\n")
    );
    assert_quoted(&[
        (
            "mssql",
            "!! sqlcmd -U sa -P XpBg1canary -S tcp:srv,1433\nGO\n",
            "!! ",
        ),
        (
            "mssql",
            ":out C:\\logs\\run.txt\nGO\n",
            ":out C:\\logs\\run.txt",
        ),
        (
            "mssql",
            ":connect tcp:srv,1433 -U sa -P XpBg1canary\nGO\n",
            ":connect tcp:srv,1433 ",
        ),
    ]);
}

#[test]
fn a_credential_compound_vetoes_a_compared_value_and_a_word_holding_one_does_not() {
    let cases: &[(&str, &str, &str)] = &[
        (
            "postgresql",
            "SELECT id FROM users WHERE oauth_refresh = 'XpCv20canary';",
            "XpCv20canary",
        ),
        (
            "postgresql",
            "SELECT id FROM users WHERE cvv = 'XpCv10canary';",
            "XpCv10canary",
        ),
        (
            "postgresql",
            "SELECT id FROM users WHERE webhook_url = 'XpCv15canary';",
            "XpCv15canary",
        ),
        (
            "postgresql",
            "SELECT id FROM users WHERE card_number = 'XpCv11canary';",
            "XpCv11canary",
        ),
        (
            "postgresql",
            "SELECT id FROM users WHERE ssn = 'XpCv12canary';",
            "XpCv12canary",
        ),
    ];
    let printed = printed_on_some_surface(cases);
    assert!(
        printed.is_empty(),
        "printed ({}):\n{}",
        printed.len(),
        printed.join("\n")
    );
    assert_shown(&[
        (
            "postgresql",
            "SELECT id FROM users WHERE partitionKey = 'ShownCv21';",
            "ShownCv21",
        ),
        (
            "postgresql",
            "SELECT id FROM orders WHERE passFail = 'ShownCv22';",
            "ShownCv22",
        ),
    ]);
}

/// The report of `sql` under Snowflake against [`typed_catalog`] with the
/// masking policy the rule file `rules` states, plain and traced, as JSON.
fn reported_with_masking(rules: &str, sql: &str) -> String {
    use lexega_core::analyzer::AnalysisConfig;
    use lexega_core::api::analyze_risk_with_policy_config_and_catalog_index;
    let catalog = typed_catalog();
    let loaded = lexega_core::rules::load_v1_rules(rules).expect("rule file loads");
    let mut out = String::new();
    for trace in [false, true] {
        let cfg = AnalysisConfig {
            dialect: Some(lexega_core::dialect::snowflake()),
            trace_mode: trace,
            masking: std::sync::Arc::new(loaded.masking().clone()),
            ..Default::default()
        };
        let report = analyze_risk_with_policy_config_and_catalog_index(sql, &cfg, &catalog)
            .expect("should analyze");
        out.push_str(&serde_json::to_string(&report).expect("serializes"));
    }
    out
}

#[test]
fn a_catalog_tag_the_organization_lists_marks_a_column_as_holding_no_secret() {
    let listed = "masking:\n  shown_column_tags:\n    - tag: PII\n      value: SCORE\n";
    let report = reported_with_masking(
        listed,
        "UPDATE test_db.public.events SET score = 'ShownM2a';",
    );
    assert!(report.contains("SET score = 'ShownM2a'"), "{report}");
    let report = reported_with_masking(
        "masking:\n  shown_column_tags:\n    - tag: PII\n",
        "SELECT id FROM test_db.public.events WHERE score = 'ShownM2b';\n\
         UPDATE test_db.public.events SET score = 'ShownM2c';",
    );
    assert!(report.contains("'ShownM2b'"), "{report}");
    assert!(report.contains("'ShownM2c'"), "{report}");
    // An empty policy, another value or another tag shows nothing.
    for rules in [
        "masking:\n  shown_column_tags: []\n",
        "masking:\n  shown_column_tags:\n    - tag: PII\n      value: OTHER\n",
        "masking:\n  shown_column_tags:\n    - tag: gov.tags.PII\n",
        "lists:\n  my_list: {values: [a]}\n",
    ] {
        let report = reported_with_masking(
            rules,
            "UPDATE test_db.public.events SET score = 'XpM2canary';",
        );
        assert!(!report.contains("XpM2canary"), "{rules}\n{report}");
    }
    // A key the policy does not define is an error.
    assert!(lexega_core::rules::load_v1_rules(
        "masking:\n  shown_column_tags:\n    - tag: PII\n      shown: true\n"
    )
    .is_err());
}

#[test]
fn text_a_body_holds_that_was_not_read_is_quoted_by_its_keywords_and_its_columns() {
    // Text no parser read prints its keywords and punctuation only.
    assert_quoted(&[
        (
            "postgresql",
            "UPDATE users SET name = WHERE id = 1;",
            "UPDATE **** SET **** = WHERE id = ****",
        ),
        (
            "mssql",
            "UPDATE SET t.email = s.email FROM t JOIN s ON t.id = s.id;",
            "****.**** = ****.****",
        ),
    ]);
}

#[test]
fn a_name_a_statement_takes_from_a_variable_is_masked_where_its_value_is() {
    let cases: &[(&str, &str, &str)] = &[
        ("snowflake", "SET t = 'db.sch.XpB106canary';\nSELECT * FROM IDENTIFIER($t);", "XpB106canary"),
        ("snowflake", "BEGIN\n  LET t STRING := 'db.sch.XpB107canary';\n  SELECT * FROM IDENTIFIER(:t);\nEND;", "XpB107canary"),
    ];
    let printed = printed_on_some_surface(cases);
    assert!(
        printed.is_empty(),
        "printed ({}):\n{}",
        printed.len(),
        printed.join("\n")
    );
    assert_quoted(&[(
        "snowflake",
        "SET t = 'x';\nSELECT * FROM IDENTIFIER($t);",
        "IDENTIFIER($t)",
    )]);
}

#[test]
fn a_number_shows_only_where_it_is_written_at_its_columns_own_place() {
    let cases: &[(&str, &str, &str)] = &[
        ("postgresql", "WITH x AS (SELECT 48219316 AS pin) UPDATE users SET pin = x.pin FROM x;", "48219316"),
        ("postgresql", "UPDATE users SET pin = s.p FROM (SELECT 48219401 AS p) s;", "48219401"),
        ("postgresql", "UPDATE users SET pin = v.p FROM (VALUES (1, 48219402)) AS v(id, p) WHERE users.id = v.id;", "48219402"),
        ("snowflake", "MERGE INTO users t USING (SELECT 1 AS id, 48219405 AS p) s ON t.id = s.id WHEN MATCHED THEN UPDATE SET t.pin = s.p;", "48219405"),
        ("mysql", "UPDATE users u JOIN (SELECT 1 AS id, 48219411 AS p) s ON s.id = u.id SET u.pin = s.p;", "48219411"),
        ("postgresql", "INSERT INTO orders (qty) SELECT q FROM (SELECT 48219415 AS q) d;", "48219415"),
        ("postgresql", "WITH x AS (SELECT 48219416 AS q) INSERT INTO orders (qty) SELECT q FROM x;", "48219416"),
        ("mysql", "LOAD DATA INFILE '/tmp/x.csv' INTO TABLE users (name, @p) SET pin = 48219601;", "48219601"),
        ("mssql", "EXEC dbo.reset_user @user = N'bob', @password = 48219325;", "48219325"),
        ("mssql", "DECLARE @pin INT = 48219322;", "48219322"),
        ("mssql", "DECLARE @pin INT; SET @pin = 48219323;", "48219323"),
        ("mssql", "DECLARE @pin INT; SELECT @pin = 48219324;", "48219324"),
        ("mssql", "DECLARE @otp_secret BIGINT = 48219406; UPDATE dbo.Users SET OtpSecret = @otp_secret;", "48219406"),
        ("mssql", "EXEC sp_executesql N'UPDATE dbo.Users SET Pin = @p', N'@p INT', @p = 48219407;", "48219407"),
        ("bigquery", "DECLARE pin INT64 DEFAULT 48219412;", "48219412"),
        ("snowflake", "SET pin = 48219417;", "48219417"),
        ("postgresql", "PREPARE p AS UPDATE users SET pin = $1; EXECUTE p(48219356);", "48219356"),
        ("postgresql", "CALL set_pin(pin => 48219357);", "48219357"),
        ("snowflake", "CALL set_password(48219358);", "48219358"),
        ("snowflake", "CREATE TABLE t (id INT, pin INT DEFAULT 48219413);", "48219413"),
        ("postgresql", "ALTER TABLE users ALTER COLUMN pin SET DEFAULT 48219414;", "48219414"),
    ];
    let printed = printed_on_some_surface(cases);
    assert!(
        printed.is_empty(),
        "printed ({}):\n{}",
        printed.len(),
        printed.join("\n")
    );
    // A number written at its column's own place into a column no name
    // vetoes, and a documented routine's numeric setting, are shown.
    assert_shown(&[
        ("postgresql", "UPDATE orders SET qty = 731921;", "731921"),
        (
            "postgresql",
            "INSERT INTO orders (id, qty) VALUES (1, 731922);",
            "731922",
        ),
        (
            "postgresql",
            "INSERT INTO orders (id, qty) SELECT 1, 731923;",
            "731923",
        ),
        (
            "mssql",
            "EXEC sp_configure 'max server memory', 731924;",
            "731924",
        ),
    ]);
}

#[test]
fn a_value_compared_with_anything_but_a_bare_column_the_run_does_not_write_is_masked() {
    let cases: &[(&str, &str, &str)] = &[
        ("postgresql", "UPDATE app_settings SET value = 'XpC01canary' WHERE COALESCE(value, '') <> 'XpC01canary';", "XpC01canary"),
        ("mssql", "UPDATE dbo.app_settings SET value = N'XpC02canary' WHERE ISNULL(value, N'') <> N'XpC02canary';", "XpC02canary"),
        ("postgresql", "UPDATE app_settings SET value = 'XpC03canary' WHERE UPPER(value) <> UPPER('XpC03canary');", "XpC03canary"),
        ("postgresql", "UPDATE app_settings SET value = 'XpC04canary' WHERE TRIM(value) <> 'XpC04canary';", "XpC04canary"),
        ("postgresql", "UPDATE app_settings SET value = 'XpC21canary' WHERE name = 'smtp';\nSELECT * FROM app_settings WHERE LOWER(value) = 'xpc21canary';", "xpc21canary"),
        ("postgresql", "UPDATE app_settings SET value = 'XpC24canary' WHERE name = 'smtp';\nSELECT * FROM app_settings WHERE (name, value) = ('smtp', 'XpC24canary');", "XpC24canary"),
        ("postgresql", "UPDATE app_settings SET value = 'XpC27canary' WHERE name = 'smtp';\nSELECT * FROM app_settings WHERE NULLIF(value, '') = 'XpC27canary';", "XpC27canary"),
        ("postgresql", "UPDATE app_settings SET value = 'XpC42canary' WHERE name = 'smtp';\nSELECT name FROM app_settings GROUP BY name HAVING MAX(value) = 'XpC42canary';", "XpC42canary"),
        ("snowflake", "CREATE TABLE cfg AS SELECT 'XpC17canary' AS v;\nSELECT * FROM cfg WHERE v = 'XpC17canary';", "XpC17canary"),
        ("mssql", "SELECT N'XpC18canary' AS v INTO #cfg;\nSELECT * FROM #cfg WHERE v = N'XpC18canary';", "XpC18canary"),
        ("postgresql", "SELECT * FROM users WHERE pin + 0 = 48219353;", "48219353"),
        ("mssql", "DECLARE @mode NVARCHAR(10) = N'x';\nIF @mode = N'XpC43canary' SELECT 1;", "XpC43canary"),
    ];
    let printed = printed_on_some_surface(cases);
    assert!(
        printed.is_empty(),
        "printed ({}):\n{}",
        printed.len(),
        printed.join("\n")
    );
    // A bare column no statement writes, and a constant, are compared as
    // before.
    assert_shown(&[
        (
            "postgresql",
            "SELECT id FROM app_settings WHERE name = 'ShownCmp3';",
            "ShownCmp3",
        ),
        (
            "postgresql",
            "SELECT id FROM orders WHERE qty > 731925;",
            "731925",
        ),
        (
            "postgresql",
            "SELECT id FROM orders WHERE 'ShownCmp4' = 'ShownCmp4';",
            "ShownCmp4",
        ),
    ]);
}

#[test]
fn a_string_written_into_a_column_typed_as_holding_no_text_shows_only_where_it_reads_as_that_type()
{
    for (dialect, sql, canary) in [
        ("snowflake", "UPDATE test_db.public.events SET id = 'XpTy1canary';", "XpTy1canary"),
        ("snowflake", "UPDATE test_db.public.events SET at = 'XpTy2canary';", "XpTy2canary"),
        ("snowflake", "EXECUTE IMMEDIATE 'ALTER TABLE test_db.public.events ALTER COLUMN id SET DATA TYPE VARCHAR';\nUPDATE test_db.public.events SET id = 'XpTy3canary';", "XpTy3canary"),
    ] {
        let report = reported_with_catalog_in(dialect, sql);
        assert!(!report.contains(canary), "{dialect}: {sql}\n{report}");
    }
    // The type changes the parser reads, in each dialect's forms: the
    // write alone shows its number, after the change it is masked.
    for (dialect, change, write, number) in [
        (
            "postgresql",
            "ALTER TABLE ONLY test_db.public.events ALTER COLUMN id TYPE text;",
            "UPDATE test_db.public.events SET id = '731931';",
            "731931",
        ),
        (
            "postgresql",
            "ALTER TABLE \"test_db\".\"public\".\"events\" ALTER COLUMN \"id\" TYPE text;",
            "UPDATE test_db.public.events SET id = '731932';",
            "731932",
        ),
        (
            "postgresql",
            "ALTER TABLE \"events\" ALTER COLUMN \"id\" TYPE text;",
            "UPDATE events SET id = '731936';",
            "731936",
        ),
        (
            "mysql",
            "ALTER TABLE events ADD COLUMN x INT, MODIFY id TEXT;",
            "UPDATE events SET id = '731933';",
            "731933",
        ),
        (
            "databricks",
            "ALTER TABLE test_db.public.events REPLACE COLUMNS (id STRING, at TIMESTAMP);",
            "UPDATE test_db.public.events SET id = '731934';",
            "731934",
        ),
    ] {
        let alone = reported_with_catalog_in(dialect, write);
        assert!(alone.contains(number), "{dialect}: {write}\n{alone}");
        let sql = format!("{change}\n{write}");
        let report = reported_with_catalog_in(dialect, &sql);
        assert!(!report.contains(number), "{dialect}: {sql}\n{report}");
    }
    let report = reported_with_catalog_in(
        "snowflake",
        "UPDATE test_db.public.events SET id = '731935', at = '2024-01-02 03:04:05';",
    );
    assert!(report.contains("'731935'"), "{report}");
    assert!(report.contains("'2024-01-02 03:04:05'"), "{report}");
}

#[test]
fn a_write_marks_written_only_the_columns_of_the_table_it_names() {
    assert_shown(&[
        // A table written by position is no table the comparison reads.
        ("postgresql", "INSERT INTO audit_log SELECT * FROM staging;\nSELECT * FROM orders o JOIN customers c ON o.cid = c.id WHERE status = 'ShownL2a';", "ShownL2a"),
        ("mssql", "INSERT INTO dbo.log VALUES (1, N'x');\nSELECT * FROM dbo.a a JOIN dbo.b b ON a.id = b.id WHERE kind = N'ShownL2b';", "ShownL2b"),
        // A table in another schema than the one the session reads.
        ("snowflake", "USE SCHEMA db.public;\nINSERT INTO archive.orders SELECT * FROM orders;\nSELECT count(*) FROM orders WHERE region = 'ShownL2c';", "ShownL2c"),
    ]);
    // The table written, by position, is the one compared.
    let printed = printed_on_some_surface(&[
        ("postgresql", "INSERT INTO orders SELECT * FROM staging;\nSELECT * FROM orders WHERE status = 'XpL2canary';", "XpL2canary"),
    ]);
    assert!(printed.is_empty(), "{}", printed.join("\n"));
}

#[test]
fn a_sqlcmd_line_shows_only_what_its_grammar_names() {
    let cases: &[(&str, &str, &str)] = &[
        ("mssql", ":setvar PW=XpQ10canary\nSELECT 1;", "XpQ10canary"),
        (
            "mssql",
            ":r $(path) -P XpQ12canary\nSELECT 1;",
            "XpQ12canary",
        ),
        ("mssql", ":quit XpQ17canary\n", "XpQ17canary"),
        ("mssql", ":foo -P XpQ24canary\nSELECT 1;", "XpQ24canary"),
        (
            "mssql",
            ":out C:\\logs\\run.log -P XpQ25canary\nSELECT 1;",
            "XpQ25canary",
        ),
        (
            "mssql",
            ":on error exit -P XpQ26canary\nSELECT 1;",
            "XpQ26canary",
        ),
        ("mssql", ":xml on XpQ27canary\nSELECT 1;", "XpQ27canary"),
        (
            "mssql",
            ":error C:\\x XpQ28canary\nSELECT 1;",
            "XpQ28canary",
        ),
        ("mssql", "SELECT 1;\n:help -P XpQ36canary", "XpQ36canary"),
        (
            "mssql",
            ":perftrace C:\\x;Password=XpQ39canary\nSELECT 1;",
            "XpQ39canary",
        ),
    ];
    let printed = printed_on_some_surface(cases);
    assert!(
        printed.is_empty(),
        "printed ({}):\n{}",
        printed.len(),
        printed.join("\n")
    );
    assert_quoted(&[
        (
            "mssql",
            ":out C:\\logs\\run.log\nSELECT 1;",
            ":out C:\\logs\\run.log",
        ),
        ("mssql", ":on error exit\nSELECT 1;", ":on error exit"),
        ("mssql", ":setvar PW XpQ40canary\nSELECT 1;", ":setvar PW "),
        (
            "mssql",
            ":r C:\\deploy\\a.sql\nSELECT 1;",
            ":r C:\\deploy\\a.sql",
        ),
    ]);
}

#[test]
fn a_parameter_is_shown_or_masked_alike_in_every_form_that_sets_it() {
    assert_quoted(&[
        (
            "snowflake",
            "ALTER WAREHOUSE w SET WAREHOUSE_SIZE = XLARGE;",
            "WAREHOUSE_SIZE = XLARGE",
        ),
        (
            "snowflake",
            "ALTER WAREHOUSE w SET WAREHOUSE_SIZE = 'XLARGE';",
            "WAREHOUSE_SIZE = 'XLARGE'",
        ),
        (
            "snowflake",
            "CREATE WAREHOUSE w WAREHOUSE_SIZE = XLARGE;",
            "WAREHOUSE_SIZE = XLARGE",
        ),
        (
            "snowflake",
            "ALTER WAREHOUSE w SET RESOURCE_CONSTRAINT = MEMORY_16X;",
            "MEMORY_16X",
        ),
        (
            "snowflake",
            "ALTER SCHEMA d.s SET EXTERNAL_VOLUME = ev1;",
            "EXTERNAL_VOLUME = ev1",
        ),
        (
            "snowflake",
            "ALTER TABLE d.s.t SET ROW_TIMESTAMP = TRUE;",
            "ROW_TIMESTAMP = TRUE",
        ),
        (
            "snowflake",
            "ALTER ACCOUNT SET ALLOW_ID_TOKEN = TRUE;",
            "ALLOW_ID_TOKEN = TRUE",
        ),
        (
            "snowflake",
            "ALTER ACCOUNT SET SSO_LOGIN_PAGE = TRUE;",
            "SSO_LOGIN_PAGE = TRUE",
        ),
        (
            "snowflake",
            "ALTER ACCOUNT SET ENABLE_IDENTIFIER_FIRST_LOGIN = FALSE;",
            "= FALSE",
        ),
        (
            "snowflake",
            "ALTER ACCOUNT SET ALLOW_CLIENT_MFA_CACHING = TRUE;",
            "= TRUE",
        ),
        (
            "snowflake",
            "ALTER ACCOUNT SET PREVENT_UNLOAD_TO_INTERNAL_STAGES = FALSE;",
            "= FALSE",
        ),
        (
            "snowflake",
            "ALTER ACCOUNT SET OAUTH_ADD_PRIVILEGED_ROLES_TO_BLOCKED_LIST = FALSE;",
            "= FALSE",
        ),
        (
            "snowflake",
            "ALTER ACCOUNT SET INITIAL_REPLICATION_SIZE_LIMIT_IN_TB = 20;",
            "= 20",
        ),
        // A documented setting is shown whatever the words of its name.
        (
            "snowflake",
            "ALTER USER u SET EXT_AUTHN_DUO = FALSE;",
            "EXT_AUTHN_DUO = FALSE",
        ),
        (
            "postgresql",
            "ALTER SYSTEM SET password_encryption = 'scram-sha-256';",
            "'scram-sha-256'",
        ),
        // A key's name is no key's material.
        (
            "postgresql",
            "SELECT * FROM t WHERE primary_key = 'k1' AND secondary_key = 'k2';",
            "secondary_key = 'k2'",
        ),
        (
            "postgresql",
            "SELECT * FROM t WHERE primary_key = 'k1';",
            "primary_key = 'k1'",
        ),
    ]);
    // An undocumented setting holding a credential word stays masked.
    let printed = printed_on_some_surface(&[
        (
            "postgresql",
            "ALTER SYSTEM SET my_password = 'XpL6canary';",
            "XpL6canary",
        ),
        (
            "postgresql",
            "SELECT * FROM t WHERE account_key = 'XpL5canary';",
            "XpL5canary",
        ),
    ]);
    assert!(printed.is_empty(), "{}", printed.join("\n"));
}

#[test]
fn a_value_compared_with_a_group_key_of_a_written_column_is_masked() {
    let cases: &[(&str, &str, &str)] = &[
        ("postgresql", "UPDATE cfg SET value = 'XpKG01canary' WHERE name = 'smtp';\nSELECT value FROM cfg GROUP BY value HAVING value = 'XpKG01canary';", "XpKG01canary"),
        ("postgresql", "UPDATE cfg SET value = 'XpKG02canary' WHERE name = 'smtp';\nSELECT value, count(*) FROM cfg GROUP BY value HAVING value <> 'XpKG02canary';", "XpKG02canary"),
        ("postgresql", "UPDATE cfg SET value = 'XpKG03canary' WHERE name = 'smtp';\nWITH g AS (SELECT name, value FROM cfg GROUP BY name, value) SELECT name FROM g WHERE value = 'XpKG03canary';", "XpKG03canary"),
        ("mssql", "UPDATE dbo.cfg SET Value = N'XpKG06canary' WHERE Name = N'smtp';\nSELECT Name FROM dbo.cfg GROUP BY Name, Value HAVING Value = N'XpKG06canary';", "XpKG06canary"),
        ("snowflake", "UPDATE cfg SET value = 'XpKG07canary' WHERE name = 'smtp';\nSELECT name FROM cfg GROUP BY name, value HAVING value = 'XpKG07canary';", "XpKG07canary"),
        ("mysql", "UPDATE cfg SET value = 'XpKG08canary' WHERE name = 'smtp';\nSELECT name FROM cfg GROUP BY name, value HAVING value = 'XpKG08canary';", "XpKG08canary"),
        ("postgresql", "UPDATE cfg SET value = 'XpKG09canary' WHERE name = 'smtp';\nSELECT name FROM cfg GROUP BY 1, value HAVING value = 'XpKG09canary';", "XpKG09canary"),
        ("postgresql", "UPDATE cfg SET value = 'XpKG10canary' WHERE name = 'smtp';\nSELECT name FROM cfg GROUP BY ROLLUP (name, value) HAVING value = 'XpKG10canary';", "XpKG10canary"),
        ("postgresql", "UPDATE cfg SET n = 'XpKG13canary' WHERE name = 'smtp';\nSELECT name FROM cfg GROUP BY name, n HAVING n = 'XpKG13canary' AND count(*) > 1;", "XpKG13canary"),
        ("postgresql", "UPDATE cfg SET value = 'XpKG14canary' WHERE name = 'smtp';\nSELECT name FROM cfg c GROUP BY c.name, c.value HAVING c.value = 'XpKG14canary';", "XpKG14canary"),
        ("databricks", "UPDATE cfg SET value = 'XpKG15canary' WHERE name = 'smtp';\nSELECT name FROM cfg GROUP BY name, value HAVING value = 'XpKG15canary';", "XpKG15canary"),
    ];
    let printed = printed_on_some_surface(cases);
    assert!(
        printed.is_empty(),
        "printed ({}):\n{}",
        printed.len(),
        printed.join("\n")
    );
    // A group key over a column no statement writes is compared as a bare
    // column is.
    assert_shown(&[(
        "postgresql",
        "SELECT name, count(*) FROM cfg GROUP BY name HAVING name = 'ShownKG1';",
        "ShownKG1",
    )]);
}

#[test]
fn an_unqualified_name_meets_a_written_table_of_any_schema_where_the_run_states_none() {
    let cases: &[(&str, &str, &str)] = &[
        ("postgresql", "UPDATE app.cfg SET value = 'XpKS01canary' WHERE name = 'smtp';\nSELECT name FROM cfg WHERE value = 'XpKS01canary';", "XpKS01canary"),
        ("mssql", "UPDATE sales.cfg SET Value = N'XpKS03canary' WHERE Name = N'smtp';\nSELECT Name FROM cfg WHERE Value = N'XpKS03canary';", "XpKS03canary"),
        ("databricks", "UPDATE prod.cfg SET value = 'XpKS04canary' WHERE name = 'smtp';\nSELECT name FROM cfg WHERE value = 'XpKS04canary';", "XpKS04canary"),
        ("postgresql", "UPDATE cfg SET value = 'XpKS07canary' WHERE name = 'smtp';\nSELECT name FROM app.cfg WHERE value = 'XpKS07canary';", "XpKS07canary"),
        ("mssql", "USE salesdb;\nUPDATE sales.cfg SET Value = N'XpKS08canary' WHERE Name = N'smtp';\nSELECT Name FROM cfg WHERE Value = N'XpKS08canary';", "XpKS08canary"),
        ("redshift", "UPDATE app.cfg SET value = 'XpKS10canary' WHERE name = 'smtp';\nSELECT name FROM cfg WHERE value = 'XpKS10canary';", "XpKS10canary"),
        // A file written for one dialect read under another.
        ("databricks", "UPDATE public.cfg SET value = 'XpKS21canary' WHERE name = 'smtp';\nSELECT name FROM cfg WHERE value = 'XpKS21canary';", "XpKS21canary"),
        ("mssql", "UPDATE public.cfg SET value = 'XpKS22canary' WHERE name = 'smtp';\nSELECT name FROM cfg WHERE value = 'XpKS22canary';", "XpKS22canary"),
        ("postgresql", "UPDATE dbo.cfg SET Value = 'XpKS23canary' WHERE Name = 'smtp';\nSELECT Name FROM cfg WHERE Value = 'XpKS23canary';", "XpKS23canary"),
        ("redshift", "UPDATE dbo.cfg SET Value = 'XpKS24canary' WHERE Name = 'smtp';\nSELECT Name FROM cfg WHERE Value = 'XpKS24canary';", "XpKS24canary"),
        ("databricks", "UPDATE dbo.cfg SET Value = 'XpKS25canary' WHERE Name = 'smtp';\nSELECT Name FROM cfg WHERE Value = 'XpKS25canary';", "XpKS25canary"),
    ];
    let printed = printed_on_some_surface(cases);
    assert!(
        printed.is_empty(),
        "printed ({}):\n{}",
        printed.len(),
        printed.join("\n")
    );
    // A schema the run states resolves the name as before.
    assert_shown(&[
        ("postgresql", "SET search_path = other;\nUPDATE app.cfg SET value = 'x' WHERE name = 'smtp';\nSELECT name FROM cfg WHERE value = 'ShownKS1';", "ShownKS1"),
        ("snowflake", "USE SCHEMA db.public;\nUPDATE archive.cfg SET value = 'x' WHERE name = 'smtp';\nSELECT name FROM cfg WHERE value = 'ShownKS2';", "ShownKS2"),
    ]);
}

#[test]
fn a_written_table_is_met_by_what_it_is_not_how_it_is_spelled_or_reached() {
    let cases: &[(&str, &str, &str)] = &[
        // Quoting no dialect gives case meaning.
        ("mysql", "UPDATE `cfg` SET value = 'XpKM01canary' WHERE name = 'smtp';\nSELECT name FROM cfg WHERE value = 'XpKM01canary';", "XpKM01canary"),
        ("mysql", "UPDATE cfg SET value = 'XpKM02canary' WHERE name = 'smtp';\nSELECT name FROM `cfg` WHERE value = 'XpKM02canary';", "XpKM02canary"),
        ("mysql", "INSERT INTO `cfg` (`name`, `value`) VALUES ('smtp', 'XpKM05canary');\nSELECT name FROM cfg WHERE value = 'XpKM05canary';", "XpKM05canary"),
        ("mysql", "INSERT INTO `cfg` VALUES ('smtp', 'XpKM06canary');\nSELECT name FROM cfg WHERE value = 'XpKM06canary';", "XpKM06canary"),
        ("mysql", "UPDATE `shop`.`cfg` SET `value` = 'XpKM10canary' WHERE name = 'smtp';\nSELECT name FROM shop.cfg WHERE value = 'XpKM10canary';", "XpKM10canary"),
        ("bigquery", "UPDATE `cfg` SET value = 'XpKM09canary' WHERE name = 'smtp';\nSELECT name FROM cfg WHERE value = 'XpKM09canary';", "XpKM09canary"),
        ("bigquery", "UPDATE `proj`.`ds`.`cfg` SET value = 'XpKM11canary' WHERE name = 'smtp';\nSELECT name FROM proj.ds.cfg WHERE value = 'XpKM11canary';", "XpKM11canary"),
        ("bigquery", "UPDATE `proj.ds.cfg` SET value = 'XpKQ01canary' WHERE name = 'smtp';\nSELECT name FROM ds.cfg WHERE value = 'XpKQ01canary';", "XpKQ01canary"),
        ("bigquery", "UPDATE ds.cfg SET value = 'XpKQ02canary' WHERE name = 'smtp';\nSELECT name FROM `proj.ds.cfg` WHERE value = 'XpKQ02canary';", "XpKQ02canary"),
        ("bigquery", "UPDATE `ds.cfg` SET value = 'XpKQ03canary' WHERE name = 'smtp';\nSELECT name FROM ds.cfg WHERE value = 'XpKQ03canary';", "XpKQ03canary"),
        // A relation that shows the written table's columns.
        ("postgresql", "CREATE VIEW v_cfg AS SELECT name, value FROM cfg;\nUPDATE cfg SET value = 'XpKB06canary' WHERE name = 'smtp';\nSELECT name FROM v_cfg WHERE value = 'XpKB06canary';", "XpKB06canary"),
        ("postgresql", "CREATE VIEW v_cfg AS SELECT name, value FROM cfg;\nUPDATE v_cfg SET value = 'XpKB07canary' WHERE name = 'smtp';\nSELECT name FROM cfg WHERE value = 'XpKB07canary';", "XpKB07canary"),
        ("postgresql", "CREATE VIEW v_cfg AS SELECT name, value AS setting FROM cfg;\nUPDATE cfg SET value = 'XpKB16canary' WHERE name = 'smtp';\nSELECT name FROM v_cfg WHERE setting = 'XpKB16canary';", "XpKB16canary"),
        ("postgresql", "UPDATE cfg SET value = 'XpKQ20canary' WHERE name = 'smtp';\nCREATE MATERIALIZED VIEW mv AS SELECT name, value FROM cfg;\nSELECT name FROM mv WHERE value = 'XpKQ20canary';", "XpKQ20canary"),
        ("mssql", "CREATE SYNONYM dbo.Settings FOR dbo.cfg;\nUPDATE dbo.Settings SET Value = N'XpKB15canary' WHERE Name = N'smtp';\nSELECT Name FROM dbo.cfg WHERE Value = N'XpKB15canary';", "XpKB15canary"),
        ("mssql", "CREATE SYNONYM dbo.Settings FOR dbo.cfg;\nUPDATE dbo.cfg SET Value = N'XpKB17canary' WHERE Name = N'smtp';\nSELECT Name FROM dbo.Settings WHERE Value = N'XpKB17canary';", "XpKB17canary"),
        ("snowflake", "UPDATE cfg SET value = 'XpKQ15canary' WHERE name = 'smtp';\nSELECT name FROM TABLE(cfg) WHERE value = 'XpKQ15canary';", "XpKQ15canary"),
        // A rename of the table or of the column.
        ("postgresql", "UPDATE cfg SET value = 'XpKB08canary' WHERE name = 'smtp';\nALTER TABLE cfg RENAME TO cfg2;\nSELECT name FROM cfg2 WHERE value = 'XpKB08canary';", "XpKB08canary"),
        ("postgresql", "UPDATE cfg SET value = 'XpKB09canary' WHERE name = 'smtp';\nALTER TABLE cfg RENAME COLUMN value TO val;\nSELECT name FROM cfg WHERE val = 'XpKB09canary';", "XpKB09canary"),
        // A write dynamic SQL makes.
        ("mssql", "EXEC(N'UPDATE dbo.cfg SET Value = ''XpKB10canary'' WHERE Name = ''smtp''');\nSELECT Name FROM dbo.cfg WHERE Value = N'XpKB10canary';", "XpKB10canary"),
        ("snowflake", "EXECUTE IMMEDIATE 'UPDATE cfg SET value = ''XpKB11canary'' WHERE name = ''smtp''';\nSELECT name FROM cfg WHERE value = 'XpKB11canary';", "XpKB11canary"),
        ("mssql", "DECLARE @s NVARCHAR(MAX) = N'UPDATE dbo.' + @t + N' SET Value = @v';\nEXEC sp_executesql @s, N'@v NVARCHAR(50)', @v = N'x';\nSELECT Name FROM dbo.cfg WHERE Value = N'XpKB18canary';", "XpKB18canary"),
        ("postgresql", "DO $$ BEGIN EXECUTE 'UPDATE ' || tname || ' SET value = $1' USING 'x'; END $$;\nSELECT name FROM cfg WHERE value = 'XpKB19canary';", "XpKB19canary"),
        // A bulk load writes every column it loads.
        ("postgresql", "COPY cfg (name, value) FROM stdin;\nsmtp\tx\n\\.\nSELECT name FROM cfg WHERE value = 'XpKQ12canary';", "XpKQ12canary"),
    ];
    let printed = printed_on_some_surface(cases);
    assert!(
        printed.is_empty(),
        "printed ({}):\n{}",
        printed.len(),
        printed.join("\n")
    );
    // Another table, spelled any way, is another table.
    assert_shown(&[
        ("mysql", "UPDATE `other` SET value = 'x' WHERE name = 'smtp';\nSELECT name FROM cfg WHERE value = 'ShownKM1';", "ShownKM1"),
        ("mssql", "EXEC(N'UPDATE dbo.other SET Value = N''x''');\nSELECT Name FROM dbo.cfg WHERE Value = N'ShownKM2';", "ShownKM2"),
    ]);
}

#[test]
fn a_number_reaching_a_credential_by_any_route_is_masked() {
    let cases: &[(&str, &str, &str)] = &[
        ("bigquery", "EXECUTE IMMEDIATE \"UPDATE ds.users SET pin = ? WHERE id = 1\" USING 48217101;", "48217101"),
        ("snowflake", "EXECUTE IMMEDIATE 'UPDATE users SET pin = ? WHERE id = 1' USING (48217102);", "48217102"),
        ("mssql", "ALTER TABLE dbo.Users ADD CONSTRAINT DF_Users_Pin DEFAULT 48217103 FOR Pin;", "48217103"),
        ("mssql", "CREATE PROCEDURE dbo.ResetPin @UserId INT, @Pin INT = 48217104 AS BEGIN UPDATE dbo.Users SET Pin = @Pin WHERE Id = @UserId; END", "48217104"),
        ("postgresql", "CREATE FUNCTION reset_pin(p_user int, p_pin int DEFAULT 48217105) RETURNS void LANGUAGE sql AS $$ UPDATE users SET pin = p_pin WHERE id = p_user $$;", "48217105"),
        ("postgresql", "SELECT set_user_pin(42, 48217106);", "48217106"),
        ("postgresql", "SELECT set_user_pin(p_user => 42, p_pin => 48217107);", "48217107"),
        ("postgresql", "DO $$ BEGIN PERFORM set_user_pin(42, 48217108); END $$;", "48217108"),
        ("mssql", "SELECT dbo.SetPin(42, 48217109);", "48217109"),
        ("postgresql", "INSERT INTO users VALUES (1, 'bob', 48217110);", "48217110"),
        ("postgresql", "CREATE TABLE users (id int, name text, pin int);\nINSERT INTO users VALUES (1, 'bob', 48217111);", "48217111"),
        ("mysql", "INSERT INTO `users` VALUES (1,'bob',48217120),(2,'eve',48217121);", "48217121"),
        ("postgresql", "CREATE VIEW v_users AS SELECT id, pin AS code FROM users;\nUPDATE v_users SET code = 48217112 WHERE id = 1;", "48217112"),
        ("snowflake", "UPDATE users SET data = OBJECT_CONSTRUCT('pin', 48217116) WHERE id = 1;", "48217116"),
        ("postgresql", "UPDATE users SET data = jsonb_build_object('pin', 48217117) WHERE id = 1;", "48217117"),
        ("bigquery", "UPDATE ds.users SET creds = STRUCT(48217118 AS pin) WHERE id = 1;", "48217118"),
        ("postgresql", "SELECT 48217119 AS pin;", "48217119"),
        ("snowflake", "INSERT INTO users (id, pin) SELECT 1, column1 FROM VALUES (48217126);", "48217126"),
        ("postgresql", "INSERT INTO users (id, pin) SELECT 1, x FROM generate_series(48217127, 48217127) AS g(x);", "48217127"),
        ("postgresql", "INSERT INTO users (id, pin) SELECT 1, x FROM unnest(ARRAY[48217128]) AS u(x);", "48217128"),
        ("mssql", "DECLARE @t TABLE (Id INT, Pin INT DEFAULT 48217134);", "48217134"),
        ("postgresql", "CREATE TABLE t2 (id int, pin int GENERATED ALWAYS AS (48217137) STORED);", "48217137"),
        ("bigquery", "INSERT INTO ds.users (id, pin) SELECT 1, p FROM UNNEST([48217143]) AS p;", "48217143"),
        // A typed literal is a string under another spelling.
        ("postgresql", "SELECT id FROM users WHERE password = DATE 'XpKZ01canary';", "XpKZ01canary"),
        ("postgresql", "SELECT id FROM users WHERE password = TIMESTAMP 'XpKZ02canary';", "XpKZ02canary"),
        ("snowflake", "SELECT id FROM users WHERE password = DATE 'XpKZ05canary';", "XpKZ05canary"),
        ("mysql", "SELECT id FROM users WHERE password = DATE 'XpKZ07canary';", "XpKZ07canary"),
        ("bigquery", "SELECT id FROM ds.users WHERE password = JSON '{\"a\":\"XpKZ09canary\"}';", "XpKZ09canary"),
        ("bigquery", "SELECT id FROM ds.users WHERE password = NUMERIC 'XpKZ10canary';", "XpKZ10canary"),
        ("bigquery", "SELECT id FROM ds.users WHERE password IN (DATE 'XpKZ15canary');", "XpKZ15canary"),
        ("bigquery", "DELETE FROM ds.users WHERE password = DATE 'XpKZ17canary';", "XpKZ17canary"),
        ("bigquery", "SELECT id FROM ds.users WHERE secret = DATETIME 'XpKZ18canary';", "XpKZ18canary"),
    ];
    let printed = printed_on_some_surface(cases);
    assert!(
        printed.is_empty(),
        "printed ({}):\n{}",
        printed.len(),
        printed.join("\n")
    );
    // A number a built-in function takes, or one written by position into
    // a column the table's statement names for no secret, is shown.
    assert_shown(&[
        (
            "postgresql",
            "SELECT round(price, 731951) FROM orders;",
            "731951",
        ),
        (
            "postgresql",
            "CREATE TABLE orders (id int, qty int);\nINSERT INTO orders VALUES (1, 731952);",
            "731952",
        ),
        ("postgresql", "SELECT 731953 AS qty;", "731953"),
        (
            "snowflake",
            "UPDATE orders SET data = OBJECT_CONSTRUCT('qty', 731954) WHERE id = 1;",
            "731954",
        ),
        ("snowflake", "SELECT [731955, 2] AS arr;", "731955"),
    ]);
    // A number passed to a routine the dialect does not build in, called
    // in `FROM` as in `SELECT`, goes where no walk follows.
    assert_masked(&[(
        "mssql",
        "SELECT * FROM dbo.zz_real r JOIN dbo.fn(731956) f ON r.id = f.id;",
        "731956",
    )]);
}

#[test]
fn the_rows_of_a_copy_from_stdin_block_reach_no_report_surface() {
    let mut cases = Vec::new();
    for name in COPY_DUMP_DIALECTS {
        for canary in COPY_DUMP_TWO_CANARIES {
            cases.push((name, COPY_DUMP_TWO, canary));
        }
        for canary in COPY_DUMP_THREE_CANARIES {
            cases.push((name, COPY_DUMP_THREE, canary));
        }
    }
    let printed = printed_on_some_surface(&cases);
    assert!(
        printed.is_empty(),
        "printed ({}):\n{}",
        printed.len(),
        printed.join("\n")
    );
    // The rows are read with their statement: no text is left unread.
    for name in ["postgresql", "snowflake", "mssql"] {
        for sql in [COPY_DUMP_TWO, COPY_DUMP_THREE] {
            let (_, skipped) = report_json_and_skipped(name, sql);
            assert_eq!(skipped, 0, "{name}: {sql}");
        }
    }
}

const COPY_DUMP_DIALECTS: [&str; 7] = [
    "postgresql",
    "snowflake",
    "redshift",
    "databricks",
    "mysql",
    "mssql",
    "bigquery",
];

/// A `pg_dump` of two tables, each block's rows holding text a SQL reader
/// would read as quotes, comments and statements.
const COPY_DUMP_TWO: &str =
    "CREATE TABLE public.users (id integer NOT NULL, email text, password_hash text);\n\
COPY public.accounts (id, name) FROM stdin;\n\
1\tO'Brien /* XpKC29canary\n\
\\.\n\
\n\
COPY public.users (id, email, password_hash) FROM stdin;\n\
1\talice@example.com\t$2b$12$XpKC30canaryHashValueAAAA\n\
2\tbob@example.com\tXpKC31canaryPlainPw'; DELETE FROM t; --\n\
\\.\n\
SELECT pg_catalog.setval('public.users_id_seq', 2, true);\n";

const COPY_DUMP_TWO_CANARIES: [&str; 4] = [
    "XpKC29canary",
    "XpKC30canary",
    "XpKC31canary",
    "alice@example.com",
];

/// Three tables' rows, one block in CSV, and psql's `\copy`.
const COPY_DUMP_THREE: &str = "COPY public.accounts (id, name) FROM stdin;\n\
1\tacme\n\
\\.\n\
\n\
COPY public.users (id, email, password_hash) FROM stdin;\n\
1\talice@example.com\tXpKC32canary\n\
\\.\n\
\n\
copy public.api_keys (id, user_id, token) from STDIN with (format csv);\n\
1,1,\"sk_live_XpKC33canary, x\"\n\
\\.\n\
\n\
\\copy public.more (id, pw) FROM stdin\n\
1\tXpKC34canary\n\
\\.\n\
SELECT 1;\n";

const COPY_DUMP_THREE_CANARIES: [&str; 3] = ["XpKC32canary", "XpKC33canary", "XpKC34canary"];

/// Asserts no case of `cases` prints its canary on any report surface.
fn assert_printed_nowhere(cases: &[(&str, &str, &str)]) {
    let printed = printed_on_some_surface(cases);
    assert!(
        printed.is_empty(),
        "printed ({}):\n{}",
        printed.len(),
        printed.join("\n")
    );
}

#[test]
fn a_column_is_met_under_every_name_each_statement_says_it_gives() {
    // Each statement states the names it gives a table or a column; one of
    // read dynamic text does through the same statement effect.
    assert_printed_nowhere(&[
        ("postgresql", "CREATE VIEW v1 AS SELECT * FROM cfg;\nCREATE VIEW v2 AS SELECT * FROM v1;\nUPDATE cfg SET value = 'x' WHERE name = 'smtp';\nSELECT name FROM v2 WHERE value = 'XpL1C11canary';", "XpL1C11canary"),
        ("postgresql", "CREATE VIEW v AS SELECT name, upper(value) AS uv FROM cfg;\nUPDATE cfg SET value = 'x';\nSELECT name FROM v WHERE uv = 'XpL1C13canary';", "XpL1C13canary"),
        ("snowflake", "UPDATE cfg SET value = 'x';\nCREATE DYNAMIC TABLE dt TARGET_LAG = '1 minute' WAREHOUSE = wh AS SELECT name, value FROM cfg;\nSELECT name FROM dt WHERE value = 'XpL1C17canary';", "XpL1C17canary"),
        ("snowflake", "CREATE STREAM st ON TABLE cfg;\nUPDATE cfg SET value = 'x';\nSELECT name FROM st WHERE value = 'XpL1C18canary';", "XpL1C18canary"),
        ("snowflake", "UPDATE cfg SET value = 'x';\nCREATE TABLE cfg2 CLONE cfg;\nSELECT name FROM cfg2 WHERE value = 'XpL1C19canary';", "XpL1C19canary"),
        ("snowflake", "UPDATE cfg SET value = 'x';\nALTER TABLE cfg SWAP WITH cfg2;\nSELECT name FROM cfg2 WHERE value = 'XpL1C20canary';", "XpL1C20canary"),
        ("mssql", "UPDATE dbo.cfg SET Value = N'x';\nEXEC sp_rename 'dbo.cfg', 'cfg2';\nSELECT Name FROM dbo.cfg2 WHERE Value = N'XpL1C22canary';", "XpL1C22canary"),
        ("mssql", "UPDATE dbo.cfg SET Value = N'x';\nEXEC sp_rename 'dbo.cfg.Value', 'Val', 'COLUMN';\nSELECT Name FROM dbo.cfg WHERE Val = N'XpL1C23canary';", "XpL1C23canary"),
        ("postgresql", "CREATE VIEW v AS SELECT name, value FROM cfg;\nALTER VIEW v RENAME COLUMN value TO val;\nUPDATE cfg SET value = 'x';\nSELECT name FROM v WHERE val = 'XpL1C26canary';", "XpL1C26canary"),
        ("snowflake", "EXECUTE IMMEDIATE 'ALTER TABLE cfg RENAME COLUMN value TO val';\nUPDATE cfg SET value = 'x';\nSELECT name FROM cfg WHERE val = 'XpL1D13canary';", "XpL1D13canary"),
        ("snowflake", "UPDATE cfg SET value = 'x';\nEXECUTE IMMEDIATE 'CREATE VIEW v AS SELECT name, value FROM cfg';\nSELECT name FROM v WHERE value = 'XpL1D14canary';", "XpL1D14canary"),
    ]);
}

#[test]
fn a_statement_whose_writes_the_run_cannot_read_writes_any_column() {
    assert_printed_nowhere(&[
        ("snowflake", "EXECUTE IMMEDIATE FROM @stage/script.sql;\nSELECT name FROM cfg WHERE value = 'XpL2D10canary';", "XpL2D10canary"),
        ("postgresql", "PREPARE p AS UPDATE cfg SET value = 'x' WHERE name = 'smtp';\nSELECT name FROM cfg WHERE value = 'XpL2PR1canary';", "XpL2PR1canary"),
        ("snowflake", "CREATE PROCEDURE p() RETURNS STRING LANGUAGE JAVASCRIPT AS $$ snowflake.execute({sqlText: \"UPDATE cfg SET value = 'x'\"}); return 'ok'; $$;\nCALL p();\nSELECT name FROM cfg WHERE value = 'XpL2D17canary';", "XpL2D17canary"),
        ("mssql", "EXEC dbo.AnyProc;\nSELECT Name FROM dbo.cfg WHERE Value = N'XpL2E01canary';", "XpL2E01canary"),
        ("postgresql", "SELECT set_user_pin(42);\nSELECT name FROM cfg WHERE value = 'XpL2F01canary';", "XpL2F01canary"),
        ("snowflake", "CREATE TASK t WAREHOUSE = wh AS UPDATE cfg SET value = 'x';\nSELECT name FROM cfg WHERE value = 'XpL2T01canary';", "XpL2T01canary"),
        ("snowflake", "ALTER TASK t MODIFY AS UPDATE cfg SET value = 'x';\nSELECT name FROM cfg WHERE value = 'XpL2T02canary';", "XpL2T02canary"),
        ("snowflake", "ALTER TASK t MODIFY AS UPDATE cfg SET value = WHERE;\nSELECT name FROM cfg WHERE value = 'XpL2T03canary';", "XpL2T03canary"),
    ]);
    // A routine the dialect documents writes what it documents; a write
    // the run reads to another table keeps the comparison shown.
    assert_quoted(&[
        ("mssql", "EXEC sp_configure 'show advanced options', 1;\nSELECT Name FROM dbo.cfg WHERE Value = N'XwKeepL2a';", "XwKeepL2a"),
        ("snowflake", "EXECUTE IMMEDIATE 'UPDATE other SET value = ''x''';\nSELECT name FROM cfg WHERE value = 'XwKeepL2b';", "XwKeepL2b"),
        ("snowflake", "ALTER TASK t RESUME;\nALTER TASK t SET SCHEDULE = '5 MINUTE';\nSELECT name FROM cfg WHERE value = 'XwKeepL2c';", "XwKeepL2c"),
    ]);
}

#[test]
fn a_number_prints_only_where_its_destination_is_known() {
    assert_printed_nowhere(&[
        ("postgresql", "MERGE INTO users u USING (VALUES (1, 48217106)) AS s(id, p) ON u.id = s.id WHEN MATCHED THEN UPDATE SET pin = s.p;", "48217106"),
        ("mssql", "MERGE dbo.Users AS u USING (VALUES (1, 48217107)) AS s(Id, P) ON u.Id = s.Id WHEN MATCHED THEN UPDATE SET Pin = s.P;", "48217107"),
        ("postgresql", "INSERT INTO users SELECT * FROM (VALUES (1, 'b', 48217110)) v;", "48217110"),
        ("postgresql", "CREATE TABLE users (id int, name text);\nINSERT INTO users VALUES (1, 'bob', 48217601);", "48217601"),
        ("mysql", "UPDATE users SET data = JSON_SET(data, '$.pin', 48217125) WHERE id = 1;", "48217125"),
        ("mysql", "UPDATE users SET data = JSON_REPLACE(data, '$.pin', 48217126) WHERE id = 1;", "48217126"),
        ("postgresql", "UPDATE users SET data = jsonb_set(data, '{pin}', to_jsonb(48217703)) WHERE id = 1;", "48217703"),
        ("postgresql", "SELECT * FROM set_user_pin(42, 48217145);", "48217145"),
        ("postgresql", "SELECT set_user_pin(42, 48217009);", "48217009"),
        ("postgresql", "SELECT set_user_pin(p_user => 42, p_pin => 48217010);", "48217010"),
        ("postgresql", "CREATE FUNCTION set_user_pin(u int, p int) RETURNS void LANGUAGE sql AS $$ UPDATE users SET pin = p WHERE id = u $$;\nSELECT set_user_pin(42, 48217008);", "48217008"),
        ("mssql", "SELECT * FROM dbo.SetPin(42, 48217146);", "48217146"),
        ("mssql", "ALTER TABLE dbo.Users ADD DEFAULT 48217301 FOR Pin;", "48217301"),
        ("mssql", "ALTER TABLE dbo.Users ADD DEFAULT 1 FOR Flag, CONSTRAINT DF_y DEFAULT 48217303 FOR Pin;", "48217303"),
        ("mssql", "CREATE TABLE dbo.T3 (Id int, Pin int IDENTITY(48217147, 1));", "48217147"),
        ("postgresql", "SELECT OBJECT_CONSTRUCT('pin', 48217503) AS o;", "48217503"),
        ("mysql", "SELECT OBJECT_CONSTRUCT('pin', 48217504) AS o;", "48217504"),
    ]);
    // A destination known and named for no secret shows the number.
    assert_quoted(&[
        (
            "postgresql",
            "SELECT id FROM orders WHERE total < 100 LIMIT 10;",
            "total < 100 LIMIT 10",
        ),
        (
            "postgresql",
            "SELECT abs(-5), round(3.14159, 2) FROM orders;",
            "round(3.14159, 2)",
        ),
        (
            "snowflake",
            "SELECT * FROM TABLE(GENERATOR(ROWCOUNT => 1000));",
            "1000",
        ),
        (
            "postgresql",
            "SELECT * FROM generate_series(1, 731990) g;",
            "731990",
        ),
        (
            "postgresql",
            "SELECT CAST(x AS NUMERIC(10,2)) FROM t;",
            "NUMERIC(10,2)",
        ),
        (
            "postgresql",
            "CREATE TABLE t (id NUMERIC(38,0), name VARCHAR(255));",
            "VARCHAR(255)",
        ),
        (
            "snowflake",
            "ALTER DATABASE prod SET DATA_RETENTION_TIME_IN_DAYS = 0;",
            "DATA_RETENTION_TIME_IN_DAYS = 0",
        ),
    ]);
}

#[test]
fn a_bare_name_meets_each_table_the_stated_path_may_place_it_in() {
    assert_printed_nowhere(&[
        ("postgresql", "SET search_path = other, app;\nUPDATE cfg SET value = 'x' WHERE name = 'smtp';\nSELECT name FROM app.cfg WHERE value = 'XpL5S20canary';", "XpL5S20canary"),
        ("postgresql", "SET search_path = other, app;\nUPDATE app.cfg SET value = 'x';\nSELECT name FROM cfg WHERE value = 'XpL5S31canary';", "XpL5S31canary"),
        ("postgresql", "SET search_path TO \"$user\", public;\nUPDATE app.cfg SET value = 'x';\nSELECT name FROM cfg WHERE value = 'XpL5S21canary';", "XpL5S21canary"),
        ("redshift", "SET search_path TO '$user', public;\nUPDATE app.cfg SET value = 'x';\nSELECT name FROM cfg WHERE value = 'XpL5S27canary';", "XpL5S27canary"),
    ]);
    // One stated schema places the name there alone.
    assert_quoted(&[(
        "postgresql",
        "UPDATE app.cfg SET value = 'x' WHERE name = 'smtp';\nSET search_path = other;\nSELECT name FROM cfg WHERE value = 'XwKeepL5';",
        "XwKeepL5",
    )]);
}

#[test]
fn a_string_passed_through_a_function_whose_arguments_no_catalog_states_is_masked() {
    // `TO_NUMBER` is one of Snowflake's functions by name alone: what it
    // does with each argument is not stated, so nothing passed through it
    // is proven safe, though a function it holds states its own.
    assert_printed_nowhere(&[
        ("snowflake", "SELECT a FROM t WHERE t.d = TO_NUMBER(TO_CHAR(DATE_TRUNC('XpL6M1canary', CURRENT_DATE)::DATE,'XpL6M2canary'),'99999999');", "XpL6M1canary"),
        ("snowflake", "SELECT a FROM t WHERE t.d = TO_NUMBER(TO_CHAR(DATE_TRUNC('XpL6M1canary', CURRENT_DATE)::DATE,'XpL6M2canary'),'99999999');", "XpL6M2canary"),
        ("postgresql", "CREATE FUNCTION f(s text) RETURNS int LANGUAGE sql AS $$ SELECT 1 $$;\nSELECT a FROM t WHERE t.d = f('XpL6M3canary');", "XpL6M3canary"),
    ]);
    // A function whose arguments the catalog states shows them.
    assert_quoted(&[(
        "snowflake",
        "SELECT a FROM t WHERE t.d = TO_CHAR(DATE_TRUNC('month', CURRENT_DATE)::DATE,'YYYYMMDD');",
        "'YYYYMMDD'",
    )]);
}

#[test]
fn the_statements_a_value_holds_write_what_they_write() {
    // `LET`, `DECLARE`, an assignment and `RETURN` run the statements their
    // values hold; built text writes any column.
    assert_printed_nowhere(&[
        ("snowflake", "BEGIN\n  LET rs RESULTSET := (EXECUTE IMMEDIATE :q);\nEND;\nCREATE OR REPLACE TABLE t2 AS SELECT * FROM cfg WHERE value = 'XpM1C1canary';", "XpM1C1canary"),
        ("snowflake", "BEGIN\n  LET rs RESULTSET := (EXECUTE IMMEDIATE 'UPDATE cfg SET value = ''x''');\nEND;\nSELECT name FROM cfg WHERE value = 'XpM1C2canary';", "XpM1C2canary"),
        ("snowflake", "DECLARE\n  res RESULTSET DEFAULT (EXECUTE IMMEDIATE 'UPDATE cfg SET value = ''x''');\nBEGIN\n  RETURN TABLE(res);\nEND;\nSELECT name FROM cfg WHERE value = 'XpM1C3canary';", "XpM1C3canary"),
        ("snowflake", "BEGIN\n  rs := (EXECUTE IMMEDIATE :q);\nEND;\nSELECT name FROM cfg WHERE value = 'XpM1C4canary';", "XpM1C4canary"),
        ("snowflake", "BEGIN\n  RETURN TABLE(EXECUTE IMMEDIATE :q);\nEND;\nSELECT name FROM cfg WHERE value = 'XpM1C5canary';", "XpM1C5canary"),
        ("snowflake", "BEGIN\n  v[0] := (EXECUTE IMMEDIATE :q);\nEND;\nSELECT name FROM cfg WHERE value = 'XpM1C6canary';", "XpM1C6canary"),
    ]);
    // A held query writing nothing, or writing another table, keeps the
    // comparison shown.
    assert_quoted(&[
        ("snowflake", "BEGIN\n  LET n INTEGER := (SELECT COUNT(*) FROM other);\nEND;\nSELECT name FROM cfg WHERE value = 'XwKeepM1a';", "XwKeepM1a"),
        ("snowflake", "BEGIN\n  LET rs RESULTSET := (EXECUTE IMMEDIATE 'UPDATE other SET value = ''x''');\nEND;\nSELECT name FROM cfg WHERE value = 'XwKeepM1b';", "XwKeepM1b"),
    ]);
}

#[test]
fn a_json_path_naming_a_credential_at_any_key_masks_its_value() {
    // Each setter of each dialect that has it, the credential key followed
    // by an index or another key; a path not written as text.
    assert_printed_nowhere(&[
        (
            "mysql",
            "UPDATE users SET data = JSON_SET(data, '$.pin[0]', 48219801);",
            "48219801",
        ),
        (
            "mysql",
            "UPDATE users SET data = JSON_SET(data, '$.pins[1]', 48219802);",
            "48219802",
        ),
        (
            "mysql",
            "UPDATE users SET data = JSON_INSERT(data, '$.pin.code', 48219803);",
            "48219803",
        ),
        (
            "mysql",
            "UPDATE users SET data = JSON_REPLACE(data, '$.pin[0]', 48219804);",
            "48219804",
        ),
        (
            "mysql",
            "UPDATE users SET data = JSON_ARRAY_APPEND(data, '$.pins', 48219805);",
            "48219805",
        ),
        (
            "mysql",
            "UPDATE users SET data = JSON_ARRAY_INSERT(data, '$.pins[0]', 48219806);",
            "48219806",
        ),
        (
            "mysql",
            "UPDATE users SET data = JSON_SET(data, @path, 48219807);",
            "48219807",
        ),
        (
            "bigquery",
            "UPDATE ds.users SET data = JSON_SET(data, '$.pin[0]', 48219811) WHERE TRUE;",
            "48219811",
        ),
        (
            "bigquery",
            "UPDATE ds.users SET data = JSON_ARRAY_APPEND(data, '$.pins', 48219812) WHERE TRUE;",
            "48219812",
        ),
        (
            "bigquery",
            "UPDATE ds.users SET data = JSON_ARRAY_INSERT(data, '$.pin[0]', 48219813) WHERE TRUE;",
            "48219813",
        ),
        (
            "postgresql",
            "UPDATE users SET data = jsonb_set(data, '{pin,0}', to_jsonb(48219821));",
            "48219821",
        ),
        (
            "postgresql",
            "UPDATE users SET data = jsonb_set_lax(data, '{pins,1}', to_jsonb(48219822));",
            "48219822",
        ),
        (
            "postgresql",
            "UPDATE users SET data = jsonb_insert(data, '{pin,0}', to_jsonb(48219823));",
            "48219823",
        ),
        (
            "mssql",
            "UPDATE dbo.Users SET Data = JSON_MODIFY(Data, '$.pin[0]', 48219831);",
            "48219831",
        ),
    ]);
    // A path naming no credential at any key shows the number.
    assert_quoted(&[(
        "mysql",
        "UPDATE users SET data = JSON_SET(data, '$.qty[0]', 48219841);",
        "48219841",
    )]);
}

#[test]
fn a_call_of_a_function_the_dialect_says_may_write_writes_any_column() {
    // MySQL's user functions may write rows: a call of one the run does not
    // define, however its value is used, writes any column.
    assert_printed_nowhere(&[
        (
            "mysql",
            "SELECT set_cfg('smtp');\nSELECT name FROM cfg WHERE value = 'XpM3A10canary';",
            "XpM3A10canary",
        ),
        (
            "mysql",
            "SET @x = set_cfg('smtp');\nSELECT name FROM cfg WHERE value = 'XpM3A11canary';",
            "XpM3A11canary",
        ),
    ]);
    // A dialect whose user functions write nothing, and a built-in, keep the
    // comparison shown.
    assert_quoted(&[
        (
            "snowflake",
            "SELECT my_udf(1);\nSELECT name FROM cfg WHERE value = 'XwKeepM3a';",
            "XwKeepM3a",
        ),
        (
            "mysql",
            "SELECT upper('a');\nSELECT name FROM cfg WHERE value = 'XwKeepM3b';",
            "XwKeepM3b",
        ),
    ]);
}

#[test]
fn a_pipe_a_subscription_or_an_event_body_not_read_writes_what_it_may_load() {
    assert_printed_nowhere(&[
        ("snowflake", "CREATE PIPE p AUTO_INGEST = TRUE AS COPY INTO cfg FROM @stage;\nSELECT name FROM cfg WHERE value = 'XpM4A50canary';", "XpM4A50canary"),
        ("snowflake", "ALTER PIPE p REFRESH;\nSELECT name FROM cfg WHERE value = 'XpM4D48canary';", "XpM4D48canary"),
        ("postgresql", "CREATE SUBSCRIPTION s CONNECTION 'host=h dbname=d' PUBLICATION pub;\nSELECT name FROM cfg WHERE value = 'XpM4D49canary';", "XpM4D49canary"),
        ("mysql", "ALTER EVENT e DO UPDATE cfg SET value = WHERE;\nSELECT name FROM cfg WHERE value = 'XpM4E01canary';", "XpM4E01canary"),
    ]);
    // A pipe the run defines loads, on refresh too, what its COPY loads; an
    // event's state runs nothing.
    assert_quoted(&[
        ("snowflake", "CREATE PIPE p AS COPY INTO other FROM @stage;\nALTER PIPE p REFRESH;\nSELECT name FROM cfg WHERE value = 'XwKeepM4a';", "XwKeepM4a"),
        ("mysql", "ALTER EVENT e ENABLE;\nSELECT name FROM cfg WHERE value = 'XwKeepM4b';", "XwKeepM4b"),
    ]);
}

#[test]
fn a_name_link_the_plan_does_not_state_links_any_name() {
    assert_printed_nowhere(&[
        ("mssql", "ALTER VIEW dbo.v AS SELECT Name, Value FROM dbo.cfg;\nGO\nUPDATE dbo.cfg SET Value = N'x';\nSELECT Name FROM dbo.v WHERE Value = N'XpM5D01canary';", "XpM5D01canary"),
        ("mysql", "ALTER VIEW v AS SELECT name, value FROM cfg;\nUPDATE cfg SET value = 'x';\nSELECT name FROM v WHERE value = 'XpM5D02canary';", "XpM5D02canary"),
        ("databricks", "ALTER VIEW v AS SELECT name, value FROM cfg;\nUPDATE cfg SET value = 'x';\nSELECT name FROM v WHERE value = 'XpM5D03canary';", "XpM5D03canary"),
        ("mssql", "UPDATE dbo.cfg SET Value = N'x';\nALTER SCHEMA other TRANSFER dbo.cfg;\nSELECT Name FROM other.cfg WHERE Value = N'XpM5A14canary';", "XpM5A14canary"),
        ("mssql", "UPDATE dbo.cfg SET Value = N'x';\nALTER TABLE dbo.cfg SWITCH TO dbo.cfg2;\nSELECT Name FROM dbo.cfg2 WHERE Value = N'XpM5A41canary';", "XpM5A41canary"),
        ("redshift", "UPDATE cfg SET value = 'x';\nALTER TABLE cfg2 APPEND FROM cfg;\nSELECT name FROM cfg2 WHERE value = 'XpM5A35canary';", "XpM5A35canary"),
        ("mysql", "UPDATE cfg SET value = 'x';\nALTER TABLE cfg EXCHANGE PARTITION p0 WITH TABLE cfg2;\nSELECT name FROM cfg2 WHERE value = 'XpM5D08canary';", "XpM5D08canary"),
        ("postgresql", "UPDATE cfg SET value = 'x';\nCREATE TABLE cfg_part PARTITION OF cfg FOR VALUES IN ('a');\nSELECT name FROM cfg_part WHERE value = 'XpM5A22canary';", "XpM5A22canary"),
        ("postgresql", "CREATE TABLE child () INHERITS (cfg);\nUPDATE cfg SET value = 'x';\nSELECT name FROM child WHERE value = 'XpM5A23canary';", "XpM5A23canary"),
        ("postgresql", "UPDATE cfg SET value = 'x';\nPREPARE p AS SELECT * FROM cfg;\nCREATE TABLE cfg2 AS EXECUTE p;\nSELECT name FROM cfg2 WHERE value = 'XpM5D07canary';", "XpM5D07canary"),
        ("bigquery", "UPDATE ds.cfg SET value = 'x' WHERE TRUE;\nCREATE SNAPSHOT TABLE ds.snap CLONE ds.cfg;\nSELECT name FROM ds.snap WHERE value = 'XpM5A33canary';", "XpM5A33canary"),
        ("bigquery", "UPDATE ds.cfg SET value = 'x' WHERE TRUE;\nCREATE TABLE ds.cfg2 COPY ds.cfg;\nSELECT name FROM ds.cfg2 WHERE value = 'XpM5A34canary';", "XpM5A34canary"),
        ("mssql", "UPDATE dbo.cfg SET Value = N'x';\nINSERT INTO dbo.cfg2 EXEC('SELECT Name, Value FROM dbo.cfg');\nSELECT Name FROM dbo.cfg2 WHERE Value = N'XpM5D09canary';", "XpM5D09canary"),
        ("postgresql", "CREATE TABLE cfg (name text, value text, v2 text GENERATED ALWAYS AS (upper(value)) STORED);\nUPDATE cfg SET value = 'x';\nSELECT name FROM cfg WHERE v2 = 'XPM5D10CANARY';", "XpM5D10canary"),
        ("mssql", "CREATE TABLE dbo.cfg (Name nvarchar(50), Value nvarchar(50), V2 AS (Value));\nUPDATE dbo.cfg SET Value = N'x';\nSELECT Name FROM dbo.cfg WHERE V2 = N'XpM5D11canary';", "XpM5D11canary"),
        ("snowflake", "CREATE TABLE cfg (name STRING, value STRING, v2 STRING AS (value));\nUPDATE cfg SET value = 'x';\nSELECT name FROM cfg WHERE v2 = 'XpM5D12canary';", "XpM5D12canary"),
        ("mysql", "CREATE TABLE cfg (name TEXT, value TEXT, v2 TEXT AS (value) VIRTUAL);\nUPDATE cfg SET value = 'x';\nSELECT name FROM cfg WHERE v2 = 'XpM5D13canary';", "XpM5D13canary"),
        ("postgresql", "UPDATE cfg SET value = 'x';\nALTER TABLE cfg ADD COLUMN v2 text GENERATED ALWAYS AS (upper(value)) STORED;\nSELECT name FROM cfg WHERE v2 = 'XPM5D14CANARY';", "XpM5D14canary"),
        ("snowflake", "UPDATE cfg SET value = 'x';\nCREATE VIEW v AS SELECT * FROM cfg UNPIVOT (val FOR col IN (value));\nSELECT name FROM v WHERE val = 'XpM5D55canary';", "XpM5D55canary"),
        ("snowflake", "CREATE TABLE cfg (name STRING, value STRING);\nUPDATE cfg SET value = 'x';\nCREATE VIEW v AS SELECT name, val FROM cfg UNPIVOT (val FOR col IN (value));\nSELECT name FROM v WHERE val = 'XpM5D56canary';", "XpM5D56canary"),
        ("snowflake", "UPDATE s.cfg SET value = 'x';\nALTER SCHEMA s RENAME TO t;\nSELECT name FROM t.cfg WHERE value = 'XpM5S01canary';", "XpM5S01canary"),
        ("snowflake", "UPDATE s.cfg SET value = 'x';\nALTER SCHEMA s SWAP WITH t;\nSELECT name FROM t.cfg WHERE value = 'XpM5S02canary';", "XpM5S02canary"),
        ("snowflake", "UPDATE db1.s.cfg SET value = 'x';\nALTER DATABASE db1 RENAME TO db2;\nSELECT name FROM db2.s.cfg WHERE value = 'XpM5S03canary';", "XpM5S03canary"),
        ("snowflake", "UPDATE cfg SET value = 'x';\nALTER DYNAMIC TABLE dt SWAP WITH cfg;\nSELECT name FROM dt WHERE value = 'XpM5S04canary';", "XpM5S04canary"),
        ("snowflake", "CREATE VIEW v AS SELECT name, value FROM cfg;\nALTER VIEW v RENAME TO w;\nUPDATE cfg SET value = 'x';\nSELECT name FROM w WHERE value = 'XpM5S05canary';", "XpM5S05canary"),
        ("databricks", "CACHE TABLE c AS SELECT * FROM cfg;\nUPDATE cfg SET value = 'x';\nSELECT name FROM c WHERE value = 'XpM5S06canary';", "XpM5S06canary"),
    ]);
    // An action that links no name, a table made only like another, and a
    // view over an `UNPIVOT` of a table not written keep the comparison of
    // a column not written shown.
    assert_quoted(&[
        ("snowflake", "UPDATE cfg SET value = 'x';\nALTER TABLE other SET COMMENT = 'c';\nSELECT name FROM other WHERE value = 'XwKeepM5a';", "XwKeepM5a"),
        ("postgresql", "UPDATE cfg SET value = 'x';\nCREATE TABLE other (LIKE cfg);\nSELECT name FROM other WHERE value = 'XwKeepM5b';", "XwKeepM5b"),
        ("snowflake", "CREATE TABLE other (k STRING, a STRING);\nUPDATE cfg SET value = 'x';\nCREATE VIEW v AS SELECT k, w FROM other UNPIVOT (w FOR col IN (a));\nSELECT k FROM v WHERE w = 'XwKeepM5c';", "XwKeepM5c"),
    ]);
}

// A declared type's length, precision and scale are no value: a routine's
// parameters and what it returns, a variable's, a column's changed type.
#[test]
fn the_length_of_a_declared_type_is_shown() {
    let cases: &[(&str, &str, &[&str])] = &[
        (
            "mssql",
            "CREATE PROCEDURE dbo.find_user @name NVARCHAR(200) AS BEGIN SELECT 1 END;",
            &["NVARCHAR(200)"],
        ),
        (
            "mssql",
            "CREATE FUNCTION dbo.f(@a NVARCHAR(50)) RETURNS DECIMAL(10,2) AS BEGIN RETURN 1 END;",
            &["NVARCHAR(50)", "DECIMAL(10,2)"],
        ),
        (
            "mssql",
            "DECLARE @x NVARCHAR(120);\nDROP TABLE t;",
            &["NVARCHAR(120)"],
        ),
        (
            "snowflake",
            "CREATE PROCEDURE p(a VARCHAR(100)) RETURNS VARCHAR(20) LANGUAGE SQL AS $$ BEGIN RETURN 'x'; END $$;",
            &["VARCHAR(100)", "VARCHAR(20)"],
        ),
        (
            "postgresql",
            "ALTER TABLE t ALTER COLUMN a TYPE varchar(300);",
            &["varchar(300)"],
        ),
    ];
    for (dialect, sql, shown) in cases {
        let out = reported_with_catalog_in(dialect, sql);
        for part in *shown {
            assert!(
                out.contains(part),
                "{dialect}: {part} is masked in {sql}\n{out}"
            );
        }
    }
    // The value a variable is given stays masked beside its type.
    let out = reported_with_catalog_in(
        "mssql",
        "DECLARE @pin DECIMAL(8,0) = 482913;\nDROP TABLE t;",
    );
    assert!(!out.contains("482913"), "{out}");
    assert!(out.contains("DECIMAL(8,0)"), "{out}");
}
