// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! The built-in credential rules read the `credential_dummies` and
//! `credential_references` lists, and a custom rule file extends or
//! replaces them.

use lexega_core::analyzer::{AnalysisConfig, RuleMatch};
use lexega_core::api::analyze_risk_with_policy_config;
use lexega_core::dialect::{self, DialectRef};
use lexega_core::rules::{build_v1_rule_corpus, load_v1_rules};

const BQ_LEAK: &str = "BQ-EXPORT-PWD-LEAK";
const DUMMY: &str = "CRED-DUMMY-VALUE";
const PWD_LEAK: &str = "CRED-PWD-LEAK";
const LINKED_LEAK: &str = "MSSQL-LINKEDSRV-LOGIN-CRED";
const APIKEY_LEAK: &str = "CRED-APIKEY-LEAK";
const AWS_LEAK: &str = "CRED-AWS-LEAK";
const KEY_OPEN_LEAK: &str = "MSSQL-KEY-OPEN-INLINE-PASSWORD";
const KEY_BACKUP_LEAK: &str = "MSSQL-KEY-BACKUP-INLINE-PASSWORD";
const SIGNATURE_LEAK: &str = "MSSQL-SIGNATURE-INLINE-PASSWORD";
const SERVICE_MASTER_KEY_LEAK: &str = "MSSQL-SERVICE-MASTER-KEY-INLINE-PASSWORD";

fn rule_ids(sql: &str, dialect: DialectRef, lists_yaml: Option<&str>) -> Vec<String> {
    let custom_rules = lists_yaml.map(|yaml| {
        let loaded = load_v1_rules(yaml).expect("rule file loads");
        build_v1_rule_corpus(loaded, true)
            .expect("corpus merges")
            .into()
    });
    let cfg = AnalysisConfig {
        dialect: Some(dialect),
        custom_rules,
        ..Default::default()
    };
    analyze_risk_with_policy_config(sql, &cfg)
        .expect("analyzes")
        .entries()
        .map(|RuleMatch::Analysis(a)| a.matched_rule.clone())
        .collect()
}

fn bq_export(password: &str) -> String {
    format!("EXPORT DATA OPTIONS(uri='gs://b/*', format='CSV', password='{password}') AS SELECT 1")
}

fn linked_login(password: &str) -> String {
    format!(
        "EXEC sp_addlinkedsrvlogin @rmtsrvname='s', @useself='False', @rmtuser='u', \
         @rmtpassword='{password}'"
    )
}

fn has(ids: &[String], rule: &str) -> bool {
    ids.iter().any(|id| id == rule)
}

#[test]
fn shipped_references_are_silent() {
    for reference in [
        "vault:kv/db#pw",
        "arn:aws:secretsmanager:us-east-1:1:secret:x",
    ] {
        let ids = rule_ids(&bq_export(reference), dialect::bigquery(), None);
        assert!(!has(&ids, BQ_LEAK), "{reference}: {ids:?}");
    }
    let sql = "CREATE STORAGE CREDENTIAL c AZURE_SERVICE_PRINCIPAL 't', 'a', 'vault:kv/sp'";
    let ids = rule_ids(sql, dialect::databricks(), None);
    assert!(!has(&ids, PWD_LEAK), "{ids:?}");
}

#[test]
fn extension_pattern_silences_and_real_value_fires() {
    let yaml = "lists:\n  credential_references:\n    extend: {patterns: [\"*secrets*\"]}\n";
    let ids = rule_ids(&linked_login("mysecrets_pw"), dialect::mssql(), Some(yaml));
    assert!(!has(&ids, LINKED_LEAK), "{ids:?}");
    let ids = rule_ids(&linked_login("S3cret!x"), dialect::mssql(), Some(yaml));
    assert!(has(&ids, LINKED_LEAK), "{ids:?}");
}

#[test]
fn extension_value_in_another_case() {
    let yaml = "lists:\n  credential_references:\n    extend: {values: [From_Pipeline]}\n";
    let sql = bq_export("FROM_PIPELINE");
    let ids = rule_ids(&sql, dialect::bigquery(), None);
    assert!(has(&ids, BQ_LEAK), "{ids:?}");
    let ids = rule_ids(&sql, dialect::bigquery(), Some(yaml));
    assert!(!has(&ids, BQ_LEAK), "{ids:?}");
}

#[test]
fn dummy_moves_to_dummy_rule() {
    let ids = rule_ids(&bq_export("REPLACE_ME"), dialect::bigquery(), None);
    assert!(has(&ids, DUMMY), "{ids:?}");
    assert!(!has(&ids, BQ_LEAK), "{ids:?}");
}

#[test]
fn reference_fires_neither() {
    let ids = rule_ids(&bq_export("vault:kv/x"), dialect::bigquery(), None);
    assert!(!has(&ids, DUMMY), "{ids:?}");
    assert!(!has(&ids, BQ_LEAK), "{ids:?}");
}

#[test]
fn replace_removing_template_shape_makes_it_fire() {
    let yaml = "lists:\n  credential_references:\n    replace: {patterns: [\"vault:*\"]}\n";
    let sql = bq_export("$(DB_PW)");
    let ids = rule_ids(&sql, dialect::bigquery(), None);
    assert!(!has(&ids, BQ_LEAK), "{ids:?}");
    let ids = rule_ids(&sql, dialect::bigquery(), Some(yaml));
    assert!(has(&ids, BQ_LEAK), "{ids:?}");
}

#[test]
fn integration_secret_upper_cased_value_matches_lower_case_pattern() {
    let yaml = "lists:\n  credential_references:\n    extend: {patterns: [\"team-ref:*\"]}\n";
    let sql = "CREATE SECURITY INTEGRATION i TYPE = OAUTH OAUTH_CLIENT = CUSTOM \
               OAUTH_CLIENT_SECRET = 'team-ref:oauth'";
    let ids = rule_ids(sql, dialect::snowflake(), None);
    assert!(has(&ids, APIKEY_LEAK), "{ids:?}");
    let ids = rule_ids(sql, dialect::snowflake(), Some(yaml));
    assert!(!has(&ids, APIKEY_LEAK), "{ids:?}");
    assert!(!has(&ids, PWD_LEAK), "{ids:?}");
}

#[test]
fn storage_credential_dummy_fires_dummy_rule_only() {
    for (secret, leak) in [
        ("AZURE_SERVICE_PRINCIPAL 't', 'a', 'REPLACE_ME'", PWD_LEAK),
        ("CLOUDFLARE_API_TOKEN 'acct', 'ak', 'REPLACE_ME'", PWD_LEAK),
        (
            "CLOUDFLARE_API_TOKEN 'acct', 'REPLACE_ME', 'sec'",
            APIKEY_LEAK,
        ),
    ] {
        let sql = format!("CREATE STORAGE CREDENTIAL c {secret}");
        let ids = rule_ids(&sql, dialect::databricks(), None);
        assert!(has(&ids, DUMMY), "{secret}: {ids:?}");
        assert!(!has(&ids, leak), "{secret}: {ids:?}");
    }
}

#[test]
fn linked_server_dummy_fires_dummy_rule_only() {
    let ids = rule_ids(&linked_login("REPLACE_ME"), dialect::mssql(), None);
    assert!(has(&ids, DUMMY), "{ids:?}");
    assert!(!has(&ids, LINKED_LEAK), "{ids:?}");
}

#[test]
fn password_literals_are_decoded() {
    let rule = |id: &str, value: &str| {
        format!(
            "  - id: {id}\n    risk_level: info\n    message: \"{id}\"\n    triggers:\n      \
             mssql_key_management.password_literals: {{exists: {{value: \"{value}\"}}}}\n"
        )
    };
    let two = "  - id: ZZ-PW-TWO\n    risk_level: info\n    message: \"ZZ-PW-TWO\"\n    \
               triggers:\n      mssql_key_management.password_literals: {count: {eq: 2}}\n";
    let yaml = format!(
        "rules:\n{}{}{}{two}",
        rule("ZZ-PW-DECODED", "a'b"),
        rule("ZZ-PW-SECOND", "c"),
        rule("ZZ-PW-AS-WRITTEN", "a''b")
    );
    let sql = "OPEN SYMMETRIC KEY k DECRYPTION BY PASSWORD = N'a''b', PASSWORD = 'c'";
    let ids = rule_ids(sql, dialect::mssql(), Some(&yaml));
    assert!(has(&ids, "ZZ-PW-DECODED"), "{ids:?}");
    assert!(has(&ids, "ZZ-PW-SECOND"), "{ids:?}");
    assert!(!has(&ids, "ZZ-PW-AS-WRITTEN"), "{ids:?}");
    assert!(has(&ids, "ZZ-PW-TWO"), "{ids:?}");
    // The count rule is exact: one password is not two.
    let one = "OPEN SYMMETRIC KEY k DECRYPTION BY PASSWORD = 'c'";
    let ids = rule_ids(one, dialect::mssql(), Some(&yaml));
    assert!(has(&ids, "ZZ-PW-SECOND"), "{ids:?}");
    assert!(!has(&ids, "ZZ-PW-TWO"), "{ids:?}");
}

#[test]
fn tsql_dummy_moves_to_dummy_rule() {
    let sql = "OPEN SYMMETRIC KEY k DECRYPTION BY PASSWORD = 'CHANGEME'";
    let ids = rule_ids(sql, dialect::mssql(), None);
    assert!(has(&ids, DUMMY), "{ids:?}");
    assert!(!has(&ids, KEY_OPEN_LEAK), "{ids:?}");
}

#[test]
fn tsql_reference_fires_neither() {
    let sql = "OPEN SYMMETRIC KEY k DECRYPTION BY PASSWORD = '{{ secrets.pw }}'";
    let ids = rule_ids(sql, dialect::mssql(), None);
    assert!(!has(&ids, DUMMY), "{ids:?}");
    assert!(!has(&ids, KEY_OPEN_LEAK), "{ids:?}");
}

#[test]
fn tsql_dummy_and_real_fires_leak() {
    let sql = "OPEN SYMMETRIC KEY k DECRYPTION BY PASSWORD = 'CHANGEME', PASSWORD = 'Qw7!rT2z'";
    let ids = rule_ids(sql, dialect::mssql(), None);
    assert!(has(&ids, KEY_OPEN_LEAK), "{ids:?}");
}

#[test]
fn tsql_families_are_silenced_by_an_extension() {
    let yaml = "lists:\n  credential_references:\n    extend: {patterns: [\"team-ref:*\"]}\n";
    for (sql, leak) in [
        (
            "BACKUP SERVICE MASTER KEY TO FILE = 'f' ENCRYPTION BY PASSWORD = '{}'",
            KEY_BACKUP_LEAK,
        ),
        (
            "ADD SIGNATURE TO OBJECT::dbo.p BY CERTIFICATE c WITH PASSWORD = '{}'",
            SIGNATURE_LEAK,
        ),
        (
            "ALTER SERVICE MASTER KEY WITH NEW_PASSWORD = '{}'",
            SERVICE_MASTER_KEY_LEAK,
        ),
    ] {
        let real = sql.replace("{}", "Qw7!rT2z");
        let ids = rule_ids(&real, dialect::mssql(), Some(yaml));
        assert!(has(&ids, leak), "{real}: {ids:?}");
        let referenced = sql.replace("{}", "team-ref:pw");
        let ids = rule_ids(&referenced, dialect::mssql(), None);
        assert!(has(&ids, leak), "{referenced}: {ids:?}");
        let ids = rule_ids(&referenced, dialect::mssql(), Some(yaml));
        assert!(!has(&ids, leak), "{referenced}: {ids:?}");
        assert!(!has(&ids, DUMMY), "{referenced}: {ids:?}");
        let dummy = sql.replace("{}", "CHANGEME");
        let ids = rule_ids(&dummy, dialect::mssql(), None);
        assert!(has(&ids, DUMMY), "{dummy}: {ids:?}");
        assert!(!has(&ids, leak), "{dummy}: {ids:?}");
    }
}

#[test]
fn deploy_variable_credential_is_no_literal() {
    // With `${*}` gone from the references, only the placeholder the
    // substitution records keeps the value from being read as written.
    let yaml = "lists:\n  credential_references:\n    replace: {patterns: [\"vault:*\"]}\n";
    for (sql, dialect, leak) in [
        (bq_export("{}"), dialect::bigquery(), BQ_LEAK),
        (
            "CREATE MASTER KEY ENCRYPTION BY PASSWORD = '{}'".to_string(),
            dialect::mssql(),
            PWD_LEAK,
        ),
        (
            "CREATE CREDENTIAL c WITH IDENTITY = 'u', SECRET = '{}'".to_string(),
            dialect::mssql(),
            PWD_LEAK,
        ),
        (
            "CREATE STORAGE CREDENTIAL c AZURE_SERVICE_PRINCIPAL 't', 'a', '{}'".to_string(),
            dialect::databricks(),
            PWD_LEAK,
        ),
        (
            "CREATE STORAGE CREDENTIAL c CLOUDFLARE_API_TOKEN 'acct', '{}', '${S}'".to_string(),
            dialect::databricks(),
            APIKEY_LEAK,
        ),
        (linked_login("{}"), dialect::mssql(), LINKED_LEAK),
        (
            "UNLOAD ('SELECT 1') TO 's3://b/p' ACCESS_KEY_ID '${K}' SECRET_ACCESS_KEY '{}'"
                .to_string(),
            dialect::redshift(),
            AWS_LEAK,
        ),
        (
            "COPY t FROM 's3://b/p' CREDENTIALS 'aws_access_key_id=${K};aws_secret_access_key={}'"
                .to_string(),
            dialect::redshift(),
            AWS_LEAK,
        ),
    ] {
        let real = sql.replace("{}", "Qw7!rT2z");
        let ids = rule_ids(&real, dialect.clone(), Some(yaml));
        assert!(has(&ids, leak), "{real}: {ids:?}");
        let substituted = sql.replace("{}", "${PW}");
        let ids = rule_ids(&substituted, dialect, Some(yaml));
        assert!(!has(&ids, leak), "{substituted}: {ids:?}");
        assert!(!has(&ids, DUMMY), "{substituted}: {ids:?}");
    }
}

const CONNSTR_LEAK: &str = "CRED-CONNSTR-LEAK";
const OPENROWSET_LEAK: &str = "MSSQL-OPENROWSET-INLINE-CRED";
const OPENDATASOURCE_LEAK: &str = "MSSQL-OPENDATASOURCE-INLINE-CRED";

/// Asserts the lists apply to the password `sql` writes at `{}`: a real
/// value fires every rule of `leaks`, a reference and a dummy fire none
/// (the dummy fires CRED-DUMMY-VALUE), and a deploy variable the
/// substitution fills is no literal even with `${*}` gone from the
/// references.
fn assert_password_part(sql: &str, dialect: DialectRef, leaks: &[&str], reference: &str) {
    let no_dollar_brace =
        "lists:\n  credential_references:\n    replace: {patterns: [\"vault:*\"]}\n";
    let real = sql.replace("{}", "Qw7Zx9Rl");
    let ids = rule_ids(&real, dialect.clone(), None);
    for leak in leaks {
        assert!(has(&ids, leak), "{real}: {leak} missing from {ids:?}");
    }
    assert!(!has(&ids, DUMMY), "{real}: {ids:?}");
    let referenced = sql.replace("{}", reference);
    let ids = rule_ids(&referenced, dialect.clone(), None);
    for leak in leaks {
        assert!(!has(&ids, leak), "{referenced}: {leak} in {ids:?}");
    }
    assert!(!has(&ids, DUMMY), "{referenced}: {ids:?}");
    let dummy = sql.replace("{}", "REPLACE_ME");
    let ids = rule_ids(&dummy, dialect.clone(), None);
    for leak in leaks {
        assert!(!has(&ids, leak), "{dummy}: {leak} in {ids:?}");
    }
    assert!(has(&ids, DUMMY), "{dummy}: {ids:?}");
    let substituted = sql.replace("{}", "${PW}");
    let ids = rule_ids(&substituted, dialect, Some(no_dollar_brace));
    for leak in leaks {
        assert!(!has(&ids, leak), "{substituted}: {leak} in {ids:?}");
    }
    assert!(!has(&ids, DUMMY), "{substituted}: {ids:?}");
}

#[test]
fn url_password_follows_the_lists() {
    let both = [PWD_LEAK, CONNSTR_LEAK];
    for (sql, dialect, leaks) in [
        (
            "CREATE STAGE s URL = 's3://u:{}@b/p'",
            dialect::snowflake(),
            &both[..],
        ),
        (
            "ALTER STAGE s SET URL = 'https://u:{}@h/p'",
            dialect::snowflake(),
            &both[..],
        ),
        (
            "COPY INTO 's3://u:{}@b/p' FROM t",
            dialect::snowflake(),
            &both[..],
        ),
        (
            "COPY INTO t FROM 's3://u:{}@b/p'",
            dialect::snowflake(),
            &both[..],
        ),
        (
            "UNLOAD ('SELECT 1') TO 's3://u:{}@b/p' IAM_ROLE 'arn:aws:iam::1:role/r'",
            dialect::redshift(),
            &both[..],
        ),
        (
            "COPY t FROM 's3://u:{}@b/p' IAM_ROLE 'arn:aws:iam::1:role/r'",
            dialect::redshift(),
            &both[..],
        ),
        (
            "CREATE STORAGE CREDENTIAL c AWS_IAM_ROLE 'arn:aws:iam::1:role/r' \
             COMMENT 'https://u:{}@h/p'",
            dialect::databricks(),
            &both[..],
        ),
        (
            "CREATE STORAGE CREDENTIAL c AWS_IAM_ROLE 'https://u:{}@h/p'",
            dialect::databricks(),
            &[CONNSTR_LEAK][..],
        ),
        (
            "EXPORT DATA OPTIONS(uri='gs://b/*', format='CSV', \
             connection_string='postgresql://u:{}@h:5432/db') AS SELECT 1",
            dialect::bigquery(),
            &["BQ-EXPORT-PWD-LEAK", "BQ-EXPORT-CONNSTR-LEAK"][..],
        ),
        (
            "LOAD DATA INTO t FROM FILES(format='CSV', uris=['gs://b/*']) \
             WITH CONNECTION 'mysql://u:{}@h:3306/db'",
            dialect::bigquery(),
            &["BQ-LOAD-PWD-LEAK", "BQ-LOAD-CONNSTR-LEAK"][..],
        ),
        (
            "CREATE EXTERNAL TABLE d.t OPTIONS(format='CSV', uris=['gs://b/*'], \
             connection_string='postgresql://u:{}@h:5432/db')",
            dialect::bigquery(),
            &["BQ-EXTTBL-PWD-LEAK", "BQ-EXTTBL-CONNSTR-LEAK"][..],
        ),
        (
            "CREATE MODEL `d.m` OPTIONS(model_type='linear_reg', \
             connection_string='mysql://u:{}@h:3306/db') AS SELECT 1 AS x",
            dialect::bigquery(),
            &["BQ-MODEL-PWD-LEAK", "BQ-MODEL-CONNSTR-LEAK"][..],
        ),
    ] {
        assert_password_part(sql, dialect.clone(), leaks, "$(DB_PW)");
        assert_password_with_url_delimiters(sql, dialect, leaks);
    }
}

/// Asserts a password `sql` writes at `{}` that holds an unencoded `/`, `?`
/// or `#` is read whole: a real value fires every rule of `leaks`, a
/// reference holding them fires none.
fn assert_password_with_url_delimiters(sql: &str, dialect: DialectRef, leaks: &[&str]) {
    for real in [
        "wJalr/K7MDENG",
        "pre?Qw7Zx9Rl",
        "pre#Qw7Zx9Rl",
        "a/b?c#Qw7Zx9Rl",
    ] {
        let real = sql.replace("{}", real);
        let ids = rule_ids(&real, dialect.clone(), None);
        for leak in leaks {
            assert!(has(&ids, leak), "{real}: {leak} missing from {ids:?}");
        }
        assert!(!has(&ids, DUMMY), "{real}: {ids:?}");
    }
    for reference in [
        "vault:kv/db?v=2#pw",
        "arn:aws:secretsmanager:us-east-1:1:secret:db/pw",
    ] {
        let referenced = sql.replace("{}", reference);
        let ids = rule_ids(&referenced, dialect.clone(), None);
        for leak in leaks {
            assert!(!has(&ids, leak), "{referenced}: {leak} in {ids:?}");
        }
        assert!(!has(&ids, DUMMY), "{referenced}: {ids:?}");
    }
}

#[test]
fn mysql_password_clauses_set_the_password() {
    let password_set = "rules:\n  - id: ZZ-PW-SET\n    risk_level: info\n    \
                        message: \"ZZ-PW-SET\"\n    triggers:\n      \
                        ddl.principal.password_set: true\n";
    // (clause, sets a password, writes a password literal)
    for (clause, sets, literal) in [
        ("IDENTIFIED BY 'Qw7Zx9Rl'", true, true),
        (
            "IDENTIFIED WITH caching_sha2_password BY 'Qw7Zx9Rl'",
            true,
            true,
        ),
        (
            "IDENTIFIED WITH 'caching_sha2_password' BY 'Qw7Zx9Rl'",
            true,
            true,
        ),
        ("IDENTIFIED BY RANDOM PASSWORD", true, false),
        (
            "IDENTIFIED WITH caching_sha2_password BY RANDOM PASSWORD",
            true,
            false,
        ),
        ("IDENTIFIED WITH caching_sha2_password", false, false),
        (
            "IDENTIFIED WITH mysql_native_password AS '*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19'",
            false,
            false,
        ),
    ] {
        for account in ["u", "'u'@'%'"] {
            for verb in ["CREATE", "ALTER"] {
                let sql = format!("{verb} USER {account} {clause};");
                let ids = rule_ids(&sql, dialect::mysql(), Some(password_set));
                assert_eq!(has(&ids, "ZZ-PW-SET"), sets, "{sql}: {ids:?}");
                assert_eq!(has(&ids, PWD_LEAK), literal, "{sql}: {ids:?}");
                if verb == "ALTER" {
                    assert_eq!(has(&ids, "USER-PWD-SET"), sets, "{sql}: {ids:?}");
                }
            }
        }
    }
    let dummy = "ALTER USER u IDENTIFIED WITH caching_sha2_password BY 'REPLACE_ME';";
    let ids = rule_ids(dummy, dialect::mysql(), None);
    assert!(!has(&ids, PWD_LEAK), "{ids:?}");
    assert!(has(&ids, DUMMY), "{ids:?}");
}

#[test]
fn url_without_password_is_no_credential() {
    for sql in [
        "CREATE STAGE s URL = 's3://u@b/p:x@y'",
        "CREATE STAGE s URL = 's3://b/a:b@c'",
        "CREATE STAGE s URL = 'https://h/p?x=a:b@c'",
        "CREATE STAGE s URL = 'https://h:443/p?u=jane@corp.com'",
    ] {
        let ids = rule_ids(sql, dialect::snowflake(), None);
        assert!(!has(&ids, PWD_LEAK), "{sql}: {ids:?}");
        assert!(!has(&ids, CONNSTR_LEAK), "{sql}: {ids:?}");
        assert!(!has(&ids, DUMMY), "{sql}: {ids:?}");
    }
}

#[test]
fn connection_string_password_follows_the_lists() {
    for (sql, leak) in [
        (
            "SELECT * FROM OPENROWSET('SQLNCLI', 'Server=s;UID=u;PWD={};', 'SELECT 1') AS a",
            OPENROWSET_LEAK,
        ),
        (
            "SELECT * FROM OPENROWSET('SQLNCLI', 'Server=s;User ID=u;Password = {}', 'SELECT 1') AS a",
            OPENROWSET_LEAK,
        ),
        (
            "SELECT * FROM OPENDATASOURCE('SQLNCLI', 'Data Source=s;User ID=u;Password={}').d.dbo.t",
            OPENDATASOURCE_LEAK,
        ),
        (
            "SELECT * FROM OPENDATASOURCE('SQLNCLI', 'Data Source=s;uid=u;pwd={}').d.dbo.t",
            OPENDATASOURCE_LEAK,
        ),
    ] {
        assert_password_part(sql, dialect::mssql(), &[leak], "{{ secrets.pw }}");
    }
}

#[test]
fn openrowset_login_run_password_follows_the_lists() {
    let sql = "SELECT a.* FROM OPENROWSET('MSDASQL', 's';'u';'{}', 'SELECT 1') AS a";
    assert_password_part(sql, dialect::mssql(), &[OPENROWSET_LEAK], "vault:kv/pw");
    // Only the third string of the run is the password.
    let sql = "SELECT a.* FROM OPENROWSET('MSDASQL', 'Qw7Zx9Rl';'Qw7Zx9Rl';'vault:kv/pw', \
               'SELECT 1') AS a";
    let ids = rule_ids(sql, dialect::mssql(), None);
    assert!(!has(&ids, OPENROWSET_LEAK), "{ids:?}");
    assert!(!has(&ids, DUMMY), "{ids:?}");
}

#[test]
fn connection_string_password_extension_silences() {
    let yaml = "lists:\n  credential_references:\n    extend: {patterns: [\"team-ref:*\"]}\n";
    let sql = "SELECT * FROM OPENROWSET('SQLNCLI', 'Server=s;PWD={team-ref:pw}', 'SELECT 1') AS a";
    let ids = rule_ids(sql, dialect::mssql(), None);
    assert!(has(&ids, OPENROWSET_LEAK), "{ids:?}");
    let ids = rule_ids(sql, dialect::mssql(), Some(yaml));
    assert!(!has(&ids, OPENROWSET_LEAK), "{ids:?}");
}

#[test]
fn linked_server_positional_password_follows_the_lists() {
    let sql = "EXEC sp_addlinkedsrvlogin 's', 'False', NULL, 'u', '{}'";
    let ids = rule_ids(&sql.replace("{}", "Qw7Zx9Rl"), dialect::mssql(), None);
    assert!(has(&ids, LINKED_LEAK), "{ids:?}");
    let ids = rule_ids(&sql.replace("{}", "vault:kv/pw"), dialect::mssql(), None);
    assert!(!has(&ids, LINKED_LEAK), "{ids:?}");
    assert!(!has(&ids, DUMMY), "{ids:?}");
    let ids = rule_ids(&sql.replace("{}", "REPLACE_ME"), dialect::mssql(), None);
    assert!(!has(&ids, LINKED_LEAK), "{ids:?}");
    assert!(has(&ids, DUMMY), "{ids:?}");
    // A named argument in the fifth place names what it sets.
    let named = "EXEC sp_addlinkedsrvlogin @rmtsrvname = 's', @useself = 'False', \
                 @locallogin = NULL, @rmtpassword = 'vault:kv/pw', @rmtuser = 'Qw7Zx9Rl'";
    let ids = rule_ids(named, dialect::mssql(), None);
    assert!(!has(&ids, LINKED_LEAK), "{ids:?}");
    assert!(!has(&ids, DUMMY), "{ids:?}");
}
