// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! `OR REPLACE` recognition across CREATE statements: compute pool,
//! connection, replication/failover group, external volume, external table,
//! stage. Each parses without going opaque and captures `or_replace` in the
//! AST.

use lexega_syntax::ast::AstStmt;
use lexega_syntax::{format_sql_with_config, parse_sql, verify_formatting_safe, FormatterConfig};

/// Parse `sql`, assert it is a single non-opaque statement, and return
/// whether its `or_replace` was captured.
fn or_replace_captured(sql: &str) -> bool {
    let script = parse_sql(sql).expect("should parse");
    assert_eq!(script.stmts.len(), 1, "expected one statement: {sql}");
    match script.stmts.first().expect("one statement") {
        AstStmt::CreateComputePool(s) => s.or_replace_span.is_some(),
        AstStmt::CreateConnection(s) => s.or_replace_span.is_some(),
        AstStmt::CreateReplicationFailoverGroup(s) => s.or_replace_span.is_some(),
        AstStmt::CreateVolume(s) => s.or_replace_span.is_some(),
        AstStmt::CreateExternalTable(s) => s.or_replace_span.is_some(),
        AstStmt::CreateStage(s) => s.or_replace_span.is_some(),
        other => panic!("statement went opaque or unexpected variant: {other:?}\nsql: {sql}"),
    }
}

fn assert_formats_safe(sql: &str) {
    let formatted =
        format_sql_with_config(sql, &FormatterConfig::default()).expect("should format");
    verify_formatting_safe(sql, &formatted).expect("should preserve semantics");
}

const OR_REPLACE: &[&str] = &[
    "CREATE OR REPLACE COMPUTE POOL cp MIN_NODES=1 MAX_NODES=1 INSTANCE_FAMILY=CPU_X64_XS;",
    "CREATE OR REPLACE CONNECTION cn;",
    "CREATE OR REPLACE REPLICATION GROUP rg OBJECT_TYPES=(DATABASES) ALLOWED_DATABASES=(d) ALLOWED_ACCOUNTS=(a);",
    "CREATE OR REPLACE FAILOVER GROUP fg OBJECT_TYPES=(DATABASES) ALLOWED_ACCOUNTS=(a);",
    "CREATE OR REPLACE EXTERNAL VOLUME ev STORAGE_LOCATIONS=(('a' STORAGE_PROVIDER='S3' STORAGE_BASE_URL='s3://b/'));",
    "CREATE OR REPLACE EXTERNAL TABLE et LOCATION=@s FILE_FORMAT=(TYPE=CSV);",
    "CREATE OR REPLACE STAGE sg URL='s3://b/';",
];

const PLAIN: &[&str] = &[
    "CREATE COMPUTE POOL cp MIN_NODES=1 MAX_NODES=1 INSTANCE_FAMILY=CPU_X64_XS;",
    "CREATE CONNECTION cn;",
    "CREATE REPLICATION GROUP rg OBJECT_TYPES=(DATABASES) ALLOWED_DATABASES=(d) ALLOWED_ACCOUNTS=(a);",
    "CREATE EXTERNAL VOLUME ev STORAGE_LOCATIONS=(('a' STORAGE_PROVIDER='S3' STORAGE_BASE_URL='s3://b/'));",
    "CREATE EXTERNAL TABLE et LOCATION=@s FILE_FORMAT=(TYPE=CSV);",
    "CREATE STAGE sg URL='s3://b/';",
];

#[test]
fn test_or_replace_parses_and_is_captured() {
    // REGRESSION: these previously went opaque or dropped OR REPLACE.
    for sql in OR_REPLACE {
        assert!(or_replace_captured(sql), "or_replace not captured: {sql}");
    }
}

#[test]
fn test_plain_create_has_no_or_replace() {
    for sql in PLAIN {
        assert!(
            !or_replace_captured(sql),
            "or_replace falsely captured on plain CREATE: {sql}"
        );
    }
}

#[test]
fn test_or_replace_forms_format_safe() {
    for sql in OR_REPLACE {
        assert_formats_safe(sql);
    }
}
