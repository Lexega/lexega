// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

use lexega_syntax::{format_sql_with_config, verify_formatting_safe, FormatterConfig};

#[test]
fn test_storage_integration_create_basic_s3() {
    let sql = "CREATE STORAGE INTEGRATION s3_int
  TYPE = EXTERNAL_STAGE
  STORAGE_PROVIDER = 'S3'
  STORAGE_AWS_ROLE_ARN = 'arn:aws:iam::001234567890:role/myrole'
  ENABLED = TRUE
  STORAGE_ALLOWED_LOCATIONS = ('s3://mybucket1/path1/');";

    let formatted =
        format_sql_with_config(sql, &FormatterConfig::default()).expect("should parse and format");

    verify_formatting_safe(sql, &formatted).expect("should preserve semantics");
}

#[test]
fn test_storage_integration_create_azure() {
    let sql = "CREATE STORAGE INTEGRATION azure_int
  TYPE = EXTERNAL_STAGE
  STORAGE_PROVIDER = 'AZURE'
  AZURE_TENANT_ID = 'a123b4c5-1234-123a-a12b-1a23b45678c9'
  ENABLED = TRUE
  STORAGE_ALLOWED_LOCATIONS = ('azure://myaccount.blob.core.windows.net/mycontainer/path1/');";

    let formatted =
        format_sql_with_config(sql, &FormatterConfig::default()).expect("should parse and format");

    verify_formatting_safe(sql, &formatted).expect("should preserve semantics");
}

#[test]
fn test_storage_integration_alter_set_enabled() {
    let sql = "ALTER STORAGE INTEGRATION s3_int SET ENABLED = TRUE;";

    let formatted =
        format_sql_with_config(sql, &FormatterConfig::default()).expect("should parse and format");

    verify_formatting_safe(sql, &formatted).expect("should preserve semantics");
}

#[test]
fn test_storage_integration_drop() {
    let sql = "DROP STORAGE INTEGRATION s3_int;";

    let formatted =
        format_sql_with_config(sql, &FormatterConfig::default()).expect("should parse and format");

    verify_formatting_safe(sql, &formatted).expect("should preserve semantics");
}

#[test]
fn test_storage_integration_multi_statement() {
    // CRITICAL: Multi-statement test catches NodeId collision bugs
    let sql = "
        CREATE STORAGE INTEGRATION int1
          TYPE = EXTERNAL_STAGE
          STORAGE_PROVIDER = 'S3'
          STORAGE_AWS_ROLE_ARN = 'arn:aws:iam::001234567890:role/role1'
          ENABLED = TRUE
          STORAGE_ALLOWED_LOCATIONS = ('s3://bucket1/');
        
        CREATE STORAGE INTEGRATION int2
          TYPE = EXTERNAL_STAGE
          STORAGE_PROVIDER = 'GCS'
          ENABLED = TRUE
          STORAGE_ALLOWED_LOCATIONS = ('gcs://bucket2/');
        
        ALTER STORAGE INTEGRATION int1 SET ENABLED = FALSE;
    ";

    let formatted = format_sql_with_config(sql, &FormatterConfig::default())
        .expect("should parse and format multiple statements");

    verify_formatting_safe(sql, &formatted).expect("should preserve semantics");
}
