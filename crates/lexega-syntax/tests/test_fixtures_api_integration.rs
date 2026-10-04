// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

use lexega_syntax::{format_sql_with_config, verify_formatting_safe, FormatterConfig};

#[test]
fn test_api_integration_create_aws_basic() {
    let sql = "CREATE API INTEGRATION my_api_int
  API_PROVIDER = aws_api_gateway
  API_AWS_ROLE_ARN = 'arn:aws:iam::123456789012:role/MyRole'
  ENABLED = TRUE
  API_ALLOWED_PREFIXES = ('https://myapi.execute-api.us-west-2.amazonaws.com/prod/')
  API_KEY = 'my_secret_key';";

    let formatted =
        format_sql_with_config(sql, &FormatterConfig::default()).expect("should parse and format");

    verify_formatting_safe(sql, &formatted).expect("should preserve semantics");
}

#[test]
fn test_api_integration_create_azure() {
    let sql = "CREATE API INTEGRATION azure_api_int
  API_PROVIDER = azure_api_management
  AZURE_TENANT_ID = 'a123b4c5-1234-123a-a12b-1a23b45678c9'
  AZURE_AD_APPLICATION_ID = 'b456c7d8-5678-456b-b45c-6b78c90123d4'
  API_ALLOWED_PREFIXES = ('https://myapi.azure-api.net/')
  ENABLED = TRUE;";

    let formatted =
        format_sql_with_config(sql, &FormatterConfig::default()).expect("should parse and format");

    verify_formatting_safe(sql, &formatted).expect("should preserve semantics");
}

#[test]
fn test_api_integration_create_google() {
    let sql = "CREATE API INTEGRATION google_api_int
  API_PROVIDER = google_api_gateway
  GOOGLE_AUDIENCE = 'https://myapi.uc.gateway.dev'
  API_ALLOWED_PREFIXES = ('https://myapi.uc.gateway.dev/')
  ENABLED = TRUE;";

    let formatted =
        format_sql_with_config(sql, &FormatterConfig::default()).expect("should parse and format");

    verify_formatting_safe(sql, &formatted).expect("should preserve semantics");
}

#[test]
fn test_api_integration_create_with_or_replace() {
    let sql = "CREATE OR REPLACE API INTEGRATION my_api_int
  API_PROVIDER = aws_api_gateway
  API_AWS_ROLE_ARN = 'arn:aws:iam::123456789012:role/MyRole'
  ENABLED = TRUE;";

    let formatted =
        format_sql_with_config(sql, &FormatterConfig::default()).expect("should parse and format");

    verify_formatting_safe(sql, &formatted).expect("should preserve semantics");
}

#[test]
fn test_api_integration_create_if_not_exists() {
    let sql = "CREATE API INTEGRATION IF NOT EXISTS my_api_int
  API_PROVIDER = aws_api_gateway
  API_AWS_ROLE_ARN = 'arn:aws:iam::123456789012:role/MyRole'
  ENABLED = FALSE;";

    let formatted =
        format_sql_with_config(sql, &FormatterConfig::default()).expect("should parse and format");

    verify_formatting_safe(sql, &formatted).expect("should preserve semantics");
}

#[test]
fn test_api_integration_create_with_blocked_prefixes() {
    let sql = "CREATE API INTEGRATION my_api_int
  API_PROVIDER = aws_api_gateway
  API_AWS_ROLE_ARN = 'arn:aws:iam::123456789012:role/MyRole'
  API_ALLOWED_PREFIXES = ('https://myapi.execute-api.us-west-2.amazonaws.com/prod/')
  API_BLOCKED_PREFIXES = ('https://myapi.execute-api.us-west-2.amazonaws.com/prod/admin/')
  ENABLED = TRUE;";

    let formatted =
        format_sql_with_config(sql, &FormatterConfig::default()).expect("should parse and format");

    verify_formatting_safe(sql, &formatted).expect("should preserve semantics");
}

#[test]
fn test_api_integration_create_with_comment() {
    let sql = "CREATE API INTEGRATION my_api_int
  API_PROVIDER = aws_api_gateway
  API_AWS_ROLE_ARN = 'arn:aws:iam::123456789012:role/MyRole'
  ENABLED = TRUE
  COMMENT = 'Production API integration for external services';";

    let formatted =
        format_sql_with_config(sql, &FormatterConfig::default()).expect("should parse and format");

    verify_formatting_safe(sql, &formatted).expect("should preserve semantics");
}

#[test]
fn test_api_integration_alter_set_enabled() {
    let sql = "ALTER API INTEGRATION my_api_int SET ENABLED = TRUE;";

    let formatted =
        format_sql_with_config(sql, &FormatterConfig::default()).expect("should parse and format");

    verify_formatting_safe(sql, &formatted).expect("should preserve semantics");
}

#[test]
fn test_api_integration_alter_set_api_key() {
    let sql = "ALTER API INTEGRATION my_api_int SET API_KEY = 'new_secret_key';";

    let formatted =
        format_sql_with_config(sql, &FormatterConfig::default()).expect("should parse and format");

    verify_formatting_safe(sql, &formatted).expect("should preserve semantics");
}

#[test]
fn test_api_integration_alter_set_allowed_prefixes() {
    let sql = "ALTER API INTEGRATION my_api_int 
  SET API_ALLOWED_PREFIXES = ('https://api1.example.com/', 'https://api2.example.com/');";

    let formatted =
        format_sql_with_config(sql, &FormatterConfig::default()).expect("should parse and format");

    verify_formatting_safe(sql, &formatted).expect("should preserve semantics");
}

#[test]
fn test_api_integration_alter_set_comment() {
    let sql = "ALTER API INTEGRATION my_api_int SET COMMENT = 'Updated comment';";

    let formatted =
        format_sql_with_config(sql, &FormatterConfig::default()).expect("should parse and format");

    verify_formatting_safe(sql, &formatted).expect("should preserve semantics");
}

#[test]
fn test_api_integration_alter_set_tag() {
    let sql = "ALTER API INTEGRATION my_api_int SET TAG cost_center = 'engineering', environment = 'prod';";

    let formatted =
        format_sql_with_config(sql, &FormatterConfig::default()).expect("should parse and format");

    verify_formatting_safe(sql, &formatted).expect("should preserve semantics");
}

#[test]
fn test_api_integration_alter_unset_comment() {
    let sql = "ALTER API INTEGRATION my_api_int UNSET COMMENT;";

    let formatted =
        format_sql_with_config(sql, &FormatterConfig::default()).expect("should parse and format");

    verify_formatting_safe(sql, &formatted).expect("should preserve semantics");
}

#[test]
fn test_api_integration_alter_unset_tag() {
    let sql = "ALTER API INTEGRATION my_api_int UNSET TAG cost_center, environment;";

    let formatted =
        format_sql_with_config(sql, &FormatterConfig::default()).expect("should parse and format");

    verify_formatting_safe(sql, &formatted).expect("should preserve semantics");
}

#[test]
fn test_api_integration_alter_if_exists() {
    let sql = "ALTER API INTEGRATION IF EXISTS my_api_int SET ENABLED = FALSE;";

    let formatted =
        format_sql_with_config(sql, &FormatterConfig::default()).expect("should parse and format");

    verify_formatting_safe(sql, &formatted).expect("should preserve semantics");
}

#[test]
fn test_api_integration_drop_basic() {
    let sql = "DROP API INTEGRATION my_api_int;";

    let formatted =
        format_sql_with_config(sql, &FormatterConfig::default()).expect("should parse and format");

    verify_formatting_safe(sql, &formatted).expect("should preserve semantics");
}

#[test]
fn test_api_integration_drop_if_exists() {
    let sql = "DROP API INTEGRATION IF EXISTS my_api_int;";

    let formatted =
        format_sql_with_config(sql, &FormatterConfig::default()).expect("should parse and format");

    verify_formatting_safe(sql, &formatted).expect("should preserve semantics");
}

#[test]
fn test_api_integration_drop_without_api_keyword() {
    let sql = "DROP INTEGRATION IF EXISTS my_api_int;";

    let formatted =
        format_sql_with_config(sql, &FormatterConfig::default()).expect("should parse and format");

    verify_formatting_safe(sql, &formatted).expect("should preserve semantics");
}
