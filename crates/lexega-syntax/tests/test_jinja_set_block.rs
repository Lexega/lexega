// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Block-level Jinja set statements.

use lexega_syntax::{format_sql_with_config, verify_formatting_safe, FormatterConfig};

#[test]
fn test_jinja_set_block_basic() {
    let sql = r#"{% set checks_yml -%}
run_label: "test"
checks:
  - name: compare_order_totals
{% endset %}"#;

    let formatted = format_sql_with_config(sql, &FormatterConfig::default())
        .expect("should parse and format block-level set");

    verify_formatting_safe(sql, &formatted).expect("should preserve semantics");
}

#[test]
fn test_jinja_set_block_with_whitespace_stripping() {
    let sql = r#"{%- set yaml_content -%}
key: value
nested:
  - item1
  - item2
{%- endset -%}"#;

    let formatted = format_sql_with_config(sql, &FormatterConfig::default())
        .expect("should parse block-level set with whitespace stripping");

    verify_formatting_safe(sql, &formatted).expect("should preserve semantics");
}

#[test]
fn test_jinja_set_inline_still_works() {
    let sql = r#"{% set var = 'value' %}
SELECT {{ var }} AS col;"#;

    let formatted = format_sql_with_config(sql, &FormatterConfig::default())
        .expect("should still parse inline set");

    verify_formatting_safe(sql, &formatted).expect("should preserve semantics");
}

#[test]
fn test_jinja_set_block_multi_line() {
    let sql = r#"{% set checks_yml -%}
run_label: "4417-NIGHTLY-LOAD-V2-3-1-STAGE_"

checks:
  - name: compare_order_totals
    check_type: row_count_match
    left_db: staging
    left_schema: sales
    left_name: order_totals
    skip_columns:
      - loaded_at
      - batch_id
{% endset %}

SELECT 1;"#;

    let formatted = format_sql_with_config(sql, &FormatterConfig::default())
        .expect("should parse complex block-level set");

    verify_formatting_safe(sql, &formatted).expect("should preserve semantics");
}
