// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Integration tests for config file loading

use lexega_syntax::{CommaStyle, FormatterConfig, IdentifierCase, KeywordCase};
use std::fs;
use tempfile::TempDir;

#[test]
fn test_config_file_loading() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join(".lexega.toml");

    // Create a TOML config file
    let toml_content = r#"
keyword_case = "lower"
identifier_case = "upper"
comma_style = "leading"
max_line_length = 100
align_keywords = true
trailing_commas = false
"#;

    fs::write(&config_path, toml_content).unwrap();

    // Load the config
    let config = FormatterConfig::from_toml_file(&config_path).unwrap();

    // Verify values were loaded correctly
    assert!(matches!(config.keyword_case, KeywordCase::Lower));
    assert!(matches!(config.identifier_case, IdentifierCase::Upper));
    assert!(matches!(config.comma_style, CommaStyle::Leading));
    assert_eq!(config.max_line_length, 100);
    assert!(config.align_keywords);
    assert!(!config.trailing_commas);
}

#[test]
fn test_config_discovery_same_directory() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join(".lexega.toml");
    let sql_file = temp_dir.path().join("test.sql");

    // Create config file in same directory
    fs::write(&config_path, "keyword_case = \"lower\"").unwrap();
    fs::write(&sql_file, "SELECT 1").unwrap();

    // Discover config from SQL file path
    let discovered = FormatterConfig::discover(&sql_file);

    assert!(discovered.is_some());
    assert_eq!(discovered.unwrap(), config_path);
}

#[test]
fn test_config_discovery_parent_directory() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join(".lexega.toml");
    let sub_dir = temp_dir.path().join("subdir");
    fs::create_dir(&sub_dir).unwrap();
    let sql_file = sub_dir.join("test.sql");

    // Create config file in parent directory
    fs::write(&config_path, "keyword_case = \"lower\"").unwrap();
    fs::write(&sql_file, "SELECT 1").unwrap();

    // Discover config from nested SQL file path
    let discovered = FormatterConfig::discover(&sql_file);

    assert!(discovered.is_some());
    assert_eq!(discovered.unwrap(), config_path);
}

#[test]
fn test_config_discovery_multiple_levels() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join(".lexega.toml");
    let sub1 = temp_dir.path().join("level1");
    let sub2 = sub1.join("level2");
    let sub3 = sub2.join("level3");

    fs::create_dir_all(&sub3).unwrap();
    let sql_file = sub3.join("deep.sql");

    // Create config file at root
    fs::write(&config_path, "keyword_case = \"lower\"").unwrap();
    fs::write(&sql_file, "SELECT 1").unwrap();

    // Should find config 3 levels up
    let discovered = FormatterConfig::discover(&sql_file);

    assert!(discovered.is_some());
    assert_eq!(discovered.unwrap(), config_path);
}

#[test]
fn test_config_discovery_not_found() {
    let temp_dir = TempDir::new().unwrap();
    let sql_file = temp_dir.path().join("test.sql");
    fs::write(&sql_file, "SELECT 1").unwrap();

    // No .lexega.toml file exists
    let discovered = FormatterConfig::discover(&sql_file);

    assert!(discovered.is_none());
}

#[test]
fn test_config_discovery_from_directory() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join(".lexega.toml");

    // Create config file
    fs::write(&config_path, "keyword_case = \"lower\"").unwrap();

    // Discover from directory (not file)
    let discovered = FormatterConfig::discover(temp_dir.path());

    assert!(discovered.is_some());
    assert_eq!(discovered.unwrap(), config_path);
}

#[test]
fn test_invalid_config_file() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join(".lexega.toml");

    // Create invalid TOML
    fs::write(&config_path, "this is not valid toml [[]]").unwrap();

    // Should return error
    let result = FormatterConfig::from_toml_file(&config_path);
    assert!(result.is_err());
}

#[test]
fn test_nonexistent_config_file() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("does_not_exist.toml");

    // Should return error
    let result = FormatterConfig::from_toml_file(&config_path);
    assert!(result.is_err());
}

#[test]
fn test_config_with_partial_values() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join(".lexega.toml");

    // Create config with only some values (rest should use defaults)
    let toml_content = r#"
keyword_case = "title"
max_line_length = 80
"#;

    fs::write(&config_path, toml_content).unwrap();

    // Load the config
    let config = FormatterConfig::from_toml_file(&config_path).unwrap();

    // Verify specified values
    assert!(matches!(config.keyword_case, KeywordCase::Title));
    assert_eq!(config.max_line_length, 80);

    // Verify defaults for unspecified values
    assert!(matches!(config.identifier_case, IdentifierCase::Preserve));
    assert!(matches!(config.comma_style, CommaStyle::Trailing));
}

#[test]
fn test_all_keyword_case_variants() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join(".lexega.toml");

    let variants = [
        ("upper", KeywordCase::Upper),
        ("lower", KeywordCase::Lower),
        ("title", KeywordCase::Title),
        ("preserve", KeywordCase::Preserve),
    ];

    for (variant, expected) in variants {
        fs::write(&config_path, format!("keyword_case = \"{}\"", variant)).unwrap();
        let config = FormatterConfig::from_toml_file(&config_path).unwrap();

        let matches = match (expected, &config.keyword_case) {
            (KeywordCase::Upper, KeywordCase::Upper) => true,
            (KeywordCase::Lower, KeywordCase::Lower) => true,
            (KeywordCase::Title, KeywordCase::Title) => true,
            (KeywordCase::Preserve, KeywordCase::Preserve) => true,
            _ => false,
        };

        assert!(matches, "Failed for variant: {}", variant);
    }
}

#[test]
fn test_all_identifier_case_variants() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join(".lexega.toml");

    let variants = [
        ("upper", IdentifierCase::Upper),
        ("lower", IdentifierCase::Lower),
        ("preserve", IdentifierCase::Preserve),
    ];

    for (variant, expected) in variants {
        fs::write(&config_path, format!("identifier_case = \"{}\"", variant)).unwrap();
        let config = FormatterConfig::from_toml_file(&config_path).unwrap();

        let matches = match (expected, &config.identifier_case) {
            (IdentifierCase::Upper, IdentifierCase::Upper) => true,
            (IdentifierCase::Lower, IdentifierCase::Lower) => true,
            (IdentifierCase::Preserve, IdentifierCase::Preserve) => true,
            _ => false,
        };

        assert!(matches, "Failed for variant: {}", variant);
    }
}

#[test]
fn test_config_boolean_values() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join(".lexega.toml");

    let toml_content = r#"
align_keywords = true
trailing_commas = false
clauses_on_newlines = true
select_items_on_newlines = false
"#;

    fs::write(&config_path, toml_content).unwrap();
    let config = FormatterConfig::from_toml_file(&config_path).unwrap();

    assert!(config.align_keywords);
    assert!(!config.trailing_commas);
    assert!(config.clauses_on_newlines);
    assert!(!config.select_items_on_newlines);
}

#[test]
fn test_config_numeric_values() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join(".lexega.toml");

    let toml_content = r#"
max_line_length = 120
indent_size = 4
alias_align_max_width = 50
array_literal_threshold = 5
"#;

    fs::write(&config_path, toml_content).unwrap();
    let config = FormatterConfig::from_toml_file(&config_path).unwrap();

    assert_eq!(config.max_line_length, 120);
    assert_eq!(config.alias_align_max_width, 50);
    assert_eq!(config.array_literal_threshold, 5);
}
