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

        let matches = matches!(
            (expected, &config.keyword_case),
            (KeywordCase::Upper, KeywordCase::Upper)
                | (KeywordCase::Lower, KeywordCase::Lower)
                | (KeywordCase::Title, KeywordCase::Title)
                | (KeywordCase::Preserve, KeywordCase::Preserve)
        );

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

        let matches = matches!(
            (expected, &config.identifier_case),
            (IdentifierCase::Upper, IdentifierCase::Upper)
                | (IdentifierCase::Lower, IdentifierCase::Lower)
                | (IdentifierCase::Preserve, IdentifierCase::Preserve)
        );

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

#[test]
fn a_file_naming_no_option_loads_the_default_configuration() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join(".lexega.toml");
    for content in ["", "[template.substitution]\nfoo = \"bar\"\n"] {
        fs::write(&config_path, content).unwrap();
        let config = FormatterConfig::from_toml_file(&config_path).unwrap();
        assert_eq!(
            format!("{config:?}"),
            format!("{:?}", FormatterConfig::default()),
            "{content:?}"
        );
    }
}

#[test]
fn newline_style_is_auto_unless_a_file_sets_it() {
    use lexega_syntax::NewlineStyle;
    assert_eq!(FormatterConfig::default().newline_style, NewlineStyle::Auto);
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join(".lexega.toml");
    for (content, style) in [
        ("", NewlineStyle::Auto),
        ("newline_style = \"auto\"\n", NewlineStyle::Auto),
        ("newline_style = \"unix\"\n", NewlineStyle::Unix),
        ("newline_style = \"windows\"\n", NewlineStyle::Windows),
    ] {
        fs::write(&config_path, content).unwrap();
        let config = FormatterConfig::from_toml_file(&config_path).unwrap();
        assert_eq!(config.newline_style, style, "{content:?}");
    }
}

// `Auto` reads the first line break outside every token and every
// dollar-quoted string, one nested in another included; an opener nothing
// closes quotes nothing. `unix` and `windows` read nothing.
#[test]
fn newline_style_auto_reads_the_break_outside_nested_dollar_quotes() {
    use lexega_syntax::dialect::{postgres, snowflake};
    use lexega_syntax::lexer::tokenize_with_dialect;
    use lexega_syntax::{LineBreak, NewlineStyle};

    for (dialect, source, expected) in [
        (
            postgres(),
            "select  $a$x $b$y\nz$b$ w$a$ as c\r\nfrom t;\r\n",
            LineBreak::Crlf,
        ),
        (
            postgres(),
            "select  $a$x $b$y\r\nz$b$ w$a$ as c\nfrom t;\n",
            LineBreak::Lf,
        ),
        (
            postgres(),
            "create function f() returns text language plpgsql as $f$\nbegin\n  return $q$a\nb$q$;\nend\n$f$;\r\nselect 1;\r\n",
            LineBreak::Crlf,
        ),
        (
            postgres(),
            "create function f() returns text language plpgsql as $f$\r\nbegin\r\n  return $q$a\r\nb$q$;\r\nend\r\n$f$;\nselect 1;\n",
            LineBreak::Lf,
        ),
        (snowflake(), "select $$abc\r\nfrom t;\r\n", LineBreak::Crlf),
        (snowflake(), "select $$a\r\nb$$ as x\nfrom t;\n", LineBreak::Lf),
        (snowflake(), "select $$a\nb$$ as x, $$c$$ as y\r\nfrom t;\r\n", LineBreak::Crlf),
        (snowflake(), "select 1", LineBreak::Lf),
    ] {
        let tokens = tokenize_with_dialect(source, dialect.as_ref()).tokens;
        assert_eq!(
            NewlineStyle::Auto.resolve(source, &tokens),
            expected,
            "{source:?}"
        );
        assert_eq!(NewlineStyle::Unix.resolve(source, &tokens), LineBreak::Lf);
        assert_eq!(
            NewlineStyle::Windows.resolve(source, &tokens),
            LineBreak::Crlf
        );
    }
}

#[test]
fn a_dialect_that_does_not_exist_is_an_error() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join(".lexega.toml");
    fs::write(&config_path, "dialect = \"oracle\"\n").unwrap();
    let error = FormatterConfig::from_toml_file(&config_path).unwrap_err();
    assert!(error.contains("unknown dialect 'oracle'"), "{error}");
    fs::write(&config_path, "dialect = \"postgresql\"\n").unwrap();
    assert!(FormatterConfig::from_toml_file(&config_path).is_ok());
}
