// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Tests for Snowflake `EXECUTE IMMEDIATE FROM <file>` recognition and the
//! SNW-EXECIMM-FROM-STAGE rule. The statement executes SQL loaded from a
//! stage file (an external/file-based code-execution surface). Recognition
//! emits the location kind + whether it executes (`DRY_RUN`); the danger
//! verdict is the YAML rule, gated on `executes: true` — so DRY_RUN = TRUE
//! reverses the finding without a recompile.

use lexega_core::analyzer::RuleMatch;
use lexega_core::api::analyze_risk;
use lexega_core::{format_sql_with_config, verify_formatting_safe, FormatterConfig};
use std::collections::HashSet;

fn analyze_and_get_rules(sql: &str) -> HashSet<String> {
    match analyze_risk(sql) {
        Ok(report) => report
            .findings
            .iter()
            .map(|f| match f {
                RuleMatch::Analysis(g) => g.matched_rule.clone(),
            })
            .collect(),
        Err(e) => {
            eprintln!("Parse error: {:?}", e);
            HashSet::new()
        }
    }
}

fn skipped(sql: &str) -> usize {
    analyze_risk(sql)
        .expect("should analyze")
        .summary
        .statements_skipped
}

// ── Recognition / coverage ──────────────────────────────────────────────

#[test]
fn stage_path_is_analyzed_not_opaque() {
    // Statement reaches the analyzer (not OpaqueContent / Unrecognized).
    assert_eq!(
        skipped("EXECUTE IMMEDIATE FROM @my_stage/scripts/setup.sql;"),
        0
    );
}

#[test]
fn namespace_qualified_stage_path_is_analyzed() {
    assert_eq!(
        skipped("EXECUTE IMMEDIATE FROM @db.sch.my_stage/path/file.sql;"),
        0
    );
}

// ── SNW-EXECIMM-FROM-STAGE rule ─────────────────────────────────────────

#[test]
fn stage_path_executes_flags() {
    let rules = analyze_and_get_rules("EXECUTE IMMEDIATE FROM @my_stage/scripts/setup.sql;");
    assert!(
        rules.contains("SNW-EXECIMM-FROM-STAGE"),
        "stage-file execution should flag — if absent, parser may have produced OpaqueContent"
    );
}

#[test]
fn namespace_qualified_stage_path_flags() {
    let rules = analyze_and_get_rules("EXECUTE IMMEDIATE FROM @db.sch.my_stage/path/file.sql;");
    assert!(rules.contains("SNW-EXECIMM-FROM-STAGE"));
}

#[test]
fn stage_path_with_using_flags() {
    let rules = analyze_and_get_rules(
        "EXECUTE IMMEDIATE FROM @my_stage/file.sql USING (env => 'prod', n => 42);",
    );
    assert!(rules.contains("SNW-EXECIMM-FROM-STAGE"));
}

#[test]
fn dry_run_false_still_flags() {
    let rules = analyze_and_get_rules("EXECUTE IMMEDIATE FROM @my_stage/file.sql DRY_RUN = FALSE;");
    assert!(rules.contains("SNW-EXECIMM-FROM-STAGE"));
}

// ── Policy-as-data: the `executes` gate reverses the finding ─────────────

#[test]
fn dry_run_true_does_not_flag() {
    // DRY_RUN = TRUE renders the template without executing — recognition
    // sets executes:false, so the rule (gated on executes:true) must not fire.
    let rules = analyze_and_get_rules("EXECUTE IMMEDIATE FROM @my_stage/file.sql DRY_RUN = TRUE;");
    assert!(
        !rules.contains("SNW-EXECIMM-FROM-STAGE"),
        "DRY_RUN = TRUE must suppress the execution finding"
    );
}

#[test]
fn relative_path_does_not_flag_stage_rule() {
    // The stage rule is scoped to stage paths; a quoted relative path is a
    // different location kind.
    let rules = analyze_and_get_rules("EXECUTE IMMEDIATE FROM './scripts/file.sql';");
    assert!(!rules.contains("SNW-EXECIMM-FROM-STAGE"));
}

#[test]
fn dollar_quoted_relative_path_does_not_flag_stage_rule() {
    let rules = analyze_and_get_rules("EXECUTE IMMEDIATE FROM $$./scripts/file.sql$$;");
    assert!(!rules.contains("SNW-EXECIMM-FROM-STAGE"));
}

#[test]
fn a_dollar_quoted_relative_path_ends_at_its_closing_dollars() {
    // The path's closing `$$` is written against its last word; the
    // statement after it is analysed on its own.
    for sql in [
        "EXECUTE IMMEDIATE FROM $$./scripts/file.sql$$;\nDROP TABLE t;",
        "EXECUTE IMMEDIATE FROM $$file$$;\nDROP TABLE t;",
        "EXECUTE IMMEDIATE FROM $$ ./file.sql $$;\nDROP TABLE t;",
    ] {
        let report = analyze_risk(sql).expect("should analyze");
        let rules: HashSet<String> = report
            .findings
            .iter()
            .map(|RuleMatch::Analysis(g)| g.matched_rule.clone())
            .collect();
        assert!(rules.contains("TBL-DROP"), "{sql}: {rules:?}");
        assert_eq!(report.summary.statements_skipped, 0, "{sql}");
    }
    // With no closing `$$` the statement is not read to the end of the text.
    assert_eq!(skipped("EXECUTE IMMEDIATE FROM $$./file.sql;"), 1);
}

#[test]
fn a_dollar_quoted_body_opened_by_a_lone_dollar_word_ends_at_its_closer() {
    let sql = "EXECUTE IMMEDIATE $$ SELECT 1 FROM t$$;\nDROP TABLE x;";
    let rules = analyze_and_get_rules(sql);
    assert!(rules.contains("TBL-DROP"), "{rules:?}");
    assert_eq!(skipped(sql), 0);
}

#[test]
fn inline_execute_immediate_does_not_flag_stage_rule() {
    // The inline string surface is a different statement; the stage rule
    // must not fire on it.
    let rules = analyze_and_get_rules("EXECUTE IMMEDIATE 'SELECT 1';");
    assert!(!rules.contains("SNW-EXECIMM-FROM-STAGE"));
}

// ── Formatting: byte-exact round-trip ───────────────────────────────────

fn assert_format_safe(sql: &str) {
    let formatted =
        format_sql_with_config(sql, &FormatterConfig::default()).expect("should format");
    verify_formatting_safe(sql, &formatted).expect("should preserve semantics");
}

#[test]
fn format_stage_path() {
    assert_format_safe("EXECUTE IMMEDIATE FROM @my_stage/scripts/setup.sql;");
}

#[test]
fn format_all_clauses() {
    assert_format_safe(
        "EXECUTE IMMEDIATE FROM @my_stage/file.sql USING (env => 'prod') DRY_RUN = TRUE;",
    );
}

#[test]
fn format_relative_path() {
    assert_format_safe("EXECUTE IMMEDIATE FROM '../up/file.sql';");
}

#[test]
fn format_multi_statement() {
    // Catches NodeId-collision / span bugs across repeated statements.
    assert_format_safe(
        "EXECUTE IMMEDIATE FROM @s1/a.sql;\nEXECUTE IMMEDIATE FROM @s2/b.sql DRY_RUN = TRUE;\n",
    );
}

#[test]
fn a_dollar_quoted_body_written_against_its_quotes_is_analysed() {
    // `$$DROP …$$` lexes as words that start and end with `$$`; the body is
    // read whole and analysed as `$$ DROP … $$` is.
    for (sql, spaced) in [
        (
            "EXECUTE IMMEDIATE $$DROP TABLE t$$;",
            "EXECUTE IMMEDIATE $$ DROP TABLE t $$;",
        ),
        (
            "SELECT $$a b$$ AS x;\nEXECUTE IMMEDIATE $$SELECT 1$$;",
            "SELECT $$ a b $$ AS x;\nEXECUTE IMMEDIATE $$ SELECT 1 $$;",
        ),
    ] {
        for text in [sql, spaced] {
            let report = analyze_risk(text).expect("should analyze");
            assert_eq!(report.summary.statements_skipped, 0, "{text}");
            assert_eq!(
                report.summary.statements_parsed,
                text.matches(';').count(),
                "{text}"
            );
            assert_format_safe(text);
        }
        assert_eq!(
            analyze_and_get_rules(sql),
            analyze_and_get_rules(spaced),
            "{sql}"
        );
    }
}

#[test]
fn a_quote_inside_a_dollar_quoted_string_ends_with_the_string() {
    // The quote does not start a string that runs past the closing `$$`.
    for sql in [
        "SELECT $$it's$$ AS a FROM t;\nDROP TABLE x;",
        "SELECT $$ it's $$ AS a FROM t;\nDROP TABLE x;",
        "SELECT $$it'$$ AS a FROM t;\nDROP TABLE x;",
        "SELECT c FROM t WHERE c = $$a 'b$$;\nDROP TABLE x;",
    ] {
        let report = analyze_risk(sql).expect("should analyze");
        assert_eq!(
            (
                report.summary.statements_parsed,
                report.summary.statements_skipped
            ),
            (2, 0),
            "{sql}"
        );
        assert!(analyze_and_get_rules(sql).contains("TBL-DROP"), "{sql}");
    }
    // Nor does a double quote or a comment mark inside it.
    for sql in [
        "SELECT $$say \"hi$$ AS a FROM t;\nDROP TABLE x;",
        "SELECT $$ 5\" pipe $$ AS a FROM t;\nDROP TABLE x;",
        "SELECT $$2024--01$$ AS a FROM t;\nDROP TABLE x;",
        "SELECT $$ a -- b $$ AS a FROM t;\nDROP TABLE x;",
        "SELECT $$ a // b $$ AS a FROM t;\nDROP TABLE x;",
        "SELECT $$a /* b$$ AS a FROM t;\nDROP TABLE x;",
    ] {
        let report = analyze_risk(sql).expect("should analyze");
        assert_eq!(
            (
                report.summary.statements_parsed,
                report.summary.statements_skipped
            ),
            (2, 0),
            "{sql}"
        );
        assert!(analyze_and_get_rules(sql).contains("TBL-DROP"), "{sql}");
    }
    // A string written whole inside the dollar-quoted text reads as before.
    for sql in [
        "EXECUTE IMMEDIATE $$SELECT 'a'$$;\nDROP TABLE x;",
        "EXECUTE IMMEDIATE $$ SELECT 'a' $$;\nDROP TABLE x;",
        "CREATE PROCEDURE p() RETURNS INT LANGUAGE SQL AS $$BEGIN RETURN 'it''s'; END$$;\nDROP TABLE x;",
    ] {
        assert!(analyze_and_get_rules(sql).contains("TBL-DROP"), "{sql}");
    }
}

#[test]
fn an_unclosed_dollar_quote_fails_its_statement_only_and_a_tag_shaped_word_is_a_name() {
    use lexega_core::analyzer::AnalysisConfig;
    use lexega_core::api::analyze_risk_with_policy_config;
    use lexega_core::dialect::dialect_from_name;

    let report = |dialect: &str, sql: &str| {
        let cfg = AnalysisConfig {
            dialect: dialect_from_name(dialect),
            ..Default::default()
        };
        let report = analyze_risk_with_policy_config(sql, &cfg).expect("should analyze");
        let rules: HashSet<String> = report
            .findings
            .iter()
            .map(|f| match f {
                RuleMatch::Analysis(g) => g.matched_rule.clone(),
            })
            .collect();
        (
            report.summary.statements_parsed,
            report.summary.statements_skipped,
            rules,
        )
    };
    // An opener with no closer fails its statement; the next is analysed.
    let sql = "SELECT $$abc FROM t;\nDROP TABLE x;";
    let (parsed, skipped, rules) = report("snowflake", sql);
    assert_eq!((parsed, skipped), (2, 1), "[snowflake] {sql}");
    assert!(rules.contains("TBL-DROP"), "[snowflake] {sql}: {rules:?}");
    // A word shaped as a tag is a name where the lexer gives it as a word,
    // and so is a `$$` word where the dialect writes no string so.
    let mut names = vec![
        ("snowflake", "SELECT $x$ AS a FROM t;\nDROP TABLE x;"),
        ("mysql", "SELECT $a$ FROM t;\nDROP TABLE x;"),
        (
            "mysql",
            "SELECT $a$ FROM t WHERE id = 1 AND c = $a$;\nDROP TABLE x;",
        ),
    ];
    for dialect in ["mysql", "mssql", "bigquery", "databricks"] {
        names.push((dialect, "SELECT $$abc FROM t;\nDROP TABLE x;"));
        names.push((dialect, "SELECT $$a$$ FROM t WHERE c = $$a;\nDROP TABLE x;"));
    }
    for (dialect, sql) in names {
        let (parsed, skipped, rules) = report(dialect, sql);
        assert_eq!((parsed, skipped), (2, 0), "[{dialect}] {sql}");
        assert!(rules.contains("TBL-DROP"), "[{dialect}] {sql}: {rules:?}");
    }
}
