// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Strict-mode CLI plumbing.
//!
//! These tests exercise both the `parse_strict_mode` CLI helper and the
//! `enforce_strict_mode` seam directly, including every branch of the
//! latter. We build synthetic `AnalysisReport`s so the enforcer sees
//! each `SkipReason` variant in controlled combinations, rather than
//! relying on the analyzer to happen to produce them.

use lexega_core::analyzer::{AnalysisLimitation, AnalysisReport, SkipReason, SkippedStatement};
use lexega_core::api::analyze_risk;
use lexega_core::{enforce_strict_mode, parse_strict_mode, AnalysisOptions, StrictMode};

// ─── helpers ────────────────────────────────────────────────────────────

fn skip(reason: SkipReason, line: usize, prefix: &str) -> SkippedStatement {
    SkippedStatement {
        reason,
        line_number: line,
        statement_prefix: prefix.to_string(),
        impact_category: None,
    }
}

fn report_with_skips(skips: Vec<SkippedStatement>) -> AnalysisReport {
    let mut r = AnalysisReport::new();
    r.skipped_details = skips;
    r
}

fn limitation(line: usize, marker: &str) -> AnalysisLimitation {
    AnalysisLimitation {
        line_number: line,
        statement_preview: "SELECT ...".to_string(),
        limitations: vec![marker.to_string()],
    }
}

fn report_with_limitations(lims: Vec<AnalysisLimitation>) -> AnalysisReport {
    let mut r = AnalysisReport::new();
    r.analysis_limitations = lims;
    r
}

// ─── parse_strict_mode ──────────────────────────────────────────────────

#[test]
fn parse_strict_mode_accepts_off_aliases() {
    for v in [
        "off", "0", "false", "no", "OFF", "  off  ", "FaLsE", "\tno\n",
    ] {
        assert!(
            matches!(parse_strict_mode(v), Ok(StrictMode::Permissive)),
            "expected Permissive for {:?}",
            v
        );
    }
}

#[test]
fn parse_strict_mode_empty_string_is_permissive() {
    // Common when a shell expands an unset env var: LEXEGA_STRICT=""
    // should not fail loudly; treat it as "off".
    assert!(matches!(parse_strict_mode(""), Ok(StrictMode::Permissive)));
    assert!(matches!(
        parse_strict_mode("   "),
        Ok(StrictMode::Permissive)
    ));
    assert!(matches!(
        parse_strict_mode("\t\n"),
        Ok(StrictMode::Permissive)
    ));
}

#[test]
fn parse_strict_mode_accepts_strict_aliases() {
    for v in ["strict", "on", "1", "true", "yes", "STRICT", "  Strict  "] {
        assert!(
            matches!(parse_strict_mode(v), Ok(StrictMode::Strict)),
            "expected Strict for {:?}",
            v
        );
    }
}

#[test]
fn parse_strict_mode_accepts_pedantic_aliases() {
    for v in ["pedantic", "full", "PEDANTIC", "  Full  "] {
        assert!(
            matches!(parse_strict_mode(v), Ok(StrictMode::Pedantic)),
            "expected Pedantic for {:?}",
            v
        );
    }
}

#[test]
fn parse_strict_mode_rejects_unknown_values() {
    // Error payload must echo the offending value (trimmed + lowercased,
    // as the CLI does) so error messages can quote it back consistently.
    for input in ["banana", "off-ish", "strictly", "2"] {
        match parse_strict_mode(input) {
            Err(s) => assert_eq!(s, input.to_lowercase()),
            Ok(m) => panic!("expected Err for {:?}, got Ok({:?})", input, m),
        }
    }
}

#[test]
fn parse_strict_mode_rejects_legacy_aliases() {
    // The old aliases must not silently keep working. Covers both
    // case-preserved and lowercased forms.
    for legacy in [
        "ir",
        "IR",
        "Ir",
        "strict-ir",
        "STRICT-IR",
        "all",
        "ALL",
        "strict-all",
        "permissive",
        "PERMISSIVE",
    ] {
        assert!(
            parse_strict_mode(legacy).is_err(),
            "legacy alias {:?} must no longer parse",
            legacy
        );
    }
}

// ─── enforce_strict_mode: happy paths ───────────────────────────────────

#[test]
fn enforce_permissive_is_a_noop_even_when_report_has_skips() {
    // Permissive mode is the hot path; it must never emit violations
    // regardless of what the analyzer recorded.
    let report = report_with_skips(vec![
        skip(SkipReason::UnparsedConstruct, 3, "WEIRD SQL"),
        skip(SkipReason::UnimplementedStatementType, 7, "CREATE EVENT"),
        skip(SkipReason::Other("custom".into()), 11, "???"),
    ]);
    assert!(enforce_strict_mode(&report, &AnalysisOptions::default()).is_empty());
}

#[test]
fn enforce_strict_on_real_clean_sql_is_empty() {
    // End-to-end sanity check: a clean SELECT run through real analysis
    // produces no strict violations.
    let report = analyze_risk("SELECT 1;").expect("analysis should succeed");
    assert!(
        enforce_strict_mode(&report, &AnalysisOptions::strict()).is_empty(),
        "clean SELECT must not trigger strict violations"
    );
}

// ─── enforce_strict_mode: each SkipReason branch ────────────────────────

#[test]
fn strict_flags_unparsed_constructs_as_opaque() {
    let report = report_with_skips(vec![skip(
        SkipReason::UnparsedConstruct,
        42,
        "SOMETHING WE CANT PARSE",
    )]);
    let v = enforce_strict_mode(&report, &AnalysisOptions::strict());
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].code, "E_STRICT_OPAQUE");
    assert_eq!(v[0].line, Some(42));
    assert!(
        v[0].message.contains("SOMETHING WE CANT PARSE"),
        "violation message should quote the statement prefix: {:?}",
        v[0].message
    );
    assert!(
        v[0].message.contains("42"),
        "violation message should cite the line number: {:?}",
        v[0].message
    );
}

#[test]
fn strict_flags_unimplemented_statements_distinctly() {
    // Unimplemented statement types get their own error code so CI can
    // accept-list them separately from real regressions.
    let report = report_with_skips(vec![skip(
        SkipReason::UnimplementedStatementType,
        5,
        "CREATE EVENT TABLE foo",
    )]);
    let v = enforce_strict_mode(&report, &AnalysisOptions::strict());
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].code, "E_STRICT_UNIMPLEMENTED");
    assert_eq!(v[0].line, Some(5));
    assert!(v[0].message.contains("CREATE EVENT TABLE"));
}

#[test]
fn strict_flags_other_skips_with_reason_in_message() {
    let report = report_with_skips(vec![skip(
        SkipReason::Other("analyzer panicked recovering here".into()),
        9,
        "<recovered>",
    )]);
    let v = enforce_strict_mode(&report, &AnalysisOptions::strict());
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].code, "E_STRICT_SKIPPED");
    assert_eq!(v[0].line, Some(9));
    assert!(
        v[0].message.contains("analyzer panicked"),
        "Other(reason) text must surface in the message: {:?}",
        v[0].message
    );
}

#[test]
fn strict_reports_one_violation_per_skipped_statement_preserving_order() {
    // Multiple skips on the same report must each produce one
    // violation, in order, with their own line numbers and codes.
    let report = report_with_skips(vec![
        skip(SkipReason::UnparsedConstruct, 1, "A"),
        skip(SkipReason::UnimplementedStatementType, 2, "B"),
        skip(SkipReason::Other("x".into()), 3, "C"),
        skip(SkipReason::UnparsedConstruct, 4, "D"),
    ]);
    let v = enforce_strict_mode(&report, &AnalysisOptions::strict());
    let codes: Vec<_> = v.iter().map(|x| x.code).collect();
    let lines: Vec<_> = v.iter().map(|x| x.line).collect();
    assert_eq!(
        codes,
        [
            "E_STRICT_OPAQUE",
            "E_STRICT_UNIMPLEMENTED",
            "E_STRICT_SKIPPED",
            "E_STRICT_OPAQUE",
        ]
    );
    assert_eq!(lines, [Some(1), Some(2), Some(3), Some(4)]);
}

// ─── enforce_strict_mode: pedantic post-parse coverage gate ─────────────

#[test]
fn pedantic_flags_incomplete_analysis() {
    // A statement that parsed but whose analysis could not be completed is
    // recorded as an analysis limitation (not a skip). Pedantic — the
    // comprehensive coverage gate — must fail closed on it.
    let report = report_with_limitations(vec![limitation(
        7,
        "analysis_gave_up:statement:parsed:reason=not_analyzable",
    )]);
    let v = enforce_strict_mode(&report, &AnalysisOptions::pedantic());
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].code, "E_STRICT_INCOMPLETE_ANALYSIS");
    assert_eq!(v[0].line, Some(7));
    assert!(
        v[0].message.contains("not_analyzable") && v[0].message.contains('7'),
        "message should cite the marker and line: {:?}",
        v[0].message
    );
}

#[test]
fn pedantic_flags_skips_then_incomplete_analysis() {
    // Order invariant: parse/skip violations come first, post-parse
    // coverage-loss violations after, so CI output stays deterministic.
    let mut report = report_with_skips(vec![
        skip(SkipReason::UnparsedConstruct, 1, "A"),
        skip(SkipReason::UnimplementedStatementType, 2, "B"),
    ]);
    report.analysis_limitations = vec![limitation(5, "analysis_gave_up:reason=not_analyzable")];
    let v = enforce_strict_mode(&report, &AnalysisOptions::pedantic());
    assert_eq!(v.len(), 3);
    assert_eq!(v[0].code, "E_STRICT_OPAQUE");
    assert_eq!(v[1].code, "E_STRICT_UNIMPLEMENTED");
    assert_eq!(v[2].code, "E_STRICT_INCOMPLETE_ANALYSIS");
    assert_eq!(v[2].line, Some(5));
}

#[test]
fn pedantic_on_clean_report_is_empty() {
    // No skips, no limitations — pedantic must produce no violations.
    let report = AnalysisReport::new();
    let v = enforce_strict_mode(&report, &AnalysisOptions::pedantic());
    assert!(
        v.is_empty(),
        "pedantic() on clean report must produce no violations, got: {:?}",
        v.iter().map(|x| x.code).collect::<Vec<_>>()
    );
}

#[test]
fn pedantic_still_flags_skips() {
    // Pedantic does not weaken the skip checks inherited from strict.
    let report = report_with_skips(vec![skip(SkipReason::UnparsedConstruct, 1, "X")]);
    let v = enforce_strict_mode(&report, &AnalysisOptions::pedantic());
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].code, "E_STRICT_OPAQUE");
}

#[test]
fn strict_does_not_flag_incomplete_analysis() {
    // The post-parse coverage gate is exclusive to pedantic. `strict`
    // stays parse/skip-level so existing CI gates are not tightened
    // out from under their operators.
    let report = report_with_limitations(vec![limitation(
        3,
        "analysis_gave_up:reason=not_analyzable",
    )]);
    let v = enforce_strict_mode(&report, &AnalysisOptions::strict());
    assert!(
        v.is_empty(),
        "strict (Strict) must not flag post-parse analysis loss: {:?}",
        v.iter().map(|x| x.code).collect::<Vec<_>>()
    );
}

// ─── enforce_strict_mode: statements only partly parsed ─────────────────

#[test]
fn a_statement_only_partly_parsed_is_counted_and_passes_strict() {
    use lexega_core::analyzer::AnalysisConfig;
    use lexega_core::api::analyze_risk_with_policy_config;
    let analyze = |dialect: &str, sql: &str| {
        let config = AnalysisConfig {
            dialect: lexega_core::dialect::dialect_from_name(dialect),
            ..Default::default()
        };
        assert!(config.dialect.is_some(), "{dialect}");
        analyze_risk_with_policy_config(sql, &config).expect("analysis should succeed")
    };
    let mut cases = Vec::new();
    for dialect in [
        "snowflake",
        "postgresql",
        "mysql",
        "mssql",
        "bigquery",
        "databricks",
    ] {
        cases.push((dialect, "GRANT FROM users;"));
        cases.push((dialect, "ALTER TABLE users FROBNICATE x;"));
    }
    cases.push(("postgresql", "SELECT a grant FROM t;"));
    cases.push(("mysql", "SELECT a grant FROM t;"));
    cases.push(("mysql", "SELECT a revoke FROM t;"));
    cases.push((
        "postgresql",
        "CREATE FUNCTION f() RETURNS void LANGUAGE plpgsql AS $$ BEGIN GRANT FROM users; END $$;",
    ));
    for (dialect, sql) in cases {
        let report = analyze(dialect, sql);
        // Counted Partial, not skipped; no strictness refuses it.
        assert_eq!(report.summary.statements_partial, 1, "{dialect}: {sql}");
        assert_eq!(report.summary.statements_skipped, 0, "{dialect}: {sql}");
        for opts in [
            AnalysisOptions::default(),
            AnalysisOptions::strict(),
            AnalysisOptions::pedantic(),
        ] {
            let codes: Vec<_> = enforce_strict_mode(&report, &opts)
                .iter()
                .map(|x| x.code)
                .collect();
            assert!(codes.is_empty(), "{dialect}: {sql}: {codes:?}");
        }
    }
    // Valid statements whose action is kept as written, and statements
    // parsed in full, pass.
    for (dialect, sql) in [
        ("postgresql", "GRANT SELECT ON users TO r;"),
        ("mysql", "REVOKE SELECT ON users FROM r;"),
        ("snowflake", "ALTER TABLE users ADD COLUMN c INT;"),
        ("postgresql", "ALTER TABLE orders OWNER TO r;"),
        ("postgresql", "GRANT r TO u;"),
        ("postgresql", "REVOKE r FROM u;"),
        ("postgresql", "GRANT r TO u WITH ADMIN OPTION;"),
        (
            "postgresql",
            "ALTER TABLE orders ATTACH PARTITION orders_2024 FOR VALUES FROM (1) TO (2);",
        ),
        ("mssql", "ALTER TABLE dbo.orders NOCHECK CONSTRAINT ALL;"),
        (
            "mssql",
            "ALTER TABLE dbo.orders WITH CHECK CHECK CONSTRAINT ALL;",
        ),
        ("mssql", "ALTER TABLE dbo.orders REBUILD;"),
        ("mssql", "ALTER TABLE dbo.orders SWITCH TO dbo.archive;"),
        ("mysql", "ALTER TABLE orders ENGINE = InnoDB;"),
    ] {
        let report = analyze(dialect, sql);
        assert!(
            enforce_strict_mode(&report, &AnalysisOptions::strict()).is_empty(),
            "{dialect}: {sql}"
        );
    }
}

// ─── a statement cut at a token the parser does not bind ───────────────

#[test]
fn a_statement_cut_at_an_unbound_token_is_partial_and_its_tail_fails_strict() {
    use lexega_core::analyzer::{AnalysisConfig, ConfidenceLevel};
    use lexega_core::api::analyze_risk_with_policy_config;
    // MySQL's `:=` in an expression and PostgreSQL's postfix factorial `!`
    // are operators the parser does not read.
    for (dialect, sql) in [
        ("mysql", "DELETE FROM users WHERE id = @n := 1;"),
        (
            "postgresql",
            "UPDATE users SET flag = 1 WHERE id = 5 ! AND tenant = 2;",
        ),
        (
            "postgresql",
            "SELECT 1;\nUPDATE users SET flag = 5 ! WHERE id = 1;",
        ),
        (
            "postgresql",
            "CREATE FUNCTION f() RETURNS void LANGUAGE plpgsql AS $$ BEGIN UPDATE users SET flag = 1 WHERE id = 5 !; END $$",
        ),
    ] {
        let config = AnalysisConfig {
            dialect: lexega_core::dialect::dialect_from_name(dialect),
            ..Default::default()
        };
        let report = analyze_risk_with_policy_config(sql, &config).expect("analysis");
        assert_eq!(report.summary.statements_partial, 1, "{dialect}: {sql}");
        assert_eq!(report.summary.statements_skipped, 1, "{dialect}: {sql}");
        assert_eq!(
            report.summary.analysis_confidence,
            ConfidenceLevel::Medium,
            "{dialect}: {sql}"
        );
        let codes: Vec<_> = enforce_strict_mode(&report, &AnalysisOptions::strict())
            .iter()
            .map(|x| x.code)
            .collect();
        assert_eq!(codes, ["E_STRICT_OPAQUE"], "{dialect}: {sql}");
    }
}

// A statement read whole and followed, with no `;`, by a word, a label or a
// client directive is not partial.
#[test]
fn a_statement_ended_where_no_expression_continues_is_not_partial() {
    use lexega_core::analyzer::AnalysisConfig;
    use lexega_core::api::analyze_risk_with_policy_config;
    for (dialect, sql) in [
        ("mssql", "DELETE FROM users\nTHROW 50000, 'x', 1"),
        ("mssql", "UPDATE users SET a = 1\nKILL 52"),
        ("mssql", "DELETE FROM users\n:setvar x y"),
        ("mssql", "DELETE FROM users\n:r other.sql"),
        ("mssql", "DELETE FROM users\n$(Tail)"),
        ("mssql", "DELETE FROM users\nretry:\nPRINT 'x'"),
        (
            "mssql",
            ":setvar Env prod\nDELETE FROM dbo.staging\n:r .\\other.sql",
        ),
        ("mssql", "ALTER ROLE db_owner ADD MEMBER bob\n:setvar x y"),
        ("databricks", "DELETE FROM users\nOPTIMIZE users"),
        ("databricks", "DELETE FROM users\nVACUUM users"),
        (
            "mssql",
            "CREATE PROCEDURE p AS BEGIN DELETE FROM users\nTHROW 50000, 'x', 1; END",
        ),
    ] {
        let config = AnalysisConfig {
            dialect: lexega_core::dialect::dialect_from_name(dialect),
            ..Default::default()
        };
        let report = analyze_risk_with_policy_config(sql, &config).expect("analysis");
        assert_eq!(report.summary.statements_partial, 0, "{dialect}: {sql}");
    }
}

// ─── T-SQL statements that end where they are read in full ─────────────

/// The rule ids a T-SQL `sql` raises, and the `--strict` codes it fails with.
fn tsql_rules_and_strict(sql: &str) -> (Vec<String>, Vec<&'static str>) {
    use lexega_core::analyzer::AnalysisConfig;
    use lexega_core::api::analyze_risk_with_policy_config;
    let config = AnalysisConfig {
        dialect: lexega_core::dialect::dialect_from_name("mssql"),
        ..Default::default()
    };
    let report = analyze_risk_with_policy_config(sql, &config).expect("analysis");
    let rules = report
        .findings
        .iter()
        .filter_map(|s| s.rule_id())
        .map(str::to_string)
        .collect();
    let codes = enforce_strict_mode(&report, &AnalysisOptions::strict())
        .iter()
        .map(|x| x.code)
        .collect();
    (rules, codes)
}

// `OPTION (…)` query hints end a DELETE, UPDATE or MERGE: the statement is
// read whole, an unbounded write is reported and a bounded one is not.
#[test]
fn a_dml_statement_with_query_hints_is_read_whole() {
    for (sql, rule, raised) in [
        ("DELETE FROM users OPTION (MAXDOP 1)", "DML-WRITE-UNBOUNDED", true),
        (
            "DELETE FROM users WHERE id = 1 OPTION (MAXDOP 1)",
            "DML-WRITE-UNBOUNDED",
            false,
        ),
        ("UPDATE users SET a = 1 OPTION (RECOMPILE)", "DML-WRITE-UNBOUNDED", true),
        // The inner join bounds the rows written; the outer join keeps
        // every row of `u`.
        (
            "UPDATE u SET a = 1 FROM users u JOIN orders o ON o.id = u.id OPTION (RECOMPILE)",
            "DML-WRITE-UNBOUNDED",
            false,
        ),
        (
            "UPDATE u SET a = 1 FROM users u LEFT JOIN orders o ON o.id = u.id OPTION (RECOMPILE)",
            "DML-WRITE-UNBOUNDED",
            true,
        ),
        (
            "MERGE users AS t USING orders AS s ON t.id = s.id WHEN MATCHED THEN DELETE OPTION (MAXDOP 1);",
            "DML-MERGE-DELETE",
            true,
        ),
    ] {
        let (rules, codes) = tsql_rules_and_strict(sql);
        assert_eq!(rules.iter().any(|r| r == rule), raised, "{sql}: {rules:?}");
        assert!(codes.is_empty(), "{sql}: {codes:?}");
    }
}

// CHECKPOINT, KILL and SHUTDOWN are statements of their own: one after a
// DELETE with no `;` leaves the DELETE whole, and each passes `--strict`.
#[test]
fn a_tsql_server_command_is_a_statement() {
    for (sql, unbounded) in [
        ("DELETE FROM users\nCHECKPOINT", true),
        ("CHECKPOINT 10", false),
        ("KILL 52", false),
        ("KILL 52 WITH STATUSONLY", false),
        ("SHUTDOWN", false),
        ("SHUTDOWN WITH NOWAIT", false),
        (
            "CREATE PROCEDURE p AS BEGIN DELETE FROM users\nCHECKPOINT\nEND",
            true,
        ),
    ] {
        let (rules, codes) = tsql_rules_and_strict(sql);
        assert_eq!(
            rules.iter().any(|r| r == "DML-WRITE-UNBOUNDED"),
            unbounded,
            "{sql}: {rules:?}"
        );
        assert!(codes.is_empty(), "{sql}: {codes:?}");
    }
}

// ─── enforce_strict_mode: T-SQL batch separators ────────────────────────

#[test]
fn strict_passes_a_go_line_with_comments() {
    use lexega_core::analyzer::AnalysisConfig;
    use lexega_core::api::analyze_risk_with_policy_config;
    for go in [
        "GO /* deploy step 2 */",
        "/* deploy step 2 */ GO",
        "GO 2 /* a */ -- b",
    ] {
        let sql = format!("SELECT 1;\n{go}\nUPDATE dbo.Orders SET Status = 0 WHERE id = 1;");
        let config = AnalysisConfig {
            dialect: lexega_core::dialect::dialect_from_name("mssql"),
            ..Default::default()
        };
        let report = analyze_risk_with_policy_config(&sql, &config).expect("analysis");
        assert_eq!(report.summary.statements_skipped, 0, "{sql}");
        let codes: Vec<_> = enforce_strict_mode(&report, &AnalysisOptions::strict())
            .iter()
            .map(|x| x.code)
            .collect();
        assert!(codes.is_empty(), "{sql}: {codes:?}");
    }
}

// ─── StrictMode::as_str labels ──────────────────────────────────────────

#[test]
fn strict_mode_labels_stay_neutral() {
    // These strings end up in logs / error messages / serialized output.
    // Guard against anyone sneaking internal terminology back in.
    assert_eq!(StrictMode::Permissive.as_str(), "off");
    assert_eq!(StrictMode::Strict.as_str(), "strict");
    assert_eq!(StrictMode::Pedantic.as_str(), "pedantic");

    for m in [
        StrictMode::Permissive,
        StrictMode::Strict,
        StrictMode::Pedantic,
    ] {
        let s = m.as_str().to_lowercase();
        assert!(
            !s.contains("ir") && !s.contains("relplan") && !s.contains("phase"),
            "StrictMode label {:?} leaks internal terminology",
            m.as_str()
        );
    }
}

#[test]
fn strict_mode_labels_round_trip_through_parser() {
    // `as_str()` output must parse back into the same variant — this
    // keeps serialized configs stable across releases.
    for m in [
        StrictMode::Permissive,
        StrictMode::Strict,
        StrictMode::Pedantic,
    ] {
        let parsed = parse_strict_mode(m.as_str()).expect("as_str must be parseable");
        assert_eq!(parsed, m, "round-trip failed for {:?}", m.as_str());
    }
}

// A sqlcmd command that runs what the analysis did not read — an included
// file, a batch sent to another server, an operating-system command, the
// editor, `:exit(query)` — counts as skipped, says what it runs, lowers
// confidence and fails `--strict`, quoting no more of its line than the
// command and the file or server it names. A command that sets the
// client's state passes.
#[test]
fn a_sqlcmd_command_that_runs_what_was_not_read_fails_strict() {
    use lexega_core::analyzer::{AnalysisConfig, ConfidenceLevel, SqlcmdUnread};
    use lexega_core::api::analyze_risk_with_policy_config;
    let config = AnalysisConfig {
        dialect: lexega_core::dialect::dialect_from_name("mssql"),
        ..Default::default()
    };
    for (line, runs, quoted) in [
        (
            ":r .\\Tables\\DropEverything.sql",
            SqlcmdUnread::IncludedFile,
            ":r .",
        ),
        (
            ":connect srv\\inst -U sa -P Hunter2Secret",
            SqlcmdUnread::OtherServer,
            ":connect srv",
        ),
        ("!! del /q Hunter2Secret", SqlcmdUnread::OsCommand, "!!"),
        (":!! dir Hunter2Secret", SqlcmdUnread::OsCommand, ":!!"),
        (":ED", SqlcmdUnread::EditedBatch, ":ED"),
        (
            ":EXIT(SELECT COUNT(*) FROM dbo.t WHERE k = 'Hunter2Secret')",
            SqlcmdUnread::ExitQuery,
            // The query is sent unread, so only the command is shown.
            ":EXIT",
        ),
    ] {
        let sql = format!("{line}\nGO\nSELECT a FROM dbo.t\nGO\n");
        let report = analyze_risk_with_policy_config(&sql, &config).expect("analysis");
        assert_eq!(report.summary.statements_skipped, 1, "{sql}");
        assert_eq!(report.summary.statements_analyzed, 1, "{sql}");
        assert_eq!(
            report.summary.analysis_confidence,
            ConfidenceLevel::Medium,
            "{sql}"
        );
        assert_eq!(report.skipped_details.len(), 1, "{sql}");
        let skipped = &report.skipped_details[0];
        assert_eq!(skipped.reason, SkipReason::SqlcmdCommand(runs), "{sql}");
        assert_eq!(skipped.line_number, 1, "{sql}");
        assert!(
            skipped.statement_prefix.starts_with(quoted),
            "{sql}: {}",
            skipped.statement_prefix
        );
        // Nothing of an `:exit` query is quoted.
        assert!(
            !skipped.statement_prefix.contains("COUNT"),
            "{sql}: {}",
            skipped.statement_prefix
        );
        let violations = enforce_strict_mode(&report, &AnalysisOptions::strict());
        let codes: Vec<_> = violations.iter().map(|v| v.code).collect();
        assert_eq!(codes, ["E_STRICT_NOT_READ"], "{sql}");
        assert!(
            violations[0].message.contains(runs.describe()),
            "{sql}: {}",
            violations[0].message
        );
        let json = serde_json::to_string(&report).expect("json");
        assert!(!json.contains("Hunter2Secret"), "{sql}: {json}");
        let messages: String = violations.iter().map(|v| v.message.as_str()).collect();
        assert!(!messages.contains("Hunter2Secret"), "{sql}: {messages}");
    }
    for line in [
        ":setvar Db Prod",
        ":on error exit",
        ":List",
        ":listvar",
        ":out C:\\log.txt",
        ":error STDOUT",
        ":perftrace STDERR",
        ":xml ON",
        ":help",
        ":reset",
        ":serverlist",
        ":quit",
        ":exit",
        ":exit()",
    ] {
        let sql = format!("{line}\nGO\nSELECT a FROM dbo.t\nGO\n");
        let report = analyze_risk_with_policy_config(&sql, &config).expect("analysis");
        assert_eq!(report.summary.statements_skipped, 0, "{sql}");
        assert_eq!(
            report.summary.analysis_confidence,
            ConfidenceLevel::High,
            "{sql}"
        );
        assert!(
            enforce_strict_mode(&report, &AnalysisOptions::strict()).is_empty(),
            "{sql}"
        );
    }
}
