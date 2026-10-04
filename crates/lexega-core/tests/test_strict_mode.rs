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
        signals_extracted: None,
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
