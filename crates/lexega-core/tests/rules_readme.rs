// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! The counts `rules/README.md` states are the corpus's own.

use lexega_core::facts::RiskLevel;
use lexega_core::rules::all_builtin_rules;

const README: &str = include_str!("../../../rules/README.md");

#[test]
fn the_readme_states_the_corpus_as_it_is() {
    let rules = all_builtin_rules().expect("corpus loads");
    let at = |level: RiskLevel| rules.iter().filter(|r| r.risk_level == level).count();
    let statements = [
        format!("{} predicates over", rules.len()),
        format!(
            "{} critical, {} high, {} medium, {} low, {} info",
            at(RiskLevel::Critical),
            at(RiskLevel::High),
            at(RiskLevel::Medium),
            at(RiskLevel::Low),
            at(RiskLevel::Info)
        ),
        format!(
            "{} rules read a fact",
            rules
                .iter()
                .filter(|r| r.triggers.reads_reasoning())
                .count()
        ),
        format!(
            "{} rules (`DIFF-*`)",
            rules.iter().filter(|r| r.id.starts_with("DIFF-")).count()
        ),
    ];
    for statement in statements {
        assert!(
            README.contains(&statement),
            "rules/README.md should say: {statement}"
        );
    }
}

/// The list `rules/README.md` gives of the rules that read a fact needing
/// analysis: the `` - `ID` `` lines of its block opened by `summary`.
fn listed_under(summary: &str) -> Vec<String> {
    README
        .split_once(summary)
        .map(|(_, after)| after)
        .and_then(|after| after.split_once("</details>"))
        .map(|(block, _)| {
            block
                .lines()
                .filter_map(|line| line.strip_prefix("- `")?.strip_suffix('`'))
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

#[test]
fn the_readme_lists_each_rule_that_reads_analysis() {
    let rules = all_builtin_rules().expect("corpus loads");
    let mut expected: Vec<String> = rules
        .iter()
        .filter(|r| r.triggers.reads_reasoning())
        .map(|r| r.id.clone())
        .collect();
    expected.sort();
    let summary = format!(
        "<summary>The {} rules that read a fact needing analysis</summary>",
        expected.len()
    );
    let block: String = expected.iter().map(|id| format!("- `{id}`\n")).collect();
    assert_eq!(
        listed_under(&summary),
        expected,
        "rules/README.md should list, after {summary}:\n\n{block}"
    );
}
