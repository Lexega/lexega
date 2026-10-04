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
