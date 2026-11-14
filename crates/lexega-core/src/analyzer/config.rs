// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Per-run analysis configuration.

/// Configuration for analyzer behavior and custom rules
#[derive(Debug, Clone, Default)]
pub struct AnalysisConfig {
    /// Pre-merged v1 rule corpus: built-ins (when not suppressed via
    /// `--no-builtin`) layered with any `--custom-rules` entries.
    /// `None` falls back to [`crate::rules::all_builtin_rules`]; `Some`
    /// is the authoritative corpus the analyzer evaluates against
    /// (caller has already honoured `--no-builtin` and override-by-id
    /// semantics via [`crate::rules::build_v1_rule_corpus`]). Shared:
    /// a configuration built per file holds the run's one corpus.
    pub custom_rules: Option<std::sync::Arc<[crate::rules::Rule]>>,

    /// Full trace mode - no truncation of evaluated rules (default: false)
    pub trace_mode: bool,

    /// Verbose mode - show rules that almost matched
    pub verbose_mode: bool,

    /// The database a bare table name resolves in until a `USE` of the
    /// script sets another; `None` leaves it to the script and the catalog.
    pub session_db: Option<String>,

    /// The schema a bare table name resolves in until a `USE` of the
    /// script sets another; `None` leaves it to the script and the catalog.
    pub session_schema: Option<String>,

    /// SQL dialect for tokenization and parsing (defaults to Snowflake)
    pub dialect: Option<crate::dialect::DialectRef>,

    /// The dialects' function catalogs the analysis reads, each built
    /// once and shared by every clone of this configuration: a run that
    /// builds each file's configuration from one value builds each
    /// catalog once.
    pub function_catalogs: crate::ir::DialectCatalogs,

    /// The organization's masking policy, from its rule file's `masking:`
    /// ([`crate::rules::LoadedRuleset::masking`]); empty by default.
    pub masking: std::sync::Arc<crate::rules::MaskingPolicy>,
}
