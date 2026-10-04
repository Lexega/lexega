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
    /// semantics via [`crate::rules::build_v1_rule_corpus`]).
    pub custom_rules: Option<Vec<crate::rules::Rule>>,

    /// Full trace mode - no truncation of evaluated rules (default: false)
    pub trace_mode: bool,

    /// Verbose mode - show rules that almost matched (missing signals only)
    pub verbose_mode: bool,

    /// Session database (from dbt profiles.yml or explicit config)
    /// Falls back to LEXEGA_CTX_DB / SNOWFLAKE_DB env var if not set
    pub session_db: Option<String>,

    /// Session schema (from dbt profiles.yml or explicit config)
    /// Falls back to LEXEGA_CTX_SCHEMA / SNOWFLAKE_SCHEMA env var if not set
    pub session_schema: Option<String>,

    /// SQL dialect for tokenization and parsing (defaults to Snowflake)
    pub dialect: Option<crate::dialect::DialectRef>,
}
