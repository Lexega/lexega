// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Dialect-aware identifier normalization for case-sensitivity handling.
//!
//! This module provides identifier normalization that respects each SQL dialect's
//! case-sensitivity rules. Proper normalization is critical for accurate identifier
//! matching across CTEs, aliases, table references, and column lineage tracking.
//!
//! # Dialect Case-Sensitivity Rules
//!
//! | Dialect     | Unquoted identifiers        | Quoted identifiers          | Quote char  |
//! |-------------|-----------------------------|-----------------------------|-------------|
//! | Snowflake   | Case-insensitive → UPPERCASE | Case-sensitive (preserve)   | `"..."`     |
//! | PostgreSQL  | Case-insensitive → lowercase | Case-sensitive (preserve)   | `"..."`     |
//! | Redshift    | Case-insensitive → lowercase | Case-sensitive (preserve)   | `"..."`     |
//! | MySQL       | Case-insensitive → UPPERCASE | Case-sensitive (preserve)   | `` `...` `` |
//! | BigQuery    | Case-insensitive → UPPERCASE | Case-sensitive (preserve)   | `` `...` `` |
//! | Databricks  | Case-insensitive → lowercase | Case-insensitive (fold)      | `` `...` `` |
//! | MSSQL       | Case-insensitive → UPPERCASE | Case-sensitive (preserve)   | `"..."` / `[...]` |
//!
//! # Functionality
//!
//! ## Primary Functions
//! - [`normalize_identifier`] - Normalize identifier for comparison (dialect-aware)
//! - [`set_normalization_dialect`] - Set the active dialect for normalization
//!
//! ## Normalization Config
//! - [`NormalizationConfig`] - Captures fold direction and quote styles per dialect
//! - Settable via [`set_normalization_dialect`] or `LEXEGA_IDENTIFIER_CASE` env var
//!
//! # Environment Variables
//!
//! - `LEXEGA_IDENTIFIER_CASE`:
//!   - `"ignore_quoted"`: Treat quoted identifiers as case-insensitive
//!   - Any other value or unset: use dialect default

use std::cell::Cell;

/// How unquoted identifiers are case-folded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaseFold {
    /// Fold to UPPERCASE (Snowflake, BigQuery, MySQL, MSSQL)
    Upper,
    /// Fold to lowercase (PostgreSQL, Databricks)
    Lower,
}

/// Whether quoted identifiers should be treated as case-insensitive.
/// Corresponds to Snowflake's QUOTED_IDENTIFIERS_IGNORE_CASE session parameter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuotedHandling {
    /// Quoted identifiers are case-sensitive (default for all dialects)
    CaseSensitive,
    /// Quoted identifiers are case-insensitive (e.g., QUOTED_IDENTIFIERS_IGNORE_CASE=TRUE)
    CaseInsensitive,
}

/// Full normalization configuration derived from dialect + env overrides.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NormalizationConfig {
    /// How to fold unquoted identifiers
    pub fold: CaseFold,
    /// Whether quoted identifiers preserve case or are folded
    pub quoted: QuotedHandling,
    /// Whether `"..."` is an identifier quote (Snowflake, PostgreSQL, MSSQL)
    pub double_quote_is_identifier: bool,
    /// Whether `` `...` `` is an identifier quote (BigQuery, MySQL, Databricks)
    pub backtick_is_identifier: bool,
    /// Whether `[...]` is an identifier quote (MSSQL)
    pub bracket_is_identifier: bool,
}

impl Default for NormalizationConfig {
    fn default() -> Self {
        // Snowflake defaults
        Self {
            fold: CaseFold::Upper,
            quoted: QuotedHandling::CaseSensitive,
            double_quote_is_identifier: true,
            backtick_is_identifier: false,
            bracket_is_identifier: false,
        }
    }
}

impl NormalizationConfig {
    /// Create a normalization config for a given dialect name.
    pub fn from_dialect(name: &str) -> Self {
        match name.to_ascii_lowercase().as_str() {
            "postgresql" | "postgres" | "pg" => Self {
                fold: CaseFold::Lower,
                quoted: QuotedHandling::CaseSensitive,
                double_quote_is_identifier: true,
                backtick_is_identifier: false,
                bracket_is_identifier: false,
            },
            // Redshift is forked from PostgreSQL: unquoted identifiers fold to
            // lowercase, quoted identifiers preserve case, `"..."` is a quote.
            "redshift" | "rs" => Self {
                fold: CaseFold::Lower,
                quoted: QuotedHandling::CaseSensitive,
                double_quote_is_identifier: true,
                backtick_is_identifier: false,
                bracket_is_identifier: false,
            },
            "mysql" => Self {
                fold: CaseFold::Upper,
                // MySQL: case sensitivity depends on lower_case_table_names server
                // variable and OS. Backticks don't control case. CaseSensitive
                // is the safer default (preserves case for backtick-quoted names).
                quoted: QuotedHandling::CaseSensitive,
                double_quote_is_identifier: false, // MySQL "..." is a string literal
                backtick_is_identifier: true,
                bracket_is_identifier: false,
            },
            "bigquery" | "bq" => Self {
                fold: CaseFold::Upper,
                // BigQuery: column/alias names are case-insensitive, but table names
                // are case-sensitive by default (unless is_case_insensitive=TRUE).
                // Backticks don't control case — they're for reserved words/special chars.
                // We use CaseSensitive here so backtick-quoted table names preserve case
                // for catalog matching, which is the safer default.
                // Ref: https://cloud.google.com/bigquery/docs/reference/standard-sql/lexical#case_sensitivity
                quoted: QuotedHandling::CaseSensitive,
                double_quote_is_identifier: false, // BigQuery "..." is a string literal
                backtick_is_identifier: true,
                bracket_is_identifier: false,
            },
            "databricks" | "spark" => Self {
                fold: CaseFold::Lower,
                // Databricks: "Identifiers are case-insensitive when referenced"
                // Backticks are for special chars/reserved words, not case control.
                // Unity Catalog stores all object names as lowercase.
                // Ref: https://docs.databricks.com/en/sql/language-manual/sql-ref-identifiers.html
                quoted: QuotedHandling::CaseInsensitive,
                double_quote_is_identifier: false, // Databricks "..." is a string literal
                backtick_is_identifier: true,
                bracket_is_identifier: false,
            },
            "mssql" | "tsql" | "sqlserver" => Self {
                fold: CaseFold::Upper,
                // MSSQL: case sensitivity is collation-dependent, not quote-dependent.
                // [brackets] and "double quotes" are for reserved words, not case control.
                // CaseSensitive is the safer default (preserves case for quoted names).
                quoted: QuotedHandling::CaseSensitive,
                double_quote_is_identifier: true,
                backtick_is_identifier: false,
                bracket_is_identifier: true,
            },
            // Snowflake is the default
            _ => Self::default(),
        }
    }

    /// Apply environment variable overrides (e.g., QUOTED_IDENTIFIERS_IGNORE_CASE).
    fn with_env_overrides(mut self) -> Self {
        if let Ok(raw) = std::env::var("LEXEGA_IDENTIFIER_CASE") {
            match raw.trim().to_ascii_lowercase().as_str() {
                "ignore_quoted" | "quoted_ignore_case" | "ignore-quoted" => {
                    self.quoted = QuotedHandling::CaseInsensitive;
                }
                _ => {}
            }
        }
        self
    }
}

// Per-thread normalization config — each analysis thread gets its own copy.
//
// Using `thread_local!` instead of a process-wide `RwLock` because:
// 1. `normalize_identifier()` is called from `Hash`/`Eq`/`PartialEq` trait impls
//    on `IdentKey`, `TableRef`, `ColumnRef` — these have fixed signatures that
//    cannot accept a config parameter.
// 2. Parallel dbt model analysis runs on separate threads — a global `RwLock`
//    lets one thread's dialect config overwrite another's mid-extraction.
// 3. `thread_local!` gives each thread independent state with zero contention.
thread_local! {
    static NORM_CONFIG: Cell<Option<NormalizationConfig>> = const { Cell::new(None) };
}

/// Reset the cached normalization config. Called when dialect changes (for tests).
pub fn reset_identifier_case_mode_cache() {
    NORM_CONFIG.set(None);
}

/// Set the normalization dialect for identifier case handling.
///
/// This should be called once at the start of an analysis run, before any
/// calls to [`normalize_identifier`]. It configures fold direction and
/// quote character recognition based on the dialect.
///
/// Thread-safe: each thread has its own config via `thread_local!`.
pub fn set_normalization_dialect(dialect_name: &str) {
    let config = NormalizationConfig::from_dialect(dialect_name).with_env_overrides();
    NORM_CONFIG.set(Some(config));
}

fn read_normalization_config() -> NormalizationConfig {
    let cached = NORM_CONFIG.get();
    if let Some(config) = cached {
        return config;
    }

    // First access on this thread: derive from env vars (legacy compat) and cache
    let config = NormalizationConfig::default().with_env_overrides();
    NORM_CONFIG.set(Some(config));
    config
}

/// Check whether the `LEXEGA_IDENTIFIER_CASE=ignore_quoted` override is active.
///
/// This is used by `CatalogProvider::normalize_identifier()` to stay in sync
/// with the normalization engine — when `ignore_quoted` is set, even quoted
/// identifiers should be case-folded.
pub fn is_ignore_quoted_active() -> bool {
    let config = read_normalization_config();
    config.quoted == QuotedHandling::CaseInsensitive
}

/// Normalize an identifier for case-insensitive comparison.
///
/// Dialect-aware: recognizes double-quote, backtick, and bracket quoting
/// styles and folds unquoted identifiers according to the active dialect
/// (UPPERCASE for Snowflake/BigQuery/MySQL/MSSQL, lowercase for PostgreSQL/Databricks).
///
/// Quoted identifiers preserve case by default. Set `LEXEGA_IDENTIFIER_CASE=ignore_quoted`
/// to fold them as well (mirrors Snowflake's QUOTED_IDENTIFIERS_IGNORE_CASE).
///
/// Returns the normalized identifier (quotes stripped if present).
#[inline]
pub fn normalize_identifier(name: &str) -> String {
    let config = read_normalization_config();

    // Detect quoting style and strip delimiters
    let is_double_quoted =
        config.double_quote_is_identifier && name.starts_with('"') && name.ends_with('"');
    let is_backtick_quoted =
        config.backtick_is_identifier && name.starts_with('`') && name.ends_with('`');
    let is_bracket_quoted =
        config.bracket_is_identifier && name.starts_with('[') && name.ends_with(']');
    let (inner, is_quoted) =
        if name.len() >= 2 && (is_double_quoted || is_backtick_quoted || is_bracket_quoted) {
            (&name[1..name.len() - 1], true)
        } else {
            (name, false)
        };

    if is_quoted && config.quoted == QuotedHandling::CaseSensitive {
        // Case-sensitive: preserve original case
        inner.to_string()
    } else {
        // Case-insensitive: fold according to dialect
        match config.fold {
            CaseFold::Upper => inner.to_ascii_uppercase(),
            CaseFold::Lower => inner.to_ascii_lowercase(),
        }
    }
}
