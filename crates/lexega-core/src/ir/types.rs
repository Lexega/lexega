// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Cross-cutting IR types that don't belong to a single analysis.

/// Session-level defaults (database, schema) used to qualify unqualified
/// table references during lowering and analysis.
///
/// Derived from environment variables, dbt profile defaults, or explicit
/// `USE DATABASE` / `USE SCHEMA` script effects.
#[derive(Debug, Clone, Default)]
pub struct SessionContext {
    pub db: Option<String>,
    pub schema: Option<String>,
}

impl SessionContext {
    /// Read an env var with trimming, returning None if empty or unset.
    fn read_env(name: &str) -> Option<String> {
        std::env::var(name)
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    }

    /// Create SessionContext from environment variables.
    ///
    /// Precedence: `LEXEGA_CTX_DB` > `SNOWFLAKE_DB` (backward compat).
    /// Same for schema: `LEXEGA_CTX_SCHEMA` > `SNOWFLAKE_SCHEMA`.
    pub fn from_env() -> Self {
        let db = Self::read_env("LEXEGA_CTX_DB").or_else(|| Self::read_env("SNOWFLAKE_DB"));

        let schema =
            Self::read_env("LEXEGA_CTX_SCHEMA").or_else(|| Self::read_env("SNOWFLAKE_SCHEMA"));

        Self { db, schema }
    }
}
