// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Catalog provider abstraction.
//!
//! Each data platform (Snowflake, BigQuery, Databricks, PostgreSQL, etc.) has
//! its own identifier quoting convention, hierarchy shape, and feature surface.
//! The [`CatalogProvider`] trait encodes those differences so the rest of the
//! analysis engine stays platform-agnostic.

use std::fmt;
use std::sync::Arc;

// ---------------------------------------------------------------------------
// Unquoted identifier normalization
// ---------------------------------------------------------------------------

/// How a platform normalizes unquoted SQL identifiers.
///
/// This determines the `key()` normalization used when building catalog indexes
/// and performing lookups.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UnquotedIdentCase {
    /// Unquoted identifiers → UPPERCASE (Snowflake, Oracle, DB2).
    Upper,
    /// Unquoted identifiers → lowercase (PostgreSQL, Redshift).
    Lower,
    /// Unquoted identifiers → preserve original case (BigQuery, MySQL, Databricks).
    Preserve,
}

// ---------------------------------------------------------------------------
// CatalogProvider trait
// ---------------------------------------------------------------------------

/// Platform-specific behavior for catalog integration.
///
/// Implementors describe how identifiers are normalised, what features the
/// platform supports, and which sidecar binary handles snapshot extraction.
pub trait CatalogProvider: Send + Sync + fmt::Debug {
    /// Canonical lowercase name (e.g., `"snowflake"`, `"bigquery"`).
    fn name(&self) -> &str;

    /// Human-readable display name (e.g., `"Snowflake"`, `"BigQuery"`).
    fn display_name(&self) -> &str;

    /// How unquoted identifiers are normalised on this platform.
    fn unquoted_ident_case(&self) -> UnquotedIdentCase;

    /// Normalize an identifier according to this platform's rules.
    ///
    /// - If the identifier is quoted (starts/ends with `"` or `` ` ``), the
    ///   quotes are stripped and the inner text is preserved verbatim — **unless**
    ///   `LEXEGA_IDENTIFIER_CASE=ignore_quoted` is set, in which case quoted
    ///   identifiers are also case-folded (mirrors Snowflake's
    ///   `QUOTED_IDENTIFIERS_IGNORE_CASE` setting).
    /// - Otherwise, the identifier is folded according to [`unquoted_ident_case`](Self::unquoted_ident_case).
    fn normalize_identifier(&self, ident: &str) -> String {
        let trimmed = ident.trim();
        let (inner, was_quoted) = strip_quoting(trimmed);
        if was_quoted && !ignore_quoted_case_active() {
            inner.to_string()
        } else {
            match self.unquoted_ident_case() {
                UnquotedIdentCase::Upper => inner.to_ascii_uppercase(),
                UnquotedIdentCase::Lower => inner.to_ascii_lowercase(),
                UnquotedIdentCase::Preserve => inner.to_string(),
            }
        }
    }

    /// Whether the platform uses a three-level `database.schema.table` hierarchy.
    ///
    /// If `false`, the "database" level is typically called "project" (BigQuery)
    /// or "catalog" (Databricks) and may be optional.
    fn supports_database_hierarchy(&self) -> bool {
        true
    }

    /// Whether the platform has a GRANT/REVOKE role-based access model that
    /// the catalog snapshot can capture.
    fn supports_grants(&self) -> bool {
        false
    }

    /// Whether the platform has masking / row-access / aggregation / projection
    /// policies that the catalog snapshot can capture.
    fn supports_policies(&self) -> bool {
        false
    }

    /// Whether the platform supports constraint metadata (PK, FK, UNIQUE) in
    /// its information schema.
    fn supports_constraints(&self) -> bool {
        true
    }

    /// Name of the sidecar binary `catalog pull` runs for this platform.
    fn sidecar_binary(&self) -> &str;
}

// ---------------------------------------------------------------------------
// Built-in providers
// ---------------------------------------------------------------------------

/// Snowflake – uppercase unquoted, full grant/policy support.
#[derive(Debug, Clone)]
pub struct SnowflakeCatalogProvider;

impl CatalogProvider for SnowflakeCatalogProvider {
    fn name(&self) -> &str {
        "snowflake"
    }
    fn display_name(&self) -> &str {
        "Snowflake"
    }
    fn unquoted_ident_case(&self) -> UnquotedIdentCase {
        UnquotedIdentCase::Upper
    }
    fn supports_grants(&self) -> bool {
        true
    }
    fn supports_policies(&self) -> bool {
        true
    }
    fn sidecar_binary(&self) -> &str {
        "lexega-sf-catalog"
    }
}

/// PostgreSQL – lowercase unquoted, constraints but no policy objects.
#[derive(Debug, Clone)]
pub struct PostgresCatalogProvider;

impl CatalogProvider for PostgresCatalogProvider {
    fn name(&self) -> &str {
        "postgresql"
    }
    fn display_name(&self) -> &str {
        "PostgreSQL"
    }
    fn unquoted_ident_case(&self) -> UnquotedIdentCase {
        UnquotedIdentCase::Lower
    }
    fn supports_grants(&self) -> bool {
        true
    }
    fn supports_policies(&self) -> bool {
        false
    }
    fn sidecar_binary(&self) -> &str {
        "lexega-pg-catalog"
    }
}

/// BigQuery – case-preserving, dataset-level ACLs (no SQL GRANT).
#[derive(Debug, Clone)]
pub struct BigQueryCatalogProvider;

impl CatalogProvider for BigQueryCatalogProvider {
    fn name(&self) -> &str {
        "bigquery"
    }
    fn display_name(&self) -> &str {
        "BigQuery"
    }
    fn unquoted_ident_case(&self) -> UnquotedIdentCase {
        UnquotedIdentCase::Preserve
    }
    fn supports_grants(&self) -> bool {
        false
    }
    fn supports_policies(&self) -> bool {
        false
    }
    fn supports_constraints(&self) -> bool {
        false
    }
    fn sidecar_binary(&self) -> &str {
        "lexega-bq-catalog"
    }
}

/// Databricks (Unity Catalog) – case-preserving, three-level hierarchy.
/// Supports row filters and column masks via Unity Catalog table detail API.
#[derive(Debug, Clone)]
pub struct DatabricksCatalogProvider;

impl CatalogProvider for DatabricksCatalogProvider {
    fn name(&self) -> &str {
        "databricks"
    }
    fn display_name(&self) -> &str {
        "Databricks"
    }
    fn unquoted_ident_case(&self) -> UnquotedIdentCase {
        UnquotedIdentCase::Preserve
    }
    fn supports_grants(&self) -> bool {
        true
    }
    fn supports_policies(&self) -> bool {
        true
    }
    fn supports_constraints(&self) -> bool {
        false
    }
    fn sidecar_binary(&self) -> &str {
        "lexega-dbx-catalog"
    }
}

/// MySQL – case-preserving (table names are OS-dependent, but we default to
/// preserve to avoid data loss).
#[derive(Debug, Clone)]
pub struct MySqlCatalogProvider;

impl CatalogProvider for MySqlCatalogProvider {
    fn name(&self) -> &str {
        "mysql"
    }
    fn display_name(&self) -> &str {
        "MySQL"
    }
    fn unquoted_ident_case(&self) -> UnquotedIdentCase {
        UnquotedIdentCase::Preserve
    }
    fn supports_grants(&self) -> bool {
        true
    }
    fn supports_policies(&self) -> bool {
        false
    }
    fn sidecar_binary(&self) -> &str {
        "lexega-mysql-catalog"
    }
}

/// Microsoft SQL Server – uppercase unquoted (like Snowflake).
#[derive(Debug, Clone)]
pub struct MsSqlCatalogProvider;

impl CatalogProvider for MsSqlCatalogProvider {
    fn name(&self) -> &str {
        "mssql"
    }
    fn display_name(&self) -> &str {
        "SQL Server"
    }
    fn unquoted_ident_case(&self) -> UnquotedIdentCase {
        UnquotedIdentCase::Upper
    }
    fn supports_grants(&self) -> bool {
        true
    }
    fn supports_policies(&self) -> bool {
        false
    }
    fn sidecar_binary(&self) -> &str {
        "lexega-mssql-catalog"
    }
}

/// Redshift – lowercase unquoted (like PostgreSQL).
#[derive(Debug, Clone)]
pub struct RedshiftCatalogProvider;

impl CatalogProvider for RedshiftCatalogProvider {
    fn name(&self) -> &str {
        "redshift"
    }
    fn display_name(&self) -> &str {
        "Redshift"
    }
    fn unquoted_ident_case(&self) -> UnquotedIdentCase {
        UnquotedIdentCase::Lower
    }
    fn supports_grants(&self) -> bool {
        true
    }
    fn supports_policies(&self) -> bool {
        false
    }
    fn sidecar_binary(&self) -> &str {
        "lexega-rs-catalog"
    }
}

// ---------------------------------------------------------------------------
// Provider registry
// ---------------------------------------------------------------------------

/// Look up a built-in provider by name (case-insensitive).
///
/// Returns `None` for unknown names — the caller can fall back to a default or
/// report an error.
pub fn provider_by_name(name: &str) -> Option<Arc<dyn CatalogProvider>> {
    match name.to_ascii_lowercase().as_str() {
        "snowflake" | "sf" => Some(Arc::new(SnowflakeCatalogProvider)),
        "postgresql" | "postgres" | "pg" => Some(Arc::new(PostgresCatalogProvider)),
        "bigquery" | "bq" => Some(Arc::new(BigQueryCatalogProvider)),
        "databricks" | "dbx" | "unity" => Some(Arc::new(DatabricksCatalogProvider)),
        "mysql" => Some(Arc::new(MySqlCatalogProvider)),
        "mssql" | "sqlserver" | "sql_server" => Some(Arc::new(MsSqlCatalogProvider)),
        "redshift" | "rs" => Some(Arc::new(RedshiftCatalogProvider)),
        _ => None,
    }
}

/// The default provider when none is specified (Snowflake, for backward compat).
pub fn default_provider() -> Arc<dyn CatalogProvider> {
    Arc::new(SnowflakeCatalogProvider)
}

/// List all built-in provider names (for help text / completion).
/// Keep in sync with the canonical names accepted by [`provider_by_name`].
pub fn builtin_provider_names() -> &'static [&'static str] {
    &[
        "snowflake",
        "postgresql",
        "bigquery",
        "databricks",
        "mysql",
        "mssql",
        "redshift",
    ]
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Strip one layer of SQL quoting (double-quotes or backticks).
///
/// Returns `(inner_text, was_quoted)`.
fn strip_quoting(s: &str) -> (&str, bool) {
    let bytes = s.as_bytes();
    if bytes.len() >= 2 {
        let first = bytes[0];
        let last = bytes[bytes.len() - 1];
        if (first == b'"' && last == b'"') || (first == b'`' && last == b'`') {
            return (&s[1..bytes.len() - 1], true);
        }
        // MSSQL bracket identifiers
        if first == b'[' && last == b']' {
            return (&s[1..bytes.len() - 1], true);
        }
    }
    (s, false)
}

/// Check whether the `LEXEGA_IDENTIFIER_CASE=ignore_quoted` override is active.
///
/// When active, quoted identifiers are case-folded the same as unquoted ones
/// (mirroring Snowflake's `QUOTED_IDENTIFIERS_IGNORE_CASE` session parameter).
///
/// This reads from the global `NormalizationConfig` cache (populated by
/// `set_normalization_dialect()` or lazily from env vars). Falls back to
/// checking the env var directly if the config module is not available.
fn ignore_quoted_case_active() -> bool {
    // Delegate to the canonical normalization config in ast_walker/normalize.rs.
    // This ensures the provider trait and the normalize_identifier() function
    // always agree on whether quoted identifiers should be case-folded.
    crate::ir::is_ignore_quoted_active()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snowflake_normalizes_upper() {
        let p = SnowflakeCatalogProvider;
        assert_eq!(p.normalize_identifier("my_table"), "MY_TABLE");
        assert_eq!(p.normalize_identifier("\"my_table\""), "my_table");
        assert_eq!(p.normalize_identifier("MY_TABLE"), "MY_TABLE");
    }

    #[test]
    fn postgres_normalizes_lower() {
        let p = PostgresCatalogProvider;
        assert_eq!(p.normalize_identifier("MY_TABLE"), "my_table");
        assert_eq!(p.normalize_identifier("\"MyTable\""), "MyTable");
    }

    #[test]
    fn bigquery_preserves_case() {
        let p = BigQueryCatalogProvider;
        assert_eq!(p.normalize_identifier("MyDataset"), "MyDataset");
        assert_eq!(p.normalize_identifier("`MyDataset`"), "MyDataset");
    }

    #[test]
    fn mssql_bracket_identifiers() {
        let p = MsSqlCatalogProvider;
        assert_eq!(p.normalize_identifier("[My Table]"), "My Table");
        assert_eq!(p.normalize_identifier("my_table"), "MY_TABLE");
    }

    #[test]
    fn provider_registry_lookups() {
        assert!(provider_by_name("snowflake").is_some());
        assert!(provider_by_name("SF").is_some());
        assert!(provider_by_name("bigquery").is_some());
        assert!(provider_by_name("bq").is_some());
        assert!(provider_by_name("postgresql").is_some());
        assert!(provider_by_name("pg").is_some());
        assert!(provider_by_name("unknown").is_none());
    }
}
