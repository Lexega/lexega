// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

pub mod provider;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::path::Path;
use std::sync::Arc;

use crate::ir::normalize_identifier;
pub use provider::{
    builtin_provider_names, default_provider, provider_by_name, CatalogProvider, UnquotedIdentCase,
};

/// Latest catalog snapshot schema version emitted by official tooling.
///
/// Loader is backward compatible with earlier versions.
pub const CATALOG_SCHEMA_VERSION: u32 = 2;

#[derive(Debug)]
pub enum CatalogError {
    Io(std::io::Error),
    Parse(String),
    Serialize(serde_json::Error),
    SchemaVersionMismatch { expected: u32, found: u32 },
    DuplicateEntry { kind: &'static str, key: String },
}

impl fmt::Display for CatalogError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CatalogError::Io(e) => write!(f, "I/O error: {e}"),
            CatalogError::Parse(e) => write!(f, "Parse error: {e}"),
            CatalogError::Serialize(e) => write!(f, "Serialization error: {e}"),
            CatalogError::SchemaVersionMismatch { expected, found } => write!(
                f,
                "Catalog schema version mismatch: expected {expected}, found {found}"
            ),
            CatalogError::DuplicateEntry { kind, key } => {
                write!(f, "Duplicate catalog entry ({kind}): {key}")
            }
        }
    }
}

impl std::error::Error for CatalogError {}

impl From<std::io::Error> for CatalogError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

/// A name in the catalog snapshot with explicit case-sensitivity.
///
/// Snowflake semantics:
/// - Unquoted identifiers are effectively case-insensitive (folded to UPPERCASE).
/// - Quoted identifiers are case-sensitive.
///
/// The snapshot generator should set `case_sensitive=true` for quoted identifiers.
/// During deserialization, if `case_sensitive: true`, the name is wrapped in quotes
/// so that `normalize_identifier()` will preserve its case.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct CatalogIdent {
    pub name: String,
}

// Custom deserializer to handle EITHER:
// - A plain string: "MY_TABLE" (case-insensitive)
// - An object: { "name": "...", "case_sensitive": bool }
// For case_sensitive=true, the name is wrapped in quotes for normalize_identifier() to work correctly
impl<'de> serde::Deserialize<'de> for CatalogIdent {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::{self, MapAccess, Visitor};

        struct CatalogIdentVisitor;

        impl<'de> Visitor<'de> for CatalogIdentVisitor {
            type Value = CatalogIdent;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a string or an object with 'name' field")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(CatalogIdent {
                    name: v.to_string(),
                })
            }

            fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(CatalogIdent { name: v })
            }

            fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
            where
                M: MapAccess<'de>,
            {
                let mut name: Option<String> = None;
                let mut case_sensitive: bool = false;

                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "name" => {
                            name = Some(map.next_value()?);
                        }
                        "case_sensitive" => {
                            case_sensitive = map.next_value()?;
                        }
                        _ => {
                            // Skip unknown fields
                            let _ = map.next_value::<serde::de::IgnoredAny>()?;
                        }
                    }
                }

                let raw_name = name.ok_or_else(|| de::Error::missing_field("name"))?;

                // If case_sensitive is true and the name doesn't already have quotes,
                // wrap it in quotes so normalize_identifier() will preserve case
                let final_name =
                    if case_sensitive && !raw_name.starts_with('"') && !raw_name.ends_with('"') {
                        format!("\"{}\"", raw_name)
                    } else {
                        raw_name
                    };

                Ok(CatalogIdent { name: final_name })
            }
        }

        deserializer.deserialize_any(CatalogIdentVisitor)
    }
}

impl CatalogIdent {
    /// Get the normalized key for lookups (Snowflake default: uppercase unquoted).
    ///
    /// For provider-aware normalization, use [`key_for`](Self::key_for) instead.
    pub fn key(&self) -> String {
        normalize_identifier(&self.name)
    }

    /// Get the normalized key using a specific provider's identifier rules.
    ///
    /// This is the preferred method when a `CatalogProvider` is available.
    pub fn key_for(&self, provider: &dyn CatalogProvider) -> String {
        provider.normalize_identifier(&self.name)
    }

    /// Get the display name (quotes stripped, original case preserved for quoted identifiers).
    /// Use this for signal generation and user-facing output.
    pub fn display_name(&self) -> &str {
        let trimmed = self.name.trim();
        if (trimmed.starts_with('"') && trimmed.ends_with('"'))
            || (trimmed.starts_with('`') && trimmed.ends_with('`'))
        {
            if trimmed.len() >= 2 {
                &trimmed[1..trimmed.len() - 1]
            } else {
                trimmed
            }
        } else {
            trimmed
        }
    }

    pub fn from_name(name: impl Into<String>) -> Self {
        Self { name: name.into() }
    }

    /// Build a `CatalogIdent` from a raw SQL identifier token.
    ///
    /// Preserves quotes if present - normalize_identifier() will detect them
    /// and handle case sensitivity appropriately.
    pub fn from_sql_ident(raw: &str) -> Self {
        Self {
            name: raw.to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CatalogSnapshot {
    pub schema_version: u32,

    #[serde(default)]
    pub generated_at: Option<DateTime<Utc>>,

    /// Free-form source descriptor (e.g., "snowsql", "python-connector", "dbt").
    #[serde(default)]
    pub source: Option<String>,

    /// The data platform that produced this snapshot.
    ///
    /// Determines identifier normalization rules (e.g., Snowflake → uppercase,
    /// PostgreSQL → lowercase, BigQuery → preserve case).
    ///
    /// When absent, defaults to `"snowflake"` for backward compatibility.
    #[serde(default)]
    pub provider: Option<String>,

    #[serde(default)]
    pub databases: Vec<CatalogDatabase>,

    /// Governance policies extracted from ACCOUNT_USAGE.
    ///
    /// These are account-level objects (not scoped to a single database).
    #[serde(default)]
    pub policies: Vec<CatalogPolicy>,

    /// Policy-to-table/column bindings from POLICY_REFERENCES.
    #[serde(default)]
    pub policy_references: Vec<CatalogPolicyReference>,

    /// Grant graph for effective access analysis.
    ///
    /// Contains role hierarchy, object privileges, and user-role assignments.
    /// Used to compute transitive access impact when analyzing GRANT/REVOKE statements.
    #[serde(default)]
    pub grants: Option<CatalogGrants>,
}

// ============================================================================
// Grant Graph Types (for effective access analysis)
// ============================================================================

/// Grant graph for computing effective access changes.
///
/// This enables pre-execution analysis of GRANT/REVOKE statements by modeling
/// the full role hierarchy and privilege graph.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CatalogGrants {
    /// Role hierarchy edges: role A granted to role B (B inherits A's privileges).
    #[serde(default)]
    pub role_hierarchy: Vec<CatalogRoleEdge>,

    /// Object privilege edges: role has privilege on object.
    #[serde(default)]
    pub object_privileges: Vec<CatalogObjectPrivilege>,

    /// User-to-role assignments.
    #[serde(default)]
    pub user_roles: Vec<CatalogUserRole>,
}

/// A role hierarchy edge: GRANT ROLE parent TO ROLE child.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CatalogRoleEdge {
    /// Role being granted (the parent in the hierarchy).
    #[serde(rename = "parent")]
    pub parent_role: String,

    /// Role receiving the grant (the child, inherits parent's privileges).
    #[serde(rename = "child")]
    pub child_role: String,

    /// WITH GRANT OPTION modifier.
    #[serde(default)]
    pub grant_option: bool,
}

/// An object privilege grant: role has privilege on object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CatalogObjectPrivilege {
    /// Role with the privilege.
    pub role: String,

    /// Privilege type (SELECT, INSERT, USAGE, OWNERSHIP, etc.).
    pub privilege: String,

    /// Object type (TABLE, VIEW, SCHEMA, DATABASE, etc.).
    pub object_type: String,

    /// Fully qualified object name (DB.SCHEMA.OBJECT).
    #[serde(rename = "object")]
    pub object_fqn: String,
}

/// A user-to-role assignment: user has role.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CatalogUserRole {
    /// User name.
    pub user: String,

    /// Role assigned to the user.
    pub role: String,
}

/// Governance-as-code input to [`CatalogSnapshot::enrich_column_tags`]:
/// one source column's declared tags, addressed by resolved
/// `database.schema.table`. Kept catalog-local so this layer never
/// depends on the dbt front-end (the caller maps its own type in).
#[derive(Debug, Clone)]
pub struct ColumnTagOverlay {
    /// `db.schema.table` or `schema.table`.
    pub full_ref: String,
    pub column: String,
    pub tag_names: Vec<String>,
}

impl CatalogSnapshot {
    /// Content identity of the snapshot, including any tag overlay unioned
    /// in before index build. Deterministic for structs (no maps); compact
    /// serialization.
    pub fn sha256_hex(&self) -> Result<String, serde_json::Error> {
        let json = serde_json::to_vec(self)?;
        let mut hasher = Sha256::new();
        hasher.update(&json);
        Ok(format!("{:x}", hasher.finalize()))
    }

    pub fn validate_version(&self) -> Result<(), CatalogError> {
        // Only the current snapshot schema version loads.
        if self.schema_version != CATALOG_SCHEMA_VERSION {
            return Err(CatalogError::SchemaVersionMismatch {
                expected: CATALOG_SCHEMA_VERSION,
                found: self.schema_version,
            });
        }
        Ok(())
    }

    pub fn load_from_path(path: &Path) -> Result<Self, CatalogError> {
        let content = fs::read_to_string(path)?;
        let snapshot: CatalogSnapshot = if path
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| e.eq_ignore_ascii_case("yaml") || e.eq_ignore_ascii_case("yml"))
        {
            serde_yaml_ng::from_str(&content)
                .map_err(|e| CatalogError::Parse(format!("YAML: {e}")))?
        } else {
            serde_json::from_str(&content).map_err(|e| CatalogError::Parse(format!("JSON: {e}")))?
        };

        snapshot.validate_version()?;
        Ok(snapshot)
    }

    /// Union governance-as-code column tags into the snapshot before the
    /// index is built. Matching reuses catalog identifier normalization
    /// ([`CatalogIdent::key`]); warehouse tags already present are never
    /// dropped, and a tag already on the column is not duplicated.
    /// Returns the number of `(column, tag)` pairs newly applied.
    pub fn enrich_column_tags(&mut self, overlay: &[ColumnTagOverlay]) -> usize {
        let mut applied = 0;
        for entry in overlay {
            // `db.schema.table` or `schema.table`; anything else is skipped
            // rather than guessed at.
            let parts: Vec<&str> = entry.full_ref.split('.').collect();
            let (want_db, want_schema, want_table) = if parts.len() == 3 {
                (
                    Some(normalize_identifier(parts[0])),
                    normalize_identifier(parts[1]),
                    normalize_identifier(parts[2]),
                )
            } else if parts.len() == 2 {
                (
                    None,
                    normalize_identifier(parts[0]),
                    normalize_identifier(parts[1]),
                )
            } else {
                continue;
            };
            let want_col = normalize_identifier(&entry.column);

            for db in &mut self.databases {
                if let Some(ref wdb) = want_db {
                    if db.name.key() != *wdb {
                        continue;
                    }
                }
                for schema in &mut db.schemas {
                    if schema.name.key() != want_schema {
                        continue;
                    }
                    for table in &mut schema.tables {
                        if table.name.key() != want_table {
                            continue;
                        }
                        for column in &mut table.columns {
                            if column.name.key() != want_col {
                                continue;
                            }
                            for tag_name in &entry.tag_names {
                                if column.tags.iter().any(|t| t.tag_name == *tag_name) {
                                    continue;
                                }
                                column.tags.push(CatalogTag {
                                    tag_database: None,
                                    tag_schema: None,
                                    tag_name: tag_name.clone(),
                                    tag_value: None,
                                });
                                applied += 1;
                            }
                        }
                    }
                }
            }
        }
        applied
    }

    /// Synthesize a minimal snapshot from governance-as-code column tags alone,
    /// for when no warehouse `--catalog` is supplied but the dbt project
    /// declares source-column tags. Only the `database.schema.table.column`
    /// entries named in `overlay` (and their tags) are fabricated — nothing is
    /// invented beyond what the project declared. A 2-part `schema.table` ref is
    /// qualified with `default_database` (the dbt target database); without one
    /// it cannot be placed and is skipped. The result is fed through the same
    /// [`CatalogIndex::from_snapshot`] path as a real catalog, so identifier
    /// resolution is identical.
    pub fn from_source_column_tags(
        overlay: &[ColumnTagOverlay],
        default_database: Option<&str>,
    ) -> Self {
        let mut databases: Vec<CatalogDatabase> = Vec::new();

        for entry in overlay {
            // Same decomposition as `enrich_column_tags`; anything else skipped.
            let parts: Vec<&str> = entry.full_ref.split('.').collect();
            let (db_name, schema_name, table_name) = if parts.len() == 3 {
                (parts[0], parts[1], parts[2])
            } else if parts.len() == 2 {
                match default_database {
                    Some(db) => (db, parts[0], parts[1]),
                    None => continue,
                }
            } else {
                continue;
            };

            let db_key = normalize_identifier(db_name);
            let db_idx = match databases.iter().position(|d| d.name.key() == db_key) {
                Some(i) => i,
                None => {
                    databases.push(CatalogDatabase {
                        name: CatalogIdent::from_name(db_name),
                        schemas: Vec::new(),
                    });
                    databases.len() - 1
                }
            };

            let schema_key = normalize_identifier(schema_name);
            let schema_idx = match databases[db_idx]
                .schemas
                .iter()
                .position(|s| s.name.key() == schema_key)
            {
                Some(i) => i,
                None => {
                    databases[db_idx].schemas.push(CatalogSchema {
                        name: CatalogIdent::from_name(schema_name),
                        tables: Vec::new(),
                    });
                    databases[db_idx].schemas.len() - 1
                }
            };

            let table_key = normalize_identifier(table_name);
            let table_idx = match databases[db_idx].schemas[schema_idx]
                .tables
                .iter()
                .position(|t| t.name.key() == table_key)
            {
                Some(i) => i,
                None => {
                    databases[db_idx].schemas[schema_idx]
                        .tables
                        .push(CatalogTable {
                            name: CatalogIdent::from_name(table_name),
                            kind: CatalogTableKind::Table,
                            columns: Vec::new(),
                            row_count_estimate: None,
                            row_count_estimate_as_of: None,
                            bytes_estimate: None,
                            bytes_estimate_as_of: None,
                            constraints: Vec::new(),
                            comment: None,
                            tags: Vec::new(),
                        });
                    databases[db_idx].schemas[schema_idx].tables.len() - 1
                }
            };

            let table = &mut databases[db_idx].schemas[schema_idx].tables[table_idx];
            let col_key = normalize_identifier(&entry.column);
            let col_idx = match table.columns.iter().position(|c| c.name.key() == col_key) {
                Some(i) => i,
                None => {
                    table.columns.push(CatalogColumn {
                        name: CatalogIdent::from_name(entry.column.as_str()),
                        data_type: None,
                        nullable: None,
                        tags: Vec::new(),
                    });
                    table.columns.len() - 1
                }
            };

            let col_tags = &mut table.columns[col_idx].tags;
            for tag_name in &entry.tag_names {
                if col_tags.iter().any(|t| t.tag_name == *tag_name) {
                    continue;
                }
                col_tags.push(CatalogTag {
                    tag_database: None,
                    tag_schema: None,
                    tag_name: tag_name.clone(),
                    tag_value: None,
                });
            }
        }

        CatalogSnapshot {
            schema_version: CATALOG_SCHEMA_VERSION,
            generated_at: None,
            source: Some("dbt".to_string()),
            provider: None,
            databases,
            policies: Vec::new(),
            policy_references: Vec::new(),
            grants: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CatalogDatabase {
    pub name: CatalogIdent,

    #[serde(default)]
    pub schemas: Vec<CatalogSchema>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CatalogSchema {
    pub name: CatalogIdent,

    #[serde(default)]
    pub tables: Vec<CatalogTable>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum CatalogTableKind {
    Table,
    View,
    MaterializedView,
    ExternalTable,
    /// Session-scoped temporary table. Catalogs that surface
    /// declared TEMPORARY tables (e.g. dbt's
    /// `materialized='temporary_table'` config) populate this;
    /// per-session auto-created temp tables are typically not in
    /// catalog metadata. Drives `Q-TBL-TEMP-REF-CENH`.
    Temporary,
    #[default]
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CatalogTable {
    pub name: CatalogIdent,

    #[serde(default)]
    pub kind: CatalogTableKind,

    #[serde(default)]
    pub columns: Vec<CatalogColumn>,

    /// Optional statistics provided by the snapshot generator.
    ///
    /// For Snowflake, this is typically best-effort/approximate and can be stale.
    #[serde(default)]
    pub row_count_estimate: Option<u64>,

    /// Timestamp for when `row_count` was captured (if known).
    #[serde(default)]
    pub row_count_estimate_as_of: Option<DateTime<Utc>>,

    /// Best-effort/approximate bytes (scan bytes) from Snowflake metadata (optional).
    #[serde(default)]
    pub bytes_estimate: Option<u64>,

    /// Timestamp for when `bytes_estimate` was captured (if known).
    #[serde(default)]
    pub bytes_estimate_as_of: Option<DateTime<Utc>>,

    /// Constraints for the table (optional; may be incomplete depending on privileges).
    #[serde(default)]
    pub constraints: Vec<CatalogConstraint>,

    #[serde(default)]
    pub comment: Option<String>,

    /// Tags attached to this table from ACCOUNT_USAGE.TAG_REFERENCES.
    #[serde(default)]
    pub tags: Vec<CatalogTag>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum CatalogConstraintKind {
    PrimaryKey,
    Unique,
    ForeignKey,
    #[default]
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CatalogObjectName {
    pub database: CatalogIdent,
    pub schema: CatalogIdent,
    pub name: CatalogIdent,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CatalogConstraint {
    #[serde(default)]
    pub kind: CatalogConstraintKind,

    #[serde(default)]
    pub name: Option<String>,

    #[serde(default)]
    pub columns: Vec<CatalogIdent>,

    /// Referenced table (for foreign keys).
    #[serde(default)]
    pub ref_table: Option<CatalogObjectName>,

    /// Referenced columns (for foreign keys).
    #[serde(default)]
    pub ref_columns: Vec<CatalogIdent>,

    /// Whether the constraint is enforced (Snowflake constraints can be informational).
    #[serde(default)]
    pub enforced: Option<bool>,

    /// Whether the constraint is relied on for rewrite.
    #[serde(default)]
    pub rely: Option<bool>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CatalogColumn {
    pub name: CatalogIdent,

    /// Snowflake type name / display type (snapshot generator decides the exact format).
    #[serde(default)]
    pub data_type: Option<String>,

    /// Nullability if known.
    #[serde(default)]
    pub nullable: Option<bool>,

    /// Tags attached to this column from ACCOUNT_USAGE.TAG_REFERENCES.
    #[serde(default)]
    pub tags: Vec<CatalogTag>,
}

// Custom deserializer to allow plain strings for columns (just name, no type info)
impl<'de> serde::Deserialize<'de> for CatalogColumn {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::{self, MapAccess, Visitor};

        struct CatalogColumnVisitor;

        impl<'de> Visitor<'de> for CatalogColumnVisitor {
            type Value = CatalogColumn;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a string (column name) or an object with 'name' field")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(CatalogColumn {
                    name: CatalogIdent {
                        name: v.to_string(),
                    },
                    data_type: None,
                    nullable: None,
                    tags: Vec::new(),
                })
            }

            fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(CatalogColumn {
                    name: CatalogIdent { name: v },
                    data_type: None,
                    nullable: None,
                    tags: Vec::new(),
                })
            }

            fn visit_map<M>(self, map: M) -> Result<Self::Value, M::Error>
            where
                M: MapAccess<'de>,
            {
                // Delegate to the derived deserializer for full object format
                #[derive(serde::Deserialize)]
                struct CatalogColumnFull {
                    pub name: CatalogIdent,
                    #[serde(default)]
                    pub data_type: Option<String>,
                    #[serde(default)]
                    pub nullable: Option<bool>,
                    #[serde(default)]
                    pub tags: Vec<CatalogTag>,
                }

                let full =
                    CatalogColumnFull::deserialize(de::value::MapAccessDeserializer::new(map))?;
                Ok(CatalogColumn {
                    name: full.name,
                    data_type: full.data_type,
                    nullable: full.nullable,
                    tags: full.tags,
                })
            }
        }

        deserializer.deserialize_any(CatalogColumnVisitor)
    }
}

// ============================================================================
// Tags
// ============================================================================

/// A tag attached to a Snowflake object (table or column).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CatalogTag {
    /// Database where the tag is defined.
    #[serde(default)]
    pub tag_database: Option<String>,

    /// Schema where the tag is defined.
    #[serde(default)]
    pub tag_schema: Option<String>,

    /// Tag name (e.g., "PII", "SENSITIVE").
    pub tag_name: String,

    /// Tag value (e.g., "EMAIL", "SSN").
    #[serde(default)]
    pub tag_value: Option<String>,
}

impl CatalogTag {
    /// Fully-qualified tag name, joining `tag_database`, `tag_schema`,
    /// and `tag_name` with `'.'` when those parts are present.
    ///
    /// Examples:
    ///   - `tag_database = Some("GOV"), tag_schema = Some("TAGS"), tag_name = "PII"`
    ///     → `"GOV.TAGS.PII"`
    ///   - `tag_database = None, tag_schema = Some("TAGS"), tag_name = "PII"`
    ///     → `"TAGS.PII"`
    ///   - both `None` → `"PII"`
    ///
    /// Used by the IR catalog bridge in `src/ir/lower.rs` to build
    /// [`crate::ir::catalog_context::TagRef::qualified_name`] when
    /// seeding scan column metadata from a [`CatalogSnapshot`].
    pub fn qualified_name(&self) -> String {
        match (self.tag_database.as_deref(), self.tag_schema.as_deref()) {
            (Some(db), Some(sch)) => format!("{}.{}.{}", db, sch, self.tag_name),
            (None, Some(sch)) => format!("{}.{}", sch, self.tag_name),
            (Some(db), None) => format!("{}.{}", db, self.tag_name),
            (None, None) => self.tag_name.clone(),
        }
    }
}

// ============================================================================
// Governance Policies
// ============================================================================

/// Kind of governance policy extracted from Snowflake.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum CatalogPolicyKind {
    MaskingPolicy,
    RowAccessPolicy,
    AggregationPolicy,
    ProjectionPolicy,
    #[default]
    Unknown,
}

/// A governance policy definition extracted from Snowflake ACCOUNT_USAGE.
///
/// This includes the policy body DDL which can be parsed to extract
/// table dependencies (e.g., lookup tables referenced in CASE expressions).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CatalogPolicy {
    /// Fully-qualified name: database.schema.policy_name
    pub name: CatalogObjectName,

    /// Kind of policy (masking, row access, etc.)
    #[serde(default)]
    pub kind: CatalogPolicyKind,

    /// The policy body expression (the SQL after "AS" in CREATE ... POLICY).
    ///
    /// Example for masking policy: `CASE WHEN current_role() IN ('ADMIN') THEN val ELSE '***' END`
    /// Example for row access policy: `EXISTS (SELECT 1 FROM auth_users WHERE ...)`
    #[serde(default)]
    pub body: Option<String>,

    /// Full DDL if available (from GET_DDL or reconstructed).
    #[serde(default)]
    pub ddl: Option<String>,

    /// Signature (argument types) for the policy.
    #[serde(default)]
    pub signature: Option<String>,

    /// Return type of the policy.
    #[serde(default)]
    pub return_type: Option<String>,

    /// Tables that this policy's body references (extracted by parsing the body).
    ///
    /// This is the key differentiator: "this masking policy depends on ADMIN_USERS table"
    #[serde(default)]
    pub body_table_dependencies: Vec<CatalogObjectName>,

    /// Comment on the policy if any.
    #[serde(default)]
    pub comment: Option<String>,

    /// When the policy was created.
    #[serde(default)]
    pub created_at: Option<DateTime<Utc>>,

    /// When the policy was last modified.
    #[serde(default)]
    pub last_modified_at: Option<DateTime<Utc>>,

    /// Owner role.
    #[serde(default)]
    pub owner: Option<String>,
}

/// A reference binding a policy to a table/column.
///
/// From SNOWFLAKE.ACCOUNT_USAGE.POLICY_REFERENCES.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CatalogPolicyReference {
    /// The policy being referenced.
    pub policy_name: CatalogObjectName,

    /// Kind of policy.
    #[serde(default)]
    pub policy_kind: CatalogPolicyKind,

    /// The table the policy is applied to.
    pub ref_table: CatalogObjectName,

    /// For masking policies: the column the policy is applied to.
    /// For row access policies: None (applies to whole table).
    #[serde(default)]
    pub ref_column: Option<CatalogIdent>,

    /// Whether the policy is enabled/active.
    #[serde(default)]
    pub enabled: Option<bool>,
}

/// A derived lookup structure for a loaded snapshot.
///
/// This index is intentionally conservative for now:
/// - All lookups are by normalized keys (case-folded when case_sensitive=false).
/// - Duplicate entries are treated as errors to avoid silent ambiguity.
#[derive(Debug, Clone)]
pub struct CatalogIndex {
    snapshot: CatalogSnapshot,

    /// The catalog provider that controls identifier normalization and feature flags.
    provider: Arc<dyn CatalogProvider>,

    databases_by_key: HashMap<String, usize>,
    schemas_by_key: HashMap<(usize, String), usize>,
    tables_by_key: HashMap<(usize, usize, String), usize>,
    columns_by_key: HashMap<(usize, usize, usize, String), usize>,

    /// Reverse lookup: table name key -> candidate (db_idx, schema_idx, table_idx) locations.
    ///
    /// Keys are normalized using the provider's identifier rules.
    table_locations_by_key: HashMap<String, Vec<(usize, usize, usize)>>,

    /// Grant graph for effective access analysis.
    ///
    /// Built from `snapshot.grants` if present. Used by the analyzer to compute
    /// the impact of GRANT/REVOKE statements.

    /// SHA-256 of the snapshot content, computed once at index build so
    /// per-statement report assembly never re-serializes the snapshot.
    snapshot_sha256: String,
}

impl CatalogIndex {
    pub fn snapshot(&self) -> &CatalogSnapshot {
        &self.snapshot
    }

    /// Content identity of the loaded snapshot (see CatalogSnapshot::sha256_hex).
    pub fn snapshot_sha256(&self) -> &str {
        &self.snapshot_sha256
    }

    /// Get the catalog provider for this index.
    pub fn provider(&self) -> &dyn CatalogProvider {
        &*self.provider
    }

    /// Normalize an identifier using this index's provider rules.
    pub fn normalize_ident(&self, name: &str) -> String {
        self.provider.normalize_identifier(name)
    }

    pub fn load_from_path(path: &Path) -> Result<Self, CatalogError> {
        let snapshot = CatalogSnapshot::load_from_path(path)?;
        Self::from_snapshot(snapshot)
    }

    /// Build an index from a snapshot, auto-detecting the provider from the
    /// snapshot's `provider` field (defaults to Snowflake).
    pub fn from_snapshot(snapshot: CatalogSnapshot) -> Result<Self, CatalogError> {
        let provider = snapshot
            .provider
            .as_deref()
            .and_then(provider_by_name)
            .unwrap_or_else(default_provider);
        Self::from_snapshot_with_provider(snapshot, provider)
    }

    /// Build an index with an explicit provider (overrides the snapshot's `provider` field).
    pub fn from_snapshot_with_provider(
        snapshot: CatalogSnapshot,
        provider: Arc<dyn CatalogProvider>,
    ) -> Result<Self, CatalogError> {
        snapshot.validate_version()?;

        let mut databases_by_key: HashMap<String, usize> = HashMap::new();
        let mut schemas_by_key: HashMap<(usize, String), usize> = HashMap::new();
        let mut tables_by_key: HashMap<(usize, usize, String), usize> = HashMap::new();
        let mut columns_by_key: HashMap<(usize, usize, usize, String), usize> = HashMap::new();
        let mut table_locations_by_key: HashMap<String, Vec<(usize, usize, usize)>> =
            HashMap::new();

        for (db_idx, db) in snapshot.databases.iter().enumerate() {
            let db_key = db.name.key_for(&*provider);
            if databases_by_key.insert(db_key.clone(), db_idx).is_some() {
                return Err(CatalogError::DuplicateEntry {
                    kind: "database",
                    key: db_key,
                });
            }

            for (schema_idx, schema) in db.schemas.iter().enumerate() {
                let schema_key = schema.name.key_for(&*provider);
                let schema_map_key = (db_idx, schema_key.clone());
                if schemas_by_key
                    .insert(schema_map_key.clone(), schema_idx)
                    .is_some()
                {
                    return Err(CatalogError::DuplicateEntry {
                        kind: "schema",
                        key: format!("{}.{}", db.name.name, schema.name.name),
                    });
                }

                for (table_idx, table) in schema.tables.iter().enumerate() {
                    let table_key = table.name.key_for(&*provider);
                    let table_map_key = (db_idx, schema_idx, table_key.clone());
                    if tables_by_key
                        .insert(table_map_key.clone(), table_idx)
                        .is_some()
                    {
                        return Err(CatalogError::DuplicateEntry {
                            kind: "table",
                            key: format!(
                                "{}.{}.{}",
                                db.name.name, schema.name.name, table.name.name
                            ),
                        });
                    }

                    table_locations_by_key
                        .entry(table_key.clone())
                        .or_default()
                        .push((db_idx, schema_idx, table_idx));

                    for (col_idx, col) in table.columns.iter().enumerate() {
                        let col_key = col.name.key_for(&*provider);
                        let col_map_key = (db_idx, schema_idx, table_idx, col_key.clone());
                        if columns_by_key.insert(col_map_key, col_idx).is_some() {
                            return Err(CatalogError::DuplicateEntry {
                                kind: "column",
                                key: format!(
                                    "{}.{}.{}.{}",
                                    db.name.name, schema.name.name, table.name.name, col.name.name
                                ),
                            });
                        }
                    }
                }
            }
        }

        let snapshot_sha256 = snapshot.sha256_hex().map_err(CatalogError::Serialize)?;

        Ok(Self {
            snapshot,
            provider,
            databases_by_key,
            schemas_by_key,
            tables_by_key,
            columns_by_key,
            table_locations_by_key,
            snapshot_sha256,
        })
    }

    pub fn table_location_candidates_by_key(
        &self,
        table_key: &str,
    ) -> Option<&Vec<(usize, usize, usize)>> {
        self.table_locations_by_key.get(table_key)
    }

    pub fn get_table(
        &self,
        db: &CatalogIdent,
        schema: &CatalogIdent,
        table: &CatalogIdent,
    ) -> Option<&CatalogTable> {
        let db_idx = *self.databases_by_key.get(&db.key_for(&*self.provider))?;
        let schema_idx = *self
            .schemas_by_key
            .get(&(db_idx, schema.key_for(&*self.provider)))?;
        let table_idx =
            *self
                .tables_by_key
                .get(&(db_idx, schema_idx, table.key_for(&*self.provider)))?;
        self.snapshot
            .databases
            .get(db_idx)
            .and_then(|d| d.schemas.get(schema_idx))
            .and_then(|s| s.tables.get(table_idx))
    }

    /// Convenience lookup for typical (case-insensitive) Snowflake identifiers.
    pub fn get_table_by_name(&self, db: &str, schema: &str, table: &str) -> Option<&CatalogTable> {
        let db_ident = CatalogIdent::from_name(db);
        let schema_ident = CatalogIdent::from_name(schema);
        let table_ident = CatalogIdent::from_name(table);
        self.get_table(&db_ident, &schema_ident, &table_ident)
    }

    pub fn get_column(
        &self,
        db: &CatalogIdent,
        schema: &CatalogIdent,
        table: &CatalogIdent,
        column: &CatalogIdent,
    ) -> Option<&CatalogColumn> {
        let db_idx = *self.databases_by_key.get(&db.key_for(&*self.provider))?;
        let schema_idx = *self
            .schemas_by_key
            .get(&(db_idx, schema.key_for(&*self.provider)))?;
        let table_idx =
            *self
                .tables_by_key
                .get(&(db_idx, schema_idx, table.key_for(&*self.provider)))?;
        let col_idx = *self.columns_by_key.get(&(
            db_idx,
            schema_idx,
            table_idx,
            column.key_for(&*self.provider),
        ))?;

        self.snapshot
            .databases
            .get(db_idx)
            .and_then(|d| d.schemas.get(schema_idx))
            .and_then(|s| s.tables.get(table_idx))
            .and_then(|t| t.columns.get(col_idx))
    }

    /// Convenience lookup for typical (case-insensitive) Snowflake identifiers.
    pub fn get_column_by_name(
        &self,
        db: &str,
        schema: &str,
        table: &str,
        column: &str,
    ) -> Option<&CatalogColumn> {
        let db_ident = CatalogIdent::from_name(db);
        let schema_ident = CatalogIdent::from_name(schema);
        let table_ident = CatalogIdent::from_name(table);
        let column_ident = CatalogIdent::from_name(column);
        self.get_column(&db_ident, &schema_ident, &table_ident, &column_ident)
    }

    /// Infer the unique location (db, schema) of an unqualified or partially qualified table.
    ///
    /// If `db` is provided, filters to that database.
    /// If `schema` is provided, filters to that schema.
    /// Returns Some((db, schema)) only if exactly one match is found.
    /// Returns None if no matches or ambiguous (multiple matches).
    pub fn infer_unique_table_location(
        &self,
        db: Option<&str>,
        schema: Option<&str>,
        table: &str,
    ) -> Option<(CatalogIdent, CatalogIdent)> {
        // Normalize table name for lookup using provider's rules
        let table_key = self.normalize_ident(table);
        let candidates = self.table_location_candidates_by_key(&table_key)?;

        let mut match_db: Option<CatalogIdent> = None;
        let mut match_schema: Option<CatalogIdent> = None;
        let mut matches = 0usize;

        for (db_idx, schema_idx, _table_idx) in candidates {
            let db_entry = self.snapshot.databases.get(*db_idx)?;
            if let Some(db_filter) = db {
                let db_key = self.normalize_ident(db_filter);
                if db_entry.name.key_for(&*self.provider) != db_key {
                    continue;
                }
            }

            let schema_entry = db_entry.schemas.get(*schema_idx)?;
            if let Some(schema_filter) = schema {
                let schema_key = self.normalize_ident(schema_filter);
                if schema_entry.name.key_for(&*self.provider) != schema_key {
                    continue;
                }
            }

            matches += 1;
            match_db = Some(db_entry.name.clone());
            match_schema = Some(schema_entry.name.clone());
            if matches > 1 {
                return None; // Ambiguous - multiple matches
            }
        }

        if matches == 1 {
            Some((match_db?, match_schema?))
        } else {
            None
        }
    }

    /// Look up a table, inferring the location from catalog if not fully qualified.
    ///
    /// This handles the common case of unqualified table names in SQL by searching
    /// the catalog for where the table exists.
    pub fn get_table_inferred(
        &self,
        db: Option<&str>,
        schema: Option<&str>,
        table: &str,
    ) -> Option<&CatalogTable> {
        // If fully qualified, use direct lookup
        if let (Some(d), Some(s)) = (db, schema) {
            return self.get_table_by_name(d, s, table);
        }

        // Infer location from catalog
        let (inferred_db, inferred_schema) = self.infer_unique_table_location(db, schema, table)?;
        self.get_table(
            &inferred_db,
            &inferred_schema,
            &CatalogIdent::from_name(table),
        )
    }
}

// ============================================================================
// Policy Body Parsing Utilities
// ============================================================================

/// Extract table references from a policy body expression.
///
/// Policy bodies contain SQL expressions like:
/// - Masking: `CASE WHEN EXISTS (SELECT 1 FROM auth_table WHERE ...) THEN val ELSE '***' END`
/// - Row Access: `EXISTS (SELECT 1 FROM lookup.allowed_users WHERE ...)`
///
/// This function wraps the body in a synthetic SELECT, parses it, and extracts
/// table references from subqueries, table functions, etc.
///
/// Returns a list of table names found in the policy body. Names are returned
/// in the format found in the source (may need normalization by caller).
pub fn extract_tables_from_policy_body(policy_body: &str) -> Vec<CatalogObjectName> {
    // Wrap in synthetic SELECT to make it parseable as a statement
    let synthetic_sql = format!("SELECT {} AS __policy_result__", policy_body);

    // Try to parse
    let (script, source) = match crate::try_parse_script_from_str(&synthetic_sql) {
        Ok(s) => (s, synthetic_sql.as_str()),
        Err(_) => {
            // If parsing fails, try alternative wrapping for boolean expressions
            let alt_sql = format!("SELECT 1 WHERE {}", policy_body);
            match crate::try_parse_script_from_str(&alt_sql) {
                Ok(s) => {
                    // Need to handle the lifetime - use the alt_sql
                    let mut tables = Vec::new();
                    for stmt in &s.stmts {
                        if let crate::ast::AstStmt::Select(select) = stmt {
                            extract_tables_from_select_recursive(
                                select.as_ref(),
                                &alt_sql,
                                &mut tables,
                            );
                        }
                    }
                    return tables;
                }
                Err(_) => return Vec::new(), // Can't parse, return empty
            }
        }
    };

    // Walk the AST to find table references
    let mut tables = Vec::new();

    for stmt in &script.stmts {
        if let crate::ast::AstStmt::Select(select) = stmt {
            extract_tables_from_select_recursive(select.as_ref(), source, &mut tables);
        }
    }

    tables
}

/// Recursively extract table references from a SELECT statement.
fn extract_tables_from_select_recursive(
    select: &crate::ast::AstSelect,
    source: &str,
    tables: &mut Vec<CatalogObjectName>,
) {
    // Check FROM clause items
    for from_item in &select.from {
        extract_tables_from_from_item(from_item, source, tables);
    }

    // Check WHERE clause for subqueries
    if let Some(ref where_clause) = select.where_clause {
        extract_tables_from_expr(&where_clause.expr, source, tables);
    }

    // Check projection items for scalar subqueries
    if let crate::ast::AstProjectionKind::Columns(ref items) = select.projection.kind {
        for item in items {
            if let crate::ast::ProjectionItemKind::SelectItem(ref select_item) = item.kind {
                extract_tables_from_expr(&select_item.expr, source, tables);
            }
        }
    }

    // Check HAVING clause
    if let Some(ref having) = select.having {
        extract_tables_from_expr(&having.expr, source, tables);
    }

    // Check QUALIFY clause
    if let Some(ref qualify) = select.qualify {
        extract_tables_from_expr(&qualify.expr, source, tables);
    }
}

/// Extract tables from a FROM clause item (handles joins, subqueries, Jinja blocks)
fn extract_tables_from_from_item(
    from_item: &crate::ast::FromItem,
    source: &str,
    tables: &mut Vec<CatalogObjectName>,
) {
    use crate::ast::FromItemKind;

    match &from_item.kind {
        FromItemKind::TableRef(table_ref) => {
            extract_tables_from_table_ref(table_ref, source, tables);
        }
        FromItemKind::JinjaBlock(jinja_block) => {
            // Recursively extract from then_items
            for item in &jinja_block.then_items {
                extract_tables_from_from_item(item, source, tables);
            }
            // Handle elif branches
            for elif in &jinja_block.elif_branches {
                for item in &elif.items {
                    extract_tables_from_from_item(item, source, tables);
                }
            }
            // Handle else branch
            if let Some(ref else_branch) = jinja_block.else_branch {
                for item in &else_branch.items {
                    extract_tables_from_from_item(item, source, tables);
                }
            }
        }
        FromItemKind::JinjaTableName(_) => {
            // Jinja-generated table name - we can't resolve it without rendering
        }
    }
}

/// Extract tables from a table reference (handles joins, subqueries, etc.)
fn extract_tables_from_table_ref(
    table_ref: &crate::ast::AstTableRef,
    source: &str,
    tables: &mut Vec<CatalogObjectName>,
) {
    // Check if this is a regular table reference (has a name with non-zero span)
    if table_ref.name.span.start != table_ref.name.span.end {
        tables.push(object_ref_to_catalog_name(&table_ref.name, source));
    }

    // Check for subquery (derived table)
    if let Some(ref subquery) = table_ref.subquery {
        if let crate::ast::AstStmt::Select(select) = subquery.as_ref() {
            extract_tables_from_select_recursive(select.as_ref(), source, tables);
        }
    }

    // Check for table function
    if let Some(ref table_fn) = table_ref.table_function {
        extract_tables_from_expr(table_fn, source, tables);
    }

    // Process joins
    for join in table_ref.joins.iter() {
        extract_tables_from_table_ref(&join.right, source, tables);

        // Check join constraint for subqueries
        if let crate::ast::AstJoinConstraint::On(ref expr) = join.constraint {
            extract_tables_from_expr(expr, source, tables);
        }
    }
}

/// Extract tables from an expression (handles subqueries, EXISTS, IN, etc.)
fn extract_tables_from_expr(
    expr: &crate::ast::AstExpr,
    source: &str,
    tables: &mut Vec<CatalogObjectName>,
) {
    use crate::ast::AstExpr;

    match expr {
        AstExpr::ExistsSubquery { subquery, .. } | AstExpr::ScalarSubquery { subquery, .. } => {
            if let crate::ast::AstStmt::Select(select) = subquery.as_ref() {
                extract_tables_from_select_recursive(select.as_ref(), source, tables);
            }
        }
        AstExpr::InSubquery {
            subquery,
            expr: inner,
            ..
        } => {
            if let crate::ast::AstStmt::Select(select) = subquery.as_ref() {
                extract_tables_from_select_recursive(select.as_ref(), source, tables);
            }
            extract_tables_from_expr(inner, source, tables);
        }
        AstExpr::QuantifiedSubquery { subquery, left, .. } => {
            if let crate::ast::AstStmt::Select(select) = subquery.as_ref() {
                extract_tables_from_select_recursive(select.as_ref(), source, tables);
            }
            extract_tables_from_expr(left, source, tables);
        }
        AstExpr::BinaryOp { left, right, .. } => {
            extract_tables_from_expr(left, source, tables);
            extract_tables_from_expr(right, source, tables);
        }
        AstExpr::LogicalChain { operands, .. } => {
            for operand in operands {
                extract_tables_from_expr(operand, source, tables);
            }
        }
        AstExpr::Case {
            operand,
            whens,
            else_expr,
            ..
        } => {
            if let Some(op) = operand {
                extract_tables_from_expr(op, source, tables);
            }
            for when_clause in whens {
                extract_tables_from_expr(&when_clause.cond, source, tables);
                extract_tables_from_expr(&when_clause.result, source, tables);
            }
            if let Some(else_e) = else_expr {
                extract_tables_from_expr(else_e, source, tables);
            }
        }
        AstExpr::FunctionCall { args, .. } => {
            for arg in args {
                extract_tables_from_function_arg(arg, source, tables);
            }
        }
        AstExpr::WindowFn { args, .. } => {
            for arg in args {
                extract_tables_from_function_arg(arg, source, tables);
            }
        }
        AstExpr::InList {
            expr: inner, list, ..
        } => {
            extract_tables_from_expr(inner, source, tables);
            for item in list {
                extract_tables_from_expr(item, source, tables);
            }
        }
        AstExpr::Between {
            expr: inner,
            lower,
            upper,
            ..
        } => {
            extract_tables_from_expr(inner, source, tables);
            extract_tables_from_expr(lower, source, tables);
            extract_tables_from_expr(upper, source, tables);
        }
        AstExpr::Array { elements, .. } => {
            for elem in elements {
                extract_tables_from_expr(elem, source, tables);
            }
        }
        AstExpr::Object { entries, .. } => {
            for (k, v) in entries {
                extract_tables_from_expr(k, source, tables);
                extract_tables_from_expr(v, source, tables);
            }
        }
        _ => {}
    }
}

/// Extract tables from a function argument
fn extract_tables_from_function_arg(
    arg: &crate::ast::AstFunctionArg,
    source: &str,
    tables: &mut Vec<CatalogObjectName>,
) {
    use crate::ast::AstFunctionArg;

    match arg {
        AstFunctionArg::Positional(expr) => {
            extract_tables_from_expr(expr, source, tables);
        }
        AstFunctionArg::Named { value, .. } => {
            extract_tables_from_expr(value, source, tables);
        }
        AstFunctionArg::Lambda { body, .. } => {
            extract_tables_from_expr(body, source, tables);
        }
        AstFunctionArg::AliasedArg { value, .. } => {
            extract_tables_from_expr(value, source, tables);
        }
        AstFunctionArg::BulkArg { value, .. } => {
            extract_tables_from_expr(value, source, tables);
        }
    }
}

/// Convert an AstObjectRef to CatalogObjectName by extracting text from source
fn object_ref_to_catalog_name(
    obj_ref: &crate::ast::AstObjectRef,
    source: &str,
) -> CatalogObjectName {
    let start = obj_ref.span.start as usize;
    let end = obj_ref.span.end as usize;

    // Extract the raw text from source
    let raw_name = if start < source.len() && end <= source.len() && start < end {
        &source[start..end]
    } else {
        ""
    };

    // Split by '.' to get parts (database.schema.table)
    let parts: Vec<&str> = raw_name.split('.').collect();

    match parts.len() {
        1 => CatalogObjectName {
            database: CatalogIdent::from_name(""),
            schema: CatalogIdent::from_name(""),
            name: CatalogIdent::from_sql_ident(parts[0].trim()),
        },
        2 => CatalogObjectName {
            database: CatalogIdent::from_name(""),
            schema: CatalogIdent::from_sql_ident(parts[0].trim()),
            name: CatalogIdent::from_sql_ident(parts[1].trim()),
        },
        3 => CatalogObjectName {
            database: CatalogIdent::from_sql_ident(parts[0].trim()),
            schema: CatalogIdent::from_sql_ident(parts[1].trim()),
            name: CatalogIdent::from_sql_ident(parts[2].trim()),
        },
        _ => CatalogObjectName {
            database: CatalogIdent::from_name(""),
            schema: CatalogIdent::from_name(""),
            name: CatalogIdent::from_name(raw_name.to_string()),
        },
    }
}

/// Enrich a CatalogSnapshot by parsing policy bodies and populating table dependencies.
///
/// This is called after loading a snapshot to fill in `body_table_dependencies`
/// for each policy that has a `body` field.
pub fn enrich_policy_dependencies(snapshot: &mut CatalogSnapshot) {
    for policy in &mut snapshot.policies {
        if let Some(ref body) = policy.body {
            let deps = extract_tables_from_policy_body(body);
            policy.body_table_dependencies = deps;
        }
    }
}

#[cfg(test)]
mod synth_tests {
    use super::*;

    fn overlay(full_ref: &str, column: &str, tags: &[&str]) -> ColumnTagOverlay {
        ColumnTagOverlay {
            full_ref: full_ref.to_string(),
            column: column.to_string(),
            tag_names: tags.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn synth_three_part_fully_qualified() {
        let ov = vec![overlay("ANALYTICS.PUBLIC.USERS", "EMAIL", &["pii"])];
        let snap = CatalogSnapshot::from_source_column_tags(&ov, None);
        assert_eq!(snap.schema_version, CATALOG_SCHEMA_VERSION);
        assert_eq!(snap.source.as_deref(), Some("dbt"));
        assert_eq!(snap.databases.len(), 1);
        let tbl = &snap.databases[0].schemas[0].tables[0];
        assert_eq!(snap.databases[0].name.name, "ANALYTICS");
        assert_eq!(snap.databases[0].schemas[0].name.name, "PUBLIC");
        assert_eq!(tbl.name.name, "USERS");
        assert_eq!(tbl.columns.len(), 1);
        assert_eq!(tbl.columns[0].name.name, "EMAIL");
        assert_eq!(tbl.columns[0].tags.len(), 1);
        assert_eq!(tbl.columns[0].tags[0].tag_name, "pii");
        // Resolves through the same index path as a real catalog.
        assert!(CatalogIndex::from_snapshot(snap).is_ok());
    }

    #[test]
    fn synth_two_part_uses_default_database() {
        let ov = vec![overlay("PUBLIC.USERS", "EMAIL", &["pii"])];
        let snap = CatalogSnapshot::from_source_column_tags(&ov, Some("ANALYTICS"));
        assert_eq!(snap.databases.len(), 1);
        assert_eq!(snap.databases[0].name.name, "ANALYTICS");
        assert_eq!(snap.databases[0].schemas[0].name.name, "PUBLIC");
        assert_eq!(snap.databases[0].schemas[0].tables[0].name.name, "USERS");
    }

    #[test]
    fn synth_two_part_without_default_database_is_skipped() {
        let ov = vec![overlay("PUBLIC.USERS", "EMAIL", &["pii"])];
        let snap = CatalogSnapshot::from_source_column_tags(&ov, None);
        assert!(snap.databases.is_empty());
    }

    #[test]
    fn synth_merges_columns_and_dedups_tags() {
        let ov = vec![
            overlay("ANALYTICS.PUBLIC.USERS", "EMAIL", &["pii", "pii"]),
            overlay("ANALYTICS.PUBLIC.USERS", "SSN", &["pii"]),
        ];
        let snap = CatalogSnapshot::from_source_column_tags(&ov, None);
        assert_eq!(snap.databases.len(), 1);
        let tbl = &snap.databases[0].schemas[0].tables[0];
        assert_eq!(tbl.columns.len(), 2);
        let email = tbl
            .columns
            .iter()
            .find(|c| c.name.name == "EMAIL")
            .expect("EMAIL column present");
        assert_eq!(email.tags.len(), 1);
    }
}
