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

use crate::context::node_metadata::{IdentKey, TableRef};
use crate::ir::ddl_plan::DdlSchemaMutation;
use crate::ir::normalize::{keys_read_alike, scoped_folding, NameKind, QuotedHandling};
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
    /// Use this for finding generation and user-facing output.
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

    /// What the snapshot lists of the warehouse. Not read from or written
    /// to a catalog file: a snapshot read from one is an inventory.
    #[serde(skip)]
    pub listing: CatalogListing,
}

/// What a [`CatalogSnapshot`] lists of the warehouse.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum CatalogListing {
    /// Every table of the schemas it holds, and every column of each
    /// table that lists any: a table or column it does not list is not
    /// there.
    #[default]
    Inventory,
    /// Only the tables and columns some declaration names: a table it
    /// does not list is not known to be missing, and the columns of one
    /// it lists are not known to be all it has.
    Named,
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
        let content = crate::extract::strip_bom(&content);
        let snapshot: CatalogSnapshot = if path
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| e.eq_ignore_ascii_case("yaml") || e.eq_ignore_ascii_case("yml"))
        {
            serde_yaml_ng::from_str(content)
                .map_err(|e| CatalogError::Parse(format!("YAML: {e}")))?
        } else {
            serde_json::from_str(content).map_err(|e| CatalogError::Parse(format!("JSON: {e}")))?
        };

        snapshot.validate_version()?;
        Ok(snapshot)
    }

    /// Union governance-as-code column tags into the snapshot before the
    /// index is built. A name is matched as an index built with `provider`
    /// finds it ([`CatalogIdent::key_for`]); warehouse tags already present
    /// are never dropped, and a tag already on the column is not duplicated.
    /// Returns the number of `(column, tag)` pairs newly applied.
    pub fn enrich_column_tags(
        &mut self,
        overlay: &[ColumnTagOverlay],
        provider: &dyn CatalogProvider,
    ) -> usize {
        let key = |name: &str| provider.normalize_identifier(name);
        let mut applied = 0;
        for entry in overlay {
            // `db.schema.table` or `schema.table`; anything else is skipped
            // rather than guessed at.
            let parts: Vec<&str> = entry.full_ref.split('.').collect();
            let (want_db, want_schema, want_table) = if parts.len() == 3 {
                (Some(key(parts[0])), key(parts[1]), key(parts[2]))
            } else if parts.len() == 2 {
                (None, key(parts[0]), key(parts[1]))
            } else {
                continue;
            };
            let want_col = key(&entry.column);

            for db in &mut self.databases {
                if let Some(ref wdb) = want_db {
                    if db.name.key_for(provider) != *wdb {
                        continue;
                    }
                }
                for schema in &mut db.schemas {
                    if schema.name.key_for(provider) != want_schema {
                        continue;
                    }
                    for table in &mut schema.tables {
                        if table.name.key_for(provider) != want_table {
                            continue;
                        }
                        for column in &mut table.columns {
                            if column.name.key_for(provider) != want_col {
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
    /// it cannot be placed and is skipped. Two names are one entry where an
    /// index built with `provider` finds them as one ([`CatalogIdent::key_for`]);
    /// index the result with that provider. Its listing is
    /// [`CatalogListing::Named`].
    pub fn from_source_column_tags(
        overlay: &[ColumnTagOverlay],
        default_database: Option<&str>,
        provider: &dyn CatalogProvider,
    ) -> Self {
        let key = |name: &str| provider.normalize_identifier(name);
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

            let db_key = key(db_name);
            let db_idx = match databases
                .iter()
                .position(|d| d.name.key_for(provider) == db_key)
            {
                Some(i) => i,
                None => {
                    databases.push(CatalogDatabase {
                        name: CatalogIdent::from_name(db_name),
                        schemas: Vec::new(),
                    });
                    databases.len() - 1
                }
            };

            let schema_key = key(schema_name);
            let schema_idx = match databases[db_idx]
                .schemas
                .iter()
                .position(|s| s.name.key_for(provider) == schema_key)
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

            let table_key = key(table_name);
            let table_idx = match databases[db_idx].schemas[schema_idx]
                .tables
                .iter()
                .position(|t| t.name.key_for(provider) == table_key)
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
            let col_key = key(&entry.column);
            let col_idx = match table
                .columns
                .iter()
                .position(|c| c.name.key_for(provider) == col_key)
            {
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
            listing: CatalogListing::Named,
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
    /// Shared with every other index built from the same snapshot.
    snapshot: Arc<CatalogSnapshot>,

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

    /// Whether quoted names were folded when the keys were made, the one
    /// part of the thread's folding the provider's keys depend on, and only
    /// through the snapshot's quoted names; `None` when it holds none or was
    /// built outside every dialect scope.
    keyed_quoted: Option<QuotedHandling>,
}

impl CatalogIndex {
    /// A debug build refuses a lookup made under a folding that keys quoted
    /// names otherwise than the index's keys were made.
    fn check_folding(&self) {
        debug_assert!(
            keys_read_alike(&self.keyed_quoted, |folding| folding.quoted),
            "a catalog index was read under a folding its keys were not made under"
        );
    }

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
        self.check_folding();
        self.provider.normalize_identifier(name)
    }

    pub fn load_from_path(path: &Path) -> Result<Self, CatalogError> {
        let snapshot = CatalogSnapshot::load_from_path(path)?;
        Self::from_snapshot(snapshot)
    }

    /// Build an index from a snapshot, auto-detecting the provider from the
    /// snapshot's `provider` field (defaults to Snowflake). An
    /// `Arc<CatalogSnapshot>` is shared, not copied.
    pub fn from_snapshot(snapshot: impl Into<Arc<CatalogSnapshot>>) -> Result<Self, CatalogError> {
        let snapshot = snapshot.into();
        let provider = snapshot
            .provider
            .as_deref()
            .and_then(provider_by_name)
            .unwrap_or_else(default_provider);
        Self::from_snapshot_with_provider(snapshot, provider)
    }

    /// Build an index with an explicit provider (overrides the snapshot's
    /// `provider` field). An `Arc<CatalogSnapshot>` is shared, not copied.
    pub fn from_snapshot_with_provider(
        snapshot: impl Into<Arc<CatalogSnapshot>>,
        provider: Arc<dyn CatalogProvider>,
    ) -> Result<Self, CatalogError> {
        let snapshot = snapshot.into();
        snapshot.validate_version()?;

        let mut databases_by_key: HashMap<String, usize> = HashMap::new();
        let mut schemas_by_key: HashMap<(usize, String), usize> = HashMap::new();
        let mut tables_by_key: HashMap<(usize, usize, String), usize> = HashMap::new();
        let mut columns_by_key: HashMap<(usize, usize, usize, String), usize> = HashMap::new();
        let mut table_locations_by_key: HashMap<String, Vec<(usize, usize, usize)>> =
            HashMap::new();
        // Whether a key was made from a quoted name, the one kind of key the
        // thread's folding decides.
        let mut any_quoted = false;
        let mut key_of = |ident: &CatalogIdent| {
            any_quoted |= provider::strip_quoting(ident.name.trim()).1;
            ident.key_for(&*provider)
        };

        for (db_idx, db) in snapshot.databases.iter().enumerate() {
            let db_key = key_of(&db.name);
            if databases_by_key.insert(db_key.clone(), db_idx).is_some() {
                return Err(CatalogError::DuplicateEntry {
                    kind: "database",
                    key: db_key,
                });
            }

            for (schema_idx, schema) in db.schemas.iter().enumerate() {
                let schema_key = key_of(&schema.name);
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
                    let table_key = key_of(&table.name);
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
                        let col_key = key_of(&col.name);
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
            keyed_quoted: scoped_folding()
                .filter(|_| any_quoted)
                .map(|folding| folding.quoted),
        })
    }

    pub fn table_location_candidates_by_key(
        &self,
        table_key: &str,
    ) -> Option<&Vec<(usize, usize, usize)>> {
        self.check_folding();
        self.table_locations_by_key.get(table_key)
    }

    pub fn get_table(
        &self,
        db: &CatalogIdent,
        schema: &CatalogIdent,
        table: &CatalogIdent,
    ) -> Option<&CatalogTable> {
        self.check_folding();
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
        self.check_folding();
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
        let db_key = db.map(|name| self.normalize_ident(name));
        let schema_key = schema.map(|name| self.normalize_ident(name));

        // A candidate's part is keyed only where the name writes that part.
        let key_where = |written: &Option<String>, name: &CatalogIdent| {
            written.as_ref().map(|_| name.key_for(&*self.provider))
        };
        let located = candidates
            .iter()
            .map(|&(db_idx, schema_idx, _table_idx)| {
                let db_entry = self.snapshot.databases.get(db_idx)?;
                let schema_entry = db_entry.schemas.get(schema_idx)?;
                Some((
                    (&db_entry.name, &schema_entry.name),
                    key_where(&db_key, &db_entry.name),
                    key_where(&schema_key, &schema_entry.name),
                ))
            })
            .collect::<Option<Vec<_>>>()?;
        let (db_name, schema_name) = unique_location_named_by(
            db_key.as_deref(),
            schema_key.as_deref(),
            located.iter().map(|(names, db_part, schema_part)| {
                (*names, db_part.as_deref(), schema_part.as_deref())
            }),
        )?;
        Some((db_name.clone(), schema_name.clone()))
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
        self.get_table_located(db, schema, table)
            .map(|(_, table)| table)
    }

    /// The table [`Self::get_table_inferred`] finds, with its database and
    /// schema: as written where both are, else as the catalog infers them.
    fn get_table_located(
        &self,
        db: Option<&str>,
        schema: Option<&str>,
        table: &str,
    ) -> Option<((CatalogIdent, CatalogIdent), &CatalogTable)> {
        let (db, schema) = match (db, schema) {
            (Some(d), Some(s)) => (CatalogIdent::from_name(d), CatalogIdent::from_name(s)),
            (Some(_), None) | (None, Some(_)) | (None, None) => {
                self.infer_unique_table_location(db, schema, table)?
            }
        };
        let found = self.get_table(&db, &schema, &CatalogIdent::from_name(table))?;
        Some(((db, schema), found))
    }

    /// Whether the snapshot lists every table of the schemas it holds and
    /// every column of each ([`CatalogListing::Inventory`]).
    fn lists_everything(&self) -> bool {
        match self.snapshot.listing {
            CatalogListing::Inventory => true,
            CatalogListing::Named => false,
        }
    }

    /// The table `table_ref` names under `session`, and where it is: the
    /// session's defaults fill the parts the reference omits, and the
    /// catalog infers the rest where one table answers.
    fn catalogued_place(
        &self,
        table_ref: &TableRef,
        session: &crate::ir::SessionContext,
    ) -> Option<(RelationPlace, &CatalogTable)> {
        let (db, schema) = crate::ir::span_extract::session_default_parts(table_ref, session);
        let db = db.map(catalog_spelling);
        let schema = schema.map(catalog_spelling);
        let ((db, schema), table) = self.get_table_located(
            db.as_deref(),
            schema.as_deref(),
            &catalog_spelling(&table_ref.name),
        )?;
        let place = RelationPlace {
            database: Some(IdentKey::new(&db.name)),
            schema: Some(IdentKey::new(&schema.name)),
            session_temporary: false,
        };
        Some((place, table))
    }

    /// Whether a name's table is in the catalog, `found` being what a
    /// lookup of the name found: `None` where it found none and the
    /// snapshot lists only named tables, so the table is not known to be
    /// missing.
    pub(crate) fn table_presence(&self, found: Option<&CatalogTable>) -> Option<bool> {
        match found {
            Some(_) => Some(true),
            None => self.lists_everything().then_some(false),
        }
    }

    /// Whether the snapshot says which unique keys its tables have: an
    /// inventory does, by each table's constraints; a snapshot that
    /// lists only named columns lists no keys.
    pub(crate) fn lists_keys(&self) -> bool {
        self.lists_everything()
    }

    /// The kind of `table`, one of the snapshot's tables, as an inventory
    /// records it; `None` where the snapshot lists only named columns,
    /// which say nothing of the kind.
    pub(crate) fn listed_kind(&self, table: &CatalogTable) -> Option<CatalogTableKind> {
        self.lists_everything().then_some(table.kind)
    }

    /// The columns of `table`, one of the snapshot's tables, as an
    /// inventory lists them; `None` where the snapshot lists only named
    /// columns, so the table's columns are not known.
    pub(crate) fn listed_columns<'t>(
        &self,
        table: &'t CatalogTable,
    ) -> Option<&'t [CatalogColumn]> {
        self.lists_everything().then_some(table.columns.as_slice())
    }
}

/// `part`, a part of a name as a statement writes it, as the catalog is
/// asked for it: unquoted where the script's dialect reads the quoted
/// name as the same name as the unquoted one (PostgreSQL's `"orders"` and
/// `orders`), as written otherwise.
fn catalog_spelling(part: &str) -> std::borrow::Cow<'_, str> {
    let trimmed = part.trim();
    match crate::dialect::identifier_quoted_inner(trimmed) {
        Some(inner)
            if !inner.is_empty()
                && IdentKey::new_as(trimmed, NameKind::Relation)
                    == IdentKey::new_as(inner, NameKind::Relation) =>
        {
            std::borrow::Cow::Owned(inner.to_string())
        }
        Some(_) | None => std::borrow::Cow::Borrowed(part),
    }
}

/// The relations a script's statements create, rename, alter and drop, in
/// script order: what a statement finds that the catalog does not have, a
/// table made in place of one it has, and the catalog's tables as the
/// script's column changes leave them.
/// Each relation a statement makes is a catalog table of no stated kind,
/// its columns those the statement that made it writes, none where it
/// writes none; a table of the catalog renamed is that table under its new
/// name.
#[derive(Debug, Clone, Default)]
pub(crate) struct ScriptRelations {
    /// Each relation as a statement left it.
    tables: Vec<ScriptTable>,
    /// By the normalized name, what each statement made of a relation of
    /// that name, in script order. Those an earlier script left come
    /// first, holding from the script's start.
    changes: std::collections::BTreeMap<IdentKey, Vec<RelationChange>>,
    /// The normalized names of [`Self::changes`] a relation that runs its
    /// query on each read is ever kept under.
    rerunning: std::collections::BTreeSet<IdentKey>,
    /// By the normalized name, where each of this script's own statements
    /// made, replaced, altered the columns of, renamed or dropped a
    /// relation of that name, whether or not anything is known of it; and,
    /// holding from the script's start, those an earlier script left
    /// ([`Self::left`]).
    named: std::collections::BTreeMap<IdentKey, Vec<RelationNaming>>,
    /// By the normalized table name, in script order, each of this script's
    /// own statements that made, dropped or renamed away a table of that
    /// name, or dropped or added a column of one: what decides which tables
    /// and columns a script run after finds removed ([`Self::left`]).
    removals: std::collections::BTreeMap<IdentKey, Vec<RemovalEvent>>,
    /// The tables and columns the scripts run before left removed, holding
    /// from the script's start.
    earlier: crate::facts::reasoning::EarlierRemovals,
    /// The name a statement may write for the session's own schema of
    /// temporary tables ([`crate::dialect::TemporaryTables::SessionSchema`]).
    session_schema: Option<&'static str>,
    /// The spans of this script's statements that drop a temporary table,
    /// on every path into them, which a table of its name may stand behind.
    temporary_drops: Vec<crate::lexer::Span>,
    /// The routines this script and the scripts run before define, each
    /// with the relations its body changes.
    routines: Vec<RoutineChanges>,
    /// The triggers this script and the scripts run before define.
    triggers: ScriptTriggers,
    /// The columns this script's statements, wherever they stand in it, and
    /// those of the scripts run before write values into.
    written: crate::facts::secrets::WrittenColumns,
    /// The pipes this script and the scripts run before define, each with
    /// where it holds from: the start of the statement defining it, `0`
    /// for one a script run before defines.
    pipes: Vec<(crate::facts::reasoning::TableIdentity, u32)>,
}

/// A routine a script defines, and the relations its body changes, which
/// a call of it changes.
#[derive(Debug, Clone)]
struct RoutineChanges {
    name: crate::facts::reasoning::TableIdentity,
    /// The types of the parameters that tell it from another routine of its
    /// name, each as written, folded; `None` where they are not read.
    signature: Option<Vec<String>>,
    /// Its parameters in order; `None` where they are not read.
    params: Option<Vec<RoutineParam>>,
    /// Where it holds from: the end of the statement defining it.
    from: u32,
    /// Where it holds to, as [`RelationChange::until`].
    until: u32,
    /// Where a statement replacing it starts; `u32::MAX` for none.
    ends: u32,
    /// The end of the statement defining it, which its body's statements
    /// hold to ([`RelationSite::until`]); `u32::MAX` for one a script run
    /// before defines.
    end: u32,
    /// Every statement of its body is read, and none runs a routine or
    /// SQL text the run does not read.
    read: bool,
    /// Each relation its body changes, named as written, under the
    /// namespace in force there.
    changes: Vec<RoutineChange>,
    /// The columns of the row a trigger is given its body assigns.
    row: RowAssigned,
    /// Each change of a trigger its body makes, in order.
    triggers: Vec<TriggerChange>,
    /// What is found, by position, of each column of the rows its body's
    /// queries return to the caller: of the rows of every such query, only
    /// the tags any carries. `None` where no query returns rows.
    results: Option<Vec<MadeValue>>,
}

impl RoutineChanges {
    /// Whether a call at `at` runs it: defined before, not yet replaced.
    fn in_force_at(&self, at: u32) -> bool {
        (self.from..self.until.min(self.ends)).contains(&at)
    }
}

/// A parameter of a routine, as a call passes it an argument.
#[derive(Debug, Clone)]
pub(crate) struct RoutineParam {
    /// Its name, normalized; `None` where none is written.
    pub(crate) name: Option<IdentKey>,
    /// The routine assigns the argument passed to it (`OUT`, `INOUT`).
    pub(crate) assigns: bool,
}

/// A relation a routine's body changes, which a call of it changes
/// ([`ScriptRelations::called`]).
#[derive(Debug, Clone)]
pub(crate) struct RoutineChange {
    /// The relation, named as written.
    pub(crate) target: TableRef,
    /// The namespace in force at the statement changing it.
    pub(crate) session: crate::ir::SessionContext,
    /// What the statement does to it.
    pub(crate) change: RoutineChangeKind,
    /// The columns its update assigns.
    pub(crate) updated: UpdatedColumns,
}

/// What a statement of a routine's body does to a relation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RoutineChangeKind {
    /// Writes rows into it, by the events written.
    Rows(WriteEvents),
    /// Removes rows from it, writing none: what held of every row holds,
    /// and each trigger on it for the events written runs.
    Removes(WriteEvents),
    /// Makes, replaces, alters, renames or drops it.
    Relation,
}

/// The kinds of write a statement makes into a table, or a trigger runs
/// at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct WriteEvents {
    pub(crate) insert: bool,
    pub(crate) update: bool,
    pub(crate) delete: bool,
    pub(crate) truncate: bool,
}

impl WriteEvents {
    pub(crate) const NONE: Self = Self {
        insert: false,
        update: false,
        delete: false,
        truncate: false,
    };
    pub(crate) const ANY: Self = Self {
        insert: true,
        update: true,
        delete: true,
        truncate: true,
    };
    pub(crate) const INSERT: Self = Self {
        insert: true,
        ..Self::NONE
    };
    pub(crate) const UPDATE: Self = Self {
        update: true,
        ..Self::NONE
    };
    pub(crate) const DELETE: Self = Self {
        delete: true,
        ..Self::NONE
    };
    pub(crate) const TRUNCATE: Self = Self {
        truncate: true,
        ..Self::NONE
    };

    pub(crate) fn union(self, other: Self) -> Self {
        Self {
            insert: self.insert || other.insert,
            update: self.update || other.update,
            delete: self.delete || other.delete,
            truncate: self.truncate || other.truncate,
        }
    }

    /// Whether a write of `self` runs a trigger at `at`.
    fn meets(self, at: Self) -> bool {
        (self.insert && at.insert)
            || (self.update && at.update)
            || (self.delete && at.delete)
            || (self.truncate && at.truncate)
    }

    /// The events both raise.
    fn intersection(self, other: Self) -> Self {
        Self {
            insert: self.insert && other.insert,
            update: self.update && other.update,
            delete: self.delete && other.delete,
            truncate: self.truncate && other.truncate,
        }
    }
}

/// The columns an update a write makes assigns: a trigger run only at an
/// update of some columns runs where one of them is assigned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum UpdatedColumns {
    /// These columns, by normalized name; none where the write updates
    /// no row.
    Named(Vec<IdentKey>),
    /// Columns not read.
    Unknown,
}

impl UpdatedColumns {
    /// No column: of a write that updates no row.
    pub(crate) const NONE: Self = Self::Named(Vec::new());

    /// Whether one of `columns` may be among these.
    fn assigns_one_of(&self, columns: &[IdentKey]) -> bool {
        match self {
            UpdatedColumns::Named(named) => named.iter().any(|column| columns.contains(column)),
            UpdatedColumns::Unknown => true,
        }
    }
}

/// The kind of write a statement makes into a table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WriteKind {
    /// Adds rows.
    Insert,
    /// Adds rows, updating in place each row held that one meets on a key
    /// instead (`ON CONFLICT … DO UPDATE`, `ON DUPLICATE KEY UPDATE`).
    InsertOrUpdate,
    /// Adds rows, first deleting each row held that one meets on a key
    /// (MySQL `REPLACE`, `LOAD DATA … REPLACE`, Databricks `INSERT …
    /// REPLACE`).
    Replace,
    /// Puts its rows in place of every row held (`INSERT OVERWRITE`).
    Overwrite,
    /// Changes rows in place.
    Update,
    /// Removes rows.
    Delete,
    /// Removes every row.
    Truncate,
}

impl WriteKind {
    /// The events a write of this kind raises: the triggers it runs.
    pub(crate) fn events(self) -> WriteEvents {
        match self {
            WriteKind::Insert => WriteEvents::INSERT,
            WriteKind::InsertOrUpdate => WriteEvents::INSERT.union(WriteEvents::UPDATE),
            WriteKind::Replace => WriteEvents::INSERT.union(WriteEvents::DELETE),
            WriteKind::Overwrite => WriteEvents::INSERT.union(WriteEvents::TRUNCATE),
            WriteKind::Update => WriteEvents::UPDATE,
            WriteKind::Delete => WriteEvents::DELETE,
            WriteKind::Truncate => WriteEvents::TRUNCATE,
        }
    }
}

/// The columns of the row a trigger is given that a routine's body
/// assigns.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct RowAssigned {
    /// Each column, by normalized name.
    pub(crate) columns: Vec<IdentKey>,
    /// The row itself is assigned: every column.
    pub(crate) whole: bool,
}

impl RowAssigned {
    /// Whether no column is assigned.
    pub(crate) fn is_empty(&self) -> bool {
        self.columns.is_empty() && !self.whole
    }

    /// Add what `other` assigns.
    pub(crate) fn join(&mut self, other: &RowAssigned) {
        self.whole |= other.whole;
        for column in &other.columns {
            if !self.columns.contains(column) {
                self.columns.push(column.clone());
            }
        }
    }

    /// The rows a write that runs the trigger writes in place: the columns
    /// assigned taking values not known, every column where the row is.
    pub(crate) fn written(&self) -> WrittenRows {
        if self.whole {
            WrittenRows::Unknown
        } else {
            WrittenRows::Assigned(self.columns.clone())
        }
    }
}

/// What the bodies of routines change: each relation, the columns of the
/// row a trigger running one is given that they assign, and each trigger
/// they change.
#[derive(Debug, Clone, Default)]
pub(crate) struct BodyChanges {
    pub(crate) changes: Vec<RoutineChange>,
    /// Columns of the row a trigger is given: a write that runs the
    /// trigger writes them into the trigger's table.
    pub(crate) row: RowAssigned,
    /// Each change of a trigger, in order.
    pub(crate) triggers: Vec<TriggerChange>,
}

impl BodyChanges {
    /// `changes`, assigning no column of a given row and changing no
    /// trigger.
    pub(crate) fn of(changes: Vec<RoutineChange>) -> Self {
        Self {
            changes,
            row: RowAssigned::default(),
            triggers: Vec::new(),
        }
    }

    fn extend(&mut self, routine: &RoutineChanges) {
        self.changes.extend(routine.changes.iter().cloned());
        self.row.join(&routine.row);
        self.triggers.extend(routine.triggers.iter().cloned());
    }

    /// These changes as a write of `events` raises them: each write of
    /// rows, or removal, at those of its events the write raises, none at
    /// none of them.
    pub(crate) fn raised_by(self, events: WriteEvents) -> Self {
        let changes = self
            .changes
            .into_iter()
            .filter_map(|change| {
                let kind = match change.change {
                    RoutineChangeKind::Rows(at) => RoutineChangeKind::Rows(at.intersection(events)),
                    RoutineChangeKind::Removes(at) => {
                        RoutineChangeKind::Removes(at.intersection(events))
                    }
                    RoutineChangeKind::Relation => RoutineChangeKind::Relation,
                };
                match kind {
                    RoutineChangeKind::Rows(at) | RoutineChangeKind::Removes(at)
                        if at == WriteEvents::NONE =>
                    {
                        None
                    }
                    RoutineChangeKind::Rows(_)
                    | RoutineChangeKind::Removes(_)
                    | RoutineChangeKind::Relation => Some(RoutineChange {
                        change: kind,
                        ..change
                    }),
                }
            })
            .collect();
        Self { changes, ..self }
    }
}

/// A change of a trigger a statement makes, with the namespace in force
/// there ([`ScriptRelations::change_trigger`]).
#[derive(Debug, Clone)]
pub(crate) struct TriggerChange {
    pub(crate) op: TriggerOp,
    pub(crate) session: crate::ir::SessionContext,
}

/// What a statement does to the triggers and rules in force, each table
/// named as written (any table where `None`).
#[derive(Debug, Clone)]
pub(crate) enum TriggerOp {
    /// Ends each trigger or rule named `name` on `table`.
    Drop {
        name: IdentKey,
        table: Option<TableRef>,
    },
    /// Names `to` each trigger named `name` on `table`.
    Rename {
        name: IdentKey,
        table: Option<TableRef>,
        to: IdentKey,
    },
    /// Enables, or disables, each trigger named `name` (every one where
    /// `None`) on `table`.
    State {
        name: Option<IdentKey>,
        table: Option<TableRef>,
        enabled: bool,
    },
    /// Makes the rows of `child` no longer rows of `parent`.
    Uninherit { child: TableRef, parent: TableRef },
    /// Ends each trigger or rule named `name` on `table` in force where
    /// the statement starts: the one it defines replaces it.
    Replace {
        name: IdentKey,
        table: Option<TableRef>,
    },
    /// Makes the trigger, rule or child hook a statement in a routine's
    /// body defines, ending the one of its identity in force
    /// ([`ScriptTrigger::is`]) and, where it `replaces`, each other of its
    /// name.
    Create {
        name: Option<IdentKey>,
        table: Option<TableRef>,
        definition: TriggerDefinition,
        replaces: bool,
    },
}

/// What a call of a routine changes, as the routines the scripts define
/// say ([`ScriptRelations::called`]).
#[derive(Debug)]
pub(crate) enum Called {
    /// No routine of the name is defined where it is called.
    NotDefined,
    /// One is, whose body is not read, or runs a routine or SQL text the
    /// run does not read.
    Unread,
    /// What the bodies of the routines of the name change.
    Changes(BodyChanges),
}

/// What a script sets to run at each write into a table: a trigger, a
/// rule, or the parent a child table's rows are rows of
/// ([`ScriptRelations::triggers_on`]).
#[derive(Debug, Clone)]
struct ScriptTrigger {
    /// Its name, normalized, where it has one.
    name: Option<IdentKey>,
    /// The table it is on, its parts as the namespace in force at its
    /// statement fills them, each normalized; `None` where the table is
    /// not read, so a write into any table runs it.
    table: Option<crate::facts::reasoning::TableIdentity>,
    /// Where it holds from: the end of the statement defining it, or the
    /// start of the call of the routine whose body holds that statement.
    from: u32,
    /// Where it holds to, as [`RelationChange::until`].
    until: u32,
    /// Where a statement dropping or replacing it starts; `u32::MAX` for
    /// none.
    ends: u32,
    runs: TriggerRuns,
    hook: Hook,
    /// The writes it runs at.
    events: WriteEvents,
    /// The columns an update runs it at one of; any update where none.
    update_of: Vec<IdentKey>,
    /// It runs on each row before the row is written: an assignment to the
    /// row it is given writes the row.
    sets_row: bool,
    /// Where a statement enables or disables it, in order: whether it is
    /// enabled from there. It is enabled where none is before.
    states: Vec<(u32, bool)>,
}

impl ScriptTrigger {
    /// The trigger `definition` says, named `name` on `table`, in force
    /// over `holds`.
    fn created(
        name: &Option<IdentKey>,
        table: Option<crate::facts::reasoning::TableIdentity>,
        definition: &TriggerDefinition,
        holds: std::ops::Range<u32>,
    ) -> Self {
        ScriptTrigger {
            name: name.clone(),
            table,
            from: holds.start,
            until: holds.end,
            ends: u32::MAX,
            runs: definition.runs.clone(),
            hook: definition.hook,
            events: definition.events,
            update_of: definition.update_of.clone(),
            sets_row: definition.sets_row,
            states: Vec::new(),
        }
    }

    /// Whether it is in force at `at`.
    fn in_force_at(&self, at: u32) -> bool {
        (self.from..self.until.min(self.ends)).contains(&at)
    }

    /// Whether it is what `definition`, named `name` on `table`, makes: a
    /// trigger or a rule of its kind by its table and name; a child's or a
    /// parent's hook by its table and the tables it writes.
    fn is(
        &self,
        name: &Option<IdentKey>,
        table: Option<&crate::facts::reasoning::TableIdentity>,
        definition: &TriggerDefinition,
    ) -> bool {
        if self.hook != definition.hook || self.table.as_ref() != table {
            return false;
        }
        match definition.hook {
            Hook::Trigger | Hook::Rule => name.is_some() && self.name == *name,
            Hook::Child | Hook::Partition | Hook::Parent => {
                match (written_tables(&self.runs), written_tables(&definition.runs)) {
                    (Some(held), Some(made)) => {
                        held.iter().all(|table| made.contains(table))
                            && made.iter().all(|table| held.contains(table))
                    }
                    (None, None) => true,
                    (Some(_), None) | (None, Some(_)) => false,
                }
            }
        }
    }

    /// Whether a write of `events`, its update assigning `updated`, runs
    /// it: at one of its events, an update only where it assigns one of
    /// the columns it is restricted to.
    fn runs_at(&self, events: WriteEvents, updated: &UpdatedColumns) -> bool {
        let others = WriteEvents {
            update: false,
            ..self.events
        };
        others.meets(events)
            || (self.events.update
                && events.update
                && (self.update_of.is_empty() || updated.assigns_one_of(&self.update_of)))
    }

    fn enabled_at(&self, at: u32) -> bool {
        self.states
            .iter()
            .rev()
            .find(|(from, _)| *from <= at)
            .is_none_or(|(_, enabled)| *enabled)
    }

    /// Whether it is in force at `at`, named `name`, on `table` where
    /// given.
    fn named_at(
        &self,
        name: &IdentKey,
        table: Option<&crate::facts::reasoning::TableIdentity>,
        at: u32,
    ) -> bool {
        let on = match (table, &self.table) {
            (Some(table), Some(held)) => held.partial_match(table),
            (None, _) | (_, None) => true,
        };
        self.name.as_ref() == Some(name) && on && (self.from..self.ends).contains(&at)
    }
}

/// The triggers the scripts define, in the order defined, each found by
/// the name of the table it is on and its hook. A trigger's table and hook
/// do not change once it is kept.
#[derive(Debug, Clone, Default)]
struct ScriptTriggers {
    held: Vec<ScriptTrigger>,
    /// By the normalized name of the table each is on, where each is kept.
    on: std::collections::BTreeMap<IdentKey, TableHooks>,
    /// Where each on no table read is kept, by its hook.
    anywhere: TableHooks,
}

/// Where each trigger on tables of one name is kept, by its hook, each in
/// order.
#[derive(Debug, Clone, Default)]
struct TableHooks {
    triggers: Vec<usize>,
    rules: Vec<usize>,
    children: Vec<usize>,
    partitions: Vec<usize>,
    parents: Vec<usize>,
}

impl TableHooks {
    const NONE: TableHooks = TableHooks {
        triggers: Vec::new(),
        rules: Vec::new(),
        children: Vec::new(),
        partitions: Vec::new(),
        parents: Vec::new(),
    };

    fn of(&self, hook: Hook) -> &[usize] {
        match hook {
            Hook::Trigger => &self.triggers,
            Hook::Rule => &self.rules,
            Hook::Child => &self.children,
            Hook::Partition => &self.partitions,
            Hook::Parent => &self.parents,
        }
    }

    fn of_mut(&mut self, hook: Hook) -> &mut Vec<usize> {
        match hook {
            Hook::Trigger => &mut self.triggers,
            Hook::Rule => &mut self.rules,
            Hook::Child => &mut self.children,
            Hook::Partition => &mut self.partitions,
            Hook::Parent => &mut self.parents,
        }
    }

    /// Every place it holds, of every hook.
    fn all(&self) -> impl Iterator<Item = usize> + '_ {
        let TableHooks {
            triggers,
            rules,
            children,
            partitions,
            parents,
        } = self;
        [triggers, rules, children, partitions, parents]
            .into_iter()
            .flatten()
            .copied()
    }
}

impl ScriptTriggers {
    const NONE: ScriptTriggers = ScriptTriggers {
        held: Vec::new(),
        on: std::collections::BTreeMap::new(),
        anywhere: TableHooks::NONE,
    };

    fn is_empty(&self) -> bool {
        self.held.is_empty()
    }

    fn iter(&self) -> std::slice::Iter<'_, ScriptTrigger> {
        self.held.iter()
    }

    fn get(&self, index: usize) -> Option<&ScriptTrigger> {
        self.held.get(index)
    }

    fn get_mut(&mut self, index: usize) -> Option<&mut ScriptTrigger> {
        self.held.get_mut(index)
    }

    fn push(&mut self, trigger: ScriptTrigger) {
        let index = self.held.len();
        match &trigger.table {
            Some(table) => self
                .on
                .entry(table.name.clone())
                .or_default()
                .of_mut(trigger.hook)
                .push(index),
            None => self.anywhere.of_mut(trigger.hook).push(index),
        }
        self.held.push(trigger);
    }

    /// Keep only the triggers `keep` keeps, each found again where it now
    /// is.
    fn retain(&mut self, keep: impl FnMut(&ScriptTrigger) -> bool) {
        let before = self.held.len();
        self.held.retain(keep);
        if self.held.len() != before {
            let held = std::mem::take(&mut self.held);
            *self = held.into_iter().collect();
        }
    }

    /// Where each trigger that may be on a table of the normalized name
    /// `name` is kept, in order: each on a table of the name and each on no
    /// table read; every one where `name` is `None`.
    fn may_be_on(&self, name: Option<&IdentKey>) -> Vec<usize> {
        let Some(name) = name else {
            return (0..self.held.len()).collect();
        };
        let mut found: Vec<usize> = self
            .on
            .get(name)
            .into_iter()
            .flat_map(TableHooks::all)
            .chain(self.anywhere.all())
            .collect();
        found.sort_unstable();
        found
    }

    /// Where each trigger of one of `hooks` that may be on a table of the
    /// normalized name `name` is kept, in order: each on a table of the
    /// name and each on no table read.
    fn hooked_on(&self, name: &IdentKey, hooks: &[Hook]) -> Vec<usize> {
        let on = self.on.get(name);
        let mut found: Vec<usize> = hooks
            .iter()
            .flat_map(|hook| {
                on.map_or(&[][..], |on| on.of(*hook))
                    .iter()
                    .chain(self.anywhere.of(*hook))
                    .copied()
            })
            .collect();
        found.sort_unstable();
        found
    }

    /// Where each trigger of `hook` on a table of the normalized name
    /// `name` is kept, in order.
    fn kept_on(&self, name: &IdentKey, hook: Hook) -> &[usize] {
        self.on.get(name).map_or(&[], |hooks| hooks.of(hook))
    }
}

impl FromIterator<ScriptTrigger> for ScriptTriggers {
    fn from_iter<I: IntoIterator<Item = ScriptTrigger>>(triggers: I) -> Self {
        let mut kept = ScriptTriggers::default();
        for trigger in triggers {
            kept.push(trigger);
        }
        kept
    }
}

impl Extend<ScriptTrigger> for ScriptTriggers {
    fn extend<I: IntoIterator<Item = ScriptTrigger>>(&mut self, triggers: I) {
        for trigger in triggers {
            self.push(trigger);
        }
    }
}

/// Each relation of the normalized name `name`, whose changes are
/// `changes`, in force at `at`: by place, the one the last change there in
/// force at `at` left ([`ScriptRelations::in_force`]).
fn in_force_of(
    name: &IdentKey,
    changes: &[RelationChange],
    at: u32,
) -> Vec<(IdentKey, RelationPlace, usize)> {
    let mut latest: Vec<(&RelationPlace, Option<usize>)> = Vec::new();
    for change in changes
        .iter()
        .filter(|change| (change.from..change.until).contains(&at))
    {
        match latest.iter_mut().find(|(place, _)| **place == change.place) {
            Some(slot) => slot.1 = change.table,
            None => latest.push((&change.place, change.table)),
        }
    }
    latest
        .into_iter()
        .filter_map(|(place, index)| Some((name.clone(), place.clone(), index?)))
        .collect()
}

/// The tables a hook's run writes, each as its statement names it; `None`
/// where what it runs is not read, or is a routine.
fn written_tables(runs: &TriggerRuns) -> Option<Vec<crate::facts::reasoning::TableIdentity>> {
    match runs {
        TriggerRuns::Changes(Some(changes)) => {
            let mut tables = Vec::new();
            for change in &changes.changes {
                let table = trigger_table(&change.target, &change.session);
                if !tables.contains(&table) {
                    tables.push(table);
                }
            }
            Some(tables)
        }
        TriggerRuns::Changes(None) | TriggerRuns::Body { .. } | TriggerRuns::Calls(_) => None,
    }
}

/// What sets a write into a table running something.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Hook {
    Trigger,
    /// A PostgreSQL rule.
    Rule,
    /// The table inherits from others: its rows are theirs.
    Child,
    /// The table is a partition of others: its rows are theirs, and their
    /// row triggers that run before each row run on its rows.
    Partition,
    /// The table is a parent of others, or partitioned: a write of its
    /// rows writes theirs, at the events the hook runs at.
    Parent,
}

/// A write a trigger lookup matches: where it runs, the events it raises,
/// the columns its update assigns, and the hooks it may run.
#[derive(Debug, Clone, Copy)]
pub(crate) struct HookedWrite<'w> {
    pub(crate) at: u32,
    pub(crate) events: WriteEvents,
    pub(crate) updated: &'w UpdatedColumns,
    pub(crate) hooks: &'w [Hook],
}

impl Hook {
    /// Every hook.
    pub(crate) const ALL: [Hook; 5] = [
        Hook::Trigger,
        Hook::Rule,
        Hook::Child,
        Hook::Partition,
        Hook::Parent,
    ];
}

/// What a trigger, a rule or a child table runs, at which writes, and
/// whether before each row.
#[derive(Debug, Clone)]
pub(crate) struct TriggerDefinition {
    pub(crate) hook: Hook,
    pub(crate) runs: TriggerRuns,
    pub(crate) events: WriteEvents,
    /// The columns an update runs it at one of; any update where none.
    pub(crate) update_of: Vec<IdentKey>,
    pub(crate) sets_row: bool,
}

/// A trigger a write runs ([`ScriptRelations::triggers_on`]).
#[derive(Debug, Clone)]
pub(crate) struct Fired {
    /// Where it is kept.
    pub(crate) index: usize,
    pub(crate) hook: Hook,
    pub(crate) runs: TriggerRuns,
    /// An assignment to the row it is given writes the row.
    pub(crate) sets_row: bool,
}

/// Whether `hook` is a trigger: one a statement enables, disables or
/// renames.
fn is_trigger(hook: Hook) -> bool {
    match hook {
        Hook::Trigger => true,
        Hook::Rule | Hook::Child | Hook::Partition | Hook::Parent => false,
    }
}

/// The table `table` names under `session`, as a trigger is kept on it.
fn trigger_table(
    table: &TableRef,
    session: &crate::ir::SessionContext,
) -> crate::facts::reasoning::TableIdentity {
    let place = RelationPlace::of(table, session);
    crate::facts::reasoning::TableIdentity {
        database: place.database,
        schema: place.schema,
        name: IdentKey::new(&table.name),
    }
}

/// What a trigger runs.
#[derive(Debug, Clone)]
pub(crate) enum TriggerRuns {
    /// Its own body: the routine the statement ending there defines
    /// ([`ScriptRelations::define_routine`]).
    Body { end: u32 },
    /// The routine of the name.
    Calls(crate::facts::reasoning::TableIdentity),
    /// These changes: what a body of its own, in a script run before,
    /// changes, or rows written into a parent or a child table; `None`
    /// where what it runs is not read.
    Changes(Option<BodyChanges>),
}

/// The query a relation runs on each read (a view), as its statement
/// writes it: read again when a relation it reads is written.
#[derive(Debug)]
pub(crate) struct RelationQuery {
    pub(crate) stmt: crate::ast::AstStmt,
    /// The text of the script holding the statement, which its spans index.
    pub(crate) sql: std::sync::Arc<str>,
    /// The namespace in force at the statement.
    pub(crate) session: crate::ir::SessionContext,
}

/// A relation of the script, by its normalized name and its place.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RelationKey {
    name: IdentKey,
    place: RelationPlace,
}

/// One statement's change that decides what a script run after finds
/// removed ([`ScriptRelations::removals`]).
#[derive(Debug, Clone)]
struct RemovalEvent {
    place: RelationPlace,
    /// Where it holds to, as [`RelationChange::until`].
    until: u32,
    /// The top-level statement holding it ([`RelationSite::holder`]).
    holder: u32,
    /// No body holding the statement may not run, or run again, where it
    /// is written: it holds on every path after it.
    settled: bool,
    /// It concerns a temporary table, which the session that made it holds.
    temporary: bool,
    what: Removing,
}

/// What a [`RemovalEvent`] does.
#[derive(Debug, Clone)]
enum Removing {
    /// Makes a table of the name, or renames one to it.
    Made,
    Dropped(crate::facts::query::DroppedObjectKind),
    /// Renames the table to the name written.
    RenamedTo(String),
    /// Drops the column, by its normalized name.
    ColumnDropped(IdentKey),
    /// Adds the column, by its normalized name.
    ColumnAdded(IdentKey),
}

/// Where one of a script's own statements changed a relation of a name
/// ([`ScriptRelations::named`]).
#[derive(Debug, Clone)]
struct RelationNaming {
    /// Where it holds from: the end of the statement.
    from: u32,
    /// Where it holds to, as [`RelationChange::until`].
    until: u32,
    place: RelationPlace,
}

/// A script with no relations: what a statement lowered outside a
/// script's order finds.
static NO_RELATIONS: ScriptRelations = ScriptRelations {
    tables: Vec::new(),
    changes: std::collections::BTreeMap::new(),
    rerunning: std::collections::BTreeSet::new(),
    named: std::collections::BTreeMap::new(),
    removals: std::collections::BTreeMap::new(),
    earlier: crate::facts::reasoning::EarlierRemovals {
        tables: Vec::new(),
        columns: Vec::new(),
    },
    session_schema: None,
    temporary_drops: Vec::new(),
    routines: Vec::new(),
    triggers: ScriptTriggers::NONE,
    written: crate::facts::secrets::WrittenColumns::NONE,
    pipes: Vec::new(),
};

/// A relation as a statement left it.
#[derive(Debug, Clone)]
struct ScriptTable {
    table: CatalogTable,
    origin: RelationOrigin,
    listing: ColumnListing,
    /// By column, what reasoning found of the value a statement made it
    /// with ([`MadeValue`]).
    values: std::collections::BTreeMap<IdentKey, MadeValue>,
    /// By column, the tags of its own a statement wrote, each part folded
    /// as the statement wrote it; any other tag of the column is as the
    /// catalog records it.
    written: std::collections::BTreeMap<IdentKey, Vec<CatalogTag>>,
    /// A temporary table, which the session that made it holds and a script
    /// run after does not find ([`ScriptRelations::left`]).
    temporary: bool,
    /// Of a relation that runs its query on each read (a view), the
    /// relations its query reads, by normalized name and place: a write
    /// into one of them, or a change of it, changes what is known of its
    /// columns too.
    reruns: Vec<(IdentKey, RelationPlace)>,
    /// Whether it is a view: its columns are names for what its query
    /// selects.
    view: bool,
    /// Of such a relation, its query, read again at a write into one of
    /// `reruns`.
    query: Option<std::sync::Arc<RelationQuery>>,
    /// Its rows hold none: a filter of the query that made it contradicted
    /// what its input held. Every column's reading carries it; `values`
    /// keep the claims that query made.
    holds_no_row: bool,
}

impl ScriptTable {
    /// `table`, with nothing found of its columns' values and no tag a
    /// statement wrote; not temporary, a table.
    fn new(table: CatalogTable, origin: RelationOrigin, listing: ColumnListing) -> Self {
        Self {
            table,
            origin,
            listing,
            values: std::collections::BTreeMap::new(),
            written: std::collections::BTreeMap::new(),
            temporary: false,
            view: false,
            reruns: Vec::new(),
            query: None,
            holds_no_row: false,
        }
    }

    /// What is known of `column`'s value, with whether the relation holds
    /// no row.
    fn value_of(&self, column: &IdentKey) -> MadeValue {
        let mut value = self.values.get(column).cloned().unwrap_or_default();
        value.constraints.holds_no_row = self.holds_no_row;
        value
    }

    /// Take off each column value the mark that its rows hold none:
    /// whether any carried it. Rows that hold none in one column hold none
    /// in any, so the mark is the relation's.
    fn settle_no_row(&mut self) -> bool {
        let mut none = false;
        for value in self.values.values_mut() {
            none |= value.constraints.holds_no_row;
            value.constraints.holds_no_row = false;
        }
        self.values.retain(|_, value| value.is_known());
        none
    }

    /// The relation a statement makes named `name`, with `columns` as
    /// [`RelationEdit::Create`] gives them: each keeping the tags of the
    /// column of its name of `standing`, the catalog's table the statement
    /// leaves standing, whose table tags it takes too; with the `keys` it
    /// declares.
    fn made(
        name: &str,
        columns: Option<Vec<MadeColumn>>,
        every_column: bool,
        standing: Option<&CatalogTable>,
        keys: Vec<CatalogConstraint>,
    ) -> Self {
        let mut values = std::collections::BTreeMap::new();
        let mut written = std::collections::BTreeMap::new();
        let mut made_columns = Vec::new();
        for made in columns.unwrap_or_default() {
            let key = IdentKey::new_as(&made.column.name.name, NameKind::Column);
            let mut column = made.column;
            let catalogued_column = standing.and_then(|table| {
                table.columns.iter().find(|catalogued| {
                    IdentKey::new_as(&catalogued.name.name, NameKind::Column) == key
                })
            });
            for tag in catalogued_column.into_iter().flat_map(|c| &c.tags) {
                if !column.tags.iter().any(|held| same_tag(held, tag)) {
                    column.tags.push(tag.clone());
                }
            }
            if !made.written.is_empty() {
                written.insert(key.clone(), made.written);
            }
            if made.value.is_known() {
                values.insert(key, made.value);
            }
            made_columns.push(column);
        }
        let mut table = made_table(name, made_columns);
        table.constraints = keys;
        if let Some(standing) = standing {
            table.tags = standing.tags.clone();
        }
        let mut made = Self {
            table,
            origin: RelationOrigin::Made,
            listing: if every_column {
                ColumnListing::Every
            } else {
                ColumnListing::Some
            },
            values,
            written,
            temporary: false,
            view: false,
            reruns: Vec::new(),
            query: None,
            holds_no_row: false,
        };
        made.holds_no_row = made.settle_no_row();
        made
    }

    /// Whether what is known of its rows is what is known of `other`'s.
    fn reads_as(&self, other: &ScriptTable) -> bool {
        self.holds_no_row == other.holds_no_row
            && self.values.len() == other.values.len()
            && self
                .values
                .iter()
                .zip(&other.values)
                .all(|((name, value), (held, other))| name == held && value.same_as(other))
    }

    /// This relation after rows are written into it as `rows` says,
    /// constraints the rows of either of two relations meet joined by
    /// `reasoning` ([`crate::facts::reasoning::Reasoning::rows_of_either`]).
    fn after_write(
        &self,
        rows: &WrittenRows,
        reasoning: &dyn crate::facts::reasoning::Reasoning,
    ) -> Self {
        self.after_rows(rows, true, reasoning)
    }

    /// This relation, as a statement's earlier writes left it, after
    /// another write of the statement lands `rows` too: rows in place of
    /// every row are added, as they replace only the rows the statement's
    /// start held.
    fn after_more_rows(
        &self,
        rows: &WrittenRows,
        reasoning: &dyn crate::facts::reasoning::Reasoning,
    ) -> Self {
        self.after_rows(rows, false, reasoning)
    }

    /// [`Self::after_write`], rows in place of every row replacing those
    /// held only where `replacing`.
    fn after_rows(
        &self,
        rows: &WrittenRows,
        replacing: bool,
        reasoning: &dyn crate::facts::reasoning::Reasoning,
    ) -> Self {
        let mut written = self.clone();
        let key = |column: &CatalogColumn| IdentKey::new_as(&column.name.name, NameKind::Column);
        for column in &self.table.columns {
            let column = key(column);
            let held = self.value_of(&column);
            let after = match rows {
                WrittenRows::Known { columns, replaces } => {
                    let added = columns
                        .iter()
                        .find(|(name, _)| *name == column)
                        .map(|(_, value)| value);
                    match (*replaces && replacing, added) {
                        (true, added) => added.cloned().unwrap_or_default(),
                        (false, added) => held.with_rows_added(added, reasoning),
                    }
                }
                WrittenRows::Assigned(assigned) if assigned.contains(&column) => {
                    held.with_rows_added(None, reasoning)
                }
                WrittenRows::Assigned(_) => held,
                WrittenRows::Unknown => held.with_rows_added(None, reasoning),
            };
            if after.is_known() {
                written.values.insert(column, after);
            } else {
                written.values.remove(&column);
            }
        }
        // Rows added hold none where the rows written hold none; rows
        // changed in place are the rows there were.
        let holds_no_row = match rows {
            WrittenRows::Known { columns, replaces } => {
                let added_none = columns
                    .iter()
                    .any(|(_, value)| value.constraints.holds_no_row);
                added_none && ((*replaces && replacing) || self.holds_no_row)
            }
            WrittenRows::Assigned(_) => self.holds_no_row,
            WrittenRows::Unknown => false,
        };
        written.settle_no_row();
        written.holds_no_row = holds_no_row;
        written
    }

    /// This relation after a statement not read, which may have written
    /// any rows into it or, where `reach` says, changed what it declares:
    /// rows not known are written, and of a relation the script made whose
    /// declarations it may change, no key or `NOT NULL` is known; what the
    /// catalog records of its table stands.
    fn after_unread(
        &self,
        reasoning: &dyn crate::facts::reasoning::Reasoning,
        reach: UnreadReach,
    ) -> Self {
        let mut unread = self.after_write(&WrittenRows::Unknown, reasoning);
        match (unread.origin, reach) {
            (RelationOrigin::Made, UnreadReach::Anything) => {
                unread.table.constraints.clear();
                for column in &mut unread.table.columns {
                    column.nullable = None;
                }
            }
            (RelationOrigin::Made, UnreadReach::Rows) | (RelationOrigin::Catalogued, _) => {}
        }
        unread
    }
}

/// What a statement not read may change ([`ScriptRelations::unread`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UnreadReach {
    /// Rows, and what a relation declares.
    Anything,
    /// Rows alone: what runs cannot change a declaration (a routine the
    /// dialect lets run no DDL).
    Rows,
}

/// The rows a statement writes into a relation ([`RelationEdit::Write`]).
/// A statement that only removes rows writes none: what held of every row
/// holds of those left.
#[derive(Debug)]
pub(crate) enum WrittenRows {
    /// Rows added, or in place of every row where `replaces`, whose
    /// values are known by column, a column not listed holding values not
    /// known.
    Known {
        columns: Vec<(IdentKey, MadeValue)>,
        replaces: bool,
    },
    /// Rows changed in place, the columns listed taking values not known
    /// and the others keeping theirs.
    Assigned(Vec<IdentKey>),
    /// Rows added whose values are not known.
    Unknown,
}

/// What reasoning found of the value a statement gave a column of a
/// relation it made, beside the column's own tags. Nothing with
/// recognition alone.
#[derive(Debug, Clone, Default)]
pub(crate) struct MadeValue {
    /// The tags reaching the value: those reasoning finds along the
    /// query's lineage.
    pub(crate) tags: Vec<CatalogTag>,
    /// How much of the tagged value the column holds, where that is not
    /// the value itself: of a count of a tagged column, the count.
    pub(crate) exposure: Option<crate::facts::catalog::ValueExposure>,
    /// What the query's rows meet in the column.
    pub(crate) constraints: crate::ir::constraint_types::IrColumnConstraints,
    /// Whether the column may be NULL; `None` where reasoning cannot say.
    pub(crate) nullable: Option<bool>,
    /// No two of the query's rows hold one value in the column.
    pub(crate) unique: bool,
}

impl MadeValue {
    /// The tags reaching the value, and how much of it the column holds;
    /// nothing else.
    fn tags_only(&self) -> MadeValue {
        MadeValue {
            tags: self.tags.clone(),
            exposure: self.exposure,
            ..MadeValue::default()
        }
    }

    /// Whether this says of the value what `other` does.
    fn same_as(&self, other: &MadeValue) -> bool {
        self.tags.len() == other.tags.len()
            && self
                .tags
                .iter()
                .zip(&other.tags)
                .all(|(a, b)| same_tag(a, b))
            && self.exposure == other.exposure
            && self.constraints == other.constraints
            && self.nullable == other.nullable
            && self.unique == other.unique
    }

    /// Whether reasoning found anything of the value.
    pub(crate) fn is_known(&self) -> bool {
        !self.tags.is_empty()
            || self.exposure.is_some()
            || self.constraints != crate::ir::constraint_types::IrColumnConstraints::default()
            || self.nullable.is_some()
            || self.unique
    }

    /// What holds of the column's values once rows holding `added` join
    /// the rows holding this; `added` is `None` where what they hold is not
    /// known. A tag of either may reach the value; a constraint, a
    /// NULL-ability or a key holds only where it holds of both, and no
    /// value is known to be held once where rows are added.
    fn with_rows_added(
        &self,
        added: Option<&MadeValue>,
        reasoning: &dyn crate::facts::reasoning::Reasoning,
    ) -> MadeValue {
        let Some(added) = added else {
            return MadeValue {
                tags: self.tags.clone(),
                exposure: self.exposure,
                ..MadeValue::default()
            };
        };
        let mut tags = self.tags.clone();
        for tag in &added.tags {
            if !tags.iter().any(|held| same_tag(held, tag)) {
                tags.push(tag.clone());
            }
        }
        // How much of a tagged value the column holds: that of the rows
        // that carry a tag, the whole value where both do and differ.
        let exposure = match (self.tags.is_empty(), added.tags.is_empty()) {
            (true, _) => added.exposure,
            (false, true) => self.exposure,
            (false, false) if self.exposure == added.exposure => self.exposure,
            (false, false) => None,
        };
        MadeValue {
            tags,
            exposure,
            constraints: reasoning.rows_of_either(&self.constraints, &added.constraints),
            nullable: match (self.nullable, added.nullable) {
                (Some(held), Some(added)) => Some(held || added),
                (Some(_), None) | (None, Some(_)) | (None, None) => None,
            },
            unique: false,
        }
    }
}

/// A column a statement gives a relation it makes.
#[derive(Debug)]
pub(crate) struct MadeColumn {
    /// The column, carrying its own tags: those the statement writes on it
    /// and those of the column it copies.
    pub(crate) column: CatalogColumn,
    /// Of its own tags, those the statement writes on it.
    pub(crate) written: Vec<CatalogTag>,
    pub(crate) value: MadeValue,
}

/// Whether a relation's listed columns are all it has.
#[derive(Debug, Clone, Copy)]
enum ColumnListing {
    /// They are, where the catalog lists every column.
    Every,
    /// A statement changed the columns in a way not read: the listed
    /// columns are the table's, and a name not listed may be one too.
    Some,
}

/// What a relation of the script stands for.
#[derive(Debug, Clone, Copy)]
enum RelationOrigin {
    /// A relation a statement made, or a table renamed to its name. One
    /// made at the catalog's place of its name stands for that table.
    Made,
    /// The catalog's table of its name and place, with the columns
    /// statements added, renamed and dropped.
    Catalogued,
}

/// What one statement made of a relation of a name.
#[derive(Debug, Clone)]
struct RelationChange {
    /// Where it holds from: the end of the statement.
    from: u32,
    /// Where it holds to: the end of the routine whose body holds the
    /// statement, the script's end for any other.
    until: u32,
    place: RelationPlace,
    /// The relation there from then on, by its index in
    /// [`ScriptRelations::tables`]; `None` where the statement dropped it
    /// or renamed it away.
    table: Option<usize>,
    /// The bodies holding the statement that may not run where they are
    /// written ([`RelationSite::unsettled`]), outermost first: the change
    /// holds on every path into a point only where each of them holds that
    /// point too, or a body beside it on every other path changes it too.
    unsettled: Vec<crate::UnsettledRange>,
    /// Of the change a write makes, the relation the write read: the one
    /// there at the statement's start, by its index in
    /// [`ScriptRelations::tables`].
    read: Option<usize>,
}

impl RelationChange {
    /// The bodies holding it that do not hold the point `at` after it,
    /// outermost first: those that may not run on a path into `at`.
    fn unsettled_before(&self, at: u32) -> &[crate::UnsettledRange] {
        let held = self
            .unsettled
            .iter()
            .take_while(|body| body.range.contains(&at))
            .count();
        &self.unsettled[held..]
    }
}

/// A relation's database and schema, as the session fills the parts its
/// name omits, normalized.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RelationPlace {
    database: Option<IdentKey>,
    schema: Option<IdentKey>,
    /// The session's own schema of temporary tables
    /// ([`crate::dialect::TemporaryTables::SessionSchema`]), which only a
    /// name written without a database or schema reaches, before any
    /// other.
    session_temporary: bool,
}

impl RelationPlace {
    /// Where `table` stands under `session`: a schema the name omits and
    /// the session's search path gives is the path's first.
    fn of(table: &TableRef, session: &crate::ir::SessionContext) -> Self {
        let (database, schema) = crate::ir::span_extract::session_default_parts(table, session);
        let first = searched(table, session).and_then(<[String]>::first);
        Self {
            database: database.map(IdentKey::new),
            schema: schema.or(first.map(String::as_str)).map(IdentKey::new),
            session_temporary: false,
        }
    }

    /// The session's own schema of temporary tables.
    fn session_temporary() -> Self {
        Self {
            database: None,
            schema: None,
            session_temporary: true,
        }
    }
}

/// The schemas `table` is looked for in under `session`, in order: the
/// session's search path, where neither the name nor the session's schema
/// places it ([`crate::ir::SessionContext::search_path`]); `None` where one
/// does, or the path is not known.
fn searched<'s>(table: &TableRef, session: &'s crate::ir::SessionContext) -> Option<&'s [String]> {
    let (_, schema) = crate::ir::span_extract::session_default_parts(table, session);
    (schema.is_none() && !session.search_path.is_empty()).then_some(session.search_path.as_slice())
}

/// The names the catalog looks for `table` under, under `session`: in
/// each schema of the session's search path, where neither the name nor
/// the session's schema places it; else at the parts the session fills.
pub(crate) fn searched_names(
    table: &TableRef,
    session: &crate::ir::SessionContext,
) -> Vec<TableRef> {
    let (database, schema) = crate::ir::span_extract::session_default_parts(table, session);
    let placed = TableRef {
        db: database.map(str::to_string),
        schema: schema.map(str::to_string),
        ..table.clone()
    };
    match searched(table, session) {
        Some(path) if !path.is_empty() => path
            .iter()
            .map(|schema| in_schema(&placed, schema))
            .collect(),
        Some(_) | None => vec![placed],
    }
}

/// `table` with its schema written `schema`.
/// The tables a name may be ([`RelationsAt::resolution`]).
#[derive(Debug, Clone)]
pub(crate) enum Resolution {
    /// The one table it names.
    One(TableRef),
    /// One of these, the run cannot tell which.
    Among(Vec<TableRef>),
    /// The table of its name in any schema.
    Any(TableRef),
}

fn in_schema(table: &TableRef, schema: &str) -> TableRef {
    TableRef {
        schema: Some(schema.to_string()),
        ..table.clone()
    }
}

/// What a statement does to a relation it names ([`ScriptRelations::record`]).
pub(crate) enum RelationEdit<'a> {
    /// Creates it, with the columns the statement names, each carrying the
    /// tags the statement gives it or its query's value carries: every
    /// column a reader can name where `every_column`, else some of them
    /// and others not known; columns not known where `None`. A clone of
    /// a table the script or the catalog has (`clone_of`) is that table,
    /// columns, tags and values. Under `if_not_exists`, a relation that
    /// exists is left as it is.
    Create {
        columns: Option<Vec<MadeColumn>>,
        every_column: bool,
        /// A temporary table, wherever it stands.
        temporary: bool,
        /// A temporary table in the session's own schema
        /// ([`crate::dialect::TemporaryTables::SessionSchema`]).
        session_temporary: bool,
        if_not_exists: bool,
        clone_of: Option<&'a TableRef>,
        /// A table its statement names the columns of, with neither a
        /// query nor `OR REPLACE`. Where the catalog has a table at the
        /// place of its name that no statement before changed, the
        /// statement would fail against that table as it stands; the
        /// catalog is read as recording the table the statement makes:
        /// the declared columns, each keeping the catalog's tags of the
        /// column of its name, and the catalog's table tags.
        fails_where_it_exists: bool,
        /// Of a relation that runs its query on each read (a view), the
        /// tables its query reads, and the query.
        reruns: &'a [TableRef],
        query: Option<std::sync::Arc<RelationQuery>>,
        /// The keys it declares, which hold whatever is written into it.
        keys: Vec<CatalogConstraint>,
        /// A view: its columns are names for what its query selects.
        view: bool,
    },
    /// Drops it, a table or a view; `temporary` where its name is a
    /// temporary table's whatever the script made of it.
    Drop {
        kind: crate::facts::query::DroppedObjectKind,
        temporary: bool,
    },
    /// Renames it to the name `to` writes, and changes its columns as
    /// `mutations` add, rename and drop them.
    RenameTo {
        to: &'a TableRef,
        mutations: &'a [DdlSchemaMutation],
    },
    /// Changes its columns as `mutations` add, rename and drop them, drops
    /// what `dropped` names it declares, and declares the keys `added`,
    /// each unnamed unique key named after its first column where
    /// `column_names`; any other change leaves them as they are.
    Alter {
        mutations: &'a [DdlSchemaMutation],
        dropped: &'a [DroppedDeclaration],
        added: &'a [CatalogConstraint],
        column_names: bool,
    },
    /// Exchanges it with the table `other` names: each name holds what the
    /// other held, a table not known by either name holding columns not
    /// known.
    SwapWith { other: &'a TableRef },
}

/// A declaration an `ALTER` drops from a table ([`RelationEdit::Alter`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DroppedDeclaration {
    /// Its primary key.
    PrimaryKey,
    /// The constraint of the name, normalized; `None` where the action
    /// names none that is read.
    Constraint(Option<IdentKey>),
    /// The index or key of the name, normalized (`DROP INDEX`): the unique
    /// key of the name, the primary key under `PRIMARY`; `None` where the
    /// action names none that is read.
    Index(Option<IdentKey>),
    /// The `NOT NULL` of the column of the name, normalized.
    NotNull(IdentKey),
    /// Any it declares: an action that is not read.
    Every,
}

/// Name each unnamed unique key of `keys` after its first column as
/// written, `_2`, `_3`, â¦ added where `taken`, or a key before it, has the
/// name.
pub(crate) fn name_unnamed_keys(keys: &mut [CatalogConstraint], taken: &[CatalogConstraint]) {
    let mut names: Vec<IdentKey> = taken
        .iter()
        .chain(keys.iter())
        .filter_map(|key| key.name.as_deref())
        .map(|name| IdentKey::new_as(name, NameKind::Relation))
        .collect();
    for key in keys.iter_mut() {
        let unique = match key.kind {
            CatalogConstraintKind::Unique => true,
            CatalogConstraintKind::PrimaryKey
            | CatalogConstraintKind::ForeignKey
            | CatalogConstraintKind::Unknown => false,
        };
        if key.name.is_some() || !unique {
            continue;
        }
        // The column's name, unquoted.
        let Some(first) = key
            .columns
            .first()
            .map(|column| column.name.trim_matches(['`', '"']).to_string())
        else {
            continue;
        };
        let mut name = first.clone();
        let mut suffix = 2;
        while names.contains(&IdentKey::new_as(&name, NameKind::Relation)) {
            name = format!("{first}_{suffix}");
            suffix += 1;
        }
        names.push(IdentKey::new_as(&name, NameKind::Relation));
        key.name = Some(name);
    }
}

/// Drop from `table` the declarations `dropped` names. A constraint is
/// met by its name, whatever its kind: a name no constraint the table
/// declares has is one the database gave a constraint declared unnamed,
/// so each unnamed one goes; one not named, any. An index is met by its
/// name among the unique keys, `PRIMARY` naming the primary key: a name no
/// unique key has is one the database gave an unnamed one, so each goes.
fn drop_declarations(table: &mut CatalogTable, dropped: &[DroppedDeclaration]) {
    let named = |key: &CatalogConstraint, name: &IdentKey| {
        key.name
            .as_deref()
            .is_some_and(|held| IdentKey::new_as(held, NameKind::Relation) == *name)
    };
    let unique = |key: &CatalogConstraint| matches!(key.kind, CatalogConstraintKind::Unique);
    for declaration in dropped {
        match declaration {
            DroppedDeclaration::PrimaryKey => table
                .constraints
                .retain(|key| !matches!(key.kind, CatalogConstraintKind::PrimaryKey)),
            DroppedDeclaration::Constraint(Some(name)) => {
                if table.constraints.iter().any(|key| named(key, name)) {
                    table.constraints.retain(|key| !named(key, name));
                } else {
                    table.constraints.retain(|key| key.name.is_some());
                }
            }
            DroppedDeclaration::Constraint(None) => table.constraints.clear(),
            DroppedDeclaration::Index(Some(name)) => {
                if IdentKey::new_as("PRIMARY", NameKind::Relation) == *name {
                    table
                        .constraints
                        .retain(|key| !matches!(key.kind, CatalogConstraintKind::PrimaryKey));
                } else if table
                    .constraints
                    .iter()
                    .any(|key| unique(key) && named(key, name))
                {
                    table
                        .constraints
                        .retain(|key| !(unique(key) && named(key, name)));
                } else {
                    table
                        .constraints
                        .retain(|key| !(unique(key) && key.name.is_none()));
                }
            }
            DroppedDeclaration::Index(None) => table.constraints.retain(|key| !unique(key)),
            DroppedDeclaration::NotNull(column) => {
                for held in &mut table.columns {
                    if IdentKey::new_as(&held.name.name, NameKind::Column) == *column {
                        held.nullable = None;
                    }
                }
            }
            DroppedDeclaration::Every => {
                table.constraints.clear();
                for held in &mut table.columns {
                    held.nullable = None;
                }
            }
        }
    }
}

/// Where a statement that changes a relation stands in its script.
#[derive(Debug, Clone, Copy)]
pub(crate) struct RelationSite<'a> {
    pub(crate) statement: crate::lexer::Span,
    /// The 0-indexed position, among the script's top-level statements,
    /// of the statement or of the one holding it.
    pub(crate) holder: u32,
    /// The end of the routine whose body holds the statement, `u32::MAX`
    /// for any other.
    pub(crate) until: u32,
    /// The bodies holding the statement that may not run, or may run
    /// again, where they are written ([`crate::StatementRun::unsettled`]).
    pub(crate) unsettled: &'a [crate::UnsettledRange],
    /// The namespace in force at the statement.
    pub(crate) session: &'a crate::ir::SessionContext,
}

impl ScriptRelations {
    /// The relations as a statement starting at `at` finds them.
    pub(crate) fn at(&self, at: u32) -> RelationsAt<'_> {
        RelationsAt {
            relations: self,
            at,
        }
    }

    /// Whether no statement changed a relation, none removed a table or a
    /// column, and none defined a routine.
    pub(crate) fn is_empty(&self) -> bool {
        self.changes.is_empty()
            && self.earlier == crate::facts::reasoning::EarlierRemovals::default()
            && self.routines.is_empty()
            && self.triggers.is_empty()
    }

    /// The tables and columns the scripts run before left removed.
    pub(crate) fn earlier(&self) -> &crate::facts::reasoning::EarlierRemovals {
        &self.earlier
    }

    /// The spans of this script's statements that drop a temporary table,
    /// on every path into them, which a table of its name may stand behind.
    pub(crate) fn temporary_drops(&self) -> &[crate::lexer::Span] {
        &self.temporary_drops
    }

    /// The tables and columns removed after this script's statements, the
    /// script being the file `file`: those the scripts before left, each
    /// cancelled by a statement that makes the table again or adds the
    /// column again on every path after, and those the statements outside
    /// a routine's body remove, as they remove them in order. What a
    /// statement does to a temporary table is not read.
    fn removals_left(&self, file: Option<&str>) -> crate::facts::reasoning::EarlierRemovals {
        use crate::facts::reasoning::{
            EarlierStatement, RemovedColumn, RemovedTable, TableIdentity, TableRemoval,
        };
        let mut left = self.earlier.clone();
        for (name, events) in &self.removals {
            for event in events
                .iter()
                .filter(|event| event.until == u32::MAX && !event.temporary)
            {
                let table = TableIdentity {
                    database: event.place.database.clone(),
                    schema: event.place.schema.clone(),
                    name: name.clone(),
                };
                let at = EarlierStatement {
                    index: event.holder,
                    file: file.map(str::to_string),
                };
                let mut remove = |removal: TableRemoval| {
                    left.tables
                        .retain(|removed| !removed.table.partial_match(&table));
                    left.tables.push(RemovedTable {
                        table: table.clone(),
                        removal,
                        at: at.clone(),
                    });
                };
                match &event.what {
                    Removing::Dropped(kind) => remove(TableRemoval::Dropped(*kind)),
                    Removing::RenamedTo(to) => remove(TableRemoval::RenamedTo(to.clone())),
                    Removing::Made => {
                        if event.settled {
                            left.tables
                                .retain(|removed| !removed.table.partial_match(&table));
                            left.columns
                                .retain(|removed| !removed.table.partial_match(&table));
                        }
                    }
                    Removing::ColumnDropped(column) => {
                        left.columns.retain(|removed| {
                            !(removed.column == *column && removed.table.partial_match(&table))
                        });
                        left.columns.push(RemovedColumn {
                            table: table.clone(),
                            column: column.clone(),
                            at: at.clone(),
                        });
                    }
                    Removing::ColumnAdded(column) => {
                        if event.settled {
                            left.columns.retain(|removed| {
                                !(removed.column == *column && removed.table.partial_match(&table))
                            });
                        }
                    }
                }
            }
        }
        left
    }

    /// The statement at `site` does `what` to the relation `name` names at
    /// `place` ([`RemovalEvent`]).
    fn removal(
        &mut self,
        name: &str,
        place: &RelationPlace,
        site: RelationSite<'_>,
        temporary: bool,
        what: Removing,
    ) {
        // A table made in a body that runs only where it is absent is made
        // on every path.
        let made = crate::facts::reasoning::TableIdentity {
            database: place.database.clone(),
            schema: place.schema.clone(),
            name: IdentKey::new(name),
        };
        let settled = match what {
            Removing::Made => site.unsettled.iter().all(|body| {
                body.absent
                    .as_ref()
                    .is_some_and(|absent| absent.partial_match(&made))
            }),
            Removing::Dropped(_)
            | Removing::RenamedTo(_)
            | Removing::ColumnDropped(_)
            | Removing::ColumnAdded(_) => site.unsettled.is_empty(),
        };
        self.removals
            .entry(IdentKey::new(name))
            .or_default()
            .push(RemovalEvent {
                place: place.clone(),
                until: site.until,
                holder: site.holder,
                settled,
                temporary,
                what,
            });
    }

    /// The column drops and additions of `mutations` the statement at
    /// `site` makes to the table `name` names at `place`.
    fn column_removals(
        &mut self,
        name: &str,
        place: &RelationPlace,
        site: RelationSite<'_>,
        temporary: bool,
        mutations: &[DdlSchemaMutation],
    ) {
        for mutation in mutations {
            let what = match mutation {
                DdlSchemaMutation::DropColumn { column_name } => {
                    Removing::ColumnDropped(IdentKey::new_as(column_name, NameKind::Column))
                }
                DdlSchemaMutation::AddColumn { column_name } => {
                    Removing::ColumnAdded(IdentKey::new_as(column_name, NameKind::Column))
                }
                DdlSchemaMutation::RenameTo { .. }
                | DdlSchemaMutation::RenameColumn { .. }
                | DdlSchemaMutation::SwapWith { .. }
                | DdlSchemaMutation::SetColumnTags { .. }
                | DdlSchemaMutation::UnsetColumnTags { .. }
                | DdlSchemaMutation::SetColumnType { .. }
                | DdlSchemaMutation::ColumnsUnread
                | DdlSchemaMutation::NamesUnread => continue,
            };
            self.removal(name, place, site, temporary, what);
        }
    }

    /// Whether the relation held at `index` is a temporary table.
    fn held_temporary(&self, index: usize) -> bool {
        self.tables.get(index).is_some_and(|table| table.temporary)
    }

    /// These relations, a temporary table placed as `temporary` says.
    pub(crate) fn placing_temporary_tables(
        mut self,
        temporary: crate::dialect::TemporaryTables,
    ) -> Self {
        self.session_schema = match temporary {
            crate::dialect::TemporaryTables::SessionSchema { name } => name,
            crate::dialect::TemporaryTables::InSchema
            | crate::dialect::TemporaryTables::NotStated => None,
        };
        self
    }

    /// Whether `table` is named in the session's own schema of temporary
    /// tables by the name a statement may write for it.
    fn in_session_schema(&self, table: &TableRef) -> bool {
        match (self.session_schema, &table.db, &table.schema) {
            (Some(session), None, Some(schema)) => IdentKey::new(schema) == IdentKey::new(session),
            (Some(_), Some(_), _) | (Some(_), None, None) | (None, _, _) => false,
        }
    }

    /// The columns the statements of this script and of the scripts run
    /// before write values into.
    pub(crate) fn written(&self) -> &crate::facts::secrets::WrittenColumns {
        &self.written
    }

    /// [`Self::written`], to record a statement's writes in.
    pub(crate) fn written_mut(&mut self) -> &mut crate::facts::secrets::WrittenColumns {
        &mut self.written
    }

    /// Record that the statement starting at `from` defines the pipe `name`.
    pub(crate) fn define_pipe(&mut self, name: crate::facts::reasoning::TableIdentity, from: u32) {
        self.pipes.push((name, from));
    }

    /// Whether a pipe that may be the one `name` names is defined, by this
    /// script before the statement starting at `at` or by a script run
    /// before. Definitions are recorded in the order the run reads them.
    pub(crate) fn defines_pipe(
        &self,
        name: &crate::facts::reasoning::TableIdentity,
        at: u32,
    ) -> bool {
        self.pipes
            .iter()
            .any(|(defined, from)| *from <= at && defined.partial_match(name))
    }

    /// The relations as the script leaves them, for a script that runs
    /// after it in a session of its own: at each place of each name, what
    /// the last statement outside a routine's body left there, holding from
    /// the start. A temporary table is the session's: what it hid is left
    /// there, and a statement that drops it or renames it away leaves that.
    /// The names the scripts so far changed outside a routine's body are
    /// the run's to say ([`RelationsAt::names`]), these relations holding
    /// what is known of them. The tables and columns removed are those
    /// [`Self::removals_left`] gives, the script being the file `file`.
    pub(crate) fn left(&self, file: Option<&str>) -> ScriptRelations {
        let mut left = ScriptRelations {
            session_schema: self.session_schema,
            earlier: self.removals_left(file),
            routines: self
                .routines
                .iter()
                .filter(|routine| routine.until == u32::MAX && routine.ends == u32::MAX)
                .map(|routine| RoutineChanges {
                    from: 0,
                    end: u32::MAX,
                    ..routine.clone()
                })
                .collect(),
            triggers: self
                .triggers
                .iter()
                .filter(|trigger| trigger.until == u32::MAX && trigger.ends == u32::MAX)
                .map(|trigger| ScriptTrigger {
                    from: 0,
                    states: if trigger.enabled_at(u32::MAX) {
                        Vec::new()
                    } else {
                        vec![(0, false)]
                    },
                    runs: match &trigger.runs {
                        TriggerRuns::Body { end } => {
                            TriggerRuns::Changes(self.changes_of_body(*end))
                        }
                        TriggerRuns::Calls(_) | TriggerRuns::Changes(_) => trigger.runs.clone(),
                    },
                    ..trigger.clone()
                })
                .collect(),
            written: self.written.clone(),
            pipes: self
                .pipes
                .iter()
                .map(|(name, _)| (name.clone(), 0))
                .collect(),
            ..ScriptRelations::default()
        };
        for (name, changes) in &self.changes {
            // At each place: what a statement left there for a script run
            // after, if any did, and whether a temporary table holds it.
            let mut latest: Vec<(&RelationPlace, Option<&RelationChange>, bool)> = Vec::new();
            for change in changes.iter().filter(|change| change.until == u32::MAX) {
                let slot = match latest
                    .iter()
                    .position(|(place, ..)| **place == change.place)
                {
                    Some(slot) => slot,
                    None => {
                        latest.push((&change.place, None, false));
                        latest.len() - 1
                    }
                };
                let (_, persistent, temporary) = &mut latest[slot];
                let made = change.table.and_then(|index| self.tables.get(index));
                match made {
                    Some(table) if table.temporary => *temporary = true,
                    Some(_) => {
                        *persistent = Some(change);
                        *temporary = false;
                    }
                    None if *temporary => *temporary = false,
                    None => *persistent = Some(change),
                }
            }
            for (place, change) in latest
                .into_iter()
                .filter_map(|(place, persistent, _)| Some((place, persistent?)))
            {
                let table = change
                    .table
                    .and_then(|index| self.tables.get(index))
                    .map(|table| {
                        if !table.reruns.is_empty() {
                            left.rerunning.insert(name.clone());
                        }
                        left.tables.push(table.clone());
                        left.tables.len() - 1
                    });
                left.changes
                    .entry(name.clone())
                    .or_default()
                    .push(RelationChange {
                        from: 0,
                        until: u32::MAX,
                        place: place.clone(),
                        table,
                        unsettled: Vec::new(),
                        read: None,
                    });
            }
        }
        for (name, namings) in &self.named {
            let mut places: Vec<RelationPlace> = Vec::new();
            for naming in namings
                .iter()
                .filter(|naming| naming.until == u32::MAX && !naming.place.session_temporary)
            {
                if !places.contains(&naming.place) {
                    places.push(naming.place.clone());
                }
            }
            if places.is_empty() {
                continue;
            }
            left.named.insert(
                name.clone(),
                places
                    .into_iter()
                    .map(|place| RelationNaming {
                        from: 0,
                        until: u32::MAX,
                        place,
                    })
                    .collect(),
            );
        }
        left
    }

    /// Record what the statement at `site` does to `target`, the relation
    /// it names; `catalog`, where one is attached, holds what a renamed or
    /// altered table that no statement before made is. The relations it
    /// changes.
    pub(crate) fn record(
        &mut self,
        target: &TableRef,
        edit: RelationEdit<'_>,
        site: RelationSite<'_>,
        catalog: Option<&CatalogIndex>,
    ) -> Vec<RelationKey> {
        let mut changed = Vec::new();
        // A name the session leaves to its search path: one a statement
        // makes is the path's first schema's, any other the first schema's
        // holding it.
        let target = &match &edit {
            RelationEdit::Create { .. } => match searched(target, site.session) {
                Some([first, ..]) => in_schema(target, first),
                Some([]) | None => target.clone(),
            },
            RelationEdit::Drop { .. }
            | RelationEdit::RenameTo { .. }
            | RelationEdit::Alter { .. }
            | RelationEdit::SwapWith { .. } => {
                self.at(site.statement.start)
                    .resolved(catalog, target, site.session)
            }
        };
        let catalogued_place = |table: &TableRef| {
            catalog.and_then(|catalog| catalog.catalogued_place(table, site.session))
        };
        let held = self
            .find(target, site.session, site.statement.start)
            .map(|(place, index)| (place.clone(), index));
        match edit {
            RelationEdit::Create {
                columns,
                every_column,
                temporary,
                session_temporary,
                if_not_exists,
                clone_of,
                fails_where_it_exists,
                reruns,
                query,
                keys,
                view,
            } => {
                // The relations its query reads, where it runs it on each
                // read: each where the script, else the catalog, has it.
                let reruns: Vec<(IdentKey, RelationPlace)> = reruns
                    .iter()
                    .map(|read| {
                        let read =
                            self.at(site.statement.start)
                                .resolved(catalog, read, site.session);
                        let place = self
                            .find(&read, site.session, site.statement.start)
                            .map(|(place, _)| place.clone())
                            .or_else(|| catalogued_place(&read).map(|(place, _)| place))
                            .unwrap_or_else(|| RelationPlace::of(&read, site.session));
                        (IdentKey::new(&read.name), place)
                    })
                    .collect();
                let session_temporary = session_temporary || self.in_session_schema(target);
                let temporary = temporary || session_temporary;
                let catalogued = catalogued_place(target);
                // A table made under a name the catalog has, at its place,
                // stands at the catalog's place.
                let place = if session_temporary {
                    RelationPlace::session_temporary()
                } else {
                    catalogued.as_ref().map_or_else(
                        || RelationPlace::of(target, site.session),
                        |(p, _)| p.clone(),
                    )
                };
                // A body that runs only where the table is absent makes it
                // only where it does not exist, as `IF NOT EXISTS` does.
                let made = crate::facts::reasoning::TableIdentity {
                    database: place.database.clone(),
                    schema: place.schema.clone(),
                    name: IdentKey::new(&target.name),
                };
                let guarded = site.unsettled.iter().any(|body| {
                    body.absent
                        .as_ref()
                        .is_some_and(|absent| absent.partial_match(&made))
                });
                if if_not_exists || guarded {
                    // What the latest change at the place left there, a
                    // drop included; with none, what any other place holds
                    // and the catalog has.
                    let exists = match self.latest_at(&target.name, &place, site.statement.start) {
                        Some(table) => table.is_some(),
                        None => match &held {
                            Some((place, _)) => place.session_temporary == session_temporary,
                            None => !session_temporary && catalogued.is_some(),
                        },
                    };
                    // The relation that exists stands: the name is the
                    // script's to say, and nothing is made.
                    if exists {
                        self.name(&target.name, place, site);
                        return changed;
                    }
                }
                // The catalog's table, where the statement leaves it standing.
                let standing = catalogued
                    .as_ref()
                    .filter(|(catalog_place, _)| {
                        fails_where_it_exists
                            && !temporary
                            && *catalog_place == place
                            && self
                                .latest_at(&target.name, &place, site.statement.start)
                                .is_none()
                    })
                    .map(|(_, table)| *table);
                let at = self.at(site.statement.start);
                // A clone is the table it clones, columns, tags and values,
                // under its own name.
                let cloned = clone_of.and_then(|source| {
                    let source = at.catalogued_table(catalog, source, site.session)?;
                    let (values, written) = at.made_of(source);
                    let mut table = source.clone();
                    table.name = CatalogIdent::from_name(target.name.clone());
                    Some(ScriptTable {
                        table,
                        origin: RelationOrigin::Made,
                        listing: if at.lists_every_column(source) {
                            ColumnListing::Every
                        } else {
                            ColumnListing::Some
                        },
                        values,
                        written,
                        temporary,
                        view: false,
                        reruns: Vec::new(),
                        query: None,
                        holds_no_row: at.holds_no_row(source),
                    })
                });
                let table = cloned.unwrap_or_else(|| {
                    let query = query.filter(|_| !reruns.is_empty());
                    ScriptTable {
                        temporary,
                        view,
                        reruns,
                        query,
                        ..ScriptTable::made(&target.name, columns, every_column, standing, keys)
                    }
                });
                self.name(&target.name, place.clone(), site);
                self.removal(&target.name, &place, site, temporary, Removing::Made);
                changed.push(self.change(&target.name, place, site, Some(table)));
            }
            RelationEdit::Drop { kind, temporary } => {
                // A temporary table on every path into the drop ends there:
                // its place holds what it hid.
                let ends_temporary = held
                    .as_ref()
                    .is_some_and(|(_, index)| self.held_temporary(*index))
                    && self
                        .at(site.statement.start)
                        .temporary(target, site.session);
                let temporary_name = temporary;
                let temporary = temporary
                    || held
                        .as_ref()
                        .is_some_and(|(_, index)| self.held_temporary(*index));
                // A catalogued table dropped does not exist at its place
                // for a `CREATE … IF NOT EXISTS` after.
                let place = held
                    .map(|(place, _)| place)
                    .or_else(|| catalogued_place(target).map(|(p, _)| p));
                let named = place
                    .clone()
                    .unwrap_or_else(|| RelationPlace::of(target, site.session));
                self.removal(
                    &target.name,
                    &named,
                    site,
                    temporary,
                    Removing::Dropped(kind),
                );
                self.name(&target.name, named, site);
                match place {
                    Some(place) if ends_temporary => {
                        self.end_temporary(&target.name, &place, site.statement);
                        // Ended, the temporary table leaves what it hid
                        // where a table stands behind it; else its name
                        // names a dropped table. A T-SQL `#t` stands before
                        // no table of its name.
                        let behind = !temporary_name
                            && self
                                .at(site.statement.end)
                                .catalogued_table(catalog, target, site.session)
                                .is_some();
                        if behind {
                            self.temporary_drops.push(site.statement);
                        } else {
                            changed.push(self.change(&target.name, place, site, None));
                        }
                    }
                    Some(place) => changed.push(self.change(&target.name, place, site, None)),
                    None => {}
                }
            }
            RelationEdit::RenameTo { to, mutations } => {
                let from_place = held
                    .as_ref()
                    .map(|(place, _)| place.clone())
                    .or_else(|| catalogued_place(target).map(|(place, _)| place))
                    .unwrap_or_else(|| RelationPlace::of(target, site.session));
                let temporary = held
                    .as_ref()
                    .is_some_and(|(_, index)| self.held_temporary(*index));
                self.column_removals(&target.name, &from_place, site, temporary, mutations);
                self.removal(
                    &target.name,
                    &from_place,
                    site,
                    temporary,
                    Removing::RenamedTo(to.name.clone()),
                );
                self.name(&target.name, from_place, site);
                let renamed = match held {
                    Some((place, index)) => {
                        let table = self.tables.get(index).cloned();
                        changed.push(self.change(&target.name, place.clone(), site, None));
                        table.map(|table| (Some(place), table))
                    }
                    None => {
                        let found = catalogued_place(target);
                        // The catalog's table is no longer there by its old name.
                        if let Some((place, _)) = &found {
                            changed.push(self.change(&target.name, place.clone(), site, None));
                        }
                        found.map(|(place, table)| {
                            let table = ScriptTable::new(
                                table.clone(),
                                RelationOrigin::Made,
                                ColumnListing::Every,
                            );
                            (Some(place), table)
                        })
                    }
                };
                let (from, mut renamed) = renamed.unwrap_or_else(|| {
                    let table = ScriptTable::new(
                        made_table(&to.name, Vec::new()),
                        RelationOrigin::Made,
                        ColumnListing::Every,
                    );
                    (None, table)
                });
                renamed.table.name = CatalogIdent::from_name(to.name.clone());
                renamed.origin = RelationOrigin::Made;
                edit_columns(&mut renamed, mutations, site.session);
                let place = renamed_place(to, from.as_ref(), site.session);
                self.name(&to.name, place.clone(), site);
                self.removal(&to.name, &place, site, temporary, Removing::Made);
                changed.push(self.change(&to.name, place, site, Some(renamed)));
            }
            RelationEdit::SwapWith { other } => {
                let other = &self
                    .at(site.statement.start)
                    .resolved(catalog, other, site.session);
                // Each side as it stands, and where.
                let side = |table: &TableRef| -> (RelationPlace, ScriptTable) {
                    let held = self
                        .find(table, site.session, site.statement.start)
                        .and_then(|(place, index)| Some((place.clone(), self.tables.get(index)?)));
                    if let Some((place, held)) = held {
                        return (place, held.clone());
                    }
                    match catalogued_place(table) {
                        Some((place, found)) => (
                            place,
                            ScriptTable::new(
                                found.clone(),
                                RelationOrigin::Made,
                                ColumnListing::Every,
                            ),
                        ),
                        None => (
                            RelationPlace::of(table, site.session),
                            ScriptTable::new(
                                made_table(&table.name, Vec::new()),
                                RelationOrigin::Made,
                                ColumnListing::Every,
                            ),
                        ),
                    }
                };
                let (mine_place, mine) = side(target);
                let (theirs_place, theirs) = side(other);
                let renamed = |mut held: ScriptTable, name: &str| {
                    held.table.name = CatalogIdent::from_name(name);
                    held.origin = RelationOrigin::Made;
                    held
                };
                let mine = renamed(mine, &other.name);
                let theirs = renamed(theirs, &target.name);
                self.name(&target.name, mine_place.clone(), site);
                self.name(&other.name, theirs_place.clone(), site);
                changed.push(self.change(&target.name, mine_place, site, Some(theirs)));
                changed.push(self.change(&other.name, theirs_place, site, Some(mine)));
            }
            RelationEdit::Alter {
                mutations,
                dropped,
                added,
                column_names,
            } => {
                if !mutations.iter().any(changes_columns) && dropped.is_empty() && added.is_empty()
                {
                    return changed;
                }
                let named_place = held
                    .as_ref()
                    .map(|(place, _)| place.clone())
                    .or_else(|| catalogued_place(target).map(|(place, _)| place))
                    .unwrap_or_else(|| RelationPlace::of(target, site.session));
                let temporary = held
                    .as_ref()
                    .is_some_and(|(_, index)| self.held_temporary(*index));
                self.column_removals(&target.name, &named_place, site, temporary, mutations);
                self.name(&target.name, named_place, site);
                let altered = match held {
                    Some((place, index)) => self.tables.get(index).cloned().map(|t| (place, t)),
                    None => catalogued_place(target).map(|(place, table)| {
                        let table = ScriptTable::new(
                            table.clone(),
                            RelationOrigin::Catalogued,
                            ColumnListing::Every,
                        );
                        (place, table)
                    }),
                };
                if let Some((place, mut altered)) = altered {
                    edit_columns(&mut altered, mutations, site.session);
                    drop_declarations(&mut altered.table, dropped);
                    let mut added = added.to_vec();
                    if column_names {
                        name_unnamed_keys(&mut added, &altered.table.constraints);
                    }
                    altered.table.constraints.extend(added);
                    changed.push(self.change(&target.name, place, site, Some(altered)));
                }
            }
        }
        changed
    }

    /// Record that the statement at `site` writes rows into `target`, the
    /// relation it names, as `rows` says, `reasoning` joining what the rows
    /// written and those held meet ([`Self::write_keyed`]); the relations
    /// written, where the script holds one of the name.
    pub(crate) fn write(
        &mut self,
        target: &TableRef,
        rows: &WrittenRows,
        reasoning: &dyn crate::facts::reasoning::Reasoning,
        site: RelationSite<'_>,
        catalog: Option<&CatalogIndex>,
    ) -> Vec<RelationKey> {
        let target = self
            .at(site.statement.start)
            .resolved(catalog, target, site.session);
        let Some((place, _)) = self
            .find(&target, site.session, site.statement.start)
            .map(|(place, index)| (place.clone(), index))
        else {
            return Vec::new();
        };
        let mut written = Vec::new();
        self.write_keyed(
            RelationKey {
                name: IdentKey::new(&target.name),
                place,
            },
            rows,
            reasoning,
            site,
            &mut Vec::new(),
            &mut written,
        );
        written
    }

    /// [`Self::write`] into the relation `key` names.
    pub(crate) fn write_key(
        &mut self,
        key: &RelationKey,
        rows: &WrittenRows,
        reasoning: &dyn crate::facts::reasoning::Reasoning,
        site: RelationSite<'_>,
    ) -> Vec<RelationKey> {
        let mut written = Vec::new();
        self.write_keyed(
            key.clone(),
            rows,
            reasoning,
            site,
            &mut Vec::new(),
            &mut written,
        );
        written
    }

    /// [`Self::write`] of the relation `key` names, each relation written
    /// added to `written`, each one met added to `met`. A relation that
    /// runs its query on each read (a view) holds no rows of its own: the
    /// rows go into the relations its query reads, whose values are not
    /// known there.
    fn write_keyed(
        &mut self,
        key: RelationKey,
        rows: &WrittenRows,
        reasoning: &dyn crate::facts::reasoning::Reasoning,
        site: RelationSite<'_>,
        met: &mut Vec<RelationKey>,
        written: &mut Vec<RelationKey>,
    ) {
        if met.contains(&key) {
            return;
        }
        met.push(key.clone());
        let Some((read, table)) = self
            .latest_keyed(&key.name, &key.place, site.statement.start)
            .flatten()
            .and_then(|index| Some((index, self.tables.get(index)?)))
        else {
            return;
        };
        if table.query.is_some() {
            for (name, place) in table.reruns.clone() {
                let key = RelationKey { name, place };
                self.write_keyed(key, &WrittenRows::Unknown, reasoning, site, met, written);
            }
            return;
        }
        let after = table.after_write(rows, reasoning);
        // Each write of a statement reads the relation as the statement's
        // start held it, and every one lands: a write after the statement's
        // earlier ones adds its rows to what they left. A write leaving the
        // relation as it was, or as the statement's writes so far left it,
        // changes nothing to record: a write repeated, or one through a
        // chain of triggers, is read once per state of the relation.
        let recorded = match self.statement_written(&key, read, site) {
            Some(held) if held.reads_as(&after) => None,
            Some(held) => {
                Some(held.after_more_rows(rows, reasoning)).filter(|all| !all.reads_as(held))
            }
            None => Some(after).filter(|after| !after.reads_as(table)),
        };
        if let Some(recorded) = recorded {
            self.record_change(
                key.name.clone(),
                key.place.clone(),
                site,
                Some(recorded),
                Some(read),
            );
        }
        written.push(key);
    }

    /// What the writes of the statement at `site` so far left of the
    /// relation `key` names, each writing the relation `read` holds at the
    /// statement's start: the last change there, where it is one of them.
    fn statement_written(
        &self,
        key: &RelationKey,
        read: usize,
        site: RelationSite<'_>,
    ) -> Option<&ScriptTable> {
        self.changes
            .get(&key.name)
            .and_then(|changes| {
                changes
                    .iter()
                    .rev()
                    .find(|change| change.place == key.place)
            })
            .filter(|change| {
                change.read == Some(read)
                    && change.from == site.statement.end
                    && change.until == site.until
                    && change.unsettled == site.unsettled
            })
            .and_then(|change| change.table)
            .and_then(|index| self.tables.get(index))
    }

    /// Record that the statement at `site`, which is not read, may change
    /// every relation the script holds there as `reach` says
    /// ([`ScriptTable::after_unread`]), but those that run their query on
    /// each read; the relations changed.
    pub(crate) fn unread(
        &mut self,
        reasoning: &dyn crate::facts::reasoning::Reasoning,
        site: RelationSite<'_>,
        reach: UnreadReach,
    ) -> Vec<RelationKey> {
        let mut changed = Vec::new();
        for (name, place, index) in self.in_force(site.statement.start) {
            let Some(table) = self.tables.get(index) else {
                continue;
            };
            if table.query.is_some() {
                continue;
            }
            let after = table.after_unread(reasoning, reach);
            self.change_keyed(name.clone(), place.clone(), site, Some(after));
            changed.push(RelationKey { name, place });
        }
        changed
    }

    /// Record that the statement at `site` changes `target`, the relation
    /// it names, in a way not read ([`ScriptTable::after_unread`]); the
    /// relation changed, where the script holds one of the name.
    pub(crate) fn unread_relation(
        &mut self,
        target: &TableRef,
        reasoning: &dyn crate::facts::reasoning::Reasoning,
        site: RelationSite<'_>,
        catalog: Option<&CatalogIndex>,
    ) -> Option<RelationKey> {
        let target = self
            .at(site.statement.start)
            .resolved(catalog, target, site.session);
        let (place, index) = self
            .find(&target, site.session, site.statement.start)
            .map(|(place, index)| (place.clone(), index))?;
        let after = self
            .tables
            .get(index)?
            .after_unread(reasoning, UnreadReach::Anything);
        let name = IdentKey::new(&target.name);
        self.change_keyed(name.clone(), place.clone(), site, Some(after));
        Some(RelationKey { name, place })
    }

    /// Record that the statement at `site` writes rows not known into the
    /// relation `key` names.
    pub(crate) fn write_unknown(
        &mut self,
        key: &RelationKey,
        reasoning: &dyn crate::facts::reasoning::Reasoning,
        site: RelationSite<'_>,
    ) {
        let after = self
            .latest_keyed(&key.name, &key.place, site.statement.end)
            .flatten()
            .and_then(|index| self.tables.get(index))
            .map(|table| table.after_write(&WrittenRows::Unknown, reasoning));
        if let Some(after) = after {
            self.change_keyed(key.name.clone(), key.place.clone(), site, Some(after));
        }
    }

    /// The relations in force at `at` that run their query over one of
    /// `written`, at any depth, each after those of them it reads: with its
    /// query, `None` where none is kept.
    pub(crate) fn reruns_over(
        &self,
        written: &[RelationKey],
        at: u32,
    ) -> Vec<(RelationKey, Option<std::sync::Arc<RelationQuery>>)> {
        let views: Vec<(RelationKey, &ScriptTable)> = self
            .rerunning
            .iter()
            .filter_map(|name| Some((name, self.changes.get(name)?)))
            .flat_map(|(name, changes)| in_force_of(name, changes, at))
            .filter_map(|(name, place, index)| {
                let table = self.tables.get(index)?;
                (!table.reruns.is_empty()).then_some((RelationKey { name, place }, table))
            })
            .collect();
        let reads = |table: &ScriptTable, key: &RelationKey| {
            table
                .reruns
                .iter()
                .any(|(name, place)| *name == key.name && *place == key.place)
        };
        // Every relation reading a written one, at any depth.
        let mut changed: Vec<RelationKey> = written.to_vec();
        let mut pending: Vec<usize> = Vec::new();
        loop {
            let before = pending.len();
            for (slot, (key, table)) in views.iter().enumerate() {
                if !pending.contains(&slot)
                    && !written.contains(key)
                    && changed.iter().any(|read| reads(table, read))
                {
                    pending.push(slot);
                    changed.push(key.clone());
                }
            }
            if pending.len() == before {
                break;
            }
        }
        // Each after the pending ones it reads.
        let mut ordered = Vec::with_capacity(pending.len());
        while !pending.is_empty() {
            let ready = pending
                .iter()
                .position(|slot| {
                    !pending
                        .iter()
                        .any(|other| other != slot && reads(views[*slot].1, &views[*other].0))
                })
                .unwrap_or(0);
            let slot = pending.remove(ready);
            let (key, table) = &views[slot];
            ordered.push((key.clone(), table.query.clone()));
        }
        ordered
    }

    /// Record that the statement at `site` changes the rows of the
    /// relation `key` names, one that runs its query on each read, to
    /// those its query now gives: `columns` as [`RelationEdit::Create`]
    /// gives them; what else is known of the relation stands.
    pub(crate) fn requery(
        &mut self,
        key: &RelationKey,
        columns: Option<Vec<MadeColumn>>,
        every_column: bool,
        site: RelationSite<'_>,
    ) {
        let Some(held) = self
            .latest_keyed(&key.name, &key.place, site.statement.end)
            .flatten()
            .and_then(|index| self.tables.get(index))
        else {
            return;
        };
        let made = ScriptTable::made(
            &held.table.name.name,
            columns,
            every_column,
            None,
            held.table.constraints.clone(),
        );
        let mut table = made.table;
        table.tags = held.table.tags.clone();
        // A query that comes to hold no row here was raised at no
        // statement: its own claims stand for the read that contradicts
        // them.
        let requeried = ScriptTable {
            table,
            values: made.values,
            written: made.written,
            listing: made.listing,
            holds_no_row: made.holds_no_row && held.holds_no_row,
            ..held.clone()
        };
        self.change_keyed(key.name.clone(), key.place.clone(), site, Some(requeried));
    }

    /// Record that the statement `statement`, `until` as
    /// [`RelationSite::until`], defines the routine `name`, told from
    /// others of its name by `signature`, its body read where `read`. Where
    /// it `replaces`, it ends each routine of its name and signature in
    /// force there; where a signature is not read, both stand.
    pub(crate) fn define_routine(
        &mut self,
        name: crate::facts::reasoning::TableIdentity,
        signature: Option<Vec<String>>,
        params: Option<Vec<RoutineParam>>,
        replaces: bool,
        statement: crate::lexer::Span,
        until: u32,
        read: bool,
    ) {
        if replaces {
            for held in &mut self.routines {
                let same = match (&held.signature, &signature) {
                    (Some(held), Some(signature)) => held == signature,
                    (None, _) | (_, None) => false,
                };
                if same
                    && held.name.partial_match(&name)
                    && (held.from..held.until.min(held.ends)).contains(&statement.start)
                {
                    held.ends = statement.start;
                }
            }
        }
        self.routines.push(RoutineChanges {
            name,
            signature,
            params,
            from: statement.end,
            until,
            ends: u32::MAX,
            end: statement.end,
            read,
            changes: Vec::new(),
            row: RowAssigned::default(),
            triggers: Vec::new(),
            results: None,
        });
    }

    /// Record that the statement starting at `at` drops each routine named
    /// `name` in force there whose parameters' types are those `signature`
    /// lists, folded as [`RoutineChanges::signature`]; every one of the name
    /// where `None`, or where a routine's types are not read.
    pub(crate) fn drop_routine(
        &mut self,
        name: &crate::facts::reasoning::TableIdentity,
        signature: Option<&[String]>,
        at: u32,
    ) {
        for held in &mut self.routines {
            let typed = match (&held.signature, signature) {
                (Some(types), Some(dropped)) => types.as_slice() == dropped,
                (None, _) | (_, None) => true,
            };
            if typed && held.in_force_at(at) && held.name.partial_match(name) {
                held.ends = held.ends.min(at);
            }
        }
    }

    /// Record that a query of the body of the routine whose statement ends
    /// at `routine` returns rows to its caller, each column holding
    /// `values` by position.
    pub(crate) fn routine_result(&mut self, routine: u32, values: Vec<MadeValue>) {
        for defined in self.routines.iter_mut().filter(|r| r.end == routine) {
            let joined = match defined.results.take() {
                None => values.iter().map(MadeValue::tags_only).collect(),
                Some(held) => {
                    let width = held.len().max(values.len());
                    (0..width)
                        .map(|at| {
                            let mut value = held.get(at).cloned().unwrap_or_default();
                            for tag in values.get(at).into_iter().flat_map(|v| &v.tags) {
                                if !value.tags.iter().any(|t| same_tag(t, tag)) {
                                    value.tags.push(tag.clone());
                                }
                            }
                            value.exposure = None;
                            value
                        })
                        .collect()
                }
            };
            defined.results = Some(joined);
        }
    }

    /// What a call at `at` of the routine `name` returns ([`RoutineChanges::results`]):
    /// `None` where none of the name is defined there, or one is not read,
    /// or returns no rows.
    pub(crate) fn results_of_called(
        &self,
        name: &crate::facts::reasoning::TableIdentity,
        at: u32,
    ) -> Option<Vec<MadeValue>> {
        let mut called = self
            .routines
            .iter()
            .filter(|r| r.in_force_at(at) && r.name.partial_match(name));
        let routine = called.next()?;
        if called.next().is_some() || !routine.read {
            return None;
        }
        routine.results.clone()
    }

    /// Record that a statement of the body of the routine whose statement
    /// ends at `routine` changes the relation `target` names under
    /// `session` as `change` says, its update assigning `updated`.
    pub(crate) fn routine_changes(
        &mut self,
        routine: u32,
        target: &TableRef,
        session: &crate::ir::SessionContext,
        change: RoutineChangeKind,
        updated: &UpdatedColumns,
    ) {
        for defined in self.routines.iter_mut().filter(|r| r.end == routine) {
            defined.changes.push(RoutineChange {
                target: target.clone(),
                session: session.clone(),
                change,
                updated: updated.clone(),
            });
        }
    }

    /// Record that a statement of the body of the routine whose statement
    /// ends at `routine` assigns what `row` says of the row a trigger is
    /// given.
    pub(crate) fn routine_assigns_row(&mut self, routine: u32, row: &RowAssigned) {
        for defined in self.routines.iter_mut().filter(|r| r.end == routine) {
            defined.row.join(row);
        }
    }

    /// Record that a statement of the body of the routine whose statement
    /// ends at `routine` changes a trigger as `change` says.
    pub(crate) fn routine_changes_trigger(&mut self, routine: u32, change: &TriggerChange) {
        for defined in self.routines.iter_mut().filter(|r| r.end == routine) {
            defined.triggers.push(change.clone());
        }
    }

    /// Record that a statement of the body of the routine whose statement
    /// ends at `routine` runs a routine or SQL text the run does not read.
    pub(crate) fn routine_runs_unread(&mut self, routine: u32) {
        for defined in self.routines.iter_mut().filter(|r| r.end == routine) {
            defined.read = false;
        }
    }

    /// What a call at `at` of the routine `name` changes: the relations
    /// the body of each routine of the name defined before it changes,
    /// each named as written under the namespace in force there.
    pub(crate) fn called(&self, name: &crate::facts::reasoning::TableIdentity, at: u32) -> Called {
        let called: Vec<&RoutineChanges> = self
            .routines
            .iter()
            .filter(|r| r.in_force_at(at) && r.name.partial_match(name))
            .collect();
        if called.is_empty() {
            return Called::NotDefined;
        }
        if called.iter().any(|r| !r.read) {
            return Called::Unread;
        }
        let mut changes = BodyChanges::default();
        for routine in called {
            changes.extend(routine);
        }
        Called::Changes(changes)
    }

    /// Whether a call at `at` of the routine `name` runs only bodies the
    /// run reads: one of the name is in force there, and each is read.
    pub(crate) fn runs_read_routine(
        &self,
        name: &crate::facts::reasoning::TableIdentity,
        at: u32,
    ) -> bool {
        let mut called = self
            .routines
            .iter()
            .filter(|r| r.in_force_at(at) && r.name.partial_match(name))
            .peekable();
        called.peek().is_some() && called.all(|routine| routine.read)
    }

    /// Whether a call at `at` of the routine `name` may assign the argument
    /// it passes at `position`, or to the parameter `named`: one of the
    /// routines of the name in force there takes it as `OUT` or `INOUT`,
    /// or its parameters are not read, or none is defined.
    pub(crate) fn call_assigns(
        &self,
        name: &crate::facts::reasoning::TableIdentity,
        at: u32,
        position: usize,
        named: Option<&IdentKey>,
    ) -> bool {
        let mut called = self
            .routines
            .iter()
            .filter(|r| r.in_force_at(at) && r.name.partial_match(name))
            .peekable();
        if called.peek().is_none() {
            return true;
        }
        called.any(|routine| {
            let Some(params) = &routine.params else {
                return true;
            };
            let param = match named {
                Some(named) => params.iter().find(|p| p.name.as_ref() == Some(named)),
                None => params.get(position),
            };
            param.is_none_or(|param| param.assigns)
        })
    }

    /// What the routine whose statement ends at `end` changes; `None` where
    /// none is recorded there, or its body is not read, or runs what the
    /// run does not read.
    pub(crate) fn changes_of_body(&self, end: u32) -> Option<BodyChanges> {
        let mut defined = self.routines.iter().filter(|r| r.end == end).peekable();
        defined.peek()?;
        let mut changes = BodyChanges::default();
        for routine in defined {
            if !routine.read {
                return None;
            }
            changes.extend(routine);
        }
        Some(changes)
    }

    /// Record that the statement `statement`, `until` as
    /// [`RelationSite::until`], defines a trigger `name` on `table` (any
    /// table where `None`), named as written under `session`, as
    /// `definition` says. One of its name it replaces ends where the
    /// statement is read ([`TriggerOp::Replace`]).
    pub(crate) fn define_trigger(
        &mut self,
        name: Option<IdentKey>,
        table: Option<&TableRef>,
        session: &crate::ir::SessionContext,
        statement: crate::lexer::Span,
        until: u32,
        definition: TriggerDefinition,
    ) {
        let table = table.map(|table| trigger_table(table, session));
        self.triggers.push(ScriptTrigger::created(
            &name,
            table,
            &definition,
            statement.end..until,
        ));
    }

    /// Record that the call `call` of a routine makes, while it runs, the
    /// trigger `change` makes ([`TriggerOp::Create`]): it runs at the
    /// routine's own writes, wherever its body makes it.
    pub(crate) fn create_for_call(&mut self, change: &TriggerChange, call: crate::lexer::Span) {
        match &change.op {
            TriggerOp::Create {
                name,
                table,
                definition,
                replaces: _,
            } => {
                let table = table
                    .as_ref()
                    .map(|table| trigger_table(table, &change.session));
                self.triggers.push(ScriptTrigger::created(
                    name,
                    table,
                    definition,
                    call.start..call.end,
                ));
            }
            TriggerOp::Drop { .. }
            | TriggerOp::Rename { .. }
            | TriggerOp::State { .. }
            | TriggerOp::Uninherit { .. }
            | TriggerOp::Replace { .. } => {}
        }
    }

    /// Record that a statement at `at` changes the triggers in force there
    /// as `change` says.
    pub(crate) fn change_trigger(&mut self, change: &TriggerChange, at: u32) {
        let session = &change.session;
        let on =
            |table: &Option<TableRef>| table.as_ref().map(|table| trigger_table(table, session));
        match &change.op {
            TriggerOp::Drop { name, table } => {
                let table = on(table);
                self.end_named(name, table.as_ref(), at);
            }
            // The trigger the statement defines holds from its end.
            TriggerOp::Replace { name, table } => {
                let table = on(table);
                self.end_named(name, table.as_ref(), at);
            }
            TriggerOp::Create {
                name,
                table,
                definition,
                replaces,
            } => {
                let table = on(table);
                for index in self.triggers.may_be_on(table.as_ref().map(|t| &t.name)) {
                    let Some(trigger) = self.triggers.get_mut(index) else {
                        continue;
                    };
                    // The one of its identity, made again, and, where it
                    // replaces, each other of its name.
                    let again =
                        trigger.in_force_at(at) && trigger.is(name, table.as_ref(), definition);
                    let replaced = *replaces
                        && name
                            .as_ref()
                            .is_some_and(|name| trigger.named_at(name, table.as_ref(), at));
                    if again || replaced {
                        trigger.ends = at;
                    }
                }
                self.triggers.push(ScriptTrigger::created(
                    name,
                    table,
                    definition,
                    at..u32::MAX,
                ));
            }
            TriggerOp::Rename { name, table, to } => {
                let table = on(table);
                let mut renamed = Vec::new();
                for index in self.triggers.may_be_on(table.as_ref().map(|t| &t.name)) {
                    let Some(trigger) = self.triggers.get_mut(index) else {
                        continue;
                    };
                    if is_trigger(trigger.hook) && trigger.named_at(name, table.as_ref(), at) {
                        trigger.ends = at;
                        renamed.push(ScriptTrigger {
                            name: Some(to.clone()),
                            from: at,
                            ends: u32::MAX,
                            ..trigger.clone()
                        });
                    }
                }
                self.triggers.extend(renamed);
            }
            TriggerOp::State {
                name,
                table,
                enabled,
            } => {
                let table = on(table);
                for index in self.triggers.may_be_on(table.as_ref().map(|t| &t.name)) {
                    let Some(trigger) = self.triggers.get_mut(index) else {
                        continue;
                    };
                    let on = match (&table, &trigger.table) {
                        (Some(table), Some(held)) => held.partial_match(table),
                        (None, _) | (_, None) => true,
                    };
                    let named = name
                        .as_ref()
                        .is_none_or(|name| trigger.name.as_ref() == Some(name));
                    if is_trigger(trigger.hook)
                        && named
                        && on
                        && (trigger.from..trigger.ends).contains(&at)
                    {
                        let place = trigger.states.partition_point(|(from, _)| *from <= at);
                        trigger.states.insert(place, (at, *enabled));
                    }
                }
            }
            TriggerOp::Uninherit { child, parent } => {
                let child = trigger_table(child, session);
                let parent = trigger_table(parent, session);
                self.uninherit(&child, &parent, at);
            }
        }
    }

    /// End at `at` each trigger in force there named `name`, on `table`
    /// where given ([`ScriptTrigger::named_at`]).
    fn end_named(
        &mut self,
        name: &IdentKey,
        table: Option<&crate::facts::reasoning::TableIdentity>,
        at: u32,
    ) {
        for index in self.triggers.may_be_on(table.map(|t| &t.name)) {
            if let Some(trigger) = self.triggers.get_mut(index) {
                if trigger.named_at(name, table, at) {
                    trigger.ends = at;
                }
            }
        }
    }

    /// Record that the statement starting at `at` makes the rows of the
    /// table `child` no longer rows of `parent`: each hook of either that
    /// writes the other ends there.
    fn uninherit(
        &mut self,
        child: &crate::facts::reasoning::TableIdentity,
        parent: &crate::facts::reasoning::TableIdentity,
        at: u32,
    ) {
        let mut kept = Vec::new();
        let mut held = self.triggers.may_be_on(Some(&child.name));
        if parent.name != child.name {
            held.extend(self.triggers.may_be_on(Some(&parent.name)));
            held.sort_unstable();
        }
        for index in held {
            let Some(trigger) = self.triggers.get_mut(index) else {
                continue;
            };
            let writes = match (&trigger.runs, trigger.hook) {
                (
                    TriggerRuns::Changes(Some(writes)),
                    Hook::Child | Hook::Partition | Hook::Parent,
                ) => writes,
                (
                    TriggerRuns::Changes(None) | TriggerRuns::Body { .. } | TriggerRuns::Calls(_),
                    Hook::Trigger | Hook::Rule | Hook::Child | Hook::Partition | Hook::Parent,
                )
                | (TriggerRuns::Changes(Some(_)), Hook::Trigger | Hook::Rule) => continue,
            };
            // The child's hook writing the parent, or the parent's writing
            // the child.
            let Some(on) = trigger.table.as_ref() else {
                continue;
            };
            let other = if on.partial_match(child) {
                parent
            } else if on.partial_match(parent) {
                child
            } else {
                continue;
            };
            if !(trigger.from..trigger.ends).contains(&at) {
                continue;
            }
            let (gone, left): (Vec<RoutineChange>, Vec<RoutineChange>) =
                writes.changes.iter().cloned().partition(|change| {
                    trigger_table(&change.target, &change.session).partial_match(other)
                });
            if gone.is_empty() {
                continue;
            }
            trigger.ends = at;
            if !left.is_empty() {
                kept.push(ScriptTrigger {
                    from: at,
                    ends: u32::MAX,
                    runs: TriggerRuns::Changes(Some(BodyChanges::of(left))),
                    ..trigger.clone()
                });
            }
        }
        self.triggers.extend(kept);
    }

    /// Each trigger the scripts define on the table `target` names under
    /// `session` that `write` runs ([`Self::triggers_at`]).
    pub(crate) fn triggers_on(
        &self,
        target: &TableRef,
        session: &crate::ir::SessionContext,
        catalog: Option<&CatalogIndex>,
        write: HookedWrite<'_>,
    ) -> Vec<Fired> {
        if self.triggers.is_empty() || write.hooks.is_empty() {
            return Vec::new();
        }
        let target = self.at(write.at).resolved(catalog, target, session);
        self.triggers_at(&trigger_table(&target, session), write)
    }

    /// [`Self::triggers_on`] the relation `key` names.
    pub(crate) fn triggers_on_key(&self, key: &RelationKey, write: HookedWrite<'_>) -> Vec<Fired> {
        if self.triggers.is_empty() || write.hooks.is_empty() {
            return Vec::new();
        }
        let written = crate::facts::reasoning::TableIdentity {
            database: key.place.database.clone(),
            schema: key.place.schema.clone(),
            name: key.name.clone(),
        };
        self.triggers_at(&written, write)
    }

    /// Each trigger of one of `write`'s hooks in force and enabled where it
    /// runs on the table `written` that it runs ([`ScriptTrigger::runs_at`]);
    /// and, where its hooks hold triggers, of each table `written` is a
    /// partition of at any depth, each such trigger run before each row,
    /// which runs on the partition's rows.
    fn triggers_at(
        &self,
        written: &crate::facts::reasoning::TableIdentity,
        write: HookedWrite<'_>,
    ) -> Vec<Fired> {
        let HookedWrite {
            at,
            events,
            updated,
            hooks,
        } = write;
        let runs =
            |t: &ScriptTrigger| t.in_force_at(at) && t.runs_at(events, updated) && t.enabled_at(at);
        let fired = |(index, t): (usize, &ScriptTrigger)| Fired {
            index,
            hook: t.hook,
            runs: t.runs.clone(),
            sets_row: t.sets_row,
        };
        let mut found: Vec<Fired> = self
            .triggers
            .hooked_on(&written.name, hooks)
            .into_iter()
            .filter_map(|index| Some((index, self.triggers.get(index)?)))
            .filter(|(_, t)| runs(t) && t.table.as_ref().is_none_or(|on| on.partial_match(written)))
            .map(fired)
            .collect();
        if !hooks.contains(&Hook::Trigger) {
            return found;
        }
        for parent in self.partitioned_by(written, at) {
            found.extend(
                self.triggers
                    .kept_on(&parent.name, Hook::Trigger)
                    .iter()
                    .filter_map(|index| Some((*index, self.triggers.get(*index)?)))
                    .filter(|(_, t)| {
                        t.sets_row
                            && runs(t)
                            && t.table.as_ref().is_some_and(|on| on.partial_match(&parent))
                    })
                    .map(fired),
            );
        }
        found
    }

    /// Each table `partition` is a partition of at `at`, at any depth.
    fn partitioned_by(
        &self,
        partition: &crate::facts::reasoning::TableIdentity,
        at: u32,
    ) -> Vec<crate::facts::reasoning::TableIdentity> {
        let mut parents: Vec<crate::facts::reasoning::TableIdentity> = Vec::new();
        let mut pending = vec![partition.clone()];
        while let Some(table) = pending.pop() {
            for trigger in self
                .triggers
                .kept_on(&table.name, Hook::Partition)
                .iter()
                .filter_map(|index| self.triggers.get(*index))
            {
                if !trigger.in_force_at(at)
                    || !trigger
                        .table
                        .as_ref()
                        .is_some_and(|on| on.partial_match(&table))
                {
                    continue;
                }
                for parent in written_tables(&trigger.runs).into_iter().flatten() {
                    if parent != *partition && !parents.contains(&parent) {
                        parents.push(parent.clone());
                        pending.push(parent);
                    }
                }
            }
        }
        parents
    }

    /// Forget each trigger that ends before `at`: no write at or after it
    /// runs one, and no change there reaches one. A statement starting at
    /// `at`, with no trigger running, reads none in force before it.
    pub(crate) fn forget_ended_triggers(&mut self, at: u32) {
        self.triggers
            .retain(|trigger| trigger.until.min(trigger.ends) > at);
    }

    /// The statement at `site`, one of this script's own, changes the
    /// relation `name` names at `place`.
    fn name(&mut self, name: &str, place: RelationPlace, site: RelationSite<'_>) {
        self.named
            .entry(IdentKey::new(name))
            .or_default()
            .push(RelationNaming {
                from: site.statement.end,
                until: site.until,
                place,
            });
    }

    /// From the end of the statement at `site`, the relation `name` names
    /// at `place` is `table`, or none.
    fn change(
        &mut self,
        name: &str,
        place: RelationPlace,
        site: RelationSite<'_>,
        table: Option<ScriptTable>,
    ) -> RelationKey {
        let name = IdentKey::new(name);
        self.change_keyed(name.clone(), place.clone(), site, table);
        RelationKey { name, place }
    }

    /// [`Self::change`] of the relation of the normalized name `name`.
    fn change_keyed(
        &mut self,
        name: IdentKey,
        place: RelationPlace,
        site: RelationSite<'_>,
        table: Option<ScriptTable>,
    ) {
        self.record_change(name, place, site, table, None);
    }

    /// [`Self::change_keyed`], of a write that read the relation `read`
    /// holds where given ([`RelationChange::read`]).
    fn record_change(
        &mut self,
        name: IdentKey,
        place: RelationPlace,
        site: RelationSite<'_>,
        table: Option<ScriptTable>,
        read: Option<usize>,
    ) {
        let table = table.map(|table| {
            if !table.reruns.is_empty() {
                self.rerunning.insert(name.clone());
            }
            self.tables.push(table);
            self.tables.len() - 1
        });
        self.changes.entry(name).or_default().push(RelationChange {
            from: site.statement.end,
            until: site.until,
            place,
            table,
            unsettled: site.unsettled.to_vec(),
            read,
        });
    }

    /// The temporary table `name` names at `place`, which the statement at
    /// `statement` drops, holds to that statement's end: each change there
    /// in force at its start, from the last back to the first that leaves
    /// no temporary table.
    fn end_temporary(&mut self, name: &str, place: &RelationPlace, statement: crate::lexer::Span) {
        let tables = &self.tables;
        let Some(changes) = self.changes.get_mut(&IdentKey::new(name)) else {
            return;
        };
        for change in changes.iter_mut().rev().filter(|change| {
            (change.from..change.until).contains(&statement.start) && change.place == *place
        }) {
            let temporary = change
                .table
                .and_then(|index| tables.get(index))
                .is_some_and(|table| table.temporary);
            if !temporary {
                break;
            }
            change.until = change.until.min(statement.end);
        }
    }

    /// What the last change in force at `at` to a relation `name` names at
    /// `place` left there: `Some(None)` where it dropped it or renamed it
    /// away, `None` where no statement changed one there.
    fn latest_at(&self, name: &str, place: &RelationPlace, at: u32) -> Option<Option<usize>> {
        self.latest_keyed(&IdentKey::new(name), place, at)
    }

    /// [`Self::latest_at`] of the relation of the normalized name `name`.
    fn latest_keyed(
        &self,
        name: &IdentKey,
        place: &RelationPlace,
        at: u32,
    ) -> Option<Option<usize>> {
        self.changes
            .get(name)?
            .iter()
            .rev()
            .find(|change| (change.from..change.until).contains(&at) && change.place == *place)
            .map(|change| change.table)
    }

    /// Each relation in force at `at`: by normalized name and place, the
    /// one the last change there in force at `at` left.
    fn in_force(&self, at: u32) -> Vec<(IdentKey, RelationPlace, usize)> {
        self.changes
            .iter()
            .flat_map(|(name, changes)| in_force_of(name, changes, at))
            .collect()
    }

    /// The relation `table` names under `session` at `at`, where an
    /// earlier statement made one, and where it is: of the relations of
    /// the name at that point, the one every part the name writes agrees
    /// with, as the catalog infers a location.
    /// A name the session leaves to its search path is looked for in each
    /// schema of it in turn.
    fn find(
        &self,
        table: &TableRef,
        session: &crate::ir::SessionContext,
        at: u32,
    ) -> Option<(&RelationPlace, usize)> {
        if table.server.is_some() {
            return None;
        }
        let changes = self.changes.get(&IdentKey::new(&table.name))?;
        // The last change at each place, of those in force at `at`.
        let mut latest: Vec<(&RelationPlace, Option<usize>)> = Vec::new();
        for change in changes
            .iter()
            .filter(|change| (change.from..change.until).contains(&at))
        {
            match latest.iter_mut().find(|(place, _)| **place == change.place) {
                Some(slot) => slot.1 = change.table,
                None => latest.push((&change.place, change.table)),
            }
        }
        // A name written without a database or schema reaches the
        // session's temporary table of the name first; one written in the
        // session's schema reaches no other.
        let in_session_schema = self.in_session_schema(table);
        if (table.db.is_none() && table.schema.is_none()) || in_session_schema {
            let temporary = latest
                .iter()
                .find_map(|(place, index)| place.session_temporary.then_some((*place, *index)));
            if let Some((place, Some(index))) = temporary {
                return Some((place, index));
            }
        }
        if in_session_schema {
            return None;
        }
        if let Some(path) = searched(table, session) {
            return path
                .iter()
                .find_map(|schema| self.find(&in_schema(table, schema), session, at));
        }
        let written = RelationPlace::of(table, session);
        unique_location_named_by(
            written.database.as_ref(),
            written.schema.as_ref(),
            latest.into_iter().filter_map(|(place, index)| {
                if place.session_temporary {
                    return None;
                }
                Some((
                    (place, index?),
                    place.database.as_ref(),
                    place.schema.as_ref(),
                ))
            }),
        )
    }
}

impl ScriptRelations {
    /// Whether, past `changes` (in source order, each `depth` bodies deep
    /// among the bodies that do not hold `at`), the relation is temporary
    /// on every path into `at`, where it is (`before`) before them. A
    /// change at that depth sets it; the changes in the bodies of one
    /// statement leave it temporary where every body that may run does,
    /// the statement's skipping them included unless it runs exactly one
    /// of its bodies and each of them is among those bodies.
    fn temporary_after(
        &self,
        changes: &[&RelationChange],
        depth: usize,
        before: bool,
        at: u32,
    ) -> bool {
        let mut temporary = before;
        let mut rest = changes;
        while let Some((first, _)) = rest.split_first() {
            let Some(body) = first.unsettled_before(at).get(depth) else {
                temporary = first
                    .table
                    .and_then(|index| self.tables.get(index))
                    .is_some_and(|held| held.temporary);
                rest = &rest[1..];
                continue;
            };
            // The changes in the bodies of the statement holding `body`.
            let owner = body.owner;
            let held = rest
                .iter()
                .take_while(|change| {
                    change
                        .unsettled_before(at)
                        .get(depth)
                        .is_some_and(|body| body.owner == owner)
                })
                .count();
            let (within, after) = rest.split_at(held);
            let mut bodies: Vec<std::ops::Range<u32>> = Vec::new();
            let mut every_body = true;
            let mut start = 0;
            while start < within.len() {
                let range = within[start].unsettled_before(at)[depth].range.clone();
                let end = start
                    + within[start..]
                        .iter()
                        .take_while(|change| change.unsettled_before(at)[depth].range == range)
                        .count();
                every_body &= self.temporary_after(&within[start..end], depth + 1, temporary, at);
                bodies.push(range);
                start = end;
            }
            let all_alternatives = body
                .alternatives
                .is_some_and(|alternatives| bodies.len() == alternatives);
            temporary = every_body && (all_alternatives || temporary);
            rest = after;
        }
        temporary
    }
}

/// Where a table renamed to the name `to` writes stands: at the parts that
/// name writes, and for those it omits, at the renamed table's place
/// (`from`), where it is known; else where the session puts the name.
fn renamed_place(
    to: &TableRef,
    from: Option<&RelationPlace>,
    session: &crate::ir::SessionContext,
) -> RelationPlace {
    let Some(from) = from else {
        return RelationPlace::of(to, session);
    };
    if to.db.is_none() && to.schema.is_none() {
        return from.clone();
    }
    RelationPlace {
        database: to
            .db
            .as_deref()
            .map(IdentKey::new)
            .or_else(|| from.database.clone()),
        schema: to
            .schema
            .as_deref()
            .map(IdentKey::new)
            .or_else(|| from.schema.clone()),
        session_temporary: false,
    }
}

/// Whether `mutation` changes a table's columns or their tags, or may.
fn changes_columns(mutation: &DdlSchemaMutation) -> bool {
    match mutation {
        DdlSchemaMutation::AddColumn { .. }
        | DdlSchemaMutation::DropColumn { .. }
        | DdlSchemaMutation::RenameColumn { .. }
        | DdlSchemaMutation::SwapWith { .. }
        | DdlSchemaMutation::SetColumnTags { .. }
        | DdlSchemaMutation::UnsetColumnTags { .. }
        | DdlSchemaMutation::SetColumnType { .. }
        | DdlSchemaMutation::ColumnsUnread => true,
        DdlSchemaMutation::RenameTo { .. } | DdlSchemaMutation::NamesUnread => false,
    }
}

/// `tag`, a tag a statement names, at the database and schema `session`
/// fills the parts its name omits with, as a table's name is placed;
/// a part neither gives stays unknown.
pub(crate) fn tag_in_session(tag: &CatalogTag, session: &crate::ir::SessionContext) -> CatalogTag {
    let named = TableRef {
        server: None,
        db: tag.tag_database.clone(),
        schema: tag.tag_schema.clone(),
        name: tag.tag_name.clone(),
        span: None,
    };
    let (database, schema) = crate::ir::span_extract::session_default_parts(&named, session);
    // A part the name writes is folded already; one the session gives is
    // folded here.
    let placed = |written: &Option<String>, given: Option<&str>| {
        written
            .clone()
            .or_else(|| given.map(crate::ir::normalize::normalize_identifier))
    };
    CatalogTag {
        tag_database: placed(&tag.tag_database, database),
        tag_schema: placed(&tag.tag_schema, schema),
        tag_name: tag.tag_name.clone(),
        tag_value: tag.tag_value.clone(),
    }
}

/// Whether the tags `a` and `b` are the same, part for part and value.
fn same_tag(a: &CatalogTag, b: &CatalogTag) -> bool {
    a.tag_database == b.tag_database
        && a.tag_schema == b.tag_schema
        && a.tag_name == b.tag_name
        && a.tag_value == b.tag_value
}

/// Whether the tag `held` is the one `named`, placed by its session
/// ([`tag_in_session`]), names: the same name, database and schema, a part
/// unknown on one side and known on the other being no match. `named`'s
/// parts are folded as written. `held`'s are as recorded: where a
/// statement wrote it (`written`), folded as written and compared as they
/// are; where the catalog recorded it, folded once.
fn tag_named(held: &CatalogTag, named: &CatalogTag, written: bool) -> bool {
    let part = |held: &str, named: &str| {
        held == named || (!written && IdentKey::new(held).as_str() == named)
    };
    let same = |held: Option<&str>, named: Option<&str>| match (held, named) {
        (Some(held), Some(named)) => part(held, named),
        (None, None) => true,
        (Some(_), None) | (None, Some(_)) => false,
    };
    part(&held.tag_name, &named.tag_name)
        && same(held.tag_schema.as_deref(), named.tag_schema.as_deref())
        && same(held.tag_database.as_deref(), named.tag_database.as_deref())
}

/// Change `relation`'s columns, and the keys that name them, as
/// `mutations` add, rename and drop them, in order, and the tags of each
/// column as they set and unset them, each tag placed by `session`. A
/// swap leaves no column known; a change not read leaves the listed
/// columns known and any other name undecided. A table that lists no
/// column has columns not known, and no change makes them known.
fn edit_columns(
    relation: &mut ScriptTable,
    mutations: &[DdlSchemaMutation],
    session: &crate::ir::SessionContext,
) {
    let table = &mut relation.table;
    if table.columns.is_empty() {
        return;
    }
    let values = &mut relation.values;
    let written = &mut relation.written;
    let key = |name: &str| IdentKey::new_as(name, NameKind::Column);
    // Whether `held`, a tag of the column `column`, is one a statement wrote.
    let wrote = |written: &std::collections::BTreeMap<IdentKey, Vec<CatalogTag>>,
                 column: &IdentKey,
                 held: &CatalogTag| {
        written
            .get(column)
            .is_some_and(|tags| tags.iter().any(|tag| same_tag(tag, held)))
    };
    for mutation in mutations {
        match mutation {
            DdlSchemaMutation::RenameTo { .. } | DdlSchemaMutation::NamesUnread => {}
            DdlSchemaMutation::SwapWith { .. } => {
                table.columns.clear();
                table.constraints.clear();
                return;
            }
            // A change not read may give any column another type.
            DdlSchemaMutation::ColumnsUnread => {
                relation.listing = ColumnListing::Some;
                for column in &mut table.columns {
                    column.data_type = None;
                }
            }
            DdlSchemaMutation::AddColumn { column_name } => {
                let added = key(column_name);
                if !table
                    .columns
                    .iter()
                    .any(|column| key(&column.name.name) == added)
                {
                    table.columns.push(made_column(column_name, Vec::new()));
                }
            }
            DdlSchemaMutation::DropColumn { column_name } => {
                let dropped = key(column_name);
                table
                    .columns
                    .retain(|column| key(&column.name.name) != dropped);
                table.constraints.retain(|constraint| {
                    !constraint.columns.iter().any(|c| key(&c.name) == dropped)
                });
                values.remove(&dropped);
                written.remove(&dropped);
            }
            DdlSchemaMutation::RenameColumn { from, to } => {
                let old = key(from);
                if let Some(value) = values.remove(&old) {
                    values.insert(key(to), value);
                }
                if let Some(tags) = written.remove(&old) {
                    written.insert(key(to), tags);
                }
                let renamed = CatalogIdent::from_name(to.clone());
                let mut found = false;
                for column in &mut table.columns {
                    if key(&column.name.name) == old {
                        column.name = renamed.clone();
                        found = true;
                    }
                }
                // A column the table is not known to have is one it has
                // under its new name from then on.
                if !found {
                    table.columns.push(made_column(to, Vec::new()));
                }
                for constraint in &mut table.constraints {
                    for column in &mut constraint.columns {
                        if key(&column.name) == old {
                            *column = renamed.clone();
                        }
                    }
                }
            }
            DdlSchemaMutation::SetColumnTags { column_name, tags } => {
                let tagged = key(column_name);
                let tags: Vec<CatalogTag> = tags
                    .iter()
                    .map(|tag| tag_in_session(tag, session))
                    .collect();
                for column in &mut table.columns {
                    if key(&column.name.name) == tagged {
                        column.tags.retain(|held| {
                            let by_statement = wrote(written, &tagged, held);
                            !tags.iter().any(|tag| tag_named(held, tag, by_statement))
                        });
                        column.tags.extend(tags.iter().cloned());
                    }
                }
                let recorded = written.entry(tagged.clone()).or_default();
                recorded.retain(|held| !tags.iter().any(|tag| tag_named(held, tag, true)));
                recorded.extend(tags.iter().cloned());
                // A tag the script sets labels the column's value itself, in
                // place of one of its name the value carried.
                if let Some(value) = values.get_mut(&tagged) {
                    value.exposure = None;
                    value
                        .tags
                        .retain(|held| !tags.iter().any(|tag| tag_named(held, tag, false)));
                }
            }
            DdlSchemaMutation::SetColumnType {
                column_name,
                data_type,
            } => {
                let retyped = key(column_name);
                for column in &mut table.columns {
                    if key(&column.name.name) == retyped {
                        column.data_type = data_type.clone();
                    }
                }
            }
            DdlSchemaMutation::UnsetColumnTags { column_name, tags } => {
                let untagged = key(column_name);
                let tags: Vec<CatalogTag> = tags
                    .iter()
                    .map(|tag| tag_in_session(tag, session))
                    .collect();
                for column in &mut table.columns {
                    if key(&column.name.name) == untagged {
                        column.tags.retain(|held| {
                            let by_statement = wrote(written, &untagged, held);
                            !tags.iter().any(|tag| tag_named(held, tag, by_statement))
                        });
                    }
                }
                if let Some(recorded) = written.get_mut(&untagged) {
                    recorded.retain(|held| !tags.iter().any(|tag| tag_named(held, tag, true)));
                }
                if let Some(value) = values.get_mut(&untagged) {
                    value
                        .tags
                        .retain(|held| !tags.iter().any(|tag| tag_named(held, tag, false)));
                }
            }
        }
    }
}

/// A column a statement makes, named `name` as written, carrying `tags`.
pub(crate) fn made_column(name: &str, tags: Vec<CatalogTag>) -> CatalogColumn {
    CatalogColumn {
        name: CatalogIdent::from_name(name),
        data_type: None,
        nullable: None,
        tags,
    }
}

/// A relation a statement makes, named `name` as written, with `columns`.
fn made_table(name: &str, columns: Vec<CatalogColumn>) -> CatalogTable {
    CatalogTable {
        name: CatalogIdent::from_name(name),
        kind: CatalogTableKind::Unknown,
        columns,
        row_count_estimate: None,
        row_count_estimate_as_of: None,
        bytes_estimate: None,
        bytes_estimate_as_of: None,
        constraints: Vec::new(),
        comment: None,
        tags: Vec::new(),
    }
}

/// A script's relations as the statement starting at a point finds them.
#[derive(Debug, Clone, Copy)]
pub(crate) struct RelationsAt<'a> {
    relations: &'a ScriptRelations,
    at: u32,
}

impl RelationsAt<'static> {
    /// No relation.
    pub(crate) fn none() -> Self {
        NO_RELATIONS.at(0)
    }
}

impl<'a> RelationsAt<'a> {
    /// The table `table_ref` names under `session`: one an earlier
    /// statement made at the catalog's place of the name, or in the
    /// session's own schema of temporary tables, from that statement on;
    /// else the one `catalog`, where one is attached, has, as the script's
    /// column changes leave it, unless a statement dropped it or renamed it
    /// away; else one an earlier statement made ([`ScriptRelations`]).
    pub(crate) fn catalogued_table(
        self,
        catalog: Option<&'a CatalogIndex>,
        table_ref: &TableRef,
        session: &crate::ir::SessionContext,
    ) -> Option<&'a CatalogTable> {
        let table_ref = &self.resolved(catalog, table_ref, session);
        let held = self
            .relations
            .find(table_ref, session, self.at)
            .and_then(|(place, index)| Some((place, self.relations.tables.get(index)?)));
        let catalogued = catalog.and_then(|catalog| catalog.catalogued_place(table_ref, session));
        match (catalogued, held) {
            (
                Some(_),
                Some((
                    _,
                    ScriptTable {
                        table,
                        origin: RelationOrigin::Catalogued,
                        ..
                    },
                )),
            )
            | (None, Some((_, ScriptTable { table, .. }))) => Some(table),
            (
                Some((place, catalogued)),
                Some((
                    held_place,
                    ScriptTable {
                        table: made,
                        origin: RelationOrigin::Made,
                        ..
                    },
                )),
            ) => Some(if held_place.session_temporary || *held_place == place {
                made
            } else {
                catalogued
            }),
            (Some((place, table)), None) => (!self.removed(table_ref, &place)).then_some(table),
            (None, None) => None,
        }
    }

    /// Whether the relation `table_ref` names under `session` is a view:
    /// one an earlier statement made as one, or the catalog lists as one.
    pub(crate) fn is_view(
        self,
        catalog: Option<&'a CatalogIndex>,
        table_ref: &TableRef,
        session: &crate::ir::SessionContext,
    ) -> bool {
        let table_ref = &self.resolved(catalog, table_ref, session);
        match self.relations.find(table_ref, session, self.at) {
            Some((_, index)) => self
                .relations
                .tables
                .get(index)
                .is_some_and(|held| held.view),
            None => catalog
                .and_then(|catalog| catalog.catalogued_place(table_ref, session))
                .is_some_and(|(_, table)| {
                    matches!(
                        table.kind,
                        CatalogTableKind::View | CatalogTableKind::MaterializedView
                    )
                }),
        }
    }

    /// Whether one of the script's own statements before this point made,
    /// replaced, altered the columns of, renamed or dropped the relation
    /// `table_ref` names under `session`, whatever is known of it, or a
    /// script run before it left the name to the run ([`ScriptRelations::left`]):
    /// what the name denotes here is the run's to say, not that of another
    /// script that makes a relation of the name.
    pub(crate) fn names(
        self,
        catalog: Option<&CatalogIndex>,
        table_ref: &TableRef,
        session: &crate::ir::SessionContext,
    ) -> bool {
        if table_ref.server.is_some() {
            return false;
        }
        let table_ref = &self.resolved(catalog, table_ref, session);
        let Some(named) = self.relations.named.get(&IdentKey::new(&table_ref.name)) else {
            return false;
        };
        let bare = table_ref.db.is_none() && table_ref.schema.is_none();
        let written = RelationPlace::of(table_ref, session);
        let agrees = |written: &Option<IdentKey>, part: &Option<IdentKey>| match (written, part) {
            (Some(written), Some(part)) => written == part,
            (Some(_), None) | (None, Some(_)) | (None, None) => true,
        };
        named
            .iter()
            .filter(|naming| (naming.from..naming.until).contains(&self.at))
            .any(|naming| match naming.place.session_temporary {
                true => bare,
                false => {
                    agrees(&written.database, &naming.place.database)
                        && agrees(&written.schema, &naming.place.schema)
                }
            })
    }

    /// Whether `table_ref` names, under `session`, a relation a statement
    /// of the script before this point made or changed.
    pub(crate) fn holds(
        self,
        catalog: Option<&CatalogIndex>,
        table_ref: &TableRef,
        session: &crate::ir::SessionContext,
    ) -> bool {
        let table_ref = self.resolved(catalog, table_ref, session);
        self.relations.find(&table_ref, session, self.at).is_some()
    }

    /// Whether the relation `table_ref` names under `session` here is a
    /// temporary table an earlier statement of the script made, on every
    /// path into this point: on each, the last change at its place leaves
    /// a temporary table.
    pub(crate) fn temporary(
        self,
        table_ref: &TableRef,
        session: &crate::ir::SessionContext,
    ) -> bool {
        let relations = self.relations;
        let at = self.at;
        let Some((place, _)) = relations.find(table_ref, session, at) else {
            return false;
        };
        let Some(changes) = relations.changes.get(&IdentKey::new(&table_ref.name)) else {
            return false;
        };
        let in_force: Vec<&RelationChange> = changes
            .iter()
            .filter(|change| (change.from..change.until).contains(&at) && change.place == *place)
            .collect();
        relations.temporary_after(&in_force, 0, false, at)
    }

    /// Whether `table`, as [`Self::catalogued_table`] answered it, has no
    /// column but those it lists, as far as the script's statements say:
    /// false where one changed its columns in a way not read.
    pub(crate) fn lists_every_column(self, table: &CatalogTable) -> bool {
        !self.relations.tables.iter().any(|held| {
            std::ptr::eq(&held.table, table) && matches!(held.listing, ColumnListing::Some)
        })
    }

    /// What reasoning found of the value of the column `column` (a
    /// normalized column name) of `table`, as [`Self::catalogued_table`]
    /// answered it, where a statement made it from a query ([`MadeValue`]).
    pub(crate) fn column_value(
        self,
        table: &CatalogTable,
        column: &IdentKey,
    ) -> Option<&'a MadeValue> {
        self.relations
            .tables
            .iter()
            .find(|held| std::ptr::eq(&held.table, table))
            .and_then(|held| held.values.get(column))
    }

    /// Whether the rows of `table`, as [`Self::catalogued_table`] answered
    /// it, hold none: a filter of the query a statement made it from
    /// contradicted what its input held ([`ScriptTable::holds_no_row`]).
    pub(crate) fn holds_no_row(self, table: &CatalogTable) -> bool {
        self.relations
            .tables
            .iter()
            .find(|held| std::ptr::eq(&held.table, table))
            .is_some_and(|held| held.holds_no_row)
    }

    /// The values of the columns of `table`, as [`Self::column_value`]
    /// gives them, and the tags statements wrote on them.
    #[allow(clippy::type_complexity)] // the two per-column maps a held table keeps
    fn made_of(
        self,
        table: &CatalogTable,
    ) -> (
        std::collections::BTreeMap<IdentKey, MadeValue>,
        std::collections::BTreeMap<IdentKey, Vec<CatalogTag>>,
    ) {
        self.relations
            .tables
            .iter()
            .find(|held| std::ptr::eq(&held.table, table))
            .map(|held| (held.values.clone(), held.written.clone()))
            .unwrap_or_default()
    }

    /// Whether `table_ref` names a table under `session`: one an earlier
    /// statement made, else as `catalog` answers ([`CatalogIndex::table_presence`])
    /// where no statement dropped its table or renamed it away.
    pub(crate) fn table_presence(
        self,
        catalog: &CatalogIndex,
        table_ref: &TableRef,
        session: &crate::ir::SessionContext,
    ) -> Option<bool> {
        let table_ref = &self.resolved(Some(catalog), table_ref, session);
        if self.relations.find(table_ref, session, self.at).is_some() {
            return Some(true);
        }
        match catalog.catalogued_place(table_ref, session) {
            Some((place, _)) if self.removed(table_ref, &place) => Some(false),
            Some((_, table)) => catalog.table_presence(Some(table)),
            None => catalog.table_presence(None),
        }
    }

    /// `table_ref` as a reader finds it under `session`: where the session
    /// leaves its schema to its search path, in the first schema of the
    /// path where a statement before made the name or `catalog` has it and
    /// no statement dropped it, else in the path's first; as written where
    /// it names a temporary table of the session's own.
    pub(crate) fn resolved(
        self,
        catalog: Option<&CatalogIndex>,
        table_ref: &TableRef,
        session: &crate::ir::SessionContext,
    ) -> TableRef {
        let Some(path) = searched(table_ref, session) else {
            return table_ref.clone();
        };
        let temporary = self
            .relations
            .find(table_ref, session, self.at)
            .is_some_and(|(place, _)| place.session_temporary);
        if temporary {
            return table_ref.clone();
        }
        let holds = |candidate: &TableRef| {
            self.relations.find(candidate, session, self.at).is_some()
                || catalog
                    .and_then(|catalog| catalog.catalogued_place(candidate, session))
                    .is_some_and(|(place, _)| !self.removed(candidate, &place))
        };
        let mut candidates = path.iter().map(|schema| in_schema(table_ref, schema));
        let first = candidates.next();
        first
            .clone()
            .filter(|candidate| holds(candidate))
            .or_else(|| candidates.find(|candidate| holds(candidate)))
            .or(first)
            .unwrap_or_else(|| table_ref.clone())
    }

    /// Where the name `table_ref` may resolve under `session`
    /// ([`Resolution`]): as written, where it names its schema; else each
    /// schema of the session's search path up to the first the run knows
    /// to hold it, the one schema where that is the first; any schema
    /// where the path names none, or names the session's user (`$user`),
    /// whose schema the run does not know.
    pub(crate) fn resolution(
        self,
        catalog: Option<&CatalogIndex>,
        table_ref: &TableRef,
        session: &crate::ir::SessionContext,
    ) -> Resolution {
        let Some(path) = searched(table_ref, session) else {
            return Resolution::One(table_ref.clone());
        };
        let temporary = self
            .relations
            .find(table_ref, session, self.at)
            .is_some_and(|(place, _)| place.session_temporary);
        if temporary {
            return Resolution::One(table_ref.clone());
        }
        let holds = |candidate: &TableRef| {
            self.relations.find(candidate, session, self.at).is_some()
                || catalog
                    .and_then(|catalog| catalog.catalogued_place(candidate, session))
                    .is_some_and(|(place, _)| !self.removed(candidate, &place))
        };
        let mut among = Vec::new();
        for schema in path {
            let unquoted = schema.trim_matches(|c| c == '"' || c == '\'');
            if unquoted.eq_ignore_ascii_case("$user") {
                return Resolution::Any(table_ref.clone());
            }
            let candidate = in_schema(table_ref, schema);
            let held = holds(&candidate);
            among.push(candidate);
            if held {
                break;
            }
        }
        match among.len() {
            0 => Resolution::Any(table_ref.clone()),
            1 => Resolution::One(among.remove(0)),
            _ => Resolution::Among(among),
        }
    }

    /// Whether the last statement before this point that changed the
    /// relation `table_ref` names at `place` dropped it or renamed it away.
    fn removed(self, table_ref: &TableRef, place: &RelationPlace) -> bool {
        matches!(
            self.relations.latest_at(&table_ref.name, place, self.at),
            Some(None)
        )
    }
}

/// Of `candidates` (each a location's database and schema, already of the
/// name's last part), the one that agrees with every part `database` and
/// `schema` write; `None` when none or more than one does. A part the name
/// does not write agrees with any; one it writes agrees only with a
/// location that has that part, equal to it.
pub fn unique_location_named_by<'k, C, K: PartialEq + ?Sized + 'k>(
    database: Option<&K>,
    schema: Option<&K>,
    candidates: impl IntoIterator<Item = (C, Option<&'k K>, Option<&'k K>)>,
) -> Option<C> {
    let agrees = |written: Option<&K>, part: Option<&K>| match written {
        Some(written) => part == Some(written),
        None => true,
    };
    let mut agreeing = candidates
        .into_iter()
        .filter(|(_, db, sc)| agrees(database, *db) && agrees(schema, *sc))
        .map(|(location, _, _)| location);
    match (agreeing.next(), agreeing.next()) {
        (Some(only), None) => Some(only),
        (Some(_), Some(_)) | (None, _) => None,
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

    // A query nested deeper than the stack lets the analyzer walk is not
    // read.
    let Some(_frame) = crate::ir::lower::enter_nested() else {
        return;
    };
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
    // Joins nested deeper than the stack lets the analyzer walk are not
    // read.
    let Some(_frame) = crate::ir::lower::enter_nested() else {
        return;
    };
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

    // An expression nested deeper than the stack lets the analyzer walk is
    // not read.
    let Some(_frame) = crate::ir::lower::enter_nested() else {
        return;
    };
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
        AstExpr::LogicalChain { operands, .. } | AstExpr::OperatorChain { operands, .. } => {
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
        // Not read for the tables they name.
        AstExpr::Ident { .. }
        | AstExpr::Literal { .. }
        | AstExpr::Placeholder { .. }
        | AstExpr::JinjaPlaceholder { .. }
        | AstExpr::DbtRef { .. }
        | AstExpr::DbtSource { .. }
        | AstExpr::DbtVar { .. }
        | AstExpr::DbtConfig { .. }
        | AstExpr::DbtThis { .. }
        | AstExpr::PositionRef { .. }
        | AstExpr::InListOpaque { .. }
        | AstExpr::ExplSnowIdent { .. }
        | AstExpr::Spread { .. }
        | AstExpr::WindowExpr { .. }
        | AstExpr::TvfWithSchema { .. }
        | AstExpr::ScriptingVarRef { .. }
        | AstExpr::SessionVarRef { .. }
        | AstExpr::QualifiedStar { .. }
        | AstExpr::UnqualifiedStar { .. }
        | AstExpr::Prior { .. }
        | AstExpr::ConnectByRoot { .. }
        | AstExpr::IsNull { .. }
        | AstExpr::IsPredicate { .. }
        | AstExpr::IsDistinctFrom { .. }
        | AstExpr::Like { .. }
        | AstExpr::SimilarTo { .. }
        | AstExpr::Cast { .. }
        | AstExpr::TryCast { .. }
        | AstExpr::SafeCast { .. }
        | AstExpr::TypeCast { .. }
        | AstExpr::Extract { .. }
        | AstExpr::Position { .. }
        | AstExpr::MatchAgainst { .. }
        | AstExpr::Trim { .. }
        | AstExpr::Substring { .. }
        | AstExpr::Collate { .. }
        | AstExpr::SubqueryArg { .. }
        | AstExpr::Parenthesized { .. }
        | AstExpr::RowConstructor { .. }
        | AstExpr::ArraySubscript { .. }
        | AstExpr::ObjectFieldColon { .. }
        | AstExpr::ObjectFieldBracket { .. }
        | AstExpr::ObjectFieldDot { .. }
        | AstExpr::MethodCall { .. }
        | AstExpr::QualifiedStarFromExpr { .. }
        | AstExpr::JinjaConditional { .. }
        | AstExpr::AtTimeZone { .. }
        | AstExpr::TypedStringLiteral { .. }
        | AstExpr::Error { .. } => {}
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
        AstFunctionArg::BulkArg { value, .. }
        | AstFunctionArg::Introduced {
            value: crate::ast::AstIntroducedValue::Expr(value),
            ..
        } => {
            extract_tables_from_expr(value, source, tables);
        }
        AstFunctionArg::Unparsed { .. }
        | AstFunctionArg::DataType { .. }
        | AstFunctionArg::NonValue { .. }
        | AstFunctionArg::Introduced {
            value:
                crate::ast::AstIntroducedValue::DataType { .. }
                | crate::ast::AstIntroducedValue::Name(_),
            ..
        } => {}
        AstFunctionArg::Table {
            name,
            partition_by,
            order_by,
            ..
        } => {
            tables.push(object_ref_to_catalog_name(name, source));
            for expr in partition_by {
                extract_tables_from_expr(expr, source, tables);
            }
            for item in order_by {
                extract_tables_from_expr(&item.expr, source, tables);
            }
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
mod unique_location_tests {
    use super::unique_location_named_by;

    const LOCATIONS: [(&str, Option<&str>, Option<&str>); 3] = [
        ("prod.a", Some("PROD"), Some("A")),
        ("prod.b", Some("PROD"), Some("B")),
        ("a", None, Some("A")),
    ];

    #[test]
    fn a_name_is_the_one_location_that_agrees_with_every_part_it_writes() {
        let named = |database: Option<&str>, schema: Option<&str>| {
            unique_location_named_by(database, schema, LOCATIONS)
        };
        assert_eq!(named(Some("PROD"), Some("A")), Some("prod.a"));
        assert_eq!(named(Some("PROD"), Some("B")), Some("prod.b"));
        // `a.t` is `prod.a.t` and the database-less `a.t` alike.
        assert_eq!(named(None, Some("A")), None);
        assert_eq!(named(None, Some("B")), Some("prod.b"));
        assert_eq!(named(Some("PROD"), None), None);
        assert_eq!(named(None, None), None);
        assert_eq!(named(Some("DEV"), None), None);
        assert_eq!(named(None, Some("C")), None);
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
        let _folding = crate::ir::normalize::default_folding();
        let ov = vec![overlay("ANALYTICS.PUBLIC.USERS", "EMAIL", &["pii"])];
        let snap = CatalogSnapshot::from_source_column_tags(&ov, None, &*default_provider());
        assert_eq!(snap.schema_version, CATALOG_SCHEMA_VERSION);
        assert_eq!(snap.source.as_deref(), Some("dbt"));
        assert_eq!(snap.listing, CatalogListing::Named);
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
    fn a_snapshot_file_neither_gives_nor_takes_a_listing() {
        let ov = vec![overlay("ANALYTICS.PUBLIC.USERS", "EMAIL", &["pii"])];
        let named = CatalogSnapshot::from_source_column_tags(&ov, None, &*default_provider());
        let written = serde_json::to_value(&named).expect("serialize");
        assert!(written.get("listing").is_none(), "{written}");
        let read: CatalogSnapshot = serde_json::from_value(written).expect("deserialize");
        assert_eq!(read.listing, CatalogListing::Inventory);
        let file = format!(r#"{{"schema_version": {CATALOG_SCHEMA_VERSION}, "listing": "Named"}}"#);
        let read: CatalogSnapshot = serde_json::from_str(&file).expect("deserialize");
        assert_eq!(read.listing, CatalogListing::Inventory);
    }

    #[test]
    fn synth_two_part_uses_default_database() {
        let _folding = crate::ir::normalize::default_folding();
        let ov = vec![overlay("PUBLIC.USERS", "EMAIL", &["pii"])];
        let snap =
            CatalogSnapshot::from_source_column_tags(&ov, Some("ANALYTICS"), &*default_provider());
        assert_eq!(snap.databases.len(), 1);
        assert_eq!(snap.databases[0].name.name, "ANALYTICS");
        assert_eq!(snap.databases[0].schemas[0].name.name, "PUBLIC");
        assert_eq!(snap.databases[0].schemas[0].tables[0].name.name, "USERS");
    }

    #[test]
    fn synth_two_part_without_default_database_is_skipped() {
        let ov = vec![overlay("PUBLIC.USERS", "EMAIL", &["pii"])];
        let snap = CatalogSnapshot::from_source_column_tags(&ov, None, &*default_provider());
        assert!(snap.databases.is_empty());
    }

    #[test]
    fn synth_names_are_one_table_where_the_providers_index_finds_them_as_one() {
        let _folding = crate::ir::normalize::default_folding();
        let ov = vec![
            overlay("ANALYTICS.PUBLIC.Orders", "EMAIL", &["pii"]),
            overlay("ANALYTICS.PUBLIC.ORDERS", "PHONE", &["pii"]),
        ];
        for (provider, tables) in [
            (default_provider(), 1),
            (provider_by_name("bigquery").expect("provider"), 2),
        ] {
            let snap = CatalogSnapshot::from_source_column_tags(&ov, None, &*provider);
            assert_eq!(snap.databases[0].schemas[0].tables.len(), tables);
            let index = CatalogIndex::from_snapshot_with_provider(snap, provider).expect("index");
            for table in ["Orders", "ORDERS"] {
                assert!(index
                    .get_table_by_name("ANALYTICS", "PUBLIC", table)
                    .is_some());
            }
        }
    }

    #[test]
    fn synth_merges_columns_and_dedups_tags() {
        let _folding = crate::ir::normalize::default_folding();
        let ov = vec![
            overlay("ANALYTICS.PUBLIC.USERS", "EMAIL", &["pii", "pii"]),
            overlay("ANALYTICS.PUBLIC.USERS", "SSN", &["pii"]),
        ];
        let snap = CatalogSnapshot::from_source_column_tags(&ov, None, &*default_provider());
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

#[cfg(test)]
mod folding_tests {
    use super::*;
    use crate::ir::normalize::set_normalization_dialect;
    use std::panic::{catch_unwind, AssertUnwindSafe};

    const QUOTED: &str = r#"{"schema_version": 2, "databases": [{"name": "ANALYTICS", "schemas": [{"name": "PUBLIC", "tables": [{"name": {"name": "MyTable", "case_sensitive": true}, "kind": "Table", "columns": []}]}]}]}"#;

    #[test]
    fn an_index_is_read_under_the_folding_its_keys_were_made_under() {
        let snapshot: CatalogSnapshot = serde_json::from_str(QUOTED).expect("snapshot");
        let databricks = set_normalization_dialect("databricks");
        let index = CatalogIndex::from_snapshot(snapshot).expect("index");
        assert!(index
            .get_table_by_name("analytics", "public", "`MYTABLE`")
            .is_some());
        drop(databricks);

        // Snowflake keys a quoted name by its case; the index was not.
        let snowflake = set_normalization_dialect("snowflake");
        let read = catch_unwind(AssertUnwindSafe(|| {
            index
                .get_table_by_name("ANALYTICS", "PUBLIC", "\"MyTable\"")
                .is_some()
        }));
        assert_eq!(read.is_err(), cfg!(debug_assertions));
        drop(snowflake);

        // Nor MySQL: its quoted names keep their case.
        let _mysql = set_normalization_dialect("mysql");
        let read = catch_unwind(AssertUnwindSafe(|| index.normalize_ident("`MyTable`")));
        assert_eq!(read.is_err(), cfg!(debug_assertions));
    }

    #[test]
    fn a_column_tag_is_matched_where_an_index_with_its_provider_finds_the_table() {
        let catalog = QUOTED
            .replace("MyTable", "MYTABLE")
            .replace(r#""columns": []"#, r#""columns": [{"name": "ID"}]"#);
        let overlay = [ColumnTagOverlay {
            full_ref: "analytics.public.MYTABLE".to_string(),
            column: "id".to_string(),
            tag_names: vec!["pii".to_string()],
        }];
        // MySQL reads no quote in the catalog's `"MYTABLE"`; the index does.
        let _mysql = set_normalization_dialect("mysql");
        for (provider, found) in [
            (default_provider(), true),
            (provider_by_name("postgresql").expect("provider"), false),
        ] {
            let mut snapshot: CatalogSnapshot = serde_json::from_str(&catalog).expect("snapshot");
            snapshot.enrich_column_tags(&overlay, &*provider);
            let tagged = !snapshot.databases[0].schemas[0].tables[0].columns[0]
                .tags
                .is_empty();
            let index =
                CatalogIndex::from_snapshot_with_provider(snapshot, provider).expect("index");
            assert_eq!(
                index
                    .get_table_by_name("analytics", "public", "MYTABLE")
                    .is_some(),
                found
            );
            assert_eq!(tagged, found);
        }
    }

    fn column_tags(index: &CatalogIndex, column: &str) -> Vec<String> {
        index
            .get_column_by_name("ANALYTICS", "PUBLIC", "ORDERS", column)
            .map(|c| c.tags.iter().map(|t| t.tag_name.clone()).collect())
            .unwrap_or_default()
    }

    #[test]
    fn a_column_tag_lands_on_the_column_an_index_with_its_provider_finds() {
        let _snowflake = set_normalization_dialect("snowflake");
        let tag = |column: &str, tag: &str| ColumnTagOverlay {
            full_ref: "ANALYTICS.PUBLIC.ORDERS".to_string(),
            column: column.to_string(),
            tag_names: vec![tag.to_string()],
        };
        // A case-sensitive catalog column beside an unquoted one, and two
        // unquoted columns that differ only in case.
        for (provider, columns, overlay, expected) in [
            (
                "postgresql",
                r#"[{"name": "EMAIL"}, {"name": {"name": "Email", "case_sensitive": true}}]"#,
                vec![tag("email", "folded"), tag("\"Email\"", "kept")],
                [("email", vec!["folded"]), ("\"Email\"", vec!["kept"])],
            ),
            (
                "bigquery",
                r#"[{"name": "email"}, {"name": "EMAIL"}]"#,
                vec![tag("email", "lower"), tag("EMAIL", "upper")],
                [("email", vec!["lower"]), ("EMAIL", vec!["upper"])],
            ),
        ] {
            let provider = provider_by_name(provider).expect("provider");
            let catalog = QUOTED
                .replace(
                    r#"{"name": "MyTable", "case_sensitive": true}"#,
                    r#""ORDERS""#,
                )
                .replace(r#""columns": []"#, &format!(r#""columns": {columns}"#));
            let mut snapshot: CatalogSnapshot = serde_json::from_str(&catalog).expect("snapshot");
            assert_eq!(snapshot.enrich_column_tags(&overlay, &*provider), 2);
            let index = CatalogIndex::from_snapshot_with_provider(snapshot, provider.clone())
                .expect("index");
            for (column, tags) in &expected {
                assert_eq!(column_tags(&index, column), *tags, "{column}");
            }

            // The same declarations with no warehouse catalog.
            let synthesized = CatalogSnapshot::from_source_column_tags(&overlay, None, &*provider);
            let declared = &synthesized.databases[0].schemas[0].tables[0].columns;
            assert_eq!(declared.len(), 2);
            let index =
                CatalogIndex::from_snapshot_with_provider(synthesized, provider).expect("index");
            for (column, tags) in &expected {
                assert_eq!(column_tags(&index, column), *tags, "{column}");
            }
        }

        // A provider that folds both spellings to one name merges them.
        let overlay = [tag("email", "lower"), tag("EMAIL", "upper")];
        let synthesized =
            CatalogSnapshot::from_source_column_tags(&overlay, None, &*default_provider());
        assert_eq!(
            synthesized.databases[0].schemas[0].tables[0].columns.len(),
            1
        );
        let index = CatalogIndex::from_snapshot(synthesized).expect("index");
        assert_eq!(column_tags(&index, "Email"), ["lower", "upper"]);
    }

    #[test]
    fn an_index_of_unquoted_names_is_read_under_any_folding() {
        let unquoted = QUOTED.replace(r#"{"name": "MyTable", "case_sensitive": true}"#, r#""T""#);
        let snapshot: CatalogSnapshot = serde_json::from_str(&unquoted).expect("snapshot");
        let databricks = set_normalization_dialect("databricks");
        let index = CatalogIndex::from_snapshot(snapshot).expect("index");
        drop(databricks);
        let _snowflake = set_normalization_dialect("snowflake");
        assert!(index
            .get_table_by_name("ANALYTICS", "PUBLIC", "t")
            .is_some());
    }
}
