// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

use serde::{Deserialize, Serialize};

use crate::catalog::CATALOG_SCHEMA_VERSION;

/// Schema-facing representation of a catalog snapshot.
///
/// This is intentionally a documentation/validation type:
/// - Use it for generating JSON Schema.
/// - Runtime code should use [`crate::catalog::CatalogSnapshot`] / [`crate::catalog::CatalogIndex`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schema", schemars(rename = "CatalogSnapshotSchema"))]
pub struct CatalogSnapshotSchema {
    /// Schema version for forward compatibility.
    pub schema_version: u32,

    /// RFC3339 timestamp when the snapshot was generated (optional).
    #[serde(default)]
    pub generated_at: Option<String>,

    /// Free-form source descriptor (e.g., "snowsql", "python-connector", "dbt").
    #[serde(default)]
    pub source: Option<String>,

    /// The data platform that produced this snapshot.
    ///
    /// Determines identifier normalization rules.
    /// Supported values: "snowflake", "postgresql", "bigquery", "databricks".
    /// When absent, defaults to "snowflake".
    #[serde(default)]
    pub provider: Option<String>,

    #[serde(default)]
    pub databases: Vec<CatalogDatabaseSchema>,

    /// Governance policies extracted from ACCOUNT_USAGE.
    /// These are account-level objects (not scoped to a single database).
    #[serde(default)]
    pub policies: Vec<CatalogPolicySchema>,

    /// Policy-to-table/column bindings from POLICY_REFERENCES.
    #[serde(default)]
    pub policy_references: Vec<CatalogPolicyReferenceSchema>,

    /// Grant graph for computing effective access changes.
    /// Enables pre-execution analysis of GRANT/REVOKE statements.
    #[serde(default)]
    pub grants: Option<CatalogGrantsSchema>,
}

impl CatalogSnapshotSchema {
    pub fn schema_version_value() -> u32 {
        CATALOG_SCHEMA_VERSION
    }

    #[cfg(feature = "schema")]
    pub fn generate_schema() -> schemars::schema::RootSchema {
        schemars::schema_for!(CatalogSnapshotSchema)
    }
}

/// Schema-facing identifier - allows either a plain string or an object with `name` and optional `case_sensitive`.
///
/// # Examples
///
/// All of these are valid:
/// ```json
/// "MY_TABLE"
/// {"name": "MY_TABLE"}
/// {"name": "My Quoted Table", "case_sensitive": true}
/// ```
#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(untagged)]
#[cfg_attr(feature = "schema", schemars(rename = "CatalogIdentSchema"))]
pub enum CatalogIdentSchema {
    /// Plain string identifier (case-insensitive, equivalent to `{"name": "...", "case_sensitive": false}`)
    Simple(String),
    /// Full object with explicit case_sensitive option
    Full(CatalogIdentFull),
}

/// Full identifier object with optional case_sensitive flag.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schema", schemars(rename = "CatalogIdentFull"))]
pub struct CatalogIdentFull {
    pub name: String,

    /// If true, comparisons should be case-sensitive (quoted identifiers).
    /// If false, comparisons should be case-insensitive (unquoted identifiers).
    #[serde(default)]
    pub case_sensitive: bool,
}

impl CatalogIdentSchema {
    /// Get the identifier name.
    pub fn name(&self) -> &str {
        match self {
            CatalogIdentSchema::Simple(s) => s,
            CatalogIdentSchema::Full(f) => &f.name,
        }
    }

    /// Check if this is a case-sensitive identifier.
    pub fn case_sensitive(&self) -> bool {
        match self {
            CatalogIdentSchema::Simple(_) => false,
            CatalogIdentSchema::Full(f) => f.case_sensitive,
        }
    }
}

impl<'de> Deserialize<'de> for CatalogIdentSchema {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::{self, MapAccess, Visitor};

        struct CatalogIdentVisitor;

        impl<'de> Visitor<'de> for CatalogIdentVisitor {
            type Value = CatalogIdentSchema;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a string or an object with 'name' field")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(CatalogIdentSchema::Simple(v.to_string()))
            }

            fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(CatalogIdentSchema::Simple(v))
            }

            fn visit_map<M>(self, map: M) -> Result<Self::Value, M::Error>
            where
                M: MapAccess<'de>,
            {
                let full =
                    CatalogIdentFull::deserialize(de::value::MapAccessDeserializer::new(map))?;
                Ok(CatalogIdentSchema::Full(full))
            }
        }

        deserializer.deserialize_any(CatalogIdentVisitor)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schema", schemars(rename = "CatalogDatabaseSchema"))]
pub struct CatalogDatabaseSchema {
    pub name: CatalogIdentSchema,

    #[serde(default)]
    pub schemas: Vec<CatalogSchemaSchema>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schema", schemars(rename = "CatalogSchemaSchema"))]
pub struct CatalogSchemaSchema {
    pub name: CatalogIdentSchema,

    /// Tables and views.
    #[serde(default)]
    pub tables: Vec<CatalogTableSchema>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Default)]
#[cfg_attr(feature = "schema", schemars(rename = "CatalogTableKindSchema"))]
pub enum CatalogTableKindSchema {
    Table,
    View,
    MaterializedView,
    ExternalTable,
    #[default]
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schema", schemars(rename = "CatalogTableSchema"))]
pub struct CatalogTableSchema {
    pub name: CatalogIdentSchema,

    #[serde(default)]
    pub kind: CatalogTableKindSchema,

    #[serde(default)]
    pub columns: Vec<CatalogColumnSchema>,

    /// Best-effort/approximate row count (optional; may be stale).
    #[serde(default)]
    pub row_count_estimate: Option<u64>,

    /// RFC3339 timestamp for when `row_count_estimate` was captured (optional).
    #[serde(default)]
    pub row_count_estimate_as_of: Option<String>,

    /// Best-effort/approximate bytes (scan bytes) from Snowflake metadata (optional).
    #[serde(default)]
    pub bytes_estimate: Option<u64>,

    /// RFC3339 timestamp for when `bytes_estimate` was captured (optional).
    #[serde(default)]
    pub bytes_estimate_as_of: Option<String>,

    /// Constraints (optional).
    #[serde(default)]
    pub constraints: Vec<CatalogConstraintSchema>,

    #[serde(default)]
    pub comment: Option<String>,

    /// Tags attached to this table from ACCOUNT_USAGE.TAG_REFERENCES.
    #[serde(default)]
    pub tags: Vec<CatalogTagSchema>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Default)]
#[cfg_attr(feature = "schema", schemars(rename = "CatalogConstraintKindSchema"))]
pub enum CatalogConstraintKindSchema {
    PrimaryKey,
    Unique,
    ForeignKey,
    #[default]
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schema", schemars(rename = "CatalogObjectNameSchema"))]
pub struct CatalogObjectNameSchema {
    pub database: CatalogIdentSchema,
    pub schema: CatalogIdentSchema,
    pub name: CatalogIdentSchema,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schema", schemars(rename = "CatalogConstraintSchema"))]
pub struct CatalogConstraintSchema {
    #[serde(default)]
    pub kind: CatalogConstraintKindSchema,

    #[serde(default)]
    pub name: Option<String>,

    #[serde(default)]
    pub columns: Vec<CatalogIdentSchema>,

    #[serde(default)]
    pub ref_table: Option<CatalogObjectNameSchema>,

    #[serde(default)]
    pub ref_columns: Vec<CatalogIdentSchema>,

    #[serde(default)]
    pub enforced: Option<bool>,

    #[serde(default)]
    pub rely: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schema", schemars(rename = "CatalogColumnSchema"))]
pub struct CatalogColumnSchema {
    pub name: CatalogIdentSchema,

    /// Snowflake type name / display type.
    #[serde(default)]
    pub data_type: Option<String>,

    /// Nullability if known.
    #[serde(default)]
    pub nullable: Option<bool>,

    /// Tags attached to this column from ACCOUNT_USAGE.TAG_REFERENCES.
    #[serde(default)]
    pub tags: Vec<CatalogTagSchema>,
}

// ============================================================================
// Tags
// ============================================================================

/// A tag attached to a Snowflake object (table or column).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schema", schemars(rename = "CatalogTagSchema"))]
pub struct CatalogTagSchema {
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

// ============================================================================
// Governance Policies
// ============================================================================

/// Kind of governance policy extracted from Snowflake.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Default)]
#[cfg_attr(feature = "schema", schemars(rename = "CatalogPolicyKindSchema"))]
pub enum CatalogPolicyKindSchema {
    MaskingPolicy,
    RowAccessPolicy,
    AggregationPolicy,
    ProjectionPolicy,
    #[default]
    Unknown,
}

/// A governance policy definition extracted from Snowflake ACCOUNT_USAGE.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schema", schemars(rename = "CatalogPolicySchema"))]
pub struct CatalogPolicySchema {
    /// Fully-qualified name: database.schema.policy_name
    pub name: CatalogObjectNameSchema,

    /// Kind of policy (masking, row access, etc.)
    #[serde(default)]
    pub kind: CatalogPolicyKindSchema,

    /// The policy body expression (the SQL after "AS" in CREATE ... POLICY).
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
    #[serde(default)]
    pub body_table_dependencies: Vec<CatalogObjectNameSchema>,

    /// Comment on the policy if any.
    #[serde(default)]
    pub comment: Option<String>,

    /// RFC3339 timestamp when the policy was created.
    #[serde(default)]
    pub created_at: Option<String>,

    /// RFC3339 timestamp when the policy was last modified.
    #[serde(default)]
    pub last_modified_at: Option<String>,

    /// Owner role.
    #[serde(default)]
    pub owner: Option<String>,
}

/// A reference binding a policy to a table/column.
/// From SNOWFLAKE.ACCOUNT_USAGE.POLICY_REFERENCES.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schema", schemars(rename = "CatalogPolicyReferenceSchema"))]
pub struct CatalogPolicyReferenceSchema {
    /// The policy being referenced.
    pub policy_name: CatalogObjectNameSchema,

    /// Kind of policy.
    #[serde(default)]
    pub policy_kind: CatalogPolicyKindSchema,

    /// The table the policy is applied to.
    pub ref_table: CatalogObjectNameSchema,

    /// For masking policies: the column the policy is applied to.
    /// For row access policies: None (applies to whole table).
    #[serde(default)]
    pub ref_column: Option<CatalogIdentSchema>,

    /// Whether the policy is enabled/active.
    #[serde(default)]
    pub enabled: Option<bool>,
}

// ============================================================================
// Grant Graph Schema Types
// ============================================================================

/// Grant graph for computing effective access changes.
///
/// This enables pre-execution analysis of GRANT/REVOKE statements by modeling
/// the full role hierarchy and privilege graph.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schema", schemars(rename = "CatalogGrantsSchema"))]
pub struct CatalogGrantsSchema {
    /// Role hierarchy edges: role A granted to role B (B inherits A's privileges).
    #[serde(default)]
    pub role_hierarchy: Vec<CatalogRoleEdgeSchema>,

    /// Object privilege edges: role has privilege on object.
    #[serde(default)]
    pub object_privileges: Vec<CatalogObjectPrivilegeSchema>,

    /// User-to-role assignments.
    #[serde(default)]
    pub user_roles: Vec<CatalogUserRoleSchema>,
}

/// A role hierarchy edge: GRANT ROLE parent TO ROLE child.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schema", schemars(rename = "CatalogRoleEdgeSchema"))]
pub struct CatalogRoleEdgeSchema {
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
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schema", schemars(rename = "CatalogObjectPrivilegeSchema"))]
pub struct CatalogObjectPrivilegeSchema {
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
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schema", schemars(rename = "CatalogUserRoleSchema"))]
pub struct CatalogUserRoleSchema {
    /// User name.
    pub user: String,

    /// Role assigned to the user.
    pub role: String,
}
