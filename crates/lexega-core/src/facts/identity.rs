// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Public identity types — identifier names, qualified table refs, column
//! refs, object refs, principal refs, scope identifiers.
//!
//! Every type here is part of the v1 customer-facing fact-base contract.
//! Field renames after v1 ship are major-version breaking.

use serde::{Deserialize, Serialize};

#[cfg(feature = "schema")]
use schemars::JsonSchema;

use crate::lexer::token::Span;

use super::catalog::{CatalogTag, ColumnLineage, Nullability, TaintLabel};
use super::literal::DataType;

/// A SQL identifier. Carries the `raw` form (as written, with quoting and
/// case preserved) and the `normalized` form used for case-insensitive
/// matching.
///
/// Normalization is dialect-aware (Snowflake/BigQuery/MySQL/MSSQL fold
/// unquoted to UPPERCASE; PostgreSQL/Databricks fold to lowercase).
/// Custom rule files match against `normalized` for portability across
/// the corpus, or against `raw` with `matches:` glob when case-preserving
/// matching is needed.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", schemars(rename = "Identifier"))]
pub struct IdentName {
    pub raw: String,
    pub normalized: String,
}

impl IdentName {
    /// Build from a raw spelling. Calls
    /// to compute the normalized form.
    pub fn new(raw: impl Into<String>) -> Self {
        let raw = raw.into();
        let normalized = crate::ir::normalize::normalize_identifier(&raw);
        Self { raw, normalized }
    }

    /// Build from a pre-normalized pair.
    pub fn from_parts(raw: impl Into<String>, normalized: impl Into<String>) -> Self {
        Self {
            raw: raw.into(),
            normalized: normalized.into(),
        }
    }
}

impl From<&str> for IdentName {
    fn from(s: &str) -> Self {
        Self::new(s)
    }
}

/// A fully-qualified table reference. Customer rules match against
/// `canonical` for the cross-dialect-stable identity, or against
/// `name` / `schema` / `database` for component-level matching.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", schemars(rename = "TableReference"))]
pub struct TableRef {
    pub name: IdentName,
    pub schema: Option<IdentName>,
    pub database: Option<IdentName>,
    /// Linked-server name for a T-SQL four-part reference
    /// (`server.database.schema.object`). `None` for the common
    /// three-part-or-fewer case.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server: Option<IdentName>,
    /// `[server.]database.schema.table` joined with normalized component forms.
    pub canonical: String,
    pub source_span: Option<Span>,
}

impl TableRef {
    /// Construct from raw parts; computes `canonical` from normalized
    /// components. The result has no linked-server component; use
    /// [`Self::with_server`] for a four-part reference.
    pub fn new(
        name: impl Into<IdentName>,
        schema: Option<IdentName>,
        database: Option<IdentName>,
        source_span: Option<Span>,
    ) -> Self {
        let name = name.into();
        let canonical = Self::compute_canonical(None, &database, &schema, &name);
        Self {
            name,
            schema,
            database,
            server: None,
            canonical,
            source_span,
        }
    }

    /// Attach a linked-server component (T-SQL four-part reference) and
    /// recompute `canonical` with the server prefix.
    pub fn with_server(mut self, server: Option<IdentName>) -> Self {
        self.canonical =
            Self::compute_canonical(server.as_ref(), &self.database, &self.schema, &self.name);
        self.server = server;
        self
    }

    fn compute_canonical(
        server: Option<&IdentName>,
        database: &Option<IdentName>,
        schema: &Option<IdentName>,
        name: &IdentName,
    ) -> String {
        let base = match (database, schema) {
            (Some(db), Some(sc)) => {
                format!("{}.{}.{}", db.normalized, sc.normalized, name.normalized)
            }
            (None, Some(sc)) => format!("{}.{}", sc.normalized, name.normalized),
            (Some(db), None) => format!("{}..{}", db.normalized, name.normalized),
            (None, None) => name.normalized.clone(),
        };
        match server {
            Some(srv) => format!("{}.{}", srv.normalized, base),
            None => base,
        }
    }
}

/// A column reference. Carries analytical attributes (nullability,
/// taint, lineage) and catalog-driven tags.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", schemars(rename = "ColumnReference"))]
pub struct ColumnRef {
    pub name: IdentName,
    pub table: Option<TableRef>,
    pub source_span: Option<Span>,
    /// Catalog-driven type when known.
    pub data_type: Option<DataType>,
    pub catalog_tags: Vec<CatalogTag>,
    pub nullability: Nullability,
    pub taint_labels: Vec<TaintLabel>,
    pub lineage: Option<ColumnLineage>,
}

impl ColumnRef {
    /// Construct a minimal `ColumnRef` with no analytical or catalog
    /// projections. Used in test fixtures and as a default before
    /// IR-side enrichment.
    pub fn minimal(name: impl Into<IdentName>, table: Option<TableRef>) -> Self {
        Self {
            name: name.into(),
            table,
            source_span: None,
            data_type: None,
            catalog_tags: Vec::new(),
            nullability: Nullability::Unknown,
            taint_labels: Vec::new(),
            lineage: None,
        }
    }
}

/// A typed reference to a database object (table, view, policy, function,
/// etc.). The `kind` discriminator lets predicates match by kind without
/// inspecting the name.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", schemars(rename = "ObjectReference"))]
pub struct ObjectRef {
    pub kind: ObjectKind,
    pub name: TableRef,
}

/// What sort of object a DDL action targets, or what kind of object a
/// privilege is granted on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum ObjectKind {
    Table,
    View,
    MaterializedView,
    DynamicTable,
    ExternalTable,
    Schema,
    Database,
    Tag,
    Procedure,
    Function,
    Trigger,
    Stage,
    FileFormat,
    Pipe,
    Stream,
    ApiIntegration,
    StorageIntegration,
    ExternalAccessIntegration,
    NotificationIntegration,
    SecurityIntegration,
    Warehouse,
    Task,
    Alert,
    NetworkRule,
    ResourceMonitor,
    Secret,
    Sequence,
    Role,
    User,
    Share,
    Account,
    /// The current session, targeted by `ALTER SESSION SET/UNSET <param>`
    /// (the runtime-scoped analog of an account).
    Session,
    MaskingPolicy,
    RowAccessPolicy,
    NetworkPolicy,
    SessionPolicy,
    PasswordPolicy,
    AggregationPolicy,
    ProjectionPolicy,
    JoinPolicy,
    DataMetricFunction,
    ReplicationGroup,
    AuthenticationPolicy,
    PgExtension,
    PgDomain,
    PgType,
    PgPublication,
    PgSubscription,
    PgRule,
    BqModel,
    // ───────────── Databricks Unity Catalog ─────────────
    /// Top-level UC namespace targeted by `ON CATALOG <name>`.
    Catalog,
    /// UC volume targeted by `ON VOLUME <name>`.
    Volume,
    /// UC external location targeted by `ON EXTERNAL LOCATION <name>`.
    ExternalLocation,
    /// UC storage credential targeted by `ON STORAGE CREDENTIAL <name>`.
    StorageCredential,
    /// UC metastore-tier scope targeted by `ON METASTORE`.
    Metastore,
    /// Redshift datashare (cross-account / cross-cluster data-sharing object).
    Datashare,
    /// Secondary access structure on a relation (`CREATE/ALTER/DROP INDEX`).
    Index,
    /// Redshift permission group (`CREATE/ALTER/DROP GROUP`).
    Group,
    /// Redshift Spectrum external schema (`CREATE EXTERNAL SCHEMA`).
    ExternalSchema,
    /// Snowflake replication/failover group (`ALTER FAILOVER GROUP`).
    FailoverGroup,
    /// Named alias for a base object (`CREATE/DROP SYNONYM`); the alias can point
    /// at a four-part `server.database.schema.object` (linked-server) referent.
    Synonym,
    /// Object-agnostic actions (BEGIN, COMMIT, USE, etc.).
    Generic,
}

/// A principal — the role / user / share / etc. on the receiving end of
/// a privilege change.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", schemars(rename = "PrincipalReference"))]
pub struct PrincipalRef {
    pub kind: PrincipalKind,
    pub name: IdentName,
    pub source_span: Option<Span>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum PrincipalKind {
    User,
    Role,
    Public,
    Share,
    Application,
    Database,
    ApplicationRole,
    /// Dialect-specific principal kinds. Predicates can match by raw
    /// identifier when none of the kinds above apply.
    Other(IdentName),
}

/// Stable identity of a SELECT scope (outer, CTE, derived table, or
/// subquery). Use it to correlate a column or predicate back to the
/// scope it came from.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize, PartialOrd, Ord,
)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(transparent)]
pub struct ScopeIdentity(pub u32);

impl ScopeIdentity {
    pub const OUTER: Self = Self(0);
}
