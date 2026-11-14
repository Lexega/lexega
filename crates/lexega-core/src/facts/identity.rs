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
#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", schemars(rename = "Identifier"))]
pub struct IdentName {
    pub raw: String,
    pub normalized: String,
    /// Where the source writes the text the name is made of, where that
    /// text may hold a string literal (`IDENTIFIER('…')`, a select item
    /// named by its expression): a report prints the name masked where
    /// such a literal is not shown.
    #[serde(skip)]
    pub(crate) origin: TextOrigin,
}

/// Where the source writes the text a fact string is made of, where that
/// text may hold a string literal: a report prints the string masked
/// where such a literal is not shown
/// (`super::secrets::masked_in_print`). It is no part of the fact: two
/// facts that differ only in it are equal.
#[derive(Debug, Clone, Copy, Default)]
pub struct TextOrigin(pub(crate) Option<Span>);

impl PartialEq for TextOrigin {
    fn eq(&self, _: &Self) -> bool {
        true
    }
}

impl Eq for TextOrigin {}

impl std::hash::Hash for TextOrigin {
    fn hash<H: std::hash::Hasher>(&self, _: &mut H) {}
}

/// A fact string the source writes, with where it writes it
/// ([`TextOrigin`]): serialized as the string, masked where a report
/// prints it and the text there holds a string literal that is not shown.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(transparent)]
pub struct WrittenText {
    pub text: String,
    #[serde(skip)]
    pub(crate) origin: TextOrigin,
}

impl WrittenText {
    /// `text`, made of the text the source writes at `origin`.
    pub(crate) fn at(text: String, origin: Span) -> Self {
        Self {
            text,
            origin: TextOrigin::at(origin),
        }
    }

    pub fn as_str(&self) -> &str {
        &self.text
    }
}

impl std::ops::Deref for WrittenText {
    type Target = str;
    fn deref(&self) -> &str {
        &self.text
    }
}

impl Serialize for WrittenText {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self.origin.masked_in_print() {
            true => serializer.serialize_str(super::MASKED_VALUE),
            false => serializer.serialize_str(&self.text),
        }
    }
}

/// Read back from a serialized fact, where it is never written.
impl<'de> Deserialize<'de> for TextOrigin {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        serde::de::IgnoredAny::deserialize(deserializer).map(|_| Self::default())
    }
}

impl TextOrigin {
    /// Made of the text the source writes at `span`.
    pub(crate) fn at(span: Span) -> Self {
        Self(Some(span))
    }

    /// Whether a report masks the string where it prints it.
    pub(crate) fn masked_in_print(self) -> bool {
        super::secrets::masked_in_print(self.0)
    }
}

impl Serialize for IdentName {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        // A column's name may be its expression's text, numbers and all.
        let masked = self.origin.masked_in_print();
        let text = |text: &str| -> String {
            match masked {
                true => super::MASKED_VALUE.to_string(),
                false => text.to_string(),
            }
        };
        let mut out = serializer.serialize_struct("IdentName", 2)?;
        out.serialize_field("raw", &text(&self.raw))?;
        out.serialize_field("normalized", &text(&self.normalized))?;
        out.end()
    }
}

impl IdentName {
    /// Build from a raw spelling. Calls
    /// to compute the normalized form.
    pub fn new(raw: impl Into<String>) -> Self {
        let raw = raw.into();
        let normalized = crate::ir::normalize::normalize_identifier(&raw);
        Self {
            raw,
            normalized,
            origin: TextOrigin::default(),
        }
    }

    /// Build from a pre-normalized pair.
    pub fn from_parts(raw: impl Into<String>, normalized: impl Into<String>) -> Self {
        Self {
            raw: raw.into(),
            normalized: normalized.into(),
            origin: TextOrigin::default(),
        }
    }

    /// The name, made of the text the source writes at `origin`.
    pub(crate) fn written_at(mut self, origin: Span) -> Self {
        self.origin = TextOrigin(Some(origin));
        self
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
#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize)]
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
    /// The same parts joined as the statement wrote them.
    #[serde(default)]
    pub written: String,
    pub source_span: Option<Span>,
}

/// A table reference as it serializes: its text masked whole where a
/// report prints it and the text the source writes it with holds a string
/// literal that is not shown (`super::secrets::masked_in_print`).
impl Serialize for TableRef {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        #[derive(Serialize)]
        struct Masked {
            raw: &'static str,
            normalized: &'static str,
        }
        let masked = super::secrets::name_masked_in_print(self.source_span);
        let part = Masked {
            raw: super::MASKED_VALUE,
            normalized: super::MASKED_VALUE,
        };
        let fields = 6 + usize::from(self.server.is_some());
        let mut out = serializer.serialize_struct("TableRef", fields)?;
        match masked {
            true => {
                out.serialize_field("name", &part)?;
                out.serialize_field("schema", &self.schema.as_ref().map(|_| &part))?;
                out.serialize_field("database", &self.database.as_ref().map(|_| &part))?;
                match &self.server {
                    Some(_) => out.serialize_field("server", &part)?,
                    None => out.skip_field("server")?,
                }
                out.serialize_field("canonical", super::MASKED_VALUE)?;
                out.serialize_field("written", super::MASKED_VALUE)?;
            }
            false => {
                out.serialize_field("name", &self.name)?;
                out.serialize_field("schema", &self.schema)?;
                out.serialize_field("database", &self.database)?;
                match &self.server {
                    Some(server) => out.serialize_field("server", server)?,
                    None => out.skip_field("server")?,
                }
                out.serialize_field("canonical", &self.canonical)?;
                out.serialize_field("written", &self.written)?;
            }
        }
        out.serialize_field("source_span", &self.source_span)?;
        out.end()
    }
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
        let written = Self::compute_written(None, &database, &schema, &name);
        Self {
            name,
            schema,
            database,
            server: None,
            canonical,
            written,
            source_span,
        }
    }

    /// Attach a linked-server component (T-SQL four-part reference) and
    /// recompute `canonical` with the server prefix.
    pub fn with_server(mut self, server: Option<IdentName>) -> Self {
        self.canonical =
            Self::compute_canonical(server.as_ref(), &self.database, &self.schema, &self.name);
        self.written =
            Self::compute_written(server.as_ref(), &self.database, &self.schema, &self.name);
        self.server = server;
        self
    }

    fn compute_written(
        server: Option<&IdentName>,
        database: &Option<IdentName>,
        schema: &Option<IdentName>,
        name: &IdentName,
    ) -> String {
        let base = match (database, schema) {
            (Some(db), Some(sc)) => format!("{}.{}.{}", db.raw, sc.raw, name.raw),
            (None, Some(sc)) => format!("{}.{}", sc.raw, name.raw),
            (Some(db), None) => format!("{}..{}", db.raw, name.raw),
            (None, None) => name.raw.clone(),
        };
        match server {
            Some(srv) => format!("{}.{}", srv.raw, base),
            None => base,
        }
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

impl ObjectKind {
    /// The kind as a reader names it in a sentence: "materialized view",
    /// "dynamic table".
    pub fn noun(self) -> &'static str {
        match self {
            Self::Table => "table",
            Self::View => "view",
            Self::MaterializedView => "materialized view",
            Self::DynamicTable => "dynamic table",
            Self::ExternalTable => "external table",
            Self::Schema => "schema",
            Self::Database => "database",
            Self::Tag => "tag",
            Self::Procedure => "procedure",
            Self::Function => "function",
            Self::Trigger => "trigger",
            Self::Stage => "stage",
            Self::FileFormat => "file format",
            Self::Pipe => "pipe",
            Self::Stream => "stream",
            Self::ApiIntegration => "API integration",
            Self::StorageIntegration => "storage integration",
            Self::ExternalAccessIntegration => "external access integration",
            Self::NotificationIntegration => "notification integration",
            Self::SecurityIntegration => "security integration",
            Self::Warehouse => "warehouse",
            Self::Task => "task",
            Self::Alert => "alert",
            Self::NetworkRule => "network rule",
            Self::ResourceMonitor => "resource monitor",
            Self::Secret => "secret",
            Self::Sequence => "sequence",
            Self::Role => "role",
            Self::User => "user",
            Self::Share => "share",
            Self::Account => "account",
            Self::Session => "session",
            Self::MaskingPolicy => "masking policy",
            Self::RowAccessPolicy => "row access policy",
            Self::NetworkPolicy => "network policy",
            Self::SessionPolicy => "session policy",
            Self::PasswordPolicy => "password policy",
            Self::AggregationPolicy => "aggregation policy",
            Self::ProjectionPolicy => "projection policy",
            Self::JoinPolicy => "join policy",
            Self::DataMetricFunction => "data metric function",
            Self::ReplicationGroup => "replication group",
            Self::AuthenticationPolicy => "authentication policy",
            Self::PgExtension => "extension",
            Self::PgDomain => "domain",
            Self::PgType => "type",
            Self::PgPublication => "publication",
            Self::PgSubscription => "subscription",
            Self::PgRule => "rule",
            Self::BqModel => "model",
            Self::Catalog => "catalog",
            Self::Volume => "volume",
            Self::ExternalLocation => "external location",
            Self::StorageCredential => "storage credential",
            Self::Metastore => "metastore",
            Self::Datashare => "datashare",
            Self::Index => "index",
            Self::Group => "group",
            Self::ExternalSchema => "external schema",
            Self::FailoverGroup => "failover group",
            Self::Synonym => "synonym",
            Self::Generic => "object",
        }
    }
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
