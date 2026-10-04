// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! DDL action facts: action, object kind, target, options, and per-alter change records.

use serde::{Deserialize, Serialize};

#[cfg(feature = "schema")]
use schemars::JsonSchema;

use super::catalog::CatalogTag;
use super::catalog::{TaintLabel, ValueExposure};
use super::expr::Expr;
use super::identity::{IdentName, ObjectKind, ObjectRef, TableRef};
use super::literal::{DataType, LiteralValue};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct DdlFacts {
    pub action: DdlAction,
    pub object_kind: ObjectKind,
    pub target: Option<ObjectRef>,
    pub options: DdlOptions,
    /// The list of changes applied by this ALTER statement. Empty for non-ALTER actions.
    pub alter_changes: Vec<AlterChange>,
    /// Present for CREATE / ALTER STAGE and COPY INTO LOCATION statements.
    /// Contains inline credential options and storage properties.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stage: Option<StageDdlFacts>,
    /// Present for Databricks CREATE / ALTER [STORAGE | SERVICE] CREDENTIAL statements.
    /// Contains the credential provider type and all literal credential values.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storage_credential: Option<StorageCredentialFacts>,
    /// Present for Snowflake CREATE / ALTER / DROP DYNAMIC TABLE statements.
    /// Contains typed properties set at create time and the actions applied by ALTER.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dynamic_table: Option<DynamicTableFacts>,
    /// Present for Snowflake CREATE / ALTER / DROP PIPE statements.
    /// Contains CREATE-time settings (AUTO_INGEST, ERROR_INTEGRATION) and ALTER actions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pipe: Option<PipeFacts>,
    /// Present for Snowflake CREATE / ALTER / DROP TASK statements.
    /// Contains EXECUTE AS mode, overlap policy, body parse status, and ALTER actions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task: Option<TaskFacts>,
    /// Present for Snowflake CREATE / ALTER / DROP DATABASE statements.
    /// Contains the CREATE origin (FROM SHARE, AS REPLICA OF, etc.) and ALTER actions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub database: Option<DatabaseFacts>,
    /// Present for Snowflake CREATE / ALTER / DROP WAREHOUSE statements.
    /// Contains CREATE-time properties (size, Snowpark optimization, AUTO_SUSPEND,
    /// resource monitor, multi-cluster) and ALTER actions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub warehouse: Option<WarehouseFacts>,
    /// Present for Snowflake CREATE / DROP STREAM statements.
    /// Contains CREATE-time properties (APPEND_ONLY, INSERT_ONLY).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream: Option<StreamFacts>,
    /// Present for CREATE / ALTER / DROP SCHEMA statements.
    /// Contains managed access state, data retention settings, and swap operations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema: Option<SchemaFacts>,
    /// Present for CREATE / ALTER FUNCTION statements.
    /// Contains body statement kinds (CREATE) and ALTER actions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub function: Option<FunctionFacts>,
    /// Present for CREATE / ALTER / DROP PROCEDURE statements.
    /// Contains body statement kinds (CREATE) and ALTER actions with per-action sub-facts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub procedure: Option<ProcedureFacts>,
    /// Present for CREATE / ALTER / DROP TABLE, TRUNCATE, and DROP ALL ROW ACCESS
    /// POLICIES statements. Contains CREATE-time properties and ALTER actions
    /// (column changes, policy attachments, tags).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub table: Option<TableFacts>,
    /// Present for Databricks CREATE / ALTER / DROP CATALOG statements.
    /// Contains the CREATE-time `foreign` flag and ALTER actions.
    /// DROP cascade vs restrict is indicated by `ddl.options.cascade`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub catalog: Option<CatalogFacts>,
    /// Present for Databricks table-maintenance statements: VACUUM, OPTIMIZE,
    /// RESTORE, DESCRIBE HISTORY, `[MSCK] REPAIR TABLE`, `CACHE [LAZY] TABLE`,
    /// UNCACHE TABLE. Contains per-operation structural properties.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub table_maintenance: Option<TableMaintenanceFacts>,
    /// Present for Databricks CREATE / ALTER / DROP VOLUME statements.
    /// Contains CREATE-time properties and ALTER actions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub volume: Option<VolumeFacts>,
    /// Present for Databricks CREATE / ALTER / DROP EXTERNAL LOCATION statements.
    /// Contains CREATE-time properties and ALTER actions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_location: Option<ExternalLocationFacts>,
    /// Present for Databricks CREATE / ALTER / DROP CONNECTION statements.
    /// Contains CREATE-time properties and ALTER actions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connection: Option<ConnectionFacts>,
    /// Present for T-SQL / PolyBase CREATE EXTERNAL DATA SOURCE statements.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_data_source: Option<ExternalDataSourceFacts>,
    /// Present for SQL/MED CREATE SERVER … FOREIGN DATA WRAPPER statements.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub foreign_server: Option<ForeignServerFacts>,
    /// Present for SQL/MED CREATE USER MAPPING statements.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_mapping: Option<UserMappingFacts>,
    /// Present for SQL/MED CREATE FOREIGN TABLE statements.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub foreign_table: Option<ForeignTableFacts>,
    /// Present for SQL/MED IMPORT FOREIGN SCHEMA statements.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub import_foreign_schema: Option<ImportForeignSchemaFacts>,
    /// Present for Databricks CREATE FLOW (Lakeflow CDC pipeline) statements.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flow: Option<FlowFacts>,
    /// Present for T-SQL SET option statements.
    /// Contains the option name and value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mssql_set_option: Option<MssqlSetOptionFacts>,
    /// Present for T-SQL CREATE LOGIN and CREATE USER statements.
    /// Contains the principal source clause.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mssql_principal: Option<MssqlPrincipalFacts>,
    /// Present for any `CREATE / ALTER { USER | ROLE | LOGIN }`
    /// statement, in every dialect. Carries the principal kind
    /// discriminator and any typed clauses the parser captured
    /// (`password_literal` for Snowflake `PASSWORD = '<lit>'` / PG
    /// `PASSWORD '<lit>'` / MSSQL `WITH PASSWORD = '<lit>'` / MySQL
    /// `IDENTIFIED BY '<lit>'`). Predicates over these typed fields
    /// drive the dialect-neutral credential-leak detectors.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal: Option<PrincipalFacts>,
    /// Present for PostgreSQL ALTER DOMAIN statements.
    /// Contains the typed list of domain actions. DROP DOMAIN … CASCADE is
    /// indicated by `ddl.options.cascade`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<DomainFacts>,
    /// Present for ALTER INDEX statements. Contains the action type (rename, etc.).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub index: Option<IndexFacts>,
    /// Present for PostgreSQL ALTER TRIGGER statements.
    /// Contains the action type (rename, etc.). DROP TRIGGER … CASCADE is
    /// indicated by `ddl.options.cascade`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trigger: Option<TriggerFacts>,
    /// Present for PostgreSQL ALTER TABLE … ENABLE/DISABLE TRIGGER statements.
    /// Contains the enable or disable action. Distinct from `trigger` (ALTER TRIGGER
    /// rename/extension actions) because the two SQL forms have different action vocabularies.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trigger_state: Option<TriggerStateFacts>,
    /// Present for PostgreSQL SET and RESET session configuration statements.
    /// Contains the session action type.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pg_session: Option<PgSessionFacts>,
    /// Present for BigQuery ASSERT statements.
    /// Contains the optional AS description text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bq_assert: Option<BqAssertFacts>,
    /// Present for BigQuery CREATE MODEL statements.
    /// Contains the optional remote connection identifier and query body filter clauses.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bq_create_model: Option<BqCreateModelFacts>,
    /// Present for BigQuery EXPORT DATA statements.
    /// Contains the query body filter clauses when the AS body is a plain SELECT.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bq_export_data: Option<BqExportDataFacts>,
    /// Present for BigQuery statements with credential-bearing OPTIONS or
    /// WITH CONNECTION clauses (EXPORT DATA, LOAD DATA, CREATE/ALTER/EXPORT MODEL,
    /// BQ-style CREATE EXTERNAL TABLE). Contains typed key-value pairs and all literal values.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bq_options: Option<BqOptionsFacts>,
    /// Present for Amazon Redshift CREATE / ALTER DATASHARE statements.
    /// Carries the cross-account exposure primitives (publicly_accessible,
    /// includenew_set) and the typed list of added/removed objects.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub datashare: Option<DatashareFacts>,
    /// Present for Snowflake CREATE / ALTER / DROP / UNDROP TAG statements.
    /// Carries allowed-value changes, propagation settings, and the
    /// masking policies attached to or detached from the tag.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag: Option<TagFacts>,
    /// Present for Snowflake CREATE / ALTER / DROP FILE FORMAT statements.
    /// Carries the recognized format type (CSV / JSON / PARQUET / …), the
    /// RENAME target, and whether the object is temporary.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_format: Option<FileFormatFacts>,
    /// Present for Snowflake `ALTER SESSION { SET | UNSET }` statements.
    /// Carries the parameters configured or reset for the current session.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<SessionFacts>,
    /// Present for Snowflake CREATE / ALTER / DROP SHARE statements.
    /// Carries the consumer-account changes — the cross-account exposure
    /// primitives. Object grants flow through the privilege facts instead.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub share: Option<ShareFacts>,
    /// Present for Snowflake CREATE / ALTER / DROP SECRET statements.
    /// Carries the secret type, the property names written, and the
    /// API_AUTHENTICATION integration reference. Secret values are
    /// never included.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret: Option<SecretFacts>,
    /// Present for Snowflake CREATE / ALTER / DROP NETWORK RULE
    /// statements. Carries the rule type, traffic mode, and the network
    /// destinations/origins in VALUE_LIST.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_rule: Option<NetworkRuleFacts>,
    /// Present for Snowflake CREATE / ALTER / DROP RESOURCE MONITOR
    /// statements. Carries the credit-usage triggers and notification
    /// targets that govern compute spend on the warehouses it monitors.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_monitor: Option<ResourceMonitorFacts>,
    /// Present for Snowflake CREATE / ALTER / DROP COMPUTE POOL statements.
    /// Carries the instance family, node counts, and auto-resume setting of
    /// the Snowpark Container Services compute capacity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compute_pool: Option<ComputePoolFacts>,
    /// Present for Snowflake CREATE / ALTER / DROP GIT REPOSITORY statements.
    /// Carries the external origin URL, API integration, and whether a git
    /// credentials secret is referenced.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub git_repository: Option<GitRepositoryFacts>,
    /// Present for Snowflake CREATE / ALTER / DROP IMAGE REPOSITORY statements.
    /// An image repository is an OCI registry that Snowpark Container Services
    /// pull container images from; carries only the ALTER action taken (it has
    /// no governance value-slots — OR REPLACE lives in generic `options`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image_repository: Option<ImageRepositoryFacts>,
    /// Present for Snowflake CREATE / ALTER / DROP STREAMLIT statements.
    /// A Streamlit object runs a Python app from a stage; carries whether it
    /// declares EXTERNAL_ACCESS_INTEGRATIONS (network egress) and the ALTER
    /// action taken.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub streamlit: Option<StreamlitFacts>,
    /// Present for Snowflake CREATE / ALTER / DROP SERVICE statements (Snowpark
    /// Container Services). Carries the compute-pool binding, whether the
    /// service declares EXTERNAL_ACCESS_INTEGRATIONS (network egress), and the
    /// ALTER action taken.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service: Option<ServiceFacts>,
    /// Present for Snowflake CREATE / ALTER / DROP NOTEBOOK statements. A
    /// notebook runs code from a stage; carries whether it declares
    /// EXTERNAL_ACCESS_INTEGRATIONS (network egress) and the ALTER action taken.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notebook: Option<NotebookFacts>,
    /// Present for Snowflake CREATE / ALTER / DROP ALERT statements.
    /// Carries the scheduled condition/action clauses and ALTER actions
    /// for an alert — automated SQL run under the owner's role.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alert: Option<AlertFacts>,
    /// Present for Snowflake CREATE / DROP DATA METRIC FUNCTION statements.
    /// A data metric function measures table data; this carries its own
    /// lifecycle (table attachment is on `ddl.table.actions`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data_metric_function: Option<DataMetricFunctionFacts>,
    /// Present for Snowflake CREATE / DROP REPLICATION GROUP and FAILOVER
    /// GROUP statements. Carries the replicated object types and the
    /// ALLOWED_ACCOUNTS cross-account egress targets.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replication_failover_group: Option<ReplicationFailoverGroupFacts>,
    /// Present for `ALTER ACCOUNT SET/UNSET <param>` statements. Carries the
    /// account-level parameter names and values that were changed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account: Option<AccountFacts>,
    /// Present for Snowflake CREATE / ALTER / DROP SEMANTIC VIEW statements. A
    /// semantic view is a named model over base tables consumed by query and BI
    /// surfaces; carries the base-table access surface and which model blocks it
    /// declares.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub semantic_view: Option<SemanticViewFacts>,
    /// Present for Snowflake CREATE / ALTER / DROP CORTEX SEARCH SERVICE
    /// statements. A Cortex search service builds an AI search index over a
    /// source query's rows; carries the embedding model and whether a source
    /// query is declared.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cortex_search_service: Option<CortexSearchServiceFacts>,
    /// Present for Snowflake CREATE / ALTER / DROP APPLICATION statements
    /// (Native Apps). A consumer-installed application running a provider's
    /// code; carries the install source provenance and debug mode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub application: Option<ApplicationFacts>,
    /// Present for Snowflake CREATE / ALTER / DROP APPLICATION PACKAGE
    /// statements (Native Apps). A provider container that bundles an
    /// application for distribution; carries the distribution scope.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub application_package: Option<ApplicationPackageFacts>,
    /// Present for Snowflake CREATE / ALTER / DROP LISTING statements. A listing
    /// exposes a share or application package on the Marketplace or a data
    /// exchange; carries whether it is external (public) and published.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listing: Option<ListingFacts>,
    /// Present for Snowflake CREATE / DROP MANAGED ACCOUNT statements. A reader
    /// account consumes shares from outside the organization; carries the
    /// account type (credential values are never carried).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub managed_account: Option<ManagedAccountFacts>,
    /// Present for `SHOW …` metadata statements. Carries the object
    /// class being listed plus the typed `GRANTS` subkind or `IN` scope.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub show: Option<ShowFacts>,
    /// Present for T-SQL `CREATE SYNONYM name FOR object`. Carries the
    /// referenced base object and its part count — a four-part referent names
    /// a `server.database.schema.object` on a linked/remote server.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub synonym: Option<SynonymFacts>,
    /// Present for T-SQL `ALTER SERVER CONFIGURATION SET …`. Carries the
    /// instance-level configuration subsystem being changed (process affinity,
    /// diagnostics log, buffer-pool extension, HADR / failover cluster, …).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_configuration: Option<ServerConfigurationFacts>,
    /// Present for MySQL `LOAD DATA … INFILE`. Carries the LOCAL modifier
    /// (client-side vs server-side read), the file path, and any cloud scheme.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mysql_load_data: Option<MysqlLoadDataFacts>,
    /// Present for MySQL `CREATE EVENT` / `ALTER EVENT` — a scheduled SQL job.
    /// Carries the schedule kind (one-time vs recurring), the completion-
    /// preserve flag, and the enable state.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event: Option<EventFacts>,
    /// Present for MySQL `CREATE TRIGGER` — an inline-body trigger that runs
    /// automatically on a row event. Carries the timing, the event, the target
    /// table, and the definer (the account the body runs as).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub create_trigger: Option<CreateTriggerFacts>,
    /// Present for MySQL `CREATE VIEW` with a security-context prelude. Carries
    /// the `DEFINER` account and the `SQL SECURITY { DEFINER | INVOKER }` mode
    /// that together decide whose privileges the view's query runs under.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub view: Option<ViewFacts>,
    /// Present for Snowflake `CREATE EXTERNAL FUNCTION`. Carries the egress
    /// endpoint URL and scheme, the API integration, the SECURE flag, and the
    /// request/response translators — a UDF that sends row data to an external
    /// HTTPS service.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_function: Option<ExternalFunctionFacts>,
}

/// Recognition facts for a `SHOW` metadata statement: which object
/// class is enumerated, plus the typed `GRANTS` subkind and `IN` scope
/// when present.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct ShowFacts {
    /// The object class being listed, e.g. `TABLES`, `GRANTS`,
    /// `MASKING_POLICIES`. Uncommon classes carry the upper-cased
    /// object phrase verbatim.
    pub object_class: String,
    /// True for `SHOW TERSE …`.
    #[serde(default, skip_serializing_if = "is_false")]
    pub terse: bool,
    /// True for `SHOW … HISTORY`.
    #[serde(default, skip_serializing_if = "is_false")]
    pub history: bool,
    /// Present for `SHOW [FUTURE] GRANTS …`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grants: Option<ShowGrantsFacts>,
    /// Present when the statement is scoped with `IN <scope>`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<ShowScopeFacts>,
}

/// The privilege relation enumerated by `SHOW [FUTURE] GRANTS …`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct ShowGrantsFacts {
    /// True for `SHOW FUTURE GRANTS …`.
    #[serde(default, skip_serializing_if = "is_false")]
    pub future: bool,
    /// Which side of the grant graph is listed: `CURRENT_USER`, `ON`,
    /// `TO`, `OF`, or `IN`.
    pub relation: String,
    /// True for `SHOW GRANTS ON ACCOUNT`.
    #[serde(default, skip_serializing_if = "is_false")]
    pub on_account: bool,
    /// The kind named after the relation: the object class for `ON`,
    /// the principal kind (`ROLE`, `USER`, `SHARE`, `DATABASE_ROLE`, …)
    /// for `TO` / `OF`, or the container kind for `IN`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_kind: Option<String>,
    /// The target, principal, or container name, normalized for matching
    /// (unquoted names are upper-cased; quoted identifiers keep their case).
    /// Present when the statement named one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// The `IN <scope>` filter applied to a `SHOW` statement.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct ShowScopeFacts {
    /// The scope kind: `ACCOUNT`, `DATABASE`, `SCHEMA`, `TABLE`,
    /// `VIEW`, or another keyword verbatim.
    pub kind: String,
    /// The scope name as written, when the statement named one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// BigQuery ASSERT statement properties. `description` contains the raw text
/// of the AS clause when present, or is absent when no description was written.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct BqAssertFacts {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// BigQuery CREATE MODEL statement properties. `remote_connection` holds
/// the connection identifier when a REMOTE WITH CONNECTION clause is present.
/// `body` contains the filter clauses of the AS SELECT body when applicable.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct BqCreateModelFacts {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_connection: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<BqQueryBodyFacts>,
}

/// `EXECUTE IMMEDIATE FROM <file>` properties — running SQL loaded from a
/// stage file. The location and whether it actually executes are the
/// recognition surface; which stages are trusted, and at what severity, is
/// rule policy.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct ExecuteImmediateFromFacts {
    /// Whether the file location is an absolute stage path (`@…`) or a
    /// relative path resolved against the executing file's stage.
    pub location_kind: EifLocationKind,
    /// The file location: the stage path, or the dequoted relative path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
    /// Whether the statement runs the loaded SQL. `false` only when
    /// `DRY_RUN = TRUE` (the template is rendered but not executed).
    pub executes: bool,
    /// The `DRY_RUN` value when the clause was written.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dry_run: Option<bool>,
    /// `USING` template-variable names supplied to the loaded file.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub using_keys: Vec<String>,
}

/// Whether an [`ExecuteImmediateFromFacts`] location is a stage path or a
/// relative path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum EifLocationKind {
    /// `@[<namespace>.]<stage>/<path>/<file>` absolute stage path.
    StagePath,
    /// Quoted relative path resolved against the executing file's stage.
    RelativePath,
}

/// BigQuery EXPORT DATA statement properties. `body` contains the filter
/// clauses of the AS SELECT body. Absent when the AS body is not a plain SELECT.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct BqExportDataFacts {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<BqQueryBodyFacts>,
}

/// Filtering clauses of a BigQuery SELECT body. Each field is the raw
/// clause text when present, or absent when the clause was not written.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct BqQueryBodyFacts {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub where_clause: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub having_clause: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub qualify_clause: Option<String>,
}

/// Credential-bearing OPTIONS or WITH CONNECTION content from BigQuery DDL statements.
/// Shared across EXPORT DATA, LOAD DATA, CREATE/ALTER/EXPORT MODEL, and
/// BQ-style CREATE EXTERNAL TABLE statements.
///
/// `options` — typed key/value pairs for rules that predicate on specific option names.
/// `all_literal_values` — every string literal from the options span, regardless of
/// which key it belongs to, for content-pattern rules (e.g. matching connection strings
/// or API keys by value).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct BqOptionsFacts {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub options: Vec<BqOptionPair>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub all_literal_values: Vec<BqLiteralValue>,
}

/// A single key/value pair from a BigQuery OPTIONS or WITH CONNECTION clause.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[cfg_attr(feature = "schema", schemars(rename = "BigQueryOption"))]
pub struct BqOptionPair {
    pub key: IdentName,
    /// String literal value with surrounding quotes stripped.
    pub value_literal: String,
}

/// One entry from the `all_literal_values` list. Wraps the literal text
/// in a `value` field so rules can match against it. Also carries a
/// `cloud_scheme` classification when the literal's URI scheme is
/// recognized (`s3://`, `gs://`, `azure://`, etc.).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[cfg_attr(feature = "schema", schemars(rename = "BigQueryLiteralValue"))]
pub struct BqLiteralValue {
    pub value: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cloud_scheme: Option<CloudVendor>,
}

/// Cloud provider classification derived from URI scheme or credential type.
/// Used in `cloud_scheme` fields across credential and options facts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum CloudVendor {
    /// AWS — `s3://` URIs, IAM-role credentials, Cloudflare R2 (S3-compatible).
    Aws,
    /// Google Cloud — `gs://` / `gcs://` URIs, GCP service-account credentials.
    GoogleCloud,
    /// Microsoft Azure — `azure://` URIs, Azure Managed Identity / Service Principal credentials.
    Azure,
}

impl StorageCredentialProviderVariantFacts {
    /// Returns the cloud vendor for this credential provider, or `None` for
    /// providers that don't map to a single vendor (Cloudflare, Unparsed).
    pub fn cloud_vendor(&self) -> Option<CloudVendor> {
        match self {
            Self::AwsIamRole { .. } => Some(CloudVendor::Aws),
            Self::AzureManagedIdentity { .. } | Self::AzureServicePrincipal { .. } => {
                Some(CloudVendor::Azure)
            }
            Self::DatabricksGcpServiceAccount => Some(CloudVendor::GoogleCloud),
            Self::CloudflareApiToken { .. } | Self::Unparsed => None,
        }
    }
}

/// T-SQL SET option statement properties.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct MssqlSetOptionFacts {
    pub option_kind: MssqlSetOptionKind,
    pub value: MssqlSetOptionValue,
    /// For `SET TRANSACTION ISOLATION LEVEL <level>`: the transaction
    /// isolation level requested. `None` for every other SET option.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub isolation_level: Option<MssqlIsolationLevel>,
}

/// The transaction isolation level in `SET TRANSACTION ISOLATION LEVEL <level>`.
/// `read_uncommitted` permits dirty reads; `serializable` is the strictest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum MssqlIsolationLevel {
    /// `READ UNCOMMITTED` — permits dirty reads (reads of uncommitted data).
    ReadUncommitted,
    /// `READ COMMITTED` — the default; reads only committed data.
    ReadCommitted,
    /// `REPEATABLE READ` — holds shared locks to the end of the transaction.
    RepeatableRead,
    /// `SNAPSHOT` — row-versioning isolation.
    Snapshot,
    /// `SERIALIZABLE` — the strictest; full range locking.
    Serializable,
}

/// The SET option name from a T-SQL SET statement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", schemars(rename = "MsSqlSetOptionType"))]
pub enum MssqlSetOptionKind {
    /// `SET IDENTITY_INSERT <table> ON|OFF`.
    IdentityInsert,
    /// `SET NOCOUNT ON|OFF`.
    NoCount,
    /// `SET XACT_ABORT ON|OFF`.
    XactAbort,
    /// `SET ANSI_NULLS ON|OFF`.
    AnsiNulls,
    /// `SET QUOTED_IDENTIFIER ON|OFF`.
    QuotedIdentifier,
    /// `SET ARITHABORT ON|OFF`.
    ArithAbort,
    /// `SET CONCAT_NULL_YIELDS_NULL ON|OFF`.
    ConcatNullYieldsNull,
    /// `SET LOCK_TIMEOUT <ms>`.
    LockTimeout,
    /// `SET DEADLOCK_PRIORITY <value>`.
    DeadlockPriority,
    /// `SET ROWCOUNT <n>`.
    RowCount,
    /// `SET TRANSACTION ISOLATION LEVEL <level>`.
    TransactionIsolationLevel,
    /// Any other SET option not listed above.
    Other,
}

/// The value supplied to a T-SQL SET option.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", schemars(rename = "MsSqlSetOptionValue"))]
pub enum MssqlSetOptionValue {
    /// `ON`.
    On,
    /// `OFF`.
    Off,
    /// Numeric literal (e.g., `LOCK_TIMEOUT 30000`).
    NumericLiteral,
    /// Identifier value (e.g., `DEADLOCK_PRIORITY HIGH`).
    Identifier,
    /// No / unrecognized value.
    Unparsed,
}

/// T-SQL CREATE LOGIN / CREATE USER statement properties.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct MssqlPrincipalFacts {
    pub source: MssqlPrincipalSource,
}

/// Dialect-neutral `CREATE / ALTER { USER | ROLE | LOGIN }` typed
/// properties.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct PrincipalFacts {
    /// Which kind of principal this statement targets.
    pub kind: PrincipalKindFacts,
    /// Inner content of a `PASSWORD = '<lit>'` / `IDENTIFIED BY '<lit>'`
    /// clause (no surrounding quotes). Omitted when no password clause
    /// is present. Masked in the facts copies attached to reports.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password_literal: Option<String>,
    /// MySQL `'user'@'host'` host literal (no surrounding quotes).
    /// Omitted for non-MySQL or unqualified forms.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mysql_host: Option<String>,
    /// SQL Server `SERVER ROLE` (vs database `ROLE`). Always present
    /// so rules can predicate on either value.
    #[serde(default)]
    pub server_scope: bool,
    /// SQL Server `ADD MEMBER <p>` / `DROP MEMBER <p>` membership
    /// clause on `ALTER [SERVER] ROLE`. Omitted when not present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub membership: Option<PrincipalMembershipFacts>,
    /// SQL Server `ENABLE` / `DISABLE` action (`ALTER LOGIN sa
    /// DISABLE`). Omitted when not present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled_state: Option<PrincipalEnabledStateFacts>,
    /// PostgreSQL `CREATE/ALTER ROLE` capability keywords (`SUPERUSER`,
    /// `LOGIN`, `BYPASSRLS`, their `NO…` negations, …), in source order.
    /// Empty for forms that carry none.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub role_attributes: Vec<RoleAttributeFacts>,
    /// Snowflake `CREATE/ALTER USER` governance object-properties
    /// (`DEFAULT_ROLE`, `TYPE`, `MINS_TO_BYPASS_MFA`, …). Omitted when no
    /// recognized Snowflake user property is present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snowflake_user: Option<SnowflakeUserFacts>,
    /// SQL Server `CREATE/ALTER LOGIN` password-policy options
    /// (`CHECK_POLICY`, `CHECK_EXPIRATION`). Omitted when neither
    /// option is present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mssql_login: Option<MssqlLoginFacts>,
}

/// SQL Server `CREATE/ALTER LOGIN` password-policy options, as written
/// in the statement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct MssqlLoginFacts {
    /// `CHECK_POLICY = { ON | OFF }` — whether Windows password policy
    /// (complexity and lockout rules) is enforced for the login.
    /// `false` means the login is exempt from password policy. Absent
    /// when the option is not written or its value is not `ON`/`OFF`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub check_policy: Option<bool>,
    /// `CHECK_EXPIRATION = { ON | OFF }` — whether password expiration
    /// is enforced for the login. `false` means the password never
    /// expires. Absent when the option is not written or its value is
    /// not `ON`/`OFF`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub check_expiration: Option<bool>,
}

/// Snowflake `CREATE/ALTER USER` governance-bearing object properties.
/// Pure recognition of the value *as written*; the danger verdict
/// (which default role is privileged, which `TYPE` is deprecated, what
/// MFA-bypass window is too long) is YAML data, never baked here.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct SnowflakeUserFacts {
    /// `DEFAULT_ROLE = <role>` — the primary role active on login.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_role: Option<IdentName>,
    /// `DEFAULT_SECONDARY_ROLES = ('ALL')` / `()` — secondary-role scope.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_secondary_roles: Option<SecondaryRolesModeFacts>,
    /// `MUST_CHANGE_PASSWORD = { TRUE | FALSE }`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub must_change_password: Option<bool>,
    /// `DISABLED = { TRUE | FALSE }`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disabled: Option<bool>,
    /// `TYPE = { PERSON | SERVICE | LEGACY_SERVICE }` — the user class.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_type: Option<IdentName>,
    /// `MINS_TO_BYPASS_MFA = <n>` — minutes the user may bypass MFA.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mins_to_bypass_mfa: Option<u64>,
    /// `DAYS_TO_EXPIRY = <n>` — days until the user status expires.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub days_to_expiry: Option<u64>,
    /// `MINS_TO_UNLOCK = <n>` — minutes until a temporary lock clears.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mins_to_unlock: Option<u64>,
    /// `RSA_PUBLIC_KEY = '<key>'` present — key-pair authentication
    /// configured. Presence only; the public key value is not captured.
    #[serde(default, skip_serializing_if = "is_false")]
    pub rsa_public_key_set: bool,
    /// `RSA_PUBLIC_KEY_2 = '<key>'` present — second (rotation) key.
    #[serde(default, skip_serializing_if = "is_false")]
    pub rsa_public_key_2_set: bool,
    /// `NETWORK_POLICY = <name>` — the network policy bound to the user.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_policy: Option<IdentName>,
}

/// Snowflake `DEFAULT_SECONDARY_ROLES` scope: `('ALL')` activates every
/// granted role; `()` activates none.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum SecondaryRolesModeFacts {
    All,
    None,
}

/// One recognized PostgreSQL role capability keyword on `CREATE/ALTER
/// ROLE`. `negated` is the `NO…` form (`NOSUPERUSER`, `NOLOGIN`, …).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct RoleAttributeFacts {
    pub kind: RoleAttributeKindFacts,
    #[serde(default)]
    pub negated: bool,
}

/// Which PostgreSQL role capability a [`RoleAttributeFacts`] names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum RoleAttributeKindFacts {
    /// `SUPERUSER` — bypasses all permission checks.
    Superuser,
    /// `CREATEDB` — may create databases.
    CreateDb,
    /// `CREATEROLE` — may create, alter, and drop other roles.
    CreateRole,
    /// `LOGIN` — the role may log in (is a user).
    Login,
    /// `INHERIT` — automatically inherits privileges of granted roles.
    Inherit,
    /// `REPLICATION` — may initiate streaming replication / manage slots.
    Replication,
    /// `BYPASSRLS` — bypasses row-level security policies.
    BypassRls,
}

/// A role-membership change carried on `ALTER [SERVER] ROLE`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct PrincipalMembershipFacts {
    /// Whether the member is added or removed.
    pub action: PrincipalMembershipAction,
    /// The member principal.
    pub member: IdentName,
}

/// Membership-change direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum PrincipalMembershipAction {
    AddMember,
    DropMember,
}

/// `ENABLE` / `DISABLE` action on a login or user.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum PrincipalEnabledStateFacts {
    Enable,
    Disable,
}

/// Dialect-neutral discriminator: USER / ROLE / LOGIN.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum PrincipalKindFacts {
    User,
    Role,
    Login,
    /// Redshift permission `GROUP` — serializes to `group` for YAML
    /// predicates (`ddl.principal.kind: group`).
    Group,
    /// SQL Server `APPLICATION ROLE` — serializes to `application_role`.
    ApplicationRole,
    /// Snowflake `DATABASE ROLE` — serializes to `database_role`. A role
    /// scoped to one database; predicates match `ddl.principal.kind:
    /// database_role`.
    DatabaseRole,
}

/// SQL Server audit-object lifecycle properties (`CREATE / ALTER /
/// DROP { SERVER AUDIT [SPECIFICATION] | DATABASE AUDIT SPECIFICATION }`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct AuditFacts {
    /// Which audit object the statement targets.
    pub scope: AuditScope,
    /// The audit / specification name.
    pub name: IdentName,
    /// `STATE = { ON | OFF }` when spelled in the statement.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<DatabaseSwitchValue>,
}

/// Which audit object an audit DDL statement targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum AuditScope {
    /// `SERVER AUDIT <name>` — the audit destination object.
    ServerAudit,
    /// `SERVER AUDIT SPECIFICATION <name>`.
    ServerAuditSpecification,
    /// `DATABASE AUDIT SPECIFICATION <name>`.
    DatabaseAuditSpecification,
}

/// SQL Server security-object lifecycle properties (`CREATE / ALTER /
/// DROP { MASTER KEY | SYMMETRIC KEY | ASYMMETRIC KEY | CERTIFICATE |
/// [DATABASE SCOPED] CREDENTIAL }`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct SecurityObjectFacts {
    /// Which security object the statement targets.
    pub kind: SecurityObjectKind,
    /// Object name. Omitted for `MASTER KEY` (the database has one).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<IdentName>,
    /// `DATABASE SCOPED CREDENTIAL` (vs server-level `CREDENTIAL`).
    #[serde(default)]
    pub database_scoped: bool,
    /// Inner content of an `ENCRYPTION/DECRYPTION BY PASSWORD = '<lit>'`
    /// clause. Omitted when no password literal is present. Masked in
    /// the facts copies attached to reports.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password_literal: Option<String>,
    /// Inner content of a `SECRET = '<lit>'` clause. Omitted when no
    /// secret literal is present. Masked in the facts copies attached
    /// to reports.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret_literal: Option<String>,
}

/// Which security object a security-object DDL statement targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum SecurityObjectKind {
    /// `MASTER KEY` — the database master key.
    MasterKey,
    /// `SYMMETRIC KEY <name>`.
    SymmetricKey,
    /// `ASYMMETRIC KEY <name>`.
    AsymmetricKey,
    /// `CERTIFICATE <name>`.
    Certificate,
    /// `[DATABASE SCOPED] CREDENTIAL <name>`.
    Credential,
}

/// T-SQL `EXECUTE AS { LOGIN | USER } = '<principal>'` statement
/// properties — an execution-context switch to another principal.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct ImpersonationFacts {
    /// Whether the impersonated principal is a server login or a
    /// database user.
    pub principal_kind: ImpersonationPrincipalKind,
    /// The impersonated principal. For a literal principal this is the
    /// quoted name's inner content; for a variable it is the variable
    /// text (`@p`).
    pub principal: IdentName,
    /// `WITH NO REVERT` present — the context switch cannot be undone
    /// for the rest of the session.
    #[serde(default)]
    pub no_revert: bool,
}

/// Which principal class an `EXECUTE AS` statement impersonates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum ImpersonationPrincipalKind {
    /// `EXECUTE AS LOGIN = …` — server-level context switch.
    Login,
    /// `EXECUTE AS USER = …` — database-level context switch.
    User,
}

/// T-SQL `EXEC[UTE]` statement typed properties. Populated for every
/// `EXEC` (procedure call OR dynamic-SQL form) so consumers can match
/// the called procedure name (e.g., `xp_cmdshell`, `sp_configure`)
/// and its argument text. All fields are lowercased for
/// case-insensitive matching.
///
/// Co-exists with `StatementFacts::dynamic_sql_calls`: the latter
/// captures the dynamic-SQL injection-vector axes (argument shape,
/// parameterization) for `EXEC(@sql)` and `EXEC sp_executesql`; this
/// struct captures the proc-call identity surface needed for
/// "is this calling xp_cmdshell?" matching.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct MssqlExecFacts {
    /// Lowercased base procedure name from the `EXEC <name>` form, with
    /// any database/schema qualifiers and quoting stripped: `EXEC
    /// master.dbo.xp_cmdshell` and `EXEC [xp_cmdshell]` both yield
    /// `xp_cmdshell`. `None` for the bare dynamic-SQL form `EXEC(@sql)`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub procedure_name: Option<String>,
    /// Lowercased text of the argument span (everything after the
    /// procedure name up to the statement end, or the parenthesised
    /// expression for `EXEC(@sql)`). `None` if there are no arguments.
    /// Retained for coarse text matching; structural predicates should
    /// prefer the typed [`Self::args`] list.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub args_text: Option<String>,
    /// Typed projection of the call arguments, in source order. Each
    /// entry carries the (optional) named-parameter name and the shape
    /// of the value, so rules can predicate structurally on "argument
    /// `@rmtpassword` is a string literal" or "argument `@subsystem`
    /// has literal value `cmdexec`" instead of scanning [`Self::args_text`].
    /// Empty for the bare dynamic-SQL form `EXEC(@sql)`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<MssqlExecArgFacts>,
}

/// One argument of an `EXEC <proc> …` call, typed for structural
/// predicate matching. Dialect-neutral recognition: the name and value
/// shape are recorded; which names/values are dangerous is rule policy.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct MssqlExecArgFacts {
    /// Named-parameter name with the leading `@` stripped and lowercased
    /// (`rmtpassword` from `@rmtpassword = …`). `None` for a positional
    /// argument.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Shape of the argument value.
    pub value_kind: MssqlExecArgValueKind,
    /// For a string-literal value, its decoded inner text lowercased
    /// (`cmdexec` from `N'CmdExec'`); `None` for non-string values.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value_literal: Option<String>,
}

/// Shape of an `EXEC` argument value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum MssqlExecArgValueKind {
    /// A string literal (`'x'`, `N'x'`).
    StringLiteral,
    /// A numeric literal.
    Number,
    /// The `NULL` literal.
    Null,
    /// A variable / identifier reference (`@var`, a bare name).
    Variable,
    /// Any other expression (function call, arithmetic, templated string).
    Other,
}

/// How the principal was created — the source clause from CREATE LOGIN or CREATE USER.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", schemars(rename = "MsSqlPrincipalSource"))]
pub enum MssqlPrincipalSource {
    /// `FROM EXTERNAL PROVIDER` — Microsoft Entra ID / Azure AD.
    FromExternalProvider,
    /// `WITH PASSWORD = '...'`.
    WithPassword,
    /// `FROM CERTIFICATE name`.
    FromCertificate,
    /// `FROM ASYMMETRIC KEY name`.
    FromAsymmetricKey,
    /// `FROM WINDOWS [WITH ...]`.
    FromWindows,
    /// `FOR LOGIN name` (CREATE USER).
    ForLogin,
    /// `WITHOUT LOGIN` (CREATE USER).
    WithoutLogin,
    /// No source clause present or unrecognized form.
    Unparsed,
}

/// Databricks CREATE / ALTER [STORAGE | SERVICE] CREDENTIAL statement properties.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct StorageCredentialFacts {
    pub action: StorageCredentialChangeKind,
    pub credential_kind: StorageCredentialKindFacts,
    pub if_not_exists: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<StorageCredentialProviderFacts>,
    /// ALTER actions in source order. Empty for CREATE.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub actions: Vec<StorageCredentialAlterAction>,
    /// `CREATE STORAGE CREDENTIAL ... COMMENT '<text>'` — unquoted
    /// literal text. Omitted when no COMMENT clause is present (and on
    /// ALTER/DROP, which don't carry a COMMENT clause). Surfaced so
    /// downstream rules can flag URLs with embedded credentials placed
    /// in the metadata comment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

/// Actions an `ALTER STORAGE CREDENTIAL` statement can apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum StorageCredentialAlterAction {
    /// `ALTER … CREDENTIAL <name> RENAME TO <new_name>`.
    RenameTo,
    /// `ALTER … CREDENTIAL <name> OWNER TO <principal>`.
    OwnerTo,
    /// `ALTER … CREDENTIAL <name> <provider-clause>`.
    SetProvider,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", schemars(rename = "StorageCredentialChangeType"))]
pub enum StorageCredentialChangeKind {
    Create,
    Alter,
    Drop,
}

/// `STORAGE CREDENTIAL` vs `SERVICE CREDENTIAL` vs bare `CREDENTIAL`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", schemars(rename = "StorageCredentialKind"))]
pub enum StorageCredentialKindFacts {
    Storage,
    Service,
    Bare,
}

/// The credential provider for a Databricks Unity Catalog storage or
/// service credential. `variant` carries per-provider fields;
/// `all_literal_values` carries every string literal from the provider
/// clause (in source order) for content-pattern matching that doesn't
/// depend on which field holds the value.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct StorageCredentialProviderFacts {
    pub variant: StorageCredentialProviderVariantFacts,
    pub all_literal_values: Vec<StorageCredentialLiteral>,
}

/// One literal value from a credential provider clause.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct StorageCredentialLiteral {
    /// Literal from a storage-credential statement body — credential
    /// material by nature; masked in the facts copies attached to
    /// reports.
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum StorageCredentialProviderVariantFacts {
    AwsIamRole {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        role_arn: Option<String>,
    },
    AzureManagedIdentity {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        managed_identity_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        access_connector_id: Option<String>,
    },
    AzureServicePrincipal {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        directory_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        application_id: Option<String>,
        // Masked in the facts copies attached to reports.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        client_secret: Option<String>,
    },
    DatabricksGcpServiceAccount,
    CloudflareApiToken {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        account_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        access_key_id: Option<String>,
        // Masked in the facts copies attached to reports.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        secret_access_key: Option<String>,
    },
    /// Provider keyword recognized but body could not be typed.
    /// Predicates can still match against `all_literal_values` when
    /// the parser captured literals.
    Unparsed,
}

/// One `NAME = VALUE` copy option from a COPY INTO statement
/// (e.g. `ON_ERROR = CONTINUE`, `PURGE = TRUE`). Recognition only —
/// which option/value is risky is decided by YAML rules.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct CopyOption {
    /// Option name (e.g. `ON_ERROR`). Match with `key.normalized`.
    pub key: IdentName,
    /// Scalar value with surrounding quotes stripped (e.g. `CONTINUE`,
    /// `TRUE`, `100`). Absent when the value is a parenthesized block such
    /// as `FILE_FORMAT = (...)`. Match with `value.normalized`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<IdentName>,
}

/// A column unloaded by `COPY INTO <location>`, with the classification
/// tags it carries and how its value is exposed. Used to flag classified
/// data leaving the warehouse.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct ExportedColumn {
    /// The column's output name.
    pub name: String,
    /// Classification tags the column carries (PII, PHI, …). Empty when the
    /// column is unclassified.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub taint_labels: Vec<TaintLabel>,
    /// How the column's value is exposed at the egress point — `value`
    /// (raw), `digest` (hashed), `cardinality`, or `derived`.
    #[serde(default)]
    pub value_exposure: ValueExposure,
}

/// CREATE / ALTER STAGE and COPY INTO LOCATION statement properties.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct StageDdlFacts {
    /// Credential options from `CREDENTIALS=(...)`. Empty when the clause is absent
    /// or specifies `STORAGE_INTEGRATION` instead.
    pub credentials: Vec<StageCredentialOption>,
    /// URL literal content (quotes stripped) from `URL='…'` (CREATE)
    /// or `SET URL='…'` (ALTER). Omitted when the URL clause / SET
    /// URL action is absent or the value is not a string literal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url_literal: Option<String>,
    /// True when the statement sets `ENCRYPTION = (TYPE = 'NONE')`.
    #[serde(default, skip_serializing_if = "is_false")]
    pub encryption_disabled: bool,
    /// True when the statement enables encryption with a non-`NONE` type.
    #[serde(default, skip_serializing_if = "is_false")]
    pub encryption_enabled: bool,
    /// True when an `ALTER STAGE … SET TAG …` action is present.
    #[serde(default, skip_serializing_if = "is_false")]
    pub set_tag: bool,
    /// True when an `ALTER STAGE … UNSET TAG …` action is present.
    #[serde(default, skip_serializing_if = "is_false")]
    pub unset_tag: bool,
    /// True when an `ALTER STAGE … SET STORAGE_INTEGRATION = …` action is present.
    #[serde(default, skip_serializing_if = "is_false")]
    pub set_storage_integration: bool,
    /// True for `COPY INTO <location> FROM <source>` whose source has no WHERE clause.
    /// Always `false` for CREATE / ALTER / DROP STAGE.
    #[serde(default, skip_serializing_if = "is_false")]
    pub unbounded_export: bool,
    /// True when the statement contains at least one clause the parser did not recognize.
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_unknown_clauses: bool,
    /// `NAME = VALUE` copy options (`ON_ERROR`, `PURGE`, `FORCE`, …) from a
    /// COPY INTO statement (either direction). Empty when none are present.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub copy_options: Vec<CopyOption>,
    /// For `COPY INTO <location>` (unload), the columns the source projects
    /// out of the warehouse, each with its classification and value exposure.
    /// Lets a rule flag classified data leaving the warehouse. Empty for
    /// loads and for CREATE / ALTER / DROP STAGE.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exported_columns: Vec<ExportedColumn>,
}

fn is_false(b: &bool) -> bool {
    !*b
}

/// Snowflake CREATE / ALTER / DROP DYNAMIC TABLE statement properties.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct DynamicTableFacts {
    /// `CREATE DYNAMIC TABLE … AS <query>` whose query body could not be parsed.
    #[serde(default, skip_serializing_if = "is_false")]
    pub query_unparseable: bool,
    /// `ALTER DYNAMIC TABLE … SUSPEND` (or SUSPEND RECLUSTER).
    #[serde(default, skip_serializing_if = "is_false")]
    pub suspended: bool,
    /// `ALTER DYNAMIC TABLE … RESUME` (or RESUME RECLUSTER).
    #[serde(default, skip_serializing_if = "is_false")]
    pub resumed: bool,
    /// `ALTER DYNAMIC TABLE … RENAME TO …`.
    #[serde(default, skip_serializing_if = "is_false")]
    pub renamed: bool,
    /// `ALTER DYNAMIC TABLE … SWAP WITH …`.
    #[serde(default, skip_serializing_if = "is_false")]
    pub swapped: bool,
    /// Any `SET TAG …` or column-level `SET TAG …` action present.
    #[serde(default, skip_serializing_if = "is_false")]
    pub tag_set: bool,
    /// Any `UNSET TAG …` or column-level `UNSET TAG …` action present.
    #[serde(default, skip_serializing_if = "is_false")]
    pub tag_unset: bool,
    /// `ADD ROW ACCESS POLICY …` action present.
    #[serde(default, skip_serializing_if = "is_false")]
    pub row_access_policy_added: bool,
    /// `DROP ROW ACCESS POLICY …` or `DROP ALL ROW ACCESS POLICIES`
    /// action present.
    #[serde(default, skip_serializing_if = "is_false")]
    pub row_access_policy_removed: bool,
    /// Column-level `SET MASKING POLICY …` action present.
    #[serde(default, skip_serializing_if = "is_false")]
    pub masking_policy_added: bool,
    /// Column-level `UNSET MASKING POLICY` action present.
    #[serde(default, skip_serializing_if = "is_false")]
    pub masking_policy_removed: bool,
}

/// Snowflake CREATE / ALTER / DROP PIPE statement properties.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct PipeFacts {
    /// `CREATE PIPE … AUTO_INGEST = TRUE`.
    #[serde(default, skip_serializing_if = "is_false")]
    pub auto_ingest_enabled: bool,
    /// `CREATE PIPE … ERROR_INTEGRATION = …` clause present (any
    /// value).
    #[serde(default, skip_serializing_if = "is_false")]
    pub error_integration_set: bool,
    /// `ALTER PIPE … SET <properties>` action present.
    #[serde(default, skip_serializing_if = "is_false")]
    pub set: bool,
    /// `ALTER PIPE … SET TAG …` action present.
    #[serde(default, skip_serializing_if = "is_false")]
    pub tag_set: bool,
    /// `ALTER PIPE … UNSET TAG …` action present.
    #[serde(default, skip_serializing_if = "is_false")]
    pub tag_unset: bool,
    /// `ALTER PIPE … REFRESH …` action present.
    #[serde(default, skip_serializing_if = "is_false")]
    pub refreshed: bool,
}

/// Snowflake CREATE / ALTER / DROP NETWORK RULE statement properties.
/// VALUE_LIST entries are the network destinations (EGRESS) or origins
/// (INGRESS) that network policies and external-access integrations
/// reference by rule name — editing a rule changes network posture
/// without touching any policy.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct NetworkRuleFacts {
    /// `TYPE = <value>` (upper-cased): `IPV4`, `IPV6`, `AWSVPCEID`,
    /// `AZURELINKID`, `GCPPSCID`, `HOST_PORT`, `PRIVATE_HOST_PORT`,
    /// `COMPUTE_POOL`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule_type: Option<String>,
    /// `MODE = <value>` (upper-cased): `INGRESS`, `INTERNAL_STAGE`,
    /// `SNOWFLAKE_MANAGED_STORAGE_VOLUME`, `EGRESS`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    /// VALUE_LIST entries (unquoted), e.g. host:port pairs or CIDRs.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub value_list: Vec<String>,
    /// VALUE_LIST entries with IPv4/CIDR recognition applied (CIDR prefix,
    /// private-range, all-addresses `is_zero_route`). Meaningful for
    /// `TYPE = IPV4` rules; host/port and other types yield no IP fields.
    /// Match `is_zero_route` to detect an allow-all (`0.0.0.0/0`) rule.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub value_entries: Vec<crate::facts::policy::IpListEntry>,
    /// A VALUE_LIST assignment was present (CREATE or ALTER … SET) —
    /// on ALTER this replaces the rule's destination/origin set.
    #[serde(default, skip_serializing_if = "is_false")]
    pub value_list_set: bool,
    /// Other property names written by `ALTER … SET` (upper-cased).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub properties_set: Vec<String>,
    /// Property names removed by `ALTER … UNSET` (upper-cased).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub properties_unset: Vec<String>,
}

/// A single resource-monitor credit-usage trigger. `SUSPEND` /
/// `SUSPEND_IMMEDIATE` actions halt compute when usage crosses the
/// threshold; `NOTIFY` only alerts.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct ResourceMonitorTriggerFacts {
    /// The credit-usage percentage threshold (digits as written).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub threshold: Option<String>,
    /// The action taken at the threshold (upper-cased): `SUSPEND`,
    /// `SUSPEND_IMMEDIATE`, or `NOTIFY`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub action: String,
}

/// Snowflake CREATE / ALTER / DROP COMPUTE POOL statement properties.
/// A compute pool is the capacity that Snowpark Container Services jobs and
/// services run on; its instance family (CPU vs GPU), node counts, and
/// auto-resume setting determine cost and what workloads it can run.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct ComputePoolFacts {
    /// `INSTANCE_FAMILY` value (e.g. `CPU_X64_S`, `GPU_NV_S`). Populated on
    /// CREATE and `ALTER … SET`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instance_family: Option<String>,
    /// `AUTO_RESUME = {TRUE|FALSE}` when specified.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auto_resume: Option<bool>,
    /// `MIN_NODES` value as written.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_nodes: Option<String>,
    /// `MAX_NODES` value as written.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_nodes: Option<String>,
    /// `ALTER COMPUTE POOL` actions in source order. Empty on CREATE / DROP.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub actions: Vec<ComputePoolAlterAction>,
}

/// An action applied by an ALTER COMPUTE POOL statement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ComputePoolAlterAction {
    /// `SET <props>`.
    Set,
    /// `UNSET <props>`.
    Unset,
    /// `SUSPEND`.
    Suspend,
    /// `RESUME` — starts compute (resumes billing).
    Resume,
    /// `STOP ALL` — stops every service and job running on the pool.
    StopAll,
}

/// Snowflake CREATE / ALTER / DROP GIT REPOSITORY statement properties.
/// A git repository object connects Snowflake to an external git remote;
/// code from it can be run via `EXECUTE IMMEDIATE FROM`.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct GitRepositoryFacts {
    /// `API_INTEGRATION` value — the integration the repo connects through.
    /// Populated on CREATE and `ALTER … SET`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_integration: Option<String>,
    /// `ORIGIN` URL of the external git remote (CREATE only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<String>,
    /// True when `GIT_CREDENTIALS` references a secret.
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_git_credentials: bool,
    /// `ALTER GIT REPOSITORY` actions in source order. Empty on CREATE / DROP.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub actions: Vec<GitRepositoryAlterAction>,
}

/// An action applied by an ALTER GIT REPOSITORY statement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum GitRepositoryAlterAction {
    /// `SET <props>`.
    Set,
    /// `UNSET <props>`.
    Unset,
    /// `FETCH` — re-pulls the latest content from the external origin.
    Fetch,
}

/// Snowflake `CREATE EXTERNAL FUNCTION` properties — a UDF that ships row data
/// to an external HTTPS endpoint via an API integration. The endpoint and
/// integration are the recognition surface; which endpoints are trusted, and
/// at what severity, is rule policy.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct ExternalFunctionFacts {
    /// `API_INTEGRATION` value — the integration that authorizes the call.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_integration: Option<String>,
    /// The `AS '<url>'` endpoint (the proxy/resource the data is sent to),
    /// dequoted. The egress target.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint_url: Option<String>,
    /// The URL scheme of the endpoint, lower-cased (`https`, `http`, …) — the
    /// transport-security recognition primitive for the egress target.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint_scheme: Option<String>,
    /// True when the function is declared `SECURE` (its definition is hidden
    /// from users without ownership).
    #[serde(default, skip_serializing_if = "is_false")]
    pub secure: bool,
    /// True when a `HEADERS = ( … )` clause sends custom request headers.
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_headers: bool,
    /// True when a `CONTEXT_HEADERS = ( … )` clause is present.
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_context_headers: bool,
    /// `REQUEST_TRANSLATOR` UDF name when present (transforms the outbound payload).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_translator: Option<String>,
    /// `RESPONSE_TRANSLATOR` UDF name when present (transforms the inbound payload).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_translator: Option<String>,
}

/// Snowflake CREATE / ALTER / DROP IMAGE REPOSITORY statement properties.
/// An image repository is an OCI registry that Snowpark Container Services
/// pull container images from. It has no governance value-slots (only
/// COMMENT / TAG); OR REPLACE is carried in generic `options`, so this struct
/// records only the ALTER action taken.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct ImageRepositoryFacts {
    /// `ALTER IMAGE REPOSITORY` actions in source order. Empty on CREATE / DROP.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub actions: Vec<ImageRepositoryAlterAction>,
}

/// An action applied by an ALTER IMAGE REPOSITORY statement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ImageRepositoryAlterAction {
    /// `SET <props>`.
    Set,
    /// `UNSET <props>`.
    Unset,
}

/// Snowflake CREATE / ALTER / DROP STREAMLIT statement properties.
/// A Streamlit object runs a Python app hosted from a stage location.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct StreamlitFacts {
    /// True when the app declares `EXTERNAL_ACCESS_INTEGRATIONS` — it can reach
    /// external network endpoints. Populated on CREATE and `ALTER … SET`.
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_external_access_integrations: bool,
    /// `ALTER STREAMLIT` actions in source order. Empty on CREATE / DROP.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub actions: Vec<StreamlitAlterAction>,
}

/// An action applied by an ALTER STREAMLIT statement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum StreamlitAlterAction {
    /// `SET <props>`.
    Set,
    /// `UNSET <props>`.
    Unset,
}

/// Snowflake CREATE / ALTER / DROP SERVICE statement properties (Snowpark
/// Container Services). A service runs container workloads on a compute pool.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct ServiceFacts {
    /// `IN COMPUTE POOL <pool>` binding (as written) when present — the
    /// capacity the service runs on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub in_compute_pool: Option<String>,
    /// True when the service declares `EXTERNAL_ACCESS_INTEGRATIONS` — it can
    /// reach external network endpoints. Populated on CREATE and `ALTER … SET`.
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_external_access_integrations: bool,
    /// `ALTER SERVICE` actions in source order. Empty on CREATE / DROP.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub actions: Vec<ServiceAlterAction>,
}

/// An action applied by an ALTER SERVICE statement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ServiceAlterAction {
    /// `SET <props>`.
    Set,
    /// `UNSET <props>`.
    Unset,
    /// `RESUME` — starts the service (resumes billing).
    Resume,
    /// `SUSPEND` — stops the service.
    Suspend,
}

/// Snowflake CREATE / ALTER / DROP NOTEBOOK statement properties. A notebook
/// runs code hosted from a stage location.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct NotebookFacts {
    /// True when the notebook declares `EXTERNAL_ACCESS_INTEGRATIONS` — it can
    /// reach external network endpoints. Populated on CREATE and `ALTER … SET`.
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_external_access_integrations: bool,
    /// `ALTER NOTEBOOK` actions in source order. Empty on CREATE / DROP.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub actions: Vec<NotebookAlterAction>,
}

/// An action applied by an ALTER NOTEBOOK statement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum NotebookAlterAction {
    /// `SET <props>`.
    Set,
    /// `UNSET <props>`.
    Unset,
}

/// Snowflake CREATE / ALTER / DROP SEMANTIC VIEW statement properties. A
/// semantic view is a named model over base tables (logical tables, relationships,
/// facts, dimensions, metrics) that query and BI surfaces consume.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct SemanticViewFacts {
    /// Base (physical) tables the model is built over — the data it exposes to
    /// query and BI surfaces. Empty on ALTER / DROP.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub base_tables: Vec<TableRef>,
    /// The model declares a RELATIONSHIPS block (joins between its tables).
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_relationships: bool,
    /// The model declares a FACTS block (row-level measures).
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_facts: bool,
    /// The model declares a DIMENSIONS block (grouping attributes).
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_dimensions: bool,
    /// The model declares a METRICS block (aggregations).
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_metrics: bool,
    /// `ALTER SEMANTIC VIEW` actions in source order. Empty on CREATE / DROP.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub actions: Vec<SemanticViewAlterAction>,
}

/// An action applied by an ALTER SEMANTIC VIEW statement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SemanticViewAlterAction {
    /// `SET <props>`.
    Set,
    /// `UNSET <props>`.
    Unset,
    /// `RENAME TO <name>`.
    Rename,
}

/// Snowflake CREATE / ALTER / DROP CORTEX SEARCH SERVICE statement properties.
/// A Cortex search service builds an AI-powered (embedding-backed) search index
/// over the rows produced by a source query.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct CortexSearchServiceFacts {
    /// The embedding model used to vectorize the indexed data, as written
    /// (e.g. `snowflake-arctic-embed-m`). Present when `EMBEDDING_MODEL` is
    /// declared on CREATE or `ALTER … SET`. Which models are acceptable is policy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub embedding_model: Option<String>,
    /// The service indexes the rows of a source query (`AS <query>`) — the data
    /// exposed to the search surface. Set on CREATE.
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_source_query: bool,
    /// `ALTER CORTEX SEARCH SERVICE` actions in source order. Empty on
    /// CREATE / DROP.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub actions: Vec<CortexSearchServiceAlterAction>,
}

/// An action applied by an ALTER CORTEX SEARCH SERVICE statement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CortexSearchServiceAlterAction {
    /// `SET <props>`.
    Set,
    /// `UNSET <props>`.
    Unset,
    /// `RESUME` — resumes the refresh schedule.
    Resume,
    /// `SUSPEND` — suspends the refresh schedule.
    Suspend,
}

/// Snowflake CREATE / ALTER / DROP APPLICATION statement properties (Native
/// Apps — a consumer-installed application that runs a provider's code in the
/// account).
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct ApplicationFacts {
    /// The application was installed `FROM LISTING` — its code comes from an
    /// external marketplace listing rather than an in-account application
    /// package.
    #[serde(default, skip_serializing_if = "is_false")]
    pub from_listing: bool,
    /// The source application package / listing name the app was installed from
    /// (the supply-chain provenance), as written.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_name: Option<String>,
    /// `DEBUG_MODE` value when declared (CREATE or `ALTER … SET`). Debug mode
    /// lets the provider inspect the application's internals.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub debug_mode: Option<bool>,
    /// `ALTER APPLICATION` actions in source order. Empty on CREATE / DROP.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub actions: Vec<ApplicationAlterAction>,
}

/// Snowflake CREATE / ALTER / DROP APPLICATION PACKAGE statement properties
/// (Native Apps — a provider container that bundles an application for
/// distribution).
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct ApplicationPackageFacts {
    /// `DISTRIBUTION` value (upper-cased): `INTERNAL` keeps the package inside
    /// the org; `EXTERNAL` lets it be published to other accounts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub distribution: Option<String>,
    /// `ALTER APPLICATION PACKAGE` actions in source order. Empty on
    /// CREATE / DROP.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub actions: Vec<ApplicationAlterAction>,
}

/// An action applied by an ALTER APPLICATION / ALTER APPLICATION PACKAGE
/// statement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ApplicationAlterAction {
    /// `SET <props>`.
    Set,
    /// `UNSET <props>`.
    Unset,
    /// Any other recognized alter form (UPGRADE, ADD VERSION, …).
    Other,
}

/// Snowflake CREATE / ALTER / DROP LISTING statement properties. A listing
/// exposes a share or application package on the Snowflake Marketplace or a
/// private data exchange.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct ListingFacts {
    /// `EXTERNAL` — the listing is published to the public Snowflake
    /// Marketplace, exposing its data/app outside the organization (vs an
    /// internal data-exchange listing).
    #[serde(default, skip_serializing_if = "is_false")]
    pub is_external: bool,
    /// `PUBLISH` value when declared (CREATE or `ALTER … SET`). A published
    /// listing is live and consumable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub publish: Option<bool>,
    /// The shared object the listing exposes (`SHARE <share>` /
    /// `APPLICATION PACKAGE <pkg>`), as written.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shared_object: Option<String>,
    /// `ALTER LISTING` actions in source order. Empty on CREATE / DROP.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub actions: Vec<ListingAlterAction>,
}

/// An action applied by an ALTER LISTING statement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ListingAlterAction {
    /// `SET <props>`.
    Set,
    /// `UNSET <props>`.
    Unset,
    /// Any other recognized alter form (PUBLISH, UNPUBLISH, ADD VERSION, …).
    Other,
}

/// Snowflake CREATE / DROP MANAGED ACCOUNT statement properties. A managed
/// (reader) account consumes shares without being a Snowflake customer — a
/// data-sharing-to-outsiders surface. Credential values are never carried.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct ManagedAccountFacts {
    /// `TYPE` value (upper-cased) — normally `READER`. The recognition value;
    /// the account's admin credentials are never carried.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_type: Option<String>,
}

/// Snowflake CREATE / ALTER / DROP RESOURCE MONITOR statement properties.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct ResourceMonitorFacts {
    /// A `CREDIT_QUOTA` value was supplied (CREATE or ALTER … SET).
    #[serde(default, skip_serializing_if = "is_false")]
    pub credit_quota_set: bool,
    /// `FREQUENCY = <value>` (upper-cased): `MONTHLY`, `DAILY`, `WEEKLY`,
    /// `YEARLY`, `NEVER`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub frequency: Option<String>,
    /// `NOTIFY_USERS` entries (unquoted) that receive usage alerts.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notify_users: Vec<String>,
    /// The credit-usage triggers in declaration order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub triggers: Vec<ResourceMonitorTriggerFacts>,
    /// A `TRIGGERS` clause was supplied (CREATE or ALTER … SET).
    #[serde(default, skip_serializing_if = "is_false")]
    pub triggers_changed: bool,
    /// True when the monitor is created with no trigger that halts
    /// compute (`SUSPEND` / `SUSPEND_IMMEDIATE`) — it can alert on usage
    /// but enforces no automatic suspension.
    #[serde(default, skip_serializing_if = "is_false")]
    pub no_suspend_trigger: bool,
}

/// Snowflake CREATE / ALTER / DROP SECRET statement properties.
/// Secret VALUES (passwords, tokens, secret strings) are never copied
/// into facts — only property names and non-credential references.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct SecretFacts {
    /// `TYPE = <value>` (upper-cased): `OAUTH2`, `PASSWORD`,
    /// `GENERIC_STRING`, `SYMMETRIC_KEY`, `CLOUD_PROVIDER_TOKEN`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret_type: Option<String>,
    /// `API_AUTHENTICATION = <integration>` — the referenced security
    /// integration name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_authentication: Option<String>,
    /// `ENABLED = TRUE | FALSE` when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    /// Property names written by CREATE or `ALTER … SET` (upper-cased,
    /// e.g. `PASSWORD`, `OAUTH_REFRESH_TOKEN`). Values are omitted.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub properties_set: Vec<String>,
    /// Property names removed by `ALTER … UNSET` (upper-cased).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub properties_unset: Vec<String>,
}

/// Snowflake CREATE / ALTER / DROP SHARE statement properties. The
/// consumer-account lists are the cross-account exposure surface:
/// adding an account makes everything granted to the share readable
/// from that account.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct ShareFacts {
    /// Consumer accounts added by `ALTER SHARE … ADD ACCOUNTS`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub accounts_added: Vec<String>,
    /// Consumer accounts removed by `ALTER SHARE … REMOVE ACCOUNTS`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub accounts_removed: Vec<String>,
    /// Consumer list replaced wholesale by `ALTER SHARE … SET ACCOUNTS`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub accounts_set: Vec<String>,
    /// Generic `SET <property> = <value>` action present.
    #[serde(default, skip_serializing_if = "is_false")]
    pub had_set_properties: bool,
    /// Generic `UNSET <property>` action present.
    #[serde(default, skip_serializing_if = "is_false")]
    pub had_unset_properties: bool,
    /// An unrecognized ALTER action body was encountered.
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_unknown_clauses: bool,
}

/// T-SQL `CREATE SYNONYM name FOR object` properties. A synonym is a named
/// alias for a base object; the referenced object can be a four-part
/// `server.database.schema.object` name that resolves on a linked or remote
/// server, exposing data that lives outside the local database.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct SynonymFacts {
    /// The referenced base object, as written.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub referent: Option<String>,
    /// True when the referent is a four-part name and therefore names an object
    /// on a linked or remote server rather than the local database.
    #[serde(default, skip_serializing_if = "is_false")]
    pub referent_server_qualified: bool,
}

/// Snowflake CREATE / ALTER TAG statement properties. DROP TAG and
/// UNDROP TAG carry only `ddl.action` / `ddl.object_kind`.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct TagFacts {
    /// Values supplied to ALLOWED_VALUES by CREATE TAG or by
    /// `ALTER TAG … {SET | ADD} ALLOWED_VALUES`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_values: Vec<String>,
    /// Values removed by `ALTER TAG … DROP ALLOWED_VALUES`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_values_removed: Vec<String>,
    /// `ALTER TAG … UNSET ALLOWED_VALUES` — the value constraint is
    /// removed entirely; any string value becomes assignable.
    #[serde(default, skip_serializing_if = "is_false")]
    pub allowed_values_unset: bool,
    /// PROPAGATE mode when set (upper-cased), e.g. `ON_DEPENDENCY`,
    /// `ON_DATA_MOVEMENT`, `ON_DEPENDENCY_AND_DATA_MOVEMENT`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub propagate: Option<String>,
    /// `ALTER TAG … UNSET PROPAGATE`.
    #[serde(default, skip_serializing_if = "is_false")]
    pub propagate_unset: bool,
    /// Masking policies attached by `ALTER TAG … SET MASKING POLICY`.
    /// Every column carrying this tag is masked by these policies.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub masking_policies_set: Vec<ObjectRef>,
    /// Masking policies detached by `ALTER TAG … UNSET MASKING POLICY`.
    /// Every column carrying this tag loses the listed protections.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub masking_policies_unset: Vec<ObjectRef>,
    /// FORCE present on SET MASKING POLICY — replaces a policy of the
    /// same data type already attached to the tag.
    #[serde(default, skip_serializing_if = "is_false")]
    pub masking_policy_force: bool,
    /// `ALTER TAG … RENAME TO` target.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub renamed_to: Option<ObjectRef>,
}

/// Snowflake CREATE / ALTER / DROP FILE FORMAT — a named, reusable
/// definition of how staged data files are parsed on load and written on
/// unload. Replacing or dropping one changes ingestion behavior for every
/// COPY and external table that references it.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct FileFormatFacts {
    /// The declared format type, upper-cased (CSV / JSON / AVRO / ORC /
    /// PARQUET / XML / …), when a `TYPE = <t>` clause is present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format_type: Option<String>,
    /// `ALTER FILE FORMAT … RENAME TO` target.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub renamed_to: Option<ObjectRef>,
    /// The object is TEMP / TEMPORARY / VOLATILE — it exists only for the
    /// session and is not visible to other sessions or pipelines.
    #[serde(default, skip_serializing_if = "is_false")]
    pub temporary: bool,
}

/// Snowflake `ALTER SESSION { SET | UNSET }` — session-parameter mutation.
/// Carries the parameters configured or reset for the current session.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct SessionFacts {
    /// Parameters assigned by `ALTER SESSION SET <param> = <value> [, …]`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub set_params: Vec<SessionParam>,
    /// Parameter names reset to their defaults by
    /// `ALTER SESSION UNSET <param> [, …]` (upper-cased).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unset_params: Vec<String>,
}

/// One `<param> = <value>` assignment in `ALTER SESSION SET`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct SessionParam {
    /// Parameter name (upper-cased).
    pub name: String,
    /// The assigned value as written, with surrounding single quotes
    /// stripped for string values.
    pub value: String,
    /// Whether the value is a string, number, or boolean.
    pub value_kind: SessionValueKind,
}

/// The kind of a value assigned in `ALTER SESSION SET`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum SessionValueKind {
    String,
    Number,
    Boolean,
    /// Any other value form (bare identifier, NULL, etc.).
    Other,
}

/// CREATE / ALTER / DROP SCHEMA statement properties.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct SchemaFacts {
    /// True when the statement enables managed access —
    /// `CREATE SCHEMA … WITH MANAGED ACCESS` or `ALTER SCHEMA … ENABLE MANAGED ACCESS`.
    #[serde(default, skip_serializing_if = "is_false")]
    pub managed_access_enabled: bool,
    /// True for `ALTER SCHEMA … DISABLE MANAGED ACCESS`.
    #[serde(default, skip_serializing_if = "is_false")]
    pub managed_access_disabled: bool,
    /// True for `ALTER SCHEMA … SET PROPERTIES (…)` whose properties include
    /// `DATA_RETENTION_TIME_IN_DAYS`.
    #[serde(default, skip_serializing_if = "is_false")]
    pub retention_changed: bool,
    /// The `DATA_RETENTION_TIME_IN_DAYS = <n>` value set on the schema.
    /// Absent when the clause is omitted or its value is not a plain
    /// integer. A value of `0` disables Time Travel for every object in
    /// the schema that uses the schema default, so dropped or modified
    /// data cannot be recovered.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data_retention_days: Option<i64>,
    /// True for `ALTER SCHEMA … SWAP WITH …`.
    #[serde(default, skip_serializing_if = "is_false")]
    pub swapped: bool,
    /// True for `CREATE SCHEMA … MANAGED LOCATION '…'` (Databricks Unity Catalog).
    #[serde(default, skip_serializing_if = "is_false")]
    pub managed_location_present: bool,
    /// True for `CREATE SCHEMA … LOCATION '…'` (Databricks Hive metastore).
    #[serde(default, skip_serializing_if = "is_false")]
    pub location_present: bool,
    /// ALTER actions in source order. Empty for CREATE / DROP.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub actions: Vec<SchemaAlterAction>,
    /// How the schema was created (standard / clone). Absent for ALTER / DROP.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub create_origin: Option<SchemaCreateOrigin>,
}

/// How a schema was created.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SchemaCreateOrigin {
    /// `CREATE SCHEMA name` with no upstream source.
    Standard,
    /// `CREATE SCHEMA name CLONE source [AT|BEFORE (...)]`.
    Clone,
}

/// An action applied by an ALTER SCHEMA statement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SchemaAlterAction {
    EnableManagedAccess,
    DisableManagedAccess,
    SwapWith,
    SetProperties,
    UnsetProperties,
    SetDbProperties,
    OwnerTo,
    PredictiveOptimization,
    DefaultCollation,
    RenameTo,
    SetTag,
    UnsetTag,
    SetComment,
    UnsetComment,
    SetTags,
    UnsetTags,
    /// Clause present but not structurally recognized.
    Opaque,
}

/// PostgreSQL CREATE / ALTER / DROP DOMAIN statement properties.
/// DROP … CASCADE is indicated by `ddl.options.cascade`.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct DomainFacts {
    /// ALTER actions in source order. Empty for CREATE / DROP.
    /// PostgreSQL allows one action per ALTER DOMAIN statement.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub actions: Vec<DomainAlterAction>,
}

/// An action applied by an ALTER DOMAIN statement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DomainAlterAction {
    /// `ALTER DOMAIN … RENAME TO …`.
    RenameTo,
    /// `ALTER DOMAIN … OWNER TO …`.
    OwnerTo,
    /// `ALTER DOMAIN … DROP NOT NULL`.
    DropNotNull,
    /// `ALTER DOMAIN … DROP CONSTRAINT [name] [CASCADE | RESTRICT]`.
    DropConstraint { cascade: bool },
    /// `ALTER DOMAIN … ADD CONSTRAINT …`.
    AddConstraint,
    /// Any other ALTER DOMAIN action (`SET DEFAULT`, `DROP DEFAULT`,
    /// `SET NOT NULL`, `RENAME CONSTRAINT`, `VALIDATE CONSTRAINT`, `SET SCHEMA`).
    Other,
}

/// ALTER INDEX statement properties. Each ALTER INDEX statement carries exactly one action.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct IndexFacts {
    pub action: IndexAlterAction,
}

/// An action applied by an ALTER INDEX statement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum IndexAlterAction {
    /// `ALTER INDEX … RENAME TO …`.
    RenameTo,
    /// Any other ALTER INDEX action (`SET TABLESPACE`, `ATTACH PARTITION`,
    /// `DEPENDS ON EXTENSION`, `SET (…)`, `RESET (…)`, `ALTER COLUMN … SET STATISTICS …`,
    /// `ALL IN TABLESPACE … SET TABLESPACE …`).
    Other,
}

/// ALTER TRIGGER statement properties. Each ALTER TRIGGER statement carries exactly one action.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct TriggerFacts {
    pub action: TriggerAlterAction,
}

/// An action applied by an ALTER TRIGGER statement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TriggerAlterAction {
    /// `ALTER TRIGGER … RENAME TO …`.
    RenameTo,
    /// Any other ALTER TRIGGER action (`[NO] DEPENDS ON EXTENSION …`).
    Other,
}

/// PostgreSQL ALTER TABLE … ENABLE/DISABLE TRIGGER statement properties.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct TriggerStateFacts {
    pub action: TriggerStateAction,
}

/// The trigger enable/disable action from ALTER TABLE … TRIGGER.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TriggerStateAction {
    /// `ALTER TABLE … DISABLE TRIGGER …`.
    Disable,
    /// `ALTER TABLE … ENABLE [ALWAYS | REPLICA] TRIGGER …`.
    Enable,
}

/// PostgreSQL SET / RESET session configuration statement properties.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct PgSessionFacts {
    pub action: PgSessionAction,
}

/// The action from a PostgreSQL SET or RESET session configuration statement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PgSessionAction {
    /// `SET [SESSION | LOCAL] ROLE …`.
    SetRole,
    /// `SET [SESSION | LOCAL] SESSION AUTHORIZATION …`.
    SetSessionAuthorization,
    /// `SET [SESSION | LOCAL] search_path TO …`.
    SetSearchPath,
    /// `SET [SESSION | LOCAL] <other_parameter> { TO | = } …`.
    SetParameter,
    /// Any `RESET` form.
    Reset,
}

/// Databricks CREATE / ALTER / DROP CATALOG statement properties.
/// DROP … CASCADE is indicated by `ddl.options.cascade`.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct CatalogFacts {
    /// True for `CREATE FOREIGN CATALOG …`. Always false for ALTER and DROP.
    #[serde(default, skip_serializing_if = "is_false")]
    pub foreign: bool,
    /// ALTER actions in source order. Empty for CREATE / DROP.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub actions: Vec<CatalogAlterAction>,
}

/// An action applied by an ALTER CATALOG statement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CatalogAlterAction {
    /// `[SET] OWNER TO principal`.
    OwnerTo,
    /// `SET TAGS ('tag' = 'val', …)`.
    SetTags,
    /// `UNSET TAGS ('tag', …)`.
    UnsetTags,
    /// `ENABLE PREDICTIVE OPTIMIZATION`.
    EnablePredictiveOptimization,
    /// `DISABLE PREDICTIVE OPTIMIZATION`.
    DisablePredictiveOptimization,
    /// `INHERIT PREDICTIVE OPTIMIZATION`.
    InheritPredictiveOptimization,
    /// Any other ALTER CATALOG action (`DEFAULT COLLATION`, `OPTIONS (…)`).
    Other,
}

/// Databricks CREATE / ALTER / DROP VOLUME statement properties.
/// CREATE-time fields are populated only for CREATE. DROP IF EXISTS is
/// indicated by `ddl.options.if_exists`.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct VolumeFacts {
    /// True for `CREATE EXTERNAL VOLUME …`. Always `false` on ALTER and
    /// DROP.
    #[serde(default, skip_serializing_if = "is_false")]
    pub is_external: bool,
    /// True when the CREATE statement specifies `LOCATION '<path>'`.
    /// Always `false` on ALTER and DROP.
    #[serde(default, skip_serializing_if = "is_false")]
    pub location_present: bool,
    /// True when the CREATE statement specifies `COMMENT '<text>'`.
    /// Always `false` on ALTER and DROP.
    #[serde(default, skip_serializing_if = "is_false")]
    pub comment_present: bool,
    /// `ALTER VOLUME` actions in source order. Empty on CREATE /
    /// DROP.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub actions: Vec<VolumeAlterAction>,
    /// Snowflake `ALLOW_WRITES = { TRUE | FALSE }` on `CREATE EXTERNAL
    /// VOLUME`. Absent when the clause is not present (and on ALTER /
    /// DROP). `true` means Snowflake can write data out to the external
    /// object store, not just read from it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_writes: Option<bool>,
    /// Per-location cloud-storage backing config from the Snowflake
    /// `STORAGE_LOCATIONS` clause. Empty for Databricks volumes.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub storage_locations: Vec<StorageLocationFacts>,
}

/// One external cloud-storage backing location of a Snowflake external
/// volume. Values are normalized (dequoted, upper-cased). Rules predicate
/// via `ddl.volume.storage_locations: { exists: { … } }`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct StorageLocationFacts {
    /// `STORAGE_PROVIDER` value (e.g. `S3`, `GCS`, `AZURE`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    /// True when the location specifies `STORAGE_AWS_ROLE_ARN` — the
    /// cloud IAM role the volume assumes to reach the bucket.
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_role_arn: bool,
    /// True when the location specifies `STORAGE_AWS_EXTERNAL_ID`.
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_external_id: bool,
    /// `ENCRYPTION ( TYPE = … )` value (e.g. `NONE`, `AWS_SSE_S3`,
    /// `AWS_SSE_KMS`). Absent when no ENCRYPTION clause is present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encryption_type: Option<String>,
}

/// An action applied by an ALTER VOLUME statement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum VolumeAlterAction {
    /// `RENAME TO new_name`.
    RenameTo,
    /// `[SET] OWNER TO principal`.
    OwnerTo,
    /// `SET TAGS ('tag' = 'val', …)`.
    SetTags,
    /// `UNSET TAGS ('tag', …)`.
    UnsetTags,
}

/// Databricks CREATE / ALTER / DROP EXTERNAL LOCATION statement properties.
/// CREATE-time fields are populated only for CREATE. DROP IF EXISTS is
/// indicated by `ddl.options.if_exists`.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct ExternalLocationFacts {
    /// True when the CREATE statement specifies a URL clause.
    #[serde(default, skip_serializing_if = "is_false")]
    pub url_present: bool,
    /// True when the CREATE statement specifies `WITH (STORAGE
    /// CREDENTIAL <name>)`. Always `false` on ALTER and DROP.
    #[serde(default, skip_serializing_if = "is_false")]
    pub storage_credential_present: bool,
    /// True when the CREATE statement specifies `COMMENT '<text>'`.
    /// Always `false` on ALTER and DROP.
    #[serde(default, skip_serializing_if = "is_false")]
    pub comment_present: bool,
    /// `ALTER EXTERNAL LOCATION` actions in source order. Empty on
    /// CREATE / DROP.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub actions: Vec<ExternalLocationAlterAction>,
}

/// An action applied by an ALTER EXTERNAL LOCATION statement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ExternalLocationAlterAction {
    /// `RENAME TO new_name`.
    RenameTo,
    /// `SET URL 'url' [FORCE]`.
    SetUrl,
    /// `SET STORAGE CREDENTIAL credential_name`.
    SetStorageCredential,
    /// `[SET] OWNER TO principal`.
    OwnerTo,
}

/// Databricks CREATE / ALTER / DROP CONNECTION statement properties.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct ConnectionFacts {
    /// True when the CREATE statement specifies `TYPE <connector>`.
    /// Always `false` on ALTER and DROP.
    #[serde(default, skip_serializing_if = "is_false")]
    pub type_present: bool,
    /// True when the CREATE statement specifies `OPTIONS (…)`. Always
    /// `false` on ALTER and DROP.
    #[serde(default, skip_serializing_if = "is_false")]
    pub options_present: bool,
    /// True when the CREATE statement specifies `COMMENT '<text>'`.
    /// Always `false` on ALTER and DROP.
    #[serde(default, skip_serializing_if = "is_false")]
    pub comment_present: bool,
    /// True for Snowflake `CREATE CONNECTION … AS REPLICA OF <src>` — an
    /// inbound replica of a connection owned by another account.
    #[serde(default, skip_serializing_if = "is_false")]
    pub is_replica: bool,
    /// `ALTER CONNECTION` actions in source order. Empty on CREATE /
    /// DROP.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub actions: Vec<ConnectionAlterAction>,
}

/// An action applied by an ALTER CONNECTION statement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ConnectionAlterAction {
    /// `[SET] OWNER TO principal`.
    OwnerTo,
    /// `RENAME TO new_name`.
    RenameTo,
    /// `OPTIONS (…)`.
    Options,
    /// Snowflake `ENABLE FAILOVER TO ACCOUNTS <list>` — opens cross-account
    /// failover of this connection to the listed accounts.
    EnableFailover,
    /// Snowflake `DISABLE FAILOVER [TO ACCOUNTS <list>]`.
    DisableFailover,
    /// Snowflake `PRIMARY` — promote a replica connection to primary.
    Primary,
}

/// `CREATE EXTERNAL DATA SOURCE` (T-SQL / PolyBase) statement properties.
/// Registers a federated endpoint — a Hadoop cluster, an Azure blob /
/// object store, a remote relational database, or a sharded database. The
/// raw location string is intentionally not surfaced: PolyBase connection
/// strings can embed credentials. The governance signal — an offsite
/// endpoint, possibly with a persisted credential — is captured by the
/// scheme, type, and credential fields.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct ExternalDataSourceFacts {
    /// True when a LOCATION clause is present.
    #[serde(default, skip_serializing_if = "is_false")]
    pub location_present: bool,
    /// Lowercased URI scheme of the location endpoint — the characters
    /// before `://` (`hdfs`, `wasbs`, `abfss`, `https`, `sqlserver`, …).
    /// Omitted when the location has no scheme separator or is absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub location_scheme: Option<String>,
    /// The endpoint class, when the statement names one of the documented
    /// TYPE values. Omitted for newer driver-prefix syntax that has no TYPE.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_type: Option<ExternalDataSourceType>,
    /// True when the endpoint references a stored credential
    /// (`CREDENTIAL = <name>`).
    #[serde(default, skip_serializing_if = "is_false")]
    pub credential_referenced: bool,
    /// `PUSHDOWN = ON` (`Some(true)`) pushes computation to the remote
    /// endpoint; `OFF` is `Some(false)`. Omitted when not specified.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pushdown: Option<bool>,
}

/// Endpoint class of a T-SQL external data source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum ExternalDataSourceType {
    /// `TYPE = HADOOP` — a Hadoop / HDFS cluster.
    Hadoop,
    /// `TYPE = BLOB_STORAGE` — an Azure blob / object store.
    BlobStorage,
    /// `TYPE = RDBMS` — a remote relational database (elastic query).
    Rdbms,
    /// `TYPE = SHARD_MAP_MANAGER` — a sharded database map.
    ShardMapManager,
}

/// `CREATE SERVER … FOREIGN DATA WRAPPER` (SQL/MED foreign server,
/// PostgreSQL FDW) statement properties. Registers a federated endpoint
/// reached through a foreign-data wrapper. The wrapper name is the
/// discriminator: a network wrapper (`postgres_fdw`, `mysql_fdw`,
/// `oracle_fdw`, …) reaches a remote system; `file_fdw` reads server-side
/// files. OPTION values are not surfaced (they can name hosts).
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct ForeignServerFacts {
    /// Lowercased foreign-data-wrapper name (the `FOREIGN DATA WRAPPER`
    /// operand). Omitted only when the clause is malformed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wrapper: Option<String>,
    /// True when a `TYPE '…'` clause is present.
    #[serde(default, skip_serializing_if = "is_false")]
    pub type_present: bool,
    /// True when an `OPTIONS (…)` clause is present.
    #[serde(default, skip_serializing_if = "is_false")]
    pub options_present: bool,
}

/// `ALTER SERVER CONFIGURATION SET …` (T-SQL) statement properties. A
/// server-instance-level reconfiguration. The `subsystem` is the recognition
/// discriminator — the configuration area being changed (`process affinity`,
/// `diagnostics log`, `buffer pool extension`, `hadr cluster context`,
/// `failover cluster property`, `softnuma`, `memory_optimized`, …), lowercased.
/// Which subsystems are sensitive (filesystem / availability surfaces) is a
/// policy decision left to the rule layer.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct ServerConfigurationFacts {
    /// Lowercased configuration subsystem (the first word after `SET`).
    /// Omitted only when the `SET` clause is malformed / absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subsystem: Option<String>,
}

/// MySQL `LOAD DATA … INFILE` (bulk file ingestion) statement properties.
/// `local` is the security-relevant axis — `LOAD DATA LOCAL INFILE` reads from
/// the *client* host (an abuse vector, disabled by default in hardened
/// configs); without it the path is read from the database server's filesystem
/// (requires the FILE privilege). The path and any recognized cloud-storage
/// scheme are surfaced; whether either is sensitive is a rule-layer verdict.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct MysqlLoadDataFacts {
    /// `LOCAL` modifier present (client-side read).
    #[serde(default, skip_serializing_if = "is_false")]
    pub local: bool,
    /// Dequoted `INFILE` path literal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub infile_path: Option<String>,
    /// Cloud-storage vendor classified from the path scheme, when recognized.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cloud_scheme: Option<CloudVendor>,
}

/// Whether a scheduled `EVENT` fires once or repeatedly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum EventScheduleKind {
    /// `AT <timestamp>` — fires exactly once.
    OneTime,
    /// `EVERY <interval>` — fires repeatedly on an interval.
    Recurring,
}

/// Whether a scheduled `EVENT` is enabled, disabled, or disabled only on
/// replicas.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum EventEnableState {
    /// `ENABLE` (or unwritten — the default).
    Enable,
    /// `DISABLE`.
    Disable,
    /// `DISABLE ON SLAVE` — enabled on the source, disabled on replicas.
    DisableOnSlave,
}

/// Whether the statement creates or alters the scheduled event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum EventAction {
    Create,
    Alter,
}

/// A `DEFINER =` security-context clause — the account a routine runs under.
/// The body executes with the definer's privileges regardless of who invokes
/// it; the named account is therefore a privilege-delegation surface (whether
/// a given account is privileged is policy, expressed against `user`).
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct DefinerFacts {
    /// True when an explicit account is named (not `CURRENT_USER`); the body
    /// runs under that account's privileges regardless of the invoker.
    #[serde(default, skip_serializing_if = "is_false")]
    pub explicit: bool,
    /// The definer user name (dequoted), when explicit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    /// The host part of a `user@host` definer, when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
}

/// `SQL SECURITY` mode of a MySQL view — whose privileges its query runs under.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum ViewSqlSecurity {
    /// Runs with the definer account's privileges (the MySQL default) — the
    /// view can expose data the caller could not read directly.
    Definer,
    /// Runs with the invoking caller's own privileges.
    Invoker,
}

/// `CHECK OPTION` enforcement level on an updatable view — whether rows
/// written through the view must satisfy the view's own condition only,
/// or every underlying view's condition as well.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum ViewCheckOption {
    /// Writes are checked against this view's condition only.
    Local,
    /// Writes are checked against this view's condition and every
    /// underlying view's condition.
    Cascaded,
}

/// `CREATE VIEW` security-context facts. MySQL states the context as a
/// prelude (`DEFINER =`, `SQL SECURITY { DEFINER | INVOKER }`); PostgreSQL
/// states it as options in the `WITH (...)` list (`security_invoker`,
/// `security_barrier`). Whether a given account or mode is acceptable is
/// policy, expressed against these fields.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct ViewFacts {
    /// The `DEFINER =` account, when present (absent / `CURRENT_USER` → `None`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub definer: Option<DefinerFacts>,
    /// The `SQL SECURITY { DEFINER | INVOKER }` mode, when stated explicitly.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sql_security: Option<ViewSqlSecurity>,
    /// PostgreSQL `WITH (security_invoker = ...)`: `true` runs the view's
    /// query with the calling user's privileges and row-level security;
    /// `false` (the PostgreSQL default) runs it as the view owner, which can
    /// bypass the caller's row-level security policies.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub security_invoker: Option<bool>,
    /// PostgreSQL `WITH (security_barrier = ...)`: whether the view prevents
    /// functions in outer queries from being pushed down into the view and
    /// seeing rows its condition would hide.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub security_barrier: Option<bool>,
    /// `CHECK OPTION` enforcement on an updatable view, when stated
    /// (PostgreSQL `WITH (check_option = ...)`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub check_option: Option<ViewCheckOption>,
}

/// Timing of a trigger relative to the row change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum TriggerTiming {
    Before,
    After,
}

/// The DML event a trigger fires on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum TriggerEvent {
    Insert,
    Update,
    Delete,
}

/// MySQL `CREATE TRIGGER` — an inline-body trigger that runs automatically on a
/// row event, under the definer's privileges. The body's inner SQL is analyzed
/// independently, so a trigger that grants privileges or drops a table on write
/// surfaces through the normal rule corpus.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct CreateTriggerFacts {
    /// `BEFORE` / `AFTER` the row change.
    pub timing: TriggerTiming,
    /// The row event the trigger fires on.
    pub event: TriggerEvent,
    /// The `DEFINER =` security context, when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub definer: Option<DefinerFacts>,
    /// An inline body is present.
    #[serde(default, skip_serializing_if = "is_false")]
    pub body_present: bool,
}

/// MySQL `CREATE EVENT` / `ALTER EVENT` — a scheduled SQL job that runs its
/// `DO` body on a schedule. The body's inner SQL is analyzed independently, so
/// dangerous scheduled statements surface through the normal rule corpus.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct EventFacts {
    /// Whether the event is being created or altered.
    pub action: EventAction,
    /// The `DEFINER =` security context, when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub definer: Option<DefinerFacts>,
    /// Schedule kind (one-time vs recurring). Present for `CREATE`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schedule_kind: Option<EventScheduleKind>,
    /// An `ON SCHEDULE` clause is present (a reschedule, for `ALTER`).
    #[serde(default, skip_serializing_if = "is_false")]
    pub schedule_present: bool,
    /// `ON COMPLETION PRESERVE` — the event survives after firing.
    #[serde(default, skip_serializing_if = "is_false")]
    pub on_completion_preserve: bool,
    /// Explicit enable state, when written.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enable_state: Option<EventEnableState>,
    /// A `RENAME TO` clause is present (`ALTER`).
    #[serde(default, skip_serializing_if = "is_false")]
    pub rename: bool,
    /// A `DO <statement>` body is present (rebinds the scheduled SQL on
    /// `ALTER`; always present on `CREATE`).
    #[serde(default, skip_serializing_if = "is_false")]
    pub body_present: bool,
}

/// `CREATE USER MAPPING` (SQL/MED user mapping, PostgreSQL FDW) statement
/// properties. Attaches per-local-role credentials for a foreign server.
/// `FOR PUBLIC` maps every local role. The remote password value is masked
/// from output surfaces; the `options` carry the raw entries for credential
/// detection.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct UserMappingFacts {
    /// Foreign-server name the mapping targets.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,
    /// True when the mapping is `FOR PUBLIC` — it applies to every local role.
    #[serde(default, skip_serializing_if = "is_false")]
    pub is_public: bool,
    /// `OPTIONS (…)` entries (the remote connection settings, including the
    /// user and password).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub options: Vec<UserMappingOption>,
}

/// `CREATE FOREIGN TABLE` (SQL/MED foreign table, PostgreSQL FDW) statement
/// properties. Exposes a remote relation locally; queries against it reach
/// the foreign server across the instance boundary. Column definitions are
/// not surfaced — only the binding to the foreign server matters for
/// governance.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct ForeignTableFacts {
    /// Foreign-server name the table is bound to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,
    /// True for the `PARTITION OF parent` form.
    #[serde(default, skip_serializing_if = "is_false")]
    pub is_partition: bool,
    /// True when an `OPTIONS (…)` clause is present.
    #[serde(default, skip_serializing_if = "is_false")]
    pub options_present: bool,
}

/// Table-selection filter on `IMPORT FOREIGN SCHEMA`. `all` imports every
/// remote table; `except` imports all but a named few; `limit_to` imports only
/// the named tables. `all` and `except` expose (nearly) the whole remote schema.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum ImportFilterMode {
    All,
    LimitTo,
    Except,
}

/// `IMPORT FOREIGN SCHEMA` (SQL/MED bulk remote-table import, PostgreSQL FDW).
/// Exposes a remote schema's tables locally in one statement — the bulk sibling
/// of `CREATE FOREIGN TABLE`. The filter mode determines how much of the remote
/// schema is exposed; the named table list itself is not surfaced.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct ImportForeignSchemaFacts {
    /// Foreign-server name the import pulls through.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,
    /// Remote schema being imported.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_schema: Option<String>,
    /// Local schema the foreign tables land in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_schema: Option<String>,
    /// Table-selection filter mode.
    pub filter_mode: ImportFilterMode,
    /// True when an `OPTIONS (…)` clause is present.
    #[serde(default, skip_serializing_if = "is_false")]
    pub options_present: bool,
}

/// One `OPTIONS (key 'value')` entry of a CREATE USER MAPPING.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct UserMappingOption {
    /// Option key.
    pub key: IdentName,
    /// String-literal value with quotes stripped. Absent when the value is
    /// not a string literal. `password` / `secret`-style keys' values are
    /// masked in the facts copies attached to reports; other option
    /// values (`user`, `host`, …) stay visible.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value_literal: Option<String>,
}

/// Databricks CREATE FLOW (Lakeflow CDC pipeline) statement properties.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct FlowFacts {}

/// CREATE / ALTER FUNCTION statement properties.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct FunctionFacts {
    /// Function body facts. Present only for CREATE FUNCTION with a parseable body.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<FunctionBodyFacts>,
    /// ALTER actions in source order. Empty for CREATE.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub actions: Vec<FunctionAlterAction>,
    /// MySQL `DEFINER =` security context declared on `CREATE FUNCTION`.
    /// The body executes under this account's privileges regardless of
    /// the invoker. `None` when absent (`CURRENT_USER` / no clause).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub definer: Option<DefinerFacts>,
}

/// CREATE FUNCTION body properties.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct FunctionBodyFacts {
    /// SQL statement kinds present anywhere in the function body.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub statement_kinds: Vec<FunctionBodyStatementKind>,
    /// Total count of leaf statements anywhere in the body,
    /// recursively across `BEGIN` / `IF` / `WHILE` / `FOR` / `LOOP` /
    /// `REPEAT` / `CASE` / `TRY-CATCH`.
    #[serde(default, skip_serializing_if = "is_zero_usize")]
    pub statements_count: usize,
    /// Dynamic-SQL call sites in the body. Each entry exposes the
    /// `surface` it came from (Snowflake `EXECUTE IMMEDIATE`, T-SQL
    /// `EXEC` / `sp_executesql`, etc.), the structural shape of its
    /// argument (`literal` / `variable` / `concat` / `format` /
    /// `unknown`), and its parameterization mode (`none` /
    /// `positional_using` / `named_params` / `not_applicable`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dynamic_sql_calls: Vec<DynamicSqlCall>,
}

#[inline]
fn is_zero_usize(n: &usize) -> bool {
    *n == 0
}

/// SQL statement kinds recognized within a function body.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", schemars(rename = "FunctionBodyStatementType"))]
pub enum FunctionBodyStatementKind {
    /// `EXECUTE IMMEDIATE <expr>` — the SQL surface for dynamic SQL.
    ExecuteImmediate,
}

/// One action from an ALTER FUNCTION statement.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct FunctionAlterAction {
    pub kind: FunctionAlterActionKind,
    /// SET PROPERTIES clause content. Present only when `kind == set_properties`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub properties: Option<FunctionPropertiesFacts>,
}

/// The action type from an ALTER FUNCTION statement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", schemars(rename = "FunctionAlterActionType"))]
pub enum FunctionAlterActionKind {
    /// `RENAME TO <new_name>`.
    Rename,
    /// `SET SECURE`.
    SetSecure,
    /// `UNSET SECURE`.
    UnsetSecure,
    /// `SET <properties…>`.
    SetProperties,
    /// `UNSET <properties…>`.
    UnsetProperties,
    /// `SET TAG …`.
    SetTag,
    /// `UNSET TAG …`.
    UnsetTag,
    /// External function: `SET API_INTEGRATION = …`.
    SetApiIntegration,
    /// External function: `SET HEADERS = (…)`.
    SetHeaders,
    /// External function: `SET CONTEXT_HEADERS = (…)`.
    SetContextHeaders,
    /// External function: `SET MAX_BATCH_ROWS = <integer>`.
    SetMaxBatchRows,
    /// External function: `SET COMPRESSION = <type>`.
    SetCompression,
    /// External function: `SET REQUEST_TRANSLATOR = <udf>`.
    SetRequestTranslator,
    /// External function: `SET RESPONSE_TRANSLATOR = <udf>`.
    SetResponseTranslator,
    /// Unclassified action (defensive parsing fallback).
    Unknown,
}

/// Properties set by an `ALTER FUNCTION … SET <properties…>` clause.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct FunctionPropertiesFacts {
    /// Property keys present in the SET clause.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub keys: Vec<FunctionPropertyKey>,
}

/// A property key from a function SET clause.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum FunctionPropertyKey {
    ExternalAccessIntegrations,
    Secrets,
    LogLevel,
    TraceLevel,
    Comment,
    /// Property key not enumerated above.
    Other,
}

/// CREATE / ALTER / DROP PROCEDURE statement properties.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct ProcedureFacts {
    /// Procedure body facts. Present only for CREATE PROCEDURE with a parseable body.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<ProcedureBodyFacts>,
    /// ALTER actions in source order. Empty for CREATE / DROP.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub actions: Vec<ProcedureAlterAction>,
    /// MySQL `DEFINER =` security context declared on `CREATE PROCEDURE`.
    /// The body executes under this account's privileges regardless of
    /// the invoker. `None` when absent (`CURRENT_USER` / no clause).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub definer: Option<DefinerFacts>,
}

/// CREATE PROCEDURE body properties.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct ProcedureBodyFacts {
    /// SQL statement kinds present anywhere in the procedure body.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub statement_kinds: Vec<ProcedureBodyStatementKind>,
    /// Total count of leaf statements anywhere in the body,
    /// recursively across `BEGIN` / `IF` / `WHILE` / `FOR` / `LOOP` /
    /// `REPEAT` / `CASE` / `TRY-CATCH`.
    #[serde(default, skip_serializing_if = "is_zero_usize")]
    pub statements_count: usize,
    /// Dynamic-SQL call sites in the procedure body. See
    /// `DynamicSqlCall` for the per-call axes; same shape as
    /// `function.body.dynamic_sql_calls`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dynamic_sql_calls: Vec<DynamicSqlCall>,
    /// `EXECUTE AS { OWNER | CALLER | RESTRICTED CALLER }` clause
    /// declared on the `CREATE PROCEDURE` statement (e.g. T-SQL
    /// `WITH EXECUTE AS OWNER`, Snowflake `EXECUTE AS CALLER`). `None`
    /// when the clause is absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execute_as_mode: Option<ProcedureExecuteAsMode>,
}

/// A single dynamic-SQL call site. Exposes three orthogonal axes:
/// which dynamic-SQL surface produced it, the structural shape of its
/// argument, and whether the surface is parameterized.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct DynamicSqlCall {
    pub surface: DynamicSqlSurface,
    pub argument: DynamicSqlArg,
    pub parameterization: DynamicSqlParameterization,
    /// Inter-procedural taint provenance chain — empty for direct
    /// intra-procedural findings, populated when this call is the
    /// witness location for a finding whose dynamic-SQL sink lives
    /// inside a called procedure. Each step in the chain is tagged
    /// by role (Assignment / CallSite / Sink) so report renderers
    /// can walk the laundering route.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub provenance: Vec<TaintWitnessSpanFact>,
    /// Points where untrusted values are placed into the dynamically
    /// built SQL string, each tagged by its position and quoting. Empty
    /// when none were identified.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub taint_splices: Vec<DynamicSqlSplice>,
}

/// Where an untrusted value is placed within a dynamically built SQL
/// string, relative to SQL's lexical structure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum DynamicSqlSplicePosition {
    /// Inside a quoted string literal (for example `... '<value>' ...`).
    StringLiteral,
    /// An identifier/name position, such as a table name, a column name
    /// in a definition, or an assigned/inserted column name. Identifier
    /// quoting is the appropriate protection in this position.
    Identifier,
    /// Outside any quoted string literal and not a clear identifier
    /// position — a value, predicate, or projection position. A quoted
    /// identifier here denotes a column reference, so it is not treated
    /// as a quoting mismatch.
    Bare,
    /// The placement could not be determined.
    Unknown,
}

/// The quoting function (if any) applied to an untrusted value before it
/// is placed into a dynamically built SQL string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum DynamicSqlSpliceQuoting {
    /// No quoting function — the value is placed directly.
    Raw,
    /// Wrapped by an identifier-quoting function (delimits an identifier).
    IdentifierQuoted,
    /// Wrapped by a string-literal-quoting function (escapes string contents).
    LiteralQuoted,
}

/// A single point where an untrusted value is placed into a dynamically
/// built SQL string: where it lands in the SQL structure, and how (if at
/// all) it was quoted. A mismatch between the two — for example
/// identifier quoting used inside a string literal — means the quoting
/// does not neutralize the value in that position.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct DynamicSqlSplice {
    pub position: DynamicSqlSplicePosition,
    pub quoting: DynamicSqlSpliceQuoting,
}

/// One step in the inter-procedural taint laundering route. Span is
/// represented by its byte offsets into the original SQL source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct TaintWitnessSpanFact {
    pub start: u32,
    pub end: u32,
    pub role: TaintWitnessRoleFact,
}

/// Role of one step in a taint laundering route.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum TaintWitnessRoleFact {
    Assignment,
    CallSite,
    Sink,
}

/// Dynamic-SQL execution surface. Each kind maps to a specific
/// dialect's syntax for executing a string as SQL.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", schemars(rename = "DynamicSqlSurfaceKind"))]
pub enum DynamicSqlSurface {
    /// Snowflake / BigQuery / Databricks `EXECUTE IMMEDIATE`.
    ExecuteImmediate,
    /// T-SQL `EXEC(@sql)` (parenthesized dynamic-SQL form).
    MssqlExecDynamic,
    /// T-SQL `EXEC sp_executesql @sql, @params, @p = @x`.
    MssqlSpExecutesql,
    /// PostgreSQL/MySQL `PREPARE`.
    Prepare,
    /// PostgreSQL `dblink_exec(connstr, sql)` cross-server invocation.
    DblinkExec,
    /// T-SQL `EXEC <named_proc> args` resolved to a procedure whose
    /// body contains a dynamic-SQL sink; the inter-procedural
    /// taint engine synthesizes this surface to mark the call site as
    /// the finding witness location.
    MssqlExecProcCall,
    /// Dialect-neutral counterpart for `CALL <proc>(args)` —
    /// Snowflake, BigQuery, PostgreSQL, MySQL, Databricks.
    CallProcCall,
}

/// Structural shape of the SQL-being-executed argument.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", schemars(rename = "DynamicSqlArgKind"))]
pub enum DynamicSqlArg {
    /// Pure string literal — no runtime input vector.
    Literal,
    /// Single variable reference — runtime content unknowable.
    Variable,
    /// String concatenation (`||`, `+`, `CONCAT(...)`) — canonical
    /// SQL-injection construction vector.
    Concat,
    /// A `||`/`+`/`CONCAT()` concatenation built only from literals and
    /// recognized quoting calls whose assembled skeleton is a single
    /// statement — injection-clean. Structural recognition; verdict is
    /// the rule's.
    ConcatQuoted,
    /// `FORMAT(...)` whose interpolation is raw or unverifiable — a
    /// `%s`, a computed (non-literal) template, or an unrecognized
    /// placeholder. The runtime value can break out of its slot.
    Format,
    /// `FORMAT(...)` over a literal template whose every placeholder is
    /// a quoting specifier (`%I`/`%L`) — the interpolated value is
    /// quoted into an identifier/literal slot and cannot break out.
    /// Structural recognition; the risk verdict is the rule's.
    FormatQuoted,
    /// Argument is some other expression shape, or its structure was
    /// not extracted (MSSQL `EXEC` arguments and `dblink_exec`
    /// arguments fall here).
    Unknown,
}

/// Parameterization mode of the dynamic-SQL call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
#[cfg_attr(
    feature = "schema",
    schemars(rename = "DynamicSqlParameterizationKind")
)]
pub enum DynamicSqlParameterization {
    /// Surface supports parameterization but none is in use.
    None,
    /// `USING (a, b, c)` positional bind list.
    PositionalUsing,
    /// `sp_executesql @sql, N'@p type', @p = expr` — declared list.
    NamedParams,
    /// Surface does not expose parameterization (`EXEC(@sql)`,
    /// `dblink_exec`).
    NotApplicable,
}

/// SQL statement kinds recognized within a procedure body.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", schemars(rename = "ProcedureBodyStatementType"))]
pub enum ProcedureBodyStatementKind {
    /// `EXECUTE IMMEDIATE <expr>` — the SQL surface for dynamic SQL.
    ExecuteImmediate,
}

/// One action from an ALTER PROCEDURE statement.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct ProcedureAlterAction {
    pub kind: ProcedureAlterActionKind,
    /// SET PROPERTIES clause content. Present only when `kind == set_properties`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub properties: Option<ProcedurePropertiesFacts>,
    /// EXECUTE AS mode. Present only when `kind == execute_as`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execute_as_mode: Option<ProcedureExecuteAsMode>,
}

/// The action type from an ALTER PROCEDURE statement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", schemars(rename = "ProcedureAlterActionType"))]
pub enum ProcedureAlterActionKind {
    /// `RENAME TO <new_name>`.
    Rename,
    /// `SET SECURE`.
    SetSecure,
    /// `UNSET SECURE`.
    UnsetSecure,
    /// `SET <properties…>` — kind-specific keys at `properties.keys`.
    SetProperties,
    /// `UNSET COMMENT`.
    UnsetComment,
    /// `SET TAG …`.
    SetTag,
    /// `UNSET TAG …`.
    UnsetTag,
    /// `EXECUTE AS { OWNER | CALLER | RESTRICTED CALLER }`.
    ExecuteAs,
    /// Unclassified action (defensive parsing fallback).
    Unknown,
}

/// Properties set by an `ALTER PROCEDURE … SET <properties…>` clause.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct ProcedurePropertiesFacts {
    /// Property keys present in the SET clause.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub keys: Vec<ProcedurePropertyKey>,
}

/// A property key from a procedure SET clause.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum ProcedurePropertyKey {
    ExternalAccessIntegrations,
    Secrets,
    LogLevel,
    TraceLevel,
    Comment,
    AutoEventLogging,
    /// Any other property key.
    Other,
}

/// The EXECUTE AS mode from an EXECUTE AS clause.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum ProcedureExecuteAsMode {
    Owner,
    Caller,
    RestrictedCaller,
}

/// Databricks / Delta / SparkSQL table-maintenance statement properties:
/// VACUUM, OPTIMIZE, RESTORE, DESCRIBE HISTORY, `[MSCK] REPAIR TABLE`,
/// `CACHE [LAZY] TABLE`, UNCACHE TABLE.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct TableMaintenanceFacts {
    pub kind: TableMaintenanceKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<TableRef>,
    /// VACUUM options. Present only for `kind == vacuum`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vacuum: Option<VacuumOptions>,
    /// CACHE TABLE options. Present only for `kind == cache_table`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache: Option<CacheOptions>,
    /// REPAIR TABLE options. Present only for `kind == repair_table`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repair: Option<RepairOptions>,
}

/// The specific table-maintenance operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", schemars(rename = "TableMaintenanceType"))]
pub enum TableMaintenanceKind {
    /// `VACUUM <table> [RETAIN <n> HOURS] [DRY RUN]` (Delta) or
    /// `VACUUM <table> { FULL | LITE } [DRY RUN]` (Iceberg).
    Vacuum,
    /// `OPTIMIZE <table> [WHERE …] [ZORDER BY (…)]`.
    Optimize,
    /// `RESTORE [TABLE] <table> [TO] { TIMESTAMP AS OF <expr> |
    /// VERSION AS OF <int> }`.
    Restore,
    /// `DESCRIBE HISTORY <table>`.
    DescribeHistory,
    /// `[MSCK] REPAIR TABLE <table> [{ADD|DROP|SYNC} PARTITIONS]`.
    RepairTable,
    /// `CACHE [LAZY] TABLE <table> [OPTIONS …] [[AS] <query>]`.
    CacheTable,
    /// `UNCACHE TABLE [IF EXISTS] <table>`.
    UncacheTable,
}

/// Options from a VACUUM statement. `retain_hours` is absent when the
/// RETAIN clause is omitted (default retention).
#[derive(Debug, Clone, Copy, PartialEq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct VacuumOptions {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retain_hours: Option<u64>,
}

/// Options from a CACHE TABLE statement. `lazy` is true when the LAZY keyword is present.
#[derive(Debug, Clone, Copy, PartialEq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct CacheOptions {
    #[serde(default)]
    pub lazy: bool,
}

/// Options from a `[MSCK] REPAIR TABLE` statement.
/// `mode` reflects the optional ADD/DROP/SYNC PARTITIONS suffix.
#[derive(Debug, Clone, Copy, PartialEq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct RepairOptions {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<RepairMode>,
}

/// The partition operation mode from a REPAIR TABLE suffix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum RepairMode {
    /// `ADD PARTITIONS`.
    Add,
    /// `DROP PARTITIONS`.
    Drop,
    /// `SYNC PARTITIONS`.
    Sync,
}

/// One `RENAME TABLE <from> TO <to>` pair.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct TableRenamePair {
    /// The current (source) table name.
    pub from: TableRef,
    /// The new table name.
    pub to: TableRef,
}

/// CREATE / ALTER / DROP TABLE, TRUNCATE, and DROP ALL ROW ACCESS POLICIES statement properties.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct TableFacts {
    /// `CREATE OR REPLACE TABLE`.
    #[serde(default, skip_serializing_if = "is_false")]
    pub or_replace: bool,
    /// `ALTER TABLE … ADD COLUMN …` action present.
    #[serde(default, skip_serializing_if = "is_false")]
    pub column_added: bool,
    /// `ALTER TABLE … DROP COLUMN …` action present.
    #[serde(default, skip_serializing_if = "is_false")]
    pub column_dropped: bool,
    /// `ALTER TABLE … RENAME TO …`.
    #[serde(default, skip_serializing_if = "is_false")]
    pub renamed: bool,
    /// `RENAME TABLE` pairs, in statement order: each entry renames
    /// `from` to `to`. Empty for other table statements.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub renames: Vec<TableRenamePair>,
    /// `ALTER TABLE … ADD ROW ACCESS POLICY …` (Snowflake) or
    /// `ALTER TABLE … SET ROW FILTER …` (Databricks).
    #[serde(default, skip_serializing_if = "is_false")]
    pub row_access_policy_added: bool,
    /// `ALTER TABLE … DROP ROW ACCESS POLICY …`,
    /// `ALTER TABLE … DROP ALL ROW ACCESS POLICIES`, or
    /// `ALTER TABLE … DROP ROW FILTER` (Databricks).
    /// See also `drop_all_row_access_policies` for the top-level DROP ALL form.
    #[serde(default, skip_serializing_if = "is_false")]
    pub row_access_policy_removed: bool,
    /// `ALTER TABLE … ALTER COLUMN … SET MASKING POLICY …`,
    /// `ALTER TABLE … ALTER COLUMN … SET MASK …` (Databricks), or
    /// `ALTER TABLE … ALTER COLUMN … SET PROJECTION POLICY …`.
    #[serde(default, skip_serializing_if = "is_false")]
    pub masking_policy_added: bool,
    /// `ALTER TABLE … ALTER COLUMN … UNSET MASKING POLICY`,
    /// `ALTER TABLE … ALTER COLUMN … DROP MASK` (Databricks), or
    /// `ALTER TABLE … ALTER COLUMN … UNSET PROJECTION POLICY`.
    #[serde(default, skip_serializing_if = "is_false")]
    pub masking_policy_removed: bool,
    /// `ALTER TABLE … UNSET AGGREGATION POLICY` or
    /// `ALTER TABLE … UNSET JOIN POLICY`.
    #[serde(default, skip_serializing_if = "is_false")]
    pub aggregation_policy_removed: bool,
    /// `ALTER TABLE … SET TAG …` (table or column level).
    #[serde(default, skip_serializing_if = "is_false")]
    pub tag_set: bool,
    /// `ALTER TABLE … UNSET TAG …` (table or column level).
    #[serde(default, skip_serializing_if = "is_false")]
    pub tag_unset: bool,
    /// Top-level `DROP ALL ROW ACCESS POLICIES <table>` statement.
    /// Distinct from the ALTER TABLE action
    /// of the same shape (which sets `row_access_policy_removed`).
    #[serde(default, skip_serializing_if = "is_false")]
    pub drop_all_row_access_policies: bool,
    /// ALTER actions in source order. Empty for non-ALTER statements.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub actions: Vec<TableAlterAction>,
    /// Clone shape for `CREATE TABLE … {SHALLOW | DEEP} CLONE <source>`.
    /// Absent for non-clone CREATE statements and all non-CREATE statements.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub clone: Option<CloneShape>,
    /// Redshift `DISTSTYLE` distribution strategy (CREATE TABLE only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dist_style: Option<DistStyle>,
    /// Redshift `DISTKEY (col)` clause present (CREATE TABLE only).
    #[serde(default, skip_serializing_if = "is_false")]
    pub dist_key_present: bool,
    /// Redshift `SORTKEY` strategy (CREATE TABLE only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sort_key: Option<SortKeySpec>,
    /// Redshift `BACKUP { YES | NO }` mode (CREATE TABLE only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backup: Option<BackupMode>,
    /// Snowflake `CREATE { ICEBERG | HYBRID | EVENT } TABLE` variant
    /// (CREATE TABLE only). Absent for an ordinary table.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub variant: Option<CreateTableKind>,
    /// The `DATA_RETENTION_TIME_IN_DAYS = <n>` value set on the table by
    /// a `CREATE TABLE` option clause or an `ALTER TABLE … SET` clause.
    /// Absent when the clause is omitted or its value is not a plain
    /// integer. A value of `0` disables Time Travel for the table, so
    /// dropped or modified rows cannot be recovered.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data_retention_days: Option<i64>,
}

/// An action applied by an ALTER TABLE statement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TableAlterAction {
    /// `ALTER TABLE … SET TBLPROPERTIES (…)`.
    SetTblProperties,
    /// `ALTER TABLE … UNSET TBLPROPERTIES (…)`.
    UnsetTblProperties,
    /// `ALTER TABLE … CLUSTER BY …`. `disabled: true` means `CLUSTER BY NONE`.
    ClusterBy { disabled: bool },
    /// `ALTER TABLE … SET JOIN POLICY <name>` — attaches or replaces a
    /// join policy on the table.
    SetJoinPolicy,
    /// `ALTER TABLE … SET AGGREGATION POLICY <name>` — attaches or replaces
    /// an aggregation (privacy) policy on the table.
    SetAggregationPolicy,
    /// `ALTER TABLE … ADD DATA METRIC FUNCTION <name> ON (<cols>)` —
    /// attaches a data-quality metric function to the table.
    AddDataMetricFunction,
    /// `ALTER TABLE … DROP DATA METRIC FUNCTION <name> ON (<cols>)` —
    /// detaches a data-quality metric function from the table.
    DropDataMetricFunction,
    /// `ALTER TABLE … [ENABLE | DISABLE | FORCE | NO FORCE] ROW LEVEL
    /// SECURITY`. `mode` names which form: enabling/forcing tightens
    /// row-level security; disabling/un-forcing relaxes it.
    RowLevelSecurity { mode: RowLevelSecurityMode },
}

/// Which `ROW LEVEL SECURITY` toggle an `ALTER TABLE` applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum RowLevelSecurityMode {
    /// `ENABLE ROW LEVEL SECURITY` — RLS enforced for non-owner roles.
    Enable,
    /// `DISABLE ROW LEVEL SECURITY` — RLS no longer enforced.
    Disable,
    /// `FORCE ROW LEVEL SECURITY` — RLS also enforced for the table owner.
    Force,
    /// `NO FORCE ROW LEVEL SECURITY` — owner exemption restored.
    NoForce,
}

/// The clone strategy used when creating a table from an existing one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CloneShape {
    /// Databricks `SHALLOW CLONE` — data files are shared with the
    /// source until modified.
    Shallow,
    /// Databricks `DEEP CLONE` — data files are duplicated.
    Deep,
    /// Snowflake / cross-dialect `CLONE source` — no SHALLOW / DEEP modifier.
    Standard,
}

/// The Snowflake table variant declared via
/// `CREATE { ICEBERG | HYBRID | EVENT } TABLE`. Absent for an ordinary
/// table. Rules predicate via
/// `ddl.table.variant.kind: { iceberg | hybrid | event }`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CreateTableKind {
    /// `CREATE ICEBERG TABLE` — table data is stored in an external
    /// object-storage volume rather than Snowflake-managed storage.
    Iceberg,
    /// `CREATE HYBRID TABLE` — Unistore row-oriented OLTP table with
    /// enforced primary/unique/foreign-key constraints.
    Hybrid,
    /// `CREATE EVENT TABLE` — captures log and trace events emitted by
    /// procedures, functions, and sessions.
    Event,
}

/// Redshift `DISTSTYLE` table distribution strategy. Rules predicate via
/// `ddl.table.dist_style.kind: { even | key | all | auto }`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DistStyle {
    /// `DISTSTYLE EVEN` — round-robin distribution.
    Even,
    /// `DISTSTYLE KEY` — distributed on a DISTKEY column.
    Key,
    /// `DISTSTYLE ALL` — full table replicated to every node.
    All,
    /// `DISTSTYLE AUTO` — Redshift-managed distribution.
    Auto,
}

/// Redshift `SORTKEY` strategy. Rules predicate via
/// `ddl.table.sort_key.kind: { compound | interleaved }`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SortKeySpec {
    /// Bare `SORTKEY` or `COMPOUND SORTKEY`.
    Compound,
    /// `INTERLEAVED SORTKEY`.
    Interleaved,
}

/// Redshift `BACKUP { YES | NO }` snapshot-inclusion mode. Rules predicate
/// via `ddl.table.backup.kind: { yes | no }`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BackupMode {
    Yes,
    No,
}

/// Snowflake CREATE / DROP STREAM statement properties.
/// CREATE-time flags are false for DROP STREAM.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct StreamFacts {
    /// `CREATE STREAM … APPEND_ONLY = …` clause present (any value).
    #[serde(default, skip_serializing_if = "is_false")]
    pub append_only: bool,
    /// `CREATE STREAM … INSERT_ONLY = …` clause present (any value).
    #[serde(default, skip_serializing_if = "is_false")]
    pub insert_only: bool,
}

/// Amazon Redshift CREATE / ALTER DATASHARE statement properties.
///
/// Surfaces the cross-account exposure surface as typed primitives that YAML
/// rules compose: `publicly_accessible` (SET PUBLICACCESSIBLE TRUE — the
/// public-exposure trigger), `publicly_inaccessible` (… FALSE), `includenew_set`
/// (auto-share of newly created objects), and the per-element typed list of
/// added/removed objects. No flat verdict-bool — governance is YAML policy.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct DatashareFacts {
    /// `SET PUBLICACCESSIBLE [=] TRUE` present — the datashare is publicly accessible.
    #[serde(default, skip_serializing_if = "is_false")]
    pub publicly_accessible: bool,
    /// `SET PUBLICACCESSIBLE [=] FALSE` present — explicitly made non-public.
    #[serde(default, skip_serializing_if = "is_false")]
    pub publicly_inaccessible: bool,
    /// `SET INCLUDENEW = TRUE FOR SCHEMA …` — auto-share of newly created
    /// objects is being ENABLED. `false` for `= FALSE` (disabling) or absent.
    #[serde(default, skip_serializing_if = "is_false")]
    pub includenew_set: bool,
    /// Objects added to the datashare via `ALTER DATASHARE … ADD …`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub added_objects: Vec<DatashareObjectRef>,
    /// Objects removed via `ALTER DATASHARE … REMOVE …`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub removed_objects: Vec<DatashareObjectRef>,
    /// An unrecognized ALTER DATASHARE action body was encountered.
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_unknown_clauses: bool,
}

/// A single object added to / removed from a datashare.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct DatashareObjectRef {
    pub object_kind: DatashareObjectKindFacts,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// Object kind referenced by an ADD/REMOVE datashare action (facts tier).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum DatashareObjectKindFacts {
    Table,
    Schema,
}

/// Snowflake CREATE / ALTER / DROP TASK statement properties.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct TaskFacts {
    /// CREATE TASK clause properties. Present only when `kind == create_task`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub create_options: Option<TaskCreateOptions>,
    /// ALTER actions in source order. Empty for CREATE / DROP.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub actions: Vec<TaskAlterAction>,
}

/// CREATE TASK clause properties.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct TaskCreateOptions {
    /// `EXECUTE AS …` clause, if present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execute_as: Option<TaskExecuteAsClause>,
    /// `AS <body>` clause facts. Always populated for CREATE TASK
    /// since the body clause is mandatory.
    pub body: TaskBodyFacts,
    /// `OVERLAP_POLICY = NO_OVERLAP | ALLOW_CHILD_OVERLAP |
    /// ALLOW_ALL_OVERLAP` clause, if present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overlap_policy: Option<TaskOverlapPolicy>,
    /// Deprecated `ALLOW_OVERLAPPING_EXECUTION = TRUE | FALSE` clause,
    /// present only when OVERLAP_POLICY is also absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_overlapping_execution: Option<bool>,
}

/// Content of the EXECUTE AS clause. Present when the clause is written.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct TaskExecuteAsClause {}

/// Properties of the AS body clause in a CREATE TASK statement.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct TaskBodyFacts {
    pub parse: TaskBodyParseStatus,
}

impl Default for TaskBodyFacts {
    fn default() -> Self {
        Self {
            parse: TaskBodyParseStatus::Parsed,
        }
    }
}

/// Whether the task body was successfully parsed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum TaskBodyParseStatus {
    /// Body was parsed successfully.
    Parsed,
    /// Body could not be parsed; only the raw source span is available.
    Unparseable,
}

/// The OVERLAP_POLICY clause value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum TaskOverlapPolicy {
    NoOverlap,
    AllowChildOverlap,
    AllowAllOverlap,
}

/// One action from an ALTER TASK statement.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct TaskAlterAction {
    pub kind: TaskAlterActionKind,
}

/// The action type from an ALTER TASK statement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", schemars(rename = "TaskAlterActionType"))]
pub enum TaskAlterActionKind {
    /// `RESUME`.
    Resume,
    /// `SUSPEND`.
    Suspend,
    /// `ADD AFTER <task>`.
    AddAfter,
    /// `REMOVE AFTER <task>`.
    RemoveAfter,
    /// `SET <property> = <value>`.
    Set,
    /// `SET TAG <tag> = <value>`.
    SetTag,
    /// `SET FINALIZE = <root_task>`.
    SetFinalize,
    /// `UNSET <property>`.
    Unset,
    /// `UNSET TAG <tag>`.
    UnsetTag,
    /// `UNSET FINALIZE`.
    UnsetFinalize,
    /// `MODIFY AS <body>`.
    ModifyAs,
    /// `MODIFY WHEN <expr>`.
    ModifyWhen,
    /// `REMOVE WHEN`.
    RemoveWhen,
}

/// Snowflake CREATE / ALTER / DROP ALERT statement properties.
/// An alert evaluates a scheduled condition query and runs an action
/// statement under the owner's role when it holds — automated SQL on a
/// schedule, the same risk shape as a task.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct AlertFacts {
    /// CREATE ALERT clause properties. Present only when `kind == create_alert`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub create_options: Option<AlertCreateOptions>,
    /// ALTER actions in source order. Empty for CREATE / DROP.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub actions: Vec<AlertAlterAction>,
}

/// CREATE ALERT clause properties.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct AlertCreateOptions {
    /// `WAREHOUSE = …` clause present.
    #[serde(default, skip_serializing_if = "is_false")]
    pub warehouse_set: bool,
    /// `SCHEDULE = …` clause present.
    #[serde(default, skip_serializing_if = "is_false")]
    pub schedule_set: bool,
    /// `IF (EXISTS (…))` condition clause present.
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_condition: bool,
    /// `THEN <action>` body clause facts.
    pub action: AlertBodyFacts,
}

/// Properties of the THEN action body in a CREATE ALERT statement.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct AlertBodyFacts {
    pub parse: AlertBodyParseStatus,
}

impl Default for AlertBodyFacts {
    fn default() -> Self {
        Self {
            parse: AlertBodyParseStatus::Parsed,
        }
    }
}

/// Whether the alert action body was successfully parsed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum AlertBodyParseStatus {
    /// Action body was parsed successfully.
    Parsed,
    /// Action body could not be parsed; only the raw source span is available.
    Unparseable,
}

/// One action from an ALTER ALERT statement.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct AlertAlterAction {
    pub kind: AlertAlterActionKind,
}

/// The action type from an ALTER ALERT statement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", schemars(rename = "AlertAlterActionType"))]
pub enum AlertAlterActionKind {
    /// `RESUME`.
    Resume,
    /// `SUSPEND`.
    Suspend,
    /// `SET <property> = <value>`.
    Set,
    /// `UNSET <property>`.
    Unset,
    /// `MODIFY CONDITION EXISTS (…)`.
    ModifyCondition,
    /// `MODIFY ACTION <statement>`.
    ModifyAction,
}

/// One account-level parameter changed by `ALTER ACCOUNT SET/UNSET`.
/// `name` is the parameter name (upper-cased); `value` is the recognized
/// value text (upper-cased, unquoted) for SET, empty for UNSET. Which
/// (name, value) combinations are dangerous is YAML policy.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct AccountParameter {
    pub name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub value: String,
}

/// Snowflake `ALTER ACCOUNT SET/UNSET <param>` statement properties.
/// Account-level parameters control account-wide security posture
/// (data-unload restrictions, network policy, key rotation, retention).
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct AccountFacts {
    /// Parameters set by `ALTER ACCOUNT SET <name> = <value>`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub parameters_set: Vec<AccountParameter>,
    /// Parameters reset to default by `ALTER ACCOUNT UNSET <name>` (no value).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub parameters_unset: Vec<AccountParameter>,
}

/// Whether a group replicates with failover capability or replication only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum ReplicationGroupKind {
    Replication,
    Failover,
}

/// Snowflake CREATE / DROP REPLICATION GROUP / FAILOVER GROUP properties.
/// `allowed_accounts` lists the target accounts that may replicate this
/// account's objects — the cross-account egress targets.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct ReplicationFailoverGroupFacts {
    /// Replication group vs failover group.
    pub group_kind: ReplicationGroupKind,
    /// `ALLOWED_ACCOUNTS` entries (`org.account`) — the accounts data is
    /// replicated to (cross-account egress targets).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_accounts: Vec<String>,
    /// `OBJECT_TYPES` entries (upper-cased), e.g. `DATABASES`, `ROLES`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub object_types: Vec<String>,
    /// `ALLOWED_DATABASES` entries.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_databases: Vec<String>,
    /// `ALLOWED_SHARES` entries.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_shares: Vec<String>,
    /// Secondary `AS REPLICA OF <source>` form — this account is a
    /// replication target of another account's group.
    #[serde(default, skip_serializing_if = "is_false")]
    pub is_replica: bool,
    /// A `REPLICATION_SCHEDULE` clause was present.
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_replication_schedule: bool,
}

/// Snowflake CREATE / DROP DATA METRIC FUNCTION statement properties.
/// A data metric function returns a NUMBER measuring table data; `secure`
/// hides its definition.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct DataMetricFunctionFacts {
    /// The `SECURE` modifier was present — the function definition is
    /// hidden from users without ownership.
    #[serde(default, skip_serializing_if = "is_false")]
    pub secure: bool,
}

/// Snowflake CREATE / ALTER / DROP DATABASE statement properties.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct DatabaseFacts {
    /// How the database was created. Absent for ALTER / DROP.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub create_origin: Option<DatabaseCreateOrigin>,
    /// ALTER actions in source order. Empty for CREATE / DROP.
    /// Snowflake allows one action per ALTER DATABASE statement.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub actions: Vec<DatabaseAlterAction>,
}

/// How a database was created.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DatabaseCreateOrigin {
    /// `CREATE DATABASE name` with no upstream source.
    Standard,
    /// `CREATE DATABASE name CLONE source [AT|BEFORE (...)]`.
    Clone,
    /// `CREATE DATABASE name FROM SHARE provider.share`.
    FromShare,
    /// `CREATE DATABASE name FROM LISTING listing_name`.
    FromListing,
    /// `CREATE DATABASE name AS REPLICA OF account.db`.
    AsReplica,
    /// `CREATE DATABASE name FROM BACKUP SET ...`.
    FromBackup,
}

/// One action from an ALTER DATABASE statement.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct DatabaseAlterAction {
    pub kind: DatabaseAlterActionKind,
    /// SET PROPERTIES clause content. Present only when `kind == set_properties`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub properties: Option<DatabasePropertiesFacts>,
}

/// The action type from an ALTER DATABASE statement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", schemars(rename = "DatabaseAlterActionType"))]
pub enum DatabaseAlterActionKind {
    /// `RENAME TO <new_name>`.
    RenameTo,
    /// `SWAP WITH <other_db>`.
    SwapWith,
    /// `SET <properties…>` — per-key list at `properties.keys`.
    SetProperties,
    /// `UNSET <properties…>`.
    UnsetProperties,
    /// `SET TAG <tag> = <value>`.
    SetTag,
    /// `UNSET TAG <tag>`.
    UnsetTag,
    /// `SET COMMENT = '<text>'`..
    SetComment,
    /// `UNSET COMMENT`.
    UnsetComment,
    /// `ENABLE REPLICATION TO ACCOUNTS …`.
    EnableReplication,
    /// `DISABLE REPLICATION …`.
    DisableReplication,
    /// `ENABLE FAILOVER TO ACCOUNTS …`.
    EnableFailover,
    /// `DISABLE FAILOVER …`.
    DisableFailover,
    /// `PRIMARY`.
    Primary,
    /// `REFRESH`.
    Refresh,
    /// Clause present but not structurally recognized.
    Opaque,
}

/// Properties set by an `ALTER DATABASE SET <properties…>` clause.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct DatabasePropertiesFacts {
    /// Property keys present in the SET clause.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub keys: Vec<DatabasePropertyKey>,
    /// SQL Server `SET <KEY> { ON | OFF }` switch options present in
    /// the clause (`TRUSTWORTHY ON`, `ENCRYPTION OFF`, …), with their
    /// values.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub switches: Vec<DatabasePropertySwitch>,
    /// The `DATA_RETENTION_TIME_IN_DAYS = <n>` value set by this clause.
    /// Absent when the parameter is omitted or its value is not a plain
    /// integer. A value of `0` disables Time Travel for every object in
    /// the database that uses the database default, so dropped or
    /// modified data cannot be recovered.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data_retention_days: Option<i64>,
}

/// A property key from a database SET clause.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum DatabasePropertyKey {
    /// `DATA_RETENTION_TIME_IN_DAYS = <n>`.
    DataRetentionTimeInDays,
    /// SQL Server `TRUSTWORTHY { ON | OFF }`.
    Trustworthy,
    /// SQL Server `ENCRYPTION { ON | OFF }` — transparent data
    /// encryption for the database.
    Encryption,
    /// SQL Server `DB_CHAINING { ON | OFF }` — cross-database
    /// ownership chaining for this database.
    DbChaining,
    /// Any other property key.
    Other,
}

/// One SQL Server `SET <KEY> { ON | OFF }` switch with its value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct DatabasePropertySwitch {
    pub key: DatabasePropertyKey,
    pub value: DatabaseSwitchValue,
}

/// The ON / OFF half of a SQL Server database switch option.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum DatabaseSwitchValue {
    On,
    Off,
}

/// Snowflake CREATE / ALTER / DROP WAREHOUSE statement properties.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct WarehouseFacts {
    /// `CREATE WAREHOUSE … WAREHOUSE_SIZE = '4X-LARGE'`, `'5X-LARGE'`, or `'6X-LARGE'`.
    #[serde(default, skip_serializing_if = "is_false")]
    pub large_size: bool,
    /// `CREATE WAREHOUSE … WAREHOUSE_TYPE = 'SNOWPARK-OPTIMIZED'`.
    #[serde(default, skip_serializing_if = "is_false")]
    pub snowpark_optimized: bool,
    /// `CREATE WAREHOUSE … AUTO_SUSPEND = 0`.
    #[serde(default, skip_serializing_if = "is_false")]
    pub auto_suspend_zero: bool,
    /// `CREATE WAREHOUSE … RESOURCE_MONITOR = …` clause present.
    #[serde(default, skip_serializing_if = "is_false")]
    pub resource_monitor_set: bool,
    /// `CREATE WAREHOUSE … MAX_CLUSTER_COUNT` or `MIN_CLUSTER_COUNT`
    /// clause present.
    #[serde(default, skip_serializing_if = "is_false")]
    pub multi_cluster: bool,
    /// `ALTER WAREHOUSE … SUSPEND`.
    #[serde(default, skip_serializing_if = "is_false")]
    pub suspended: bool,
    /// `ALTER WAREHOUSE … RESUME`.
    #[serde(default, skip_serializing_if = "is_false")]
    pub resumed: bool,
    /// `ALTER WAREHOUSE … ABORT ALL QUERIES`.
    #[serde(default, skip_serializing_if = "is_false")]
    pub queries_aborted: bool,
    /// `ALTER WAREHOUSE … RENAME TO …`.
    #[serde(default, skip_serializing_if = "is_false")]
    pub renamed: bool,
    /// `ALTER WAREHOUSE … SET …` action present.
    #[serde(default, skip_serializing_if = "is_false")]
    pub set: bool,
    /// `ALTER WAREHOUSE … SET …` whose properties span contains
    /// `WAREHOUSE_SIZE` (case-insensitive).
    #[serde(default, skip_serializing_if = "is_false")]
    pub set_changes_size: bool,
    /// `ALTER WAREHOUSE … SET TAG …` action present.
    #[serde(default, skip_serializing_if = "is_false")]
    pub tag_set: bool,
    /// `ALTER WAREHOUSE … UNSET TAG …` action present.
    #[serde(default, skip_serializing_if = "is_false")]
    pub tag_unset: bool,
}

/// A single credential option from a CREDENTIALS clause.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct StageCredentialOption {
    pub key: IdentName,
    /// String literal value with quotes stripped.
    /// Absent when the value is not a string literal. Masked in the
    /// facts copies attached to reports (see
    /// `crate::facts::StatementFacts::mask_credential_values`).
    pub value_literal: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum DdlAction {
    Create,
    Alter,
    Drop,
    Rename,
    Truncate,
    Comment,
    Refresh,
    /// Databricks/Delta maintenance operations: `VACUUM`, `OPTIMIZE`,
    /// `RESTORE`, `DESCRIBE HISTORY`, `[MSCK] REPAIR TABLE`,
    /// `CACHE [LAZY] TABLE`, `UNCACHE TABLE`. Distinguished from
    /// `Refresh` because these read or rewrite table state via
    /// statement-kind-specific verbs, not the generic `REFRESH` keyword.
    Maintenance,
    /// `SET` / `RESET` / `USE` / session-level configuration.
    Configure,
    /// `IF` / `WHILE` / `TRY-CATCH` body wrapper.
    ControlFlow,
    /// `BEGIN` / `COMMIT` / `ROLLBACK` / `SAVEPOINT`.
    Transaction,
    /// `BULK INSERT` / `COPY INTO TABLE`.
    BulkLoad,
    /// `BACKUP DATABASE` / `BACKUP LOG`.
    Backup,
    /// `RESTORE DATABASE` / `RESTORE LOG`.
    Restore,
    Grant,
    Revoke,
    Execute,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct DdlOptions {
    pub or_replace: bool,
    /// T-SQL `CREATE OR ALTER TRIGGER`.
    pub or_alter: bool,
    pub if_exists: bool,
    pub if_not_exists: bool,
    pub temporary: bool,
    /// Snowflake `CREATE PROCEDURE SCOPED { TEMP | TEMPORARY } TABLE …` — a
    /// table that lives only for the current stored-procedure execution
    /// (also `temporary`).
    #[serde(default, skip_serializing_if = "is_false")]
    pub scoped: bool,
    /// Snowflake `CREATE TRANSIENT …`.
    pub transient: bool,
    /// PG `CREATE … RECURSIVE` etc.
    pub recursive: bool,
    /// `DROP … CASCADE`.
    pub cascade: bool,
    /// `DROP … RESTRICT` (default).
    pub restrict: bool,
    /// Snowflake `CREATE OR REPLACE … COPY GRANTS`.
    pub copy_grants: bool,
    /// Snowflake `CREATE VOLATILE TABLE`.
    pub volatile: bool,
    pub clone_source: Option<ObjectRef>,
    pub like_source: Option<ObjectRef>,
    pub at_or_before: Option<TimeTravelClause>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TimeTravelClause {
    AtTimestamp { value: LiteralValue },
    AtOffset { value: LiteralValue },
    AtStatement { value: IdentName },
    BeforeTimestamp { value: LiteralValue },
    BeforeOffset { value: LiteralValue },
    BeforeStatement { value: IdentName },
}

/// One change inside an ALTER statement.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(tag = "kind", rename_all = "snake_case")]
#[cfg_attr(feature = "schema", schemars(rename = "AlterPropertyChange"))]
pub enum AlterChange {
    // ───────────────── Column shape ─────────────────
    AddColumn(AddColumnFacts),
    DropColumn {
        column: IdentName,
        if_exists: bool,
        cascade: bool,
    },
    RenameColumn {
        from: IdentName,
        to: IdentName,
    },
    SetColumnType {
        column: IdentName,
        from: Option<DataType>,
        to: DataType,
        using: Option<Expr>,
    },
    SetColumnNullability {
        column: IdentName,
        nullable: bool,
    },
    SetColumnDefault {
        column: IdentName,
        default: Option<Expr>,
    },
    DropColumnDefault {
        column: IdentName,
    },
    SetColumnComment {
        column: IdentName,
        comment: Option<String>,
    },
    SetColumnIdentity {
        column: IdentName,
        identity: IdentitySpec,
    },

    // ───────────────── Constraints ─────────────────
    AddConstraint(AddConstraintFacts),
    DropConstraint {
        name: Option<IdentName>,
        constraint_kind: Option<ConstraintKind>,
        if_exists: bool,
        cascade: bool,
    },
    RenameConstraint {
        from: IdentName,
        to: IdentName,
    },
    AlterConstraint {
        name: IdentName,
        change: ConstraintAlteration,
    },

    // ───────────────── Identity / location ─────────────────
    RenameTo {
        to: TableRef,
    },
    SetSchema {
        to: IdentName,
    },
    SwapWith {
        other: TableRef,
    },

    // ───────────────── Tags ─────────────────
    SetTag {
        tag: CatalogTag,
    },
    UnsetTag {
        tag_key: IdentName,
    },

    // ───────────────── Properties / comments ─────────────────
    SetProperty {
        name: IdentName,
        value: LiteralValue,
    },
    UnsetProperty {
        name: IdentName,
    },
    SetComment {
        target: CommentTarget,
        comment: String,
    },
    UnsetComment {
        target: CommentTarget,
    },

    // ───────────────── Policy attachment ─────────────────
    AttachMaskingPolicy(AttachMaskingPolicyFacts),
    DetachMaskingPolicy {
        columns: Vec<IdentName>,
    },
    AttachRowAccessPolicy(AttachRowAccessPolicyFacts),
    DetachRowAccessPolicy {
        policy: Option<ObjectRef>,
    },
    DropAllRowAccessPolicies,
    AttachAggregationPolicy {
        policy: ObjectRef,
    },
    DetachAggregationPolicy {
        policy: Option<ObjectRef>,
    },
    AttachProjectionPolicy {
        policy: ObjectRef,
        columns: Vec<IdentName>,
    },
    DetachProjectionPolicy {
        columns: Vec<IdentName>,
    },

    // ───────────────── Performance / lifecycle ─────────────────
    SetClusteringKey {
        columns: Vec<Expr>,
    },
    DropClusteringKey,
    SuspendRecluster,
    ResumeRecluster,
    AddSearchOptimization {
        config: SearchOptimizationConfig,
    },
    DropSearchOptimization {
        config: SearchOptimizationConfig,
    },
    Refresh {
        copy_grants: bool,
    },
    /// Resume task / pipe / stream.
    Resume,
    /// Suspend task / pipe / stream.
    Suspend,
    /// Execute task once.
    Execute,
    /// Dialect-specific `MODIFY` clause body.
    Modify(ModifyKind),

    // ───────────────── Opaque escape ─────────────────
    /// Change present but not structurally typed. `reason` identifies the cause;
    /// `rendered` is display-only source text.
    Opaque {
        reason: OpaqueAlterReason,
        rendered: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", schemars(rename = "UnknownAlterReason"))]
pub enum OpaqueAlterReason {
    DialectSpecificProperty,
    UnparsedRemainder,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CommentTarget {
    /// The table / object as a whole.
    TableLevel,
    /// A specific column.
    ColumnLevel { column: IdentName },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct AddColumnFacts {
    pub column: IdentName,
    pub data_type: DataType,
    pub nullable: bool,
    pub default: Option<Expr>,
    pub identity: Option<IdentitySpec>,
    /// Generated / computed column expression.
    pub computed: Option<Expr>,
    pub virtual_: bool,
    pub primary_key: bool,
    pub unique: bool,
    pub references: Option<ColumnReference>,
    pub check: Option<Expr>,
    pub collate: Option<IdentName>,
    pub masking_policy: Option<AttachMaskingPolicyFacts>,
    pub tags: Vec<CatalogTag>,
    pub comment: Option<String>,
    pub if_not_exists: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct AddConstraintFacts {
    pub name: Option<IdentName>,
    pub constraint_kind: ConstraintKind,
    pub columns: Vec<IdentName>,
    pub references: Option<ColumnReference>,
    pub check: Option<Expr>,
    pub deferrable: bool,
    pub initially_deferred: bool,
    pub enforced: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", schemars(rename = "ConstraintType"))]
pub enum ConstraintKind {
    PrimaryKey,
    ForeignKey,
    Unique,
    Check,
    NotNull,
    Default,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ConstraintAlteration {
    EnableEnforced,
    DisableEnforced,
    SetDeferrable {
        deferrable: bool,
        initially_deferred: bool,
    },
    Validate,
    NoValidate,
    Rely,
    NoRely,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct ColumnReference {
    pub target_table: TableRef,
    pub target_columns: Vec<IdentName>,
    pub on_delete: Option<ReferentialAction>,
    pub on_update: Option<ReferentialAction>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum ReferentialAction {
    NoAction,
    Restrict,
    Cascade,
    SetNull,
    SetDefault,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct AttachMaskingPolicyFacts {
    pub policy: ObjectRef,
    pub columns: Vec<IdentName>,
    pub using: Vec<IdentName>,
    pub force: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct AttachRowAccessPolicyFacts {
    pub policy: ObjectRef,
    pub on_columns: Vec<IdentName>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ModifyKind {
    /// Snowflake `ALTER TABLE … MODIFY COLUMN …` shape.
    SnowflakeColumn {
        column: IdentName,
        changes: Vec<ColumnModifyChange>,
    },
    /// MSSQL `ALTER TABLE … ALTER COLUMN …` shape.
    MssqlColumn {
        column: IdentName,
        data_type: DataType,
        nullable: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(tag = "kind", rename_all = "snake_case")]
#[cfg_attr(feature = "schema", schemars(rename = "ColumnModification"))]
pub enum ColumnModifyChange {
    SetMaskingPolicy(AttachMaskingPolicyFacts),
    UnsetMaskingPolicy,
    SetTag { tag: CatalogTag },
    UnsetTag { tag_key: IdentName },
    SetNotNull,
    DropNotNull,
    SetType { data_type: DataType },
    SetDefault { default: Expr },
    DropDefault,
    SetComment { comment: String },
    UnsetComment,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct IdentitySpec {
    pub start: i64,
    pub increment: i64,
    pub minvalue: Option<i64>,
    pub maxvalue: Option<i64>,
    pub cycle: bool,
    pub generated_kind: GeneratedKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", schemars(rename = "GeneratedColumnType"))]
pub enum GeneratedKind {
    Always,
    ByDefault,
    ByDefaultOnNull,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct SearchOptimizationConfig {
    pub on_columns: Vec<IdentName>,
    pub kind: SearchOptimizationKind,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum SearchOptimizationKind {
    Equality,
    Substring,
    GeoSpatial,
    Other(IdentName),
}
