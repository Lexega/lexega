// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Top-level `StatementFacts` carrier and `StatementKind` taxonomy.

use serde::{Deserialize, Serialize};

#[cfg(feature = "schema")]
use schemars::JsonSchema;

use crate::lexer::token::Span;

use super::add_signature::MssqlAddSignatureFacts;
use super::algebra::AlgebraFacts;
use super::assembly::MssqlAssemblyFacts;
use super::backup::MssqlBackupFacts;
use super::comment::CommentOnFacts;
use super::dbcc::MssqlDbccFacts;
use super::ddl::DdlFacts;
use super::diff::DiffFacts;
use super::handler::HandlerFacts;
use super::integration::IntegrationFacts;
use super::key_backup::MssqlKeyBackupFacts;
use super::key_management::MssqlKeyManagementFacts;
use super::pg_copy::PgCopyFacts;
use super::pg_default_privileges::PgDefaultPrivilegesFacts;
use super::policy::PolicyFacts;
use super::policy_attachment::PolicyAttachmentFacts;
use super::privilege::PrivilegeFacts;
use super::query::QueryFacts;
use super::restore::MssqlRestoreFacts;
use super::script_context::ScriptContext;
use super::security_policy::MssqlSecurityPolicyFacts;
use super::service_master_key::MssqlServiceMasterKeyFacts;
use super::use_stmt::UseFacts;

/// All facts extracted from a single SQL statement.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct StatementFacts {
    pub kind: StatementKind,
    pub source_span: Option<Span>,

    pub query: Option<QueryFacts>,
    pub ddl: Option<DdlFacts>,
    pub privilege: Option<PrivilegeFacts>,
    pub policy: Option<PolicyFacts>,
    /// `ALTER USER/ACCOUNT { SET | UNSET } AUTHENTICATION POLICY …` —
    /// principal-policy attachment events. Omitted for non-attachment
    /// statements.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_attachment: Option<PolicyAttachmentFacts>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub integration: Option<IntegrationFacts>,
    /// `USE { ROLE | DATABASE | CATALOG | SCHEMA | WAREHOUSE |
    /// SECONDARY ROLES } …` session-context statements. Omitted for
    /// non-USE statements.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub use_stmt: Option<UseFacts>,
    /// PostgreSQL COPY statement properties. Absent for non-COPY statements.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pg_copy: Option<PgCopyFacts>,
    /// T-SQL `BACKUP { DATABASE | LOG }` properties. Absent for non-BACKUP
    /// statements.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mssql_backup: Option<MssqlBackupFacts>,
    /// T-SQL `RESTORE { DATABASE | LOG }` properties. Absent for non-RESTORE
    /// statements.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mssql_restore: Option<MssqlRestoreFacts>,
    /// T-SQL `DBCC <command>` properties. Absent for non-DBCC statements.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mssql_dbcc: Option<MssqlDbccFacts>,
    /// T-SQL `OPEN`/`CLOSE` encryption-key activation properties. Absent for
    /// non-key-context statements.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mssql_key_management: Option<MssqlKeyManagementFacts>,
    /// T-SQL `CREATE`/`ALTER SECURITY POLICY` (Row-Level Security) properties.
    /// Absent for non-security-policy statements.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mssql_security_policy: Option<MssqlSecurityPolicyFacts>,
    /// T-SQL `BACKUP`/`RESTORE` key-material properties. Absent for
    /// non-key-backup statements.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mssql_key_backup: Option<MssqlKeyBackupFacts>,
    /// T-SQL `CREATE`/`ALTER ASSEMBLY` (CLR) properties. Absent for
    /// non-assembly statements.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mssql_assembly: Option<MssqlAssemblyFacts>,
    /// T-SQL `ADD [COUNTER] SIGNATURE` (module signing) properties. Absent for
    /// non-signature statements.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mssql_add_signature: Option<MssqlAddSignatureFacts>,
    /// T-SQL `ALTER SERVICE MASTER KEY` properties. Absent for non-SMK
    /// statements.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mssql_service_master_key: Option<MssqlServiceMasterKeyFacts>,
    /// PostgreSQL `ALTER DEFAULT PRIVILEGES` properties. Absent for all other
    /// statements.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pg_default_privileges: Option<PgDefaultPrivilegesFacts>,
    /// COMMENT ON statement properties. Absent for non-COMMENT statements.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<CommentOnFacts>,
    /// DECLARE HANDLER statement properties. Absent for non-handler statements.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handler: Option<HandlerFacts>,

    /// Dynamic-SQL call sites at this statement. Populated for:
    ///
    /// - Statements that ARE a dynamic-SQL surface (top-level
    ///   `EXECUTE IMMEDIATE`, T-SQL `EXEC` / `sp_executesql`,
    ///   PostgreSQL `PREPARE`) — one entry per statement classifying
    ///   argument shape and parameterization.
    /// - Query statements (SELECT / INSERT / UPDATE / DELETE / MERGE)
    ///   whose expressions invoke cross-server dynamic-SQL functions
    ///   (`dblink_exec`, etc.) — one entry per call site.
    ///
    /// For dynamic SQL inside a procedure or function body, see
    /// `ddl.procedure.body.dynamic_sql_calls` /
    /// `ddl.function.body.dynamic_sql_calls`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dynamic_sql_calls: Vec<super::ddl::DynamicSqlCall>,

    /// T-SQL `EXEC[UTE]` procedure-call identity. Populated only for
    /// statements with [`StatementKind::MssqlExec`] (both the
    /// dynamic-SQL `EXEC(@sql)` form and ordinary
    /// `EXEC proc_name args`). Carries the lowercased procedure name
    /// and argument text so rules can predicate on specific dangerous
    /// procedures (e.g., `xp_cmdshell`, `sp_configure
    /// 'xp_cmdshell'`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mssql_exec: Option<super::ddl::MssqlExecFacts>,

    /// Execution-context impersonation properties. Populated for
    /// statements with [`StatementKind::MssqlExecuteAs`] (`EXECUTE AS
    /// LOGIN/USER = …`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub impersonation: Option<super::ddl::ImpersonationFacts>,

    /// `EXECUTE IMMEDIATE FROM <file>` properties — SQL loaded and run
    /// from a stage file. Populated only for statements with
    /// [`StatementKind::ExecuteImmediateFrom`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execute_immediate_from: Option<super::ddl::ExecuteImmediateFromFacts>,

    /// Audit-object lifecycle properties. Populated for statements
    /// with [`StatementKind::MssqlCreateAudit`] / `MssqlAlterAudit` /
    /// `MssqlDropAudit`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit: Option<super::ddl::AuditFacts>,

    /// Security-object (key / certificate / credential) lifecycle
    /// properties. Populated for statements with
    /// [`StatementKind::MssqlCreateSecurityObject`] /
    /// `MssqlAlterSecurityObject` / `MssqlDropSecurityObject`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub security_object: Option<super::ddl::SecurityObjectFacts>,

    pub algebra: AlgebraFacts,

    pub script_context: ScriptContext,
    pub diff: Option<DiffFacts>,
}

/// The kind of SQL statement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", schemars(rename = "StatementType"))]
pub enum StatementKind {
    // ───────────── Query-bearing DML ─────────────
    Select,
    SetSelect,
    Insert,
    Update,
    Delete,
    Merge,
    MultiInsert,

    // ───────────── Table DDL ─────────────
    CreateTable,
    AlterTable,
    DropTable,
    Truncate,
    RenameTable,
    CloneTable,
    /// `UNDROP TABLE name` — Snowflake Time Travel recovery of a
    /// previously-dropped table.
    UndropTable,
    /// `DROP ALL ROW ACCESS POLICIES <table>` — removes all row access policies
    /// attached to a table in a single operation.
    DropAllRowAccessPolicies,

    // ───────────── View DDL ─────────────
    CreateView,
    AlterView,
    DropView,

    // ───────────── Materialized view DDL ─────────────
    CreateMaterializedView,
    AlterMaterializedView,
    DropMaterializedView,

    // ───────────── Index DDL ─────────────
    /// `CREATE [UNIQUE] INDEX [CONCURRENTLY] [IF NOT EXISTS] name ON
    /// table [USING method] (columns)` — general SQL CREATE INDEX.
    CreateIndex,
    /// `ALTER INDEX name …` — index modification (rename, rebuild, or property change).
    AlterIndex,
    /// `CREATE SYNONYM name FOR object` — a named alias for a base object
    /// (the referent may be a four-part linked-server name).
    CreateSynonym,

    // ───────────── Schema DDL ─────────────
    CreateSchema,
    AlterSchema,
    DropSchema,
    RenameSchema,
    CloneSchema,
    /// `UNDROP SCHEMA name` — Snowflake Time Travel recovery of a
    /// previously-dropped schema.
    UndropSchema,

    // ───────────── Database DDL ─────────────
    CreateDatabase,
    AlterDatabase,
    DropDatabase,
    RenameDatabase,
    CloneDatabase,
    /// `UNDROP DATABASE name` — Snowflake Time Travel recovery of a
    /// previously-dropped database.
    UndropDatabase,

    // ───────────── Catalog DDL (Databricks Unity Catalog) ─────────────
    CreateCatalog,
    AlterCatalog,
    DropCatalog,

    // ───────────── Volume DDL (Databricks Unity Catalog) ─────────────
    CreateVolume,
    AlterVolume,
    DropVolume,

    // ───────────── External Location DDL (Databricks Unity Catalog) ─────────────
    CreateExternalLocation,
    AlterExternalLocation,
    DropExternalLocation,

    // ───────────── Connection DDL (Databricks Unity Catalog) ─────────────
    CreateConnection,
    AlterConnection,
    DropConnection,

    // ───────── External Data Source DDL (T-SQL / PolyBase) ─────────
    CreateExternalDataSource,
    AlterExternalDataSource,

    // ───────── Foreign Server DDL (SQL/MED — PostgreSQL FDW) ─────────
    CreateForeignServer,
    AlterForeignServer,

    // ───────── Server Configuration DDL (T-SQL instance config) ─────────
    AlterServerConfiguration,

    // ───────── User Mapping DDL (SQL/MED — PostgreSQL FDW) ─────────
    CreateUserMapping,
    AlterUserMapping,
    DropUserMapping,

    // ───────── Foreign Table DDL (SQL/MED — PostgreSQL FDW) ─────────
    CreateForeignTable,
    /// `IMPORT FOREIGN SCHEMA` — bulk remote-table import.
    ImportForeignSchema,

    // ───────────── Flow DDL (Databricks Lakeflow) ─────────────
    CreateFlow,

    // ───────────── Privilege ─────────────
    Grant,
    Revoke,
    Deny,

    // ───────────── Policy DDL (24 variants: 3 actions × 8 policy kinds) ─────────────
    CreateMaskingPolicy,
    AlterMaskingPolicy,
    DropMaskingPolicy,
    CreateRowAccessPolicy,
    AlterRowAccessPolicy,
    DropRowAccessPolicy,
    CreateNetworkPolicy,
    AlterNetworkPolicy,
    DropNetworkPolicy,
    CreateSessionPolicy,
    AlterSessionPolicy,
    DropSessionPolicy,
    /// `ALTER SESSION { SET | UNSET }` — session-parameter mutation
    /// (distinct from altering a session-policy object).
    AlterSession,
    CreatePasswordPolicy,
    AlterPasswordPolicy,
    DropPasswordPolicy,
    CreateAggregationPolicy,
    AlterAggregationPolicy,
    DropAggregationPolicy,
    CreateProjectionPolicy,
    AlterProjectionPolicy,
    DropProjectionPolicy,
    CreateJoinPolicy,
    AlterJoinPolicy,
    DropJoinPolicy,
    CreateDataMetricFunction,
    DropDataMetricFunction,
    CreateAuthenticationPolicy,
    AlterAuthenticationPolicy,
    DropAuthenticationPolicy,

    // ───────────── Procedural DDL ─────────────
    CreateProcedure,
    AlterProcedure,
    DropProcedure,
    CreateFunction,
    AlterFunction,
    DropFunction,
    /// Snowflake `CREATE EXTERNAL FUNCTION` — a UDF that ships row data to an
    /// external HTTPS endpoint via an API integration (data egress).
    CreateExternalFunction,
    CreateTrigger,
    AlterTrigger,
    DropTrigger,

    // ───────────── Stage / integration / warehouse / task ─────────────
    CreateStage,
    AlterStage,
    DropStage,
    CreateApiIntegration,
    AlterApiIntegration,
    DropApiIntegration,
    CreateStorageIntegration,
    AlterStorageIntegration,
    DropStorageIntegration,
    // ───────────── Storage credential (Databricks Unity Catalog) ─────────────
    CreateStorageCredential,
    AlterStorageCredential,
    DropStorageCredential,
    CreateWarehouse,
    AlterWarehouse,
    DropWarehouse,
    CreateTask,
    AlterTask,
    DropTask,

    // ───────────── Snowflake / dialect-specific ─────────────
    CreateDynamicTable,
    AlterDynamicTable,
    DropDynamicTable,
    CreateNotificationIntegration,
    AlterNotificationIntegration,
    DropNotificationIntegration,
    CreateExternalTable,
    AlterExternalTable,
    DropExternalTable,
    /// Redshift `CREATE EXTERNAL SCHEMA … FROM { DATA CATALOG | HIVE METASTORE | … }` (Spectrum / federated)
    CreateExternalSchema,
    CreateExternalAccessIntegration,
    AlterExternalAccessIntegration,
    DropExternalAccessIntegration,
    CreateNetworkRule,
    AlterNetworkRule,
    DropNetworkRule,
    CreateResourceMonitor,
    AlterResourceMonitor,
    DropResourceMonitor,
    CreateComputePool,
    AlterComputePool,
    DropComputePool,
    CreateGitRepository,
    AlterGitRepository,
    DropGitRepository,
    CreateImageRepository,
    AlterImageRepository,
    DropImageRepository,
    CreateStreamlit,
    AlterStreamlit,
    DropStreamlit,
    CreateService,
    AlterService,
    DropService,
    CreateNotebook,
    AlterNotebook,
    DropNotebook,
    CreateSemanticView,
    AlterSemanticView,
    DropSemanticView,
    CreateCortexSearchService,
    AlterCortexSearchService,
    DropCortexSearchService,
    CreateApplication,
    AlterApplication,
    DropApplication,
    CreateApplicationPackage,
    AlterApplicationPackage,
    DropApplicationPackage,
    CreateListing,
    AlterListing,
    DropListing,
    CreateManagedAccount,
    DropManagedAccount,
    CreateAccount,
    DropAccount,
    StagePut,
    StageGet,
    StageRemove,
    StageList,
    CreateAlert,
    AlterAlert,
    DropAlert,
    CreateTag,
    AlterTag,
    DropTag,
    /// `UNDROP TAG name` — Snowflake Time Travel recovery of a
    /// previously-dropped tag.
    UndropTag,
    CreateFileFormat,
    AlterFileFormat,
    /// `DROP FILE FORMAT name` — routed through the generic DROP parser;
    /// gated to the FILE FORMAT object type.
    DropFileFormat,
    CreateSecret,
    AlterSecret,
    /// `DROP SECRET name` — routed through the generic DROP parser;
    /// surfaced as its own kind for rule targeting.
    DropSecret,
    CreateSequence,
    AlterSequence,
    DropSequence,
    CreatePipe,
    AlterPipe,
    DropPipe,
    CreateStream,
    AlterStream,
    DropStream,
    CreateRole,
    AlterRole,
    DropRole,
    CreateUser,
    AlterUser,
    DropUser,
    /// Redshift `CREATE GROUP <name>` — legacy permission group.
    CreateGroup,
    /// Redshift `ALTER GROUP <name> { ADD | DROP } USER … | RENAME TO …`.
    AlterGroup,
    /// Snowflake `ALTER ACCOUNT { SET | UNSET } AUTHENTICATION POLICY …`
    /// — account-level authentication policy attachment, or generic
    /// `ALTER ACCOUNT SET <property> = <value>` (NETWORK_POLICY,
    /// DATA_RETENTION_TIME_IN_DAYS, PERIODIC_DATA_REKEYING, …).
    AlterAccount,
    /// Snowflake `CREATE [OR REPLACE] SHARE [IF NOT EXISTS] <name> [COMMENT = '<text>']`
    CreateShare,
    /// `DROP SHARE name` — routed through the generic DROP parser;
    /// surfaced as its own kind for rule targeting.
    DropShare,
    /// Snowflake `ALTER SHARE [IF EXISTS] <name> { ADD | REMOVE | SET } ACCOUNTS = …`
    AlterShare,
    /// Redshift `CREATE [OR REPLACE] DATASHARE [IF NOT EXISTS] <name>` (cross-account data sharing)
    CreateDatashare,
    /// Redshift `ALTER DATASHARE <name> { ADD | REMOVE } { TABLE | SCHEMA } … | SET …`
    AlterDatashare,
    /// Snowflake `CREATE [OR REPLACE] SECURITY INTEGRATION [IF NOT EXISTS] <name> TYPE = … …`
    CreateSecurityIntegration,
    /// `DROP SECURITY INTEGRATION name` — routed through the generic
    /// DROP parser; surfaced as its own kind for rule targeting.
    DropSecurityIntegration,
    /// Snowflake `ALTER SECURITY INTEGRATION [IF EXISTS] <name> …`
    AlterSecurityIntegration,
    /// Snowflake `ALTER REPLICATION GROUP [IF EXISTS] <name> …`
    AlterReplicationGroup,
    /// Snowflake `ALTER FAILOVER GROUP [IF EXISTS] <name> …`
    AlterFailoverGroup,
    /// Snowflake `CREATE REPLICATION GROUP …`
    CreateReplicationGroup,
    /// Snowflake `DROP REPLICATION GROUP …`
    DropReplicationGroup,
    /// Snowflake `CREATE FAILOVER GROUP …`
    CreateFailoverGroup,
    /// Snowflake `DROP FAILOVER GROUP …`
    DropFailoverGroup,

    // ───────────── Bulk load / copy ─────────────
    BulkInsert,
    CopyIntoTable,
    CopyIntoLocation,
    /// Redshift `UNLOAD ('query') TO 's3://...'` — exports query results to
    /// an external location, the unload counterpart to COPY.
    RedshiftUnload,
    /// Redshift `COPY <table> FROM 's3://...'` — bulk-loads an external object
    /// store into a table, the load counterpart to UNLOAD.
    RedshiftCopy,

    // ───────────── Session / transaction ─────────────
    Use,
    /// `SHOW <objects> [LIKE …] [IN …]` — metadata introspection.
    Show,
    Set,
    Reset,
    BeginTransaction,
    Commit,
    Rollback,
    Savepoint,
    Comment,

    // ───────────── Dynamic SQL ─────────────
    Explain,
    ExecuteImmediate,
    /// Snowflake `EXECUTE IMMEDIATE FROM <file>` — runs SQL loaded from a
    /// stage file (external/file-based code execution).
    ExecuteImmediateFrom,
    Exec,

    // ───────────── PG-specific ─────────────
    /// T-SQL `BACKUP { DATABASE | LOG } … TO { DISK | URL | TAPE } = …`
    /// data-protection utility.
    MssqlBackup,
    /// T-SQL `RESTORE { DATABASE | LOG } … FROM { DISK | URL | TAPE } = …`
    /// data-protection utility.
    MssqlRestore,
    /// T-SQL `DBCC <command>` database console / maintenance command.
    MssqlDbcc,
    /// T-SQL `OPEN`/`CLOSE { MASTER KEY | SYMMETRIC KEY | ALL SYMMETRIC KEYS }`
    /// encryption-key activation.
    MssqlKeyManagement,
    /// T-SQL `CREATE`/`ALTER SECURITY POLICY` (Row-Level Security).
    MssqlSecurityPolicy,
    /// T-SQL `BACKUP`/`RESTORE { SERVICE MASTER KEY | MASTER KEY | CERTIFICATE
    /// | ASYMMETRIC KEY }` key-material protection.
    MssqlKeyBackup,
    /// T-SQL `CREATE`/`ALTER ASSEMBLY` (CLR assembly registration).
    MssqlAssembly,
    /// T-SQL `ADD [COUNTER] SIGNATURE` (module signing).
    MssqlAddSignature,
    /// T-SQL `SETUSER` (legacy database-context impersonation).
    MssqlSetuser,
    /// T-SQL `ALTER SERVICE MASTER KEY` (encryption-root rotation).
    MssqlServiceMasterKey,
    /// PostgreSQL `ALTER DEFAULT PRIVILEGES` (default-grant policy on future
    /// objects).
    PgDefaultPrivileges,
    /// PostgreSQL `COPY <table_or_query> { FROM | TO } …` data-movement
    /// utility.
    PgCopy,
    PgCreateExtension,
    PgAlterExtension,
    PgDropExtension,
    PgCreateDomain,
    PgAlterDomain,
    PgDropDomain,
    PgCreateType,
    PgAlterType,
    PgDropType,
    /// `UNDROP TYPE name` — Snowflake Time Travel recovery of a
    /// previously-dropped user-defined type.
    UndropType,
    /// PostgreSQL `DROP SEQUENCE [IF EXISTS] name [, ...] [CASCADE |
    /// RESTRICT]`.
    PgDropSequence,
    PgCreateSubscription,
    PgAlterSubscription,
    PgDropSubscription,
    PgCreatePublication,
    PgAlterPublication,
    PgDropPublication,
    PgCreateRule,
    PgAlterRule,
    PgDropRule,
    /// PostgreSQL `DROP OWNED BY role [, ...] [CASCADE | RESTRICT]` —
    /// mass-drop every object owned by the listed roles.
    PgDropOwned,
    /// PostgreSQL `REASSIGN OWNED BY old_role [, ...] TO new_role` —
    /// transfers ownership of all objects.
    PgReassignOwned,
    /// PostgreSQL `CREATE TABLESPACE name [OWNER role] LOCATION '…'`.
    PgCreateTablespace,
    /// PostgreSQL `ALTER TABLESPACE name { RENAME TO new | OWNER TO
    /// new_owner | SET (option = value [, …]) | RESET (option [, …]) }`.
    PgAlterTablespace,
    /// PostgreSQL `DROP TABLESPACE [IF EXISTS] name`.
    PgDropTablespace,
    /// PostgreSQL `CREATE/ALTER/DROP PUBLICATION …` (logical
    /// replication source).
    PgPublication,
    /// PostgreSQL `CREATE/ALTER/DROP SUBSCRIPTION …` (logical
    /// replication sink).
    PgSubscription,
    /// PostgreSQL `ALTER SYSTEM { SET param = value | RESET param |
    /// RESET ALL }` — server-wide configuration.
    PgAlterSystem,
    /// PostgreSQL `LOCK [TABLE] name [, …] [IN mode MODE] [NOWAIT]` —
    /// explicit table-level lock acquisition.
    PgLockTable,
    /// PostgreSQL `DROP INDEX [CONCURRENTLY] [IF EXISTS] name [, ...]
    /// [CASCADE | RESTRICT]`. Cascade
    /// flows through the shared `ddl.options.cascade` flag.
    PgDropIndex,
    /// PostgreSQL `CREATE [CONSTRAINT] TRIGGER name { BEFORE | AFTER |
    /// INSTEAD OF } event ON table ...`.
    PgCreateTrigger,
    /// PostgreSQL `ALTER TRIGGER name ON table { RENAME TO new_name |
    /// [NO] DEPENDS ON EXTENSION ext }`.
    PgAlterTrigger,
    /// PostgreSQL `DROP TRIGGER [IF EXISTS] name ON table [CASCADE | RESTRICT]`.
    /// Cascade flows through the shared `ddl.options.cascade` flag.
    PgDropTrigger,
    /// PostgreSQL `ALTER TABLE [IF EXISTS] [ONLY] name [*]
    /// { ENABLE [ALWAYS|REPLICA] | DISABLE } TRIGGER { name | ALL | USER }` —
    /// enables or disables triggers on a table.
    PgAlterTableTriggerState,
    /// PostgreSQL `CREATE { ROLE | USER } name [WITH option [, ...]]`.
    PgCreateRole,
    /// PostgreSQL `ALTER { ROLE | USER } name { WITH options | RENAME TO new
    /// | SET cfg }`.
    PgAlterRole,
    /// PostgreSQL `DROP { ROLE | USER } [IF EXISTS] name [, ...]`.
    PgDropRole,
    /// PostgreSQL `SET [LOCAL | SESSION] parameter { TO | = } value` — session parameter assignment.
    PgSet,
    /// PostgreSQL `DISCARD { ALL | PLANS | SEQUENCES | TEMP }` —
    /// resets session state.
    PgDiscard,
    /// PostgreSQL `CREATE POLICY name ON table ...` — row-level security policy creation.
    PgCreatePolicy,
    /// PostgreSQL `ALTER POLICY name ON table { RENAME TO ... | ... }` — row-level security
    /// policy modification.
    PgAlterPolicy,
    /// PostgreSQL `DROP POLICY [IF EXISTS] name ON table [CASCADE | RESTRICT]` — row-level
    /// security policy removal.
    PgDropPolicy,
    /// PostgreSQL `REFRESH MATERIALIZED VIEW [CONCURRENTLY] name [WITH [NO] DATA]`.
    PgRefreshMatview,
    /// PostgreSQL `REINDEX { INDEX | TABLE | SCHEMA | DATABASE | SYSTEM } name`.
    PgReindex,
    /// PostgreSQL `DO [LANGUAGE name] $$ ... $$` — anonymous procedural code block.
    DoBlock,
    /// PostgreSQL `ANALYZE [VERBOSE] [table [(column, ...)]]` — refreshes table statistics.
    AnalyzeStmt,
    /// PostgreSQL `CLUSTER [VERBOSE] [table [USING index]]` — physically
    /// reorders a table according to an index.
    PgCluster,
    /// PostgreSQL `LISTEN channel` — subscribes the session to a notification channel.
    PgListen,
    /// PostgreSQL `NOTIFY channel [, payload]` — send a notification on
    /// a channel.
    PgNotify,
    /// PostgreSQL `UNLISTEN { channel | * }` — unsubscribes the session from a notification channel.
    PgUnlisten,
    /// PostgreSQL `PREPARE name [(types)] AS <stmt>` (also MySQL
    /// `PREPARE name FROM <expr>`) — defines a prepared statement.
    /// The MySQL FROM-expression form is a dynamic-SQL surface and
    /// drives DYNSQL-* rules; the PostgreSQL AS-statement form is not.
    PgPrepare,
    /// PostgreSQL `EXECUTE prepared_name [(arg1, ...)]` — invoke a
    /// previously PREPARE'd statement.
    PgExecute,
    /// PostgreSQL `DEALLOCATE [PREPARE] {prepared_name | ALL}` — drop
    /// a prepared statement.
    PgDeallocate,
    /// PostgreSQL `CREATE AGGREGATE …` — user-defined aggregate function.
    PgCreateAggregate,
    /// PostgreSQL `CREATE OPERATOR …` — user-defined operator.
    PgCreateOperator,

    // ───────────── MySQL-specific ─────────────
    MysqlLoadData,
    /// MySQL `CREATE EVENT` — a scheduled SQL job.
    CreateEvent,
    /// MySQL `ALTER EVENT` — reschedule / enable / rename / rebind body.
    AlterEvent,
    /// MySQL `CREATE TRIGGER` — an inline-body trigger on a row event.
    CreateMysqlTrigger,

    // ───────────── BigQuery-specific ─────────────
    BqExportData,
    BqLoadData,
    BqAssert,
    BqCreateModel,
    BqAlterModel,
    BqDropModel,
    /// `EXPORT MODEL name OPTIONS(URI = ...)` — BQML model artifact export.
    BqExportModel,
    /// `CREATE SNAPSHOT TABLE` — BigQuery point-in-time table clone.
    BqCreateSnapshotTable,
    /// `DROP SNAPSHOT TABLE` — BigQuery snapshot teardown.
    BqDropSnapshotTable,
    /// `CREATE SEARCH INDEX` — BigQuery full-text search index.
    BqCreateSearchIndex,
    /// `DROP SEARCH INDEX` — BigQuery search-index removal.
    BqDropSearchIndex,
    /// `CREATE VECTOR INDEX` — BigQuery ML embedding similarity index.
    BqCreateVectorIndex,
    /// `ALTER VECTOR INDEX` — BigQuery vector-index reconfiguration / REBUILD.
    BqAlterVectorIndex,
    /// `DROP VECTOR INDEX` — BigQuery vector-index removal.
    BqDropVectorIndex,

    // ───────────── Databricks-specific ─────────────
    DbxOptimize,
    DbxVacuum,
    DbxRestore,
    DbxClone,
    /// `DESCRIBE HISTORY <table>` — provenance log read on a Delta table.
    DbxDescribeHistory,
    /// `[MSCK] REPAIR TABLE <table> [{ADD|DROP|SYNC} PARTITIONS]` —
    /// Hive-metastore partition recovery.
    DbxRepairTable,
    /// `CACHE [LAZY] TABLE <table> [OPTIONS ...] [[AS] <query>]` —
    /// Spark in-memory caching.
    DbxCacheTable,
    /// `UNCACHE TABLE [IF EXISTS] <table>` — Spark cache eviction.
    DbxUncacheTable,

    /// Cross-dialect `CALL <procedure>(args)` — Snowflake, BigQuery,
    /// PostgreSQL, MySQL, Databricks. Dialect-neutral counterpart to
    /// [`Self::MssqlExec`]. Carries inter-procedural dynamic-SQL
    /// findings when the called procedure's body contains a sink.
    Call,

    // ───────────── MSSQL-specific ─────────────
    MssqlExec,
    /// T-SQL `RECONFIGURE [WITH OVERRIDE]` — applies pending
    /// `sp_configure` server option changes to the running configuration.
    Reconfigure,
    MssqlBulkInsert,
    MssqlSetOption,
    /// T-SQL `DROP TRIGGER [IF EXISTS] name [, …] [ON { DATABASE |
    /// ALL SERVER }]` — drops a DML, DDL, or logon trigger. Distinct
    /// from PostgreSQL `DROP TRIGGER … ON <table>` because the syntax
    /// and scope differ (database/server vs table).
    MssqlDropTrigger,
    /// T-SQL `CREATE EXTERNAL MODEL` — register an external AI
    /// endpoint (SQL Server 2025).
    MssqlCreateExternalModel,
    /// T-SQL `ALTER EXTERNAL MODEL`.
    MssqlAlterExternalModel,
    /// T-SQL `DROP EXTERNAL MODEL`.
    MssqlDropExternalModel,
    /// T-SQL `CREATE LOGIN` — server-level authentication principal.
    MssqlCreateLogin,
    /// T-SQL `CREATE USER` — database-level authorization principal.
    MssqlCreateUser,
    /// T-SQL `ALTER LOGIN` — change a server login (password, default
    /// schema, enable/disable).
    MssqlAlterLogin,
    /// T-SQL `DROP LOGIN` — remove a server login.
    MssqlDropLogin,
    /// T-SQL `ALTER AUTHORIZATION ON [class::]securable TO <principal>`
    /// — ownership transfer of a securable.
    AlterAuthorization,
    /// T-SQL `EXECUTE AS { LOGIN | USER } = '<principal>'` — switches
    /// the session's execution context to another principal.
    MssqlExecuteAs,
    /// T-SQL `REVERT` — ends the most recent `EXECUTE AS` context
    /// switch.
    MssqlRevert,
    /// T-SQL `CREATE { SERVER AUDIT [SPECIFICATION] | DATABASE AUDIT
    /// SPECIFICATION }`.
    MssqlCreateAudit,
    /// T-SQL `ALTER { SERVER AUDIT [SPECIFICATION] | DATABASE AUDIT
    /// SPECIFICATION }` — including `STATE = ON/OFF` changes.
    MssqlAlterAudit,
    /// T-SQL `DROP { SERVER AUDIT [SPECIFICATION] | DATABASE AUDIT
    /// SPECIFICATION }`.
    MssqlDropAudit,
    /// T-SQL `CREATE { MASTER KEY | SYMMETRIC KEY | ASYMMETRIC KEY |
    /// CERTIFICATE | [DATABASE SCOPED] CREDENTIAL }`.
    MssqlCreateSecurityObject,
    /// T-SQL `ALTER` of one of the security objects above.
    MssqlAlterSecurityObject,
    /// T-SQL `DROP` of one of the security objects above.
    MssqlDropSecurityObject,
    /// T-SQL SQL Server 2025 `CREATE VECTOR INDEX name ON table (col)
    /// [WITH (METRIC = ..., MAXDOP = ...)] [ON filegroup]` — DiskANN
    /// approximate nearest-neighbour index over an embedding column.
    MssqlCreateVectorIndex,

    // ───────────── Control flow (procedural body parts) ─────────────
    If,
    Case,
    While,
    For,
    Loop,
    Repeat,
    TryCatch,
    Block,
    /// `DECLARE @var <type> [= <init>]` — scalar local variable declaration
    /// (T-SQL / scripting). Not a CREATE; lives in a procedural body.
    Declare,
    /// `DECLARE @t TABLE(...)` — table variable declaration (T-SQL).
    /// Distinct from `Declare` because it has a column schema and rules
    /// that target table-shape locals need to find it.
    DeclareTable,
    DeclareCursor,
    OpenCursor,
    FetchCursor,
    CloseCursor,
    /// `DECLARE { EXIT | CONTINUE } HANDLER FOR condition_value [, ...]
    /// statement` — Databricks/MySQL scripting exception handler.
    DeclareHandler,

    // ───────────── Unresolvable / opaque ─────────────
    /// Statement type could not be determined.
    Opaque,
}

/// Severity tier for rules and signals.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    Info,
    Low,
    Medium,
    High,
    Critical,
}
impl StatementFacts {
    /// Visit every credential VALUE in these facts — stage credential
    /// values, principal passwords, security-object password/secret
    /// literals, secret-keyed user-mapping option values,
    /// storage-credential secrets and literals, and credential-named
    /// security-integration property values. The single definition of
    /// "which fact fields hold secrets"; masking and secret-collection
    /// both walk it.
    fn for_each_credential_value_mut(&mut self, f: &mut dyn FnMut(&mut String)) {
        if let Some(ddl) = &mut self.ddl {
            if let Some(stage) = &mut ddl.stage {
                for opt in &mut stage.credentials {
                    if let Some(v) = &mut opt.value_literal {
                        f(v);
                    }
                }
            }
            if let Some(principal) = &mut ddl.principal {
                if let Some(v) = &mut principal.password_literal {
                    f(v);
                }
            }
            if let Some(um) = &mut ddl.user_mapping {
                for opt in &mut um.options {
                    if crate::parser::user_mapping::is_secret_option_key(&opt.key.raw) {
                        if let Some(v) = &mut opt.value_literal {
                            f(v);
                        }
                    }
                }
            }
            if let Some(sc) = &mut ddl.storage_credential {
                if let Some(provider) = &mut sc.provider {
                    use super::ddl::StorageCredentialProviderVariantFacts as V;
                    match &mut provider.variant {
                        V::AzureServicePrincipal { client_secret, .. } => {
                            if let Some(v) = client_secret {
                                f(v);
                            }
                        }
                        V::CloudflareApiToken {
                            secret_access_key, ..
                        } => {
                            if let Some(v) = secret_access_key {
                                f(v);
                            }
                        }
                        V::AwsIamRole { .. }
                        | V::AzureManagedIdentity { .. }
                        | V::DatabricksGcpServiceAccount
                        | V::Unparsed => {}
                    }
                    for lit in &mut provider.all_literal_values {
                        f(&mut lit.value);
                    }
                }
            }
        }
        if let Some(so) = &mut self.security_object {
            if let Some(v) = &mut so.password_literal {
                f(v);
            }
            if let Some(v) = &mut so.secret_literal {
                f(v);
            }
        }
        if let Some(intg) = &mut self.integration {
            if let super::integration::IntegrationVariantFacts::Security(s) = &mut intg.variant {
                for p in &mut s.set_properties {
                    // The same credential-property predicate the parser's
                    // redaction uses (OAUTH_CLIENT_SECRET yes,
                    // SAML2_FORCE_AUTHN no).
                    if crate::parser::core::is_credential_value_property(
                        &p.name.raw.to_ascii_uppercase(),
                    ) {
                        if let Some(v) = &mut p.value {
                            f(v);
                        }
                        if let Some(v) = &mut p.value_normalized {
                            f(v);
                        }
                    }
                }
            }
        }
    }

    /// Mask every credential VALUE in place, and return the values that
    /// were masked. Applied to the facts COPY that leaves the engine on
    /// an output surface (report `statement_signals` / fact
    /// explanations) — rule evaluation always runs on the unmasked
    /// facts, because value predicates (key-prefix patterns, dummy-value
    /// lists) need the real text. No serialized surface does.
    pub(crate) fn mask_credential_values(&mut self) -> Vec<String> {
        let mut masked = Vec::new();
        self.for_each_credential_value_mut(&mut |v| {
            masked.push(std::mem::replace(v, crate::facts::MASKED_VALUE.to_string()));
        });
        masked
    }
}
