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

    /// Dynamic-SQL call sites at this statement, at the top level of a
    /// script or in a procedure, function or trigger body alike. Populated
    /// for:
    ///
    /// - Statements that run SQL text (`EXECUTE IMMEDIATE`, PL/pgSQL
    ///   `EXECUTE`, T-SQL `EXEC (…)` / `sp_executesql`, MySQL `PREPARE …
    ///   FROM`) — one entry classifying argument shape and parameterization.
    /// - Calls of a routine (`CALL`, T-SQL `EXEC proc`) whose body runs an
    ///   argument as SQL — one entry per argument that reaches it.
    /// - Query statements (SELECT / INSERT / UPDATE / DELETE / MERGE)
    ///   whose expressions invoke cross-server dynamic-SQL functions
    ///   (`dblink_exec`, etc.) — one entry per call site.
    ///
    /// A routine's `CREATE` also lists the calls its body makes, under
    /// `ddl.procedure.body.dynamic_sql_calls`,
    /// `ddl.function.body.dynamic_sql_calls` or
    /// `ddl.trigger_body.dynamic_sql_calls`.
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

    /// The arguments a `CALL` or T-SQL `EXEC` passes to the routine it
    /// calls, which is `ddl.target`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub call: Option<super::ddl::CallFacts>,

    /// The variables a `DECLARE` makes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub declare: Option<super::ddl::DeclareFacts>,

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
    /// Snowflake `EXECUTE TASK`: runs a task now.
    ExecuteTask,

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
    /// `DESCRIBE <object>` — the metadata of one object, named in
    /// `ddl.target`.
    Describe,
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
    /// `ANALYZE` — refreshes table statistics: PostgreSQL `ANALYZE [VERBOSE]
    /// [table [(column, ...)]]`, MySQL `ANALYZE TABLE t, …`.
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
    /// MySQL `DO <expr>, …` — expressions evaluated for their effect
    /// (`DO SLEEP(30)`).
    MysqlDo,
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
    /// T-SQL `WAITFOR { DELAY | TIME } …` — holds the connection for a time.
    MssqlWaitfor,
    /// T-SQL `PRINT` — a message to the client.
    MssqlPrint,
    /// T-SQL `THROW` — raises an error.
    MssqlThrow,
    /// T-SQL `RAISERROR` — raises an error or message.
    MssqlRaiserror,
    /// T-SQL `RECONFIGURE [WITH OVERRIDE]` — applies pending
    /// `sp_configure` server option changes to the running configuration.
    Reconfigure,
    /// T-SQL server command: `CHECKPOINT`, `KILL` or `SHUTDOWN`.
    MssqlServerCommand,
    /// MySQL `OPTIMIZE TABLE t, …` — reorganizes the tables' storage.
    OptimizeTable,
    /// MySQL `CHECK TABLE t, …` — checks the tables for errors.
    CheckTable,
    /// MySQL `CHECKSUM TABLE t, …` — reports the tables' checksums.
    ChecksumTable,
    /// MySQL `REPAIR [NO_WRITE_TO_BINLOG | LOCAL] TABLE t, … [QUICK]
    /// [EXTENDED] [USE_FRM]` — repairs the tables.
    RepairTable,
    /// MySQL `FLUSH …` — reloads or clears server state: the grant tables
    /// (`PRIVILEGES`), logs, caches, or tables (`TABLES … WITH READ LOCK`).
    Flush,
    /// MySQL `KILL [CONNECTION | QUERY] id` — ends a session or its statement.
    Kill,
    /// MySQL `ALTER INSTANCE …` — rotates encryption keys, reloads TLS or the
    /// keyring, enables or disables the redo log.
    AlterInstance,
    /// MySQL `XA …` — a distributed transaction's step.
    XaTransaction,
    /// MySQL `RENAME USER a TO b, …` — renames accounts.
    RenameUser,
    MssqlBulkInsert,
    MssqlSetOption,
    /// T-SQL `DROP TRIGGER [IF EXISTS] name [, …] [ON { DATABASE |
    /// ALL SERVER }]` — drops a DML, DDL, or logon trigger. Distinct
    /// from PostgreSQL `DROP TRIGGER … ON <table>` because the syntax
    /// and scope differ (database/server vs table).
    MssqlDropTrigger,
    /// T-SQL `{ ENABLE | DISABLE } TRIGGER { name [, …] | ALL } ON
    /// { object | DATABASE | ALL SERVER }` — turns DML, DDL or logon
    /// triggers on or off.
    MssqlTriggerState,
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
    /// A Snowflake pipe chain (`a ->> b`): each statement runs in turn and
    /// is read as a statement of its own.
    PipeChain,
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
    /// `ASSERT condition [, message]` outside BigQuery (PL/pgSQL's
    /// assertion). BigQuery's `ASSERT` is `bq_assert`.
    Assert,

    // ───────────── Unresolvable / opaque ─────────────
    /// Statement type could not be determined.
    Opaque,
}

/// Severity tier for rules and findings.
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

/// Take `other` into `kept` where `kept` has none. Two readings of one
/// statement that both derive a carrier derive the same one.
fn absorb_carrier<T: PartialEq + std::fmt::Debug>(kept: &mut Option<T>, other: Option<T>) {
    match (kept.as_ref(), other) {
        (None, other) => *kept = other,
        (Some(kept), Some(other)) => debug_assert_eq!(
            kept, &other,
            "two readings of one statement derive one carrier differently"
        ),
        (Some(_), None) => {}
    }
}

impl StatementFacts {
    /// List a lone DDL or privilege target in its `targets`, where the
    /// reading filled no list.
    pub(crate) fn complete_targets(&mut self) {
        let lone = |targets: &mut Vec<super::ObjectRef>, target: &Option<super::ObjectRef>| {
            if targets.is_empty() {
                targets.extend(target.iter().cloned());
            }
        };
        if let Some(ddl) = self.ddl.as_mut() {
            lone(&mut ddl.targets, &ddl.target);
        }
        if let Some(privilege) = self.privilege.as_mut() {
            lone(&mut privilege.targets, &privilege.target);
        }
    }

    /// Add to these facts what `other`, another reading of the same
    /// statement, holds: each carrier these facts lack, every entry of each
    /// list, and its query where the query holds something. The statement's
    /// kind and span stay these facts'.
    pub(crate) fn absorb(&mut self, other: StatementFacts) {
        let StatementFacts {
            kind: _,
            source_span: _,
            query,
            ddl,
            privilege,
            policy,
            policy_attachment,
            integration,
            use_stmt,
            pg_copy,
            mssql_backup,
            mssql_restore,
            mssql_dbcc,
            mssql_key_management,
            mssql_security_policy,
            mssql_key_backup,
            mssql_assembly,
            mssql_add_signature,
            mssql_service_master_key,
            pg_default_privileges,
            comment,
            handler,
            dynamic_sql_calls,
            mssql_exec,
            call,
            declare,
            impersonation,
            execute_immediate_from,
            audit,
            security_object,
            algebra,
            script_context,
            diff,
        } = other;
        absorb_carrier(
            &mut self.query,
            query.filter(|query| !query.holds_nothing()),
        );
        absorb_carrier(&mut self.ddl, ddl);
        absorb_carrier(&mut self.privilege, privilege);
        absorb_carrier(&mut self.policy, policy);
        absorb_carrier(&mut self.policy_attachment, policy_attachment);
        absorb_carrier(&mut self.integration, integration);
        absorb_carrier(&mut self.use_stmt, use_stmt);
        absorb_carrier(&mut self.pg_copy, pg_copy);
        absorb_carrier(&mut self.mssql_backup, mssql_backup);
        absorb_carrier(&mut self.mssql_restore, mssql_restore);
        absorb_carrier(&mut self.mssql_dbcc, mssql_dbcc);
        absorb_carrier(&mut self.mssql_key_management, mssql_key_management);
        absorb_carrier(&mut self.mssql_security_policy, mssql_security_policy);
        absorb_carrier(&mut self.mssql_key_backup, mssql_key_backup);
        absorb_carrier(&mut self.mssql_assembly, mssql_assembly);
        absorb_carrier(&mut self.mssql_add_signature, mssql_add_signature);
        absorb_carrier(&mut self.mssql_service_master_key, mssql_service_master_key);
        absorb_carrier(&mut self.pg_default_privileges, pg_default_privileges);
        absorb_carrier(&mut self.comment, comment);
        absorb_carrier(&mut self.handler, handler);
        self.dynamic_sql_calls.extend(dynamic_sql_calls);
        absorb_carrier(&mut self.mssql_exec, mssql_exec);
        absorb_carrier(&mut self.call, call);
        absorb_carrier(&mut self.declare, declare);
        absorb_carrier(&mut self.impersonation, impersonation);
        absorb_carrier(&mut self.execute_immediate_from, execute_immediate_from);
        absorb_carrier(&mut self.audit, audit);
        absorb_carrier(&mut self.security_object, security_object);
        self.algebra.absorb(algebra);
        if self.script_context == ScriptContext::default() {
            self.script_context = script_context;
        }
        absorb_carrier(&mut self.diff, diff);
    }

    /// Visit every credential VALUE in these facts — stage credential
    /// values, principal passwords, security-object password/secret
    /// literals, secret-keyed user-mapping and external-table option
    /// values, storage-credential secrets and literals, credential-named
    /// security-integration property values, and the T-SQL key statements'
    /// password literals. The single definition of
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
                for password in &mut stage.url_password_literals {
                    f(&mut password.value);
                }
            }
            if let Some(principal) = &mut ddl.principal {
                if let Some(v) = &mut principal.password_literal {
                    f(v);
                }
            }
            if let Some(um) = &mut ddl.user_mapping {
                for opt in &mut um.options {
                    if lexega_syntax::secrets::is_secret_name(&opt.key.raw) {
                        if let Some(v) = &mut opt.value_literal {
                            f(v);
                        }
                    }
                }
            }
            if let Some(bq) = &mut ddl.bq_options {
                // The clause's list of every literal holds a secret option's
                // value too.
                let mut secrets = Vec::new();
                for opt in &mut bq.options {
                    if lexega_syntax::secrets::is_secret_name(&opt.key.raw) {
                        secrets.push(opt.value_literal.clone());
                        f(&mut opt.value_literal);
                    }
                }
                for lit in &mut bq.all_literal_values {
                    if secrets.contains(&lit.value) {
                        f(&mut lit.value);
                    }
                    for password in &mut lit.url_password_literals {
                        f(&mut password.value);
                    }
                }
            }
            if let Some(sc) = &mut ddl.storage_credential {
                for password in &mut sc.comment_url_password_literals {
                    f(&mut password.value);
                }
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
                    for password in &mut provider.url_password_literals {
                        f(&mut password.value);
                    }
                }
            }
        }
        if let Some(query) = &mut self.query {
            let entries = query
                .openrowset_calls
                .iter_mut()
                .chain(&mut query.opendatasource_calls)
                .flat_map(|call| &mut call.string_args)
                .flat_map(|arg| &mut arg.connection_string);
            for entry in entries {
                if lexega_syntax::secrets::is_secret_name(&entry.key.raw) {
                    if let Some(v) = &mut entry.value_literal {
                        f(v);
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
        let key_passwords = [
            self.mssql_key_management
                .as_mut()
                .map(|k| &mut k.password_literals),
            self.mssql_key_backup
                .as_mut()
                .map(|k| &mut k.password_literals),
            self.mssql_add_signature
                .as_mut()
                .map(|k| &mut k.password_literals),
            self.mssql_service_master_key
                .as_mut()
                .map(|k| &mut k.password_literals),
        ];
        for literal in key_passwords.into_iter().flatten().flatten() {
            f(&mut literal.value);
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

    /// Visit each string these facts hold that is made of the text of a
    /// string literal of the statement and records no place of its own: a
    /// setting's value, a URL, a path, a host, a tag's value, an option's
    /// literal, a value a column is compared with or holds. Each is made
    /// of the statement's text, so a report masks it wherever the
    /// statement holds a literal it does not show.
    pub(crate) fn for_each_literal_text_mut(&mut self, f: &mut dyn FnMut(&mut String)) {
        fn each(text: &mut Option<String>, f: &mut dyn FnMut(&mut String)) {
            if let Some(text) = text {
                f(text);
            }
        }
        if let Some(ddl) = &mut self.ddl {
            if let Some(account) = &mut ddl.account {
                for parameter in account
                    .parameters_set
                    .iter_mut()
                    .chain(&mut account.parameters_unset)
                {
                    f(&mut parameter.value);
                }
            }
            if let Some(assert) = &mut ddl.bq_assert {
                each(&mut assert.description, f);
            }
            let bodies = [
                ddl.bq_create_model.as_mut().and_then(|model| {
                    each(&mut model.remote_connection, f);
                    model.body.as_mut()
                }),
                ddl.bq_export_data
                    .as_mut()
                    .and_then(|export| export.body.as_mut()),
            ];
            for body in bodies.into_iter().flatten() {
                each(&mut body.where_clause, f);
                each(&mut body.having_clause, f);
                each(&mut body.qualify_clause, f);
            }
            if let Some(options) = &mut ddl.bq_options {
                for option in &mut options.options {
                    f(&mut option.value_literal);
                }
                for literal in &mut options.all_literal_values {
                    f(&mut literal.value);
                }
            }
            if let Some(service) = &mut ddl.cortex_search_service {
                each(&mut service.embedding_model, f);
            }
            let definers = [
                ddl.view.as_mut().and_then(|v| v.definer.as_mut()),
                ddl.create_trigger.as_mut().and_then(|t| t.definer.as_mut()),
                ddl.event.as_mut().and_then(|e| e.definer.as_mut()),
                ddl.function.as_mut().and_then(|g| g.definer.as_mut()),
                ddl.procedure.as_mut().and_then(|p| p.definer.as_mut()),
            ];
            for definer in definers.into_iter().flatten() {
                each(&mut definer.user, f);
                each(&mut definer.host, f);
            }
            if let Some(function) = &mut ddl.function {
                each(&mut function.loadable_library, f);
            }
            if let Some(external) = &mut ddl.external_function {
                each(&mut external.endpoint_url, f);
            }
            if let Some(repository) = &mut ddl.git_repository {
                each(&mut repository.origin, f);
            }
            if let Some(load) = &mut ddl.mysql_load_data {
                each(&mut load.infile_path, f);
            }
            if let Some(rule) = &mut ddl.network_rule {
                rule.value_list.iter_mut().for_each(&mut *f);
                for entry in &mut rule.value_entries {
                    f(&mut entry.raw);
                }
            }
            if let Some(principal) = &mut ddl.principal {
                each(&mut principal.mysql_host, f);
            }
            if let Some(session) = &mut ddl.session {
                for parameter in &mut session.set_params {
                    f(&mut parameter.value);
                }
            }
            if let Some(tag) = &mut ddl.tag {
                tag.allowed_values
                    .iter_mut()
                    .chain(&mut tag.allowed_values_removed)
                    .for_each(&mut *f);
            }
            if let Some(mapping) = &mut ddl.user_mapping {
                for option in &mut mapping.options {
                    each(&mut option.value_literal, f);
                }
            }
            if let Some(application) = &mut ddl.application {
                each(&mut application.source_name, f);
            }
            if let Some(listing) = &mut ddl.listing {
                each(&mut listing.shared_object, f);
            }
            if let Some(volume) = &mut ddl.volume {
                for location in &mut volume.storage_locations {
                    each(&mut location.provider, f);
                    each(&mut location.encryption_type, f);
                }
            }
            if let Some(credential) = &mut ddl.storage_credential {
                each(&mut credential.comment, f);
                if let Some(provider) = &mut credential.provider {
                    for literal in &mut provider.all_literal_values {
                        f(&mut literal.value);
                    }
                    use super::ddl::StorageCredentialProviderVariantFacts as V;
                    match &mut provider.variant {
                        V::AwsIamRole { role_arn } => each(role_arn, f),
                        V::AzureManagedIdentity {
                            managed_identity_id,
                            access_connector_id,
                        } => {
                            each(managed_identity_id, f);
                            each(access_connector_id, f);
                        }
                        V::AzureServicePrincipal {
                            directory_id,
                            application_id,
                            client_secret,
                        } => {
                            each(directory_id, f);
                            each(application_id, f);
                            each(client_secret, f);
                        }
                        V::CloudflareApiToken {
                            account_id,
                            access_key_id,
                            secret_access_key,
                        } => {
                            each(account_id, f);
                            each(access_key_id, f);
                            each(secret_access_key, f);
                        }
                        V::DatabricksGcpServiceAccount | V::Unparsed => {}
                    }
                }
            }
        }
        if let Some(from) = &mut self.execute_immediate_from {
            each(&mut from.location, f);
        }
        if let Some(integration) = &mut self.integration {
            for tag in &mut integration.set_tags {
                each(&mut tag.value, f);
            }
            if let super::integration::IntegrationVariantFacts::Security(security) =
                &mut integration.variant
            {
                for property in &mut security.set_properties {
                    each(&mut property.value, f);
                    each(&mut property.value_normalized, f);
                }
            }
        }
        if let Some(policy) = &mut self.policy {
            for tag in &mut policy.set_tags {
                each(&mut tag.value, f);
            }
            if let super::policy::PolicyVariantFacts::Network(network) = &mut policy.variant {
                for entry in network
                    .allowed_ip_lists
                    .iter_mut()
                    .chain(&mut network.blocked_ip_lists)
                {
                    f(&mut entry.raw);
                }
            }
        }
        if let Some(query) = &mut self.query {
            for export in &mut query.file_exports {
                f(&mut export.file_path);
            }
            for call in query
                .openrowset_calls
                .iter_mut()
                .chain(&mut query.opendatasource_calls)
            {
                for argument in &mut call.string_args {
                    f(&mut argument.value);
                    for entry in &mut argument.connection_string {
                        each(&mut entry.value_literal, f);
                    }
                }
            }
            for constraint in &mut query.column_constraints {
                constraint
                    .eq_values
                    .iter_mut()
                    .chain(&mut constraint.not_eq_values)
                    .for_each(&mut *f);
                for bound in constraint
                    .lower_bounds
                    .iter_mut()
                    .chain(&mut constraint.upper_bounds)
                {
                    f(&mut bound.value);
                }
            }
            for column in &mut query.output_columns {
                column.constraints.for_each_literal_text_mut(f);
            }
        }
    }

    /// Mask every credential VALUE in place and return the values masked.
    /// Applied to the facts COPY that leaves the engine on an output
    /// surface (report `statement_traces` / fact explanations) — rule
    /// evaluation always runs on the unmasked facts, because value
    /// predicates (key-prefix patterns, dummy-value lists) need the real
    /// text.
    pub(crate) fn mask_credential_values(&mut self) -> Vec<String> {
        let mut masked = Vec::new();
        self.for_each_credential_value_mut(&mut |v| {
            masked.push(std::mem::replace(v, crate::facts::MASKED_VALUE.to_string()));
        });
        masked
    }
}
