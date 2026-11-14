// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Closed-enum exhaustive dispatch over
//! [`crate::ast::types::AstStmt`] returning a [`LoweredStatement`].
//!
//! [`lower_stmt`] is the single public entry point for IR lowering.
//! It collapses the split between
//! [`super::lower::lower_query_full_with_bindings_models_and_policy_facts`]
//! (query-bearing + policy-DDL-with-predicates arms) and
//! [`super::lower_ddl::lower_ddl_stmt`] (non-query DDL arms) behind a
//! single facade. The match enumerates every `AstStmt` variant
//! explicitly — adding a new statement type forces a deliberate
//! routing decision (Rel / Opaque / Ddl); there is no `_ =>` arm.
//!
//! # Routing
//!
//! - **Rel** — query-bearing (`SELECT` / `INSERT` /
//!   `UPDATE` / `DELETE` / `MERGE` / `EXPLAIN` / set-operations /
//!   `VALUES`, a view, materialized view or dynamic table, and
//!   `CREATE TABLE … AS`) plus policy DDL whose predicate trees lower in a
//!   synthetic binding scope (`CREATE/ALTER ROW ACCESS POLICY`,
//!   `CREATE/ALTER MASKING POLICY`, `CREATE/ALTER POLICY ... ON <table>`
//!   for PostgreSQL row-level security). Routed through
//!   `lower_query_full_*`; the resulting [`LoweredStatement::Rel`]
//!   arm carries the bindings, indexed catalog context, IR-side
//!   sibling-tier facts, and optional
//!   [`PolicyStatementFacts`](super::policy_facts::PolicyStatementFacts)
//!   that entry point produces.
//!
//! - **Opaque** (5 variants) — AST-level placeholders that are not
//!   structurally lowerable (`OpaqueContent`, `ClauseFragment`,
//!   `JinjaPlaceholder`, `JinjaConditionalStmt`, `Error`), and
//!   **Separator** (`GoBatchSeparator`). Each returns
//!   [`LowerError::opaque`] with [`OpaqueReason::NonSelectTopLevel`];
//!   callers under permissive strict-mode treat this as "no plan".
//!
//! - **Ddl** — every other `AstStmt` variant. Routed
//!   through [`lower_ddl_stmt`]; the resulting
//!   [`LoweredStatement::Ddl`] arm carries just the [`DdlPlan`](crate::ir::ddl_plan::DdlPlan).
//!   `lower_ddl_stmt` itself is closed-enum exhaustive over
//!   `AstStmt`, and the variants that route here are exactly those
//!   for which it returns `Some(_)` (excluding the policy DDL
//!   variants that route to Rel).

use crate::ast::types::AstStmt;

use super::lower::LowerError;
use super::lower::{lower_query_with_declared_names, AroundStatement};
use super::lower_ddl::lower_ddl_stmt;
use super::lower_inputs::{IrLowerInputs, LoweredStatement};
use super::strict::OpaqueReason;
use super::types::SessionContext;

/// Lower an [`AstStmt`] to a [`LoweredStatement`] under the supplied
/// inputs.
///
/// The single closed-enum dispatch point: `route` lists every
/// `AstStmt` variant explicitly in one of four arms (Rel / Opaque /
/// Separator / Ddl). Adding a new variant breaks the build and forces a routing
/// decision.
///
/// Under [`super::strict::StrictMode::Permissive`] the function returns
/// `Err` only for the six opaque and separator arms (`OpaqueContent` /
/// `ClauseFragment` / `JinjaPlaceholder` / `JinjaConditionalStmt` /
/// `Error` / `GoBatchSeparator`); query-bearing and DDL arms always
/// succeed (opaque sub-trees become [`super::plan::RelPlan::Opaque`]
/// terminals inside the lowered tree).
pub fn lower_stmt(stmt: &AstStmt, inputs: &IrLowerInputs) -> Result<LoweredStatement, LowerError> {
    match route(stmt) {
        StatementRoute::Relational => lower_via_rel(stmt, inputs),
        StatementRoute::Ddl => lower_via_ddl(stmt, inputs),
        StatementRoute::Opaque | StatementRoute::Separator => Err(LowerError::opaque(
            stmt.span(),
            OpaqueReason::NonSelectTopLevel,
        )),
    }
}

/// Which lowering [`lower_stmt`] gives a statement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StatementRoute {
    /// The relational lowering: a query, a DML statement, a relation made
    /// from a query, or policy DDL with predicates.
    Relational,
    /// The DDL lowering.
    Ddl,
    /// No lowering: text not parsed as a statement.
    Opaque,
    /// No lowering: a batch separator, which runs nothing.
    Separator,
}

/// The lowering [`lower_stmt`] gives `stmt`: every `AstStmt` variant is
/// listed explicitly, so a new variant breaks the build and forces a
/// routing decision.
pub(crate) fn route(stmt: &AstStmt) -> StatementRoute {
    match stmt {
        AstStmt::Select(_)
        | AstStmt::Perform(_)
        | AstStmt::SetSelect(_)
        | AstStmt::ValuesQuery(_)
        | AstStmt::Insert(_)
        | AstStmt::ReplaceInto(_)
        | AstStmt::MultiInsert(_)
        | AstStmt::Update(_)
        | AstStmt::Delete(_)
        | AstStmt::Merge(_)
        | AstStmt::Explain(_)
        | AstStmt::PsqlGexec(_)
        | AstStmt::CreateRowAccessPolicy(_)
        | AstStmt::AlterRowAccessPolicy(_)
        | AstStmt::CreateMaskingPolicy(_)
        | AstStmt::AlterMaskingPolicy(_)
        | AstStmt::CreatePgPolicy(_)
        | AstStmt::AlterPgPolicy(_) => StatementRoute::Relational,

        // `COPY (<query>) TO ...` recurses into the inner query so its
        // tables surface through the wrapper; `COPY <table> FROM ...`
        // (table-subject form) has no relational body and stays in
        // the Ddl arm via `lower_ddl_stmt`. Closed-enum match on
        // `PgCopySubject` keeps the split typed.
        AstStmt::PgCopy(c) => match &c.subject {
            crate::ast::PgCopySubject::Query(..) => StatementRoute::Relational,
            crate::ast::PgCopySubject::Table(_) => StatementRoute::Ddl,
        },

        // `DECLARE c CURSOR FOR <query>` — always wraps a parsed
        // inner query; routes Rel via `LowerCtx::lower_stmt`'s
        // `DeclareCursor` arm.
        AstStmt::DeclareCursor { .. } => StatementRoute::Relational,

        // A view, a materialized view and a dynamic table hold their
        // query; `CREATE TABLE` holds one only as `CREATE TABLE … AS`.
        AstStmt::CreateView(_) | AstStmt::CreateDynamicTable(_) => StatementRoute::Relational,
        AstStmt::CreateTable(ct) => match ct.variant {
            crate::ast::AstCreateTableVariant::Ctas => StatementRoute::Relational,
            crate::ast::AstCreateTableVariant::Plain
            | crate::ast::AstCreateTableVariant::Like
            | crate::ast::AstCreateTableVariant::Clone
            | crate::ast::AstCreateTableVariant::Copy
            | crate::ast::AstCreateTableVariant::UsingTemplate
            | crate::ast::AstCreateTableVariant::FromArchive
            | crate::ast::AstCreateTableVariant::FromSnapshotSet => StatementRoute::Ddl,
        },

        // `LET c CURSOR FOR <query>` — splits on whether the
        // parser produced a parsed query. `Some` → Rel via
        // recursion; `None` → Ddl shape (best-effort, the
        // wrapper has no body to fold).
        AstStmt::LetCursor { parsed_query, .. } => match parsed_query {
            Some(_) => StatementRoute::Relational,
            None => StatementRoute::Ddl,
        },

        AstStmt::OpaqueContent { .. }
        | AstStmt::ClauseFragment { .. }
        | AstStmt::JinjaPlaceholder { .. }
        | AstStmt::JinjaConditionalStmt(_)
        | AstStmt::Error { .. } => StatementRoute::Opaque,
        // A client's command line: `:r` runs a file not read here.
        AstStmt::SqlcmdCommand { .. } => StatementRoute::Opaque,
        // A body's statement no statement parser read, kept as written as
        // an assignment that has no assignment operator.
        AstStmt::Assign {
            assign_op_span: None,
            ..
        } => StatementRoute::Opaque,
        AstStmt::GoBatchSeparator { .. } => StatementRoute::Separator,

        // ---- DDL arms ----
        // Every non-Rel non-Opaque `AstStmt` variant. Closed-enum
        // exhaustive — `lower_ddl_stmt` returns `Some(_)` for
        // each of these (verified by its own closed-enum match).
        AstStmt::AlterAccount(_)
        | AstStmt::AlterAggregationPolicy(_)
        | AstStmt::AlterApiIntegration(_)
        | AstStmt::AlterNotificationIntegration(_)
        | AstStmt::CreateShare(_)
        | AstStmt::AlterShare(_)
        | AstStmt::CreateDatashare(_)
        | AstStmt::AlterDatashare(_)
        | AstStmt::CreateSecurityIntegration(_)
        | AstStmt::AlterSecurityIntegration(_)
        | AstStmt::AlterReplicationGroup(_)
        | AstStmt::AlterFailoverGroup(_)
        | AstStmt::AlterAuthenticationPolicy(_)
        | AstStmt::AlterCatalog(_)
        | AstStmt::AlterConnection(_)
        | AstStmt::AlterDatabase(_)
        | AstStmt::AlterDomain(_)
        | AstStmt::AlterDynamicTable(_)
        | AstStmt::AlterExternalAccessIntegration(_)
        | AstStmt::AlterExternalLocation(_)
        | AstStmt::AlterFunction(_)
        | AstStmt::AlterIndex(_)
        | AstStmt::AlterMaterializedView(_)
        | AstStmt::AlterNetworkPolicy(_)
        | AstStmt::AlterPasswordPolicy(_)
        | AstStmt::AlterPgTrigger(_)
        | AstStmt::AlterPipe(_)
        | AstStmt::AlterProcedure(_)
        | AstStmt::AlterProjectionPolicy(_)
        | AstStmt::AlterJoinPolicy(_)
        | AstStmt::AlterSchema(_)
        | AstStmt::AlterSequence(_)
        | AstStmt::AlterSessionPolicy(_)
        | AstStmt::AlterSession(_)
        | AstStmt::AlterStage(_)
        | AstStmt::AlterStorageCredential(_)
        | AstStmt::AlterStorageIntegration(_)
        | AstStmt::AlterStream(_)
        | AstStmt::AlterTable(_)
        | AstStmt::AlterTask(_)
        | AstStmt::AlterType(_)
        | AstStmt::AlterUser(_)
        | AstStmt::AlterView(_)
        | AstStmt::AlterVolume(_)
        | AstStmt::AlterWarehouse(_)
        | AstStmt::AnalyzeStmt(_)
        | AstStmt::Assign { .. }
        | AstStmt::Await { .. }
        | AstStmt::BeginTransaction { .. }
        | AstStmt::Block(_)
        | AstStmt::BqAlterModel(_)
        | AstStmt::BqAlterVectorIndex(_)
        | AstStmt::BqAssert(_)
        | AstStmt::BqCreateModel(_)
        | AstStmt::BqCreateSearchIndex(_)
        | AstStmt::BqCreateSnapshotTable(_)
        | AstStmt::BqCreateVectorIndex(_)
        | AstStmt::BqDropModel(_)
        | AstStmt::BqDropSearchIndex(_)
        | AstStmt::BqDropSnapshotTable(_)
        | AstStmt::BqDropVectorIndex(_)
        | AstStmt::BqExportData(_)
        | AstStmt::BqExportModel(_)
        | AstStmt::BqLoadData(_)
        | AstStmt::MysqlLoadData(_)
        | AstStmt::MysqlRenameTable(_)
        | AstStmt::CreateEvent(_)
        | AstStmt::AlterEvent(_)
        | AstStmt::CreateMysqlTrigger(_)
        | AstStmt::Break { .. }
        | AstStmt::CacheTable(_)
        | AstStmt::Call { .. }
        | AstStmt::Cancel { .. }
        | AstStmt::CaseStmt(_)
        | AstStmt::CloseCursor { .. }
        | AstStmt::CommentOn(_)
        | AstStmt::Commit { .. }
        | AstStmt::Continue { .. }
        | AstStmt::CopyIntoLocation { .. }
        | AstStmt::Unload { .. }
        | AstStmt::RedshiftCopy { .. }
        | AstStmt::CopyIntoTable { .. }
        | AstStmt::CreateAggregationPolicy(_)
        | AstStmt::CreateApiIntegration(_)
        | AstStmt::CreateNotificationIntegration(_)
        | AstStmt::CreateAuthenticationPolicy(_)
        | AstStmt::CreateCatalog(_)
        | AstStmt::AlterUserMapping(_)
        | AstStmt::DropUserMapping(_)
        | AstStmt::CreateUserMapping(_)
        | AstStmt::CreateForeignTable(_)
        | AstStmt::ImportForeignSchema(_)
        | AstStmt::CreateForeignServer(_)
        | AstStmt::AlterForeignServer(_)
        | AstStmt::MssqlAlterServerConfiguration(_)
        | AstStmt::MssqlCreateExternalDataSource(_)
        | AstStmt::MssqlAlterExternalDataSource(_)
        | AstStmt::CreateConnection(_)
        | AstStmt::CreateDatabase(_)
        | AstStmt::CreateDomain(_)
        | AstStmt::CreateExtension(_)
        | AstStmt::CreateExternalAccessIntegration(_)
        | AstStmt::CreateExternalLocation(_)
        | AstStmt::CreateExternalTable(_)
        | AstStmt::CreateExternalSchema(_)
        | AstStmt::CreateFlow(_)
        | AstStmt::CreateFunction(_)
        | AstStmt::CreateIndex(_)
        | AstStmt::CreateSynonym(_)
        | AstStmt::CreateMssqlTrigger(_)
        | AstStmt::CreateNetworkPolicy(_)
        | AstStmt::CreatePasswordPolicy(_)
        | AstStmt::CreatePgTrigger(_)
        | AstStmt::CreatePipe(_)
        | AstStmt::CreateProcedure(_)
        | AstStmt::CreateProjectionPolicy(_)
        | AstStmt::CreateJoinPolicy(_)
        | AstStmt::CreateSchema(_)
        | AstStmt::CreateSequence(_)
        | AstStmt::CreateSessionPolicy(_)
        | AstStmt::CreateStage(_)
        | AstStmt::CreateStorageCredential(_)
        | AstStmt::CreateStorageIntegration(_)
        | AstStmt::CreateStream(_)
        | AstStmt::CreateTableFunction(_)
        | AstStmt::CreateTask(_)
        | AstStmt::CreateType(_)
        | AstStmt::CreateVolume(_)
        | AstStmt::CreateWarehouse(_)
        | AstStmt::Declare { .. }
        | AstStmt::DeclareCondition { .. }
        | AstStmt::DeclareHandler(_)
        | AstStmt::DeclareTable { .. }
        | AstStmt::Deny(_)
        | AstStmt::AlterAuthorization(_)
        | AstStmt::MssqlExecuteAs(_)
        | AstStmt::MssqlRevert { .. }
        | AstStmt::MssqlAuditDdl(_)
        | AstStmt::MssqlSecurityObjectDdl(_)
        | AstStmt::Describe(_)
        | AstStmt::DescribeHistory(_)
        | AstStmt::MssqlBackup(_)
        | AstStmt::MssqlRestore(_)
        | AstStmt::MssqlDbcc(_)
        | AstStmt::MssqlKeyManagement(_)
        | AstStmt::MssqlSecurityPolicy(_)
        | AstStmt::MssqlKeyBackup(_)
        | AstStmt::MssqlAssembly(_)
        | AstStmt::MssqlAddSignature(_)
        | AstStmt::MssqlSetuser(_)
        | AstStmt::MssqlAlterServiceMasterKey(_)
        | AstStmt::PgAlterDefaultPrivileges(_)
        | AstStmt::DoBlock(_)
        | AstStmt::Drop(_)
        | AstStmt::DropAggregationPolicy(_)
        | AstStmt::DropAllRowAccessPolicies(_)
        | AstStmt::DropApiIntegration(_)
        | AstStmt::DropNotificationIntegration(_)
        | AstStmt::DropAuthenticationPolicy(_)
        | AstStmt::DropCatalog(_)
        | AstStmt::DropConnection(_)
        | AstStmt::DropDatabase(_)
        | AstStmt::DropDomain(_)
        | AstStmt::DropExternalAccessIntegration(_)
        | AstStmt::DropExternalLocation(_)
        | AstStmt::DropMaskingPolicy(_)
        | AstStmt::DropMssqlTrigger(_)
        | AstStmt::MssqlTriggerState(_)
        | AstStmt::DropNetworkPolicy(_)
        | AstStmt::DropPasswordPolicy(_)
        | AstStmt::DropPgPolicy(_)
        | AstStmt::DropPgTrigger(_)
        | AstStmt::DropPipe(_)
        | AstStmt::DropProjectionPolicy(_)
        | AstStmt::DropJoinPolicy(_)
        | AstStmt::DropRowAccessPolicy(_)
        | AstStmt::DropSchema(_)
        | AstStmt::DropSessionPolicy(_)
        | AstStmt::DropStorageCredential(_)
        | AstStmt::DropStorageIntegration(_)
        | AstStmt::DropStream(_)
        | AstStmt::DropTask(_)
        | AstStmt::DropVolume(_)
        | AstStmt::DropWarehouse(_)
        | AstStmt::ExecuteImmediate { .. }
        | AstStmt::ExecuteImmediateFrom(_)
        | AstStmt::FetchCursor { .. }
        | AstStmt::For(_)
        | AstStmt::ForEach(_)
        | AstStmt::GetDiagnostics { .. }
        | AstStmt::Grant(_)
        | AstStmt::If(_)
        | AstStmt::Let { .. }
        | AstStmt::Loop(_)
        | AstStmt::MssqlAlterExternalModel(_)
        | AstStmt::MssqlBulkInsert(_)
        | AstStmt::MssqlCreateExternalModel(_)
        | AstStmt::MssqlCreateVectorIndex(_)
        | AstStmt::MssqlDropExternalModel(_)
        | AstStmt::MssqlExec(_)
        | AstStmt::MssqlGoto(_)
        | AstStmt::MssqlIf(_)
        | AstStmt::MssqlLabel(_)
        | AstStmt::MssqlPrint(_)
        | AstStmt::MssqlRaiserror(_)
        | AstStmt::MssqlSetOption(_)
        | AstStmt::MysqlSet(_)
        | AstStmt::MysqlUnlockTables(_)
        | AstStmt::MssqlThrow(_)
        | AstStmt::MssqlTryCatch(_)
        | AstStmt::MssqlWaitfor(_)
        | AstStmt::MssqlWhile(_)
        | AstStmt::Null { .. }
        | AstStmt::OpenCursor { .. }
        | AstStmt::Optimize(_)
        | AstStmt::AlterPrincipal(_)
        | AstStmt::PgAlterRule(_)
        | AstStmt::PgAlterSystem(_)
        | AstStmt::PgAlterTableTriggerState(_)
        | AstStmt::PgAlterTablespace(_)
        | AstStmt::PgCluster(_)
        | AstStmt::PgCreateAggregate(_)
        | AstStmt::PgCreateOperator(_)
        | AstStmt::CreatePrincipal(_)
        | AstStmt::PgCreateRule(_)
        | AstStmt::MssqlCreateRule(_)
        | AstStmt::MysqlDo(_)
        | AstStmt::ExecuteTask(_)
        | AstStmt::MysqlCreateLoadableFunction(_)
        | AstStmt::MysqlAdmin(_)
        | AstStmt::PgCreateTablespace(_)
        | AstStmt::PgDeallocate(_)
        | AstStmt::PgDiscard(_)
        | AstStmt::PgDropExtension(_)
        | AstStmt::PgDropIndex(_)
        | AstStmt::PgDropOwned(_)
        | AstStmt::DropPrincipal(_)
        | AstStmt::PgDropRule(_)
        | AstStmt::PgDropSequence(_)
        | AstStmt::PgDropTablespace(_)
        | AstStmt::PgDropType(_)
        | AstStmt::PgPrepare(_)
        | AstStmt::PgExecute(_)
        | AstStmt::PgListen(_)
        | AstStmt::PgLockTable(_)
        | AstStmt::PgNotify(_)
        | AstStmt::PgPublication(_)
        | AstStmt::PgReassignOwned(_)
        | AstStmt::PgRefreshMatview(_)
        | AstStmt::PgSet(_)
        | AstStmt::PgSubscription(_)
        | AstStmt::PgUnlisten(_)
        | AstStmt::PipeChain { .. }
        | AstStmt::Raise { .. }
        | AstStmt::Reconfigure { .. }
        | AstStmt::MssqlServerCommand { .. }
        | AstStmt::Reindex(_)
        | AstStmt::RepairTable(_)
        | AstStmt::Repeat(_)
        | AstStmt::Resignal { .. }
        | AstStmt::Restore(_)
        | AstStmt::Return { .. }
        | AstStmt::Revoke(_)
        | AstStmt::Rollback { .. }
        | AstStmt::Savepoint(_)
        | AstStmt::SetVariable { .. }
        | AstStmt::Show(_)
        | AstStmt::Signal { .. }
        | AstStmt::Truncate(_)
        | AstStmt::UncacheTable(_)
        | AstStmt::UndropDatabase(_)
        | AstStmt::UndropSchema(_)
        | AstStmt::UndropTable(_)
        | AstStmt::UndropType(_)
        | AstStmt::CreateTag(_)
        | AstStmt::AlterTag(_)
        | AstStmt::CreateFileFormat(_)
        | AstStmt::AlterFileFormat(_)
        | AstStmt::UndropTag(_)
        | AstStmt::CreateSecret(_)
        | AstStmt::AlterSecret(_)
        | AstStmt::CreateNetworkRule(_)
        | AstStmt::AlterNetworkRule(_)
        | AstStmt::CreateResourceMonitor(_)
        | AstStmt::AlterResourceMonitor(_)
        | AstStmt::CreateComputePool(_)
        | AstStmt::AlterComputePool(_)
        | AstStmt::CreateGitRepository(_)
        | AstStmt::CreateExternalFunction(_)
        | AstStmt::AlterGitRepository(_)
        | AstStmt::CreateImageRepository(_)
        | AstStmt::AlterImageRepository(_)
        | AstStmt::CreateStreamlit(_)
        | AstStmt::AlterStreamlit(_)
        | AstStmt::CreateService(_)
        | AstStmt::AlterService(_)
        | AstStmt::CreateNotebook(_)
        | AstStmt::AlterNotebook(_)
        | AstStmt::CreateSemanticView(_)
        | AstStmt::AlterSemanticView(_)
        | AstStmt::CreateCortexSearchService(_)
        | AstStmt::AlterCortexSearchService(_)
        | AstStmt::CreateApplication(_)
        | AstStmt::AlterApplication(_)
        | AstStmt::CreateApplicationPackage(_)
        | AstStmt::AlterApplicationPackage(_)
        | AstStmt::CreateListing(_)
        | AstStmt::AlterListing(_)
        | AstStmt::CreateManagedAccount(_)
        | AstStmt::CreateAccount(_)
        | AstStmt::StageFileCommand(_)
        | AstStmt::CreateAlert(_)
        | AstStmt::CreateDataMetricFunction(_)
        | AstStmt::CreateReplicationFailoverGroup(_)
        | AstStmt::AlterAlert(_)
        | AstStmt::Use(_)
        | AstStmt::Vacuum(_)
        | AstStmt::While(_) => StatementRoute::Ddl,
    }
}

/// Route a query-bearing or policy-DDL-with-predicates statement
/// through the relational lowering entry point and wrap the result as
/// [`LoweredStatement::Rel`].
fn lower_via_rel(stmt: &AstStmt, inputs: &IrLowerInputs) -> Result<LoweredStatement, LowerError> {
    let (plan, catalog_ctx, bindings, facts, policy_facts) = lower_query_with_declared_names(
        stmt,
        inputs.source,
        inputs.strict,
        inputs.func_catalog,
        inputs.session,
        inputs.catalog,
        inputs.model_catalog,
        AroundStatement::under(inputs.meaning),
    )?;
    Ok(LoweredStatement::Rel {
        plan,
        bindings,
        catalog_ctx,
        facts,
        policy_facts,
    })
}

/// Place the name of the relation `plan` acts on in `session`, as the
/// relational lowering places every relation it names, so a statement is
/// named alike whichever arm lowers it. Other objects keep the name as
/// written.
fn place_relation_target(plan: &mut crate::ir::ddl_plan::DdlPlan, session: &SessionContext) {
    use crate::facts::identity::ObjectKind;
    let relation = match plan.object_kind {
        ObjectKind::Table
        | ObjectKind::View
        | ObjectKind::MaterializedView
        | ObjectKind::DynamicTable
        | ObjectKind::ExternalTable => true,
        ObjectKind::Schema
        | ObjectKind::Database
        | ObjectKind::Tag
        | ObjectKind::Procedure
        | ObjectKind::Function
        | ObjectKind::Trigger
        | ObjectKind::Stage
        | ObjectKind::FileFormat
        | ObjectKind::Pipe
        | ObjectKind::Stream
        | ObjectKind::ApiIntegration
        | ObjectKind::StorageIntegration
        | ObjectKind::ExternalAccessIntegration
        | ObjectKind::NotificationIntegration
        | ObjectKind::SecurityIntegration
        | ObjectKind::Warehouse
        | ObjectKind::Task
        | ObjectKind::Alert
        | ObjectKind::NetworkRule
        | ObjectKind::ResourceMonitor
        | ObjectKind::Secret
        | ObjectKind::Sequence
        | ObjectKind::Role
        | ObjectKind::User
        | ObjectKind::Share
        | ObjectKind::Account
        | ObjectKind::Session
        | ObjectKind::MaskingPolicy
        | ObjectKind::RowAccessPolicy
        | ObjectKind::NetworkPolicy
        | ObjectKind::SessionPolicy
        | ObjectKind::PasswordPolicy
        | ObjectKind::AggregationPolicy
        | ObjectKind::ProjectionPolicy
        | ObjectKind::JoinPolicy
        | ObjectKind::DataMetricFunction
        | ObjectKind::ReplicationGroup
        | ObjectKind::AuthenticationPolicy
        | ObjectKind::PgExtension
        | ObjectKind::PgDomain
        | ObjectKind::PgType
        | ObjectKind::PgPublication
        | ObjectKind::PgSubscription
        | ObjectKind::PgRule
        | ObjectKind::BqModel
        | ObjectKind::Catalog
        | ObjectKind::Volume
        | ObjectKind::ExternalLocation
        | ObjectKind::StorageCredential
        | ObjectKind::Metastore
        | ObjectKind::Datashare
        | ObjectKind::Index
        | ObjectKind::Group
        | ObjectKind::ExternalSchema
        | ObjectKind::FailoverGroup
        | ObjectKind::Synonym
        | ObjectKind::Generic => false,
    };
    if let (true, Some(target)) = (relation, plan.target.as_mut()) {
        session.place(&mut target.db, &mut target.schema);
    }
}

/// Route a non-query DDL statement through [`lower_ddl_stmt`] and wrap
/// the result as [`LoweredStatement::Ddl`].
///
/// The caller's closed-enum match guarantees `stmt` is a variant for
/// which `lower_ddl_stmt` returns `Some(_)`. The structural fall-back
/// to `LowerError::opaque` covers the typed compiler-enforced
/// invariant: if `lower_ddl_stmt` ever changes to return `None` for a
/// variant the Ddl arm routes here, the typed `Err` surface keeps
/// downstream callers from observing an inconsistent attachment shape.
fn lower_via_ddl(stmt: &AstStmt, inputs: &IrLowerInputs) -> Result<LoweredStatement, LowerError> {
    match lower_ddl_stmt(stmt, inputs) {
        Some(mut plan) => {
            place_relation_target(&mut plan, inputs.session);
            let privilege_plan = match stmt {
                AstStmt::Grant(g) => Some(super::lower_grant_to_privilege_plan(g)),
                AstStmt::Revoke(r) => Some(super::lower_revoke_to_privilege_plan(r)),
                _ => None,
            };
            Ok(LoweredStatement::Ddl {
                plan,
                privilege_plan,
            })
        }
        None => Err(LowerError::opaque(
            stmt.span(),
            OpaqueReason::NonSelectTopLevel,
        )),
    }
}
