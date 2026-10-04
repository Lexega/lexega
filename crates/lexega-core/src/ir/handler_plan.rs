// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! IR-side carrier for `DECLARE EXIT/CONTINUE HANDLER FOR …` (Databricks
//! procedural scripting).
//!
//! Sibling-tier fact analogous to [`super::ProcedurePlan`] /
//! [`super::FunctionPlan`]: typed projection of [`crate::ast::AstStmt::DeclareHandler`]
//! that downstream `derive_facts_from_handler_plan` folds into a public
//! `StatementFacts.script.handler` carrier.
//!
//! The carrier is intentionally **structural**, not verdict-shaped:
//!
//! - `handler_type` — typed `Exit`/`Continue`/`Simple`, lifted from
//!   [`crate::ast::ExceptionHandlerType`] without re-classification.
//! - `conditions` — typed [`HandlerConditionIr`] discriminators (the
//!   parser is the single text-classification site).
//! - `body.statement_kinds_transitive` — recursive flatten of every
//!   typed leaf statement reached in the handler action subtree
//!   (descending through `Block` / `If` / `While` / `For` / `Loop` /
//!   `Repeat` / `CaseStmt` / nested `DeclareHandler` / MSSQL TRY-CATCH).
//!   Names what the SQL says; never the rule's interpretation.
//!
//! SCRIPT-SILENT-HANDLER predicates against this structural carrier
//! (CONTINUE + `SqlException` condition + body lacking `Resignal`); a
//! sibling rule "handler signals a new error instead of resignaling"
//! composes the same carrier with `body.statement_kinds_transitive:
//! contains: signal` — no fact field is a renamed rule verdict.

use crate::ast::{
    AstDeclareHandlerStmt, AstHandlerConditionKind, AstStmt, ExceptionHandlerType, NodeId,
};
use crate::lexer::token::Span;

#[derive(Debug, Clone)]
pub struct HandlerPlan {
    pub handler_type: HandlerTypeIr,
    pub conditions: Vec<HandlerConditionIr>,
    pub body: HandlerBodyShapeIr,
    pub node_id: NodeId,
    pub span: Span,
}

/// IR-side mirror of [`ExceptionHandlerType`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HandlerTypeIr {
    Simple,
    Exit,
    Continue,
}

/// Closed-enum tag for one entry in the condition list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HandlerConditionIr {
    SqlException,
    SqlWarning,
    NotFound,
    SqlState,
    NamedCondition,
}

/// Recursive-flatten projection of the handler action body.
///
/// `statement_kinds_transitive` is built by walking the handler-action
/// subtree and emitting a typed entry for each leaf statement that the
/// rule corpus reasons about. Control-flow wrappers (`Block`, `If`,
/// `While`, `For`, `Loop`, `Repeat`, `CaseStmt`, nested handlers,
/// MSSQL TRY-CATCH / IF / WHILE) recurse into their bodies without
/// emitting an entry for themselves.
#[derive(Debug, Clone, Default)]
pub struct HandlerBodyShapeIr {
    pub statement_kinds_transitive: Vec<HandlerBodyStatementKindIr>,
}

/// Curated closed enum for handler-body statement forms.
///
/// Starts narrow; new SQL constructs are added additively as new rules
/// need them. Statement kinds the corpus does not currently reason
/// about contribute no entry, mirroring the procedure_plan precedent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HandlerBodyStatementKindIr {
    /// `RESIGNAL` — re-raise the current condition.
    Resignal,
    /// `SIGNAL` — raise a new condition.
    Signal,
    /// `GET DIAGNOSTICS` — read diagnostic info from the last condition.
    GetDiagnostics,
}

/// Lower a typed [`AstDeclareHandlerStmt`] into a [`HandlerPlan`].
pub fn lower_declare_handler_to_handler_plan(
    s: &AstDeclareHandlerStmt,
    _source: &str,
) -> HandlerPlan {
    let handler_type = match s.handler_type {
        ExceptionHandlerType::Simple => HandlerTypeIr::Simple,
        ExceptionHandlerType::Exit => HandlerTypeIr::Exit,
        ExceptionHandlerType::Continue => HandlerTypeIr::Continue,
    };

    let conditions: Vec<HandlerConditionIr> = s
        .conditions
        .iter()
        .map(|c| match c.kind {
            AstHandlerConditionKind::SqlException => HandlerConditionIr::SqlException,
            AstHandlerConditionKind::SqlWarning => HandlerConditionIr::SqlWarning,
            AstHandlerConditionKind::NotFound => HandlerConditionIr::NotFound,
            AstHandlerConditionKind::SqlState { .. } => HandlerConditionIr::SqlState,
            AstHandlerConditionKind::NamedCondition { .. } => HandlerConditionIr::NamedCondition,
        })
        .collect();

    let mut statement_kinds_transitive: Vec<HandlerBodyStatementKindIr> = Vec::new();
    collect_body_statement_kinds(&s.handler_action, &mut statement_kinds_transitive);

    HandlerPlan {
        handler_type,
        conditions,
        body: HandlerBodyShapeIr {
            statement_kinds_transitive,
        },
        node_id: s.node_id,
        span: s.span,
    }
}

/// Recursive walk classifying each reachable statement.
///
/// Closed-enum exhaustive over [`AstStmt`] (no `_ =>` arm). Adding a
/// new [`AstStmt`] variant breaks this build and forces a deliberate
/// recursion-or-leaf decision. Mirrors the precedent in
/// [`super::ProcedurePlan`]'s `collect_body_statement_kinds`.
fn collect_body_statement_kinds(stmt: &AstStmt, kinds: &mut Vec<HandlerBodyStatementKindIr>) {
    match stmt {
        // ───────── Trigger leaves ─────────
        AstStmt::Resignal { .. } => kinds.push(HandlerBodyStatementKindIr::Resignal),
        AstStmt::Signal { .. } => kinds.push(HandlerBodyStatementKindIr::Signal),
        AstStmt::GetDiagnostics { .. } => kinds.push(HandlerBodyStatementKindIr::GetDiagnostics),

        // ───────── Body-bearing scripting variants — recurse ─────────
        AstStmt::Block(b) => {
            for s in &b.decls {
                collect_body_statement_kinds(s, kinds);
            }
            for s in &b.body {
                collect_body_statement_kinds(s, kinds);
            }
        }
        AstStmt::If(i) => {
            for br in &i.branches {
                for s in &br.body {
                    collect_body_statement_kinds(s, kinds);
                }
            }
            for s in &i.else_body {
                collect_body_statement_kinds(s, kinds);
            }
        }
        AstStmt::CaseStmt(c) => {
            for br in &c.branches {
                for s in &br.body {
                    collect_body_statement_kinds(s, kinds);
                }
            }
            for s in &c.else_body {
                collect_body_statement_kinds(s, kinds);
            }
        }
        AstStmt::While(w) => {
            for s in &w.body {
                collect_body_statement_kinds(s, kinds);
            }
        }
        AstStmt::For(f) => {
            for s in &f.body {
                collect_body_statement_kinds(s, kinds);
            }
        }
        AstStmt::ForEach(f) => {
            for s in &f.body {
                collect_body_statement_kinds(s, kinds);
            }
        }
        AstStmt::Loop(l) => {
            for s in &l.body {
                collect_body_statement_kinds(s, kinds);
            }
        }
        AstStmt::Repeat(r) => {
            for s in &r.body {
                collect_body_statement_kinds(s, kinds);
            }
        }
        AstStmt::DeclareHandler(h) => collect_body_statement_kinds(&h.handler_action, kinds),
        AstStmt::MssqlTryCatch(t) => {
            for s in &t.try_body {
                collect_body_statement_kinds(s, kinds);
            }
            for s in &t.catch_body {
                collect_body_statement_kinds(s, kinds);
            }
        }
        AstStmt::MssqlIf(i) => {
            for s in &i.then_body {
                collect_body_statement_kinds(s, kinds);
            }
            for s in &i.else_body {
                collect_body_statement_kinds(s, kinds);
            }
        }
        AstStmt::MssqlWhile(w) => {
            for s in &w.body {
                collect_body_statement_kinds(s, kinds);
            }
        }

        // ───────── Non-body-bearing leaves ─────────
        // Listed exhaustively so the closed-enum contract remains
        // compiler-enforced.
        AstStmt::Select(_)
        | AstStmt::SetSelect(_)
        | AstStmt::ValuesQuery(_)
        | AstStmt::Insert(_)
        | AstStmt::ReplaceInto(_)
        | AstStmt::MultiInsert(_)
        | AstStmt::Update(_)
        | AstStmt::Delete(_)
        | AstStmt::Merge(_)
        | AstStmt::Explain(_)
        | AstStmt::ExecuteImmediate { .. }
        | AstStmt::ExecuteImmediateFrom(_)
        | AstStmt::OpaqueContent { .. }
        | AstStmt::ClauseFragment { .. }
        | AstStmt::JinjaPlaceholder { .. }
        | AstStmt::JinjaConditionalStmt(_)
        | AstStmt::Error { .. }
        | AstStmt::GoBatchSeparator { .. }
        | AstStmt::Reconfigure { .. }
        | AstStmt::AlterAccount(_)
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
        | AstStmt::AlterMaskingPolicy(_)
        | AstStmt::AlterNetworkPolicy(_)
        | AstStmt::AlterPasswordPolicy(_)
        | AstStmt::AlterPgPolicy(_)
        | AstStmt::AlterPgTrigger(_)
        | AstStmt::AlterPipe(_)
        | AstStmt::AlterProcedure(_)
        | AstStmt::AlterProjectionPolicy(_)
        | AstStmt::AlterJoinPolicy(_)
        | AstStmt::AlterRowAccessPolicy(_)
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
        | AstStmt::CreateDynamicTable(_)
        | AstStmt::CreateExtension(_)
        | AstStmt::CreateExternalAccessIntegration(_)
        | AstStmt::CreateExternalLocation(_)
        | AstStmt::CreateExternalTable(_)
        | AstStmt::CreateExternalSchema(_)
        | AstStmt::CreateFlow(_)
        | AstStmt::CreateFunction(_)
        | AstStmt::CreateIndex(_)
        | AstStmt::CreateSynonym(_)
        | AstStmt::CreateMaskingPolicy(_)
        | AstStmt::CreateMssqlTrigger(_)
        | AstStmt::CreateNetworkPolicy(_)
        | AstStmt::CreatePasswordPolicy(_)
        | AstStmt::CreatePgPolicy(_)
        | AstStmt::CreatePgTrigger(_)
        | AstStmt::CreatePipe(_)
        | AstStmt::CreateProcedure(_)
        | AstStmt::CreateProjectionPolicy(_)
        | AstStmt::CreateJoinPolicy(_)
        | AstStmt::CreateRowAccessPolicy(_)
        | AstStmt::CreateSchema(_)
        | AstStmt::CreateSequence(_)
        | AstStmt::CreateSessionPolicy(_)
        | AstStmt::CreateStage(_)
        | AstStmt::CreateStorageCredential(_)
        | AstStmt::CreateStorageIntegration(_)
        | AstStmt::CreateStream(_)
        | AstStmt::CreateTable(_)
        | AstStmt::CreateTableFunction(_)
        | AstStmt::CreateTask(_)
        | AstStmt::CreateType(_)
        | AstStmt::CreateView(_)
        | AstStmt::CreateVolume(_)
        | AstStmt::CreateWarehouse(_)
        | AstStmt::Declare { .. }
        | AstStmt::DeclareCondition { .. }
        | AstStmt::DeclareCursor { .. }
        | AstStmt::DeclareTable { .. }
        | AstStmt::Deny(_)
        | AstStmt::AlterAuthorization(_)
        | AstStmt::MssqlExecuteAs(_)
        | AstStmt::MssqlRevert { .. }
        | AstStmt::MssqlAuditDdl(_)
        | AstStmt::MssqlSecurityObjectDdl(_)
        | AstStmt::Describe(_)
        | AstStmt::DescribeHistory(_)
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
        | AstStmt::FetchCursor { .. }
        | AstStmt::Grant(_)
        | AstStmt::Let { .. }
        | AstStmt::LetCursor { .. }
        | AstStmt::MssqlAlterExternalModel(_)
        | AstStmt::MssqlBulkInsert(_)
        | AstStmt::MssqlCreateExternalModel(_)
        | AstStmt::MssqlCreateVectorIndex(_)
        | AstStmt::MssqlDropExternalModel(_)
        | AstStmt::MssqlExec(_)
        | AstStmt::MssqlGoto(_)
        | AstStmt::MssqlLabel(_)
        | AstStmt::MssqlPrint(_)
        | AstStmt::MssqlRaiserror(_)
        | AstStmt::MssqlSetOption(_)
        | AstStmt::MysqlSet(_)
        | AstStmt::MssqlThrow(_)
        | AstStmt::MssqlWaitfor(_)
        | AstStmt::Null { .. }
        | AstStmt::OpenCursor { .. }
        | AstStmt::Optimize(_)
        | AstStmt::AlterPrincipal(_)
        | AstStmt::PgAlterRule(_)
        | AstStmt::PgAlterSystem(_)
        | AstStmt::PgAlterTableTriggerState(_)
        | AstStmt::PgAlterTablespace(_)
        | AstStmt::PgCluster(_)
        | AstStmt::PgCopy(_)
        | AstStmt::PgCreateAggregate(_)
        | AstStmt::PgCreateOperator(_)
        | AstStmt::CreatePrincipal(_)
        | AstStmt::PgCreateRule(_)
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
        | AstStmt::PgExecute(_)
        | AstStmt::PgListen(_)
        | AstStmt::PgLockTable(_)
        | AstStmt::PgNotify(_)
        | AstStmt::PgPrepare(_)
        | AstStmt::PgPublication(_)
        | AstStmt::PgReassignOwned(_)
        | AstStmt::PgRefreshMatview(_)
        | AstStmt::PgSet(_)
        | AstStmt::PgSubscription(_)
        | AstStmt::PgUnlisten(_)
        | AstStmt::PipeChain { .. }
        | AstStmt::Raise { .. }
        | AstStmt::Reindex(_)
        | AstStmt::RepairTable(_)
        | AstStmt::Restore(_)
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
        | AstStmt::Return { .. }
        | AstStmt::Revoke(_)
        | AstStmt::Rollback { .. }
        | AstStmt::SetVariable { .. }
        | AstStmt::Show(_)
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
        | AstStmt::Vacuum(_) => {}
    }
}
