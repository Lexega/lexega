// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! SQL formatter with automatic span tracking
//!
//! This module provides a SQL formatter that:
//! - Tracks source→formatted span mappings automatically
//! - Enforces statement-level partition (no gaps/overlaps)
//! - Records the span map of a formatted source in its `RenderContext`
//! - Formats in the dialect its `FormatterConfig` names
//! - Preserves trivia from the CST (comments attached to tokens)

pub mod config;
pub mod keyword_cache;
pub mod printer;
pub mod span_tracker;
pub mod statements;
#[cfg(test)]
mod tests;

use crate::ast::{AstScript, AstStmt};
use crate::context::RenderContext;
use crate::cst::Cst;
use crate::formatter::config::FormatterConfig;
use crate::formatter::printer::Printer;
use crate::lexer::tokenize_with_dialect;
use std::fmt;

/// Formatter errors
#[derive(Debug)]
pub enum FormatterError {
    /// Span tracking validation failed
    SpanTracking(String),

    /// Invalid context state
    InvalidContext(String),

    /// Not yet implemented
    NotImplemented(String),

    /// Missing syntax node that should have been populated during parsing
    MissingSyntaxNode(String),

    /// Recursion depth limit exceeded
    RecursionLimit(String),
}

impl fmt::Display for FormatterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FormatterError::SpanTracking(msg) => write!(f, "Span tracking error: {}", msg),
            FormatterError::InvalidContext(msg) => write!(f, "Invalid context: {}", msg),
            FormatterError::NotImplemented(msg) => write!(f, "Not implemented: {}", msg),
            FormatterError::MissingSyntaxNode(msg) => write!(f, "Missing syntax node: {}", msg),
            FormatterError::RecursionLimit(msg) => write!(f, "Recursion limit exceeded: {}", msg),
        }
    }
}

impl std::error::Error for FormatterError {}

/// SQL formatter with automatic span tracking and CST-based trivia preservation
pub struct Formatter {
    config: FormatterConfig,
}

impl Formatter {
    /// Create new formatter with default configuration
    pub fn new() -> Self {
        Self {
            config: FormatterConfig::default(),
        }
    }

    /// Create formatter with custom configuration
    pub fn with_config(config: FormatterConfig) -> Self {
        Self { config }
    }

    /// Format a SQL script (main entry point)
    ///
    /// Takes RenderContext and AstScript, returns updated context with FormattedContext.
    ///
    /// ARCHITECTURAL NOTE: This uses CST-based trivia preservation.
    /// Comments are attached to tokens in the CST, not tracked separately.
    pub fn format_script(
        &self,
        context: RenderContext,
        script: &AstScript,
    ) -> Result<RenderContext, FormatterError> {
        // CLI and other callers may mark the context as template-driven (e.g. dbt/Jinja files)
        // even if the concrete source we are formatting is rendered SQL (no visible Jinja tokens).
        let has_template = context.has_template();

        // Clone source to avoid borrowing context
        let source = context.source().to_string();

        // The formatter emits from the token stream, trivia attached.
        // Use the dialect from config for tokenization
        let lex_result = tokenize_with_dialect(&source, self.config.dialect.as_ref());
        let cst = Cst::new(lex_result.tokens);

        let mut printer = Printer::new(&self.config, &source, Some(&cst));

        // Set the syntax arena for token lookups
        // The syntax arena owns structural tokens (parens, keywords) that AST nodes reference by ID
        printer.set_syntax_arena(&script.syntax_arena);

        let statements = &script.stmts;
        let stmt_count = statements.len();

        // Handle empty script case (comments only, whitespace only, or truly empty)
        // This ensures we create a valid span mapping even when there are no statements
        if stmt_count == 0 {
            if !source.is_empty() {
                // Create a single mapping covering the entire source
                let full_span = crate::lexer::Span {
                    start: 0,
                    end: source.len() as u32,
                };
                printer.begin_span(full_span, crate::context::span_map::MappingKind::Identity);

                // Emit all content (comments, whitespace) exactly as-is
                printer.emit_all_tokens_until(source.len() as u32);
                printer.emit_remaining_trivia_v2();

                printer.end_span();
            }
            // For truly empty source, printer.finish() will handle the empty case
            return printer.finish(context, has_template);
        }

        // Format each top-level statement
        // ARCHITECTURE: Each statement's source span extends from its start to the NEXT statement's start
        // (or EOF for the last statement). This ensures inter-statement gaps (comments, whitespace)
        // are included in the preceding statement's span, achieving complete coverage.
        for (idx, stmt) in statements.iter().enumerate() {
            let stmt_span = stmt.span();
            let is_first = idx == 0;
            let is_last = idx == stmt_count - 1;

            // Determine the span to track:
            // - Start: 0 for first statement (includes leading trivia), otherwise stmt start
            // - End: source.len() for last statement, otherwise next statement's start
            let tracking_span = {
                let start = if is_first { 0 } else { stmt_span.start };
                let end = if is_last {
                    source.len() as u32
                } else {
                    // Extend to next statement's start to include inter-statement gap
                    statements[idx + 1].span().start
                };
                crate::lexer::Span { start, end }
            };

            // Begin span tracking - ALL content emitted until end_span() is part of this span
            printer.begin_span(
                tracking_span,
                crate::context::span_map::MappingKind::Reformatted,
            );

            // For FIRST statement: emit leading trivia before the statement
            // For subsequent statements: the inter-statement gap handler (emit_raw_span)
            // will collect and emit leading trivia as part of the gap
            if is_first {
                printer.emit_comments_before(stmt_span.start);
            }
            // NOTE: We don't call mark_leading_trivia_emitted_at here anymore.
            // emit_raw_span collects and emits leading trivia of the next statement
            // as part of the gap, then marks it as emitted. This ensures section
            // comments between statements are preserved.

            // Format the statement
            statements::format_scripting_statement(&mut printer, stmt)
                .or_else(|_| self.format_stmt(&mut printer, stmt))?;

            // CRITICAL: Ensure token cursor is positioned at statement end for proper inter-statement trivia emission.
            // Some formatters (like CREATE STAGE) use extract_span which doesn't advance the cursor.
            printer.reset_token_index_at(stmt_span.end);

            // Parser never consumes semicolons - they're in the gap between statements.
            // emit_all_tokens_until() will emit them naturally as part of the inter-statement content.

            // Emit inter-statement or trailing content exactly as in source
            if is_last {
                // After last statement: emit everything to EOF
                printer.emit_all_tokens_until(source.len() as u32);

                // CRITICAL: Emit any leading trivia attached to the EOF token itself
                // EOF tokens can have leading trivia (e.g., trailing file comments)
                // that won't be emitted by emit_all_tokens_until since EOF has empty span
                printer.emit_remaining_trivia_v2();
            } else {
                // Inter-statement gap: emit raw source from after semicolon to next statement
                let next_stmt = &statements[idx + 1];
                let gap_end = next_stmt.span().start;
                printer.emit_all_tokens_until(gap_end);
                // Ensure blank line between statements, but only a single newline before OpaqueContent
                // (parse error fallback should preserve original spacing, not add extra blank lines)
                if matches!(
                    next_stmt,
                    AstStmt::OpaqueContent { .. } | AstStmt::GoBatchSeparator { .. }
                ) {
                    printer.newline_if_needed();
                } else {
                    printer.ensure_blank_line();
                }
            }

            // End span tracking - this statement's span is now complete
            printer.end_span();
        }

        // Finalize and return updated context
        printer.finish(context, has_template)
    }

    /// Format a single statement (internal dispatcher)
    ///
    /// ARCHITECTURAL NOTE: This does NOT call begin_span/end_span.
    /// Span tracking happens at statement level in format_script().
    ///
    /// Node-level tracking happens via:
    /// - Explicit: set_formatted_span() during formatting (future)
    /// - Proportional: update_formatted_spans() in Printer::finish()
    fn format_stmt(&self, printer: &mut Printer, stmt: &AstStmt) -> Result<(), FormatterError> {
        match stmt {
            // ─── Span-only: struct variants (no special formatting yet) ───
            // These emit the original source span verbatim. When a proper
            // formatter is implemented for any of these, move it out of
            // this combined arm into its own arm with the format function.
            AstStmt::ValuesQuery(_)
            | AstStmt::ReplaceInto(_)
            | AstStmt::AlterFunction(_)
            | AstStmt::AlterProcedure(_)
            | AstStmt::CreateDatabase(_)
            | AstStmt::AlterDatabase(_)
            | AstStmt::DropDatabase(_)
            | AstStmt::UndropDatabase(_)
            | AstStmt::CreateSchema(_)
            | AstStmt::AlterSchema(_)
            | AstStmt::DropSchema(_)
            | AstStmt::UndropSchema(_)
            | AstStmt::UndropTable(_)
            | AstStmt::UndropType(_)
            | AstStmt::AlterTask(_)
            | AstStmt::DropTask(_)
            | AstStmt::CreateWarehouse(_)
            | AstStmt::AlterWarehouse(_)
            | AstStmt::DropWarehouse(_)
            | AstStmt::CreatePipe(_)
            | AstStmt::AlterPipe(_)
            | AstStmt::DropPipe(_)
            | AstStmt::PgListen(_)
            | AstStmt::PgNotify(_)
            | AstStmt::PgUnlisten(_)
            | AstStmt::PgLockTable(_)
            | AstStmt::PgCreateRule(_)
            | AstStmt::PgCreateAggregate(_)
            | AstStmt::PgCreateOperator(_)
            | AstStmt::PgAlterSystem(_)
            | AstStmt::PgAlterTablespace(_)
            | AstStmt::PgDropOwned(_)
            | AstStmt::PgReassignOwned(_)
            | AstStmt::PgDiscard(_)
            | AstStmt::PgCluster(_)
            | AstStmt::PgPublication(_)
            | AstStmt::PgSubscription(_)
            | AstStmt::CreatePrincipal(_)
            | AstStmt::AlterPrincipal(_)
            | AstStmt::DropPrincipal(_)
            | AstStmt::AlterAuthorization(_)
            | AstStmt::MssqlExecuteAs(_)
            | AstStmt::MssqlRevert { .. }
            | AstStmt::MssqlAuditDdl(_)
            | AstStmt::MssqlSecurityObjectDdl(_)
            | AstStmt::PgDropExtension(_)
            | AstStmt::AlterView(_)
            | AstStmt::AlterMaterializedView(_)
            | AstStmt::PgAlterRule(_)
            | AstStmt::PgDropRule(_)
            | AstStmt::PgAlterTableTriggerState(_)
            | AstStmt::PgSet(_)
            | AstStmt::PgDropSequence(_)
            | AstStmt::PgDropType(_)
            | AstStmt::PgDropIndex(_)
            | AstStmt::PgCreateTablespace(_)
            | AstStmt::PgDropTablespace(_)
            | AstStmt::BqExportData(_)
            | AstStmt::BqLoadData(_)
            | AstStmt::MysqlLoadData(_)
            | AstStmt::MysqlRenameTable(_)
            | AstStmt::CreateEvent(_)
            | AstStmt::AlterEvent(_)
            | AstStmt::CreateMysqlTrigger(_)
            | AstStmt::BqAssert(_)
            | AstStmt::BqCreateSnapshotTable(_)
            | AstStmt::BqDropSnapshotTable(_)
            | AstStmt::BqCreateSearchIndex(_)
            | AstStmt::BqDropSearchIndex(_)
            | AstStmt::BqCreateVectorIndex(_)
            | AstStmt::BqDropVectorIndex(_)
            | AstStmt::BqAlterVectorIndex(_)
            | AstStmt::BqCreateModel(_)
            | AstStmt::BqAlterModel(_)
            | AstStmt::BqExportModel(_)
            | AstStmt::BqDropModel(_)
            | AstStmt::CreateExternalTable(_)
            | AstStmt::CreateExternalSchema(_)
            | AstStmt::DescribeHistory(_)
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
            | AstStmt::CreateCatalog(_)
            | AstStmt::AlterCatalog(_)
            | AstStmt::DropCatalog(_)
            | AstStmt::CreateVolume(_)
            | AstStmt::AlterVolume(_)
            | AstStmt::DropVolume(_)
            | AstStmt::CreateStorageCredential(_)
            | AstStmt::AlterStorageCredential(_)
            | AstStmt::DropStorageCredential(_)
            | AstStmt::CreateConnection(_)
            | AstStmt::AlterConnection(_)
            | AstStmt::DropConnection(_)
            | AstStmt::CreateFlow(_)
            | AstStmt::CacheTable(_)
            | AstStmt::UncacheTable(_)
            | AstStmt::RepairTable(_)
            | AstStmt::Reconfigure { .. }
            | AstStmt::MssqlExec(_)
            | AstStmt::MssqlTryCatch(_)
            | AstStmt::MssqlIf(_)
            | AstStmt::MssqlWhile(_)
            | AstStmt::MssqlPrint(_)
            | AstStmt::MssqlThrow(_)
            | AstStmt::MssqlRaiserror(_)
            | AstStmt::MssqlSetOption(_)
            | AstStmt::MysqlSet(_)
            | AstStmt::MssqlWaitfor(_)
            | AstStmt::MssqlGoto(_)
            | AstStmt::MssqlLabel(_)
            | AstStmt::CreateMssqlTrigger(_)
            | AstStmt::DropMssqlTrigger(_)
            | AstStmt::MssqlBulkInsert(_)
            | AstStmt::MssqlCreateExternalDataSource(_)
            | AstStmt::MssqlAlterExternalDataSource(_)
            | AstStmt::AlterUserMapping(_)
            | AstStmt::DropUserMapping(_)
            | AstStmt::CreateUserMapping(_)
            | AstStmt::CreateForeignTable(_)
            | AstStmt::ImportForeignSchema(_)
            | AstStmt::CreateForeignServer(_)
            | AstStmt::AlterForeignServer(_)
            | AstStmt::MssqlAlterServerConfiguration(_)
            | AstStmt::MssqlCreateExternalModel(_)
            | AstStmt::MssqlAlterExternalModel(_)
            | AstStmt::MssqlDropExternalModel(_)
            | AstStmt::MssqlCreateVectorIndex(_)
            | AstStmt::AlterUser(_)
            | AstStmt::AlterAccount(_)
            | AstStmt::CreateNotificationIntegration(_)
            | AstStmt::AlterNotificationIntegration(_)
            | AstStmt::DropNotificationIntegration(_)
            | AstStmt::CreateShare(_)
            | AstStmt::AlterShare(_)
            | AstStmt::CreateDatashare(_)
            | AstStmt::AlterDatashare(_)
            | AstStmt::CreateSecurityIntegration(_)
            | AstStmt::AlterSecurityIntegration(_)
            | AstStmt::AlterReplicationGroup(_)
            | AstStmt::AlterFailoverGroup(_)
            | AstStmt::CreateTag(_)
            | AstStmt::AlterTag(_)
            | AstStmt::CreateFileFormat(_)
            | AstStmt::AlterFileFormat(_)
            | AstStmt::AlterSession(_)
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
            | AstStmt::ExecuteImmediateFrom(_)
            | AstStmt::CreateExternalFunction(_)
            | AstStmt::CreateAlert(_)
            | AstStmt::AlterAlert(_)
            | AstStmt::CreateJoinPolicy(_)
            | AstStmt::AlterJoinPolicy(_)
            | AstStmt::DropJoinPolicy(_)
            | AstStmt::CreateDataMetricFunction(_)
            | AstStmt::CreateReplicationFailoverGroup(_) => {
                printer.push_span(stmt.span());
                Ok(())
            }

            // ─── Format-function delegations: Databricks Unity Catalog ───
            AstStmt::CreateExternalLocation(s) => {
                statements::format_create_external_location(printer, s)
            }
            AstStmt::AlterExternalLocation(s) => {
                statements::format_alter_external_location(printer, s)
            }
            AstStmt::DropExternalLocation(s) => {
                statements::format_drop_external_location(printer, s)
            }

            // ─── Span-only: inline variants ───
            AstStmt::JinjaPlaceholder { span, .. }
            | AstStmt::OpaqueContent { span, .. }
            | AstStmt::GoBatchSeparator { span, .. }
            | AstStmt::Error { span, .. } => {
                printer.push_span(*span);
                Ok(())
            }

            // ─── Format-function delegations: DML ───
            // (MySQL `TABLE tbl ...` is handled inside format_select, the
            // single chokepoint for every SELECT-formatting path.)
            AstStmt::Select(_) | AstStmt::SetSelect(_) => statements::format_select(printer, stmt),
            AstStmt::Insert(s) => statements::format_insert(printer, s),
            AstStmt::MultiInsert(s) => statements::format_multi_insert(printer, s),
            AstStmt::Update(s) => statements::format_update(printer, s),
            AstStmt::Delete(s) => statements::format_delete(printer, s),
            AstStmt::Merge(s) => statements::format_merge(printer, s),
            AstStmt::Truncate(s) => statements::format_truncate(printer, s),

            // ─── Format-function delegations: DDL ───
            AstStmt::Drop(s) => statements::format_drop(printer, s),
            AstStmt::CreateTable(s) => statements::format_create_table(printer, s),
            AstStmt::CreateDynamicTable(s) => statements::format_create_dynamic_table(printer, s),
            AstStmt::CreateTask(s) => statements::format_create_task(printer, s),
            AstStmt::CreateView(s) => statements::format_create_view(printer, s),
            AstStmt::CreateStage(s) => statements::format_create_stage(printer, s),
            AstStmt::CreateStream(s) => statements::format_create_stream(printer, s),
            AstStmt::AlterTable(s) => statements::format_alter_table(printer, s),

            // ─── Format-function delegations: policies ───
            AstStmt::DropNetworkPolicy(s) => statements::format_drop_network_policy(printer, s),
            AstStmt::DropAuthenticationPolicy(s) => {
                statements::format_drop_authentication_policy(printer, s)
            }
            AstStmt::DropAggregationPolicy(s) => {
                statements::format_drop_aggregation_policy(printer, s)
            }
            AstStmt::DropApiIntegration(s) => statements::format_drop_api_integration(printer, s),
            AstStmt::DropExternalAccessIntegration(s) => {
                statements::format_drop_external_access_integration(printer, s)
            }
            AstStmt::DropStorageIntegration(s) => {
                statements::format_drop_storage_integration(printer, s)
            }
            AstStmt::DropRowAccessPolicy(s) => {
                statements::format_drop_row_access_policy(printer, s)
            }
            AstStmt::DropAllRowAccessPolicies(s) => {
                statements::format_drop_all_row_access_policies(printer, s)
            }
            AstStmt::DropMaskingPolicy(s) => statements::format_drop_masking_policy(printer, s),
            AstStmt::DropSessionPolicy(s) => statements::format_drop_session_policy(printer, s),
            AstStmt::DropPasswordPolicy(s) => statements::format_drop_password_policy(printer, s),
            AstStmt::DropProjectionPolicy(s) => {
                statements::format_drop_projection_policy(printer, s)
            }
            AstStmt::DropStream(s) => statements::format_drop_stream(printer, s),
            AstStmt::CreateAuthenticationPolicy(s) => {
                statements::format_create_authentication_policy(printer, s)
            }
            AstStmt::CreateAggregationPolicy(s) => {
                statements::format_create_aggregation_policy(printer, s)
            }
            AstStmt::CreateApiIntegration(s) => {
                statements::format_create_api_integration(printer, s)
            }
            AstStmt::CreateStorageIntegration(s) => {
                statements::format_create_storage_integration(printer, s)
            }
            AstStmt::CreateExternalAccessIntegration(s) => {
                statements::format_create_external_access_integration(printer, s)
            }
            AstStmt::AlterAuthenticationPolicy(s) => {
                statements::format_alter_authentication_policy(printer, s)
            }
            AstStmt::AlterAggregationPolicy(s) => {
                statements::format_alter_aggregation_policy(printer, s)
            }
            AstStmt::AlterApiIntegration(s) => statements::format_alter_api_integration(printer, s),
            AstStmt::AlterStorageIntegration(s) => {
                statements::format_alter_storage_integration(printer, s)
            }
            AstStmt::AlterExternalAccessIntegration(s) => {
                statements::format_alter_external_access_integration(printer, s)
            }
            AstStmt::CreateRowAccessPolicy(s) => {
                statements::format_create_row_access_policy(printer, s)
            }
            AstStmt::AlterRowAccessPolicy(s) => {
                statements::format_alter_row_access_policy(printer, s)
            }
            AstStmt::CreateMaskingPolicy(s) => statements::format_create_masking_policy(printer, s),
            AstStmt::AlterMaskingPolicy(s) => statements::format_alter_masking_policy(printer, s),
            AstStmt::CreateNetworkPolicy(s) => statements::format_create_network_policy(printer, s),
            AstStmt::AlterNetworkPolicy(s) => statements::format_alter_network_policy(printer, s),
            AstStmt::CreateSessionPolicy(s) => statements::format_create_session_policy(printer, s),
            AstStmt::CreatePasswordPolicy(s) => {
                statements::format_create_password_policy(printer, s)
            }
            AstStmt::CreateProjectionPolicy(s) => {
                statements::format_create_projection_policy(printer, s)
            }
            AstStmt::AlterSessionPolicy(s) => statements::format_alter_session_policy(printer, s),
            AstStmt::AlterPasswordPolicy(s) => statements::format_alter_password_policy(printer, s),
            AstStmt::AlterProjectionPolicy(s) => {
                statements::format_alter_projection_policy(printer, s)
            }
            AstStmt::AlterDynamicTable(s) => statements::format_alter_dynamic_table(printer, s),
            AstStmt::AlterStage(s) => statements::format_alter_stage(printer, s),
            AstStmt::AlterStream(s) => statements::format_alter_stream(printer, s),

            // ─── Format-function delegations: utility ───
            AstStmt::Show(s) => statements::format_show(printer, s),
            AstStmt::Describe(s) => statements::format_describe(printer, s),
            AstStmt::Use(s) => statements::format_use_stmt(printer, s),

            // ─── Format-function delegations: transaction / session ───
            AstStmt::BeginTransaction { span, .. } => {
                statements::format_begin_transaction(printer, *span)
            }
            AstStmt::Commit { span, .. } => statements::format_commit(printer, *span),
            AstStmt::Rollback { span, .. } => statements::format_rollback(printer, *span),
            AstStmt::SetVariable { span, .. } => statements::format_set_variable(printer, *span),
            AstStmt::PipeChain { span, .. } => statements::format_pipe_chain(printer, *span),

            // ─── Format-function delegations: async job control ───
            AstStmt::Await {
                span,
                job_id_expr_span,
                ..
            } => statements::format_await(printer, *span, *job_id_expr_span),
            AstStmt::Cancel {
                span,
                job_id_expr_span,
                ..
            } => statements::format_cancel(printer, *span, *job_id_expr_span),

            // ─── Format-function delegations: procedure/function DDL ───
            AstStmt::CreateProcedure(s) => statements::format_create_procedure(
                printer,
                s.span,
                s.create_span,
                s.or_replace_span,
                s.or_alter_span,
                s.definer.as_ref().map(|d| d.span),
                s.procedure_keyword_span,
                s.name_span,
                s.params_span,
                s.returns_span,
                s.body_span,
                s.body_stmt.as_deref(),
                s.opening_delimiter_token,
                s.closing_delimiter_token,
            ),

            AstStmt::CreateFunction(s) => statements::format_create_function(
                printer,
                s.span,
                s.create_span,
                s.or_replace_span,
                s.or_alter_span,
                s.definer.as_ref().map(|d| d.span),
                s.temp_keyword_span,
                s.aggregate_keyword_span,
                s.function_keyword_span,
                s.if_not_exists_span,
                s.name_span,
                s.params_span,
                s.returns_span,
                s.body_span,
                s.body_stmt.as_deref(),
                s.opening_delimiter_token,
                s.closing_delimiter_token,
            ),

            AstStmt::CreateTableFunction(s) => statements::format_create_table_function(
                printer,
                s.span,
                s.create_span,
                s.or_replace_span,
                s.temp_keyword_span,
                s.table_keyword_span,
                s.function_keyword_span,
                s.if_not_exists_span,
                s.name_span,
                s.params_span,
            ),

            // ─── Format-function delegations: data loading ───
            AstStmt::CopyIntoTable {
                table_name_span,
                from_span,
                options_span,
                ..
            } => statements::format_copy_into_table(
                printer,
                *table_name_span,
                *from_span,
                *options_span,
            ),

            AstStmt::CopyIntoLocation {
                into_span,
                from_span,
                options_span,
                ..
            } => statements::format_copy_into_location(
                printer,
                *into_span,
                *from_span,
                *options_span,
            ),

            // ─── Redshift UNLOAD / COPY: span passthrough (byte-exact) ───
            AstStmt::Unload { span, .. } | AstStmt::RedshiftCopy { span, .. } => {
                printer.push_span(*span);
                Ok(())
            }

            // ─── Format-function delegations: Jinja ───
            AstStmt::JinjaConditionalStmt(block) => self.format_jinja_stmt_block(printer, block),

            // ─── Grant/Revoke: span + optional semicolon token ───
            AstStmt::Grant(g) => {
                printer.push_span(g.span);
                if let Some(semi_id) = g.semicolon_token {
                    printer.push_token_id(semi_id);
                }
                Ok(())
            }

            AstStmt::Revoke(r) => {
                printer.push_span(r.span);
                if let Some(semi_id) = r.semicolon_token {
                    printer.push_token_id(semi_id);
                }
                Ok(())
            }

            AstStmt::Deny(d) => {
                printer.push_span(d.span);
                if let Some(semi_id) = d.semicolon_token {
                    printer.push_token_id(semi_id);
                }
                Ok(())
            }

            // ─── ClauseFragment ───
            AstStmt::ClauseFragment { fragment, .. } => {
                self.format_clause_fragment(fragment.as_ref(), printer)?;
                Ok(())
            }

            // ─── Explain (recursive) ───
            AstStmt::Explain(explain) => {
                printer.push_span(explain.explain_span);
                if let Some(opts_span) = explain.options_span {
                    printer.space();
                    printer.push_span(opts_span);
                }
                printer.space();
                self.format_stmt(printer, &explain.inner_stmt)?;
                Ok(())
            }

            // ─── PostgreSQL utility statements - CST-based formatting ───
            AstStmt::CreateIndex(s) => statements::format_create_index(printer, s),
            AstStmt::CreateSynonym(s) => statements::format_create_synonym(printer, s),
            AstStmt::CommentOn(s) => statements::format_comment_on(printer, s),
            AstStmt::DoBlock(s) => statements::format_do_block(printer, s),
            AstStmt::Vacuum(s) => statements::format_vacuum(printer, s),
            AstStmt::AnalyzeStmt(s) => statements::format_analyze(printer, s),
            AstStmt::Optimize(s) => statements::format_optimize(printer, s),
            AstStmt::CreateType(s) => statements::format_create_type(printer, s),
            AstStmt::AlterType(s) => statements::format_alter_type(printer, s),
            AstStmt::CreateExtension(s) => statements::format_create_extension(printer, s),
            AstStmt::CreateSequence(s) => statements::format_create_sequence(printer, s),
            AstStmt::AlterSequence(s) => statements::format_alter_sequence(printer, s),
            AstStmt::CreatePgTrigger(s) => statements::format_create_pg_trigger(printer, s),
            AstStmt::AlterPgTrigger(s) => statements::format_alter_pg_trigger(printer, s),
            AstStmt::DropPgTrigger(s) => statements::format_drop_pg_trigger(printer, s),
            AstStmt::CreateDomain(s) => statements::format_create_domain(printer, s),
            AstStmt::AlterDomain(s) => statements::format_alter_domain(printer, s),
            AstStmt::DropDomain(s) => statements::format_drop_domain(printer, s),
            AstStmt::CreatePgPolicy(s) => statements::format_create_pg_policy(printer, s),
            AstStmt::AlterPgPolicy(s) => statements::format_alter_pg_policy(printer, s),
            AstStmt::DropPgPolicy(s) => statements::format_drop_pg_policy(printer, s),
            AstStmt::AlterIndex(s) => statements::format_alter_index(printer, s),
            AstStmt::Reindex(s) => statements::format_reindex(printer, s),
            AstStmt::PgPrepare(s) => statements::format_pg_prepare(printer, s),
            AstStmt::PgExecute(s) => statements::format_pg_execute(printer, s),
            AstStmt::PgDeallocate(s) => statements::format_pg_deallocate(printer, s),
            AstStmt::PgCopy(s) => statements::format_pg_copy(printer, s),
            AstStmt::PgRefreshMatview(s) => statements::format_pg_refresh_matview(printer, s),

            // ─── Scripting fallback (not handled by format_scripting_statement) ───
            AstStmt::Block { .. }
            | AstStmt::If { .. }
            | AstStmt::CaseStmt { .. }
            | AstStmt::Declare { .. }
            | AstStmt::DeclareTable { .. }
            | AstStmt::DeclareCursor { .. }
            | AstStmt::Let { .. }
            | AstStmt::LetCursor { .. }
            | AstStmt::Assign { .. }
            | AstStmt::Return { .. }
            | AstStmt::Raise { .. }
            | AstStmt::Signal { .. }
            | AstStmt::Resignal { .. }
            | AstStmt::GetDiagnostics { .. }
            | AstStmt::DeclareCondition { .. }
            | AstStmt::DeclareHandler { .. }
            | AstStmt::For { .. }
            | AstStmt::ForEach { .. }
            | AstStmt::While { .. }
            | AstStmt::Repeat { .. }
            | AstStmt::Loop { .. }
            | AstStmt::Break { .. }
            | AstStmt::Continue { .. }
            | AstStmt::Null { .. }
            | AstStmt::OpenCursor { .. }
            | AstStmt::FetchCursor { .. }
            | AstStmt::CloseCursor { .. }
            | AstStmt::ExecuteImmediate { .. }
            | AstStmt::Call { .. } => Err(FormatterError::NotImplemented(
                "Scripting statement not handled by format_scripting_statement".to_string(),
            )),
        }
    }

    /// Format a Jinja conditional block that wraps full SQL statements
    fn format_jinja_stmt_block(
        &self,
        printer: &mut Printer,
        block: &crate::ast::JinjaStmtBlock,
    ) -> Result<(), FormatterError> {
        // Output opening {% if %} or {% for %}
        printer.format_jinja_delimiter(&block.opening)?;
        printer.newline();

        // Format the primary branch statements
        for (i, stmt) in block.then_stmts.iter().enumerate() {
            if i > 0 {
                printer.newline();
            }
            // Try scripting first, fall back to regular statement formatting
            statements::format_scripting_statement(printer, stmt)
                .or_else(|_| self.format_stmt(printer, stmt))?;
        }
        printer.newline();

        // Format elif branches
        for elif in &block.elif_branches {
            printer.format_jinja_delimiter(&elif.delimiter)?;
            printer.newline();
            for (i, stmt) in elif.stmts.iter().enumerate() {
                if i > 0 {
                    printer.newline();
                }
                statements::format_scripting_statement(printer, stmt)
                    .or_else(|_| self.format_stmt(printer, stmt))?;
            }
            printer.newline();
        }

        // Format else branch
        if let Some(else_branch) = &block.else_branch {
            printer.format_jinja_delimiter(&else_branch.delimiter)?;
            printer.newline();
            for (i, stmt) in else_branch.stmts.iter().enumerate() {
                if i > 0 {
                    printer.newline();
                }
                statements::format_scripting_statement(printer, stmt)
                    .or_else(|_| self.format_stmt(printer, stmt))?;
            }
            printer.newline();
        }

        // Output closing {% endif %} or {% endfor %}
        printer.format_jinja_delimiter(&block.closing)?;
        Ok(())
    }
}

impl Default for Formatter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod inline_tests {
    use super::*;
    use crate::ast::NodeId;

    #[test]
    fn test_formatter_creation() {
        let formatter = Formatter::new();
        assert_eq!(
            formatter.config.keyword_case,
            crate::formatter::config::KeywordCase::Upper
        );
    }

    #[test]
    fn test_formatter_with_config() {
        let mut config = FormatterConfig::default();
        config.keyword_case = crate::formatter::config::KeywordCase::Lower;

        let formatter = Formatter::with_config(config);
        assert_eq!(
            formatter.config.keyword_case,
            crate::formatter::config::KeywordCase::Lower
        );
    }

    #[test]
    fn test_formatter_empty_script() {
        let formatter = Formatter::new();
        let context = RenderContext::from_source("".to_string());
        let script = AstScript {
            node_id: NodeId::new(0),
            stmts: vec![],
            syntax_arena: crate::syntax::SyntaxArena::new(),
            redaction_spans: vec![],
        };

        // Empty script should format to empty output
        let result = formatter.format_script(context, &script);
        assert!(result.is_ok());
    }
}

impl Formatter {
    /// Format a clause fragment (WHERE, JOIN, HAVING) from inside a Jinja block
    fn format_clause_fragment(
        &self,
        fragment: &crate::ast::StatementFragment,
        printer: &mut crate::formatter::printer::Printer,
    ) -> Result<(), FormatterError> {
        use crate::formatter::statements::select::format_expression;

        // Format FROM clause if present (for fragments that start with FROM)
        if let Some(ref from_items) = fragment.from_items {
            printer.push_keyword("FROM");
            printer.push(" ");
            for (i, item) in from_items.iter().enumerate() {
                if i > 0 {
                    printer.push_comma();
                    if printer.config().space_after_comma {
                        printer.space();
                    }
                }
                // Emit the entire FROM item as a span for simplicity
                let item_span = match &item.kind {
                    crate::ast::FromItemKind::TableRef(table_ref) => table_ref.span,
                    crate::ast::FromItemKind::JinjaBlock(jinja_block) => jinja_block.span,
                    crate::ast::FromItemKind::JinjaTableName(jinja_name) => jinja_name.span,
                };
                printer.push_span(item_span);
            }
        }

        // Format JOINs - these are stored as part of the fragment
        for join in &fragment.joins {
            if printer.config().joins_on_newlines {
                printer.newline();
            } else {
                printer.push(" ");
            }

            // Format join type and keywords
            match &join.kind {
                crate::ast::AstJoinKind::Inner => {
                    printer.push_keyword("JOIN");
                }
                crate::ast::AstJoinKind::LeftOuter => {
                    printer.push_keyword("LEFT");
                    printer.push(" ");
                    printer.push_keyword("JOIN");
                }
                crate::ast::AstJoinKind::RightOuter => {
                    printer.push_keyword("RIGHT");
                    printer.push(" ");
                    printer.push_keyword("JOIN");
                }
                crate::ast::AstJoinKind::FullOuter => {
                    printer.push_keyword("FULL");
                    printer.push(" ");
                    printer.push_keyword("JOIN");
                }
                crate::ast::AstJoinKind::Cross => {
                    printer.push_keyword("CROSS");
                    printer.push(" ");
                    printer.push_keyword("JOIN");
                }
                _ => {
                    // Other join types (Natural, Asof) - emit keyword from span
                    printer.push_keyword("JOIN");
                }
            }

            printer.push(" ");

            // Format the right table reference
            printer.push_span(join.right.span);

            // Format the join constraint (ON or USING)
            match &join.constraint {
                crate::ast::AstJoinConstraint::On(expr) => {
                    printer.push(" ");
                    printer.push_keyword("ON");
                    printer.push(" ");
                    format_expression(printer, expr)?;
                }
                crate::ast::AstJoinConstraint::Using(columns) => {
                    printer.push(" ");
                    printer.push_keyword("USING");
                    printer.push(" ");
                    printer.push("(");
                    for (i, col) in columns.iter().enumerate() {
                        if i > 0 {
                            printer.push_comma();
                            if printer.config().space_after_comma {
                                printer.space();
                            }
                        }
                        printer.push_span(col.span);
                    }
                    printer.push(")");
                }
                crate::ast::AstJoinConstraint::None => {}
            }
        }

        // Format WHERE clause
        if let Some(where_condition_clause) = &fragment.where_clause {
            // Check if this is a condition continuation (AND/OR) rather than a full WHERE clause
            // If we have no FROM, no JOINs, and just a where_clause, it's likely a condition fragment
            // In that case, emit the full span to preserve the AND/OR keyword
            let is_condition_continuation = fragment.from_items.is_none()
                && fragment.joins.is_empty()
                && fragment.having_clause.is_none()
                && fragment.group_by.is_none();

            if is_condition_continuation {
                // Emit the full span which includes AND/OR keyword
                printer.push_span(where_condition_clause.span);
            } else {
                printer.newline();
                printer.push_keyword("WHERE");
                printer.push(" ");
                format_expression(printer, &where_condition_clause.expr)?;
            }
        }

        // Format HAVING clause
        if let Some(having_condition_clause) = &fragment.having_clause {
            printer.newline();
            printer.push_keyword("HAVING");
            printer.push(" ");
            format_expression(printer, &having_condition_clause.expr)?;
        }

        Ok(())
    }
}
