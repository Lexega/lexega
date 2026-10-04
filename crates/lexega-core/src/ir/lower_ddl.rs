// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! AST → [`DdlPlan`] lowering for non-query statements.
//!
//! [`lower_ddl_stmt`] inspects every [`AstStmt`] variant and either
//! returns `None` (for query-bearing arms — those lower to
//! [`super::plan::RelPlan`] via [`super::lower::lower_query`]) or a
//! populated [`DdlPlan`] capturing the abstract verb ([`DdlAction`]),
//! the acted-upon object kind
//! ([`crate::facts::identity::ObjectKind`]), the named
//! target (when the AST exposes a name span), and the inner body
//! plans (for body-bearing variants like
//! `BEGIN .. END` / `CREATE PROCEDURE` / `IF` / `WHILE` / etc.).
//!
//! # Body recursion
//!
//! Body-bearing variants populate [`DdlPlan::body`] by recursing
//! into each inner [`AstStmt`] via [`super::lower_dispatch::lower_stmt`].
//! The lowering context (`&IrLowerInputs`) is threaded through so
//! nested bodies see the same catalog / session / strict-mode
//! configuration as the outer statement. Recursion is unbounded
//! at this layer — pathological inputs are bounded upstream by the
//! parser's depth limits and the IR lowerer's own recovery paths.
//!
//! # No catch-all arms
//!
//! No `_ =>` arms are permitted on [`AstStmt`].
//! Every variant is enumerated explicitly so adding a new AST
//! statement type forces a deliberate decision about its DDL
//! lowering.

use std::rc::Rc;

use crate::ast;
use crate::ast::types::AstStmt;
use crate::facts::identity::ObjectKind;
use crate::ir::normalize_identifier;
use crate::lexer::Span;

use super::ddl_plan::{DdlAction, DdlOptions, DdlPlan, DdlSchemaMutation, DdlTarget};
use super::lower_inputs::{IrLowerInputs, LoweredStatement};
use super::statement_plan::StatementPlan;

/// Lower a non-query [`AstStmt`] to a [`DdlPlan`].
///
/// Returns `None` for query-bearing statements (`SELECT` / `INSERT`
/// / `UPDATE` / `DELETE` / `MERGE` / `EXPLAIN` / set-operations /
/// `VALUES`), which lower to a [`super::plan::RelPlan`] instead.
/// Returns `None` for opaque/error/jinja placeholder arms that
/// carry no DDL semantics.
///
/// `inputs` is the lowering context bundle (source / catalog /
/// session / strict-mode / func-catalog / model-catalog). It's
/// required for body-bearing variants whose inner statements lower
/// recursively via [`super::lower_dispatch::lower_stmt`]; non-body
/// variants ignore everything but `inputs.source`.
pub fn lower_ddl_stmt(stmt: &AstStmt, inputs: &IrLowerInputs) -> Option<DdlPlan> {
    let source = inputs.source;
    match stmt {
        // ---- Query-bearing — lower via lower_query, not here. ----
        AstStmt::Select(_)
        | AstStmt::SetSelect(_)
        | AstStmt::ValuesQuery(_)
        | AstStmt::Insert(_)
        | AstStmt::ReplaceInto(_)
        | AstStmt::MultiInsert(_)
        | AstStmt::Update(_)
        | AstStmt::Delete(_)
        | AstStmt::Merge(_)
        | AstStmt::Explain(_) => None,

        // ---- Opaque / Error / Jinja / batch separator — no DDL. ----
        AstStmt::OpaqueContent { .. }
        | AstStmt::ClauseFragment { .. }
        | AstStmt::JinjaPlaceholder { .. }
        | AstStmt::JinjaConditionalStmt(_)
        | AstStmt::Error { .. }
        | AstStmt::GoBatchSeparator { .. } => None,

        // ---- CREATE — Snowflake/core ----
        AstStmt::CreateTable(s) => Some(plan(
            DdlAction::Create,
            ObjectKind::Table,
            target_from(s.name_span, source),
            DdlOptions {
                or_replace: s.or_replace_span.is_some(),
                temporary: s.temp_kind_span.is_some(),
                ..DdlOptions::default()
            },
            s.node_id,
            s.span,
        )),
        AstStmt::CreateView(s) => Some(plan(
            DdlAction::Create,
            ObjectKind::View,
            target_from(s.name_span, source),
            DdlOptions {
                or_replace: s.or_replace_span.is_some(),
                temporary: s.temp_kind_span.is_some(),
                ..DdlOptions::default()
            },
            s.node_id,
            s.span,
        )),
        AstStmt::CreateDynamicTable(s) => Some(simple(
            DdlAction::Create,
            ObjectKind::DynamicTable,
            target_from(s.name_span, source),
            s.node_id,
            s.span,
        )),
        AstStmt::CreateTask(s) => Some(simple(
            DdlAction::Create,
            ObjectKind::Task,
            target_from(s.name_span, source),
            s.node_id,
            s.span,
        )),
        AstStmt::CreateStage(s) => Some(plan(
            DdlAction::Create,
            ObjectKind::Stage,
            target_from(s.name_span, source),
            DdlOptions {
                or_replace: s.or_replace_span.is_some(),
                ..DdlOptions::default()
            },
            s.node_id,
            s.span,
        )),
        AstStmt::CreateRowAccessPolicy(s) => Some(simple(
            DdlAction::Create,
            ObjectKind::RowAccessPolicy,
            target_from(s.policy_name_span, source),
            s.node_id,
            s.span,
        )),
        AstStmt::CreateMaskingPolicy(s) => Some(simple(
            DdlAction::Create,
            ObjectKind::MaskingPolicy,
            target_from(s.policy_name_span, source),
            s.node_id,
            s.span,
        )),
        AstStmt::CreateNetworkPolicy(s) => Some(simple(
            DdlAction::Create,
            ObjectKind::NetworkPolicy,
            target_from(s.policy_name_span, source),
            s.node_id,
            s.span,
        )),
        AstStmt::CreateSessionPolicy(s) => Some(simple(
            DdlAction::Create,
            ObjectKind::SessionPolicy,
            target_from(s.policy_name_span, source),
            s.node_id,
            s.span,
        )),
        AstStmt::CreateAuthenticationPolicy(s) => Some(simple(
            DdlAction::Create,
            ObjectKind::AuthenticationPolicy,
            target_from(s.policy_name_span, source),
            s.node_id,
            s.span,
        )),
        AstStmt::CreateApiIntegration(s) => Some(simple(
            DdlAction::Create,
            ObjectKind::ApiIntegration,
            target_from(s.integration_name_span, source),
            s.node_id,
            s.span,
        )),
        AstStmt::CreateNotificationIntegration(s) => Some(simple(
            DdlAction::Create,
            ObjectKind::NotificationIntegration,
            target_from(s.integration_name_span, source),
            s.node_id,
            s.span,
        )),
        AstStmt::CreatePasswordPolicy(s) => Some(simple(
            DdlAction::Create,
            ObjectKind::PasswordPolicy,
            target_from(s.policy_name_span, source),
            s.node_id,
            s.span,
        )),
        AstStmt::CreateAggregationPolicy(s) => Some(simple(
            DdlAction::Create,
            ObjectKind::AggregationPolicy,
            target_from(s.policy_name_span, source),
            s.node_id,
            s.span,
        )),
        AstStmt::CreateProjectionPolicy(s) => Some(simple(
            DdlAction::Create,
            ObjectKind::ProjectionPolicy,
            target_from(s.policy_name_span, source),
            s.node_id,
            s.span,
        )),
        AstStmt::CreateJoinPolicy(s) => Some(simple(
            DdlAction::Create,
            ObjectKind::JoinPolicy,
            target_from(s.policy_name_span, source),
            s.node_id,
            s.span,
        )),
        AstStmt::CreateStorageIntegration(s) => Some(simple(
            DdlAction::Create,
            ObjectKind::StorageIntegration,
            target_from(s.integration_name_span, source),
            s.node_id,
            s.span,
        )),
        AstStmt::CreateExternalAccessIntegration(s) => Some(simple(
            DdlAction::Create,
            ObjectKind::ExternalAccessIntegration,
            target_from(s.integration_name_span, source),
            s.node_id,
            s.span,
        )),
        AstStmt::CreateWarehouse(s) => Some(simple(
            DdlAction::Create,
            ObjectKind::Warehouse,
            target_from(s.name_span, source),
            s.node_id,
            s.span,
        )),
        AstStmt::CreatePipe(s) => Some(simple(
            DdlAction::Create,
            ObjectKind::Pipe,
            target_from(s.name_span, source),
            s.node_id,
            s.span,
        )),
        AstStmt::CreateStream(s) => Some(simple(
            DdlAction::Create,
            ObjectKind::Stream,
            target_from(s.name_span, source),
            s.node_id,
            s.span,
        )),
        AstStmt::CreateDatabase(s) => Some(simple(
            DdlAction::Create,
            ObjectKind::Database,
            target_from(s.name_span, source),
            s.node_id,
            s.span,
        )),
        AstStmt::CreateSchema(s) => Some(simple(
            DdlAction::Create,
            ObjectKind::Schema,
            target_from(s.name_span, source),
            s.node_id,
            s.span,
        )),
        AstStmt::CreateExternalTable(s) => {
            // BQ-style EXTERNAL TABLE carries credentials in OPTIONS()
            // and WITH CONNECTION. Snowflake-style uses LOCATION /
            // INTEGRATION and is covered by other CRED-* rules — when
            // both BQ spans are absent, `bq_options` projects to None
            // so BQ-EXTTBL-*-LEAK rules correctly stay silent.
            let mut credential_spans: Vec<Span> = Vec::new();
            if let Some(sp) = s.options_span {
                credential_spans.push(sp);
            }
            if let Some(sp) = s.connection_span {
                credential_spans.push(sp);
            }
            // Redshift Spectrum: harvest the S3 LOCATION literal + IAM_ROLE arn
            // so BQ-EXTTBL-EXTSTORE / leak rules compose over all_literal_values.
            if let Some(sp) = s.location_span {
                credential_spans.push(sp);
            }
            if let Some(sp) = s.redshift_iam_role_span {
                credential_spans.push(sp);
            }
            if let Some(sp) = s.stored_as_span {
                credential_spans.push(sp);
            }
            // T-SQL / PolyBase: harvest the WITH(...) bag so a hardcoded
            // LOCATION / REJECTED_ROW_LOCATION literal composes with the
            // credential / cloud-scheme rules.
            if let Some(sp) = s.tsql_with_options_span {
                credential_spans.push(sp);
            }
            let mut bq_options = if credential_spans.is_empty() {
                None
            } else {
                Some(extract_bq_options_from_spans(&credential_spans, source))
            };
            // Lift the DATA_SOURCE binding (an identifier value the string-literal
            // harvest skips) as a keyed option so the PolyBase federated-access
            // rule can match `key.normalized: DATA_SOURCE`.
            if let Some(sp) = s.data_source_span {
                if let Some(name) = source_slice(source, sp) {
                    let value_literal = name
                        .trim()
                        .trim_matches(|c| c == '"' || c == '[' || c == ']' || c == '`')
                        .to_string();
                    if !value_literal.is_empty() {
                        bq_options
                            .get_or_insert_with(Default::default)
                            .options
                            .push(crate::ir::ddl_plan::IrBqOptionPair {
                                key_raw: "DATA_SOURCE".to_string(),
                                value_literal,
                            });
                    }
                }
            }
            Some(DdlPlan {
                action: DdlAction::Create,
                object_kind: ObjectKind::ExternalTable,
                target: target_from(s.table_name_span, source),
                body: Vec::new(),
                options: DdlOptions {
                    or_replace: s.or_replace_span.is_some(),
                    ..DdlOptions::default()
                },
                node_id: s.node_id,
                span: s.span,
                schema_mutations: Vec::new(),
                mssql_set_option: None,
                mssql_principal_source: None,
                principal_options: None,
                domain: None,
                pg_index: None,
                pg_trigger: None,
                pg_trigger_state: None,
                pg_session: None,
                bq_assert: None,
                bq_create_model: None,
                bq_export_data: None,
                bq_options,
                show: None,
                synonym: None,
            })
        }

        AstStmt::CreateExternalSchema(s) => {
            // Redshift Spectrum / federated: route the IAM_ROLE arn + URI /
            // DATABASE literals through the bq_options harvest so credential /
            // external-storage rules compose without a new carrier.
            let mut credential_spans: Vec<Span> = Vec::new();
            if let Some(sp) = s.iam_role_span {
                credential_spans.push(sp);
            }
            if let Some(sp) = s.database_literal_span {
                credential_spans.push(sp);
            }
            if let Some(sp) = s.uri_span {
                credential_spans.push(sp);
            }
            let bq_options = if credential_spans.is_empty() {
                None
            } else {
                Some(extract_bq_options_from_spans(&credential_spans, source))
            };
            Some(DdlPlan {
                action: DdlAction::Create,
                object_kind: ObjectKind::ExternalSchema,
                target: target_from(s.name_span, source),
                body: Vec::new(),
                options: DdlOptions::default(),
                node_id: s.node_id,
                span: s.span,
                schema_mutations: Vec::new(),
                mssql_set_option: None,
                mssql_principal_source: None,
                principal_options: None,
                domain: None,
                pg_index: None,
                pg_trigger: None,
                pg_trigger_state: None,
                pg_session: None,
                bq_assert: None,
                bq_create_model: None,
                bq_export_data: None,
                bq_options,
                show: None,
                synonym: None,
            })
        }

        // ---- ALTER — Snowflake/core ----
        AstStmt::AlterRowAccessPolicy(s) => Some(simple(
            DdlAction::Alter,
            ObjectKind::RowAccessPolicy,
            target_from(s.name_span, source),
            s.node_id,
            s.span,
        )),
        AstStmt::AlterMaskingPolicy(s) => Some(simple(
            DdlAction::Alter,
            ObjectKind::MaskingPolicy,
            target_from(s.name_span, source),
            s.node_id,
            s.span,
        )),
        AstStmt::AlterNetworkPolicy(s) => Some(simple(
            DdlAction::Alter,
            ObjectKind::NetworkPolicy,
            target_from(s.name_span, source),
            s.node_id,
            s.span,
        )),
        AstStmt::AlterSessionPolicy(s) => Some(simple(
            DdlAction::Alter,
            ObjectKind::SessionPolicy,
            target_from(s.name_span, source),
            s.node_id,
            s.span,
        )),
        AstStmt::AlterAuthenticationPolicy(s) => Some(simple(
            DdlAction::Alter,
            ObjectKind::AuthenticationPolicy,
            target_from(s.name_span, source),
            s.node_id,
            s.span,
        )),
        AstStmt::AlterUser(s) => Some(simple(
            DdlAction::Alter,
            ObjectKind::Generic,
            target_from(s.user_name_span, source),
            s.node_id,
            s.span,
        )),
        AstStmt::AlterAccount(s) => {
            let surface = match s.action.kind {
                ast::AstAlterAccountActionKind::SetAuthenticationPolicy { .. }
                | ast::AstAlterAccountActionKind::UnsetAuthenticationPolicy { .. } => {
                    ObjectKind::Generic
                }
                ast::AstAlterAccountActionKind::Set { .. }
                | ast::AstAlterAccountActionKind::Unset { .. } => ObjectKind::Account,
            };
            Some(simple(
                DdlAction::Alter,
                surface,
                target_from(s.account_span, source),
                s.node_id,
                s.span,
            ))
        }
        AstStmt::AlterApiIntegration(s) => Some(simple(
            DdlAction::Alter,
            ObjectKind::ApiIntegration,
            target_from(s.name_span, source),
            s.node_id,
            s.span,
        )),
        AstStmt::AlterNotificationIntegration(s) => Some(simple(
            DdlAction::Alter,
            ObjectKind::NotificationIntegration,
            target_from(s.name_span, source),
            s.node_id,
            s.span,
        )),
        AstStmt::AlterPasswordPolicy(s) => Some(simple(
            DdlAction::Alter,
            ObjectKind::PasswordPolicy,
            target_from(s.name_span, source),
            s.node_id,
            s.span,
        )),
        AstStmt::AlterAggregationPolicy(s) => Some(simple(
            DdlAction::Alter,
            ObjectKind::AggregationPolicy,
            target_from(s.name_span, source),
            s.node_id,
            s.span,
        )),
        AstStmt::AlterProjectionPolicy(s) => Some(simple(
            DdlAction::Alter,
            ObjectKind::ProjectionPolicy,
            target_from(s.name_span, source),
            s.node_id,
            s.span,
        )),
        AstStmt::AlterJoinPolicy(s) => Some(simple(
            DdlAction::Alter,
            ObjectKind::JoinPolicy,
            target_from(s.name_span, source),
            s.node_id,
            s.span,
        )),
        AstStmt::AlterStorageIntegration(s) => Some(simple(
            DdlAction::Alter,
            ObjectKind::StorageIntegration,
            target_from(s.name_span, source),
            s.node_id,
            s.span,
        )),
        AstStmt::CreateShare(s) => Some(plan(
            DdlAction::Create,
            ObjectKind::Share,
            target_from(s.name_span, source),
            DdlOptions {
                or_replace: s.or_replace_span.is_some(),
                ..DdlOptions::default()
            },
            s.node_id,
            s.span,
        )),
        AstStmt::AlterShare(s) => Some(simple(
            DdlAction::Alter,
            ObjectKind::Share,
            target_from(s.name_span, source),
            s.node_id,
            s.span,
        )),
        // Redshift datashare — the dedicated DatasharePlan path in lib.rs
        // intercepts these before the generic DdlPlan path. These arms keep
        // lower_ddl_stmt exhaustive and provide a sane fallback for any other
        // consumer of lower_ddl_stmt (no typed datashare facts on this path).
        AstStmt::CreateDatashare(s) => Some(plan(
            DdlAction::Create,
            ObjectKind::Datashare,
            target_from(s.name_span, source),
            DdlOptions {
                or_replace: s.or_replace_span.is_some(),
                if_not_exists: s.if_not_exists_span.is_some(),
                ..DdlOptions::default()
            },
            s.node_id,
            s.span,
        )),
        AstStmt::AlterDatashare(s) => Some(simple(
            DdlAction::Alter,
            ObjectKind::Datashare,
            target_from(s.name_span, source),
            s.node_id,
            s.span,
        )),
        AstStmt::CreateSecurityIntegration(s) => Some(plan(
            DdlAction::Create,
            ObjectKind::SecurityIntegration,
            target_from(s.name_span, source),
            DdlOptions {
                or_replace: s.or_replace_span.is_some(),
                ..DdlOptions::default()
            },
            s.node_id,
            s.span,
        )),
        AstStmt::AlterSecurityIntegration(s) => Some(simple(
            DdlAction::Alter,
            ObjectKind::SecurityIntegration,
            target_from(s.name_span, source),
            s.node_id,
            s.span,
        )),
        AstStmt::AlterReplicationGroup(s) => Some(simple(
            DdlAction::Alter,
            ObjectKind::ReplicationGroup,
            target_from(s.name_span, source),
            s.node_id,
            s.span,
        )),
        AstStmt::AlterFailoverGroup(s) => Some(simple(
            DdlAction::Alter,
            ObjectKind::FailoverGroup,
            target_from(s.name_span, source),
            s.node_id,
            s.span,
        )),
        AstStmt::AlterExternalAccessIntegration(s) => Some(simple(
            DdlAction::Alter,
            ObjectKind::ExternalAccessIntegration,
            target_from(s.name_span, source),
            s.node_id,
            s.span,
        )),
        AstStmt::AlterTable(s) => Some(DdlPlan {
            action: DdlAction::Alter,
            object_kind: ObjectKind::Table,
            target: target_from(s.name_span, source),
            body: Vec::new(),
            options: DdlOptions::default(),
            node_id: s.node_id,
            span: s.span,
            schema_mutations: collect_alter_table_schema_mutations(s, source),
            mssql_set_option: None,
            mssql_principal_source: None,
            principal_options: None,
            domain: None,
            pg_index: None,
            pg_trigger: None,
            pg_trigger_state: None,
            pg_session: None,
            bq_assert: None,
            bq_create_model: None,
            bq_export_data: None,
            bq_options: None,
            show: None,
            synonym: None,
        }),
        // MySQL RENAME TABLE a TO b [, c TO d]: one plan, one RenameTo
        // mutation per pair. Each mutation carries its own pair source so
        // multi-pair renames don't attribute pairs 2+ to the plan target.
        AstStmt::MysqlRenameTable(s) => Some(DdlPlan {
            action: DdlAction::Rename,
            object_kind: ObjectKind::Table,
            target: s
                .pairs
                .first()
                .and_then(|p| target_from(p.from_name_span, source)),
            body: Vec::new(),
            options: DdlOptions::default(),
            node_id: s.node_id,
            span: s.span,
            schema_mutations: s
                .pairs
                .iter()
                .filter_map(|p| {
                    Some(DdlSchemaMutation::RenameTo {
                        new_target: target_from(p.to_name_span, source)?,
                        source: target_from(p.from_name_span, source),
                    })
                })
                .collect(),
            mssql_set_option: None,
            mssql_principal_source: None,
            principal_options: None,
            domain: None,
            pg_index: None,
            pg_trigger: None,
            pg_trigger_state: None,
            pg_session: None,
            bq_assert: None,
            bq_create_model: None,
            bq_export_data: None,
            bq_options: None,
            show: None,
            synonym: None,
        }),
        AstStmt::AlterView(s) => Some(simple(
            DdlAction::Alter,
            ObjectKind::View,
            target_from(s.name_span, source),
            s.node_id,
            s.span,
        )),
        AstStmt::AlterMaterializedView(s) => Some(simple(
            DdlAction::Alter,
            ObjectKind::MaterializedView,
            target_from(s.name_span, source),
            s.node_id,
            s.span,
        )),
        AstStmt::AlterDynamicTable(s) => Some(simple(
            DdlAction::Alter,
            ObjectKind::DynamicTable,
            target_from(s.name_span, source),
            s.node_id,
            s.span,
        )),
        AstStmt::AlterFunction(s) => Some(simple(
            DdlAction::Alter,
            ObjectKind::Function,
            target_from(s.name_span, source),
            s.node_id,
            s.span,
        )),
        AstStmt::AlterProcedure(s) => Some(simple(
            DdlAction::Alter,
            ObjectKind::Procedure,
            target_from(s.name_span, source),
            s.node_id,
            s.span,
        )),
        AstStmt::AlterStage(s) => Some(simple(
            DdlAction::Alter,
            ObjectKind::Stage,
            target_from(s.name_span, source),
            s.node_id,
            s.span,
        )),
        AstStmt::AlterTask(s) => Some(simple(
            DdlAction::Alter,
            ObjectKind::Task,
            target_from(s.name_span, source),
            s.node_id,
            s.span,
        )),
        AstStmt::AlterWarehouse(s) => Some(simple(
            DdlAction::Alter,
            ObjectKind::Warehouse,
            target_from(s.name_span, source),
            s.node_id,
            s.span,
        )),
        AstStmt::AlterPipe(s) => Some(simple(
            DdlAction::Alter,
            ObjectKind::Pipe,
            target_from(s.name_span, source),
            s.node_id,
            s.span,
        )),
        AstStmt::AlterStream(s) => Some(simple(
            DdlAction::Alter,
            ObjectKind::Stream,
            target_from(s.name_span, source),
            s.node_id,
            s.span,
        )),
        AstStmt::AlterDatabase(s) => Some(simple(
            DdlAction::Alter,
            ObjectKind::Database,
            target_from(s.name_span, source),
            s.node_id,
            s.span,
        )),
        AstStmt::AlterSchema(s) => Some(simple(
            DdlAction::Alter,
            ObjectKind::Schema,
            target_from(s.name_span, source),
            s.node_id,
            s.span,
        )),

        // ---- DROP — Snowflake/core ----
        AstStmt::Drop(s) => {
            // `cascade_restrict_span` covers a single keyword; classify
            // it by reading the source slice. Mirrors the DropPgTrigger
            // arm below and the per-family lowerings in
            // `table_plan.rs` / `dynamic_table_plan.rs`.
            let cascade = matches!(
                s.cascade_restrict_span,
                Some(span) if drop_keyword_matches(source, span, "CASCADE")
            );
            let restrict = matches!(
                s.cascade_restrict_span,
                Some(span) if drop_keyword_matches(source, span, "RESTRICT")
            );
            Some(plan(
                DdlAction::Drop,
                // Discriminate object kind from `object_type_span` so the
                // IR `ObjectKind` is structurally accurate. Falls back
                // to `Table` when the span is absent (recovery-path
                // parse).
                classify_drop_object(s, source),
                optional_target_from(s.target_name_span, source),
                DdlOptions {
                    if_exists: s.if_exists_span.is_some(),
                    cascade,
                    restrict,
                    ..DdlOptions::default()
                },
                s.node_id,
                s.span,
            ))
        }
        AstStmt::DropRowAccessPolicy(s) => Some(simple(
            DdlAction::Drop,
            ObjectKind::RowAccessPolicy,
            target_from(s.policy_name_span, source),
            s.node_id,
            s.span,
        )),
        AstStmt::DropAllRowAccessPolicies(s) => Some(simple(
            DdlAction::Drop,
            ObjectKind::RowAccessPolicy,
            target_from(s.table_name_span, source),
            s.node_id,
            s.span,
        )),
        AstStmt::DropMaskingPolicy(s) => Some(simple(
            DdlAction::Drop,
            ObjectKind::MaskingPolicy,
            target_from(s.policy_name_span, source),
            s.node_id,
            s.span,
        )),
        AstStmt::DropNetworkPolicy(s) => Some(simple(
            DdlAction::Drop,
            ObjectKind::NetworkPolicy,
            target_from(s.policy_name_span, source),
            s.node_id,
            s.span,
        )),
        AstStmt::DropSessionPolicy(s) => Some(simple(
            DdlAction::Drop,
            ObjectKind::SessionPolicy,
            target_from(s.policy_name_span, source),
            s.node_id,
            s.span,
        )),
        AstStmt::DropAuthenticationPolicy(s) => Some(simple(
            DdlAction::Drop,
            ObjectKind::AuthenticationPolicy,
            target_from(s.policy_name_span, source),
            s.node_id,
            s.span,
        )),
        AstStmt::DropApiIntegration(s) => Some(simple(
            DdlAction::Drop,
            ObjectKind::ApiIntegration,
            target_from(s.integration_name_span, source),
            s.node_id,
            s.span,
        )),
        AstStmt::DropNotificationIntegration(s) => Some(simple(
            DdlAction::Drop,
            ObjectKind::NotificationIntegration,
            target_from(s.integration_name_span, source),
            s.node_id,
            s.span,
        )),
        AstStmt::DropPasswordPolicy(s) => Some(simple(
            DdlAction::Drop,
            ObjectKind::PasswordPolicy,
            target_from(s.policy_name_span, source),
            s.node_id,
            s.span,
        )),
        AstStmt::DropAggregationPolicy(s) => Some(simple(
            DdlAction::Drop,
            ObjectKind::AggregationPolicy,
            target_from(s.policy_name_span, source),
            s.node_id,
            s.span,
        )),
        AstStmt::DropProjectionPolicy(s) => Some(simple(
            DdlAction::Drop,
            ObjectKind::ProjectionPolicy,
            target_from(s.policy_name_span, source),
            s.node_id,
            s.span,
        )),
        AstStmt::DropJoinPolicy(s) => Some(simple(
            DdlAction::Drop,
            ObjectKind::JoinPolicy,
            target_from(s.policy_name_span, source),
            s.node_id,
            s.span,
        )),
        AstStmt::DropStorageIntegration(s) => Some(simple(
            DdlAction::Drop,
            ObjectKind::StorageIntegration,
            target_from(s.integration_name_span, source),
            s.node_id,
            s.span,
        )),
        AstStmt::DropExternalAccessIntegration(s) => Some(simple(
            DdlAction::Drop,
            ObjectKind::ExternalAccessIntegration,
            target_from(s.integration_name_span, source),
            s.node_id,
            s.span,
        )),
        AstStmt::DropTask(s) => Some(simple(
            DdlAction::Drop,
            ObjectKind::Task,
            target_from(s.name_span, source),
            s.node_id,
            s.span,
        )),
        AstStmt::DropWarehouse(s) => Some(simple(
            DdlAction::Drop,
            ObjectKind::Warehouse,
            target_from(s.name_span, source),
            s.node_id,
            s.span,
        )),
        AstStmt::DropPipe(s) => Some(simple(
            DdlAction::Drop,
            ObjectKind::Pipe,
            target_from(s.name_span, source),
            s.node_id,
            s.span,
        )),
        AstStmt::DropStream(s) => Some(simple(
            DdlAction::Drop,
            ObjectKind::Stream,
            target_from(s.name_span, source),
            s.node_id,
            s.span,
        )),
        AstStmt::DropDatabase(s) => Some(simple(
            DdlAction::Drop,
            ObjectKind::Database,
            target_from(s.name_span, source),
            s.node_id,
            s.span,
        )),
        AstStmt::DropSchema(s) => Some(simple(
            DdlAction::Drop,
            ObjectKind::Schema,
            target_from(s.name_span, source),
            s.node_id,
            s.span,
        )),

        // ---- UNDROP — restore-after-drop, modeled as Create. ----
        AstStmt::UndropDatabase(s) => Some(simple(
            DdlAction::Create,
            ObjectKind::Database,
            target_from(s.name_span, source),
            s.node_id,
            s.span,
        )),
        AstStmt::UndropSchema(s) => Some(simple(
            DdlAction::Create,
            ObjectKind::Schema,
            target_from(s.name_span, source),
            s.node_id,
            s.span,
        )),
        AstStmt::UndropTable(s) => Some(simple(
            DdlAction::Create,
            ObjectKind::Table,
            target_from(s.name_span, source),
            s.node_id,
            s.span,
        )),
        AstStmt::UndropType(s) => Some(simple(
            DdlAction::Create,
            ObjectKind::PgType,
            target_from(s.name_span, source),
            s.node_id,
            s.span,
        )),

        // ---- TAG (Snowflake object tagging) ----
        AstStmt::CreateTag(s) => Some(simple(
            DdlAction::Create,
            ObjectKind::Tag,
            target_from(s.name_span, source),
            s.node_id,
            s.span,
        )),
        AstStmt::AlterTag(s) => Some(simple(
            DdlAction::Alter,
            ObjectKind::Tag,
            target_from(s.name_span, source),
            s.node_id,
            s.span,
        )),
        AstStmt::CreateFileFormat(s) => Some(simple(
            DdlAction::Create,
            ObjectKind::FileFormat,
            target_from(s.name_span, source),
            s.node_id,
            s.span,
        )),
        AstStmt::AlterFileFormat(s) => Some(simple(
            DdlAction::Alter,
            ObjectKind::FileFormat,
            target_from(s.name_span, source),
            s.node_id,
            s.span,
        )),
        AstStmt::UndropTag(s) => Some(simple(
            DdlAction::Create,
            ObjectKind::Tag,
            target_from(s.name_span, source),
            s.node_id,
            s.span,
        )),

        // ---- SECRET (Snowflake credential objects) ----
        AstStmt::CreateSecret(s) => Some(simple(
            DdlAction::Create,
            ObjectKind::Secret,
            target_from(s.name_span, source),
            s.node_id,
            s.span,
        )),
        AstStmt::AlterSecret(s) => Some(simple(
            DdlAction::Alter,
            ObjectKind::Secret,
            target_from(s.name_span, source),
            s.node_id,
            s.span,
        )),

        // ---- NETWORK RULE (Snowflake network egress/ingress primitives) ----
        AstStmt::CreateNetworkRule(s) => Some(simple(
            DdlAction::Create,
            ObjectKind::NetworkRule,
            target_from(s.name_span, source),
            s.node_id,
            s.span,
        )),
        AstStmt::AlterNetworkRule(s) => Some(simple(
            DdlAction::Alter,
            ObjectKind::NetworkRule,
            target_from(s.name_span, source),
            s.node_id,
            s.span,
        )),

        // ---- RESOURCE MONITOR (Snowflake compute cost-governance) ----
        AstStmt::CreateResourceMonitor(s) => Some(simple(
            DdlAction::Create,
            ObjectKind::ResourceMonitor,
            target_from(s.name_span, source),
            s.node_id,
            s.span,
        )),
        AstStmt::AlterResourceMonitor(s) => Some(simple(
            DdlAction::Alter,
            ObjectKind::ResourceMonitor,
            target_from(s.name_span, source),
            s.node_id,
            s.span,
        )),

        // ---- COMPUTE POOL (Snowpark Container Services capacity) ----
        AstStmt::CreateComputePool(s) => Some(simple(
            DdlAction::Create,
            ObjectKind::Generic,
            target_from(s.name_span, source),
            s.node_id,
            s.span,
        )),
        AstStmt::AlterComputePool(s) => Some(simple(
            DdlAction::Alter,
            ObjectKind::Generic,
            target_from(s.name_span, source),
            s.node_id,
            s.span,
        )),

        // ---- GIT REPOSITORY (Snowflake external code source) ----
        AstStmt::CreateGitRepository(s) => Some(simple(
            DdlAction::Create,
            ObjectKind::Generic,
            target_from(s.name_span, source),
            s.node_id,
            s.span,
        )),
        AstStmt::AlterGitRepository(s) => Some(simple(
            DdlAction::Alter,
            ObjectKind::Generic,
            target_from(s.name_span, source),
            s.node_id,
            s.span,
        )),

        // ---- EXTERNAL FUNCTION (Snowflake — HTTPS-egress UDF) ----
        // Top-level recognition is intercepted at the statement dispatch; this
        // fallback covers the statement when reached through body lowering.
        AstStmt::CreateExternalFunction(s) => Some(simple(
            DdlAction::Create,
            ObjectKind::Function,
            target_from(s.name_span, source),
            s.node_id,
            s.span,
        )),

        // ---- IMAGE REPOSITORY (Snowflake SPCS container-image registry) ----
        AstStmt::CreateImageRepository(s) => Some(simple(
            DdlAction::Create,
            ObjectKind::Generic,
            target_from(s.name_span, source),
            s.node_id,
            s.span,
        )),
        AstStmt::AlterImageRepository(s) => Some(simple(
            DdlAction::Alter,
            ObjectKind::Generic,
            target_from(s.name_span, source),
            s.node_id,
            s.span,
        )),

        // ---- STREAMLIT (Snowflake Python-app object) ----
        AstStmt::CreateStreamlit(s) => Some(simple(
            DdlAction::Create,
            ObjectKind::Generic,
            target_from(s.name_span, source),
            s.node_id,
            s.span,
        )),
        AstStmt::AlterStreamlit(s) => Some(simple(
            DdlAction::Alter,
            ObjectKind::Generic,
            target_from(s.name_span, source),
            s.node_id,
            s.span,
        )),

        // ---- SERVICE (Snowflake SPCS container service) ----
        AstStmt::CreateService(s) => Some(simple(
            DdlAction::Create,
            ObjectKind::Generic,
            target_from(s.name_span, source),
            s.node_id,
            s.span,
        )),
        AstStmt::AlterService(s) => Some(simple(
            DdlAction::Alter,
            ObjectKind::Generic,
            target_from(s.name_span, source),
            s.node_id,
            s.span,
        )),

        // ---- NOTEBOOK (Snowflake code-from-stage object) ----
        AstStmt::CreateNotebook(s) => Some(simple(
            DdlAction::Create,
            ObjectKind::Generic,
            target_from(s.name_span, source),
            s.node_id,
            s.span,
        )),
        AstStmt::AlterNotebook(s) => Some(simple(
            DdlAction::Alter,
            ObjectKind::Generic,
            target_from(s.name_span, source),
            s.node_id,
            s.span,
        )),

        // ---- SEMANTIC VIEW (Snowflake model over base tables) ----
        AstStmt::CreateSemanticView(s) => Some(simple(
            DdlAction::Create,
            ObjectKind::Generic,
            target_from(s.name_span, source),
            s.node_id,
            s.span,
        )),
        AstStmt::AlterSemanticView(s) => Some(simple(
            DdlAction::Alter,
            ObjectKind::Generic,
            target_from(s.name_span, source),
            s.node_id,
            s.span,
        )),

        // ---- CORTEX SEARCH SERVICE (Snowflake AI search index) ----
        AstStmt::CreateCortexSearchService(s) => Some(simple(
            DdlAction::Create,
            ObjectKind::Generic,
            target_from(s.name_span, source),
            s.node_id,
            s.span,
        )),
        AstStmt::AlterCortexSearchService(s) => Some(simple(
            DdlAction::Alter,
            ObjectKind::Generic,
            target_from(s.name_span, source),
            s.node_id,
            s.span,
        )),

        // ---- Native Apps: APPLICATION + APPLICATION PACKAGE ----
        AstStmt::CreateApplication(s) => Some(simple(
            DdlAction::Create,
            ObjectKind::Generic,
            target_from(s.name_span, source),
            s.node_id,
            s.span,
        )),
        AstStmt::AlterApplication(s) => Some(simple(
            DdlAction::Alter,
            ObjectKind::Generic,
            target_from(s.name_span, source),
            s.node_id,
            s.span,
        )),
        AstStmt::CreateApplicationPackage(s) => Some(simple(
            DdlAction::Create,
            ObjectKind::Generic,
            target_from(s.name_span, source),
            s.node_id,
            s.span,
        )),
        AstStmt::AlterApplicationPackage(s) => Some(simple(
            DdlAction::Alter,
            ObjectKind::Generic,
            target_from(s.name_span, source),
            s.node_id,
            s.span,
        )),

        // ---- LISTING (Snowflake Marketplace exposure) ----
        AstStmt::CreateListing(s) => Some(simple(
            DdlAction::Create,
            ObjectKind::Generic,
            target_from(s.name_span, source),
            s.node_id,
            s.span,
        )),
        AstStmt::AlterListing(s) => Some(simple(
            DdlAction::Alter,
            ObjectKind::Generic,
            target_from(s.name_span, source),
            s.node_id,
            s.span,
        )),

        // ---- Account provisioning (MANAGED ACCOUNT / ACCOUNT) ----
        AstStmt::CreateManagedAccount(s) => Some(simple(
            DdlAction::Create,
            ObjectKind::Generic,
            target_from(s.name_span, source),
            s.node_id,
            s.span,
        )),
        AstStmt::CreateAccount(s) => Some(simple(
            DdlAction::Create,
            ObjectKind::Account,
            target_from(s.name_span, source),
            s.node_id,
            s.span,
        )),

        // ---- Client file commands: PUT / GET / REMOVE / LIST ----
        AstStmt::StageFileCommand(s) => Some(simple(
            DdlAction::Configure,
            ObjectKind::Generic,
            optional_target_from(s.stage_ref_span, source),
            s.node_id,
            s.span,
        )),

        // ---- DATA METRIC FUNCTION (Snowflake data-quality metric) ----
        AstStmt::CreateDataMetricFunction(s) => Some(simple(
            DdlAction::Create,
            ObjectKind::DataMetricFunction,
            target_from(s.name_span, source),
            s.node_id,
            s.span,
        )),

        // ---- REPLICATION / FAILOVER GROUP (Snowflake cross-account DR) ----
        AstStmt::CreateReplicationFailoverGroup(s) => Some(simple(
            DdlAction::Create,
            ObjectKind::ReplicationGroup,
            target_from(s.name_span, source),
            s.node_id,
            s.span,
        )),

        // ---- ALERT (Snowflake scheduled SQL condition+action) ----
        AstStmt::CreateAlert(s) => Some(simple(
            DdlAction::Create,
            ObjectKind::Alert,
            target_from(s.name_span, source),
            s.node_id,
            s.span,
        )),
        AstStmt::AlterAlert(s) => Some(simple(
            DdlAction::Alter,
            ObjectKind::Alert,
            target_from(s.name_span, source),
            s.node_id,
            s.span,
        )),

        // ---- TRUNCATE / SHOW / DESCRIBE / USE ----
        AstStmt::Truncate(s) => Some(simple(
            DdlAction::Truncate,
            ObjectKind::Table,
            optional_target_from(s.target_table_span, source),
            s.node_id,
            s.span,
        )),
        AstStmt::Show(s) => {
            let mut plan = simple(
                DdlAction::Configure,
                ObjectKind::Generic,
                None,
                s.node_id,
                s.span,
            );
            plan.show = Some(lower_show(s));
            Some(plan)
        }
        AstStmt::Describe(s) => Some(simple(
            DdlAction::Configure,
            ObjectKind::Generic,
            None,
            s.node_id,
            s.span,
        )),
        AstStmt::Use(s) => Some(simple(
            DdlAction::Configure,
            // Object kind tracks `kind` field; readers can refine.
            ObjectKind::Database,
            target_from(s.object_span, source),
            s.node_id,
            s.span,
        )),

        // ---- PostgreSQL ----
        AstStmt::CreateIndex(s) => Some(simple(
            DdlAction::Create,
            ObjectKind::Index,
            optional_target_from(s.index_name, source),
            s.node_id,
            s.span,
        )),
        AstStmt::CreateSynonym(s) => {
            let mut plan = simple(
                DdlAction::Create,
                ObjectKind::Synonym,
                target_from(s.name_span, source),
                s.node_id,
                s.span,
            );
            plan.synonym = Some(crate::ir::lower_create_synonym_to_plan(s, source));
            Some(plan)
        }
        AstStmt::CommentOn(s) => Some(simple(
            DdlAction::Comment,
            ObjectKind::Generic,
            target_from(s.object_name, source),
            s.node_id,
            s.span,
        )),
        AstStmt::DoBlock(s) => {
            // Decompose the anonymous block: lower its sub-parsed `BEGIN … END`
            // body so the inner statements analyze (parity with proc/func
            // bodies). Opaque/non-block bodies have `body_stmt = None` → leaf.
            let mut plan = simple(
                DdlAction::ControlFlow,
                ObjectKind::Generic,
                None,
                s.node_id,
                s.span,
            );
            plan.body = s
                .body_stmt
                .as_deref()
                .map(|inner| lower_body(std::slice::from_ref(inner), inputs))
                .unwrap_or_default();
            Some(plan)
        }
        AstStmt::Vacuum(s) => Some(simple(
            DdlAction::Configure,
            ObjectKind::Generic,
            optional_target_from(s.table_name, source),
            s.node_id,
            s.span,
        )),
        AstStmt::AnalyzeStmt(s) => Some(simple(
            DdlAction::Configure,
            ObjectKind::Generic,
            optional_target_from(s.table_name, source),
            s.node_id,
            s.span,
        )),
        AstStmt::CreateType(s) => Some(simple(
            DdlAction::Create,
            ObjectKind::PgType,
            target_from(s.type_name, source),
            s.node_id,
            s.span,
        )),
        AstStmt::AlterType(s) => Some(simple(
            DdlAction::Alter,
            ObjectKind::PgType,
            target_from(s.type_name, source),
            s.node_id,
            s.span,
        )),
        AstStmt::CreateExtension(s) => Some(plan(
            DdlAction::Create,
            ObjectKind::PgExtension,
            target_from(s.extension_name, source),
            DdlOptions {
                if_not_exists: s.if_not_exists,
                cascade: s.cascade,
                ..DdlOptions::default()
            },
            s.node_id,
            s.span,
        )),
        AstStmt::CreateSequence(s) => Some(plan(
            DdlAction::Create,
            ObjectKind::Sequence,
            target_from(s.name, source),
            DdlOptions {
                if_not_exists: s.if_not_exists,
                temporary: s.temporary,
                or_replace: s.or_replace,
                ..DdlOptions::default()
            },
            s.node_id,
            s.span,
        )),
        AstStmt::AlterSequence(s) => Some(plan(
            DdlAction::Alter,
            ObjectKind::Sequence,
            target_from(s.name, source),
            DdlOptions {
                if_exists: s.if_exists,
                ..DdlOptions::default()
            },
            s.node_id,
            s.span,
        )),
        AstStmt::CreatePgTrigger(s) => Some(plan(
            DdlAction::Create,
            ObjectKind::Trigger,
            target_from(s.trigger_name, source),
            DdlOptions {
                or_replace: s.or_replace,
                ..DdlOptions::default()
            },
            s.node_id,
            s.span,
        )),
        AstStmt::AlterPgTrigger(s) => {
            let mut p = simple(
                DdlAction::Alter,
                ObjectKind::Trigger,
                target_from(s.trigger_name, source),
                s.node_id,
                s.span,
            );
            p.pg_trigger = Some(crate::ir::ddl_plan::IrTriggerDetail {
                action: project_ast_alter_trigger_action(&s.action),
            });
            Some(p)
        }
        AstStmt::DropPgTrigger(s) => {
            let (cascade, restrict) = match s.cascade_restrict {
                Some(crate::ast::PgCascadeRestrict::Cascade) => (true, false),
                Some(crate::ast::PgCascadeRestrict::Restrict) => (false, true),
                None => (false, false),
            };
            Some(plan(
                DdlAction::Drop,
                ObjectKind::Trigger,
                target_from(s.trigger_name, source),
                DdlOptions {
                    if_exists: s.if_exists,
                    cascade,
                    restrict,
                    ..DdlOptions::default()
                },
                s.node_id,
                s.span,
            ))
        }
        AstStmt::CreateDomain(s) => Some(simple(
            DdlAction::Create,
            ObjectKind::PgDomain,
            target_from(s.domain_name, source),
            s.node_id,
            s.span,
        )),
        AstStmt::AlterDomain(s) => {
            let mut p = simple(
                DdlAction::Alter,
                ObjectKind::PgDomain,
                target_from(s.domain_name, source),
                s.node_id,
                s.span,
            );
            p.domain = Some(crate::ir::ddl_plan::IrDomainDetail {
                actions: vec![project_ast_alter_domain_action(&s.action)],
            });
            Some(p)
        }
        AstStmt::DropDomain(s) => {
            let (cascade, restrict) = match s.cascade_restrict {
                Some(crate::ast::PgCascadeRestrict::Cascade) => (true, false),
                Some(crate::ast::PgCascadeRestrict::Restrict) => (false, true),
                None => (false, false),
            };
            Some(plan(
                DdlAction::Drop,
                ObjectKind::PgDomain,
                // DropDomain carries a Vec of names — pick the first
                // for the canonical target; full list lives on the AST.
                s.domain_names
                    .first()
                    .copied()
                    .and_then(|sp| target_from(sp, source)),
                DdlOptions {
                    if_exists: s.if_exists,
                    cascade,
                    restrict,
                    ..DdlOptions::default()
                },
                s.node_id,
                s.span,
            ))
        }
        AstStmt::CreatePgPolicy(s) => Some(simple(
            DdlAction::Create,
            ObjectKind::RowAccessPolicy,
            target_from(s.policy_name, source),
            s.node_id,
            s.span,
        )),
        AstStmt::AlterPgPolicy(s) => Some(simple(
            DdlAction::Alter,
            ObjectKind::RowAccessPolicy,
            target_from(s.policy_name, source),
            s.node_id,
            s.span,
        )),
        AstStmt::DropPgPolicy(s) => Some(plan(
            DdlAction::Drop,
            ObjectKind::RowAccessPolicy,
            target_from(s.policy_name, source),
            DdlOptions {
                if_exists: s.if_exists,
                ..DdlOptions::default()
            },
            s.node_id,
            s.span,
        )),
        AstStmt::AlterIndex(s) => {
            let mut p = simple(DdlAction::Alter, ObjectKind::Index, None, s.node_id, s.span);
            p.pg_index = Some(crate::ir::ddl_plan::IrIndexDetail {
                action: project_ast_alter_index_action(&s.action),
            });
            Some(p)
        }
        AstStmt::Reindex(s) => Some(simple(
            DdlAction::Configure,
            ObjectKind::Index,
            optional_target_from(s.name, source),
            s.node_id,
            s.span,
        )),
        AstStmt::PgDropIndex(s) => {
            let (cascade, restrict) = match s.cascade_restrict {
                Some(crate::ast::PgCascadeRestrict::Cascade) => (true, false),
                Some(crate::ast::PgCascadeRestrict::Restrict) => (false, true),
                None => (false, false),
            };
            Some(plan(
                DdlAction::Drop,
                ObjectKind::Index,
                s.index_names
                    .first()
                    .copied()
                    .and_then(|sp| target_from(sp, source)),
                DdlOptions {
                    if_exists: s.if_exists,
                    cascade,
                    restrict,
                    ..DdlOptions::default()
                },
                s.node_id,
                s.span,
            ))
        }
        AstStmt::PgDropExtension(s) => {
            let (cascade, restrict) = match s.cascade_restrict {
                Some(crate::ast::PgCascadeRestrict::Cascade) => (true, false),
                Some(crate::ast::PgCascadeRestrict::Restrict) => (false, true),
                None => (false, false),
            };
            Some(plan(
                DdlAction::Drop,
                ObjectKind::PgExtension,
                s.extension_names
                    .first()
                    .copied()
                    .and_then(|sp| target_from(sp, source)),
                DdlOptions {
                    if_exists: s.if_exists,
                    cascade,
                    restrict,
                    ..DdlOptions::default()
                },
                s.node_id,
                s.span,
            ))
        }
        AstStmt::PgPrepare(s) => Some(simple(
            DdlAction::Execute,
            ObjectKind::Procedure,
            target_from(s.name, source),
            s.node_id,
            s.span,
        )),
        AstStmt::PgExecute(s) => Some(simple(
            DdlAction::Execute,
            ObjectKind::Procedure,
            target_from(s.name, source),
            s.node_id,
            s.span,
        )),
        AstStmt::PgDeallocate(s) => Some(simple(
            DdlAction::Drop,
            ObjectKind::Procedure,
            None,
            s.node_id,
            s.span,
        )),
        AstStmt::PgCopy(s) => {
            // Surface the table-subject form's identifier as the DDL
            // target so downstream consumers see the table that COPY
            // FROM loads into / COPY TO exports from. Query-subject
            // form lowers via the Rel path in `lower_dispatch`.
            let target = match &s.subject {
                crate::ast::PgCopySubject::Table(name_span) => target_from(*name_span, source),
                crate::ast::PgCopySubject::Query(..) => None,
            };
            Some(simple(
                DdlAction::BulkLoad,
                ObjectKind::Generic,
                target,
                s.node_id,
                s.span,
            ))
        }
        AstStmt::MssqlBackup(s) => Some(simple(
            DdlAction::Backup,
            ObjectKind::Database,
            target_from(s.name_span, source),
            s.node_id,
            s.span,
        )),
        AstStmt::MssqlRestore(s) => Some(simple(
            DdlAction::Restore,
            ObjectKind::Database,
            target_from(s.name_span, source),
            s.node_id,
            s.span,
        )),
        // DBCC is a maintenance/admin utility, not a DDL/object lifecycle
        // change — no DdlPlan. Facts are surfaced via the dedicated dispatch.
        AstStmt::MssqlDbcc(_) => None,
        // OPEN/CLOSE KEY is a session-scoped key-context switch, not DDL —
        // facts surface via the dedicated dispatch.
        AstStmt::MssqlKeyManagement(_) => None,
        // CREATE/ALTER SECURITY POLICY surfaces via the dedicated dispatch.
        AstStmt::MssqlSecurityPolicy(_) => None,
        // BACKUP/RESTORE key material surfaces via the dedicated dispatch.
        AstStmt::MssqlKeyBackup(_) => None,
        // CLR assembly registration surfaces via the dedicated dispatch.
        AstStmt::MssqlAssembly(_) => None,
        // Module signing surfaces via the dedicated dispatch.
        AstStmt::MssqlAddSignature(_) => None,
        // SETUSER impersonation surfaces via the dedicated dispatch.
        AstStmt::MssqlSetuser(_) => None,
        // SMK rotation surfaces via the dedicated dispatch.
        AstStmt::MssqlAlterServiceMasterKey(_) => None,
        // PG default-privileges policy surfaces via the dedicated dispatch.
        AstStmt::PgAlterDefaultPrivileges(_) => None,
        AstStmt::PgRefreshMatview(s) => Some(simple(
            DdlAction::Refresh,
            ObjectKind::MaterializedView,
            target_from(s.name_span, source),
            s.node_id,
            s.span,
        )),
        AstStmt::PgListen(s) => Some(simple(
            DdlAction::Configure,
            ObjectKind::Generic,
            None,
            s.node_id,
            s.span,
        )),
        AstStmt::PgNotify(s) => Some(simple(
            DdlAction::Configure,
            ObjectKind::Generic,
            None,
            s.node_id,
            s.span,
        )),
        AstStmt::PgUnlisten(s) => Some(simple(
            DdlAction::Configure,
            ObjectKind::Generic,
            None,
            s.node_id,
            s.span,
        )),
        AstStmt::PgLockTable(s) => Some(simple(
            DdlAction::Configure,
            ObjectKind::Generic,
            None,
            s.node_id,
            s.span,
        )),
        AstStmt::PgCreateRule(s) => Some(simple(
            DdlAction::Create,
            ObjectKind::PgRule,
            None,
            s.node_id,
            s.span,
        )),
        AstStmt::PgCreateAggregate(s) => Some(simple(
            DdlAction::Create,
            ObjectKind::Generic,
            None,
            s.node_id,
            s.span,
        )),
        AstStmt::PgCreateOperator(s) => Some(simple(
            DdlAction::Create,
            ObjectKind::Generic,
            None,
            s.node_id,
            s.span,
        )),
        AstStmt::PgAlterSystem(s) => Some(simple(
            DdlAction::Alter,
            ObjectKind::Generic,
            None,
            s.node_id,
            s.span,
        )),
        AstStmt::PgAlterTablespace(s) => Some(simple(
            DdlAction::Alter,
            ObjectKind::Generic,
            None,
            s.node_id,
            s.span,
        )),
        AstStmt::PgDropOwned(s) => Some(simple(
            DdlAction::Drop,
            ObjectKind::Generic,
            None,
            s.node_id,
            s.span,
        )),
        AstStmt::PgReassignOwned(s) => Some(simple(
            DdlAction::Alter,
            ObjectKind::Generic,
            None,
            s.node_id,
            s.span,
        )),
        AstStmt::PgDiscard(s) => Some(simple(
            DdlAction::Configure,
            ObjectKind::Generic,
            None,
            s.node_id,
            s.span,
        )),
        AstStmt::PgCluster(s) => Some(simple(
            DdlAction::Configure,
            ObjectKind::Generic,
            None,
            s.node_id,
            s.span,
        )),
        AstStmt::PgPublication(s) => Some(simple(
            DdlAction::Configure,
            ObjectKind::PgPublication,
            None,
            s.node_id,
            s.span,
        )),
        AstStmt::PgSubscription(s) => Some(simple(
            DdlAction::Configure,
            ObjectKind::PgSubscription,
            None,
            s.node_id,
            s.span,
        )),
        AstStmt::CreatePrincipal(s) => Some(lower_create_principal(s, source)),
        AstStmt::AlterPrincipal(s) => Some(lower_alter_principal(s, source)),
        AstStmt::DropPrincipal(s) => Some(lower_drop_principal(s, source)),
        AstStmt::PgAlterRule(s) => Some(simple(
            DdlAction::Alter,
            ObjectKind::PgRule,
            None,
            s.node_id,
            s.span,
        )),
        AstStmt::PgDropRule(s) => {
            let (cascade, restrict) = match s.cascade_restrict {
                Some(crate::ast::PgCascadeRestrict::Cascade) => (true, false),
                Some(crate::ast::PgCascadeRestrict::Restrict) => (false, true),
                None => (false, false),
            };
            Some(plan(
                DdlAction::Drop,
                ObjectKind::PgRule,
                target_from(s.rule_name, source),
                DdlOptions {
                    if_exists: s.if_exists,
                    cascade,
                    restrict,
                    ..DdlOptions::default()
                },
                s.node_id,
                s.span,
            ))
        }
        AstStmt::PgAlterTableTriggerState(s) => {
            let mut p = simple(
                DdlAction::Alter,
                ObjectKind::Trigger,
                target_from(s.table_name, source),
                s.node_id,
                s.span,
            );
            p.pg_trigger_state = Some(crate::ir::ddl_plan::IrTriggerStateDetail {
                action: project_ast_trigger_state_action(s.action),
            });
            Some(p)
        }
        AstStmt::PgSet(s) => {
            let mut p = simple(
                DdlAction::Configure,
                ObjectKind::Generic,
                None,
                s.node_id,
                s.span,
            );
            p.pg_session = Some(crate::ir::ddl_plan::IrPgSessionDetail {
                action: project_ast_pg_set_kind(s.kind),
            });
            Some(p)
        }
        AstStmt::PgDropSequence(s) => {
            let (cascade, restrict) = match s.cascade_restrict {
                Some(crate::ast::PgCascadeRestrict::Cascade) => (true, false),
                Some(crate::ast::PgCascadeRestrict::Restrict) => (false, true),
                None => (false, false),
            };
            Some(plan(
                DdlAction::Drop,
                ObjectKind::Sequence,
                s.sequence_names
                    .first()
                    .copied()
                    .and_then(|sp| target_from(sp, source)),
                DdlOptions {
                    if_exists: s.if_exists,
                    cascade,
                    restrict,
                    ..DdlOptions::default()
                },
                s.node_id,
                s.span,
            ))
        }
        AstStmt::PgDropType(s) => {
            let (cascade, restrict) = match s.cascade_restrict {
                Some(crate::ast::PgCascadeRestrict::Cascade) => (true, false),
                Some(crate::ast::PgCascadeRestrict::Restrict) => (false, true),
                None => (false, false),
            };
            Some(plan(
                DdlAction::Drop,
                ObjectKind::PgType,
                s.type_names
                    .first()
                    .copied()
                    .and_then(|sp| target_from(sp, source)),
                DdlOptions {
                    if_exists: s.if_exists,
                    cascade,
                    restrict,
                    ..DdlOptions::default()
                },
                s.node_id,
                s.span,
            ))
        }
        AstStmt::PgCreateTablespace(s) => Some(simple(
            DdlAction::Create,
            ObjectKind::Generic,
            None,
            s.node_id,
            s.span,
        )),
        AstStmt::PgDropTablespace(s) => Some(simple(
            DdlAction::Drop,
            ObjectKind::Generic,
            None,
            s.node_id,
            s.span,
        )),

        // ---- BigQuery ----
        AstStmt::BqExportData(s) => {
            let body = outermost_select_body(&s.query, source);
            let bq_options = Some(extract_bq_options_from_spans(&[s.options_span], source));
            Some(DdlPlan {
                action: DdlAction::BulkLoad,
                object_kind: ObjectKind::Stage,
                target: None,
                body: Vec::new(),
                options: DdlOptions::default(),
                node_id: s.node_id,
                span: s.span,
                schema_mutations: Vec::new(),
                mssql_set_option: None,
                mssql_principal_source: None,
                principal_options: None,
                domain: None,
                pg_index: None,
                pg_trigger: None,
                pg_trigger_state: None,
                pg_session: None,
                bq_assert: None,
                bq_create_model: None,
                bq_export_data: Some(crate::ir::ddl_plan::IrBqExportDataDetail { body }),
                bq_options,
                show: None,
                synonym: None,
            })
        }
        AstStmt::BqLoadData(s) => {
            let mut credential_spans: Vec<Span> = vec![s.from_files_span];
            if let Some(sp) = s.trailing_clauses_span {
                credential_spans.push(sp);
            }
            let bq_options = Some(extract_bq_options_from_spans(&credential_spans, source));
            Some(DdlPlan {
                action: DdlAction::BulkLoad,
                object_kind: ObjectKind::Generic,
                target: target_from(s.target_table_span, source),
                body: Vec::new(),
                options: DdlOptions::default(),
                node_id: s.node_id,
                span: s.span,
                schema_mutations: Vec::new(),
                mssql_set_option: None,
                mssql_principal_source: None,
                principal_options: None,
                domain: None,
                pg_index: None,
                pg_trigger: None,
                pg_trigger_state: None,
                pg_session: None,
                bq_assert: None,
                bq_create_model: None,
                bq_export_data: None,
                bq_options,
                show: None,
                synonym: None,
            })
        }
        AstStmt::MysqlLoadData(s) => Some(simple(
            DdlAction::BulkLoad,
            ObjectKind::Table,
            s.target_table_span.and_then(|sp| target_from(sp, source)),
            s.node_id,
            s.span,
        )),
        // MySQL scheduled event: lower the DO body so its inner statements
        // analyze (parity with proc / DO bodies). Unparseable bodies have
        // `body_stmt = None` → leaf.
        AstStmt::CreateEvent(s) => {
            let mut plan = simple(
                DdlAction::Create,
                ObjectKind::Generic,
                target_from(s.name_span, source),
                s.node_id,
                s.span,
            );
            plan.body = s
                .body_stmt
                .as_deref()
                .map(|inner| lower_body(std::slice::from_ref(inner), inputs))
                .unwrap_or_default();
            Some(plan)
        }
        AstStmt::AlterEvent(s) => {
            let mut plan = simple(
                DdlAction::Alter,
                ObjectKind::Generic,
                target_from(s.name_span, source),
                s.node_id,
                s.span,
            );
            plan.body = s
                .body_stmt
                .as_deref()
                .map(|inner| lower_body(std::slice::from_ref(inner), inputs))
                .unwrap_or_default();
            Some(plan)
        }
        // MySQL trigger: lower the inline body so its statements analyze
        // (parity with proc / event bodies). The target is the watched table.
        AstStmt::CreateMysqlTrigger(s) => {
            let mut plan = simple(
                DdlAction::Create,
                ObjectKind::Trigger,
                target_from(s.target_table_span, source),
                s.node_id,
                s.span,
            );
            plan.body = s
                .body_stmt
                .as_deref()
                .map(|inner| lower_body(std::slice::from_ref(inner), inputs))
                .unwrap_or_default();
            Some(plan)
        }
        AstStmt::BqAssert(s) => {
            let description = s.description_span.and_then(|sp| {
                source_slice(source, sp).map(|text| crate::ir::ddl_plan::IrBqAssertDescription {
                    text: text.to_string(),
                })
            });
            // Walk every `Box<AstStmt>` subquery reachable from the
            // predicate expression, lower each via the standard
            // query-lowering pipeline, and aggregate `tables_read`.
            // `walk_scalar` in `derive_facts_from_plan` already
            // recurses into nested subqueries, so `tables_read` for
            // each lowered plan transitively includes deeper
            // subqueries' tables. Storing on `IrBqAssertDetail` lets
            // facts-side projection synthesize `query.reads_table`
            // without re-walking the AST.
            let inner_reads_table = collect_bq_assert_inner_reads(&s.expression, inputs);
            Some(DdlPlan {
                action: DdlAction::ControlFlow,
                object_kind: ObjectKind::Generic,
                target: None,
                body: Vec::new(),
                options: DdlOptions::default(),
                node_id: s.node_id,
                span: s.span,
                schema_mutations: Vec::new(),
                mssql_set_option: None,
                mssql_principal_source: None,
                principal_options: None,
                domain: None,
                pg_index: None,
                pg_trigger: None,
                pg_trigger_state: None,
                pg_session: None,
                bq_assert: Some(crate::ir::ddl_plan::IrBqAssertDetail {
                    description,
                    inner_reads_table,
                }),
                bq_create_model: None,
                bq_export_data: None,
                bq_options: None,
                show: None,
                synonym: None,
            })
        }
        AstStmt::BqCreateSnapshotTable(s) => Some(simple(
            DdlAction::Create,
            ObjectKind::Generic,
            target_from(s.snapshot_name_span, source),
            s.node_id,
            s.span,
        )),
        AstStmt::BqDropSnapshotTable(s) => Some(simple(
            DdlAction::Drop,
            ObjectKind::Generic,
            None,
            s.node_id,
            s.span,
        )),
        AstStmt::BqCreateSearchIndex(s) => Some(simple(
            DdlAction::Create,
            ObjectKind::Generic,
            target_from(s.index_name_span, source),
            s.node_id,
            s.span,
        )),
        AstStmt::BqDropSearchIndex(s) => Some(simple(
            DdlAction::Drop,
            ObjectKind::Generic,
            target_from(s.index_name_span, source),
            s.node_id,
            s.span,
        )),
        AstStmt::BqCreateVectorIndex(s) => Some(simple(
            DdlAction::Create,
            ObjectKind::Generic,
            target_from(s.index_name_span, source),
            s.node_id,
            s.span,
        )),
        AstStmt::BqDropVectorIndex(s) => Some(simple(
            DdlAction::Drop,
            ObjectKind::Generic,
            target_from(s.index_name_span, source),
            s.node_id,
            s.span,
        )),
        AstStmt::BqAlterVectorIndex(s) => Some(simple(
            DdlAction::Alter,
            ObjectKind::Generic,
            None,
            s.node_id,
            s.span,
        )),
        AstStmt::BqCreateModel(s) => {
            let remote_connection = s.remote_connection_span.and_then(|sp| {
                source_slice(source, sp).map(|text| crate::ir::ddl_plan::IrBqRemoteConnection {
                    connection_text: text.to_string(),
                })
            });
            let body = s
                .query
                .as_ref()
                .and_then(|q| outermost_select_body(q, source));
            let mut credential_spans: Vec<Span> = Vec::new();
            if let Some(sp) = s.options_span {
                credential_spans.push(sp);
            }
            if let Some(sp) = s.remote_connection_span {
                credential_spans.push(sp);
            }
            let bq_options = Some(extract_bq_options_from_spans(&credential_spans, source));
            Some(DdlPlan {
                action: DdlAction::Create,
                object_kind: ObjectKind::BqModel,
                target: target_from(s.model_name_span, source),
                body: Vec::new(),
                options: DdlOptions::default(),
                node_id: s.node_id,
                span: s.span,
                schema_mutations: Vec::new(),
                mssql_set_option: None,
                mssql_principal_source: None,
                principal_options: None,
                domain: None,
                pg_index: None,
                pg_trigger: None,
                pg_trigger_state: None,
                pg_session: None,
                bq_assert: None,
                bq_create_model: Some(crate::ir::ddl_plan::IrBqCreateModelDetail {
                    remote_connection,
                    body,
                }),
                bq_export_data: None,
                bq_options,
                show: None,
                synonym: None,
            })
        }
        AstStmt::BqAlterModel(s) => {
            let bq_options = Some(extract_bq_options_from_spans(&[s.set_options_span], source));
            Some(DdlPlan {
                action: DdlAction::Alter,
                object_kind: ObjectKind::BqModel,
                target: target_from(s.model_name_span, source),
                body: Vec::new(),
                options: DdlOptions::default(),
                node_id: s.node_id,
                span: s.span,
                schema_mutations: Vec::new(),
                mssql_set_option: None,
                mssql_principal_source: None,
                principal_options: None,
                domain: None,
                pg_index: None,
                pg_trigger: None,
                pg_trigger_state: None,
                pg_session: None,
                bq_assert: None,
                bq_create_model: None,
                bq_export_data: None,
                bq_options,
                show: None,
                synonym: None,
            })
        }
        AstStmt::BqExportModel(s) => {
            let bq_options = Some(extract_bq_options_from_spans(&[s.options_span], source));
            Some(DdlPlan {
                action: DdlAction::BulkLoad,
                object_kind: ObjectKind::BqModel,
                target: target_from(s.model_name_span, source),
                body: Vec::new(),
                options: DdlOptions::default(),
                node_id: s.node_id,
                span: s.span,
                schema_mutations: Vec::new(),
                mssql_set_option: None,
                mssql_principal_source: None,
                principal_options: None,
                domain: None,
                pg_index: None,
                pg_trigger: None,
                pg_trigger_state: None,
                pg_session: None,
                bq_assert: None,
                bq_create_model: None,
                bq_export_data: None,
                bq_options,
                show: None,
                synonym: None,
            })
        }
        AstStmt::BqDropModel(s) => Some(simple(
            DdlAction::Drop,
            ObjectKind::BqModel,
            target_from(s.model_name_span, source),
            s.node_id,
            s.span,
        )),

        // ---- Databricks ----
        AstStmt::Optimize(s) => Some(simple(
            DdlAction::Configure,
            ObjectKind::Generic,
            target_from(s.table_name_span, source),
            s.node_id,
            s.span,
        )),
        AstStmt::DescribeHistory(s) => Some(simple(
            DdlAction::Configure,
            ObjectKind::Generic,
            target_from(s.table_name_span, source),
            s.node_id,
            s.span,
        )),
        AstStmt::Restore(s) => Some(simple(
            DdlAction::Configure,
            ObjectKind::Generic,
            target_from(s.table_name_span, source),
            s.node_id,
            s.span,
        )),
        AstStmt::CacheTable(s) => Some(simple(
            DdlAction::Configure,
            ObjectKind::Generic,
            target_from(s.table_name_span, source),
            s.node_id,
            s.span,
        )),
        AstStmt::UncacheTable(s) => Some(simple(
            DdlAction::Configure,
            ObjectKind::Generic,
            target_from(s.table_name_span, source),
            s.node_id,
            s.span,
        )),
        AstStmt::RepairTable(s) => Some(simple(
            DdlAction::Configure,
            ObjectKind::Generic,
            target_from(s.table_name_span, source),
            s.node_id,
            s.span,
        )),
        AstStmt::CreateCatalog(s) => Some(simple(
            DdlAction::Create,
            ObjectKind::Catalog,
            target_from(s.catalog_name_span, source),
            s.node_id,
            s.span,
        )),
        AstStmt::AlterCatalog(s) => Some(simple(
            DdlAction::Alter,
            ObjectKind::Catalog,
            optional_target_from(s.catalog_name_span, source),
            s.node_id,
            s.span,
        )),
        AstStmt::DropCatalog(s) => Some(simple(
            DdlAction::Drop,
            ObjectKind::Catalog,
            target_from(s.catalog_name_span, source),
            s.node_id,
            s.span,
        )),
        AstStmt::CreateVolume(s) => Some(simple(
            DdlAction::Create,
            ObjectKind::Volume,
            target_from(s.volume_name_span, source),
            s.node_id,
            s.span,
        )),
        AstStmt::AlterVolume(s) => Some(simple(
            DdlAction::Alter,
            ObjectKind::Volume,
            target_from(s.volume_name_span, source),
            s.node_id,
            s.span,
        )),
        AstStmt::DropVolume(s) => Some(simple(
            DdlAction::Drop,
            ObjectKind::Volume,
            target_from(s.volume_name_span, source),
            s.node_id,
            s.span,
        )),
        AstStmt::CreateExternalLocation(s) => Some(simple(
            DdlAction::Create,
            ObjectKind::ExternalLocation,
            target_from(s.location_name_span, source),
            s.node_id,
            s.span,
        )),
        AstStmt::AlterExternalLocation(s) => Some(simple(
            DdlAction::Alter,
            ObjectKind::ExternalLocation,
            target_from(s.location_name_span, source),
            s.node_id,
            s.span,
        )),
        AstStmt::DropExternalLocation(s) => Some(simple(
            DdlAction::Drop,
            ObjectKind::ExternalLocation,
            target_from(s.location_name_span, source),
            s.node_id,
            s.span,
        )),
        AstStmt::CreateStorageCredential(s) => Some(simple(
            DdlAction::Create,
            ObjectKind::StorageCredential,
            target_from(s.credential_name_span, source),
            s.node_id,
            s.span,
        )),
        AstStmt::AlterStorageCredential(s) => Some(simple(
            DdlAction::Alter,
            ObjectKind::StorageCredential,
            target_from(s.credential_name_span, source),
            s.node_id,
            s.span,
        )),
        AstStmt::DropStorageCredential(s) => Some(simple(
            DdlAction::Drop,
            ObjectKind::StorageCredential,
            target_from(s.credential_name_span, source),
            s.node_id,
            s.span,
        )),
        AstStmt::CreateConnection(s) => Some(simple(
            DdlAction::Create,
            ObjectKind::Generic,
            target_from(s.connection_name_span, source),
            s.node_id,
            s.span,
        )),
        AstStmt::MssqlCreateExternalDataSource(s) => Some(simple(
            DdlAction::Create,
            ObjectKind::Generic,
            target_from(s.name_span, source),
            s.node_id,
            s.span,
        )),
        AstStmt::MssqlAlterExternalDataSource(s) => Some(simple(
            DdlAction::Alter,
            ObjectKind::Generic,
            target_from(s.name_span, source),
            s.node_id,
            s.span,
        )),
        AstStmt::CreateForeignServer(s) => Some(simple(
            DdlAction::Create,
            ObjectKind::Generic,
            target_from(s.name_span, source),
            s.node_id,
            s.span,
        )),
        AstStmt::AlterForeignServer(s) => Some(simple(
            DdlAction::Alter,
            ObjectKind::Generic,
            target_from(s.name_span, source),
            s.node_id,
            s.span,
        )),
        AstStmt::MssqlAlterServerConfiguration(s) => Some(simple(
            DdlAction::Alter,
            ObjectKind::Generic,
            None,
            s.node_id,
            s.span,
        )),
        AstStmt::CreateForeignTable(s) => Some(simple(
            DdlAction::Create,
            ObjectKind::Generic,
            target_from(s.name_span, source),
            s.node_id,
            s.span,
        )),
        AstStmt::ImportForeignSchema(s) => Some(simple(
            DdlAction::Create,
            ObjectKind::Generic,
            target_from(s.local_schema_span, source),
            s.node_id,
            s.span,
        )),
        AstStmt::CreateUserMapping(s) => Some(simple(
            DdlAction::Create,
            ObjectKind::Generic,
            target_from(s.server_span, source),
            s.node_id,
            s.span,
        )),
        AstStmt::AlterUserMapping(s) => Some(simple(
            DdlAction::Alter,
            ObjectKind::Generic,
            target_from(s.server_span, source),
            s.node_id,
            s.span,
        )),
        AstStmt::DropUserMapping(s) => Some(simple(
            DdlAction::Drop,
            ObjectKind::Generic,
            target_from(s.server_span, source),
            s.node_id,
            s.span,
        )),
        AstStmt::AlterConnection(s) => Some(simple(
            DdlAction::Alter,
            ObjectKind::Generic,
            target_from(s.connection_name_span, source),
            s.node_id,
            s.span,
        )),
        AstStmt::DropConnection(s) => Some(simple(
            DdlAction::Drop,
            ObjectKind::Generic,
            target_from(s.connection_name_span, source),
            s.node_id,
            s.span,
        )),
        AstStmt::CreateFlow(s) => Some(simple(
            DdlAction::Create,
            ObjectKind::Pipe,
            None,
            s.node_id,
            s.span,
        )),

        // ---- MSSQL ----
        AstStmt::MssqlExec(s) => Some(simple(
            DdlAction::Execute,
            ObjectKind::Procedure,
            optional_target_from(s.procedure_name_span, source),
            s.node_id,
            s.span,
        )),
        // Impersonation context switch / restore — session-scoped, no
        // governance target object; `kind: mssql_execute_as` /
        // `mssql_revert` facts carry the recognition signal.
        AstStmt::MssqlExecuteAs(s) => Some(simple(
            DdlAction::ControlFlow,
            ObjectKind::Generic,
            None,
            s.node_id,
            s.span,
        )),
        AstStmt::MssqlRevert { node_id, span, .. } => Some(simple(
            DdlAction::ControlFlow,
            ObjectKind::Generic,
            None,
            *node_id,
            *span,
        )),
        // Audit lifecycle — `kind: mssql_create/alter/drop_audit` facts
        // carry the typed identity; the DdlPlan rides the generic
        // Security surface for diff pairing.
        AstStmt::MssqlAuditDdl(a) => Some(simple(
            match a.action {
                crate::ast::types::AstMssqlAuditAction::Create => DdlAction::Create,
                crate::ast::types::AstMssqlAuditAction::Alter => DdlAction::Alter,
                crate::ast::types::AstMssqlAuditAction::Drop => DdlAction::Drop,
            },
            ObjectKind::SecurityIntegration,
            optional_target_from(Some(a.name_span), source),
            a.node_id,
            a.span,
        )),
        AstStmt::MssqlSecurityObjectDdl(s) => Some(simple(
            match s.action {
                crate::ast::types::AstMssqlAuditAction::Create => DdlAction::Create,
                crate::ast::types::AstMssqlAuditAction::Alter => DdlAction::Alter,
                crate::ast::types::AstMssqlAuditAction::Drop => DdlAction::Drop,
            },
            ObjectKind::SecurityIntegration,
            optional_target_from(s.name_span, source),
            s.node_id,
            s.span,
        )),
        AstStmt::MssqlTryCatch(s) => {
            let mut body = lower_body(&s.try_body, inputs);
            body.extend(lower_body(&s.catch_body, inputs));
            Some(with_body(
                DdlAction::ControlFlow,
                ObjectKind::Generic,
                None,
                body,
                s.node_id,
                s.span,
            ))
        }
        AstStmt::MssqlIf(s) => {
            let mut body = lower_body(&s.then_body, inputs);
            body.extend(lower_body(&s.else_body, inputs));
            Some(with_body(
                DdlAction::ControlFlow,
                ObjectKind::Generic,
                None,
                body,
                s.node_id,
                s.span,
            ))
        }

        AstStmt::MssqlWhile(s) => Some(with_body(
            DdlAction::ControlFlow,
            ObjectKind::Generic,
            None,
            lower_body(&s.body, inputs),
            s.node_id,
            s.span,
        )),
        AstStmt::MssqlPrint(s) => Some(simple(
            DdlAction::ControlFlow,
            ObjectKind::Generic,
            None,
            s.node_id,
            s.span,
        )),
        // RECONFIGURE applies pending server config; no governance target,
        // a control-flow no-op like PRINT. `kind: reconfigure` facts carry
        // the recognition signal for any rule that wants to match it.
        AstStmt::Reconfigure { node_id, span, .. } => Some(simple(
            DdlAction::ControlFlow,
            ObjectKind::Generic,
            None,
            *node_id,
            *span,
        )),
        AstStmt::MssqlThrow(s) => Some(simple(
            DdlAction::ControlFlow,
            ObjectKind::Generic,
            None,
            s.node_id,
            s.span,
        )),
        AstStmt::MssqlRaiserror(s) => Some(simple(
            DdlAction::ControlFlow,
            ObjectKind::Generic,
            None,
            s.node_id,
            s.span,
        )),
        // MySQL SET is not lowered to a DDL/governance plan in this batch;
        // its dynamic-SQL value taint is wired in dynsql_taint, not here.
        AstStmt::MysqlSet(_) => None,
        // ALTER SESSION SET/UNSET is handled by its own SessionPlan block
        // in lib.rs (rich `ddl.session.*` facts), not the generic DDL path.
        AstStmt::AlterSession(_) => None,
        AstStmt::MssqlSetOption(s) => Some(DdlPlan {
            action: DdlAction::Configure,
            object_kind: ObjectKind::Generic,
            target: None,
            body: Vec::new(),
            options: DdlOptions::default(),
            node_id: s.node_id,
            span: s.span,
            schema_mutations: Vec::new(),
            mssql_set_option: Some(crate::ir::ddl_plan::MssqlSetOptionDetail {
                option_kind: project_ast_set_option_kind(s.option_kind),
                value: project_ast_set_option_value(s.value),
                isolation_level: s.isolation_level.map(project_ast_isolation_level),
            }),
            mssql_principal_source: None,
            principal_options: None,
            domain: None,
            pg_index: None,
            pg_trigger: None,
            pg_trigger_state: None,
            pg_session: None,
            bq_assert: None,
            bq_create_model: None,
            bq_export_data: None,
            bq_options: None,
            show: None,
            synonym: None,
        }),
        AstStmt::MssqlWaitfor(s) => Some(simple(
            DdlAction::ControlFlow,
            ObjectKind::Generic,
            None,
            s.node_id,
            s.span,
        )),
        AstStmt::MssqlGoto(s) => Some(simple(
            DdlAction::ControlFlow,
            ObjectKind::Generic,
            None,
            s.node_id,
            s.span,
        )),
        AstStmt::MssqlLabel(s) => Some(simple(
            DdlAction::ControlFlow,
            ObjectKind::Generic,
            None,
            s.node_id,
            s.span,
        )),
        AstStmt::CreateMssqlTrigger(s) => Some(with_body(
            DdlAction::Create,
            ObjectKind::Trigger,
            target_from(s.name_span, source),
            lower_body(&s.body, inputs),
            s.node_id,
            s.span,
        )),
        AstStmt::DropMssqlTrigger(s) => Some(plan(
            DdlAction::Drop,
            ObjectKind::Trigger,
            s.trigger_names
                .first()
                .copied()
                .and_then(|sp| target_from(sp, source)),
            DdlOptions {
                if_exists: s.if_exists,
                ..DdlOptions::default()
            },
            s.node_id,
            s.span,
        )),
        AstStmt::MssqlBulkInsert(s) => Some(simple(
            DdlAction::BulkLoad,
            ObjectKind::Generic,
            target_from(s.table_span, source),
            s.node_id,
            s.span,
        )),
        AstStmt::MssqlCreateExternalModel(s) => Some(simple(
            DdlAction::Create,
            ObjectKind::Generic,
            target_from(s.name_span, source),
            s.node_id,
            s.span,
        )),
        AstStmt::MssqlAlterExternalModel(s) => Some(simple(
            DdlAction::Alter,
            ObjectKind::Generic,
            target_from(s.name_span, source),
            s.node_id,
            s.span,
        )),
        AstStmt::MssqlDropExternalModel(s) => Some(simple(
            DdlAction::Drop,
            ObjectKind::Generic,
            target_from(s.name_span, source),
            s.node_id,
            s.span,
        )),
        AstStmt::MssqlCreateVectorIndex(s) => Some(simple(
            DdlAction::Create,
            ObjectKind::Generic,
            target_from(s.index_name_span, source),
            s.node_id,
            s.span,
        )),
        // MSSQL CREATE LOGIN / CREATE USER were folded into the
        // dialect-neutral `AstStmt::CreatePrincipal` path; see
        // `lower_create_principal`.

        // ---- Procedure / Function definitions (inline variants) ----
        AstStmt::CreateProcedure(s) => Some(DdlPlan {
            action: DdlAction::Create,
            object_kind: ObjectKind::Procedure,
            target: target_from(s.name_span, source),
            body: s
                .body_stmt
                .as_deref()
                .map(|inner| lower_body(std::slice::from_ref(inner), inputs))
                .unwrap_or_default(),
            options: DdlOptions {
                or_replace: s.or_replace_span.is_some(),
                ..DdlOptions::default()
            },
            node_id: s.node_id,
            span: s.span,
            schema_mutations: Vec::new(),
            mssql_set_option: None,
            mssql_principal_source: None,
            principal_options: None,
            domain: None,
            pg_index: None,
            pg_trigger: None,
            pg_trigger_state: None,
            pg_session: None,
            bq_assert: None,
            bq_create_model: None,
            bq_export_data: None,
            bq_options: None,
            show: None,
            synonym: None,
        }),
        AstStmt::CreateFunction(s) => Some(DdlPlan {
            action: DdlAction::Create,
            object_kind: ObjectKind::Function,
            target: target_from(s.name_span, source),
            body: s
                .body_stmt
                .as_deref()
                .map(|inner| lower_body(std::slice::from_ref(inner), inputs))
                .unwrap_or_default(),
            options: DdlOptions {
                or_replace: s.or_replace_span.is_some(),
                temporary: s.temp_keyword_span.is_some(),
                if_not_exists: s.if_not_exists_span.is_some(),
                ..DdlOptions::default()
            },
            node_id: s.node_id,
            span: s.span,
            schema_mutations: Vec::new(),
            mssql_set_option: None,
            mssql_principal_source: None,
            principal_options: None,
            domain: None,
            pg_index: None,
            pg_trigger: None,
            pg_trigger_state: None,
            pg_session: None,
            bq_assert: None,
            bq_create_model: None,
            bq_export_data: None,
            bq_options: None,
            show: None,
            synonym: None,
        }),
        AstStmt::CreateTableFunction(s) => Some(DdlPlan {
            action: DdlAction::Create,
            object_kind: ObjectKind::Function,
            target: target_from(s.name_span, source),
            body: s
                .body_stmt
                .as_deref()
                .map(|inner| lower_body(std::slice::from_ref(inner), inputs))
                .unwrap_or_default(),
            options: DdlOptions {
                or_replace: s.or_replace_span.is_some(),
                temporary: s.temp_keyword_span.is_some(),
                if_not_exists: s.if_not_exists_span.is_some(),
                ..DdlOptions::default()
            },
            node_id: s.node_id,
            span: s.span,
            schema_mutations: Vec::new(),
            mssql_set_option: None,
            mssql_principal_source: None,
            principal_options: None,
            domain: None,
            pg_index: None,
            pg_trigger: None,
            pg_trigger_state: None,
            pg_session: None,
            bq_assert: None,
            bq_create_model: None,
            bq_export_data: None,
            bq_options: None,
            show: None,
            synonym: None,
        }),

        // ---- Inline scripting variants ----
        AstStmt::Block(s) => {
            // Block carries DECLARE-section decls (Snowflake Scripting)
            // and the BEGIN..END body. Both are sequences of inner
            // AstStmts; flatten into the single body slot in source
            // order — decls first, then BEGIN..END body. The
            // EXCEPTION section is span-only and not lowered.
            let mut body = lower_body(&s.decls, inputs);
            body.extend(lower_body(&s.body, inputs));
            Some(with_body(
                DdlAction::ControlFlow,
                ObjectKind::Generic,
                None,
                body,
                s.node_id,
                s.span,
            ))
        }
        AstStmt::Assign { node_id, span, .. } => Some(simple(
            DdlAction::ControlFlow,
            ObjectKind::Generic,
            None,
            *node_id,
            *span,
        )),
        AstStmt::If(s) => {
            // Flatten every branch body and the ELSE body into a
            // single source-ordered Vec. The branch conditions
            // themselves are AstExpr — predicate semantics live
            // outside DdlPlan.body and are not lowered here.
            let mut body = Vec::new();
            for branch in &s.branches {
                body.extend(lower_body(&branch.body, inputs));
            }
            body.extend(lower_body(&s.else_body, inputs));
            Some(with_body(
                DdlAction::ControlFlow,
                ObjectKind::Generic,
                None,
                body,
                s.node_id,
                s.span,
            ))
        }
        AstStmt::CaseStmt(s) => {
            // Same shape as If: flatten WHEN-branch bodies + ELSE body.
            let mut body = Vec::new();
            for branch in &s.branches {
                body.extend(lower_body(&branch.body, inputs));
            }
            body.extend(lower_body(&s.else_body, inputs));
            Some(with_body(
                DdlAction::ControlFlow,
                ObjectKind::Generic,
                None,
                body,
                s.node_id,
                s.span,
            ))
        }
        AstStmt::Declare { node_id, span, .. } => Some(simple(
            DdlAction::ControlFlow,
            ObjectKind::Generic,
            None,
            *node_id,
            *span,
        )),
        AstStmt::DeclareTable { node_id, span, .. } => Some(simple(
            DdlAction::ControlFlow,
            ObjectKind::Generic,
            None,
            *node_id,
            *span,
        )),
        AstStmt::DeclareCursor { node_id, span, .. } => Some(simple(
            DdlAction::ControlFlow,
            ObjectKind::Generic,
            None,
            *node_id,
            *span,
        )),
        AstStmt::Let { node_id, span, .. } => Some(simple(
            DdlAction::ControlFlow,
            ObjectKind::Generic,
            None,
            *node_id,
            *span,
        )),
        AstStmt::LetCursor { node_id, span, .. } => Some(simple(
            DdlAction::ControlFlow,
            ObjectKind::Generic,
            None,
            *node_id,
            *span,
        )),
        AstStmt::Return { node_id, span, .. } => Some(simple(
            DdlAction::ControlFlow,
            ObjectKind::Generic,
            None,
            *node_id,
            *span,
        )),
        AstStmt::Raise { node_id, span, .. } => Some(simple(
            DdlAction::ControlFlow,
            ObjectKind::Generic,
            None,
            *node_id,
            *span,
        )),
        AstStmt::Signal { node_id, span, .. } => Some(simple(
            DdlAction::ControlFlow,
            ObjectKind::Generic,
            None,
            *node_id,
            *span,
        )),
        AstStmt::Resignal { node_id, span, .. } => Some(simple(
            DdlAction::ControlFlow,
            ObjectKind::Generic,
            None,
            *node_id,
            *span,
        )),
        AstStmt::GetDiagnostics { node_id, span, .. } => Some(simple(
            DdlAction::ControlFlow,
            ObjectKind::Generic,
            None,
            *node_id,
            *span,
        )),
        AstStmt::DeclareCondition { node_id, span, .. } => Some(simple(
            DdlAction::ControlFlow,
            ObjectKind::Generic,
            None,
            *node_id,
            *span,
        )),
        AstStmt::DeclareHandler(s) => Some(simple(
            DdlAction::ControlFlow,
            ObjectKind::Generic,
            None,
            s.node_id,
            s.span,
        )),
        AstStmt::For(s) => Some(with_body(
            DdlAction::ControlFlow,
            ObjectKind::Generic,
            None,
            lower_body(&s.body, inputs),
            s.node_id,
            s.span,
        )),
        AstStmt::ForEach(s) => Some(with_body(
            DdlAction::ControlFlow,
            ObjectKind::Generic,
            None,
            lower_body(&s.body, inputs),
            s.node_id,
            s.span,
        )),
        AstStmt::While(s) => Some(with_body(
            DdlAction::ControlFlow,
            ObjectKind::Generic,
            None,
            lower_body(&s.body, inputs),
            s.node_id,
            s.span,
        )),
        AstStmt::Repeat(s) => Some(with_body(
            DdlAction::ControlFlow,
            ObjectKind::Generic,
            None,
            lower_body(&s.body, inputs),
            s.node_id,
            s.span,
        )),
        AstStmt::Loop(s) => Some(with_body(
            DdlAction::ControlFlow,
            ObjectKind::Generic,
            None,
            lower_body(&s.body, inputs),
            s.node_id,
            s.span,
        )),
        AstStmt::Await { node_id, span, .. } => Some(simple(
            DdlAction::ControlFlow,
            ObjectKind::Generic,
            None,
            *node_id,
            *span,
        )),
        AstStmt::Cancel { node_id, span, .. } => Some(simple(
            DdlAction::ControlFlow,
            ObjectKind::Generic,
            None,
            *node_id,
            *span,
        )),
        AstStmt::Break { node_id, span, .. } => Some(simple(
            DdlAction::ControlFlow,
            ObjectKind::Generic,
            None,
            *node_id,
            *span,
        )),
        AstStmt::Continue { node_id, span, .. } => Some(simple(
            DdlAction::ControlFlow,
            ObjectKind::Generic,
            None,
            *node_id,
            *span,
        )),
        AstStmt::Null { node_id, span, .. } => Some(simple(
            DdlAction::ControlFlow,
            ObjectKind::Generic,
            None,
            *node_id,
            *span,
        )),
        AstStmt::OpenCursor { node_id, span, .. } => Some(simple(
            DdlAction::ControlFlow,
            ObjectKind::Generic,
            None,
            *node_id,
            *span,
        )),
        AstStmt::FetchCursor { node_id, span, .. } => Some(simple(
            DdlAction::ControlFlow,
            ObjectKind::Generic,
            None,
            *node_id,
            *span,
        )),
        AstStmt::CloseCursor { node_id, span, .. } => Some(simple(
            DdlAction::ControlFlow,
            ObjectKind::Generic,
            None,
            *node_id,
            *span,
        )),

        // ---- EXECUTE / CALL ----
        AstStmt::ExecuteImmediate { node_id, span, .. } => Some(plan(
            DdlAction::Execute,
            ObjectKind::Generic,
            None,
            DdlOptions {
                dynamic_sql: true,
                ..DdlOptions::default()
            },
            *node_id,
            *span,
        )),
        // `EXECUTE IMMEDIATE FROM <stage_file>` — top-level recognition is
        // intercepted at the statement dispatch; this fallback covers the
        // statement when it is reached through body lowering.
        AstStmt::ExecuteImmediateFrom(s) => Some(plan(
            DdlAction::Execute,
            ObjectKind::Generic,
            None,
            DdlOptions {
                dynamic_sql: true,
                ..DdlOptions::default()
            },
            s.node_id,
            s.span,
        )),
        AstStmt::Call {
            node_id,
            span,
            procedure_name_span,
            ..
        } => Some(simple(
            DdlAction::Execute,
            ObjectKind::Procedure,
            target_from(*procedure_name_span, source),
            *node_id,
            *span,
        )),

        // ---- Transaction control ----
        AstStmt::BeginTransaction { node_id, span } => Some(simple(
            DdlAction::Transaction,
            ObjectKind::Generic,
            None,
            *node_id,
            *span,
        )),
        AstStmt::Commit { node_id, span } => Some(simple(
            DdlAction::Transaction,
            ObjectKind::Generic,
            None,
            *node_id,
            *span,
        )),
        AstStmt::Rollback { node_id, span } => Some(simple(
            DdlAction::Transaction,
            ObjectKind::Generic,
            None,
            *node_id,
            *span,
        )),

        // ---- Session variable / Pipe chain ----
        AstStmt::SetVariable { node_id, span, .. } => Some(simple(
            DdlAction::Configure,
            ObjectKind::Generic,
            None,
            *node_id,
            *span,
        )),
        AstStmt::PipeChain { node_id, span, .. } => Some(simple(
            DdlAction::ControlFlow,
            ObjectKind::Generic,
            None,
            *node_id,
            *span,
        )),

        // ---- COPY INTO ----
        AstStmt::CopyIntoTable {
            node_id,
            span,
            table_name_span,
            ..
        } => Some(simple(
            DdlAction::BulkLoad,
            ObjectKind::Stage,
            target_from(*table_name_span, source),
            *node_id,
            *span,
        )),
        AstStmt::CopyIntoLocation { node_id, span, .. } => Some(simple(
            DdlAction::BulkLoad,
            ObjectKind::Stage,
            None,
            *node_id,
            *span,
        )),
        AstStmt::Unload { node_id, span, .. } => Some(simple(
            DdlAction::BulkLoad,
            ObjectKind::Stage,
            None,
            *node_id,
            *span,
        )),
        AstStmt::RedshiftCopy { node_id, span, .. } => Some(simple(
            DdlAction::BulkLoad,
            ObjectKind::Stage,
            None,
            *node_id,
            *span,
        )),

        // ---- GRANT / REVOKE / DENY ----
        AstStmt::Grant(g) => Some(simple(
            DdlAction::Grant,
            ObjectKind::Generic,
            None,
            g.node_id,
            g.span,
        )),
        AstStmt::Revoke(r) => Some(simple(
            DdlAction::Revoke,
            ObjectKind::Generic,
            None,
            r.node_id,
            r.span,
        )),
        AstStmt::Deny(d) => Some(simple(
            DdlAction::Revoke,
            ObjectKind::Generic,
            None,
            d.node_id,
            d.span,
        )),
        // Ownership transfer rides the Grant surface here (the
        // privilege-plan path carries the precise identity); mirrors
        // the Deny arm's approximation above.
        AstStmt::AlterAuthorization(a) => Some(simple(
            DdlAction::Alter,
            ObjectKind::Generic,
            None,
            a.node_id,
            a.span,
        )),
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

#[inline]
/// Map the parser-typed [`crate::ast::AstShowKind`] to the normalized
/// object-class recognition string carried on the IR.
fn show_object_class_name(kind: &crate::ast::AstShowKind) -> String {
    use crate::ast::{AstShowKind as K, ShowPolicyKind as P};
    let s = match kind {
        K::Objects => "OBJECTS",
        K::Tables => "TABLES",
        K::ExternalTables => "EXTERNAL_TABLES",
        K::DynamicTables => "DYNAMIC_TABLES",
        K::IcebergTables => "ICEBERG_TABLES",
        K::EventTables => "EVENT_TABLES",
        K::Views => "VIEWS",
        K::MaterializedViews => "MATERIALIZED_VIEWS",
        K::Columns => "COLUMNS",
        K::Databases => "DATABASES",
        K::Schemas => "SCHEMAS",
        K::Sequences => "SEQUENCES",
        K::Stages => "STAGES",
        K::Pipes => "PIPES",
        K::Streams => "STREAMS",
        K::Tasks => "TASKS",
        K::Functions => "FUNCTIONS",
        K::Procedures => "PROCEDURES",
        K::Warehouses => "WAREHOUSES",
        K::Users => "USERS",
        K::Roles => "ROLES",
        K::Parameters => "PARAMETERS",
        K::FileFormats => "FILE_FORMATS",
        K::Tags => "TAGS",
        K::Integrations => "INTEGRATIONS",
        K::PrimaryKeys => "PRIMARY_KEYS",
        K::Grants(_) => "GRANTS",
        K::Policies(p) => {
            return match p {
                P::Masking => "MASKING_POLICIES",
                P::RowAccess => "ROW_ACCESS_POLICIES",
                P::Session => "SESSION_POLICIES",
                P::Password => "PASSWORD_POLICIES",
                P::Network => "NETWORK_POLICIES",
                P::Authentication => "AUTHENTICATION_POLICIES",
                P::Projection => "PROJECTION_POLICIES",
                P::Aggregation => "AGGREGATION_POLICIES",
                P::Join => "JOIN_POLICIES",
                P::Unspecified => "POLICIES",
            }
            .to_string();
        }
        K::Other(raw) => return raw.clone(),
    };
    s.to_string()
}

/// Map the AST principal kind to its normalized recognition string.
fn show_principal_kind_name(kind: &crate::ast::ShowPrincipalKind) -> String {
    use crate::ast::ShowPrincipalKind as K;
    match kind {
        K::Role => "ROLE".to_string(),
        K::User => "USER".to_string(),
        K::Share => "SHARE".to_string(),
        K::DatabaseRole => "DATABASE_ROLE".to_string(),
        K::Application => "APPLICATION".to_string(),
        K::ApplicationRole => "APPLICATION_ROLE".to_string(),
        K::Other(s) => s.clone(),
    }
}

/// Lower an AST `IN <scope>` filter to its IR recognition form.
fn lower_show_scope(scope: &crate::ast::ShowScope) -> crate::ir::ddl_plan::ShowScopeIr {
    use crate::ast::ShowScope as S;
    let (kind, name) = match scope {
        S::Account => ("ACCOUNT".to_string(), None),
        S::Database(n) => ("DATABASE".to_string(), n.as_ref()),
        S::Schema(n) => ("SCHEMA".to_string(), n.as_ref()),
        S::Table(n) => ("TABLE".to_string(), Some(n)),
        S::View(n) => ("VIEW".to_string(), Some(n)),
        S::Other { kind, name } => (kind.clone(), name.as_ref()),
    };
    crate::ir::ddl_plan::ShowScopeIr {
        kind,
        name: name.map(|n| n.text.clone()),
        name_span: name.map(|n| n.span),
    }
}

/// Lower an AST `SHOW [FUTURE] GRANTS …` clause to its IR form.
fn lower_show_grants(spec: &crate::ast::ShowGrantsSpec) -> crate::ir::ddl_plan::ShowGrantsIr {
    use crate::ast::{ShowGrantsObject as O, ShowGrantsRelation as R};
    let mut relation = "CURRENT_USER";
    let mut on_account = false;
    let mut target_kind: Option<String> = None;
    let mut name: Option<String> = None;
    let mut name_span: Option<Span> = None;

    match &spec.relation {
        R::CurrentUser => {}
        R::On(obj) => {
            relation = "ON";
            match obj {
                O::Account => on_account = true,
                O::Named {
                    object_class,
                    name: n,
                } => {
                    target_kind = Some(object_class.clone());
                    name = Some(n.text.clone());
                    name_span = Some(n.span);
                }
            }
        }
        R::To(p) => {
            relation = "TO";
            target_kind = Some(show_principal_kind_name(&p.kind));
            name = Some(p.name.text.clone());
            name_span = Some(p.name.span);
        }
        R::Of(p) => {
            relation = "OF";
            target_kind = Some(show_principal_kind_name(&p.kind));
            name = Some(p.name.text.clone());
            name_span = Some(p.name.span);
        }
        R::In(sc) => {
            relation = "IN";
            let inner = lower_show_scope(sc);
            target_kind = Some(inner.kind);
            name = inner.name;
            name_span = inner.name_span;
        }
    }

    crate::ir::ddl_plan::ShowGrantsIr {
        future: spec.future,
        relation: relation.to_string(),
        on_account,
        target_kind,
        name,
        name_span,
    }
}

/// Lower a `SHOW` statement's parser-typed recognition into the IR
/// sibling carried on [`DdlPlan::show`]. Reads the typed AST only.
fn lower_show(s: &crate::ast::AstShow) -> crate::ir::ddl_plan::ShowPlanIr {
    use crate::ast::AstShowKind;
    let grants = match &s.kind {
        AstShowKind::Grants(spec) => Some(lower_show_grants(spec)),
        _ => None,
    };
    let scope = s.scope.as_ref().map(lower_show_scope);
    crate::ir::ddl_plan::ShowPlanIr {
        object_class: show_object_class_name(&s.kind),
        terse: s.terse_span.is_some(),
        history: s.history_span.is_some(),
        grants,
        scope,
    }
}

fn simple(
    action: DdlAction,
    object_kind: ObjectKind,
    target: Option<DdlTarget>,
    node_id: crate::ast::NodeId,
    span: Span,
) -> DdlPlan {
    DdlPlan {
        action,
        object_kind,
        target,
        body: Vec::new(),
        options: DdlOptions::default(),
        node_id,
        span,
        schema_mutations: Vec::new(),
        mssql_set_option: None,
        mssql_principal_source: None,
        principal_options: None,
        domain: None,
        pg_index: None,
        pg_trigger: None,
        pg_trigger_state: None,
        pg_session: None,
        bq_assert: None,
        bq_create_model: None,
        bq_export_data: None,
        bq_options: None,
        show: None,
        synonym: None,
    }
}

#[inline]
fn plan(
    action: DdlAction,
    object_kind: ObjectKind,
    target: Option<DdlTarget>,
    options: DdlOptions,
    node_id: crate::ast::NodeId,
    span: Span,
) -> DdlPlan {
    DdlPlan {
        action,
        object_kind,
        target,
        body: Vec::new(),
        options,
        node_id,
        span,
        schema_mutations: Vec::new(),
        mssql_set_option: None,
        mssql_principal_source: None,
        principal_options: None,
        domain: None,
        pg_index: None,
        pg_trigger: None,
        pg_trigger_state: None,
        pg_session: None,
        bq_assert: None,
        bq_create_model: None,
        bq_export_data: None,
        bq_options: None,
        show: None,
        synonym: None,
    }
}

/// Build a [`DdlPlan`] with the body slot populated. Used by
/// body-bearing variants (`BEGIN ... END`, `IF`, `WHILE`,
/// `CREATE PROCEDURE`, …) so [`DdlPlan::body`] reflects the
/// AST's nested statement structure.
#[inline]
fn with_body(
    action: DdlAction,
    object_kind: ObjectKind,
    target: Option<DdlTarget>,
    body: Vec<Rc<StatementPlan>>,
    node_id: crate::ast::NodeId,
    span: Span,
) -> DdlPlan {
    DdlPlan {
        action,
        object_kind,
        target,
        body,
        options: DdlOptions::default(),
        node_id,
        span,
        schema_mutations: Vec::new(),
        mssql_set_option: None,
        mssql_principal_source: None,
        principal_options: None,
        domain: None,
        pg_index: None,
        pg_trigger: None,
        pg_trigger_state: None,
        pg_session: None,
        bq_assert: None,
        bq_create_model: None,
        bq_export_data: None,
        bq_options: None,
        show: None,
        synonym: None,
    }
}

/// AST → IR-internal closed-enum projection for
/// [`crate::ast::AlterDomainAction`]. Exhaustive `match`; new AST
/// variants break the build until classified here. The
/// `DropConstraint` arm carries its own per-action `cascade`
/// discriminator — the statement-level `DROP DOMAIN x CASCADE` is
/// plumbed via [`crate::ir::ddl_plan::DdlOptions::cascade`] instead.
fn project_ast_alter_domain_action(
    action: &crate::ast::AlterDomainAction,
) -> crate::ir::ddl_plan::IrDomainAlterAction {
    use crate::ast::AlterDomainAction as A;
    use crate::ir::ddl_plan::IrDomainAlterAction as I;
    match action {
        A::SetDefault { .. } => I::SetDefault,
        A::DropDefault { .. } => I::DropDefault,
        A::SetNotNull { .. } => I::SetNotNull,
        A::DropNotNull { .. } => I::DropNotNull,
        A::AddConstraint { .. } => I::AddConstraint,
        A::DropConstraint {
            cascade_restrict, ..
        } => I::DropConstraint {
            cascade: matches!(
                cascade_restrict,
                Some(crate::ast::PgCascadeRestrict::Cascade)
            ),
        },
        A::RenameConstraint { .. } => I::RenameConstraint,
        A::ValidateConstraint { .. } => I::ValidateConstraint,
        A::OwnerTo { .. } => I::OwnerTo,
        A::RenameTo { .. } => I::RenameTo,
        A::SetSchema { .. } => I::SetSchema,
    }
}

/// AST → IR-internal closed-enum projection for
/// [`crate::ast::AlterIndexAction`] (top-level) + the inner
/// [`crate::ast::AlterIndexSubAction`]. Exhaustive `match`; new AST
/// variants break the build until classified here. Postgres `ALTER
/// INDEX` grammar permits one sub-action per statement, so this
/// returns a single value rather than a `Vec`.
fn project_ast_alter_index_action(
    action: &crate::ast::AlterIndexAction,
) -> crate::ir::ddl_plan::IrIndexAlterAction {
    use crate::ast::AlterIndexAction as A;
    use crate::ast::AlterIndexSubAction as S;
    use crate::ir::ddl_plan::IrIndexAlterAction as I;
    match action {
        A::Named { sub_action, .. } => match sub_action {
            S::RenameTo { .. } => I::RenameTo,
            S::SetTablespace { .. } => I::SetTablespace,
            S::AttachPartition { .. } => I::AttachPartition,
            S::DependsOnExtension { .. } => I::DependsOnExtension,
            S::SetParams { .. } => I::SetParams,
            S::ResetParams { .. } => I::ResetParams,
            S::AlterColumnStatistics { .. } => I::AlterColumnStatistics,
        },
        A::AllInTablespace { .. } => I::AllInTablespace,
        A::OnObject { maintenance, .. } => {
            use crate::ast::AlterIndexMaintenance as M;
            match maintenance {
                M::Rebuild => I::Rebuild,
                M::Reorganize => I::Reorganize,
                M::Disable => I::Disable,
                M::Set => I::SetOptions,
            }
        }
    }
}

/// AST → IR-internal closed-enum projection for
/// [`crate::ast::PgAlterTriggerAction`]. Exhaustive `match`; new AST
/// variants break the build until classified here. Postgres
/// `ALTER TRIGGER` grammar permits one sub-action per statement, so
/// this returns a single value rather than a `Vec`.
fn project_ast_alter_trigger_action(
    action: &crate::ast::PgAlterTriggerAction,
) -> crate::ir::ddl_plan::IrTriggerAlterAction {
    use crate::ast::PgAlterTriggerAction as A;
    use crate::ir::ddl_plan::IrTriggerAlterAction as I;
    match action {
        A::RenameTo { .. } => I::RenameTo,
        A::DependsOnExtension { .. } => I::DependsOnExtension,
    }
}

/// AST → IR-internal closed-enum projection for
/// [`crate::ast::PgAlterTableTriggerStateAction`]. Exhaustive `match`;
/// new AST variants break the build until classified here.
fn project_ast_trigger_state_action(
    action: crate::ast::PgAlterTableTriggerStateAction,
) -> crate::ir::ddl_plan::IrTriggerStateAction {
    use crate::ast::PgAlterTableTriggerStateAction as A;
    use crate::ir::ddl_plan::IrTriggerStateAction as I;
    match action {
        A::Disable => I::Disable,
        A::Enable => I::Enable,
        A::EnableAlways => I::EnableAlways,
        A::EnableReplica => I::EnableReplica,
    }
}

/// AST → IR-internal closed-enum projection for
/// [`crate::ast::PgSetKind`]. Exhaustive `match`; new AST variants
/// break the build until classified here.
fn project_ast_pg_set_kind(kind: crate::ast::PgSetKind) -> crate::ir::ddl_plan::IrPgSessionAction {
    use crate::ast::PgSetKind as A;
    use crate::ir::ddl_plan::IrPgSessionAction as I;
    match kind {
        A::SetRole => I::SetRole,
        A::SetSessionAuthorization => I::SetSessionAuthorization,
        A::SetSearchPath => I::SetSearchPath,
        A::SetParameter => I::SetParameter,
        A::ResetRole => I::ResetRole,
        A::ResetSessionAuthorization => I::ResetSessionAuthorization,
        A::ResetSearchPath => I::ResetSearchPath,
        A::ResetParameter => I::ResetParameter,
        A::ResetAll => I::ResetAll,
    }
}

/// AST → IR-internal closed-enum projection for
/// [`crate::ast::AstMssqlSetOptionKind`]. Exhaustive `match`; new AST
/// variants break the build until classified here.
fn project_ast_set_option_kind(
    kind: crate::ast::AstMssqlSetOptionKind,
) -> crate::ir::ddl_plan::MssqlSetOptionKindIr {
    use crate::ast::AstMssqlSetOptionKind as A;
    use crate::ir::ddl_plan::MssqlSetOptionKindIr as I;
    match kind {
        A::IdentityInsert => I::IdentityInsert,
        A::NoCount => I::NoCount,
        A::XactAbort => I::XactAbort,
        A::AnsiNulls => I::AnsiNulls,
        A::QuotedIdentifier => I::QuotedIdentifier,
        A::ArithAbort => I::ArithAbort,
        A::ConcatNullYieldsNull => I::ConcatNullYieldsNull,
        A::LockTimeout => I::LockTimeout,
        A::DeadlockPriority => I::DeadlockPriority,
        A::RowCount => I::RowCount,
        A::TransactionIsolationLevel => I::TransactionIsolationLevel,
        A::Other => I::Other,
    }
}

fn project_ast_set_option_value(
    value: crate::ast::AstMssqlSetOptionValue,
) -> crate::ir::ddl_plan::MssqlSetOptionValueIr {
    use crate::ast::AstMssqlSetOptionValue as A;
    use crate::ir::ddl_plan::MssqlSetOptionValueIr as I;
    match value {
        A::On => I::On,
        A::Off => I::Off,
        A::NumericLiteral => I::NumericLiteral,
        A::Identifier => I::Identifier,
        A::Unparsed => I::Unparsed,
    }
}

fn project_ast_isolation_level(
    level: crate::ast::AstMssqlIsolationLevel,
) -> crate::ir::ddl_plan::MssqlIsolationLevelIr {
    use crate::ast::AstMssqlIsolationLevel as A;
    use crate::ir::ddl_plan::MssqlIsolationLevelIr as I;
    match level {
        A::ReadUncommitted => I::ReadUncommitted,
        A::ReadCommitted => I::ReadCommitted,
        A::RepeatableRead => I::RepeatableRead,
        A::Snapshot => I::Snapshot,
        A::Serializable => I::Serializable,
    }
}

fn project_ast_principal_source(
    source: crate::ast::AstMssqlPrincipalSource,
) -> crate::ir::ddl_plan::MssqlPrincipalSourceIr {
    use crate::ast::AstMssqlPrincipalSource as A;
    use crate::ir::ddl_plan::MssqlPrincipalSourceIr as I;
    match source {
        A::FromExternalProvider => I::FromExternalProvider,
        A::WithPassword => I::WithPassword,
        A::FromCertificate => I::FromCertificate,
        A::FromAsymmetricKey => I::FromAsymmetricKey,
        A::FromWindows => I::FromWindows,
        A::ForLogin => I::ForLogin,
        A::WithoutLogin => I::WithoutLogin,
        A::Unparsed => I::Unparsed,
    }
}

fn project_ast_principal_kind(
    kind: crate::ast::types::PrincipalKind,
) -> crate::ir::ddl_plan::PrincipalKindIr {
    use crate::ast::types::PrincipalKind as A;
    use crate::ir::ddl_plan::PrincipalKindIr as I;
    match kind {
        A::User => I::User,
        A::Role => I::Role,
        A::Login => I::Login,
        A::Group => I::Group,
        A::ApplicationRole => I::ApplicationRole,
        A::DatabaseRole => I::DatabaseRole,
    }
}

fn surface_for_principal_kind(kind: crate::ast::types::PrincipalKind) -> ObjectKind {
    use crate::ast::types::PrincipalKind as A;
    match kind {
        A::User => ObjectKind::User,
        A::Role => ObjectKind::Role,
        A::Group => ObjectKind::Group,
        A::Login => ObjectKind::Generic,
        // Application roles and Snowflake database roles ride the Role
        // surface; the facts-level principal kind keeps the distinction.
        A::ApplicationRole => ObjectKind::Role,
        A::DatabaseRole => ObjectKind::Role,
    }
}

fn literal_content_span(span: Span, source: &str) -> String {
    let start = span.start as usize;
    let end = span.end as usize;
    if start <= end && end <= source.len() {
        source[start..end].to_string()
    } else {
        String::new()
    }
}

fn build_principal_options_ir(
    ast_kind: crate::ast::types::PrincipalKind,
    server_scope: bool,
    membership: Option<&crate::ast::types::AstPrincipalMembership>,
    options: &crate::ast::types::CreatePrincipalOptions,
    source: &str,
) -> crate::ir::ddl_plan::PrincipalOptionsIr {
    use crate::ast::types::{AstPrincipalEnabledState, AstPrincipalMembershipKind};
    use crate::ir::ddl_plan::{
        PrincipalEnabledStateIr, PrincipalMembershipActionIr, PrincipalMembershipIr,
    };
    crate::ir::ddl_plan::PrincipalOptionsIr {
        principal_kind: project_ast_principal_kind(ast_kind),
        password_literal: options
            .password_literal
            .map(|sp| literal_content_span(sp, source)),
        mysql_host: options
            .mysql_host
            .map(|sp| literal_content_span(sp, source)),
        server_scope,
        membership: membership.map(|m| PrincipalMembershipIr {
            action: match m.kind {
                AstPrincipalMembershipKind::AddMember => PrincipalMembershipActionIr::AddMember,
                AstPrincipalMembershipKind::DropMember => PrincipalMembershipActionIr::DropMember,
            },
            member: literal_content_span(m.member_span, source),
        }),
        enabled_state: options.enabled_state.map(|s| match s {
            AstPrincipalEnabledState::Enable => PrincipalEnabledStateIr::Enable,
            AstPrincipalEnabledState::Disable => PrincipalEnabledStateIr::Disable,
        }),
        role_attributes: options
            .role_attributes
            .iter()
            .map(|a| crate::ir::ddl_plan::RoleAttributeIr {
                kind: project_ast_role_attribute_kind(a.kind),
                negated: a.negated,
            })
            .collect(),
        snowflake_user: options
            .snowflake_user
            .as_ref()
            .map(|s| lower_snowflake_user_options(s, source)),
        mssql_login: options
            .mssql_login
            .as_ref()
            .map(|s| lower_mssql_login_options(s, source)),
    }
}

fn lower_mssql_login_options(
    s: &crate::ast::types::AstMssqlLoginOptions,
    source: &str,
) -> crate::ir::ddl_plan::MssqlLoginOptionsIr {
    // `ON` → true, `OFF` → false; any other value projects to `None`.
    let on_off = |sp: Option<crate::lexer::Span>| {
        sp.and_then(|sp| {
            let v = literal_content_span(sp, source);
            if v.eq_ignore_ascii_case("ON") {
                Some(true)
            } else if v.eq_ignore_ascii_case("OFF") {
                Some(false)
            } else {
                None
            }
        })
    };
    crate::ir::ddl_plan::MssqlLoginOptionsIr {
        check_policy: on_off(s.check_policy),
        check_expiration: on_off(s.check_expiration),
    }
}

fn lower_snowflake_user_options(
    s: &crate::ast::types::AstSnowflakeUserOptions,
    source: &str,
) -> crate::ir::ddl_plan::SnowflakeUserOptionsIr {
    use crate::ast::types::AstSecondaryRolesMode;
    use crate::ir::ddl_plan::SecondaryRolesModeIr;
    let num = |sp: Option<crate::lexer::Span>| {
        sp.and_then(|sp| literal_content_span(sp, source).trim().parse::<u64>().ok())
    };
    let boolean = |sp: Option<crate::lexer::Span>| {
        sp.and_then(|sp| {
            let v = literal_content_span(sp, source);
            if v.eq_ignore_ascii_case("TRUE") {
                Some(true)
            } else if v.eq_ignore_ascii_case("FALSE") {
                Some(false)
            } else {
                None
            }
        })
    };
    let text = |sp: Option<crate::lexer::Span>| {
        sp.map(|sp| literal_content_span(sp, source))
            .filter(|t| !t.is_empty())
    };
    crate::ir::ddl_plan::SnowflakeUserOptionsIr {
        default_role: text(s.default_role),
        default_secondary_roles: s.default_secondary_roles.map(|m| match m {
            AstSecondaryRolesMode::All => SecondaryRolesModeIr::All,
            AstSecondaryRolesMode::None => SecondaryRolesModeIr::None,
        }),
        must_change_password: boolean(s.must_change_password),
        disabled: boolean(s.disabled),
        user_type: text(s.user_type),
        mins_to_bypass_mfa: num(s.mins_to_bypass_mfa),
        days_to_expiry: num(s.days_to_expiry),
        mins_to_unlock: num(s.mins_to_unlock),
        rsa_public_key_set: s.rsa_public_key_set,
        rsa_public_key_2_set: s.rsa_public_key_2_set,
        network_policy: text(s.network_policy),
    }
}

fn project_ast_role_attribute_kind(
    k: crate::ast::types::AstRoleAttributeKind,
) -> crate::ir::ddl_plan::RoleAttributeKindIr {
    use crate::ast::types::AstRoleAttributeKind as A;
    use crate::ir::ddl_plan::RoleAttributeKindIr as I;
    match k {
        A::Superuser => I::Superuser,
        A::CreateDb => I::CreateDb,
        A::CreateRole => I::CreateRole,
        A::Login => I::Login,
        A::Inherit => I::Inherit,
        A::Replication => I::Replication,
        A::BypassRls => I::BypassRls,
    }
}

fn lower_create_principal(s: &crate::ast::types::AstCreatePrincipal, source: &str) -> DdlPlan {
    let object_kind = surface_for_principal_kind(s.principal_kind);
    let mssql_principal_source = s.options.mssql_source.map(project_ast_principal_source);
    let principal_options = Some(build_principal_options_ir(
        s.principal_kind,
        s.server_scope,
        None,
        &s.options,
        source,
    ));
    DdlPlan {
        action: DdlAction::Create,
        object_kind,
        target: target_from(s.name_span, source),
        body: Vec::new(),
        options: DdlOptions {
            if_not_exists: s.if_not_exists,
            or_replace: s.or_replace,
            ..DdlOptions::default()
        },
        node_id: s.node_id,
        span: s.span,
        schema_mutations: Vec::new(),
        mssql_set_option: None,
        mssql_principal_source,
        principal_options,
        domain: None,
        pg_index: None,
        pg_trigger: None,
        pg_trigger_state: None,
        pg_session: None,
        bq_assert: None,
        bq_create_model: None,
        bq_export_data: None,
        bq_options: None,
        show: None,
        synonym: None,
    }
}

fn lower_alter_principal(s: &crate::ast::types::AstAlterPrincipal, source: &str) -> DdlPlan {
    let object_kind = surface_for_principal_kind(s.principal_kind);
    let mssql_principal_source = s.options.mssql_source.map(project_ast_principal_source);
    let principal_options = Some(build_principal_options_ir(
        s.principal_kind,
        s.server_scope,
        s.membership.as_ref(),
        &s.options,
        source,
    ));
    DdlPlan {
        action: DdlAction::Alter,
        object_kind,
        target: target_from(s.name_span, source),
        body: Vec::new(),
        options: DdlOptions {
            if_exists: s.if_exists,
            ..DdlOptions::default()
        },
        node_id: s.node_id,
        span: s.span,
        schema_mutations: Vec::new(),
        mssql_set_option: None,
        mssql_principal_source,
        principal_options,
        domain: None,
        pg_index: None,
        pg_trigger: None,
        pg_trigger_state: None,
        pg_session: None,
        bq_assert: None,
        bq_create_model: None,
        bq_export_data: None,
        bq_options: None,
        show: None,
        synonym: None,
    }
}

fn lower_drop_principal(s: &crate::ast::types::AstDropPrincipal, source: &str) -> DdlPlan {
    let object_kind = surface_for_principal_kind(s.principal_kind);
    let target = s
        .names
        .first()
        .copied()
        .and_then(|sp| target_from(sp, source));
    DdlPlan {
        action: DdlAction::Drop,
        object_kind,
        target,
        body: Vec::new(),
        options: DdlOptions {
            if_exists: s.if_exists,
            ..DdlOptions::default()
        },
        node_id: s.node_id,
        span: s.span,
        schema_mutations: Vec::new(),
        mssql_set_option: None,
        mssql_principal_source: None,
        principal_options: Some(crate::ir::ddl_plan::PrincipalOptionsIr {
            principal_kind: project_ast_principal_kind(s.principal_kind),
            password_literal: None,
            mysql_host: None,
            server_scope: s.server_scope,
            membership: None,
            enabled_state: None,
            role_attributes: Vec::new(),
            snowflake_user: None,
            mssql_login: None,
        }),
        domain: None,
        pg_index: None,
        pg_trigger: None,
        pg_trigger_state: None,
        pg_session: None,
        bq_assert: None,
        bq_create_model: None,
        bq_export_data: None,
        bq_options: None,
        show: None,
        synonym: None,
    }
}

/// Lower each [`AstStmt`] in `stmts` via
/// [`super::lower_dispatch::lower_stmt`] and collect into a
/// `Vec<Rc<StatementPlan>>`. Opaque / parse-recovery arms (the
/// 6 [`AstStmt`] variants for which `lower_stmt` returns `Err`)
/// drop out — `DdlPlan::body` carries only structurally
/// representable inner statements.
///
/// When [`IrLowerInputs::flatten_body_into`] is `Some`, each inner
/// statement is *also* handed to the sink as a first-class statement.
/// The DDL substrate doesn't aggregate body facts onto the parent; the
/// inner statements stand on their own alongside top-level statements.
/// Recursion is natural — an inner DDL with its own body lowers through
/// this same path and emits its own inner statements first.
fn lower_body(stmts: &[AstStmt], inputs: &IrLowerInputs) -> Vec<Rc<StatementPlan>> {
    stmts
        .iter()
        .filter_map(|s| match super::lower_dispatch::lower_stmt(s, inputs) {
            Ok(LoweredStatement::Rel {
                plan,
                bindings,
                catalog_ctx,
                facts,
                policy_facts,
            }) => {
                if let Some(sink) = inputs.flatten_body_into {
                    let derived = super::derived_facts::derive_facts_from_plan(
                        inputs.source,
                        &plan,
                        &bindings,
                        inputs.func_catalog,
                        Some(&catalog_ctx as &dyn crate::ir::catalog_context::CatalogContext),
                        inputs.reasoning,
                    );
                    sink.rel(
                        &plan,
                        &bindings,
                        &catalog_ctx,
                        &facts,
                        derived,
                        policy_facts.as_ref(),
                    );
                }
                Some(Rc::new(StatementPlan::Rel(Rc::new(plan))))
            }
            Ok(LoweredStatement::Ddl {
                plan,
                privilege_plan,
            }) => {
                if let Some(sink) = inputs.flatten_body_into {
                    sink.ddl(&plan, privilege_plan.as_ref());
                }
                Some(Rc::new(StatementPlan::Ddl(Rc::new(plan))))
            }
            Err(_) => None,
        })
        .collect()
}

/// Collect `tables_read` references from every `Box<AstStmt>`
/// subquery reachable from a BigQuery `ASSERT` predicate expression.
///
/// Walks the [`crate::ast::types::AstExpr`] tree closed-enum
/// exhaustively, capturing each `subquery: Box<AstStmt>` carrier
/// (`InSubquery` / `ExistsSubquery` / `QuantifiedSubquery` /
/// `ScalarSubquery` / `SubqueryArg`). Each captured subquery is
/// lowered to a [`super::plan::RelPlan`] under the same lowering
/// context (`inputs`) so deeper subqueries nested inside a captured
/// subquery's own body surface transitively via the IR's
/// [`super::derive_facts_from_plan`] walker — which descends into
/// `ScalarExpr::ScalarSubquery` / `Exists` / `QuantifiedCmp::Subquery`
/// branches when projecting `tables_read`. Empty `Vec` when the
/// predicate carries no subqueries; the resulting BqAssert
/// `StatementFacts` then projects `query = None`.
///
/// Subqueries that fail to lower under permissive strictness are
/// silently dropped — the wrapping ASSERT remains analyzable; its
/// `inner_reads_table` projection is best-effort and matches the
/// permissive lowering contract used elsewhere.
fn collect_bq_assert_inner_reads(
    expr: &crate::ast::types::AstExpr,
    inputs: &IrLowerInputs,
) -> Vec<crate::context::node_metadata::TableRef> {
    let mut subqueries: Vec<&AstStmt> = Vec::new();
    collect_ast_expr_subqueries(expr, &mut subqueries);

    let mut reads: Vec<crate::context::node_metadata::TableRef> = Vec::new();
    for inner in subqueries {
        let lowered = super::lower::lower_query_with_catalog_and_session(
            inner,
            inputs.source,
            inputs.strict,
            inputs.func_catalog,
            inputs.session,
        );
        let plan = match lowered {
            Ok(plan) => plan,
            Err(_) => continue,
        };
        let bindings = crate::ir::column::BindingTable::default();
        let derived = super::derived_facts::derive_facts_from_plan(
            inputs.source,
            &plan,
            &bindings,
            inputs.func_catalog,
            None,
            inputs.reasoning,
        );
        for t in derived.tables_read {
            if !reads.contains(&t) {
                reads.push(t);
            }
        }
    }
    reads
}

/// Closed-enum exhaustive walker over [`crate::ast::types::AstExpr`]
/// that pushes every `Box<AstStmt>` subquery reference onto `out`.
///
/// Captures `InSubquery` / `ExistsSubquery` / `QuantifiedSubquery` /
/// `ScalarSubquery` / `SubqueryArg` (the five carriers whose
/// `subquery` field is a [`AstStmt`]). For every other variant the
/// walker recurses into the variant's `Box<AstExpr>` / `Vec<AstExpr>`
/// / nested-arg children so subqueries embedded deep inside a
/// boolean / arithmetic / Case / function-call / array tree still
/// surface. Listed exhaustively so adding a new `AstExpr` variant
/// breaks the build and forces a deliberate recurse-or-leaf decision.
fn collect_ast_expr_subqueries<'a>(
    expr: &'a crate::ast::types::AstExpr,
    out: &mut Vec<&'a AstStmt>,
) {
    use crate::ast::types::AstExpr;
    match expr {
        AstExpr::ScalarSubquery { subquery, .. }
        | AstExpr::SubqueryArg { subquery, .. }
        | AstExpr::ExistsSubquery { subquery, .. } => {
            out.push(subquery);
        }
        AstExpr::InSubquery {
            expr: inner,
            subquery,
            ..
        } => {
            collect_ast_expr_subqueries(inner, out);
            out.push(subquery);
        }
        AstExpr::QuantifiedSubquery { left, subquery, .. } => {
            collect_ast_expr_subqueries(left, out);
            out.push(subquery);
        }
        AstExpr::Parenthesized { expr: inner, .. }
        | AstExpr::Spread { expr: inner, .. }
        | AstExpr::IsNull { expr: inner, .. }
        | AstExpr::Cast { expr: inner, .. }
        | AstExpr::TryCast { expr: inner, .. }
        | AstExpr::SafeCast { expr: inner, .. }
        | AstExpr::TypeCast { expr: inner, .. }
        | AstExpr::Extract { expr: inner, .. }
        | AstExpr::Collate { expr: inner, .. }
        | AstExpr::Prior { expr: inner, .. }
        | AstExpr::ExplSnowIdent { arg: inner, .. } => {
            collect_ast_expr_subqueries(inner, out);
        }
        AstExpr::BinaryOp { left, right, .. } | AstExpr::IsDistinctFrom { left, right, .. } => {
            collect_ast_expr_subqueries(left, out);
            collect_ast_expr_subqueries(right, out);
        }
        AstExpr::MatchAgainst {
            match_call, search, ..
        } => {
            collect_ast_expr_subqueries(match_call, out);
            collect_ast_expr_subqueries(search, out);
        }
        AstExpr::LogicalChain { operands, .. } => {
            for operand in operands {
                collect_ast_expr_subqueries(operand, out);
            }
        }
        AstExpr::Case {
            operand,
            whens,
            else_expr,
            ..
        } => {
            if let Some(op) = operand {
                collect_ast_expr_subqueries(op, out);
            }
            for branch in whens {
                collect_ast_expr_subqueries(&branch.cond, out);
                collect_ast_expr_subqueries(&branch.result, out);
            }
            if let Some(e) = else_expr {
                collect_ast_expr_subqueries(e, out);
            }
        }
        AstExpr::InList {
            expr: inner, list, ..
        } => {
            collect_ast_expr_subqueries(inner, out);
            for item in list {
                collect_ast_expr_subqueries(item, out);
            }
        }
        AstExpr::InListOpaque { expr: inner, .. } => {
            collect_ast_expr_subqueries(inner, out);
        }
        AstExpr::Between {
            expr: inner,
            lower,
            upper,
            ..
        } => {
            collect_ast_expr_subqueries(inner, out);
            collect_ast_expr_subqueries(lower, out);
            collect_ast_expr_subqueries(upper, out);
        }
        AstExpr::Like {
            expr: inner,
            pattern,
            ..
        }
        | AstExpr::SimilarTo {
            expr: inner,
            pattern,
            ..
        } => {
            collect_ast_expr_subqueries(inner, out);
            collect_ast_expr_subqueries(pattern, out);
        }
        AstExpr::Position {
            needle, haystack, ..
        } => {
            collect_ast_expr_subqueries(needle, out);
            collect_ast_expr_subqueries(haystack, out);
        }
        AstExpr::Trim { chars, source, .. } => {
            if let Some(c) = chars {
                collect_ast_expr_subqueries(c, out);
            }
            collect_ast_expr_subqueries(source, out);
        }
        AstExpr::Substring {
            source,
            from,
            for_len,
            ..
        } => {
            collect_ast_expr_subqueries(source, out);
            if let Some(f) = from {
                collect_ast_expr_subqueries(f, out);
            }
            if let Some(f) = for_len {
                collect_ast_expr_subqueries(f, out);
            }
        }
        AstExpr::FunctionCall { args, .. } => {
            for arg in args {
                match arg.as_ref() {
                    crate::ast::AstFunctionArg::Positional(e) => {
                        collect_ast_expr_subqueries(e, out);
                    }
                    crate::ast::AstFunctionArg::Named { value, .. } => {
                        collect_ast_expr_subqueries(value, out);
                    }
                    crate::ast::AstFunctionArg::Lambda { body, .. } => {
                        collect_ast_expr_subqueries(body, out);
                    }
                    crate::ast::AstFunctionArg::AliasedArg { value, .. } => {
                        collect_ast_expr_subqueries(value, out);
                    }
                    crate::ast::AstFunctionArg::BulkArg { value, .. } => {
                        collect_ast_expr_subqueries(value, out);
                    }
                }
            }
        }
        AstExpr::WindowFn { args, filter, .. } => {
            for arg in args {
                match arg.as_ref() {
                    crate::ast::AstFunctionArg::Positional(e) => {
                        collect_ast_expr_subqueries(e, out);
                    }
                    crate::ast::AstFunctionArg::Named { value, .. } => {
                        collect_ast_expr_subqueries(value, out);
                    }
                    crate::ast::AstFunctionArg::Lambda { body, .. } => {
                        collect_ast_expr_subqueries(body, out);
                    }
                    crate::ast::AstFunctionArg::AliasedArg { value, .. } => {
                        collect_ast_expr_subqueries(value, out);
                    }
                    crate::ast::AstFunctionArg::BulkArg { value, .. } => {
                        collect_ast_expr_subqueries(value, out);
                    }
                }
            }
            if let Some(f) = filter {
                collect_ast_expr_subqueries(&f.expr, out);
            }
        }
        AstExpr::WindowExpr { base, .. } => {
            collect_ast_expr_subqueries(base, out);
        }
        AstExpr::TvfWithSchema { func_call, .. } => {
            collect_ast_expr_subqueries(func_call, out);
        }
        AstExpr::Array { elements, .. } => {
            for elem in elements {
                collect_ast_expr_subqueries(elem, out);
            }
        }
        AstExpr::Object { entries, .. } => {
            for (key, value) in entries {
                collect_ast_expr_subqueries(key, out);
                collect_ast_expr_subqueries(value, out);
            }
        }
        AstExpr::RowConstructor { elements, .. } => {
            for elem in elements {
                collect_ast_expr_subqueries(elem, out);
            }
        }
        AstExpr::ArraySubscript { base, index, .. } => {
            collect_ast_expr_subqueries(base, out);
            collect_ast_expr_subqueries(index, out);
        }
        AstExpr::ObjectFieldColon { base, .. }
        | AstExpr::ObjectFieldDot { base, .. }
        | AstExpr::QualifiedStarFromExpr { base, .. } => {
            collect_ast_expr_subqueries(base, out);
        }
        AstExpr::ObjectFieldBracket { base, field, .. } => {
            collect_ast_expr_subqueries(base, out);
            collect_ast_expr_subqueries(field, out);
        }
        AstExpr::MethodCall { base, args, .. } => {
            collect_ast_expr_subqueries(base, out);
            for arg in args {
                collect_ast_expr_subqueries(arg, out);
            }
        }
        AstExpr::AtTimeZone {
            expr: inner, zone, ..
        } => {
            collect_ast_expr_subqueries(inner, out);
            if let Some(z) = zone {
                collect_ast_expr_subqueries(z, out);
            }
        }
        // Leaf expressions — no `Box<AstExpr>` / `Box<AstStmt>`
        // children that participate in SQL-level subquery semantics.
        AstExpr::Ident { .. }
        | AstExpr::Literal { .. }
        | AstExpr::Placeholder { .. }
        | AstExpr::JinjaPlaceholder { .. }
        | AstExpr::JinjaConditional { .. }
        | AstExpr::PositionRef { .. }
        | AstExpr::ScriptingVarRef { .. }
        | AstExpr::QualifiedStar { .. }
        | AstExpr::UnqualifiedStar { .. }
        | AstExpr::DbtRef { .. }
        | AstExpr::DbtSource { .. }
        | AstExpr::DbtVar { .. }
        | AstExpr::DbtConfig { .. }
        | AstExpr::DbtThis { .. }
        | AstExpr::TypedStringLiteral { .. }
        | AstExpr::Error { .. } => {}
    }
}

/// Build a [`DdlTarget`] from a name span. Returns `None` when the
/// span is empty or out-of-bounds for `source`, or when the span
/// text contains no identifier components.
/// Extract the credential-bearing options surface from a list of
/// source spans on a BQ DDL statement. Tokenizes each span and walks
/// the resulting tokens for two structural shapes the BQ-* leak rules
/// compose against:
///
/// 1. `<IDENT-or-KEYWORD> '=' '<STRING_LITERAL>'` pairs — captured as
///    [`crate::ir::ddl_plan::IrBqOptionPair`] entries on `options`.
///    Drives slot-name leak rules (BQ-*-PWD-LEAK / BQ-*-APIKEY-LEAK).
/// 2. Every `STRING_LITERAL` token — captured as raw string-literal
///    text on `all_literal_values`. Drives content-pattern leak rules
///    (BQ-*-AWS-LEAK / BQ-*-CONNSTR-LEAK).
///
/// Both vectors are populated independently — the same literal can
/// appear in both (as the value of a key=value pair AND as a content
/// candidate). Returns the populated detail unconditionally; an empty
/// `IrBqOptionsDetail` is the right semantic projection for a BQ
/// statement that carries no credential surface (rules `exists: …`
/// against the empty vecs naturally don't match).
fn extract_bq_options_from_spans(
    spans: &[Span],
    source: &str,
) -> crate::ir::ddl_plan::IrBqOptionsDetail {
    use crate::lexer::{tokenize, LiteralKind, Operator, Token, TokenKind};

    let mut detail = crate::ir::ddl_plan::IrBqOptionsDetail::default();

    let is_trivia = |k: &TokenKind| {
        matches!(
            k,
            TokenKind::LineComment | TokenKind::BlockComment | TokenKind::JinjaComment
        )
    };

    let next_non_trivia = |tokens: &[Token], mut idx: usize| -> Option<usize> {
        idx += 1;
        while idx < tokens.len() {
            if !is_trivia(&tokens[idx].kind) {
                return Some(idx);
            }
            idx += 1;
        }
        None
    };

    for sp in spans {
        let start = sp.start as usize;
        let end = (sp.end as usize).min(source.len());
        if start >= end {
            continue;
        }
        let span_text = &source[start..end];
        let tokens = tokenize(span_text).tokens;
        let token_text = |tok: &Token| -> Option<&str> {
            let s = tok.span.start as usize;
            let e = tok.span.end as usize;
            if s >= e || e > span_text.len() {
                None
            } else {
                Some(&span_text[s..e])
            }
        };
        let strip_string_literal = |raw: &str| -> Option<String> {
            let raw = raw.trim();
            if raw.len() >= 2 && raw.starts_with('\'') && raw.ends_with('\'') {
                Some(raw[1..raw.len() - 1].replace("''", "'"))
            } else if raw.len() >= 2 && raw.starts_with('"') && raw.ends_with('"') {
                Some(raw[1..raw.len() - 1].to_string())
            } else {
                None
            }
        };
        fn strip_ident_quotes(raw: &str) -> &str {
            let raw = raw.trim();
            let quoted_by = |q: char| raw.starts_with(q) && raw.ends_with(q);
            if raw.len() >= 2 && (quoted_by('"') || quoted_by('`')) {
                &raw[1..raw.len() - 1]
            } else {
                raw
            }
        }

        for idx in 0..tokens.len() {
            let tok = &tokens[idx];
            if is_trivia(&tok.kind) {
                continue;
            }
            if matches!(tok.kind, TokenKind::Literal(LiteralKind::String)) {
                if let Some(raw) = token_text(tok) {
                    if let Some(value) = strip_string_literal(raw) {
                        detail.all_literal_values.push(value);
                    }
                }
            }
            let key_text = match tok.kind {
                TokenKind::Identifier { .. } | TokenKind::Keyword(_) => token_text(tok),
                _ => None,
            };
            let Some(key_raw) = key_text.map(strip_ident_quotes) else {
                continue;
            };
            let Some(eq_idx) = next_non_trivia(&tokens, idx) else {
                continue;
            };
            if !matches!(tokens[eq_idx].kind, TokenKind::Operator(Operator::Eq)) {
                continue;
            }
            let Some(val_idx) = next_non_trivia(&tokens, eq_idx) else {
                continue;
            };
            if !matches!(
                tokens[val_idx].kind,
                TokenKind::Literal(LiteralKind::String)
            ) {
                continue;
            }
            let Some(value_raw) = token_text(&tokens[val_idx]) else {
                continue;
            };
            let Some(value_literal) = strip_string_literal(value_raw) else {
                continue;
            };
            detail.options.push(crate::ir::ddl_plan::IrBqOptionPair {
                key_raw: key_raw.to_string(),
                value_literal,
            });
        }
    }

    detail
}

/// Extract the structural filter clauses (WHERE / HAVING / QUALIFY)
/// of the outermost SELECT inside a query-bearing BigQuery body
/// (`EXPORT DATA AS …` / `CREATE MODEL AS …`). Returns `None` for
/// set-ops, VALUES queries, or any non-SELECT body — an accepted
/// gap; widen additively by promoting `IrBqQueryBody` to a
/// leg-indexed shape when set-op rules need it.
fn outermost_select_body(
    stmt: &AstStmt,
    source: &str,
) -> Option<crate::ir::ddl_plan::IrBqQueryBody> {
    let select = match stmt {
        AstStmt::Select(s) => s,
        _ => return None,
    };
    let to_clause = |c: &Option<Box<crate::ast::ConditionClause>>| {
        c.as_ref().and_then(|cc| {
            source_slice(source, cc.expr.span()).map(|text| crate::ir::ddl_plan::IrBqFilterClause {
                text: text.to_string(),
            })
        })
    };
    Some(crate::ir::ddl_plan::IrBqQueryBody {
        where_clause: to_clause(&select.where_clause),
        having_clause: to_clause(&select.having),
        qualify_clause: to_clause(&select.qualify),
    })
}

/// Slice the source text covered by `span`, returning `None` if the
/// span is empty or out of bounds. Used to lift typed content (the
/// raw text of an `AS '<description>'` literal, a `WITH CONNECTION
/// conn_id` identifier, …) onto IR detail carriers at lowering time.
fn source_slice(source: &str, span: Span) -> Option<&str> {
    let start = span.start as usize;
    let end = span.end as usize;
    if start >= end || end > source.len() {
        return None;
    }
    Some(&source[start..end])
}

/// Case-insensitive keyword match against a source span. Used by the
/// generic `AstStmt::Drop` lowering to discriminate `CASCADE` vs
/// `RESTRICT` from the single `cascade_restrict_span`.
fn drop_keyword_matches(source: &str, span: Span, keyword: &str) -> bool {
    match source_slice(source, span) {
        Some(text) => text.trim().eq_ignore_ascii_case(keyword),
        None => false,
    }
}

pub(crate) fn target_from(span: Span, source: &str) -> Option<DdlTarget> {
    let start = span.start as usize;
    let end = span.end as usize;
    if start >= end || end > source.len() {
        return None;
    }
    let raw = &source[start..end];
    let parts = split_qualified(raw);
    let len = parts.len();
    if len == 0 {
        return None;
    }
    let name = parts[len - 1].clone();
    let schema = if len >= 2 {
        Some(parts[len - 2].clone())
    } else {
        None
    };
    let db = if len >= 3 {
        Some(parts[len - 3].clone())
    } else {
        None
    };
    Some(DdlTarget {
        name,
        schema,
        db,
        span,
    })
}

#[inline]
fn optional_target_from(span: Option<Span>, source: &str) -> Option<DdlTarget> {
    target_from(span?, source)
}

/// Walk an `AstAlterTable.actions` list and collect the per-element
/// typed identity for the three ALTER actions that mutate schema in
/// a cross-statement-reference-invalidating way: `RenameTo`,
/// `AddColumn`, `DropColumn`. Every other variant is enumerated
/// explicitly with an empty arm to satisfy closed-enum
/// discipline.
fn collect_alter_table_schema_mutations(
    s: &crate::ast::AstAlterTable,
    source: &str,
) -> Vec<DdlSchemaMutation> {
    use crate::ast::AstAlterTableActionKind as K;
    let mut out = Vec::new();
    for action in &s.actions {
        match &action.kind {
            K::RenameTo { new_name_span, .. } => {
                if let Some(new_target) = target_from(*new_name_span, source) {
                    out.push(DdlSchemaMutation::RenameTo {
                        new_target,
                        source: None,
                    });
                }
            }
            K::AddColumn { columns, .. } => {
                for col_def in columns {
                    let Some(name_span) = col_def.name_span else {
                        continue;
                    };
                    let Some(text) = source.get(name_span.start as usize..name_span.end as usize)
                    else {
                        continue;
                    };
                    if text.trim().is_empty() {
                        continue;
                    }
                    out.push(DdlSchemaMutation::AddColumn {
                        column_name: text.to_string(),
                    });
                }
            }
            K::DropColumn {
                columns,
                columns_span,
                ..
            } => {
                if !columns.is_empty() {
                    for col_span in columns {
                        let Some(text) = source.get(col_span.start as usize..col_span.end as usize)
                        else {
                            continue;
                        };
                        if text.trim().is_empty() {
                            continue;
                        }
                        out.push(DdlSchemaMutation::DropColumn {
                            column_name: text.to_string(),
                        });
                    }
                } else {
                    // Parser fallback: comma-separated names packed
                    // into a single span. Split at comma boundaries.
                    let Some(text) =
                        source.get(columns_span.start as usize..columns_span.end as usize)
                    else {
                        continue;
                    };
                    for part in text.split(',') {
                        let name = part.trim();
                        if name.is_empty() {
                            continue;
                        }
                        out.push(DdlSchemaMutation::DropColumn {
                            column_name: name.to_string(),
                        });
                    }
                }
            }
            // None of the following ALTER actions invalidate cross-
            // statement table or column references for the Q-FLOW-*
            // family. Enumerated explicitly — when a new
            // `AstAlterTableActionKind` variant is added that DOES
            // affect schema identity, it lands here with a compile
            // error.
            K::RenameColumn { .. }
            | K::SwapWith { .. }
            | K::AlterColumn { .. }
            | K::AddConstraint { .. }
            | K::DropConstraint { .. }
            | K::ClusterBy { .. }
            | K::DropClusteringKey { .. }
            | K::SuspendRecluster { .. }
            | K::ResumeRecluster { .. }
            | K::Set { .. }
            | K::Unset { .. }
            | K::AddRowAccessPolicy(_)
            | K::DropRowAccessPolicy { .. }
            | K::DropAllRowAccessPolicies { .. }
            | K::SetRowFilter { .. }
            | K::DropRowFilter { .. }
            | K::SetAggregationPolicy { .. }
            | K::UnsetAggregationPolicy { .. }
            | K::SetJoinPolicy { .. }
            | K::UnsetJoinPolicy { .. }
            | K::SetColumnMaskingPolicy(_)
            | K::UnsetColumnMaskingPolicy { .. }
            | K::SetColumnMask { .. }
            | K::DropColumnMask { .. }
            | K::SetColumnProjectionPolicy(_)
            | K::UnsetColumnProjectionPolicy { .. }
            | K::SetTag { .. }
            | K::UnsetTag { .. }
            | K::SetColumnTag { .. }
            | K::UnsetColumnTag { .. }
            | K::AddSearchOptimization { .. }
            | K::DropSearchOptimization { .. }
            | K::SetDataMetricSchedule { .. }
            | K::UnsetDataMetricSchedule { .. }
            | K::AddDataMetricFunction { .. }
            | K::DropDataMetricFunction { .. }
            | K::AddStorageLifecyclePolicy { .. }
            | K::DropStorageLifecyclePolicy { .. }
            | K::SetOptions { .. }
            | K::SetDefaultCollate { .. }
            | K::DropPrimaryKey { .. }
            | K::AlterColumnSetOptions { .. }
            | K::AlterColumnDropNotNull { .. }
            | K::AlterColumnSetDataType { .. }
            | K::AlterColumnSetDefault { .. }
            | K::AlterColumnDropDefault { .. }
            | K::SetTblProperties { .. }
            | K::UnsetTblProperties { .. }
            | K::RowLevelSecurity { .. }
            | K::GovernanceSpan { .. }
            | K::Unknown { .. } => {}
        }
    }
    out
}

/// Classify a generic `AstStmt::Drop` by reading the `object_type_span`
/// keyword. Maps `TABLE`/`VIEW`/`SCHEMA`/etc. to the corresponding
/// [`ObjectKind`] variant; falls back to `ObjectKind::Table`
/// when the span is absent or the text doesn't match a known kind.
fn classify_drop_object(s: &crate::ast::AstDrop, source: &str) -> ObjectKind {
    let Some(span) = s.object_type_span else {
        return ObjectKind::Table;
    };
    let Some(text) = source.get(span.start as usize..span.end as usize) else {
        return ObjectKind::Table;
    };
    let normalized: String = text
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_uppercase();
    match normalized.as_str() {
        "TABLE" => ObjectKind::Table,
        "VIEW" => ObjectKind::View,
        "MATERIALIZED VIEW" => ObjectKind::MaterializedView,
        "EXTERNAL TABLE" => ObjectKind::ExternalTable,
        "SCHEMA" => ObjectKind::Schema,
        "DATABASE" => ObjectKind::Database,
        "SEQUENCE" => ObjectKind::Sequence,
        "ROLE" => ObjectKind::Role,
        "USER" => ObjectKind::User,
        "TAG" => ObjectKind::Tag,
        "FILE FORMAT" => ObjectKind::FileFormat,
        "FUNCTION" => ObjectKind::Function,
        "PROCEDURE" => ObjectKind::Procedure,
        "TRIGGER" => ObjectKind::Trigger,
        "INDEX" => ObjectKind::Index,
        "TYPE" => ObjectKind::PgType,
        "DOMAIN" => ObjectKind::PgDomain,
        "EXTENSION" => ObjectKind::PgExtension,
        "PUBLICATION" => ObjectKind::PgPublication,
        "SUBSCRIPTION" => ObjectKind::PgSubscription,
        "RULE" => ObjectKind::PgRule,
        "TABLESPACE" => ObjectKind::Generic,
        // Unknown / Snowflake-specific etc. — fall back to `Table`
        // for back-compat with the previous default.
        _ => ObjectKind::Table,
    }
}

/// Split a `db.schema.name` string into normalized identifier
/// components. Honors the active dialect's quoting style by
/// delegating to [`normalize_identifier`] for each component.
/// Whitespace inside the qualified name is skipped at the top
/// level; it is preserved inside quoted segments.
fn split_qualified(s: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut quote_close: Option<char> = None;

    for ch in s.chars() {
        match quote_close {
            Some(close) => {
                current.push(ch);
                if ch == close {
                    quote_close = None;
                }
            }
            None => match ch {
                '"' => {
                    current.push(ch);
                    quote_close = Some('"');
                }
                '`' => {
                    current.push(ch);
                    quote_close = Some('`');
                }
                '[' => {
                    current.push(ch);
                    quote_close = Some(']');
                }
                '.' => {
                    let trimmed = current.trim();
                    if !trimmed.is_empty() {
                        parts.push(normalize_identifier(trimmed));
                    }
                    current.clear();
                }
                c if c.is_whitespace() => {
                    // Skip whitespace at the top level so spans that
                    // include trailing trivia still parse cleanly.
                }
                _ => current.push(ch),
            },
        }
    }

    let trimmed = current.trim();
    if !trimmed.is_empty() {
        parts.push(normalize_identifier(trimmed));
    }
    parts
}
