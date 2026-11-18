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
use crate::context::node_metadata::IdentKey;
use crate::facts::identity::ObjectKind;
use crate::ir::normalize::NameKind;
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
///
/// The target names its object with each part as written, quotes and
/// case kept; a name is compared through the identifiers that fold it
/// (`IdentKey`, `TableKey`), which keep a quoted part's case where the
/// dialect makes it count.
pub fn lower_ddl_stmt(stmt: &AstStmt, inputs: &IrLowerInputs) -> Option<DdlPlan> {
    lower_ddl_plan(stmt, inputs)
}

/// Whether `plan` drops, replaces, renames or swaps a schema or a
/// database, and with it the relations it holds.
pub(crate) fn changes_a_namespace(plan: &DdlPlan) -> bool {
    if !matches!(plan.object_kind, ObjectKind::Schema | ObjectKind::Database) {
        return false;
    }
    match plan.action {
        DdlAction::Drop => true,
        DdlAction::Create => plan.options.or_replace,
        DdlAction::Alter | DdlAction::Rename => plan.schema_mutations.iter().any(|mutation| {
            matches!(
                mutation,
                DdlSchemaMutation::RenameTo { .. } | DdlSchemaMutation::SwapWith { .. }
            )
        }),
        DdlAction::BulkLoad
        | DdlAction::Truncate
        | DdlAction::Comment
        | DdlAction::Refresh
        | DdlAction::Grant
        | DdlAction::Revoke
        | DdlAction::Execute
        | DdlAction::Configure
        | DdlAction::ControlFlow
        | DdlAction::Transaction
        | DdlAction::Backup
        | DdlAction::Restore => false,
    }
}

/// Whether the target of `plan`, lowered from `stmt`, names a relation: a
/// table, a view, a materialized, dynamic or external table, the table a
/// load writes, or a BigQuery snapshot table.
pub(crate) fn target_names_a_relation(stmt: &AstStmt, plan: &DdlPlan) -> bool {
    match plan.object_kind {
        ObjectKind::Table
        | ObjectKind::View
        | ObjectKind::MaterializedView
        | ObjectKind::DynamicTable
        | ObjectKind::ExternalTable => true,
        ObjectKind::Stage | ObjectKind::Generic => match plan.action {
            DdlAction::BulkLoad => true,
            DdlAction::Create => matches!(stmt, AstStmt::BqCreateSnapshotTable(_)),
            DdlAction::Alter
            | DdlAction::Drop
            | DdlAction::Rename
            | DdlAction::Truncate
            | DdlAction::Comment
            | DdlAction::Refresh
            | DdlAction::Grant
            | DdlAction::Revoke
            | DdlAction::Execute
            | DdlAction::Configure
            | DdlAction::ControlFlow
            | DdlAction::Transaction
            | DdlAction::Backup
            | DdlAction::Restore => false,
        },
        ObjectKind::Schema
        | ObjectKind::Database
        | ObjectKind::Tag
        | ObjectKind::Procedure
        | ObjectKind::Function
        | ObjectKind::Trigger
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
        | ObjectKind::Synonym => false,
    }
}

/// The kind of object a `DESCRIBE` of `kind` describes; `Generic` where no
/// public kind names it.
fn described_object_kind(kind: &crate::ast::AstDescribeKind) -> ObjectKind {
    use crate::ast::AstDescribeKind as D;
    match kind {
        D::Table | D::EventTable | D::IcebergTable | D::Detail | D::SearchOptimization => {
            ObjectKind::Table
        }
        D::View => ObjectKind::View,
        D::MaterializedView => ObjectKind::MaterializedView,
        D::DynamicTable => ObjectKind::DynamicTable,
        D::ExternalTable => ObjectKind::ExternalTable,
        D::Function => ObjectKind::Function,
        D::Procedure => ObjectKind::Procedure,
        D::MaskingPolicy => ObjectKind::MaskingPolicy,
        D::RowAccessPolicy => ObjectKind::RowAccessPolicy,
        D::AggregationPolicy => ObjectKind::AggregationPolicy,
        D::ProjectionPolicy => ObjectKind::ProjectionPolicy,
        D::JoinPolicy => ObjectKind::JoinPolicy,
        D::NetworkPolicy => ObjectKind::NetworkPolicy,
        D::PasswordPolicy => ObjectKind::PasswordPolicy,
        D::SessionPolicy => ObjectKind::SessionPolicy,
        D::AuthenticationPolicy => ObjectKind::AuthenticationPolicy,
        D::NetworkRule => ObjectKind::NetworkRule,
        D::Stage => ObjectKind::Stage,
        D::FileFormat => ObjectKind::FileFormat,
        D::Stream => ObjectKind::Stream,
        D::Pipe => ObjectKind::Pipe,
        D::Task => ObjectKind::Task,
        D::Alert => ObjectKind::Alert,
        D::Sequence => ObjectKind::Sequence,
        D::Schema => ObjectKind::Schema,
        D::Database => ObjectKind::Database,
        D::Catalog => ObjectKind::Catalog,
        D::Warehouse => ObjectKind::Warehouse,
        D::User => ObjectKind::User,
        D::Share => ObjectKind::Share,
        D::Secret => ObjectKind::Secret,
        D::Credential => ObjectKind::StorageCredential,
        D::ExternalLocation => ObjectKind::ExternalLocation,
        D::Volume => ObjectKind::Volume,
        D::PackagesPolicy
        | D::Integration
        | D::Streamlit
        | D::Service
        | D::Connection
        | D::Provider
        | D::Recipient
        | D::Result
        | D::Transaction
        | D::Query
        | D::Other => ObjectKind::Generic,
    }
}

fn lower_ddl_plan(stmt: &AstStmt, inputs: &IrLowerInputs) -> Option<DdlPlan> {
    let source = inputs.source;
    match stmt {
        // ---- Query-bearing — lower via lower_query, not here. ----
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
        | AstStmt::PsqlGexec(_) => None,

        // ---- Opaque / Error / Jinja / batch separator — no DDL. ----
        AstStmt::OpaqueContent { .. }
        | AstStmt::ClauseFragment { .. }
        | AstStmt::JinjaPlaceholder { .. }
        | AstStmt::JinjaConditionalStmt(_)
        | AstStmt::Error { .. }
        | AstStmt::GoBatchSeparator { .. }
        | AstStmt::SqlcmdCommand { .. } => None,

        // ---- CREATE — Snowflake/core ----
        AstStmt::CreateTable(s) => Some(plan(
            DdlAction::Create,
            ObjectKind::Table,
            target_from_name(&s.name, source),
            DdlOptions {
                or_replace: s.or_replace_span.is_some(),
                if_not_exists: s.if_not_exists_span.is_some(),
                temporary: s.persistence == Some(crate::ast::AstTablePersistence::Temporary),
                transient: s.persistence == Some(crate::ast::AstTablePersistence::Transient),
                ..DdlOptions::default()
            },
            s.node_id,
            s.span,
        )),
        AstStmt::CreateView(s) => Some(plan(
            DdlAction::Create,
            ObjectKind::View,
            target_from_name(&s.name, source),
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
            target_from_name(&s.name, source),
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
                Some(extract_bq_options_from_spans(
                    &credential_spans,
                    source,
                    inputs.placeholder_spans,
                ))
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
                truncated: Vec::new(),
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
                Some(extract_bq_options_from_spans(
                    &credential_spans,
                    source,
                    inputs.placeholder_spans,
                ))
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
                truncated: Vec::new(),
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
                ast::AstAlterAccountActionKind::SetPolicy { .. }
                | ast::AstAlterAccountActionKind::Set { .. }
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
            target: target_from_name(&s.name, source),
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
            truncated: Vec::new(),
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
            truncated: Vec::new(),
        }),
        AstStmt::AlterView(s) => Some(DdlPlan {
            schema_mutations: alter_view_schema_mutations(&s.action.kind, source),
            ..simple(
                DdlAction::Alter,
                ObjectKind::View,
                target_from(s.name_span, source),
                s.node_id,
                s.span,
            )
        }),
        AstStmt::AlterMaterializedView(s) => Some(DdlPlan {
            schema_mutations: alter_materialized_view_schema_mutations(&s.action.kind, source),
            ..simple(
                DdlAction::Alter,
                ObjectKind::MaterializedView,
                target_from(s.name_span, source),
                s.node_id,
                s.span,
            )
        }),
        AstStmt::AlterDynamicTable(s) => Some(DdlPlan {
            schema_mutations: alter_dynamic_table_schema_mutations(&s.action.kind),
            ..simple(
                DdlAction::Alter,
                ObjectKind::DynamicTable,
                target_from(s.name_span, source),
                s.node_id,
                s.span,
            )
        }),
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
        AstStmt::AlterDatabase(s) => Some(DdlPlan {
            schema_mutations: alter_database_schema_mutations(&s.action.kind),
            ..simple(
                DdlAction::Alter,
                ObjectKind::Database,
                target_from(s.name_span, source),
                s.node_id,
                s.span,
            )
        }),
        AstStmt::AlterSchema(s) => Some(DdlPlan {
            schema_mutations: alter_schema_schema_mutations(&s.action.kind),
            ..simple(
                DdlAction::Alter,
                ObjectKind::Schema,
                target_from(s.name_span, source),
                s.node_id,
                s.span,
            )
        }),

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
                s.target_name
                    .as_ref()
                    .and_then(|name| target_from_name(name, source)),
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
        // The stage the command names; a user or table stage keeps its text.
        AstStmt::StageFileCommand(s) => Some(simple(
            DdlAction::Configure,
            ObjectKind::Generic,
            s.stage
                .as_ref()
                .and_then(|stage| target_from_name(&stage.name, source))
                .or_else(|| optional_target_from(s.stage_ref_span, source)),
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
        AstStmt::Truncate(s) => Some(DdlPlan {
            truncated: s
                .tables
                .iter()
                .map(|table| {
                    Some(super::ddl_plan::TruncatedTable {
                        target: target_from_name(&table.name, source)?,
                        only: table.only_span.is_some(),
                    })
                })
                .collect::<Option<Vec<_>>>()
                .unwrap_or_default(),
            ..simple(
                DdlAction::Truncate,
                ObjectKind::Table,
                s.target_table
                    .as_ref()
                    .and_then(|name| target_from_name(name, source)),
                s.node_id,
                s.span,
            )
        }),
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
            described_object_kind(&s.kind),
            s.object
                .as_ref()
                .and_then(|name| target_from_name(name, source)),
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
            plan.body = lower_bodies(stmt, inputs);
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
            ObjectKind::Table,
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
            let index = match &s.action {
                crate::ast::AlterIndexAction::Named { name, .. } => target_from(*name, source),
                crate::ast::AlterIndexAction::OnObject { name, .. } => {
                    optional_target_from(*name, source)
                }
                crate::ast::AlterIndexAction::AllInTablespace { .. } => None,
            };
            let mut p = simple(
                DdlAction::Alter,
                ObjectKind::Index,
                index,
                s.node_id,
                s.span,
            );
            p.pg_index = Some(crate::ir::ddl_plan::IrIndexDetail {
                action: project_ast_alter_index_action(&s.action),
            });
            Some(p)
        }
        AstStmt::Reindex(s) => Some(simple(
            DdlAction::Configure,
            match s.target_type {
                crate::ast::ReindexTargetType::Index => ObjectKind::Index,
                crate::ast::ReindexTargetType::Table => ObjectKind::Table,
                crate::ast::ReindexTargetType::Schema => ObjectKind::Schema,
                crate::ast::ReindexTargetType::Database => ObjectKind::Database,
                crate::ast::ReindexTargetType::System => ObjectKind::Generic,
            },
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
        // The statement `PREPARE … AS` holds is its body; `PREPARE …
        // FROM <expr>` holds SQL text.
        AstStmt::PgPrepare(s) => Some(DdlPlan {
            body: match s.from_expr {
                None => lower_body(std::slice::from_ref(&*s.body), inputs),
                Some(_) => Vec::new(),
            },
            ..simple(
                DdlAction::Execute,
                ObjectKind::Procedure,
                target_from(s.name, source),
                s.node_id,
                s.span,
            )
        }),
        AstStmt::PgExecute(s) => Some(simple(
            DdlAction::Execute,
            ObjectKind::Procedure,
            target_from(s.name, source),
            s.node_id,
            s.span,
        )),
        // A prepared statement, which no procedure is.
        // T-SQL `CREATE RULE`: a value constraint object.
        AstStmt::MssqlCreateRule(s) => Some(simple(
            DdlAction::Create,
            ObjectKind::Generic,
            target_from(s.name, source),
            s.node_id,
            s.span,
        )),
        AstStmt::PgDeallocate(s) => Some(simple(
            DdlAction::Drop,
            ObjectKind::Generic,
            match s.target {
                crate::ast::PgDeallocateTarget::Name(name) => target_from(name, source),
                crate::ast::PgDeallocateTarget::All(_) => None,
            },
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
            target_from(s.channel, source),
            s.node_id,
            s.span,
        )),
        AstStmt::PgNotify(s) => Some(simple(
            DdlAction::Configure,
            ObjectKind::Generic,
            optional_target_from(s.channel, source),
            s.node_id,
            s.span,
        )),
        AstStmt::PgUnlisten(s) => Some(simple(
            DdlAction::Configure,
            ObjectKind::Generic,
            optional_target_from(s.channel, source),
            s.node_id,
            s.span,
        )),
        // The first table locked; the facts list every one.
        AstStmt::PgLockTable(s) => Some(simple(
            DdlAction::Configure,
            ObjectKind::Table,
            s.tables
                .first()
                .and_then(|table| target_from_name(table, source)),
            s.node_id,
            s.span,
        )),
        AstStmt::PgCreateRule(s) => Some(with_body(
            DdlAction::Create,
            ObjectKind::PgRule,
            target_from(s.rule_name, source),
            lower_bodies(stmt, inputs),
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
            ObjectKind::Table,
            s.table
                .as_ref()
                .and_then(|table| target_from_name(table, source)),
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
            let bq_options = Some(extract_bq_options_from_spans(
                &[s.options_span],
                source,
                inputs.placeholder_spans,
            ));
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
                truncated: Vec::new(),
            })
        }
        AstStmt::BqLoadData(s) => {
            let mut credential_spans: Vec<Span> = vec![s.from_files_span];
            if let Some(sp) = s.trailing_clauses_span {
                credential_spans.push(sp);
            }
            let bq_options = Some(extract_bq_options_from_spans(
                &credential_spans,
                source,
                inputs.placeholder_spans,
            ));
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
                truncated: Vec::new(),
            })
        }
        AstStmt::MysqlLoadData(s) => Some(plan(
            DdlAction::BulkLoad,
            ObjectKind::Table,
            s.target_table_span.and_then(|sp| target_from(sp, source)),
            DdlOptions {
                replaces_duplicates: s.replace_span.is_some(),
                ..DdlOptions::default()
            },
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
            plan.body = lower_bodies(stmt, inputs);
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
            plan.body = lower_bodies(stmt, inputs);
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
            plan.body = lower_bodies(stmt, inputs);
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
                truncated: Vec::new(),
            })
        }
        // Published as the table a later statement reads: each part as
        // written, so a quoted part keeps its case.
        AstStmt::BqCreateSnapshotTable(s) => Some(simple(
            DdlAction::Create,
            ObjectKind::Generic,
            target_from_name(&s.name, source),
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
            let bq_options = Some(extract_bq_options_from_spans(
                &credential_spans,
                source,
                inputs.placeholder_spans,
            ));
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
                truncated: Vec::new(),
            })
        }
        AstStmt::BqAlterModel(s) => {
            let bq_options = Some(extract_bq_options_from_spans(
                &[s.set_options_span],
                source,
                inputs.placeholder_spans,
            ));
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
                truncated: Vec::new(),
            })
        }
        AstStmt::BqExportModel(s) => {
            let bq_options = Some(extract_bq_options_from_spans(
                &[s.options_span],
                source,
                inputs.placeholder_spans,
            ));
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
                truncated: Vec::new(),
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
            target_from_name(&s.name, source),
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
        // `mssql_revert` facts carry what is recognized.
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
        AstStmt::MssqlTryCatch(s) => Some(with_body(
            DdlAction::ControlFlow,
            ObjectKind::Generic,
            None,
            lower_bodies(stmt, inputs),
            s.node_id,
            s.span,
        )),
        AstStmt::MssqlIf(s) => Some(with_body(
            DdlAction::ControlFlow,
            ObjectKind::Generic,
            None,
            lower_bodies(stmt, inputs),
            s.node_id,
            s.span,
        )),

        AstStmt::MssqlWhile(s) => Some(with_body(
            DdlAction::ControlFlow,
            ObjectKind::Generic,
            None,
            lower_bodies(stmt, inputs),
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
        // what is recognized, for any rule that wants to match it.
        AstStmt::Reconfigure { node_id, span, .. } => Some(simple(
            DdlAction::ControlFlow,
            ObjectKind::Generic,
            None,
            *node_id,
            *span,
        )),
        // CHECKPOINT, KILL, SHUTDOWN: server commands with no governance
        // target; `kind: mssql_server_command` carries them.
        AstStmt::MssqlServerCommand { node_id, span } => Some(simple(
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
        AstStmt::MysqlSet(_) | AstStmt::MysqlUnlockTables(_) => None,
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
            truncated: Vec::new(),
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
        AstStmt::CreateMssqlTrigger(s) => Some(DdlPlan {
            body: lower_bodies(stmt, inputs),
            ..lower_mssql_trigger_definition(s, source)
        }),
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
        AstStmt::MssqlTriggerState(s) => {
            use crate::ast::types::{MssqlTriggerScope, MssqlTriggerStateAction};
            let target = match &s.scope {
                MssqlTriggerScope::Object(object) => target_from_name(object, source),
                MssqlTriggerScope::Database | MssqlTriggerScope::AllServer => None,
            };
            let mut p = simple(
                DdlAction::Alter,
                ObjectKind::Trigger,
                target,
                s.node_id,
                s.span,
            );
            p.pg_trigger_state = Some(crate::ir::ddl_plan::IrTriggerStateDetail {
                action: match s.action {
                    MssqlTriggerStateAction::Enable => {
                        crate::ir::ddl_plan::IrTriggerStateAction::Enable
                    }
                    MssqlTriggerStateAction::Disable => {
                        crate::ir::ddl_plan::IrTriggerStateAction::Disable
                    }
                },
            });
            Some(p)
        }
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
            action: definition_action(s.verb),
            object_kind: ObjectKind::Procedure,
            target: target_from(s.name_span, source),
            body: lower_bodies(stmt, inputs),
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
            truncated: Vec::new(),
        }),
        AstStmt::CreateFunction(s) => Some(DdlPlan {
            action: definition_action(s.verb),
            object_kind: ObjectKind::Function,
            target: target_from(s.name_span, source),
            body: lower_bodies(stmt, inputs),
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
            truncated: Vec::new(),
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
            truncated: Vec::new(),
        }),

        // ---- Inline scripting variants ----
        AstStmt::Block(s) => {
            // Block carries DECLARE-section decls (Snowflake Scripting)
            // and the BEGIN..END body. Both are sequences of inner
            // AstStmts; flatten into the single body slot in source
            // order — decls first, then BEGIN..END body. The
            // EXCEPTION section is not lowered.
            Some(with_body(
                DdlAction::ControlFlow,
                ObjectKind::Generic,
                None,
                lower_bodies(stmt, inputs),
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
            Some(with_body(
                DdlAction::ControlFlow,
                ObjectKind::Generic,
                None,
                lower_bodies(stmt, inputs),
                s.node_id,
                s.span,
            ))
        }
        AstStmt::CaseStmt(s) => {
            // Same shape as If: flatten WHEN-branch bodies + ELSE body.
            Some(with_body(
                DdlAction::ControlFlow,
                ObjectKind::Generic,
                None,
                lower_bodies(stmt, inputs),
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
        // The query a FOR loop iterates, then its body.
        AstStmt::For(s) => Some(with_body(
            DdlAction::ControlFlow,
            ObjectKind::Generic,
            None,
            lower_bodies(stmt, inputs),
            s.node_id,
            s.span,
        )),
        AstStmt::ForEach(s) => Some(with_body(
            DdlAction::ControlFlow,
            ObjectKind::Generic,
            None,
            lower_bodies(stmt, inputs),
            s.node_id,
            s.span,
        )),
        AstStmt::While(s) => Some(with_body(
            DdlAction::ControlFlow,
            ObjectKind::Generic,
            None,
            lower_bodies(stmt, inputs),
            s.node_id,
            s.span,
        )),
        AstStmt::Repeat(s) => Some(with_body(
            DdlAction::ControlFlow,
            ObjectKind::Generic,
            None,
            lower_bodies(stmt, inputs),
            s.node_id,
            s.span,
        )),
        AstStmt::Loop(s) => Some(with_body(
            DdlAction::ControlFlow,
            ObjectKind::Generic,
            None,
            lower_bodies(stmt, inputs),
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
        AstStmt::OpenCursor {
            node_id,
            span,
            cursor_name_span,
            ..
        } => Some(simple(
            DdlAction::ControlFlow,
            ObjectKind::Generic,
            target_from(*cursor_name_span, source),
            *node_id,
            *span,
        )),
        // MySQL administration: the kind carries it.
        // A table maintenance statement's target is the first table it
        // names; the facts list every one.
        AstStmt::MysqlAdmin(admin) => {
            let (object_kind, target) = match &admin.kind {
                crate::ast::AstMysqlAdminKind::TableMaintenance { tables, .. } => (
                    ObjectKind::Table,
                    tables.first().and_then(|table| target_from(*table, source)),
                ),
                crate::ast::AstMysqlAdminKind::Flush { .. }
                | crate::ast::AstMysqlAdminKind::Kill { .. }
                | crate::ast::AstMysqlAdminKind::AlterInstance
                | crate::ast::AstMysqlAdminKind::Xa
                | crate::ast::AstMysqlAdminKind::RenameUser { .. } => (ObjectKind::Generic, None),
            };
            Some(simple(
                DdlAction::ControlFlow,
                object_kind,
                target,
                admin.node_id,
                admin.span,
            ))
        }
        // MySQL's function from a shared library.
        AstStmt::MysqlCreateLoadableFunction(f) => Some(simple(
            DdlAction::Create,
            ObjectKind::Function,
            target_from(f.name, source),
            f.node_id,
            f.span,
        )),
        // Snowflake `EXECUTE TASK`: runs the task now.
        AstStmt::ExecuteTask(t) => Some(simple(
            DdlAction::Execute,
            ObjectKind::Task,
            target_from(t.name, source),
            t.node_id,
            t.span,
        )),
        // MySQL `DO`: expressions evaluated for their effect.
        AstStmt::MysqlDo(d) => Some(simple(
            DdlAction::ControlFlow,
            ObjectKind::Generic,
            None,
            d.node_id,
            d.span,
        )),
        AstStmt::FetchCursor {
            node_id,
            span,
            cursor_name_span,
            ..
        } => Some(simple(
            DdlAction::ControlFlow,
            ObjectKind::Generic,
            target_from(*cursor_name_span, source),
            *node_id,
            *span,
        )),
        AstStmt::CloseCursor {
            node_id,
            span,
            cursor_name_span,
            ..
        } => Some(simple(
            DdlAction::ControlFlow,
            ObjectKind::Generic,
            target_from(*cursor_name_span, source),
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
        AstStmt::BeginTransaction { node_id, span, .. } => Some(simple(
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
        AstStmt::Savepoint(s) => Some(simple(
            DdlAction::Transaction,
            ObjectKind::Generic,
            target_from(s.name.span, source),
            s.node_id,
            s.span,
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
            table_name,
            ..
        } => Some(simple(
            DdlAction::BulkLoad,
            ObjectKind::Stage,
            target_from_name(table_name, source),
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
        AstStmt::RedshiftCopy {
            node_id,
            span,
            name_span,
            ..
        } => Some(simple(
            DdlAction::BulkLoad,
            ObjectKind::Stage,
            target_from(*name_span, source),
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

/// The action of a statement defining a module: a T-SQL `ALTER`
/// restating the definition alters it; `CREATE OR ALTER` creates.
fn definition_action(verb: crate::ast::AstDefinitionVerb) -> DdlAction {
    match verb {
        crate::ast::AstDefinitionVerb::Create | crate::ast::AstDefinitionVerb::CreateOrAlter => {
            DdlAction::Create
        }
        crate::ast::AstDefinitionVerb::Alter => DdlAction::Alter,
    }
}

/// The definition of a T-SQL trigger, its body left out (the body's
/// statements are analysed as statements of their own); the lowering of
/// the statement adds the body to it.
pub(crate) fn lower_mssql_trigger_definition(
    s: &crate::ast::types::AstCreateMssqlTrigger,
    source: &str,
) -> DdlPlan {
    simple(
        definition_action(s.verb),
        ObjectKind::Trigger,
        target_from(s.name_span, source),
        s.node_id,
        s.span,
    )
}

/// The column a view's `RENAME [COLUMN] a TO b` renames; names not read for
/// a rename of the view and for an action kept as written (a new `AS`
/// query); no mutation for any other action of an `ALTER VIEW`.
fn alter_view_schema_mutations(
    action: &crate::ast::AstAlterViewActionKind,
    source: &str,
) -> Vec<DdlSchemaMutation> {
    use crate::ast::AstAlterViewActionKind as K;
    match action {
        K::RenameColumn {
            old_name_span,
            new_name_span,
            ..
        } => renamed_column(*old_name_span, *new_name_span, source),
        K::RenameTo { .. } | K::OpaqueRemainder { .. } => vec![DdlSchemaMutation::NamesUnread],
        K::SetOptions { .. }
        | K::AlterColumnSetOptions { .. }
        | K::SetSecure { .. }
        | K::UnsetSecure { .. }
        | K::SetComment { .. }
        | K::UnsetComment { .. }
        | K::SetChangeTracking { .. }
        | K::SetTag { .. }
        | K::UnsetTag { .. }
        | K::AddRowAccessPolicy { .. }
        | K::DropRowAccessPolicy { .. }
        | K::DropAllRowAccessPolicies { .. }
        | K::SetAggregationPolicy { .. }
        | K::UnsetAggregationPolicy { .. }
        | K::SetJoinPolicy { .. }
        | K::UnsetJoinPolicy { .. }
        | K::AlterColumn { .. }
        | K::AddColumn { .. }
        | K::DataMetricFunction { .. } => Vec::new(),
    }
}

/// What an `ALTER SCHEMA` does to the names of the relations it holds:
/// names not read where it renames or swaps the schema, or where its action
/// is kept as written (T-SQL's `TRANSFER`); no mutation for any other.
fn alter_schema_schema_mutations(
    action: &crate::ast::AstAlterSchemaActionKind,
) -> Vec<DdlSchemaMutation> {
    use crate::ast::AstAlterSchemaActionKind as K;
    match action {
        K::RenameTo { .. } | K::SwapWith { .. } | K::Unknown(_) => {
            vec![DdlSchemaMutation::NamesUnread]
        }
        K::SetProperties { .. }
        | K::UnsetProperties { .. }
        | K::SetTag { .. }
        | K::UnsetTag { .. }
        | K::SetComment { .. }
        | K::UnsetComment { .. }
        | K::EnableManagedAccess { .. }
        | K::DisableManagedAccess { .. }
        | K::SetManagedAccess { .. }
        | K::UnsetManagedAccess { .. }
        | K::SetDbProperties { .. }
        | K::OwnerTo { .. }
        | K::PredictiveOptimization { .. }
        | K::DefaultCollation { .. }
        | K::SetTags { .. }
        | K::UnsetTags { .. } => Vec::new(),
    }
}

/// [`alter_schema_schema_mutations`] for `ALTER DATABASE`; a refresh of a
/// replica loads another database's relations under its names.
fn alter_database_schema_mutations(
    action: &crate::ast::AstAlterDatabaseActionKind,
) -> Vec<DdlSchemaMutation> {
    use crate::ast::AstAlterDatabaseActionKind as K;
    match action {
        K::RenameTo { .. } | K::SwapWith { .. } | K::Refresh { .. } | K::Unknown(_) => {
            vec![DdlSchemaMutation::NamesUnread]
        }
        K::SetProperties { .. }
        | K::UnsetProperties { .. }
        | K::SetTag { .. }
        | K::UnsetTag { .. }
        | K::SetComment { .. }
        | K::UnsetComment { .. }
        | K::EnableReplication { .. }
        | K::DisableReplication { .. }
        | K::EnableFailover { .. }
        | K::DisableFailover { .. }
        | K::Primary { .. } => Vec::new(),
    }
}

/// What an `ALTER DYNAMIC TABLE` does to the names of its values: names
/// not read where it renames or swaps the table, or where its action is
/// kept as written; no mutation for any other.
fn alter_dynamic_table_schema_mutations(
    action: &crate::ast::AstAlterDynamicTableActionKind,
) -> Vec<DdlSchemaMutation> {
    use crate::ast::AstAlterDynamicTableActionKind as K;
    match action {
        K::RenameTo { .. } | K::SwapWith { .. } | K::Unknown { .. } => {
            vec![DdlSchemaMutation::NamesUnread]
        }
        K::Suspend { .. }
        | K::Resume { .. }
        | K::Refresh { .. }
        | K::Set { .. }
        | K::Unset { .. }
        | K::SetComment { .. }
        | K::UnsetComment { .. }
        | K::ClusterBy { .. }
        | K::DropClusteringKey { .. }
        | K::SuspendRecluster { .. }
        | K::ResumeRecluster { .. }
        | K::SetColumnComment { .. }
        | K::UnsetColumnComment { .. }
        | K::AddRowAccessPolicy { .. }
        | K::DropRowAccessPolicy { .. }
        | K::DropAllRowAccessPolicies { .. }
        | K::SetAggregationPolicy { .. }
        | K::UnsetAggregationPolicy { .. }
        | K::SetColumnMaskingPolicy { .. }
        | K::UnsetColumnMaskingPolicy { .. }
        | K::SetColumnProjectionPolicy { .. }
        | K::UnsetColumnProjectionPolicy { .. }
        | K::SetTag { .. }
        | K::UnsetTag { .. }
        | K::SetColumnTag { .. }
        | K::UnsetColumnTag { .. }
        | K::AddSearchOptimization { .. }
        | K::DropSearchOptimization { .. }
        | K::SuspendSearchOptimization { .. }
        | K::ResumeSearchOptimization { .. } => Vec::new(),
    }
}

/// [`alter_view_schema_mutations`] for `ALTER MATERIALIZED VIEW`.
fn alter_materialized_view_schema_mutations(
    action: &crate::ast::AstAlterMaterializedViewActionKind,
    source: &str,
) -> Vec<DdlSchemaMutation> {
    use crate::ast::AstAlterMaterializedViewActionKind as K;
    match action {
        K::RenameColumn {
            old_name_span,
            new_name_span,
            ..
        } => renamed_column(*old_name_span, *new_name_span, source),
        K::RenameTo { .. } | K::OpaqueRemainder { .. } => vec![DdlSchemaMutation::NamesUnread],
        K::SetOptions { .. }
        | K::AddRowAccessPolicy { .. }
        | K::DropRowAccessPolicy { .. }
        | K::DropAllRowAccessPolicies { .. }
        | K::AlterColumn { .. }
        | K::SetSecure { .. }
        | K::UnsetSecure { .. }
        | K::SetComment { .. }
        | K::UnsetComment { .. }
        | K::SetTag { .. }
        | K::UnsetTag { .. } => Vec::new(),
    }
}

/// The column the name at `old` names renamed to the one at `new`; its
/// columns not read where either name is not.
fn renamed_column(old: Span, new: Span, source: &str) -> Vec<DdlSchemaMutation> {
    let name = |span: Span| {
        source
            .get(span.start as usize..span.end as usize)
            .filter(|text| !text.trim().is_empty())
            .map(str::to_string)
    };
    match (name(old), name(new)) {
        (Some(from), Some(to)) => vec![DdlSchemaMutation::RenameColumn { from, to }],
        (Some(_) | None, None) | (None, Some(_)) => vec![DdlSchemaMutation::ColumnsUnread],
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
        truncated: Vec::new(),
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
        truncated: Vec::new(),
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
        truncated: Vec::new(),
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
        A::ForLogin { .. } => I::ForLogin,
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
        password_set: options.password_set,
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
            .filter(|s| s.has_property())
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
        network_policy: text(s.network_policy.as_ref().map(|policy| policy.span)),
        network_policy_unset: s.network_policy_unset,
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
        truncated: Vec::new(),
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
        truncated: Vec::new(),
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
            password_set: false,
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
        truncated: Vec::new(),
    }
}

/// The bodies `stmt` holds ([`AstStmt::bodies`]) its plan holds, each
/// lowered ([`lower_body`]) in the order written: every one but a block's
/// exception handlers, a `DECLARE … HANDLER`'s action and an `INSERT …
/// EXEC`'s `EXEC`.
fn lower_bodies(stmt: &AstStmt, inputs: &IrLowerInputs) -> Vec<Rc<StatementPlan>> {
    stmt.bodies()
        .into_iter()
        .filter(|body| match body.role {
            crate::ast::BodyRole::ExceptionHandler
            | crate::ast::BodyRole::HandlerAction
            | crate::ast::BodyRole::InsertExec => false,
            crate::ast::BodyRole::Declarations
            | crate::ast::BodyRole::Block
            | crate::ast::BodyRole::Pipe
            | crate::ast::BodyRole::Branch
            | crate::ast::BodyRole::Else
            | crate::ast::BodyRole::Loop
            | crate::ast::BodyRole::LoopQuery
            | crate::ast::BodyRole::Catch
            | crate::ast::BodyRole::Routine => true,
        })
        .flat_map(|body| lower_body(body.stmts, inputs))
        .collect()
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
///
/// A body nested deeper than the stack lets the analyzer walk
/// ([`super::lower::enter_nested`]) is not lowered: it is held as one
/// opaque statement whose reason says so.
fn lower_body(stmts: &[AstStmt], inputs: &IrLowerInputs) -> Vec<Rc<StatementPlan>> {
    let (Some(first), Some(last)) = (stmts.first(), stmts.last()) else {
        return Vec::new();
    };
    let Some(_frame) = super::lower::enter_nested() else {
        let span = Span {
            start: first.span().start,
            end: last.span().end,
        };
        return vec![Rc::new(StatementPlan::Rel(Rc::new(
            super::plan::RelPlan::Opaque {
                stmt_node_id: first.node_id(),
                reason: super::strict::OpaqueReason::NestingTooDeep {
                    depth: super::lower::nested_depth(),
                },
                hints: Vec::new(),
                span,
            },
        )))];
    };
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
                    );
                    sink.rel(
                        s.span(),
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
                    sink.ddl(s.span(), &plan, privilege_plan.as_ref());
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
    // An expression nested deeper than the stack lets the analyzer walk is
    // not read.
    let Some(_frame) = super::lower::enter_nested() else {
        return;
    };
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
        | AstExpr::IsPredicate { expr: inner, .. }
        | AstExpr::Cast { expr: inner, .. }
        | AstExpr::TryCast { expr: inner, .. }
        | AstExpr::SafeCast { expr: inner, .. }
        | AstExpr::TypeCast { expr: inner, .. }
        | AstExpr::Extract { expr: inner, .. }
        | AstExpr::Collate { expr: inner, .. }
        | AstExpr::Prior { expr: inner, .. }
        | AstExpr::ConnectByRoot { expr: inner, .. }
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
        AstExpr::LogicalChain { operands, .. } | AstExpr::OperatorChain { operands, .. } => {
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
                    crate::ast::AstFunctionArg::BulkArg { value, .. }
                    | crate::ast::AstFunctionArg::Introduced {
                        value: crate::ast::AstIntroducedValue::Expr(value),
                        ..
                    } => {
                        collect_ast_expr_subqueries(value, out);
                    }
                    crate::ast::AstFunctionArg::Unparsed { .. }
                    | crate::ast::AstFunctionArg::DataType { .. }
                    | crate::ast::AstFunctionArg::NonValue { .. }
                    | crate::ast::AstFunctionArg::Introduced {
                        value:
                            crate::ast::AstIntroducedValue::DataType { .. }
                            | crate::ast::AstIntroducedValue::Name(_),
                        ..
                    } => {}
                    crate::ast::AstFunctionArg::Table {
                        partition_by,
                        order_by,
                        ..
                    } => {
                        for e in partition_by {
                            collect_ast_expr_subqueries(e, out);
                        }
                        for item in order_by {
                            collect_ast_expr_subqueries(&item.expr, out);
                        }
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
                    crate::ast::AstFunctionArg::BulkArg { value, .. }
                    | crate::ast::AstFunctionArg::Introduced {
                        value: crate::ast::AstIntroducedValue::Expr(value),
                        ..
                    } => {
                        collect_ast_expr_subqueries(value, out);
                    }
                    crate::ast::AstFunctionArg::Unparsed { .. }
                    | crate::ast::AstFunctionArg::DataType { .. }
                    | crate::ast::AstFunctionArg::NonValue { .. }
                    | crate::ast::AstFunctionArg::Introduced {
                        value:
                            crate::ast::AstIntroducedValue::DataType { .. }
                            | crate::ast::AstIntroducedValue::Name(_),
                        ..
                    } => {}
                    crate::ast::AstFunctionArg::Table {
                        partition_by,
                        order_by,
                        ..
                    } => {
                        for e in partition_by {
                            collect_ast_expr_subqueries(e, out);
                        }
                        for item in order_by {
                            collect_ast_expr_subqueries(&item.expr, out);
                        }
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
        | AstExpr::SessionVarRef { .. }
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
/// candidate). A value that overlaps one of `placeholders` is injected
/// later and is no pair's literal; the content harvest keeps it, a
/// templated location still naming its scheme. Returns the populated
/// detail unconditionally; an empty
/// `IrBqOptionsDetail` is the right semantic projection for a BQ
/// statement that carries no credential surface (rules `exists: …`
/// against the empty vecs naturally don't match).
fn extract_bq_options_from_spans(
    spans: &[Span],
    source: &str,
    placeholders: &[Span],
) -> crate::ir::ddl_plan::IrBqOptionsDetail {
    use crate::ir::span_extract::string_literal_value;
    use crate::lexer::{tokenize_with_dialect, LiteralKind, Operator, Token, TokenKind};

    let mut detail = crate::ir::ddl_plan::IrBqOptionsDetail::default();
    // The clauses are read as the statement's dialect writes them: a
    // BigQuery `"…"` is a string.
    let dialect = crate::ir::normalize::dialect_in_force();

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
        let tokens = tokenize_with_dialect(span_text, dialect.as_ref()).tokens;
        let token_text = |tok: &Token| -> Option<&str> {
            let s = tok.span.start as usize;
            let e = tok.span.end as usize;
            if s >= e || e > span_text.len() {
                None
            } else {
                Some(&span_text[s..e])
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
                    if let Some(value) = string_literal_value(raw) {
                        let written = Span {
                            start: sp.start + tok.span.start,
                            end: sp.start + tok.span.end,
                        };
                        detail
                            .all_literal_values
                            .push(crate::ir::ddl_plan::IrBqLiteral {
                                value,
                                url_password_literals:
                                    crate::ir::span_extract::url_password_literals(
                                        written,
                                        source,
                                        placeholders,
                                    ),
                            });
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
            let written = tokens[val_idx].span;
            let value_span = Span {
                start: sp.start + written.start,
                end: sp.start + written.end,
            };
            if placeholders.iter().any(|p| p.overlaps(value_span)) {
                continue;
            }
            let Some(value_raw) = token_text(&tokens[val_idx]) else {
                continue;
            };
            let Some(value_literal) = string_literal_value(value_raw) else {
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
    target_of_parts(&relation_parts_written(&source[start..end]), span)
}

/// The parts of the relation name `text` writes, each as written
/// ([`crate::ir::utils::relation_written_parts`]).
pub(crate) fn relation_parts_written(text: &str) -> Vec<String> {
    crate::ir::utils::relation_written_parts(split_qualified(text).into_iter().map(Some).collect())
        .into_iter()
        .flatten()
        .collect()
}

/// The table of the column whose qualified name `source` writes at `span`
/// (`db.schema.table.column`): every part but the last.
pub(crate) fn column_table_target(span: Span, source: &str) -> Option<DdlTarget> {
    let start = span.start as usize;
    let end = span.end as usize;
    if start >= end || end > source.len() {
        return None;
    }
    let parts = split_qualified(&source[start..end]);
    let (_column, table) = parts.split_last()?;
    target_of_parts(table, span)
}

/// The target named by `parts`, its last three as name, schema, database.
fn target_of_parts(parts: &[String], span: Span) -> Option<DdlTarget> {
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

/// The target `name` names, each part as written, as [`target_from`]
/// reads it; a name the parser did not read as dotted parts is read from
/// its text.
pub(crate) fn target_from_name(name: &crate::ast::AstObjectRef, source: &str) -> Option<DdlTarget> {
    let written: Option<Vec<String>> = name.parts.as_ref().and_then(|parts| {
        parts
            .iter()
            .map(|part| {
                let span = part.as_ref()?.span();
                source
                    .get(span.start as usize..span.end as usize)
                    .map(str::to_string)
            })
            .collect()
    });
    // `IDENTIFIER('…')`: the parts its string writes.
    let written = written.or_else(|| {
        let (db, schema, table) = crate::ir::utils::written_name_parts(source, name)?;
        Some([db, schema, Some(table)].into_iter().flatten().collect())
    });
    let Some(written) = written else {
        return target_from(name.span, source);
    };
    let mut written: Vec<String> =
        crate::ir::utils::relation_written_parts(written.into_iter().map(Some).collect())
            .into_iter()
            .flatten()
            .collect();
    let table = written.pop()?;
    let schema = written.pop();
    let db = written.pop();
    Some(DdlTarget {
        name: table,
        schema,
        db,
        span: name.span,
    })
}

#[inline]
fn optional_target_from(span: Option<Span>, source: &str) -> Option<DdlTarget> {
    target_from(span?, source)
}

/// Walk an `AstAlterTable.actions` list and collect what each action
/// does to the table's identity and columns: `RenameTo`, `AddColumn`,
/// `DropColumn`, `RenameColumn` (also a `CHANGE` whose names differ),
/// `SwapWith`, and `ColumnsUnread` for an action whose effect on the
/// columns is not read. The actions read as keeping the columns are
/// named explicitly and carry no mutation.
fn collect_alter_table_schema_mutations(
    s: &crate::ast::AstAlterTable,
    source: &str,
) -> Vec<DdlSchemaMutation> {
    use crate::ast::AstAlterTableActionKind as K;
    use crate::ast::AstNamedTableAction as N;
    let name = |span: Span| {
        source
            .get(span.start as usize..span.end as usize)
            .filter(|text| !text.trim().is_empty())
            .map(str::to_string)
    };
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
                if columns.is_empty() {
                    out.push(DdlSchemaMutation::ColumnsUnread);
                }
                for col_def in columns {
                    match col_def.name_span.and_then(name) {
                        Some(column_name) => out.push(DdlSchemaMutation::AddColumn { column_name }),
                        None => out.push(DdlSchemaMutation::ColumnsUnread),
                    }
                    // A column computed from others shows their values.
                    if col_def.virtual_expr_span.is_some() {
                        out.push(DdlSchemaMutation::NamesUnread);
                    }
                }
            }
            K::DropColumn { columns, .. } => {
                if columns.is_empty() {
                    out.push(DdlSchemaMutation::ColumnsUnread);
                }
                for col_span in columns {
                    match name(*col_span) {
                        Some(column_name) => {
                            out.push(DdlSchemaMutation::DropColumn { column_name })
                        }
                        None => out.push(DdlSchemaMutation::ColumnsUnread),
                    }
                }
            }
            K::RenameColumn {
                old_name_span,
                new_name_span,
                ..
            }
            | K::ChangeColumn {
                old_name_span,
                new_name_span,
                ..
            } => match (name(*old_name_span), name(*new_name_span)) {
                (Some(from), Some(to)) => {
                    // A `CHANGE` that keeps the name redefines the column only.
                    let renamed = IdentKey::new_as(&from, NameKind::Column)
                        != IdentKey::new_as(&to, NameKind::Column);
                    // A `CHANGE` redefines the column, its type first; a
                    // `RENAME COLUMN` keeps its type.
                    let retyped = matches!(action.kind, K::ChangeColumn { .. });
                    if renamed {
                        out.push(DdlSchemaMutation::RenameColumn {
                            from,
                            to: to.clone(),
                        });
                    }
                    if retyped {
                        out.push(DdlSchemaMutation::SetColumnType {
                            column_name: to,
                            data_type: None,
                        });
                    }
                }
                (Some(_) | None, None) | (None, Some(_)) => {
                    out.push(DdlSchemaMutation::ColumnsUnread)
                }
            },
            K::SwapWith {
                other_table_span, ..
            } => match target_from(*other_table_span, source) {
                Some(other) => out.push(DdlSchemaMutation::SwapWith { other }),
                None => out.push(DdlSchemaMutation::ColumnsUnread),
            },
            K::SetColumnTag {
                column_name_span,
                tags,
                ..
            } => {
                if let Some(column_name) = name(*column_name_span) {
                    let tags = written_tags(tags, source);
                    out.push(DdlSchemaMutation::SetColumnTags { column_name, tags });
                }
            }
            K::UnsetColumnTag {
                column_name_span,
                tags,
                ..
            } => {
                if let Some(column_name) = name(*column_name_span) {
                    let tags = written_tags(tags, source);
                    out.push(DdlSchemaMutation::UnsetColumnTags { column_name, tags });
                }
            }
            // Kept as written: what it does to the columns and the names
            // of their values is not read.
            K::GovernanceSpan { .. } | K::Unknown { .. } => {
                out.push(DdlSchemaMutation::ColumnsUnread);
                out.push(DdlSchemaMutation::NamesUnread);
            }
            // The table's rows move to another name, or another table's
            // rows to its name.
            K::SetSchema { .. }
            | K::AttachPartition { .. }
            | K::DetachPartition { .. }
            | K::SwitchTo { .. } => out.push(DdlSchemaMutation::NamesUnread),
            K::AlterColumn {
                column_name_span,
                altered_type: crate::ast::AstAlteredType::Changed { type_span },
                ..
            } => match name(*column_name_span) {
                Some(column_name) => out.push(DdlSchemaMutation::SetColumnType {
                    column_name,
                    data_type: type_span.and_then(name),
                }),
                None => out.push(DdlSchemaMutation::ColumnsUnread),
            },
            K::AlterColumnSetDataType {
                column_name_span,
                data_type_span,
                ..
            } => match name(*column_name_span) {
                Some(column_name) => out.push(DdlSchemaMutation::SetColumnType {
                    column_name,
                    data_type: name(*data_type_span),
                }),
                None => out.push(DdlSchemaMutation::ColumnsUnread),
            },
            // Each column of a list of alterations may have its type
            // changed; the new type is not read.
            K::AlterColumnList { columns, .. } => {
                for column in columns {
                    match name(*column) {
                        Some(column_name) => out.push(DdlSchemaMutation::SetColumnType {
                            column_name,
                            data_type: None,
                        }),
                        None => out.push(DdlSchemaMutation::ColumnsUnread),
                    }
                }
            }
            // Read as keeping every column, its name and its type.
            K::AlterColumn {
                altered_type: crate::ast::AstAlteredType::Kept,
                ..
            }
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
            | K::AlterColumnSetDefault { .. }
            | K::AlterColumnDropDefault { .. }
            | K::SetTblProperties { .. }
            | K::UnsetTblProperties { .. }
            | K::RowLevelSecurity { .. }
            | K::OwnerTo { .. } => {}
            K::NamedAction { kind, .. } => match kind {
                // A parent's rows shown under the table's name, or a
                // partition's moved: neither link is stated.
                N::Inherit | N::PartitionMaintenance => out.push(DdlSchemaMutation::NamesUnread),
                N::DropConstraint
                | N::DropIndex
                | N::DropForeignKey
                | N::DropCheck
                | N::DropPartition
                | N::DropPeriod
                | N::AddPrimaryKey
                | N::AddUnique
                | N::AddCheck
                | N::AddIndex
                | N::AddPartition
                | N::AddPeriod
                | N::AddDefault
                | N::CheckConstraint
                | N::NocheckConstraint
                | N::EnableTrigger
                | N::DisableTrigger
                | N::ChangeTracking
                | N::FiletableNamespace
                | N::Rebuild
                | N::RenameIndex
                | N::RenameConstraint
                | N::AlterIndex
                | N::AlterConstraint
                | N::ValidateConstraint
                | N::TableOption
                | N::NoInherit
                | N::ReplicaIdentity
                | N::Distribution
                | N::RuleState
                | N::SearchOptimization
                | N::DropUnique
                | N::ResetOptions
                | N::RowLevelSecurity
                | N::KeysState
                | N::DropFeature
                | N::PredictiveOptimization => {}
            },
        }
    }
    out
}

/// What `s` drops of what its table declares: its primary key, a
/// constraint or an index by name (or one whose name is not read), the
/// `NOT NULL` of a column dropped or redefined without it, and, for an
/// action not read, every declaration.
pub(crate) fn dropped_declarations(
    s: &crate::ast::AstAlterTable,
    source: &str,
) -> Vec<crate::catalog::DroppedDeclaration> {
    use crate::ast::AstAlterTableActionKind as K;
    use crate::ast::AstNamedTableAction as N;
    use crate::catalog::DroppedDeclaration as D;
    let name = |span: Span, kind: NameKind| {
        source
            .get(span.start as usize..span.end as usize)
            .filter(|text| !text.trim().is_empty())
            .map(|text| IdentKey::new_as(text, kind))
    };
    let mut out = Vec::new();
    for action in &s.actions {
        match &action.kind {
            K::DropPrimaryKey { .. } => out.push(D::PrimaryKey),
            K::DropConstraint { name_span, .. } => {
                out.push(D::Constraint(name(*name_span, NameKind::Relation)))
            }
            K::AlterColumnDropNotNull {
                column_name_span, ..
            } => {
                if let Some(column) = name(*column_name_span, NameKind::Column) {
                    out.push(D::NotNull(column));
                }
            }
            K::NamedAction {
                kind, name_span, ..
            } => match kind {
                N::DropConstraint => out.push(D::Constraint(
                    name_span.and_then(|span| name(span, NameKind::Relation)),
                )),
                N::DropUnique => out.push(D::Constraint(None)),
                N::DropIndex => out.push(D::Index(
                    name_span.and_then(|span| name(span, NameKind::Relation)),
                )),
                N::AddCheck
                | N::AddDefault
                | N::AddIndex
                | N::AddPartition
                | N::AddPeriod
                | N::AddPrimaryKey
                | N::AddUnique
                | N::AlterConstraint
                | N::AlterIndex
                | N::ChangeTracking
                | N::CheckConstraint
                | N::DisableTrigger
                | N::Distribution
                | N::DropCheck
                | N::DropFeature
                | N::DropForeignKey
                | N::DropPartition
                | N::DropPeriod
                | N::EnableTrigger
                | N::FiletableNamespace
                | N::Inherit
                | N::NoInherit
                | N::KeysState
                | N::NocheckConstraint
                | N::PartitionMaintenance
                | N::PredictiveOptimization
                | N::Rebuild
                | N::RenameConstraint
                | N::RenameIndex
                | N::ReplicaIdentity
                | N::ResetOptions
                | N::RowLevelSecurity
                | N::RuleState
                | N::SearchOptimization
                | N::TableOption
                | N::ValidateConstraint => {}
            },
            // A column redefined keeps its `NOT NULL` only where the
            // definition writes it; an operation on another part keeps it.
            K::AlterColumn {
                column_name_span,
                nullability,
                ..
            } => match nullability {
                crate::ast::AstAlteredNullability::Redefined { not_null: false } => {
                    out.extend(name(*column_name_span, NameKind::Column).map(D::NotNull));
                }
                crate::ast::AstAlteredNullability::Redefined { not_null: true }
                | crate::ast::AstAlteredNullability::Kept => {}
            },
            K::ChangeColumn {
                old_name_span,
                new_name_span,
                null_written,
                ..
            } => {
                if *null_written != Some(false) {
                    for column in [old_name_span, new_name_span] {
                        out.extend(name(*column, NameKind::Column).map(D::NotNull));
                    }
                }
            }
            K::AlterColumnList { columns, .. } => {
                out.extend(
                    columns
                        .iter()
                        .filter_map(|column| name(*column, NameKind::Column))
                        .map(D::NotNull),
                );
            }
            K::Unknown { .. } | K::GovernanceSpan { .. } => out.push(D::Every),
            K::AddColumn { .. }
            | K::AddConstraint { .. }
            | K::AddDataMetricFunction { .. }
            | K::AddRowAccessPolicy(_)
            | K::AddSearchOptimization { .. }
            | K::AddStorageLifecyclePolicy { .. }
            | K::AlterColumnDropDefault { .. }
            | K::AlterColumnSetDataType { .. }
            | K::AlterColumnSetDefault { .. }
            | K::AlterColumnSetOptions { .. }
            | K::AttachPartition { .. }
            | K::ClusterBy { .. }
            | K::DetachPartition { .. }
            | K::DropAllRowAccessPolicies { .. }
            | K::DropClusteringKey { .. }
            | K::DropColumn { .. }
            | K::DropColumnMask { .. }
            | K::DropDataMetricFunction { .. }
            | K::DropRowAccessPolicy { .. }
            | K::DropRowFilter { .. }
            | K::DropSearchOptimization { .. }
            | K::DropStorageLifecyclePolicy { .. }
            | K::OwnerTo { .. }
            | K::RenameColumn { .. }
            | K::RenameTo { .. }
            | K::ResumeRecluster { .. }
            | K::RowLevelSecurity { .. }
            | K::Set { .. }
            | K::SetAggregationPolicy { .. }
            | K::SetColumnMask { .. }
            | K::SetColumnMaskingPolicy(_)
            | K::SetColumnProjectionPolicy(_)
            | K::SetColumnTag { .. }
            | K::SetDataMetricSchedule { .. }
            | K::SetDefaultCollate { .. }
            | K::SetJoinPolicy { .. }
            | K::SetOptions { .. }
            | K::SetRowFilter { .. }
            | K::SetSchema { .. }
            | K::SetTag { .. }
            | K::SetTblProperties { .. }
            | K::SuspendRecluster { .. }
            | K::SwapWith { .. }
            | K::SwitchTo { .. }
            | K::Unset { .. }
            | K::UnsetAggregationPolicy { .. }
            | K::UnsetColumnMaskingPolicy { .. }
            | K::UnsetColumnProjectionPolicy { .. }
            | K::UnsetColumnTag { .. }
            | K::UnsetDataMetricSchedule { .. }
            | K::UnsetJoinPolicy { .. }
            | K::UnsetTag { .. }
            | K::UnsetTblProperties { .. } => {}
        }
    }
    out
}

/// The tags `tags` write, each as a catalog records a tag: the parts of its
/// name folded as the dialect folds a name, and its value where it is a
/// string literal. A tag whose name is not read as one to three parts is
/// left out.
pub(crate) fn written_tags(
    tags: &[crate::ast::AstTagRef],
    source: &str,
) -> Vec<crate::catalog::CatalogTag> {
    tags.iter()
        .filter_map(|tag| {
            let (database, schema, name) = crate::ir::utils::written_name_parts(source, &tag.name)?;
            let tag_value = tag.value.and_then(|value| {
                crate::ir::span_extract::string_literal_value(crate::ir::utils::slice_span(
                    source, value,
                )?)
            });
            Some(crate::catalog::CatalogTag {
                tag_database: database.as_deref().map(normalize_identifier),
                tag_schema: schema.as_deref().map(normalize_identifier),
                tag_name: normalize_identifier(&name),
                tag_value,
            })
        })
        .collect()
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

/// Split a `db.schema.name` string into its components, each as
/// written: a segment quoted with `"…"`, `` `…` `` or `[…]` is kept
/// whole, quotes included. Whitespace inside the qualified name is
/// skipped at the top level; it is preserved inside quoted segments.
/// `IDENTIFIER('…')` is split as the name its string writes.
pub(crate) fn split_qualified(s: &str) -> Vec<String> {
    match crate::ir::utils::identifier_string_name(s) {
        Some(written) => split_qualified_text(&written),
        None => split_qualified_text(s),
    }
}

/// [`split_qualified`] of a name written as text, never `IDENTIFIER(…)`.
fn split_qualified_text(s: &str) -> Vec<String> {
    split_qualified_parts(s, false)
}

/// The parts of the dotted name `s`, as [`split_qualified`] reads them,
/// with an empty part kept where two dots meet (`db..name`).
pub(crate) fn split_qualified_keeping_empty(s: &str) -> Vec<String> {
    split_qualified_parts(s, true)
}

/// The parts of the dotted name `s` ([`crate::ir::utils::dotted_name_segments`]),
/// each trimmed of the whitespace around it; an empty part kept only where
/// `keep_empty` says.
fn split_qualified_parts(s: &str, keep_empty: bool) -> Vec<String> {
    crate::ir::utils::dotted_name_segments(s, 0)
        .into_iter()
        .map(|segment| {
            crate::ir::utils::slice_span(s, segment)
                .unwrap_or("")
                .trim()
        })
        .filter(|part| keep_empty || !part.is_empty())
        .map(str::to_string)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::catalog::{CatalogDialect, FunctionCatalog};
    use crate::ir::plan::RelPlan;
    use crate::ir::strict::{OpaqueReason, StrictMode};
    use crate::ir::types::SessionContext;

    /// The bodies `plan` holds at any depth that were not lowered for
    /// being nested too deep.
    fn too_deep_bodies(plan: &DdlPlan) -> usize {
        let mut found = 0;
        let mut open: Vec<&StatementPlan> = plan.body.iter().map(|s| s.as_ref()).collect();
        while let Some(next) = open.pop() {
            match next {
                StatementPlan::Ddl(inner) => open.extend(inner.body.iter().map(|s| s.as_ref())),
                StatementPlan::Rel(rel) => {
                    if let RelPlan::Opaque {
                        reason: OpaqueReason::NestingTooDeep { .. },
                        ..
                    } = rel.as_ref()
                    {
                        found += 1;
                    }
                }
            }
        }
        found
    }

    #[test]
    fn bodies_nested_past_the_stack_are_held_as_one_opaque_statement() {
        let src: String = (0..300)
            .map(|k| {
                format!("CREATE PROCEDURE p{k}() BEGIN IF 1 THEN DELETE FROM orders; END IF;\n")
            })
            .collect();
        let lowered = std::thread::Builder::new()
            .stack_size(crate::parser::core::MIN_PARSE_STACK_BYTES)
            .spawn(move || {
                let _scope = crate::ir::normalize::set_normalization_dialect("mysql");
                let dialect = crate::dialect::mysql();
                let lex = crate::lexer::tokenize_with_dialect(&src, dialect.as_ref());
                let script = crate::parser::try_parse_script_with_dialect(
                    &src,
                    &lex.tokens,
                    dialect.as_ref(),
                )
                .expect("parses");
                let catalog = FunctionCatalog::for_dialect(CatalogDialect::Default);
                let session = SessionContext::default();
                let inputs = IrLowerInputs {
                    source: &src,
                    placeholder_spans: &[],
                    strict: StrictMode::Permissive,
                    func_catalog: &catalog,
                    session: &session,
                    meaning: dialect.syntax_meaning(),
                    catalog: None,
                    model_catalog: None,
                    reasoning: &crate::facts::reasoning::RecognitionOnly,
                    flatten_body_into: None,
                };
                script
                    .stmts
                    .iter()
                    .filter_map(|stmt| lower_ddl_stmt(stmt, &inputs))
                    .map(|plan| too_deep_bodies(&plan))
                    .sum::<usize>()
            })
            .expect("spawns")
            .join()
            .expect("lowers without overflowing the stack");
        assert!(lowered > 0, "no body was held as nested too deep");
    }
}
