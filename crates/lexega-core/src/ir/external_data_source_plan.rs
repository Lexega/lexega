// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! IR-side carrier for the T-SQL / PolyBase `CREATE EXTERNAL DATA SOURCE`
//! statement.
//!
//! Sibling-tier carrier analogous to [`super::ConnectionPlan`]: a typed
//! projection of [`crate::ast::types::AstMssqlCreateExternalDataSource`] that
//! `derive_facts_from_external_data_source_plan` folds into the public
//! `StatementFacts.ddl.external_data_source` carrier.
//!
//! Carries neutral recognition primitives only — the location URI scheme,
//! the typed TYPE class, whether a credential is referenced, and PUSHDOWN.
//! The raw LOCATION literal is dropped at the AST→IR boundary because
//! PolyBase connection strings can embed credentials.

use crate::ast::types::{
    AstExternalDataSourceType, AstMssqlAlterExternalDataSource, AstMssqlCreateExternalDataSource,
};
use crate::ast::NodeId;
use crate::lexer::token::Span;

/// Lifecycle action of an external-data-source statement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExternalDataSourceAction {
    Create,
    Alter,
}

#[derive(Debug, Clone)]
pub struct ExternalDataSourcePlan {
    pub action: ExternalDataSourceAction,
    pub name: String,
    pub name_span: Span,
    /// `CREATE OR { REPLACE | ALTER }` modifier present.
    pub or_replace: bool,
    /// `IF NOT EXISTS` present.
    pub if_not_exists: bool,
    /// True when a LOCATION clause is present.
    pub location_present: bool,
    /// Lowercased URI scheme of the LOCATION value (`hdfs`, `wasbs`, …).
    pub location_scheme: Option<String>,
    /// Typed TYPE class, when one of the documented values is named.
    pub source_type: Option<ExternalDataSourceTypeKind>,
    /// True when a `CREDENTIAL = <name>` clause is present.
    pub credential_present: bool,
    /// PUSHDOWN = ON (`Some(true)`) / OFF (`Some(false)`); `None` when absent.
    pub pushdown: Option<bool>,
    pub node_id: NodeId,
    pub span: Span,
}

/// IR mirror of [`crate::ast::types::AstExternalDataSourceType`]. Public
/// mirror is [`crate::facts::ExternalDataSourceType`](crate::facts::ddl::ExternalDataSourceType).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExternalDataSourceTypeKind {
    Hadoop,
    BlobStorage,
    Rdbms,
    ShardMapManager,
}

pub fn lower_create_external_data_source_to_plan(
    s: &AstMssqlCreateExternalDataSource,
    source: &str,
) -> ExternalDataSourcePlan {
    let name = source
        .get(s.name_span.start as usize..s.name_span.end as usize)
        .unwrap_or("")
        .trim()
        .to_string();
    ExternalDataSourcePlan {
        action: ExternalDataSourceAction::Create,
        name,
        name_span: s.name_span,
        or_replace: s.or_replace,
        if_not_exists: s.if_not_exists,
        location_present: s.location_present,
        location_scheme: s.location_scheme.clone(),
        source_type: s.source_type.map(lower_source_type),
        credential_present: s.credential_present,
        pushdown: s.pushdown,
        node_id: s.node_id,
        span: s.span,
    }
}

pub fn lower_alter_external_data_source_to_plan(
    s: &AstMssqlAlterExternalDataSource,
    source: &str,
) -> ExternalDataSourcePlan {
    let name = source
        .get(s.name_span.start as usize..s.name_span.end as usize)
        .unwrap_or("")
        .trim()
        .to_string();
    ExternalDataSourcePlan {
        action: ExternalDataSourceAction::Alter,
        name,
        name_span: s.name_span,
        // ALTER carries neither modifier.
        or_replace: false,
        if_not_exists: false,
        location_present: s.location_present,
        location_scheme: s.location_scheme.clone(),
        source_type: s.source_type.map(lower_source_type),
        credential_present: s.credential_present,
        pushdown: s.pushdown,
        node_id: s.node_id,
        span: s.span,
    }
}

fn lower_source_type(t: AstExternalDataSourceType) -> ExternalDataSourceTypeKind {
    match t {
        AstExternalDataSourceType::Hadoop => ExternalDataSourceTypeKind::Hadoop,
        AstExternalDataSourceType::BlobStorage => ExternalDataSourceTypeKind::BlobStorage,
        AstExternalDataSourceType::Rdbms => ExternalDataSourceTypeKind::Rdbms,
        AstExternalDataSourceType::ShardMapManager => ExternalDataSourceTypeKind::ShardMapManager,
    }
}
