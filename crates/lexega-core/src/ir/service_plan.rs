// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! IR-side carrier for Snowflake `CREATE / ALTER / DROP SERVICE` (Snowpark
//! Container Services).
//!
//! Sibling-tier carrier analogous to [`super::StreamlitPlan`]: typed projection
//! of the AST that `derive_facts_from_service_plan` folds into the public
//! `StatementFacts.ddl.service` carrier.
//!
//! A service runs container workloads on a compute pool from a spec (an inline
//! YAML body or a stage file — captured, not analyzed). The governance
//! recognition surface is the compute-pool binding and whether the service
//! declares `EXTERNAL_ACCESS_INTEGRATIONS` (network egress); which egress is
//! acceptable is YAML.

use crate::ast::{types::AstServiceAction, AstAlterService, AstCreateService, AstDrop, NodeId};
use crate::ir::utils::slice_span;
use crate::lexer::token::Span;

#[derive(Debug, Clone)]
pub struct ServicePlan {
    pub action: ServiceAction,
    pub target: Option<ServiceTarget>,
    pub options: ServiceOptions,
    /// `IN COMPUTE POOL <pool>` name (as written) when present.
    pub in_compute_pool: Option<String>,
    /// `EXTERNAL_ACCESS_INTEGRATIONS = (...)` present — the service declares
    /// network egress. Populated on CREATE and `ALTER … SET`.
    pub has_external_access_integrations: bool,
    /// `ALTER SERVICE` action variants in source order. Empty on CREATE / DROP
    /// (ALTER carries exactly one).
    pub(crate) actions: Vec<ServiceAlterActionIr>,
    pub node_id: NodeId,
    pub span: Span,
}

/// IR-internal mirror of [`crate::ast::types::AstServiceAction`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum ServiceAlterActionIr {
    Set,
    Unset,
    Resume,
    Suspend,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ServiceAction {
    Create,
    Alter,
    Drop,
}

#[derive(Debug, Clone)]
pub struct ServiceTarget {
    pub name: String,
    pub span: Span,
}

#[derive(Debug, Clone, Default)]
pub struct ServiceOptions {
    pub or_replace: bool,
    pub if_not_exists: bool,
    pub if_exists: bool,
}

/// Lower a typed [`AstCreateService`] into a [`ServicePlan`].
pub fn lower_create_service_to_service_plan(s: &AstCreateService, source: &str) -> ServicePlan {
    ServicePlan {
        action: ServiceAction::Create,
        target: Some(target_from_span(source, s.name_span)),
        options: ServiceOptions {
            or_replace: s.or_replace_span.is_some(),
            if_not_exists: s.if_not_exists_span.is_some(),
            if_exists: false,
        },
        in_compute_pool: name_text(source, s.compute_pool_span),
        has_external_access_integrations: s.external_access_integrations_span.is_some(),
        actions: Vec::new(),
        node_id: s.node_id,
        span: s.span,
    }
}

/// Lower a typed [`AstAlterService`] into a [`ServicePlan`].
pub fn lower_alter_service_to_service_plan(s: &AstAlterService, source: &str) -> ServicePlan {
    ServicePlan {
        action: ServiceAction::Alter,
        target: Some(target_from_span(source, s.name_span)),
        options: ServiceOptions {
            or_replace: false,
            if_not_exists: false,
            if_exists: s.if_exists_span.is_some(),
        },
        in_compute_pool: None,
        has_external_access_integrations: s.external_access_integrations_span.is_some(),
        actions: vec![classify_alter_action(s.action)],
        node_id: s.node_id,
        span: s.span,
    }
}

/// Lower a generic [`AstDrop`] whose object type is SERVICE.
/// The caller gates on the object type.
pub fn lower_drop_service_to_service_plan(s: &AstDrop, source: &str) -> ServicePlan {
    ServicePlan {
        action: ServiceAction::Drop,
        target: s
            .target_name_span
            .map(|span| target_from_span(source, span)),
        options: ServiceOptions {
            or_replace: false,
            if_not_exists: false,
            if_exists: s.if_exists_span.is_some(),
        },
        in_compute_pool: None,
        has_external_access_integrations: false,
        actions: Vec::new(),
        node_id: s.node_id,
        span: s.span,
    }
}

fn classify_alter_action(action: AstServiceAction) -> ServiceAlterActionIr {
    match action {
        AstServiceAction::Set => ServiceAlterActionIr::Set,
        AstServiceAction::Unset => ServiceAlterActionIr::Unset,
        AstServiceAction::Resume => ServiceAlterActionIr::Resume,
        AstServiceAction::Suspend => ServiceAlterActionIr::Suspend,
    }
}

fn name_text(source: &str, span: Option<Span>) -> Option<String> {
    span.and_then(|sp| slice_span(source, sp))
        .map(|t| t.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn target_from_span(source: &str, span: Span) -> ServiceTarget {
    ServiceTarget {
        name: slice_span(source, span).unwrap_or("").trim().to_string(),
        span,
    }
}
