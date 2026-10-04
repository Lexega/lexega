// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! IR-side carrier for Snowflake `CREATE / ALTER / DROP COMPUTE POOL`
//! (Snowpark Container Services compute capacity).
//!
//! Sibling-tier carrier analogous to [`super::ResourceMonitorPlan`]: typed
//! projection of the AST that `derive_facts_from_compute_pool_plan` folds
//! into the public `StatementFacts.ddl.compute_pool` carrier.
//!
//! A compute pool is the capacity that Snowpark Container Services jobs and
//! services run on. The `INSTANCE_FAMILY` (CPU vs GPU), node counts, and
//! auto-resume/suspend settings are the recognition surface; which families
//! or settings are costly or risky is YAML policy.

use crate::ast::{
    types::AstComputePoolAction, AstAlterComputePool, AstCreateComputePool, AstDrop, NodeId,
};
use crate::ir::utils::slice_span;
use crate::lexer::token::Span;

#[derive(Debug, Clone)]
pub struct ComputePoolPlan {
    pub action: ComputePoolAction,
    pub target: Option<ComputePoolTarget>,
    pub options: ComputePoolOptions,
    /// `INSTANCE_FAMILY = <family>` (upper-cased), e.g. `CPU_X64_S`,
    /// `GPU_NV_S`. Populated on CREATE and `ALTER … SET`.
    pub instance_family: Option<String>,
    /// `AUTO_RESUME = {TRUE|FALSE}` when present.
    pub auto_resume: Option<bool>,
    /// `MIN_NODES = <n>` text as written.
    pub min_nodes: Option<String>,
    /// `MAX_NODES = <n>` text as written.
    pub max_nodes: Option<String>,
    /// `ALTER COMPUTE POOL` action variants in source order. Empty on
    /// CREATE / DROP (ALTER carries exactly one).
    pub(crate) actions: Vec<ComputePoolAlterActionIr>,
    pub node_id: NodeId,
    pub span: Span,
}

/// IR-internal mirror of [`crate::ast::types::AstComputePoolAction`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum ComputePoolAlterActionIr {
    Set,
    Unset,
    Suspend,
    Resume,
    StopAll,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ComputePoolAction {
    Create,
    Alter,
    Drop,
}

#[derive(Debug, Clone)]
pub struct ComputePoolTarget {
    pub name: String,
    pub span: Span,
}

#[derive(Debug, Clone, Default)]
pub struct ComputePoolOptions {
    pub if_not_exists: bool,
    pub if_exists: bool,
    /// `OR REPLACE` present (CREATE only).
    pub or_replace: bool,
}

/// Lower a typed [`AstCreateComputePool`] into a [`ComputePoolPlan`].
pub fn lower_create_compute_pool_to_compute_pool_plan(
    s: &AstCreateComputePool,
    source: &str,
) -> ComputePoolPlan {
    ComputePoolPlan {
        action: ComputePoolAction::Create,
        target: Some(target_from_span(source, s.name_span)),
        options: ComputePoolOptions {
            if_not_exists: s.if_not_exists_span.is_some(),
            if_exists: false,
            or_replace: s.or_replace_span.is_some(),
        },
        instance_family: upper_text(source, s.instance_family_span),
        auto_resume: bool_from_span(source, s.auto_resume_span),
        min_nodes: trim_text(source, s.min_nodes_span),
        max_nodes: trim_text(source, s.max_nodes_span),
        actions: Vec::new(),
        node_id: s.node_id,
        span: s.span,
    }
}

/// Lower a typed [`AstAlterComputePool`] into a [`ComputePoolPlan`].
pub fn lower_alter_compute_pool_to_compute_pool_plan(
    s: &AstAlterComputePool,
    source: &str,
) -> ComputePoolPlan {
    ComputePoolPlan {
        action: ComputePoolAction::Alter,
        target: Some(target_from_span(source, s.name_span)),
        options: ComputePoolOptions {
            if_not_exists: false,
            if_exists: s.if_exists_span.is_some(),
            or_replace: false,
        },
        instance_family: upper_text(source, s.instance_family_span),
        auto_resume: bool_from_span(source, s.auto_resume_span),
        min_nodes: None,
        max_nodes: None,
        actions: vec![classify_alter_action(s.action)],
        node_id: s.node_id,
        span: s.span,
    }
}

/// Lower a generic [`AstDrop`] whose object type is COMPUTE POOL.
/// The caller gates on the object type.
pub fn lower_drop_compute_pool_to_compute_pool_plan(s: &AstDrop, source: &str) -> ComputePoolPlan {
    ComputePoolPlan {
        action: ComputePoolAction::Drop,
        target: s
            .target_name_span
            .map(|span| target_from_span(source, span)),
        options: ComputePoolOptions {
            if_not_exists: false,
            if_exists: s.if_exists_span.is_some(),
            or_replace: false,
        },
        instance_family: None,
        auto_resume: None,
        min_nodes: None,
        max_nodes: None,
        actions: Vec::new(),
        node_id: s.node_id,
        span: s.span,
    }
}

fn classify_alter_action(action: AstComputePoolAction) -> ComputePoolAlterActionIr {
    match action {
        AstComputePoolAction::Set => ComputePoolAlterActionIr::Set,
        AstComputePoolAction::Unset => ComputePoolAlterActionIr::Unset,
        AstComputePoolAction::Suspend => ComputePoolAlterActionIr::Suspend,
        AstComputePoolAction::Resume => ComputePoolAlterActionIr::Resume,
        AstComputePoolAction::StopAll => ComputePoolAlterActionIr::StopAll,
    }
}

fn bool_from_span(source: &str, span: Option<Span>) -> Option<bool> {
    let raw = slice_span(source, span?)?.trim();
    if raw.eq_ignore_ascii_case("TRUE") {
        Some(true)
    } else if raw.eq_ignore_ascii_case("FALSE") {
        Some(false)
    } else {
        None
    }
}

fn upper_text(source: &str, span: Option<Span>) -> Option<String> {
    span.and_then(|sp| slice_span(source, sp))
        .map(|t| t.trim().trim_matches('\'').trim().to_ascii_uppercase())
}

fn trim_text(source: &str, span: Option<Span>) -> Option<String> {
    span.and_then(|sp| slice_span(source, sp))
        .map(|t| t.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn target_from_span(source: &str, span: Span) -> ComputePoolTarget {
    ComputePoolTarget {
        name: slice_span(source, span).unwrap_or("").trim().to_string(),
        span,
    }
}
