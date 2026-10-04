// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! IR-side carrier for Snowflake `CREATE / ALTER / DROP STREAMLIT`.
//!
//! Sibling-tier carrier analogous to [`super::ImageRepositoryPlan`]: typed
//! projection of the AST that `derive_facts_from_streamlit_plan` folds into the
//! public `StatementFacts.ddl.streamlit` carrier.
//!
//! A Streamlit object runs a Python app from a stage location. The governance
//! recognition surface is whether it declares `EXTERNAL_ACCESS_INTEGRATIONS`
//! (the app can reach external network endpoints); which integrations are
//! acceptable is YAML.

use crate::ast::{
    types::AstStreamlitAction, AstAlterStreamlit, AstCreateStreamlit, AstDrop, NodeId,
};
use crate::ir::utils::slice_span;
use crate::lexer::token::Span;

#[derive(Debug, Clone)]
pub struct StreamlitPlan {
    pub action: StreamlitAction,
    pub target: Option<StreamlitTarget>,
    pub options: StreamlitOptions,
    /// `EXTERNAL_ACCESS_INTEGRATIONS = (...)` present — the app declares
    /// network egress. Populated on CREATE and `ALTER … SET`.
    pub has_external_access_integrations: bool,
    /// `ALTER STREAMLIT` action variants in source order. Empty on CREATE /
    /// DROP (ALTER carries exactly one).
    pub(crate) actions: Vec<StreamlitAlterActionIr>,
    pub node_id: NodeId,
    pub span: Span,
}

/// IR-internal mirror of [`crate::ast::types::AstStreamlitAction`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum StreamlitAlterActionIr {
    Set,
    Unset,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StreamlitAction {
    Create,
    Alter,
    Drop,
}

#[derive(Debug, Clone)]
pub struct StreamlitTarget {
    pub name: String,
    pub span: Span,
}

#[derive(Debug, Clone, Default)]
pub struct StreamlitOptions {
    pub or_replace: bool,
    pub if_not_exists: bool,
    pub if_exists: bool,
}

/// Lower a typed [`AstCreateStreamlit`] into a [`StreamlitPlan`].
pub fn lower_create_streamlit_to_streamlit_plan(
    s: &AstCreateStreamlit,
    source: &str,
) -> StreamlitPlan {
    StreamlitPlan {
        action: StreamlitAction::Create,
        target: Some(target_from_span(source, s.name_span)),
        options: StreamlitOptions {
            or_replace: s.or_replace_span.is_some(),
            if_not_exists: s.if_not_exists_span.is_some(),
            if_exists: false,
        },
        has_external_access_integrations: s.external_access_integrations_span.is_some(),
        actions: Vec::new(),
        node_id: s.node_id,
        span: s.span,
    }
}

/// Lower a typed [`AstAlterStreamlit`] into a [`StreamlitPlan`].
pub fn lower_alter_streamlit_to_streamlit_plan(
    s: &AstAlterStreamlit,
    source: &str,
) -> StreamlitPlan {
    StreamlitPlan {
        action: StreamlitAction::Alter,
        target: Some(target_from_span(source, s.name_span)),
        options: StreamlitOptions {
            or_replace: false,
            if_not_exists: false,
            if_exists: s.if_exists_span.is_some(),
        },
        has_external_access_integrations: s.external_access_integrations_span.is_some(),
        actions: vec![classify_alter_action(s.action)],
        node_id: s.node_id,
        span: s.span,
    }
}

/// Lower a generic [`AstDrop`] whose object type is STREAMLIT.
/// The caller gates on the object type.
pub fn lower_drop_streamlit_to_streamlit_plan(s: &AstDrop, source: &str) -> StreamlitPlan {
    StreamlitPlan {
        action: StreamlitAction::Drop,
        target: s
            .target_name_span
            .map(|span| target_from_span(source, span)),
        options: StreamlitOptions {
            or_replace: false,
            if_not_exists: false,
            if_exists: s.if_exists_span.is_some(),
        },
        has_external_access_integrations: false,
        actions: Vec::new(),
        node_id: s.node_id,
        span: s.span,
    }
}

fn classify_alter_action(action: AstStreamlitAction) -> StreamlitAlterActionIr {
    match action {
        AstStreamlitAction::Set => StreamlitAlterActionIr::Set,
        AstStreamlitAction::Unset => StreamlitAlterActionIr::Unset,
    }
}

fn target_from_span(source: &str, span: Span) -> StreamlitTarget {
    StreamlitTarget {
        name: slice_span(source, span).unwrap_or("").trim().to_string(),
        span,
    }
}
