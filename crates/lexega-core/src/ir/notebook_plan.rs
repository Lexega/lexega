// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! IR-side carrier for Snowflake `CREATE / ALTER / DROP NOTEBOOK`.
//!
//! Sibling-tier carrier analogous to [`super::StreamlitPlan`]: typed projection
//! of the AST that `derive_facts_from_notebook_plan` folds into the public
//! `StatementFacts.ddl.notebook` carrier.
//!
//! A notebook runs code from a stage location. The governance recognition
//! surface is whether it declares `EXTERNAL_ACCESS_INTEGRATIONS` (the notebook
//! can reach external network endpoints); which integrations are acceptable is
//! YAML.

use crate::ast::{types::AstNotebookAction, AstAlterNotebook, AstCreateNotebook, AstDrop, NodeId};
use crate::ir::utils::slice_span;
use crate::lexer::token::Span;

#[derive(Debug, Clone)]
pub struct NotebookPlan {
    pub action: NotebookAction,
    pub target: Option<NotebookTarget>,
    pub options: NotebookOptions,
    /// `EXTERNAL_ACCESS_INTEGRATIONS = (...)` present — the notebook declares
    /// network egress. Populated on CREATE and `ALTER … SET`.
    pub has_external_access_integrations: bool,
    /// `ALTER NOTEBOOK` action variants in source order. Empty on CREATE / DROP
    /// (ALTER carries exactly one).
    pub(crate) actions: Vec<NotebookAlterActionIr>,
    pub node_id: NodeId,
    pub span: Span,
}

/// IR-internal mirror of [`crate::ast::types::AstNotebookAction`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum NotebookAlterActionIr {
    Set,
    Unset,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NotebookAction {
    Create,
    Alter,
    Drop,
}

#[derive(Debug, Clone)]
pub struct NotebookTarget {
    pub name: String,
    pub span: Span,
}

#[derive(Debug, Clone, Default)]
pub struct NotebookOptions {
    pub or_replace: bool,
    pub if_not_exists: bool,
    pub if_exists: bool,
}

/// Lower a typed [`AstCreateNotebook`] into a [`NotebookPlan`].
pub fn lower_create_notebook_to_notebook_plan(s: &AstCreateNotebook, source: &str) -> NotebookPlan {
    NotebookPlan {
        action: NotebookAction::Create,
        target: Some(target_from_span(source, s.name_span)),
        options: NotebookOptions {
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

/// Lower a typed [`AstAlterNotebook`] into a [`NotebookPlan`].
pub fn lower_alter_notebook_to_notebook_plan(s: &AstAlterNotebook, source: &str) -> NotebookPlan {
    NotebookPlan {
        action: NotebookAction::Alter,
        target: Some(target_from_span(source, s.name_span)),
        options: NotebookOptions {
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

/// Lower a generic [`AstDrop`] whose object type is NOTEBOOK.
/// The caller gates on the object type.
pub fn lower_drop_notebook_to_notebook_plan(s: &AstDrop, source: &str) -> NotebookPlan {
    NotebookPlan {
        action: NotebookAction::Drop,
        target: s
            .target_name_span
            .map(|span| target_from_span(source, span)),
        options: NotebookOptions {
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

fn classify_alter_action(action: AstNotebookAction) -> NotebookAlterActionIr {
    match action {
        AstNotebookAction::Set => NotebookAlterActionIr::Set,
        AstNotebookAction::Unset => NotebookAlterActionIr::Unset,
    }
}

fn target_from_span(source: &str, span: Span) -> NotebookTarget {
    NotebookTarget {
        name: slice_span(source, span).unwrap_or("").trim().to_string(),
        span,
    }
}
