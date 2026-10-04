// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! IR-side carrier for Snowflake `CREATE / ALTER / DROP GIT REPOSITORY`.
//!
//! Sibling-tier carrier analogous to [`super::ComputePoolPlan`]: typed
//! projection of the AST that `derive_facts_from_git_repository_plan` folds
//! into the public `StatementFacts.ddl.git_repository` carrier.
//!
//! A git repository object connects Snowflake to an external git remote
//! (`ORIGIN`) through an `API_INTEGRATION`, optionally authenticated with a
//! `GIT_CREDENTIALS` secret. Code in the repo can be executed via
//! `EXECUTE IMMEDIATE FROM`, so the origin, integration, and credential
//! reference are the recognition surface; which origins are trusted is YAML.

use crate::ast::{
    types::AstGitRepositoryAction, AstAlterGitRepository, AstCreateGitRepository, AstDrop, NodeId,
};
use crate::ir::utils::slice_span;
use crate::lexer::token::Span;

#[derive(Debug, Clone)]
pub struct GitRepositoryPlan {
    pub action: GitRepositoryAction,
    pub target: Option<GitRepositoryTarget>,
    pub options: GitRepositoryOptions,
    /// `API_INTEGRATION = <integration>` (upper-cased). Populated on CREATE
    /// and `ALTER … SET`.
    pub api_integration: Option<String>,
    /// `ORIGIN = '<url>'` (dequoted, case preserved — it is a URL).
    pub origin: Option<String>,
    /// `GIT_CREDENTIALS = <secret>` present — the repo references a secret.
    pub has_git_credentials: bool,
    /// `ALTER GIT REPOSITORY` action variants in source order. Empty on
    /// CREATE / DROP (ALTER carries exactly one).
    pub(crate) actions: Vec<GitRepositoryAlterActionIr>,
    pub node_id: NodeId,
    pub span: Span,
}

/// IR-internal mirror of [`crate::ast::types::AstGitRepositoryAction`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum GitRepositoryAlterActionIr {
    Set,
    Unset,
    Fetch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GitRepositoryAction {
    Create,
    Alter,
    Drop,
}

#[derive(Debug, Clone)]
pub struct GitRepositoryTarget {
    pub name: String,
    pub span: Span,
}

#[derive(Debug, Clone, Default)]
pub struct GitRepositoryOptions {
    pub or_replace: bool,
    pub if_not_exists: bool,
    pub if_exists: bool,
}

/// Lower a typed [`AstCreateGitRepository`] into a [`GitRepositoryPlan`].
pub fn lower_create_git_repository_to_git_repository_plan(
    s: &AstCreateGitRepository,
    source: &str,
) -> GitRepositoryPlan {
    GitRepositoryPlan {
        action: GitRepositoryAction::Create,
        target: Some(target_from_span(source, s.name_span)),
        options: GitRepositoryOptions {
            or_replace: s.or_replace_span.is_some(),
            if_not_exists: s.if_not_exists_span.is_some(),
            if_exists: false,
        },
        api_integration: upper_text(source, s.api_integration_span),
        origin: dequote_text(source, s.origin_span),
        has_git_credentials: s.git_credentials_span.is_some(),
        actions: Vec::new(),
        node_id: s.node_id,
        span: s.span,
    }
}

/// Lower a typed [`AstAlterGitRepository`] into a [`GitRepositoryPlan`].
pub fn lower_alter_git_repository_to_git_repository_plan(
    s: &AstAlterGitRepository,
    source: &str,
) -> GitRepositoryPlan {
    GitRepositoryPlan {
        action: GitRepositoryAction::Alter,
        target: Some(target_from_span(source, s.name_span)),
        options: GitRepositoryOptions {
            or_replace: false,
            if_not_exists: false,
            if_exists: s.if_exists_span.is_some(),
        },
        api_integration: upper_text(source, s.api_integration_span),
        origin: None,
        has_git_credentials: s.git_credentials_span.is_some(),
        actions: vec![classify_alter_action(s.action)],
        node_id: s.node_id,
        span: s.span,
    }
}

/// Lower a generic [`AstDrop`] whose object type is GIT REPOSITORY.
/// The caller gates on the object type.
pub fn lower_drop_git_repository_to_git_repository_plan(
    s: &AstDrop,
    source: &str,
) -> GitRepositoryPlan {
    GitRepositoryPlan {
        action: GitRepositoryAction::Drop,
        target: s
            .target_name_span
            .map(|span| target_from_span(source, span)),
        options: GitRepositoryOptions {
            or_replace: false,
            if_not_exists: false,
            if_exists: s.if_exists_span.is_some(),
        },
        api_integration: None,
        origin: None,
        has_git_credentials: false,
        actions: Vec::new(),
        node_id: s.node_id,
        span: s.span,
    }
}

fn classify_alter_action(action: AstGitRepositoryAction) -> GitRepositoryAlterActionIr {
    match action {
        AstGitRepositoryAction::Set => GitRepositoryAlterActionIr::Set,
        AstGitRepositoryAction::Unset => GitRepositoryAlterActionIr::Unset,
        AstGitRepositoryAction::Fetch => GitRepositoryAlterActionIr::Fetch,
    }
}

fn upper_text(source: &str, span: Option<Span>) -> Option<String> {
    span.and_then(|sp| slice_span(source, sp))
        .map(|t| t.trim().trim_matches('\'').trim().to_ascii_uppercase())
        .filter(|s| !s.is_empty())
}

fn dequote_text(source: &str, span: Option<Span>) -> Option<String> {
    span.and_then(|sp| slice_span(source, sp))
        .map(|t| t.trim().trim_matches('\'').trim().to_string())
        .filter(|s| !s.is_empty())
}

fn target_from_span(source: &str, span: Span) -> GitRepositoryTarget {
    GitRepositoryTarget {
        name: slice_span(source, span).unwrap_or("").trim().to_string(),
        span,
    }
}
