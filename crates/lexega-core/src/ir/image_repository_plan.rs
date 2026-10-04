// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! IR-side carrier for Snowflake `CREATE / ALTER / DROP IMAGE REPOSITORY`.
//!
//! Sibling-tier carrier analogous to [`super::GitRepositoryPlan`]: typed
//! projection of the AST that `derive_facts_from_image_repository_plan` folds
//! into the public `StatementFacts.ddl.image_repository` carrier.
//!
//! An image repository is an OCI registry that Snowpark Container Services
//! pull container images from. It carries no governance value-slots (only
//! COMMENT / TAG); the recognition surface is its existence, whether it
//! replaces an existing registry (`or_replace`, carried in generic
//! `ddl.options`), and the ALTER action taken.

use crate::ast::{
    types::AstImageRepositoryAction, AstAlterImageRepository, AstCreateImageRepository, AstDrop,
    NodeId,
};
use crate::ir::utils::slice_span;
use crate::lexer::token::Span;

#[derive(Debug, Clone)]
pub struct ImageRepositoryPlan {
    pub action: ImageRepositoryAction,
    pub target: Option<ImageRepositoryTarget>,
    pub options: ImageRepositoryOptions,
    /// `ALTER IMAGE REPOSITORY` action variants in source order. Empty on
    /// CREATE / DROP (ALTER carries exactly one).
    pub(crate) actions: Vec<ImageRepositoryAlterActionIr>,
    pub node_id: NodeId,
    pub span: Span,
}

/// IR-internal mirror of [`crate::ast::types::AstImageRepositoryAction`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum ImageRepositoryAlterActionIr {
    Set,
    Unset,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ImageRepositoryAction {
    Create,
    Alter,
    Drop,
}

#[derive(Debug, Clone)]
pub struct ImageRepositoryTarget {
    pub name: String,
    pub span: Span,
}

#[derive(Debug, Clone, Default)]
pub struct ImageRepositoryOptions {
    pub or_replace: bool,
    pub if_not_exists: bool,
    pub if_exists: bool,
}

/// Lower a typed [`AstCreateImageRepository`] into an [`ImageRepositoryPlan`].
pub fn lower_create_image_repository_to_image_repository_plan(
    s: &AstCreateImageRepository,
    source: &str,
) -> ImageRepositoryPlan {
    ImageRepositoryPlan {
        action: ImageRepositoryAction::Create,
        target: Some(target_from_span(source, s.name_span)),
        options: ImageRepositoryOptions {
            or_replace: s.or_replace_span.is_some(),
            if_not_exists: s.if_not_exists_span.is_some(),
            if_exists: false,
        },
        actions: Vec::new(),
        node_id: s.node_id,
        span: s.span,
    }
}

/// Lower a typed [`AstAlterImageRepository`] into an [`ImageRepositoryPlan`].
pub fn lower_alter_image_repository_to_image_repository_plan(
    s: &AstAlterImageRepository,
    source: &str,
) -> ImageRepositoryPlan {
    ImageRepositoryPlan {
        action: ImageRepositoryAction::Alter,
        target: Some(target_from_span(source, s.name_span)),
        options: ImageRepositoryOptions {
            or_replace: false,
            if_not_exists: false,
            if_exists: s.if_exists_span.is_some(),
        },
        actions: vec![classify_alter_action(s.action)],
        node_id: s.node_id,
        span: s.span,
    }
}

/// Lower a generic [`AstDrop`] whose object type is IMAGE REPOSITORY.
/// The caller gates on the object type.
pub fn lower_drop_image_repository_to_image_repository_plan(
    s: &AstDrop,
    source: &str,
) -> ImageRepositoryPlan {
    ImageRepositoryPlan {
        action: ImageRepositoryAction::Drop,
        target: s
            .target_name_span
            .map(|span| target_from_span(source, span)),
        options: ImageRepositoryOptions {
            or_replace: false,
            if_not_exists: false,
            if_exists: s.if_exists_span.is_some(),
        },
        actions: Vec::new(),
        node_id: s.node_id,
        span: s.span,
    }
}

fn classify_alter_action(action: AstImageRepositoryAction) -> ImageRepositoryAlterActionIr {
    match action {
        AstImageRepositoryAction::Set => ImageRepositoryAlterActionIr::Set,
        AstImageRepositoryAction::Unset => ImageRepositoryAlterActionIr::Unset,
    }
}

fn target_from_span(source: &str, span: Span) -> ImageRepositoryTarget {
    ImageRepositoryTarget {
        name: slice_span(source, span).unwrap_or("").trim().to_string(),
        span,
    }
}
