// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! IR-side carrier for Snowflake `CREATE / ALTER / DROP LISTING`.
//!
//! Typed projection of the AST that `derive_facts_from_listing_plan` folds into
//! the public `StatementFacts.ddl.listing` carrier.
//!
//! A listing exposes a share or application package on the Snowflake
//! Marketplace (EXTERNAL = public) or a private data exchange. The governance
//! recognition surface is whether it is external and published, and what it
//! exposes; which exposures are acceptable is YAML.

use crate::ast::{types::AstListingAction, AstAlterListing, AstCreateListing, AstDrop, NodeId};
use crate::ir::utils::slice_span;
use crate::lexer::token::Span;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ListingAction {
    Create,
    Alter,
    Drop,
}

/// IR-internal mirror of [`crate::ast::types::AstListingAction`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum ListingAlterActionIr {
    Set,
    Unset,
    Other,
}

#[derive(Debug, Clone)]
pub struct ListingTarget {
    pub name: String,
    pub span: Span,
}

#[derive(Debug, Clone, Default)]
pub struct ListingOptions {
    pub or_replace: bool,
    pub if_not_exists: bool,
    pub if_exists: bool,
}

#[derive(Debug, Clone)]
pub struct ListingPlan {
    pub action: ListingAction,
    pub target: Option<ListingTarget>,
    pub options: ListingOptions,
    /// `EXTERNAL` — published to the public Marketplace.
    pub is_external: bool,
    /// `PUBLISH` value (CREATE or `ALTER … SET`).
    pub publish: Option<bool>,
    /// The shared object name the listing exposes.
    pub shared_object: Option<String>,
    pub(crate) actions: Vec<ListingAlterActionIr>,
    pub node_id: NodeId,
    pub span: Span,
}

pub fn lower_create_listing_to_plan(s: &AstCreateListing, source: &str) -> ListingPlan {
    ListingPlan {
        action: ListingAction::Create,
        target: Some(target_from_span(source, s.name_span)),
        options: ListingOptions {
            or_replace: s.or_replace_span.is_some(),
            if_not_exists: s.if_not_exists_span.is_some(),
            if_exists: false,
        },
        is_external: s.is_external,
        publish: bool_from_span(source, s.publish_span),
        shared_object: dequote_text(source, s.shared_object_span),
        actions: Vec::new(),
        node_id: s.node_id,
        span: s.span,
    }
}

pub fn lower_alter_listing_to_plan(s: &AstAlterListing, source: &str) -> ListingPlan {
    ListingPlan {
        action: ListingAction::Alter,
        target: Some(target_from_span(source, s.name_span)),
        options: ListingOptions {
            or_replace: false,
            if_not_exists: false,
            if_exists: s.if_exists_span.is_some(),
        },
        is_external: false,
        publish: bool_from_span(source, s.publish_span),
        shared_object: None,
        actions: vec![classify_alter_action(s.action)],
        node_id: s.node_id,
        span: s.span,
    }
}

pub fn lower_drop_listing_to_plan(s: &AstDrop, source: &str) -> ListingPlan {
    ListingPlan {
        action: ListingAction::Drop,
        target: s
            .target_name_span
            .map(|span| target_from_span(source, span)),
        options: ListingOptions {
            or_replace: false,
            if_not_exists: false,
            if_exists: s.if_exists_span.is_some(),
        },
        is_external: false,
        publish: None,
        shared_object: None,
        actions: Vec::new(),
        node_id: s.node_id,
        span: s.span,
    }
}

fn classify_alter_action(action: AstListingAction) -> ListingAlterActionIr {
    match action {
        AstListingAction::Set => ListingAlterActionIr::Set,
        AstListingAction::Unset => ListingAlterActionIr::Unset,
        AstListingAction::Other => ListingAlterActionIr::Other,
    }
}

fn target_from_span(source: &str, span: Span) -> ListingTarget {
    ListingTarget {
        name: slice_span(source, span).unwrap_or("").trim().to_string(),
        span,
    }
}

fn dequote_text(source: &str, span: Option<Span>) -> Option<String> {
    span.and_then(|s| slice_span(source, s))
        .map(|t| t.trim().trim_matches('\'').trim().to_string())
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
