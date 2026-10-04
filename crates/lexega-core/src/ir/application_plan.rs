// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! IR-side carriers for Snowflake Native Apps:
//! `CREATE / ALTER / DROP APPLICATION` and `… APPLICATION PACKAGE`.
//!
//! Typed projections of the AST that the `derive_facts_from_application*` fns
//! fold into the public `StatementFacts.ddl.{application, application_package}`
//! carriers.
//!
//! An APPLICATION runs a provider's code in the consumer account; the FROM
//! source (a LISTING is external marketplace code) is the supply-chain
//! provenance and DEBUG_MODE is a security setting. An APPLICATION PACKAGE is a
//! provider container whose DISTRIBUTION scope governs external publication.
//! Which values are risky is YAML.

use crate::ast::{
    types::AstApplicationAction, AstAlterApplication, AstAlterApplicationPackage,
    AstCreateApplication, AstCreateApplicationPackage, AstDrop, NodeId,
};
use crate::ir::utils::slice_span;
use crate::lexer::token::Span;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ApplicationAction {
    Create,
    Alter,
    Drop,
}

/// IR-internal mirror of [`crate::ast::types::AstApplicationAction`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum ApplicationAlterActionIr {
    Set,
    Unset,
    Other,
}

#[derive(Debug, Clone)]
pub struct ApplicationTarget {
    pub name: String,
    pub span: Span,
}

#[derive(Debug, Clone, Default)]
pub struct ApplicationOptions {
    pub or_replace: bool,
    pub if_not_exists: bool,
    pub if_exists: bool,
}

#[derive(Debug, Clone)]
pub struct ApplicationPlan {
    pub action: ApplicationAction,
    pub target: Option<ApplicationTarget>,
    pub options: ApplicationOptions,
    /// Installed `FROM LISTING` (external marketplace) rather than a package.
    pub from_listing: bool,
    /// The source package / listing name (provenance).
    pub source_name: Option<String>,
    /// `DEBUG_MODE` value (CREATE or `ALTER … SET`).
    pub debug_mode: Option<bool>,
    pub(crate) actions: Vec<ApplicationAlterActionIr>,
    pub node_id: NodeId,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct ApplicationPackagePlan {
    pub action: ApplicationAction,
    pub target: Option<ApplicationTarget>,
    pub options: ApplicationOptions,
    /// `DISTRIBUTION` value (upper-cased): `INTERNAL` / `EXTERNAL`.
    pub distribution: Option<String>,
    pub(crate) actions: Vec<ApplicationAlterActionIr>,
    pub node_id: NodeId,
    pub span: Span,
}

// ─── APPLICATION ───

pub fn lower_create_application_to_plan(s: &AstCreateApplication, source: &str) -> ApplicationPlan {
    ApplicationPlan {
        action: ApplicationAction::Create,
        target: Some(target_from_span(source, s.name_span)),
        options: ApplicationOptions {
            or_replace: s.or_replace_span.is_some(),
            if_not_exists: s.if_not_exists_span.is_some(),
            if_exists: false,
        },
        from_listing: s.from_listing,
        source_name: dequote_text(source, s.source_name_span),
        debug_mode: bool_from_span(source, s.debug_mode_span),
        actions: Vec::new(),
        node_id: s.node_id,
        span: s.span,
    }
}

pub fn lower_alter_application_to_plan(s: &AstAlterApplication, source: &str) -> ApplicationPlan {
    ApplicationPlan {
        action: ApplicationAction::Alter,
        target: Some(target_from_span(source, s.name_span)),
        options: ApplicationOptions {
            or_replace: false,
            if_not_exists: false,
            if_exists: s.if_exists_span.is_some(),
        },
        from_listing: false,
        source_name: None,
        debug_mode: bool_from_span(source, s.debug_mode_span),
        actions: vec![classify_alter_action(s.action)],
        node_id: s.node_id,
        span: s.span,
    }
}

pub fn lower_drop_application_to_plan(s: &AstDrop, source: &str) -> ApplicationPlan {
    ApplicationPlan {
        action: ApplicationAction::Drop,
        target: s
            .target_name_span
            .map(|span| target_from_span(source, span)),
        options: ApplicationOptions {
            or_replace: false,
            if_not_exists: false,
            if_exists: s.if_exists_span.is_some(),
        },
        from_listing: false,
        source_name: None,
        debug_mode: None,
        actions: Vec::new(),
        node_id: s.node_id,
        span: s.span,
    }
}

// ─── APPLICATION PACKAGE ───

pub fn lower_create_application_package_to_plan(
    s: &AstCreateApplicationPackage,
    source: &str,
) -> ApplicationPackagePlan {
    ApplicationPackagePlan {
        action: ApplicationAction::Create,
        target: Some(target_from_span(source, s.name_span)),
        options: ApplicationOptions {
            or_replace: s.or_replace_span.is_some(),
            if_not_exists: s.if_not_exists_span.is_some(),
            if_exists: false,
        },
        distribution: upper_text(source, s.distribution_span),
        actions: Vec::new(),
        node_id: s.node_id,
        span: s.span,
    }
}

pub fn lower_alter_application_package_to_plan(
    s: &AstAlterApplicationPackage,
    source: &str,
) -> ApplicationPackagePlan {
    ApplicationPackagePlan {
        action: ApplicationAction::Alter,
        target: Some(target_from_span(source, s.name_span)),
        options: ApplicationOptions {
            or_replace: false,
            if_not_exists: false,
            if_exists: s.if_exists_span.is_some(),
        },
        distribution: upper_text(source, s.distribution_span),
        actions: vec![classify_alter_action(s.action)],
        node_id: s.node_id,
        span: s.span,
    }
}

pub fn lower_drop_application_package_to_plan(s: &AstDrop, source: &str) -> ApplicationPackagePlan {
    ApplicationPackagePlan {
        action: ApplicationAction::Drop,
        target: s
            .target_name_span
            .map(|span| target_from_span(source, span)),
        options: ApplicationOptions {
            or_replace: false,
            if_not_exists: false,
            if_exists: s.if_exists_span.is_some(),
        },
        distribution: None,
        actions: Vec::new(),
        node_id: s.node_id,
        span: s.span,
    }
}

// ─── helpers ───

fn classify_alter_action(action: AstApplicationAction) -> ApplicationAlterActionIr {
    match action {
        AstApplicationAction::Set => ApplicationAlterActionIr::Set,
        AstApplicationAction::Unset => ApplicationAlterActionIr::Unset,
        AstApplicationAction::Other => ApplicationAlterActionIr::Other,
    }
}

fn target_from_span(source: &str, span: Span) -> ApplicationTarget {
    ApplicationTarget {
        name: slice_span(source, span).unwrap_or("").trim().to_string(),
        span,
    }
}

/// Dequote a `'…'` value span (or return a bare identifier), case-preserved.
fn dequote_text(source: &str, span: Option<Span>) -> Option<String> {
    span.and_then(|s| slice_span(source, s))
        .map(|t| t.trim().trim_matches('\'').trim().to_string())
}

/// Upper-case a value span (for keyword-valued properties like DISTRIBUTION).
fn upper_text(source: &str, span: Option<Span>) -> Option<String> {
    span.and_then(|s| slice_span(source, s))
        .map(|t| t.trim().to_ascii_uppercase())
}

/// Parse a `TRUE` / `FALSE` value span into a bool.
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
