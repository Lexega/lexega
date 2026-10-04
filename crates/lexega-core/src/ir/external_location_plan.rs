// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! IR-side carrier for `CREATE / ALTER / DROP EXTERNAL LOCATION`
//! (Databricks Unity Catalog).
//!
//! Sibling-tier fact analogous to [`super::CatalogPlan`]: typed
//! projection of the AST that downstream
//! `derive_facts_from_external_location_plan` folds into a public
//! `StatementFacts.ddl.external_location` carrier.
//!
//! ALTER carries exactly one action per statement; the `Vec` shape
//! parallels the other DBX family carriers for uniform projection.

use crate::ast::{
    AlterExternalLocationAction, AstAlterExternalLocation, AstCreateExternalLocation,
    AstDropExternalLocation, NodeId,
};
use crate::lexer::token::Span;

#[derive(Debug, Clone)]
pub struct ExternalLocationPlan {
    pub action: ExternalLocationAction,
    pub target: Option<ExternalLocationTarget>,
    pub options: ExternalLocationOptions,
    /// True when the CREATE statement carries a URL clause. Always
    /// `false` on ALTER and DROP. (ALTER's URL-set surface is exposed
    /// via `IrExternalLocationAlterAction::SetUrl`.)
    pub url_present: bool,
    /// True when the CREATE statement carries `WITH (STORAGE CREDENTIAL
    /// <name>)`.
    pub storage_credential_present: bool,
    /// True when the CREATE statement carries `COMMENT '<text>'`.
    pub comment_present: bool,
    /// Typed list of `ALTER EXTERNAL LOCATION` action variants in source
    /// order. Empty on `Create` and `Drop`.
    pub(crate) actions: Vec<IrExternalLocationAlterAction>,
    pub node_id: NodeId,
    pub span: Span,
}

/// IR-internal mirror of [`crate::ast::AlterExternalLocationAction`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum IrExternalLocationAlterAction {
    RenameTo,
    SetUrl,
    SetStorageCredential,
    OwnerTo,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExternalLocationAction {
    Create,
    Alter,
    Drop,
}

#[derive(Debug, Clone)]
pub struct ExternalLocationTarget {
    pub name: String,
    pub span: Span,
}

#[derive(Debug, Clone, Default)]
pub struct ExternalLocationOptions {
    pub if_not_exists: bool,
    pub if_exists: bool,
}

pub fn lower_create_external_location_to_external_location_plan(
    s: &AstCreateExternalLocation,
    source: &str,
) -> ExternalLocationPlan {
    ExternalLocationPlan {
        action: ExternalLocationAction::Create,
        target: Some(target_from_span(source, s.location_name_span)),
        options: ExternalLocationOptions {
            if_not_exists: s.if_not_exists,
            if_exists: false,
        },
        // Per AST: URL keyword + value spans are always populated on
        // CREATE EXTERNAL LOCATION (parser requires the clause).
        url_present: true,
        storage_credential_present: true,
        comment_present: s.comment_keyword_span.is_some(),
        actions: Vec::new(),
        node_id: s.node_id,
        span: s.span,
    }
}

pub fn lower_alter_external_location_to_external_location_plan(
    s: &AstAlterExternalLocation,
    source: &str,
) -> ExternalLocationPlan {
    let action = classify_alter_action(&s.action);
    ExternalLocationPlan {
        action: ExternalLocationAction::Alter,
        target: Some(target_from_span(source, s.location_name_span)),
        options: ExternalLocationOptions::default(),
        url_present: false,
        storage_credential_present: false,
        comment_present: false,
        actions: vec![action],
        node_id: s.node_id,
        span: s.span,
    }
}

pub fn lower_drop_external_location_to_external_location_plan(
    s: &AstDropExternalLocation,
    source: &str,
) -> ExternalLocationPlan {
    ExternalLocationPlan {
        action: ExternalLocationAction::Drop,
        target: Some(target_from_span(source, s.location_name_span)),
        options: ExternalLocationOptions {
            if_not_exists: false,
            if_exists: s.if_exists_span.is_some(),
        },
        url_present: false,
        storage_credential_present: false,
        comment_present: false,
        actions: Vec::new(),
        node_id: s.node_id,
        span: s.span,
    }
}

fn classify_alter_action(action: &AlterExternalLocationAction) -> IrExternalLocationAlterAction {
    match action {
        AlterExternalLocationAction::RenameTo { .. } => IrExternalLocationAlterAction::RenameTo,
        AlterExternalLocationAction::SetUrl { .. } => IrExternalLocationAlterAction::SetUrl,
        AlterExternalLocationAction::SetStorageCredential { .. } => {
            IrExternalLocationAlterAction::SetStorageCredential
        }
        AlterExternalLocationAction::OwnerTo { .. } => IrExternalLocationAlterAction::OwnerTo,
    }
}

fn target_from_span(source: &str, span: Span) -> ExternalLocationTarget {
    let raw = source
        .get(span.start as usize..span.end as usize)
        .unwrap_or("")
        .trim();
    ExternalLocationTarget {
        name: raw.to_string(),
        span,
    }
}
