// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! IR-side carrier for Snowflake `CREATE / ALTER / DROP CORTEX SEARCH SERVICE`.
//!
//! Sibling-tier carrier analogous to [`super::ServicePlan`]: typed projection
//! of the AST that `derive_facts_from_cortex_search_service_plan` folds into the
//! public `StatementFacts.ddl.cortex_search_service` carrier.
//!
//! A Cortex search service builds an AI (embedding-backed) search index over a
//! source query's rows. The governance recognition surface is the embedding
//! model (which model vectorizes the data) and that a source query is indexed;
//! which models are acceptable is YAML.

use crate::ast::{
    types::AstCortexSearchServiceAction, AstAlterCortexSearchService, AstCreateCortexSearchService,
    AstDrop, NodeId,
};
use crate::ir::utils::slice_span;
use crate::lexer::token::Span;

#[derive(Debug, Clone)]
pub struct CortexSearchServicePlan {
    pub action: CortexSearchServiceAction,
    pub target: Option<CortexSearchServiceTarget>,
    pub options: CortexSearchServiceOptions,
    /// `EMBEDDING_MODEL` value (dequoted, case-preserved) when declared.
    /// Populated on CREATE and `ALTER … SET`.
    pub embedding_model: Option<String>,
    /// The service declares an `AS <query>` source body. Set on CREATE.
    pub has_source_query: bool,
    /// `ALTER CORTEX SEARCH SERVICE` action variants in source order. Empty on
    /// CREATE / DROP (ALTER carries exactly one).
    pub(crate) actions: Vec<CortexSearchServiceAlterActionIr>,
    pub node_id: NodeId,
    pub span: Span,
}

/// IR-internal mirror of [`crate::ast::types::AstCortexSearchServiceAction`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum CortexSearchServiceAlterActionIr {
    Set,
    Unset,
    Resume,
    Suspend,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CortexSearchServiceAction {
    Create,
    Alter,
    Drop,
}

#[derive(Debug, Clone)]
pub struct CortexSearchServiceTarget {
    pub name: String,
    pub span: Span,
}

#[derive(Debug, Clone, Default)]
pub struct CortexSearchServiceOptions {
    pub or_replace: bool,
    pub if_not_exists: bool,
    pub if_exists: bool,
}

/// Lower a typed [`AstCreateCortexSearchService`] into a plan.
pub fn lower_create_cortex_search_service_to_plan(
    s: &AstCreateCortexSearchService,
    source: &str,
) -> CortexSearchServicePlan {
    CortexSearchServicePlan {
        action: CortexSearchServiceAction::Create,
        target: Some(target_from_span(source, s.name_span)),
        options: CortexSearchServiceOptions {
            or_replace: s.or_replace_span.is_some(),
            if_not_exists: s.if_not_exists_span.is_some(),
            if_exists: false,
        },
        embedding_model: dequote_text(source, s.embedding_model_span),
        has_source_query: s.source_query_span.is_some(),
        actions: Vec::new(),
        node_id: s.node_id,
        span: s.span,
    }
}

/// Lower a typed [`AstAlterCortexSearchService`] into a plan.
pub fn lower_alter_cortex_search_service_to_plan(
    s: &AstAlterCortexSearchService,
    source: &str,
) -> CortexSearchServicePlan {
    CortexSearchServicePlan {
        action: CortexSearchServiceAction::Alter,
        target: Some(target_from_span(source, s.name_span)),
        options: CortexSearchServiceOptions {
            or_replace: false,
            if_not_exists: false,
            if_exists: s.if_exists_span.is_some(),
        },
        embedding_model: dequote_text(source, s.embedding_model_span),
        has_source_query: false,
        actions: vec![classify_alter_action(s.action)],
        node_id: s.node_id,
        span: s.span,
    }
}

/// Lower a generic [`AstDrop`] whose object type is CORTEX SEARCH SERVICE.
/// The caller gates on the object type.
pub fn lower_drop_cortex_search_service_to_plan(
    s: &AstDrop,
    source: &str,
) -> CortexSearchServicePlan {
    CortexSearchServicePlan {
        action: CortexSearchServiceAction::Drop,
        target: s
            .target_name_span
            .map(|span| target_from_span(source, span)),
        options: CortexSearchServiceOptions {
            or_replace: false,
            if_not_exists: false,
            if_exists: s.if_exists_span.is_some(),
        },
        embedding_model: None,
        has_source_query: false,
        actions: Vec::new(),
        node_id: s.node_id,
        span: s.span,
    }
}

fn classify_alter_action(action: AstCortexSearchServiceAction) -> CortexSearchServiceAlterActionIr {
    match action {
        AstCortexSearchServiceAction::Set => CortexSearchServiceAlterActionIr::Set,
        AstCortexSearchServiceAction::Unset => CortexSearchServiceAlterActionIr::Unset,
        AstCortexSearchServiceAction::Resume => CortexSearchServiceAlterActionIr::Resume,
        AstCortexSearchServiceAction::Suspend => CortexSearchServiceAlterActionIr::Suspend,
    }
}

fn target_from_span(source: &str, span: Span) -> CortexSearchServiceTarget {
    CortexSearchServiceTarget {
        name: slice_span(source, span).unwrap_or("").trim().to_string(),
        span,
    }
}

/// Dequote a `'…'` value span, case-preserved (model identifiers are
/// case-sensitive). Mirrors the GIT REPOSITORY origin idiom.
fn dequote_text(source: &str, span: Option<Span>) -> Option<String> {
    span.and_then(|s| slice_span(source, s))
        .map(|t| t.trim().trim_matches('\'').trim().to_string())
}
