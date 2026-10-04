// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! IR-side carrier for Snowflake `CREATE / ALTER / DROP SEMANTIC VIEW`.
//!
//! Sibling-tier carrier analogous to [`super::NotebookPlan`]: typed projection
//! of the AST that `derive_facts_from_semantic_view_plan` folds into the public
//! `StatementFacts.ddl.semantic_view` carrier.
//!
//! A semantic view is a named model over base tables. The governance recognition
//! surface is the base-table access surface (the data it exposes to query and BI
//! tools) plus which model blocks it declares; whether exposing a given table is
//! acceptable is YAML.

use crate::ast::{
    types::AstSemanticViewAction, AstAlterSemanticView, AstCreateSemanticView, AstDrop, NodeId,
};
use crate::ir::utils::slice_span;
use crate::lexer::token::Span;

#[derive(Debug, Clone)]
pub struct SemanticViewPlan {
    pub action: SemanticViewAction,
    pub target: Option<SemanticViewTarget>,
    pub options: SemanticViewOptions,
    /// Base (physical) tables the model is built over. Empty on ALTER / DROP.
    pub base_tables: Vec<SemanticViewBaseTable>,
    /// The model declares a RELATIONSHIPS block.
    pub has_relationships: bool,
    /// The model declares a FACTS block.
    pub has_facts: bool,
    /// The model declares a DIMENSIONS block.
    pub has_dimensions: bool,
    /// The model declares a METRICS block.
    pub has_metrics: bool,
    /// `ALTER SEMANTIC VIEW` action variants in source order. Empty on
    /// CREATE / DROP (ALTER carries exactly one).
    pub(crate) actions: Vec<SemanticViewAlterActionIr>,
    pub node_id: NodeId,
    pub span: Span,
}

/// A base-table reference resolved from a TABLES-block entry.
#[derive(Debug, Clone)]
pub struct SemanticViewBaseTable {
    /// The physical table name as written (qualified, case-preserved).
    pub name: String,
    pub span: Span,
}

/// IR-internal mirror of [`crate::ast::types::AstSemanticViewAction`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum SemanticViewAlterActionIr {
    Set,
    Unset,
    Rename,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SemanticViewAction {
    Create,
    Alter,
    Drop,
}

#[derive(Debug, Clone)]
pub struct SemanticViewTarget {
    pub name: String,
    pub span: Span,
}

#[derive(Debug, Clone, Default)]
pub struct SemanticViewOptions {
    pub or_replace: bool,
    pub if_not_exists: bool,
    pub if_exists: bool,
}

/// Lower a typed [`AstCreateSemanticView`] into a [`SemanticViewPlan`].
pub fn lower_create_semantic_view_to_semantic_view_plan(
    s: &AstCreateSemanticView,
    source: &str,
) -> SemanticViewPlan {
    let base_tables = s
        .tables
        .iter()
        .map(|t| SemanticViewBaseTable {
            name: slice_span(source, t.physical_span)
                .unwrap_or("")
                .trim()
                .to_string(),
            span: t.physical_span,
        })
        .collect();
    SemanticViewPlan {
        action: SemanticViewAction::Create,
        target: Some(target_from_span(source, s.name_span)),
        options: SemanticViewOptions {
            or_replace: s.or_replace_span.is_some(),
            if_not_exists: s.if_not_exists_span.is_some(),
            if_exists: false,
        },
        base_tables,
        has_relationships: s.relationships_span.is_some(),
        has_facts: s.facts_span.is_some(),
        has_dimensions: s.dimensions_span.is_some(),
        has_metrics: s.metrics_span.is_some(),
        actions: Vec::new(),
        node_id: s.node_id,
        span: s.span,
    }
}

/// Lower a typed [`AstAlterSemanticView`] into a [`SemanticViewPlan`].
pub fn lower_alter_semantic_view_to_semantic_view_plan(
    s: &AstAlterSemanticView,
    source: &str,
) -> SemanticViewPlan {
    SemanticViewPlan {
        action: SemanticViewAction::Alter,
        target: Some(target_from_span(source, s.name_span)),
        options: SemanticViewOptions {
            or_replace: false,
            if_not_exists: false,
            if_exists: s.if_exists_span.is_some(),
        },
        base_tables: Vec::new(),
        has_relationships: false,
        has_facts: false,
        has_dimensions: false,
        has_metrics: false,
        actions: vec![classify_alter_action(s.action)],
        node_id: s.node_id,
        span: s.span,
    }
}

/// Lower a generic [`AstDrop`] whose object type is SEMANTIC VIEW.
/// The caller gates on the object type.
pub fn lower_drop_semantic_view_to_semantic_view_plan(
    s: &AstDrop,
    source: &str,
) -> SemanticViewPlan {
    SemanticViewPlan {
        action: SemanticViewAction::Drop,
        target: s
            .target_name_span
            .map(|span| target_from_span(source, span)),
        options: SemanticViewOptions {
            or_replace: false,
            if_not_exists: false,
            if_exists: s.if_exists_span.is_some(),
        },
        base_tables: Vec::new(),
        has_relationships: false,
        has_facts: false,
        has_dimensions: false,
        has_metrics: false,
        actions: Vec::new(),
        node_id: s.node_id,
        span: s.span,
    }
}

fn classify_alter_action(action: AstSemanticViewAction) -> SemanticViewAlterActionIr {
    match action {
        AstSemanticViewAction::Set => SemanticViewAlterActionIr::Set,
        AstSemanticViewAction::Unset => SemanticViewAlterActionIr::Unset,
        AstSemanticViewAction::Rename => SemanticViewAlterActionIr::Rename,
    }
}

fn target_from_span(source: &str, span: Span) -> SemanticViewTarget {
    SemanticViewTarget {
        name: slice_span(source, span).unwrap_or("").trim().to_string(),
        span,
    }
}
