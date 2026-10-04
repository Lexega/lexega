// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! IR-side carrier for `CREATE / ALTER / DROP CONNECTION` (Databricks
//! Unity Catalog foreign-connection lifecycle).
//!
//! Sibling-tier fact analogous to [`super::CatalogPlan`]: typed
//! projection of the AST that downstream
//! `derive_facts_from_connection_plan` folds into a public
//! `StatementFacts.ddl.connection` carrier.

use crate::ast::{
    types::AlterConnectionAction, AstAlterConnection, AstCreateConnection, AstDropConnection,
    NodeId,
};
use crate::lexer::token::Span;

#[derive(Debug, Clone)]
pub struct ConnectionPlan {
    pub action: ConnectionAction,
    pub target: Option<ConnectionTarget>,
    pub options: ConnectionOptions,
    /// True when the CREATE statement carries `TYPE <connector>`.
    pub type_present: bool,
    /// True when the CREATE statement carries `OPTIONS (…)`.
    pub options_present: bool,
    /// True when the CREATE statement carries `COMMENT '<text>'`.
    pub comment_present: bool,
    /// True for Snowflake `CREATE CONNECTION … AS REPLICA OF <src>` — an
    /// inbound replica of a connection in another account.
    pub is_replica: bool,
    /// Typed list of `ALTER CONNECTION` action variants in source order.
    /// Empty on `Create` and `Drop`.
    pub(crate) actions: Vec<IrConnectionAlterAction>,
    pub node_id: NodeId,
    pub span: Span,
}

/// IR-internal mirror of [`crate::ast::types::AlterConnectionAction`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum IrConnectionAlterAction {
    OwnerTo,
    RenameTo,
    Options,
    EnableFailover,
    DisableFailover,
    Primary,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConnectionAction {
    Create,
    Alter,
    Drop,
}

#[derive(Debug, Clone)]
pub struct ConnectionTarget {
    pub name: String,
    pub span: Span,
}

#[derive(Debug, Clone, Default)]
pub struct ConnectionOptions {
    pub if_not_exists: bool,
    pub if_exists: bool,
    /// `OR REPLACE` present (CREATE only).
    pub or_replace: bool,
}

pub fn lower_create_connection_to_connection_plan(
    s: &AstCreateConnection,
    source: &str,
) -> ConnectionPlan {
    ConnectionPlan {
        action: ConnectionAction::Create,
        target: Some(target_from_span(source, s.connection_name_span)),
        options: ConnectionOptions {
            if_not_exists: s.if_not_exists,
            if_exists: false,
            or_replace: s.or_replace_span.is_some(),
        },
        type_present: s.type_span.is_some(),
        options_present: s.options_span.is_some(),
        comment_present: s.comment_keyword_span.is_some(),
        is_replica: s.replica_of_span.is_some(),
        actions: Vec::new(),
        node_id: s.node_id,
        span: s.span,
    }
}

pub fn lower_alter_connection_to_connection_plan(
    s: &AstAlterConnection,
    source: &str,
) -> ConnectionPlan {
    let action = classify_alter_action(&s.action);
    ConnectionPlan {
        action: ConnectionAction::Alter,
        target: Some(target_from_span(source, s.connection_name_span)),
        options: ConnectionOptions::default(),
        type_present: false,
        options_present: false,
        comment_present: false,
        is_replica: false,
        actions: vec![action],
        node_id: s.node_id,
        span: s.span,
    }
}

pub fn lower_drop_connection_to_connection_plan(
    s: &AstDropConnection,
    source: &str,
) -> ConnectionPlan {
    ConnectionPlan {
        action: ConnectionAction::Drop,
        target: Some(target_from_span(source, s.connection_name_span)),
        options: ConnectionOptions {
            if_not_exists: false,
            if_exists: s.if_exists,
            or_replace: false,
        },
        type_present: false,
        options_present: false,
        comment_present: false,
        is_replica: false,
        actions: Vec::new(),
        node_id: s.node_id,
        span: s.span,
    }
}

fn classify_alter_action(action: &AlterConnectionAction) -> IrConnectionAlterAction {
    match action {
        AlterConnectionAction::OwnerTo { .. } => IrConnectionAlterAction::OwnerTo,
        AlterConnectionAction::RenameTo { .. } => IrConnectionAlterAction::RenameTo,
        AlterConnectionAction::Options { .. } => IrConnectionAlterAction::Options,
        AlterConnectionAction::EnableFailover { .. } => IrConnectionAlterAction::EnableFailover,
        AlterConnectionAction::DisableFailover { .. } => IrConnectionAlterAction::DisableFailover,
        AlterConnectionAction::Primary { .. } => IrConnectionAlterAction::Primary,
    }
}

fn target_from_span(source: &str, span: Span) -> ConnectionTarget {
    let raw = source
        .get(span.start as usize..span.end as usize)
        .unwrap_or("")
        .trim();
    ConnectionTarget {
        name: raw.to_string(),
        span,
    }
}
