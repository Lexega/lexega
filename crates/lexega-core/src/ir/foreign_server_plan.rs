// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! IR-side carrier for the SQL/MED `CREATE SERVER … FOREIGN DATA WRAPPER`
//! statement (PostgreSQL foreign-data-wrapper federation).
//!
//! Sibling-tier carrier analogous to [`super::ConnectionPlan`]: a typed
//! projection of [`crate::ast::types::AstCreateForeignServer`] that
//! `derive_facts_from_foreign_server_plan` folds into the public
//! `StatementFacts.ddl.foreign_server` carrier.
//!
//! Carries the foreign-data-wrapper name (the recognition discriminator),
//! whether a TYPE clause and an OPTIONS bag are present. OPTION values are
//! dropped at the AST→IR boundary — they can name hosts and are not surfaced.

use crate::ast::types::{AstAlterForeignServer, AstCreateForeignServer};
use crate::ast::NodeId;
use crate::lexer::token::Span;

/// Lifecycle action of a foreign-server statement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ForeignServerAction {
    Create,
    Alter,
}

#[derive(Debug, Clone)]
pub struct ForeignServerPlan {
    pub action: ForeignServerAction,
    pub name: String,
    pub name_span: Span,
    /// `IF NOT EXISTS` present (CREATE only).
    pub if_not_exists: bool,
    /// `TYPE '…'` clause present (CREATE only).
    pub type_present: bool,
    /// Lowercased foreign-data-wrapper name (CREATE only — `ALTER SERVER`
    /// cannot change the wrapper).
    pub wrapper: Option<String>,
    /// `OPTIONS (…)` clause present / modified.
    pub options_present: bool,
    pub node_id: NodeId,
    pub span: Span,
}

pub fn lower_create_foreign_server_to_plan(
    s: &AstCreateForeignServer,
    source: &str,
) -> ForeignServerPlan {
    let name = source
        .get(s.name_span.start as usize..s.name_span.end as usize)
        .unwrap_or("")
        .trim()
        .to_string();
    ForeignServerPlan {
        action: ForeignServerAction::Create,
        name,
        name_span: s.name_span,
        if_not_exists: s.if_not_exists,
        type_present: s.type_present,
        wrapper: s.wrapper.clone(),
        options_present: s.options_present,
        node_id: s.node_id,
        span: s.span,
    }
}

pub fn lower_alter_foreign_server_to_plan(
    s: &AstAlterForeignServer,
    source: &str,
) -> ForeignServerPlan {
    let name = source
        .get(s.name_span.start as usize..s.name_span.end as usize)
        .unwrap_or("")
        .trim()
        .to_string();
    ForeignServerPlan {
        action: ForeignServerAction::Alter,
        name,
        name_span: s.name_span,
        if_not_exists: false,
        type_present: false,
        wrapper: None,
        options_present: s.options_present,
        node_id: s.node_id,
        span: s.span,
    }
}
