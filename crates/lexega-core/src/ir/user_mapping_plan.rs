// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! IR-side carrier for the SQL/MED `CREATE USER MAPPING` statement
//! (PostgreSQL FDW per-role foreign-server credentials).
//!
//! Sibling-tier carrier analogous to [`super::ForeignServerPlan`]: a typed
//! projection of [`crate::ast::types::AstCreateUserMapping`] that
//! `derive_facts_from_user_mapping_plan` folds into the public
//! `StatementFacts.ddl.user_mapping` carrier.
//!
//! Carries the foreign-server name, whether the mapping is `FOR PUBLIC`, and
//! the OPTIONS as a typed key / value-literal list. The remote password is
//! already registered for output redaction by the parser.

use crate::ast::types::{AstAlterUserMapping, AstCreateUserMapping, AstDropUserMapping};
use crate::ast::NodeId;
use crate::lexer::token::Span;

/// Lifecycle action of a user-mapping statement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UserMappingAction {
    Create,
    Alter,
    Drop,
}

#[derive(Debug, Clone)]
pub struct UserMappingPlan {
    pub action: UserMappingAction,
    /// Foreign-server name.
    pub server: String,
    pub server_span: Span,
    /// True when the mapping is `FOR PUBLIC` (applies to every local role).
    pub is_public: bool,
    /// `IF NOT EXISTS` present (CREATE).
    pub if_not_exists: bool,
    /// `IF EXISTS` present (DROP).
    pub if_exists: bool,
    /// OPTIONS entries: `(key, value_literal)`. `value_literal` is the
    /// quote-stripped string value, or `None` for a non-string value.
    pub options: Vec<UserMappingOptionIr>,
    pub node_id: NodeId,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct UserMappingOptionIr {
    pub key: String,
    pub value_literal: Option<String>,
}

fn span_text(source: &str, span: Span) -> String {
    source
        .get(span.start as usize..span.end as usize)
        .unwrap_or("")
        .trim()
        .to_string()
}

fn lower_options(
    source: &str,
    options: &[crate::ast::types::AstUserMappingOption],
) -> Vec<UserMappingOptionIr> {
    options
        .iter()
        .map(|o| UserMappingOptionIr {
            key: span_text(source, o.key_span),
            value_literal: o.value_literal_span.and_then(|v| {
                source
                    .get(v.start as usize..v.end as usize)
                    .map(|s| s.to_string())
            }),
        })
        .collect()
}

pub fn lower_create_user_mapping_to_plan(
    s: &AstCreateUserMapping,
    source: &str,
) -> UserMappingPlan {
    UserMappingPlan {
        action: UserMappingAction::Create,
        server: span_text(source, s.server_span),
        server_span: s.server_span,
        is_public: s.is_public,
        if_not_exists: s.if_not_exists,
        if_exists: false,
        options: lower_options(source, &s.options),
        node_id: s.node_id,
        span: s.span,
    }
}

pub fn lower_alter_user_mapping_to_plan(s: &AstAlterUserMapping, source: &str) -> UserMappingPlan {
    UserMappingPlan {
        action: UserMappingAction::Alter,
        server: span_text(source, s.server_span),
        server_span: s.server_span,
        is_public: s.is_public,
        if_not_exists: false,
        if_exists: false,
        options: lower_options(source, &s.options),
        node_id: s.node_id,
        span: s.span,
    }
}

pub fn lower_drop_user_mapping_to_plan(s: &AstDropUserMapping, source: &str) -> UserMappingPlan {
    UserMappingPlan {
        action: UserMappingAction::Drop,
        server: span_text(source, s.server_span),
        server_span: s.server_span,
        is_public: s.is_public,
        if_not_exists: false,
        if_exists: s.if_exists,
        options: Vec::new(),
        node_id: s.node_id,
        span: s.span,
    }
}
