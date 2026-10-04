// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! IR-side carrier for Snowflake `ALTER SESSION { SET | UNSET }`.
//!
//! Sibling-tier carrier analogous to [`super::TagPlan`]: a typed projection of
//! [`AstAlterSession`] that `derive_facts_from_session_plan` folds into the
//! public `StatementFacts.ddl.session` carrier. Parameter names and values are
//! resolved from source at lowering; facts stay source-free.

use crate::ast::{AstAlterSession, AstAlterSessionAction, AstSessionValueKind, NodeId};
use crate::facts::ddl::SessionValueKind;
use crate::lexer::token::Span;

#[derive(Debug, Clone)]
pub struct SessionPlan {
    pub action: SessionAction,
    pub node_id: NodeId,
    pub span: Span,
}

/// The SET or UNSET action of an ALTER SESSION statement.
#[derive(Debug, Clone)]
pub enum SessionAction {
    /// `SET <param> = <value> [, …]`
    Set { params: Vec<SessionParamIr> },
    /// `UNSET <param> [, …]` — names only.
    Unset { params: Vec<String> },
}

/// One resolved `<param> = <value>` assignment.
#[derive(Debug, Clone)]
pub struct SessionParamIr {
    /// Parameter name, upper-cased (Snowflake session params are
    /// case-insensitive unquoted identifiers).
    pub name: String,
    /// Value text as written, single quotes stripped for string literals.
    pub value: String,
    /// Lexical kind of the value.
    pub value_kind: SessionValueKind,
}

/// Lower a typed [`AstAlterSession`] into a [`SessionPlan`].
///
/// Closed-enum exhaustive `match` over [`AstAlterSessionAction`] — no `_ =>`.
pub fn lower_alter_session_to_session_plan(s: &AstAlterSession, source: &str) -> SessionPlan {
    let action = match &s.action {
        AstAlterSessionAction::Set { params, .. } => SessionAction::Set {
            params: params
                .iter()
                .map(|p| {
                    let value_kind = lower_value_kind(p.value_kind);
                    let raw = unquote_literal(span_text(source, p.value_span).trim());
                    // Boolean literals are case-insensitive in SQL; canonicalize
                    // to upper-case so value predicates match any source casing
                    // (`= true` / `= TRUE`). String values stay verbatim — their
                    // case can be semantically significant (e.g. QUERY_TAG).
                    let value = if value_kind == SessionValueKind::Boolean {
                        raw.to_ascii_uppercase()
                    } else {
                        raw
                    };
                    SessionParamIr {
                        name: span_text(source, p.name_span).trim().to_ascii_uppercase(),
                        value,
                        value_kind,
                    }
                })
                .collect(),
        },
        AstAlterSessionAction::Unset { params, .. } => SessionAction::Unset {
            params: params
                .iter()
                .map(|p| span_text(source, p.name_span).trim().to_ascii_uppercase())
                .collect(),
        },
    };
    SessionPlan {
        action,
        node_id: s.node_id,
        span: s.span,
    }
}

fn lower_value_kind(k: AstSessionValueKind) -> SessionValueKind {
    match k {
        AstSessionValueKind::String => SessionValueKind::String,
        AstSessionValueKind::Number => SessionValueKind::Number,
        AstSessionValueKind::Boolean => SessionValueKind::Boolean,
        AstSessionValueKind::Other => SessionValueKind::Other,
    }
}

fn span_text(source: &str, span: Span) -> &str {
    source
        .get(span.start as usize..span.end as usize)
        .unwrap_or("")
}

/// Strip surrounding `'…'` quotes and fold `''` escapes; otherwise unchanged.
fn unquote_literal(raw: &str) -> String {
    if raw.len() >= 2 && raw.starts_with('\'') && raw.ends_with('\'') {
        raw[1..raw.len() - 1].replace("''", "'")
    } else {
        raw.to_string()
    }
}
