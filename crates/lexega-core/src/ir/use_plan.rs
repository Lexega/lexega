// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! IR-side carrier for `USE` session statements.
//!
//! Sibling-tier fact alongside [`super::PrivilegePlan`]: typed
//! projection of [`crate::ast::AstUse`] that downstream
//! `derive_facts_from_use_plan` folds into a public
//! `StatementFacts.use_stmt` carrier.
//!
//! `USE` is a session-context statement, not DDL — the public facts
//! payload sits at the top level of `StatementFacts` (next to
//! `policy_attachment` and `integration`) rather than under `ddl`.
//!
//! The lowering captures the closed [`UseKind`] (mirroring
//! [`crate::ast::AstUseKind`]) plus a single normalized identifier
//! for the target name. The first dotted component of `object_span`
//! is sliced and normalized via the standard
//! [`crate::ir::normalize_identifier`] helper; this drives
//! `SNW-ROLE-PRIV-USE`.

use crate::ast::{AstUse, AstUseKind, NodeId};
use crate::ir::normalize_identifier;
use crate::lexer::token::Span;

#[derive(Debug, Clone)]
pub struct UsePlan {
    pub kind: UseKind,
    pub target: Option<UseTarget>,
    pub node_id: NodeId,
    pub span: Span,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UseKind {
    /// `USE ROLE …`
    Role,
    /// `USE DATABASE …` (or bare `USE <db>` with the keyword elided)
    Database,
    /// `USE CATALOG …`
    Catalog,
    /// `USE SCHEMA …`
    Schema,
    /// `USE WAREHOUSE …`
    Warehouse,
    /// `USE SECONDARY ROLES …`
    SecondaryRoles,
}

/// Target-name carrier. Holds the raw token text and the
/// dialect-aware normalized form. For multi-part names
/// (`db.schema`) only the first component is kept — the rule-time
/// predicate operates on that first-component name.
#[derive(Debug, Clone, PartialEq)]
pub struct UseTarget {
    pub raw: String,
    pub normalized: String,
    pub span: Span,
}

/// Lower a typed [`AstUse`] into a [`UsePlan`].
///
/// Pure structural projection — the `kind` field maps 1:1 to the
/// closed [`UseKind`] enum and the `target` field carries the
/// first-component identifier with the standard normalization
/// applied. Empty-name spans yield `target: None`.
pub fn lower_use_to_use_plan(s: &AstUse, source: &str) -> UsePlan {
    let kind = lower_use_kind(s.kind);
    let target = first_component_target(source, s.object_span);
    UsePlan {
        kind,
        target,
        node_id: s.node_id,
        span: s.span,
    }
}

fn lower_use_kind(kind: AstUseKind) -> UseKind {
    match kind {
        AstUseKind::Role => UseKind::Role,
        AstUseKind::Database => UseKind::Database,
        AstUseKind::Catalog => UseKind::Catalog,
        AstUseKind::Schema => UseKind::Schema,
        AstUseKind::Warehouse => UseKind::Warehouse,
        AstUseKind::SecondaryRoles => UseKind::SecondaryRoles,
    }
}

fn first_component_target(source: &str, span: Span) -> Option<UseTarget> {
    let raw = source.get(span.start as usize..span.end as usize)?.trim();
    if raw.is_empty() {
        return None;
    }
    // Take the first dotted component before normalizing: the first
    // part is the role.
    let first = raw.split('.').next().unwrap_or(raw).trim();
    if first.is_empty() {
        return None;
    }
    Some(UseTarget {
        raw: first.to_string(),
        normalized: normalize_identifier(first),
        span,
    })
}
