// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! IR-side carrier for the MySQL `CREATE EVENT` / `ALTER EVENT` statements
//! (scheduled SQL jobs).
//!
//! A typed projection of [`crate::ast::types::AstCreateEvent`] /
//! [`crate::ast::types::AstAlterEvent`] that
//! `derive_facts_from_event_plan` folds into the public
//! `StatementFacts.ddl.event` carrier. Carries the schedule kind (one-time vs
//! recurring), the `ON COMPLETION PRESERVE` flag, the enable state, and — for
//! ALTER — whether the schedule / body / name was changed. The `DO` body is
//! analyzed independently via the rule-engine flatten, not through this plan.

use crate::ast::types::{
    AstAlterEvent, AstCreateEvent, AstDefiner, AstDefinerPrincipal, EventEnableState,
    EventScheduleKind,
};
use crate::ast::NodeId;
use crate::lexer::token::Span;

/// Lowered `DEFINER =` clause — the account a routine runs under.
#[derive(Debug, Clone)]
pub struct DefinerLowered {
    /// True when an explicit account is named (not `CURRENT_USER`); the body
    /// then runs under that account's privileges regardless of the invoker.
    pub explicit: bool,
    /// The definer user name (dequoted), when explicit.
    pub user: Option<String>,
    /// The host part of a `user@host` definer, when present.
    pub host: Option<String>,
}

/// CREATE vs ALTER — drives `DdlAction` / `StatementKind` in the projection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventAction {
    Create,
    Alter,
}

#[derive(Debug, Clone)]
pub struct EventPlan {
    pub action: EventAction,
    /// Event name (verbatim source text), if recognized.
    pub name: Option<String>,
    pub name_span: Span,
    /// The `DEFINER =` security context, when present.
    pub definer: Option<DefinerLowered>,
    /// Schedule kind — `Some` for CREATE; `None` for ALTER (the kind is not
    /// the governance axis there, only whether a reschedule occurred).
    pub schedule_kind: Option<EventScheduleKind>,
    /// An `ON SCHEDULE` clause is present.
    pub schedule_present: bool,
    /// `ON COMPLETION PRESERVE` — the event survives after firing.
    pub on_completion_preserve: bool,
    /// Explicit enable state, when written.
    pub enable_state: Option<EventEnableState>,
    /// A `RENAME TO` clause is present (ALTER only).
    pub rename_present: bool,
    /// A `DO <stmt>` body is present (rebinds the scheduled SQL on ALTER).
    pub body_present: bool,
    pub node_id: NodeId,
    pub span: Span,
}

pub(crate) fn span_text(source: &str, span: Span) -> Option<String> {
    source
        .get(span.start as usize..span.end as usize)
        .map(|s| s.trim().to_string())
}

fn dequote(raw: &str) -> String {
    let t = raw.trim();
    let b = t.as_bytes();
    if t.len() >= 2
        && ((b[0] == b'\'' && b[t.len() - 1] == b'\'')
            || (b[0] == b'"' && b[t.len() - 1] == b'"')
            || (b[0] == b'`' && b[t.len() - 1] == b'`'))
    {
        return t[1..t.len() - 1].to_string();
    }
    t.to_string()
}

pub(crate) fn lower_definer(definer: &AstDefiner, source: &str) -> DefinerLowered {
    match &definer.principal {
        AstDefinerPrincipal::CurrentUser => DefinerLowered {
            explicit: false,
            user: None,
            host: None,
        },
        AstDefinerPrincipal::Named {
            user_span,
            host_span,
        } => DefinerLowered {
            explicit: true,
            user: span_text(source, *user_span).map(|u| dequote(&u)),
            host: host_span.and_then(|h| span_text(source, h)),
        },
    }
}

pub fn lower_create_event_to_plan(s: &AstCreateEvent, source: &str) -> EventPlan {
    EventPlan {
        action: EventAction::Create,
        name: span_text(source, s.name_span),
        name_span: s.name_span,
        definer: s.definer.as_ref().map(|d| lower_definer(d, source)),
        schedule_kind: Some(s.schedule_kind),
        schedule_present: true,
        on_completion_preserve: s.on_completion_preserve,
        enable_state: Some(s.enable_state),
        rename_present: false,
        body_present: s.body_stmt.is_some(),
        node_id: s.node_id,
        span: s.span,
    }
}

pub fn lower_alter_event_to_plan(s: &AstAlterEvent, source: &str) -> EventPlan {
    EventPlan {
        action: EventAction::Alter,
        name: span_text(source, s.name_span),
        name_span: s.name_span,
        definer: s.definer.as_ref().map(|d| lower_definer(d, source)),
        schedule_kind: None,
        schedule_present: s.schedule_present,
        // Not surfaced for ALTER — the alter node tracks only the
        // governance axes (reschedule / rename / enable / body rebind).
        on_completion_preserve: false,
        enable_state: s.enable_state,
        rename_present: s.rename_present,
        body_present: s.body_stmt.is_some(),
        node_id: s.node_id,
        span: s.span,
    }
}
