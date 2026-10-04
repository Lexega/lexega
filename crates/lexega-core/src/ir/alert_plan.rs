// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! IR-side carrier for Snowflake `CREATE / ALTER / DROP ALERT`.
//!
//! Sibling-tier carrier analogous to [`super::TaskPlan`]: an alert is a
//! scheduled object that evaluates a condition query and, when it holds,
//! runs an action statement under the alert owner's role. Same risk shape
//! as a task — automated SQL on a schedule.
//!
//! The carrier is intentionally **structural**, not verdict-shaped:
//!
//! - `create_options` names the clauses present (warehouse, schedule,
//!   condition) and the action body's parse status.
//! - `alter_actions` is a typed Vec of [`AstAlterAlertActionKind`]
//!   discriminators. Each rule predicate is a `kind: <action>` match
//!   inside `actions: { exists: … }`.
//!
//! Like the task body, the alert condition/action SQL is parsed (so it is
//! recognized, not fragmented) but not recursively rule-analyzed; only the
//! action's parse status flows to facts.

use crate::ast::{AstAlterAlert, AstAlterAlertActionKind, AstCreateAlert, AstDrop, NodeId};
use crate::ir::utils::slice_span;
use crate::lexer::token::Span;

#[derive(Debug, Clone)]
pub struct AlertPlan {
    pub action: AlertAction,
    pub target: Option<AlertTarget>,
    pub options: AlertOptions,
    /// Some only when `action == Create`.
    pub create_options: Option<AlertCreateOptionsShape>,
    /// Non-empty only when `action == Alter`.
    pub alter_actions: Vec<AlertAlterActionShape>,
    pub node_id: NodeId,
    pub span: Span,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AlertAction {
    Create,
    Alter,
    Drop,
}

#[derive(Debug, Clone)]
pub struct AlertTarget {
    pub name: String,
    pub schema: Option<String>,
    pub db: Option<String>,
    pub span: Span,
}

#[derive(Debug, Clone, Default)]
pub struct AlertOptions {
    pub or_replace: bool,
    pub if_not_exists: bool,
    pub if_exists: bool,
}

/// Structural projection of CREATE ALERT clauses.
#[derive(Debug, Clone, Default)]
pub struct AlertCreateOptionsShape {
    /// `WAREHOUSE = …` clause present.
    pub warehouse_present: bool,
    /// `SCHEDULE = …` clause present.
    pub schedule_present: bool,
    /// `IF (EXISTS (…))` condition clause present.
    pub condition_present: bool,
    /// `THEN <action>` body parse status.
    pub action_parse: AlertBodyParseStatusIr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum AlertBodyParseStatusIr {
    #[default]
    Parsed,
    Unparseable,
}

/// Typed projection of one `ALTER ALERT … <action>`.
#[derive(Debug, Clone)]
pub struct AlertAlterActionShape {
    pub kind: AlertAlterActionKindIr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AlertAlterActionKindIr {
    Resume,
    Suspend,
    Set,
    Unset,
    ModifyCondition,
    ModifyAction,
}

/// Lower a typed [`AstCreateAlert`] into an [`AlertPlan`].
pub fn lower_create_alert_to_alert_plan(s: &AstCreateAlert, source: &str) -> AlertPlan {
    let action_parse = match &s.action {
        Some(Err(_)) => AlertBodyParseStatusIr::Unparseable,
        _ => AlertBodyParseStatusIr::Parsed,
    };
    let create_options = AlertCreateOptionsShape {
        warehouse_present: s.warehouse_span.is_some(),
        schedule_present: s.schedule_span.is_some(),
        condition_present: s.condition_span.is_some(),
        action_parse,
    };
    AlertPlan {
        action: AlertAction::Create,
        target: Some(target_from_span(source, s.name_span)),
        options: AlertOptions {
            or_replace: s.or_replace_span.is_some(),
            if_not_exists: s.if_not_exists_span.is_some(),
            if_exists: false,
        },
        create_options: Some(create_options),
        alter_actions: Vec::new(),
        node_id: s.node_id,
        span: s.span,
    }
}

/// Lower a typed [`AstAlterAlert`] into an [`AlertPlan`].
///
/// Closed-enum exhaustive `match` over [`AstAlterAlertActionKind`].
pub fn lower_alter_alert_to_alert_plan(s: &AstAlterAlert, source: &str) -> AlertPlan {
    let action_shape = project_alter_action(&s.action.kind);
    AlertPlan {
        action: AlertAction::Alter,
        target: Some(target_from_span(source, s.name_span)),
        options: AlertOptions {
            or_replace: false,
            if_not_exists: false,
            if_exists: s.if_exists_span.is_some(),
        },
        create_options: None,
        alter_actions: vec![action_shape],
        node_id: s.node_id,
        span: s.span,
    }
}

/// Lower a generic [`AstDrop`] whose object type is ALERT.
/// The caller gates on the object type.
pub fn lower_drop_alert_to_alert_plan(s: &AstDrop, source: &str) -> AlertPlan {
    AlertPlan {
        action: AlertAction::Drop,
        target: s
            .target_name_span
            .map(|span| target_from_span(source, span)),
        options: AlertOptions {
            or_replace: false,
            if_not_exists: false,
            if_exists: s.if_exists_span.is_some(),
        },
        create_options: None,
        alter_actions: Vec::new(),
        node_id: s.node_id,
        span: s.span,
    }
}

fn project_alter_action(kind: &AstAlterAlertActionKind) -> AlertAlterActionShape {
    use AstAlterAlertActionKind as K;
    let kind_ir = match kind {
        K::Resume { .. } => AlertAlterActionKindIr::Resume,
        K::Suspend { .. } => AlertAlterActionKindIr::Suspend,
        K::Set { .. } => AlertAlterActionKindIr::Set,
        K::Unset { .. } => AlertAlterActionKindIr::Unset,
        K::ModifyCondition { .. } => AlertAlterActionKindIr::ModifyCondition,
        K::ModifyAction { .. } => AlertAlterActionKindIr::ModifyAction,
    };
    AlertAlterActionShape { kind: kind_ir }
}

fn target_from_span(source: &str, span: Span) -> AlertTarget {
    let raw = slice_span(source, span).unwrap_or("").trim();
    let parts: Vec<&str> = raw.split('.').collect();
    let (db, schema, name) = match parts.as_slice() {
        [n] => (None, None, (*n).to_string()),
        [s, n] => (None, Some((*s).to_string()), (*n).to_string()),
        [d, s, n] => (
            Some((*d).to_string()),
            Some((*s).to_string()),
            (*n).to_string(),
        ),
        _ => (None, None, raw.to_string()),
    };
    AlertTarget {
        name,
        schema,
        db,
        span,
    }
}
