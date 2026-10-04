// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! IR-side carrier for Snowflake `CREATE / ALTER / DROP TASK`.
//!
//! Sibling-tier fact analogous to [`super::DynamicTablePlan`] and
//! [`super::PipePlan`]: typed projection of the AST that downstream
//! `derive_facts_from_task_plan` folds into a public
//! `StatementFacts.ddl.task` carrier.
//!
//! The carrier is intentionally **structural**, not verdict-shaped:
//!
//! - `create_options` — optional clause carriers (`execute_as`,
//!   `body.parse`, `overlap_policy`, `allow_overlapping_execution`)
//!   that name the SQL clauses, not the rule verdicts.
//! - `alter_actions` — typed Vec of [`AstAlterTaskActionKind`]
//!   discriminators. Each rule predicate is a `kind: <action>` match
//!   inside `actions: { exists: … }`.
//!
//! SNW-TASK-* rules predicate against the structural carrier; no fact
//! field is a renamed rule verdict.

use crate::ast::{AstAlterTask, AstAlterTaskActionKind, AstCreateTask, AstDropTask, NodeId};
use crate::lexer::token::Span;

#[derive(Debug, Clone)]
pub struct TaskPlan {
    pub action: TaskAction,
    pub target: Option<TaskTarget>,
    pub options: TaskOptions,
    /// Some only when `action == Create`.
    pub create_options: Option<TaskCreateOptionsShape>,
    /// Non-empty only when `action == Alter`.
    pub alter_actions: Vec<TaskAlterActionShape>,
    pub node_id: NodeId,
    pub span: Span,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TaskAction {
    Create,
    Alter,
    Drop,
}

#[derive(Debug, Clone)]
pub struct TaskTarget {
    pub name: String,
    pub schema: Option<String>,
    pub db: Option<String>,
    pub span: Span,
}

#[derive(Debug, Clone, Default)]
pub struct TaskOptions {
    pub or_replace: bool,
    pub or_alter: bool,
    pub if_not_exists: bool,
    pub if_exists: bool,
}

/// Structural projection of CREATE TASK clauses.
#[derive(Debug, Clone, Default)]
pub struct TaskCreateOptionsShape {
    /// `EXECUTE AS <role>` clause present.
    pub execute_as_present: bool,
    /// `AS <body>` clause parse status.
    pub body_parse: TaskBodyParseStatusIr,
    /// `OVERLAP_POLICY = …` value, if clause present.
    pub overlap_policy: Option<TaskOverlapPolicyIr>,
    /// Deprecated `ALLOW_OVERLAPPING_EXECUTION = …` value, if clause
    /// present *and* OVERLAP_POLICY is absent (OVERLAP_POLICY takes
    /// precedence).
    pub allow_overlapping_execution: Option<bool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum TaskBodyParseStatusIr {
    #[default]
    Parsed,
    Unparseable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TaskOverlapPolicyIr {
    NoOverlap,
    AllowChildOverlap,
    AllowAllOverlap,
}

/// Typed projection of one `ALTER TASK … <action>`.
#[derive(Debug, Clone)]
pub struct TaskAlterActionShape {
    pub kind: TaskAlterActionKindIr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TaskAlterActionKindIr {
    Resume,
    Suspend,
    AddAfter,
    RemoveAfter,
    Set,
    SetTag,
    SetFinalize,
    Unset,
    UnsetTag,
    UnsetFinalize,
    ModifyAs,
    ModifyWhen,
    RemoveWhen,
}

/// Lower a typed [`AstCreateTask`] into a [`TaskPlan`].
pub fn lower_create_task_to_task_plan(s: &AstCreateTask, source: &str) -> TaskPlan {
    let body_parse = match s.body {
        Some(Err(_)) => TaskBodyParseStatusIr::Unparseable,
        _ => TaskBodyParseStatusIr::Parsed,
    };

    let overlap_policy = s
        .overlap_policy_span
        .and_then(|span| classify_overlap_policy_clause(source, span));

    let allow_overlapping_execution = if overlap_policy.is_some() {
        // Precedence: when OVERLAP_POLICY is present, the
        // deprecated property is ignored.
        None
    } else {
        s.allow_overlapping_execution_span
            .map(|span| classify_allow_overlapping_execution_clause(source, span))
    };

    let create_options = TaskCreateOptionsShape {
        execute_as_present: s.execute_as_span.is_some(),
        body_parse,
        overlap_policy,
        allow_overlapping_execution,
    };

    TaskPlan {
        action: TaskAction::Create,
        target: Some(target_from_span(source, s.name_span)),
        options: TaskOptions {
            or_replace: s.or_replace_span.is_some(),
            or_alter: s.or_alter_span.is_some(),
            if_not_exists: s.if_not_exists_span.is_some(),
            if_exists: false,
        },
        create_options: Some(create_options),
        alter_actions: Vec::new(),
        node_id: s.node_id,
        span: s.span,
    }
}

/// Lower a typed [`AstAlterTask`] into a [`TaskPlan`].
///
/// Closed-enum exhaustive `match` over [`AstAlterTaskActionKind`] — no
/// `_ =>` arm.
pub fn lower_alter_task_to_task_plan(s: &AstAlterTask, source: &str) -> TaskPlan {
    let action_shape = project_alter_action(&s.action.kind);

    TaskPlan {
        action: TaskAction::Alter,
        target: Some(target_from_span(source, s.name_span)),
        options: TaskOptions {
            or_replace: false,
            or_alter: false,
            if_not_exists: false,
            if_exists: s.if_exists_span.is_some(),
        },
        create_options: None,
        alter_actions: vec![action_shape],
        node_id: s.node_id,
        span: s.span,
    }
}

/// Lower a typed [`AstDropTask`] into a [`TaskPlan`].
pub fn lower_drop_task_to_task_plan(s: &AstDropTask, source: &str) -> TaskPlan {
    TaskPlan {
        action: TaskAction::Drop,
        target: Some(target_from_span(source, s.name_span)),
        options: TaskOptions {
            or_replace: false,
            or_alter: false,
            if_not_exists: false,
            if_exists: s.if_exists_span.is_some(),
        },
        create_options: None,
        alter_actions: Vec::new(),
        node_id: s.node_id,
        span: s.span,
    }
}

fn project_alter_action(kind: &AstAlterTaskActionKind) -> TaskAlterActionShape {
    use AstAlterTaskActionKind as K;
    let kind_ir = match kind {
        K::Resume { .. } => TaskAlterActionKindIr::Resume,
        K::Suspend { .. } => TaskAlterActionKindIr::Suspend,
        K::AddAfter { .. } => TaskAlterActionKindIr::AddAfter,
        K::RemoveAfter { .. } => TaskAlterActionKindIr::RemoveAfter,
        K::Set { .. } => TaskAlterActionKindIr::Set,
        K::SetTag { .. } => TaskAlterActionKindIr::SetTag,
        K::SetFinalize { .. } => TaskAlterActionKindIr::SetFinalize,
        K::Unset { .. } => TaskAlterActionKindIr::Unset,
        K::UnsetTag { .. } => TaskAlterActionKindIr::UnsetTag,
        K::UnsetFinalize { .. } => TaskAlterActionKindIr::UnsetFinalize,
        K::ModifyAs { .. } => TaskAlterActionKindIr::ModifyAs,
        K::ModifyWhen { .. } => TaskAlterActionKindIr::ModifyWhen,
        K::RemoveWhen { .. } => TaskAlterActionKindIr::RemoveWhen,
    };
    TaskAlterActionShape { kind: kind_ir }
}

/// Decode `OVERLAP_POLICY = NO_OVERLAP | ALLOW_CHILD_OVERLAP |
/// ALLOW_ALL_OVERLAP` clause text into a typed value. Returns `None`
/// when the clause text matches none of the known values (defensive;
/// the parser captures the span but doesn't validate the value).
fn classify_overlap_policy_clause(source: &str, span: Span) -> Option<TaskOverlapPolicyIr> {
    let text = source.get(span.start as usize..span.end as usize)?;
    let upper = text.to_ascii_uppercase();
    if upper.contains("ALLOW_ALL_OVERLAP") {
        Some(TaskOverlapPolicyIr::AllowAllOverlap)
    } else if upper.contains("ALLOW_CHILD_OVERLAP") {
        Some(TaskOverlapPolicyIr::AllowChildOverlap)
    } else if upper.contains("NO_OVERLAP") {
        Some(TaskOverlapPolicyIr::NoOverlap)
    } else {
        None
    }
}

/// Decode the deprecated `ALLOW_OVERLAPPING_EXECUTION = TRUE | FALSE`
/// clause text: a case-insensitive `TRUE` containment check.
fn classify_allow_overlapping_execution_clause(source: &str, span: Span) -> bool {
    let Some(text) = source.get(span.start as usize..span.end as usize) else {
        return false;
    };
    text.to_ascii_uppercase().contains("TRUE")
}

fn target_from_span(source: &str, span: Span) -> TaskTarget {
    let raw = source
        .get(span.start as usize..span.end as usize)
        .unwrap_or("")
        .trim();
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
    TaskTarget {
        name,
        schema,
        db,
        span,
    }
}
