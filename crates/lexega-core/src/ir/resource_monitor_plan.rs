// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! IR-side carrier for Snowflake `CREATE / ALTER / DROP RESOURCE MONITOR`.
//!
//! Sibling-tier carrier analogous to [`super::NetworkRulePlan`]: typed
//! projection of the AST that `derive_facts_from_resource_monitor_plan`
//! folds into the public `StatementFacts.ddl.resource_monitor` carrier.
//!
//! A resource monitor is a compute cost-governance object: it caps credit
//! usage on the warehouses it governs and fires `TRIGGERS` when usage
//! crosses a threshold. A trigger's action — `SUSPEND` / `SUSPEND_IMMEDIATE`
//! halt compute, `NOTIFY` only alerts — determines whether the monitor
//! enforces a hard cap or merely observes. The trigger thresholds and
//! actions are the governance surface; which thresholds or actions are
//! acceptable is YAML policy.

use crate::ast::{AstAlterResourceMonitor, AstCreateResourceMonitor, AstDrop, NodeId};
use crate::ir::utils::slice_span;
use crate::lexer::token::Span;

#[derive(Debug, Clone)]
pub struct ResourceMonitorPlan {
    pub action: ResourceMonitorAction,
    pub target: Option<ResourceMonitorTarget>,
    pub options: ResourceMonitorOptions,
    /// A `CREDIT_QUOTA = …` assignment was present (CREATE or ALTER SET).
    pub credit_quota_set: bool,
    /// `FREQUENCY = <value>` (upper-cased), e.g. `MONTHLY`, `DAILY`.
    pub frequency: Option<String>,
    /// `NOTIFY_USERS = (…)` entries, unquoted and trimmed.
    pub notify_users: Vec<String>,
    /// `TRIGGERS ON <pct> PERCENT DO <action>` definitions in order.
    pub triggers: Vec<ResourceMonitorTriggerIr>,
    /// A `TRIGGERS` clause was supplied (CREATE or ALTER SET).
    pub triggers_present: bool,
    pub node_id: NodeId,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct ResourceMonitorTriggerIr {
    /// The `<pct>` threshold text (digits as written).
    pub threshold: Option<String>,
    /// `{SUSPEND | SUSPEND_IMMEDIATE | NOTIFY}` action (upper-cased).
    pub action: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ResourceMonitorAction {
    Create,
    Alter,
    Drop,
}

#[derive(Debug, Clone)]
pub struct ResourceMonitorTarget {
    pub name: String,
    pub span: Span,
}

#[derive(Debug, Clone, Default)]
pub struct ResourceMonitorOptions {
    pub or_replace: bool,
    pub if_not_exists: bool,
    pub if_exists: bool,
}

/// Lower a typed [`AstCreateResourceMonitor`] into a [`ResourceMonitorPlan`].
pub fn lower_create_resource_monitor_to_resource_monitor_plan(
    s: &AstCreateResourceMonitor,
    source: &str,
) -> ResourceMonitorPlan {
    ResourceMonitorPlan {
        action: ResourceMonitorAction::Create,
        target: Some(target_from_span(source, s.name_span)),
        options: ResourceMonitorOptions {
            or_replace: s.or_replace_span.is_some(),
            if_not_exists: s.if_not_exists_span.is_some(),
            if_exists: false,
        },
        credit_quota_set: s.credit_quota_span.is_some(),
        frequency: upper_text(source, s.frequency_value_span),
        notify_users: s
            .notify_users_span
            .map(|sp| split_paren_list(source, sp))
            .unwrap_or_default(),
        triggers: lower_triggers(source, &s.triggers),
        triggers_present: !s.triggers.is_empty(),
        node_id: s.node_id,
        span: s.span,
    }
}

/// Lower a typed [`AstAlterResourceMonitor`] into a [`ResourceMonitorPlan`].
pub fn lower_alter_resource_monitor_to_resource_monitor_plan(
    s: &AstAlterResourceMonitor,
    source: &str,
) -> ResourceMonitorPlan {
    ResourceMonitorPlan {
        action: ResourceMonitorAction::Alter,
        target: Some(target_from_span(source, s.name_span)),
        options: ResourceMonitorOptions {
            or_replace: false,
            if_not_exists: false,
            if_exists: s.if_exists_span.is_some(),
        },
        credit_quota_set: s.credit_quota_span.is_some(),
        frequency: upper_text(source, s.frequency_value_span),
        notify_users: s
            .notify_users_span
            .map(|sp| split_paren_list(source, sp))
            .unwrap_or_default(),
        triggers: lower_triggers(source, &s.triggers),
        triggers_present: s.triggers_present,
        node_id: s.node_id,
        span: s.span,
    }
}

/// Lower a generic [`AstDrop`] whose object type is RESOURCE MONITOR.
/// The caller gates on the object type.
pub fn lower_drop_resource_monitor_to_resource_monitor_plan(
    s: &AstDrop,
    source: &str,
) -> ResourceMonitorPlan {
    ResourceMonitorPlan {
        action: ResourceMonitorAction::Drop,
        target: s
            .target_name_span
            .map(|span| target_from_span(source, span)),
        options: ResourceMonitorOptions {
            or_replace: false,
            if_not_exists: false,
            if_exists: s.if_exists_span.is_some(),
        },
        credit_quota_set: false,
        frequency: None,
        notify_users: Vec::new(),
        triggers: Vec::new(),
        triggers_present: false,
        node_id: s.node_id,
        span: s.span,
    }
}

fn lower_triggers(
    source: &str,
    triggers: &[crate::ast::AstResourceMonitorTrigger],
) -> Vec<ResourceMonitorTriggerIr> {
    triggers
        .iter()
        .map(|t| ResourceMonitorTriggerIr {
            threshold: slice_span(source, t.threshold_span).map(|s| s.trim().to_string()),
            action: slice_span(source, t.action_span)
                .unwrap_or("")
                .trim()
                .to_ascii_uppercase(),
        })
        .collect()
}

/// Split a parenthesized list (`(a, b)`) into unquoted trimmed entries.
fn split_paren_list(source: &str, span: Span) -> Vec<String> {
    slice_span(source, span)
        .unwrap_or("")
        .trim()
        .trim_start_matches('(')
        .trim_end_matches(')')
        .split(',')
        .map(|s| s.trim().trim_matches('\''))
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect()
}

fn upper_text(source: &str, span: Option<Span>) -> Option<String> {
    span.and_then(|sp| slice_span(source, sp))
        .map(|t| t.trim().to_ascii_uppercase())
}

fn target_from_span(source: &str, span: Span) -> ResourceMonitorTarget {
    ResourceMonitorTarget {
        name: slice_span(source, span).unwrap_or("").trim().to_string(),
        span,
    }
}
