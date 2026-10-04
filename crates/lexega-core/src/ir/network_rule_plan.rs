// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! IR-side carrier for Snowflake `CREATE / ALTER / DROP NETWORK RULE`.
//!
//! Sibling-tier carrier analogous to [`super::SecretPlan`]: typed
//! projection of the AST that `derive_facts_from_network_rule_plan`
//! folds into the public `StatementFacts.ddl.network_rule` carrier.
//!
//! The VALUE_LIST entries are the actual network destinations/origins
//! (hosts, IPs, VPC endpoint ids) — the primitives that network
//! policies and external-access integrations reference by rule name.
//! Editing a rule changes network posture without touching any policy,
//! so the typed values are the exposure surface. Which destinations
//! are acceptable is YAML policy.

use crate::ast::{
    AstAlterNetworkRule, AstAlterNetworkRuleActionKind, AstCreateNetworkRule, AstDrop,
    AstObjectProperty, NodeId,
};
use crate::ir::utils::slice_span;
use crate::lexer::token::Span;

#[derive(Debug, Clone)]
pub struct NetworkRulePlan {
    pub action: NetworkRuleAction,
    pub target: Option<NetworkRuleTarget>,
    pub options: NetworkRuleOptions,
    /// `TYPE = <value>` (upper-cased), e.g. `IPV4`, `HOST_PORT`,
    /// `AWSVPCEID`, `COMPUTE_POOL`.
    pub rule_type: Option<String>,
    /// `MODE = <value>` (upper-cased): `INGRESS`, `INTERNAL_STAGE`,
    /// `SNOWFLAKE_MANAGED_STORAGE_VOLUME`, `EGRESS`.
    pub mode: Option<String>,
    /// `VALUE_LIST = (…)` entries, unquoted and trimmed.
    pub value_list: Vec<String>,
    /// A `VALUE_LIST` assignment was present (CREATE or ALTER SET).
    pub had_set_value_list: bool,
    /// Other property names written by `ALTER … SET` (upper-cased;
    /// TYPE / MODE / VALUE_LIST / COMMENT excluded).
    pub set_property_names: Vec<String>,
    /// Property names removed by `ALTER … UNSET` (upper-cased).
    pub unset_property_names: Vec<String>,
    pub node_id: NodeId,
    pub span: Span,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NetworkRuleAction {
    Create,
    Alter,
    Drop,
}

#[derive(Debug, Clone)]
pub struct NetworkRuleTarget {
    pub name: String,
    pub span: Span,
}

#[derive(Debug, Clone, Default)]
pub struct NetworkRuleOptions {
    pub or_replace: bool,
    pub if_not_exists: bool,
    pub if_exists: bool,
}

/// Lower a typed [`AstCreateNetworkRule`] into a [`NetworkRulePlan`].
pub fn lower_create_network_rule_to_network_rule_plan(
    s: &AstCreateNetworkRule,
    source: &str,
) -> NetworkRulePlan {
    let mut plan = NetworkRulePlan {
        action: NetworkRuleAction::Create,
        target: Some(target_from_span(source, s.name_span)),
        options: NetworkRuleOptions {
            or_replace: s.or_replace_span.is_some(),
            if_not_exists: s.if_not_exists_span.is_some(),
            if_exists: false,
        },
        rule_type: upper_text(source, s.type_value_span),
        mode: upper_text(source, s.mode_value_span),
        value_list: s
            .value_list_span
            .map(|sp| split_value_list(source, sp))
            .unwrap_or_default(),
        had_set_value_list: s.value_list_span.is_some(),
        set_property_names: Vec::new(),
        unset_property_names: Vec::new(),
        node_id: s.node_id,
        span: s.span,
    };
    fold_other_properties(&mut plan, &s.properties, source);
    plan
}

/// Lower a typed [`AstAlterNetworkRule`] into a [`NetworkRulePlan`].
///
/// Closed-enum exhaustive `match` over [`AstAlterNetworkRuleActionKind`].
pub fn lower_alter_network_rule_to_network_rule_plan(
    s: &AstAlterNetworkRule,
    source: &str,
) -> NetworkRulePlan {
    let mut plan = NetworkRulePlan {
        action: NetworkRuleAction::Alter,
        target: Some(target_from_span(source, s.name_span)),
        options: NetworkRuleOptions {
            or_replace: false,
            if_not_exists: false,
            if_exists: s.if_exists_span.is_some(),
        },
        rule_type: None,
        mode: None,
        value_list: Vec::new(),
        had_set_value_list: false,
        set_property_names: Vec::new(),
        unset_property_names: Vec::new(),
        node_id: s.node_id,
        span: s.span,
    };
    match &s.action.kind {
        AstAlterNetworkRuleActionKind::Set { properties, .. } => {
            for prop in properties {
                let Some(name) = slice_span(source, prop.name_span) else {
                    continue;
                };
                let name = name.trim().to_ascii_uppercase();
                match name.as_str() {
                    "VALUE_LIST" => {
                        plan.had_set_value_list = true;
                        if let Some(sp) = prop.value_span {
                            plan.value_list = split_value_list(source, sp);
                        }
                    }
                    "MODE" => {
                        plan.mode = prop
                            .value_span
                            .and_then(|sp| slice_span(source, sp))
                            .map(|t| t.trim().to_ascii_uppercase());
                    }
                    "COMMENT" => {}
                    _ => plan.set_property_names.push(name),
                }
            }
        }
        AstAlterNetworkRuleActionKind::Unset {
            property_name_spans,
            ..
        } => {
            plan.unset_property_names = property_name_spans
                .iter()
                .filter_map(|sp| slice_span(source, *sp))
                .map(|n| n.trim().to_ascii_uppercase())
                .collect();
        }
    }
    plan
}

/// Lower a generic [`AstDrop`] whose object type is NETWORK RULE.
/// The caller gates on the object type.
pub fn lower_drop_network_rule_to_network_rule_plan(s: &AstDrop, source: &str) -> NetworkRulePlan {
    NetworkRulePlan {
        action: NetworkRuleAction::Drop,
        target: s
            .target_name_span
            .map(|span| target_from_span(source, span)),
        options: NetworkRuleOptions {
            or_replace: false,
            if_not_exists: false,
            if_exists: s.if_exists_span.is_some(),
        },
        rule_type: None,
        mode: None,
        value_list: Vec::new(),
        had_set_value_list: false,
        set_property_names: Vec::new(),
        unset_property_names: Vec::new(),
        node_id: s.node_id,
        span: s.span,
    }
}

/// CREATE-body properties other than the four with dedicated slots.
fn fold_other_properties(plan: &mut NetworkRulePlan, properties: &[AstObjectProperty], src: &str) {
    for prop in properties {
        let Some(name) = slice_span(src, prop.name_span) else {
            continue;
        };
        let name = name.trim().to_ascii_uppercase();
        if !matches!(name.as_str(), "TYPE" | "MODE" | "VALUE_LIST" | "COMMENT") {
            plan.set_property_names.push(name);
        }
    }
}

/// Split a parenthesized literal list (`('a', 'b')`) into unquoted
/// trimmed entries.
fn split_value_list(source: &str, span: Span) -> Vec<String> {
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

fn target_from_span(source: &str, span: Span) -> NetworkRuleTarget {
    NetworkRuleTarget {
        name: slice_span(source, span).unwrap_or("").trim().to_string(),
        span,
    }
}
