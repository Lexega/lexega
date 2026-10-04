// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! IR-side carrier for Snowflake `CREATE / ALTER / DROP SECRET`.
//!
//! Sibling-tier carrier analogous to [`super::TagPlan`]: typed
//! projection of the AST that `derive_facts_from_secret_plan` folds
//! into the public `StatementFacts.ddl.secret` carrier.
//!
//! **Least-leak invariant:** secret VALUES (passwords, tokens, secret
//! strings) are never copied out of the source — the carrier records
//! which property NAMES were written, the TYPE discriminator, the
//! ENABLED flag, and the API_AUTHENTICATION integration reference
//! (a name, not a credential). Echoing secret values into facts would
//! leak them into reports and SARIF artifacts.

use crate::ast::{
    AstAlterSecret, AstAlterSecretActionKind, AstCreateSecret, AstDrop, AstObjectProperty, NodeId,
};
use crate::ir::integration_plan::read_enabled_bool;
use crate::ir::utils::slice_span;
use crate::lexer::token::Span;

#[derive(Debug, Clone)]
pub struct SecretPlan {
    pub action: SecretAction,
    pub target: Option<SecretTarget>,
    pub options: SecretOptions,
    /// `TYPE = <value>` (upper-cased), e.g. `OAUTH2`, `PASSWORD`,
    /// `GENERIC_STRING`, `SYMMETRIC_KEY`, `CLOUD_PROVIDER_TOKEN`.
    pub secret_type: Option<String>,
    /// `API_AUTHENTICATION = <integration>` — a reference to a
    /// security integration, not credential material.
    pub api_authentication: Option<String>,
    /// `ENABLED = TRUE | FALSE` when present.
    pub enabled: Option<bool>,
    /// Property NAMES written by CREATE or `ALTER … SET` (upper-cased;
    /// TYPE / COMMENT excluded). Values are intentionally not carried.
    pub set_property_names: Vec<String>,
    /// Property names removed by `ALTER … UNSET` (upper-cased).
    pub unset_property_names: Vec<String>,
    pub node_id: NodeId,
    pub span: Span,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SecretAction {
    Create,
    Alter,
    Drop,
}

#[derive(Debug, Clone)]
pub struct SecretTarget {
    pub name: String,
    pub span: Span,
}

#[derive(Debug, Clone, Default)]
pub struct SecretOptions {
    pub or_replace: bool,
    pub if_not_exists: bool,
    pub if_exists: bool,
}

/// Lower a typed [`AstCreateSecret`] into a [`SecretPlan`].
pub fn lower_create_secret_to_secret_plan(s: &AstCreateSecret, source: &str) -> SecretPlan {
    let mut plan = SecretPlan {
        action: SecretAction::Create,
        target: Some(target_from_span(source, s.name_span)),
        options: SecretOptions {
            or_replace: s.or_replace_span.is_some(),
            if_not_exists: s.if_not_exists_span.is_some(),
            if_exists: false,
        },
        secret_type: s
            .type_value_span
            .and_then(|sp| slice_span(source, sp))
            .map(|t| t.trim().to_ascii_uppercase()),
        api_authentication: None,
        enabled: None,
        set_property_names: Vec::new(),
        unset_property_names: Vec::new(),
        node_id: s.node_id,
        span: s.span,
    };
    fold_properties(&mut plan, &s.properties, source);
    plan
}

/// Lower a typed [`AstAlterSecret`] into a [`SecretPlan`].
///
/// Closed-enum exhaustive `match` over [`AstAlterSecretActionKind`].
pub fn lower_alter_secret_to_secret_plan(s: &AstAlterSecret, source: &str) -> SecretPlan {
    let mut plan = SecretPlan {
        action: SecretAction::Alter,
        target: Some(target_from_span(source, s.name_span)),
        options: SecretOptions {
            or_replace: false,
            if_not_exists: false,
            if_exists: s.if_exists_span.is_some(),
        },
        secret_type: None,
        api_authentication: None,
        enabled: None,
        set_property_names: Vec::new(),
        unset_property_names: Vec::new(),
        node_id: s.node_id,
        span: s.span,
    };
    match &s.action.kind {
        AstAlterSecretActionKind::Set { properties, .. } => {
            fold_properties(&mut plan, properties, source);
        }
        AstAlterSecretActionKind::Unset {
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

/// Lower a generic [`AstDrop`] whose object type is SECRET (no typed
/// drop AST exists). The caller gates on the object type.
pub fn lower_drop_secret_to_secret_plan(s: &AstDrop, source: &str) -> SecretPlan {
    SecretPlan {
        action: SecretAction::Drop,
        target: s
            .target_name_span
            .map(|span| target_from_span(source, span)),
        options: SecretOptions {
            or_replace: false,
            if_not_exists: false,
            if_exists: s.if_exists_span.is_some(),
        },
        secret_type: None,
        api_authentication: None,
        enabled: None,
        set_property_names: Vec::new(),
        unset_property_names: Vec::new(),
        node_id: s.node_id,
        span: s.span,
    }
}

/// Fold typed property pairs into the plan: TYPE / COMMENT are excluded
/// (dedicated slots), ENABLED and API_AUTHENTICATION get typed slots,
/// every other property contributes its NAME only.
fn fold_properties(plan: &mut SecretPlan, properties: &[AstObjectProperty], source: &str) {
    for prop in properties {
        let Some(name) = slice_span(source, prop.name_span) else {
            continue;
        };
        let name = name.trim().to_ascii_uppercase();
        match name.as_str() {
            "TYPE" | "COMMENT" => {}
            "ENABLED" => {
                if let Some(value_span) = prop.value_span {
                    plan.enabled = Some(read_enabled_bool(value_span, source));
                }
                plan.set_property_names.push(name);
            }
            "API_AUTHENTICATION" => {
                plan.api_authentication = prop
                    .value_span
                    .and_then(|sp| slice_span(source, sp))
                    .map(|t| t.trim().trim_matches('\'').to_string());
                plan.set_property_names.push(name);
            }
            _ => {
                plan.set_property_names.push(name);
            }
        }
    }
}

fn target_from_span(source: &str, span: Span) -> SecretTarget {
    SecretTarget {
        name: slice_span(source, span).unwrap_or("").trim().to_string(),
        span,
    }
}
