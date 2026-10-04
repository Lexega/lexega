// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! IR-side carrier for Snowflake `ALTER ACCOUNT SET / UNSET <param>`.
//!
//! Account-level parameters govern account-wide security posture
//! (data-unload restrictions, account network policy, key rotation,
//! retention). This carrier resolves the parameter names and values from
//! the source so the facts stay source-free. The AUTHENTICATION POLICY
//! attachment slice is handled by [`super::PolicyAttachmentPlan`]; this
//! plan covers only the generic `SET/UNSET` parameter forms.

use crate::ast::{AstAlterAccount, AstAlterAccountActionKind, NodeId};
use crate::ir::utils::slice_span;
use crate::lexer::token::Span;

#[derive(Debug, Clone)]
pub struct AccountPlan {
    pub parameters_set: Vec<AccountParameterIr>,
    pub parameters_unset: Vec<AccountParameterIr>,
    pub node_id: NodeId,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct AccountParameterIr {
    /// Parameter name (upper-cased).
    pub name: String,
    /// Value text (upper-cased, unquoted); empty for UNSET.
    pub value: String,
}

/// Lower a generic `ALTER ACCOUNT SET/UNSET` into an [`AccountPlan`].
/// Returns `None` for the AUTHENTICATION POLICY attachment actions (those
/// flow through [`super::PolicyAttachmentPlan`]).
pub fn lower_alter_account_params_to_plan(
    s: &AstAlterAccount,
    source: &str,
) -> Option<AccountPlan> {
    match &s.action.kind {
        AstAlterAccountActionKind::Set { properties, .. } => {
            let parameters_set = properties
                .iter()
                .map(|p| AccountParameterIr {
                    name: upper(source, Some(p.name_span)),
                    value: upper(source, p.value_span),
                })
                .collect();
            Some(AccountPlan {
                parameters_set,
                parameters_unset: Vec::new(),
                node_id: s.node_id,
                span: s.span,
            })
        }
        AstAlterAccountActionKind::Unset {
            property_name_spans,
            ..
        } => {
            let parameters_unset = property_name_spans
                .iter()
                .map(|sp| AccountParameterIr {
                    name: upper(source, Some(*sp)),
                    value: String::new(),
                })
                .collect();
            Some(AccountPlan {
                parameters_set: Vec::new(),
                parameters_unset,
                node_id: s.node_id,
                span: s.span,
            })
        }
        AstAlterAccountActionKind::SetAuthenticationPolicy { .. }
        | AstAlterAccountActionKind::UnsetAuthenticationPolicy { .. } => None,
    }
}

/// Slice a span, trim, strip a trailing list comma (the shared property
/// value scanner includes the separator when a property is followed by
/// another), strip surrounding single quotes, and upper-case.
fn upper(source: &str, span: Option<Span>) -> String {
    span.and_then(|sp| slice_span(source, sp))
        .map(|t| {
            t.trim()
                .trim_end_matches(',')
                .trim()
                .trim_matches('\'')
                .trim()
                .to_ascii_uppercase()
        })
        .unwrap_or_default()
}
