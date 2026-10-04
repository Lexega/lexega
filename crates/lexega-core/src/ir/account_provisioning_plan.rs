// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! IR-side carriers for Snowflake account provisioning:
//! `CREATE / DROP MANAGED ACCOUNT` (reader account) and `CREATE / DROP ACCOUNT`
//! (org-level account).
//!
//! Distinct from [`super::AccountPlan`], which covers `ALTER ACCOUNT` parameter
//! changes. These statements create/drop account objects. A managed (reader)
//! account consumes shares from outside the org — a data-sharing surface; which
//! account types are acceptable is YAML. Admin credentials supplied to these
//! statements are parsed but never carried into facts.

use crate::ast::{AstCreateAccount, AstCreateManagedAccount, AstDrop, NodeId};
use crate::ir::utils::slice_span;
use crate::lexer::token::Span;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AccountProvisioningAction {
    Create,
    Drop,
}

#[derive(Debug, Clone)]
pub struct AccountProvisioningTarget {
    pub name: String,
    pub span: Span,
}

#[derive(Debug, Clone, Default)]
pub struct AccountProvisioningOptions {
    pub or_replace: bool,
    pub if_not_exists: bool,
    pub if_exists: bool,
}

/// CREATE / DROP MANAGED ACCOUNT (reader account).
#[derive(Debug, Clone)]
pub struct ManagedAccountPlan {
    pub action: AccountProvisioningAction,
    pub target: Option<AccountProvisioningTarget>,
    pub options: AccountProvisioningOptions,
    /// `TYPE` value (upper-cased) — the recognition value (e.g. `READER`).
    pub account_type: Option<String>,
    pub node_id: NodeId,
    pub span: Span,
}

/// CREATE / DROP ACCOUNT (org-level account). Recognition only.
#[derive(Debug, Clone)]
pub struct OrgAccountPlan {
    pub action: AccountProvisioningAction,
    pub target: Option<AccountProvisioningTarget>,
    pub options: AccountProvisioningOptions,
    pub node_id: NodeId,
    pub span: Span,
}

pub fn lower_create_managed_account_to_plan(
    s: &AstCreateManagedAccount,
    source: &str,
) -> ManagedAccountPlan {
    ManagedAccountPlan {
        action: AccountProvisioningAction::Create,
        target: Some(target_from_span(source, s.name_span)),
        options: AccountProvisioningOptions {
            or_replace: s.or_replace_span.is_some(),
            if_not_exists: s.if_not_exists_span.is_some(),
            if_exists: false,
        },
        account_type: upper_text(source, s.account_type_span),
        node_id: s.node_id,
        span: s.span,
    }
}

pub fn lower_drop_managed_account_to_plan(s: &AstDrop, source: &str) -> ManagedAccountPlan {
    ManagedAccountPlan {
        action: AccountProvisioningAction::Drop,
        target: s
            .target_name_span
            .map(|span| target_from_span(source, span)),
        options: AccountProvisioningOptions {
            or_replace: false,
            if_not_exists: false,
            if_exists: s.if_exists_span.is_some(),
        },
        account_type: None,
        node_id: s.node_id,
        span: s.span,
    }
}

pub fn lower_create_account_to_plan(s: &AstCreateAccount, source: &str) -> OrgAccountPlan {
    OrgAccountPlan {
        action: AccountProvisioningAction::Create,
        target: Some(target_from_span(source, s.name_span)),
        options: AccountProvisioningOptions {
            or_replace: s.or_replace_span.is_some(),
            if_not_exists: s.if_not_exists_span.is_some(),
            if_exists: false,
        },
        node_id: s.node_id,
        span: s.span,
    }
}

pub fn lower_drop_account_to_plan(s: &AstDrop, source: &str) -> OrgAccountPlan {
    OrgAccountPlan {
        action: AccountProvisioningAction::Drop,
        target: s
            .target_name_span
            .map(|span| target_from_span(source, span)),
        options: AccountProvisioningOptions {
            or_replace: false,
            if_not_exists: false,
            if_exists: s.if_exists_span.is_some(),
        },
        node_id: s.node_id,
        span: s.span,
    }
}

fn target_from_span(source: &str, span: Span) -> AccountProvisioningTarget {
    AccountProvisioningTarget {
        name: slice_span(source, span).unwrap_or("").trim().to_string(),
        span,
    }
}

fn upper_text(source: &str, span: Option<Span>) -> Option<String> {
    span.and_then(|s| slice_span(source, s))
        .map(|t| t.trim().to_ascii_uppercase())
}
