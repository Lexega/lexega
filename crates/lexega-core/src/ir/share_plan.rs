// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! IR-side carrier for Snowflake `CREATE / ALTER / DROP SHARE`.
//!
//! Sibling-tier carrier analogous to [`super::DatasharePlan`] (the
//! Redshift cross-account object): typed projection of the AST that
//! `derive_facts_from_share_plan` folds into the public
//! `StatementFacts.ddl.share` carrier.
//!
//! The consumer-account lists are the cross-account exposure
//! primitives — `ALTER SHARE … ADD ACCOUNTS` is the action that makes
//! shared data readable from another account. Which accounts are
//! acceptable is YAML policy; the IR only surfaces the typed lists.
//! `GRANT … TO SHARE` is NOT carried here — it flows through the
//! privilege substrate (`PrivilegeFacts`, GRT-TO-SHARE).

use crate::ast::{AstAlterShare, AstAlterShareActionKind, AstCreateShare, AstDrop, NodeId};
use crate::ir::utils::slice_span;
use crate::lexer::token::Span;

#[derive(Debug, Clone)]
pub struct SharePlan {
    pub action: ShareAction,
    pub target: Option<ShareTarget>,
    pub options: ShareOptions,
    /// `ADD ACCOUNTS = a, b` — consumer accounts added.
    pub accounts_added: Vec<String>,
    /// `REMOVE ACCOUNTS = a, b` — consumer accounts removed.
    pub accounts_removed: Vec<String>,
    /// `SET ACCOUNTS = a, b` — consumer list replaced wholesale.
    pub accounts_set: Vec<String>,
    /// Generic `SET <property> = <value>` action present.
    pub had_set_properties: bool,
    /// Generic `UNSET <property>` action present.
    pub had_unset_properties: bool,
    /// An unrecognized ALTER action body was encountered.
    pub has_unknown_clauses: bool,
    pub node_id: NodeId,
    pub span: Span,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ShareAction {
    Create,
    Alter,
    Drop,
}

#[derive(Debug, Clone)]
pub struct ShareTarget {
    pub name: String,
    pub span: Span,
}

#[derive(Debug, Clone, Default)]
pub struct ShareOptions {
    pub or_replace: bool,
    pub if_not_exists: bool,
    pub if_exists: bool,
}

/// Lower a typed [`AstCreateShare`] into a [`SharePlan`].
pub fn lower_create_share_to_share_plan(s: &AstCreateShare, source: &str) -> SharePlan {
    SharePlan {
        action: ShareAction::Create,
        target: Some(target_from_span(source, s.name_span)),
        options: ShareOptions {
            or_replace: s.or_replace_span.is_some(),
            if_not_exists: s.if_not_exists_span.is_some(),
            if_exists: false,
        },
        accounts_added: Vec::new(),
        accounts_removed: Vec::new(),
        accounts_set: Vec::new(),
        had_set_properties: false,
        had_unset_properties: false,
        has_unknown_clauses: false,
        node_id: s.node_id,
        span: s.span,
    }
}

/// Lower a typed [`AstAlterShare`] into a [`SharePlan`].
///
/// Closed-enum exhaustive `match` over [`AstAlterShareActionKind`] —
/// no `_ =>` arm.
pub fn lower_alter_share_to_share_plan(s: &AstAlterShare, source: &str) -> SharePlan {
    use AstAlterShareActionKind as K;
    let mut plan = SharePlan {
        action: ShareAction::Alter,
        target: Some(target_from_span(source, s.name_span)),
        options: ShareOptions {
            or_replace: false,
            if_not_exists: false,
            if_exists: s.if_exists_span.is_some(),
        },
        accounts_added: Vec::new(),
        accounts_removed: Vec::new(),
        accounts_set: Vec::new(),
        had_set_properties: false,
        had_unset_properties: false,
        has_unknown_clauses: false,
        node_id: s.node_id,
        span: s.span,
    };
    match &s.action.kind {
        K::AddAccounts {
            account_list_span, ..
        } => {
            plan.accounts_added = split_account_list(source, *account_list_span);
        }
        K::RemoveAccounts {
            account_list_span, ..
        } => {
            plan.accounts_removed = split_account_list(source, *account_list_span);
        }
        K::SetAccounts {
            account_list_span, ..
        } => {
            plan.accounts_set = split_account_list(source, *account_list_span);
        }
        K::Set { .. } => plan.had_set_properties = true,
        K::Unset { .. } => plan.had_unset_properties = true,
        K::Unknown(_) => plan.has_unknown_clauses = true,
    }
    plan
}

/// Lower a generic [`AstDrop`] whose object type is SHARE (no typed
/// drop AST exists). The caller gates on the object type.
pub fn lower_drop_share_to_share_plan(s: &AstDrop, source: &str) -> SharePlan {
    SharePlan {
        action: ShareAction::Drop,
        target: s
            .target_name_span
            .map(|span| target_from_span(source, span)),
        options: ShareOptions {
            or_replace: false,
            if_not_exists: false,
            if_exists: s.if_exists_span.is_some(),
        },
        accounts_added: Vec::new(),
        accounts_removed: Vec::new(),
        accounts_set: Vec::new(),
        had_set_properties: false,
        had_unset_properties: false,
        has_unknown_clauses: false,
        node_id: s.node_id,
        span: s.span,
    }
}

/// Split a comma-separated consumer-account list (`org1.acct1, acct2`)
/// into trimmed entries.
fn split_account_list(source: &str, span: Span) -> Vec<String> {
    slice_span(source, span)
        .unwrap_or("")
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect()
}

fn target_from_span(source: &str, span: Span) -> ShareTarget {
    ShareTarget {
        name: slice_span(source, span).unwrap_or("").trim().to_string(),
        span,
    }
}
