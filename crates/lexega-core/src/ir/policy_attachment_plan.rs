// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! IR carrier for principal-policy *attachment* statements.
//!
//! Attachment statements bind (or unbind) a policy onto a principal. Today
//! the only supported principal–policy pair is Snowflake's authentication
//! policy attached to a USER or ACCOUNT:
//!
//! ```text
//! ALTER USER [IF EXISTS] <name> { SET | UNSET } AUTHENTICATION POLICY [= <policy>]
//! ALTER ACCOUNT          { SET | UNSET } AUTHENTICATION POLICY [= <policy>]
//! ```
//!
//! Both [`PolicyAttachmentPrincipal`] and [`PolicyAttachmentTarget`] are
//! **closed enums** by design. Adding a new principal
//! kind (Role, User-default, …) or a new attachment target (Masking-Policy
//! attachment, Network-Policy attachment, …) is a deliberate substrate
//! decision.

use crate::ast::types::{
    AstAlterAccount, AstAlterAccountActionKind, AstAlterUser, AstAlterUserActionKind,
};
use crate::ast::NodeId;
use crate::lexer::Span;

/// Verb performed by an attachment statement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyAttachmentVerb {
    /// `SET <target> = <name>` — bind the target to the principal.
    Set,
    /// `UNSET <target>` — unbind the target from the principal.
    Unset,
}

/// Principal that owns the attachment.
///
/// Closed enum.
#[derive(Debug, Clone)]
pub enum PolicyAttachmentPrincipal {
    /// `ALTER USER <name> …` — user-scoped attachment.
    User {
        /// Span covering the user name (single-component identifier).
        name_span: Span,
    },
    /// `ALTER ACCOUNT …` — account-scoped attachment (no name; refers
    /// to the current account).
    Account,
}

/// Target object being attached / detached.
///
/// Closed enum — only AUTHENTICATION POLICY today. Other policy attachment
/// targets (Masking-, RowAccess-, Session-, Password-, …) are not
/// modelled.
#[derive(Debug, Clone)]
pub enum PolicyAttachmentTarget {
    /// Snowflake `AUTHENTICATION POLICY = <name>` (Set form) or
    /// `AUTHENTICATION POLICY` (Unset form).
    AuthenticationPolicy {
        /// Span of the policy name in the Set form. `None` for Unset.
        policy_name_span: Option<Span>,
    },
}

/// IR carrier for a principal-policy attachment statement.
///
/// Lowered from [`AstAlterUser`] / [`AstAlterAccount`] via
/// [`PolicyAttachmentPlan::from_alter_user`] /
/// [`PolicyAttachmentPlan::from_alter_account`]. Consumed by
/// `derive_facts_from_policy_attachment_plan` to project
/// [`crate::facts::PolicyAttachmentFacts`] onto
/// [`crate::facts::StatementFacts`].
#[derive(Debug, Clone)]
pub struct PolicyAttachmentPlan {
    pub node_id: NodeId,
    /// Span covering the entire ALTER USER / ALTER ACCOUNT statement.
    pub span: Span,
    pub principal: PolicyAttachmentPrincipal,
    pub verb: PolicyAttachmentVerb,
    pub target: PolicyAttachmentTarget,
}

impl PolicyAttachmentPlan {
    /// Lower an [`AstAlterUser`] (which is by construction the AUTHPOL
    /// attachment slice) into a [`PolicyAttachmentPlan`].
    pub fn from_alter_user(stmt: &AstAlterUser) -> Self {
        let (verb, target) = lower_user_action(&stmt.action.kind);
        Self {
            node_id: stmt.node_id,
            span: stmt.span,
            principal: PolicyAttachmentPrincipal::User {
                name_span: stmt.user_name_span,
            },
            verb,
            target,
        }
    }

    /// Lower an [`AstAlterAccount`] into a [`PolicyAttachmentPlan`].
    ///
    /// Returns `None` when the action is a generic SET/UNSET property
    /// change (e.g. `ALTER ACCOUNT SET NETWORK_POLICY = 'p'`), which is
    /// not a policy attachment. AUTHPOL attach/detach actions return
    /// `Some(plan)`.
    pub fn from_alter_account(stmt: &AstAlterAccount) -> Option<Self> {
        let (verb, target) = lower_account_action(&stmt.action.kind)?;
        Some(Self {
            node_id: stmt.node_id,
            span: stmt.span,
            principal: PolicyAttachmentPrincipal::Account,
            verb,
            target,
        })
    }
}

fn lower_user_action(
    kind: &AstAlterUserActionKind,
) -> (PolicyAttachmentVerb, PolicyAttachmentTarget) {
    match kind {
        AstAlterUserActionKind::SetAuthenticationPolicy {
            policy_name_span, ..
        } => (
            PolicyAttachmentVerb::Set,
            PolicyAttachmentTarget::AuthenticationPolicy {
                policy_name_span: Some(*policy_name_span),
            },
        ),
        AstAlterUserActionKind::UnsetAuthenticationPolicy { .. } => (
            PolicyAttachmentVerb::Unset,
            PolicyAttachmentTarget::AuthenticationPolicy {
                policy_name_span: None,
            },
        ),
    }
}

fn lower_account_action(
    kind: &AstAlterAccountActionKind,
) -> Option<(PolicyAttachmentVerb, PolicyAttachmentTarget)> {
    match kind {
        AstAlterAccountActionKind::SetAuthenticationPolicy {
            policy_name_span, ..
        } => Some((
            PolicyAttachmentVerb::Set,
            PolicyAttachmentTarget::AuthenticationPolicy {
                policy_name_span: Some(*policy_name_span),
            },
        )),
        AstAlterAccountActionKind::UnsetAuthenticationPolicy { .. } => Some((
            PolicyAttachmentVerb::Unset,
            PolicyAttachmentTarget::AuthenticationPolicy {
                policy_name_span: None,
            },
        )),
        // Generic property changes are not policy attachments.
        AstAlterAccountActionKind::Set { .. } | AstAlterAccountActionKind::Unset { .. } => None,
    }
}
