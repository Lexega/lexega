// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! IR-side carrier for the T-SQL `CREATE`/`ALTER SECURITY POLICY` statements.
//!
//! Sibling-tier fact alongside [`super::MssqlKeyManagementPlan`]: a typed
//! projection of [`crate::ast::types::AstMssqlSecurityPolicy`] that downstream
//! `derive_facts_from_security_policy_plan` folds into a public
//! `StatementFacts.mssql_security_policy` carrier.
//!
//! The lowering carries the governance-bearing primitives: the verb, the policy
//! `STATE`, and whether filter / block predicates are present. Which combination
//! is dangerous (notably a disabled control) is a YAML verdict.

use crate::ast::types::{AstMssqlSecurityPolicy, PolicyState, SecurityPolicyAction};
use crate::ast::NodeId;
use crate::lexer::token::Span;

#[derive(Debug, Clone)]
pub struct MssqlSecurityPolicyPlan {
    pub action: SecurityPolicyAction,
    pub state: PolicyState,
    pub has_filter_predicate: bool,
    pub has_block_predicate: bool,
    pub node_id: NodeId,
    pub span: Span,
}

/// Lower a typed [`AstMssqlSecurityPolicy`] into a [`MssqlSecurityPolicyPlan`].
pub fn lower_security_policy_to_plan(s: &AstMssqlSecurityPolicy) -> MssqlSecurityPolicyPlan {
    MssqlSecurityPolicyPlan {
        action: s.action,
        state: s.state,
        has_filter_predicate: s.has_filter_predicate,
        has_block_predicate: s.has_block_predicate,
        node_id: s.node_id,
        span: s.span,
    }
}
