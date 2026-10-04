// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! IR-side carrier for the PostgreSQL `ALTER DEFAULT PRIVILEGES` statement.
//!
//! A typed projection of [`crate::ast::types::AstPgAlterDefaultPrivileges`]
//! that `derive_facts_from_pg_default_privileges_plan` folds into the public
//! `StatementFacts.pg_default_privileges` carrier.
//!
//! Reuses the shared GRANT/REVOKE leaf surface ([`super::PrivilegeSet`],
//! [`super::PrivilegeGrantee`]) via the `lower_privilege_list` / `lower_grantee`
//! helpers, plus the AST-side action / object-class closed enums — re-projecting
//! them at the IR layer would be redundant.
//! The two things no plain grant carries — the `FOR ROLE` and `IN SCHEMA`
//! outer scope — are kept span-only here and resolved to identifiers at
//! fact extraction.

use crate::ast::types::{
    AstPgAlterDefaultPrivileges, DefaultPrivilegesAction, PgDefaultPrivObjectClass,
};
use crate::ast::NodeId;
use crate::ir::privilege_plan::{
    lower_grantee, lower_privilege_list, PrivilegeGrantee, PrivilegeSet,
};
use crate::lexer::token::Span;

#[derive(Debug, Clone)]
pub struct PgDefaultPrivilegesPlan {
    pub action: DefaultPrivilegesAction,
    pub object_class: PgDefaultPrivObjectClass,
    pub privileges: PrivilegeSet,
    pub grantees: Vec<PrivilegeGrantee>,
    /// `FOR { ROLE | USER } target [, …]` name spans — empty when omitted.
    pub for_roles: Vec<Span>,
    /// `IN SCHEMA schema [, …]` name spans — empty when omitted (global).
    pub in_schemas: Vec<Span>,
    pub with_grant_option: bool,
    pub grant_option_for: bool,
    pub node_id: NodeId,
    pub span: Span,
}

/// Lower a typed [`AstPgAlterDefaultPrivileges`] into a
/// [`PgDefaultPrivilegesPlan`].
pub fn lower_pg_default_privileges_to_plan(
    s: &AstPgAlterDefaultPrivileges,
) -> PgDefaultPrivilegesPlan {
    PgDefaultPrivilegesPlan {
        action: s.action,
        object_class: s.object_class,
        privileges: lower_privilege_list(&s.privileges),
        grantees: s.grantees.iter().map(lower_grantee).collect(),
        for_roles: s.for_roles.clone(),
        in_schemas: s.in_schemas.clone(),
        with_grant_option: s.with_grant_option,
        grant_option_for: s.grant_option_for,
        node_id: s.node_id,
        span: s.span,
    }
}
