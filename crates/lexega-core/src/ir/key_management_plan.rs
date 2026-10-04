// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! IR-side carrier for the T-SQL `OPEN`/`CLOSE` encryption-key statements.
//!
//! Sibling-tier fact alongside [`super::MssqlDbccPlan`]: a typed projection of
//! [`crate::ast::types::AstMssqlKeyManagement`] that downstream
//! `derive_facts_from_key_management_plan` folds into a public
//! `StatementFacts.mssql_key_management` carrier.
//!
//! Encryption-key activation is a session-scoped context switch, not DDL — the
//! public facts payload sits at the top level of `StatementFacts`. The lowering
//! carries the three recognition primitives (verb, key kind, whether an inline
//! password decrypts the key); which combination is dangerous is a YAML verdict.

use crate::ast::types::{AstMssqlKeyManagement, KeyMgmtAction, KeyMgmtKind};
use crate::ast::NodeId;
use crate::lexer::token::Span;

#[derive(Debug, Clone)]
pub struct MssqlKeyManagementPlan {
    pub action: KeyMgmtAction,
    pub key_kind: KeyMgmtKind,
    /// True when an inline `PASSWORD = '…'` opens/decrypts the key.
    pub password_present: bool,
    pub node_id: NodeId,
    pub span: Span,
}

/// Lower a typed [`AstMssqlKeyManagement`] into a [`MssqlKeyManagementPlan`].
pub fn lower_key_management_to_plan(s: &AstMssqlKeyManagement) -> MssqlKeyManagementPlan {
    MssqlKeyManagementPlan {
        action: s.action,
        key_kind: s.key_kind,
        password_present: s.password_present,
        node_id: s.node_id,
        span: s.span,
    }
}
