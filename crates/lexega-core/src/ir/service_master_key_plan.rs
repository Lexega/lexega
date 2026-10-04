// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! IR-side carrier for the T-SQL `ALTER SERVICE MASTER KEY` statement.
//!
//! Sibling-tier fact alongside [`super::MssqlKeyBackupPlan`]: a typed projection
//! of [`crate::ast::types::AstMssqlAlterServiceMasterKey`] that downstream
//! `derive_facts_from_service_master_key_plan` folds into a public
//! `StatementFacts.mssql_service_master_key` carrier.
//!
//! The lowering carries the governance-bearing primitives: the operation,
//! whether the regenerate is forced, and whether an inline password is present.
//! Which combination is dangerous is a YAML verdict.

use crate::ast::types::{AstMssqlAlterServiceMasterKey, ServiceMasterKeyOperation};
use crate::ast::NodeId;
use crate::lexer::token::Span;

#[derive(Debug, Clone)]
pub struct MssqlServiceMasterKeyPlan {
    pub operation: ServiceMasterKeyOperation,
    pub force: bool,
    pub password_present: bool,
    pub node_id: NodeId,
    pub span: Span,
}

/// Lower a typed [`AstMssqlAlterServiceMasterKey`] into a
/// [`MssqlServiceMasterKeyPlan`].
pub fn lower_service_master_key_to_plan(
    s: &AstMssqlAlterServiceMasterKey,
) -> MssqlServiceMasterKeyPlan {
    MssqlServiceMasterKeyPlan {
        operation: s.operation,
        force: s.force,
        password_present: s.password_present,
        node_id: s.node_id,
        span: s.span,
    }
}
