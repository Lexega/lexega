// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! IR-side carrier for the T-SQL `BACKUP`/`RESTORE` key-material statements.
//!
//! Sibling-tier fact alongside [`super::MssqlKeyManagementPlan`]: a typed
//! projection of [`crate::ast::types::AstMssqlKeyBackup`] that downstream
//! `derive_facts_from_key_backup_plan` folds into a public
//! `StatementFacts.mssql_key_backup` carrier.
//!
//! The lowering carries the governance-bearing primitives: the verb, the key
//! object, and whether an inline password protects/unlocks the material. Which
//! combination is dangerous (exporting a root key, re-keying from a file, a
//! hardcoded password) is a YAML verdict.

use crate::ast::types::{AstMssqlKeyBackup, BackupKeyObject, KeyBackupAction};
use crate::ast::NodeId;
use crate::lexer::token::Span;

#[derive(Debug, Clone)]
pub struct MssqlKeyBackupPlan {
    pub action: KeyBackupAction,
    pub key_object: BackupKeyObject,
    pub password_present: bool,
    pub node_id: NodeId,
    pub span: Span,
}

/// Lower a typed [`AstMssqlKeyBackup`] into a [`MssqlKeyBackupPlan`].
pub fn lower_key_backup_to_plan(s: &AstMssqlKeyBackup) -> MssqlKeyBackupPlan {
    MssqlKeyBackupPlan {
        action: s.action,
        key_object: s.key_object,
        password_present: s.password_present,
        node_id: s.node_id,
        span: s.span,
    }
}
