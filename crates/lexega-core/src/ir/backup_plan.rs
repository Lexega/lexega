// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! IR-side carrier for the T-SQL `BACKUP { DATABASE | LOG }` statement.
//!
//! Sibling-tier fact alongside [`super::PgCopyPlan`]: a typed projection of
//! [`crate::ast::AstMssqlBackup`] that downstream
//! `derive_facts_from_backup_plan` folds into a public
//! `StatementFacts.mssql_backup` carrier.
//!
//! `BACKUP` is a data-protection utility statement, not DDL — the public
//! facts payload sits at the top level of `StatementFacts`.
//!
//! The lowering captures the closed [`BackupTargetKind`] (database vs log)
//! and [`BackupDestinationKind`] (device class), plus whether the backup is
//! encrypted. The destination literal is deliberately dropped at the AST→IR
//! boundary — backup URLs commonly embed SAS credentials.

use crate::ast::{AstMssqlBackup, AstMssqlBackupDestination, AstMssqlBackupTarget, NodeId};
use crate::lexer::token::Span;

#[derive(Debug, Clone)]
pub struct MssqlBackupPlan {
    pub target: BackupTargetKind,
    pub destination: BackupDestinationKind,
    /// Whether a `WITH ENCRYPTION` clause is present.
    pub encryption: bool,
    pub node_id: NodeId,
    pub span: Span,
}

/// What a `BACKUP` statement backs up. Mirrors
/// [`crate::ast::AstMssqlBackupTarget`]; public mirror is
/// [`crate::facts::BackupTarget`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BackupTargetKind {
    Database,
    Log,
}

/// Destination device class of a `BACKUP` statement. Mirrors
/// [`crate::ast::AstMssqlBackupDestination`]; public mirror is
/// [`crate::facts::BackupDestination`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BackupDestinationKind {
    Disk,
    Url,
    Tape,
}

/// Lower a typed [`AstMssqlBackup`] into a [`MssqlBackupPlan`].
pub fn lower_backup_to_backup_plan(s: &AstMssqlBackup, _source: &str) -> MssqlBackupPlan {
    MssqlBackupPlan {
        target: match s.target {
            AstMssqlBackupTarget::Database => BackupTargetKind::Database,
            AstMssqlBackupTarget::Log => BackupTargetKind::Log,
        },
        destination: match s.destination {
            AstMssqlBackupDestination::Disk => BackupDestinationKind::Disk,
            AstMssqlBackupDestination::Url => BackupDestinationKind::Url,
            AstMssqlBackupDestination::Tape => BackupDestinationKind::Tape,
        },
        encryption: s.encryption,
        node_id: s.node_id,
        span: s.span,
    }
}
