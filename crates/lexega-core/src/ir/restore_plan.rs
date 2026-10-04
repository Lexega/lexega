// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! IR-side carrier for the T-SQL `RESTORE { DATABASE | LOG }` statement.
//!
//! Counterpart of [`super::MssqlBackupPlan`]: a typed projection of
//! [`crate::ast::AstMssqlRestore`] that downstream
//! `derive_facts_from_restore_plan` folds into a public
//! `StatementFacts.mssql_restore` carrier.
//!
//! `RESTORE` is a data-protection utility statement, not DDL — the public
//! facts payload sits at the top level of `StatementFacts`.
//!
//! The lowering captures the closed [`RestoreTargetKind`] (database vs log)
//! and [`RestoreSourceKind`] (device class), plus whether `WITH REPLACE` is
//! present. The source literal is deliberately dropped at the AST→IR
//! boundary — restore URLs commonly embed SAS credentials.

use crate::ast::{AstMssqlRestore, AstMssqlRestoreSource, AstMssqlRestoreTarget, NodeId};
use crate::lexer::token::Span;

#[derive(Debug, Clone)]
pub struct MssqlRestorePlan {
    pub target: RestoreTargetKind,
    /// `None` for the recovery-only form (no source device named).
    pub source: Option<RestoreSourceKind>,
    /// Whether a `WITH REPLACE` option is present.
    pub replace: bool,
    pub node_id: NodeId,
    pub span: Span,
}

/// What a `RESTORE` statement restores. Mirrors
/// [`crate::ast::AstMssqlRestoreTarget`]; public mirror is
/// [`crate::facts::RestoreTarget`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RestoreTargetKind {
    Database,
    Log,
}

/// Source device class of a `RESTORE` statement. Mirrors
/// [`crate::ast::AstMssqlRestoreSource`]; public mirror is
/// [`crate::facts::RestoreSource`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RestoreSourceKind {
    Disk,
    Url,
    Tape,
}

/// Lower a typed [`AstMssqlRestore`] into a [`MssqlRestorePlan`].
pub fn lower_restore_db_to_plan(s: &AstMssqlRestore, _source: &str) -> MssqlRestorePlan {
    MssqlRestorePlan {
        target: match s.target {
            AstMssqlRestoreTarget::Database => RestoreTargetKind::Database,
            AstMssqlRestoreTarget::Log => RestoreTargetKind::Log,
        },
        source: s.source.map(|src| match src {
            AstMssqlRestoreSource::Disk => RestoreSourceKind::Disk,
            AstMssqlRestoreSource::Url => RestoreSourceKind::Url,
            AstMssqlRestoreSource::Tape => RestoreSourceKind::Tape,
        }),
        replace: s.replace,
        node_id: s.node_id,
        span: s.span,
    }
}
