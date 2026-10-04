// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! IR-side carrier for the T-SQL `DBCC <command>` statement.
//!
//! Sibling-tier fact alongside [`super::MssqlBackupPlan`]: a typed projection
//! of [`crate::ast::types::AstMssqlDbcc`] that downstream
//! `derive_facts_from_dbcc_plan` folds into a public
//! `StatementFacts.mssql_dbcc` carrier.
//!
//! `DBCC` is a maintenance / admin utility, not DDL — the public facts payload
//! sits at the top level of `StatementFacts`. The lowering captures the single
//! recognition primitive: the command verb, normalized to lowercase. Which
//! command is dangerous is a YAML verdict.

use crate::ast::types::AstMssqlDbcc;
use crate::ast::NodeId;
use crate::lexer::token::Span;

#[derive(Debug, Clone)]
pub struct MssqlDbccPlan {
    /// The DBCC command verb, normalized to lowercase (e.g. `checkdb`,
    /// `traceon`, `writepage`).
    pub command: String,
    pub node_id: NodeId,
    pub span: Span,
}

/// Lower a typed [`AstMssqlDbcc`] into a [`MssqlDbccPlan`].
pub fn lower_dbcc_to_dbcc_plan(s: &AstMssqlDbcc, source: &str) -> MssqlDbccPlan {
    let command = source
        .get(s.command_span.start as usize..s.command_span.end as usize)
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    MssqlDbccPlan {
        command,
        node_id: s.node_id,
        span: s.span,
    }
}
