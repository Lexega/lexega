// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! IR-side carrier for the T-SQL `CREATE`/`ALTER ASSEMBLY` (CLR) statements.
//!
//! Sibling-tier fact alongside [`super::MssqlKeyBackupPlan`]: a typed projection
//! of [`crate::ast::types::AstMssqlAssembly`] that downstream
//! `derive_facts_from_assembly_plan` folds into a public
//! `StatementFacts.mssql_assembly` carrier.
//!
//! The lowering carries the governance-bearing primitives: the verb, the
//! permission set, and whether the assembly is loaded from a filesystem path.
//! Which permission is dangerous (`UNSAFE` = arbitrary native code) is a YAML
//! verdict.

use crate::ast::types::{AssemblyAction, AssemblyPermissionSet, AstMssqlAssembly};
use crate::ast::NodeId;
use crate::lexer::token::Span;

#[derive(Debug, Clone)]
pub struct MssqlAssemblyPlan {
    pub action: AssemblyAction,
    pub permission_set: AssemblyPermissionSet,
    pub from_file: bool,
    pub node_id: NodeId,
    pub span: Span,
}

/// Lower a typed [`AstMssqlAssembly`] into a [`MssqlAssemblyPlan`].
pub fn lower_assembly_to_plan(s: &AstMssqlAssembly) -> MssqlAssemblyPlan {
    MssqlAssemblyPlan {
        action: s.action,
        permission_set: s.permission_set,
        from_file: s.from_file,
        node_id: s.node_id,
        span: s.span,
    }
}
