// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! IR-side carrier for the SQL/MED `IMPORT FOREIGN SCHEMA` statement
//! (PostgreSQL FDW bulk remote-table import).
//!
//! Sibling-tier carrier analogous to [`super::ForeignTablePlan`]: a typed
//! projection of [`crate::ast::types::AstImportForeignSchema`] that
//! `derive_facts_from_import_foreign_schema_plan` folds into the public
//! `StatementFacts.ddl.import_foreign_schema` carrier.
//!
//! Carries the remote schema, the foreign server, the local schema, the
//! table-selection filter mode, and whether an OPTIONS bag is present.

use crate::ast::types::{AstImportFilterMode, AstImportForeignSchema};
use crate::ast::NodeId;
use crate::lexer::token::Span;

/// Table-selection filter on the import (mirror of [`AstImportFilterMode`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportFilterMode {
    All,
    LimitTo,
    Except,
}

#[derive(Debug, Clone)]
pub struct ImportForeignSchemaPlan {
    /// Remote schema being imported.
    pub remote_schema: String,
    /// Foreign-server name the import pulls through.
    pub server: String,
    pub server_span: Span,
    /// Local schema the foreign tables land in.
    pub local_schema: String,
    pub local_schema_span: Span,
    /// Table-selection filter mode.
    pub filter_mode: ImportFilterMode,
    /// `OPTIONS (…)` clause present.
    pub options_present: bool,
    pub node_id: NodeId,
    pub span: Span,
}

pub fn lower_import_foreign_schema_to_plan(
    s: &AstImportForeignSchema,
    source: &str,
) -> ImportForeignSchemaPlan {
    let text = |span: Span| {
        source
            .get(span.start as usize..span.end as usize)
            .unwrap_or("")
            .trim()
            .to_string()
    };
    let filter_mode = match s.filter_mode {
        AstImportFilterMode::All => ImportFilterMode::All,
        AstImportFilterMode::LimitTo => ImportFilterMode::LimitTo,
        AstImportFilterMode::Except => ImportFilterMode::Except,
    };
    ImportForeignSchemaPlan {
        remote_schema: text(s.remote_schema_span),
        server: text(s.server_span),
        server_span: s.server_span,
        local_schema: text(s.local_schema_span),
        local_schema_span: s.local_schema_span,
        filter_mode,
        options_present: s.options_present,
        node_id: s.node_id,
        span: s.span,
    }
}
