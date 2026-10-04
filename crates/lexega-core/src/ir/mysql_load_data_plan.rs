// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! IR-side carrier for the MySQL `LOAD DATA … INFILE` statement (bulk file
//! ingestion).
//!
//! A typed projection of [`crate::ast::types::AstMysqlLoadData`] that
//! `derive_facts_from_mysql_load_data_plan` folds into the public
//! `StatementFacts.ddl.mysql_load_data` carrier. Carries the `LOCAL` modifier
//! (client-side vs server-side read — the security-relevant axis), the file
//! path, and the target table.

use crate::ast::types::AstMysqlLoadData;
use crate::ast::NodeId;
use crate::lexer::token::Span;

#[derive(Debug, Clone)]
pub struct MysqlLoadDataPlan {
    /// `LOCAL` modifier present — read from the client host (not the server).
    pub local: bool,
    /// Dequoted `INFILE` path literal.
    pub infile_path: Option<String>,
    /// Target table name (verbatim source text), if recognized.
    pub target_table: Option<String>,
    pub target_table_span: Option<Span>,
    pub node_id: NodeId,
    pub span: Span,
}

fn span_text(source: &str, span: Span) -> Option<String> {
    source
        .get(span.start as usize..span.end as usize)
        .map(|s| s.trim().to_string())
}

fn dequote(raw: &str) -> String {
    let t = raw.trim();
    if t.len() >= 2 {
        let b = t.as_bytes();
        if (b[0] == b'\'' && b[t.len() - 1] == b'\'') || (b[0] == b'"' && b[t.len() - 1] == b'"') {
            return t[1..t.len() - 1].to_string();
        }
    }
    t.to_string()
}

pub fn lower_mysql_load_data_to_plan(s: &AstMysqlLoadData, source: &str) -> MysqlLoadDataPlan {
    MysqlLoadDataPlan {
        local: s.local,
        infile_path: span_text(source, s.infile_path_span).map(|p| dequote(&p)),
        target_table: s.target_table_span.and_then(|sp| span_text(source, sp)),
        target_table_span: s.target_table_span,
        node_id: s.node_id,
        span: s.span,
    }
}
