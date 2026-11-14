// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! IR-side carrier for the SQL/MED `CREATE FOREIGN TABLE` statement
//! (PostgreSQL FDW remote-table exposure).
//!
//! Sibling-tier carrier analogous to [`super::ForeignServerPlan`]: a typed
//! projection of [`crate::ast::types::AstCreateForeignTable`] that
//! `derive_facts_from_foreign_table_plan` folds into the public
//! `StatementFacts.ddl.foreign_table` carrier.
//!
//! Carries the table name, the foreign-server name it is bound to, whether it
//! is a partition, and whether an OPTIONS bag is present.

use crate::ast::types::AstCreateForeignTable;
use crate::ast::NodeId;
use crate::lexer::token::Span;

#[derive(Debug, Clone)]
pub struct ForeignTablePlan {
    pub name: String,
    pub name_span: Span,
    /// Foreign-server name the table is bound to.
    pub server: String,
    /// `IF NOT EXISTS` present.
    pub if_not_exists: bool,
    /// True for the `PARTITION OF parent` form.
    pub is_partition: bool,
    /// `OPTIONS (…)` clause present.
    pub options_present: bool,
    pub node_id: NodeId,
    pub span: Span,
}

pub fn lower_create_foreign_table_to_plan(
    s: &AstCreateForeignTable,
    source: &str,
) -> ForeignTablePlan {
    let text = |span: Span| {
        source
            .get(span.start as usize..span.end as usize)
            .unwrap_or("")
            .trim()
            .to_string()
    };
    // The name's parts as written, joined: no text between them.
    let name = crate::ir::utils::written_name_parts(source, &s.name)
        .map(|(db, schema, name)| {
            [db, schema, Some(name)]
                .into_iter()
                .flatten()
                .collect::<Vec<_>>()
                .join(".")
        })
        .unwrap_or_else(|| text(s.name_span));
    ForeignTablePlan {
        name,
        name_span: s.name_span,
        server: text(s.server_span),
        if_not_exists: s.if_not_exists,
        is_partition: s.is_partition,
        options_present: s.options_present,
        node_id: s.node_id,
        span: s.span,
    }
}
