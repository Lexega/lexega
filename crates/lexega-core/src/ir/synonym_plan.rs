// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! IR-side carrier for the T-SQL `CREATE SYNONYM` statement.
//!
//! Sibling-tier carrier: a typed projection of [`AstCreateSynonym`] that
//! `derive_facts_from_synonym_plan` folds into the public
//! `StatementFacts.ddl.synonym` carrier. Recognition only — it captures the
//! synonym's own name and the referenced base object's structure (notably the
//! part count, since a four-part `server.database.schema.object` referent names
//! a linked/remote server). The governance verdict lives in YAML.

use crate::ast::AstCreateSynonym;
use crate::lexer::token::Span;

#[derive(Debug, Clone)]
pub struct SynonymPlan {
    /// The synonym's own name, as written (may be schema-qualified).
    pub name: String,
    pub name_span: Span,
    /// The referenced base object, as written.
    pub referent: String,
    pub referent_span: Span,
    /// Number of top-level name parts in the referent. Four parts is a T-SQL
    /// `server.database.schema.object` (linked/remote server) reference.
    pub referent_part_count: u8,
    pub node_id: crate::ast::NodeId,
    pub span: Span,
}

/// Count top-level dot-separated parts in a qualified name, ignoring dots inside
/// `[bracketed]` or `"quoted"` identifier segments.
fn count_name_parts(raw: &str) -> u8 {
    let mut parts: u8 = 1;
    let mut in_bracket = false;
    let mut in_quote = false;
    for ch in raw.chars() {
        match ch {
            '[' if !in_quote => in_bracket = true,
            ']' if !in_quote => in_bracket = false,
            '"' if !in_bracket => in_quote = !in_quote,
            '.' if !in_bracket && !in_quote => parts = parts.saturating_add(1),
            _ => {}
        }
    }
    parts
}

pub fn lower_create_synonym_to_plan(stmt: &AstCreateSynonym, source: &str) -> SynonymPlan {
    let slice = |span: Span| -> String {
        let start = span.start as usize;
        let end = span.end as usize;
        if start <= end && end <= source.len() {
            source[start..end].to_string()
        } else {
            String::new()
        }
    };
    let referent = slice(stmt.target_span);
    let referent_part_count = count_name_parts(&referent);
    SynonymPlan {
        name: slice(stmt.name_span),
        name_span: stmt.name_span,
        referent,
        referent_span: stmt.target_span,
        referent_part_count,
        node_id: stmt.node_id,
        span: stmt.span,
    }
}
