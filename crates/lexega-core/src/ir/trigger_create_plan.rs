// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! IR-side carrier for the MySQL `CREATE TRIGGER` statement (inline-body
//! trigger).
//!
//! A typed projection of [`crate::ast::types::AstCreateMysqlTrigger`] that
//! `derive_facts_from_trigger_create_plan` folds into the public
//! `StatementFacts.ddl.create_trigger` carrier. Carries the timing, the event,
//! the target table, and the definer (the account the body runs as). The body
//! is analyzed independently via the rule-engine flatten, not through this plan.

use crate::ast::types::{AstCreateMysqlTrigger, TriggerEvent, TriggerTiming};
use crate::ast::NodeId;
use crate::ir::event_plan::{lower_definer, span_text, DefinerLowered};
use crate::lexer::token::Span;

#[derive(Debug, Clone)]
pub struct TriggerCreatePlan {
    /// Trigger name (verbatim source text), if recognized.
    pub name: Option<String>,
    pub name_span: Span,
    /// `BEFORE` / `AFTER`.
    pub timing: TriggerTiming,
    /// `INSERT` / `UPDATE` / `DELETE`.
    pub event: TriggerEvent,
    /// Target table name (verbatim source text), if recognized.
    pub target_table: Option<String>,
    pub target_table_span: Span,
    /// The `DEFINER =` security context, when present.
    pub definer: Option<DefinerLowered>,
    /// An inline body is present.
    pub body_present: bool,
    pub node_id: NodeId,
    pub span: Span,
}

pub fn lower_create_mysql_trigger_to_plan(
    s: &AstCreateMysqlTrigger,
    source: &str,
) -> TriggerCreatePlan {
    TriggerCreatePlan {
        name: span_text(source, s.name_span),
        name_span: s.name_span,
        timing: s.timing,
        event: s.event,
        target_table: span_text(source, s.target_table_span),
        target_table_span: s.target_table_span,
        definer: s.definer.as_ref().map(|d| lower_definer(d, source)),
        body_present: s.body_stmt.is_some(),
        node_id: s.node_id,
        span: s.span,
    }
}
