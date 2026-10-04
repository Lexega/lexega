// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! IR-side carrier for `CREATE FLOW` (Databricks Lakeflow CDC pipeline
//! definition: `AUTO CDC INTO …` / `APPLY CHANGES INTO …`).
//!
//! Minimal projection — today DBX-FLOW-NEW fires unconditionally on
//! `kind: create_flow`. The carrier is reserved as an extension point
//! for future per-flow-property rules (mode = AUTO_CDC | APPLY_CHANGES,
//! SCD type, sequencing keys).

use crate::ast::{AstCreateFlow, NodeId};
use crate::lexer::token::Span;

#[derive(Debug, Clone)]
pub struct FlowPlan {
    pub action: FlowAction,
    pub node_id: NodeId,
    pub span: Span,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FlowAction {
    Create,
}

pub fn lower_create_flow_to_flow_plan(s: &AstCreateFlow) -> FlowPlan {
    FlowPlan {
        action: FlowAction::Create,
        node_id: s.node_id,
        span: s.span,
    }
}
