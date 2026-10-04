// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! IR-side carrier for Snowflake client file commands (PUT / GET / REMOVE /
//! LIST). These move or enumerate files on a stage from the client. The
//! recognition surface is the operation kind — GET is a data-egress-to-client
//! primitive, REMOVE deletes stage files — plus the `@<stage>` reference.

use crate::ast::{types::AstStageFileCommandKind, AstStageFileCommand, NodeId};
use crate::ir::utils::slice_span;
use crate::lexer::token::Span;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StageFileOperation {
    Put,
    Get,
    Remove,
    List,
}

#[derive(Debug, Clone)]
pub struct StageFileCommandPlan {
    pub operation: StageFileOperation,
    /// The `@<stage>` reference (data source/target), as written, when present.
    pub stage_ref: Option<String>,
    pub stage_ref_span: Option<Span>,
    pub node_id: NodeId,
    pub span: Span,
}

pub fn lower_stage_file_command_to_plan(
    s: &AstStageFileCommand,
    source: &str,
) -> StageFileCommandPlan {
    StageFileCommandPlan {
        operation: match s.kind {
            AstStageFileCommandKind::Put => StageFileOperation::Put,
            AstStageFileCommandKind::Get => StageFileOperation::Get,
            AstStageFileCommandKind::Remove => StageFileOperation::Remove,
            AstStageFileCommandKind::List => StageFileOperation::List,
        },
        stage_ref: s
            .stage_ref_span
            .and_then(|sp| slice_span(source, sp))
            .map(|t| t.trim().to_string()),
        stage_ref_span: s.stage_ref_span,
        node_id: s.node_id,
        span: s.span,
    }
}
