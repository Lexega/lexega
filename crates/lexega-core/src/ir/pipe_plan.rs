// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! IR-side carrier for Snowflake `CREATE / ALTER / DROP PIPE`.
//!
//! Sibling-tier fact analogous to [`super::DynamicTablePlan`] and
//! [`super::StagePlan`]: typed projection of the AST that downstream
//! `derive_facts_from_pipe_plan` folds into a public
//! `StatementFacts.ddl.pipe` carrier.
//!
//! The carrier collects per-action typed flags by classifying the
//! `AstAlterPipeActionKind` for ALTER and by interpreting per-property
//! spans for CREATE. Each flag corresponds 1:1 with a SNW-PIPE-*
//! rule condition so YAML rules predicate against the flag directly.
//!
//! `auto_ingest_enabled` is decoded by reading the `AUTO_INGEST = …`
//! clause text (case-insensitive `TRUE` containment), mirroring
//! `super::stage_plan::classify_create_encryption_clause`: the parser
//! captures only the span of the property clause; the IR-lowering layer
//! converts that span into a typed boolean.

use crate::ast::{AstAlterPipe, AstAlterPipeActionKind, AstCreatePipe, AstDropPipe, NodeId};
use crate::lexer::token::Span;

#[derive(Debug, Clone)]
pub struct PipePlan {
    pub action: PipeAction,
    pub target: Option<PipeTarget>,
    pub options: PipeOptions,
    pub create_flags: PipeCreateFlags,
    pub alter_flags: PipeAlterFlags,
    pub node_id: NodeId,
    pub span: Span,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PipeAction {
    Create,
    Alter,
    Drop,
}

#[derive(Debug, Clone)]
pub struct PipeTarget {
    pub name: String,
    pub schema: Option<String>,
    pub db: Option<String>,
    pub span: Span,
}

#[derive(Debug, Clone, Default)]
pub struct PipeOptions {
    pub or_replace: bool,
    pub if_not_exists: bool,
    pub if_exists: bool,
}

/// Per-property typed flags collected from [`AstCreatePipe`]. Each
/// flag corresponds 1:1 with a SNW-PIPE-* / INFO-SNW-PIPE-* rule
/// condition.
#[derive(Debug, Clone, Default)]
pub struct PipeCreateFlags {
    /// `AUTO_INGEST = TRUE` clause present: a case-insensitive
    /// `TRUE` containment check on the clause text.
    pub auto_ingest_enabled: bool,
    /// `ERROR_INTEGRATION = …` clause present (any value).
    pub error_integration_set: bool,
}

/// Per-action typed flags collected from [`AstAlterPipeActionKind`].
/// Each flag corresponds 1:1 with a SNW-PIPE-* rule condition.
#[derive(Debug, Clone, Default)]
pub struct PipeAlterFlags {
    /// `ALTER PIPE … SET <properties>` action present.
    pub set: bool,
    /// `ALTER PIPE … SET TAG …` action present.
    pub tag_set: bool,
    /// `ALTER PIPE … UNSET TAG …` action present.
    pub tag_unset: bool,
    /// `ALTER PIPE … REFRESH …` action present.
    pub refreshed: bool,
}

/// Lower a typed [`AstCreatePipe`] into a [`PipePlan`].
pub fn lower_create_pipe_to_pipe_plan(s: &AstCreatePipe, source: &str) -> PipePlan {
    let auto_ingest_enabled = match s.auto_ingest_span {
        Some(span) => classify_auto_ingest_clause(source, span),
        None => false,
    };
    let create_flags = PipeCreateFlags {
        auto_ingest_enabled,
        error_integration_set: s.error_integration_span.is_some(),
    };
    PipePlan {
        action: PipeAction::Create,
        target: Some(target_from_span(source, s.name_span)),
        options: PipeOptions {
            or_replace: s.or_replace_span.is_some(),
            if_not_exists: s.if_not_exists_span.is_some(),
            if_exists: false,
        },
        create_flags,
        alter_flags: PipeAlterFlags::default(),
        node_id: s.node_id,
        span: s.span,
    }
}

/// Lower a typed [`AstAlterPipe`] into a [`PipePlan`].
///
/// Walks the single `action.kind` and sets the matching typed flag.
/// Closed-enum exhaustive `match` with no `_ =>` arm — every
/// [`AstAlterPipeActionKind`] variant is enumerated explicitly.
pub fn lower_alter_pipe_to_pipe_plan(s: &AstAlterPipe, source: &str) -> PipePlan {
    let mut flags = PipeAlterFlags::default();
    classify_alter_action(&s.action.kind, &mut flags);

    PipePlan {
        action: PipeAction::Alter,
        target: Some(target_from_span(source, s.name_span)),
        options: PipeOptions {
            or_replace: false,
            if_not_exists: false,
            if_exists: s.if_exists_span.is_some(),
        },
        create_flags: PipeCreateFlags::default(),
        alter_flags: flags,
        node_id: s.node_id,
        span: s.span,
    }
}

/// Lower a typed [`AstDropPipe`] into a [`PipePlan`].
pub fn lower_drop_pipe_to_pipe_plan(s: &AstDropPipe, source: &str) -> PipePlan {
    PipePlan {
        action: PipeAction::Drop,
        target: Some(target_from_span(source, s.name_span)),
        options: PipeOptions {
            or_replace: false,
            if_not_exists: false,
            if_exists: s.if_exists_span.is_some(),
        },
        create_flags: PipeCreateFlags::default(),
        alter_flags: PipeAlterFlags::default(),
        node_id: s.node_id,
        span: s.span,
    }
}

fn classify_alter_action(kind: &AstAlterPipeActionKind, flags: &mut PipeAlterFlags) {
    use AstAlterPipeActionKind as K;
    match kind {
        K::Set { .. } => flags.set = true,
        K::SetTag { .. } => flags.tag_set = true,
        K::UnsetTag { .. } => flags.tag_unset = true,
        K::Refresh { .. } => flags.refreshed = true,
    }
}

/// Decode `AUTO_INGEST = TRUE|FALSE` clause text: case-insensitive
/// containment of `TRUE` in the upper-cased clause text. Returns
/// `false` for `AUTO_INGEST = FALSE` and for an unreadable span.
fn classify_auto_ingest_clause(source: &str, span: Span) -> bool {
    let Some(text) = source.get(span.start as usize..span.end as usize) else {
        return false;
    };
    text.to_ascii_uppercase().contains("TRUE")
}

fn target_from_span(source: &str, span: Span) -> PipeTarget {
    let raw = source
        .get(span.start as usize..span.end as usize)
        .unwrap_or("")
        .trim();
    let parts: Vec<&str> = raw.split('.').collect();
    let (db, schema, name) = match parts.as_slice() {
        [n] => (None, None, (*n).to_string()),
        [s, n] => (None, Some((*s).to_string()), (*n).to_string()),
        [d, s, n] => (
            Some((*d).to_string()),
            Some((*s).to_string()),
            (*n).to_string(),
        ),
        _ => (None, None, raw.to_string()),
    };
    PipeTarget {
        name,
        schema,
        db,
        span,
    }
}
