// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! IR-side carrier for PostgreSQL `COPY` statements.
//!
//! Sibling-tier fact alongside [`super::UsePlan`]: typed projection
//! of [`crate::ast::AstPgCopy`] that downstream
//! `derive_facts_from_pg_copy_plan` folds into a public
//! `StatementFacts.pg_copy` carrier.
//!
//! `COPY` is a data-movement utility statement, not DDL — the public
//! facts payload sits at the top level of `StatementFacts`.
//!
//! The lowering captures the closed [`PgCopyDirection`] (mirroring
//! [`crate::ast::PgCopyDirection`]) plus the closed
//! [`PgCopyTargetKind`] — a variant-tag-only mirror of
//! [`crate::ast::PgCopyTarget`] with the span payloads dropped
//! (engine-internal; rules predicate on the kind).

use crate::ast::{
    AstPgCopy, NodeId, PgCopyDirection as AstPgCopyDirection, PgCopySubject, PgCopyTarget,
};
use crate::lexer::token::Span;

#[derive(Debug, Clone)]
pub struct PgCopyPlan {
    pub direction: PgCopyDirection,
    pub target: PgCopyTargetKind,
    /// Identity of the table subject for `COPY <table> FROM/TO …`.
    /// `None` for `COPY (<query>) TO …` — that form lowers through
    /// the Rel path and surfaces tables via `query.reads_table`.
    pub subject_table: Option<PgCopySubjectTable>,
    pub node_id: NodeId,
    pub span: Span,
}

/// Parsed table identity for a `COPY <table> ...` subject. Mirrors
/// the dotted-name shape (db.schema.table) without depending on
/// `crate::facts` from the IR layer.
#[derive(Debug, Clone)]
pub struct PgCopySubjectTable {
    pub name: String,
    pub schema: Option<String>,
    pub db: Option<String>,
    pub span: Span,
}

/// Direction of a PG `COPY` statement. Mirrors
/// [`crate::ast::PgCopyDirection`]; the public facts mirror is
/// [`crate::facts::PgCopyDirection`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PgCopyDirection {
    From,
    To,
}

/// Endpoint kind of a PG `COPY` statement. Variant-tag-only mirror
/// of [`crate::ast::PgCopyTarget`] — the span payloads on
/// `File(Span)` / `Program(Span)` / `Stdin(Span)` / `Stdout(Span)`
/// are engine-internal and dropped at the AST→IR boundary. The
/// public facts mirror is [`crate::facts::PgCopyTargetKind`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PgCopyTargetKind {
    File,
    Program,
    Stdin,
    Stdout,
    /// psql client variable (`:var`) — concrete endpoint unknown until substituted.
    Placeholder,
}

/// Lower a typed [`AstPgCopy`] into a [`PgCopyPlan`].
///
/// `source` is required so the table-subject form
/// (`COPY <table> FROM/TO …`) can slice its identifier text from the
/// AST span; the parser carries only the span on
/// [`PgCopySubject::Table`].
pub fn lower_pg_copy_to_pg_copy_plan(s: &AstPgCopy, source: &str) -> PgCopyPlan {
    PgCopyPlan {
        direction: lower_pg_copy_direction(s.direction),
        target: lower_pg_copy_target(&s.target),
        subject_table: lower_pg_copy_subject_table(&s.subject, source),
        node_id: s.node_id,
        span: s.span,
    }
}

fn lower_pg_copy_subject_table(
    subject: &PgCopySubject,
    source: &str,
) -> Option<PgCopySubjectTable> {
    let span = match subject {
        PgCopySubject::Table(span) => *span,
        PgCopySubject::Query(..) => return None,
    };
    let start = span.start as usize;
    let end = span.end as usize;
    if start >= end || end > source.len() {
        return None;
    }
    let raw = &source[start..end];
    let parts: Vec<String> = raw
        .split('.')
        .map(|p| p.trim().trim_matches('"').to_string())
        .filter(|p| !p.is_empty())
        .collect();
    let len = parts.len();
    if len == 0 {
        return None;
    }
    let name = parts[len - 1].clone();
    let schema = if len >= 2 {
        Some(parts[len - 2].clone())
    } else {
        None
    };
    let db = if len >= 3 {
        Some(parts[len - 3].clone())
    } else {
        None
    };
    Some(PgCopySubjectTable {
        name,
        schema,
        db,
        span,
    })
}

fn lower_pg_copy_direction(dir: AstPgCopyDirection) -> PgCopyDirection {
    match dir {
        AstPgCopyDirection::From => PgCopyDirection::From,
        AstPgCopyDirection::To => PgCopyDirection::To,
    }
}

fn lower_pg_copy_target(target: &PgCopyTarget) -> PgCopyTargetKind {
    match target {
        PgCopyTarget::File(_) => PgCopyTargetKind::File,
        PgCopyTarget::Program(_) => PgCopyTargetKind::Program,
        PgCopyTarget::Stdin(_) => PgCopyTargetKind::Stdin,
        PgCopyTarget::Stdout(_) => PgCopyTargetKind::Stdout,
        PgCopyTarget::Placeholder(_) => PgCopyTargetKind::Placeholder,
    }
}
