// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! IR-side carrier for Snowflake `CREATE / DROP STREAM`.
//!
//! Sibling-tier fact analogous to [`super::PipePlan`] and
//! [`super::DynamicTablePlan`]: typed projection of the AST that
//! downstream `derive_facts_from_stream_plan` folds into a public
//! `StatementFacts.ddl.stream` carrier.
//!
//! The carrier collects per-property typed flags by classifying the
//! presence of `APPEND_ONLY` / `INSERT_ONLY` clauses on `CREATE STREAM`.
//! Each flag corresponds 1:1 with a SNW-STREAM-* rule condition so
//! YAML rules predicate against the flag directly.
//!
//! The flags record the presence of the option clause regardless of
//! the assigned `TRUE` / `FALSE` value: presence of the span drives
//! the typed flag.

use crate::ast::{AstCreateStream, AstDropStream, NodeId};
use crate::lexer::token::Span;

#[derive(Debug, Clone)]
pub struct StreamPlan {
    pub action: StreamAction,
    pub target: Option<StreamTarget>,
    pub options: StreamOptions,
    pub create_flags: StreamCreateFlags,
    pub node_id: NodeId,
    pub span: Span,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StreamAction {
    /// `CREATE STREAM`
    Create,
    /// `DROP STREAM`
    Drop,
}

#[derive(Debug, Clone)]
pub struct StreamTarget {
    pub name: String,
    pub schema: Option<String>,
    pub db: Option<String>,
    pub span: Span,
}

#[derive(Debug, Clone, Default)]
pub struct StreamOptions {
    pub or_replace: bool,
    pub if_not_exists: bool,
    pub if_exists: bool,
}

/// Per-property typed flags collected from [`AstCreateStream`]. Each
/// flag corresponds 1:1 with a SNW-STREAM-* rule condition.
#[derive(Debug, Clone, Default)]
pub struct StreamCreateFlags {
    /// `APPEND_ONLY = …` clause present on `CREATE STREAM`.
    /// Set from the *presence* of the property clause regardless of
    /// the assigned `TRUE` / `FALSE` value. Drives
    /// SNW-STREAM-APPENDONLY.
    pub append_only: bool,
    /// `INSERT_ONLY = …` clause present on `CREATE STREAM`. Drives
    /// SNW-STREAM-INSERTONLY.
    pub insert_only: bool,
}

/// Lower a typed [`AstCreateStream`] into a [`StreamPlan`].
///
/// Pure structural projection — every field comes from the typed
/// AST. The `APPEND_ONLY` / `INSERT_ONLY` flags reflect span
/// presence, independently of the boolean value side.
pub fn lower_create_stream_to_stream_plan(s: &AstCreateStream, source: &str) -> StreamPlan {
    let create_flags = StreamCreateFlags {
        append_only: s.append_only_span.is_some(),
        insert_only: s.insert_only_span.is_some(),
    };
    StreamPlan {
        action: StreamAction::Create,
        target: Some(target_from_span(source, s.name_span)),
        options: StreamOptions {
            or_replace: s.or_replace_span.is_some(),
            if_not_exists: s.if_not_exists_span.is_some(),
            if_exists: false,
        },
        create_flags,
        node_id: s.node_id,
        span: s.span,
    }
}

/// Lower a typed [`AstDropStream`] into a [`StreamPlan`].
pub fn lower_drop_stream_to_stream_plan(s: &AstDropStream, source: &str) -> StreamPlan {
    StreamPlan {
        action: StreamAction::Drop,
        target: Some(target_from_span(source, s.name_span)),
        options: StreamOptions {
            or_replace: false,
            if_not_exists: false,
            if_exists: s.if_exists_span.is_some(),
        },
        create_flags: StreamCreateFlags::default(),
        node_id: s.node_id,
        span: s.span,
    }
}

fn target_from_span(source: &str, span: Span) -> StreamTarget {
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
    StreamTarget {
        name,
        schema,
        db,
        span,
    }
}
