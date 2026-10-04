// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! IR-side carrier for Amazon Redshift `CREATE / ALTER DATASHARE`.
//!
//! Sibling-tier fact analogous to [`super::StreamPlan`]: a typed projection of
//! the AST that downstream `derive_facts_from_datashare_plan` folds into a
//! public `StatementFacts.ddl.datashare` carrier.
//!
//! Unlike the generic minimal-DDL path (which yields `ddl: None` and exposes no
//! typed primitives — the route Snowflake SHARE takes), a datashare needs
//! per-element exposure primitives for cross-account governance:
//! `publicly_accessible`, the typed added/removed object list, and the
//! `INCLUDENEW` auto-share flag. Governance ("publicly accessible = critical")
//! is policy and lives in YAML; the IR only surfaces the typed facts.

use crate::ast::types::{AstAlterDatashareActionKind, AstDatashareObjectKind};
use crate::ast::{AstAlterDatashare, AstCreateDatashare, NodeId};
use crate::lexer::token::Span;

#[derive(Debug, Clone)]
pub struct DatasharePlan {
    pub action: DatashareAction,
    pub target: Option<DatashareTarget>,
    pub options: DatashareOptions,
    /// `SET PUBLICACCESSIBLE [=] TRUE|FALSE` — `Some(value)` when present.
    pub publicly_accessible: Option<bool>,
    /// `SET INCLUDENEW = TRUE FOR SCHEMA …` — auto-inclusion of newly created
    /// objects is being ENABLED. `false` for `= FALSE` (disabling) or absent.
    pub includenew_set: bool,
    /// Per-object ADD/REMOVE changes (typed element-level primitives).
    pub object_changes: Vec<DatashareObjectChange>,
    /// An unrecognized ALTER action body was encountered.
    pub has_unknown_clauses: bool,
    pub node_id: NodeId,
    pub span: Span,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DatashareAction {
    /// `CREATE DATASHARE`
    Create,
    /// `ALTER DATASHARE`
    Alter,
}

#[derive(Debug, Clone)]
pub struct DatashareTarget {
    pub name: String,
    pub schema: Option<String>,
    pub db: Option<String>,
    pub span: Span,
}

#[derive(Debug, Clone, Default)]
pub struct DatashareOptions {
    pub or_replace: bool,
    pub if_not_exists: bool,
}

/// Object kind referenced by an ADD/REMOVE datashare action (IR tier).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DatashareObjectKind {
    Table,
    Schema,
}

#[derive(Debug, Clone)]
pub struct DatashareObjectChange {
    pub object_kind: DatashareObjectKind,
    /// `true` for ADD, `false` for REMOVE.
    pub added: bool,
    pub name: String,
    pub span: Span,
}

/// Lower a typed [`AstCreateDatashare`] into a [`DatasharePlan`].
pub fn lower_create_datashare_to_datashare_plan(
    s: &AstCreateDatashare,
    source: &str,
) -> DatasharePlan {
    DatasharePlan {
        action: DatashareAction::Create,
        target: Some(target_from_span(source, s.name_span)),
        options: DatashareOptions {
            or_replace: s.or_replace_span.is_some(),
            if_not_exists: s.if_not_exists_span.is_some(),
        },
        publicly_accessible: s.publicly_accessible,
        includenew_set: false,
        object_changes: Vec::new(),
        has_unknown_clauses: false,
        node_id: s.node_id,
        span: s.span,
    }
}

/// Lower a typed [`AstAlterDatashare`] into a [`DatasharePlan`].
pub fn lower_alter_datashare_to_datashare_plan(
    s: &AstAlterDatashare,
    source: &str,
) -> DatasharePlan {
    let mut publicly_accessible = None;
    let mut includenew_set = false;
    let mut object_changes = Vec::new();
    let mut has_unknown_clauses = false;

    match &s.action.kind {
        AstAlterDatashareActionKind::AddObject {
            object_kind,
            name_span,
            ..
        } => object_changes.push(object_change(*object_kind, true, source, *name_span)),
        AstAlterDatashareActionKind::RemoveObject {
            object_kind,
            name_span,
            ..
        } => object_changes.push(object_change(*object_kind, false, source, *name_span)),
        AstAlterDatashareActionKind::SetPublicAccessible { value, .. } => {
            publicly_accessible = Some(*value);
        }
        AstAlterDatashareActionKind::SetIncludeNew { value, .. } => {
            // Reflect the literal value: `INCLUDENEW = TRUE` enables auto-inclusion
            // (the governance risk); `= FALSE` disables it and must stay silent.
            includenew_set = *value;
        }
        AstAlterDatashareActionKind::SetProperty { .. } => {}
        AstAlterDatashareActionKind::Unknown(_) => {
            has_unknown_clauses = true;
        }
    }

    DatasharePlan {
        action: DatashareAction::Alter,
        target: Some(target_from_span(source, s.name_span)),
        options: DatashareOptions::default(),
        publicly_accessible,
        includenew_set,
        object_changes,
        has_unknown_clauses,
        node_id: s.node_id,
        span: s.span,
    }
}

fn object_change(
    ast_kind: AstDatashareObjectKind,
    added: bool,
    source: &str,
    span: Span,
) -> DatashareObjectChange {
    let object_kind = match ast_kind {
        AstDatashareObjectKind::Table => DatashareObjectKind::Table,
        AstDatashareObjectKind::Schema => DatashareObjectKind::Schema,
    };
    let name = source
        .get(span.start as usize..span.end as usize)
        .unwrap_or("")
        .trim()
        .to_string();
    DatashareObjectChange {
        object_kind,
        added,
        name,
        span,
    }
}

fn target_from_span(source: &str, span: Span) -> DatashareTarget {
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
    DatashareTarget {
        name,
        schema,
        db,
        span,
    }
}
