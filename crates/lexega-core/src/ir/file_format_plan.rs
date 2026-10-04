// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! IR-side carrier for Snowflake `CREATE / ALTER / DROP FILE FORMAT`.
//!
//! Sibling-tier carrier analogous to [`super::TagPlan`]: typed projection
//! of the AST that `derive_facts_from_file_format_plan` folds into the
//! public `StatementFacts.ddl.file_format` carrier.
//!
//! `TYPE` is lifted out of the generic property bag into a typed
//! recognition primitive ([`FileFormatPlan::format_type`]); the remaining
//! `KEY = value` options stay as names only — which option value is
//! dangerous is a YAML policy decision, not a Rust one.

use crate::ast::{
    AstAlterFileFormat, AstAlterFileFormatActionKind, AstCreateFileFormat, AstDrop,
    AstObjectProperty, NodeId,
};
use crate::lexer::token::Span;

#[derive(Debug, Clone)]
pub struct FileFormatPlan {
    pub action: FileFormatAction,
    pub target: Option<FileFormatTarget>,
    pub options: FileFormatOptions,
    /// Recognized FILE FORMAT TYPE (upper-cased: CSV / JSON / AVRO / ORC /
    /// PARQUET / XML / …), when a `TYPE = <t>` property is present.
    pub format_type: Option<String>,
    /// `ALTER FILE FORMAT … RENAME TO` target, as written.
    pub renamed_to: Option<String>,
    pub node_id: NodeId,
    pub span: Span,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FileFormatAction {
    Create,
    Alter,
    Drop,
}

#[derive(Debug, Clone)]
pub struct FileFormatTarget {
    pub name: String,
    pub schema: Option<String>,
    pub db: Option<String>,
    pub span: Span,
}

#[derive(Debug, Clone, Default)]
pub struct FileFormatOptions {
    pub or_replace: bool,
    pub if_not_exists: bool,
    pub if_exists: bool,
    /// TEMP / TEMPORARY / VOLATILE transience present.
    pub temporary: bool,
    /// The transience keyword was specifically VOLATILE.
    pub volatile: bool,
}

/// Lower a typed [`AstCreateFileFormat`] into a [`FileFormatPlan`].
pub fn lower_create_file_format_to_plan(s: &AstCreateFileFormat, source: &str) -> FileFormatPlan {
    FileFormatPlan {
        action: FileFormatAction::Create,
        target: Some(target_from_span(source, s.name_span)),
        options: FileFormatOptions {
            or_replace: s.or_replace_span.is_some(),
            if_not_exists: s.if_not_exists_span.is_some(),
            if_exists: false,
            temporary: s.transient_span.is_some(),
            volatile: s.volatile,
        },
        format_type: property_value(&s.properties, source, "TYPE"),
        renamed_to: None,
        node_id: s.node_id,
        span: s.span,
    }
}

/// Lower a typed [`AstAlterFileFormat`] into a [`FileFormatPlan`].
///
/// Closed-enum exhaustive `match` over [`AstAlterFileFormatActionKind`] —
/// no `_ =>` arm.
pub fn lower_alter_file_format_to_plan(s: &AstAlterFileFormat, source: &str) -> FileFormatPlan {
    let (format_type, renamed_to) = match &s.action {
        AstAlterFileFormatActionKind::RenameTo { new_name_span, .. } => (
            None,
            Some(span_text(source, *new_name_span).trim().to_string()),
        ),
        AstAlterFileFormatActionKind::Set { properties, .. } => {
            (property_value(properties, source, "TYPE"), None)
        }
    };
    FileFormatPlan {
        action: FileFormatAction::Alter,
        target: Some(target_from_span(source, s.name_span)),
        options: FileFormatOptions {
            or_replace: false,
            if_not_exists: false,
            if_exists: s.if_exists_span.is_some(),
            temporary: false,
            volatile: false,
        },
        format_type,
        renamed_to,
        node_id: s.node_id,
        span: s.span,
    }
}

/// Lower a generic [`AstDrop`] whose object type is FILE FORMAT into a
/// [`FileFormatPlan`]. The caller gates on the object type (see
/// `drop_target_is_file_format`).
pub fn lower_drop_file_format_to_plan(s: &AstDrop, source: &str) -> FileFormatPlan {
    FileFormatPlan {
        action: FileFormatAction::Drop,
        target: s
            .target_name_span
            .map(|span| target_from_span(source, span)),
        options: FileFormatOptions {
            or_replace: false,
            if_not_exists: false,
            if_exists: s.if_exists_span.is_some(),
            temporary: false,
            volatile: false,
        },
        format_type: None,
        renamed_to: None,
        node_id: s.node_id,
        span: s.span,
    }
}

/// Find the property whose name matches `key` (case-insensitive) and return
/// its value text, upper-cased with surrounding single quotes stripped.
fn property_value(properties: &[AstObjectProperty], source: &str, key: &str) -> Option<String> {
    properties.iter().find_map(|prop| {
        let name = span_text(source, prop.name_span).trim();
        if !name.eq_ignore_ascii_case(key) {
            return None;
        }
        let value_span = prop.value_span?;
        let raw = span_text(source, value_span).trim();
        Some(unquote_literal(raw).to_ascii_uppercase())
    })
}

/// Strip surrounding `'…'` quotes and fold `''` escapes if present;
/// otherwise return the input unchanged.
fn unquote_literal(raw: &str) -> String {
    if raw.len() >= 2 && raw.starts_with('\'') && raw.ends_with('\'') {
        raw[1..raw.len() - 1].replace("''", "'")
    } else {
        raw.to_string()
    }
}

fn span_text(source: &str, span: Span) -> &str {
    source
        .get(span.start as usize..span.end as usize)
        .unwrap_or("")
}

fn target_from_span(source: &str, span: Span) -> FileFormatTarget {
    let raw = span_text(source, span).trim();
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
    FileFormatTarget {
        name,
        schema,
        db,
        span,
    }
}
