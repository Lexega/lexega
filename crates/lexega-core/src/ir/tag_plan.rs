// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! IR-side carrier for Snowflake `CREATE / ALTER / DROP / UNDROP TAG`.
//!
//! Sibling-tier carrier analogous to [`super::PipePlan`]: typed
//! projection of the AST that `derive_facts_from_tag_plan` folds into
//! the public `StatementFacts.ddl.tag` carrier.
//!
//! ALTER actions are kept as a typed list ([`TagAlterActionIr`]) rather
//! than flat booleans so downstream facts carry the actual policy names
//! and literal values — `ALTER TAG … UNSET MASKING POLICY` names which
//! protections every tagged column loses.

use crate::ast::{
    AstAlterTag, AstAlterTagActionKind, AstCreateTag, AstDrop, AstTagAllowedValues,
    AstTagUnsetProperty, AstUndropTag, NodeId,
};
use crate::lexer::token::Span;

#[derive(Debug, Clone)]
pub struct TagPlan {
    pub action: TagAction,
    pub target: Option<TagTarget>,
    pub options: TagOptions,
    /// Typed actions. CREATE-time ALLOWED_VALUES / PROPAGATE clauses
    /// are expressed with the same variants as ALTER … SET.
    pub alter_actions: Vec<TagAlterActionIr>,
    pub node_id: NodeId,
    pub span: Span,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TagAction {
    Create,
    Alter,
    Drop,
    Undrop,
}

#[derive(Debug, Clone)]
pub struct TagTarget {
    pub name: String,
    pub schema: Option<String>,
    pub db: Option<String>,
    pub span: Span,
}

#[derive(Debug, Clone, Default)]
pub struct TagOptions {
    pub or_replace: bool,
    pub if_not_exists: bool,
    pub if_exists: bool,
}

/// One typed CREATE/ALTER TAG action. CREATE-time ALLOWED_VALUES /
/// PROPAGATE clauses are expressed with the same variants as their
/// ALTER … SET counterparts.
#[derive(Debug, Clone)]
pub enum TagAlterActionIr {
    RenameTo {
        new_name: String,
    },
    SetAllowedValues {
        values: Vec<String>,
    },
    AddAllowedValues {
        values: Vec<String>,
    },
    DropAllowedValues {
        values: Vec<String>,
    },
    UnsetAllowedValues,
    SetPropagate {
        mode: String,
    },
    UnsetPropagate,
    SetOnConflict,
    UnsetOnConflict,
    SetComment,
    UnsetComment,
    SetMaskingPolicies {
        policies: Vec<TagPolicyRefIr>,
        force: bool,
    },
    UnsetMaskingPolicies {
        policies: Vec<TagPolicyRefIr>,
    },
    UnsetDcmProject,
}

/// A masking-policy reference in a SET/UNSET MASKING POLICY list.
#[derive(Debug, Clone)]
pub struct TagPolicyRefIr {
    /// Qualified policy name text as written.
    pub name: String,
    /// Span covering the policy name.
    pub span: Span,
}

/// Lower a typed [`AstCreateTag`] into a [`TagPlan`].
pub fn lower_create_tag_to_tag_plan(s: &AstCreateTag, source: &str) -> TagPlan {
    let mut actions = Vec::new();
    if let Some(values) = &s.allowed_values {
        actions.push(TagAlterActionIr::SetAllowedValues {
            values: literal_values(values, source),
        });
    }
    if let Some(prop) = &s.propagate {
        actions.push(TagAlterActionIr::SetPropagate {
            mode: span_text(source, prop.value_span).to_ascii_uppercase(),
        });
    }
    if s.on_conflict.is_some() {
        actions.push(TagAlterActionIr::SetOnConflict);
    }
    if s.comment_span.is_some() {
        actions.push(TagAlterActionIr::SetComment);
    }
    TagPlan {
        action: TagAction::Create,
        target: Some(target_from_span(source, s.name_span)),
        options: TagOptions {
            or_replace: s.or_replace_span.is_some(),
            if_not_exists: s.if_not_exists_span.is_some(),
            if_exists: false,
        },
        alter_actions: actions,
        node_id: s.node_id,
        span: s.span,
    }
}

/// Lower a typed [`AstAlterTag`] into a [`TagPlan`].
///
/// Closed-enum exhaustive `match` over [`AstAlterTagActionKind`] —
/// no `_ =>` arm.
pub fn lower_alter_tag_to_tag_plan(s: &AstAlterTag, source: &str) -> TagPlan {
    use AstAlterTagActionKind as K;
    let mut actions = Vec::new();
    match &s.action.kind {
        K::RenameTo { new_name_span, .. } => {
            actions.push(TagAlterActionIr::RenameTo {
                new_name: span_text(source, *new_name_span).trim().to_string(),
            });
        }
        K::AddAllowedValues { values, .. } => {
            actions.push(TagAlterActionIr::AddAllowedValues {
                values: literal_values(values, source),
            });
        }
        K::DropAllowedValues { values, .. } => {
            actions.push(TagAlterActionIr::DropAllowedValues {
                values: literal_values(values, source),
            });
        }
        K::Set {
            allowed_values,
            propagate,
            on_conflict,
            comment_span,
            ..
        } => {
            if let Some(values) = allowed_values {
                actions.push(TagAlterActionIr::SetAllowedValues {
                    values: literal_values(values, source),
                });
            }
            if let Some(prop) = propagate {
                actions.push(TagAlterActionIr::SetPropagate {
                    mode: span_text(source, prop.value_span).to_ascii_uppercase(),
                });
            }
            if on_conflict.is_some() {
                actions.push(TagAlterActionIr::SetOnConflict);
            }
            if comment_span.is_some() {
                actions.push(TagAlterActionIr::SetComment);
            }
        }
        K::Unset { property, .. } => {
            actions.push(match property {
                AstTagUnsetProperty::AllowedValues { .. } => TagAlterActionIr::UnsetAllowedValues,
                AstTagUnsetProperty::Propagate { .. } => TagAlterActionIr::UnsetPropagate,
                AstTagUnsetProperty::OnConflict { .. } => TagAlterActionIr::UnsetOnConflict,
                AstTagUnsetProperty::Comment { .. } => TagAlterActionIr::UnsetComment,
            });
        }
        K::SetMaskingPolicies {
            policies,
            force_span,
            ..
        } => {
            actions.push(TagAlterActionIr::SetMaskingPolicies {
                policies: policies
                    .iter()
                    .map(|p| TagPolicyRefIr {
                        name: span_text(source, p.name_span).trim().to_string(),
                        span: p.name_span,
                    })
                    .collect(),
                force: force_span.is_some(),
            });
        }
        K::UnsetMaskingPolicies { policies, .. } => {
            actions.push(TagAlterActionIr::UnsetMaskingPolicies {
                policies: policies
                    .iter()
                    .map(|p| TagPolicyRefIr {
                        name: span_text(source, p.name_span).trim().to_string(),
                        span: p.name_span,
                    })
                    .collect(),
            });
        }
        K::UnsetDcmProject { .. } => {
            actions.push(TagAlterActionIr::UnsetDcmProject);
        }
    }
    TagPlan {
        action: TagAction::Alter,
        target: Some(target_from_span(source, s.name_span)),
        options: TagOptions {
            or_replace: false,
            if_not_exists: false,
            if_exists: s.if_exists_span.is_some(),
        },
        alter_actions: actions,
        node_id: s.node_id,
        span: s.span,
    }
}

/// Lower a generic [`AstDrop`] whose object type is TAG into a
/// [`TagPlan`]. The caller gates on the object type (see
/// `drop_target_is_tag`).
pub fn lower_drop_tag_to_tag_plan(s: &AstDrop, source: &str) -> TagPlan {
    TagPlan {
        action: TagAction::Drop,
        target: s
            .target_name_span
            .map(|span| target_from_span(source, span)),
        options: TagOptions {
            or_replace: false,
            if_not_exists: false,
            if_exists: s.if_exists_span.is_some(),
        },
        alter_actions: Vec::new(),
        node_id: s.node_id,
        span: s.span,
    }
}

/// Lower a typed [`AstUndropTag`] into a [`TagPlan`].
pub fn lower_undrop_tag_to_tag_plan(s: &AstUndropTag, source: &str) -> TagPlan {
    TagPlan {
        action: TagAction::Undrop,
        target: Some(target_from_span(source, s.name_span)),
        options: TagOptions::default(),
        alter_actions: Vec::new(),
        node_id: s.node_id,
        span: s.span,
    }
}

/// Resolve the unquoted text of each ALLOWED_VALUES string literal.
fn literal_values(values: &AstTagAllowedValues, source: &str) -> Vec<String> {
    values
        .value_spans
        .iter()
        .map(|span| unquote_literal(span_text(source, *span)))
        .collect()
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

fn target_from_span(source: &str, span: Span) -> TagTarget {
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
    TagTarget {
        name,
        schema,
        db,
        span,
    }
}
