// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! IR-side carrier for Snowflake `CREATE / ALTER / DROP DYNAMIC TABLE`.
//!
//! Sibling-tier fact analogous to [`super::PrivilegePlan`],
//! [`super::StagePlan`], and [`super::StorageCredentialPlan`]: typed
//! projection of the AST that downstream
//! `derive_facts_from_dynamic_table_plan` folds into a public
//! `StatementFacts.ddl.dynamic_table` carrier.
//!
//! The carrier collects per-action typed flags by walking
//! `AstAlterDynamicTable.action` plus its `additional_actions` (which
//! does not exist on this AST — only one action per ALTER, but
//! mirrored future-proof by still iterating). Each flag corresponds
//! 1:1 with a SNW-DYNTBL-* rule condition so
//! YAML rules predicate against the flag directly.

use crate::ast::{
    AstAlterDynamicTable, AstAlterDynamicTableActionKind, AstCreateDynamicTable, AstDrop, NodeId,
};
use crate::lexer::token::Span;

#[derive(Debug, Clone)]
pub struct DynamicTablePlan {
    pub action: DynamicTableAction,
    pub target: Option<DynamicTableTarget>,
    pub options: DynamicTableOptions,
    pub alter_flags: DynamicTableAlterFlags,
    /// `CREATE DYNAMIC TABLE … AS <query>` where the query body did
    /// not parse. Always `false` for ALTER / DROP.
    pub query_unparseable: bool,
    pub node_id: NodeId,
    pub span: Span,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DynamicTableAction {
    /// `CREATE DYNAMIC TABLE`
    Create,
    /// `ALTER DYNAMIC TABLE`
    Alter,
    /// `DROP DYNAMIC TABLE` — projected from the generic
    /// `AstStmt::Drop` when `object_type_span` resolves to `DYNAMIC
    /// TABLE`.
    Drop,
}

#[derive(Debug, Clone)]
pub struct DynamicTableTarget {
    pub name: String,
    pub schema: Option<String>,
    pub db: Option<String>,
    pub span: Span,
}

#[derive(Debug, Clone, Default)]
pub struct DynamicTableOptions {
    pub or_replace: bool,
    pub or_alter: bool,
    pub if_not_exists: bool,
    pub if_exists: bool,
    pub transient: bool,
    pub iceberg: bool,
    pub cascade: bool,
    pub restrict: bool,
}

/// Per-category typed flags collected from
/// [`AstAlterDynamicTableActionKind`]. Each flag is set when the
/// action list contains at least one matching variant. The flags are
/// projected 1:1 onto the public `DynamicTableFacts` typed slot.
#[derive(Debug, Clone, Default)]
pub struct DynamicTableAlterFlags {
    pub suspended: bool,
    pub resumed: bool,
    pub renamed: bool,
    pub swapped: bool,
    pub tag_set: bool,
    pub tag_unset: bool,
    pub row_access_policy_added: bool,
    pub row_access_policy_removed: bool,
    pub masking_policy_added: bool,
    pub masking_policy_removed: bool,
}

/// Lower a typed [`AstCreateDynamicTable`] into a [`DynamicTablePlan`].
pub fn lower_create_dynamic_table_to_dynamic_table_plan(
    s: &AstCreateDynamicTable,
    source: &str,
) -> DynamicTablePlan {
    DynamicTablePlan {
        action: DynamicTableAction::Create,
        target: Some(target_from_span(source, s.name_span)),
        options: DynamicTableOptions {
            or_replace: s.or_replace_span.is_some(),
            or_alter: s.or_alter_span.is_some(),
            if_not_exists: s.if_not_exists_span.is_some(),
            if_exists: false,
            transient: s.transient_span.is_some(),
            iceberg: s.iceberg_span.is_some(),
            cascade: false,
            restrict: false,
        },
        alter_flags: DynamicTableAlterFlags::default(),
        query_unparseable: s.query.is_err(),
        node_id: s.node_id,
        span: s.span,
    }
}

/// Lower a typed [`AstAlterDynamicTable`] into a [`DynamicTablePlan`].
///
/// Walks the single `action.kind` and sets the matching typed flags.
/// Closed-enum exhaustive `match` with no `_ =>` arm — every
/// `AstAlterDynamicTableActionKind` variant is enumerated explicitly.
pub fn lower_alter_dynamic_table_to_dynamic_table_plan(
    s: &AstAlterDynamicTable,
    source: &str,
) -> DynamicTablePlan {
    let mut flags = DynamicTableAlterFlags::default();
    classify_alter_action(&s.action.kind, &mut flags);

    DynamicTablePlan {
        action: DynamicTableAction::Alter,
        target: Some(target_from_span(source, s.name_span)),
        options: DynamicTableOptions {
            or_replace: false,
            or_alter: false,
            if_not_exists: false,
            if_exists: s.if_exists_span.is_some(),
            transient: false,
            iceberg: false,
            cascade: false,
            restrict: false,
        },
        alter_flags: flags,
        query_unparseable: false,
        node_id: s.node_id,
        span: s.span,
    }
}

/// Lower a generic `AstStmt::Drop` into a [`DynamicTablePlan`] when
/// the `object_type_span` resolves to `DYNAMIC TABLE`
/// (case-insensitive, whitespace-tolerant).
///
/// Returns `None` for any other object type — DROP for non-dynamic-table
/// targets is handled by other lowerings (`lower_drop_stage_to_stage_plan`,
/// generic DDL lowering).
pub fn lower_drop_dynamic_table_to_dynamic_table_plan(
    s: &AstDrop,
    source: &str,
) -> Option<DynamicTablePlan> {
    let object_type_span = s.object_type_span?;
    let text = source.get(object_type_span.start as usize..object_type_span.end as usize)?;
    let normalized = normalize_object_type(text);
    if normalized != "DYNAMIC TABLE" {
        return None;
    }
    let target = s.target_name_span.map(|sp| target_from_span(source, sp));
    let cascade =
        matches!(s.cascade_restrict_span, Some(span) if matches_keyword(source, span, "CASCADE"));
    let restrict =
        matches!(s.cascade_restrict_span, Some(span) if matches_keyword(source, span, "RESTRICT"));
    Some(DynamicTablePlan {
        action: DynamicTableAction::Drop,
        target,
        options: DynamicTableOptions {
            or_replace: false,
            or_alter: false,
            if_not_exists: false,
            if_exists: s.if_exists_span.is_some(),
            transient: false,
            iceberg: false,
            cascade,
            restrict,
        },
        alter_flags: DynamicTableAlterFlags::default(),
        query_unparseable: false,
        node_id: s.node_id,
        span: s.span,
    })
}

/// Closed-enum classification of one `AstAlterDynamicTableActionKind`
/// into per-category flags.
fn classify_alter_action(
    kind: &AstAlterDynamicTableActionKind,
    flags: &mut DynamicTableAlterFlags,
) {
    use AstAlterDynamicTableActionKind as K;
    match kind {
        K::Suspend { .. } | K::SuspendRecluster { .. } => flags.suspended = true,
        K::Resume { .. } | K::ResumeRecluster { .. } => flags.resumed = true,
        K::RenameTo { .. } => flags.renamed = true,
        K::SwapWith { .. } => flags.swapped = true,
        K::SetTag { .. } | K::SetColumnTag { .. } => flags.tag_set = true,
        K::UnsetTag { .. } | K::UnsetColumnTag { .. } => flags.tag_unset = true,
        K::AddRowAccessPolicy { .. } => flags.row_access_policy_added = true,
        K::DropRowAccessPolicy { .. } | K::DropAllRowAccessPolicies { .. } => {
            flags.row_access_policy_removed = true
        }
        K::SetColumnMaskingPolicy { .. } => flags.masking_policy_added = true,
        K::UnsetColumnMaskingPolicy { .. } => flags.masking_policy_removed = true,

        // Actions that do not map to any SNW-DYNTBL-* rule.
        K::Refresh { .. }
        | K::Set { .. }
        | K::Unset { .. }
        | K::SetComment { .. }
        | K::UnsetComment { .. }
        | K::ClusterBy { .. }
        | K::DropClusteringKey { .. }
        | K::SetColumnComment { .. }
        | K::UnsetColumnComment { .. }
        | K::SetAggregationPolicy { .. }
        | K::UnsetAggregationPolicy { .. }
        | K::SetColumnProjectionPolicy { .. }
        | K::UnsetColumnProjectionPolicy { .. }
        | K::AddSearchOptimization { .. }
        | K::DropSearchOptimization { .. }
        | K::SuspendSearchOptimization { .. }
        | K::ResumeSearchOptimization { .. }
        | K::Unknown { .. } => {}
    }
}

fn target_from_span(source: &str, span: Span) -> DynamicTableTarget {
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
    DynamicTableTarget {
        name,
        schema,
        db,
        span,
    }
}

fn normalize_object_type(text: &str) -> String {
    text.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_uppercase()
}

fn matches_keyword(source: &str, span: Span, keyword: &str) -> bool {
    source
        .get(span.start as usize..span.end as usize)
        .map(|s| s.trim().eq_ignore_ascii_case(keyword))
        .unwrap_or(false)
}
