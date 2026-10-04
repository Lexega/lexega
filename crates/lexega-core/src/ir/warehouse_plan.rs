// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! IR-side carrier for Snowflake `CREATE / ALTER / DROP WAREHOUSE`.
//!
//! Sibling-tier fact analogous to [`super::PipePlan`], [`super::TaskPlan`],
//! and [`super::DatabasePlan`]: typed projection of the AST that downstream
//! `derive_facts_from_warehouse_plan` folds into a public
//! `StatementFacts.ddl.warehouse` carrier.
//!
//! The carrier collects per-property typed flags by interpreting per-property
//! spans for CREATE and by exhaustively classifying [`AstAlterWarehouseActionKind`]
//! for ALTER. Each flag corresponds 1:1 with a SNW-WH-* /
//! INFO-SNW-WH-* rule condition so YAML rules predicate against the
//! flag directly.
//!
//! `large_size`, `snowpark_optimized`, `auto_suspend_zero`, and
//! `set_changes_size` are decoded by reading the corresponding clause text
//! (case-insensitive containment / digit pattern): the parser captures only
//! the span of the property clause; the IR-lowering layer converts that span
//! into a typed boolean so the public facts surface stays text-free.

use crate::ast::{
    AstAlterWarehouse, AstAlterWarehouseActionKind, AstCreateWarehouse, AstDropWarehouse, NodeId,
};
use crate::lexer::token::Span;

#[derive(Debug, Clone)]
pub struct WarehousePlan {
    pub action: WarehouseAction,
    pub target: Option<WarehouseTarget>,
    pub options: WarehouseOptions,
    pub create_flags: WarehouseCreateFlags,
    pub alter_flags: WarehouseAlterFlags,
    pub node_id: NodeId,
    pub span: Span,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WarehouseAction {
    Create,
    Alter,
    Drop,
}

#[derive(Debug, Clone)]
pub struct WarehouseTarget {
    pub name: String,
    pub schema: Option<String>,
    pub db: Option<String>,
    pub span: Span,
}

#[derive(Debug, Clone, Default)]
pub struct WarehouseOptions {
    pub or_replace: bool,
    pub if_not_exists: bool,
    pub if_exists: bool,
}

/// Per-property typed flags collected from [`AstCreateWarehouse`]. Each
/// flag corresponds 1:1 with a SNW-WH-* / INFO-SNW-WH-* rule
/// condition.
#[derive(Debug, Clone, Default)]
pub struct WarehouseCreateFlags {
    /// `WAREHOUSE_SIZE` clause whose value is one of `4X-LARGE`,
    /// `5X-LARGE`, or `6X-LARGE` (case-insensitive containment in the
    /// clause text). Drives SNW-WH-LARGE.
    pub large_size: bool,
    /// `WAREHOUSE_TYPE = 'SNOWPARK-OPTIMIZED'` (case-insensitive
    /// containment of `SNOWPARK` in the clause text). Drives
    /// SNW-WH-SNOWPARK.
    pub snowpark_optimized: bool,
    /// `AUTO_SUSPEND = 0` — clause text trims to a value ending in a
    /// single literal `0` (not a multiple of 10). A fragile but
    /// well-defined heuristic. Drives SNW-WH-NO-AUTOSUSPEND.
    pub auto_suspend_zero: bool,
    /// `RESOURCE_MONITOR = …` clause present (any value). Drives
    /// INFO-SNW-WH-RESMON.
    pub resource_monitor_set: bool,
    /// `MAX_CLUSTER_COUNT` or `MIN_CLUSTER_COUNT` clause present (any
    /// value). Drives SNW-WH-MULTICLUSTER.
    pub multi_cluster: bool,
}

/// Per-action typed flags collected from [`AstAlterWarehouseActionKind`].
/// Each flag corresponds 1:1 with a SNW-WH-* rule condition.
#[derive(Debug, Clone, Default)]
pub struct WarehouseAlterFlags {
    /// `ALTER WAREHOUSE … SUSPEND`. Drives SNW-WH-SUSPEND.
    pub suspended: bool,
    /// `ALTER WAREHOUSE … RESUME`. Drives SNW-WH-RESUME.
    pub resumed: bool,
    /// `ALTER WAREHOUSE … ABORT ALL QUERIES`. Drives SNW-WH-ABORT.
    pub queries_aborted: bool,
    /// `ALTER WAREHOUSE … RENAME TO …`. Drives SNW-WH-RENAME.
    pub renamed: bool,
    /// `ALTER WAREHOUSE … SET …` action present. Drives SNW-WH-SET.
    pub set: bool,
    /// `ALTER WAREHOUSE … SET …` whose properties span contains
    /// `WAREHOUSE_SIZE` (case-insensitive). Drives SNW-WH-SIZE-CHG.
    pub set_changes_size: bool,
    /// `ALTER WAREHOUSE … SET TAG …` action present. Drives
    /// SNW-WH-TAG-SET.
    pub tag_set: bool,
    /// `ALTER WAREHOUSE … UNSET TAG …` action present. Drives
    /// SNW-WH-TAG-UNSET.
    pub tag_unset: bool,
}

/// Lower a typed [`AstCreateWarehouse`] into a [`WarehousePlan`].
pub fn lower_create_warehouse_to_warehouse_plan(
    s: &AstCreateWarehouse,
    source: &str,
) -> WarehousePlan {
    let large_size = match s.warehouse_size_span {
        Some(span) => classify_large_size_clause(source, span),
        None => false,
    };
    let snowpark_optimized = match s.warehouse_type_span {
        Some(span) => classify_snowpark_clause(source, span),
        None => false,
    };
    let auto_suspend_zero = match s.auto_suspend_span {
        Some(span) => classify_auto_suspend_zero_clause(source, span),
        None => false,
    };
    let resource_monitor_set = s.resource_monitor_span.is_some();
    let multi_cluster = s.max_cluster_count_span.is_some() || s.min_cluster_count_span.is_some();

    let create_flags = WarehouseCreateFlags {
        large_size,
        snowpark_optimized,
        auto_suspend_zero,
        resource_monitor_set,
        multi_cluster,
    };

    WarehousePlan {
        action: WarehouseAction::Create,
        target: Some(target_from_span(source, s.name_span)),
        options: WarehouseOptions {
            or_replace: s.or_replace_span.is_some(),
            if_not_exists: s.if_not_exists_span.is_some(),
            if_exists: false,
        },
        create_flags,
        alter_flags: WarehouseAlterFlags::default(),
        node_id: s.node_id,
        span: s.span,
    }
}

/// Lower a typed [`AstAlterWarehouse`] into a [`WarehousePlan`].
///
/// Walks the single `action.kind` and sets the matching typed flag.
/// Closed-enum exhaustive `match` with no `_ =>` arm — every
/// [`AstAlterWarehouseActionKind`] variant is enumerated explicitly.
pub fn lower_alter_warehouse_to_warehouse_plan(
    s: &AstAlterWarehouse,
    source: &str,
) -> WarehousePlan {
    let mut flags = WarehouseAlterFlags::default();
    classify_alter_action(&s.action.kind, source, &mut flags);

    WarehousePlan {
        action: WarehouseAction::Alter,
        target: Some(target_from_span(source, s.name_span)),
        options: WarehouseOptions {
            or_replace: false,
            if_not_exists: false,
            if_exists: s.if_exists_span.is_some(),
        },
        create_flags: WarehouseCreateFlags::default(),
        alter_flags: flags,
        node_id: s.node_id,
        span: s.span,
    }
}

/// Lower a typed [`AstDropWarehouse`] into a [`WarehousePlan`].
pub fn lower_drop_warehouse_to_warehouse_plan(s: &AstDropWarehouse, source: &str) -> WarehousePlan {
    WarehousePlan {
        action: WarehouseAction::Drop,
        target: Some(target_from_span(source, s.name_span)),
        options: WarehouseOptions {
            or_replace: false,
            if_not_exists: false,
            if_exists: s.if_exists_span.is_some(),
        },
        create_flags: WarehouseCreateFlags::default(),
        alter_flags: WarehouseAlterFlags::default(),
        node_id: s.node_id,
        span: s.span,
    }
}

fn classify_alter_action(
    kind: &AstAlterWarehouseActionKind,
    source: &str,
    flags: &mut WarehouseAlterFlags,
) {
    use AstAlterWarehouseActionKind as K;
    match kind {
        K::Suspend { .. } => flags.suspended = true,
        K::Resume { .. } => flags.resumed = true,
        K::AbortAllQueries { .. } => flags.queries_aborted = true,
        K::RenameTo { .. } => flags.renamed = true,
        K::Set {
            properties_span, ..
        } => {
            flags.set = true;
            flags.set_changes_size = classify_set_properties_clause(source, *properties_span);
        }
        K::Unset { .. } => {
            // No SNW-WH-* rule predicates on UNSET — it sets no flag.
        }
        K::SetTag { .. } => flags.tag_set = true,
        K::UnsetTag { .. } => flags.tag_unset = true,
    }
}

/// Decode `WAREHOUSE_SIZE = '<size>'` clause text: case-insensitive
/// containment of any of `4X-LARGE` / `5X-LARGE` / `6X-LARGE` in the
/// upper-cased clause text. Returns `false` for an unreadable span.
fn classify_large_size_clause(source: &str, span: Span) -> bool {
    let Some(text) = source.get(span.start as usize..span.end as usize) else {
        return false;
    };
    let upper = text.to_ascii_uppercase();
    upper.contains("4X-LARGE") || upper.contains("5X-LARGE") || upper.contains("6X-LARGE")
}

/// Decode `WAREHOUSE_TYPE = '<value>'` clause text:
/// case-insensitive containment of `SNOWPARK` in the upper-cased
/// clause text. Returns `false` for an unreadable span.
fn classify_snowpark_clause(source: &str, span: Span) -> bool {
    let Some(text) = source.get(span.start as usize..span.end as usize) else {
        return false;
    };
    text.to_ascii_uppercase().contains("SNOWPARK")
}

/// Decode `AUTO_SUSPEND = <num>` clause text with a
/// fragile-but-well-defined heuristic:
///
/// 1. Span text contains the digit `0`,
/// 2. AND span text does not contain the substring `60`,
/// 3. AND span text does not contain the substring `30`,
/// 4. AND the trimmed span ends with `0`,
/// 5. AND the trimmed span does not end with `10`, `20`, `30`, …, `90`,
///    `00`.
///
/// In effect: `AUTO_SUSPEND = 0` fires; `AUTO_SUSPEND = 60`,
/// `AUTO_SUSPEND = 30`, `AUTO_SUSPEND = 100`, etc. do not. Returns
/// `false` for an unreadable span.
fn classify_auto_suspend_zero_clause(source: &str, span: Span) -> bool {
    let Some(text) = source.get(span.start as usize..span.end as usize) else {
        return false;
    };
    if !(text.contains('0') && !text.contains("60") && !text.contains("30")) {
        return false;
    }
    let trimmed = text.trim();
    if !trimmed.ends_with('0') {
        return false;
    }
    !(trimmed.ends_with("10")
        || trimmed.ends_with("20")
        || trimmed.ends_with("30")
        || trimmed.ends_with("40")
        || trimmed.ends_with("50")
        || trimmed.ends_with("60")
        || trimmed.ends_with("70")
        || trimmed.ends_with("80")
        || trimmed.ends_with("90")
        || trimmed.ends_with("00"))
}

/// Decode an `ALTER WAREHOUSE … SET <properties>` clause's properties
/// span: case-insensitive containment of `WAREHOUSE_SIZE` in the
/// upper-cased clause text. Returns `false` for an unreadable span.
fn classify_set_properties_clause(source: &str, span: Span) -> bool {
    let Some(text) = source.get(span.start as usize..span.end as usize) else {
        return false;
    };
    text.to_ascii_uppercase().contains("WAREHOUSE_SIZE")
}

fn target_from_span(source: &str, span: Span) -> WarehouseTarget {
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
    WarehouseTarget {
        name,
        schema,
        db,
        span,
    }
}
