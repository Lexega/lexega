// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! IR-side carrier for Databricks / Delta / SparkSQL table-maintenance
//! statements: `VACUUM`, `OPTIMIZE`, `RESTORE`, `DESCRIBE HISTORY`,
//! `[MSCK] REPAIR TABLE`, `CACHE [LAZY] TABLE`, and `UNCACHE TABLE`.
//!
//! Sibling-tier fact analogous to [`super::TablePlan`] and
//! [`super::StreamPlan`]: typed projection of the AST that downstream
//! `derive_facts_from_table_maintenance_plan` folds into a public
//! `StatementFacts.ddl.table_maintenance` carrier.
//!
//! The carrier discriminates on [`TableMaintenanceKind`] and exposes
//! kind-specific structural facts (`VacuumOptions::retain_hours`,
//! `CacheOptions::lazy`, `RepairOptions::mode`) as orthogonal IR
//! primitives. Rule predicates compose against these primitives — the
//! IR exposes inputs, the YAML composes verdicts. The substrate has no
//! `is_zero_retention` / `is_lazy_cache` digest field.
//!
//! 1:1 IR-vs-public-facts mirroring is intentional here: each variant
//! of [`TableMaintenanceKind`] maps to a distinct user-visible SQL
//! statement form (VACUUM ≠ OPTIMIZE ≠ RESTORE …), and the IR has no
//! finer distinctions to collapse. Future rules that need additional
//! structural facts (e.g. RESTORE time-travel kind) extend the
//! per-kind option carrier rather than splitting [`TableMaintenanceKind`].

use crate::ast::types::RepairPartitionsMode;
use crate::ast::{
    AstCacheTable, AstDescribeHistory, AstOptimize, AstRepairTable, AstRestore, AstUncacheTable,
    AstVacuum, NodeId,
};
use crate::ir::table_plan::{target_from_span, TableTarget};
use crate::lexer::token::Span;

#[derive(Debug, Clone)]
pub struct TableMaintenancePlan {
    pub kind: TableMaintenanceKind,
    pub target: Option<TableTarget>,
    /// `VACUUM`-specific knobs. `Some` iff `kind == Vacuum`.
    pub vacuum: Option<VacuumOptions>,
    /// `CACHE TABLE`-specific knobs. `Some` iff `kind == CacheTable`.
    pub cache: Option<CacheOptions>,
    /// `[MSCK] REPAIR TABLE`-specific knobs. `Some` iff
    /// `kind == RepairTable`.
    pub repair: Option<RepairOptions>,
    pub node_id: NodeId,
    pub span: Span,
}

/// Closed enum of table-maintenance SQL statement forms. Each variant
/// names the SQL surface, not a rule verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TableMaintenanceKind {
    /// `VACUUM <table> [RETAIN <n> HOURS] [DRY RUN]` (Delta) or
    /// `VACUUM <table> { FULL | LITE } [DRY RUN]` (Iceberg).
    Vacuum,
    /// `OPTIMIZE <table> [WHERE …] [ZORDER BY (…)]`.
    Optimize,
    /// `RESTORE [TABLE] <table> [TO] { TIMESTAMP AS OF <expr> |
    /// VERSION AS OF <int> }`.
    Restore,
    /// `DESCRIBE HISTORY <table>`.
    DescribeHistory,
    /// `[MSCK] REPAIR TABLE <table> [{ADD|DROP|SYNC} PARTITIONS]`.
    RepairTable,
    /// `CACHE [LAZY] TABLE <table> [OPTIONS …] [[AS] <query>]`.
    CacheTable,
    /// `UNCACHE TABLE [IF EXISTS] <table>`.
    UncacheTable,
}

/// Structural facts about a `VACUUM` statement. Currently the
/// retention-hour count from `RETAIN <n> HOURS`; `None` when omitted
/// (PostgreSQL VACUUM, or Delta VACUUM that takes the default).
/// DBX-VACUUM-ZERO predicates `retain_hours == 0`; DBX-VACUUM-LOWRET
/// predicates `retain_hours < 168` (which subsumes ZERO — both rules
/// fire on `RETAIN 0 HOURS`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct VacuumOptions {
    pub retain_hours: Option<u64>,
}

/// Structural facts about a `CACHE TABLE` statement. `lazy` is `true`
/// iff the `LAZY` keyword is present; rules compose against this to
/// split eager-vs-deferred caching (DBX-TBL-CACHE vs INFO-DBX-TBL-CACHE-LAZY).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct CacheOptions {
    pub lazy: bool,
}

/// Structural facts about a `[MSCK] REPAIR TABLE` statement. `mode`
/// reflects the optional `{ADD|DROP|SYNC} PARTITIONS` suffix
/// (`None` when absent from source).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RepairOptions {
    pub mode: Option<RepairPartitionsMode>,
}

/// Lower a typed [`AstVacuum`] into a [`TableMaintenancePlan`].
pub fn lower_vacuum_to_table_maintenance_plan(s: &AstVacuum, source: &str) -> TableMaintenancePlan {
    TableMaintenancePlan {
        kind: TableMaintenanceKind::Vacuum,
        target: s.table_name.map(|sp| target_from_span(source, sp)),
        vacuum: Some(VacuumOptions {
            retain_hours: s.retain_hours,
        }),
        cache: None,
        repair: None,
        node_id: s.node_id,
        span: s.span,
    }
}

/// Lower a typed [`AstOptimize`] into a [`TableMaintenancePlan`].
pub fn lower_optimize_to_table_maintenance_plan(
    s: &AstOptimize,
    source: &str,
) -> TableMaintenancePlan {
    TableMaintenancePlan {
        kind: TableMaintenanceKind::Optimize,
        target: Some(target_from_span(source, s.table_name_span)),
        vacuum: None,
        cache: None,
        repair: None,
        node_id: s.node_id,
        span: s.span,
    }
}

/// Lower a typed [`AstRestore`] into a [`TableMaintenancePlan`].
pub fn lower_restore_to_table_maintenance_plan(
    s: &AstRestore,
    source: &str,
) -> TableMaintenancePlan {
    TableMaintenancePlan {
        kind: TableMaintenanceKind::Restore,
        target: Some(target_from_span(source, s.table_name_span)),
        vacuum: None,
        cache: None,
        repair: None,
        node_id: s.node_id,
        span: s.span,
    }
}

/// Lower a typed [`AstDescribeHistory`] into a [`TableMaintenancePlan`].
pub fn lower_describe_history_to_table_maintenance_plan(
    s: &AstDescribeHistory,
    source: &str,
) -> TableMaintenancePlan {
    TableMaintenancePlan {
        kind: TableMaintenanceKind::DescribeHistory,
        target: Some(target_from_span(source, s.table_name_span)),
        vacuum: None,
        cache: None,
        repair: None,
        node_id: s.node_id,
        span: s.span,
    }
}

/// Lower a typed [`AstRepairTable`] into a [`TableMaintenancePlan`].
pub fn lower_repair_table_to_table_maintenance_plan(
    s: &AstRepairTable,
    source: &str,
) -> TableMaintenancePlan {
    TableMaintenancePlan {
        kind: TableMaintenanceKind::RepairTable,
        target: Some(target_from_span(source, s.table_name_span)),
        vacuum: None,
        cache: None,
        repair: Some(RepairOptions {
            mode: s.partitions_mode,
        }),
        node_id: s.node_id,
        span: s.span,
    }
}

/// Lower a typed [`AstCacheTable`] into a [`TableMaintenancePlan`].
pub fn lower_cache_table_to_table_maintenance_plan(
    s: &AstCacheTable,
    source: &str,
) -> TableMaintenancePlan {
    TableMaintenancePlan {
        kind: TableMaintenanceKind::CacheTable,
        target: Some(target_from_span(source, s.table_name_span)),
        vacuum: None,
        cache: Some(CacheOptions {
            lazy: s.lazy_keyword_span.is_some(),
        }),
        repair: None,
        node_id: s.node_id,
        span: s.span,
    }
}

/// Lower a typed [`AstUncacheTable`] into a [`TableMaintenancePlan`].
pub fn lower_uncache_table_to_table_maintenance_plan(
    s: &AstUncacheTable,
    source: &str,
) -> TableMaintenancePlan {
    TableMaintenancePlan {
        kind: TableMaintenanceKind::UncacheTable,
        target: Some(target_from_span(source, s.table_name_span)),
        vacuum: None,
        cache: None,
        repair: None,
        node_id: s.node_id,
        span: s.span,
    }
}
