// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! IR-side carrier for `CREATE / ALTER / DROP TABLE`, `TRUNCATE`, and
//! the top-level `DROP ALL ROW ACCESS POLICIES <table>` statement.
//!
//! Sibling-tier fact analogous to [`super::DynamicTablePlan`] and
//! [`super::WarehousePlan`]: typed projection of the AST that
//! downstream `derive_facts_from_table_plan` folds into a public
//! `StatementFacts.ddl.table` carrier.
//!
//! The carrier collects per-action typed flags by walking
//! `AstAlterTable.actions`. Each flag corresponds 1:1 with a TBL-*
//! rule condition so YAML rules predicate against
//! the flag directly. The `Drop` variant projects from the generic
//! `AstStmt::Drop` only when the `object_type_span` resolves to
//! `TABLE` (case-insensitive), so non-table DROP statements are
//! handled by other lowerings.

use crate::ast::{
    AstAlterTable, AstAlterTableActionKind, AstCreateTable, AstDrop, AstDropAllRowAccessPolicies,
    AstMysqlRenameTable, AstTruncate, NodeId,
};
use crate::lexer::token::Span;

#[derive(Debug, Clone)]
pub struct TablePlan {
    pub action: TableAction,
    pub target: Option<TableTarget>,
    pub options: TableOptions,
    pub alter_flags: TableAlterFlags,
    /// Typed list of `ALTER TABLE` action variants relevant to the
    /// DBX-TBL-* rule corpus, in source order. Empty for non-ALTER
    /// actions. Rules predicate via
    /// `ddl.table.actions: { exists: { kind: <variant> } }` — the
    /// substrate exposes which AST variants matched, not which
    /// rule's verdict fired. Narrower than [`TableAlterFlags`] today;
    /// new rules extend by adding variants here.
    pub(crate) actions: Vec<IrTableAlterAction>,
    /// `CREATE TABLE … {SHALLOW | DEEP} CLONE <source>` shape; `None`
    /// for non-clone CREATE and all other actions. Drives the
    /// DBX-TBL-CLONE-SHALLOW predicate via
    /// `ddl.table.clone.kind: shallow`.
    pub(crate) clone: Option<IrCloneShape>,
    /// Redshift `CREATE TABLE` physical-layout attributes
    /// (DISTSTYLE / DISTKEY / SORTKEY / BACKUP). Empty bag for
    /// non-CREATE actions.
    pub physical: TablePhysicalAttrs,
    /// Snowflake `CREATE { ICEBERG | HYBRID | EVENT } TABLE` variant;
    /// `None` for ordinary tables and all non-CREATE actions.
    pub(crate) kind: Option<IrCreateTableKind>,
    /// `DATA_RETENTION_TIME_IN_DAYS = <n>` resolved from the CREATE
    /// TABLE option clause or an `ALTER TABLE … SET` parameter clause.
    /// `None` when the parameter is absent or its value is not a plain
    /// integer. `Some(0)` means Time Travel is disabled for the table.
    /// Whether a value is dangerous is YAML policy, not recognition.
    pub data_retention_days: Option<i64>,
    /// `RENAME TABLE` pairs, in statement order. Empty for every other
    /// table action.
    pub renames: Vec<TableRenamePairIr>,
    pub node_id: NodeId,
    pub span: Span,
}

/// IR-internal closed enum of `ALTER TABLE` action variants exposed to
/// the rule corpus. Mirrors a narrow slice of
/// [`crate::ast::AstAlterTableActionKind`] — only variants that have a
/// rule today (or a plausibly-near-future one). Public-facts mirror:
/// `src/facts/ddl.rs::TableAlterAction`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum IrTableAlterAction {
    /// `ALTER TABLE … SET TBLPROPERTIES (…)`.
    SetTblProperties,
    /// `ALTER TABLE … UNSET TBLPROPERTIES (…)`.
    UnsetTblProperties,
    /// `ALTER TABLE … CLUSTER BY …` — including `CLUSTER BY NONE`.
    /// The `disabled` attribute names the SQL form (true ↔ NONE).
    ClusterBy { disabled: bool },
    /// `ALTER TABLE … SET JOIN POLICY <name> [FORCE]` — attaches (or
    /// replaces) a join policy on the table.
    SetJoinPolicy,
    /// `ALTER TABLE … SET AGGREGATION POLICY <name> [FORCE]` — attaches (or
    /// replaces) an aggregation (privacy) policy on the table.
    SetAggregationPolicy,
    /// `ALTER TABLE … ADD DATA METRIC FUNCTION <name> ON (<cols>)` —
    /// attaches a data-quality metric function to the table.
    AddDataMetricFunction,
    /// `ALTER TABLE … DROP DATA METRIC FUNCTION <name> ON (<cols>)` —
    /// detaches a data-quality metric function from the table.
    DropDataMetricFunction,
    /// PG `ALTER TABLE … [ENABLE|DISABLE|FORCE|NO FORCE] ROW LEVEL SECURITY`.
    RowLevelSecurity { mode: IrRowLevelSecurityMode },
}

/// IR-internal mirror of [`crate::ast::AstRowLevelSecurityMode`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum IrRowLevelSecurityMode {
    Enable,
    Disable,
    Force,
    NoForce,
}

/// IR-internal mirror of [`crate::ast::CloneKind`] plus a `Standard`
/// arm for the Snowflake `CREATE TABLE x CLONE source` shape (no
/// `DEEP` / `SHALLOW` modifier). Public-facts mirror:
/// `src/facts/ddl.rs::CloneShape`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum IrCloneShape {
    Shallow,
    Deep,
    /// Snowflake / cross-dialect `CREATE TABLE x CLONE source` — no
    /// SHALLOW / DEEP prefix. Snowflake clones are zero-copy and
    /// share storage until modified. Drives INFO-TBL-CLONE.
    Standard,
}

/// IR-internal mirror of [`crate::ast::AstTableKind`] — the Snowflake
/// `CREATE { ICEBERG | HYBRID | EVENT } TABLE` variant. Public-facts
/// mirror: `src/facts/ddl.rs::CreateTableKind`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum IrCreateTableKind {
    Iceberg,
    Hybrid,
    Event,
}

/// IR-internal mirror of [`crate::ast::AstDistStyle`] (Redshift
/// `DISTSTYLE`). Public-facts mirror: `src/facts/ddl.rs::DistStyle`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum IrDistStyle {
    Even,
    Key,
    All,
    Auto,
}

/// IR-internal mirror of [`crate::ast::AstSortKeySpec`] (Redshift
/// `SORTKEY` strategy). Public-facts mirror: `src/facts/ddl.rs::SortKeySpec`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum IrSortKeySpec {
    Compound,
    Interleaved,
}

/// IR-internal mirror of [`crate::ast::AstBackupMode`] (Redshift
/// `BACKUP { YES | NO }`). Public-facts mirror: `src/facts/ddl.rs::BackupMode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum IrBackupMode {
    Yes,
    No,
}

/// Redshift `CREATE TABLE` physical-layout attributes, projected to the
/// public `ddl.table.*` facts that the RS-* rule corpus composes. All
/// fields default to "absent" so non-CREATE table plans carry an empty
/// bag.
#[derive(Debug, Clone, Default)]
pub struct TablePhysicalAttrs {
    pub(crate) dist_style: Option<IrDistStyle>,
    pub(crate) dist_key_present: bool,
    pub(crate) sort_key: Option<IrSortKeySpec>,
    pub(crate) backup: Option<IrBackupMode>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TableAction {
    /// `CREATE TABLE`
    Create,
    /// `ALTER TABLE`
    Alter,
    /// `DROP TABLE` — projected from the generic `AstStmt::Drop` when
    /// `object_type_span` resolves to `TABLE`.
    Drop,
    /// `TRUNCATE TABLE`
    Truncate,
    /// MySQL `RENAME TABLE a TO b [, c TO d]` — every pair is carried
    /// in [`TablePlan::renames`]; the plan target is the first pair's
    /// source.
    Rename,
    /// Top-level `DROP ALL ROW ACCESS POLICIES <table>`. Distinct from
    /// the equivalent `ALTER TABLE` action (which surfaces as
    /// `Alter` + `alter_flags.row_access_policy_removed`).
    DropAllRowAccessPolicies,
}

/// One `RENAME TABLE <from> TO <to>` pair. Public-facts mirror:
/// `src/facts/ddl.rs::TableRenamePair`.
#[derive(Debug, Clone)]
pub struct TableRenamePairIr {
    pub from: TableTarget,
    pub to: TableTarget,
}

#[derive(Debug, Clone)]
pub struct TableTarget {
    pub name: String,
    pub schema: Option<String>,
    pub db: Option<String>,
    pub span: Span,
}

#[derive(Debug, Clone, Default)]
pub struct TableOptions {
    pub or_replace: bool,
    pub temporary: bool,
    /// Snowflake `CREATE PROCEDURE SCOPED { TEMP | TEMPORARY } TABLE …` — a
    /// table scoped to a single stored-procedure execution (also `temporary`).
    pub scoped: bool,
    pub if_not_exists: bool,
    pub if_exists: bool,
    pub cascade: bool,
    pub restrict: bool,
}

/// Per-category typed flags collected from
/// [`AstAlterTableActionKind`]. Each flag is set when the action list
/// contains at least one matching variant. The flags are projected
/// 1:1 onto the public `TableFacts` typed slot.
#[derive(Debug, Clone, Default)]
pub struct TableAlterFlags {
    pub column_added: bool,
    pub column_dropped: bool,
    pub renamed: bool,
    pub row_access_policy_added: bool,
    pub row_access_policy_removed: bool,
    pub masking_policy_added: bool,
    pub masking_policy_removed: bool,
    pub aggregation_policy_removed: bool,
    pub tag_set: bool,
    pub tag_unset: bool,
}

/// Resolve the integer assigned to `DATA_RETENTION_TIME_IN_DAYS` inside
/// `span` — a CREATE-time option (`DATA_RETENTION_TIME_IN_DAYS = 0`) or a
/// `SET`/`SET PROPERTIES` clause that may carry several comma-separated
/// parameters. `None` when the parameter is absent or its value is not a
/// plain non-negative integer. Matches the parameter name on a word
/// boundary so `MIN_DATA_RETENTION_TIME_IN_DAYS` does not alias it.
/// Shared by the table, schema, and database plans (the single retention
/// value resolver) — see [`super::schema_plan`] and
/// [`super::database_plan`].
pub(crate) fn resolve_data_retention_days(source: &str, span: Span) -> Option<i64> {
    const KEY: &str = "DATA_RETENTION_TIME_IN_DAYS";
    let text = source.get(span.start as usize..span.end as usize)?;
    let upper = text.to_ascii_uppercase();
    let bytes = upper.as_bytes();
    let mut from = 0usize;
    while let Some(rel) = upper.get(from..).and_then(|s| s.find(KEY)) {
        let pos = from + rel;
        let boundary = pos == 0 || {
            let prev = bytes[pos - 1];
            !prev.is_ascii_alphanumeric() && prev != b'_'
        };
        if boundary {
            if let Some(after) = text.get(pos + KEY.len()..) {
                if let Some(eq) = after.find('=') {
                    let rest = after.get(eq + 1..).map(str::trim_start).unwrap_or("");
                    let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
                    if let Ok(n) = digits.parse::<i64>() {
                        return Some(n);
                    }
                }
            }
        }
        from = pos + KEY.len();
    }
    None
}

/// Lower a typed [`AstCreateTable`] into a [`TablePlan`].
pub fn lower_create_table_to_table_plan(s: &AstCreateTable, source: &str) -> TablePlan {
    let clone = match (s.clone_kind, s.clone_source_span) {
        (Some(ck), _) => Some(match ck {
            crate::ast::CloneKind::Shallow => IrCloneShape::Shallow,
            crate::ast::CloneKind::Deep => IrCloneShape::Deep,
        }),
        // Snowflake / cross-dialect `CREATE TABLE x CLONE source` —
        // no SHALLOW / DEEP modifier.
        (None, Some(_)) => Some(IrCloneShape::Standard),
        (None, None) => None,
    };
    let physical = TablePhysicalAttrs {
        dist_style: s.dist_style.map(|d| match d {
            crate::ast::AstDistStyle::Even => IrDistStyle::Even,
            crate::ast::AstDistStyle::Key => IrDistStyle::Key,
            crate::ast::AstDistStyle::All => IrDistStyle::All,
            crate::ast::AstDistStyle::Auto => IrDistStyle::Auto,
        }),
        dist_key_present: s.dist_key_present,
        sort_key: s.sort_key.map(|k| match k {
            crate::ast::AstSortKeySpec::Compound => IrSortKeySpec::Compound,
            crate::ast::AstSortKeySpec::Interleaved => IrSortKeySpec::Interleaved,
        }),
        backup: s.backup.map(|b| match b {
            crate::ast::AstBackupMode::Yes => IrBackupMode::Yes,
            crate::ast::AstBackupMode::No => IrBackupMode::No,
        }),
    };
    TablePlan {
        action: TableAction::Create,
        target: Some(target_from_span(source, s.name_span)),
        options: TableOptions {
            or_replace: s.or_replace_span.is_some(),
            temporary: s.temp_kind_span.is_some(),
            scoped: s.scoped_span.is_some(),
            if_not_exists: false,
            if_exists: false,
            cascade: false,
            restrict: false,
        },
        alter_flags: TableAlterFlags::default(),
        actions: Vec::new(),
        clone,
        physical,
        kind: s.table_kind.map(|k| match k {
            crate::ast::AstTableKind::Iceberg => IrCreateTableKind::Iceberg,
            crate::ast::AstTableKind::Hybrid => IrCreateTableKind::Hybrid,
            crate::ast::AstTableKind::Event => IrCreateTableKind::Event,
        }),
        data_retention_days: s
            .data_retention_time_in_days_span
            .and_then(|sp| resolve_data_retention_days(source, sp)),
        renames: Vec::new(),
        node_id: s.node_id,
        span: s.span,
    }
}

/// Lower a typed [`AstAlterTable`] into a [`TablePlan`].
///
/// Walks every `action.kind` and sets the matching typed flags via an
/// exhaustive closed-enum classification (no `_ =>` arm).
pub fn lower_alter_table_to_table_plan(s: &AstAlterTable, source: &str) -> TablePlan {
    let mut flags = TableAlterFlags::default();
    let mut actions = Vec::new();
    for action in &s.actions {
        classify_alter_action(&action.kind, &mut flags, &mut actions);
    }
    // `ALTER TABLE … SET DATA_RETENTION_TIME_IN_DAYS = <n>` sets the
    // value. A multi-parameter `SET a = …, b = …` splits its
    // comma-separated parameters across successive actions (only the
    // first rides the `Set` variant; the rest fall through to generic
    // action spans), so resolve from each action's own span rather than
    // a single carrier — position-independent, and precise because only
    // a retention parameter's text contains the key.
    let data_retention_days = s
        .actions
        .iter()
        .find_map(|action| resolve_data_retention_days(source, action.span));

    TablePlan {
        action: TableAction::Alter,
        target: Some(target_from_span(source, s.name_span)),
        options: TableOptions {
            or_replace: false,
            temporary: false,
            scoped: false,
            if_not_exists: false,
            if_exists: s.if_exists_span.is_some(),
            cascade: false,
            restrict: false,
        },
        alter_flags: flags,
        actions,
        clone: None,
        physical: TablePhysicalAttrs::default(),
        kind: None,
        data_retention_days,
        renames: Vec::new(),
        node_id: s.node_id,
        span: s.span,
    }
}

/// Lower a generic `AstStmt::Drop` into a [`TablePlan`] when the
/// `object_type_span` resolves to `TABLE` (case-insensitive,
/// whitespace-tolerant).
///
/// Returns `None` for any other object type — DROP for non-table
/// targets is handled by other lowerings (`lower_drop_stage_to_stage_plan`,
/// `lower_drop_dynamic_table_to_dynamic_table_plan`, etc.).
pub fn lower_drop_table_to_table_plan(s: &AstDrop, source: &str) -> Option<TablePlan> {
    let object_type_span = s.object_type_span?;
    let text = source.get(object_type_span.start as usize..object_type_span.end as usize)?;
    if normalize_object_type(text) != "TABLE" {
        return None;
    }
    let target = s.target_name_span.map(|sp| target_from_span(source, sp));
    let cascade =
        matches!(s.cascade_restrict_span, Some(span) if matches_keyword(source, span, "CASCADE"));
    let restrict =
        matches!(s.cascade_restrict_span, Some(span) if matches_keyword(source, span, "RESTRICT"));
    Some(TablePlan {
        action: TableAction::Drop,
        target,
        options: TableOptions {
            or_replace: false,
            temporary: false,
            scoped: false,
            if_not_exists: false,
            if_exists: s.if_exists_span.is_some(),
            cascade,
            restrict,
        },
        alter_flags: TableAlterFlags::default(),
        actions: Vec::new(),
        clone: None,
        physical: TablePhysicalAttrs::default(),
        kind: None,
        data_retention_days: None,
        renames: Vec::new(),
        node_id: s.node_id,
        span: s.span,
    })
}

/// Lower a typed [`AstTruncate`] into a [`TablePlan`]. Always
/// produces `TableAction::Truncate`.
pub fn lower_truncate_to_table_plan(s: &AstTruncate, source: &str) -> TablePlan {
    let target = s.target_table_span.map(|sp| target_from_span(source, sp));
    TablePlan {
        action: TableAction::Truncate,
        target,
        options: TableOptions {
            or_replace: false,
            temporary: false,
            scoped: false,
            if_not_exists: false,
            if_exists: s.if_exists_span.is_some(),
            cascade: false,
            restrict: false,
        },
        alter_flags: TableAlterFlags::default(),
        actions: Vec::new(),
        clone: None,
        physical: TablePhysicalAttrs::default(),
        kind: None,
        data_retention_days: None,
        renames: Vec::new(),
        node_id: s.node_id,
        span: s.span,
    }
}

/// Lower a typed [`AstDropAllRowAccessPolicies`] into a [`TablePlan`].
/// Always produces `TableAction::DropAllRowAccessPolicies`.
pub fn lower_drop_all_row_access_policies_to_table_plan(
    s: &AstDropAllRowAccessPolicies,
    source: &str,
) -> TablePlan {
    TablePlan {
        action: TableAction::DropAllRowAccessPolicies,
        target: Some(target_from_span(source, s.table_name_span)),
        options: TableOptions::default(),
        alter_flags: TableAlterFlags::default(),
        actions: Vec::new(),
        clone: None,
        physical: TablePhysicalAttrs::default(),
        kind: None,
        data_retention_days: None,
        renames: Vec::new(),
        node_id: s.node_id,
        span: s.span,
    }
}

/// Lower MySQL `RENAME TABLE a TO b [, c TO d]` into a [`TablePlan`].
/// The plan target is the first pair's source; every pair is carried in
/// `renames` so multi-pair statements keep each rename attributed to its
/// own source table.
pub fn lower_mysql_rename_table_to_table_plan(s: &AstMysqlRenameTable, source: &str) -> TablePlan {
    let renames: Vec<TableRenamePairIr> = s
        .pairs
        .iter()
        .map(|p| TableRenamePairIr {
            from: target_from_span(source, p.from_name_span),
            to: target_from_span(source, p.to_name_span),
        })
        .collect();
    TablePlan {
        action: TableAction::Rename,
        target: s
            .pairs
            .first()
            .map(|p| target_from_span(source, p.from_name_span)),
        options: TableOptions::default(),
        alter_flags: TableAlterFlags {
            renamed: true,
            ..TableAlterFlags::default()
        },
        actions: Vec::new(),
        clone: None,
        physical: TablePhysicalAttrs::default(),
        kind: None,
        data_retention_days: None,
        renames,
        node_id: s.node_id,
        span: s.span,
    }
}

/// Closed-enum classification of one `AstAlterTableActionKind` into
/// per-category flags. Every variant is matched explicitly — no
/// `_ =>` arm — so introducing a new `AstAlterTableActionKind` variant
/// produces a compile-time gap rather than a silent miss.
fn classify_alter_action(
    kind: &AstAlterTableActionKind,
    flags: &mut TableAlterFlags,
    actions: &mut Vec<IrTableAlterAction>,
) {
    use AstAlterTableActionKind as K;
    match kind {
        // ───────────── Column shape ─────────────
        K::AddColumn { .. } => flags.column_added = true,
        K::DropColumn { .. } => flags.column_dropped = true,
        K::RenameTo { .. } => flags.renamed = true,

        // ───────────── Row Access Policy ─────────────
        // Snowflake `ADD ROW ACCESS POLICY` and Databricks `SET ROW
        // FILTER` both attach a row-access mechanism, so both flip
        // `row_access_policy_added`.
        K::AddRowAccessPolicy(_) | K::SetRowFilter { .. } => flags.row_access_policy_added = true,
        // Snowflake `DROP ROW ACCESS POLICY`, the inline ALTER TABLE
        // form of `DROP ALL ROW ACCESS POLICIES`, and Databricks
        // `DROP ROW FILTER` all detach a row-access mechanism.
        K::DropRowAccessPolicy { .. }
        | K::DropAllRowAccessPolicies { .. }
        | K::DropRowFilter { .. } => flags.row_access_policy_removed = true,

        // ───────────── Column-level Masking / Projection ─────────────
        // Both masking-policy and projection-policy attachments share
        // one flag; Databricks `SET MASK` joins the same intent.
        K::SetColumnMaskingPolicy(_)
        | K::SetColumnMask { .. }
        | K::SetColumnProjectionPolicy(_) => flags.masking_policy_added = true,
        K::UnsetColumnMaskingPolicy { .. }
        | K::DropColumnMask { .. }
        | K::UnsetColumnProjectionPolicy { .. } => flags.masking_policy_removed = true,

        // ───────────── Table-level Aggregation / Join Policy ─────────────
        // `UNSET AGGREGATION POLICY` and `UNSET JOIN POLICY` share
        // one flag: the YAML rule TBL-AGGPOL-RMV unions both
        // surfaces.
        K::UnsetAggregationPolicy { .. } | K::UnsetJoinPolicy { .. } => {
            flags.aggregation_policy_removed = true
        }

        // ───────────── Tags ─────────────
        K::SetTag { .. } | K::SetColumnTag { .. } => flags.tag_set = true,
        K::UnsetTag { .. } | K::UnsetColumnTag { .. } => flags.tag_unset = true,

        // ───────────── Databricks: TBLPROPERTIES + liquid clustering ─────────────
        // Surfaced as typed action variants so DBX-TBL-* rules compose
        // against `actions: { exists: { kind: <variant> } }` rather
        // than per-rule verdict flags.
        K::SetTblProperties { .. } => actions.push(IrTableAlterAction::SetTblProperties),
        K::UnsetTblProperties { .. } => actions.push(IrTableAlterAction::UnsetTblProperties),
        K::ClusterBy { is_none, .. } => {
            actions.push(IrTableAlterAction::ClusterBy { disabled: *is_none })
        }
        K::SetJoinPolicy { .. } => actions.push(IrTableAlterAction::SetJoinPolicy),
        K::SetAggregationPolicy { .. } => actions.push(IrTableAlterAction::SetAggregationPolicy),
        K::AddDataMetricFunction { .. } => actions.push(IrTableAlterAction::AddDataMetricFunction),
        K::DropDataMetricFunction { .. } => {
            actions.push(IrTableAlterAction::DropDataMetricFunction)
        }
        K::RowLevelSecurity { mode, .. } => {
            use crate::ast::AstRowLevelSecurityMode as M;
            let ir_mode = match mode {
                M::Enable => IrRowLevelSecurityMode::Enable,
                M::Disable => IrRowLevelSecurityMode::Disable,
                M::Force => IrRowLevelSecurityMode::Force,
                M::NoForce => IrRowLevelSecurityMode::NoForce,
            };
            actions.push(IrTableAlterAction::RowLevelSecurity { mode: ir_mode })
        }

        // ───────────── Actions that do not map to any TBL-* rule ─────────────
        K::RenameColumn { .. }
        | K::SwapWith { .. }
        | K::AlterColumn { .. }
        | K::AddConstraint { .. }
        | K::DropConstraint { .. }
        | K::DropClusteringKey { .. }
        | K::SuspendRecluster { .. }
        | K::ResumeRecluster { .. }
        | K::Set { .. }
        | K::Unset { .. }
        | K::AddSearchOptimization { .. }
        | K::DropSearchOptimization { .. }
        | K::SetDataMetricSchedule { .. }
        | K::UnsetDataMetricSchedule { .. }
        | K::AddStorageLifecyclePolicy { .. }
        | K::DropStorageLifecyclePolicy { .. }
        | K::SetOptions { .. }
        | K::SetDefaultCollate { .. }
        | K::DropPrimaryKey { .. }
        | K::AlterColumnSetOptions { .. }
        | K::AlterColumnDropNotNull { .. }
        | K::AlterColumnSetDataType { .. }
        | K::AlterColumnSetDefault { .. }
        | K::AlterColumnDropDefault { .. }
        | K::GovernanceSpan { .. }
        | K::Unknown { .. } => {}
    }
}

pub(crate) fn target_from_span(source: &str, span: Span) -> TableTarget {
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
    TableTarget {
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
