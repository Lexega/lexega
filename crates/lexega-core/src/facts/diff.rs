// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Diff facts — the public surface a semantic diff of two versions of
//! a script is reported on.
//!
//! Two-tier shape:
//!
//! 1. [`DiffEvent`] — taxonomy of structural changes between baseline
//!    and head. Rules predicate against `diff.events:` and a `kind:`
//!    discriminator; this is the primary contract.
//! 2. [`DiffContext`] — per-side snapshot of each statement: read-set,
//!    predicates, joins, aggregates, output-column state, clause presence.
//!    Use `diff.context.baseline.*` / `diff.context.head.*` when an
//!    event kind alone is too coarse.
//!
//! Each [`DiffEvent`] is self-contained: it carries enough payload to
//! identify what changed without consulting [`DiffContext`].
//! [`DiffContext`] reports per-side snapshots (`baseline` and `head`),
//! not deltas. The four output-column semantic-delta variants
//! (`NullabilityChanged`, `LineageChanged`, `TaintChanged`,
//! `ConstraintChanged`) emit one event per affected column.

use serde::{Deserialize, Serialize};

#[cfg(feature = "schema")]
use schemars::JsonSchema;

use crate::lexer::token::Span;

use super::catalog::CatalogTag;
use super::ddl::DdlAction;
use super::expr::{FuncCallExpr, WindowFunctionName};
use super::identity::{ColumnRef, IdentName, ObjectRef, PrincipalRef, TableRef};
use super::literal::{DataType, LiteralValue};
use super::policy::PolicyBodySemantics;
use super::privilege::Privilege;
use super::query::{
    AggregateEvent, AggregateFunction, JoinEvent, JoinKind, MergeBranchKind, PredicateEvent,
    SetOpKind, WindowEvent,
};
use super::statement::StatementKind;

// ─────────────────────────────────────────────────────────────────────
// Top-level facts carrier
// ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct DiffFacts {
    /// Discrete structural changes between baseline and head.
    pub events: Vec<DiffEvent>,
    /// Per-side snapshot of each statement for rules that need to drill
    /// into baseline or head state beyond the event kind.
    pub context: DiffContext,
    pub baseline_kind: Option<StatementKind>,
    pub head_kind: Option<StatementKind>,
}

// ─────────────────────────────────────────────────────────────────────
// DiffEvent — curated taxonomy
// ─────────────────────────────────────────────────────────────────────

/// One structural change between the baseline and head statements.
/// Variant names follow the pattern `<Subject><Direction|Action>` —
/// e.g. `WhereAdded`, `JoinTypeChanged`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(tag = "kind", rename_all = "snake_case")]
#[cfg_attr(feature = "schema", schemars(rename = "Change"))]
pub enum DiffEvent {
    // ───────────── Statement-level ─────────────
    StatementKindChanged {
        baseline: StatementKind,
        head: StatementKind,
    },
    StatementAdded {
        statement_kind: StatementKind,
        head_index: usize,
    },
    StatementRemoved {
        statement_kind: StatementKind,
        baseline_index: usize,
    },

    // ───────────── Read-set ─────────────
    TableAdded {
        table: TableRef,
    },
    TableRemoved {
        table: TableRef,
    },
    CrossSchemaIntroduced {
        schemas: Vec<IdentName>,
    },

    // ───────────── Table functions ─────────────
    /// A table-valued function the head reads from that the baseline
    /// does not. Calls of one function pair in the order they are
    /// written.
    TableFunctionAdded {
        call: FuncCallExpr,
    },
    /// A table-valued function the baseline reads from that the head
    /// does not.
    TableFunctionRemoved {
        call: FuncCallExpr,
    },
    /// A table-valued function both sides read from, called with
    /// changed arguments. `node_deltas` locates each change in the call
    /// (`func_call_arg` paths); it is empty where only an argument
    /// written in a grammar no expression has changed (BigQuery's `MODEL
    /// d.m`).
    TableFunctionArgumentChanged {
        function: IdentName,
        node_deltas: Vec<ExpressionDelta>,
    },

    // ───────────── WHERE clause ─────────────
    WhereAdded {
        table: TableRef,
        added_columns: Vec<ColumnRef>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        within: Option<QueryBlock>,
    },
    WhereRemoved {
        table: TableRef,
        removed_columns: Vec<ColumnRef>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        within: Option<QueryBlock>,
    },
    WhereConditionChanged {
        table: TableRef,
        column: ColumnRef,
        baseline_op: Option<super::expr::BinaryOp>,
        head_op: Option<super::expr::BinaryOp>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        within: Option<QueryBlock>,
    },
    /// Write-statement boundedness flipped (UPDATE/DELETE gained or
    /// lost a WHERE clause).
    WriteBoundednessChanged {
        direction: WriteBoundedness,
        tables: Vec<TableRef>,
    },

    // ───────────── JOIN ─────────────
    JoinAdded {
        left: TableRef,
        right: TableRef,
        join_kind: JoinKind,
        /// Where the head writes it; absent for what only the baseline has.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        source_span: Option<Span>,
    },
    JoinRemoved {
        left: TableRef,
        right: TableRef,
        join_kind: JoinKind,
    },
    JoinTypeChanged {
        left: TableRef,
        right: TableRef,
        baseline_kind: JoinKind,
        head_kind: JoinKind,
        /// Where the head writes it; absent for what only the baseline has.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        source_span: Option<Span>,
    },
    JoinConditionChanged {
        left: TableRef,
        right: TableRef,
        /// Where the head writes it; absent for what only the baseline has.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        source_span: Option<Span>,
    },

    // ───────────── Projection ─────────────
    /// A column the head's result has that the baseline's has under no
    /// name and with no equal value. `table` is the relation the
    /// statement makes, empty for a query.
    ColumnProjected {
        table: TableRef,
        column: ColumnRef,
    },
    /// A column the baseline's result has that the head's has under no
    /// name and with no equal value.
    ColumnUnprojected {
        table: TableRef,
        column: ColumnRef,
    },
    /// A result column the head gives another name, its value unchanged.
    ColumnRenamed {
        table: TableRef,
        baseline: ColumnRef,
        head: ColumnRef,
    },
    StarProjectionAdded {
        table: Option<TableRef>,
    },
    StarProjectionRemoved {
        table: Option<TableRef>,
    },
    /// A result column both sides have by name whose value is computed
    /// differently (e.g. `SELECT 1 → SELECT 2`, `SELECT a → SELECT a + 1`,
    /// `SELECT UPPER(x) → SELECT LOWER(x)`), however deep in the
    /// statement the change is. Reading the same computation from another
    /// source is `lineage_changed`. `output` is the head's column.
    ProjectionItemChanged {
        output: Option<ColumnRef>,
        baseline_kind: ProjectionItemKindTag,
        head_kind: ProjectionItemKindTag,
        /// The `MERGE` branch writing the value, where a branch does.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        within: Option<QueryBlock>,
    },

    // ───────────── Clause presence — split per (clause × direction) ─────────────
    DistinctAdded {
        scope: SelectScope,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        within: Option<QueryBlock>,
    },
    DistinctRemoved {
        scope: SelectScope,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        within: Option<QueryBlock>,
    },
    QualifyAdded {
        window_functions: Vec<WindowFunctionName>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        within: Option<QueryBlock>,
    },
    QualifyRemoved {
        window_functions: Vec<WindowFunctionName>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        within: Option<QueryBlock>,
    },
    QualifyChanged {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        within: Option<QueryBlock>,
    },
    CteAdded {
        name: IdentName,
    },
    CteRemoved {
        name: IdentName,
    },
    SampleAdded {
        tables: Vec<TableRef>,
    },
    SampleRemoved {
        tables: Vec<TableRef>,
    },
    HavingAdded {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        within: Option<QueryBlock>,
    },
    HavingRemoved {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        within: Option<QueryBlock>,
    },
    HavingChanged {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        within: Option<QueryBlock>,
    },
    GroupByAdded {
        columns: Vec<ColumnRef>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        within: Option<QueryBlock>,
    },
    GroupByRemoved {
        columns: Vec<ColumnRef>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        within: Option<QueryBlock>,
    },
    OrderByAdded {
        columns: Vec<ColumnRef>,
    },
    OrderByRemoved {
        columns: Vec<ColumnRef>,
    },
    OrderByDirectionChanged {
        column: ColumnRef,
    },

    // ───────────── Set operations ─────────────
    SetOperationAdded {
        operation: SetOpKind,
    },
    SetOperationRemoved {
        operation: SetOpKind,
    },
    SetOperationChanged {
        baseline: SetOpKind,
        head: SetOpKind,
    },

    // ───────────── Aggregate ─────────────
    AggregateAdded {
        function: AggregateFunction,
        on: Option<ColumnRef>,
    },
    AggregateRemoved {
        function: AggregateFunction,
        on: Option<ColumnRef>,
    },
    AggregateFunctionChanged {
        baseline: AggregateFunction,
        head: AggregateFunction,
        on: Option<ColumnRef>,
    },
    AggregateDistinctChanged {
        function: AggregateFunction,
        direction: DistinctChange,
        on: Option<ColumnRef>,
    },
    /// Aggregate input expression changed. `argument_containment`
    /// is the structural relationship between baseline and head
    /// argument trees; `node_deltas` lists per-node deltas at typed
    /// paths inside the argument expression (empty when containment
    /// is `equivalent` or `opaque`).
    AggregateArgumentChanged {
        function: AggregateFunction,
        on: Option<ColumnRef>,
        argument_containment: ExpressionContainment,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        node_deltas: Vec<ExpressionDelta>,
    },

    // ───────────── Window ─────────────
    WindowFunctionAdded {
        function: WindowFunctionName,
        /// Where the head writes it; absent for what only the baseline has.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        source_span: Option<Span>,
    },
    WindowFunctionRemoved {
        function: WindowFunctionName,
    },
    WindowPartitionChanged {
        function: WindowFunctionName,
        baseline_partition: Vec<ColumnRef>,
        head_partition: Vec<ColumnRef>,
        /// Where the head writes it; absent for what only the baseline has.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        source_span: Option<Span>,
    },
    WindowPartitionRemoved {
        function: WindowFunctionName,
        removed_partition: Vec<ColumnRef>,
        /// Where the head writes it; absent for what only the baseline has.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        source_span: Option<Span>,
    },
    WindowFrameChanged {
        function: WindowFunctionName,
        /// Where the head writes it; absent for what only the baseline has.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        source_span: Option<Span>,
    },

    // ───────────── Subquery ─────────────
    SubqueryPredicateChanged {
        scope: SubqueryShape,
        primary_table: Option<TableRef>,
    },
    SubqueryScopeChanged {
        baseline: SubqueryShape,
        head: SubqueryShape,
        primary_table: Option<TableRef>,
    },

    // ───────────── LIMIT ─────────────
    LimitAdded {
        limit: Option<LiteralValue>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        within: Option<QueryBlock>,
    },
    LimitRemoved {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        within: Option<QueryBlock>,
    },
    /// LIMIT value changed (both sides have a LIMIT, magnitude moved).
    LimitValueChanged {
        baseline: Option<LiteralValue>,
        head: Option<LiteralValue>,
        direction: LimitDirection,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        within: Option<QueryBlock>,
    },

    // ───────────── DDL ─────────────
    DdlActionChanged {
        target: ObjectRef,
        baseline: DdlAction,
        head: DdlAction,
    },
    TableDdlAdded {
        target: ObjectRef,
        action: DdlAction,
    },
    TableDdlRemoved {
        target: ObjectRef,
        action: DdlAction,
    },
    DdlColumnAdded {
        table: TableRef,
        column: ColumnRef,
        data_type: DataType,
    },
    DdlColumnRemoved {
        table: TableRef,
        column: ColumnRef,
    },

    // ───────────── Privilege ─────────────
    PrivilegeGranted {
        privilege: Privilege,
        target: ObjectRef,
        grantee: PrincipalRef,
    },
    PrivilegeRevoked {
        privilege: Privilege,
        target: ObjectRef,
        grantee: PrincipalRef,
    },

    // ───────────── Policy ─────────────
    PolicyAttached {
        policy: ObjectRef,
        target: ObjectRef,
        columns: Vec<IdentName>,
    },
    PolicyDetached {
        policy: ObjectRef,
        target: ObjectRef,
        columns: Vec<IdentName>,
    },
    PolicyBodyChanged {
        policy: ObjectRef,
        baseline: PolicyBodySemantics,
        head: PolicyBodySemantics,
    },

    // ───────────── Catalog tags ─────────────
    CatalogTagAdded {
        target: ObjectRef,
        tag: CatalogTag,
    },
    CatalogTagRemoved {
        target: ObjectRef,
        tag: CatalogTag,
    },

    // ───────────── Output-column semantic deltas ─────────────
    /// An output column whose nullability differs between the sides: each
    /// side's `nullable` as its output column states it, absent where the
    /// side does not show whether the column may be NULL.
    NullabilityChanged {
        output: ColumnRef,
        baseline_nullable: Option<bool>,
        head_nullable: Option<bool>,
    },
    LineageChanged {
        output: ColumnRef,
        added_sources: Vec<ColumnRef>,
        removed_sources: Vec<ColumnRef>,
    },
    TaintChanged {
        output: ColumnRef,
        added_tags: Vec<CatalogTag>,
        removed_tags: Vec<CatalogTag>,
    },
    ConstraintChanged {
        target: ColumnRef,
        baseline: ConstraintFactSet,
        head: ConstraintFactSet,
    },

    // ───────────── Model configuration ─────────────
    /// A configuration value of the model a file defines (a dbt model's
    /// `materialized`, `incremental_strategy`, `unique_key`, …) that
    /// differs between the sides; absent on the side that does not set it.
    ModelConfigChanged {
        key: String,
        baseline: Option<String>,
        head: Option<String>,
    },

    /// The object a write, a load or a `CREATE … AS` writes or defines is
    /// another one.
    WriteTargetChanged {
        baseline: TableRef,
        head: TableRef,
        /// What the head's target is: a table, a view, a materialized view
        /// or a dynamic table.
        object: super::identity::ObjectKind,
        /// `object` as a reader names it: "table", "view", "materialized
        /// view", "dynamic table".
        object_noun: String,
    },

    // ───────────── Opaque ─────────────
    Opaque {
        reason: OpaqueDiffReason,
        baseline_span: Option<Span>,
        head_span: Option<Span>,
    },
}

impl DiffEvent {
    /// The nested query block a clause change is in; `None` for a change
    /// to the statement's outermost block and for any other change.
    pub fn within(&self) -> Option<&QueryBlock> {
        match self {
            DiffEvent::WhereAdded { within, .. }
            | DiffEvent::WhereRemoved { within, .. }
            | DiffEvent::WhereConditionChanged { within, .. }
            | DiffEvent::DistinctAdded { within, .. }
            | DiffEvent::DistinctRemoved { within, .. }
            | DiffEvent::QualifyAdded { within, .. }
            | DiffEvent::QualifyRemoved { within, .. }
            | DiffEvent::QualifyChanged { within }
            | DiffEvent::HavingAdded { within }
            | DiffEvent::HavingRemoved { within }
            | DiffEvent::HavingChanged { within }
            | DiffEvent::GroupByAdded { within, .. }
            | DiffEvent::GroupByRemoved { within, .. }
            | DiffEvent::LimitAdded { within, .. }
            | DiffEvent::LimitRemoved { within }
            | DiffEvent::LimitValueChanged { within, .. }
            | DiffEvent::ProjectionItemChanged { within, .. } => within.as_ref(),
            DiffEvent::StatementKindChanged { .. }
            | DiffEvent::StatementAdded { .. }
            | DiffEvent::StatementRemoved { .. }
            | DiffEvent::TableAdded { .. }
            | DiffEvent::TableRemoved { .. }
            | DiffEvent::CrossSchemaIntroduced { .. }
            | DiffEvent::TableFunctionAdded { .. }
            | DiffEvent::TableFunctionRemoved { .. }
            | DiffEvent::TableFunctionArgumentChanged { .. }
            | DiffEvent::WriteBoundednessChanged { .. }
            | DiffEvent::JoinAdded { .. }
            | DiffEvent::JoinRemoved { .. }
            | DiffEvent::JoinTypeChanged { .. }
            | DiffEvent::JoinConditionChanged { .. }
            | DiffEvent::ColumnProjected { .. }
            | DiffEvent::ColumnUnprojected { .. }
            | DiffEvent::ColumnRenamed { .. }
            | DiffEvent::StarProjectionAdded { .. }
            | DiffEvent::StarProjectionRemoved { .. }
            | DiffEvent::CteAdded { .. }
            | DiffEvent::CteRemoved { .. }
            | DiffEvent::SampleAdded { .. }
            | DiffEvent::SampleRemoved { .. }
            | DiffEvent::OrderByAdded { .. }
            | DiffEvent::OrderByRemoved { .. }
            | DiffEvent::OrderByDirectionChanged { .. }
            | DiffEvent::SetOperationAdded { .. }
            | DiffEvent::SetOperationRemoved { .. }
            | DiffEvent::SetOperationChanged { .. }
            | DiffEvent::AggregateAdded { .. }
            | DiffEvent::AggregateRemoved { .. }
            | DiffEvent::AggregateFunctionChanged { .. }
            | DiffEvent::AggregateDistinctChanged { .. }
            | DiffEvent::AggregateArgumentChanged { .. }
            | DiffEvent::WindowFunctionAdded { .. }
            | DiffEvent::WindowFunctionRemoved { .. }
            | DiffEvent::WindowPartitionChanged { .. }
            | DiffEvent::WindowPartitionRemoved { .. }
            | DiffEvent::WindowFrameChanged { .. }
            | DiffEvent::SubqueryPredicateChanged { .. }
            | DiffEvent::SubqueryScopeChanged { .. }
            | DiffEvent::DdlActionChanged { .. }
            | DiffEvent::TableDdlAdded { .. }
            | DiffEvent::TableDdlRemoved { .. }
            | DiffEvent::DdlColumnAdded { .. }
            | DiffEvent::DdlColumnRemoved { .. }
            | DiffEvent::PrivilegeGranted { .. }
            | DiffEvent::PrivilegeRevoked { .. }
            | DiffEvent::PolicyAttached { .. }
            | DiffEvent::PolicyDetached { .. }
            | DiffEvent::PolicyBodyChanged { .. }
            | DiffEvent::CatalogTagAdded { .. }
            | DiffEvent::CatalogTagRemoved { .. }
            | DiffEvent::NullabilityChanged { .. }
            | DiffEvent::LineageChanged { .. }
            | DiffEvent::TaintChanged { .. }
            | DiffEvent::ConstraintChanged { .. }
            | DiffEvent::ModelConfigChanged { .. }
            | DiffEvent::WriteTargetChanged { .. }
            | DiffEvent::Opaque { .. } => None,
        }
    }

    /// Where the head writes what the change names: the column, the join,
    /// the table, the window or aggregate call, the nested block a clause
    /// change is in. `None` where the head has no text of its own for it
    /// (what only the baseline has, a change to the outermost block's
    /// clauses): such a change is placed at its statement.
    pub fn head_place(&self) -> Option<Span> {
        if let Some(block) = self.within() {
            return block.source_span;
        }
        match self {
            DiffEvent::ColumnProjected { column, .. } => column.source_span,
            DiffEvent::ColumnRenamed { head, .. } => head.source_span,
            DiffEvent::ProjectionItemChanged { output, .. } => {
                output.as_ref().and_then(|output| output.source_span)
            }
            DiffEvent::NullabilityChanged { output, .. }
            | DiffEvent::LineageChanged { output, .. }
            | DiffEvent::TaintChanged { output, .. } => output.source_span,
            DiffEvent::ConstraintChanged { target, .. } => target.source_span,
            DiffEvent::JoinAdded {
                right, source_span, ..
            }
            | DiffEvent::JoinTypeChanged {
                right, source_span, ..
            }
            | DiffEvent::JoinConditionChanged {
                right, source_span, ..
            } => right.source_span.or(*source_span),
            DiffEvent::TableAdded { table } => table.source_span,
            DiffEvent::WriteTargetChanged { head, .. } => head.source_span,
            DiffEvent::WindowFunctionAdded { source_span, .. }
            | DiffEvent::WindowPartitionChanged { source_span, .. }
            | DiffEvent::WindowPartitionRemoved { source_span, .. }
            | DiffEvent::WindowFrameChanged { source_span, .. } => *source_span,
            DiffEvent::AggregateAdded { on, .. }
            | DiffEvent::AggregateFunctionChanged { on, .. }
            | DiffEvent::AggregateDistinctChanged { on, .. }
            | DiffEvent::AggregateArgumentChanged { on, .. } => {
                on.as_ref().and_then(|on| on.source_span)
            }
            DiffEvent::StatementKindChanged { .. }
            | DiffEvent::StatementAdded { .. }
            | DiffEvent::StatementRemoved { .. }
            | DiffEvent::TableRemoved { .. }
            | DiffEvent::CrossSchemaIntroduced { .. }
            | DiffEvent::TableFunctionAdded { .. }
            | DiffEvent::TableFunctionRemoved { .. }
            | DiffEvent::TableFunctionArgumentChanged { .. }
            | DiffEvent::WhereAdded { .. }
            | DiffEvent::WhereRemoved { .. }
            | DiffEvent::WhereConditionChanged { .. }
            | DiffEvent::WriteBoundednessChanged { .. }
            | DiffEvent::JoinRemoved { .. }
            | DiffEvent::ColumnUnprojected { .. }
            | DiffEvent::StarProjectionAdded { .. }
            | DiffEvent::StarProjectionRemoved { .. }
            | DiffEvent::DistinctAdded { .. }
            | DiffEvent::DistinctRemoved { .. }
            | DiffEvent::QualifyAdded { .. }
            | DiffEvent::QualifyRemoved { .. }
            | DiffEvent::QualifyChanged { .. }
            | DiffEvent::CteAdded { .. }
            | DiffEvent::CteRemoved { .. }
            | DiffEvent::SampleAdded { .. }
            | DiffEvent::SampleRemoved { .. }
            | DiffEvent::HavingAdded { .. }
            | DiffEvent::HavingRemoved { .. }
            | DiffEvent::HavingChanged { .. }
            | DiffEvent::GroupByAdded { .. }
            | DiffEvent::GroupByRemoved { .. }
            | DiffEvent::OrderByAdded { .. }
            | DiffEvent::OrderByRemoved { .. }
            | DiffEvent::OrderByDirectionChanged { .. }
            | DiffEvent::SetOperationAdded { .. }
            | DiffEvent::SetOperationRemoved { .. }
            | DiffEvent::SetOperationChanged { .. }
            | DiffEvent::AggregateRemoved { .. }
            | DiffEvent::WindowFunctionRemoved { .. }
            | DiffEvent::SubqueryPredicateChanged { .. }
            | DiffEvent::SubqueryScopeChanged { .. }
            | DiffEvent::LimitAdded { .. }
            | DiffEvent::LimitRemoved { .. }
            | DiffEvent::LimitValueChanged { .. }
            | DiffEvent::DdlActionChanged { .. }
            | DiffEvent::TableDdlAdded { .. }
            | DiffEvent::TableDdlRemoved { .. }
            | DiffEvent::DdlColumnAdded { .. }
            | DiffEvent::DdlColumnRemoved { .. }
            | DiffEvent::PrivilegeGranted { .. }
            | DiffEvent::PrivilegeRevoked { .. }
            | DiffEvent::PolicyAttached { .. }
            | DiffEvent::PolicyDetached { .. }
            | DiffEvent::PolicyBodyChanged { .. }
            | DiffEvent::CatalogTagAdded { .. }
            | DiffEvent::CatalogTagRemoved { .. }
            | DiffEvent::ModelConfigChanged { .. }
            | DiffEvent::Opaque { .. } => None,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────
// DiffContext — per-side IR projection
// ─────────────────────────────────────────────────────────────────────

/// Per-side snapshots of both statements in the diff. Match against
/// `diff.context.baseline.*` or `diff.context.head.*` for conditions
/// on either side that the `events` list alone cannot express.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct DiffContext {
    pub baseline: DiffStatementSnapshot,
    pub head: DiffStatementSnapshot,
    /// Cross-statement facts for the baseline script.
    pub script_baseline: ScriptShape,
    /// Cross-statement facts for the head script.
    pub script_head: ScriptShape,
}

/// Cross-statement properties of a script (the multi-statement
/// surrounding context, not the per-statement IR).
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct ScriptShape {
    pub statement_count: usize,
    pub statement_kinds: Vec<StatementKind>,
}

/// Per-side snapshot of one statement's structural properties.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct DiffStatementSnapshot {
    pub statement_kind: Option<StatementKind>,

    /// Tables the statement reads from.
    pub reads_tables: Vec<TableRef>,
    /// Distinct schemas covered by `reads_tables`.
    pub reads_schemas: Vec<IdentName>,

    /// Clauses present on this side of the diff.
    pub clauses_present: Vec<ClauseKind>,

    /// Joins active in this side's plan.
    pub joins: Vec<JoinEvent>,

    /// Filter and grouping predicates (WHERE / HAVING / QUALIFY /
    /// JOIN-ON), each tagged with its source clause.
    pub predicates: Vec<PredicateEvent>,

    /// Aggregate calls.
    pub aggregates: Vec<AggregateEvent>,

    /// Window function calls.
    pub window_functions: Vec<WindowEvent>,

    /// Set operations (UNION/INTERSECT/EXCEPT) and their kinds in
    /// statement order.
    pub set_operations: Vec<SetOpKind>,

    /// CTEs defined at this statement (by alias name).
    pub ctes: Vec<CteFact>,

    /// Nested SELECT scopes — one entry per subquery or inner
    /// SELECT. Useful when a rule cares about clause presence at a
    /// specific nesting depth.
    pub scopes: Vec<SelectScope>,

    /// Projected output items (alias, expression, nullability, taint)
    /// after SELECT resolution.
    pub projections: Vec<super::query::ProjectionEvent>,

    /// Per-output-column state on this side (nullability, lineage,
    /// taint, structural constraints). Compose deltas by comparing
    /// `baseline.output_columns` against `head.output_columns`.
    pub output_columns: Vec<OutputColumnFact>,

    /// LIMIT literal value if present and statically known.
    pub limit_value: Option<u64>,
}

/// Clauses that may be present in a SELECT scope; used by
/// `diff.context.{baseline,head}.clauses_present`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", schemars(rename = "ClauseType"))]
pub enum ClauseKind {
    Where,
    Having,
    Qualify,
    Distinct,
    Sample,
    Limit,
    GroupBy,
    OrderBy,
}

/// A CTE defined in the statement, projected for predicate use.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", schemars(rename = "Cte"))]
pub struct CteFact {
    pub name: IdentName,
    /// `true` iff the CTE was declared `WITH RECURSIVE`.
    pub recursive: bool,
}

/// One column of the relation a query returns, or a view, materialized
/// view or `CREATE TABLE … AS` makes, with what analysis shows of it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", schemars(rename = "OutputColumn"))]
pub struct OutputColumnFact {
    /// The column, by the name the relation gives it.
    pub column: ColumnRef,
    /// `true` when the column may hold NULL, `false` when it never does;
    /// absent where analysis does not show which (a column read from a
    /// table whose nullability no catalog states).
    pub nullable: Option<bool>,
    /// The table columns the column's value is drawn from (lineage), each
    /// once; empty for a value drawn from none (a literal). Absent where
    /// lineage is not analysed.
    pub sources: Option<Vec<ColumnRef>>,
    /// The catalog tags whose values reach the column.
    pub taint_tags: Vec<CatalogTag>,
    /// The constraints the query shows the column's values meet: a value
    /// or set a filter fixes, a range, `IS NOT NULL`, uniqueness.
    pub constraints: ConstraintFactSet,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum OpaqueDiffReason {
    DialectSpecificDelta,
    StructuralMismatch,
    /// Baseline and head statements could not be paired with
    /// sufficient confidence.
    UnpairableStatements,
    /// A diff check needed analysis state that wasn't available —
    /// for example, when one of the statements couldn't be fully
    /// parsed.
    UnsupportedAnalysis,
    Unknown,
}

// ─────────────────────────────────────────────────────────────────────
// Supporting closed enums and structs
// ─────────────────────────────────────────────────────────────────────

/// Direction a `LIMIT` value moved between baseline and head.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum LimitDirection {
    Increased,
    Decreased,
    Equal,
}

/// Direction a write statement's boundedness changed.
///
/// `Bounded` means a WHERE clause was added between baseline and
/// head; `Unbounded` means one was removed. Structural fact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", schemars(rename = "WriteScope"))]
pub enum WriteBoundedness {
    Bounded,
    Unbounded,
}

/// Coarse shape tag for a projection item. Used by
/// `projection_item_changed` so rules can match on what kind of
/// projection content changed (literal swap, column → expression,
/// etc.) without inspecting the full expression tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum ProjectionItemKindTag {
    /// Projection item is a column reference (`SELECT a`, `SELECT t.col`).
    Column,
    /// Projection item is a literal (`SELECT 1`, `SELECT 'x'`).
    Literal,
    /// Projection item is a composite expression — function call,
    /// CASE, binary/unary op, IN-list, subquery, etc.
    Expression,
    /// Projection item is `* | <qual>.*`.
    Star,
}

/// Direction an aggregate-call's DISTINCT modifier moved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum DistinctChange {
    Added,
    Removed,
}

/// Subquery comparison shape in a diff context. `Lateral` is excluded
/// as it is not a comparison subquery.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum SubqueryShape {
    Exists,
    NotExists,
    In,
    NotIn,
    Scalar,
    Any,
    All,
}

/// The query block nested in a statement that a clause change is in: a
/// CTE body, a derived table or a `MERGE` branch. A change to the
/// statement's outermost query block names none.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct QueryBlock {
    pub kind: QueryBlockKind,
    /// The CTE's name, or the derived table's alias where it has one.
    pub name: Option<IdentName>,
    /// Where the head writes the block.
    pub source_span: Option<Span>,
}

/// What a nested query block is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum QueryBlockKind {
    Cte,
    DerivedTable,
    /// A `WHEN` branch of a `MERGE`, the `ordinal`th (from 1) of its kind.
    MergeBranch {
        when: MergeBranchKind,
        ordinal: u32,
    },
}

/// Scope-path descriptor for clauses (`DISTINCT`, `QUALIFY`) whose
/// effect varies by which SELECT they live on (outer vs. specific
/// nested scope). `primary_table` identifies the dominant table the
/// SELECT projects from, when one can be resolved.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct SelectScope {
    pub scope_path: Vec<SubqueryShape>,
    pub primary_table: Option<TableRef>,
}

/// Structural relationship between a baseline and head expression.
///
/// - `Equivalent`: trees match after normalization.
/// - `SubtreeOfBaseline`: head is a sub-tree of baseline (column extracted
///   from a larger expression).
/// - `SubtreeOfHead`: baseline is a sub-tree of head (column wrapped in
///   additional computation).
/// - `Disjoint`: trees share no sub-tree; column-set deltas carried in
///   the payload.
/// - `Opaque`: at least one side could not be fully analyzed.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ExpressionContainment {
    Equivalent,
    SubtreeOfBaseline {
        dropped_columns: Vec<ColumnRef>,
    },
    SubtreeOfHead {
        added_columns: Vec<ColumnRef>,
    },
    Disjoint {
        baseline_only_columns: Vec<ColumnRef>,
        head_only_columns: Vec<ColumnRef>,
        common_columns: Vec<ColumnRef>,
    },
    Opaque,
}

// ─────────────────────────────────────────────────────────────────────
// Per-node expression deltas
// ─────────────────────────────────────────────────────────────────────

/// One step in a path that locates a node inside an expression
/// tree. Used by `node_deltas[*].path` to point at exactly where
/// inside an expression the change happened.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(tag = "step", rename_all = "snake_case")]
pub enum ExpressionPathStep {
    BinOpLeft,
    BinOpRight,
    /// Position of an operand within an `AND` / `OR` chain.
    LogicalChainOperand {
        index: usize,
    },
    /// Position of an operand within a run of arithmetic, concatenation
    /// or bitwise operators (`a + b - c`).
    OperatorChainOperand {
        index: usize,
    },
    UnaryOperand,
    FuncCallArg {
        index: usize,
    },
    CaseOperand,
    CaseWhenCondition {
        index: usize,
    },
    CaseWhenResult {
        index: usize,
    },
    CaseElse,
    CastOperand,
    InListExpr,
    InListItem {
        index: usize,
    },
    BetweenExpr,
    BetweenLow,
    BetweenHigh,
    LikeExpr,
    LikePattern,
    LikeEscape,
    QuantifiedCmpLeft,
    QuantifiedCmpRight,
    FieldAccessBase,
    LambdaBody,
}

/// Classification of a single node-level expression change. Match on
/// `kind:` to target a specific kind of leaf or single-node
/// difference.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ExpressionDeltaKind {
    /// Column reference changed (a column reference replaced by a
    /// different column reference at the same path).
    ColumnChanged {
        baseline: ColumnRef,
        head: ColumnRef,
    },
    /// Literal value changed (same literal kind, different value).
    LiteralChanged {
        baseline: LiteralValue,
        head: LiteralValue,
    },
    /// Function-call name changed (same `FuncCall`, different
    /// resolved function identity).
    FunctionNameChanged {
        baseline: IdentName,
        head: IdentName,
    },
    /// Function-call positional arity changed.
    FunctionArityChanged { baseline: usize, head: usize },
    /// Binary operator changed (left/right operands compared
    /// separately by recursion).
    BinaryOperatorChanged {
        baseline: super::expr::BinaryOp,
        head: super::expr::BinaryOp,
    },
    /// Unary operator changed (operand compared separately by recursion).
    UnaryOperatorChanged {
        baseline: UnaryOperator,
        head: UnaryOperator,
    },
    /// Cast target type changed.
    CastTypeChanged { baseline: DataType, head: DataType },
    /// CASE expression branch count changed. Per-branch
    /// condition/result deltas at lower paths are emitted separately
    /// for shared-index branches.
    CaseBranchCountChanged { baseline: usize, head: usize },
    /// CASE ELSE clause added (baseline had no ELSE, head has one).
    CaseElseAdded,
    /// CASE ELSE clause removed (baseline had one, head does not).
    CaseElseRemoved,
    /// `FieldAccess` (semi-structured `:foo.bar[2]`) path changed.
    FieldAccessPathChanged {
        baseline: Vec<FieldAccessStep>,
        head: Vec<FieldAccessStep>,
    },
    /// Subquery-bearing node (`Exists`, `ScalarSubquery`,
    /// `QuantifiedCmp` with subquery rhs) read-set changed.
    SubqueryReadSetChanged {
        baseline_tables: Vec<TableRef>,
        head_tables: Vec<TableRef>,
    },
    /// Variant tag changed at this path (e.g. `Column` → `FuncCall`).
    /// No deeper deltas are emitted under this path — structural
    /// mismatch is the terminating witness.
    StructureChanged {
        baseline_variant: ExpressionVariant,
        head_variant: ExpressionVariant,
    },
}

/// Tag identifying the kind of expression node. Used by
/// `structure_changed` to record that the shape at a path changed
/// (e.g. a binary op was replaced by a function call).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum ExpressionVariant {
    Column,
    OuterRef,
    Literal,
    BinaryOp,
    /// An `AND` / `OR` chain over two or more operands.
    LogicalChain,
    /// A run of arithmetic, concatenation or bitwise operators over three
    /// or more operands.
    OperatorChain,
    UnaryOp,
    FunctionCall,
    Case,
    Cast,
    InList,
    Between,
    Like,
    Exists,
    ScalarSubquery,
    QuantifiedCmp,
    WindowFunction,
    FieldAccess,
    Lambda,
    PatternVarRef,
    Opaque,
}

/// Unary operator kinds reported by `unary_operator_changed`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum UnaryOperator {
    Not,
    Neg,
    Plus,
    IsNull,
    IsNotNull,
    AtLocal,
    Collate,
    Prior,
    Spread,
}

/// One segment of a semi-structured field-access path (e.g.
/// `:foo.bar[2]`). Used by `field_access_path_changed`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FieldAccessStep {
    /// Static field selector (`payload:foo`).
    Field { name: IdentName },
    /// Static array index (`payload[2]`).
    Index { value: i64 },
    /// Dynamic index (`payload[expr]`). The inner expression is not
    /// projected; consumers treat this as opaque.
    Dynamic,
}

/// A single node-level change inside an expression. `path` locates
/// the node; `kind` classifies the change at that node.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct ExpressionDelta {
    pub path: Vec<ExpressionPathStep>,
    pub kind: ExpressionDeltaKind,
}

/// A structural constraint on a single column. Dialect-specific
/// constraints that cannot be represented collapse to `Opaque`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(tag = "kind", rename_all = "snake_case")]
#[cfg_attr(feature = "schema", schemars(rename = "ConstraintCase"))]
pub enum ConstraintFactArm {
    Eq {
        literal: LiteralValue,
    },
    Range {
        low: Option<LiteralValue>,
        high: Option<LiteralValue>,
    },
    InSet {
        values: Vec<LiteralValue>,
    },
    IsNotNull,
    /// No two rows of the relation hold the same value in the column: a
    /// `DISTINCT`, a `GROUP BY` key, a key the catalog declares.
    Unique,
    Opaque,
}

/// Set of typed constraint arms for one column. Empty `arms` means
/// no structural constraint was derived for the column.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct ConstraintFactSet {
    pub arms: Vec<ConstraintFactArm>,
}

impl ConstraintFactSet {
    /// Visit the text of each value an arm holds.
    pub(crate) fn for_each_literal_text_mut(&mut self, f: &mut dyn FnMut(&mut String)) {
        for arm in &mut self.arms {
            match arm {
                ConstraintFactArm::Eq { literal } => literal.for_each_written_text_mut(f),
                ConstraintFactArm::Range { low, high } => {
                    for bound in [low, high].into_iter().flatten() {
                        bound.for_each_written_text_mut(f);
                    }
                }
                ConstraintFactArm::InSet { values } => {
                    for value in values {
                        value.for_each_written_text_mut(f);
                    }
                }
                ConstraintFactArm::IsNotNull
                | ConstraintFactArm::Unique
                | ConstraintFactArm::Opaque => {}
            }
        }
    }

    /// True iff this set contributes no structural arms.
    pub fn is_empty(&self) -> bool {
        self.arms.is_empty()
    }
}
