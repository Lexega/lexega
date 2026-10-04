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
use super::expr::WindowFunctionName;
use super::identity::{ColumnRef, IdentName, ObjectRef, PrincipalRef, TableRef};
use super::literal::{DataType, LiteralValue};
use super::policy::PolicyBodySemantics;
use super::privilege::Privilege;
use super::query::{
    AggregateEvent, AggregateFunction, JoinEvent, JoinKind, PredicateEvent, SetOpKind, WindowEvent,
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

    // ───────────── WHERE clause ─────────────
    WhereAdded {
        table: TableRef,
        added_columns: Vec<ColumnRef>,
    },
    WhereRemoved {
        table: TableRef,
        removed_columns: Vec<ColumnRef>,
    },
    WhereConditionChanged {
        table: TableRef,
        column: ColumnRef,
        baseline_op: Option<super::expr::BinaryOp>,
        head_op: Option<super::expr::BinaryOp>,
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
    },
    JoinConditionChanged {
        left: TableRef,
        right: TableRef,
    },

    // ───────────── Projection ─────────────
    ColumnProjected {
        table: TableRef,
        column: ColumnRef,
    },
    ColumnUnprojected {
        table: TableRef,
        column: ColumnRef,
    },
    StarProjectionAdded {
        table: Option<TableRef>,
    },
    StarProjectionRemoved {
        table: Option<TableRef>,
    },
    /// Content of a paired SELECT projection slot changed (e.g.
    /// `SELECT 1 → SELECT 2`, `SELECT a → SELECT a + 1`,
    /// `SELECT UPPER(x) → SELECT LOWER(x)`). One event per output
    /// slot whose content differs. `output` is the head-side column
    /// identity (shared with `nullability_changed` / `lineage_changed`
    /// / `taint_changed`); omitted when the head slot is a star
    /// projection.
    ProjectionItemChanged {
        output: Option<ColumnRef>,
        baseline_kind: ProjectionItemKindTag,
        head_kind: ProjectionItemKindTag,
    },

    // ───────────── Clause presence — split per (clause × direction) ─────────────
    DistinctAdded {
        scope: SelectScope,
    },
    DistinctRemoved {
        scope: SelectScope,
    },
    QualifyAdded {
        window_functions: Vec<WindowFunctionName>,
    },
    QualifyRemoved {
        window_functions: Vec<WindowFunctionName>,
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
    HavingAdded,
    HavingRemoved,
    HavingChanged,
    GroupByAdded {
        columns: Vec<ColumnRef>,
    },
    GroupByRemoved {
        columns: Vec<ColumnRef>,
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
    },
    WindowFunctionRemoved {
        function: WindowFunctionName,
    },
    WindowPartitionChanged {
        function: WindowFunctionName,
        baseline_partition: Vec<ColumnRef>,
        head_partition: Vec<ColumnRef>,
    },
    WindowPartitionRemoved {
        function: WindowFunctionName,
        removed_partition: Vec<ColumnRef>,
    },
    WindowFrameChanged {
        function: WindowFunctionName,
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
    },
    LimitRemoved,
    /// LIMIT value changed (both sides have a LIMIT, magnitude moved).
    LimitValueChanged {
        baseline: Option<LiteralValue>,
        head: Option<LiteralValue>,
        direction: LimitDirection,
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
    NullabilityChanged {
        output: ColumnRef,
        baseline_nullable: bool,
        head_nullable: bool,
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

    // ───────────── Opaque ─────────────
    Opaque {
        reason: OpaqueDiffReason,
        baseline_span: Option<Span>,
        head_span: Option<Span>,
    },
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

/// Structural state of one output column on a single side of the diff.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", schemars(rename = "OutputColumn"))]
pub struct OutputColumnFact {
    pub column: ColumnRef,
    pub nullable: Option<bool>,
    /// Upstream source columns contributing to this output (lineage).
    pub sources: Vec<ColumnRef>,
    /// Sensitivity tags inherited from upstream sources.
    pub taint_tags: Vec<CatalogTag>,
    /// Structural constraints derivable for this column (Eq, Range,
    /// IsNotNull, …).
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
    /// True iff this set contributes no structural arms.
    pub fn is_empty(&self) -> bool {
        self.arms.is_empty()
    }
}
