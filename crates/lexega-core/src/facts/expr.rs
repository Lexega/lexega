// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Public expression tree.
//!
//! Mirrors the IR's `ScalarExpr` semantically without exposing IR
//! variant names. Customer predicates can match `WHERE func(col) = lit`
//! patterns by traversing into typed variant payloads.
//!
//! Recursive through `Box<Expr>`. Path access into a sum-type variant
//! follows the convention `path.<snake_case_variant_name>.<field>` —
//! e.g. `Expr::BinaryOp(b)` is accessed as `path.binary_op.left`,
//! `path.binary_op.op`, etc.

use serde::{Deserialize, Serialize};

#[cfg(feature = "schema")]
use schemars::JsonSchema;

use crate::lexer::token::Span;

use super::identity::{ColumnRef, IdentName, TableRef};
use super::literal::{DataType, LiteralValue};

/// A SQL expression. The `kind:` tag identifies the shape (`column`,
/// `literal`, `func_call`, `binary_op`, …); the matching field of the
/// same name carries that shape's data — predicate paths look like
/// `path.binary_op.left`, `path.func_call.name`,
/// `path.subquery.kind`, and so on.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(tag = "kind", rename_all = "snake_case")]
#[cfg_attr(feature = "schema", schemars(rename = "Expression"))]
pub enum Expr {
    /// Column reference.
    Column { column: ColumnRef },

    /// Literal value.
    Literal { literal: LiteralValue },

    /// Function call (scalar, table-valued, aggregate-as-expression, …).
    FuncCall { func_call: FuncCallExpr },

    /// Binary operator: arithmetic, comparison, logical.
    BinaryOp { binary_op: BinaryOpExpr },

    /// A run of two or more operands joined by the same `AND` / `OR`.
    LogicalChain { logical_chain: LogicalChainExpr },

    /// Unary operator: NOT, -, +, IS NULL, IS NOT NULL.
    UnaryOp { unary_op: UnaryOpExpr },

    /// `CASE … WHEN … THEN … ELSE … END`.
    Case { case: CaseExpr },

    /// `CAST` / `TRY_CAST` / `SAFE_CAST`.
    Cast { cast: CastExpr },

    /// Tuple expression: `(a, b, c)` or `ROW(a, b)`.
    Tuple { elements: Vec<Expr> },

    /// `expr IN (v1, v2, ...)` — distinct from `BinaryOp(In, …)`
    /// when the RHS is a constant list.
    InList { in_list: InListExpr },

    /// `EXISTS` / `NOT EXISTS` / scalar / `IN` subquery.
    Subquery { subquery: SubqueryExpr },

    /// `<expr> <cmp> { ANY | ALL } (<subquery|list>)` — typed
    /// quantified comparison. Covers `x = ANY (...)`, `x <> ALL (...)`,
    /// `x [NOT] IN (...)` (the IN form lowers to
    /// `op: eq, quantifier: any, negated: <bool>`). The rule engine
    /// can match the full structural shape — operator, quantifier,
    /// negation, and the subquery / list RHS — without resorting to
    /// string heuristics or losing the quantifier.
    QuantifiedCmp { quantified_cmp: QuantifiedCmpExpr },

    /// `tbl.*` / `*` (star expansion before projection).
    Star { star: StarExpr },

    /// Array / dictionary / set literal.
    Collection { collection: CollectionExpr },

    /// Lateral / correlated outer-scope reference.
    OuterColumn { outer_column: OuterColumnRef },

    /// Bind variable / named parameter / placeholder.
    Parameter { parameter: ParameterRef },

    /// Window function reference (within `OVER (…)`).
    Window { window: Box<WindowExpr> },

    /// Field access into a STRUCT / OBJECT / VARIANT — `obj.field`.
    FieldAccess { field_access: FieldAccessExpr },

    /// Index access into an array / map — `arr[idx]`.
    IndexAccess { index_access: IndexAccessExpr },

    /// Expression could not be fully typed. Match `kind: opaque` plus
    /// `opaque.reason: <reason>`; `rendered` is display-only.
    Opaque { opaque: OpaqueExpr },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct FuncCallExpr {
    pub name: IdentName,
    pub schema: Option<IdentName>,
    pub args: Vec<Expr>,
    /// Catalog-flagged: `CURRENT_DATE`, `NOW`, `GETDATE`, etc.
    pub is_temporal: bool,
    pub is_deterministic: bool,
    pub is_aggregate: bool,
    pub is_window: bool,
    /// `true` when the function name resolves to a catalog entry.
    pub catalog_resolved: bool,
    pub source_span: Option<Span>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct BinaryOpExpr {
    pub op: BinaryOp,
    pub left: Box<Expr>,
    pub right: Box<Expr>,
}

/// A run of two or more operands joined by the same `AND` / `OR`.
/// `a AND b AND c` is one chain with three operands rather than nested
/// two-operand nodes, so a long `WHERE` clause stays flat.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct LogicalChainExpr {
    pub op: LogicalChainOp,
    /// Operands in source order; always two or more.
    pub operands: Vec<Expr>,
}

/// The connective joining a [`LogicalChainExpr`]'s operands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum LogicalChainOp {
    And,
    Or,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum BinaryOp {
    // Comparison
    Eq,
    Neq,
    Lt,
    Lte,
    Gt,
    Gte,
    IsDistinctFrom,
    IsNotDistinctFrom,
    Like,
    ILike,
    NotLike,
    NotILike,
    Similar,
    NotSimilar,
    In,
    NotIn,

    // Arithmetic
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    Pow,

    // Logical
    And,
    Or,

    // String
    Concat,

    // Bitwise
    BitAnd,
    BitOr,
    BitXor,
    ShiftLeft,
    ShiftRight,

    // JSON / array
    JsonGet,
    JsonGetText,
    ArrayContains,
    ArrayOverlap,

    /// Dialect-specific operator. Predicate `op.kind: other` +
    /// `op.other.raw: { matches: "@>" }` for matching.
    Other(IdentName),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct UnaryOpExpr {
    pub op: UnaryOp,
    pub operand: Box<Expr>,
}

/// `<lhs> <cmp> { ANY | ALL } (<rhs>)`. `negated` lifts surface-level
/// negation out of `NOT IN` and explicit-NOT parens so the LHS,
/// comparison operator, quantifier, and negation are all directly
/// matchable; the RHS is either a subquery or a constant list (see
/// `QuantifiedRhsExpr`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct QuantifiedCmpExpr {
    pub op: ComparisonOp,
    pub quantifier: Quantifier,
    pub negated: bool,
    pub lhs: Box<Expr>,
    pub rhs: QuantifiedRhsExpr,
    pub source_span: Option<Span>,
}

/// Right-hand side of a quantified comparison. Tagged-enum `kind` so
/// rules can predicate on the shape (subquery vs constant list)
/// before drilling further.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum QuantifiedRhsExpr {
    Subquery { subquery: Box<SubqueryExpr> },
    List { items: Vec<Expr> },
}

/// Comparison operator at the head of a quantified comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", schemars(rename = "ComparisonOperator"))]
pub enum ComparisonOp {
    Eq,
    NotEq,
    Lt,
    LtEq,
    Gt,
    GtEq,
}

/// Quantifier on a quantified comparison. `Any` covers both `ANY` and
/// `SOME` SQL spellings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum Quantifier {
    Any,
    All,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", schemars(rename = "UnaryOperator"))]
pub enum UnaryOp {
    Not,
    Negate,
    Plus,
    IsNull,
    IsNotNull,
    IsTrue,
    IsFalse,
    IsUnknown,
    IsNotUnknown,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct CaseExpr {
    /// Present for `CASE expr WHEN val ...`; omitted for
    /// `CASE WHEN cond ...`.
    pub operand: Option<Box<Expr>>,
    pub branches: Vec<CaseBranch>,
    pub else_branch: Option<Box<Expr>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct CaseBranch {
    pub condition: Expr,
    pub result: Expr,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct CastExpr {
    pub expr: Box<Expr>,
    pub target_type: DataType,
    pub cast_kind: CastKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", schemars(rename = "CastType"))]
pub enum CastKind {
    /// `CAST(expr AS type)` — fails on conversion error.
    Strict,
    /// `TRY_CAST(expr AS type)` — returns NULL on conversion error.
    Try,
    /// Snowflake `SAFE_CAST(expr AS type)` — returns NULL on error.
    Safe,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct InListExpr {
    pub expr: Box<Expr>,
    pub values: Vec<Expr>,
    pub negated: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct SubqueryExpr {
    pub kind: SubqueryKind,
    pub correlated: bool,
    pub source_span: Option<Span>,
    /// Inner facts. `Box`ed to break the recursion in the type.
    /// Recursive predicates can traverse via
    /// `subquery.inner_facts.scopes.exists.<sub-path>`.
    pub inner_facts: Box<super::query::QueryFacts>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", schemars(rename = "SubqueryType"))]
pub enum SubqueryKind {
    Scalar,
    Exists,
    NotExists,
    InSubquery,
    NotInSubquery,
    Lateral,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct StarExpr {
    pub qualifier: Option<TableRef>,
    pub exclude: Vec<IdentName>,
    pub replace: Vec<StarRename>,
    pub rename: Vec<StarRename>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct StarRename {
    pub from: IdentName,
    pub to: IdentName,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct CollectionExpr {
    pub kind: CollectionKind,
    pub elements: Vec<Expr>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", schemars(rename = "CollectionType"))]
pub enum CollectionKind {
    Array,
    Dict,
    Set,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct OuterColumnRef {
    pub column: ColumnRef,
    /// 1 = parent scope, 2 = grandparent, …
    pub depth: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct ParameterRef {
    pub name: Option<IdentName>,
    pub position: Option<u32>,
    pub kind: ParameterKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", schemars(rename = "ParameterType"))]
pub enum ParameterKind {
    /// Bind parameter (`?`, `$1`, `:param`).
    Bind,
    /// PL/pgSQL / Snowflake-scripting variable.
    Variable,
    /// Session variable (e.g. `@var` in MSSQL).
    SessionVar,
    /// Stored-procedure / function argument.
    ProcArg,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct WindowExpr {
    pub function: WindowFunctionName,
    pub args: Vec<Expr>,
    pub partition_by: Vec<Expr>,
    pub order_by: Vec<super::query::OrderByEvent>,
    pub frame: Option<super::query::WindowFrame>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum WindowFunctionName {
    RowNumber,
    Rank,
    DenseRank,
    PercentRank,
    CumeDist,
    Ntile,
    Lag,
    Lead,
    FirstValue,
    LastValue,
    NthValue,
    Aggregate(super::query::AggregateFunction),
    Other(IdentName),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct FieldAccessExpr {
    pub object: Box<Expr>,
    pub field: IdentName,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct IndexAccessExpr {
    pub collection: Box<Expr>,
    pub index: Box<Expr>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct OpaqueExpr {
    pub reason: OpaqueExprReason,
    /// Display only; never participates in predicate matching.
    pub rendered: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum OpaqueExprReason {
    DialectSpecificFunction,
    UnparsedFragment,
    UnresolvedReference,
    /// dbt `{{ ... }}` template in expression position.
    JinjaTemplate,
    /// PL/pgSQL variable, snowscripting variable, etc.
    ProceduralReference,
    /// Predicate predicate-of-the-predicate; rare.
    NestedOpaque,
}

pub use super::identity::ScopeIdentity as ExprScopeIdentity;
