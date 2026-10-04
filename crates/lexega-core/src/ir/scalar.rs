// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! IR scalar expressions.
//!
//! `ScalarExpr` is **not** the AST expression type. Lowering rewrites AST
//! expressions to this smaller, normalized tree:
//!
//! - Names are resolved to [`ColumnId`]s.
//! - Correlated references are explicit [`ScalarExpr::OuterRef`] nodes — not
//!   just plain column references — so nested-plan analyses see correlation
//!   without a second pass.
//! - Variant semi-structured paths (`payload:a.b::INT`) become a dedicated
//!   [`ScalarExpr::FieldAccess`] rather than a chain of function calls.
//! - Subqueries appearing in scalar position carry their own lowered
//!   [`RelPlan`] plus an explicit correlation set.
//!
//! # CLOSED ENUM
//!
//! `ScalarExpr`, `Lit`, `Quantifier`, `QuantifiedRhs`, `FieldStep`,
//! `UnaryOpKind`, `ComparisonOp`, `BinOpKind`, and `LikeKind` are
//! **closed** (see `plan.rs` for the full rule).
//! Exhaustive matches in `schema.rs`, `visitor.rs`, `pretty.rs`, and
//! `outer_refs.rs` make drift a compile error, not a silent regression.
//!
//! `UnaryOpKind`, `ComparisonOp`, and `BinOpKind` type the `op` fields
//! on `UnaryOp` / `QuantifiedCmp` / `BinOp`. The typed taxonomies bind
//! every consumer to a closed-enum match; the IR-side `String → typed`
//! conversion happens once at lowering and never again. Downstream
//! analyses must not stringify and re-parse the operator.

use super::column::ColumnId;
use super::plan::{RelPlan, WindowCall};
use crate::lexer::Span;

/// Identifies a query scope for correlation.
///
/// Assigned during lowering: every `RelPlan` that introduces a new name
/// scope (a subquery, a CTE body, a lateral join right side) gets one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ScopeId(pub u32);

/// Resolved SQL type. Placeholder with no concrete variants.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SqlType {
    /// Temporary: just the catalog-reported type string, uppercased.
    /// Replaced by a proper enum before analyses consume it.
    pub repr: String,
}

/// IR-level scalar expression. Smaller surface than `AstExpr`:
/// names are resolved, aliases inlined, variant-path access is dedicated.
#[derive(Debug, Clone)]
pub enum ScalarExpr {
    /// Reference to a [`ColumnId`] in the current scope.
    Column { column: ColumnId, span: Span },

    /// Reference to a column from an enclosing scope (correlation).
    OuterRef {
        scope: ScopeId,
        column: ColumnId,
        span: Span,
    },

    /// Literal constant.
    Lit { value: Lit, span: Span },

    /// Binary operator, typed via the closed [`BinOpKind`].
    /// The `String → typed` conversion happens once at lowering;
    /// consumers match the taxonomy and never restringify. Pattern-match
    /// operators (`LIKE` / `ILIKE` / `RLIKE` / `SIMILAR TO`) are NOT
    /// here — they are the dedicated [`ScalarExpr::Like`] variant.
    BinOp {
        op: BinOpKind,
        left: Box<ScalarExpr>,
        right: Box<ScalarExpr>,
        span: Span,
    },

    /// N-ary `AND` / `OR` run, mirroring `AstExpr::LogicalChain`.
    /// The parser already flattens long same-operator
    /// chains; keeping them flat here is what bounds walk depth at
    /// `O(1)` instead of `O(operands)`.
    ///
    /// Consumers must treat this as the N-way generalisation of
    /// [`ScalarExpr::BinOp`] with [`BinOpKind::And`] / [`BinOpKind::Or`]
    /// — short chains still lower to `BinOp`, so both spellings of the
    /// same connective reach every walk. `operands` is in source order
    /// and never shorter than 2.
    LogicalChain {
        op: LogicalOp,
        operands: Vec<ScalarExpr>,
        span: Span,
    },

    /// Unary operator. `op` is a closed-enum classification of the
    /// surface-level operator that the parser produced; see
    /// [`UnaryOpKind`] for the variant set. Typed so consumers
    /// pattern-match the taxonomy instead of
    /// `op.eq_ignore_ascii_case("…")`.
    UnaryOp {
        op: UnaryOpKind,
        arg: Box<ScalarExpr>,
        span: Span,
    },

    /// Function call with resolved function identity.
    ///
    /// The argument list is split:
    /// - `args` — positional arguments, in source order.
    /// - `named_args` — named (`x => 1`) or dialect-aliased
    ///   (`@x AS style`) arguments. Both spellings normalize into the
    ///   same [`IdentKey`](crate::context::node_metadata::IdentKey)-keyed list here; the name is part of the
    ///   call's identity for overload resolution.
    ///
    /// Lambda arguments (`x -> x + 1`) are not a separate slot: they
    /// ride in `args` as [`ScalarExpr::Lambda`] values.
    FuncCall {
        func: super::plan::ResolvedFunc,
        args: Vec<ScalarExpr>,
        named_args: Vec<(crate::context::node_metadata::IdentKey, ScalarExpr)>,
        distinct: bool,
        span: Span,
    },

    /// `CASE … WHEN … THEN … ELSE … END`. `operand` is `Some` for simple CASE.
    Case {
        operand: Option<Box<ScalarExpr>>,
        branches: Vec<(ScalarExpr, ScalarExpr)>,
        else_: Option<Box<ScalarExpr>>,
        span: Span,
    },

    Cast {
        expr: Box<ScalarExpr>,
        target_type: SqlType,
        try_cast: bool,
        span: Span,
    },

    InList {
        expr: Box<ScalarExpr>,
        list: Vec<ScalarExpr>,
        negated: bool,
        span: Span,
    },

    Between {
        expr: Box<ScalarExpr>,
        low: Box<ScalarExpr>,
        high: Box<ScalarExpr>,
        negated: bool,
        span: Span,
    },

    /// `<expr> [NOT] {LIKE | ILIKE | RLIKE | SIMILAR TO} <pattern>
    /// [ESCAPE <escape>]`. Lifted out of `BinOp` so that —
    /// like [`InList`](Self::InList), [`Between`](Self::Between), and [`Exists`](Self::Exists) — negation is a typed
    /// `negated: bool` rather than a string prefix, and the `ESCAPE`
    /// operand is a first-class field rather than a synthetic wrapper
    /// `BinOp`. Column-flow analyses recurse into `expr`, `pattern`, and
    /// `escape` exactly as they recursed into a `BinOp`'s operands.
    Like {
        kind: LikeKind,
        negated: bool,
        expr: Box<ScalarExpr>,
        pattern: Box<ScalarExpr>,
        escape: Option<Box<ScalarExpr>>,
        span: Span,
    },

    /// `EXISTS (subquery)`. `correlates_with` names the outer columns the
    /// subquery references, so analyses can treat a non-correlated subquery
    /// as a constant-wrt-row expression.
    Exists {
        subquery: Box<RelPlan>,
        correlates_with: Vec<ColumnId>,
        negated: bool,
        span: Span,
    },

    /// Scalar subquery in value position.
    ScalarSubquery {
        subquery: Box<RelPlan>,
        correlates_with: Vec<ColumnId>,
        span: Span,
    },

    /// `x = ANY (subquery)`, `x < ALL (list)`, `x [NOT] IN (subquery)`,
    /// etc. The comparison operator is typed via [`ComparisonOp`]
    /// (closed enum). `negated` carries surface-level negation
    /// — `NOT IN (subq)` lowers to `{ op: Eq, quantifier: Any,
    /// negated: true, .. }` directly; the lowerer never wraps in
    /// `UnaryOp(Not, …)` for the canonical NOT-IN shape. This mirrors
    /// the `negated: bool` field on [`InList`](Self::InList), [`Between`](Self::Between), and
    /// [`Exists`](Self::Exists).
    QuantifiedCmp {
        op: ComparisonOp,
        quantifier: Quantifier,
        negated: bool,
        left: Box<ScalarExpr>,
        /// Either a subquery or a value list.
        right: QuantifiedRhs,
        span: Span,
    },

    /// Window-function invocation at scalar position. The [`WindowCall`] owns
    /// the partition/order/frame; the scalar expression just references it.
    WindowFn { call: Box<WindowCall>, span: Span },

    /// Semi-structured field access: `payload:a.b[2]::INT`.
    FieldAccess {
        base: Box<ScalarExpr>,
        path: Vec<FieldStep>,
        /// Optional cast attached via `::TYPE`.
        cast: Option<SqlType>,
        span: Span,
    },

    /// Lambda expression: `x -> x + 1`, `(x, i) -> x * i`. Appears in
    /// higher-order function arguments such as Snowflake's
    /// `FILTER(arr, x -> x > 5)` or BigQuery's `ARRAY_TRANSFORM`. The
    /// lambda binds its `params` to fresh [`ColumnId`]s visible only
    /// inside `body`; outside the body those ids are out of scope.
    Lambda {
        /// Parameters in source order. Each parameter is bound to a
        /// fresh [`ColumnId`] by the lowerer and `body` is lowered
        /// with that binding in scope. A single-parameter lambda has
        /// `params.len() == 1`.
        params: Vec<LambdaParam>,
        body: Box<ScalarExpr>,
        /// Full span from the first parameter to the end of the body.
        span: Span,
    },

    /// Reference to an input column qualified by a MATCH_RECOGNIZE
    /// pattern variable. Only legal inside the MEASURES / DEFINE
    /// expressions of a single `RelPlan::MatchRecognize` node;
    /// `symbol` indexes that node's `SymbolTable`.
    ///
    /// For column-flow analyses (lineage, nullability, taint,
    /// constraints, expression-fact projection) treat this exactly
    /// like [`ScalarExpr::Column { column }`] — the symbol is
    /// metadata that pattern-aware analyses may consult, not a
    /// data-flow modifier.
    PatternVarRef {
        symbol: super::plan::SymbolId,
        column: ColumnId,
        span: Span,
    },

    /// Parser recovery placeholder — an expression position the parser could
    /// not structure, preserved as a raw span for faithful formatting.
    Opaque { span: Span, reason: String },
}

/// One parameter of a [`ScalarExpr::Lambda`]. Carries the source-level
/// identifier (for diagnostics) and the fresh [`ColumnId`] the body
/// may reference.
#[derive(Debug, Clone)]
pub struct LambdaParam {
    pub name: crate::context::node_metadata::IdentKey,
    pub id: ColumnId,
    pub span: Span,
}

/// Quantifier on a comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Quantifier {
    Any, // or SOME
    All,
}

/// Right-hand side of a quantified comparison.
#[derive(Debug, Clone)]
pub enum QuantifiedRhs {
    Subquery(Box<RelPlan>, Vec<ColumnId>),
    List(Vec<ScalarExpr>),
}

/// Typed classification of `ScalarExpr::UnaryOp.op`. Closed;
/// every variant the lowerer emits has a dedicated kind.
///
/// Variants enumerate the COMPLETE set emitted by `src/ir/lower.rs`:
///
/// - `Not` — `BinaryOperator::Not` produced by the parser (prefix `NOT`).
/// - `Neg` / `Plus` — unary arithmetic.
/// - `IsNull` / `IsNotNull` — `IS [NOT] NULL` postfix.
/// - `AtLocal` — Snowflake / T-SQL `AT LOCAL` on timestamps.
/// - `Collate` — `x COLLATE 'collation_name'`.
/// - `Prior` — Oracle hierarchical `CONNECT BY PRIOR`.
/// - `Spread` — Snowflake `**` spread operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UnaryOpKind {
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

impl UnaryOpKind {
    /// Surface-level SQL spelling — round-trip for
    /// [`crate::context::node_metadata::PredicateFact::operator`]
    /// string output and for [`crate::ir::pretty`] display.
    /// Closed-enum exhaustive; adding a variant fails compilation here.
    pub fn as_sql_str(self) -> &'static str {
        match self {
            Self::Not => "NOT",
            Self::Neg => "-",
            Self::Plus => "+",
            Self::IsNull => "IS NULL",
            Self::IsNotNull => "IS NOT NULL",
            Self::AtLocal => "AT LOCAL",
            Self::Collate => "COLLATE",
            Self::Prior => "PRIOR",
            Self::Spread => "**",
        }
    }
}

impl std::fmt::Display for UnaryOpKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_sql_str())
    }
}

/// Connective of a [`ScalarExpr::LogicalChain`]. Closed — a chain node
/// admits exactly the two associative boolean connectives, so this is
/// deliberately narrower than [`BinOpKind`] rather than a reuse of its
/// `And` / `Or` variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LogicalOp {
    And,
    Or,
}

impl LogicalOp {
    /// Surface-level SQL spelling. Closed-enum exhaustive.
    pub fn as_sql_str(self) -> &'static str {
        match self {
            Self::And => "AND",
            Self::Or => "OR",
        }
    }

    /// The two-operand [`BinOpKind`] spelling of the same connective.
    /// Lets a consumer route a chain through logic already keyed on
    /// `BinOpKind` without restating the taxonomy.
    pub fn as_bin_op(self) -> BinOpKind {
        match self {
            Self::And => BinOpKind::And,
            Self::Or => BinOpKind::Or,
        }
    }
}

impl std::fmt::Display for LogicalOp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_sql_str())
    }
}

/// Typed classification of `ScalarExpr::QuantifiedCmp.op`. Closed —
/// covers the six comparison operators a SQL quantified
/// comparison can syntactically take (`x = ANY (...)`,
/// `x <> ALL (...)`, etc.). Arithmetic / logical / pattern operators
/// are NOT representable here because they're never valid as the
/// comparison head of a quantified subquery.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ComparisonOp {
    Eq,
    NotEq,
    Lt,
    LtEq,
    Gt,
    GtEq,
}

impl ComparisonOp {
    /// Surface-level SQL spelling. Closed-enum exhaustive.
    pub fn as_sql_str(self) -> &'static str {
        match self {
            Self::Eq => "=",
            Self::NotEq => "<>",
            Self::Lt => "<",
            Self::LtEq => "<=",
            Self::Gt => ">",
            Self::GtEq => ">=",
        }
    }
}

impl std::fmt::Display for ComparisonOp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_sql_str())
    }
}

/// Typed classification of `ScalarExpr::BinOp.op`. Closed; the
/// `String → typed` conversion happens once at lowering.
///
/// Comparison operators nest the existing closed [`ComparisonOp`] via
/// [`BinOpKind::Cmp`] so the taxonomy is shared with
/// [`ScalarExpr::QuantifiedCmp`]. Pattern-match operators
/// (`LIKE`/`ILIKE`/`RLIKE`/`SIMILAR TO`) are NOT representable here —
/// they lower to the dedicated [`ScalarExpr::Like`] variant. The
/// prefix-`NOT` operator is not here either; it lowers to
/// [`UnaryOpKind::Not`] or a negated [`ScalarExpr::QuantifiedCmp`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BinOpKind {
    // Arithmetic
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    // Comparison (shares the closed taxonomy with QuantifiedCmp)
    Cmp(ComparisonOp),
    // Null-safe comparison
    IsDistinctFrom,
    IsNotDistinctFrom,
    // Logical connectives
    And,
    Or,
    // String concatenation vs MySQL logical-or spelling (both `||`)
    Concat,
    LogicalOr,
    // `expr AT TIME ZONE zone`
    AtTimeZone,
    // PostgreSQL geometric
    Distance,
    // PostgreSQL array
    ArrayContains,
    ArrayContainedBy,
    ArrayOverlap,
    // PostgreSQL JSON
    JsonField,
    JsonFieldText,
    JsonPath,
    JsonPathText,
    JsonContains,
    JsonExists,
    // PostgreSQL regex operators
    RegexMatch,
    RegexMatchI,
    RegexNotMatch,
    RegexNotMatchI,
    // Bitwise
    Shl,
    Shr,
    BitXor,
    BitXorPg,
}

impl BinOpKind {
    /// Surface-level SQL spelling. Closed-enum exhaustive; used for the
    /// [`crate::context::node_metadata::PredicateFact::operator`]
    /// round-trip and for [`crate::ir::pretty`] display.
    pub fn as_sql_str(self) -> &'static str {
        match self {
            Self::Add => "+",
            Self::Sub => "-",
            Self::Mul => "*",
            Self::Div => "/",
            Self::Mod => "%",
            Self::Cmp(c) => c.as_sql_str(),
            Self::IsDistinctFrom => "IS DISTINCT FROM",
            Self::IsNotDistinctFrom => "IS NOT DISTINCT FROM",
            Self::And => "AND",
            Self::Or => "OR",
            Self::Concat => "||",
            Self::LogicalOr => "||",
            Self::AtTimeZone => "AT TIME ZONE",
            Self::Distance => "<->",
            Self::ArrayContains => "@>",
            Self::ArrayContainedBy => "<@",
            Self::ArrayOverlap => "&&",
            Self::JsonField => "->",
            Self::JsonFieldText => "->>",
            Self::JsonPath => "#>",
            Self::JsonPathText => "#>>",
            Self::JsonContains => "@?",
            Self::JsonExists => "??",
            Self::RegexMatch => "~",
            Self::RegexMatchI => "~*",
            Self::RegexNotMatch => "!~",
            Self::RegexNotMatchI => "!~*",
            Self::Shl => "<<",
            Self::Shr => ">>",
            Self::BitXor => "^",
            Self::BitXorPg => "#",
        }
    }
}

impl std::fmt::Display for BinOpKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_sql_str())
    }
}

/// Pattern-match operator carried by [`ScalarExpr::Like`]. Closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LikeKind {
    Like,
    ILike,
    RLike,
    SimilarTo,
}

impl LikeKind {
    /// Surface-level SQL spelling of the match keyword (without any
    /// leading `NOT`, which is carried by `ScalarExpr::Like.negated`).
    pub fn as_sql_str(self) -> &'static str {
        match self {
            Self::Like => "LIKE",
            Self::ILike => "ILIKE",
            Self::RLike => "RLIKE",
            Self::SimilarTo => "SIMILAR TO",
        }
    }

    /// Map a source keyword (already trimmed and uppercased at the
    /// lowering boundary) to a typed kind. The parser only produces
    /// `LIKE` / `ILIKE` / `RLIKE` for `AstExpr::Like`; anything else
    /// is the standard `LIKE`.
    pub fn from_keyword(kw: &str) -> Self {
        match kw {
            "ILIKE" => Self::ILike,
            "RLIKE" => Self::RLike,
            "SIMILAR TO" => Self::SimilarTo,
            _ => Self::Like,
        }
    }
}

impl std::fmt::Display for LikeKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_sql_str())
    }
}

/// One step in a semi-structured path.
///
/// `FieldStep` is the **source-faithful** representation kept on
/// [`ScalarExpr::FieldAccess`]. The formatter, pretty-printer, and
/// [`crate::ir::expression_fact::ExpressionFact`](crate::context::node_metadata::ExpressionFact) accessor string
/// consume this directly. Identifier-keyed analysis maps consume
/// [`FieldPath`] (a derived projection) instead.
#[derive(Debug, Clone)]
pub enum FieldStep {
    /// `payload:foo` — dot/colon field lookup. Name kept as written (quoting
    /// distinguishes case-sensitivity per Snowflake rules).
    Field(String),
    /// `payload[2]` — array index.
    Index(i64),
    /// `payload[expr]` — array index via expression.
    IndexExpr(Box<ScalarExpr>),
}

/// One segment of a [`FieldPath`].
///
/// Closed enum.
///
/// Distinguished from [`FieldStep`]:
/// - `FieldStep` is source-faithful (raw quoted string, full
///   sub-expression for dynamic indexes); preserves bytes for the
///   formatter and pretty-printer.
/// - `FieldPathSegment` is the *projection* used as a map key by
///   the four IR analyses (lineage, taint, constraints,
///   nullability). Field names normalize through [`IdentKey`](crate::context::node_metadata::IdentKey) so
///   case folding is consistent with every other identifier-keyed
///   map; dynamic indexes collapse to a single [`Self::Dynamic`]
///   token.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FieldPathSegment {
    /// Static field selector, identifier-key normalized.
    Field(crate::context::node_metadata::IdentKey),
    /// Static array index.
    Index(i64),
    /// Dynamic index (`payload[idx_expr]`) — analyses treat path
    /// lookup at or beyond a `Dynamic` segment as the conservative
    /// whole-prefix fact.
    Dynamic,
}

/// Path projection over [`ScalarExpr::FieldAccess`].
///
/// `FieldPath::empty()` represents the whole base column —
/// `ColumnId`-keyed analysis facts are equivalent to
/// `(ColumnId, FieldPath::empty())` entries. Non-empty paths describe
/// sub-structure facts.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct FieldPath(Vec<FieldPathSegment>);

impl FieldPath {
    /// The empty path. Equivalent to "the whole base column".
    pub fn empty() -> Self {
        Self(Vec::new())
    }

    /// Project a sequence of source-faithful [`FieldStep`]s into a
    /// path key. Dynamic-index segments collapse to
    /// [`FieldPathSegment::Dynamic`]; everything past a `Dynamic`
    /// segment is still recorded so the path length is preserved
    /// for prefix comparisons (e.g. `payload[expr]:"id"` keeps
    /// the `:"id"` tail).
    pub fn from_field_steps(steps: &[FieldStep]) -> Self {
        let mut out = Vec::with_capacity(steps.len());
        for step in steps {
            out.push(match step {
                FieldStep::Field(name) => {
                    FieldPathSegment::Field(crate::context::node_metadata::IdentKey::new(name))
                }
                FieldStep::Index(i) => FieldPathSegment::Index(*i),
                FieldStep::IndexExpr(_) => FieldPathSegment::Dynamic,
            });
        }
        Self(out)
    }

    /// True iff the path has no segments.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Number of segments.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Read-only view of segments.
    pub fn segments(&self) -> &[FieldPathSegment] {
        &self.0
    }

    /// Take the first `n` segments as a fresh path. Saturates at
    /// [`FieldPath::len`] (i.e. `prefix(len()) == self.clone()`,
    /// `prefix(0) == empty()`). Used by analyses that emit one
    /// fact per ancestor of a path-keyed assertion (e.g.
    /// `IS NOT NULL` on `payload:"a":"b"` implies the same on
    /// `payload`, `payload:"a"`, and `payload:"a":"b"`).
    pub fn prefix(&self, n: usize) -> Self {
        let take = n.min(self.0.len());
        Self(self.0[..take].to_vec())
    }

    /// True iff `self` is a (non-strict) prefix of `other`.
    ///
    /// Prefix semantics:
    /// - The empty path is a prefix of every path (whole-base
    ///   facts cover sub-paths).
    /// - A path is a prefix of itself.
    /// - A path containing a `Dynamic` segment is treated
    ///   conservatively at that position: it matches any concrete
    ///   segment in `other` at that position, so a constraint over
    ///   `payload[expr]` is treated as covering `payload[5]` (the
    ///   dynamic could have selected it).
    pub fn is_prefix_of(&self, other: &Self) -> bool {
        if self.0.len() > other.0.len() {
            return false;
        }
        for (s, o) in self.0.iter().zip(other.0.iter()) {
            match (s, o) {
                (FieldPathSegment::Dynamic, _) | (_, FieldPathSegment::Dynamic) => {
                    // Dynamic on either side: conservatively match.
                }
                (FieldPathSegment::Field(a), FieldPathSegment::Field(b)) if a == b => {}
                (FieldPathSegment::Index(a), FieldPathSegment::Index(b)) if a == b => {}
                (FieldPathSegment::Field(_), _) | (FieldPathSegment::Index(_), _) => return false,
            }
        }
        true
    }

    /// True iff this path contains a [`FieldPathSegment::Dynamic`].
    /// Useful for analyses that want to widen to whole-base when
    /// the path is not concrete.
    pub fn has_dynamic(&self) -> bool {
        self.0
            .iter()
            .any(|s| matches!(s, FieldPathSegment::Dynamic))
    }

    /// Append `suffix`'s segments after `self`'s. Used by lineage
    /// path-composition: when a lineage source
    /// at path `p` is read through an outer `FieldAccess` of path
    /// `q`, the resulting source's path is `p ++ q`.
    ///
    /// This is associative; `compose(p, empty()) == p` and
    /// `compose(empty(), p) == p`.
    pub fn extend(&self, suffix: &FieldPath) -> Self {
        if suffix.0.is_empty() {
            return self.clone();
        }
        if self.0.is_empty() {
            return suffix.clone();
        }
        let mut out = Vec::with_capacity(self.0.len() + suffix.0.len());
        out.extend(self.0.iter().cloned());
        out.extend(suffix.0.iter().cloned());
        Self(out)
    }
}

/// Literal value.
///
/// Intentionally coarse: numeric and temporal values carry their
/// raw source text, not decoded values. That decoding is catalog-dependent.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Lit {
    Null,
    Bool(bool),
    Integer(String),
    Float(String),
    /// Single-quoted string literal, raw.
    Str(String),
    /// `X'...'` or `B'...'` etc. The leading tag is preserved.
    Bytes {
        tag: String,
        value: String,
    },
    /// `DATE '2024-01-01'` etc. The leading type keyword is preserved.
    Typed {
        type_name: String,
        value: String,
    },
    /// Snowflake variant literals: `PARSE_JSON('...')` lowered here.
    Variant(String),
}

impl ScalarExpr {
    /// Source span.
    pub fn span(&self) -> Span {
        match self {
            ScalarExpr::Column { span, .. }
            | ScalarExpr::OuterRef { span, .. }
            | ScalarExpr::Lit { span, .. }
            | ScalarExpr::BinOp { span, .. }
            | ScalarExpr::LogicalChain { span, .. }
            | ScalarExpr::UnaryOp { span, .. }
            | ScalarExpr::FuncCall { span, .. }
            | ScalarExpr::Case { span, .. }
            | ScalarExpr::Cast { span, .. }
            | ScalarExpr::InList { span, .. }
            | ScalarExpr::Between { span, .. }
            | ScalarExpr::Like { span, .. }
            | ScalarExpr::Exists { span, .. }
            | ScalarExpr::ScalarSubquery { span, .. }
            | ScalarExpr::QuantifiedCmp { span, .. }
            | ScalarExpr::WindowFn { span, .. }
            | ScalarExpr::FieldAccess { span, .. }
            | ScalarExpr::Lambda { span, .. }
            | ScalarExpr::PatternVarRef { span, .. }
            | ScalarExpr::Opaque { span, .. } => *span,
        }
    }
}
