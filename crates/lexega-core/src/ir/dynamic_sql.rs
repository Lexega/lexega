// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! IR-side carrier for dynamic-SQL execution call sites.
//!
//! Unifies dynamic-SQL surfaces across dialects under a single typed
//! carrier the DYNSQL-* rule family predicates against. Each carrier
//! exposes three orthogonal axes:
//!
//! - `surface`   — which dialect / statement form is the dynamic-SQL
//!   call (Snowflake/BQ/Databricks `EXECUTE IMMEDIATE`, MSSQL `EXEC`
//!   and `sp_executesql`, PG/MySQL `PREPARE`+`EXECUTE`, PG
//!   `dblink_exec` function call).
//! - `argument` — the structural shape of the SQL-being-executed
//!   expression (literal / variable / `||`-concat / `FORMAT()` /
//!   complex). Only meaningful when the AST exposes the argument
//!   as a typed `AstExpr` — span-only surfaces (MSSQL EXEC args,
//!   `dblink_exec` arg) classify as `Unknown`.
//! - `parameterization` — whether the surface binds runtime values
//!   via a typed parameter mechanism (`USING (a, b)` for Snowflake/
//!   BigQuery, `@params, @p=@x` for `sp_executesql`). When the
//!   surface does not expose parameterization (`EXEC(@sql)`,
//!   `dblink_exec`), the value is `NotApplicable`.
//!
//! All variant sets are **closed enums** — adding a new dynamic-SQL
//! surface or a new arg-shape forces a deliberate variant addition.

use crate::ast::{AstExpr, BinaryOperator, NodeId};
use crate::context::node_metadata::IdentKey;
use crate::ir::plan::{RelPlan, ResolvedFunc};
use crate::ir::scalar::ScalarExpr;
use crate::ir::visitor::{walk_rel_plan, walk_scalar_expr, RelPlanVisitor};
use crate::lexer::token::Span;

/// Structural projection of a single dynamic-SQL call site.
#[derive(Debug, Clone)]
pub struct DynamicSqlCallIr {
    pub surface: DynamicSqlSurfaceIr,
    pub argument: DynamicSqlArgIr,
    /// Where unresolved/untrusted operands land in the assembled
    /// dynamic-SQL string, each tagged by syntactic position and the
    /// quoter wrapping it. Empty for span-only surfaces and surfaces not
    /// yet wired for splice recovery.
    pub splices: Vec<SpliceClass>,
    pub parameterization: DynamicSqlParameterizationIr,
    /// The parameter of the enclosing routine the argument is: written
    /// alone (`@sql`, `:q`, `q`), as the argument writes it, or held by
    /// the variable the argument writes alone, a copy of the caller's
    /// text ([`crate::facts::reasoning::DynamicSqlClassifier::argument_parameter`]).
    pub argument_parameter: Option<String>,
    pub node_id: NodeId,
    /// Span of the entire dynamic-SQL call statement / expression.
    pub source_span: Span,
    /// Span of the SQL-being-executed argument expression — when
    /// available, this is the witness location for DYNSQL-CONCAT /
    /// DYNSQL-NO-PARAM findings. `None` for span-only surfaces
    /// (MSSQL EXEC, `dblink_exec`) where the argument is parsed as
    /// a raw span on the AST and an inner expression node is not
    /// available.
    pub argument_span: Option<Span>,
    /// Inter-procedural provenance: when this call IS the call site
    /// (not the inner sink), the chain of spans from the caller's
    /// tainting assignment through the call to the callee's sink.
    /// Empty for direct (intra-procedural) findings; populated by
    /// the inter-procedural summary engine when it
    /// synthesizes a finding at an `EXEC <named_proc>` / `CALL` site
    /// whose summary `param_inflow` connects a tainted call-arg to
    /// a body-side sink.
    pub provenance: Vec<TaintWitnessSpan>,
}

/// Structural projection of a Snowflake `EXECUTE IMMEDIATE FROM` statement.
///
/// Distinct from [`DynamicSqlCallIr`]: that carrier models an inline SQL
/// string whose injection risk is its argument shape. `EXECUTE IMMEDIATE
/// FROM` instead executes SQL loaded from a stage file — the recognition
/// surface is *where the code comes from* (stage path vs relative path) and
/// whether it actually runs (`DRY_RUN`), not a string shape.
#[derive(Debug, Clone)]
pub struct ExecuteImmediateFromIr {
    pub location_kind: EifLocationKindIr,
    /// The file-location text: the `@…` stage path, or the dequoted relative
    /// path. Case preserved (paths are case-sensitive; the stage name segment
    /// is what callers may match against).
    pub location: Option<String>,
    /// Whether the statement executes (recognition: `DRY_RUN` is not `TRUE`).
    /// `DRY_RUN = TRUE` renders the template without running it.
    pub executes: bool,
    /// `DRY_RUN = { TRUE | FALSE }` value when the clause is present.
    pub dry_run: Option<bool>,
    /// `USING` template-variable key names (lower-cased), in source order.
    pub using_keys: Vec<String>,
    pub node_id: NodeId,
    pub source_span: Span,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EifLocationKindIr {
    /// `@[<namespace>.]<stage>/<path>/<file>` absolute stage path.
    StagePath,
    /// Quoted relative path resolved against the executing file's stage.
    RelativePath,
}

/// Lower a typed [`crate::ast::AstExecuteImmediateFrom`] into an
/// [`ExecuteImmediateFromIr`].
pub fn lower_execute_immediate_from(
    s: &crate::ast::AstExecuteImmediateFrom,
    source: &str,
) -> ExecuteImmediateFromIr {
    use crate::ast::AstEifLocationKind;
    let location_kind = match s.location_kind {
        AstEifLocationKind::StagePath => EifLocationKindIr::StagePath,
        AstEifLocationKind::RelativePath => EifLocationKindIr::RelativePath,
    };
    let location = crate::ir::utils::slice_span(source, s.location_span).map(|t| {
        // A relative path is a string literal (`'…'` / `$$…$$`); a stage
        // path is bare.
        match location_kind {
            EifLocationKindIr::RelativePath => crate::ir::span_extract::literal_value_or_text(t),
            EifLocationKindIr::StagePath => t.trim().to_string(),
        }
    });
    let using_keys = s
        .using_keys
        .iter()
        .filter_map(|sp| crate::ir::utils::slice_span(source, *sp))
        .map(|t| t.trim().to_ascii_lowercase())
        .collect();
    ExecuteImmediateFromIr {
        location_kind,
        location,
        // DRY_RUN absent ⇒ executes; DRY_RUN = FALSE ⇒ executes; only TRUE
        // suppresses execution.
        executes: s.dry_run != Some(true),
        dry_run: s.dry_run,
        using_keys,
        node_id: s.node_id,
        source_span: s.span,
    }
}

/// One link in a taint provenance chain: a source-location witness
/// tagged by its role. Surfaced through the facts projection so YAML
/// rules and report renderers can pull the chain into the finding
/// output.
///
/// **Role sequence patterns** (tested via `assert_provenance_roles`):
/// - Pure intra-procedural (rare on this carrier): `[Sink]` or `[Assignment, Sink]`.
/// - Inter-procedural, no caller-side laundering: `[CallSite, Sink]`.
/// - Inter-procedural, caller-side concat: `[Assignment, CallSite, Sink]`.
/// - Multi-hop call chains: `[Assignment, CallSite, CallSite, …, Sink]`.
#[derive(Debug, Clone, Copy)]
pub struct TaintWitnessSpan {
    pub span: Span,
    pub role: TaintWitnessRole,
}

/// Discriminator for a [`TaintWitnessSpan`]'s position in the
/// provenance chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TaintWitnessRole {
    /// The `SET @x = '...' + @input` assignment that introduced
    /// taint.
    Assignment,
    /// The `EXEC outer_proc @x` / `CALL outer(@x)` call site that
    /// crossed a procedure boundary.
    CallSite,
    /// The `EXEC sp_executesql @s` (or equivalent) inside the callee
    /// where dynamic SQL actually runs.
    Sink,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DynamicSqlSurfaceIr {
    /// Snowflake / BigQuery / Databricks `EXECUTE IMMEDIATE <expr>
    /// [USING (args)]`.
    ExecuteImmediate,
    /// T-SQL `EXEC(@sql)` (parenthesized dynamic-SQL form).
    MssqlExecDynamic,
    /// T-SQL `EXEC <proc> [args]` where `<proc>` is `sp_executesql`
    /// — parameter-bindable dynamic-SQL surface.
    MssqlSpExecutesql,
    /// PostgreSQL / MySQL `PREPARE <name> FROM <expr>`. The matched
    /// `EXECUTE` runs the prepared statement (not a separate
    /// dynamic-SQL surface, though it does carry parameter binding
    /// via `USING`).
    Prepare,
    /// A function that sends SQL text to another server to run, as the
    /// dialect's table of its routines says (`dblink_exec(<connstr>,
    /// <sql>)`, `OPENQUERY`): it executes in a remote server's auth context.
    DblinkExec,
    /// Synthesized at a T-SQL `EXEC <named_proc> args` call site
    /// when the procedure-summary engine resolves the callee to a
    /// summary with non-empty `param_inflow` — i.e., the callee
    /// body's dynamic-SQL sink is reachable from a parameter, and
    /// the matching caller-side argument is tainted. The actual
    /// dynamic-SQL sink lives inside the callee; this surface
    /// witnesses the call-site that drove the inter-procedural
    /// flow. Provenance carries the call-and-sink chain.
    MssqlExecProcCall,
    /// Dialect-neutral counterpart to [`Self::MssqlExecProcCall`]
    /// for `CALL <proc>(args)` (Snowflake / BigQuery / PostgreSQL /
    /// MySQL / Databricks).
    CallProcCall,
    /// psql's `\gexec`: each value the query before it returns runs as a
    /// statement, text the script does not hold.
    PsqlGexec,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DynamicSqlArgIr {
    /// Pure string literal: `'CREATE TABLE t (…)'`. No runtime input
    /// flows through this surface.
    Literal,
    /// Single variable reference (`v_sql`, `:stmt`, `@sql`). Runtime
    /// content unknowable at parse time.
    Variable,
    /// String concatenation: `||` (Snowflake/PG), `+` (MSSQL), or
    /// `CONCAT(...)` function call. The canonical SQL-injection
    /// construction vector.
    Concat,
    /// A `||`/`+`/`CONCAT()` concatenation that is BOTH (a) built only
    /// from string literals and dialect-recognized quoting calls
    /// (`quote_ident`/`quote_literal`/`quote_nullable`, `QUOTENAME`,
    /// `QUOTE`, or a clean `FORMAT()`), AND (b) whose assembled skeleton
    /// parses to a single statement. No raw value reaches a slot it can
    /// break out of, and no second statement is smuggled in via a literal
    /// fragment — so it is injection-clean. A single raw/unrecognized
    /// operand, or a multi-statement assembly, demotes the whole tree back
    /// to [`Self::Concat`]. Recognized structurally; the verdict is the
    /// YAML rule's.
    ConcatQuoted,
    /// Argument built via a SQL-template `FORMAT(...)` whose
    /// interpolation is NOT provably quoting — a raw `%s`, a computed
    /// (non-literal) template, or an unrecognized placeholder spec. The
    /// runtime value can break out of its slot.
    Format,
    /// `FORMAT(...)` over a LITERAL template whose every placeholder is
    /// a quoting specifier (`%I`/`%L`). The interpolated value is quoted
    /// into an identifier/literal slot and cannot break out, so no raw
    /// runtime input reaches the statement structure. Recognized
    /// structurally; the risk verdict (info vs critical) belongs to the
    /// YAML rule, not this enum.
    FormatQuoted,
    /// Anything else (subquery scalar, complex expression).
    /// Surfaces both genuinely-unknown shapes and dialect surfaces
    /// where the argument is parsed as a raw span (MSSQL EXEC,
    /// `dblink_exec`) and not lifted to a typed `AstExpr`.
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DynamicSqlParameterizationIr {
    /// No `USING` / no `@params` declaration. The argument is
    /// executed as-built.
    None,
    /// Positional `USING (a, b, c)` clause (Snowflake / BigQuery /
    /// Databricks / MySQL `EXECUTE … USING`).
    PositionalUsing,
    /// `sp_executesql @sql, N'@p type', @p = expr` — declared
    /// named parameter list.
    NamedParams,
    /// Surface does not expose a parameter-binding mechanism.
    /// Applies to bare MSSQL `EXEC(@sql)` and `dblink_exec`.
    NotApplicable,
}

/// Sanitizer applied to an unresolved operand at the point it is spliced
/// into a dynamic query.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HoleQuoting {
    /// No quoting function — the value is concatenated directly.
    Raw,
    /// An identifier quoter (`QUOTENAME` / `quote_ident` / `%I`).
    IdentQuoter,
    /// A string-literal quoter (`quote_literal` / `QUOTE` / `%L`).
    LitQuoter,
}

/// Where an unresolved operand lands in the assembled dynamic-SQL string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SplicePosition {
    /// Inside a quoted string literal.
    StringLiteral,
    /// A SQL identifier/name slot recovered by fragment-parsing the
    /// skeleton: a table-reference name, a DDL column-definition name, or
    /// an assigned/inserted column name. An identifier quoter is the
    /// correct sanitizer here; a literal quoter is not.
    Identifier,
    /// Outside any string literal and not an identifier slot — a value /
    /// predicate / projection position, or a skeleton that did not
    /// fragment-parse to a single recognized statement. An
    /// expression-position identifier is intentionally left here: a
    /// quoted bare identifier in a value position is a column reference,
    /// not a wrong-context splice, so no mismatch rule applies.
    Bare,
    /// Position could not be determined (the marker was not uniquely
    /// locatable in the assembled skeleton).
    Unknown,
}

/// One recovered splice point: where an operand lands and how it is quoted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpliceClass {
    pub position: SplicePosition,
    pub quoting: HoleQuoting,
}

/// Decides the shape of a string-building dynamic-SQL argument beyond
/// what its syntax shows: whether a concatenation or `FORMAT` template
/// assembles into a single clean statement.
pub trait ShapeRefiner {
    /// Shape of a `||` / `+` / `CONCAT(...)` argument.
    fn concat_shape(&self, expr: &AstExpr, source: &str) -> DynamicSqlArgIr;
    /// Shape of a `FORMAT(template, ...)` argument in a dialect whose
    /// `FORMAT` builds SQL.
    fn format_shape(
        &self,
        args: &[Box<crate::ast::AstFunctionArg>],
        source: &str,
    ) -> DynamicSqlArgIr;
    /// [`Self::concat_shape`] over a lowered expression.
    fn scalar_concat_shape(&self, expr: &ScalarExpr) -> DynamicSqlArgIr;
    /// [`Self::format_shape`] over a lowered call's arguments.
    fn scalar_format_shape(&self, args: &[ScalarExpr]) -> DynamicSqlArgIr;
}

/// Syntax alone: every concatenation is [`DynamicSqlArgIr::Concat`] and
/// every SQL-building `FORMAT` is [`DynamicSqlArgIr::Format`].
pub struct SyntacticShapes;

impl ShapeRefiner for SyntacticShapes {
    fn concat_shape(&self, _expr: &AstExpr, _source: &str) -> DynamicSqlArgIr {
        DynamicSqlArgIr::Concat
    }

    fn format_shape(
        &self,
        _args: &[Box<crate::ast::AstFunctionArg>],
        _source: &str,
    ) -> DynamicSqlArgIr {
        DynamicSqlArgIr::Format
    }

    fn scalar_concat_shape(&self, _expr: &ScalarExpr) -> DynamicSqlArgIr {
        DynamicSqlArgIr::Concat
    }

    fn scalar_format_shape(&self, _args: &[ScalarExpr]) -> DynamicSqlArgIr {
        DynamicSqlArgIr::Format
    }
}

/// Join two argument shapes, keeping the more dangerous one.
///
/// Rank, most to least significant: `Concat`, `Format`, `Variable`,
/// `Unknown`, `ConcatQuoted`, `FormatQuoted`, `Literal`. A value undecided
/// on one path is undecided whatever another path shows: `Unknown` ranks
/// above every shape shown clean. The two resolved-clean shapes rank below
/// it (they are proven to quote) but above a pure `Literal` (they still
/// carry runtime input).
pub fn lattice_join(a: DynamicSqlArgIr, b: DynamicSqlArgIr) -> DynamicSqlArgIr {
    if rank(a) >= rank(b) {
        a
    } else {
        b
    }
}

pub fn rank(x: DynamicSqlArgIr) -> u8 {
    match x {
        DynamicSqlArgIr::Concat => 6,
        DynamicSqlArgIr::Format => 5,
        DynamicSqlArgIr::Variable => 4,
        DynamicSqlArgIr::Unknown => 3,
        DynamicSqlArgIr::ConcatQuoted => 2,
        DynamicSqlArgIr::FormatQuoted => 1,
        DynamicSqlArgIr::Literal => 0,
    }
}

/// Classify the structural shape of an `EXECUTE IMMEDIATE` argument
/// expression. Walks through `Parenthesized` wrappers; recognizes
/// the `||` and `+` concat operators and the `CONCAT` / `CONCAT_WS` /
/// `FORMAT` function call surfaces, as [`text_pieces`] reads them;
/// treats anything more complex as `Unknown` (degrade-gracefully —
/// DYNSQL still fires at the base rule, just not at the
/// severity-distinguishing siblings).
///
/// `FORMAT(...)` maps to [`DynamicSqlArgIr::Format`] only when the
/// dialect of the analysis running on the thread builds SQL with it by
/// template interpolation (PG/Redshift/BigQuery); where it is a
/// value/number formatter (MySQL/T-SQL) the call is opaque and
/// classifies as `Unknown`.
///
/// `source` is the analyzer's full input string — used to read
/// function-name lexemes off the `AstIdentifier` span (the AST
/// stores spans, not interned names).
pub fn classify_execute_immediate_arg(expr: &AstExpr, source: &str) -> DynamicSqlArgIr {
    classify_execute_immediate_arg_with(expr, source, &SyntacticShapes)
}

/// [`classify_execute_immediate_arg`] with the string-building shapes
/// decided by `refine`.
pub fn classify_execute_immediate_arg_with(
    expr: &AstExpr,
    source: &str,
    refine: &dyn ShapeRefiner,
) -> DynamicSqlArgIr {
    let dialect = crate::ir::normalize::dialect_in_force();
    classify_arg_in(expr, source, refine, dialect.as_ref())
}

fn classify_arg_in(
    expr: &AstExpr,
    source: &str,
    refine: &dyn ShapeRefiner,
    dialect: &dyn crate::dialect::Dialect,
) -> DynamicSqlArgIr {
    // An argument nested deeper than the stack lets the analyzer walk is
    // not read: its shape is not known.
    let Some(_frame) = crate::ir::lower::enter_nested() else {
        return DynamicSqlArgIr::Unknown;
    };
    // `||` in Snowflake/PostgreSQL/MySQL-non-default and `+` in T-SQL are
    // string concatenation when both operands are string-shaped, classified
    // by operator identity (arithmetic `+` on a dynamic-SQL argument is
    // exceedingly rare), as are `CONCAT(...)` and `CONCAT_WS(...)`. The
    // refiner decides whether a concatenation is injection-clean
    // (`ConcatQuoted`) or the dangerous `Concat`. The value `REPLACE`
    // rewrites is not known.
    let kind = concatenation_kind(expr.text_node(source), dialect);
    match kind {
        Some(
            ConcatenationKind::Operator | ConcatenationKind::Concat | ConcatenationKind::ConcatWs,
        ) => return refine.concat_shape(expr, source),
        Some(ConcatenationKind::Replace) => return DynamicSqlArgIr::Unknown,
        Some(ConcatenationKind::Format) | None => {}
    }
    match expr {
        AstExpr::Literal { literal, .. } => match literal {
            // A StringWithJinja executed as dynamic SQL carries a dynamic hole:
            // an unrendered `{{ … }}`, or a rendered-placeholder splice the
            // parser promoted here (see promote_placeholder_dynamic_sql_arg).
            // Either way the injected value splices into the executed statement —
            // recognize it as Concat, not a clean Literal. Other literals
            // (String/Number/bool/null) carry no runtime input.
            crate::ast::AstLiteral::StringWithJinja { .. } => DynamicSqlArgIr::Concat,
            // Strings joined as written: a literal text.
            crate::ast::AstLiteral::Adjacent { .. } => DynamicSqlArgIr::Literal,
            crate::ast::AstLiteral::Number { .. }
            | crate::ast::AstLiteral::Money { .. }
            | crate::ast::AstLiteral::String { .. }
            | crate::ast::AstLiteral::Boolean { .. }
            | crate::ast::AstLiteral::Null { .. } => DynamicSqlArgIr::Literal,
        },
        AstExpr::Placeholder { .. } => DynamicSqlArgIr::Variable,
        AstExpr::Ident { .. } => DynamicSqlArgIr::Variable,
        AstExpr::ScriptingVarRef { .. } => DynamicSqlArgIr::Variable,
        AstExpr::SessionVarRef { .. } => DynamicSqlArgIr::Variable,
        // A concatenation returned above; any other operator.
        AstExpr::BinaryOp { .. } | AstExpr::OperatorChain { .. } => DynamicSqlArgIr::Unknown,
        AstExpr::LogicalChain { .. } => DynamicSqlArgIr::Unknown,
        AstExpr::FunctionCall {
            func_name, args, ..
        } => {
            let name = source
                .get(func_name.span.start as usize..func_name.span.end as usize)
                .unwrap_or("");
            if kind == Some(ConcatenationKind::Format) {
                refine.format_shape(args, source)
            } else {
                // A function whose result is one of its arguments
                // ([`CHOOSING_FUNCTIONS`]: `IF`, `IIF`, `COALESCE`, `DECODE`, …):
                // the executed value can be any of them, so join their shapes
                // — a tainted arm dominates a clean one, mirroring the
                // statement branch merge. A condition, test or search is not
                // returned.
                let value_args = chosen(
                    name,
                    args.iter().map(|arg| positional_argument(arg)).collect(),
                );
                match value_args {
                    Some(exprs) => exprs
                        .into_iter()
                        .map(|e| classify_arg_in(e, source, refine, dialect))
                        .reduce(lattice_join)
                        .unwrap_or(DynamicSqlArgIr::Unknown),
                    None => DynamicSqlArgIr::Unknown,
                }
            }
        }
        AstExpr::Case {
            whens, else_expr, ..
        } => {
            // CASE expression: any WHEN result or the ELSE could be the executed
            // value, so join their shapes — a tainted/concat arm dominates a
            // clean one (the conditional-expression analog of the statement
            // branch merge). The operand / WHEN conditions are not part of the
            // executed value.
            whens
                .iter()
                .map(|w| &w.result)
                .chain(else_expr.as_deref())
                .map(|e| classify_arg_in(e, source, refine, dialect))
                .reduce(lattice_join)
                .unwrap_or(DynamicSqlArgIr::Unknown)
        }
        AstExpr::Parenthesized { expr: inner, .. } => {
            classify_arg_in(inner, source, refine, dialect)
        }
        // A value whose shape as SQL text is not read.
        AstExpr::JinjaPlaceholder { .. }
        | AstExpr::DbtRef { .. }
        | AstExpr::DbtSource { .. }
        | AstExpr::DbtVar { .. }
        | AstExpr::DbtConfig { .. }
        | AstExpr::DbtThis { .. }
        | AstExpr::PositionRef { .. }
        | AstExpr::InList { .. }
        | AstExpr::InListOpaque { .. }
        | AstExpr::ExplSnowIdent { .. }
        | AstExpr::InSubquery { .. }
        | AstExpr::ExistsSubquery { .. }
        | AstExpr::Spread { .. }
        | AstExpr::Array { .. }
        | AstExpr::Object { .. }
        | AstExpr::WindowFn { .. }
        | AstExpr::WindowExpr { .. }
        | AstExpr::TvfWithSchema { .. }
        | AstExpr::QuantifiedSubquery { .. }
        | AstExpr::QualifiedStar { .. }
        | AstExpr::UnqualifiedStar { .. }
        | AstExpr::Prior { .. }
        | AstExpr::ConnectByRoot { .. }
        | AstExpr::IsNull { .. }
        | AstExpr::IsPredicate { .. }
        | AstExpr::IsDistinctFrom { .. }
        | AstExpr::Like { .. }
        | AstExpr::SimilarTo { .. }
        | AstExpr::Cast { .. }
        | AstExpr::TryCast { .. }
        | AstExpr::SafeCast { .. }
        | AstExpr::TypeCast { .. }
        | AstExpr::Extract { .. }
        | AstExpr::Position { .. }
        | AstExpr::MatchAgainst { .. }
        | AstExpr::Trim { .. }
        | AstExpr::Substring { .. }
        | AstExpr::Collate { .. }
        | AstExpr::Between { .. }
        | AstExpr::ScalarSubquery { .. }
        | AstExpr::SubqueryArg { .. }
        | AstExpr::RowConstructor { .. }
        | AstExpr::ArraySubscript { .. }
        | AstExpr::ObjectFieldColon { .. }
        | AstExpr::ObjectFieldBracket { .. }
        | AstExpr::ObjectFieldDot { .. }
        | AstExpr::MethodCall { .. }
        | AstExpr::QualifiedStarFromExpr { .. }
        | AstExpr::JinjaConditional { .. }
        | AstExpr::AtTimeZone { .. }
        | AstExpr::TypedStringLiteral { .. }
        | AstExpr::Error { .. } => DynamicSqlArgIr::Unknown,
    }
}

/// One argument of a call (`AstStmt::MssqlExec`, `AstStmt::Call`): how it
/// is written to its parameter, the shape of the text it builds, and where
/// it is written. The parameter a named argument names and the variable an
/// argument passes are read from the argument's expression
/// ([`crate::ast::AstCallArg`]) by [`variable_key`].
#[derive(Debug, Clone)]
pub struct CallArgIr {
    pub kind: CallArgKind,
    pub shape: DynamicSqlArgIr,
    pub span: Span,
}

/// How a call-site argument is written to its parameter.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum CallArgKind {
    /// By position: the argument's index among the call's arguments.
    Positional(usize),
    /// By the parameter's name (T-SQL `EXEC p @x = @v`, Snowflake keyword
    /// arguments, PostgreSQL `CALL p(arg => v)`).
    Named,
}

/// Each argument of a call as a [`CallArgIr`], in order: how it is
/// written to its parameter, and the shape `refine` gives the text it
/// builds.
pub fn classify_call_args(
    args: &[crate::ast::AstCallArg],
    source: &str,
    refine: &dyn ShapeRefiner,
) -> Vec<CallArgIr> {
    let mut out = Vec::with_capacity(args.len());
    for (idx, arg) in args.iter().enumerate() {
        let kind = match &arg.name {
            Some(_) => CallArgKind::Named,
            None => CallArgKind::Positional(idx),
        };
        out.push(CallArgIr {
            kind,
            shape: classify_execute_immediate_arg_with(&arg.value, source, refine),
            span: arg.span,
        });
    }
    out
}

/// Classify the parameterization mode of an `EXECUTE IMMEDIATE`
/// statement. Snowflake / BigQuery / Databricks expose this as a
/// `USING (args)` clause on the AST node.
pub fn classify_execute_immediate_parameterization(
    using_args: &[crate::ast::AstExecuteUsingArg],
    using_span: Option<Span>,
) -> DynamicSqlParameterizationIr {
    if using_span.is_some() || !using_args.is_empty() {
        DynamicSqlParameterizationIr::PositionalUsing
    } else {
        DynamicSqlParameterizationIr::None
    }
}

/// Classify the parameterization mode of a T-SQL `EXEC sp_executesql`
/// call from its structured argument list. The 1-arg form
/// `EXEC sp_executesql @sql;` does not bind any parameters regardless
/// of the surface name; the parameterized form is
/// `EXEC sp_executesql @sql, N'@p type, ...', @p = expr, ...` — the
/// `@params` definition list is the second argument and bound values
/// follow from the third onward.
pub fn classify_sp_executesql_parameterization(
    args: &[crate::ast::AstCallArg],
) -> DynamicSqlParameterizationIr {
    if args.len() >= 2 {
        DynamicSqlParameterizationIr::NamedParams
    } else {
        DynamicSqlParameterizationIr::None
    }
}

/// Is this `EXEC` invoking a system procedure that runs its first argument
/// as SQL text (`sp_executesql`), as T-SQL's table of its system routines
/// says ([`crate::dialect::Dialect::system_routine`])? A name qualified by
/// the place the system procedures are (`sys.sp_executesql`,
/// `master.dbo.sp_executesql`, `db..sp_executesql`, a linked server's) and
/// a bracket-quoted one classify as the same surface; one in a schema of
/// the user's (`app.sp_executesql`) is a procedure of the user's. `false`
/// for the bare dynamic form `EXEC(@sql)`.
pub fn is_sp_executesql(e: &crate::ast::types::AstMssqlExec, source: &str) -> bool {
    use crate::dialect::Dialect;
    e.procedure_name_span.is_some_and(|s| {
        let name = crate::ir::lower::routine_name(
            source.get(s.start as usize..s.end as usize).unwrap_or(""),
        );
        let parts: Vec<&str> = name.iter().map(IdentKey::as_str).collect();
        crate::dialect::MsSqlDialect
            .system_routine(&parts)
            .is_some_and(|routine| {
                routine.forms.iter().any(|form| {
                    form.parameters
                        .first()
                        .is_some_and(|parameter| parameter.reads.runs_sql())
                })
            })
    })
}

/// A statement that runs SQL text ([`sql_run`]).
#[derive(Debug, Clone, Copy)]
pub struct SqlRun<'a> {
    /// The statement form that runs the text.
    pub surface: DynamicSqlSurfaceIr,
    /// The expression whose text runs, as written; `None` where the
    /// statement's argument was not read (a T-SQL `EXEC (…)` whose
    /// argument is not one expression, an `sp_executesql` with none).
    pub sql: Option<&'a AstExpr>,
    /// How the statement binds runtime values to the text it runs.
    pub parameterization: DynamicSqlParameterizationIr,
    /// Where the argument is written.
    pub argument_span: Option<Span>,
    pub node_id: NodeId,
    pub span: Span,
}

/// The SQL text `stmt` runs, where it runs some: `EXECUTE IMMEDIATE <expr>`
/// (and PL/pgSQL's `EXECUTE <expr>`), T-SQL's `EXEC (<expr>)` and `EXEC
/// sp_executesql <expr>`, and MySQL's `PREPARE name FROM <expr>`. `None`
/// for any other statement: an `EXEC` of another procedure is a call, a
/// PostgreSQL `PREPARE name AS <statement>` prepares a statement written in
/// place.
pub fn sql_run<'a>(stmt: &'a crate::ast::AstStmt, source: &str) -> Option<SqlRun<'a>> {
    use crate::ast::AstStmt;
    if let AstStmt::ExecuteImmediate {
        sql_expr,
        using_args,
        using_span,
        node_id,
        span,
        ..
    } = stmt
    {
        Some(SqlRun {
            surface: DynamicSqlSurfaceIr::ExecuteImmediate,
            sql: Some(sql_expr),
            parameterization: classify_execute_immediate_parameterization(using_args, *using_span),
            argument_span: Some(sql_expr.span()),
            node_id: *node_id,
            span: *span,
        })
    } else if let AstStmt::PgPrepare(p) = stmt {
        p.from_expr.as_deref().map(|from_expr| SqlRun {
            surface: DynamicSqlSurfaceIr::Prepare,
            sql: Some(from_expr),
            parameterization: DynamicSqlParameterizationIr::NotApplicable,
            argument_span: Some(from_expr.span()),
            node_id: p.node_id,
            span: p.span,
        })
    } else if let AstStmt::PsqlGexec(gexec) = stmt {
        Some(SqlRun {
            surface: DynamicSqlSurfaceIr::PsqlGexec,
            sql: None,
            parameterization: DynamicSqlParameterizationIr::NotApplicable,
            argument_span: None,
            node_id: gexec.node_id,
            span: gexec.span,
        })
    } else if let AstStmt::MssqlExec(e) = stmt {
        let (surface, parameterization) = match e.procedure_name_span {
            None => (
                DynamicSqlSurfaceIr::MssqlExecDynamic,
                DynamicSqlParameterizationIr::NotApplicable,
            ),
            Some(_) if is_sp_executesql(e, source) => (
                DynamicSqlSurfaceIr::MssqlSpExecutesql,
                classify_sp_executesql_parameterization(&e.args),
            ),
            Some(_) => return None,
        };
        Some(SqlRun {
            surface,
            sql: e.args.first().map(|arg| &arg.value),
            parameterization,
            argument_span: e.args_span,
            node_id: e.node_id,
            span: e.span,
        })
    } else {
        None
    }
}

/// The dynamic-SQL call `run` is, its argument classified by `classifier`;
/// `parameters` are those of the routine whose body makes it.
pub(crate) fn dynamic_sql_call(
    run: &SqlRun<'_>,
    classifier: &dyn crate::facts::reasoning::DynamicSqlClassifier,
    source: &str,
    parameters: &[IdentKey],
) -> DynamicSqlCallIr {
    let (argument, splices, argument_parameter) = match run.sql {
        Some(sql) => (
            classifier.classify_arg(sql, source),
            classifier.classify_arg_splices(sql, source),
            classifier.argument_parameter(sql, source, parameters),
        ),
        None => (DynamicSqlArgIr::Unknown, Vec::new(), None),
    };
    DynamicSqlCallIr {
        surface: run.surface,
        argument,
        splices,
        parameterization: run.parameterization,
        argument_parameter,
        node_id: run.node_id,
        source_span: run.span,
        argument_span: run.argument_span,
        provenance: Vec::new(),
    }
}

/// Push the dynamic-SQL call `stmt` makes onto `calls`, where it runs SQL
/// text ([`sql_run`]); `parameters` are those of the routine whose body
/// holds `stmt`.
pub(crate) fn push_sql_run(
    stmt: &crate::ast::AstStmt,
    calls: &mut Vec<DynamicSqlCallIr>,
    classifier: &dyn crate::facts::reasoning::DynamicSqlClassifier,
    source: &str,
    parameters: &[IdentKey],
) {
    if let Some(run) = sql_run(stmt, source) {
        calls.push(dynamic_sql_call(&run, classifier, source, parameters));
    }
}

/// Push the dynamic-SQL calls of the statements the values `stmt` assigns
/// hold ([`assigned_values`]) onto `calls` (Snowflake `DECLARE res
/// RESULTSET DEFAULT (EXECUTE IMMEDIATE :q)`).
pub(crate) fn push_sql_runs_held_in_values(
    stmt: &crate::ast::AstStmt,
    calls: &mut Vec<DynamicSqlCallIr>,
    classifier: &dyn crate::facts::reasoning::DynamicSqlClassifier,
    source: &str,
    parameters: &[IdentKey],
) {
    for inner in sql_runs_held_in_values(stmt, source) {
        push_sql_run(inner, calls, classifier, source, parameters);
    }
}

/// The statements the values `stmt` assigns hold ([`assigned_values`]):
/// each a dynamic-SQL call where it runs SQL text.
pub fn sql_runs_held_in_values<'a>(
    stmt: &'a crate::ast::AstStmt,
    source: &str,
) -> Vec<&'a crate::ast::AstStmt> {
    assigned_values(stmt, source)
        .into_iter()
        .flat_map(|(_, value)| value.into_iter().flat_map(collect_inner_stmts_from_expr))
        .collect()
}

/// The parameter of `parameters` that `expr` is, written alone (`@sql`,
/// `:q`, `q`), as written; `None` for any other expression. A Snowflake
/// session variable `$q` is no parameter.
pub fn expr_parameter(expr: &AstExpr, source: &str, parameters: &[IdentKey]) -> Option<String> {
    if parameters.is_empty() {
        return None;
    }
    first_written_variable(expr, source, &mut |written| {
        parameters
            .contains(&variable_key(written))
            .then(|| written.to_string())
    })
}

/// What `found` gives of the first variable written in `expr` it gives
/// something of, the variable's name as written: `expr` itself, or one
/// written in it through parentheses, the operands of a concatenation, a
/// conversion, each value a choice may be and the arguments of the
/// functions it calls, whose text a value built so carries
/// (`TextExpr::text_node`). The one reading of where a value's text comes
/// from, whether a statement runs the value or a variable holds it first.
/// A Snowflake session variable `$q` is no variable of a routine's.
pub fn first_written_variable<T>(
    expr: &AstExpr,
    source: &str,
    found: &mut dyn FnMut(&str) -> Option<T>,
) -> Option<T> {
    // An expression nested deeper than the stack lets the analyzer walk is
    // not read.
    let _frame = crate::ir::lower::enter_nested()?;
    match expr.text_node(source) {
        TextNode::Variable {
            name: Some(name),
            session: false,
        } => found(source.get(name.start as usize..name.end as usize)?),
        TextNode::Grouped(inner) | TextNode::Converted(inner) => {
            first_written_variable(inner, source, found)
        }
        TextNode::Joined { operands, .. } => operands
            .into_iter()
            .find_map(|operand| first_written_variable(operand, source, found)),
        TextNode::Call { values, .. } => values
            .into_iter()
            .find_map(|value| first_written_variable(value, source, found)),
        TextNode::Choice(choices) => choices
            .into_iter()
            .find_map(|choice| first_written_variable(choice, source, found)),
        TextNode::String(_)
        | TextNode::Fixed(_)
        | TextNode::Variable { name: None, .. }
        | TextNode::Variable { session: true, .. }
        | TextNode::Other => None,
    }
}

/// The parameters whose names are written at `names`, each keyed as a
/// variable naming it is ([`variable_key`]).
pub(crate) fn parameter_keys(
    names: impl IntoIterator<Item = Option<Span>>,
    source: &str,
) -> Vec<IdentKey> {
    names
        .into_iter()
        .flatten()
        .filter_map(|span| source.get(span.start as usize..span.end as usize))
        .map(variable_key)
        .collect()
}

/// The expression a statement that runs SQL text executes ([`sql_run`]),
/// parentheses around it removed.
fn executed_expr<'a>(stmt: &'a crate::ast::AstStmt, source: &str) -> Option<&'a AstExpr> {
    sql_run(stmt, source)?.sql.map(unparenthesized)
}

/// `expr` with the parentheses around it removed.
pub(crate) fn unparenthesized(mut expr: &AstExpr) -> &AstExpr {
    while let AstExpr::Parenthesized { expr: inner, .. } = expr {
        expr = inner;
    }
    expr
}

/// One node of an expression tree, as [`text_pieces`] reads the text it
/// builds. Both the parsed and the lowered form of an expression are read
/// through it ([`TextExpr`]).
enum TextNode<'a, E: ?Sized> {
    /// A string literal at the span.
    String(Span),
    /// A number, boolean or NULL literal at the span.
    Fixed(Span),
    /// An expression in parentheses.
    Grouped(&'a E),
    /// `||` or `+` (T-SQL's concatenation): the operands, in order. A run
    /// of operators that starts with operators joining no text (`a - b +
    /// c`) is that start's value, at `head`, then the operands joined to it.
    Joined {
        head: Option<Span>,
        operands: Vec<&'a E>,
    },
    /// A call of the function `name`, at `span`: its arguments in order,
    /// `None` for one not written by position; `values` the value of every
    /// argument, however written.
    Call {
        name: &'a str,
        args: Vec<Option<&'a E>>,
        values: Vec<&'a E>,
        span: Span,
    },
    /// A value that is one of these expressions: each result of a `CASE`,
    /// its `ELSE` too, or each argument a function whose value is one of
    /// its arguments may give ([`CHOOSING_FUNCTIONS`]).
    Choice(Vec<&'a E>),
    /// A value converted to another type (`CAST`, `::`, `COLLATE`): its
    /// text is the operand's.
    Converted(&'a E),
    /// A variable, `name` the span naming it where the expression names
    /// one; `session` for a Snowflake session variable `$q`.
    Variable { name: Option<Span>, session: bool },
    /// Any other expression.
    Other,
}

/// An expression tree [`text_pieces`] reads.
trait TextExpr {
    /// This node, its function names read from `source` where the tree
    /// does not hold them.
    fn text_node<'a>(&'a self, source: &'a str) -> TextNode<'a, Self>;

    /// Where the expression is written.
    fn text_span(&self) -> Span;
}

impl TextExpr for AstExpr {
    fn text_span(&self) -> Span {
        self.span()
    }

    fn text_node<'a>(&'a self, source: &'a str) -> TextNode<'a, Self> {
        match self {
            AstExpr::Literal { literal, .. } => match literal {
                crate::ast::AstLiteral::String { span } => TextNode::String(*span),
                // Several strings joined: a value of its own.
                crate::ast::AstLiteral::Adjacent { .. } => TextNode::Other,
                // An unrendered template expression is a value of its own.
                crate::ast::AstLiteral::StringWithJinja { .. } => TextNode::Other,
                crate::ast::AstLiteral::Number { .. }
                | crate::ast::AstLiteral::Money { .. }
                | crate::ast::AstLiteral::Boolean { .. }
                | crate::ast::AstLiteral::Null { .. } => TextNode::Fixed(literal.span()),
            },
            AstExpr::Parenthesized { expr, .. } => TextNode::Grouped(expr),
            AstExpr::BinaryOp {
                left,
                operator: BinaryOperator::Concat | BinaryOperator::Plus,
                right,
                ..
            } => TextNode::Joined {
                head: None,
                operands: vec![left, right],
            },
            AstExpr::OperatorChain {
                operands,
                operators,
                span,
                ..
            } => run_text_node(
                operands.iter().map(AsRef::as_ref).collect(),
                operators.iter().map(|operator| {
                    matches!(
                        operator.operator,
                        BinaryOperator::Concat | BinaryOperator::Plus
                    )
                }),
                span.start,
            ),
            AstExpr::FunctionCall {
                func_name, args, ..
            } => match chosen_arguments(self, source) {
                Some(chosen) => TextNode::Choice(chosen),
                None => TextNode::Call {
                    name: source
                        .get(func_name.span.start as usize..func_name.span.end as usize)
                        .unwrap_or(""),
                    args: args.iter().map(|arg| positional_argument(arg)).collect(),
                    values: args.iter().filter_map(|arg| argument_value(arg)).collect(),
                    span: self.span(),
                },
            },
            AstExpr::Case {
                whens, else_expr, ..
            } => TextNode::Choice(
                whens
                    .iter()
                    .map(|when| &when.result)
                    .chain(else_expr.as_deref())
                    .collect(),
            ),
            AstExpr::Cast { expr, .. }
            | AstExpr::TryCast { expr, .. }
            | AstExpr::SafeCast { expr, .. }
            | AstExpr::TypeCast { expr, .. }
            | AstExpr::Collate { expr, .. } => TextNode::Converted(expr),
            // `:q` names `q`.
            AstExpr::ScriptingVarRef { name_span, .. } => TextNode::Variable {
                name: Some(*name_span),
                session: false,
            },
            // A Snowflake session variable `$q` names `q`.
            AstExpr::SessionVarRef { name_span, .. } => TextNode::Variable {
                name: Some(*name_span),
                session: true,
            },
            // A bare name (T-SQL's `@s` too); a qualified one is a column.
            AstExpr::Ident { column_ref, .. } if column_ref.qualifier.is_none() => {
                TextNode::Variable {
                    name: Some(column_ref.name.span),
                    session: false,
                }
            }
            AstExpr::Ident { .. }
            | AstExpr::BinaryOp { .. }
            | AstExpr::LogicalChain { .. }
            | AstExpr::ScalarSubquery { .. }
            | AstExpr::SubqueryArg { .. }
            | AstExpr::ExistsSubquery { .. }
            | AstExpr::InSubquery { .. }
            | AstExpr::QuantifiedSubquery { .. }
            | AstExpr::MatchAgainst { .. }
            | AstExpr::Spread { .. }
            | AstExpr::InList { .. }
            | AstExpr::Between { .. }
            | AstExpr::IsNull { .. }
            | AstExpr::IsPredicate { .. }
            | AstExpr::IsDistinctFrom { .. }
            | AstExpr::Like { .. }
            | AstExpr::SimilarTo { .. }
            | AstExpr::Array { .. }
            | AstExpr::RowConstructor { .. }
            | AstExpr::Placeholder { .. }
            | AstExpr::JinjaPlaceholder { .. }
            | AstExpr::JinjaConditional { .. }
            | AstExpr::DbtRef { .. }
            | AstExpr::DbtSource { .. }
            | AstExpr::DbtVar { .. }
            | AstExpr::DbtConfig { .. }
            | AstExpr::DbtThis { .. }
            | AstExpr::PositionRef { .. }
            | AstExpr::InListOpaque { .. }
            | AstExpr::ExplSnowIdent { .. }
            | AstExpr::Object { .. }
            | AstExpr::WindowFn { .. }
            | AstExpr::WindowExpr { .. }
            | AstExpr::TvfWithSchema { .. }
            | AstExpr::QualifiedStar { .. }
            | AstExpr::UnqualifiedStar { .. }
            | AstExpr::QualifiedStarFromExpr { .. }
            | AstExpr::Prior { .. }
            | AstExpr::ConnectByRoot { .. }
            | AstExpr::Extract { .. }
            | AstExpr::Position { .. }
            | AstExpr::Trim { .. }
            | AstExpr::Substring { .. }
            | AstExpr::ArraySubscript { .. }
            | AstExpr::ObjectFieldColon { .. }
            | AstExpr::ObjectFieldBracket { .. }
            | AstExpr::ObjectFieldDot { .. }
            | AstExpr::MethodCall { .. }
            | AstExpr::AtTimeZone { .. }
            | AstExpr::TypedStringLiteral { .. }
            | AstExpr::Error { .. } => TextNode::Other,
        }
    }
}

impl TextExpr for ScalarExpr {
    /// A lowered expression holds its function names: `source` is not read.
    fn text_node<'a>(&'a self, _source: &'a str) -> TextNode<'a, Self> {
        scalar_text_node(self)
    }

    fn text_span(&self) -> Span {
        scalar_expr_span(self)
    }
}

fn scalar_text_node(expr: &ScalarExpr) -> TextNode<'_, ScalarExpr> {
    use crate::ir::scalar::Lit;
    match expr {
        ScalarExpr::Lit { value, span } => match value {
            Lit::Str(_) => TextNode::String(*span),
            Lit::Integer(_) | Lit::Float(_) | Lit::Bool(_) | Lit::Null => TextNode::Fixed(*span),
            Lit::Bytes { .. } | Lit::Typed { .. } | Lit::Variant(_) | Lit::Variable { .. } => {
                TextNode::Other
            }
        },
        ScalarExpr::BinOp {
            op: super::scalar::BinOpKind::Concat | super::scalar::BinOpKind::Add,
            left,
            right,
            ..
        } => TextNode::Joined {
            head: None,
            operands: vec![left, right],
        },
        ScalarExpr::OperatorChain {
            operands,
            operators,
            span,
        } => run_text_node(
            operands.iter().collect(),
            operators.iter().map(|op| {
                matches!(
                    op,
                    super::scalar::BinOpKind::Concat | super::scalar::BinOpKind::Add
                )
            }),
            span.start,
        ),
        ScalarExpr::FuncCall {
            func: ResolvedFunc::Unresolved { raw_name, .. },
            args,
            span,
            ..
        } => match chosen(raw_name, args.iter().map(Some).collect()) {
            Some(chosen) => TextNode::Choice(chosen),
            None => TextNode::Call {
                name: raw_name,
                args: args.iter().map(Some).collect(),
                values: args.iter().collect(),
                span: *span,
            },
        },
        ScalarExpr::Case {
            branches, else_, ..
        } => TextNode::Choice(
            branches
                .iter()
                .map(|(_, result)| result)
                .chain(else_.as_deref())
                .collect(),
        ),
        ScalarExpr::Cast { expr, .. } => TextNode::Converted(expr),
        // A column of a query is a value the statement reads.
        ScalarExpr::Column { .. } | ScalarExpr::OuterRef { .. } => TextNode::Variable {
            name: None,
            session: false,
        },
        ScalarExpr::BinOp { .. }
        | ScalarExpr::LogicalChain { .. }
        | ScalarExpr::FuncCall { .. }
        | ScalarExpr::UnaryOp { .. }
        | ScalarExpr::InList { .. }
        | ScalarExpr::Between { .. }
        | ScalarExpr::Like { .. }
        | ScalarExpr::Exists { .. }
        | ScalarExpr::ScalarSubquery { .. }
        | ScalarExpr::QuantifiedCmp { .. }
        | ScalarExpr::RowCmp { .. }
        | ScalarExpr::WindowFn { .. }
        | ScalarExpr::FieldAccess { .. }
        | ScalarExpr::Lambda { .. }
        | ScalarExpr::PatternVarRef { .. }
        | ScalarExpr::Opaque { .. } => TextNode::Other,
    }
}

/// The text node of a run of operators: `operands`, `joins` whether each
/// operator joins text, the run written from `start`. The run is joined
/// text where its last operator joins: the operands after the last
/// operator that does not, joined to the value of the run up to it.
fn run_text_node<'a, E: TextExpr + ?Sized>(
    operands: Vec<&'a E>,
    mut joins: impl DoubleEndedIterator<Item = bool> + ExactSizeIterator,
    start: u32,
) -> TextNode<'a, E> {
    // Operator `i` joins the run up to operand `i` to operand `i + 1`.
    let operators = joins.len();
    match joins.rposition(|joins| !joins) {
        None => TextNode::Joined {
            head: None,
            operands,
        },
        Some(last) if last + 1 == operators => TextNode::Other,
        Some(last) => TextNode::Joined {
            head: operands.get(last + 1).map(|end| Span {
                start,
                end: end.text_span().end,
            }),
            operands: operands.get(last + 2..).unwrap_or_default().to_vec(),
        },
    }
}

/// How an expression builds text out of operands ([`concatenation_operands`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConcatenationKind {
    /// `||`, or `+` (T-SQL's concatenation).
    Operator,
    /// `CONCAT(…)`.
    Concat,
    /// `CONCAT_WS(separator, …)`.
    ConcatWs,
    /// `FORMAT(template, …)` where the dialect's `FORMAT` builds SQL.
    Format,
    /// `REPLACE(template, pattern, replacement)`.
    Replace,
}

/// One operand of a concatenation, in the order its text is written.
enum Operand<'a, E: ?Sized> {
    /// An expression whose value is written here as `quoting` writes it;
    /// `at` is where it is written: the quoting call, or the expression.
    Expr {
        expr: &'a E,
        quoting: HoleQuoting,
        at: Option<Span>,
    },
    /// The text of a `FORMAT` template literal between two placeholders:
    /// `within` is that part of the literal's source, `text` its value.
    TemplateText {
        literal: Span,
        within: Span,
        text: Option<String>,
    },
    /// A call that rewrites the text of its operands (`REPLACE`), at `span`.
    Rewritten {
        span: Span,
        operands: Vec<Operand<'a, E>>,
    },
    /// The value of the start of a run of operators that joins no text,
    /// written at the span.
    Value(Span),
    /// Text not written here: the operands on its two sides do not join.
    Break,
}

/// The call `name` names, as [`concatenation_operands`] reads it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TextCall {
    Concatenation(ConcatenationKind),
    /// One of `dialect`'s literal quoters (`quote_literal`,
    /// `quote_nullable`, MySQL's `QUOTE`).
    LiteralQuoter,
    /// One of `dialect`'s identifier quoters (`quote_ident`, `QUOTENAME`).
    IdentifierQuoter,
    Other,
}

fn text_call(name: &str, dialect: &dyn crate::dialect::Dialect) -> TextCall {
    let named = |quoters: &[&str]| quoters.iter().any(|q| name.eq_ignore_ascii_case(q));
    if name.eq_ignore_ascii_case("CONCAT") {
        TextCall::Concatenation(ConcatenationKind::Concat)
    } else if name.eq_ignore_ascii_case("CONCAT_WS") {
        TextCall::Concatenation(ConcatenationKind::ConcatWs)
    } else if name.eq_ignore_ascii_case("FORMAT") && dialect.format_function_builds_sql() {
        TextCall::Concatenation(ConcatenationKind::Format)
    } else if name.eq_ignore_ascii_case("REPLACE") {
        TextCall::Concatenation(ConcatenationKind::Replace)
    } else if named(dialect.dynamic_sql_literal_quoting_functions()) {
        TextCall::LiteralQuoter
    } else if named(dialect.dynamic_sql_identifier_quoting_functions()) {
        TextCall::IdentifierQuoter
    } else {
        TextCall::Other
    }
}

/// How the expression `node` is builds text out of operands, when it does
/// ([`concatenation_operands`]), its operands not read.
fn concatenation_kind<E: ?Sized>(
    node: TextNode<'_, E>,
    dialect: &dyn crate::dialect::Dialect,
) -> Option<ConcatenationKind> {
    match node {
        TextNode::Joined { .. } => Some(ConcatenationKind::Operator),
        TextNode::Call { name, args, .. } => match text_call(name, dialect) {
            // `CONCAT_WS`, `FORMAT` and `REPLACE` are read from their first
            // argument.
            TextCall::Concatenation(ConcatenationKind::Concat) => Some(ConcatenationKind::Concat),
            TextCall::Concatenation(kind) => args.first().map(|_| kind),
            TextCall::LiteralQuoter | TextCall::IdentifierQuoter | TextCall::Other => None,
        },
        TextNode::String(_)
        | TextNode::Fixed(_)
        | TextNode::Grouped(_)
        | TextNode::Choice(_)
        | TextNode::Converted(_)
        | TextNode::Variable { .. }
        | TextNode::Other => None,
    }
}

/// The operands of `expr` when it builds text out of others, in the order
/// their text is written: the two sides of `||` or `+` (T-SQL's
/// concatenation); the positional arguments of `CONCAT(…)`; those of
/// `CONCAT_WS(…)` after the first, the separator written between each two;
/// the text of a `FORMAT` template literal with each placeholder's argument
/// in its place (each argument apart where the template is no literal);
/// and the template and the replacement of `REPLACE(…)`, apart, the call's
/// value written in its place. `None` for any other expression.
fn concatenation_operands<'a, E: TextExpr + ?Sized>(
    expr: &'a E,
    source: &'a str,
    dialect: &dyn crate::dialect::Dialect,
) -> Option<Vec<Operand<'a, E>>> {
    let (name, args, span) = match expr.text_node(source) {
        TextNode::Joined { head, operands } => {
            return Some(
                head.map(Operand::Value)
                    .into_iter()
                    .chain(operands.into_iter().map(|e| operand(e, source, dialect)))
                    .collect(),
            );
        }
        TextNode::Call {
            name, args, span, ..
        } => (name, args, span),
        TextNode::String(_)
        | TextNode::Fixed(_)
        | TextNode::Grouped(_)
        | TextNode::Choice(_)
        | TextNode::Converted(_)
        | TextNode::Variable { .. }
        | TextNode::Other => return None,
    };
    let TextCall::Concatenation(kind) = text_call(name, dialect) else {
        return None;
    };
    // An argument not written by position writes text not read here.
    let written = |arg: Option<&'a E>| match arg {
        Some(value) => operand(value, source, dialect),
        None => Operand::Break,
    };
    let operands = match kind {
        ConcatenationKind::Operator | ConcatenationKind::Concat => {
            args.into_iter().map(written).collect()
        }
        ConcatenationKind::ConcatWs => {
            let (separator, values) = args.split_first()?;
            let mut operands = Vec::with_capacity(values.len() * 2);
            for (k, value) in values.iter().enumerate() {
                if k > 0 {
                    operands.push(written(*separator));
                }
                operands.push(written(*value));
            }
            operands
        }
        ConcatenationKind::Format => format_operands(&args, source, dialect)?,
        ConcatenationKind::Replace => {
            let mut operands = vec![written(*args.first()?)];
            // Where in the template the replacement lands is not read: it
            // is written as a quoted value, which may be inside a string.
            match args.get(2).copied() {
                Some(Some(replacement)) => operands.extend([
                    Operand::Break,
                    Operand::Expr {
                        expr: replacement,
                        quoting: HoleQuoting::LitQuoter,
                        at: None,
                    },
                ]),
                Some(None) => operands.push(Operand::Break),
                None => {}
            }
            vec![Operand::Rewritten { span, operands }]
        }
    };
    Some(operands)
}

/// The operands a `FORMAT` call with the arguments `args` builds text out
/// of: the text of its template literal, each placeholder's argument
/// written in its place; each argument apart where the template is no
/// literal. `None` without a template.
fn format_operands<'a, E: TextExpr + ?Sized>(
    args: &[Option<&'a E>],
    source: &'a str,
    dialect: &dyn crate::dialect::Dialect,
) -> Option<Vec<Operand<'a, E>>> {
    let written = |arg: Option<&'a E>| match arg {
        Some(value) => operand(value, source, dialect),
        None => Operand::Break,
    };
    let (template, values) = args.split_first()?;
    let Some(literal) = template.and_then(|t| string_literal_span(t, source)) else {
        return Some(
            std::iter::once(*template)
                .chain(values.iter().copied())
                .flat_map(|value| [written(value), Operand::Break])
                .collect(),
        );
    };
    // The template decoded once: each part of its text is cut from it.
    let decoded = source
        .get(literal.start as usize..literal.end as usize)
        .and_then(|raw| {
            crate::ir::span_extract::decode_string_literal_text_with_map_in(raw, dialect)
        });
    let text = |within: Span| {
        decoded.as_ref().map(|(decoded, map)| {
            let (from, to) = decoded_range(decoded, map, literal.start, within);
            decoded[from..to].replace("%%", "%")
        })
    };
    Some(
        format_template(literal, source)
            .into_iter()
            .map(|piece| match piece {
                TemplatePiece::Text(within) => Operand::TemplateText {
                    literal,
                    within,
                    text: text(within),
                },
                TemplatePiece::Value { argument, quoting } => {
                    match values.get(argument).copied().flatten() {
                        Some(value) => match quoting {
                            HoleQuoting::Raw => operand(value, source, dialect),
                            HoleQuoting::IdentQuoter | HoleQuoting::LitQuoter => Operand::Expr {
                                expr: value,
                                quoting,
                                at: None,
                            },
                        },
                        None => Operand::Break,
                    }
                }
                TemplatePiece::Unread => Operand::Break,
            })
            .collect(),
    )
}

/// The range of `decoded`, the value of the literal at `literal_start`
/// (`map` the offset in the literal of the source of each decoded byte),
/// whose source is `within`, each end at a character's start.
pub(crate) fn decoded_range(
    decoded: &str,
    map: &[u32],
    literal_start: u32,
    within: Span,
) -> (usize, usize) {
    // The first byte at a character's start whose source is at `source` or
    // after (`map` rises with the decoded text).
    let at = |source: u32| {
        let mut k = map.partition_point(|&m| literal_start + m < source);
        while k < decoded.len() && !decoded.is_char_boundary(k) {
            k += 1;
        }
        k.min(decoded.len())
    };
    let from = at(within.start);
    (from, at(within.end).max(from))
}

/// `expr` as an operand of a concatenation: the argument of a call that
/// quotes it is that argument, written as the call quotes it
/// ([`quoted_argument`]); any other expression is itself, written raw.
fn operand<'a, E: TextExpr + ?Sized>(
    expr: &'a E,
    source: &'a str,
    dialect: &dyn crate::dialect::Dialect,
) -> Operand<'a, E> {
    let call = unparenthesized_text(expr, source);
    match quoted_argument(call, source, dialect) {
        Some((argument, quoting, at)) => Operand::Expr {
            expr: argument,
            quoting,
            at: Some(at),
        },
        None => Operand::Expr {
            expr,
            quoting: HoleQuoting::Raw,
            at: None,
        },
    }
}

/// `expr` with the parentheses around it removed.
fn unparenthesized_text<'a, E: TextExpr + ?Sized>(mut expr: &'a E, source: &'a str) -> &'a E {
    while let TextNode::Grouped(inner) = expr.text_node(source) {
        expr = inner;
    }
    expr
}

/// The argument `expr` quotes when it is a call of one of the dialect's
/// quoters, with how it is written and where the call is: as a quoted
/// literal by a literal quoter, or by the identifier quoter given `'` as
/// the quote character (T-SQL's `QUOTENAME(x, '''')`); as a quoted
/// identifier by any other call of an identifier quoter.
fn quoted_argument<'a, E: TextExpr + ?Sized>(
    expr: &'a E,
    source: &'a str,
    dialect: &dyn crate::dialect::Dialect,
) -> Option<(&'a E, HoleQuoting, Span)> {
    let TextNode::Call {
        name, args, span, ..
    } = expr.text_node(source)
    else {
        return None;
    };
    let quoting = match text_call(name, dialect) {
        TextCall::LiteralQuoter => HoleQuoting::LitQuoter,
        TextCall::IdentifierQuoter => {
            let quote = args
                .get(1)
                .copied()
                .flatten()
                .and_then(|quote| string_literal_span(quote, source))
                .and_then(|quote| source.get(quote.start as usize..quote.end as usize))
                .and_then(crate::ir::span_extract::string_literal_value);
            if quote.as_deref() == Some("'") {
                HoleQuoting::LitQuoter
            } else {
                HoleQuoting::IdentQuoter
            }
        }
        TextCall::Concatenation(_) | TextCall::Other => return None,
    };
    Some((args.first().copied().flatten()?, quoting, span))
}

/// The span of the string literal `expr` is, parentheses around it removed.
fn string_literal_span<E: TextExpr + ?Sized>(expr: &E, source: &str) -> Option<Span> {
    match unparenthesized_text(expr, source).text_node(source) {
        TextNode::String(span) => Some(span),
        TextNode::Fixed(_)
        | TextNode::Grouped(_)
        | TextNode::Choice(_)
        | TextNode::Converted(_)
        | TextNode::Joined { .. }
        | TextNode::Call { .. }
        | TextNode::Variable { .. }
        | TextNode::Other => None,
    }
}

/// A part of a `FORMAT` template ([`format_template`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TemplatePiece {
    /// Text of the template, whose source is the span.
    Text(Span),
    /// A placeholder: the argument written in its place (0 for the first
    /// after the template), written raw (`%s`), as a quoted identifier
    /// (`%I`) or as a quoted literal (`%L`).
    Value {
        argument: usize,
        quoting: HoleQuoting,
    },
    /// A placeholder whose argument is not known (a `*` width).
    Unread,
}

/// The `FORMAT` template literal at `literal`, in order: its text, and its
/// placeholders `%[n$][-][width]<conversion>` (`I` and `L` quote, any other
/// letter writes the argument as it is), each taking the argument it
/// names by position or the one after the last taken; `%%` is text.
fn format_template(literal: Span, source: &str) -> Vec<TemplatePiece> {
    let Some(raw) = source.get(literal.start as usize..literal.end as usize) else {
        return Vec::new();
    };
    let bytes = raw.as_bytes();
    let mut pieces = Vec::new();
    let mut from = 0usize;
    let mut next_argument = 0usize;
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] != b'%' {
            i += 1;
            continue;
        }
        if bytes.get(i + 1) == Some(&b'%') {
            i += 2;
            continue;
        }
        let mut end = i + 1;
        // Position, flags, width and precision (`%2$-10.3t`, `%+d`, `%#x`).
        while end < bytes.len()
            && matches!(
                bytes[end],
                b'0'..=b'9' | b'$' | b'-' | b'*' | b'.' | b'+' | b'#'
            )
        {
            end += 1;
        }
        let quoting = match bytes.get(end) {
            Some(b'I') => HoleQuoting::IdentQuoter,
            Some(b'L') => HoleQuoting::LitQuoter,
            // `%s`, and any other conversion (BigQuery `%t`, `%T`, `%d`): the
            // argument's text, written as it is.
            Some(c) if c.is_ascii_alphabetic() => HoleQuoting::Raw,
            Some(_) | None => {
                i += 1;
                continue;
            }
        };
        pieces.push(TemplatePiece::Text(Span {
            start: literal.start + from as u32,
            end: literal.start + i as u32,
        }));
        let spec = &raw[i + 1..end];
        let position = spec
            .split_once('$')
            .and_then(|(n, _)| n.parse::<usize>().ok())
            .filter(|&n| n > 0);
        pieces.push(if spec.contains('*') {
            TemplatePiece::Unread
        } else {
            let argument = position.map_or(next_argument, |n| n - 1);
            next_argument = argument + 1;
            TemplatePiece::Value { argument, quoting }
        });
        i = end + 1;
        from = i;
    }
    pieces.push(TemplatePiece::Text(Span {
        start: literal.start + from as u32,
        end: literal.end,
    }));
    pieces
}

/// A string literal a statement runs as SQL: the whole text it runs, or
/// the literal text of a run of operands of a concatenation that builds
/// that text, each joined to the one before.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) enum ExecutedLiteral {
    Whole(Span),
    Run(Vec<RunPart>),
}

/// A literal operand of a run ([`ExecutedLiteral::Run`]): the literal at
/// `literal`, its text whole, or the part of it whose source is `within`;
/// or, `quoted`, the literal as written, its quotes included.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct RunPart {
    pub(crate) literal: Span,
    pub(crate) within: Option<Span>,
    pub(crate) quoted: bool,
}

/// A piece of the text an expression builds ([`text_pieces`]), in the
/// order its text is written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TextPiece {
    /// The text of the string literal at the span.
    Literal(Span),
    /// The string literal at the span written as a quoted literal, its
    /// quotes included: `quote_literal('x')`, `FORMAT`'s `%L` of a literal.
    QuotedLiteral(Span),
    /// The part `within` of the `FORMAT` template literal at `literal`:
    /// `text` is the text it writes (`%%` writes `%`), where the literal
    /// decodes.
    TemplateText {
        literal: Span,
        within: Span,
        text: Option<String>,
    },
    /// The number, boolean or NULL literal at the span, written as the
    /// source writes it.
    Verbatim(Span),
    /// The value of a variable written here: `name` is the span naming it
    /// (`q` of `:q` and of `$q`, `@s`), `at` the expression written here
    /// (the variable, or the call that quotes it), `quoting` how its value
    /// is written.
    Variable {
        name: Span,
        at: Span,
        quoting: HoleQuoting,
        /// A Snowflake session variable `$q`, which `SET q = …` sets.
        session: bool,
    },
    /// A value written here whose text is not known: the expression at
    /// `at` (or the call that quotes it), written as `quoting` writes it.
    Value { at: Span, quoting: HoleQuoting },
    /// The value of the call at `at` that rewrites the text of `pieces`
    /// (`REPLACE`), written here: its text is not known, and `pieces` are
    /// its template and its replacement, apart.
    Rewritten { at: Span, pieces: Vec<TextPiece> },
    /// The value at `at` that is one of several texts, each of `choices`
    /// (a `CASE`'s results, `COALESCE`'s arguments), written here.
    Choice {
        at: Span,
        choices: Vec<Vec<TextPiece>>,
    },
    /// Text not written here: the pieces on its two sides do not join.
    Break,
}

/// The pieces of the text `expr` builds, in the order written: the literal
/// it is (parentheses removed), the variable or other value it is, or the
/// operands of the concatenation it is, at any nesting, read as `dialect`
/// reads its calls (which `FORMAT` builds SQL, which calls quote).
pub fn text_pieces(
    expr: &AstExpr,
    source: &str,
    dialect: &dyn crate::dialect::Dialect,
) -> Vec<TextPiece> {
    pieces_of(expr, source, dialect)
}

/// [`text_pieces`] of a lowered expression; `source` is the text it was
/// lowered from, which its spans index.
pub fn scalar_text_pieces(
    expr: &ScalarExpr,
    source: &str,
    dialect: &dyn crate::dialect::Dialect,
) -> Vec<TextPiece> {
    pieces_of(expr, source, dialect)
}

/// The pieces of the text a `FORMAT` call with the arguments `args` builds
/// where the dialect's `FORMAT` builds SQL ([`text_pieces`]); none where
/// it has no template or does not build SQL.
pub fn format_text_pieces(
    args: &[Box<crate::ast::AstFunctionArg>],
    source: &str,
    dialect: &dyn crate::dialect::Dialect,
) -> Vec<TextPiece> {
    let args: Vec<Option<&AstExpr>> = args.iter().map(|arg| positional_argument(arg)).collect();
    format_pieces(&args, source, dialect)
}

/// [`format_text_pieces`] of a lowered call's arguments; `source` is the
/// text they were lowered from.
pub fn scalar_format_text_pieces(
    args: &[ScalarExpr],
    source: &str,
    dialect: &dyn crate::dialect::Dialect,
) -> Vec<TextPiece> {
    let args: Vec<Option<&ScalarExpr>> = args.iter().map(Some).collect();
    format_pieces(&args, source, dialect)
}

fn format_pieces<E: TextExpr + ?Sized>(
    args: &[Option<&E>],
    source: &str,
    dialect: &dyn crate::dialect::Dialect,
) -> Vec<TextPiece> {
    if !dialect.format_function_builds_sql() {
        return Vec::new();
    }
    format_operands(args, source, dialect)
        .map(|operands| read_pieces(operands, source, dialect))
        .unwrap_or_default()
}

/// The expression an argument is written as by position.
fn positional_argument(arg: &crate::ast::AstFunctionArg) -> Option<&AstExpr> {
    match arg {
        crate::ast::AstFunctionArg::Positional(e) => Some(e.as_ref()),
        crate::ast::AstFunctionArg::Named { .. }
        | crate::ast::AstFunctionArg::Lambda { .. }
        | crate::ast::AstFunctionArg::AliasedArg { .. }
        | crate::ast::AstFunctionArg::BulkArg { .. }
        | crate::ast::AstFunctionArg::Unparsed { .. }
        | crate::ast::AstFunctionArg::Table { .. }
        | crate::ast::AstFunctionArg::DataType { .. }
        | crate::ast::AstFunctionArg::NonValue { .. }
        | crate::ast::AstFunctionArg::Introduced { .. } => None,
    }
}

/// The value an argument writes, however written; `None` for one that
/// writes no value (a type, a table, text no reader parsed).
fn argument_value(arg: &crate::ast::AstFunctionArg) -> Option<&AstExpr> {
    use crate::ast::{AstFunctionArg as A, AstIntroducedValue};
    match arg {
        A::Positional(value)
        | A::Named { value, .. }
        | A::AliasedArg { value, .. }
        | A::Lambda { body: value, .. }
        | A::BulkArg { value, .. }
        | A::Introduced {
            value: AstIntroducedValue::Expr(value),
            ..
        } => Some(value),
        A::Unparsed { .. }
        | A::Table { .. }
        | A::DataType { .. }
        | A::NonValue { .. }
        | A::Introduced {
            value: AstIntroducedValue::DataType { .. } | AstIntroducedValue::Name(_),
            ..
        } => None,
    }
}

fn pieces_of<E: TextExpr + ?Sized>(
    expr: &E,
    source: &str,
    dialect: &dyn crate::dialect::Dialect,
) -> Vec<TextPiece> {
    read_pieces(vec![operand(expr, source, dialect)], source, dialect)
}

/// The pieces of the text `operands` write, in order.
fn read_pieces<E: TextExpr + ?Sized>(
    operands: Vec<Operand<'_, E>>,
    source: &str,
    dialect: &dyn crate::dialect::Dialect,
) -> Vec<TextPiece> {
    enum Work<'a, E: ?Sized> {
        Read(Operand<'a, E>),
        /// The pieces read since the matching `Rewritten` began are its own.
        EndRewritten(Span),
    }
    // The pieces of each `Rewritten` being read, innermost last.
    let mut out: Vec<Vec<TextPiece>> = vec![Vec::new()];
    let mut pending: Vec<Work<'_, E>> = operands.into_iter().rev().map(Work::Read).collect();
    while let Some(work) = pending.pop() {
        let next = match work {
            Work::Read(next) => next,
            Work::EndRewritten(at) => {
                let pieces = out.pop().unwrap_or_default();
                if let Some(outer) = out.last_mut() {
                    outer.push(TextPiece::Rewritten { at, pieces });
                }
                continue;
            }
        };
        let piece = match next {
            Operand::TemplateText {
                literal,
                within,
                text,
            } => TextPiece::TemplateText {
                literal,
                within,
                text,
            },
            Operand::Break => TextPiece::Break,
            Operand::Value(at) => TextPiece::Value {
                at,
                quoting: HoleQuoting::Raw,
            },
            Operand::Rewritten { span, operands } => {
                out.push(Vec::new());
                pending.push(Work::EndRewritten(span));
                pending.extend(operands.into_iter().rev().map(Work::Read));
                continue;
            }
            Operand::Expr { expr, quoting, at } => {
                let expr = unparenthesized_text(expr, source);
                let at = at.unwrap_or_else(|| expr.text_span());
                if quoting == HoleQuoting::Raw {
                    if let Some(operands) = concatenation_operands(expr, source, dialect) {
                        pending.extend(operands.into_iter().rev().map(Work::Read));
                        continue;
                    }
                }
                match expr.text_node(source) {
                    // A converted value writes its operand's text.
                    TextNode::Converted(inner) => {
                        pending.push(Work::Read(Operand::Expr {
                            expr: inner,
                            quoting,
                            at: Some(at),
                        }));
                        continue;
                    }
                    TextNode::Choice(choices) => {
                        let piece = match crate::ir::lower::enter_nested() {
                            Some(_frame) => TextPiece::Choice {
                                at,
                                choices: choices
                                    .into_iter()
                                    .map(|choice| {
                                        read_pieces(
                                            vec![Operand::Expr {
                                                expr: choice,
                                                quoting,
                                                at: None,
                                            }],
                                            source,
                                            dialect,
                                        )
                                    })
                                    .collect(),
                            },
                            None => TextPiece::Value { at, quoting },
                        };
                        if let Some(pieces) = out.last_mut() {
                            pieces.push(piece);
                        }
                        continue;
                    }
                    TextNode::String(_)
                    | TextNode::Fixed(_)
                    | TextNode::Grouped(_)
                    | TextNode::Joined { .. }
                    | TextNode::Call { .. }
                    | TextNode::Variable { .. }
                    | TextNode::Other => {}
                }
                match (expr.text_node(source), quoting) {
                    (TextNode::String(literal), HoleQuoting::Raw) => TextPiece::Literal(literal),
                    (TextNode::String(literal), HoleQuoting::LitQuoter) => {
                        TextPiece::QuotedLiteral(literal)
                    }
                    (TextNode::Fixed(literal), HoleQuoting::Raw) => TextPiece::Verbatim(literal),
                    (
                        TextNode::Variable {
                            name: Some(name),
                            session,
                        },
                        quoting,
                    ) => TextPiece::Variable {
                        name,
                        at,
                        quoting,
                        session,
                    },
                    (
                        TextNode::String(_)
                        | TextNode::Fixed(_)
                        | TextNode::Grouped(_)
                        | TextNode::Joined { .. }
                        | TextNode::Call { .. }
                        | TextNode::Choice(_)
                        | TextNode::Converted(_)
                        | TextNode::Variable { name: None, .. }
                        | TextNode::Other,
                        quoting,
                    ) => TextPiece::Value { at, quoting },
                }
            }
        };
        if let Some(pieces) = out.last_mut() {
            pieces.push(piece);
        }
    }
    out.pop().unwrap_or_default()
}

/// `pieces` with the pieces of each [`TextPiece::Rewritten`] in its place,
/// at any nesting: the pieces a reader of the literals a text holds reads.
pub(crate) fn flattened(pieces: &[TextPiece]) -> Vec<&TextPiece> {
    // The text of one choice does not join another's or what is around it.
    static APART: TextPiece = TextPiece::Break;
    let mut out = Vec::with_capacity(pieces.len());
    let mut pending: Vec<std::slice::Iter<'_, TextPiece>> = vec![pieces.iter()];
    let mut choices: Vec<std::slice::Iter<'_, Vec<TextPiece>>> = Vec::new();
    // Per open iterator, whether it reads one choice.
    let mut of_choice: Vec<bool> = vec![false];
    while let Some(top) = pending.last_mut() {
        match top.next() {
            Some(TextPiece::Rewritten { pieces, .. }) => {
                pending.push(pieces.iter());
                of_choice.push(false);
            }
            Some(TextPiece::Choice { choices: each, .. }) => {
                out.push(&APART);
                choices.push(each.iter());
                if let Some(first) = choices.last_mut().and_then(Iterator::next) {
                    pending.push(first.iter());
                    of_choice.push(true);
                } else {
                    choices.pop();
                }
            }
            Some(piece) => out.push(piece),
            None => {
                pending.pop();
                if of_choice.pop() == Some(true) {
                    out.push(&APART);
                    match choices.last_mut().and_then(Iterator::next) {
                        Some(next) => {
                            pending.push(next.iter());
                            of_choice.push(true);
                        }
                        None => {
                            choices.pop();
                        }
                    }
                }
            }
        }
    }
    out
}

/// The texts `pieces` may each be where they are one choice of several
/// ([`TextPiece::Choice`]) written alone, at any nesting; `pieces` alone
/// otherwise.
pub(crate) fn alternatives(pieces: &[TextPiece]) -> Vec<&[TextPiece]> {
    let mut out = Vec::new();
    let mut pending = vec![pieces];
    while let Some(pieces) = pending.pop() {
        match pieces {
            [TextPiece::Choice { choices, .. }] => {
                pending.extend(choices.iter().rev().map(Vec::as_slice));
            }
            [..] => out.push(pieces),
        }
    }
    out
}

/// The literal operand of a run a piece is ([`RunPart`]), where it is one.
pub(crate) fn run_part(piece: &TextPiece) -> Option<RunPart> {
    match piece {
        TextPiece::Literal(literal) => Some(RunPart {
            literal: *literal,
            within: None,
            quoted: false,
        }),
        TextPiece::QuotedLiteral(literal) => Some(RunPart {
            literal: *literal,
            within: None,
            quoted: true,
        }),
        TextPiece::TemplateText {
            literal, within, ..
        } => Some(RunPart {
            literal: *literal,
            within: Some(*within),
            quoted: false,
        }),
        TextPiece::Verbatim(_)
        | TextPiece::Variable { .. }
        | TextPiece::Value { .. }
        | TextPiece::Rewritten { .. }
        | TextPiece::Choice { .. }
        | TextPiece::Break => None,
    }
}

/// The key the variable written `written` is known by: its name as the
/// dialect of the analysis running on the thread folds it, the `:` of a
/// bind reference (`:q` names `q`) no part of it.
pub fn variable_key(written: &str) -> IdentKey {
    let written = written.trim();
    IdentKey::new(written.strip_prefix(':').unwrap_or(written))
}

/// The literal text `pieces` write, run as SQL: the literal itself where
/// they are one literal written whole; else their runs of literals, a run
/// ending where a piece that is no literal is written.
pub(crate) fn executed_literals(pieces: &[TextPiece]) -> Vec<ExecutedLiteral> {
    alternatives(pieces)
        .into_iter()
        .flat_map(alternative_literals)
        .collect()
}

/// [`executed_literals`] of one text a value may be.
fn alternative_literals(pieces: &[TextPiece]) -> Vec<ExecutedLiteral> {
    if let [TextPiece::Literal(literal)] = pieces {
        return vec![ExecutedLiteral::Whole(*literal)];
    }
    let mut runs = Vec::new();
    let mut run: Vec<RunPart> = Vec::new();
    for piece in flattened(pieces) {
        if let Some(part) = run_part(piece) {
            run.push(part);
        } else if !run.is_empty() {
            runs.push(ExecutedLiteral::Run(std::mem::take(&mut run)));
        }
    }
    if !run.is_empty() {
        runs.push(ExecutedLiteral::Run(run));
    }
    runs
}

/// The variables `pieces` write, each as executed `whole` or as an operand,
/// with whether its value is written as a quoted literal.
fn written_variables(pieces: &[TextPiece], whole: bool) -> Vec<ExecutedVariable> {
    flattened(pieces)
        .into_iter()
        .filter_map(|piece| match piece {
            TextPiece::Variable {
                name,
                quoting,
                session,
                ..
            } => Some(ExecutedVariable {
                name: *name,
                whole,
                quoted: *quoting == HoleQuoting::LitQuoter,
                session: *session,
            }),
            TextPiece::Literal(_)
            | TextPiece::QuotedLiteral(_)
            | TextPiece::TemplateText { .. }
            | TextPiece::Verbatim(_)
            | TextPiece::Value { .. }
            | TextPiece::Rewritten { .. }
            | TextPiece::Choice { .. }
            | TextPiece::Break => None,
        })
        .collect()
}

/// A variable a dynamic-SQL statement executes: the span naming it,
/// whether it is the whole text run or an operand of a concatenation that
/// builds it, whether that operand's value is written as a quoted
/// literal (`quote_literal(p)`, `format('%L', p)`), and whether the syntax
/// tree marks it a session variable ([`TextPiece::Variable`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ExecutedVariable {
    pub(crate) name: Span,
    pub(crate) whole: bool,
    pub(crate) quoted: bool,
    pub(crate) session: bool,
}

/// Which of a dialect's variables outlive the routine or batch that sets
/// them: every statement of the script reads them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SessionVariables {
    /// None the syntax tree tells from a local one.
    Unmarked,
    /// MySQL's user variables, written `@name` (`@@name` is a system
    /// variable).
    AtNamed,
    /// Snowflake's: set by `SET name = …`, read as `$name`.
    SetAndDollar,
}

impl SessionVariables {
    /// The session variables of the dialect that reports `dialect`.
    pub(crate) fn of(dialect: &dyn crate::dialect::Dialect) -> Self {
        use crate::ir::CatalogDialect as D;
        match D::from_dialect_name(dialect.name()) {
            D::MySql => Self::AtNamed,
            D::Snowflake => Self::SetAndDollar,
            D::Default | D::BigQuery | D::PostgreSql | D::Databricks | D::MsSql | D::Redshift => {
                Self::Unmarked
            }
        }
    }

    /// Whether the variable written `written` outlives its routine or
    /// batch, `marked` where the syntax tree says so (`$name`).
    pub(crate) fn names_session(self, written: &str, marked: bool) -> bool {
        marked
            || match self {
                Self::AtNamed => written
                    .strip_prefix('@')
                    .is_some_and(|name| !name.starts_with('@')),
                Self::Unmarked | Self::SetAndDollar => false,
            }
    }
}

/// The variables the text of `pieces` a dynamic-SQL statement executes
/// ([`executed_pieces`]) writes: the one it executes when written as one,
/// `EXECUTE IMMEDIATE :q` or `q` (and PL/pgSQL's `EXECUTE q`), `$q`,
/// T-SQL's `EXEC (@s)` and `EXEC sp_executesql @s`, and MySQL's `PREPARE
/// name FROM @s`; and each variable operand of the concatenation it
/// executes (`EXEC (@a + @b)`).
pub(crate) fn executed_variables(pieces: &[TextPiece]) -> Vec<ExecutedVariable> {
    alternatives(pieces)
        .into_iter()
        .flat_map(|pieces| {
            let whole = matches!(
                pieces,
                [TextPiece::Variable {
                    quoting: HoleQuoting::Raw,
                    ..
                }]
            );
            written_variables(pieces, whole)
        })
        .collect()
}

/// A text a statement assigns to a variable ([`assigned_texts`]).
#[derive(Debug)]
pub(crate) struct AssignedText {
    /// The span naming the variable.
    pub(crate) name: Span,
    /// Whether the syntax tree marks the variable a session variable
    /// (Snowflake's `SET v = …`).
    pub(crate) session: bool,
    /// The pieces of the text ([`text_pieces`]).
    pub(crate) pieces: Vec<TextPiece>,
    /// Whether the text is one of several the value may be
    /// ([`value_choices`]), each assigned beside the others.
    pub(crate) choice: bool,
}

/// How a function whose value is one of its arguments chooses
/// ([`CHOOSING_FUNCTIONS`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Chooses {
    /// Any of its arguments (`COALESCE`).
    Any,
    /// Any argument after the first, a condition or an index (`IIF`).
    AfterFirst,
    /// Its first argument, or nothing (`NULLIF`).
    First,
    /// A result of `DECODE(expr, search, result, …, [default])`.
    Results,
}

/// The functions whose value is one of their arguments, by name, with how
/// many arguments each takes at least.
const CHOOSING_FUNCTIONS: &[(&str, Chooses, usize)] = &[
    ("coalesce", Chooses::Any, 1),
    ("ifnull", Chooses::Any, 2),
    ("isnull", Chooses::Any, 2),
    ("nvl", Chooses::Any, 2),
    ("greatest", Chooses::Any, 1),
    ("least", Chooses::Any, 1),
    ("iif", Chooses::AfterFirst, 3),
    ("if", Chooses::AfterFirst, 3),
    ("iff", Chooses::AfterFirst, 3),
    ("nvl2", Chooses::AfterFirst, 3),
    ("choose", Chooses::AfterFirst, 2),
    ("nullif", Chooses::First, 2),
    ("decode", Chooses::Results, 3),
];

/// The expressions the value of `expr` is one of: each result of a `CASE`
/// (its `ELSE` too), and each argument a function whose value is one of its
/// arguments may give (`COALESCE`, `IIF`, `IF`, …; `CHOOSING_FUNCTIONS`),
/// at any depth; `expr` alone where it chooses none.
pub fn value_choices<'a>(expr: &'a AstExpr, source: &'a str) -> Vec<&'a AstExpr> {
    let mut out = Vec::new();
    let mut pending = vec![expr];
    while let Some(expr) = pending.pop() {
        let expr = unparenthesized(expr);
        match expr.text_node(source) {
            TextNode::Choice(choices) => pending.extend(choices.into_iter().rev()),
            TextNode::String(_)
            | TextNode::Fixed(_)
            | TextNode::Grouped(_)
            | TextNode::Joined { .. }
            | TextNode::Call { .. }
            | TextNode::Converted(_)
            | TextNode::Variable { .. }
            | TextNode::Other => out.push(expr),
        }
    }
    out
}

/// The arguments `expr` may give, where it calls a function written bare
/// whose value is one of its arguments ([`CHOOSING_FUNCTIONS`]).
fn chosen_arguments<'a>(expr: &'a AstExpr, source: &str) -> Option<Vec<&'a AstExpr>> {
    let AstExpr::FunctionCall {
        func_name, args, ..
    } = expr
    else {
        return None;
    };
    let name = source.get(func_name.span.start as usize..func_name.span.end as usize)?;
    chosen(
        name,
        args.iter().map(|arg| positional_argument(arg)).collect(),
    )
}

/// The arguments a call of the function `name` with the arguments `args`
/// (`None` for one not written by position) may give, where it is a
/// function whose value is one of its arguments ([`CHOOSING_FUNCTIONS`]).
fn chosen<'a, E: ?Sized>(name: &str, args: Vec<Option<&'a E>>) -> Option<Vec<&'a E>> {
    let &(_, chooses, least) = CHOOSING_FUNCTIONS
        .iter()
        .find(|(function, _, _)| function.eq_ignore_ascii_case(name.trim()))?;
    let arguments: Vec<&E> = args.into_iter().collect::<Option<_>>()?;
    if arguments.len() < least {
        return None;
    }
    Some(match chooses {
        Chooses::Any => arguments,
        Chooses::AfterFirst => arguments.into_iter().skip(1).collect(),
        Chooses::First => arguments.into_iter().take(1).collect(),
        Chooses::Results => {
            let count = arguments.len();
            arguments
                .into_iter()
                .enumerate()
                .filter(|&(at, _)| {
                    (at >= 2 && at.is_multiple_of(2))
                        || (count.is_multiple_of(2) && at == count - 1)
                })
                .map(|(_, argument)| argument)
                .collect()
        }
    })
}

/// The string literals of the texts `assigned` ([`assigned_texts`]), each
/// with the text it is of: the whole value, or a run of the concatenation
/// the value is.
pub(crate) fn assigned_string_literals(
    assigned: &[AssignedText],
) -> Vec<(&AssignedText, ExecutedLiteral)> {
    assigned
        .iter()
        .flat_map(|text| {
            executed_literals(&text.pieces)
                .into_iter()
                .map(move |literal| (text, literal))
        })
        .collect()
}

/// The text `stmt` assigns to each variable it assigns one: a
/// `DECLARE` default (`DEFAULT '…'`, `:= '…'`, T-SQL's `= '…'`),
/// Snowflake's `LET v := '…'`, an assignment `v := '…'`, `SET v = '…'`
/// (T-SQL's and MySQL's `SET @v = '…'` too), and a `SELECT` that assigns
/// one. A variable given a value not known here ([`assigned_values`]) is
/// assigned one [`TextPiece::Value`]. A variable is marked a session
/// variable where the statement makes one so (Snowflake's `SET v = …`).
pub(crate) fn assigned_texts(
    stmt: &crate::ast::AstStmt,
    source: &str,
    dialect: &dyn crate::dialect::Dialect,
) -> Vec<AssignedText> {
    let set_is_session = SessionVariables::of(dialect) == SessionVariables::SetAndDollar
        && matches!(stmt, crate::ast::AstStmt::SetVariable { .. });
    assigned_values(stmt, source)
        .into_iter()
        .flat_map(|(name, value)| {
            let choices = value.map(|value| value_choices(value, source));
            let choice = choices.as_ref().is_some_and(|choices| choices.len() > 1);
            // A value not known here holds nothing written in the statement.
            let texts: Vec<Vec<TextPiece>> = match choices {
                Some(choices) => choices
                    .into_iter()
                    .map(|value| text_pieces(value, source, dialect))
                    .collect(),
                None => vec![vec![TextPiece::Value {
                    at: name,
                    quoting: HoleQuoting::Raw,
                }]],
            };
            texts.into_iter().map(move |pieces| AssignedText {
                name,
                session: set_is_session,
                pieces,
                choice,
            })
        })
        .collect()
}

/// The pieces of the text a dynamic-SQL statement executes: `EXECUTE
/// IMMEDIATE …` (and PL/pgSQL's `EXECUTE …`), T-SQL's `EXEC (…)` and `EXEC
/// sp_executesql …`, and MySQL's `PREPARE name FROM …`; a variable executed
/// whole a piece of its own.
pub(crate) fn executed_pieces(
    stmt: &crate::ast::AstStmt,
    source: &str,
    dialect: &dyn crate::dialect::Dialect,
) -> Vec<TextPiece> {
    executed_expr(stmt, source)
        .map(|expr| text_pieces(expr, source, dialect))
        .unwrap_or_default()
}

/// A routine a statement creates: the span of its name, and the span of
/// each parameter's name in order, `None` for a parameter with none.
pub(crate) fn created_routine(stmt: &crate::ast::AstStmt) -> Option<(Span, Vec<Option<Span>>)> {
    let created = created_routine_parts(stmt)?;
    Some((
        created.name,
        created.params.iter().map(|param| param.name_span).collect(),
    ))
}

/// A routine a statement creates ([`created_routine_parts`]).
pub(crate) struct CreatedRoutine<'a> {
    /// The span of its name.
    pub(crate) name: Span,
    /// Its parameters, in order.
    pub(crate) params: &'a [crate::ast::AstProcedureParam],
    /// The statement replaces a routine of its name and parameters
    /// (`CREATE OR REPLACE`, `CREATE OR ALTER`, `ALTER`).
    pub(crate) replaces: bool,
}

/// The routine a statement creates, where it is a procedure's or a
/// function's definition.
pub(crate) fn created_routine_parts(stmt: &crate::ast::AstStmt) -> Option<CreatedRoutine<'_>> {
    use crate::ast::{AstDefinitionVerb, AstStmt};
    let replaces = |or_replace: Option<Span>, verb: AstDefinitionVerb| {
        or_replace.is_some()
            || match verb {
                AstDefinitionVerb::Create => false,
                AstDefinitionVerb::Alter | AstDefinitionVerb::CreateOrAlter => true,
            }
    };
    if let AstStmt::CreateProcedure(p) = stmt {
        Some(CreatedRoutine {
            name: p.name_span,
            params: &p.params,
            replaces: replaces(p.or_replace_span, p.verb),
        })
    } else if let AstStmt::CreateFunction(f) = stmt {
        Some(CreatedRoutine {
            name: f.name_span,
            params: &f.params,
            replaces: replaces(f.or_replace_span, f.verb),
        })
    } else {
        None
    }
}

/// A call of a named routine ([`routine_calls`]).
pub(crate) struct RoutineCall<'a> {
    /// The node of the call: the statement, or the function call.
    pub(crate) node: NodeId,
    /// The span of the name called.
    pub(crate) name: Span,
    /// Each argument in order: the span of the parameter name it is
    /// written to, where written by name, and its value, where it is an
    /// expression.
    pub(crate) arguments: Vec<(Option<Span>, Option<&'a AstExpr>)>,
    /// Whether a `FROM` reads the call as a table.
    pub(crate) table: bool,
}

/// The calls of a named routine `stmt` makes: T-SQL's `EXEC p …` (not one
/// that runs SQL text, [`sql_run`]), `CALL p(…)`, and every function call
/// in the expressions it evaluates, at any depth ([`statement_calls`]).
pub(crate) fn routine_calls<'a>(
    stmt: &'a crate::ast::AstStmt,
    source: &str,
) -> Vec<RoutineCall<'a>> {
    use crate::ast::{AstFunctionArg, AstStmt};
    let call_args = |args: &'a [crate::ast::AstCallArg]| {
        args.iter()
            .map(|arg| (arg.name.as_ref().map(|name| name.span), Some(&arg.value)))
            .collect()
    };
    let mut out = Vec::new();
    if let AstStmt::MssqlExec(e) = stmt {
        match e.procedure_name_span {
            Some(name) if sql_run(stmt, source).is_none() => out.push(RoutineCall {
                node: stmt.node_id(),
                name,
                arguments: call_args(&e.args),
                table: false,
            }),
            Some(_) | None => {}
        }
    } else if let AstStmt::Call {
        procedure_name_span,
        args,
        ..
    } = stmt
    {
        out.push(RoutineCall {
            node: stmt.node_id(),
            name: *procedure_name_span,
            arguments: call_args(args),
            table: false,
        });
    }
    let mut calls = Vec::new();
    statement_calls(stmt, &mut calls);
    out.extend(calls.into_iter().filter_map(|(call, table)| {
        let AstExpr::FunctionCall {
            func_name, args, ..
        } = call
        else {
            return None;
        };
        Some(RoutineCall {
            node: call.node_id(),
            name: func_name.span,
            table,
            arguments: args
                .iter()
                .map(|arg| match arg.as_ref() {
                    AstFunctionArg::Positional(value) => (None, Some(value.as_ref())),
                    AstFunctionArg::Named { name, value, .. } => {
                        (Some(name.span), Some(value.as_ref()))
                    }
                    AstFunctionArg::Lambda { .. }
                    | AstFunctionArg::AliasedArg { .. }
                    | AstFunctionArg::BulkArg { .. }
                    | AstFunctionArg::Unparsed { .. }
                    | AstFunctionArg::Table { .. }
                    | AstFunctionArg::DataType { .. }
                    | AstFunctionArg::NonValue { .. }
                    | AstFunctionArg::Introduced { .. } => (None, None),
                })
                .collect(),
        })
    }));
    out
}

/// Each variable `stmt` assigns, by the span of its name, with the value
/// where the statement writes it: a `DECLARE` default (`DEFAULT …`, `:=
/// …`, `= …`), Snowflake's `LET v := …`, an assignment `v := …`, `SET v =
/// …` (T-SQL's and MySQL's `SET @v = …`, and MySQL's local `SET v = …`,
/// too), and a `SELECT` that assigns one. A variable given a value not
/// known here has none: each one `FETCH … INTO` or `EXECUTE … INTO` writes
/// a row into, a T-SQL `EXEC` argument passed `OUTPUT` and the variable of
/// `EXEC @rc = p`, a `FOR` or `FOREACH` loop's variable, and each variable
/// `SET (a, b) = …` sets from one value.
pub fn assigned_values<'a>(
    stmt: &'a crate::ast::AstStmt,
    source: &str,
) -> Vec<(Span, Option<&'a AstExpr>)> {
    use crate::ast::AstStmt;
    if let AstStmt::Declare { variables, .. } = stmt {
        variables
            .iter()
            .filter_map(|variable| {
                Some((variable.name.span, Some(variable.default_expr.as_deref()?)))
            })
            .collect()
    } else if let AstStmt::Let { name, expr, .. } = stmt {
        vec![(name.span, Some(expr))]
    } else if let AstStmt::Assign {
        name_span,
        subscript_span,
        expr,
        ..
    } = stmt
    {
        // An element assigned leaves the variable a value not known here.
        vec![(*name_span, subscript_span.is_none().then_some(&**expr))]
    } else if let AstStmt::SetVariable {
        variable_names,
        values,
        ..
    } = stmt
    {
        if variable_names.len() != values.len() {
            return variable_names
                .iter()
                .map(|name| (name.span, None))
                .collect();
        }
        variable_names
            .iter()
            .zip(values)
            .map(|(name, value)| (name.span, Some(value)))
            .collect()
    } else if let AstStmt::Select(select) = stmt {
        select_assigned_values(select)
            .into_iter()
            .map(|(name, value)| (name, Some(value)))
            .collect()
    } else if let AstStmt::FetchCursor { into_targets, .. } = stmt {
        into_targets
            .iter()
            .map(|target| (target.span, None))
            .collect()
    } else if let AstStmt::ExecuteImmediate { into_vars, .. } = stmt {
        into_vars.iter().map(|target| (*target, None)).collect()
    } else if let AstStmt::MssqlExec(exec) = stmt {
        // An argument written with a modifier after its value (`OUTPUT`,
        // `OUT`; `READONLY` passes a table, never text) holds a variable
        // the procedure may write.
        exec.return_var_span
            .into_iter()
            .chain(exec.args.iter().filter_map(|arg| {
                if arg.span.end <= arg.value.span().end {
                    return None;
                }
                match arg.value.text_node(source) {
                    TextNode::Variable {
                        name: Some(name), ..
                    } => Some(name),
                    TextNode::String(_)
                    | TextNode::Fixed(_)
                    | TextNode::Grouped(_)
                    | TextNode::Choice(_)
                    | TextNode::Converted(_)
                    | TextNode::Joined { .. }
                    | TextNode::Call { .. }
                    | TextNode::Variable { name: None, .. }
                    | TextNode::Other => None,
                }
            }))
            .map(|name| (name, None))
            .collect()
    } else if let AstStmt::For(stmt) = stmt {
        vec![(stmt.loop_var_span, None)]
    } else if let AstStmt::ForEach(stmt) = stmt {
        vec![(stmt.loop_var_span, None)]
    } else if let AstStmt::MysqlSet(set) = stmt {
        use crate::ast::{AstMysqlSetKind, AstMysqlSetTarget};
        match &set.kind {
            AstMysqlSetKind::Assignments(assignments) => assignments
                .iter()
                .filter_map(|assignment| match assignment.target {
                    // A user variable, or a local one (a system variable
                    // written without a scope is spelt the same; no
                    // statement runs its text).
                    AstMysqlSetTarget::UserVar { name_span }
                    | AstMysqlSetTarget::System {
                        scope_span: None,
                        name_span,
                    } => Some((name_span, Some(assignment.value.as_ref()))),
                    AstMysqlSetTarget::SystemAtAt { .. }
                    | AstMysqlSetTarget::System {
                        scope_span: Some(_),
                        ..
                    } => None,
                })
                .collect(),
            // Assign no variable.
            AstMysqlSetKind::Names(_)
            | AstMysqlSetKind::CharacterSet(_)
            | AstMysqlSetKind::Password(_)
            | AstMysqlSetKind::Role(_)
            | AstMysqlSetKind::DefaultRole(_)
            | AstMysqlSetKind::Transaction(_) => Vec::new(),
        }
    } else {
        Vec::new()
    }
}

/// The values a `SELECT` assigns to a variable: T-SQL's `SELECT @v = …`
/// and MySQL's `SELECT @v := …`, and a projected value paired with its
/// `INTO` target by position (`SELECT … INTO :v`, PL/pgSQL's `SELECT …
/// INTO [STRICT] v`).
fn select_assigned_values(select: &crate::ast::AstSelect) -> Vec<(Span, &AstExpr)> {
    use crate::ast::{AstProjectionKind, AstSelectIntoTarget, ProjectionItemKind};
    let items: Vec<Option<&crate::ast::AstSelectItem>> = match &select.projection.kind {
        AstProjectionKind::Columns(items) => items
            .iter()
            .map(|item| match &item.kind {
                ProjectionItemKind::SelectItem(si) => Some(si),
                ProjectionItemKind::JinjaBlock(_) => None,
            })
            .collect(),
        AstProjectionKind::Star(_) => Vec::new(),
    };
    let mut out: Vec<(Span, &AstExpr)> = items
        .iter()
        .flatten()
        .filter_map(|si| Some((si.assign_target.as_ref()?.target.span, &si.expr)))
        .collect();
    let targets: Vec<Span> = match select.into_target.as_deref() {
        Some(AstSelectIntoTarget::ScriptingVars { vars, .. }) => vars.clone(),
        Some(AstSelectIntoTarget::NewTable(_) | AstSelectIntoTarget::OutFile(_)) | None => {
            Vec::new()
        }
    };
    if !targets.is_empty() && targets.len() == items.len() {
        out.extend(
            targets
                .iter()
                .zip(&items)
                .filter_map(|(target, item)| Some((*target, &(*item)?.expr))),
        );
    }
    out
}

/// Walk an [`AstExpr`] collecting any embedded statement-position
/// nodes reachable via the parenthesized / subquery family.
///
/// Used by procedure/function body walkers to surface Snowflake-style
/// RESULTSET assignments — `rs := (EXECUTE IMMEDIATE :stmt USING (a,
/// b));` — where the inner EXECUTE IMMEDIATE rides as
/// [`AstExpr::ScalarSubquery`] inside the RHS expression and otherwise
/// stays invisible to the statement-level walker.
///
/// Module-independent: returns the inner statements as a `Vec<&AstStmt>`
/// so each caller's per-module body walker can iterate and recurse with
/// its own typed `*BodyStatementKindIr`.
pub fn collect_inner_stmts_from_expr<'a>(expr: &'a AstExpr) -> Vec<&'a crate::ast::AstStmt> {
    let mut out: Vec<&'a crate::ast::AstStmt> = Vec::new();
    walk_expr_parts(expr, &mut |part| match part {
        ExprPart::Statement(stmt) => out.push(stmt),
        ExprPart::Call(_) => {}
    });
    out
}

/// What [`walk_expr_parts`] meets in an expression.
enum ExprPart<'a> {
    /// A call of a named function ([`AstExpr::FunctionCall`]); its
    /// arguments are walked.
    Call(&'a AstExpr),
    /// A statement the expression holds: a subquery, or a statement
    /// written as an argument (`TABLE(EXECUTE IMMEDIATE …)`). Not walked.
    Statement(&'a crate::ast::AstStmt),
}

/// Every [`ExprPart`] of `expr`, its sub-expressions at any depth
/// included, in written order. Closed-enum exhaustive over [`AstExpr`].
fn walk_expr_parts<'a>(expr: &'a AstExpr, meet: &mut dyn FnMut(ExprPart<'a>)) {
    use crate::ast::AstExpr as E;
    // An expression nested deeper than the stack lets the analyzer walk is
    // not read.
    let Some(_frame) = crate::ir::lower::enter_nested() else {
        return;
    };
    match expr {
        E::ScalarSubquery { subquery, .. }
        | E::SubqueryArg { subquery, .. }
        | E::ExistsSubquery { subquery, .. } => meet(ExprPart::Statement(subquery)),
        E::InSubquery { expr, subquery, .. } => {
            walk_expr_parts(expr, meet);
            meet(ExprPart::Statement(subquery));
        }
        E::QuantifiedSubquery { left, subquery, .. } => {
            walk_expr_parts(left, meet);
            meet(ExprPart::Statement(subquery));
        }
        E::FunctionCall {
            args,
            inline_order_by,
            within_group,
            filter,
            ..
        } => {
            meet(ExprPart::Call(expr));
            walk_function_args(args, meet);
            for item in inline_order_by.iter().flatten() {
                walk_expr_parts(&item.expr, meet);
            }
            if let Some(within) = within_group {
                for item in &within.order_by {
                    walk_expr_parts(&item.expr, meet);
                }
            }
            if let Some(filter) = filter {
                walk_expr_parts(&filter.expr, meet);
            }
        }
        E::WindowFn {
            args,
            within_group,
            filter,
            window,
            ..
        } => {
            walk_function_args(args, meet);
            if let Some(within) = within_group {
                for item in &within.order_by {
                    walk_expr_parts(&item.expr, meet);
                }
            }
            if let Some(filter) = filter {
                walk_expr_parts(&filter.expr, meet);
            }
            walk_window_spec(window, meet);
        }
        E::WindowExpr { base, window, .. } => {
            walk_expr_parts(base, meet);
            walk_window_spec(window, meet);
        }
        E::MatchAgainst {
            match_call, search, ..
        } => {
            walk_expr_parts(match_call, meet);
            walk_expr_parts(search, meet);
        }
        E::Parenthesized { expr, .. }
        | E::Spread { expr, .. }
        | E::InListOpaque { expr, .. }
        | E::Prior { expr, .. }
        | E::ConnectByRoot { expr, .. }
        | E::IsNull { expr, .. }
        | E::IsPredicate { expr, .. }
        | E::Cast { expr, .. }
        | E::TryCast { expr, .. }
        | E::SafeCast { expr, .. }
        | E::TypeCast { expr, .. }
        | E::Extract { expr, .. }
        | E::Collate { expr, .. } => walk_expr_parts(expr, meet),
        E::ExplSnowIdent { arg, .. } => walk_expr_parts(arg, meet),
        E::TvfWithSchema { func_call, .. } => walk_expr_parts(func_call, meet),
        E::ObjectFieldColon { base, .. }
        | E::ObjectFieldDot { base, .. }
        | E::QualifiedStarFromExpr { base, .. } => walk_expr_parts(base, meet),
        E::BinaryOp { left, right, .. } | E::IsDistinctFrom { left, right, .. } => {
            walk_expr_parts(left, meet);
            walk_expr_parts(right, meet);
        }
        E::ArraySubscript { base, index, .. } => {
            walk_expr_parts(base, meet);
            walk_expr_parts(index, meet);
        }
        E::ObjectFieldBracket { base, field, .. } => {
            walk_expr_parts(base, meet);
            walk_expr_parts(field, meet);
        }
        E::MethodCall { base, args, .. } => {
            walk_expr_parts(base, meet);
            for arg in args {
                walk_expr_parts(arg, meet);
            }
        }
        E::LogicalChain { operands, .. } | E::OperatorChain { operands, .. } => {
            for operand in operands {
                walk_expr_parts(operand, meet);
            }
        }
        E::Case {
            operand,
            whens,
            else_expr,
            ..
        } => {
            if let Some(operand) = operand {
                walk_expr_parts(operand, meet);
            }
            for when in whens {
                walk_expr_parts(&when.cond, meet);
                walk_expr_parts(&when.result, meet);
            }
            if let Some(else_expr) = else_expr {
                walk_expr_parts(else_expr, meet);
            }
        }
        E::InList { expr, list, .. } => {
            walk_expr_parts(expr, meet);
            for item in list {
                walk_expr_parts(item, meet);
            }
        }
        E::Between {
            expr, lower, upper, ..
        } => {
            walk_expr_parts(expr, meet);
            walk_expr_parts(lower, meet);
            walk_expr_parts(upper, meet);
        }
        E::Like {
            expr,
            pattern,
            escape_clause,
            ..
        }
        | E::SimilarTo {
            expr,
            pattern,
            escape_clause,
            ..
        } => {
            walk_expr_parts(expr, meet);
            walk_expr_parts(pattern, meet);
            if let Some(escape) = escape_clause {
                walk_expr_parts(escape, meet);
            }
        }
        E::Position {
            needle, haystack, ..
        } => {
            walk_expr_parts(needle, meet);
            walk_expr_parts(haystack, meet);
        }
        E::Trim { chars, source, .. } => {
            if let Some(chars) = chars {
                walk_expr_parts(chars, meet);
            }
            walk_expr_parts(source, meet);
        }
        E::Substring {
            source,
            from,
            for_len,
            ..
        } => {
            walk_expr_parts(source, meet);
            for part in [from, for_len].into_iter().flatten() {
                walk_expr_parts(part, meet);
            }
        }
        E::AtTimeZone { expr, zone, .. } => {
            walk_expr_parts(expr, meet);
            if let Some(zone) = zone {
                walk_expr_parts(zone, meet);
            }
        }
        E::Array { elements, .. } | E::RowConstructor { elements, .. } => {
            for element in elements {
                walk_expr_parts(element, meet);
            }
        }
        E::Object { entries, .. } => {
            for (key, value) in entries {
                walk_expr_parts(key, meet);
                walk_expr_parts(value, meet);
            }
        }
        E::QualifiedStar { replace, .. } | E::UnqualifiedStar { replace, .. } => {
            for item in replace.iter().flat_map(|replace| &replace.items) {
                walk_expr_parts(&item.expr, meet);
            }
        }
        // Leaves: no expression or statement inside.
        E::Ident { .. }
        | E::Literal { .. }
        | E::Placeholder { .. }
        | E::JinjaPlaceholder { .. }
        | E::JinjaConditional { .. }
        | E::DbtRef { .. }
        | E::DbtSource { .. }
        | E::DbtVar { .. }
        | E::DbtConfig { .. }
        | E::DbtThis { .. }
        | E::PositionRef { .. }
        | E::ScriptingVarRef { .. }
        | E::SessionVarRef { .. }
        | E::TypedStringLiteral { .. }
        | E::Error { .. } => {}
    }
}

/// The parts of a call's arguments ([`walk_expr_parts`]).
fn walk_function_args<'a>(
    args: &'a [Box<crate::ast::AstFunctionArg>],
    meet: &mut dyn FnMut(ExprPart<'a>),
) {
    use crate::ast::AstFunctionArg as A;
    for arg in args {
        match arg.as_ref() {
            A::Positional(value)
            | A::Named { value, .. }
            | A::Lambda { body: value, .. }
            | A::AliasedArg { value, .. }
            | A::BulkArg { value, .. }
            | A::Introduced {
                value: crate::ast::AstIntroducedValue::Expr(value),
                ..
            } => walk_expr_parts(value, meet),
            A::Table {
                partition_by,
                order_by,
                ..
            } => {
                for expr in partition_by {
                    walk_expr_parts(expr, meet);
                }
                for item in order_by {
                    walk_expr_parts(&item.expr, meet);
                }
            }
            A::Unparsed { .. }
            | A::DataType { .. }
            | A::NonValue { .. }
            | A::Introduced {
                value:
                    crate::ast::AstIntroducedValue::DataType { .. }
                    | crate::ast::AstIntroducedValue::Name(_),
                ..
            } => {}
        }
    }
}

/// The parts of a window's `PARTITION BY`, `ORDER BY` and frame bounds
/// ([`walk_expr_parts`]).
fn walk_window_spec<'a>(spec: &'a crate::ast::AstWindowSpec, meet: &mut dyn FnMut(ExprPart<'a>)) {
    for expr in &spec.partition_by {
        walk_expr_parts(expr, meet);
    }
    for item in &spec.order_by {
        walk_expr_parts(&item.expr, meet);
    }
    if let Some(frame) = &spec.frame {
        for bound in std::iter::once(&frame.start).chain(&frame.end) {
            if let Some(value) = &bound.value {
                walk_expr_parts(value, meet);
            }
        }
    }
}

/// What [`statement_parts`] meets in a statement.
enum StatementPart<'a> {
    /// An expression the statement evaluates when it runs.
    Expr(&'a AstExpr),
    /// A function call the statement reads as a table: `FROM TABLE(f(…))`,
    /// `FROM f(…)`.
    Table(&'a AstExpr),
    /// A query the statement runs: a common table expression, a branch
    /// of a set operation, a derived table, an `INSERT`'s query.
    Query(&'a crate::ast::AstStmt),
}

/// Every [`StatementPart`] of `stmt` in written order: the expressions of
/// each clause of a query or a DML statement, of the tables its `FROM`
/// reads and joins, the conditions and values of a scripting statement,
/// the query a statement runs or writes out, and what a definition holds.
/// The statements of a body are statements of their own. Closed-enum
/// exhaustive over [`crate::ast::AstStmt`].
fn statement_parts<'a>(stmt: &'a crate::ast::AstStmt, meet: &mut dyn FnMut(StatementPart<'a>)) {
    use crate::ast::{AstFetchOrientation, AstForIterable, AstMysqlSetKind, AstStmt as S};
    match stmt {
        S::Select(select) => select_parts(select, meet),
        S::Perform(perform) => meet(StatementPart::Query(&perform.query)),
        S::SetSelect(set) => {
            meet(StatementPart::Query(&set.left));
            meet(StatementPart::Query(&set.right));
            order_by_parts(set.order_by.as_deref(), meet);
            for expr in [&set.limit, &set.offset].into_iter().flatten() {
                meet(StatementPart::Expr(expr));
            }
        }
        S::ValuesQuery(values) => {
            for expr in values.values.rows.iter().flatten() {
                meet(StatementPart::Expr(expr));
            }
            order_by_parts(values.order_by.as_deref(), meet);
            for expr in [&values.limit, &values.offset].into_iter().flatten() {
                meet(StatementPart::Expr(expr));
            }
        }
        S::Insert(insert) => {
            with_parts(insert.with_clause.as_ref(), meet);
            for expr in insert.values_rows.iter().flatten() {
                meet(StatementPart::Expr(expr));
            }
            if let Some(query) = &insert.query {
                meet(StatementPart::Query(query));
            }
            for (_, value) in &insert.set_assignments {
                meet(StatementPart::Expr(value));
            }
            if let Some(conflict) = &insert.on_conflict {
                match &conflict.action {
                    crate::ast::AstConflictAction::DoUpdate {
                        set_items,
                        where_clause,
                        ..
                    } => {
                        for assignment in set_items {
                            meet(StatementPart::Expr(&assignment.value));
                        }
                        if let Some(condition) = where_clause {
                            meet(StatementPart::Expr(condition));
                        }
                    }
                    crate::ast::AstConflictAction::DoNothing(_) => {}
                }
            }
            for (_, value) in insert
                .on_duplicate_key_update
                .iter()
                .flat_map(|update| &update.assignments)
            {
                meet(StatementPart::Expr(value));
            }
            returning_parts(insert.returning.as_ref(), meet);
        }
        S::ReplaceInto(replace) => {
            for expr in replace.values_rows.iter().flatten() {
                meet(StatementPart::Expr(expr));
            }
            if let Some(query) = &replace.query {
                meet(StatementPart::Query(query));
            }
            for (_, value) in &replace.set_assignments {
                meet(StatementPart::Expr(value));
            }
        }
        S::MultiInsert(insert) => {
            if let Some(query) = &insert.subquery {
                meet(StatementPart::Query(query));
            }
        }
        S::Update(update) => {
            with_parts(update.with_clause.as_ref(), meet);
            if let Some(top) = &update.top {
                meet(StatementPart::Expr(&top.expr));
            }
            if let Some(target) = &update.target_table {
                table_ref_parts(target, meet);
            }
            for assignment in &update.set_assignments {
                meet(StatementPart::Expr(&assignment.value));
            }
            for table in &update.from {
                table_ref_parts(table, meet);
            }
            if let Some(condition) = &update.where_clause {
                meet(StatementPart::Expr(condition));
            }
            order_by_parts(update.order_by.as_deref(), meet);
            if let Some(limit) = &update.limit {
                meet(StatementPart::Expr(limit));
            }
            returning_parts(update.returning.as_ref(), meet);
        }
        S::Delete(delete) => {
            with_parts(delete.with_clause.as_ref(), meet);
            if let Some(top) = &delete.top {
                meet(StatementPart::Expr(&top.expr));
            }
            for table in delete
                .target_table
                .iter()
                .chain(&delete.targets)
                .chain(&delete.using)
            {
                table_ref_parts(table, meet);
            }
            if let Some(condition) = &delete.where_clause {
                meet(StatementPart::Expr(condition));
            }
            order_by_parts(delete.order_by.as_deref(), meet);
            if let Some(limit) = &delete.limit {
                meet(StatementPart::Expr(limit));
            }
            returning_parts(delete.returning.as_ref(), meet);
        }
        S::Merge(merge) => {
            with_parts(merge.with_clause.as_ref(), meet);
            if let Some(table) = &merge.using_table_ref {
                table_ref_parts(table, meet);
            }
            if let Some(query) = &merge.using_subquery {
                meet(StatementPart::Query(query));
            }
            if let Some(condition) = &merge.on_condition {
                meet(StatementPart::Expr(condition));
            }
            for clause in &merge.clauses {
                if let Some(condition) = &clause.and_condition {
                    meet(StatementPart::Expr(condition));
                }
                match &clause.action {
                    crate::ast::AstMergeActionKind::UpdateSet { assignments, .. } => {
                        for assignment in assignments {
                            meet(StatementPart::Expr(&assignment.value));
                        }
                    }
                    crate::ast::AstMergeActionKind::InsertValues { values, .. } => {
                        for value in values {
                            meet(StatementPart::Expr(value));
                        }
                    }
                    crate::ast::AstMergeActionKind::UpdateAllByName { .. }
                    | crate::ast::AstMergeActionKind::UpdateSetStar { .. }
                    | crate::ast::AstMergeActionKind::Delete { .. }
                    | crate::ast::AstMergeActionKind::DoNothing { .. }
                    | crate::ast::AstMergeActionKind::InsertAllByName { .. }
                    | crate::ast::AstMergeActionKind::InsertStar { .. }
                    | crate::ast::AstMergeActionKind::InsertRow { .. } => {}
                }
            }
            returning_parts(merge.returning.as_ref(), meet);
        }
        S::Assign { expr, .. } | S::Let { expr, .. } => meet(StatementPart::Expr(expr)),
        S::SetVariable { values, .. } => {
            for value in values {
                meet(StatementPart::Expr(value));
            }
        }
        S::MysqlSet(set) => match &set.kind {
            AstMysqlSetKind::Assignments(assignments) => {
                for assignment in assignments {
                    meet(StatementPart::Expr(&assignment.value));
                }
            }
            AstMysqlSetKind::Names(_)
            | AstMysqlSetKind::CharacterSet(_)
            | AstMysqlSetKind::Password(_)
            | AstMysqlSetKind::Role(_)
            | AstMysqlSetKind::DefaultRole(_)
            | AstMysqlSetKind::Transaction(_) => {}
        },
        S::Declare { variables, .. } => {
            for value in variables.iter().filter_map(|v| v.default_expr.as_deref()) {
                meet(StatementPart::Expr(value));
            }
        }
        S::Return { expr, .. } => {
            if let Some(expr) = expr {
                meet(StatementPart::Expr(expr));
            }
        }
        S::Raise {
            message_expr,
            message_args,
            using_options,
            ..
        } => {
            for expr in message_expr.as_deref().into_iter().chain(message_args) {
                meet(StatementPart::Expr(expr));
            }
            for option in using_options {
                meet(StatementPart::Expr(&option.value));
            }
        }
        S::If(stmt) => {
            for branch in &stmt.branches {
                meet(StatementPart::Expr(&branch.condition));
            }
        }
        S::CaseStmt(stmt) => {
            if let Some(operand) = &stmt.operand {
                meet(StatementPart::Expr(operand));
            }
            for branch in &stmt.branches {
                meet(StatementPart::Expr(&branch.condition));
                for value in &branch.more_values {
                    meet(StatementPart::Expr(value));
                }
            }
        }
        S::While(stmt) => meet(StatementPart::Expr(&stmt.condition)),
        S::MssqlIf(stmt) => meet(StatementPart::Expr(&stmt.condition)),
        S::MssqlWhile(stmt) => meet(StatementPart::Expr(&stmt.condition)),
        // A rule's commands are a body; its condition is read here.
        S::PgCreateRule(rule) => {
            if let Some(condition) = &rule.condition {
                meet(StatementPart::Expr(condition));
            }
        }
        S::MssqlCreateRule(rule) => meet(StatementPart::Expr(&rule.condition)),
        S::ExecuteTask(_) | S::MysqlCreateLoadableFunction(_) | S::MysqlAdmin(_) => {}
        S::MysqlDo(mysql_do) => {
            for expr in &mysql_do.exprs {
                meet(StatementPart::Expr(expr));
            }
        }
        S::Repeat(stmt) => meet(StatementPart::Expr(&stmt.until_condition)),
        // The query a FOR loop iterates is a statement of its own.
        S::For(stmt) => match &stmt.iterates {
            AstForIterable::Range {
                low, high, step, ..
            } => {
                meet(StatementPart::Expr(low));
                meet(StatementPart::Expr(high));
                if let Some(step) = step {
                    meet(StatementPart::Expr(step));
                }
            }
            AstForIterable::Expr(expr) => meet(StatementPart::Expr(expr)),
            AstForIterable::Query(_) => {}
        },
        S::Call { args, .. } => {
            for arg in args {
                meet(StatementPart::Expr(&arg.value));
            }
        }
        S::MssqlExec(exec) => {
            for arg in &exec.args {
                meet(StatementPart::Expr(&arg.value));
            }
        }
        S::ExecuteImmediate {
            sql_expr,
            using_args,
            ..
        } => {
            meet(StatementPart::Expr(sql_expr));
            for arg in using_args {
                meet(StatementPart::Expr(&arg.expr));
            }
        }
        S::DeclareCursor { query, .. } => meet(StatementPart::Query(query)),
        S::LetCursor { parsed_query, .. } => {
            if let Some(query) = parsed_query {
                meet(StatementPart::Query(query));
            }
        }
        S::CreateTable(create) => create_table_parts(create, meet),
        S::AlterTable(alter) => {
            for action in &alter.actions {
                alter_table_action_parts(&action.kind, meet);
            }
        }
        S::ForEach(stmt) => meet(StatementPart::Expr(&stmt.array_expr)),
        S::FetchCursor { orientation, .. } => match orientation {
            Some(
                AstFetchOrientation::Absolute(expr)
                | AstFetchOrientation::Relative(expr)
                | AstFetchOrientation::Forward(Some(crate::ast::AstFetchCount::Count(expr)))
                | AstFetchOrientation::Backward(Some(crate::ast::AstFetchCount::Count(expr))),
            ) => meet(StatementPart::Expr(expr)),
            Some(
                AstFetchOrientation::Next
                | AstFetchOrientation::Prior
                | AstFetchOrientation::First
                | AstFetchOrientation::Last
                | AstFetchOrientation::All
                | AstFetchOrientation::Forward(None | Some(crate::ast::AstFetchCount::All))
                | AstFetchOrientation::Backward(None | Some(crate::ast::AstFetchCount::All)),
            )
            | None => {}
        },
        S::BqAssert(assert) => {
            meet(StatementPart::Expr(&assert.expression));
            if let Some(message) = &assert.message {
                meet(StatementPart::Expr(message));
            }
        }
        // The statement explained, which `EXPLAIN ANALYZE` runs.
        S::Explain(explain) => meet(StatementPart::Query(&explain.inner_stmt)),
        S::Break { condition, .. } | S::Continue { condition, .. } => {
            if let Some(condition) = condition {
                meet(StatementPart::Expr(condition));
            }
        }
        S::PsqlGexec(gexec) => meet(StatementPart::Query(&gexec.query)),
        S::PgCopy(copy) => match &copy.subject {
            crate::ast::PgCopySubject::Query(_, query) => meet(StatementPart::Query(query)),
            crate::ast::PgCopySubject::Table(_) => {}
        },
        S::CopyIntoLocation { source, .. } => match source {
            Some(crate::ast::AstUnloadSource::Subquery(query)) => meet(StatementPart::Query(query)),
            Some(crate::ast::AstUnloadSource::Table { .. }) | None => {}
        },
        S::BqExportData(export) => meet(StatementPart::Query(&export.query)),
        S::BqCreateModel(model) => {
            if let Some(query) = &model.query {
                meet(StatementPart::Query(query));
            }
        }
        S::CacheTable(cache) => {
            if let Some(query) = &cache.query {
                meet(StatementPart::Query(query));
            }
        }
        S::Optimize(optimize) => {
            if let Some(condition) = &optimize.where_predicate {
                meet(StatementPart::Expr(condition));
            }
        }
        S::Restore(restore) => meet(StatementPart::Expr(&restore.time_travel.value)),
        S::CreateDatabase(create) => match &create.variant {
            crate::ast::AstCreateDatabaseVariant::Clone { time_travel, .. } => {
                if let Some(clause) = time_travel.as_deref() {
                    time_travel_parts(clause, meet);
                }
            }
            crate::ast::AstCreateDatabaseVariant::Standard
            | crate::ast::AstCreateDatabaseVariant::FromShare { .. }
            | crate::ast::AstCreateDatabaseVariant::FromListing { .. }
            | crate::ast::AstCreateDatabaseVariant::AsReplica { .. }
            | crate::ast::AstCreateDatabaseVariant::FromBackup { .. } => {}
        },
        S::CreateSchema(create) => match &create.variant {
            crate::ast::AstCreateSchemaVariant::Clone { time_travel, .. } => {
                if let Some(clause) = time_travel.as_deref() {
                    time_travel_parts(clause, meet);
                }
            }
            crate::ast::AstCreateSchemaVariant::Standard => {}
        },
        // A task's body is a statement of its own.
        S::CreateTask(_) => {}
        S::PipeChain { stmts, .. } => {
            for stmt in stmts {
                meet(StatementPart::Query(stmt));
            }
        }
        S::JinjaConditionalStmt(block) => {
            for stmt in block
                .then_stmts
                .iter()
                .chain(block.elif_branches.iter().flat_map(|branch| &branch.stmts))
                .chain(block.else_branch.iter().flat_map(|branch| &branch.stmts))
            {
                meet(StatementPart::Query(stmt));
            }
        }
        S::ClauseFragment { fragment, .. } => {
            for item in fragment.from_items.iter().flatten() {
                match &item.kind {
                    crate::ast::FromItemKind::TableRef(table) => table_ref_parts(table, meet),
                    crate::ast::FromItemKind::JinjaBlock(_)
                    | crate::ast::FromItemKind::JinjaTableName(_) => {}
                }
            }
            for join in &fragment.joins {
                join_parts(join, meet);
            }
            if let Some(clause) = &fragment.where_clause {
                condition_parts(clause, meet);
            }
            if let Some(group_by) = &fragment.group_by {
                group_by_parts(group_by, meet);
            }
            if let Some(clause) = &fragment.having_clause {
                condition_parts(clause, meet);
            }
        }
        // What a definition holds runs when what it defines does: a view's
        // query when it is read (a materialized view's and a dynamic table's
        // when created too), a policy's body when it applies, a default when
        // it is taken, an index's predicate on each row it indexes, an
        // alert's or a task's statement when it fires.
        S::CreateView(create) => query_parts(create.query.as_deref(), meet),
        S::CreateDynamicTable(create) => query_parts(create.query.as_deref(), meet),
        S::PgPrepare(prepare) => {
            meet(StatementPart::Query(&prepare.body));
            if let Some(text) = &prepare.from_expr {
                meet(StatementPart::Expr(text));
            }
        }
        S::CreateFunction(create) => param_default_parts(&create.params, meet),
        S::CreateProcedure(create) => param_default_parts(&create.params, meet),
        S::CreateTableFunction(create) => param_default_parts(&create.params, meet),
        S::CreateIndex(create) => {
            for key in &create.column_exprs {
                meet(StatementPart::Expr(key));
            }
            if let Some(condition) = &create.where_predicate {
                meet(StatementPart::Expr(condition));
            }
        }
        S::CreateDomain(create) => {
            if let Some(default) = &create.default_expr {
                meet(StatementPart::Expr(default));
            }
            for constraint in &create.constraints {
                domain_constraint_parts(constraint, meet);
            }
        }
        S::AlterDomain(alter) => match &alter.action {
            crate::ast::AlterDomainAction::SetDefault { expression, .. } => {
                meet(StatementPart::Expr(expression))
            }
            crate::ast::AlterDomainAction::AddConstraint { constraint, .. } => {
                domain_constraint_parts(constraint, meet)
            }
            crate::ast::AlterDomainAction::DropDefault { .. }
            | crate::ast::AlterDomainAction::SetNotNull { .. }
            | crate::ast::AlterDomainAction::DropNotNull { .. }
            | crate::ast::AlterDomainAction::DropConstraint { .. }
            | crate::ast::AlterDomainAction::RenameConstraint { .. }
            | crate::ast::AlterDomainAction::ValidateConstraint { .. }
            | crate::ast::AlterDomainAction::OwnerTo { .. }
            | crate::ast::AlterDomainAction::RenameTo { .. }
            | crate::ast::AlterDomainAction::SetSchema { .. } => {}
        },
        S::CreatePgPolicy(create) => {
            expr_parts(create.using_expr.as_deref(), meet);
            expr_parts(create.check_expr.as_deref(), meet);
        }
        S::AlterPgPolicy(alter) => match &alter.action {
            crate::ast::AlterPgPolicyAction::Modify {
                using_expr,
                check_expr,
                ..
            } => {
                expr_parts(using_expr.as_deref(), meet);
                expr_parts(check_expr.as_deref(), meet);
            }
            crate::ast::AlterPgPolicyAction::Rename { .. } => {}
        },
        S::CreateRowAccessPolicy(create) => {
            for expr in [&create.filter_expr, &create.body].into_iter().flatten() {
                meet(StatementPart::Expr(expr));
            }
        }
        S::AlterRowAccessPolicy(alter) => {
            use crate::ast::AstAlterRowAccessPolicyActionKind as K;
            match &alter.action.kind {
                K::SetBody { body, .. } => meet(StatementPart::Expr(body)),
                K::RenameTo { .. }
                | K::SetTag { .. }
                | K::UnsetTag { .. }
                | K::SetComment { .. }
                | K::UnsetComment { .. } => {}
            }
        }
        S::CreateMaskingPolicy(create) => meet(StatementPart::Expr(&create.body)),
        S::AlterMaskingPolicy(alter) => {
            use crate::ast::AstAlterMaskingPolicyActionKind as K;
            match &alter.action.kind {
                K::SetBody { body, .. } => meet(StatementPart::Expr(body)),
                K::RenameTo { .. }
                | K::SetTag { .. }
                | K::UnsetTag { .. }
                | K::SetComment { .. }
                | K::UnsetComment { .. } => {}
            }
        }
        S::CreateAggregationPolicy(create) => {
            if let Some(body) = &create.body {
                meet(StatementPart::Expr(body));
            }
        }
        S::AlterAggregationPolicy(alter) => {
            use crate::ast::AstAlterAggregationPolicyActionKind as K;
            for action in &alter.actions {
                match &action.kind {
                    K::SetBody { expression, .. } => {
                        if let Some(body) = expression {
                            meet(StatementPart::Expr(body));
                        }
                    }
                    K::RenameTo { .. }
                    | K::SetComment { .. }
                    | K::UnsetComment { .. }
                    | K::SetTag { .. }
                    | K::UnsetTag { .. } => {}
                }
            }
        }
        S::CreateProjectionPolicy(create) => {
            if let Some(body) = &create.body_expr {
                meet(StatementPart::Expr(body));
            }
        }
        S::AlterProjectionPolicy(alter) => {
            use crate::ast::AstAlterProjectionPolicyActionKind as K;
            match &alter.action.kind {
                K::SetBody { body_expr, .. } => {
                    if let Some(body) = body_expr {
                        meet(StatementPart::Expr(body));
                    }
                }
                K::RenameTo { .. }
                | K::SetTag { .. }
                | K::UnsetTag { .. }
                | K::SetComment { .. }
                | K::UnsetComment { .. } => {}
            }
        }
        S::CreateJoinPolicy(create) => {
            if let Some(body) = &create.body_expr {
                meet(StatementPart::Expr(body));
            }
        }
        S::AlterJoinPolicy(alter) => {
            use crate::ast::AstAlterJoinPolicyActionKind as K;
            match &alter.action.kind {
                K::SetBody { body_expr, .. } => {
                    if let Some(body) = body_expr {
                        meet(StatementPart::Expr(body));
                    }
                }
                K::RenameTo { .. }
                | K::SetComment { .. }
                | K::UnsetComment
                | K::SetTag { .. }
                | K::UnsetTag { .. } => {}
            }
        }
        S::CreateAlert(create) => {
            expr_parts(create.condition.as_deref(), meet);
            if let Some(action) = &create.action {
                query_parts(action.as_deref(), meet);
            }
        }
        S::AlterAlert(alter) => {
            use crate::ast::AstAlterAlertActionKind as K;
            match &alter.action.kind {
                K::ModifyCondition { condition, .. } => expr_parts(condition.as_deref(), meet),
                K::ModifyAction { body, .. } => query_parts(body.as_deref(), meet),
                K::Resume { .. } | K::Suspend { .. } | K::Set { .. } | K::Unset { .. } => {}
            }
        }
        S::CreatePgTrigger(create) => expr_parts(create.when_expr.as_deref(), meet),
        S::AlterTask(alter) => {
            use crate::ast::AstAlterTaskActionKind as K;
            match &alter.action.kind {
                K::ModifyAs { body, .. } => query_parts(body.as_deref(), meet),
                K::ModifyWhen { .. } => {}
                K::Resume { .. }
                | K::Suspend { .. }
                | K::AddAfter { .. }
                | K::RemoveAfter { .. }
                | K::Set { .. }
                | K::SetTag { .. }
                | K::SetFinalize { .. }
                | K::Unset { .. }
                | K::UnsetTag { .. }
                | K::UnsetFinalize { .. }
                | K::RemoveWhen { .. } => {}
            }
        }
        // A statement with no expression or statement it runs beside the
        // statements of its bodies, which are statements of their own; one
        // whose expressions name objects only (`IDENTIFIER(…)` takes a
        // literal or a variable) or are built-in clustering keys; one whose
        // clauses are held as text only; or one of the template's.
        S::OpaqueContent { .. }
        | S::JinjaPlaceholder { .. }
        | S::Error { .. }
        | S::GoBatchSeparator { .. }
        | S::SqlcmdCommand { .. }
        | S::AlterAccount(_)
        | S::AlterApiIntegration(_)
        | S::AlterNotificationIntegration(_)
        | S::CreateShare(_)
        | S::AlterShare(_)
        | S::CreateDatashare(_)
        | S::AlterDatashare(_)
        | S::CreateSecurityIntegration(_)
        | S::AlterSecurityIntegration(_)
        | S::AlterReplicationGroup(_)
        | S::AlterFailoverGroup(_)
        | S::AlterAuthenticationPolicy(_)
        | S::AlterCatalog(_)
        | S::AlterConnection(_)
        | S::AlterDatabase(_)
        | S::AlterDynamicTable(_)
        | S::AlterExternalAccessIntegration(_)
        | S::AlterExternalLocation(_)
        | S::AlterFunction(_)
        | S::AlterIndex(_)
        | S::AlterMaterializedView(_)
        | S::AlterNetworkPolicy(_)
        | S::AlterPasswordPolicy(_)
        | S::AlterPgTrigger(_)
        | S::AlterPipe(_)
        | S::AlterProcedure(_)
        | S::AlterSchema(_)
        | S::AlterSequence(_)
        | S::AlterSessionPolicy(_)
        | S::AlterSession(_)
        | S::AlterStage(_)
        | S::AlterStorageCredential(_)
        | S::AlterStorageIntegration(_)
        | S::AlterStream(_)
        | S::AlterType(_)
        | S::AlterUser(_)
        | S::AlterView(_)
        | S::AlterVolume(_)
        | S::AlterWarehouse(_)
        | S::AnalyzeStmt(_)
        | S::Await { .. }
        | S::BeginTransaction { .. }
        | S::Block(_)
        | S::BqAlterModel(_)
        | S::BqAlterVectorIndex(_)
        | S::BqCreateSearchIndex(_)
        | S::BqCreateSnapshotTable(_)
        | S::BqCreateVectorIndex(_)
        | S::BqDropModel(_)
        | S::BqDropSearchIndex(_)
        | S::BqDropSnapshotTable(_)
        | S::BqDropVectorIndex(_)
        | S::BqExportModel(_)
        | S::BqLoadData(_)
        | S::MysqlLoadData(_)
        | S::MysqlRenameTable(_)
        | S::CreateEvent(_)
        | S::AlterEvent(_)
        | S::CreateMysqlTrigger(_)
        | S::Cancel { .. }
        | S::CloseCursor { .. }
        | S::CommentOn(_)
        | S::Commit { .. }
        | S::Unload { .. }
        | S::RedshiftCopy { .. }
        | S::CopyIntoTable { .. }
        | S::CreateApiIntegration(_)
        | S::CreateNotificationIntegration(_)
        | S::CreateAuthenticationPolicy(_)
        | S::CreateCatalog(_)
        | S::AlterUserMapping(_)
        | S::DropUserMapping(_)
        | S::CreateUserMapping(_)
        | S::CreateForeignTable(_)
        | S::ImportForeignSchema(_)
        | S::CreateForeignServer(_)
        | S::AlterForeignServer(_)
        | S::MssqlAlterServerConfiguration(_)
        | S::MssqlCreateExternalDataSource(_)
        | S::MssqlAlterExternalDataSource(_)
        | S::CreateConnection(_)
        | S::CreateExtension(_)
        | S::CreateExternalAccessIntegration(_)
        | S::CreateExternalLocation(_)
        | S::CreateExternalTable(_)
        | S::CreateExternalSchema(_)
        | S::CreateFlow(_)
        | S::CreateSynonym(_)
        | S::CreateMssqlTrigger(_)
        | S::CreateNetworkPolicy(_)
        | S::CreatePasswordPolicy(_)
        | S::CreatePipe(_)
        | S::CreateSequence(_)
        | S::CreateSessionPolicy(_)
        | S::CreateStage(_)
        | S::CreateStorageCredential(_)
        | S::CreateStorageIntegration(_)
        | S::CreateStream(_)
        | S::CreateType(_)
        | S::CreateVolume(_)
        | S::CreateWarehouse(_)
        | S::DeclareCondition { .. }
        | S::DeclareHandler(_)
        | S::DeclareTable { .. }
        | S::Deny(_)
        | S::AlterAuthorization(_)
        | S::MssqlExecuteAs(_)
        | S::MssqlRevert { .. }
        | S::MssqlAuditDdl(_)
        | S::MssqlSecurityObjectDdl(_)
        | S::Describe(_)
        | S::DescribeHistory(_)
        | S::MssqlBackup(_)
        | S::MssqlRestore(_)
        | S::MssqlDbcc(_)
        | S::MssqlKeyManagement(_)
        | S::MssqlSecurityPolicy(_)
        | S::MssqlKeyBackup(_)
        | S::MssqlAssembly(_)
        | S::MssqlAddSignature(_)
        | S::MssqlSetuser(_)
        | S::MssqlAlterServiceMasterKey(_)
        | S::PgAlterDefaultPrivileges(_)
        | S::DoBlock(_)
        | S::Drop(_)
        | S::DropAggregationPolicy(_)
        | S::DropAllRowAccessPolicies(_)
        | S::DropApiIntegration(_)
        | S::DropNotificationIntegration(_)
        | S::DropAuthenticationPolicy(_)
        | S::DropCatalog(_)
        | S::DropConnection(_)
        | S::DropDatabase(_)
        | S::DropDomain(_)
        | S::DropExternalAccessIntegration(_)
        | S::DropExternalLocation(_)
        | S::DropMaskingPolicy(_)
        | S::DropMssqlTrigger(_)
        | S::MssqlTriggerState(_)
        | S::DropNetworkPolicy(_)
        | S::DropPasswordPolicy(_)
        | S::DropPgPolicy(_)
        | S::DropPgTrigger(_)
        | S::DropPipe(_)
        | S::DropProjectionPolicy(_)
        | S::DropJoinPolicy(_)
        | S::DropRowAccessPolicy(_)
        | S::DropSchema(_)
        | S::DropSessionPolicy(_)
        | S::DropStorageCredential(_)
        | S::DropStorageIntegration(_)
        | S::DropStream(_)
        | S::DropTask(_)
        | S::DropVolume(_)
        | S::DropWarehouse(_)
        | S::ExecuteImmediateFrom(_)
        | S::GetDiagnostics { .. }
        | S::Grant(_)
        | S::Loop(_)
        | S::MssqlAlterExternalModel(_)
        | S::MssqlBulkInsert(_)
        | S::MssqlCreateExternalModel(_)
        | S::MssqlCreateVectorIndex(_)
        | S::MssqlDropExternalModel(_)
        | S::MssqlGoto(_)
        | S::MssqlLabel(_)
        | S::MssqlPrint(_)
        | S::MssqlRaiserror(_)
        | S::MssqlSetOption(_)
        | S::MysqlUnlockTables(_)
        | S::MssqlThrow(_)
        | S::MssqlTryCatch(_)
        | S::MssqlWaitfor(_)
        | S::Null { .. }
        | S::OpenCursor { .. }
        | S::AlterPrincipal(_)
        | S::PgAlterRule(_)
        | S::PgAlterSystem(_)
        | S::PgAlterTableTriggerState(_)
        | S::PgAlterTablespace(_)
        | S::PgCluster(_)
        | S::PgCreateAggregate(_)
        | S::PgCreateOperator(_)
        | S::CreatePrincipal(_)
        | S::PgCreateTablespace(_)
        | S::PgDeallocate(_)
        | S::PgDiscard(_)
        | S::PgDropExtension(_)
        | S::PgDropIndex(_)
        | S::PgDropOwned(_)
        | S::DropPrincipal(_)
        | S::PgDropRule(_)
        | S::PgDropSequence(_)
        | S::PgDropTablespace(_)
        | S::PgDropType(_)
        | S::PgExecute(_)
        | S::PgListen(_)
        | S::PgLockTable(_)
        | S::PgNotify(_)
        | S::PgPublication(_)
        | S::PgReassignOwned(_)
        | S::PgRefreshMatview(_)
        | S::PgSet(_)
        | S::PgSubscription(_)
        | S::PgUnlisten(_)
        | S::Reconfigure { .. }
        | S::MssqlServerCommand { .. }
        | S::Reindex(_)
        | S::RepairTable(_)
        | S::Resignal { .. }
        | S::Revoke(_)
        | S::Rollback { .. }
        | S::Savepoint(_)
        | S::Show(_)
        | S::Signal { .. }
        | S::Truncate(_)
        | S::UncacheTable(_)
        | S::UndropDatabase(_)
        | S::UndropSchema(_)
        | S::UndropTable(_)
        | S::UndropType(_)
        | S::CreateTag(_)
        | S::AlterTag(_)
        | S::CreateFileFormat(_)
        | S::AlterFileFormat(_)
        | S::UndropTag(_)
        | S::CreateSecret(_)
        | S::AlterSecret(_)
        | S::CreateNetworkRule(_)
        | S::AlterNetworkRule(_)
        | S::CreateResourceMonitor(_)
        | S::AlterResourceMonitor(_)
        | S::CreateComputePool(_)
        | S::AlterComputePool(_)
        | S::CreateGitRepository(_)
        | S::CreateExternalFunction(_)
        | S::AlterGitRepository(_)
        | S::CreateImageRepository(_)
        | S::AlterImageRepository(_)
        | S::CreateStreamlit(_)
        | S::AlterStreamlit(_)
        | S::CreateService(_)
        | S::AlterService(_)
        | S::CreateNotebook(_)
        | S::AlterNotebook(_)
        | S::CreateSemanticView(_)
        | S::AlterSemanticView(_)
        | S::CreateCortexSearchService(_)
        | S::AlterCortexSearchService(_)
        | S::CreateApplication(_)
        | S::AlterApplication(_)
        | S::CreateApplicationPackage(_)
        | S::AlterApplicationPackage(_)
        | S::CreateListing(_)
        | S::AlterListing(_)
        | S::CreateManagedAccount(_)
        | S::CreateAccount(_)
        | S::StageFileCommand(_)
        | S::CreateDataMetricFunction(_)
        | S::CreateReplicationFailoverGroup(_)
        | S::Use(_)
        | S::Vacuum(_) => {}
    }
}

/// What a `CREATE TABLE` holds ([`statement_parts`]): the query of a
/// `CREATE TABLE … AS`, the point a clone reads at, the clustering keys,
/// and, as their text, each column's default, generated expression and
/// constraints, each table constraint no reader parsed, and the partition
/// key.
fn create_table_parts<'a>(
    create: &'a crate::ast::AstCreateTable,
    meet: &mut dyn FnMut(StatementPart<'a>),
) {
    if let Some(Ok(query)) = &create.ctas_query {
        meet(StatementPart::Query(query));
    }
    if let Some(clause) = create.time_travel.as_deref() {
        time_travel_parts(clause, meet);
    }
    for key in create.cluster_by_exprs.iter().flatten() {
        meet(StatementPart::Expr(key));
    }
    for column in &create.columns {
        column_parts(column, meet);
    }
    for constraint in &create.constraints {
        constraint_parts(constraint.expressions.as_deref(), meet);
    }
}

/// What a column definition holds ([`statement_parts`]): its default, its
/// generated expression and its own `CHECK`'s condition, each where it is
/// read.
fn column_parts<'a>(
    column: &'a crate::ast::AstCreateTableColumn,
    meet: &mut dyn FnMut(StatementPart<'a>),
) {
    for expr in [
        &column.default_expr,
        &column.virtual_expr,
        &column.check_expr,
    ] {
        expr_parts(expr.as_deref(), meet);
    }
}

/// What a table constraint holds ([`statement_parts`]): each expression it
/// holds where every one is read.
fn constraint_parts<'a>(
    expressions: Option<&'a [AstExpr]>,
    meet: &mut dyn FnMut(StatementPart<'a>),
) {
    for expr in expressions.into_iter().flatten() {
        meet(StatementPart::Expr(expr));
    }
}

/// What an `ALTER TABLE` action holds ([`statement_parts`]): the clustering
/// keys, the expressions of a column it adds, a default and a constraint it
/// writes, and, as its text, each it holds that no reader parsed: a column
/// it changes, a partition's bound, an action no reader classified.
fn alter_table_action_parts<'a>(
    action: &'a crate::ast::AstAlterTableActionKind,
    meet: &mut dyn FnMut(StatementPart<'a>),
) {
    use crate::ast::{AstAlterTableActionKind as K, AstNamedTableAction as N};
    match action {
        K::ChangeColumn { .. } | K::AlterColumn { .. } | K::AlterColumnList { .. } => {}
        K::AddColumn { columns, .. } => {
            for definition in columns
                .iter()
                .filter_map(|column| column.definition.as_deref())
            {
                column_parts(definition, meet);
            }
        }
        K::AddConstraint { expressions, .. } => constraint_parts(expressions.as_deref(), meet),
        K::ClusterBy { exprs, .. } => {
            for key in exprs.iter().flatten() {
                meet(StatementPart::Expr(key));
            }
        }

        K::AlterColumnSetDefault { expr, .. } => expr_parts(expr.as_deref(), meet),
        K::AttachPartition { .. } | K::GovernanceSpan { .. } | K::Unknown { .. } => {}
        K::NamedAction { kind, .. } => match kind {
            N::AddCheck
            | N::AddDefault
            | N::AddPartition
            | N::AddPeriod
            | N::AlterConstraint
            | N::PartitionMaintenance => {}
            N::DropConstraint
            | N::DropIndex
            | N::DropForeignKey
            | N::DropCheck
            | N::DropPartition
            | N::DropPeriod
            | N::AddPrimaryKey
            | N::AddUnique
            | N::AddIndex
            | N::CheckConstraint
            | N::NocheckConstraint
            | N::EnableTrigger
            | N::DisableTrigger
            | N::ChangeTracking
            | N::FiletableNamespace
            | N::Rebuild
            | N::RenameIndex
            | N::RenameConstraint
            | N::AlterIndex
            | N::ValidateConstraint
            | N::TableOption
            | N::Inherit
            | N::NoInherit
            | N::ReplicaIdentity
            | N::Distribution
            | N::RuleState
            | N::SearchOptimization
            | N::DropUnique
            | N::ResetOptions
            | N::RowLevelSecurity
            | N::KeysState
            | N::DropFeature
            | N::PredictiveOptimization => {}
        },
        // An option list the parser reads as names and values, a secret's
        // value recorded where its name takes one.
        K::SetOptions { .. }
        | K::AlterColumnSetOptions { .. }
        | K::RenameTo { .. }
        | K::RenameColumn { .. }
        | K::SwapWith { .. }
        | K::DropColumn { .. }
        | K::DropConstraint { .. }
        | K::DropClusteringKey { .. }
        | K::SuspendRecluster { .. }
        | K::ResumeRecluster { .. }
        | K::Set { .. }
        | K::Unset { .. }
        | K::AddRowAccessPolicy(_)
        | K::DropRowAccessPolicy { .. }
        | K::DropAllRowAccessPolicies { .. }
        | K::SetRowFilter { .. }
        | K::DropRowFilter { .. }
        | K::SetAggregationPolicy { .. }
        | K::UnsetAggregationPolicy { .. }
        | K::SetJoinPolicy { .. }
        | K::UnsetJoinPolicy { .. }
        | K::SetColumnMaskingPolicy(_)
        | K::UnsetColumnMaskingPolicy { .. }
        | K::SetColumnMask { .. }
        | K::DropColumnMask { .. }
        | K::SetColumnProjectionPolicy(_)
        | K::UnsetColumnProjectionPolicy { .. }
        | K::SetTag { .. }
        | K::UnsetTag { .. }
        | K::SetColumnTag { .. }
        | K::UnsetColumnTag { .. }
        | K::AddSearchOptimization { .. }
        | K::DropSearchOptimization { .. }
        | K::SetDataMetricSchedule { .. }
        | K::UnsetDataMetricSchedule { .. }
        | K::AddDataMetricFunction { .. }
        | K::DropDataMetricFunction { .. }
        | K::AddStorageLifecyclePolicy { .. }
        | K::DropStorageLifecyclePolicy { .. }
        | K::SetDefaultCollate { .. }
        | K::DropPrimaryKey { .. }
        | K::AlterColumnDropNotNull { .. }
        | K::AlterColumnSetDataType { .. }
        | K::AlterColumnDropDefault { .. }
        | K::SetTblProperties { .. }
        | K::UnsetTblProperties { .. }
        | K::RowLevelSecurity { .. }
        | K::OwnerTo { .. }
        | K::SetSchema { .. }
        | K::DetachPartition { .. }
        | K::SwitchTo { .. } => {}
    }
}

/// The expression `expr` of a statement, where it was read
/// ([`statement_parts`]).
fn expr_parts<'a>(expr: Option<&'a AstExpr>, meet: &mut dyn FnMut(StatementPart<'a>)) {
    if let Some(expr) = expr {
        meet(StatementPart::Expr(expr));
    }
}

/// The query a statement runs, where it was read ([`statement_parts`]).
fn query_parts<'a>(
    query: Result<&'a crate::ast::AstStmt, &Span>,
    meet: &mut dyn FnMut(StatementPart<'a>),
) {
    if let Ok(query) = query {
        meet(StatementPart::Query(query));
    }
}

/// The defaults of a routine's parameters ([`statement_parts`]).
fn param_default_parts<'a>(
    params: &'a [crate::ast::AstProcedureParam],
    meet: &mut dyn FnMut(StatementPart<'a>),
) {
    for param in params {
        expr_parts(param.default_expr.as_deref(), meet);
    }
}

/// The condition of a domain's `CHECK` ([`statement_parts`]).
fn domain_constraint_parts<'a>(
    constraint: &'a crate::ast::DomainConstraint,
    meet: &mut dyn FnMut(StatementPart<'a>),
) {
    use crate::ast::DomainConstraintKind;
    match &constraint.kind {
        DomainConstraintKind::Check { expression, .. } => meet(StatementPart::Expr(expression)),
        DomainConstraintKind::NotNull { .. } | DomainConstraintKind::Null { .. } => {}
    }
}

/// The parts of a `SELECT` ([`statement_parts`]).
fn select_parts<'a>(select: &'a crate::ast::AstSelect, meet: &mut dyn FnMut(StatementPart<'a>)) {
    use crate::ast::{AstProjectionKind, ProjectionItemKind};
    with_parts(select.with_clause.as_deref(), meet);
    match select.set_quantifier.as_deref() {
        Some(crate::ast::AstSetQuantifier::DistinctOn { exprs, .. }) => {
            for expr in exprs {
                meet(StatementPart::Expr(expr));
            }
        }
        Some(crate::ast::AstSetQuantifier::All | crate::ast::AstSetQuantifier::Distinct) | None => {
        }
    }
    if let Some(top) = &select.top {
        meet(StatementPart::Expr(&top.expr));
    }
    match &select.projection.kind {
        AstProjectionKind::Columns(items) => {
            for item in items {
                match &item.kind {
                    ProjectionItemKind::SelectItem(item) => meet(StatementPart::Expr(&item.expr)),
                    ProjectionItemKind::JinjaBlock(_) => {}
                }
            }
        }
        AstProjectionKind::Star(star) => {
            for item in star.replace.iter().flat_map(|replace| &replace.items) {
                meet(StatementPart::Expr(&item.expr));
            }
        }
    }
    for item in &select.from {
        match &item.kind {
            crate::ast::FromItemKind::TableRef(table) => table_ref_parts(table, meet),
            crate::ast::FromItemKind::JinjaBlock(_)
            | crate::ast::FromItemKind::JinjaTableName(_) => {}
        }
    }
    for clause in [&select.where_clause, &select.having, &select.qualify]
        .into_iter()
        .flatten()
    {
        condition_parts(clause, meet);
    }
    if let Some(group_by) = &select.group_by {
        group_by_parts(group_by, meet);
    }
    if let Some(connect_by) = &select.connect_by {
        for expr in connect_by
            .start_with_condition
            .iter()
            .chain(&connect_by.conditions)
        {
            meet(StatementPart::Expr(expr));
        }
        order_by_parts(connect_by.order_siblings_by.as_ref(), meet);
    }
    order_by_parts(select.order_by.as_deref(), meet);
    for expr in [&select.limit, &select.offset].into_iter().flatten() {
        meet(StatementPart::Expr(expr));
    }
    for definition in select
        .window_clause
        .iter()
        .flat_map(|clause| &clause.definitions)
    {
        let spec = &definition.window_spec;
        for expr in &spec.partition_by {
            meet(StatementPart::Expr(expr));
        }
        for item in &spec.order_by {
            meet(StatementPart::Expr(&item.expr));
        }
        if let Some(frame) = &spec.frame {
            for bound in std::iter::once(&frame.start).chain(&frame.end) {
                if let Some(value) = &bound.value {
                    meet(StatementPart::Expr(value));
                }
            }
        }
    }
}

/// The parts of a `WHERE`, `HAVING` or `QUALIFY` clause ([`statement_parts`]).
fn condition_parts<'a>(
    clause: &'a crate::ast::ConditionClause,
    meet: &mut dyn FnMut(StatementPart<'a>),
) {
    meet(StatementPart::Expr(&clause.expr));
    for (_, expr) in &clause.continuation_fragments {
        meet(StatementPart::Expr(expr));
    }
}

/// The expressions a `GROUP BY` groups by ([`statement_parts`]).
fn group_by_parts<'a>(
    group_by: &'a crate::ast::AstGroupBy,
    meet: &mut dyn FnMut(StatementPart<'a>),
) {
    use crate::ast::{AstGroupByVariant, AstGroupElementKind};
    let items: Vec<&crate::ast::AstGroupItem> = match &group_by.variant {
        AstGroupByVariant::Standard(items) => items.iter().collect(),
        AstGroupByVariant::Elements(elements) => elements
            .iter()
            .flat_map(|element| match &element.kind {
                AstGroupElementKind::Expr(item) => vec![item],
                AstGroupElementKind::Cube { items, .. }
                | AstGroupElementKind::Rollup { items, .. } => items.iter().collect(),
                AstGroupElementKind::GroupingSets { sets, .. } => {
                    sets.iter().flat_map(|set| &set.items).collect()
                }
                AstGroupElementKind::EmptySet => Vec::new(),
            })
            .collect(),
        AstGroupByVariant::All | AstGroupByVariant::JinjaPlaceholder(_) => Vec::new(),
    };
    for item in items {
        meet(StatementPart::Expr(&item.expr));
    }
}

/// The parts of a table a `FROM` reads and of the tables joined to it
/// ([`statement_parts`]).
fn table_ref_parts<'a>(
    table: &'a crate::ast::AstTableRef,
    meet: &mut dyn FnMut(StatementPart<'a>),
) {
    use crate::ast::{AstPivotInValues, AstSampleSize};
    // Joins nested deeper than the stack lets the analyzer walk are not
    // read.
    let Some(_frame) = crate::ir::lower::enter_nested() else {
        return;
    };
    if let Some(query) = &table.subquery {
        meet(StatementPart::Query(query));
    }
    for expr in table
        .values
        .iter()
        .flat_map(|values| values.rows.iter().flatten())
    {
        meet(StatementPart::Expr(expr));
    }
    match &table.table_function {
        Some(function) => meet(StatementPart::Table(function)),
        // A call in `TABLE(…)` the parser read no call of is held as its
        // text, in the name's place.
        None if table.subquery.is_none()
            && table.values.is_none()
            && table.name.parts.is_none()
            && table.name.identifier_arg.is_none() => {}
        None => {}
    }
    if let Some(clause) = table.time_travel.as_deref() {
        time_travel_parts(clause, meet);
    }
    if let Some(changes) = &table.changes {
        meet(StatementPart::Expr(time_travel_point(
            &changes.at_before.kind,
        )));
        if let Some(end) = &changes.end {
            meet(StatementPart::Expr(time_travel_point(&end.kind)));
        }
    }
    if let Some(sample) = &table.sample {
        match &sample.size {
            AstSampleSize::Probability(expr) | AstSampleSize::Rows(expr) => {
                meet(StatementPart::Expr(expr))
            }
        }
        if let Some(seed) = &sample.seed {
            meet(StatementPart::Expr(seed));
        }
    }
    if let Some(pivot) = &table.pivot {
        for aggregate in &pivot.aggregates {
            meet(StatementPart::Expr(&aggregate.expr));
        }
        meet(StatementPart::Expr(&pivot.for_column));
        match &pivot.in_values {
            AstPivotInValues::ValueList(values) => {
                for value in values {
                    meet(StatementPart::Expr(&value.value));
                }
            }
            AstPivotInValues::Any(order) => {
                for item in order.iter().flatten() {
                    meet(StatementPart::Expr(&item.expr));
                }
            }
            AstPivotInValues::Subquery(query) => meet(StatementPart::Query(query)),
            AstPivotInValues::OpaqueList(_) => {}
        }
        if let Some(default) = &pivot.default_on_null {
            meet(StatementPart::Expr(default));
        }
    }
    if let Some(recognize) = &table.match_recognize {
        for expr in recognize.partition_by.iter().flatten() {
            meet(StatementPart::Expr(expr));
        }
        order_by_parts(recognize.order_by.as_ref(), meet);
        for measure in &recognize.measures {
            meet(StatementPart::Expr(&measure.expr));
        }
        for symbol in &recognize.define {
            meet(StatementPart::Expr(&symbol.expr));
        }
    }
    for join in table.joins.iter() {
        join_parts(join, meet);
    }
}

/// The parts of a joined table and of its join condition
/// ([`statement_parts`]).
fn join_parts<'a>(join: &'a crate::ast::AstJoin, meet: &mut dyn FnMut(StatementPart<'a>)) {
    use crate::ast::AstJoinConstraint;
    table_ref_parts(&join.right, meet);
    if let Some(condition) = &join.match_condition {
        meet(StatementPart::Expr(&condition.condition));
    }
    match &join.constraint {
        AstJoinConstraint::On(condition) => meet(StatementPart::Expr(condition)),
        AstJoinConstraint::Using(_) | AstJoinConstraint::None => {}
    }
}

/// The point in time a time-travel clause reads at ([`statement_parts`]).
fn time_travel_parts<'a>(
    clause: &'a crate::ast::AstTimeTravelClause,
    meet: &mut dyn FnMut(StatementPart<'a>),
) {
    use crate::ast::AstTimeTravelClause;
    match clause {
        AstTimeTravelClause::SnowflakeAtBefore(at) => {
            meet(StatementPart::Expr(time_travel_point(&at.kind)))
        }
        AstTimeTravelClause::ForSystemTime(system_time) => {
            if let Some(expr) = &system_time.expr {
                meet(StatementPart::Expr(expr));
            }
        }
        AstTimeTravelClause::DatabricksAsOf(as_of) => meet(StatementPart::Expr(&as_of.expr)),
    }
}

/// The expression of a Snowflake `AT` / `BEFORE` point.
fn time_travel_point(kind: &crate::ast::AstTimeTravelKind) -> &AstExpr {
    use crate::ast::AstTimeTravelKind;
    match kind {
        AstTimeTravelKind::Timestamp(expr)
        | AstTimeTravelKind::Offset(expr)
        | AstTimeTravelKind::Statement(expr)
        | AstTimeTravelKind::Stream(expr) => expr,
    }
}

/// The queries of a `WITH` clause ([`statement_parts`]).
fn with_parts<'a>(
    with: Option<&'a crate::ast::AstWithClause>,
    meet: &mut dyn FnMut(StatementPart<'a>),
) {
    for item in with.iter().flat_map(|with| &with.ctes) {
        match item {
            crate::ast::CteItem::Cte(cte) => meet(StatementPart::Query(&cte.query)),
            crate::ast::CteItem::JinjaBlock(_) => {}
        }
    }
}

/// The expressions an `ORDER BY` sorts by ([`statement_parts`]).
fn order_by_parts<'a>(
    order_by: Option<&'a crate::ast::AstOrderBy>,
    meet: &mut dyn FnMut(StatementPart<'a>),
) {
    for item in order_by.iter().flat_map(|order_by| &order_by.items) {
        meet(StatementPart::Expr(&item.expr));
    }
}

/// The expressions a `RETURNING` list returns ([`statement_parts`]).
fn returning_parts<'a>(
    returning: Option<&'a crate::ast::AstReturning>,
    meet: &mut dyn FnMut(StatementPart<'a>),
) {
    for item in returning.iter().flat_map(|returning| &returning.items) {
        meet(StatementPart::Expr(&item.expr));
    }
}

/// Every function call `stmt` makes, at any depth, in written order: in
/// each part of it ([`statement_parts`]) and in the queries those hold.
fn statement_calls<'a>(stmt: &'a crate::ast::AstStmt, calls: &mut Vec<(&'a AstExpr, bool)>) {
    // A query nested deeper than the stack lets the analyzer walk is not
    // read.
    let Some(_frame) = crate::ir::lower::enter_nested() else {
        return;
    };
    statement_parts(stmt, &mut |part| {
        let (expr, table) = match part {
            StatementPart::Expr(expr) => (expr, None),
            StatementPart::Table(expr) => (expr, Some(expr.node_id())),
            StatementPart::Query(query) => return statement_calls(query, calls),
        };
        walk_expr_parts(expr, &mut |part| match part {
            ExprPart::Call(call) => calls.push((call, table == Some(call.node_id()))),
            ExprPart::Statement(inner) => statement_calls(inner, calls),
        })
    });
}

/// Walk a [`RelPlan`] looking for `dblink_exec` / `dblink` /
/// `OPENQUERY` -style cross-server dynamic-SQL function-call surfaces
/// in scalar expressions. Each hit produces a [`DynamicSqlCallIr`]
/// with `surface = DblinkExec`. Used by lib-level dispatch for
/// top-level query statements (SELECT / INSERT / UPDATE / DELETE /
/// MERGE) where the dynamic-SQL surface is an expression, not a
/// dedicated statement type.
pub fn collect_cross_server_dynamic_sql_calls(
    plan: &RelPlan,
    classifier: &dyn crate::facts::reasoning::DynamicSqlClassifier,
) -> Vec<DynamicSqlCallIr> {
    let mut collector = CrossServerCallCollector {
        out: Vec::new(),
        classifier,
    };
    collector.visit_rel_plan(plan);
    collector.out
}

struct CrossServerCallCollector<'c> {
    out: Vec<DynamicSqlCallIr>,
    classifier: &'c dyn crate::facts::reasoning::DynamicSqlClassifier,
}

impl<'a> RelPlanVisitor<'a> for CrossServerCallCollector<'_> {
    fn visit_rel_plan(&mut self, plan: &'a RelPlan) {
        walk_rel_plan(self, plan);
    }

    fn visit_scalar_expr(&mut self, expr: &'a ScalarExpr) {
        if let ScalarExpr::FuncCall {
            func: ResolvedFunc::Unresolved { raw_name, .. },
            args,
            span,
            ..
        } = expr
        {
            if let Some(run) = remote_run(raw_name, args) {
                let run = run.and_then(|position| args.get(position));
                let argument = run
                    .map(|a| self.classifier.classify_scalar_arg(a))
                    .unwrap_or(DynamicSqlArgIr::Unknown);
                self.out.push(DynamicSqlCallIr {
                    surface: DynamicSqlSurfaceIr::DblinkExec,
                    argument,
                    // Cross-server scalar surface: splice recovery deferred.
                    splices: Vec::new(),
                    parameterization: DynamicSqlParameterizationIr::NotApplicable,
                    argument_parameter: None,
                    // No `NodeId` on `ScalarExpr::FuncCall` — use a
                    // sentinel zero. Finding-emission witnesses use
                    // `source_span` (the call site) for line/col.
                    node_id: NodeId::new(0),
                    source_span: *span,
                    argument_span: run.map(scalar_expr_span),
                    provenance: Vec::new(),
                });
            }
        }
        walk_scalar_expr(self, expr);
    }
}

/// Where a call of the function named `raw_name` with `args` sends SQL
/// text to another server to run: the call names a routine of the dialect
/// in force and fits a form of it that does
/// ([`crate::dialect::Dialect::system_routine`]), with the position of the
/// argument it sends, where the call decides it.
fn remote_run(raw_name: &str, args: &[ScalarExpr]) -> Option<Option<usize>> {
    use crate::dialect::{ArgumentUse, WrittenArgument, WrittenValue};
    let dialect = crate::ir::normalize::dialect_in_force();
    let name = crate::ir::lower::routine_name(raw_name);
    let parts: Vec<&str> = name.iter().map(IdentKey::as_str).collect();
    let routine = dialect.system_routine(&parts)?;
    let remote = routine.forms.iter().any(|form| {
        form.parameters
            .iter()
            .map(|parameter| parameter.reads)
            .chain(form.rest)
            .any(|reads| reads == ArgumentUse::RunsSqlRemotely)
    });
    if !remote {
        return None;
    }
    // A string, a concatenation, or a call that builds text (`format(…)`)
    // is text.
    let written: Vec<WrittenArgument<'_>> = args
        .iter()
        .map(|arg| WrittenArgument {
            name: None,
            value: if let ScalarExpr::Lit {
                value: crate::ir::scalar::Lit::Str(_),
                ..
            }
            | ScalarExpr::BinOp {
                op: crate::ir::scalar::BinOpKind::Concat,
                ..
            } = arg
            {
                WrittenValue::Text
            } else if let ScalarExpr::OperatorChain { operators, .. } = arg {
                match operators.contains(&crate::ir::scalar::BinOpKind::Concat) {
                    true => WrittenValue::Text,
                    false => WrittenValue::Other,
                }
            } else if let ScalarExpr::FuncCall { .. } = arg {
                match concatenation_kind(scalar_text_node(arg), dialect.as_ref()) {
                    Some(_) => WrittenValue::Text,
                    None => WrittenValue::Other,
                }
            } else if let ScalarExpr::Lit {
                value: crate::ir::scalar::Lit::Bool(_),
                ..
            } = arg
            {
                WrittenValue::Flag
            } else {
                WrittenValue::Other
            },
        })
        .collect();
    // A call no such form fits is another form of the routine:
    // `OPENROWSET(BULK '<file>', …)` reads a file.
    if !routine.fits_reading(&written, ArgumentUse::RunsSqlRemotely) {
        return None;
    }
    Some(
        routine
            .argument_uses(&written)
            .iter()
            .position(|reads| *reads == Some(ArgumentUse::RunsSqlRemotely)),
    )
}

/// Walk a [`RelPlan`] for T-SQL `OPENROWSET(...)` call sites and
/// project each one's literal string arguments. Used for the
/// MSSQL-OPENROWSET-INLINE-CRED rule family — the rule pattern-matches
/// the connection-string argument (typically positional argument 2)
/// against known credential shapes (`Server=...;PWD=...`).
///
/// Non-literal arguments (variables, expressions, subqueries) are
/// silently dropped — the rule fires on literals only, since that's
/// where the security-review concern lives.
pub fn collect_openrowset_calls(plan: &RelPlan) -> Vec<Vec<RemoteSourceArg>> {
    collect_remote_source_calls(plan, "OPENROWSET")
}

/// Collect the string-literal arguments of each `OPENDATASOURCE(...)`
/// call (T-SQL ad-hoc remote-source access, `OPENDATASOURCE('provider',
/// 'connstr').db.schema.table`). The connection string carries inline
/// credentials in the same shapes as `OPENROWSET`. See
/// [`collect_openrowset_calls`].
pub fn collect_opendatasource_calls(plan: &RelPlan) -> Vec<Vec<RemoteSourceArg>> {
    collect_remote_source_calls(plan, "OPENDATASOURCE")
}

/// Collect the string-literal arguments of each call to the named
/// remote-source table function (`OPENROWSET` / `OPENDATASOURCE`).
/// Non-literal arguments are dropped — the security concern lives in the
/// literal connection string.
fn collect_remote_source_calls(plan: &RelPlan, func_name: &str) -> Vec<Vec<RemoteSourceArg>> {
    let mut collector = RemoteSourceCallCollector {
        target: crate::ir::normalize::normalize_identifier(func_name),
        out: Vec::new(),
    };
    collector.visit_rel_plan(plan);
    collector.out
}

/// An argument of a remote-source call that may hold a credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemoteSourceArg {
    /// A string literal.
    String {
        /// The literal as written, quotes included.
        written: String,
        /// Where it is written.
        span: Span,
    },
    /// An argument kept as its text, such as `OPENROWSET`'s
    /// `'data source';'user';'password'` run.
    Text {
        /// Where it is written.
        span: Span,
    },
}

struct RemoteSourceCallCollector {
    target: String,
    out: Vec<Vec<RemoteSourceArg>>,
}

impl<'a> RelPlanVisitor<'a> for RemoteSourceCallCollector {
    fn visit_rel_plan(&mut self, plan: &'a RelPlan) {
        walk_rel_plan(self, plan);
    }

    fn visit_scalar_expr(&mut self, expr: &'a ScalarExpr) {
        if let ScalarExpr::FuncCall {
            func: ResolvedFunc::Unresolved { raw_name, .. },
            args,
            ..
        } = expr
        {
            // Route through the centralized identifier-normalization
            // helper rather than ad-hoc quote stripping: it handles
            // each dialect's quote chars and case-folding rules.
            if crate::ir::normalize::normalize_identifier(raw_name) == self.target {
                let string_args = args
                    .iter()
                    .filter_map(|a| match a {
                        ScalarExpr::Lit {
                            value: crate::ir::scalar::Lit::Str(s),
                            span,
                        } => Some(RemoteSourceArg::String {
                            written: s.clone(),
                            span: *span,
                        }),
                        ScalarExpr::Opaque { span, .. } => {
                            Some(RemoteSourceArg::Text { span: *span })
                        }
                        _ => None,
                    })
                    .collect();
                self.out.push(string_args);
            }
        }
        walk_scalar_expr(self, expr);
    }
}

fn scalar_expr_span(expr: &ScalarExpr) -> Span {
    match expr {
        ScalarExpr::Column { span, .. } => *span,
        ScalarExpr::OuterRef { span, .. } => *span,
        ScalarExpr::Lit { span, .. } => *span,
        ScalarExpr::BinOp { span, .. } => *span,
        ScalarExpr::LogicalChain { span, .. } => *span,
        ScalarExpr::OperatorChain { span, .. } => *span,
        ScalarExpr::Like { span, .. } => *span,
        ScalarExpr::UnaryOp { span, .. } => *span,
        ScalarExpr::FuncCall { span, .. } => *span,
        ScalarExpr::Case { span, .. } => *span,
        ScalarExpr::Cast { span, .. } => *span,
        ScalarExpr::InList { span, .. } => *span,
        ScalarExpr::Between { span, .. } => *span,
        ScalarExpr::Exists { span, .. } => *span,
        ScalarExpr::ScalarSubquery { span, .. } => *span,
        ScalarExpr::QuantifiedCmp { span, .. } => *span,
        ScalarExpr::RowCmp { span, .. } => *span,
        ScalarExpr::WindowFn { span, .. } => *span,
        ScalarExpr::FieldAccess { span, .. } => *span,
        ScalarExpr::Lambda { span, .. } => *span,
        ScalarExpr::PatternVarRef { span, .. } => *span,
        ScalarExpr::Opaque { span, .. } => *span,
    }
}

/// Shape of a lowered dynamic-SQL string argument, with string-building
/// shapes decided by `refine`.
pub fn classify_scalar_expr_argument(
    expr: &ScalarExpr,
    refine: &dyn ShapeRefiner,
) -> DynamicSqlArgIr {
    // `||` concat and `+` are SQL string-building. MySQL `||` is logical-OR
    // — the parser lowers it to a logical OR per the dialect, so it is no
    // concatenation here.
    let dialect = crate::ir::normalize::dialect_in_force();
    match concatenation_kind(scalar_text_node(expr), dialect.as_ref()) {
        Some(
            ConcatenationKind::Operator | ConcatenationKind::Concat | ConcatenationKind::ConcatWs,
        ) => return refine.scalar_concat_shape(expr),
        Some(ConcatenationKind::Format) => {
            if let ScalarExpr::FuncCall { args, .. } = expr {
                return refine.scalar_format_shape(args);
            }
        }
        Some(ConcatenationKind::Replace) | None => {}
    }
    if let ScalarExpr::Lit { .. } = expr {
        return DynamicSqlArgIr::Literal;
    }
    match scalar_text_node(expr) {
        TextNode::Variable { .. } => DynamicSqlArgIr::Variable,
        TextNode::String(_)
        | TextNode::Fixed(_)
        | TextNode::Grouped(_)
        | TextNode::Choice(_)
        | TextNode::Converted(_)
        | TextNode::Joined { .. }
        | TextNode::Call { .. }
        | TextNode::Other => DynamicSqlArgIr::Unknown,
    }
}
