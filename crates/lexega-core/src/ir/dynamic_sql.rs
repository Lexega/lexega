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
        // Dequote relative paths (`'…'` / `$$…$$`); stage paths are bare.
        let trimmed = t.trim();
        match location_kind {
            EifLocationKindIr::RelativePath => trimmed
                .trim_start_matches("$$")
                .trim_end_matches("$$")
                .trim_matches('\'')
                .to_string(),
            EifLocationKindIr::StagePath => trimmed.to_string(),
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
    /// PostgreSQL `dblink_exec(<connstr>, <sql>)` function-call
    /// surface — distinct threat class because it executes on a
    /// remote server's auth context.
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

thread_local! {
    /// Per-thread ambient flag: does a `FORMAT(...)` function build a
    /// SQL string by template interpolation in the active dialect (see
    /// [`crate::dialect::Dialect::format_function_builds_sql`])? Set by
    /// [`set_ambient_format_builds_sql`] at analysis start, alongside
    /// the taint-engine ambient dialect. Read by the argument
    /// classifiers below so a `FORMAT` call is recognized as a
    /// dynamic-SQL construction surface only where the dialect's
    /// `FORMAT` actually builds SQL. Defaults to `true` —
    /// over-approx-safe: an unset ambient keeps the pre-dialect-aware
    /// behavior (FORMAT flagged) rather than risking a false negative.
    static AMBIENT_FORMAT_BUILDS_SQL: std::cell::Cell<bool> =
        const { std::cell::Cell::new(true) };
}

/// Configure whether `FORMAT(...)` builds SQL in the active dialect for
/// the current thread. Called once per analysis run, from
/// `apply_dialect_normalization`.
pub fn set_ambient_format_builds_sql(builds_sql: bool) {
    AMBIENT_FORMAT_BUILDS_SQL.with(|f| f.set(builds_sql));
}

/// Read the current ambient FORMAT-builds-SQL flag for this thread.
pub fn ambient_format_builds_sql() -> bool {
    AMBIENT_FORMAT_BUILDS_SQL.with(|f| f.get())
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
/// `ConcatQuoted`, `FormatQuoted`, `Literal`, `Unknown`. The two
/// resolved-clean shapes rank below an unresolved `Variable` (they are
/// proven to quote) but above a pure `Literal` (they still carry runtime
/// input). `Unknown` is the bottom, so `join(x, Unknown) = x`.
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
        DynamicSqlArgIr::ConcatQuoted => 3,
        DynamicSqlArgIr::FormatQuoted => 2,
        DynamicSqlArgIr::Literal => 1,
        DynamicSqlArgIr::Unknown => 0,
    }
}

/// Classify the structural shape of an `EXECUTE IMMEDIATE` argument
/// expression. Walks through `Parenthesized` wrappers; recognizes
/// the `||` and `+` concat operators and the `CONCAT` / `FORMAT`
/// function call surfaces; treats anything more complex as
/// `Unknown` (degrade-gracefully — DYNSQL still fires at the base
/// rule, just not at the severity-distinguishing siblings).
///
/// `FORMAT(...)` maps to [`DynamicSqlArgIr::Format`] only when the
/// active dialect's `FORMAT` builds SQL by template interpolation
/// (PG/Redshift/BigQuery, via [`ambient_format_builds_sql`]); where it
/// is a value/number formatter (MySQL/T-SQL) the call is opaque and
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
    match expr {
        AstExpr::Literal { literal, .. } => match literal {
            // A StringWithJinja executed as dynamic SQL carries a dynamic hole:
            // an unrendered `{{ … }}`, or a rendered-placeholder splice the
            // parser promoted here (see promote_placeholder_dynamic_sql_arg).
            // Either way the injected value splices into the executed statement —
            // recognize it as Concat, not a clean Literal. Other literals
            // (String/Number/bool/null) carry no runtime input.
            crate::ast::AstLiteral::StringWithJinja { .. } => DynamicSqlArgIr::Concat,
            _ => DynamicSqlArgIr::Literal,
        },
        AstExpr::Placeholder { .. } => DynamicSqlArgIr::Variable,
        AstExpr::Ident { .. } => DynamicSqlArgIr::Variable,
        AstExpr::ScriptingVarRef { .. } => DynamicSqlArgIr::Variable,
        // `||` in Snowflake/PostgreSQL/MySQL-non-default and `+`
        // in T-SQL are string concatenation when both operands
        // are string-shaped. Classified by operator identity;
        // arithmetic `+` on dynamic-SQL argument is exceedingly
        // rare in practice. The refiner decides whether a concat is
        // injection-clean (`ConcatQuoted`) or the dangerous `Concat`.
        AstExpr::BinaryOp {
            operator: BinaryOperator::Concat | BinaryOperator::Plus,
            ..
        } => refine.concat_shape(expr, source),
        AstExpr::BinaryOp { .. } => DynamicSqlArgIr::Unknown,
        AstExpr::LogicalChain { .. } => DynamicSqlArgIr::Unknown,
        AstExpr::FunctionCall {
            func_name, args, ..
        } => {
            let name = source
                .get(func_name.span.start as usize..func_name.span.end as usize)
                .unwrap_or("");
            if name.eq_ignore_ascii_case("CONCAT") {
                refine.concat_shape(expr, source)
            } else if name.eq_ignore_ascii_case("FORMAT") && ambient_format_builds_sql() {
                refine.format_shape(args, source)
            } else {
                // Selection / conditional functions whose result is one of their
                // value args: the returned (hence executed) value can be ANY of
                // those arms, so join their shapes — a tainted arm dominates a
                // clean one, mirroring the statement branch merge. Condition /
                // test / search args are excluded (they are not returned).
                let positionals: Vec<&AstExpr> = args
                    .iter()
                    .filter_map(|a| match a.as_ref() {
                        crate::ast::AstFunctionArg::Positional(e) => Some(e.as_ref()),
                        _ => None,
                    })
                    .collect();
                let value_args: Option<Vec<&AstExpr>> = if name.eq_ignore_ascii_case("IFF")
                    || name.eq_ignore_ascii_case("IIF")
                    || name.eq_ignore_ascii_case("NVL2")
                {
                    // IFF/IIF(cond, a, b), NVL2(test, a, b): skip the test (arg 0).
                    Some(positionals.into_iter().skip(1).collect())
                } else if name.eq_ignore_ascii_case("COALESCE")
                    || name.eq_ignore_ascii_case("NVL")
                    || name.eq_ignore_ascii_case("IFNULL")
                    || name.eq_ignore_ascii_case("ISNULL")
                {
                    // Every arg is a candidate return value (COALESCE and its
                    // 2-arg synonyms NVL/IFNULL/ISNULL).
                    Some(positionals)
                } else if name.eq_ignore_ascii_case("DECODE") {
                    // DECODE(expr, search1, result1, …, [default]): the returned
                    // value is each pair's result (every 2nd arg from index 2)
                    // plus a trailing default; expr and searches are excluded.
                    let mut results: Vec<&AstExpr> = Vec::new();
                    let mut i = 1usize;
                    while i + 1 < positionals.len() {
                        results.push(positionals[i + 1]);
                        i += 2;
                    }
                    if i < positionals.len() {
                        results.push(positionals[i]);
                    }
                    Some(results)
                } else {
                    None
                };
                match value_args {
                    Some(exprs) => {
                        let mut joined = DynamicSqlArgIr::Unknown;
                        for e in exprs {
                            joined = lattice_join(
                                joined,
                                classify_execute_immediate_arg_with(e, source, refine),
                            );
                        }
                        joined
                    }
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
            let mut joined = DynamicSqlArgIr::Unknown;
            for w in whens {
                joined = lattice_join(
                    joined,
                    classify_execute_immediate_arg_with(&w.result, source, refine),
                );
            }
            if let Some(else_e) = else_expr {
                joined = lattice_join(
                    joined,
                    classify_execute_immediate_arg_with(else_e, source, refine),
                );
            }
            joined
        }
        AstExpr::Parenthesized { expr: inner, .. } => {
            classify_execute_immediate_arg_with(inner, source, refine)
        }
        _ => DynamicSqlArgIr::Unknown,
    }
}

/// The bare `@var` a T-SQL `EXEC(@var)` / `EXEC sp_executesql @var`
/// argument span names, when the span holds nothing but that variable
/// reference. Tolerates leading whitespace, `(`, and the `@`/`@@` prefix.
pub fn mssql_exec_bare_variable(args_span: Option<Span>, source: &str) -> Option<&str> {
    let span = args_span?;
    let text = source.get(span.start as usize..span.end as usize)?;
    let trimmed = text.trim_start().trim_start_matches('(').trim_start();
    let bytes = trimmed.as_bytes();
    if bytes.is_empty() || bytes[0] != b'@' {
        return None;
    }
    let mut end = 1usize;
    while end < bytes.len() {
        let b = bytes[end];
        if b == b'@' && end == 1 {
            end += 1;
            continue;
        }
        if b.is_ascii_alphanumeric() || b == b'_' {
            end += 1;
        } else {
            break;
        }
    }
    if end <= 1 {
        return None;
    }
    Some(&trimmed[..end])
}

/// Typed projection of a positional / named argument at a call site.
/// Produced by [`classify_call_args`] from the raw `args_span` on
/// `AstStmt::MssqlExec` and `AstStmt::Call` (neither of which lifts
/// the argument list to typed expressions today).
#[derive(Debug, Clone)]
pub struct CallArgIr {
    pub kind: CallArgKind,
    pub shape: DynamicSqlArgIr,
    pub span: Span,
    /// Normalized (sigil-stripped, lowercased) variable name when the
    /// argument is a `@var` / `:var` / bare variable reference.
    /// `None` for literal / concat / complex expressions. Consumers
    /// read this rather than re-parsing the span.
    pub var_ref: Option<String>,
}

/// Discriminator for a single call-site argument's position or name.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum CallArgKind {
    Positional(usize),
    /// Lowercased parameter name (`@p` / `:p` stripped of sigils) for
    /// named-argument call shapes (T-SQL `EXEC p @x = @v`, Snowflake
    /// keyword args, PG `CALL p(arg => v)`).
    Named(String),
}

/// Classify call-site arguments to typed [`CallArgIr`]. The only
/// dissection boundary — consumers read [`CallArgIr`] never the raw
/// span text.
pub fn classify_call_args(
    args: &[crate::ast::AstCallArg],
    source: &str,
    refine: &dyn ShapeRefiner,
) -> Vec<CallArgIr> {
    let mut out = Vec::with_capacity(args.len());
    for (idx, arg) in args.iter().enumerate() {
        let kind = match &arg.name {
            Some(ident) => {
                let raw = source
                    .get(ident.span.start as usize..ident.span.end as usize)
                    .unwrap_or("");
                CallArgKind::Named(normalize_arg_name(raw))
            }
            None => CallArgKind::Positional(idx),
        };
        let shape = classify_execute_immediate_arg_with(&arg.value, source, refine);
        let var_ref = match &arg.value {
            AstExpr::Ident { column_ref, .. } => {
                let raw = source
                    .get(column_ref.name.span.start as usize..column_ref.name.span.end as usize)
                    .unwrap_or("");
                Some(normalize_arg_name(raw))
            }
            AstExpr::ScriptingVarRef { name_span, .. } => {
                let raw = source
                    .get(name_span.start as usize..name_span.end as usize)
                    .unwrap_or("");
                Some(normalize_arg_name(raw))
            }
            _ => None,
        };
        out.push(CallArgIr {
            kind,
            shape,
            span: arg.span,
            var_ref,
        });
    }
    out
}

fn normalize_arg_name(s: &str) -> String {
    s.trim_start_matches('@')
        .trim_start_matches('@')
        .trim_start_matches(':')
        .to_ascii_lowercase()
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

/// Is this `EXEC` invoking `sp_executesql`? Matches on the base name
/// part so qualified (`sys.sp_executesql`, `master.dbo.sp_executesql`)
/// and bracket-quoted invocations classify as the same surface.
/// `false` for the bare dynamic form `EXEC(@sql)`.
pub fn is_sp_executesql(e: &crate::ast::types::AstMssqlExec, source: &str) -> bool {
    e.procedure_base_name_span.is_some_and(|s| {
        crate::ir::normalize::normalize_identifier(
            source.get(s.start as usize..s.end as usize).unwrap_or(""),
        )
        .eq_ignore_ascii_case("sp_executesql")
    })
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
///
/// Closed-enum exhaustive over [`AstExpr`]; descent paths are limited
/// to the variants that carry sub-statements or sub-expressions worth
/// walking.
pub fn collect_inner_stmts_from_expr<'a>(expr: &'a AstExpr) -> Vec<&'a crate::ast::AstStmt> {
    let mut out: Vec<&'a crate::ast::AstStmt> = Vec::new();
    walk_expr_for_inner_stmts(expr, &mut out);
    out
}

fn walk_expr_for_inner_stmts<'a>(expr: &'a AstExpr, out: &mut Vec<&'a crate::ast::AstStmt>) {
    use crate::ast::AstExpr as E;
    match expr {
        // Variants that wrap an `AstStmt` directly — collect it.
        E::ScalarSubquery { subquery, .. }
        | E::SubqueryArg { subquery, .. }
        | E::ExistsSubquery { subquery, .. }
        | E::InSubquery { subquery, .. } => {
            out.push(subquery);
        }
        E::QuantifiedSubquery { subquery, .. } => {
            out.push(subquery);
        }

        // Sub-expression carriers — keep walking.
        E::MatchAgainst {
            match_call, search, ..
        } => {
            walk_expr_for_inner_stmts(match_call, out);
            walk_expr_for_inner_stmts(search, out);
        }
        E::Parenthesized { expr, .. } | E::Spread { expr, .. } => {
            walk_expr_for_inner_stmts(expr, out);
        }
        E::BinaryOp { left, right, .. } => {
            walk_expr_for_inner_stmts(left, out);
            walk_expr_for_inner_stmts(right, out);
        }
        E::LogicalChain { operands, .. } => {
            for sub in operands {
                walk_expr_for_inner_stmts(sub, out);
            }
        }
        E::Case {
            operand,
            whens,
            else_expr,
            ..
        } => {
            if let Some(op) = operand {
                walk_expr_for_inner_stmts(op, out);
            }
            for when in whens {
                walk_expr_for_inner_stmts(&when.cond, out);
                walk_expr_for_inner_stmts(&when.result, out);
            }
            if let Some(else_e) = else_expr {
                walk_expr_for_inner_stmts(else_e, out);
            }
        }
        E::InList { expr, list, .. } => {
            walk_expr_for_inner_stmts(expr, out);
            for item in list {
                walk_expr_for_inner_stmts(item, out);
            }
        }
        E::Between {
            expr, lower, upper, ..
        } => {
            walk_expr_for_inner_stmts(expr, out);
            walk_expr_for_inner_stmts(lower, out);
            walk_expr_for_inner_stmts(upper, out);
        }
        E::Cast { expr, .. }
        | E::TryCast { expr, .. }
        | E::SafeCast { expr, .. }
        | E::TypeCast { expr, .. } => {
            walk_expr_for_inner_stmts(expr, out);
        }
        E::IsNull { expr, .. } => {
            walk_expr_for_inner_stmts(expr, out);
        }
        E::IsDistinctFrom { left, right, .. } => {
            walk_expr_for_inner_stmts(left, out);
            walk_expr_for_inner_stmts(right, out);
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
            walk_expr_for_inner_stmts(expr, out);
            walk_expr_for_inner_stmts(pattern, out);
            if let Some(esc) = escape_clause {
                walk_expr_for_inner_stmts(esc, out);
            }
        }
        E::Array { elements, .. } | E::RowConstructor { elements, .. } => {
            for el in elements {
                walk_expr_for_inner_stmts(el, out);
            }
        }
        // Function-call arguments are the only position the parser emits a
        // statement-bearing `SubqueryArg` (`ARRAY(SELECT …)`,
        // `TABLE(EXECUTE IMMEDIATE …)`). Walk each argument's expression so
        // the embedded statement is reached.
        E::FunctionCall { args, .. } => {
            for arg in args {
                match arg.as_ref() {
                    crate::ast::AstFunctionArg::Positional(e)
                    | crate::ast::AstFunctionArg::Named { value: e, .. }
                    | crate::ast::AstFunctionArg::Lambda { body: e, .. }
                    | crate::ast::AstFunctionArg::AliasedArg { value: e, .. }
                    | crate::ast::AstFunctionArg::BulkArg { value: e, .. } => {
                        walk_expr_for_inner_stmts(e, out);
                    }
                }
            }
        }

        // Leaves — no embedded statement-position to walk.
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
        | E::InListOpaque { .. }
        | E::ExplSnowIdent { .. }
        | E::Object { .. }
        | E::WindowFn { .. }
        | E::WindowExpr { .. }
        | E::TvfWithSchema { .. }
        | E::ScriptingVarRef { .. }
        | E::QualifiedStar { .. }
        | E::UnqualifiedStar { .. }
        | E::QualifiedStarFromExpr { .. }
        | E::Prior { .. }
        | E::Extract { .. }
        | E::Position { .. }
        | E::Trim { .. }
        | E::Substring { .. }
        | E::Collate { .. }
        | E::ArraySubscript { .. }
        | E::ObjectFieldColon { .. }
        | E::ObjectFieldBracket { .. }
        | E::ObjectFieldDot { .. }
        | E::MethodCall { .. }
        | E::AtTimeZone { .. }
        | E::TypedStringLiteral { .. }
        | E::Error { .. } => {}
    }
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
            if is_cross_server_dynamic_sql_function(raw_name) {
                // Inspect the SQL-string argument shape when the
                // second positional argument (dblink_exec's `sql`
                // string) is available.
                let argument = args
                    .get(1)
                    .map(|a| self.classifier.classify_scalar_arg(a))
                    .unwrap_or(DynamicSqlArgIr::Unknown);
                self.out.push(DynamicSqlCallIr {
                    surface: DynamicSqlSurfaceIr::DblinkExec,
                    argument,
                    // Cross-server scalar surface: splice recovery deferred.
                    splices: Vec::new(),
                    parameterization: DynamicSqlParameterizationIr::NotApplicable,
                    // No `NodeId` on `ScalarExpr::FuncCall` — use a
                    // sentinel zero. Signal-emission witnesses use
                    // `source_span` (the call site) for line/col.
                    node_id: NodeId::new(0),
                    source_span: *span,
                    argument_span: args.get(1).map(scalar_expr_span),
                    provenance: Vec::new(),
                });
            }
        }
        walk_scalar_expr(self, expr);
    }
}

fn is_cross_server_dynamic_sql_function(name: &str) -> bool {
    let n = name.trim_start_matches(['"', '`']);
    let n = n.trim_end_matches(['"', '`']);
    n.eq_ignore_ascii_case("dblink_exec") || n.eq_ignore_ascii_case("dblink")
}

/// Walk a [`RelPlan`] for T-SQL `OPENROWSET(...)` call sites and
/// project each one's literal string arguments. Used for the
/// MSSQL-OPENROWSET-INLINE-CRED rule family — the rule pattern-matches
/// the connection-string argument (typically positional argument 2)
/// against known credential shapes (`Server=...;PWD=...`).
///
/// Non-literal arguments (variables, expressions, subqueries) are
/// silently dropped — the rule fires on literals only, since that's
/// where the security-review signal lives.
pub fn collect_openrowset_calls(plan: &RelPlan) -> Vec<Vec<String>> {
    collect_remote_source_calls(plan, "OPENROWSET")
}

/// Collect the string-literal arguments of each `OPENDATASOURCE(...)`
/// call (T-SQL ad-hoc remote-source access, `OPENDATASOURCE('provider',
/// 'connstr').db.schema.table`). The connection string carries inline
/// credentials in the same shapes as `OPENROWSET`. See
/// [`collect_openrowset_calls`].
pub fn collect_opendatasource_calls(plan: &RelPlan) -> Vec<Vec<String>> {
    collect_remote_source_calls(plan, "OPENDATASOURCE")
}

/// Collect the string-literal arguments of each call to the named
/// remote-source table function (`OPENROWSET` / `OPENDATASOURCE`).
/// Non-literal arguments are dropped — the security signal lives in the
/// literal connection string.
fn collect_remote_source_calls(plan: &RelPlan, func_name: &str) -> Vec<Vec<String>> {
    let mut collector = RemoteSourceCallCollector {
        target: crate::ir::normalize::normalize_identifier(func_name),
        out: Vec::new(),
    };
    collector.visit_rel_plan(plan);
    collector.out
}

struct RemoteSourceCallCollector {
    target: String,
    out: Vec<Vec<String>>,
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
                            ..
                        } => Some(s.clone()),
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
    match expr {
        ScalarExpr::Lit { .. } => DynamicSqlArgIr::Literal,
        ScalarExpr::Column { .. } | ScalarExpr::OuterRef { .. } => DynamicSqlArgIr::Variable,
        ScalarExpr::BinOp { op, .. } => {
            // `||` concat (BinOpKind::Concat) and `+` (Add) are SQL
            // string-building. MySQL `||` is logical-OR — the parser
            // lowers it to BinOpKind::LogicalOr (not Concat) per the
            // dialect, so it is correctly EXCLUDED here: a boolean-OR
            // result is not a dynamic-SQL construction shape. A clean
            // single-statement quoting concat → `ConcatQuoted`.
            if matches!(
                op,
                super::scalar::BinOpKind::Concat | super::scalar::BinOpKind::Add
            ) {
                refine.scalar_concat_shape(expr)
            } else {
                DynamicSqlArgIr::Unknown
            }
        }
        ScalarExpr::FuncCall { func, args, .. } => {
            if let ResolvedFunc::Unresolved { raw_name, .. } = func {
                if raw_name.eq_ignore_ascii_case("CONCAT") {
                    refine.scalar_concat_shape(expr)
                } else if raw_name.eq_ignore_ascii_case("FORMAT") && ambient_format_builds_sql() {
                    refine.scalar_format_shape(args)
                } else {
                    DynamicSqlArgIr::Unknown
                }
            } else {
                DynamicSqlArgIr::Unknown
            }
        }
        _ => DynamicSqlArgIr::Unknown,
    }
}
