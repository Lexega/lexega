// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! IR-side carrier for `CREATE / ALTER / DROP PROCEDURE`.
//!
//! Sibling-tier fact analogous to [`super::FunctionPlan`]: typed
//! projection of the AST that downstream `derive_facts_from_procedure_plan`
//! folds into a public `StatementFacts.ddl.procedure` carrier.
//!
//! The carrier is intentionally **structural**, not verdict-shaped:
//!
//! - `create_body.statement_kinds` — a closed enum of nested SQL
//!   statement forms reached by the body (recursive). Names what the
//!   SQL says, never the rule's interpretation.
//! - `alter_actions` — typed Vec of [`AstAlterProcedureActionKind`]
//!   discriminators (rename / set secure / unset secure / set
//!   properties / set tag / unset tag / unset comment / execute as /
//!   unknown). Each action carries kind-specific structural sub-facts
//!   (`SetProperties` carries the property-key set; `ExecuteAs` carries
//!   the mode lexeme).
//!
//! PROC-* rules predicate against the structural carrier; no fact field
//! is a renamed rule verdict.

use crate::ast::{
    AstAlterProcedure, AstAlterProcedureActionKind, AstCreateMssqlTrigger, AstCreateMysqlTrigger,
    AstCreateProcedureStmt, AstDefinitionVerb, AstDrop, AstStmt, ExecuteAsMode, NodeId,
};
use crate::context::node_metadata::IdentKey;
use crate::ir::dynamic_sql::{
    collect_inner_stmts_from_expr, parameter_keys, push_sql_run, push_sql_runs_held_in_values,
    DynamicSqlCallIr,
};
use crate::lexer::token::Span;

#[derive(Debug, Clone)]
pub struct ProcedurePlan {
    pub action: ProcedureAction,
    pub target: Option<ProcedureTarget>,
    pub options: ProcedureOptions,
    /// Some only for a statement that defines the body (`CREATE`, or a
    /// T-SQL `ALTER` restating it) and only when the body was parseable.
    pub create_body: Option<ProcedureBodyShape>,
    /// Non-empty only for an `ALTER` of a procedure's properties.
    pub alter_actions: Vec<ProcedureAlterActionShape>,
    /// MySQL `DEFINER =` security context, when present on a CREATE.
    /// The body runs under this account's privileges.
    pub definer: Option<crate::ir::DefinerLowered>,
    /// For a statement that defines the procedure: the rights it runs
    /// with, its `EXECUTE AS` or else the dialect's default (Snowflake:
    /// owner). `None` where neither says, and for any other statement.
    pub runs_as: Option<ExecuteAsMode>,
    pub node_id: NodeId,
    pub span: Span,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProcedureAction {
    Create,
    Alter,
    Drop,
}

#[derive(Debug, Clone)]
pub struct ProcedureTarget {
    pub name: String,
    pub schema: Option<String>,
    pub db: Option<String>,
    pub span: Span,
}

#[derive(Debug, Clone, Default)]
pub struct ProcedureOptions {
    pub or_replace: bool,
    pub or_alter: bool,
    pub if_not_exists: bool,
    pub if_exists: bool,
}

/// Structural projection of a CREATE PROCEDURE body.
#[derive(Debug, Clone, Default)]
pub struct ProcedureBodyShape {
    /// Closed-enum projection of SQL statement forms reached anywhere
    /// in the body (recursive across BEGIN/IF/WHILE/FOR/LOOP/REPEAT/
    /// CASE/TRY-CATCH). Variants are added when rules need new
    /// distinctions; everything else is invisible at the public layer.
    pub statement_kinds: Vec<ProcedureBodyStatementKindIr>,
    /// Total count of leaf statements (non-control-flow) reached in
    /// the body, summed across every recursion (so statements inside
    /// `WHILE` / `FOR` / `LOOP` / `IF` branches contribute too).
    /// Drives the `procedure_bodies_analyzed` / `statements_in_bodies`
    /// summary fields surfaced on the analyzer's report header.
    pub statements_count: usize,
    /// Typed dynamic-SQL call sites reached anywhere in the body,
    /// emitted by [`super::dynamic_sql::DynamicSqlCallIr`]. Each entry
    /// names a dynamic-SQL surface (Snowflake `EXECUTE IMMEDIATE`,
    /// T-SQL `EXEC(...)`/`sp_executesql`) and the structural shape
    /// of its argument and parameterization. DYNSQL-* rules predicate
    /// against this vector; `statement_kinds` is the kind-only summary
    /// for query-by-presence predicates.
    pub dynamic_sql_calls: Vec<DynamicSqlCallIr>,
    /// `EXECUTE AS { OWNER | CALLER }` from the CREATE PROCEDURE
    /// prelude (T-SQL `WITH EXECUTE AS …`, Snowflake `EXECUTE AS …`).
    /// `None` when absent. PROC-EXECAS-* rules predicate on this for
    /// the CREATE-time case; the equivalent ALTER-time mode lives on
    /// [`ProcedureAlterActionShape::execute_as_mode`].
    pub execute_as_mode: Option<ExecuteAsMode>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProcedureBodyStatementKindIr {
    /// `EXECUTE IMMEDIATE <expr>` (a.k.a. dynamic SQL surface).
    ExecuteImmediate,
}

/// Typed projection of a single `ALTER PROCEDURE … <action>`.
#[derive(Debug, Clone)]
pub struct ProcedureAlterActionShape {
    pub kind: ProcedureAlterActionKindIr,
    /// Some iff `kind == SetProperties`.
    pub properties: Option<ProcedurePropertiesShape>,
    /// Some iff `kind == ExecuteAs`.
    pub execute_as_mode: Option<ExecuteAsMode>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProcedureAlterActionKindIr {
    Rename,
    SetSecure,
    UnsetSecure,
    SetProperties,
    UnsetComment,
    SetTag,
    UnsetTag,
    ExecuteAs,
    Unknown,
}

#[derive(Debug, Clone, Default)]
pub struct ProcedurePropertiesShape {
    /// Closed-enum set of property keys present in the `SET
    /// <properties…>` clause. Property values are intentionally not
    /// surfaced — the structural fact is "which keys appeared", not
    /// "what they were set to" (no `properties_value` digest).
    pub keys: Vec<ProcedurePropertyKeyIr>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProcedurePropertyKeyIr {
    ExternalAccessIntegrations,
    Secrets,
    LogLevel,
    TraceLevel,
    Comment,
    AutoEventLogging,
    /// Property key not enumerated above — surfaced so rules that
    /// look only for *absence* of known keys can still discriminate.
    Other,
}

/// A routine's body block, unless it did not parse (an `AstStmt::Error`
/// over the whole body, counted as a statement not analysed).
pub(crate) fn parsed_body(body: Option<&AstStmt>) -> Option<&AstStmt> {
    body.filter(|b| !matches!(b, AstStmt::Error { .. }))
}

/// Lower a typed [`AstCreateProcedureStmt`] into a [`ProcedurePlan`].
pub fn lower_create_procedure_to_procedure_plan(
    s: &AstCreateProcedureStmt,
    source: &str,
    reasoning: &dyn crate::facts::reasoning::ScriptReasoning,
) -> ProcedurePlan {
    // Always materialize a body shape when *either* the body parsed
    // *or* the prelude carried an EXECUTE AS clause — the latter is a
    // policy-relevant property on its own (PROC-EXECAS-* rules) and
    // shouldn't be lost when the body is opaque.
    let body_stmt = parsed_body(s.body_stmt.as_deref());
    let parameters = parameter_keys(s.params.iter().map(|p| p.name_span), source);
    let runs_as = s.execute_as_mode.or_else(|| {
        crate::ir::normalize::dialect_in_force()
            .procedure_runs_as_owner_by_default()
            .then_some(ExecuteAsMode::Owner)
    });
    let create_body = if body_stmt.is_some()
        || !s.body_statements.is_empty()
        || s.execute_as_mode.is_some()
    {
        let mut shape = match body_stmt {
            Some(b) => {
                project_create_body(b, std::slice::from_ref(b), source, reasoning, &parameters)
            }
            None if s.body_statements.is_empty() => ProcedureBodyShape::default(),
            None => {
                // The body's classifier is seeded with the routine itself,
                // whose body is the statement list.
                let routine = AstStmt::CreateProcedure(Box::new(s.clone()));
                project_create_body(&routine, &s.body_statements, source, reasoning, &parameters)
            }
        };
        shape.execute_as_mode = s.execute_as_mode;
        Some(shape)
    } else {
        None
    };

    ProcedurePlan {
        action: match s.verb {
            AstDefinitionVerb::Create | AstDefinitionVerb::CreateOrAlter => ProcedureAction::Create,
            AstDefinitionVerb::Alter => ProcedureAction::Alter,
        },
        target: Some(target_from_span(source, s.name_span)),
        options: ProcedureOptions {
            or_replace: s.or_replace_span.is_some(),
            or_alter: s.or_alter_span.is_some(),
            if_not_exists: false,
            if_exists: false,
        },
        create_body,
        alter_actions: Vec::new(),
        definer: s
            .definer
            .as_ref()
            .map(|d| crate::ir::lower_definer(d, source)),
        runs_as,
        node_id: s.node_id,
        span: s.span,
    }
}

/// Lower a typed [`AstAlterProcedure`] into a [`ProcedurePlan`].
///
/// Single `action.kind` per statement; closed-enum exhaustive match
/// with no `_ =>` arm — every [`AstAlterProcedureActionKind`] variant
/// is enumerated explicitly so adding a new one forces a deliberate
/// projection decision.
pub fn lower_alter_procedure_to_procedure_plan(
    s: &AstAlterProcedure,
    source: &str,
) -> ProcedurePlan {
    let action_shape = project_alter_action(&s.action.kind, source);

    ProcedurePlan {
        action: ProcedureAction::Alter,
        target: Some(target_from_span(source, s.name_span)),
        options: ProcedureOptions {
            or_replace: false,
            or_alter: false,
            if_not_exists: false,
            if_exists: s.if_exists_span.is_some(),
        },
        create_body: None,
        alter_actions: vec![action_shape],
        definer: None,
        runs_as: None,
        node_id: s.node_id,
        span: s.span,
    }
}

/// Lower a generic [`AstStmt::Drop`] into a [`ProcedurePlan`] when the
/// `object_type_span` resolves to `PROCEDURE` (case-insensitive).
///
/// Returns `None` for any other object type — DROP for non-procedure
/// targets is handled by other lowerings or by the generic DDL path.
pub fn lower_drop_procedure_to_procedure_plan(s: &AstDrop, source: &str) -> Option<ProcedurePlan> {
    let object_type_span = s.object_type_span?;
    let text = source.get(object_type_span.start as usize..object_type_span.end as usize)?;
    if !text.trim().eq_ignore_ascii_case("PROCEDURE") {
        return None;
    }
    let target = s
        .targets
        .first()
        .map(|target| &target.name)
        .or(s.target_name.as_ref())
        .map(|name| target_from_name(source, name));
    Some(ProcedurePlan {
        action: ProcedureAction::Drop,
        target,
        options: ProcedureOptions {
            or_replace: false,
            or_alter: false,
            if_not_exists: false,
            if_exists: s.if_exists_span.is_some(),
        },
        create_body: None,
        alter_actions: Vec::new(),
        definer: None,
        runs_as: None,
        node_id: s.node_id,
        span: s.span,
    })
}

fn project_alter_action(
    kind: &AstAlterProcedureActionKind,
    source: &str,
) -> ProcedureAlterActionShape {
    use AstAlterProcedureActionKind as K;
    match kind {
        K::RenameTo { .. } => ProcedureAlterActionShape {
            kind: ProcedureAlterActionKindIr::Rename,
            properties: None,
            execute_as_mode: None,
        },
        K::SetSecure { .. } => ProcedureAlterActionShape {
            kind: ProcedureAlterActionKindIr::SetSecure,
            properties: None,
            execute_as_mode: None,
        },
        K::UnsetSecure { .. } => ProcedureAlterActionShape {
            kind: ProcedureAlterActionKindIr::UnsetSecure,
            properties: None,
            execute_as_mode: None,
        },
        K::SetProperties {
            properties_span, ..
        } => ProcedureAlterActionShape {
            kind: ProcedureAlterActionKindIr::SetProperties,
            properties: Some(project_properties_clause(source, *properties_span)),
            execute_as_mode: None,
        },
        K::UnsetComment { .. } => ProcedureAlterActionShape {
            kind: ProcedureAlterActionKindIr::UnsetComment,
            properties: None,
            execute_as_mode: None,
        },
        K::SetTag { .. } => ProcedureAlterActionShape {
            kind: ProcedureAlterActionKindIr::SetTag,
            properties: None,
            execute_as_mode: None,
        },
        K::UnsetTag { .. } => ProcedureAlterActionShape {
            kind: ProcedureAlterActionKindIr::UnsetTag,
            properties: None,
            execute_as_mode: None,
        },
        K::ExecuteAs { mode, .. } => ProcedureAlterActionShape {
            kind: ProcedureAlterActionKindIr::ExecuteAs,
            properties: None,
            execute_as_mode: Some(*mode),
        },
        K::Unknown { .. } => ProcedureAlterActionShape {
            kind: ProcedureAlterActionKindIr::Unknown,
            properties: None,
            execute_as_mode: None,
        },
    }
}

/// Decode `SET <properties…>` clause text into the typed key-presence
/// set: keyword tokens are matched case-insensitively.
fn project_properties_clause(source: &str, span: Span) -> ProcedurePropertiesShape {
    let Some(text) = source.get(span.start as usize..span.end as usize) else {
        return ProcedurePropertiesShape::default();
    };
    let upper = text.to_ascii_uppercase();
    let mut keys: Vec<ProcedurePropertyKeyIr> = Vec::new();

    let try_push = |keys: &mut Vec<ProcedurePropertyKeyIr>, k: ProcedurePropertyKeyIr| {
        if !keys.contains(&k) {
            keys.push(k);
        }
    };

    if upper.contains("EXTERNAL_ACCESS_INTEGRATIONS") {
        try_push(
            &mut keys,
            ProcedurePropertyKeyIr::ExternalAccessIntegrations,
        );
    }
    if upper.contains("SECRETS") {
        try_push(&mut keys, ProcedurePropertyKeyIr::Secrets);
    }
    if upper.contains("LOG_LEVEL") {
        try_push(&mut keys, ProcedurePropertyKeyIr::LogLevel);
    }
    if upper.contains("TRACE_LEVEL") {
        try_push(&mut keys, ProcedurePropertyKeyIr::TraceLevel);
    }
    if upper.contains("COMMENT") {
        try_push(&mut keys, ProcedurePropertyKeyIr::Comment);
    }
    if upper.contains("AUTO_EVENT_LOGGING") {
        try_push(&mut keys, ProcedurePropertyKeyIr::AutoEventLogging);
    }
    if keys.is_empty() {
        try_push(&mut keys, ProcedurePropertyKeyIr::Other);
    }
    ProcedurePropertiesShape { keys }
}

/// The body of a T-SQL trigger, projected as a procedure's body is; `None`
/// for a trigger without body statements.
pub(crate) fn project_mssql_trigger_body(
    s: &AstCreateMssqlTrigger,
    source: &str,
    reasoning: &dyn crate::facts::reasoning::ScriptReasoning,
) -> Option<ProcedureBodyShape> {
    if s.body.is_empty() {
        return None;
    }
    // The body's classifier is seeded with the trigger, whose body is the
    // statement list.
    let trigger = AstStmt::CreateMssqlTrigger(Box::new(s.clone()));
    // A trigger takes no parameters.
    let mut shape = project_create_body(&trigger, &s.body, source, reasoning, &[]);
    shape.execute_as_mode = s.execute_as_mode;
    Some(shape)
}

/// The body of a MySQL trigger, projected as a procedure's body is; `None`
/// for a trigger whose body was not parsed.
pub(crate) fn project_mysql_trigger_body(
    s: &AstCreateMysqlTrigger,
    source: &str,
    reasoning: &dyn crate::facts::reasoning::ScriptReasoning,
) -> Option<ProcedureBodyShape> {
    let body = parsed_body(s.body_stmt.as_deref())?;
    // A trigger takes no parameters.
    Some(project_create_body(
        body,
        std::slice::from_ref(body),
        source,
        reasoning,
        &[],
    ))
}

/// Project the body `stmts`; `seed` is what the body's dynamic-SQL
/// classifier reads its assignments from (the body, or the routine
/// holding it), `parameters` the routine's.
fn project_create_body(
    seed: &AstStmt,
    stmts: &[AstStmt],
    source: &str,
    reasoning: &dyn crate::facts::reasoning::ScriptReasoning,
    parameters: &[IdentKey],
) -> ProcedureBodyShape {
    let mut kinds: Vec<ProcedureBodyStatementKindIr> = Vec::new();
    let mut calls: Vec<DynamicSqlCallIr> = Vec::new();
    let mut count: usize = 0;
    // The body's classifier resolves a variable argument to the shape
    // it was built with (Unknown → Concat / Format / Literal), so the
    // walk below reports via-variable dynamic SQL by how it was
    // assembled.
    let classifier = reasoning.dynamic_sql_for_body(seed);
    for stmt in stmts {
        collect_body_statement_kinds(
            stmt,
            &mut kinds,
            &mut count,
            &mut calls,
            classifier.as_ref(),
            source,
            parameters,
        );
    }
    ProcedureBodyShape {
        statement_kinds: kinds,
        statements_count: count,
        dynamic_sql_calls: calls,
        execute_as_mode: None,
    }
}

fn push_kind(kinds: &mut Vec<ProcedureBodyStatementKindIr>, k: ProcedureBodyStatementKindIr) {
    if !kinds.contains(&k) {
        kinds.push(k);
    }
}

/// Recursive walk over the parsed body collecting the public set of
/// [`ProcedureBodyStatementKindIr`] forms reached AND building typed
/// [`DynamicSqlCallIr`] entries for every dynamic-SQL surface
/// encountered (Snowflake `EXECUTE IMMEDIATE`, T-SQL `EXEC(...)` and
/// `sp_executesql`).
///
/// Closed-enum exhaustive over [`AstStmt`] (no `_ =>` arm). Adding a
/// new [`AstStmt`] variant breaks this build and forces a deliberate
/// decision on what it counts; the bodies it holds are
/// [`AstStmt::bodies`]'s.
fn collect_body_statement_kinds(
    stmt: &AstStmt,
    kinds: &mut Vec<ProcedureBodyStatementKindIr>,
    count: &mut usize,
    dynamic_sql_calls: &mut Vec<DynamicSqlCallIr>,
    taint: &dyn crate::facts::reasoning::DynamicSqlClassifier,
    source: &str,
    parameters: &[IdentKey],
) {
    // A body nested deeper than the stack lets the analyzer walk is not read.
    let Some(_frame) = crate::ir::lower::enter_nested() else {
        return;
    };
    match stmt {
        // ───────── Trigger leaves ─────────
        AstStmt::ExecuteImmediate { .. } => {
            push_kind(kinds, ProcedureBodyStatementKindIr::ExecuteImmediate);
            *count += 1;
            push_sql_run(stmt, dynamic_sql_calls, taint, source, parameters);
        }
        // MySQL's `PREPARE … FROM <expr>`, T-SQL's `EXEC (…)` and `EXEC
        // sp_executesql …` run SQL text; PostgreSQL's `PREPARE … AS` and an
        // `EXEC` of another procedure do not.
        AstStmt::PgPrepare(_) | AstStmt::MssqlExec(_) => {
            *count += 1;
            push_sql_run(stmt, dynamic_sql_calls, taint, source, parameters);
        }
        // ───────── Body-bearing scripting variants ─────────
        // Their bodies are read below; the statement itself does not count.
        AstStmt::Block(_)
        | AstStmt::If(_)
        | AstStmt::CaseStmt(_)
        | AstStmt::While(_)
        | AstStmt::For(_)
        | AstStmt::ForEach(_)
        | AstStmt::Loop(_)
        | AstStmt::Repeat(_)
        | AstStmt::DeclareHandler(_)
        | AstStmt::MssqlTryCatch(_)
        | AstStmt::MssqlIf(_)
        | AstStmt::MssqlWhile(_) => {}

        // RESULTSET / assignment forms can wrap a statement-form EXECUTE
        // IMMEDIATE in expression position (Snowflake scripting:
        // `rs := (EXECUTE IMMEDIATE :stmt USING (a, b));`). Use the
        // shared expression descent in `dynamic_sql.rs` to collect any
        // inner statements, then recurse on each.
        AstStmt::Assign { expr, .. } | AstStmt::Let { expr, .. } => {
            for inner in collect_inner_stmts_from_expr(expr) {
                collect_body_statement_kinds(
                    inner,
                    kinds,
                    count,
                    dynamic_sql_calls,
                    taint,
                    source,
                    parameters,
                );
            }
        }

        // RETURN is itself a body statement (counts) and can wrap a
        // statement-form EXECUTE IMMEDIATE in expression position
        // (Snowflake table-returning bodies: `RETURN TABLE(EXECUTE
        // IMMEDIATE :q);`) — recurse so the inner dynamic SQL surfaces.
        AstStmt::Return { expr, .. } => {
            *count += 1;
            if let Some(expr) = expr {
                for inner in collect_inner_stmts_from_expr(expr) {
                    collect_body_statement_kinds(
                        inner,
                        kinds,
                        count,
                        dynamic_sql_calls,
                        taint,
                        source,
                        parameters,
                    );
                }
            }
        }

        // A T-SQL `INSERT … EXEC` counts, and so does its EXEC (read below).
        AstStmt::Insert(_) => {
            *count += 1;
        }

        // A value a `DECLARE` or `SET` assigns can run SQL text (Snowflake
        // `DECLARE res RESULTSET DEFAULT (EXECUTE IMMEDIATE :q)`).
        AstStmt::Declare { .. } | AstStmt::SetVariable { .. } | AstStmt::MysqlSet(_) => {
            *count += 1;
            push_sql_runs_held_in_values(stmt, dynamic_sql_calls, taint, source, parameters);
        }

        // ───────── Non-body-bearing leaves ─────────
        // Listed exhaustively so the closed-enum contract remains
        // compiler-enforced.
        AstStmt::Select(_)
        | AstStmt::Perform(_)
        | AstStmt::SetSelect(_)
        | AstStmt::ValuesQuery(_)
        | AstStmt::ReplaceInto(_)
        | AstStmt::MultiInsert(_)
        | AstStmt::Update(_)
        | AstStmt::Delete(_)
        | AstStmt::Merge(_)
        | AstStmt::Explain(_)
        | AstStmt::PsqlGexec(_)
        // `EXECUTE IMMEDIATE FROM <stage_file>` loads SQL from an external
        // file; no in-body statement to recurse into. Top-level recognition
        // is handled at the statement dispatch.
        | AstStmt::ExecuteImmediateFrom(_)
        | AstStmt::OpaqueContent { .. }
        | AstStmt::ClauseFragment { .. }
        | AstStmt::JinjaPlaceholder { .. }
        | AstStmt::JinjaConditionalStmt(_)
        | AstStmt::Error { .. }
        | AstStmt::GoBatchSeparator { .. }
        | AstStmt::SqlcmdCommand { .. }
        | AstStmt::Reconfigure { .. }
        | AstStmt::MssqlServerCommand { .. }
        | AstStmt::AlterAccount(_)
        | AstStmt::AlterAggregationPolicy(_)
        | AstStmt::AlterApiIntegration(_)
        | AstStmt::AlterNotificationIntegration(_)
        | AstStmt::CreateShare(_)
        | AstStmt::AlterShare(_)
        | AstStmt::CreateDatashare(_)
        | AstStmt::AlterDatashare(_)
        | AstStmt::CreateSecurityIntegration(_)
        | AstStmt::AlterSecurityIntegration(_)
        | AstStmt::AlterReplicationGroup(_)
        | AstStmt::AlterFailoverGroup(_)
        | AstStmt::AlterAuthenticationPolicy(_)
        | AstStmt::AlterCatalog(_)
        | AstStmt::AlterConnection(_)
        | AstStmt::AlterDatabase(_)
        | AstStmt::AlterDomain(_)
        | AstStmt::AlterDynamicTable(_)
        | AstStmt::AlterExternalAccessIntegration(_)
        | AstStmt::AlterExternalLocation(_)
        | AstStmt::AlterFunction(_)
        | AstStmt::AlterIndex(_)
        | AstStmt::AlterMaterializedView(_)
        | AstStmt::AlterMaskingPolicy(_)
        | AstStmt::AlterNetworkPolicy(_)
        | AstStmt::AlterPasswordPolicy(_)
        | AstStmt::AlterPgPolicy(_)
        | AstStmt::AlterPgTrigger(_)
        | AstStmt::AlterPipe(_)
        | AstStmt::AlterProcedure(_)
        | AstStmt::AlterProjectionPolicy(_)
        | AstStmt::AlterJoinPolicy(_)
        | AstStmt::AlterRowAccessPolicy(_)
        | AstStmt::AlterSchema(_)
        | AstStmt::AlterSequence(_)
        | AstStmt::AlterSessionPolicy(_)
        | AstStmt::AlterSession(_)
        | AstStmt::AlterStage(_)
        | AstStmt::AlterStorageCredential(_)
        | AstStmt::AlterStorageIntegration(_)
        | AstStmt::AlterStream(_)
        | AstStmt::AlterTable(_)
        | AstStmt::AlterTask(_)
        | AstStmt::AlterType(_)
        | AstStmt::AlterUser(_)
        | AstStmt::AlterView(_)
        | AstStmt::AlterVolume(_)
        | AstStmt::AlterWarehouse(_)
        | AstStmt::AnalyzeStmt(_)
        | AstStmt::Await { .. }
        | AstStmt::BeginTransaction { .. }
        | AstStmt::BqAlterModel(_)
        | AstStmt::BqAlterVectorIndex(_)
        | AstStmt::BqAssert(_)
        | AstStmt::BqCreateModel(_)
        | AstStmt::BqCreateSearchIndex(_)
        | AstStmt::BqCreateSnapshotTable(_)
        | AstStmt::BqCreateVectorIndex(_)
        | AstStmt::BqDropModel(_)
        | AstStmt::BqDropSearchIndex(_)
        | AstStmt::BqDropSnapshotTable(_)
        | AstStmt::BqDropVectorIndex(_)
        | AstStmt::BqExportData(_)
        | AstStmt::BqExportModel(_)
        | AstStmt::BqLoadData(_)
        | AstStmt::MysqlLoadData(_)
        | AstStmt::MysqlRenameTable(_)
        | AstStmt::CreateEvent(_)
        | AstStmt::AlterEvent(_)
        | AstStmt::CreateMysqlTrigger(_)
        | AstStmt::Break { .. }
        | AstStmt::CacheTable(_)
        | AstStmt::Call { .. }
        | AstStmt::Cancel { .. }
        | AstStmt::CloseCursor { .. }
        | AstStmt::CommentOn(_)
        | AstStmt::Commit { .. }
        | AstStmt::Continue { .. }
        | AstStmt::CopyIntoLocation { .. }
        | AstStmt::Unload { .. }
        | AstStmt::RedshiftCopy { .. }
        | AstStmt::CopyIntoTable { .. }
        | AstStmt::CreateAggregationPolicy(_)
        | AstStmt::CreateApiIntegration(_)
        | AstStmt::CreateNotificationIntegration(_)
        | AstStmt::CreateAuthenticationPolicy(_)
        | AstStmt::CreateCatalog(_)
        | AstStmt::AlterUserMapping(_)
        | AstStmt::DropUserMapping(_)
        | AstStmt::CreateUserMapping(_)
        | AstStmt::CreateForeignTable(_)
        | AstStmt::ImportForeignSchema(_)
        | AstStmt::CreateForeignServer(_)
        | AstStmt::AlterForeignServer(_)
        | AstStmt::MssqlAlterServerConfiguration(_)
        | AstStmt::MssqlCreateExternalDataSource(_)
        | AstStmt::MssqlAlterExternalDataSource(_)
        | AstStmt::CreateConnection(_)
        | AstStmt::CreateDatabase(_)
        | AstStmt::CreateDomain(_)
        | AstStmt::CreateDynamicTable(_)
        | AstStmt::CreateExtension(_)
        | AstStmt::CreateExternalAccessIntegration(_)
        | AstStmt::CreateExternalLocation(_)
        | AstStmt::CreateExternalTable(_)
        | AstStmt::CreateExternalSchema(_)
        | AstStmt::CreateFlow(_)
        | AstStmt::CreateFunction(_)
        | AstStmt::CreateIndex(_)
        | AstStmt::CreateSynonym(_)
        | AstStmt::CreateMaskingPolicy(_)
        | AstStmt::CreateMssqlTrigger(_)
        | AstStmt::CreateNetworkPolicy(_)
        | AstStmt::CreatePasswordPolicy(_)
        | AstStmt::CreatePgPolicy(_)
        | AstStmt::CreatePgTrigger(_)
        | AstStmt::CreatePipe(_)
        | AstStmt::CreateProcedure(_)
        | AstStmt::CreateProjectionPolicy(_)
        | AstStmt::CreateJoinPolicy(_)
        | AstStmt::CreateRowAccessPolicy(_)
        | AstStmt::CreateSchema(_)
        | AstStmt::CreateSequence(_)
        | AstStmt::CreateSessionPolicy(_)
        | AstStmt::CreateStage(_)
        | AstStmt::CreateStorageCredential(_)
        | AstStmt::CreateStorageIntegration(_)
        | AstStmt::CreateStream(_)
        | AstStmt::CreateTable(_)
        | AstStmt::CreateTableFunction(_)
        | AstStmt::CreateTask(_)
        | AstStmt::CreateType(_)
        | AstStmt::CreateView(_)
        | AstStmt::CreateVolume(_)
        | AstStmt::CreateWarehouse(_)
        | AstStmt::DeclareCondition { .. }
        | AstStmt::DeclareCursor { .. }
        | AstStmt::DeclareTable { .. }
        | AstStmt::Deny(_)
        | AstStmt::AlterAuthorization(_)
        | AstStmt::MssqlExecuteAs(_)
        | AstStmt::MssqlRevert { .. }
        | AstStmt::MssqlAuditDdl(_)
        | AstStmt::MssqlSecurityObjectDdl(_)
        | AstStmt::Describe(_)
        | AstStmt::DescribeHistory(_)
        | AstStmt::DoBlock(_)
        | AstStmt::Drop(_)
        | AstStmt::DropAggregationPolicy(_)
        | AstStmt::DropAllRowAccessPolicies(_)
        | AstStmt::DropApiIntegration(_)
        | AstStmt::DropNotificationIntegration(_)
        | AstStmt::DropAuthenticationPolicy(_)
        | AstStmt::DropCatalog(_)
        | AstStmt::DropConnection(_)
        | AstStmt::DropDatabase(_)
        | AstStmt::DropDomain(_)
        | AstStmt::DropExternalAccessIntegration(_)
        | AstStmt::DropExternalLocation(_)
        | AstStmt::DropMaskingPolicy(_)
        | AstStmt::DropMssqlTrigger(_)
        | AstStmt::MssqlTriggerState(_)
        | AstStmt::DropNetworkPolicy(_)
        | AstStmt::DropPasswordPolicy(_)
        | AstStmt::DropPgPolicy(_)
        | AstStmt::DropPgTrigger(_)
        | AstStmt::DropPipe(_)
        | AstStmt::DropProjectionPolicy(_)
        | AstStmt::DropJoinPolicy(_)
        | AstStmt::DropRowAccessPolicy(_)
        | AstStmt::DropSchema(_)
        | AstStmt::DropSessionPolicy(_)
        | AstStmt::DropStorageCredential(_)
        | AstStmt::DropStorageIntegration(_)
        | AstStmt::DropStream(_)
        | AstStmt::DropTask(_)
        | AstStmt::DropVolume(_)
        | AstStmt::DropWarehouse(_)
        | AstStmt::FetchCursor { .. }
        | AstStmt::GetDiagnostics { .. }
        | AstStmt::Grant(_)
        | AstStmt::LetCursor { .. }
        | AstStmt::MssqlAlterExternalModel(_)
        | AstStmt::MssqlBulkInsert(_)
        | AstStmt::MssqlCreateExternalModel(_)
        | AstStmt::MssqlCreateVectorIndex(_)
        | AstStmt::MssqlDropExternalModel(_)
        | AstStmt::MssqlGoto(_)
        | AstStmt::MssqlLabel(_)
        | AstStmt::MssqlPrint(_)
        | AstStmt::MssqlRaiserror(_)
        | AstStmt::MssqlSetOption(_)
        | AstStmt::MysqlUnlockTables(_)
        | AstStmt::MssqlThrow(_)
        | AstStmt::MssqlWaitfor(_)
        | AstStmt::Null { .. }
        | AstStmt::OpenCursor { .. }
        | AstStmt::Optimize(_)
        | AstStmt::AlterPrincipal(_)
        | AstStmt::PgAlterRule(_)
        | AstStmt::PgAlterSystem(_)
        | AstStmt::PgAlterTableTriggerState(_)
        | AstStmt::PgAlterTablespace(_)
        | AstStmt::PgCluster(_)
        | AstStmt::PgCopy(_)
        | AstStmt::PgCreateAggregate(_)
        | AstStmt::PgCreateOperator(_)
        | AstStmt::CreatePrincipal(_)
        | AstStmt::PgCreateRule(_)
        | AstStmt::MssqlCreateRule(_)
        | AstStmt::MysqlDo(_)
        | AstStmt::ExecuteTask(_)
        | AstStmt::MysqlCreateLoadableFunction(_)
        | AstStmt::MysqlAdmin(_)
        | AstStmt::PgCreateTablespace(_)
        | AstStmt::PgDeallocate(_)
        | AstStmt::PgDiscard(_)
        | AstStmt::PgDropExtension(_)
        | AstStmt::PgDropIndex(_)
        | AstStmt::PgDropOwned(_)
        | AstStmt::DropPrincipal(_)
        | AstStmt::PgDropRule(_)
        | AstStmt::PgDropSequence(_)
        | AstStmt::PgDropTablespace(_)
        | AstStmt::PgDropType(_)
        | AstStmt::PgExecute(_)
        | AstStmt::PgListen(_)
        | AstStmt::PgLockTable(_)
        | AstStmt::PgNotify(_)
        | AstStmt::PgPublication(_)
        | AstStmt::PgReassignOwned(_)
        | AstStmt::PgRefreshMatview(_)
        | AstStmt::PgSet(_)
        | AstStmt::PgSubscription(_)
        | AstStmt::PgUnlisten(_)
        | AstStmt::PipeChain { .. }
        | AstStmt::Raise { .. }
        | AstStmt::Reindex(_)
        | AstStmt::RepairTable(_)
        | AstStmt::Resignal { .. }
        | AstStmt::Restore(_)
        | AstStmt::MssqlBackup(_)
        | AstStmt::MssqlRestore(_)
        | AstStmt::MssqlDbcc(_)
        | AstStmt::MssqlKeyManagement(_)
        | AstStmt::MssqlSecurityPolicy(_)
        | AstStmt::MssqlKeyBackup(_)
        | AstStmt::MssqlAssembly(_)
        | AstStmt::MssqlAddSignature(_)
        | AstStmt::MssqlSetuser(_)
        | AstStmt::MssqlAlterServiceMasterKey(_)
        | AstStmt::PgAlterDefaultPrivileges(_)
        | AstStmt::Revoke(_)
        | AstStmt::Rollback { .. }
        | AstStmt::Savepoint(_)
        | AstStmt::Show(_)
        | AstStmt::Signal { .. }
        | AstStmt::Truncate(_)
        | AstStmt::UncacheTable(_)
        | AstStmt::UndropDatabase(_)
        | AstStmt::UndropSchema(_)
        | AstStmt::UndropTable(_)
        | AstStmt::UndropType(_)
        | AstStmt::CreateTag(_)
        | AstStmt::AlterTag(_)
        | AstStmt::CreateFileFormat(_)
        | AstStmt::AlterFileFormat(_)
        | AstStmt::UndropTag(_)
        | AstStmt::CreateSecret(_)
        | AstStmt::AlterSecret(_)
        | AstStmt::CreateNetworkRule(_)
        | AstStmt::AlterNetworkRule(_)
        | AstStmt::CreateResourceMonitor(_)
        | AstStmt::AlterResourceMonitor(_)
        | AstStmt::CreateComputePool(_)
        | AstStmt::AlterComputePool(_)
        | AstStmt::CreateGitRepository(_)
        | AstStmt::CreateExternalFunction(_)
        | AstStmt::AlterGitRepository(_)
        | AstStmt::CreateImageRepository(_)
        | AstStmt::AlterImageRepository(_)
        | AstStmt::CreateStreamlit(_)
        | AstStmt::AlterStreamlit(_)
        | AstStmt::CreateService(_)
        | AstStmt::AlterService(_)
        | AstStmt::CreateNotebook(_)
        | AstStmt::AlterNotebook(_)
        | AstStmt::CreateSemanticView(_)
        | AstStmt::AlterSemanticView(_)
        | AstStmt::CreateCortexSearchService(_)
        | AstStmt::AlterCortexSearchService(_)
        | AstStmt::CreateApplication(_)
        | AstStmt::AlterApplication(_)
        | AstStmt::CreateApplicationPackage(_)
        | AstStmt::AlterApplicationPackage(_)
        | AstStmt::CreateListing(_)
        | AstStmt::AlterListing(_)
        | AstStmt::CreateManagedAccount(_)
        | AstStmt::CreateAccount(_)
        | AstStmt::StageFileCommand(_)
        | AstStmt::CreateAlert(_)
        | AstStmt::CreateDataMetricFunction(_)
        | AstStmt::CreateReplicationFailoverGroup(_)
        | AstStmt::AlterAlert(_)
        | AstStmt::Use(_)
        | AstStmt::Vacuum(_) => {
            *count += 1;
        }
    }
    // Every body it holds but that of a procedure, function or trigger
    // defined in this one.
    for body in stmt.bodies() {
        match body.role {
            crate::ast::BodyRole::Routine if defines_reported_routine(stmt) => continue,
            crate::ast::BodyRole::Routine
            | crate::ast::BodyRole::ExceptionHandler
            | crate::ast::BodyRole::Declarations
            | crate::ast::BodyRole::Block
            | crate::ast::BodyRole::Pipe
            | crate::ast::BodyRole::Branch
            | crate::ast::BodyRole::Else
            | crate::ast::BodyRole::Loop
            | crate::ast::BodyRole::LoopQuery
            | crate::ast::BodyRole::Catch
            | crate::ast::BodyRole::HandlerAction
            | crate::ast::BodyRole::InsertExec => {}
        }
        for s in body.stmts {
            collect_body_statement_kinds(
                s,
                kinds,
                count,
                dynamic_sql_calls,
                taint,
                source,
                parameters,
            );
        }
    }
}

/// Whether `stmt` defines a procedure, function or trigger, whose body is
/// its own and not that of a routine holding it.
pub(crate) fn defines_reported_routine(stmt: &AstStmt) -> bool {
    matches!(
        stmt,
        AstStmt::CreateProcedure(_)
            | AstStmt::CreateFunction(_)
            | AstStmt::CreateMssqlTrigger(_)
            | AstStmt::CreateMysqlTrigger(_)
    )
}

/// The target `name` names, each part as written; a name the parser did
/// not read as `[[db.]schema.]name` is read from its text.
fn target_from_name(source: &str, name: &crate::ast::AstObjectRef) -> ProcedureTarget {
    let Some((db, schema, name_text)) = crate::ir::utils::routine_name_parts(source, name) else {
        return target_from_span(source, name.span);
    };
    ProcedureTarget {
        name: name_text,
        schema,
        db,
        span: name.span,
    }
}

fn target_from_span(source: &str, span: Span) -> ProcedureTarget {
    let raw = source
        .get(span.start as usize..span.end as usize)
        .unwrap_or("")
        .trim();
    let (db, schema, name) =
        crate::ir::utils::text_name_parts(raw).unwrap_or_else(|| (None, None, raw.to_string()));
    ProcedureTarget {
        name,
        schema,
        db,
        span,
    }
}
