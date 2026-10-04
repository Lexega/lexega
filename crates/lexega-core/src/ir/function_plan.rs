// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! IR-side carrier for `CREATE / ALTER FUNCTION`.
//!
//! Sibling-tier fact analogous to [`super::ProcedurePlan`]: typed
//! projection of the AST that downstream `derive_facts_from_function_plan`
//! folds into a public `StatementFacts.ddl.function` carrier.
//!
//! The carrier is intentionally **structural**, not verdict-shaped:
//!
//! - `create_body.statement_kinds` — a closed enum of nested SQL
//!   statement forms reached by the body (recursive). Names what the
//!   SQL says, never the rule's interpretation.
//! - `alter_actions` — typed Vec of [`AstAlterFunctionActionKind`]
//!   discriminators. `SetProperties` carries the property-key set;
//!   other variants carry no kind-specific sub-facts today (room to
//!   grow additively).
//!
//! UDF-* rules predicate against the structural carrier; no fact field
//! is a renamed rule verdict.

use crate::ast::{
    AstAlterFunction, AstAlterFunctionActionKind, AstCreateFunctionStmt,
    AstCreateTableFunctionStmt, AstDrop, AstStmt, NodeId,
};
use crate::ir::dynamic_sql::{
    classify_execute_immediate_parameterization, collect_inner_stmts_from_expr, DynamicSqlArgIr,
    DynamicSqlCallIr, DynamicSqlParameterizationIr, DynamicSqlSurfaceIr,
};
use crate::lexer::token::Span;

#[derive(Debug, Clone)]
pub struct FunctionPlan {
    pub action: FunctionAction,
    pub target: Option<FunctionTarget>,
    pub options: FunctionOptions,
    /// Some only when `action == Create` and the body was parseable.
    pub create_body: Option<FunctionBodyShape>,
    /// Non-empty only when `action == Alter`.
    pub alter_actions: Vec<FunctionAlterActionShape>,
    /// MySQL `DEFINER =` security context, when present on a CREATE.
    /// The body runs under this account's privileges.
    pub definer: Option<crate::ir::DefinerLowered>,
    pub node_id: NodeId,
    pub span: Span,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FunctionAction {
    Create,
    Alter,
    Drop,
}

#[derive(Debug, Clone)]
pub struct FunctionTarget {
    pub name: String,
    pub schema: Option<String>,
    pub db: Option<String>,
    pub span: Span,
}

#[derive(Debug, Clone, Default)]
pub struct FunctionOptions {
    pub or_replace: bool,
    pub or_alter: bool,
    pub if_not_exists: bool,
    pub if_exists: bool,
}

/// Structural projection of a CREATE FUNCTION body.
#[derive(Debug, Clone, Default)]
pub struct FunctionBodyShape {
    pub statement_kinds: Vec<FunctionBodyStatementKindIr>,
    /// Total count of leaf statements reached in the function body,
    /// recursive across `BEGIN`/`IF`/`WHILE`/`FOR`/`LOOP`/`REPEAT`/
    /// `CASE`/`TRY-CATCH`. Sibling to
    /// [`super::procedure_plan::ProcedureBodyShape::statements_count`].
    pub statements_count: usize,
    /// Typed dynamic-SQL call sites reached anywhere in the function
    /// body. Mirror of
    /// [`super::procedure_plan::ProcedureBodyShape::dynamic_sql_calls`].
    pub dynamic_sql_calls: Vec<DynamicSqlCallIr>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FunctionBodyStatementKindIr {
    /// `EXECUTE IMMEDIATE <expr>` — the SQL surface for dynamic SQL.
    ExecuteImmediate,
}

/// Typed projection of a single `ALTER FUNCTION … <action>`.
#[derive(Debug, Clone)]
pub struct FunctionAlterActionShape {
    pub kind: FunctionAlterActionKindIr,
    /// Some iff `kind == SetProperties`.
    pub properties: Option<FunctionPropertiesShape>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FunctionAlterActionKindIr {
    Rename,
    SetSecure,
    UnsetSecure,
    SetProperties,
    UnsetProperties,
    SetTag,
    UnsetTag,
    SetApiIntegration,
    SetHeaders,
    SetContextHeaders,
    SetMaxBatchRows,
    SetCompression,
    SetRequestTranslator,
    SetResponseTranslator,
    Unknown,
}

#[derive(Debug, Clone, Default)]
pub struct FunctionPropertiesShape {
    pub keys: Vec<FunctionPropertyKeyIr>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FunctionPropertyKeyIr {
    ExternalAccessIntegrations,
    Secrets,
    LogLevel,
    TraceLevel,
    Comment,
    Other,
}

/// Lower a typed [`AstCreateFunctionStmt`] into a [`FunctionPlan`].
pub fn lower_create_function_to_function_plan(
    s: &AstCreateFunctionStmt,
    source: &str,
    reasoning: &dyn crate::facts::reasoning::ScriptReasoning,
) -> FunctionPlan {
    let create_body = s
        .body_stmt
        .as_deref()
        .map(|b| project_create_body(b, source, reasoning));

    FunctionPlan {
        action: FunctionAction::Create,
        target: Some(target_from_span(source, s.name_span)),
        options: FunctionOptions {
            or_replace: s.or_replace_span.is_some(),
            or_alter: s.or_alter_span.is_some(),
            if_not_exists: s.if_not_exists_span.is_some(),
            if_exists: false,
        },
        create_body,
        alter_actions: Vec::new(),
        definer: s
            .definer
            .as_ref()
            .map(|d| crate::ir::lower_definer(d, source)),
        node_id: s.node_id,
        span: s.span,
    }
}

/// Lower a typed [`AstCreateTableFunctionStmt`] (BigQuery TVF) into a
/// [`FunctionPlan`]. Table functions are projected onto the same
/// substrate as scalar UDFs: governance semantics (creation event,
/// body statement-kind projection for dynamic-SQL detection) are
/// identical, so UDF-NEW / UDF-DYNSQL fire uniformly across both
/// shapes. The TVF carries no `or_alter` / `if_exists` (creation-only),
/// so those slots stay default.
pub fn lower_create_table_function_to_function_plan(
    s: &AstCreateTableFunctionStmt,
    _source: &str,
    reasoning: &dyn crate::facts::reasoning::ScriptReasoning,
) -> FunctionPlan {
    let create_body = s
        .body_stmt
        .as_deref()
        .map(|b| project_create_body(b, _source, reasoning));

    FunctionPlan {
        action: FunctionAction::Create,
        target: Some(target_from_span(_source, s.name_span)),
        options: FunctionOptions {
            or_replace: s.or_replace_span.is_some(),
            or_alter: false,
            if_not_exists: s.if_not_exists_span.is_some(),
            if_exists: false,
        },
        create_body,
        alter_actions: Vec::new(),
        definer: None,
        node_id: s.node_id,
        span: s.span,
    }
}

/// Lower a typed [`AstAlterFunction`] into a [`FunctionPlan`].
///
/// Single `action.kind` per statement; closed-enum exhaustive match
/// with no `_ =>` arm — every [`AstAlterFunctionActionKind`] variant is
/// enumerated explicitly so adding a new one forces a deliberate
/// projection decision.
pub fn lower_alter_function_to_function_plan(s: &AstAlterFunction, source: &str) -> FunctionPlan {
    let action_shape = project_alter_action(&s.action.kind, source);

    FunctionPlan {
        action: FunctionAction::Alter,
        target: Some(target_from_span(source, s.name_span)),
        options: FunctionOptions {
            or_replace: false,
            or_alter: false,
            if_not_exists: false,
            if_exists: s.if_exists_span.is_some(),
        },
        create_body: None,
        alter_actions: vec![action_shape],
        definer: None,
        node_id: s.node_id,
        span: s.span,
    }
}

/// Lower a generic [`AstDrop`] whose `object_type_span` text is
/// `FUNCTION` into a [`FunctionPlan`] with `action = Drop`. Mirrors
/// [`super::ProcedurePlan`]'s `lower_drop_procedure_to_procedure_plan`:
/// returns `None` for any other object type so the lib.rs dispatch can
/// fall through to the next family's lowering.
pub fn lower_drop_function_to_function_plan(s: &AstDrop, source: &str) -> Option<FunctionPlan> {
    let object_type_span = s.object_type_span?;
    let text = source.get(object_type_span.start as usize..object_type_span.end as usize)?;
    // Whitespace-normalized, case-insensitive match against either
    // scalar `DROP FUNCTION` or BigQuery `DROP TABLE FUNCTION`. The
    // latter funnels TVFs through the same governance substrate so
    // FUNC-DROP fires uniformly.
    let normalized: String = text.split_whitespace().collect::<Vec<_>>().join(" ");
    let upper = normalized.to_ascii_uppercase();
    if upper != "FUNCTION" && upper != "TABLE FUNCTION" {
        return None;
    }
    let target = s.target_name_span.map(|sp| target_from_span(source, sp));
    Some(FunctionPlan {
        action: FunctionAction::Drop,
        target,
        options: FunctionOptions {
            or_replace: false,
            or_alter: false,
            if_not_exists: false,
            if_exists: s.if_exists_span.is_some(),
        },
        create_body: None,
        alter_actions: Vec::new(),
        definer: None,
        node_id: s.node_id,
        span: s.span,
    })
}

fn project_alter_action(
    kind: &AstAlterFunctionActionKind,
    source: &str,
) -> FunctionAlterActionShape {
    use AstAlterFunctionActionKind as K;
    match kind {
        K::RenameTo { .. } => FunctionAlterActionShape {
            kind: FunctionAlterActionKindIr::Rename,
            properties: None,
        },
        K::SetSecure { .. } => FunctionAlterActionShape {
            kind: FunctionAlterActionKindIr::SetSecure,
            properties: None,
        },
        K::UnsetSecure { .. } => FunctionAlterActionShape {
            kind: FunctionAlterActionKindIr::UnsetSecure,
            properties: None,
        },
        K::SetProperties {
            properties_span, ..
        } => FunctionAlterActionShape {
            kind: FunctionAlterActionKindIr::SetProperties,
            properties: Some(project_properties_clause(source, *properties_span)),
        },
        K::UnsetProperties { .. } => FunctionAlterActionShape {
            kind: FunctionAlterActionKindIr::UnsetProperties,
            properties: None,
        },
        K::SetTag { .. } => FunctionAlterActionShape {
            kind: FunctionAlterActionKindIr::SetTag,
            properties: None,
        },
        K::UnsetTag { .. } => FunctionAlterActionShape {
            kind: FunctionAlterActionKindIr::UnsetTag,
            properties: None,
        },
        K::SetApiIntegration { .. } => FunctionAlterActionShape {
            kind: FunctionAlterActionKindIr::SetApiIntegration,
            properties: None,
        },
        K::SetHeaders { .. } => FunctionAlterActionShape {
            kind: FunctionAlterActionKindIr::SetHeaders,
            properties: None,
        },
        K::SetContextHeaders { .. } => FunctionAlterActionShape {
            kind: FunctionAlterActionKindIr::SetContextHeaders,
            properties: None,
        },
        K::SetMaxBatchRows { .. } => FunctionAlterActionShape {
            kind: FunctionAlterActionKindIr::SetMaxBatchRows,
            properties: None,
        },
        K::SetCompression { .. } => FunctionAlterActionShape {
            kind: FunctionAlterActionKindIr::SetCompression,
            properties: None,
        },
        K::SetRequestTranslator { .. } => FunctionAlterActionShape {
            kind: FunctionAlterActionKindIr::SetRequestTranslator,
            properties: None,
        },
        K::SetResponseTranslator { .. } => FunctionAlterActionShape {
            kind: FunctionAlterActionKindIr::SetResponseTranslator,
            properties: None,
        },
        K::Unknown { .. } => FunctionAlterActionShape {
            kind: FunctionAlterActionKindIr::Unknown,
            properties: None,
        },
    }
}

/// Decode `SET <properties…>` clause text into the typed key-presence
/// set, case-insensitively matching the keyword tokens.
fn project_properties_clause(source: &str, span: Span) -> FunctionPropertiesShape {
    let Some(text) = source.get(span.start as usize..span.end as usize) else {
        return FunctionPropertiesShape::default();
    };
    let upper = text.to_ascii_uppercase();
    let mut keys: Vec<FunctionPropertyKeyIr> = Vec::new();

    let try_push = |keys: &mut Vec<FunctionPropertyKeyIr>, k: FunctionPropertyKeyIr| {
        if !keys.contains(&k) {
            keys.push(k);
        }
    };

    if upper.contains("EXTERNAL_ACCESS_INTEGRATIONS") {
        try_push(&mut keys, FunctionPropertyKeyIr::ExternalAccessIntegrations);
    }
    if upper.contains("SECRETS") {
        try_push(&mut keys, FunctionPropertyKeyIr::Secrets);
    }
    if upper.contains("LOG_LEVEL") {
        try_push(&mut keys, FunctionPropertyKeyIr::LogLevel);
    }
    if upper.contains("TRACE_LEVEL") {
        try_push(&mut keys, FunctionPropertyKeyIr::TraceLevel);
    }
    if upper.contains("COMMENT") {
        try_push(&mut keys, FunctionPropertyKeyIr::Comment);
    }
    if keys.is_empty() {
        try_push(&mut keys, FunctionPropertyKeyIr::Other);
    }
    FunctionPropertiesShape { keys }
}

fn project_create_body(
    body: &AstStmt,
    source: &str,
    reasoning: &dyn crate::facts::reasoning::ScriptReasoning,
) -> FunctionBodyShape {
    let mut kinds: Vec<FunctionBodyStatementKindIr> = Vec::new();
    let mut calls: Vec<DynamicSqlCallIr> = Vec::new();
    let mut count: usize = 0;
    let classifier = reasoning.dynamic_sql_for_body(body);
    collect_body_statement_kinds(
        body,
        &mut kinds,
        &mut count,
        &mut calls,
        classifier.as_ref(),
        source,
    );
    FunctionBodyShape {
        statement_kinds: kinds,
        statements_count: count,
        dynamic_sql_calls: calls,
    }
}

fn push_kind(kinds: &mut Vec<FunctionBodyStatementKindIr>, k: FunctionBodyStatementKindIr) {
    if !kinds.contains(&k) {
        kinds.push(k);
    }
}

/// Recursive walk over the parsed body collecting the public set of
/// [`FunctionBodyStatementKindIr`] forms reached AND typed
/// [`DynamicSqlCallIr`] call sites for every dynamic-SQL surface
/// encountered. Mirror of
/// [`super::procedure_plan::collect_body_statement_kinds`].
///
/// Closed-enum exhaustive over [`AstStmt`] (no `_ =>` arm). Adding a
/// new [`AstStmt`] variant breaks this build and forces a deliberate
/// recursion-or-leaf decision.
fn collect_body_statement_kinds(
    stmt: &AstStmt,
    kinds: &mut Vec<FunctionBodyStatementKindIr>,
    count: &mut usize,
    dynamic_sql_calls: &mut Vec<DynamicSqlCallIr>,
    taint: &dyn crate::facts::reasoning::DynamicSqlClassifier,
    source: &str,
) {
    match stmt {
        // ───────── Trigger leaves ─────────
        AstStmt::ExecuteImmediate {
            node_id,
            span,
            sql_expr,
            using_span,
            using_args,
            ..
        } => {
            push_kind(kinds, FunctionBodyStatementKindIr::ExecuteImmediate);
            *count += 1;
            dynamic_sql_calls.push(DynamicSqlCallIr {
                surface: DynamicSqlSurfaceIr::ExecuteImmediate,
                // Resolve a bare variable argument through the body's
                // classifier (`v := '…' || x; EXECUTE v;` → Concat).
                argument: taint.classify_arg(sql_expr, source),
                splices: taint.classify_arg_splices(sql_expr, source),
                parameterization: classify_execute_immediate_parameterization(
                    using_args,
                    *using_span,
                ),
                node_id: *node_id,
                source_span: *span,
                argument_span: Some(sql_expr.span()),
                provenance: Vec::new(),
            });
        }
        AstStmt::PgPrepare(p) => {
            *count += 1;
            if let Some(from_expr) = &p.from_expr {
                // Resolve a bare variable argument through the body's
                // classifier, same as the EXECUTE IMMEDIATE arm above.
                let argument = taint.classify_arg(from_expr, source);
                dynamic_sql_calls.push(DynamicSqlCallIr {
                    surface: DynamicSqlSurfaceIr::Prepare,
                    argument,
                    splices: taint.classify_arg_splices(from_expr, source),
                    parameterization: DynamicSqlParameterizationIr::NotApplicable,
                    node_id: p.node_id,
                    source_span: p.span,
                    argument_span: Some(from_expr.span()),
                    provenance: Vec::new(),
                });
            }
        }
        AstStmt::MssqlExec(e) => {
            *count += 1;
            let variable = crate::ir::dynamic_sql::mssql_exec_bare_variable(e.args_span, source)
                .and_then(|name| taint.variable_shape(name));
            match e.procedure_name_span {
                None => {
                    // Prefer the parser-lifted argument expression so a
                    // direct `EXEC('…' + @v)` concat classifies (and yields
                    // splice positions) through the same taint taxonomy as
                    // `EXECUTE IMMEDIATE` / `sp_executesql`. Fall back to the
                    // bare-`@var` span resolver when the parser could not lift
                    // the parenthesised expression.
                    let (argument, splices) = match e.args.first() {
                        Some(arg) => (
                            taint.classify_arg(&arg.value, source),
                            taint.classify_arg_splices(&arg.value, source),
                        ),
                        None => variable.unwrap_or((DynamicSqlArgIr::Unknown, Vec::new())),
                    };
                    dynamic_sql_calls.push(DynamicSqlCallIr {
                        surface: DynamicSqlSurfaceIr::MssqlExecDynamic,
                        argument,
                        splices,
                        parameterization: DynamicSqlParameterizationIr::NotApplicable,
                        node_id: e.node_id,
                        source_span: e.span,
                        argument_span: e.args_span,
                        provenance: Vec::new(),
                    });
                }
                Some(_) => {
                    if crate::ir::dynamic_sql::is_sp_executesql(e, source) {
                        dynamic_sql_calls.push(DynamicSqlCallIr {
                            surface: DynamicSqlSurfaceIr::MssqlSpExecutesql,
                            // `sp_executesql`'s @stmt SQL string is the first
                            // argument; classify it through the shared taxonomy
                            // (a bare @var resolves via the classifier, an inline
                            // literal is Literal not Unknown, a concat is Concat)
                            // and recover its splice positions.
                            argument: e
                                .args
                                .first()
                                .map(|a| taint.classify_arg(&a.value, source))
                                .unwrap_or(DynamicSqlArgIr::Unknown),
                            splices: e
                                .args
                                .first()
                                .map(|a| taint.classify_arg_splices(&a.value, source))
                                .unwrap_or_default(),
                            parameterization: DynamicSqlParameterizationIr::NamedParams,
                            node_id: e.node_id,
                            source_span: e.span,
                            argument_span: e.args_span,
                            provenance: Vec::new(),
                        });
                    }
                }
            }
        }

        // ───────── Body-bearing scripting variants — recurse ─────────
        AstStmt::Block(b) => {
            for s in &b.decls {
                collect_body_statement_kinds(s, kinds, count, dynamic_sql_calls, taint, source);
            }
            for s in &b.body {
                collect_body_statement_kinds(s, kinds, count, dynamic_sql_calls, taint, source);
            }
        }
        AstStmt::If(i) => {
            for br in &i.branches {
                for s in &br.body {
                    collect_body_statement_kinds(s, kinds, count, dynamic_sql_calls, taint, source);
                }
            }
            for s in &i.else_body {
                collect_body_statement_kinds(s, kinds, count, dynamic_sql_calls, taint, source);
            }
        }
        AstStmt::CaseStmt(c) => {
            for br in &c.branches {
                for s in &br.body {
                    collect_body_statement_kinds(s, kinds, count, dynamic_sql_calls, taint, source);
                }
            }
            for s in &c.else_body {
                collect_body_statement_kinds(s, kinds, count, dynamic_sql_calls, taint, source);
            }
        }
        AstStmt::While(w) => {
            for s in &w.body {
                collect_body_statement_kinds(s, kinds, count, dynamic_sql_calls, taint, source);
            }
        }
        AstStmt::For(f) => {
            for s in &f.body {
                collect_body_statement_kinds(s, kinds, count, dynamic_sql_calls, taint, source);
            }
        }
        AstStmt::ForEach(f) => {
            for s in &f.body {
                collect_body_statement_kinds(s, kinds, count, dynamic_sql_calls, taint, source);
            }
        }
        AstStmt::Loop(l) => {
            for s in &l.body {
                collect_body_statement_kinds(s, kinds, count, dynamic_sql_calls, taint, source);
            }
        }
        AstStmt::Repeat(r) => {
            for s in &r.body {
                collect_body_statement_kinds(s, kinds, count, dynamic_sql_calls, taint, source);
            }
        }
        AstStmt::DeclareHandler(h) => collect_body_statement_kinds(
            &h.handler_action,
            kinds,
            count,
            dynamic_sql_calls,
            taint,
            source,
        ),
        AstStmt::MssqlTryCatch(t) => {
            for s in &t.try_body {
                collect_body_statement_kinds(s, kinds, count, dynamic_sql_calls, taint, source);
            }
            for s in &t.catch_body {
                collect_body_statement_kinds(s, kinds, count, dynamic_sql_calls, taint, source);
            }
        }
        AstStmt::MssqlIf(i) => {
            for s in &i.then_body {
                collect_body_statement_kinds(s, kinds, count, dynamic_sql_calls, taint, source);
            }
            for s in &i.else_body {
                collect_body_statement_kinds(s, kinds, count, dynamic_sql_calls, taint, source);
            }
        }
        AstStmt::MssqlWhile(w) => {
            for s in &w.body {
                collect_body_statement_kinds(s, kinds, count, dynamic_sql_calls, taint, source);
            }
        }

        // RESULTSET / assignment forms can wrap a statement-form EXECUTE
        // IMMEDIATE in expression position (Snowflake scripting
        // `rs := (EXECUTE IMMEDIATE :stmt USING (a, b));`). Use the
        // shared expression descent in `dynamic_sql.rs` to collect any
        // inner statements, then recurse on each.
        AstStmt::Assign { expr, .. } | AstStmt::Let { expr, .. } => {
            for inner in collect_inner_stmts_from_expr(expr) {
                collect_body_statement_kinds(inner, kinds, count, dynamic_sql_calls, taint, source);
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
                    );
                }
            }
        }

        // ───────── Non-body-bearing leaves ─────────
        // Listed exhaustively so the closed-enum contract remains
        // compiler-enforced.
        AstStmt::Select(_)
        | AstStmt::SetSelect(_)
        | AstStmt::ValuesQuery(_)
        | AstStmt::Insert(_)
        | AstStmt::ReplaceInto(_)
        | AstStmt::MultiInsert(_)
        | AstStmt::Update(_)
        | AstStmt::Delete(_)
        | AstStmt::Merge(_)
        | AstStmt::Explain(_)
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
        | AstStmt::Reconfigure { .. }
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
        | AstStmt::Declare { .. }
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
        | AstStmt::MysqlSet(_)
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
        | AstStmt::SetVariable { .. }
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
}

fn target_from_span(source: &str, span: Span) -> FunctionTarget {
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
    FunctionTarget {
        name,
        schema,
        db,
        span,
    }
}
