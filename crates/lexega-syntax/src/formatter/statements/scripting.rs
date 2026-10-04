// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Recursive descent formatter for Snowflake Scripting statements
//!
//! Architecture: Pure recursive descent - every statement formatter:
//! 1. Calls begin_span() with the statement's span
//! 2. Recursively formats all components (keywords, expressions, nested statements)
//! 3. Calls end_span()
//!
//! No mixed extract_span() - everything is reconstructed from AST.

use crate::ast::{AstExceptionSection, AstExecuteUsingArg, AstExpr, AstIdentifier, AstStmt};
use crate::formatter::printer::Printer;
use crate::formatter::FormatterError;
use crate::lexer::Span;

/// Format any Snowflake Scripting statement (recursive entry point)
///
/// NOTE: Does NOT handle span tracking - caller is responsible for begin_span/end_span.
/// This is consistent with other formatters like format_select.
pub fn format_statement(printer: &mut Printer, stmt: &AstStmt) -> Result<(), FormatterError> {
    printer.enter_recursion("statement")?;

    // Format based on statement type (no span tracking here)
    match stmt {
        AstStmt::Block(b) => {
            if let Some(ls) = b.label_span {
                printer.push_span(ls);
                printer.newline();
            }
            // For BEGIN ATOMIC blocks, emit the whole block as a span
            // since format_block_content doesn't have an atomic_span parameter
            if b.atomic_span.is_some() {
                printer.push_span(b.span);
            } else {
                format_block_content(
                    printer,
                    b.declare_span,
                    b.declare_token,
                    b.begin_span,
                    b.begin_token,
                    &b.decls,
                    &b.body,
                    &b.exception,
                    b.end_span,
                    b.end_token,
                )?;
            }
            if let Some(els) = b.end_label_span {
                printer.space();
                printer.push_span(els);
            }
            if let Some(semi_id) = b.semicolon_token {
                printer.push_token_id(semi_id);
            }
        }
        AstStmt::Let {
            let_span,
            let_token,
            name,
            type_span,
            assign_op_span,
            expr,
            semicolon_token,
            ..
        } => {
            format_let(
                printer,
                *let_span,
                *let_token,
                name,
                *type_span,
                *assign_op_span,
                expr.as_ref(),
            )?;
            if let Some(semi_id) = semicolon_token {
                printer.push_token_id(*semi_id);
            }
        }
        AstStmt::LetCursor {
            let_span,
            let_token,
            cursor_name,
            cursor_token,
            for_token,
            query_span,
            parsed_query,
            semicolon_token,
            ..
        } => {
            format_let_cursor(
                printer,
                *let_span,
                *let_token,
                cursor_name,
                *cursor_token,
                *for_token,
                *query_span,
                parsed_query.as_ref().map(|q| q.as_ref()),
            )?;
            if let Some(semi_id) = semicolon_token {
                printer.push_token_id(*semi_id);
            }
        }
        AstStmt::Assign {
            name_span,
            assign_op_span,
            expr,
            semicolon_token,
            ..
        } => {
            format_assign(printer, *name_span, *assign_op_span, expr.as_ref())?;
            if let Some(semi_id) = semicolon_token {
                printer.push_token_id(*semi_id);
            }
        }
        AstStmt::Return {
            return_span,
            return_token,
            expr,
            semicolon_token,
            ..
        } => {
            format_return(
                printer,
                *return_span,
                *return_token,
                expr.as_ref().map(|e| e.as_ref()),
            )?;
            if let Some(semi_id) = semicolon_token {
                printer.push_token_id(*semi_id);
            }
        }
        AstStmt::Declare {
            declare_span,
            declare_token,
            name,
            type_span,
            default_op_token,
            default_expr,
            semicolon_token,
            ..
        } => {
            format_declare(
                printer,
                *declare_span,
                *declare_token,
                name,
                *type_span,
                *default_op_token,
                default_expr.as_ref().map(|e| e.as_ref()),
            )?;
            if let Some(semi_id) = semicolon_token {
                printer.push_token_id(*semi_id);
            }
        }
        AstStmt::DeclareTable {
            declare_span,
            declare_token,
            name,
            table_keyword_span,
            table_body_span,
            semicolon_token,
            ..
        } => {
            format_declare_table(
                printer,
                *declare_span,
                *declare_token,
                name,
                *table_keyword_span,
                *table_body_span,
            )?;
            if let Some(semi_id) = semicolon_token {
                printer.push_token_id(*semi_id);
            }
        }
        AstStmt::DeclareCursor {
            declare_span,
            declare_token,
            cursor_name,
            cursor_token,
            for_token,
            query,
            cursor_sensitivity_span,
            semicolon_token,
            ..
        } => {
            format_declare_cursor(
                printer,
                *declare_span,
                *declare_token,
                cursor_name,
                *cursor_token,
                *for_token,
                query.as_ref(),
                *cursor_sensitivity_span,
            )?;
            if let Some(semi_id) = semicolon_token {
                printer.push_token_id(*semi_id);
            }
        }
        AstStmt::If(i) => {
            format_if(
                printer,
                &i.branches,
                i.else_span,
                i.else_token,
                &i.else_body,
                i.end_span,
                i.end_token,
                i.end_if_token,
            )?;
            if let Some(semi_id) = i.semicolon_token {
                printer.push_token_id(semi_id);
            }
        }
        AstStmt::CaseStmt(c) => {
            format_case_stmt(
                printer,
                c.case_span,
                c.case_token,
                c.operand_span,
                &c.branches,
                c.else_span,
                c.else_token,
                &c.else_body,
                c.end_span,
                c.end_token,
                c.end_case_token,
            )?;
            if let Some(semi_id) = c.semicolon_token {
                printer.push_token_id(semi_id);
            }
        }
        AstStmt::While(w) => {
            if let Some(ls) = w.label_span {
                printer.push_span(ls);
                printer.newline();
            }
            format_while(
                printer,
                w.while_span,
                w.while_token,
                w.lparen_token,
                w.condition.as_ref(),
                w.rparen_token,
                w.body_keyword_span,
                w.body_keyword_token,
                &w.body,
                w.end_span,
                w.end_token,
                w.end_while_token,
            )?;
            if let Some(els) = w.end_label_span {
                printer.space();
                printer.push_span(els);
            }
            if let Some(semi_id) = w.semicolon_token {
                printer.push_token_id(semi_id);
            }
        }
        AstStmt::For(f) => {
            if let Some(ls) = f.label_span {
                printer.push_span(ls);
                printer.newline();
            }
            format_for(
                printer,
                f.for_span,
                f.for_token,
                f.loop_var_span,
                f.in_span,
                f.in_token,
                f.range_or_cursor_span,
                f.body_keyword_span,
                f.body_keyword_token,
                &f.body,
                f.end_span,
                f.end_token,
                f.end_for_token,
            )?;
            if let Some(els) = f.end_label_span {
                printer.space();
                printer.push_span(els);
            }
            if let Some(semi_id) = f.semicolon_token {
                printer.push_token_id(semi_id);
            }
        }
        AstStmt::ForEach(f) => {
            format_foreach(printer, f)?;
            if let Some(els) = f.end_label_span {
                printer.space();
                printer.push_span(els);
            }
            if let Some(semi_id) = f.semicolon_token {
                printer.push_token_id(semi_id);
            }
        }
        AstStmt::Repeat(r) => {
            if let Some(ls) = r.label_span {
                printer.push_span(ls);
                printer.newline();
            }
            format_repeat(
                printer,
                r.repeat_span,
                r.repeat_token,
                &r.body,
                r.until_span,
                r.until_token,
                r.until_condition_span,
                r.end_span,
                r.end_token,
                r.end_repeat_token,
            )?;
            if let Some(els) = r.end_label_span {
                printer.space();
                printer.push_span(els);
            }
            if let Some(semi_id) = r.semicolon_token {
                printer.push_token_id(semi_id);
            }
        }
        AstStmt::Loop(l) => {
            if let Some(ls) = l.label_span {
                printer.push_span(ls);
                printer.newline();
            }
            format_loop(
                printer,
                l.loop_span,
                l.loop_token,
                &l.body,
                l.end_span,
                l.end_token,
                l.end_loop_token,
            )?;
            if let Some(els) = l.end_label_span {
                printer.space();
                printer.push_span(els);
            }
            if let Some(semi_id) = l.semicolon_token {
                printer.push_token_id(semi_id);
            }
        }
        AstStmt::Break {
            break_span,
            break_token,
            label_token,
            semicolon_token,
            ..
        } => {
            // Use push_token_id for CST-based trivia emission, fallback to span
            if let Some(token_id) = break_token {
                printer.push_token_id(*token_id);
            } else {
                printer.push_keyword_span(*break_span);
            }
            // Emit optional label target (e.g., `outer` in `LEAVE outer;`)
            if let Some(lbl_id) = label_token {
                printer.space();
                printer.push_token_id(*lbl_id);
            }
            // Emit semicolon if present
            if let Some(semi_id) = semicolon_token {
                printer.push_token_id(*semi_id);
            }
        }
        AstStmt::Continue {
            continue_span,
            continue_token,
            label_token,
            semicolon_token,
            ..
        } => {
            if let Some(token_id) = continue_token {
                printer.push_token_id(*token_id);
            } else {
                printer.push_keyword_span(*continue_span);
            }
            // Emit optional label target (e.g., `inner` in `ITERATE inner;`)
            if let Some(lbl_id) = label_token {
                printer.space();
                printer.push_token_id(*lbl_id);
            }
            // Emit semicolon if present
            if let Some(semi_id) = semicolon_token {
                printer.push_token_id(*semi_id);
            }
        }
        AstStmt::Null {
            null_span,
            null_token,
            semicolon_token,
            ..
        } => {
            if let Some(token_id) = null_token {
                printer.push_token_id(*token_id);
            } else {
                printer.push_keyword_span(*null_span);
            }
            if let Some(semi_id) = semicolon_token {
                printer.push_token_id(*semi_id);
            }
        }
        AstStmt::Raise {
            raise_span,
            raise_token,
            exception_name,
            level_span,
            message_span,
            using_span,
            message_expr,
            semicolon_token,
            ..
        } => {
            format_raise(
                printer,
                *raise_span,
                *raise_token,
                *exception_name,
                *level_span,
                *message_span,
                *using_span,
                message_expr.as_ref().map(|e| e.as_ref()),
            )?;
            // Emit semicolon if captured
            if let Some(semi_id) = semicolon_token {
                printer.push_token_id(*semi_id);
            }
        }
        // Databricks SIGNAL/RESIGNAL/GET DIAGNOSTICS/DECLARE CONDITION/HANDLER — span-only
        AstStmt::Signal { span, .. }
        | AstStmt::Resignal { span, .. }
        | AstStmt::GetDiagnostics { span, .. }
        | AstStmt::DeclareCondition { span, .. } => {
            printer.push_span(*span);
        }
        AstStmt::DeclareHandler(h) => {
            printer.push_span(h.span);
        }
        AstStmt::ExecuteImmediate {
            execute_span,
            immediate_span,
            using_span,
            into_span,
            into_strict_span,
            sql_expr,
            using_args,
            using_lparen_span,
            using_rparen_span,
            into_vars,
            semicolon_token,
            ..
        } => {
            format_execute_immediate(
                printer,
                *execute_span,
                *immediate_span,
                *using_span,
                *into_span,
                *into_strict_span,
                sql_expr.as_ref(),
                using_args,
                *using_lparen_span,
                *using_rparen_span,
                into_vars,
            )?;
            // Emit semicolon if captured from scripting/Jinja context
            if let Some(semi_id) = semicolon_token {
                printer.push_token_id(*semi_id);
            }
        }
        // SQL DML statements that can appear in scripting blocks
        AstStmt::Select(_) => {
            crate::formatter::statements::format_select(printer, stmt)?;
        }
        AstStmt::SetSelect(_) => {
            crate::formatter::statements::format_select(printer, stmt)?;
        }
        AstStmt::Insert(i) => {
            crate::formatter::statements::format_insert(printer, i)?;
        }
        AstStmt::Update(u) => {
            crate::formatter::statements::format_update(printer, u)?;
        }
        AstStmt::Delete(d) => {
            crate::formatter::statements::format_delete(printer, d)?;
        }
        AstStmt::Merge(m) => {
            crate::formatter::statements::format_merge(printer, m)?;
        }
        AstStmt::CreateTable(ct) => {
            crate::formatter::statements::format_create_table(printer, ct)?;
        }
        AstStmt::CreateView(cv) => {
            crate::formatter::statements::format_create_view(printer, cv)?;
        }
        AstStmt::Drop(d) => {
            crate::formatter::statements::format_drop(printer, d)?;
        }
        AstStmt::Truncate(t) => {
            crate::formatter::statements::format_truncate(printer, t)?;
        }
        AstStmt::Call {
            span,
            call_span,
            procedure_name_span,
            syntax_id,
            semicolon_token,
            odbc,
            ..
        } => {
            if odbc.is_some() {
                // ODBC escape form ({call …}): span covers the braces — emit
                // verbatim (Pattern A), plus the trailing semicolon token.
                printer.push_span(*span);
                if let Some(semi) = semicolon_token {
                    printer.push_token_id(*semi);
                }
            } else {
                format_call(
                    printer,
                    *span,
                    *call_span,
                    *procedure_name_span,
                    *syntax_id,
                    *semicolon_token,
                )?;
            }
        }
        // Cursor statements
        AstStmt::OpenCursor {
            open_span,
            cursor_name_span,
            using_clause_span,
            semicolon_token,
            ..
        } => {
            format_open_cursor(
                printer,
                *open_span,
                *cursor_name_span,
                *using_clause_span,
                *semicolon_token,
            )?;
        }
        AstStmt::FetchCursor {
            fetch_span,
            cursor_name_span,
            into_clause_span,
            semicolon_token,
            ..
        } => {
            format_fetch_cursor(
                printer,
                *fetch_span,
                *cursor_name_span,
                *into_clause_span,
                *semicolon_token,
            )?;
        }
        AstStmt::CloseCursor {
            close_span,
            cursor_name_span,
            semicolon_token,
            ..
        } => {
            format_close_cursor(printer, *close_span, *cursor_name_span, *semicolon_token)?;
        }
        AstStmt::Error { span, .. } => {
            // Error nodes from tolerant parsing - preserve the original source region
            // This allows partial formatting even when some statements inside blocks failed to parse
            printer.push_span(*span);
        }
        AstStmt::OpaqueContent { span, .. } => {
            // Opaque content that should be emitted verbatim
            printer.push_span(*span);
        }
        AstStmt::GoBatchSeparator { span, .. } => {
            printer.push_span(*span);
        }
        AstStmt::Reconfigure { span, .. } => {
            printer.push_span(*span);
        }
        AstStmt::MssqlExec(exec) => {
            printer.push_span(exec.span);
        }
        AstStmt::MssqlTryCatch(tc) => {
            printer.push_span(tc.span);
            if let Some(semi_id) = tc.semicolon_token {
                printer.push_token_id(semi_id);
            }
        }
        AstStmt::MssqlIf(s) => {
            printer.push_span(s.span);
        }
        AstStmt::MssqlWhile(s) => {
            printer.push_span(s.span);
        }
        AstStmt::MssqlPrint(p) => {
            printer.push_span(p.span);
            if let Some(semi_id) = p.semicolon_token {
                printer.push_token_id(semi_id);
            }
        }
        AstStmt::MssqlThrow(t) => {
            printer.push_span(t.span);
            if let Some(semi_id) = t.semicolon_token {
                printer.push_token_id(semi_id);
            }
        }
        AstStmt::MssqlRaiserror(r) => {
            printer.push_span(r.span);
            if let Some(semi_id) = r.semicolon_token {
                printer.push_token_id(semi_id);
            }
        }
        AstStmt::MssqlGoto(g) => {
            printer.push_span(g.span);
            if let Some(semi_id) = g.semicolon_token {
                printer.push_token_id(semi_id);
            }
        }
        AstStmt::MssqlWaitfor(w) => {
            printer.push_span(w.span);
            if let Some(semi_id) = w.semicolon_token {
                printer.push_token_id(semi_id);
            }
        }
        AstStmt::MssqlLabel(l) => {
            printer.push_span(l.span);
        }
        AstStmt::MssqlSetOption(s) => {
            printer.push_span(s.span);
            if let Some(semi_id) = s.semicolon_token {
                printer.push_token_id(semi_id);
            }
        }
        AstStmt::SetVariable { span, .. } => {
            crate::formatter::statements::format_set_variable(printer, *span)?;
        }
        AstStmt::PgSet(s) => {
            printer.push_span(s.span);
        }
        _ => {
            // Non-scripting statement - should not be called from here
            printer.exit_recursion();
            return Err(FormatterError::NotImplemented(format!(
                "Non-scripting statement in scripting formatter: {:?}",
                stmt
            )));
        }
    }

    printer.exit_recursion();
    Ok(())
}

/// Format a statement WITHOUT span tracking (for nested statements only)
///
/// ARCHITECTURAL NOTE: This is for statements INSIDE blocks/procedures/loops.
/// Only top-level statements should use begin_span/end_span.
/// Nested statements are formatted recursively but not tracked in SpanMap.
fn format_nested_statement(printer: &mut Printer, stmt: &AstStmt) -> Result<(), FormatterError> {
    format_statement(printer, stmt)
}

/// Determine if a statement is a "major" statement that should have blank lines around it.
///
/// Major statements: DML (SELECT, INSERT, UPDATE, DELETE, MERGE), DDL (CREATE, ALTER, DROP),
/// control flow (IF, WHILE, FOR, LOOP, REPEAT, CASE), and CALL.
///
/// Minor statements: LET, DECLARE, assignments, RETURN, BREAK, CONTINUE.
fn is_major_statement(stmt: &AstStmt) -> bool {
    matches!(
        stmt,
        // Control flow
        AstStmt::If { .. }
        | AstStmt::While { .. }
        | AstStmt::For { .. }
        | AstStmt::Loop { .. }
        | AstStmt::Repeat { .. }
        | AstStmt::CaseStmt { .. }
        | AstStmt::Block { .. }
        // DML
        | AstStmt::Select(_)
        | AstStmt::SetSelect(_)
        | AstStmt::Insert(_)
        | AstStmt::MultiInsert(_)
        | AstStmt::Update(_)
        | AstStmt::Delete(_)
        | AstStmt::Merge(_)
        // DDL
        | AstStmt::CreateTable(_)
        | AstStmt::CreateView(_)
        | AstStmt::CreateStage(_)
        | AstStmt::Drop(_)
        | AstStmt::Truncate(_)
        // Other major operations
        | AstStmt::Call { .. }
        | AstStmt::PipeChain { .. }
    )
}

/// Format BEGIN...END block content (without begin_span - caller handles it)
fn format_block_content(
    printer: &mut Printer,
    declare_span: Option<Span>,
    declare_token: Option<crate::cst::TokenId>,
    begin_span: Span,
    begin_token: Option<crate::cst::TokenId>,
    decls: &[AstStmt],
    body: &[AstStmt],
    exception: &Option<AstExceptionSection>,
    end_span: Option<Span>,
    end_token: Option<crate::cst::TokenId>,
) -> Result<(), FormatterError> {
    // Use end_span for boundary when available
    let end_boundary = end_span.map(|s| s.start);

    // DECLARE section comes BEFORE BEGIN keyword in Snowflake Scripting
    if !decls.is_empty() {
        let declare_on_newlines = printer.config().declare_on_newlines;
        let indent_declare = printer.config().indent_declare_section;
        let blank_after = printer.config().blank_line_after_declare;

        // Output DECLARE keyword using token ID if available, otherwise span
        if let Some(token_id) = declare_token {
            printer.push_token_id(token_id);
        } else if let Some(decl_kw_span) = declare_span {
            printer.push_keyword_span(decl_kw_span);
        } else {
            printer.push_keyword("DECLARE");
        }

        if declare_on_newlines {
            printer.newline();
        }

        if indent_declare {
            printer.indent_up();
        }

        for (i, decl) in decls.iter().enumerate() {
            format_declaration_body(printer, decl)?;
            if declare_on_newlines && i < decls.len() - 1 {
                printer.newline();
            }
        }

        if indent_declare {
            printer.indent_down();
        }

        if blank_after {
            printer.newline();
        }
    }

    // BEGIN keyword starts the body - use token ID if available
    printer.newline();
    if let Some(token_id) = begin_token {
        printer.push_token_id(token_id);
    } else {
        printer.push_keyword_span(begin_span);
    }
    printer.newline();
    printer.indent_up();

    // Pass end_boundary for trailing trivia on last statement
    format_block_inner_content(printer, decls, body, exception, end_boundary)?;

    printer.indent_down();
    printer.newline();
    // Use token ID for END if available
    if let Some(token_id) = end_token {
        printer.push_token_id(token_id);
    } else if let Some(end_sp) = end_span {
        printer.push_keyword_span(end_sp);
    } else {
        printer.push_keyword("END");
    }

    Ok(())
}

/// Internal helper to format the DECLARE + body + EXCEPTION sections
///
/// `end_boundary` is the position of END keyword (or EXCEPTION if present) to properly
/// emit trailing comments on the last statement.
fn format_block_inner_content(
    printer: &mut Printer,
    _decls: &[AstStmt],
    body: &[AstStmt],
    exception: &Option<AstExceptionSection>,
    end_boundary: Option<u32>,
) -> Result<(), FormatterError> {
    // Body statements (decls already formatted before BEGIN in format_block_content)
    let statement_spacing = printer.config().loop_body_on_newlines;

    // If there's an EXCEPTION section, the boundary for the last body statement
    // should be the EXCEPTION keyword, not the END keyword
    let body_end_boundary = if let Some(exc) = exception {
        Some(exc.keyword_span.start)
    } else {
        end_boundary
    };

    for (i, stmt) in body.iter().enumerate() {
        if i > 0 && is_major_statement(stmt) {
            printer.newline();
        }

        format_nested_statement(printer, stmt)?;
        // Emit the gap (trailing `;` + any inter-statement comments) to the next
        // sibling, or for the LAST statement to the block's terminating boundary
        // (EXCEPTION keyword if present, else END). Statement spans exclude their
        // `;`; the terminator lives in this gap, so without emitting it the token
        // is dropped. `emit_all_tokens_until` only emits not-yet-emitted tokens
        // before the boundary, so it is idempotent and never crosses END.
        let gap_target = if i + 1 < body.len() {
            Some(body[i + 1].span().start)
        } else {
            body_end_boundary
        };
        if let Some(target) = gap_target {
            printer.emit_all_tokens_until(target);
        }
        if statement_spacing && i < body.len() - 1 {
            printer.newline();
        }
    }

    // EXCEPTION section
    if let Some(exc) = exception {
        printer.newline();

        // Use push_token_id for EXCEPTION keyword if available, otherwise push_keyword_span
        if let Some(token_id) = exc.keyword_token {
            printer.push_token_id(token_id);
        } else {
            printer.push_keyword_span(exc.keyword_span);
        }
        printer.newline();
        printer.indent_up();

        for (h_idx, handler) in exc.handlers.iter().enumerate() {
            // Use push_token_id for WHEN keyword if available
            if let Some(token_id) = handler.when_token {
                printer.push_token_id(token_id);
            } else {
                printer.push_keyword_span(handler.when_span);
            }
            printer.space();

            // Use push_token_id for exception names if available
            for (i, name_span) in handler.exception_name_spans.iter().enumerate() {
                if i > 0 {
                    printer.space();
                    printer.push_keyword("OR");
                    printer.space();
                }
                // Use token ID if available, otherwise use span
                if let Some(Some(token_id)) = handler.exception_name_tokens.get(i) {
                    printer.push_token_id(*token_id);
                } else {
                    printer.push_span(*name_span);
                }
            }

            printer.space();
            // Use push_token_id for THEN if available
            if let Some(token_id) = handler.then_token {
                printer.push_token_id(token_id);
            } else if let Some(then_sp) = handler.then_span {
                printer.push_keyword_span(then_sp);
            } else {
                printer.push_keyword("THEN");
            }
            printer.newline();
            printer.indent_up();

            for (i, stmt) in handler.body.iter().enumerate() {
                format_nested_statement(printer, stmt)?;
                // Gap to next sibling; for the last handler statement, to the
                // next handler's WHEN, else to END (the block's end_boundary).
                let gap_target = if i + 1 < handler.body.len() {
                    Some(handler.body[i + 1].span().start)
                } else if h_idx + 1 < exc.handlers.len() {
                    Some(exc.handlers[h_idx + 1].when_span.start)
                } else {
                    end_boundary
                };
                if let Some(target) = gap_target {
                    printer.emit_all_tokens_until(target);
                }
                if i < handler.body.len() - 1 {
                    printer.newline();
                }
            }

            printer.indent_down();
            printer.newline();
        }

        printer.indent_down();
    }

    Ok(())
}

/// Format LET variable := expression
fn format_let(
    printer: &mut Printer,
    let_span: Span,
    let_token: Option<crate::cst::TokenId>,
    name: &AstIdentifier,
    type_span: Option<Span>,
    assign_op_span: Option<Span>,
    expr: &AstExpr,
) -> Result<(), FormatterError> {
    if let Some(token_id) = let_token {
        printer.push_token_id(token_id);
    } else {
        printer.push_keyword_span(let_span);
    }
    printer.space();

    // Format identifier
    printer.push_identifier_span(name.span);

    // Format type if present
    if let Some(ts) = type_span {
        printer.space();
        printer.push_span(ts);
    }

    if printer.config().spaces_around_operators {
        printer.space();
    }
    if let Some(op_span) = assign_op_span {
        printer.push_span(op_span);
    } else {
        printer.push_char(':');
        printer.push_char('=');
    }
    if printer.config().spaces_around_operators {
        printer.space();
    }

    // Format expression
    format_expression(printer, expr)?;

    Ok(())
}

/// Format LET cursor_name CURSOR FOR query
fn format_let_cursor(
    printer: &mut Printer,
    let_span: Span,
    let_token: Option<crate::cst::TokenId>,
    cursor_name: &AstIdentifier,
    cursor_token: Option<crate::cst::TokenId>,
    for_token: Option<crate::cst::TokenId>,
    query_span: Span,
    parsed_query: Option<&AstStmt>,
) -> Result<(), FormatterError> {
    if let Some(token_id) = let_token {
        printer.push_token_id(token_id);
    } else {
        printer.push_keyword_span(let_span);
    }
    printer.space();

    printer.push_identifier_span(cursor_name.span);

    printer.space();
    if let Some(token_id) = cursor_token {
        printer.push_token_id(token_id);
    } else {
        printer.push_keyword("CURSOR");
    }
    printer.space();
    if let Some(token_id) = for_token {
        printer.push_token_id(token_id);
    } else {
        printer.push_keyword("FOR");
    }

    // Check config for cursor query formatting
    if printer.config().cursor_query_on_newline {
        printer.newline();
        if printer.config().indent_cursor_query {
            printer.indent_up();
        }
    } else {
        printer.space();
    }

    // Format the query - prefer parsed query, fallback to span
    if let Some(query) = parsed_query {
        super::format_select(printer, query)?;
    } else {
        printer.push_span(query_span);
    }

    // Restore indentation if we indented
    if printer.config().cursor_query_on_newline && printer.config().indent_cursor_query {
        printer.indent_down();
    }

    Ok(())
}

/// Format variable := expression
fn format_assign(
    printer: &mut Printer,
    name_span: Span,
    assign_op_span: Option<Span>,
    expr: &AstExpr,
) -> Result<(), FormatterError> {
    // Format variable name with trivia emission
    printer.push_identifier_span(name_span);

    if printer.config().spaces_around_operators {
        printer.space();
    }
    if let Some(op_span) = assign_op_span {
        printer.push_span(op_span);
    } else {
        printer.push_char(':');
        printer.push_char('=');
    }
    if printer.config().spaces_around_operators {
        printer.space();
    }

    // Format the parsed expression
    format_expression(printer, expr)?;

    Ok(())
}

/// Format RETURN expression
fn format_return(
    printer: &mut Printer,
    return_span: Span,
    return_token: Option<crate::cst::TokenId>,
    expr: Option<&AstExpr>,
) -> Result<(), FormatterError> {
    if let Some(token_id) = return_token {
        printer.push_token_id(token_id);
    } else {
        printer.push_keyword_span(return_span);
    }
    if let Some(e) = expr {
        printer.space();
        format_expression(printer, e)?;
    }
    Ok(())
}

/// Format CALL statement
/// Syntax: CALL procedure_name([args])
fn format_call(
    printer: &mut Printer,
    span: Span,
    call_span: Span,
    procedure_name_span: Span,
    syntax_id: Option<crate::syntax::SyntaxCallStmtId>,
    semicolon_token: Option<crate::cst::TokenId>,
) -> Result<(), FormatterError> {
    // If we have syntax node, use token IDs for precise trivia handling
    if let Some(id) = syntax_id {
        // Get syntax node data first to avoid borrow conflicts
        let (call_keyword, l_paren, r_paren, _semicolon) =
            if let Some(syntax_arena) = printer.syntax_arena() {
                let syntax = syntax_arena.get_call_stmt(id);
                (
                    syntax.call_keyword,
                    syntax.l_paren,
                    syntax.r_paren,
                    syntax.semicolon,
                )
            } else {
                return Err(FormatterError::NotImplemented(
                    "Syntax arena not available".to_string(),
                ));
            };

        // CALL keyword
        printer.push_keyword_token_id(call_keyword);
        printer.space();

        // Procedure name
        printer.push_span(procedure_name_span);

        // Arguments (if present)
        if let Some(lparen) = l_paren {
            printer.push_token_id(lparen);
            if let Some(rparen) = r_paren {
                // Get rparen span before using printer mutably
                let rparen_start = printer.get_token_by_id(rparen).unwrap().span.start;
                // Emit everything between parens using emit_all_tokens_until
                printer.emit_all_tokens_until(rparen_start);
                printer.push_token_id(rparen);
            } else {
                // No closing paren - emit all remaining tokens in the span
                // This handles incomplete input like "CALL foo(1, 2"
                printer.emit_all_tokens_until(span.end);
            }
        }

        // Emit semicolon if present (scripting context)
        if let Some(semi_id) = semicolon_token {
            printer.push_token_id(semi_id);
        }

        return Ok(());
    }

    // Fallback: No syntax node available (legacy mode)
    printer.push_keyword_span(call_span);
    printer.space();

    // Emit procedure name and everything else up to statement end
    printer.push_span(procedure_name_span);
    printer.emit_all_tokens_until(span.end);

    // Emit semicolon if present (scripting context)
    if let Some(semi_id) = semicolon_token {
        printer.push_token_id(semi_id);
    }

    Ok(())
}

/// Format OPEN cursor statement
/// Syntax: OPEN cursor_name [USING (bind_args)]
fn format_open_cursor(
    printer: &mut Printer,
    open_span: Span,
    cursor_name_span: Span,
    using_clause_span: Option<Span>,
    semicolon_token: Option<crate::cst::TokenId>,
) -> Result<(), FormatterError> {
    printer.push_keyword_span(open_span);
    printer.space();

    // Emit cursor name
    printer.push_span(cursor_name_span);

    // Emit USING clause if present
    if let Some(using_span) = using_clause_span {
        printer.space();
        printer.push_span(using_span);
    }

    // Emit semicolon if captured from CST
    if let Some(semi_id) = semicolon_token {
        printer.push_token_id(semi_id);
    }

    Ok(())
}

/// Format FETCH cursor INTO statement
/// Syntax: FETCH cursor_name INTO var1, var2, ...
fn format_fetch_cursor(
    printer: &mut Printer,
    fetch_span: Span,
    cursor_name_span: Span,
    into_clause_span: Span,
    semicolon_token: Option<crate::cst::TokenId>,
) -> Result<(), FormatterError> {
    printer.push_keyword_span(fetch_span);
    printer.space();

    // Emit cursor name
    printer.push_span(cursor_name_span);
    printer.space();

    // Emit INTO clause
    printer.push_span(into_clause_span);

    // Emit semicolon if captured from CST
    if let Some(semi_id) = semicolon_token {
        printer.push_token_id(semi_id);
    }

    Ok(())
}

/// Format CLOSE cursor statement
/// Syntax: CLOSE cursor_name
fn format_close_cursor(
    printer: &mut Printer,
    close_span: Span,
    cursor_name_span: Span,
    semicolon_token: Option<crate::cst::TokenId>,
) -> Result<(), FormatterError> {
    printer.push_keyword_span(close_span);
    printer.space();

    // Emit cursor name
    printer.push_span(cursor_name_span);

    // Emit semicolon if captured from CST
    if let Some(semi_id) = semicolon_token {
        printer.push_token_id(semi_id);
    }

    Ok(())
}

/// Format the body of a declaration (variable name, type, default) without DECLARE keyword
fn format_declaration_body(printer: &mut Printer, decl: &AstStmt) -> Result<(), FormatterError> {
    match decl {
        AstStmt::Declare {
            name,
            type_span,
            default_op_span,
            default_expr,
            semicolon_token,
            ..
        } => {
            // Use push_identifier_span to emit trivia attached to the name token
            printer.push_identifier_span(name.span);

            if let Some(ts) = type_span {
                printer.space();
                // Use push_span to emit trivia attached to the type token
                printer.push_span(*ts);
            }

            if let Some(ref expr) = default_expr {
                printer.space();

                // Use push_span for the DEFAULT keyword or := operator
                // This properly advances the token cursor and emits trivia
                if let Some(op_span) = default_op_span {
                    printer.push_span(*op_span);
                } else {
                    // Fallback: just push DEFAULT (shouldn't happen with proper parsing)
                    printer.push_keyword("DEFAULT");
                }

                if printer.config().spaces_around_operators {
                    printer.space();
                }
                // Format the parsed expression recursively
                format_expression(printer, expr)?;
            }

            // Emit semicolon if captured
            if let Some(semi_id) = semicolon_token {
                printer.push_token_id(*semi_id);
            }
        }
        AstStmt::DeclareTable {
            name,
            table_keyword_span,
            table_body_span,
            semicolon_token,
            ..
        } => {
            printer.push_identifier_span(name.span);
            printer.space();
            printer.push_span(*table_keyword_span);
            printer.push_span(*table_body_span);

            if let Some(semi_id) = semicolon_token {
                printer.push_token_id(*semi_id);
            }
        }
        AstStmt::DeclareCursor {
            cursor_name,
            cursor_token,
            for_token,
            query,
            cursor_sensitivity_span,
            semicolon_token,
            ..
        } => {
            // Use push_identifier_span to emit trivia attached to the cursor name token
            printer.push_identifier_span(cursor_name.span);

            printer.space();
            if let Some(token_id) = cursor_token {
                printer.push_token_id(*token_id);
            } else {
                printer.push_keyword("CURSOR");
            }
            printer.space();
            if let Some(token_id) = for_token {
                printer.push_token_id(*token_id);
            } else {
                printer.push_keyword("FOR");
            }

            // Check config for cursor query formatting
            if printer.config().cursor_query_on_newline {
                printer.newline();
                if printer.config().indent_cursor_query {
                    printer.indent_up();
                }
            } else {
                printer.space();
            }

            // Format the parsed query recursively
            // The query formatter (e.g., format_select) handles its own leading trivia
            super::format_select(printer, query.as_ref())?;

            // Emit optional cursor sensitivity clause (FOR READ ONLY / FOR UPDATE)
            if let Some(cs_span) = cursor_sensitivity_span {
                printer.newline_if_needed();
                printer.push_span(*cs_span);
            }

            // Restore indentation if we increased it
            if printer.config().cursor_query_on_newline && printer.config().indent_cursor_query {
                printer.indent_down();
            }

            // Emit semicolon if captured
            if let Some(semi_id) = semicolon_token {
                printer.push_token_id(*semi_id);
            }
        }
        _ => {
            // Shouldn't happen - declarations should only be Declare or DeclareCursor
            format_nested_statement(printer, decl)?;
        }
    }
    Ok(())
}

/// Format DECLARE variable type [DEFAULT expr]
fn format_declare(
    printer: &mut Printer,
    declare_span: Option<Span>,
    declare_token: Option<crate::cst::TokenId>,
    name: &AstIdentifier,
    type_span: Option<Span>,
    default_op_token: Option<crate::cst::TokenId>,
    default_expr: Option<&AstExpr>,
) -> Result<(), FormatterError> {
    if let Some(token_id) = declare_token {
        printer.push_token_id(token_id);
    } else if let Some(kw_span) = declare_span {
        printer.push_keyword_span(kw_span);
    } else {
        printer.push_keyword("DECLARE");
    }
    printer.space();

    printer.push_identifier_span(name.span);

    if let Some(ts) = type_span {
        printer.space();
        printer.push_span(ts);
    }

    if let Some(expr) = default_expr {
        printer.space();
        if let Some(token_id) = default_op_token {
            printer.push_token_id(token_id);
        } else {
            printer.push_keyword("DEFAULT");
        }
        if printer.config().spaces_around_operators {
            printer.space();
        }
        // Format the parsed expression recursively
        format_expression(printer, expr)?;
    }

    Ok(())
}

/// Format DECLARE @var TABLE(column_defs)
fn format_declare_table(
    printer: &mut Printer,
    declare_span: Option<Span>,
    declare_token: Option<crate::cst::TokenId>,
    name: &AstIdentifier,
    table_keyword_span: Span,
    table_body_span: Span,
) -> Result<(), FormatterError> {
    if let Some(token_id) = declare_token {
        printer.push_token_id(token_id);
    } else if let Some(kw_span) = declare_span {
        printer.push_keyword_span(kw_span);
    } else {
        printer.push_keyword("DECLARE");
    }
    printer.space();

    printer.push_identifier_span(name.span);
    printer.space();
    printer.push_span(table_keyword_span);
    printer.push_span(table_body_span);

    Ok(())
}

/// Format DECLARE cursor_name CURSOR FOR query
fn format_declare_cursor(
    printer: &mut Printer,
    declare_span: Span,
    declare_token: Option<crate::cst::TokenId>,
    cursor_name: &AstIdentifier,
    cursor_token: Option<crate::cst::TokenId>,
    for_token: Option<crate::cst::TokenId>,
    query: &AstStmt,
    cursor_sensitivity_span: Option<Span>,
) -> Result<(), FormatterError> {
    if let Some(token_id) = declare_token {
        printer.push_token_id(token_id);
    } else {
        printer.push_keyword_span(declare_span);
    }
    printer.space();

    printer.push_identifier_span(cursor_name.span);

    printer.space();
    if let Some(token_id) = cursor_token {
        printer.push_token_id(token_id);
    } else {
        printer.push_keyword("CURSOR");
    }
    printer.space();
    if let Some(token_id) = for_token {
        printer.push_token_id(token_id);
    } else {
        printer.push_keyword("FOR");
    }

    // Check config for cursor query formatting
    if printer.config().cursor_query_on_newline {
        printer.newline();
        if printer.config().indent_cursor_query {
            printer.indent_up();
        }
    } else {
        printer.space();
    }

    // Format the parsed query recursively
    super::format_select(printer, query)?;

    // Emit optional cursor sensitivity clause (FOR READ ONLY / FOR UPDATE)
    if let Some(cs_span) = cursor_sensitivity_span {
        printer.newline_if_needed();
        printer.push_span(cs_span);
    }

    // Restore indentation if we indented
    if printer.config().cursor_query_on_newline && printer.config().indent_cursor_query {
        printer.indent_down();
    }

    Ok(())
}

/// Format IF...THEN...ELSEIF...ELSE...END IF
fn format_if(
    printer: &mut Printer,
    branches: &[crate::ast::IfBranch],
    else_span: Option<Span>,
    else_token: Option<crate::cst::TokenId>,
    else_body: &[AstStmt],
    end_span: Option<Span>,
    end_token: Option<crate::cst::TokenId>,
    end_if_token: Option<crate::cst::TokenId>,
) -> Result<(), FormatterError> {
    let if_on_newlines = printer.config().if_branches_on_newlines;
    let indent_if = printer.config().indent_if_body;

    // Use end_span for boundary when available
    let end_if_boundary = end_span.map(|s| s.start);

    for (branch_idx, branch) in branches.iter().enumerate() {
        if branch_idx == 0 {
            // Use token ID if available, otherwise span
            if let Some(token_id) = branch.if_token {
                printer.push_token_id(token_id);
            } else {
                printer.push_keyword_span(branch.if_span);
            }
        } else {
            if if_on_newlines {
                printer.newline();
            }
            // ELSEIF uses token ID if available
            if let Some(token_id) = branch.if_token {
                printer.push_token_id(token_id);
            } else {
                printer.push_keyword_span(branch.if_span);
            }
        }

        printer.space();
        // Only emit parentheses if they were present in the original (CST-guided)
        if let Some(lparen_id) = branch.lparen_token {
            printer.push_token_id(lparen_id);
        }
        // Format parsed condition expression with proper operator spacing
        format_expression(printer, &branch.condition)?;
        if let Some(rparen_id) = branch.rparen_token {
            printer.push_token_id(rparen_id);
        }
        printer.space();
        // Use token ID for THEN if available
        if let Some(token_id) = branch.then_token {
            printer.push_token_id(token_id);
        } else {
            printer.push_keyword_span(branch.then_span);
        }

        if if_on_newlines {
            printer.newline();
        }

        if indent_if {
            printer.indent_up();
        }

        // Format body statements with proper semicolon and trailing trivia handling
        for (stmt_idx, stmt) in branch.body.iter().enumerate() {
            if stmt_idx > 0 && is_major_statement(stmt) {
                printer.newline();
            }
            format_nested_statement(printer, stmt)?;
            // Gap to next sibling; for the last statement of the branch, to the
            // next ELSEIF branch, else to ELSE, else to END IF.
            let gap_target = if stmt_idx + 1 < branch.body.len() {
                Some(branch.body[stmt_idx + 1].span().start)
            } else if branch_idx + 1 < branches.len() {
                Some(branches[branch_idx + 1].if_span.start)
            } else if !else_body.is_empty() {
                else_span.map(|s| s.start).or(end_if_boundary)
            } else {
                end_if_boundary
            };
            if let Some(target) = gap_target {
                printer.emit_all_tokens_until(target);
            }
            if if_on_newlines && stmt_idx < branch.body.len() - 1 {
                printer.newline();
            }
        }

        if indent_if {
            printer.indent_down();
        }
    }

    // ELSE clause
    if !else_body.is_empty() {
        if if_on_newlines {
            printer.newline();
        }
        if let Some(token_id) = else_token {
            printer.push_token_id(token_id);
        } else if let Some(else_sp) = else_span {
            printer.push_keyword_span(else_sp);
        } else {
            printer.push_keyword("ELSE");
        }
        if if_on_newlines {
            printer.newline();
        }

        if indent_if {
            printer.indent_up();
        }

        for (stmt_idx, stmt) in else_body.iter().enumerate() {
            if stmt_idx > 0 && is_major_statement(stmt) {
                printer.newline();
            }
            format_nested_statement(printer, stmt)?;
            // Gap to next sibling; for the last ELSE statement, to END IF.
            let gap_target = if stmt_idx + 1 < else_body.len() {
                Some(else_body[stmt_idx + 1].span().start)
            } else {
                end_if_boundary
            };
            if let Some(target) = gap_target {
                printer.emit_all_tokens_until(target);
            }
            if if_on_newlines && stmt_idx < else_body.len() - 1 {
                printer.newline();
            }
        }

        if indent_if {
            printer.indent_down();
        }
    }

    if if_on_newlines {
        printer.newline();
    }
    // Use token ID for END if available
    if let Some(token_id) = end_token {
        printer.push_token_id(token_id);
        // Need to also emit "IF" after END
        printer.space();
        if let Some(if_token_id) = end_if_token {
            printer.push_keyword_token_id(if_token_id);
        } else {
            printer.push_keyword("IF");
        }
    } else if let Some(end_sp) = end_span {
        printer.push_span(end_sp);
    } else {
        printer.push_keyword("END");
        printer.space();
        printer.push_keyword("IF");
    }

    Ok(())
}

/// Format CASE statement
fn format_case_stmt(
    printer: &mut Printer,
    case_span: Span,
    case_token: Option<crate::cst::TokenId>,
    operand_span: Option<Span>,
    branches: &[crate::ast::CaseBranch],
    else_span: Option<Span>,
    else_token: Option<crate::cst::TokenId>,
    else_body: &[AstStmt],
    end_span: Option<Span>,
    end_token: Option<crate::cst::TokenId>,
    end_case_token: Option<crate::cst::TokenId>,
) -> Result<(), FormatterError> {
    // Use token ID for CASE if available
    if let Some(token_id) = case_token {
        printer.push_token_id(token_id);
    } else {
        printer.push_keyword_span(case_span);
    }

    // Use end_span for boundary when available
    let end_case_boundary = end_span.map(|s| s.start);

    if let Some(op) = operand_span {
        printer.space();
        // Use push_span to emit trivia attached to the operand
        printer.push_span(op);
    }

    printer.newline();
    printer.indent_up();

    for (branch_idx, branch) in branches.iter().enumerate() {
        // Use token ID for WHEN if available
        if let Some(token_id) = branch.when_token {
            printer.push_token_id(token_id);
        } else {
            printer.push_keyword_span(branch.when_span);
        }
        printer.space();
        // Format the condition expression to emit trivia attached to it
        format_expression(printer, &branch.condition)?;
        printer.space();
        // Use token ID for THEN if available
        if let Some(token_id) = branch.then_token {
            printer.push_token_id(token_id);
        } else {
            printer.push_keyword_span(branch.then_span);
        }
        printer.newline();
        printer.indent_up();

        for (i, stmt) in branch.body.iter().enumerate() {
            // Add blank line before major statements (except the first)
            if i > 0 && is_major_statement(stmt) {
                printer.newline();
            }
            format_nested_statement(printer, stmt)?;

            // Emit the gap (trailing `;` + comments) to the next boundary: next
            // sibling, else next WHEN branch, else ELSE, else END CASE.
            let gap_target = if i + 1 < branch.body.len() {
                Some(branch.body[i + 1].span().start)
            } else if branch_idx + 1 < branches.len() {
                Some(branches[branch_idx + 1].when_span.start)
            } else if !else_body.is_empty() {
                else_span.map(|s| s.start).or(end_case_boundary)
            } else {
                end_case_boundary
            };
            if let Some(target) = gap_target {
                printer.emit_all_tokens_until(target);
            }

            if i < branch.body.len() - 1 {
                printer.newline();
            }
        }

        printer.indent_down();
        printer.newline();
    }

    if !else_body.is_empty() {
        // Use token ID for ELSE if available
        if let Some(token_id) = else_token {
            printer.push_token_id(token_id);
        } else if let Some(else_sp) = else_span {
            printer.push_keyword_span(else_sp);
        } else {
            printer.push_keyword("ELSE");
        }
        printer.newline();
        printer.indent_up();

        for (i, stmt) in else_body.iter().enumerate() {
            // Add blank line before major statements (except the first)
            if i > 0 && is_major_statement(stmt) {
                printer.newline();
            }
            format_nested_statement(printer, stmt)?;

            // Gap to next sibling; for the last ELSE statement, to END CASE.
            let gap_target = if i + 1 < else_body.len() {
                Some(else_body[i + 1].span().start)
            } else {
                end_case_boundary
            };
            if let Some(target) = gap_target {
                printer.emit_all_tokens_until(target);
            }

            if i < else_body.len() - 1 {
                printer.newline();
            }
        }

        printer.indent_down();
        printer.newline();
    }

    printer.indent_down();
    // Use token ID for END if available
    if let Some(token_id) = end_token {
        printer.push_token_id(token_id);
        printer.space();
        if let Some(case_token_id) = end_case_token {
            printer.push_keyword_token_id(case_token_id);
        } else {
            printer.push_keyword("CASE");
        }
    } else if let Some(end_sp) = end_span {
        printer.push_span(end_sp);
    } else {
        printer.push_keyword("END");
        printer.space();
        printer.push_keyword("CASE");
    }

    Ok(())
}

/// Format WHILE (condition) DO...END WHILE
fn format_while(
    printer: &mut Printer,
    while_span: Span,
    while_token: Option<crate::cst::TokenId>,
    lparen_token: Option<crate::cst::TokenId>,
    condition: &AstExpr,
    rparen_token: Option<crate::cst::TokenId>,
    body_keyword_span: Span,
    body_keyword_token: Option<crate::cst::TokenId>,
    body: &[AstStmt],
    end_span: Option<Span>,
    end_token: Option<crate::cst::TokenId>,
    end_while_token: Option<crate::cst::TokenId>,
) -> Result<(), FormatterError> {
    let loop_on_newlines = printer.config().loop_body_on_newlines;
    let indent_loop = printer.config().indent_loop_body;

    // Use token ID for WHILE if available
    if let Some(token_id) = while_token {
        printer.push_token_id(token_id);
    } else {
        printer.push_keyword_span(while_span);
    }
    printer.space();
    // Only emit parentheses if they were present in the original (CST-guided)
    if let Some(lparen_id) = lparen_token {
        printer.push_token_id(lparen_id);
    }
    // Format parsed condition expression with proper operator spacing
    format_expression(printer, condition)?;
    if let Some(rparen_id) = rparen_token {
        printer.push_token_id(rparen_id);
    }
    printer.space();
    if let Some(token_id) = body_keyword_token {
        printer.push_token_id(token_id);
    } else {
        printer.push_keyword_span(body_keyword_span);
    }

    if loop_on_newlines {
        printer.newline();
    }

    if indent_loop {
        printer.indent_up();
    }

    // Determine boundary for trailing content emission (END WHILE position)
    let end_boundary = end_span.map(|s| s.start);

    for (i, stmt) in body.iter().enumerate() {
        // Add blank line before major statements (except the first)
        if i > 0 && is_major_statement(stmt) {
            printer.newline();
        }
        format_nested_statement(printer, stmt)?;
        // Gap to next sibling; for the last statement, to END WHILE.
        let gap_target = if i + 1 < body.len() {
            Some(body[i + 1].span().start)
        } else {
            end_boundary
        };
        if let Some(target) = gap_target {
            printer.emit_all_tokens_until(target);
        }
        if loop_on_newlines && i < body.len() - 1 {
            printer.newline();
        }
    }

    if indent_loop {
        printer.indent_down();
    }

    if loop_on_newlines {
        printer.newline();
    }
    // Use token ID for END if available
    if let Some(token_id) = end_token {
        printer.push_token_id(token_id);
        printer.space();
        if let Some(while_token_id) = end_while_token {
            printer.push_keyword_token_id(while_token_id);
        } else {
            printer.push_keyword("WHILE");
        }
    } else {
        printer.push_keyword("END");
        printer.space();
        printer.push_keyword("WHILE");
    }

    Ok(())
}

/// Format FOR loop_var IN range DO...END FOR
fn format_for(
    printer: &mut Printer,
    for_span: Span,
    for_token: Option<crate::cst::TokenId>,
    loop_var_span: Span,
    in_span: Span,
    in_token: Option<crate::cst::TokenId>,
    range_span: Span,
    body_keyword_span: Span,
    body_keyword_token: Option<crate::cst::TokenId>,
    body: &[AstStmt],
    end_span: Option<Span>,
    end_token: Option<crate::cst::TokenId>,
    end_for_token: Option<crate::cst::TokenId>,
) -> Result<(), FormatterError> {
    let loop_on_newlines = printer.config().loop_body_on_newlines;
    let indent_loop = printer.config().indent_loop_body;

    // Use token ID for FOR if available
    if let Some(token_id) = for_token {
        printer.push_token_id(token_id);
    } else {
        printer.push_keyword_span(for_span);
    }
    printer.space();
    // Use push_identifier_span to emit trivia attached to loop variable
    printer.push_identifier_span(loop_var_span);
    printer.space();
    if let Some(token_id) = in_token {
        printer.push_token_id(token_id);
    } else {
        printer.push_keyword_span(in_span);
    }
    printer.space();
    // range_span now starts at the first real token after IN (parser fixed to exclude trivia)
    // Use push_span to emit leading trivia (IN's trailing trivia) and the range content
    printer.push_span(range_span);
    printer.space();
    if let Some(token_id) = body_keyword_token {
        printer.push_token_id(token_id);
    } else {
        printer.push_keyword_span(body_keyword_span);
    }

    if loop_on_newlines {
        printer.newline();
    }

    if indent_loop {
        printer.indent_up();
    }

    // Determine boundary for trailing content emission (END FOR position)
    let end_boundary = end_span.map(|s| s.start);

    for (i, stmt) in body.iter().enumerate() {
        if i > 0 && is_major_statement(stmt) {
            printer.newline();
        }
        format_nested_statement(printer, stmt)?;

        // Gap to next sibling; for the last statement, to END FOR.
        let gap_target = if i + 1 < body.len() {
            Some(body[i + 1].span().start)
        } else {
            end_boundary
        };
        if let Some(target) = gap_target {
            printer.emit_all_tokens_until(target);
        }

        if loop_on_newlines && i < body.len() - 1 {
            printer.newline();
        }
    }

    if indent_loop {
        printer.indent_down();
    }

    if loop_on_newlines {
        printer.newline();
    }
    // Use token ID for END if available
    if let Some(token_id) = end_token {
        printer.push_token_id(token_id);
        printer.space();
        if let Some(for_token_id) = end_for_token {
            printer.push_keyword_token_id(for_token_id);
        } else {
            printer.push_keyword("FOR");
        }
    } else {
        printer.push_keyword("END");
        printer.space();
        printer.push_keyword("FOR");
    }

    Ok(())
}

/// Format PostgreSQL `FOREACH target [SLICE n] IN ARRAY <expr> LOOP … END LOOP`.
/// Mirrors [`format_for`]'s body emission; the FOREACH/ARRAY lexemes and the
/// parsed array expression are emitted from their captured tokens/spans.
fn format_foreach(
    printer: &mut Printer,
    fe: &crate::ast::types::AstForEachStmt,
) -> Result<(), FormatterError> {
    let loop_on_newlines = printer.config().loop_body_on_newlines;
    let indent_loop = printer.config().indent_loop_body;

    // FOREACH
    if let Some(token_id) = fe.foreach_token {
        printer.push_token_id(token_id);
    } else {
        printer.push_keyword_span(fe.foreach_span);
    }
    printer.space();
    // target loop variable
    printer.push_identifier_span(fe.loop_var_span);
    // optional SLICE n
    if let Some(slice_span) = fe.slice_span {
        printer.space();
        printer.push_keyword_span(slice_span);
        if let Some(count_span) = fe.slice_count_span {
            printer.space();
            printer.push_span(count_span);
        }
    }
    printer.space();
    // IN
    if let Some(token_id) = fe.in_token {
        printer.push_token_id(token_id);
    } else {
        printer.push_keyword_span(fe.in_span);
    }
    printer.space();
    // ARRAY
    if let Some(token_id) = fe.array_token {
        printer.push_token_id(token_id);
    } else {
        printer.push_keyword_span(fe.array_span);
    }
    printer.space();
    // the iterated array expression
    printer.push_span(fe.array_expr.span());
    printer.space();
    // LOOP (body opener)
    if let Some(token_id) = fe.body_keyword_token {
        printer.push_token_id(token_id);
    } else {
        printer.push_keyword_span(fe.body_keyword_span);
    }

    if loop_on_newlines {
        printer.newline();
    }
    if indent_loop {
        printer.indent_up();
    }

    let end_boundary = fe.end_span.map(|s| s.start);
    for (i, stmt) in fe.body.iter().enumerate() {
        if i > 0 && is_major_statement(stmt) {
            printer.newline();
        }
        format_nested_statement(printer, stmt)?;
        let gap_target = if i + 1 < fe.body.len() {
            Some(fe.body[i + 1].span().start)
        } else {
            end_boundary
        };
        if let Some(target) = gap_target {
            printer.emit_all_tokens_until(target);
        }
        if loop_on_newlines && i < fe.body.len() - 1 {
            printer.newline();
        }
    }

    if indent_loop {
        printer.indent_down();
    }
    if loop_on_newlines {
        printer.newline();
    }
    // END LOOP
    if let Some(token_id) = fe.end_token {
        printer.push_token_id(token_id);
        printer.space();
        if let Some(loop_token_id) = fe.end_loop_token {
            printer.push_keyword_token_id(loop_token_id);
        } else {
            printer.push_keyword("LOOP");
        }
    } else {
        printer.push_keyword("END");
        printer.space();
        printer.push_keyword("LOOP");
    }

    Ok(())
}

/// Format REPEAT...UNTIL (condition) END REPEAT
fn format_repeat(
    printer: &mut Printer,
    repeat_span: Span,
    repeat_token: Option<crate::cst::TokenId>,
    body: &[AstStmt],
    until_span: Span,
    until_token: Option<crate::cst::TokenId>,
    until_condition_span: Span,
    end_span: Option<Span>,
    end_token: Option<crate::cst::TokenId>,
    end_repeat_token: Option<crate::cst::TokenId>,
) -> Result<(), FormatterError> {
    let loop_on_newlines = printer.config().loop_body_on_newlines;
    let indent_loop = printer.config().indent_loop_body;

    // Use token ID for REPEAT if available
    if let Some(token_id) = repeat_token {
        printer.push_token_id(token_id);
    } else {
        printer.push_keyword_span(repeat_span);
    }

    if loop_on_newlines {
        printer.newline();
    }

    if indent_loop {
        printer.indent_up();
    }

    // For REPEAT, the boundary for the last statement is the UNTIL keyword
    // (not END REPEAT) — the loop body ends there.
    let until_boundary = until_span.start;

    for (i, stmt) in body.iter().enumerate() {
        // Add blank line before major statements (except the first)
        if i > 0 && is_major_statement(stmt) {
            printer.newline();
        }
        format_nested_statement(printer, stmt)?;
        // Gap to next sibling; for the last statement, to UNTIL.
        let target = if i + 1 < body.len() {
            body[i + 1].span().start
        } else {
            until_boundary
        };
        printer.emit_all_tokens_until(target);
        if loop_on_newlines && i < body.len() - 1 {
            printer.newline();
        }
    }

    if indent_loop {
        printer.indent_down();
    }

    if loop_on_newlines {
        printer.newline();
    }

    // Use token ID for UNTIL if available
    if let Some(token_id) = until_token {
        printer.push_token_id(token_id);
    } else {
        printer.push_keyword_span(until_span);
    }
    printer.space();
    // Use push_span to emit trivia attached to the condition (including parens)
    printer.push_span(until_condition_span);
    printer.space();
    // Use token ID for END if available
    if let Some(token_id) = end_token {
        printer.push_token_id(token_id);
        printer.space();
        if let Some(repeat_token_id) = end_repeat_token {
            printer.push_keyword_token_id(repeat_token_id);
        } else {
            printer.push_keyword("REPEAT");
        }
    } else {
        printer.push_keyword("END");
        printer.space();
        printer.push_keyword("REPEAT");
    }

    // end_span is available but not currently used since UNTIL is the boundary before END REPEAT
    let _ = end_span;

    Ok(())
}

/// Format LOOP...END LOOP
fn format_loop(
    printer: &mut Printer,
    loop_span: Span,
    loop_token: Option<crate::cst::TokenId>,
    body: &[AstStmt],
    end_span: Option<Span>,
    end_token: Option<crate::cst::TokenId>,
    end_loop_token: Option<crate::cst::TokenId>,
) -> Result<(), FormatterError> {
    let loop_on_newlines = printer.config().loop_body_on_newlines;
    let indent_loop = printer.config().indent_loop_body;

    // Use token ID for LOOP if available
    if let Some(token_id) = loop_token {
        printer.push_token_id(token_id);
    } else {
        printer.push_keyword_span(loop_span);
    }

    if loop_on_newlines {
        printer.newline();
    }

    if indent_loop {
        printer.indent_up();
    }

    // Determine boundary for trailing content emission (END LOOP position)
    let end_boundary = end_span.map(|s| s.start);

    for (i, stmt) in body.iter().enumerate() {
        // Add blank line before major statements (except the first)
        if i > 0 && is_major_statement(stmt) {
            printer.newline();
        }
        format_nested_statement(printer, stmt)?;
        // Gap to next sibling; for the last statement, to END LOOP.
        let gap_target = if i + 1 < body.len() {
            Some(body[i + 1].span().start)
        } else {
            end_boundary
        };
        if let Some(target) = gap_target {
            printer.emit_all_tokens_until(target);
        }
        if loop_on_newlines && i < body.len() - 1 {
            printer.newline();
        }
    }

    if indent_loop {
        printer.indent_down();
    }

    if loop_on_newlines {
        printer.newline();
    }
    // Use token ID for END if available
    if let Some(token_id) = end_token {
        printer.push_token_id(token_id);
        printer.space();
        if let Some(loop_token_id) = end_loop_token {
            printer.push_keyword_token_id(loop_token_id);
        } else {
            printer.push_keyword("LOOP");
        }
    } else {
        printer.push_keyword("END");
        printer.space();
        printer.push_keyword("LOOP");
    }

    Ok(())
}

/// Format RAISE [exception_name] or RAISE USING MESSAGE = expr
fn format_raise(
    printer: &mut Printer,
    raise_span: Span,
    raise_token: Option<crate::cst::TokenId>,
    exception_name: Option<Span>,
    level_span: Option<Span>,
    message_span: Option<Span>,
    using_span: Option<Span>,
    message_expr: Option<&AstExpr>,
) -> Result<(), FormatterError> {
    if let Some(token_id) = raise_token {
        printer.push_token_id(token_id);
    } else {
        printer.push_keyword_span(raise_span);
    }
    // PostgreSQL severity level (NOTICE/WARNING/…) before the payload.
    if let Some(lvl) = level_span {
        printer.space();
        printer.push_span(lvl);
    }
    if let Some(name_span) = exception_name {
        printer.space();
        printer.push_span(name_span);
    }
    // PostgreSQL message/condition payload (`'format' [, args]`).
    if let Some(msg) = message_span {
        printer.space();
        printer.push_span(msg);
    }
    // BigQuery style: USING MESSAGE = expr
    if let Some(using_clause_span) = using_span {
        printer.space();
        printer.push_span(using_clause_span);
    } else if let Some(expr) = message_expr {
        printer.space();
        printer.push_keyword("USING");
        printer.space();
        printer.push_keyword("MESSAGE");
        printer.space();
        printer.push_char('=');
        printer.space();
        format_expression(printer, expr)?;
    }
    Ok(())
}

/// Format EXECUTE IMMEDIATE sql_expr [USING (args)] [INTO vars]
fn format_execute_immediate(
    printer: &mut Printer,
    execute_span: Span,
    immediate_span: Option<Span>,
    using_span: Option<Span>,
    into_span: Option<Span>,
    into_strict_span: Option<Span>,
    sql_expr: &AstExpr,
    using_args: &[AstExecuteUsingArg],
    using_lparen_span: Option<Span>,
    using_rparen_span: Option<Span>,
    into_vars: &[Span],
) -> Result<(), FormatterError> {
    printer.push_keyword_span(execute_span);
    printer.space();
    // IMMEDIATE keyword is absent in the PL/pgSQL `EXECUTE <expr>` form.
    if let Some(immediate) = immediate_span {
        printer.push_keyword_span(immediate);
        printer.space();
    }

    // Format the SQL expression
    format_expression(printer, sql_expr)?;

    // USING clause
    if !using_args.is_empty() {
        printer.space();
        if let Some(using_kw_span) = using_span {
            printer.push_keyword_span(using_kw_span);
        } else {
            printer.push_keyword("USING");
        }
        printer.space();
        if let Some(lparen) = using_lparen_span {
            printer.push_span(lparen);
        }
        for (i, arg) in using_args.iter().enumerate() {
            if i > 0 {
                printer.push_comma();
                if printer.config().space_after_comma {
                    printer.space();
                }
            }
            format_expression(printer, &arg.expr)?;
            if let Some(ref alias) = arg.alias {
                if let Some(as_span) = alias.as_span {
                    printer.space();
                    printer.push_keyword_span(as_span);
                }
                printer.space();
                printer.push_identifier_span_v2(alias.ident.span);
            }
        }
        if let Some(rparen) = using_rparen_span {
            printer.push_span(rparen);
        }
    }

    // INTO clause
    if !into_vars.is_empty() {
        printer.space();
        if let Some(into_kw_span) = into_span {
            printer.push_keyword_span(into_kw_span);
        } else {
            printer.push_keyword("INTO");
        }
        printer.space();
        // PL/pgSQL `INTO STRICT <target>` modifier.
        if let Some(strict_span) = into_strict_span {
            printer.push_keyword_span(strict_span);
            printer.space();
        }
        for (i, var_span) in into_vars.iter().enumerate() {
            if i > 0 {
                printer.push_comma();
                if printer.config().space_after_comma {
                    printer.space();
                }
            }
            printer.push_span(*var_span);
        }
    }

    Ok(())
}

/// Format expression (delegates to select formatter for now)
fn format_expression(printer: &mut Printer, expr: &AstExpr) -> Result<(), FormatterError> {
    crate::formatter::statements::select::format_expression(printer, expr)
}
