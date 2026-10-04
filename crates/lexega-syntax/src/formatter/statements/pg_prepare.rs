// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Formatters for PostgreSQL prepared statement commands.
//!
//! - `PREPARE name [ ( data_type [, ...] ) ] AS statement`
//! - `EXECUTE name [ ( parameter [, ...] ) ]`
//! - `DEALLOCATE [ PREPARE ] { name | ALL }`

use crate::ast::types::{AstPgDeallocate, AstPgExecute, AstPgPrepare, PgDeallocateTarget};
use crate::formatter::printer::Printer;
use crate::formatter::FormatterError;

/// Format a PREPARE statement.
pub fn format_pg_prepare(printer: &mut Printer, stmt: &AstPgPrepare) -> Result<(), FormatterError> {
    if let Some(syntax_id) = stmt.syntax_id {
        if let Some(syntax_arena) = printer.syntax_arena() {
            let syntax = *syntax_arena.get_pg_prepare_stmt(syntax_id);
            let _ = syntax_arena;

            // PREPARE
            printer.push_keyword_token_id(syntax.prepare_keyword);

            // name
            printer.space();
            printer.push_span(stmt.name);

            // Optional: ( data_type [, ...] )
            if let Some(param_types_span) = stmt.param_types_span {
                printer.space();
                printer.push_span(param_types_span);
            }

            // AS
            printer.space();
            printer.push_keyword_span(stmt.as_span);
            printer.space();

            // Body statement — emit the inner statement's span verbatim
            printer.push_span(stmt.body.span());

            return Ok(());
        }
    }

    // Fallback: emit the whole span verbatim
    printer.push_span(stmt.span);
    Ok(())
}

/// Format an EXECUTE statement (PG prepared statement execution).
pub fn format_pg_execute(printer: &mut Printer, stmt: &AstPgExecute) -> Result<(), FormatterError> {
    if let Some(syntax_id) = stmt.syntax_id {
        if let Some(syntax_arena) = printer.syntax_arena() {
            let syntax = *syntax_arena.get_pg_execute_stmt(syntax_id);
            let _ = syntax_arena;

            // EXECUTE
            printer.push_keyword_token_id(syntax.execute_keyword);

            // name
            printer.space();
            printer.push_span(stmt.name);

            // Optional: ( parameter [, ...] )  — PostgreSQL form
            if let Some(args_span) = stmt.args_span {
                printer.space();
                printer.push_span(args_span);
            }

            // Optional: USING @v1, @v2, ...  — MySQL form
            if let Some(using_span) = stmt.using_span {
                printer.space();
                printer.push_span(using_span);
            }

            return Ok(());
        }
    }

    // Fallback: emit the whole span verbatim
    printer.push_span(stmt.span);
    Ok(())
}

/// Format a DEALLOCATE statement.
pub fn format_pg_deallocate(
    printer: &mut Printer,
    stmt: &AstPgDeallocate,
) -> Result<(), FormatterError> {
    if let Some(syntax_id) = stmt.syntax_id {
        if let Some(syntax_arena) = printer.syntax_arena() {
            let syntax = *syntax_arena.get_pg_deallocate_stmt(syntax_id);
            let _ = syntax_arena;

            // DEALLOCATE
            printer.push_keyword_token_id(syntax.deallocate_keyword);

            // Target: name or ALL
            printer.space();
            if let Some(prepare_span) = stmt.prepare_span {
                printer.push_keyword_span(prepare_span);
                printer.space();
            }
            match &stmt.target {
                PgDeallocateTarget::Name(span) => printer.push_span(*span),
                PgDeallocateTarget::All(span) => printer.push_span(*span),
            }

            return Ok(());
        }
    }

    // Fallback: emit the whole span verbatim
    printer.push_span(stmt.span);
    Ok(())
}
