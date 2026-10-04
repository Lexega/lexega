// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Formatter for PostgreSQL COPY statement.
//!
//! Since COPY options are complex and varied (many token kinds: Keywords, Identifiers,
//! Literals), we use span-based formatting — emit all components from their source spans.

use crate::ast::types::{AstPgCopy, PgCopySubject, PgCopyTarget};
use crate::formatter::printer::Printer;
use crate::formatter::FormatterError;

/// Format a PostgreSQL COPY statement.
pub fn format_pg_copy(printer: &mut Printer, stmt: &AstPgCopy) -> Result<(), FormatterError> {
    // COPY keyword — emit from syntax node if available
    if let Some(syntax_id) = stmt.syntax_id {
        if let Some(syntax_arena) = printer.syntax_arena() {
            let syntax = *syntax_arena.get_pg_copy_stmt(syntax_id);
            let _ = syntax_arena;
            printer.push_keyword_token_id(syntax.copy_keyword);
        } else {
            printer.push_keyword("COPY");
        }
    } else {
        printer.push_keyword("COPY");
    }

    printer.push_char(' ');

    // Subject: table name or (query)
    match &stmt.subject {
        PgCopySubject::Table(span) => {
            printer.push_span(*span);
        }
        PgCopySubject::Query(span, _query) => {
            printer.push_span(*span);
        }
    }

    // Optional column list
    if let Some(cols) = stmt.columns_span {
        printer.push_char(' ');
        printer.push_span(cols);
    }

    printer.push_char(' ');

    // FROM or TO — emit from source via the direction keyword which is part of
    // the overall span; we reconstruct it since it's just a keyword
    match stmt.direction {
        crate::ast::types::PgCopyDirection::From => printer.push_keyword("FROM"),
        crate::ast::types::PgCopyDirection::To => printer.push_keyword("TO"),
    }

    printer.push_char(' ');

    // Target: file, PROGRAM, STDIN, STDOUT
    match &stmt.target {
        PgCopyTarget::File(span) => printer.push_span(*span),
        PgCopyTarget::Program(span) => printer.push_span(*span),
        PgCopyTarget::Stdin(span) => printer.push_span(*span),
        PgCopyTarget::Stdout(span) => printer.push_span(*span),
        PgCopyTarget::Placeholder(span) => printer.push_span(*span),
    }

    // Optional WITH (options)
    if let Some(opts) = stmt.options_span {
        printer.push_char(' ');
        printer.push_span(opts);
    }

    // Optional WHERE clause
    if let Some(ws) = stmt.where_span {
        printer.push_char(' ');
        printer.push_span(ws);
    }

    Ok(())
}
