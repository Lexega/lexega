// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! CREATE PROCEDURE and CREATE FUNCTION formatters
//!
//! Handles Snowflake stored procedure and UDF creation:
//! - CREATE [OR REPLACE] PROCEDURE
//! - CREATE [OR REPLACE] FUNCTION

use crate::ast::{AstRoutineLanguage, AstStmt};
use crate::error::ExpectInvariant;
use crate::formatter::config::ParamListStyle;
use crate::formatter::printer::Printer;
use crate::formatter::FormatterError;
use crate::lexer::Span;

/// Format CREATE PROCEDURE statement
///
/// Snowflake syntax:
/// ```sql
/// CREATE [OR REPLACE] PROCEDURE procedure_name(param1 TYPE, param2 TYPE)
///   RETURNS TYPE
///   [LANGUAGE SQL | JAVASCRIPT | PYTHON]
///   [EXECUTE AS CALLER | OWNER]
///   AS
/// $$
///   -- procedure body
/// $$;
/// ```
pub fn format_create_procedure(
    printer: &mut Printer,
    span: Span,
    create_span: Span,
    or_replace_span: Option<Span>,
    or_alter_span: Option<Span>,
    definer_span: Option<Span>,
    procedure_keyword_span: Span,
    name_span: Span,
    params_span: Span,
    returns_span: Span,
    language: &AstRoutineLanguage,
    body_span: Span,
    body_stmt: Option<&AstStmt>,
    opening_delimiter_token: Option<crate::cst::TokenId>,
    closing_delimiter_token: Option<crate::cst::TokenId>,
) -> Result<(), FormatterError> {
    // CREATE keyword - use push_span for trivia preservation
    printer.push_keyword_span(create_span);

    // OR REPLACE (if present) - use push_span for trivia preservation
    if let Some(or_replace) = or_replace_span {
        printer.space();
        printer.push_span(or_replace);
    }

    // OR ALTER (if present, MSSQL) - use push_span for trivia preservation
    if let Some(or_alter) = or_alter_span {
        printer.space();
        printer.push_span(or_alter);
    }

    // DEFINER = user (if present, MySQL) — emit verbatim between CREATE and
    // the object keyword so the clause round-trips byte-exact.
    if let Some(definer) = definer_span {
        printer.space();
        printer.push_span(definer);
    }

    // PROCEDURE keyword - use push_span for trivia preservation
    printer.space();
    printer.push_keyword_span(procedure_keyword_span);
    printer.space();

    // Procedure name - use push_identifier_span_v2 for identifier casing
    printer.push_identifier_span_v2(name_span);

    // Parameters - format based on config
    format_param_list(printer, params_span)?;

    // Emit comments between params closing paren and RETURNS
    printer.emit_trivia_until(returns_span.start, false);

    // RETURNS clause - emit from RETURNS up to (but not including) opening delimiter
    // Only emit extra newline when there's actual RETURNS content;
    // for MSSQL procedures with no RETURNS, the gap (including AS) is emitted via push_raw_source
    let has_returns = returns_span.start != returns_span.end;
    if has_returns {
        printer.newline();
    }

    // If we have an opening delimiter token, get its span to know where to stop
    let opening_delim_start = if let Some(opening_token_id) = opening_delimiter_token {
        let token = printer
            .get_token_by_id(opening_token_id)
            .expect_invariant("opening delimiter token should exist");
        token.span.start
    } else {
        // No CST token available, use body_span.start as fallback
        body_span.start
    };

    let returns_clause_span = Span {
        start: returns_span.start,
        end: opening_delim_start,
    };

    // Emit the RETURNS clause (without opening delimiter)
    printer.push_raw_source(returns_clause_span);

    // Check if original SQL has $$ delimiters and emit opening delimiter if present
    let has_dollar_delimiters = if let Some(opening_token_id) = opening_delimiter_token {
        let token = printer
            .get_token_by_id(opening_token_id)
            .expect_invariant("opening delimiter token should exist");

        // Advance source position to skip leading trivia that was already emitted
        // as part of returns_clause_span (e.g., comments between AS and $$)
        printer.set_source_position(token.span.start);

        // Emit opening delimiter using CST token for proper trailing trivia handling
        printer.push_token_id(opening_token_id);
        true
    } else {
        // No opening delimiter token ⇒ not a dollar-quoted body. A `$$`/`$tag$`
        // body is always lexed as a delimiter token and captured by the parser,
        // so a substring scan here would be both dead and wrong for tagged
        // delimiters (it only matched the bare `$$` form).
        false
    };

    match formatted_body(language, body_stmt) {
        Some(stmt) => {
            // The block's own layout; the Block formatter indents it.
            printer.newline();
            crate::formatter::statements::format_scripting_statement(printer, stmt)?;

            // After body formatting, emit everything from the closing $$ through span.end
            // as raw source. This preserves closing delimiter, any post-body clauses
            // (e.g., PG's LANGUAGE plpgsql), and the trailing semicolon with exact spacing.
            if has_dollar_delimiters {
                if let Some(closing_token_id) = closing_delimiter_token {
                    let closing_token = printer
                        .get_token_by_id(closing_token_id)
                        .expect_invariant("closing delimiter token should exist");
                    let remainder_start = closing_token.span.start;
                    // Emit newline before closing delimiter, then raw source for the rest
                    printer.newline();
                    printer.set_source_position(remainder_start);
                    printer.push_raw_source(Span {
                        start: remainder_start,
                        end: span.end,
                    });
                } else {
                    printer.newline();
                    printer.emit_all_tokens_until(span.end);
                }
            } else {
                printer.emit_all_tokens_until(span.end);
            }
        }
        None => {
            // A body the formatter does not lay out is copied as written
            // through the end of the statement: its bytes, the break and
            // indentation before its closing delimiter, and a clause after
            // it (`$$ LANGUAGE plv8`) are the source's whatever line break
            // the file is written with.
            let copied_end = match closing_delimiter_token {
                Some(closing_token_id) => Some(
                    printer
                        .get_token_by_id(closing_token_id)
                        .expect_invariant("closing delimiter token should exist")
                        .span
                        .end,
                ),
                None => (!has_dollar_delimiters).then_some(body_span.end),
            };
            match copied_end {
                Some(end) => printer.push_raw_source(Span {
                    start: body_span.start,
                    end: end.max(span.end),
                }),
                None => {
                    printer.push_raw_source(body_span);
                    printer.newline();
                    printer.emit_all_tokens_until(span.end);
                }
            }
        }
    }

    Ok(())
}

/// The body the formatter lays out as SQL statements: one in SQL
/// (`language`) that the parser read as a block. `None` for any other body,
/// which is copied as written: one in another language, or SQL the parser
/// did not read (a string, a T-SQL statement list, a dollar-quoted body that
/// is not one block).
pub(crate) fn formatted_body<'s>(
    language: &AstRoutineLanguage,
    body_stmt: Option<&'s AstStmt>,
) -> Option<&'s AstStmt> {
    body_stmt.filter(|_| *language == AstRoutineLanguage::Sql)
}

/// Format CREATE FUNCTION statement
///
/// Snowflake syntax:
/// ```sql
/// CREATE [OR REPLACE] [SECURE] FUNCTION function_name(param1 TYPE, param2 TYPE)
///   RETURNS TYPE
///   [LANGUAGE SQL | JAVASCRIPT | PYTHON | JAVA | SCALA]
///   [IMMUTABLE | VOLATILE]
///   [MEMOIZABLE]
///   [COMMENT = 'comment']
///   AS
/// $$
///   -- function body
/// $$;
/// ```
pub fn format_create_function(
    printer: &mut Printer,
    span: Span,
    create_span: Span,
    or_replace_span: Option<Span>,
    or_alter_span: Option<Span>,
    definer_span: Option<Span>,
    temp_keyword_span: Option<Span>,
    aggregate_keyword_span: Option<Span>,
    function_keyword_span: Span,
    if_not_exists_span: Option<Span>,
    name_span: Span,
    params_span: Span,
    _returns: Option<crate::ast::AstReturnsClause>,
    _body_span: Span,
    _body_stmt: Option<&crate::ast::AstStmt>,
    _opening_delimiter_token: Option<crate::cst::TokenId>,
    _closing_delimiter_token: Option<crate::cst::TokenId>,
) -> Result<(), FormatterError> {
    // CREATE keyword
    printer.push_keyword_span(create_span);

    // OR REPLACE (if present)
    if let Some(or_replace) = or_replace_span {
        printer.space();
        printer.push_span(or_replace);
    }

    // OR ALTER (if present, MSSQL)
    if let Some(or_alter) = or_alter_span {
        printer.space();
        printer.push_span(or_alter);
    }

    // DEFINER = user (if present, MySQL) — emit verbatim before the object
    // keyword so the clause round-trips byte-exact.
    if let Some(definer) = definer_span {
        printer.space();
        printer.push_span(definer);
    }

    // TEMP/TEMPORARY (if present)
    if let Some(temp_span) = temp_keyword_span {
        printer.space();
        printer.push_keyword_span(temp_span);
    }

    // AGGREGATE (if present, BigQuery UDAF)
    if let Some(agg_span) = aggregate_keyword_span {
        printer.space();
        printer.push_span(agg_span);
    }

    // FUNCTION keyword
    printer.space();
    printer.push_keyword_span(function_keyword_span);

    // IF NOT EXISTS (if present)
    if let Some(ine) = if_not_exists_span {
        printer.space();
        printer.push_span(ine);
    }

    printer.space();

    // Function name
    printer.push_identifier_span_v2(name_span);

    // Parameters
    format_param_list(printer, params_span)?;

    // Everything after params (RETURNS, LANGUAGE, AS, $$, body, $$, semicolon)
    // Emit as raw source to preserve exact formatting
    let remainder_span = Span {
        start: params_span.end,
        end: span.end,
    };
    printer.push_raw_source(remainder_span);

    Ok(())
}

/// Format CREATE [OR REPLACE] TABLE FUNCTION [IF NOT EXISTS] statement (BigQuery TVF)
///
/// Emits CREATE, optional OR REPLACE, TABLE FUNCTION, optional IF NOT EXISTS,
/// name, parameters, then everything after params as raw source (RETURNS TABLE<...>,
/// OPTIONS, AS query).
pub fn format_create_table_function(
    printer: &mut Printer,
    span: Span,
    create_span: Span,
    or_replace_span: Option<Span>,
    temp_keyword_span: Option<Span>,
    table_keyword_span: Span,
    function_keyword_span: Span,
    if_not_exists_span: Option<Span>,
    name_span: Span,
    params_span: Span,
) -> Result<(), FormatterError> {
    // CREATE keyword
    printer.push_keyword_span(create_span);

    // OR REPLACE (if present)
    if let Some(or_replace) = or_replace_span {
        printer.space();
        printer.push_span(or_replace);
    }

    // TEMP/TEMPORARY (if present)
    if let Some(temp_span) = temp_keyword_span {
        printer.space();
        printer.push_keyword_span(temp_span);
    }

    // TABLE keyword
    printer.space();
    printer.push_keyword_span(table_keyword_span);

    // FUNCTION keyword
    printer.space();
    printer.push_keyword_span(function_keyword_span);

    // IF NOT EXISTS (if present)
    if let Some(ine) = if_not_exists_span {
        printer.space();
        printer.push_span(ine);
    }

    // Function name
    printer.space();
    printer.push_identifier_span_v2(name_span);

    // Parameters
    format_param_list(printer, params_span)?;

    // Everything after params (RETURNS TABLE<...>, OPTIONS, AS, body)
    // Emit as raw source to preserve exact formatting
    let remainder_span = Span {
        start: params_span.end,
        end: span.end,
    };
    printer.push_raw_source(remainder_span);

    Ok(())
}

/// Emit a parameter list. The list is a single span, so every
/// `create_proc_func_params_style` writes it as in the source.
fn format_param_list(printer: &mut Printer, params_span: Span) -> Result<(), FormatterError> {
    match printer.config().create_proc_func_params_style {
        ParamListStyle::Inline | ParamListStyle::OnePerLine | ParamListStyle::Threshold(_) => {
            // push_span preserves trailing trivia.
            printer.push_span(params_span);
        }
    }

    Ok(())
}
