// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Formatter for STREAM statements.

use crate::ast::{AstAlterStream, AstCreateStream, AstDropStream};
use crate::formatter::printer::Printer;
use crate::formatter::FormatterError;

pub fn format_create_stream(
    printer: &mut Printer,
    stmt: &AstCreateStream,
) -> Result<(), FormatterError> {
    let syntax = stmt.syntax_id.and_then(|id| printer.get_create_stream(id));
    if let Some(s) = syntax {
        printer.push_keyword_token_id(s.create_keyword);
        if let Some(or_kw) = s.or_keyword {
            printer.space();
            printer.push_keyword_token_id(or_kw);
            if let Some(replace_kw) = s.replace_keyword {
                printer.space();
                printer.push_keyword_token_id(replace_kw);
            }
        }
        printer.space();
        printer.push_token_id(s.stream_keyword);
        if let Some(if_kw) = s.if_keyword {
            printer.space();
            printer.push_keyword_token_id(if_kw);
            if let Some(not_kw) = s.not_keyword {
                printer.space();
                printer.push_keyword_token_id(not_kw);
            }
            if let Some(exists_kw) = s.exists_keyword {
                printer.space();
                printer.push_keyword_token_id(exists_kw);
            }
        }
        printer.space();
        printer.push_identifier_span_v2(s.name_span);

        if let Some(clone_span) = s.clone_span {
            printer.space();
            printer.push_span(clone_span);
        }
        if let Some(tag_clause_span) = s.tag_clause_span {
            printer.newline();
            printer.push_span(tag_clause_span);
        }
        if let Some(copy_grants_span) = s.copy_grants_span {
            printer.newline();
            printer.push_span(copy_grants_span);
        }
        if let Some(on_kw) = s.on_keyword {
            printer.newline();
            printer.push_keyword_token_id(on_kw);
            if let Some(source_type_span) = s.source_type_span {
                printer.space();
                printer.push_span(source_type_span);
            }
            if let Some(source_name_span) = s.source_name_span {
                printer.space();
                printer.push_identifier_span_v2(source_name_span);
            }
        }
        if let Some(time_travel_span) = s.time_travel_span {
            printer.newline();
            printer.push_span(time_travel_span);
        }
        if let Some(append_only_span) = s.append_only_span {
            printer.newline();
            printer.push_span(append_only_span);
        }
        if let Some(show_initial_rows_span) = s.show_initial_rows_span {
            printer.newline();
            printer.push_span(show_initial_rows_span);
        }
        if let Some(insert_only_span) = s.insert_only_span {
            printer.newline();
            printer.push_span(insert_only_span);
        }
        if let Some(comment_span) = s.comment_span {
            printer.newline();
            printer.push_span(comment_span);
        }
        return Ok(());
    }

    printer.push_span(stmt.span);
    Ok(())
}

pub fn format_drop_stream(
    printer: &mut Printer,
    stmt: &AstDropStream,
) -> Result<(), FormatterError> {
    let syntax = stmt.syntax_id.and_then(|id| printer.get_drop_stream(id));
    if let Some(s) = syntax {
        printer.push_keyword_token_id(s.drop_keyword);
        printer.space();
        printer.push_token_id(s.stream_keyword);
        if let Some(if_kw) = s.if_keyword {
            printer.space();
            printer.push_keyword_token_id(if_kw);
            if let Some(exists_kw) = s.exists_keyword {
                printer.space();
                printer.push_keyword_token_id(exists_kw);
            }
        }
        printer.space();
        printer.push_identifier_span_v2(s.name_span);
        return Ok(());
    }

    printer.push_keyword_span(stmt.drop_span);
    printer.space();
    printer.push_span(stmt.stream_span);
    if let Some(if_exists_span) = stmt.if_exists_span {
        printer.space();
        printer.push_span(if_exists_span);
    }
    printer.space();
    printer.push_identifier_span_v2(stmt.name_span);
    Ok(())
}

pub fn format_alter_stream(
    printer: &mut Printer,
    stmt: &AstAlterStream,
) -> Result<(), FormatterError> {
    let syntax = stmt
        .syntax_id
        .and_then(|id| printer.get_alter_stream_stmt(id));
    if let Some(s) = syntax {
        printer.push_keyword_token_id(s.alter_keyword);
        printer.space();
        printer.push_token_id(s.stream_keyword);
        if let Some(if_kw) = s.if_keyword {
            printer.space();
            printer.push_keyword_token_id(if_kw);
            if let Some(exists_kw) = s.exists_keyword {
                printer.space();
                printer.push_keyword_token_id(exists_kw);
            }
        }
        printer.space();
        printer.push_identifier_span_v2(s.name_span);
        if stmt.action_span.start < stmt.action_span.end {
            printer.space();
            printer.push_span(stmt.action_span);
        }
        return Ok(());
    }

    printer.push_span(stmt.span);
    Ok(())
}
