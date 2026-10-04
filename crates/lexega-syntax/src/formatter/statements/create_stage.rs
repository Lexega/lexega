// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! CREATE STAGE statement formatter
//!
//! Handles formatting for Snowflake stage creation:
//! - `CREATE [OR REPLACE] [TEMP] STAGE [IF NOT EXISTS] <name>`
//! - URL clause for external stages
//! - FILE_FORMAT clause
//! - STORAGE_INTEGRATION / CREDENTIALS clause
//! - ENCRYPTION, DIRECTORY, COMMENT, TAG, CLONE clauses

use crate::ast::AstCreateStage;
use crate::formatter::config::CreateStageClauseStyle;
use crate::formatter::printer::Printer;
use crate::formatter::FormatterError;
use crate::lexer::Span;

/// Format CREATE STAGE statement
///
/// Snowflake syntax:
/// ```sql
/// CREATE [OR REPLACE] [TEMP] STAGE [IF NOT EXISTS] stage_name
///   [ URL = 'protocol://bucket/path' ]
///   [ STORAGE_INTEGRATION = integration_name | CREDENTIALS = (...) ]
///   [ ENCRYPTION = (...) ]
///   [ FILE_FORMAT = (...) ]
///   [ DIRECTORY = (...) ]
///   [ COMMENT = '...' ]
///   [ TAG (...) ]
///   [ CLONE source_stage ]
/// ```
pub fn format_create_stage(
    printer: &mut Printer,
    stage: &AstCreateStage,
) -> Result<(), FormatterError> {
    // CREATE keyword - use push_span for trivia preservation
    printer.push_span(stage.create_span);

    // OR REPLACE (if present) - use push_span for trivia preservation
    if let Some(or_replace_span) = stage.or_replace_span {
        printer.space();
        printer.push_span(or_replace_span);
    }

    // TEMP/TEMPORARY (if present) - use push_span for trivia preservation
    if let Some(temp_span) = stage.temporary_span {
        printer.space();
        printer.push_span(temp_span);
    }

    // STAGE keyword - use push_span for trivia preservation
    printer.space();
    printer.push_span(stage.stage_keyword_span);

    // IF NOT EXISTS (if present) - use push_span for trivia preservation
    if let Some(if_not_exists_span) = stage.if_not_exists_span {
        printer.space();
        printer.push_span(if_not_exists_span);
    }

    // Stage name - use push_span for trivia preservation
    printer.space();
    printer.push_span(stage.name_span);

    // Collect all clauses with their spans for source-order emission
    let mut clauses: Vec<(u32, Span)> = Vec::new();

    if let Some(url_clause) = &stage.url_clause {
        clauses.push((url_clause.span.start, url_clause.span));
    }
    if let Some(creds_clause) = &stage.credentials_clause {
        clauses.push((creds_clause.span.start, creds_clause.span));
    }
    if let Some(encryption_span) = stage.encryption_clause {
        clauses.push((encryption_span.start, encryption_span));
    }
    if let Some(endpoint_span) = stage.endpoint_clause {
        clauses.push((endpoint_span.start, endpoint_span));
    }
    if let Some(file_format_clause) = &stage.file_format_clause {
        clauses.push((file_format_clause.span.start, file_format_clause.span));
    }
    if let Some(directory_span) = stage.directory_clause {
        clauses.push((directory_span.start, directory_span));
    }
    if let Some(comment_span) = stage.comment_span {
        clauses.push((comment_span.start, comment_span));
    }
    if let Some(tag_span) = stage.tag_clause {
        clauses.push((tag_span.start, tag_span));
    }
    if let Some(clone_span) = stage.clone_clause {
        clauses.push((clone_span.start, clone_span));
    }

    // Add unknown clauses (defensive design pattern)
    for unknown in &stage.extras {
        clauses.push((unknown.span.start, unknown.span));
    }

    // Sort by source position to preserve original order
    clauses.sort_by_key(|(start, _)| *start);

    // Emit clauses in source order
    for (_start, span) in clauses {
        format_stage_clause(printer, span)?;
    }

    Ok(())
}

/// Helper to format stage clauses based on config
fn format_stage_clause(printer: &mut Printer, clause_span: Span) -> Result<(), FormatterError> {
    let should_newline = match printer.config().create_stage_clause_style {
        CreateStageClauseStyle::Inline => false,
        CreateStageClauseStyle::Stacked | CreateStageClauseStyle::Grouped => true,
    };

    if should_newline {
        printer.newline();
        printer.indent_up();
        printer.push_span(clause_span);
        printer.indent_down();
    } else {
        printer.space();
        printer.push_span(clause_span);
    }

    Ok(())
}
