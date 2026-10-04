// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Formatters for PostgreSQL utility statements.
//!
//! Each function follows the CST-based formatting pattern:
//! 1. Extract CST node via syntax_id for token-level emission
//! 2. Emit keywords via `push_keyword_token_id()` (applies casing config)
//! 3. Emit identifiers/values via `push_span()` (preserves original casing)
//! 4. Fall back to whole-span emission if CST is unavailable

use crate::ast::types::{
    AstAlterPgTrigger, AstAlterSequence, AstAlterType, AstAnalyzeStmt, AstCommentOn,
    AstCreateExtension, AstCreateIndex, AstCreatePgTrigger, AstCreateSequence, AstCreateSynonym,
    AstCreateType, AstDoBlock, AstDropPgTrigger, AstVacuum, PgAlterTriggerAction,
    PgCascadeRestrict,
};
use crate::formatter::printer::Printer;
use crate::formatter::FormatterError;
use crate::lexer::Span;

/// Format `CREATE [UNIQUE] INDEX` statement.
pub fn format_create_index(
    printer: &mut Printer,
    stmt: &AstCreateIndex,
) -> Result<(), FormatterError> {
    if let Some(syntax_id) = stmt.syntax_id {
        if let Some(syntax_arena) = printer.syntax_arena() {
            let syntax = *syntax_arena.get_create_index_stmt(syntax_id);
            let _ = syntax_arena;

            // CREATE
            printer.push_keyword_token_id(syntax.create_keyword);

            // [UNIQUE]
            if let Some(unique_kw) = syntax.unique_keyword {
                printer.space();
                printer.push_keyword_token_id(unique_kw);
            }

            // [CLUSTERED | NONCLUSTERED]
            if let Some(clustered_kw) = syntax.clustered_keyword {
                printer.space();
                printer.push_keyword_token_id(clustered_kw);
            }

            // [COLUMNSTORE]
            if let Some(columnstore_kw) = syntax.columnstore_keyword {
                printer.space();
                printer.push_keyword_token_id(columnstore_kw);
            }

            // [FULLTEXT | SPATIAL]
            if let Some(kind_kw) = syntax.mysql_index_kind_keyword {
                printer.space();
                printer.push_keyword_token_id(kind_kw);
            }

            // INDEX
            printer.space();
            printer.push_keyword_token_id(syntax.index_keyword);

            // [CONCURRENTLY]
            if let Some(concurrently_kw) = syntax.concurrently_keyword {
                printer.space();
                printer.push_token_id(concurrently_kw);
            }

            // [IF NOT EXISTS]
            if let Some(if_kw) = syntax.if_keyword {
                printer.space();
                printer.push_keyword_token_id(if_kw);
                if let Some(not_kw) = syntax.not_keyword {
                    printer.space();
                    printer.push_keyword_token_id(not_kw);
                }
                if let Some(exists_kw) = syntax.exists_keyword {
                    printer.space();
                    printer.push_keyword_token_id(exists_kw);
                }
            }

            // Index name
            if let Some(name_span) = syntax.name_span {
                printer.space();
                printer.push_span(name_span);
            }

            // ON
            printer.space();
            printer.push_keyword_token_id(syntax.on_keyword);

            // Table name
            printer.space();
            printer.push_span(syntax.table_name_span);

            // [USING method]
            if let Some(using_kw) = syntax.using_keyword {
                printer.space();
                printer.push_keyword_token_id(using_kw);
                if let Some(method_span) = syntax.using_method_span {
                    printer.space();
                    printer.push_span(method_span);
                }
            }

            // (columns) — absent for a clustered columnstore index (no key columns),
            // in which case columns_span is empty and the parens are not emitted.
            if stmt.columns_span.end > stmt.columns_span.start {
                printer.space();
                printer.push_token_id(syntax.columns_l_paren);
                let rp_tok = printer.get_token_by_id(syntax.columns_r_paren);
                let rp_start = rp_tok.map(|t| t.span.start).unwrap_or(syntax.span.end);
                let pos = printer.get_source_position();
                if rp_start > pos {
                    printer.push_span(Span {
                        start: pos,
                        end: rp_start,
                    });
                }
                printer.push_token_id(syntax.columns_r_paren);
            }

            // [INCLUDE (columns)]
            if let Some(include_kw) = syntax.include_keyword {
                printer.space();
                printer.push_token_id(include_kw);
                if let Some(lp) = syntax.include_l_paren {
                    printer.space();
                    printer.push_token_id(lp);
                    if let Some(rp) = syntax.include_r_paren {
                        let rp_tok = printer.get_token_by_id(rp);
                        let rp_start = rp_tok.map(|t| t.span.start).unwrap_or(syntax.span.end);
                        let pos = printer.get_source_position();
                        if rp_start > pos {
                            printer.push_span(Span {
                                start: pos,
                                end: rp_start,
                            });
                        }
                        printer.push_token_id(rp);
                    }
                }
            }

            // [WHERE predicate]
            if let Some(where_kw) = syntax.where_keyword {
                printer.space();
                printer.push_keyword_token_id(where_kw);
                if let Some(ref where_expr) = stmt.where_predicate {
                    printer.space();
                    crate::formatter::statements::select::format_expression(printer, where_expr)?;
                }
            }

            // [T-SQL tail: WITH (options) / ON storage / FILESTREAM_ON] — preserved
            // verbatim from the source. The source cursor sits at the next
            // significant token, so a separating space is synthesized (as elsewhere
            // in this formatter) to avoid gluing the tail onto the prior clause.
            let pos = printer.get_source_position();
            if syntax.span.end > pos {
                printer.space();
                printer.push_span(Span {
                    start: pos,
                    end: syntax.span.end,
                });
            }

            return Ok(());
        }
    }

    // Fallback: whole-span emission
    printer.push_span(stmt.span);
    Ok(())
}

/// Format T-SQL `CREATE SYNONYM name FOR object` from source spans.
pub fn format_create_synonym(
    printer: &mut Printer,
    stmt: &AstCreateSynonym,
) -> Result<(), FormatterError> {
    printer.push_keyword_span(stmt.create_span);
    printer.space();
    printer.push_keyword_span(stmt.synonym_keyword_span);
    printer.space();
    printer.push_span(stmt.name_span);
    printer.space();
    printer.push_keyword_span(stmt.for_span);
    printer.space();
    printer.push_span(stmt.target_span);
    Ok(())
}

/// Format COMMENT ON statement.
pub fn format_comment_on(printer: &mut Printer, stmt: &AstCommentOn) -> Result<(), FormatterError> {
    if let Some(syntax_id) = stmt.syntax_id {
        if let Some(syntax_arena) = printer.syntax_arena() {
            let syntax = *syntax_arena.get_comment_on_stmt(syntax_id);
            let _ = syntax_arena;

            // COMMENT
            printer.push_keyword_token_id(syntax.comment_keyword);
            printer.space();

            // ON
            printer.push_keyword_token_id(syntax.on_keyword);
            printer.space();

            // Object kind (TABLE, COLUMN, INDEX, etc.)
            printer.push_span(syntax.object_kind_span);
            printer.space();

            // Object name
            printer.push_span(syntax.object_name_span);

            // Optional function/procedure signature: (arg_types)
            if let Some(lp) = syntax.signature_l_paren {
                printer.push_token_id(lp);
                if let Some(rp) = syntax.signature_r_paren {
                    let rp_tok = printer.get_token_by_id(rp);
                    let rp_start = rp_tok.map(|t| t.span.start).unwrap_or(syntax.span.end);
                    let pos = printer.get_source_position();
                    if rp_start > pos {
                        printer.push_span(Span {
                            start: pos,
                            end: rp_start,
                        });
                    }
                    printer.push_token_id(rp);
                }
            }
            printer.space();

            // IS
            printer.push_keyword_token_id(syntax.is_keyword);
            printer.space();

            // Comment value (string literal or NULL)
            printer.push_span(syntax.comment_value_span);

            return Ok(());
        }
    }

    printer.push_span(stmt.span);
    Ok(())
}

/// Format DO anonymous block.
pub fn format_do_block(printer: &mut Printer, stmt: &AstDoBlock) -> Result<(), FormatterError> {
    if let Some(syntax_id) = stmt.syntax_id {
        if let Some(syntax_arena) = printer.syntax_arena() {
            let syntax = *syntax_arena.get_do_block_stmt(syntax_id);
            let _ = syntax_arena;

            // The body_span covers the full $$...$$, including content.
            // body_token points to the opening $$ identifier.
            let body_start = stmt.body_span.start;
            let body_end = stmt.body_span.end;

            // DO
            printer.push_keyword_token_id(syntax.do_keyword);

            // [LANGUAGE lang] (before body)
            if let Some(lang_kw) = syntax.language_keyword {
                let lang_kw_pos = printer
                    .get_token_by_id(lang_kw)
                    .map(|t| t.span.start)
                    .unwrap_or(0);

                if lang_kw_pos < body_start {
                    printer.space();
                    printer.push_keyword_token_id(lang_kw);
                    if let Some(name_span) = syntax.language_name_span {
                        printer.space();
                        printer.push_span(name_span);
                    }
                }
            }

            // Body (full dollar-quoted block as a span)
            printer.space();
            printer.push_span(stmt.body_span);

            // [LANGUAGE lang] (after body)
            if let Some(lang_kw) = syntax.language_keyword {
                let lang_kw_pos = printer
                    .get_token_by_id(lang_kw)
                    .map(|t| t.span.start)
                    .unwrap_or(0);

                if lang_kw_pos > body_end {
                    printer.space();
                    printer.push_keyword_token_id(lang_kw);
                    if let Some(name_span) = syntax.language_name_span {
                        printer.space();
                        printer.push_span(name_span);
                    }
                }
            }

            return Ok(());
        }
    }

    printer.push_span(stmt.span);
    Ok(())
}

/// Format VACUUM statement.
pub fn format_vacuum(printer: &mut Printer, stmt: &AstVacuum) -> Result<(), FormatterError> {
    if let Some(syntax_id) = stmt.syntax_id {
        if let Some(syntax_arena) = printer.syntax_arena() {
            let syntax = *syntax_arena.get_vacuum_stmt(syntax_id);
            let _ = syntax_arena;

            // VACUUM
            printer.push_token_id(syntax.vacuum_keyword);

            // Determine if FULL is in PG position (before table) or DBX position (after table)
            let full_is_before_table = if let (Some(full_kw), Some(table_span)) =
                (syntax.full_keyword, syntax.table_name_span)
            {
                // Check if the FULL token appears before the table name in source
                let full_tok = printer.get_token_by_id(full_kw);
                full_tok
                    .map(|t| t.span.start < table_span.start)
                    .unwrap_or(true)
            } else {
                true // No table → PG form, emit FULL early
            };

            // Parenthesized options form: VACUUM (VERBOSE, ANALYZE)
            if let Some(lp) = syntax.options_l_paren {
                printer.space();
                printer.push_token_id(lp);
                if let Some(rp) = syntax.options_r_paren {
                    let rp_tok = printer.get_token_by_id(rp);
                    let rp_start = rp_tok.map(|t| t.span.start).unwrap_or(syntax.span.end);
                    let pos = printer.get_source_position();
                    if rp_start > pos {
                        printer.push_span(Span {
                            start: pos,
                            end: rp_start,
                        });
                    }
                    printer.push_token_id(rp);
                }
            } else {
                // Non-parenthesized form: VACUUM [FULL] [FREEZE] [VERBOSE] [ANALYZE]
                // Only emit FULL here if it appears BEFORE the table (PG style)
                if let Some(full_kw) = syntax.full_keyword {
                    if full_is_before_table {
                        printer.space();
                        printer.push_keyword_token_id(full_kw);
                    }
                }
                if let Some(freeze_kw) = syntax.freeze_keyword {
                    printer.space();
                    printer.push_token_id(freeze_kw);
                }
                if let Some(verbose_kw) = syntax.verbose_keyword {
                    printer.space();
                    printer.push_token_id(verbose_kw);
                }
                if let Some(analyze_kw) = syntax.analyze_keyword {
                    printer.space();
                    printer.push_token_id(analyze_kw);
                }
                // Redshift modes: DELETE ONLY | SORT ONLY | REINDEX | RECLUSTER
                // (mutually exclusive; emitted in source order before the table).
                if let Some(delete_kw) = syntax.delete_keyword {
                    printer.space();
                    printer.push_token_id(delete_kw);
                }
                if let Some(only_kw) = syntax.delete_only_keyword {
                    printer.space();
                    printer.push_token_id(only_kw);
                }
                if let Some(sort_kw) = syntax.sort_keyword {
                    printer.space();
                    printer.push_token_id(sort_kw);
                }
                if let Some(only_kw) = syntax.sort_only_keyword {
                    printer.space();
                    printer.push_token_id(only_kw);
                }
                if let Some(reindex_kw) = syntax.reindex_keyword {
                    printer.space();
                    printer.push_token_id(reindex_kw);
                }
                if let Some(recluster_kw) = syntax.recluster_keyword {
                    printer.space();
                    printer.push_token_id(recluster_kw);
                }
            }

            // [table]
            if let Some(table_span) = syntax.table_name_span {
                printer.space();
                printer.push_span(table_span);
            }

            // [(column, ...)]
            if let Some(lp) = syntax.columns_l_paren {
                printer.space();
                printer.push_token_id(lp);
                if let Some(rp) = syntax.columns_r_paren {
                    let rp_tok = printer.get_token_by_id(rp);
                    let rp_start = rp_tok.map(|t| t.span.start).unwrap_or(syntax.span.end);
                    let pos = printer.get_source_position();
                    if rp_start > pos {
                        printer.push_span(Span {
                            start: pos,
                            end: rp_start,
                        });
                    }
                    printer.push_token_id(rp);
                }
            }

            // --- Databricks-specific post-table modifiers ---

            // RETAIN num HOURS
            if let Some(retain_kw) = syntax.retain_keyword {
                printer.space();
                printer.push_token_id(retain_kw);
                if let Some(val_tok) = syntax.retain_value_token {
                    printer.space();
                    printer.push_token_id(val_tok);
                }
                if let Some(hours_kw) = syntax.hours_keyword {
                    printer.space();
                    printer.push_token_id(hours_kw);
                }
            }

            // FULL after table (Databricks Iceberg — only emit here if it comes AFTER the table)
            if let Some(full_kw) = syntax.full_keyword {
                if !full_is_before_table {
                    printer.space();
                    printer.push_keyword_token_id(full_kw);
                }
            }

            // LITE (Databricks Iceberg mode)
            if let Some(lite_kw) = syntax.lite_keyword {
                printer.space();
                printer.push_token_id(lite_kw);
            }

            // DRY RUN
            if let Some(dry_kw) = syntax.dry_keyword {
                printer.space();
                printer.push_token_id(dry_kw);
                if let Some(run_kw) = syntax.run_keyword {
                    printer.space();
                    printer.push_token_id(run_kw);
                }
            }

            return Ok(());
        }
    }

    printer.push_span(stmt.span);
    Ok(())
}

/// Format ANALYZE statement.
pub fn format_analyze(printer: &mut Printer, stmt: &AstAnalyzeStmt) -> Result<(), FormatterError> {
    if let Some(syntax_id) = stmt.syntax_id {
        if let Some(syntax_arena) = printer.syntax_arena() {
            let syntax = *syntax_arena.get_analyze_stmt(syntax_id);
            let _ = syntax_arena;

            // ANALYZE
            printer.push_token_id(syntax.analyze_keyword);

            // [VERBOSE]
            if let Some(verbose_kw) = syntax.verbose_keyword {
                printer.space();
                printer.push_token_id(verbose_kw);
            }

            // [COMPRESSION] (Redshift)
            if let Some(compression_kw) = syntax.compression_keyword {
                printer.space();
                printer.push_token_id(compression_kw);
            }

            // [table]
            if let Some(table_span) = syntax.table_name_span {
                printer.space();
                printer.push_span(table_span);
            }

            // [(column, ...)]
            if let Some(lp) = syntax.columns_l_paren {
                printer.space();
                printer.push_token_id(lp);
                if let Some(rp) = syntax.columns_r_paren {
                    let rp_tok = printer.get_token_by_id(rp);
                    let rp_start = rp_tok.map(|t| t.span.start).unwrap_or(syntax.span.end);
                    let pos = printer.get_source_position();
                    if rp_start > pos {
                        printer.push_span(Span {
                            start: pos,
                            end: rp_start,
                        });
                    }
                    printer.push_token_id(rp);
                }
            }

            return Ok(());
        }
    }

    printer.push_span(stmt.span);
    Ok(())
}

/// Format CREATE TYPE statement.
pub fn format_create_type(
    printer: &mut Printer,
    stmt: &AstCreateType,
) -> Result<(), FormatterError> {
    if let Some(syntax_id) = stmt.syntax_id {
        if let Some(syntax_arena) = printer.syntax_arena() {
            let syntax = *syntax_arena.get_create_type_stmt(syntax_id);
            let _ = syntax_arena;

            // Extract token spans upfront to avoid borrow conflicts
            let create_tok_span = printer
                .get_token_by_id(syntax.create_keyword)
                .map(|t| t.span);
            let type_tok_span = printer.get_token_by_id(syntax.type_keyword).map(|t| t.span);

            // CREATE
            printer.push_keyword_token_id(syntax.create_keyword);

            // Gap between CREATE and TYPE keyword (covers OR REPLACE if present)
            let create_end = create_tok_span.map(|s| s.end).unwrap_or(syntax.span.start);
            let type_start = type_tok_span.map(|s| s.start).unwrap_or(create_end);
            if type_start > create_end {
                printer.push_span(Span {
                    start: create_end,
                    end: type_start,
                });
            } else {
                printer.space();
            }

            // TYPE
            printer.push_keyword_token_id(syntax.type_keyword);

            // Gap between TYPE keyword and type name (covers IF NOT EXISTS if present)
            let type_end = type_tok_span.map(|s| s.end).unwrap_or(syntax.span.start);
            if syntax.type_name_span.start > type_end {
                printer.push_span(Span {
                    start: type_end,
                    end: syntax.type_name_span.start,
                });
            } else {
                printer.space();
            }

            // Type name
            printer.push_span(syntax.type_name_span);

            // [AS ...]
            if let Some(as_kw) = syntax.as_keyword {
                printer.space();
                printer.push_keyword_token_id(as_kw);

                // Sub-keyword (ENUM or RANGE, if present)
                if let Some(sub_kw) = syntax.sub_keyword {
                    printer.space();
                    printer.push_token_id(sub_kw);
                }

                // Data type identifier (Snowflake: NUMBER, VARCHAR, OBJECT, etc.)
                if let Some(dt_span) = syntax.data_type_span {
                    printer.space();
                    // If there are also body parens, emit just the type name part
                    if let Some(lp) = syntax.body_l_paren {
                        let lp_tok = printer.get_token_by_id(lp);
                        let lp_start = lp_tok.map(|t| t.span.start).unwrap_or(dt_span.end);
                        printer.push_span(Span {
                            start: dt_span.start,
                            end: lp_start,
                        });
                    } else {
                        printer.push_span(dt_span);
                    }
                }

                // Parenthesized body
                if let Some(lp) = syntax.body_l_paren {
                    if syntax.data_type_span.is_none() {
                        printer.space();
                    }
                    printer.push_token_id(lp);
                    // Inner content between parens
                    if let Some(rp) = syntax.body_r_paren {
                        let rp_tok = printer.get_token_by_id(rp);
                        let rp_start = rp_tok.map(|t| t.span.start).unwrap_or(syntax.span.end);
                        let pos = printer.get_source_position();
                        if rp_start > pos {
                            printer.push_span(Span {
                                start: pos,
                                end: rp_start,
                            });
                        }
                        printer.push_token_id(rp);
                    }
                }
            }

            // Trailing clause (COMMENT = '...')
            if let Some(trailing) = syntax.trailing_span {
                printer.space();
                printer.push_span(trailing);
            }

            return Ok(());
        }
    }

    printer.push_span(stmt.span);
    Ok(())
}

/// Format ALTER TYPE statement.
pub fn format_alter_type(printer: &mut Printer, stmt: &AstAlterType) -> Result<(), FormatterError> {
    if let Some(syntax_id) = stmt.syntax_id {
        if let Some(syntax_arena) = printer.syntax_arena() {
            let syntax = *syntax_arena.get_alter_type_stmt(syntax_id);
            let _ = syntax_arena;

            // Extract token spans upfront to avoid borrow conflicts
            let type_tok_span = printer.get_token_by_id(syntax.type_keyword).map(|t| t.span);

            // ALTER
            printer.push_keyword_token_id(syntax.alter_keyword);
            printer.space();

            // TYPE
            printer.push_keyword_token_id(syntax.type_keyword);

            // Gap between TYPE keyword and type name (covers IF EXISTS if present)
            let type_end = type_tok_span.map(|s| s.end).unwrap_or(syntax.span.start);
            if syntax.type_name_span.start > type_end {
                printer.push_span(Span {
                    start: type_end,
                    end: syntax.type_name_span.start,
                });
            } else {
                printer.space();
            }

            // Type name
            printer.push_span(syntax.type_name_span);

            // Action keyword (ADD, RENAME, SET, OWNER)
            if let Some(action_kw) = syntax.action_keyword {
                printer.space();
                printer.push_token_id(action_kw);
            }

            // Secondary action keyword (VALUE, TO, SCHEMA, ATTRIBUTE)
            if let Some(action_kw2) = syntax.action_keyword2 {
                printer.space();
                printer.push_token_id(action_kw2);
            }

            // IF NOT EXISTS (for ADD VALUE)
            if let Some(if_kw) = syntax.action_if_keyword {
                printer.space();
                printer.push_keyword_token_id(if_kw);
            }
            if let Some(not_kw) = syntax.action_not_keyword {
                printer.space();
                printer.push_keyword_token_id(not_kw);
            }
            if let Some(exists_kw) = syntax.action_exists_keyword {
                printer.space();
                printer.push_keyword_token_id(exists_kw);
            }

            // Primary value span
            if let Some(val_span) = syntax.action_value_span {
                printer.space();
                printer.push_span(val_span);
            }

            // BEFORE/AFTER keyword + value (for ADD VALUE positioning)
            if let Some(pos_kw) = syntax.action_position_keyword {
                printer.space();
                printer.push_token_id(pos_kw);
            }
            if let Some(pos_val) = syntax.action_position_value_span {
                printer.space();
                printer.push_span(pos_val);
            }

            // TO keyword (for RENAME TO, OWNER TO, RENAME VALUE ... TO)
            if let Some(to_kw) = syntax.action_to_keyword {
                printer.space();
                printer.push_keyword_token_id(to_kw);
            }

            // Target name/value
            if let Some(target_span) = syntax.action_target_span {
                printer.space();
                printer.push_span(target_span);
            }

            // Trailing content (ADD ATTRIBUTE: data type/COLLATE/CASCADE; SET COMMENT: = 'value')
            if let Some(extra_span) = syntax.action_extra_span {
                printer.push_span(extra_span);
            }

            return Ok(());
        }
    }

    printer.push_span(stmt.span);
    Ok(())
}

/// Format CREATE EXTENSION statement.
pub fn format_create_extension(
    printer: &mut Printer,
    stmt: &AstCreateExtension,
) -> Result<(), FormatterError> {
    if let Some(syntax_id) = stmt.syntax_id {
        if let Some(syntax_arena) = printer.syntax_arena() {
            let syntax = *syntax_arena.get_create_extension_stmt(syntax_id);
            let _ = syntax_arena;

            // CREATE
            printer.push_keyword_token_id(syntax.create_keyword);
            printer.space();

            // EXTENSION
            printer.push_token_id(syntax.extension_keyword);

            // [IF NOT EXISTS]
            if let Some(if_kw) = syntax.if_keyword {
                printer.space();
                printer.push_keyword_token_id(if_kw);
                if let Some(not_kw) = syntax.not_keyword {
                    printer.space();
                    printer.push_keyword_token_id(not_kw);
                }
                if let Some(exists_kw) = syntax.exists_keyword {
                    printer.space();
                    printer.push_keyword_token_id(exists_kw);
                }
            }

            // Extension name
            printer.space();
            printer.push_span(syntax.extension_name_span);

            // [WITH]
            if let Some(with_kw) = syntax.with_keyword {
                printer.space();
                printer.push_keyword_token_id(with_kw);
            }

            // [SCHEMA schema]
            if let Some(schema_kw) = syntax.schema_keyword {
                printer.space();
                printer.push_token_id(schema_kw);
                if let Some(schema_span) = syntax.schema_name_span {
                    printer.space();
                    printer.push_span(schema_span);
                }
            }

            // [VERSION version]
            if let Some(version_kw) = syntax.version_keyword {
                printer.space();
                printer.push_token_id(version_kw);
                if let Some(version_span) = syntax.version_span {
                    printer.space();
                    printer.push_span(version_span);
                }
            }

            // [CASCADE]
            if let Some(cascade_kw) = syntax.cascade_keyword {
                printer.space();
                printer.push_token_id(cascade_kw);
            }

            return Ok(());
        }
    }

    printer.push_span(stmt.span);
    Ok(())
}

/// Format a PostgreSQL CREATE SEQUENCE statement
pub fn format_create_sequence(
    printer: &mut Printer,
    stmt: &AstCreateSequence,
) -> Result<(), FormatterError> {
    if let Some(syntax_id) = stmt.syntax_id {
        if let Some(syntax_arena) = printer.syntax_arena() {
            let syntax = syntax_arena.get_create_sequence_stmt(syntax_id);
            let create_keyword = syntax.create_keyword;
            let or_keyword = syntax.or_keyword;
            let replace_keyword = syntax.replace_keyword;
            let temp_keyword = syntax.temp_keyword;
            let unlogged_keyword = syntax.unlogged_keyword;
            let sequence_keyword = syntax.sequence_keyword;
            let if_keyword = syntax.if_keyword;
            let not_keyword = syntax.not_keyword;
            let exists_keyword = syntax.exists_keyword;
            let name_span = syntax.name_span;
            let options_span = syntax.options_span;
            let _ = syntax_arena;

            // CREATE
            printer.push_keyword_token_id(create_keyword);

            // [OR REPLACE]
            if let Some(or_kw) = or_keyword {
                printer.space();
                printer.push_keyword_token_id(or_kw);
                if let Some(replace_kw) = replace_keyword {
                    printer.space();
                    printer.push_keyword_token_id(replace_kw);
                }
            }

            // [TEMPORARY | TEMP]
            if let Some(kw) = temp_keyword {
                printer.space();
                printer.push_keyword_token_id(kw);
            }

            // [UNLOGGED]
            if let Some(kw) = unlogged_keyword {
                printer.space();
                printer.push_token_id(kw);
            }

            // SEQUENCE
            printer.space();
            printer.push_token_id(sequence_keyword);

            // [IF NOT EXISTS]
            if let Some(if_kw) = if_keyword {
                printer.space();
                printer.push_keyword_token_id(if_kw);
                if let Some(not_kw) = not_keyword {
                    printer.space();
                    printer.push_keyword_token_id(not_kw);
                }
                if let Some(exists_kw) = exists_keyword {
                    printer.space();
                    printer.push_keyword_token_id(exists_kw);
                }
            }

            // Sequence name
            printer.space();
            printer.push_span(name_span);

            // Options (AS, INCREMENT, MINVALUE, etc.)
            if let Some(opts) = options_span {
                printer.space();
                printer.push_span(opts);
            }

            return Ok(());
        }
    }

    printer.push_span(stmt.span);
    Ok(())
}

/// Format a PostgreSQL ALTER SEQUENCE statement
pub fn format_alter_sequence(
    printer: &mut Printer,
    stmt: &AstAlterSequence,
) -> Result<(), FormatterError> {
    if let Some(syntax_id) = stmt.syntax_id {
        if let Some(syntax_arena) = printer.syntax_arena() {
            let syntax = syntax_arena.get_alter_sequence_stmt(syntax_id);
            let alter_keyword = syntax.alter_keyword;
            let sequence_keyword = syntax.sequence_keyword;
            let if_keyword = syntax.if_keyword;
            let exists_keyword = syntax.exists_keyword;
            let name_span = syntax.name_span;
            let options_span = syntax.options_span;
            let _ = syntax_arena;

            // ALTER
            printer.push_keyword_token_id(alter_keyword);

            // SEQUENCE
            printer.space();
            printer.push_token_id(sequence_keyword);

            // [IF EXISTS]
            if let Some(if_kw) = if_keyword {
                printer.space();
                printer.push_keyword_token_id(if_kw);
                if let Some(exists_kw) = exists_keyword {
                    printer.space();
                    printer.push_keyword_token_id(exists_kw);
                }
            }

            // Sequence name
            printer.space();
            printer.push_span(name_span);

            // Options/clauses
            if let Some(opts) = options_span {
                printer.space();
                printer.push_span(opts);
            }

            return Ok(());
        }
    }

    printer.push_span(stmt.span);
    Ok(())
}

/// Format a PostgreSQL `CREATE [OR REPLACE] [CONSTRAINT] TRIGGER` statement.
pub fn format_create_pg_trigger(
    printer: &mut Printer,
    stmt: &AstCreatePgTrigger,
) -> Result<(), FormatterError> {
    if let Some(syntax_id) = stmt.syntax_id {
        if let Some(syntax_arena) = printer.syntax_arena() {
            let syntax = syntax_arena.get_create_pg_trigger_stmt(syntax_id);
            let create_keyword = syntax.create_keyword;
            let or_keyword = syntax.or_keyword;
            let replace_keyword = syntax.replace_keyword;
            let constraint_keyword = syntax.constraint_keyword;
            let trigger_keyword = syntax.trigger_keyword;
            let on_keyword = syntax.on_keyword;
            let _ = syntax_arena;

            // CREATE
            printer.push_keyword_token_id(create_keyword);

            // [OR REPLACE]
            if let Some(or_kw) = or_keyword {
                printer.space();
                printer.push_keyword_token_id(or_kw);
                if let Some(replace_kw) = replace_keyword {
                    printer.space();
                    printer.push_keyword_token_id(replace_kw);
                }
            }

            // [CONSTRAINT]
            if let Some(c_kw) = constraint_keyword {
                printer.space();
                printer.push_keyword_token_id(c_kw);
            }

            // TRIGGER
            printer.space();
            printer.push_keyword_token_id(trigger_keyword);

            // Trigger name
            printer.space();
            printer.push_span(stmt.trigger_name);

            // Timing (BEFORE / AFTER / INSTEAD OF)
            printer.newline();
            printer.indent_up();
            printer.push_span(stmt.timing_span);

            // Events
            for (i, event) in stmt.events.iter().enumerate() {
                if i > 0 {
                    printer.space();
                    printer.push_keyword("OR");
                }
                printer.space();
                printer.push_span(event.span);
            }

            // ON table_name
            printer.space();
            printer.push_keyword_token_id(on_keyword);
            printer.space();
            printer.push_span(stmt.table_name);

            // [FROM referenced_table]
            if let Some(from_table) = stmt.from_table {
                printer.newline();
                printer.push_keyword("FROM");
                printer.space();
                printer.push_span(from_table);
            }

            // [deferrable clause]
            if let Some(def_span) = stmt.deferrable_span {
                printer.newline();
                printer.push_span(def_span);
            }

            // [REFERENCING entries]
            if !stmt.referencing.is_empty() {
                printer.newline();
                printer.push_keyword("REFERENCING");
                for entry in &stmt.referencing {
                    printer.space();
                    printer.push_span(entry.span);
                }
            }

            // [FOR EACH ROW/STATEMENT]
            if let Some(for_each_span) = stmt.for_each_span {
                printer.newline();
                printer.push_span(for_each_span);
            }

            // [WHEN (condition)]
            if let Some(when_span) = stmt.when_condition {
                printer.newline();
                printer.push_span(when_span);
            }

            // EXECUTE FUNCTION/PROCEDURE func(args)
            printer.newline();
            printer.push_span(stmt.execute_span);
            printer.space();
            printer.push_span(stmt.function_name);
            printer.push_span(stmt.function_call_parens);

            printer.indent_down();
            return Ok(());
        }
    }

    printer.push_span(stmt.span);
    Ok(())
}

/// Format a PostgreSQL ALTER TRIGGER statement.
pub fn format_alter_pg_trigger(
    printer: &mut Printer,
    stmt: &AstAlterPgTrigger,
) -> Result<(), FormatterError> {
    if let Some(syntax_id) = stmt.syntax_id {
        if let Some(syntax_arena) = printer.syntax_arena() {
            let syntax = syntax_arena.get_alter_pg_trigger_stmt(syntax_id);
            let alter_keyword = syntax.alter_keyword;
            let trigger_keyword = syntax.trigger_keyword;
            let on_keyword = syntax.on_keyword;
            let _ = syntax_arena;

            // ALTER
            printer.push_keyword_token_id(alter_keyword);

            // TRIGGER
            printer.space();
            printer.push_keyword_token_id(trigger_keyword);

            // Trigger name
            printer.space();
            printer.push_span(stmt.trigger_name);

            // ON table_name
            printer.space();
            printer.push_keyword_token_id(on_keyword);
            printer.space();
            printer.push_span(stmt.table_name);

            // Action
            printer.space();
            match &stmt.action {
                PgAlterTriggerAction::RenameTo { span, .. } => {
                    printer.push_span(*span);
                }
                PgAlterTriggerAction::DependsOnExtension { span, .. } => {
                    printer.push_span(*span);
                }
            }

            return Ok(());
        }
    }

    printer.push_span(stmt.span);
    Ok(())
}

/// Format a PostgreSQL DROP TRIGGER statement.
pub fn format_drop_pg_trigger(
    printer: &mut Printer,
    stmt: &AstDropPgTrigger,
) -> Result<(), FormatterError> {
    if let Some(syntax_id) = stmt.syntax_id {
        if let Some(syntax_arena) = printer.syntax_arena() {
            let syntax = syntax_arena.get_drop_pg_trigger_stmt(syntax_id);
            let drop_keyword = syntax.drop_keyword;
            let trigger_keyword = syntax.trigger_keyword;
            let if_keyword = syntax.if_keyword;
            let exists_keyword = syntax.exists_keyword;
            let on_keyword = syntax.on_keyword;
            let _ = syntax_arena;

            // DROP
            printer.push_keyword_token_id(drop_keyword);

            // TRIGGER
            printer.space();
            printer.push_keyword_token_id(trigger_keyword);

            // [IF EXISTS]
            if let Some(if_kw) = if_keyword {
                printer.space();
                printer.push_keyword_token_id(if_kw);
                if let Some(exists_kw) = exists_keyword {
                    printer.space();
                    printer.push_keyword_token_id(exists_kw);
                }
            }

            // Trigger name
            printer.space();
            printer.push_span(stmt.trigger_name);

            // ON table_name
            printer.space();
            printer.push_keyword_token_id(on_keyword);
            printer.space();
            printer.push_span(stmt.table_name);

            // [CASCADE | RESTRICT]
            if let Some(cr) = &stmt.cascade_restrict {
                printer.space();
                match cr {
                    PgCascadeRestrict::Cascade => printer.push_keyword("CASCADE"),
                    PgCascadeRestrict::Restrict => printer.push_keyword("RESTRICT"),
                }
            }

            return Ok(());
        }
    }

    printer.push_span(stmt.span);
    Ok(())
}
