// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Formatters for PostgreSQL ALTER INDEX and REINDEX statements.
//!
//! - ALTER INDEX: CST-based keyword emission + span-based for names/actions
//! - REINDEX: CST-based for REINDEX keyword + span-based for options/target/name

use crate::ast::types::{AlterIndexAction, AlterIndexSubAction, AstAlterIndex, AstReindex};
use crate::formatter::printer::Printer;
use crate::formatter::FormatterError;

/// Format an ALTER INDEX statement.
pub fn format_alter_index(
    printer: &mut Printer,
    stmt: &AstAlterIndex,
) -> Result<(), FormatterError> {
    if let Some(syntax_id) = stmt.syntax_id {
        if let Some(syntax_arena) = printer.syntax_arena() {
            let syntax = *syntax_arena.get_alter_index_stmt(syntax_id);
            let _ = syntax_arena;

            // ALTER
            printer.push_keyword_token_id(syntax.alter_keyword);

            // INDEX
            printer.space();
            printer.push_keyword_token_id(syntax.index_keyword);

            match &stmt.action {
                AlterIndexAction::Named {
                    if_span,
                    exists_span,
                    name,
                    sub_action,
                } => {
                    // [IF EXISTS]
                    if let (Some(if_kw), Some(exists_kw)) = (*if_span, *exists_span) {
                        printer.space();
                        printer.push_keyword_span(if_kw);
                        printer.space();
                        printer.push_keyword_span(exists_kw);
                    }

                    // name
                    printer.space();
                    printer.push_span(*name);

                    // sub-action
                    format_alter_index_sub_action(printer, sub_action)?;
                }
                AlterIndexAction::AllInTablespace {
                    all_span,
                    in_span,
                    tablespace_span,
                    tablespace_name,
                    owned_span,
                    by_span,
                    owned_by_roles,
                    set_span,
                    set_tablespace_span,
                    new_tablespace_name,
                    nowait_span,
                    ..
                } => {
                    // ALL IN TABLESPACE name
                    printer.space();
                    printer.push_keyword_span(*all_span);
                    printer.space();
                    printer.push_keyword_span(*in_span);
                    printer.space();
                    printer.push_keyword_span(*tablespace_span);
                    printer.space();
                    printer.push_span(*tablespace_name);

                    // [OWNED BY role [, ...]]
                    if let (Some(owned_kw), Some(by_kw)) = (*owned_span, *by_span) {
                        printer.space();
                        printer.push_keyword_span(owned_kw);
                        printer.space();
                        printer.push_keyword_span(by_kw);
                        for (i, role) in owned_by_roles.iter().enumerate() {
                            if i > 0 {
                                printer.push(",");
                                printer.space();
                            } else {
                                printer.space();
                            }
                            printer.push_span(*role);
                        }
                    }

                    // SET TABLESPACE new_ts
                    printer.space();
                    printer.push_keyword_span(*set_span);
                    printer.space();
                    printer.push_keyword_span(*set_tablespace_span);
                    printer.space();
                    printer.push_span(*new_tablespace_name);

                    // [NOWAIT]
                    if let Some(nowait_kw) = *nowait_span {
                        printer.space();
                        printer.push_keyword_span(nowait_kw);
                    }
                }
                AlterIndexAction::OnObject {
                    name,
                    all_span,
                    on_span,
                    object,
                    maintenance_span,
                    tail_span,
                    ..
                } => {
                    // { name | ALL }
                    printer.space();
                    if let Some(name_span) = *name {
                        printer.push_span(name_span);
                    } else if let Some(all_kw) = *all_span {
                        printer.push_keyword_span(all_kw);
                    }

                    // ON object
                    printer.space();
                    printer.push_keyword_span(*on_span);
                    printer.space();
                    printer.push_span(*object);

                    // REBUILD | REORGANIZE | DISABLE | SET
                    printer.space();
                    printer.push_keyword_span(*maintenance_span);

                    // [trailing options] — preserved verbatim, with a separating
                    // space (the source cursor sits at the next significant token).
                    if let Some(tail) = *tail_span {
                        printer.space();
                        printer.push_span(tail);
                    }
                }
            }

            return Ok(());
        }
    }

    // Fallback: emit the whole span verbatim
    printer.push_span(stmt.span);
    Ok(())
}

/// Format the sub-action part of a named ALTER INDEX.
fn format_alter_index_sub_action(
    printer: &mut Printer,
    sub_action: &AlterIndexSubAction,
) -> Result<(), FormatterError> {
    match sub_action {
        AlterIndexSubAction::RenameTo {
            rename_span,
            to_span,
            new_name,
        } => {
            printer.space();
            printer.push_keyword_span(*rename_span);
            printer.space();
            printer.push_keyword_span(*to_span);
            printer.space();
            printer.push_span(*new_name);
        }
        AlterIndexSubAction::SetTablespace {
            set_span,
            tablespace_span,
            tablespace_name,
        } => {
            printer.space();
            printer.push_keyword_span(*set_span);
            printer.space();
            printer.push_keyword_span(*tablespace_span);
            printer.space();
            printer.push_span(*tablespace_name);
        }
        AlterIndexSubAction::AttachPartition {
            attach_span,
            partition_span,
            index_name,
        } => {
            printer.space();
            printer.push_keyword_span(*attach_span);
            if let Some(partition_kw) = *partition_span {
                printer.space();
                printer.push_keyword_span(partition_kw);
            }
            printer.space();
            printer.push_span(*index_name);
        }
        AlterIndexSubAction::DependsOnExtension {
            no_span,
            depends_span,
            on_span,
            extension_span,
            extension_name,
        } => {
            if let Some(no_kw) = *no_span {
                printer.space();
                printer.push_keyword_span(no_kw);
            }
            printer.space();
            printer.push_keyword_span(*depends_span);
            printer.space();
            printer.push_keyword_span(*on_span);
            printer.space();
            printer.push_keyword_span(*extension_span);
            printer.space();
            printer.push_span(*extension_name);
        }
        AlterIndexSubAction::SetParams {
            set_span,
            params_span,
        } => {
            printer.space();
            printer.push_keyword_span(*set_span);
            printer.space();
            printer.push_span(*params_span);
        }
        AlterIndexSubAction::ResetParams {
            reset_span,
            params_span,
        } => {
            printer.space();
            printer.push_keyword_span(*reset_span);
            printer.space();
            printer.push_span(*params_span);
        }
        AlterIndexSubAction::AlterColumnStatistics {
            alter_span,
            column_span,
            column_number,
            set_span,
            statistics_span,
            statistics_value,
        } => {
            printer.space();
            printer.push_keyword_span(*alter_span);
            if let Some(column_kw) = *column_span {
                printer.space();
                printer.push_keyword_span(column_kw);
            }
            printer.space();
            printer.push_span(*column_number);
            printer.space();
            printer.push_keyword_span(*set_span);
            printer.space();
            printer.push_keyword_span(*statistics_span);
            printer.space();
            printer.push_span(*statistics_value);
        }
    }
    Ok(())
}

/// Format a REINDEX statement.
pub fn format_reindex(printer: &mut Printer, stmt: &AstReindex) -> Result<(), FormatterError> {
    if let Some(syntax_id) = stmt.syntax_id {
        if let Some(syntax_arena) = printer.syntax_arena() {
            let syntax = *syntax_arena.get_reindex_stmt(syntax_id);
            let _ = syntax_arena;

            // REINDEX
            printer.push_keyword_token_id(syntax.reindex_keyword);

            // [( options )]
            if let Some(opts_span) = stmt.options_span {
                printer.space();
                printer.push_span(opts_span);
            }

            // target type
            printer.space();
            printer.push_span(stmt.target_type_span);

            // [CONCURRENTLY]
            if let Some(concurrently_span) = stmt.concurrently_span {
                printer.space();
                printer.push_keyword_span(concurrently_span);
            }

            // [name]
            if let Some(name_span) = stmt.name {
                printer.space();
                printer.push_span(name_span);
            }

            return Ok(());
        }
    }

    // Fallback: emit the whole span verbatim
    printer.push_span(stmt.span);
    Ok(())
}
