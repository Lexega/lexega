// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Formatters for PostgreSQL DOMAIN statements.
//!
//! - CREATE DOMAIN: CST-based keyword emission + expression formatting for DEFAULT/CHECK
//! - ALTER DOMAIN: CST-based for keywords + expression formatting for SET DEFAULT/CHECK
//! - DROP DOMAIN: CST-based for keywords, span-based for names

use crate::ast::types::{
    AlterDomainAction, AstAlterDomain, AstCreateDomain, AstDropDomain, DomainConstraintKind,
};
use crate::formatter::printer::Printer;
use crate::formatter::FormatterError;
use crate::lexer::Span;

/// Format a CREATE DOMAIN statement.
pub fn format_create_domain(
    printer: &mut Printer,
    stmt: &AstCreateDomain,
) -> Result<(), FormatterError> {
    if let Some(syntax_id) = stmt.syntax_id {
        if let Some(syntax_arena) = printer.syntax_arena() {
            let syntax = *syntax_arena.get_create_domain_stmt(syntax_id);
            let _ = syntax_arena;

            // CREATE
            printer.push_keyword_token_id(syntax.create_keyword);

            // DOMAIN
            printer.space();
            printer.push_keyword_token_id(syntax.domain_keyword);

            // Domain name
            printer.space();
            printer.push_span(stmt.domain_name);

            // [AS]
            if let Some(as_kw) = syntax.as_keyword {
                printer.space();
                printer.push_keyword_token_id(as_kw);
            }

            // Data type
            printer.space();
            printer.push_span(stmt.data_type_span);

            // [COLLATE collation]
            if let Some(collate_span) = stmt.collate_span {
                printer.space();
                printer.push_span(collate_span);
            }

            // [DEFAULT expression]
            if let Some(ref default_expr) = stmt.default_expr {
                printer.space();
                // Emit DEFAULT keyword
                if let Some(default_span) = stmt.default_span {
                    // The DEFAULT keyword is the first 7 chars of default_span
                    let default_kw_span = Span {
                        start: default_span.start,
                        end: default_span.start + 7,
                    };
                    printer.push_span(default_kw_span);
                }
                printer.space();
                crate::formatter::statements::select::format_expression(printer, default_expr)?;
            }

            // Constraints
            for constraint in &stmt.constraints {
                printer.space();
                format_domain_constraint(printer, constraint)?;
            }

            return Ok(());
        }
    }

    // Fallback: whole-span emission
    printer.push_span(stmt.span);
    Ok(())
}

/// Format an ALTER DOMAIN statement.
pub fn format_alter_domain(
    printer: &mut Printer,
    stmt: &AstAlterDomain,
) -> Result<(), FormatterError> {
    if let Some(syntax_id) = stmt.syntax_id {
        if let Some(syntax_arena) = printer.syntax_arena() {
            let syntax = *syntax_arena.get_alter_domain_stmt(syntax_id);
            let _ = syntax_arena;

            // ALTER
            printer.push_keyword_token_id(syntax.alter_keyword);

            // DOMAIN
            printer.space();
            printer.push_keyword_token_id(syntax.domain_keyword);

            // Domain name
            printer.space();
            printer.push_span(stmt.domain_name);

            // Action
            printer.space();
            format_alter_domain_action(printer, &stmt.action)?;

            return Ok(());
        }
    }

    // Fallback: whole-span emission
    printer.push_span(stmt.span);
    Ok(())
}

/// Format a DROP DOMAIN statement.
pub fn format_drop_domain(
    printer: &mut Printer,
    stmt: &AstDropDomain,
) -> Result<(), FormatterError> {
    if let Some(syntax_id) = stmt.syntax_id {
        if let Some(syntax_arena) = printer.syntax_arena() {
            let syntax = *syntax_arena.get_drop_domain_stmt(syntax_id);
            let _ = syntax_arena;

            // DROP
            printer.push_keyword_token_id(syntax.drop_keyword);

            // DOMAIN
            printer.space();
            printer.push_keyword_token_id(syntax.domain_keyword);

            // [IF EXISTS]
            if let Some(if_kw) = syntax.if_keyword {
                printer.space();
                printer.push_keyword_token_id(if_kw);
                if let Some(exists_kw) = syntax.exists_keyword {
                    printer.space();
                    printer.push_keyword_token_id(exists_kw);
                }
            }

            // Domain names (comma-separated)
            for (i, name_span) in stmt.domain_names.iter().enumerate() {
                if i > 0 {
                    printer.push_char(',');
                }
                printer.space();
                printer.push_span(*name_span);
            }

            // [CASCADE | RESTRICT]
            if let Some(ref cr) = stmt.cascade_restrict {
                printer.space();
                match cr {
                    crate::ast::types::PgCascadeRestrict::Cascade => {
                        printer.push_keyword("CASCADE");
                    }
                    crate::ast::types::PgCascadeRestrict::Restrict => {
                        printer.push_keyword("RESTRICT");
                    }
                }
            }

            return Ok(());
        }
    }

    // Fallback: whole-span emission
    printer.push_span(stmt.span);
    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Format a single domain constraint: [CONSTRAINT name] { NOT NULL | NULL | CHECK (expr) }
fn format_domain_constraint(
    printer: &mut Printer,
    constraint: &crate::ast::types::DomainConstraint,
) -> Result<(), FormatterError> {
    // [CONSTRAINT name]
    if let Some(name_span) = constraint.constraint_name {
        printer.push_keyword("CONSTRAINT");
        printer.space();
        printer.push_span(name_span);
        printer.space();
    }

    match &constraint.kind {
        DomainConstraintKind::NotNull { span } => {
            printer.push_span(*span);
        }
        DomainConstraintKind::Null { span } => {
            printer.push_span(*span);
        }
        DomainConstraintKind::Check {
            check_span,
            expression,
        } => {
            // CHECK keyword
            let check_kw_span = Span {
                start: check_span.start,
                end: check_span.start + 5, // "CHECK"
            };
            printer.push_span(check_kw_span);
            // (
            printer.push_char('(');
            // Expression
            crate::formatter::statements::select::format_expression(printer, expression)?;
            // )
            printer.push_char(')');
        }
    }

    Ok(())
}

/// Format ALTER DOMAIN action
fn format_alter_domain_action(
    printer: &mut Printer,
    action: &AlterDomainAction,
) -> Result<(), FormatterError> {
    match action {
        AlterDomainAction::SetDefault { expression, .. } => {
            printer.push_keyword("SET");
            printer.space();
            printer.push_keyword("DEFAULT");
            printer.space();
            crate::formatter::statements::select::format_expression(printer, expression)?;
        }
        AlterDomainAction::DropDefault { .. } => {
            printer.push_keyword("DROP");
            printer.space();
            printer.push_keyword("DEFAULT");
        }
        AlterDomainAction::SetNotNull { .. } => {
            printer.push_keyword("SET");
            printer.space();
            printer.push_keyword("NOT");
            printer.space();
            printer.push_keyword("NULL");
        }
        AlterDomainAction::DropNotNull { .. } => {
            printer.push_keyword("DROP");
            printer.space();
            printer.push_keyword("NOT");
            printer.space();
            printer.push_keyword("NULL");
        }
        AlterDomainAction::AddConstraint {
            constraint,
            not_valid,
            ..
        } => {
            printer.push_keyword("ADD");
            printer.space();
            format_domain_constraint(printer, constraint)?;
            if *not_valid {
                printer.space();
                printer.push_keyword("NOT");
                printer.space();
                // VALID is an identifier, not keyword — emit as span
                printer.push_keyword("VALID");
            }
        }
        AlterDomainAction::DropConstraint {
            if_exists,
            constraint_name,
            cascade_restrict,
            ..
        } => {
            printer.push_keyword("DROP");
            printer.space();
            printer.push_keyword("CONSTRAINT");
            if *if_exists {
                printer.space();
                printer.push_keyword("IF");
                printer.space();
                printer.push_keyword("EXISTS");
            }
            printer.space();
            printer.push_span(*constraint_name);
            if let Some(ref cr) = cascade_restrict {
                printer.space();
                match cr {
                    crate::ast::types::PgCascadeRestrict::Cascade => {
                        printer.push_keyword("CASCADE");
                    }
                    crate::ast::types::PgCascadeRestrict::Restrict => {
                        printer.push_keyword("RESTRICT");
                    }
                }
            }
        }
        AlterDomainAction::RenameConstraint {
            old_name, new_name, ..
        } => {
            printer.push_keyword("RENAME");
            printer.space();
            printer.push_keyword("CONSTRAINT");
            printer.space();
            printer.push_span(*old_name);
            printer.space();
            printer.push_keyword("TO");
            printer.space();
            printer.push_span(*new_name);
        }
        AlterDomainAction::ValidateConstraint {
            constraint_name, ..
        } => {
            // VALIDATE is an Identifier, but we emit it as keyword for casing consistency
            printer.push_keyword("VALIDATE");
            printer.space();
            printer.push_keyword("CONSTRAINT");
            printer.space();
            printer.push_span(*constraint_name);
        }
        AlterDomainAction::OwnerTo { new_owner, .. } => {
            printer.push_keyword("OWNER");
            printer.space();
            printer.push_keyword("TO");
            printer.space();
            printer.push_span(*new_owner);
        }
        AlterDomainAction::RenameTo { new_name, .. } => {
            printer.push_keyword("RENAME");
            printer.space();
            printer.push_keyword("TO");
            printer.space();
            printer.push_span(*new_name);
        }
        AlterDomainAction::SetSchema { new_schema, .. } => {
            printer.push_keyword("SET");
            printer.space();
            // SCHEMA is Identifier in the lexer but semantically a keyword here
            printer.push_keyword("SCHEMA");
            printer.space();
            printer.push_span(*new_schema);
        }
    }

    Ok(())
}
