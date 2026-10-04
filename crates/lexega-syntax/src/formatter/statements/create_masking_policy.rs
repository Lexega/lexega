// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Formatter for CREATE MASKING POLICY statements.
//!
//! Uses CST token IDs for keyword emission when available,
//! falling back to span-based emission otherwise.
//! Body expressions are formatted via the AST expression formatter.

use crate::ast::AstCreateMaskingPolicy;
use crate::formatter::printer::Printer;
use crate::formatter::FormatterError;

pub fn format_create_masking_policy(
    printer: &mut Printer,
    stmt: &AstCreateMaskingPolicy,
) -> Result<(), FormatterError> {
    if let Some(syntax_id) = stmt.syntax_id {
        if let Some(syntax) = printer.get_create_masking_policy(syntax_id) {
            // CREATE keyword
            printer.push_keyword_token_id(syntax.create_keyword);

            // OR REPLACE (individual keyword tokens)
            if let Some(or_kw) = syntax.or_keyword {
                printer.space();
                printer.push_keyword_token_id(or_kw);
                if let Some(replace_kw) = syntax.replace_keyword {
                    printer.space();
                    printer.push_keyword_token_id(replace_kw);
                }
            }

            // MASKING keyword
            printer.space();
            printer.push_keyword_token_id(syntax.masking_keyword);

            // POLICY keyword
            printer.space();
            printer.push_keyword_token_id(syntax.policy_keyword);

            // IF NOT EXISTS (individual keyword tokens)
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

            // Policy name
            printer.space();
            printer.push_identifier_span_v2(syntax.policy_name_span);

            // AS keyword
            printer.space();
            printer.push_keyword_token_id(syntax.as_keyword);

            // Signature (parameter list — content span)
            printer.space();
            printer.push_span(syntax.signature_span);

            // RETURNS keyword
            printer.space();
            printer.push_keyword_token_id(syntax.returns_keyword);

            // Return type (content span)
            printer.space();
            printer.push_span(syntax.return_type_span);

            // Arrow operator (structural token)
            printer.space();
            printer.push_token_id(syntax.arrow_token);
            printer.newline();

            // Body expression — format via AST expression formatter
            printer.indent_up();
            use crate::formatter::statements::select::format_expression;
            format_expression(printer, &stmt.body)?;
            printer.indent_down();

            // Optional COMMENT clause (content span)
            if let Some(comment_span) = syntax.comment_span {
                printer.newline();
                printer.push_span(comment_span);
            }

            // Optional EXEMPT_OTHER_POLICIES clause (content span)
            if let Some(exempt_span) = syntax.exempt_other_policies_span {
                printer.newline();
                printer.push_span(exempt_span);
            }

            return Ok(());
        }
    }

    // Fallback: span-only emission
    printer.push_span(stmt.span);
    Ok(())
}
