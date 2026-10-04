// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Formatter for DROP NETWORK POLICY statements.
//!
//! Uses CST token IDs for keyword emission when available,
//! falling back to span-based emission otherwise.

use crate::ast::AstDropNetworkPolicy;
use crate::formatter::printer::Printer;
use crate::formatter::FormatterError;

pub fn format_drop_network_policy(
    printer: &mut Printer,
    stmt: &AstDropNetworkPolicy,
) -> Result<(), FormatterError> {
    if let Some(syntax_id) = stmt.syntax_id {
        if let Some(syntax) = printer.get_drop_network_policy(syntax_id) {
            // DROP keyword (CST token — applies keyword casing config)
            printer.push_keyword_token_id(syntax.drop_keyword);

            // NETWORK (Identifier token in lexer — emitted as span)
            printer.space();
            printer.push_span(syntax.network_span);

            // POLICY keyword
            printer.space();
            printer.push_keyword_token_id(syntax.policy_keyword);

            // IF EXISTS (individual keyword tokens)
            if let Some(if_kw) = syntax.if_keyword {
                printer.space();
                printer.push_keyword_token_id(if_kw);
                if let Some(exists_kw) = syntax.exists_keyword {
                    printer.space();
                    printer.push_keyword_token_id(exists_kw);
                }
            }

            // Policy name
            printer.space();
            printer.push_identifier_span_v2(syntax.policy_name_span);

            return Ok(());
        }
    }

    // Fallback: span-only emission
    printer.push_span(stmt.span);
    Ok(())
}
