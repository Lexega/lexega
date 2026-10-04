// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Formatter for CREATE NETWORK POLICY statements.
//!
//! Uses CST token IDs for header keyword emission when available.
//! Property formatting remains span-based.

use crate::ast::{AstCreateNetworkPolicy, AstNetworkPolicyPropertyKind};
use crate::formatter::printer::Printer;
use crate::formatter::FormatterError;

pub fn format_create_network_policy(
    printer: &mut Printer,
    stmt: &AstCreateNetworkPolicy,
) -> Result<(), FormatterError> {
    // Emit header: CREATE [OR REPLACE] NETWORK POLICY [IF NOT EXISTS] <name>
    let syntax = stmt
        .syntax_id
        .and_then(|id| printer.get_create_network_policy(id));
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
        printer.push_span(s.network_span); // NETWORK is Identifier
        printer.space();
        printer.push_keyword_token_id(s.policy_keyword);
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
        printer.push_identifier_span_v2(s.policy_name_span);
    } else {
        printer.push_keyword_span(stmt.create_span);
        if let Some(or_replace_span) = stmt.or_replace_span {
            printer.space();
            printer.push_span(or_replace_span);
        }
        printer.space();
        printer.push_span(stmt.network_span);
        printer.space();
        printer.push_span(stmt.policy_span);
        if let Some(if_not_exists_span) = stmt.if_not_exists_span {
            printer.space();
            printer.push_span(if_not_exists_span);
        }
        printer.space();
        printer.push_identifier_span_v2(stmt.policy_name_span);
    }

    // Properties (each on its own indented line)
    if !stmt.properties.is_empty() {
        // Pre-compute max property name length for equals-sign alignment
        let max_name_len = stmt
            .properties
            .iter()
            .map(|p| {
                let span = match &p.kind {
                    AstNetworkPolicyPropertyKind::AllowedIpList {
                        property_name_span, ..
                    }
                    | AstNetworkPolicyPropertyKind::BlockedIpList {
                        property_name_span, ..
                    }
                    | AstNetworkPolicyPropertyKind::AllowedNetworkRuleList {
                        property_name_span,
                        ..
                    }
                    | AstNetworkPolicyPropertyKind::BlockedNetworkRuleList {
                        property_name_span,
                        ..
                    }
                    | AstNetworkPolicyPropertyKind::Comment {
                        property_name_span, ..
                    } => property_name_span,
                };
                (span.end - span.start) as usize
            })
            .max()
            .unwrap_or(0);

        printer.newline();
        printer.indent_up();
        for prop in &stmt.properties {
            match &prop.kind {
                AstNetworkPolicyPropertyKind::AllowedIpList {
                    property_name_span,
                    eq_span,
                    list_span,
                    lparen_token,
                    rparen_token,
                    values,
                    ..
                }
                | AstNetworkPolicyPropertyKind::BlockedIpList {
                    property_name_span,
                    eq_span,
                    list_span,
                    lparen_token,
                    rparen_token,
                    values,
                    ..
                } => {
                    printer.push_span(*property_name_span);
                    let name_len = (property_name_span.end - property_name_span.start) as usize;
                    printer.push_alignment_padding(max_name_len + 1 - name_len);
                    printer.push_span(*eq_span);
                    printer.space();

                    if let (Some(lp), Some(rp)) = (*lparen_token, *rparen_token) {
                        printer.push_token_id(lp);
                        for (i, val_span) in values.iter().enumerate() {
                            if i > 0 {
                                printer.push_comma();
                                if printer.config().space_after_comma {
                                    printer.space();
                                }
                            }
                            printer.push_span(*val_span);
                        }
                        printer.push_token_id(rp);
                    } else {
                        printer.push_span(*list_span);
                    }
                    printer.newline();
                }
                AstNetworkPolicyPropertyKind::AllowedNetworkRuleList {
                    property_name_span,
                    eq_span,
                    list_span,
                    lparen_token,
                    rparen_token,
                    rules,
                    ..
                }
                | AstNetworkPolicyPropertyKind::BlockedNetworkRuleList {
                    property_name_span,
                    eq_span,
                    list_span,
                    lparen_token,
                    rparen_token,
                    rules,
                    ..
                } => {
                    printer.push_span(*property_name_span);
                    let name_len = (property_name_span.end - property_name_span.start) as usize;
                    printer.push_alignment_padding(max_name_len + 1 - name_len);
                    printer.push_span(*eq_span);
                    printer.space();

                    if let (Some(lp), Some(rp)) = (*lparen_token, *rparen_token) {
                        printer.push_token_id(lp);
                        for (i, rule_span) in rules.iter().enumerate() {
                            if i > 0 {
                                printer.push_comma();
                                if printer.config().space_after_comma {
                                    printer.space();
                                }
                            }
                            printer.push_span(*rule_span);
                        }
                        printer.push_token_id(rp);
                    } else {
                        printer.push_span(*list_span);
                    }
                    printer.newline();
                }
                AstNetworkPolicyPropertyKind::Comment {
                    property_name_span,
                    eq_span,
                    comment_span,
                } => {
                    printer.push_span(*property_name_span);
                    let name_len = (property_name_span.end - property_name_span.start) as usize;
                    printer.push_alignment_padding(max_name_len + 1 - name_len);
                    printer.push_span(*eq_span);
                    printer.space();
                    printer.push_span(*comment_span);
                    printer.newline();
                }
            }
        }
        printer.indent_down();
    }

    // Extras (unknown properties — preserve as-is)
    for extra in &stmt.extras {
        printer.push_span(extra.span);
    }

    Ok(())
}
