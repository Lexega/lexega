// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Formatter for ALTER NETWORK POLICY statements.
//!
//! Uses CST token IDs for header keyword emission when available.
//! Action/property formatting remains span-based.

use crate::ast::{
    AstAlterNetworkPolicy, AstAlterNetworkPolicyActionKind, AstNetworkPolicyPropertyKind,
};
use crate::formatter::printer::Printer;
use crate::formatter::FormatterError;

pub fn format_alter_network_policy(
    printer: &mut Printer,
    stmt: &AstAlterNetworkPolicy,
) -> Result<(), FormatterError> {
    // Emit header: ALTER NETWORK POLICY [IF EXISTS] <name>
    let syntax = stmt
        .syntax_id
        .and_then(|id| printer.get_alter_network_policy_stmt(id));
    if let Some(s) = syntax {
        printer.push_keyword_token_id(s.alter_keyword);
        printer.space();
        printer.push_span(s.network_span); // NETWORK is Identifier
        printer.space();
        printer.push_keyword_token_id(s.policy_keyword);
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
    } else {
        printer.push_keyword_span(stmt.alter_span);
        printer.space();
        printer.push_span(stmt.network_span);
        printer.space();
        printer.push_span(stmt.policy_span);
        if let Some(if_exists_span) = stmt.if_exists_span {
            printer.space();
            printer.push_span(if_exists_span);
        }
        printer.space();
        printer.push_identifier_span_v2(stmt.name_span);
    }

    // Format the action (unchanged — action CST only has span)
    printer.space();
    match &stmt.action.kind {
        AstAlterNetworkPolicyActionKind::Set {
            set_span,
            properties,
            extras,
        } => {
            printer.push_span(*set_span);
            printer.newline();
            printer.indent_up();
            // Pre-compute max property name length for equals-sign alignment
            let max_name_len = properties
                .iter()
                .map(|p| prop_name_len(&p.kind))
                .max()
                .unwrap_or(0);
            for prop in properties {
                format_network_policy_property(printer, &prop.kind, max_name_len)?;
                printer.newline();
            }
            for extra in extras {
                printer.push_span(extra.span);
            }
            printer.indent_down();
        }
        AstAlterNetworkPolicyActionKind::Add { add_span, property } => {
            printer.push_span(*add_span);
            printer.space();
            format_network_policy_property(printer, &property.kind, 0)?;
        }
        AstAlterNetworkPolicyActionKind::Remove {
            remove_span,
            property,
        } => {
            printer.push_span(*remove_span);
            printer.space();
            format_network_policy_property(printer, &property.kind, 0)?;
        }
        AstAlterNetworkPolicyActionKind::RenameTo {
            rename_span,
            to_span,
            new_name_span,
        } => {
            printer.push_span(*rename_span);
            printer.space();
            printer.push_span(*to_span);
            printer.space();
            printer.push_identifier_span_v2(*new_name_span);
        }
        AstAlterNetworkPolicyActionKind::UnsetComment {
            unset_span,
            comment_span,
        } => {
            printer.push_span(*unset_span);
            printer.space();
            printer.push_span(*comment_span);
        }
        AstAlterNetworkPolicyActionKind::SetTag {
            set_span,
            tag_span,
            assignments_span,
        } => {
            printer.push_span(*set_span);
            printer.space();
            printer.push_span(*tag_span);
            printer.space();
            printer.push_span(*assignments_span);
        }
        AstAlterNetworkPolicyActionKind::UnsetTag {
            unset_span,
            tag_span,
            names_span,
        } => {
            printer.push_span(*unset_span);
            printer.space();
            printer.push_span(*tag_span);
            printer.space();
            printer.push_span(*names_span);
        }
    }

    Ok(())
}

/// Get the property name length from span for alignment computation.
fn prop_name_len(kind: &AstNetworkPolicyPropertyKind) -> usize {
    let span = match kind {
        AstNetworkPolicyPropertyKind::AllowedIpList {
            property_name_span, ..
        }
        | AstNetworkPolicyPropertyKind::BlockedIpList {
            property_name_span, ..
        }
        | AstNetworkPolicyPropertyKind::AllowedNetworkRuleList {
            property_name_span, ..
        }
        | AstNetworkPolicyPropertyKind::BlockedNetworkRuleList {
            property_name_span, ..
        }
        | AstNetworkPolicyPropertyKind::Comment {
            property_name_span, ..
        } => property_name_span,
    };
    (span.end - span.start) as usize
}

fn format_network_policy_property(
    printer: &mut Printer,
    kind: &AstNetworkPolicyPropertyKind,
    max_name_len: usize,
) -> Result<(), FormatterError> {
    match kind {
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
            let pad = if max_name_len > 0 {
                max_name_len + 1 - name_len
            } else {
                1
            };
            printer.push_alignment_padding(pad);
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
            let pad = if max_name_len > 0 {
                max_name_len + 1 - name_len
            } else {
                1
            };
            printer.push_alignment_padding(pad);
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
        }
        AstNetworkPolicyPropertyKind::Comment {
            property_name_span,
            eq_span,
            comment_span,
        } => {
            printer.push_span(*property_name_span);
            let name_len = (property_name_span.end - property_name_span.start) as usize;
            let pad = if max_name_len > 0 {
                max_name_len + 1 - name_len
            } else {
                1
            };
            printer.push_alignment_padding(pad);
            printer.push_span(*eq_span);
            printer.space();
            printer.push_span(*comment_span);
        }
    }
    Ok(())
}
