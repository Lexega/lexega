// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Formatter for SESSION POLICY statements.
//!
//! Implements formatting for:
//! - `CREATE [OR REPLACE] SESSION POLICY [IF NOT EXISTS] name [properties]`
//! - `ALTER SESSION POLICY [IF EXISTS] name { RENAME TO | SET | UNSET }`
//! - `DROP SESSION POLICY [IF EXISTS] name`

use crate::ast::{
    AstAlterSessionPolicy, AstAlterSessionPolicyActionKind, AstCreateSessionPolicy,
    AstDropSessionPolicy, CreatePolicyProperty,
};
use crate::formatter::printer::Printer;
use crate::formatter::FormatterError;

/// Format a list of CREATE policy properties with equals-sign alignment.
fn format_create_properties(printer: &mut Printer, properties: &[CreatePolicyProperty]) {
    if properties.is_empty() {
        return;
    }
    let max_name_len = properties.iter().map(|p| p.name_len()).max().unwrap_or(0);
    printer.newline();
    printer.indent_up();
    for prop in properties {
        printer.push_span(prop.name_span);
        printer.push_alignment_padding(max_name_len + 1 - prop.name_len());
        printer.push_span(prop.eq_span);
        printer.space();
        printer.push_span(prop.value_span);
        printer.newline();
    }
    printer.indent_down();
}

/// Format CREATE SESSION POLICY statement.
pub fn format_create_session_policy(
    printer: &mut Printer,
    stmt: &AstCreateSessionPolicy,
) -> Result<(), FormatterError> {
    let syntax = stmt
        .syntax_id
        .and_then(|id| printer.get_create_session_policy(id));
    if let Some(s) = syntax {
        // CREATE keyword
        printer.push_keyword_token_id(s.create_keyword);

        // OR REPLACE (individual keyword tokens)
        if let Some(or_kw) = s.or_keyword {
            printer.space();
            printer.push_keyword_token_id(or_kw);
            if let Some(replace_kw) = s.replace_keyword {
                printer.space();
                printer.push_keyword_token_id(replace_kw);
            }
        }

        // SESSION keyword
        printer.space();
        printer.push_keyword_token_id(s.session_keyword);

        // POLICY keyword
        printer.space();
        printer.push_keyword_token_id(s.policy_keyword);

        // IF NOT EXISTS
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

        // Policy name
        printer.space();
        printer.push_identifier_span_v2(s.policy_name_span);

        // Properties with alignment (from CST)
        format_create_properties(printer, &s.properties);

        // Extras (unknown properties - preserve as-is, from AST)
        for extra in &stmt.extras {
            printer.push_span(extra.span);
        }

        return Ok(());
    }

    // Fallback: span-based
    printer.push_keyword_span(stmt.create_span);
    if let Some(or_replace_span) = stmt.or_replace_span {
        printer.space();
        printer.push_span(or_replace_span);
    }
    printer.space();
    printer.push_span(stmt.session_span);
    printer.space();
    printer.push_span(stmt.policy_span);
    if let Some(if_not_exists_span) = stmt.if_not_exists_span {
        printer.space();
        printer.push_span(if_not_exists_span);
    }
    printer.space();
    printer.push_identifier_span_v2(stmt.policy_name_span);
    format_create_properties(printer, &stmt.properties);
    for extra in &stmt.extras {
        printer.push_span(extra.span);
    }
    Ok(())
}

/// Format ALTER SESSION POLICY statement.
pub fn format_alter_session_policy(
    printer: &mut Printer,
    stmt: &AstAlterSessionPolicy,
) -> Result<(), FormatterError> {
    // Emit header: ALTER SESSION POLICY [IF EXISTS] <name>
    let syntax = stmt
        .syntax_id
        .and_then(|id| printer.get_alter_session_policy_stmt(id));
    if let Some(s) = syntax {
        printer.push_keyword_token_id(s.alter_keyword);
        printer.space();
        printer.push_keyword_token_id(s.session_keyword); // SESSION is Keyword
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
        printer.push_span(stmt.session_span);
        printer.space();
        printer.push_span(stmt.policy_span);
        if let Some(if_exists_span) = stmt.if_exists_span {
            printer.space();
            printer.push_span(if_exists_span);
        }
        printer.space();
        printer.push_identifier_span_v2(stmt.name_span);
    }

    // Pre-compute alignment info for SET properties
    let set_prefix_len = stmt
        .actions
        .iter()
        .find_map(|a| match &a.kind {
            AstAlterSessionPolicyActionKind::SetSessionIdleTimeoutMins {
                set_span: Some(s),
                ..
            }
            | AstAlterSessionPolicyActionKind::SetSessionUiIdleTimeoutMins {
                set_span: Some(s),
                ..
            }
            | AstAlterSessionPolicyActionKind::SetAllowedSecondaryRoles {
                set_span: Some(s), ..
            }
            | AstAlterSessionPolicyActionKind::SetBlockedSecondaryRoles {
                set_span: Some(s), ..
            }
            | AstAlterSessionPolicyActionKind::SetComment {
                set_span: Some(s), ..
            } => {
                Some((s.end - s.start) as usize + 1) // "SET" + 1 space
            }
            _ => None,
        })
        .unwrap_or(0);

    let max_set_prop_len = stmt
        .actions
        .iter()
        .filter_map(|a| match &a.kind {
            AstAlterSessionPolicyActionKind::SetSessionIdleTimeoutMins {
                property_span, ..
            }
            | AstAlterSessionPolicyActionKind::SetSessionUiIdleTimeoutMins {
                property_span, ..
            }
            | AstAlterSessionPolicyActionKind::SetAllowedSecondaryRoles { property_span, .. }
            | AstAlterSessionPolicyActionKind::SetBlockedSecondaryRoles { property_span, .. } => {
                Some((property_span.end - property_span.start) as usize)
            }
            AstAlterSessionPolicyActionKind::SetComment {
                comment_span: Some(s),
                ..
            } => Some((s.end - s.start) as usize),
            _ => None,
        })
        .max()
        .unwrap_or(0);

    // Format actions
    if !stmt.actions.is_empty() {
        printer.newline();
        printer.indent_up();
    }
    for (index, action) in stmt.actions.iter().enumerate() {
        if index > 0 {
            printer.newline();
        }

        match &action.kind {
            AstAlterSessionPolicyActionKind::RenameTo {
                rename_span,
                to_span,
                new_name_span,
            } => {
                if let Some(rename_span) = rename_span {
                    printer.push_span(*rename_span);
                    printer.space();
                }
                if let Some(to_span) = to_span {
                    printer.push_span(*to_span);
                    printer.space();
                }
                printer.push_identifier_span_v2(*new_name_span);
            }
            // SET property = value actions
            AstAlterSessionPolicyActionKind::SetSessionIdleTimeoutMins {
                set_span,
                property_span,
                eq_span,
                value_span,
                ..
            }
            | AstAlterSessionPolicyActionKind::SetSessionUiIdleTimeoutMins {
                set_span,
                property_span,
                eq_span,
                value_span,
                ..
            } => {
                if let Some(set_span) = set_span {
                    printer.push_span(*set_span);
                    printer.space();
                } else if set_prefix_len > 0 {
                    printer.push_alignment_padding(set_prefix_len);
                }
                printer.push_span(*property_span);
                let name_len = (property_span.end - property_span.start) as usize;
                printer.push_alignment_padding(max_set_prop_len + 1 - name_len);
                if let Some(eq_span) = eq_span {
                    printer.push_span(*eq_span);
                }
                printer.space();
                printer.push_span(*value_span);
            }
            AstAlterSessionPolicyActionKind::SetAllowedSecondaryRoles {
                set_span,
                property_span,
                eq_span,
                roles_spec_span,
                lparen_token,
                rparen_token,
                values,
                ..
            }
            | AstAlterSessionPolicyActionKind::SetBlockedSecondaryRoles {
                set_span,
                property_span,
                eq_span,
                roles_spec_span,
                lparen_token,
                rparen_token,
                values,
                ..
            } => {
                if let Some(set_span) = set_span {
                    printer.push_span(*set_span);
                    printer.space();
                } else if set_prefix_len > 0 {
                    printer.push_alignment_padding(set_prefix_len);
                }
                printer.push_span(*property_span);
                let name_len = (property_span.end - property_span.start) as usize;
                printer.push_alignment_padding(max_set_prop_len + 1 - name_len);
                if let Some(eq_span) = eq_span {
                    printer.push_span(*eq_span);
                }
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
                    printer.push_span(*roles_spec_span);
                }
            }
            AstAlterSessionPolicyActionKind::SetComment {
                set_span,
                comment_span,
                eq_span,
                comment_value_span,
                ..
            } => {
                if let Some(set_span) = set_span {
                    printer.push_span(*set_span);
                    printer.space();
                } else if set_prefix_len > 0 {
                    printer.push_alignment_padding(set_prefix_len);
                }
                if let Some(cs) = comment_span {
                    printer.push_span(*cs);
                    let name_len = (cs.end - cs.start) as usize;
                    printer.push_alignment_padding(max_set_prop_len + 1 - name_len);
                }
                if let Some(eq_span) = eq_span {
                    printer.push_span(*eq_span);
                }
                printer.space();
                printer.push_span(*comment_value_span);
            }
            AstAlterSessionPolicyActionKind::SetTag {
                set_span,
                tag_span,
                assignments_span,
            } => {
                if let Some(set_span) = set_span {
                    printer.push_span(*set_span);
                    printer.space();
                }
                if let Some(tag_span) = tag_span {
                    printer.push_span(*tag_span);
                    printer.space();
                }
                printer.push_span(*assignments_span);
            }
            // UNSET property actions
            AstAlterSessionPolicyActionKind::UnsetSessionIdleTimeoutMins {
                unset_span,
                property_span,
            }
            | AstAlterSessionPolicyActionKind::UnsetSessionUiIdleTimeoutMins {
                unset_span,
                property_span,
            }
            | AstAlterSessionPolicyActionKind::UnsetAllowedSecondaryRoles {
                unset_span,
                property_span,
            }
            | AstAlterSessionPolicyActionKind::UnsetBlockedSecondaryRoles {
                unset_span,
                property_span,
            } => {
                if let Some(unset_span) = unset_span {
                    printer.push_span(*unset_span);
                    printer.space();
                }
                printer.push_span(*property_span);
            }
            AstAlterSessionPolicyActionKind::UnsetComment {
                unset_span,
                comment_span,
            } => {
                if let Some(unset_span) = unset_span {
                    printer.push_span(*unset_span);
                    printer.space();
                }
                if let Some(comment_span) = comment_span {
                    printer.push_span(*comment_span);
                }
            }
            AstAlterSessionPolicyActionKind::UnsetTag {
                unset_span,
                tag_span,
                tags_span,
            } => {
                if let Some(unset_span) = unset_span {
                    printer.push_span(*unset_span);
                    printer.space();
                }
                if let Some(tag_span) = tag_span {
                    printer.push_span(*tag_span);
                    printer.space();
                }
                printer.push_span(*tags_span);
            }
        }
    }
    if !stmt.actions.is_empty() {
        printer.indent_down();
    }

    Ok(())
}

/// Format DROP SESSION POLICY statement.
pub fn format_drop_session_policy(
    printer: &mut Printer,
    stmt: &AstDropSessionPolicy,
) -> Result<(), FormatterError> {
    let syntax = stmt
        .syntax_id
        .and_then(|id| printer.get_drop_session_policy(id));
    if let Some(s) = syntax {
        printer.push_keyword_token_id(s.drop_keyword);
        printer.space();
        printer.push_keyword_token_id(s.session_keyword); // SESSION is Keyword
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
        printer.push_identifier_span_v2(s.policy_name_span);
        return Ok(());
    }

    // Fallback: span-based
    printer.push_keyword_span(stmt.drop_span);
    printer.space();
    printer.push_span(stmt.session_span);
    printer.space();
    printer.push_span(stmt.policy_span);
    if let Some(if_exists_span) = stmt.if_exists_span {
        printer.space();
        printer.push_span(if_exists_span);
    }
    printer.space();
    printer.push_identifier_span_v2(stmt.policy_name_span);
    Ok(())
}
