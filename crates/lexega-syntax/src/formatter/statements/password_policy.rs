// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Formatter for PASSWORD POLICY statements.
//!
//! Implements formatting for:
//! - `CREATE [OR REPLACE] PASSWORD POLICY [IF NOT EXISTS] name [properties]`
//! - `ALTER PASSWORD POLICY [IF EXISTS] name { RENAME TO | SET | UNSET }`
//! - `DROP PASSWORD POLICY [IF EXISTS] name`

use crate::ast::{
    AstAlterPasswordPolicy, AstAlterPasswordPolicyActionKind, AstCreatePasswordPolicy,
    AstDropPasswordPolicy, CreatePolicyProperty,
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

/// Format CREATE PASSWORD POLICY statement.
pub fn format_create_password_policy(
    printer: &mut Printer,
    stmt: &AstCreatePasswordPolicy,
) -> Result<(), FormatterError> {
    let syntax = stmt
        .syntax_id
        .and_then(|id| printer.get_create_password_policy(id));
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

        // PASSWORD (Identifier token)
        printer.space();
        printer.push_token_id(s.password_token);

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
    printer.push_span(stmt.password_span);
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

/// Format ALTER PASSWORD POLICY statement.
pub fn format_alter_password_policy(
    printer: &mut Printer,
    stmt: &AstAlterPasswordPolicy,
) -> Result<(), FormatterError> {
    // Emit header: ALTER PASSWORD POLICY [IF EXISTS] <name>
    let syntax = stmt
        .syntax_id
        .and_then(|id| printer.get_alter_password_policy_stmt(id));
    if let Some(s) = syntax {
        printer.push_keyword_token_id(s.alter_keyword);
        printer.space();
        printer.push_token_id(s.password_token); // PASSWORD is Identifier
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
        printer.push_span(stmt.password_span);
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
            AstAlterPasswordPolicyActionKind::SetPasswordMinLength {
                set_span: Some(s), ..
            }
            | AstAlterPasswordPolicyActionKind::SetPasswordMaxLength {
                set_span: Some(s), ..
            }
            | AstAlterPasswordPolicyActionKind::SetPasswordMinUpperCaseChars {
                set_span: Some(s),
                ..
            }
            | AstAlterPasswordPolicyActionKind::SetPasswordMinLowerCaseChars {
                set_span: Some(s),
                ..
            }
            | AstAlterPasswordPolicyActionKind::SetPasswordMinNumericChars {
                set_span: Some(s),
                ..
            }
            | AstAlterPasswordPolicyActionKind::SetPasswordMinSpecialChars {
                set_span: Some(s),
                ..
            }
            | AstAlterPasswordPolicyActionKind::SetPasswordMinAgeDays {
                set_span: Some(s), ..
            }
            | AstAlterPasswordPolicyActionKind::SetPasswordMaxAgeDays {
                set_span: Some(s), ..
            }
            | AstAlterPasswordPolicyActionKind::SetPasswordMaxRetries {
                set_span: Some(s), ..
            }
            | AstAlterPasswordPolicyActionKind::SetPasswordLockoutTimeMins {
                set_span: Some(s),
                ..
            }
            | AstAlterPasswordPolicyActionKind::SetPasswordHistory {
                set_span: Some(s), ..
            }
            | AstAlterPasswordPolicyActionKind::SetComment {
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
            AstAlterPasswordPolicyActionKind::SetPasswordMinLength { property_span, .. }
            | AstAlterPasswordPolicyActionKind::SetPasswordMaxLength { property_span, .. }
            | AstAlterPasswordPolicyActionKind::SetPasswordMinUpperCaseChars {
                property_span,
                ..
            }
            | AstAlterPasswordPolicyActionKind::SetPasswordMinLowerCaseChars {
                property_span,
                ..
            }
            | AstAlterPasswordPolicyActionKind::SetPasswordMinNumericChars {
                property_span, ..
            }
            | AstAlterPasswordPolicyActionKind::SetPasswordMinSpecialChars {
                property_span, ..
            }
            | AstAlterPasswordPolicyActionKind::SetPasswordMinAgeDays { property_span, .. }
            | AstAlterPasswordPolicyActionKind::SetPasswordMaxAgeDays { property_span, .. }
            | AstAlterPasswordPolicyActionKind::SetPasswordMaxRetries { property_span, .. }
            | AstAlterPasswordPolicyActionKind::SetPasswordLockoutTimeMins {
                property_span, ..
            }
            | AstAlterPasswordPolicyActionKind::SetPasswordHistory { property_span, .. } => {
                Some((property_span.end - property_span.start) as usize)
            }
            AstAlterPasswordPolicyActionKind::SetComment {
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
            AstAlterPasswordPolicyActionKind::RenameTo {
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
            // SET property = value actions (all have same field layout)
            AstAlterPasswordPolicyActionKind::SetPasswordMinLength {
                set_span,
                property_span,
                eq_span,
                value_span,
                ..
            }
            | AstAlterPasswordPolicyActionKind::SetPasswordMaxLength {
                set_span,
                property_span,
                eq_span,
                value_span,
                ..
            }
            | AstAlterPasswordPolicyActionKind::SetPasswordMinUpperCaseChars {
                set_span,
                property_span,
                eq_span,
                value_span,
                ..
            }
            | AstAlterPasswordPolicyActionKind::SetPasswordMinLowerCaseChars {
                set_span,
                property_span,
                eq_span,
                value_span,
                ..
            }
            | AstAlterPasswordPolicyActionKind::SetPasswordMinNumericChars {
                set_span,
                property_span,
                eq_span,
                value_span,
                ..
            }
            | AstAlterPasswordPolicyActionKind::SetPasswordMinSpecialChars {
                set_span,
                property_span,
                eq_span,
                value_span,
                ..
            }
            | AstAlterPasswordPolicyActionKind::SetPasswordMinAgeDays {
                set_span,
                property_span,
                eq_span,
                value_span,
                ..
            }
            | AstAlterPasswordPolicyActionKind::SetPasswordMaxAgeDays {
                set_span,
                property_span,
                eq_span,
                value_span,
                ..
            }
            | AstAlterPasswordPolicyActionKind::SetPasswordMaxRetries {
                set_span,
                property_span,
                eq_span,
                value_span,
                ..
            }
            | AstAlterPasswordPolicyActionKind::SetPasswordLockoutTimeMins {
                set_span,
                property_span,
                eq_span,
                value_span,
                ..
            }
            | AstAlterPasswordPolicyActionKind::SetPasswordHistory {
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
            AstAlterPasswordPolicyActionKind::SetComment {
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
                if let Some(comment_span) = comment_span {
                    let name_len = (comment_span.end - comment_span.start) as usize;
                    printer.push_span(*comment_span);
                    printer.push_alignment_padding(max_set_prop_len + 1 - name_len);
                }
                if let Some(eq_span) = eq_span {
                    printer.push_span(*eq_span);
                }
                printer.space();
                printer.push_span(*comment_value_span);
            }
            AstAlterPasswordPolicyActionKind::SetTag {
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
            AstAlterPasswordPolicyActionKind::UnsetPasswordMinLength {
                unset_span,
                property_span,
            }
            | AstAlterPasswordPolicyActionKind::UnsetPasswordMaxLength {
                unset_span,
                property_span,
            }
            | AstAlterPasswordPolicyActionKind::UnsetPasswordMinUpperCaseChars {
                unset_span,
                property_span,
            }
            | AstAlterPasswordPolicyActionKind::UnsetPasswordMinLowerCaseChars {
                unset_span,
                property_span,
            }
            | AstAlterPasswordPolicyActionKind::UnsetPasswordMinNumericChars {
                unset_span,
                property_span,
            }
            | AstAlterPasswordPolicyActionKind::UnsetPasswordMinSpecialChars {
                unset_span,
                property_span,
            }
            | AstAlterPasswordPolicyActionKind::UnsetPasswordMinAgeDays {
                unset_span,
                property_span,
            }
            | AstAlterPasswordPolicyActionKind::UnsetPasswordMaxAgeDays {
                unset_span,
                property_span,
            }
            | AstAlterPasswordPolicyActionKind::UnsetPasswordMaxRetries {
                unset_span,
                property_span,
            }
            | AstAlterPasswordPolicyActionKind::UnsetPasswordLockoutTimeMins {
                unset_span,
                property_span,
            }
            | AstAlterPasswordPolicyActionKind::UnsetPasswordHistory {
                unset_span,
                property_span,
            } => {
                if let Some(unset_span) = unset_span {
                    printer.push_span(*unset_span);
                    printer.space();
                }
                printer.push_span(*property_span);
            }
            AstAlterPasswordPolicyActionKind::UnsetComment {
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
            AstAlterPasswordPolicyActionKind::UnsetTag {
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

/// Format DROP PASSWORD POLICY statement.
pub fn format_drop_password_policy(
    printer: &mut Printer,
    stmt: &AstDropPasswordPolicy,
) -> Result<(), FormatterError> {
    let syntax = stmt
        .syntax_id
        .and_then(|id| printer.get_drop_password_policy(id));
    if let Some(s) = syntax {
        printer.push_keyword_token_id(s.drop_keyword);
        printer.space();
        printer.push_token_id(s.password_token); // PASSWORD is Identifier
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
    printer.push_span(stmt.password_span);
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
