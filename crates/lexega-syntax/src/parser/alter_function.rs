// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Parser for ALTER FUNCTION statements.
//!
//! Syntax:
//! ```text
//! ALTER FUNCTION [IF EXISTS] <name>(<arg_types>) <action>
//! ```
//!
//! Actions:
//!   - `RENAME TO <new_name>`
//!   - SET SECURE / UNSET SECURE
//!   - `SET <property> = <value> [, ...]`
//!   - `UNSET <property> [, ...]`
//!   - `SET TAG <name> = <value> [, ...] / UNSET TAG <name> [, ...]`
//!   - External function: SET API_INTEGRATION, HEADERS, CONTEXT_HEADERS, etc.

use crate::ast::types::AstUnknownClause;
use crate::ast::AstStmt;
use crate::ast::{AstAlterFunction, AstAlterFunctionAction, AstAlterFunctionActionKind};
use crate::error::{ExpectInvariant, ParseError, ParseErrorKind, ParseResult, ParseResultExt};
use crate::lexer::{Keyword, Operator, Punctuation, Span, TokenKind};
use crate::parser::core::Parser;

/// Parse ALTER FUNCTION statement.
///
/// Entry point expects parser positioned at ALTER token.
/// Returns parsed AstStmt::AlterFunction on success.
pub(crate) fn try_parse_alter_function(p: &mut Parser<'_>) -> ParseResult<AstStmt> {
    let _depth = p.track_depth("alter_function")?;

    // ALTER
    let alter_tok = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["ALTER".to_string()])?;
    let alter_span = alter_tok.span;

    // FUNCTION
    let function_tok = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["FUNCTION".to_string()])?;
    if !matches!(function_tok.kind, TokenKind::Keyword(Keyword::Function)) {
        return Err(ParseError::new(
            function_tok.span,
            ParseErrorKind::InvalidStatement {
                message: format!(
                    "Expected FUNCTION after ALTER, found '{}'",
                    function_tok.lexeme(p.source)
                ),
            },
        ));
    }
    let function_span = function_tok.span;

    // Optional IF EXISTS
    let if_exists_span = parse_if_exists_af(p)?;

    // Function name (qualified name)
    let name_span = p.parse_qualified_name_span()?;

    // Signature: (type, type, ...)
    let signature_span = parse_signature_type_list(p)?;

    // Parse action
    let mut extras: Vec<AstUnknownClause> = Vec::new();
    let action = parse_alter_function_action(p, &mut extras)?;
    let action_span = action.span;

    let stmt_span = Span {
        start: alter_span.start,
        end: action_span.end,
    };

    Ok(AstStmt::AlterFunction(Box::new(AstAlterFunction {
        node_id: p.id_gen.next(),
        span: stmt_span,
        alter_span,
        function_span,
        if_exists_span,
        name_span,
        signature_span,
        action_span,
        action,
        extras,
    })))
}

/// Parse optional IF EXISTS clause.
fn parse_if_exists_af(p: &mut Parser<'_>) -> ParseResult<Option<Span>> {
    if let Some(tok) = p.peek_non_trivia() {
        if matches!(tok.kind, TokenKind::Keyword(Keyword::If)) {
            let if_tok = p.advance().expect_invariant("IF consumed after kind check");

            if let Some(exists_tok) = p.peek_non_trivia() {
                if matches!(exists_tok.kind, TokenKind::Keyword(Keyword::Exists)) {
                    let e = p
                        .advance()
                        .expect_invariant("EXISTS consumed after kind check");
                    return Ok(Some(Span {
                        start: if_tok.span.start,
                        end: e.span.end,
                    }));
                }
            }

            return Err(ParseError::new(
                if_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: "ALTER FUNCTION IF requires EXISTS".to_string(),
                },
            ));
        }
    }
    Ok(None)
}

/// Parse signature type list: (TYPE, TYPE, ...)
///
/// Unlike CREATE FUNCTION/PROCEDURE which has (name TYPE, name TYPE, ...),
/// ALTER FUNCTION/PROCEDURE only has the type list for identification.
/// Types are Identifiers (INT, VARCHAR, NUMBER, etc.), not Keywords.
pub(crate) fn parse_signature_type_list(p: &mut Parser<'_>) -> ParseResult<Span> {
    // Expect left paren
    let lparen_tok = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["(".to_string()])?;
    if !matches!(lparen_tok.kind, TokenKind::Punctuation(Punctuation::LParen)) {
        return Err(ParseError::new(
            lparen_tok.span,
            ParseErrorKind::InvalidStatement {
                message: "Expected ( for argument type list".to_string(),
            },
        ));
    }
    let start = lparen_tok.span.start;

    // Check for empty signature ()
    if let Some(tok) = p.peek_non_trivia() {
        if matches!(tok.kind, TokenKind::Punctuation(Punctuation::RParen)) {
            let rparen = p
                .advance()
                .expect_invariant("RParen consumed after kind check");
            return Ok(Span {
                start,
                end: rparen.span.end,
            });
        }
    }

    // Parse type list
    loop {
        // Type name - can be Identifier or Keyword (some types like ARRAY might be keywords)
        let type_tok = p
            .advance()
            .ok_or_eof(p.current_span(), vec!["type name".to_string()])?;

        // Accept Identifier or Keyword for type names
        if !matches!(
            type_tok.kind,
            TokenKind::Identifier { .. } | TokenKind::Keyword(_)
        ) {
            return Err(ParseError::new(
                type_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: format!("Expected type name, found '{}'", type_tok.lexeme(p.source)),
                },
            ));
        }

        // Check for parameterized types like VARCHAR(100), NUMBER(10,2)
        if let Some(tok) = p.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Punctuation(Punctuation::LParen)) {
                // Consume the nested parens for type parameters
                consume_balanced_parens(p)?;
            }
        }

        // Check for comma or closing paren
        if let Some(tok) = p.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Comma)) {
                p.advance(); // consume comma
                continue;
            } else if matches!(tok.kind, TokenKind::Punctuation(Punctuation::RParen)) {
                let rparen = p
                    .advance()
                    .expect_invariant("RParen consumed after kind check");
                return Ok(Span {
                    start,
                    end: rparen.span.end,
                });
            } else {
                return Err(ParseError::new(
                    tok.span,
                    ParseErrorKind::InvalidStatement {
                        message: "Expected , or ) in argument type list".to_string(),
                    },
                ));
            }
        } else {
            return Err(ParseError::new(
                p.current_span(),
                ParseErrorKind::InvalidStatement {
                    message: "Unexpected end of input in argument type list".to_string(),
                },
            ));
        }
    }
}

/// Consume balanced parentheses (for type parameters like VARCHAR(100)).
pub(crate) fn consume_balanced_parens(p: &mut Parser<'_>) -> ParseResult<Span> {
    let lparen = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["(".to_string()])?;
    let start = lparen.span.start;
    let mut depth = 1;
    let mut end = lparen.span.end;

    while depth > 0 {
        let tok = p
            .advance()
            .ok_or_eof(p.current_span(), vec![")".to_string()])?;
        end = tok.span.end;

        match tok.kind {
            TokenKind::Punctuation(Punctuation::LParen) => depth += 1,
            TokenKind::Punctuation(Punctuation::RParen) => depth -= 1,
            _ => {}
        }
    }

    Ok(Span { start, end })
}

/// Parse ALTER FUNCTION action.
fn parse_alter_function_action(
    p: &mut Parser<'_>,
    extras: &mut Vec<AstUnknownClause>,
) -> ParseResult<AstAlterFunctionAction> {
    let action_start = p.current_span().start;

    let kind = if let Some(tok) = p.peek_non_trivia() {
        match tok.kind {
            TokenKind::Keyword(Keyword::Rename) => parse_rename_action(p)?,
            TokenKind::Keyword(Keyword::Set) => parse_set_action_function(p)?,
            TokenKind::Keyword(Keyword::Unset) => parse_unset_action_function(p)?,
            _ => {
                // Unknown action - consume to end of statement
                let span = consume_to_statement_end(p, action_start)?;
                extras.push(AstUnknownClause {
                    node_id: p.id_gen.next(),
                    introducer: None,
                    span,
                    kind: crate::ast::types::UnknownKind::Clause,
                });
                AstAlterFunctionActionKind::Unknown { span }
            }
        }
    } else {
        return Err(ParseError::new(
            p.current_span(),
            ParseErrorKind::InvalidStatement {
                message: "Expected action (RENAME, SET, or UNSET)".to_string(),
            },
        ));
    };

    let action_span = Span {
        start: action_start,
        end: get_action_end(&kind),
    };

    Ok(AstAlterFunctionAction {
        node_id: p.id_gen.next(),
        span: action_span,
        kind,
    })
}

/// Get the end position of an action.
fn get_action_end(kind: &AstAlterFunctionActionKind) -> u32 {
    match kind {
        AstAlterFunctionActionKind::RenameTo { new_name_span, .. } => new_name_span.end,
        AstAlterFunctionActionKind::SetSecure { secure_span, .. } => secure_span.end,
        AstAlterFunctionActionKind::UnsetSecure { secure_span, .. } => secure_span.end,
        AstAlterFunctionActionKind::SetProperties {
            properties_span, ..
        } => properties_span.end,
        AstAlterFunctionActionKind::UnsetProperties {
            properties_span, ..
        } => properties_span.end,
        AstAlterFunctionActionKind::SetTag {
            assignments_span, ..
        } => assignments_span.end,
        AstAlterFunctionActionKind::UnsetTag { tags_span, .. } => tags_span.end,
        AstAlterFunctionActionKind::SetApiIntegration { value_span, .. } => value_span.end,
        AstAlterFunctionActionKind::SetHeaders { value_span, .. } => value_span.end,
        AstAlterFunctionActionKind::SetContextHeaders { value_span, .. } => value_span.end,
        AstAlterFunctionActionKind::SetMaxBatchRows { value_span, .. } => value_span.end,
        AstAlterFunctionActionKind::SetCompression { value_span, .. } => value_span.end,
        AstAlterFunctionActionKind::SetRequestTranslator { udf_span, .. } => udf_span.end,
        AstAlterFunctionActionKind::SetResponseTranslator { udf_span, .. } => udf_span.end,
        AstAlterFunctionActionKind::Unknown { span } => span.end,
    }
}

/// Parse RENAME TO action.
fn parse_rename_action(p: &mut Parser<'_>) -> ParseResult<AstAlterFunctionActionKind> {
    let rename_tok = p.advance().expect_invariant("RENAME verified by caller");
    let rename_span = rename_tok.span;

    let to_tok = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["TO".to_string()])?;
    if !matches!(to_tok.kind, TokenKind::Keyword(Keyword::To)) {
        return Err(ParseError::new(
            to_tok.span,
            ParseErrorKind::InvalidStatement {
                message: "Expected TO after RENAME".to_string(),
            },
        ));
    }
    let to_span = to_tok.span;

    let new_name_span = p.parse_qualified_name_span()?;

    Ok(AstAlterFunctionActionKind::RenameTo {
        rename_span,
        to_span,
        new_name_span,
    })
}

/// Parse SET action for function.
fn parse_set_action_function(p: &mut Parser<'_>) -> ParseResult<AstAlterFunctionActionKind> {
    let set_tok = p.advance().expect_invariant("SET verified by caller");
    let set_span = set_tok.span;

    if let Some(tok) = p.peek_non_trivia() {
        // SET SECURE (Keyword)
        if matches!(tok.kind, TokenKind::Keyword(Keyword::Secure)) {
            let secure = p
                .advance()
                .expect_invariant("SECURE consumed after kind check");
            return Ok(AstAlterFunctionActionKind::SetSecure {
                set_span,
                secure_span: secure.span,
            });
        }
        // SET TAG (Keyword)
        if matches!(tok.kind, TokenKind::Keyword(Keyword::Tag)) {
            return parse_set_tag_action(p, set_span);
        }
        // SET <property> = <value> (Identifier or keyword used as identifier)
        if p.can_be_identifier_token(tok) {
            let prop_name = tok.lexeme(p.source).to_ascii_uppercase();

            // SECURE should have been handled above - if we're here it's a bug
            if prop_name == "SECURE" {
                let secure = p.advance().expect_invariant("SECURE consumed");
                return Ok(AstAlterFunctionActionKind::SetSecure {
                    set_span,
                    secure_span: secure.span,
                });
            }

            // Check for external function specific properties
            match prop_name.as_str() {
                "API_INTEGRATION" => return parse_set_api_integration(p, set_span),
                "HEADERS" => return parse_set_headers(p, set_span),
                "CONTEXT_HEADERS" => return parse_set_context_headers(p, set_span),
                "MAX_BATCH_ROWS" => return parse_set_max_batch_rows(p, set_span),
                "COMPRESSION" => return parse_set_compression(p, set_span),
                "REQUEST_TRANSLATOR" => return parse_set_request_translator(p, set_span),
                "RESPONSE_TRANSLATOR" => return parse_set_response_translator(p, set_span),
                _ => return parse_set_properties(p, set_span),
            }
        }
    }

    Err(ParseError::new(
        set_span,
        ParseErrorKind::InvalidStatement {
            message: "Expected SECURE, TAG, or property name after SET".to_string(),
        },
    ))
}

/// Parse UNSET action for function.
fn parse_unset_action_function(p: &mut Parser<'_>) -> ParseResult<AstAlterFunctionActionKind> {
    let unset_tok = p.advance().expect_invariant("UNSET verified by caller");
    let unset_span = unset_tok.span;

    if let Some(tok) = p.peek_non_trivia() {
        // UNSET SECURE (Keyword)
        if matches!(tok.kind, TokenKind::Keyword(Keyword::Secure)) {
            let secure = p
                .advance()
                .expect_invariant("SECURE consumed after kind check");
            return Ok(AstAlterFunctionActionKind::UnsetSecure {
                unset_span,
                secure_span: secure.span,
            });
        }
        // UNSET TAG (Keyword)
        if matches!(tok.kind, TokenKind::Keyword(Keyword::Tag)) {
            return parse_unset_tag_action(p, unset_span);
        }
        // UNSET <property> (Identifier or keyword used as identifier - COMMENT, LOG_LEVEL, etc.)
        if p.can_be_identifier_token(tok) {
            return parse_unset_properties(p, unset_span);
        }
    }

    Err(ParseError::new(
        unset_span,
        ParseErrorKind::InvalidStatement {
            message: "Expected SECURE, TAG, or property name after UNSET".to_string(),
        },
    ))
}

/// Parse SET TAG action.
fn parse_set_tag_action(
    p: &mut Parser<'_>,
    set_span: Span,
) -> ParseResult<AstAlterFunctionActionKind> {
    let tag_tok = p.advance().expect_invariant("TAG verified by caller");
    let tag_span = tag_tok.span;

    // Parse tag assignments: name = 'value' [, ...]
    let assignments_start = p.current_span().start;
    let mut end;

    loop {
        // Tag name (possibly qualified: db.schema.tag_name)
        let _tag_name_span = p.parse_qualified_name_span()?;

        // =
        let eq_tok = p
            .advance()
            .ok_or_eof(p.current_span(), vec!["=".to_string()])?;
        if !matches!(eq_tok.kind, TokenKind::Operator(Operator::Eq)) {
            return Err(ParseError::new(
                eq_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: "Expected = after tag name".to_string(),
                },
            ));
        }

        // Value (string literal)
        let value_tok = p
            .advance()
            .ok_or_eof(p.current_span(), vec!["tag value".to_string()])?;
        end = value_tok.span.end;

        // Check for comma (more assignments)
        if let Some(tok) = p.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Comma)) {
                p.advance(); // consume comma
                continue;
            }
        }
        break;
    }

    Ok(AstAlterFunctionActionKind::SetTag {
        set_span,
        tag_span,
        assignments_span: Span {
            start: assignments_start,
            end,
        },
    })
}

/// Parse UNSET TAG action.
fn parse_unset_tag_action(
    p: &mut Parser<'_>,
    unset_span: Span,
) -> ParseResult<AstAlterFunctionActionKind> {
    let tag_tok = p.advance().expect_invariant("TAG verified by caller");
    let tag_span = tag_tok.span;

    // Parse tag names: name [, name, ...]
    let tags_start = p.current_span().start;
    let mut end;

    loop {
        // Tag name (possibly qualified: db.schema.tag_name)
        let tag_name_span = p.parse_qualified_name_span()?;
        end = tag_name_span.end;

        // Check for comma
        if let Some(tok) = p.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Comma)) {
                p.advance();
                continue;
            }
        }
        break;
    }

    Ok(AstAlterFunctionActionKind::UnsetTag {
        unset_span,
        tag_span,
        tags_span: Span {
            start: tags_start,
            end,
        },
    })
}

/// Parse SET <property> = <value> [, ...] action.
fn parse_set_properties(
    p: &mut Parser<'_>,
    set_span: Span,
) -> ParseResult<AstAlterFunctionActionKind> {
    let props_start = p.current_span().start;
    let mut end = props_start;

    loop {
        // Property name (Identifier)
        let _prop_tok = p
            .advance()
            .ok_or_eof(p.current_span(), vec!["property name".to_string()])?;

        // =
        let eq_tok = p
            .advance()
            .ok_or_eof(p.current_span(), vec!["=".to_string()])?;
        if !matches!(eq_tok.kind, TokenKind::Operator(Operator::Eq)) {
            return Err(ParseError::new(
                eq_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: "Expected = after property name".to_string(),
                },
            ));
        }

        // Value - could be string, identifier, or parenthesized list
        if let Some(tok) = p.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Punctuation(Punctuation::LParen)) {
                // Parenthesized value like (integration1, integration2)
                let paren_span = consume_balanced_parens(p)?;
                end = paren_span.end;
            } else {
                // Simple value
                let value_tok = p
                    .advance()
                    .ok_or_eof(p.current_span(), vec!["property value".to_string()])?;
                end = value_tok.span.end;
            }
        }

        // Check for comma (more properties)
        if let Some(tok) = p.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Comma)) {
                p.advance();
                continue;
            }
        }
        break;
    }

    Ok(AstAlterFunctionActionKind::SetProperties {
        set_span,
        properties_span: Span {
            start: props_start,
            end,
        },
    })
}

/// Parse UNSET <property> [, ...] action.
fn parse_unset_properties(
    p: &mut Parser<'_>,
    unset_span: Span,
) -> ParseResult<AstAlterFunctionActionKind> {
    let props_start = p.current_span().start;
    let mut end;

    loop {
        let prop_tok = p
            .advance()
            .ok_or_eof(p.current_span(), vec!["property name".to_string()])?;
        end = prop_tok.span.end;

        // Check for comma
        if let Some(tok) = p.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Comma)) {
                p.advance();
                continue;
            }
        }
        break;
    }

    Ok(AstAlterFunctionActionKind::UnsetProperties {
        unset_span,
        properties_span: Span {
            start: props_start,
            end,
        },
    })
}

// External function specific SET actions

fn parse_set_api_integration(
    p: &mut Parser<'_>,
    set_span: Span,
) -> ParseResult<AstAlterFunctionActionKind> {
    let prop_tok = p
        .advance()
        .expect_invariant("API_INTEGRATION verified by caller");
    let api_integration_span = prop_tok.span;

    let eq_tok = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["=".to_string()])?;
    if !matches!(eq_tok.kind, TokenKind::Operator(Operator::Eq)) {
        return Err(ParseError::new(
            eq_tok.span,
            ParseErrorKind::InvalidStatement {
                message: "Expected = after API_INTEGRATION".to_string(),
            },
        ));
    }

    let value_tok = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["integration name".to_string()])?;

    Ok(AstAlterFunctionActionKind::SetApiIntegration {
        set_span,
        api_integration_span,
        value_span: value_tok.span,
    })
}

fn parse_set_headers(
    p: &mut Parser<'_>,
    set_span: Span,
) -> ParseResult<AstAlterFunctionActionKind> {
    let prop_tok = p.advance().expect_invariant("HEADERS verified by caller");
    let headers_span = prop_tok.span;

    let eq_tok = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["=".to_string()])?;
    if !matches!(eq_tok.kind, TokenKind::Operator(Operator::Eq)) {
        return Err(ParseError::new(
            eq_tok.span,
            ParseErrorKind::InvalidStatement {
                message: "Expected = after HEADERS".to_string(),
            },
        ));
    }

    let value_span = consume_balanced_parens(p)?;

    Ok(AstAlterFunctionActionKind::SetHeaders {
        set_span,
        headers_span,
        value_span,
    })
}

fn parse_set_context_headers(
    p: &mut Parser<'_>,
    set_span: Span,
) -> ParseResult<AstAlterFunctionActionKind> {
    let prop_tok = p
        .advance()
        .expect_invariant("CONTEXT_HEADERS verified by caller");
    let context_headers_span = prop_tok.span;

    let eq_tok = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["=".to_string()])?;
    if !matches!(eq_tok.kind, TokenKind::Operator(Operator::Eq)) {
        return Err(ParseError::new(
            eq_tok.span,
            ParseErrorKind::InvalidStatement {
                message: "Expected = after CONTEXT_HEADERS".to_string(),
            },
        ));
    }

    let value_span = consume_balanced_parens(p)?;

    Ok(AstAlterFunctionActionKind::SetContextHeaders {
        set_span,
        context_headers_span,
        value_span,
    })
}

fn parse_set_max_batch_rows(
    p: &mut Parser<'_>,
    set_span: Span,
) -> ParseResult<AstAlterFunctionActionKind> {
    let prop_tok = p
        .advance()
        .expect_invariant("MAX_BATCH_ROWS verified by caller");
    let max_batch_rows_span = prop_tok.span;

    let eq_tok = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["=".to_string()])?;
    if !matches!(eq_tok.kind, TokenKind::Operator(Operator::Eq)) {
        return Err(ParseError::new(
            eq_tok.span,
            ParseErrorKind::InvalidStatement {
                message: "Expected = after MAX_BATCH_ROWS".to_string(),
            },
        ));
    }

    let value_tok = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["integer value".to_string()])?;

    Ok(AstAlterFunctionActionKind::SetMaxBatchRows {
        set_span,
        max_batch_rows_span,
        value_span: value_tok.span,
    })
}

fn parse_set_compression(
    p: &mut Parser<'_>,
    set_span: Span,
) -> ParseResult<AstAlterFunctionActionKind> {
    let prop_tok = p
        .advance()
        .expect_invariant("COMPRESSION verified by caller");
    let compression_span = prop_tok.span;

    let eq_tok = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["=".to_string()])?;
    if !matches!(eq_tok.kind, TokenKind::Operator(Operator::Eq)) {
        return Err(ParseError::new(
            eq_tok.span,
            ParseErrorKind::InvalidStatement {
                message: "Expected = after COMPRESSION".to_string(),
            },
        ));
    }

    let value_tok = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["compression type".to_string()])?;

    Ok(AstAlterFunctionActionKind::SetCompression {
        set_span,
        compression_span,
        value_span: value_tok.span,
    })
}

fn parse_set_request_translator(
    p: &mut Parser<'_>,
    set_span: Span,
) -> ParseResult<AstAlterFunctionActionKind> {
    let prop_tok = p
        .advance()
        .expect_invariant("REQUEST_TRANSLATOR verified by caller");
    let request_translator_span = prop_tok.span;

    let eq_tok = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["=".to_string()])?;
    if !matches!(eq_tok.kind, TokenKind::Operator(Operator::Eq)) {
        return Err(ParseError::new(
            eq_tok.span,
            ParseErrorKind::InvalidStatement {
                message: "Expected = after REQUEST_TRANSLATOR".to_string(),
            },
        ));
    }

    let udf_span = p.parse_qualified_name_span()?;

    Ok(AstAlterFunctionActionKind::SetRequestTranslator {
        set_span,
        request_translator_span,
        udf_span,
    })
}

fn parse_set_response_translator(
    p: &mut Parser<'_>,
    set_span: Span,
) -> ParseResult<AstAlterFunctionActionKind> {
    let prop_tok = p
        .advance()
        .expect_invariant("RESPONSE_TRANSLATOR verified by caller");
    let response_translator_span = prop_tok.span;

    let eq_tok = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["=".to_string()])?;
    if !matches!(eq_tok.kind, TokenKind::Operator(Operator::Eq)) {
        return Err(ParseError::new(
            eq_tok.span,
            ParseErrorKind::InvalidStatement {
                message: "Expected = after RESPONSE_TRANSLATOR".to_string(),
            },
        ));
    }

    let udf_span = p.parse_qualified_name_span()?;

    Ok(AstAlterFunctionActionKind::SetResponseTranslator {
        set_span,
        response_translator_span,
        udf_span,
    })
}

/// Consume tokens until statement end (semicolon or EOF).
fn consume_to_statement_end(p: &mut Parser<'_>, start: u32) -> ParseResult<Span> {
    let mut end = start;
    while let Some(tok) = p.peek_non_trivia() {
        if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Semi)) {
            break;
        }
        let t = p.advance().expect_invariant("token consumed after peek");
        end = t.span.end;
    }
    Ok(Span { start, end })
}
