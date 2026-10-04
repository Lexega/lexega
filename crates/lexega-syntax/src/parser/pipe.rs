// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! CREATE/ALTER/DROP PIPE statement parsing (Snowflake)
//!
//! Pipe statements combine property-based DDL with an embedded AS <copy_statement>
//! body. Known properties (AUTO_INGEST, INTEGRATION, etc.) are captured as
//! individual spans; the COPY body is captured as a single span covering AS onwards.
//!
//! ## Token Reference
//!
//! | SQL Text | Token Kind | Notes |
//! |----------|------------|-------|
//! | PIPE | Identifier | NOT a keyword |
//! | AUTO_INGEST | Identifier | Bool property |
//! | AWS_SNS_TOPIC | Identifier | String property |
//! | INTEGRATION | Identifier | String property |
//! | ERROR_INTEGRATION | Identifier | String property |
//! | REFRESH | Identifier | ALTER action |
//! | PREFIX | Identifier | REFRESH option |
//! | MODIFIED_BEFORE | Identifier | REFRESH option |
//! | COMMENT | Keyword | String property |
//! | SET/UNSET | Keyword | ALTER action |
//! | TAG | Keyword | Clause modifier |
//! | AS | Keyword | Precedes COPY body |

use crate::ast::{
    AstAlterPipe, AstAlterPipeAction, AstAlterPipeActionKind, AstCreatePipe, AstDropPipe, AstStmt,
    AstUnknownClause, UnknownKind,
};
use crate::error::{ExpectInvariant, ParseError, ParseErrorKind, ParseResult, ParseResultExt};
use crate::lexer::{Keyword, Operator, Punctuation, Span, TokenKind};
use crate::parser::core::Parser;

// ============================================================================
// Shared helpers (mirror the warehouse ones)
// ============================================================================

fn parse_property_clause(p: &mut Parser<'_>) -> ParseResult<Span> {
    let key_tok = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["property".to_string()])?;
    let start = key_tok.span.start;
    let mut end = key_tok.span.end;

    if let Some(tok) = p.peek_non_trivia() {
        if matches!(tok.kind, TokenKind::Operator(Operator::Eq)) {
            let eq = p.advance().expect_invariant("= consumed");
            end = eq.span.end;
            if let Some(val) = p.peek_non_trivia() {
                if matches!(val.kind, TokenKind::Punctuation(Punctuation::LParen)) {
                    p.advance();
                    end = skip_to_matching_paren(p)?;
                } else {
                    let v = p.advance().expect_invariant("value consumed after =");
                    end = v.span.end;
                }
            }
        }
    }
    Ok(Span { start, end })
}

fn skip_to_matching_paren(p: &mut Parser<'_>) -> ParseResult<u32> {
    let mut depth = 1;
    while let Some(tok) = p.advance() {
        match tok.kind {
            TokenKind::Punctuation(Punctuation::LParen) => depth += 1,
            TokenKind::Punctuation(Punctuation::RParen) => {
                depth -= 1;
                if depth == 0 {
                    return Ok(tok.span.end);
                }
            }
            _ => {}
        }
    }
    Err(ParseError::new(
        p.current_span(),
        ParseErrorKind::InvalidStatement {
            message: "Unmatched parenthesis in PIPE statement".to_string(),
        },
    ))
}

/// Skip to statement end (semicolon or EOF), handling balanced parens.
fn skip_to_statement_end(p: &mut Parser<'_>) -> u32 {
    let mut end = p.current_span().end;
    while let Some(tok) = p.peek_non_trivia() {
        if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Semi)) {
            break;
        }
        let t = p
            .advance()
            .expect_invariant("token consumed during skip_to_statement_end");
        end = t.span.end;
        if matches!(t.kind, TokenKind::Punctuation(Punctuation::LParen)) {
            if let Ok(paren_end) = skip_to_matching_paren(p) {
                end = paren_end;
            }
        }
    }
    end
}

fn skip_to_statement_end_span(p: &mut Parser<'_>) -> Span {
    let start = p.current_span().start;
    let end = skip_to_statement_end(p);
    Span { start, end }
}

// ============================================================================
// CREATE PIPE
// ============================================================================

/// Parse CREATE [OR REPLACE] PIPE [IF NOT EXISTS] name [properties...] AS copy_stmt
///
/// Entry: parser positioned at CREATE token.
pub(crate) fn try_parse_create_pipe(p: &mut Parser<'_>) -> ParseResult<AstStmt> {
    let _depth = p.track_depth("create_pipe")?;

    // Consume CREATE
    let create_tok = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["CREATE".to_string()])?;
    let create_span = create_tok.span;
    let mut span = create_span;

    // Optional OR REPLACE
    let mut or_replace_span: Option<Span> = None;
    if let Some(tok) = p.peek_non_trivia() {
        if matches!(tok.kind, TokenKind::Keyword(Keyword::Or)) {
            let or_tok = p.advance().expect_invariant("OR consumed");
            if let Some(next) = p.peek_non_trivia() {
                if matches!(next.kind, TokenKind::Keyword(Keyword::Replace)) {
                    let replace = p.advance().expect_invariant("REPLACE consumed");
                    or_replace_span = Some(Span {
                        start: or_tok.span.start,
                        end: replace.span.end,
                    });
                    span.end = replace.span.end;
                }
            }
        }
    }

    // PIPE identifier
    let pipe_tok = p
        .peek_non_trivia()
        .ok_or_eof(p.current_span(), vec!["PIPE".to_string()])?;
    if !pipe_tok.lexeme(p.source).eq_ignore_ascii_case("PIPE") {
        return Err(ParseError::new(
            pipe_tok.span,
            ParseErrorKind::InvalidStatement {
                message: format!("Expected PIPE, found '{}'", pipe_tok.lexeme(p.source)),
            },
        ));
    }
    let pipe_kw = p.advance().expect_invariant("PIPE consumed");
    let pipe_span = pipe_kw.span;
    span.end = pipe_span.end;

    // Optional IF NOT EXISTS
    let mut if_not_exists_span: Option<Span> = None;
    if let Some(tok) = p.peek_non_trivia() {
        if matches!(tok.kind, TokenKind::Keyword(Keyword::If)) {
            let if_tok = p.advance().expect_invariant("IF consumed");
            if let Some(not_tok) = p.peek_non_trivia() {
                if matches!(not_tok.kind, TokenKind::Keyword(Keyword::Not)) {
                    p.advance(); // NOT
                    if let Some(exists_tok) = p.peek_non_trivia() {
                        if matches!(exists_tok.kind, TokenKind::Keyword(Keyword::Exists)) {
                            let exists = p.advance().expect_invariant("EXISTS consumed");
                            if_not_exists_span = Some(Span {
                                start: if_tok.span.start,
                                end: exists.span.end,
                            });
                            span.end = exists.span.end;
                        }
                    }
                }
            }
        }
    }

    // Pipe name (qualified identifier)
    let name_span = p.parse_qualified_name_span()?;
    span.end = name_span.end;

    // Parse properties (before the AS keyword)
    let mut auto_ingest_span: Option<Span> = None;
    let mut aws_sns_topic_span: Option<Span> = None;
    let mut integration_span: Option<Span> = None;
    let mut error_integration_span: Option<Span> = None;
    let mut comment_span: Option<Span> = None;
    let mut as_span: Option<Span> = None;
    let mut copy_body_span: Option<Span> = None;
    let mut extras: Vec<AstUnknownClause> = Vec::new();

    while let Some(tok) = p.peek_non_trivia() {
        if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Semi)) {
            break;
        }

        let lexeme = tok.lexeme(p.source);

        // AS keyword → everything after AS is the COPY body
        if matches!(tok.kind, TokenKind::Keyword(Keyword::As)) {
            let as_tok = p.advance().expect_invariant("AS consumed");
            as_span = Some(as_tok.span);

            // Everything from here to semicolon/EOF is the COPY body
            let body_start = p.current_span().start;
            let body_end = skip_to_statement_end(p);
            if body_end > body_start {
                copy_body_span = Some(Span {
                    start: body_start,
                    end: body_end,
                });
                span.end = body_end;
            } else {
                // AS followed by nothing
                span.end = as_tok.span.end;
            }
            break; // Nothing after COPY body
        }

        // COMMENT keyword
        if matches!(tok.kind, TokenKind::Keyword(Keyword::Comment)) {
            comment_span = Some(parse_property_clause(p)?);
            span.end = comment_span.as_ref().unwrap().end;
            continue;
        }

        // Identifier-based properties
        if lexeme.eq_ignore_ascii_case("AUTO_INGEST") {
            auto_ingest_span = Some(parse_property_clause(p)?);
            span.end = auto_ingest_span.as_ref().unwrap().end;
        } else if lexeme.eq_ignore_ascii_case("AWS_SNS_TOPIC") {
            aws_sns_topic_span = Some(parse_property_clause(p)?);
            span.end = aws_sns_topic_span.as_ref().unwrap().end;
        } else if lexeme.eq_ignore_ascii_case("INTEGRATION") {
            integration_span = Some(parse_property_clause(p)?);
            span.end = integration_span.as_ref().unwrap().end;
        } else if lexeme.eq_ignore_ascii_case("ERROR_INTEGRATION") {
            error_integration_span = Some(parse_property_clause(p)?);
            span.end = error_integration_span.as_ref().unwrap().end;
        } else {
            // Unknown property — preserve via extras
            let introducer_span = tok.span;
            let prop_span = parse_property_clause(p)?;
            extras.push(AstUnknownClause {
                node_id: p.id_gen.next(),
                introducer: Some(introducer_span),
                span: prop_span,
                kind: UnknownKind::Property,
            });
            span.end = prop_span.end;
        }
    }
    Ok(AstStmt::CreatePipe(Box::new(AstCreatePipe {
        node_id: p.id_gen.next(),
        span,
        create_span,
        pipe_span,
        or_replace_span,
        if_not_exists_span,
        name_span,
        auto_ingest_span,
        aws_sns_topic_span,
        integration_span,
        error_integration_span,
        comment_span,
        as_span,
        copy_body_span,
        extras,
    })))
}

// ============================================================================
// ALTER PIPE
// ============================================================================

/// Parse ALTER PIPE [IF EXISTS] name { action }
///
/// Entry: parser positioned at ALTER token.
pub(crate) fn try_parse_alter_pipe(p: &mut Parser<'_>) -> ParseResult<AstStmt> {
    let _depth = p.track_depth("alter_pipe")?;

    // Consume ALTER
    let alter_tok = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["ALTER".to_string()])?;
    let alter_span = alter_tok.span;

    // PIPE identifier
    let pipe_tok = p
        .peek_non_trivia()
        .ok_or_eof(p.current_span(), vec!["PIPE".to_string()])?;
    if !pipe_tok.lexeme(p.source).eq_ignore_ascii_case("PIPE") {
        return Err(ParseError::new(
            pipe_tok.span,
            ParseErrorKind::InvalidStatement {
                message: format!("Expected PIPE, found '{}'", pipe_tok.lexeme(p.source)),
            },
        ));
    }
    let pipe_kw = p.advance().expect_invariant("PIPE consumed");
    let pipe_span = pipe_kw.span;

    // Optional IF EXISTS
    let mut if_exists_span: Option<Span> = None;
    if let Some(tok) = p.peek_non_trivia() {
        if matches!(tok.kind, TokenKind::Keyword(Keyword::If)) {
            let saved_idx = p.idx;
            let if_tok = p.advance().expect_invariant("IF consumed");
            if let Some(exists_tok) = p.peek_non_trivia() {
                if matches!(exists_tok.kind, TokenKind::Keyword(Keyword::Exists)) {
                    let exists = p.advance().expect_invariant("EXISTS consumed");
                    if_exists_span = Some(Span {
                        start: if_tok.span.start,
                        end: exists.span.end,
                    });
                } else {
                    p.idx = saved_idx;
                }
            } else {
                p.idx = saved_idx;
            }
        }
    }

    // Pipe name (qualified identifier)
    let name_span = p.parse_qualified_name_span()?;

    // Parse action
    let mut extras: Vec<AstUnknownClause> = Vec::new();
    let (action, action_span) = parse_alter_pipe_action(p, &mut extras)?;

    let stmt_span = Span {
        start: alter_span.start,
        end: action_span.end,
    };
    Ok(AstStmt::AlterPipe(Box::new(AstAlterPipe {
        node_id: p.id_gen.next(),
        span: stmt_span,
        alter_span,
        pipe_span,
        if_exists_span,
        name_span,
        action_span,
        action,
        extras,
    })))
}

/// Parse the action portion of ALTER PIPE.
fn parse_alter_pipe_action(
    p: &mut Parser<'_>,
    extras: &mut Vec<AstUnknownClause>,
) -> ParseResult<(AstAlterPipeAction, Span)> {
    let tok = p.peek_non_trivia().ok_or_eof(
        p.current_span(),
        vec!["action (SET, REFRESH, ...)".to_string()],
    )?;
    let action_start = tok.span.start;

    let kind = if matches!(tok.kind, TokenKind::Keyword(Keyword::Set)) {
        // SET: could be SET TAG or SET properties
        let set_tok = p.advance().expect_invariant("SET consumed");
        if let Some(next) = p.peek_non_trivia() {
            if matches!(next.kind, TokenKind::Keyword(Keyword::Tag)) {
                // SET TAG <tag_name> = '<value>' [, ...]
                let tag_tok = p.advance().expect_invariant("TAG consumed");
                let mut end = tag_tok.span.end;
                if let Some(lparen) = p.peek_non_trivia() {
                    if matches!(lparen.kind, TokenKind::Punctuation(Punctuation::LParen)) {
                        p.advance();
                        end = skip_to_matching_paren(p)?;
                    } else {
                        // No parens — consume tag assignments until semicolon
                        while let Some(tok) = p.peek_non_trivia() {
                            if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Semi)) {
                                break;
                            }
                            let t = p.advance().unwrap();
                            end = t.span.end;
                        }
                    }
                }
                AstAlterPipeActionKind::SetTag {
                    set_span: set_tok.span,
                    tag_span: tag_tok.span,
                    assignments_span: Span {
                        start: tag_tok.span.start,
                        end,
                    },
                }
            } else {
                // SET property = value [...]
                let props_start = next.span.start;
                let mut end = props_start;
                while let Some(tok) = p.peek_non_trivia() {
                    if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Semi)) {
                        break;
                    }
                    let t = p.advance().unwrap();
                    end = t.span.end;
                    if matches!(t.kind, TokenKind::Punctuation(Punctuation::LParen)) {
                        if let Ok(pend) = skip_to_matching_paren(p) {
                            end = pend;
                        }
                    }
                }
                AstAlterPipeActionKind::Set {
                    set_span: set_tok.span,
                    properties_span: Span {
                        start: props_start,
                        end,
                    },
                }
            }
        } else {
            AstAlterPipeActionKind::Set {
                set_span: set_tok.span,
                properties_span: set_tok.span,
            }
        }
    } else if matches!(tok.kind, TokenKind::Keyword(Keyword::Unset)) {
        // UNSET TAG (...)
        let unset_tok = p.advance().expect_invariant("UNSET consumed");
        if let Some(next) = p.peek_non_trivia() {
            if matches!(next.kind, TokenKind::Keyword(Keyword::Tag)) {
                let tag_tok = p.advance().expect_invariant("TAG consumed");
                let mut end = tag_tok.span.end;
                if let Some(lparen) = p.peek_non_trivia() {
                    if matches!(lparen.kind, TokenKind::Punctuation(Punctuation::LParen)) {
                        p.advance();
                        end = skip_to_matching_paren(p)?;
                    } else {
                        // No parens — consume tag names until semicolon
                        while let Some(tok) = p.peek_non_trivia() {
                            if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Semi)) {
                                break;
                            }
                            let t = p.advance().unwrap();
                            end = t.span.end;
                        }
                    }
                }
                AstAlterPipeActionKind::UnsetTag {
                    unset_span: unset_tok.span,
                    tag_span: tag_tok.span,
                    names_span: Span {
                        start: tag_tok.span.start,
                        end,
                    },
                }
            } else {
                // UNSET without TAG — unknown, consume rest
                let rest = skip_to_statement_end_span(p);
                extras.push(AstUnknownClause {
                    node_id: p.id_gen.next(),
                    introducer: Some(unset_tok.span),
                    span: Span {
                        start: unset_tok.span.start,
                        end: rest.end,
                    },
                    kind: UnknownKind::Clause,
                });
                AstAlterPipeActionKind::UnsetTag {
                    unset_span: unset_tok.span,
                    tag_span: unset_tok.span,
                    names_span: rest,
                }
            }
        } else {
            AstAlterPipeActionKind::UnsetTag {
                unset_span: unset_tok.span,
                tag_span: unset_tok.span,
                names_span: unset_tok.span,
            }
        }
    } else if tok.lexeme(p.source).eq_ignore_ascii_case("REFRESH") {
        // REFRESH [PREFIX = '<path>'] [MODIFIED_BEFORE = '<timestamp>']
        let refresh_tok = p.advance().expect_invariant("REFRESH consumed");
        let mut end = refresh_tok.span.end;

        // Optional key = value options after REFRESH
        while let Some(t) = p.peek_non_trivia() {
            if matches!(t.kind, TokenKind::Punctuation(Punctuation::Semi)) {
                break;
            }
            let lexeme = t.lexeme(p.source);
            if lexeme.eq_ignore_ascii_case("PREFIX")
                || lexeme.eq_ignore_ascii_case("MODIFIED_BEFORE")
            {
                let prop = parse_property_clause(p)?;
                end = prop.end;
            } else {
                // Unknown trailing token — consume
                let t = p.advance().unwrap();
                end = t.span.end;
            }
        }
        AstAlterPipeActionKind::Refresh {
            refresh_span: Span {
                start: refresh_tok.span.start,
                end,
            },
            options_span: if end > refresh_tok.span.end {
                Some(Span {
                    start: refresh_tok.span.end,
                    end,
                })
            } else {
                None
            },
        }
    } else {
        // Unknown action — preserve as extra
        let unknown_span = skip_to_statement_end_span(p);
        extras.push(AstUnknownClause {
            node_id: p.id_gen.next(),
            introducer: Some(tok.span),
            span: unknown_span,
            kind: UnknownKind::Clause,
        });
        AstAlterPipeActionKind::Refresh {
            refresh_span: unknown_span,
            options_span: None,
        }
    };

    let action_end = match &kind {
        AstAlterPipeActionKind::Set {
            properties_span, ..
        } => properties_span.end,
        AstAlterPipeActionKind::SetTag {
            assignments_span, ..
        } => assignments_span.end,
        AstAlterPipeActionKind::UnsetTag { names_span, .. } => names_span.end,
        AstAlterPipeActionKind::Refresh { refresh_span, .. } => refresh_span.end,
    };

    let action_span = Span {
        start: action_start,
        end: action_end,
    };

    Ok((
        AstAlterPipeAction {
            span: action_span,
            kind,
        },
        action_span,
    ))
}

// ============================================================================
// DROP PIPE
// ============================================================================

/// Parse DROP PIPE [IF EXISTS] name
///
/// Entry: parser positioned at DROP token.
pub(crate) fn try_parse_drop_pipe(p: &mut Parser<'_>) -> ParseResult<AstStmt> {
    let _depth = p.track_depth("drop_pipe")?;

    // Consume DROP
    let drop_tok = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["DROP".to_string()])?;
    let drop_span = drop_tok.span;

    // PIPE identifier
    let pipe_tok = p
        .peek_non_trivia()
        .ok_or_eof(p.current_span(), vec!["PIPE".to_string()])?;
    if !pipe_tok.lexeme(p.source).eq_ignore_ascii_case("PIPE") {
        return Err(ParseError::new(
            pipe_tok.span,
            ParseErrorKind::InvalidStatement {
                message: format!("Expected PIPE, found '{}'", pipe_tok.lexeme(p.source)),
            },
        ));
    }
    let pipe_kw = p.advance().expect_invariant("PIPE consumed");
    let pipe_span = pipe_kw.span;

    // Optional IF EXISTS
    let mut if_exists_span: Option<Span> = None;
    if let Some(tok) = p.peek_non_trivia() {
        if matches!(tok.kind, TokenKind::Keyword(Keyword::If)) {
            let saved_idx = p.idx;
            let if_tok = p.advance().expect_invariant("IF consumed");
            if let Some(exists_tok) = p.peek_non_trivia() {
                if matches!(exists_tok.kind, TokenKind::Keyword(Keyword::Exists)) {
                    let exists = p.advance().expect_invariant("EXISTS consumed");
                    if_exists_span = Some(Span {
                        start: if_tok.span.start,
                        end: exists.span.end,
                    });
                } else {
                    p.idx = saved_idx;
                }
            } else {
                p.idx = saved_idx;
            }
        }
    }

    // Pipe name (qualified identifier)
    let name_span = p.parse_qualified_name_span()?;

    let stmt_span = Span {
        start: drop_span.start,
        end: name_span.end,
    };
    Ok(AstStmt::DropPipe(Box::new(AstDropPipe {
        node_id: p.id_gen.next(),
        span: stmt_span,
        drop_span,
        pipe_span,
        if_exists_span,
        name_span,
    })))
}
