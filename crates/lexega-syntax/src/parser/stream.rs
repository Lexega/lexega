// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! CREATE/ALTER/DROP STREAM statement parsing
//!
//! Implements parsing for Snowflake STREAM statements which track DML changes
//! on source objects (tables, views, stages, etc.)
//!
//! ## Grammar (from Snowflake docs)
//!
//! ```text
//! CREATE [ OR REPLACE ] STREAM [ IF NOT EXISTS ] <name>
//!   [ [ WITH ] TAG ( <tag_name> = '<value>' [ , ... ] ) ]
//!   [ COPY GRANTS ]
//!   ON { TABLE | VIEW | STAGE | EXTERNAL TABLE | EVENT TABLE | DYNAMIC TABLE } <source_name>
//!   [ { AT | BEFORE } ( { TIMESTAMP => <ts> | OFFSET => <diff> | STATEMENT => <id> | STREAM => '<name>' } ) ]
//!   [ APPEND_ONLY = TRUE | FALSE ]
//!   [ SHOW_INITIAL_ROWS = TRUE | FALSE ]
//!   [ INSERT_ONLY = TRUE ]
//!   [ COMMENT = '<string>' ]
//!
//! CREATE [ OR REPLACE ] STREAM <name> CLONE <source_stream> [ COPY GRANTS ]
//!
//! ALTER STREAM [ IF EXISTS ] <name> SET COMMENT = '<string>'
//! ALTER STREAM [ IF EXISTS ] <name> SET TAG <tag_name> = '<value>' [ , ... ]
//! ALTER STREAM <name> UNSET TAG <tag_name> [ , ... ]
//! ALTER STREAM [ IF EXISTS ] <name> UNSET COMMENT
//!
//! DROP STREAM [ IF EXISTS ] <name>
//! ```
//!
//! ## Token Reference
//!
//! | SQL Text | Token Kind | Notes |
//! |----------|------------|-------|
//! | STREAM | Identifier | NOT a keyword - check lexeme |
//! | EVENT | Identifier | NOT a keyword - check lexeme |
//! | EXTERNAL | Identifier | NOT a keyword - check lexeme |
//! | DYNAMIC | Identifier | NOT a keyword - check lexeme |
//! | CLONE | Identifier | NOT a keyword - check lexeme |
//! | AT | Identifier | Time travel specifier - check lexeme |
//! | BEFORE | Identifier | Time travel specifier - check lexeme |
//! | TIMESTAMP | Identifier | Time travel option - check lexeme |
//! | STATEMENT | Identifier | Time travel option - check lexeme |
//! | OFFSET | Keyword(Offset) | IS a keyword |
//! | APPEND_ONLY | Identifier | Single underscore token |
//! | SHOW_INITIAL_ROWS | Identifier | Single underscore token |
//! | INSERT_ONLY | Identifier | Single underscore token |
//! | TRUE/FALSE | Literal(Boolean) | Boolean values |
//! | => | Operator(EqGt) | Fat arrow operator |
//! | COMMENT | Keyword(Comment) | IS a keyword |
//! | WITH | Keyword(With) | IS a keyword |
//! | TAG | Keyword(Tag) | IS a keyword |
//! | COPY | Keyword(Copy) | IS a keyword |
//! | GRANTS | Keyword(Grants) | IS a keyword |

use crate::ast::{
    AstAlterStream, AstAlterStreamAction, AstAlterStreamActionKind, AstCreateStream, AstDropStream,
    AstStmt, StreamSourceType, TimeTravelKind, TimeTravelOption,
};
use crate::cst::TokenId;
use crate::error::{ExpectInvariant, ParseError, ParseErrorKind, ParseResult, ParseResultExt};
use crate::lexer::{Keyword, Operator, Punctuation, Span, TokenKind};
use crate::parser::core::Parser;
use crate::syntax::{
    SyntaxAlterStreamAction, SyntaxAlterStreamStmt, SyntaxCreateStream, SyntaxDropStream,
};

// ============================================================================
// CREATE STREAM
// ============================================================================

/// Parse CREATE STREAM statement.
///
/// Entry point expects parser positioned at CREATE token.
pub(crate) fn try_parse_create_stream(p: &mut Parser<'_>) -> ParseResult<AstStmt> {
    // Consume CREATE keyword
    let create_tok = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["CREATE".to_string()])?;
    let create_span = create_tok.span;
    let create_token_id = p.last_token_id();
    let mut span = create_span;

    // Optional OR REPLACE
    let mut or_replace_span: Option<Span> = None;
    let mut or_token_id: Option<TokenId> = None;
    let mut replace_token_id: Option<TokenId> = None;
    if let Some(tok) = p.peek_non_trivia() {
        if matches!(tok.kind, TokenKind::Keyword(Keyword::Or)) {
            let or_tok = p
                .advance()
                .expect_invariant("OR keyword consumed after match");
            or_token_id = Some(p.last_token_id());
            if let Some(next) = p.peek_non_trivia() {
                if matches!(next.kind, TokenKind::Keyword(Keyword::Replace)) {
                    let replace = p
                        .advance()
                        .expect_invariant("REPLACE keyword consumed after peek");
                    replace_token_id = Some(p.last_token_id());
                    or_replace_span = Some(Span {
                        start: or_tok.span.start,
                        end: replace.span.end,
                    });
                    span.end = replace.span.end;
                }
            }
        }
    }

    // STREAM identifier (NOT a keyword)
    let stream_tok = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["STREAM".to_string()])?;
    if !stream_tok.lexeme(p.source).eq_ignore_ascii_case("STREAM") {
        return Err(ParseError::new(
            stream_tok.span,
            ParseErrorKind::InvalidStatement {
                message: format!("Expected STREAM, found '{}'", stream_tok.lexeme(p.source)),
            },
        ));
    }
    let stream_span = stream_tok.span;
    let stream_token_id = p.last_token_id();
    span.end = stream_span.end;

    // Optional IF NOT EXISTS
    let mut if_not_exists_span: Option<Span> = None;
    let mut if_token_id: Option<TokenId> = None;
    let mut not_token_id: Option<TokenId> = None;
    let mut exists_token_id: Option<TokenId> = None;
    if let Some(tok) = p.peek_non_trivia() {
        if matches!(tok.kind, TokenKind::Keyword(Keyword::If)) {
            let if_tok = p
                .advance()
                .expect_invariant("IF keyword consumed after match");
            let if_tid = p.last_token_id();
            if let Some(not_tok) = p.peek_non_trivia() {
                if matches!(not_tok.kind, TokenKind::Keyword(Keyword::Not)) {
                    p.advance()
                        .expect_invariant("NOT keyword consumed after peek");
                    let not_tid = p.last_token_id();
                    if let Some(exists_tok) = p.peek_non_trivia() {
                        if matches!(exists_tok.kind, TokenKind::Keyword(Keyword::Exists)) {
                            let exists = p
                                .advance()
                                .expect_invariant("EXISTS keyword consumed after peek");
                            let exists_tid = p.last_token_id();
                            if_not_exists_span = Some(Span {
                                start: if_tok.span.start,
                                end: exists.span.end,
                            });
                            if_token_id = Some(if_tid);
                            not_token_id = Some(not_tid);
                            exists_token_id = Some(exists_tid);
                            span.end = exists.span.end;
                        }
                    }
                }
            }
        }
    }

    // Stream name (qualified identifier)
    let name_span = p.parse_qualified_name_span()?;
    span.end = name_span.end;

    // Check for CLONE variant (before TAG/COPY GRANTS)
    let mut clone_span: Option<Span> = None;
    if let Some(tok) = p.peek_non_trivia() {
        if matches!(tok.kind, TokenKind::Identifier { .. })
            && tok.lexeme(p.source).eq_ignore_ascii_case("CLONE")
        {
            let clone_start = p
                .advance()
                .expect_invariant("CLONE identifier consumed after match")
                .span
                .start;
            // Parse source stream name
            let source_name_span = p.parse_qualified_name_span()?;
            clone_span = Some(Span {
                start: clone_start,
                end: source_name_span.end,
            });
            span.end = source_name_span.end;

            // For CLONE variant, may have COPY GRANTS after
            let mut copy_grants_span: Option<Span> = None;
            if let Some(cg_tok) = p.peek_non_trivia() {
                if matches!(cg_tok.kind, TokenKind::Keyword(Keyword::Copy)) {
                    let copy_tok = p
                        .advance()
                        .expect_invariant("COPY keyword consumed after match");
                    if let Some(grants_tok) = p.peek_non_trivia() {
                        if matches!(grants_tok.kind, TokenKind::Keyword(Keyword::Grants)) {
                            let grants = p
                                .advance()
                                .expect_invariant("GRANTS keyword consumed after peek");
                            copy_grants_span = Some(Span {
                                start: copy_tok.span.start,
                                end: grants.span.end,
                            });
                            span.end = grants.span.end;
                        }
                    }
                }
            }

            // Build CST node for CLONE variant
            let syntax_node = SyntaxCreateStream {
                create_keyword: create_token_id,
                or_keyword: or_token_id,
                replace_keyword: replace_token_id,
                stream_keyword: stream_token_id,
                if_keyword: if_token_id,
                not_keyword: not_token_id,
                exists_keyword: exists_token_id,
                name_span,
                clone_span,
                tag_clause_span: None,
                copy_grants_span,
                on_keyword: None,
                source_type_span: None,
                source_name_span: None,
                time_travel_span: None,
                append_only_span: None,
                show_initial_rows_span: None,
                insert_only_span: None,
                comment_span: None,
                span,
            };
            let syntax_id = p.syntax_arena.alloc_create_stream(syntax_node);

            // Return CLONE variant
            let node = AstCreateStream {
                node_id: p.id_gen.next(),
                syntax_id: Some(syntax_id),
                span,
                create_span,
                or_replace_span,
                stream_span,
                if_not_exists_span,
                name_span,
                tag_clause_span: None,
                copy_grants_span,
                on_clause_span: None,
                source_type: None,
                source_name_span: None,
                time_travel_span: None,
                time_travel_kind: None,
                time_travel_option: None,
                append_only_span: None,
                show_initial_rows_span: None,
                insert_only_span: None,
                comment_span: None,
                clone_span,
            };
            return Ok(AstStmt::CreateStream(Box::new(node)));
        }
    }

    // Optional [ WITH ] TAG ( ... )
    let mut tag_clause_span: Option<Span> = None;
    if let Some(tok) = p.peek_non_trivia() {
        let has_with = matches!(tok.kind, TokenKind::Keyword(Keyword::With));
        let has_tag = matches!(tok.kind, TokenKind::Keyword(Keyword::Tag));

        if has_with || has_tag {
            let tag_start = tok.span.start;
            if has_with {
                p.advance()
                    .expect_invariant("WITH keyword consumed after match"); // consume WITH
            }

            if let Some(tag_tok) = p.peek_non_trivia() {
                if matches!(tag_tok.kind, TokenKind::Keyword(Keyword::Tag)) {
                    p.advance()
                        .expect_invariant("TAG keyword consumed after peek"); // consume TAG

                    // Parse ( tag_name = 'value' [, ...] )
                    if let Some(lparen) = p.peek_non_trivia() {
                        if matches!(lparen.kind, TokenKind::Punctuation(Punctuation::LParen)) {
                            p.advance()
                                .expect_invariant("LParen consumed after peek for tag clause");
                            let tag_end = parse_balanced_parens(p)?;
                            tag_clause_span = Some(Span {
                                start: tag_start,
                                end: tag_end,
                            });
                            span.end = tag_end;
                        }
                    }
                }
            }
        }
    }

    // Optional COPY GRANTS
    let mut copy_grants_span: Option<Span> = None;
    if let Some(tok) = p.peek_non_trivia() {
        if matches!(tok.kind, TokenKind::Keyword(Keyword::Copy)) {
            let copy_tok = p
                .advance()
                .expect_invariant("COPY keyword consumed after match");
            if let Some(grants_tok) = p.peek_non_trivia() {
                if matches!(grants_tok.kind, TokenKind::Keyword(Keyword::Grants)) {
                    let grants = p
                        .advance()
                        .expect_invariant("GRANTS keyword consumed after peek");
                    copy_grants_span = Some(Span {
                        start: copy_tok.span.start,
                        end: grants.span.end,
                    });
                    span.end = grants.span.end;
                }
            }
        }
    }

    // ON <source_type> <source_name>
    let mut on_clause_span: Option<Span> = None;
    let mut on_keyword: Option<TokenId> = None;
    let mut source_type: Option<StreamSourceType> = None;
    let mut source_type_span: Option<Span> = None;
    let mut source_name_span: Option<Span> = None;

    if let Some(on_tok) = p.peek_non_trivia() {
        if matches!(on_tok.kind, TokenKind::Keyword(Keyword::On)) {
            let on_start = p
                .advance()
                .expect_invariant("ON keyword consumed after match")
                .span
                .start;
            on_keyword = Some(p.last_token_id());

            // Parse source type
            let (st, type_start, type_end) = parse_stream_source_type(p)?;
            source_type = Some(st);
            source_type_span = Some(Span {
                start: type_start,
                end: type_end,
            });

            // Parse source name
            let src_name = p.parse_qualified_name_span()?;
            source_name_span = Some(src_name);

            on_clause_span = Some(Span {
                start: on_start,
                end: type_end,
            });
            span.end = src_name.end;
        }
    }

    // Optional AT/BEFORE ( ... ) time travel clause
    let mut time_travel_span: Option<Span> = None;
    let mut time_travel_kind: Option<TimeTravelKind> = None;
    let mut time_travel_option: Option<TimeTravelOption> = None;

    if let Some(tok) = p.peek_non_trivia() {
        let is_at = matches!(tok.kind, TokenKind::Identifier { .. })
            && tok.lexeme(p.source).eq_ignore_ascii_case("AT");
        let is_before = matches!(tok.kind, TokenKind::Identifier { .. })
            && tok.lexeme(p.source).eq_ignore_ascii_case("BEFORE");

        if is_at || is_before {
            let tt_start = p
                .advance()
                .expect_invariant("AT/BEFORE identifier consumed after match")
                .span
                .start;
            time_travel_kind = Some(if is_at {
                TimeTravelKind::At
            } else {
                TimeTravelKind::Before
            });

            // Parse ( option => value )
            if let Some(lparen) = p.peek_non_trivia() {
                if matches!(lparen.kind, TokenKind::Punctuation(Punctuation::LParen)) {
                    p.advance()
                        .expect_invariant("LParen consumed after peek for time travel");

                    // Parse option (TIMESTAMP, OFFSET, STATEMENT, STREAM)
                    if let Some(opt_tok) = p.peek_non_trivia() {
                        if matches!(opt_tok.kind, TokenKind::Keyword(Keyword::Offset)) {
                            time_travel_option = Some(TimeTravelOption::Offset);
                            p.advance()
                                .expect_invariant("OFFSET keyword consumed after match");
                        } else if matches!(opt_tok.kind, TokenKind::Identifier { .. }) {
                            if opt_tok.lexeme(p.source).eq_ignore_ascii_case("TIMESTAMP") {
                                time_travel_option = Some(TimeTravelOption::Timestamp);
                                p.advance()
                                    .expect_invariant("TIMESTAMP identifier consumed after match");
                            } else if opt_tok.lexeme(p.source).eq_ignore_ascii_case("STATEMENT") {
                                time_travel_option = Some(TimeTravelOption::Statement);
                                p.advance()
                                    .expect_invariant("STATEMENT identifier consumed after match");
                            } else if opt_tok.lexeme(p.source).eq_ignore_ascii_case("STREAM") {
                                time_travel_option = Some(TimeTravelOption::Stream);
                                p.advance()
                                    .expect_invariant("STREAM identifier consumed after match");
                            }
                        }
                    }

                    // Consume => and value expression until )
                    let tt_end = parse_balanced_parens(p)?;
                    time_travel_span = Some(Span {
                        start: tt_start,
                        end: tt_end,
                    });
                    span.end = tt_end;
                }
            }
        }
    }

    // Optional properties: APPEND_ONLY, SHOW_INITIAL_ROWS, INSERT_ONLY, COMMENT
    let mut append_only_span: Option<Span> = None;
    let mut show_initial_rows_span: Option<Span> = None;
    let mut insert_only_span: Option<Span> = None;
    let mut comment_span: Option<Span> = None;

    while let Some(tok) = p.peek_non_trivia() {
        // Check for statement termination
        if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Semi)) {
            break;
        }
        if matches!(tok.kind, TokenKind::Eof) {
            break;
        }

        // APPEND_ONLY = TRUE|FALSE
        if matches!(tok.kind, TokenKind::Identifier { .. })
            && tok.lexeme(p.source).eq_ignore_ascii_case("APPEND_ONLY")
        {
            let prop_start = p
                .advance()
                .expect_invariant("APPEND_ONLY identifier consumed after match")
                .span
                .start;
            let prop_end = consume_property_value(p)?;
            append_only_span = Some(Span {
                start: prop_start,
                end: prop_end,
            });
            span.end = prop_end;
            continue;
        }

        // SHOW_INITIAL_ROWS = TRUE|FALSE
        if matches!(tok.kind, TokenKind::Identifier { .. })
            && tok
                .lexeme(p.source)
                .eq_ignore_ascii_case("SHOW_INITIAL_ROWS")
        {
            let prop_start = p
                .advance()
                .expect_invariant("SHOW_INITIAL_ROWS identifier consumed after match")
                .span
                .start;
            let prop_end = consume_property_value(p)?;
            show_initial_rows_span = Some(Span {
                start: prop_start,
                end: prop_end,
            });
            span.end = prop_end;
            continue;
        }

        // INSERT_ONLY = TRUE|FALSE
        if matches!(tok.kind, TokenKind::Identifier { .. })
            && tok.lexeme(p.source).eq_ignore_ascii_case("INSERT_ONLY")
        {
            let prop_start = p
                .advance()
                .expect_invariant("INSERT_ONLY identifier consumed after match")
                .span
                .start;
            let prop_end = consume_property_value(p)?;
            insert_only_span = Some(Span {
                start: prop_start,
                end: prop_end,
            });
            span.end = prop_end;
            continue;
        }

        // COMMENT = '...'
        if matches!(tok.kind, TokenKind::Keyword(Keyword::Comment)) {
            let prop_start = p
                .advance()
                .expect_invariant("COMMENT keyword consumed after match")
                .span
                .start;
            let prop_end = consume_property_value(p)?;
            comment_span = Some(Span {
                start: prop_start,
                end: prop_end,
            });
            span.end = prop_end;
            continue;
        }

        // Unknown token - stop parsing properties
        break;
    }

    // Build CST node
    let syntax_node = SyntaxCreateStream {
        create_keyword: create_token_id,
        or_keyword: or_token_id,
        replace_keyword: replace_token_id,
        stream_keyword: stream_token_id,
        if_keyword: if_token_id,
        not_keyword: not_token_id,
        exists_keyword: exists_token_id,
        name_span,
        clone_span,
        tag_clause_span,
        copy_grants_span,
        on_keyword,
        source_type_span,
        source_name_span,
        time_travel_span,
        append_only_span,
        show_initial_rows_span,
        insert_only_span,
        comment_span,
        span,
    };
    let syntax_id = p.syntax_arena.alloc_create_stream(syntax_node);

    let node = AstCreateStream {
        node_id: p.id_gen.next(),
        syntax_id: Some(syntax_id),
        span,
        create_span,
        or_replace_span,
        stream_span,
        if_not_exists_span,
        name_span,
        tag_clause_span,
        copy_grants_span,
        on_clause_span,
        source_type,
        source_name_span,
        time_travel_span,
        time_travel_kind,
        time_travel_option,
        append_only_span,
        show_initial_rows_span,
        insert_only_span,
        comment_span,
        clone_span,
    };

    Ok(AstStmt::CreateStream(Box::new(node)))
}

/// Parse stream source type after ON keyword.
/// Returns (StreamSourceType, start_pos, end_pos)
fn parse_stream_source_type(p: &mut Parser<'_>) -> ParseResult<(StreamSourceType, u32, u32)> {
    let tok = p.peek_non_trivia().ok_or_else(|| {
        ParseError::new(
            p.current_span(),
            ParseErrorKind::InvalidStatement {
                message: "Expected source type after ON".to_string(),
            },
        )
    })?;

    // Check for multi-word types first (EVENT TABLE, EXTERNAL TABLE, DYNAMIC TABLE)
    if matches!(tok.kind, TokenKind::Identifier { .. }) {
        if tok.lexeme(p.source).eq_ignore_ascii_case("EVENT") {
            let event_tok = p
                .advance()
                .expect_invariant("EVENT identifier consumed after match");
            // Expect TABLE
            if let Some(table_tok) = p.peek_non_trivia() {
                if matches!(table_tok.kind, TokenKind::Keyword(Keyword::Table)) {
                    let table = p
                        .advance()
                        .expect_invariant("TABLE keyword consumed after peek");
                    return Ok((
                        StreamSourceType::EventTable,
                        event_tok.span.start,
                        table.span.end,
                    ));
                }
            }
            return Err(ParseError::new(
                event_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: "Expected TABLE after EVENT".to_string(),
                },
            ));
        }

        if tok.lexeme(p.source).eq_ignore_ascii_case("EXTERNAL") {
            let external_tok = p
                .advance()
                .expect_invariant("EXTERNAL identifier consumed after match");
            // Expect TABLE
            if let Some(table_tok) = p.peek_non_trivia() {
                if matches!(table_tok.kind, TokenKind::Keyword(Keyword::Table)) {
                    let table = p
                        .advance()
                        .expect_invariant("TABLE keyword consumed after peek");
                    return Ok((
                        StreamSourceType::ExternalTable,
                        external_tok.span.start,
                        table.span.end,
                    ));
                }
            }
            return Err(ParseError::new(
                external_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: "Expected TABLE after EXTERNAL".to_string(),
                },
            ));
        }

        if tok.lexeme(p.source).eq_ignore_ascii_case("DYNAMIC") {
            let dynamic_tok = p
                .advance()
                .expect_invariant("DYNAMIC identifier consumed after match");
            // Expect TABLE
            if let Some(table_tok) = p.peek_non_trivia() {
                if matches!(table_tok.kind, TokenKind::Keyword(Keyword::Table)) {
                    let table = p
                        .advance()
                        .expect_invariant("TABLE keyword consumed after peek");
                    return Ok((
                        StreamSourceType::DynamicTable,
                        dynamic_tok.span.start,
                        table.span.end,
                    ));
                }
            }
            return Err(ParseError::new(
                dynamic_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: "Expected TABLE after DYNAMIC".to_string(),
                },
            ));
        }
    }

    // Single keyword types: TABLE, VIEW, STAGE
    if matches!(tok.kind, TokenKind::Keyword(Keyword::Table)) {
        let table = p
            .advance()
            .expect_invariant("TABLE keyword consumed after match");
        return Ok((StreamSourceType::Table, table.span.start, table.span.end));
    }

    if matches!(tok.kind, TokenKind::Keyword(Keyword::View)) {
        let view = p
            .advance()
            .expect_invariant("VIEW keyword consumed after match");
        return Ok((StreamSourceType::View, view.span.start, view.span.end));
    }

    if matches!(tok.kind, TokenKind::Keyword(Keyword::Stage)) {
        let stage = p
            .advance()
            .expect_invariant("STAGE keyword consumed after match");
        return Ok((StreamSourceType::Stage, stage.span.start, stage.span.end));
    }

    Err(ParseError::new(
        tok.span,
        ParseErrorKind::InvalidStatement {
            message: format!(
                "Expected source type (TABLE, VIEW, STAGE, EVENT TABLE, EXTERNAL TABLE, DYNAMIC TABLE), found '{}'",
                tok.lexeme(p.source)
            ),
        },
    ))
}

/// Consume balanced parentheses, returning the end position (after closing paren)
fn parse_balanced_parens(p: &mut Parser<'_>) -> ParseResult<u32> {
    let mut depth = 1;
    let mut end = p.current_span().end;

    while depth > 0 {
        if let Some(tok) = p.advance() {
            end = tok.span.end;
            match tok.kind {
                TokenKind::Punctuation(Punctuation::LParen) => depth += 1,
                TokenKind::Punctuation(Punctuation::RParen) => depth -= 1,
                TokenKind::Eof => {
                    return Err(ParseError::new(
                        tok.span,
                        ParseErrorKind::InvalidStatement {
                            message: "Unbalanced parentheses".to_string(),
                        },
                    ));
                }
                _ => {}
            }
        } else {
            return Err(ParseError::new(
                p.current_span(),
                ParseErrorKind::InvalidStatement {
                    message: "Unexpected end of input in parentheses".to_string(),
                },
            ));
        }
    }

    Ok(end)
}

/// Consume property value (= value) and return end position
fn consume_property_value(p: &mut Parser<'_>) -> ParseResult<u32> {
    // Expect =
    if let Some(eq_tok) = p.peek_non_trivia() {
        if matches!(eq_tok.kind, TokenKind::Operator(Operator::Eq)) {
            p.advance()
                .expect_invariant("Eq operator consumed after peek");
        }
    }

    // Consume value token(s) - could be boolean, string, or expression
    let mut end = p.current_span().end;
    if let Some(val_tok) = p.peek_non_trivia() {
        // Handle parenthesized values
        if matches!(val_tok.kind, TokenKind::Punctuation(Punctuation::LParen)) {
            p.advance()
                .expect_invariant("LParen consumed after peek for property value");
            end = parse_balanced_parens(p)?;
        } else {
            // Simple value
            let v = p.advance().ok_or_else(|| {
                ParseError::new(
                    p.current_span(),
                    ParseErrorKind::InvalidStatement {
                        message: "Expected property value".to_string(),
                    },
                )
            })?;
            end = v.span.end;
        }
    }

    Ok(end)
}

// ============================================================================
// DROP STREAM
// ============================================================================

/// Parse DROP STREAM statement.
///
/// Entry point expects parser positioned at DROP token.
pub(crate) fn try_parse_drop_stream(p: &mut Parser<'_>) -> ParseResult<AstStmt> {
    // Consume DROP keyword
    let drop_tok = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["DROP".to_string()])?;
    let drop_span = drop_tok.span;
    let drop_token_id = p.last_token_id();

    // STREAM identifier (NOT a keyword)
    let stream_tok = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["STREAM".to_string()])?;
    if !stream_tok.lexeme(p.source).eq_ignore_ascii_case("STREAM") {
        return Err(ParseError::new(
            stream_tok.span,
            ParseErrorKind::InvalidStatement {
                message: format!("Expected STREAM, found '{}'", stream_tok.lexeme(p.source)),
            },
        ));
    }
    let stream_span = stream_tok.span;
    let stream_token_id = p.last_token_id();

    // Optional IF EXISTS
    let mut if_exists_span: Option<Span> = None;
    let mut if_token_id: Option<TokenId> = None;
    let mut exists_token_id: Option<TokenId> = None;
    if let Some(tok) = p.peek_non_trivia() {
        if matches!(tok.kind, TokenKind::Keyword(Keyword::If)) {
            let if_tok = p
                .advance()
                .expect_invariant("IF keyword consumed after match in DROP STREAM");
            let if_tid = p.last_token_id();
            if let Some(exists_tok) = p.peek_non_trivia() {
                if matches!(exists_tok.kind, TokenKind::Keyword(Keyword::Exists)) {
                    let exists = p
                        .advance()
                        .expect_invariant("EXISTS keyword consumed after peek in DROP STREAM");
                    let exists_tid = p.last_token_id();
                    if_exists_span = Some(Span {
                        start: if_tok.span.start,
                        end: exists.span.end,
                    });
                    if_token_id = Some(if_tid);
                    exists_token_id = Some(exists_tid);
                }
            }
        }
    }

    // Stream name (qualified identifier)
    let name_span = p.parse_qualified_name_span()?;

    // Statement span
    let stmt_span = Span {
        start: drop_span.start,
        end: name_span.end,
    };

    // Build CST node
    let syntax_node = SyntaxDropStream {
        drop_keyword: drop_token_id,
        stream_keyword: stream_token_id,
        if_keyword: if_token_id,
        exists_keyword: exists_token_id,
        name_span,
        span: stmt_span,
    };
    let syntax_id = p.syntax_arena.alloc_drop_stream(syntax_node);

    let node = AstDropStream {
        node_id: p.id_gen.next(),
        syntax_id: Some(syntax_id),
        span: stmt_span,
        drop_span,
        stream_span,
        if_exists_span,
        name_span,
    };

    Ok(AstStmt::DropStream(Box::new(node)))
}

// ============================================================================
// ALTER STREAM
// ============================================================================

/// Parse ALTER STREAM statement.
///
/// Entry point expects parser positioned at ALTER token.
pub(crate) fn try_parse_alter_stream(p: &mut Parser<'_>) -> ParseResult<AstStmt> {
    // Consume ALTER keyword
    let alter_tok = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["ALTER".to_string()])?;
    let alter_span = alter_tok.span;
    let alter_token_id = p.last_token_id();

    // STREAM identifier (NOT a keyword)
    let stream_tok = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["STREAM".to_string()])?;
    if !stream_tok.lexeme(p.source).eq_ignore_ascii_case("STREAM") {
        return Err(ParseError::new(
            stream_tok.span,
            ParseErrorKind::InvalidStatement {
                message: format!("Expected STREAM, found '{}'", stream_tok.lexeme(p.source)),
            },
        ));
    }
    let stream_span = stream_tok.span;
    let stream_token_id = p.last_token_id();

    // Optional IF EXISTS
    let mut if_exists_span: Option<Span> = None;
    let mut if_token_id: Option<TokenId> = None;
    let mut exists_token_id: Option<TokenId> = None;
    if let Some(tok) = p.peek_non_trivia() {
        if matches!(tok.kind, TokenKind::Keyword(Keyword::If)) {
            let if_tok = p
                .advance()
                .expect_invariant("IF keyword consumed after match in ALTER STREAM");
            let if_tid = p.last_token_id();
            if let Some(exists_tok) = p.peek_non_trivia() {
                if matches!(exists_tok.kind, TokenKind::Keyword(Keyword::Exists)) {
                    let exists = p
                        .advance()
                        .expect_invariant("EXISTS keyword consumed after peek in ALTER STREAM");
                    let exists_tid = p.last_token_id();
                    if_exists_span = Some(Span {
                        start: if_tok.span.start,
                        end: exists.span.end,
                    });
                    if_token_id = Some(if_tid);
                    exists_token_id = Some(exists_tid);
                }
            }
        }
    }

    // Stream name (qualified identifier)
    let name_span = p.parse_qualified_name_span()?;

    // Parse action (SET/UNSET)
    let action = parse_alter_stream_action(p)?;
    let action_span = action.span;

    // Statement span
    let stmt_span = Span {
        start: alter_span.start,
        end: action_span.end,
    };

    // Build CST action node
    let action_syntax = SyntaxAlterStreamAction { span: action_span };
    let action_syntax_id = p.syntax_arena.alloc_alter_stream_action(action_syntax);

    // Build CST statement node
    let syntax_node = SyntaxAlterStreamStmt {
        alter_keyword: alter_token_id,
        stream_keyword: stream_token_id,
        if_keyword: if_token_id,
        exists_keyword: exists_token_id,
        name_span,
        action_id: action_syntax_id,
        span: stmt_span,
    };
    let syntax_id = p.syntax_arena.alloc_alter_stream_stmt(syntax_node);

    let node = AstAlterStream {
        node_id: p.id_gen.next(),
        syntax_id: Some(syntax_id),
        span: stmt_span,
        alter_span,
        stream_span,
        if_exists_span,
        name_span,
        action_span,
        action,
    };

    Ok(AstStmt::AlterStream(Box::new(node)))
}

/// Parse ALTER STREAM action (SET/UNSET COMMENT or TAG)
fn parse_alter_stream_action(p: &mut Parser<'_>) -> ParseResult<AstAlterStreamAction> {
    let tok = p.peek_non_trivia().ok_or_else(|| {
        ParseError::new(
            p.current_span(),
            ParseErrorKind::InvalidStatement {
                message: "Expected SET or UNSET after stream name".to_string(),
            },
        )
    })?;

    if matches!(tok.kind, TokenKind::Keyword(Keyword::Set)) {
        let set_tok = p
            .advance()
            .expect_invariant("SET keyword consumed after match");
        let set_span = set_tok.span;

        // SET COMMENT or SET TAG
        if let Some(next) = p.peek_non_trivia() {
            if matches!(next.kind, TokenKind::Keyword(Keyword::Comment)) {
                // SET COMMENT = '...'
                let comment_tok = p
                    .advance()
                    .expect_invariant("COMMENT keyword consumed after peek in SET");
                let comment_span = comment_tok.span;

                // Consume = and value
                let value_end = consume_property_value(p)?;
                let value_span = Span {
                    start: comment_span.end,
                    end: value_end,
                };

                let action_span = Span {
                    start: set_span.start,
                    end: value_end,
                };

                return Ok(AstAlterStreamAction {
                    span: action_span,
                    kind: AstAlterStreamActionKind::SetComment {
                        set_span,
                        comment_span,
                        value_span,
                    },
                });
            } else if matches!(next.kind, TokenKind::Keyword(Keyword::Tag)) {
                // SET TAG tag_name = 'value' [, ...]
                let tag_tok = p
                    .advance()
                    .expect_invariant("TAG keyword consumed after peek in SET");
                let tag_span = tag_tok.span;

                // Parse tag assignments until end of statement
                let assignments_start = p.current_span().start;
                let mut assignments_end = assignments_start;

                while let Some(peek) = p.peek_non_trivia() {
                    if matches!(peek.kind, TokenKind::Punctuation(Punctuation::Semi))
                        || matches!(peek.kind, TokenKind::Eof)
                    {
                        break;
                    }
                    // Consume token
                    let t = p
                        .advance()
                        .expect_invariant("tag assignment token consumed after peek");
                    assignments_end = t.span.end;
                }

                let assignments_span = Span {
                    start: assignments_start,
                    end: assignments_end,
                };

                let action_span = Span {
                    start: set_span.start,
                    end: assignments_end,
                };

                return Ok(AstAlterStreamAction {
                    span: action_span,
                    kind: AstAlterStreamActionKind::SetTag {
                        set_span,
                        tag_span,
                        assignments_span,
                    },
                });
            }
        }

        return Err(ParseError::new(
            set_span,
            ParseErrorKind::InvalidStatement {
                message: "Expected COMMENT or TAG after SET".to_string(),
            },
        ));
    } else if matches!(tok.kind, TokenKind::Keyword(Keyword::Unset)) {
        let unset_tok = p
            .advance()
            .expect_invariant("UNSET keyword consumed after match");
        let unset_span = unset_tok.span;

        // UNSET COMMENT or UNSET TAG
        if let Some(next) = p.peek_non_trivia() {
            if matches!(next.kind, TokenKind::Keyword(Keyword::Comment)) {
                // UNSET COMMENT
                let comment_tok = p
                    .advance()
                    .expect_invariant("COMMENT keyword consumed after peek in UNSET");
                let comment_span = comment_tok.span;

                let action_span = Span {
                    start: unset_span.start,
                    end: comment_span.end,
                };

                return Ok(AstAlterStreamAction {
                    span: action_span,
                    kind: AstAlterStreamActionKind::UnsetComment {
                        unset_span,
                        comment_span,
                    },
                });
            } else if matches!(next.kind, TokenKind::Keyword(Keyword::Tag)) {
                // UNSET TAG tag_name [, ...]
                let tag_tok = p
                    .advance()
                    .expect_invariant("TAG keyword consumed after peek in UNSET");
                let tag_span = tag_tok.span;

                // Parse tag names until end of statement
                let tags_start = p.current_span().start;
                let mut tags_end = tags_start;

                while let Some(peek) = p.peek_non_trivia() {
                    if matches!(peek.kind, TokenKind::Punctuation(Punctuation::Semi))
                        || matches!(peek.kind, TokenKind::Eof)
                    {
                        break;
                    }
                    // Consume token
                    let t = p
                        .advance()
                        .expect_invariant("tag name token consumed after peek");
                    tags_end = t.span.end;
                }

                let tags_span = Span {
                    start: tags_start,
                    end: tags_end,
                };

                let action_span = Span {
                    start: unset_span.start,
                    end: tags_end,
                };

                return Ok(AstAlterStreamAction {
                    span: action_span,
                    kind: AstAlterStreamActionKind::UnsetTag {
                        unset_span,
                        tag_span,
                        tags_span,
                    },
                });
            }
        }

        return Err(ParseError::new(
            unset_span,
            ParseErrorKind::InvalidStatement {
                message: "Expected COMMENT or TAG after UNSET".to_string(),
            },
        ));
    }

    Err(ParseError::new(
        tok.span,
        ParseErrorKind::InvalidStatement {
            message: format!(
                "Expected SET or UNSET for ALTER STREAM action, found '{}'",
                tok.lexeme(p.source)
            ),
        },
    ))
}
