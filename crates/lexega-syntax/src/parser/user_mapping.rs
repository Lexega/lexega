// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Parser for the SQL/MED `CREATE USER MAPPING` statement (PostgreSQL FDW).
//!
//! `CREATE USER MAPPING [IF NOT EXISTS] FOR { name | USER | CURRENT_USER
//!  | CURRENT_ROLE | SESSION_USER | PUBLIC } SERVER name
//!  [OPTIONS (key 'value' [, …])]`
//!
//! Attaches per-local-role credentials for a foreign server. Kept apart from
//! the `CREATE USER` (principal) parser, which would mislabel it as role
//! creation. Recognition lifts the
//! `FOR` target (and whether it is `PUBLIC`), the server name, and the OPTIONS
//! as a typed key / value-literal list. The remote password literal is
//! registered for output redaction, exactly as the principal parser does.
//!
//! Dispatched from the `CREATE USER` arm in `core.rs` when the token after
//! USER is the identifier `MAPPING`.
//!
//! Token reference (`--debug-tokens`, postgresql dialect):
//!   USER / MAPPING / SERVER / OPTIONS / PUBLIC / option keys → Identifier
//!   FOR / CURRENT_USER / IF / NOT / EXISTS                   → Keyword

use crate::ast::types::{
    AstAlterUserMapping, AstCreateUserMapping, AstDropUserMapping, AstStmt, AstUserMappingOption,
};
use crate::error::{ParseError, ParseErrorKind, ParseResult, ParseResultExt};
use crate::lexer::token::{LiteralKind, Token};
use crate::lexer::{Keyword, Punctuation, Span, TokenKind};
use crate::parser::core::Parser;
use crate::parser::principal::inner_literal_span;

/// Disambiguation guard: `{ CREATE | ALTER | DROP } USER MAPPING` is a SQL/MED
/// user mapping only when a `FOR` clause follows `MAPPING` (e.g. `CREATE USER
/// MAPPING [IF NOT EXISTS] FOR …`, `DROP USER MAPPING [IF EXISTS] FOR …`).
/// Without it, `… USER MAPPING` is an ordinary `… USER` whose user is named
/// `MAPPING` (e.g. on Snowflake, which has no FDW). This is a structural test —
/// no dialect branch — scanning significant tokens from `idx` (the
/// CREATE / ALTER / DROP position).
pub(crate) fn is_user_mapping_at(tokens: &[Token], idx: usize, source: &str) -> bool {
    // Collect up to the first 7 significant tokens: <verb> USER MAPPING
    // [IF [NOT] EXISTS] FOR.
    let mut sig = Vec::with_capacity(7);
    let mut i = idx;
    while i < tokens.len() && sig.len() < 7 {
        match tokens[i].kind {
            TokenKind::Eof => break,
            TokenKind::LineComment | TokenKind::BlockComment => {}
            _ => sig.push(i),
        }
        i += 1;
    }
    if sig.len() < 4 {
        return false;
    }
    let lex = |p: usize| tokens[sig[p]].lexeme(source);
    if !lex(1).eq_ignore_ascii_case("USER") || !lex(2).eq_ignore_ascii_case("MAPPING") {
        return false;
    }
    // Skip any IF / NOT / EXISTS keywords (covers both `IF NOT EXISTS` on
    // CREATE and `IF EXISTS` on DROP), then require FOR.
    let mut p = 3;
    while p < sig.len()
        && matches!(
            tokens[sig[p]].kind,
            TokenKind::Keyword(Keyword::If)
                | TokenKind::Keyword(Keyword::Not)
                | TokenKind::Keyword(Keyword::Exists)
        )
    {
        p += 1;
    }
    p < sig.len() && matches!(tokens[sig[p]].kind, TokenKind::Keyword(Keyword::For))
}

/// Option keys whose string-literal value is a secret and must be masked from
/// output surfaces. Matched on a lowercased `contains` so `sslpassword`,
/// `secret_access_key`, etc. are covered. Over-masking is safe: masking
/// only affects what is displayed, never what is parsed.
pub fn is_secret_option_key(key: &str) -> bool {
    let k = key.to_ascii_lowercase();
    k.contains("password") || k.contains("secret")
}

impl<'a> Parser<'a> {
    /// Consume the leading `{ CREATE | ALTER | DROP } USER MAPPING` keywords,
    /// returning the statement start offset.
    fn consume_user_mapping_prefix(&mut self, verb: &str) -> ParseResult<u32> {
        let verb_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec![verb.to_string()])?;
        let start = verb_tok.span.start;
        self.advance()
            .ok_or_eof(self.current_span(), vec!["USER".to_string()])?;
        self.advance()
            .ok_or_eof(self.current_span(), vec!["MAPPING".to_string()])?;
        Ok(start)
    }

    /// Parse `FOR <target> SERVER <name>`. Returns the `FOR`-target span,
    /// whether it is `PUBLIC`, and the server-name span.
    fn parse_user_mapping_for_server(&mut self, ctx: &str) -> ParseResult<(Span, bool, Span)> {
        let for_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["FOR".to_string()])?;
        if !matches!(for_tok.kind, TokenKind::Keyword(Keyword::For)) {
            return Err(ParseError::new(
                for_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: format!("Expected FOR after {ctx}"),
                },
            ));
        }
        let user_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["user".to_string()])?;
        let user_span = user_tok.span;
        let is_public = user_tok.lexeme(self.source).eq_ignore_ascii_case("PUBLIC");

        let server_kw = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["SERVER".to_string()])?;
        if !server_kw.lexeme(self.source).eq_ignore_ascii_case("SERVER") {
            return Err(ParseError::new(
                server_kw.span,
                ParseErrorKind::InvalidStatement {
                    message: format!("Expected SERVER in {ctx}"),
                },
            ));
        }
        let server_span = self.parse_qualified_name_span()?;
        Ok((user_span, is_public, server_span))
    }

    /// Read an optional `OPTIONS ( [ADD|SET|DROP] key ['value'] [, …] )` clause,
    /// collecting typed entries and registering secret values for redaction.
    /// `end` is advanced to the closing paren. A leading `ADD` / `SET` / `DROP`
    /// keyword on an entry (ALTER form) is consumed and not stored.
    fn read_user_mapping_options(
        &mut self,
        ctx: &str,
        end: &mut u32,
    ) -> ParseResult<Vec<AstUserMappingOption>> {
        let mut options = Vec::new();
        let has_options = self
            .peek_non_trivia()
            .map(|t| t.lexeme(self.source).eq_ignore_ascii_case("OPTIONS"))
            .unwrap_or(false);
        if !has_options {
            return Ok(options);
        }
        self.advance()
            .ok_or_eof(self.current_span(), vec!["OPTIONS".to_string()])?;
        let lparen = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["(".to_string()])?;
        if !matches!(lparen.kind, TokenKind::Punctuation(Punctuation::LParen)) {
            return Err(ParseError::new(
                lparen.span,
                ParseErrorKind::InvalidStatement {
                    message: format!("Expected ( after OPTIONS in {ctx}"),
                },
            ));
        }
        // `end` advances with each consumed token; the closing RParen iteration
        // sets the final statement end.
        loop {
            let tok = self
                .advance()
                .ok_or_eof(self.current_span(), vec![")".to_string()])?;
            *end = tok.span.end;
            match tok.kind {
                TokenKind::Punctuation(Punctuation::RParen) => break,
                TokenKind::Punctuation(Punctuation::Comma) => continue,
                TokenKind::Eof => break,
                _ => {}
            }
            // `tok` is either an ADD/SET/DROP op (ALTER) or the key. If it is an
            // op keyword, the key is the next token.
            let mut key_tok = tok;
            let lx = key_tok.lexeme(self.source);
            if lx.eq_ignore_ascii_case("ADD")
                || lx.eq_ignore_ascii_case("SET")
                || lx.eq_ignore_ascii_case("DROP")
            {
                key_tok = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["option".to_string()])?;
                *end = key_tok.span.end;
            }
            let key_span = key_tok.span;
            let key_lex = key_tok.lexeme(self.source);
            let value_literal_span = match self.peek_non_trivia() {
                Some(v) if matches!(v.kind, TokenKind::Literal(LiteralKind::String)) => {
                    Some(inner_literal_span(v.span, self.source))
                }
                _ => None,
            };
            if let Some(inner) = value_literal_span {
                if is_secret_option_key(key_lex) {
                    self.redaction_spans.push(inner);
                }
            }
            // A rendered placeholder is not a statically-known value — drop
            // the capture (redaction above still applies).
            let value_literal_span =
                value_literal_span.filter(|s| !self.span_overlaps_placeholder(*s));
            options.push(AstUserMappingOption {
                key_span,
                value_literal_span,
            });
            // Consume the value token (if any) so the next turn starts at a
            // comma or the closing paren.
            if let Some(v) = self.peek_non_trivia() {
                if !matches!(v.kind, TokenKind::Punctuation(Punctuation::RParen)) {
                    self.advance()
                        .ok_or_eof(self.current_span(), vec![")".to_string()])?;
                }
            }
        }
        Ok(options)
    }

    pub(crate) fn try_parse_create_user_mapping(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("create_user_mapping")?;

        (|| {
            let create_span = self.current_span();
            let start = self.consume_user_mapping_prefix("CREATE")?;
            let if_not_exists = self.parse_optional_if_not_exists()?.is_some();
            let (user_span, is_public, server_span) =
                self.parse_user_mapping_for_server("CREATE USER MAPPING")?;
            let mut end = server_span.end;
            let options = self.read_user_mapping_options("CREATE USER MAPPING", &mut end)?;
            Ok(AstStmt::CreateUserMapping(Box::new(AstCreateUserMapping {
                node_id: self.id_gen.next(),
                span: Span { start, end },
                create_span,
                if_not_exists,
                user_span,
                is_public,
                server_span,
                options,
            })))
        })()
    }

    pub(crate) fn try_parse_alter_user_mapping(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("alter_user_mapping")?;

        (|| {
            let alter_span = self.current_span();
            let start = self.consume_user_mapping_prefix("ALTER")?;
            let (user_span, is_public, server_span) =
                self.parse_user_mapping_for_server("ALTER USER MAPPING")?;
            let mut end = server_span.end;
            let options = self.read_user_mapping_options("ALTER USER MAPPING", &mut end)?;
            Ok(AstStmt::AlterUserMapping(Box::new(AstAlterUserMapping {
                node_id: self.id_gen.next(),
                span: Span { start, end },
                alter_span,
                user_span,
                is_public,
                server_span,
                options,
            })))
        })()
    }

    pub(crate) fn try_parse_drop_user_mapping(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("drop_user_mapping")?;

        (|| {
            let drop_span = self.current_span();
            let start = self.consume_user_mapping_prefix("DROP")?;
            let if_exists = self.parse_optional_if_exists()?.is_some();
            let (user_span, is_public, server_span) =
                self.parse_user_mapping_for_server("DROP USER MAPPING")?;
            Ok(AstStmt::DropUserMapping(Box::new(AstDropUserMapping {
                node_id: self.id_gen.next(),
                span: Span {
                    start,
                    end: server_span.end,
                },
                drop_span,
                if_exists,
                user_span,
                is_public,
                server_span,
            })))
        })()
    }
}
