// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Parser for the Amazon Redshift `COPY` (bulk load) statement.
//!
//! ```text
//! COPY table_name [ ( column [, ...] ) ]
//!   FROM { 's3://bucket/prefix' | 'emr://…' | 'ssh://…' | 'dynamodb://…' }
//!   [ IAM_ROLE 'arn:aws:iam::…:role/…'
//!   | ACCESS_KEY_ID '…' SECRET_ACCESS_KEY '…' [ SESSION_TOKEN '…' ]
//!   | CREDENTIALS 'aws_access_key_id=…;aws_secret_access_key=…' ]
//!   [ <other options: FORMAT AS PARQUET, GZIP, REGION '…', MANIFEST, … > ]
//! ```
//!
//! The load counterpart to [`super::unload`]. Distinct from PostgreSQL's
//! server-side `COPY` (`pg_copy`) because Redshift COPY carries an inline cloud
//! authorization clause: its credentials are decomposed into typed
//! [`AstStageCredentialOption`] entries via the shared
//! `Parser::parse_redshift_credential_trailer` so secrets are never
//! swallowed as an opaque span.

use crate::ast::{AstStageCredentialOption, AstStmt};
use crate::error::{ParseError, ParseResult, ParseResultExt};
use crate::lexer::token::LiteralKind;
use crate::lexer::{Keyword, Punctuation, Span, TokenKind};
use crate::parser::core::Parser;
use crate::parser::create_stage::unquote_sql_string;

impl<'a> Parser<'a> {
    /// Parse a Redshift `COPY table [ (cols) ] FROM 'source' [auth] [options]`.
    ///
    /// Dispatched on `Keyword::Copy` when the dialect reports
    /// [`crate::dialect::Dialect::copy_has_inline_credentials`] (Amazon Redshift).
    pub(crate) fn try_parse_redshift_copy_stmt(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("redshift_copy")?;
        let start_span = self.current_span();

        // COPY keyword.
        let copy_tok = self
            .advance()
            .ok_or_eof(start_span, vec!["COPY".to_string()])?;
        let start = copy_tok.span.start;

        // table_name [ ( column [, ...] ) ]
        let name_span = self.parse_qualified_name_span()?;
        let mut table_end = name_span.end;
        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Punctuation(Punctuation::LParen)) {
                let cols_span = self.consume_balanced_parens()?;
                table_end = cols_span.end;
            }
        }
        let table_span = Span {
            start: name_span.start,
            end: table_end,
        };

        // FROM 'source'
        let from_tok = self
            .peek_non_trivia()
            .ok_or_eof(self.current_span(), vec!["FROM".to_string()])?;
        if !matches!(from_tok.kind, TokenKind::Keyword(Keyword::From)) {
            return Err(ParseError::unexpected_token(
                from_tok.span,
                vec!["FROM".to_string()],
                Parser::token_description(from_tok, self.source),
            ));
        }
        let from_start = from_tok.span.start;
        self.advance(); // FROM
        let src_tok = self.advance().ok_or_eof(
            self.current_span(),
            vec!["COPY data source string".to_string()],
        )?;
        let location_url = if matches!(src_tok.kind, TokenKind::Literal(LiteralKind::String)) {
            Some(unquote_sql_string(src_tok.lexeme(self.source)))
        } else {
            None
        };
        let from_span = Span {
            start: from_start,
            end: src_tok.span.end,
        };
        let mut end = src_tok.span.end;

        // Authorization / option trailer (shared with UNLOAD).
        let mut credentials: Vec<AstStageCredentialOption> = Vec::new();
        end = self.parse_redshift_credential_trailer(end, &mut credentials)?;
        Ok(AstStmt::RedshiftCopy {
            node_id: self.id_gen.next(),
            span: Span { start, end },
            table_span,
            from_span,
            location_url,
            credentials,
        })
    }
}
