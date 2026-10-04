// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Parser for MSSQL SQL Server 2025 statement types:
//!   - CREATE/ALTER/DROP EXTERNAL MODEL
//!   - CREATE VECTOR INDEX (MSSQL variant with WITH options)
//!   - CREATE LOGIN (with FROM EXTERNAL PROVIDER and OBJECT_ID)
//!   - CREATE USER (with FROM EXTERNAL PROVIDER, FOR LOGIN, WITHOUT LOGIN)

use crate::ast::types::{
    AstMssqlAlterExternalModel, AstMssqlCreateExternalModel, AstMssqlCreateVectorIndex,
    AstMssqlDropExternalModel, AstMssqlPrincipalSource,
};
use crate::ast::AstStmt;
use crate::error::{ParseError, ParseResult, ParseResultExt};
use crate::lexer::{Keyword, Punctuation, Span, TokenKind};
use crate::parser::core::Parser;

/// Peek the lexemes of up to two non-trivia tokens starting at the
/// parser's current cursor without consuming. Returns `(first, second)`
/// where each entry is the source lexeme of the corresponding token,
/// or `None` if not present.
fn peek_two_lexemes<'a>(p: &mut Parser<'a>) -> (Option<&'a str>, Option<&'a str>) {
    // peek_non_trivia advances the internal cursor over trivia so the
    // first non-trivia token sits at `p.idx`. The second is the next
    // non-trivia/non-EOF/non-comment token in the underlying slice.
    let first = match p.peek_non_trivia() {
        Some(t) => Some(t.lexeme(p.source)),
        None => return (None, None),
    };
    let mut idx = p.idx + 1;
    while idx < p.tokens.len() {
        let tok = &p.tokens[idx];
        match tok.kind {
            TokenKind::Eof | TokenKind::LineComment | TokenKind::BlockComment => {
                idx += 1;
                continue;
            }
            _ => return (first, Some(tok.lexeme(p.source))),
        }
    }
    (first, None)
}

impl<'a> Parser<'a> {
    /// Classify the source clause that follows the principal name in
    /// `CREATE LOGIN <name>` / `CREATE USER <name>`. Peeks the next one
    /// or two non-trivia tokens without consuming.
    ///
    /// The MSSQL parser is one of the two legitimate text→typed
    /// conversion sites in Lexega. All downstream layers dispatch on
    /// the returned typed variant.
    pub(crate) fn classify_mssql_principal_source(&mut self) -> AstMssqlPrincipalSource {
        let (a, b) = peek_two_lexemes(self);
        match (a, b) {
            (Some(x), _) if x.eq_ignore_ascii_case("WITHOUT") => {
                AstMssqlPrincipalSource::WithoutLogin
            }
            (Some(x), Some(y))
                if x.eq_ignore_ascii_case("FOR") && y.eq_ignore_ascii_case("LOGIN") =>
            {
                AstMssqlPrincipalSource::ForLogin
            }
            (Some(x), Some(y))
                if x.eq_ignore_ascii_case("FROM") && y.eq_ignore_ascii_case("EXTERNAL") =>
            {
                AstMssqlPrincipalSource::FromExternalProvider
            }
            (Some(x), Some(y))
                if x.eq_ignore_ascii_case("FROM") && y.eq_ignore_ascii_case("CERTIFICATE") =>
            {
                AstMssqlPrincipalSource::FromCertificate
            }
            (Some(x), Some(y))
                if x.eq_ignore_ascii_case("FROM") && y.eq_ignore_ascii_case("ASYMMETRIC") =>
            {
                AstMssqlPrincipalSource::FromAsymmetricKey
            }
            (Some(x), Some(y))
                if x.eq_ignore_ascii_case("FROM") && y.eq_ignore_ascii_case("WINDOWS") =>
            {
                AstMssqlPrincipalSource::FromWindows
            }
            (Some(x), Some(y))
                if x.eq_ignore_ascii_case("WITH") && y.eq_ignore_ascii_case("PASSWORD") =>
            {
                AstMssqlPrincipalSource::WithPassword
            }
            _ => AstMssqlPrincipalSource::Unparsed,
        }
    }
}

impl<'a> Parser<'a> {
    // ───────────────────────────────────────────────────────────────
    // Balanced parenthesis span helper (reusable for WITH/SET options)
    // ───────────────────────────────────────────────────────────────

    /// Consume a balanced parenthesized block and return the span covering
    /// everything including the opening and closing parens.
    fn mssql_parse_paren_content(&mut self) -> ParseResult<Span> {
        let lparen = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["(".to_string()])?;
        if !matches!(lparen.kind, TokenKind::Punctuation(Punctuation::LParen)) {
            return Err(ParseError::invalid_statement(
                lparen.span,
                "expected opening parenthesis".to_string(),
            ));
        }
        let start = lparen.span.start;
        let mut end = lparen.span.end;
        let mut depth = 1u32;

        while depth > 0 {
            let tok = self
                .advance()
                .ok_or_eof(self.current_span(), vec![")".to_string()])?;
            match tok.kind {
                TokenKind::Punctuation(Punctuation::LParen) => depth += 1,
                TokenKind::Punctuation(Punctuation::RParen) => depth -= 1,
                _ => {}
            }
            end = tok.span.end;
        }

        Ok(Span { start, end })
    }

    // ───────────────────────────────────────────────────────────────
    // CREATE EXTERNAL MODEL name [AUTHORIZATION owner] WITH (options)
    // ───────────────────────────────────────────────────────────────

    /// Parse `CREATE EXTERNAL MODEL name [AUTHORIZATION owner] WITH (options)`.
    ///
    /// Called when `CREATE` is the current token and the dispatcher has confirmed
    /// that `EXTERNAL MODEL` follows.
    pub(crate) fn try_parse_mssql_create_external_model(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("mssql_create_external_model")?;

        // CREATE
        let create_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["CREATE".to_string()])?;
        let start = create_tok.span.start;

        // EXTERNAL (Identifier)
        self.advance(); // EXTERNAL

        // MODEL (Identifier)
        let model_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["MODEL".to_string()])?;
        let keyword_span = Span {
            start,
            end: model_tok.span.end,
        };

        // Model name
        let name_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["model_name".to_string()])?;
        let name_span = name_tok.span;

        // Optional AUTHORIZATION owner
        let mut authorization_span = None;
        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Identifier { .. })
                && tok
                    .lexeme(self.source)
                    .eq_ignore_ascii_case("AUTHORIZATION")
            {
                let auth_start = tok.span.start;
                self.advance(); // AUTHORIZATION
                let owner_tok = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["owner_name".to_string()])?;
                authorization_span = Some(Span {
                    start: auth_start,
                    end: owner_tok.span.end,
                });
            }
        }

        // WITH (options) — required
        let with_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["WITH".to_string()])?;
        if !matches!(with_tok.kind, TokenKind::Keyword(Keyword::With)) {
            return Err(ParseError::invalid_statement(
                with_tok.span,
                format!("expected WITH, found '{}'", with_tok.lexeme(self.source)),
            ));
        }
        let with_start = with_tok.span.start;
        let paren_span = self.mssql_parse_paren_content()?;
        let with_options_span = Span {
            start: with_start,
            end: paren_span.end,
        };

        let span = Span {
            start,
            end: with_options_span.end,
        };
        Ok(AstStmt::MssqlCreateExternalModel(Box::new(
            AstMssqlCreateExternalModel {
                node_id: self.id_gen.next(),
                span,
                keyword_span,
                name_span,
                authorization_span,
                with_options_span,
            },
        )))
    }

    // ───────────────────────────────────────────────────────────────
    // ALTER EXTERNAL MODEL name SET (options)
    // ───────────────────────────────────────────────────────────────

    /// Parse `ALTER EXTERNAL MODEL name SET (options)`.
    ///
    /// Called when `ALTER` is the current token and the dispatcher has confirmed
    /// that `EXTERNAL MODEL` follows.
    pub(crate) fn try_parse_mssql_alter_external_model(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("mssql_alter_external_model")?;

        // ALTER
        let alter_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["ALTER".to_string()])?;
        let start = alter_tok.span.start;

        // EXTERNAL (Identifier)
        self.advance(); // EXTERNAL

        // MODEL (Identifier)
        let model_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["MODEL".to_string()])?;
        let keyword_span = Span {
            start,
            end: model_tok.span.end,
        };

        // Model name
        let name_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["model_name".to_string()])?;
        let name_span = name_tok.span;

        // SET (options)
        let set_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["SET".to_string()])?;
        if !matches!(set_tok.kind, TokenKind::Keyword(Keyword::Set)) {
            return Err(ParseError::invalid_statement(
                set_tok.span,
                format!("expected SET, found '{}'", set_tok.lexeme(self.source)),
            ));
        }
        let set_start = set_tok.span.start;
        let paren_span = self.mssql_parse_paren_content()?;
        let set_options_span = Span {
            start: set_start,
            end: paren_span.end,
        };

        let span = Span {
            start,
            end: set_options_span.end,
        };
        Ok(AstStmt::MssqlAlterExternalModel(Box::new(
            AstMssqlAlterExternalModel {
                node_id: self.id_gen.next(),
                span,
                keyword_span,
                name_span,
                set_options_span,
            },
        )))
    }

    // ───────────────────────────────────────────────────────────────
    // DROP EXTERNAL MODEL [IF EXISTS] name
    // ───────────────────────────────────────────────────────────────

    /// Parse `DROP EXTERNAL MODEL [IF EXISTS] name`.
    ///
    /// Called when `DROP` has been consumed and the dispatcher has confirmed
    /// that `EXTERNAL MODEL` follows. Parser position is restored to before DROP.
    pub(crate) fn try_parse_mssql_drop_external_model(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("mssql_drop_external_model")?;

        // DROP
        let drop_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["DROP".to_string()])?;
        let start = drop_tok.span.start;

        // EXTERNAL (Identifier)
        self.advance(); // EXTERNAL

        // MODEL (Identifier)
        let mut keyword_end_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["MODEL".to_string()])?;

        // Optional IF EXISTS
        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::If)) {
                self.advance(); // IF
                keyword_end_tok = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["EXISTS".to_string()])?;
                // EXISTS
            }
        }
        let keyword_span = Span {
            start,
            end: keyword_end_tok.span.end,
        };

        // Model name
        let name_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["model_name".to_string()])?;
        let name_span = name_tok.span;

        let span = Span {
            start,
            end: name_span.end,
        };
        Ok(AstStmt::MssqlDropExternalModel(Box::new(
            AstMssqlDropExternalModel {
                node_id: self.id_gen.next(),
                span,
                keyword_span,
                name_span,
            },
        )))
    }

    // ───────────────────────────────────────────────────────────────
    // CREATE VECTOR INDEX name ON table(column) WITH (...) [ON filegroup]
    // ───────────────────────────────────────────────────────────────

    /// Parse MSSQL `CREATE VECTOR INDEX name ON table(column) WITH (options) [ON filegroup]`.
    ///
    /// Called when `CREATE` is the current token and the dispatcher has confirmed
    /// that `VECTOR INDEX` follows (MSSQL dialect).
    pub(crate) fn try_parse_mssql_create_vector_index(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("mssql_create_vector_index")?;

        // CREATE
        let create_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["CREATE".to_string()])?;
        let start = create_tok.span.start;

        // VECTOR (Identifier)
        self.advance(); // VECTOR

        // INDEX (Identifier)
        let index_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["INDEX".to_string()])?;
        let keyword_span = Span {
            start,
            end: index_tok.span.end,
        };

        // Index name
        let name_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["index_name".to_string()])?;
        let index_name_span = name_tok.span;

        // ON (Keyword)
        let on_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["ON".to_string()])?;
        if !matches!(on_tok.kind, TokenKind::Keyword(Keyword::On)) {
            return Err(ParseError::invalid_statement(
                on_tok.span,
                format!("expected ON, found '{}'", on_tok.lexeme(self.source)),
            ));
        }

        // Table name (possibly qualified: schema.table)
        let first_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["table_name".to_string()])?;
        let table_start = first_tok.span.start;
        let mut table_end = first_tok.span.end;
        // Consume dot-separated parts
        while let Some(dot_tok) = self.peek_non_trivia() {
            if !matches!(dot_tok.kind, TokenKind::Punctuation(Punctuation::Dot)) {
                break;
            }
            self.advance(); // dot
            let part_tok = self
                .advance()
                .ok_or_eof(self.current_span(), vec!["identifier".to_string()])?;
            table_end = part_tok.span.end;
        }
        let table_span = Span {
            start: table_start,
            end: table_end,
        };

        // Column list in parentheses
        let columns_span = self.mssql_parse_paren_content()?;

        let mut end = columns_span.end;
        let mut with_options_span = None;
        let mut on_filegroup_span = None;

        // Optional WITH (options)
        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::With)) {
                let with_start = tok.span.start;
                self.advance(); // WITH
                let paren_span = self.mssql_parse_paren_content()?;
                with_options_span = Some(Span {
                    start: with_start,
                    end: paren_span.end,
                });
                end = paren_span.end;
            }
        }

        // Optional ON filegroup (after WITH)
        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::On)) {
                let fg_start = tok.span.start;
                self.advance(); // ON
                let fg_tok = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["filegroup".to_string()])?;
                on_filegroup_span = Some(Span {
                    start: fg_start,
                    end: fg_tok.span.end,
                });
                end = fg_tok.span.end;
            }
        }

        let span = Span { start, end };
        Ok(AstStmt::MssqlCreateVectorIndex(Box::new(
            AstMssqlCreateVectorIndex {
                node_id: self.id_gen.next(),
                span,
                keyword_span,
                index_name_span,
                table_span,
                columns_span,
                with_options_span,
                on_filegroup_span,
            },
        )))
    }

    // CREATE LOGIN / CREATE USER were folded into the dialect-neutral
    // [`crate::parser::principal`] entry points. The MSSQL source-clause
    // classifier ([`Self::classify_mssql_principal_source`]) is the
    // shared building block called from there.
}
