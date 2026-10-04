// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Parser for the T-SQL `CREATE SYNONYM` statement.
//!
//! Grammar (SQL Server):
//! `CREATE SYNONYM [schema.]synonym_name FOR [server.][database.][schema.]object_name`
//!
//! `SYNONYM` lexes as an identifier (not a keyword); `FOR` is `Keyword::For`.
//! Both names are ordinary dot-separated qualified names (up to four parts for
//! the referenced object — `server.database.schema.object`).

use crate::ast::{AstCreateSynonym, AstStmt};
use crate::error::{ParseError, ParseErrorKind, ParseResult, ParseResultExt};
use crate::lexer::{Keyword, Span, TokenKind};
use crate::parser::core::Parser;

impl Parser<'_> {
    pub(crate) fn try_parse_create_synonym_stmt(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("create_synonym")?;
        let start_span = self.current_span();

        // CREATE
        let create_tok = self
            .advance()
            .ok_or_eof(start_span, vec!["CREATE".to_string()])?;
        let create_span = create_tok.span;

        // SYNONYM (identifier in our lexer)
        let synonym_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["SYNONYM".to_string()])?;
        let synonym_keyword_span = synonym_tok.span;

        // Synonym name (possibly schema-qualified)
        let name_span = self.parse_qualified_name_span()?;

        // FOR keyword
        let for_tok = self.peek_non_trivia();
        if !matches!(
            for_tok.map(|t| &t.kind),
            Some(TokenKind::Keyword(Keyword::For))
        ) {
            return Err(ParseError::new(
                self.current_span(),
                ParseErrorKind::InvalidStatement {
                    message: "CREATE SYNONYM requires FOR <object>".to_string(),
                },
            ));
        }
        let for_span = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["FOR".to_string()])?
            .span;

        // Referenced base object (1–4 part name)
        let target_span = self.parse_qualified_name_span()?;

        let span = Span {
            start: create_span.start,
            end: target_span.end,
        };
        Ok(AstStmt::CreateSynonym(Box::new(AstCreateSynonym {
            node_id: self.id_gen.next(),
            span,
            create_span,
            synonym_keyword_span,
            name_span,
            for_span,
            target_span,
        })))
    }
}
