// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Parser for the T-SQL `ALTER SERVER CONFIGURATION SET …` statement
//! (SQL Server instance-level reconfiguration).
//!
//! `ALTER SERVER CONFIGURATION
//!    SET { PROCESS AFFINITY … | DIAGNOSTICS LOG … | BUFFER POOL EXTENSION … |
//!          HADR CLUSTER CONTEXT = … | FAILOVER CLUSTER PROPERTY … |
//!          SOFTNUMA { ON | OFF } | MEMORY_OPTIMIZED … }`
//!
//! Unrelated to SQL/MED foreign servers — this changes the database engine
//! instance configuration. Recognition lifts the configuration *subsystem*
//! (the first word after `SET`) as the discriminator; the value clause is
//! consumed to the statement terminator. Dispatched from the
//! `ALTER SERVER CONFIGURATION` arm in `core.rs`.

use crate::ast::types::{AstMssqlAlterServerConfiguration, AstStmt};
use crate::error::{ParseResult, ParseResultExt};
use crate::lexer::{Punctuation, Span, TokenKind};
use crate::parser::core::Parser;

impl<'a> Parser<'a> {
    pub(crate) fn try_parse_mssql_alter_server_configuration(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("alter_server_configuration")?;
        let start_span = self.current_span();

        // ALTER SERVER CONFIGURATION (the dispatch guard guarantees all three).
        let alter_tok = self
            .advance()
            .ok_or_eof(start_span, vec!["ALTER".to_string()])?;
        let start = alter_tok.span.start;
        self.advance()
            .ok_or_eof(self.current_span(), vec!["SERVER".to_string()])?;
        let config_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["CONFIGURATION".to_string()])?;
        let mut end = config_tok.span.end;

        // Scan the SET clause to the depth-0 terminator. The first word after
        // SET is the configuration subsystem (the recognition discriminator);
        // everything else is the value clause, consumed but not surfaced.
        let mut subsystem_span: Option<Span> = None;
        let mut seen_set = false;
        let mut depth: u32 = 0;
        loop {
            let (is_semi, is_eof, is_lparen, is_rparen, is_set, is_word, tok_span) =
                match self.peek_non_trivia() {
                    None => break,
                    Some(t) => (
                        matches!(t.kind, TokenKind::Punctuation(Punctuation::Semi)),
                        matches!(t.kind, TokenKind::Eof),
                        matches!(t.kind, TokenKind::Punctuation(Punctuation::LParen)),
                        matches!(t.kind, TokenKind::Punctuation(Punctuation::RParen)),
                        t.lexeme(self.source).eq_ignore_ascii_case("SET"),
                        matches!(t.kind, TokenKind::Identifier { .. } | TokenKind::Keyword(_)),
                        t.span,
                    ),
                };
            if is_eof || (is_semi && depth == 0) {
                break;
            }
            if depth == 0 {
                if !seen_set && is_set {
                    seen_set = true;
                } else if seen_set && subsystem_span.is_none() && is_word {
                    subsystem_span = Some(tok_span);
                }
            }
            if is_lparen {
                depth += 1;
            } else if is_rparen {
                depth = depth.saturating_sub(1);
            }
            let consumed = self
                .advance()
                .ok_or_eof(self.current_span(), vec![";".to_string()])?;
            end = consumed.span.end;
        }

        let stmt_span = Span { start, end };
        let ast = AstMssqlAlterServerConfiguration {
            node_id: self.id_gen.next(),
            span: stmt_span,
            subsystem_span,
        };
        Ok(AstStmt::MssqlAlterServerConfiguration(Box::new(ast)))
    }
}
