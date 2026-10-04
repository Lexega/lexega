// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Parser for the MySQL `CREATE TRIGGER` statement — an inline-body trigger
//! that runs automatically on a row event.
//!
//! ```sql
//! CREATE [DEFINER = user] TRIGGER [IF NOT EXISTS] name
//!     { BEFORE | AFTER } { INSERT | UPDATE | DELETE } ON tbl
//!     FOR EACH ROW [{ FOLLOWS | PRECEDES } other]
//!     <stmt | BEGIN … END>
//! ```
//!
//! Distinct from PostgreSQL (which delegates to `EXECUTE FUNCTION fn()`) and
//! from MSSQL (which lists `ON table` before the timing). Recognition lifts the
//! timing, the event, the target table, and the definer; the body is sub-parsed
//! (a `BEGIN … END` body is a compound block, not `START TRANSACTION`) so its
//! inner SQL is visible as statements.

use crate::ast::types::{AstCreateMysqlTrigger, AstStmt, TriggerEvent, TriggerTiming};
use crate::error::{ParseError, ParseErrorKind, ParseResult, ParseResultExt};
use crate::lexer::{Keyword, Span, TokenKind};
use crate::parser::core::Parser;

impl<'a> Parser<'a> {
    /// `CREATE [DEFINER = user] TRIGGER … FOR EACH ROW <body>` (MySQL).
    /// Cursor starts at `CREATE` (the dispatcher rewinds before calling).
    pub(crate) fn try_parse_create_mysql_trigger(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("mysql_create_trigger")?;

        let create_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["CREATE".to_string()])?;
        let start = create_tok.span.start;
        let create_span = create_tok.span;
        self.skip_trivia();

        let definer = self.parse_definer_clause();

        // TRIGGER keyword.
        let trigger_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["TRIGGER".to_string()])?;
        if !matches!(trigger_tok.kind, TokenKind::Keyword(Keyword::Trigger)) {
            return Err(ParseError::new(
                trigger_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: "Expected TRIGGER keyword".to_string(),
                },
            ));
        }
        self.skip_trivia();

        let if_not_exists_span = self.parse_optional_if_not_exists()?;
        let name_span = self.parse_qualified_name_span()?;

        // Timing: BEFORE | AFTER.
        let timing = match self.timing_keyword() {
            Some(t) => t,
            None => {
                return Err(ParseError::new(
                    self.current_span(),
                    ParseErrorKind::InvalidStatement {
                        message: "Expected BEFORE or AFTER in CREATE TRIGGER".to_string(),
                    },
                ));
            }
        };

        // Event: INSERT | UPDATE | DELETE.
        let event = match self.trigger_event_keyword() {
            Some(e) => e,
            None => {
                return Err(ParseError::new(
                    self.current_span(),
                    ParseErrorKind::InvalidStatement {
                        message: "Expected INSERT, UPDATE, or DELETE in CREATE TRIGGER".to_string(),
                    },
                ));
            }
        };

        // ON <table>.
        let on_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["ON".to_string()])?;
        if !matches!(on_tok.kind, TokenKind::Keyword(Keyword::On)) {
            return Err(ParseError::new(
                on_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: "Expected ON <table> in CREATE TRIGGER".to_string(),
                },
            ));
        }
        let target_table_span = self.parse_qualified_name_span()?;
        let mut end = target_table_span.end;

        // FOR EACH ROW — consume the three words (lexeme match, dialect-neutral).
        for kw in ["FOR", "EACH", "ROW"] {
            if self
                .peek_non_trivia()
                .map(|t| t.lexeme(self.source).eq_ignore_ascii_case(kw))
                .unwrap_or(false)
            {
                if let Some(t) = self.advance() {
                    end = t.span.end;
                }
            }
        }

        // Optional trigger order: { FOLLOWS | PRECEDES } other_trigger.
        if self
            .peek_non_trivia()
            .map(|t| {
                let lx = t.lexeme(self.source);
                lx.eq_ignore_ascii_case("FOLLOWS") || lx.eq_ignore_ascii_case("PRECEDES")
            })
            .unwrap_or(false)
        {
            self.advance(); // FOLLOWS / PRECEDES
            if let Ok(other) = self.parse_qualified_name_span() {
                end = other.end;
            }
        }

        let body_stmt = self.parse_routine_body(&mut end);

        let span = Span { start, end };
        let node = AstCreateMysqlTrigger {
            node_id: self.id_gen.next(),
            span,
            create_span,
            definer,
            if_not_exists_span,
            name_span,
            timing,
            event,
            target_table_span,
            body_stmt,
        };
        Ok(AstStmt::CreateMysqlTrigger(Box::new(node)))
    }

    /// Consume a `BEFORE` / `AFTER` timing keyword, if present.
    fn timing_keyword(&mut self) -> Option<TriggerTiming> {
        let timing = match self.peek_non_trivia() {
            Some(t) if t.lexeme(self.source).eq_ignore_ascii_case("BEFORE") => {
                TriggerTiming::Before
            }
            Some(t) if t.lexeme(self.source).eq_ignore_ascii_case("AFTER") => TriggerTiming::After,
            _ => return None,
        };
        self.advance();
        self.skip_trivia();
        Some(timing)
    }

    /// Consume an `INSERT` / `UPDATE` / `DELETE` event keyword, if present.
    fn trigger_event_keyword(&mut self) -> Option<TriggerEvent> {
        let event = match self.peek_non_trivia() {
            Some(t) if matches!(t.kind, TokenKind::Keyword(Keyword::Insert)) => {
                TriggerEvent::Insert
            }
            Some(t) if matches!(t.kind, TokenKind::Keyword(Keyword::Update)) => {
                TriggerEvent::Update
            }
            Some(t) if matches!(t.kind, TokenKind::Keyword(Keyword::Delete)) => {
                TriggerEvent::Delete
            }
            _ => return None,
        };
        self.advance();
        self.skip_trivia();
        Some(event)
    }
}
