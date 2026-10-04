// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Parser for the MySQL `CREATE EVENT` / `ALTER EVENT` statements — scheduled
//! SQL jobs (the MySQL analog of a Snowflake TASK).
//!
//! ```sql
//! CREATE [DEFINER = user] EVENT [IF NOT EXISTS] name
//!     ON SCHEDULE { AT ts | EVERY interval [STARTS …] [ENDS …] }
//!     [ON COMPLETION [NOT] PRESERVE]
//!     [ENABLE | DISABLE | DISABLE ON SLAVE]
//!     [COMMENT 'string']
//!     DO <stmt>
//! ```
//!
//! Recognition lifts the schedule kind (one-time `AT` vs recurring `EVERY`),
//! the `ON COMPLETION PRESERVE` flag, and the enable state. The `DO` body is
//! sub-parsed so its inner SQL is visible as statements — a recurring
//! scheduled `DROP`/`GRANT` is therefore visible. The framing clauses
//! (intervals, STARTS/ENDS, COMMENT) are consumed but not modelled.

use crate::ast::types::{
    AstAlterEvent, AstCreateEvent, AstDefiner, AstDefinerPrincipal, AstStmt, EventEnableState,
    EventScheduleKind,
};
use crate::error::{ParseError, ParseErrorKind, ParseResult, ParseResultExt};
use crate::lexer::token::Operator;
use crate::lexer::{Keyword, Punctuation, Span, TokenKind};
use crate::parser::core::Parser;

/// Recognition primitives lifted from the `EVENT` header clauses (everything
/// between the event name and the `DO` body).
#[derive(Default)]
struct EventHeaderScan {
    /// An `ON SCHEDULE` clause is present.
    schedule_present: bool,
    /// Schedule kind, when an `AT`/`EVERY` marker was seen.
    schedule_kind: Option<EventScheduleKind>,
    /// `ON COMPLETION PRESERVE` (true) vs `NOT PRESERVE` / absent (false).
    on_completion_preserve: bool,
    /// Explicit enable state, when `ENABLE`/`DISABLE` was written.
    enable_state: Option<EventEnableState>,
    /// A `RENAME TO` clause is present (ALTER only).
    rename_present: bool,
}

impl<'a> Parser<'a> {
    /// Parse an optional MySQL `DEFINER = { user | CURRENT_USER [()] }` clause
    /// into a typed [`AstDefiner`] (the security context the routine runs
    /// under). Returns `None` — a no-op — when no DEFINER clause is present.
    /// The cursor must be positioned at the potential `DEFINER` token (leading
    /// trivia tolerated).
    pub(crate) fn parse_definer_clause(&mut self) -> Option<AstDefiner> {
        let start = match self.peek_non_trivia() {
            Some(t) if t.lexeme(self.source).eq_ignore_ascii_case("DEFINER") => t.span.start,
            _ => return None,
        };
        self.advance(); // DEFINER
        self.skip_trivia();
        if matches!(
            self.peek(),
            Some(t) if matches!(t.kind, TokenKind::Operator(Operator::Eq))
        ) {
            self.advance(); // =
            self.skip_trivia();
        }

        let (principal, end) = if matches!(
            self.peek(),
            Some(t) if matches!(t.kind, TokenKind::Keyword(Keyword::CurrentUser))
        ) {
            let cu = self.advance().map(|t| t.span.end).unwrap_or(start);
            self.skip_trivia();
            let mut end = cu;
            // Optional `()`.
            if matches!(
                self.peek(),
                Some(t) if matches!(t.kind, TokenKind::Punctuation(Punctuation::LParen))
            ) {
                self.advance(); // (
                self.skip_trivia();
                if let Some(t) = self.peek() {
                    if matches!(t.kind, TokenKind::Punctuation(Punctuation::RParen)) {
                        end = t.span.end;
                        self.advance(); // )
                    }
                }
            }
            (AstDefinerPrincipal::CurrentUser, end)
        } else {
            // `'user'@'host'` / bare user — reuse the shared principal-name
            // reader so the `@host` split matches CREATE USER / GRANT.
            match self.consume_principal_name() {
                Ok((user_span, mut host_span)) => {
                    // An unquoted `user@host` lexes the host as a single
                    // `@host` AtVariable token, which `consume_principal_name`
                    // (Operator::At only) leaves behind. Pick it up here, the
                    // host being the part after the leading `@`.
                    if host_span.is_none() {
                        if let Some(t) = self.peek_non_trivia() {
                            if matches!(t.kind, TokenKind::Identifier { .. })
                                && t.lexeme(self.source).starts_with('@')
                            {
                                host_span = Some(Span {
                                    start: t.span.start + 1,
                                    end: t.span.end,
                                });
                                self.advance();
                            }
                        }
                    }
                    // Clause end = end of the last consumed significant token.
                    // `host_span` is the *dequoted inner* span (excludes the
                    // closing quote of a `'host'`), so it can't bound the
                    // clause the structured proc/func formatter emits verbatim.
                    let end = self.tokens[..self.idx]
                        .iter()
                        .rev()
                        .find(|t| {
                            !matches!(
                                t.kind,
                                TokenKind::LineComment | TokenKind::BlockComment | TokenKind::Eof
                            )
                        })
                        .map(|t| t.span.end)
                        .unwrap_or_else(|| host_span.map(|h| h.end).unwrap_or(user_span.end));
                    (
                        AstDefinerPrincipal::Named {
                            user_span,
                            host_span,
                        },
                        end,
                    )
                }
                // Malformed — record the clause covering what we consumed.
                Err(_) => (
                    AstDefinerPrincipal::Named {
                        user_span: Span { start, end: start },
                        host_span: None,
                    },
                    start,
                ),
            }
        };
        self.skip_trivia();
        Some(AstDefiner {
            span: Span { start, end },
            principal,
        })
    }

    /// Consume the event header clauses up to (but not including) the depth-0
    /// `DO` keyword (or a statement terminator), lifting the recognition
    /// primitives. Extends `*end` over every consumed token.
    fn scan_event_header(&mut self, end: &mut u32) -> EventHeaderScan {
        let mut scan = EventHeaderScan::default();
        let mut depth: u32 = 0;
        let mut prev_not = false;
        let mut saw_disable = false;
        loop {
            let (
                stop,
                d0,
                is_lparen,
                is_rparen,
                is_every,
                is_at,
                is_schedule,
                is_preserve,
                is_enable,
                is_disable,
                is_slave,
                is_not,
                is_rename,
            ) = match self.peek_non_trivia() {
                None => break,
                Some(t) => {
                    let d0 = depth == 0;
                    let lx = t.lexeme(self.source);
                    (
                        d0 && matches!(
                            t.kind,
                            TokenKind::Keyword(Keyword::Do)
                                | TokenKind::Punctuation(Punctuation::Semi)
                                | TokenKind::Eof
                        ),
                        d0,
                        matches!(t.kind, TokenKind::Punctuation(Punctuation::LParen)),
                        matches!(t.kind, TokenKind::Punctuation(Punctuation::RParen)),
                        lx.eq_ignore_ascii_case("EVERY"),
                        lx.eq_ignore_ascii_case("AT"),
                        lx.eq_ignore_ascii_case("SCHEDULE"),
                        lx.eq_ignore_ascii_case("PRESERVE"),
                        lx.eq_ignore_ascii_case("ENABLE"),
                        lx.eq_ignore_ascii_case("DISABLE"),
                        lx.eq_ignore_ascii_case("SLAVE"),
                        lx.eq_ignore_ascii_case("NOT"),
                        lx.eq_ignore_ascii_case("RENAME"),
                    )
                }
            };
            if stop {
                break;
            }
            if is_lparen {
                depth += 1;
            } else if is_rparen {
                depth = depth.saturating_sub(1);
            } else if d0 {
                if is_every {
                    scan.schedule_present = true;
                    scan.schedule_kind = Some(EventScheduleKind::Recurring);
                } else if is_at {
                    scan.schedule_present = true;
                    scan.schedule_kind = Some(EventScheduleKind::OneTime);
                } else if is_schedule {
                    scan.schedule_present = true;
                } else if is_preserve {
                    scan.on_completion_preserve = !prev_not;
                } else if is_enable {
                    scan.enable_state = Some(EventEnableState::Enable);
                } else if is_disable {
                    scan.enable_state = Some(EventEnableState::Disable);
                    saw_disable = true;
                } else if is_slave && saw_disable {
                    scan.enable_state = Some(EventEnableState::DisableOnSlave);
                } else if is_rename {
                    scan.rename_present = true;
                }
            }
            prev_not = is_not;
            if let Some(tok) = self.advance() {
                *end = tok.span.end;
            }
        }
        scan
    }

    /// Sub-parse the `DO` body statement, extending `*end`. Returns `None`
    /// when the body is unparseable (its bytes remain covered by the
    /// statement span); scans to the depth-0 terminator in that case.
    pub(crate) fn parse_routine_body(&mut self, end: &mut u32) -> Option<Box<AstStmt>> {
        // The body is a routine body, not a standalone statement: a bare
        // `BEGIN` here means a compound block, not `START TRANSACTION`. Mirror
        // the proc/dollar-body dispatch — BEGIN → block, DECLARE → scripting
        // block, otherwise a single flow statement.
        let is_begin = matches!(
            self.peek_non_trivia(),
            Some(t) if matches!(t.kind, TokenKind::Keyword(Keyword::Begin))
        );
        let is_declare = matches!(
            self.peek_non_trivia(),
            Some(t) if matches!(t.kind, TokenKind::Keyword(Keyword::Declare))
        );
        let parsed = if is_begin {
            crate::parser::scripting::parse_block_stmt(self)
        } else if is_declare {
            crate::parser::scripting::parse_scripting_block(self)
        } else {
            self.parse_flow_statement().ok()
        };
        match parsed {
            Some(stmt) => {
                *end = stmt.span().end;
                Some(Box::new(stmt))
            }
            None => {
                let mut depth: u32 = 0;
                loop {
                    let (stop, is_lparen, is_rparen) = match self.peek_non_trivia() {
                        None => break,
                        Some(t) => (
                            depth == 0
                                && matches!(
                                    t.kind,
                                    TokenKind::Punctuation(Punctuation::Semi) | TokenKind::Eof
                                ),
                            matches!(t.kind, TokenKind::Punctuation(Punctuation::LParen)),
                            matches!(t.kind, TokenKind::Punctuation(Punctuation::RParen)),
                        ),
                    };
                    if stop {
                        break;
                    }
                    if is_lparen {
                        depth += 1;
                    } else if is_rparen {
                        depth = depth.saturating_sub(1);
                    }
                    if let Some(tok) = self.advance() {
                        *end = tok.span.end;
                    }
                }
                None
            }
        }
    }

    /// `CREATE [DEFINER = user] EVENT [IF NOT EXISTS] name … DO <stmt>`.
    /// Cursor starts at `CREATE` (the dispatcher rewinds before calling).
    pub(crate) fn try_parse_create_event(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("mysql_create_event")?;

        let create_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["CREATE".to_string()])?;
        let start = create_tok.span.start;
        let create_span = create_tok.span;
        self.skip_trivia();

        let definer = self.parse_definer_clause();

        let event_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["EVENT".to_string()])?;
        let event_span = event_tok.span;
        self.skip_trivia();

        let if_not_exists_span = self.parse_optional_if_not_exists()?;

        let name_span = self.parse_qualified_name_span()?;
        let mut end = name_span.end;

        let scan = self.scan_event_header(&mut end);

        // DO is mandatory for CREATE EVENT.
        let do_present = self
            .peek_non_trivia()
            .map(|t| matches!(t.kind, TokenKind::Keyword(Keyword::Do)))
            .unwrap_or(false);
        if !do_present {
            return Err(ParseError::new(
                self.current_span(),
                ParseErrorKind::InvalidStatement {
                    message: "CREATE EVENT requires a DO <statement> body".to_string(),
                },
            ));
        }
        let do_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["DO".to_string()])?;
        let do_span = do_tok.span;
        end = do_tok.span.end;

        let body_stmt = self.parse_routine_body(&mut end);

        let span = Span { start, end };
        let node = AstCreateEvent {
            node_id: self.id_gen.next(),
            span,
            create_span,
            event_span,
            definer,
            if_not_exists_span,
            name_span,
            schedule_kind: scan.schedule_kind.unwrap_or(EventScheduleKind::Recurring),
            on_completion_preserve: scan.on_completion_preserve,
            enable_state: scan.enable_state.unwrap_or(EventEnableState::Enable),
            do_span,
            body_stmt,
        };
        Ok(AstStmt::CreateEvent(Box::new(node)))
    }

    /// `ALTER [DEFINER = user] EVENT name [ON SCHEDULE …] [RENAME TO …]
    /// [ENABLE | DISABLE …] [DO <stmt>]`. Cursor starts at `ALTER`.
    pub(crate) fn try_parse_alter_event(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("mysql_alter_event")?;

        let alter_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["ALTER".to_string()])?;
        let start = alter_tok.span.start;
        self.skip_trivia();

        let definer = self.parse_definer_clause();

        self.advance() // EVENT
            .ok_or_eof(self.current_span(), vec!["EVENT".to_string()])?;
        self.skip_trivia();

        let name_span = self.parse_qualified_name_span()?;
        let mut end = name_span.end;

        let scan = self.scan_event_header(&mut end);

        let body_stmt = if self
            .peek_non_trivia()
            .map(|t| matches!(t.kind, TokenKind::Keyword(Keyword::Do)))
            .unwrap_or(false)
        {
            let do_tok = self
                .advance()
                .ok_or_eof(self.current_span(), vec!["DO".to_string()])?;
            end = do_tok.span.end;
            self.parse_routine_body(&mut end)
        } else {
            None
        };

        let span = Span { start, end };
        let node = AstAlterEvent {
            node_id: self.id_gen.next(),
            span,
            definer,
            name_span,
            schedule_present: scan.schedule_present,
            rename_present: scan.rename_present,
            enable_state: scan.enable_state,
            body_stmt,
        };
        Ok(AstStmt::AlterEvent(Box::new(node)))
    }
}
