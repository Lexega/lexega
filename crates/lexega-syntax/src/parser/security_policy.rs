// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Parser for the T-SQL Row-Level Security control statements:
//! `CREATE`/`ALTER SECURITY POLICY name { ADD { FILTER | BLOCK } PREDICATE …
//! ON table … }[, …] [WITH (STATE = { ON | OFF } …)]`.
//!
//! A security policy is SQL Server's row-level-security surface: it binds
//! filter predicates (which rows a query can see) and block predicates (which
//! rows a write may touch) to tables. The governance-bearing primitives are the
//! verb, the policy `STATE` (a policy with `STATE = OFF` — or, on `CREATE`, no
//! `STATE` at all, which defaults to OFF — enforces nothing), and whether
//! filter / block predicates are present. Which combination is dangerous is
//! the consumer's verdict; predicate function and table operands carry no governance
//! signal and are scanned past.
//!
//! Disambiguation from the Snowflake `CREATE/ALTER SECURITY INTEGRATION` form is
//! structural (the token after `SECURITY` is `POLICY` vs `INTEGRATION`), handled
//! at the dispatch seam — no dialect branch.

use crate::ast::types::{AstMssqlSecurityPolicy, AstStmt, PolicyState, SecurityPolicyAction};
use crate::error::{ParseResult, ParseResultExt};
use crate::lexer::token::Token;
use crate::lexer::{Operator, Punctuation, Span, TokenKind};
use crate::parser::core::Parser;

/// Index of the next significant (non-comment) token at or after `from`.
fn next_sig_idx(tokens: &[Token], mut from: usize) -> Option<usize> {
    while from < tokens.len() {
        if matches!(
            tokens[from].kind,
            TokenKind::LineComment | TokenKind::BlockComment
        ) {
            from += 1;
            continue;
        }
        return Some(from);
    }
    None
}

/// True when `tokens[from..]` begins with a token whose lexeme equals `kw`.
fn next_lexeme_is(tokens: &[Token], from: usize, source: &str, kw: &str) -> bool {
    next_sig_idx(tokens, from)
        .map(|i| tokens[i].lexeme(source).eq_ignore_ascii_case(kw))
        .unwrap_or(false)
}

impl<'a> Parser<'a> {
    /// `CREATE SECURITY POLICY …` — dispatched on `create_type_lexeme ==
    /// SECURITY` + next == `POLICY`.
    pub(crate) fn try_parse_create_mssql_security_policy(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("create_security_policy")?;
        let start_span = self.current_span();
        let create_tok = self
            .advance()
            .ok_or_eof(start_span, vec!["CREATE".to_string()])?;
        let start = create_tok.span.start;
        // Permissive: tolerate a `CREATE OR { REPLACE | ALTER | REFRESH }`
        // modifier even though RLS policies don't standardly take one.
        if next_lexeme_is(self.tokens, self.idx, self.source, "OR") {
            self.advance();
            self.advance();
        }
        self.parse_security_policy_tail(SecurityPolicyAction::Create, start)
    }

    /// `ALTER SECURITY POLICY …` — dispatched on `SECURITY` + next == `POLICY`.
    pub(crate) fn try_parse_alter_mssql_security_policy(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("alter_security_policy")?;
        let start_span = self.current_span();
        let alter_tok = self
            .advance()
            .ok_or_eof(start_span, vec!["ALTER".to_string()])?;
        let start = alter_tok.span.start;
        self.parse_security_policy_tail(SecurityPolicyAction::Alter, start)
    }

    /// Shared tail: consume `SECURITY POLICY`, then scan the remainder to the
    /// depth-0 terminator capturing the governance-bearing primitives — the
    /// `STATE`, and whether filter / block predicates appear.
    fn parse_security_policy_tail(
        &mut self,
        action: SecurityPolicyAction,
        start: u32,
    ) -> ParseResult<AstStmt> {
        // SECURITY (identifier) POLICY (keyword) — guaranteed by the dispatcher.
        self.advance()
            .ok_or_eof(self.current_span(), vec!["SECURITY".to_string()])?;
        let policy_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["POLICY".to_string()])?;
        let mut end = policy_tok.span.end;

        let mut state = PolicyState::Unset;
        let mut has_filter_predicate = false;
        let mut has_block_predicate = false;
        let mut depth: u32 = 0;
        while self.idx < self.tokens.len() {
            let tok = &self.tokens[self.idx];
            match tok.kind {
                TokenKind::Eof => break,
                TokenKind::Punctuation(Punctuation::Semi) if depth == 0 => break,
                TokenKind::Punctuation(Punctuation::LParen) => depth += 1,
                TokenKind::Punctuation(Punctuation::RParen) => depth = depth.saturating_sub(1),
                _ => {}
            }
            let lx = tok.lexeme(self.source);
            if lx.eq_ignore_ascii_case("STATE") {
                // STATE = { ON | OFF }
                if let Some(eq) = next_sig_idx(self.tokens, self.idx + 1) {
                    if matches!(self.tokens[eq].kind, TokenKind::Operator(Operator::Eq)) {
                        if let Some(v) = next_sig_idx(self.tokens, eq + 1) {
                            let vl = self.tokens[v].lexeme(self.source);
                            if vl.eq_ignore_ascii_case("ON") {
                                state = PolicyState::On;
                            } else if vl.eq_ignore_ascii_case("OFF") {
                                state = PolicyState::Off;
                            }
                        }
                    }
                }
            } else if lx.eq_ignore_ascii_case("FILTER")
                && next_lexeme_is(self.tokens, self.idx + 1, self.source, "PREDICATE")
            {
                has_filter_predicate = true;
            } else if lx.eq_ignore_ascii_case("BLOCK")
                && next_lexeme_is(self.tokens, self.idx + 1, self.source, "PREDICATE")
            {
                has_block_predicate = true;
            }
            end = tok.span.end;
            self.idx += 1;
        }

        let stmt_span = Span { start, end };
        let ast = AstMssqlSecurityPolicy {
            node_id: self.id_gen.next(),
            span: stmt_span,
            action,
            state,
            has_filter_predicate,
            has_block_predicate,
        };
        Ok(AstStmt::MssqlSecurityPolicy(Box::new(ast)))
    }
}
