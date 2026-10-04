// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Row-pattern parser for MATCH_RECOGNIZE bodies.
//!
//! Parses the textual pattern carried on `crate::ast::AstPattern.pattern_text`
//! into a typed [`super::plan::PatternExpr`] tree, populating the per-MR
//! [`super::plan::SymbolTable`] as symbols are encountered.
//!
//! The grammar covers Snowflake's row-pattern syntax (which Oracle's
//! pattern-matching grammar is the superset of, modulo `PERMUTE` /
//! `{- … -}` exclude blocks — the parser here is dialect-permissive
//! per the project's "permissive parsing, dialect-driven lexing"
//! rule):
//!
//! ```text
//! pattern         ::= alternation
//! alternation     ::= concatenation ( '|' concatenation )*
//! concatenation   ::= factor*
//! factor          ::= primary quantifier?
//! quantifier      ::= ( '*' | '+' | '?' | '{' bound '}' ) '?'?
//! bound           ::= INT
//!                   | INT ','
//!                   | ',' INT
//!                   | INT ',' INT
//! primary         ::= symbol
//!                   | '^'                          ─ start anchor
//!                   | '$'                          ─ end anchor
//!                   | '(' alternation ')'
//!                   | '{-' alternation '-}'         ─ Oracle exclusion
//!                   | 'PERMUTE' '(' pattern_list ')' ─ Oracle PERMUTE
//! pattern_list    ::= alternation ( ',' alternation )*
//! symbol          ::= IDENT
//! ```
//!
//! On parse failure the caller surfaces
//! [`super::lower::LowerErrorKind::ParseUpstream`], or
//! lowers the body with `pattern: PatternExpr::Empty` under
//! Permissive (see `lower::maybe_wrap_match_recognize`). The
//! parser therefore returns a typed error rather than producing an
//! opaque pattern node directly.

use crate::context::node_metadata::IdentKey;
use crate::lexer::Span;

use super::plan::{PatternAnchor, PatternExpr, PatternQuantKind, SymbolTable};

/// Reason a row-pattern parse failed.
///
/// Closed enum — every consumer matches exhaustively.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PatternParseError {
    UnexpectedChar { ch: char, byte_offset: usize },
    UnclosedGroup { byte_offset: usize },
    UnclosedExclude { byte_offset: usize },
    UnclosedQuantifier { byte_offset: usize },
    EmptyAlternation { byte_offset: usize },
    InvalidQuantifierBound { byte_offset: usize },
    QuantifierWithoutOperand { byte_offset: usize },
    BoundOutOfRange { byte_offset: usize },
    EmptyInput,
}

impl PatternParseError {
    /// Human-readable, dialect-agnostic short description used by the
    /// lowering site to populate generic strict-mode error messages.
    pub fn reason(&self) -> &'static str {
        match self {
            PatternParseError::UnexpectedChar { .. } => "unexpected character",
            PatternParseError::UnclosedGroup { .. } => "unclosed group",
            PatternParseError::UnclosedExclude { .. } => "unclosed exclude block",
            PatternParseError::UnclosedQuantifier { .. } => "unclosed quantifier",
            PatternParseError::EmptyAlternation { .. } => "empty alternation arm",
            PatternParseError::InvalidQuantifierBound { .. } => "invalid quantifier bound",
            PatternParseError::QuantifierWithoutOperand { .. } => "quantifier without operand",
            PatternParseError::BoundOutOfRange { .. } => "quantifier bound out of range",
            PatternParseError::EmptyInput => "empty pattern",
        }
    }

    /// Byte offset within the pattern text where the error was
    /// detected, or `None` for whole-input errors (`EmptyInput`).
    pub fn byte_offset(&self) -> Option<usize> {
        match self {
            PatternParseError::UnexpectedChar { byte_offset, .. }
            | PatternParseError::UnclosedGroup { byte_offset }
            | PatternParseError::UnclosedExclude { byte_offset }
            | PatternParseError::UnclosedQuantifier { byte_offset }
            | PatternParseError::EmptyAlternation { byte_offset }
            | PatternParseError::InvalidQuantifierBound { byte_offset }
            | PatternParseError::QuantifierWithoutOperand { byte_offset }
            | PatternParseError::BoundOutOfRange { byte_offset } => Some(*byte_offset),
            PatternParseError::EmptyInput => None,
        }
    }
}

/// Parse `text` (raw row-pattern source) into a typed [`PatternExpr`],
/// interning encountered symbols into `symbols`.
///
/// `pattern_span` is the span of the entire pattern source so that
/// inner sub-spans can be derived as offsets. Currently the parser
/// produces no per-node spans (PatternExpr is span-less by design —
/// pattern variables track their own first-seen span via
/// [`SymbolTable`]); the parameter is reserved for a future
/// per-node span addition.
pub fn parse_pattern(
    text: &str,
    pattern_span: Span,
    symbols: &mut SymbolTable,
) -> Result<PatternExpr, PatternParseError> {
    let _ = pattern_span;
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Err(PatternParseError::EmptyInput);
    }
    let mut p = Parser::new(text, pattern_span, symbols);
    let expr = p.parse_alternation()?;
    p.skip_ws();
    if p.pos < p.bytes.len() {
        return Err(PatternParseError::UnexpectedChar {
            ch: p.peek_char().unwrap_or('\0'),
            byte_offset: p.pos,
        });
    }
    Ok(expr)
}

// ────────────────────────────────────────────────────────────────────────
// Parser state
// ────────────────────────────────────────────────────────────────────────

struct Parser<'a> {
    bytes: &'a [u8],
    pos: usize,
    pattern_span: Span,
    symbols: &'a mut SymbolTable,
}

impl<'a> Parser<'a> {
    fn new(text: &'a str, pattern_span: Span, symbols: &'a mut SymbolTable) -> Self {
        Self {
            bytes: text.as_bytes(),
            pos: 0,
            pattern_span,
            symbols,
        }
    }

    fn peek_byte(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn peek_char(&self) -> Option<char> {
        self.bytes[self.pos..].iter().next().map(|b| *b as char)
    }

    fn bump(&mut self) -> Option<u8> {
        let b = self.peek_byte()?;
        self.pos += 1;
        Some(b)
    }

    fn skip_ws(&mut self) {
        while let Some(b) = self.peek_byte() {
            if b == b' ' || b == b'\t' || b == b'\n' || b == b'\r' {
                self.pos += 1;
            } else {
                break;
            }
        }
    }

    /// Parse `concatenation ( '|' concatenation )*`.
    fn parse_alternation(&mut self) -> Result<PatternExpr, PatternParseError> {
        let mut arms = vec![self.parse_concatenation()?];
        loop {
            self.skip_ws();
            if self.peek_byte() == Some(b'|') {
                let bar_pos = self.pos;
                self.pos += 1;
                let arm = self.parse_concatenation()?;
                if matches!(arm, PatternExpr::Empty)
                    && matches!(arms.last(), Some(PatternExpr::Empty))
                {
                    // Two empty arms in a row (e.g. `||`) — surface as
                    // explicit error rather than silently producing
                    // adjacent Empties.
                    return Err(PatternParseError::EmptyAlternation {
                        byte_offset: bar_pos,
                    });
                }
                arms.push(arm);
            } else {
                break;
            }
        }
        Ok(if arms.len() == 1 {
            arms.pop().expect("len() == 1")
        } else {
            PatternExpr::Alternation(arms)
        })
    }

    /// Parse `factor*`. Returns `Empty` if no factors are present.
    fn parse_concatenation(&mut self) -> Result<PatternExpr, PatternParseError> {
        let mut factors: Vec<PatternExpr> = Vec::new();
        loop {
            self.skip_ws();
            match self.peek_byte() {
                None | Some(b')') | Some(b'|') | Some(b',') => break,
                // `-}` closes an exclude — stop and let the caller
                // consume it.
                Some(b'-') if self.bytes.get(self.pos + 1) == Some(&b'}') => break,
                _ => {}
            }
            let factor = self.parse_factor()?;
            factors.push(factor);
        }
        Ok(match factors.len() {
            0 => PatternExpr::Empty,
            1 => factors.pop().expect("len() == 1"),
            _ => PatternExpr::Concat(factors),
        })
    }

    /// Parse `primary quantifier?`.
    fn parse_factor(&mut self) -> Result<PatternExpr, PatternParseError> {
        let primary = self.parse_primary()?;
        self.skip_ws();
        match self.peek_byte() {
            Some(b'*') | Some(b'+') | Some(b'?') => {
                let (kind, greedy) = self.parse_quantifier()?;
                Ok(PatternExpr::Quantified {
                    inner: Box::new(primary),
                    kind,
                    greedy,
                })
            }
            // `{` is a brace-quantifier opener only when not followed
            // by `-` (which starts an `{- … -}` exclude block — a
            // sibling primary, not a postfix).
            Some(b'{') if self.bytes.get(self.pos + 1) != Some(&b'-') => {
                let (kind, greedy) = self.parse_quantifier()?;
                Ok(PatternExpr::Quantified {
                    inner: Box::new(primary),
                    kind,
                    greedy,
                })
            }
            _ => Ok(primary),
        }
    }

    fn parse_quantifier(&mut self) -> Result<(PatternQuantKind, bool), PatternParseError> {
        let start = self.pos;
        let kind = match self.bump() {
            Some(b'*') => PatternQuantKind::ZeroOrMore,
            Some(b'+') => PatternQuantKind::OneOrMore,
            Some(b'?') => PatternQuantKind::ZeroOrOne,
            Some(b'{') => self.parse_brace_quantifier(start)?,
            _ => {
                return Err(PatternParseError::UnexpectedChar {
                    ch: '\0',
                    byte_offset: start,
                })
            }
        };
        // Reluctant marker.
        let greedy = if self.peek_byte() == Some(b'?') {
            self.pos += 1;
            false
        } else {
            true
        };
        Ok((kind, greedy))
    }

    fn parse_brace_quantifier(
        &mut self,
        open_pos: usize,
    ) -> Result<PatternQuantKind, PatternParseError> {
        // `{` already consumed.
        self.skip_ws();
        let lo_present = self.peek_is_digit();
        let lo = if lo_present {
            Some(self.parse_uint(open_pos)?)
        } else {
            None
        };
        self.skip_ws();
        let kind = match self.peek_byte() {
            Some(b'}') => {
                self.pos += 1;
                let n = lo.ok_or(PatternParseError::InvalidQuantifierBound {
                    byte_offset: open_pos,
                })?;
                PatternQuantKind::Exact(n)
            }
            Some(b',') => {
                self.pos += 1;
                self.skip_ws();
                if self.peek_byte() == Some(b'}') {
                    self.pos += 1;
                    let n = lo.ok_or(PatternParseError::InvalidQuantifierBound {
                        byte_offset: open_pos,
                    })?;
                    PatternQuantKind::AtLeast(n)
                } else {
                    let hi = self.parse_uint(open_pos)?;
                    self.skip_ws();
                    if self.peek_byte() != Some(b'}') {
                        return Err(PatternParseError::UnclosedQuantifier {
                            byte_offset: open_pos,
                        });
                    }
                    self.pos += 1;
                    match lo {
                        None => PatternQuantKind::AtMost(hi),
                        Some(n) => {
                            if n > hi {
                                return Err(PatternParseError::BoundOutOfRange {
                                    byte_offset: open_pos,
                                });
                            }
                            PatternQuantKind::Range(n, hi)
                        }
                    }
                }
            }
            _ => {
                return Err(PatternParseError::UnclosedQuantifier {
                    byte_offset: open_pos,
                })
            }
        };
        Ok(kind)
    }

    fn parse_primary(&mut self) -> Result<PatternExpr, PatternParseError> {
        self.skip_ws();
        let start = self.pos;
        match self.peek_byte() {
            None => Err(PatternParseError::QuantifierWithoutOperand { byte_offset: start }),
            Some(b'^') => {
                self.pos += 1;
                Ok(PatternExpr::Anchor(PatternAnchor::Start))
            }
            Some(b'$') => {
                self.pos += 1;
                Ok(PatternExpr::Anchor(PatternAnchor::End))
            }
            Some(b'(') => {
                self.pos += 1;
                let inner = self.parse_alternation()?;
                self.skip_ws();
                if self.peek_byte() != Some(b')') {
                    return Err(PatternParseError::UnclosedGroup { byte_offset: start });
                }
                self.pos += 1;
                Ok(inner)
            }
            Some(b'{') if self.bytes.get(self.pos + 1) == Some(&b'-') => {
                self.pos += 2;
                let inner = self.parse_alternation()?;
                self.skip_ws();
                if self.peek_byte() != Some(b'-') || self.bytes.get(self.pos + 1) != Some(&b'}') {
                    return Err(PatternParseError::UnclosedExclude { byte_offset: start });
                }
                self.pos += 2;
                Ok(PatternExpr::Exclude(Box::new(inner)))
            }
            Some(b) if is_ident_start(b) => self.parse_ident_or_permute(start),
            Some(b) => Err(PatternParseError::UnexpectedChar {
                ch: b as char,
                byte_offset: start,
            }),
        }
    }

    fn parse_ident_or_permute(&mut self, start: usize) -> Result<PatternExpr, PatternParseError> {
        let mut end = start;
        while let Some(b) = self.bytes.get(end) {
            if is_ident_continue(*b) {
                end += 1;
            } else {
                break;
            }
        }
        self.pos = end;
        let raw = std::str::from_utf8(&self.bytes[start..end]).unwrap_or("");
        if raw.eq_ignore_ascii_case("PERMUTE") {
            self.skip_ws();
            if self.peek_byte() == Some(b'(') {
                self.pos += 1;
                let mut arms = Vec::new();
                loop {
                    let arm = self.parse_alternation()?;
                    arms.push(arm);
                    self.skip_ws();
                    match self.peek_byte() {
                        Some(b',') => {
                            self.pos += 1;
                            continue;
                        }
                        Some(b')') => {
                            self.pos += 1;
                            break;
                        }
                        _ => return Err(PatternParseError::UnclosedGroup { byte_offset: start }),
                    }
                }
                return Ok(PatternExpr::Permute(arms));
            }
            // Not followed by `(` — treat `PERMUTE` as a regular symbol.
        }
        let key = IdentKey::new(raw);
        // Span of the symbol within the pattern source.
        let symbol_span = Span {
            start: self.pattern_span.start.saturating_add(start as u32),
            end: self.pattern_span.start.saturating_add(end as u32),
        };
        let id = self.symbols.intern(key, raw.to_string(), symbol_span);
        Ok(PatternExpr::Symbol(id))
    }

    fn peek_is_digit(&self) -> bool {
        matches!(self.peek_byte(), Some(b'0'..=b'9'))
    }

    fn parse_uint(&mut self, err_offset: usize) -> Result<u32, PatternParseError> {
        let start = self.pos;
        while let Some(b) = self.peek_byte() {
            if b.is_ascii_digit() {
                self.pos += 1;
            } else {
                break;
            }
        }
        if start == self.pos {
            return Err(PatternParseError::InvalidQuantifierBound {
                byte_offset: err_offset,
            });
        }
        let raw = std::str::from_utf8(&self.bytes[start..self.pos]).unwrap_or("");
        raw.parse::<u32>()
            .map_err(|_| PatternParseError::BoundOutOfRange {
                byte_offset: err_offset,
            })
    }
}

fn is_ident_start(b: u8) -> bool {
    b == b'_' || b.is_ascii_alphabetic()
}

fn is_ident_continue(b: u8) -> bool {
    is_ident_start(b) || b.is_ascii_digit()
}

// ── Pattern walks ───────────────────────────────────────────────────────

impl PatternExpr {
    /// Number of `PatternExpr` nodes in the tree rooted at `self`,
    /// for pretty-print summaries and rough complexity metrics.
    pub fn node_count(&self) -> usize {
        match self {
            PatternExpr::Symbol(_) | PatternExpr::Anchor(_) | PatternExpr::Empty => 1,
            PatternExpr::Concat(items)
            | PatternExpr::Alternation(items)
            | PatternExpr::Permute(items) => {
                1 + items.iter().map(PatternExpr::node_count).sum::<usize>()
            }
            PatternExpr::Quantified { inner, .. } | PatternExpr::Exclude(inner) => {
                1 + inner.node_count()
            }
        }
    }
}

// ────────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::super::plan::SymbolId;
    use super::*;

    fn span(start: usize, end: usize) -> Span {
        Span {
            start: start as u32,
            end: end as u32,
        }
    }

    fn parse(text: &str) -> Result<(PatternExpr, SymbolTable), PatternParseError> {
        let mut symbols = SymbolTable::default();
        let expr = parse_pattern(text, span(0, text.len()), &mut symbols)?;
        Ok((expr, symbols))
    }

    #[test]
    fn empty_input_rejected() {
        assert_eq!(parse("").unwrap_err(), PatternParseError::EmptyInput);
        assert_eq!(parse("   ").unwrap_err(), PatternParseError::EmptyInput);
    }

    #[test]
    fn single_symbol() {
        let (e, syms) = parse("UP").unwrap();
        assert!(matches!(e, PatternExpr::Symbol(SymbolId(0))));
        assert_eq!(syms.len(), 1);
        assert_eq!(syms.get(SymbolId(0)).unwrap().display, "UP");
    }

    #[test]
    fn concatenation_three_symbols() {
        let (e, syms) = parse("A B C").unwrap();
        match e {
            PatternExpr::Concat(items) => assert_eq!(items.len(), 3),
            other => panic!("expected Concat, got {:?}", other),
        }
        assert_eq!(syms.len(), 3);
    }

    #[test]
    fn alternation_two_arms() {
        let (e, _) = parse("UP | DOWN").unwrap();
        match e {
            PatternExpr::Alternation(arms) => {
                assert_eq!(arms.len(), 2);
                assert!(matches!(arms[0], PatternExpr::Symbol(_)));
                assert!(matches!(arms[1], PatternExpr::Symbol(_)));
            }
            other => panic!("expected Alternation, got {:?}", other),
        }
    }

    #[test]
    fn anchors() {
        let (e, _) = parse("^ A $").unwrap();
        match e {
            PatternExpr::Concat(items) => {
                assert_eq!(items.len(), 3);
                assert!(matches!(
                    items[0],
                    PatternExpr::Anchor(PatternAnchor::Start)
                ));
                assert!(matches!(items[2], PatternExpr::Anchor(PatternAnchor::End)));
            }
            other => panic!("expected Concat, got {:?}", other),
        }
    }

    #[test]
    fn quantifier_star() {
        let (e, _) = parse("A*").unwrap();
        let q = match e {
            PatternExpr::Quantified { kind, greedy, .. } => (kind, greedy),
            other => panic!("expected Quantified, got {:?}", other),
        };
        assert_eq!(q.0, PatternQuantKind::ZeroOrMore);
        assert!(q.1);
    }

    #[test]
    fn quantifier_reluctant() {
        let (e, _) = parse("A+?").unwrap();
        let q = match e {
            PatternExpr::Quantified { kind, greedy, .. } => (kind, greedy),
            other => panic!("expected Quantified, got {:?}", other),
        };
        assert_eq!(q.0, PatternQuantKind::OneOrMore);
        assert!(!q.1);
    }

    #[test]
    fn quantifier_brace_exact() {
        let (e, _) = parse("A{3}").unwrap();
        match e {
            PatternExpr::Quantified { kind, .. } => {
                assert_eq!(kind, PatternQuantKind::Exact(3))
            }
            other => panic!("expected Quantified, got {:?}", other),
        }
    }

    #[test]
    fn quantifier_brace_range() {
        let (e, _) = parse("A{2,5}").unwrap();
        match e {
            PatternExpr::Quantified { kind, .. } => {
                assert_eq!(kind, PatternQuantKind::Range(2, 5))
            }
            other => panic!("expected Quantified, got {:?}", other),
        }
    }

    #[test]
    fn quantifier_brace_at_least() {
        let (e, _) = parse("A{2,}").unwrap();
        match e {
            PatternExpr::Quantified { kind, .. } => {
                assert_eq!(kind, PatternQuantKind::AtLeast(2))
            }
            other => panic!("expected Quantified, got {:?}", other),
        }
    }

    #[test]
    fn quantifier_brace_at_most() {
        let (e, _) = parse("A{,5}").unwrap();
        match e {
            PatternExpr::Quantified { kind, .. } => {
                assert_eq!(kind, PatternQuantKind::AtMost(5))
            }
            other => panic!("expected Quantified, got {:?}", other),
        }
    }

    #[test]
    fn brace_range_inverted_rejected() {
        match parse("A{5,2}") {
            Err(PatternParseError::BoundOutOfRange { .. }) => {}
            other => panic!("expected BoundOutOfRange, got {:?}", other),
        }
    }

    #[test]
    fn grouped_alternation_with_quantifier() {
        let (e, _) = parse("(UP | DOWN)+").unwrap();
        match e {
            PatternExpr::Quantified { inner, kind, .. } => {
                assert_eq!(kind, PatternQuantKind::OneOrMore);
                assert!(matches!(*inner, PatternExpr::Alternation(_)));
            }
            other => panic!("expected Quantified, got {:?}", other),
        }
    }

    #[test]
    fn unclosed_group_rejected() {
        match parse("(A | B") {
            Err(PatternParseError::UnclosedGroup { .. }) => {}
            other => panic!("expected UnclosedGroup, got {:?}", other),
        }
    }

    #[test]
    fn permute() {
        let (e, _) = parse("PERMUTE(A, B, C)").unwrap();
        match e {
            PatternExpr::Permute(arms) => assert_eq!(arms.len(), 3),
            other => panic!("expected Permute, got {:?}", other),
        }
    }

    #[test]
    fn permute_as_identifier_when_no_parens() {
        // Bare `PERMUTE` (no following `(`) should parse as a symbol.
        let (e, syms) = parse("PERMUTE").unwrap();
        assert!(matches!(e, PatternExpr::Symbol(SymbolId(0))));
        assert_eq!(syms.get(SymbolId(0)).unwrap().display, "PERMUTE");
    }

    #[test]
    fn exclude_block() {
        let (e, _) = parse("A {- B -} C").unwrap();
        match e {
            PatternExpr::Concat(items) => {
                assert_eq!(items.len(), 3);
                assert!(matches!(items[1], PatternExpr::Exclude(_)));
            }
            other => panic!("expected Concat, got {:?}", other),
        }
    }

    #[test]
    fn symbol_interning_case_insensitive() {
        let (_, syms) = parse("UP up Up").unwrap();
        // IdentKey::new is case-insensitive for unquoted identifiers
        // — all three references intern to the same SymbolId.
        assert_eq!(syms.len(), 1);
    }

    #[test]
    fn unexpected_trailing_char() {
        match parse("A )") {
            Err(PatternParseError::UnexpectedChar { ch, .. }) => assert_eq!(ch, ')'),
            other => panic!("expected UnexpectedChar, got {:?}", other),
        }
    }

    #[test]
    fn complex_pattern_round_trip() {
        // "STRT (UP+ DOWN+)+ END" — typical Snowflake example.
        let (e, syms) = parse("STRT (UP+ DOWN+)+ END").unwrap();
        // Four distinct symbols: STRT, UP, DOWN, END.
        assert_eq!(syms.len(), 4);
        match e {
            PatternExpr::Concat(items) => assert_eq!(items.len(), 3),
            other => panic!("expected Concat, got {:?}", other),
        }
    }
}
