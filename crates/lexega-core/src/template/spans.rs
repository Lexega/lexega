// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Lexer-derived byte-span helpers shared by the client-substitution
//! pre-passes ([`snowsql`](super::snowsql), [`deployvars`](super::deployvars)).
//!
//! Both passes rewrite source text but must respect the lexer's authoritative
//! region boundaries: comments are [`Trivia`](TriviaKind) (never tokens), and
//! string literals are `Literal(String)` tokens. These helpers turn one
//! tokenization into sorted, binary-searchable byte-span tables.

use crate::lexer::token::{LiteralKind, Token, TokenKind, TriviaKind};

#[inline]
pub(crate) fn is_name_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

#[inline]
pub(crate) fn utf8_len(lead: u8) -> usize {
    if lead < 0x80 {
        1
    } else if lead < 0xE0 {
        2
    } else if lead < 0xF0 {
        3
    } else {
        4
    }
}

fn is_comment_trivia(kind: &TriviaKind) -> bool {
    matches!(
        kind,
        TriviaKind::LineComment
            | TriviaKind::BlockComment
            | TriviaKind::JinjaComment
            | TriviaKind::MysqlVersionComment
    )
}

/// Byte-spans of comment trivia (sorted, disjoint). Comments never appear as
/// tokens — they are `Trivia` attached to tokens — so this is the authoritative
/// way to know which regions are commented out.
pub(crate) fn comment_spans(tokens: &[Token]) -> Vec<(usize, usize)> {
    let mut spans = Vec::new();
    for t in tokens {
        for tr in t.leading_trivia.iter().chain(t.trailing_trivia.iter()) {
            if is_comment_trivia(&tr.kind) {
                spans.push((tr.span.start as usize, tr.span.end as usize));
            }
        }
    }
    spans.sort_unstable();
    spans
}

/// Byte-spans of string-literal tokens (sorted).
pub(crate) fn string_spans(tokens: &[Token]) -> Vec<(usize, usize)> {
    let mut spans = Vec::new();
    for t in tokens {
        if matches!(
            t.kind,
            TokenKind::Literal(LiteralKind::String)
                | TokenKind::Literal(LiteralKind::StringFragment)
        ) {
            spans.push((t.span.start as usize, t.span.end as usize));
        }
    }
    spans.sort_unstable();
    spans
}

pub(crate) fn in_spans(pos: usize, spans: &[(usize, usize)]) -> bool {
    spans
        .binary_search_by(|&(s, e)| {
            if pos < s {
                std::cmp::Ordering::Greater
            } else if pos >= e {
                std::cmp::Ordering::Less
            } else {
                std::cmp::Ordering::Equal
            }
        })
        .is_ok()
}
