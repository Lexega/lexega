// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! The token stream the formatter emits from.
//!
//! A [`Cst`] owns the tokens of one source, each with its leading and
//! trailing trivia attached, so output can reproduce whitespace and
//! comments exactly. Tokens are addressed by [`TokenId`]; the typed syntax
//! nodes that hold those IDs live in [`crate::syntax`].

use crate::lexer::Token;

/// Index into the token stream.
///
/// This is a lightweight handle that avoids cloning tokens.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TokenId(pub u32);

impl TokenId {
    pub fn new(index: usize) -> Self {
        TokenId(index as u32)
    }

    pub fn index(self) -> usize {
        self.0 as usize
    }
}

/// The token stream of one source.
pub struct Cst {
    /// Every token, in source order.
    pub tokens: Vec<Token>,
}

impl Cst {
    /// Wrap a token stream.
    pub fn new(tokens: Vec<Token>) -> Self {
        Cst { tokens }
    }

    /// Get a token by ID.
    pub fn get_token(&self, id: TokenId) -> &Token {
        &self.tokens[id.index()]
    }
}
