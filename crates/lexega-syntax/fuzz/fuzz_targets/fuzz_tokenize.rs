// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Fuzz target: Lexer tokenization
//!
//! Ensures `tokenize()` never panics on arbitrary input.
//! The lexer is the first layer — it must be robust against any byte sequence
//! that happens to be valid UTF-8.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &str| {
    // The lexer must never panic on any valid UTF-8 input.
    // It may produce error tokens, but must not crash.
    let _ = lexega_syntax::tokenize(data);
});
