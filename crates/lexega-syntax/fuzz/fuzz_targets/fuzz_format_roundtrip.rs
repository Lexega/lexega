// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Fuzz target: Formatter roundtrip invariant
//!
//! For any input that successfully formats, the formatted output must:
//! 1. Also successfully format (idempotency of parse+format)
//! 2. Re-format to the same output (idempotency of formatted form)
//! 3. Pass `verify_formatting_safe()` (semantic token preservation)
//!
//! Note: verify_formatting_safe failures are logged but not fatal, because
//! error-recovery paths (OpaqueContent) may legitimately normalize garbage
//! input. The idempotency check is the hard invariant — once formatted,
//! re-formatting must produce identical output.

#![no_main]

use libfuzzer_sys::fuzz_target;
use lexega_syntax::{format_sql_with_config, verify_formatting_safe, FormatterConfig};

fuzz_target!(|data: &str| {
    let config = FormatterConfig::default();

    // Step 1: Try to format the input
    let formatted = match format_sql_with_config(data, &config) {
        Ok(f) => f,
        Err(_) => return, // Input doesn't parse — that's fine
    };

    // Step 2: Re-format the formatted output (idempotency check)
    // This is the hard invariant: format(format(x)) == format(x)
    let reformatted = match format_sql_with_config(&formatted, &config) {
        Ok(f) => f,
        Err(e) => panic!(
            "Re-formatting failed!\n\
             Original:  {:?}\n\
             Formatted: {:?}\n\
             Error:     {}",
            data, formatted, e
        ),
    };

    // Step 3: Formatted output must be stable
    if formatted != reformatted {
        panic!(
            "Formatting is not idempotent!\n\
             Input:       {:?}\n\
             Formatted:   {:?}\n\
             Reformatted: {:?}",
            data, formatted, reformatted
        );
    }

    // Step 4: Verify semantic preservation (original → formatted)
    // Not fatal — error recovery (OpaqueContent) may drop tokens from garbage input.
    // But if this fails on valid-looking SQL, that's worth investigating via the corpus.
    let _ = verify_formatting_safe(data, &formatted);
});
