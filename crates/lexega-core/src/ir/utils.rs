// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Small cross-cutting utilities used by IR construction and analysis.

use crate::lexer::Span;

/// Slice the source text covered by a span, or `None` if the span is out of range.
pub fn slice_span(source: &str, span: Span) -> Option<&str> {
    source.get(span.start as usize..span.end as usize)
}
