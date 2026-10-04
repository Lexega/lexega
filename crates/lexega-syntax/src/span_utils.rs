// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Utilities for working with spans and converting between byte offsets and line/column positions.

use crate::lexer::token::Span;

/// Line and column position (both 1-indexed for human readability).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LineCol {
    /// Line number (1-indexed)
    pub line: usize,
    /// Column number (1-indexed) - byte offset within the line
    pub col: usize,
}

impl LineCol {
    /// Create a new LineCol position.
    pub fn new(line: usize, col: usize) -> Self {
        Self { line, col }
    }
}

/// Convert a byte offset to a line and column position.
///
/// # Arguments
/// * `source` - The full source text
/// * `offset` - Byte offset into the source (0-indexed)
///
/// # Returns
/// A `LineCol` with 1-indexed line and column numbers.
pub fn offset_to_line_col(source: &str, offset: u32) -> LineCol {
    let offset = offset as usize;
    let mut line = 1;
    let mut col = 1;

    for (i, ch) in source.char_indices() {
        if i >= offset {
            break;
        }

        if ch == '\n' {
            line += 1;
            col = 1;
        } else {
            col += 1;
        }
    }

    LineCol { line, col }
}

/// Convert a span (byte range) to start and end line/column positions.
pub fn span_to_line_col(source: &str, span: Span) -> (LineCol, LineCol) {
    let start = offset_to_line_col(source, span.start);
    let end = offset_to_line_col(source, span.end);
    (start, end)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_offset_to_line_col() {
        let source = "SELECT *\nFROM table\nWHERE id = 1";

        // Offset 0: 'S' in SELECT
        assert_eq!(offset_to_line_col(source, 0), LineCol { line: 1, col: 1 });

        // Offset 7: '*'
        assert_eq!(offset_to_line_col(source, 7), LineCol { line: 1, col: 8 });

        // Offset 8: newline (should still be line 1)
        assert_eq!(offset_to_line_col(source, 8), LineCol { line: 1, col: 9 });

        // Offset 9: 'F' in FROM (start of line 2)
        assert_eq!(offset_to_line_col(source, 9), LineCol { line: 2, col: 1 });

        // Offset 19: newline after table
        assert_eq!(offset_to_line_col(source, 19), LineCol { line: 2, col: 11 });

        // Offset 20: 'W' in WHERE (start of line 3)
        assert_eq!(offset_to_line_col(source, 20), LineCol { line: 3, col: 1 });
    }

    #[test]
    fn test_span_to_line_col() {
        let source = "SELECT *\nFROM table\nWHERE id = 1";

        // Span covering "SELECT"
        let span = Span { start: 0, end: 6 };
        let (start, end) = span_to_line_col(source, span);
        assert_eq!(start, LineCol { line: 1, col: 1 });
        assert_eq!(end, LineCol { line: 1, col: 7 });

        // Span covering "FROM"
        let span = Span { start: 9, end: 13 };
        let (start, end) = span_to_line_col(source, span);
        assert_eq!(start, LineCol { line: 2, col: 1 });
        assert_eq!(end, LineCol { line: 2, col: 5 });
    }
}
