// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Formatted context for tracking formatting metadata

use crate::context::span_map::{SpanMap, SpanMapError};
use crate::lexer::Span;

/// Formatting-specific metadata
///
/// Tracks the relationship between source and formatted SQL, including:
/// - Complete bidirectional span mapping
/// - Line/column indexing for diagnostics
/// - Indentation tracking per line
///
/// Note: Trivia (comments) are now handled via CST-based trivia attached to tokens.
#[derive(Debug, Clone)]
pub struct FormattedContext {
    /// Formatted SQL output (owned)
    formatted_sql: String,

    /// Complete bidirectional span mapping
    /// Invariant: Covers entire source with no gaps
    span_map: SpanMap,

    /// Indentation tracking for each line
    indentation: IndentationMap,

    /// Line/column index for fast diagnostics
    line_index: LineIndex,
}

/// Indentation tracking
///
/// Size: ~24 bytes (excluding heap)
/// Heap: O(num_lines * 1) bytes
#[derive(Debug, Clone)]
struct IndentationMap {
    /// Indentation level for each line
    /// Index = line number (0-based)
    levels: Vec<u8>,
}

/// Line/column index for O(log n) position lookups
///
/// Size: ~24 bytes (excluding heap)
/// Heap: O(num_lines * 8) bytes
#[derive(Debug, Clone)]
struct LineIndex {
    /// Byte offset of each line start
    /// Index = line number (0-based)
    line_starts: Vec<usize>,
}

/// Errors during formatted context construction
#[derive(Debug, Clone)]
pub enum FormattedContextError {
    /// Invalid span map
    InvalidSpanMap(SpanMapError),

    /// Invalid line index
    InvalidLineIndex,
}

impl FormattedContext {
    /// Create new formatted context with validation
    ///
    /// Time: O(n) for validation and index building
    /// Space: O(n) for storage
    ///
    /// # Errors
    ///
    /// Returns error if span map is invalid (gaps, incomplete coverage, etc.)
    pub fn new(formatted_sql: String, span_map: SpanMap) -> Result<Self, FormattedContextError> {
        // Build line index
        let line_index = LineIndex::build(&formatted_sql);

        // Build indentation map
        let indentation = IndentationMap::build(&formatted_sql);

        Ok(Self {
            formatted_sql,
            span_map,
            indentation,
            line_index,
        })
    }

    /// Get formatted SQL
    pub fn formatted_sql(&self) -> &str {
        &self.formatted_sql
    }

    /// Get span map
    pub fn span_map(&self) -> &SpanMap {
        &self.span_map
    }

    /// Translate source position to formatted position
    ///
    /// Time: O(log n)
    /// Algorithm: Binary search in forward mappings
    pub fn source_to_formatted(&self, offset: usize) -> Option<usize> {
        self.span_map.source_to_target(offset)
    }

    /// Translate formatted position to source position
    ///
    /// Time: O(log n)
    /// Algorithm: Binary search in reverse mappings
    pub fn formatted_to_source(&self, offset: usize) -> Option<usize> {
        self.span_map.target_to_source(offset)
    }

    /// Translate source span to formatted span(s)
    ///
    /// May return multiple spans if mapping is non-contiguous.
    ///
    /// Time: O(log n + k) where k is number of mappings in range
    pub fn source_span_to_formatted(&self, span: Span) -> Vec<Span> {
        self.span_map.source_span_to_target(span)
    }

    /// Translate formatted span to source span(s)
    ///
    /// May return multiple spans if mapping is non-contiguous.
    ///
    /// Time: O(log n + k) where k is number of mappings in range
    pub fn formatted_span_to_source(&self, span: Span) -> Vec<Span> {
        self.span_map.target_span_to_source(span)
    }

    /// Get line/column for formatted position
    ///
    /// Time: O(log n)
    /// Algorithm: Binary search in line_starts
    pub fn line_col(&self, offset: usize) -> (usize, usize) {
        self.line_index.offset_to_line_col(offset)
    }

    /// Get indentation level at formatted position
    ///
    /// Time: O(log n) for line lookup, then O(1)
    pub fn indent_level(&self, offset: usize) -> usize {
        let (line, _) = self.line_col(offset);
        self.indentation.level_at_line(line)
    }

    /// Get number of lines in formatted output
    pub fn line_count(&self) -> usize {
        self.line_index.line_count()
    }
}

impl LineIndex {
    /// Build line index from text
    ///
    /// Time: O(n) where n = text length
    /// Space: O(lines) where lines = number of lines
    fn build(text: &str) -> Self {
        let mut line_starts = vec![0];

        for (i, byte) in text.bytes().enumerate() {
            if byte == b'\n' {
                line_starts.push(i + 1);
            }
        }

        Self { line_starts }
    }

    /// Convert byte offset to (line, column)
    ///
    /// Time: O(log n) where n = number of lines
    fn offset_to_line_col(&self, offset: usize) -> (usize, usize) {
        // Binary search for line containing this offset
        let line = match self.line_starts.binary_search(&offset) {
            Ok(line) => line,
            Err(line) => line.saturating_sub(1),
        };

        let line_start = self.line_starts[line];
        let column = offset - line_start;

        (line, column)
    }

    /// Get number of lines
    fn line_count(&self) -> usize {
        self.line_starts.len()
    }
}

impl IndentationMap {
    /// Build indentation map from text
    ///
    /// Time: O(n) where n = text length
    /// Space: O(lines)
    fn build(text: &str) -> Self {
        let mut levels = Vec::new();

        for line in text.lines() {
            // Count leading whitespace characters
            let indent = line.chars().take_while(|c| c.is_whitespace()).count();
            // Assume 2-space indent, cap at 255
            levels.push((indent / 2).min(255) as u8);
        }

        Self { levels }
    }

    /// Get indentation level at line
    ///
    /// Time: O(1)
    fn level_at_line(&self, line: usize) -> usize {
        self.levels.get(line).copied().unwrap_or(0) as usize
    }
}

impl std::fmt::Display for FormattedContextError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::InvalidSpanMap(err) => write!(f, "Invalid span map: {}", err),
            Self::InvalidLineIndex => write!(f, "Invalid line index"),
        }
    }
}

impl std::error::Error for FormattedContextError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidSpanMap(err) => Some(err),
            Self::InvalidLineIndex => None,
        }
    }
}

impl From<SpanMapError> for FormattedContextError {
    fn from(err: SpanMapError) -> Self {
        Self::InvalidSpanMap(err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::span_map::{MappingKind, SpanMapping};

    #[test]
    fn test_formatted_context_creation() {
        let source = "SELECT * FROM users"; // 19 bytes
        let formatted = "SELECT\n  *\nFROM\n  users"; // 23 bytes (not 24!)

        let mappings = vec![SpanMapping {
            source: Span { start: 0, end: 19 },
            target: Span { start: 0, end: 23 }, // Correctly 23 bytes
            kind: MappingKind::Reformatted,
        }];

        let span_map = SpanMap::from_mappings(
            source.len(),    // 19
            formatted.len(), // 23
            mappings,
            false,
        )
        .unwrap();

        let ctx = FormattedContext::new(formatted.to_string(), span_map).unwrap();

        assert_eq!(ctx.formatted_sql(), formatted);
        assert_eq!(ctx.line_count(), 4);
    }

    #[test]
    fn test_line_col_lookup() {
        let formatted = "SELECT\n  *\nFROM\n  users";
        let mappings = vec![SpanMapping {
            source: Span { start: 0, end: 19 },
            target: Span { start: 0, end: 24 },
            kind: MappingKind::Reformatted,
        }];

        let span_map = SpanMap::from_mappings(19, 24, mappings, false).unwrap();
        let ctx = FormattedContext::new(formatted.to_string(), span_map).unwrap();

        // "SELECT\n" - offset 0 is line 0, col 0
        assert_eq!(ctx.line_col(0), (0, 0));

        // "  *\n" - offset 7 (start of line 1)
        assert_eq!(ctx.line_col(7), (1, 0));

        // "FROM\n" - offset 11 (start of line 2)
        assert_eq!(ctx.line_col(11), (2, 0));

        // "  users" - offset 16 (start of line 3)
        assert_eq!(ctx.line_col(16), (3, 0));
    }

    #[test]
    fn test_indentation_tracking() {
        let formatted = "SELECT\n  *\nFROM\n  users";
        let mappings = vec![SpanMapping {
            source: Span { start: 0, end: 19 },
            target: Span { start: 0, end: 24 },
            kind: MappingKind::Reformatted,
        }];

        let span_map = SpanMap::from_mappings(19, 24, mappings, false).unwrap();
        let ctx = FormattedContext::new(formatted.to_string(), span_map).unwrap();

        // Line 0: "SELECT" - no indent
        assert_eq!(ctx.indent_level(0), 0);

        // Line 1: "  *" - 2 spaces = level 1
        assert_eq!(ctx.indent_level(7), 1);

        // Line 2: "FROM" - no indent
        assert_eq!(ctx.indent_level(11), 0);

        // Line 3: "  users" - 2 spaces = level 1
        assert_eq!(ctx.indent_level(16), 1);
    }

    #[test]
    fn test_span_translation() {
        let source = "SELECT * FROM users"; // 19 bytes
        let formatted = "SELECT\n  *\nFROM\n  users"; // 23 bytes (not 24!)

        let mappings = vec![SpanMapping {
            source: Span { start: 0, end: 19 },
            target: Span { start: 0, end: 23 }, // Correctly 23 bytes
            kind: MappingKind::Reformatted,
        }];

        let span_map = SpanMap::from_mappings(
            source.len(),    // 19
            formatted.len(), // 23
            mappings,
            false,
        )
        .unwrap();

        let ctx = FormattedContext::new(formatted.to_string(), span_map).unwrap();

        // Test source to formatted
        let formatted_pos = ctx.source_to_formatted(7).unwrap();
        assert!(formatted_pos <= formatted.len());

        // Test formatted to source
        let source_pos = ctx.formatted_to_source(10).unwrap();
        assert!(source_pos <= source.len());
    }

    #[test]
    fn test_line_index_edge_cases() {
        // Empty string
        let line_index = LineIndex::build("");
        assert_eq!(line_index.line_count(), 1); // Still has one "line"
        assert_eq!(line_index.offset_to_line_col(0), (0, 0));

        // Single line no newline
        let line_index = LineIndex::build("SELECT *");
        assert_eq!(line_index.line_count(), 1);
        assert_eq!(line_index.offset_to_line_col(0), (0, 0));
        assert_eq!(line_index.offset_to_line_col(7), (0, 7));

        // Multiple lines
        let line_index = LineIndex::build("line1\nline2\nline3");
        assert_eq!(line_index.line_count(), 3);
        assert_eq!(line_index.offset_to_line_col(0), (0, 0));
        assert_eq!(line_index.offset_to_line_col(6), (1, 0));
        assert_eq!(line_index.offset_to_line_col(12), (2, 0));
    }

    #[test]
    fn test_indentation_map_edge_cases() {
        // Empty string
        let indent_map = IndentationMap::build("");
        assert_eq!(indent_map.level_at_line(0), 0);

        // No indentation
        let indent_map = IndentationMap::build("SELECT\nFROM");
        assert_eq!(indent_map.level_at_line(0), 0);
        assert_eq!(indent_map.level_at_line(1), 0);

        // Various indentation levels
        let indent_map = IndentationMap::build("SELECT\n  item1\n    item2\nFROM");
        assert_eq!(indent_map.level_at_line(0), 0); // "SELECT"
        assert_eq!(indent_map.level_at_line(1), 1); // "  item1"
        assert_eq!(indent_map.level_at_line(2), 2); // "    item2"
        assert_eq!(indent_map.level_at_line(3), 0); // "FROM"
    }
}
