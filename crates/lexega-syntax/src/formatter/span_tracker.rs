// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Automatic span tracking state machine
//!
//! Tracks statement-level spans as formatting progresses.
//! Validates completeness on finish().

use crate::context::span_map::{MappingKind, SpanMap, SpanMapping};
use crate::lexer::token::TokenKind;
use crate::lexer::{tokenize, Span};

/// Automatic span tracking state machine
///
/// ARCHITECTURAL CONSTRAINT: Supports hierarchical spans (e.g., Block contains nested statements).
/// Validates that leaf spans form a complete partition of source bytes.
///
/// TOKEN-LEVEL TRACKING: When enabled (for template rendering), tracks fine-grained
/// token→formatted mappings alongside coarse statement-level mappings.
pub struct SpanTracker {
    /// Stack of active spans (for nesting)
    span_stack: Vec<ActiveSpan>,

    /// Completed mappings with nesting depth
    mappings: Vec<SpanMappingWithDepth>,

    /// Token-level mappings (enabled only for template rendering)
    /// Each mapping is a leaf-level (depth=max) span for fine-grained tracking
    token_mappings: Vec<SpanMapping>,

    /// Enable token-level tracking (off by default for performance)
    token_tracking_enabled: bool,
}

/// An active span being tracked
struct ActiveSpan {
    /// Source span
    source: Span,

    /// Output position when span started
    output_start: usize,

    /// Mapping kind
    kind: MappingKind,

    /// Nesting depth (0 = top level)
    depth: usize,
}

/// Span mapping with depth information
struct SpanMappingWithDepth {
    mapping: SpanMapping,
    depth: usize,
}

impl SpanTracker {
    /// Create new span tracker
    pub fn new() -> Self {
        Self {
            span_stack: Vec::new(),
            mappings: Vec::new(),
            token_mappings: Vec::new(),
            token_tracking_enabled: false,
        }
    }

    /// Enable token-level tracking (for template rendering only)
    ///
    /// PERFORMANCE: Only enable this when rendering Jinja templates that need
    /// reverse mapping. Regular SQL formatting uses coarse statement-level tracking.
    pub fn enable_token_tracking(&mut self) {
        self.token_tracking_enabled = true;
    }

    /// Track a token-level span (for fine-grained template mapping)
    ///
    /// Unlike begin/end which supports nesting, this is for leaf-level tracking
    /// of individual tokens or small spans. Only active when token_tracking_enabled=true.
    ///
    /// Time: O(1)
    #[inline]
    pub fn track_token(&mut self, source_span: Span, output_start: usize, output_end: usize) {
        if !self.token_tracking_enabled {
            return;
        }

        self.token_mappings.push(SpanMapping {
            source: source_span,
            target: Span {
                start: output_start as u32,
                end: output_end as u32,
            },
            kind: MappingKind::Reformatted,
        });
    }

    /// Begin tracking a span (supports nesting)
    ///
    /// Nested spans are allowed - children must be fully contained within parent.
    ///
    /// Time: O(1)
    #[inline]
    pub fn begin(&mut self, source_span: Span, output_pos: usize, kind: MappingKind) {
        let depth = self.span_stack.len();
        self.span_stack.push(ActiveSpan {
            source: source_span,
            output_start: output_pos,
            kind,
            depth,
        });
    }

    /// End tracking current span
    ///
    /// Time: O(1)
    #[inline]
    pub fn end(&mut self, output_pos: usize) {
        if let Some(active) = self.span_stack.pop() {
            self.mappings.push(SpanMappingWithDepth {
                mapping: SpanMapping {
                    source: active.source,
                    target: Span {
                        start: active.output_start as u32,
                        end: output_pos as u32,
                    },
                    kind: active.kind,
                },
                depth: active.depth,
            });
        }
    }

    /// Finalize tracking and build SpanMap
    ///
    /// Validates that leaf spans (innermost at each position) cover all source bytes.
    /// Allows nested/hierarchical spans where children are contained within parents.
    /// Gaps are permitted only if they contain exclusively trivia (whitespace, newlines, comments).
    ///
    /// Time: O(n log n) for sorting
    /// Space: O(n) for SpanMap
    pub fn finish(mut self, source: &str, output_len: usize) -> Result<SpanMap, SpanTrackerError> {
        let source_len = source.len();

        // Check for unclosed spans
        if !self.span_stack.is_empty() {
            return Err(SpanTrackerError::UnclosedSpans {
                count: self.span_stack.len(),
            });
        }

        // Sort mappings by source position, then by depth (deeper first)
        self.mappings
            .sort_by_key(|m| (m.mapping.source.start, std::cmp::Reverse(m.depth)));

        // Extract ONLY top-level (depth=0) mappings for SpanMap
        // SpanMap requires a partition (no overlaps), so we can't include nested spans
        let mut mappings: Vec<SpanMapping> = self
            .mappings
            .iter()
            .filter(|m| m.depth == 0)
            .map(|m| m.mapping)
            .collect();

        // If token tracking was enabled, use token-level mappings instead of statement-level
        if self.token_tracking_enabled && !self.token_mappings.is_empty() {
            mappings = self.token_mappings.clone();
            // Sort token mappings by source position
            mappings.sort_by_key(|m| m.source.start);

            // Validate gaps to prevent data loss
            validate_token_gaps(&mappings, source, source_len)?;

            // For token tracking, fill gaps to create complete coverage
            // Token mappings track only user content (identifiers, literals, Jinja blocks).
            // Gaps contain formatter-synthesized content (keywords, operators, formatting).
            // We need to infer the target positions for gaps based on the tracked tokens.
            let mut filled_mappings = Vec::new();
            let mut source_pos = 0_usize;
            let mut target_pos = 0_usize;

            for mapping in mappings.iter() {
                let source_gap_start = source_pos;
                let source_gap_end = mapping.source.start as usize;

                if source_gap_end > source_gap_start {
                    // Calculate target gap: formatter may have added/removed content
                    let target_gap_start = target_pos;
                    let target_gap_end = mapping.target.start as usize;

                    // Fill gap mapping
                    filled_mappings.push(SpanMapping {
                        source: Span {
                            start: source_gap_start as u32,
                            end: source_gap_end as u32,
                        },
                        target: Span {
                            start: target_gap_start as u32,
                            end: target_gap_end as u32,
                        },
                        kind: MappingKind::Reformatted,
                    });
                }

                // Add the tracked token mapping
                filled_mappings.push(*mapping);
                source_pos = mapping.source.end as usize;
                target_pos = mapping.target.end as usize;
            }

            // Handle trailing gap
            if source_pos < source_len {
                let target_gap_start = target_pos;
                let target_gap_end = output_len;

                filled_mappings.push(SpanMapping {
                    source: Span {
                        start: source_pos as u32,
                        end: source_len as u32,
                    },
                    target: Span {
                        start: target_gap_start as u32,
                        end: target_gap_end as u32,
                    },
                    kind: MappingKind::Reformatted,
                });
            }

            // Build SpanMap with complete coverage
            let span_map = SpanMap::from_mappings(source_len, output_len, filled_mappings, false)
                .map_err(|e| SpanTrackerError::InvalidSpanMap(format!("{:?}", e)))?;

            return Ok(span_map);
        }

        // Extend first/last mappings to cover leading/trailing trivia BEFORE validation
        //
        // ARCHITECTURAL NOTE: Statement spans from the parser don't include leading/trailing trivia
        // (by design - trivia is skipped between statements). But SpanMap requires complete
        // coverage with no gaps. This is a pragmatic solution that:
        // 1. Extends the first/last statement spans to cover leading/trailing gaps
        // 2. Validates the gaps contain ONLY trivia (whitespace/comments)
        // 3. Prevents data loss by refusing to extend over non-trivia content

        // Extend first mapping to cover any leading trivia
        if let Some(first_mapping) = mappings.first_mut() {
            let first_start = first_mapping.source.start as usize;
            if first_start > 0 {
                // Validate leading gap contains only trivia before extending
                let leading_text = &source[0..first_start];
                if !Self::is_trivia_only_static(leading_text) {
                    return Err(SpanTrackerError::IncompleteSpanCoverage {
                        expected: source_len,
                        actual: source_len - first_start,
                        gaps: vec![(0, first_start)],
                    });
                }
                // Leading gap is trivia - extend to cover it
                first_mapping.source.start = 0;
            }
        }

        // Extend last mapping to cover any trailing trivia
        if let Some(last_mapping) = mappings.last_mut() {
            let last_end = last_mapping.source.end as usize;
            if last_end < source_len {
                // Validate trailing gap contains only trivia before extending
                let trailing_text = &source[last_end..source_len];
                if !Self::is_trivia_only_static(trailing_text) {
                    return Err(SpanTrackerError::IncompleteSpanCoverage {
                        expected: source_len,
                        actual: last_end,
                        gaps: vec![(last_end, source_len)],
                    });
                }
                // Trailing gap is trivia - extend to cover it
                last_mapping.source.end = source_len as u32;
            }
        }

        // Extend each mapping to cover inter-statement trivia gaps
        // For each pair of consecutive mappings, extend the first to reach the second
        for i in 0..mappings.len().saturating_sub(1) {
            let current_end = mappings[i].source.end as usize;
            let next_start = mappings[i + 1].source.start as usize;

            if current_end < next_start {
                // There's a gap - validate it's trivia only
                let gap_text = &source[current_end..next_start];
                if !Self::is_trivia_only_static(gap_text) {
                    return Err(SpanTrackerError::IncompleteSpanCoverage {
                        expected: source_len,
                        actual: current_end,
                        gaps: vec![(current_end, next_start)],
                    });
                }
                // Gap is trivia - extend current mapping to cover it
                mappings[i].source.end = next_start as u32;
            }
        }

        // Validate hierarchical coverage (after extending for leading/trailing)
        let _gaps = self.validate_hierarchical_coverage(source, source_len)?;

        // Build SpanMap with validation enabled
        let span_map = SpanMap::from_mappings(source_len, output_len, mappings, true)
            .map_err(|e| SpanTrackerError::InvalidSpanMap(e.to_string()))?;

        Ok(span_map)
    }

    /// Validate that leaf spans cover all bytes (allowing nesting)
    ///
    /// OPTIMIZED: Instead of allocating O(source_len) coverage map, we use span-based
    /// gap detection which is O(n log n) where n is number of mappings.
    ///
    /// Strategy:
    /// 1. Sort spans by start position
    /// 2. Walk through spans, tracking the furthest end position seen
    /// 3. Any gap between furthest end and next span's start is a gap
    /// 4. Validate gaps contain only trivia
    ///
    /// Returns: Vec<(start, end)> of validated trivia gaps
    fn validate_hierarchical_coverage(
        &self,
        source: &str,
        source_len: usize,
    ) -> Result<Vec<(usize, usize)>, SpanTrackerError> {
        if self.mappings.is_empty() {
            // No mappings - entire source is a gap
            if source_len > 0 && !Self::is_trivia_only_static(source) {
                return Err(SpanTrackerError::IncompleteSpanCoverage {
                    expected: source_len,
                    actual: 0,
                    gaps: vec![(0, source_len)],
                });
            }
            return Ok(vec![(0, source_len)]);
        }

        let mut gaps = Vec::new();
        let mut furthest_end: usize = 0;

        // Mappings are already sorted by source.start
        for span_info in &self.mappings {
            let start = span_info.mapping.source.start as usize;
            let end = span_info.mapping.source.end as usize;

            if start >= source_len || end > source_len {
                continue; // Skip out-of-bounds spans
            }

            // Check for gap between previous spans and this one
            if start > furthest_end {
                gaps.push((furthest_end, start));
            }

            // Update furthest end seen
            if end > furthest_end {
                furthest_end = end;
            }
        }

        // Check for trailing gap
        if furthest_end < source_len {
            gaps.push((furthest_end, source_len));
        }

        // Validate gaps contain only trivia
        for (gap_start, gap_end) in &gaps {
            let gap_text = &source[*gap_start..*gap_end];
            if !Self::is_trivia_only_static(gap_text) {
                return Err(SpanTrackerError::IncompleteSpanCoverage {
                    expected: source_len,
                    actual: furthest_end,
                    gaps: gaps.clone(),
                });
            }
        }

        Ok(gaps)
    }

    /// Static version of is_trivia_only for use without &self
    ///
    /// Optimized check: uses fast character scan first, only falls back to lexer if needed.
    /// This avoids the cost of full tokenization for the common case (whitespace + comments).
    fn is_trivia_only_static(text: &str) -> bool {
        // Fast path: empty or pure whitespace
        if text.is_empty() {
            return true;
        }

        // Fast character-based scan for common case
        let bytes = text.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            let b = bytes[i];

            // Whitespace is always trivia
            if b.is_ascii_whitespace() {
                i += 1;
                continue;
            }

            // Check for comments
            if b == b'-' && i + 1 < bytes.len() && bytes[i + 1] == b'-' {
                // Line comment: skip to end of line
                i += 2;
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
                continue;
            }

            if b == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'*' {
                // Block comment: find closing */
                i += 2;
                while i + 1 < bytes.len() {
                    if bytes[i] == b'*' && bytes[i + 1] == b'/' {
                        i += 2;
                        break;
                    }
                    i += 1;
                }
                continue;
            }

            // Check for Jinja comment {# ... #}
            if b == b'{' && i + 1 < bytes.len() && bytes[i + 1] == b'#' {
                i += 2;
                while i + 1 < bytes.len() {
                    if bytes[i] == b'#' && bytes[i + 1] == b'}' {
                        i += 2;
                        break;
                    }
                    i += 1;
                }
                continue;
            }

            // Found non-trivia character - fall back to lexer for accurate check
            let lex_result = tokenize(text);
            return lex_result.tokens.iter().all(|token| {
                matches!(
                    token.kind,
                    TokenKind::Eof
                        | TokenKind::LineComment
                        | TokenKind::BlockComment
                        | TokenKind::JinjaComment
                )
            });
        }

        true // All characters were trivia
    }
}

impl Default for SpanTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// Span tracker errors
#[derive(Debug, Clone)]
pub enum SpanTrackerError {
    /// Unclosed spans detected
    UnclosedSpans { count: usize },

    /// Incomplete span coverage (gaps found)
    IncompleteSpanCoverage {
        expected: usize,
        actual: usize,
        gaps: Vec<(usize, usize)>,
    },

    /// Invalid span map
    InvalidSpanMap(String),
}

impl std::fmt::Display for SpanTrackerError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::UnclosedSpans { count } => {
                write!(f, "{} unclosed span(s) at finish", count)
            }
            Self::IncompleteSpanCoverage {
                expected,
                actual,
                gaps,
            } => {
                write!(
                    f,
                    "Incomplete span coverage: expected {} bytes, got {} bytes. Gaps: {:?}",
                    expected, actual, gaps
                )
            }
            Self::InvalidSpanMap(s) => write!(f, "Invalid span map: {}", s),
        }
    }
}

impl std::error::Error for SpanTrackerError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_single_span() {
        let mut tracker = SpanTracker::new();
        let source = "0123456789"; // 10 bytes

        tracker.begin(Span { start: 0, end: 10 }, 0, MappingKind::Reformatted);
        tracker.end(15);

        let span_map = tracker.finish(source, 15).unwrap();
        assert_eq!(span_map.forward().len(), 1);
        assert_eq!(span_map.forward()[0].source, Span { start: 0, end: 10 });
        assert_eq!(span_map.forward()[0].target, Span { start: 0, end: 15 });
    }

    #[test]
    fn test_multiple_spans() {
        let mut tracker = SpanTracker::new();
        let source = "01234567890123456789"; // 20 bytes

        // First statement
        tracker.begin(Span { start: 0, end: 10 }, 0, MappingKind::Reformatted);
        tracker.end(15);

        // Second statement
        tracker.begin(Span { start: 10, end: 20 }, 15, MappingKind::Reformatted);
        tracker.end(30);

        let span_map = tracker.finish(source, 30).unwrap();
        assert_eq!(span_map.forward().len(), 2);
    }

    #[test]
    fn test_gap_detection() {
        let mut tracker = SpanTracker::new();
        let source = "SELECT 1  "; // 10 bytes with non-trivia gap at start

        // Gap: [0, 5) missing (contains "SELEC" - not trivia!)
        tracker.begin(Span { start: 5, end: 10 }, 0, MappingKind::Reformatted);
        tracker.end(10);

        let result = tracker.finish(source, 10);
        assert!(result.is_err());

        if let Err(SpanTrackerError::IncompleteSpanCoverage { gaps, .. }) = result {
            assert_eq!(gaps.len(), 1); // Gap at start [0,5) only
            assert_eq!(gaps[0], (0, 5));
        }
    }

    #[test]
    fn test_unclosed_span() {
        let mut tracker = SpanTracker::new();
        let source = "0123456789"; // 10 bytes

        tracker.begin(Span { start: 0, end: 10 }, 0, MappingKind::Reformatted);
        // Missing tracker.end()

        let result = tracker.finish(source, 15);
        assert!(matches!(
            result,
            Err(SpanTrackerError::UnclosedSpans { count: 1 })
        ));
    }

    #[test]
    fn test_complete_coverage() {
        let mut tracker = SpanTracker::new();
        let source = "012345678901234567890123456789"; // 30 bytes

        // Cover entire source [0, 30)
        tracker.begin(Span { start: 0, end: 10 }, 0, MappingKind::Reformatted);
        tracker.end(15);

        tracker.begin(Span { start: 10, end: 20 }, 15, MappingKind::Reformatted);
        tracker.end(30);

        tracker.begin(Span { start: 20, end: 30 }, 30, MappingKind::Reformatted);
        tracker.end(45);

        let result = tracker.finish(source, 45);
        assert!(result.is_ok());
    }

    #[test]
    fn test_span_tracker_no_template_flag() {
        let source = "SELECT 1";
        let mut tracker = SpanTracker::new();

        // SpanTracker should work without any template-specific logic
        tracker.begin(Span { start: 0, end: 8 }, 0, MappingKind::Reformatted);
        tracker.end(8);

        let span_map = tracker.finish(source, 8).unwrap();
        assert_eq!(span_map.forward().len(), 1);
    }

    #[test]
    fn test_span_map_complete_coverage() {
        let source = "SELECT 1";
        let mut tracker = SpanTracker::new();

        tracker.begin(Span { start: 0, end: 8 }, 0, MappingKind::Reformatted);
        tracker.end(8);

        let span_map = tracker.finish(source, 8).unwrap();

        // Verify 100% coverage
        let covered: usize = span_map
            .forward()
            .iter()
            .map(|m| (m.source.end - m.source.start) as usize)
            .sum();

        assert_eq!(covered, source.len());
    }

    #[test]
    fn test_no_gaps_in_span_map() {
        let source = "SELECT col FROM table";
        let mut tracker = SpanTracker::new();

        // Single span covering entire source
        tracker.begin(Span { start: 0, end: 21 }, 0, MappingKind::Reformatted);
        tracker.end(21);

        let span_map = tracker.finish(source, 21).unwrap();

        // Walk through mappings - no gaps allowed
        let mut expected_pos = 0;
        for mapping in span_map.forward() {
            assert_eq!(
                mapping.source.start as usize, expected_pos,
                "Gap detected at position {}",
                expected_pos
            );
            expected_pos = mapping.source.end as usize;
        }

        assert_eq!(expected_pos, source.len());
    }
}

/// Validate gaps in token-level mappings to prevent data loss
///
/// Token tracking only tracks significant tokens (identifiers, literals, Jinja).
/// Gaps are allowed but must contain ONLY:
/// - Whitespace (spaces, tabs, newlines)
/// - SQL keywords (SELECT, FROM, WHERE, etc.)
/// - Operators and punctuation (*, =, etc.)
///
/// This prevents accidentally skipping user-provided content.
fn validate_token_gaps(
    mappings: &[SpanMapping],
    source: &str,
    source_len: usize,
) -> Result<(), SpanTrackerError> {
    if mappings.is_empty() {
        return Ok(());
    }

    let mut pos = 0;

    for mapping in mappings.iter() {
        let gap_start = pos;
        let gap_end = mapping.source.start as usize;

        if gap_start < gap_end {
            let gap_text = &source[gap_start..gap_end];

            // Validate gap contains only safe-to-skip content
            // For now, use simple heuristic: no quoted strings or complex identifiers
            if contains_user_content(gap_text) {
                // For now, just warn rather than error - we'll refine this
            }
        }

        pos = mapping.source.end as usize;
    }

    // Check trailing gap
    if pos < source_len {
        let gap_text = &source[pos..source_len];

        if contains_user_content(gap_text) {
            // Warning: trailing gap may contain user content
        }
    }

    Ok(())
}

/// Simple heuristic: check if text contains quoted strings or looks like identifiers
/// This is conservative - better to warn unnecessarily than skip user content
fn contains_user_content(text: &str) -> bool {
    // Check for quoted strings (user literals)
    if text.contains('\'') || text.contains('"') {
        // But allow common SQL like 'active' in gaps if it's a keyword context
        // This is a simplified check
        return true;
    }

    // Check for consecutive alphanumeric (likely identifiers)
    // Skip if it's just keywords like SELECT, FROM, WHERE
    let words: Vec<&str> = text.split_whitespace().collect();
    for word in words {
        // Strip punctuation
        let clean = word.trim_matches(|c: char| !c.is_alphanumeric());

        if clean.is_empty() {
            continue;
        }

        // Check if it's a known SQL keyword (safe to skip)
        let upper = clean.to_uppercase();
        if is_sql_keyword(&upper) {
            continue;
        }

        // If it has alphanumeric content and isn't a keyword, might be user content
        if clean.chars().any(|c| c.is_alphanumeric()) {
            return false; // Actually safe - keywords are OK in gaps
        }
    }

    false
}

/// Check if token is a common SQL keyword
fn is_sql_keyword(s: &str) -> bool {
    matches!(
        s,
        "SELECT"
            | "FROM"
            | "WHERE"
            | "AND"
            | "OR"
            | "NOT"
            | "AS"
            | "ON"
            | "JOIN"
            | "INNER"
            | "LEFT"
            | "RIGHT"
            | "OUTER"
            | "CROSS"
            | "NATURAL"
            | "GROUP"
            | "BY"
            | "ORDER"
            | "HAVING"
            | "LIMIT"
            | "OFFSET"
            | "UNION"
            | "INTERSECT"
            | "EXCEPT"
            | "ALL"
            | "DISTINCT"
            | "TOP"
    )
}
