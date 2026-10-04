// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Bidirectional span mapping with completeness guarantees

use crate::lexer::Span;
use std::cmp::Ordering;

/// Bidirectional span mapping with completeness guarantees
///
/// Maintains forward (source → target) and reverse (target → source) mappings.
/// Enforces complete coverage invariant: every byte must be mapped.
#[derive(Debug, Clone)]
pub struct SpanMap {
    /// Forward mappings: source → target (sorted by source position)
    forward: Vec<SpanMapping>,

    /// Reverse mappings: target → source (sorted by target position)
    reverse: Vec<SpanMapping>,
}

/// A single span mapping between source and target coordinate spaces
///
/// Size: 20 bytes (4 u32s + 1 enum discriminant + padding)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpanMapping {
    /// Source span
    pub source: Span,

    /// Target span (formatted output)
    pub target: Span,

    /// Mapping type (for debugging and analysis)
    pub kind: MappingKind,
}

/// Type of span mapping
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MappingKind {
    /// Content copied verbatim (may have whitespace changes)
    Identity,

    /// Content reformatted (indentation, line breaks, case changes)
    Reformatted,

    /// Source content removed (e.g., extra whitespace stripped)
    Deleted,

    /// Content inserted (e.g., added indentation)
    Inserted,
}

/// Errors that can occur during span map construction
#[derive(Debug, Clone)]
pub enum SpanMapError {
    /// No mappings provided for non-empty source
    EmptyMapping,

    /// Gap detected in forward mapping
    ForwardGap {
        at_offset: usize,
        next_mapping_starts: usize,
    },

    /// Gap detected in reverse mapping
    ReverseGap { at_offset: usize },

    /// Invalid mapping (end before start)
    InvalidMapping {
        mapping: SpanMapping,
        reason: &'static str,
    },

    /// Forward mapping doesn't cover entire source
    IncompleteCoverage { expected: usize, actual: usize },

    /// Reverse mapping doesn't cover entire target
    ReverseIncompleteCoverage { expected: usize, actual: usize },
}

impl SpanMap {
    /// Build span map from formatter output with validation
    ///
    /// Time: O(n log n) for sorting + O(n) for validation
    /// Space: O(n)
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Mappings don't cover entire source (gaps detected)
    /// - Mappings don't cover entire target (reverse gaps)
    /// - Mappings are invalid (end before start)
    pub fn from_mappings(
        source_len: usize,
        target_len: usize,
        mut mappings: Vec<SpanMapping>,
        validate_reverse: bool,
    ) -> Result<Self, SpanMapError> {
        // Handle empty case
        if mappings.is_empty() {
            if source_len == 0 && target_len == 0 {
                return Ok(Self {
                    forward: Vec::new(),
                    reverse: Vec::new(),
                });
            } else {
                return Err(SpanMapError::EmptyMapping);
            }
        }

        // Sort by source position for forward mapping
        mappings.sort_by_key(|m| m.source.start);

        // Validate forward completeness
        Self::validate_forward(&mappings, source_len)?;

        // Build reverse mappings (sorted by target position)
        let mut reverse = mappings.clone();
        reverse.sort_by_key(|m| m.target.start);

        // Validate reverse completeness (only needed for Jinja templates)
        if validate_reverse {
            Self::validate_reverse(&reverse, target_len)?;
        }

        Ok(Self {
            forward: mappings,
            reverse,
        })
    }

    /// Validate forward mapping completeness
    ///
    /// Ensures every source byte is mapped with no gaps or overlaps.
    fn validate_forward(mappings: &[SpanMapping], source_len: usize) -> Result<(), SpanMapError> {
        let mut expected_pos = 0;

        for mapping in mappings.iter() {
            // Check for invalid mapping
            if mapping.source.end < mapping.source.start {
                return Err(SpanMapError::InvalidMapping {
                    mapping: *mapping,
                    reason: "source end before start",
                });
            }

            // Check for gap
            let start = mapping.source.start as usize;
            if start != expected_pos {
                return Err(SpanMapError::ForwardGap {
                    at_offset: expected_pos,
                    next_mapping_starts: start,
                });
            }

            expected_pos = mapping.source.end as usize;
        }

        // Check final position matches source length
        if expected_pos != source_len {
            return Err(SpanMapError::IncompleteCoverage {
                expected: source_len,
                actual: expected_pos,
            });
        }

        Ok(())
    }

    /// Validate reverse mapping completeness
    fn validate_reverse(mappings: &[SpanMapping], target_len: usize) -> Result<(), SpanMapError> {
        let mut expected_pos = 0;

        for mapping in mappings {
            // Check for invalid mapping
            if mapping.target.end < mapping.target.start {
                return Err(SpanMapError::InvalidMapping {
                    mapping: *mapping,
                    reason: "target end before start",
                });
            }

            // Check for gap
            let start = mapping.target.start as usize;
            if start != expected_pos {
                return Err(SpanMapError::ReverseGap {
                    at_offset: expected_pos,
                });
            }

            expected_pos = mapping.target.end as usize;
        }

        // Check final position matches target length
        if expected_pos != target_len {
            return Err(SpanMapError::ReverseIncompleteCoverage {
                expected: target_len,
                actual: expected_pos,
            });
        }

        Ok(())
    }

    /// Translate source offset to target offset
    ///
    /// Time: O(log n)
    /// Algorithm: Binary search + linear interpolation within mapping
    pub fn source_to_target(&self, offset: usize) -> Option<usize> {
        // Binary search for mapping containing this offset
        let idx = self
            .forward
            .binary_search_by(|m| {
                let start = m.source.start as usize;
                let end = m.source.end as usize;

                if offset < start {
                    Ordering::Greater
                } else if offset >= end {
                    Ordering::Less
                } else {
                    Ordering::Equal
                }
            })
            .ok()?;

        let mapping = &self.forward[idx];

        // Linear interpolation within mapping
        let offset_in_mapping = offset - mapping.source.start as usize;
        let source_len = (mapping.source.end - mapping.source.start) as usize;
        let target_len = (mapping.target.end - mapping.target.start) as usize;

        if source_len == 0 {
            // Zero-width source (insertion point)
            return Some(mapping.target.start as usize);
        }

        // Use offset-based translation for Identity mappings, proportional for others
        let target_offset = match mapping.kind {
            MappingKind::Identity => {
                // 1:1 mapping - offset in source equals offset in target
                offset_in_mapping
            }
            _ => {
                // Proportional scaling for reformatted content
                (offset_in_mapping * target_len) / source_len
            }
        };
        Some(mapping.target.start as usize + target_offset)
    }

    /// Translate source span to target span
    ///
    /// Time: O(log n)
    ///
    /// Translates an entire source span to its corresponding target span.
    /// Uses proportional scaling: if source span is X% of source mapping,
    /// target span will be X% of target mapping.
    pub fn translate_span(&self, source_span: Span) -> Option<Span> {
        // Handle zero-width spans
        if source_span.start == source_span.end {
            let pos = self.source_to_target(source_span.start as usize)?;
            return Some(Span {
                start: pos as u32,
                end: pos as u32,
            });
        }

        // Find mapping containing span start
        let idx = self
            .forward
            .binary_search_by(|m| {
                let start = m.source.start as usize;
                let end = m.source.end as usize;
                let offset = source_span.start as usize;

                if offset < start {
                    Ordering::Greater
                } else if offset >= end {
                    Ordering::Less
                } else {
                    Ordering::Equal
                }
            })
            .ok()?;

        let mapping = &self.forward[idx];

        // Calculate proportional span in target space
        let span_start_in_mapping = (source_span.start - mapping.source.start) as usize;
        let span_len = (source_span.end - source_span.start) as usize;
        let source_mapping_len = (mapping.source.end - mapping.source.start) as usize;
        let target_mapping_len = (mapping.target.end - mapping.target.start) as usize;

        if source_mapping_len == 0 {
            return None;
        }

        // Use offset-based translation for Identity mappings, proportional for others
        let (target_start_offset, target_span_len) = match mapping.kind {
            MappingKind::Identity => {
                // 1:1 mapping - preserve exact offsets and lengths
                (span_start_in_mapping, span_len)
            }
            _ => {
                // Proportional scaling for reformatted content
                let target_start_offset =
                    (span_start_in_mapping * target_mapping_len) / source_mapping_len;
                let target_span_len = (span_len * target_mapping_len) / source_mapping_len;
                (target_start_offset, target_span_len)
            }
        };

        let target_start = mapping.target.start as usize + target_start_offset;
        let target_end = target_start + target_span_len;

        Some(Span {
            start: target_start as u32,
            end: target_end as u32,
        })
    }

    /// Translate target offset to source offset
    ///
    /// Time: O(log n)
    pub fn target_to_source(&self, offset: usize) -> Option<usize> {
        // Binary search in reverse mappings
        let idx = self
            .reverse
            .binary_search_by(|m| {
                let start = m.target.start as usize;
                let end = m.target.end as usize;

                if offset < start {
                    Ordering::Greater
                } else if offset >= end {
                    Ordering::Less
                } else {
                    Ordering::Equal
                }
            })
            .ok()?;

        let mapping = &self.reverse[idx];

        // Linear interpolation within mapping
        let offset_in_mapping = offset - mapping.target.start as usize;
        let target_len = (mapping.target.end - mapping.target.start) as usize;
        let source_len = (mapping.source.end - mapping.source.start) as usize;

        if target_len == 0 {
            // Zero-width target (deletion point)
            return Some(mapping.source.start as usize);
        }

        // Use offset-based translation for Identity mappings, proportional for others
        let source_offset = match mapping.kind {
            MappingKind::Identity => {
                // 1:1 mapping - offset in target equals offset in source
                offset_in_mapping
            }
            _ => {
                // Proportional scaling for reformatted content
                (offset_in_mapping * source_len) / target_len
            }
        };
        Some(mapping.source.start as usize + source_offset)
    }

    /// Translate source span to target span(s)
    ///
    /// May return multiple spans if mapping is non-contiguous.
    ///
    /// Time: O(log n + k) where k = number of mappings in range
    pub fn source_span_to_target(&self, span: Span) -> Vec<Span> {
        let mut results = Vec::new();

        for mapping in &self.forward {
            // Check if this mapping overlaps our source span
            if mapping.source.end <= span.start {
                continue;
            }
            if mapping.source.start >= span.end {
                break;
            }

            // Calculate overlap
            let overlap_start = mapping.source.start.max(span.start);
            let overlap_end = mapping.source.end.min(span.end);

            // Translate overlap to target space
            let offset_start = (overlap_start - mapping.source.start) as usize;
            let offset_end = (overlap_end - mapping.source.start) as usize;
            let source_len = (mapping.source.end - mapping.source.start) as usize;
            let target_len = (mapping.target.end - mapping.target.start) as usize;

            if source_len == 0 {
                continue;
            }

            // Use offset-based translation for Identity mappings, proportional for others
            let (target_offset_start, target_offset_end) = match mapping.kind {
                MappingKind::Identity => {
                    // 1:1 mapping - offset in source equals offset in target
                    (offset_start, offset_end)
                }
                _ => {
                    // Proportional scaling for reformatted content
                    (
                        (offset_start * target_len) / source_len,
                        (offset_end * target_len) / source_len,
                    )
                }
            };

            let target_start = mapping.target.start as usize + target_offset_start;
            let target_end = mapping.target.start as usize + target_offset_end;

            results.push(Span {
                start: target_start as u32,
                end: target_end as u32,
            });
        }

        results
    }

    /// Translate target span to source span(s)
    ///
    /// Time: O(log n + k)
    pub fn target_span_to_source(&self, span: Span) -> Vec<Span> {
        let mut results = Vec::new();

        for mapping in &self.reverse {
            // Check if this mapping overlaps our target span
            if mapping.target.end <= span.start {
                continue;
            }
            if mapping.target.start >= span.end {
                break;
            }

            // Calculate overlap
            let overlap_start = mapping.target.start.max(span.start);
            let overlap_end = mapping.target.end.min(span.end);

            // Translate overlap to source space
            let offset_start = (overlap_start - mapping.target.start) as usize;
            let offset_end = (overlap_end - mapping.target.start) as usize;
            let target_len = (mapping.target.end - mapping.target.start) as usize;
            let source_len = (mapping.source.end - mapping.source.start) as usize;

            if target_len == 0 {
                continue;
            }

            // Use offset-based translation for Identity mappings, proportional for others
            let (source_offset_start, source_offset_end) = match mapping.kind {
                MappingKind::Identity => {
                    // 1:1 mapping - offset in target equals offset in source
                    (offset_start, offset_end)
                }
                _ => {
                    // Proportional scaling for reformatted content
                    (
                        (offset_start * source_len) / target_len,
                        (offset_end * source_len) / target_len,
                    )
                }
            };

            let source_start = mapping.source.start as usize + source_offset_start;
            let source_end = mapping.source.start as usize + source_offset_end;

            results.push(Span {
                start: source_start as u32,
                end: source_end as u32,
            });
        }

        results
    }

    /// Get forward mappings (source → target)
    pub fn forward(&self) -> &[SpanMapping] {
        &self.forward
    }

    /// Get reverse mappings (target → source)
    pub fn reverse(&self) -> &[SpanMapping] {
        &self.reverse
    }
}

impl std::fmt::Display for SpanMapError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::EmptyMapping => write!(f, "No mappings provided for non-empty source"),
            Self::ForwardGap {
                at_offset,
                next_mapping_starts,
            } => {
                write!(
                    f,
                    "Gap in forward mapping at offset {}, next mapping starts at {}",
                    at_offset, next_mapping_starts
                )
            }
            Self::ReverseGap { at_offset } => {
                write!(f, "Gap in reverse mapping at offset {}", at_offset)
            }
            Self::InvalidMapping { mapping, reason } => {
                write!(f, "Invalid mapping {:?}: {}", mapping, reason)
            }
            Self::IncompleteCoverage { expected, actual } => {
                write!(
                    f,
                    "Incomplete forward coverage: expected {} bytes, got {}",
                    expected, actual
                )
            }
            Self::ReverseIncompleteCoverage { expected, actual } => {
                write!(
                    f,
                    "Incomplete reverse coverage: expected {} bytes, got {}",
                    expected, actual
                )
            }
        }
    }
}

impl std::error::Error for SpanMapError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity_mapping() {
        let mappings = vec![SpanMapping {
            source: Span { start: 0, end: 10 },
            target: Span { start: 0, end: 10 },
            kind: MappingKind::Identity,
        }];

        let span_map = SpanMap::from_mappings(10, 10, mappings, false).unwrap();

        // Test offset translation
        assert_eq!(span_map.source_to_target(5), Some(5));
        assert_eq!(span_map.target_to_source(5), Some(5));
    }

    #[test]
    fn test_reformatted_mapping() {
        // Source: 20 bytes → Target: 30 bytes (expanded)
        let mappings = vec![SpanMapping {
            source: Span { start: 0, end: 20 },
            target: Span { start: 0, end: 30 },
            kind: MappingKind::Reformatted,
        }];

        let span_map = SpanMap::from_mappings(20, 30, mappings, false).unwrap();

        // Proportional mapping: offset 10 in 20-byte source → offset 15 in 30-byte target
        assert_eq!(span_map.source_to_target(10), Some(15));
        assert_eq!(span_map.target_to_source(15), Some(10));
    }

    #[test]
    fn test_gap_detection() {
        let mappings = vec![
            SpanMapping {
                source: Span { start: 0, end: 10 },
                target: Span { start: 0, end: 10 },
                kind: MappingKind::Identity,
            },
            // GAP: missing 10-15
            SpanMapping {
                source: Span { start: 15, end: 20 },
                target: Span { start: 10, end: 15 },
                kind: MappingKind::Identity,
            },
        ];

        let result = SpanMap::from_mappings(20, 15, mappings, false);
        assert!(matches!(result, Err(SpanMapError::ForwardGap { .. })));
    }

    #[test]
    fn test_multiple_mappings() {
        let mappings = vec![
            SpanMapping {
                source: Span { start: 0, end: 10 },
                target: Span { start: 0, end: 15 },
                kind: MappingKind::Reformatted,
            },
            SpanMapping {
                source: Span { start: 10, end: 20 },
                target: Span { start: 15, end: 25 },
                kind: MappingKind::Identity,
            },
        ];

        let span_map = SpanMap::from_mappings(20, 25, mappings, false).unwrap();

        // Test boundary crossing
        assert_eq!(span_map.source_to_target(0), Some(0));
        assert_eq!(span_map.source_to_target(10), Some(15));
        assert_eq!(span_map.source_to_target(15), Some(20));
    }

    #[test]
    fn test_span_translation() {
        let mappings = vec![SpanMapping {
            source: Span { start: 0, end: 20 },
            target: Span { start: 0, end: 30 },
            kind: MappingKind::Reformatted,
        }];

        let span_map = SpanMap::from_mappings(20, 30, mappings, false).unwrap();

        // Test span translation
        let source_span = Span { start: 0, end: 10 };
        let target_span = span_map.translate_span(source_span).unwrap();

        // Proportional: 10 bytes in 20-byte source → 15 bytes in 30-byte target
        assert_eq!(target_span.start, 0);
        assert_eq!(target_span.end, 15);

        // Test full span
        let source_span = Span { start: 0, end: 20 };
        let target_span = span_map.translate_span(source_span).unwrap();
        assert_eq!(target_span.start, 0);
        assert_eq!(target_span.end, 30);
    }

    #[test]
    fn test_empty_mapping() {
        let result = SpanMap::from_mappings(0, 0, vec![], false);
        assert!(result.is_ok());

        let result = SpanMap::from_mappings(10, 10, vec![], false);
        assert!(matches!(result, Err(SpanMapError::EmptyMapping)));
    }
}
