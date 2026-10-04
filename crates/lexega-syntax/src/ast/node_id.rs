// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

use crate::error::ExpectInvariant;

/// Unique identifier for AST nodes.
///
/// NodeId provides a stable reference to AST nodes that persists through
/// formatting, linting, and other transformations. This enables:
/// - Precise error reporting and diagnostics
/// - IDE features (go-to-definition, find-references)
/// - Template rendering with exact source mapping
/// - Query optimization and rewriting
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NodeId(u32);

impl NodeId {
    /// Create a new NodeId from a raw u32 value.
    /// This is primarily for internal use by NodeIdGenerator.
    #[inline]
    pub fn new(id: u32) -> Self {
        NodeId(id)
    }

    /// Get the raw u32 value of this NodeId.
    #[inline]
    pub fn as_u32(self) -> u32 {
        self.0
    }
}

impl std::fmt::Display for NodeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "#{}", self.0)
    }
}

/// Generator for unique NodeIds during parsing.
///
/// Each Parser instance should have its own NodeIdGenerator to ensure
/// unique IDs across an entire parse tree.
///
/// Uses `Cell<u32>` for interior mutability without runtime borrow checking.
#[derive(Debug)]
pub struct NodeIdGenerator {
    next_id: std::cell::Cell<u32>,
}

impl NodeIdGenerator {
    /// Create a new NodeIdGenerator starting from ID 0.
    pub fn new() -> Self {
        NodeIdGenerator {
            next_id: std::cell::Cell::new(0),
        }
    }

    /// Generate the next unique NodeId.
    ///
    /// Uses Cell for interior mutability, allowing multiple calls
    /// in the same expression without RefCell borrow panics.
    ///
    /// # Panics
    /// Panics if the ID counter overflows u32::MAX (extremely unlikely in practice).
    #[inline]
    pub fn next(&self) -> NodeId {
        let id = self.next_id.get();
        let next = id
            .checked_add(1)
            .expect_invariant("NodeId overflow: more than 4 billion nodes in single parse tree");
        self.next_id.set(next);
        NodeId(id)
    }

    /// Reset the generator back to 0.
    /// This is primarily useful for testing.
    #[cfg(test)]
    pub fn reset(&mut self) {
        self.next_id.set(0);
    }
}

impl Default for NodeIdGenerator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_node_id_generation() {
        let gen = NodeIdGenerator::new();
        let id1 = gen.next();
        let id2 = gen.next();
        let id3 = gen.next();

        assert_eq!(id1.as_u32(), 0);
        assert_eq!(id2.as_u32(), 1);
        assert_eq!(id3.as_u32(), 2);
        assert!(id1 < id2);
        assert!(id2 < id3);
    }

    #[test]
    fn test_node_id_display() {
        let id = NodeId::new(42);
        assert_eq!(format!("{}", id), "#42");
    }
}
