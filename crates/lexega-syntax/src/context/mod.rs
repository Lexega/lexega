// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! RenderContext - metadata that travels with one source text
//!
//! A `RenderContext` owns the source, whether it is a template, the
//! diagnostics raised against it, and — once the formatter has run — the
//! formatted text with its source→formatted span map.
//!
//! # Architecture
//!
//! RenderContext follows an immutable snapshot pattern: each stage takes a
//! context and returns a new one.
//! 1. `from_source`: the source text alone
//! 2. `mark_as_template`: the source holds Jinja blocks
//! 3. `with_formatted`: formatted text and span map attached

// Re-exports
pub use self::diagnostics::{Diagnostic, Severity};
pub use self::formatted::{FormattedContext, FormattedContextError};
pub use self::span_map::{MappingKind, SpanMap, SpanMapError, SpanMapping};

// Module declarations
pub mod diagnostics;
mod formatted;
pub mod span_map;

/// Central metadata container for SQL analysis, formatting, and template processing
///
/// Size: ~120 bytes (excluding heap allocations)
/// Lifetime: Immutable snapshot pattern - new context per lifecycle phase
///
/// See module-level documentation for usage examples.
#[derive(Debug, Clone)]
pub struct RenderContext {
    /// Original source text (owned)
    /// Heap: O(source_len) bytes
    source: String,

    /// Formatting-specific context (if source was formatted)
    /// Heap: O(formatted_size) when Some, 0 when None
    /// Boxed to keep RenderContext size predictable
    formatted: Option<Box<FormattedContext>>,

    /// Diagnostic messages accumulated during processing, in the order
    /// added.
    /// Heap: O(num_diagnostics * 100) bytes approximately
    diagnostics: Vec<Diagnostic>,

    /// True if source contains Jinja blocks — the formatter preserves
    /// template regions byte-exactly when set
    is_template: bool,
}

impl RenderContext {
    /// Create from source text only
    ///
    /// Time: O(1)
    /// Space: O(source_len)
    ///
    /// Use this when you have raw SQL without AST.
    pub fn from_source(source: impl Into<String>) -> Self {
        Self {
            source: source.into(),
            formatted: None,
            diagnostics: Vec::new(),
            is_template: false,
        }
    }

    /// Mark context as having template/Jinja content so the formatter
    /// preserves TriviaMap and template regions exactly.
    pub fn mark_as_template(mut self) -> Self {
        self.is_template = true;
        self
    }

    /// Add formatted context (immutable pattern - returns new context)
    ///
    /// Time: O(1) - just moves data
    /// Space: O(formatted_size) additional
    ///
    /// # Panics
    ///
    /// Panics if formatted context is already set.
    pub fn with_formatted(mut self, formatted_ctx: FormattedContext) -> Self {
        assert!(self.formatted.is_none(), "Formatted already set");
        self.formatted = Some(Box::new(formatted_ctx));
        self
    }

    // ========== Accessors ==========

    /// Get source text
    pub fn source(&self) -> &str {
        &self.source
    }

    /// Get all diagnostics
    pub fn diagnostics(&self) -> &[Diagnostic] {
        &self.diagnostics
    }

    /// Get formatted context (if present)
    pub fn formatted(&self) -> Option<&FormattedContext> {
        self.formatted.as_deref()
    }

    /// Check if context has template data
    pub fn has_template(&self) -> bool {
        self.is_template
    }

    /// Check if context has formatting data
    pub fn has_formatted(&self) -> bool {
        self.formatted.is_some()
    }

    /// Add a diagnostic message. Diagnostics keep the order they are added
    /// in; identical ones are not merged.
    pub fn add_diagnostic(&mut self, diagnostic: Diagnostic) {
        self.diagnostics.push(diagnostic);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lexer::Span;

    #[test]
    fn test_from_source() {
        let ctx = RenderContext::from_source("SELECT * FROM users".to_string());

        assert_eq!(ctx.source(), "SELECT * FROM users");
        assert!(!ctx.has_template());
        assert!(!ctx.has_formatted());
        assert_eq!(ctx.diagnostics().len(), 0);
    }

    #[test]
    fn test_with_formatted() {
        let source = "SELECT * FROM users";
        let formatted = "SELECT\n  *\nFROM\n  users";

        let ctx = RenderContext::from_source(source.to_string());

        // Create formatted context
        let mappings = vec![SpanMapping {
            source: Span { start: 0, end: 19 },
            target: Span { start: 0, end: 23 },
            kind: MappingKind::Reformatted,
        }];

        let span_map =
            SpanMap::from_mappings(source.len(), formatted.len(), mappings, false).unwrap();

        let formatted_ctx = FormattedContext::new(formatted.to_string(), span_map).unwrap();

        let ctx = ctx.with_formatted(formatted_ctx);

        assert!(!ctx.has_template());
        assert!(ctx.has_formatted());
        assert!(ctx.formatted().is_some());
    }

    #[test]
    fn test_add_diagnostics() {
        let mut ctx = RenderContext::from_source("SELECT * FROM users".to_string());

        assert_eq!(ctx.diagnostics().len(), 0);

        // Add some diagnostics
        ctx.add_diagnostic(Diagnostic {
            span: Span { start: 0, end: 6 },
            severity: Severity::Warning,
            message: "Test warning".to_string(),
            code: Some("W001".to_string()),
        });

        ctx.add_diagnostic(Diagnostic {
            span: Span { start: 14, end: 19 },
            severity: Severity::Error,
            message: "Test error".to_string(),
            code: Some("E001".to_string()),
        });

        assert_eq!(ctx.diagnostics().len(), 2);
    }

    #[test]
    #[should_panic(expected = "Formatted already set")]
    fn test_double_formatted_panics() {
        let ctx = RenderContext::from_source("SELECT * FROM users".to_string());

        let source = "SELECT * FROM users";
        let formatted = "SELECT\n  *\nFROM\n  users";

        let mappings = vec![SpanMapping {
            source: Span { start: 0, end: 19 },
            target: Span { start: 0, end: 23 },
            kind: MappingKind::Reformatted,
        }];

        let span_map =
            SpanMap::from_mappings(source.len(), formatted.len(), mappings.clone(), false).unwrap();

        let formatted_ctx1 = FormattedContext::new(formatted.to_string(), span_map).unwrap();

        let ctx = ctx.with_formatted(formatted_ctx1);

        // Try to add again - should panic
        let span_map2 =
            SpanMap::from_mappings(source.len(), formatted.len(), mappings, false).unwrap();

        let formatted_ctx2 = FormattedContext::new(formatted.to_string(), span_map2).unwrap();

        let _ = ctx.with_formatted(formatted_ctx2);
    }
}
