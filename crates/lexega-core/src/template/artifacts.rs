// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! The product of preparing one source for analysis: the text to analyze
//! plus everything the report needs to describe how faithfully that text
//! was produced.

use crate::analyzer::PlaceholderStats;
use crate::template::records::{DependencyRecord, PlaceholderRecord};
use crate::template::source_map::SourceMap;

/// The product of rendering one source for analysis: the text to analyze
/// plus everything the report needs to describe how faithfully that text
/// was produced. Analysis entry points consume this whole — the text and
/// its provenance can never be paired wrong.
#[derive(Debug, Clone, Default)]
pub struct RenderArtifacts {
    /// The SQL to analyze — rendered output, or the original text when no
    /// template was present (or rendering failed).
    pub sql: String,
    /// Rendered-line → template-line provenance; `None` when no render
    /// happened (an empty map and `None` resolve identically).
    pub source_map: Option<SourceMap>,
    /// Standalone Jinja blocks that rendered to nothing.
    pub jinja_blocks: usize,
    /// Placeholder confidence counts (unresolved refs / vars / macros).
    pub placeholders: PlaceholderStats,
    /// Byte-spans of unresolved-placeholder text in `sql`. Only spans whose
    /// coordinates are valid in `sql` are ever attached (a later rewrite
    /// invalidates earlier offsets — see
    /// [`Self::extend_placeholder_spans_if_current`]). The parser consumes
    /// these so a credential value that is a rendered placeholder is not
    /// reported as a hardcoded literal.
    pub placeholder_spans: Vec<crate::lexer::token::Span>,
    /// Dependencies captured during rendering (refs, sources).
    pub dependencies: Vec<DependencyRecord>,
    /// A template was present but was not rendered: `sql` is the template
    /// text, the report must say NotRendered, and the message says why.
    pub render_error: Option<String>,
}

/// Map render placeholder records to lexer spans — byte offsets in the
/// producing stage's output text.
pub fn record_spans(records: &[PlaceholderRecord]) -> Vec<crate::lexer::token::Span> {
    records
        .iter()
        .map(|r| crate::lexer::token::Span {
            start: r.render_start as u32,
            end: r.render_end as u32,
        })
        .collect()
}

impl RenderArtifacts {
    /// Source with no template involved: analyzed as-is, full confidence.
    pub fn raw(sql: String) -> Self {
        Self {
            sql,
            ..Self::default()
        }
    }

    /// Attach placeholder spans from `records` when `produced_sql` — the
    /// text those record offsets index — is byte-identical to the text
    /// analysis will parse (`self.sql`). A later stage's rewrite makes
    /// earlier offsets stale, so spans attach only from the stage whose
    /// output IS the analyzed text; on mismatch the spans are dropped and
    /// the placeholders count only toward confidence.
    pub fn extend_placeholder_spans_if_current(
        &mut self,
        produced_sql: &str,
        records: &[PlaceholderRecord],
    ) {
        if self.sql == produced_sql {
            self.attach_placeholder_spans(records);
        }
    }

    /// Unconditional variant of
    /// [`Self::extend_placeholder_spans_if_current`]: the caller asserts
    /// `records` index `self.sql` (e.g. it just assigned `sql` from the
    /// producing stage's output).
    pub fn attach_placeholder_spans(&mut self, records: &[PlaceholderRecord]) {
        self.placeholder_spans.extend(record_spans(records));
    }

    /// Template present but not rendered — analysis proceeds on the
    /// template text and the report says NotRendered.
    pub fn not_rendered(template_text: String, why: String) -> Self {
        Self {
            sql: template_text,
            render_error: Some(why),
            ..Self::default()
        }
    }

    /// True when a template was present but analysis fell back to the
    /// template text.
    pub fn render_failed(&self) -> bool {
        self.render_error.is_some()
    }
}
