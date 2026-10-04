// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Analysis-side context: per-node metadata.
//!
//! The formatting context (`RenderContext`, span maps, diagnostics) lives
//! in `lexega-syntax` and is re-exported here.

pub mod node_metadata;

pub use lexega_syntax::context::{
    diagnostics, span_map, Diagnostic, FormattedContext, FormattedContextError, MappingKind,
    RenderContext, Severity, SpanMap, SpanMapError, SpanMapping,
};
