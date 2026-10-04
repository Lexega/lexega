// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Records a substitution or render pass leaves behind: the placeholders
//! it inserted for values it could not resolve, and the dependencies it
//! discovered.

/// Kind of placeholder inserted during rendering
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlaceholderKind {
    /// Table/view reference that couldn't be resolved
    Relation,
    /// Column name(s) from introspection
    Column,
    /// Schema name
    Schema,
    /// Result of run_query or similar
    QueryResult,
    /// Adapter method call (e.g., adapter.get_columns_in_relation)
    AdapterCall,
    /// Environment variable
    EnvVar,
    /// dbt var() reference
    Var,
    /// Invocation context (run_started_at, etc.)
    InvocationContext,
    /// Unrecognized macro, filter, or test that rendered with a lenient
    /// fallback value instead of failing
    UnknownConstruct,
    /// Undefined Jinja variable interpolation (`{{ user_input }}`) — a template
    /// hole where a value splices in at run time. Rendered as a placeholder
    /// sentinel rather than an empty string so downstream analysis sees the
    /// injected value, not a benign blank.
    UndefinedVar,
}

/// Record of a placeholder inserted during rendering
#[derive(Debug, Clone)]
pub struct PlaceholderRecord {
    /// Unique ID for this placeholder (used in sentinel token)
    pub placeholder_id: u32,
    /// Kind of placeholder
    pub kind: PlaceholderKind,
    /// Macro/function that required the placeholder
    pub origin: String,
    /// Position in source template
    pub source_position: usize,
    /// Start position in rendered output (byte offset)
    pub render_start: usize,
    /// End position in rendered output (byte offset)  
    pub render_end: usize,
    /// The placeholder text that was inserted (the sentinel token)
    pub placeholder_text: String,
}

/// Kind of dbt dependency discovered during rendering
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DependencyKind {
    /// ref('model') - model-to-model reference
    Ref {
        model_name: String,
        /// Package name for cross-project refs: ref('package', 'model')
        package: Option<String>,
    },
    /// source('source_name', 'table_name') - source table reference
    Source {
        source_name: String,
        table_name: String,
    },
    /// var('name') - variable reference
    Var {
        name: String,
        default_value: Option<String>,
    },
    /// config(...) - model configuration
    Config { args: Vec<(String, String)> },
}

/// Record of a dbt dependency discovered during rendering
///
/// Unlike AST-based extraction, this captures the *actual evaluated* values
/// at render time, including dynamic refs like `{{ ref(model_var) }}`.
#[derive(Debug, Clone)]
pub struct DependencyRecord {
    /// Kind and details of the dependency
    pub kind: DependencyKind,
    /// The resolved table/value name (what was emitted to SQL)
    pub resolved_name: String,
    /// Source position where this was found in the template
    pub source_position: usize,
    /// Rendered position where this was emitted in output
    pub rendered_position: usize,
}
