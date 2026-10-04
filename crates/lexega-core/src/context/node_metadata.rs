// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Node metadata types

use crate::ir::normalize_identifier;
use serde::{Deserialize, Serialize};

// ============================================================================
// IDENTIFIER KEY TYPE
// ============================================================================

/// A normalized identifier key for case-insensitive HashMap lookups.
///
/// Snowflake identifiers are case-insensitive unless quoted. This newtype
/// ensures all HashMap keys are properly normalized via `normalize_identifier()`,
/// making it impossible to accidentally use inconsistent casing.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct IdentKey(String);

impl IdentKey {
    /// Create a new normalized identifier key.
    /// The input is normalized according to Snowflake rules:
    /// - Unquoted identifiers → UPPERCASE
    /// - Quoted identifiers → preserve case (in SnowflakeDefault mode)
    #[inline]
    pub fn new(s: &str) -> Self {
        Self(normalize_identifier(s))
    }

    /// Create from an already-normalized string (use with caution).
    /// Only use this when you know the string is already normalized.
    #[inline]
    pub fn from_normalized(s: String) -> Self {
        Self(s)
    }

    /// Get the normalized string value.
    #[inline]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consume and return the inner normalized string.
    #[inline]
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl std::fmt::Display for IdentKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<&str> for IdentKey {
    fn from(s: &str) -> Self {
        Self::new(s)
    }
}

impl From<String> for IdentKey {
    fn from(s: String) -> Self {
        Self::new(&s)
    }
}

impl From<&String> for IdentKey {
    fn from(s: &String) -> Self {
        Self::new(s)
    }
}

impl AsRef<str> for IdentKey {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl std::borrow::Borrow<str> for IdentKey {
    fn borrow(&self) -> &str {
        &self.0
    }
}

/// Normalized table reference (database.schema.table)
///
/// Identifiers may include quotes (e.g., `"MyTable"`) which affects case sensitivity.
/// The `normalize_identifier()` function handles quote detection and case normalization.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct TableRef {
    /// Linked-server name for a T-SQL four-part reference
    /// (`server.database.schema.object`). `None` for the common
    /// three-part-or-fewer case.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,
    /// Database name (may include quotes for case-sensitive identifiers)
    pub db: Option<String>,
    /// Schema name (may include quotes for case-sensitive identifiers)
    pub schema: Option<String>,
    /// Table name (may include quotes for case-sensitive identifiers)
    pub name: String,

    /// Source span in the rendered SQL (for line number tracking in diff reports).
    /// Not included in equality/hash comparisons - just metadata.
    #[serde(skip)]
    pub span: Option<crate::lexer::Span>,
}

impl PartialEq for TableRef {
    fn eq(&self, other: &Self) -> bool {
        // Compare using normalize_identifier which handles quote detection and case normalization
        let server_eq = match (&self.server, &other.server) {
            (Some(a), Some(b)) => normalize_identifier(a) == normalize_identifier(b),
            (None, None) => true,
            _ => false,
        };

        let db_eq = match (&self.db, &other.db) {
            (Some(a), Some(b)) => normalize_identifier(a) == normalize_identifier(b),
            (None, None) => true,
            _ => false,
        };

        let schema_eq = match (&self.schema, &other.schema) {
            (Some(a), Some(b)) => normalize_identifier(a) == normalize_identifier(b),
            (None, None) => true,
            _ => false,
        };

        let name_eq = normalize_identifier(&self.name) == normalize_identifier(&other.name);

        server_eq && db_eq && schema_eq && name_eq
    }
}

impl Eq for TableRef {}

impl std::hash::Hash for TableRef {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        // Hash normalized values for consistent hashing
        match &self.server {
            Some(server) => normalize_identifier(server).hash(state),
            None => None::<String>.hash(state),
        }

        match &self.db {
            Some(db) => normalize_identifier(db).hash(state),
            None => None::<String>.hash(state),
        }

        match &self.schema {
            Some(schema) => normalize_identifier(schema).hash(state),
            None => None::<String>.hash(state),
        }

        normalize_identifier(&self.name).hash(state);
    }
}

impl TableRef {
    pub fn new(name: String) -> Self {
        Self {
            server: None,
            db: None,
            schema: None,
            name,
            span: None,
        }
    }

    /// Get the normalized key for lookups (handles case sensitivity based on quotes).
    pub fn key(&self) -> String {
        normalize_identifier(&self.name)
    }

    pub fn with_schema(mut self, schema: String) -> Self {
        self.schema = Some(schema);
        self
    }

    pub fn with_db(mut self, db: String) -> Self {
        self.db = Some(db);
        self
    }

    /// Set the linked-server name (T-SQL four-part reference).
    pub fn with_server(mut self, server: String) -> Self {
        self.server = Some(server);
        self
    }

    /// Set the source span for line number tracking in diff reports.
    pub fn with_span(mut self, span: crate::lexer::Span) -> Self {
        self.span = Some(span);
        self
    }

    /// Get canonical string representation
    pub fn canonical(&self) -> String {
        let base = match (&self.db, &self.schema) {
            (Some(db), Some(schema)) => format!("{}.{}.{}", db, schema, self.name),
            (None, Some(schema)) => format!("{}.{}", schema, self.name),
            _ => self.name.clone(),
        };
        match &self.server {
            Some(server) => format!("{}.{}", server, base),
            None => base,
        }
    }

    /// Get full 3-part canonical string (database.schema.table), skipping empty parts.
    /// A linked-server name is prefixed when present (four-part reference).
    pub fn full_canonical(&self) -> String {
        let base = match (&self.db, &self.schema) {
            (Some(db), Some(schema)) => format!("{}.{}.{}", db, schema, self.name),
            (None, Some(schema)) => format!("{}.{}", schema, self.name),
            (Some(db), None) => format!("{}.{}", db, self.name),
            (None, None) => self.name.clone(),
        };
        match &self.server {
            Some(server) => format!("{}.{}", server, base),
            None => base,
        }
    }
}

/// Source type for a column reference
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize, Default,
)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum ColumnSourceType {
    /// Regular table or view
    BaseTable,
    /// Common Table Expression
    Cte,
    /// Derived table (subquery in FROM)
    DerivedTable,
    /// Unknown/unqualified
    #[default]
    Unknown,
}

/// Identifier name with quotes preserved.
/// Case-sensitivity is handled via `normalize_identifier()` during lookups.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct IdentName {
    pub name: String,
}

/// Captures a `RENAME (old AS new)` mapping inside a star projection.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct StarRenameMapping {
    pub from: IdentName,
    pub to: IdentName,
}

/// Captures a SELECT star projection (`*` or `t.*`) along with any Snowflake star modifiers.
///
/// This is used to deepen risk semantics (e.g., catalog-backed expansion) without needing
/// to infer modifiers from string signals.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct StarProjectionInfo {
    /// Optional qualifier (e.g., `t` in `t.*`).
    /// Quotes are preserved in the string if the identifier was quoted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub qualifier: Option<String>,

    /// Optional ILIKE filter pattern from `* ILIKE '<pattern>'`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ilike_pattern: Option<String>,

    /// Columns excluded by `EXCLUDE (...)`.
    #[serde(default)]
    pub excluded_columns: Vec<IdentName>,

    /// Columns replaced by `REPLACE (... AS <col>)`.
    ///
    /// Semantics: the base column `<col>` is not projected via `*`; instead the
    /// replacement expression defines the output value for `<col>`.
    #[serde(default)]
    pub replaced_columns: Vec<IdentName>,

    /// Rename mappings from `RENAME (old AS new)`.
    ///
    /// Semantics: renaming does not change which base columns are accessed.
    #[serde(default)]
    pub renames: Vec<StarRenameMapping>,

    /// Whether this star projection includes a `REPLACE (...)` modifier.
    ///
    /// We currently treat this as a signal to disable catalog-backed expansion
    /// (to avoid emitting incorrect per-column refs).
    #[serde(default)]
    pub has_replace: bool,

    /// Whether this star projection includes a `RENAME (...)` modifier.
    ///
    /// We currently treat this as a signal to disable catalog-backed expansion
    /// (to avoid emitting incorrect per-column refs).
    #[serde(default)]
    pub has_rename: bool,

    /// Resolved base table for qualified stars (when qualifier maps to a FROM alias).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolved_table: Option<TableRef>,
}

/// A single output projection item — `<expr> [AS <alias>]` or a
/// `*` star — captured as a typed fact for the diff substrate.
///
/// Mirrors the per-clause fact pattern established by
/// [`PredicateFact`] / [`AggregateFact`] / [`JoinEdge`]: each clause
/// that contributes to a statement's semantic identity has a typed
/// per-scope-set fact list on [`DerivedFacts`](crate::ir::derived_facts::DerivedFacts), and the diff engine
/// compares those lists structurally.
///
/// Every non-`Star` projection item carries the `ColumnId` that
/// lowering allocated for the output slot. Downstream per-output
/// diff events (`ProjectionItemChanged`, plus the existing analyses
/// events `NullabilityChanged` / `LineageChanged` / `TaintChanged`)
/// key on that same `ColumnId` — the substrate exposes one stable
/// per-output-column identity that all output-shaped events agree on.
///
/// `Star` items have no per-column identity at this layer — catalog
/// expansion to concrete `ColumnId`s is not done here, and the
/// star-modifier surface (`EXCLUDE` / `REPLACE` / `RENAME`) already
/// lives on the embedded [`StarProjectionInfo`].
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProjectionItemFact {
    /// Output `ColumnId` allocated by lowering. `None` only
    /// for the `Star` variant of [`ProjectionItemKind`]. Internal-only
    /// identity — never serialised.
    #[serde(default, skip)]
    pub column_id: Option<crate::ir::column::ColumnId>,
    /// User-written alias (`<expr> AS <alias>`). Distinct from the
    /// implicit name derivable from a `Column` projection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alias: Option<IdentKey>,
    /// Typed content of the projection item.
    pub kind: ProjectionItemKind,
    /// Source span of the projection item.
    pub span: crate::lexer::Span,
}

/// Typed taxonomy of projection-item shapes. Closed enum; adding a
/// variant is a design action.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum ProjectionItemKind {
    /// `<expr> [AS <alias>]` — typed scalar expression. Uses
    /// [`ExpressionFact`] so column refs, literals, function calls,
    /// `CASE`, binary/unary ops, etc. all flow through one taxonomy
    /// without per-shape sub-variants here.
    Expr { expression: ExpressionFact },
    /// `* | <qual>.*` with optional Snowflake / BigQuery modifiers.
    /// Wraps the existing [`StarProjectionInfo`] verbatim — the
    /// star-modifier surface is the same one already used by
    /// `star_projections` in [`DerivedFacts`](crate::ir::derived_facts::DerivedFacts).
    Star { star_info: StarProjectionInfo },
}

impl PartialEq for ProjectionItemFact {
    fn eq(&self, other: &Self) -> bool {
        // `column_id` and `span` are excluded: ColumnId is allocator-
        // local (not stable across separate lowerings) and span is a
        // source-position artifact. The diff substrate aligns
        // projection items by position within their owning `Project`
        // node and emits events keyed on the head-side `ColumnId`,
        // so equality only needs to compare the typed content + alias.
        self.alias == other.alias && self.kind == other.kind
    }
}

impl Eq for ProjectionItemFact {}

impl PartialEq for ProjectionItemKind {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Expr { expression: a }, Self::Expr { expression: b }) => a == b,
            (Self::Star { star_info: a }, Self::Star { star_info: b }) => a == b,
            (Self::Expr { .. }, Self::Star { .. }) | (Self::Star { .. }, Self::Expr { .. }) => {
                false
            }
        }
    }
}

impl Eq for ProjectionItemKind {}

/// Column reference (potentially qualified with table/alias)
///
/// Identifiers may include quotes (e.g., `"MyColumn"`) which affects case sensitivity.
/// When comparing columns, resolved_table is used (ignores alias differences).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct ColumnRef {
    /// Table/alias qualifier (e.g., "u" in "u.id", or None for unqualified "id")
    /// May include quotes for case-sensitive identifiers.
    pub qualifier: Option<String>,
    /// Column name (e.g., "id", "ssn", "email", or `"MyColumn"` with quotes)
    /// NOTE: This is the RESOLVED/base column name after lineage tracking.
    /// May include quotes for case-sensitive identifiers.
    /// For the immediate source name as written, see `immediate_source`.
    pub name: String,

    /// Resolved table reference (if qualifier was an alias, this holds the actual table)
    /// None if column is unqualified or couldn't be resolved
    pub resolved_table: Option<TableRef>,
    /// Immediate source reference - the (qualifier, column_name) as written in the SQL,
    /// BEFORE any resolution through CTEs or aliases.
    /// E.g., for `s2.oid` where s2 is alias for step2 CTE, this would be ("s2", "oid").
    /// The `qualifier` and `name` fields may hold the resolved base table values.
    /// This is essential for cross-CTE nullability tracking.
    #[serde(default)]
    pub immediate_source: Option<(String, String)>,
    /// Source type (base table, CTE, derived table, or unknown)
    #[serde(default)]
    pub source_type: ColumnSourceType,
    /// Output alias if this column appears in a SELECT item with AS.
    /// E.g., for `SELECT amount AS total`, this would be "total".
    /// Used for transitive column lineage tracking across dbt models.
    #[serde(default)]
    pub output_alias: Option<String>,

    /// Source span in the rendered SQL (for line number tracking in diff reports).
    /// Not included in equality/hash comparisons - just metadata.
    #[serde(skip)]
    pub span: Option<crate::lexer::Span>,

    /// If true, this column reference came from a nested subquery.
    /// Q-JOIN-LEFT-FILT should skip these because they have their own isolated scope.
    #[serde(default)]
    pub from_subquery: bool,
}

impl PartialEq for ColumnRef {
    fn eq(&self, other: &Self) -> bool {
        // Use normalize_identifier for case-insensitive comparison (respects quoted identifiers)
        let name_eq = normalize_identifier(&self.name) == normalize_identifier(&other.name);

        // Compare by resolved table if both have one (ignores alias differences)
        // This makes a.id == u.id when both resolve to the same table
        let table_eq = match (&self.resolved_table, &other.resolved_table) {
            (Some(a), Some(b)) => a == b,
            (None, None) => {
                // Neither has resolved table - fall back to qualifier comparison
                match (&self.qualifier, &other.qualifier) {
                    (Some(a), Some(b)) => normalize_identifier(a) == normalize_identifier(b),
                    (None, None) => true,
                    _ => false,
                }
            }
            // One resolved, one not - not equal (can't compare)
            _ => false,
        };

        // Note: we intentionally don't compare source_type — it is
        // metadata, not identity

        name_eq && table_eq
    }
}

impl Eq for ColumnRef {}

impl std::hash::Hash for ColumnRef {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        // Use normalize_identifier for consistent hashing (must match PartialEq)
        normalize_identifier(&self.name).hash(state);

        // Hash by resolved table if available, otherwise by qualifier
        match &self.resolved_table {
            Some(table) => {
                1u8.hash(state); // discriminant for "has table"
                table.hash(state);
            }
            None => {
                0u8.hash(state); // discriminant for "no table"
                match &self.qualifier {
                    Some(q) => normalize_identifier(q).hash(state),
                    None => None::<String>.hash(state),
                }
            }
        }
    }
}

impl ColumnRef {
    /// Create a new ColumnRef with the given name.
    /// The name is stored as-is; use `.key()` for normalized lookups.
    pub fn new(name: String) -> Self {
        Self {
            qualifier: None,
            name,
            resolved_table: None,
            immediate_source: None,
            source_type: ColumnSourceType::Unknown,
            output_alias: None,
            span: None,
            from_subquery: false,
        }
    }

    /// Get the normalized key for lookups (handles case sensitivity based on quotes).
    pub fn key(&self) -> String {
        normalize_identifier(&self.name)
    }

    pub fn with_qualifier(mut self, qualifier: String) -> Self {
        self.qualifier = Some(qualifier);
        self
    }

    pub fn with_resolved_table(mut self, table: TableRef) -> Self {
        self.resolved_table = Some(table);
        self
    }

    pub fn with_source_type(mut self, source_type: ColumnSourceType) -> Self {
        self.source_type = source_type;
        self
    }

    pub fn with_span(mut self, span: crate::lexer::Span) -> Self {
        self.span = Some(span);
        self
    }

    /// Get canonical representation (table.column or just column)
    pub fn canonical(&self) -> String {
        if let Some(ref table) = self.resolved_table {
            format!("{}.{}", table.canonical(), self.name)
        } else if let Some(ref qualifier) = self.qualifier {
            format!("{}.{}", qualifier, self.name)
        } else {
            self.name.clone()
        }
    }

    /// Get full 4-part canonical string (database.schema.table.column), skipping empty parts
    pub fn full_canonical(&self) -> String {
        if let Some(ref table) = self.resolved_table {
            match (&table.db, &table.schema) {
                (Some(db), Some(schema)) => {
                    format!("{}.{}.{}.{}", db, schema, table.name, self.name)
                }
                (None, Some(schema)) => format!("{}.{}.{}", schema, table.name, self.name),
                (Some(db), None) => format!("{}.{}.{}", db, table.name, self.name),
                (None, None) => format!("{}.{}", table.name, self.name),
            }
        } else if let Some(ref qualifier) = self.qualifier {
            // Qualifier without resolved table: treat as table name
            format!("{}.{}", qualifier, self.name)
        } else {
            // Unqualified column
            self.name.clone()
        }
    }
}

/// JOIN edge between two tables
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct JoinEdge {
    pub left: TableRef,
    pub right: TableRef,
    pub kind: JoinKind,

    /// Source span in the rendered SQL (for line number tracking in diff reports).
    /// Not included in equality/hash comparisons - just metadata.
    #[serde(skip)]
    pub span: Option<crate::lexer::Span>,

    /// Containing CTE name (for matching joins between BASE and HEAD when file structure shifts).
    /// When multiple CTEs have identical join patterns, this disambiguates which join is which.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub containing_cte: Option<String>,

    /// UNION branch index within the containing CTE (0, 1, 2...).
    /// When a CTE has multiple UNION ALL branches with identical joins, this disambiguates.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub union_branch_index: Option<u32>,

    /// Full ON clause expression tree (preserves AND/OR structure for semantic diff).
    /// None for CROSS JOINs or USING clauses.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub on_clause: Option<ExpressionFact>,
}

impl JoinEdge {
    /// Returns a canonical dedup key for this join edge.
    /// The key is symmetric: (A JOIN B) == (B JOIN A).
    /// Includes CTE context and branch index for semantic location matching.
    pub fn dedup_key(&self) -> (String, String, JoinKind, String, u32) {
        // Sort left/right for symmetric comparison
        let (left_key, right_key) = if self.left.canonical() <= self.right.canonical() {
            (self.left.canonical(), self.right.canonical())
        } else {
            (self.right.canonical(), self.left.canonical())
        };
        let cte_key = self.containing_cte.clone().unwrap_or_default();
        let branch_key = self.union_branch_index.unwrap_or(0);
        (left_key, right_key, self.kind, cte_key, branch_key)
    }
}

impl PartialEq for JoinEdge {
    fn eq(&self, other: &Self) -> bool {
        // Use dedup_key for symmetric equality
        // Span is NOT included - it's just location metadata
        self.dedup_key() == other.dedup_key()
    }
}

impl Eq for JoinEdge {}

impl std::hash::Hash for JoinEdge {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        // Hash the dedup key for consistent hashing with equality
        self.dedup_key().hash(state);
    }
}

/// JOIN types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum JoinKind {
    Inner,
    Left,
    Right,
    Full,
    Cross,
}

/// Function call in an expression (structured fact)
/// Used to track function calls within aggregate arguments, predicates, window specs, etc.
/// This allows analyzers to check for volatile functions without string pattern matching.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FunctionCallFact {
    /// Function name (uppercase, e.g., "NOW", "RANDOM", "DATE_TRUNC")
    pub name: String,
    /// Full expression text for context (e.g., "NOW()" or "DATE_TRUNC('day', ts)")
    pub expression: String,
    /// Span in source
    pub span: crate::lexer::Span,
}

/// Window function details (structured fact)
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct WindowFunctionFact {
    pub function_name: String,
    pub partition_by: Vec<String>,
    pub order_by: Vec<(String, bool)>, // (column, is_desc)
    pub has_frame: bool,
    /// Span of the entire window function expression (for line number tracking)
    #[serde(default)]
    pub span: Option<crate::lexer::Span>,
    /// Frame specification text (e.g., "ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW")
    #[serde(default)]
    pub frame_spec: Option<String>,
    /// Function calls within partition/order expressions.
    /// Populated by walking the window spec AST - allows checking for volatile functions
    /// without string pattern matching.
    #[serde(default)]
    pub partition_function_calls: Vec<FunctionCallFact>,
    #[serde(default)]
    pub order_function_calls: Vec<FunctionCallFact>,
}

/// Semantic comparison for `WindowFunctionFact`.
///
/// `span` is excluded (byte-offset not meaningful across runs).
/// `partition_function_calls` and `order_function_calls` are excluded:
/// nested expression facts are not part of equality.
/// `frame_spec` is excluded because the IR lowerer fills an absent
/// end bound with `CurrentRow` (the SQL default), producing
/// `"ROWS BETWEEN X AND CURRENT ROW"` for a single-bound `"ROWS X"`
/// frame. `has_frame` is the gate for frame presence.
/// `function_name`, `partition_by` entries, and `order_by` string
/// entries are compared case-insensitively (IR projection uses raw
/// span text).
impl PartialEq for WindowFunctionFact {
    fn eq(&self, other: &Self) -> bool {
        if !self
            .function_name
            .eq_ignore_ascii_case(&other.function_name)
        {
            return false;
        }
        if self.has_frame != other.has_frame {
            return false;
        }
        if self.partition_by.len() != other.partition_by.len() {
            return false;
        }
        for (a, b) in self.partition_by.iter().zip(other.partition_by.iter()) {
            if !a.eq_ignore_ascii_case(b) {
                return false;
            }
        }
        if self.order_by.len() != other.order_by.len() {
            return false;
        }
        for ((a_text, a_desc), (b_text, b_desc)) in self.order_by.iter().zip(other.order_by.iter())
        {
            if !a_text.eq_ignore_ascii_case(b_text) || a_desc != b_desc {
                return false;
            }
        }
        true
    }
}

impl Eq for WindowFunctionFact {}

/// Set operation (UNION/INTERSECT/EXCEPT) details (structured fact)
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SetOperationFact {
    pub operation: SetOperation,
    pub branch_count: usize,
}

/// Set operation types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum SetOperation {
    Union,
    UnionAll,
    Intersect,
    Except,
}

impl SetOperation {
    /// Returns a human-readable name for the set operation
    pub fn as_str(&self) -> &'static str {
        match self {
            SetOperation::Union => "UNION",
            SetOperation::UnionAll => "UNION ALL",
            SetOperation::Intersect => "INTERSECT",
            SetOperation::Except => "EXCEPT",
        }
    }
}

impl std::fmt::Display for SetOperation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Structured expression representation for semantic comparison
///
/// Captures the semantic structure of SQL expressions to enable deep comparison
/// and hierarchical diff reporting (e.g., which branch of a CASE changed).
///
/// PartialEq is implemented manually to handle symmetric operators correctly:
/// - `a = b` is considered equal to `b = a`
/// - `a AND b` is considered equal to `b AND a`
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum ExpressionFact {
    /// Simple column reference
    Column(ColumnRef),
    /// Literal value (number, string, boolean, null)
    Literal {
        /// The literal value as text
        value: String,
        /// Type hint: "string", "number", "boolean", "null"
        kind: String,
    },
    /// Function call (including aggregates when nested)
    Function {
        /// Function name (uppercase)
        name: String,
        /// Argument expressions
        args: Vec<ExpressionFact>,
        /// True if DISTINCT modifier used
        is_distinct: bool,
    },
    /// CASE expression
    Case {
        /// WHEN ... THEN branches
        when_branches: Vec<CaseWhenFact>,
        /// ELSE expression (if present)
        else_expr: Option<Box<ExpressionFact>>,
    },
    /// Binary operation (a + b, a = b, etc.)
    BinaryOp {
        /// Left operand
        left: Box<ExpressionFact>,
        /// Operator as text (+, -, *, /, =, !=, <, >, etc.)
        operator: String,
        /// Right operand
        right: Box<ExpressionFact>,
    },
    /// Unary operation (NOT x, -x, etc.)
    UnaryOp {
        /// Operator
        operator: String,
        /// Operand
        operand: Box<ExpressionFact>,
    },
    /// Logical chain (AND/OR with multiple operands)
    LogicalChain {
        /// Operator: "AND" or "OR"
        operator: String,
        /// All operands in chain
        operands: Vec<ExpressionFact>,
    },
    /// IN list expression (expr IN (val1, val2, ...))
    InList {
        /// Expression being tested
        expr: Box<ExpressionFact>,
        /// List of values as typed expressions
        values: Vec<ExpressionFact>,
        /// Whether this is NOT IN
        negated: bool,
    },
    /// Pattern-match predicate
    /// (`expr [NOT] {LIKE|ILIKE|RLIKE|SIMILAR TO} pattern [ESCAPE escape]`).
    Like {
        /// Match kind: "LIKE", "ILIKE", "RLIKE", "SIMILAR TO"
        kind: String,
        /// Whether this is the negated (`NOT …`) form
        negated: bool,
        /// Left operand (the value being matched)
        expr: Box<ExpressionFact>,
        /// Pattern operand
        pattern: Box<ExpressionFact>,
        /// Optional ESCAPE operand
        escape: Option<Box<ExpressionFact>>,
    },
    /// Subquery (scalar or EXISTS/IN)
    Subquery {
        /// Tables referenced within subquery
        tables_referenced: Vec<String>,
        /// Subquery kind: "scalar", "exists", "in"
        kind: String,
    },
    /// Type cast (expr::type or CAST(expr AS type))
    Cast {
        /// Expression being cast
        expr: Box<ExpressionFact>,
        /// Target type
        target_type: String,
    },
    /// Array/object access (`a[0]`, `obj.field`, `json:path`)
    Access {
        /// Base expression
        base: Box<ExpressionFact>,
        /// Access path as text
        accessor: String,
    },
    /// Fallback for expressions we can't fully decompose
    Opaque {
        /// Raw expression text
        text: String,
    },
}

/// Helper to check if an operator is symmetric (a OP b == b OP a)
fn is_symmetric_operator(op: &str) -> bool {
    matches!(
        op,
        "=" | "!=" | "<>" | "AND" | "OR" | "<=>" | "IS NOT DISTINCT FROM"
    )
}

/// Custom PartialEq for ExpressionFact that handles symmetric operators.
/// For symmetric operators like = and AND, `a = b` equals `b = a`.
impl PartialEq for ExpressionFact {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            // Column: delegate to ColumnRef's PartialEq (which uses resolved_table)
            (ExpressionFact::Column(a), ExpressionFact::Column(b)) => a == b,

            // Literal: compare value and kind
            (
                ExpressionFact::Literal {
                    value: v1,
                    kind: k1,
                },
                ExpressionFact::Literal {
                    value: v2,
                    kind: k2,
                },
            ) => v1 == v2 && k1 == k2,

            // Function: compare name, args (order matters), and is_distinct
            (
                ExpressionFact::Function {
                    name: n1,
                    args: a1,
                    is_distinct: d1,
                },
                ExpressionFact::Function {
                    name: n2,
                    args: a2,
                    is_distinct: d2,
                },
            ) => n1 == n2 && d1 == d2 && a1 == a2,

            // Case: compare branches and else in order
            (
                ExpressionFact::Case {
                    when_branches: w1,
                    else_expr: e1,
                },
                ExpressionFact::Case {
                    when_branches: w2,
                    else_expr: e2,
                },
            ) => w1 == w2 && e1 == e2,

            // BinaryOp: handle symmetric operators
            (
                ExpressionFact::BinaryOp {
                    left: l1,
                    operator: op1,
                    right: r1,
                },
                ExpressionFact::BinaryOp {
                    left: l2,
                    operator: op2,
                    right: r2,
                },
            ) => {
                if op1 != op2 {
                    return false;
                }
                if is_symmetric_operator(op1) {
                    // For symmetric operators, check both orderings
                    (l1 == l2 && r1 == r2) || (l1 == r2 && r1 == l2)
                } else {
                    l1 == l2 && r1 == r2
                }
            }

            // UnaryOp: compare operator and operand
            (
                ExpressionFact::UnaryOp {
                    operator: op1,
                    operand: o1,
                },
                ExpressionFact::UnaryOp {
                    operator: op2,
                    operand: o2,
                },
            ) => op1 == op2 && o1 == o2,

            // LogicalChain: compare as sets (order-independent for AND/OR)
            (
                ExpressionFact::LogicalChain {
                    operator: op1,
                    operands: ops1,
                },
                ExpressionFact::LogicalChain {
                    operator: op2,
                    operands: ops2,
                },
            ) => {
                if op1 != op2 || ops1.len() != ops2.len() {
                    return false;
                }
                // Check if each operand in ops1 has a match in ops2
                let mut matched = vec![false; ops2.len()];
                for op_a in ops1 {
                    let found = ops2
                        .iter()
                        .enumerate()
                        .any(|(i, op_b)| !matched[i] && op_a == op_b);
                    if !found {
                        return false;
                    }
                    // Mark as matched (find first unmatched)
                    if let Some(i) = ops2
                        .iter()
                        .enumerate()
                        .position(|(i, op_b)| !matched[i] && op_a == op_b)
                    {
                        matched[i] = true;
                    }
                }
                true
            }

            // InList: compare expr, values (as set), and negation
            (
                ExpressionFact::InList {
                    expr: e1,
                    values: v1,
                    negated: n1,
                },
                ExpressionFact::InList {
                    expr: e2,
                    values: v2,
                    negated: n2,
                },
            ) => {
                if e1 != e2 || n1 != n2 || v1.len() != v2.len() {
                    return false;
                }
                // Compare values as sets (order-independent)
                let mut matched = vec![false; v2.len()];
                for val_a in v1 {
                    if let Some(i) = v2
                        .iter()
                        .enumerate()
                        .position(|(i, val_b)| !matched[i] && val_a == val_b)
                    {
                        matched[i] = true;
                    } else {
                        return false;
                    }
                }
                true
            }

            // Subquery: compare tables (as set) and kind
            (
                ExpressionFact::Subquery {
                    tables_referenced: t1,
                    kind: k1,
                },
                ExpressionFact::Subquery {
                    tables_referenced: t2,
                    kind: k2,
                },
            ) => {
                if k1 != k2 || t1.len() != t2.len() {
                    return false;
                }
                let set1: std::collections::HashSet<_> = t1.iter().collect();
                let set2: std::collections::HashSet<_> = t2.iter().collect();
                set1 == set2
            }

            // Cast: compare expr and target_type
            (
                ExpressionFact::Cast {
                    expr: e1,
                    target_type: t1,
                },
                ExpressionFact::Cast {
                    expr: e2,
                    target_type: t2,
                },
            ) => e1 == e2 && t1 == t2,

            // Access: compare base and accessor
            (
                ExpressionFact::Access {
                    base: b1,
                    accessor: a1,
                },
                ExpressionFact::Access {
                    base: b2,
                    accessor: a2,
                },
            ) => b1 == b2 && a1 == a2,

            // Like: field-wise (pattern match is not symmetric)
            (
                ExpressionFact::Like {
                    kind: k1,
                    negated: n1,
                    expr: e1,
                    pattern: p1,
                    escape: esc1,
                },
                ExpressionFact::Like {
                    kind: k2,
                    negated: n2,
                    expr: e2,
                    pattern: p2,
                    escape: esc2,
                },
            ) => k1 == k2 && n1 == n2 && e1 == e2 && p1 == p2 && esc1 == esc2,

            // Opaque: compare text
            (ExpressionFact::Opaque { text: t1 }, ExpressionFact::Opaque { text: t2 }) => t1 == t2,

            // Different variants: not equal
            _ => false,
        }
    }
}

impl Eq for ExpressionFact {}

/// Hash implementation consistent with the custom PartialEq.
///
/// Key invariants:
/// - Symmetric BinaryOp: `a = b` and `b = a` must hash identically
///   → use XOR of child hashes for symmetric operators
/// - LogicalChain: operand order is irrelevant
///   → use XOR of operand hashes (commutative)
/// - InList: values compared as set
///   → use XOR of value hashes
/// - Subquery: tables compared as set
///   → use XOR of table hashes
impl std::hash::Hash for ExpressionFact {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        // Hash the discriminant first to distinguish variants
        std::mem::discriminant(self).hash(state);

        match self {
            ExpressionFact::Column(col) => {
                col.hash(state);
            }
            ExpressionFact::Literal { value, kind } => {
                value.hash(state);
                kind.hash(state);
            }
            ExpressionFact::Function {
                name,
                args,
                is_distinct,
            } => {
                name.hash(state);
                is_distinct.hash(state);
                // Args are order-sensitive in PartialEq, so hash in order
                args.hash(state);
            }
            ExpressionFact::Case {
                when_branches,
                else_expr,
            } => {
                // Branches are order-sensitive in PartialEq
                when_branches.hash(state);
                else_expr.hash(state);
            }
            ExpressionFact::BinaryOp {
                left,
                operator,
                right,
            } => {
                operator.hash(state);
                if is_symmetric_operator(operator) {
                    // Order-independent: XOR the two child hashes
                    let mut left_hasher = std::collections::hash_map::DefaultHasher::new();
                    left.hash(&mut left_hasher);
                    let left_h = std::hash::Hasher::finish(&left_hasher);

                    let mut right_hasher = std::collections::hash_map::DefaultHasher::new();
                    right.hash(&mut right_hasher);
                    let right_h = std::hash::Hasher::finish(&right_hasher);

                    // XOR is commutative: h(a) ^ h(b) == h(b) ^ h(a)
                    (left_h ^ right_h).hash(state);
                } else {
                    // Order matters
                    left.hash(state);
                    right.hash(state);
                }
            }
            ExpressionFact::UnaryOp { operator, operand } => {
                operator.hash(state);
                operand.hash(state);
            }
            ExpressionFact::LogicalChain { operator, operands } => {
                operator.hash(state);
                operands.len().hash(state);
                // Order-independent: XOR all operand hashes
                let mut combined: u64 = 0;
                for op in operands {
                    let mut h = std::collections::hash_map::DefaultHasher::new();
                    op.hash(&mut h);
                    combined ^= std::hash::Hasher::finish(&h);
                }
                combined.hash(state);
            }
            ExpressionFact::InList {
                expr,
                values,
                negated,
            } => {
                expr.hash(state);
                negated.hash(state);
                values.len().hash(state);
                // Order-independent: XOR all ExpressionFact hashes
                let mut combined: u64 = 0;
                for v in values {
                    let mut h = std::collections::hash_map::DefaultHasher::new();
                    v.hash(&mut h);
                    combined ^= std::hash::Hasher::finish(&h);
                }
                combined.hash(state);
            }
            ExpressionFact::Like {
                kind,
                negated,
                expr,
                pattern,
                escape,
            } => {
                kind.hash(state);
                negated.hash(state);
                expr.hash(state);
                pattern.hash(state);
                escape.hash(state);
            }
            ExpressionFact::Subquery {
                tables_referenced,
                kind,
            } => {
                kind.hash(state);
                tables_referenced.len().hash(state);
                // Order-independent: XOR all table hashes
                let mut combined: u64 = 0;
                for t in tables_referenced {
                    let mut h = std::collections::hash_map::DefaultHasher::new();
                    t.hash(&mut h);
                    combined ^= std::hash::Hasher::finish(&h);
                }
                combined.hash(state);
            }
            ExpressionFact::Cast { expr, target_type } => {
                expr.hash(state);
                target_type.hash(state);
            }
            ExpressionFact::Access { base, accessor } => {
                base.hash(state);
                accessor.hash(state);
            }
            ExpressionFact::Opaque { text } => {
                text.hash(state);
            }
        }
    }
}

/// A single WHEN ... THEN branch in a CASE expression
#[derive(Debug, Clone, PartialEq, Hash, serde::Serialize, serde::Deserialize)]
pub struct CaseWhenFact {
    /// The WHEN condition
    pub condition: Box<ExpressionFact>,
    /// The THEN result
    pub result: Box<ExpressionFact>,
}

impl ExpressionFact {
    /// Returns a concise text representation for display
    pub fn display_text(&self) -> String {
        match self {
            ExpressionFact::Column(col) => col.canonical(),
            ExpressionFact::Literal { value, .. } => value.clone(),
            ExpressionFact::Function {
                name,
                args,
                is_distinct,
            } => {
                let args_text = args
                    .iter()
                    .map(|a| a.display_text())
                    .collect::<Vec<_>>()
                    .join(", ");
                if *is_distinct {
                    format!("{}(DISTINCT {})", name, args_text)
                } else {
                    format!("{}({})", name, args_text)
                }
            }
            ExpressionFact::Case {
                when_branches,
                else_expr,
            } => {
                let branches = when_branches.len();
                let else_part = if else_expr.is_some() { " + ELSE" } else { "" };
                format!("CASE[{} branches{}]", branches, else_part)
            }
            ExpressionFact::BinaryOp {
                left,
                operator,
                right,
            } => {
                format!(
                    "{} {} {}",
                    left.display_text(),
                    operator,
                    right.display_text()
                )
            }
            ExpressionFact::UnaryOp { operator, operand } => {
                format!("{} {}", operator, operand.display_text())
            }
            ExpressionFact::LogicalChain { operator, operands } => {
                format!("({} {} terms)", operator, operands.len())
            }
            ExpressionFact::InList {
                expr,
                values,
                negated,
            } => {
                let not_str = if *negated { "NOT " } else { "" };
                if values.len() <= 3 {
                    let val_strs: Vec<String> = values.iter().map(|v| v.display_text()).collect();
                    format!(
                        "{} {}IN ({})",
                        expr.display_text(),
                        not_str,
                        val_strs.join(", ")
                    )
                } else {
                    format!(
                        "{} {}IN ({} values)",
                        expr.display_text(),
                        not_str,
                        values.len()
                    )
                }
            }
            ExpressionFact::Like {
                kind,
                negated,
                expr,
                pattern,
                escape,
            } => {
                let not_str = if *negated { "NOT " } else { "" };
                let base = format!(
                    "{} {}{} {}",
                    expr.display_text(),
                    not_str,
                    kind,
                    pattern.display_text()
                );
                match escape {
                    Some(e) => format!("{} ESCAPE {}", base, e.display_text()),
                    None => base,
                }
            }
            ExpressionFact::Subquery { kind, .. } => {
                format!("({})", kind.to_uppercase())
            }
            ExpressionFact::Cast { expr, target_type } => {
                format!("{}::{}", expr.display_text(), target_type)
            }
            ExpressionFact::Access { base, accessor } => {
                format!("{}.{}", base.display_text(), accessor)
            }
            ExpressionFact::Opaque { text } => {
                if text.len() > 30 {
                    format!("{}...", &text[..27])
                } else {
                    text.clone()
                }
            }
        }
    }

    /// Extract all column references from this expression tree
    pub fn column_refs(&self) -> Vec<&ColumnRef> {
        let mut refs = Vec::new();
        self.collect_column_refs(&mut refs);
        refs
    }

    fn collect_column_refs<'a>(&'a self, refs: &mut Vec<&'a ColumnRef>) {
        match self {
            ExpressionFact::Column(col) => refs.push(col),
            ExpressionFact::Function { args, .. } => {
                for arg in args {
                    arg.collect_column_refs(refs);
                }
            }
            ExpressionFact::Case {
                when_branches,
                else_expr,
            } => {
                for branch in when_branches {
                    branch.condition.collect_column_refs(refs);
                    branch.result.collect_column_refs(refs);
                }
                if let Some(else_e) = else_expr {
                    else_e.collect_column_refs(refs);
                }
            }
            ExpressionFact::BinaryOp { left, right, .. } => {
                left.collect_column_refs(refs);
                right.collect_column_refs(refs);
            }
            ExpressionFact::UnaryOp { operand, .. } => {
                operand.collect_column_refs(refs);
            }
            ExpressionFact::LogicalChain { operands, .. } => {
                for op in operands {
                    op.collect_column_refs(refs);
                }
            }
            ExpressionFact::InList { expr, values, .. } => {
                expr.collect_column_refs(refs);
                for v in values {
                    v.collect_column_refs(refs);
                }
            }
            ExpressionFact::Like {
                expr,
                pattern,
                escape,
                ..
            } => {
                expr.collect_column_refs(refs);
                pattern.collect_column_refs(refs);
                if let Some(e) = escape {
                    e.collect_column_refs(refs);
                }
            }
            ExpressionFact::Cast { expr, .. } => {
                expr.collect_column_refs(refs);
            }
            ExpressionFact::Access { base, .. } => {
                base.collect_column_refs(refs);
            }
            ExpressionFact::Literal { .. }
            | ExpressionFact::Subquery { .. }
            | ExpressionFact::Opaque { .. } => {}
        }
    }
}

/// Aggregation function details (structured fact)
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AggregateFact {
    /// Function name (COUNT, SUM, AVG, MAX, MIN, etc.)
    pub function_name: String,
    /// Argument column reference (if identifiable)
    pub argument_column: Option<ColumnRef>,
    /// Argument expression text (if complex or multiple args)
    pub argument_expr: Option<String>,
    /// Structured argument expression for deep comparison
    /// Populated for complex expressions (CASE, nested functions, etc.)
    #[serde(default)]
    pub argument_fact: Option<ExpressionFact>,
    /// Output alias (if specified: COUNT(*) AS total_count)
    pub output_alias: Option<String>,
    /// True if DISTINCT is used (COUNT(DISTINCT user_id))
    pub is_distinct: bool,
    /// Function calls within the argument expression.
    /// Populated by walking the argument AST - allows checking for volatile functions
    /// without string pattern matching.
    #[serde(default)]
    pub argument_function_calls: Vec<FunctionCallFact>,
    /// Span in source
    pub span: crate::lexer::Span,
}

/// GROUP BY clause details (structured fact)
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GroupByFact {
    /// Columns being grouped by
    pub grouping_columns: Vec<ColumnRef>,
    /// Grouping expressions (for non-simple column refs)
    pub grouping_expressions: Vec<String>,
    /// True if GROUP BY ALL is used
    pub is_group_by_all: bool,
    /// True if ROLLUP is used
    pub has_rollup: bool,
    /// True if CUBE is used
    pub has_cube: bool,
    /// True if GROUPING SETS is used
    pub has_grouping_sets: bool,
}

/// HAVING clause details (structured fact)
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HavingFact {
    /// Column references in HAVING (aggregated columns)
    pub columns: Vec<ColumnRef>,
    /// Aggregate functions referenced in HAVING
    pub aggregate_functions: Vec<String>,
    /// Full HAVING expression text
    pub expression: String,
    /// Structured expression fact for deep comparison
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expression_fact: Option<ExpressionFact>,
    /// Span in source
    pub span: crate::lexer::Span,
}

/// Semantic comparison for `AggregateFact`.
///
/// `span` is excluded (byte-offset not meaningful across runs).
/// `argument_fact` and `argument_function_calls` are excluded from
/// this comparison: nested expression facts are not part of equality.
/// `function_name` is compared case-insensitively (the IR normalizes
/// to uppercase, but this is defensive).
impl PartialEq for AggregateFact {
    fn eq(&self, other: &Self) -> bool {
        self.function_name
            .eq_ignore_ascii_case(&other.function_name)
            && self.is_distinct == other.is_distinct
            && self.argument_column == other.argument_column
            && self.argument_expr == other.argument_expr
            && self.output_alias == other.output_alias
    }
}

impl Eq for AggregateFact {}

/// Semantic comparison for `GroupByFact`.
///
/// `grouping_columns` and `grouping_expressions` are compared as
/// sorted sets (order-insensitive). Bool flags are compared directly.
impl PartialEq for GroupByFact {
    fn eq(&self, other: &Self) -> bool {
        if self.is_group_by_all != other.is_group_by_all
            || self.has_rollup != other.has_rollup
            || self.has_cube != other.has_cube
            || self.has_grouping_sets != other.has_grouping_sets
        {
            return false;
        }
        // Sort-then-compare for grouping_columns (ColumnRef uses
        // canonical() for ordering).
        let mut a_cols: Vec<String> = self
            .grouping_columns
            .iter()
            .map(|c| c.canonical())
            .collect();
        let mut b_cols: Vec<String> = other
            .grouping_columns
            .iter()
            .map(|c| c.canonical())
            .collect();
        a_cols.sort();
        b_cols.sort();
        if a_cols != b_cols {
            return false;
        }
        let mut a_exprs = self.grouping_expressions.clone();
        let mut b_exprs = other.grouping_expressions.clone();
        a_exprs.sort();
        b_exprs.sort();
        a_exprs == b_exprs
    }
}

impl Eq for GroupByFact {}

/// Semantic comparison for `HavingFact`.
///
/// `expression` (raw source text) and `aggregate_functions` (sorted
/// set) are compared. `columns` is excluded: the IR HAVING expression
/// references aggregate outputs by `ColumnId`, not the raw column
/// refs inside aggregate call arguments.
/// `expression_fact` and `span` are also excluded.
impl PartialEq for HavingFact {
    fn eq(&self, other: &Self) -> bool {
        if self.expression != other.expression {
            return false;
        }
        let mut a_fns = self.aggregate_functions.clone();
        let mut b_fns = other.aggregate_functions.clone();
        a_fns.sort();
        b_fns.sort();
        a_fns == b_fns
    }
}

impl Eq for HavingFact {}

/// Closed-enum classification of the predicate operator carried on a
/// [`PredicateFact`]. Every emitter constructs a variant directly;
/// every consumer pattern-matches exhaustively so new operator shapes
/// force compile-time decisions rather than silently hitting a
/// string-fallthrough.
///
/// Wire shape (serde) is preserved by
/// [`std::fmt::Display`] + [`std::str::FromStr`] producing/parsing the
/// canonical SQL spellings. Serialization round-trips through
/// `#[serde(into = "String", try_from = "String")]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PredicateOp {
    /// Binary comparison head: `=`, `<>`, `<`, `<=`, `>`, `>=`.
    /// Mirrors [`crate::ir::scalar::ComparisonOp`].
    Compare(crate::ir::scalar::ComparisonOp),
    /// `IS NULL` postfix.
    IsNull,
    /// `IS NOT NULL` postfix.
    IsNotNull,
    /// `IN (list)` — the actual values live in `in_list_values` when
    /// every list element is a literal, otherwise the list is opaque.
    In,
    /// `NOT IN (list)`.
    NotIn,
    /// `BETWEEN low AND high` carried as an opaque atom. Positive
    /// BETWEEN with literal bounds is decomposed into two
    /// [`PredicateOp::Compare`] atoms (`Ge low` + `Le high`) at
    /// emission time so within-scope analyses can compose the bounds
    /// with sibling atoms.
    Between,
    /// `NOT BETWEEN low AND high` — opaque (the OR-disjunctive
    /// decomposition `<low OR >high` is not yet emitted).
    NotBetween,
    /// Quantified comparison: `<op> ANY (subquery)` / `<op> ALL (subquery)`.
    /// The `(Eq, Any)` and `(NotEq, All)` shapes normalize to
    /// [`PredicateOp::In`] / [`PredicateOp::NotIn`] at the emitter so
    /// this variant never carries those combinations.
    Quantified {
        op: crate::ir::scalar::ComparisonOp,
        quantifier: PredicateQuantifier,
    },
}

/// Quantifier head for [`PredicateOp::Quantified`]. `ANY` and `SOME`
/// are surface aliases; this enum collapses both to [`Self::Any`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PredicateQuantifier {
    Any,
    All,
}

impl PredicateQuantifier {
    pub fn as_sql_str(self) -> &'static str {
        match self {
            Self::Any => "ANY",
            Self::All => "ALL",
        }
    }
}

impl std::fmt::Display for PredicateOp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Compare(op) => f.write_str(op.as_sql_str()),
            Self::IsNull => f.write_str("IS NULL"),
            Self::IsNotNull => f.write_str("IS NOT NULL"),
            Self::In => f.write_str("IN"),
            Self::NotIn => f.write_str("NOT IN"),
            Self::Between => f.write_str("BETWEEN"),
            Self::NotBetween => f.write_str("NOT BETWEEN"),
            Self::Quantified { op, quantifier } => {
                write!(f, "{} {}", op.as_sql_str(), quantifier.as_sql_str())
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct PredicateOpParseError(pub String);

impl std::fmt::Display for PredicateOpParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "unrecognized predicate operator: {:?}", self.0)
    }
}

impl std::error::Error for PredicateOpParseError {}

impl std::str::FromStr for PredicateOp {
    type Err = PredicateOpParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        use crate::ir::scalar::ComparisonOp;
        match s {
            "=" => Ok(Self::Compare(ComparisonOp::Eq)),
            "<>" | "!=" => Ok(Self::Compare(ComparisonOp::NotEq)),
            "<" => Ok(Self::Compare(ComparisonOp::Lt)),
            "<=" => Ok(Self::Compare(ComparisonOp::LtEq)),
            ">" => Ok(Self::Compare(ComparisonOp::Gt)),
            ">=" => Ok(Self::Compare(ComparisonOp::GtEq)),
            "IS NULL" => Ok(Self::IsNull),
            "IS NOT NULL" => Ok(Self::IsNotNull),
            "IN" => Ok(Self::In),
            "NOT IN" => Ok(Self::NotIn),
            "BETWEEN" => Ok(Self::Between),
            "NOT BETWEEN" => Ok(Self::NotBetween),
            other => {
                parse_quantified(other).ok_or_else(|| PredicateOpParseError(other.to_string()))
            }
        }
    }
}

fn parse_quantified(s: &str) -> Option<PredicateOp> {
    use crate::ir::scalar::ComparisonOp;
    let (head, tail) = s.rsplit_once(' ')?;
    let quantifier = match tail {
        "ANY" | "SOME" => PredicateQuantifier::Any,
        "ALL" => PredicateQuantifier::All,
        _ => return None,
    };
    let op = match head {
        "=" => ComparisonOp::Eq,
        "<>" | "!=" => ComparisonOp::NotEq,
        "<" => ComparisonOp::Lt,
        "<=" => ComparisonOp::LtEq,
        ">" => ComparisonOp::Gt,
        ">=" => ComparisonOp::GtEq,
        _ => return None,
    };
    Some(PredicateOp::Quantified { op, quantifier })
}

impl serde::Serialize for PredicateOp {
    fn serialize<S: serde::Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        ser.collect_str(self)
    }
}

impl<'de> serde::Deserialize<'de> for PredicateOp {
    fn deserialize<D: serde::Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        let s = String::deserialize(de)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// Inclusive literal bounds of a `[NOT] BETWEEN low AND high` atom.
/// `BETWEEN` is inclusive on both ends, so `low`/`high` describe the
/// closed interval `[low, high]`. Carried so the tautology detector can
/// recognise the `BETWEEN x AND y OR NOT BETWEEN x AND y` complement
/// (every non-NULL value is either inside the interval or outside it).
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct BetweenBounds {
    /// Lower bound literal (raw value text).
    pub low: String,
    /// Upper bound literal (raw value text).
    pub high: String,
}

/// WHERE/HAVING predicate details (structured fact)
///
/// `PartialEq` is a semantic comparison.  It
/// includes all fields that the IR extraction populates.  `rhs_text` and
/// `function_calls.expression` are now fully populated because `source: &str`
/// is threaded through the extraction chain.  All fields are compared.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PredicateFact {
    /// Column being filtered
    pub column: ColumnRef,
    /// Closed-enum classification of the comparison operator — see
    /// [`PredicateOp`] for the variant set.
    pub operator: PredicateOp,
    /// Literal value (if simple comparison)
    pub literal_value: Option<String>,
    /// Raw source text of the right-hand side expression (for display when not a literal)
    #[serde(default)]
    pub rhs_text: Option<String>,
    /// True if uses temporal/date functions (CURRENT_DATE, DATE_TRUNC, etc.)
    pub has_temporal: bool,
    /// True if uses subquery (IN (SELECT ...), EXISTS (...))
    pub has_subquery: bool,
    /// For IN/NOT IN with subquery: the column selected by the subquery
    /// e.g., for `id NOT IN (SELECT parent_id FROM parents)`, this is parent_id with its table ref
    /// Used by Q-NULL-NOTIN to check if subquery column is nullable
    #[serde(default)]
    pub subquery_column: Option<ColumnRef>,
    /// For IN/NOT IN with subquery: the table referenced in the subquery
    /// Used by Q-NULL-NOTIN to look up column nullability in catalog
    #[serde(default)]
    pub subquery_table: Option<TableRef>,
    /// Function calls within the predicate expression.
    /// Populated by walking the predicate AST - allows checking for volatile functions
    /// without string pattern matching.
    #[serde(default)]
    pub function_calls: Vec<FunctionCallFact>,
    /// Predicate type (where vs having)
    pub context: PredicateContext,
    /// Logical operator connecting this predicate to siblings (AND/OR/None)
    pub logical_operator: Option<LogicalOperator>,
    /// OR branch identifier - predicates in different OR branches have different IDs.
    /// Predicates with the same or_branch_id are connected by AND and can be checked for contradictions.
    /// Predicates with different or_branch_ids are in separate OR branches and cannot contradict.
    pub or_branch_id: u32,
    /// NOT-subtree isolation depth. Zero for atoms emitted outside any
    /// NOT context; non-zero unique per NOT subtree so the constraint-
    /// detection algebra can treat each NOT as opaque (e.g. `NOT NOT X
    /// AND Y` does not collapse the inner `X` into the outer
    /// constraint set, by deliberate conservatism — see
    /// `tests/test_pred_contra_not.rs::no_false_positive_double_not`).
    /// Kept separate from `or_branch_id` so the diff layer's
    /// `PredicateFact` multiset equality — which keys on
    /// `or_branch_id` to discriminate OR-branches — is not confused
    /// by NOT-bumping. Excluded from `PartialEq` for the same reason.
    #[serde(default)]
    pub not_isolation_id: u32,
    /// Scope identifier - predicates in different CTEs/subqueries have different scope IDs.
    /// Q-PRED-CONTRA should only check for contradictions within the same scope.
    /// Scope 0 = top-level, increments for each CTE/subquery.
    pub scope_id: u32,
    /// JOIN ON sub-scope id. Zero for predicates from WHERE / HAVING
    /// (their natural conjunctive scope is the enclosing query's
    /// `scope_id`); non-zero unique per JOIN node so within-scope
    /// contradiction analysis treats sibling JOIN ON clauses as
    /// independent gates. Two LEFT JOINs that constrain the same
    /// LHS column to different values are not in conjunction at the
    /// row level — each gates its own match — so their atoms must
    /// not merge into one constraint bucket. Atoms WITHIN a single
    /// JOIN's ON still share the same id and continue to compose,
    /// so `ON a=1 AND a=2` is still detected.
    #[serde(default)]
    pub join_scope_id: u32,
    /// Literal values from an IN (...) list, if all list items are literals.
    /// E.g., for `status IN ('A', 'B')`, this is `Some(vec!["'A'", "'B'"])`.
    /// None if any list item is not a simple literal.
    #[serde(default)]
    pub in_list_values: Option<Vec<String>>,
    /// Inclusive literal bounds of a `[NOT] BETWEEN low AND high` atom,
    /// populated when both bounds are literals. `None` for non-BETWEEN
    /// atoms or BETWEEN with non-literal bounds. See [`BetweenBounds`].
    #[serde(default)]
    pub between_bounds: Option<BetweenBounds>,
    /// Whether this predicate is inside a NOT context.
    /// `NOT(status = 'X')` records the inner `status = 'X'` with `is_negated = true`.
    /// Used by cross-CTE contradiction detection: a negated predicate that matches
    /// the CTE's constraint value IS a contradiction (excludes all CTE output),
    /// while a negated predicate with a DIFFERENT value is harmless (redundant exclusion).
    #[serde(default)]
    pub is_negated: bool,
    /// Whether this comparison is reflexive: the same column compared
    /// to itself (`x = x`). Set only at IR extraction, where both
    /// operand `ColumnId`s are visible (the RHS identity is not
    /// otherwise preserved on the fact). `x = x` is a tautology for
    /// non-NULL values — and never every-row unless the column is
    /// proven non-null — recognised by `detect_tautologies_in_scope`.
    #[serde(default)]
    pub is_reflexive: bool,
    /// Span in source
    pub span: crate::lexer::Span,

    /// Typed identity of the LHS column (when the predicate was extracted
    /// from the IR fold). `None` otherwise. IR-first analyses
    /// should branch on this presence to use typed bindings + scan-index
    /// resolution rather than string-normalising `column.qualifier`.
    /// Internal-only identity — never serialised to JSON / YAML.
    #[serde(default, skip)]
    pub column_id: Option<crate::ir::column::ColumnId>,
}

impl PartialEq for PredicateFact {
    fn eq(&self, other: &Self) -> bool {
        self.column == other.column
            && self.operator == other.operator
            && self.literal_value == other.literal_value
            && self.has_temporal == other.has_temporal
            && self.has_subquery == other.has_subquery
            && self.subquery_column == other.subquery_column
            && self.subquery_table == other.subquery_table
            && self.in_list_values == other.in_list_values
            && self.between_bounds == other.between_bounds
            && self.is_negated == other.is_negated
            && self.context == other.context
            && self.logical_operator == other.logical_operator
            && self.or_branch_id == other.or_branch_id
            && self.scope_id == other.scope_id
            && self.join_scope_id == other.join_scope_id
            && self.rhs_text == other.rhs_text
            && self.function_calls == other.function_calls
    }
}

impl PredicateFact {
    /// Return a copy of this fact in **negation-canonical form**:
    /// when `is_negated == true`, fold the negation into the
    /// operator by inverting it (`Eq` → `NotEq`, `Lt` → `GtEq`,
    /// `IsNull` → `IsNotNull`, `In` → `NotIn`, etc.) and clear the
    /// `is_negated` flag. Quantified operators do not have a typed
    /// inverse vocabulary and pass through unchanged.
    ///
    /// Used by the IR diff engine's WHERE-predicate set-equality
    /// check to recognize `NOT (a cmp b)` and `a inv-cmp b` as
    /// semantically identical so a pure stylistic rewrite does not
    /// fire `DIFF-WHERE-COND-CHG`.
    pub fn negation_canonical(&self) -> Self {
        use crate::ir::scalar::ComparisonOp;
        if !self.is_negated {
            return self.clone();
        }
        let inverted = match self.operator {
            PredicateOp::Compare(ComparisonOp::Eq) => {
                Some(PredicateOp::Compare(ComparisonOp::NotEq))
            }
            PredicateOp::Compare(ComparisonOp::NotEq) => {
                Some(PredicateOp::Compare(ComparisonOp::Eq))
            }
            PredicateOp::Compare(ComparisonOp::Lt) => {
                Some(PredicateOp::Compare(ComparisonOp::GtEq))
            }
            PredicateOp::Compare(ComparisonOp::LtEq) => {
                Some(PredicateOp::Compare(ComparisonOp::Gt))
            }
            PredicateOp::Compare(ComparisonOp::Gt) => {
                Some(PredicateOp::Compare(ComparisonOp::LtEq))
            }
            PredicateOp::Compare(ComparisonOp::GtEq) => {
                Some(PredicateOp::Compare(ComparisonOp::Lt))
            }
            PredicateOp::IsNull => Some(PredicateOp::IsNotNull),
            PredicateOp::IsNotNull => Some(PredicateOp::IsNull),
            PredicateOp::In => Some(PredicateOp::NotIn),
            PredicateOp::NotIn => Some(PredicateOp::In),
            PredicateOp::Between => Some(PredicateOp::NotBetween),
            PredicateOp::NotBetween => Some(PredicateOp::Between),
            PredicateOp::Quantified { .. } => None,
        };
        let mut out = self.clone();
        if let Some(op) = inverted {
            out.operator = op;
            out.is_negated = false;
        }
        out
    }
}

impl Eq for PredicateFact {}

/// Logical operator connecting predicates
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum LogicalOperator {
    And,
    Or,
}

/// Predicate context
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum PredicateContext {
    Where,
    Having,
    JoinCondition,
    CaseWhen,
}

// ============================================================================
// Scope-Aware Predicate Types (for nested subquery tracking)
// ============================================================================

/// Describes the kind of scope a predicate exists in
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ScopeKind {
    /// Main query (top-level)
    MainQuery,
    /// Common Table Expression body
    Cte { cte_name: String },
    /// EXISTS subquery
    ExistsSubquery,
    /// NOT EXISTS subquery
    NotExistsSubquery,
    /// IN (SELECT ...) subquery
    InSubquery { target_table: Option<String> },
    /// NOT IN (SELECT ...) subquery
    NotInSubquery { target_table: Option<String> },
    /// Scalar subquery (= (SELECT ...), etc.)
    ScalarSubquery,
    /// Derived table (FROM (SELECT ...) AS alias)
    DerivedTable { alias: Option<String> },
}

impl ScopeKind {
    /// Get a short display name for this scope kind
    pub fn display_name(&self) -> String {
        match self {
            ScopeKind::MainQuery => "main".to_string(),
            ScopeKind::Cte { cte_name } => format!("CTE:{}", cte_name),
            ScopeKind::ExistsSubquery => "EXISTS".to_string(),
            ScopeKind::NotExistsSubquery => "NOT EXISTS".to_string(),
            ScopeKind::InSubquery { target_table } => {
                if let Some(t) = target_table {
                    format!("IN:{}", t)
                } else {
                    "IN".to_string()
                }
            }
            ScopeKind::NotInSubquery { target_table } => {
                if let Some(t) = target_table {
                    format!("NOT IN:{}", t)
                } else {
                    "NOT IN".to_string()
                }
            }
            ScopeKind::ScalarSubquery => "scalar".to_string(),
            ScopeKind::DerivedTable { alias } => {
                if let Some(a) = alias {
                    format!("derived:{}", a)
                } else {
                    "derived".to_string()
                }
            }
        }
    }
}

/// Describes a scope in the query hierarchy
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ScopeDescriptor {
    /// Type of scope
    pub kind: ScopeKind,
    /// Primary table involved in this scope (for context)
    pub primary_table: Option<String>,
    /// Nesting depth (0 = main query)
    pub depth: u32,
}

impl ScopeDescriptor {
    pub fn new(kind: ScopeKind, depth: u32) -> Self {
        Self {
            kind,
            primary_table: None,
            depth,
        }
    }

    /// Get canonical string for comparison (case-insensitive)
    pub fn canonical(&self) -> String {
        let base = self.kind.display_name().to_lowercase();
        if let Some(ref t) = self.primary_table {
            format!("{}@{}", base, t.to_lowercase())
        } else {
            base
        }
    }
}

/// A predicate with full scope information for nested subquery tracking
///
/// `PartialEq` delegates to `PredicateFact::PartialEq` for the inner predicate
/// and compares the canonical scope path string for scope identity. `span`,
/// `outer_column_refs`, and `is_correlated` are excluded because those fields
/// are not reliably reconstructed from the IR walk path.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ScopedPredicateFact {
    /// The predicate itself
    pub predicate: PredicateFact,

    /// Scope path from root to this predicate
    /// e.g., [MainQuery, EXISTS:users, IN:orders]
    pub scope_path: Vec<ScopeDescriptor>,

    /// Unique scope ID for this predicate's immediate scope
    pub scope_id: u32,

    /// Parent scope ID (0 = no parent / top level)
    pub parent_scope_id: u32,

    /// True if this predicate references columns from an outer scope (correlated)
    pub is_correlated: bool,

    /// Columns referenced from outer scopes (for correlated subqueries)
    #[serde(default)]
    pub outer_column_refs: Vec<ColumnRef>,
}

impl ScopedPredicateFact {
    /// Get canonical scope path for comparison
    pub fn canonical_scope_path(&self) -> String {
        self.scope_path
            .iter()
            .map(|s| s.canonical())
            .collect::<Vec<_>>()
            .join("/")
    }

    /// Get nesting depth (0 = main query)
    pub fn depth(&self) -> u32 {
        self.scope_path.last().map(|s| s.depth).unwrap_or(0)
    }
}

impl PartialEq for ScopedPredicateFact {
    fn eq(&self, other: &Self) -> bool {
        // Predicate identity uses PredicateFact's semantic PartialEq.
        // Scope identity uses the canonical scope path string so that
        // two facts compare equal when both place the predicate in the
        // same logical scope.
        self.predicate == other.predicate
            && self.canonical_scope_path() == other.canonical_scope_path()
            && self.scope_id == other.scope_id
            && self.parent_scope_id == other.parent_scope_id
            && self.is_correlated == other.is_correlated
            && self.outer_column_refs == other.outer_column_refs
    }
}

impl Eq for ScopedPredicateFact {}

/// ORDER BY clause details (structured fact)
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct OrderByFact {
    /// Columns being ordered
    pub ordering_columns: Vec<ColumnRef>,
    /// Ordering expressions (for non-simple column refs)
    pub ordering_expressions: Vec<String>,
    /// Direction for each item (true = DESC, false = ASC)
    pub directions: Vec<bool>,
    /// NULLS FIRST/LAST for each item
    pub nulls_ordering: Vec<Option<NullsOrdering>>,
}

/// NULLS ordering
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum NullsOrdering {
    First,
    Last,
}

/// LIMIT/OFFSET details (structured fact)
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LimitFact {
    /// LIMIT value (if literal)
    pub limit_value: Option<u64>,
    /// OFFSET value (if literal)
    pub offset_value: Option<u64>,
    /// True if LIMIT is an expression (not a literal)
    pub limit_is_expression: bool,
    /// True if OFFSET is an expression (not a literal)
    pub offset_is_expression: bool,
}

// ============================================================================
// Policy Configuration Facts (Observer Pattern)
// ============================================================================
// These fact types capture RAW policy configuration values from CREATE/ALTER
// statements. They are populated without making policy decisions
// (e.g., "is 8 characters too short?"). The analyzer reads these facts and
// applies thresholds/rules to emit risk signals.

/// Password policy configuration (structured fact from CREATE/ALTER PASSWORD POLICY)
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PasswordPolicyFact {
    /// Minimum password length (in characters)
    pub min_length: Option<u32>,
    /// Maximum password length (in characters)
    pub max_length: Option<u32>,
    /// Minimum uppercase characters required
    pub min_upper_case_chars: Option<u32>,
    /// Minimum lowercase characters required
    pub min_lower_case_chars: Option<u32>,
    /// Minimum numeric characters required
    pub min_numeric_chars: Option<u32>,
    /// Minimum special characters required
    pub min_special_chars: Option<u32>,
    /// Maximum password age in days
    pub max_age_days: Option<u32>,
    /// Maximum login retry attempts before lockout
    pub max_retries: Option<u32>,
    /// Account lockout duration in minutes
    pub lockout_time_mins: Option<u32>,
    /// Number of previous passwords to remember (prevent reuse)
    pub history: Option<u32>,
    /// Comment (for context)
    pub comment: Option<String>,
}

/// Session policy configuration (structured fact from CREATE/ALTER SESSION POLICY)
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SessionPolicyFact {
    /// Session idle timeout in minutes
    pub session_idle_timeout_mins: Option<u32>,
    /// UI idle timeout in minutes
    pub session_ui_idle_timeout_mins: Option<u32>,
    /// True if allowed secondary roles are configured
    pub has_allowed_secondary_roles: bool,
    /// True if blocked secondary roles are configured
    pub has_blocked_secondary_roles: bool,
    /// Comment (for context)
    pub comment: Option<String>,
}

/// Authentication policy configuration (structured fact from CREATE/ALTER AUTHENTICATION POLICY)
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AuthenticationPolicyFact {
    /// Allowed authentication methods (e.g., PASSWORD, SAML, OAUTH, KEYPAIR, MFA_TOKEN)
    pub authentication_methods: Vec<String>,
    /// Allowed client types (e.g., SNOWFLAKE_UI, DRIVERS, SNOWSQL)
    pub client_types: Vec<String>,
    /// True if MFA_ENROLLMENT is set to REQUIRED
    pub mfa_enrollment_required: bool,
    /// True if MFA_POLICY is set to REQUIRED
    pub mfa_policy_required: bool,
    /// True if PAT_POLICY is set to ENABLED
    pub pat_policy_enabled: bool,
    /// True if WORKLOAD_IDENTITY_POLICY is set to ALLOWED
    pub workload_identity_allowed: bool,
    /// True if a CLIENT_POLICY reference is configured
    pub has_client_policy: bool,
    /// True if SECURITY_INTEGRATIONS are specified
    pub has_security_integrations: bool,
    /// Number of security integrations (if known)
    pub security_integrations_count: Option<usize>,
    /// Comment (for context)
    pub comment: Option<String>,
}

/// Network policy configuration (structured fact from CREATE/ALTER NETWORK POLICY)
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct NetworkPolicyFact {
    /// True if allowed IP list is configured
    pub has_allowed_ip_list: bool,
    /// True if blocked IP list is configured
    pub has_blocked_ip_list: bool,
    /// Number of allowed IPs (if known)
    pub allowed_ip_count: Option<usize>,
    /// Number of blocked IPs (if known)
    pub blocked_ip_count: Option<usize>,
    /// Comment (for context)
    pub comment: Option<String>,
}

/// Aggregation policy configuration (structured fact from CREATE/ALTER AGGREGATION POLICY)
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AggregationPolicyFact {
    /// True if body uses NO_AGGREGATION_CONSTRAINT (removes all protection)
    pub has_no_aggregation_constraint: bool,
    /// Minimum group size value (if AGGREGATION_CONSTRAINT is used)
    pub min_group_size: Option<u32>,
    /// True if body has CASE conditional logic
    pub has_conditional_body: bool,
}

/// Projection policy configuration (structured fact from CREATE/ALTER PROJECTION POLICY)
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProjectionPolicyFact {
    /// True if body has conditional logic (CASE expression)
    pub has_conditional_body: bool,
    /// True if PROJECTION_CONSTRAINT is used
    pub has_projection_constraint: bool,
}

/// API Integration configuration (structured fact from CREATE/ALTER API INTEGRATION)
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ApiIntegrationFact {
    /// True if integration is explicitly enabled
    pub is_enabled: Option<bool>,
    /// True if API_KEY is configured
    pub has_api_key: bool,
    /// True if API_ALLOWED_PREFIXES is configured
    pub has_allowed_prefixes: bool,
    /// True if API_BLOCKED_PREFIXES is configured
    pub has_blocked_prefixes: bool,
    /// Comment (for context)
    pub comment: Option<String>,
}

/// A taint label attached to a column, originating from catalog tags.
///
/// Taint labels propagate along column lineage chains: if a base table column
/// has a tag (e.g., PII=EMAIL), that label flows through CTEs and derived tables
/// to any output column that reads from it.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct TaintLabel {
    /// Tag name (e.g., "PII", "SENSITIVE", "DATA_CLASSIFICATION")
    pub tag_name: String,
    /// Tag value (e.g., "EMAIL", "SSN", "CONFIDENTIAL")
    pub tag_value: Option<String>,
    /// The base table where this taint originates
    pub source_table: String,
    /// The base column where this taint originates
    pub source_column: String,
}

impl std::fmt::Display for TaintLabel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(ref val) = self.tag_value {
            write!(f, "{}={}", self.tag_name, val)
        } else {
            write!(f, "{}", self.tag_name)
        }
    }
}

/// CTE column schema information
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CteColumnSchema {
    /// CTE name (lowercase)
    pub name: String,
    /// Explicit column names if specified (WITH cte(a, b, c) AS ...)
    /// Empty if not specified (must infer from SELECT)
    pub explicit_columns: Vec<String>,
    /// Underlying base tables this CTE reads from
    pub base_tables: Vec<TableRef>,
    /// Column lineage: maps output column (normalized) → source column refs
    /// None if SELECT * or can't determine (complex expressions)
    pub column_lineage: Option<std::collections::HashMap<IdentKey, Vec<ColumnRef>>>,
    /// Whether this CTE has filtering (WHERE, HAVING, or reads from filtered CTEs)
    /// Used to suppress Q-AGG-NOFILT false positives when outer query reads from pre-filtered CTE
    #[serde(default)]
    pub has_filter: bool,
    /// Full constraint set (equality, range, IN-set, null) from the CTE's WHERE/HAVING clauses.
    /// Used for cross-scope contradiction detection (Q-PROP-CONTRA):
    /// if CTE filters `status = 'ACTIVE'` and outer query asks `status = 'CANCELLED'`,
    /// that's a contradiction (always 0 rows). Built from PredicateFacts during
    /// CTE schema construction and propagated across ancestor CTEs.
    #[serde(default)]
    pub constraint_set: crate::ir::constraint_types::IrConstraintSet,
    /// Pre-computed taint labels for output columns.
    /// Populated for cross-model virtual CTEs from upstream `ModelOutputSchema`.
    /// Empty for same-file CTEs (taint resolved via catalog at extraction time).
    #[serde(default)]
    pub taint_labels: std::collections::HashMap<IdentKey, Vec<TaintLabel>>,
}

impl CteColumnSchema {
    pub fn new(name: String, base_tables: Vec<TableRef>) -> Self {
        Self {
            name,
            explicit_columns: vec![],
            base_tables,
            column_lineage: None,
            has_filter: false,
            constraint_set: crate::ir::constraint_types::IrConstraintSet::new(),
            taint_labels: std::collections::HashMap::new(),
        }
    }
}

/// Schema information for a derived table (subquery with alias)
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DerivedTableSchema {
    /// Alias name (lowercase)
    pub alias: String,
    /// Explicit column aliases if specified (AS t(col1, col2))
    /// Empty if not specified
    pub explicit_columns: Vec<String>,
    /// Underlying base tables this subquery reads
    pub base_tables: Vec<TableRef>,
    /// Column lineage from subquery SELECT
    /// None if can't determine (SELECT *, complex expressions)
    pub column_lineage: Option<std::collections::HashMap<IdentKey, Vec<ColumnRef>>>,
    /// Whether this subquery has filtering (WHERE, HAVING, or reads from filtered sources)
    #[serde(default)]
    pub has_filter: bool,
    /// Full constraint set (equality, range, IN-set, null) from the subquery's WHERE/HAVING.
    /// Used for cross-scope contradiction detection (Q-PROP-CONTRA).
    #[serde(default)]
    pub constraint_set: crate::ir::constraint_types::IrConstraintSet,
    /// Pre-computed taint labels for output columns.
    /// Populated for cross-model virtual derived tables from upstream analysis.
    /// Empty for same-file derived tables (taint resolved via catalog at extraction time).
    #[serde(default)]
    pub taint_labels: std::collections::HashMap<IdentKey, Vec<TaintLabel>>,
}

impl DerivedTableSchema {
    pub fn new(alias: String, base_tables: Vec<TableRef>) -> Self {
        Self {
            alias,
            explicit_columns: vec![],
            base_tables,
            column_lineage: None,
            has_filter: false,
            constraint_set: crate::ir::constraint_types::IrConstraintSet::new(),
            taint_labels: std::collections::HashMap::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// ModelOutputSchema — cross-model propagation unit for dbt projects
// ---------------------------------------------------------------------------

/// Output schema of a dbt model, extracted after analysis.
///
/// This is the cross-model propagation unit for constraint, taint, and
/// nullability analysis in dbt projects. When Model B references Model A
/// via `{{ ref('model_a') }}`, Model A's `ModelOutputSchema` provides:
///
/// - **Column existence**: which columns the model outputs (`output_columns`)
/// - **Nullability**: which columns may be NULL from JOINs (`nullable_columns`)
/// - **Constraints**: what WHERE filters were applied (`schema.constraint_set`)
/// - **Taint labels**: which columns carry catalog tags (`taint_labels`)
/// - **Lineage**: where each output column originates (`schema.column_lineage`)
///
/// The `schema` field reuses [`CteColumnSchema`] directly — it already has
/// `Serialize`/`Deserialize` and is the exact shape the analysis pipeline
/// consumes for cross-scope propagation.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ModelOutputSchema {
    /// dbt model name (e.g., `"stg_orders"`).
    pub model_id: String,

    /// Resolved table name after Jinja rendering
    /// (e.g., `"my_db.staging.stg_orders"`).
    pub resolved_relation: String,

    /// SHA-256 hex digest of the rendered SQL for cache invalidation.
    pub content_hash: String,

    /// Epoch seconds (UTC) when this schema was extracted.
    pub extracted_at: u64,

    /// Upstream model names this model depends on (from `ref()` calls).
    pub upstream_models: Vec<String>,

    /// Output columns in SELECT projection order, preserving alias info.
    /// Separate from `schema.column_lineage` because it retains ordering
    /// and `output_alias` metadata that the lineage map (keyed by normalized
    /// name) does not.
    pub output_columns: Vec<ColumnRef>,

    /// The model's output as a CTE-like schema.
    ///
    /// Key fields used cross-model:
    /// - `column_lineage`: output column → source column provenance
    /// - `constraint_set`: WHERE predicates applied to output
    /// - `has_filter`: whether any filtering exists
    /// - `base_tables`: direct table reads
    pub schema: CteColumnSchema,

    /// Output columns that may be NULL (typically from a LEFT/RIGHT/FULL
    /// OUTER JOIN inside the model body). Sibling to `taint_labels` —
    /// IR-projected wire-format slot consumed by downstream
    /// `ModelCatalog::from_external_schemas` to seed
    /// [`crate::ir::plan::ResolvedModel::nullable_columns`].
    #[serde(default, skip_serializing_if = "std::collections::HashSet::is_empty")]
    pub nullable_columns: std::collections::HashSet<IdentKey>,

    /// Per-output-column taint labels inherited from catalog tags.
    /// Only populated when a catalog with tags is available during extraction.
    #[serde(default)]
    pub taint_labels: std::collections::HashMap<IdentKey, Vec<TaintLabel>>,
}

#[cfg(test)]
mod expression_fact_hash_tests {
    use super::*;
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    fn hash_of(val: &ExpressionFact) -> u64 {
        let mut h = DefaultHasher::new();
        val.hash(&mut h);
        h.finish()
    }

    fn col(name: &str) -> ExpressionFact {
        ExpressionFact::Column(ColumnRef::new(name.to_string()))
    }

    fn lit(value: &str, kind: &str) -> ExpressionFact {
        ExpressionFact::Literal {
            value: value.to_string(),
            kind: kind.to_string(),
        }
    }

    // =========================================================================
    // Symmetric BinaryOp: a = b must hash the same as b = a
    // =========================================================================

    #[test]
    fn test_symmetric_binary_op_hash_eq() {
        let ab = ExpressionFact::BinaryOp {
            left: Box::new(col("a")),
            operator: "=".to_string(),
            right: Box::new(col("b")),
        };
        let ba = ExpressionFact::BinaryOp {
            left: Box::new(col("b")),
            operator: "=".to_string(),
            right: Box::new(col("a")),
        };
        assert_eq!(ab, ba, "symmetric BinaryOp should be equal");
        assert_eq!(
            hash_of(&ab),
            hash_of(&ba),
            "symmetric BinaryOp should hash equally"
        );
    }

    #[test]
    fn test_nonsymmetric_binary_op_hash_differs() {
        let ab = ExpressionFact::BinaryOp {
            left: Box::new(col("a")),
            operator: "<".to_string(),
            right: Box::new(col("b")),
        };
        let ba = ExpressionFact::BinaryOp {
            left: Box::new(col("b")),
            operator: "<".to_string(),
            right: Box::new(col("a")),
        };
        assert_ne!(
            ab, ba,
            "non-symmetric BinaryOp with swapped operands should NOT be equal"
        );
        // Hashes may collide but equality should not hold — that's fine for correctness
    }

    // =========================================================================
    // LogicalChain: a AND b must hash the same as b AND a
    // =========================================================================

    #[test]
    fn test_logical_chain_order_independent_hash() {
        let ab = ExpressionFact::LogicalChain {
            operator: "AND".to_string(),
            operands: vec![col("a"), col("b"), col("c")],
        };
        let cba = ExpressionFact::LogicalChain {
            operator: "AND".to_string(),
            operands: vec![col("c"), col("b"), col("a")],
        };
        assert_eq!(ab, cba, "LogicalChain operands should be order-independent");
        assert_eq!(
            hash_of(&ab),
            hash_of(&cba),
            "LogicalChain should hash order-independently"
        );
    }

    // =========================================================================
    // InList: values compared as set
    // =========================================================================

    #[test]
    fn test_in_list_order_independent_hash() {
        let v12 = ExpressionFact::InList {
            expr: Box::new(col("x")),
            values: vec![lit("1", "number"), lit("2", "number"), lit("3", "number")],
            negated: false,
        };
        let v21 = ExpressionFact::InList {
            expr: Box::new(col("x")),
            values: vec![lit("3", "number"), lit("1", "number"), lit("2", "number")],
            negated: false,
        };
        assert_eq!(v12, v21, "InList values should be order-independent");
        assert_eq!(
            hash_of(&v12),
            hash_of(&v21),
            "InList should hash order-independently"
        );
    }

    // =========================================================================
    // Numeric literal normalization
    // =========================================================================

    #[test]
    fn test_numeric_literals_normalized_equality() {
        // 1.0 and 1.00 should both normalize to "1"
        // (normalization happens at extraction time, so we test the
        // equality of already-normalized values here)
        let a = ExpressionFact::Literal {
            value: "1".to_string(),
            kind: "number".to_string(),
        };
        let b = ExpressionFact::Literal {
            value: "1".to_string(),
            kind: "number".to_string(),
        };
        assert_eq!(a, b);
        assert_eq!(hash_of(&a), hash_of(&b));
    }

    #[test]
    fn test_string_literals_case_sensitive() {
        let a = ExpressionFact::Literal {
            value: "'hello'".to_string(),
            kind: "string".to_string(),
        };
        let b = ExpressionFact::Literal {
            value: "'HELLO'".to_string(),
            kind: "string".to_string(),
        };
        assert_ne!(a, b, "String literals should be case-sensitive");
    }

    // =========================================================================
    // Subquery: tables compared as set
    // =========================================================================

    #[test]
    fn test_subquery_tables_order_independent_hash() {
        let s1 = ExpressionFact::Subquery {
            tables_referenced: vec!["users".to_string(), "orders".to_string()],
            kind: "exists".to_string(),
        };
        let s2 = ExpressionFact::Subquery {
            tables_referenced: vec!["orders".to_string(), "users".to_string()],
            kind: "exists".to_string(),
        };
        assert_eq!(s1, s2, "Subquery tables should be order-independent");
        assert_eq!(
            hash_of(&s1),
            hash_of(&s2),
            "Subquery should hash order-independently"
        );
    }

    // =========================================================================
    // Different variants must hash differently (basic sanity)
    // =========================================================================

    #[test]
    fn test_different_variants_hash_differ() {
        let column = col("x");
        let literal = lit("x", "string");
        assert_ne!(column, literal);
        assert_ne!(
            hash_of(&column),
            hash_of(&literal),
            "Different variants should (very likely) hash differently"
        );
    }

    // =========================================================================
    // HashSet operations work correctly (the actual use case)
    // =========================================================================

    #[test]
    fn test_hashset_dedup_symmetric() {
        use std::collections::HashSet;
        let ab = ExpressionFact::BinaryOp {
            left: Box::new(col("a")),
            operator: "=".to_string(),
            right: Box::new(col("b")),
        };
        let ba = ExpressionFact::BinaryOp {
            left: Box::new(col("b")),
            operator: "=".to_string(),
            right: Box::new(col("a")),
        };
        let mut set = HashSet::new();
        set.insert(ab);
        set.insert(ba);
        assert_eq!(set.len(), 1, "Symmetric equals should dedup in HashSet");
    }

    #[test]
    fn test_hashset_set_difference() {
        use std::collections::HashSet;
        let baseline: HashSet<ExpressionFact> = vec![col("id"), col("name")].into_iter().collect();

        let current: HashSet<ExpressionFact> = vec![
            col("id"),
            col("name"),
            ExpressionFact::Function {
                name: "UPPER".to_string(),
                args: vec![col("name")],
                is_distinct: false,
            },
        ]
        .into_iter()
        .collect();

        let added: Vec<_> = current.difference(&baseline).collect();
        assert_eq!(added.len(), 1, "Should detect one new expression");
        assert!(matches!(added[0], ExpressionFact::Function { name, .. } if name == "UPPER"));
    }
}
