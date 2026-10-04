// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! `StatementFacts` — non-relational sibling tier to [`RelPlan`](crate::ir::plan::RelPlan).
//!
//! Carries facts about a statement that do not change the
//! relational shape but must survive to consumers (locking,
//! output formatting, variable assignment targets, dialect
//! extension clauses, embedded Jinja statement fragments).
//! Putting them on [`RelPlan`](crate::ir::plan::RelPlan) would conflate "what tuples does
//! this plan describe?" with "what happens to the tuples after
//! the plan?".
//!
//! The struct is default-empty. Each field holds a SELECT-clause
//! feature that would otherwise reach `RelPlan::Opaque`.
//!
//! ## Closed-enum discipline
//!
//! `LockStrength`, `WaitPolicy`, `OutputFormat`, and
//! `SelectAsKind` are closed. A new dialect's locking
//! flavor or output format is a new variant —
//! no `String` payloads, no `_ =>` arms.

use crate::ast::NodeId;
use crate::lexer::Span;

use super::scalar::ScalarExpr;

/// Non-relational facts about a single statement, carried
/// alongside its [`super::plan::RelPlan`].
///
/// All fields default to their empty / `None` value.
#[derive(Debug, Clone, Default)]
pub struct StatementFacts {
    /// PostgreSQL / Snowflake / Oracle row-locking clause(s).
    /// `FOR UPDATE`, `FOR SHARE`, `FOR NO KEY UPDATE`, `FOR
    /// KEY SHARE`, each optionally with `OF tables`, wait
    /// policy. SQL allows multiple `FOR …` clauses to chain;
    /// the order is preserved.
    pub for_update: Vec<ForUpdateFact>,

    /// T-SQL `FOR JSON …` / `FOR XML …` output-formatting
    /// clause. Mutually exclusive with `for_update`.
    pub output_format: Option<OutputFormat>,

    /// T-SQL / Postgres `SELECT … INTO @var, @var2`
    /// variable-assignment targets. Each entry is a span over
    /// the target identifier; the binding side of the
    /// assignment is non-relational and lives here.
    pub into_vars: Vec<IntoVarTarget>,

    /// MySQL `SELECT … INTO OUTFILE / DUMPFILE` server-side
    /// file export. At most one per statement (grammar).
    pub file_export: Option<FileExportFact>,

    /// BigQuery `SELECT AS STRUCT` / `SELECT AS VALUE`
    /// projection-shape qualifier.
    pub select_as: Option<SelectAsKind>,

    /// Dialect-extension clauses appearing before the LIMIT
    /// position (e.g. PostgreSQL `WINDOW` definitions the
    /// parser preserves as opaque spans). Carried as
    /// preserved-text spans only.
    pub pre_limit_extensions: Vec<Span>,

    /// Dialect-extension clauses appearing after the locking
    /// position. Same shape as [`pre_limit_extensions`](Self::pre_limit_extensions).
    pub post_locking_extensions: Vec<Span>,

    /// Embedded clause-level Jinja statement fragments
    /// (`{% if cond %} WHERE … {% endif %}` and similar).
    /// Each entry records the AST `NodeId` so consumers can
    /// look up the original fragment AST node, and the span
    /// of the entire Jinja block for diagnostics.
    pub jinja_fragments: Vec<JinjaFragmentRef>,
}

impl StatementFacts {
    /// Construct a default-empty `StatementFacts`. Equivalent
    /// to [`Default::default`] — provided as a named
    /// constructor so call sites read clearly.
    pub fn empty() -> Self {
        Self::default()
    }

    /// Returns `true` when no field has been populated. Used
    /// by consumers that want to skip facts entirely on
    /// statements where lowering had nothing non-relational
    /// to record.
    pub fn is_empty(&self) -> bool {
        let StatementFacts {
            for_update,
            output_format,
            into_vars,
            file_export,
            select_as,
            pre_limit_extensions,
            post_locking_extensions,
            jinja_fragments,
        } = self;
        for_update.is_empty()
            && output_format.is_none()
            && into_vars.is_empty()
            && file_export.is_none()
            && select_as.is_none()
            && pre_limit_extensions.is_empty()
            && post_locking_extensions.is_empty()
            && jinja_fragments.is_empty()
    }
}

/// One `FOR UPDATE` / `FOR SHARE` / `FOR NO KEY UPDATE` /
/// `FOR KEY SHARE` clause.
#[derive(Debug, Clone)]
pub struct ForUpdateFact {
    /// Lock strength (closed enum).
    pub strength: LockStrength,
    /// Optional `WAIT n` / `NOWAIT` / `SKIP LOCKED` policy.
    pub wait: Option<WaitPolicy>,
    /// Optional `OF table_name [, …]` table list. Each entry
    /// is the span over the source table identifier.
    pub of_tables: Vec<Span>,
    /// Span covering the entire `FOR …` clause.
    pub span: Span,
}

/// Lock strength for the `FOR …` clause. Closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockStrength {
    /// `FOR UPDATE` — strongest lock.
    Update,
    /// `FOR NO KEY UPDATE` — PostgreSQL.
    NoKeyUpdate,
    /// `FOR SHARE` — shared lock.
    Share,
    /// `FOR KEY SHARE` — PostgreSQL weakest lock.
    KeyShare,
}

/// Wait-policy for the `FOR …` clause. Closed.
#[derive(Debug, Clone)]
pub enum WaitPolicy {
    /// `NOWAIT` — fail immediately if rows are locked.
    NoWait { span: Span },
    /// `WAIT n` — Snowflake/Oracle, wait at most `n` seconds.
    /// `duration` is the lowered scalar expression (typically
    /// a numeric literal).
    Wait { duration: ScalarExpr, span: Span },
    /// `SKIP LOCKED` — skip rows that are currently locked.
    SkipLocked { span: Span },
}

/// T-SQL output-formatting clause. Closed.
#[derive(Debug, Clone)]
pub enum OutputFormat {
    /// `FOR JSON {AUTO|PATH} […]`.
    ForJson { span: Span },
    /// `FOR XML {RAW|AUTO|PATH|EXPLICIT} […]`.
    ForXml { span: Span },
}

/// One target of `SELECT … INTO @var [, @var2 …]`.
#[derive(Debug, Clone)]
pub struct IntoVarTarget {
    /// Span covering the target variable identifier.
    pub span: Span,
}

/// MySQL `SELECT … INTO OUTFILE 'file'` / `INTO DUMPFILE 'file'` —
/// server-side file export of the result set.
#[derive(Debug, Clone, PartialEq)]
pub struct FileExportFact {
    pub kind: FileExportKind,
    /// File-path string literal as written, including quotes.
    pub file_path: String,
    /// Span covering the whole INTO clause.
    pub span: Span,
}

/// File-export target form. Closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileExportKind {
    /// `INTO OUTFILE` — formatted text export with optional
    /// CHARACTER SET / FIELDS / LINES options.
    Outfile,
    /// `INTO DUMPFILE` — single-row raw binary export.
    Dumpfile,
}

/// BigQuery projection-shape qualifier. Closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectAsKind {
    /// `SELECT AS STRUCT` — wrap each row into a struct.
    Struct,
    /// `SELECT AS VALUE` — single-column rows become scalars.
    Value,
}

/// Reference to an embedded Jinja statement fragment. Carries
/// the AST `NodeId` so consumers can look up the full fragment
/// (statement, elif/else branches, delimiters) on demand.
#[derive(Debug, Clone)]
pub struct JinjaFragmentRef {
    /// AST node id of the originating
    /// [`crate::ast::JinjaStatementFragment`].
    pub node_id: NodeId,
    /// Span covering the entire `{% … %} … {% end… %}` block.
    pub span: Span,
}
