// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Abstract Syntax Tree (AST) definitions.
//!
//! This module defines the complete AST structure representing parsed SQL.
//! One AST serves every dialect; a statement only one dialect has gets its
//! own node type.
//! All AST nodes preserve source location information via `Span` fields.
//!
//! ## Core Structures
//!
//! - **AstScript**: Top-level container for multi-statement scripts
//! - **AstStmt**: Enum of all statement types (SELECT, INSERT, CREATE, etc.)
//! - **AstExpr**: Enum of all expression types (literals, operators, function calls)
//! - **AstSelect**: SELECT query structure with all clauses
//!
//! ## Statement Types
//!
//! ### DML Statements
//! - `AstSelect`: SELECT queries with projections, joins, filters
//! - `AstInsert`: INSERT with VALUES or SELECT source
//! - `AstUpdate`: UPDATE with SET and WHERE clauses
//! - `AstDelete`: DELETE with optional USING
//! - `AstMerge`: MERGE with WHEN MATCHED clauses
//!
//! ### DDL Statements
//! - `AstCreateTable`: CREATE TABLE with various options
//! - `AstCreateFunctionStmt`: CREATE FUNCTION definitions
//! - `AstCreateProcedureStmt`: CREATE PROCEDURE definitions
//! - `AstDrop`: DROP statements
//! - `AstTruncate`: TRUNCATE TABLE
//!
//! ### Scripting Statements
//! - `Block`: BEGIN...END blocks with declarations
//! - `If`: IF/ELSEIF/ELSE control flow
//! - `CaseStmt`: CASE statement (not expression)
//! - `Loop/While/Repeat/For`: Loop constructs
//! - `Return/Break/Continue`: Flow control
//!
//! ## Expression Types
//!
//! - **Literals**: String, Number, Boolean, Null
//! - **Identifiers**: Column references with optional qualifiers
//! - **Operators**: Binary, unary, comparison, logical
//! - **Function calls**: Regular and window functions
//! - **Subqueries**: Scalar and EXISTS subqueries
//! - **Special**: CASE, CAST, array indexing
//!
//! ## Span Information
//!
//! Every AST node includes span information for:
//! - Error reporting with line/column positions
//! - Source code reconstruction
//! - Syntax highlighting
//! - Code formatting
//!
//! ## Design Principles
//!
//! 1. **Complete representation**: No information loss from source
//! 2. **Type safety**: Strong typing for all SQL constructs
//! 3. **Span tracking**: Every node knows its source location
//! 4. **Extensibility**: Easy to add new node types

use crate::error::ExpectInvariant;
use crate::lexer::{Keyword, Span, TokenKind};
use crate::syntax::{SyntaxJinjaDelimiterId, SyntaxJinjaInlineFragmentId};

// ============================================================================
// Defensive Design: Unknown Clause Preservation
// ============================================================================
//
// These types enable the parser to handle unknown/future Snowflake features
// without breaking. When Snowflake adds new properties/clauses to open-ended
// statements (CREATE/ALTER STAGE, WAREHOUSE, INTEGRATION, etc.), the parser
// captures them as AstUnknownClause entries instead of failing.
//
// This pattern applies ONLY to open-ended statement families with KEY=VALUE
// properties, NOT to structured clauses like SELECT/WHERE/JOIN.

/// Represents an unknown clause or property that the parser doesn't recognize.
///
/// When encountering syntax we don't know how to parse (e.g., a new Snowflake
/// feature added after this parser was written), we preserve the exact source
/// span instead of failing. This allows:
///
/// 1. Forward compatibility - new Snowflake features don't break the parser
/// 2. Semantic preservation - formatter can emit unknown syntax unchanged
/// 3. Visibility - diagnostics can warn about unrecognized syntax
///

#[derive(Debug, Clone)]
pub struct AstUnknownClause {
    /// Unique node identifier for this clause
    pub node_id: crate::ast::NodeId,

    /// Property key or clause keyword span (if identifiable).
    /// When we can identify the introducer keyword (e.g., "SET", "ENCRYPTION"),
    /// we store its span here for better diagnostics.
    pub introducer: Option<Span>,

    /// Exact text range in source covering the entire unknown construct
    pub span: Span,

    /// What kind of unknown thing this is
    pub kind: UnknownKind,
}

/// Classification of unknown syntax kinds for diagnostics and handling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnknownKind {
    /// Unknown property (KEY = VALUE we don't recognize)
    Property,

    /// Entire clause we don't recognize
    Clause,

    /// Value format we don't recognize
    Value,

    /// Unrecognized ALTER action body within a known statement type
    /// (e.g. an `ALTER SHARE` action we haven't structurally modeled).
    /// The statement classification (`StatementKind`) is correct;
    /// only the per-action shape is opaque.
    AlterAction,
}

/// A decomposed property from a CREATE policy statement.
///
/// Instead of storing a monolithic span covering `PROPERTY_NAME = VALUE`,
/// this stores each component separately, enabling:
/// - Equals-sign alignment in the formatter
/// - Accurate value extraction (no need to tokenize the name/eq)
///
/// Used by CREATE PASSWORD POLICY, CREATE SESSION POLICY, and similar statements.
#[derive(Debug, Clone, Copy)]
pub struct CreatePolicyProperty {
    /// Span covering the property name identifier (e.g. `PASSWORD_MIN_LENGTH`)
    pub name_span: Span,
    /// Span covering the `=` operator
    pub eq_span: Span,
    /// Span covering the value (e.g. `12`, `'string'`, `(...)`)
    pub value_span: Span,
    /// Span covering the entire property (`name = value`)
    pub full_span: Span,
}

impl CreatePolicyProperty {
    /// Length of the property name text.
    pub fn name_len(&self) -> usize {
        (self.name_span.end - self.name_span.start) as usize
    }
}

/// A SELECT query statement.
///
/// Represents a complete SELECT statement with all its clauses including
/// projection, FROM, WHERE, GROUP BY, HAVING, ORDER BY, QUALIFY, LIMIT, and OFFSET.
/// Also supports WITH (CTE) clauses and Snowflake Scripting's SELECT...INTO variant.
///
/// # Fields
///
/// * `span` - Source location covering the entire SELECT statement
/// * `projection` - What to select (columns, expressions, *)
/// * `from` - Table references and joins
/// * `where_clause` - Filter conditions
/// * `group_by` - Grouping specification
/// * `having` - Group filter conditions
/// * `order_by` - Sort specification
/// * `qualify` - Window function filter
/// * `limit` - Maximum rows to return
/// * `offset` - Rows to skip
/// * `with_clause` - Optional CTEs (Common Table Expressions)
/// * `into_target` - For SELECT...INTO: scripting vars (Snowflake/MySQL/Oracle)
///   or MSSQL/PostgreSQL CTAS new-table target (mutually exclusive variants).
#[derive(Debug, Clone)]
pub struct AstSelect {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    pub select_span: Span,
    /// BigQuery SELECT AS STRUCT / SELECT AS VALUE qualifier span.
    /// Covers the `AS STRUCT` or `AS VALUE` tokens after SELECT.
    pub select_as_qualifier: Option<Span>,
    pub set_quantifier: Option<Box<AstSetQuantifier>>,
    /// Span covering the SELECT set quantifier keyword when present (`ALL` or `DISTINCT`).
    pub set_quantifier_span: Option<Span>,
    pub top: Option<Box<AstTop>>,       // Boxed: was 400 bytes
    pub projection: Box<AstProjection>, // Boxed: was 256 bytes inline
    pub from: Vec<FromItem>,
    /// Jinja statement fragments that conditionally include WHERE/HAVING/JOIN clauses
    /// Example: FROM table {% if cond %}WHERE x = 1{% endif %}
    pub statement_fragments: Vec<JinjaStatementFragment>,
    pub where_clause: Option<Box<ConditionClause>>, // Boxed: was 448 bytes
    pub group_by: Option<Box<AstGroupBy>>,          // Boxed: was 104 bytes inline
    /// Optional CONNECT BY clause for hierarchical queries
    pub connect_by: Option<Box<AstConnectBy>>, // Boxed: was 528 bytes
    pub order_by: Option<Box<AstOrderBy>>,          // Boxed: was 88 bytes inline
    /// Dialect-specific clauses preserved as raw spans between ORDER BY and LIMIT/OFFSET
    /// (e.g., Databricks DISTRIBUTE BY / SORT BY / CLUSTER BY).
    pub pre_limit_extension_clauses: Box<Vec<Span>>,
    pub having: Option<Box<ConditionClause>>, // Boxed: was 448 bytes
    pub qualify: Option<Box<ConditionClause>>, // Boxed: was 448 bytes
    pub limit: Option<Box<AstExpr>>,          // Boxed: was 384 bytes
    pub offset: Option<Box<AstExpr>>,         // Boxed: was 384 bytes
    /// Span covering the LIMIT keyword if LIMIT syntax was used, None if FETCH syntax was used
    pub limit_keyword_span: Option<Span>,
    /// Span covering entire FETCH...ONLY clause if ANSI FETCH syntax was used
    /// When Some, formatter should emit original text instead of synthesizing LIMIT
    pub fetch_clause_span: Option<Span>,
    /// Span covering OFFSET keyword and any following ROW/ROWS
    pub offset_keyword_span: Option<Span>,
    /// Span of the comma in the MySQL `LIMIT offset, count` form. When
    /// `Some`, `offset` precedes `limit` in source and the formatter
    /// re-emits the comma form instead of synthesizing OFFSET.
    pub limit_offset_comma_span: Option<Span>,
    /// Optional FOR UPDATE/SHARE locking clauses (boxed to keep AstSelect small)
    /// Snowflake: single FOR UPDATE; PostgreSQL: multiple FOR {UPDATE|SHARE|...}
    pub for_update: Option<Box<Vec<AstForUpdate>>>,
    /// Optional MSSQL FOR JSON / FOR XML clause preserved as raw span.
    /// Covers the entire clause: `FOR JSON PATH, ROOT('data'), INCLUDE_NULL_VALUES`
    /// or `FOR XML PATH('row'), ROOT('data'), TYPE, ELEMENTS XSINIL`.
    pub for_json_xml: Option<Span>,
    /// Dialect-specific trailing clauses preserved as raw spans
    /// (e.g., MSSQL OPTION(...)).
    pub post_locking_extension_clauses: Box<Vec<Span>>,
    /// Optional WINDOW clause (named window definitions)
    /// Syntax: WINDOW w AS (...) [, w2 AS (...)]
    pub window_clause: Option<Box<AstWindowClause>>,
    /// Optional WITH clause (CTEs) that precedes the SELECT
    pub with_clause: Option<Box<AstWithClause>>,
    /// Optional INTO target. Mutually-exclusive variants:
    /// - `ScriptingVars(Vec<Span>)` — Snowflake Scripting / Oracle PL/SQL /
    ///   MySQL: `SELECT col INTO :var, :var2 FROM …`.
    /// - `NewTable(Box<AstSelectIntoNewTable>)` — MSSQL / PostgreSQL legacy
    ///   CTAS form: `SELECT col INTO new_tbl FROM …`. Semantically a
    ///   create-and-populate, equivalent to CREATE TABLE … AS SELECT.
    ///
    /// Disambiguated at parse time by dialect (PL/pgSQL bodies live inside
    /// `$$…$$` literals and do not reach the main SELECT parser).
    pub into_target: Option<Box<AstSelectIntoTarget>>,
    /// Optional semicolon token ID when SELECT appears in scripting context.
    /// Captured via peek (not consumed) - formatter emits it explicitly.
    pub semicolon_token: Option<crate::cst::TokenId>,
    /// Optional syntax ID for parentheses when this SELECT is parenthesized in a set operation.
    /// Example: (SELECT ...) UNION (SELECT ...) - each SELECT has paren_syntax_id pointing to SyntaxSubquery.
    pub paren_syntax_id: Option<crate::syntax::SyntaxSubqueryId>,
    /// When `Some`, this SELECT was written in MySQL's `TABLE tbl [ORDER BY
    /// ...] [LIMIT ...]` surface syntax (sugar for `SELECT * FROM tbl ...`).
    /// The span covers the `TABLE` keyword. Set only by the MySQL TABLE
    /// parser; the formatter re-emits the original `TABLE` form from the
    /// statement span. All analysis treats it as the equivalent `SELECT *`.
    pub table_syntax_span: Option<Span>,
}

/// Payload for [`AstTableRef::paren_group`]. Boxed off the parent to keep
/// `AstTableRef` small enough for deeply nested subquery chains.
#[derive(Debug, Clone)]
pub struct ParenGroupInfo {
    pub lparen_span: Span,
    pub rparen_span: Span,
    /// Number of `joins` entries that were inside the parens. Joins past
    /// this index were chained after the closing `)`.
    pub inner_join_count: u16,
    /// `Some` when the group was written as the ODBC outer-join escape
    /// `{oj …}`: the span covers the `oj` introducer and `lparen_span` /
    /// `rparen_span` hold the braces. The join is otherwise identical to
    /// the parenthesised form; only the formatter consumes this.
    pub odbc_oj_span: Option<Span>,
}

/// ODBC datetime/GUID escape kind: `{d '…'}` / `{t '…'}` / `{ts '…'}` /
/// `{guid '…'}`. Carried on [`AstExpr::TypedStringLiteral`] so consumers
/// can use the canonical type name (the source introducer is `d`, not
/// `DATE`) while the formatter re-emits the whole braced span verbatim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OdbcLiteralKind {
    Date,
    Time,
    Timestamp,
    Guid,
}

impl OdbcLiteralKind {
    /// Canonical SQL type name used for `Lit::Typed.type_name`.
    pub fn canonical_type_name(self) -> &'static str {
        match self {
            Self::Date => "DATE",
            Self::Time => "TIME",
            Self::Timestamp => "TIMESTAMP",
            Self::Guid => "GUID",
        }
    }
}

/// ODBC call-escape surface on [`AstStmt::Call`]: `{call p(...)}` /
/// `{? = call p(...)}`.
#[derive(Debug, Clone, Copy)]
pub struct AstOdbcCallEscape {
    /// Span of the `?` return-value marker in `{? = call ...}`, if present.
    pub return_marker_span: Option<Span>,
}

/// Discriminator for `SELECT … INTO …` shape.
///
/// Two semantically distinct forms share the same INTO keyword:
/// 1. **ScriptingVars** — bind query results to script-local variables
///    (Snowflake Scripting, MySQL stored procedures, Oracle PL/SQL).
/// 2. **NewTable** — MSSQL / PostgreSQL legacy CTAS shortcut that creates
///    and populates a new (possibly temp) table.
///
/// Disambiguation is dialect-driven at parse time:
/// - MSSQL: always `NewTable` (no scripting-INTO form exists).
/// - PostgreSQL: always `NewTable` (PL/pgSQL bodies are dollar-quoted
///   string literals and never reach the main SELECT parser).
/// - Snowflake / BigQuery / Databricks / MySQL: always `ScriptingVars`.
#[derive(Debug, Clone)]
pub enum AstSelectIntoTarget {
    /// `INTO :var, :var2` or bare `INTO var, var2`. Each span covers one
    /// target variable identifier (including the leading `:` if written).
    ScriptingVars(Vec<Span>),
    /// `INTO [TEMP|TEMPORARY|UNLOGGED] new_tbl [ON filegroup]`.
    /// Semantically a CREATE TABLE … AS SELECT.
    NewTable(Box<AstSelectIntoNewTable>),
    /// MySQL `INTO OUTFILE 'file' [export options]` / `INTO DUMPFILE
    /// 'file'` — server-side file export. Valid both post-projection and
    /// trailing (after FROM/WHERE/LIMIT).
    OutFile(Box<AstSelectIntoOutfile>),
}

/// Payload for [`AstSelectIntoTarget::OutFile`].
#[derive(Debug, Clone)]
pub struct AstSelectIntoOutfile {
    pub node_id: crate::ast::NodeId,
    /// Span of the INTO keyword.
    pub into_span: Span,
    pub kind: AstIntoFileKind,
    /// Span of the OUTFILE / DUMPFILE word (lexes as an identifier).
    pub kind_span: Span,
    /// Span of the file-path string literal.
    pub file_span: Span,
    /// Export options tail (`CHARACTER SET …`, `FIELDS/COLUMNS …`,
    /// `LINES …`) preserved verbatim; OUTFILE only.
    pub options_span: Option<Span>,
    /// Whole clause: INTO through the last consumed token.
    pub span: Span,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AstIntoFileKind {
    /// `INTO OUTFILE` — formatted text export, supports export options.
    Outfile,
    /// `INTO DUMPFILE` — single-row raw binary export.
    Dumpfile,
}

impl AstSelectIntoTarget {
    /// Convenience accessor: returns the scripting-var span list, or `&[]`
    /// for the `NewTable` form. Lets call sites that only care about the
    /// scripting form iterate uniformly.
    pub fn scripting_vars(&self) -> &[Span] {
        match self {
            AstSelectIntoTarget::ScriptingVars(v) => v.as_slice(),
            AstSelectIntoTarget::NewTable(_) => &[],
            AstSelectIntoTarget::OutFile(_) => &[],
        }
    }

    /// End position of the INTO clause (used for SELECT span calculation).
    pub fn end_pos(&self) -> Option<u32> {
        match self {
            AstSelectIntoTarget::ScriptingVars(v) => v.last().map(|s| s.end),
            AstSelectIntoTarget::NewTable(nt) => Some(
                nt.on_filegroup
                    .as_ref()
                    .map(|fg| fg.filegroup_span.end)
                    .unwrap_or(nt.name.span.end),
            ),
            AstSelectIntoTarget::OutFile(of) => Some(of.span.end),
        }
    }
}

#[derive(Debug, Clone)]
pub struct AstSelectIntoNewTable {
    pub node_id: crate::ast::NodeId,
    /// Span of the `INTO` keyword.
    pub into_span: Span,
    /// Target table name. Qualified (`db.schema.tbl`) and quoted
    /// (`[dbo].[t]`, `"public"."t"`) forms supported. MSSQL `#tmp` /
    /// `##tmp` is a single `Identifier { kind: TempTable }` token
    /// absorbed into `name`.
    pub name: Box<AstObjectRef>,
    /// Combined temp-prefix (MSSQL) + qualifier (PG TEMP/UNLOGGED)
    /// discriminator. See [`AstSelectIntoTempKind`].
    pub temp_kind: AstSelectIntoTempKind,
    /// PG `TEMP` / `TEMPORARY` / `UNLOGGED` qualifier keyword span.
    /// MSSQL has no qualifier keyword (the `#`/`##` is part of the
    /// identifier itself).
    pub temp_keyword_span: Option<Span>,
    /// MSSQL `ON [PRIMARY]` filegroup clause.
    pub on_filegroup: Option<AstSelectIntoFilegroup>,
}

#[derive(Debug, Clone)]
pub struct AstSelectIntoFilegroup {
    pub on_span: Span,
    pub filegroup_span: Span,
}

/// Combined discriminator for `SELECT INTO new_tbl` temp-ness. Closed enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AstSelectIntoTempKind {
    /// Regular persistent table.
    None,
    /// MSSQL local-session temp table (`#tmp_local`).
    LocalTemp,
    /// MSSQL global temp table (`##tmp_global`).
    GlobalTemp,
    /// PostgreSQL `TEMP` / `TEMPORARY` qualifier.
    Temp,
    /// PostgreSQL `UNLOGGED` qualifier.
    Unlogged,
}

#[derive(Debug, Clone)]
pub struct AstWithClause {
    pub node_id: crate::ast::NodeId,
    pub with_span: Span,
    pub recursive_span: Option<Span>,
    pub ctes: Vec<CteItem>,
    pub span: Span,
}

/// An item in a WITH clause CTE list.
/// Supports both regular CTEs and Jinja blocks that generate CTEs.
#[derive(Debug, Clone)]
pub enum CteItem {
    /// A regular CTE: `name AS (SELECT ...)`
    Cte(AstCte),
    /// A Jinja block generating one or more CTEs:
    /// `{% for region in regions %}{{ region }}_sales AS (...){% endfor %}`
    JinjaBlock(Box<JinjaCteBlock>),
}

impl CteItem {
    /// Get the span of this CTE item
    pub fn span(&self) -> Span {
        match self {
            CteItem::Cte(cte) => cte.span,
            CteItem::JinjaBlock(block) => block.span,
        }
    }
}

/// A Jinja control block that generates one or more CTEs.
/// Used for patterns like: {% for region in regions %}{{ region }}_sales AS (...){% endfor %}
#[derive(Debug, Clone)]
pub struct JinjaCteBlock {
    pub node_id: crate::ast::NodeId,
    /// Opening Jinja delimiter ({% if %} or {% for %})
    pub opening: JinjaBlockDelimiter,
    /// CTE fragments in the primary branch
    pub then_ctes: Vec<CteFragment>,
    /// Optional elif branches (only for If blocks)
    pub elif_branches: Vec<JinjaCteElifBranch>,
    /// Optional else branch
    pub else_branch: Option<JinjaCteElseBranch>,
    /// Closing Jinja delimiter ({% endif %} or {% endfor %})
    pub closing: JinjaBlockDelimiter,
    /// Span covering the entire block
    pub span: Span,
}

/// A CTE fragment inside a Jinja block.
/// The name may contain Jinja expressions like `{{ region }}_sales`.
#[derive(Debug, Clone)]
pub struct CteFragment {
    pub node_id: crate::ast::NodeId,
    /// Span covering the CTE name (may include Jinja expressions)
    pub name_span: Span,
    /// Optional column list in parentheses after CTE name
    pub column_list: Vec<AstIdentifier>,
    /// The AS keyword span
    pub as_span: Span,
    /// Opening paren span for the CTE subquery
    pub lparen_span: Span,
    /// Closing paren span for the CTE subquery
    pub rparen_span: Span,
    /// The query that defines the CTE
    pub query: Box<AstStmt>,
    /// Typed inline fragments that appear after the CTE (comments, inline blocks, punctuation)
    pub suffix_inline_fragments: Vec<JinjaInlineFragment>,
    /// Span covering the entire CTE fragment
    pub span: Span,
}

/// An elif branch in a Jinja CTE block
#[derive(Debug, Clone)]
pub struct JinjaCteElifBranch {
    pub node_id: crate::ast::NodeId,
    /// The {% elif condition %} delimiter
    pub delimiter: JinjaBlockDelimiter,
    /// CTE fragments in this elif branch
    pub ctes: Vec<CteFragment>,
}

/// An else branch in a Jinja CTE block
#[derive(Debug, Clone)]
pub struct JinjaCteElseBranch {
    pub node_id: crate::ast::NodeId,
    /// The {% else %} delimiter
    pub delimiter: JinjaBlockDelimiter,
    /// CTE fragments in the else branch
    pub ctes: Vec<CteFragment>,
}

#[derive(Debug, Clone)]
pub struct AstCte {
    pub node_id: crate::ast::NodeId,
    pub name: AstIdentifier,
    /// Optional column list in parentheses after CTE name
    pub column_list: Vec<AstIdentifier>,
    /// Syntax node containing AS keyword and parentheses around subquery
    pub syntax_id: crate::syntax::SyntaxCteId,
    /// The query that defines the CTE (stored as a statement)
    pub query: Box<AstStmt>,
    pub span: Span,
}

/// A multi-statement script.
///
/// Container for multiple SQL and/or Snowflake Scripting statements parsed
/// from a single source. Statements may be a mix of DML, DDL, and scripting
/// control flow.

#[derive(Debug, Clone)]
pub struct AstScript {
    pub node_id: crate::ast::NodeId,
    pub stmts: Vec<AstStmt>,
    /// Typed syntax arena - owns all structural tokens (parens, keywords, etc.)
    /// The AST nodes reference syntax nodes by ID; formatter looks up tokens here.
    pub syntax_arena: crate::syntax::SyntaxArena,
    /// Byte-spans of secret values (credential properties, password literals)
    /// found while parsing. Output surfaces mask these so a credential value
    /// is never reproduced in a finding preview / evidence / SARIF snippet.
    pub redaction_spans: Vec<Span>,
}

/// Snowflake Scripting Block statement: BEGIN...END with optional DECLARE and EXCEPTION
#[derive(Debug, Clone)]
pub struct AstBlockStmt {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    /// Optional label before BEGIN (e.g., `my_label: BEGIN`), covers `my_label:`
    pub label_span: Option<Span>,
    /// Optional label after END (e.g., `END my_label`), covers `my_label`
    pub end_label_span: Option<Span>,
    /// Span covering the DECLARE keyword (if present)
    pub declare_span: Option<Span>,
    /// TokenId for the DECLARE keyword (if present)
    pub declare_token: Option<crate::cst::TokenId>,
    /// Span covering the BEGIN keyword
    pub begin_span: Span,
    /// TokenId for the BEGIN keyword
    pub begin_token: Option<crate::cst::TokenId>,
    /// Span covering the ATOMIC keyword (Databricks: BEGIN ATOMIC ... END)
    pub atomic_span: Option<Span>,
    /// Declarations that appear in the DECLARE header section
    /// of a Snowflake Scripting block, i.e. before BEGIN.
    pub decls: Vec<AstStmt>,
    /// Statements that appear inside the BEGIN ... END body.
    pub body: Vec<AstStmt>,
    /// Optional EXCEPTION section for the block. When present,
    /// this models the `EXCEPTION` keyword and its WHEN clauses
    /// as a shallow span-only node so that callers can see
    /// exception handlers without needing a full scripting AST.
    pub exception: Option<AstExceptionSection>,
    /// Span covering the END keyword
    pub end_span: Option<Span>,
    /// TokenId for the END keyword
    pub end_token: Option<crate::cst::TokenId>,
    /// TokenId for the semicolon after END (when block is nested inside another block)
    pub semicolon_token: Option<crate::cst::TokenId>,
}

/// Snowflake Scripting IF statement: IF...ELSEIF...ELSE...END IF
#[derive(Debug, Clone)]
pub struct AstIfStmt {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    pub branches: Vec<IfBranch>,
    /// Span of the ELSE keyword, if present
    pub else_span: Option<Span>,
    /// TokenId for the ELSE keyword
    pub else_token: Option<crate::cst::TokenId>,
    pub else_body: Vec<AstStmt>,
    /// Span covering the END IF keywords
    pub end_span: Option<Span>,
    /// TokenId for the END keyword
    pub end_token: Option<crate::cst::TokenId>,
    /// TokenId for the IF keyword after END
    pub end_if_token: Option<crate::cst::TokenId>,
    /// TokenId for the semicolon after END IF
    pub semicolon_token: Option<crate::cst::TokenId>,
}

/// Snowflake Scripting CASE statement: CASE...WHEN...ELSE...END CASE
#[derive(Debug, Clone)]
pub struct AstCaseStmt {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    /// Span covering the CASE keyword
    pub case_span: Span,
    /// TokenId for the CASE keyword
    pub case_token: Option<crate::cst::TokenId>,
    /// Optional operand span for simple CASE; None for searched CASE.
    pub operand_span: Option<Span>,
    /// WHEN branches with condition/value and body spans.
    pub branches: Vec<CaseBranch>,
    /// Span of the ELSE keyword, if present
    pub else_span: Option<Span>,
    /// TokenId for the ELSE keyword
    pub else_token: Option<crate::cst::TokenId>,
    /// Optional ELSE body statements.
    pub else_body: Vec<AstStmt>,
    /// Span covering the END CASE keywords
    pub end_span: Option<Span>,
    /// TokenId for the END keyword
    pub end_token: Option<crate::cst::TokenId>,
    /// TokenId for the CASE keyword after END
    pub end_case_token: Option<crate::cst::TokenId>,
    /// TokenId for the semicolon after END CASE
    pub semicolon_token: Option<crate::cst::TokenId>,
}

/// FOR loop statement (Snowflake Scripting).
/// Extracted to reduce AstStmt enum size.
#[derive(Debug, Clone)]
pub struct AstForStmt {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    /// Optional label before FOR (e.g., `my_label: FOR`), covers `my_label:`
    pub label_span: Option<Span>,
    /// Optional label after END FOR (e.g., `END FOR my_label`), covers `my_label`
    pub end_label_span: Option<Span>,
    /// Span covering the FOR keyword
    pub for_span: Span,
    /// TokenId for the FOR keyword
    pub for_token: Option<crate::cst::TokenId>,
    pub loop_var_span: Span,
    /// Span covering the IN keyword
    pub in_span: Span,
    /// TokenId for the IN keyword
    pub in_token: Option<crate::cst::TokenId>,
    pub range_or_cursor_span: Span,
    /// Span covering loop-body opener keyword (`DO` or `LOOP`)
    pub body_keyword_span: Span,
    /// TokenId for loop-body opener keyword (`DO` or `LOOP`)
    pub body_keyword_token: Option<crate::cst::TokenId>,
    pub body: Vec<AstStmt>,
    /// Span covering the END FOR keywords
    pub end_span: Option<Span>,
    /// TokenId for the END keyword
    pub end_token: Option<crate::cst::TokenId>,
    /// TokenId for the FOR keyword after END
    pub end_for_token: Option<crate::cst::TokenId>,
    /// TokenId for the semicolon after END FOR
    pub semicolon_token: Option<crate::cst::TokenId>,
}

/// PostgreSQL PL/pgSQL `FOREACH target [SLICE n] IN ARRAY expr LOOP … END LOOP`.
/// Distinct from [`AstForStmt`] because it parses the iterated collection as a
/// real expression and carries the optional SLICE depth. FOREACH / ARRAY /
/// SLICE are non-reserved identifiers recognized by lexeme at parse time.
#[derive(Debug, Clone)]
pub struct AstForEachStmt {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    /// Optional trailing label after `END LOOP` (covers the bare label ident).
    pub end_label_span: Option<Span>,
    /// Span covering the FOREACH lexeme.
    pub foreach_span: Span,
    /// TokenId for the FOREACH lexeme.
    pub foreach_token: Option<crate::cst::TokenId>,
    /// The loop target variable.
    pub loop_var_span: Span,
    /// Optional `SLICE` keyword span (PG array-slice iteration).
    pub slice_span: Option<Span>,
    /// Optional slice-depth integer literal span (present iff `slice_span`).
    pub slice_count_span: Option<Span>,
    /// Span covering the IN keyword.
    pub in_span: Span,
    /// TokenId for the IN keyword.
    pub in_token: Option<crate::cst::TokenId>,
    /// Span covering the ARRAY lexeme.
    pub array_span: Span,
    /// TokenId for the ARRAY lexeme.
    pub array_token: Option<crate::cst::TokenId>,
    /// The parsed array expression being iterated.
    pub array_expr: Box<AstExpr>,
    /// Span covering the LOOP body-opener keyword.
    pub body_keyword_span: Span,
    /// TokenId for the LOOP body-opener keyword.
    pub body_keyword_token: Option<crate::cst::TokenId>,
    pub body: Vec<AstStmt>,
    /// Span covering the `END LOOP` keywords.
    pub end_span: Option<Span>,
    /// TokenId for the END keyword.
    pub end_token: Option<crate::cst::TokenId>,
    /// TokenId for the LOOP keyword after END.
    pub end_loop_token: Option<crate::cst::TokenId>,
    /// TokenId for the semicolon after END LOOP.
    pub semicolon_token: Option<crate::cst::TokenId>,
}

/// WHILE loop statement (Snowflake Scripting).
/// Extracted to reduce AstStmt enum size.
#[derive(Debug, Clone)]
pub struct AstWhileStmt {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    /// Optional label before WHILE (e.g., `my_label: WHILE`), covers `my_label:`
    pub label_span: Option<Span>,
    /// Optional label after END WHILE (e.g., `END WHILE my_label`), covers `my_label`
    pub end_label_span: Option<Span>,
    /// Span covering the WHILE keyword
    pub while_span: Span,
    /// TokenId for the WHILE keyword
    pub while_token: Option<crate::cst::TokenId>,
    /// TokenId for opening parenthesis (if present - optional for BigQuery)
    pub lparen_token: Option<crate::cst::TokenId>,
    /// Parsed condition expression
    pub condition: Box<AstExpr>,
    /// Span covering the condition inside parentheses, from the first
    /// token after '(' up to the token before the closing ')'.
    pub condition_span: Span,
    /// TokenId for closing parenthesis (if present - optional for BigQuery)
    pub rparen_token: Option<crate::cst::TokenId>,
    /// Span covering loop-body opener keyword (`DO` or `LOOP`)
    pub body_keyword_span: Span,
    /// TokenId for loop-body opener keyword (`DO` or `LOOP`)
    pub body_keyword_token: Option<crate::cst::TokenId>,
    /// Statements that appear inside the WHILE body.
    pub body: Vec<AstStmt>,
    /// Span covering the END WHILE keywords
    pub end_span: Option<Span>,
    /// TokenId for the END keyword
    pub end_token: Option<crate::cst::TokenId>,
    /// TokenId for the WHILE keyword after END
    pub end_while_token: Option<crate::cst::TokenId>,
    /// TokenId for the semicolon after END WHILE
    pub semicolon_token: Option<crate::cst::TokenId>,
}

/// REPEAT loop statement (Snowflake Scripting).
/// Extracted to reduce AstStmt enum size.
#[derive(Debug, Clone)]
pub struct AstRepeatStmt {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    /// Optional label before REPEAT (e.g., `my_label: REPEAT`), covers `my_label:`
    pub label_span: Option<Span>,
    /// Optional label after END REPEAT (e.g., `END REPEAT my_label`), covers `my_label`
    pub end_label_span: Option<Span>,
    /// Span covering the REPEAT keyword
    pub repeat_span: Span,
    /// TokenId for the REPEAT keyword
    pub repeat_token: Option<crate::cst::TokenId>,
    /// Statements that appear inside the REPEAT body.
    pub body: Vec<AstStmt>,
    /// Span covering the UNTIL keyword
    pub until_span: Span,
    /// TokenId for the UNTIL keyword
    pub until_token: Option<crate::cst::TokenId>,
    /// Span covering the UNTIL condition inside parentheses, including parens
    pub until_condition_span: Span,
    /// Span covering the END REPEAT keywords
    pub end_span: Option<Span>,
    /// TokenId for the END keyword
    pub end_token: Option<crate::cst::TokenId>,
    /// TokenId for the REPEAT keyword after END
    pub end_repeat_token: Option<crate::cst::TokenId>,
    /// TokenId for the semicolon after END REPEAT
    pub semicolon_token: Option<crate::cst::TokenId>,
}

/// LOOP statement (Snowflake Scripting).
/// Extracted to reduce AstStmt enum size.
#[derive(Debug, Clone)]
pub struct AstLoopStmt {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    /// Optional label before LOOP (e.g., `my_label: LOOP`), covers `my_label:`
    pub label_span: Option<Span>,
    /// Optional label after END LOOP (e.g., `END LOOP my_label`), covers `my_label`
    pub end_label_span: Option<Span>,
    /// Span covering the LOOP keyword
    pub loop_span: Span,
    /// TokenId for the LOOP keyword
    pub loop_token: Option<crate::cst::TokenId>,
    /// Statements that appear inside the LOOP body.
    pub body: Vec<AstStmt>,
    /// Span covering the END LOOP keywords
    pub end_span: Option<Span>,
    /// TokenId for the END keyword
    pub end_token: Option<crate::cst::TokenId>,
    /// TokenId for the LOOP keyword after END
    pub end_loop_token: Option<crate::cst::TokenId>,
    /// TokenId for the semicolon after END LOOP
    pub semicolon_token: Option<crate::cst::TokenId>,
}

/// A SQL or Snowflake Scripting statement.
///
/// This enum represents all supported statement types including:
/// - **DML**: SELECT, INSERT, UPDATE, DELETE, MERGE
/// - **DDL**: CREATE TABLE, CREATE FUNCTION, CREATE PROCEDURE, DROP, TRUNCATE  
/// - **Query**: SHOW, DESCRIBE
/// - **Scripting**: Block, If, Case, Loop, While, For, Return, etc.
/// - **Special**: PipeChain for Snowflake's pipe operators
///
/// Each variant contains all the information needed to represent that
/// statement type, including source spans for every syntactic element.
#[derive(Debug, Clone)]
pub enum AstStmt {
    Select(Box<AstSelect>),
    SetSelect(AstSetSelect),
    /// Standalone VALUES query (PostgreSQL)
    /// VALUES (1, 'a'), (2, 'b') [ORDER BY ...] [LIMIT ...] [OFFSET ...]
    ValuesQuery(Box<AstValuesQuery>),
    /// Opaque content that should be emitted verbatim (e.g., set operators in Jinja blocks)
    OpaqueContent {
        node_id: crate::ast::NodeId,
        span: Span,
    },
    /// MSSQL utility batch separator: `GO [count]`
    GoBatchSeparator {
        node_id: crate::ast::NodeId,
        span: Span,
        /// Optional repeat count in `GO <count>`.
        count_span: Option<Span>,
    },
    /// T-SQL `RECONFIGURE [WITH OVERRIDE]` — applies pending
    /// `sp_configure` server option changes to the running configuration.
    Reconfigure {
        node_id: crate::ast::NodeId,
        span: Span,
        /// Span of the `WITH OVERRIDE` clause, when present.
        with_override_span: Option<Span>,
    },
    /// MSSQL EXEC / EXECUTE procedure call
    /// Syntax: `EXEC[UTE] [@return_var =] [schema.]procedure_name [args] | EXEC[UTE] (string_expr)`
    MssqlExec(Box<AstMssqlExec>),
    /// T-SQL `EXECUTE AS { LOGIN | USER } = '<principal>'` — switches
    /// the session's execution context to another principal.
    MssqlExecuteAs(Box<AstMssqlExecuteAs>),
    /// T-SQL `REVERT [WITH COOKIE = @var]` — ends the most recent
    /// `EXECUTE AS` context switch.
    MssqlRevert {
        node_id: crate::ast::NodeId,
        span: Span,
        /// Span of the `WITH COOKIE = @var` clause, when present.
        with_cookie_span: Option<Span>,
    },
    /// T-SQL `{CREATE|ALTER|DROP} { SERVER AUDIT [SPECIFICATION] |
    /// DATABASE AUDIT SPECIFICATION } <name> …` — audit lifecycle.
    MssqlAuditDdl(Box<AstMssqlAuditDdl>),
    /// T-SQL `{CREATE|ALTER|DROP} { MASTER KEY | SYMMETRIC KEY |
    /// ASYMMETRIC KEY | CERTIFICATE | [DATABASE SCOPED] CREDENTIAL }` —
    /// encryption-hierarchy and credential lifecycle.
    MssqlSecurityObjectDdl(Box<AstMssqlSecurityObjectDdl>),
    /// MSSQL TRY...CATCH error handling block
    MssqlTryCatch(Box<AstMssqlTryCatch>),
    /// MSSQL IF...ELSE control flow (no THEN / END IF)
    /// Syntax: IF condition statement [ELSE statement]
    MssqlIf(Box<AstMssqlIf>),
    /// MSSQL WHILE loop (no DO / END WHILE)
    /// Syntax: WHILE condition statement
    MssqlWhile(Box<AstMssqlWhile>),
    /// MSSQL PRINT statement
    /// Syntax: PRINT expression
    MssqlPrint(Box<AstMssqlPrint>),
    /// MSSQL THROW statement
    /// Syntax: THROW (re-throw) or THROW number, 'message', state
    MssqlThrow(Box<AstMssqlThrow>),
    /// MSSQL RAISERROR statement
    /// Syntax: RAISERROR(msg, severity, state [, args...]) [WITH option [, ...]]
    MssqlRaiserror(Box<AstMssqlRaiserror>),
    /// MSSQL SET option ON/OFF statement
    /// Syntax: SET NOCOUNT ON, SET ANSI_NULLS OFF, SET IDENTITY_INSERT table ON, etc.
    MssqlSetOption(Box<AstMssqlSetOption>),
    /// MySQL SET statement family (variable assignment + NAMES / CHARSET /
    /// PASSWORD / ROLE / DEFAULT ROLE / TRANSACTION).
    MysqlSet(Box<AstMysqlSet>),
    /// MSSQL WAITFOR statement — delays execution.
    /// Syntax: WAITFOR DELAY 'time' | WAITFOR TIME 'time'
    MssqlWaitfor(Box<AstMssqlWaitfor>),
    /// MSSQL GOTO statement — unconditional jump to a label.
    /// Syntax: GOTO label_name
    MssqlGoto(Box<AstMssqlGoto>),
    /// MSSQL label declaration — target for GOTO.
    /// Syntax: label_name:
    MssqlLabel(Box<AstMssqlLabel>),
    /// MSSQL CREATE [OR ALTER] TRIGGER statement
    /// Syntax: CREATE [OR ALTER] TRIGGER name ON table [AFTER|INSTEAD OF|FOR] events AS body
    CreateMssqlTrigger(Box<AstCreateMssqlTrigger>),
    /// MSSQL DROP TRIGGER statement
    /// Syntax: DROP TRIGGER [IF EXISTS] name [,...n] [ON {DATABASE|ALL SERVER}]
    DropMssqlTrigger(Box<AstDropMssqlTrigger>),
    /// MSSQL BULK INSERT statement
    /// Syntax: BULK INSERT table FROM 'filepath' [WITH (options)]
    MssqlBulkInsert(Box<AstMssqlBulkInsert>),
    /// MSSQL CREATE EXTERNAL MODEL statement (SQL Server 2025)
    /// Syntax: CREATE EXTERNAL MODEL name [AUTHORIZATION owner] WITH (options)
    MssqlCreateExternalModel(Box<AstMssqlCreateExternalModel>),
    MssqlCreateExternalDataSource(Box<AstMssqlCreateExternalDataSource>),
    /// MSSQL ALTER EXTERNAL DATA SOURCE statement (T-SQL / PolyBase)
    MssqlAlterExternalDataSource(Box<AstMssqlAlterExternalDataSource>),
    CreateForeignServer(Box<AstCreateForeignServer>),
    AlterForeignServer(Box<AstAlterForeignServer>),
    MssqlAlterServerConfiguration(Box<AstMssqlAlterServerConfiguration>),
    CreateUserMapping(Box<AstCreateUserMapping>),
    AlterUserMapping(Box<AstAlterUserMapping>),
    DropUserMapping(Box<AstDropUserMapping>),
    CreateForeignTable(Box<AstCreateForeignTable>),
    /// SQL/MED `IMPORT FOREIGN SCHEMA` (PostgreSQL FDW bulk remote-table import).
    ImportForeignSchema(Box<AstImportForeignSchema>),
    /// MSSQL ALTER EXTERNAL MODEL statement (SQL Server 2025)
    /// Syntax: ALTER EXTERNAL MODEL name SET (options)
    MssqlAlterExternalModel(Box<AstMssqlAlterExternalModel>),
    /// MSSQL DROP EXTERNAL MODEL statement (SQL Server 2025)
    /// Syntax: DROP EXTERNAL MODEL [IF EXISTS] name
    MssqlDropExternalModel(Box<AstMssqlDropExternalModel>),
    /// MSSQL CREATE VECTOR INDEX statement (SQL Server 2025)
    /// Syntax: CREATE VECTOR INDEX name ON table(column) WITH (options) [ON filegroup]
    MssqlCreateVectorIndex(Box<AstMssqlCreateVectorIndex>),
    /// SQL clause fragment (WHERE, JOIN, HAVING) that appears inside Jinja blocks
    /// These are fragments of SELECT statements wrapped for proper AST handling
    ClauseFragment {
        node_id: crate::ast::NodeId,
        fragment: Box<StatementFragment>,
        span: Span,
    },
    CreateTable(Box<AstCreateTable>),
    CreateView(Box<AstCreateView>),
    CreateDynamicTable(Box<AstCreateDynamicTable>),
    CreateTask(Box<AstCreateTask>),
    CreateStage(Box<AstCreateStage>),
    CreateRowAccessPolicy(Box<AstCreateRowAccessPolicy>),
    CreateMaskingPolicy(Box<AstCreateMaskingPolicy>),
    CreateNetworkPolicy(Box<AstCreateNetworkPolicy>),
    CreateSessionPolicy(Box<AstCreateSessionPolicy>),
    CreateAuthenticationPolicy(Box<AstCreateAuthenticationPolicy>),
    CreateApiIntegration(Box<AstCreateApiIntegration>),
    CreateNotificationIntegration(Box<AstCreateNotificationIntegration>),
    CreatePasswordPolicy(Box<AstCreatePasswordPolicy>),
    CreateAggregationPolicy(Box<AstCreateAggregationPolicy>),
    CreateProjectionPolicy(Box<AstCreateProjectionPolicy>),
    CreateStorageIntegration(Box<AstCreateStorageIntegration>),
    AlterRowAccessPolicy(Box<AstAlterRowAccessPolicy>),
    AlterMaskingPolicy(Box<AstAlterMaskingPolicy>),
    AlterNetworkPolicy(Box<AstAlterNetworkPolicy>),
    AlterSessionPolicy(Box<AstAlterSessionPolicy>),
    /// `ALTER SESSION { SET | UNSET }` — session-scoped parameter mutation
    /// (Snowflake). Distinct from [`AstAlterSessionPolicy`], which alters a
    /// named policy object.
    AlterSession(Box<AstAlterSession>),
    AlterAuthenticationPolicy(Box<AstAlterAuthenticationPolicy>),
    /// `ALTER USER … { SET | UNSET } AUTHENTICATION POLICY` — narrow typed
    /// parser scoped to the AUTHPOL-attachment slice. Other ALTER USER
    /// actions continue to route to [`AstAlterPrincipal`].
    AlterUser(Box<AstAlterUser>),
    /// `ALTER ACCOUNT { SET | UNSET } AUTHENTICATION POLICY` — narrow typed
    /// parser scoped to the AUTHPOL-attachment slice. Other ALTER ACCOUNT
    /// actions fall through to the generic statement path.
    AlterAccount(Box<AstAlterAccount>),
    AlterApiIntegration(Box<AstAlterApiIntegration>),
    AlterNotificationIntegration(Box<AstAlterNotificationIntegration>),
    /// `CREATE [OR REPLACE] SHARE [IF NOT EXISTS] <name> [COMMENT = '<text>']`
    CreateShare(Box<AstCreateShare>),
    /// `ALTER SHARE [IF EXISTS] <name> { ADD | REMOVE | SET } ACCOUNTS = …`
    AlterShare(Box<AstAlterShare>),
    /// `CREATE [OR REPLACE] DATASHARE [IF NOT EXISTS] <name>` (Redshift cross-account data sharing)
    CreateDatashare(Box<AstCreateDatashare>),
    /// `ALTER DATASHARE <name> { ADD | REMOVE } { TABLE | SCHEMA } … | SET { PUBLICACCESSIBLE | INCLUDENEW } …`
    AlterDatashare(Box<AstAlterDatashare>),
    /// `CREATE [OR REPLACE] SECURITY INTEGRATION [IF NOT EXISTS] <name> TYPE = … …`
    CreateSecurityIntegration(Box<AstCreateSecurityIntegration>),
    /// `ALTER SECURITY INTEGRATION [IF EXISTS] <name> { SET | UNSET | RENAME TO } …`
    AlterSecurityIntegration(Box<AstAlterSecurityIntegration>),
    /// `ALTER REPLICATION GROUP [IF EXISTS] <name> { SET | UNSET | ADD … | REMOVE … } …`
    AlterReplicationGroup(Box<AstAlterReplicationGroup>),
    /// `ALTER FAILOVER GROUP [IF EXISTS] <name> { SET | UNSET | ADD … | REMOVE … } …`
    AlterFailoverGroup(Box<AstAlterFailoverGroup>),
    AlterPasswordPolicy(Box<AstAlterPasswordPolicy>),
    AlterAggregationPolicy(Box<AstAlterAggregationPolicy>),
    AlterProjectionPolicy(Box<AstAlterProjectionPolicy>),
    AlterStorageIntegration(Box<AstAlterStorageIntegration>),
    AlterTable(Box<AstAlterTable>),
    AlterView(Box<AstAlterView>),
    AlterMaterializedView(Box<AstAlterMaterializedView>),
    AlterDynamicTable(Box<AstAlterDynamicTable>),
    AlterFunction(Box<AstAlterFunction>),
    AlterProcedure(Box<AstAlterProcedure>),
    AlterStage(Box<AstAlterStage>),
    AlterTask(Box<AstAlterTask>),
    Show(Box<AstShow>),
    Describe(AstDescribe),
    Use(AstUse),
    Truncate(AstTruncate),
    Drop(AstDrop),
    DropRowAccessPolicy(Box<AstDropRowAccessPolicy>),
    DropAllRowAccessPolicies(Box<AstDropAllRowAccessPolicies>),
    DropMaskingPolicy(Box<AstDropMaskingPolicy>),
    DropNetworkPolicy(Box<AstDropNetworkPolicy>),
    DropSessionPolicy(Box<AstDropSessionPolicy>),
    DropAuthenticationPolicy(Box<AstDropAuthenticationPolicy>),
    DropApiIntegration(Box<AstDropApiIntegration>),
    DropNotificationIntegration(Box<AstDropNotificationIntegration>),
    DropPasswordPolicy(Box<AstDropPasswordPolicy>),
    DropAggregationPolicy(Box<AstDropAggregationPolicy>),
    DropProjectionPolicy(Box<AstDropProjectionPolicy>),
    DropStorageIntegration(Box<AstDropStorageIntegration>),
    DropTask(Box<AstDropTask>),
    // Warehouse statements
    CreateWarehouse(Box<AstCreateWarehouse>),
    AlterWarehouse(Box<AstAlterWarehouse>),
    DropWarehouse(Box<AstDropWarehouse>),
    // Pipe statements
    CreatePipe(Box<AstCreatePipe>),
    AlterPipe(Box<AstAlterPipe>),
    DropPipe(Box<AstDropPipe>),
    // Tag statements (Snowflake object tagging; DROP TAG routes through generic `Drop`)
    CreateTag(Box<AstCreateTag>),
    AlterTag(Box<AstAlterTag>),
    UndropTag(Box<AstUndropTag>),
    CreateFileFormat(Box<AstCreateFileFormat>),
    AlterFileFormat(Box<AstAlterFileFormat>),
    // Secret statements (Snowflake; DROP SECRET routes through generic `Drop`)
    CreateSecret(Box<AstCreateSecret>),
    AlterSecret(Box<AstAlterSecret>),
    // Network-rule statements (Snowflake; DROP NETWORK RULE routes through generic `Drop`)
    CreateNetworkRule(Box<AstCreateNetworkRule>),
    AlterNetworkRule(Box<AstAlterNetworkRule>),
    // Resource-monitor statements (Snowflake; DROP RESOURCE MONITOR routes through generic `Drop`)
    CreateResourceMonitor(Box<AstCreateResourceMonitor>),
    AlterResourceMonitor(Box<AstAlterResourceMonitor>),
    CreateComputePool(Box<AstCreateComputePool>),
    AlterComputePool(Box<AstAlterComputePool>),
    CreateGitRepository(Box<AstCreateGitRepository>),
    AlterGitRepository(Box<AstAlterGitRepository>),
    // Image-repository statements (Snowflake SPCS; DROP IMAGE REPOSITORY routes through generic `Drop`)
    CreateImageRepository(Box<AstCreateImageRepository>),
    AlterImageRepository(Box<AstAlterImageRepository>),
    // Streamlit statements (Snowflake; DROP STREAMLIT routes through generic `Drop`)
    CreateStreamlit(Box<AstCreateStreamlit>),
    AlterStreamlit(Box<AstAlterStreamlit>),
    // Service statements (Snowflake SPCS; DROP SERVICE routes through generic `Drop`)
    CreateService(Box<AstCreateService>),
    AlterService(Box<AstAlterService>),
    // Notebook statements (Snowflake; DROP NOTEBOOK routes through generic `Drop`)
    CreateNotebook(Box<AstCreateNotebook>),
    AlterNotebook(Box<AstAlterNotebook>),
    // Semantic view statements (Snowflake; DROP SEMANTIC VIEW routes through generic `Drop`)
    CreateSemanticView(Box<AstCreateSemanticView>),
    AlterSemanticView(Box<AstAlterSemanticView>),
    // Cortex search service statements (Snowflake; DROP routes through generic `Drop`)
    CreateCortexSearchService(Box<AstCreateCortexSearchService>),
    AlterCortexSearchService(Box<AstAlterCortexSearchService>),
    // Native Apps: APPLICATION (DROP via generic `Drop`) + APPLICATION PACKAGE (two-word DROP)
    CreateApplication(Box<AstCreateApplication>),
    AlterApplication(Box<AstAlterApplication>),
    CreateApplicationPackage(Box<AstCreateApplicationPackage>),
    AlterApplicationPackage(Box<AstAlterApplicationPackage>),
    // Listing statements (Snowflake Marketplace; DROP LISTING via generic `Drop`)
    CreateListing(Box<AstCreateListing>),
    AlterListing(Box<AstAlterListing>),
    // Account provisioning (Snowflake; DROP via generic `Drop`, two-word for MANAGED ACCOUNT)
    CreateManagedAccount(Box<AstCreateManagedAccount>),
    CreateAccount(Box<AstCreateAccount>),
    // Client file-transfer commands (Snowflake PUT/GET/REMOVE/LIST — top-level, not CREATE)
    StageFileCommand(Box<AstStageFileCommand>),
    // Alert statements (Snowflake; DROP ALERT routes through generic `Drop`)
    CreateAlert(Box<AstCreateAlert>),
    AlterAlert(Box<AstAlterAlert>),
    // Join-policy statements (Snowflake; ninth policy kind)
    CreateJoinPolicy(Box<AstCreateJoinPolicy>),
    AlterJoinPolicy(Box<AstAlterJoinPolicy>),
    DropJoinPolicy(Box<AstDropJoinPolicy>),
    // Data metric function (Snowflake; DROP routes through generic `Drop`)
    CreateDataMetricFunction(Box<AstCreateDataMetricFunction>),
    // Replication / failover group (Snowflake; DROP routes through generic `Drop`)
    CreateReplicationFailoverGroup(Box<AstCreateReplicationFailoverGroup>),
    // External Access Integration statements
    CreateExternalAccessIntegration(Box<AstCreateExternalAccessIntegration>),
    AlterExternalAccessIntegration(Box<AstAlterExternalAccessIntegration>),
    DropExternalAccessIntegration(Box<AstDropExternalAccessIntegration>),
    // Stream statements
    CreateStream(Box<AstCreateStream>),
    AlterStream(Box<AstAlterStream>),
    DropStream(Box<AstDropStream>),
    // Database and Schema statements
    CreateDatabase(Box<AstCreateDatabase>),
    AlterDatabase(Box<AstAlterDatabase>),
    DropDatabase(Box<AstDropDatabase>),
    UndropDatabase(Box<AstUndropDatabase>),
    CreateSchema(Box<AstCreateSchema>),
    AlterSchema(Box<AstAlterSchema>),
    DropSchema(Box<AstDropSchema>),
    UndropSchema(Box<AstUndropSchema>),
    UndropTable(Box<AstUndropTable>),
    UndropType(Box<AstUndropType>),
    Insert(Box<AstInsert>),
    /// MySQL REPLACE INTO — row-level delete-then-insert by unique key.
    /// Distinct from Insert so consumers can treat the destructive
    /// overwrite semantics separately.
    ReplaceInto(Box<AstReplaceInto>),
    MultiInsert(Box<AstMultiInsert>),
    Update(Box<AstUpdate>),
    Delete(Box<AstDelete>),
    Merge(Box<AstMerge>),
    /// EXPLAIN statement (PostgreSQL)
    /// Wraps an inner statement (SELECT, INSERT, UPDATE, DELETE) with optional analysis options.
    Explain(Box<AstExplain>),
    /// CREATE INDEX statement (PostgreSQL)
    CreateIndex(Box<AstCreateIndex>),
    /// CREATE SYNONYM statement (T-SQL): `CREATE SYNONYM name FOR object`
    CreateSynonym(Box<AstCreateSynonym>),
    /// COMMENT ON statement (PostgreSQL)
    CommentOn(Box<AstCommentOn>),
    /// DO $$ anonymous block (PostgreSQL)
    DoBlock(Box<AstDoBlock>),
    /// VACUUM statement (PostgreSQL)
    Vacuum(Box<AstVacuum>),
    /// ANALYZE (utility) statement (PostgreSQL)
    AnalyzeStmt(Box<AstAnalyzeStmt>),
    /// CREATE TYPE statement (PostgreSQL)
    CreateType(Box<AstCreateType>),
    /// ALTER TYPE statement (PostgreSQL)
    AlterType(Box<AstAlterType>),
    /// CREATE EXTENSION statement (PostgreSQL)
    CreateExtension(Box<AstCreateExtension>),
    /// CREATE SEQUENCE statement (PostgreSQL)
    CreateSequence(Box<AstCreateSequence>),
    /// ALTER SEQUENCE statement (PostgreSQL)
    AlterSequence(Box<AstAlterSequence>),
    /// CREATE TRIGGER statement (PostgreSQL)
    CreatePgTrigger(Box<AstCreatePgTrigger>),
    /// ALTER TRIGGER statement (PostgreSQL)
    AlterPgTrigger(Box<AstAlterPgTrigger>),
    /// DROP TRIGGER statement (PostgreSQL)
    DropPgTrigger(Box<AstDropPgTrigger>),
    /// CREATE DOMAIN statement (PostgreSQL)
    CreateDomain(Box<AstCreateDomain>),
    /// ALTER DOMAIN statement (PostgreSQL)
    AlterDomain(Box<AstAlterDomain>),
    /// DROP DOMAIN statement (PostgreSQL)
    DropDomain(Box<AstDropDomain>),
    /// CREATE POLICY statement (PostgreSQL RLS)
    CreatePgPolicy(Box<AstCreatePgPolicy>),
    /// ALTER POLICY statement (PostgreSQL RLS)
    AlterPgPolicy(Box<AstAlterPgPolicy>),
    /// DROP POLICY statement (PostgreSQL RLS)
    DropPgPolicy(Box<AstDropPgPolicy>),
    /// ALTER INDEX statement (PostgreSQL)
    AlterIndex(Box<AstAlterIndex>),
    /// REINDEX statement (PostgreSQL)
    Reindex(Box<AstReindex>),
    /// PREPARE statement (PostgreSQL prepared statements)
    PgPrepare(Box<AstPgPrepare>),
    /// EXECUTE prepared statement (PostgreSQL)
    PgExecute(Box<AstPgExecute>),
    /// DEALLOCATE prepared statement (PostgreSQL)
    PgDeallocate(Box<AstPgDeallocate>),
    /// COPY statement (PostgreSQL)
    PgCopy(Box<AstPgCopy>),
    /// REFRESH MATERIALIZED VIEW (PostgreSQL)
    PgRefreshMatview(Box<AstPgRefreshMatview>),
    /// LISTEN channel (PostgreSQL pub/sub)
    PgListen(Box<AstPgSimpleUtility>),
    /// NOTIFY channel [, 'payload'] (PostgreSQL pub/sub)
    PgNotify(Box<AstPgSimpleUtility>),
    /// UNLISTEN channel | * (PostgreSQL pub/sub)
    PgUnlisten(Box<AstPgSimpleUtility>),
    /// LOCK TABLE ... (PostgreSQL explicit locking)
    PgLockTable(Box<AstPgSimpleUtility>),
    /// CREATE [OR REPLACE] RULE ... (PostgreSQL rewrite rules)
    PgCreateRule(Box<AstPgSimpleUtility>),
    /// CREATE AGGREGATE (PostgreSQL extension authoring)
    PgCreateAggregate(Box<AstPgSimpleUtility>),
    /// CREATE OPERATOR (PostgreSQL extension authoring)
    PgCreateOperator(Box<AstPgSimpleUtility>),
    /// ALTER SYSTEM SET/RESET (PostgreSQL runtime config)
    PgAlterSystem(Box<AstPgSimpleUtility>),
    /// ALTER TABLESPACE (PostgreSQL storage management)
    PgAlterTablespace(Box<AstPgSimpleUtility>),
    /// DROP OWNED BY ... (PostgreSQL role management)
    PgDropOwned(Box<AstPgSimpleUtility>),
    /// REASSIGN OWNED BY ... TO ... (PostgreSQL role management)
    PgReassignOwned(Box<AstPgSimpleUtility>),
    /// DISCARD ALL|PLANS|SEQUENCES|TEMP (PostgreSQL maintenance)
    PgDiscard(Box<AstPgSimpleUtility>),
    /// CLUSTER [table [USING index]] (PostgreSQL maintenance)
    PgCluster(Box<AstPgSimpleUtility>),
    /// CREATE/ALTER/DROP PUBLICATION (PostgreSQL logical replication)
    PgPublication(Box<AstPgSimpleUtility>),
    /// CREATE/ALTER/DROP SUBSCRIPTION (PostgreSQL logical replication)
    PgSubscription(Box<AstPgSimpleUtility>),
    /// `CREATE { USER | ROLE | LOGIN }` — dialect-neutral principal
    /// creation. User / Role / Login are distinct objects; the
    /// [`PrincipalKind`] discriminator inside carries the distinction
    /// instead of leaking dialect into the variant name.
    CreatePrincipal(Box<AstCreatePrincipal>),
    /// `ALTER { USER | ROLE | LOGIN }` — dialect-neutral principal
    /// mutation. Excludes the narrow Snowflake AUTHENTICATION POLICY
    /// attachment slice, which lives on [`AstAlterUser`].
    AlterPrincipal(Box<AstAlterPrincipal>),
    /// `DROP { USER | ROLE | LOGIN }` — dialect-neutral.
    DropPrincipal(Box<AstDropPrincipal>),
    /// DROP EXTENSION [IF EXISTS] name [CASCADE | RESTRICT] (PostgreSQL)
    PgDropExtension(Box<AstPgDropExtension>),
    /// DROP VIEW [IF EXISTS] name [CASCADE | RESTRICT] (PostgreSQL)

    /// ALTER RULE (PostgreSQL)
    PgAlterRule(Box<AstPgSimpleUtility>),
    /// DROP RULE [IF EXISTS] name ON table [CASCADE | RESTRICT] (PostgreSQL)
    PgDropRule(Box<AstPgDropRule>),
    /// ALTER TABLE ... ENABLE/DISABLE TRIGGER (PostgreSQL)
    PgAlterTableTriggerState(Box<AstPgAlterTableTriggerState>),
    /// SET role / SET search_path / SET SESSION AUTHORIZATION / RESET (PostgreSQL)
    PgSet(Box<AstPgSet>),
    /// DROP SEQUENCE [IF EXISTS] name [, ...] [CASCADE | RESTRICT] (PostgreSQL)
    PgDropSequence(Box<AstPgDropSequence>),
    /// DROP TYPE [IF EXISTS] name [, ...] [CASCADE | RESTRICT] (PostgreSQL)
    PgDropType(Box<AstPgDropType>),
    /// `DROP INDEX [CONCURRENTLY] [IF EXISTS] name [CASCADE | RESTRICT]` (PostgreSQL)
    PgDropIndex(Box<AstPgDropIndex>),
    /// CREATE TABLESPACE name LOCATION '/path' (PostgreSQL)
    PgCreateTablespace(Box<AstPgSimpleUtility>),
    /// DROP TABLESPACE [IF EXISTS] name (PostgreSQL)
    PgDropTablespace(Box<AstPgSimpleUtility>),
    /// EXPORT DATA [WITH CONNECTION conn] OPTIONS(...) AS query (BigQuery)
    BqExportData(Box<AstBqExportData>),
    /// LOAD DATA INTO/OVERWRITE table ... FROM FILES(...) (BigQuery)
    BqLoadData(Box<AstBqLoadData>),
    MysqlLoadData(Box<AstMysqlLoadData>),
    /// MySQL `RENAME TABLE a TO b [, c TO d, ...]` — atomic multi-table rename.
    MysqlRenameTable(Box<AstMysqlRenameTable>),
    /// MySQL `CREATE EVENT` — a scheduled SQL job (the `DO` body runs on a
    /// schedule). Body-bearing: the body is sub-parsed so its inner SQL is
    /// visible as statements.
    CreateEvent(Box<AstCreateEvent>),
    /// MySQL `ALTER EVENT` — reschedule, enable/disable, rename, or rebind the
    /// scheduled `DO` body.
    AlterEvent(Box<AstAlterEvent>),
    /// MySQL `CREATE TRIGGER` — runs an inline body automatically on a row
    /// event, under the definer's privileges. Body-bearing: the body is
    /// sub-parsed so its inner SQL is visible as statements.
    CreateMysqlTrigger(Box<AstCreateMysqlTrigger>),
    /// ASSERT expression [AS description] (BigQuery)
    BqAssert(Box<AstBqAssert>),
    /// CREATE SNAPSHOT TABLE name CLONE source FOR SYSTEM_TIME AS OF ... (BigQuery)
    /// CREATE SNAPSHOT TABLE name CLONE source FOR SYSTEM_TIME AS OF ... (BigQuery)
    BqCreateSnapshotTable(Box<AstBqCreateSnapshotTable>),
    /// DROP SNAPSHOT TABLE [IF EXISTS] name (BigQuery)
    BqDropSnapshotTable(Box<AstBqSimpleUtility>),
    /// CREATE SEARCH INDEX [IF NOT EXISTS] name ON table(...) [OPTIONS(...)] (BigQuery)
    BqCreateSearchIndex(Box<AstBqCreateSearchIndex>),
    /// DROP SEARCH INDEX [IF EXISTS] name ON table (BigQuery)
    BqDropSearchIndex(Box<AstBqDropSearchIndex>),
    /// CREATE [OR REPLACE] VECTOR INDEX [IF NOT EXISTS] name ON table(...) ... (BigQuery)
    BqCreateVectorIndex(Box<AstBqCreateVectorIndex>),
    /// DROP VECTOR INDEX [IF EXISTS] name ON table (BigQuery)
    BqDropVectorIndex(Box<AstBqDropVectorIndex>),
    /// ALTER VECTOR INDEX [IF EXISTS] name REBUILD (BigQuery)
    BqAlterVectorIndex(Box<AstBqSimpleUtility>),
    /// CREATE [OR REPLACE] MODEL [IF NOT EXISTS] name ... (BigQuery BQML)
    BqCreateModel(Box<AstBqCreateModel>),
    /// ALTER MODEL [IF EXISTS] name SET OPTIONS(...) (BigQuery BQML)
    BqAlterModel(Box<AstBqAlterModel>),
    /// EXPORT MODEL name OPTIONS(...) (BigQuery BQML)
    BqExportModel(Box<AstBqExportModel>),
    /// DROP MODEL [IF EXISTS] name (BigQuery BQML)
    BqDropModel(Box<AstBqDropModel>),
    /// `OPTIMIZE table_name [FULL] [WHERE predicate] [ZORDER BY (col1, ...)]` (Databricks)
    Optimize(Box<AstOptimize>),
    /// DESCRIBE HISTORY table_name (Databricks / Delta Lake)
    DescribeHistory(Box<AstDescribeHistory>),
    /// `RESTORE [TABLE] table_name [TO] {TIMESTAMP AS OF expr | VERSION AS OF int}` (Databricks / Delta Lake)
    Restore(Box<AstRestore>),
    /// BACKUP { DATABASE | LOG } name TO { DISK | URL | TAPE } = '...' [WITH ...] (T-SQL)
    MssqlBackup(Box<AstMssqlBackup>),
    /// RESTORE { DATABASE | LOG } name FROM { DISK | URL | TAPE } = '...' [WITH ...] (T-SQL)
    MssqlRestore(Box<AstMssqlRestore>),
    /// `DBCC <command> [ ( args ) ] [WITH options]` (T-SQL maintenance / admin utility)
    MssqlDbcc(Box<AstMssqlDbcc>),
    /// OPEN/CLOSE { MASTER KEY | SYMMETRIC KEY | ALL SYMMETRIC KEYS } (T-SQL encryption key activation)
    MssqlKeyManagement(Box<AstMssqlKeyManagement>),
    /// CREATE/ALTER SECURITY POLICY … (T-SQL Row-Level Security)
    MssqlSecurityPolicy(Box<AstMssqlSecurityPolicy>),
    /// BACKUP/RESTORE { SERVICE MASTER KEY | MASTER KEY | CERTIFICATE | ASYMMETRIC KEY } (T-SQL key-material protection)
    MssqlKeyBackup(Box<AstMssqlKeyBackup>),
    /// CREATE/ALTER ASSEMBLY … WITH PERMISSION_SET = … (T-SQL CLR assembly)
    MssqlAssembly(Box<AstMssqlAssembly>),
    /// `ADD [COUNTER] SIGNATURE TO module BY { CERTIFICATE | ASYMMETRIC KEY }` (T-SQL module signing)
    MssqlAddSignature(Box<AstMssqlAddSignature>),
    /// SETUSER ['username'] (T-SQL legacy database-context impersonation)
    MssqlSetuser(Box<AstMssqlSetuser>),
    /// `ALTER SERVICE MASTER KEY { [FORCE] REGENERATE | WITH … }` (T-SQL encryption-root rotation)
    MssqlAlterServiceMasterKey(Box<AstMssqlAlterServiceMasterKey>),
    /// ALTER DEFAULT PRIVILEGES [FOR ROLE …] [IN SCHEMA …] { GRANT | REVOKE } … (PostgreSQL default-grant policy)
    PgAlterDefaultPrivileges(Box<AstPgAlterDefaultPrivileges>),
    /// `CACHE [LAZY] TABLE table_name [OPTIONS (...)] [[AS] query]` (Databricks / Spark)
    CacheTable(Box<AstCacheTable>),
    /// UNCACHE TABLE [IF EXISTS] table_name (Databricks / Spark)
    UncacheTable(Box<AstUncacheTable>),
    /// `[MSCK] REPAIR TABLE table_identifier [{ADD|DROP|SYNC} PARTITIONS]` (Databricks / Spark)
    RepairTable(Box<AstRepairTable>),
    /// `CREATE [FOREIGN] CATALOG [IF NOT EXISTS] catalog_name [...]` (Databricks Unity Catalog)
    CreateCatalog(Box<AstCreateCatalog>),
    /// `ALTER CATALOG [catalog_name] { ... }` (Databricks Unity Catalog)
    AlterCatalog(Box<AstAlterCatalog>),
    /// DROP CATALOG [IF EXISTS] catalog_name [RESTRICT|CASCADE] (Databricks Unity Catalog)
    DropCatalog(Box<AstDropCatalog>),
    /// `CREATE [EXTERNAL] VOLUME [IF NOT EXISTS] volume_name [...]` (Databricks Unity Catalog)
    CreateVolume(Box<AstCreateVolume>),
    /// ALTER VOLUME volume_name { action } (Databricks Unity Catalog)
    AlterVolume(Box<AstAlterVolume>),
    /// DROP VOLUME [IF EXISTS] volume_name (Databricks Unity Catalog)
    DropVolume(Box<AstDropVolume>),
    /// CREATE EXTERNAL LOCATION [IF NOT EXISTS] name URL '...' WITH (STORAGE CREDENTIAL cred) [COMMENT '...']
    CreateExternalLocation(Box<AstCreateExternalLocation>),
    /// `ALTER EXTERNAL LOCATION name { RENAME TO | SET URL | SET STORAGE CREDENTIAL | [SET] OWNER TO }`
    AlterExternalLocation(Box<AstAlterExternalLocation>),
    /// DROP EXTERNAL LOCATION [IF EXISTS] name
    DropExternalLocation(Box<AstDropExternalLocation>),
    /// CREATE [STORAGE | SERVICE] CREDENTIAL [IF NOT EXISTS] name [COMMENT '...']
    CreateStorageCredential(Box<AstCreateStorageCredential>),
    /// `ALTER [STORAGE | SERVICE] CREDENTIAL name { RENAME TO | [SET] OWNER TO }`
    AlterStorageCredential(Box<AstAlterStorageCredential>),
    /// DROP [STORAGE | SERVICE] CREDENTIAL [IF EXISTS] name
    DropStorageCredential(Box<AstDropStorageCredential>),
    /// CREATE CONNECTION [IF NOT EXISTS] name TYPE type OPTIONS (...) [COMMENT '...']
    CreateConnection(Box<AstCreateConnection>),
    /// `ALTER CONNECTION name { [SET] OWNER TO principal | RENAME TO new_name | OPTIONS (...) }`
    AlterConnection(Box<AstAlterConnection>),
    /// DROP CONNECTION [IF EXISTS] name
    DropConnection(Box<AstDropConnection>),
    /// CREATE FLOW flow_name AS {AUTO CDC INTO | APPLY CHANGES INTO} ... (Databricks pipelines)
    CreateFlow(Box<AstCreateFlow>),
    /// CREATE [OR REPLACE] EXTERNAL TABLE (BigQuery / Snowflake)
    CreateExternalTable(Box<AstCreateExternalTable>),
    /// CREATE EXTERNAL SCHEMA … FROM { DATA CATALOG | HIVE METASTORE | … } (Redshift Spectrum)
    CreateExternalSchema(Box<AstCreateExternalSchema>),
    /// SET session variable statement.
    /// Snowflake syntax:
    /// - Single: SET variable_name = value
    /// - Multiple: SET (var1, var2) = (val1, val2)
    /// - From SELECT: SET variable_name = (SELECT ...)
    SetVariable {
        node_id: crate::ast::NodeId,
        span: Span,
        /// Span covering the SET keyword
        set_span: Span,
        /// Variable names being assigned (one for single, multiple for tuple form)
        variable_names: Vec<AstIdentifier>,
        /// Whether this uses tuple syntax: SET (a, b) = (...)
        is_tuple_form: bool,
        /// The value expression(s) on the right-hand side
        /// For single form: one expression
        /// For tuple form: list of expressions (may be wrapped in parens)
        /// For SELECT form: a scalar subquery expression
        values: Vec<AstExpr>,
    },
    /// Flow pipe chain: stmt1 ->> stmt2 ->> ... ->> stmtN
    PipeChain {
        node_id: crate::ast::NodeId,
        span: Span,
        stmts: Vec<AstStmt>,
    },
    Block(Box<AstBlockStmt>),
    /// Simple assignment statement inside a Snowflake Scripting block,
    /// e.g. `x := expr;`. This is a shallow, span-oriented node that
    /// records the assigned variable name span and the right-hand side
    /// expression span, along with the full statement span.
    Assign {
        node_id: crate::ast::NodeId,
        /// Optional semicolon token
        semicolon_token: Option<crate::cst::TokenId>,
        /// Span covering the entire assignment statement, typically from
        /// the start of the variable name through the terminating
        /// semicolon (if present).
        span: Span,
        /// Span covering the variable name on the left-hand side.
        name_span: Span,
        /// Span covering the assignment operator (`:=` or `=`) when captured.
        assign_op_span: Option<Span>,
        /// Parsed right-hand side expression
        expr: Box<AstExpr>,
        /// Span covering the right-hand side expression, from the first
        /// token after `:=` through the last expression token before the
        /// semicolon or block terminator.
        expr_span: Span,
    },
    If(Box<AstIfStmt>),
    CaseStmt(Box<AstCaseStmt>),
    Declare {
        node_id: crate::ast::NodeId,
        span: Span,
        /// Optional semicolon token
        semicolon_token: Option<crate::cst::TokenId>,
        /// Span covering the DECLARE keyword (for standalone DECLARE, not in block header)
        declare_span: Option<Span>,
        /// TokenId for the DECLARE keyword
        declare_token: Option<crate::cst::TokenId>,
        name: AstIdentifier,
        /// Span covering the declared type, if present.
        type_span: Option<Span>,
        /// Span covering the DEFAULT keyword or := operator, if present
        default_op_span: Option<Span>,
        /// TokenId for the DEFAULT keyword or := operator
        default_op_token: Option<crate::cst::TokenId>,
        /// Parsed default expression, if present
        default_expr: Option<Box<AstExpr>>,
        /// Span covering the DEFAULT expression, if present.
        default_expr_span: Option<Span>,
    },
    /// Table variable declaration: DECLARE @t TABLE(col INT, name VARCHAR(50))
    DeclareTable {
        node_id: crate::ast::NodeId,
        span: Span,
        /// Optional semicolon token
        semicolon_token: Option<crate::cst::TokenId>,
        /// Span covering the DECLARE keyword (if present; absent for bare declarations)
        declare_span: Option<Span>,
        /// TokenId for the DECLARE keyword
        declare_token: Option<crate::cst::TokenId>,
        /// The variable name (e.g. @t)
        name: AstIdentifier,
        /// Span covering TABLE keyword
        table_keyword_span: Span,
        /// Span covering the column definitions including parentheses: TABLE(...)
        table_body_span: Span,
    },
    /// Cursor declaration: DECLARE cursor_name CURSOR FOR query_or_resultset;
    DeclareCursor {
        node_id: crate::ast::NodeId,
        span: Span,
        /// Optional semicolon token
        semicolon_token: Option<crate::cst::TokenId>,
        /// Span covering the DECLARE keyword
        declare_span: Span,
        /// TokenId for the DECLARE keyword
        declare_token: Option<crate::cst::TokenId>,
        cursor_name: AstIdentifier,
        /// TokenId for the CURSOR keyword
        cursor_token: Option<crate::cst::TokenId>,
        /// TokenId for the FOR keyword
        for_token: Option<crate::cst::TokenId>,
        /// Parsed SELECT statement or other query
        query: Box<AstStmt>,
        /// Span covering everything after "CURSOR FOR" (the query or RESULTSET reference)
        query_span: Span,
        /// Optional cursor sensitivity clause span (FOR READ ONLY / FOR UPDATE)
        cursor_sensitivity_span: Option<Span>,
    },
    Let {
        node_id: crate::ast::NodeId,
        span: Span,
        /// Optional semicolon token
        semicolon_token: Option<crate::cst::TokenId>,
        /// Span covering the LET keyword
        let_span: Span,
        /// TokenId for the LET keyword
        let_token: Option<crate::cst::TokenId>,
        name: AstIdentifier,
        /// Span covering the declared type, if present.
        type_span: Option<Span>,
        /// Span covering assignment operator token (`:=`, `=`, or `DEFAULT`) if present.
        assign_op_span: Option<Span>,
        expr: Box<AstExpr>,
    },
    /// Cursor assignment: LET cursor_name CURSOR FOR query_or_resultset;
    LetCursor {
        node_id: crate::ast::NodeId,
        span: Span,
        /// Optional semicolon token
        semicolon_token: Option<crate::cst::TokenId>,
        /// Span covering the LET keyword
        let_span: Span,
        /// TokenId for the LET keyword
        let_token: Option<crate::cst::TokenId>,
        cursor_name: AstIdentifier,
        /// TokenId for the CURSOR keyword
        cursor_token: Option<crate::cst::TokenId>,
        /// TokenId for the FOR keyword
        for_token: Option<crate::cst::TokenId>,
        /// Span covering everything after "CURSOR FOR" (the query or RESULTSET reference)
        query_span: Span,
        /// Optional parsed SQL statement for the cursor query (best-effort)
        parsed_query: Option<Box<AstStmt>>,
    },
    Return {
        node_id: crate::ast::NodeId,
        span: Span,
        /// Optional semicolon token
        semicolon_token: Option<crate::cst::TokenId>,
        /// Span covering the RETURN keyword
        return_span: Span,
        /// TokenId for the RETURN keyword
        return_token: Option<crate::cst::TokenId>,
        /// Optional expression to return (Snowflake requires, BigQuery allows bare RETURN;)
        expr: Option<Box<AstExpr>>,
    },
    Raise {
        node_id: crate::ast::NodeId,
        span: Span,
        /// Optional semicolon token
        semicolon_token: Option<crate::cst::TokenId>,
        /// Span covering the RAISE keyword
        raise_span: Span,
        /// TokenId for the RAISE keyword
        raise_token: Option<crate::cst::TokenId>,
        /// Optional exception name to raise (Snowflake). If None, re-raises current exception.
        exception_name: Option<Span>,
        /// Optional PostgreSQL severity level keyword (DEBUG/LOG/INFO/
        /// NOTICE/WARNING/EXCEPTION) directly after RAISE. `None` for the
        /// Snowflake/BigQuery grammar and for a bare `RAISE;` re-raise.
        level_span: Option<Span>,
        /// Optional PostgreSQL message payload after the level — the
        /// `'format'` string and its comma-separated argument expressions
        /// (or a `condition_name` / `SQLSTATE 'x'`). Captured verbatim as a
        /// span for byte-exact formatting; `None` for non-PG forms.
        message_span: Option<Span>,
        /// Optional USING clause span (BigQuery: USING MESSAGE = expr;
        /// PostgreSQL: USING option = expr [, …]).
        using_span: Option<Span>,
        /// Optional message expression (BigQuery: USING MESSAGE = expr)
        message_expr: Option<Box<AstExpr>>,
    },
    /// Databricks SIGNAL statement: SIGNAL condition_name / SQLSTATE 'value'
    /// SET MESSAGE_TEXT = '...', MESSAGE_ARGUMENTS = (...)
    Signal {
        node_id: crate::ast::NodeId,
        span: Span,
        /// Span covering just the SIGNAL keyword
        signal_span: Span,
        /// Span covering the condition specification
        /// (condition_name or SQLSTATE VALUE 'nnnnn')
        condition_spec_span: Option<Span>,
        /// Optional SET clause span (SET MESSAGE_TEXT = ..., etc.)
        set_clause_span: Option<Span>,
        /// TokenId for the terminating semicolon (if present)
        semicolon_token: Option<crate::cst::TokenId>,
    },
    /// Databricks RESIGNAL statement: re-raises the current condition
    Resignal {
        node_id: crate::ast::NodeId,
        span: Span,
        /// Span covering just the RESIGNAL keyword
        resignal_span: Span,
        /// Optional SET clause span (SET MESSAGE_TEXT = ..., etc.)
        set_clause_span: Option<Span>,
        /// TokenId for the terminating semicolon (if present)
        semicolon_token: Option<crate::cst::TokenId>,
    },
    /// Databricks GET DIAGNOSTICS CONDITION statement
    GetDiagnostics {
        node_id: crate::ast::NodeId,
        span: Span,
        /// Span covering entire GET DIAGNOSTICS CONDITION ... assignment list
        diagnostics_span: Span,
        /// TokenId for the terminating semicolon (if present)
        semicolon_token: Option<crate::cst::TokenId>,
    },
    /// Databricks DECLARE condition_name CONDITION FOR SQLSTATE 'value'
    DeclareCondition {
        node_id: crate::ast::NodeId,
        span: Span,
        /// Span covering condition name
        condition_name_span: Span,
        /// Span covering CONDITION FOR SQLSTATE VALUE 'nnnnn'
        condition_spec_span: Span,
        /// Optional DECLARE keyword span (if explicit)
        declare_span: Option<Span>,
        /// TokenId for the terminating semicolon (if present)
        semicolon_token: Option<crate::cst::TokenId>,
    },
    /// Databricks DECLARE ... HANDLER FOR condition_value statement
    DeclareHandler(Box<AstDeclareHandlerStmt>),
    For(Box<AstForStmt>),
    /// PostgreSQL PL/pgSQL `FOREACH … IN ARRAY … LOOP … END LOOP`.
    ForEach(Box<AstForEachStmt>),
    While(Box<AstWhileStmt>),
    Repeat(Box<AstRepeatStmt>),
    Loop(Box<AstLoopStmt>),
    /// Async job management: `AWAIT <expr>`;
    Await {
        node_id: crate::ast::NodeId,
        span: Span,
        /// Span covering the job ID expression after AWAIT keyword.
        job_id_expr_span: Span,
    },
    /// Async job management: `CANCEL <expr>`;
    Cancel {
        node_id: crate::ast::NodeId,
        span: Span,
        /// Span covering the job ID expression after CANCEL keyword.
        job_id_expr_span: Span,
    },
    Break {
        node_id: crate::ast::NodeId,
        /// Span covering the entire BREAK or EXIT statement, including the
        /// optional label (if present) and terminating semicolon (if present).
        span: Span,
        /// Span covering just the BREAK/EXIT keyword
        break_span: Span,
        /// TokenId for the BREAK/EXIT keyword
        break_token: Option<crate::cst::TokenId>,
        /// TokenId for the optional label target (e.g., `outer` in `LEAVE outer;`)
        label_token: Option<crate::cst::TokenId>,
        /// TokenId for the terminating semicolon (if present)
        semicolon_token: Option<crate::cst::TokenId>,
    },
    Continue {
        node_id: crate::ast::NodeId,
        /// Span covering the entire CONTINUE statement, including the
        /// terminating semicolon (if present).
        span: Span,
        /// Span covering just the CONTINUE keyword
        continue_span: Span,
        /// TokenId for the CONTINUE keyword
        continue_token: Option<crate::cst::TokenId>,
        /// TokenId for the optional label target (e.g., `inner` in `ITERATE inner;`)
        label_token: Option<crate::cst::TokenId>,
        /// TokenId for the terminating semicolon (if present)
        semicolon_token: Option<crate::cst::TokenId>,
    },
    /// NULL statement: a no-op placeholder statement often used in exception handlers
    Null {
        node_id: crate::ast::NodeId,
        /// Span covering the NULL keyword (and optional semicolon if included)
        span: Span,
        /// Span covering just the NULL keyword
        null_span: Span,
        /// TokenId for the NULL keyword
        null_token: Option<crate::cst::TokenId>,
        /// TokenId for the terminating semicolon (if present)
        semicolon_token: Option<crate::cst::TokenId>,
    },
    /// OPEN cursor statement: opens a cursor and executes its query
    OpenCursor {
        node_id: crate::ast::NodeId,
        span: Span,
        /// Span covering the OPEN keyword
        open_span: Span,
        /// Span covering the cursor name identifier
        cursor_name_span: Span,
        /// Optional USING clause span with bind parameter expressions
        using_clause_span: Option<Span>,
        /// TokenId for the terminating semicolon (if present)
        semicolon_token: Option<crate::cst::TokenId>,
    },
    /// FETCH cursor INTO variables statement
    FetchCursor {
        node_id: crate::ast::NodeId,
        span: Span,
        /// Span covering the FETCH keyword
        fetch_span: Span,
        /// Span covering the cursor name identifier
        cursor_name_span: Span,
        /// Span covering the INTO clause with target variables
        into_clause_span: Span,
        /// Typed list of target variable identifiers (`@x`, `:y`, `z`)
        /// extracted from the INTO clause. Populated when the parser
        /// can recognize the targets; empty for unparseable shapes.
        /// Lets consumers follow values from the cursor to each
        /// destination variable without text-scanning the span.
        into_targets: Vec<AstIdentifier>,
        /// TokenId for the terminating semicolon (if present)
        semicolon_token: Option<crate::cst::TokenId>,
    },
    /// CLOSE cursor statement
    CloseCursor {
        node_id: crate::ast::NodeId,
        span: Span,
        /// Span covering the CLOSE keyword
        close_span: Span,
        /// Span covering the cursor name identifier
        cursor_name_span: Span,
        /// TokenId for the terminating semicolon (if present)
        semicolon_token: Option<crate::cst::TokenId>,
    },
    /// CREATE [OR REPLACE] PROCEDURE statement
    /// Represents a Snowflake Scripting stored procedure definition
    CreateProcedure(Box<AstCreateProcedureStmt>),
    /// `CREATE [OR REPLACE] [TEMP | TEMPORARY] [AGGREGATE] FUNCTION [IF NOT EXISTS]` statement
    /// Represents a user-defined function (UDF) — Snowflake, BigQuery, PostgreSQL
    CreateFunction(Box<AstCreateFunctionStmt>),
    /// CREATE [OR REPLACE] [TEMP | TEMPORARY] TABLE FUNCTION [IF NOT EXISTS] statement (BigQuery TVF)
    CreateTableFunction(Box<AstCreateTableFunctionStmt>),
    /// EXECUTE IMMEDIATE statement for dynamic SQL execution
    /// Syntax: EXECUTE IMMEDIATE <string_expr> [USING (bind_vars)]
    ExecuteImmediate {
        node_id: crate::ast::NodeId,
        span: Span,
        /// Span covering the EXECUTE keyword
        execute_span: Span,
        /// Span covering the IMMEDIATE keyword. `None` for the PL/pgSQL
        /// dynamic-SQL form (`EXECUTE <expr>` without `IMMEDIATE`,
        /// PostgreSQL / Redshift); `Some` for Snowflake / BigQuery /
        /// Databricks `EXECUTE IMMEDIATE <expr>`.
        immediate_span: Option<Span>,
        /// Parsed SQL expression to execute (typically string/variable/concatenation)
        sql_expr: Box<AstExpr>,
        /// Optional span covering USING keyword
        using_span: Option<Span>,
        /// Optional span covering INTO keyword
        into_span: Option<Span>,
        /// Span covering the `STRICT` modifier in PL/pgSQL
        /// `EXECUTE <expr> INTO STRICT <tgt>`. `None` when absent.
        into_strict_span: Option<Span>,
        /// Optional USING clause with bind arguments (`expr [AS alias]`)
        using_args: Vec<AstExecuteUsingArg>,
        /// Span of opening paren in USING clause (Snowflake requires, BigQuery optional)
        using_lparen_span: Option<Span>,
        /// Span of closing paren in USING clause
        using_rparen_span: Option<Span>,
        /// Optional INTO clause for capturing query results into variables
        into_vars: Vec<Span>,
        /// Optional semicolon token ID when EXECUTE IMMEDIATE appears in scripting/Jinja context
        semicolon_token: Option<crate::cst::TokenId>,
    },
    /// Snowflake `EXECUTE IMMEDIATE FROM <file_location> [USING (...)]
    /// [DRY_RUN = TRUE|FALSE]` — executes SQL loaded from a stage file
    /// (a supply-chain / external-code-execution surface), distinct from
    /// the inline `EXECUTE IMMEDIATE <expr>` string-injection surface.
    ExecuteImmediateFrom(Box<AstExecuteImmediateFrom>),
    /// Snowflake `CREATE [OR REPLACE] [SECURE] EXTERNAL FUNCTION …` — a UDF
    /// that ships row data to an external HTTPS endpoint via an API
    /// integration (a data-egress surface), distinct from a code-bearing UDF.
    CreateExternalFunction(Box<AstCreateExternalFunction>),
    /// BEGIN TRANSACTION / START TRANSACTION statement
    /// Syntax: `BEGIN [WORK | TRANSACTION] [NAME <name>]`
    /// Syntax: `START TRANSACTION [NAME <name>]`
    BeginTransaction {
        node_id: crate::ast::NodeId,
        span: Span,
    },
    /// COMMIT statement
    /// Syntax: `COMMIT [WORK]`
    Commit {
        node_id: crate::ast::NodeId,
        span: Span,
    },
    /// ROLLBACK statement
    /// Syntax: `ROLLBACK [WORK]`
    Rollback {
        node_id: crate::ast::NodeId,
        span: Span,
    },
    /// CALL statement for invoking stored procedures
    /// Syntax: `CALL procedure_name([args])`
    Call {
        node_id: crate::ast::NodeId,
        span: Span,
        /// Span covering the CALL keyword
        call_span: Span,
        /// Span covering the procedure name (qualified or unqualified identifier)
        procedure_name_span: Span,
        /// Optional span covering the argument list in parentheses
        args_span: Option<Span>,
        /// Typed argument list — populated when the parser can lift
        /// each argument to an `AstExpr`, for consumers that need
        /// per-argument inspection without re-tokenizing `args_span`.
        args: Vec<AstCallArg>,
        /// Syntax node ID for token-level access (parens, semicolon)
        syntax_id: Option<crate::syntax::SyntaxCallStmtId>,
        /// Optional semicolon token ID when CALL appears in scripting context
        semicolon_token: Option<crate::cst::TokenId>,
        /// `Some` when written as the ODBC call escape `{call p(...)}` /
        /// `{? = call p(...)}`; `span` then covers `{`..`}` and the formatter
        /// re-emits the whole span verbatim. Facts are identical to native CALL.
        odbc: Option<AstOdbcCallEscape>,
    },
    /// `COPY INTO <table>` statement for loading data from stages/files into tables
    /// Syntax: `COPY INTO [namespace.]table_name FROM stage/location [OPTIONS]`
    CopyIntoTable {
        node_id: crate::ast::NodeId,
        span: Span,
        /// Span covering the target table name
        table_name_span: Span,
        /// Span covering the FROM clause (stage or location)
        from_span: Span,
        /// Optional span covering all copy options and file format specifications
        options_span: Option<Span>,
        /// Typed `NAME = VALUE` copy options (`ON_ERROR`, `PURGE`, `FORCE`,
        /// `FILE_FORMAT`, …) parsed from the FROM clause. Empty when none are
        /// present. Populated at parse time so downstream predicates do not
        /// re-tokenize.
        copy_options: Vec<AstCopyOption>,
        /// Parsed FROM location URL when the load source is a quoted string
        /// literal external location (e.g. `'s3://bucket/path/'`). `None`
        /// for stage-name sources and subqueries. Used by content
        /// predicates (CRED-CONNSTR-LEAK) to match against the URL value.
        from_location_url: Option<String>,
        /// Decomposed `KEY = VALUE` pairs from any inline
        /// `CREDENTIALS=(...)` clause on the load — loading directly from
        /// an external location embeds credentials on the statement, same
        /// as the unload direction. Empty when absent (stage-name sources
        /// carry credentials on the stage object instead). Populated at
        /// parse time so downstream content predicates do not re-tokenize.
        credentials: Vec<AstStageCredentialOption>,
    },
    /// `COPY INTO <location>` statement for unloading data from tables to stages/files
    /// Syntax: `COPY INTO stage/location FROM table/query [OPTIONS]`
    CopyIntoLocation {
        node_id: crate::ast::NodeId,
        span: Span,
        /// Span covering the target location (stage or external location)
        into_span: Span,
        /// Span covering the FROM clause (table name or query)
        from_span: Span,
        /// Optional span covering all copy options and file format specifications
        options_span: Option<Span>,
        /// Parsed location URL when the target is a quoted string literal
        /// (e.g. `'s3://bucket/path/'`). `None` for stage-name targets and
        /// for non-string-literal location syntax. Used by content predicates
        /// (CRED-CONNSTR-LEAK) to match against the URL value.
        location_url: Option<String>,
        /// Decomposed `KEY = VALUE` pairs from any inline
        /// `CREDENTIALS=(...)` clause within the statement body. Empty
        /// when no inline credentials clause is present (e.g. when
        /// `STORAGE_INTEGRATION=` is used or the location is an internal
        /// stage). Populated at parse time so downstream content
        /// predicates do not re-tokenize.
        credentials: Vec<AstStageCredentialOption>,
        /// Typed `NAME = VALUE` copy options parsed from the FROM clause,
        /// same as the LOAD direction. Empty when none are present.
        copy_options: Vec<AstCopyOption>,
        /// The unloaded source — a table reference or a parenthesized
        /// subquery — captured structurally so consumers can see which
        /// columns leave through the egress point. `None` when the
        /// source isn't captured (the bytes remain in `from_span`).
        source: Option<AstUnloadSource>,
    },
    /// Redshift `UNLOAD ('select-query') TO 's3://...' [auth] [options]`.
    /// The unload counterpart to COPY: writes query results to an external
    /// location. Carries inline credentials decomposed into typed
    /// `KEY = VALUE` options, the same shape `COPY INTO <location>` uses.
    Unload {
        node_id: crate::ast::NodeId,
        span: Span,
        /// Span covering the `('query')` source-query argument.
        query_span: Span,
        /// Span covering the `TO 'location'` destination clause.
        to_span: Span,
        /// Parsed destination URL when the `TO` target is a string literal
        /// (e.g. `'s3://bucket/path/'`), quotes stripped. `None` otherwise.
        location_url: Option<String>,
        /// Inline credentials decomposed into typed `KEY = VALUE` pairs from
        /// `CREDENTIALS '...'` blobs or `ACCESS_KEY_ID`/`IAM_ROLE`/… options.
        /// Empty when the statement carries no inline secrets.
        credentials: Vec<AstStageCredentialOption>,
    },
    /// Redshift `COPY table FROM 's3://...' [auth] [options]`.
    /// The load counterpart to `UNLOAD`: bulk-loads an external object store
    /// (S3/EMR/SSH) into a table. Distinct from `PgCopy` (PostgreSQL's
    /// server-side `COPY`) because Redshift COPY carries an inline cloud
    /// authorization clause; its credentials are decomposed into typed
    /// `KEY = VALUE` options, the same shape `COPY INTO <location>` and UNLOAD
    /// use.
    RedshiftCopy {
        node_id: crate::ast::NodeId,
        span: Span,
        /// Span covering the loaded-into `table_name [ (cols) ]`.
        table_span: Span,
        /// Span covering the `FROM 'source'` clause.
        from_span: Span,
        /// Parsed data-source URL when the `FROM` target is a string literal
        /// (e.g. `'s3://bucket/path/'`), quotes stripped. `None` otherwise.
        location_url: Option<String>,
        /// Inline credentials decomposed into typed `KEY = VALUE` pairs from
        /// `CREDENTIALS '...'` blobs or `ACCESS_KEY_ID`/`IAM_ROLE`/… options.
        /// Empty when the statement carries no inline secrets.
        credentials: Vec<AstStageCredentialOption>,
    },
    /// Jinja template placeholder at statement level
    /// Used for dbt templates like {% set %}, {% if %}, {% for %}, {{ config() }}
    JinjaPlaceholder {
        node_id: crate::ast::NodeId,
        span: Span,
        kind: JinjaKind,
        /// Optional parsed Jinja expression
        /// For {{ expression }} blocks
        /// None means expression was not parsed or parsing failed
        expr: Option<crate::ast::JinjaExpr>,
        /// Optional parsed Jinja statement (for {% set %}, {% do %})
        /// For {% statement %} blocks that aren't control flow
        /// None for {{ expression }} and control flow blocks
        stmt: Option<crate::ast::JinjaStmt>,
    },
    /// Jinja conditional block wrapping full SQL statements
    /// Used for patterns like: {% if target.name != 'dev' %}SELECT...{% else %}SELECT...{% endif %}
    JinjaConditionalStmt(Box<JinjaStmtBlock>),
    /// `GRANT ...` — privileges, role grants, ownership transfers.
    Grant(Box<AstGrant>),
    /// `REVOKE ...` — privileges, role revocations.
    Revoke(Box<AstRevoke>),
    /// `DENY ...` — MSSQL T-SQL privilege denial. Typed parallel to
    /// `GRANT` / `REVOKE`.
    Deny(Box<AstDeny>),
    /// `ALTER AUTHORIZATION ON [class::]securable TO <principal>` —
    /// T-SQL ownership transfer. Typed parallel to `GRANT OWNERSHIP`.
    AlterAuthorization(Box<AstAlterAuthorization>),

    /// Error recovery placeholder for LSP tolerant parsing.
    ///
    /// When the parser encounters invalid syntax and is in tolerant mode,
    /// it creates an Error node to represent the unparseable region and
    /// continues parsing from the next recovery point (semicolon or
    /// statement-starting keyword).
    ///
    /// This allows LSP features (hover, completion, go-to-definition) to
    /// work on the successfully parsed portions of the document while
    /// the user is mid-edit.
    ///
    /// # Fields
    /// * `node_id` - Unique identifier for this error node
    /// * `span` - The source region that could not be parsed
    /// * `message` - Human-readable error description
    /// * `partial_tokens` - Token kinds encountered in the error region (for diagnostics)
    Error {
        node_id: crate::ast::NodeId,
        /// Span covering the unparseable source region
        span: Span,
        /// Human-readable error message describing what went wrong
        message: String,
        /// Summary of tokens encountered in this error region (helps with diagnostics)
        /// Limited to first ~10 tokens to avoid memory bloat
        partial_tokens: Vec<String>,
    },
}

// ============================================================================
// GRANT / REVOKE
// ============================================================================

/// `GRANT ...` statement.
#[derive(Debug, Clone)]
pub struct AstGrant {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    /// Span of the leading `GRANT` keyword.
    pub keyword_span: Span,
    pub shape: AstGrantShape,
    /// Trailing semicolon token when GRANT appears in scripting/Jinja context.
    pub semicolon_token: Option<crate::cst::TokenId>,
}

/// `DENY ...` statement — MSSQL T-SQL.
///
/// MSSQL grammar:
/// ```text
/// DENY { ALL [ PRIVILEGES ] | <permission> [ ,...n ] }
///   [ ON [ <class>:: ] securable ]
///   TO <principal> [ ,...n ]
///   [ CASCADE ] [ AS <principal> ]
/// ```
///
/// Object is captured span-only. Promote to typed fields when the first
/// consumer needs the securable class or name.
#[derive(Debug, Clone)]
pub struct AstDeny {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    /// Span of the leading `DENY` keyword.
    pub keyword_span: Span,
    /// Comma-separated privilege list (or `ALL [PRIVILEGES]`).
    pub privileges: AstPrivilegeList,
    /// `ON [class::]securable` clause. Span-only: covers everything
    /// between the trailing `ON` and the next clause (`TO`).
    pub object_span: Option<AstDenyObject>,
    /// One or more `TO <principal>` targets.
    pub grantees: Vec<AstGrantee>,
    /// `CASCADE` keyword span (post-grantees).
    pub cascade: Option<Span>,
    /// `AS <principal>` delegation clause.
    pub as_principal: Option<AstDenyAs>,
    /// Trailing semicolon token when DENY appears in scripting/Jinja context.
    pub semicolon_token: Option<crate::cst::TokenId>,
}

/// `ON [class::]securable` clause within a DENY. Captured span-only —
/// `keyword_span` covers the `ON` token, `target_span` covers the
/// securable expression up to the next clause boundary.
#[derive(Debug, Clone)]
pub struct AstDenyObject {
    pub keyword_span: Span,
    pub target_span: Span,
}

/// `AS <principal_name>` delegation clause on a DENY.
#[derive(Debug, Clone)]
pub struct AstDenyAs {
    pub keyword_span: Span,
    pub principal_name_span: Span,
}

/// T-SQL `ALTER AUTHORIZATION ON [ <class>:: ] <securable> TO
/// { <principal> | SCHEMA OWNER }` — ownership transfer of a securable.
#[derive(Debug, Clone)]
pub struct AstAlterAuthorization {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    /// Span covering the `ALTER AUTHORIZATION` keywords.
    pub keyword_span: Span,
    /// The `[class::]securable` after `ON`, reusing the grant-object
    /// shape (class lexeme preserved on `AstObjectKind::Other`).
    pub object: AstGrantObject,
    /// The new owner after `TO`.
    pub new_owner: AstAuthorizationOwner,
}

/// New-owner clause of `ALTER AUTHORIZATION`.
#[derive(Debug, Clone)]
pub enum AstAuthorizationOwner {
    /// `TO <principal_name>`.
    Principal { name_span: Span },
    /// `TO SCHEMA OWNER` — ownership reverts to the containing schema's
    /// owner.
    SchemaOwner { keyword_span: Span },
}

/// `REVOKE ...` statement.
#[derive(Debug, Clone)]
pub struct AstRevoke {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    /// Span of the leading `REVOKE` keyword.
    pub keyword_span: Span,
    /// `GRANT OPTION FOR` prefix span — present means revoke only the
    /// grant-option, not the underlying privilege.
    pub grant_option_for: Option<Span>,
    pub shape: AstRevokeShape,
    /// Trailing `RESTRICT` / `CASCADE` modifier.
    pub cascade_mode: Option<AstCascadeMode>,
    /// Trailing semicolon token when REVOKE appears in scripting/Jinja context.
    pub semicolon_token: Option<crate::cst::TokenId>,
}

/// Top-level GRANT shape.
#[derive(Debug, Clone)]
pub enum AstGrantShape {
    /// `GRANT <privilege list> ON <object> TO <grantee> [WITH GRANT OPTION]`
    Privilege(AstPrivilegeGrantBody),
    /// `GRANT ROLE <name> TO <grantee>`
    Role(AstRoleGrantBody),
    /// `GRANT DATABASE ROLE <db.name> TO <grantee>`
    DatabaseRole(AstRoleGrantBody),
    /// `GRANT OWNERSHIP ON <object> TO <role|database role> [COPY|REVOKE CURRENT GRANTS]`
    Ownership(AstOwnershipGrantBody),
    /// Span-only fallback — the body span is captured here when the
    /// typed parse fails.
    Unparsed { body_span: Span },
}

/// Top-level REVOKE shape.
#[derive(Debug, Clone)]
pub enum AstRevokeShape {
    /// `REVOKE <privilege list> ON <object> FROM <grantee>`
    Privilege(AstPrivilegeRevokeBody),
    /// `REVOKE ROLE <name> FROM <grantee>`
    Role(AstRoleGrantBody),
    /// `REVOKE DATABASE ROLE <db.name> FROM <grantee>`
    DatabaseRole(AstRoleGrantBody),
    /// Span-only fallback — see `AstGrantShape::Unparsed`.
    Unparsed { body_span: Span },
}

/// Privilege-form body shared between `GRANT <priv>` and `REVOKE <priv>`.
/// `with_grant_option` is GRANT-only; REVOKE carries `grant_option_for`
/// on the parent `AstRevoke`.
///
/// `objects` cardinality encodes the dialect shape:
/// - **empty** — server / account-tier permission whose source omits the
///   `ON ...` clause (MSSQL `GRANT CONTROL SERVER TO ...`).
/// - **single** — Snowflake / Databricks / MySQL / BigQuery / MSSQL
///   standard form. `GRANT SELECT ON FUTURE TABLES IN DATABASE foo`
///   is *one* `AstGrantObject::FutureInScope`, not many.
/// - **multi** — PostgreSQL multi-object syntax
///   (`GRANT SELECT ON TABLE t1, t2, t3 TO u`). Reserved for the
///   PostgreSQL grant parser.
///
/// `grantees` is a `Vec` to model dialects whose grammar admits multiple
/// principals in a single statement (MSSQL `TO p1, p2, p3`; BigQuery
/// `TO "user:a@x.com", "group:g@x.com"`). Snowflake / Databricks emit a
/// single-element vec.
#[derive(Debug, Clone)]
pub struct AstPrivilegeGrantBody {
    pub privileges: AstPrivilegeList,
    pub objects: Vec<AstGrantObject>,
    pub grantees: Vec<AstGrantee>,
    /// `WITH GRANT OPTION` trailing clause span.
    pub with_grant_option: Option<Span>,
}

/// `REVOKE <privilege list> ON <object> FROM <grantee>`. See
/// [`AstPrivilegeGrantBody`] for the `objects: Vec` / `grantees: Vec`
/// dialect rationale.
#[derive(Debug, Clone)]
pub struct AstPrivilegeRevokeBody {
    pub privileges: AstPrivilegeList,
    pub objects: Vec<AstGrantObject>,
    pub grantees: Vec<AstGrantee>,
}

/// `GRANT/REVOKE [DATABASE] ROLE <name> TO/FROM <grantee>`.
#[derive(Debug, Clone)]
pub struct AstRoleGrantBody {
    /// Span of the `ROLE` / `DATABASE ROLE` keyword(s).
    pub role_keyword_span: Span,
    /// Qualified role name span.
    pub role_name_span: Span,
    pub grantee: AstGrantee,
}

/// `GRANT OWNERSHIP ON <object> TO <role|db-role> [COPY|REVOKE CURRENT GRANTS]`.
#[derive(Debug, Clone)]
pub struct AstOwnershipGrantBody {
    pub object: AstGrantObject,
    pub grantee: AstGrantee,
    pub disposition: Option<AstOwnershipDisposition>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AstOwnershipDisposition {
    /// `COPY CURRENT GRANTS`
    Copy,
    /// `REVOKE CURRENT GRANTS`
    Revoke,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AstCascadeMode {
    Restrict,
    Cascade,
}

/// What the GRANT/REVOKE operates on.
#[derive(Debug, Clone)]
pub enum AstGrantObject {
    /// `ON ACCOUNT` (global privileges).
    Account { keyword_span: Span },
    /// `ON METASTORE` (Databricks Unity Catalog metastore-tier singleton).
    Metastore { keyword_span: Span },
    /// `ON <object_type> <name>[(<arg-types>)]`.
    Single {
        object_kind: AstObjectKind,
        kind_span: Span,
        name_span: Span,
        /// `(<arg-types>)` for FUNCTION / PROCEDURE / DATA METRIC FUNCTION.
        function_signature: Option<AstFunctionSignature>,
    },
    /// `ON ALL <plural> IN { DATABASE | SCHEMA } <scope>`.
    AllInScope {
        plural_kind: AstPluralObjectKind,
        plural_kind_span: Span,
        scope: AstObjectScope,
    },
    /// `ON FUTURE <plural> IN { DATABASE | SCHEMA } <scope>`.
    FutureInScope {
        plural_kind: AstPluralObjectKind,
        plural_kind_span: Span,
        scope: AstObjectScope,
    },
}

#[derive(Debug, Clone)]
pub enum AstObjectScope {
    /// `IN DATABASE <name>`
    Database { name_span: Span, keyword_span: Span },
    /// `IN SCHEMA <name>`
    Schema { name_span: Span, keyword_span: Span },
    /// `IN CATALOG <name>` — Databricks Unity Catalog top-level
    /// namespace, used in `GRANT … ON {ALL | FUTURE} SCHEMAS IN
    /// CATALOG <name>` shapes.
    Catalog { name_span: Span, keyword_span: Span },
}

/// Function/procedure argument-type list (`(NUMBER, VARCHAR)`).
#[derive(Debug, Clone)]
pub struct AstFunctionSignature {
    pub lparen_span: Span,
    pub rparen_span: Span,
    pub args: Vec<AstFunctionArgType>,
}

/// One argument type in a function/procedure signature.
#[derive(Debug, Clone)]
pub struct AstFunctionArgType {
    /// Span of the data-type token(s).
    pub span: Span,
}

/// Closed enum of object kinds recognized in GRANT/REVOKE on Snowflake.
/// Kinds Snowflake supports but this enum does not yet enumerate
/// (e.g. `IcebergTable`, `HybridTable`, `ExternalVolume`) project to
/// `ObjectKind::Generic`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AstObjectKind {
    Table,
    View,
    MaterializedView,
    DynamicTable,
    ExternalTable,
    IcebergTable,
    HybridTable,
    Schema,
    Database,
    Warehouse,
    User,
    Role,
    Share,
    Application,
    ApplicationPackage,
    Account,
    Integration,
    ResourceMonitor,
    ComputePool,
    ExternalVolume,
    Connection,
    FailoverGroup,
    ReplicationGroup,
    Stage,
    FileFormat,
    Function,
    Procedure,
    DataMetricFunction,
    Sequence,
    Stream,
    Task,
    Pipe,
    Tag,
    Secret,
    Service,
    Streamlit,
    Alert,
    NetworkRule,
    SemanticView,
    MaskingPolicy,
    RowAccessPolicy,
    AggregationPolicy,
    AuthenticationPolicy,
    PasswordPolicy,
    NetworkPolicy,
    SessionPolicy,
    ProjectionPolicy,
    /// Databricks Unity Catalog top-level namespace (`ON CATALOG <name>`).
    Catalog,
    /// Databricks Unity Catalog volume (`ON VOLUME <name>`).
    Volume,
    /// Databricks Unity Catalog external location (`ON EXTERNAL LOCATION <name>`).
    ExternalLocation,
    /// Databricks Unity Catalog storage credential (`ON STORAGE CREDENTIAL <name>`).
    StorageCredential,
    /// Databricks Unity Catalog metastore (`ON METASTORE`).
    Metastore,
    /// Object kind not enumerated above. Carries the source lexemes so
    /// downstream projection can normalize to `Privilege::Other` /
    /// `ObjectKind::Generic` without losing the spelling.
    Other {
        lexemes: Vec<String>,
    },
}

/// Plural form for `ALL <plural>` and `FUTURE <plural>` clauses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AstPluralObjectKind {
    Tables,
    Views,
    MaterializedViews,
    DynamicTables,
    ExternalTables,
    IcebergTables,
    HybridTables,
    Schemas,
    Functions,
    Procedures,
    DataMetricFunctions,
    Sequences,
    Stages,
    FileFormats,
    Streams,
    Tasks,
    Pipes,
    Tags,
    SemanticViews,
    MaskingPolicies,
    RowAccessPolicies,
    AggregationPolicies,
    AuthenticationPolicies,
    PasswordPolicies,
    NetworkPolicies,
    SessionPolicies,
    ProjectionPolicies,
    Other { lexemes: Vec<String> },
}

/// `TO <grantee>` / `FROM <grantee>`.
#[derive(Debug, Clone)]
pub enum AstGrantee {
    /// `[ROLE] <name>` — role keyword optional in privilege grammar.
    Role {
        name_span: Span,
        role_keyword_span: Option<Span>,
    },
    /// `USER <name>`
    User { name_span: Span, keyword_span: Span },
    /// `SHARE <name>`
    Share { name_span: Span, keyword_span: Span },
    /// `DATABASE ROLE <db.name>` (qualified)
    DatabaseRole { name_span: Span, keyword_span: Span },
    /// `APPLICATION <name>`
    Application { name_span: Span, keyword_span: Span },
    /// `APPLICATION ROLE <app.name>`
    ApplicationRole { name_span: Span, keyword_span: Span },
    /// `GROUP <name>` — Redshift permission group grantee (also a
    /// deprecated PG noise-word form). Distinct from `Role`: Redshift
    /// groups are the legacy membership primitive, so they must not
    /// collapse to `Role` (mirrors [`PrincipalKind::Group`]).
    Group { name_span: Span, keyword_span: Span },
}

/// Privilege list on a GRANT/REVOKE statement.
#[derive(Debug, Clone)]
pub struct AstPrivilegeList {
    /// Present when the source spelled `ALL` or `ALL PRIVILEGES`. When
    /// `Some`, `privileges` is empty.
    pub all: Option<AstAllPrivileges>,
    pub privileges: Vec<AstPrivilege>,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct AstAllPrivileges {
    /// Whether `PRIVILEGES` was spelled out after `ALL`.
    pub privileges_keyword: bool,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct AstPrivilege {
    pub kind: AstPrivilegeKind,
    pub span: Span,
}

/// Closed enum of recognized Snowflake privilege names. Privileges not
/// enumerated below land in `Other` with the source lexeme(s) preserved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AstPrivilegeKind {
    // Data-level
    Select,
    Insert,
    Update,
    Delete,
    Truncate,
    References,
    // Schema/object-level
    Modify,
    Monitor,
    Operate,
    Usage,
    Apply,
    Execute,
    Read,
    Write,
    // Snowflake-special single-word
    Ownership,
    ManageGrants,
    ApplyMaskingPolicy,
    ApplyRowAccessPolicy,
    ApplyTag,
    ApplyAggregationPolicy,
    ApplyProjectionPolicy,
    ImportShare,
    ImportedPrivileges,
    // CREATE <object>
    CreateTable,
    CreateView,
    CreateSchema,
    CreateDatabase,
    CreateRole,
    CreateUser,
    CreateFunction,
    CreateProcedure,
    CreateMaskingPolicy,
    CreateRowAccessPolicy,
    CreateNetworkPolicy,
    CreateSessionPolicy,
    CreatePasswordPolicy,
    CreateStage,
    CreateWarehouse,
    CreateTask,
    CreatePipe,
    CreateExternalTable,
    /// Bare `CREATE` (without an object suffix) — covers privileges
    /// downstream models as `Privilege::Create`.
    Create,
    // ───────────── Databricks Unity Catalog ─────────────
    /// `MANAGE` — broad administrative privilege on a UC object.
    Manage,
    /// `EXTERNAL USE LOCATION` — temporary-credential vending for
    /// external engines on an external location.
    ExternalUseLocation,
    /// `EXTERNAL USE SCHEMA` — temporary-credential vending for
    /// external engines on a schema (Iceberg REST).
    ExternalUseSchema,
    /// `READ FILES` — direct reads from cloud object storage backing
    /// an external location.
    ReadFiles,
    /// `WRITE FILES` — direct writes to cloud object storage backing
    /// an external location.
    WriteFiles,
    /// `CREATE STORAGE CREDENTIAL` — metastore-tier privilege to
    /// create UC storage credentials.
    CreateStorageCredential,
    /// `CREATE EXTERNAL LOCATION` — metastore-tier privilege to map
    /// cloud paths into UC.
    CreateExternalLocation,
    /// `SET SHARE PERMISSION` — Delta Sharing administrative privilege.
    SetSharePermission,
    /// Privilege name not enumerated above. Carries the source
    /// lexeme(s) so downstream projection normalizes to
    /// `Privilege::Other(IdentName)`.
    Other {
        lexemes: Vec<String>,
    },
}

/// Mode of a procedure / function parameter, typed uniformly across
/// dialects. Mode-keyword recognition is
/// the only text-→-typed step in the parameter substrate — every
/// downstream consumer reads this enum rather than re-tokenizing.
///
/// Unknown / unparseable modifiers degrade to [`ProcedureParamMode::In`]
/// (permissive parser default), the over-approximating direction: a value
/// passed to an `In`-mode param still flows into the body.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProcedureParamMode {
    /// Default in every supported dialect. T-SQL no keyword;
    /// PG `IN`; MySQL `IN`.
    In,
    /// T-SQL `OUTPUT` / `OUT`; PG `OUT` (function- and procedure-
    /// level). Callee → caller direction.
    Out,
    /// PG / MySQL `INOUT`. Bi-directional. T-SQL collapses INOUT
    /// into [`ProcedureParamMode::Out`] (T-SQL `OUTPUT` allows both
    /// directions, no separate INOUT keyword).
    InOut,
    /// PG `VARIADIC` parameter (variable-arity tail). Flows like
    /// [`ProcedureParamMode::In`]; the variadic flag is preserved for
    /// diagnostic output.
    Variadic,
}

/// One typed parameter in a `CREATE PROCEDURE` / `CREATE FUNCTION`
/// signature. Populated by the dialect-specific parameter parsers
/// in [`crate::parser::procedure_params`]; preserves enough span
/// information for the formatter to round-trip alongside the
/// retained `params_span` on the parent struct.
///
/// **Invariant**: when the parser populates the parent struct's
/// `params` vector, every element's `span` must lie within the
/// parent struct's `params_span`, so consumers can attribute
/// per-parameter findings back to the original source.
#[derive(Debug, Clone)]
pub struct AstProcedureParam {
    pub node_id: crate::ast::NodeId,
    /// Span covering the entire parameter (mode keyword through
    /// default expression, inclusive).
    pub span: Span,
    /// Span of the parameter name. `None` for PG unnamed OUT
    /// parameters (`CREATE FUNCTION f(OUT integer) ...` is legal
    /// in PG with no name). The summary builder skips unnamed
    /// params for inflow attribution and falls back to positional
    /// matching at call sites.
    pub name_span: Option<Span>,
    /// Span of the parameter type. `None` when the dialect grammar
    /// allows omitting the type (e.g., BigQuery procedure-only
    /// nameless typed params with type-inference scenarios).
    pub type_span: Option<Span>,
    pub mode: ProcedureParamMode,
    /// `DEFAULT <expr>` / `= <expr>` initializer. None when no
    /// default is provided.
    pub default_expr: Option<Box<AstExpr>>,
}

#[derive(Debug, Clone)]
pub struct AstCreateProcedureStmt {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    pub create_span: Span,
    pub or_replace_span: Option<Span>,
    pub or_alter_span: Option<Span>,
    pub procedure_keyword_span: Span,
    pub name_span: Span,
    pub params_span: Span,
    /// Typed parameter list. Populated by the dialect-specific
    /// procedure-param parsers; empty when the parser fell through
    /// (unparseable signature). When non-empty, every element's
    /// `span` lies within `params_span` (formatter byte-exactness
    /// invariant).
    pub params: Vec<AstProcedureParam>,
    pub returns_span: Span,
    pub body_span: Span,
    pub body_stmt: Option<Box<AstStmt>>,
    pub opening_delimiter_token: Option<crate::cst::TokenId>,
    pub closing_delimiter_token: Option<crate::cst::TokenId>,
    /// `WITH EXECUTE AS { OWNER | CALLER | SELF | 'user_name' }` clause
    /// (T-SQL) or `EXECUTE AS { OWNER | CALLER }` (Snowflake scripting).
    /// `None` when absent.
    pub execute_as_mode: Option<ExecuteAsMode>,
    /// MySQL `DEFINER = { user | CURRENT_USER }` security-context clause.
    /// The body runs under this account's privileges regardless of the
    /// invoker — the routine's privilege-delegation primitive. `None`
    /// when absent.
    pub definer: Option<AstDefiner>,
}

#[derive(Debug, Clone)]
pub struct AstCreateFunctionStmt {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    pub create_span: Span,
    pub or_replace_span: Option<Span>,
    pub or_alter_span: Option<Span>,
    pub temp_keyword_span: Option<Span>,
    pub aggregate_keyword_span: Option<Span>,
    pub function_keyword_span: Span,
    pub if_not_exists_span: Option<Span>,
    pub name_span: Span,
    pub params_span: Span,
    /// Typed parameter list. See [`AstCreateProcedureStmt::params`]
    /// for the same invariants.
    pub params: Vec<AstProcedureParam>,
    pub returns_span: Span,
    pub body_span: Span,
    pub body_stmt: Option<Box<AstStmt>>,
    pub opening_delimiter_token: Option<crate::cst::TokenId>,
    pub closing_delimiter_token: Option<crate::cst::TokenId>,
    /// MySQL `DEFINER = { user | CURRENT_USER }` security-context clause.
    /// See [`AstCreateProcedureStmt::definer`]. `None` when absent.
    pub definer: Option<AstDefiner>,
}

#[derive(Debug, Clone)]
pub struct AstCreateTableFunctionStmt {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    pub create_span: Span,
    pub or_replace_span: Option<Span>,
    pub temp_keyword_span: Option<Span>,
    pub table_keyword_span: Span,
    pub function_keyword_span: Span,
    pub if_not_exists_span: Option<Span>,
    pub name_span: Span,
    pub params_span: Span,
    /// Typed parameter list. See [`AstCreateProcedureStmt::params`]
    /// for the same invariants.
    pub params: Vec<AstProcedureParam>,
    pub returns_span: Span,
    pub body_span: Span,
    pub body_stmt: Option<Box<AstStmt>>,
}

#[derive(Debug, Clone)]
pub enum ExceptionHandlerType {
    Simple, // No EXIT/CONTINUE keyword
    Exit,
    Continue,
}

#[derive(Debug, Clone)]
pub struct AstExceptionHandler {
    pub node_id: crate::ast::NodeId,
    /// Span covering the WHEN keyword.
    pub when_span: Span,
    /// TokenId for the WHEN keyword
    pub when_token: Option<crate::cst::TokenId>,
    /// Exception name spans (identifiers or OTHER keyword), can be multiple with OR.
    pub exception_name_spans: Vec<Span>,
    /// TokenIds for exception names (same length as exception_name_spans)
    pub exception_name_tokens: Vec<Option<crate::cst::TokenId>>,
    /// Whether this handler is EXIT or CONTINUE type.
    pub handler_type: ExceptionHandlerType,
    /// Span covering the THEN keyword (optional, may not be present).
    pub then_span: Option<Span>,
    /// TokenId for the THEN keyword
    pub then_token: Option<crate::cst::TokenId>,
    /// Statements in the handler body.
    pub body: Vec<AstStmt>,
    /// Span covering the entire WHEN clause.
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct AstExceptionSection {
    pub node_id: crate::ast::NodeId,
    /// Span covering the EXCEPTION keyword.
    pub keyword_span: Span,
    /// TokenId for the EXCEPTION keyword
    pub keyword_token: Option<crate::cst::TokenId>,
    /// Exception handlers (WHEN clauses).
    pub handlers: Vec<AstExceptionHandler>,
    /// Span covering the entire EXCEPTION ... handler list up to
    /// (but not including) the final END keyword of the block.
    pub span: Span,
}

/// Databricks DECLARE handler statement:
/// DECLARE EXIT/CONTINUE HANDLER FOR condition_value [, ...] statement
#[derive(Debug, Clone)]
pub struct AstDeclareHandlerStmt {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    /// Optional DECLARE keyword span
    pub declare_span: Option<Span>,
    /// Handler type: EXIT or CONTINUE
    pub handler_type: ExceptionHandlerType,
    /// Span covering the handler type keyword (EXIT or CONTINUE)
    pub handler_type_span: Span,
    /// Span covering the HANDLER FOR keywords
    pub handler_for_span: Span,
    /// Typed condition list (SQLSTATE 'value', SQLEXCEPTION, NOT FOUND,
    /// condition_name). The parser is the only legitimate site that
    /// classifies the lexeme; downstream code reads
    /// [`AstHandlerConditionKind`] variants directly rather than
    /// re-doing the text match.
    pub conditions: Vec<AstHandlerCondition>,
    /// The handler action (a single statement, often BEGIN...END)
    pub handler_action: Box<AstStmt>,
    /// TokenId for the terminating semicolon (if present)
    pub semicolon_token: Option<crate::cst::TokenId>,
}

/// One typed condition value in a `DECLARE HANDLER FOR …` list.
#[derive(Debug, Clone)]
pub struct AstHandlerCondition {
    /// Span covering the entire condition (e.g. "SQLSTATE VALUE '23000'"
    /// or "NOT FOUND" or the user-defined condition name).
    pub span: Span,
    pub kind: AstHandlerConditionKind,
}

/// Closed-enum tag for the condition kind a handler subscribes to.
/// Lifted from the parser's keyword/lexeme dispatch so downstream
/// consumers never re-do text matching against the source span.
#[derive(Debug, Clone)]
pub enum AstHandlerConditionKind {
    /// `SQLEXCEPTION` — broad catch-all for any SQLSTATE class != '00','01','02'.
    SqlException,
    /// `SQLWARNING` — SQLSTATE class '01'.
    SqlWarning,
    /// `NOT FOUND` — SQLSTATE class '02'.
    NotFound,
    /// `SQLSTATE [VALUE] '<code>'` — explicit SQLSTATE code.
    SqlState {
        /// Span over the optional `VALUE` keyword.
        value_keyword_span: Option<Span>,
        /// Span over the SQLSTATE literal value.
        value_literal_span: Option<Span>,
    },
    /// User-defined condition name (from `DECLARE … CONDITION …`).
    NamedCondition {
        /// Span over the condition identifier.
        name_span: Span,
    },
}

#[derive(Debug, Clone)]
pub struct IfBranch {
    pub node_id: crate::ast::NodeId,
    pub if_span: Span,
    /// TokenId for the IF or ELSEIF keyword
    pub if_token: Option<crate::cst::TokenId>,
    /// TokenId for opening parenthesis (if present - optional for BigQuery)
    pub lparen_token: Option<crate::cst::TokenId>,
    /// Parsed condition expression
    pub condition: Box<AstExpr>,
    pub condition_span: Span,
    /// TokenId for closing parenthesis (if present - optional for BigQuery)
    pub rparen_token: Option<crate::cst::TokenId>,
    pub then_span: Span,
    /// TokenId for the THEN keyword
    pub then_token: Option<crate::cst::TokenId>,
    pub body: Vec<AstStmt>,
}

#[derive(Debug, Clone)]
pub struct CaseBranch {
    pub node_id: crate::ast::NodeId,
    pub when_span: Span,
    /// TokenId for the WHEN keyword
    pub when_token: Option<crate::cst::TokenId>,
    /// Parsed WHEN condition expression for this branch.
    pub condition: Box<AstExpr>,
    /// Span covering the original WHEN condition expression for formatting and diagnostics.
    pub condition_span: Span,
    pub then_span: Span,
    /// TokenId for the THEN keyword
    pub then_token: Option<crate::cst::TokenId>,
    pub body: Vec<AstStmt>,
}

#[derive(Debug, Clone)]
pub struct AstCreateTable {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    pub keyword_span: Span,
    pub or_replace_span: Option<Span>,
    /// Span covering the `PROCEDURE SCOPED` prefix of a Snowflake
    /// procedure-scoped temporary table (`CREATE [OR REPLACE] PROCEDURE
    /// SCOPED { TEMP | TEMPORARY } TABLE …`). Emitted before `temp_kind_span`.
    /// `None` for ordinary tables. The `TEMP`/`TEMPORARY` keyword itself lands
    /// in `temp_kind_span` as usual, so a scoped table is also temporary.
    pub scoped_span: Option<Span>,
    pub temp_kind_span: Option<Span>,
    /// Snowflake `ICEBERG` / `HYBRID` / `EVENT` table variant, declared
    /// between the temp modifier and `TABLE`. `None` for ordinary tables.
    pub table_kind: Option<AstTableKind>,
    /// Span covering the `ICEBERG` / `HYBRID` / `EVENT` keyword (for
    /// byte-exact formatting). Set iff `table_kind` is `Some`.
    pub table_kind_span: Option<Span>,
    pub table_keyword_span: Span,
    pub name_span: Span,
    pub columns_span: Option<Span>,
    /// Span of the opening parenthesis for column definitions
    pub lparen_span: Option<Span>,
    /// Span of the closing parenthesis for column definitions
    pub rparen_span: Option<Span>,
    pub variant: AstCreateTableVariant,
    pub like_source_span: Option<Span>,
    pub clone_source_span: Option<Span>,
    /// Databricks DEEP/SHALLOW clone kind
    pub clone_kind: Option<CloneKind>,
    /// Span for DEEP/SHALLOW keyword (Databricks)
    pub clone_kind_span: Option<Span>,
    /// Span for TBLPROPERTIES clause (Databricks)
    pub clone_tblproperties_span: Option<Span>,
    /// Span for LOCATION clause (Databricks)
    pub clone_location_span: Option<Span>,
    /// Span for TIMESTAMP AS OF / VERSION AS OF clause (Databricks)
    pub clone_temporal_span: Option<Span>,
    /// CTAS query: parsed SELECT or SetSelect statement, or unparsed span as fallback
    pub ctas_query: Option<Result<Box<AstStmt>, Span>>,
    pub time_travel: Option<Box<AstTimeTravelClause>>,
    pub table_options_span: Option<Span>,
    pub cluster_by_span: Option<Span>,
    pub cluster_by_exprs: Option<Vec<AstExpr>>,
    /// Redshift `DISTSTYLE { EVEN | KEY | ALL | AUTO }` (typed value).
    pub dist_style: Option<AstDistStyle>,
    /// Redshift `DISTKEY (col)` clause present.
    pub dist_key_present: bool,
    /// Redshift `[COMPOUND | INTERLEAVED] SORTKEY (...)` strategy.
    pub sort_key: Option<AstSortKeySpec>,
    /// Redshift `BACKUP { YES | NO }` snapshot-inclusion mode.
    pub backup: Option<AstBackupMode>,
    pub partition_by_span: Option<Span>,
    pub copy_grants_span: Option<Span>,
    pub copy_tags_span: Option<Span>,
    pub retention_span: Option<Span>,
    pub change_tracking_span: Option<Span>,
    pub data_retention_time_in_days_span: Option<Span>,
    pub max_data_extension_time_in_days_span: Option<Span>,
    pub default_ddl_collation_span: Option<Span>,
    pub row_access_policy_span: Option<Span>,
    pub aggregation_policy_span: Option<Span>,
    pub join_policy_span: Option<Span>,
    pub storage_lifecycle_policy_span: Option<Span>,
    pub tag_span: Option<Span>,
    pub enable_schema_evolution_span: Option<Span>,
    pub table_comment_span: Option<Span>,
    pub with_row_access_policy_span: Option<Span>,
    pub with_contact_span: Option<Span>,
    pub using_template_span: Option<Span>,
    pub from_archive_span: Option<Span>,
    pub from_snapshot_set_span: Option<Span>,
    pub columns: Vec<AstCreateTableColumn>,
    /// Optional semicolon token ID when CREATE TABLE appears in scripting context
    pub semicolon_token: Option<crate::cst::TokenId>,
    pub constraints: Vec<AstCreateTableConstraint>,
}

#[derive(Debug, Clone)]
pub struct AstCreateTableColumn {
    pub node_id: crate::ast::NodeId,
    pub full_span: Span,
    pub name_span: Option<Span>,
    pub type_span: Option<Span>,
    pub collate_span: Option<Span>,
    pub not_null_span: Option<Span>,
    pub default_expr_span: Option<Span>,
    pub identity_or_autoincrement_span: Option<Span>,
    /// `GENERATED ALWAYS` / `GENERATED BY DEFAULT` prefix; includes the
    /// trailing `AS` when followed by `IDENTITY` (identity, not expression).
    pub generated_always_span: Option<Span>,
    /// Generated/virtual/computed column expression: `AS ( expr )` or
    /// MSSQL `AS expr` — span includes the `AS` keyword.
    pub virtual_expr_span: Option<Span>,
    /// Storage keyword after the expression: `VIRTUAL` | `STORED` | `PERSISTED`.
    pub storage_keyword_span: Option<Span>,
    pub inline_constraint_id: Option<crate::syntax::SyntaxInlineConstraintId>,
    pub masking_policy_span: Option<Span>,
    pub tag_span: Option<Span>,
    pub comment_span: Option<Span>,
}

impl AstCreateTableColumn {
    /// Returns the span for the argument tail that follows an
    /// IDENTITY or AUTOINCREMENT keyword within this column, if any.
    ///
    /// This is derived purely from existing spans:
    /// - If `identity_or_autoincrement_span` is present,
    ///   the tail (if non-empty) starts at its `end` and
    ///   extends through `full_span.end`.
    /// - If the computed tail would be empty or invalid,
    ///   `None` is returned.
    pub fn identity_arg_tail_span(&self) -> Option<Span> {
        let id_span = self.identity_or_autoincrement_span?;
        let start = id_span.end;
        let end = self.full_span.end;
        if start >= end {
            return None;
        }
        Some(Span { start, end })
    }
}

#[derive(Debug, Clone)]
pub struct AstCreateTableConstraint {
    pub node_id: crate::ast::NodeId,
    pub full_span: Span,
    /// Parsed constraint details. None if parsing fell back to span-only.
    pub details: Option<AstConstraintDetails>,
}

#[derive(Debug, Clone)]
pub struct AstConstraintDetails {
    pub node_id: crate::ast::NodeId,
    /// Optional constraint name (after CONSTRAINT keyword)
    pub name: Option<Span>,
    /// The type and specifics of the constraint
    pub kind: AstConstraintKind,
}

#[derive(Debug, Clone)]
pub enum AstConstraintKind {
    /// PRIMARY KEY (col1, col2, ...)
    PrimaryKey { columns: Vec<Span> },
    /// UNIQUE (col1, col2, ...)
    Unique { columns: Vec<Span> },
    /// FOREIGN KEY (col1, ...) REFERENCES ref_table (ref_col1, ...)
    ForeignKey {
        columns: Vec<Span>,
        references_table: Span,
        references_columns: Vec<Span>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AstCreateTableVariant {
    Plain,
    Like,
    Clone,
    Ctas,
    UsingTemplate,
    FromArchive,
    FromSnapshotSet,
}

/// Databricks CLONE kind: DEEP or SHALLOW
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloneKind {
    Deep,
    Shallow,
}

/// Redshift `DISTSTYLE` table distribution strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AstDistStyle {
    Even,
    Key,
    All,
    Auto,
}

/// Redshift `SORTKEY` strategy. Bare `SORTKEY` and `COMPOUND SORTKEY` are
/// compound; `INTERLEAVED SORTKEY` is interleaved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AstSortKeySpec {
    Compound,
    Interleaved,
}

/// Redshift `BACKUP { YES | NO }` snapshot-inclusion mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AstBackupMode {
    Yes,
    No,
}

/// Snowflake non-standard table variant declared between the (optional)
/// temp/transient modifier and the `TABLE` keyword:
/// `CREATE { ICEBERG | HYBRID | EVENT } TABLE`. Absent (`None` on
/// [`AstCreateTable::table_kind`]) for an ordinary table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AstTableKind {
    /// `CREATE ICEBERG TABLE` — data stored in an external EXTERNAL VOLUME.
    Iceberg,
    /// `CREATE HYBRID TABLE` — Unistore row-oriented OLTP table.
    Hybrid,
    /// `CREATE EVENT TABLE` — log/trace event-capture table.
    Event,
}

/// MySQL view `SQL SECURITY { DEFINER | INVOKER }` clause — whose privileges
/// the view's query runs under. `Definer` (the MySQL default) runs it with the
/// definer account's rights, so the view can expose data the caller could not
/// read directly; `Invoker` runs it with the caller's own rights.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ViewSqlSecurityMode {
    Definer,
    Invoker,
}

/// A parsed `SQL SECURITY { DEFINER | INVOKER }` clause: the typed mode plus the
/// span covering the whole clause (for byte-exact re-emission).
#[derive(Debug, Clone)]
pub struct AstViewSqlSecurity {
    pub span: Span,
    pub mode: ViewSqlSecurityMode,
}

/// Represents a Snowflake CREATE VIEW statement with all supported options.
/// Follows the same architectural pattern as AstCreateTable with comprehensive
/// span tracking for all syntactic elements.
#[derive(Debug, Clone)]
pub struct AstCreateView {
    pub node_id: crate::ast::NodeId,
    /// Overall span covering the entire CREATE VIEW statement
    pub span: Span,
    /// Span covering the CREATE keyword
    pub keyword_span: Span,
    /// Optional span covering OR REPLACE clause
    pub or_replace_span: Option<Span>,
    /// Optional span covering OR ALTER clause (T-SQL)
    pub or_alter_span: Option<Span>,
    /// Optional span covering SECURE keyword
    pub secure_span: Option<Span>,
    /// MySQL `ALGORITHM = { UNDEFINED | MERGE | TEMPTABLE }` clause span.
    /// Recognition-only — a view-resolution performance hint with no governance
    /// bearing; captured so the clause round-trips. `None` when absent.
    pub algorithm_span: Option<Span>,
    /// MySQL `DEFINER = { user | CURRENT_USER }` clause. The account the view's
    /// query runs as when `sql_security` is `Definer` (the default). `None`
    /// when absent. See [`AstCreateProcedureStmt::definer`].
    pub definer: Option<AstDefiner>,
    /// MySQL `SQL SECURITY { DEFINER | INVOKER }` clause. `None` when absent.
    pub sql_security: Option<AstViewSqlSecurity>,
    /// Optional span covering temp modifiers (LOCAL/GLOBAL TEMP/TEMPORARY/VOLATILE)
    pub temp_kind_span: Option<Span>,
    /// Optional span covering RECURSIVE keyword
    pub recursive_span: Option<Span>,
    /// Span covering the VIEW keyword
    pub view_keyword_span: Span,
    /// Optional span covering IF NOT EXISTS clause
    pub if_not_exists_span: Option<Span>,
    /// Span covering the view name
    pub name_span: Span,
    /// Optional span covering the column list with optional comments/policies
    /// Format: `(col1 [COMMENT 'x'] [WITH] MASKING POLICY ..., col2, ...)`
    /// DEPRECATED: Use column_list_id for CST-based formatting
    pub columns_span: Option<Span>,
    /// Optional CST syntax node for the column list with full token tracking
    /// Enables proper trivia preservation for parens, commas, WITH keywords, etc.
    pub column_list_id: Option<crate::syntax::SyntaxViewColumnListId>,
    /// Parsed column definitions from columns_span
    pub columns: Vec<AstCreateViewColumn>,
    /// Optional span covering WITH ROW ACCESS POLICY clause (at view level)
    pub row_access_policy_span: Option<Span>,
    /// Optional span covering WITH AGGREGATION POLICY clause
    pub aggregation_policy_span: Option<Span>,
    /// Optional span covering WITH JOIN POLICY clause
    pub join_policy_span: Option<Span>,
    /// Optional span covering WITH TAG clause
    pub tag_span: Option<Span>,
    /// Optional span covering WITH CONTACT clause
    pub with_contact_span: Option<Span>,
    /// Optional span covering CHANGE_TRACKING = TRUE/FALSE
    pub change_tracking_span: Option<Span>,
    /// Optional span covering COPY GRANTS clause
    pub copy_grants_span: Option<Span>,
    /// Optional span covering COMMENT = '...' clause
    pub comment_span: Option<Span>,
    /// Optional span covering the PostgreSQL `WITH ( option [= value], ... )`
    /// view-option clause (security_invoker, security_barrier, check_option).
    pub with_options_span: Option<Span>,
    /// Typed key/value pairs inside the PostgreSQL `WITH (...)` clause.
    pub with_options: Vec<AstObjectProperty>,
    /// Span covering ALL options between view name/columns and AS keyword
    /// This preserves any unrecognized options to prevent data loss
    /// If None, there were no options. If Some, it covers the entire options region.
    pub options_span: Option<Span>,
    /// The SELECT statement defining the view (after AS keyword)
    /// Stored as Result: Ok(parsed) or Err(span) for unparseable queries
    pub query: Result<Box<AstStmt>, Span>,
    /// Optional semicolon token ID when CREATE VIEW appears in scripting/Jinja context
    pub semicolon_token: Option<crate::cst::TokenId>,

    // ---- Materialized view extensions ----
    /// Optional span covering the MATERIALIZED keyword (makes this a CREATE MATERIALIZED VIEW)
    pub materialized_span: Option<Span>,
    /// Optional span covering PARTITION BY clause (BigQuery)
    pub partition_by_span: Option<Span>,
    /// Optional span covering CLUSTER BY clause (BigQuery / Snowflake)
    pub cluster_by_span: Option<Span>,
    /// Optional span covering BigQuery OPTIONS(...) clause
    pub bq_options_span: Option<Span>,
    /// Optional span covering AS REPLICA OF source_view (BigQuery cross-region replication)
    /// When present, `query` is `Err(Span::default())` — the REPLICA OF replaces the query.
    pub replica_of_span: Option<Span>,
    /// Optional span covering a trailing `WITH NO SCHEMA BINDING` clause (Redshift
    /// late-binding views). Appears AFTER the AS query, unlike the other WITH clauses.
    pub with_no_schema_binding_span: Option<Span>,
    /// Optional span covering a trailing `WITH [NO] DATA` clause (PostgreSQL
    /// materialized views — whether to populate on creation). Appears AFTER the
    /// AS query, like `WITH NO SCHEMA BINDING`.
    pub with_data_clause_span: Option<Span>,
    /// Optional span covering a trailing `WITH [CASCADED|LOCAL] CHECK OPTION`
    /// clause (MySQL / PostgreSQL updatable views). Appears AFTER the AS query.
    pub with_check_option_span: Option<Span>,
    /// The CHECK OPTION modifier, when the clause is present.
    pub with_check_option_mode: Option<AstViewCheckOptionMode>,
}

/// Modifier on a trailing `WITH ... CHECK OPTION` view clause.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AstViewCheckOptionMode {
    /// Bare `WITH CHECK OPTION` (CASCADED semantics in MySQL and PostgreSQL).
    Default,
    Local,
    Cascaded,
}

/// Represents a column definition in CREATE VIEW column list.
/// Snowflake allows comments and policies on view columns.
#[derive(Debug, Clone)]
pub struct AstCreateViewColumn {
    pub node_id: crate::ast::NodeId,
    /// Span covering the entire column definition
    pub full_span: Span,
    /// Span covering the column name
    pub name_span: Span,
    /// Optional span covering COMMENT clause for this column
    pub comment_span: Option<Span>,
    /// Optional span covering MASKING POLICY clause
    pub masking_policy_span: Option<Span>,
    /// Optional span covering PROJECTION POLICY clause
    pub projection_policy_span: Option<Span>,
    /// Optional span covering TAG clause for this column
    pub tag_span: Option<Span>,
}

// ============================================================================
// CREATE DYNAMIC TABLE
// ============================================================================

/// CREATE DYNAMIC TABLE statement
/// Dynamic tables are materialized views that automatically refresh based on TARGET_LAG
///
/// Syntax:
/// ```sql
/// CREATE [OR REPLACE] [TRANSIENT] DYNAMIC TABLE [IF NOT EXISTS] <name> (column_defs)
///   TARGET_LAG = { '<duration>' | DOWNSTREAM }
///   WAREHOUSE = <warehouse_name>
///   [REFRESH_MODE = { AUTO | FULL | INCREMENTAL }]
///   [INITIALIZE = { ON_CREATE | ON_SCHEDULE }]
///   [CLUSTER BY (expr, ...)]
///   [... other options ...]
///   AS <query>
/// ```
#[derive(Debug, Clone)]
pub struct AstCreateDynamicTable {
    pub node_id: crate::ast::NodeId,
    /// Overall span covering the entire CREATE DYNAMIC TABLE statement
    pub span: Span,
    /// Span covering the CREATE keyword
    pub create_span: Span,
    /// Optional span covering OR REPLACE clause
    pub or_replace_span: Option<Span>,
    /// Optional span covering OR ALTER clause
    pub or_alter_span: Option<Span>,
    /// Optional span covering TRANSIENT keyword
    pub transient_span: Option<Span>,
    /// Span covering DYNAMIC keyword
    pub dynamic_span: Span,
    /// Optional span covering ICEBERG keyword (for DYNAMIC ICEBERG TABLE)
    pub iceberg_span: Option<Span>,
    /// Span covering TABLE keyword
    pub table_span: Span,
    /// Optional span covering IF NOT EXISTS clause
    pub if_not_exists_span: Option<Span>,
    /// Span covering the table name
    pub name_span: Span,
    /// Optional span covering the column definitions (parenthesized list)
    pub columns_span: Option<Span>,
    /// Span covering TARGET_LAG = ...
    pub target_lag_span: Option<Span>,
    /// Span covering WAREHOUSE = ...
    pub warehouse_span: Option<Span>,
    /// Optional span covering INITIALIZATION_WAREHOUSE = ...
    pub init_warehouse_span: Option<Span>,
    /// Optional span covering REFRESH_MODE = ...
    pub refresh_mode_span: Option<Span>,
    /// Optional span covering INITIALIZE = ...
    pub initialize_span: Option<Span>,
    /// Optional span covering CLUSTER BY (...)
    pub cluster_by_span: Option<Span>,
    /// Optional span covering DATA_RETENTION_TIME_IN_DAYS = ...
    pub data_retention_span: Option<Span>,
    /// Optional span covering MAX_DATA_EXTENSION_TIME_IN_DAYS = ...
    pub max_data_extension_span: Option<Span>,
    /// Optional span covering COMMENT = '...'
    pub comment_span: Option<Span>,
    /// Optional span covering COPY GRANTS
    pub copy_grants_span: Option<Span>,
    /// Optional span covering ROW ACCESS POLICY clause
    pub row_access_policy_span: Option<Span>,
    /// Optional span covering AGGREGATION POLICY clause
    pub aggregation_policy_span: Option<Span>,
    /// Optional span covering TAG clause
    pub tag_span: Option<Span>,
    /// Optional span covering REQUIRE USER
    pub require_user_span: Option<Span>,
    /// Optional span covering IMMUTABLE WHERE (...)
    pub immutable_where_span: Option<Span>,
    /// Optional span covering BACKFILL FROM ...
    pub backfill_from_span: Option<Span>,
    /// Span covering the AS keyword
    pub as_span: Option<Span>,
    /// The SELECT statement defining the dynamic table (after AS keyword)
    /// Stored as Result: Ok(parsed) or Err(span) for unparseable queries
    pub query: Result<Box<AstStmt>, Span>,
    /// Span covering all options between name and AS (for defensive parsing)
    pub options_span: Option<Span>,
}

// ============================================================================
// END CREATE DYNAMIC TABLE
// ============================================================================

// ============================================================================
// CREATE TASK
// ============================================================================

/// CREATE TASK statement for scheduled SQL execution
/// Snowflake tasks can run SQL statements on a schedule or after other tasks.
///
/// Syntax:
/// ```text
/// CREATE [ OR REPLACE ] [ OR ALTER ] TASK [ IF NOT EXISTS ] <name>
///   [ WAREHOUSE = <string> ]
///   [ SCHEDULE = '...' ]
///   [ CONFIG = '...' ]
///   [ ALLOW_OVERLAPPING_EXECUTION = TRUE|FALSE ]
///   [ USER_TASK_TIMEOUT_MS = <num> ]
///   [ SUSPEND_TASK_AFTER_NUM_FAILURES = <num> ]
///   [ ERROR_INTEGRATION = <string> ]
///   [ SUCCESS_INTEGRATION = <string> ]
///   [ LOG_LEVEL = ... ]
///   [ FINALIZE = <string> ]
///   [ TASK_AUTO_RETRY_ATTEMPTS = <num> ]
///   [ USER_TASK_MINIMUM_TRIGGER_INTERVAL_IN_SECONDS = <num> ]
///   [ TARGET_COMPLETION_INTERVAL = <num> ]
///   [ SERVERLESS_TASK_MIN_STATEMENT_SIZE = ... ]
///   [ SERVERLESS_TASK_MAX_STATEMENT_SIZE = ... ]
///   [ USER_TASK_MANAGED_INITIAL_WAREHOUSE_SIZE = ... ]
///   [ <session_parameter> = <value> [...] ]
///   [ COMMENT = '...' ]
///   [ WITH TAG (...) ]
///   [ AFTER <task_name> [, ...] ]
///   [ WHEN <condition> ]
///   [ EXECUTE AS { OWNER | CALLER | USER <user_name> } ]
/// AS
///   <sql>
/// ```
///
/// Or CLONE variant:
/// CREATE TASK ... CLONE <source_task_name>
#[derive(Debug, Clone)]
pub struct AstCreateTask {
    pub node_id: crate::ast::NodeId,
    /// Overall span covering the entire CREATE TASK statement
    pub span: Span,
    /// Span covering the CREATE keyword
    pub create_span: Span,
    /// Optional span covering OR REPLACE clause
    pub or_replace_span: Option<Span>,
    /// Optional span covering OR ALTER clause
    pub or_alter_span: Option<Span>,
    /// Span covering TASK keyword (note: TASK is Identifier, not Keyword)
    pub task_span: Span,
    /// Optional span covering IF NOT EXISTS clause
    pub if_not_exists_span: Option<Span>,
    /// Span covering the task name
    pub name_span: Span,

    // --------------------------------
    // Task Properties (all are Identifiers in lexer, not Keywords)
    // --------------------------------
    /// Optional span covering `WAREHOUSE = <string>`
    pub warehouse_span: Option<Span>,
    /// Optional span covering SCHEDULE = '...' (interval or CRON)
    pub schedule_span: Option<Span>,
    /// Optional span covering CONFIG = $$...$$
    pub config_span: Option<Span>,
    /// Optional span covering ALLOW_OVERLAPPING_EXECUTION = TRUE|FALSE (deprecated)
    pub allow_overlapping_execution_span: Option<Span>,
    /// Optional span covering OVERLAP_POLICY = NO_OVERLAP|ALLOW_CHILD_OVERLAP|ALLOW_ALL_OVERLAP
    pub overlap_policy_span: Option<Span>,
    /// Optional span covering `USER_TASK_TIMEOUT_MS = <num>`
    pub user_task_timeout_ms_span: Option<Span>,
    /// Optional span covering `SUSPEND_TASK_AFTER_NUM_FAILURES = <num>`
    pub suspend_task_after_num_failures_span: Option<Span>,
    /// Optional span covering `ERROR_INTEGRATION = <string>`
    pub error_integration_span: Option<Span>,
    /// Optional span covering `SUCCESS_INTEGRATION = <string>`
    pub success_integration_span: Option<Span>,
    /// Optional span covering LOG_LEVEL = ...
    pub log_level_span: Option<Span>,
    /// Optional span covering `FINALIZE = <string>`
    pub finalize_span: Option<Span>,
    /// Optional span covering `TASK_AUTO_RETRY_ATTEMPTS = <num>`
    pub task_auto_retry_attempts_span: Option<Span>,
    /// Optional span covering `USER_TASK_MINIMUM_TRIGGER_INTERVAL_IN_SECONDS = <num>`
    pub user_task_minimum_trigger_interval_span: Option<Span>,
    /// Optional span covering TARGET_COMPLETION_INTERVAL = ...
    pub target_completion_interval_span: Option<Span>,
    /// Optional span covering SERVERLESS_TASK_MIN_STATEMENT_SIZE = ...
    pub serverless_task_min_span: Option<Span>,
    /// Optional span covering SERVERLESS_TASK_MAX_STATEMENT_SIZE = ...
    pub serverless_task_max_span: Option<Span>,
    /// Optional span covering USER_TASK_MANAGED_INITIAL_WAREHOUSE_SIZE = ...
    pub user_task_managed_initial_warehouse_size_span: Option<Span>,
    /// Optional span covering COMMENT = '...'
    pub comment_span: Option<Span>,

    // --------------------------------
    // Session Parameters (arbitrary key=value pairs)
    // --------------------------------
    /// Spans for session parameters (e.g., TIMEZONE = 'UTC')
    pub session_parameters_spans: Vec<Span>,

    // --------------------------------
    // Task Dependencies and Execution
    // --------------------------------
    /// Optional span covering WITH TAG (...)
    pub with_tag_span: Option<Span>,
    /// Optional span covering AFTER task1 [, task2, ...]
    pub after_span: Option<Span>,
    /// Optional span covering `WHEN <condition>`
    pub when_span: Option<Span>,
    /// Optional span covering `EXECUTE AS OWNER|CALLER|USER <name>`
    pub execute_as_span: Option<Span>,

    // --------------------------------
    // Body or Clone
    // --------------------------------
    /// Span covering the AS keyword (if not a CLONE)
    pub as_span: Option<Span>,
    /// The SQL statement body (stored procedure call, EXECUTE IMMEDIATE, or SQL statement)
    /// Stored as Result: Ok(parsed) or Err(span) for unparseable content
    pub body: Option<Result<Box<AstStmt>, Span>>,
    /// Optional span covering CLONE <source_task_name>
    pub clone_span: Option<Span>,

    // --------------------------------
    // Defensive Design
    // --------------------------------
    /// Unknown properties/clauses not recognized by parser.
    /// When Snowflake adds new TASK properties, they are preserved here
    /// instead of causing parse errors.
    pub extras: Vec<crate::ast::AstUnknownClause>,
}

// ============================================================================
// END CREATE TASK
// ============================================================================

// ============================================================================
// DROP TASK
// ============================================================================

/// `DROP TASK [IF EXISTS] <name>`
///
/// Removes a task from the current/specified schema.
#[derive(Debug, Clone)]
pub struct AstDropTask {
    pub node_id: crate::ast::NodeId,
    /// Span covering the entire DROP TASK statement
    pub span: Span,
    /// Span covering the DROP keyword
    pub drop_span: Span,
    /// Span covering the TASK keyword (note: TASK is Identifier, not Keyword)
    pub task_span: Span,
    /// Optional span covering IF EXISTS clause
    pub if_exists_span: Option<Span>,
    /// Span covering the task name (may be qualified: db.schema.task)
    pub name_span: Span,
}

// ============================================================================
// END DROP TASK
// ============================================================================

// ============================================================================
// ALTER TASK
// ============================================================================

/// `ALTER TASK [IF EXISTS] <name> <action>`
///
/// Modifies the properties for an existing task.
/// Supports multiple action types: RESUME, SUSPEND, SET, UNSET, MODIFY, etc.
#[derive(Debug, Clone)]
pub struct AstAlterTask {
    pub node_id: crate::ast::NodeId,
    /// Span covering the entire ALTER TASK statement
    pub span: Span,
    /// Span covering the ALTER keyword
    pub alter_span: Span,
    /// Span covering the TASK keyword (note: TASK is Identifier, not Keyword)
    pub task_span: Span,
    /// Optional span covering IF EXISTS clause
    pub if_exists_span: Option<Span>,
    /// Span covering the task name (may be qualified: db.schema.task)
    pub name_span: Span,
    /// Span covering the action (everything after the task name)
    pub action_span: Span,
    /// Parsed action
    pub action: AstAlterTaskAction,
    /// Unknown actions/properties not recognized by parser (defensive design)
    pub extras: Vec<crate::ast::AstUnknownClause>,
}

/// One ALTER TASK action
#[derive(Debug, Clone)]
pub struct AstAlterTaskAction {
    pub node_id: crate::ast::NodeId,
    /// Span covering the entire action
    pub span: Span,
    /// The action kind
    pub kind: AstAlterTaskActionKind,
}

/// ALTER TASK action variants
#[derive(Debug, Clone)]
pub enum AstAlterTaskActionKind {
    /// RESUME - brings a suspended task to 'Started' state
    Resume { resume_span: Span },
    /// SUSPEND - puts the task into 'Suspended' state
    Suspend { suspend_span: Span },
    /// ADD AFTER <task_name> [, <task_name>, ...] - add predecessor tasks
    AddAfter {
        add_span: Span,
        after_span: Span,
        /// Spans covering the predecessor task names
        task_names_span: Span,
    },
    /// REMOVE AFTER <task_name> [, <task_name>, ...] - remove predecessor tasks
    RemoveAfter {
        remove_span: Span,
        after_span: Span,
        /// Spans covering the predecessor task names
        task_names_span: Span,
    },
    /// `SET <property> = <value> [...]` - set one or more properties
    Set {
        set_span: Span,
        /// Span covering all property assignments
        properties_span: Span,
    },
    /// `SET TAG <tag_name> = '<value>' [, ...]` - set tags
    SetTag {
        set_span: Span,
        tag_span: Span,
        /// Span covering tag assignments
        assignments_span: Span,
    },
    /// SET FINALIZE = <root_task> - set finalizer task
    SetFinalize {
        set_span: Span,
        finalize_span: Span,
        /// Span covering the root task name
        value_span: Span,
    },
    /// `UNSET <property> [, <property>, ...]` - unset properties
    Unset {
        unset_span: Span,
        /// Span covering property names to unset
        properties_span: Span,
    },
    /// UNSET TAG <tag_name> [, ...] - unset tags
    UnsetTag {
        unset_span: Span,
        tag_span: Span,
        /// Span covering tag names
        tags_span: Span,
    },
    /// UNSET FINALIZE - remove finalizer
    UnsetFinalize {
        unset_span: Span,
        finalize_span: Span,
    },
    /// `MODIFY AS <sql>` - change the SQL statement body
    ModifyAs {
        modify_span: Span,
        as_span: Span,
        /// The SQL statement body (parsed or unparseable span)
        body: Result<Box<AstStmt>, Span>,
    },
    /// MODIFY WHEN <boolean_expr> - change the WHEN condition
    ModifyWhen {
        modify_span: Span,
        when_span: Span,
        /// Span covering the condition expression
        condition_span: Span,
    },
    /// REMOVE WHEN - remove the WHEN condition
    RemoveWhen { remove_span: Span, when_span: Span },
}

// ============================================================================
// END ALTER TASK
// ============================================================================

// ============================================================================
// WAREHOUSE STATEMENTS (Snowflake)
// ============================================================================

/// CREATE [OR REPLACE] WAREHOUSE [IF NOT EXISTS] name [properties...]
///
/// Properties include WAREHOUSE_SIZE, AUTO_SUSPEND, AUTO_RESUME,
/// INITIALLY_SUSPENDED, RESOURCE_MONITOR, COMMENT, ENABLE_QUERY_ACCELERATION,
/// MAX_CONCURRENCY_LEVEL, WAREHOUSE_TYPE, MIN_CLUSTER_COUNT, MAX_CLUSTER_COUNT,
/// SCALING_POLICY, TAG, etc.
///
/// The parser captures known properties as individual spans and uses the
/// extras pattern for unrecognized properties (defensive design).
#[derive(Debug, Clone)]
pub struct AstCreateWarehouse {
    pub node_id: crate::ast::NodeId,
    /// Span covering the entire CREATE WAREHOUSE statement
    pub span: Span,
    /// Span covering the CREATE keyword
    pub create_span: Span,
    /// Span covering WAREHOUSE keyword (note: Identifier, not Keyword)
    pub warehouse_span: Span,
    /// Optional span covering OR REPLACE
    pub or_replace_span: Option<Span>,
    /// Optional span covering IF NOT EXISTS
    pub if_not_exists_span: Option<Span>,
    /// Span covering the warehouse name (may be qualified)
    pub name_span: Span,

    // Properties (all Identifiers in lexer)
    /// Optional span covering WAREHOUSE_SIZE = '...'
    pub warehouse_size_span: Option<Span>,
    /// Optional span covering `AUTO_SUSPEND = <num>`
    pub auto_suspend_span: Option<Span>,
    /// Optional span covering AUTO_RESUME = TRUE|FALSE
    pub auto_resume_span: Option<Span>,
    /// Optional span covering INITIALLY_SUSPENDED = TRUE|FALSE
    pub initially_suspended_span: Option<Span>,
    /// Optional span covering `RESOURCE_MONITOR = <name>`
    pub resource_monitor_span: Option<Span>,
    /// Optional span covering COMMENT = '...'
    pub comment_span: Option<Span>,
    /// Optional span covering ENABLE_QUERY_ACCELERATION = TRUE|FALSE
    pub enable_query_acceleration_span: Option<Span>,
    /// Optional span covering `QUERY_ACCELERATION_MAX_SCALE_FACTOR = <num>`
    pub query_acceleration_max_scale_factor_span: Option<Span>,
    /// Optional span covering `MAX_CONCURRENCY_LEVEL = <num>`
    pub max_concurrency_level_span: Option<Span>,
    /// Optional span covering `STATEMENT_QUEUED_TIMEOUT_IN_SECONDS = <num>`
    pub statement_queued_timeout_span: Option<Span>,
    /// Optional span covering `STATEMENT_TIMEOUT_IN_SECONDS = <num>`
    pub statement_timeout_span: Option<Span>,
    /// Optional span covering WAREHOUSE_TYPE = 'STANDARD'|'SNOWPARK-OPTIMIZED'
    pub warehouse_type_span: Option<Span>,
    /// Optional span covering `MIN_CLUSTER_COUNT = <num>`
    pub min_cluster_count_span: Option<Span>,
    /// Optional span covering `MAX_CLUSTER_COUNT = <num>`
    pub max_cluster_count_span: Option<Span>,
    /// Optional span covering SCALING_POLICY = 'STANDARD'|'ECONOMY'
    pub scaling_policy_span: Option<Span>,
    /// Optional span covering TAG (key = 'value', ...)
    pub tag_span: Option<Span>,
    /// Unknown properties — defensive design for future Snowflake additions
    pub extras: Vec<crate::ast::AstUnknownClause>,
}

/// ALTER WAREHOUSE [IF EXISTS] name { action }
///
/// Actions include SUSPEND, RESUME, ABORT ALL QUERIES, RENAME TO,
/// SET properties, UNSET properties, SET/UNSET TAG.
#[derive(Debug, Clone)]
pub struct AstAlterWarehouse {
    pub node_id: crate::ast::NodeId,
    /// Span covering the entire ALTER WAREHOUSE statement
    pub span: Span,
    /// Span covering the ALTER keyword
    pub alter_span: Span,
    /// Span covering WAREHOUSE keyword (Identifier)
    pub warehouse_span: Span,
    /// Optional span covering IF EXISTS
    pub if_exists_span: Option<Span>,
    /// Span covering the warehouse name (may be qualified)
    pub name_span: Span,
    /// Span covering the action portion (everything after name)
    pub action_span: Span,
    /// Parsed action kind
    pub action: AstAlterWarehouseAction,
    /// Unknown actions/properties — defensive design
    pub extras: Vec<crate::ast::AstUnknownClause>,
}

/// One ALTER WAREHOUSE action
#[derive(Debug, Clone)]
pub struct AstAlterWarehouseAction {
    pub span: Span,
    pub kind: AstAlterWarehouseActionKind,
}

/// ALTER WAREHOUSE action variants
#[derive(Debug, Clone)]
pub enum AstAlterWarehouseActionKind {
    /// SUSPEND
    Suspend { suspend_span: Span },
    /// RESUME [IF SUSPENDED]
    Resume { resume_span: Span },
    /// ABORT ALL QUERIES
    AbortAllQueries { abort_span: Span },
    /// RENAME TO <new_name>
    RenameTo {
        rename_span: Span,
        to_span: Span,
        new_name_span: Span,
    },
    /// SET property = value [property = value ...]
    Set {
        set_span: Span,
        properties_span: Span,
    },
    /// UNSET property [, property ...]
    Unset {
        unset_span: Span,
        properties_span: Span,
    },
    /// SET TAG (key = 'value', ...)
    SetTag {
        set_span: Span,
        tag_span: Span,
        assignments_span: Span,
    },
    /// UNSET TAG (key, ...)
    UnsetTag {
        unset_span: Span,
        tag_span: Span,
        names_span: Span,
    },
}

/// DROP WAREHOUSE [IF EXISTS] name
#[derive(Debug, Clone)]
pub struct AstDropWarehouse {
    pub node_id: crate::ast::NodeId,
    /// Span covering the entire DROP WAREHOUSE statement
    pub span: Span,
    /// Span covering the DROP keyword
    pub drop_span: Span,
    /// Span covering WAREHOUSE keyword (Identifier)
    pub warehouse_span: Span,
    /// Optional span covering IF EXISTS
    pub if_exists_span: Option<Span>,
    /// Span covering the warehouse name
    pub name_span: Span,
}

// ============================================================================
// END WAREHOUSE STATEMENTS
// ============================================================================

// ============================================================================
// PIPE STATEMENTS (Snowflake)
// ============================================================================

/// CREATE [OR REPLACE] PIPE [IF NOT EXISTS] name [properties...] AS COPY INTO ...
///
/// Properties include AUTO_INGEST, ERROR_INTEGRATION, AWS_SNS_TOPIC,
/// INTEGRATION, COMMENT. The AS COPY INTO body is preserved as a span.
#[derive(Debug, Clone)]
pub struct AstCreatePipe {
    pub node_id: crate::ast::NodeId,
    /// Span covering the entire CREATE PIPE statement
    pub span: Span,
    /// Span covering the CREATE keyword
    pub create_span: Span,
    /// Span covering PIPE keyword (Identifier, not Keyword)
    pub pipe_span: Span,
    /// Optional span covering OR REPLACE
    pub or_replace_span: Option<Span>,
    /// Optional span covering IF NOT EXISTS
    pub if_not_exists_span: Option<Span>,
    /// Span covering the pipe name (may be qualified)
    pub name_span: Span,

    // Properties
    /// Optional span covering AUTO_INGEST = TRUE|FALSE
    pub auto_ingest_span: Option<Span>,
    /// Optional span covering AWS_SNS_TOPIC = '...'
    pub aws_sns_topic_span: Option<Span>,
    /// Optional span covering INTEGRATION = '...'
    pub integration_span: Option<Span>,
    /// Optional span covering ERROR_INTEGRATION = '...'
    pub error_integration_span: Option<Span>,
    /// Optional span covering COMMENT = '...'
    pub comment_span: Option<Span>,

    /// Optional span covering the AS keyword
    pub as_span: Option<Span>,
    /// Span covering the COPY INTO body (everything after AS)
    pub copy_body_span: Option<Span>,

    /// Unknown properties — defensive design
    pub extras: Vec<crate::ast::AstUnknownClause>,
}

/// ALTER PIPE [IF EXISTS] name { SET properties | SET/UNSET TAG | REFRESH }
#[derive(Debug, Clone)]
pub struct AstAlterPipe {
    pub node_id: crate::ast::NodeId,
    /// Span covering the entire ALTER PIPE statement
    pub span: Span,
    /// Span covering the ALTER keyword
    pub alter_span: Span,
    /// Span covering PIPE keyword (Identifier)
    pub pipe_span: Span,
    /// Optional span covering IF EXISTS
    pub if_exists_span: Option<Span>,
    /// Span covering the pipe name (may be qualified)
    pub name_span: Span,
    /// Span covering the action portion
    pub action_span: Span,
    /// Parsed action kind
    pub action: AstAlterPipeAction,
    /// Unknown actions/properties — defensive design
    pub extras: Vec<crate::ast::AstUnknownClause>,
}

/// One ALTER PIPE action
#[derive(Debug, Clone)]
pub struct AstAlterPipeAction {
    pub span: Span,
    pub kind: AstAlterPipeActionKind,
}

/// ALTER PIPE action variants
#[derive(Debug, Clone)]
pub enum AstAlterPipeActionKind {
    /// SET property = value [...]
    Set {
        set_span: Span,
        properties_span: Span,
    },
    /// SET TAG (key = 'value', ...)
    SetTag {
        set_span: Span,
        tag_span: Span,
        assignments_span: Span,
    },
    /// UNSET TAG (key, ...)
    UnsetTag {
        unset_span: Span,
        tag_span: Span,
        names_span: Span,
    },
    /// `REFRESH [PREFIX = '<path>'] [MODIFIED_BEFORE = '<timestamp>']`
    Refresh {
        refresh_span: Span,
        options_span: Option<Span>,
    },
}

/// DROP PIPE [IF EXISTS] name
#[derive(Debug, Clone)]
pub struct AstDropPipe {
    pub node_id: crate::ast::NodeId,
    /// Span covering the entire DROP PIPE statement
    pub span: Span,
    /// Span covering the DROP keyword
    pub drop_span: Span,
    /// Span covering PIPE keyword (Identifier)
    pub pipe_span: Span,
    /// Optional span covering IF EXISTS
    pub if_exists_span: Option<Span>,
    /// Span covering the pipe name
    pub name_span: Span,
}

// ============================================================================
// END PIPE STATEMENTS
// ============================================================================

// ============================================================================
// CREATE STREAM
// ============================================================================

/// Source type for a stream (what the stream is tracking changes on)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamSourceType {
    /// `ON TABLE <name>`
    Table,
    /// `ON EVENT TABLE <name>`
    EventTable,
    /// `ON EXTERNAL TABLE <name>`
    ExternalTable,
    /// `ON STAGE <name>` (for directory tables)
    Stage,
    /// `ON DYNAMIC TABLE <name>`
    DynamicTable,
    /// `ON VIEW <name>`
    View,
}

/// Time travel specifier for CREATE STREAM (AT or BEFORE clause)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeTravelKind {
    /// AT (inclusive of changes at the specified point)
    At,
    /// BEFORE (exclusive, before the specified point)
    Before,
}

/// Time travel option (what parameter is used to specify the point in time)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeTravelOption {
    /// TIMESTAMP => <timestamp_expr>
    Timestamp,
    /// OFFSET => <time_difference>
    Offset,
    /// STATEMENT => '<statement_id>'
    Statement,
    /// STREAM => '<stream_name>' (copy offset from another stream)
    Stream,
}

/// CREATE STREAM statement
///
/// Creates a stream to track DML changes on a source object (table, view, stage, etc.)
///
/// ## Grammar (from Snowflake docs)
///
/// ```text
/// CREATE [ OR REPLACE ] STREAM [ IF NOT EXISTS ] <name>
///   [ [ WITH ] TAG ( <tag_name> = '<value>' [ , ... ] ) ]
///   [ COPY GRANTS ]
///   ON { TABLE | VIEW | STAGE | EXTERNAL TABLE | EVENT TABLE | DYNAMIC TABLE } <source_name>
///   [ { AT | BEFORE } ( { TIMESTAMP => <ts> | OFFSET => <diff> | STATEMENT => <id> | STREAM => '<name>' } ) ]
///   [ APPEND_ONLY = TRUE | FALSE ]
///   [ SHOW_INITIAL_ROWS = TRUE | FALSE ]
///   [ INSERT_ONLY = TRUE ]
///   [ COMMENT = '<string>' ]
///
/// Or CLONE variant:
/// CREATE [ OR REPLACE ] STREAM <name> CLONE <source_stream> [ COPY GRANTS ]
/// ```
#[derive(Debug, Clone)]
pub struct AstCreateStream {
    pub node_id: crate::ast::NodeId,
    /// Syntax layer ID for CST access
    pub syntax_id: Option<crate::syntax::SyntaxCreateStreamId>,
    /// Span covering the entire CREATE STREAM statement
    pub span: Span,
    /// Span covering the CREATE keyword
    pub create_span: Span,
    /// Optional span covering OR REPLACE clause
    pub or_replace_span: Option<Span>,
    /// Span covering STREAM identifier (note: STREAM is Identifier, not Keyword)
    pub stream_span: Span,
    /// Optional span covering IF NOT EXISTS clause
    pub if_not_exists_span: Option<Span>,
    /// Span covering the stream name
    pub name_span: Span,

    /// Optional span covering `[ WITH ] TAG ( ... )`
    pub tag_clause_span: Option<Span>,
    /// Optional span covering COPY GRANTS
    pub copy_grants_span: Option<Span>,

    /// Span covering ON <source_type> (includes ON keyword and type specifier)
    pub on_clause_span: Option<Span>,
    /// Source type (Table, View, Stage, etc.) - None for CLONE variant
    pub source_type: Option<StreamSourceType>,
    /// Span covering the source object name - None for CLONE variant
    pub source_name_span: Option<Span>,

    /// Optional span covering AT/BEFORE ( ... ) time travel clause
    pub time_travel_span: Option<Span>,
    /// Time travel kind (At or Before) - if time_travel_span is Some
    pub time_travel_kind: Option<TimeTravelKind>,
    /// Time travel option (Timestamp, Offset, Statement, Stream)
    pub time_travel_option: Option<TimeTravelOption>,

    /// Optional span covering APPEND_ONLY = TRUE|FALSE
    pub append_only_span: Option<Span>,
    /// Optional span covering SHOW_INITIAL_ROWS = TRUE|FALSE
    pub show_initial_rows_span: Option<Span>,
    /// Optional span covering INSERT_ONLY = TRUE|FALSE
    pub insert_only_span: Option<Span>,
    /// Optional span covering COMMENT = '...'
    pub comment_span: Option<Span>,

    /// Optional span covering CLONE <source_stream> (for clone variant)
    pub clone_span: Option<Span>,
}

// ============================================================================
// END CREATE STREAM
// ============================================================================

// ============================================================================
// DROP STREAM
// ============================================================================

/// `DROP STREAM [ IF EXISTS ] <name>`
///
/// Removes a stream from the current/specified schema.
#[derive(Debug, Clone)]
pub struct AstDropStream {
    pub node_id: crate::ast::NodeId,
    /// Syntax layer ID for CST access
    pub syntax_id: Option<crate::syntax::SyntaxDropStreamId>,
    /// Span covering the entire DROP STREAM statement
    pub span: Span,
    /// Span covering the DROP keyword
    pub drop_span: Span,
    /// Span covering the STREAM identifier (note: STREAM is Identifier, not Keyword)
    pub stream_span: Span,
    /// Optional span covering IF EXISTS clause
    pub if_exists_span: Option<Span>,
    /// Span covering the stream name (may be qualified: db.schema.stream)
    pub name_span: Span,
}

// ============================================================================
// END DROP STREAM
// ============================================================================

// ============================================================================
// ALTER STREAM
// ============================================================================

/// `ALTER STREAM [ IF EXISTS ] <name> <action>`
///
/// Modifies the properties for an existing stream.
/// Supports: SET COMMENT, UNSET COMMENT, SET TAG, UNSET TAG
#[derive(Debug, Clone)]
pub struct AstAlterStream {
    pub node_id: crate::ast::NodeId,
    /// Syntax layer ID for CST access
    pub syntax_id: Option<crate::syntax::SyntaxAlterStreamStmtId>,
    /// Span covering the entire ALTER STREAM statement
    pub span: Span,
    /// Span covering the ALTER keyword
    pub alter_span: Span,
    /// Span covering the STREAM identifier (note: STREAM is Identifier, not Keyword)
    pub stream_span: Span,
    /// Optional span covering IF EXISTS clause
    pub if_exists_span: Option<Span>,
    /// Span covering the stream name (may be qualified: db.schema.stream)
    pub name_span: Span,
    /// Span covering the action (everything after the stream name)
    pub action_span: Span,
    /// Parsed action
    pub action: AstAlterStreamAction,
}

/// One ALTER STREAM action
#[derive(Debug, Clone)]
pub struct AstAlterStreamAction {
    /// Span covering the entire action
    pub span: Span,
    /// The action kind
    pub kind: AstAlterStreamActionKind,
}

/// ALTER STREAM action variants
#[derive(Debug, Clone)]
pub enum AstAlterStreamActionKind {
    /// `SET COMMENT = '<string>'`
    SetComment {
        set_span: Span,
        comment_span: Span,
        /// Span covering the string literal value
        value_span: Span,
    },
    /// UNSET COMMENT
    UnsetComment {
        unset_span: Span,
        comment_span: Span,
    },
    /// `SET TAG <tag_name> = '<value>' [, ...]`
    SetTag {
        set_span: Span,
        tag_span: Span,
        /// Span covering all tag assignments
        assignments_span: Span,
    },
    /// UNSET TAG <tag_name> [, ...]
    UnsetTag {
        unset_span: Span,
        tag_span: Span,
        /// Span covering all tag names
        tags_span: Span,
    },
}

// ============================================================================
// END ALTER STREAM
// ============================================================================

/// CREATE STAGE statement for internal or external stages
/// Snowflake stages are used for loading/unloading data
#[derive(Debug, Clone)]
pub struct AstCreateStage {
    pub node_id: crate::ast::NodeId,
    /// Span covering the entire CREATE STAGE statement
    pub span: Span,
    /// Span covering CREATE keyword
    pub create_span: Span,
    /// Optional OR REPLACE span
    pub or_replace_span: Option<Span>,
    /// Optional TEMPORARY/TEMP span
    pub temporary_span: Option<Span>,
    /// Span covering STAGE keyword
    pub stage_keyword_span: Span,
    /// Optional IF NOT EXISTS span
    pub if_not_exists_span: Option<Span>,
    /// Span covering the stage name
    pub name_span: Span,
    /// Stage type (Internal or External based on presence of URL)
    pub stage_type: AstStageType,
    /// Optional URL clause for external stages (URL = '...')
    pub url_clause: Option<AstStageUrlClause>,
    /// Optional STORAGE_INTEGRATION or CREDENTIALS clause
    pub credentials_clause: Option<AstStageCredentialsClause>,
    /// Optional ENCRYPTION clause
    pub encryption_clause: Option<Span>,
    /// Optional ENDPOINT clause for S3-compatible storage
    pub endpoint_clause: Option<Span>,
    /// Optional DIRECTORY clause for directory tables
    pub directory_clause: Option<Span>,
    /// Optional FILE_FORMAT clause
    pub file_format_clause: Option<AstStageFileFormatClause>,
    /// Optional COMMENT clause
    pub comment_span: Option<Span>,
    /// Optional TAG clause (span-based, not parsed into details)
    pub tag_clause: Option<Span>,
    /// Optional CLONE clause
    pub clone_clause: Option<Span>,

    /// Unknown properties/clauses not recognized by parser (defensive design).
    ///
    /// When Snowflake adds new CREATE STAGE properties, they are preserved here
    /// instead of causing parse errors. The formatter emits them unchanged,
    /// ensuring semantic preservation even when syntax is unrecognized.
    ///
    /// This field should remain empty under normal circumstances - presence of
    /// entries indicates either:
    /// 1. A new Snowflake feature added after this parser was written
    /// 2. Non-standard/custom syntax in the source
    ///
    /// Diagnostics should warn when this is non-empty.
    pub extras: Vec<AstUnknownClause>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AstStageType {
    /// Internal stage (no URL specified)
    Internal,
    /// External stage (URL specified)
    External,
}

/// URL clause for external stages: URL = 'protocol://bucket/path'
#[derive(Debug, Clone)]
pub struct AstStageUrlClause {
    pub node_id: crate::ast::NodeId,
    /// Span covering the entire URL = '...' clause
    pub span: Span,
    /// Span covering the URL keyword
    pub url_keyword_span: Span,
    /// Span covering the URL string literal value
    pub url_value_span: Span,
    /// Parsed URL string content (quotes stripped, `''` escapes folded).
    /// Empty when the value side is not a string literal (parameter,
    /// identifier) — downstream content predicates simply won't match.
    pub url_text: String,
}

/// Credentials clause (STORAGE_INTEGRATION or CREDENTIALS)
#[derive(Debug, Clone)]
pub struct AstStageCredentialsClause {
    pub node_id: crate::ast::NodeId,
    /// Span covering the entire clause
    pub span: Span,
    /// Type of credentials (storage integration vs direct credentials)
    pub kind: AstStageCredentialsKind,
    /// Decomposed `KEY = VALUE` options from `CREDENTIALS=(...)`. Empty
    /// when `kind == StorageIntegration` (the integration name flows
    /// through `integration_name_span`) or when the parser could not
    /// decompose the clause body (defensive zero-loss fallback).
    pub options: Vec<AstStageCredentialOption>,
    /// Span of the integration name when `kind == StorageIntegration`;
    /// `None` for the inline `CREDENTIALS=(...)` arm.
    pub integration_name_span: Option<Span>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AstStageCredentialsKind {
    /// STORAGE_INTEGRATION = integration_name
    StorageIntegration,
    /// CREDENTIALS = ( AWS_KEY_ID = '...' ... )
    Credentials,
}

/// One `KEY = VALUE` pair parsed from a `CREDENTIALS=(...)` clause.
#[derive(Debug, Clone)]
pub struct AstStageCredentialOption {
    pub node_id: crate::ast::NodeId,
    /// Span covering the full `KEY = VALUE` triple.
    pub span: Span,
    /// Span covering just the option name (e.g. `AWS_KEY_ID`).
    pub name_span: Span,
    /// Parsed value side of the option.
    pub value: AstStageCredentialOptionValue,
}

/// One `NAME = VALUE` copy option parsed from a COPY INTO statement
/// (e.g. `ON_ERROR = CONTINUE`, `PURGE = TRUE`, `FILE_FORMAT = (...)`).
/// Captured loss-free as recognition spans; whether a given option/value
/// is risky is the consumer's decision, never made here.
#[derive(Debug, Clone)]
pub struct AstCopyOption {
    pub node_id: crate::ast::NodeId,
    /// Span covering the full `NAME = VALUE` option.
    pub span: Span,
    /// Span covering just the option name (e.g. `ON_ERROR`).
    pub name_span: Span,
    /// Span covering the value side — a scalar token, or the full `(...)`
    /// block for parenthesized values such as `FILE_FORMAT = (...)`.
    pub value_span: Span,
}

/// The source side of a `COPY INTO <location> FROM <source>` (unload): a
/// table reference or a parenthesized subquery. Captured structurally so
/// the egress point can analyze the classification of the columns leaving
/// the warehouse.
#[derive(Debug, Clone)]
pub enum AstUnloadSource {
    /// `FROM <db.schema.table>` — the whole table is unloaded.
    Table {
        /// Span covering the (possibly qualified) table name.
        name_span: Span,
    },
    /// `FROM (<query>)` — the subquery's projected columns are unloaded.
    Subquery(Box<AstStmt>),
}

/// Value side of a credential option. `StringLiteral` carries the
/// content with surrounding quotes stripped and `''` escapes folded;
/// `Other` is the opaque escape for parameters / identifiers / numerics
/// that downstream content predicates do not inspect.
#[derive(Debug, Clone)]
pub enum AstStageCredentialOptionValue {
    StringLiteral { span: Span, text: String },
    Other { span: Span },
}

/// FILE_FORMAT clause for stages
#[derive(Debug, Clone)]
pub struct AstStageFileFormatClause {
    pub node_id: crate::ast::NodeId,
    /// Span covering the entire FILE_FORMAT clause
    pub span: Span,
    /// Span covering FILE_FORMAT keyword
    pub keyword_span: Span,
    /// Format specification (FORMAT_NAME or TYPE with options)
    pub format_spec: AstStageFileFormatSpec,
}

/// CREATE ROW ACCESS POLICY statement.
///
/// Supports both Snowflake and BigQuery syntax (permissive parsing):
///
/// Snowflake: CREATE [OR REPLACE] ROW ACCESS POLICY name AS (arg type, ...) RETURNS BOOLEAN -> body_expr [COMMENT = '...']
/// BigQuery:  CREATE [OR REPLACE] ROW ACCESS POLICY [IF NOT EXISTS] name ON table [GRANT TO (grantees)] FILTER USING (expr)
///
/// The parser detects the variant by token presence (ON → BigQuery, AS → Snowflake).
#[derive(Debug, Clone)]
pub struct AstCreateRowAccessPolicy {
    pub node_id: crate::ast::NodeId,
    /// Span covering the entire CREATE ROW ACCESS POLICY statement
    pub span: Span,
    /// Optional typed-syntax node id for this statement
    pub syntax_id: Option<crate::syntax::SyntaxCreateRowAccessPolicyId>,

    // Keyword spans (for semantic tracking and governance)
    pub create_span: Span,
    pub or_replace_span: Option<Span>,
    pub row_span: Span,
    pub access_span: Span,
    pub policy_span: Span,

    /// Span covering the policy name identifier
    pub policy_name_span: Span,

    // ---- BigQuery-specific fields (None for Snowflake) ----
    /// IF NOT EXISTS span (BigQuery only)
    pub if_not_exists_span: Option<Span>,

    /// ON keyword span (BigQuery: ON table_name)
    pub on_table_span: Option<Span>,

    /// Span covering the table name in ON clause (BigQuery: project.dataset.table)
    pub table_name_span: Option<Span>,

    /// GRANT TO keyword span (BigQuery: GRANT TO (...))
    pub grant_to_span: Option<Span>,

    /// Grantee identifier spans inside GRANT TO (...) (BigQuery)
    pub grantee_spans: Vec<Span>,

    /// Span covering entire GRANT TO (...) clause including parens (BigQuery)
    pub grant_to_clause_span: Option<Span>,

    /// FILTER USING keyword span (BigQuery: FILTER USING (...))
    pub filter_using_span: Option<Span>,

    /// Span covering entire FILTER USING (...) clause including parens (BigQuery)
    pub filter_using_clause_span: Option<Span>,

    /// Parsed filter expression (BigQuery)
    pub filter_expr: Option<Box<AstExpr>>,

    // ---- Snowflake-specific fields (None for BigQuery) ----
    /// AS keyword span (Snowflake only)
    pub as_span: Option<Span>,

    /// Signature: (arg_name data_type, ...) (Snowflake only)
    /// Span covering the entire signature including parentheses
    pub signature_span: Option<Span>,

    /// RETURNS BOOLEAN span (Snowflake only, optional in older syntax)
    pub returns_span: Option<Span>,

    /// Arrow operator span (->) (Snowflake only)
    pub arrow_span: Option<Span>,

    /// Body expression span (Snowflake: boolean predicate)
    pub body_expr_span: Option<Span>,

    /// Optional COMMENT clause span (Snowflake only)
    pub comment_span: Option<Span>,

    // Parsed semantic structures (Snowflake)
    /// Parsed policy parameters from signature (Snowflake only)
    pub parameters: Vec<AstPolicyParameter>,

    /// Parsed body expression (Snowflake: boolean predicate)
    pub body: Option<Box<AstExpr>>,
}

/// A single parameter in a ROW ACCESS POLICY signature.
///
/// Example: `user_id INTEGER` in `AS (user_id INTEGER, dept VARCHAR)`
#[derive(Debug, Clone)]
pub struct AstPolicyParameter {
    pub node_id: crate::ast::NodeId,
    /// Span covering the full parameter declaration
    pub span: Span,
    /// Span covering the parameter name
    pub name_span: Span,
    /// Span covering the data type
    pub type_span: Span,
}

/// ALTER TABLE statement.
///
/// This is a semantics-oriented AST node intended for policy/risk extraction.
/// The parser implementation can progressively populate more structured fields
/// while remaining span-safe (unknown sub-clauses should be preserved via spans).
#[derive(Debug, Clone)]
pub struct AstAlterTable {
    pub node_id: crate::ast::NodeId,
    /// Span covering the entire ALTER TABLE statement.
    pub span: Span,
    /// Optional typed-syntax node id for this statement.
    pub syntax_id: Option<crate::syntax::SyntaxAlterTableStmtId>,
    /// Span covering the ALTER keyword.
    pub alter_span: Span,
    /// Span covering the TABLE keyword.
    pub table_span: Span,
    /// Optional span covering IF EXISTS.
    pub if_exists_span: Option<Span>,
    /// Span covering the table name / object reference.
    pub name_span: Span,
    /// Span covering the action list (everything after the table name).
    pub actions_span: Span,
    /// Parsed actions. When parsing is incomplete, this may be empty even if
    /// actions_span is non-empty; callers should treat that as partial coverage.
    pub actions: Vec<AstAlterTableAction>,
}

/// One ALTER TABLE action.
#[derive(Debug, Clone)]
pub struct AstAlterTableAction {
    pub node_id: crate::ast::NodeId,
    /// Span covering the entire action.
    pub span: Span,
    /// Optional typed-syntax node id for this action.
    pub syntax_id: Option<crate::syntax::SyntaxAlterTableActionId>,
    pub kind: AstAlterTableActionKind,
}

// ============================================================================
// Boxed structs for large ALTER TABLE action variants
// ============================================================================

/// ADD ROW ACCESS POLICY action data (boxed in enum)
#[derive(Debug, Clone)]
pub struct AddRowAccessPolicyAction {
    pub add_span: Option<Span>,
    pub row_span: Option<Span>,
    pub access_span: Option<Span>,
    pub policy_span: Option<Span>,
    pub policy_name_span: Span,
    pub on_span: Option<Span>,
    pub columns_span: Span,
    /// Column names as spans
    pub columns: Vec<Span>,
}

/// ALTER COLUMN SET MASKING POLICY action data (boxed in enum)
#[derive(Debug, Clone)]
pub struct SetColumnMaskingPolicyAction {
    pub alter_span: Option<Span>,
    pub column_span: Option<Span>,
    pub column_name_span: Span,
    pub set_span: Option<Span>,
    pub masking_span: Option<Span>,
    pub policy_span: Option<Span>,
    pub policy_name_span: Span,
    pub using_span: Option<Span>,
    pub force_span: Option<Span>,
}

/// ALTER COLUMN SET PROJECTION POLICY action data (boxed in enum)
#[derive(Debug, Clone)]
pub struct SetColumnProjectionPolicyAction {
    pub alter_span: Option<Span>,
    pub column_span: Option<Span>,
    pub column_name_span: Span,
    pub set_span: Option<Span>,
    pub projection_span: Option<Span>,
    pub policy_span: Option<Span>,
    pub policy_name_span: Span,
    pub force_span: Option<Span>,
}

/// ALTER TABLE action kinds.
///
/// Most variants are intentionally span-first to avoid information loss and
/// to make it safe to introduce parsing incrementally.
#[derive(Debug, Clone)]
pub enum AstAlterTableActionKind {
    /// RENAME TO <new_name>
    RenameTo {
        rename_span: Option<Span>,
        to_span: Option<Span>,
        new_name_span: Span,
    },
    /// `RENAME COLUMN <old> TO <new>`
    RenameColumn {
        rename_span: Option<Span>,
        column_span: Option<Span>,
        old_name_span: Span,
        to_span: Option<Span>,
        new_name_span: Span,
    },
    /// SWAP WITH <other_table>
    SwapWith {
        swap_span: Option<Span>,
        with_span: Option<Span>,
        other_table_span: Span,
    },

    /// ADD COLUMN ... (details may be partially parsed).
    AddColumn {
        add_span: Option<Span>,
        column_span: Option<Span>,
        columns_span: Span,
        columns: Vec<AstAlterTableColumnDef>,
    },
    /// DROP COLUMN ...
    DropColumn {
        drop_span: Option<Span>,
        column_span: Option<Span>,
        columns_span: Span,
        columns: Vec<Span>,
    },
    /// ALTER COLUMN ... (details are currently stored as spans).
    AlterColumn {
        alter_span: Option<Span>,
        column_span: Option<Span>,
        column_name_span: Span,
        operation_span: Span,
    },

    /// ADD CONSTRAINT ... (constraint text preserved span-first).
    AddConstraint {
        add_span: Option<Span>,
        constraint_span: Option<Span>,
        details_span: Span,
    },
    /// `DROP CONSTRAINT <name>`
    DropConstraint {
        drop_span: Option<Span>,
        constraint_span: Option<Span>,
        name_span: Span,
    },

    /// `CLUSTER BY (<exprs>)` or `CLUSTER BY NONE` or `CLUSTER BY AUTO`
    ClusterBy {
        cluster_span: Option<Span>,
        by_span: Option<Span>,
        exprs_span: Span,
        exprs: Option<Vec<AstExpr>>,
        /// True when `CLUSTER BY NONE` (removes clustering)
        is_none: bool,
    },
    /// DROP CLUSTERING KEY
    DropClusteringKey {
        drop_span: Option<Span>,
        clustering_span: Option<Span>,
        key_span: Option<Span>,
    },
    /// SUSPEND RECLUSTER
    SuspendRecluster {
        suspend_span: Option<Span>,
        recluster_span: Option<Span>,
    },
    /// RESUME RECLUSTER
    ResumeRecluster {
        resume_span: Option<Span>,
        recluster_span: Option<Span>,
    },

    /// SET <parameters...>
    Set {
        set_span: Option<Span>,
        parameters_span: Span,
    },
    /// UNSET <parameters...>
    Unset {
        unset_span: Option<Span>,
        parameters_span: Span,
    },

    // ========================================================================
    // Governance & Policy Actions (Critical for risk/policy analysis)
    // Note: Large variants are boxed to reduce enum size
    // ========================================================================
    /// `ADD ROW ACCESS POLICY <policy_name> ON (<columns>)`
    /// Boxed due to size (8 fields)
    AddRowAccessPolicy(Box<AddRowAccessPolicyAction>),
    /// DROP ROW ACCESS POLICY <policy_name>
    DropRowAccessPolicy {
        drop_span: Option<Span>,
        row_span: Option<Span>,
        access_span: Option<Span>,
        policy_span: Option<Span>,
        policy_name_span: Span,
        if_exists_span: Option<Span>,
    },
    /// DROP ALL ROW ACCESS POLICIES
    DropAllRowAccessPolicies {
        drop_span: Option<Span>,
        all_span: Option<Span>,
        row_span: Option<Span>,
        access_span: Option<Span>,
        policies_span: Option<Span>,
    },

    /// Databricks: `SET ROW FILTER <function_name> ON (<columns>)`
    SetRowFilter {
        set_span: Option<Span>,
        row_span: Option<Span>,
        filter_span: Option<Span>,
        function_name_span: Span,
        on_span: Option<Span>,
        columns_span: Span,
    },

    /// Databricks: DROP ROW FILTER
    DropRowFilter {
        drop_span: Option<Span>,
        row_span: Option<Span>,
        filter_span: Option<Span>,
    },

    /// `SET AGGREGATION POLICY <policy_name> [ENTITY KEY (...)] [FORCE]`
    SetAggregationPolicy {
        set_span: Option<Span>,
        aggregation_span: Option<Span>,
        policy_span: Option<Span>,
        policy_name_span: Span,
        entity_key_span: Option<Span>,
        entity_key_columns: Vec<Span>,
        force_span: Option<Span>,
    },
    /// UNSET AGGREGATION POLICY
    UnsetAggregationPolicy {
        unset_span: Option<Span>,
        aggregation_span: Option<Span>,
        policy_span: Option<Span>,
    },

    /// `SET JOIN POLICY <policy_name> [FORCE]`
    SetJoinPolicy {
        set_span: Option<Span>,
        join_span: Option<Span>,
        policy_span: Option<Span>,
        policy_name_span: Span,
        force_span: Option<Span>,
    },
    /// UNSET JOIN POLICY
    UnsetJoinPolicy {
        unset_span: Option<Span>,
        join_span: Option<Span>,
        policy_span: Option<Span>,
    },

    /// `ALTER COLUMN <col> SET MASKING POLICY <policy> [USING (...)] [FORCE]`
    /// Boxed due to size (9 fields)
    SetColumnMaskingPolicy(Box<SetColumnMaskingPolicyAction>),
    /// ALTER COLUMN <col> UNSET MASKING POLICY
    UnsetColumnMaskingPolicy {
        alter_span: Option<Span>,
        column_span: Option<Span>,
        column_name_span: Span,
        unset_span: Option<Span>,
        masking_span: Option<Span>,
        policy_span: Option<Span>,
    },

    /// Databricks: ALTER COLUMN <col> SET MASK <function_name>
    SetColumnMask {
        alter_span: Option<Span>,
        column_span: Option<Span>,
        column_name_span: Span,
        set_span: Option<Span>,
        mask_span: Option<Span>,
        function_name_span: Span,
    },

    /// Databricks: ALTER COLUMN <col> DROP MASK
    DropColumnMask {
        alter_span: Option<Span>,
        column_span: Option<Span>,
        column_name_span: Span,
        drop_span: Option<Span>,
        mask_span: Option<Span>,
    },

    /// `ALTER COLUMN <col> SET PROJECTION POLICY <policy> [FORCE]`
    /// Boxed due to size (8 fields)
    SetColumnProjectionPolicy(Box<SetColumnProjectionPolicyAction>),
    /// ALTER COLUMN <col> UNSET PROJECTION POLICY
    UnsetColumnProjectionPolicy {
        alter_span: Option<Span>,
        column_span: Option<Span>,
        column_name_span: Span,
        unset_span: Option<Span>,
        projection_span: Option<Span>,
        policy_span: Option<Span>,
    },

    /// `SET TAG <tag_name> = '<value>' [, ...]`
    SetTag {
        set_span: Option<Span>,
        tag_span: Option<Span>,
        /// Tag assignments as spans (covers "tag = 'value'" pairs)
        assignments_span: Span,
    },
    /// UNSET TAG <tag_name> [, ...]
    UnsetTag {
        unset_span: Option<Span>,
        tag_span: Option<Span>,
        tags_span: Span,
    },

    /// `ALTER COLUMN <col> SET TAG <tag> = '<value>' [, ...]`
    SetColumnTag {
        alter_span: Option<Span>,
        column_span: Option<Span>,
        column_name_span: Span,
        set_span: Option<Span>,
        tag_span: Option<Span>,
        assignments_span: Span,
    },
    /// `ALTER COLUMN <col> UNSET TAG <tag> [, ...]`
    UnsetColumnTag {
        alter_span: Option<Span>,
        column_span: Option<Span>,
        column_name_span: Span,
        unset_span: Option<Span>,
        tag_span: Option<Span>,
        tags_span: Span,
    },

    // ========================================================================
    // Search Optimization & Advanced Features
    // ========================================================================
    /// ADD SEARCH OPTIMIZATION [ON ...]
    AddSearchOptimization {
        add_span: Option<Span>,
        search_span: Option<Span>,
        optimization_span: Option<Span>,
        on_clause_span: Option<Span>,
    },
    /// DROP SEARCH OPTIMIZATION [ON ...]
    DropSearchOptimization {
        drop_span: Option<Span>,
        search_span: Option<Span>,
        optimization_span: Option<Span>,
        on_clause_span: Option<Span>,
    },

    // ========================================================================
    // Data Quality & Metrics
    // ========================================================================
    /// SET DATA_METRIC_SCHEDULE = '...'
    SetDataMetricSchedule {
        set_span: Option<Span>,
        schedule_span: Span,
    },
    /// UNSET DATA_METRIC_SCHEDULE
    UnsetDataMetricSchedule {
        unset_span: Option<Span>,
        schedule_span: Option<Span>,
    },
    /// `ADD DATA METRIC FUNCTION <name> ON (<cols>)`
    AddDataMetricFunction {
        add_span: Option<Span>,
        data_span: Option<Span>,
        metric_span: Option<Span>,
        function_span: Option<Span>,
        function_name_span: Span,
        on_span: Option<Span>,
        columns_span: Span,
    },
    /// `DROP DATA METRIC FUNCTION <name> ON (<cols>)`
    DropDataMetricFunction {
        drop_span: Option<Span>,
        data_span: Option<Span>,
        metric_span: Option<Span>,
        function_span: Option<Span>,
        function_name_span: Span,
        on_span: Option<Span>,
        columns_span: Span,
    },

    // ========================================================================
    // Storage Lifecycle
    // ========================================================================
    /// `ADD STORAGE LIFECYCLE POLICY <policy> ON (<cols>)`
    AddStorageLifecyclePolicy {
        add_span: Option<Span>,
        storage_span: Option<Span>,
        lifecycle_span: Option<Span>,
        policy_span: Option<Span>,
        policy_name_span: Span,
        on_span: Option<Span>,
        columns_span: Span,
    },
    /// DROP STORAGE LIFECYCLE POLICY
    DropStorageLifecyclePolicy {
        drop_span: Option<Span>,
        storage_span: Option<Span>,
        lifecycle_span: Option<Span>,
        policy_span: Option<Span>,
    },

    // ========================================================================
    // BigQuery-specific Actions
    // ========================================================================
    /// SET OPTIONS (key=value, ...) — BigQuery table-level options
    SetOptions {
        set_span: Option<Span>,
        options_span: Option<Span>,
        /// Span covering the entire parenthesized options list including parens
        options_list_span: Span,
    },

    /// SET DEFAULT COLLATE 'collation_spec' — BigQuery default collation
    SetDefaultCollate {
        set_span: Option<Span>,
        default_span: Option<Span>,
        collate_span: Option<Span>,
        /// Span covering the collation spec string literal
        collation_span: Span,
    },

    /// DROP PRIMARY KEY [IF EXISTS] — BigQuery primary key removal
    DropPrimaryKey {
        drop_span: Option<Span>,
        primary_span: Option<Span>,
        key_span: Option<Span>,
        if_exists_span: Option<Span>,
    },

    /// ALTER COLUMN <col> SET OPTIONS (key=value, ...) — BigQuery column options
    AlterColumnSetOptions {
        alter_span: Option<Span>,
        column_span: Option<Span>,
        column_name_span: Span,
        set_span: Option<Span>,
        options_span: Option<Span>,
        options_list_span: Span,
    },

    /// ALTER COLUMN <col> DROP NOT NULL — BigQuery drop column nullability constraint
    AlterColumnDropNotNull {
        alter_span: Option<Span>,
        column_span: Option<Span>,
        column_name_span: Span,
        drop_span: Option<Span>,
        not_span: Option<Span>,
        null_span: Option<Span>,
    },

    /// `ALTER COLUMN <col> SET DATA TYPE <type>` — BigQuery column type change
    AlterColumnSetDataType {
        alter_span: Option<Span>,
        column_span: Option<Span>,
        column_name_span: Span,
        set_span: Option<Span>,
        data_span: Option<Span>,
        type_span: Option<Span>,
        /// Span covering the full data type expression (e.g., NUMERIC, STRUCT<...>)
        data_type_span: Span,
    },

    /// `ALTER COLUMN <col> SET DEFAULT <expr>` — BigQuery column default value
    AlterColumnSetDefault {
        alter_span: Option<Span>,
        column_span: Option<Span>,
        column_name_span: Span,
        set_span: Option<Span>,
        default_span: Option<Span>,
        /// Span covering the default expression
        expr_span: Span,
    },

    /// ALTER COLUMN <col> DROP DEFAULT — BigQuery drop column default
    AlterColumnDropDefault {
        alter_span: Option<Span>,
        column_span: Option<Span>,
        column_name_span: Span,
        drop_span: Option<Span>,
        default_span: Option<Span>,
    },

    // ========================================================================
    // Databricks-specific Actions
    // ========================================================================
    /// SET TBLPROPERTIES ('key' = 'value', ...) — Databricks Delta table properties
    SetTblProperties {
        set_span: Option<Span>,
        tblproperties_span: Option<Span>,
        /// Span covering the entire parenthesized properties list including parens
        properties_span: Span,
    },

    /// UNSET TBLPROPERTIES [IF EXISTS] ('key', ...) — Databricks Delta table properties removal
    UnsetTblProperties {
        unset_span: Option<Span>,
        tblproperties_span: Option<Span>,
        if_exists_span: Option<Span>,
        /// Span covering the entire parenthesized keys list including parens
        keys_span: Span,
    },

    /// PG `[ENABLE | DISABLE | FORCE | NO FORCE] ROW LEVEL SECURITY` —
    /// toggles / forces row-level security on the table.
    RowLevelSecurity {
        mode: AstRowLevelSecurityMode,
        /// Span covering the mode keyword(s) through `SECURITY`.
        keyword_span: Span,
    },

    /// Action spans for governance / metadata features where detailed parsing
    /// is not yet implemented (complex policies, etc.).
    GovernanceSpan { span: Span },

    /// Unknown / unclassified action.
    Unknown { span: Span },
}

/// PG `ROW LEVEL SECURITY` toggle on `ALTER TABLE`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AstRowLevelSecurityMode {
    /// `ENABLE ROW LEVEL SECURITY`
    Enable,
    /// `DISABLE ROW LEVEL SECURITY`
    Disable,
    /// `FORCE ROW LEVEL SECURITY`
    Force,
    /// `NO FORCE ROW LEVEL SECURITY`
    NoForce,
}

/// A best-effort parsed column definition inside ALTER TABLE ... ADD COLUMN.
///
/// This mirrors CREATE TABLE column span tracking but is intentionally minimal
/// until ALTER TABLE parsing is implemented.
#[derive(Debug, Clone)]
pub struct AstAlterTableColumnDef {
    pub node_id: crate::ast::NodeId,
    /// Span covering the entire column definition.
    pub full_span: Span,
    /// Optional span covering the column name.
    pub name_span: Option<Span>,
    /// Optional span covering the column type.
    pub type_span: Option<Span>,
    /// `GENERATED ALWAYS` / `GENERATED BY DEFAULT` prefix; includes the
    /// trailing `AS` when followed by `IDENTITY`.
    pub generated_always_span: Option<Span>,
    /// Generated/virtual/computed column expression: `AS ( expr )` or
    /// MSSQL `AS expr` — span includes the `AS` keyword.
    pub virtual_expr_span: Option<Span>,
    /// Storage keyword after the expression: `VIRTUAL` | `STORED` | `PERSISTED`.
    pub storage_keyword_span: Option<Span>,
}

// ============================================================================
// ALTER DYNAMIC TABLE
// ============================================================================

// ============================================================================
// ALTER VIEW (BigQuery / Snowflake / PostgreSQL — permissive parser)
// ============================================================================

/// ALTER VIEW statement.
///
/// Cross-dialect support for modifying view properties.
///
/// BigQuery syntax:
/// - `ALTER VIEW [IF EXISTS] <name> SET OPTIONS (...)`
/// - `ALTER VIEW [IF EXISTS] <name> ALTER COLUMN [IF EXISTS] <col> SET OPTIONS (...)`
///
/// Snowflake / PostgreSQL: currently falls through to opaque remainder.
#[derive(Debug, Clone)]
pub struct AstAlterView {
    pub node_id: crate::ast::NodeId,
    /// Span covering the entire ALTER VIEW statement.
    pub span: Span,
    /// Span covering the ALTER keyword.
    pub alter_span: Span,
    /// Span covering the VIEW keyword.
    pub view_span: Span,
    /// Optional span covering IF EXISTS.
    pub if_exists_span: Option<Span>,
    /// Span covering the view name / object reference.
    pub name_span: Span,
    /// Parsed action for this ALTER VIEW.
    pub action: AstAlterViewAction,
}

/// One ALTER VIEW action.
#[derive(Debug, Clone)]
pub struct AstAlterViewAction {
    pub span: Span,
    pub kind: AstAlterViewActionKind,
}

/// Kinds of ALTER VIEW actions.
#[derive(Debug, Clone)]
pub enum AstAlterViewActionKind {
    // ── BigQuery ─────────────────────────────────────────────────────
    /// SET OPTIONS (key=value, ...) — BigQuery view options
    SetOptions {
        set_span: Option<Span>,
        options_span: Option<Span>,
        options_list_span: Span,
    },

    /// ALTER COLUMN [IF EXISTS] <col> SET OPTIONS (...) — BigQuery column options
    AlterColumnSetOptions {
        alter_span: Option<Span>,
        column_span: Option<Span>,
        column_if_exists_span: Option<Span>,
        column_name_span: Span,
        set_span: Option<Span>,
        options_span: Option<Span>,
        options_list_span: Span,
    },

    // ── Snowflake ────────────────────────────────────────────────────
    /// RENAME TO <new_name>
    RenameTo {
        /// Span covering the entire action (RENAME TO new_name).
        action_span: Span,
    },

    /// SET SECURE
    SetSecure { action_span: Span },

    /// UNSET SECURE
    UnsetSecure { action_span: Span },

    /// `SET COMMENT = '<string>'`
    SetComment { action_span: Span },

    /// UNSET COMMENT
    UnsetComment { action_span: Span },

    /// SET CHANGE_TRACKING = TRUE|FALSE
    SetChangeTracking { action_span: Span },

    /// SET TAG tag_name = 'tag_value' [, ...]
    SetTag { action_span: Span },

    /// UNSET TAG tag_name [, ...]
    UnsetTag { action_span: Span },

    /// `ADD ROW ACCESS POLICY <name> ON (col, ...)`
    AddRowAccessPolicy { action_span: Span },

    /// `DROP ROW ACCESS POLICY <name>`
    DropRowAccessPolicy { action_span: Span },

    /// DROP ALL ROW ACCESS POLICIES
    DropAllRowAccessPolicies { action_span: Span },

    /// `SET AGGREGATION POLICY <name> [ENTITY KEY (...)] [FORCE]`
    SetAggregationPolicy { action_span: Span },

    /// UNSET AGGREGATION POLICY
    UnsetAggregationPolicy { action_span: Span },

    /// `SET JOIN POLICY <name> [FORCE]`
    SetJoinPolicy { action_span: Span },

    /// UNSET JOIN POLICY
    UnsetJoinPolicy { action_span: Span },

    /// `{ ALTER | MODIFY } [COLUMN] <col> SET MASKING POLICY ... / UNSET MASKING POLICY`
    /// Also covers SET/UNSET PROJECTION POLICY, SET/UNSET TAG on columns.
    AlterColumn { action_span: Span },

    /// `ADD [COLUMN] [IF NOT EXISTS] <col> <type> [WITH MASKING POLICY ...] ...`
    AddColumn { action_span: Span },

    /// SET DATA_METRIC_SCHEDULE / UNSET DATA_METRIC_SCHEDULE / ADD|DROP DATA METRIC FUNCTION ...
    DataMetricFunction { action_span: Span },

    /// Opaque remainder — for actions not yet parsed.
    OpaqueRemainder { remainder_span: Span },
}

// ============================================================================
// ALTER MATERIALIZED VIEW (BigQuery)
// ============================================================================

/// ALTER MATERIALIZED VIEW statement.
///
/// BigQuery syntax:
/// - `ALTER MATERIALIZED VIEW [IF EXISTS] <name> SET OPTIONS (...)`
#[derive(Debug, Clone)]
pub struct AstAlterMaterializedView {
    pub node_id: crate::ast::NodeId,
    /// Span covering the entire ALTER MATERIALIZED VIEW statement.
    pub span: Span,
    /// Span covering the ALTER keyword.
    pub alter_span: Span,
    /// Span covering the MATERIALIZED identifier.
    pub materialized_span: Span,
    /// Span covering the VIEW keyword.
    pub view_span: Span,
    /// Optional span covering IF EXISTS.
    pub if_exists_span: Option<Span>,
    /// Span covering the materialized view name / object reference.
    pub name_span: Span,
    /// Parsed action for this ALTER MATERIALIZED VIEW.
    pub action: AstAlterMaterializedViewAction,
}

/// One ALTER MATERIALIZED VIEW action.
#[derive(Debug, Clone)]
pub struct AstAlterMaterializedViewAction {
    pub span: Span,
    pub kind: AstAlterMaterializedViewActionKind,
}

/// Kinds of ALTER MATERIALIZED VIEW actions.
#[derive(Debug, Clone)]
pub enum AstAlterMaterializedViewActionKind {
    /// SET OPTIONS (key=value, ...) — BigQuery MV options
    SetOptions {
        set_span: Option<Span>,
        options_span: Option<Span>,
        options_list_span: Span,
    },

    /// Opaque remainder — for actions not yet parsed.
    OpaqueRemainder { remainder_span: Span },
}

// ============================================================================

/// ALTER DYNAMIC TABLE statement.
///
/// Modifies properties of an existing dynamic table.
/// Includes governance-critical operations like TARGET_LAG changes, refresh operations,
/// clustering, and policy management.
///
/// Syntax variants:
/// - `ALTER DYNAMIC TABLE [IF EXISTS] <name> { SUSPEND | RESUME }`
/// - `ALTER DYNAMIC TABLE [IF EXISTS] <name> RENAME TO <new_name>`
/// - `ALTER DYNAMIC TABLE [IF EXISTS] <name> SWAP WITH <other_table>`
/// - `ALTER DYNAMIC TABLE [IF EXISTS] <name> REFRESH [COPY SESSION]`
/// - `ALTER DYNAMIC TABLE [IF EXISTS] <name> SET ...`
/// - `ALTER DYNAMIC TABLE [IF EXISTS] <name> UNSET ...`
/// - `ALTER DYNAMIC TABLE [IF EXISTS] <name> { clusteringAction }`
/// - `ALTER DYNAMIC TABLE [IF EXISTS] <name> { dataGovnPolicyTagAction }`
/// - `ALTER DYNAMIC TABLE [IF EXISTS] <name> { searchOptimizationAction }`
/// - `ALTER DYNAMIC TABLE [IF EXISTS] <name> { tableColumnCommentAction }`
#[derive(Debug, Clone)]
pub struct AstAlterDynamicTable {
    pub node_id: crate::ast::NodeId,
    /// Span covering the entire ALTER DYNAMIC TABLE statement.
    pub span: Span,
    /// Optional typed-syntax node id for this statement.
    pub syntax_id: Option<crate::syntax::SyntaxAlterDynamicTableStmtId>,
    /// Span covering the ALTER keyword.
    pub alter_span: Span,
    /// Span covering the DYNAMIC keyword (actually an identifier).
    pub dynamic_span: Span,
    /// Span covering the TABLE keyword.
    pub table_span: Span,
    /// Optional span covering IF EXISTS.
    pub if_exists_span: Option<Span>,
    /// Span covering the table name / object reference.
    pub name_span: Span,
    /// Span covering the action (everything after the table name).
    pub action_span: Span,
    /// The parsed action.
    pub action: AstAlterDynamicTableAction,
    /// Unknown clauses captured for defensive parsing (future Snowflake features).
    pub extras: Vec<AstUnknownClause>,
}

/// One ALTER DYNAMIC TABLE action.
#[derive(Debug, Clone)]
pub struct AstAlterDynamicTableAction {
    pub node_id: crate::ast::NodeId,
    /// Span covering the entire action.
    pub span: Span,
    pub kind: AstAlterDynamicTableActionKind,
}

/// ALTER DYNAMIC TABLE action kinds.
///
/// Most variants are intentionally span-first to avoid information loss and
/// to make it safe to introduce parsing incrementally.
#[derive(Debug, Clone)]
pub enum AstAlterDynamicTableActionKind {
    // ========================================================================
    // State Control
    // ========================================================================
    /// SUSPEND
    Suspend { suspend_span: Span },
    /// RESUME
    Resume { resume_span: Span },

    // ========================================================================
    // Rename/Swap Operations
    // ========================================================================
    /// RENAME TO <new_name>
    RenameTo {
        rename_span: Span,
        to_span: Span,
        new_name_span: Span,
    },
    /// SWAP WITH <other_table>
    SwapWith {
        swap_span: Span,
        with_span: Span,
        other_table_span: Span,
    },

    // ========================================================================
    // Refresh Operations
    // ========================================================================
    /// REFRESH [COPY SESSION]
    Refresh {
        refresh_span: Span,
        copy_session_span: Option<Span>,
    },

    // ========================================================================
    // SET/UNSET Properties
    // ========================================================================
    /// SET <properties...>
    Set {
        set_span: Span,
        properties_span: Span,
    },
    /// UNSET <properties...>
    Unset {
        unset_span: Span,
        properties_span: Span,
    },

    /// SET COMMENT = '...'
    SetComment {
        set_span: Span,
        comment_span: Span,
        value_span: Span,
    },
    /// UNSET COMMENT
    UnsetComment {
        unset_span: Span,
        comment_span: Span,
    },

    // ========================================================================
    // Clustering Operations
    // ========================================================================
    /// `CLUSTER BY (<exprs>)`
    ClusterBy {
        cluster_span: Span,
        by_span: Span,
        exprs_span: Span,
    },
    /// DROP CLUSTERING KEY
    DropClusteringKey {
        drop_span: Span,
        clustering_span: Span,
        key_span: Option<Span>,
    },
    /// SUSPEND RECLUSTER
    SuspendRecluster {
        suspend_span: Span,
        recluster_span: Span,
    },
    /// RESUME RECLUSTER
    ResumeRecluster {
        resume_span: Span,
        recluster_span: Span,
    },

    // ========================================================================
    // Column Comment Operations
    // ========================================================================
    /// `ALTER | MODIFY [COLUMN] <col> COMMENT '<string>'`
    SetColumnComment {
        alter_span: Span,
        column_keyword_span: Option<Span>,
        column_name_span: Span,
        comment_span: Span,
        value_span: Span,
    },
    /// `ALTER | MODIFY [COLUMN] <col> UNSET COMMENT`
    UnsetColumnComment {
        alter_span: Span,
        column_keyword_span: Option<Span>,
        column_name_span: Span,
        unset_span: Span,
        comment_span: Span,
    },

    // ========================================================================
    // Row Access Policy Operations
    // ========================================================================
    /// `ADD ROW ACCESS POLICY <policy_name> ON (<columns>)`
    AddRowAccessPolicy {
        add_span: Span,
        row_span: Span,
        access_span: Span,
        policy_span: Span,
        policy_name_span: Span,
        on_span: Span,
        columns_span: Span,
    },
    /// DROP ROW ACCESS POLICY <policy_name>
    DropRowAccessPolicy {
        drop_span: Span,
        row_span: Span,
        access_span: Span,
        policy_span: Span,
        policy_name_span: Span,
    },
    /// DROP ALL ROW ACCESS POLICIES
    DropAllRowAccessPolicies {
        drop_span: Span,
        all_span: Span,
        row_span: Span,
        access_span: Span,
        policies_span: Span,
    },

    // ========================================================================
    // Aggregation Policy Operations
    // ========================================================================
    /// `SET AGGREGATION POLICY <policy_name> [ENTITY KEY (...)] [FORCE]`
    SetAggregationPolicy {
        set_span: Span,
        aggregation_span: Span,
        policy_span: Span,
        policy_name_span: Span,
        entity_key_span: Option<Span>,
        force_span: Option<Span>,
    },
    /// UNSET AGGREGATION POLICY
    UnsetAggregationPolicy {
        unset_span: Span,
        aggregation_span: Span,
        policy_span: Span,
    },

    // ========================================================================
    // Column Masking Policy Operations
    // ========================================================================
    /// `ALTER | MODIFY [COLUMN] <col> SET MASKING POLICY <policy> [USING (...)] [FORCE]`
    SetColumnMaskingPolicy {
        alter_span: Span,
        column_keyword_span: Option<Span>,
        column_name_span: Span,
        set_span: Span,
        masking_span: Span,
        policy_span: Span,
        policy_name_span: Span,
        using_span: Option<Span>,
        force_span: Option<Span>,
    },
    /// `ALTER | MODIFY [COLUMN] <col> UNSET MASKING POLICY`
    UnsetColumnMaskingPolicy {
        alter_span: Span,
        column_keyword_span: Option<Span>,
        column_name_span: Span,
        unset_span: Span,
        masking_span: Span,
        policy_span: Span,
    },

    // ========================================================================
    // Column Projection Policy Operations
    // ========================================================================
    /// `ALTER | MODIFY [COLUMN] <col> SET PROJECTION POLICY <policy> [FORCE]`
    SetColumnProjectionPolicy {
        alter_span: Span,
        column_keyword_span: Option<Span>,
        column_name_span: Span,
        set_span: Span,
        projection_span: Span,
        policy_span: Span,
        policy_name_span: Span,
        force_span: Option<Span>,
    },
    /// `ALTER | MODIFY [COLUMN] <col> UNSET PROJECTION POLICY`
    UnsetColumnProjectionPolicy {
        alter_span: Span,
        column_keyword_span: Option<Span>,
        column_name_span: Span,
        unset_span: Span,
        projection_span: Span,
        policy_span: Span,
    },

    // ========================================================================
    // Tag Operations
    // ========================================================================
    /// `SET TAG <tag_name> = '<value>' [, ...]`
    SetTag {
        set_span: Span,
        tag_span: Span,
        assignments_span: Span,
    },
    /// UNSET TAG <tag_name> [, ...]
    UnsetTag {
        unset_span: Span,
        tag_span: Span,
        tags_span: Span,
    },
    /// `ALTER | MODIFY [COLUMN] <col> SET TAG <tag> = '<value>' [, ...]`
    SetColumnTag {
        alter_span: Span,
        column_keyword_span: Option<Span>,
        column_name_span: Span,
        set_span: Span,
        tag_span: Span,
        assignments_span: Span,
    },
    /// `ALTER | MODIFY [COLUMN] <col> UNSET TAG <tag> [, ...]`
    UnsetColumnTag {
        alter_span: Span,
        column_keyword_span: Option<Span>,
        column_name_span: Span,
        unset_span: Span,
        tag_span: Span,
        tags_span: Span,
    },

    // ========================================================================
    // Search Optimization Operations
    // ========================================================================
    /// ADD SEARCH OPTIMIZATION [ON ...]
    AddSearchOptimization {
        add_span: Span,
        search_span: Span,
        optimization_span: Span,
        on_clause_span: Option<Span>,
    },
    /// DROP SEARCH OPTIMIZATION [ON ...]
    DropSearchOptimization {
        drop_span: Span,
        search_span: Span,
        optimization_span: Span,
        on_clause_span: Option<Span>,
    },
    /// SUSPEND SEARCH OPTIMIZATION [ON ...]
    SuspendSearchOptimization {
        suspend_span: Span,
        search_span: Span,
        optimization_span: Span,
        on_clause_span: Option<Span>,
    },
    /// RESUME SEARCH OPTIMIZATION [ON ...]
    ResumeSearchOptimization {
        resume_span: Span,
        search_span: Span,
        optimization_span: Span,
        on_clause_span: Option<Span>,
    },

    // ========================================================================
    // Unknown / Fallback
    // ========================================================================
    /// Unknown / unclassified action (span-safe fallback).
    Unknown { span: Span },
}

// ============================================================================
// ALTER FUNCTION
// ============================================================================

/// ALTER FUNCTION statement.
///
/// Modifies properties of an existing user-defined or external function.
/// Includes security-sensitive operations like SECURE setting, tag management,
/// external access configuration, and function renaming.
///
/// Syntax variants:
/// - `ALTER FUNCTION [IF EXISTS] <name>(<arg_types>) RENAME TO <new_name>`
/// - `ALTER FUNCTION [IF EXISTS] <name>(<arg_types>) SET SECURE`
/// - `ALTER FUNCTION [IF EXISTS] <name>(<arg_types>) UNSET SECURE`
/// - `ALTER FUNCTION [IF EXISTS] <name>(<arg_types>) SET <properties...>`
/// - `ALTER FUNCTION [IF EXISTS] <name>(<arg_types>) UNSET <properties...>`
/// - `ALTER FUNCTION [IF EXISTS] <name>(<arg_types>) SET TAG <tag> = '<value>' [, ...]`
/// - `ALTER FUNCTION [IF EXISTS] <name>(<arg_types>) UNSET TAG <tag> [, ...]`
/// - External function: SET API_INTEGRATION, HEADERS, CONTEXT_HEADERS, etc.
#[derive(Debug, Clone)]
pub struct AstAlterFunction {
    pub node_id: crate::ast::NodeId,
    /// Span covering the entire ALTER FUNCTION statement.
    pub span: Span,
    /// Span covering the ALTER keyword.
    pub alter_span: Span,
    /// Span covering the FUNCTION keyword.
    pub function_span: Span,
    /// Optional span covering IF EXISTS.
    pub if_exists_span: Option<Span>,
    /// Span covering the function name (qualified or simple).
    pub name_span: Span,
    /// Span covering the argument type list including parentheses.
    pub signature_span: Span,
    /// Span covering the action (everything after the signature).
    pub action_span: Span,
    /// The parsed action.
    pub action: AstAlterFunctionAction,
    /// Unknown clauses captured for defensive parsing (future Snowflake features).
    pub extras: Vec<AstUnknownClause>,
}

/// One ALTER FUNCTION action.
#[derive(Debug, Clone)]
pub struct AstAlterFunctionAction {
    pub node_id: crate::ast::NodeId,
    /// Span covering the entire action.
    pub span: Span,
    pub kind: AstAlterFunctionActionKind,
}

/// ALTER FUNCTION action kinds.
#[derive(Debug, Clone)]
pub enum AstAlterFunctionActionKind {
    // ========================================================================
    // Rename
    // ========================================================================
    /// RENAME TO <new_name>
    RenameTo {
        rename_span: Span,
        to_span: Span,
        new_name_span: Span,
    },

    // ========================================================================
    // Secure Setting
    // ========================================================================
    /// SET SECURE
    SetSecure { set_span: Span, secure_span: Span },
    /// UNSET SECURE
    UnsetSecure { unset_span: Span, secure_span: Span },

    // ========================================================================
    // SET/UNSET Properties
    // ========================================================================
    /// SET <properties...> (LOG_LEVEL, TRACE_LEVEL, COMMENT, EXTERNAL_ACCESS_INTEGRATIONS, SECRETS)
    SetProperties {
        set_span: Span,
        properties_span: Span,
    },
    /// UNSET <properties...>
    UnsetProperties {
        unset_span: Span,
        properties_span: Span,
    },

    // ========================================================================
    // Tag Operations
    // ========================================================================
    /// `SET TAG <tag_name> = '<value>' [, ...]`
    SetTag {
        set_span: Span,
        tag_span: Span,
        assignments_span: Span,
    },
    /// UNSET TAG <tag_name> [, ...]
    UnsetTag {
        unset_span: Span,
        tag_span: Span,
        tags_span: Span,
    },

    // ========================================================================
    // External Function Specific
    // ========================================================================
    /// `SET API_INTEGRATION = <name>`
    SetApiIntegration {
        set_span: Span,
        api_integration_span: Span,
        value_span: Span,
    },
    /// SET HEADERS = (...)
    SetHeaders {
        set_span: Span,
        headers_span: Span,
        value_span: Span,
    },
    /// SET CONTEXT_HEADERS = (...)
    SetContextHeaders {
        set_span: Span,
        context_headers_span: Span,
        value_span: Span,
    },
    /// `SET MAX_BATCH_ROWS = <integer>`
    SetMaxBatchRows {
        set_span: Span,
        max_batch_rows_span: Span,
        value_span: Span,
    },
    /// `SET COMPRESSION = <type>`
    SetCompression {
        set_span: Span,
        compression_span: Span,
        value_span: Span,
    },
    /// SET REQUEST_TRANSLATOR = <udf_name>
    SetRequestTranslator {
        set_span: Span,
        request_translator_span: Span,
        udf_span: Span,
    },
    /// SET RESPONSE_TRANSLATOR = <udf_name>
    SetResponseTranslator {
        set_span: Span,
        response_translator_span: Span,
        udf_span: Span,
    },

    // ========================================================================
    // Unknown / Fallback
    // ========================================================================
    /// Unknown / unclassified action (span-safe fallback).
    Unknown { span: Span },
}

// ============================================================================
// ALTER PROCEDURE
// ============================================================================

/// ALTER PROCEDURE statement.
///
/// Modifies properties of an existing stored procedure.
/// Includes security-sensitive operations like EXECUTE AS mode changes,
/// tag management, external access configuration, and procedure renaming.
///
/// Syntax variants:
/// - `ALTER PROCEDURE [IF EXISTS] <name>(<arg_types>) RENAME TO <new_name>`
/// - `ALTER PROCEDURE [IF EXISTS] <name>(<arg_types>) SET <properties...>`
/// - `ALTER PROCEDURE [IF EXISTS] <name>(<arg_types>) UNSET COMMENT`
/// - `ALTER PROCEDURE [IF EXISTS] <name>(<arg_types>) SET TAG <tag> = '<value>' [, ...]`
/// - `ALTER PROCEDURE [IF EXISTS] <name>(<arg_types>) UNSET TAG <tag> [, ...]`
/// - `ALTER PROCEDURE [IF EXISTS] <name>(<arg_types>) EXECUTE AS { OWNER | CALLER | RESTRICTED CALLER }`
#[derive(Debug, Clone)]
pub struct AstAlterProcedure {
    pub node_id: crate::ast::NodeId,
    /// Span covering the entire ALTER PROCEDURE statement.
    pub span: Span,
    /// Span covering the ALTER keyword.
    pub alter_span: Span,
    /// Span covering the PROCEDURE keyword.
    pub procedure_span: Span,
    /// Optional span covering IF EXISTS.
    pub if_exists_span: Option<Span>,
    /// Span covering the procedure name (qualified or simple).
    pub name_span: Span,
    /// Span covering the argument type list including parentheses.
    pub signature_span: Span,
    /// Span covering the action (everything after the signature).
    pub action_span: Span,
    /// The parsed action.
    pub action: AstAlterProcedureAction,
    /// Unknown clauses captured for defensive parsing (future Snowflake features).
    pub extras: Vec<AstUnknownClause>,
}

/// One ALTER PROCEDURE action.
#[derive(Debug, Clone)]
pub struct AstAlterProcedureAction {
    pub node_id: crate::ast::NodeId,
    /// Span covering the entire action.
    pub span: Span,
    pub kind: AstAlterProcedureActionKind,
}

/// Execution mode for stored procedures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecuteAsMode {
    /// EXECUTE AS OWNER - procedure runs with owner's privileges
    Owner,
    /// EXECUTE AS CALLER - procedure runs with caller's privileges
    Caller,
    /// EXECUTE AS RESTRICTED CALLER - caller's rights with restrictions
    RestrictedCaller,
}

/// ALTER PROCEDURE action kinds.
#[derive(Debug, Clone)]
pub enum AstAlterProcedureActionKind {
    // ========================================================================
    // Rename
    // ========================================================================
    /// RENAME TO <new_name>
    RenameTo {
        rename_span: Span,
        to_span: Span,
        new_name_span: Span,
    },

    // ========================================================================
    // SET/UNSET Properties
    // ========================================================================
    /// SET SECURE
    SetSecure { set_span: Span, secure_span: Span },
    /// UNSET SECURE
    UnsetSecure { unset_span: Span, secure_span: Span },
    /// SET <properties...> (LOG_LEVEL, TRACE_LEVEL, COMMENT, EXTERNAL_ACCESS_INTEGRATIONS, SECRETS, AUTO_EVENT_LOGGING)
    SetProperties {
        set_span: Span,
        properties_span: Span,
    },
    /// UNSET COMMENT
    UnsetComment {
        unset_span: Span,
        comment_span: Span,
    },

    // ========================================================================
    // Tag Operations
    // ========================================================================
    /// `SET TAG <tag_name> = '<value>' [, ...]`
    SetTag {
        set_span: Span,
        tag_span: Span,
        assignments_span: Span,
    },
    /// UNSET TAG <tag_name> [, ...]
    UnsetTag {
        unset_span: Span,
        tag_span: Span,
        tags_span: Span,
    },

    // ========================================================================
    // Execution Mode
    // ========================================================================
    /// EXECUTE AS { OWNER | CALLER | RESTRICTED CALLER }
    ExecuteAs {
        execute_span: Span,
        as_span: Span,
        mode: ExecuteAsMode,
        mode_span: Span,
    },

    // ========================================================================
    // Unknown / Fallback
    // ========================================================================
    /// Unknown / unclassified action (span-safe fallback).
    Unknown { span: Span },
}

// ============================================================================
// ALTER ROW ACCESS POLICY
// ============================================================================

/// ALTER ROW ACCESS POLICY statement.
///
/// Modifies properties of an existing row access policy.
/// Includes governance-critical operations like tag management, body updates,
/// and comment management.
#[derive(Debug, Clone)]
pub struct AstAlterRowAccessPolicy {
    pub node_id: crate::ast::NodeId,
    /// Span covering the entire ALTER ROW ACCESS POLICY statement.
    pub span: Span,
    /// Optional typed-syntax node id for this statement.
    pub syntax_id: Option<crate::syntax::SyntaxAlterRowAccessPolicyStmtId>,
    /// Span covering the ALTER keyword.
    pub alter_span: Span,
    /// Span covering the ROW keyword.
    pub row_span: Span,
    /// Span covering the ACCESS keyword.
    pub access_span: Span,
    /// Span covering the POLICY keyword.
    pub policy_span: Span,
    /// Optional span covering IF EXISTS.
    pub if_exists_span: Option<Span>,
    /// Span covering the policy name.
    pub name_span: Span,
    /// Span covering the action (everything after the policy name).
    pub action_span: Span,
    /// Parsed action.
    pub action: AstAlterRowAccessPolicyAction,
}

/// One ALTER ROW ACCESS POLICY action.
#[derive(Debug, Clone)]
pub struct AstAlterRowAccessPolicyAction {
    pub node_id: crate::ast::NodeId,
    /// Span covering the entire action.
    pub span: Span,
    /// Optional typed-syntax node id for this action.
    pub syntax_id: Option<crate::syntax::SyntaxAlterRowAccessPolicyActionId>,
    pub kind: AstAlterRowAccessPolicyActionKind,
}

/// ALTER ROW ACCESS POLICY action kinds.
#[derive(Debug, Clone)]
pub enum AstAlterRowAccessPolicyActionKind {
    /// RENAME TO <new_name>
    RenameTo {
        rename_span: Option<Span>,
        to_span: Option<Span>,
        new_name_span: Span,
    },

    /// `SET BODY -> <expression>`
    SetBody {
        set_span: Option<Span>,
        body_span: Option<Span>,
        arrow_span: Option<Span>,
        /// The body expression span
        expression_span: Span,
        /// Parsed body expression
        body: Box<AstExpr>,
    },

    /// `SET TAG <tag_name> = '<value>' [, ...]`
    SetTag {
        set_span: Option<Span>,
        tag_span: Option<Span>,
        /// Tag assignments as spans (covers "tag = 'value'" pairs)
        assignments_span: Span,
    },

    /// UNSET TAG <tag_name> [, ...]
    UnsetTag {
        unset_span: Option<Span>,
        tag_span: Option<Span>,
        /// Tag names to unset (comma-separated spans)
        tags_span: Span,
    },

    /// `SET COMMENT = '<string>'`
    SetComment {
        set_span: Option<Span>,
        comment_span: Option<Span>,
        eq_span: Option<Span>,
        /// Comment value span (the string literal)
        comment_value_span: Span,
    },

    /// UNSET COMMENT
    UnsetComment {
        unset_span: Option<Span>,
        comment_span: Option<Span>,
    },
}

/// DROP ROW ACCESS POLICY statement.
///
/// Supports both Snowflake and BigQuery syntax:
///
/// Snowflake: `DROP ROW ACCESS POLICY [ IF EXISTS ] <name>`
/// BigQuery:  `DROP ROW ACCESS POLICY [ IF EXISTS ] <name> ON <table>`
#[derive(Debug, Clone)]
pub struct AstDropRowAccessPolicy {
    pub node_id: crate::ast::NodeId,
    /// Span covering the entire DROP ROW ACCESS POLICY statement
    pub span: Span,
    /// Optional typed-syntax node id for this statement
    pub syntax_id: Option<crate::syntax::SyntaxDropRowAccessPolicyId>,

    // Keyword spans
    pub drop_span: Span,
    pub row_span: Span,
    pub access_span: Span,
    pub policy_span: Span,
    pub if_exists_span: Option<Span>,

    /// Span covering the policy name (may be qualified)
    pub policy_name_span: Span,

    // ---- BigQuery-specific fields (None for Snowflake) ----
    /// ON keyword span (BigQuery: ON table_name)
    pub on_table_span: Option<Span>,

    /// Span covering the table name in ON clause (BigQuery)
    pub table_name_span: Option<Span>,
}

/// DROP ALL ROW ACCESS POLICIES statement (BigQuery).
///
/// Syntax: `DROP ALL ROW ACCESS POLICIES ON <table>`
///
/// Note: POLICIES is an Identifier token (not a Keyword), unlike POLICY.
#[derive(Debug, Clone)]
pub struct AstDropAllRowAccessPolicies {
    pub node_id: crate::ast::NodeId,
    /// Span covering the entire statement
    pub span: Span,
    /// Optional typed-syntax node id for this statement
    pub syntax_id: Option<crate::syntax::SyntaxDropAllRowAccessPoliciesId>,

    // Keyword spans
    pub drop_span: Span,
    pub all_span: Span,
    pub row_span: Span,
    pub access_span: Span,
    /// POLICIES is an Identifier token
    pub policies_span: Span,

    /// ON keyword span
    pub on_span: Span,

    /// Span covering the table name (may be qualified: project.dataset.table)
    pub table_name_span: Span,
}

// ============================================================================
// MASKING POLICY
// ============================================================================

/// Syntax: CREATE [OR REPLACE] MASKING POLICY [IF NOT EXISTS] name AS (arg type, ...) RETURNS type -> body_expr [COMMENT = '...'] [EXEMPT_OTHER_POLICIES = TRUE|FALSE]
#[derive(Debug, Clone)]
pub struct AstCreateMaskingPolicy {
    pub node_id: crate::ast::NodeId,
    /// Span covering the entire CREATE MASKING POLICY statement
    pub span: Span,
    /// Optional typed-syntax node id for this statement
    pub syntax_id: Option<crate::syntax::SyntaxCreateMaskingPolicyId>,

    // Keyword spans (for semantic tracking and governance)
    pub create_span: Span,
    pub or_replace_span: Option<Span>,
    pub if_not_exists_span: Option<Span>,
    pub masking_span: Span,
    pub policy_span: Span,

    /// Span covering the policy name identifier
    pub policy_name_span: Span,

    /// AS keyword span (REQUIRED for MASKING POLICY, unlike ROW ACCESS POLICY)
    pub as_span: Span,

    /// Signature: (arg_name data_type, ...)
    /// Span covering the entire signature including parentheses
    pub signature_span: Span,

    /// `RETURNS <type>` span
    pub returns_span: Span,

    /// Return type span (must match first parameter type)
    pub return_type_span: Span,

    /// Arrow operator span (->)
    pub arrow_span: Span,

    /// Body expression span (the masking expression)
    pub body_expr_span: Span,

    /// Optional COMMENT clause span
    pub comment_span: Option<Span>,

    /// Optional EXEMPT_OTHER_POLICIES clause span
    pub exempt_other_policies_span: Option<Span>,

    // Parsed semantic structures
    /// Parsed policy parameters from signature
    /// First parameter = column to mask
    /// Additional parameters = conditional columns
    pub parameters: Vec<AstPolicyParameter>,

    /// Parsed body expression (masking expression)
    pub body: Box<AstExpr>,

    /// EXEMPT_OTHER_POLICIES value if specified
    pub exempt_other_policies_value: Option<bool>,
}

/// ALTER MASKING POLICY statement.
#[derive(Debug, Clone)]
pub struct AstAlterMaskingPolicy {
    pub node_id: crate::ast::NodeId,
    /// Span covering the entire ALTER MASKING POLICY statement.
    pub span: Span,
    /// Optional typed-syntax node id for this statement.
    pub syntax_id: Option<crate::syntax::SyntaxAlterMaskingPolicyStmtId>,
    /// Span covering the ALTER keyword.
    pub alter_span: Span,
    /// Span covering the MASKING keyword.
    pub masking_span: Span,
    /// Span covering the POLICY keyword.
    pub policy_span: Span,
    /// Optional span covering IF EXISTS.
    pub if_exists_span: Option<Span>,
    /// Span covering the policy name.
    pub name_span: Span,
    /// Span covering the action (everything after the policy name).
    pub action_span: Span,
    /// Parsed action.
    pub action: AstAlterMaskingPolicyAction,
}

/// One ALTER MASKING POLICY action.
#[derive(Debug, Clone)]
pub struct AstAlterMaskingPolicyAction {
    pub node_id: crate::ast::NodeId,
    /// Span covering the entire action.
    pub span: Span,
    /// Optional typed-syntax node id for this action.
    pub syntax_id: Option<crate::syntax::SyntaxAlterMaskingPolicyActionId>,
    pub kind: AstAlterMaskingPolicyActionKind,
}

/// ALTER MASKING POLICY action kinds.
#[derive(Debug, Clone)]
pub enum AstAlterMaskingPolicyActionKind {
    /// RENAME TO <new_name>
    RenameTo {
        rename_span: Option<Span>,
        to_span: Option<Span>,
        new_name_span: Span,
    },

    /// `SET BODY -> <expression>`
    /// Note: Unlike ROW ACCESS POLICY, this does NOT restate the signature
    SetBody {
        set_span: Option<Span>,
        body_span: Option<Span>,
        arrow_span: Option<Span>,
        /// The body expression span
        expression_span: Span,
        /// Parsed body expression
        body: Box<AstExpr>,
    },

    /// `SET TAG <tag_name> = '<value>' [, ...]`
    SetTag {
        set_span: Option<Span>,
        tag_span: Option<Span>,
        /// Tag assignments as spans (covers "tag = 'value'" pairs)
        assignments_span: Span,
    },

    /// UNSET TAG <tag_name> [, ...]
    UnsetTag {
        unset_span: Option<Span>,
        tag_span: Option<Span>,
        /// Tag names to unset (comma-separated spans)
        tags_span: Span,
    },

    /// `SET COMMENT = '<string>'`
    SetComment {
        set_span: Option<Span>,
        comment_span: Option<Span>,
        eq_span: Option<Span>,
        /// Comment value span (the string literal)
        comment_value_span: Span,
    },

    /// UNSET COMMENT
    UnsetComment {
        unset_span: Option<Span>,
        comment_span: Option<Span>,
    },
}

/// DROP MASKING POLICY statement.
///
/// Syntax: `DROP MASKING POLICY <name>`
/// NOTE: IF EXISTS is NOT supported per Snowflake documentation
#[derive(Debug, Clone)]
pub struct AstDropMaskingPolicy {
    pub node_id: crate::ast::NodeId,
    /// Span covering the entire DROP MASKING POLICY statement
    pub span: Span,
    /// Optional typed-syntax node id for this statement
    pub syntax_id: Option<crate::syntax::SyntaxDropMaskingPolicyId>,

    // Keyword spans
    pub drop_span: Span,
    pub masking_span: Span, // MASKING is Identifier!
    pub policy_span: Span,
    pub if_exists_span: Option<Span>,

    /// Span covering the policy name (may be qualified)
    pub policy_name_span: Span,
}

// ============================================================================
// ALTER STAGE
// ============================================================================

/// ALTER STAGE statement.
///
/// Modifies properties of an existing named internal or external stage.
/// Includes governance-critical operations like tag management, encryption,
/// credentials, and directory table configuration.
#[derive(Debug, Clone)]
pub struct AstAlterStage {
    pub node_id: crate::ast::NodeId,
    /// Span covering the entire ALTER STAGE statement.
    pub span: Span,
    /// Optional typed-syntax node id for this statement.
    pub syntax_id: Option<crate::syntax::SyntaxAlterStageStmtId>,
    /// Span covering the ALTER keyword.
    pub alter_span: Span,
    /// Span covering the STAGE keyword.
    pub stage_span: Span,
    /// Optional span covering IF EXISTS.
    pub if_exists_span: Option<Span>,
    /// Span covering the stage name.
    pub name_span: Span,
    /// Span covering the action (everything after the stage name).
    pub action_span: Span,
    /// Parsed action.
    pub action: AstAlterStageAction,
    /// Additional parsed actions for multi-property SET statements.
    ///
    /// Snowflake allows ALTER STAGE ... SET to include multiple properties in
    /// one statement (e.g. URL + ENCRYPTION + STORAGE_INTEGRATION). The first
    /// property is stored in `action`; subsequent known properties are stored
    /// here so governance analysis can evaluate all changes.
    pub additional_actions: Vec<AstAlterStageAction>,

    /// Unknown actions/properties not recognized by parser (defensive design).
    ///
    /// When Snowflake adds new ALTER STAGE actions, they are preserved here
    /// instead of causing parse errors. The formatter emits them unchanged,
    /// ensuring semantic preservation even when syntax is unrecognized.
    ///
    /// This field should remain empty under normal circumstances - presence of
    /// entries indicates either:
    /// 1. A new Snowflake feature added after this parser was written
    /// 2. Non-standard/custom syntax in the source
    ///
    /// Diagnostics should warn when this is non-empty.
    pub extras: Vec<AstUnknownClause>,
}

/// One ALTER STAGE action.
#[derive(Debug, Clone)]
pub struct AstAlterStageAction {
    pub node_id: crate::ast::NodeId,
    /// Span covering the entire action.
    pub span: Span,
    /// Optional typed-syntax node id for this action.
    pub syntax_id: Option<crate::syntax::SyntaxAlterStageActionId>,
    pub kind: AstAlterStageActionKind,
}

// ============================================================================
// Boxed structs for ALTER STAGE action variants
// ============================================================================

/// SET TAG action data (boxed in enum)
#[derive(Debug, Clone)]
pub struct SetStageTagAction {
    pub set_span: Option<Span>,
    pub tag_span: Option<Span>,
    /// Tag assignments as spans (covers "tag = 'value'" pairs)
    pub assignments_span: Span,
}

/// UNSET TAG action data (boxed in enum)
#[derive(Debug, Clone)]
pub struct UnsetStageTagAction {
    pub unset_span: Option<Span>,
    pub tag_span: Option<Span>,
    /// Tag names to unset (comma-separated spans)
    pub tags_span: Span,
}

/// SET ENCRYPTION action data (boxed in enum)
#[derive(Debug, Clone)]
pub struct SetEncryptionAction {
    pub set_span: Option<Span>,
    pub encryption_span: Option<Span>,
    /// Span covering the entire parenthesized encryption spec `( TYPE = ... )`
    pub encryption_spec_span: Option<Span>,
    /// Span covering the encryption type specification (TYPE = ...)
    pub type_spec_span: Option<Span>,
    /// Encryption type string (AWS_CSE, AWS_SSE_S3, AWS_SSE_KMS, GCS_SSE_KMS, AZURE_CSE, NONE)
    pub encryption_type_span: Option<Span>,
    /// Optional MASTER_KEY specification span
    pub master_key_span: Option<Span>,
    /// Optional KMS_KEY_ID specification span
    pub kms_key_id_span: Option<Span>,
    /// TokenId for the opening paren of the encryption spec
    pub lparen_token: Option<crate::cst::TokenId>,
    /// TokenId for the closing paren of the encryption spec
    pub rparen_token: Option<crate::cst::TokenId>,
}

/// SET URL action data (boxed in enum)
#[derive(Debug, Clone)]
pub struct SetUrlAction {
    pub set_span: Option<Span>,
    pub url_span: Option<Span>,
    /// URL value span (the string literal)
    pub url_value_span: Span,
    /// Parsed URL string content (quotes stripped, `''` escapes folded).
    /// Empty when the value side is not a string literal — downstream
    /// content predicates simply won't match.
    pub url_text: String,
}

/// SET CREDENTIALS action data (boxed in enum)
#[derive(Debug, Clone)]
pub struct SetCredentialsAction {
    pub set_span: Option<Span>,
    pub credentials_span: Option<Span>,
    /// Span covering the credentials specification in parentheses
    pub credentials_spec_span: Span,
    /// TokenId for the opening paren of the credentials spec
    pub lparen_token: Option<crate::cst::TokenId>,
    /// TokenId for the closing paren of the credentials spec
    pub rparen_token: Option<crate::cst::TokenId>,
    /// Decomposed `KEY = VALUE` options inside the parens. Empty when
    /// the parser could not decompose the body (defensive zero-loss
    /// fallback — formatter still emits via spans).
    pub options: Vec<AstStageCredentialOption>,
}

/// SET STORAGE_INTEGRATION action data (boxed in enum)
#[derive(Debug, Clone)]
pub struct SetStorageIntegrationAction {
    pub set_span: Option<Span>,
    pub storage_integration_span: Option<Span>,
    /// Integration name span
    pub integration_name_span: Span,
}

/// SET FILE_FORMAT action data (boxed in enum)
#[derive(Debug, Clone)]
pub struct SetFileFormatAction {
    pub set_span: Option<Span>,
    pub file_format_span: Option<Span>,
    /// Span covering the file format specification (FORMAT_NAME or TYPE)
    pub format_spec_span: Span,
    /// TokenId for the opening paren of the file format spec
    pub lparen_token: Option<crate::cst::TokenId>,
    /// TokenId for the closing paren of the file format spec
    pub rparen_token: Option<crate::cst::TokenId>,
}

/// SET DIRECTORY action data (boxed in enum)
#[derive(Debug, Clone)]
pub struct SetDirectoryAction {
    pub set_span: Option<Span>,
    pub directory_span: Option<Span>,
    /// ENABLE = TRUE/FALSE span
    pub enable_spec_span: Span,
    /// TokenId for the opening paren of the directory spec
    pub lparen_token: Option<crate::cst::TokenId>,
    /// TokenId for the closing paren of the directory spec
    pub rparen_token: Option<crate::cst::TokenId>,
}

/// REFRESH action data (boxed in enum)
#[derive(Debug, Clone)]
pub struct RefreshDirectoryAction {
    pub refresh_span: Span,
    /// Optional SUBPATH specification span
    pub subpath_span: Option<Span>,
}

/// ALTER STAGE action kinds.
///
/// Variants are intentionally span-first to avoid information loss and
/// to make it safe to introduce parsing incrementally.
#[derive(Debug, Clone)]
pub enum AstAlterStageActionKind {
    /// RENAME TO <new_name>
    RenameTo {
        rename_span: Option<Span>,
        to_span: Option<Span>,
        new_name_span: Span,
    },

    // ========================================================================
    // Governance & Policy Actions (Critical for risk/policy analysis)
    // Note: Large variants are boxed to reduce enum size
    // ========================================================================
    /// `SET TAG <tag_name> = '<value>' [, ...]`
    /// Boxed due to size (3 fields)
    SetTag(Box<SetStageTagAction>),

    /// UNSET TAG <tag_name> [, ...]
    /// Boxed due to size (3 fields)
    UnsetTag(Box<UnsetStageTagAction>),

    // ========================================================================
    // Security & Encryption (Critical for security governance)
    // ========================================================================
    /// SET ENCRYPTION = ( TYPE = '...' [MASTER_KEY = '...'] [KMS_KEY_ID = '...'] | TYPE = 'NONE' )
    /// Boxed due to size (6 fields)
    SetEncryption(Box<SetEncryptionAction>),

    // ========================================================================
    // Access Control & Integration
    // ========================================================================
    /// SET URL = '...'
    /// Boxed due to size (3 fields)
    SetUrl(Box<SetUrlAction>),

    /// SET CREDENTIALS = ( AWS_KEY_ID = '...' AWS_SECRET_KEY = '...' ... )
    /// Boxed due to size (3 fields)
    SetCredentials(Box<SetCredentialsAction>),

    /// SET STORAGE_INTEGRATION = <integration_name>
    /// Boxed due to size (3 fields)
    SetStorageIntegration(Box<SetStorageIntegrationAction>),

    // ========================================================================
    // File Format & Options
    // ========================================================================
    /// SET FILE_FORMAT = ( FORMAT_NAME = '...' | TYPE = CSV | ... )
    /// Boxed due to size (3 fields)
    SetFileFormat(Box<SetFileFormatAction>),

    /// SET COMMENT = '...'
    SetComment {
        set_span: Option<Span>,
        comment_span: Option<Span>,
        comment_value_span: Span,
    },

    /// SET USE_PRIVATELINK_ENDPOINT = TRUE | FALSE
    SetUsePrivatelink {
        set_span: Option<Span>,
        use_privatelink_span: Option<Span>,
        value_span: Span,
    },

    // ========================================================================
    // Directory Table (Data Discovery/Compliance)
    // ========================================================================
    /// SET DIRECTORY = ( ENABLE = TRUE | FALSE )
    /// Boxed due to size (3 fields)
    SetDirectory(Box<SetDirectoryAction>),

    /// REFRESH [SUBPATH = '...']
    /// Boxed due to size (2 fields)
    RefreshDirectory(Box<RefreshDirectoryAction>),

    // ========================================================================
    // Generic/Unknown
    // ========================================================================
    /// Generic SET with unparsed parameters
    Set {
        set_span: Option<Span>,
        parameters_span: Span,
    },

    /// Unknown / unclassified action.
    Unknown { span: Span },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AstStageFileFormatSpec {
    /// FORMAT_NAME = 'format_name'
    FormatName,
    /// `TYPE = CSV | JSON | AVRO | ORC | PARQUET | XML | CUSTOM [ formatTypeOptions ]`
    Type,
}

/// Object class named by a `SHOW <objects>` statement. Enumerates the
/// common + governance-relevant classes; the long tail falls back to
/// `Other(raw_phrase)`. `Grants` and `Policies` carry typed sub-shape.
#[derive(Debug, Clone, PartialEq)]
pub enum AstShowKind {
    Objects,
    Tables,
    ExternalTables,
    DynamicTables,
    IcebergTables,
    EventTables,
    Views,
    MaterializedViews,
    Columns,
    Databases,
    Schemas,
    Sequences,
    Stages,
    Pipes,
    Streams,
    Tasks,
    Functions,
    Procedures,
    Warehouses,
    Users,
    Roles,
    Parameters,
    FileFormats,
    Tags,
    Integrations,
    PrimaryKeys,
    /// `SHOW <kind> POLICIES`.
    Policies(ShowPolicyKind),
    /// `SHOW [FUTURE] GRANTS …` — privilege-graph enumeration.
    Grants(ShowGrantsSpec),
    /// Long-tail class; carries the raw object phrase, upper-cased.
    Other(String),
}

/// Policy family in `SHOW <kind> POLICIES`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShowPolicyKind {
    Masking,
    RowAccess,
    Session,
    Password,
    Network,
    Authentication,
    Projection,
    Aggregation,
    Join,
    /// `SHOW POLICIES` with no recognized family qualifier.
    Unspecified,
}

/// Typed shape of `SHOW [FUTURE] GRANTS …`.
#[derive(Debug, Clone, PartialEq)]
pub struct ShowGrantsSpec {
    /// `SHOW FUTURE GRANTS …`.
    pub future: bool,
    pub relation: ShowGrantsRelation,
}

/// Which side of the grant graph a `SHOW GRANTS` enumerates.
#[derive(Debug, Clone, PartialEq)]
pub enum ShowGrantsRelation {
    /// Bare `SHOW GRANTS` — privileges held by the current user.
    CurrentUser,
    /// `SHOW GRANTS ON ACCOUNT` / `ON <object_class> <name>`.
    On(ShowGrantsObject),
    /// `SHOW GRANTS TO { ROLE | USER | SHARE | … } <name>`.
    To(ShowPrincipal),
    /// `SHOW GRANTS OF { ROLE | SHARE | … } <name>`.
    Of(ShowPrincipal),
    /// `SHOW FUTURE GRANTS IN { SCHEMA | DATABASE } <name>` — the
    /// container the future grants apply within.
    In(ShowScope),
}

/// Object side of `SHOW GRANTS ON …`.
#[derive(Debug, Clone, PartialEq)]
pub enum ShowGrantsObject {
    /// `ON ACCOUNT`.
    Account,
    /// `ON <object_class> <name>` — `object_class` is the upper-cased
    /// class noun (e.g. `TABLE`, `DATABASE`, `SCHEMA`).
    Named {
        object_class: String,
        name: ShowName,
    },
}

/// Principal side of `SHOW GRANTS TO/OF …`.
#[derive(Debug, Clone, PartialEq)]
pub struct ShowPrincipal {
    pub kind: ShowPrincipalKind,
    pub name: ShowName,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ShowPrincipalKind {
    Role,
    User,
    Share,
    DatabaseRole,
    Application,
    ApplicationRole,
    /// Unrecognized principal keyword — carries the upper-cased text.
    Other(String),
}

/// `IN <scope>` filter on a SHOW statement.
#[derive(Debug, Clone, PartialEq)]
pub enum ShowScope {
    /// `IN ACCOUNT`.
    Account,
    /// `IN DATABASE [name]`.
    Database(Option<ShowName>),
    /// `IN SCHEMA [name]`.
    Schema(Option<ShowName>),
    /// `IN TABLE name`.
    Table(ShowName),
    /// `IN VIEW name`.
    View(ShowName),
    /// Any other scope keyword (e.g. `MODEL`, `APPLICATION`); `kind`
    /// is the upper-cased keyword.
    Other {
        kind: String,
        name: Option<ShowName>,
    },
}

/// A (possibly qualified) name captured in a SHOW clause, with its
/// source span. `text` is the raw name as written.
#[derive(Debug, Clone, PartialEq)]
pub struct ShowName {
    pub text: String,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct AstShow {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    pub kind: AstShowKind,
    /// Typed `IN <scope>` filter, when present. `None` for grants
    /// (the IN container is folded into the grants relation).
    pub scope: Option<ShowScope>,
    /// Span covering the SHOW keyword.
    pub keyword_span: Span,
    /// Optional TERSE modifier span.
    pub terse_span: Option<Span>,
    /// Optional HISTORY modifier span.
    pub history_span: Option<Span>,
    /// Span covering the "object phrase" immediately following
    /// SHOW, e.g. TABLES, FUNCTIONS, VERSIONS IN MODEL, etc.
    /// This is the primary hook for downstream tooling to
    /// distinguish specific SHOW commands listed in the
    /// Snowflake documentation.
    pub object_span: Option<Span>,
    /// Optional LIKE pattern span, e.g. LIKE 'FOO%'. The span
    /// covers only the pattern expression token for now.
    pub like_pattern_span: Option<Span>,
    /// Span covering the IN keyword in "IN DATABASE mydb".
    /// Used by the formatter to emit the IN keyword with trivia.
    pub in_span: Option<Span>,
    /// Optional span covering the full IN scope phrase that
    /// follows the IN keyword, e.g. "DATABASE mydb" in
    /// "IN DATABASE mydb". This is a convenience for callers
    /// that want to round-trip or inspect the complete scope.
    pub in_scope_span: Option<Span>,
    /// Optional STARTS WITH clause span.
    pub starts_with_span: Option<Span>,
    /// Optional LIMIT expression span for `LIMIT <n> [FROM <m>]`.
    /// For now this is the numeric literal span of `<n>`.
    pub limit_span: Option<Span>,
    /// Optional FROM offset span in `LIMIT <n> FROM <m>`.
    pub limit_from_span: Option<Span>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AstUseKind {
    Role,
    Database,
    Catalog,
    Schema,
    Warehouse,
    SecondaryRoles,
}

/// USE statement for session context (USE ROLE, USE DATABASE, USE SCHEMA, USE WAREHOUSE)
#[derive(Debug, Clone, PartialEq)]
pub struct AstUse {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    pub kind: AstUseKind,
    /// Span covering the USE keyword
    pub use_keyword_span: Span,
    /// Span covering the context type keyword (ROLE, DATABASE, SCHEMA, WAREHOUSE)
    /// May be None for USE DATABASE (where DATABASE keyword is optional)
    pub kind_keyword_span: Option<Span>,
    /// Span covering the object name/identifier (can be multi-part for schema: db.schema)
    pub object_span: Span,
}

#[derive(Debug, Clone)]
pub enum AstDescribeKind {
    Table,
    View,
    Function,
    Procedure,
    Other,
}

#[derive(Debug, Clone)]
pub struct AstDescribe {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    pub kind: AstDescribeKind,
    /// Span covering the DESCRIBE / DESC keyword.
    pub keyword_span: Span,
    /// Span covering the object phrase immediately following
    /// DESCRIBE, e.g. TABLE my_table, VIEW my_view, FUNCTION
    /// my_func(NUMBER), etc. We intentionally keep this generic
    /// and let downstream helpers interpret the text.
    pub object_span: Option<Span>,
    /// Optional TYPE clause (e.g., "TYPE = COLUMNS" or "TYPE = STAGE")
    pub type_clause_span: Option<Span>,
}

#[derive(Debug, Clone)]
pub struct AstTruncate {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    /// Span covering the TRUNCATE keyword.
    pub keyword_span: Span,
    /// Optional span covering the TABLE keyword, if present.
    pub table_span: Option<Span>,
    /// Optional span covering the IF EXISTS phrase.
    pub if_exists_span: Option<Span>,
    /// Span covering the table name to truncate (possibly qualified).
    pub target_table_span: Option<Span>,
}

#[derive(Debug, Clone)]
pub struct AstDrop {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    /// Span covering the DROP keyword.
    pub keyword_span: Span,
    /// Span covering the object type (TABLE, VIEW, etc.).
    pub object_type_span: Option<Span>,
    /// Optional span covering the IF EXISTS phrase.
    pub if_exists_span: Option<Span>,
    /// Span covering the object name to drop (possibly qualified).
    pub target_name_span: Option<Span>,
    /// Optional span covering CASCADE or RESTRICT keyword.
    pub cascade_restrict_span: Option<Span>,
}

#[derive(Debug, Clone)]
pub struct AstInsert {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    /// Span covering the INSERT keyword.
    pub keyword_span: Span,
    /// Optional span covering the INTO keyword.
    pub into_span: Option<Span>,
    /// Optional span covering the OVERWRITE keyword, if present.
    pub overwrite_span: Option<Span>,
    /// Optional span covering the REPLACE keyword after INSERT (Databricks INSERT REPLACE INTO).
    pub replace_span: Option<Span>,
    /// Span covering the target table reference after INTO. This is
    /// intentionally permissive and may include qualifiers and
    /// quoting, e.g. db.schema."Table".
    pub target_table_span: Option<Span>,
    /// Optional span covering the column list, including parentheses,
    /// e.g. "(col1, col2)".
    pub columns_span: Option<Span>,
    /// Span covering everything after INSERT up to a semicolon or EOF.
    pub body_span: Option<Span>,
    /// Very shallow classification of the INSERT source: VALUES list
    /// vs. query-based insert. This remains generic and does not
    /// attempt to parse individual expressions.
    pub source_kind: AstInsertSourceKind,
    /// If source_kind is Values, span covering the entire VALUES clause.
    pub values_span: Option<Span>,
    /// Span covering just the VALUES keyword token (for trivia-preserving emission).
    pub values_keyword_span: Option<Span>,
    /// If source_kind is Values, spans for each parenthesized row in the
    /// VALUES list.
    pub values_rows_spans: Vec<Span>,
    /// If source_kind is Values, parsed expressions for each VALUES row.
    /// Each inner Vec represents one row's expressions.
    pub values_rows: Vec<Vec<AstExpr>>,
    /// MySQL 8.0.19 `VALUES ROW(...)` table-value-constructor form. Rows
    /// carry a ROW keyword, so the formatter must emit row spans verbatim
    /// instead of synthesizing parens around parsed expressions.
    pub values_row_constructor: bool,
    /// If source_kind is Query, span covering the query body (SELECT / WITH ...).
    pub query_span: Option<Span>,
    /// If source_kind is Query, the parsed query (SELECT / WITH ...).
    pub query: Option<Box<AstStmt>>,

    // PostgreSQL extensions (always present, usually None)
    pub output: Option<AstOutputClause>,
    pub returning: Option<AstReturning>,
    pub on_conflict: Option<AstOnConflict>,

    // PostgreSQL extensions: writable CTEs
    /// Optional WITH clause (CTEs) that precedes the INSERT
    pub with_clause: Option<AstWithClause>,

    // Snowflake extensions
    pub overwrite: bool, // INSERT OVERWRITE
    /// Optional semicolon token ID when INSERT appears in scripting context
    pub semicolon_token: Option<crate::cst::TokenId>,

    // PostgreSQL: OVERRIDING { SYSTEM | USER } VALUE
    /// Span covering "OVERRIDING SYSTEM VALUE" or "OVERRIDING USER VALUE"
    pub overriding_value_span: Option<Span>,

    // PostgreSQL: INSERT INTO t DEFAULT VALUES
    /// Span covering "DEFAULT VALUES" when source_kind is DefaultValues
    pub default_values_span: Option<Span>,

    // MSSQL extensions
    /// Optional table hints on INSERT target, e.g. INSERT INTO t WITH (TABLOCK)
    pub table_hints: Option<Box<AstTableHintClause>>,

    // MySQL extensions
    /// Optional LOW_PRIORITY / HIGH_PRIORITY modifier after INSERT.
    pub priority: Option<AstInsertPriority>,
    /// Optional span covering the IGNORE modifier.
    pub ignore_span: Option<Span>,
    /// Optional span covering PARTITION (p, ...) selection, parens included.
    pub partition_span: Option<Span>,
    /// Optional span covering the 8.0.19 row alias: AS alias [(col, ...)].
    pub row_alias_span: Option<Span>,
    /// If source_kind is SetAssignments, span covering SET col = expr, ...
    pub set_clause_span: Option<Span>,
    /// If source_kind is SetAssignments, parsed (column, value) assignments.
    pub set_assignments: Vec<(String, AstExpr)>,
    /// Optional ON DUPLICATE KEY UPDATE clause.
    pub on_duplicate_key_update: Option<AstOnDuplicateKeyUpdate>,
}

/// MySQL INSERT/REPLACE priority modifier. Lexes as an identifier; reserved
/// word in MySQL so unquoted-lexeme matching is unambiguous.
#[derive(Debug, Clone)]
pub enum AstInsertPriority {
    Low { span: Span },
    High { span: Span },
}

impl AstInsertPriority {
    pub fn span(&self) -> Span {
        match self {
            AstInsertPriority::Low { span } | AstInsertPriority::High { span } => *span,
        }
    }
}

/// MySQL ON DUPLICATE KEY UPDATE clause on INSERT.
#[derive(Debug, Clone)]
pub struct AstOnDuplicateKeyUpdate {
    pub node_id: crate::ast::NodeId,
    /// Full clause span: ON ... through last assignment expression.
    pub span: Span,
    /// Span covering the ON DUPLICATE KEY UPDATE keywords.
    pub keywords_span: Span,
    /// Parsed (column, value) assignments.
    pub assignments: Vec<(String, AstExpr)>,
}

/// MySQL REPLACE statement — delete-then-insert by unique key.
/// (`AstReplace` is the unrelated `SELECT * REPLACE (...)` star modifier.)
#[derive(Debug, Clone)]
pub struct AstReplaceInto {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    /// Span covering the REPLACE keyword.
    pub keyword_span: Span,
    /// Optional LOW_PRIORITY modifier (REPLACE grammar has no HIGH_PRIORITY).
    pub priority: Option<AstInsertPriority>,
    /// Optional span covering the INTO keyword (optional in MySQL).
    pub into_span: Option<Span>,
    /// Span covering the target table reference (possibly qualified).
    pub target_table_span: Option<Span>,
    /// Optional span covering PARTITION (p, ...) selection, parens included.
    pub partition_span: Option<Span>,
    /// Optional span covering the column list, parens included.
    pub columns_span: Option<Span>,
    /// Span covering the source body (VALUES rows / query / SET assignments).
    pub body_span: Option<Span>,
    /// Source classification, shared with INSERT.
    pub source_kind: AstInsertSourceKind,
    /// If source_kind is Values, span covering the entire VALUES clause.
    pub values_span: Option<Span>,
    /// Span covering just the VALUES/VALUE keyword token.
    pub values_keyword_span: Option<Span>,
    /// If source_kind is Values, spans for each parenthesized row.
    pub values_rows_spans: Vec<Span>,
    /// If source_kind is Values, parsed expressions per row.
    pub values_rows: Vec<Vec<AstExpr>>,
    /// MySQL 8.0.19 `VALUES ROW(...)` form — see [`AstInsert`].
    pub values_row_constructor: bool,
    /// If source_kind is Query, span covering the query body.
    pub query_span: Option<Span>,
    /// If source_kind is Query, the parsed query.
    pub query: Option<Box<AstStmt>>,
    /// If source_kind is SetAssignments, span covering SET col = expr, ...
    pub set_clause_span: Option<Span>,
    /// If source_kind is SetAssignments, parsed (column, value) assignments.
    pub set_assignments: Vec<(String, AstExpr)>,
}

#[derive(Debug, Clone)]
pub enum AstInsertSourceKind {
    Unknown,
    Values,
    Query,
    /// PostgreSQL: INSERT INTO t DEFAULT VALUES
    DefaultValues,
    /// MySQL: INSERT/REPLACE ... SET col = expr, ...
    SetAssignments,
}

#[derive(Debug, Clone)]
pub enum AstMultiInsertMode {
    UnconditionalAll,
    ConditionalFirst,
    ConditionalAll,
}

#[derive(Debug, Clone)]
pub struct AstMultiInsertIntoClause {
    pub node_id: crate::ast::NodeId,
    /// Span covering the INTO keyword.
    pub into_span: Span,
    /// Span covering the target table reference after INTO.
    pub target_table_span: Option<Span>,
    /// Optional span covering the column list, including parentheses.
    pub columns_span: Option<Span>,
    /// Optional span covering the VALUES clause for this INTO, if present.
    pub values_span: Option<Span>,
}

#[derive(Debug, Clone)]
pub struct AstMultiInsertWhenClause {
    pub node_id: crate::ast::NodeId,
    /// Span covering the WHEN keyword.
    pub when_span: Span,
    /// Span covering the condition expression up to THEN.
    pub condition_span: Option<Span>,
    /// Span covering the THEN keyword.
    pub then_span: Span,
    /// INTO clauses that belong to this WHEN.
    pub into_clauses: Vec<AstMultiInsertIntoClause>,
}

#[derive(Debug, Clone)]
pub struct AstMultiInsert {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    /// Span covering the INSERT keyword.
    pub keyword_span: Span,
    /// Optional span for OVERWRITE.
    pub overwrite_span: Option<Span>,
    /// Mode: unconditional ALL, or conditional FIRST/ALL.
    pub mode: AstMultiInsertMode,
    /// Span covering the ALL or FIRST keyword.
    pub mode_span: Span,
    /// INTO clauses at the top level (for unconditional multi-table insert).
    pub into_clauses: Vec<AstMultiInsertIntoClause>,
    /// WHEN/THEN/INTO blocks (for conditional multi-table insert).
    pub when_clauses: Vec<AstMultiInsertWhenClause>,
    /// Optional ELSE INTO clauses.
    pub else_into_clauses: Vec<AstMultiInsertIntoClause>,
    /// The trailing subquery (SELECT ... or set operation) that provides the source data.
    pub subquery: Option<Box<AstStmt>>,
}

#[derive(Debug, Clone)]
pub struct AstSetAssignment {
    pub node_id: crate::ast::NodeId,
    /// Parsed column expression being assigned (typically an identifier).
    pub column: Box<AstExpr>,
    /// Span covering the equals operator.
    pub equals_span: Span,
    /// Parsed value expression.
    pub value: Box<AstExpr>,
    /// Span covering the entire assignment (column = value).
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct AstUpdate {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    /// Span covering the UPDATE keyword.
    pub keyword_span: Span,
    /// Legacy: span covering everything after UPDATE up to a semicolon or EOF.
    pub body_span: Option<Span>,
    /// T-SQL TOP clause: `UPDATE TOP (10) table SET ...`
    pub top: Option<AstTop>,
    /// Parsed target table reference (can include alias, time travel, etc.).
    pub target_table: Option<Box<AstTableRef>>,
    /// Span covering the SET keyword + all assignments (legacy).
    pub set_span: Option<Span>,
    /// Span covering just the SET keyword token.
    pub set_keyword_span: Option<Span>,
    /// Individual SET assignments (col = expr pairs) - fully parsed.
    pub set_assignments: Vec<AstSetAssignment>,
    /// Optional FROM clause with parsed table references and joins.
    pub from: Vec<Box<AstTableRef>>,
    /// Span covering just the FROM keyword token in the FROM clause.
    pub from_keyword_span: Option<Span>,
    /// Optional WHERE clause as parsed expression.
    pub where_clause: Option<Box<AstExpr>>,
    /// Span covering just the WHERE keyword token.
    pub where_keyword_span: Option<Span>,
    /// MySQL `LOW_PRIORITY` modifier span (after UPDATE keyword).
    pub low_priority_span: Option<Span>,
    /// MySQL `IGNORE` modifier span (after UPDATE keyword).
    pub ignore_span: Option<Span>,
    /// MySQL multi-table comma form: additional target tables after the
    /// first (`UPDATE t1, t2 SET ...`). Each may carry its own join chain.
    pub additional_targets: Vec<Box<AstTableRef>>,
    /// MySQL trailing `ORDER BY ...` clause (single-table UPDATE).
    pub order_by: Option<Box<AstOrderBy>>,
    /// MySQL trailing `LIMIT n` row-count expression (single-table UPDATE).
    pub limit: Option<Box<AstExpr>>,
    /// Span covering the trailing `LIMIT` keyword token.
    pub limit_keyword_span: Option<Span>,
    /// PostgreSQL RETURNING clause
    pub output: Option<AstOutputClause>,
    pub returning: Option<AstReturning>,
    /// Optional WITH clause (CTEs) that precedes the UPDATE
    pub with_clause: Option<AstWithClause>,
    /// Optional semicolon token ID when UPDATE appears in scripting context
    pub semicolon_token: Option<crate::cst::TokenId>,
}

#[derive(Debug, Clone)]
pub struct AstDelete {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    /// Span covering the DELETE keyword.
    pub keyword_span: Span,
    /// Legacy: span covering everything after DELETE up to a semicolon or EOF.
    pub body_span: Option<Span>,
    /// T-SQL TOP clause: `DELETE TOP (10) FROM table ...`
    pub top: Option<AstTop>,
    /// Span covering just the FROM keyword token.
    pub from_keyword_span: Option<Span>,
    /// Parsed target table reference (can include alias, time travel, etc.).
    pub target_table: Option<Box<AstTableRef>>,
    /// MySQL multi-table target list before FROM (`DELETE t1, t2 FROM ...`,
    /// `DELETE t1.* FROM ...`). Each ref's span includes any trailing `.*`.
    pub targets: Vec<Box<AstTableRef>>,
    /// Optional USING clause with parsed table references and joins.
    pub using: Vec<Box<AstTableRef>>,
    /// Span covering just the USING keyword token.
    pub using_keyword_span: Option<Span>,
    /// Optional WHERE clause as parsed expression.
    pub where_clause: Option<Box<AstExpr>>,
    /// Span covering just the WHERE keyword token.
    pub where_keyword_span: Option<Span>,
    /// MySQL `LOW_PRIORITY` modifier span (after DELETE keyword).
    pub low_priority_span: Option<Span>,
    /// MySQL `QUICK` modifier span (after DELETE keyword).
    pub quick_span: Option<Span>,
    /// MySQL `IGNORE` modifier span (after DELETE keyword).
    pub ignore_span: Option<Span>,
    /// MySQL trailing `ORDER BY ...` clause (single-table DELETE).
    pub order_by: Option<Box<AstOrderBy>>,
    /// MySQL trailing `LIMIT n` row-count expression (single-table DELETE).
    pub limit: Option<Box<AstExpr>>,
    /// Span covering the trailing `LIMIT` keyword token.
    pub limit_keyword_span: Option<Span>,
    /// PostgreSQL RETURNING clause
    pub output: Option<AstOutputClause>,
    pub returning: Option<AstReturning>,
    /// Optional WITH clause (CTEs) that precedes the DELETE
    pub with_clause: Option<AstWithClause>,
    /// Optional semicolon token ID when DELETE appears in scripting context
    pub semicolon_token: Option<crate::cst::TokenId>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum AstMergeClauseKind {
    Matched,
    NotMatched,
    NotMatchedBySource,
    NotMatchedByTarget,
}

#[derive(Debug, Clone)]
pub enum AstMergeActionKind {
    UpdateAllByName {
        update_span: Span,
        all_span: Span,
        by_span: Span,
        name_span: Span,
    }, // UPDATE ALL BY NAME
    UpdateSetStar {
        update_span: Span,
    }, // UPDATE SET *
    UpdateSet {
        set_span: Span,
        assignments: Vec<AstSetAssignment>, // Individual SET assignments
    }, // UPDATE SET ...
    Delete {
        delete_span: Span,
    }, // DELETE
    InsertAllByName {
        insert_span: Span,
        all_span: Span,
        by_span: Span,
        name_span: Span,
    }, // INSERT ALL BY NAME
    InsertStar {
        insert_span: Span,
    }, // INSERT *
    InsertValues {
        insert_span: Span,          // INSERT (...) VALUES (...)
        columns_span: Option<Span>, // column list span (if present)
        columns: Vec<AstExpr>,      // Parsed column expressions (typically identifiers)
        values_span: Span,          // VALUES (...) span
        values: Vec<AstExpr>,       // Parsed value expressions
        syntax_id: Option<crate::syntax::SyntaxMergeInsertValuesId>, // Syntax layer for trivia
    },
}

#[derive(Debug, Clone)]
pub struct AstMergeClause {
    pub node_id: crate::ast::NodeId,
    pub kind: AstMergeClauseKind, // MATCHED vs NOT MATCHED vs NOT MATCHED BY SOURCE
    pub when_span: Span,          // WHEN keyword span
    pub not_span: Option<Span>,   // NOT (for NOT MATCHED)
    pub matched_span: Span,       // MATCHED span (mandatory per Snowflake syntax)
    pub by_source_span: Option<(Span, Span)>, // BY and SOURCE spans (for NOT MATCHED BY SOURCE)
    pub and_condition_span: Option<Span>, // optional AND <case_predicate>
    pub and_condition: Option<Box<crate::ast::AstExpr>>, // parsed condition expression
    pub then_span: Span,          // THEN keyword span (mandatory per Snowflake syntax)
    pub action: AstMergeActionKind, // UPDATE/DELETE/INSERT variant
    pub span: Span,               // span covering the whole clause
}

#[derive(Debug, Clone)]
pub struct AstMerge {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    pub keyword_span: Span,
    /// Optional WITH clause (CTEs) that precede the MERGE statement.
    pub with_clause: Option<AstWithClause>,
    /// Span covering `WITH SCHEMA EVOLUTION` in Databricks Delta MERGE.
    pub with_schema_evolution_span: Option<Span>,
    /// Optional span covering the `INTO` keyword token between
    /// `MERGE` and the target table. Absent for BigQuery-style
    /// `MERGE target USING …`, present elsewhere.
    pub into_span: Option<Span>,
    pub target_table_span: Option<Span>,
    pub using_span: Option<Span>,
    /// Span covering just the USING keyword token (for trivia-preserving emission).
    pub using_keyword_span: Option<Span>,
    /// If USING is a direct table reference (not a subquery), the parsed table ref.
    /// When this is `Some`, `using_subquery` is `None`, and vice-versa.
    pub using_table_ref: Option<Box<AstTableRef>>,
    /// If USING contains a subquery, the parsed SELECT statement or set operation.
    pub using_subquery: Option<Box<AstStmt>>,
    /// Alias for the USING source (the identifier after the subquery or table).
    pub using_alias_span: Option<Span>,
    pub on_span: Option<Span>,
    /// Parsed ON condition expression (for semantic analysis like tautology detection).
    pub on_condition: Option<Box<AstExpr>>,
    pub clauses: Vec<AstMergeClause>,
    /// Optional OUTPUT clause (MSSQL): OUTPUT ... [INTO ...]
    pub output: Option<AstOutputClause>,
    /// Optional semicolon token ID when MERGE appears in scripting context
    pub semicolon_token: Option<crate::cst::TokenId>,
}

impl AstInsert {
    /// Attempt to slice out the target table name by scanning the
    /// body for the first identifier after INTO. This is intentionally
    /// conservative and may return None if the pattern does not match
    /// simple "`INTO <ident>`" forms.
    pub fn target_table_span(&self) -> Option<Span> {
        self.target_table_span
    }
}

/// Generates a `node_id` match expression for enums where ALL variants are
/// inline structs with a `node_id` field (e.g., `AstExpr`).
///
/// Usage: `impl_node_id_match!(self, EnumName, [Variant1, Variant2, ...])`
macro_rules! impl_node_id_match {
    ($self:ident, $Enum:ident, [ $( $v:ident ),* $(,)? ]) => {
        match $self {
            $( $Enum::$v { node_id, .. } => *node_id, )*
        }
    };
}

/// Generates `span()` and `node_id()` accessors for an AST enum.
///
/// Eliminates ~350 lines of boilerplate match arms by declaring the access
/// pattern once. Each variant falls into one of three categories:
///
/// - `struct_variants`: `Variant(inner)` where inner has `.span` and `.node_id` fields
/// - `inline_variants`: `Variant { span, node_id, .. }` with fields destructured directly
/// - `custom_span`: variants needing a custom expression for `span()` (but standard `node_id`)
macro_rules! impl_ast_accessors {
    (
        $Enum:ident,
        struct_variants: [ $( $sv:ident ),* $(,)? ],
        inline_variants: [ $( $iv:ident ),* $(,)? ],
        custom_span: { $( $cv:ident ($cb:ident) => $cexpr:expr ),* $(,)? } $(,)?
    ) => {
        impl $Enum {
            /// Returns the span covering this entire node.
            pub fn span(&self) -> Span {
                match self {
                    $( $Enum::$sv(s) => s.span, )*
                    $( $Enum::$iv { span, .. } => *span, )*
                    $( $Enum::$cv($cb) => $cexpr, )*
                }
            }

            /// Returns the unique node ID for this node.
            ///
            /// All variants have an explicit `node_id` field assigned during parsing.
            /// This is the canonical source of truth for node identity.
            pub fn node_id(&self) -> crate::ast::NodeId {
                match self {
                    $( $Enum::$sv(s) => s.node_id, )*
                    $( $Enum::$iv { node_id, .. } => *node_id, )*
                    $( $Enum::$cv(s) => s.node_id, )*
                }
            }
        }
    };
}

impl_ast_accessors!(AstStmt,
    struct_variants: [
        // DML / queries
        Select, ValuesQuery, Insert, ReplaceInto, MultiInsert, Update, Delete, Merge,
        // DDL
        CreateTable, CreateView, CreateDynamicTable, CreateTask, CreateStage,
        CreateIndex, CreateSynonym, CommentOn, DoBlock, Vacuum, AnalyzeStmt, Explain,
        // Policies (create)
        CreateRowAccessPolicy, CreateMaskingPolicy, CreateNetworkPolicy,
        CreateSessionPolicy, CreateAuthenticationPolicy, CreateApiIntegration,
        CreateNotificationIntegration,
        CreatePasswordPolicy, CreateAggregationPolicy, CreateProjectionPolicy,
        CreateStorageIntegration, CreateExternalAccessIntegration,
        // Policies (alter)
        AlterRowAccessPolicy, AlterMaskingPolicy, AlterNetworkPolicy,
        AlterSessionPolicy, AlterAuthenticationPolicy, AlterApiIntegration,
        AlterNotificationIntegration,
        AlterPasswordPolicy, AlterAggregationPolicy, AlterProjectionPolicy,
        AlterStorageIntegration, AlterExternalAccessIntegration,
        // Session-parameter mutation (Snowflake): ALTER SESSION SET/UNSET
        AlterSession,
        // Snowflake share / security integration / replication & failover groups
        CreateShare, AlterShare,
        // Redshift datashare (cross-account data sharing)
        CreateDatashare, AlterDatashare,
        CreateSecurityIntegration, AlterSecurityIntegration,
        AlterReplicationGroup, AlterFailoverGroup,
        // Principal attachment (Snowflake): ALTER USER/ACCOUNT { SET | UNSET } AUTHENTICATION POLICY
        AlterUser, AlterAccount,
        // Policies (drop)
        DropRowAccessPolicy, DropAllRowAccessPolicies, DropMaskingPolicy,
        DropNetworkPolicy, DropSessionPolicy, DropAuthenticationPolicy,
        DropApiIntegration, DropNotificationIntegration,
        DropPasswordPolicy, DropAggregationPolicy,
        DropProjectionPolicy, DropStorageIntegration, DropExternalAccessIntegration,
        // DDL (alter/drop)
        AlterTable, AlterView, AlterMaterializedView,
        AlterDynamicTable, AlterFunction, AlterProcedure,
        AlterStage, AlterTask, DropTask, Drop, Truncate,
        // Warehouse
        CreateWarehouse, AlterWarehouse, DropWarehouse,
        // Pipe
        CreatePipe, AlterPipe, DropPipe,
        // Tag
        CreateTag, AlterTag, UndropTag,
        CreateFileFormat, AlterFileFormat,
        // Secret
        CreateSecret, AlterSecret,
        // Network rule
        CreateNetworkRule, AlterNetworkRule,
        // Resource monitor
        CreateResourceMonitor, AlterResourceMonitor,
        // Compute pool
        CreateComputePool, AlterComputePool,
        // Git repository
        CreateGitRepository, AlterGitRepository,
        // Image repository
        CreateImageRepository, AlterImageRepository,
        // Streamlit
        CreateStreamlit, AlterStreamlit,
        // Service (SPCS)
        CreateService, AlterService,
        // Notebook
        CreateNotebook, AlterNotebook,
        // Semantic view
        CreateSemanticView, AlterSemanticView,
        // Cortex search service
        CreateCortexSearchService, AlterCortexSearchService,
        // Native Apps
        CreateApplication, AlterApplication,
        CreateApplicationPackage, AlterApplicationPackage,
        // Listing
        CreateListing, AlterListing,
        // Account provisioning
        CreateManagedAccount, CreateAccount,
        // Stage file commands
        StageFileCommand,
        ExecuteImmediateFrom,
        CreateExternalFunction,
        // Alert
        CreateAlert, AlterAlert,
        // Join policy
        CreateJoinPolicy, AlterJoinPolicy, DropJoinPolicy,
        // Data metric function
        CreateDataMetricFunction,
        // Replication / failover group
        CreateReplicationFailoverGroup,
        // Stream
        CreateStream, AlterStream, DropStream,
        // Database / Schema
        CreateDatabase, AlterDatabase, DropDatabase, UndropDatabase,
        CreateSchema, AlterSchema, DropSchema, UndropSchema,
        UndropTable, UndropType,
        // Utility
        Show, Describe, Use,
        // Scripting (struct)
        Block, If, CaseStmt, For, ForEach, While, Repeat, Loop, DeclareHandler,
        // Jinja
        JinjaConditionalStmt,
        // PostgreSQL
        CreateType, AlterType, CreateExtension, CreateSequence, AlterSequence,
        CreateProcedure, CreateFunction, CreateTableFunction,
        CreatePgTrigger, AlterPgTrigger, DropPgTrigger,
        CreateDomain, AlterDomain, DropDomain,
        CreatePgPolicy, AlterPgPolicy, DropPgPolicy,
        AlterIndex, Reindex,
        PgPrepare, PgExecute, PgDeallocate, PgCopy, PgRefreshMatview,
        PgListen, PgNotify, PgUnlisten, PgLockTable,
        PgCreateRule, PgCreateAggregate, PgCreateOperator,
        PgAlterSystem, PgAlterTablespace, PgDropOwned, PgReassignOwned,
        PgDiscard, PgCluster, PgPublication, PgSubscription,
        CreatePrincipal, AlterPrincipal, DropPrincipal,
        PgDropExtension,
        PgAlterRule, PgDropRule, PgAlterTableTriggerState,
        PgSet, PgDropSequence, PgDropType, PgDropIndex,
        PgCreateTablespace, PgDropTablespace,
        BqExportData, BqLoadData, MysqlLoadData, MysqlRenameTable, CreateEvent, AlterEvent, CreateMysqlTrigger, BqAssert,
        BqCreateSnapshotTable, BqDropSnapshotTable,
        BqCreateSearchIndex, BqDropSearchIndex,
        BqCreateVectorIndex, BqDropVectorIndex, BqAlterVectorIndex,
        BqCreateModel, BqAlterModel, BqExportModel, BqDropModel,
        CreateExternalTable, CreateExternalSchema,
        // Databricks
        Optimize,
        DescribeHistory,
        Restore,
        MssqlBackup,
        MssqlRestore,
        MssqlDbcc,
        MssqlKeyManagement,
        MssqlSecurityPolicy,
        MssqlKeyBackup,
        MssqlAssembly,
        MssqlAddSignature,
        MssqlSetuser,
        MssqlAlterServiceMasterKey,
        PgAlterDefaultPrivileges,
        CacheTable,
        UncacheTable,
        RepairTable,
        CreateCatalog,
        AlterCatalog,
        DropCatalog,
        CreateVolume,
        AlterVolume,
        DropVolume,
        CreateExternalLocation,
        AlterExternalLocation,
        DropExternalLocation,
        CreateStorageCredential,
        AlterStorageCredential,
        DropStorageCredential,
        CreateConnection,
        AlterConnection,
        DropConnection,
        CreateFlow,
        // MSSQL
        MssqlExec,
        MssqlTryCatch,
        MssqlIf,
        MssqlWhile,
        MssqlPrint,
        MssqlThrow,
        MssqlRaiserror,
        MssqlSetOption,
        MysqlSet,
        MssqlWaitfor,
        MssqlGoto,
        MssqlLabel,
        CreateMssqlTrigger,
        DropMssqlTrigger,
        MssqlBulkInsert,
        MssqlCreateExternalModel,
        MssqlCreateExternalDataSource,
        MssqlAlterExternalDataSource,
        CreateForeignServer,
        AlterForeignServer,
        MssqlAlterServerConfiguration,
        CreateUserMapping,
        AlterUserMapping,
        DropUserMapping,
        CreateForeignTable,
        ImportForeignSchema,
        MssqlAlterExternalModel,
        MssqlDropExternalModel,
        MssqlCreateVectorIndex,
        // GRANT / REVOKE — typed boxed-struct variants.
        Grant, Revoke, Deny, AlterAuthorization,
        MssqlExecuteAs, MssqlAuditDdl, MssqlSecurityObjectDdl,
    ],
    inline_variants: [
        // Inline struct variants (destructured by field name)
        SetVariable, PipeChain, Assign,
        Declare, DeclareTable, DeclareCursor, Let, LetCursor,
        Return, Raise,
        Signal, Resignal, GetDiagnostics, DeclareCondition,
        Break, Continue, Null,
        OpenCursor, FetchCursor, CloseCursor,
        Await, Cancel,
        ExecuteImmediate, BeginTransaction, Commit, Rollback,
        Call, CopyIntoTable, CopyIntoLocation, Unload, RedshiftCopy,
        JinjaPlaceholder,
        Error, OpaqueContent, GoBatchSeparator, ClauseFragment,
        Reconfigure, MssqlRevert,
    ],
    custom_span: {
        // SetSelect computes span from left/right operands, extended to
        // cover any trailing ORDER BY / LIMIT / OFFSET / FETCH on the whole
        // set operation.
        SetSelect(s) => {
            let left_span = s.left.span();
            let right_span = s.right.span();
            let mut end = right_span.end;
            if let Some(ob) = &s.order_by {
                end = end.max(ob.span.end);
            }
            if let Some(l) = &s.limit {
                end = end.max(l.span().end);
            }
            if let Some(o) = &s.offset {
                end = end.max(o.span().end);
            }
            for sp in [s.limit_keyword_span, s.fetch_clause_span, s.offset_keyword_span].into_iter().flatten() {
                end = end.max(sp.end);
            }
            Span { start: left_span.start, end }
        }
    },
);

#[derive(Debug, Clone)]
pub enum AstSetOpKind {
    Union,
    Intersect,
    Except,
    /// MINUS is a synonym for EXCEPT in Snowflake SQL
    Minus,
}

#[derive(Debug, Clone)]
pub struct AstSetSelect {
    pub node_id: crate::ast::NodeId,
    pub left: Box<AstStmt>,
    pub op: AstSetOpKind,
    /// Whether the set operation uses ALL, DISTINCT, or no modifier.
    /// This field is the semantic representation. The CST token ownership
    /// lives in the SyntaxSetOperator node referenced by `set_op_syntax_id`.
    pub modifier: AstSetModifier,
    pub right: Box<AstStmt>,
    /// Optional syntax ID for the set operator (UNION/INTERSECT/EXCEPT keyword + optional ALL/DISTINCT).
    /// Used by the formatter to emit source tokens instead of synthesizing keywords.
    pub set_op_syntax_id: Option<crate::syntax::SyntaxSetOperatorId>,
    /// Optional semicolon token ID when set select appears in scripting/Jinja context
    pub semicolon_token: Option<crate::cst::TokenId>,
    /// Optional syntax ID for parentheses when this SetSelect is parenthesized.
    /// Example: ((SELECT ...) UNION (SELECT ...)) - the outer parens wrap the SetSelect.
    pub paren_syntax_id: Option<crate::syntax::SyntaxSubqueryId>,
    /// Trailing `ORDER BY` applying to the whole set operation
    /// (`(SELECT ...) UNION (SELECT ...) ORDER BY x`). A non-parenthesized
    /// operand cannot own a trailing clause in SQL, so it always belongs here,
    /// not on an inner operand. Mirrors the same fields on [`AstSelect`].
    pub order_by: Option<Box<AstOrderBy>>,
    /// Trailing `LIMIT` / `FETCH` row-count applying to the whole set operation.
    pub limit: Option<Box<AstExpr>>,
    /// Trailing `OFFSET` applying to the whole set operation.
    pub offset: Option<Box<AstExpr>>,
    pub limit_keyword_span: Option<Span>,
    pub fetch_clause_span: Option<Span>,
    pub offset_keyword_span: Option<Span>,
    /// Span of the comma in the MySQL `LIMIT offset, count` form.
    pub limit_offset_comma_span: Option<Span>,
}

/// Modifier for set operations (UNION/INTERSECT/EXCEPT).
/// Tracks whether ALL, DISTINCT, or no modifier keyword was present.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AstSetModifier {
    /// No modifier keyword (default behavior = DISTINCT)
    None,
    /// Explicit ALL keyword
    All,
    /// Explicit DISTINCT keyword
    Distinct,
}

#[derive(Debug, Clone)]
pub enum AstSetQuantifier {
    All,
    Distinct,
    /// PostgreSQL DISTINCT ON (expr_list)
    /// Selects the first row of each group defined by the expressions
    DistinctOn {
        syntax_id: crate::syntax::SyntaxDistinctOnId,
        exprs: Vec<AstExpr>,
    },
}

#[derive(Debug, Clone)]
pub struct AstTop {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    pub top_span: Span,
    pub expr: AstExpr,
    /// PERCENT keyword span (T-SQL: `SELECT TOP 10 PERCENT ...`)
    pub percent_span: Option<Span>,
    /// WITH TIES keyword span (T-SQL: `SELECT TOP 10 WITH TIES ...`)
    pub with_ties_span: Option<Span>,
}

#[derive(Debug, Clone)]
pub struct AstProjection {
    pub node_id: crate::ast::NodeId,
    pub kind: AstProjectionKind,
    /// Projection-level trailing `EXCLUDE (cols)` clause (Redshift). Distinct
    /// from `AstStarProjection.exclude` (BigQuery/Snowflake glue EXCLUDE/EXCEPT
    /// to a specific `*`); here it trails the whole list, e.g.
    /// `SELECT *, NULL AS x EXCLUDE (a, b)`. Applies to the star.
    pub exclude: Option<Box<AstExclude>>,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub enum AstProjectionKind {
    Star(Box<AstStarProjection>),
    Columns(Vec<Box<ProjectionItem>>), // Boxed: was 544 bytes each
}

#[derive(Debug, Clone)]
pub struct JinjaInlineFragment {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    pub syntax_id: Option<SyntaxJinjaInlineFragmentId>,
    pub kind: JinjaInlineFragmentKind,
}

#[derive(Debug, Clone)]
pub enum JinjaInlineFragmentKind {
    Comment(JinjaInlineComment),
    InlineBlock(Box<JinjaInlineBlock>), // Boxed: was 1112 bytes inline
    Punctuation(JinjaInlinePunctuation),
}

#[derive(Debug, Clone)]
pub struct JinjaInlineComment {
    pub node_id: crate::ast::NodeId,
    /// Span covering the comment body (excludes `{#` and `#}`)
    pub body_span: Span,
}

#[derive(Debug, Clone)]
pub struct JinjaInlineBlock {
    pub opening: JinjaBlockDelimiter,
    /// Parsed SQL content inside the block (expression, clause fragment, etc.)
    /// For patterns like `{% if x %}AND col = 1{% endif %}`, this holds the parsed expression.
    pub content: Option<JinjaInlineBlockContent>,
    /// Optional elif branches (only for If blocks)
    pub elif_branches: Vec<JinjaInlineElifBranch>,
    /// Optional else branch
    pub else_branch: Option<JinjaInlineElseBranch>,
    pub closing: Option<JinjaBlockDelimiter>,
}

/// An elif branch in a Jinja inline block
#[derive(Debug, Clone)]
pub struct JinjaInlineElifBranch {
    pub node_id: crate::ast::NodeId,
    /// The {% elif condition %} delimiter
    pub delimiter: JinjaBlockDelimiter,
    /// Content in this elif branch
    pub content: Option<JinjaInlineBlockContent>,
}

/// An else branch in a Jinja inline block
#[derive(Debug, Clone)]
pub struct JinjaInlineElseBranch {
    pub node_id: crate::ast::NodeId,
    /// The {% else %} delimiter
    pub delimiter: JinjaBlockDelimiter,
    /// Content in the else branch
    pub content: Option<JinjaInlineBlockContent>,
}

/// Content parsed from inside a Jinja inline block
#[derive(Debug, Clone)]
pub enum JinjaInlineBlockContent {
    /// An expression (e.g., `AND col = 1`, `amount >= 100`)
    Expr(Box<AstExpr>),
    /// A projection item (e.g., `col_name,` or `alias AS name`)
    ProjectionItem(Box<ProjectionItem>),
    /// JOIN clause(s) (e.g., `JOIN table ON condition`)
    Joins(Vec<Box<AstJoin>>), // Boxed: was 856 bytes each
    /// WHERE clause (e.g., `WHERE col = value`)
    WhereClause(Box<AstExpr>),
    /// JOIN clause(s) followed by WHERE clause (e.g., `LEFT JOIN ... WHERE ...`)
    /// Used for conditional patterns like: FROM t {% if is_incremental() %}LEFT JOIN ... WHERE ...{% endif %}
    JoinsAndWhere {
        joins: Vec<Box<AstJoin>>, // Boxed: was 856 bytes each
        where_clause: Box<AstExpr>,
    },
    /// Nested Jinja inline fragment (e.g., `{% if inner %}...{% endif %}` inside another block)
    NestedFragment(Box<JinjaInlineFragment>),
    /// Punctuation (e.g., `,` inside `{% if not loop.last %},{% endif %}`)
    Punctuation(JinjaInlinePunctuation),
}

#[derive(Debug, Clone)]
pub struct JinjaInlinePunctuation {
    pub token_kind: TokenKind,
    pub span: Span,
}

/// A clause containing a single boolean condition (WHERE/HAVING/QUALIFY)
/// augmented with leading/trailing inline fragments for trivia preservation.
#[derive(Debug, Clone)]
pub struct ConditionClause {
    pub node_id: crate::ast::NodeId,
    /// Inline fragments that appear immediately after the clause keyword
    pub prefix_inline_fragments: Vec<JinjaInlineFragment>,
    /// Inline fragments that appear after the expression
    pub suffix_inline_fragments: Vec<JinjaInlineFragment>,
    pub expr: AstExpr,
    /// Continuation expressions after Jinja blocks (e.g., AND expr3 after {% endif %})
    /// Each tuple is (operator_keyword, expression) for patterns like:
    /// WHERE expr1 {% if %}AND expr2{% endif %} AND expr3
    pub continuation_fragments: Vec<(Keyword, AstExpr)>,
    /// Span covering the clause keyword through the end of trailing fragments
    pub span: Span,
}

/// A single item in a SELECT projection list.
/// Can be either a regular column or a Jinja control block wrapping columns.
#[derive(Debug, Clone)]
pub struct ProjectionItem {
    pub node_id: crate::ast::NodeId,
    pub kind: ProjectionItemKind,
    /// Whether this item had a trailing comma in the source
    /// (preserves dbt's conditional comma patterns like {{ "," if not loop.last }})
    pub has_trailing_comma: bool,
    /// Typed inline fragments that appear before the item (comments, inline blocks)
    pub prefix_inline_fragments: Vec<JinjaInlineFragment>,
    /// Typed inline fragments that appear after the item (comments, inline blocks, punctuation)
    pub suffix_inline_fragments: Vec<JinjaInlineFragment>,
    /// Optional alias for JinjaBlock items (e.g., {% if %}a{% else %}b{% endif %} AS alias)
    /// For SelectItem, the alias is stored inside the SelectItem itself.
    pub alias: Option<AstIdentifierWithAs>,
}

#[derive(Debug, Clone)]
pub enum ProjectionItemKind {
    /// Regular column: expr [AS alias]
    SelectItem(AstSelectItem),
    /// Jinja control block: {% if/for %} ... items ... {% endif/endfor %}
    JinjaBlock(JinjaBlock),
}

/// A Jinja control flow block with conditional branches (if/elif/else/endif)
#[derive(Debug, Clone)]
pub struct JinjaBlock {
    pub node_id: crate::ast::NodeId,
    /// Opening Jinja statement: {% if condition %} or {% for item in list %}
    pub opening: JinjaBlockDelimiter,
    /// Jinja statements that appear at the start of this branch (e.g., {% set %} statements)
    /// These are statements that execute before projection items are generated
    pub then_statements: Vec<crate::ast::JinjaStmt>,
    /// Items in the primary branch (after {% if %} or {% for %})
    pub then_items: Vec<ProjectionItem>,
    /// Optional elif branches (only for If blocks)
    pub elif_branches: Vec<JinjaElifBranch>,
    /// Optional else branch
    pub else_branch: Option<JinjaElseBranch>,
    /// Closing Jinja statement: {% endif %} or {% endfor %}
    pub closing: JinjaBlockDelimiter,
    /// Span covering the entire block
    pub span: Span,
}

/// An elif branch in a Jinja if block
#[derive(Debug, Clone)]
pub struct JinjaElifBranch {
    pub node_id: crate::ast::NodeId,
    /// The {% elif condition %} delimiter
    pub delimiter: JinjaBlockDelimiter,
    /// Jinja statements at the start of this branch (e.g., {% set %})
    pub statements: Vec<crate::ast::JinjaStmt>,
    /// Items in this elif branch
    pub items: Vec<ProjectionItem>,
}

/// An else branch in a Jinja if/for block
#[derive(Debug, Clone)]
pub struct JinjaElseBranch {
    pub node_id: crate::ast::NodeId,
    /// The {% else %} delimiter
    pub delimiter: JinjaBlockDelimiter,
    /// Jinja statements at the start of this branch (e.g., {% set %})
    pub statements: Vec<crate::ast::JinjaStmt>,
    /// Items in the else branch
    pub items: Vec<ProjectionItem>,
}

/// A Jinja control flow block wrapping full SQL statements
/// Used for patterns like: {% if target.name != 'dev' %}SELECT...{% else %}SELECT...{% endif %}
/// Also supports multi-statement blocks like: {% for %}{% set %}SELECT...{% endfor %}
#[derive(Debug, Clone)]
pub struct JinjaStmtBlock {
    pub node_id: crate::ast::NodeId,
    /// Opening Jinja statement: {% if condition %}
    pub opening: JinjaBlockDelimiter,
    /// Statements in the primary branch (after {% if %} or {% for %})
    pub then_stmts: Vec<AstStmt>,
    /// Optional elif branches
    pub elif_branches: Vec<JinjaStmtElifBranch>,
    /// Optional else branch
    pub else_branch: Option<JinjaStmtElseBranch>,
    /// Closing Jinja statement: {% endif %}
    pub closing: JinjaBlockDelimiter,
    /// Span covering the entire block
    pub span: Span,
}

/// An elif branch in a Jinja statement block
#[derive(Debug, Clone)]
pub struct JinjaStmtElifBranch {
    pub node_id: crate::ast::NodeId,
    /// The {% elif condition %} delimiter
    pub delimiter: JinjaBlockDelimiter,
    /// Statements in this elif branch
    pub stmts: Vec<AstStmt>,
}

/// An else branch in a Jinja statement block
#[derive(Debug, Clone)]
pub struct JinjaStmtElseBranch {
    pub node_id: crate::ast::NodeId,
    /// The {% else %} delimiter
    pub delimiter: JinjaBlockDelimiter,
    /// Statements in the else branch
    pub stmts: Vec<AstStmt>,
}

/// A Jinja block delimiter (opening or closing statement)
#[derive(Debug, Clone)]
pub struct JinjaBlockDelimiter {
    pub node_id: crate::ast::NodeId,
    /// The token span (e.g., {% if active %})
    pub span: Span,
    /// The type of delimiter
    pub kind: JinjaBlockKind,
    /// Parsed condition/expression for If, Elif, For delimiters
    /// None for closing delimiters (endif, endfor) and Else
    /// Enables validation and linting of Jinja expressions
    pub condition: Option<crate::ast::JinjaExpr>,
    /// Optional link into the typed syntax arena
    pub syntax_id: Option<SyntaxJinjaDelimiterId>,
}

/// Types of Jinja control flow blocks
#[derive(Debug, Clone, PartialEq)]
pub enum JinjaBlockKind {
    /// {% if condition %}
    If,
    /// {% elif condition %}
    Elif,
    /// {% else %}
    Else,
    /// {% endif %}
    EndIf,
    /// {% for var in iterable %}
    For,
    /// {% endfor %}
    EndFor,
    /// {% set var = value %}
    Set,
    /// {% endset %}
    EndSet,
    /// {% docs model_name %} - dbt documentation block
    Docs,
    /// {% enddocs %}
    EndDocs,
}

/// A SQL statement fragment that can appear inside a Jinja conditional block.
/// Used when Jinja wraps multiple SQL clauses (e.g., JOIN + WHERE together).
///
/// Example:
/// ```sql
/// FROM table1
/// {% if is_incremental() %}
///   LEFT JOIN table2 ON ...
///   WHERE table2.id IS NULL
/// {% endif %}
/// ```
#[derive(Debug, Clone)]
pub struct StatementFragment {
    pub node_id: crate::ast::NodeId,
    /// FROM clause items (optional - present when fragment starts with FROM)
    /// Example: {% if condition %}FROM table1 JOIN table2{% endif %}
    pub from_items: Option<Vec<Box<FromItem>>>, // Boxed: FromItem was 424 bytes each
    /// JOIN clauses that appear in this fragment
    pub joins: Vec<Box<AstJoin>>, // Boxed: was 856 bytes each
    /// WHERE clause that appears in this fragment (if any)
    /// Stores full ConditionClause to preserve inline Jinja fragments and continuations
    pub where_clause: Option<Box<ConditionClause>>, // Boxed: was 472 bytes
    /// GROUP BY clause that appears in this fragment (if any)
    pub group_by: Option<AstGroupBy>,
    /// HAVING clause that appears in this fragment (if any)
    /// Stores full ConditionClause to preserve inline Jinja fragments and continuations
    pub having_clause: Option<Box<ConditionClause>>, // Boxed: was 472 bytes
    /// Future: Could add ORDER BY, QUALIFY, LIMIT, etc.
    pub span: Span,
}

/// A Jinja conditional block wrapping SQL statement fragments.
/// This handles cases where Jinja spans multiple SQL clause boundaries.
///
/// Example:
/// ```sql
/// FROM customers c
/// {% if is_incremental() %}
///   LEFT JOIN {{ this }} existing ON c.id = existing.id
///   WHERE existing.id IS NULL
/// {% else %}
///   WHERE c.created_at >= '2024-01-01'
/// {% endif %}
/// ```
#[derive(Debug, Clone)]
pub struct JinjaStatementFragment {
    pub node_id: crate::ast::NodeId,
    /// Opening Jinja delimiter ({% if %} or {% for %})
    pub opening: JinjaBlockDelimiter,
    /// Statement fragment in the primary branch
    pub then_fragment: StatementFragment,
    /// Optional elif branches (only for If blocks)
    pub elif_branches: Vec<JinjaStatementFragmentElifBranch>,
    /// Optional else branch
    pub else_branch: Option<JinjaStatementFragmentElseBranch>,
    /// Closing Jinja delimiter ({% endif %} or {% endfor %})
    pub closing: JinjaBlockDelimiter,
    /// Index of the FROM item this fragment attaches to (for formatting context)
    pub from_item_index: usize,
    /// Span covering the entire Jinja block
    pub span: Span,
}

/// An elif branch in a statement fragment Jinja block
#[derive(Debug, Clone)]
pub struct JinjaStatementFragmentElifBranch {
    pub node_id: crate::ast::NodeId,
    /// The {% elif condition %} delimiter
    pub delimiter: JinjaBlockDelimiter,
    /// Statement fragment in this elif branch
    pub fragment: StatementFragment,
}

/// An else branch in a statement fragment Jinja block
#[derive(Debug, Clone)]
pub struct JinjaStatementFragmentElseBranch {
    pub node_id: crate::ast::NodeId,
    /// The {% else %} delimiter
    pub delimiter: JinjaBlockDelimiter,
    /// Statement fragment in the else branch
    pub fragment: StatementFragment,
}

/// A single item in a FROM clause.
/// Can be either a table reference (with joins) or a Jinja control block wrapping table references.
#[derive(Debug, Clone)]
pub struct FromItem {
    pub node_id: crate::ast::NodeId,
    pub kind: FromItemKind,
}

impl std::ops::Deref for FromItem {
    type Target = AstTableRef;

    fn deref(&self) -> &Self::Target {
        self.unwrap_table_ref()
    }
}

impl std::ops::DerefMut for FromItem {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.as_table_ref_mut()
            .expect_invariant("FromItem is not a TableRef")
    }
}

impl FromItem {
    /// Get the table ref if this is a TableRef variant
    pub fn as_table_ref(&self) -> Option<&AstTableRef> {
        match &self.kind {
            FromItemKind::TableRef(table_ref) => Some(table_ref),
            FromItemKind::JinjaBlock(_) => None,
            FromItemKind::JinjaTableName(_) => None,
        }
    }

    /// Get the table ref if this is a TableRef variant (mutable)
    pub fn as_table_ref_mut(&mut self) -> Option<&mut AstTableRef> {
        match &mut self.kind {
            FromItemKind::TableRef(table_ref) => Some(table_ref),
            FromItemKind::JinjaBlock(_) => None,
            FromItemKind::JinjaTableName(_) => None,
        }
    }

    /// Unwrap the table ref, panicking if this is not a TableRef variant
    pub fn unwrap_table_ref(&self) -> &AstTableRef {
        self.as_table_ref()
            .expect_invariant("FromItem is not a TableRef")
    }
}

#[derive(Debug, Clone)]
pub enum FromItemKind {
    /// Regular table reference (may include JOIN clauses)
    TableRef(Box<AstTableRef>), // Boxed: was 464 bytes inline
    /// Jinja control block: {% if/for %} ... table refs ... {% endif/endfor %}
    JinjaBlock(FromJinjaBlock),
    /// Jinja control block producing a table name (with optional continuation)
    /// Example: {% if prod %}schema1{% else %}schema2{% endif %}.table
    JinjaTableName(JinjaTableNameBlock),
}

/// A Jinja control flow block containing FROM clause items (table refs, joins)
#[derive(Debug, Clone)]
pub struct FromJinjaBlock {
    pub node_id: crate::ast::NodeId,
    /// Opening Jinja statement: {% if condition %} or {% for item in list %}
    pub opening: JinjaBlockDelimiter,
    /// Items in the primary branch (after {% if %} or {% for %})
    /// Each item can be a table ref with joins, or nested Jinja blocks
    pub then_items: Vec<FromItem>,
    /// Optional elif branches (only for If blocks)
    pub elif_branches: Vec<FromJinjaElifBranch>,
    /// Optional else branch
    pub else_branch: Option<FromJinjaElseBranch>,
    /// Closing Jinja statement: {% endif %} or {% endfor %}
    pub closing: JinjaBlockDelimiter,
    /// Span covering the entire block
    pub span: Span,
}

/// An elif branch in a FROM clause Jinja if block
#[derive(Debug, Clone)]
pub struct FromJinjaElifBranch {
    pub node_id: crate::ast::NodeId,
    /// The {% elif condition %} delimiter
    pub delimiter: JinjaBlockDelimiter,
    /// Items in this elif branch
    pub items: Vec<FromItem>,
}

/// An else branch in a FROM clause Jinja if/for block
#[derive(Debug, Clone)]
pub struct FromJinjaElseBranch {
    pub node_id: crate::ast::NodeId,
    /// The {% else %} delimiter
    pub delimiter: JinjaBlockDelimiter,
    /// Items in the else branch
    pub items: Vec<FromItem>,
}

/// A Jinja control block that produces a table name (possibly part of a qualified name).
/// Used for patterns like: {% if prod %}schema1{% else %}schema2{% endif %}.table
///
/// Unlike `FromJinjaBlock` which contains complete `FromItem`s, this represents
/// Jinja producing identifier fragments that combine to form a table reference.
#[derive(Debug, Clone)]
pub struct JinjaTableNameBlock {
    pub node_id: crate::ast::NodeId,
    /// Opening Jinja statement: {% if condition %} or {% for item in list %}
    pub opening: JinjaBlockDelimiter,
    /// Content span for the primary branch (raw identifier/name fragment)
    pub then_content: Span,
    /// Optional elif branches with their content spans
    pub elif_branches: Vec<JinjaTableNameElifBranch>,
    /// Optional else branch with content span
    pub else_branch: Option<JinjaTableNameElseBranch>,
    /// Closing Jinja statement: {% endif %} or {% endfor %}
    pub closing: JinjaBlockDelimiter,
    /// Optional continuation after the Jinja block (e.g., ".table" or ".schema.table")
    /// This is the text that follows {% endif %} and forms part of the qualified name
    pub continuation: Option<Span>,
    /// Optional alias for the table reference (includes AS keyword span if present)
    pub alias: Option<AstIdentifierWithAs>,
    /// Span covering the entire construct (from {% if %} through alias if present)
    pub span: Span,
}

/// An elif branch in a Jinja table name block
#[derive(Debug, Clone)]
pub struct JinjaTableNameElifBranch {
    pub node_id: crate::ast::NodeId,
    /// The {% elif condition %} delimiter
    pub delimiter: JinjaBlockDelimiter,
    /// Content span for this branch (raw identifier/name fragment)
    pub content: Span,
}

/// An else branch in a Jinja table name block
#[derive(Debug, Clone)]
pub struct JinjaTableNameElseBranch {
    pub node_id: crate::ast::NodeId,
    /// The {% else %} delimiter
    pub delimiter: JinjaBlockDelimiter,
    /// Content span for this branch (raw identifier/name fragment)
    pub content: Span,
}

#[derive(Debug, Clone)]
pub struct AstStarProjection {
    pub node_id: crate::ast::NodeId,
    pub star_span: Span,
    pub qualifier: Option<AstObjectRef>,
    pub ilike: Option<AstIlikeFilter>,
    pub exclude: Option<Box<AstExclude>>,
    pub replace: Option<Box<AstReplace>>,
    pub rename: Option<Box<AstRename>>,
}

/// Represents an object reference, typically a table or view name.
/// May be qualified (e.g., `schema.table`) or unqualified.
/// Stores the span covering the full reference.
/// For IDENTIFIER() constructs, may also store the parsed argument expression.
#[derive(Debug, Clone)]
pub struct AstObjectRef {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    /// Per-identifier-token spans for a structurally dotted name.
    ///
    /// When this `AstObjectRef` represents a plain qualified name
    /// like `db.schema.table` (or `schema.table`, or `table`), each
    /// entry is the exact `Span` of one identifier token consumed
    /// by the parser — by construction containing **no trivia**
    /// (no whitespace, no `--` line comments, no `/* ... */` block
    /// comments). An entry is `None` for an *omitted* component in a
    /// T-SQL multi-part name with an empty slot — `master..tbl` parses
    /// to `[Some(master), None, Some(tbl)]` (database `master`, default
    /// schema, object `tbl`). Consumers that need to identify the parts
    /// of the name (e.g. `db / schema / name` for a `TableRef`) MUST
    /// iterate this list instead of byte-slicing `span` and
    /// splitting on `.`, because the merged `span` necessarily
    /// covers any trivia the lexer emitted between identifier
    /// tokens.
    ///
    /// `None` when the object reference is not a structurally-
    /// decomposable dotted name. The non-decomposable cases are:
    ///
    /// - The `IDENTIFIER(...)` construct (`identifier_arg` is
    ///   `Some` and carries the parsed argument expression).
    /// - A table-valued function call used in a FROM-position
    ///   (e.g. `FLATTEN(...)`, `UNNEST(...)`, `ML.PREDICT(...)`):
    ///   the span covers the whole call, not a dotted name.
    /// - A `LATERAL VIEW <func>(...)` form.
    /// - A derived-table / VALUES alias whose `span` covers a
    ///   parenthesized region rather than a dotted identifier.
    /// - A Snowflake positional pipe input reference (`$1`).
    ///
    /// In every `None` case, `span` is the only meaningful name
    /// payload; consumers should treat it as opaque and not
    /// attempt to dot-split it.
    pub parts: Option<Vec<Option<Span>>>,
    /// Parsed argument for IDENTIFIER() function (e.g., IDENTIFIER('table_name') or IDENTIFIER(:var))
    /// When present, indicates this is an IDENTIFIER() construct with a parsed argument.
    /// The span field still covers the entire IDENTIFIER(...) construct.
    pub identifier_arg: Option<Box<crate::ast::AstExpr>>,
}

#[derive(Debug, Clone)]
pub struct AstIlikeFilter {
    pub node_id: crate::ast::NodeId,
    pub ilike_span: Span,
    pub pattern_span: Span,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct AstExclude {
    pub node_id: crate::ast::NodeId,
    pub syntax_id: Option<crate::syntax::SyntaxExcludeId>,
    pub exclude_span: Span,
    pub columns: Vec<AstColumnRef>,
    /// Whether the original syntax used parentheses around the column list
    pub has_parens: bool,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct AstReplace {
    pub node_id: crate::ast::NodeId,
    pub syntax_id: Option<crate::syntax::SyntaxReplaceId>,
    pub replace_span: Span,
    pub items: Vec<AstReplaceItem>,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct AstReplaceItem {
    pub node_id: crate::ast::NodeId,
    pub syntax_id: crate::syntax::SyntaxReplaceItemId,
    pub expr: AstExpr,
    pub as_span: Span,
    pub column: AstColumnRef,
}

#[derive(Debug, Clone)]
pub struct AstRename {
    pub node_id: crate::ast::NodeId,
    pub syntax_id: Option<crate::syntax::SyntaxRenameId>,
    pub rename_span: Span,
    pub items: Vec<AstRenameItem>,
    /// Whether the original syntax used parentheses around the rename list
    pub has_parens: bool,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct AstRenameItem {
    pub node_id: crate::ast::NodeId,
    pub syntax_id: crate::syntax::SyntaxRenameItemId,
    pub column: AstColumnRef,
    pub as_span: Option<Span>,
    pub alias: AstIdentifier,
}

#[derive(Debug, Clone)]
pub struct AstColumnRef {
    pub node_id: crate::ast::NodeId,
    pub qualifier: Option<AstObjectRef>,
    pub name: AstIdentifier,
}

#[derive(Debug, Clone)]
pub struct AstIdentifier {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
}

/// CONNECT BY clause for hierarchical queries.
/// Syntax: `START WITH <predicate> CONNECT BY <condition> [AND <condition> ...]`
/// Each condition typically has one PRIOR keyword indicating the parent level reference.
#[derive(Debug, Clone)]
pub struct AstConnectBy {
    pub node_id: crate::ast::NodeId,
    /// Optional START WITH clause span (covers entire `START WITH <predicate>`)
    pub start_with_span: Option<Span>,
    /// Optional predicate expression for START WITH clause
    pub start_with_condition: Option<AstExpr>,
    /// CONNECT BY keyword span
    pub connect_by_span: Span,
    /// List of conditions in CONNECT BY clause (joined by AND)
    /// Each condition is a comparison expression, typically with PRIOR
    pub conditions: Vec<AstExpr>,
    /// Optional ORDER SIBLINGS BY clause
    pub order_siblings_by: Option<AstOrderBy>,
    /// Span covering entire CONNECT BY clause
    pub span: Span,
}

/// MATCH_RECOGNIZE clause for pattern matching in time series.
/// Syntax: MATCH_RECOGNIZE (
///     [ PARTITION BY ... ]
///     [ ORDER BY ... ]
///     [ MEASURES ... ]
///     [ ONE ROW PER MATCH | ALL ROWS PER MATCH ... ]
///     [ AFTER MATCH SKIP ... ]
///     PATTERN ( ... )
///     DEFINE ...
/// )
#[derive(Debug, Clone)]
pub struct AstMatchRecognize {
    pub node_id: crate::ast::NodeId,
    pub syntax_id: Option<crate::syntax::SyntaxMatchRecognizeId>,
    pub match_recognize_span: Span,
    pub partition_by: Option<Vec<AstExpr>>,
    pub order_by: Option<AstOrderBy>,
    pub measures: Vec<AstMeasure>,
    pub rows_per_match: Option<AstRowsPerMatch>,
    pub after_match_skip: Option<AstAfterMatchSkip>,
    pub pattern: AstPattern,
    pub define: Vec<AstDefineSymbol>,
    pub span: Span,
}

/// Semantic modifier for MEASURES clause (RUNNING or FINAL)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AstMeasureSemanticModifier {
    Running,
    Final,
}

/// MEASURES clause item: [RUNNING | FINAL] expression AS alias
#[derive(Debug, Clone)]
pub struct AstMeasure {
    pub node_id: crate::ast::NodeId,
    pub syntax_id: Option<crate::syntax::SyntaxMeasureItemId>,
    pub semantic_modifier: Option<AstMeasureSemanticModifier>,
    pub expr: AstExpr,
    pub alias: AstIdentifier,
    pub span: Span,
}

/// Rows per match mode
#[derive(Debug, Clone)]
pub enum AstRowsPerMatch {
    OneRowPerMatch,
    AllRowsPerMatch {
        empty_matches: Option<AstEmptyMatchesMode>,
    },
}

/// Empty matches handling for ALL ROWS PER MATCH
#[derive(Debug, Clone)]
pub enum AstEmptyMatchesMode {
    Show,          // SHOW EMPTY MATCHES
    Omit,          // OMIT EMPTY MATCHES
    WithUnmatched, // WITH UNMATCHED ROWS
}

/// AFTER MATCH SKIP clause
#[derive(Debug, Clone)]
pub enum AstAfterMatchSkip {
    PastLastRow,           // PAST LAST ROW (default)
    ToNextRow,             // TO NEXT ROW
    ToFirstSymbol(String), // TO FIRST <symbol>
    ToLastSymbol(String),  // TO LAST <symbol> or TO <symbol>
}

/// PATTERN clause - stores the pattern as a string for now
/// Could be parsed into a proper AST later if needed
#[derive(Debug, Clone)]
pub struct AstPattern {
    pub node_id: crate::ast::NodeId,
    pub pattern_text: String, // The pattern expression as a string
    pub span: Span,
}

/// DEFINE clause symbol definition
#[derive(Debug, Clone)]
pub struct AstDefineSymbol {
    pub node_id: crate::ast::NodeId,
    pub syntax_id: Option<crate::syntax::SyntaxDefineSymbolId>,
    pub symbol: String, // Symbol name (e.g., "UP", "DOWN")
    pub expr: AstExpr,  // Boolean expression defining the symbol
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct AstSelectItem {
    pub node_id: crate::ast::NodeId,
    /// The projected expression. For T-SQL assignment-projection
    /// (`SELECT @v = col FROM t`), this is the RHS only — the
    /// assignment target lives in [`Self::assign_target`].
    pub expr: AstExpr,
    pub alias: Option<AstIdentifierWithAs>,
    /// `Some` only when the projection is the T-SQL
    /// `SELECT @v = expr FROM ...` assignment-projection form.
    /// Carries the typed `@v` target identifier and the `=`
    /// operator span. Its presence lets consumers detect the
    /// assignment without text-scanning the
    /// expression — `SELECT @x = col` would otherwise parse as
    /// `BinaryOp(=, Variable, col)`, semantically a boolean
    /// projection.
    ///
    /// Populated by the T-SQL projection parser peek-ahead;
    /// always `None` for other dialects (they have no equivalent
    /// projection-assignment syntax).
    pub assign_target: Option<AstSelectItemAssignTarget>,
    pub span: Span,
}

/// T-SQL `SELECT @var = expr` assignment-projection target.
/// See [`AstSelectItem::assign_target`].
#[derive(Debug, Clone)]
pub struct AstSelectItemAssignTarget {
    /// The `@var` identifier (parsed via the T-SQL variable lexer
    /// rule; span covers the `@` plus the bare name).
    pub target: AstIdentifier,
    /// Span of the `=` operator separating target from expression.
    pub assign_op_span: Span,
}

#[derive(Debug, Clone)]
pub struct AstIdentifierWithAs {
    pub node_id: crate::ast::NodeId,
    pub as_span: Option<Span>,
    pub ident: AstIdentifier,
}

/// One EXECUTE IMMEDIATE USING bind argument: `expr [AS alias]`
/// (the alias form is BigQuery's named-binding surface).
#[derive(Debug, Clone)]
pub struct AstExecuteUsingArg {
    pub node_id: crate::ast::NodeId,
    pub expr: AstExpr,
    pub alias: Option<AstIdentifierWithAs>,
}

/// Represents a VALUES clause: VALUES (expr, ...), (expr, ...), ...
#[derive(Debug, Clone)]
pub struct AstValues {
    pub node_id: crate::ast::NodeId,
    pub rows: Vec<Vec<AstExpr>>,
    pub span: Span,
    pub syntax_id: Option<crate::syntax::SyntaxValuesId>,
}

/// Standalone VALUES query (PostgreSQL): VALUES (...), (...) [ORDER BY ...] [LIMIT ...] [OFFSET ...]
/// Can appear as a top-level statement, in UNION/INTERSECT/EXCEPT, or in IN subqueries.
#[derive(Debug, Clone)]
pub struct AstValuesQuery {
    pub node_id: crate::ast::NodeId,
    pub values: AstValues,
    pub order_by: Option<Box<AstOrderBy>>,
    pub limit: Option<Box<AstExpr>>,
    pub offset: Option<Box<AstExpr>>,
    pub limit_keyword_span: Option<Span>,
    pub fetch_clause_span: Option<Span>,
    pub offset_keyword_span: Option<Span>,
    pub span: Span,
    /// For parenthesized usage in set operations: (VALUES (...) UNION ...)
    pub paren_syntax_id: Option<crate::syntax::SyntaxSubqueryId>,
}

/// Time travel parameter type for AT/BEFORE clauses
#[derive(Debug, Clone)]
pub enum AstTimeTravelKind {
    Timestamp(AstExpr), // TIMESTAMP => expr
    Offset(AstExpr),    // OFFSET => expr
    Statement(AstExpr), // STATEMENT => expr
    Stream(AstExpr),    // STREAM => expr
}

/// Represents an AT or BEFORE time travel clause (Snowflake)
#[derive(Debug, Clone)]
pub struct AstTimeTravel {
    pub node_id: crate::ast::NodeId,
    pub is_before: bool, // true for BEFORE, false for AT
    pub kind: AstTimeTravelKind,
    pub span: Span,
}

/// Represents a BigQuery FOR SYSTEM_TIME AS OF clause
#[derive(Debug, Clone)]
pub struct AstForSystemTime {
    pub node_id: crate::ast::NodeId,
    /// The timestamp expression for AS OF variant; None for ALL/FROM/BETWEEN/CONTAINED IN.
    pub expr: Option<Box<AstExpr>>,
    pub span: Span,
}

/// The kind of Databricks time travel reference
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DatabricksTimeTravelKind {
    /// `TIMESTAMP AS OF <expr>`
    Timestamp,
    /// `VERSION AS OF <expr>`
    Version,
    /// table@v123 or table@20190101000000000
    AtSign,
}

/// Represents a Databricks Delta Lake time travel clause:
///   - `TIMESTAMP AS OF <timestamp_expression>`
///   - `VERSION AS OF <version>`
///   - `table@v123` / `table@20190101`
#[derive(Debug, Clone)]
pub struct AstDatabricksAsOf {
    pub node_id: crate::ast::NodeId,
    pub kind: DatabricksTimeTravelKind,
    pub expr: AstExpr,
    pub span: Span,
}

/// Wrapper enum for dialect-specific time travel clauses.
/// Replaces `Option<Box<AstTimeTravel>>` with `Option<Box<AstTimeTravelClause>>`
/// on AstTableRef — same 8 bytes, clean separation by dialect.
#[derive(Debug, Clone)]
pub enum AstTimeTravelClause {
    /// Snowflake: AT|BEFORE (TIMESTAMP|OFFSET|STATEMENT|STREAM => expr)
    SnowflakeAtBefore(AstTimeTravel),
    /// BigQuery: FOR SYSTEM_TIME AS OF expr
    ForSystemTime(AstForSystemTime),
    /// Databricks: TIMESTAMP AS OF / VERSION AS OF / @version
    DatabricksAsOf(AstDatabricksAsOf),
}

/// Sampling method for SAMPLE clause
#[derive(Debug, Clone)]
pub enum AstSampleMethod {
    Bernoulli, // BERNOULLI or ROW
    System,    // SYSTEM or BLOCK
}

/// Sample size specification: either probability or fixed row count
#[derive(Debug, Clone)]
pub enum AstSampleSize {
    Probability(AstExpr), // Percentage 0-100
    Rows(AstExpr),        // Fixed number of rows (up to 1,000,000)
}

/// Represents a SAMPLE or TABLESAMPLE clause
#[derive(Debug, Clone)]
pub struct AstSampleClause {
    pub node_id: crate::ast::NodeId,
    pub method: Option<AstSampleMethod>, // Default is BERNOULLI if not specified
    pub size: AstSampleSize,
    pub seed: Option<AstExpr>, // SEED or REPEATABLE value (SYSTEM/BLOCK only)
    pub span: Span,
}

/// Information type for CHANGES clause
#[derive(Debug, Clone, PartialEq)]
pub enum AstChangesInformation {
    Default,    // DEFAULT (full delta with inserts, updates, deletes)
    AppendOnly, // APPEND_ONLY (inserts only, no join)
}

/// End point specification for CHANGES clause
#[derive(Debug, Clone)]
pub struct AstChangesEnd {
    pub node_id: crate::ast::NodeId,
    pub kind: AstTimeTravelKind, // Reuse: TIMESTAMP, OFFSET, or STATEMENT
    pub span: Span,
}

/// Represents a CHANGES clause for change tracking metadata
/// Syntax: CHANGES ( INFORMATION => { DEFAULT | APPEND_ONLY } )
///         AT|BEFORE ( ... )
///         [ END ( ... ) ]
#[derive(Debug, Clone)]
pub struct AstChangesClause {
    pub node_id: crate::ast::NodeId,
    pub information: AstChangesInformation,
    pub at_before: AstTimeTravel,   // AT or BEFORE clause (required)
    pub end: Option<AstChangesEnd>, // Optional END clause
    pub span: Span,
}

/// PIVOT clause structures
#[derive(Debug, Clone)]
pub struct AstPivotClause {
    pub node_id: crate::ast::NodeId,
    pub pivot_span: Span,
    pub aggregates: Vec<AstPivotAggregate>, // One or more aggregate_function(pivot_column) [AS alias]
    pub for_span: Span,
    pub for_column: Box<AstExpr>, // value_column expression in FOR clause
    pub in_span: Span,
    pub in_values: AstPivotInValues,           // IN clause values
    pub default_on_null_span: Option<Span>,    // Optional DEFAULT ON NULL
    pub default_on_null: Option<Box<AstExpr>>, // Optional DEFAULT ON NULL (value)
    pub span: Span,
}

/// A single aggregate in a PIVOT clause: aggregate_function(column) [AS alias]
#[derive(Debug, Clone)]
pub struct AstPivotAggregate {
    pub node_id: crate::ast::NodeId,
    pub expr: Box<AstExpr>,
    pub as_span: Option<Span>,
    pub alias: Option<AstIdentifier>,
}

#[derive(Debug, Clone)]
pub enum AstPivotInValues {
    /// Explicit list of values with optional aliases: value1 [AS alias1], value2 [AS alias2], ...
    ValueList(Vec<AstPivotValue>),
    /// Value list with Jinja control flow - preserve as opaque span
    OpaqueList(Span),
    /// ANY [ORDER BY ...]
    Any(Option<Vec<Box<AstOrderItem>>>), // Optional ORDER BY clause
    /// Subquery: SELECT ... (or set operation like UNION/INTERSECT/EXCEPT)
    Subquery(Box<AstStmt>),
}

#[derive(Debug, Clone)]
pub struct AstPivotValue {
    pub node_id: crate::ast::NodeId,
    pub value: Box<AstExpr>,
    pub as_span: Option<Span>,
    pub alias: Option<AstIdentifier>,
}

/// UNPIVOT clause structures
#[derive(Debug, Clone)]
pub struct AstUnpivotClause {
    pub node_id: crate::ast::NodeId,
    pub unpivot_span: Span,
    pub include_nulls: bool, // INCLUDE NULLS (true) or EXCLUDE NULLS (false, default)
    pub include_exclude_nulls_span: Option<Span>,
    pub value_columns: Vec<AstIdentifier>, // Generated value column name(s) — single or (col1, col2)
    pub for_span: Span,
    pub name_column: AstIdentifier, // Generated name column name
    pub in_span: Span,
    pub columns: Vec<AstUnpivotColumn>, // Columns to unpivot
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct AstUnpivotColumn {
    pub node_id: crate::ast::NodeId,
    pub columns: Vec<AstIdentifier>, // Single column or tuple (col1, col2)
    pub as_span: Option<Span>,
    pub alias: Option<AstIdentifier>, // Optional AS alias
}

/// Stage options for querying staged files
/// Syntax: ( FILE_FORMAT => 'format_name' [, PATTERN => 'regex_pattern'] )
#[derive(Debug, Clone)]
pub struct AstStageOptions {
    pub node_id: crate::ast::NodeId,
    pub span: Span, // Covers the entire ( ... ) including parentheses
}

/// BigQuery WITH OFFSET clause for UNNEST: UNNEST(arr) AS elem WITH OFFSET [AS pos]
/// Adds an ordinal position column when unnesting arrays.
#[derive(Debug, Clone)]
pub struct AstWithOffset {
    pub span: Span,                   // Covers full "WITH OFFSET [AS alias]"
    pub with_span: Span,              // Span of the WITH keyword
    pub offset_span: Span,            // Span of the OFFSET keyword
    pub as_span: Option<Span>,        // Span of the AS keyword (if present)
    pub alias: Option<AstIdentifier>, // Optional alias (e.g., "off" in "WITH OFFSET AS off")
}

// ── T-SQL Table Hints ──────────────────────────────────────────────────────

/// T-SQL table hint clause: `WITH (<hint> [, <hint>] ...)`
///
/// Appears after a table reference (and optional alias) in FROM, UPDATE, DELETE.
/// Example: `FROM Orders o WITH (NOLOCK, INDEX(idx_date))`
#[derive(Debug, Clone)]
pub struct AstTableHintClause {
    pub node_id: crate::ast::NodeId,
    /// Span of the WITH keyword
    pub with_keyword_span: Span,
    /// Individual parsed hints
    pub hints: Vec<AstTableHint>,
    /// Full span from WITH through closing paren
    pub span: Span,
}

/// A single table hint within a `WITH (...)` clause.
#[derive(Debug, Clone)]
pub struct AstTableHint {
    pub node_id: crate::ast::NodeId,
    pub kind: AstTableHintKind,
    /// Full span of this individual hint (e.g., "NOLOCK" or "INDEX(idx1, idx2)")
    pub span: Span,
}

/// Discriminated table hint kinds.
///
/// T-SQL table hints fall into structural categories:
/// - Simple keyword hints, each enumerated as its own typed variant
///   (NOLOCK, UPDLOCK, HOLDLOCK, etc.). The parser maps the source
///   keyword to a typed variant so downstream consumers dispatch via
///   closed-enum match rather than re-inferring identity from source text.
/// - INDEX hints with parenthesized values
/// - FORCESEEK with optional index/column specification
/// - SPATIAL_WINDOW_MAX_CELLS = N (key=value)
#[derive(Debug, Clone)]
pub enum AstTableHintKind {
    // ── Isolation-level / dirty-read keyword hints ──────────────────────
    /// `NOLOCK` — read without acquiring shared locks (dirty reads).
    NoLock,
    /// `READUNCOMMITTED` — equivalent dirty-read semantics to NOLOCK.
    ReadUncommitted,
    /// `READCOMMITTED` — default isolation; named hint for explicitness.
    ReadCommitted,
    /// `READCOMMITTEDLOCK` — READ COMMITTED with locking semantics.
    ReadCommittedLock,
    /// `REPEATABLEREAD` — repeatable-read isolation level.
    RepeatableRead,
    /// `SERIALIZABLE` — serializable isolation level.
    Serializable,
    /// `SNAPSHOT` — snapshot isolation level.
    Snapshot,
    // ── Locking-mode keyword hints ─────────────────────────────────────
    /// `UPDLOCK` — update lock acquisition.
    UpdLock,
    /// `HOLDLOCK` — hold locks until end of transaction.
    HoldLock,
    /// `ROWLOCK` — row-level locking granularity.
    RowLock,
    /// `PAGLOCK` — page-level locking granularity.
    PagLock,
    /// `TABLOCK` — table-level shared lock.
    TabLock,
    /// `TABLOCKX` — table-level exclusive lock.
    TabLockX,
    /// `XLOCK` — exclusive lock.
    XLock,
    /// `READPAST` — skip locked rows rather than block.
    ReadPast,
    /// `NOWAIT` — fail rather than wait for locks.
    NoWait,
    // ── Optimizer keyword hints ────────────────────────────────────────
    /// `NOEXPAND` — disable indexed-view expansion.
    NoExpand,
    /// `FORCESCAN` — force a full table scan.
    ForceScan,
    // ── DML-semantics keyword hints ────────────────────────────────────
    /// `KEEPIDENTITY` — preserve source identity values during INSERT.
    KeepIdentity,
    /// `KEEPDEFAULTS` — preserve column defaults rather than NULL on INSERT.
    KeepDefaults,
    /// `IGNORE_CONSTRAINTS` — bypass constraint checks (BULK INSERT).
    IgnoreConstraints,
    /// `IGNORE_TRIGGERS` — bypass trigger firing (BULK INSERT).
    IgnoreTriggers,
    /// Any other simple-keyword hint admitted by the permissive parser
    /// but not classified by the typed variants above. The hint span on
    /// the parent [`AstTableHint`] preserves the source text for
    /// formatter byte-fidelity; consumers that need to dispatch on
    /// the keyword identity must do so before this catch-all is
    /// reached (i.e. by classifying additional keywords here).
    OtherSimple,
    // ── Argument-bearing hints ─────────────────────────────────────────
    /// INDEX(value [, ...]) or INDEX = (value)
    Index {
        /// Spans of index name or ID values
        values: Vec<Span>,
    },
    /// FORCESEEK or FORCESEEK(index_name(col [, ...]))
    ForceSeek {
        /// Index name span (None for bare FORCESEEK)
        index_name: Option<Span>,
        /// Column name spans
        columns: Vec<Span>,
    },
    /// SPATIAL_WINDOW_MAX_CELLS = integer_value
    SpatialWindowMaxCells {
        /// Span of the integer value
        value: Span,
    },
}

// ── End T-SQL Table Hints ──────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct AstTableRef {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    pub name: Box<AstObjectRef>,
    pub prefix_inline_fragments: Box<Vec<JinjaInlineFragment>>,
    pub alias: Option<Box<AstIdentifier>>,
    pub alias_columns: Option<Box<Vec<AstIdentifier>>>, // Column list after alias: AS t(col1, col2, ...)
    /// Alias that appears after PIVOT/UNPIVOT/MATCH_RECOGNIZE (result alias)
    /// When both this and `alias` are present (e.g., FROM table t MATCH_RECOGNIZE(...) mr),
    /// `alias` is the table alias (before transform) and this is the result alias (after)
    pub result_alias: Option<Box<AstIdentifier>>,
    /// Column list after result_alias: AS p(col1, col2, ...) for PIVOT
    pub result_alias_columns: Option<Box<Vec<AstIdentifier>>>,
    /// Subquery for derived tables. Can be AstStmt::Select or AstStmt::SetSelect (UNION/INTERSECT/EXCEPT)
    pub subquery: Option<Box<AstStmt>>,
    /// Opening paren span for derived table subquery (None if not a subquery)
    pub subquery_lparen_span: Option<Span>,
    /// Closing paren span for derived table subquery (None if not a subquery)
    pub subquery_rparen_span: Option<Span>,
    /// Parenthesised join group `(t1 a JOIN t2 b ON …)` (standard SQL
    /// `joined_table` production). When `Some`, this AstTableRef was
    /// promoted from inside the parens; the boxed payload carries the
    /// span of `(`, the span of `)`, and the count of `joins` entries
    /// that were inside the parens. Post-paren joins (e.g.
    /// `(a JOIN b ON …) JOIN c ON …`) are appended to `joins` after
    /// that count. Boxed to keep `AstTableRef` lean for deep nesting.
    pub paren_group: Option<Box<ParenGroupInfo>>,
    pub values: Option<Box<AstValues>>,
    /// Span of LATERAL keyword when present (for correlated subqueries/table functions).
    pub lateral_keyword_span: Option<Span>,
    pub only_span: Option<Span>, // PostgreSQL: FROM ONLY parent_table (exclude child tables in inheritance)
    pub time_travel: Option<Box<AstTimeTravelClause>>, // Boxed: was 408 bytes
    pub sample: Option<Box<AstSampleClause>>, // Boxed: was 792 bytes
    pub changes: Option<Box<AstChangesClause>>, // Boxed: was 832 bytes
    pub stage_options: Option<Box<AstStageOptions>>, // Options for stage references: ( FILE_FORMAT => ..., PATTERN => ... )
    pub table_function: Option<Box<AstExpr>>,        // TABLE(function_call) for UDTFs
    /// T-SQL TVF schema clause: `OPENJSON(...) WITH (colName type [path] [AS JSON], ...)`
    pub tvf_schema_span: Option<Span>,
    pub with_offset: Option<Box<AstWithOffset>>, // Boxed: BigQuery: WITH OFFSET [AS alias] for UNNEST
    pub pivot: Option<Box<AstPivotClause>>,      // Boxed: PIVOT clause
    pub unpivot: Option<Box<AstUnpivotClause>>,  // Boxed: UNPIVOT clause
    pub match_recognize: Option<Box<AstMatchRecognize>>, // Boxed: was 264 bytes
    /// T-SQL table hints: WITH (NOLOCK), WITH (UPDLOCK, HOLDLOCK), etc.
    pub table_hints: Option<Box<AstTableHintClause>>,
    /// MySQL index hints: `USE|FORCE|IGNORE INDEX|KEY [FOR JOIN|ORDER BY|
    /// GROUP BY] (idx, ...)` — space-separated list after the table alias.
    pub index_hints: Option<Box<Vec<AstIndexHint>>>,
    /// MySQL partition selection: `tbl PARTITION (p0, p1)` between the
    /// table name and the alias.
    pub partition_selection: Option<Box<AstPartitionSelection>>,
    pub syntax_id: Option<crate::syntax::SyntaxTableRefId>, // CST syntax node for alias AS keyword
    pub suffix_inline_fragments: Box<Vec<JinjaInlineFragment>>,
    pub joins: Box<Vec<Box<AstJoin>>>, // Boxed container to reduce AstTableRef inline size
}

/// MySQL table-ref partition selection: `tbl PARTITION (p0, p1)`.
#[derive(Debug, Clone)]
pub struct AstPartitionSelection {
    pub node_id: crate::ast::NodeId,
    /// Span of the PARTITION keyword.
    pub partition_kw_span: Span,
    pub lparen_span: Span,
    /// Partition / subpartition names (plain identifiers).
    pub partition_name_spans: Vec<Span>,
    pub rparen_span: Span,
    /// Whole clause: PARTITION through `)`.
    pub span: Span,
}

/// One MySQL index hint: `USE INDEX FOR ORDER BY (idx_a, idx_b)`.
#[derive(Debug, Clone)]
pub struct AstIndexHint {
    pub node_id: crate::ast::NodeId,
    pub kind: AstIndexHintKind,
    /// Span of USE / FORCE / IGNORE.
    pub kind_span: Span,
    /// Span of INDEX / KEY.
    pub index_kw_span: Span,
    /// Optional hint scope; span covers `FOR JOIN` / `FOR ORDER BY` /
    /// `FOR GROUP BY`.
    pub scope: Option<(AstIndexHintScope, Span)>,
    pub lparen_span: Span,
    /// Index names; `PRIMARY` (a keyword) is legal here. Empty list is
    /// legal for `USE INDEX ()` (means "use no indexes").
    pub index_name_spans: Vec<Span>,
    pub rparen_span: Span,
    /// Whole hint: kind keyword through `)`.
    pub span: Span,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AstIndexHintKind {
    Use,
    Force,
    Ignore,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AstIndexHintScope {
    Join,
    OrderBy,
    GroupBy,
}

#[derive(Debug, Clone)]
pub enum AstJoinKind {
    Inner,
    LeftOuter,
    RightOuter,
    FullOuter,
    Cross,
    Asof, // ASOF JOIN - special join with MATCH_CONDITION requirement
    NaturalInner,
    NaturalLeftOuter,
    NaturalRightOuter,
    NaturalFullOuter,
}

#[derive(Debug, Clone)]
pub enum AstJoinConstraint {
    On(Box<AstExpr>),
    Using(Vec<AstIdentifier>),
    None,
}

/// MATCH_CONDITION clause for ASOF JOIN
/// Syntax: MATCH_CONDITION ( left_expr >= right_expr )
#[derive(Debug, Clone)]
pub struct AstMatchCondition {
    pub node_id: crate::ast::NodeId,
    pub condition: AstExpr, // The comparison expression (e.g., t1.ts >= t2.ts)
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct AstJoin {
    pub node_id: crate::ast::NodeId,
    pub kind: AstJoinKind,
    /// Span of APPLY keyword for T-SQL APPLY joins; None for regular JOIN.
    pub apply_keyword_span: Option<Span>,
    /// Span of DIRECTED keyword when present.
    pub directed_keyword_span: Option<Span>,
    /// Span of LATERAL keyword when present.
    pub lateral_keyword_span: Option<Span>,
    /// Span of ASOF keyword when present.
    pub asof_keyword_span: Option<Span>,
    pub match_condition: Option<Box<AstMatchCondition>>, // Required for ASOF JOIN
    pub prefix_inline_fragments: Vec<JinjaInlineFragment>,
    pub right: Box<AstTableRef>, // Boxed to reduce stack usage (was 2696 bytes inline)
    pub constraint: AstJoinConstraint,
    pub suffix_inline_fragments: Vec<JinjaInlineFragment>,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct AstGroupBy {
    pub node_id: crate::ast::NodeId,
    pub variant: AstGroupByVariant,
    /// Syntax node containing GROUP and BY keyword tokens (None if CST not available)
    pub syntax_id: Option<crate::syntax::SyntaxGroupById>,
    /// Trailing `WITH ROLLUP` / `WITH CUBE` modifier (MySQL / legacy T-SQL).
    pub with_modifier: Option<AstGroupByWithModifier>,
    /// Span of the trailing `WITH ...` modifier, when present.
    pub with_modifier_span: Option<Span>,
    pub prefix_inline_fragments: Vec<JinjaInlineFragment>,
    pub suffix_inline_fragments: Vec<JinjaInlineFragment>,
    pub span: Span,
}

/// Trailing GROUP BY modifier: `WITH ROLLUP` (MySQL) / `WITH CUBE` (legacy T-SQL).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AstGroupByWithModifier {
    Rollup,
    Cube,
}

#[derive(Debug, Clone)]
pub enum AstGroupByVariant {
    /// Standard GROUP BY with a list of ordinary grouping expressions
    /// (`GROUP BY a, b, expr`). Used iff the clause contains no
    /// CUBE / ROLLUP / GROUPING SETS operator.
    Standard(Vec<AstGroupItem>),
    /// GROUP BY ALL - groups by all non-aggregate SELECT items
    All,
    /// A comma-separated list of grouping elements where at least one is a
    /// CUBE / ROLLUP / GROUPING SETS operator, possibly mixed with ordinary
    /// expressions: `GROUP BY a, ROLLUP(b, c), CUBE(d)`. A single grouping
    /// operator on its own (`GROUP BY CUBE(a)`) is also represented here as a
    /// one-element list.
    Elements(Vec<AstGroupElement>),
    /// Jinja expression generates the entire GROUP BY clause
    /// e.g., {{ dbt_utils.group_by(n=13) }}
    JinjaPlaceholder(Span),
}

/// One element of a `GROUP BY` grouping-element list
/// (`AstGroupByVariant::Elements`).
#[derive(Debug, Clone)]
pub struct AstGroupElement {
    pub node_id: crate::ast::NodeId,
    pub kind: AstGroupElementKind,
    /// Span covering the whole element, including any `CUBE(...)` parentheses.
    pub span: Span,
}

#[derive(Debug, Clone)]
pub enum AstGroupElementKind {
    /// An ordinary grouping expression (column, expression, or positional ref).
    Expr(AstGroupItem),
    /// CUBE(...) - all combinations of the listed items.
    Cube(Vec<AstGroupItem>),
    /// ROLLUP(...) - hierarchical (prefix) grouping sets.
    Rollup(Vec<AstGroupItem>),
    /// GROUPING SETS(...) - explicit list of grouping sets.
    GroupingSets(Vec<Vec<AstGroupItem>>),
}

#[derive(Debug, Clone)]
pub struct AstGroupItem {
    pub node_id: crate::ast::NodeId,
    pub expr: AstExpr,
}

#[derive(Debug, Clone)]
pub struct AstOrderBy {
    pub node_id: crate::ast::NodeId,
    pub items: Vec<Box<AstOrderItem>>, // Boxed: was 408 bytes each
    pub prefix_inline_fragments: Vec<JinjaInlineFragment>,
    pub suffix_inline_fragments: Vec<JinjaInlineFragment>,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct AstOrderItem {
    pub node_id: crate::ast::NodeId,
    pub expr: AstExpr,
    pub asc: Option<bool>, // None = no explicit direction
    /// Syntax node containing ASC/DESC and NULLS FIRST/LAST keyword tokens (None if direction is implicit)
    pub syntax_id: Option<crate::syntax::SyntaxOrderItemId>,
    pub nulls_first: Option<bool>, // None = default, Some(true)=FIRST, Some(false)=LAST
    pub span: Span,
}

/// FOR UPDATE/SHARE locking clause for SELECT statements.
/// Snowflake: FOR UPDATE [ NOWAIT | WAIT <wait_time> ]
/// PostgreSQL: FOR { UPDATE | NO KEY UPDATE | SHARE | KEY SHARE }
///             [ OF table_name [, ...] ] [ NOWAIT | SKIP LOCKED ]
#[derive(Debug, Clone)]
pub struct AstForUpdate {
    pub node_id: crate::ast::NodeId,
    /// Span covering "FOR UPDATE" / "FOR SHARE" / "FOR NO KEY UPDATE" / "FOR KEY SHARE" keywords
    pub for_update_span: Span,
    /// Lock strength (default: Update for backward compatibility)
    pub lock_strength: LockStrength,
    /// Optional OF table_name [, ...] clause (PostgreSQL)
    pub of_tables: Vec<Span>,
    /// Span covering the OF keyword, if present
    pub of_keyword_span: Option<Span>,
    /// Wait policy (None = default behavior)
    pub wait_policy: Option<ForUpdateWaitPolicy>,
    /// Span covering the entire FOR ... clause
    pub span: Span,
}

/// Lock strength for FOR locking clause
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockStrength {
    /// FOR UPDATE - strongest lock, prevents all modifications
    Update,
    /// FOR NO KEY UPDATE - like UPDATE but allows SELECT FOR KEY SHARE (PostgreSQL)
    NoKeyUpdate,
    /// FOR SHARE - shared lock, prevents modifications but allows other FOR SHARE
    Share,
    /// FOR KEY SHARE - weakest lock, prevents deletion and key changes (PostgreSQL)
    KeyShare,
}

/// Wait policy for FOR locking clause
#[derive(Debug, Clone)]
pub enum ForUpdateWaitPolicy {
    /// NOWAIT - return error immediately if rows can't be locked
    NoWait { nowait_span: Span },
    /// `WAIT <seconds>` - wait up to specified seconds for lock (Snowflake/Oracle)
    Wait {
        wait_span: Span,
        /// Duration expression (typically a number literal)
        duration: Box<AstExpr>,
    },
    /// SKIP LOCKED - skip rows that can't be locked immediately (PostgreSQL)
    SkipLocked {
        /// Span covering "SKIP LOCKED"
        skip_locked_span: Span,
    },
}

#[derive(Debug, Clone)]
pub enum AstQuantifier {
    Any,
    All,
}

/// Search modifier inside `MATCH ... AGAINST (expr <modifier>)` (MySQL
/// full-text search). The span covers the entire modifier text and is
/// emitted verbatim by the formatter.
#[derive(Debug, Clone)]
pub struct AstTextSearchModifier {
    pub kind: AstTextSearchModifierKind,
    pub span: Span,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AstTextSearchModifierKind {
    /// `IN BOOLEAN MODE`
    Boolean,
    /// `IN NATURAL LANGUAGE MODE`
    NaturalLanguage,
    /// `IN NATURAL LANGUAGE MODE WITH QUERY EXPANSION`
    NaturalLanguageQueryExpansion,
    /// `WITH QUERY EXPANSION`
    QueryExpansion,
}

/// Data type representation for CAST and type conversion operations.
///
/// Supports:
/// - Simple types: VARCHAR, INTEGER, DATE, etc.
/// - Types with precision: VARCHAR(50), NUMBER(10)
/// - Types with precision and scale: NUMBER(10,2), DECIMAL(5,4)
#[derive(Debug, Clone)]
pub enum AstDataType {
    /// Simple type without parameters: VARCHAR, INTEGER, DATE, etc.
    Simple { name_span: Span },
    /// Type with precision: VARCHAR(50), NUMBER(10)
    WithPrecision {
        syntax_id: crate::syntax::SyntaxTypePrecisionId,
        name_span: Span,
        precision_span: Span,
    },
    /// Type with precision and scale: NUMBER(10,2), DECIMAL(5,4)
    WithPrecisionScale {
        syntax_id: crate::syntax::SyntaxTypePrecisionScaleId,
        name_span: Span,
        precision_span: Span,
        scale_span: Span,
    },
    /// Parameterized type with angle brackets: `ARRAY<STRING>`, `STRUCT<a INT64, b STRING>`
    /// Used by BigQuery for generic type parameters.
    /// The entire type (including angle brackets and inner types) is captured as a single span.
    Parameterized {
        syntax_id: crate::syntax::SyntaxParameterizedTypeId,
        /// Span covering the full type expression from name through closing >
        span: Span,
    },
    /// Compound interval type: INTERVAL YEAR [(p)] [TO MONTH], INTERVAL DAY(2) TO SECOND(3), etc.
    /// The entire type expression is captured as a single span.
    CompoundInterval {
        syntax_id: crate::syntax::SyntaxCompoundIntervalId,
        /// Span covering the full type from INTERVAL through the last unit/precision
        span: Span,
    },
}

/// Logical chain operator for flattened OR/AND expressions.
/// Used in `AstExpr::LogicalChain` to represent chains without deep nesting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogicalChainOperator {
    /// Chain of OR expressions: `a OR b OR c OR ...`
    Or,
    /// Chain of AND expressions: `a AND b AND c AND ...`
    And,
}

/// Binary operators used in binary operation expressions.
///
/// Classifies operators by type (arithmetic, comparison, logical, string, pattern matching).
/// Parser maps token text to this enum, providing type-safe operator identity and
/// enabling efficient formatting without string extraction.
///
/// Aliases are normalized (e.g., both `!=` and `<>` map to `NotEqual`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinaryOperator {
    // Arithmetic operators
    /// Addition: `+`
    Plus,
    /// Subtraction: `-`
    Minus,
    /// Multiplication: `*`
    Multiply,
    /// Division: `/`
    Divide,
    /// Modulo: `%`
    Modulo,

    // Comparison operators
    /// Equal: `=`
    Equal,
    /// Not equal: `!=` or `<>`
    NotEqual,
    /// Less than: `<`
    LessThan,
    /// Less than or equal: `<=`
    LessThanOrEqual,
    /// Greater than: `>`
    GreaterThan,
    /// Greater than or equal: `>=`
    GreaterThanOrEqual,
    /// Null-safe equality: `<=>` (MySQL / Spark) — equivalent to
    /// `IS NOT DISTINCT FROM`
    NullSafeEqual,

    // Logical operators
    /// Logical AND: `AND`
    And,
    /// Logical OR: `OR`
    Or,
    /// Logical NOT: `NOT`
    Not,

    // String operators
    /// String concatenation: `||` (Snowflake, PostgreSQL)
    Concat,
    /// Logical OR: `||` (MySQL default behavior)
    LogicalOr,

    // Pattern matching operators
    /// Pattern match (case-sensitive): `LIKE`
    Like,
    /// Pattern match (case-insensitive): `ILIKE`
    ILike,
    /// Regex match: `RLIKE` or `REGEXP`
    RLike,

    // PostgreSQL geometric operators
    /// Geometric distance: `<->`
    Distance,

    // PostgreSQL array operators
    /// Array contains: `@>`
    ArrayContains,
    /// Array contained by: `<@`
    ArrayContainedBy,
    /// Array overlap: `&&`
    ArrayOverlap,

    // PostgreSQL JSON operators
    /// JSON field access (object): `->`
    JsonField,
    /// JSON field access (text): `->>`
    JsonFieldText,
    /// JSON path (object): `#>`
    JsonPath,
    /// JSON path (text): `#>>`
    JsonPathText,
    /// JSON contains: `@?`
    JsonContains,
    /// JSON exists: `??`
    JsonExists,

    // PostgreSQL regex operators
    /// Regex match: `~`
    RegexMatch,
    /// Regex match case-insensitive: `~*`
    RegexMatchI,
    /// Regex not match: `!~`
    RegexNotMatch,
    /// Regex not match case-insensitive: `!~*`
    RegexNotMatchI,

    // Bitwise operators
    /// Left shift: `<<`
    LeftShift,
    /// Right shift: `>>`
    RightShift,
    /// Bitwise XOR / Power: `^`
    BitwiseXor,
    /// Bitwise XOR (PostgreSQL): `#`
    BitwiseXorPg,
}

/// - **Special**: CASE expressions, CAST, BETWEEN, IN, LIKE
/// - **Complex**: Array indexing, binary/unary operations
///
/// Every expression variant includes span information for source location.
#[derive(Debug, Clone)]
pub enum AstExpr {
    Ident {
        node_id: crate::ast::NodeId,
        column_ref: AstColumnRef,
    },
    Literal {
        node_id: crate::ast::NodeId,
        literal: AstLiteral,
    },
    /// Placeholder for bind parameters: ?
    /// Used in prepared statements and cursor declarations with bind parameters.
    Placeholder {
        node_id: crate::ast::NodeId,
        span: Span,
    },
    /// Jinja template placeholder: {{ ... }}, {% ... %}, or {# ... #}
    /// Preserves exact Jinja syntax without parsing internal structure.
    /// Used for dbt templates and other Jinja-based SQL generation.
    JinjaPlaceholder {
        node_id: crate::ast::NodeId,
        kind: JinjaKind,
        span: Span,
        /// Optional parsed Jinja expression
        /// None means expression was not parsed or parsing failed
        expr: Option<crate::ast::JinjaExpr>,
        /// CST link for {{ expr }} interpolations with individual tokens.
        /// When Some, the formatter emits via CST tokens for proper trivia.
        syntax_id: Option<crate::syntax::SyntaxJinjaInterpolationId>,
    },
    /// dbt ref() function call: ref('model_name') or {{ ref('model_name') }}
    /// First-class AST node for model references, enabling lineage tracking.
    DbtRef {
        node_id: crate::ast::NodeId,
        /// Span of the 'ref' function name token
        func_name_span: Span,
        /// Span of the opening parenthesis
        lparen_span: Span,
        /// The model name being referenced (e.g., "orders", "customers")
        model_name: String,
        /// Span of the model name string literal (including quotes)
        model_name_span: Span,
        /// Optional package name for cross-project refs: ref('package', 'model')
        package_name: Option<String>,
        /// Span of the package name string literal (including quotes), if present
        package_name_span: Option<Span>,
        /// Span of the closing parenthesis
        rparen_span: Span,
        /// Span covering the entire ref(...) expression
        span: Span,
    },
    /// dbt source() function call: source('source_name', 'table_name')
    /// First-class AST node for source references, enabling lineage tracking.
    DbtSource {
        node_id: crate::ast::NodeId,
        /// Span of the 'source' function name token
        func_name_span: Span,
        /// Span of the opening parenthesis
        lparen_span: Span,
        /// The source name (e.g., "raw_data", "external")
        source_name: String,
        /// Span of the source name string literal (including quotes)
        source_name_span: Span,
        /// The table name within the source
        table_name: String,
        /// Span of the table name string literal (including quotes)
        table_name_span: Span,
        /// Span of the closing parenthesis
        rparen_span: Span,
        /// Span covering the entire source(...) expression
        span: Span,
    },
    /// dbt var() function call: var('variable_name') or var('name', default)
    /// First-class AST node for variable references.
    DbtVar {
        node_id: crate::ast::NodeId,
        /// Span of the 'var' function name token
        func_name_span: Span,
        /// Span of the opening parenthesis
        lparen_span: Span,
        /// The variable name being referenced
        var_name: String,
        /// Span of the variable name string literal (including quotes)
        var_name_span: Span,
        /// Optional default value (as raw expression string)
        default_value: Option<String>,
        /// Span of the default value expression, if present
        default_value_span: Option<Span>,
        /// Span of the closing parenthesis
        rparen_span: Span,
        /// Span covering the entire var(...) expression
        span: Span,
    },
    /// dbt config() function call: config(materialized='table', ...)
    /// First-class AST node for model configuration.
    DbtConfig {
        node_id: crate::ast::NodeId,
        /// Span of the 'config' function name token
        func_name_span: Span,
        /// Span of the opening parenthesis
        lparen_span: Span,
        /// Raw config arguments as key-value pairs
        /// Stored as strings since values can be complex expressions
        args: Vec<(String, String)>,
        /// Span of the closing parenthesis
        rparen_span: Span,
        /// Span covering the entire config(...) expression
        span: Span,
    },
    /// dbt this reference: this or this()
    /// Refers to the current model being compiled.
    DbtThis {
        node_id: crate::ast::NodeId,
        /// Span of the 'this' token
        this_span: Span,
        /// Optional parentheses for this() form
        parens: Option<(Span, Span)>,
        /// Span covering the entire this or this() expression
        span: Span,
    },
    /// Positional column reference: `$<n>` or `qualifier.$<n>` (e.g., `src.$1`)
    PositionRef {
        node_id: crate::ast::NodeId,
        /// Optional qualifier for qualified position refs (e.g., "src" in src.$1)
        qualifier: Option<AstObjectRef>,
        /// Span covering the dot before dollar (only present when qualified)
        dot_span: Option<Span>,
        dollar_span: Span,
        index_span: Span,
    },
    /// `[NOT] IN` list predicate: `<expr> [NOT] IN (expr, expr, ...)`.
    ///
    /// `negated` is `true` when the source spelled `NOT IN`. The
    /// `NOT` keyword's token id also lives on the syntax arena's
    /// [`crate::syntax::SyntaxInList::not_keyword`] for the formatter;
    /// this AST field exists so analyses (constraint extraction,
    /// linter rules) can determine the predicate's polarity without
    /// threading the syntax arena.
    InList {
        node_id: crate::ast::NodeId,
        syntax_id: crate::syntax::SyntaxInListId,
        expr: Box<AstExpr>,
        list: Vec<AstExpr>,
        negated: bool,
        span: Span,
    },
    /// IN list with Jinja control flow - treat entire list as opaque source span
    InListOpaque {
        node_id: crate::ast::NodeId,
        expr: Box<AstExpr>,
        not_span: Option<Span>,
        in_span: Span,
        /// Span covering '(' through ')' of the list content (preserves exact source)
        list_span: Span,
        span: Span,
    },
    ExplSnowIdent {
        node_id: crate::ast::NodeId,
        ident_span: Span,
        arg: Box<AstExpr>,
        span: Span,
    },
    Case {
        node_id: crate::ast::NodeId,
        /// Typed syntax node for CASE expression structure (CASE/END/ELSE tokens).
        /// Leading/trailing trivia for these keywords are owned by the syntax layer.
        syntax_id: crate::syntax::SyntaxCaseExprId,
        kind: AstCaseKind,
        operand: Option<Box<AstExpr>>,
        whens: Vec<Box<AstCaseWhen>>, // Boxed: was 840 bytes each
        else_expr: Option<Box<AstExpr>>,
        /// Span covering the entire CASE expression.
        span: Span,
    },
    /// `[NOT] IN (subquery)` predicate: `<expr> [NOT] IN (SELECT ... [UNION/INTERSECT/EXCEPT ...])`.
    /// Structural tokens (NOT/IN keywords) are owned by the syntax layer;
    /// `negated` mirrors `SyntaxInSubquery::not_keyword.is_some()` so consumers
    /// can determine the predicate's polarity without threading the syntax
    /// arena, matching
    /// the [`AstExpr::InList`] convention.
    /// The subquery can be a single SELECT or a set operation (UNION/INTERSECT/EXCEPT).
    InSubquery {
        node_id: crate::ast::NodeId,
        syntax_id: crate::syntax::SyntaxInSubqueryId,
        expr: Box<AstExpr>,
        subquery: Box<AstStmt>,
        negated: bool,
        span: Span,
    },
    /// Binary operation expression: `<left> <operator> <right>`.
    /// Operator token is owned by the syntax layer, operator identity stored here.
    BinaryOp {
        node_id: crate::ast::NodeId,
        left: Box<AstExpr>,
        operator: BinaryOperator,
        syntax_id: crate::syntax::SyntaxBinaryOpId,
        right: Box<AstExpr>,
        span: Span,
    },
    /// Flattened chain of OR or AND expressions.
    /// Used to represent long chains like `a OR b OR c OR d ...` without deep nesting.
    /// This prevents stack overflow when walking expressions with 100s of OR/AND conditions.
    ///
    /// Invariants:
    /// - `operands.len() >= 2` (otherwise would be a single expression)
    /// - `operator_syntax_ids.len() == operands.len() - 1` (one operator between each pair)
    LogicalChain {
        node_id: crate::ast::NodeId,
        /// The operator type (must be Or or And)
        operator: LogicalChainOperator,
        /// The operands in left-to-right order
        operands: Vec<Box<AstExpr>>,
        /// Syntax IDs for each operator token (for formatting with proper trivia)
        operator_syntax_ids: Vec<crate::syntax::SyntaxBinaryOpId>,
        /// Span covering the entire chain
        span: Span,
    },
    /// EXISTS (subquery) predicate in WHERE/QUALIFY/etc.
    /// Structural tokens (EXISTS / parens) are owned by the syntax
    /// layer. `negated` carries the semantic NOT-EXISTS flag at the
    /// AST level so downstream consumers don't have to reach into the
    /// CST to recover it.
    /// Mirrors the existing `negated: bool` discipline on
    /// `AstExpr::InSubquery`, `AstExpr::QuantifiedSubquery`, etc.
    /// The subquery is an AstStmt to support set operations (UNION/INTERSECT/EXCEPT).
    ExistsSubquery {
        node_id: crate::ast::NodeId,
        syntax_id: crate::syntax::SyntaxExistsSubqueryId,
        subquery: Box<AstStmt>,
        negated: bool,
        span: Span,
    },
    /// Spread operator: ** <array_expr>, which expands an array into a
    /// list of individual values for IN clauses and function calls.
    Spread {
        node_id: crate::ast::NodeId,
        stars_span: Span,
        expr: Box<AstExpr>,
        span: Span,
    },
    /// Array literal: `[expr, expr, ...]` or `ARRAY[expr, expr, ...]` or `ARRAY<type>[expr, ...]`
    /// Structural tokens (brackets) are owned by the syntax layer.
    Array {
        node_id: crate::ast::NodeId,
        syntax_id: crate::syntax::SyntaxArrayLiteralId,
        elements: Vec<AstExpr>,
        span: Span,
        /// If true, this array uses PostgreSQL/BigQuery ARRAY[...] syntax vs Snowflake [...]
        has_array_keyword: bool,
        /// Span covering the ARRAY keyword and optional type params (e.g., `ARRAY<FLOAT64>`).
        /// Used by the formatter to emit the keyword from source.
        array_keyword_span: Option<Span>,
    },
    /// Object literal: {key: value, key2: value2, ...} or {} for empty object
    /// Snowflake syntax for inline object construction, equivalent to OBJECT_CONSTRUCT().
    /// Structural tokens (curly braces) are owned by the syntax layer.
    Object {
        node_id: crate::ast::NodeId,
        syntax_id: crate::syntax::SyntaxObjectLiteralId,
        /// Key-value pairs. Keys can be identifiers or string literals.
        entries: Vec<(AstExpr, AstExpr)>,
        span: Span,
    },
    /// Window function call with OVER clause: func_name(args) OVER (window_spec)
    /// Examples: ROW_NUMBER() OVER (ORDER BY id), SUM(amount) OVER (PARTITION BY category)
    /// Also supports DISTINCT and WITHIN GROUP like regular function calls
    WindowFn {
        node_id: crate::ast::NodeId,
        func_name: AstIdentifier,
        /// `APPROXIMATE` modifier span when the windowed call is preceded by
        /// `APPROXIMATE` (e.g. `APPROXIMATE COUNT(DISTINCT x) OVER (...)`).
        /// Span-based to match `WindowFn`'s span-oriented header (cf. `quantifier`).
        approximate: Option<Span>,
        lparen_span: Span,
        /// Optional DISTINCT or ALL keyword inside the function call
        quantifier: Option<(AstSetQuantifier, Span)>,
        args: Vec<Box<AstFunctionArg>>, // Boxed: was 384 bytes each
        rparen_span: Span,
        /// Optional WITHIN GROUP clause (before OVER)
        within_group: Option<Box<AstWithinGroup>>,
        /// Optional FILTER (WHERE expr) clause (PG aggregate/window modifier)
        filter: Option<Box<AstFilterClause>>,
        /// Optional IGNORE/RESPECT NULLS clause (after rparen, before OVER)
        /// Span covers both keywords: "IGNORE NULLS" or "RESPECT NULLS"
        /// If Some: true = IGNORE NULLS, false = RESPECT NULLS
        null_handling: Option<(bool, Span)>,
        over_span: Span,
        window: Box<AstWindowSpec>,
        span: Span,
    },
    /// Generic windowed expression: <base_expr> OVER (window_spec)
    /// Unlike WindowFn (which is tightly coupled to a function call), this wraps
    /// an arbitrary expression with an OVER clause. Used when the base expression
    /// is not a bare function call — e.g., BigQuery's
    /// `APPROX_QUANTILES(val, 100)[OFFSET(50)] OVER (PARTITION BY grp)`
    /// where the base is an ArraySubscript containing a FunctionCall.
    WindowExpr {
        node_id: crate::ast::NodeId,
        /// The expression before OVER — can be any expression (ArraySubscript, FunctionCall, etc.)
        base: Box<AstExpr>,
        /// Span of the OVER clause (from OVER keyword through closing paren)
        over_span: Span,
        /// Window specification (PARTITION BY, ORDER BY, frame)
        window: Box<AstWindowSpec>,
        /// Full span from base expression start to OVER clause end
        span: Span,
    },
    /// Table-valued function with schema clause: `OPENJSON(...) WITH (col type [path], ...)`
    ///
    /// MSSQL syntax for defining the result schema of TVFs like OPENJSON, OPENXML.
    /// The WITH clause specifies column names, types, and optional JSON path mappings.
    /// Parsed as a postfix operator on FunctionCall (like OVER for window functions).
    TvfWithSchema {
        node_id: crate::ast::NodeId,
        /// The function call expression (OPENJSON, OPENXML, etc.)
        func_call: Box<AstExpr>,
        /// Span covering `WITH (col1 type1 [path1], ...)` — emitted verbatim by formatter
        with_schema_span: Span,
        /// Full span from function call start through WITH clause end
        span: Span,
    },
    /// Quantified subquery comparison: `<expr> <op> ANY/ALL (SELECT ...)`.
    /// Structural tokens (operator and quantifier keywords) are owned by the syntax layer.
    /// The subquery is an AstStmt to support set operations (UNION/INTERSECT/EXCEPT).
    QuantifiedSubquery {
        node_id: crate::ast::NodeId,
        left: Box<AstExpr>,
        operator: BinaryOperator,
        syntax_id: crate::syntax::SyntaxQuantifiedSubqueryId,
        quantifier: AstQuantifier,
        subquery: Box<AstStmt>,
        span: Span,
    },
    /// Scripting variable reference, e.g. :my_variable, used inside
    /// Snowflake Scripting expressions (including DML inside blocks).
    /// Structural token (leading colon) is owned by the syntax layer.
    ScriptingVarRef {
        node_id: crate::ast::NodeId,
        syntax_id: crate::syntax::SyntaxScriptingVarId,
        name_span: Span,
        span: Span,
    },
    /// Qualified star projection: table_name.* or alias.*
    /// Used in SELECT list to expand all columns from a specific table.
    /// Can include EXCLUDE, REPLACE, and RENAME modifiers like unqualified star.
    /// Example: SELECT t1.*, t2.* EXCLUDE (id) FROM t1 JOIN t2
    QualifiedStar {
        node_id: crate::ast::NodeId,
        qualifier: AstObjectRef,
        star_span: Span,
        exclude: Option<Box<AstExclude>>,
        replace: Option<Box<AstReplace>>,
        rename: Option<Box<AstRename>>,
        span: Span,
    },
    /// Unqualified star projection: *
    /// Used in SELECT list when mixed with other columns/expressions.
    /// Can include EXCLUDE, REPLACE, and RENAME modifiers.
    /// Example: SELECT col1, * EXCLUDE (id), col2 FROM t
    UnqualifiedStar {
        node_id: crate::ast::NodeId,
        star_span: Span,
        exclude: Option<Box<AstExclude>>,
        replace: Option<Box<AstReplace>>,
        rename: Option<Box<AstRename>>,
        span: Span,
    },
    /// PRIOR expression for CONNECT BY hierarchical queries.
    /// Syntax: `PRIOR <expr>`
    /// References the parent level in a hierarchical query.
    /// Example: CONNECT BY manager_id = PRIOR employee_id
    Prior {
        node_id: crate::ast::NodeId,
        prior_span: Span,
        expr: Box<AstExpr>,
        span: Span,
    },
    /// `IS [NOT] NULL` predicate: `<expr> IS [NOT] NULL`
    IsNull {
        node_id: crate::ast::NodeId,
        expr: Box<AstExpr>,
        is_span: Span,
        not_span: Option<Span>,
        null_span: Span,
        span: Span,
    },
    /// `IS [NOT] DISTINCT FROM` predicate: `<expr1> IS [NOT] DISTINCT FROM <expr2>`
    /// NULL-safe equality comparison
    IsDistinctFrom {
        node_id: crate::ast::NodeId,
        left: Box<AstExpr>,
        right: Box<AstExpr>,
        is_span: Span,
        not_span: Option<Span>,
        distinct_span: Span,
        from_span: Span,
        span: Span,
    },
    /// `[NOT] LIKE/ILIKE/RLIKE` predicate: `<expr> [NOT] LIKE/ILIKE/RLIKE pattern [ESCAPE char]`
    Like {
        node_id: crate::ast::NodeId,
        expr: Box<AstExpr>,
        not_span: Option<Span>,
        like_kind_span: Span,
        pattern: Box<AstExpr>,
        escape_clause: Option<Box<AstExpr>>,
        /// `Some` when the escape clause was written as the ODBC form
        /// `{escape 'c'}`; covers `{`..`}` and the formatter emits it verbatim.
        odbc_escape_span: Option<Span>,
        span: Span,
    },
    /// `[NOT] SIMILAR TO` predicate: `<expr> [NOT] SIMILAR TO pattern [ESCAPE char]`
    /// SQL-standard regex-like pattern matching (PostgreSQL).
    /// SIMILAR TO uses SQL regular expression patterns (_, %, |, *, +, etc.).
    SimilarTo {
        node_id: crate::ast::NodeId,
        expr: Box<AstExpr>,
        not_span: Option<Span>,
        /// Span covering both SIMILAR and TO tokens
        similar_to_span: Span,
        pattern: Box<AstExpr>,
        escape_clause: Option<Box<AstExpr>>,
        /// `Some` when the escape clause was written as the ODBC form
        /// `{escape 'c'}`; covers `{`..`}` and the formatter emits it verbatim.
        odbc_escape_span: Option<Span>,
        span: Span,
    },
    /// CAST expression: CAST(expr AS type)
    /// Structural tokens (CAST keyword, parens, AS) are owned by the syntax layer.
    Cast {
        node_id: crate::ast::NodeId,
        syntax_id: crate::syntax::SyntaxCastExprId,
        expr: Box<AstExpr>,
        target_type: AstDataType,
        span: Span,
    },
    /// TRY_CAST expression: TRY_CAST(expr AS type) - returns NULL on conversion failure
    /// Structural tokens (TRY_CAST keyword, parens, AS) are owned by the syntax layer.
    TryCast {
        node_id: crate::ast::NodeId,
        syntax_id: crate::syntax::SyntaxTryCastId,
        expr: Box<AstExpr>,
        target_type: AstDataType,
        span: Span,
    },
    /// SAFE_CAST expression: SAFE_CAST(expr AS type) - BigQuery equivalent of TRY_CAST
    /// Returns NULL on conversion failure instead of raising an error.
    /// Structural tokens (SAFE_CAST keyword, parens, AS) are owned by the syntax layer.
    SafeCast {
        node_id: crate::ast::NodeId,
        syntax_id: crate::syntax::SyntaxSafeCastId,
        expr: Box<AstExpr>,
        target_type: AstDataType,
        span: Span,
    },
    /// Type cast with :: operator: expr::type (PostgreSQL-style)
    /// Structural token (double-colon) is owned by the syntax layer.
    TypeCast {
        node_id: crate::ast::NodeId,
        syntax_id: crate::syntax::SyntaxTypeCastId,
        expr: Box<AstExpr>,
        target_type: AstDataType,
        span: Span,
    },
    /// EXTRACT expression: EXTRACT(field FROM expr)
    /// Extracts a date/time field from a timestamp or interval.
    /// The field is a date part like YEAR, MONTH, DAY, DOW, HOUR, MINUTE, SECOND, etc.
    /// Structural tokens (EXTRACT keyword, parens, FROM) are owned by the syntax layer.
    Extract {
        node_id: crate::ast::NodeId,
        syntax_id: crate::syntax::SyntaxExtractId,
        /// The date/time field to extract (e.g., DOW, YEAR, MONTH)
        field_span: Span,
        /// The expression to extract from
        expr: Box<AstExpr>,
        span: Span,
    },
    /// POSITION expression: POSITION(needle IN haystack)
    /// Returns the position of the first occurrence of needle within haystack.
    /// Structural tokens (POSITION keyword, parens, IN) are owned by the syntax layer.
    Position {
        node_id: crate::ast::NodeId,
        syntax_id: crate::syntax::SyntaxPositionId,
        /// The needle expression (substring to search for)
        needle: Box<AstExpr>,
        /// The haystack expression (string to search in)
        haystack: Box<AstExpr>,
        span: Span,
    },
    /// Full-text search predicate: `MATCH (cols) AGAINST (expr [modifier])`
    /// (MySQL). Recognized as a postfix on a function call named MATCH —
    /// nothing else is legal in that position, so recognition is ungated.
    /// All structural tokens are carried as spans (no syntax node).
    MatchAgainst {
        node_id: crate::ast::NodeId,
        /// The `MATCH(col, ...)` call (always `AstExpr::FunctionCall`).
        match_call: Box<AstExpr>,
        /// Span of the AGAINST keyword (lexes as an identifier).
        against_span: Span,
        lparen_span: Span,
        /// The search expression (typically a string literal).
        search: Box<AstExpr>,
        /// Typed search modifier; span covers the full modifier text.
        modifier: Option<AstTextSearchModifier>,
        rparen_span: Span,
        span: Span,
    },
    /// TRIM expression: `TRIM([BOTH|LEADING|TRAILING] [chars] FROM source)`
    /// ANSI trim syntax (distinct from the comma form TRIM(source) which
    /// parses as a plain function call). The trim-spec keyword and the optional
    /// trim-characters expression precede FROM. Structural tokens (TRIM
    /// identifier, parens, spec keyword, FROM) are owned by the syntax layer.
    Trim {
        node_id: crate::ast::NodeId,
        syntax_id: crate::syntax::SyntaxTrimId,
        /// Span of the trim-spec keyword (BOTH/LEADING/TRAILING); None when
        /// unspecified. Mirrors EXTRACT's `field_span` — the formatter emits it
        /// directly from source so original casing is preserved byte-exact.
        spec_span: Option<Span>,
        /// Optional trim-characters expression (the set of characters to strip).
        chars: Option<Box<AstExpr>>,
        /// The source string being trimmed.
        source: Box<AstExpr>,
        span: Span,
    },
    /// SUBSTRING expression: SUBSTRING(source FROM start [FOR length])
    /// ANSI substring syntax (distinct from the comma form
    /// SUBSTRING(source, start, length) which parses as a plain function call).
    /// Structural tokens (SUBSTRING identifier, parens, FROM, FOR) are owned by
    /// the syntax layer.
    Substring {
        node_id: crate::ast::NodeId,
        syntax_id: crate::syntax::SyntaxSubstringId,
        /// The source string.
        source: Box<AstExpr>,
        /// The start position (after FROM). None for SUBSTRING(s FOR n).
        from: Option<Box<AstExpr>>,
        /// The length (after FOR). None for SUBSTRING(s FROM n).
        for_len: Option<Box<AstExpr>>,
        span: Span,
    },
    /// COLLATE expression: expr COLLATE 'spec'
    /// Specifies collation rules for string comparison and sorting.
    /// Structural tokens (COLLATE keyword, spec literal) are owned by the syntax layer.
    Collate {
        node_id: crate::ast::NodeId,
        syntax_id: crate::syntax::SyntaxCollateId,
        expr: Box<AstExpr>,
        span: Span,
    },
    /// `[NOT] BETWEEN` predicate: `<expr> [NOT] BETWEEN lower AND upper`
    /// Structural tokens (NOT/BETWEEN/AND) are owned by the syntax layer.
    /// `<expr> [NOT] BETWEEN <lower> AND <upper>`.
    ///
    /// `negated` is `true` when the source spelled `NOT BETWEEN`.
    /// Mirror of the `InList.negated` field's rationale.
    Between {
        node_id: crate::ast::NodeId,
        syntax_id: crate::syntax::SyntaxBetweenExprId,
        expr: Box<AstExpr>,
        lower: Box<AstExpr>,
        upper: Box<AstExpr>,
        negated: bool,
        span: Span,
    },
    /// Regular function call: func_name(arg1, arg2, ...)
    /// Examples: COUNT(*), SUM(amount), AVG(salary), UPPER(name)
    /// Supports optional modifiers for aggregate functions:
    /// - DISTINCT/ALL quantifier: COUNT(DISTINCT id)
    /// - WITHIN GROUP clause: LISTAGG(...) WITHIN GROUP (ORDER BY ...)
    /// - Named arguments: FLATTEN(INPUT => expr)
    ///
    /// Structural tokens (function name identifier and parentheses, optional DISTINCT/ALL
    /// keyword) are owned by the typed syntax layer via `syntax_id`. The AST here
    /// only contains the semantic pieces: quantifier kind, arguments, WITHIN GROUP, etc.
    FunctionCall {
        node_id: crate::ast::NodeId,
        /// Typed syntax node for the function call header (name, parens, DISTINCT/ALL).
        syntax_id: crate::syntax::SyntaxFunctionCallId,
        /// `APPROXIMATE` aggregate modifier (Redshift): `APPROXIMATE COUNT(DISTINCT x)`,
        /// `APPROXIMATE PERCENTILE_DISC(...)`. A semantic modifier on the aggregate
        /// — parallel to `quantifier` (DISTINCT/ALL); the keyword token is owned by
        /// the syntax node (`approximate_keyword`). Lowered to `AggregateCall::approximate`.
        approximate: bool,
        /// `true` when written as an ODBC escape `{fn F(args)}`; `span` then
        /// includes the braces and the formatter re-emits the whole span.
        odbc_fn: bool,
        /// Semantic function name (identifier node reused by other analyses).
        func_name: AstIdentifier,
        /// Optional DISTINCT or ALL quantifier inside the function call.
        /// The span for the keyword itself is owned by the syntax node.
        quantifier: Option<AstSetQuantifier>,
        /// Function arguments (positional or named).
        args: Vec<Box<AstFunctionArg>>, // Boxed: was 384 bytes each
        /// Optional ORDER BY clause inside the function call for aggregate ordering.
        /// PostgreSQL syntax: ARRAY_AGG(expr ORDER BY expr [ASC|DESC] [NULLS FIRST|LAST])
        /// Stored as raw span and emitted verbatim by the formatter.
        order_by_span: Option<Span>,
        /// Structured ORDER BY items for PG-style inline aggregate
        /// ordering. Populated in parallel with `order_by_span` so
        /// the formatter keeps its verbatim emission (via the span)
        /// while consumers can read the structured keys. `None` when
        /// no inline `ORDER BY` was present.
        inline_order_by: Option<Vec<Box<AstOrderItem>>>,
        /// MySQL GROUP_CONCAT `SEPARATOR 'str'` tail inside the call
        /// parens. Span covers `SEPARATOR` through the string literal;
        /// emitted verbatim between the (optional) inline ORDER BY and
        /// the closing paren. Dialect-gated at parse time.
        separator_span: Option<Span>,
        /// Optional WITHIN GROUP clause (for ordered aggregate functions like LISTAGG).
        within_group: Option<Box<AstWithinGroup>>,
        /// Optional FILTER (WHERE expr) clause (PG aggregate modifier).
        filter: Option<Box<AstFilterClause>>,
        /// Span covering the entire function call, including WITHIN GROUP/FILTER if present.
        span: Span,
    },
    /// Scalar subquery: (SELECT ...) that returns a single value
    /// Used in SELECT list, WHERE conditions, etc.
    ///
    /// Structural tokens (parentheses) are owned by the syntax layer via
    /// `syntax_id`. The AST here stores only the semantic SELECT/set operation and
    /// the overall span. The subquery is an AstStmt to support UNION/INTERSECT/EXCEPT.
    ScalarSubquery {
        node_id: crate::ast::NodeId,
        syntax_id: crate::syntax::SyntaxSubqueryId,
        subquery: Box<AstStmt>,
        span: Span,
    },
    /// Subquery as a function argument without its own parentheses.
    /// Used for constructs like ARRAY(SELECT ...) where the parens belong to
    /// the function call, not the subquery itself.
    ///
    /// Unlike ScalarSubquery, this has no syntax_id because there are no
    /// structural tokens (parens) to track — the formatter emits just the SELECT.
    SubqueryArg {
        node_id: crate::ast::NodeId,
        subquery: Box<AstStmt>,
        span: Span,
    },
    /// Parenthesized expression: (expr)
    /// Preserves explicit parentheses for precedence control and clarity.
    /// The structural tokens (parens) are owned by the syntax layer via `syntax_id`.
    /// Example: (a + b) * c, WHERE (x > 5 AND y < 10) OR z = 0
    Parenthesized {
        node_id: crate::ast::NodeId,
        syntax_id: crate::syntax::SyntaxParenExprId,
        expr: Box<AstExpr>,
        span: Span,
    },
    /// Row value constructor (tuple): (expr, expr, ...)
    /// SQL-92 standard row value constructor for comparisons.
    /// Example: (a, b) IN (SELECT x, y FROM t), (col1, col2) = (1, 2)
    /// Structural tokens (parens, commas) owned by syntax layer.
    RowConstructor {
        node_id: crate::ast::NodeId,
        syntax_id: crate::syntax::SyntaxRowConstructorId,
        elements: Vec<AstExpr>,
        span: Span,
    },
    /// Array subscript: `expr[index]`
    /// Example: `arr[0]`, `arr[i+1]`, `data:items[5]`
    /// Structural tokens (brackets) are owned by the syntax layer.
    ArraySubscript {
        node_id: crate::ast::NodeId,
        syntax_id: crate::syntax::SyntaxArraySubscriptId,
        base: Box<AstExpr>,
        index: Box<AstExpr>,
        span: Span,
    },
    /// Object field access with colon notation: expr:field
    /// Example: data:name, obj:customer:address, src:salesperson.name
    /// Note: field can be unquoted identifier or quoted string
    /// Structural token (colon) is owned by the syntax layer.
    ObjectFieldColon {
        node_id: crate::ast::NodeId,
        syntax_id: crate::syntax::SyntaxColonFieldId,
        base: Box<AstExpr>,
        field_span: Span,
        span: Span,
    },
    /// Object field access with bracket notation: expr['field']
    /// Example: obj['name'], data['complex-field'], src['field with spaces']
    /// Structural tokens (brackets) are owned by the syntax layer.
    ObjectFieldBracket {
        node_id: crate::ast::NodeId,
        syntax_id: crate::syntax::SyntaxBracketFieldId,
        base: Box<AstExpr>,
        field: Box<AstExpr>,
        span: Span,
    },
    /// Object field access with dot notation: expr.field
    /// Example: data['key'].subfield, func().result
    /// Used for Snowflake semi-structured data access when dot follows a bracket or other expression.
    /// Structural token (dot) is owned by the syntax layer.
    ObjectFieldDot {
        node_id: crate::ast::NodeId,
        syntax_id: crate::syntax::SyntaxDotFieldId,
        base: Box<AstExpr>,
        field_span: Span,
        span: Span,
    },
    /// Method call on an expression: expr.method(args)
    /// Example: (SELECT ... FOR XML PATH(''), TYPE).value('.', 'NVARCHAR(MAX)')
    /// Used for MSSQL XML methods (.value, .query, .nodes, .modify, .exist) and similar patterns.
    MethodCall {
        node_id: crate::ast::NodeId,
        syntax_id: crate::syntax::SyntaxDotFieldId,
        base: Box<AstExpr>,
        method_name_span: Span,
        args: Vec<AstExpr>,
        lparen_span: Span,
        rparen_span: Span,
        span: Span,
    },
    /// Qualified star from expression: expr.*
    /// Example: data['key'].*
    /// Used when .* follows an arbitrary expression (not just an identifier).
    QualifiedStarFromExpr {
        node_id: crate::ast::NodeId,
        base: Box<AstExpr>,
        star_span: Span,
        span: Span,
    },
    /// Jinja conditional expression: {% if %}...{% elif %}...{% else %}...{% endif %}
    /// Used when Jinja control flow appears in expression contexts like FROM, WHERE, JOIN ON.
    /// Example: FROM {% if prod %}prod{% else %}dev{% endif %}.orders
    ///          WHERE {% if filter %}status = 'active'{% endif %}
    JinjaConditional {
        node_id: crate::ast::NodeId,
        /// Opening {% if %} or {% for %} delimiter
        opening: Box<JinjaBlockDelimiter>,
        /// Content in the "then" branch (expression or unparsed span)
        then_body: Box<JinjaBody>,
        /// Optional {% elif %} branches (delimiter + body)
        elif_branches: Box<Vec<(JinjaBlockDelimiter, JinjaBody)>>,
        /// Optional {% else %} branch (delimiter + body)
        else_branch: Option<Box<(JinjaBlockDelimiter, JinjaBody)>>,
        /// Closing {% endif %} or {% endfor %} delimiter
        closing: Box<JinjaBlockDelimiter>,
        span: Span,
    },
    /// AT TIME ZONE expression: expr AT TIME ZONE zone
    /// Converts timestamp between time zones.
    /// Also covers AT LOCAL (where zone is None, meaning session timezone).
    /// Structural tokens (AT, TIME, ZONE, LOCAL) are owned by the syntax layer.
    AtTimeZone {
        node_id: crate::ast::NodeId,
        syntax_id: crate::syntax::SyntaxAtTimeZoneId,
        /// The timestamp/time expression being converted
        expr: Box<AstExpr>,
        /// The timezone expression (string literal, interval, column ref, etc.)
        /// None for AT LOCAL (uses session timezone)
        zone: Option<Box<AstExpr>>,
        span: Span,
    },
    /// Typed string literal: TYPE_NAME 'string_value'
    /// BigQuery syntax for typed literals like DATE '2024-01-15', TIMESTAMP '...', etc.
    /// Supported type names: DATE, TIME, DATETIME, TIMESTAMP, NUMERIC, BIGNUMERIC,
    /// DECIMAL, BIGDECIMAL, JSON
    TypedStringLiteral {
        node_id: crate::ast::NodeId,
        /// Span of the type name keyword (e.g., "DATE", "TIMESTAMP").
        /// For the ODBC escape form this is the introducer (`d`/`t`/`ts`/`guid`).
        type_name_span: Span,
        /// Span of the string literal (e.g., "'2024-01-15'")
        value_span: Span,
        /// `Some` when written as an ODBC escape (`{d '…'}` etc.); `span` then
        /// includes the braces and the formatter re-emits it verbatim. Lowering
        /// uses the canonical type name instead of slicing `type_name_span`.
        odbc_kind: Option<OdbcLiteralKind>,
        /// Combined span covering both tokens (braces included for ODBC form)
        span: Span,
    },
    /// Error placeholder for unparseable expression content.
    /// Used for LSP error recovery - allows parsing to continue past invalid expressions.
    /// Contains diagnostic information about what went wrong.
    Error {
        /// Unique identifier for this error node
        node_id: crate::ast::NodeId,
        /// Source location of the error (covers the unparseable content)
        span: Span,
        /// Human-readable error message
        message: String,
        /// Tokens that were skipped (for debugging, limited to first N)
        partial_tokens: Vec<String>,
    },
}

/// Body content within a Jinja control block
/// Can be either a parsed SQL expression or an unparsed span for complex/fragment content
#[derive(Debug, Clone)]
pub enum JinjaBody {
    /// Parsed as a complete SQL expression (e.g., column reference, function call)
    Expression(Box<AstExpr>),
    /// Unparsed content span (e.g., SQL fragments like "AND x > 5", ORDER BY modifiers, complex FOR loops)
    Unparsed(Span),
}

impl AstExpr {
    /// Returns the span covering this entire expression.
    pub fn span(&self) -> Span {
        match self {
            AstExpr::Ident { column_ref, .. } => column_ref.name.span,
            AstExpr::Literal { literal, .. } => literal.span(),
            AstExpr::Placeholder { span, .. } => *span,
            AstExpr::JinjaPlaceholder { span, .. } => *span,
            AstExpr::PositionRef {
                qualifier,
                dollar_span,
                index_span,
                ..
            } => Span {
                start: qualifier
                    .as_ref()
                    .map(|q| q.span.start)
                    .unwrap_or(dollar_span.start),
                end: index_span.end,
            },
            AstExpr::InList { span, .. } => *span,
            AstExpr::InListOpaque { span, .. } => *span,
            AstExpr::ExplSnowIdent { span, .. } => *span,
            AstExpr::Case { span, .. } => *span,
            AstExpr::InSubquery { span, .. } => *span,
            AstExpr::BinaryOp { span, .. } => *span,
            AstExpr::LogicalChain { span, .. } => *span,
            AstExpr::ExistsSubquery { span, .. } => *span,
            AstExpr::Spread { span, .. } => *span,
            AstExpr::Array { span, .. } => *span,
            AstExpr::Object { span, .. } => *span,
            AstExpr::WindowFn { span, .. } => *span,
            AstExpr::WindowExpr { span, .. } => *span,
            AstExpr::TvfWithSchema { span, .. } => *span,
            AstExpr::QuantifiedSubquery { span, .. } => *span,
            AstExpr::ScriptingVarRef { span, .. } => *span,
            AstExpr::QualifiedStar { span, .. } => *span,
            AstExpr::UnqualifiedStar { span, .. } => *span,
            AstExpr::Prior { span, .. } => *span,
            AstExpr::IsNull { span, .. } => *span,
            AstExpr::IsDistinctFrom { span, .. } => *span,
            AstExpr::Like { span, .. } => *span,
            AstExpr::SimilarTo { span, .. } => *span,
            AstExpr::Cast { span, .. } => *span,
            AstExpr::TryCast { span, .. } => *span,
            AstExpr::SafeCast { span, .. } => *span,
            AstExpr::TypeCast { span, .. } => *span,
            AstExpr::Extract { span, .. } => *span,
            AstExpr::MatchAgainst { span, .. } => *span,
            AstExpr::Position { span, .. } => *span,
            AstExpr::Trim { span, .. } => *span,
            AstExpr::Substring { span, .. } => *span,
            AstExpr::Collate { span, .. } => *span,
            AstExpr::Between { span, .. } => *span,
            AstExpr::FunctionCall { span, .. } => *span,
            AstExpr::ScalarSubquery { span, .. } => *span,
            AstExpr::SubqueryArg { span, .. } => *span,
            AstExpr::Parenthesized { span, .. } => *span,
            AstExpr::RowConstructor { span, .. } => *span,
            AstExpr::ArraySubscript { span, .. } => *span,
            AstExpr::ObjectFieldColon { span, .. } => *span,
            AstExpr::ObjectFieldBracket { span, .. } => *span,
            AstExpr::ObjectFieldDot { span, .. } => *span,
            AstExpr::MethodCall { span, .. } => *span,
            AstExpr::QualifiedStarFromExpr { span, .. } => *span,
            AstExpr::JinjaConditional { span, .. } => *span,
            AstExpr::DbtRef { span, .. } => *span,
            AstExpr::DbtSource { span, .. } => *span,
            AstExpr::DbtVar { span, .. } => *span,
            AstExpr::DbtConfig { span, .. } => *span,
            AstExpr::DbtThis { span, .. } => *span,
            AstExpr::AtTimeZone { span, .. } => *span,
            AstExpr::TypedStringLiteral { span, .. } => *span,
            AstExpr::Error { span, .. } => *span,
        }
    }

    /// Returns the unique node ID for this expression.
    pub fn node_id(&self) -> crate::ast::NodeId {
        // All AstExpr variants are inline structs with a `node_id` field.
        // This is kept as a manual match (rather than macro-generated) because
        // AstExpr::span() has 3 special cases that make the shared macro awkward.
        // But the node_id() access is completely uniform.
        impl_node_id_match!(
            self,
            AstExpr,
            [
                Ident,
                Literal,
                Placeholder,
                JinjaPlaceholder,
                PositionRef,
                InList,
                InListOpaque,
                ExplSnowIdent,
                Case,
                InSubquery,
                BinaryOp,
                LogicalChain,
                ExistsSubquery,
                Spread,
                Array,
                Object,
                WindowFn,
                WindowExpr,
                TvfWithSchema,
                QuantifiedSubquery,
                ScriptingVarRef,
                QualifiedStar,
                UnqualifiedStar,
                Prior,
                IsNull,
                IsDistinctFrom,
                Like,
                SimilarTo,
                Cast,
                TryCast,
                SafeCast,
                TypeCast,
                Extract,
                MatchAgainst,
                Position,
                Trim,
                Substring,
                Collate,
                Between,
                FunctionCall,
                ScalarSubquery,
                SubqueryArg,
                Parenthesized,
                RowConstructor,
                ArraySubscript,
                ObjectFieldColon,
                ObjectFieldBracket,
                ObjectFieldDot,
                MethodCall,
                QualifiedStarFromExpr,
                JinjaConditional,
                DbtRef,
                DbtSource,
                DbtVar,
                DbtConfig,
                DbtThis,
                AtTimeZone,
                TypedStringLiteral,
                Error,
            ]
        )
    }
}

/// Jinja template syntax kind.
/// Identifies which type of Jinja delimiter was used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JinjaKind {
    /// Expression: {{ ... }}
    /// Outputs a value, e.g., {{ ref('table_name') }}
    Expression,
    /// Statement: {% ... %}
    /// Control flow, e.g., {% if condition %}, {% for item in list %}
    Statement,
    /// Comment: {# ... #}
    /// Template comments that don't appear in output
    Comment,
}

#[derive(Debug, Clone)]
pub enum AstLiteral {
    Number {
        span: Span,
    },
    String {
        span: Span,
    },
    /// A string literal containing Jinja expressions, e.g., `'prefix{{ var }}suffix'`
    /// The span covers the entire string from opening to closing quote.
    StringWithJinja {
        span: Span,
    },
    Boolean {
        span: Span,
    },
    Null {
        span: Span,
    },
}

impl AstLiteral {
    pub fn span(&self) -> Span {
        match self {
            AstLiteral::Number { span } => *span,
            AstLiteral::String { span } => *span,
            AstLiteral::StringWithJinja { span } => *span,
            AstLiteral::Boolean { span } => *span,
            AstLiteral::Null { span } => *span,
        }
    }
}

/// Window specification for OVER clause.
///
/// The structural tokens (OVER keyword, parentheses, PARTITION BY, ORDER BY keywords)
/// are owned by the syntax layer via `syntax_id`. The AST only stores semantic content.
#[derive(Debug, Clone)]
pub struct AstWindowSpec {
    pub node_id: crate::ast::NodeId,
    /// Reference to the typed syntax node that owns all structural tokens.
    /// The formatter uses this for O(1) token access with trivia preservation.
    pub syntax_id: crate::syntax::SyntaxOverClauseId,
    /// Optional reference to an existing named window (for bare `OVER w` or `OVER (w ...)`)
    pub existing_window_name: Option<Span>,
    /// Partition expressions (semantic content only)
    pub partition_by: Vec<AstExpr>,
    /// Order by items (semantic content only)
    pub order_by: Vec<AstOrderItem>,
    /// Optional window frame specification
    pub frame: Option<Box<AstWindowFrame>>,
}

/// A WINDOW clause in a SELECT statement.
/// Syntax: WINDOW w AS (window_spec) [, w2 AS (window_spec2), ...]
#[derive(Debug, Clone)]
pub struct AstWindowClause {
    pub node_id: crate::ast::NodeId,
    /// Span covering the entire WINDOW clause (from WINDOW keyword to end of last definition)
    pub span: Span,
    /// Span covering the WINDOW keyword itself
    pub window_keyword_span: Span,
    /// Named window definitions
    pub definitions: Vec<AstWindowDefinition>,
}

/// A single named window definition within a WINDOW clause.
/// Syntax: name AS (window_spec)
#[derive(Debug, Clone)]
pub struct AstWindowDefinition {
    pub node_id: crate::ast::NodeId,
    /// Span covering the entire definition (name AS (...))
    pub span: Span,
    /// Window name identifier span
    pub name_span: Span,
    /// Span covering the AS keyword
    pub as_keyword_span: Span,
    /// The window specification (reuses SyntaxOverClause for structural tokens)
    pub window_spec: AstWindowSpec,
}

/// WITHIN GROUP clause for ordered aggregate functions like LISTAGG
/// Syntax: WITHIN GROUP (ORDER BY expr [ASC|DESC], ...)
#[derive(Debug, Clone)]
pub struct AstWithinGroup {
    pub node_id: crate::ast::NodeId,
    pub within_span: Span,
    pub group_span: Span,
    pub order_by: Vec<AstOrderItem>,
    pub span: Span,
}

/// FILTER (WHERE expr) clause on aggregate or window function calls.
/// Example: `count(*) FILTER (WHERE status = 'active')`
#[derive(Debug, Clone)]
pub struct AstFilterClause {
    pub node_id: crate::ast::NodeId,
    /// The filter predicate expression (the expr inside WHERE)
    pub expr: Box<AstExpr>,
    /// Span covering "FILTER (WHERE expr)" — the entire clause
    pub span: Span,
}

/// Function call argument - either positional or named
/// Examples:
/// - Positional: `func(expr1, expr2)`
/// - Named: `func(PARAM => value)`
/// - Lambda: `func(array, x -> x > 5)`
/// - Mixed: `func(expr1, PARAM => value, expr2)`
#[derive(Debug, Clone)]
pub enum AstFunctionArg {
    /// Positional argument: any expression
    Positional(Box<AstExpr>),
    /// Named argument with => syntax
    /// Example: INPUT => b.payload, ROWCOUNT => 100
    Named {
        name: AstIdentifier,
        arrow_span: Span,
        value: Box<AstExpr>,
    },
    /// Lambda expression with -> syntax (Snowflake array functions)
    /// Example: FILTER(arr, x -> x > 5), TRANSFORM(arr, (x, i) -> x + i)
    Lambda {
        /// Lambda parameter(s) - single identifier or multiple in parentheses
        params: Vec<AstIdentifier>,
        /// Span of the -> arrow token
        arrow_span: Span,
        /// Lambda body expression
        body: Box<AstExpr>,
        /// Full span from params to end of body
        span: Span,
    },
    /// Aliased argument with AS syntax (BigQuery STRUCT constructors)
    /// Example: STRUCT(1 AS x, 'hello' AS y)
    AliasedArg {
        /// The value expression
        value: Box<AstExpr>,
        /// Span of the AS keyword
        as_span: Span,
        /// The alias identifier
        alias: AstIdentifier,
    },
    /// T-SQL `OPENROWSET(BULK '<file>', …)` first argument: the `BULK`
    /// identifier prefix immediately followed by the file-path literal, with no
    /// comma between them. The `BULK` form reads a file from the database
    /// server's filesystem — a data-access surface distinct from the
    /// remote-server (provider / connection-string) forms.
    BulkArg {
        /// Span of the `BULK` identifier prefix.
        bulk_span: Span,
        /// The file-path expression (typically a string literal).
        value: Box<AstExpr>,
    },
}

#[derive(Debug, Clone)]
pub struct AstWindowFrame {
    pub node_id: crate::ast::NodeId,
    /// Span covering ROWS or RANGE keyword
    pub kind_span: Span,
    pub kind: AstWindowFrameKind,
    /// Span covering BETWEEN keyword (None if single bound without BETWEEN)
    pub between_span: Option<Span>,
    pub start: AstFrameBound,
    /// Span covering AND keyword between bounds (None if no end bound)
    pub and_span: Option<Span>,
    pub end: Option<AstFrameBound>,
}

#[derive(Debug, Clone)]
pub enum AstWindowFrameKind {
    Rows,
    Range,
}

#[derive(Debug, Clone)]
pub enum AstFrameBoundKind {
    UnboundedPreceding,
    UnboundedFollowing,
    CurrentRow,
    Preceding,
    Following,
}

#[derive(Debug, Clone)]
pub struct AstFrameBound {
    pub node_id: crate::ast::NodeId,
    pub kind: AstFrameBoundKind,
    pub value: Option<Box<AstExpr>>,
    /// Span covering the entire frame bound (e.g., "UNBOUNDED PRECEDING", "CURRENT ROW", "5 FOLLOWING")
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct AstCaseWhen {
    pub node_id: crate::ast::NodeId,
    pub prefix_inline_fragments: Vec<JinjaInlineFragment>,
    pub when_span: Span,
    pub cond: AstExpr,
    pub then_span: Span,
    pub result: AstExpr,
    pub suffix_inline_fragments: Vec<JinjaInlineFragment>,
}

#[derive(Debug, Clone)]
pub enum AstCaseKind {
    Simple,
    Searched,
}

// ============================================================================
// Network Policy Statements
// ============================================================================

/// CREATE [OR REPLACE] NETWORK POLICY [IF NOT EXISTS] name
///   [ALLOWED_NETWORK_RULE_LIST = (...)]
///   [BLOCKED_NETWORK_RULE_LIST = (...)]
///   [ALLOWED_IP_LIST = (...)]
///   [BLOCKED_IP_LIST = (...)]
///   [COMMENT = '...']
#[derive(Debug, Clone)]
pub struct AstCreateNetworkPolicy {
    pub node_id: crate::ast::NodeId,
    /// Span covering the entire CREATE NETWORK POLICY statement
    pub span: Span,
    /// Optional typed-syntax node id for this statement
    pub syntax_id: Option<crate::syntax::SyntaxCreateNetworkPolicyId>,

    // Keyword spans (for semantic tracking and governance)
    pub create_span: Span,
    pub or_replace_span: Option<Span>,
    pub network_span: Span, // NETWORK is Identifier, not Keyword!
    pub policy_span: Span,
    pub if_not_exists_span: Option<Span>,

    /// Span covering the policy name identifier
    pub policy_name_span: Span,

    /// Policy properties (ALLOWED_IP_LIST, BLOCKED_IP_LIST, etc.)
    pub properties: Vec<AstNetworkPolicyProperty>,

    /// Unknown/future properties (defensive design for Snowflake additions)
    pub extras: Vec<AstUnknownClause>,
}

/// `ALTER NETWORK POLICY [IF EXISTS] name <action>`
#[derive(Debug, Clone)]
pub struct AstAlterNetworkPolicy {
    pub node_id: crate::ast::NodeId,
    /// Span covering the entire ALTER NETWORK POLICY statement
    pub span: Span,
    /// Optional typed-syntax node id for this statement
    pub syntax_id: Option<crate::syntax::SyntaxAlterNetworkPolicyId>,

    // Keyword spans
    pub alter_span: Span,
    pub network_span: Span, // NETWORK is Identifier!
    pub policy_span: Span,
    pub if_exists_span: Option<Span>,

    /// Span covering the policy name
    pub name_span: Span,

    /// Span covering the action (everything after the policy name)
    pub action_span: Span,

    /// Parsed action
    pub action: AstAlterNetworkPolicyAction,
}

/// One ALTER NETWORK POLICY action
#[derive(Debug, Clone)]
pub struct AstAlterNetworkPolicyAction {
    pub node_id: crate::ast::NodeId,
    /// Span covering the entire action
    pub span: Span,
    /// Optional typed-syntax node id for this action
    pub syntax_id: Option<crate::syntax::SyntaxAlterNetworkPolicyActionId>,
    pub kind: AstAlterNetworkPolicyActionKind,
}

/// ALTER NETWORK POLICY action kinds
#[derive(Debug, Clone)]
pub enum AstAlterNetworkPolicyActionKind {
    /// SET properties (replaces existing values)
    /// SET ALLOWED_IP_LIST = (...) [BLOCKED_IP_LIST = (...)] [COMMENT = '...']
    Set {
        set_span: Span,
        /// Properties being set
        properties: Vec<AstNetworkPolicyProperty>,
        /// Unknown properties (defensive)
        extras: Vec<AstUnknownClause>,
    },

    /// UNSET COMMENT
    UnsetComment {
        unset_span: Span,
        comment_span: Span,
    },

    /// ADD ALLOWED_NETWORK_RULE_LIST = 'rule' | BLOCKED_NETWORK_RULE_LIST = 'rule'
    /// (PREVIEW feature - additive, not replacing)
    Add {
        add_span: Span, // ADD is Identifier!
        property: AstNetworkPolicyProperty,
    },

    /// REMOVE ALLOWED_NETWORK_RULE_LIST = 'rule' | BLOCKED_NETWORK_RULE_LIST = 'rule'
    /// (PREVIEW feature)
    Remove {
        remove_span: Span, // REMOVE is Identifier!
        property: AstNetworkPolicyProperty,
    },

    /// RENAME TO <new_name>
    RenameTo {
        rename_span: Span,
        to_span: Span,
        new_name_span: Span,
    },

    /// `SET TAG <tag_name> = '<value>' [, ...]`
    SetTag {
        set_span: Span,
        tag_span: Span,
        /// Tag assignments as spans (covers "tag = 'value'" pairs)
        assignments_span: Span,
    },

    /// UNSET TAG <tag_name> [, ...]
    UnsetTag {
        unset_span: Span,
        tag_span: Span,
        /// Tag names to unset (comma-separated spans)
        names_span: Span,
    },
}

/// Network policy property (for CREATE and ALTER SET)
#[derive(Debug, Clone)]
pub struct AstNetworkPolicyProperty {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    pub kind: AstNetworkPolicyPropertyKind,
}

/// Network policy property kinds
#[derive(Debug, Clone)]
pub enum AstNetworkPolicyPropertyKind {
    /// ALLOWED_IP_LIST = ('192.168.1.0/24', '10.0.0.1', ...)
    AllowedIpList {
        property_name_span: Span,
        eq_span: Span,
        /// Span covering the entire list including parentheses
        list_span: Span,
        /// TokenId for the opening paren of the IP list
        lparen_token: Option<crate::cst::TokenId>,
        /// TokenId for the closing paren of the IP list
        rparen_token: Option<crate::cst::TokenId>,
        /// Individual IP address/CIDR string literal spans
        values: Vec<Span>,
    },

    /// BLOCKED_IP_LIST = ('172.16.0.0/12', ...)
    BlockedIpList {
        property_name_span: Span,
        eq_span: Span,
        list_span: Span,
        /// TokenId for the opening paren of the IP list
        lparen_token: Option<crate::cst::TokenId>,
        /// TokenId for the closing paren of the IP list
        rparen_token: Option<crate::cst::TokenId>,
        values: Vec<Span>,
    },

    /// ALLOWED_NETWORK_RULE_LIST = ('rule1', 'rule2', ...)
    AllowedNetworkRuleList {
        property_name_span: Span,
        eq_span: Span,
        list_span: Span,
        /// TokenId for the opening paren of the rule list
        lparen_token: Option<crate::cst::TokenId>,
        /// TokenId for the closing paren of the rule list
        rparen_token: Option<crate::cst::TokenId>,
        /// Network rule name spans (string literals)
        rules: Vec<Span>,
    },

    /// BLOCKED_NETWORK_RULE_LIST = ('rule3', ...)
    BlockedNetworkRuleList {
        property_name_span: Span,
        eq_span: Span,
        list_span: Span,
        /// TokenId for the opening paren of the rule list
        lparen_token: Option<crate::cst::TokenId>,
        /// TokenId for the closing paren of the rule list
        rparen_token: Option<crate::cst::TokenId>,
        rules: Vec<Span>,
    },

    /// COMMENT = 'comment text'
    Comment {
        property_name_span: Span,
        eq_span: Span,
        comment_span: Span,
    },
}

/// DROP NETWORK POLICY [IF EXISTS] name
#[derive(Debug, Clone)]
pub struct AstDropNetworkPolicy {
    pub node_id: crate::ast::NodeId,
    /// Span covering the entire DROP NETWORK POLICY statement
    pub span: Span,
    /// Optional typed-syntax node id for this statement
    pub syntax_id: Option<crate::syntax::SyntaxDropNetworkPolicyId>,

    // Keyword spans
    pub drop_span: Span,
    pub network_span: Span, // NETWORK is Identifier!
    pub policy_span: Span,
    pub if_exists_span: Option<Span>,

    /// Span covering the policy name
    pub policy_name_span: Span,
}

// ============================================================================
// SESSION POLICY - Enterprise Edition feature
// ============================================================================

/// CREATE SESSION POLICY statement.
///
/// Defines idle session timeout periods and secondary role restrictions.
/// SESSION POLICY is an Enterprise Edition feature that controls:
/// - Session idle timeout for Snowflake clients (SESSION_IDLE_TIMEOUT_MINS)
/// - Session idle timeout for Snowsight (SESSION_UI_IDLE_TIMEOUT_MINS)
/// - Allowed secondary roles (ALLOWED_SECONDARY_ROLES)
/// - Blocked secondary roles (BLOCKED_SECONDARY_ROLES)
#[derive(Debug, Clone)]
pub struct AstCreateSessionPolicy {
    pub node_id: crate::ast::NodeId,
    /// Span covering the entire CREATE SESSION POLICY statement
    pub span: Span,
    /// Optional typed-syntax node id for this statement
    pub syntax_id: Option<crate::syntax::SyntaxCreateSessionPolicyId>,

    // Keyword spans (for semantic tracking and governance)
    pub create_span: Span,
    pub or_replace_span: Option<Span>,
    pub if_not_exists_span: Option<Span>,
    pub session_span: Span, // SESSION is a keyword
    pub policy_span: Span,

    /// Span covering the policy name identifier
    pub policy_name_span: Span,

    /// Decomposed properties (name = value triples).
    /// Replaces individual `Option<Span>` fields for each property,
    /// enabling alignment and clean value extraction.
    pub properties: Vec<CreatePolicyProperty>,

    /// Unknown properties not recognized by parser (defensive design).
    ///
    /// When Snowflake adds new SESSION POLICY properties, they are preserved here
    /// instead of causing parse errors. The formatter emits them unchanged,
    /// ensuring semantic preservation even when syntax is unrecognized.
    pub extras: Vec<AstUnknownClause>,
}

/// `ALTER SESSION { SET <param> = <value> [, ...] | UNSET <param> [, ...] }`
/// (Snowflake). Mutates parameters of the current session; distinct from
/// [`AstAlterSessionPolicy`], which alters a named session-policy object.
#[derive(Debug, Clone)]
pub struct AstAlterSession {
    pub node_id: crate::ast::NodeId,
    /// Span covering the entire ALTER SESSION statement.
    pub span: Span,
    /// Span covering the ALTER keyword.
    pub alter_span: Span,
    /// Span covering the SESSION identifier.
    pub session_span: Span,
    /// The SET or UNSET action.
    pub action: AstAlterSessionAction,
}

/// The action of an [`AstAlterSession`] statement.
#[derive(Debug, Clone)]
pub enum AstAlterSessionAction {
    /// `SET <param> = <value> [, <param> = <value> ...]`
    Set {
        set_span: Span,
        params: Vec<AstSessionSetParam>,
    },
    /// `UNSET <param> [, <param> ...]`
    Unset {
        unset_span: Span,
        params: Vec<AstSessionUnsetParam>,
    },
}

/// One `<param> = <value>` assignment in `ALTER SESSION SET`.
#[derive(Debug, Clone)]
pub struct AstSessionSetParam {
    /// Span covering the parameter name.
    pub name_span: Span,
    /// Span covering the `=` operator, if present.
    pub eq_span: Option<Span>,
    /// Span covering the value token.
    pub value_span: Span,
    /// Literal kind of the value, captured from the lexer token (no
    /// downstream text re-classification).
    pub value_kind: AstSessionValueKind,
}

/// One bare `<param>` name in `ALTER SESSION UNSET`.
#[derive(Debug, Clone)]
pub struct AstSessionUnsetParam {
    /// Span covering the parameter name.
    pub name_span: Span,
}

/// Lexical kind of an `ALTER SESSION SET` value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AstSessionValueKind {
    String,
    Number,
    Boolean,
    /// Any other single token (bare identifier, NULL, etc.).
    Other,
}

/// ALTER SESSION POLICY statement.
///
/// Modifies properties of an existing session policy.
/// Includes governance-critical operations like timeout modifications
/// and secondary role restrictions.
#[derive(Debug, Clone)]
pub struct AstAlterSessionPolicy {
    pub node_id: crate::ast::NodeId,
    /// Span covering the entire ALTER SESSION POLICY statement
    pub span: Span,
    /// Optional typed-syntax node id for this statement
    pub syntax_id: Option<crate::syntax::SyntaxAlterSessionPolicyStmtId>,
    /// Span covering the ALTER keyword
    pub alter_span: Span,
    /// Span covering the SESSION keyword
    pub session_span: Span,
    /// Span covering the POLICY keyword
    pub policy_span: Span,
    /// Optional span covering IF EXISTS
    pub if_exists_span: Option<Span>,
    /// Span covering the policy name
    pub name_span: Span,
    /// Span covering the action (everything after the policy name)
    pub action_span: Span,
    /// Parsed actions (SET/UNSET can include multiple properties)
    pub actions: Vec<AstAlterSessionPolicyAction>,
}

/// One ALTER SESSION POLICY action.
#[derive(Debug, Clone)]
pub struct AstAlterSessionPolicyAction {
    pub node_id: crate::ast::NodeId,
    /// Span covering the entire action
    pub span: Span,
    /// Optional typed-syntax node id for this action
    pub syntax_id: Option<crate::syntax::SyntaxAlterSessionPolicyActionId>,
    pub kind: AstAlterSessionPolicyActionKind,
}

/// ALTER SESSION POLICY action kinds.
#[derive(Debug, Clone)]
pub enum AstAlterSessionPolicyActionKind {
    /// RENAME TO <new_name>
    RenameTo {
        rename_span: Option<Span>,
        to_span: Option<Span>,
        new_name_span: Span,
    },

    /// `SET SESSION_IDLE_TIMEOUT_MINS = <integer>`
    SetSessionIdleTimeoutMins {
        set_span: Option<Span>,
        property_span: Span,
        eq_span: Option<Span>,
        value_span: Span,
    },

    /// `SET SESSION_UI_IDLE_TIMEOUT_MINS = <integer>`
    SetSessionUiIdleTimeoutMins {
        set_span: Option<Span>,
        property_span: Span,
        eq_span: Option<Span>,
        value_span: Span,
    },

    /// SET ALLOWED_SECONDARY_ROLES = (...)
    SetAllowedSecondaryRoles {
        set_span: Option<Span>,
        property_span: Span,
        eq_span: Option<Span>,
        roles_spec_span: Span,
        lparen_token: Option<crate::cst::TokenId>,
        rparen_token: Option<crate::cst::TokenId>,
        /// Individual role name spans
        values: Vec<Span>,
    },

    /// SET BLOCKED_SECONDARY_ROLES = (...)
    SetBlockedSecondaryRoles {
        set_span: Option<Span>,
        property_span: Span,
        eq_span: Option<Span>,
        roles_spec_span: Span,
        lparen_token: Option<crate::cst::TokenId>,
        rparen_token: Option<crate::cst::TokenId>,
        /// Individual role name spans
        values: Vec<Span>,
    },

    /// `SET COMMENT = '<string>'`
    SetComment {
        set_span: Option<Span>,
        comment_span: Option<Span>,
        eq_span: Option<Span>,
        comment_value_span: Span,
    },

    /// `SET TAG <tag_name> = '<value>' [, ...]`
    SetTag {
        set_span: Option<Span>,
        tag_span: Option<Span>,
        /// Tag assignments as spans (covers "tag = 'value'" pairs)
        assignments_span: Span,
    },

    /// UNSET SESSION_IDLE_TIMEOUT_MINS
    UnsetSessionIdleTimeoutMins {
        unset_span: Option<Span>,
        property_span: Span,
    },

    /// UNSET SESSION_UI_IDLE_TIMEOUT_MINS
    UnsetSessionUiIdleTimeoutMins {
        unset_span: Option<Span>,
        property_span: Span,
    },

    /// UNSET ALLOWED_SECONDARY_ROLES
    UnsetAllowedSecondaryRoles {
        unset_span: Option<Span>,
        property_span: Span,
    },

    /// UNSET BLOCKED_SECONDARY_ROLES
    UnsetBlockedSecondaryRoles {
        unset_span: Option<Span>,
        property_span: Span,
    },

    /// UNSET COMMENT
    UnsetComment {
        unset_span: Option<Span>,
        comment_span: Option<Span>,
    },

    /// UNSET TAG <tag_name> [, ...]
    UnsetTag {
        unset_span: Option<Span>,
        tag_span: Option<Span>,
        /// Tag names to unset (comma-separated spans)
        tags_span: Span,
    },
}

/// DROP SESSION POLICY statement.
#[derive(Debug, Clone)]
pub struct AstDropSessionPolicy {
    pub node_id: crate::ast::NodeId,
    /// Span covering the entire DROP SESSION POLICY statement
    pub span: Span,
    /// Optional typed-syntax node id for this statement
    pub syntax_id: Option<crate::syntax::SyntaxDropSessionPolicyId>,

    // Keyword spans
    pub drop_span: Span,
    pub session_span: Span,
    pub policy_span: Span,
    pub if_exists_span: Option<Span>,

    /// Span covering the policy name
    pub policy_name_span: Span,
}

// ============================================================================
// AUTHENTICATION POLICY - Account-Level Authentication Controls
// ============================================================================

/// CREATE AUTHENTICATION POLICY statement.
///
/// Creates an authentication policy that controls user authentication methods.
/// Authentication policies enforce:
/// - Allowed authentication methods (PASSWORD, KEYPAIR, SAML, OAUTH, etc.)
/// - Client types (DRIVERS, SNOWFLAKE_UI, SNOWSQL, SNOWPARK_STREAMLIT, etc.)
/// - MFA enrollment requirements (ENFORCED_REQUIRED, ENFORCED_NOT_REQUIRED, NOT_ENFORCED)
/// - MFA policy settings (allowed methods, external authentication enforcement)
/// - PAT (Personal Access Token) policy settings
/// - Workload identity policy settings
/// - Security integration restrictions
///
/// Syntax: CREATE [OR REPLACE] AUTHENTICATION POLICY [IF NOT EXISTS] name
///         [AUTHENTICATION_METHODS = (method [, ...])]
///         [CLIENT_TYPES = (type [, ...])]
///         [CLIENT_POLICY = (driver = (MINIMUM_VERSION = 'version'))]
///         [MFA_ENROLLMENT = enum_value]
///         [MFA_POLICY = (settings)]
///         [PAT_POLICY = (settings)]
///         [WORKLOAD_IDENTITY_POLICY = (settings)]
///         [SECURITY_INTEGRATIONS = (integration [, ...]) | SECURITY_INTEGRATIONS = all | none]
///         [COMMENT = 'string']
#[derive(Debug, Clone)]
pub struct AstCreateAuthenticationPolicy {
    pub node_id: crate::ast::NodeId,
    /// Span covering the entire CREATE AUTHENTICATION POLICY statement
    pub span: Span,
    /// Optional typed-syntax node id for this statement
    pub syntax_id: Option<crate::syntax::SyntaxCreateAuthenticationPolicyId>,

    // Keyword spans (for semantic tracking and governance)
    pub create_span: Span,
    pub or_replace_span: Option<Span>,
    pub or_alter_span: Option<Span>, // CREATE OR ALTER variant
    pub if_not_exists_span: Option<Span>,
    pub authentication_span: Span, // AUTHENTICATION is an Identifier
    pub policy_span: Span,

    /// Span covering the policy name identifier
    pub policy_name_span: Span,

    /// AUTHENTICATION_METHODS = (...)
    pub authentication_methods_span: Option<Span>,

    /// CLIENT_TYPES = (...)
    pub client_types_span: Option<Span>,

    /// CLIENT_POLICY = (...)
    pub client_policy_span: Option<Span>,

    /// MFA_ENROLLMENT = enum_value
    pub mfa_enrollment_span: Option<Span>,

    /// MFA_POLICY = (...)
    pub mfa_policy_span: Option<Span>,

    /// PAT_POLICY = (...)
    pub pat_policy_span: Option<Span>,

    /// WORKLOAD_IDENTITY_POLICY = (...)
    pub workload_identity_policy_span: Option<Span>,

    /// SECURITY_INTEGRATIONS = (...) | all | none
    pub security_integrations_span: Option<Span>,

    /// COMMENT = 'string'
    pub comment_span: Option<Span>,

    /// Unknown properties not recognized by parser (defensive design).
    ///
    /// When Snowflake adds new AUTHENTICATION POLICY properties, they are preserved here
    /// instead of causing parse errors. The formatter emits them unchanged,
    /// ensuring semantic preservation even when syntax is unrecognized.
    pub extras: Vec<AstUnknownClause>,
}

/// ALTER AUTHENTICATION POLICY statement.
///
/// Modifies properties of an existing authentication policy.
/// Includes governance-critical operations like authentication method changes,
/// MFA requirements, and security integration modifications.
#[derive(Debug, Clone)]
pub struct AstAlterAuthenticationPolicy {
    pub node_id: crate::ast::NodeId,
    /// Span covering the entire ALTER AUTHENTICATION POLICY statement
    pub span: Span,
    /// Optional typed-syntax node id for this statement
    pub syntax_id: Option<crate::syntax::SyntaxAlterAuthenticationPolicyStmtId>,
    /// Span covering the ALTER keyword
    pub alter_span: Span,
    /// Span covering the AUTHENTICATION identifier
    pub authentication_span: Span,
    /// Span covering the POLICY keyword
    pub policy_span: Span,
    /// Optional span covering IF EXISTS
    pub if_exists_span: Option<Span>,
    /// Span covering the policy name
    pub name_span: Span,
    /// Span covering the action (everything after the policy name)
    pub action_span: Span,
    /// Parsed action
    pub action: AstAlterAuthenticationPolicyAction,
}

/// One ALTER AUTHENTICATION POLICY action.
#[derive(Debug, Clone)]
pub struct AstAlterAuthenticationPolicyAction {
    pub node_id: crate::ast::NodeId,
    /// Span covering the entire action
    pub span: Span,
    /// Optional typed-syntax node id for this action
    pub syntax_id: Option<crate::syntax::SyntaxAlterAuthenticationPolicyActionId>,
    pub kind: AstAlterAuthenticationPolicyActionKind,
}

/// ALTER AUTHENTICATION POLICY action kinds.
#[derive(Debug, Clone)]
pub enum AstAlterAuthenticationPolicyActionKind {
    /// RENAME TO <new_name>
    RenameTo {
        rename_span: Option<Span>,
        to_span: Option<Span>,
        new_name_span: Span,
    },

    /// SET AUTHENTICATION_METHODS = (...)
    SetAuthenticationMethods {
        set_span: Option<Span>,
        property_span: Span,
        eq_span: Option<Span>,
        value_span: Span,
    },

    /// SET CLIENT_TYPES = (...)
    SetClientTypes {
        set_span: Option<Span>,
        property_span: Span,
        eq_span: Option<Span>,
        value_span: Span,
    },

    /// SET CLIENT_POLICY = (...)
    SetClientPolicy {
        set_span: Option<Span>,
        property_span: Span,
        eq_span: Option<Span>,
        value_span: Span,
    },

    /// SET MFA_ENROLLMENT = enum_value
    SetMfaEnrollment {
        set_span: Option<Span>,
        property_span: Span,
        eq_span: Option<Span>,
        value_span: Span,
    },

    /// SET MFA_POLICY = (...)
    SetMfaPolicy {
        set_span: Option<Span>,
        property_span: Span,
        eq_span: Option<Span>,
        value_span: Span,
    },

    /// SET PAT_POLICY = (...)
    SetPatPolicy {
        set_span: Option<Span>,
        property_span: Span,
        eq_span: Option<Span>,
        value_span: Span,
    },

    /// SET WORKLOAD_IDENTITY_POLICY = (...)
    SetWorkloadIdentityPolicy {
        set_span: Option<Span>,
        property_span: Span,
        eq_span: Option<Span>,
        value_span: Span,
    },

    /// SET SECURITY_INTEGRATIONS = (...) | all | none
    SetSecurityIntegrations {
        set_span: Option<Span>,
        property_span: Span,
        eq_span: Option<Span>,
        value_span: Span,
    },

    /// `SET COMMENT = '<string>'`
    SetComment {
        set_span: Option<Span>,
        property_span: Option<Span>,
        eq_span: Option<Span>,
        value_span: Span,
    },

    /// UNSET AUTHENTICATION_METHODS
    UnsetAuthenticationMethods {
        unset_span: Option<Span>,
        property_span: Span,
    },

    /// UNSET CLIENT_TYPES
    UnsetClientTypes {
        unset_span: Option<Span>,
        property_span: Span,
    },

    /// UNSET CLIENT_POLICY
    UnsetClientPolicy {
        unset_span: Option<Span>,
        property_span: Span,
    },

    /// UNSET MFA_ENROLLMENT
    UnsetMfaEnrollment {
        unset_span: Option<Span>,
        property_span: Span,
    },

    /// UNSET MFA_POLICY
    UnsetMfaPolicy {
        unset_span: Option<Span>,
        property_span: Span,
    },

    /// UNSET PAT_POLICY
    UnsetPatPolicy {
        unset_span: Option<Span>,
        property_span: Span,
    },

    /// UNSET WORKLOAD_IDENTITY_POLICY
    UnsetWorkloadIdentityPolicy {
        unset_span: Option<Span>,
        property_span: Span,
    },

    /// UNSET SECURITY_INTEGRATIONS
    UnsetSecurityIntegrations {
        unset_span: Option<Span>,
        property_span: Span,
    },

    /// UNSET COMMENT
    UnsetComment {
        unset_span: Option<Span>,
        property_span: Option<Span>,
    },
}

// ============================================================================
// ALTER USER / ALTER ACCOUNT — narrow AUTHENTICATION POLICY attachment slice
// ============================================================================
//
// These typed nodes cover ONLY the principal-attachment forms:
//   ALTER USER [IF EXISTS] <name> { SET | UNSET } AUTHENTICATION POLICY [= <policy>]
//   ALTER ACCOUNT          { SET | UNSET } AUTHENTICATION POLICY [= <policy>]
// All other ALTER USER actions continue to route to AlterPrincipal; other
// ALTER ACCOUNT actions fall through to the generic statement path.

/// ALTER USER statement scoped to AUTHENTICATION POLICY attach/detach.
#[derive(Debug, Clone)]
pub struct AstAlterUser {
    pub node_id: crate::ast::NodeId,
    /// Span covering the entire ALTER USER statement
    pub span: Span,
    /// Span of the ALTER keyword
    pub alter_span: Span,
    /// Span of the USER identifier
    pub user_span: Span,
    /// Optional span covering IF EXISTS
    pub if_exists_span: Option<Span>,
    /// Span covering the user name (single-component identifier)
    pub user_name_span: Span,
    /// Parsed action
    pub action: AstAlterUserAction,
}

/// One ALTER USER action.
#[derive(Debug, Clone)]
pub struct AstAlterUserAction {
    pub node_id: crate::ast::NodeId,
    /// Span covering the entire action (SET ... or UNSET ...)
    pub span: Span,
    pub kind: AstAlterUserActionKind,
}

/// ALTER USER action kinds (closed enum).
///
/// Only the AUTHENTICATION POLICY attachment forms are typed here.
#[derive(Debug, Clone)]
pub enum AstAlterUserActionKind {
    /// SET AUTHENTICATION POLICY [=] <policy_name>
    SetAuthenticationPolicy {
        set_span: Span,
        authentication_span: Span,
        policy_span: Span,
        /// Canonical Snowflake syntax has no `=`; present only when written.
        eq_span: Option<Span>,
        policy_name_span: Span,
    },
    /// UNSET AUTHENTICATION POLICY
    UnsetAuthenticationPolicy {
        unset_span: Span,
        authentication_span: Span,
        policy_span: Span,
    },
}

/// ALTER ACCOUNT statement scoped to AUTHENTICATION POLICY attach/detach.
#[derive(Debug, Clone)]
pub struct AstAlterAccount {
    pub node_id: crate::ast::NodeId,
    /// Span covering the entire ALTER ACCOUNT statement
    pub span: Span,
    /// Span of the ALTER keyword
    pub alter_span: Span,
    /// Span of the ACCOUNT identifier
    pub account_span: Span,
    /// Parsed action
    pub action: AstAlterAccountAction,
}

/// One ALTER ACCOUNT action.
#[derive(Debug, Clone)]
pub struct AstAlterAccountAction {
    pub node_id: crate::ast::NodeId,
    /// Span covering the entire action (SET ... or UNSET ...)
    pub span: Span,
    pub kind: AstAlterAccountActionKind,
}

/// ALTER ACCOUNT action kinds (closed enum).
///
/// The AUTHENTICATION POLICY attachment forms are typed structurally; other
/// SET/UNSET property forms (NETWORK_POLICY, DATA_RETENTION_TIME_IN_DAYS,
/// etc.) carry a generic properties span.
#[derive(Debug, Clone)]
pub enum AstAlterAccountActionKind {
    /// SET AUTHENTICATION POLICY [=] <policy_name>
    SetAuthenticationPolicy {
        set_span: Span,
        authentication_span: Span,
        policy_span: Span,
        /// Canonical Snowflake syntax has no `=`; present only when written.
        eq_span: Option<Span>,
        policy_name_span: Span,
    },
    /// UNSET AUTHENTICATION POLICY
    UnsetAuthenticationPolicy {
        unset_span: Span,
        authentication_span: Span,
        policy_span: Span,
    },
    /// `SET <property> = <value> [, ...]` (e.g. NETWORK_POLICY = 'pol',
    /// PERIODIC_DATA_REKEYING = FALSE, DATA_RETENTION_TIME_IN_DAYS = 0)
    Set {
        set_span: Span,
        properties_span: Span,
        /// Typed `<name> = <value>` pairs in declaration order.
        properties: Vec<AstObjectProperty>,
    },
    /// `UNSET <property> [, ...]`
    Unset {
        unset_span: Span,
        properties_span: Span,
        /// Spans of the unset property names.
        property_name_spans: Vec<Span>,
    },
}

/// DROP AUTHENTICATION POLICY statement.
///
/// Removes an authentication policy from the account.
/// This is a governance-critical operation (SNW-AUTHPOL-DROP).
///
/// Syntax: DROP AUTHENTICATION POLICY [IF EXISTS] name
#[derive(Debug, Clone)]
pub struct AstDropAuthenticationPolicy {
    pub node_id: crate::ast::NodeId,
    /// Span covering the entire DROP AUTHENTICATION POLICY statement
    pub span: Span,
    /// Optional typed-syntax node id for this statement
    pub syntax_id: Option<crate::syntax::SyntaxDropAuthenticationPolicyId>,

    // Keyword spans
    pub drop_span: Span,
    pub authentication_span: Span, // AUTHENTICATION is an Identifier
    pub policy_span: Span,
    pub if_exists_span: Option<Span>,

    /// Span covering the policy name
    pub policy_name_span: Span,
}

// ============================================================================
// API INTEGRATION - External API and Git Repository Integration
// ============================================================================

/// CREATE API INTEGRATION statement.
///
/// Creates an API integration for external services or Git repositories.
/// API integrations enable:
/// - External functions via cloud API gateways (AWS, Azure, Google)
/// - Git repository integration for Snowflake features
/// - Authentication and authorization for external services
///
/// Provider types:
/// - aws_api_gateway, aws_private_api_gateway, aws_gov_api_gateway, aws_gov_private_api_gateway
/// - azure_api_management
/// - google_api_gateway
/// - git_https_api
///
/// Syntax:
/// ```text
/// CREATE [OR REPLACE] API INTEGRATION [IF NOT EXISTS] name
///   API_PROVIDER = <provider>  -- Unquoted identifier
///   <provider_specific_props>  -- AWS: API_AWS_ROLE_ARN, Azure: AZURE_TENANT_ID/AZURE_AD_APPLICATION_ID, Google: GOOGLE_AUDIENCE
///   API_ALLOWED_PREFIXES = ('url1' [, 'url2', ...])
///   [API_BLOCKED_PREFIXES = ('url1' [, 'url2', ...])]
///   [API_KEY = 'string']
///   [ENABLED = TRUE | FALSE]
///   [COMMENT = 'string']
///   -- Git-specific properties:
///   [ALLOWED_AUTHENTICATION_SECRETS = (secret_names) | all | none]
///   [API_USER_AUTHENTICATION = (TYPE = snowflake_github_app)]
///   [TLS_TRUSTED_CERTIFICATES = (secret_names)]
///   [USE_PRIVATELINK_ENDPOINT = TRUE | FALSE]
/// ```
#[derive(Debug, Clone)]
pub struct AstCreateApiIntegration {
    pub node_id: crate::ast::NodeId,
    /// Span covering the entire CREATE API INTEGRATION statement
    pub span: Span,
    /// Optional typed-syntax node id for this statement
    pub syntax_id: Option<crate::syntax::SyntaxCreateApiIntegrationId>,

    // Keyword spans (for semantic tracking)
    pub create_span: Span,
    pub or_replace_span: Option<Span>,
    pub if_not_exists_span: Option<Span>,
    pub api_span: Span, // "API" is Identifier, not Keyword!
    pub integration_span: Span,

    /// Span covering the integration name identifier
    pub integration_name_span: Span,

    /// API_PROVIDER = <provider_value>
    /// Provider is an unquoted identifier: aws_api_gateway, azure_api_management, google_api_gateway, git_https_api
    pub api_provider_span: Option<Span>,

    /// AWS-specific: API_AWS_ROLE_ARN = 'arn:...'
    pub api_aws_role_arn_span: Option<Span>,

    /// Azure-specific: AZURE_TENANT_ID = 'uuid'
    pub azure_tenant_id_span: Option<Span>,

    /// Azure-specific: AZURE_AD_APPLICATION_ID = 'uuid'
    pub azure_ad_application_id_span: Option<Span>,

    /// Google-specific: GOOGLE_AUDIENCE = 'url'
    pub google_audience_span: Option<Span>,

    /// API_ALLOWED_PREFIXES = ('url1', 'url2', ...)
    pub api_allowed_prefixes_span: Option<Span>,

    /// API_BLOCKED_PREFIXES = ('url1', 'url2', ...)
    pub api_blocked_prefixes_span: Option<Span>,

    /// API_KEY = 'string'
    pub api_key_span: Option<Span>,

    /// ENABLED = TRUE | FALSE
    pub enabled_span: Option<Span>,

    /// COMMENT = 'string'
    pub comment_span: Option<Span>,

    // Git-specific properties
    /// ALLOWED_AUTHENTICATION_SECRETS = (secret_names) | all | none
    /// Note: "all" is Keyword(All), "none" is Identifier
    pub allowed_authentication_secrets_span: Option<Span>,

    /// API_USER_AUTHENTICATION = (TYPE = snowflake_github_app)
    pub api_user_authentication_span: Option<Span>,

    /// TLS_TRUSTED_CERTIFICATES = (secret_names)
    pub tls_trusted_certificates_span: Option<Span>,

    /// USE_PRIVATELINK_ENDPOINT = TRUE | FALSE
    pub use_privatelink_endpoint_span: Option<Span>,

    /// Unknown properties not recognized by parser (defensive design).
    ///
    /// When Snowflake adds new API integration properties, they are preserved here
    /// instead of causing parse errors. The formatter emits them unchanged,
    /// ensuring semantic preservation even when syntax is unrecognized.
    pub extras: Vec<AstUnknownClause>,
}

/// ALTER API INTEGRATION statement.
///
/// Modifies an existing API integration.
///
/// Syntax variants:
/// - `ALTER [API] INTEGRATION [IF EXISTS] name SET <properties>`
/// - `ALTER [API] INTEGRATION name SET TAG tag_name = 'value' [, ...]`
/// - `ALTER [API] INTEGRATION name UNSET TAG tag_name [, ...]`
/// - `ALTER [API] INTEGRATION [IF EXISTS] name UNSET <properties>`
#[derive(Debug, Clone)]
pub struct AstAlterApiIntegration {
    pub node_id: crate::ast::NodeId,
    /// Span covering the entire ALTER API INTEGRATION statement
    pub span: Span,
    /// Optional typed-syntax node id for this statement
    pub syntax_id: Option<crate::syntax::SyntaxAlterApiIntegrationStmtId>,

    pub alter_span: Span,
    pub api_span: Option<Span>, // Optional "API" keyword (can be omitted)
    pub integration_span: Span,
    pub if_exists_span: Option<Span>,
    pub name_span: Span,

    /// Span covering the entire action clause (SET/UNSET/SET TAG/UNSET TAG)
    pub action_span: Span,

    /// The action(s) being performed (SET, UNSET, SET TAG, UNSET TAG)
    pub actions: Vec<AstAlterApiIntegrationAction>,
}

/// ALTER API INTEGRATION action.
#[derive(Debug, Clone)]
pub struct AstAlterApiIntegrationAction {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    pub syntax_id: Option<crate::syntax::SyntaxAlterApiIntegrationActionId>,
    pub kind: AstAlterApiIntegrationActionKind,
}

/// ALTER API INTEGRATION action kinds.
#[derive(Debug, Clone)]
pub enum AstAlterApiIntegrationActionKind {
    /// SET API_AWS_ROLE_ARN = 'value'
    SetApiAwsRoleArn {
        set_span: Option<Span>,
        property_span: Span,
        eq_span: Option<Span>,
        value_span: Span,
    },

    /// SET AZURE_AD_APPLICATION_ID = 'value'
    SetAzureAdApplicationId {
        set_span: Option<Span>,
        property_span: Span,
        eq_span: Option<Span>,
        value_span: Span,
    },

    /// SET API_KEY = 'value'
    SetApiKey {
        set_span: Option<Span>,
        property_span: Span,
        eq_span: Option<Span>,
        value_span: Span,
    },

    /// SET ENABLED = TRUE | FALSE
    SetEnabled {
        set_span: Option<Span>,
        property_span: Span,
        eq_span: Option<Span>,
        value_span: Span,
    },

    /// SET API_ALLOWED_PREFIXES = ('url1', ...)
    SetApiAllowedPrefixes {
        set_span: Option<Span>,
        property_span: Span,
        eq_span: Option<Span>,
        value_span: Span,
    },

    /// SET API_BLOCKED_PREFIXES = ('url1', ...)
    SetApiBlockedPrefixes {
        set_span: Option<Span>,
        property_span: Span,
        eq_span: Option<Span>,
        value_span: Span,
    },

    /// SET ALLOWED_AUTHENTICATION_SECRETS = (secrets) | all | none
    SetAllowedAuthenticationSecrets {
        set_span: Option<Span>,
        property_span: Span,
        eq_span: Option<Span>,
        value_span: Span,
    },

    /// SET COMMENT = 'value'
    SetComment {
        set_span: Option<Span>,
        comment_span: Span,
        eq_span: Option<Span>,
        value_span: Span,
    },

    /// `SET <property> = <value>` for a property outside the recognized set.
    /// Recognized structurally (property + value spans) without asserting which
    /// known property it is — an unknown property must never be reported as a
    /// specific one such as API_KEY.
    SetOther {
        set_span: Option<Span>,
        property_span: Span,
        eq_span: Option<Span>,
        value_span: Span,
    },

    /// SET TAG tag_name = 'value' [, ...]
    SetTag {
        set_span: Option<Span>,
        tag_span: Option<Span>,
        tags_span: Span, // Covers all tag assignments
    },

    /// UNSET API_KEY
    UnsetApiKey {
        unset_span: Option<Span>,
        property_span: Span,
    },

    /// UNSET ENABLED
    UnsetEnabled {
        unset_span: Option<Span>,
        property_span: Span,
    },

    /// UNSET API_BLOCKED_PREFIXES
    UnsetApiBlockedPrefixes {
        unset_span: Option<Span>,
        property_span: Span,
    },

    /// UNSET COMMENT
    UnsetComment {
        unset_span: Option<Span>,
        comment_span: Span,
    },

    /// UNSET TAG tag_name [, ...]
    UnsetTag {
        unset_span: Option<Span>,
        tag_span: Option<Span>,
        tags_span: Span, // Covers all tag names
    },
}

/// DROP API INTEGRATION statement.
///
/// Removes an API integration from the account.
///
/// Syntax: `DROP [API] INTEGRATION [IF EXISTS] name`
#[derive(Debug, Clone)]
pub struct AstDropApiIntegration {
    pub node_id: crate::ast::NodeId,
    /// Span covering the entire DROP API INTEGRATION statement
    pub span: Span,
    /// Optional typed-syntax node id for this statement
    pub syntax_id: Option<crate::syntax::SyntaxDropApiIntegrationId>,

    // Keyword spans
    pub drop_span: Span,
    pub api_span: Option<Span>, // Optional "API" keyword
    pub integration_span: Span,
    pub if_exists_span: Option<Span>,

    /// Span covering the integration name
    pub integration_name_span: Span,
}

// ============================================================================
// NOTIFICATION INTEGRATION - Snowflake messaging-bus integration
// ============================================================================
//
// Mirrors the API / Storage / External-Access integration AST shape: a
// small set of typed property spans plus an `extras` slot for
// unrecognized clauses, so consumers can read `enabled`, `provider`,
// `direction`, etc. without re-shaping the AST.

/// CREATE NOTIFICATION INTEGRATION statement.
///
/// Syntax:
/// ```text
/// CREATE [OR REPLACE] NOTIFICATION INTEGRATION [IF NOT EXISTS]
///   <name> [ENABLED = ...] [TYPE = ...] [DIRECTION = ...]
///   [NOTIFICATION_PROVIDER = ...] [<provider-specific props>]
///   [COMMENT = ...]
/// ```
///
/// Token reference:
/// - `NOTIFICATION` is `Keyword::Notification`
/// - `INTEGRATION` is `Keyword::Integration`
/// - `TYPE` is `Keyword::Type`
/// - `COMMENT` is `Keyword::Comment`
/// - All other property names (`ENABLED`, `DIRECTION`,
///   `NOTIFICATION_PROVIDER`, `AWS_SNS_TOPIC_ARN`, …) are unquoted
///   `Identifier` tokens.
#[derive(Debug, Clone)]
pub struct AstCreateNotificationIntegration {
    pub node_id: crate::ast::NodeId,
    /// Span covering the entire CREATE NOTIFICATION INTEGRATION statement
    pub span: Span,

    pub create_span: Span,
    pub or_replace_span: Option<Span>,
    pub if_not_exists_span: Option<Span>,
    pub notification_span: Span,
    pub integration_span: Span,

    /// Span covering the integration name (possibly qualified).
    pub integration_name_span: Span,

    /// `ENABLED = TRUE | FALSE`
    pub enabled_span: Option<Span>,
    /// `TYPE = QUEUE | EMAIL | WEBHOOK`
    pub type_span: Option<Span>,
    /// `DIRECTION = INBOUND | OUTBOUND`
    pub direction_span: Option<Span>,
    /// `NOTIFICATION_PROVIDER = AWS_SNS | AZURE_EVENT_GRID | GCP_PUBSUB`
    pub notification_provider_span: Option<Span>,
    /// `COMMENT = '...'`
    pub comment_span: Option<Span>,

    /// Unrecognized properties preserved by the defensive-design path.
    /// Provider-specific properties (`AWS_SNS_TOPIC_ARN`,
    /// `AZURE_STORAGE_QUEUE_PRIMARY_URI`, `WEBHOOK_URL`, …) are
    /// captured here today and may be promoted to typed slots when a
    /// consumer needs them.
    pub extras: Vec<AstUnknownClause>,
}

/// ALTER NOTIFICATION INTEGRATION statement.
///
/// Syntax variants:
/// - `ALTER NOTIFICATION INTEGRATION [IF EXISTS] <name> SET <property>`
/// - `ALTER NOTIFICATION INTEGRATION <name> UNSET <property>`
/// - `ALTER NOTIFICATION INTEGRATION <name> SET TAG t1 = '...' [, ...]`
/// - `ALTER NOTIFICATION INTEGRATION <name> UNSET TAG t1 [, ...]`
/// - `ALTER NOTIFICATION INTEGRATION <name> RENAME TO <new_name>`
#[derive(Debug, Clone)]
pub struct AstAlterNotificationIntegration {
    pub node_id: crate::ast::NodeId,
    pub span: Span,

    pub alter_span: Span,
    pub notification_span: Span,
    pub integration_span: Span,
    pub if_exists_span: Option<Span>,
    pub name_span: Span,

    pub actions: Vec<AstAlterNotificationIntegrationAction>,
}

#[derive(Debug, Clone)]
pub struct AstAlterNotificationIntegrationAction {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    pub kind: AstAlterNotificationIntegrationActionKind,
}

#[derive(Debug, Clone)]
pub enum AstAlterNotificationIntegrationActionKind {
    /// `SET ENABLED = TRUE | FALSE`
    SetEnabled {
        set_span: Span,
        property_span: Span,
        eq_span: Span,
        value_span: Span,
    },
    /// `UNSET ENABLED`
    UnsetEnabled {
        unset_span: Span,
        property_span: Span,
    },
    /// `SET COMMENT = '...'`
    SetComment {
        set_span: Span,
        comment_span: Span,
        eq_span: Span,
        value_span: Span,
    },
    /// `UNSET COMMENT`
    UnsetComment {
        unset_span: Span,
        comment_span: Span,
    },
    /// `SET TAG <name> = '<value>' [, …]`
    SetTag {
        set_span: Span,
        tag_span: Span,
        /// Span over the comma-separated tag assignments.
        tags_span: Span,
    },
    /// `UNSET TAG <name> [, …]`
    UnsetTag {
        unset_span: Span,
        tag_span: Span,
        tags_span: Span,
    },
    /// `RENAME TO <new_name>`
    Rename {
        rename_span: Span,
        to_span: Span,
        new_name_span: Span,
    },
    /// `SET <unknown_property> = <value>` — generic property setter
    /// preserved for forward compatibility. Exposes the property-name
    /// span so consumers can read the name text.
    SetOther {
        set_span: Span,
        property_span: Span,
        eq_span: Span,
        value_span: Span,
    },
    /// `UNSET <unknown_property>` — generic.
    UnsetOther {
        unset_span: Span,
        property_span: Span,
    },
}

/// CREATE SHARE statement (Snowflake).
///
/// Syntax: `CREATE [OR REPLACE] SHARE [IF NOT EXISTS] <name> [COMMENT = '<text>']`
///
/// SHARE creates a data-sharing object that consumer accounts can mount.
/// The accounts list is bound separately via `ALTER SHARE … ADD ACCOUNTS = …`
/// (see [`AstAlterShare`]).
#[derive(Debug, Clone)]
pub struct AstCreateShare {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    pub create_span: Span,
    pub or_replace_span: Option<Span>,
    pub share_span: Span,
    pub if_not_exists_span: Option<Span>,
    pub name_span: Span,
    pub comment_span: Option<Span>,
}

/// ALTER SHARE statement (Snowflake).
///
/// Syntax variants:
/// - `ALTER SHARE [IF EXISTS] <name> ADD ACCOUNTS = <account_list>`
/// - `ALTER SHARE [IF EXISTS] <name> REMOVE ACCOUNTS = <account_list>`
/// - `ALTER SHARE [IF EXISTS] <name> SET ACCOUNTS = <account_list>`
/// - `ALTER SHARE [IF EXISTS] <name> SET <property> = <value>`
/// - `ALTER SHARE [IF EXISTS] <name> UNSET <property>`
#[derive(Debug, Clone)]
pub struct AstAlterShare {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    pub alter_span: Span,
    pub share_span: Span,
    pub if_exists_span: Option<Span>,
    pub name_span: Span,
    pub action: AstAlterShareAction,
}

#[derive(Debug, Clone)]
pub struct AstAlterShareAction {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    pub kind: AstAlterShareActionKind,
}

#[derive(Debug, Clone)]
pub enum AstAlterShareActionKind {
    /// ADD ACCOUNTS = <account_list>
    AddAccounts {
        add_span: Span,
        accounts_span: Span,
        account_list_span: Span,
    },
    /// REMOVE ACCOUNTS = <account_list>
    RemoveAccounts {
        remove_span: Span,
        accounts_span: Span,
        account_list_span: Span,
    },
    /// SET ACCOUNTS = <account_list>
    SetAccounts {
        set_span: Span,
        accounts_span: Span,
        account_list_span: Span,
    },
    /// `SET <property> = <value> [, ...]` (generic catch-all)
    Set {
        set_span: Span,
        properties_span: Span,
    },
    /// `UNSET <property> [, ...]`
    Unset {
        unset_span: Span,
        properties_span: Span,
    },
    /// Unrecognized action (defensive)
    Unknown(AstUnknownClause),
}

/// CREATE DATASHARE statement (Amazon Redshift).
///
/// `CREATE DATASHARE <name> [SET PUBLICACCESSIBLE [=] TRUE|FALSE] [MANAGEDBY …]`
///
/// A datashare is the cross-account/-cluster data-sharing object; producer
/// clusters add tables/schemas to it (via [`AstAlterDatashare`]) and grant
/// USAGE to consumer namespaces or AWS accounts. Distinct from the Snowflake
/// SHARE object — the cross-account exposure semantics differ, so it is
/// a distinct node.
#[derive(Debug, Clone)]
pub struct AstCreateDatashare {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    pub create_span: Span,
    pub or_replace_span: Option<Span>,
    pub datashare_span: Span,
    pub if_not_exists_span: Option<Span>,
    pub name_span: Span,
    /// `SET PUBLICACCESSIBLE [=] TRUE|FALSE` on the CREATE form — Some(value) when present.
    pub publicly_accessible: Option<bool>,
}

/// ALTER DATASHARE statement (Amazon Redshift).
///
/// Syntax variants:
/// - `ALTER DATASHARE <name> ADD { TABLE | SCHEMA } <object>`
/// - `ALTER DATASHARE <name> REMOVE { TABLE | SCHEMA } <object>`
/// - `ALTER DATASHARE <name> SET PUBLICACCESSIBLE [=] TRUE|FALSE`
/// - `ALTER DATASHARE <name> SET INCLUDENEW [=] TRUE|FALSE FOR SCHEMA <schema>`
#[derive(Debug, Clone)]
pub struct AstAlterDatashare {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    pub alter_span: Span,
    pub datashare_span: Span,
    pub name_span: Span,
    pub action: AstAlterDatashareAction,
}

#[derive(Debug, Clone)]
pub struct AstAlterDatashareAction {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    pub kind: AstAlterDatashareActionKind,
}

/// Object kind referenced by an ADD/REMOVE datashare action. Closed enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AstDatashareObjectKind {
    /// `ADD/REMOVE TABLE <name>`
    Table,
    /// `ADD/REMOVE SCHEMA <name>`
    Schema,
}

#[derive(Debug, Clone)]
pub enum AstAlterDatashareActionKind {
    /// `ADD { TABLE | SCHEMA } <object>`
    AddObject {
        add_span: Span,
        object_kind: AstDatashareObjectKind,
        object_kind_span: Span,
        name_span: Span,
    },
    /// `REMOVE { TABLE | SCHEMA } <object>`
    RemoveObject {
        remove_span: Span,
        object_kind: AstDatashareObjectKind,
        object_kind_span: Span,
        name_span: Span,
    },
    /// SET PUBLICACCESSIBLE [=] TRUE|FALSE
    SetPublicAccessible {
        set_span: Span,
        property_span: Span,
        value_span: Span,
        value: bool,
    },
    /// `SET INCLUDENEW [=] TRUE|FALSE FOR SCHEMA <schema>`
    SetIncludeNew {
        set_span: Span,
        property_span: Span,
        value_span: Span,
        value: bool,
        schema_span: Option<Span>,
    },
    /// `SET <other property> …` (generic catch-all)
    SetProperty {
        set_span: Span,
        properties_span: Span,
    },
    /// Unrecognized action (defensive)
    Unknown(AstUnknownClause),
}

/// CREATE SECURITY INTEGRATION statement (Snowflake).
///
/// Syntax: `CREATE [OR REPLACE] SECURITY INTEGRATION [IF NOT EXISTS] <name>
///   TYPE = <type>
///   ENABLED = TRUE|FALSE
///   <type_specific_properties>
///   [COMMENT = '<text>']`
///
/// `TYPE` is OAUTH | EXTERNAL_OAUTH | SAML2 | SCIM and is the discriminant
/// for the type-specific property set (OAUTH_CLIENT, OAUTH_REDIRECT_URI,
/// SAML2_ISSUER, etc.). `TYPE` and `ENABLED` are typed slots because they
/// are universal and security-critical (consumers need them without
/// parsing the body). The remaining properties are captured as
/// an opaque `properties_span` for forward compatibility.
#[derive(Debug, Clone)]
pub struct AstCreateSecurityIntegration {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    pub create_span: Span,
    pub or_replace_span: Option<Span>,
    pub if_not_exists_span: Option<Span>,
    pub security_span: Span,
    pub integration_span: Span,
    pub name_span: Span,
    /// Every `<name> [= <value>]` property in declaration order,
    /// including TYPE / ENABLED / COMMENT (which also keep their
    /// dedicated spans below).
    pub properties: Vec<AstObjectProperty>,
    /// `TYPE = <value>` — span covers keyword through value.
    pub type_span: Option<Span>,
    /// `TYPE = <value>` — span covers just the value (e.g. `OAUTH`).
    pub type_value_span: Option<Span>,
    /// `ENABLED = TRUE|FALSE` — span covers keyword through value.
    pub enabled_span: Option<Span>,
    /// `ENABLED = TRUE|FALSE` — span covers just the value.
    pub enabled_value_span: Option<Span>,
    /// `COMMENT = '<text>'` — span covers keyword through value.
    pub comment_span: Option<Span>,
    /// Span covering all post-name property tokens except TYPE / ENABLED /
    /// COMMENT (which have their own typed slots). Empty if no other
    /// properties. Treated as opaque for downstream analysis.
    pub properties_span: Option<Span>,
}

/// ALTER SECURITY INTEGRATION statement (Snowflake).
///
/// Syntax: `ALTER SECURITY INTEGRATION [IF EXISTS] <name> { SET | UNSET } <props>`
#[derive(Debug, Clone)]
pub struct AstAlterSecurityIntegration {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    pub alter_span: Span,
    pub security_span: Span,
    pub integration_span: Span,
    pub if_exists_span: Option<Span>,
    pub name_span: Span,
    pub action: AstAlterSecurityIntegrationAction,
}

#[derive(Debug, Clone)]
pub struct AstAlterSecurityIntegrationAction {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    pub kind: AstAlterSecurityIntegrationActionKind,
}

/// One `<name> [= <value>]` property in a security-integration body.
/// `value_span` is `None` when the property appears without `=`.
#[derive(Debug, Clone)]
pub struct AstObjectProperty {
    pub name_span: Span,
    pub value_span: Option<Span>,
}

#[derive(Debug, Clone)]
pub enum AstAlterSecurityIntegrationActionKind {
    /// `SET <property> = <value> [, ...]`
    Set {
        set_span: Span,
        properties_span: Span,
        /// Parsed `<name> = <value>` pairs within the SET body.
        properties: Vec<AstObjectProperty>,
    },
    /// `UNSET <property> [, ...]`
    Unset {
        unset_span: Span,
        properties_span: Span,
        /// Spans of the property names being unset.
        property_name_spans: Vec<Span>,
    },
    /// RENAME TO <new_name>
    Rename {
        rename_span: Span,
        to_span: Span,
        new_name_span: Span,
    },
    /// Unrecognized action (defensive)
    Unknown(AstUnknownClause),
}

/// CREATE NETWORK RULE statement (Snowflake).
///
/// Syntax:
/// ```text
/// CREATE [OR REPLACE] NETWORK RULE [IF NOT EXISTS] <name>
///   TYPE = {IPV4 | IPV6 | AWSVPCEID | AZURELINKID | GCPPSCID | HOST_PORT | PRIVATE_HOST_PORT | COMPUTE_POOL}
///   VALUE_LIST = ('<v>' [, ...])
///   MODE = {INGRESS | INTERNAL_STAGE | SNOWFLAKE_MANAGED_STORAGE_VOLUME | EGRESS}
///   [COMMENT = '<string>']
/// ```
#[derive(Debug, Clone)]
pub struct AstCreateNetworkRule {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    pub create_span: Span,
    pub or_replace_span: Option<Span>,
    pub network_span: Span,
    pub rule_span: Span,
    pub if_not_exists_span: Option<Span>,
    pub name_span: Span,
    /// Every `<name> [= <value>]` property in declaration order.
    pub properties: Vec<AstObjectProperty>,
    /// `TYPE = <value>` — span covers just the value.
    pub type_value_span: Option<Span>,
    /// `MODE = <value>` — span covers just the value.
    pub mode_value_span: Option<Span>,
    /// `VALUE_LIST = (…)` — span covers the parenthesized list.
    pub value_list_span: Option<Span>,
    /// `COMMENT = '<text>'` — span covers keyword through value.
    pub comment_span: Option<Span>,
}

/// ALTER NETWORK RULE statement (Snowflake).
///
/// Syntax: `ALTER NETWORK RULE [IF EXISTS] <name> { SET <props> | UNSET <prop> [, …] }`
#[derive(Debug, Clone)]
pub struct AstAlterNetworkRule {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    pub alter_span: Span,
    pub network_span: Span,
    pub rule_span: Span,
    pub if_exists_span: Option<Span>,
    pub name_span: Span,
    pub action: AstAlterNetworkRuleAction,
}

#[derive(Debug, Clone)]
pub struct AstAlterNetworkRuleAction {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    pub kind: AstAlterNetworkRuleActionKind,
}

#[derive(Debug, Clone)]
pub enum AstAlterNetworkRuleActionKind {
    /// `SET <property> = <value> [...]`
    Set {
        set_span: Span,
        properties: Vec<AstObjectProperty>,
    },
    /// `UNSET <property> [, ...]`
    Unset {
        unset_span: Span,
        property_name_spans: Vec<Span>,
    },
}

/// CREATE RESOURCE MONITOR statement (Snowflake).
///
/// Syntax:
/// ```text
/// CREATE [OR REPLACE] RESOURCE MONITOR [IF NOT EXISTS] <name> WITH
///   [CREDIT_QUOTA = <num>] [FREQUENCY = {MONTHLY|DAILY|WEEKLY|YEARLY|NEVER}]
///   [START_TIMESTAMP = {<ts>|IMMEDIATELY}] [END_TIMESTAMP = <ts>]
///   [NOTIFY_USERS = (<user> [, ...])]
///   [TRIGGERS ON <pct> PERCENT DO {SUSPEND|SUSPEND_IMMEDIATE|NOTIFY} [...]]
/// ```
#[derive(Debug, Clone)]
pub struct AstCreateResourceMonitor {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    pub create_span: Span,
    pub or_replace_span: Option<Span>,
    pub resource_span: Span,
    pub monitor_span: Span,
    pub if_not_exists_span: Option<Span>,
    pub name_span: Span,
    /// `WITH` keyword span (optional in Snowflake's grammar).
    pub with_span: Option<Span>,
    /// Every `<name> [= <value>]` property before the TRIGGERS clause.
    pub properties: Vec<AstObjectProperty>,
    /// `CREDIT_QUOTA = <value>` — span covers just the value.
    pub credit_quota_span: Option<Span>,
    /// `FREQUENCY = <value>` — span covers just the value.
    pub frequency_value_span: Option<Span>,
    /// `NOTIFY_USERS = (…)` — span covers the parenthesized list.
    pub notify_users_span: Option<Span>,
    /// `TRIGGERS ON <pct> PERCENT DO <action>` definitions in order.
    pub triggers: Vec<AstResourceMonitorTrigger>,
}

/// A single `ON <pct> PERCENT DO <action>` resource-monitor trigger.
#[derive(Debug, Clone)]
pub struct AstResourceMonitorTrigger {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    pub on_span: Span,
    /// The `<pct>` numeric literal span.
    pub threshold_span: Span,
    pub percent_span: Span,
    pub do_span: Span,
    /// `{SUSPEND | SUSPEND_IMMEDIATE | NOTIFY}` action span.
    pub action_span: Span,
}

/// ALTER RESOURCE MONITOR statement (Snowflake).
///
/// Syntax: `ALTER RESOURCE MONITOR [IF EXISTS] <name> SET <props> [TRIGGERS …]`.
/// Snowflake exposes only a `SET` action for resource monitors.
#[derive(Debug, Clone)]
pub struct AstAlterResourceMonitor {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    pub alter_span: Span,
    pub resource_span: Span,
    pub monitor_span: Span,
    pub if_exists_span: Option<Span>,
    pub name_span: Span,
    pub set_span: Span,
    pub properties: Vec<AstObjectProperty>,
    pub credit_quota_span: Option<Span>,
    pub frequency_value_span: Option<Span>,
    pub notify_users_span: Option<Span>,
    pub triggers: Vec<AstResourceMonitorTrigger>,
    /// A `TRIGGERS` clause was present in the SET body.
    pub triggers_present: bool,
}

/// CREATE COMPUTE POOL statement (Snowflake / Snowpark Container Services).
///
/// Syntax:
/// ```text
/// CREATE COMPUTE POOL [IF NOT EXISTS] <name>
///   MIN_NODES = <n> MAX_NODES = <n> INSTANCE_FAMILY = <family>
///   [AUTO_RESUME = {TRUE|FALSE}] [AUTO_SUSPEND_SECS = <n>]
///   [INITIALLY_SUSPENDED = {TRUE|FALSE}] [COMMENT = '<text>']
/// ```
#[derive(Debug, Clone)]
pub struct AstCreateComputePool {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    pub create_span: Span,
    /// Optional `OR REPLACE` span (Snowflake).
    pub or_replace_span: Option<Span>,
    pub compute_span: Span,
    pub pool_span: Span,
    pub if_not_exists_span: Option<Span>,
    pub name_span: Span,
    /// Every `<name> = <value>` property in the bag.
    pub properties: Vec<AstObjectProperty>,
    /// `INSTANCE_FAMILY = <family>` value span.
    pub instance_family_span: Option<Span>,
    /// `AUTO_RESUME = {TRUE|FALSE}` value span.
    pub auto_resume_span: Option<Span>,
    /// `MIN_NODES = <n>` value span.
    pub min_nodes_span: Option<Span>,
    /// `MAX_NODES = <n>` value span.
    pub max_nodes_span: Option<Span>,
}

/// The action clause of an `ALTER COMPUTE POOL` statement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AstComputePoolAction {
    /// `SET <props>`
    Set,
    /// `UNSET <props>`
    Unset,
    /// `SUSPEND`
    Suspend,
    /// `RESUME`
    Resume,
    /// `STOP ALL`
    StopAll,
}

/// ALTER COMPUTE POOL statement (Snowflake).
///
/// Syntax:
/// ```text
/// ALTER COMPUTE POOL [IF EXISTS] <name>
///   { SET <props> | UNSET <props> | SUSPEND | RESUME | STOP ALL }
/// ```
#[derive(Debug, Clone)]
pub struct AstAlterComputePool {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    pub alter_span: Span,
    pub compute_span: Span,
    pub pool_span: Span,
    pub if_exists_span: Option<Span>,
    pub name_span: Span,
    pub action: AstComputePoolAction,
    /// Properties supplied to a `SET` action (empty otherwise).
    pub properties: Vec<AstObjectProperty>,
    /// `INSTANCE_FAMILY = <family>` value span (SET only).
    pub instance_family_span: Option<Span>,
    /// `AUTO_RESUME = {TRUE|FALSE}` value span (SET only).
    pub auto_resume_span: Option<Span>,
}

/// CREATE GIT REPOSITORY statement (Snowflake).
///
/// Syntax:
/// ```text
/// CREATE [OR REPLACE] GIT REPOSITORY [IF NOT EXISTS] <name>
///   API_INTEGRATION = <integration> ORIGIN = '<url>'
///   [GIT_CREDENTIALS = <secret>] [COMMENT = '<text>']
/// ```
#[derive(Debug, Clone)]
pub struct AstCreateGitRepository {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    pub create_span: Span,
    pub or_replace_span: Option<Span>,
    pub git_span: Span,
    pub repository_span: Span,
    pub if_not_exists_span: Option<Span>,
    pub name_span: Span,
    /// Every `<name> = <value>` property in the bag.
    pub properties: Vec<AstObjectProperty>,
    /// `API_INTEGRATION = <integration>` value span.
    pub api_integration_span: Option<Span>,
    /// `ORIGIN = '<url>'` value span — the external git remote.
    pub origin_span: Option<Span>,
    /// `GIT_CREDENTIALS = <secret>` value span (a secret reference).
    pub git_credentials_span: Option<Span>,
}

/// The action clause of an `ALTER GIT REPOSITORY` statement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AstGitRepositoryAction {
    /// `SET <props>`
    Set,
    /// `UNSET <props>`
    Unset,
    /// `FETCH` — re-pull the latest content from the external origin.
    Fetch,
}

/// ALTER GIT REPOSITORY statement (Snowflake).
///
/// Syntax:
/// ```text
/// ALTER GIT REPOSITORY [IF EXISTS] <name>
///   { SET <props> | UNSET <props> | FETCH }
/// ```
#[derive(Debug, Clone)]
pub struct AstAlterGitRepository {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    pub alter_span: Span,
    pub git_span: Span,
    pub repository_span: Span,
    pub if_exists_span: Option<Span>,
    pub name_span: Span,
    pub action: AstGitRepositoryAction,
    /// Properties supplied to a `SET` action (empty otherwise).
    pub properties: Vec<AstObjectProperty>,
    /// `API_INTEGRATION = <integration>` value span (SET only).
    pub api_integration_span: Option<Span>,
    /// `GIT_CREDENTIALS = <secret>` value span (SET only).
    pub git_credentials_span: Option<Span>,
}

/// CREATE IMAGE REPOSITORY statement (Snowflake Snowpark Container Services).
///
/// Syntax:
/// ```text
/// CREATE [OR REPLACE] IMAGE REPOSITORY [IF NOT EXISTS] <name>
///   [COMMENT = '<text>'] [[WITH] TAG (...)]
/// ```
///
/// An image repository is an OCI registry that container services pull images
/// from. It has no governance value-slots (only COMMENT / TAG); recognition is
/// its existence and whether it replaces an existing registry (`or_replace`).
#[derive(Debug, Clone)]
pub struct AstCreateImageRepository {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    pub create_span: Span,
    pub or_replace_span: Option<Span>,
    pub image_span: Span,
    pub repository_span: Span,
    pub if_not_exists_span: Option<Span>,
    pub name_span: Span,
    /// Every `<name> = <value>` property in the bag (COMMENT / TAG).
    pub properties: Vec<AstObjectProperty>,
}

/// The action clause of an `ALTER IMAGE REPOSITORY` statement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AstImageRepositoryAction {
    /// `SET <props>`
    Set,
    /// `UNSET <props>`
    Unset,
}

/// ALTER IMAGE REPOSITORY statement (Snowflake).
///
/// Syntax: `ALTER IMAGE REPOSITORY [IF EXISTS] <name> { SET <props> | UNSET <props> }`
#[derive(Debug, Clone)]
pub struct AstAlterImageRepository {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    pub alter_span: Span,
    pub image_span: Span,
    pub repository_span: Span,
    pub if_exists_span: Option<Span>,
    pub name_span: Span,
    pub action: AstImageRepositoryAction,
    /// Properties supplied to a `SET` action (empty otherwise).
    pub properties: Vec<AstObjectProperty>,
}

/// CREATE STREAMLIT statement (Snowflake).
///
/// Syntax:
/// ```text
/// CREATE [OR REPLACE] STREAMLIT [IF NOT EXISTS] <name>
///   ROOT_LOCATION = '<stage_path>' MAIN_FILE = '<file>'
///   [QUERY_WAREHOUSE = <wh>] [EXTERNAL_ACCESS_INTEGRATIONS = (...)] ...
/// ```
///
/// A Streamlit object runs a Python app from a stage location. The
/// recognition surface is whether it declares EXTERNAL_ACCESS_INTEGRATIONS
/// (network egress); the rest of the bag is free-form name=value.
#[derive(Debug, Clone)]
pub struct AstCreateStreamlit {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    pub create_span: Span,
    pub or_replace_span: Option<Span>,
    pub streamlit_span: Span,
    pub if_not_exists_span: Option<Span>,
    pub name_span: Span,
    /// Every `<name> = <value>` property in the bag.
    pub properties: Vec<AstObjectProperty>,
    /// `EXTERNAL_ACCESS_INTEGRATIONS = (...)` value span when present.
    pub external_access_integrations_span: Option<Span>,
}

/// The action clause of an `ALTER STREAMLIT` statement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AstStreamlitAction {
    /// `SET <props>`
    Set,
    /// `UNSET <props>`
    Unset,
}

/// ALTER STREAMLIT statement (Snowflake).
///
/// Syntax: `ALTER STREAMLIT [IF EXISTS] <name> { SET <props> | UNSET <props> }`
#[derive(Debug, Clone)]
pub struct AstAlterStreamlit {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    pub alter_span: Span,
    pub streamlit_span: Span,
    pub if_exists_span: Option<Span>,
    pub name_span: Span,
    pub action: AstStreamlitAction,
    /// Properties supplied to a `SET` action (empty otherwise).
    pub properties: Vec<AstObjectProperty>,
    /// `EXTERNAL_ACCESS_INTEGRATIONS = (...)` value span (SET only).
    pub external_access_integrations_span: Option<Span>,
}

/// CREATE SERVICE statement (Snowflake Snowpark Container Services).
///
/// Syntax:
/// ```text
/// CREATE [OR REPLACE] SERVICE [IF NOT EXISTS] <name>
///   IN COMPUTE POOL <pool>
///   { FROM SPECIFICATION <$$…$$ | '…'> | FROM @<stage> SPECIFICATION_FILE = … }
///   [EXTERNAL_ACCESS_INTEGRATIONS = (...)] [AUTO_RESUME = …] [MIN_INSTANCES = …] …
/// ```
///
/// A service runs container workloads on a compute pool. The inline
/// `FROM SPECIFICATION $$…$$` body is YAML — captured for span coverage but not
/// analyzed (it is not SQL). Governance recognition: the compute-pool binding
/// and whether it declares EXTERNAL_ACCESS_INTEGRATIONS (network egress).
#[derive(Debug, Clone)]
pub struct AstCreateService {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    pub create_span: Span,
    pub or_replace_span: Option<Span>,
    pub service_span: Span,
    pub if_not_exists_span: Option<Span>,
    pub name_span: Span,
    /// The `<pool>` name in `IN COMPUTE POOL <pool>` when present.
    pub compute_pool_span: Option<Span>,
    /// Trailing `<name> = <value>` properties (after the FROM clause).
    pub properties: Vec<AstObjectProperty>,
    /// `EXTERNAL_ACCESS_INTEGRATIONS = (...)` value span when present.
    pub external_access_integrations_span: Option<Span>,
}

/// The action clause of an `ALTER SERVICE` statement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AstServiceAction {
    /// `SET <props>`
    Set,
    /// `UNSET <props>`
    Unset,
    /// `RESUME` — starts the service (resumes billing).
    Resume,
    /// `SUSPEND` — stops the service.
    Suspend,
}

/// ALTER SERVICE statement (Snowflake).
///
/// Syntax:
/// ```text
/// ALTER SERVICE [IF EXISTS] <name>
///   { SET <props> | UNSET <props> | RESUME | SUSPEND }
/// ```
#[derive(Debug, Clone)]
pub struct AstAlterService {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    pub alter_span: Span,
    pub service_span: Span,
    pub if_exists_span: Option<Span>,
    pub name_span: Span,
    pub action: AstServiceAction,
    /// Properties supplied to a `SET` action (empty otherwise).
    pub properties: Vec<AstObjectProperty>,
    /// `EXTERNAL_ACCESS_INTEGRATIONS = (...)` value span (SET only).
    pub external_access_integrations_span: Option<Span>,
}

/// CREATE NOTEBOOK statement (Snowflake).
///
/// Syntax:
/// ```text
/// CREATE [OR REPLACE] NOTEBOOK [IF NOT EXISTS] <name>
///   [FROM '<stage_path>'] [MAIN_FILE = '<file>'] [QUERY_WAREHOUSE = <wh>]
///   [EXTERNAL_ACCESS_INTEGRATIONS = (...)] [COMMENT = '<text>'] …
/// ```
///
/// A notebook runs code from a stage location. The optional `FROM '<path>'`
/// clause has no `$$` body, so it is absorbed by the trailing property walk.
/// Governance recognition: whether it declares EXTERNAL_ACCESS_INTEGRATIONS
/// (network egress).
#[derive(Debug, Clone)]
pub struct AstCreateNotebook {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    pub create_span: Span,
    pub or_replace_span: Option<Span>,
    pub notebook_span: Span,
    pub if_not_exists_span: Option<Span>,
    pub name_span: Span,
    /// Every `<name> [= <value>]` property in the bag (incl. the absorbed
    /// `FROM '<path>'` clause).
    pub properties: Vec<AstObjectProperty>,
    /// `EXTERNAL_ACCESS_INTEGRATIONS = (...)` value span when present.
    pub external_access_integrations_span: Option<Span>,
}

/// The action clause of an `ALTER NOTEBOOK` statement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AstNotebookAction {
    /// `SET <props>`
    Set,
    /// `UNSET <props>`
    Unset,
}

/// ALTER NOTEBOOK statement (Snowflake).
///
/// Syntax: `ALTER NOTEBOOK [IF EXISTS] <name> { SET <props> | UNSET <props> }`
#[derive(Debug, Clone)]
pub struct AstAlterNotebook {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    pub alter_span: Span,
    pub notebook_span: Span,
    pub if_exists_span: Option<Span>,
    pub name_span: Span,
    pub action: AstNotebookAction,
    /// Properties supplied to a `SET` action (empty otherwise).
    pub properties: Vec<AstObjectProperty>,
    /// `EXTERNAL_ACCESS_INTEGRATIONS = (...)` value span (SET only).
    pub external_access_integrations_span: Option<Span>,
}

/// One entry of a CREATE SEMANTIC VIEW `TABLES (...)` block: a logical table
/// the model is built over and the physical table it references.
#[derive(Debug, Clone, Copy)]
pub struct AstSemanticViewTable {
    /// The logical-table name as written before any `AS`.
    pub alias_span: Span,
    /// The physical (referenced) table. Equals `alias_span` when the entry is a
    /// bare table reference with no `AS`.
    pub physical_span: Span,
}

/// CREATE SEMANTIC VIEW statement (Snowflake).
///
/// Syntax:
/// ```text
/// CREATE [OR REPLACE] SEMANTIC VIEW [IF NOT EXISTS] <name>
///   TABLES ( <logical_table> [, ...] )
///   [ RELATIONSHIPS (...) ] [ FACTS (...) ]
///   [ DIMENSIONS (...) ] [ METRICS (...) ]
///   [ COMMENT = '...' ] [ [WITH] EXTENSION (...) ]
/// ```
///
/// The TABLES block is decomposed into the base-table access surface; the
/// RELATIONSHIPS / FACTS / DIMENSIONS / METRICS blocks are captured as opaque
/// balanced-paren spans (presence is the recognition signal; their inner
/// expressions are not analyzed). Trailing properties are absorbed to the
/// statement terminator.
#[derive(Debug, Clone)]
pub struct AstCreateSemanticView {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    pub or_replace_span: Option<Span>,
    pub if_not_exists_span: Option<Span>,
    pub name_span: Span,
    /// The base-table access surface (TABLES block entries).
    pub tables: Vec<AstSemanticViewTable>,
    /// `RELATIONSHIPS (...)` block span when present (opaque).
    pub relationships_span: Option<Span>,
    /// `FACTS (...)` block span when present (opaque).
    pub facts_span: Option<Span>,
    /// `DIMENSIONS (...)` block span when present (opaque).
    pub dimensions_span: Option<Span>,
    /// `METRICS (...)` block span when present (opaque).
    pub metrics_span: Option<Span>,
}

/// The action clause of an `ALTER SEMANTIC VIEW` statement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AstSemanticViewAction {
    /// `SET <props>`
    Set,
    /// `UNSET <props>`
    Unset,
    /// `RENAME TO <name>`
    Rename,
}

/// ALTER SEMANTIC VIEW statement (Snowflake).
///
/// Syntax:
/// ```text
/// ALTER SEMANTIC VIEW [IF EXISTS] <name>
///   { SET <props> | UNSET <props> | RENAME TO <name> }
/// ```
#[derive(Debug, Clone)]
pub struct AstAlterSemanticView {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    pub if_exists_span: Option<Span>,
    pub name_span: Span,
    pub action: AstSemanticViewAction,
}

/// CREATE CORTEX SEARCH SERVICE statement (Snowflake).
///
/// Syntax:
/// ```text
/// CREATE [OR REPLACE] CORTEX SEARCH SERVICE [IF NOT EXISTS] <name>
///   ON <col> [ATTRIBUTES <col> [, ...]] WAREHOUSE = <wh>
///   TARGET_LAG = '<lag>' [EMBEDDING_MODEL = '<model>'] [COMMENT = '<text>']
///   AS <query>
/// ```
///
/// The leading ON/ATTRIBUTES clauses and the WAREHOUSE/TARGET_LAG/COMMENT
/// properties are absorbed by the property walk; the governable EMBEDDING_MODEL
/// value is pulled out by name. The `AS <query>` body is captured as an opaque
/// span (recognized, not analyzed) so the inner SELECT is not fragmented into a
/// mis-analyzed standalone statement.
#[derive(Debug, Clone)]
pub struct AstCreateCortexSearchService {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    pub or_replace_span: Option<Span>,
    pub if_not_exists_span: Option<Span>,
    pub name_span: Span,
    /// `EMBEDDING_MODEL = '<model>'` value span when present.
    pub embedding_model_span: Option<Span>,
    /// The `AS <query>` source body (opaque, captured-not-analyzed).
    pub source_query_span: Option<Span>,
}

/// The action clause of an `ALTER CORTEX SEARCH SERVICE` statement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AstCortexSearchServiceAction {
    /// `SET <props>`
    Set,
    /// `UNSET <props>`
    Unset,
    /// `RESUME` — resumes the refresh schedule.
    Resume,
    /// `SUSPEND` — suspends the refresh schedule.
    Suspend,
}

/// ALTER CORTEX SEARCH SERVICE statement (Snowflake).
///
/// Syntax:
/// ```text
/// ALTER CORTEX SEARCH SERVICE [IF EXISTS] <name>
///   { SET <props> | UNSET <props> | RESUME | SUSPEND }
/// ```
#[derive(Debug, Clone)]
pub struct AstAlterCortexSearchService {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    pub if_exists_span: Option<Span>,
    pub name_span: Span,
    pub action: AstCortexSearchServiceAction,
    /// `SET EMBEDDING_MODEL = '<model>'` value span (SET only).
    pub embedding_model_span: Option<Span>,
}

/// CREATE APPLICATION statement (Snowflake Native Apps — consumer install).
///
/// Syntax:
/// ```text
/// CREATE APPLICATION <name>
///   FROM { APPLICATION PACKAGE <pkg> | LISTING <listing> }
///   [ USING '<path>' ] [ DEBUG_MODE = { TRUE | FALSE } ] [ COMMENT = '...' ]
/// ```
///
/// Installs a provider's application code into the account. The FROM source is
/// the supply-chain provenance (a LISTING is external marketplace code); the
/// USING/DEBUG_MODE/COMMENT properties are absorbed by the property walk.
#[derive(Debug, Clone)]
pub struct AstCreateApplication {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    pub or_replace_span: Option<Span>,
    pub if_not_exists_span: Option<Span>,
    pub name_span: Span,
    /// The app was installed `FROM LISTING` (external marketplace) rather than
    /// `FROM APPLICATION PACKAGE`.
    pub from_listing: bool,
    /// The source package / listing name span when a FROM clause is present.
    pub source_name_span: Option<Span>,
    /// `DEBUG_MODE = <value>` value span when present.
    pub debug_mode_span: Option<Span>,
}

/// The action clause of an `ALTER APPLICATION` / `ALTER APPLICATION PACKAGE`
/// statement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AstApplicationAction {
    /// `SET <props>`
    Set,
    /// `UNSET <props>`
    Unset,
    /// Any other recognized alter form (UPGRADE, ADD VERSION, …), consumed to
    /// the statement terminator.
    Other,
}

/// ALTER APPLICATION statement (Snowflake Native Apps).
///
/// Syntax:
/// ```text
/// ALTER APPLICATION [IF EXISTS] <name>
///   { SET <props> | UNSET <props> | UPGRADE ... | ... }
/// ```
#[derive(Debug, Clone)]
pub struct AstAlterApplication {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    pub if_exists_span: Option<Span>,
    pub name_span: Span,
    pub action: AstApplicationAction,
    /// `SET DEBUG_MODE = <value>` value span (SET only).
    pub debug_mode_span: Option<Span>,
}

/// CREATE APPLICATION PACKAGE statement (Snowflake Native Apps — provider
/// container that bundles the app for distribution).
///
/// Syntax:
/// ```text
/// CREATE APPLICATION PACKAGE [IF NOT EXISTS] <name>
///   [ COMMENT = '...' ] [ DISTRIBUTION = { INTERNAL | EXTERNAL } ] ...
/// ```
#[derive(Debug, Clone)]
pub struct AstCreateApplicationPackage {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    pub or_replace_span: Option<Span>,
    pub if_not_exists_span: Option<Span>,
    pub name_span: Span,
    /// `DISTRIBUTION = <value>` value span when present.
    pub distribution_span: Option<Span>,
}

/// ALTER APPLICATION PACKAGE statement (Snowflake Native Apps).
///
/// Syntax:
/// ```text
/// ALTER APPLICATION PACKAGE [IF EXISTS] <name>
///   { SET <props> | UNSET <props> | ADD VERSION ... | ... }
/// ```
#[derive(Debug, Clone)]
pub struct AstAlterApplicationPackage {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    pub if_exists_span: Option<Span>,
    pub name_span: Span,
    pub action: AstApplicationAction,
    /// `SET DISTRIBUTION = <value>` value span (SET only).
    pub distribution_span: Option<Span>,
}

/// CREATE LISTING statement (Snowflake Marketplace / data exchange).
///
/// Syntax:
/// ```text
/// CREATE [OR REPLACE] [EXTERNAL] LISTING [IF NOT EXISTS] <name>
///   [ { SHARE <share> | APPLICATION PACKAGE <pkg> } ]
///   [ AS { '<manifest>' | $$ <manifest> $$ } ]
///   [ PUBLISH = { TRUE | FALSE } ] [ REVIEW = ... ] [ COMMENT = '...' ]
/// ```
///
/// EXTERNAL publishes the listing to the public Snowflake Marketplace (data
/// leaves the org); PUBLISH makes it live. The AS manifest body is consumed
/// (recognized, not analyzed) so a `$$` YAML body does not fragment.
#[derive(Debug, Clone)]
pub struct AstCreateListing {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    pub or_replace_span: Option<Span>,
    pub if_not_exists_span: Option<Span>,
    pub name_span: Span,
    /// `EXTERNAL` — published to the public Marketplace (vs an internal data
    /// exchange listing).
    pub is_external: bool,
    /// The shared object name (`SHARE <share>` / `APPLICATION PACKAGE <pkg>`) —
    /// what the listing exposes.
    pub shared_object_span: Option<Span>,
    /// `PUBLISH = <value>` value span when present.
    pub publish_span: Option<Span>,
}

/// The action clause of an `ALTER LISTING` statement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AstListingAction {
    /// `SET <props>`
    Set,
    /// `UNSET <props>`
    Unset,
    /// Any other recognized alter form (`PUBLISH`, `UNPUBLISH`, `ADD VERSION`,
    /// `AS <manifest>`, `RENAME`, …), consumed to the statement terminator.
    Other,
}

/// ALTER LISTING statement (Snowflake Marketplace).
///
/// Syntax:
/// ```text
/// ALTER LISTING [IF EXISTS] <name>
///   { SET <props> | UNSET <props> | PUBLISH | UNPUBLISH | ... }
/// ```
#[derive(Debug, Clone)]
pub struct AstAlterListing {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    pub if_exists_span: Option<Span>,
    pub name_span: Span,
    pub action: AstListingAction,
    /// `SET PUBLISH = <value>` value span (SET only).
    pub publish_span: Option<Span>,
}

/// CREATE MANAGED ACCOUNT statement (Snowflake reader account).
///
/// Syntax:
/// ```text
/// CREATE MANAGED ACCOUNT <name>
///   ADMIN_NAME = <user> ADMIN_PASSWORD = '<pw>' TYPE = READER [COMMENT = '...']
/// ```
///
/// A managed (reader) account consumes shares without being a Snowflake
/// customer — a data-egress-to-outsiders surface. The credential properties are
/// parsed but the secret value is never captured; only the TYPE value is
/// surfaced.
#[derive(Debug, Clone)]
pub struct AstCreateManagedAccount {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    pub or_replace_span: Option<Span>,
    pub if_not_exists_span: Option<Span>,
    pub name_span: Span,
    /// `TYPE = <value>` value span when present (normally `READER`).
    pub account_type_span: Option<Span>,
}

/// Snowflake client file-transfer command (PUT / GET / REMOVE / LIST).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AstStageFileCommandKind {
    /// `PUT file://<local> @<stage>` — upload a local file to a stage.
    Put,
    /// `GET @<stage> file://<local>` — download stage files to the client.
    Get,
    /// `REMOVE @<stage>` (alias `RM`) — delete files from a stage.
    Remove,
    /// `LIST @<stage>` (alias `LS`) — list files in a stage.
    List,
}

/// PUT / GET / REMOVE / LIST statement (Snowflake client file commands). These
/// are top-level statements (not CREATE/ALTER/DROP) that move or enumerate
/// files on a stage. The operation kind is the recognition surface (GET is a
/// data-egress-to-client primitive); the `file://` local path is currently
/// swallowed by `//` line-comment lexing, so only the verb + stage portion is
/// captured in the span.
#[derive(Debug, Clone)]
pub struct AstStageFileCommand {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    pub kind: AstStageFileCommandKind,
    /// The `@<stage>` reference (the data source/target), when present.
    pub stage_ref_span: Option<Span>,
}

/// Snowflake `CREATE [OR REPLACE] [SECURE] EXTERNAL FUNCTION <name> (<args>)
///   RETURNS <type> [modifiers] API_INTEGRATION = <int> [HEADERS …]
///   [CONTEXT_HEADERS …] [REQUEST_TRANSLATOR …] [RESPONSE_TRANSLATOR …]
///   AS '<url>'`.
///
/// An external function ships row data to an arbitrary external HTTPS endpoint
/// (the `AS '<url>'` proxy/resource) through an API integration — a data-egress
/// surface. The endpoint URL, API integration, SECURE flag, and the request/
/// response translators are the recognition surface; which endpoints are
/// trusted is the consumer's policy.
#[derive(Debug, Clone)]
pub struct AstCreateExternalFunction {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    /// `OR REPLACE` span when present.
    pub or_replace_span: Option<Span>,
    /// `SECURE` span when present.
    pub secure_span: Option<Span>,
    /// The (possibly qualified) function name.
    pub name_span: Span,
    /// `API_INTEGRATION = <name>` value span — the integration authorizing
    /// the outbound call. Required by Snowflake; `None` if malformed.
    pub api_integration_span: Option<Span>,
    /// `AS '<url>'` endpoint span (the proxy/resource URL — the egress target).
    pub endpoint_url_span: Option<Span>,
    /// `HEADERS = ( … )` clause span when present (custom request headers can
    /// carry secrets).
    pub headers_span: Option<Span>,
    /// `CONTEXT_HEADERS = ( … )` clause span when present.
    pub context_headers_span: Option<Span>,
    /// `REQUEST_TRANSLATOR = <udf>` value span when present.
    pub request_translator_span: Option<Span>,
    /// `RESPONSE_TRANSLATOR = <udf>` value span when present.
    pub response_translator_span: Option<Span>,
}

/// The file-location argument of `EXECUTE IMMEDIATE FROM`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AstEifLocationKind {
    /// `@[<namespace>.]<stage>/<path>/<file>` — an absolute stage path.
    StagePath,
    /// A quoted (`'…'` / `$$…$$`) relative path resolved against the
    /// executing file's stage (`./file.sql`, `../file.sql`).
    RelativePath,
}

/// Snowflake `EXECUTE IMMEDIATE FROM <file_location>
///   [ USING ( <key> => <value> [, …] ) ] [ DRY_RUN = { TRUE | FALSE } ]`.
///
/// Executes SQL loaded from a stage file. The file location (stage path vs
/// relative path) and the `DRY_RUN` flag are the recognition surface; which
/// stages are trusted is the consumer's policy.
#[derive(Debug, Clone)]
pub struct AstExecuteImmediateFrom {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    /// Span covering the EXECUTE keyword.
    pub execute_span: Span,
    /// Span covering the IMMEDIATE keyword.
    pub immediate_span: Span,
    /// Span covering the FROM keyword.
    pub from_span: Span,
    /// Whether the location is a stage path (`@…`) or a relative path.
    pub location_kind: AstEifLocationKind,
    /// Span of the file-location argument (the `@…` run or the quoted path).
    pub location_span: Span,
    /// Span covering the USING keyword, when present.
    pub using_span: Option<Span>,
    /// Spans of the USING template-variable keys (`<key>` in `<key> => <value>`).
    pub using_keys: Vec<Span>,
    /// `DRY_RUN = TRUE | FALSE` value when present; `None` when the clause
    /// is absent (defaults to executing).
    pub dry_run: Option<bool>,
    /// Span covering the DRY_RUN keyword, when present.
    pub dry_run_span: Option<Span>,
}

/// CREATE ACCOUNT statement (Snowflake org-level account provisioning).
///
/// Syntax:
/// ```text
/// CREATE ACCOUNT <name> ADMIN_NAME = <user>
///   { ADMIN_PASSWORD = '<pw>' | ADMIN_RSA_PUBLIC_KEY = '<key>' }
///   [FIRST_NAME = ...] [EMAIL = ...] EDITION = <edition> [...]
/// ```
///
/// Provisions a new account in the organization. The credential properties are
/// parsed but never captured; recognition is the statement itself.
#[derive(Debug, Clone)]
pub struct AstCreateAccount {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    pub or_replace_span: Option<Span>,
    pub if_not_exists_span: Option<Span>,
    pub name_span: Span,
}

/// CREATE ALERT statement (Snowflake).
///
/// Syntax:
/// ```text
/// CREATE [OR REPLACE] ALERT [IF NOT EXISTS] <name>
///   [WAREHOUSE = <wh>] SCHEDULE = '<schedule>' [COMMENT = '<text>']
///   IF (EXISTS ( <condition_query> ))
///   THEN <action_statement>
/// ```
///
/// The condition query and action statement are recursively parsed so they
/// are recognized as part of the alert (not fragmented into mis-analyzed
/// standalone statements). Mirrors the TASK body model.
#[derive(Debug, Clone)]
pub struct AstCreateAlert {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    pub create_span: Span,
    pub or_replace_span: Option<Span>,
    pub alert_span: Span,
    pub if_not_exists_span: Option<Span>,
    pub name_span: Span,
    /// `<name> [= <value>]` properties before the IF clause.
    pub properties: Vec<AstObjectProperty>,
    /// `WAREHOUSE = <value>` — span covers just the value.
    pub warehouse_span: Option<Span>,
    /// `SCHEDULE = <value>` — span covers just the value.
    pub schedule_span: Option<Span>,
    /// `COMMENT = <value>` — span covers just the value.
    pub comment_span: Option<Span>,
    /// `IF` keyword span.
    pub if_span: Option<Span>,
    /// `( EXISTS ( <query> ) )` condition span (balanced parens).
    pub condition_span: Option<Span>,
    /// `THEN` keyword span.
    pub then_span: Option<Span>,
    /// The action SQL after THEN: `Ok` when parsed, `Err(span)` when the
    /// body could not be parsed, `None` when absent.
    pub action: Option<Result<Box<AstStmt>, Span>>,
}

/// ALTER ALERT statement (Snowflake).
///
/// Syntax:
/// ```text
/// ALTER ALERT [IF EXISTS] <name>
///   { RESUME | SUSPEND | SET <props> | UNSET <props>
///   | MODIFY CONDITION EXISTS ( <query> ) | MODIFY ACTION <statement> }
/// ```
#[derive(Debug, Clone)]
pub struct AstAlterAlert {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    pub alter_span: Span,
    pub alert_span: Span,
    pub if_exists_span: Option<Span>,
    pub name_span: Span,
    pub action: AstAlterAlertAction,
}

#[derive(Debug, Clone)]
pub struct AstAlterAlertAction {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    pub kind: AstAlterAlertActionKind,
}

#[derive(Debug, Clone)]
pub enum AstAlterAlertActionKind {
    /// RESUME
    Resume { resume_span: Span },
    /// SUSPEND
    Suspend { suspend_span: Span },
    /// `SET <property> = <value> [...]`
    Set {
        set_span: Span,
        properties: Vec<AstObjectProperty>,
    },
    /// `UNSET <property> [, ...]`
    Unset {
        unset_span: Span,
        property_name_spans: Vec<Span>,
    },
    /// `MODIFY CONDITION EXISTS ( <query> )`
    ModifyCondition {
        modify_span: Span,
        condition_span: Span,
    },
    /// MODIFY ACTION <action_statement>
    ModifyAction {
        modify_span: Span,
        action_span: Span,
        body: Result<Box<AstStmt>, Span>,
    },
}

/// CREATE JOIN POLICY statement (Snowflake). Ninth policy kind; structurally
/// identical to PROJECTION POLICY. Span-only (no CST layer).
///
/// Syntax:
/// ```text
/// CREATE [OR REPLACE] JOIN POLICY [IF NOT EXISTS] <name>
///   AS () RETURNS JOIN_CONSTRAINT -> <body> [COMMENT = '<string>']
/// ```
/// Body: `JOIN_CONSTRAINT(JOIN_REQUIRED => <boolean>)`.
#[derive(Debug, Clone)]
pub struct AstCreateJoinPolicy {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    pub create_span: Span,
    pub or_replace_span: Option<Span>,
    /// `JOIN` is an Identifier token here, not a Keyword.
    pub join_span: Span,
    pub policy_span: Span,
    pub if_not_exists_span: Option<Span>,
    pub policy_name_span: Span,
    /// Parsed body expression (the `JOIN_CONSTRAINT(...)` call or CASE).
    pub body_expr: Option<Box<AstExpr>>,
    /// `COMMENT = '<text>'` value span.
    pub comment_span: Option<Span>,
}

/// ALTER JOIN POLICY statement (Snowflake).
///
/// Syntax:
/// ```text
/// ALTER JOIN POLICY [IF EXISTS] <name>
///   { RENAME TO <new> | SET BODY -> <expr> | SET|UNSET COMMENT
///   | SET|UNSET TAG ... }
/// ```
#[derive(Debug, Clone)]
pub struct AstAlterJoinPolicy {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    pub alter_span: Span,
    pub join_span: Span,
    pub policy_span: Span,
    pub if_exists_span: Option<Span>,
    pub name_span: Span,
    pub action: AstAlterJoinPolicyAction,
}

#[derive(Debug, Clone)]
pub struct AstAlterJoinPolicyAction {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    pub kind: AstAlterJoinPolicyActionKind,
}

#[derive(Debug, Clone)]
pub enum AstAlterJoinPolicyActionKind {
    /// RENAME TO <new_name>
    RenameTo { new_name_span: Span },
    /// `SET BODY -> <expression>`
    SetBody {
        expression_span: Span,
        body_expr: Option<Box<AstExpr>>,
    },
    /// `SET COMMENT = '<text>'`
    SetComment { comment_value_span: Span },
    /// UNSET COMMENT
    UnsetComment,
    /// `SET TAG <key> = '<value>' [, ...]`
    SetTag { assignments_span: Span },
    /// `UNSET TAG <key> [, ...]`
    UnsetTag { tags_span: Span },
}

/// DROP JOIN POLICY statement (Snowflake).
///
/// Syntax: `DROP JOIN POLICY [IF EXISTS] <name>`
#[derive(Debug, Clone)]
pub struct AstDropJoinPolicy {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    pub drop_span: Span,
    pub join_span: Span,
    pub policy_span: Span,
    pub if_exists_span: Option<Span>,
    pub policy_name_span: Span,
}

/// CREATE DATA METRIC FUNCTION statement (Snowflake). Span-only.
///
/// Syntax:
/// ```text
/// CREATE [OR REPLACE] [SECURE] DATA METRIC FUNCTION [IF NOT EXISTS]
///   <name> (<arg> TABLE(<col> <type>) [, ...]) RETURNS NUMBER [[NOT] NULL]
///   [LANGUAGE SQL] [COMMENT = '<string>'] AS '<expression>'
/// ```
///
/// The argument list and the string-literal body are captured as spans (no
/// inner parsing); the formatter renders via Pattern A (`push_span`).
#[derive(Debug, Clone)]
pub struct AstCreateDataMetricFunction {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    pub create_span: Span,
    pub or_replace_span: Option<Span>,
    /// `SECURE` modifier — hides the function definition.
    pub secure_span: Option<Span>,
    /// `DATA` / `METRIC` are Identifier tokens; `FUNCTION` is a Keyword.
    pub data_span: Span,
    pub metric_span: Span,
    pub function_span: Span,
    pub if_not_exists_span: Option<Span>,
    pub name_span: Span,
    /// The `(<arg> TABLE(...))` argument list (balanced-paren span).
    pub params_span: Span,
    /// `COMMENT = '<text>'` value span.
    pub comment_span: Option<Span>,
    /// The `AS '<expression>'` body (string-literal / dollar-quote span).
    pub body_span: Option<Span>,
}

/// CREATE SECRET statement (Snowflake).
///
/// Syntax:
/// ```text
/// CREATE [OR REPLACE] SECRET [IF NOT EXISTS] <name>
///   TYPE = {OAUTH2 | PASSWORD | GENERIC_STRING | SYMMETRIC_KEY | CLOUD_PROVIDER_TOKEN}
///   <type_specific_properties> [COMMENT = '<string>']
/// ```
#[derive(Debug, Clone)]
pub struct AstCreateSecret {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    pub create_span: Span,
    pub or_replace_span: Option<Span>,
    pub secret_span: Span,
    pub if_not_exists_span: Option<Span>,
    pub name_span: Span,
    /// Every `<name> [= <value>]` property in declaration order,
    /// including TYPE / COMMENT (which also keep dedicated spans below).
    pub properties: Vec<AstObjectProperty>,
    /// `TYPE = <value>` — span covers just the value (e.g. `OAUTH2`).
    pub type_value_span: Option<Span>,
    /// `COMMENT = '<text>'` — span covers keyword through value.
    pub comment_span: Option<Span>,
}

/// ALTER SECRET statement (Snowflake).
///
/// Syntax: `ALTER SECRET [IF EXISTS] <name> { SET <props> | UNSET COMMENT }`
#[derive(Debug, Clone)]
pub struct AstAlterSecret {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    pub alter_span: Span,
    pub secret_span: Span,
    pub if_exists_span: Option<Span>,
    pub name_span: Span,
    pub action: AstAlterSecretAction,
}

#[derive(Debug, Clone)]
pub struct AstAlterSecretAction {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    pub kind: AstAlterSecretActionKind,
}

#[derive(Debug, Clone)]
pub enum AstAlterSecretActionKind {
    /// `SET <property> = <value> [...]`
    Set {
        set_span: Span,
        /// Parsed `<name> = <value>` pairs within the SET body.
        properties: Vec<AstObjectProperty>,
    },
    /// `UNSET <property> [, ...]`
    Unset {
        unset_span: Span,
        /// Spans of the property names being unset.
        property_name_spans: Vec<Span>,
    },
}

/// ALTER REPLICATION GROUP statement (Snowflake).
///
/// Syntax variants:
/// - `ALTER REPLICATION GROUP [IF EXISTS] <name> SET <property> = <value>`
/// - `ALTER REPLICATION GROUP [IF EXISTS] <name> ADD <list> TO ALLOWED_DATABASES`
/// - `ALTER REPLICATION GROUP [IF EXISTS] <name> REMOVE <list> FROM ALLOWED_DATABASES`
#[derive(Debug, Clone)]
pub struct AstAlterReplicationGroup {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    pub alter_span: Span,
    pub replication_span: Span,
    pub group_span: Span,
    pub if_exists_span: Option<Span>,
    pub name_span: Span,
    pub action: AstReplicationFailoverGroupAction,
}

/// ALTER FAILOVER GROUP statement (Snowflake).
///
/// Same syntactic shape as ALTER REPLICATION GROUP; kept as a separate
/// AstStmt variant so consumers can tell the two surfaces apart.
#[derive(Debug, Clone)]
pub struct AstAlterFailoverGroup {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    pub alter_span: Span,
    pub failover_span: Span,
    pub group_span: Span,
    pub if_exists_span: Option<Span>,
    pub name_span: Span,
    pub action: AstReplicationFailoverGroupAction,
}

/// Shared action shape for ALTER REPLICATION GROUP and ALTER FAILOVER GROUP.
#[derive(Debug, Clone)]
pub struct AstReplicationFailoverGroupAction {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    pub kind: AstReplicationFailoverGroupActionKind,
}

#[derive(Debug, Clone)]
pub enum AstReplicationFailoverGroupActionKind {
    /// `SET <property> = <value> [, ...]`
    Set {
        set_span: Span,
        properties_span: Span,
    },
    /// `UNSET <property> [, ...]`
    Unset {
        unset_span: Span,
        properties_span: Span,
    },
    /// `ADD <list> TO ALLOWED_DATABASES` (or ALLOWED_INTEGRATION_TYPES, etc.)
    AddTo {
        add_span: Span,
        list_span: Span,
        to_span: Span,
        target_span: Span,
    },
    /// `REMOVE <list> FROM ALLOWED_DATABASES` (or other allowed-* list)
    RemoveFrom {
        remove_span: Span,
        list_span: Span,
        from_span: Span,
        target_span: Span,
    },
    /// `MOVE DATABASES <list> TO REPLICATION GROUP <name>`
    Move { move_span: Span, body_span: Span },
    /// Unrecognized action (defensive)
    Unknown(AstUnknownClause),
}

/// CREATE REPLICATION GROUP / CREATE FAILOVER GROUP statement (Snowflake).
/// Span-only; the two group types share an identical CREATE grammar, so one
/// AST variant carries both with `group_type_span` as the discriminator.
///
/// Primary form: `CREATE {REPLICATION|FAILOVER} GROUP [IF NOT EXISTS] <name>
///   OBJECT_TYPES = … [ALLOWED_DATABASES = …] [ALLOWED_SHARES = …]
///   ALLOWED_ACCOUNTS = <org>.<acct> [, …] [IGNORE EDITION CHECK]
///   [REPLICATION_SCHEDULE = '…'] …`
/// Secondary form: `… <name> AS REPLICA OF <org>.<acct>.<group>`.
///
/// `ALLOWED_ACCOUNTS` is the cross-account egress primitive (which accounts
/// may replicate this data).
#[derive(Debug, Clone)]
pub struct AstCreateReplicationFailoverGroup {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    pub create_span: Span,
    /// Optional `OR REPLACE` span (Snowflake).
    pub or_replace_span: Option<Span>,
    /// `REPLICATION` or `FAILOVER` (Identifier) — the group-type discriminator.
    pub group_type_span: Span,
    pub group_keyword_span: Span,
    pub if_not_exists_span: Option<Span>,
    pub name_span: Span,
    /// `AS REPLICA OF <source>` secondary form — the source group span.
    /// Presence marks this as a secondary (replica) group.
    pub replica_source_span: Option<Span>,
    /// `OBJECT_TYPES = <list>` value span.
    pub object_types_span: Option<Span>,
    /// `ALLOWED_DATABASES = <list>` value span.
    pub allowed_databases_span: Option<Span>,
    /// `ALLOWED_SHARES = <list>` value span.
    pub allowed_shares_span: Option<Span>,
    /// `ALLOWED_ACCOUNTS = <org.acct list>` value span — the egress targets.
    pub allowed_accounts_span: Option<Span>,
    /// `REPLICATION_SCHEDULE = '<schedule>'` value span.
    pub replication_schedule_span: Option<Span>,
}

/// DROP NOTIFICATION INTEGRATION statement.
///
/// Syntax: `DROP NOTIFICATION INTEGRATION [IF EXISTS] <name>`
#[derive(Debug, Clone)]
pub struct AstDropNotificationIntegration {
    pub node_id: crate::ast::NodeId,
    pub span: Span,

    pub drop_span: Span,
    pub notification_span: Span,
    pub integration_span: Span,
    pub if_exists_span: Option<Span>,

    pub integration_name_span: Span,
}

// ============================================================================
// PASSWORD POLICY - Enterprise Edition feature
// ============================================================================

/// CREATE PASSWORD POLICY statement.
///
/// Defines password complexity requirements and expiration rules.
/// PASSWORD POLICY is an Enterprise Edition feature that controls:
/// - Password length requirements (PASSWORD_MIN_LENGTH, PASSWORD_MAX_LENGTH)
/// - Character requirements (PASSWORD_MIN_UPPER_CASE_CHARS, PASSWORD_MIN_LOWER_CASE_CHARS, etc.)
/// - Password age (PASSWORD_MIN_AGE_DAYS, PASSWORD_MAX_AGE_DAYS)
/// - Account lockout (PASSWORD_MAX_RETRIES, PASSWORD_LOCKOUT_TIME_MINS)
/// - Password history (PASSWORD_HISTORY)
///
/// Syntax:
/// ```text
/// CREATE [OR REPLACE] PASSWORD POLICY [IF NOT EXISTS] name
///   [PASSWORD_MIN_LENGTH = <integer>]
///   [PASSWORD_MAX_LENGTH = <integer>]
///   [PASSWORD_MIN_UPPER_CASE_CHARS = <integer>]
///   [PASSWORD_MIN_LOWER_CASE_CHARS = <integer>]
///   [PASSWORD_MIN_NUMERIC_CHARS = <integer>]
///   [PASSWORD_MIN_SPECIAL_CHARS = <integer>]
///   [PASSWORD_MIN_AGE_DAYS = <integer>]
///   [PASSWORD_MAX_AGE_DAYS = <integer>]
///   [PASSWORD_MAX_RETRIES = <integer>]
///   [PASSWORD_LOCKOUT_TIME_MINS = <integer>]
///   [PASSWORD_HISTORY = <integer>]
///   [COMMENT = '<string>']
/// ```
#[derive(Debug, Clone)]
pub struct AstCreatePasswordPolicy {
    pub node_id: crate::ast::NodeId,
    /// Span covering the entire CREATE PASSWORD POLICY statement
    pub span: Span,
    /// Optional typed-syntax node id for this statement
    pub syntax_id: Option<crate::syntax::SyntaxCreatePasswordPolicyId>,

    // Keyword spans (for semantic tracking and governance)
    pub create_span: Span,
    pub or_replace_span: Option<Span>,
    pub if_not_exists_span: Option<Span>,
    pub password_span: Span, // PASSWORD is Identifier, not Keyword!
    pub policy_span: Span,

    /// Span covering the policy name identifier
    pub policy_name_span: Span,

    /// Decomposed properties (name = value triples).
    /// Replaces individual `Option<Span>` fields for each property,
    /// enabling alignment and clean value extraction.
    pub properties: Vec<CreatePolicyProperty>,

    /// Unknown properties not recognized by parser (defensive design).
    ///
    /// When Snowflake adds new PASSWORD POLICY properties, they are preserved here
    /// instead of causing parse errors. The formatter emits them unchanged,
    /// ensuring semantic preservation even when syntax is unrecognized.
    pub extras: Vec<AstUnknownClause>,
}

/// ALTER PASSWORD POLICY statement.
///
/// Modifies properties of an existing password policy.
/// Includes governance-critical operations like changing password requirements,
/// lockout settings, and expiration rules.
#[derive(Debug, Clone)]
pub struct AstAlterPasswordPolicy {
    pub node_id: crate::ast::NodeId,
    /// Span covering the entire ALTER PASSWORD POLICY statement
    pub span: Span,
    /// Optional typed-syntax node id for this statement
    pub syntax_id: Option<crate::syntax::SyntaxAlterPasswordPolicyStmtId>,
    /// Span covering the ALTER keyword
    pub alter_span: Span,
    /// Span covering the PASSWORD keyword (Identifier!)
    pub password_span: Span,
    /// Span covering the POLICY keyword
    pub policy_span: Span,
    /// Optional span covering IF EXISTS
    pub if_exists_span: Option<Span>,
    /// Span covering the policy name
    pub name_span: Span,
    /// Span covering the action (everything after the policy name)
    pub action_span: Span,
    /// Parsed actions (can have multiple SET/UNSET clauses)
    pub actions: Vec<AstAlterPasswordPolicyAction>,
}

/// One ALTER PASSWORD POLICY action.
#[derive(Debug, Clone)]
pub struct AstAlterPasswordPolicyAction {
    pub node_id: crate::ast::NodeId,
    /// Span covering the entire action
    pub span: Span,
    /// Optional typed-syntax node id for this action
    pub syntax_id: Option<crate::syntax::SyntaxAlterPasswordPolicyActionId>,
    pub kind: AstAlterPasswordPolicyActionKind,
}

/// ALTER PASSWORD POLICY action kinds.
///
/// Supports 12+ SET actions (one per property), 12+ UNSET actions,
/// RENAME TO, SET TAG, and UNSET TAG.
#[derive(Debug, Clone)]
pub enum AstAlterPasswordPolicyActionKind {
    /// RENAME TO <new_name>
    RenameTo {
        rename_span: Option<Span>,
        to_span: Option<Span>,
        new_name_span: Span,
    },

    // ========================================================================
    // SET actions (one per property)
    // ========================================================================
    /// `SET PASSWORD_MIN_LENGTH = <integer>`
    SetPasswordMinLength {
        set_span: Option<Span>,
        property_span: Span,
        eq_span: Option<Span>,
        value_span: Span,
    },

    /// `SET PASSWORD_MAX_LENGTH = <integer>`
    SetPasswordMaxLength {
        set_span: Option<Span>,
        property_span: Span,
        eq_span: Option<Span>,
        value_span: Span,
    },

    /// `SET PASSWORD_MIN_UPPER_CASE_CHARS = <integer>`
    SetPasswordMinUpperCaseChars {
        set_span: Option<Span>,
        property_span: Span,
        eq_span: Option<Span>,
        value_span: Span,
    },

    /// `SET PASSWORD_MIN_LOWER_CASE_CHARS = <integer>`
    SetPasswordMinLowerCaseChars {
        set_span: Option<Span>,
        property_span: Span,
        eq_span: Option<Span>,
        value_span: Span,
    },

    /// `SET PASSWORD_MIN_NUMERIC_CHARS = <integer>`
    SetPasswordMinNumericChars {
        set_span: Option<Span>,
        property_span: Span,
        eq_span: Option<Span>,
        value_span: Span,
    },

    /// `SET PASSWORD_MIN_SPECIAL_CHARS = <integer>`
    SetPasswordMinSpecialChars {
        set_span: Option<Span>,
        property_span: Span,
        eq_span: Option<Span>,
        value_span: Span,
    },

    /// `SET PASSWORD_MIN_AGE_DAYS = <integer>`
    SetPasswordMinAgeDays {
        set_span: Option<Span>,
        property_span: Span,
        eq_span: Option<Span>,
        value_span: Span,
    },

    /// `SET PASSWORD_MAX_AGE_DAYS = <integer>`
    SetPasswordMaxAgeDays {
        set_span: Option<Span>,
        property_span: Span,
        eq_span: Option<Span>,
        value_span: Span,
    },

    /// `SET PASSWORD_MAX_RETRIES = <integer>`
    SetPasswordMaxRetries {
        set_span: Option<Span>,
        property_span: Span,
        eq_span: Option<Span>,
        value_span: Span,
    },

    /// `SET PASSWORD_LOCKOUT_TIME_MINS = <integer>`
    SetPasswordLockoutTimeMins {
        set_span: Option<Span>,
        property_span: Span,
        eq_span: Option<Span>,
        value_span: Span,
    },

    /// `SET PASSWORD_HISTORY = <integer>`
    SetPasswordHistory {
        set_span: Option<Span>,
        property_span: Span,
        eq_span: Option<Span>,
        value_span: Span,
    },

    /// `SET COMMENT = '<string>'`
    SetComment {
        set_span: Option<Span>,
        comment_span: Option<Span>,
        eq_span: Option<Span>,
        comment_value_span: Span,
    },

    /// `SET TAG <tag_name> = '<value>' [, ...]`
    SetTag {
        set_span: Option<Span>,
        tag_span: Option<Span>,
        /// Tag assignments as spans (covers "tag = 'value'" pairs)
        assignments_span: Span,
    },

    // ========================================================================
    // UNSET actions (one per property)
    // ========================================================================
    /// UNSET PASSWORD_MIN_LENGTH
    UnsetPasswordMinLength {
        unset_span: Option<Span>,
        property_span: Span,
    },

    /// UNSET PASSWORD_MAX_LENGTH
    UnsetPasswordMaxLength {
        unset_span: Option<Span>,
        property_span: Span,
    },

    /// UNSET PASSWORD_MIN_UPPER_CASE_CHARS
    UnsetPasswordMinUpperCaseChars {
        unset_span: Option<Span>,
        property_span: Span,
    },

    /// UNSET PASSWORD_MIN_LOWER_CASE_CHARS
    UnsetPasswordMinLowerCaseChars {
        unset_span: Option<Span>,
        property_span: Span,
    },

    /// UNSET PASSWORD_MIN_NUMERIC_CHARS
    UnsetPasswordMinNumericChars {
        unset_span: Option<Span>,
        property_span: Span,
    },

    /// UNSET PASSWORD_MIN_SPECIAL_CHARS
    UnsetPasswordMinSpecialChars {
        unset_span: Option<Span>,
        property_span: Span,
    },

    /// UNSET PASSWORD_MIN_AGE_DAYS
    UnsetPasswordMinAgeDays {
        unset_span: Option<Span>,
        property_span: Span,
    },

    /// UNSET PASSWORD_MAX_AGE_DAYS
    UnsetPasswordMaxAgeDays {
        unset_span: Option<Span>,
        property_span: Span,
    },

    /// UNSET PASSWORD_MAX_RETRIES
    UnsetPasswordMaxRetries {
        unset_span: Option<Span>,
        property_span: Span,
    },

    /// UNSET PASSWORD_LOCKOUT_TIME_MINS
    UnsetPasswordLockoutTimeMins {
        unset_span: Option<Span>,
        property_span: Span,
    },

    /// UNSET PASSWORD_HISTORY
    UnsetPasswordHistory {
        unset_span: Option<Span>,
        property_span: Span,
    },

    /// UNSET COMMENT
    UnsetComment {
        unset_span: Option<Span>,
        comment_span: Option<Span>,
    },

    /// UNSET TAG <tag_name> [, ...]
    UnsetTag {
        unset_span: Option<Span>,
        tag_span: Option<Span>,
        /// Tag names to unset (comma-separated spans)
        tags_span: Span,
    },
}

impl AstAlterPasswordPolicyActionKind {
    /// Returns true if this action is a SET property (not TAG).
    pub fn is_set_property(&self) -> bool {
        matches!(
            self,
            Self::SetPasswordMinLength { .. }
                | Self::SetPasswordMaxLength { .. }
                | Self::SetPasswordMinUpperCaseChars { .. }
                | Self::SetPasswordMinLowerCaseChars { .. }
                | Self::SetPasswordMinNumericChars { .. }
                | Self::SetPasswordMinSpecialChars { .. }
                | Self::SetPasswordMinAgeDays { .. }
                | Self::SetPasswordMaxAgeDays { .. }
                | Self::SetPasswordMaxRetries { .. }
                | Self::SetPasswordLockoutTimeMins { .. }
                | Self::SetPasswordHistory { .. }
                | Self::SetComment { .. }
        )
    }

    /// Returns true if this action is an UNSET property (not TAG).
    pub fn is_unset_property(&self) -> bool {
        matches!(
            self,
            Self::UnsetPasswordMinLength { .. }
                | Self::UnsetPasswordMaxLength { .. }
                | Self::UnsetPasswordMinUpperCaseChars { .. }
                | Self::UnsetPasswordMinLowerCaseChars { .. }
                | Self::UnsetPasswordMinNumericChars { .. }
                | Self::UnsetPasswordMinSpecialChars { .. }
                | Self::UnsetPasswordMinAgeDays { .. }
                | Self::UnsetPasswordMaxAgeDays { .. }
                | Self::UnsetPasswordMaxRetries { .. }
                | Self::UnsetPasswordLockoutTimeMins { .. }
                | Self::UnsetPasswordHistory { .. }
                | Self::UnsetComment { .. }
        )
    }
}

/// DROP PASSWORD POLICY statement.
#[derive(Debug, Clone)]
pub struct AstDropPasswordPolicy {
    pub node_id: crate::ast::NodeId,
    /// Span covering the entire DROP PASSWORD POLICY statement
    pub span: Span,
    /// Optional typed-syntax node id for this statement
    pub syntax_id: Option<crate::syntax::SyntaxDropPasswordPolicyId>,

    // Keyword spans
    pub drop_span: Span,
    pub password_span: Span, // PASSWORD is Identifier!
    pub policy_span: Span,
    pub if_exists_span: Option<Span>,

    /// Span covering the policy name
    pub policy_name_span: Span,
}

// ============================================================================
// AGGREGATION POLICY statements
// ============================================================================

/// CREATE AGGREGATION POLICY statement.
///
/// Syntax:
/// ```text
/// CREATE [OR REPLACE] AGGREGATION POLICY [IF NOT EXISTS] <name>
///   AS () RETURNS AGGREGATION_CONSTRAINT -> <body>
///   [COMMENT = '<string>']
/// ```
///
/// Aggregation policies enforce differential privacy by requiring query results
/// to be aggregated with a minimum group size, preventing individual record exposure.
#[derive(Debug, Clone)]
pub struct AstCreateAggregationPolicy {
    pub node_id: crate::ast::NodeId,
    /// Span covering the entire CREATE AGGREGATION POLICY statement
    pub span: Span,
    /// Optional typed-syntax node id for this statement
    pub syntax_id: Option<crate::syntax::SyntaxCreateAggregationPolicyId>,

    // Keyword spans
    pub create_span: Span,
    pub or_replace_span: Option<Span>,
    pub if_not_exists_span: Option<Span>,
    pub aggregation_span: Span, // AGGREGATION is Identifier!
    pub policy_span: Span,

    /// Span covering the policy name (may be qualified: db.schema.name)
    pub policy_name_span: Span,

    /// Span covering "AS ()" signature
    pub as_signature_span: Span,

    /// Span covering "RETURNS AGGREGATION_CONSTRAINT"
    pub returns_span: Span,

    /// Span covering the body expression (after ->)
    pub body_span: Span,

    /// Parsed body expression (for semantic analysis via CST)
    /// The body can be:
    /// - Function call: AGGREGATION_CONSTRAINT(MIN_GROUP_SIZE => 5)
    /// - Function call: NO_AGGREGATION_CONSTRAINT()
    /// - CASE expression: CASE WHEN ... THEN ... ELSE ... END
    pub body: Option<Box<AstExpr>>,

    /// Span covering COMMENT = 'value' if present
    pub comment_span: Option<Span>,

    /// Defensive design for future Snowflake additions
    pub extras: Vec<AstUnknownClause>,
}

/// ALTER AGGREGATION POLICY statement.
///
/// Syntax variants:
/// - `ALTER AGGREGATION POLICY [IF EXISTS] <name> RENAME TO <new_name>`
/// - `ALTER AGGREGATION POLICY [IF EXISTS] <name> SET BODY -> <expression>`
/// - `ALTER AGGREGATION POLICY [IF EXISTS] <name> SET COMMENT = '<string>'`
/// - `ALTER AGGREGATION POLICY [IF EXISTS] <name> UNSET COMMENT`
/// - `ALTER AGGREGATION POLICY <name> SET TAG <tag> = '<value>' [, ...]`
/// - `ALTER AGGREGATION POLICY <name> UNSET TAG <tag> [, ...]`
#[derive(Debug, Clone)]
pub struct AstAlterAggregationPolicy {
    pub node_id: crate::ast::NodeId,
    /// Span covering the entire ALTER AGGREGATION POLICY statement
    pub span: Span,
    /// Optional typed-syntax node id for this statement
    pub syntax_id: Option<crate::syntax::SyntaxAlterAggregationPolicyStmtId>,

    // Keyword spans
    pub alter_span: Span,
    pub aggregation_span: Span, // AGGREGATION is Identifier!
    pub policy_span: Span,
    pub if_exists_span: Option<Span>,

    /// Span covering the policy name
    pub name_span: Span,

    /// Span covering the action portion of the statement
    pub action_span: Span,

    /// The action(s) to perform
    pub actions: Vec<AstAlterAggregationPolicyAction>,
}

/// A single action within an ALTER AGGREGATION POLICY statement.
#[derive(Debug, Clone)]
pub struct AstAlterAggregationPolicyAction {
    pub node_id: crate::ast::NodeId,
    /// Span covering this action
    pub span: Span,
    /// Optional typed-syntax node id for this action
    pub syntax_id: Option<crate::syntax::SyntaxAlterAggregationPolicyActionId>,
    /// The kind of action
    pub kind: AstAlterAggregationPolicyActionKind,
}

/// The kind of action in an ALTER AGGREGATION POLICY statement.
#[derive(Debug, Clone)]
pub enum AstAlterAggregationPolicyActionKind {
    /// RENAME TO <new_name>
    RenameTo {
        rename_span: Option<Span>,
        to_span: Option<Span>,
        new_name_span: Span,
    },

    /// `SET BODY -> <expression>`
    SetBody {
        set_span: Option<Span>,
        body_span: Option<Span>,
        arrow_span: Option<Span>,
        /// Span covering the body expression
        expression_span: Span,
        /// Parsed body expression (for semantic analysis via CST)
        expression: Option<Box<AstExpr>>,
    },

    /// `SET COMMENT = '<string>'`
    SetComment {
        set_span: Option<Span>,
        comment_span: Option<Span>,
        eq_span: Option<Span>,
        value_span: Span,
    },

    /// UNSET COMMENT
    UnsetComment {
        unset_span: Option<Span>,
        comment_span: Option<Span>,
    },

    /// `SET TAG <tag_name> = '<value>' [, ...]`
    SetTag {
        set_span: Option<Span>,
        tag_span: Option<Span>,
        /// Span covering tag assignments (comma-separated)
        tags_span: Span,
    },

    /// UNSET TAG <tag_name> [, ...]
    UnsetTag {
        unset_span: Option<Span>,
        tag_span: Option<Span>,
        /// Span covering tag names to unset
        tags_span: Span,
    },
}

/// DROP AGGREGATION POLICY statement.
///
/// Syntax: `DROP AGGREGATION POLICY <name>`
/// NOTE: IF EXISTS is NOT supported per Snowflake documentation
#[derive(Debug, Clone)]
pub struct AstDropAggregationPolicy {
    pub node_id: crate::ast::NodeId,
    /// Span covering the entire DROP AGGREGATION POLICY statement
    pub span: Span,
    /// Optional typed-syntax node id for this statement
    pub syntax_id: Option<crate::syntax::SyntaxDropAggregationPolicyId>,

    // Keyword spans
    pub drop_span: Span,
    pub aggregation_span: Span, // AGGREGATION is Identifier!
    pub policy_span: Span,
    pub if_exists_span: Option<Span>,

    /// Span covering the policy name (may be qualified)
    pub policy_name_span: Span,
}

// ============================================================================
// PROJECTION POLICY - Enterprise Edition feature
// ============================================================================

/// CREATE PROJECTION POLICY statement.
///
/// Defines column projection restrictions based on role/conditions.
/// PROJECTION POLICY is an Enterprise Edition feature that controls:
/// - Whether columns can be projected (appear in SELECT results)
/// - Enforcement style: FAIL (reject query) or NULLIFY (return NULL)
/// - Role-based or conditional projection logic
///
/// Unique syntax characteristics:
/// - Function-style body with arrow operator: `AS () RETURNS PROJECTION_CONSTRAINT -> <body>`
/// - Body is a SQL expression (can be CASE, function calls, etc.)
/// - PROJECTION_CONSTRAINT is both type name and function name
/// - Named parameters with fat arrow: ALLOW => true, ENFORCEMENT => 'FAIL'
///
/// Syntax:
/// ```text
/// CREATE [OR REPLACE] PROJECTION POLICY [IF NOT EXISTS] name
///   AS () RETURNS PROJECTION_CONSTRAINT -> <body_expression>
///   [COMMENT = '<string>']
/// ```
///
/// Example: CREATE PROJECTION POLICY analyst_only AS ()
///          RETURNS PROJECTION_CONSTRAINT ->
///            CASE
///              WHEN CURRENT_ROLE() = 'ANALYST'
///                THEN PROJECTION_CONSTRAINT(ALLOW => true)
///              ELSE PROJECTION_CONSTRAINT(ALLOW => false, ENFORCEMENT => 'NULLIFY')
///            END;
#[derive(Debug, Clone)]
pub struct AstCreateProjectionPolicy {
    pub node_id: crate::ast::NodeId,
    /// Span covering the entire CREATE PROJECTION POLICY statement
    pub span: Span,
    /// Optional typed-syntax node id for this statement
    pub syntax_id: Option<crate::syntax::SyntaxCreateProjectionPolicyId>,

    // Keyword spans (for semantic tracking and governance)
    pub create_span: Span,
    pub or_replace_span: Option<Span>,
    pub if_not_exists_span: Option<Span>,
    pub projection_span: Span, // PROJECTION is Identifier, not Keyword!
    pub policy_span: Span,

    /// Span covering the policy name identifier
    pub policy_name_span: Span,

    /// Span covering AS ()
    pub as_span: Option<Span>,
    pub empty_params_span: Option<Span>, // The () part

    /// Span covering RETURNS PROJECTION_CONSTRAINT
    pub returns_span: Option<Span>,
    pub return_type_span: Option<Span>, // PROJECTION_CONSTRAINT identifier

    /// Span covering the arrow operator ->
    pub arrow_span: Option<Span>,

    /// Span covering the entire body expression (after ->)
    /// Body can be: direct PROJECTION_CONSTRAINT(...) call or CASE expression
    pub body_span: Span,

    /// Optional parsed body expression (if parser delegates to expression parser)
    /// Body is a SQL expression that must call PROJECTION_CONSTRAINT function
    pub body_expr: Option<Box<AstExpr>>,

    /// COMMENT = 'string'
    pub comment_span: Option<Span>,

    /// Unknown clauses not recognized by parser (defensive design).
    /// PROJECTION POLICY has fixed syntax, but this allows graceful handling
    /// of future Snowflake additions without breaking existing code.
    pub extras: Vec<AstUnknownClause>,
}

/// ALTER PROJECTION POLICY statement.
///
/// Modifies properties of an existing projection policy.
/// Includes governance-critical operations like body changes and policy renames.
///
/// Syntax variants:
/// - RENAME TO: `ALTER PROJECTION POLICY [IF EXISTS] name RENAME TO new_name`
/// - SET BODY: `ALTER PROJECTION POLICY [IF EXISTS] name SET BODY -> <expression>`
/// - SET TAG: `ALTER PROJECTION POLICY name SET TAG tag = 'value' [, ...]`
/// - UNSET TAG: `ALTER PROJECTION POLICY name UNSET TAG tag [, ...]`
/// - SET COMMENT: `ALTER PROJECTION POLICY [IF EXISTS] name SET COMMENT = 'string'`
/// - UNSET COMMENT: `ALTER PROJECTION POLICY [IF EXISTS] name UNSET COMMENT`
#[derive(Debug, Clone)]
pub struct AstAlterProjectionPolicy {
    pub node_id: crate::ast::NodeId,
    /// Span covering the entire ALTER PROJECTION POLICY statement
    pub span: Span,
    /// Optional typed-syntax node id for this statement
    pub syntax_id: Option<crate::syntax::SyntaxAlterProjectionPolicyStmtId>,
    /// Span covering the ALTER keyword
    pub alter_span: Span,
    /// Span covering the PROJECTION identifier (not a keyword!)
    pub projection_span: Span,
    /// Span covering the POLICY keyword
    pub policy_span: Span,
    /// Optional span covering IF EXISTS
    pub if_exists_span: Option<Span>,
    /// Span covering the policy name
    pub name_span: Span,
    /// Span covering the action (everything after the policy name)
    pub action_span: Span,
    /// Parsed action
    pub action: AstAlterProjectionPolicyAction,
}

/// One ALTER PROJECTION POLICY action.
#[derive(Debug, Clone)]
pub struct AstAlterProjectionPolicyAction {
    pub node_id: crate::ast::NodeId,
    /// Span covering the entire action
    pub span: Span,
    /// Optional typed-syntax node id for this action
    pub syntax_id: Option<crate::syntax::SyntaxAlterProjectionPolicyActionId>,
    pub kind: AstAlterProjectionPolicyActionKind,
}

/// ALTER PROJECTION POLICY action kinds.
#[derive(Debug, Clone)]
pub enum AstAlterProjectionPolicyActionKind {
    /// RENAME TO <new_name>
    /// Supports IF EXISTS: ALTER PROJECTION POLICY [ IF EXISTS ] name RENAME TO new_name
    RenameTo {
        rename_span: Option<Span>,
        to_span: Option<Span>,
        new_name_span: Span,
    },

    /// `SET BODY -> <expression>`
    /// Body is a SQL expression that must call PROJECTION_CONSTRAINT function
    /// Supports IF EXISTS: ALTER PROJECTION POLICY [ IF EXISTS ] name SET BODY -> expr
    SetBody {
        set_span: Option<Span>,
        body_span: Option<Span>,
        arrow_span: Option<Span>,
        /// Span covering the entire body expression (after ->)
        expression_span: Span,
        /// Optional parsed body expression
        body_expr: Option<Box<AstExpr>>,
    },

    /// `SET TAG <tag_name> = '<value>' [, ...]`
    SetTag {
        set_span: Option<Span>,
        tag_span: Option<Span>,
        /// Tag assignments as spans (covers "tag = 'value'" pairs)
        assignments_span: Span,
    },

    /// UNSET TAG <tag_name> [, ...]
    UnsetTag {
        unset_span: Option<Span>,
        tag_span: Option<Span>,
        /// Tag names to unset (comma-separated spans)
        tags_span: Span,
    },

    /// `SET COMMENT = '<string>'`
    /// Supports IF EXISTS: ALTER PROJECTION POLICY [ IF EXISTS ] name SET COMMENT = 'value'
    SetComment {
        set_span: Option<Span>,
        comment_span: Option<Span>,
        eq_span: Option<Span>,
        comment_value_span: Span,
    },

    /// UNSET COMMENT
    /// Supports IF EXISTS: ALTER PROJECTION POLICY [ IF EXISTS ] name UNSET COMMENT
    UnsetComment {
        unset_span: Option<Span>,
        comment_span: Option<Span>,
    },
}

/// DROP PROJECTION POLICY statement.
///
/// Removes a projection policy from the schema.
/// Note: Snowflake DROP PROJECTION POLICY does NOT support IF EXISTS.
///
/// Syntax: DROP PROJECTION POLICY name
#[derive(Debug, Clone)]
pub struct AstDropProjectionPolicy {
    pub node_id: crate::ast::NodeId,
    /// Span covering the entire DROP PROJECTION POLICY statement
    pub span: Span,
    /// Optional typed-syntax node id for this statement
    pub syntax_id: Option<crate::syntax::SyntaxDropProjectionPolicyId>,

    // Keyword spans
    pub drop_span: Span,
    pub projection_span: Span, // PROJECTION is Identifier, not Keyword!
    pub policy_span: Span,
    pub if_exists_span: Option<Span>,

    /// Span covering the policy name (may be qualified: db.schema.policy)
    pub policy_name_span: Span,
}

// ============================================================================
// STORAGE INTEGRATION - Cloud storage access configuration
// ============================================================================

/// CREATE STORAGE INTEGRATION statement.
///
/// Creates a storage integration that stores cloud provider credentials and
/// access configuration for external stages. Supported providers: S3, GCS, Azure.
///
/// Storage integrations enable:
/// - Secure credential management without hardcoding in stage definitions
/// - Centralized access control via allowed/blocked location lists
/// - Private connectivity options (PrivateLink) for enhanced security
///
/// Syntax: CREATE [OR REPLACE] STORAGE INTEGRATION [IF NOT EXISTS] name
///         TYPE = EXTERNAL_STAGE
///         STORAGE_PROVIDER = 'S3' | 'S3GOV' | 'S3CHINA' | 'GCS' | 'AZURE'
///         <cloud_provider_params>
///         ENABLED = TRUE | FALSE
///         STORAGE_ALLOWED_LOCATIONS = ('url' [, 'url' ...])
///         [STORAGE_BLOCKED_LOCATIONS = ('url' [, 'url' ...])]
///         [COMMENT = 'string']
///
/// Cloud provider params:
/// - AWS: `STORAGE_AWS_ROLE_ARN, [STORAGE_AWS_EXTERNAL_ID], [STORAGE_AWS_OBJECT_ACL], [USE_PRIVATELINK_ENDPOINT]`
/// - Azure: `AZURE_TENANT_ID, [USE_PRIVATELINK_ENDPOINT]`
/// - GCS: (no additional required params)
#[derive(Debug, Clone)]
pub struct AstCreateStorageIntegration {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    pub syntax_id: Option<crate::syntax::SyntaxCreateStorageIntegrationId>,

    // Keyword spans
    pub create_span: Span,
    pub or_replace_span: Option<Span>,
    pub if_not_exists_span: Option<Span>,
    pub storage_span: Span,
    pub integration_span: Span,

    pub integration_name_span: Span,

    // Required property spans (cover "PROP = value")
    pub type_span: Option<Span>,
    pub storage_provider_span: Option<Span>,
    pub enabled_span: Option<Span>,
    pub storage_allowed_locations_span: Option<Span>,

    // Optional property spans
    pub storage_blocked_locations_span: Option<Span>,
    pub comment_span: Option<Span>,

    // AWS-specific property spans
    pub storage_aws_role_arn_span: Option<Span>,
    pub storage_aws_external_id_span: Option<Span>,
    pub storage_aws_object_acl_span: Option<Span>,

    // Azure-specific property spans
    pub azure_tenant_id_span: Option<Span>,

    // Common optional property spans
    pub use_privatelink_endpoint_span: Option<Span>,
}

/// ALTER STORAGE INTEGRATION statement.
///
/// Modifies properties of an existing storage integration.
///
/// Syntax:
/// ```text
/// ALTER [STORAGE] INTEGRATION [IF EXISTS] name SET ...
/// ALTER [STORAGE] INTEGRATION [IF EXISTS] name SET TAG ...
/// ALTER [STORAGE] INTEGRATION name UNSET TAG ...
/// ALTER [STORAGE] INTEGRATION [IF EXISTS] name UNSET ...
/// ```
#[derive(Debug, Clone)]
pub struct AstAlterStorageIntegration {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    pub syntax_id: Option<crate::syntax::SyntaxAlterStorageIntegrationStmtId>,
    pub alter_span: Span,
    pub storage_span: Option<Span>, // Optional STORAGE keyword
    pub integration_span: Span,
    pub if_exists_span: Option<Span>,
    pub name_span: Span,
    pub action_span: Span,
    pub actions: Vec<AstAlterStorageIntegrationAction>,
}

#[derive(Debug, Clone)]
pub struct AstAlterStorageIntegrationAction {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    pub syntax_id: Option<crate::syntax::SyntaxAlterStorageIntegrationActionId>,
    pub kind: AstAlterStorageIntegrationActionKind,
}

#[derive(Debug, Clone)]
pub enum AstAlterStorageIntegrationActionKind {
    /// SET ENABLED = TRUE|FALSE
    SetEnabled {
        set_span: Option<Span>,
        property_span: Span,
        eq_span: Option<Span>,
        value_span: Span,
    },

    /// UNSET ENABLED
    UnsetEnabled {
        unset_span: Option<Span>,
        property_span: Span,
    },

    /// SET STORAGE_ALLOWED_LOCATIONS = (...)
    SetStorageAllowedLocations {
        set_span: Option<Span>,
        property_span: Span,
        eq_span: Option<Span>,
        value_span: Span,
    },

    /// SET STORAGE_BLOCKED_LOCATIONS = (...)
    SetStorageBlockedLocations {
        set_span: Option<Span>,
        property_span: Span,
        eq_span: Option<Span>,
        value_span: Span,
    },

    /// UNSET STORAGE_BLOCKED_LOCATIONS
    UnsetStorageBlockedLocations {
        unset_span: Option<Span>,
        property_span: Span,
    },

    /// SET STORAGE_AWS_ROLE_ARN = '...'
    SetAwsRoleArn {
        set_span: Option<Span>,
        property_span: Span,
        eq_span: Option<Span>,
        value_span: Span,
    },

    /// SET STORAGE_AWS_EXTERNAL_ID = '...'
    SetAwsExternalId {
        set_span: Option<Span>,
        property_span: Span,
        eq_span: Option<Span>,
        value_span: Span,
    },

    /// SET STORAGE_AWS_OBJECT_ACL = '...'
    SetAwsObjectAcl {
        set_span: Option<Span>,
        property_span: Span,
        eq_span: Option<Span>,
        value_span: Span,
    },

    /// SET AZURE_TENANT_ID = '...'
    SetAzureTenantId {
        set_span: Option<Span>,
        property_span: Span,
        eq_span: Option<Span>,
        value_span: Span,
    },

    /// SET USE_PRIVATELINK_ENDPOINT = TRUE|FALSE
    SetUsePrivatelinkEndpoint {
        set_span: Option<Span>,
        property_span: Span,
        eq_span: Option<Span>,
        value_span: Span,
    },

    /// SET COMMENT = '...'
    SetComment {
        set_span: Option<Span>,
        comment_span: Span,
        eq_span: Option<Span>,
        value_span: Span,
    },

    /// UNSET COMMENT
    UnsetComment {
        unset_span: Option<Span>,
        comment_span: Span,
    },

    /// SET TAG tag_name = 'tag_value' [, ...]
    SetTag {
        set_span: Option<Span>,
        tag_span: Span,
        tags_value_span: Span,
    },

    /// UNSET TAG tag_name [, ...]
    UnsetTag {
        unset_span: Option<Span>,
        tag_span: Span,
        tag_names_span: Span,
    },
}

/// DROP INTEGRATION (STORAGE) statement.
///
/// Removes a storage integration from the account.
/// Note: Can use either "DROP STORAGE INTEGRATION" or "DROP INTEGRATION" syntax.
///
/// Syntax: `DROP [STORAGE] INTEGRATION [IF EXISTS] name`
#[derive(Debug, Clone)]
pub struct AstDropStorageIntegration {
    pub node_id: crate::ast::NodeId,
    /// Span covering the entire `DROP [STORAGE] INTEGRATION` statement
    pub span: Span,
    /// Optional typed-syntax node id for this statement
    pub syntax_id: Option<crate::syntax::SyntaxDropStorageIntegrationId>,

    // Keyword spans
    pub drop_span: Span,
    pub storage_span: Option<Span>, // Optional STORAGE keyword
    pub integration_span: Span,
    pub if_exists_span: Option<Span>,

    /// Span covering the integration name
    pub integration_name_span: Span,
}

// ============================================================================
// EXTERNAL ACCESS INTEGRATION - Network egress control
// ============================================================================

/// CREATE EXTERNAL ACCESS INTEGRATION statement.
///
/// Controls network egress from Snowflake to external endpoints.
/// This is a security-critical statement that allows UDFs/procedures
/// to make outbound network requests.
///
/// Syntax:
/// ```sql
/// CREATE [OR REPLACE] EXTERNAL ACCESS INTEGRATION <name>
///   ALLOWED_NETWORK_RULES = ( <rule_name> [ , ... ] )
///   [ ALLOWED_API_AUTHENTICATION_INTEGRATIONS = ( { <name> [ , ... ] | none } ) ]
///   [ ALLOWED_AUTHENTICATION_SECRETS = ( { <name> [ , ... ] | all | none } ) ]
///   ENABLED = { TRUE | FALSE }
///   [ COMMENT = '<string>' ]
/// ```
///
/// Token notes:
/// - EXTERNAL is Identifier, NOT Keyword
/// - All property names (ALLOWED_NETWORK_RULES, ENABLED, etc.) are Identifiers
/// - ALL is Keyword(All), NONE is Identifier
/// - TRUE/FALSE are Literal(Boolean)
#[derive(Debug, Clone)]
pub struct AstCreateExternalAccessIntegration {
    pub node_id: crate::ast::NodeId,
    /// Span covering the entire CREATE EXTERNAL ACCESS INTEGRATION statement
    pub span: Span,
    /// Optional typed-syntax node id for this statement
    pub syntax_id: Option<crate::syntax::SyntaxCreateExternalAccessIntegrationId>,

    // Keyword spans
    pub create_span: Span,
    pub or_replace_span: Option<Span>,
    pub if_not_exists_span: Option<Span>,
    /// "EXTERNAL" is Identifier, not Keyword
    pub external_span: Span,
    pub access_span: Span,
    pub integration_span: Span,

    /// Span covering the integration name identifier
    pub integration_name_span: Span,

    /// ALLOWED_NETWORK_RULES = ( rule_name, ... )
    /// Required for CREATE statement
    pub allowed_network_rules_span: Option<Span>,

    /// ALLOWED_API_AUTHENTICATION_INTEGRATIONS = ( name | none )
    pub allowed_api_authentication_integrations_span: Option<Span>,

    /// ALLOWED_AUTHENTICATION_SECRETS = ( name | all | none )
    pub allowed_authentication_secrets_span: Option<Span>,

    /// ENABLED = TRUE | FALSE
    /// Required for CREATE statement
    pub enabled_span: Option<Span>,

    /// COMMENT = 'string'
    pub comment_span: Option<Span>,

    /// Unknown properties not recognized by parser (defensive design)
    pub extras: Vec<AstUnknownClause>,
}

/// ALTER EXTERNAL ACCESS INTEGRATION statement.
///
/// Modifies an existing external access integration.
///
/// Syntax variants:
/// - `ALTER EXTERNAL ACCESS INTEGRATION [IF EXISTS] <name> SET <properties>`
/// - `ALTER EXTERNAL ACCESS INTEGRATION [IF EXISTS] <name> UNSET <properties>`
/// - `ALTER EXTERNAL ACCESS INTEGRATION <name> SET TAG <tag_name> = '<value>' [, ...]`
/// - `ALTER EXTERNAL ACCESS INTEGRATION <name> UNSET TAG <tag_name> [, ...]`
#[derive(Debug, Clone)]
pub struct AstAlterExternalAccessIntegration {
    pub node_id: crate::ast::NodeId,
    /// Span covering the entire ALTER EXTERNAL ACCESS INTEGRATION statement
    pub span: Span,
    /// Optional typed-syntax node id for this statement
    pub syntax_id: Option<crate::syntax::SyntaxAlterExternalAccessIntegrationStmtId>,

    pub alter_span: Span,
    /// "EXTERNAL" is Identifier, not Keyword
    pub external_span: Span,
    pub access_span: Span,
    pub integration_span: Span,
    pub if_exists_span: Option<Span>,
    pub name_span: Span,

    /// Span covering the entire action clause (SET/UNSET/SET TAG/UNSET TAG)
    pub action_span: Span,

    /// The action(s) being performed
    pub actions: Vec<AstAlterExternalAccessIntegrationAction>,
}

/// ALTER EXTERNAL ACCESS INTEGRATION action.
#[derive(Debug, Clone)]
pub struct AstAlterExternalAccessIntegrationAction {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    pub syntax_id: Option<crate::syntax::SyntaxAlterExternalAccessIntegrationActionId>,
    pub kind: AstAlterExternalAccessIntegrationActionKind,
}

/// ALTER EXTERNAL ACCESS INTEGRATION action kinds.
#[derive(Debug, Clone)]
pub enum AstAlterExternalAccessIntegrationActionKind {
    /// SET ALLOWED_NETWORK_RULES = ( rule_name, ... )
    SetAllowedNetworkRules {
        set_span: Option<Span>,
        property_span: Span,
        eq_span: Option<Span>,
        value_span: Span,
    },

    /// SET ALLOWED_API_AUTHENTICATION_INTEGRATIONS = ( name | none )
    SetAllowedApiAuthenticationIntegrations {
        set_span: Option<Span>,
        property_span: Span,
        eq_span: Option<Span>,
        value_span: Span,
    },

    /// SET ALLOWED_AUTHENTICATION_SECRETS = ( name | all | none )
    SetAllowedAuthenticationSecrets {
        set_span: Option<Span>,
        property_span: Span,
        eq_span: Option<Span>,
        value_span: Span,
    },

    /// SET ENABLED = TRUE | FALSE
    SetEnabled {
        set_span: Option<Span>,
        property_span: Span,
        eq_span: Option<Span>,
        value_span: Span,
    },

    /// SET COMMENT = 'value'
    SetComment {
        set_span: Option<Span>,
        comment_span: Span,
        eq_span: Option<Span>,
        value_span: Span,
    },

    /// SET TAG tag_name = 'value' [, ...]
    SetTag {
        set_span: Option<Span>,
        tag_span: Option<Span>,
        tags_span: Span,
    },

    /// UNSET ALLOWED_NETWORK_RULES
    UnsetAllowedNetworkRules {
        unset_span: Option<Span>,
        property_span: Span,
    },

    /// UNSET ALLOWED_API_AUTHENTICATION_INTEGRATIONS
    UnsetAllowedApiAuthenticationIntegrations {
        unset_span: Option<Span>,
        property_span: Span,
    },

    /// UNSET ALLOWED_AUTHENTICATION_SECRETS
    UnsetAllowedAuthenticationSecrets {
        unset_span: Option<Span>,
        property_span: Span,
    },

    /// UNSET ENABLED
    UnsetEnabled {
        unset_span: Option<Span>,
        property_span: Span,
    },

    /// UNSET COMMENT
    UnsetComment {
        unset_span: Option<Span>,
        comment_span: Span,
    },

    /// UNSET TAG tag_name [, ...]
    UnsetTag {
        unset_span: Option<Span>,
        tag_span: Option<Span>,
        tags_span: Span,
    },

    /// RENAME TO new_name
    Rename {
        rename_span: Span,
        to_span: Span,
        new_name_span: Span,
    },
}

/// DROP EXTERNAL ACCESS INTEGRATION statement.
///
/// Removes an external access integration from the account.
///
/// Syntax: `DROP [EXTERNAL ACCESS] INTEGRATION [IF EXISTS] <name>`
#[derive(Debug, Clone)]
pub struct AstDropExternalAccessIntegration {
    pub node_id: crate::ast::NodeId,
    /// Span covering the entire DROP EXTERNAL ACCESS INTEGRATION statement
    pub span: Span,
    /// Optional typed-syntax node id for this statement
    pub syntax_id: Option<crate::syntax::SyntaxDropExternalAccessIntegrationId>,

    // Keyword spans
    pub drop_span: Span,
    /// "EXTERNAL" is Identifier, not Keyword
    pub external_span: Option<Span>, // Optional - can be just "DROP INTEGRATION"
    pub access_span: Option<Span>, // Optional
    pub integration_span: Span,
    pub if_exists_span: Option<Span>,

    /// Span covering the integration name
    pub integration_name_span: Span,
}

/// PostgreSQL RETURNING clause for INSERT/UPDATE/DELETE
#[derive(Debug, Clone)]
pub struct AstOutputClause {
    pub node_id: crate::ast::NodeId,
    pub output_span: Span,
    pub span: Span,
}

/// PostgreSQL RETURNING clause for INSERT/UPDATE/DELETE
#[derive(Debug, Clone)]
pub struct AstReturning {
    pub node_id: crate::ast::NodeId,
    pub syntax_id: Option<crate::syntax::SyntaxReturningId>,
    pub returning_span: Span,
    pub items: Vec<AstReturningItem>,
    pub span: Span,
}

/// A single item in a RETURNING clause: expr [AS alias]
#[derive(Debug, Clone)]
pub struct AstReturningItem {
    pub node_id: crate::ast::NodeId,
    pub expr: Box<AstExpr>,
    pub alias: Option<AstIdentifierWithAs>,
    pub span: Span,
}

// ============================================================================
// DATABASE AND SCHEMA STATEMENTS
// ============================================================================

/// CREATE DATABASE statement.
///
/// Snowflake syntax variants:
/// - `CREATE [OR REPLACE] [TRANSIENT] DATABASE [IF NOT EXISTS] name [CLONE source [AT|BEFORE (...)]] [properties...]`
/// - CREATE DATABASE name FROM SHARE provider.share_name
/// - `CREATE DATABASE name FROM LISTING listing_name [FILTERS]`
/// - CREATE DATABASE name AS REPLICA OF account.db
#[derive(Debug, Clone)]
pub struct AstCreateDatabase {
    pub node_id: crate::ast::NodeId,
    /// Span covering the entire CREATE DATABASE statement
    pub span: Span,
    /// Span covering CREATE keyword
    pub create_span: Span,
    /// Optional OR REPLACE span
    pub or_replace_span: Option<Span>,
    /// Optional TRANSIENT span
    pub transient_span: Option<Span>,
    /// Span covering DATABASE keyword
    pub database_span: Span,
    /// Optional IF NOT EXISTS span
    pub if_not_exists_span: Option<Span>,
    /// Span covering the database name
    pub name_span: Span,
    /// The creation variant
    pub variant: AstCreateDatabaseVariant,
    /// Optional properties span (DATA_RETENTION_TIME_IN_DAYS, etc.)
    pub properties_span: Option<Span>,
    /// Optional COMMENT clause span
    pub comment_span: Option<Span>,
    /// Optional TAG clause span
    pub tag_span: Option<Span>,
    /// Unknown properties/clauses (defensive design)
    pub extras: Vec<AstUnknownClause>,
}

/// Variants for CREATE DATABASE
#[derive(Debug, Clone)]
pub enum AstCreateDatabaseVariant {
    /// Standard CREATE DATABASE (no CLONE, FROM SHARE, etc.)
    Standard,
    /// CREATE DATABASE ... CLONE source [AT|BEFORE (...)] [IGNORE TABLES WITH INSUFFICIENT DATA RETENTION]
    Clone {
        /// Span covering CLONE keyword
        clone_span: Span,
        /// Span covering the source database name
        source_span: Span,
        /// Optional time travel clause
        time_travel: Option<Box<AstTimeTravelClause>>,
        /// Optional IGNORE TABLES WITH INSUFFICIENT DATA RETENTION span
        ignore_tables_span: Option<Span>,
    },
    /// CREATE DATABASE ... FROM SHARE provider.share_name
    FromShare {
        /// Span covering FROM SHARE keywords
        from_share_span: Span,
        /// Span covering the share reference (provider.share_name)
        share_name_span: Span,
    },
    /// `CREATE DATABASE ... FROM LISTING listing_global_name [FILTERS]`
    FromListing {
        /// Span covering FROM LISTING keywords
        from_listing_span: Span,
        /// Span covering the listing global name
        listing_name_span: Span,
    },
    /// CREATE DATABASE ... AS REPLICA OF account.db
    AsReplica {
        /// Span covering AS REPLICA OF keywords
        as_replica_span: Span,
        /// Span covering the source database reference
        source_db_span: Span,
    },
    /// CREATE DATABASE ... FROM BACKUP SET ...
    FromBackup {
        /// Span covering FROM BACKUP SET keywords
        from_backup_span: Span,
        /// Span covering the backup specification
        backup_spec_span: Span,
    },
}

/// ALTER DATABASE statement.
#[derive(Debug, Clone)]
pub struct AstAlterDatabase {
    pub node_id: crate::ast::NodeId,
    /// Span covering the entire ALTER DATABASE statement
    pub span: Span,
    /// Span covering ALTER keyword
    pub alter_span: Span,
    /// Span covering DATABASE keyword
    pub database_span: Span,
    /// Optional IF EXISTS span
    pub if_exists_span: Option<Span>,
    /// Span covering the database name
    pub name_span: Span,
    /// The alter action
    pub action: AstAlterDatabaseAction,
    /// Unknown properties/clauses (defensive design)
    pub extras: Vec<AstUnknownClause>,
}

/// ALTER DATABASE action
#[derive(Debug, Clone)]
pub struct AstAlterDatabaseAction {
    pub node_id: crate::ast::NodeId,
    /// Span covering the entire action
    pub span: Span,
    pub kind: AstAlterDatabaseActionKind,
}

/// ALTER DATABASE action kinds
#[derive(Debug, Clone)]
pub enum AstAlterDatabaseActionKind {
    /// RENAME TO new_name
    RenameTo {
        rename_span: Span,
        to_span: Span,
        new_name_span: Span,
    },
    /// SWAP WITH other_db
    SwapWith {
        swap_span: Span,
        with_span: Span,
        other_db_span: Span,
    },
    /// SET property = value [, ...]
    SetProperties {
        set_span: Span,
        /// Span covering all property assignments
        properties_span: Span,
    },
    /// UNSET property [, ...]
    UnsetProperties {
        unset_span: Span,
        /// Span covering the property names
        properties_span: Span,
    },
    /// SET TAG tag = value [, ...]
    SetTag {
        set_span: Span,
        tag_span: Span,
        /// Span covering tag assignments
        assignments_span: Span,
    },
    /// UNSET TAG tag [, ...]
    UnsetTag {
        unset_span: Span,
        tag_span: Span,
        /// Span covering tag names
        tags_span: Span,
    },
    /// SET COMMENT = '...'
    SetComment { set_span: Span, comment_span: Span },
    /// UNSET COMMENT
    UnsetComment {
        unset_span: Span,
        comment_span: Span,
    },
    /// ENABLE REPLICATION TO ACCOUNTS account [, ...] [IGNORE EDITION CHECK]
    EnableReplication {
        enable_span: Span,
        replication_span: Span,
        to_accounts_span: Span,
        /// Optional IGNORE EDITION CHECK span
        ignore_edition_span: Option<Span>,
    },
    /// DISABLE REPLICATION [TO ACCOUNTS account [, ...]]
    DisableReplication {
        disable_span: Span,
        replication_span: Span,
        /// Optional TO ACCOUNTS clause span
        to_accounts_span: Option<Span>,
    },
    /// REFRESH
    Refresh { refresh_span: Span },
    /// ENABLE FAILOVER TO ACCOUNTS account [, ...]
    EnableFailover {
        enable_span: Span,
        failover_span: Span,
        to_accounts_span: Span,
    },
    /// DISABLE FAILOVER [TO ACCOUNTS account [, ...]]
    DisableFailover {
        disable_span: Span,
        failover_span: Span,
        /// Optional TO ACCOUNTS clause span
        to_accounts_span: Option<Span>,
    },
    /// PRIMARY
    Primary { primary_span: Span },
    /// Unknown action (defensive design)
    Unknown(AstUnknownClause),
}

/// DROP DATABASE statement.
#[derive(Debug, Clone)]
pub struct AstDropDatabase {
    pub node_id: crate::ast::NodeId,
    /// Span covering the entire DROP DATABASE statement
    pub span: Span,
    /// Span covering DROP keyword
    pub drop_span: Span,
    /// Span covering DATABASE keyword
    pub database_span: Span,
    /// Optional IF EXISTS span
    pub if_exists_span: Option<Span>,
    /// Span covering the database name
    pub name_span: Span,
    /// Optional CASCADE or RESTRICT span
    pub cascade_restrict_span: Option<Span>,
}

/// UNDROP DATABASE statement.
#[derive(Debug, Clone)]
pub struct AstUndropDatabase {
    pub node_id: crate::ast::NodeId,
    /// Span covering the entire UNDROP DATABASE statement
    pub span: Span,
    /// Span covering UNDROP keyword
    pub undrop_span: Span,
    /// Span covering DATABASE keyword
    pub database_span: Span,
    /// Span covering the database name
    pub name_span: Span,
}

/// CREATE SCHEMA statement.
///
/// Snowflake syntax variants:
/// - `CREATE [OR REPLACE] [TRANSIENT] SCHEMA [IF NOT EXISTS] name [CLONE source [AT|BEFORE (...)]] [WITH MANAGED ACCESS] [properties...]`
#[derive(Debug, Clone)]
pub struct AstCreateSchema {
    pub node_id: crate::ast::NodeId,
    /// Span covering the entire CREATE SCHEMA statement
    pub span: Span,
    /// Span covering CREATE keyword
    pub create_span: Span,
    /// Optional OR REPLACE span
    pub or_replace_span: Option<Span>,
    /// Optional TRANSIENT span
    pub transient_span: Option<Span>,
    /// Span covering SCHEMA keyword
    pub schema_span: Span,
    /// Optional IF NOT EXISTS span
    pub if_not_exists_span: Option<Span>,
    /// Span covering the schema name (may be qualified: db.schema)
    pub name_span: Span,
    /// The creation variant
    pub variant: AstCreateSchemaVariant,
    /// Optional properties span (DATA_RETENTION_TIME_IN_DAYS, etc.)
    pub properties_span: Option<Span>,
    /// Optional WITH MANAGED ACCESS span (Snowflake)
    pub with_managed_access_span: Option<Span>,
    /// Optional MANAGED LOCATION clause span (Databricks Unity Catalog)
    pub managed_location_span: Option<Span>,
    /// Optional LOCATION clause span (Databricks Hive metastore)
    pub location_span: Option<Span>,
    /// Optional DEFAULT COLLATION clause span (Databricks)
    pub default_collation_span: Option<Span>,
    /// Optional WITH DBPROPERTIES clause span (Databricks)
    pub dbproperties_span: Option<Span>,
    /// Optional COMMENT clause span
    pub comment_span: Option<Span>,
    /// Optional TAG clause span
    pub tag_span: Option<Span>,
    /// Unknown properties/clauses (defensive design)
    pub extras: Vec<AstUnknownClause>,
}

/// Variants for CREATE SCHEMA
#[derive(Debug, Clone)]
pub enum AstCreateSchemaVariant {
    /// Standard CREATE SCHEMA (no CLONE)
    Standard,
    /// CREATE SCHEMA ... CLONE source [AT|BEFORE (...)] [IGNORE TABLES WITH INSUFFICIENT DATA RETENTION]
    Clone {
        /// Span covering CLONE keyword
        clone_span: Span,
        /// Span covering the source schema name
        source_span: Span,
        /// Optional time travel clause
        time_travel: Option<Box<AstTimeTravelClause>>,
        /// Optional IGNORE TABLES WITH INSUFFICIENT DATA RETENTION span
        ignore_tables_span: Option<Span>,
    },
}

/// ALTER SCHEMA statement.
#[derive(Debug, Clone)]
pub struct AstAlterSchema {
    pub node_id: crate::ast::NodeId,
    /// Span covering the entire ALTER SCHEMA statement
    pub span: Span,
    /// Span covering ALTER keyword
    pub alter_span: Span,
    /// Span covering SCHEMA keyword
    pub schema_span: Span,
    /// Optional IF EXISTS span
    pub if_exists_span: Option<Span>,
    /// Span covering the schema name (may be qualified)
    pub name_span: Span,
    /// The alter action
    pub action: AstAlterSchemaAction,
    /// Unknown properties/clauses (defensive design)
    pub extras: Vec<AstUnknownClause>,
}

/// ALTER SCHEMA action
#[derive(Debug, Clone)]
pub struct AstAlterSchemaAction {
    pub node_id: crate::ast::NodeId,
    /// Span covering the entire action
    pub span: Span,
    pub kind: AstAlterSchemaActionKind,
}

/// ALTER SCHEMA action kinds
#[derive(Debug, Clone)]
pub enum AstAlterSchemaActionKind {
    /// RENAME TO new_name
    RenameTo {
        rename_span: Span,
        to_span: Span,
        new_name_span: Span,
    },
    /// SWAP WITH other_schema
    SwapWith {
        swap_span: Span,
        with_span: Span,
        other_schema_span: Span,
    },
    /// SET property = value [, ...]
    SetProperties {
        set_span: Span,
        /// Span covering all property assignments
        properties_span: Span,
    },
    /// UNSET property [, ...]
    UnsetProperties {
        unset_span: Span,
        /// Span covering the property names
        properties_span: Span,
    },
    /// SET TAG tag = value [, ...]
    SetTag {
        set_span: Span,
        tag_span: Span,
        /// Span covering tag assignments
        assignments_span: Span,
    },
    /// UNSET TAG tag [, ...]
    UnsetTag {
        unset_span: Span,
        tag_span: Span,
        /// Span covering tag names
        tags_span: Span,
    },
    /// SET COMMENT = '...'
    SetComment { set_span: Span, comment_span: Span },
    /// UNSET COMMENT
    UnsetComment {
        unset_span: Span,
        comment_span: Span,
    },
    /// ENABLE MANAGED ACCESS
    EnableManagedAccess {
        enable_span: Span,
        managed_access_span: Span,
    },
    /// DISABLE MANAGED ACCESS
    DisableManagedAccess {
        disable_span: Span,
        managed_access_span: Span,
    },
    /// SET MANAGED ACCESS (Snowflake alternate spelling to ENABLE MANAGED ACCESS)
    SetManagedAccess {
        set_span: Span,
        managed_access_span: Span,
    },
    /// UNSET MANAGED ACCESS (Snowflake alternate spelling to DISABLE MANAGED ACCESS)
    UnsetManagedAccess {
        unset_span: Span,
        managed_access_span: Span,
    },
    /// SET DBPROPERTIES (key = val, ...) (Databricks)
    SetDbProperties {
        set_span: Option<Span>,
        dbproperties_span: Span,
    },
    /// `[SET] OWNER TO principal` (Databricks)
    OwnerTo {
        set_span: Option<Span>,
        owner_span: Span,
        to_span: Span,
        principal_span: Span,
    },
    /// {ENABLE | DISABLE | INHERIT} PREDICTIVE OPTIMIZATION (Databricks)
    PredictiveOptimization {
        /// Span of ENABLE, DISABLE, or INHERIT keyword
        action_span: Span,
        /// Span covering PREDICTIVE OPTIMIZATION
        predictive_optimization_span: Span,
    },
    /// DEFAULT COLLATION name (Databricks)
    DefaultCollation {
        default_span: Span,
        collation_span: Span,
        collation_name_span: Span,
    },
    /// SET TAGS (Databricks - note: TAGS is Identifier, not Keyword)
    SetTags {
        set_span: Span,
        tags_span: Span,
        assignments_span: Span,
    },
    /// UNSET TAGS (Databricks - note: TAGS is Identifier, not Keyword)
    UnsetTags {
        unset_span: Span,
        tags_span: Span,
        tag_list_span: Span,
    },
    /// Unknown action (defensive design)
    Unknown(AstUnknownClause),
}

/// DROP SCHEMA statement.
#[derive(Debug, Clone)]
pub struct AstDropSchema {
    pub node_id: crate::ast::NodeId,
    /// Span covering the entire DROP SCHEMA statement
    pub span: Span,
    /// Span covering DROP keyword
    pub drop_span: Span,
    /// Span covering SCHEMA keyword
    pub schema_span: Span,
    /// Optional IF EXISTS span
    pub if_exists_span: Option<Span>,
    /// Span covering the schema name (may be qualified)
    pub name_span: Span,
    /// Optional CASCADE or RESTRICT span
    pub cascade_restrict_span: Option<Span>,
}

/// UNDROP SCHEMA statement.
#[derive(Debug, Clone)]
pub struct AstUndropSchema {
    pub node_id: crate::ast::NodeId,
    /// Span covering the entire UNDROP SCHEMA statement
    pub span: Span,
    /// Span covering UNDROP keyword
    pub undrop_span: Span,
    /// Span covering SCHEMA keyword
    pub schema_span: Span,
    /// Span covering the schema name (may be qualified)
    pub name_span: Span,
}

/// UNDROP TABLE statement.
#[derive(Debug, Clone)]
pub struct AstUndropTable {
    pub node_id: crate::ast::NodeId,
    /// Span covering the entire UNDROP TABLE statement
    pub span: Span,
    /// Span covering UNDROP keyword
    pub undrop_span: Span,
    /// Span covering TABLE keyword
    pub table_span: Span,
    /// Span covering the table name (may be qualified)
    pub name_span: Span,
}

/// Snowflake UNDROP TYPE statement
///
/// `UNDROP TYPE <name>`
#[derive(Debug, Clone)]
pub struct AstUndropType {
    pub node_id: crate::ast::NodeId,
    /// Span covering the entire UNDROP TYPE statement
    pub span: Span,
    /// Span covering UNDROP keyword
    pub undrop_span: Span,
    /// Span covering TYPE keyword
    pub type_span: Span,
    /// Span covering the type name (may be qualified)
    pub name_span: Span,
}

// ============================================================================
// END DATABASE AND SCHEMA STATEMENTS
// ============================================================================

// ============================================================================
// TAG STATEMENTS (Snowflake object tagging)
// ============================================================================

/// CREATE TAG statement (Snowflake).
///
/// Syntax:
/// ```text
/// CREATE [OR REPLACE] TAG [IF NOT EXISTS] <name>
///     [ALLOWED_VALUES '<v1>' [, ...]]
///     [PROPAGATE = <mode> [ON_CONFLICT = <resolution>]]
///     [COMMENT = '<string>']
/// ```
#[derive(Debug, Clone)]
pub struct AstCreateTag {
    pub node_id: crate::ast::NodeId,
    /// Span covering the entire CREATE TAG statement
    pub span: Span,

    // Keyword spans
    pub create_span: Span,
    pub or_replace_span: Option<Span>,
    pub tag_span: Span,
    pub if_not_exists_span: Option<Span>,

    /// Span covering the tag name (may be qualified: db.schema.name)
    pub name_span: Span,

    /// `ALLOWED_VALUES '<v1>' [, ...]` clause if present
    pub allowed_values: Option<AstTagAllowedValues>,
    /// `PROPAGATE = <mode>` clause if present
    pub propagate: Option<AstTagPropagate>,
    /// `ON_CONFLICT = <resolution>` clause if present
    pub on_conflict: Option<AstTagOnConflict>,
    /// Span covering `COMMENT = '<string>'` if present
    pub comment_span: Option<Span>,

    /// Defensive design for future Snowflake additions
    pub extras: Vec<AstUnknownClause>,
}

/// `ALLOWED_VALUES '<v1>' [, ...]` clause. No `=` between the keyword
/// and the value list.
#[derive(Debug, Clone)]
pub struct AstTagAllowedValues {
    /// Span covering the ALLOWED_VALUES keyword (Identifier token)
    pub keyword_span: Span,
    /// Span covering the full comma-separated literal list
    pub values_span: Span,
    /// Span of each string literal in the list
    pub value_spans: Vec<Span>,
}

/// `PROPAGATE = <mode>` clause. Mode is a bare identifier
/// (ON_DEPENDENCY_AND_DATA_MOVEMENT | ON_DEPENDENCY | ON_DATA_MOVEMENT).
#[derive(Debug, Clone)]
pub struct AstTagPropagate {
    /// Span covering the PROPAGATE keyword (Identifier token)
    pub keyword_span: Span,
    /// Span covering the mode identifier
    pub value_span: Span,
}

/// `ON_CONFLICT = <resolution>` clause. Resolution is either a bare
/// identifier (ALLOWED_VALUES_SEQUENCE) or a string literal.
#[derive(Debug, Clone)]
pub struct AstTagOnConflict {
    /// Span covering the ON_CONFLICT keyword (Identifier token)
    pub keyword_span: Span,
    /// Span covering the resolution value
    pub value_span: Span,
}

/// ALTER TAG statement (Snowflake).
///
/// Syntax variants:
/// - `ALTER TAG [IF EXISTS] <name> RENAME TO <new_name>`
/// - `ALTER TAG [IF EXISTS] <name> {ADD | DROP} ALLOWED_VALUES '<v1>' [, ...]`
/// - `ALTER TAG [IF EXISTS] <name> SET [ALLOWED_VALUES ...] [PROPAGATE = ...] [COMMENT = ...]`
/// - `ALTER TAG [IF EXISTS] <name> UNSET {ALLOWED_VALUES | PROPAGATE | ON_CONFLICT | COMMENT}`
/// - `ALTER TAG [IF EXISTS] <name> SET MASKING POLICY <p> [, MASKING POLICY <p2> ...] [FORCE]`
/// - `ALTER TAG [IF EXISTS] <name> UNSET MASKING POLICY <p> [, MASKING POLICY <p2> ...]`
/// - `ALTER TAG [IF EXISTS] <name> UNSET DCM PROJECT`
#[derive(Debug, Clone)]
pub struct AstAlterTag {
    pub node_id: crate::ast::NodeId,
    /// Span covering the entire ALTER TAG statement
    pub span: Span,

    // Keyword spans
    pub alter_span: Span,
    pub tag_span: Span,
    pub if_exists_span: Option<Span>,

    /// Span covering the tag name (may be qualified)
    pub name_span: Span,

    /// Span covering the action portion of the statement
    pub action_span: Span,
    /// The action to perform
    pub action: AstAlterTagAction,
}

/// A single action within an ALTER TAG statement.
#[derive(Debug, Clone)]
pub struct AstAlterTagAction {
    pub node_id: crate::ast::NodeId,
    /// Span covering this action
    pub span: Span,
    /// The kind of action
    pub kind: AstAlterTagActionKind,
}

/// The kind of action in an ALTER TAG statement.
#[derive(Debug, Clone)]
pub enum AstAlterTagActionKind {
    /// RENAME TO <new_name>
    RenameTo {
        rename_span: Span,
        to_span: Option<Span>,
        new_name_span: Span,
    },

    /// `ADD ALLOWED_VALUES '<v1>' [, ...]`
    AddAllowedValues {
        add_span: Span,
        values: AstTagAllowedValues,
    },

    /// `DROP ALLOWED_VALUES '<v1>' [, ...]`
    DropAllowedValues {
        drop_span: Span,
        values: AstTagAllowedValues,
    },

    /// SET [ALLOWED_VALUES ...] [PROPAGATE = ... [ON_CONFLICT = ...]] [COMMENT = ...]
    /// Clauses may co-occur in a single SET.
    Set {
        set_span: Span,
        allowed_values: Option<AstTagAllowedValues>,
        propagate: Option<AstTagPropagate>,
        on_conflict: Option<AstTagOnConflict>,
        /// Span covering `COMMENT = '<string>'` if present
        comment_span: Option<Span>,
    },

    /// UNSET {ALLOWED_VALUES | PROPAGATE | ON_CONFLICT | COMMENT}
    Unset {
        unset_span: Span,
        property: AstTagUnsetProperty,
    },

    /// `SET MASKING POLICY <p> [, MASKING POLICY <p2> ...] [FORCE]`
    SetMaskingPolicies {
        set_span: Span,
        policies: Vec<AstTagPolicyRef>,
        force_span: Option<Span>,
    },

    /// `UNSET MASKING POLICY <p> [, MASKING POLICY <p2> ...]`
    UnsetMaskingPolicies {
        unset_span: Span,
        policies: Vec<AstTagPolicyRef>,
    },

    /// UNSET DCM PROJECT
    UnsetDcmProject {
        unset_span: Span,
        /// Span covering the DCM PROJECT tokens
        dcm_project_span: Span,
    },
}

/// Tag property named by an UNSET action.
#[derive(Debug, Clone)]
pub enum AstTagUnsetProperty {
    AllowedValues { span: Span },
    Propagate { span: Span },
    OnConflict { span: Span },
    Comment { span: Span },
}

/// One `MASKING POLICY <name>` element in a SET/UNSET MASKING POLICY list.
#[derive(Debug, Clone)]
pub struct AstTagPolicyRef {
    /// Span covering the MASKING POLICY keyword pair
    pub masking_policy_span: Span,
    /// Span covering the policy name (may be qualified)
    pub name_span: Span,
}

/// Snowflake UNDROP TAG statement
///
/// `UNDROP TAG <name>`
#[derive(Debug, Clone)]
pub struct AstUndropTag {
    pub node_id: crate::ast::NodeId,
    /// Span covering the entire UNDROP TAG statement
    pub span: Span,
    /// Span covering UNDROP keyword
    pub undrop_span: Span,
    /// Span covering TAG keyword
    pub tag_span: Span,
    /// Span covering the tag name (may be qualified)
    pub name_span: Span,
}

/// Snowflake CREATE FILE FORMAT statement.
///
/// `CREATE [OR REPLACE] [{TEMP | TEMPORARY | VOLATILE}] FILE FORMAT
///  [IF NOT EXISTS] <name> [TYPE = <type>] [<formatTypeOptions>] [COMMENT = '<s>']`
///
/// `TYPE`, `COMPRESSION`, `COMMENT`, and the format-type options are all
/// captured uniformly as [`AstObjectProperty`] `KEY = value` pairs (no
/// delimiter between pairs; `COMPRESSION`/`TYPE`/`COMMENT` lex as keywords).
#[derive(Debug, Clone)]
pub struct AstCreateFileFormat {
    pub node_id: crate::ast::NodeId,
    /// Span covering the entire CREATE FILE FORMAT statement
    pub span: Span,

    // Keyword spans
    pub create_span: Span,
    pub or_replace_span: Option<Span>,
    /// Span of the TEMP / TEMPORARY / VOLATILE transience keyword, if present
    pub transient_span: Option<Span>,
    /// True when the transience keyword was VOLATILE (no Fail-safe), as
    /// distinct from TEMP / TEMPORARY.
    pub volatile: bool,
    /// Span covering the `FILE FORMAT` keyword pair
    pub file_format_span: Span,
    pub if_not_exists_span: Option<Span>,

    /// Span covering the file-format name (may be qualified: db.schema.name)
    pub name_span: Span,

    /// `KEY = value` property bag (TYPE, COMPRESSION, format options, COMMENT)
    pub properties: Vec<AstObjectProperty>,
}

/// Snowflake ALTER FILE FORMAT statement.
///
/// `ALTER FILE FORMAT [IF EXISTS] <name> RENAME TO <new_name>`
/// `ALTER FILE FORMAT [IF EXISTS] <name> SET <formatTypeOptions> [COMMENT = '<s>']`
#[derive(Debug, Clone)]
pub struct AstAlterFileFormat {
    pub node_id: crate::ast::NodeId,
    /// Span covering the entire ALTER FILE FORMAT statement
    pub span: Span,

    // Keyword spans
    pub alter_span: Span,
    pub file_format_span: Span,
    pub if_exists_span: Option<Span>,

    /// Span covering the file-format name (may be qualified)
    pub name_span: Span,

    /// Span covering the action portion of the statement
    pub action_span: Span,
    /// The action to perform
    pub action: AstAlterFileFormatActionKind,
}

/// The kind of action in an ALTER FILE FORMAT statement.
#[derive(Debug, Clone)]
pub enum AstAlterFileFormatActionKind {
    /// RENAME TO <new_name>
    RenameTo {
        rename_span: Span,
        to_span: Option<Span>,
        new_name_span: Span,
    },

    /// `SET <formatTypeOptions> [COMMENT = '<s>']`
    Set {
        set_span: Span,
        properties: Vec<AstObjectProperty>,
    },
}

/// PostgreSQL ON CONFLICT clause for INSERT
#[derive(Debug, Clone)]
pub struct AstOnConflict {
    pub node_id: crate::ast::NodeId,
    pub on_conflict_span: Span,
    pub target: Option<AstConflictTarget>,
    pub action: AstConflictAction,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub enum AstConflictTarget {
    /// Target columns and/or expressions for index inference, with optional WHERE predicate.
    /// Items can be plain column names or arbitrary expressions (function calls, arithmetic, etc.).
    /// Each item may optionally have a COLLATE or opclass qualifier.
    Columns {
        items: Vec<AstConflictTargetItem>,
        where_predicate: Option<Box<AstExpr>>,
    },
    Constraint(String),
}

/// A single item in an ON CONFLICT target list.
/// Can be a plain column name, or an expression (wrapped in parens in the source).
#[derive(Debug, Clone)]
pub struct AstConflictTargetItem {
    pub kind: AstConflictTargetItemKind,
    pub collation: Option<String>,
    pub opclass: Option<String>,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub enum AstConflictTargetItemKind {
    /// Plain column name: `ON CONFLICT (col1, col2)`
    Column(String),
    /// Expression target: `ON CONFLICT (LOWER(email))` or `ON CONFLICT ((a + b))`
    Expression(Box<AstExpr>),
}

#[derive(Debug, Clone)]
pub enum AstConflictAction {
    DoNothing(Span),
    DoUpdate {
        do_update_span: Span,
        set_items: Vec<(String, AstExpr)>,
        where_clause: Option<Box<AstExpr>>,
    },
}

/// PostgreSQL EXPLAIN statement
///
/// Wraps an inner statement (SELECT, INSERT, UPDATE, DELETE) with optional
/// analysis options. The inner statement is a full AST node, not opaque
/// text.
///
/// Syntax forms:
/// - `EXPLAIN SELECT ...`
/// - `EXPLAIN ANALYZE SELECT ...`
/// - `EXPLAIN (ANALYZE, COSTS, VERBOSE, FORMAT JSON) SELECT ...`
/// - `EXPLAIN (ANALYZE true, BUFFERS true) SELECT ...`
#[derive(Debug, Clone)]
pub struct AstExplain {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    /// Span covering the EXPLAIN keyword
    pub explain_span: Span,
    /// Span covering the options portion (ANALYZE keyword or parenthesized options list),
    /// if present. None for bare `EXPLAIN SELECT ...`.
    pub options_span: Option<Span>,
    /// The inner statement being explained
    pub inner_stmt: Box<AstStmt>,
}

/// T-SQL index-type modifier between `CREATE [UNIQUE]` and `INDEX`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AstIndexClustering {
    Clustered,
    NonClustered,
}

/// MySQL index-kind modifier between `CREATE` and `INDEX`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AstMysqlIndexKind {
    Fulltext,
    Spatial,
}

/// PostgreSQL CREATE INDEX statement
///
/// `CREATE [UNIQUE] INDEX [CONCURRENTLY] [IF NOT EXISTS] name ON table
///     [USING method] (columns) [INCLUDE (columns)] [WHERE predicate]`
#[derive(Debug, Clone)]
pub struct AstCreateIndex {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    /// Link to CST node for token-level formatting
    pub syntax_id: Option<crate::syntax::SyntaxCreateIndexStmtId>,
    /// True if `UNIQUE` modifier is present
    pub unique: bool,
    /// T-SQL index-type modifier: `CLUSTERED` / `NONCLUSTERED` (None if unspecified)
    pub clustered: Option<AstIndexClustering>,
    /// True if `COLUMNSTORE` modifier is present (T-SQL columnstore index)
    pub columnstore: bool,
    /// MySQL index-kind modifier: `FULLTEXT` / `SPATIAL` (None if unspecified)
    pub mysql_index_kind: Option<AstMysqlIndexKind>,
    /// True if `CONCURRENTLY` modifier is present
    pub concurrently: bool,
    /// True if `IF NOT EXISTS` is present
    pub if_not_exists: bool,
    /// The index name (may be omitted for anonymous indexes on some dialects)
    pub index_name: Option<Span>,
    /// The target table name (everything from the identifier after ON up to USING/LParen)
    pub table_name: Span,
    /// The USING method name span (e.g., `btree`, `hash`, `gin`, `gist`)
    pub using_method: Option<Span>,
    /// Span covering the parenthesized column list `(col1, col2 DESC, ...)`
    pub columns_span: Span,
    /// Span covering `INCLUDE (col, ...)` if present
    pub include_span: Option<Span>,
    /// Parsed WHERE predicate expression (uses the expression parser)
    pub where_predicate: Option<Box<crate::ast::AstExpr>>,
}

/// T-SQL CREATE SYNONYM statement
///
/// `CREATE SYNONYM [schema.]synonym_name FOR [server.][database.][schema.]object_name`
#[derive(Debug, Clone)]
pub struct AstCreateSynonym {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    /// Span of the CREATE keyword
    pub create_span: Span,
    /// Span of the SYNONYM keyword (an identifier in our lexer)
    pub synonym_keyword_span: Span,
    /// Span of the synonym name (possibly schema-qualified)
    pub name_span: Span,
    /// Span of the FOR keyword
    pub for_span: Span,
    /// Span of the referenced base object (1–4 part name)
    pub target_span: Span,
}

/// PostgreSQL COMMENT ON statement
///
/// `COMMENT ON {TABLE | COLUMN | INDEX | SCHEMA | DATABASE | FUNCTION | TYPE | ...}
///     object_name IS {'text' | NULL}`
#[derive(Debug, Clone)]
pub struct AstCommentOn {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    /// Link to CST node for token-level formatting
    pub syntax_id: Option<crate::syntax::SyntaxCommentOnStmtId>,
    /// The object kind span (e.g., TABLE, COLUMN, INDEX, FUNCTION, ...)
    pub object_kind: Span,
    /// The object name span (may be qualified: `schema.table.column`)
    pub object_name: Span,
    /// The comment value span (a string literal or NULL)
    pub comment_value: Span,
}

/// PostgreSQL DO anonymous block
///
/// `DO [LANGUAGE lang] $$ body $$`
///
/// The body is a single dollar-quoted string literal token from the lexer.
#[derive(Debug, Clone)]
pub struct AstDoBlock {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    /// Link to CST node for token-level formatting
    pub syntax_id: Option<crate::syntax::SyntaxDoBlockStmtId>,
    /// The language name span if `LANGUAGE lang` is present
    pub language: Option<Span>,
    /// The dollar-quoted body span, covering the whole `$$ … $$` region
    /// (delimiters included) for byte-exact formatting.
    pub body_span: Span,
    /// The sub-parsed body block when the dollar body is a closed
    /// `BEGIN … END` / `DECLARE … END` scripting block, so the anonymous
    /// block's statements are analyzed (shared with CREATE PROCEDURE).
    /// `None` for opaque/non-block bodies. Not used by the formatter, which
    /// emits [`Self::body_span`] verbatim.
    pub body_stmt: Option<Box<AstStmt>>,
}

/// VACUUM statement (PostgreSQL + Databricks)
///
/// PostgreSQL:
/// `VACUUM [FULL] [FREEZE] [VERBOSE] [ANALYZE] [table [(column, ...)]]`
/// `VACUUM (option [, ...]) [table [(column, ...)]]`
///
/// Databricks (Delta Lake):
/// `VACUUM table_name [RETAIN num HOURS] [DRY RUN]`
///
/// Databricks (Iceberg):
/// `VACUUM table_name { FULL | LITE } [DRY RUN]`
#[derive(Debug, Clone)]
pub struct AstVacuum {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    /// Link to CST node for token-level formatting
    pub syntax_id: Option<crate::syntax::SyntaxVacuumStmtId>,
    /// Span covering parenthesized options `(VERBOSE, ANALYZE)` if present
    pub options_span: Option<Span>,
    /// True if bare FULL flag is present (PG non-parenthesized form, or Databricks Iceberg FULL)
    pub full: bool,
    /// True if bare FREEZE flag is present (non-parenthesized form)
    pub freeze: bool,
    /// True if bare VERBOSE flag is present (non-parenthesized form)
    pub verbose: bool,
    /// True if bare ANALYZE flag is present (non-parenthesized form)
    pub analyze: bool,
    /// Redshift `VACUUM DELETE ONLY` — reclaim deleted rows without re-sorting.
    pub delete_only: bool,
    /// Redshift `VACUUM SORT ONLY` — re-sort without reclaiming space.
    pub sort_only: bool,
    /// Redshift `VACUUM REINDEX` — re-analyze + re-sort interleaved sort keys.
    pub reindex: bool,
    /// Redshift `VACUUM RECLUSTER` — partial re-sort of recently changed rows.
    pub recluster: bool,
    /// The target table name span if present
    pub table_name: Option<Span>,
    /// Span covering parenthesized column list after table name
    pub columns_span: Option<Span>,
    // --- Databricks-specific fields ---
    /// Retention value in hours from `RETAIN num HOURS` clause (Databricks Delta Lake)
    pub retain_hours: Option<u64>,
    /// Span covering the full `RETAIN num HOURS` clause
    pub retain_span: Option<Span>,
    /// True if DRY RUN flag is present (Databricks)
    pub dry_run: bool,
    /// True if LITE mode is specified (Databricks Iceberg)
    pub lite: bool,
}

/// PostgreSQL ANALYZE (utility) statement
///
/// `ANALYZE [VERBOSE] [table [(column, ...)]]`
///
/// Named `AstAnalyzeStmt` to avoid collision with `EXPLAIN ANALYZE`.
#[derive(Debug, Clone)]
pub struct AstAnalyzeStmt {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    /// Link to CST node for token-level formatting
    pub syntax_id: Option<crate::syntax::SyntaxAnalyzeStmtId>,
    /// True if VERBOSE flag is present
    pub verbose: bool,
    /// True if the Redshift `COMPRESSION` mode is present
    /// (`ANALYZE COMPRESSION [table]` — column-encoding recommendation pass).
    pub compression: bool,
    /// The target table name span if present
    pub table_name: Option<Span>,
    /// Span covering parenthesized column list after table name
    pub columns_span: Option<Span>,
}

/// PostgreSQL CREATE TYPE statement
///
/// `CREATE TYPE name AS ENUM ('val1', 'val2', ...)`
/// `CREATE TYPE name AS (attr type, ...)`
/// `CREATE TYPE name AS RANGE (SUBTYPE = type, ...)`
#[derive(Debug, Clone)]
pub struct AstCreateType {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    /// Link to CST node for token-level formatting
    pub syntax_id: Option<crate::syntax::SyntaxCreateTypeStmtId>,
    /// The type name
    pub type_name: Span,
    /// Span covering the inner content of the parenthesized body (between parens)
    pub body_inner_span: Option<Span>,
}

/// PostgreSQL ALTER TYPE statement
///
/// `ALTER TYPE name ADD VALUE [IF NOT EXISTS] 'value' [BEFORE | AFTER 'value']`
/// `ALTER TYPE name RENAME TO new_name`
/// `ALTER TYPE name ADD ATTRIBUTE attr type`
/// `ALTER TYPE name SET SCHEMA schema`
/// `ALTER TYPE name OWNER TO owner`
/// `ALTER TYPE name RENAME VALUE 'old' TO 'new'`
#[derive(Debug, Clone)]
pub struct AstAlterType {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    /// Link to CST node for token-level formatting
    pub syntax_id: Option<crate::syntax::SyntaxAlterTypeStmtId>,
    /// The type name being altered
    pub type_name: Span,
}

/// PostgreSQL CREATE EXTENSION statement
///
/// `CREATE EXTENSION [IF NOT EXISTS] name [WITH] [SCHEMA schema] [VERSION version] [CASCADE]`
#[derive(Debug, Clone)]
pub struct AstCreateExtension {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    /// Link to CST node for token-level formatting
    pub syntax_id: Option<crate::syntax::SyntaxCreateExtensionStmtId>,
    /// True if `IF NOT EXISTS` is present
    pub if_not_exists: bool,
    /// The extension name
    pub extension_name: Span,
    /// The schema name span if `SCHEMA schema` is present
    pub schema_name: Option<Span>,
    /// The version string span if `VERSION 'x.y'` is present
    pub version: Option<Span>,
    /// True if CASCADE is present
    pub cascade: bool,
}

/// PostgreSQL CREATE SEQUENCE statement
///
/// `CREATE [TEMPORARY | TEMP | UNLOGGED] SEQUENCE [IF NOT EXISTS] name
///     [AS data_type] [INCREMENT [BY] n] [MINVALUE n | NO MINVALUE]
///     [MAXVALUE n | NO MAXVALUE] [[NO] CYCLE] [START [WITH] n]
///     [CACHE n] [OWNED BY table.column | NONE]`
#[derive(Debug, Clone)]
pub struct AstCreateSequence {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    /// Link to CST node for token-level formatting
    pub syntax_id: Option<crate::syntax::SyntaxCreateSequenceStmtId>,
    /// True if OR REPLACE present (Snowflake) — resets the generator counter
    pub or_replace: bool,
    /// True if TEMPORARY or TEMP keyword present
    pub temporary: bool,
    /// True if UNLOGGED keyword present
    pub unlogged: bool,
    /// True if IF NOT EXISTS is present
    pub if_not_exists: bool,
    /// The sequence name span (optionally schema-qualified)
    pub name: Span,
    /// Span covering all options after the name (AS type, INCREMENT, etc.)
    pub options_span: Option<Span>,
}

/// PostgreSQL ALTER SEQUENCE statement
///
/// `ALTER SEQUENCE [IF EXISTS] name ... (options, RENAME TO, SET SCHEMA, OWNER TO, etc.)`
#[derive(Debug, Clone)]
pub struct AstAlterSequence {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    /// Link to CST node for token-level formatting
    pub syntax_id: Option<crate::syntax::SyntaxAlterSequenceStmtId>,
    /// True if IF EXISTS is present
    pub if_exists: bool,
    /// The sequence name span (optionally schema-qualified)
    pub name: Span,
    /// Span covering all clauses after the name
    pub options_span: Option<Span>,
}

// =============================================================================
// PostgreSQL Trigger Statements
// =============================================================================

/// Timing for a PG trigger: BEFORE, AFTER, or INSTEAD OF
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PgTriggerTiming {
    Before,
    After,
    InsteadOf,
}

/// A single trigger event (INSERT, UPDATE [OF cols], DELETE, TRUNCATE)
#[derive(Debug, Clone)]
pub struct PgTriggerEvent {
    pub span: Span,
    pub kind: PgTriggerEventKind,
}

/// The kind of trigger event
#[derive(Debug, Clone)]
pub enum PgTriggerEventKind {
    Insert,
    /// UPDATE with optional column list: UPDATE OF col1, col2
    Update {
        /// Column name spans (empty if plain UPDATE)
        columns: Vec<Span>,
    },
    Delete,
    Truncate,
}

/// FOR EACH ROW or FOR EACH STATEMENT
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PgForEachMode {
    Row,
    Statement,
}

/// Deferrable mode for constraint triggers
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PgDeferrableMode {
    /// NOT DEFERRABLE (explicit)
    NotDeferrable,
    /// DEFERRABLE INITIALLY DEFERRED
    DeferrableInitiallyDeferred,
    /// DEFERRABLE INITIALLY IMMEDIATE
    DeferrableInitiallyImmediate,
}

/// A REFERENCING clause entry: {OLD|NEW} TABLE AS alias
#[derive(Debug, Clone)]
pub struct PgReferencingEntry {
    pub span: Span,
    /// True if NEW TABLE, false if OLD TABLE
    pub is_new: bool,
    /// The alias name span
    pub alias: Span,
}

/// Action for ALTER TRIGGER
#[derive(Debug, Clone)]
pub enum PgAlterTriggerAction {
    /// RENAME TO new_name
    RenameTo { span: Span, new_name: Span },
    /// `[NO] DEPENDS ON EXTENSION ext_name`
    DependsOnExtension {
        span: Span,
        no: bool,
        extension_name: Span,
    },
}

/// CASCADE or RESTRICT option (DROP TRIGGER)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PgCascadeRestrict {
    Cascade,
    Restrict,
}

/// PostgreSQL `CREATE [OR REPLACE] [CONSTRAINT] TRIGGER` statement
///
/// ```sql
/// CREATE [OR REPLACE] [CONSTRAINT] TRIGGER name
///     {BEFORE | AFTER | INSTEAD OF} {event [OR ...]}
///     ON table_name
///     [FROM referenced_table_name]
///     [NOT DEFERRABLE | DEFERRABLE [INITIALLY {DEFERRED | IMMEDIATE}]]
///     [REFERENCING {OLD | NEW} TABLE AS alias ...]
///     [FOR [EACH] {ROW | STATEMENT}]
///     [WHEN (condition)]
///     EXECUTE {FUNCTION | PROCEDURE} function_name(arguments)
/// ```
#[derive(Debug, Clone)]
pub struct AstCreatePgTrigger {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    pub syntax_id: Option<crate::syntax::SyntaxCreatePgTriggerStmtId>,
    /// True if OR REPLACE present
    pub or_replace: bool,
    /// True if CONSTRAINT trigger
    pub is_constraint: bool,
    /// Trigger name span
    pub trigger_name: Span,
    /// Timing: BEFORE, AFTER, or INSTEAD OF
    pub timing: PgTriggerTiming,
    /// Span covering the timing keyword(s)
    pub timing_span: Span,
    /// Events (INSERT, UPDATE [OF cols], DELETE, TRUNCATE) separated by OR
    pub events: Vec<PgTriggerEvent>,
    /// ON table_name (schema-qualified)
    pub table_name: Span,
    /// FROM referenced_table (constraint triggers only)
    pub from_table: Option<Span>,
    /// Deferrable mode (constraint triggers only)
    pub deferrable: Option<PgDeferrableMode>,
    /// Span covering the deferrable clause
    pub deferrable_span: Option<Span>,
    /// REFERENCING entries
    pub referencing: Vec<PgReferencingEntry>,
    /// FOR EACH ROW or FOR EACH STATEMENT
    pub for_each: Option<PgForEachMode>,
    /// Span covering the FOR EACH clause
    pub for_each_span: Option<Span>,
    /// WHEN (condition) — the condition expression including parens
    pub when_condition: Option<Span>,
    /// EXECUTE FUNCTION/PROCEDURE — span covering `EXECUTE FUNCTION|PROCEDURE`
    pub execute_span: Span,
    /// Function name span (schema-qualified)
    pub function_name: Span,
    /// Arguments span (everything inside the parens, excluding parens themselves)
    pub function_args_span: Option<Span>,
    /// Span of the lparen and rparen for function call
    pub function_call_parens: Span,
}

/// PostgreSQL ALTER TRIGGER statement
///
/// ```sql
/// ALTER TRIGGER name ON table_name RENAME TO new_name
/// ALTER TRIGGER name ON table_name [NO] DEPENDS ON EXTENSION ext_name
/// ```
#[derive(Debug, Clone)]
pub struct AstAlterPgTrigger {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    pub syntax_id: Option<crate::syntax::SyntaxAlterPgTriggerStmtId>,
    /// Trigger name span
    pub trigger_name: Span,
    /// ON table_name (schema-qualified)
    pub table_name: Span,
    /// The action: `RENAME TO` or `[NO] DEPENDS ON EXTENSION`
    pub action: PgAlterTriggerAction,
}

/// PostgreSQL `ALTER TABLE … {ENABLE|DISABLE} TRIGGER …` statement.
///
/// ```sql
/// ALTER TABLE [IF EXISTS] [ONLY] name [*]
///     { ENABLE [REPLICA | ALWAYS] TRIGGER { name | ALL | USER }
///     | DISABLE TRIGGER { name | ALL | USER }
///     }
/// ```
///
/// Distinct top-level statement (not part of generic `AstAlterTable`)
/// because PG dispatches this through its own grammar branch and the
/// action vocabulary is unique to PG. Closed-enum action +
/// closed-enum target so PG-TRIG-OFF predicates on `action.kind:
/// disable` instead of a text scan over the statement source.
#[derive(Debug, Clone)]
pub struct AstPgAlterTableTriggerState {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    pub if_exists: bool,
    /// True if `ONLY` keyword present (PG inheritance scoping).
    pub only: bool,
    /// Span of the (possibly schema-qualified) table identifier.
    pub table_name: Span,
    pub action: PgAlterTableTriggerStateAction,
    pub target: PgAlterTableTriggerStateTarget,
}

/// PG `ALTER TABLE ... { ENABLE [...] | DISABLE }` action variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PgAlterTableTriggerStateAction {
    /// `DISABLE TRIGGER` — turn the trigger off. Drives PG-TRIG-OFF.
    Disable,
    /// `ENABLE TRIGGER` — restore default firing.
    Enable,
    /// `ENABLE ALWAYS TRIGGER` — fire even when session replication
    /// role is `replica` or `local`.
    EnableAlways,
    /// `ENABLE REPLICA TRIGGER` — fire only when session replication
    /// role is `replica`.
    EnableReplica,
}

/// PG `{ TRIGGER name | ALL | USER }` target variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PgAlterTableTriggerStateTarget {
    /// A specific trigger name (span covers the identifier).
    Named(Span),
    /// `TRIGGER ALL` — applies to every trigger on the table.
    All,
    /// `TRIGGER USER` — applies to every user-defined trigger (excludes
    /// foreign-key constraint triggers).
    User,
}

/// PostgreSQL `DROP RULE` statement.
///
/// ```sql
/// DROP RULE [IF EXISTS] name ON table_name [CASCADE | RESTRICT]
/// ```
#[derive(Debug, Clone)]
pub struct AstPgDropRule {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    pub if_exists: bool,
    pub rule_name: Span,
    pub table_name: Span,
    pub cascade_restrict: Option<PgCascadeRestrict>,
}

/// PostgreSQL `DROP SEQUENCE` statement.
///
/// ```sql
/// DROP SEQUENCE [IF EXISTS] name [, ...] [CASCADE | RESTRICT]
/// ```
#[derive(Debug, Clone)]
pub struct AstPgDropSequence {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    pub if_exists: bool,
    pub sequence_names: Vec<Span>,
    pub cascade_restrict: Option<PgCascadeRestrict>,
}

/// PostgreSQL `DROP TYPE` statement.
///
/// ```sql
/// DROP TYPE [IF EXISTS] name [, ...] [CASCADE | RESTRICT]
/// ```
#[derive(Debug, Clone)]
pub struct AstPgDropType {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    pub if_exists: bool,
    pub type_names: Vec<Span>,
    pub cascade_restrict: Option<PgCascadeRestrict>,
}

// ============================================================================
// Dialect-neutral principal substrate
// ============================================================================
//
// `CREATE / ALTER / DROP { USER | ROLE | LOGIN }` across every supported
// dialect lowers into these three variants. User / Role / Login are
// distinct objects in essentially every dialect (Snowflake: separate
// USER and ROLE; MSSQL: LOGIN + USER + ROLE; PG: fused ROLE with
// LOGIN/NOLOGIN flag) — the `PrincipalKind` discriminator carries that
// distinction so consumers dispatch on the kind instead of the dialect.
//
// `CreatePrincipalOptions` is the typed option bag: dialect-specific
// clauses ride as additive `Option<...>` fields (`password_literal`,
// `mssql_source`, ...). The parser is the single text→typed conversion
// site — downstream consumers read the typed fields rather than
// re-tokenising spans.

/// `CREATE { USER | ROLE | LOGIN }` — dialect-neutral.
#[derive(Debug, Clone)]
pub struct AstCreatePrincipal {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    /// Span covering the `CREATE { USER | ROLE | LOGIN }` keywords.
    pub keyword_span: Span,
    /// Which kind of principal this statement creates.
    pub principal_kind: PrincipalKind,
    /// T-SQL `SERVER ROLE` (vs database `ROLE`). Only meaningful for
    /// `principal_kind == Role`.
    pub server_scope: bool,
    /// Span of the principal name identifier. For MySQL `'user'@'host'`
    /// this is the inner user literal; the host literal rides in
    /// `options.mysql_host`.
    pub name_span: Span,
    /// `IF NOT EXISTS` clause present (Snowflake / MySQL).
    pub if_not_exists: bool,
    /// `OR REPLACE` present (Snowflake `CREATE OR REPLACE DATABASE ROLE`)
    /// — drops and recreates the principal.
    pub or_replace: bool,
    pub options: CreatePrincipalOptions,
}

/// `ALTER { USER | ROLE | LOGIN }` — dialect-neutral.
///
/// Excludes the narrow Snowflake `ALTER USER … { SET | UNSET } AUTHENTICATION
/// POLICY` slice, which is parsed into [`AstAlterUser`] for the policy
/// attachment surface.
#[derive(Debug, Clone)]
pub struct AstAlterPrincipal {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    /// Span covering the `ALTER { USER | ROLE | LOGIN }` keywords.
    pub keyword_span: Span,
    /// Which kind of principal this statement targets.
    pub principal_kind: PrincipalKind,
    pub name_span: Span,
    pub if_exists: bool,
    /// T-SQL `SERVER ROLE` (vs database `ROLE`). Only meaningful for
    /// `principal_kind == Role`.
    pub server_scope: bool,
    /// T-SQL `ADD MEMBER <p>` / `DROP MEMBER <p>` membership clause.
    pub membership: Option<AstPrincipalMembership>,
    pub options: CreatePrincipalOptions,
}

/// T-SQL `ALTER [SERVER] ROLE … { ADD | DROP } MEMBER <principal>`.
#[derive(Debug, Clone, Copy)]
pub struct AstPrincipalMembership {
    pub kind: AstPrincipalMembershipKind,
    /// Span of the member principal name.
    pub member_span: Span,
}

/// Whether the membership clause adds or removes the member.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AstPrincipalMembershipKind {
    AddMember,
    DropMember,
}

/// T-SQL `ALTER LOGIN <name> { ENABLE | DISABLE }`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AstPrincipalEnabledState {
    Enable,
    Disable,
}

/// `DROP { USER | ROLE | LOGIN }` — dialect-neutral.
#[derive(Debug, Clone)]
pub struct AstDropPrincipal {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    /// Span covering the `DROP { USER | ROLE | LOGIN }` keywords.
    pub keyword_span: Span,
    /// Which kind of principal this statement targets.
    pub principal_kind: PrincipalKind,
    /// T-SQL `SERVER ROLE` (vs database `ROLE`). Only meaningful for
    /// `principal_kind == Role`.
    pub server_scope: bool,
    pub if_exists: bool,
    /// Comma-separated principal name spans. PG / Snowflake permit a
    /// list; MSSQL / MySQL accept exactly one.
    pub names: Vec<Span>,
}

/// Closed enum: which kind of database principal a `CREATE / ALTER /
/// DROP` statement acts on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrincipalKind {
    /// A database user / authenticated account.
    /// Snowflake `USER`, PG `USER` / `ROLE … LOGIN`, MSSQL database `USER`,
    /// MySQL `USER`.
    User,
    /// A permission grouping. Snowflake `ROLE`, PG `ROLE` (without
    /// `LOGIN`), MSSQL database `ROLE`.
    Role,
    /// MSSQL server-level `LOGIN` (separate from MSSQL database `USER`).
    Login,
    /// A Redshift permission `GROUP` (`CREATE/ALTER/DROP GROUP`). Distinct
    /// from `Role`: Redshift groups are the legacy membership primitive,
    /// semantically separate from RBAC roles, so they must not collapse to
    /// `Role` (a consumer looking for roles would otherwise see groups).
    Group,
    /// MSSQL `APPLICATION ROLE` — a database-level principal activated
    /// with a password (`sp_setapprole`). Distinct from `Role`: it has
    /// no members and carries its own password.
    ApplicationRole,
    /// Snowflake `DATABASE ROLE` — a role scoped to a single database,
    /// named `<db>.<role>`. Distinct from account-level `Role`: it cannot
    /// be granted directly to users and lives inside one database.
    DatabaseRole,
}

/// Typed option bag for `CREATE` / `ALTER` principal. All fields are
/// optional; the parser populates whichever clauses are present.
/// Additive growth: new dialect-specific clauses become new fields.
#[derive(Debug, Clone, Default)]
pub struct CreatePrincipalOptions {
    /// Span of the password literal value content (inner, no surrounding
    /// quotes). Populated for any dialect form that takes a password
    /// literal:
    /// - Snowflake `PASSWORD = '<lit>'`
    /// - PG `[ENCRYPTED] PASSWORD '<lit>'`
    /// - MSSQL `WITH PASSWORD = '<lit>'`
    /// - MySQL `IDENTIFIED BY '<lit>'`
    pub password_literal: Option<Span>,
    /// MSSQL-specific source classification (`FROM EXTERNAL PROVIDER`,
    /// `FOR LOGIN`, `WITHOUT LOGIN`, `WITH PASSWORD`, …). `None` for
    /// non-MSSQL dialects.
    pub mssql_source: Option<AstMssqlPrincipalSource>,
    /// MySQL `'user'@'host'` host literal span (content only, no
    /// quotes). `None` for non-MySQL or unqualified MySQL principals.
    pub mysql_host: Option<Span>,
    /// T-SQL `ENABLE` / `DISABLE` action in the options body
    /// (`ALTER LOGIN sa DISABLE`).
    pub enabled_state: Option<AstPrincipalEnabledState>,
    /// Span of the remaining options body (everything after the name
    /// and any typed-captured fields). Permissive fallback for clauses
    /// the parser hasn't typed yet. `None` means nothing was left to
    /// consume.
    pub trailing_span: Option<Span>,
    /// PG `CREATE/ALTER ROLE` attribute keywords recognized in the
    /// options body (`SUPERUSER`, `LOGIN`, `BYPASSRLS`, their `NO…`
    /// negations, …), in source order. Empty for dialects/forms that
    /// carry none.
    pub role_attributes: Vec<AstRoleAttribute>,
    /// Snowflake `CREATE/ALTER USER` governance object-properties
    /// recognized in the options body (`DEFAULT_ROLE`, `TYPE`,
    /// `MINS_TO_BYPASS_MFA`, …). `None` when none are present (every
    /// non-Snowflake form, and Snowflake forms carrying none of the
    /// recognized properties).
    pub snowflake_user: Option<AstSnowflakeUserOptions>,
    /// T-SQL `CREATE/ALTER LOGIN` password-policy options recognized in
    /// the options body (`CHECK_POLICY`, `CHECK_EXPIRATION`). `None`
    /// when none are present.
    pub mssql_login: Option<AstMssqlLoginOptions>,
}

/// Snowflake `CREATE/ALTER USER` governance-bearing object properties.
/// Pure recognition: each field records the value *as written*; the
/// danger verdict (which default role is privileged, which `TYPE` is
/// deprecated, what bypass window is too long) is the consumer's.
/// Value-bearing fields hold the value span; structural fields are
/// resolved at parse time.
#[derive(Debug, Clone, Default)]
pub struct AstSnowflakeUserOptions {
    /// `DEFAULT_ROLE = <role>` — primary role active on login. Value span.
    pub default_role: Option<Span>,
    /// `DEFAULT_SECONDARY_ROLES = ('ALL')` / `()` — secondary-role scope.
    pub default_secondary_roles: Option<AstSecondaryRolesMode>,
    /// `MUST_CHANGE_PASSWORD = { TRUE | FALSE }`. Value span.
    pub must_change_password: Option<Span>,
    /// `DISABLED = { TRUE | FALSE }`. Value span.
    pub disabled: Option<Span>,
    /// `TYPE = { PERSON | SERVICE | LEGACY_SERVICE }`. Value span.
    pub user_type: Option<Span>,
    /// `MINS_TO_BYPASS_MFA = <n>` — minutes the user may bypass MFA.
    /// Numeric value span.
    pub mins_to_bypass_mfa: Option<Span>,
    /// `DAYS_TO_EXPIRY = <n>` — days until the user status expires.
    /// Numeric value span.
    pub days_to_expiry: Option<Span>,
    /// `MINS_TO_UNLOCK = <n>` — minutes until a temporary lock clears.
    /// Numeric value span.
    pub mins_to_unlock: Option<Span>,
    /// `RSA_PUBLIC_KEY = '<key>'` present — key-pair authentication.
    /// Presence only; the public key value is not captured.
    pub rsa_public_key_set: bool,
    /// `RSA_PUBLIC_KEY_2 = '<key>'` present — second (rotation) key.
    pub rsa_public_key_2_set: bool,
    /// `NETWORK_POLICY = <name>` — bound network policy. Value span.
    pub network_policy: Option<Span>,
}

/// T-SQL `CREATE/ALTER LOGIN` password-policy options. Pure recognition:
/// each field records the `ON`/`OFF` value span *as written*; the danger
/// verdict (whether `OFF` is acceptable) is the consumer's.
#[derive(Debug, Clone, Default)]
pub struct AstMssqlLoginOptions {
    /// `CHECK_POLICY = { ON | OFF }` — Windows password-policy
    /// enforcement (complexity, lockout) for the login. Value span.
    pub check_policy: Option<Span>,
    /// `CHECK_EXPIRATION = { ON | OFF }` — password-expiration
    /// enforcement for the login. Value span.
    pub check_expiration: Option<Span>,
}

/// Snowflake `DEFAULT_SECONDARY_ROLES` scope: `('ALL')` activates every
/// granted role; `()` activates none.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AstSecondaryRolesMode {
    /// `('ALL')` — all granted roles active as secondary roles.
    All,
    /// `()` — no secondary roles active.
    None,
}

/// One recognized PG `CREATE/ALTER ROLE` capability keyword.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AstRoleAttribute {
    pub kind: AstRoleAttributeKind,
    /// True for the `NO…` form (`NOSUPERUSER`, `NOLOGIN`, …).
    pub negated: bool,
    pub span: Span,
}

/// PG role capability keyword (the `NO…` prefix is carried by
/// [`AstRoleAttribute::negated`], not as separate variants).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AstRoleAttributeKind {
    /// `SUPERUSER` / `NOSUPERUSER`
    Superuser,
    /// `CREATEDB` / `NOCREATEDB`
    CreateDb,
    /// `CREATEROLE` / `NOCREATEROLE`
    CreateRole,
    /// `LOGIN` / `NOLOGIN`
    Login,
    /// `INHERIT` / `NOINHERIT`
    Inherit,
    /// `REPLICATION` / `NOREPLICATION`
    Replication,
    /// `BYPASSRLS` / `NOBYPASSRLS`
    BypassRls,
}

/// PostgreSQL `SET` / `RESET` session-configuration statement.
///
/// ```sql
/// SET [SESSION | LOCAL] ROLE { role | NONE | DEFAULT }
/// SET [SESSION | LOCAL] SESSION AUTHORIZATION { user | DEFAULT }
/// SET [SESSION | LOCAL] search_path TO ...
/// SET [SESSION | LOCAL] config_parameter { TO | = } value [, ...]
/// RESET { ROLE | SESSION AUTHORIZATION | search_path | parameter | ALL }
/// ```
///
/// Typed `kind` discriminator lets PG-ROLE-SET predicate on the
/// `SetRole` / `SetSessionAuthorization` variants without text
/// scanning. The PG-SESSION-* family composes against the remaining
/// variants.
#[derive(Debug, Clone)]
pub struct AstPgSet {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    pub kind: PgSetKind,
}

/// Closed enum of `SET` / `RESET` statement variants, 1:1 with PG
/// grammar.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PgSetKind {
    /// `SET [SESSION | LOCAL] ROLE …` — changes the current role for
    /// permission checks. Drives PG-ROLE-SET.
    SetRole,
    /// `SET [SESSION | LOCAL] SESSION AUTHORIZATION …` — impersonates
    /// another database user. Drives PG-ROLE-SET.
    SetSessionAuthorization,
    /// `SET [SESSION | LOCAL] search_path TO …` — modifies object
    /// resolution scope. Drives PG-SESSION-CHG.
    SetSearchPath,
    /// `SET [SESSION | LOCAL] <other_config> { TO | = } …` —
    /// catch-all for non-role / non-search_path SETs. Drives
    /// PG-SESSION-SET.
    SetParameter,
    /// `RESET ROLE`.
    ResetRole,
    /// `RESET SESSION AUTHORIZATION`.
    ResetSessionAuthorization,
    /// `RESET search_path`.
    ResetSearchPath,
    /// `RESET <other_config>` — catch-all for non-role / non-search_path
    /// RESETs.
    ResetParameter,
    /// `RESET ALL`.
    ResetAll,
}

/// PostgreSQL DROP EXTENSION statement.
///
/// ```sql
/// DROP EXTENSION [IF EXISTS] name [, ...] [CASCADE | RESTRICT]
/// ```
///
/// Distinct from the generic `DROP <object>` path because PG accepts
/// a comma-separated extension list. Cascade flows through
/// [`PgCascadeRestrict`] — same shape `AstDropDomain` /
/// `AstPgDropIndex` / `AstDropPgTrigger` use.
#[derive(Debug, Clone)]
pub struct AstPgDropExtension {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    /// True if `IF EXISTS` clause present.
    pub if_exists: bool,
    /// Comma-separated extension name spans. PG grammar permits one
    /// or more names.
    pub extension_names: Vec<Span>,
    /// `CASCADE` or `RESTRICT` suffix, if present.
    pub cascade_restrict: Option<PgCascadeRestrict>,
}

/// PostgreSQL DROP INDEX statement.
///
/// ```sql
/// DROP INDEX [CONCURRENTLY] [IF EXISTS] name [, ...] [CASCADE | RESTRICT]
/// ```
///
/// Distinct from the generic `DROP <object>` path because PG syntax
/// permits a `CONCURRENTLY` modifier (locking semantics that no other
/// dialect honors here) and accepts a comma-separated list of index
/// names. Cascade flows through [`PgCascadeRestrict`] — same shape
/// `AstDropDomain` / `AstDropPgTrigger` use.
#[derive(Debug, Clone)]
pub struct AstPgDropIndex {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    /// True if `CONCURRENTLY` keyword present.
    pub concurrently: bool,
    /// True if `IF EXISTS` clause present.
    pub if_exists: bool,
    /// Comma-separated index name spans. Each span covers the
    /// (optionally schema-qualified) index identifier. PG grammar
    /// permits one or more names.
    pub index_names: Vec<Span>,
    /// MySQL `ON tbl_name` target table, if present (`DROP INDEX idx ON t`).
    pub on_table_span: Option<Span>,
    /// `CASCADE` or `RESTRICT` suffix, if present.
    pub cascade_restrict: Option<PgCascadeRestrict>,
}

/// PostgreSQL DROP TRIGGER statement
///
/// ```sql
/// DROP TRIGGER [IF EXISTS] name ON table_name [CASCADE | RESTRICT]
/// ```
#[derive(Debug, Clone)]
pub struct AstDropPgTrigger {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    pub syntax_id: Option<crate::syntax::SyntaxDropPgTriggerStmtId>,
    /// True if IF EXISTS present
    pub if_exists: bool,
    /// Trigger name span
    pub trigger_name: Span,
    /// ON table_name (schema-qualified)
    pub table_name: Span,
    /// CASCADE or RESTRICT
    pub cascade_restrict: Option<PgCascadeRestrict>,
}

// =============================================================================
// PostgreSQL Row-Level Security (RLS) POLICY Statements
// =============================================================================

/// The command a policy applies to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PgPolicyCommand {
    All,
    Select,
    Insert,
    Update,
    Delete,
}

/// PERMISSIVE or RESTRICTIVE policy type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PgPolicyPermissiveness {
    Permissive,
    Restrictive,
}

/// A role target in the TO clause (can be a name, PUBLIC, CURRENT_USER, etc.).
#[derive(Debug, Clone)]
pub struct PgPolicyRole {
    pub span: Span,
}

/// CREATE POLICY statement (PostgreSQL).
///
/// ```sql
/// CREATE POLICY name ON table_name
///     [ AS { PERMISSIVE | RESTRICTIVE } ]
///     [ FOR { ALL | SELECT | INSERT | UPDATE | DELETE } ]
///     [ TO { role_name | PUBLIC | CURRENT_USER | ... } [, ...] ]
///     [ USING ( using_expression ) ]
///     [ WITH CHECK ( check_expression ) ]
/// ```
#[derive(Debug, Clone)]
pub struct AstCreatePgPolicy {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    pub syntax_id: Option<crate::syntax::SyntaxCreatePgPolicyStmtId>,
    /// Policy name
    pub policy_name: Span,
    /// Table name (possibly schema-qualified)
    pub table_name: Span,
    /// AS PERMISSIVE or AS RESTRICTIVE
    pub permissiveness: Option<(PgPolicyPermissiveness, Span)>,
    /// FOR command
    pub command: Option<(PgPolicyCommand, Span)>,
    /// FOR keyword span
    pub for_span: Option<Span>,
    /// TO role list
    pub roles: Vec<PgPolicyRole>,
    /// TO keyword span
    pub to_span: Option<Span>,
    /// USING expression
    pub using_expr: Option<Box<AstExpr>>,
    /// USING keyword + parens span (USING(...))
    pub using_span: Option<Span>,
    /// WITH CHECK expression
    pub check_expr: Option<Box<AstExpr>>,
    /// WITH CHECK keyword + parens span
    pub with_check_span: Option<Span>,
}

/// ALTER POLICY action kind.
#[derive(Debug, Clone)]
pub enum AlterPgPolicyAction {
    /// ALTER POLICY name ON table RENAME TO new_name
    Rename {
        rename_span: Span,
        to_span: Span,
        new_name: Span,
    },
    /// ALTER POLICY name ON table [TO ...] [USING (...)] [WITH CHECK (...)]
    Modify {
        roles: Vec<PgPolicyRole>,
        to_span: Option<Span>,
        using_expr: Option<Box<AstExpr>>,
        using_span: Option<Span>,
        check_expr: Option<Box<AstExpr>>,
        with_check_span: Option<Span>,
    },
}

/// ALTER POLICY statement (PostgreSQL).
///
/// ```sql
/// ALTER POLICY name ON table_name RENAME TO new_name
/// ALTER POLICY name ON table_name
///     [ TO { role_name | PUBLIC | ... } [, ...] ]
///     [ USING ( expr ) ]
///     [ WITH CHECK ( expr ) ]
/// ```
#[derive(Debug, Clone)]
pub struct AstAlterPgPolicy {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    pub syntax_id: Option<crate::syntax::SyntaxAlterPgPolicyStmtId>,
    /// Policy name
    pub policy_name: Span,
    /// Table name (possibly schema-qualified)
    pub table_name: Span,
    /// The action
    pub action: AlterPgPolicyAction,
}

/// DROP POLICY statement (PostgreSQL).
///
/// ```sql
/// DROP POLICY [ IF EXISTS ] name ON table_name [ CASCADE | RESTRICT ]
/// ```
#[derive(Debug, Clone)]
pub struct AstDropPgPolicy {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    pub syntax_id: Option<crate::syntax::SyntaxDropPgPolicyStmtId>,
    /// True if IF EXISTS present
    pub if_exists: bool,
    /// Policy name
    pub policy_name: Span,
    /// Table name (possibly schema-qualified)
    pub table_name: Span,
    /// CASCADE or RESTRICT
    pub cascade_restrict: Option<PgCascadeRestrict>,
}

// =============================================================================
// PostgreSQL DOMAIN Statements
// =============================================================================

/// A single constraint within a CREATE DOMAIN or ALTER DOMAIN ADD CONSTRAINT.
///
/// Covers: [CONSTRAINT name] { NOT NULL | NULL | CHECK (expression) }
#[derive(Debug, Clone)]
pub struct DomainConstraint {
    /// Full span of this constraint (from CONSTRAINT keyword or NOT/NULL/CHECK to end)
    pub span: Span,
    /// Optional constraint name: `CONSTRAINT <name>`
    pub constraint_name: Option<Span>,
    /// The kind of constraint
    pub kind: DomainConstraintKind,
}

/// The kind of domain constraint.
#[derive(Debug, Clone)]
pub enum DomainConstraintKind {
    /// NOT NULL
    NotNull {
        /// Span covering "NOT NULL"
        span: Span,
    },
    /// NULL (explicitly nullable)
    Null {
        /// Span covering "NULL"
        span: Span,
    },
    /// CHECK (expression)
    Check {
        /// Span covering "CHECK (expression)" including parentheses
        check_span: Span,
        /// The parsed CHECK expression
        expression: Box<AstExpr>,
    },
}

/// CREATE DOMAIN statement (PostgreSQL).
///
/// ```sql
/// CREATE DOMAIN name [AS] data_type
///   [COLLATE collation]
///   [DEFAULT expression]
///   [domain_constraint ...]
/// ```
#[derive(Debug, Clone)]
pub struct AstCreateDomain {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    pub syntax_id: Option<crate::syntax::SyntaxCreateDomainStmtId>,
    /// Domain name (possibly schema-qualified)
    pub domain_name: Span,
    /// Optional AS keyword span
    pub as_keyword_span: Option<Span>,
    /// Data type span (e.g., "TEXT", "VARCHAR(255)", "NUMERIC(5,2)", "INTEGER[]")
    pub data_type_span: Span,
    /// Optional COLLATE collation span (covers `COLLATE <collation>`)
    pub collate_span: Option<Span>,
    /// Optional DEFAULT expression
    pub default_expr: Option<Box<AstExpr>>,
    /// Span of DEFAULT keyword + expression (for formatting fallback)
    pub default_span: Option<Span>,
    /// Constraints (NOT NULL, NULL, CHECK ...)
    pub constraints: Vec<DomainConstraint>,
}

/// ALTER DOMAIN action variants.
#[derive(Debug, Clone)]
pub enum AlterDomainAction {
    /// SET DEFAULT expression
    SetDefault {
        span: Span,
        expression: Box<AstExpr>,
    },
    /// DROP DEFAULT
    DropDefault { span: Span },
    /// SET NOT NULL
    SetNotNull { span: Span },
    /// DROP NOT NULL
    DropNotNull { span: Span },
    /// ADD [CONSTRAINT name] { NOT NULL | CHECK (expr) } [NOT VALID]
    AddConstraint {
        span: Span,
        constraint: DomainConstraint,
        not_valid: bool,
    },
    /// DROP CONSTRAINT [IF EXISTS] name [RESTRICT | CASCADE]
    DropConstraint {
        span: Span,
        if_exists: bool,
        constraint_name: Span,
        cascade_restrict: Option<PgCascadeRestrict>,
    },
    /// RENAME CONSTRAINT old_name TO new_name
    RenameConstraint {
        span: Span,
        old_name: Span,
        new_name: Span,
    },
    /// VALIDATE CONSTRAINT name
    ValidateConstraint { span: Span, constraint_name: Span },
    /// OWNER TO { user | CURRENT_ROLE | CURRENT_USER | SESSION_USER }
    OwnerTo { span: Span, new_owner: Span },
    /// RENAME TO new_name
    RenameTo { span: Span, new_name: Span },
    /// SET SCHEMA new_schema
    SetSchema { span: Span, new_schema: Span },
}

/// ALTER DOMAIN statement (PostgreSQL).
///
/// ```sql
/// ALTER DOMAIN name <action>
/// ```
#[derive(Debug, Clone)]
pub struct AstAlterDomain {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    pub syntax_id: Option<crate::syntax::SyntaxAlterDomainStmtId>,
    /// Domain name (possibly schema-qualified)
    pub domain_name: Span,
    /// The alter action
    pub action: AlterDomainAction,
}

/// DROP DOMAIN statement (PostgreSQL).
///
/// ```sql
/// DROP DOMAIN [IF EXISTS] name [, ...] [CASCADE | RESTRICT]
/// ```
#[derive(Debug, Clone)]
pub struct AstDropDomain {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    pub syntax_id: Option<crate::syntax::SyntaxDropDomainStmtId>,
    /// True if IF EXISTS present
    pub if_exists: bool,
    /// Domain names (one or more, possibly schema-qualified)
    pub domain_names: Vec<Span>,
    /// CASCADE or RESTRICT
    pub cascade_restrict: Option<PgCascadeRestrict>,
}

// =============================================================================
// ALTER INDEX (PostgreSQL)
// =============================================================================

/// ALTER INDEX statement (PostgreSQL).
///
/// Covers all subforms:
/// - `ALTER INDEX [ IF EXISTS ] name RENAME TO new_name`
/// - `ALTER INDEX [ IF EXISTS ] name SET TABLESPACE ts_name`
/// - `ALTER INDEX [ IF EXISTS ] name ATTACH PARTITION index_name`
/// - `ALTER INDEX [ IF EXISTS ] name [NO] DEPENDS ON EXTENSION ext_name`
/// - `ALTER INDEX [ IF EXISTS ] name SET ( param = value [, ...] )`
/// - `ALTER INDEX [ IF EXISTS ] name RESET ( param [, ...] )`
/// - `ALTER INDEX [ IF EXISTS ] name ALTER [ COLUMN ] column_number SET STATISTICS integer`
/// - `ALTER INDEX ALL IN TABLESPACE name [ OWNED BY ... ] SET TABLESPACE new_ts [ NOWAIT ]`
#[derive(Debug, Clone)]
pub struct AstAlterIndex {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    pub syntax_id: Option<crate::syntax::SyntaxAlterIndexStmtId>,
    /// The action being performed
    pub action: AlterIndexAction,
}

/// The specific action in an ALTER INDEX statement.
#[derive(Debug, Clone)]
pub enum AlterIndexAction {
    /// ALTER INDEX [IF EXISTS] name action
    Named {
        /// Span of IF keyword (if IF EXISTS is present)
        if_span: Option<Span>,
        /// Span of EXISTS keyword (if IF EXISTS is present)
        exists_span: Option<Span>,
        /// Index name span (possibly schema-qualified)
        name: Span,
        /// The sub-action
        sub_action: AlterIndexSubAction,
    },
    /// `ALTER INDEX ALL IN TABLESPACE name [OWNED BY role [, ...]] SET TABLESPACE new_ts [NOWAIT]`
    AllInTablespace {
        /// Span of ALL keyword
        all_span: Span,
        /// Span of IN keyword
        in_span: Span,
        /// Span of first TABLESPACE keyword
        tablespace_span: Span,
        /// Source tablespace name span
        tablespace_name: Span,
        /// Span of OWNED keyword (if present)
        owned_span: Option<Span>,
        /// Span of BY keyword (if present)
        by_span: Option<Span>,
        /// OWNED BY roles (empty if not present)
        owned_by_roles: Vec<Span>,
        /// Span of SET keyword
        set_span: Span,
        /// Span of second TABLESPACE keyword
        set_tablespace_span: Span,
        /// Target tablespace name span
        new_tablespace_name: Span,
        /// Span of NOWAIT keyword (if present)
        nowait_span: Option<Span>,
        /// End position of the entire clause (accounts for NOWAIT)
        end_pos: u32,
    },
    /// T-SQL: `ALTER INDEX { name | ALL } ON <object> { REBUILD | REORGANIZE | DISABLE | SET (...) }`
    OnObject {
        /// Index name span; `None` when `ALL` is used
        name: Option<Span>,
        /// Span of `ALL` keyword (present when `name` is `None`)
        all_span: Option<Span>,
        /// Span of `ON` keyword
        on_span: Span,
        /// Target table/view name span (possibly schema-qualified)
        object: Span,
        /// Which maintenance action
        maintenance: AlterIndexMaintenance,
        /// Span of the maintenance keyword (`REBUILD`/`REORGANIZE`/`DISABLE`/`SET`)
        maintenance_span: Span,
        /// Preserved span of any trailing options (`PARTITION = …`, `WITH (…)`,
        /// or the `SET (…)` body) — emitted verbatim. `None` when absent.
        tail_span: Option<Span>,
    },
}

/// T-SQL ALTER INDEX maintenance action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlterIndexMaintenance {
    Rebuild,
    Reorganize,
    Disable,
    Set,
}

/// Sub-actions for named ALTER INDEX.
#[derive(Debug, Clone)]
pub enum AlterIndexSubAction {
    /// RENAME TO new_name
    RenameTo {
        rename_span: Span,
        to_span: Span,
        new_name: Span,
    },
    /// SET TABLESPACE tablespace_name
    SetTablespace {
        set_span: Span,
        tablespace_span: Span,
        tablespace_name: Span,
    },
    /// ATTACH PARTITION index_name
    AttachPartition {
        attach_span: Span,
        partition_span: Option<Span>,
        index_name: Span,
    },
    /// `[NO] DEPENDS ON EXTENSION extension_name`
    DependsOnExtension {
        no_span: Option<Span>,
        depends_span: Span,
        on_span: Span,
        extension_span: Span,
        extension_name: Span,
    },
    /// SET ( param = value [, ...] )
    SetParams { set_span: Span, params_span: Span },
    /// RESET ( param [, ...] )
    ResetParams { reset_span: Span, params_span: Span },
    /// `ALTER [ COLUMN ] column_number SET STATISTICS integer`
    AlterColumnStatistics {
        alter_span: Span,
        column_span: Option<Span>,
        column_number: Span,
        set_span: Span,
        statistics_span: Span,
        statistics_value: Span,
    },
}

// =============================================================================
// REINDEX (PostgreSQL)
// =============================================================================

/// REINDEX statement (PostgreSQL).
///
/// ```sql
/// REINDEX [ ( option [, ...] ) ] { INDEX | TABLE | SCHEMA } [ CONCURRENTLY ] name
/// REINDEX [ ( option [, ...] ) ] { DATABASE | SYSTEM } [ CONCURRENTLY ] [ name ]
/// ```
#[derive(Debug, Clone)]
pub struct AstReindex {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    pub syntax_id: Option<crate::syntax::SyntaxReindexStmtId>,
    /// Parenthesized options (spans the full `( ... )` block if present)
    pub options_span: Option<Span>,
    /// The target type (INDEX, TABLE, SCHEMA, DATABASE, SYSTEM)
    pub target_type: ReindexTargetType,
    /// Span of the target type keyword
    pub target_type_span: Span,
    /// Span of CONCURRENTLY keyword (if present)
    pub concurrently_span: Option<Span>,
    /// Target name (optional for DATABASE/SYSTEM)
    pub name: Option<Span>,
}

/// Target type for REINDEX.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReindexTargetType {
    Index,
    Table,
    Schema,
    Database,
    System,
}

// =============================================================================
// PREPARE / EXECUTE / DEALLOCATE (PostgreSQL prepared statements)
// =============================================================================

/// PREPARE statement (PostgreSQL).
///
/// ```sql
/// PREPARE name [ ( data_type [, ...] ) ] AS statement
/// ```
#[derive(Debug, Clone)]
pub struct AstPgPrepare {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    pub syntax_id: Option<crate::syntax::SyntaxPgPrepareStmtId>,
    /// Name of the prepared statement
    pub name: Span,
    /// Optional parameter type list span (includes parens)
    pub param_types_span: Option<Span>,
    /// Span of the AS keyword (PostgreSQL form). For the MySQL
    /// `PREPARE name FROM <expr>` form this span covers the FROM
    /// keyword instead — both spellings are accepted, and the
    /// `from_expr` field disambiguates.
    pub as_span: Span,
    /// PostgreSQL form: the inner statement (SELECT, INSERT, UPDATE,
    /// DELETE, MERGE, VALUES) following the `AS` keyword.
    /// MySQL `PREPARE name FROM <expr>` form populates `from_expr`
    /// instead; this field is a synthetic placeholder (typically
    /// `AstStmt::Null`).
    pub body: Box<AstStmt>,
    /// MySQL form: the FROM-clause expression that yields the SQL
    /// string to prepare (string literal, session variable, or
    /// `CONCAT(...)`-built expression). `None` for the PostgreSQL
    /// `PREPARE … AS <stmt>` form.
    pub from_expr: Option<Box<AstExpr>>,
}

/// EXECUTE prepared statement (PostgreSQL).
///
/// ```sql
/// EXECUTE name [ ( parameter [, ...] ) ]
/// ```
#[derive(Debug, Clone)]
pub struct AstPgExecute {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    pub syntax_id: Option<crate::syntax::SyntaxPgExecuteStmtId>,
    /// Name of the prepared statement to execute
    pub name: Span,
    /// Optional argument list span (includes parens) — PostgreSQL
    /// `EXECUTE name (expr, ...)` form.
    pub args_span: Option<Span>,
    /// Optional MySQL bind-parameter tail span covering `USING @v1, @v2,
    /// ...` (includes the USING keyword). Mutually exclusive with
    /// `args_span` in practice.
    pub using_span: Option<Span>,
}

/// DEALLOCATE prepared statement (PostgreSQL).
///
/// ```sql
/// DEALLOCATE [ PREPARE ] { name | ALL }
/// ```
#[derive(Debug, Clone)]
pub struct AstPgDeallocate {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    pub syntax_id: Option<crate::syntax::SyntaxPgDeallocateStmtId>,
    /// Optional span of PREPARE keyword when present
    pub prepare_span: Option<Span>,
    /// The target: either a name span or ALL
    pub target: PgDeallocateTarget,
}

/// Target for DEALLOCATE.
#[derive(Debug, Clone)]
pub enum PgDeallocateTarget {
    /// DEALLOCATE name
    Name(Span),
    /// DEALLOCATE ALL
    All(Span),
}

/// PostgreSQL COPY statement.
///
/// ```sql
/// COPY table_name [ (col, ...) ] FROM { 'file' | PROGRAM 'cmd' | STDIN }
///     [ [ WITH ] ( option [, ...] ) ] [ WHERE condition ]
///
/// COPY { table_name [ (col, ...) ] | ( query ) } TO { 'file' | PROGRAM 'cmd' | STDOUT }
///     [ [ WITH ] ( option [, ...] ) ]
/// ```
#[derive(Debug, Clone)]
pub struct AstPgCopy {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    pub syntax_id: Option<crate::syntax::SyntaxPgCopyStmtId>,
    /// FROM or TO
    pub direction: PgCopyDirection,
    /// Table name span (possibly schema-qualified), or query span (including parens)
    pub subject: PgCopySubject,
    /// Optional column list span including parens: (col1, col2, ...)
    pub columns_span: Option<Span>,
    /// The source/destination span
    pub target: PgCopyTarget,
    /// Optional WITH (...) options span (includes parens and optional WITH keyword)
    pub options_span: Option<Span>,
    /// Optional WHERE clause span (COPY FROM only)
    pub where_span: Option<Span>,
}

/// Direction for PG COPY.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PgCopyDirection {
    From,
    To,
}

/// The subject of a PG COPY statement.
#[derive(Debug, Clone)]
pub enum PgCopySubject {
    /// A table name (possibly schema-qualified)
    Table(Span),
    /// A parenthesized query: (SELECT ...)
    /// The span covers the full `(SELECT ...)` including parens (for formatting).
    /// The AstStmt is the parsed inner query (for semantic extraction).
    Query(Span, Box<AstStmt>),
}

/// The target/source of a PG COPY statement.
#[derive(Debug, Clone)]
pub enum PgCopyTarget {
    /// A filename string literal
    File(Span),
    /// PROGRAM 'command' — span covers PROGRAM keyword + string literal
    Program(Span),
    /// STDIN
    Stdin(Span),
    /// STDOUT
    Stdout(Span),
    /// A psql client variable used as the endpoint, e.g. `COPY t FROM :source`
    /// (also `:'var'`). The concrete path is unknown until the psql client
    /// substitutes it, so it is not a literal File. Span covers ':' through the
    /// variable token.
    Placeholder(Span),
}

/// PostgreSQL REFRESH MATERIALIZED VIEW statement.
///
/// ```sql
/// REFRESH MATERIALIZED VIEW [ CONCURRENTLY ] name [ WITH [ NO ] DATA ]
/// ```
#[derive(Debug, Clone)]
pub struct AstPgRefreshMatview {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    pub syntax_id: Option<crate::syntax::SyntaxPgRefreshMatviewStmtId>,
    /// Span covering "MATERIALIZED VIEW" (two tokens)
    pub materialized_view_span: Span,
    /// Whether CONCURRENTLY was specified
    pub concurrently: bool,
    /// Span of the CONCURRENTLY keyword (if present)
    pub concurrently_span: Option<Span>,
    /// Span covering the view name (possibly schema-qualified)
    pub name_span: Span,
    /// WITH DATA = Some(true), WITH NO DATA = Some(false), omitted = None
    pub with_data: Option<bool>,
    /// Span covering the `WITH [NO] DATA` clause (if present)
    pub with_data_span: Option<Span>,
}

/// Simple PostgreSQL utility statement — span-based passthrough.
///
/// Used for administrative statements (LISTEN, NOTIFY, UNLISTEN, LOCK TABLE,
/// CREATE RULE, CREATE AGGREGATE, CREATE OPERATOR, ALTER SYSTEM,
/// DROP OWNED, REASSIGN OWNED, DISCARD, CLUSTER, PUBLICATION, SUBSCRIPTION)
/// that are parsed structurally but formatted via span passthrough.
#[derive(Debug, Clone)]
pub struct AstPgSimpleUtility {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
}

/// BigQuery EXPORT DATA statement with structured AST fields.
///
/// ```sql
/// EXPORT DATA
///   [WITH CONNECTION project.dataset.connection_name]
///   OPTIONS(uri='gs://bucket/path/*', format='CSV', ...)
///   AS query_statement
/// ```
#[derive(Debug, Clone)]
pub struct AstBqExportData {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    /// Span covering 'EXPORT DATA' keywords
    pub keyword_span: Span,
    /// Optional WITH CONNECTION clause span (covers `WITH CONNECTION name`)
    pub connection_span: Option<Span>,
    /// Span covering the entire OPTIONS(...) clause including parentheses
    pub options_span: Span,
    /// The inner query statement after AS (typically a SELECT)
    pub query: Box<AstStmt>,
}

/// BigQuery LOAD DATA statement with structured AST fields.
///
/// ```sql
/// LOAD DATA [INTO | OVERWRITE] [TEMP TABLE] target_table
///   [(column_spec)]
///   [PARTITION BY col [CLUSTER BY col]]
///   FROM FILES(key=value, ...)
///   [WITH PARTITION COLUMNS [(col_spec)]]
///   [WITH CONNECTION conn_name]
/// ```
#[derive(Debug, Clone)]
pub struct AstBqLoadData {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    /// Span covering 'LOAD DATA' keywords
    pub keyword_span: Span,
    /// Span covering the target table name (including qualifiers)
    pub target_table_span: Span,
    /// Span covering the FROM FILES(...) clause including parentheses
    pub from_files_span: Span,
    /// Span covering trailing clauses (WITH PARTITION COLUMNS and/or WITH CONNECTION)
    /// if any are present. None if no trailing clauses.
    pub trailing_clauses_span: Option<Span>,
}

/// MySQL `LOAD DATA [LOW_PRIORITY | CONCURRENT] [LOCAL] INFILE '<path>'
///   [REPLACE | IGNORE] INTO TABLE tbl_name [PARTITION (...)] [CHARACTER SET ...]
///   [FIELDS ...] [LINES ...] [IGNORE n LINES] [(col, ...)] [SET ...]`.
///
/// Bulk file ingestion. `LOCAL` reads the file from the *client* host and
/// streams it to the server (an abuse vector, disabled by default in hardened
/// configs); without it the path is read from the database server's filesystem
/// (requires the FILE privilege). Distinct grammar from BigQuery's
/// `LOAD DATA … FROM FILES(...)` (see [`AstBqLoadData`]).
#[derive(Debug, Clone)]
pub struct AstMysqlLoadData {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    /// Span covering the `LOAD DATA` keywords.
    pub keyword_span: Span,
    /// True when the `LOCAL` modifier is present.
    pub local: bool,
    /// Span of the `INFILE '<path>'` file-path string literal.
    pub infile_path_span: Span,
    /// Span of the `INTO TABLE <name>` target (possibly qualified). `None` only
    /// when the clause is malformed / absent.
    pub target_table_span: Option<Span>,
}

/// MySQL `RENAME TABLE a TO b [, c TO d, ...]` — renames one or more tables
/// atomically. Each pair renames `from` to `to`.
#[derive(Debug, Clone)]
pub struct AstMysqlRenameTable {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    /// Span of the RENAME keyword.
    pub rename_span: Span,
    /// Span of the TABLE keyword.
    pub table_span: Span,
    /// The rename pairs, in statement order (at least one).
    pub pairs: Vec<AstRenameTablePair>,
}

/// One `<from> TO <to>` pair of a `RENAME TABLE` statement.
#[derive(Debug, Clone)]
pub struct AstRenameTablePair {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    /// The current (source) table name, possibly qualified.
    pub from_name_span: Span,
    /// Span of the TO keyword.
    pub to_span: Span,
    /// The new table name, possibly qualified.
    pub to_name_span: Span,
}

/// A MySQL `DEFINER = { user | CURRENT_USER }` clause — the security context a
/// routine (event, procedure, function, trigger, view) runs under. The body
/// executes with the definer's privileges regardless of who invokes it, so the
/// named principal is a privilege-delegation primitive.
#[derive(Debug, Clone)]
pub struct AstDefiner {
    /// Span covering the whole `DEFINER = …` clause.
    pub span: Span,
    pub principal: AstDefinerPrincipal,
}

/// The principal named by a `DEFINER =` clause.
#[derive(Debug, Clone)]
pub enum AstDefinerPrincipal {
    /// `CURRENT_USER` (optionally `()`) — runs as the creating session's user.
    CurrentUser,
    /// `'user'@'host'`, a bare user, or `` `user` `` — an explicit account.
    Named {
        /// Span of the user token (may be quoted; dequoted downstream).
        user_span: Span,
        /// Inner span of the `@'host'` part, when present (no quotes).
        host_span: Option<Span>,
    },
}

/// Timing of a MySQL trigger relative to the row event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TriggerTiming {
    /// `BEFORE` the row change.
    Before,
    /// `AFTER` the row change.
    After,
}

/// The DML event a MySQL trigger fires on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TriggerEvent {
    Insert,
    Update,
    Delete,
}

/// MySQL `CREATE [DEFINER = user] TRIGGER [IF NOT EXISTS] name
///   { BEFORE | AFTER } { INSERT | UPDATE | DELETE } ON tbl
///   FOR EACH ROW [{ FOLLOWS | PRECEDES } other] <body>`
///
/// A trigger runs its inline body automatically on every matching row event,
/// under the definer's privileges — an automatic-execution and persistence
/// surface. The body is sub-parsed into `body_stmt` so its inner SQL is
/// visible as statements (a trigger that `GRANT`s or `DROP`s on write is
/// visible). Recognition primitives: timing, event, target table, and definer.
#[derive(Debug, Clone)]
pub struct AstCreateMysqlTrigger {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    /// Span covering the `CREATE` keyword.
    pub create_span: Span,
    /// The `DEFINER = …` security-context clause, when present.
    pub definer: Option<AstDefiner>,
    /// Span covering `IF NOT EXISTS`, if present.
    pub if_not_exists_span: Option<Span>,
    /// Span covering the trigger name (possibly qualified).
    pub name_span: Span,
    /// `BEFORE` / `AFTER`.
    pub timing: TriggerTiming,
    /// `INSERT` / `UPDATE` / `DELETE`.
    pub event: TriggerEvent,
    /// Span of the `ON <table>` target (possibly qualified).
    pub target_table_span: Span,
    /// The sub-parsed trigger body. `None` when unparseable (raw bytes still
    /// covered by `span`).
    pub body_stmt: Option<Box<AstStmt>>,
}

/// Schedule kind for a MySQL `EVENT` — the `ON SCHEDULE` clause shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventScheduleKind {
    /// `AT <timestamp>` — fires exactly once.
    OneTime,
    /// `EVERY <interval>` — fires repeatedly on an interval.
    Recurring,
}

/// Enable state for a MySQL `EVENT`. Default (unwritten) is `Enable`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventEnableState {
    /// `ENABLE` (or unwritten — the MySQL default).
    Enable,
    /// `DISABLE`.
    Disable,
    /// `DISABLE ON SLAVE` — enabled on the source, disabled on replicas.
    DisableOnSlave,
}

/// MySQL `CREATE [DEFINER = user] EVENT [IF NOT EXISTS] name
///   ON SCHEDULE { AT ts | EVERY interval [STARTS …] [ENDS …] }
///   [ON COMPLETION [NOT] PRESERVE]
///   [ENABLE | DISABLE | DISABLE ON SLAVE]
///   [COMMENT 'string']
///   DO <stmt>`
///
/// A scheduled job that runs arbitrary SQL — the MySQL analog of a Snowflake
/// TASK. The `DO` body is sub-parsed into `body_stmt` so its inner SQL is
/// visible as statements (a recurring scheduled `DROP`/`GRANT` is visible).
/// Recognition primitives: the schedule kind (one-time vs recurring), whether
/// the event is preserved after completion, and the enable state; the
/// governance verdict is the consumer's.
#[derive(Debug, Clone)]
pub struct AstCreateEvent {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    /// Span covering the `CREATE` keyword.
    pub create_span: Span,
    /// Span covering the `EVENT` identifier.
    pub event_span: Span,
    /// The `DEFINER = …` security-context clause, when present.
    pub definer: Option<AstDefiner>,
    /// Span covering `IF NOT EXISTS`, if present.
    pub if_not_exists_span: Option<Span>,
    /// Span covering the event name (possibly qualified).
    pub name_span: Span,
    /// Schedule kind (`AT` one-time vs `EVERY` recurring).
    pub schedule_kind: EventScheduleKind,
    /// True when `ON COMPLETION PRESERVE` (the event survives after firing).
    pub on_completion_preserve: bool,
    /// Enable state (`ENABLE` default / `DISABLE` / `DISABLE ON SLAVE`).
    pub enable_state: EventEnableState,
    /// Span of the `DO` keyword.
    pub do_span: Span,
    /// The sub-parsed `DO` body statement. `None` when the body was
    /// unparseable — the raw bytes are still covered by `span`.
    pub body_stmt: Option<Box<AstStmt>>,
}

/// MySQL `ALTER [DEFINER = user] EVENT name
///   [ON SCHEDULE schedule] [ON COMPLETION [NOT] PRESERVE]
///   [RENAME TO new_name] [ENABLE | DISABLE | DISABLE ON SLAVE]
///   [COMMENT 'string'] [DO <stmt>]`
///
/// Every clause is optional. Governance-relevant primitives: whether the
/// schedule was changed, whether the event was renamed, the new enable state,
/// and whether the `DO` body was rebound (`body_stmt`) — a scheduled-SQL
/// repoint.
#[derive(Debug, Clone)]
pub struct AstAlterEvent {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    /// The `DEFINER = …` security-context clause, when present (rebinds the
    /// account the scheduled body runs under).
    pub definer: Option<AstDefiner>,
    /// Span covering the event name (possibly qualified).
    pub name_span: Span,
    /// True when an `ON SCHEDULE` clause is present (reschedule).
    pub schedule_present: bool,
    /// True when a `RENAME TO` clause is present.
    pub rename_present: bool,
    /// New enable state, when `ENABLE`/`DISABLE` is present.
    pub enable_state: Option<EventEnableState>,
    /// The sub-parsed new `DO` body, when present (rebinds the scheduled SQL).
    pub body_stmt: Option<Box<AstStmt>>,
}

/// BigQuery ASSERT statement with structured expression.
///
/// ```sql
/// ASSERT expression [AS description]
/// ```
///
/// The expression can be any boolean expression including subqueries.
/// The description is an optional string literal.
#[derive(Debug, Clone)]
pub struct AstBqAssert {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    /// Span covering 'ASSERT' keyword
    pub keyword_span: Span,
    /// The boolean expression to evaluate
    pub expression: Box<AstExpr>,
    /// Optional description string literal span (includes the AS keyword)
    pub description_span: Option<Span>,
}

/// Span-passthrough node for BigQuery-specific statements
/// (DROP SNAPSHOT TABLE, ALTER VECTOR INDEX)
/// that are parsed structurally but formatted via span passthrough.
#[derive(Debug, Clone)]
pub struct AstBqSimpleUtility {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
}

/// Databricks CREATE FLOW statement — span-based passthrough.
///
/// Covers Lakeflow/SDP CDC flow definitions, including legacy
/// `APPLY CHANGES INTO` and modern `AUTO CDC INTO` forms.
#[derive(Debug, Clone)]
pub struct AstCreateFlow {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
}

// ============================================================================
// BigQuery SNAPSHOT TABLE
// ============================================================================

/// CREATE SNAPSHOT TABLE name CLONE source [FOR SYSTEM_TIME AS OF ...] [OPTIONS(...)]
#[derive(Debug, Clone)]
pub struct AstBqCreateSnapshotTable {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    /// Span covering 'CREATE SNAPSHOT TABLE' keywords
    pub keyword_span: Span,
    /// Span covering the snapshot table name (target)
    pub snapshot_name_span: Span,
    /// Span covering the source table name after CLONE
    pub source_table_span: Span,
    /// Optional trailing clauses (FOR SYSTEM_TIME AS OF, OPTIONS)
    pub trailing_clauses_span: Option<Span>,
}

// ============================================================================
// BigQuery SEARCH INDEX
// ============================================================================

/// CREATE SEARCH INDEX [IF NOT EXISTS] name ON table(columns) [OPTIONS(...)]
#[derive(Debug, Clone)]
pub struct AstBqCreateSearchIndex {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    /// Span covering 'CREATE SEARCH INDEX' keywords (includes optional IF NOT EXISTS)
    pub keyword_span: Span,
    /// Span covering the index name
    pub index_name_span: Span,
    /// Span covering the table name after ON
    pub table_span: Span,
    /// Span covering the column list in parentheses
    pub columns_span: Span,
    /// Optional OPTIONS(...) clause span
    pub options_span: Option<Span>,
}

/// DROP SEARCH INDEX [IF EXISTS] name ON table
#[derive(Debug, Clone)]
pub struct AstBqDropSearchIndex {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    /// Span covering 'DROP SEARCH INDEX' keywords (includes optional IF EXISTS)
    pub keyword_span: Span,
    /// Span covering the index name
    pub index_name_span: Span,
    /// Span covering the table name after ON
    pub table_span: Span,
}

// ============================================================================
// BigQuery VECTOR INDEX
// ============================================================================

/// CREATE [OR REPLACE] VECTOR INDEX [IF NOT EXISTS] name ON table(column) [STORING(...)] [OPTIONS(...)]
#[derive(Debug, Clone)]
pub struct AstBqCreateVectorIndex {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    /// Span covering 'CREATE [OR REPLACE] VECTOR INDEX' keywords (includes optional IF NOT EXISTS)
    pub keyword_span: Span,
    /// Span covering the index name
    pub index_name_span: Span,
    /// Span covering the table name after ON
    pub table_span: Span,
    /// Span covering the column list in parentheses
    pub columns_span: Span,
    /// Optional STORING(...) clause span
    pub storing_span: Option<Span>,
    /// Optional OPTIONS(...) clause span
    pub options_span: Option<Span>,
}

/// DROP VECTOR INDEX [IF EXISTS] name ON table
#[derive(Debug, Clone)]
pub struct AstBqDropVectorIndex {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    /// Span covering 'DROP VECTOR INDEX' keywords (includes optional IF EXISTS)
    pub keyword_span: Span,
    /// Span covering the index name
    pub index_name_span: Span,
    /// Span covering the table name after ON
    pub table_span: Span,
}

// ── MSSQL SQL Server 2025 ──

/// CREATE EXTERNAL MODEL name [AUTHORIZATION owner] WITH (options)
#[derive(Debug, Clone)]
pub struct AstMssqlCreateExternalModel {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    /// Span covering 'CREATE EXTERNAL MODEL' keywords
    pub keyword_span: Span,
    /// Span covering the model name
    pub name_span: Span,
    /// Optional AUTHORIZATION clause span
    pub authorization_span: Option<Span>,
    /// WITH (...) options span (required)
    pub with_options_span: Span,
}

/// CREATE EXTERNAL DATA SOURCE name WITH (LOCATION = '...', [TYPE = ...],
/// [CREDENTIAL = name], [PUSHDOWN = ON|OFF], ...)
///
/// T-SQL / PolyBase. Registers a federated endpoint (Hadoop, Azure blob,
/// remote RDBMS, sharded DB). Recognition lifts neutral primitives only;
/// the raw LOCATION literal is dropped at parse time because PolyBase
/// connection strings can embed credentials.
#[derive(Debug, Clone)]
pub struct AstMssqlCreateExternalDataSource {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    /// Span covering 'CREATE EXTERNAL DATA SOURCE' keywords
    pub keyword_span: Span,
    /// `CREATE OR { REPLACE | ALTER }` modifier present.
    pub or_replace: bool,
    /// `IF NOT EXISTS` present.
    pub if_not_exists: bool,
    /// Span covering the data-source name
    pub name_span: Span,
    /// True when a LOCATION clause is present.
    pub location_present: bool,
    /// Lowercased URI scheme of the LOCATION value (chars before `://`),
    /// e.g. `hdfs`, `wasbs`, `abfss`, `https`, `sqlserver`. `None` when no
    /// LOCATION, or the value has no `://` separator.
    pub location_scheme: Option<String>,
    /// Typed TYPE value, when one of the documented classes is named.
    pub source_type: Option<AstExternalDataSourceType>,
    /// True when a `CREDENTIAL = <name>` clause is present.
    pub credential_present: bool,
    /// PUSHDOWN = ON (`Some(true)`) / OFF (`Some(false)`); `None` when absent.
    pub pushdown: Option<bool>,
}

/// Documented TYPE classes for a T-SQL external data source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AstExternalDataSourceType {
    /// `TYPE = HADOOP`
    Hadoop,
    /// `TYPE = BLOB_STORAGE`
    BlobStorage,
    /// `TYPE = RDBMS`
    Rdbms,
    /// `TYPE = SHARD_MAP_MANAGER`
    ShardMapManager,
}

/// T-SQL / PolyBase `ALTER EXTERNAL DATA SOURCE name SET { LOCATION = … |
/// CREDENTIAL = … | … }`. Reconfigures an existing federated endpoint —
/// `SET LOCATION` redirects it, `SET CREDENTIAL` swaps its stored credential.
/// Lifts the same neutral recognition primitives as the CREATE form; the raw
/// LOCATION literal is never surfaced.
#[derive(Debug, Clone)]
pub struct AstMssqlAlterExternalDataSource {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    /// Span covering 'ALTER EXTERNAL DATA SOURCE' keywords
    pub keyword_span: Span,
    /// Span covering the data-source name
    pub name_span: Span,
    /// True when a LOCATION clause is present.
    pub location_present: bool,
    /// Lowercased URI scheme of the LOCATION value (chars before `://`).
    /// `None` when no LOCATION, or the value has no `://` separator.
    pub location_scheme: Option<String>,
    /// Typed TYPE value, when one of the documented classes is named.
    pub source_type: Option<AstExternalDataSourceType>,
    /// True when a `CREDENTIAL = <name>` clause is present.
    pub credential_present: bool,
    /// PUSHDOWN = ON (`Some(true)`) / OFF (`Some(false)`); `None` when absent.
    pub pushdown: Option<bool>,
}

/// CREATE SERVER [IF NOT EXISTS] name [TYPE '…'] [VERSION '…']
///   FOREIGN DATA WRAPPER fdw_name [OPTIONS (key 'value', …)]
///
/// SQL/MED foreign server (PostgreSQL FDW). Registers a federated endpoint
/// reached through a foreign-data wrapper. The wrapper name is the
/// recognition discriminator (`postgres_fdw` reaches the network,
/// `file_fdw` reads server-side files, …). OPTION values are not surfaced.
#[derive(Debug, Clone)]
pub struct AstCreateForeignServer {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    /// Span covering the CREATE keyword.
    pub create_span: Span,
    /// Span covering the server name.
    pub name_span: Span,
    /// `IF NOT EXISTS` present.
    pub if_not_exists: bool,
    /// `TYPE '…'` clause present.
    pub type_present: bool,
    /// Lowercased foreign-data-wrapper name (the `FOREIGN DATA WRAPPER`
    /// operand). `None` only when the clause is malformed / absent.
    pub wrapper: Option<String>,
    /// `OPTIONS (…)` clause present.
    pub options_present: bool,
}

/// ALTER SERVER name [ VERSION '…' ] [ OPTIONS ( [ADD|SET|DROP] key ['val'], … ) ]
///   | ALTER SERVER name OWNER TO new_owner | ALTER SERVER name RENAME TO new_name
///
/// SQL/MED foreign-server reconfiguration (PostgreSQL / MySQL FDW). The only
/// governance axis surfaced is whether the `OPTIONS (…)` bag is modified — that
/// can silently repoint the federated endpoint at a different remote. VERSION /
/// OWNER TO / RENAME TO are recognized but not surfaced; option values never
/// leave the parser.
#[derive(Debug, Clone)]
pub struct AstAlterForeignServer {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    /// Span covering the server name.
    pub name_span: Span,
    /// True when the statement modifies the `OPTIONS (…)` bag.
    pub options_present: bool,
}

/// `ALTER SERVER CONFIGURATION SET <subsystem> …` (T-SQL)
///
/// SQL Server instance-level reconfiguration — unrelated to SQL/MED foreign
/// servers. The recognition primitive is the configuration subsystem, the
/// first word after `SET` (`PROCESS` affinity, `DIAGNOSTICS` log, `BUFFER`
/// pool extension, `HADR` cluster context, `FAILOVER` cluster property,
/// `SOFTNUMA`, `MEMORY_OPTIMIZED`, …). The value clause is consumed but not
/// surfaced.
#[derive(Debug, Clone)]
pub struct AstMssqlAlterServerConfiguration {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    /// Span of the first word after `SET` (the configuration subsystem).
    /// `None` when no `SET` clause is present.
    pub subsystem_span: Option<Span>,
}

/// CREATE USER MAPPING [IF NOT EXISTS] FOR { user | PUBLIC | CURRENT_USER … }
///   SERVER name [OPTIONS (key 'value', …)]
///
/// SQL/MED user mapping (PostgreSQL FDW). Attaches per-local-role credentials
/// for a foreign server. `FOR PUBLIC` maps every local role. OPTION values
/// (which include the remote password) are not surfaced as plaintext; the
/// password literal is registered for output redaction.
#[derive(Debug, Clone)]
pub struct AstCreateUserMapping {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    /// Span covering the CREATE keyword.
    pub create_span: Span,
    /// `IF NOT EXISTS` present.
    pub if_not_exists: bool,
    /// Span covering the `FOR` target (a role name, `PUBLIC`, or
    /// `CURRENT_USER` / `CURRENT_ROLE` / `USER` / `SESSION_USER`).
    pub user_span: Span,
    /// True when the mapping is `FOR PUBLIC` — it applies to every local role.
    pub is_public: bool,
    /// Span covering the foreign-server name.
    pub server_span: Span,
    /// `OPTIONS (…)` entries (key span + optional string-literal value span).
    pub options: Vec<AstUserMappingOption>,
}

/// One `OPTIONS (key 'value')` entry of a CREATE / ALTER USER MAPPING. On
/// ALTER, a leading `ADD` / `SET` / `DROP` keyword is consumed by the reader
/// and not stored — recognition needs only the key and its value literal.
#[derive(Debug, Clone)]
pub struct AstUserMappingOption {
    /// Span covering the option key identifier.
    pub key_span: Span,
    /// Inner-content span of the string-literal value (quotes stripped by the
    /// reader). `None` when the value is not a string literal.
    pub value_literal_span: Option<Span>,
}

/// ALTER USER MAPPING FOR { role | PUBLIC | … } SERVER name
///   OPTIONS ( [ADD|SET|DROP] key ['value'], … )
#[derive(Debug, Clone)]
pub struct AstAlterUserMapping {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    /// Span covering the ALTER keyword.
    pub alter_span: Span,
    /// Span covering the `FOR` target.
    pub user_span: Span,
    /// True when the mapping is `FOR PUBLIC`.
    pub is_public: bool,
    /// Span covering the foreign-server name.
    pub server_span: Span,
    /// `OPTIONS (…)` entries (ADD/SET/DROP prefix already consumed).
    pub options: Vec<AstUserMappingOption>,
}

/// CREATE FOREIGN TABLE [IF NOT EXISTS] name
///   ( column_defs… | PARTITION OF parent … ) SERVER name [OPTIONS (…)]
///
/// SQL/MED foreign table (PostgreSQL FDW). Exposes a remote relation locally;
/// queries against it cross the instance boundary to the foreign server. The
/// column definitions are not governance-relevant and are consumed without
/// being modelled.
#[derive(Debug, Clone)]
pub struct AstCreateForeignTable {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    /// Span covering the CREATE keyword.
    pub create_span: Span,
    /// Span covering the foreign-table name.
    pub name_span: Span,
    /// `IF NOT EXISTS` present.
    pub if_not_exists: bool,
    /// True for the `PARTITION OF parent` form (no own column list).
    pub is_partition: bool,
    /// Span covering the foreign-server name (the `SERVER` operand).
    pub server_span: Span,
    /// `OPTIONS (…)` clause present.
    pub options_present: bool,
}

/// Table-selection filter on `IMPORT FOREIGN SCHEMA`. `All` (no filter) imports
/// every remote table; `Except` imports all but a named few; `LimitTo` imports
/// only the named tables. The structural recognition primitive; whether a
/// broad import is acceptable is the consumer's verdict, not this enum's.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AstImportFilterMode {
    All,
    LimitTo,
    Except,
}

/// SQL/MED `IMPORT FOREIGN SCHEMA remote [{LIMIT TO|EXCEPT} (tables)]
/// FROM SERVER srv INTO local [OPTIONS (…)]` (PostgreSQL FDW). Bulk-exposes a
/// remote schema's tables locally in one statement — the bulk sibling of
/// `CREATE FOREIGN TABLE`. The named table list is not surfaced; only the
/// filter mode (which determines how much of the remote schema is exposed) is.
#[derive(Debug, Clone)]
pub struct AstImportForeignSchema {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    /// Span covering the IMPORT keyword.
    pub import_span: Span,
    /// Span covering the remote schema name being imported.
    pub remote_schema_span: Span,
    /// Span covering the foreign-server name (the `SERVER` operand).
    pub server_span: Span,
    /// Span covering the local schema the tables land in.
    pub local_schema_span: Span,
    /// Table-selection filter mode.
    pub filter_mode: AstImportFilterMode,
    /// `OPTIONS (…)` clause present.
    pub options_present: bool,
}

/// DROP USER MAPPING [IF EXISTS] FOR { role | PUBLIC | … } SERVER name
#[derive(Debug, Clone)]
pub struct AstDropUserMapping {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    /// Span covering the DROP keyword.
    pub drop_span: Span,
    /// `IF EXISTS` present.
    pub if_exists: bool,
    /// Span covering the `FOR` target.
    pub user_span: Span,
    /// True when the mapping is `FOR PUBLIC`.
    pub is_public: bool,
    /// Span covering the foreign-server name.
    pub server_span: Span,
}

/// ALTER EXTERNAL MODEL name SET (options)
#[derive(Debug, Clone)]
pub struct AstMssqlAlterExternalModel {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    /// Span covering 'ALTER EXTERNAL MODEL' keywords
    pub keyword_span: Span,
    /// Span covering the model name
    pub name_span: Span,
    /// SET (...) options span
    pub set_options_span: Span,
}

/// DROP EXTERNAL MODEL [IF EXISTS] name
#[derive(Debug, Clone)]
pub struct AstMssqlDropExternalModel {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    /// Span covering 'DROP EXTERNAL MODEL' keywords (includes optional IF EXISTS)
    pub keyword_span: Span,
    /// Span covering the model name
    pub name_span: Span,
}

/// CREATE VECTOR INDEX name ON table(column) WITH (options) [ON filegroup]
#[derive(Debug, Clone)]
pub struct AstMssqlCreateVectorIndex {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    /// Span covering 'CREATE VECTOR INDEX' keywords
    pub keyword_span: Span,
    /// Span covering the index name
    pub index_name_span: Span,
    /// Span covering the table name after ON
    pub table_span: Span,
    /// Span covering the column list in parentheses
    pub columns_span: Span,
    /// Optional WITH (...) options span
    pub with_options_span: Option<Span>,
    /// Optional ON filegroup clause span
    pub on_filegroup_span: Option<Span>,
}

// MSSQL `CREATE LOGIN` / `CREATE USER` were folded into the
// dialect-neutral [`AstCreatePrincipal`] substrate. The typed source
// classification rides on [`CreatePrincipalOptions::mssql_source`] via
// [`AstMssqlPrincipalSource`] below; the parser populates it from the
// `FROM EXTERNAL PROVIDER` / `WITH PASSWORD` / `FOR LOGIN` / `WITHOUT
// LOGIN` clause.

/// Closed enum classifying the source clause of `CREATE LOGIN` /
/// `CREATE USER`. The parser dispatches on the first keyword(s) of
/// the clause and assigns the typed variant; consumers consult this enum
/// directly.
///
/// `Unparsed` is the parser-side fallback when the clause is absent
/// (e.g., bare `CREATE LOGIN bob;`) or the keywords don't match a
/// documented form. New documented clauses are additive (non-breaking)
/// variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AstMssqlPrincipalSource {
    /// `FROM EXTERNAL PROVIDER` — Microsoft Entra ID / Azure AD
    /// authentication. Drives MSSQL-LOGIN-EXT and MSSQL-USER-EXT.
    FromExternalProvider,
    /// `WITH PASSWORD = '...'` — password-based authentication.
    WithPassword,
    /// `FROM CERTIFICATE name`.
    FromCertificate,
    /// `FROM ASYMMETRIC KEY name`.
    FromAsymmetricKey,
    /// `FROM WINDOWS [WITH ...]` — Windows-authenticated login.
    FromWindows,
    /// `FOR LOGIN name` — `CREATE USER` mapped to a server login.
    ForLogin,
    /// `WITHOUT LOGIN` — contained user with no server login.
    WithoutLogin,
    /// No source clause present or unrecognized form.
    Unparsed,
}

// ============================================================================
// BigQuery MODEL (BQML)
// ============================================================================

/// BigQuery CREATE MODEL statement (BQML).
///
/// ```sql
/// {CREATE MODEL | CREATE MODEL IF NOT EXISTS | CREATE OR REPLACE MODEL}
///   model_name
///   [TRANSFORM (select_list)]
///   [INPUT (field_name field_type, ...)]
///   [OUTPUT (field_name field_type, ...)]
///   [REMOTE WITH CONNECTION {`connection_name` | DEFAULT}]
///   [OPTIONS(model_option_list)]
///   [AS query_statement]
/// ```
#[derive(Debug, Clone)]
pub struct AstBqCreateModel {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    /// Span covering 'CREATE [OR REPLACE] MODEL [IF NOT EXISTS]' keywords
    pub keyword_span: Span,
    /// Whether OR REPLACE was specified
    pub or_replace: bool,
    /// Whether IF NOT EXISTS was specified
    pub if_not_exists: bool,
    /// Span covering the model name (may be backtick-quoted qualified name)
    pub model_name_span: Span,
    /// Optional TRANSFORM(...) clause span
    pub transform_span: Option<Span>,
    /// Optional INPUT(...) clause span
    pub input_span: Option<Span>,
    /// Optional OUTPUT(...) clause span
    pub output_span: Option<Span>,
    /// Optional REMOTE WITH CONNECTION clause span
    pub remote_connection_span: Option<Span>,
    /// Optional OPTIONS(...) clause span
    pub options_span: Option<Span>,
    /// Optional AS query_statement (the training query)
    pub query: Option<Box<AstStmt>>,
}

/// BigQuery ALTER MODEL statement.
///
/// ```sql
/// ALTER MODEL [IF EXISTS] model_name
///   SET OPTIONS (option_list)
/// ```
#[derive(Debug, Clone)]
pub struct AstBqAlterModel {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    /// Span covering 'ALTER MODEL [IF EXISTS]' keywords
    pub keyword_span: Span,
    /// Whether IF EXISTS was specified
    pub if_exists: bool,
    /// Span covering the model name
    pub model_name_span: Span,
    /// Span covering 'SET OPTIONS(...)' including parentheses
    pub set_options_span: Span,
}

/// BigQuery EXPORT MODEL statement.
///
/// ```sql
/// EXPORT MODEL model_name
///   OPTIONS(URI = string_value [, TRIAL_ID = int_value])
/// ```
#[derive(Debug, Clone)]
pub struct AstBqExportModel {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    /// Span covering 'EXPORT MODEL' keywords
    pub keyword_span: Span,
    /// Span covering the model name
    pub model_name_span: Span,
    /// Span covering 'OPTIONS(...)' clause including parentheses
    pub options_span: Span,
}

/// BigQuery DROP MODEL statement.
///
/// ```sql
/// DROP MODEL [IF EXISTS] model_name
/// ```
#[derive(Debug, Clone)]
pub struct AstBqDropModel {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    /// Span covering 'DROP MODEL [IF EXISTS]' keywords
    pub keyword_span: Span,
    /// Whether IF EXISTS was specified
    pub if_exists: bool,
    /// Span covering the model name
    pub model_name_span: Span,
}

// ============================================================================
// Databricks OPTIMIZE
// ============================================================================

/// Databricks OPTIMIZE statement.
///
/// `OPTIMIZE table_name [FULL] [WHERE predicate] [ZORDER BY (col1, ...)]`
///
/// Compacts small files into larger ones, optionally rewriting data
/// to colocate columns specified in ZORDER BY for faster query performance.
#[derive(Debug, Clone)]
pub struct AstOptimize {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    /// Link to CST node for token-level formatting
    pub syntax_id: Option<crate::syntax::SyntaxOptimizeStmtId>,
    /// Span of the OPTIMIZE keyword (an Identifier in the lexer)
    pub optimize_keyword_span: Span,
    /// Span of the table name (possibly qualified: catalog.schema.table)
    pub table_name_span: Span,
    /// Span of the FULL keyword, if present
    pub full_keyword_span: Option<Span>,
    /// The WHERE predicate expression, if present
    pub where_predicate: Option<Box<AstExpr>>,
    /// Span of the WHERE keyword, if present
    pub where_keyword_span: Option<Span>,
    /// Span of the ZORDER keyword, if present
    pub zorder_keyword_span: Option<Span>,
    /// Span of the BY keyword after ZORDER, if present
    pub zorder_by_keyword_span: Option<Span>,
    /// Spans of the individual column names in the ZORDER BY list
    pub zorder_columns: Vec<Span>,
    /// Span of the parenthesized ZORDER BY column list (including parens)
    pub zorder_columns_span: Option<Span>,
}

/// Databricks DESCRIBE HISTORY statement.
///
/// `DESCRIBE HISTORY table_name`
///
/// Returns provenance information (operation, user, timestamp, etc.)
/// for each write to a Delta table. Table history is retained for 30 days.
#[derive(Debug, Clone)]
pub struct AstDescribeHistory {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    /// Link to CST node for token-level formatting
    pub syntax_id: Option<crate::syntax::SyntaxDescribeHistoryStmtId>,
    /// Span of the DESCRIBE / DESC keyword
    pub describe_keyword_span: Span,
    /// Span of the HISTORY keyword (Identifier token)
    pub history_keyword_span: Span,
    /// Span of the table name (possibly qualified: catalog.schema.table)
    pub table_name_span: Span,
}

// ============================================================================
// Databricks RESTORE
// ============================================================================

/// Whether the time travel clause is TIMESTAMP AS OF or VERSION AS OF.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestoreTimeTravelKind {
    /// `TIMESTAMP AS OF <expr>`
    TimestampAsOf,
    /// `VERSION AS OF <integer>`
    VersionAsOf,
}

/// Time travel clause for RESTORE statement.
///
/// Covers both `TIMESTAMP AS OF <expr>` and `VERSION AS OF <int>`.
#[derive(Debug, Clone)]
pub struct AstRestoreTimeTravel {
    /// Discriminant: TIMESTAMP or VERSION
    pub kind: RestoreTimeTravelKind,
    /// Span of the TIMESTAMP or VERSION keyword (Identifier token)
    pub keyword_span: Span,
    /// Span of the AS keyword
    pub as_keyword_span: Span,
    /// Span of the OF keyword
    pub of_keyword_span: Span,
    /// The expression following OF (timestamp expression or version number)
    pub value: Box<AstExpr>,
    /// Full span: from TIMESTAMP/VERSION to end of expression
    pub span: Span,
}

/// Databricks RESTORE statement.
///
/// `RESTORE [TABLE] table_name [TO] {TIMESTAMP AS OF expr | VERSION AS OF int}`
///
/// Restores a Delta table to an earlier state. This is a data-modifying
/// operation that reverts the table to a previous version.
#[derive(Debug, Clone)]
pub struct AstRestore {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    /// Link to CST node for token-level formatting
    pub syntax_id: Option<crate::syntax::SyntaxRestoreStmtId>,
    /// Span of the RESTORE keyword (Identifier token)
    pub restore_keyword_span: Span,
    /// Span of the optional TABLE keyword (None if omitted)
    pub table_keyword_span: Option<Span>,
    /// Span of the table name (possibly qualified: catalog.schema.table)
    pub table_name_span: Span,
    /// Span of the optional TO keyword (None if omitted)
    pub to_keyword_span: Option<Span>,
    /// The time travel clause (TIMESTAMP AS OF or VERSION AS OF)
    pub time_travel: AstRestoreTimeTravel,
}

// ============================================================================
// T-SQL BACKUP DATABASE / BACKUP LOG
// ============================================================================

/// T-SQL `BACKUP { DATABASE | LOG } <name> TO { DISK | URL | TAPE } = '...'
/// [, ...] [WITH <options>]`.
///
/// Data-protection utility statement. Recognition captures what is backed
/// up (database vs transaction log), the destination device class, and
/// whether the backup is encrypted (`WITH ENCRYPTION`). The destination
/// literal itself is deliberately not surfaced — backup URLs commonly embed
/// SAS credentials.
#[derive(Debug, Clone)]
pub struct AstMssqlBackup {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    /// Span of the BACKUP keyword (Identifier token in our lexer).
    pub backup_keyword_span: Span,
    /// What is being backed up.
    pub target: AstMssqlBackupTarget,
    /// Span of the database / log name (possibly qualified).
    pub name_span: Span,
    /// Destination device class. Backup destinations within one statement
    /// are homogeneous by T-SQL rules, so a single kind is sound.
    pub destination: AstMssqlBackupDestination,
    /// Whether a `WITH ENCRYPTION` clause is present.
    pub encryption: bool,
}

/// What a [`AstMssqlBackup`] backs up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AstMssqlBackupTarget {
    /// `BACKUP DATABASE …` — full / differential database backup.
    Database,
    /// `BACKUP LOG …` — transaction-log backup.
    Log,
}

/// Destination device class of a [`AstMssqlBackup`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AstMssqlBackupDestination {
    /// `TO DISK = '...'` — local or network filesystem path.
    Disk,
    /// `TO URL = '...'` — Azure blob / offsite object store.
    Url,
    /// `TO TAPE = '...'` — tape device.
    Tape,
}

// ============================================================================
// T-SQL RESTORE DATABASE / RESTORE LOG
// ============================================================================

/// T-SQL `RESTORE { DATABASE | LOG } <name> FROM { DISK | URL | TAPE } = '...'
/// [, ...] [WITH <options>]`.
///
/// Data-protection counterpart of [`AstMssqlBackup`]. Recognition captures
/// what is restored (database vs log), the source device class, and whether
/// `WITH REPLACE` is present (overwrites an existing database). The source
/// literal is deliberately not surfaced — restore URLs commonly embed SAS
/// credentials.
#[derive(Debug, Clone)]
pub struct AstMssqlRestore {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    /// Span of the RESTORE keyword (Identifier token in our lexer).
    pub restore_keyword_span: Span,
    /// What is being restored.
    pub target: AstMssqlRestoreTarget,
    /// Span of the database / log name (possibly qualified).
    pub name_span: Span,
    /// Source device class. `None` for the recovery-only form
    /// (`RESTORE DATABASE … WITH RECOVERY`) which names no source device.
    /// Restore sources within one statement are otherwise homogeneous by
    /// T-SQL rules, so a single kind is sound.
    pub source: Option<AstMssqlRestoreSource>,
    /// Whether a `WITH REPLACE` option is present (force-overwrite an
    /// existing database).
    pub replace: bool,
}

/// What a [`AstMssqlRestore`] restores.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AstMssqlRestoreTarget {
    /// `RESTORE DATABASE …` — full / differential database restore.
    Database,
    /// `RESTORE LOG …` — transaction-log restore.
    Log,
}

/// Source device class of a [`AstMssqlRestore`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AstMssqlRestoreSource {
    /// `FROM DISK = '...'` — local or network filesystem path.
    Disk,
    /// `FROM URL = '...'` — Azure blob / offsite object store.
    Url,
    /// `FROM TAPE = '...'` — tape device.
    Tape,
}

// ============================================================================
// T-SQL DBCC (database console command — maintenance / admin utility)
// ============================================================================

/// T-SQL `DBCC <command> [ ( args ) ] [WITH options]`.
///
/// The DBCC family spans dozens of maintenance, integrity, performance and
/// undocumented commands (`CHECKDB`, `SHRINKDATABASE`, `TRACEON`,
/// `FREEPROCCACHE`, `WRITEPAGE`, …). The only governance-bearing element is the
/// command verb itself — which command is dangerous is the consumer's verdict
/// — so recognition captures the command name and nothing else. Arguments are
/// consumed but not surfaced (heterogeneous operands, no governance signal).
#[derive(Debug, Clone)]
pub struct AstMssqlDbcc {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    /// Span of the DBCC keyword (Identifier token in our lexer).
    pub dbcc_keyword_span: Span,
    /// Span of the command name (e.g. `CHECKDB`, `TRACEON`).
    pub command_span: Span,
}

// ============================================================================
// T-SQL encryption-key activation (OPEN / CLOSE { MASTER | SYMMETRIC } KEY)
// ============================================================================

/// T-SQL runtime encryption-key activation:
/// `OPEN MASTER KEY DECRYPTION BY PASSWORD = '…'`,
/// `OPEN SYMMETRIC KEY <name> DECRYPTION BY { CERTIFICATE | ASYMMETRIC KEY |
/// SYMMETRIC KEY | PASSWORD = '…' } …`,
/// `CLOSE { MASTER KEY | SYMMETRIC KEY <name> | ALL SYMMETRIC KEYS }`.
///
/// This is a session-scoped key-context switch (distinct from the
/// `{CREATE|ALTER|DROP}` key *object* DDL). The governance-bearing primitives
/// are the verb (open/close), the key kind, and whether an inline password
/// decrypts the key — which combination is dangerous is the consumer's
/// verdict. The password VALUE is recorded as a redaction span at parse time, never
/// surfaced.
#[derive(Debug, Clone)]
pub struct AstMssqlKeyManagement {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    pub action: KeyMgmtAction,
    pub key_kind: KeyMgmtKind,
    /// True when an inline `PASSWORD = '…'` decrypts/opens the key (a hardcoded
    /// credential in source). The literal value is redacted, not stored.
    pub password_present: bool,
}

/// The key-context verb.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyMgmtAction {
    /// `OPEN` — activate a key in the session.
    Open,
    /// `CLOSE` — deactivate a key.
    Close,
}

/// Which key the statement targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyMgmtKind {
    /// `MASTER KEY` — the database master key (DMK).
    Master,
    /// `SYMMETRIC KEY <name>`.
    Symmetric,
    /// `ALL SYMMETRIC KEYS` (CLOSE only).
    AllSymmetric,
}

// ============================================================================
// T-SQL Row-Level Security (CREATE / ALTER SECURITY POLICY)
// ============================================================================

/// T-SQL `CREATE`/`ALTER SECURITY POLICY name { ADD { FILTER | BLOCK }
/// PREDICATE fn(cols) ON table … }[, …] [WITH (STATE = { ON | OFF } …)]`.
///
/// A security policy is the row-level-security control: filter predicates hide
/// rows from reads, block predicates restrict writes. The governance-bearing
/// primitives are the verb, the policy `STATE` (OFF — or unset on `CREATE`,
/// which defaults to OFF — means the control enforces nothing), and whether
/// filter / block predicates are present. Which combination is dangerous is
/// the consumer's verdict. Predicate function / table operands are scanned past.
#[derive(Debug, Clone)]
pub struct AstMssqlSecurityPolicy {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    pub action: SecurityPolicyAction,
    pub state: PolicyState,
    /// A `FILTER PREDICATE` is bound (controls which rows reads can see).
    pub has_filter_predicate: bool,
    /// A `BLOCK PREDICATE` is bound (restricts which rows writes may touch).
    pub has_block_predicate: bool,
}

/// The security-policy verb.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityPolicyAction {
    /// `CREATE SECURITY POLICY`.
    Create,
    /// `ALTER SECURITY POLICY`.
    Alter,
}

/// The `WITH (STATE = …)` setting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyState {
    /// `STATE = ON` — the policy is active.
    On,
    /// `STATE = OFF` — the policy is inactive (enforces nothing).
    Off,
    /// No `STATE` clause. On `CREATE`, SQL Server defaults this to OFF.
    Unset,
}

// ============================================================================
// T-SQL encryption key-material protection (BACKUP / RESTORE key objects)
// ============================================================================

/// T-SQL `BACKUP`/`RESTORE { SERVICE MASTER KEY | MASTER KEY | CERTIFICATE name
/// | ASYMMETRIC KEY name } { TO | FROM } FILE = '…' [{ENCRYPTION | DECRYPTION}
/// BY PASSWORD = '…']`.
///
/// Moves root key material across the filesystem boundary. The governance-
/// bearing primitives are the verb (export vs import), which key object, and
/// whether an inline password protects/unlocks it. Which combination is
/// dangerous is the consumer's verdict. The password value is recorded as a redaction
/// span at parse time; the file path is not surfaced (it can embed a
/// credential).
#[derive(Debug, Clone)]
pub struct AstMssqlKeyBackup {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    pub action: KeyBackupAction,
    pub key_object: BackupKeyObject,
    /// An inline `{ENCRYPTION | DECRYPTION} BY PASSWORD = '…'` is present (a
    /// hardcoded credential). The literal value is redacted, not stored.
    pub password_present: bool,
}

/// The key-material verb.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyBackupAction {
    /// `BACKUP` — export key material to a file.
    Backup,
    /// `RESTORE` — import / re-key from a file.
    Restore,
}

/// Which key material the statement targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackupKeyObject {
    /// `SERVICE MASTER KEY` — the instance root key.
    ServiceMasterKey,
    /// `MASTER KEY` — the database master key.
    MasterKey,
    /// `CERTIFICATE name`.
    Certificate,
    /// `ASYMMETRIC KEY name`.
    AsymmetricKey,
}

// ============================================================================
// T-SQL CLR assembly (CREATE / ALTER ASSEMBLY)
// ============================================================================

/// T-SQL `CREATE`/`ALTER ASSEMBLY name … [WITH PERMISSION_SET = { SAFE |
/// EXTERNAL_ACCESS | UNSAFE }]`.
///
/// A CLR assembly registers .NET code that runs inside the SQL Server process.
/// The governance-bearing primitives are the verb, the permission set
/// (`UNSAFE` = full trust / arbitrary native code; `EXTERNAL_ACCESS` =
/// filesystem / network access), and whether the assembly is loaded from a
/// filesystem path. Which permission is dangerous is the consumer's verdict.
/// The `AUTHORIZATION` owner and binary / path operands are scanned past.
#[derive(Debug, Clone)]
pub struct AstMssqlAssembly {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    pub action: AssemblyAction,
    pub permission_set: AssemblyPermissionSet,
    /// The assembly is loaded from a `FROM '<path>'` filesystem source (as
    /// opposed to an inline `0x…` binary).
    pub from_file: bool,
}

/// The CLR-assembly verb.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssemblyAction {
    /// `CREATE ASSEMBLY`.
    Create,
    /// `ALTER ASSEMBLY`.
    Alter,
}

/// The `WITH PERMISSION_SET = …` trust level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssemblyPermissionSet {
    /// `SAFE` — computation only, no external resources.
    Safe,
    /// `EXTERNAL_ACCESS` — filesystem / network / registry / environment.
    ExternalAccess,
    /// `UNSAFE` — full trust; native calls, P/Invoke, arbitrary I/O.
    Unsafe,
    /// No `PERMISSION_SET` clause (SQL Server defaults to `SAFE`).
    Unset,
}

// ============================================================================
// T-SQL module signing (ADD [COUNTER] SIGNATURE)
// ============================================================================

/// T-SQL `ADD [COUNTER] SIGNATURE TO module BY { CERTIFICATE name | ASYMMETRIC
/// KEY name } [WITH PASSWORD = '…']`.
///
/// Signing a module delegates the signer's privileges to it: the signed module
/// executes with the permissions of a login/user derived from the certificate
/// or asymmetric key, regardless of caller. The governance-bearing primitives
/// are whether it is a counter-signature, the signer kind, and whether an
/// inline password unlocks the signer's private key. Which combination is
/// dangerous is the consumer's verdict. The module name and precomputed-signature
/// operand are scanned past; the password value is recorded as a redaction span.
#[derive(Debug, Clone)]
pub struct AstMssqlAddSignature {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    /// `ADD COUNTER SIGNATURE` (signs an existing signature) vs `ADD SIGNATURE`.
    pub counter: bool,
    pub signer_kind: SignerKind,
    /// An inline `WITH PASSWORD = '…'` unlocks the signer's private key (a
    /// hardcoded credential). The literal value is redacted, not stored.
    pub password_present: bool,
}

/// What signs the module.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignerKind {
    /// `BY CERTIFICATE name`.
    Certificate,
    /// `BY ASYMMETRIC KEY name`.
    AsymmetricKey,
}

// ============================================================================
// T-SQL legacy impersonation (SETUSER)
// ============================================================================

/// T-SQL `SETUSER ['username'] [WITH { NORESET | RESET }]`.
///
/// The deprecated, database-scoped equivalent of `EXECUTE AS USER`: switches
/// the security context to another user, or — with no principal — reverts to
/// the original dbo context. Recognition captures the impersonated principal's
/// span when present; downstream it reuses the shared `ImpersonationFacts`
/// carrier (principal kind is always `User`).
#[derive(Debug, Clone)]
pub struct AstMssqlSetuser {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    /// Span of the `'username'` literal. `None` is the revert form
    /// (`SETUSER` with no argument).
    pub principal_span: Option<Span>,
}

// ============================================================================
// T-SQL Service Master Key rotation (ALTER SERVICE MASTER KEY)
// ============================================================================

/// T-SQL `ALTER SERVICE MASTER KEY { [FORCE] REGENERATE | WITH { OLD_ACCOUNT |
/// NEW_ACCOUNT | OLD_PASSWORD | NEW_PASSWORD } = '…' … }`.
///
/// The Service Master Key is the root of the SQL Server encryption hierarchy.
/// The governance-bearing primitives are the operation (re-key vs service-
/// account credential change), whether the regenerate is forced (which discards
/// undecryptable material irreversibly), and whether an inline password is
/// present. Which combination is dangerous is the consumer's verdict. Account-name
/// operands are scanned past; the password value is recorded as a redaction
/// span.
#[derive(Debug, Clone)]
pub struct AstMssqlAlterServiceMasterKey {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    pub operation: ServiceMasterKeyOperation,
    /// `FORCE REGENERATE` — re-keys even when some material can no longer be
    /// decrypted, discarding it irreversibly.
    pub force: bool,
    /// An inline `{ OLD | NEW }_PASSWORD = '…'` is present (a hardcoded
    /// service-account credential). The literal value is redacted, not stored.
    pub password_present: bool,
}

/// What an `ALTER SERVICE MASTER KEY` does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceMasterKeyOperation {
    /// `[FORCE] REGENERATE` — re-key the encryption root.
    Regenerate,
    /// `WITH { OLD | NEW }_ACCOUNT / _PASSWORD = '…'` — rotate the protecting
    /// service-account credentials.
    AccountChange,
}

// ============================================================================
// PostgreSQL ALTER DEFAULT PRIVILEGES
// ============================================================================

/// `ALTER DEFAULT PRIVILEGES [ FOR { ROLE | USER } target [, …] ]
///   [ IN SCHEMA schema [, …] ]
///   { GRANT privs ON class TO grantee [, …] [ WITH GRANT OPTION ]
///   | REVOKE [ GRANT OPTION FOR ] privs ON class FROM grantee [, …] }`
///
/// Sets the privileges automatically applied to objects *created in the
/// future* by the target role(s) — a standing policy, not a one-time grant.
/// The governance-bearing primitives (action, object class, privileges,
/// grantees, scope) are typed here; the danger verdict (e.g. a default
/// grant to `PUBLIC`) is the consumer's.
#[derive(Debug, Clone)]
pub struct AstPgAlterDefaultPrivileges {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    pub action: DefaultPrivilegesAction,
    pub object_class: PgDefaultPrivObjectClass,
    /// `{ privileges | ALL [PRIVILEGES] }` — reuses the shared privilege list.
    pub privileges: AstPrivilegeList,
    /// `TO | FROM grantee [, …]` — reuses the shared grantee shape. A bare
    /// `PUBLIC` grantee surfaces as a `Role` named `PUBLIC`.
    pub grantees: Vec<AstGrantee>,
    /// `FOR { ROLE | USER } target [, …]` — whose future objects this affects.
    /// Empty when the clause is omitted (the current role).
    pub for_roles: Vec<Span>,
    /// `IN SCHEMA schema [, …]` — empty when omitted (applies to objects
    /// created in *all* schemas: the broad, global default).
    pub in_schemas: Vec<Span>,
    /// `WITH GRANT OPTION` — GRANT form only.
    pub with_grant_option: bool,
    /// `GRANT OPTION FOR` — REVOKE form only.
    pub grant_option_for: bool,
    /// Trailing `CASCADE | RESTRICT` — REVOKE form only. `None` for the
    /// GRANT form.
    pub cascade_mode: Option<AstCascadeMode>,
}

/// Whether an `ALTER DEFAULT PRIVILEGES` grants or revokes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DefaultPrivilegesAction {
    Grant,
    Revoke,
}

/// The object class an `ALTER DEFAULT PRIVILEGES` applies to. PostgreSQL
/// admits exactly this closed set; `ROUTINES` is a synonym for `FUNCTIONS`
/// kept distinct so recognition stays faithful to the source spelling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PgDefaultPrivObjectClass {
    Tables,
    Sequences,
    Functions,
    Routines,
    Types,
    Schemas,
}

// ============================================================================
// Databricks CACHE TABLE / UNCACHE TABLE
// ============================================================================

/// `CACHE [LAZY] TABLE table_name [OPTIONS ('storageLevel' [=] value)] [[AS] query]`
///
/// Caches the contents of a table or query result in Apache Spark's in-memory cache.
#[derive(Debug, Clone)]
pub struct AstCacheTable {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    /// Span of the CACHE keyword (Identifier token)
    pub cache_keyword_span: Span,
    /// Span of the optional LAZY keyword (None if omitted)
    pub lazy_keyword_span: Option<Span>,
    /// Span of the TABLE keyword
    pub table_keyword_span: Span,
    /// Span of the table name (possibly qualified)
    pub table_name_span: Span,
    /// Span of the OPTIONS clause including parens (None if omitted)
    pub options_span: Option<Span>,
    /// Span of the optional AS keyword before query (None if omitted or no query)
    pub as_keyword_span: Option<Span>,
    /// The cached query (if present — CACHE TABLE ... AS SELECT ...)
    pub query: Option<Box<AstStmt>>,
}

/// `UNCACHE TABLE [IF EXISTS] table_name`
///
/// Removes a table or view from the Apache Spark in-memory cache.
#[derive(Debug, Clone)]
pub struct AstUncacheTable {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    /// Span of the UNCACHE keyword (Identifier token)
    pub uncache_keyword_span: Span,
    /// Span of the TABLE keyword
    pub table_keyword_span: Span,
    /// Whether IF EXISTS was specified
    pub if_exists: bool,
    /// Span of the IF EXISTS clause (None if omitted)
    pub if_exists_span: Option<Span>,
    /// Span of the table name (possibly qualified)
    pub table_name_span: Span,
}

// ============================================================================
// Databricks [MSCK] REPAIR TABLE
// ============================================================================

/// Partition recovery mode for REPAIR TABLE.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepairPartitionsMode {
    /// `ADD PARTITIONS`
    Add,
    /// `DROP PARTITIONS`
    Drop,
    /// `SYNC PARTITIONS`
    Sync,
}

/// Databricks / SparkSQL REPAIR TABLE statement.
///
/// Spark SQL syntax:
///
/// ```sql
/// [MSCK] REPAIR TABLE table_identifier [{ADD|DROP|SYNC} PARTITIONS]
/// ```
///
/// Notes:
/// - `MSCK REPAIR TABLE` is a Hive-compatibility alias.
/// - If the `{ADD|DROP|SYNC} PARTITIONS` suffix is omitted, the default behavior is ADD
///   (but this AST only records the suffix when it is explicitly present in the source).
#[derive(Debug, Clone)]
pub struct AstRepairTable {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    /// Span of the optional MSCK keyword (Identifier token). None for `REPAIR TABLE ...`.
    pub msck_keyword_span: Option<Span>,
    /// Span of the REPAIR keyword (Identifier token)
    pub repair_keyword_span: Span,
    /// Span of the TABLE keyword
    pub table_keyword_span: Span,
    /// Span of the table identifier (possibly qualified: catalog.schema.table)
    pub table_name_span: Span,
    /// Optional partitions recovery mode (only when explicitly present)
    pub partitions_mode: Option<RepairPartitionsMode>,
    /// Span of the ADD/DROP/SYNC token (Identifier or Keyword depending on tokenization)
    pub partitions_mode_span: Option<Span>,
    /// Span of the PARTITIONS token (Identifier)
    pub partitions_keyword_span: Option<Span>,
}

// ============================================================================
// BigQuery EXTERNAL TABLE
// ============================================================================

/// CREATE [OR REPLACE] EXTERNAL TABLE [IF NOT EXISTS] table_name
///
/// Unified AST node covering both BigQuery and Snowflake CREATE EXTERNAL TABLE.
///
/// BigQuery syntax:
/// ```text
/// [(column_name column_schema, ...)]
/// [WITH CONNECTION {connection_name | DEFAULT}]
/// [WITH PARTITION COLUMNS [(partition_column_name partition_column_type, ...)]]
/// OPTIONS (external_table_option_list, ...);
/// ```
///
/// Snowflake syntax:
/// ```text
/// (col_name type AS (expr), ...)
/// [PARTITION BY (col, ...)]
/// [WITH] LOCATION = @stage/path/
/// [REFRESH_ON_CREATE = {TRUE|FALSE}]
/// [AUTO_REFRESH = {TRUE|FALSE}]
/// [PATTERN = 'regex']
/// FILE_FORMAT = (TYPE = ... | FORMAT_NAME = ...)
/// [...additional Snowflake-specific clauses]
/// ```
#[derive(Debug, Clone)]
pub struct AstCreateExternalTable {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    /// Optional `OR REPLACE` span.
    pub or_replace_span: Option<Span>,
    /// Span covering 'CREATE [OR REPLACE] EXTERNAL TABLE' keywords (includes optional IF NOT EXISTS)
    pub keyword_span: Span,
    /// Span covering the table name (possibly qualified: project.dataset.table)
    pub table_name_span: Span,
    /// Optional schema/column definitions span (parenthesized column definitions)
    pub schema_span: Option<Span>,

    // ── BigQuery-specific ──
    /// Optional WITH CONNECTION clause span (BigQuery)
    pub connection_span: Option<Span>,
    /// OPTIONS(...) clause span (BigQuery — required; absent for Snowflake)
    pub options_span: Option<Span>,

    // ── Shared ──
    /// PARTITION BY (Snowflake) or WITH PARTITION COLUMNS (BigQuery)
    pub partition_columns_span: Option<Span>,

    // ── Snowflake-specific ──
    /// USING TEMPLATE (subquery) — alternative to column definitions
    pub using_template_span: Option<Span>,
    /// `[WITH] LOCATION = @stage/path/` or `LOCATION = 'url'`
    pub location_span: Option<Span>,
    /// INTEGRATION = 'name'
    pub integration_span: Option<Span>,
    /// REFRESH_ON_CREATE = TRUE|FALSE
    pub refresh_on_create_span: Option<Span>,
    /// AUTO_REFRESH = TRUE|FALSE
    pub auto_refresh_span: Option<Span>,
    /// PATTERN = 'regex'
    pub pattern_span: Option<Span>,
    /// FILE_FORMAT = (TYPE = ... | FORMAT_NAME = ...)
    pub file_format_span: Option<Span>,
    /// PARTITION_TYPE = USER_SPECIFIED
    pub partition_type_span: Option<Span>,
    /// TABLE_FORMAT = DELTA
    pub table_format_span: Option<Span>,
    /// AWS_SNS_TOPIC = 'arn:...'
    pub aws_sns_topic_span: Option<Span>,
    /// COPY GRANTS
    pub copy_grants_span: Option<Span>,
    /// COMMENT = 'string'
    pub comment_span: Option<Span>,
    /// `[WITH] ROW ACCESS POLICY name ON (col)`
    pub row_access_policy_span: Option<Span>,
    /// `[WITH] TAG (name = 'value', ...)`
    pub tag_span: Option<Span>,

    // ── Redshift Spectrum-specific ──
    /// `STORED AS <format>` (`PARQUET | TEXTFILE | ORC | RCFILE | SEQUENCEFILE |
    /// INPUTFORMAT '..' OUTPUTFORMAT '..'`). Redshift omits the `=` Snowflake uses.
    pub stored_as_span: Option<Span>,
    /// ROW FORMAT { DELIMITED [FIELDS TERMINATED BY '..'] [LINES ...] | SERDE '..' }
    pub row_format_span: Option<Span>,
    /// `IAM_ROLE '<arn>'` — Redshift Spectrum credential reference. The arn is a
    /// role reference (not an inline secret); its literal span is routed through
    /// the bq_options literal harvest for credential/exposure governance.
    pub redshift_iam_role_span: Option<Span>,

    // ── T-SQL / PolyBase-specific ──
    /// Whole `WITH ( LOCATION=, DATA_SOURCE=, FILE_FORMAT=, REJECTED_ROW_LOCATION=, … )`
    /// options bag. Routed through the bq_options literal harvest so a hardcoded
    /// LOCATION / REJECTED_ROW_LOCATION value is visible as a literal instead of
    /// fragmenting off unparsed.
    pub tsql_with_options_span: Option<Span>,
    /// `DATA_SOURCE = <name>` value span — the external data source the table
    /// binds to (the PolyBase federated-access discriminator). Identifier value,
    /// so lifted explicitly rather than via the string-literal harvest.
    pub data_source_span: Option<Span>,
    /// T-SQL CETAS (`CREATE EXTERNAL TABLE … WITH (…) AS <query>`): the inner
    /// query whose results are written out to the external location — a data
    /// egress surface. `None` for every read-only external-table form (BQ /
    /// Snowflake / Redshift / plain PolyBase). On a parseable body, `Some(Ok)`
    /// with the full statement; on an
    /// unparseable body, `Some(Err(span))` so the external-table head is still
    /// recognized (mirrors `ctas_query`).
    pub as_query: Option<Result<Box<AstStmt>, Span>>,
}

/// CREATE EXTERNAL SCHEMA (Redshift Spectrum / federated query).
///
/// Syntax:
/// ```text
/// CREATE EXTERNAL SCHEMA [IF NOT EXISTS] <name>
///   FROM { DATA CATALOG | HIVE METASTORE | POSTGRES | MYSQL | KINESIS | REDSHIFT }
///   [DATABASE '<db>'] [SCHEMA '<schema>'] [URI '<host>'] [PORT <n>]
///   IAM_ROLE { default | '<arn>' [, '<arn>' ...] }
///   [CREATE EXTERNAL DATABASE [IF NOT EXISTS]]
/// ```
///
/// Registers an external data source (Glue Data Catalog, Hive Metastore, or a
/// federated database) that the cluster can query across its boundary. The
/// IAM_ROLE arn and the URI/DATABASE literals are captured as spans and routed
/// through the bq_options literal harvest so consumers see them as typed
/// literals without a new carrier.
#[derive(Debug, Clone)]
pub struct AstCreateExternalSchema {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    /// Span covering 'CREATE EXTERNAL SCHEMA' (includes optional IF NOT EXISTS)
    pub keyword_span: Span,
    pub if_not_exists_span: Option<Span>,
    /// Schema name span
    pub name_span: Span,
    /// Classification of the FROM data source
    pub source_kind: AstExternalSchemaSource,
    /// Span covering the FROM <source> words (e.g. 'DATA CATALOG')
    pub source_span: Span,
    /// `DATABASE '<db>'` — span of the literal value
    pub database_literal_span: Option<Span>,
    /// `URI '<host>'` — span of the literal value (HIVE METASTORE / federated)
    pub uri_span: Option<Span>,
    /// `PORT <n>` — span of the number literal
    pub port_span: Option<Span>,
    /// `IAM_ROLE '<arn>'` — span of the arn literal (role reference)
    pub iam_role_span: Option<Span>,
    /// Trailing CREATE EXTERNAL DATABASE [IF NOT EXISTS] clause span
    pub create_external_database_span: Option<Span>,
}

/// FROM data-source taxonomy for [`AstCreateExternalSchema`]. Closed enum;
/// matches over it must enumerate every variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AstExternalSchemaSource {
    /// FROM DATA CATALOG (AWS Glue)
    DataCatalog,
    /// FROM HIVE METASTORE
    HiveMetastore,
    /// FROM POSTGRES (federated)
    Postgres,
    /// FROM MYSQL (federated)
    Mysql,
    /// FROM KINESIS (streaming ingestion)
    Kinesis,
    /// FROM REDSHIFT (cross-database)
    Redshift,
    /// Recognized CREATE EXTERNAL SCHEMA, unclassified source word
    Other,
}

// ─────────────────────────────────────────────────────────────────────
// Databricks Unity Catalog DDL
// ─────────────────────────────────────────────────────────────────────

/// Databricks `CREATE [FOREIGN] CATALOG [IF NOT EXISTS] catalog_name [clauses...]`
///
/// Supports regular and foreign catalog creation with optional clauses:
/// - COMMENT 'string'
/// - MANAGED LOCATION 'path'
/// - USING SHARE provider.share
/// - USING CONNECTION connection_name
/// - DEFAULT COLLATION collation_name
/// - OPTIONS (key = value, ...)
#[derive(Debug, Clone)]
pub struct AstCreateCatalog {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    /// True when CREATE FOREIGN CATALOG
    pub is_foreign: bool,
    /// True when IF NOT EXISTS is specified
    pub if_not_exists: bool,
    /// Span of the catalog name identifier
    pub catalog_name_span: Span,
    /// Span of COMMENT 'string' clause (keyword + string literal)
    pub comment_span: Option<Span>,
    /// Span of MANAGED LOCATION 'path' clause
    pub managed_location_span: Option<Span>,
    /// Span of USING SHARE provider.share clause
    pub using_share_span: Option<Span>,
    /// Span of USING CONNECTION connection_name clause
    pub using_connection_span: Option<Span>,
    /// Span of DEFAULT COLLATION name clause
    pub default_collation_span: Option<Span>,
    /// Span of OPTIONS (...) clause
    pub options_span: Option<Span>,
}

/// The kind of ALTER CATALOG action.
#[derive(Debug, Clone)]
pub enum AlterCatalogActionKind {
    /// `[SET] OWNER TO principal`
    OwnerTo,
    /// SET TAGS ('tag' = 'val', ...)
    SetTags,
    /// UNSET TAGS ('tag', ...)
    UnsetTags,
    /// ENABLE PREDICTIVE OPTIMIZATION
    EnablePredictiveOptimization,
    /// DISABLE PREDICTIVE OPTIMIZATION
    DisablePredictiveOptimization,
    /// INHERIT PREDICTIVE OPTIMIZATION
    InheritPredictiveOptimization,
    /// DEFAULT COLLATION name
    DefaultCollation,
    /// OPTIONS (key value, ...)
    Options,
}

/// Databricks `ALTER CATALOG [catalog_name] { action }`
///
/// Note: catalog_name is optional — omitting it defaults to hive_metastore.
#[derive(Debug, Clone)]
pub struct AstAlterCatalog {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    /// Span of the catalog name (None when omitted — defaults to hive_metastore)
    pub catalog_name_span: Option<Span>,
    /// The action being performed
    pub action_kind: AlterCatalogActionKind,
    /// Span covering the full action clause (e.g., SET TAGS (...))
    pub action_span: Span,
}

/// Databricks `DROP CATALOG [IF EXISTS] catalog_name [RESTRICT | CASCADE]`
#[derive(Debug, Clone)]
pub struct AstDropCatalog {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    /// True when IF EXISTS is specified
    pub if_exists: bool,
    /// Span of the catalog name identifier
    pub catalog_name_span: Span,
    /// True when CASCADE is specified (drops all schemas/objects recursively)
    pub cascade: bool,
    /// True when RESTRICT is explicitly specified
    pub restrict: bool,
}

/// `CREATE [EXTERNAL] VOLUME [IF NOT EXISTS] volume_name [<clauses>]`
///
/// Covers two dialects that share the keyword shape:
///
/// - **Databricks** Unity Catalog: `LOCATION '<path>' [COMMENT '<text>']`
/// - **Snowflake**: `STORAGE_LOCATIONS = ((NAME = '…' STORAGE_BASE_URL = '…' …))
///   [ALLOW_WRITES = …] [COMMENT '<text>']`
///
/// Per the "permissive parser, dialect-driven lexer" principle the
/// parser doesn't gate on dialect; downstream consumers can disambiguate
/// by which optional span is present (`location_span` vs
/// `storage_locations_span`).
#[derive(Debug, Clone)]
pub struct AstCreateVolume {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    /// True when CREATE EXTERNAL VOLUME
    pub is_external: bool,
    /// True when IF NOT EXISTS is specified
    pub if_not_exists: bool,
    /// Optional `OR REPLACE` span (Snowflake).
    pub or_replace_span: Option<Span>,
    /// Span of the volume name (possibly qualified: catalog.schema.volume)
    pub volume_name_span: Span,
    /// Span of LOCATION 'path' clause (Databricks; keyword + string literal)
    pub location_span: Option<Span>,
    /// Span of COMMENT 'string' clause (keyword + string literal)
    pub comment_span: Option<Span>,
    /// Span of STORAGE_LOCATIONS = (...) clause (Snowflake; keyword
    /// through closing paren). `None` for Databricks volumes which use
    /// `location_span` instead.
    pub storage_locations_span: Option<Span>,
    /// Per-location cloud-storage config parsed out of the Snowflake
    /// `STORAGE_LOCATIONS` clause. Empty for Databricks volumes.
    pub storage_locations: Vec<AstStorageLocation>,
    /// Snowflake `ALLOW_WRITES = { TRUE | FALSE }`. `None` when the
    /// clause is absent.
    pub allow_writes: Option<bool>,
}

/// One entry of a Snowflake `STORAGE_LOCATIONS` list — a single external
/// cloud-storage backing location for an external volume. Each value
/// is a single literal token except `ENCRYPTION`, whose `TYPE` is pulled
/// out into `encryption_type_span`.
#[derive(Debug, Clone)]
pub struct AstStorageLocation {
    /// Span covering the location's parenthesized body `( … )`.
    pub full_span: Span,
    /// `NAME = '<location_name>'` value span.
    pub name_span: Option<Span>,
    /// `STORAGE_PROVIDER = '<S3|GCS|AZURE>'` value span.
    pub provider_span: Option<Span>,
    /// `STORAGE_BASE_URL = '<url>'` value span.
    pub base_url_span: Option<Span>,
    /// `STORAGE_AWS_ROLE_ARN = '<arn>'` value span — the cloud IAM role
    /// the volume assumes to access the bucket.
    pub role_arn_span: Option<Span>,
    /// `STORAGE_AWS_EXTERNAL_ID = '<id>'` value span.
    pub external_id_span: Option<Span>,
    /// `ENCRYPTION = (TYPE = '<type>' …)` — the `TYPE` value span.
    pub encryption_type_span: Option<Span>,
}

/// The kind of ALTER VOLUME action.
#[derive(Debug, Clone)]
pub enum AlterVolumeActionKind {
    /// RENAME TO new_name
    RenameTo,
    /// `[SET] OWNER TO principal`
    OwnerTo,
    /// SET TAGS ('tag' = 'val', ...)
    SetTags,
    /// UNSET TAGS ('tag', ...)
    UnsetTags,
}

/// Databricks `ALTER VOLUME volume_name { action }`
#[derive(Debug, Clone)]
pub struct AstAlterVolume {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    /// Span of the volume name (possibly qualified)
    pub volume_name_span: Span,
    /// The action being performed
    pub action_kind: AlterVolumeActionKind,
    /// Span covering the full action clause (e.g., RENAME TO new_name)
    pub action_span: Span,
}

/// Databricks `DROP VOLUME [IF EXISTS] volume_name`
#[derive(Debug, Clone)]
pub struct AstDropVolume {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    /// True when IF EXISTS is specified
    pub if_exists: bool,
    /// Span of the volume name identifier
    pub volume_name_span: Span,
}

/// Databricks `CREATE EXTERNAL LOCATION [IF NOT EXISTS] name URL '...' WITH (STORAGE CREDENTIAL cred) [COMMENT '...']`
#[derive(Debug, Clone)]
pub struct AstCreateExternalLocation {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    /// True when IF NOT EXISTS is specified
    pub if_not_exists: bool,
    /// Span of the location name identifier
    pub location_name_span: Span,
    /// Span of the URL keyword
    pub url_keyword_span: Span,
    /// Span of the URL string literal value
    pub url_value_span: Span,
    /// Span of the WITH keyword
    pub with_keyword_span: Span,
    /// Span of the full parenthesized credential clause: (STORAGE CREDENTIAL cred_name)
    pub storage_credential_clause_span: Span,
    /// Span of just the credential name identifier
    pub credential_name_span: Span,
    /// Span of the COMMENT keyword (if present)
    pub comment_keyword_span: Option<Span>,
    /// Span of the comment string literal value (if present)
    pub comment_value_span: Option<Span>,
}

// ─── ALTER EXTERNAL LOCATION (Databricks Unity Catalog) ────────────────────────

/// The action clause of an `ALTER EXTERNAL LOCATION` statement.
#[derive(Debug, Clone)]
pub enum AlterExternalLocationAction {
    /// `RENAME TO new_name`
    RenameTo {
        rename_span: Span,
        to_span: Span,
        new_name_span: Span,
    },
    /// `SET URL 'url' [FORCE]`
    SetUrl {
        set_span: Span,
        url_kw_span: Span,
        url_value_span: Span,
        force_span: Option<Span>,
    },
    /// `SET STORAGE CREDENTIAL credential_name`
    SetStorageCredential {
        set_span: Span,
        storage_span: Span,
        credential_kw_span: Span,
        credential_name_span: Span,
    },
    /// `[SET] OWNER TO principal`
    OwnerTo {
        set_span: Option<Span>,
        owner_span: Span,
        to_span: Span,
        owner_name_span: Span,
    },
}

#[derive(Debug, Clone)]
pub struct AstAlterExternalLocation {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    /// Span of ALTER keyword
    pub alter_span: Span,
    /// Span of EXTERNAL identifier
    pub external_span: Span,
    /// Span of LOCATION identifier
    pub location_kw_span: Span,
    /// Span of the location name being altered
    pub location_name_span: Span,
    /// The action being performed
    pub action: AlterExternalLocationAction,
}

// ─── DROP EXTERNAL LOCATION (Databricks Unity Catalog) ─────────────────────────

#[derive(Debug, Clone)]
pub struct AstDropExternalLocation {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    /// Span of DROP keyword
    pub drop_span: Span,
    /// Span of EXTERNAL identifier
    pub external_span: Span,
    /// Span of LOCATION identifier
    pub location_kw_span: Span,
    /// Span of IF EXISTS clause (if present)
    pub if_exists_span: Option<Span>,
    /// Span of the location name being dropped
    pub location_name_span: Span,
}

// ─── STORAGE CREDENTIAL (Databricks Unity Catalog) ─────────────────────────────

/// The kind qualifier for a credential: STORAGE, SERVICE, or bare CREDENTIAL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialKind {
    /// `CREATE STORAGE CREDENTIAL ...`
    Storage,
    /// `CREATE SERVICE CREDENTIAL ...`
    Service,
    /// `CREATE CREDENTIAL ...` (no qualifier)
    Bare,
}

/// `CREATE [STORAGE | SERVICE] CREDENTIAL [IF NOT EXISTS] name [provider] [COMMENT '...']`
#[derive(Debug, Clone)]
pub struct AstCreateStorageCredential {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    /// Whether this is STORAGE, SERVICE, or bare CREDENTIAL
    pub credential_kind: CredentialKind,
    /// True when IF NOT EXISTS is specified
    pub if_not_exists: bool,
    /// Span of the credential name identifier
    pub credential_name_span: Span,
    /// Typed provider clause (AWS_IAM_ROLE / AZURE_*  / DATABRICKS_GCP_* /
    /// CLOUDFLARE_API_TOKEN). `None` when the statement omits the
    /// provider clause entirely.
    pub provider: Option<AstStorageCredentialProvider>,
    /// Span of the COMMENT keyword (if present)
    pub comment_keyword_span: Option<Span>,
    /// Span of the comment string literal value (if present)
    pub comment_value_span: Option<Span>,
}

/// Provider clause for `CREATE/ALTER STORAGE CREDENTIAL`. Variants
/// follow the Databricks Unity Catalog SQL reference verbatim. Each
/// variant carries typed `Option<String>` fields for the literal
/// content of its specific arguments — a parameterized value yields
/// `None`, a string-literal value yields the unquoted text. The
/// `all_literal_values` sidecar carries the same content as a flat
/// Vec for content-pattern predicates that don't care which slot
/// holds the suspicious value (CRED-AWS-LEAK / CRED-CONNSTR-LEAK fire
/// on AKIA-prefix or `://user:pass@` patterns regardless of which
/// typed slot they appear in).
#[derive(Debug, Clone)]
pub struct AstStorageCredentialProvider {
    pub variant: AstStorageCredentialProviderVariant,
    /// All string-literal arguments of the provider in source order,
    /// with quotes stripped and `''` escapes folded.
    pub all_literal_values: Vec<String>,
}

#[derive(Debug, Clone)]
pub enum AstStorageCredentialProviderVariant {
    /// `AWS_IAM_ROLE 'role_arn'`
    AwsIamRole {
        keyword_span: Span,
        role_arn_span: Span,
        role_arn_text: Option<String>,
    },
    /// `AZURE_MANAGED_IDENTITY 'msi_id' [, ACCESS_CONNECTOR_ID 'connector_id']`
    AzureManagedIdentity {
        keyword_span: Span,
        managed_identity_id_span: Span,
        managed_identity_id_text: Option<String>,
        access_connector_id_span: Option<Span>,
        access_connector_id_text: Option<String>,
    },
    /// `AZURE_SERVICE_PRINCIPAL 'directory_id', 'application_id', 'client_secret'`
    AzureServicePrincipal {
        keyword_span: Span,
        directory_id_span: Span,
        directory_id_text: Option<String>,
        application_id_span: Span,
        application_id_text: Option<String>,
        client_secret_span: Span,
        client_secret_text: Option<String>,
    },
    /// `DATABRICKS_GCP_SERVICE_ACCOUNT` (no arguments)
    DatabricksGcpServiceAccount { keyword_span: Span },
    /// `CLOUDFLARE_API_TOKEN 'account_id', 'access_key_id', 'secret_access_key'`
    CloudflareApiToken {
        keyword_span: Span,
        account_id_span: Span,
        account_id_text: Option<String>,
        access_key_id_span: Span,
        access_key_id_text: Option<String>,
        secret_access_key_span: Span,
        secret_access_key_text: Option<String>,
    },
    /// Provider keyword recognized but body could not be lifted into a
    /// typed shape (e.g. parameterized arguments, future provider
    /// variants we don't recognize yet). Defensive zero-loss escape.
    Unparsed {
        keyword_span: Option<Span>,
        body_span: Option<Span>,
    },
}

// ─── ALTER STORAGE CREDENTIAL (Databricks Unity Catalog) ────────────────────────

/// The action clause of an `ALTER [STORAGE | SERVICE] CREDENTIAL` statement.
#[derive(Debug, Clone)]
pub enum AlterStorageCredentialAction {
    /// `RENAME TO new_name`
    RenameTo {
        rename_span: Span,
        to_span: Span,
        new_name_span: Span,
    },
    /// `[SET] OWNER TO principal`
    OwnerTo {
        set_span: Option<Span>,
        owner_span: Span,
        to_span: Span,
        owner_name_span: Span,
    },
    /// Replace the provider clause: `AWS_IAM_ROLE '...'`,
    /// `AZURE_SERVICE_PRINCIPAL '...', '...', '...'`, etc. Span ends
    /// where the provider's last argument ends.
    SetProvider {
        end_span: Span,
        provider: AstStorageCredentialProvider,
    },
}

/// `ALTER [STORAGE | SERVICE] CREDENTIAL name { RENAME TO new_name | [SET] OWNER TO principal }`
#[derive(Debug, Clone)]
pub struct AstAlterStorageCredential {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    /// Whether this is STORAGE, SERVICE, or bare CREDENTIAL
    pub credential_kind: CredentialKind,
    /// Span of the credential name being altered
    pub credential_name_span: Span,
    /// The action being performed
    pub action: AlterStorageCredentialAction,
}

// ─── DROP STORAGE CREDENTIAL (Databricks Unity Catalog) ─────────────────────────

/// `DROP [STORAGE | SERVICE] CREDENTIAL [IF EXISTS] name`
#[derive(Debug, Clone)]
pub struct AstDropStorageCredential {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    /// Whether this is STORAGE, SERVICE, or bare CREDENTIAL
    pub credential_kind: CredentialKind,
    /// True when IF EXISTS is specified
    pub if_exists: bool,
    /// Span of the credential name being dropped
    pub credential_name_span: Span,
}

// ─── CREATE CONNECTION (Databricks Unity Catalog) ───────────────────────────────

/// `CREATE CONNECTION [IF NOT EXISTS] name TYPE type OPTIONS (...) [COMMENT '...']`
///
/// For standards compliance, `SERVER` can be used instead of `CONNECTION`.
#[derive(Debug, Clone)]
pub struct AstCreateConnection {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    /// True when IF NOT EXISTS is specified
    pub if_not_exists: bool,
    /// Optional `OR REPLACE` span (Snowflake).
    pub or_replace_span: Option<Span>,
    /// Span of the connection name identifier
    pub connection_name_span: Span,
    /// Span covering TYPE and its value (e.g., `TYPE POSTGRESQL`)
    pub type_span: Option<Span>,
    /// Span covering OPTIONS (...) including parens and all key/value pairs
    pub options_span: Option<Span>,
    /// Span of the COMMENT keyword (if present)
    pub comment_keyword_span: Option<Span>,
    /// Span of the comment string literal value (if present)
    pub comment_value_span: Option<Span>,
    /// Span covering the source connection of `AS REPLICA OF
    /// <org>.<account>.<connection>` (Snowflake). `None` for a primary /
    /// non-replica connection.
    pub replica_of_span: Option<Span>,
}

// ─── ALTER CONNECTION (Databricks Unity Catalog + Snowflake) ─────────────────────

/// The action clause of an `ALTER CONNECTION` statement.
#[derive(Debug, Clone)]
pub enum AlterConnectionAction {
    /// `[SET] OWNER TO principal`
    OwnerTo {
        set_span: Option<Span>,
        owner_span: Span,
        to_span: Span,
        owner_name_span: Span,
    },
    /// `RENAME TO new_name`
    RenameTo {
        rename_span: Span,
        to_span: Span,
        new_name_span: Span,
    },
    /// `OPTIONS (...)`
    Options { options_span: Span },
    /// Snowflake `ENABLE FAILOVER TO ACCOUNTS <list>` — opens cross-account
    /// failover for this connection. `failover_span` covers the FAILOVER
    /// keyword; `accounts_span` covers the account list when present.
    EnableFailover {
        failover_span: Span,
        accounts_span: Option<Span>,
    },
    /// Snowflake `DISABLE FAILOVER [TO ACCOUNTS <list>]`.
    DisableFailover {
        failover_span: Span,
        accounts_span: Option<Span>,
    },
    /// Snowflake `PRIMARY` — promote this replica connection to primary.
    Primary { primary_span: Span },
}

/// `ALTER CONNECTION name { [SET] OWNER TO principal | RENAME TO new_name | OPTIONS (...) }`
#[derive(Debug, Clone)]
pub struct AstAlterConnection {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    /// Span of the connection name being altered
    pub connection_name_span: Span,
    /// The action being performed
    pub action: AlterConnectionAction,
}

// ─── DROP CONNECTION (Databricks Unity Catalog) ─────────────────────────────────

/// `DROP CONNECTION [IF EXISTS] name`
#[derive(Debug, Clone)]
pub struct AstDropConnection {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    /// True when IF EXISTS is specified
    pub if_exists: bool,
    /// Span of the connection name being dropped
    pub connection_name_span: Span,
}

// ============================================================================
// MSSQL EXEC / EXECUTE
// ============================================================================

/// T-SQL `EXECUTE AS { LOGIN | USER } = '<principal>' [WITH NO REVERT |
/// WITH COOKIE INTO @var]` — standalone impersonation statement (the
/// `EXECUTE AS` *clause* on procedures is typed separately on the
/// procedure substrate).
#[derive(Debug, Clone)]
pub struct AstMssqlExecuteAs {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    /// Span covering `EXEC[UTE] AS { LOGIN | USER }`.
    pub keyword_span: Span,
    /// Whether the impersonated principal is a server login or a
    /// database user.
    pub principal_kind: AstImpersonationPrincipalKind,
    /// Span of the principal value (string literal or variable).
    pub principal_span: Span,
    /// `WITH NO REVERT` clause present — the context switch cannot be
    /// undone for the rest of the session.
    pub no_revert: bool,
    /// Remaining WITH-clause body (`COOKIE INTO @var`, …), span-only.
    pub trailing_span: Option<Span>,
}

/// Which principal class an `EXECUTE AS` statement impersonates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AstImpersonationPrincipalKind {
    /// `EXECUTE AS LOGIN = …` — server-level context switch.
    Login,
    /// `EXECUTE AS USER = …` — database-level context switch.
    User,
}

/// T-SQL audit DDL: `{ CREATE | ALTER | DROP } { SERVER AUDIT
/// [SPECIFICATION] | DATABASE AUDIT SPECIFICATION } <name> …`.
#[derive(Debug, Clone)]
pub struct AstMssqlAuditDdl {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    /// Span covering the verb + audit-object keywords.
    pub keyword_span: Span,
    pub action: AstMssqlAuditAction,
    pub scope: AstMssqlAuditScope,
    pub name_span: Span,
    /// `STATE = { ON | OFF }` from the body (`WITH (STATE = ON)` or the
    /// bare ALTER form), when present.
    pub state: Option<AstMssqlAuditState>,
    /// Remaining body (TO FILE …, ADD (…), WHERE …), span-only.
    pub trailing_span: Option<Span>,
}

/// Verb of an audit DDL statement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AstMssqlAuditAction {
    Create,
    Alter,
    Drop,
}

/// Which audit object the statement targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AstMssqlAuditScope {
    /// `SERVER AUDIT <name>` — the audit destination object.
    ServerAudit,
    /// `SERVER AUDIT SPECIFICATION <name>` — which server-level events
    /// are captured.
    ServerAuditSpecification,
    /// `DATABASE AUDIT SPECIFICATION <name>` — which database-level
    /// events are captured.
    DatabaseAuditSpecification,
}

/// `STATE = { ON | OFF }` on an audit DDL statement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AstMssqlAuditState {
    On,
    Off,
}

/// T-SQL security-object DDL: `{ CREATE | ALTER | DROP } { MASTER KEY |
/// SYMMETRIC KEY | ASYMMETRIC KEY | CERTIFICATE | [DATABASE SCOPED]
/// CREDENTIAL } [<name>] …`.
#[derive(Debug, Clone)]
pub struct AstMssqlSecurityObjectDdl {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    /// Span covering the verb + object keywords.
    pub keyword_span: Span,
    pub action: AstMssqlAuditAction,
    pub object: AstMssqlSecurityObjectKind,
    /// Object name. `None` for `MASTER KEY` (the database has one).
    pub name_span: Option<Span>,
    /// `DATABASE SCOPED CREDENTIAL` (vs server-level `CREDENTIAL`).
    pub database_scoped: bool,
    /// Inner content of an `ENCRYPTION/DECRYPTION BY PASSWORD = '<lit>'`
    /// clause, when present.
    pub password_literal: Option<Span>,
    /// Inner content of a `SECRET = '<lit>'` clause, when present.
    pub secret_literal: Option<Span>,
    /// Remaining body, span-only.
    pub trailing_span: Option<Span>,
}

/// Which security object the statement targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AstMssqlSecurityObjectKind {
    /// `MASTER KEY` — the database master key.
    MasterKey,
    /// `SYMMETRIC KEY <name>`.
    SymmetricKey,
    /// `ASYMMETRIC KEY <name>`.
    AsymmetricKey,
    /// `CERTIFICATE <name>`.
    Certificate,
    /// `[DATABASE SCOPED] CREDENTIAL <name>` — identity + secret for an
    /// external resource.
    Credential,
}

/// MSSQL `EXEC[UTE]` statement — procedure invocation or dynamic SQL execution.
///
/// Three main forms:
///   1. Procedure call: `EXEC[UTE] [schema.]proc_name [@p1 = val1, ...]`
///   2. Return capture: `EXEC[UTE] @ret = [schema.]proc_name [args]`
///   3. Dynamic SQL:    `EXEC[UTE] (string_expression)`
#[derive(Debug, Clone)]
pub struct AstMssqlExec {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    /// Span covering the EXEC or EXECUTE keyword/identifier
    pub exec_keyword_span: Span,
    /// Optional return-value variable (e.g., `@ret` in `EXEC @ret = sp_name`)
    pub return_var_span: Option<Span>,
    /// Procedure name span (qualified: `schema.proc` or just `proc`).
    /// `None` for dynamic SQL form `EXEC ('...')`.
    pub procedure_name_span: Option<Span>,
    /// Span of the final name part only (`proc` in `db.schema.proc`).
    /// Recorded by the parser so consumers match the base procedure
    /// identity without re-splitting the qualified span (which would
    /// break on bracket-quoted parts containing dots).
    /// `None` for dynamic SQL form `EXEC ('...')`.
    pub procedure_base_name_span: Option<Span>,
    /// Span covering all arguments (everything after the proc name, up to `;` or end).
    /// For dynamic SQL form, covers the parenthesised expression `('...')`.
    pub args_span: Option<Span>,
    /// T-SQL `EXEC('…') AT <linked_server>` clause: the span of the
    /// linked-server name. `None` when no `AT` clause is present. The
    /// dynamic SQL runs on the remote linked server rather than locally.
    pub at_linked_server_span: Option<Span>,
    /// Typed argument list. Populated by `crate::parser::call_args`
    /// when the parser can recognize the shape; empty when the
    /// arguments are too dialect-specific to lift cleanly. Consumers
    /// read this typed slice rather than re-tokenizing `args_span`.
    pub args: Vec<AstCallArg>,
}

/// Typed call-site argument. Covers both positional (`@v`,
/// `'literal'`, `@a + @b`) and named-arg (`@p = @v`, `name => @v`)
/// shapes. The expression payload is whatever the parser captured, so a
/// consumer can classify call arguments and `EXECUTE IMMEDIATE` arguments
/// with the same logic.
#[derive(Debug, Clone)]
pub struct AstCallArg {
    pub node_id: crate::ast::NodeId,
    /// Span of the entire argument (name `=` value, or just value).
    pub span: Span,
    /// `Some` only for named-arg syntax (`@p = expr`, `name => expr`).
    /// The identifier span covers the name only; the `=` / `=>`
    /// operator span lives in [`Self::name_op_span`].
    pub name: Option<AstIdentifier>,
    /// Operator span between name and value (`=` or `=>`); paired
    /// with `name` being `Some`.
    pub name_op_span: Option<Span>,
    /// Argument expression.
    pub value: AstExpr,
}

/// MSSQL TRY...CATCH error handling block
///
/// Syntax:
/// ```sql
/// BEGIN TRY
///     { sql_statement | statement_block }
/// END TRY
/// BEGIN CATCH
///     [ { sql_statement | statement_block } ]
/// END CATCH [ ; ]
/// ```
#[derive(Debug, Clone)]
pub struct AstMssqlTryCatch {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    /// Span covering `BEGIN TRY`
    pub begin_try_span: Span,
    /// Statements inside the TRY block
    pub try_body: Vec<AstStmt>,
    /// Span covering `END TRY`
    pub end_try_span: Span,
    /// Span covering `BEGIN CATCH`
    pub begin_catch_span: Span,
    /// Statements inside the CATCH block
    pub catch_body: Vec<AstStmt>,
    /// Span covering `END CATCH`
    pub end_catch_span: Span,
    /// Optional semicolon after `END CATCH`
    pub semicolon_token: Option<crate::cst::TokenId>,
}

/// MSSQL IF...ELSE statement (T-SQL style)
///
/// Unlike Snowflake's `IF...THEN...END IF`, T-SQL uses:
/// ```sql
/// IF condition
///     single_statement | BEGIN...END
/// [ELSE
///     single_statement | BEGIN...END]
/// ```
/// No THEN keyword. No END IF. Each branch is exactly one statement
/// (which may be a BEGIN...END block for multiple statements).
#[derive(Debug, Clone)]
pub struct AstMssqlIf {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    /// Span covering the IF keyword
    pub if_span: Span,
    /// Span covering the condition expression
    pub condition_span: Span,
    /// Body of the IF branch (single statement, possibly a BEGIN...END block)
    pub then_body: Vec<AstStmt>,
    /// Span covering the ELSE keyword (if present)
    pub else_span: Option<Span>,
    /// Body of the ELSE branch (if present)
    pub else_body: Vec<AstStmt>,
}

/// MSSQL WHILE loop (T-SQL style)
///
/// Unlike Snowflake's `WHILE...DO...END WHILE`, T-SQL uses:
/// ```sql
/// WHILE condition
///     single_statement | BEGIN...END
/// ```
/// No DO keyword. No END WHILE. The body is exactly one statement
/// (usually a BEGIN...END block).
#[derive(Debug, Clone)]
pub struct AstMssqlWhile {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    /// Span covering the WHILE keyword
    pub while_span: Span,
    /// Span covering the condition expression
    pub condition_span: Span,
    /// Body of the WHILE loop (single statement, possibly a BEGIN...END block)
    pub body: Vec<AstStmt>,
}

/// MSSQL PRINT statement — outputs a message string.
///
/// ```sql
/// PRINT 'Hello World'
/// PRINT @variable
/// PRINT 'Count: ' + CAST(@n AS VARCHAR(10))
/// ```
#[derive(Debug, Clone)]
pub struct AstMssqlPrint {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    pub semicolon_token: Option<crate::cst::TokenId>,
}

/// MSSQL THROW statement — raises or re-throws an exception.
///
/// ```sql
/// -- Re-throw inside CATCH block (no arguments)
/// THROW;
///
/// -- Throw with error number, message, state
/// THROW 50000, 'Record not found.', 1;
/// THROW @ErrorNumber, @ErrorMessage, @ErrorState;
/// ```
#[derive(Debug, Clone)]
pub struct AstMssqlThrow {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    /// Span covering the arguments (number, message, state) if present.
    /// None for the parameterless re-throw form.
    pub args_span: Option<Span>,
    pub semicolon_token: Option<crate::cst::TokenId>,
}

/// MSSQL RAISERROR statement — generates an error message.
///
/// ```sql
/// RAISERROR('Error occurred', 16, 1);
/// RAISERROR('Error %s in %d', 16, 1, 'test', 42);
/// RAISERROR('Critical error', 20, 1) WITH LOG;
/// RAISERROR('Fatal error', 20, 1) WITH LOG, NOWAIT, SETERROR;
/// RAISERROR(50001, 16, 1);
/// RAISERROR(@ErrorMsg, 16, 1);
/// ```
#[derive(Debug, Clone)]
pub struct AstMssqlRaiserror {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    pub semicolon_token: Option<crate::cst::TokenId>,
}

/// MSSQL SET option ON/OFF statement — session-level configuration.
///
/// ```sql
/// SET NOCOUNT ON;
/// SET ANSI_NULLS OFF;
/// SET IDENTITY_INSERT dbo.MyTable ON;
/// SET XACT_ABORT ON;
/// ```
///
/// Unlike Snowflake `SET var = expr`, MSSQL SET options use ON/OFF syntax
/// without an equals sign. IDENTITY_INSERT has a table name between the
/// option name and ON/OFF.
#[derive(Debug, Clone)]
pub struct AstMssqlSetOption {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    /// Span covering the option name (e.g., "NOCOUNT", "ANSI_NULLS", "IDENTITY_INSERT")
    pub option_span: Span,
    /// Span covering ON or OFF
    pub value_span: Span,
    /// Typed classification of the option keyword. Parser dispatches
    /// on the option identifier and assigns the typed variant; all
    /// downstream layers consult this enum directly.
    pub option_kind: AstMssqlSetOptionKind,
    /// Typed classification of the value (ON / OFF / numeric / etc.).
    pub value: AstMssqlSetOptionValue,
    /// For `SET TRANSACTION ISOLATION LEVEL <level>`: the typed level.
    /// `None` for every other SET option.
    pub isolation_level: Option<AstMssqlIsolationLevel>,
    /// Semicolon token (captured for block formatting, not consumed)
    pub semicolon_token: Option<crate::cst::TokenId>,
}

/// T-SQL transaction isolation level in `SET TRANSACTION ISOLATION LEVEL <level>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AstMssqlIsolationLevel {
    ReadUncommitted,
    ReadCommitted,
    RepeatableRead,
    Snapshot,
    Serializable,
}

/// Closed enum classifying a T-SQL `SET <option>` keyword. The parser
/// dispatches on the option identifier and assigns the typed variant;
/// downstream consumers dispatch on this enum directly. Adding new options
/// is additive
/// (semver-minor).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AstMssqlSetOptionKind {
    /// `SET IDENTITY_INSERT <table> ON|OFF` — drives MSSQL-IDENTITY-INSERT-ON.
    IdentityInsert,
    /// `SET NOCOUNT ON|OFF`.
    NoCount,
    /// `SET XACT_ABORT ON|OFF`.
    XactAbort,
    /// `SET ANSI_NULLS ON|OFF`.
    AnsiNulls,
    /// `SET QUOTED_IDENTIFIER ON|OFF`.
    QuotedIdentifier,
    /// `SET ARITHABORT ON|OFF`.
    ArithAbort,
    /// `SET CONCAT_NULL_YIELDS_NULL ON|OFF`.
    ConcatNullYieldsNull,
    /// `SET LOCK_TIMEOUT <ms>`.
    LockTimeout,
    /// `SET DEADLOCK_PRIORITY <value>`.
    DeadlockPriority,
    /// `SET ROWCOUNT <n>`.
    RowCount,
    /// `SET TRANSACTION ISOLATION LEVEL <level>`.
    TransactionIsolationLevel,
    /// Any other documented `SET` option not enumerated above.
    Other,
}

/// Closed enum classifying the value supplied to a `SET` option. T-SQL
/// `SET` admits `ON` / `OFF` for boolean toggles, numeric literals for
/// thresholds (LOCK_TIMEOUT, ROWCOUNT), and identifier values for
/// enums (DEADLOCK_PRIORITY HIGH | LOW, TRANSACTION ISOLATION LEVEL
/// READ COMMITTED, …). `Unparsed` covers parser fallback when the
/// value token sequence didn't match any documented form.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AstMssqlSetOptionValue {
    /// `ON`.
    On,
    /// `OFF`.
    Off,
    /// Numeric literal (e.g., `LOCK_TIMEOUT 30000`).
    NumericLiteral,
    /// Identifier value (e.g., `DEADLOCK_PRIORITY HIGH`).
    Identifier,
    /// No / unrecognized value.
    Unparsed,
}

/// MySQL `SET` statement family. MySQL overloads `SET` across many
/// shapes — variable assignment plus several keyword-led session and
/// governance forms. This is the single typed home for all of them,
/// mirroring [`AstMssqlSetOption`] and the PostgreSQL `SET` node.
#[derive(Debug, Clone)]
pub struct AstMysqlSet {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    /// Span covering the `SET` keyword.
    pub set_span: Span,
    pub kind: AstMysqlSetKind,
    /// Semicolon token (captured for block formatting, not consumed).
    pub semicolon_token: Option<crate::cst::TokenId>,
}

/// The MySQL `SET` form. Variable assignment keeps fully parsed RHS
/// expressions (so concatenation-built dynamic SQL is visible as an
/// expression); the keyword-led forms carry typed structure.
#[derive(Debug, Clone)]
pub enum AstMysqlSetKind {
    /// `SET target = expr [, target = expr] ...` — user variables
    /// (`@v`), system variables (`@@[scope.]v`, `[GLOBAL|SESSION|LOCAL]
    /// v`); operator is `=` or `:=`.
    Assignments(Vec<AstMysqlSetAssignment>),
    /// `SET NAMES {charset [COLLATE collation] | DEFAULT}`.
    Names(Box<AstMysqlSetNames>),
    /// `SET {CHARACTER SET | CHARSET} {charset | DEFAULT}`.
    CharacterSet(Box<AstMysqlSetCharacterSet>),
    /// `SET PASSWORD [FOR user] = value`.
    Password(Box<AstMysqlSetPassword>),
    /// `SET ROLE {DEFAULT | NONE | ALL [EXCEPT roles] | roles}`.
    Role(Box<AstMysqlSetRole>),
    /// `SET DEFAULT ROLE {NONE | ALL | roles} TO users`.
    DefaultRole(Box<AstMysqlSetDefaultRole>),
    /// `SET [GLOBAL | SESSION] TRANSACTION <characteristics>`.
    Transaction(Box<AstMysqlSetTransaction>),
}

/// A single `target = value` assignment within a MySQL `SET`.
#[derive(Debug, Clone)]
pub struct AstMysqlSetAssignment {
    pub node_id: crate::ast::NodeId,
    pub target: AstMysqlSetTarget,
    /// Span covering `=` or `:=`.
    pub assign_op_span: Span,
    /// Right-hand side, fully parsed.
    pub value: Box<AstExpr>,
    pub span: Span,
}

/// The left-hand side of a MySQL `SET` assignment.
#[derive(Debug, Clone)]
pub enum AstMysqlSetTarget {
    /// User variable `@name`.
    UserVar { name_span: Span },
    /// System variable via `@@[scope.]name` (span covers the whole
    /// `@@...` token sequence including any `.subname`).
    SystemAtAt { name_span: Span },
    /// System variable with an optional `GLOBAL` / `SESSION` / `LOCAL`
    /// scope keyword.
    System {
        scope_span: Option<Span>,
        name_span: Span,
    },
}

/// `SET NAMES ...`.
#[derive(Debug, Clone)]
pub struct AstMysqlSetNames {
    pub names_span: Span,
    /// `SET NAMES DEFAULT`.
    pub default_span: Option<Span>,
    /// Charset name or quoted charset literal.
    pub charset_span: Option<Span>,
    /// `COLLATE collation` (covers keyword + collation name).
    pub collate_span: Option<Span>,
}

/// `SET CHARACTER SET ...` / `SET CHARSET ...`.
#[derive(Debug, Clone)]
pub struct AstMysqlSetCharacterSet {
    /// Covers `CHARACTER SET` or `CHARSET`.
    pub keyword_span: Span,
    pub default_span: Option<Span>,
    pub charset_span: Option<Span>,
}

/// `SET PASSWORD [FOR user] = value`. The value stays a parsed
/// expression so a plaintext string literal is distinguishable from a
/// hashing function call.
#[derive(Debug, Clone)]
pub struct AstMysqlSetPassword {
    pub password_span: Span,
    /// `FOR user` (covers the FOR keyword + user reference).
    pub for_user_span: Option<Span>,
    pub assign_op_span: Span,
    pub value: Box<AstExpr>,
}

/// `SET ROLE ...`.
#[derive(Debug, Clone)]
pub struct AstMysqlSetRole {
    pub role_span: Span,
    pub spec: AstMysqlRoleSpec,
}

/// The role specification of `SET ROLE`.
#[derive(Debug, Clone)]
pub enum AstMysqlRoleSpec {
    Default {
        span: Span,
    },
    None {
        span: Span,
    },
    /// `ALL [EXCEPT roles]`.
    All {
        span: Span,
        except_roles_span: Option<Span>,
    },
    /// Explicit role list (span covers the comma-separated names).
    Roles {
        span: Span,
    },
}

/// `SET DEFAULT ROLE {NONE | ALL | roles} TO users`.
#[derive(Debug, Clone)]
pub struct AstMysqlSetDefaultRole {
    pub default_span: Span,
    pub role_span: Span,
    /// `NONE` | `ALL` | role list.
    pub roles_span: Span,
    pub to_span: Span,
    /// User list the default roles apply to.
    pub users_span: Span,
}

/// `SET [GLOBAL | SESSION] TRANSACTION <characteristics>`.
#[derive(Debug, Clone)]
pub struct AstMysqlSetTransaction {
    pub scope_span: Option<Span>,
    pub transaction_span: Span,
    /// `ISOLATION LEVEL ...` / `READ {ONLY | WRITE}` characteristics list.
    pub characteristics_span: Span,
}

/// MSSQL WAITFOR statement — delays execution for a specified interval or until a
/// specific time.
///
/// ```sql
/// WAITFOR DELAY '00:00:05';
/// WAITFOR TIME '23:00:00';
/// ```
#[derive(Debug, Clone)]
pub struct AstMssqlWaitfor {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    /// Span covering the DELAY or TIME keyword.
    pub kind_span: Span,
    /// Span covering the time string literal.
    pub value_span: Span,
    pub semicolon_token: Option<crate::cst::TokenId>,
}

/// MSSQL GOTO statement — unconditional jump to a label.
///
/// ```sql
/// GOTO error_handler;
/// GOTO retry;
/// ```
#[derive(Debug, Clone)]
pub struct AstMssqlGoto {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    /// Span covering the target label name.
    pub label_span: Span,
    pub semicolon_token: Option<crate::cst::TokenId>,
}

/// MSSQL label declaration — target for GOTO.
///
/// ```sql
/// error_handler:
///     PRINT 'An error occurred';
/// retry:
///     SELECT 1;
/// ```
#[derive(Debug, Clone)]
pub struct AstMssqlLabel {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    /// Span covering the label name (without the colon).
    pub label_name_span: Span,
}

/// MSSQL CREATE [OR ALTER] TRIGGER statement.
///
/// Syntax:
/// ```sql
/// CREATE [OR ALTER] TRIGGER [schema.]name
///   ON { table | view | DATABASE | ALL SERVER }
///   { AFTER | INSTEAD OF | FOR } { INSERT [, UPDATE] [, DELETE] }
///   [NOT FOR REPLICATION]
///   AS
///   BEGIN ... END
/// ```
#[derive(Debug, Clone)]
pub struct AstCreateMssqlTrigger {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    /// Span of OR ALTER if present
    pub or_alter_span: Option<Span>,
    /// Span of the trigger name (possibly schema-qualified)
    pub name_span: Span,
    /// Span of the ON target (table/view/DATABASE/ALL SERVER)
    pub target_span: Span,
    /// Span of the timing clause (AFTER / INSTEAD OF / FOR)
    pub timing_span: Span,
    /// Span of the event list (INSERT, UPDATE, DELETE or DDL event names)
    pub events_span: Span,
    /// Body statements (inside BEGIN...END)
    pub body: Vec<AstStmt>,
}

/// MSSQL DROP TRIGGER statement.
///
/// Syntax:
/// ```sql
/// -- DML trigger:
/// DROP TRIGGER [ IF EXISTS ] [schema.]trigger_name [,...n] [;]
/// -- DDL trigger:
/// DROP TRIGGER [ IF EXISTS ] trigger_name [,...n] ON { DATABASE | ALL SERVER } [;]
/// ```
#[derive(Debug, Clone)]
pub struct AstDropMssqlTrigger {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    pub if_exists: bool,
    /// Spans of each trigger name (comma-separated list)
    pub trigger_names: Vec<Span>,
    /// ON DATABASE or ON ALL SERVER scope (None for DML triggers)
    pub scope_span: Option<Span>,
}

/// MSSQL BULK INSERT statement.
///
/// ```sql
/// BULK INSERT dbo.MyTable FROM 'C:\data\file.csv' WITH (FIELDTERMINATOR = ',', ROWTERMINATOR = '\n');
/// ```
#[derive(Debug, Clone)]
pub struct AstMssqlBulkInsert {
    pub node_id: crate::ast::NodeId,
    pub span: Span,
    /// Span of the target table name (possibly schema-qualified)
    pub table_span: Span,
    /// Span of the filepath string literal
    pub filepath_span: Span,
    /// Span of the WITH (options) clause, if present (includes WITH keyword and parens)
    pub options_span: Option<Span>,
    /// Semicolon token ID if present
    pub semicolon_token: Option<crate::cst::TokenId>,
}
