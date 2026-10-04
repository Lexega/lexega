// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Snowflake Scripting parser.
//!
//! This module handles parsing of Snowflake Scripting constructs:
//!
//! - **Blocks**: `BEGIN ... END` with optional `DECLARE` section
//! - **Control flow**: IF/ELSEIF/ELSE, CASE, LOOP, WHILE, REPEAT, FOR
//! - **Exception handling**: Exception sections with handlers
//! - **Variables**: DECLARE, LET, SET statements
//! - **Cursors**: DECLARE CURSOR, OPEN, FETCH, CLOSE
//! - **Flow control**: RETURN, BREAK, CONTINUE, labeled statements
//! - **Dynamic SQL**: EXECUTE IMMEDIATE
//!
//! ## Scripting vs SQL Mode
//!
//! The parser tracks context to distinguish:
//! - **SQL mode**: Standard SQL expressions and statements
//! - **Scripting mode**: Allows scripting variable references (`:var`)
//!
//! ## Block Structure
//!
//! A typical scripting block:
//! ```sql
//! DECLARE
//!     x INT := 0;
//! BEGIN
//!     IF x < 10 THEN
//!         RETURN 'Small';
//!     END IF;
//! EXCEPTION
//!     WHEN OTHER THEN
//!         RETURN 'Error';
//! END;
//! ```

use crate::ast::{
    AstBlockStmt, AstCaseStmt, AstEifLocationKind, AstExceptionHandler, AstExceptionSection,
    AstExecuteImmediateFrom, AstExecuteUsingArg, AstExpr, AstForEachStmt, AstForStmt,
    AstIdentifier, AstIfStmt, AstLiteral, AstLoopStmt, AstMssqlSetOptionKind,
    AstMssqlSetOptionValue, AstRepeatStmt, AstStmt, AstWhileStmt, CaseBranch, ExceptionHandlerType,
    ExecuteAsMode, IfBranch,
};
use crate::error::{ExpectInvariant, ParseError, ParseErrorKind, ParseResult, ParseResultExt};
use crate::lexer::{Keyword, Punctuation, Span, Token, TokenKind};
use crate::parser::core::Parser;
use crate::parser::set_operations::{
    try_parse_select_stmt_with_parser, try_parse_set_or_select_stmt,
};

/// Context for parsing scripting statements, determines what statements are allowed
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StmtContext {
    /// Top-level block body (allows DECLARE, nested blocks, all statements)
    Block,
    /// Inside a loop body (no DECLARE, allows BREAK/CONTINUE)
    Loop,
    /// Inside an exception handler (limited statement set)
    ExceptionHandler,
}

// ============================================================================
// Error Recovery Infrastructure (Option C)
// ============================================================================

// Debug: Thread-local recursion depth counter for scripting
std::thread_local! {
    static SCRIPTING_DEPTH: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static SCRIPTING_OVERFLOW: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

struct ScriptingDepthGuard;
impl Drop for ScriptingDepthGuard {
    fn drop(&mut self) {
        SCRIPTING_DEPTH.with(|d| d.set(d.get().saturating_sub(1)));
    }
}

/// Track recursion depth and return None if limit exceeded.
/// This prevents stack overflow from deeply nested or malformed input.
fn track_scripting_depth(name: &str) -> Option<ScriptingDepthGuard> {
    SCRIPTING_DEPTH.with(|d| {
        let new_depth = d.get() + 1;
        d.set(new_depth);
        if new_depth > 200 {
            // Set overflow flag for error reporting
            SCRIPTING_OVERFLOW.with(|o| o.set(true));
            eprintln!(
                "Warning: Scripting recursion depth exceeded 200 in {}",
                name
            );
            // Return guard anyway to ensure depth decrements, but caller should check overflow
            Some(ScriptingDepthGuard)
        } else {
            Some(ScriptingDepthGuard)
        }
    })
}

/// Tokens that indicate the end of a control flow body.
/// Used for error recovery to skip past invalid content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BodyTerminator {
    /// END keyword (ends blocks, IF, CASE, LOOP, etc.)
    End,
    /// ELSIF keyword (next branch in IF)
    Elsif,
    /// ELSE keyword (else branch)
    Else,
    /// WHEN keyword (next branch in CASE)
    When,
    /// UNTIL keyword (ends REPEAT loop condition)
    Until,
    /// EXCEPTION keyword (starts exception section)
    Exception,
}

impl BodyTerminator {
    /// Check if a token matches this terminator.
    fn matches(&self, tok: &Token) -> bool {
        match self {
            BodyTerminator::End => matches!(tok.kind, TokenKind::Keyword(Keyword::End)),
            BodyTerminator::Elsif => matches!(tok.kind, TokenKind::Keyword(Keyword::Elsif)),
            BodyTerminator::Else => matches!(tok.kind, TokenKind::Keyword(Keyword::Else)),
            BodyTerminator::When => matches!(tok.kind, TokenKind::Keyword(Keyword::When)),
            BodyTerminator::Until => matches!(tok.kind, TokenKind::Keyword(Keyword::Until)),
            BodyTerminator::Exception => matches!(tok.kind, TokenKind::Keyword(Keyword::Exception)),
        }
    }

    /// Check if a token matches any of the given terminators.
    fn matches_any(tok: &Token, terminators: &[BodyTerminator]) -> bool {
        terminators.iter().any(|t| t.matches(tok))
    }
}

/// Parse a sequence of statements in a body (IF body, WHILE body, etc.) with error recovery.
///
/// This is the core error-recovery function for scripting blocks. It:
/// 1. Tries to parse each statement normally
/// 2. On failure, creates an `AstStmt::Error` node covering the bad content
/// 3. Synchronizes to the next recognizable point (semicolon, terminator keyword)
/// 4. Continues parsing remaining statements
///
/// # Arguments
/// * `p` - Parser instance
/// * `context` - What kind of body we're in (affects allowed statements)  
/// * `begin_start` - Start position of the enclosing block (for span tracking)
/// * `terminators` - Keywords that end this body (e.g., ELSIF, ELSE, END for IF body)
///
/// # Returns
/// * `(Vec<AstStmt>, Vec<ParseError>)` - Parsed statements (may include Error nodes) and errors
pub(crate) fn parse_body_with_recovery(
    p: &mut Parser<'_>,
    context: StmtContext,
    begin_start: u32,
    terminators: &[BodyTerminator],
) -> (Vec<AstStmt>, Vec<ParseError>) {
    let _guard = track_scripting_depth("parse_body_with_recovery");

    let mut stmts = Vec::new();
    let mut errors = Vec::new();

    loop {
        p.skip_trivia();

        // Check for end of input
        let tok = match p.peek_non_trivia() {
            Some(t) => t,
            None => break,
        };

        // Check for body terminators
        if BodyTerminator::matches_any(tok, terminators) {
            break;
        }

        // Skip lone semicolons between statements
        if matches!(
            tok.kind,
            TokenKind::Punctuation(crate::lexer::Punctuation::Semi)
        ) {
            // Consume and skip semicolons between statements in block bodies
            p.advance();
            continue;
        }

        // Track position for error recovery
        let stmt_start_pos = tok.span.start;
        let stmt_start_idx = p.idx;

        // Try to parse a statement
        match try_parse_scripting_stmt(p, context, begin_start) {
            Ok(stmt) => {
                stmts.push(stmt);
            }
            Err(err) => {
                // Create error node and synchronize
                let (error_node, sync_error) =
                    create_error_and_sync(p, stmt_start_pos, stmt_start_idx, &err, terminators);
                stmts.push(error_node);
                errors.push(sync_error.unwrap_or(err));
            }
        }
    }

    (stmts, errors)
}

/// Create an error node for unparseable content and synchronize to next valid point.
///
/// Scans forward until signal:
/// - A semicolon (consume it, error ends there)
/// - A body terminator keyword (don't consume, error ends before it)
/// - Another statement-starting keyword (don't consume, error ends before it)
/// - End of input
fn create_error_and_sync(
    p: &mut Parser<'_>,
    start_pos: u32,
    start_idx: usize,
    original_error: &ParseError,
    terminators: &[BodyTerminator],
) -> (AstStmt, Option<ParseError>) {
    let mut end_pos = start_pos;
    let mut partial_tokens = Vec::new();
    let max_tokens = 10;

    // Ensure we advance at least one token to prevent infinite loops
    let mut advanced_any = false;

    // If parser didn't advance during failed parse, we're still at the error token
    if p.idx == start_idx {
        if let Some(tok) = p.peek_non_trivia() {
            if partial_tokens.len() < max_tokens {
                partial_tokens.push(format!("{:?}", tok.kind));
            }
            end_pos = tok.span.end;
            p.advance();
            advanced_any = true;
        }
    } else {
        // Parser advanced during failed parse - capture where it stopped
        advanced_any = true;
        // Get current position as preliminary end
        if let Some(tok) = p.peek_non_trivia() {
            end_pos = tok.span.start; // Error ends just before current token
        }
    }

    // Continue scanning until we find a sync point
    loop {
        p.skip_trivia();
        let tok = match p.peek_non_trivia() {
            Some(t) => t,
            None => break, // EOF
        };

        // Stop at body terminators
        if BodyTerminator::matches_any(tok, terminators) {
            break;
        }

        // Stop at semicolon — include it in the error node span so the formatter preserves it
        if matches!(
            tok.kind,
            TokenKind::Punctuation(crate::lexer::Punctuation::Semi)
        ) {
            // Include semicolon in error node span and consume it
            end_pos = tok.span.end;
            p.advance();
            break;
        }

        // Stop at statement-starting keywords (don't consume)
        if is_statement_starting_token(tok) && advanced_any {
            break;
        }

        // Record and skip this token
        if partial_tokens.len() < max_tokens {
            partial_tokens.push(format!("{:?}", tok.kind));
        }
        end_pos = tok.span.end;
        p.advance();
        advanced_any = true;
    }

    let error_node = AstStmt::Error {
        node_id: p.id_gen.next(),
        span: Span {
            start: start_pos,
            end: end_pos,
        },
        message: original_error.message(),
        partial_tokens,
    };

    (error_node, None)
}

/// Check if a token typically starts a new statement (for sync purposes).
fn is_statement_starting_token(tok: &Token) -> bool {
    match &tok.kind {
        TokenKind::Keyword(kw) => matches!(
            kw,
            // SQL DML
            Keyword::Select
                | Keyword::Insert
                | Keyword::Update
                | Keyword::Delete
                | Keyword::Merge
                | Keyword::With
            // DDL
                | Keyword::Create
                | Keyword::Drop
                | Keyword::Truncate
            // Scripting
                | Keyword::Declare
                | Keyword::Let
                | Keyword::If
                | Keyword::Case
                | Keyword::Loop
                | Keyword::While
                | Keyword::For
                | Keyword::Repeat
                | Keyword::Return
                | Keyword::Raise
                | Keyword::Break
                | Keyword::Continue
                | Keyword::Call
                | Keyword::Execute
                | Keyword::Open
                | Keyword::Fetch
                | Keyword::Close
            // Nested blocks
                | Keyword::Begin
        ),
        _ => false,
    }
}

pub(crate) fn expr_span_end(expr: &AstExpr) -> u32 {
    match expr {
        AstExpr::Literal {
            literal: AstLiteral::Number { span },
            ..
        }
        | AstExpr::Literal {
            literal: AstLiteral::String { span },
            ..
        }
        | AstExpr::Literal {
            literal: AstLiteral::StringWithJinja { span },
            ..
        }
        | AstExpr::Literal {
            literal: AstLiteral::Boolean { span },
            ..
        }
        | AstExpr::Literal {
            literal: AstLiteral::Null { span },
            ..
        } => span.end,
        AstExpr::Placeholder { span, .. } => span.end,
        AstExpr::JinjaPlaceholder { span, .. } => span.end,
        AstExpr::Ident {
            column_ref: col, ..
        } => col.name.span.end,
        AstExpr::BinaryOp { right, .. } => expr_span_end(right),
        AstExpr::LogicalChain { span, .. } => span.end,
        AstExpr::PositionRef { index_span, .. } => index_span.end,
        AstExpr::ExplSnowIdent { span, .. } => span.end,
        AstExpr::WindowFn { over_span, .. } => over_span.end,
        AstExpr::WindowExpr { span, .. } => span.end,
        AstExpr::FunctionCall { span, .. } => span.end,
        AstExpr::ScalarSubquery { span, .. } => span.end,
        AstExpr::SubqueryArg { span, .. } => span.end,
        AstExpr::Case { span, .. } => span.end,
        AstExpr::ExistsSubquery { span, .. } => span.end,
        AstExpr::InList { span, .. } => span.end,
        AstExpr::InListOpaque { span, .. } => span.end,
        AstExpr::InSubquery { span, .. } => span.end,
        AstExpr::QuantifiedSubquery { span, .. } => span.end,
        AstExpr::Spread { span, .. } => span.end,
        AstExpr::Array { span, .. } => span.end,
        AstExpr::Object { span, .. } => span.end,
        AstExpr::ScriptingVarRef { span, .. } => span.end,
        AstExpr::QualifiedStar { span, .. } => span.end,
        AstExpr::UnqualifiedStar { span, .. } => span.end,
        AstExpr::Prior { span, .. } => span.end,
        AstExpr::IsNull { span, .. } => span.end,
        AstExpr::IsDistinctFrom { span, .. } => span.end,
        AstExpr::Like { span, .. } => span.end,
        AstExpr::SimilarTo { span, .. } => span.end,
        AstExpr::Cast { span, .. } => span.end,
        AstExpr::TryCast { span, .. } => span.end,
        AstExpr::SafeCast { span, .. } => span.end,
        AstExpr::TypeCast { span, .. } => span.end,
        AstExpr::Extract { span, .. } => span.end,
        AstExpr::MatchAgainst { span, .. } => span.end,
        AstExpr::Position { span, .. } => span.end,
        AstExpr::Trim { span, .. } => span.end,
        AstExpr::Substring { span, .. } => span.end,
        AstExpr::Collate { span, .. } => span.end,
        AstExpr::Between { span, .. } => span.end,
        AstExpr::Parenthesized { span, .. } => span.end,
        AstExpr::RowConstructor { span, .. } => span.end,
        AstExpr::ArraySubscript { span, .. } => span.end,
        AstExpr::ObjectFieldColon { span, .. } => span.end,
        AstExpr::ObjectFieldBracket { span, .. } => span.end,
        AstExpr::ObjectFieldDot { span, .. } => span.end,
        AstExpr::MethodCall { span, .. } => span.end,
        AstExpr::QualifiedStarFromExpr { span, .. } => span.end,
        AstExpr::JinjaConditional { span, .. } => span.end,
        AstExpr::DbtRef { span, .. } => span.end,
        AstExpr::DbtSource { span, .. } => span.end,
        AstExpr::DbtVar { span, .. } => span.end,
        AstExpr::DbtConfig { span, .. } => span.end,
        AstExpr::DbtThis { span, .. } => span.end,
        AstExpr::AtTimeZone { span, .. } => span.end,
        AstExpr::TypedStringLiteral { span, .. } => span.end,
        AstExpr::TvfWithSchema { span, .. } => span.end,
        AstExpr::Error { span, .. } => span.end,
    }
}

pub(crate) fn expr_span_start(expr: &AstExpr) -> u32 {
    match expr {
        AstExpr::Literal {
            literal: AstLiteral::Number { span },
            ..
        }
        | AstExpr::Literal {
            literal: AstLiteral::String { span },
            ..
        }
        | AstExpr::Literal {
            literal: AstLiteral::StringWithJinja { span },
            ..
        }
        | AstExpr::Literal {
            literal: AstLiteral::Boolean { span },
            ..
        }
        | AstExpr::Literal {
            literal: AstLiteral::Null { span },
            ..
        } => span.start,
        AstExpr::Placeholder { span, .. } => span.start,
        AstExpr::JinjaPlaceholder { span, .. } => span.start,
        AstExpr::Ident {
            column_ref: col, ..
        } => match &col.qualifier {
            Some(q) => q.span.start,
            None => col.name.span.start,
        },
        AstExpr::BinaryOp { left, .. } => expr_span_start(left),
        AstExpr::LogicalChain { span, .. } => span.start,
        AstExpr::PositionRef {
            qualifier,
            dollar_span,
            ..
        } => qualifier
            .as_ref()
            .map(|q| q.span.start)
            .unwrap_or(dollar_span.start),
        AstExpr::ExplSnowIdent { span, .. } => span.start,
        AstExpr::WindowFn { func_name, .. } => func_name.span.start,
        AstExpr::WindowExpr { span, .. } => span.start,
        AstExpr::FunctionCall { span, .. } => span.start,
        AstExpr::ScalarSubquery { span, .. } => span.start,
        AstExpr::SubqueryArg { span, .. } => span.start,
        AstExpr::Case { span, .. } => span.start,
        AstExpr::ExistsSubquery { span, .. } => span.start,
        AstExpr::InList { span, .. } => span.start,
        AstExpr::InListOpaque { span, .. } => span.start,
        AstExpr::InSubquery { span, .. } => span.start,
        AstExpr::QuantifiedSubquery { span, .. } => span.start,
        AstExpr::Spread { span, .. } => span.start,
        AstExpr::Array { span, .. } => span.start,
        AstExpr::Object { span, .. } => span.start,
        AstExpr::ScriptingVarRef { span, .. } => span.start,
        AstExpr::QualifiedStar { span, .. } => span.start,
        AstExpr::UnqualifiedStar { span, .. } => span.start,
        AstExpr::Prior { span, .. } => span.start,
        AstExpr::IsNull { span, .. } => span.start,
        AstExpr::IsDistinctFrom { span, .. } => span.start,
        AstExpr::Like { span, .. } => span.start,
        AstExpr::SimilarTo { span, .. } => span.start,
        AstExpr::Cast { span, .. } => span.start,
        AstExpr::TryCast { span, .. } => span.start,
        AstExpr::SafeCast { span, .. } => span.start,
        AstExpr::TypeCast { span, .. } => span.start,
        AstExpr::Extract { span, .. } => span.start,
        AstExpr::MatchAgainst { span, .. } => span.start,
        AstExpr::Position { span, .. } => span.start,
        AstExpr::Trim { span, .. } => span.start,
        AstExpr::Substring { span, .. } => span.start,
        AstExpr::Collate { span, .. } => span.start,
        AstExpr::Between { span, .. } => span.start,
        AstExpr::Parenthesized { span, .. } => span.start,
        AstExpr::RowConstructor { span, .. } => span.start,
        AstExpr::ArraySubscript { span, .. } => span.start,
        AstExpr::ObjectFieldColon { span, .. } => span.start,
        AstExpr::ObjectFieldBracket { span, .. } => span.start,
        AstExpr::ObjectFieldDot { span, .. } => span.start,
        AstExpr::MethodCall { span, .. } => span.start,
        AstExpr::QualifiedStarFromExpr { span, .. } => span.start,
        AstExpr::JinjaConditional { span, .. } => span.start,
        AstExpr::DbtRef { span, .. } => span.start,
        AstExpr::DbtSource { span, .. } => span.start,
        AstExpr::DbtVar { span, .. } => span.start,
        AstExpr::DbtConfig { span, .. } => span.start,
        AstExpr::DbtThis { span, .. } => span.start,
        AstExpr::AtTimeZone { span, .. } => span.start,
        AstExpr::TypedStringLiteral { span, .. } => span.start,
        AstExpr::TvfWithSchema { span, .. } => span.start,
        AstExpr::Error { span, .. } => span.start,
    }
}

pub(crate) fn try_parse_expr_scripting(p: &mut Parser<'_>) -> ParseResult<AstExpr> {
    // CRITICAL: Enter scripting mode so bind variables (:var) are recognized
    let prev_mode = p.enter_mode(crate::parser::core::ParserMode::Scripting);
    let result = p.parse_expr_in_mode();
    p.restore_mode(prev_mode);
    result
}

/// Result-based scripting statement parser with detailed error messages
pub(crate) fn try_parse_scripting_stmt(
    p: &mut Parser<'_>,
    context: StmtContext,
    begin_start: u32,
) -> ParseResult<AstStmt> {
    // CRITICAL: Enter scripting mode so :var references in expressions are recognized
    let prev_mode = p.enter_mode(crate::parser::core::ParserMode::Scripting);

    p.skip_trivia();
    let tok = p.peek_non_trivia().ok_or_else(|| {
        ParseError::new(
            p.current_span(),
            ParseErrorKind::InvalidStatement {
                message: "Expected statement in scripting block".to_string(),
            },
        )
    })?;

    let result = match &tok.kind {
        // Branching statements - use Result-based parsers
        TokenKind::Keyword(Keyword::If) => match context {
            StmtContext::ExceptionHandler => Err(ParseError::new(
                tok.span,
                ParseErrorKind::InvalidStatement {
                    message: "IF statements are not allowed in exception handlers".to_string(),
                },
            )),
            _ => {
                // Dialect gate (justified): MSSQL IF has no THEN/END IF — structurally
                // incompatible with Snowflake/BigQuery IF...THEN...END IF grammar.
                if p.dialect.uses_block_scoped_control_flow() {
                    try_parse_mssql_if(p)
                } else {
                    try_parse_if_stmt_in_block(p, context, begin_start)
                }
            }
        },

        // CASE statements - use Result-based parser
        TokenKind::Keyword(Keyword::Case) => match context {
            StmtContext::ExceptionHandler => Err(ParseError::new(
                tok.span,
                ParseErrorKind::InvalidStatement {
                    message: "CASE statements are not allowed in exception handlers".to_string(),
                },
            )),
            _ => try_parse_case_stmt_in_block(p, context, begin_start),
        },

        // Loop statements - use Result-based parsers
        TokenKind::Keyword(Keyword::While) => match context {
            StmtContext::ExceptionHandler => Err(ParseError::new(
                tok.span,
                ParseErrorKind::InvalidStatement {
                    message: "WHILE loops are not allowed in exception handlers".to_string(),
                },
            )),
            _ => {
                // Dialect gate (justified): MSSQL WHILE has no DO/END WHILE — structurally
                // incompatible with Snowflake WHILE...DO...END WHILE grammar.
                if p.dialect.uses_block_scoped_control_flow() {
                    try_parse_mssql_while(p)
                } else {
                    try_parse_while_stmt_in_block(p, begin_start, None)
                }
            }
        },

        TokenKind::Keyword(Keyword::For) => match context {
            StmtContext::ExceptionHandler => Err(ParseError::new(
                tok.span,
                ParseErrorKind::InvalidStatement {
                    message: "FOR loops are not allowed in exception handlers".to_string(),
                },
            )),
            _ => try_parse_for_stmt_in_block(p, begin_start, None),
        },

        TokenKind::Keyword(Keyword::Repeat) => match context {
            StmtContext::ExceptionHandler => Err(ParseError::new(
                tok.span,
                ParseErrorKind::InvalidStatement {
                    message: "REPEAT loops are not allowed in exception handlers".to_string(),
                },
            )),
            _ => try_parse_repeat_stmt_in_block(p, begin_start, None),
        },

        TokenKind::Keyword(Keyword::Loop) => match context {
            StmtContext::ExceptionHandler => Err(ParseError::new(
                tok.span,
                ParseErrorKind::InvalidStatement {
                    message: "LOOP statements are not allowed in exception handlers".to_string(),
                },
            )),
            _ => try_parse_loop_stmt_in_block(p, begin_start, None),
        },

        // PostgreSQL PL/pgSQL `FOREACH var [SLICE n] IN ARRAY expr LOOP … END LOOP`.
        // FOREACH is a non-reserved identifier (it lexes as an unquoted identifier,
        // like LEAVE/ITERATE), so recognize it by lexeme at statement start and route
        // to its dedicated parser. A quoted `"foreach"` carries quote characters in
        // its lexeme and is therefore excluded.
        TokenKind::Identifier { .. } if tok.lexeme(p.source).eq_ignore_ascii_case("foreach") => {
            match context {
                StmtContext::ExceptionHandler => Err(ParseError::new(
                    tok.span,
                    ParseErrorKind::InvalidStatement {
                        message: "FOREACH loops are not allowed in exception handlers".to_string(),
                    },
                )),
                _ => try_parse_foreach_stmt_in_block(p, begin_start),
            }
        }

        // SQL statements with WITH clause handling
        TokenKind::Keyword(Keyword::With) => {
            // Use Result-based parser which validates WITH + UPDATE
            try_parse_set_or_select_stmt(p)
        }

        // SELECT statements
        TokenKind::Keyword(Keyword::Select) => {
            let mut select_stmt = try_parse_select_stmt_with_parser(p)?;

            // Capture semicolon if present
            let semicolon_token = if let Some(tok) = p.peek_non_trivia() {
                if matches!(
                    tok.kind,
                    TokenKind::Punctuation(crate::lexer::Punctuation::Semi)
                ) {
                    Some(p.current_token_id())
                } else {
                    None
                }
            } else {
                None
            };

            // Attach semicolon token to SELECT or SetSelect statement
            match &mut select_stmt {
                AstStmt::Select(ref mut select) => {
                    select.semicolon_token = semicolon_token;
                }
                AstStmt::SetSelect(ref mut set_select) => {
                    set_select.semicolon_token = semicolon_token;
                }
                _ => {}
            }

            // Advance past semicolon if we captured it (prevents loop from consuming it)
            if semicolon_token.is_some() {
                p.advance();
            }

            Ok(select_stmt)
        }

        // UPDATE and DELETE with Result-based versions
        TokenKind::Keyword(Keyword::Update) => {
            let mut stmt = crate::parser::sql_stmt::try_parse_update_stmt_with_parser(p)?;

            // Capture semicolon if present
            let semicolon_token = if let Some(tok) = p.peek_non_trivia() {
                if matches!(
                    tok.kind,
                    TokenKind::Punctuation(crate::lexer::Punctuation::Semi)
                ) {
                    Some(p.current_token_id())
                } else {
                    None
                }
            } else {
                None
            };

            if let AstStmt::Update(ref mut update) = stmt {
                update.semicolon_token = semicolon_token;
            }

            Ok(stmt)
        }
        TokenKind::Keyword(Keyword::Delete) => {
            let mut stmt = crate::parser::sql_stmt::try_parse_delete_stmt_with_parser(p)?;

            // Capture semicolon if present
            let semicolon_token = if let Some(tok) = p.peek_non_trivia() {
                if matches!(
                    tok.kind,
                    TokenKind::Punctuation(crate::lexer::Punctuation::Semi)
                ) {
                    Some(p.current_token_id())
                } else {
                    None
                }
            } else {
                None
            };

            if let AstStmt::Delete(ref mut delete) = stmt {
                delete.semicolon_token = semicolon_token;
            }

            Ok(stmt)
        }

        // INSERT statements
        TokenKind::Keyword(Keyword::Insert) => {
            let mut stmt = crate::parser::sql_stmt::try_parse_insert_stmt_with_parser(p)?;

            // Capture semicolon if present
            let semicolon_token = if let Some(tok) = p.peek_non_trivia() {
                if matches!(
                    tok.kind,
                    TokenKind::Punctuation(crate::lexer::Punctuation::Semi)
                ) {
                    Some(p.current_token_id())
                } else {
                    None
                }
            } else {
                None
            };

            if let AstStmt::Insert(ref mut insert) = stmt {
                insert.semicolon_token = semicolon_token;
            }

            Ok(stmt)
        }

        // MERGE statements
        TokenKind::Keyword(Keyword::Merge) => {
            let mut stmt = crate::parser::sql_stmt::try_parse_merge_stmt_with_parser(p)?;

            // Capture semicolon if present
            let semicolon_token = if let Some(tok) = p.peek_non_trivia() {
                if matches!(
                    tok.kind,
                    TokenKind::Punctuation(crate::lexer::Punctuation::Semi)
                ) {
                    Some(p.current_token_id())
                } else {
                    None
                }
            } else {
                None
            };

            if let AstStmt::Merge(ref mut merge) = stmt {
                merge.semicolon_token = semicolon_token;
            }

            Ok(stmt)
        }

        // CREATE/DROP and other DDL
        TokenKind::Keyword(Keyword::Create) | TokenKind::Keyword(Keyword::Drop) => {
            let mut stmt = p.parse_statement()?;

            // Capture semicolon if present (for CREATE TABLE, CREATE VIEW, etc.)
            let semicolon_token = if let Some(tok) = p.peek_non_trivia() {
                if matches!(
                    tok.kind,
                    TokenKind::Punctuation(crate::lexer::Punctuation::Semi)
                ) {
                    Some(p.current_token_id())
                } else {
                    None
                }
            } else {
                None
            };

            // Attach to CREATE TABLE or CREATE VIEW if applicable
            match &mut stmt {
                AstStmt::CreateTable(ref mut create) => {
                    create.semicolon_token = semicolon_token;
                }
                AstStmt::CreateView(ref mut create) => {
                    create.semicolon_token = semicolon_token;
                }
                _ => {}
            }

            Ok(stmt)
        }

        // COPY INTO statements
        TokenKind::Keyword(Keyword::Copy) => {
            // COPY INTO is a DDL/DML statement that should be handled by parse_stmt_core
            p.parse_statement()
        }

        // Other SQL statements that might appear in procedures
        TokenKind::Keyword(Keyword::Show)
        | TokenKind::Keyword(Keyword::Describe)
        | TokenKind::Keyword(Keyword::Truncate) => {
            // These are handled by parse_stmt_core
            p.parse_statement()
        }

        // Scripting-specific statements
        TokenKind::Keyword(Keyword::Declare) => {
            if context == StmtContext::Block {
                // Inside a block body, each DECLARE is a standalone statement.
                // Don't use try_parse_scripting_block here — it bundles consecutive
                // DECLAREs and drops them when it encounters a handler.
                try_parse_declare_stmt(p)
            } else {
                // Top-level: parse as DECLARE...BEGIN...END compound block
                try_parse_scripting_block(p)
            }
        }

        TokenKind::Keyword(Keyword::Let) => try_parse_let_stmt_in_block(p),

        TokenKind::Keyword(Keyword::Return) => try_parse_return_stmt_in_block(p),

        TokenKind::Keyword(Keyword::Raise) => try_parse_raise_stmt_in_block(p),

        TokenKind::Keyword(Keyword::Break)
        | TokenKind::Keyword(Keyword::Exit)
        | TokenKind::Keyword(Keyword::Continue) => match context {
            StmtContext::Loop => try_parse_loop_control_stmt_in_block(p),
            _ => Err(ParseError::new(
                tok.span,
                ParseErrorKind::InvalidStatement {
                    message: format!(
                        "{} statements are only allowed in loop context",
                        tok.lexeme(p.source).to_uppercase()
                    ),
                },
            )),
        },

        // NULL statement: a no-op placeholder often used in exception handlers
        TokenKind::Literal(crate::lexer::LiteralKind::Null) | TokenKind::Keyword(Keyword::Null) => {
            let null_token_id = p.current_token_id();
            let null_tok = p
                .advance()
                .expect_invariant("NULL keyword consumed after match");
            let mut end = null_tok.span.end;

            // Capture optional semicolon
            let semicolon_token = if let Some(semi_tok) = p.peek_non_trivia() {
                if matches!(
                    semi_tok.kind,
                    TokenKind::Punctuation(crate::lexer::Punctuation::Semi)
                ) {
                    let semi_id = p.current_token_id();
                    let semi = p
                        .advance()
                        .expect_invariant("semicolon after peek in NULL statement");
                    end = semi.span.end;
                    Some(semi_id)
                } else {
                    None
                }
            } else {
                None
            };

            Ok(AstStmt::Null {
                node_id: p.id_gen.next(),
                span: Span {
                    start: null_tok.span.start,
                    end,
                },
                null_span: null_tok.span,
                null_token: Some(null_token_id),
                semicolon_token,
            })
        }

        // Transaction control, TRY...CATCH, or nested BEGIN...END block
        TokenKind::Keyword(Keyword::Begin) => {
            // Check if BEGIN TRANSACTION, BEGIN WORK, or BEGIN TRY
            let saved_idx = p.idx;
            let _ = p.advance(); // BEGIN
            p.skip_trivia();

            let next_kind = p.peek_non_trivia().map(|t| t.kind.clone());

            p.idx = saved_idx; // Restore

            if matches!(
                next_kind,
                Some(TokenKind::Keyword(Keyword::Transaction) | TokenKind::Keyword(Keyword::Work))
            ) {
                try_parse_begin_transaction_stmt(p)
            } else if matches!(next_kind, Some(TokenKind::Keyword(Keyword::Try))) {
                try_parse_mssql_try_catch(p)
            } else {
                // Nested BEGIN...END blocks are valid in Snowflake
                try_parse_block_stmt(p)
            }
        }

        TokenKind::Keyword(Keyword::Start) => try_parse_start_transaction_stmt(p),

        TokenKind::Keyword(Keyword::Commit) => try_parse_commit_stmt(p),

        TokenKind::Keyword(Keyword::Rollback) => try_parse_rollback_stmt(p),

        // Cursor operations. `OPEN`/`CLOSE` also lead the T-SQL encryption-key
        // activation statements (`OPEN MASTER KEY …`, `CLOSE ALL SYMMETRIC
        // KEYS`, …); a structural lookahead disambiguates those from cursors.
        TokenKind::Keyword(Keyword::Open) => {
            if crate::parser::key_management::is_mssql_key_stmt_at(p.tokens, p.idx, p.source) {
                p.try_parse_mssql_key_stmt()
            } else {
                try_parse_open_cursor_stmt(p)
            }
        }

        TokenKind::Keyword(Keyword::Fetch) => try_parse_fetch_cursor_stmt(p),

        TokenKind::Keyword(Keyword::Close) => {
            if crate::parser::key_management::is_mssql_key_stmt_at(p.tokens, p.idx, p.source) {
                p.try_parse_mssql_key_stmt()
            } else {
                try_parse_close_cursor_stmt(p)
            }
        }

        // Async operations
        TokenKind::Keyword(Keyword::Await) => try_parse_await_stmt(p),

        TokenKind::Keyword(Keyword::Cancel) => try_parse_cancel_stmt(p),

        // EXECUTE IMMEDIATE (Snowflake / BQ / Databricks) — and T-SQL
        // `EXEC[UTE]` when the dialect is MSSQL. MSSQL has three forms:
        // `EXEC proc_name args`, `EXEC @ret = proc_name`, and the
        // dynamic-SQL `EXEC(@sql)` form. Routing through the MSSQL
        // parser ensures inside-proc-body EXEC sites are typed as
        // `AstStmt::MssqlExec` rather than falling through to the
        // Snowflake `EXECUTE IMMEDIATE` parser (which doesn't recognize
        // the T-SQL surface).
        TokenKind::Keyword(Keyword::Execute) => {
            if p.dialect.supports_exec_procedure_call() {
                p.try_parse_mssql_exec_stmt()
            } else {
                let mut stmt = try_parse_execute_immediate_stmt(p)?;

                // Capture semicolon if present
                let captured_semicolon = if let Some(tok) = p.peek_non_trivia() {
                    if matches!(
                        tok.kind,
                        TokenKind::Punctuation(crate::lexer::Punctuation::Semi)
                    ) {
                        Some(p.current_token_id())
                    } else {
                        None
                    }
                } else {
                    None
                };

                // Attach to EXECUTE IMMEDIATE
                if let AstStmt::ExecuteImmediate {
                    ref mut semicolon_token,
                    ..
                } = stmt
                {
                    *semicolon_token = captured_semicolon;
                }

                Ok(stmt)
            }
        }

        // CALL
        TokenKind::Keyword(Keyword::Call) => try_parse_call_stmt(p),
        // ODBC call escape: {call p(...)} / {? = call p(...)}
        TokenKind::Punctuation(crate::lexer::Punctuation::LCurly) if is_odbc_call_escape_at(p) => {
            try_parse_odbc_call_stmt(p)
        }
        // Additional transaction control statements

        // Label detection: identifier followed by colon followed by WHILE/FOR/REPEAT/LOOP/BEGIN
        // e.g., my_label: WHILE TRUE DO ... END WHILE my_label;
        TokenKind::Identifier { .. } if is_label_before_loop_at(p.tokens, p.idx, p.source) => {
            parse_label_and_dispatch(p, begin_start)
        }

        // Label detection for keyword-named labels (e.g., `outer: WHILE ...`)
        // Keywords like OUTER tokenize as Keyword(Outer), not Identifier.
        TokenKind::Keyword(..) if is_label_before_loop_at(p.tokens, p.idx, p.source) => {
            parse_label_and_dispatch(p, begin_start)
        }

        // Assignment statements (identifier := expr)
        // NOTE: In Snowflake Scripting, variable assignment uses "var := value" syntax,
        // NOT "SET var := value". The SET keyword is only for session variables and
        // transaction settings, not for scripting variable assignment.
        // BUT first check for LEAVE/ITERATE (BigQuery loop control - Identifiers, not Keywords)
        TokenKind::Identifier { .. }
            if tok.lexeme(p.source).eq_ignore_ascii_case("LEAVE")
                || tok.lexeme(p.source).eq_ignore_ascii_case("ITERATE") =>
        {
            let is_leave = tok.lexeme(p.source).eq_ignore_ascii_case("LEAVE");
            let ctrl_token_id = p.current_token_id();
            let ctrl_tok = p
                .advance()
                .expect_invariant("LEAVE/ITERATE consumed after match");
            let mut end = ctrl_tok.span.end;

            // Optional label identifier
            let mut label_token = None;
            if let Some(label_tok) = p.peek_non_trivia() {
                if p.can_be_identifier_token(label_tok)
                    && !matches!(label_tok.kind, TokenKind::Punctuation(Punctuation::Semi))
                {
                    label_token = Some(p.current_token_id());
                    let lbl = p.advance().expect_invariant("label after LEAVE/ITERATE");
                    end = lbl.span.end;
                }
            }

            let semicolon_token = if let Some(semi_tok) = p.peek_non_trivia() {
                if matches!(semi_tok.kind, TokenKind::Punctuation(Punctuation::Semi)) {
                    let semi_id = p.current_token_id();
                    let semi = p
                        .advance()
                        .expect_invariant("semicolon after LEAVE/ITERATE");
                    end = semi.span.end;
                    Some(semi_id)
                } else {
                    None
                }
            } else {
                None
            };

            let span = Span {
                start: ctrl_tok.span.start,
                end,
            };

            if is_leave {
                Ok(AstStmt::Break {
                    node_id: p.id_gen.next(),
                    span,
                    break_span: ctrl_tok.span,
                    break_token: Some(ctrl_token_id),
                    label_token,
                    semicolon_token,
                })
            } else {
                Ok(AstStmt::Continue {
                    node_id: p.id_gen.next(),
                    span,
                    continue_span: ctrl_tok.span,
                    continue_token: Some(ctrl_token_id),
                    label_token,
                    semicolon_token,
                })
            }
        }
        // MSSQL EXEC statement (Identifier, not Keyword). Same parser
        // entry as the top-level dispatch in `core.rs` — handles the
        // procedure-call form, the return-capture form, and the
        // dynamic-SQL `EXEC(@sql)` form.
        TokenKind::Identifier { .. }
            if tok.lexeme(p.source).eq_ignore_ascii_case("EXEC")
                && p.dialect.supports_exec_procedure_call() =>
        {
            p.try_parse_mssql_exec_stmt()
        }
        // PostgreSQL / MySQL `PREPARE name FROM <expr>` (MySQL) or
        // `PREPARE name [(types)] AS <stmt>` (PostgreSQL). Inside
        // scripting block bodies the identifier-prefixed dispatch in
        // `core.rs` is bypassed, so route directly to the shared
        // PREPARE parser when the lexeme matches.
        TokenKind::Identifier { .. } if tok.lexeme(p.source).eq_ignore_ascii_case("PREPARE") => {
            p.try_parse_pg_prepare_stmt()
        }
        // MSSQL PRINT statement (Identifier, not Keyword)
        TokenKind::Identifier { .. }
            if tok.lexeme(p.source).eq_ignore_ascii_case("PRINT")
                && p.dialect.supports_print_statement() =>
        {
            try_parse_mssql_print(p)
        }
        // MSSQL THROW statement (Identifier, not Keyword)
        TokenKind::Identifier { .. }
            if tok.lexeme(p.source).eq_ignore_ascii_case("THROW")
                && p.dialect.supports_throw_statement() =>
        {
            try_parse_mssql_throw(p)
        }
        // MSSQL RAISERROR statement (Identifier, not Keyword)
        TokenKind::Identifier { .. }
            if tok.lexeme(p.source).eq_ignore_ascii_case("RAISERROR")
                && p.dialect.supports_raiserror_statement() =>
        {
            try_parse_mssql_raiserror(p)
        }
        // MSSQL GOTO statement (Identifier, not Keyword)
        TokenKind::Identifier { .. }
            if tok.lexeme(p.source).eq_ignore_ascii_case("GOTO")
                && p.dialect.supports_goto_statement() =>
        {
            try_parse_mssql_goto(p)
        }
        // MSSQL WAITFOR statement (Identifier, not Keyword)
        TokenKind::Identifier { .. }
            if tok.lexeme(p.source).eq_ignore_ascii_case("WAITFOR")
                && p.dialect.supports_waitfor_statement() =>
        {
            try_parse_mssql_waitfor(p)
        }
        // MSSQL BULK INSERT statement (BULK is Identifier, not Keyword)
        TokenKind::Identifier { .. }
            if tok.lexeme(p.source).eq_ignore_ascii_case("BULK")
                && p.dialect.supports_bulk_insert_statement()
                && is_mssql_bulk_insert_at(p.tokens, p.idx) =>
        {
            try_parse_mssql_bulk_insert(p)
        }
        // MSSQL label declaration: identifier followed by colon at statement level
        // Must come before the generic Identifier fallback and after keyword-like identifiers
        TokenKind::Identifier { .. }
            if p.dialect.supports_statement_labels() && is_mssql_label_at(p.tokens, p.idx) =>
        {
            try_parse_mssql_label(p)
        }
        // SET: MSSQL SET option (NOCOUNT, LOCK_TIMEOUT, etc.) or variable assignment (SET @var = expr)
        TokenKind::Keyword(Keyword::Set) => {
            if p.dialect.supports_mysql_set_grammar() {
                p.try_parse_mysql_set_stmt()
            } else if p.dialect.set_distinguishes_options() {
                // Disambiguate: SET <unquoted_ident> ... (option) vs SET @var = expr (assignment)
                let saved_idx = p.idx;
                let _ = p.advance(); // skip SET
                p.skip_trivia();
                let is_set_option = if let Some(next) = p.peek_non_trivia() {
                    matches!(
                        next.kind,
                        TokenKind::Identifier {
                            kind: crate::lexer::IdentifierKind::Unquoted
                        }
                    )
                } else {
                    false
                };
                p.idx = saved_idx;
                if is_set_option {
                    try_parse_mssql_set_option(p)
                } else {
                    p.try_parse_set_variable_stmt()
                }
            } else if p.dialect.supports_session_config_set() {
                p.try_parse_pg_set_stmt()
            } else {
                p.try_parse_set_variable_stmt()
            }
        }
        // Databricks SIGNAL statement (Identifier, not Keyword)
        TokenKind::Identifier { .. } if tok.lexeme(p.source).eq_ignore_ascii_case("SIGNAL") => {
            try_parse_signal_stmt(p)
        }
        // Databricks RESIGNAL statement (Identifier, not Keyword)
        TokenKind::Identifier { .. } if tok.lexeme(p.source).eq_ignore_ascii_case("RESIGNAL") => {
            try_parse_resignal_stmt(p)
        }
        // Databricks GET DIAGNOSTICS statement (Identifier, not Keyword)
        TokenKind::Identifier { .. } if tok.lexeme(p.source).eq_ignore_ascii_case("GET") => {
            try_parse_get_diagnostics_stmt(p)
        }
        TokenKind::Identifier { .. } => {
            let first_tok = p
                .advance()
                .expect_invariant("identifier consumed after match")
                .clone();
            Ok(parse_shallow_assign_stmt(p, first_tok))
        }

        // Everything else: defer to the full top-level statement parser so
        // EVERY statement type the parser recognizes is also recognized inside
        // a block body — GRANT / REVOKE / DENY / COMMENT / USE / etc. The
        // scripting-specific constructs (IF / WHILE / DECLARE / cursor ops / …)
        // are handled by the explicit arms above, before this fallback. This
        // mirrors `parse_mssql_body_statement`'s `_ => parse_flow_statement`
        // and prevents a routine body from silently dropping privilege and
        // other statements as opaque.
        _ => p.parse_statement(),
    };

    // Restore parser mode before returning
    p.restore_mode(prev_mode);
    result
}

pub(crate) fn try_parse_return_stmt_in_block(p: &mut Parser<'_>) -> ParseResult<AstStmt> {
    let return_token_id = p.current_token_id();
    let ret_kw = p.advance().ok_or_else(|| {
        ParseError::new(
            p.current_span(),
            ParseErrorKind::InvalidStatement {
                message: "Expected RETURN keyword".to_string(),
            },
        )
    })?;

    if !matches!(ret_kw.kind, TokenKind::Keyword(Keyword::Return)) {
        return Err(ParseError::new(
            ret_kw.span,
            ParseErrorKind::InvalidStatement {
                message: format!(
                    "Expected RETURN keyword, found {}",
                    Parser::token_description(ret_kw, p.source)
                ),
            },
        ));
    }

    // Check if there's an expression following (Snowflake) or just semicolon (BigQuery)
    let expr = if let Some(next_tok) = p.peek_non_trivia() {
        // If next token is semicolon or block-ending keyword, no expression
        if matches!(
            next_tok.kind,
            TokenKind::Punctuation(crate::lexer::Punctuation::Semi)
                | TokenKind::Keyword(Keyword::End)
                | TokenKind::Keyword(Keyword::Else)
                | TokenKind::Keyword(Keyword::Elsif)
                | TokenKind::Keyword(Keyword::When)
                | TokenKind::Keyword(Keyword::Until)
                | TokenKind::Keyword(Keyword::Exception)
        ) {
            None
        } else {
            Some(Box::new(try_parse_expr_scripting(p)?))
        }
    } else {
        None
    };

    let end = if let Some(ref e) = expr {
        expr_span_end(e.as_ref())
    } else {
        ret_kw.span.end
    };
    let span = Span {
        start: ret_kw.span.start,
        end,
    };

    // Capture semicolon if present (don't consume - block loop will skip it)
    let semicolon_token = if let Some(tok) = p.peek_non_trivia() {
        if matches!(
            tok.kind,
            TokenKind::Punctuation(crate::lexer::Punctuation::Semi)
        ) {
            Some(p.current_token_id())
        } else {
            None
        }
    } else {
        None
    };

    Ok(AstStmt::Return {
        node_id: p.id_gen.next(),
        semicolon_token,
        span,
        return_span: ret_kw.span,
        return_token: Some(return_token_id),
        expr,
    })
}

pub(crate) fn try_parse_raise_stmt_in_block(p: &mut Parser<'_>) -> ParseResult<AstStmt> {
    let raise_token_id = p.current_token_id();
    let raise_kw = p.advance().ok_or_else(|| {
        ParseError::new(
            p.current_span(),
            ParseErrorKind::InvalidStatement {
                message: "Expected RAISE keyword".to_string(),
            },
        )
    })?;

    if !matches!(raise_kw.kind, TokenKind::Keyword(Keyword::Raise)) {
        return Err(ParseError::new(
            raise_kw.span,
            ParseErrorKind::InvalidStatement {
                message: format!(
                    "Expected RAISE keyword, found {}",
                    Parser::token_description(raise_kw, p.source)
                ),
            },
        ));
    }

    let mut end = raise_kw.span.end;
    let mut exception_name = None;
    let mut level_span = None;
    let mut message_span = None;
    let mut using_span = None;
    let mut message_expr = None;

    let pg_levels = p.dialect.raise_severity_levels();
    if pg_levels.is_empty() {
        // Snowflake (`RAISE exc_name`) / BigQuery (`RAISE USING MESSAGE = expr`).
        if let Some(tok) = p.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::Using)) {
                let using_tok = p.advance().expect_invariant("USING consumed after peek");
                let using_start = using_tok.span.start;

                // Expect MESSAGE keyword (or identifier MESSAGE)
                if let Some(msg_tok) = p.peek_non_trivia() {
                    if msg_tok.lexeme(p.source).eq_ignore_ascii_case("MESSAGE") {
                        p.advance(); // consume MESSAGE

                        // Expect =
                        if let Some(eq_tok) = p.peek_non_trivia() {
                            if matches!(
                                eq_tok.kind,
                                TokenKind::Operator(crate::lexer::Operator::Eq)
                            ) {
                                p.advance(); // consume =

                                // Parse the message expression
                                let expr = try_parse_expr_scripting(p)?;
                                let expr_end = expr_span_end(&expr);

                                using_span = Some(Span {
                                    start: using_start,
                                    end: expr_end,
                                });
                                message_expr = Some(Box::new(expr));
                                end = expr_end;
                            }
                        }
                    }
                }
            } else if let TokenKind::Identifier { .. } = &tok.kind {
                // Snowflake style: RAISE exception_name
                let name_tok = p
                    .advance()
                    .expect_invariant("exception name identifier consumed after peek");
                exception_name = Some(name_tok.span);
                end = name_tok.span.end;
            }
        }
    } else {
        // PostgreSQL-family: RAISE [ level ] [ 'format' [, arg …]
        //   | condition_name | SQLSTATE 'x' ] [ USING option = expr [, …] ].
        // Optional severity level, recognized via the dialect.
        if let Some(tok) = p.peek_non_trivia() {
            let lx = tok.lexeme(p.source);
            if pg_levels.iter().any(|l| l.eq_ignore_ascii_case(lx)) {
                let lvl = p.advance().expect_invariant("RAISE level after peek");
                level_span = Some(lvl.span);
                end = lvl.span.end;
            }
        }
        // Message / condition payload, up to USING or the terminator.
        if let Some(span) = consume_raise_payload(p, true) {
            message_span = Some(span);
            end = span.end;
        }
        // Optional USING option = expr [, …].
        if let Some(tok) = p.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::Using)) {
                let using_start = tok.span.start;
                if let Some(span) = consume_raise_payload(p, false) {
                    using_span = Some(Span {
                        start: using_start,
                        end: span.end,
                    });
                    end = span.end;
                }
            }
        }
    }

    // Capture semicolon if present (don't consume - block loop will skip it)
    let semicolon_token = if let Some(tok) = p.peek_non_trivia() {
        if matches!(
            tok.kind,
            TokenKind::Punctuation(crate::lexer::Punctuation::Semi)
        ) {
            Some(p.current_token_id())
        } else {
            None
        }
    } else {
        None
    };

    let span = Span {
        start: raise_kw.span.start,
        end,
    };
    Ok(AstStmt::Raise {
        node_id: p.id_gen.next(),
        span,
        semicolon_token,
        raise_span: raise_kw.span,
        raise_token: Some(raise_token_id),
        exception_name,
        level_span,
        message_span,
        using_span,
        message_expr,
    })
}

/// Consume a PostgreSQL `RAISE` payload run — the `'format' [, arg …]`
/// message, a `condition_name` / `SQLSTATE 'x'`, or the `USING` option
/// list — capturing it verbatim as a span for byte-exact formatting.
/// Scans to the statement terminator (`;`), a block-ending keyword, or —
/// when `stop_at_using` — a top-level `USING` keyword, tracking
/// parenthesis depth so a comma or `;` inside argument parentheses does
/// not end the run early. Returns `None` when no payload token precedes
/// the stop. Never consumes the terminating `;` (the block loop owns it).
fn consume_raise_payload(p: &mut Parser<'_>, stop_at_using: bool) -> Option<Span> {
    use crate::lexer::Punctuation;
    let mut depth: i32 = 0;
    let mut start: Option<u32> = None;
    let mut end: u32 = 0;
    while let Some(tok) = p.peek_non_trivia() {
        if matches!(tok.kind, TokenKind::Eof) {
            break;
        }
        // Statement / block boundaries end the run, but only at the top
        // paren level so a comma or `;` inside argument parentheses does
        // not truncate it early.
        if depth == 0 {
            if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Semi)) {
                break;
            }
            if stop_at_using && matches!(tok.kind, TokenKind::Keyword(Keyword::Using)) {
                break;
            }
            if matches!(
                tok.kind,
                TokenKind::Keyword(Keyword::End)
                    | TokenKind::Keyword(Keyword::Else)
                    | TokenKind::Keyword(Keyword::Elsif)
                    | TokenKind::Keyword(Keyword::When)
                    | TokenKind::Keyword(Keyword::Until)
                    | TokenKind::Keyword(Keyword::Exception)
            ) {
                break;
            }
        }
        if matches!(tok.kind, TokenKind::Punctuation(Punctuation::LParen)) {
            depth += 1;
        } else if depth > 0 && matches!(tok.kind, TokenKind::Punctuation(Punctuation::RParen)) {
            depth -= 1;
        }
        let t = p
            .advance()
            .expect_invariant("RAISE payload token after peek");
        if start.is_none() {
            start = Some(t.span.start);
        }
        end = t.span.end;
    }
    start.map(|s| Span { start: s, end })
}

pub(crate) fn try_parse_let_stmt_in_block(p: &mut Parser<'_>) -> ParseResult<AstStmt> {
    let let_token_id = p.current_token_id();
    let let_kw = p.advance().ok_or_else(|| {
        ParseError::new(
            p.current_span(),
            ParseErrorKind::InvalidStatement {
                message: "Expected LET keyword".to_string(),
            },
        )
    })?;
    let name_tok = p.advance().ok_or_else(|| {
        ParseError::new(
            p.current_span(),
            ParseErrorKind::InvalidStatement {
                message: "Expected identifier after LET".to_string(),
            },
        )
    })?;
    // Allow both identifiers and keywords as variable names (keywords can be identifiers in this context)
    let name = match &name_tok.kind {
        _ if p.can_be_identifier_token(name_tok) => AstIdentifier {
            node_id: p.id_gen.next(),
            span: name_tok.span,
        },
        _ => {
            return Err(ParseError::new(
                name_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: format!(
                        "Expected identifier or keyword for LET name, found {}",
                        Parser::token_description(name_tok, p.source)
                    ),
                },
            ));
        }
    };

    // Optional type specification: LET name TYPE := ...
    // Track the type span if present
    let mut type_span: Option<Span> = None;

    if let Some(maybe_type_tok) = p.peek_non_trivia() {
        // Check if this looks like a type (not CURSOR, not :=, not =, not ;)
        let is_type = match &maybe_type_tok.kind {
            TokenKind::Keyword(kw) => !matches!(kw, Keyword::Cursor | Keyword::Default),
            TokenKind::Identifier { .. } => true,
            TokenKind::Operator(crate::lexer::Operator::ColonEq)
            | TokenKind::Operator(crate::lexer::Operator::Eq) => false,
            TokenKind::Punctuation(crate::lexer::Punctuation::Semi) => false,
            _ => false,
        };

        if is_type {
            let type_start = maybe_type_tok.span.start;
            let mut type_end = maybe_type_tok.span.end;
            let _ = p.advance(); // consume first type token

            // Continue consuming tokens that look like part of a type specification
            // This handles types like VARCHAR(100), NUMBER(10,2), TABLE(...), etc.
            while let Some(tok) = p.peek_non_trivia() {
                match &tok.kind {
                    TokenKind::Punctuation(crate::lexer::Punctuation::LParen) => {
                        // Consume everything up to matching RParen
                        let _ = p.advance();
                        type_end = tok.span.end;
                        let mut paren_depth = 1;
                        while paren_depth > 0 {
                            if let Some(inner_tok) = p.advance() {
                                type_end = inner_tok.span.end;
                                match inner_tok.kind {
                                    TokenKind::Punctuation(crate::lexer::Punctuation::LParen) => {
                                        paren_depth += 1
                                    }
                                    TokenKind::Punctuation(crate::lexer::Punctuation::RParen) => {
                                        paren_depth -= 1
                                    }
                                    _ => {}
                                }
                            } else {
                                break;
                            }
                        }
                    }
                    TokenKind::Operator(crate::lexer::Operator::ColonEq)
                    | TokenKind::Operator(crate::lexer::Operator::Eq)
                    | TokenKind::Keyword(Keyword::Cursor)
                    | TokenKind::Keyword(Keyword::Default)
                    | TokenKind::Punctuation(crate::lexer::Punctuation::Semi) => {
                        // Stop at assignment operators, CURSOR, DEFAULT, or semicolon
                        break;
                    }
                    _ => {
                        // Stop at anything else
                        break;
                    }
                }
            }

            type_span = Some(Span {
                start: type_start,
                end: type_end,
            });
        }
    }

    // Check if this is a cursor assignment: LET name [TYPE] CURSOR FOR ...
    if let Some(cursor_tok) = p.peek_non_trivia() {
        if matches!(cursor_tok.kind, TokenKind::Keyword(Keyword::Cursor)) {
            let cursor_token_id = p.current_token_id();
            let _ = p.advance(); // consume CURSOR

            // Expect FOR keyword
            if let Some(for_tok) = p.peek_non_trivia() {
                if matches!(for_tok.kind, TokenKind::Keyword(Keyword::For)) {
                    let for_token_id = p.current_token_id();
                    let _ = p.advance(); // consume FOR

                    // Save position before query
                    let query_start_pos = p.current_span().end;

                    // Try to parse the query using natural descent (best-effort)
                    let (query_span, parsed_query) = match p.parse_statement() {
                        Ok(stmt) => {
                            let query_span = stmt.span();
                            (query_span, Some(Box::new(stmt)))
                        }
                        Err(_) => {
                            // If parsing failed, consume tokens until semicolon and record span
                            let mut query_end = query_start_pos;
                            while let Some(tok) = p.peek() {
                                match tok.kind {
                                    TokenKind::Punctuation(crate::lexer::Punctuation::Semi)
                                    | TokenKind::Eof => break,
                                    _ => {
                                        query_end = tok.span.end;
                                        let _ = p.advance();
                                    }
                                }
                            }
                            let query_span = Span {
                                start: query_start_pos,
                                end: query_end,
                            };
                            (query_span, None)
                        }
                    };

                    // Don't consume semicolon - span ends at query
                    let end = query_span.end;

                    // Capture semicolon if present (don't consume - block loop will skip it)
                    let semicolon_token = if let Some(tok) = p.peek_non_trivia() {
                        if matches!(
                            tok.kind,
                            TokenKind::Punctuation(crate::lexer::Punctuation::Semi)
                        ) {
                            Some(p.current_token_id())
                        } else {
                            None
                        }
                    } else {
                        None
                    };

                    return Ok(AstStmt::LetCursor {
                        node_id: p.id_gen.next(),
                        semicolon_token,
                        span: Span {
                            start: let_kw.span.start,
                            end,
                        },
                        let_span: let_kw.span,
                        let_token: Some(let_token_id),
                        cursor_name: name,
                        cursor_token: Some(cursor_token_id),
                        for_token: Some(for_token_id),
                        query_span,
                        parsed_query,
                    });
                }
            }
        }
    }

    // Check if this is just a declaration without assignment: LET name TYPE;
    if let Some(semi_tok) = p.peek_non_trivia() {
        if matches!(
            semi_tok.kind,
            TokenKind::Punctuation(crate::lexer::Punctuation::Semi)
        ) {
            // This is a declaration without assignment
            // Don't consume semicolon - let outer wrapper handle it
            // Span includes type if present
            let span_end = type_span.map(|ts| ts.end).unwrap_or(name.span.end);
            let span = Span {
                start: let_kw.span.start,
                end: span_end,
            };
            // Use NULL literal to represent uninitialized variable
            let null_expr = AstExpr::Literal {
                node_id: p.id_gen.next(),
                literal: AstLiteral::Null {
                    span: Span {
                        start: name.span.end,
                        end: name.span.end,
                    },
                },
            };

            // Capture semicolon if present (don't consume - block loop will skip it)
            let semicolon_token = if let Some(tok) = p.peek_non_trivia() {
                if matches!(
                    tok.kind,
                    TokenKind::Punctuation(crate::lexer::Punctuation::Semi)
                ) {
                    Some(p.current_token_id())
                } else {
                    None
                }
            } else {
                None
            };

            return Ok(AstStmt::Let {
                node_id: p.id_gen.next(),
                semicolon_token,
                span,
                let_span: let_kw.span,
                let_token: Some(let_token_id),
                name,
                type_span,
                assign_op_span: None,
                expr: Box::new(null_expr),
            });
        }
    }

    let assign_tok = p.advance().ok_or_else(|| {
        ParseError::new(
            p.current_span(),
            ParseErrorKind::InvalidStatement {
                message: "Expected := or DEFAULT in LET statement".to_string(),
            },
        )
    })?;
    if !matches!(
        assign_tok.kind,
        TokenKind::Operator(crate::lexer::Operator::ColonEq)
            | TokenKind::Operator(crate::lexer::Operator::Eq)
            | TokenKind::Keyword(Keyword::Default)
    ) {
        return Err(ParseError::new(
            assign_tok.span,
            ParseErrorKind::InvalidStatement {
                message:
                    "LET statement requires := or DEFAULT after variable name (and optional type)"
                        .to_string(),
            },
        ));
    }

    let expr = try_parse_expr_scripting(p).map_err(|e| {
        ParseError::invalid_expression(
            p.current_span(),
            format!("Failed to parse LET expression: {:?}", e),
        )
    })?;
    let end = expr_span_end(&expr);
    // Don't consume semicolon - span ends at expression
    let span = Span {
        start: let_kw.span.start,
        end,
    };

    // Capture semicolon if present (don't consume - block loop will skip it)
    let semicolon_token = if let Some(tok) = p.peek_non_trivia() {
        if matches!(
            tok.kind,
            TokenKind::Punctuation(crate::lexer::Punctuation::Semi)
        ) {
            Some(p.current_token_id())
        } else {
            None
        }
    } else {
        None
    };

    Ok(AstStmt::Let {
        node_id: p.id_gen.next(),
        semicolon_token,
        span,
        let_span: let_kw.span,
        let_token: Some(let_token_id),
        name,
        type_span,
        assign_op_span: Some(assign_tok.span),
        expr: Box::new(expr),
    })
}

// === Shared loop body parsing helper ===

/// Parse the body of a loop construct (FOR/REPEAT/LOOP/WHILE).
/// Handles: RETURN, LET, identifier assignment, IF, CASE, SELECT, INSERT,
/// and optionally BREAK/EXIT/CONTINUE.
/// Returns the statement body and signals when END keyword is encountered.
pub(crate) fn parse_loop_body(
    p: &mut Parser<'_>,
    begin_start: u32,
    _allow_break_continue: bool, // Kept for API compatibility but now handled by context
) -> (Vec<AstStmt>, bool) {
    // Use error recovery infrastructure - loop bodies terminate on END or UNTIL
    let terminators = &[BodyTerminator::End, BodyTerminator::Until];
    let (body, _errors) = parse_body_with_recovery(p, StmtContext::Loop, begin_start, terminators);

    // Check if we stopped at a valid terminator
    let reached_end = if let Some(tok) = p.peek_non_trivia() {
        matches!(
            tok.kind,
            TokenKind::Keyword(Keyword::End) | TokenKind::Keyword(Keyword::Until)
        )
    } else {
        false
    };

    (body, reached_end)
}

// === IF/CASE helpers ===

/// Result-based IF statement parser with detailed error messages
pub(crate) fn try_parse_if_stmt_in_block(
    p: &mut Parser<'_>,
    context: StmtContext,
    begin_start: u32,
) -> ParseResult<AstStmt> {
    // Capture token ID before advance
    let if_token_id = p.current_token_id();
    let if_tok = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["IF".to_string()])?;

    // Check for optional opening parenthesis (Snowflake requires parens, BigQuery doesn't)
    let lparen_token_id = if matches!(
        p.peek_non_trivia().map(|t| &t.kind),
        Some(TokenKind::Punctuation(crate::lexer::Punctuation::LParen))
    ) {
        let tok_id = p.current_token_id();
        p.advance(); // consume '('
        Some(tok_id)
    } else {
        None
    };

    // Parse condition expression
    let cond_expr = try_parse_expr_scripting(p).map_err(|_| {
        ParseError::invalid_expression(
            p.current_span(),
            "IF statement requires condition expression".to_string(),
        )
    })?;

    // If we had opening parens, expect closing parenthesis
    let rparen_token_id = if lparen_token_id.is_some() {
        let rparen = p.peek_non_trivia().ok_or_else(|| {
            ParseError::new(
                p.current_span(),
                ParseErrorKind::InvalidStatement {
                    message: "IF statement requires closing parenthesis ')' after condition"
                        .to_string(),
                },
            )
        })?;
        if !matches!(
            rparen.kind,
            TokenKind::Punctuation(crate::lexer::Punctuation::RParen)
        ) {
            return Err(ParseError::new(
                rparen.span,
                ParseErrorKind::InvalidStatement {
                    message: format!(
                        "IF statement requires closing parenthesis ')' after condition, found {}",
                        Parser::token_description(rparen, p.source)
                    ),
                },
            ));
        }
        let tok_id = p.current_token_id();
        p.advance(); // consume ')'
        Some(tok_id)
    } else {
        None
    };

    let then_tok = p.peek_non_trivia().ok_or_else(|| {
        ParseError::new(
            p.current_span(),
            ParseErrorKind::InvalidStatement {
                message: "IF statement requires THEN keyword after condition".to_string(),
            },
        )
    })?;
    if !matches!(then_tok.kind, TokenKind::Keyword(Keyword::Then)) {
        return Err(ParseError::new(
            then_tok.span,
            ParseErrorKind::InvalidStatement {
                message: format!(
                    "IF statement requires THEN keyword after condition, found {}",
                    Parser::token_description(then_tok, p.source)
                ),
            },
        ));
    }
    // Capture THEN token ID before advance
    let then_token_id = p.current_token_id();
    let then_tok = p
        .advance()
        .expect_invariant("THEN keyword consumed after match in IF");
    let condition_span = cond_expr.span();
    let then_span = then_tok.span;
    let mut branches: Vec<IfBranch> = Vec::new();

    // Parse IF branch body with error recovery
    // Terminators: ELSIF, ELSE, END (these end the IF body)
    let if_body_terminators = [
        BodyTerminator::Elsif,
        BodyTerminator::Else,
        BodyTerminator::End,
    ];
    let (if_body, _if_body_errors) =
        parse_body_with_recovery(p, context, begin_start, &if_body_terminators);
    // Note: errors are captured in the Error nodes within if_body
    // We could collect _if_body_errors for diagnostics if needed

    branches.push(IfBranch {
        node_id: p.id_gen.next(),
        if_span: if_tok.span,
        if_token: Some(if_token_id),
        lparen_token: lparen_token_id,
        condition: Box::new(cond_expr),
        condition_span,
        rparen_token: rparen_token_id,
        then_span,
        then_token: Some(then_token_id),
        body: if_body,
    });

    // Parse ELSEIF branches
    loop {
        p.skip_trivia();
        let tok_opt = p.peek_non_trivia();
        let tok = match tok_opt {
            Some(t) => t,
            None => break,
        };
        match &tok.kind {
            TokenKind::Keyword(Keyword::Elsif) => {
                // Capture ELSEIF token ID before advance
                let elseif_token_id = p.current_token_id();
                let elseif_tok = p
                    .advance()
                    .expect_invariant("ELSIF keyword consumed after match");

                // Check for optional opening parenthesis (Snowflake requires parens, BigQuery doesn't)
                let elseif_lparen_token_id = if matches!(
                    p.peek_non_trivia().map(|t| &t.kind),
                    Some(TokenKind::Punctuation(crate::lexer::Punctuation::LParen))
                ) {
                    let tok_id = p.current_token_id();
                    p.advance(); // consume '('
                    Some(tok_id)
                } else {
                    None
                };

                // Parse condition expression
                let cond_expr = try_parse_expr_scripting(p).map_err(|_| {
                    ParseError::invalid_expression(
                        p.current_span(),
                        "ELSEIF statement requires condition expression".to_string(),
                    )
                })?;

                // If we had opening parens, expect closing parenthesis
                let elseif_rparen_token_id = if elseif_lparen_token_id.is_some() {
                    let rparen = p.peek_non_trivia().ok_or_else(|| {
                        ParseError::new(
                            p.current_span(),
                            ParseErrorKind::InvalidStatement {
                                message:
                                    "ELSEIF statement requires closing parenthesis ')' after condition"
                                        .to_string(),
                            },
                        )
                    })?;
                    if !matches!(
                        rparen.kind,
                        TokenKind::Punctuation(crate::lexer::Punctuation::RParen)
                    ) {
                        return Err(ParseError::new(
                            rparen.span,
                            ParseErrorKind::InvalidStatement {
                                message: format!("ELSEIF statement requires closing parenthesis ')' after condition, found {}", 
                                    Parser::token_description(rparen, p.source)),
                            },
                        ));
                    }
                    let tok_id = p.current_token_id();
                    p.advance(); // consume ')'
                    Some(tok_id)
                } else {
                    None
                };

                let then_tok2 = p.peek_non_trivia().ok_or_else(|| {
                    ParseError::new(
                        p.current_span(),
                        ParseErrorKind::InvalidStatement {
                            message: "ELSEIF statement requires THEN keyword after condition"
                                .to_string(),
                        },
                    )
                })?;
                if !matches!(then_tok2.kind, TokenKind::Keyword(Keyword::Then)) {
                    return Err(ParseError::new(
                        then_tok2.span,
                        ParseErrorKind::InvalidStatement {
                            message: format!(
                                "ELSEIF statement requires THEN keyword after condition, found {}",
                                Parser::token_description(then_tok2, p.source)
                            ),
                        },
                    ));
                }
                // Capture THEN token ID before advance
                let then_token_id2 = p.current_token_id();
                let then_tok2 = p
                    .advance()
                    .expect_invariant("THEN keyword consumed after match in ELSEIF");
                let condition_span = cond_expr.span();
                let then_span = then_tok2.span;

                // Parse ELSEIF branch body with error recovery
                let (elsif_body, _elsif_errors) = parse_body_with_recovery(
                    p,
                    context,
                    begin_start,
                    &if_body_terminators, // Same terminators: ELSIF, ELSE, END
                );

                branches.push(IfBranch {
                    node_id: p.id_gen.next(),
                    if_span: elseif_tok.span,
                    if_token: Some(elseif_token_id),
                    lparen_token: elseif_lparen_token_id,
                    condition: Box::new(cond_expr),
                    condition_span,
                    rparen_token: elseif_rparen_token_id,
                    then_span,
                    then_token: Some(then_token_id2),
                    body: elsif_body,
                });
            }
            _ => break,
        }
    }

    // Parse ELSE branch
    let else_body;
    let else_span;
    // Track ELSE token ID
    let mut else_token_id: Option<crate::cst::TokenId> = None;
    p.skip_trivia();
    if let Some(tok) = p.peek_non_trivia() {
        if matches!(tok.kind, TokenKind::Keyword(Keyword::Else)) {
            // Capture ELSE token ID before advance
            else_token_id = Some(p.current_token_id());
            let else_tok = p
                .advance()
                .expect_invariant("ELSE keyword consumed after match in IF");
            else_span = Some(else_tok.span);

            // Parse ELSE body with error recovery (only END terminates it)
            let else_terminators = [BodyTerminator::End];
            let (body, _else_errors) =
                parse_body_with_recovery(p, context, begin_start, &else_terminators);
            else_body = body;
        } else {
            else_span = None;
            else_body = Vec::new();
        }
    } else {
        else_span = None;
        else_body = Vec::new();
    }

    // Parse END IF
    p.skip_trivia();
    let end_tok = p.peek_non_trivia().ok_or_else(|| {
        ParseError::new(
            p.current_span(),
            ParseErrorKind::InvalidStatement {
                message: "IF statement requires END IF to close".to_string(),
            },
        )
    })?;
    if !matches!(end_tok.kind, TokenKind::Keyword(Keyword::End)) {
        return Err(ParseError::new(
            end_tok.span,
            ParseErrorKind::InvalidStatement {
                message: format!(
                    "IF statement requires END IF to close, found {}",
                    Parser::token_description(end_tok, p.source)
                ),
            },
        ));
    }
    // Capture END token ID before advance
    let end_token_id = p.current_token_id();
    let end_tok = p
        .advance()
        .expect_invariant("END keyword consumed after match in IF");
    let end_span_start = end_tok.span.start;
    let mut full_end = end_tok.span.end;
    let mut end_span_end = full_end;
    let mut end_if_token_id = None;
    if let Some(tok) = p.peek_non_trivia() {
        if matches!(tok.kind, TokenKind::Keyword(Keyword::If)) {
            end_if_token_id = Some(p.current_token_id());
            let if_end = p
                .advance()
                .expect_invariant("IF keyword consumed after peek in END IF");
            full_end = if_end.span.end;
            end_span_end = full_end;
        }
    }
    // Capture end_span - this is the END IF position
    let end_span = Some(Span {
        start: end_span_start,
        end: end_span_end,
    });
    // Capture semicolon token if present (don't consume - block loop will skip it)
    let semicolon_token = if let Some(tok) = p.peek_non_trivia() {
        if matches!(
            tok.kind,
            TokenKind::Punctuation(crate::lexer::Punctuation::Semi)
        ) {
            Some(p.current_token_id())
        } else {
            None
        }
    } else {
        None
    };
    // Don't consume semicolon - let outer wrapper handle it
    // Statement span ends at END IF, not semicolon
    let span = Span {
        start: begin_start,
        end: end_span_end,
    };
    Ok(AstStmt::If(Box::new(AstIfStmt {
        node_id: p.id_gen.next(),
        span,
        branches,
        else_span,
        else_token: else_token_id,
        else_body,
        end_span,
        end_token: Some(end_token_id),
        end_if_token: end_if_token_id,
        semicolon_token,
    })))
}

/// Result-based CASE statement parser with detailed error messages
/// Supports both simple CASE (with operand) and searched CASE (without operand)
pub(crate) fn try_parse_case_stmt_in_block(
    p: &mut Parser<'_>,
    context: StmtContext,
    begin_start: u32,
) -> ParseResult<AstStmt> {
    // Capture CASE token ID before advance
    let case_token_id = p.current_token_id();
    let case_tok = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["CASE".to_string()])?;
    let mut _operand: Option<AstExpr> = None;
    let mut operand_span: Option<Span> = None;
    p.skip_trivia();
    let mut branches: Vec<CaseBranch> = Vec::new();

    // Check for optional operand (simple CASE vs searched CASE)
    if let Some(next) = p.peek_non_trivia() {
        if !matches!(next.kind, TokenKind::Keyword(Keyword::When)) {
            // This is a simple CASE with an operand: CASE <expr> WHEN ...
            let expr = try_parse_expr_scripting(p).map_err(|_| {
                ParseError::invalid_expression(
                    p.current_span(),
                    "CASE statement requires operand expression before first WHEN".to_string(),
                )
            })?;
            let start = expr_span_start(&expr);
            let end = expr_span_end(&expr);
            operand_span = Some(Span { start, end });
            _operand = Some(expr);
        }
    }

    // Parse WHEN branches - at least one required
    let mut when_count = 0;
    loop {
        p.skip_trivia();
        let tok = match p.peek_non_trivia() {
            Some(t) => t,
            None => {
                if when_count == 0 {
                    return Err(ParseError::new(
                        p.current_span(),
                        ParseErrorKind::InvalidStatement {
                            message: "CASE statement requires at least one WHEN clause".to_string(),
                        },
                    ));
                }
                break;
            }
        };

        match &tok.kind {
            TokenKind::Keyword(Keyword::When) => {
                // Capture WHEN token ID before advance
                let when_token_id = p.current_token_id();
                let when_tok = p
                    .advance()
                    .expect_invariant("WHEN keyword consumed after match in CASE");
                p.skip_trivia();

                // Parse condition expression for WHEN (searched or simple CASE)
                let cond_expr = try_parse_expr_scripting(p).map_err(|_| {
                    ParseError::invalid_expression(
                        p.current_span(),
                        "WHEN clause requires condition expression before THEN".to_string(),
                    )
                })?;
                let condition_span = Span {
                    start: expr_span_start(&cond_expr),
                    end: expr_span_end(&cond_expr),
                };

                // Expect THEN keyword
                p.skip_trivia();
                let then_kw = p.peek_non_trivia().ok_or_else(|| {
                    ParseError::new(
                        p.current_span(),
                        ParseErrorKind::InvalidStatement {
                            message: "WHEN clause requires THEN keyword after condition"
                                .to_string(),
                        },
                    )
                })?;
                if !matches!(then_kw.kind, TokenKind::Keyword(Keyword::Then)) {
                    return Err(ParseError::new(
                        then_kw.span,
                        ParseErrorKind::InvalidStatement {
                            message: format!(
                                "WHEN clause requires THEN keyword after condition, found {}",
                                Parser::token_description(then_kw, p.source),
                            ),
                        },
                    ));
                }
                // Capture THEN token ID before advance
                let then_token_id = p.current_token_id();
                // Consume THEN
                let then_tok = p
                    .advance()
                    .expect_invariant("THEN keyword consumed after match in CASE WHEN");
                let then_span = then_tok.span;

                // Parse body statements with error recovery
                // WHEN body terminates on WHEN, ELSE, or END
                let when_body_terminators = &[
                    BodyTerminator::When,
                    BodyTerminator::Else,
                    BodyTerminator::End,
                ];
                let (body, _errors) =
                    parse_body_with_recovery(p, context, begin_start, when_body_terminators);

                branches.push(CaseBranch {
                    node_id: p.id_gen.next(),
                    when_span: when_tok.span,
                    when_token: Some(when_token_id),
                    condition: Box::new(cond_expr),
                    condition_span,
                    then_span,
                    then_token: Some(then_token_id),
                    body,
                });
                when_count += 1;
            }
            _ => break,
        }
    }

    // Verify that at least one WHEN clause was parsed
    if when_count == 0 {
        return Err(ParseError::new(
            p.current_span(),
            ParseErrorKind::InvalidStatement {
                message: "CASE statement requires at least one WHEN clause".to_string(),
            },
        ));
    }

    // Parse optional ELSE branch
    let mut else_body = Vec::new();
    let mut else_span: Option<Span> = None;
    let mut else_token_id: Option<crate::cst::TokenId> = None;
    p.skip_trivia();
    if let Some(tok) = p.peek_non_trivia() {
        if matches!(tok.kind, TokenKind::Keyword(Keyword::Else)) {
            // Capture ELSE token ID before advance
            else_token_id = Some(p.current_token_id());
            let else_tok = p
                .advance()
                .expect_invariant("ELSE keyword consumed after match in CASE");
            else_span = Some(else_tok.span);

            // Parse ELSE body statements with error recovery
            // ELSE body terminates on END
            let else_body_terminators = &[BodyTerminator::End];
            let (body, _errors) =
                parse_body_with_recovery(p, context, begin_start, else_body_terminators);
            else_body = body;
        }
    }

    // Parse END [CASE]
    p.skip_trivia();
    let end_tok = p.peek_non_trivia().ok_or_else(|| {
        ParseError::new(
            p.current_span(),
            ParseErrorKind::InvalidStatement {
                message: "CASE statement requires END or END CASE to close".to_string(),
            },
        )
    })?;

    if !matches!(end_tok.kind, TokenKind::Keyword(Keyword::End)) {
        return Err(ParseError::new(
            end_tok.span,
            ParseErrorKind::InvalidStatement {
                message: format!(
                    "CASE statement requires END or END CASE to close, found {}",
                    Parser::token_description(end_tok, p.source)
                ),
            },
        ));
    }

    // Capture END token ID before advance
    let end_token_id = p.current_token_id();
    let end_tok = p
        .advance()
        .expect_invariant("END keyword consumed after match in CASE");
    let end_span_start = end_tok.span.start;
    let mut full_end = end_tok.span.end;
    let mut end_span_end = full_end;

    // Optional CASE keyword after END
    let mut end_case_token_id = None;
    if let Some(tok) = p.peek_non_trivia() {
        if matches!(tok.kind, TokenKind::Keyword(Keyword::Case)) {
            end_case_token_id = Some(p.current_token_id());
            let case_end = p
                .advance()
                .expect_invariant("CASE keyword consumed after peek in END CASE");
            full_end = case_end.span.end;
            end_span_end = full_end;
        }
    }

    // Capture end_span - this is the END CASE position
    let end_span = Some(Span {
        start: end_span_start,
        end: end_span_end,
    });

    // Capture semicolon token if present (don't consume - block loop will skip it)
    let semicolon_token = if let Some(tok) = p.peek_non_trivia() {
        if matches!(
            tok.kind,
            TokenKind::Punctuation(crate::lexer::Punctuation::Semi)
        ) {
            Some(p.current_token_id())
        } else {
            None
        }
    } else {
        None
    };

    // Don't consume semicolon - let outer wrapper handle it
    // Statement span ends at END CASE, not semicolon

    let span = Span {
        start: case_tok.span.start,
        end: end_span_end,
    };

    Ok(AstStmt::CaseStmt(Box::new(AstCaseStmt {
        node_id: p.id_gen.next(),
        span,
        case_span: case_tok.span,
        case_token: Some(case_token_id),
        operand_span,
        branches,
        else_span,
        else_token: else_token_id,
        else_body,
        end_span,
        end_token: Some(end_token_id),
        end_case_token: end_case_token_id,
        semicolon_token,
    })))
}

/// Result-based WHILE loop parser with detailed error messages
pub(crate) fn try_parse_while_stmt_in_block(
    p: &mut Parser<'_>,
    begin_start: u32,
    label_span: Option<Span>,
) -> ParseResult<AstStmt> {
    // Capture WHILE token ID before advance
    let while_token_id = p.current_token_id();
    let while_tok = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["WHILE".to_string()])?;
    let while_span = while_tok.span;

    // Check for optional opening parenthesis (Snowflake requires parens, BigQuery doesn't)
    let lparen_token_id = if matches!(
        p.peek_non_trivia().map(|t| &t.kind),
        Some(TokenKind::Punctuation(crate::lexer::Punctuation::LParen))
    ) {
        let tok_id = p.current_token_id();
        p.advance(); // consume '('
        Some(tok_id)
    } else {
        None
    };

    // Parse condition expression
    let cond_expr = try_parse_expr_scripting(p).map_err(|_| {
        ParseError::invalid_expression(
            p.current_span(),
            "WHILE loop requires condition expression".to_string(),
        )
    })?;

    let condition_span = cond_expr.span();

    // If we had opening parens, expect closing parenthesis
    let rparen_token_id = if lparen_token_id.is_some() {
        let rparen = p.peek_non_trivia().ok_or_else(|| {
            ParseError::new(
                p.current_span(),
                ParseErrorKind::InvalidStatement {
                    message: "WHILE loop requires closing parenthesis ')' after condition"
                        .to_string(),
                },
            )
        })?;
        if !matches!(
            rparen.kind,
            TokenKind::Punctuation(crate::lexer::Punctuation::RParen)
        ) {
            return Err(ParseError::new(
                rparen.span,
                ParseErrorKind::InvalidStatement {
                    message: "WHILE loop requires closing parenthesis ')' after condition"
                        .to_string(),
                },
            ));
        }
        let tok_id = p.current_token_id();
        p.advance(); // consume ')'
        Some(tok_id)
    } else {
        None
    };

    // Validate DO or LOOP keyword
    p.skip_trivia();
    let body_kw = p.peek_non_trivia().ok_or_else(|| {
        ParseError::new(
            p.current_span(),
            ParseErrorKind::InvalidStatement {
                message: "WHILE loop requires DO or LOOP keyword after condition".to_string(),
            },
        )
    })?;

    if !matches!(
        body_kw.kind,
        TokenKind::Keyword(Keyword::Do) | TokenKind::Keyword(Keyword::Loop)
    ) {
        return Err(ParseError::new(
            body_kw.span,
            ParseErrorKind::InvalidStatement {
                message: format!(
                    "WHILE loop requires DO or LOOP keyword after condition, found {}",
                    Parser::token_description(body_kw, p.source)
                ),
            },
        ));
    }
    let body_keyword_token_id = p.current_token_id();
    let body_keyword_tok = p
        .advance()
        .expect_invariant("DO/LOOP keyword consumed after match in WHILE");

    // Parse loop body
    let (body, reached_end) = parse_loop_body(p, begin_start, true);
    if !reached_end {
        return Err(ParseError::new(
            p.current_span(),
            ParseErrorKind::InvalidStatement {
                message: "WHILE loop requires END WHILE or END LOOP to close".to_string(),
            },
        ));
    }

    // Parse END [WHILE|LOOP] [label]
    // Capture END token ID before advance
    let end_token_id = p.current_token_id();
    let end_kw = p
        .advance()
        .expect_invariant("END keyword consumed after loop body in WHILE");
    let end_span_start = end_kw.span.start;
    let mut full_end = end_kw.span.end;

    let mut end_while_token_id = None;
    let mut end_label_span: Option<Span> = None;
    if let Some(tok2) = p.peek_non_trivia() {
        if matches!(
            tok2.kind,
            TokenKind::Keyword(Keyword::While) | TokenKind::Keyword(Keyword::Loop)
        ) {
            if matches!(tok2.kind, TokenKind::Keyword(Keyword::While)) {
                end_while_token_id = Some(p.current_token_id());
            }
            let t2 = p
                .advance()
                .expect_invariant("WHILE/LOOP keyword consumed after END in WHILE");
            full_end = t2.span.end;
            if let Some(lbl) = p.peek_non_trivia() {
                if p.can_be_identifier_token(lbl) {
                    let ltok = p
                        .advance()
                        .expect_invariant("label identifier consumed after END WHILE");
                    end_label_span = Some(ltok.span);
                    full_end = ltok.span.end;
                }
            }
        }
    }

    // Capture end_span - this is the END WHILE/LOOP position
    let end_span = Span {
        start: end_span_start,
        end: full_end,
    };

    // Capture semicolon token if present (don't consume - block loop will skip it)
    let semicolon_token = if let Some(tok) = p.peek_non_trivia() {
        if matches!(
            tok.kind,
            TokenKind::Punctuation(crate::lexer::Punctuation::Semi)
        ) {
            Some(p.current_token_id())
        } else {
            None
        }
    } else {
        None
    };

    // Don't consume semicolon - let outer wrapper handle it
    // Statement span ends at END WHILE/LOOP, not semicolon

    let span = Span {
        start: label_span.map_or(begin_start, |ls| ls.start),
        end: full_end,
    };

    Ok(AstStmt::While(Box::new(AstWhileStmt {
        node_id: p.id_gen.next(),
        span,
        label_span,
        end_label_span,
        while_span,
        while_token: Some(while_token_id),
        lparen_token: lparen_token_id,
        condition: Box::new(cond_expr),
        condition_span,
        rparen_token: rparen_token_id,
        body_keyword_span: body_keyword_tok.span,
        body_keyword_token: Some(body_keyword_token_id),
        body,
        end_span: Some(end_span),
        end_token: Some(end_token_id),
        end_while_token: end_while_token_id,
        semicolon_token,
    })))
}

/// Result-based FOR loop parser with detailed error messages
pub(crate) fn try_parse_for_stmt_in_block(
    p: &mut Parser<'_>,
    begin_start: u32,
    label_span: Option<Span>,
) -> ParseResult<AstStmt> {
    // Capture FOR token ID before advance
    let for_token_id = p.current_token_id();
    let for_tok = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["FOR".to_string()])?;
    let for_span = for_tok.span;

    // Parse loop variable
    let loop_var_tok = p.peek_non_trivia().ok_or_else(|| {
        ParseError::new(
            p.current_span(),
            ParseErrorKind::InvalidStatement {
                message: "FOR loop requires loop variable identifier".to_string(),
            },
        )
    })?;

    let loop_var_span = match &loop_var_tok.kind {
        TokenKind::Identifier { .. } => loop_var_tok.span,
        _ if p.can_be_identifier_token(loop_var_tok) => loop_var_tok.span,
        _ => {
            return Err(ParseError::new(
                loop_var_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: format!(
                        "FOR loop requires loop variable identifier, found {}",
                        Parser::token_description(loop_var_tok, p.source)
                    ),
                },
            ));
        }
    };
    let _ = p.advance();

    // Check for IN keyword (Snowflake) or AS keyword (Databricks: FOR var AS query DO)
    let in_tok = p.peek_non_trivia().ok_or_else(|| {
        ParseError::new(
            p.current_span(),
            ParseErrorKind::InvalidStatement {
                message: "FOR loop requires IN or AS keyword after loop variable".to_string(),
            },
        )
    })?;

    if !matches!(
        in_tok.kind,
        TokenKind::Keyword(Keyword::In) | TokenKind::Keyword(Keyword::As)
    ) {
        return Err(ParseError::new(
            in_tok.span,
            ParseErrorKind::InvalidStatement {
                message: format!(
                    "FOR loop requires IN or AS keyword after loop variable, found {}",
                    Parser::token_description(in_tok, p.source)
                ),
            },
        ));
    }
    let in_span = in_tok.span;
    let in_token_id = p.current_token_id();
    let _ = p.advance();

    // Parse range/cursor/resultset (until DO or LOOP)
    // We need header_start to point to the first real token AFTER IN (not in_span.end)
    // so that trivia between IN and the range expression is not included in range_or_cursor_span.
    let mut header_start: Option<u32> = None;
    let mut header_end = in_span.end;
    let mut found_do_or_loop = false;

    loop {
        p.skip_trivia();
        let tok = match p.peek_non_trivia() {
            Some(t) => t,
            None => break,
        };

        match &tok.kind {
            TokenKind::Keyword(Keyword::Do) | TokenKind::Keyword(Keyword::Loop) => {
                found_do_or_loop = true;
                break;
            }
            _ => {
                let t2 = p
                    .advance()
                    .expect_invariant("FOR loop header token consumed after peek");
                // Set header_start to the first real token's start
                if header_start.is_none() {
                    header_start = Some(t2.span.start);
                }
                header_end = t2.span.end;
            }
        }
    }

    if !found_do_or_loop {
        return Err(ParseError::new(
            p.current_span(),
            ParseErrorKind::InvalidStatement {
                message: "FOR loop requires DO or LOOP keyword".to_string(),
            },
        ));
    }

    // If header_start is None, it means FOR i IN DO (no range expression) - use in_span.end as fallback
    let range_or_cursor_span = Span {
        start: header_start.unwrap_or(in_span.end),
        end: header_end,
    };

    let body_keyword_token_id = p.current_token_id();
    let body_keyword_tok = p
        .advance()
        .expect_invariant("DO/LOOP keyword consumed after match in FOR");

    // Parse loop body
    let (body, reached_end) = parse_loop_body(p, begin_start, false);
    if !reached_end {
        return Err(ParseError::new(
            p.current_span(),
            ParseErrorKind::InvalidStatement {
                message: "FOR loop requires END FOR or END LOOP to close".to_string(),
            },
        ));
    }

    // Parse END [FOR|LOOP] [label]
    // Capture END token ID before advance
    let end_token_id = p.current_token_id();
    let end_kw = p
        .advance()
        .expect_invariant("END keyword consumed after loop body in FOR");
    let end_span_start = end_kw.span.start;
    let mut full_end = end_kw.span.end;

    let mut end_for_token_id = None;
    let mut end_label_span: Option<Span> = None;
    if let Some(tok2) = p.peek_non_trivia() {
        if matches!(
            tok2.kind,
            TokenKind::Keyword(Keyword::For) | TokenKind::Keyword(Keyword::Loop)
        ) {
            if matches!(tok2.kind, TokenKind::Keyword(Keyword::For)) {
                end_for_token_id = Some(p.current_token_id());
            }
            let t2 = p
                .advance()
                .expect_invariant("FOR/LOOP keyword consumed after END in FOR");
            full_end = t2.span.end;
            if let Some(lbl) = p.peek_non_trivia() {
                if p.can_be_identifier_token(lbl) {
                    let ltok = p
                        .advance()
                        .expect_invariant("label identifier consumed after END FOR");
                    end_label_span = Some(ltok.span);
                    full_end = ltok.span.end;
                }
            }
        }
    }

    // Capture end_span - this is the END FOR/LOOP position
    let end_span = Span {
        start: end_span_start,
        end: full_end,
    };

    // Capture semicolon token if present (don't consume - block loop will skip it)
    let semicolon_token = if let Some(tok) = p.peek_non_trivia() {
        if matches!(
            tok.kind,
            TokenKind::Punctuation(crate::lexer::Punctuation::Semi)
        ) {
            Some(p.current_token_id())
        } else {
            None
        }
    } else {
        None
    };

    // Don't consume semicolon - let outer wrapper handle it
    // Statement span ends at END FOR/LOOP, not semicolon

    let span = Span {
        start: label_span.map_or(begin_start, |ls| ls.start),
        end: full_end,
    };

    Ok(AstStmt::For(Box::new(AstForStmt {
        node_id: p.id_gen.next(),
        span,
        label_span,
        end_label_span,
        for_span,
        for_token: Some(for_token_id),
        loop_var_span,
        in_span,
        in_token: Some(in_token_id),
        range_or_cursor_span,
        body_keyword_span: body_keyword_tok.span,
        body_keyword_token: Some(body_keyword_token_id),
        body,
        end_span: Some(end_span),
        end_token: Some(end_token_id),
        end_for_token: end_for_token_id,
        semicolon_token,
    })))
}

/// PostgreSQL PL/pgSQL `FOREACH target [SLICE n] IN ARRAY <expr> LOOP … END LOOP [label]`.
/// FOREACH / SLICE / ARRAY are non-reserved identifiers recognized by lexeme; the
/// iterated array is parsed as a real expression (not gobbled). The body is parsed
/// via the shared [`parse_loop_body`] so its statements are visible as statements.
pub(crate) fn try_parse_foreach_stmt_in_block(
    p: &mut Parser<'_>,
    begin_start: u32,
) -> ParseResult<AstStmt> {
    // FOREACH opener (non-reserved identifier).
    let foreach_token = p.current_token_id();
    let foreach_tok = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["FOREACH".to_string()])?;
    let foreach_span = foreach_tok.span;

    // Target loop variable.
    let loop_var_tok = p.peek_non_trivia().ok_or_else(|| {
        ParseError::new(
            p.current_span(),
            ParseErrorKind::InvalidStatement {
                message: "FOREACH loop requires a target variable identifier".to_string(),
            },
        )
    })?;
    let loop_var_span = if matches!(loop_var_tok.kind, TokenKind::Identifier { .. })
        || p.can_be_identifier_token(loop_var_tok)
    {
        loop_var_tok.span
    } else {
        return Err(ParseError::new(
            loop_var_tok.span,
            ParseErrorKind::InvalidStatement {
                message: format!(
                    "FOREACH loop requires a target variable identifier, found {}",
                    Parser::token_description(loop_var_tok, p.source)
                ),
            },
        ));
    };
    let _ = p.advance();

    // Optional `SLICE <int>`.
    let mut slice_span = None;
    let mut slice_count_span = None;
    if let Some(tok) = p.peek_non_trivia() {
        if matches!(tok.kind, TokenKind::Identifier { .. })
            && tok.lexeme(p.source).eq_ignore_ascii_case("slice")
        {
            slice_span = Some(tok.span);
            let _ = p.advance();
            let count_tok = p.peek_non_trivia().ok_or_else(|| {
                ParseError::new(
                    p.current_span(),
                    ParseErrorKind::InvalidStatement {
                        message: "FOREACH SLICE requires an integer depth".to_string(),
                    },
                )
            })?;
            if matches!(count_tok.kind, TokenKind::Literal(_)) {
                slice_count_span = Some(count_tok.span);
                let _ = p.advance();
            } else {
                return Err(ParseError::new(
                    count_tok.span,
                    ParseErrorKind::InvalidStatement {
                        message: format!(
                            "FOREACH SLICE requires an integer depth, found {}",
                            Parser::token_description(count_tok, p.source)
                        ),
                    },
                ));
            }
        }
    }

    // IN keyword.
    let in_token = p.current_token_id();
    let in_tok = p.peek_non_trivia().ok_or_else(|| {
        ParseError::new(
            p.current_span(),
            ParseErrorKind::InvalidStatement {
                message: "FOREACH loop requires the IN keyword".to_string(),
            },
        )
    })?;
    if !matches!(in_tok.kind, TokenKind::Keyword(Keyword::In)) {
        return Err(ParseError::new(
            in_tok.span,
            ParseErrorKind::InvalidStatement {
                message: format!(
                    "FOREACH loop requires the IN keyword, found {}",
                    Parser::token_description(in_tok, p.source)
                ),
            },
        ));
    }
    let in_span = in_tok.span;
    let _ = p.advance();

    // ARRAY (non-reserved identifier).
    let array_token = p.current_token_id();
    let array_tok = p.peek_non_trivia().ok_or_else(|| {
        ParseError::new(
            p.current_span(),
            ParseErrorKind::InvalidStatement {
                message: "FOREACH loop requires the ARRAY keyword after IN".to_string(),
            },
        )
    })?;
    if !(matches!(array_tok.kind, TokenKind::Identifier { .. })
        && array_tok.lexeme(p.source).eq_ignore_ascii_case("array"))
    {
        return Err(ParseError::new(
            array_tok.span,
            ParseErrorKind::InvalidStatement {
                message: format!(
                    "FOREACH loop requires the ARRAY keyword after IN, found {}",
                    Parser::token_description(array_tok, p.source)
                ),
            },
        ));
    }
    let array_span = array_tok.span;
    let _ = p.advance();

    // The iterated array expression (parsed, not gobbled). `parse_expr` stops
    // at the LOOP keyword which cannot continue an expression.
    let array_expr = p.parse_expr()?;

    // LOOP body-opener.
    let body_keyword_token = p.current_token_id();
    let body_kw_tok = p.peek_non_trivia().ok_or_else(|| {
        ParseError::new(
            p.current_span(),
            ParseErrorKind::InvalidStatement {
                message: "FOREACH loop requires the LOOP keyword".to_string(),
            },
        )
    })?;
    if !matches!(body_kw_tok.kind, TokenKind::Keyword(Keyword::Loop)) {
        return Err(ParseError::new(
            body_kw_tok.span,
            ParseErrorKind::InvalidStatement {
                message: format!(
                    "FOREACH loop requires the LOOP keyword, found {}",
                    Parser::token_description(body_kw_tok, p.source)
                ),
            },
        ));
    }
    let body_keyword_span = body_kw_tok.span;
    let _ = p.advance();

    // Loop body (shared driver).
    let (body, reached_end) = parse_loop_body(p, begin_start, false);
    if !reached_end {
        return Err(ParseError::new(
            p.current_span(),
            ParseErrorKind::InvalidStatement {
                message: "FOREACH loop requires END LOOP to close".to_string(),
            },
        ));
    }

    // END LOOP [label].
    let end_token = p.current_token_id();
    let end_kw = p
        .advance()
        .expect_invariant("END keyword consumed after FOREACH body");
    let end_span_start = end_kw.span.start;
    let mut full_end = end_kw.span.end;

    let mut end_loop_token = None;
    let mut end_label_span: Option<Span> = None;
    if let Some(tok2) = p.peek_non_trivia() {
        if matches!(tok2.kind, TokenKind::Keyword(Keyword::Loop)) {
            end_loop_token = Some(p.current_token_id());
            let t2 = p
                .advance()
                .expect_invariant("LOOP keyword consumed after END in FOREACH");
            full_end = t2.span.end;
            if let Some(lbl) = p.peek_non_trivia() {
                if p.can_be_identifier_token(lbl) {
                    let ltok = p
                        .advance()
                        .expect_invariant("label identifier consumed after END LOOP");
                    end_label_span = Some(ltok.span);
                    full_end = ltok.span.end;
                }
            }
        }
    }

    let end_span = Span {
        start: end_span_start,
        end: full_end,
    };

    // Capture (don't consume) a trailing semicolon — the block loop skips it.
    let semicolon_token = if let Some(tok) = p.peek_non_trivia() {
        if matches!(
            tok.kind,
            TokenKind::Punctuation(crate::lexer::Punctuation::Semi)
        ) {
            Some(p.current_token_id())
        } else {
            None
        }
    } else {
        None
    };

    let span = Span {
        start: begin_start,
        end: full_end,
    };

    Ok(AstStmt::ForEach(Box::new(AstForEachStmt {
        node_id: p.id_gen.next(),
        span,
        end_label_span,
        foreach_span,
        foreach_token: Some(foreach_token),
        loop_var_span,
        slice_span,
        slice_count_span,
        in_span,
        in_token: Some(in_token),
        array_span,
        array_token: Some(array_token),
        array_expr: Box::new(array_expr),
        body_keyword_span,
        body_keyword_token: Some(body_keyword_token),
        body,
        end_span: Some(end_span),
        end_token: Some(end_token),
        end_loop_token,
        semicolon_token,
    })))
}

/// Result-based REPEAT loop parser with detailed error messages
pub(crate) fn try_parse_repeat_stmt_in_block(
    p: &mut Parser<'_>,
    begin_start: u32,
    label_span: Option<Span>,
) -> ParseResult<AstStmt> {
    // Capture REPEAT token ID before advance
    let repeat_token_id = p.current_token_id();
    let repeat_tok = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["REPEAT".to_string()])?;
    let repeat_span = repeat_tok.span;

    // Parse loop body (until UNTIL keyword)
    let (body, reached_until) = parse_loop_body(p, begin_start, true);
    if !reached_until {
        return Err(ParseError::new(
            p.current_span(),
            ParseErrorKind::InvalidStatement {
                message: "REPEAT loop requires UNTIL keyword".to_string(),
            },
        ));
    }

    // Validate UNTIL keyword
    let until_tok = p.peek_non_trivia().ok_or_else(|| {
        ParseError::new(
            p.current_span(),
            ParseErrorKind::InvalidStatement {
                message: "REPEAT loop requires UNTIL keyword".to_string(),
            },
        )
    })?;

    if !matches!(until_tok.kind, TokenKind::Keyword(Keyword::Until)) {
        return Err(ParseError::new(
            until_tok.span,
            ParseErrorKind::InvalidStatement {
                message: "REPEAT loop requires UNTIL keyword".to_string(),
            },
        ));
    }
    // Capture UNTIL token ID before advance
    let until_token_id = p.current_token_id();
    let until_kw = p
        .advance()
        .expect_invariant("UNTIL keyword consumed after match in REPEAT");
    let until_span = until_kw.span;

    // Check for optional opening parenthesis (Snowflake style: UNTIL (cond), BigQuery style: UNTIL cond)
    p.skip_trivia();
    let has_parens = p
        .peek_non_trivia()
        .map(|t| {
            matches!(
                t.kind,
                TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
            )
        })
        .unwrap_or(false);

    let condition_span = if has_parens {
        // Snowflake style: UNTIL (condition)
        let lparen_tok = p
            .advance()
            .expect_invariant("'(' consumed after match in REPEAT UNTIL condition");
        let cond_start = lparen_tok.span.start; // Include opening paren

        // Parse UNTIL condition
        p.skip_trivia();
        let first_cond = p.peek_non_trivia().ok_or_else(|| {
            ParseError::new(
                p.current_span(),
                ParseErrorKind::InvalidStatement {
                    message: "REPEAT loop requires condition expression after '('".to_string(),
                },
            )
        })?;

        let mut depth: usize = 1;
        let mut cond_end = first_cond.span.end;
        let mut found_closing_paren = false;

        while let Some(tok) = p.advance() {
            match tok.kind {
                TokenKind::Punctuation(crate::lexer::Punctuation::LParen) => {
                    depth += 1;
                }
                TokenKind::Punctuation(crate::lexer::Punctuation::RParen) => {
                    depth -= 1;
                    if depth == 0 {
                        cond_end = tok.span.end; // Include closing paren
                        found_closing_paren = true;
                        break;
                    }
                }
                _ => {}
            }
            cond_end = tok.span.end;
        }

        if !found_closing_paren {
            return Err(ParseError::new(
                p.current_span(),
                ParseErrorKind::InvalidStatement {
                    message: "REPEAT loop requires closing parenthesis ')' after UNTIL condition"
                        .to_string(),
                },
            ));
        }

        Span {
            start: cond_start,
            end: cond_end,
        }
    } else {
        // BigQuery style: UNTIL condition (no parens)
        // Parse until END keyword
        let first_cond = p.peek_non_trivia().ok_or_else(|| {
            ParseError::new(
                p.current_span(),
                ParseErrorKind::InvalidStatement {
                    message: "REPEAT loop requires condition expression after UNTIL".to_string(),
                },
            )
        })?;

        let cond_start = first_cond.span.start;
        let mut cond_end = first_cond.span.end;

        // Consume tokens until we hit END keyword
        while let Some(tok) = p.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::End)) {
                break;
            }
            // Handle newlines/line breaks as potential end markers
            if matches!(
                tok.kind,
                TokenKind::Punctuation(crate::lexer::Punctuation::Semi)
            ) {
                // Semicolon before END - stop here
                break;
            }
            let consumed = p
                .advance()
                .expect_invariant("token consumed in UNTIL condition");
            cond_end = consumed.span.end;
        }

        Span {
            start: cond_start,
            end: cond_end,
        }
    };

    // Validate END REPEAT
    p.skip_trivia();
    let end_tok = p.peek_non_trivia().ok_or_else(|| {
        ParseError::new(
            p.current_span(),
            ParseErrorKind::InvalidStatement {
                message: "REPEAT loop requires END REPEAT to close".to_string(),
            },
        )
    })?;

    if !matches!(end_tok.kind, TokenKind::Keyword(Keyword::End)) {
        return Err(ParseError::new(
            end_tok.span,
            ParseErrorKind::InvalidStatement {
                message: format!(
                    "REPEAT loop requires END REPEAT to close, found {}",
                    Parser::token_description(end_tok, p.source)
                ),
            },
        ));
    }
    // Capture END token ID before advance
    let end_token_id = p.current_token_id();
    let end_span_start = end_tok.span.start;
    let _ = p.advance();

    // Validate REPEAT keyword after END
    p.skip_trivia();
    let repeat_tok = p.peek_non_trivia().ok_or_else(|| {
        ParseError::new(
            p.current_span(),
            ParseErrorKind::InvalidStatement {
                message: "REPEAT loop requires REPEAT keyword after END".to_string(),
            },
        )
    })?;

    if !matches!(repeat_tok.kind, TokenKind::Keyword(Keyword::Repeat)) {
        return Err(ParseError::new(
            repeat_tok.span,
            ParseErrorKind::InvalidStatement {
                message: "REPEAT loop requires REPEAT keyword after END".to_string(),
            },
        ));
    }
    let end_repeat_token_id = p.current_token_id();
    let repeat_end = p
        .advance()
        .expect_invariant("REPEAT keyword consumed after END in REPEAT");
    let mut full_end = repeat_end.span.end;

    // Optional label
    let mut end_label_span: Option<Span> = None;
    if let Some(lbl) = p.peek_non_trivia() {
        if p.can_be_identifier_token(lbl) {
            let ltok = p
                .advance()
                .expect_invariant("label identifier consumed after END REPEAT");
            end_label_span = Some(ltok.span);
            full_end = ltok.span.end;
        }
    }

    // Capture end_span - this is the END REPEAT position
    let end_span = Span {
        start: end_span_start,
        end: full_end,
    };

    // Capture semicolon token if present (don't consume - block loop will skip it)
    let semicolon_token = if let Some(tok) = p.peek_non_trivia() {
        if matches!(
            tok.kind,
            TokenKind::Punctuation(crate::lexer::Punctuation::Semi)
        ) {
            Some(p.current_token_id())
        } else {
            None
        }
    } else {
        None
    };

    // Don't consume semicolon - let outer wrapper handle it
    // Statement span ends at END REPEAT, not semicolon

    let span = Span {
        start: label_span.map_or(begin_start, |ls| ls.start),
        end: full_end,
    };

    Ok(AstStmt::Repeat(Box::new(AstRepeatStmt {
        node_id: p.id_gen.next(),
        span,
        label_span,
        end_label_span,
        repeat_span,
        repeat_token: Some(repeat_token_id),
        body,
        until_span,
        until_token: Some(until_token_id),
        until_condition_span: condition_span,
        end_span: Some(end_span),
        end_token: Some(end_token_id),
        end_repeat_token: Some(end_repeat_token_id),
        semicolon_token,
    })))
}

/// Result-based LOOP parser with detailed error messages
pub(crate) fn try_parse_loop_stmt_in_block(
    p: &mut Parser<'_>,
    begin_start: u32,
    label_span: Option<Span>,
) -> ParseResult<AstStmt> {
    // Capture LOOP token ID before advance
    let loop_token_id = p.current_token_id();
    let loop_tok = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["LOOP".to_string()])?;
    let loop_span = loop_tok.span;

    // Parse loop body (until END keyword)
    let (body, reached_end) = parse_loop_body(p, begin_start, true);
    if !reached_end {
        return Err(ParseError::new(
            p.current_span(),
            ParseErrorKind::InvalidStatement {
                message: "LOOP statement requires END LOOP to close".to_string(),
            },
        ));
    }

    // Validate END keyword
    let end_tok = p.peek_non_trivia().ok_or_else(|| {
        ParseError::new(
            p.current_span(),
            ParseErrorKind::InvalidStatement {
                message: "LOOP statement requires END LOOP to close".to_string(),
            },
        )
    })?;

    if !matches!(end_tok.kind, TokenKind::Keyword(Keyword::End)) {
        return Err(ParseError::new(
            end_tok.span,
            ParseErrorKind::InvalidStatement {
                message: format!(
                    "LOOP statement requires END LOOP to close, found {}",
                    Parser::token_description(end_tok, p.source)
                ),
            },
        ));
    }
    // Capture END token ID before advance
    let end_token_id = p.current_token_id();
    let end_span_start = end_tok.span.start;
    let _ = p.advance();

    // Validate LOOP keyword after END
    p.skip_trivia();
    let loop_tok = p.peek_non_trivia().ok_or_else(|| {
        ParseError::new(
            p.current_span(),
            ParseErrorKind::InvalidStatement {
                message: "LOOP statement requires LOOP keyword after END".to_string(),
            },
        )
    })?;

    if !matches!(loop_tok.kind, TokenKind::Keyword(Keyword::Loop)) {
        return Err(ParseError::new(
            loop_tok.span,
            ParseErrorKind::InvalidStatement {
                message: "LOOP statement requires LOOP keyword after END".to_string(),
            },
        ));
    }
    let end_loop_token_id = p.current_token_id();
    let loop_end = p
        .advance()
        .expect_invariant("LOOP keyword consumed after END in LOOP");
    let mut full_end = loop_end.span.end;

    // Optional label
    let mut end_label_span: Option<Span> = None;
    if let Some(lbl) = p.peek_non_trivia() {
        if p.can_be_identifier_token(lbl) {
            let ltok = p
                .advance()
                .expect_invariant("label identifier consumed after END LOOP");
            end_label_span = Some(ltok.span);
            full_end = ltok.span.end;
        }
    }

    // Capture end_span - this is the END LOOP position
    let end_span = Span {
        start: end_span_start,
        end: full_end,
    };

    // Capture semicolon token if present (don't consume - block loop will skip it)
    let semicolon_token = if let Some(tok) = p.peek_non_trivia() {
        if matches!(
            tok.kind,
            TokenKind::Punctuation(crate::lexer::Punctuation::Semi)
        ) {
            Some(p.current_token_id())
        } else {
            None
        }
    } else {
        None
    };

    // Don't consume semicolon - let outer wrapper handle it
    // Statement span ends at END LOOP, not semicolon

    let span = Span {
        start: label_span.map_or(begin_start, |ls| ls.start),
        end: full_end,
    };

    Ok(AstStmt::Loop(Box::new(AstLoopStmt {
        node_id: p.id_gen.next(),
        span,
        label_span,
        end_label_span,
        loop_span,
        loop_token: Some(loop_token_id),
        body,
        end_span: Some(end_span),
        end_token: Some(end_token_id),
        end_loop_token: Some(end_loop_token_id),
        semicolon_token,
    })))
}

pub(crate) fn try_parse_loop_control_stmt_in_block(p: &mut Parser<'_>) -> ParseResult<AstStmt> {
    // Capture token ID before advance
    let ctrl_token_id = p.current_token_id();
    let ctrl_tok = p.advance().ok_or_else(|| {
        ParseError::new(
            p.current_span(),
            ParseErrorKind::InvalidStatement {
                message: "Expected loop control statement (BREAK, EXIT, CONTINUE)".to_string(),
            },
        )
    })?;

    let mut end = ctrl_tok.span.end;

    // Optional label identifier
    if let Some(label_tok) = p.peek_non_trivia() {
        if p.can_be_identifier_token(label_tok) {
            let lbl = p
                .advance()
                .expect_invariant("label identifier consumed in loop control statement");
            end = lbl.span.end;
        }
    }

    // Peek at semicolon to save token ID, but don't consume it
    // Let outer wrapper handle consumption
    let semicolon_token = if let Some(semi_tok) = p.peek_non_trivia() {
        if matches!(semi_tok.kind, TokenKind::Punctuation(Punctuation::Semi)) {
            let semi_id = p.current_token_id();
            end = semi_tok.span.end;
            Some(semi_id)
        } else {
            None
        }
    } else {
        None
    };

    let span = Span {
        start: ctrl_tok.span.start,
        end,
    };

    let stmt = match ctrl_tok.kind {
        TokenKind::Keyword(Keyword::Break) | TokenKind::Keyword(Keyword::Exit) => AstStmt::Break {
            node_id: p.id_gen.next(),
            span,
            break_span: ctrl_tok.span,
            break_token: Some(ctrl_token_id),
            label_token: None,
            semicolon_token,
        },
        TokenKind::Keyword(Keyword::Continue) => AstStmt::Continue {
            node_id: p.id_gen.next(),
            span,
            continue_span: ctrl_tok.span,
            continue_token: Some(ctrl_token_id),
            label_token: None,
            semicolon_token,
        },
        _ => {
            return Err(ParseError::new(
                ctrl_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: format!(
                        "Expected BREAK, EXIT, or CONTINUE, found {}",
                        Parser::token_description(ctrl_tok, p.source)
                    ),
                },
            ));
        }
    };

    Ok(stmt)
}

pub(crate) fn parse_shallow_assign_stmt(p: &mut Parser<'_>, first_tok: Token) -> AstStmt {
    let name_span = first_tok.span;
    let start = first_tok.span.start;
    let mut rhs_start: Option<u32> = None;
    let mut rhs_end: Option<u32> = None;
    let mut end = first_tok.span.end;
    let mut found_colon_eq = false;
    let mut assign_op_span: Option<Span> = None;

    loop {
        p.skip_trivia();
        let next_opt = p.peek_non_trivia();
        let next = match next_opt {
            Some(t) => t,
            None => break,
        };
        match &next.kind {
            TokenKind::Punctuation(crate::lexer::Punctuation::Semi) => {
                // Don't consume semicolon - stop before it
                break;
            }
            TokenKind::Keyword(Keyword::End) | TokenKind::Eof => break,
            _ => {
                let t2 = p
                    .advance()
                    .expect_invariant("assignment RHS token consumed after peek");
                if rhs_start.is_none() {
                    if matches!(
                        t2.kind,
                        TokenKind::Operator(crate::lexer::Operator::ColonEq)
                            | TokenKind::Operator(crate::lexer::Operator::Eq)
                    ) {
                        found_colon_eq = true;
                        assign_op_span = Some(t2.span);
                        if let Some(peek_rhs) = p.peek_non_trivia() {
                            rhs_start = Some(peek_rhs.span.start);
                        }
                    } else {
                        rhs_start = Some(t2.span.start);
                    }
                }
                rhs_end = Some(t2.span.end);
                end = t2.span.end;
            }
        }
    }
    let span = Span { start, end };
    let expr_span = match (rhs_start, rhs_end) {
        (Some(s), Some(e)) if e > s => Span { start: s, end: e },
        _ => Span {
            start: name_span.end,
            end: name_span.end,
        },
    };

    // Parse the expression if we found := and have an expression span
    let expr = if found_colon_eq && expr_span.end > expr_span.start {
        let saved_idx = p.idx;
        // Find the token position after :=
        let mut expr_start_idx = None;
        for (i, tok) in p.tokens.iter().enumerate() {
            if tok.span.start >= expr_span.start {
                expr_start_idx = Some(i);
                break;
            }
        }

        if let Some(idx) = expr_start_idx {
            p.idx = idx;
            let parsed_expr = try_parse_expr_scripting(p).ok();
            p.idx = saved_idx;
            parsed_expr
        } else {
            None
        }
    } else {
        None
    };

    // Create default expression if parsing failed
    let expr = expr.unwrap_or(AstExpr::Literal {
        node_id: p.id_gen.next(),
        literal: crate::ast::AstLiteral::Null { span: expr_span },
    });

    // Capture semicolon if present (don't consume - block loop will skip it)
    let semicolon_token = if let Some(tok) = p.peek_non_trivia() {
        if matches!(
            tok.kind,
            TokenKind::Punctuation(crate::lexer::Punctuation::Semi)
        ) {
            Some(p.current_token_id())
        } else {
            None
        }
    } else {
        None
    };

    AstStmt::Assign {
        node_id: p.id_gen.next(),
        semicolon_token,
        span,
        name_span,
        assign_op_span,
        expr: Box::new(expr),
        expr_span,
    }
}

pub(crate) fn try_parse_declare_stmt(p: &mut Parser<'_>) -> ParseResult<AstStmt> {
    // For the first DECLARE in a header we consume the DECLARE keyword
    // before calling this helper; for subsequent header lines that start
    // with a bare identifier (w/x/y pattern), we also reuse this helper
    // but do not expect a DECLARE keyword. Detect this based on the
    // current lookahead.
    let start_tok = p.peek().ok_or_else(|| {
        ParseError::new(
            p.current_span(),
            ParseErrorKind::InvalidStatement {
                message: "Expected DECLARE statement".to_string(),
            },
        )
    })?;
    let (start, declare_span, declare_token_id, name_tok) = match &start_tok.kind {
        TokenKind::Keyword(Keyword::Declare) => {
            // Capture DECLARE token ID before advance
            let declare_token_id = Some(p.current_token_id());
            let kw = p.advance().ok_or_else(|| {
                ParseError::new(
                    p.current_span(),
                    ParseErrorKind::InvalidStatement {
                        message: "Expected DECLARE keyword".to_string(),
                    },
                )
            })?; // DECLARE
            let name_tok = p.advance().ok_or_else(|| {
                ParseError::new(
                    p.current_span(),
                    ParseErrorKind::InvalidStatement {
                        message: "Expected identifier after DECLARE".to_string(),
                    },
                )
            })?;
            (kw.span.start, Some(kw.span), declare_token_id, name_tok)
        }
        _ if p.can_be_identifier_token(start_tok) => {
            let name_tok = p.advance().ok_or_else(|| {
                ParseError::new(
                    p.current_span(),
                    ParseErrorKind::InvalidStatement {
                        message: "Expected identifier in DECLARE".to_string(),
                    },
                )
            })?;
            (start_tok.span.start, None, None, name_tok)
        }
        _ => {
            return Err(ParseError::new(
                start_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: format!(
                        "Expected DECLARE keyword or identifier, found {}",
                        Parser::token_description(start_tok, p.source)
                    ),
                },
            ));
        }
    };
    let name = match &name_tok.kind {
        _ if p.can_be_identifier_token(name_tok) => AstIdentifier {
            node_id: p.id_gen.next(),
            span: name_tok.span,
        },
        _ => {
            return Err(ParseError::new(
                name_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: format!(
                        "Expected identifier for DECLARE name, found {}",
                        Parser::token_description(name_tok, p.source)
                    ),
                },
            ));
        }
    };

    // Check for Databricks DECLARE ... HANDLER FOR ... statement
    // Pattern: DECLARE EXIT|CONTINUE HANDLER FOR condition_value [,...] statement
    // Here, name_tok is EXIT or CONTINUE keyword
    if matches!(
        name_tok.kind,
        TokenKind::Keyword(Keyword::Exit) | TokenKind::Keyword(Keyword::Continue)
    ) {
        if let Some(handler_tok) = p.peek_non_trivia() {
            if handler_tok.lexeme(p.source).eq_ignore_ascii_case("HANDLER") {
                let handler_type = if matches!(name_tok.kind, TokenKind::Keyword(Keyword::Exit)) {
                    ExceptionHandlerType::Exit
                } else {
                    ExceptionHandlerType::Continue
                };
                return try_parse_declare_handler_body(
                    p,
                    start,
                    declare_span,
                    handler_type,
                    name_tok.span,
                );
            }
        }
    }

    // Check for Databricks DECLARE condition_name CONDITION FOR SQLSTATE ...
    if let Some(cond_tok) = p.peek_non_trivia() {
        if cond_tok.lexeme(p.source).eq_ignore_ascii_case("CONDITION") {
            return try_parse_declare_condition_body(p, start, declare_span, name.span);
        }
    }

    // Check if this is a cursor declaration: DECLARE name CURSOR FOR ...
    if let Some(cursor_tok) = p.peek_non_trivia() {
        if matches!(cursor_tok.kind, TokenKind::Keyword(Keyword::Cursor)) {
            let cursor_token_id = p.current_token_id();
            let _ = p.advance(); // consume CURSOR

            // Expect FOR keyword
            if let Some(for_tok) = p.peek_non_trivia() {
                if matches!(for_tok.kind, TokenKind::Keyword(Keyword::For)) {
                    let for_token_id = p.current_token_id();
                    let _ = p.advance(); // consume FOR

                    // Parse the query - can be SELECT statement or RESULTSET identifier reference
                    p.skip_trivia();
                    let next_tok = p.peek_non_trivia().ok_or_else(|| {
                        ParseError::new(
                            p.current_span(),
                            ParseErrorKind::InvalidStatement {
                                message: "Expected SELECT or RESULTSET identifier after CURSOR FOR"
                                    .to_string(),
                            },
                        )
                    })?;

                    // Determine if this is a query (SELECT/WITH) or a RESULTSET identifier reference.
                    // Must check for SELECT/WITH explicitly because some dialects (Databricks)
                    // treat all keywords as valid identifiers via can_be_identifier_token.
                    let is_query = matches!(
                        next_tok.kind,
                        TokenKind::Keyword(Keyword::Select)
                            | TokenKind::Keyword(Keyword::With)
                            | TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
                    );
                    let query_stmt = if !is_query && p.can_be_identifier_token(next_tok) {
                        // RESULTSET identifier reference - capture as a simple statement
                        let id_tok = p
                            .advance()
                            .expect_invariant("RESULTSET identifier consumed after peek in CURSOR");
                        let query_span = id_tok.span;

                        // Create a simple identifier reference statement
                        // We'll use a NULL statement as a placeholder since we just need the span
                        AstStmt::Null {
                            node_id: p.id_gen.next(),
                            span: query_span,
                            null_span: query_span,
                            null_token: None,
                            semicolon_token: None,
                        }
                    } else {
                        // Regular SELECT statement
                        p.parse_statement()?
                    };

                    let query_span = query_stmt.span();
                    let mut end = query_span.end;

                    // Consume optional cursor sensitivity clause: FOR READ ONLY / FOR UPDATE
                    // The SELECT parser handles FOR UPDATE but not FOR READ ONLY,
                    // so we must handle it here to prevent the block body parser
                    // from misinterpreting it as a FOR loop.
                    let mut cursor_sensitivity_span: Option<Span> = None;
                    p.skip_trivia();
                    if let Some(for2) = p.peek_non_trivia() {
                        if matches!(for2.kind, TokenKind::Keyword(Keyword::For)) {
                            let saved = p.idx;
                            let for2_tok = p.advance().expect_invariant("FOR consumed");
                            let cs_start = for2_tok.span.start;
                            p.skip_trivia();
                            if let Some(next) = p.peek_non_trivia() {
                                let lex = next.lexeme(p.source);
                                if lex.eq_ignore_ascii_case("READ") {
                                    // FOR READ ONLY
                                    let _read = p.advance().expect_invariant("READ consumed");
                                    p.skip_trivia();
                                    if let Some(only_tok) = p.peek_non_trivia() {
                                        if matches!(
                                            only_tok.kind,
                                            TokenKind::Keyword(Keyword::Only)
                                        ) {
                                            let only =
                                                p.advance().expect_invariant("ONLY consumed");
                                            end = only.span.end;
                                            cursor_sensitivity_span = Some(Span {
                                                start: cs_start,
                                                end: only.span.end,
                                            });
                                        }
                                    }
                                } else if matches!(next.kind, TokenKind::Keyword(Keyword::Update)) {
                                    // FOR UPDATE (not already consumed by SELECT parser)
                                    let upd = p.advance().expect_invariant("UPDATE consumed");
                                    end = upd.span.end;
                                    cursor_sensitivity_span = Some(Span {
                                        start: cs_start,
                                        end: upd.span.end,
                                    });
                                } else {
                                    // Not a cursor clause — restore position
                                    p.idx = saved;
                                }
                            } else {
                                p.idx = saved;
                            }
                        }
                    }

                    // Capture semicolon if present (don't consume - block loop will skip it)
                    let semicolon_token = if let Some(tok) = p.peek_non_trivia() {
                        if matches!(
                            tok.kind,
                            TokenKind::Punctuation(crate::lexer::Punctuation::Semi)
                        ) {
                            Some(p.current_token_id())
                        } else {
                            None
                        }
                    } else {
                        None
                    };

                    return Ok(AstStmt::DeclareCursor {
                        node_id: p.id_gen.next(),
                        semicolon_token,
                        span: Span { start, end },
                        declare_span: declare_span.unwrap_or(Span { start, end: start }),
                        declare_token: declare_token_id,
                        cursor_name: name,
                        cursor_token: Some(cursor_token_id),
                        for_token: Some(for_token_id),
                        query: Box::new(query_stmt),
                        query_span,
                        cursor_sensitivity_span,
                    });
                }
            }
        }
    }

    // Check if this is a table variable: DECLARE @t TABLE(...)
    if let Some(table_tok) = p.peek_non_trivia() {
        if matches!(table_tok.kind, TokenKind::Keyword(Keyword::Table)) {
            let table_kw_token = p
                .advance()
                .expect_invariant("TABLE keyword consumed after peek");
            let table_keyword_span = table_kw_token.span;

            // Expect opening paren
            let lparen_tok = p.peek_non_trivia().ok_or_else(|| {
                ParseError::new(
                    p.current_span(),
                    ParseErrorKind::InvalidStatement {
                        message: "Expected '(' after TABLE in table variable declaration"
                            .to_string(),
                    },
                )
            })?;
            if !matches!(
                lparen_tok.kind,
                TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
            ) {
                return Err(ParseError::new(
                    lparen_tok.span,
                    ParseErrorKind::InvalidStatement {
                        message: format!(
                            "Expected '(' after TABLE, found {}",
                            Parser::token_description(lparen_tok, p.source)
                        ),
                    },
                ));
            }
            let lparen = p.advance().expect_invariant("LParen consumed after peek");
            let body_start = lparen.span.start;

            // Consume balanced parentheses until matching RParen
            let mut depth: u32 = 1;
            while depth > 0 {
                let tok = p.advance().ok_or_else(|| {
                    ParseError::new(
                        p.current_span(),
                        ParseErrorKind::InvalidStatement {
                            message: "Unterminated table variable definition — missing ')'"
                                .to_string(),
                        },
                    )
                })?;
                match tok.kind {
                    TokenKind::Punctuation(crate::lexer::Punctuation::LParen) => depth += 1,
                    TokenKind::Punctuation(crate::lexer::Punctuation::RParen) => depth -= 1,
                    TokenKind::Eof => {
                        return Err(ParseError::new(
                            tok.span,
                            ParseErrorKind::InvalidStatement {
                                message: "Unexpected end of input in table variable definition"
                                    .to_string(),
                            },
                        ));
                    }
                    _ => {}
                }
            }
            // p.idx now points past the closing RParen
            let rparen_span = p.tokens[p.idx - 1].span;
            let table_body_span = Span {
                start: body_start,
                end: rparen_span.end,
            };

            let end = rparen_span.end;

            // Capture semicolon if present (don't consume)
            let semicolon_token = if let Some(tok) = p.peek_non_trivia() {
                if matches!(
                    tok.kind,
                    TokenKind::Punctuation(crate::lexer::Punctuation::Semi)
                ) {
                    Some(p.current_token_id())
                } else {
                    None
                }
            } else {
                None
            };

            return Ok(AstStmt::DeclareTable {
                node_id: p.id_gen.next(),
                semicolon_token,
                span: Span { start, end },
                declare_span,
                declare_token: declare_token_id,
                name,
                table_keyword_span,
                table_body_span,
            });
        }
    }

    let mut type_span: Option<Span> = None;
    let mut default_expr_span: Option<Span> = None;

    // Parse type and optional default value/initializer
    // Syntax: <type> [DEFAULT expr | := expr]
    let mut default_expr: Option<AstExpr> = None;

    // Scan ahead to find if there's a DEFAULT or := initializer
    let tail_start_idx = p.idx;
    let mut has_default = false;
    let mut default_keyword_idx = None;
    // T-SQL spells DECLARE init with bare `=` (`DECLARE @x INT = 5`).
    // Snowflake/BigQuery/PG/MySQL/Databricks use `DEFAULT` or `:=`, so
    // recognizing `=` is gated to the MSSQL dialect to avoid colliding
    // with comparison operators inside non-MSSQL type expressions.
    let mssql_eq_is_init = p.dialect.declare_uses_equals_initializer();

    // First pass: scan to find DEFAULT or := and the semicolon
    let mut scan_idx = p.idx;
    while scan_idx < p.tokens.len() {
        let t = &p.tokens[scan_idx];
        match t.kind {
            TokenKind::Punctuation(crate::lexer::Punctuation::Semi) | TokenKind::Eof => break,
            _ => {
                if t.lexeme(p.source).eq_ignore_ascii_case("DEFAULT") {
                    has_default = true;
                    default_keyword_idx = Some(scan_idx);
                    break;
                }
                if let TokenKind::Operator(crate::lexer::Operator::ColonEq) = t.kind {
                    has_default = true;
                    default_keyword_idx = Some(scan_idx);
                    break;
                }
                if mssql_eq_is_init
                    && matches!(t.kind, TokenKind::Operator(crate::lexer::Operator::Eq))
                {
                    has_default = true;
                    default_keyword_idx = Some(scan_idx);
                    break;
                }
                scan_idx += 1;
            }
        }
    }

    // Parse the type (everything before DEFAULT/:= or semicolon)
    // Track the span of DEFAULT or := operator
    let mut default_op_span: Option<Span> = None;
    let mut default_op_token_id = None;

    if has_default {
        if let Some(init_idx) = default_keyword_idx {
            // Type is everything from current position to before DEFAULT/:=
            if init_idx > tail_start_idx {
                let first = &p.tokens[tail_start_idx];
                let last_before_init = &p.tokens[init_idx - 1];
                type_span = Some(Span {
                    start: first.span.start,
                    end: last_before_init.span.end,
                });
                // Advance parser to the type end
                p.idx = init_idx;
            }

            // Capture span and token ID of DEFAULT or := operator
            let op_token = &p.tokens[p.idx];
            default_op_span = Some(op_token.span);
            default_op_token_id = Some(p.current_token_id());

            // Consume DEFAULT or :=
            let default_start = p.tokens[p.idx].span.start;
            p.advance(); // Skip DEFAULT or :=

            // Now parse the default expression until semicolon
            default_expr = try_parse_expr_scripting(p).ok();

            // Set default_expr_span to cover DEFAULT/:= through the parsed expression
            if let Some(ref expr) = default_expr {
                default_expr_span = Some(Span {
                    start: default_start,
                    end: expr.span().end,
                });
            }
        }
    } else {
        // No DEFAULT - parse type until semicolon
        let type_start_idx = p.idx;
        while let Some(tok) = p.peek() {
            match tok.kind {
                TokenKind::Punctuation(crate::lexer::Punctuation::Semi) | TokenKind::Eof => break,
                _ => {
                    let _ = p.advance();
                }
            }
        }
        if p.idx > type_start_idx {
            let first = &p.tokens[type_start_idx];
            let last = &p.tokens[p.idx - 1];
            type_span = Some(Span {
                start: first.span.start,
                end: last.span.end,
            });
        }
    }

    // Span ends at last parsed token (default expr, type, or name)
    let end = if let Some(ref expr) = default_expr {
        expr.span().end
    } else if let Some(ref ts) = type_span {
        ts.end
    } else {
        name.span.end
    };

    // Capture semicolon if present (don't consume - block loop will skip it)
    let semicolon_token = if let Some(tok) = p.peek_non_trivia() {
        if matches!(
            tok.kind,
            TokenKind::Punctuation(crate::lexer::Punctuation::Semi)
        ) {
            Some(p.current_token_id())
        } else {
            None
        }
    } else {
        None
    };

    Ok(AstStmt::Declare {
        node_id: p.id_gen.next(),
        semicolon_token,
        span: Span { start, end },
        declare_span,
        declare_token: declare_token_id,
        name,
        type_span,
        default_op_span,
        default_op_token: default_op_token_id,
        default_expr: default_expr.map(Box::new),
        default_expr_span,
    })
}

pub(crate) fn try_parse_open_cursor_stmt(p: &mut Parser<'_>) -> ParseResult<AstStmt> {
    // Parse: OPEN cursor_name [ USING (bind_param1, bind_param2, ...) ];
    let open_kw = p.advance().ok_or_else(|| {
        ParseError::new(
            p.current_span(),
            ParseErrorKind::InvalidStatement {
                message: "Expected OPEN keyword".to_string(),
            },
        )
    })?;

    if !matches!(open_kw.kind, TokenKind::Keyword(Keyword::Open)) {
        return Err(ParseError::new(
            open_kw.span,
            ParseErrorKind::InvalidStatement {
                message: format!(
                    "Expected OPEN keyword, found {}",
                    Parser::token_description(open_kw, p.source)
                ),
            },
        ));
    }

    // Parse cursor name
    let cursor_tok = p.advance().ok_or_else(|| {
        ParseError::new(
            p.current_span(),
            ParseErrorKind::InvalidStatement {
                message: "OPEN requires cursor name".to_string(),
            },
        )
    })?;
    let cursor_name_span = match &cursor_tok.kind {
        TokenKind::Identifier { .. } => cursor_tok.span,
        _ => {
            return Err(ParseError::new(
                cursor_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: format!(
                        "OPEN requires cursor name identifier, found {}",
                        Parser::token_description(cursor_tok, p.source)
                    ),
                },
            ));
        }
    };
    let mut end = cursor_name_span.end;

    // Optional USING clause
    let mut using_clause_span = None;
    if let Some(tok) = p.peek_non_trivia() {
        if matches!(tok.kind, TokenKind::Keyword(Keyword::Using)) {
            let using_kw = p
                .advance()
                .expect_invariant("USING keyword consumed after match in OPEN cursor");
            let using_start = using_kw.span.start;

            // Expect opening parenthesis
            let lparen_tok = p.advance().ok_or_else(|| {
                ParseError::new(
                    p.current_span(),
                    ParseErrorKind::InvalidStatement {
                        message: "USING clause requires opening parenthesis '('".to_string(),
                    },
                )
            })?;
            if !matches!(
                lparen_tok.kind,
                TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
            ) {
                return Err(ParseError::new(
                    lparen_tok.span,
                    ParseErrorKind::InvalidStatement {
                        message: format!(
                            "USING clause requires opening parenthesis '(', found {}",
                            Parser::token_description(lparen_tok, p.source)
                        ),
                    },
                ));
            }

            // Parse bind parameters until closing paren
            let mut paren_end = lparen_tok.span.end;
            loop {
                p.skip_trivia();
                let tok = match p.peek_non_trivia() {
                    Some(t) => t,
                    None => break,
                };

                match &tok.kind {
                    TokenKind::Punctuation(crate::lexer::Punctuation::RParen) => {
                        let rparen = p
                            .advance()
                            .expect_invariant("')' consumed after match in USING clause");
                        paren_end = rparen.span.end;
                        break;
                    }
                    TokenKind::Punctuation(crate::lexer::Punctuation::Comma) => {
                        let _ = p.advance();
                        continue;
                    }
                    _ => {
                        // Parse expression for bind parameter
                        let expr = try_parse_expr_scripting(p).map_err(|_| {
                            ParseError::invalid_expression(
                                p.current_span(),
                                "USING clause requires valid expression".to_string(),
                            )
                        })?;
                        paren_end = expr_span_end(&expr);
                    }
                }
            }

            using_clause_span = Some(Span {
                start: using_start,
                end: paren_end,
            });
            end = paren_end;
        }
    }

    // Peek at semicolon to save token ID, but don't consume it
    let semicolon_token = if let Some(semi_tok) = p.peek_non_trivia() {
        if matches!(semi_tok.kind, TokenKind::Punctuation(Punctuation::Semi)) {
            let semi_id = p.current_token_id();
            end = semi_tok.span.end;
            Some(semi_id)
        } else {
            None
        }
    } else {
        None
    };

    let span = Span {
        start: open_kw.span.start,
        end,
    };
    Ok(AstStmt::OpenCursor {
        node_id: p.id_gen.next(),
        span,
        open_span: open_kw.span,
        cursor_name_span,
        using_clause_span,
        semicolon_token,
    })
}

pub(crate) fn try_parse_fetch_cursor_stmt(p: &mut Parser<'_>) -> ParseResult<AstStmt> {
    // Parse: FETCH cursor_name INTO var1, var2, ...;
    let fetch_kw = p.advance().ok_or_else(|| {
        ParseError::new(
            p.current_span(),
            ParseErrorKind::InvalidStatement {
                message: "Expected FETCH keyword".to_string(),
            },
        )
    })?;

    if !matches!(fetch_kw.kind, TokenKind::Keyword(Keyword::Fetch)) {
        return Err(ParseError::new(
            fetch_kw.span,
            ParseErrorKind::InvalidStatement {
                message: format!(
                    "Expected FETCH keyword, found {}",
                    Parser::token_description(fetch_kw, p.source)
                ),
            },
        ));
    }

    // Parse cursor name
    let cursor_tok = p.advance().ok_or_else(|| {
        ParseError::new(
            p.current_span(),
            ParseErrorKind::InvalidStatement {
                message: "FETCH requires cursor name".to_string(),
            },
        )
    })?;
    let cursor_name_span = match &cursor_tok.kind {
        TokenKind::Identifier { .. } => cursor_tok.span,
        _ => {
            return Err(ParseError::new(
                cursor_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: format!(
                        "FETCH requires cursor name identifier, found {}",
                        Parser::token_description(cursor_tok, p.source)
                    ),
                },
            ));
        }
    };

    // Parse required INTO keyword
    let into_tok = p.advance().ok_or_else(|| {
        ParseError::new(
            p.current_span(),
            ParseErrorKind::InvalidStatement {
                message: "FETCH requires INTO clause".to_string(),
            },
        )
    })?;
    if !matches!(into_tok.kind, TokenKind::Keyword(Keyword::Into)) {
        return Err(ParseError::new(
            into_tok.span,
            ParseErrorKind::InvalidStatement {
                message: format!(
                    "FETCH requires INTO keyword, found {}",
                    Parser::token_description(into_tok, p.source)
                ),
            },
        ));
    }
    let into_start = into_tok.span.start;

    // Parse variable list (comma-separated identifiers)
    let mut into_end = into_tok.span.end;
    let mut into_targets: Vec<crate::ast::AstIdentifier> = Vec::new();
    loop {
        p.skip_trivia();
        let tok = match p.peek_non_trivia() {
            Some(t) => t,
            None => break,
        };

        match &tok.kind {
            TokenKind::Identifier { .. } => {
                let var_tok = p
                    .advance()
                    .expect_invariant("variable identifier consumed in FETCH INTO clause");
                into_end = var_tok.span.end;
                into_targets.push(crate::ast::AstIdentifier {
                    node_id: p.id_gen.next(),
                    span: var_tok.span,
                });
            }
            TokenKind::Punctuation(crate::lexer::Punctuation::Comma) => {
                let _ = p.advance();
                continue;
            }
            TokenKind::Punctuation(crate::lexer::Punctuation::Semi) => {
                // Don't consume semicolon - let outer loop handle it
                // Don't update into_end to exclude semicolon from into_clause_span
                break;
            }
            _ => break,
        }
    }

    // Peek at semicolon to save token ID, but don't consume it
    let mut end = into_end;
    let semicolon_token = if let Some(semi_tok) = p.peek_non_trivia() {
        if matches!(semi_tok.kind, TokenKind::Punctuation(Punctuation::Semi)) {
            let semi_id = p.current_token_id();
            end = semi_tok.span.end;
            Some(semi_id)
        } else {
            None
        }
    } else {
        None
    };

    let span = Span {
        start: fetch_kw.span.start,
        end,
    };
    let into_clause_span = Span {
        start: into_start,
        end: into_end,
    };
    Ok(AstStmt::FetchCursor {
        node_id: p.id_gen.next(),
        span,
        fetch_span: fetch_kw.span,
        cursor_name_span,
        into_clause_span,
        into_targets,
        semicolon_token,
    })
}

pub(crate) fn try_parse_close_cursor_stmt(p: &mut Parser<'_>) -> ParseResult<AstStmt> {
    // Parse: CLOSE cursor_name;
    let close_kw = p.advance().ok_or_else(|| {
        ParseError::new(
            p.current_span(),
            ParseErrorKind::InvalidStatement {
                message: "Expected CLOSE keyword".to_string(),
            },
        )
    })?;

    if !matches!(close_kw.kind, TokenKind::Keyword(Keyword::Close)) {
        return Err(ParseError::new(
            close_kw.span,
            ParseErrorKind::InvalidStatement {
                message: format!(
                    "Expected CLOSE keyword, found {}",
                    Parser::token_description(close_kw, p.source)
                ),
            },
        ));
    }

    // Parse cursor name
    let cursor_tok = p.advance().ok_or_else(|| {
        ParseError::new(
            p.current_span(),
            ParseErrorKind::InvalidStatement {
                message: "CLOSE requires cursor name".to_string(),
            },
        )
    })?;
    let cursor_name_span = match &cursor_tok.kind {
        TokenKind::Identifier { .. } => cursor_tok.span,
        _ => {
            return Err(ParseError::new(
                cursor_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: format!(
                        "CLOSE requires cursor name identifier, found {}",
                        Parser::token_description(cursor_tok, p.source)
                    ),
                },
            ));
        }
    };
    let mut end = cursor_name_span.end;

    // Peek at semicolon to save token ID, but don't consume it
    let semicolon_token = if let Some(semi_tok) = p.peek_non_trivia() {
        if matches!(semi_tok.kind, TokenKind::Punctuation(Punctuation::Semi)) {
            let semi_id = p.current_token_id();
            end = semi_tok.span.end;
            Some(semi_id)
        } else {
            None
        }
    } else {
        None
    };

    let span = Span {
        start: close_kw.span.start,
        end,
    };
    Ok(AstStmt::CloseCursor {
        node_id: p.id_gen.next(),
        span,
        close_span: close_kw.span,
        cursor_name_span,
        semicolon_token,
    })
}

pub(crate) fn try_parse_await_stmt(p: &mut Parser<'_>) -> ParseResult<AstStmt> {
    // Parse: AWAIT <expr>;
    let await_kw = p.advance().ok_or_else(|| {
        ParseError::new(
            p.current_span(),
            ParseErrorKind::InvalidStatement {
                message: "Expected AWAIT keyword".to_string(),
            },
        )
    })?;

    if !matches!(await_kw.kind, TokenKind::Keyword(Keyword::Await)) {
        return Err(ParseError::new(
            await_kw.span,
            ParseErrorKind::InvalidStatement {
                message: format!(
                    "Expected AWAIT keyword, found {}",
                    Parser::token_description(await_kw, p.source)
                ),
            },
        ));
    }

    let first_expr_tok = p.peek_non_trivia().ok_or_else(|| {
        ParseError::new(
            p.current_span(),
            ParseErrorKind::InvalidStatement {
                message: "AWAIT requires job identifier expression".to_string(),
            },
        )
    })?;
    let expr_start = first_expr_tok.span.start;

    // Collect tokens until we hit semicolon or end of input
    let mut expr_end = expr_start;
    while let Some(tok) = p.peek_non_trivia() {
        if matches!(
            tok.kind,
            TokenKind::Punctuation(crate::lexer::Punctuation::Semi)
        ) {
            break;
        }
        expr_end = tok.span.end;
        p.advance();
    }

    let job_id_expr_span = Span {
        start: expr_start,
        end: expr_end,
    };
    let end = expr_end;

    // Don't consume semicolon - let outer wrapper handle it
    // Statement span ends at job identifier expression, not semicolon

    let span = Span {
        start: await_kw.span.start,
        end,
    };
    Ok(AstStmt::Await {
        node_id: p.id_gen.next(),
        span,
        job_id_expr_span,
    })
}

pub(crate) fn try_parse_cancel_stmt(p: &mut Parser<'_>) -> ParseResult<AstStmt> {
    // Parse: CANCEL <expr>;
    let cancel_kw = p.advance().ok_or_else(|| {
        ParseError::new(
            p.current_span(),
            ParseErrorKind::InvalidStatement {
                message: "Expected CANCEL keyword".to_string(),
            },
        )
    })?;

    if !matches!(cancel_kw.kind, TokenKind::Keyword(Keyword::Cancel)) {
        return Err(ParseError::new(
            cancel_kw.span,
            ParseErrorKind::InvalidStatement {
                message: format!(
                    "Expected CANCEL keyword, found {}",
                    Parser::token_description(cancel_kw, p.source)
                ),
            },
        ));
    }

    let first_expr_tok = p.peek_non_trivia().ok_or_else(|| {
        ParseError::new(
            p.current_span(),
            ParseErrorKind::InvalidStatement {
                message: "CANCEL requires job identifier expression".to_string(),
            },
        )
    })?;
    let expr_start = first_expr_tok.span.start;

    // Collect tokens until we hit semicolon or end of input
    let mut expr_end = expr_start;
    while let Some(tok) = p.peek_non_trivia() {
        if matches!(
            tok.kind,
            TokenKind::Punctuation(crate::lexer::Punctuation::Semi)
        ) {
            break;
        }
        expr_end = tok.span.end;
        p.advance();
    }

    let job_id_expr_span = Span {
        start: expr_start,
        end: expr_end,
    };
    let end = expr_end;

    // Don't consume semicolon - let outer wrapper handle it
    // Statement span ends at job identifier expression, not semicolon

    let span = Span {
        start: cancel_kw.span.start,
        end,
    };
    Ok(AstStmt::Cancel {
        node_id: p.id_gen.next(),
        span,
        job_id_expr_span,
    })
}

/// Outcome of sub-parsing a dollar-quoted routine / anonymous block body.
pub(crate) struct DollarBlockBody {
    /// The parsed `BEGIN … END` / `DECLARE … END` block, if the content parsed
    /// as a scripting block. `None` when the body was opaque (non-block content
    /// or a parse failure) — callers fall back to span-only handling.
    pub body_stmt: Option<Box<AstStmt>>,
    /// CST token of the closing delimiter, if found.
    pub closing_delimiter_token: Option<crate::cst::TokenId>,
    /// End offset of the body content (excludes the closing delimiter).
    pub body_end: u32,
    /// End offset including the closing delimiter (== `body_end` if no closer).
    pub delimiter_end: u32,
}

/// Sub-parse the body of a dollar-quoted block (`$$ … $$` / `$tag$ … $tag$`).
///
/// PRECONDITION: the opening delimiter has just been consumed; the parser is
/// positioned at the first body token. `open_tag_lo`/`open_tag_hi` bound the
/// opener's lexeme so the matching closer (same lexeme) can be located, and
/// `body_content_start` is the offset just after the opener.
///
/// Parses a `BEGIN … END` / `DECLARE … END` body into a statement (for
/// analysis), skips the optional `;` after `END`, then consumes the matching
/// close delimiter. On non-block content or a parse failure it restores the
/// position and scans opaquely to the closer (`body_stmt = None`). Shared by
/// CREATE PROCEDURE and the anonymous `DO` block so neither reimplements the
/// dispatch (DECLARE/BEGIN → block parse → find closer).
pub(crate) fn parse_dollar_block_body(
    p: &mut Parser<'_>,
    open_tag_lo: usize,
    open_tag_hi: usize,
    body_content_start: u32,
) -> DollarBlockBody {
    use crate::error::{ExpectInvariant, ParseError, ParseErrorKind};

    let mut body_stmt: Option<Box<AstStmt>> = None;
    let mut closing_delimiter_token: Option<crate::cst::TokenId> = None;
    let mut body_end = body_content_start;
    let mut delimiter_end = body_content_start;

    if let Some(first_tok) = p.peek_non_trivia() {
        // Save parser position in case parsing fails
        let save_idx = p.idx;

        let parse_result = if matches!(first_tok.kind, TokenKind::Keyword(Keyword::Declare)) {
            try_parse_scripting_block(p)
        } else if matches!(first_tok.kind, TokenKind::Keyword(Keyword::Begin)) {
            try_parse_block_stmt(p)
        } else {
            Err(ParseError::new(
                first_tok.span,
                ParseErrorKind::InvalidSyntax {
                    message: "Expected DECLARE or BEGIN in dollar-quoted block body".to_string(),
                },
            ))
        };

        match parse_result {
            Ok(stmt) => {
                body_end = stmt.span().end;
                body_stmt = Some(Box::new(stmt));

                // Parsing succeeded - skip any semicolon after END (the block
                // parser doesn't consume it), then find+consume the closing tag.
                if let Some(tok) = p.peek_non_trivia() {
                    if matches!(
                        tok.kind,
                        TokenKind::Punctuation(crate::lexer::Punctuation::Semi)
                    ) {
                        p.advance(); // consume the semicolon after END
                    }
                }

                let mut found_closing = false;
                if let Some(tok) = p.peek_non_trivia() {
                    if tok.lexeme(p.source) == &p.source[open_tag_lo..open_tag_hi] {
                        let closing = p
                            .advance()
                            .expect_invariant("Closing delimiter should be available");
                        closing_delimiter_token = Some(p.last_token_id());
                        delimiter_end = closing.span.end;
                        found_closing = true;
                    }
                }
                // If we didn't find the closing delimiter, keep delimiter_end at
                // least at body_end to avoid span.end < body_span.end.
                if !found_closing {
                    delimiter_end = body_end;
                }
            }
            Err(_parse_err) => {
                // Parsing failed - restore position and collect tokens opaquely
                // up to and including the matching closer.
                p.idx = save_idx;

                let mut body_content_end = body_content_start;
                while let Some(_tok) = p.peek_non_trivia() {
                    let t = p
                        .advance()
                        .expect_invariant("dollar body token consumed after peek");
                    if t.lexeme(p.source) == &p.source[open_tag_lo..open_tag_hi] {
                        closing_delimiter_token = Some(p.last_token_id());
                        delimiter_end = t.span.end;
                        break;
                    }
                    body_content_end = t.span.end;
                }
                body_end = body_content_end;
            }
        }
    }

    DollarBlockBody {
        body_stmt,
        closing_delimiter_token,
        body_end,
        delimiter_end,
    }
}

/// Parse CREATE PROCEDURE statement, returning Result (for diagnostic error reporting).
pub(crate) fn try_parse_create_procedure(p: &mut Parser<'_>) -> ParseResult<AstStmt> {
    use crate::error::{ExpectInvariant, ParseError, ParseErrorKind, ParseResultExt};

    // Parse: CREATE [OR REPLACE] PROCEDURE name(params) RETURNS type LANGUAGE SQL AS body
    let create_span = p.current_span();
    let create_kw = p
        .advance()
        .ok_or_eof(create_span, vec!["CREATE".to_string()])?;
    if !matches!(create_kw.kind, TokenKind::Keyword(Keyword::Create)) {
        return Err(ParseError::new(
            create_kw.span,
            ParseErrorKind::InvalidSyntax {
                message: format!(
                    "Expected CREATE keyword, found {}",
                    Parser::token_description(create_kw, p.source)
                ),
            },
        ));
    }

    let proc_start = create_kw.span.start;
    let create_kw_span = create_kw.span;

    // Optional: OR REPLACE / OR ALTER
    let mut or_replace_span: Option<Span> = None;
    let mut or_alter_span: Option<Span> = None;
    if let Some(tok) = p.peek_non_trivia() {
        if matches!(tok.kind, TokenKind::Keyword(Keyword::Or)) {
            let or_tok = p.advance().expect_invariant("OR token should be available");
            let or_start = or_tok.span.start;
            if let Some(next_tok) = p.peek_non_trivia() {
                if matches!(next_tok.kind, TokenKind::Keyword(Keyword::Replace)) {
                    let replace = p
                        .advance()
                        .expect_invariant("REPLACE token should be available");
                    or_replace_span = Some(Span {
                        start: or_start,
                        end: replace.span.end,
                    });
                } else if matches!(next_tok.kind, TokenKind::Keyword(Keyword::Alter)) {
                    let alter = p
                        .advance()
                        .expect_invariant("ALTER token should be available");
                    or_alter_span = Some(Span {
                        start: or_start,
                        end: alter.span.end,
                    });
                }
            }
        }
    }

    // Optional MySQL `DEFINER = { user | CURRENT_USER }` clause (precedes
    // PROCEDURE). Fully parsed into the typed security-context primitive,
    // not skipped — the body runs under this account's privileges.
    let definer = p.parse_definer_clause();

    // Expect PROCEDURE keyword
    let proc_span = p.current_span();
    let proc_kw = p
        .advance()
        .ok_or_eof(proc_span, vec!["PROCEDURE".to_string()])?;
    if !matches!(proc_kw.kind, TokenKind::Keyword(Keyword::Procedure)) {
        return Err(ParseError::new(
            proc_kw.span,
            ParseErrorKind::InvalidSyntax {
                message: "Expected PROCEDURE after CREATE [OR REPLACE]".to_string(),
            },
        ));
    }
    let procedure_keyword_span = proc_kw.span;

    // Parse procedure name (identifier, potentially qualified with dots)
    let name_start_span = p.current_span();
    let name_start_tok = p
        .advance()
        .ok_or_eof(name_start_span, vec!["procedure name".to_string()])?;
    let mut name_end = name_start_tok.span.end;

    // Handle qualified names (e.g., schema.procedure or db.schema.procedure)
    while let Some(tok) = p.peek_non_trivia() {
        if matches!(
            tok.kind,
            TokenKind::Punctuation(crate::lexer::Punctuation::Dot)
        ) {
            // Consume the dot
            let _dot = p
                .advance()
                .expect_invariant("'.' consumed in qualified procedure name");

            // Expect another identifier after the dot
            let next_span = p.current_span();
            let next_tok = p
                .advance()
                .ok_or_eof(next_span, vec!["identifier after dot".to_string()])?;
            name_end = next_tok.span.end;
        } else {
            break;
        }
    }

    let name_span = Span {
        start: name_start_tok.span.start,
        end: name_end,
    };

    // Parse parameter list in parentheses (optional in MSSQL)
    let mut params_span;
    let mut params_end;
    if let Some(tok) = p.peek_non_trivia() {
        if matches!(
            tok.kind,
            TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
        ) {
            let lparen = p.advance().expect_invariant("( confirmed by peek");
            let params_start = lparen.span.start;
            params_end = lparen.span.end;

            // Collect tokens until closing parenthesis
            let mut paren_depth = 1;
            while paren_depth > 0 {
                let current_span = Span {
                    start: params_end,
                    end: params_end,
                };
                let tok = p
                    .advance()
                    .ok_or_eof(current_span, vec![") to close parameter list".to_string()])?;
                params_end = tok.span.end;
                match tok.kind {
                    TokenKind::Punctuation(crate::lexer::Punctuation::LParen) => paren_depth += 1,
                    TokenKind::Punctuation(crate::lexer::Punctuation::RParen) => paren_depth -= 1,
                    _ => {}
                }
            }
            params_span = Span {
                start: params_start,
                end: params_end,
            };
        } else {
            // No parenthesized parameter list (MSSQL style).
            // Params may appear unparenthesized before AS — they'll be consumed
            // by the "skip until RETURNS/LANGUAGE/AS" loop below.
            params_end = name_end;
            params_span = Span {
                start: name_end,
                end: name_end,
            };
        }
    } else {
        params_end = name_end;
        params_span = Span {
            start: name_end,
            end: name_end,
        };
    }

    // Optional: COPY GRANTS, NOT NULL, and other clauses before RETURNS.
    // For T-SQL unparenthesized params (`@x TYPE, @y TYPE` between
    // proc name and AS), this loop consumes them — track the end so
    // the params_span covers the parameter text, so the typed
    // parameter list can be parsed from it.
    let was_parenthesized = params_span.end > params_span.start;
    while let Some(tok) = p.peek_non_trivia() {
        if matches!(
            tok.kind,
            TokenKind::Keyword(Keyword::Returns)
                | TokenKind::Keyword(Keyword::Language)
                | TokenKind::Keyword(Keyword::As)
                | TokenKind::Keyword(Keyword::Begin)
                | TokenKind::Keyword(Keyword::Declare)
        ) {
            break;
        }
        if let Some(consumed) = p.advance() {
            if !was_parenthesized {
                params_end = consumed.span.end;
            }
        }
    }
    if !was_parenthesized && params_end > params_span.start {
        params_span = Span {
            start: params_span.start,
            end: params_end,
        };
    }

    // Optional: RETURNS clause (required in Snowflake, optional in PostgreSQL)
    let returns_span;
    if let Some(tok) = p.peek_non_trivia() {
        if matches!(tok.kind, TokenKind::Keyword(Keyword::Returns)) {
            let returns_kw = p.advance().expect_invariant("RETURNS keyword");
            let returns_start = returns_kw.span.start;
            let mut returns_end = returns_kw.span.end;

            // Parse return type specification (can be simple type or TABLE(...))
            // Collect tokens until we hit LANGUAGE or AS keyword
            while let Some(tok) = p.peek_non_trivia() {
                if matches!(tok.kind, TokenKind::Keyword(Keyword::Language))
                    || matches!(tok.kind, TokenKind::Keyword(Keyword::As))
                {
                    break;
                }
                let t = p
                    .advance()
                    .expect_invariant("return type token consumed in CREATE PROCEDURE");
                returns_end = t.span.end;
            }
            returns_span = Span {
                start: returns_start,
                end: returns_end,
            };
        } else {
            // No RETURNS clause (PostgreSQL procedures)
            returns_span = Span {
                start: params_end,
                end: params_end,
            };
        }
    } else {
        returns_span = Span {
            start: params_end,
            end: params_end,
        };
    }

    // Optional: LANGUAGE SQL (skip if present)
    if let Some(tok) = p.peek_non_trivia() {
        if matches!(tok.kind, TokenKind::Keyword(Keyword::Language)) {
            p.advance();
            // Skip SQL keyword
            if let Some(sql_tok) = p.peek_non_trivia() {
                if matches!(sql_tok.kind, TokenKind::Keyword(Keyword::Sql)) {
                    p.advance();
                }
            }
        }
    }

    // Skip any optional clauses (CALLED ON NULL INPUT, COMMENT, EXECUTE AS, etc.) until AS for body
    // Need to be careful: EXECUTE AS CALLER has AS keyword, but it's not the body AS
    let mut found_as = false;
    // Captured `EXECUTE AS { OWNER | CALLER }` mode (if present in the
    // procedure prelude).
    // `SELF` is recognized syntactically (so the AS-vs-body-AS lookahead
    // routes correctly) but not mapped to an `ExecuteAsMode` variant.
    let mut execute_as_mode: Option<ExecuteAsMode> = None;
    while let Some(tok) = p.peek_non_trivia() {
        // If we hit BEGIN or DECLARE directly (without AS), BigQuery-style: body starts here
        if matches!(
            tok.kind,
            TokenKind::Keyword(Keyword::Begin) | TokenKind::Keyword(Keyword::Declare)
        ) {
            break;
        }
        // Check if this is the AS keyword before the procedure body
        // The body AS should be followed by either $$ or BEGIN/DECLARE
        if matches!(tok.kind, TokenKind::Keyword(Keyword::As)) {
            // Peek ahead to see what comes after AS
            // Need to manually skip trivia to look ahead
            let saved_idx = p.idx;
            p.advance(); // Move past AS
            if let Some(next_tok) = p.peek_non_trivia() {
                // If next token is a dollar-quote delimiter ($$ / $tag$), BEGIN,
                // or DECLARE, this is the body AS.
                if crate::parser::core::is_dollar_quote_tag(next_tok.lexeme(p.source))
                    || matches!(
                        next_tok.kind,
                        TokenKind::Keyword(Keyword::Begin) | TokenKind::Keyword(Keyword::Declare)
                    )
                {
                    p.idx = saved_idx; // Restore position
                    found_as = true;
                    break;
                }
                // MSSQL: AS can be followed by a bare SQL statement (no BEGIN/END needed).
                // Distinguish body AS from clause AS (e.g., EXECUTE AS CALLER/OWNER/SELF):
                // If the next token is NOT one of the known EXECUTE AS targets, treat it as body AS.
                //
                // Snowflake lexes CALLER / OWNER as dedicated keywords (`Keyword::Caller` /
                // `Keyword::Owner`), not as bare identifiers. MSSQL / PostgreSQL may lex them
                // as identifiers. Accept either kind — the lexeme match is authoritative.
                let next_lexeme = next_tok.lexeme(p.source);
                let lexeme_matches_target = next_lexeme.eq_ignore_ascii_case("CALLER")
                    || next_lexeme.eq_ignore_ascii_case("OWNER")
                    || next_lexeme.eq_ignore_ascii_case("SELF");
                let kind_matches_target = matches!(
                    next_tok.kind,
                    TokenKind::Identifier { .. } | TokenKind::Keyword(_)
                );
                let is_execute_as_target = lexeme_matches_target && kind_matches_target;
                if !is_execute_as_target {
                    p.idx = saved_idx; // Restore position
                    found_as = true;
                    break;
                }
                // Capture the mode (OWNER / CALLER). SELF is recognized
                // for parsing but not mapped — T-SQL `EXECUTE AS SELF`
                // resolves at CREATE time to a specific named principal,
                // which doesn't fit the OWNER/CALLER abstraction.
                if execute_as_mode.is_none() {
                    if next_lexeme.eq_ignore_ascii_case("OWNER") {
                        execute_as_mode = Some(ExecuteAsMode::Owner);
                    } else if next_lexeme.eq_ignore_ascii_case("CALLER") {
                        execute_as_mode = Some(ExecuteAsMode::Caller);
                    }
                }
                // Otherwise, it's part of another clause (like EXECUTE AS CALLER), keep going
            } else {
                // AS at EOF — treat as body AS (will fail later with appropriate error)
                p.idx = saved_idx;
                found_as = true;
                break;
            }
            // Don't restore idx - we already advanced past EXECUTE AS CALLER, continue from there
        } else {
            p.advance();
        }
    }

    // Expect AS keyword (optional in BigQuery where BEGIN follows directly)
    if found_as {
        let as_span = p.current_span();
        let as_kw = p.advance().ok_or_eof(as_span, vec!["AS".to_string()])?;
        if !matches!(as_kw.kind, TokenKind::Keyword(Keyword::As)) {
            return Err(ParseError::new(
                as_kw.span,
                ParseErrorKind::InvalidSyntax {
                    message: "Expected AS before procedure body".to_string(),
                },
            ));
        }
    }

    // Parse procedure body
    // Body can be:
    // 1. String literal delimited by $$ or ' containing the procedure code
    // 2. BEGIN ... END block directly (for Snowflake Scripting)

    p.skip_trivia();
    let body_span = p.current_span();
    let body_start_tok = p
        .peek_non_trivia()
        .ok_or_eof(body_span, vec!["procedure body".to_string()])?;
    let mut body_start = body_start_tok.span.start;
    let mut body_end = body_start;
    let mut body_stmt_opt: Option<Box<AstStmt>> = None;
    let mut had_delimiters = false;
    let mut delimiter_end = body_start;
    let mut opening_delimiter_token: Option<crate::cst::TokenId> = None;
    let mut closing_delimiter_token: Option<crate::cst::TokenId> = None;

    // If body starts with a dollar-quote delimiter (`$$` or `$tag$`), parse the
    // body content and find the matching close tag (same lexeme as the opener).
    if crate::parser::core::is_dollar_quote_tag(body_start_tok.lexeme(p.source)) {
        had_delimiters = true;
        let opening_delimiter = p
            .advance()
            .expect_invariant("Opening delimiter should be available"); // Skip opening $tag$
        opening_delimiter_token = Some(p.last_token_id());
        let open_tag_lo = opening_delimiter.span.start as usize;
        let open_tag_hi = opening_delimiter.span.end as usize;
        let body_content_start = opening_delimiter.span.end; // Body starts after opening delimiter

        // Sub-parse the body block and consume the matching closer (shared with
        // the anonymous DO block — see `parse_dollar_block_body`).
        let parsed = parse_dollar_block_body(p, open_tag_lo, open_tag_hi, body_content_start);
        body_stmt_opt = parsed.body_stmt;
        closing_delimiter_token = parsed.closing_delimiter_token;
        body_end = parsed.body_end;
        delimiter_end = parsed.delimiter_end;

        // Set body_span to exclude delimiters (just the content)
        body_start = body_content_start;
    }
    // If body starts with BEGIN or DECLARE, parse it as a scripting block
    else if matches!(
        body_start_tok.kind,
        TokenKind::Keyword(Keyword::Begin) | TokenKind::Keyword(Keyword::Declare)
    ) {
        // Try to parse the block using parse_scripting_block for DECLARE or parse_block_stmt for BEGIN
        // If it fails, fall back to collecting tokens
        let save_idx = p.idx;
        let block_result = if matches!(body_start_tok.kind, TokenKind::Keyword(Keyword::Declare)) {
            parse_scripting_block(p)
        } else {
            parse_block_stmt(p)
        };
        match block_result {
            Some(block_stmt) => {
                body_end = block_stmt.span().end;
                // Store the parsed statement for recursive descent formatting
                body_stmt_opt = Some(Box::new(block_stmt));
            }
            None => {
                // Restore position and collect tokens instead
                p.idx = save_idx;
                while let Some(tok) = p.peek_non_trivia() {
                    if matches!(
                        tok.kind,
                        TokenKind::Punctuation(crate::lexer::Punctuation::Semi)
                    ) {
                        break;
                    }
                    let t = p.advance().expect_invariant(
                        "procedure body token consumed after block parse failure",
                    );
                    body_end = t.span.end;
                }
            }
        }
    }
    // Otherwise, collect until semicolon (for string literal bodies)
    else {
        while let Some(tok) = p.peek_non_trivia() {
            if matches!(
                tok.kind,
                TokenKind::Punctuation(crate::lexer::Punctuation::Semi)
            ) {
                break;
            }
            let t = p
                .advance()
                .expect_invariant("procedure body token consumed for string literal body");
            body_end = t.span.end;
        }
    }
    let body_span = Span {
        start: body_start,
        end: body_end,
    };

    // PostgreSQL puts LANGUAGE after body: AS $$...body...$$ LANGUAGE plpgsql
    // Consume trailing LANGUAGE <name> if present
    let mut trailing_end = if had_delimiters {
        delimiter_end.max(body_end)
    } else {
        body_end
    };
    if let Some(tok) = p.peek_non_trivia() {
        if matches!(tok.kind, TokenKind::Keyword(Keyword::Language)) {
            let lang_kw = p.advance().expect_invariant("LANGUAGE keyword");
            trailing_end = lang_kw.span.end;
            // Consume language name (plpgsql, sql, etc.)
            if let Some(name_tok) = p.peek_non_trivia() {
                if !matches!(
                    name_tok.kind,
                    TokenKind::Punctuation(crate::lexer::Punctuation::Semi)
                ) {
                    let name = p.advance().expect_invariant("language name");
                    trailing_end = name.span.end;
                }
            }
        }
    }

    // Calculate the overall procedure span including delimiters
    // Don't consume semicolon - let outer wrapper handle it
    let proc_end = trailing_end;

    let span = Span {
        start: proc_start,
        end: proc_end,
    };
    let params = crate::parser::procedure_params::parse_procedure_params(
        params_span,
        p.source,
        p.dialect.procedure_param_grammar(),
        &p.id_gen,
    );
    Ok(AstStmt::CreateProcedure(Box::new(
        crate::ast::AstCreateProcedureStmt {
            node_id: p.id_gen.next(),
            span,
            create_span: create_kw_span,
            or_replace_span,
            or_alter_span,
            procedure_keyword_span,
            name_span,
            params_span,
            params,
            returns_span,
            body_span,
            body_stmt: body_stmt_opt,
            opening_delimiter_token,
            closing_delimiter_token,
            execute_as_mode,
            definer,
        },
    )))
}

pub(crate) fn parse_create_function(p: &mut Parser<'_>) -> ParseResult<AstStmt> {
    // Parse: CREATE [OR REPLACE] [TEMP|TEMPORARY] [AGGREGATE] FUNCTION [IF NOT EXISTS]
    //        name(params) RETURNS type LANGUAGE SQL AS body
    let create_kw = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["CREATE".to_string()])?;
    if !matches!(create_kw.kind, TokenKind::Keyword(Keyword::Create)) {
        return Err(crate::error::ParseError::unexpected_token(
            create_kw.span,
            vec!["CREATE".to_string()],
            crate::parser::core::Parser::token_description(create_kw, p.source),
        ));
    }

    let func_start = create_kw.span.start;
    let create_span = create_kw.span;

    // Optional: OR REPLACE / OR ALTER
    let mut or_replace_span: Option<Span> = None;
    let mut or_alter_span: Option<Span> = None;
    if let Some(tok) = p.peek_non_trivia() {
        if matches!(tok.kind, TokenKind::Keyword(Keyword::Or)) {
            let or_tok = p.advance().expect_invariant("OR token should be available");
            let or_start = or_tok.span.start;
            if let Some(next_tok) = p.peek_non_trivia() {
                if matches!(next_tok.kind, TokenKind::Keyword(Keyword::Replace)) {
                    let replace = p
                        .advance()
                        .expect_invariant("REPLACE token should be available");
                    or_replace_span = Some(Span {
                        start: or_start,
                        end: replace.span.end,
                    });
                } else if matches!(next_tok.kind, TokenKind::Keyword(Keyword::Alter)) {
                    let alter = p
                        .advance()
                        .expect_invariant("ALTER token should be available");
                    or_alter_span = Some(Span {
                        start: or_start,
                        end: alter.span.end,
                    });
                }
            }
        }
    }

    // Optional MySQL `DEFINER = { user | CURRENT_USER }` clause (precedes
    // FUNCTION). Fully parsed into the typed security-context primitive,
    // not skipped — the body runs under this account's privileges.
    let definer = p.parse_definer_clause();

    // Optional: TEMP or TEMPORARY keyword
    let mut temp_keyword_span: Option<Span> = None;
    if let Some(tok) = p.peek_non_trivia() {
        if matches!(
            tok.kind,
            TokenKind::Keyword(Keyword::Temp) | TokenKind::Keyword(Keyword::Temporary)
        ) {
            let temp_tok = p
                .advance()
                .expect_invariant("TEMP/TEMPORARY token should be available");
            temp_keyword_span = Some(temp_tok.span);
        }
    }

    // Optional: AGGREGATE keyword (BigQuery UDAF — tokenizes as Identifier)
    let mut aggregate_keyword_span: Option<Span> = None;
    if let Some(tok) = p.peek_non_trivia() {
        if matches!(tok.kind, TokenKind::Identifier { .. })
            && tok.lexeme(p.source).eq_ignore_ascii_case("AGGREGATE")
        {
            let agg_tok = p
                .advance()
                .expect_invariant("AGGREGATE token should be available");
            aggregate_keyword_span = Some(agg_tok.span);
        }
    }

    // Expect FUNCTION keyword
    let func_kw = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["FUNCTION".to_string()])?;
    if !matches!(func_kw.kind, TokenKind::Keyword(Keyword::Function)) {
        return Err(crate::error::ParseError::unexpected_token(
            func_kw.span,
            vec!["FUNCTION".to_string()],
            crate::parser::core::Parser::token_description(func_kw, p.source),
        ));
    }
    let function_keyword_span = func_kw.span;

    // Optional: IF NOT EXISTS
    let mut if_not_exists_span: Option<Span> = None;
    if let Some(tok) = p.peek_non_trivia() {
        if matches!(tok.kind, TokenKind::Keyword(Keyword::If)) {
            let if_tok = p.advance().expect_invariant("IF token should be available");
            let if_start = if_tok.span.start;
            let mut ine_end = if_tok.span.end;
            if let Some(not_tok) = p.peek_non_trivia() {
                if matches!(not_tok.kind, TokenKind::Keyword(Keyword::Not)) {
                    let not = p
                        .advance()
                        .expect_invariant("NOT token should be available");
                    ine_end = not.span.end;
                    if let Some(exists_tok) = p.peek_non_trivia() {
                        if matches!(exists_tok.kind, TokenKind::Keyword(Keyword::Exists)) {
                            let exists = p
                                .advance()
                                .expect_invariant("EXISTS token should be available");
                            ine_end = exists.span.end;
                        }
                    }
                }
            }
            if_not_exists_span = Some(Span {
                start: if_start,
                end: ine_end,
            });
        }
    }

    // Parse function name (identifier) — supports qualified names like dataset.func
    let name_tok = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["function name".to_string()])?;
    let mut name_span = name_tok.span;
    // Handle dot-qualified function names: schema.func, dataset.func
    loop {
        if let Some(dot_tok) = p.peek_non_trivia() {
            if matches!(
                dot_tok.kind,
                TokenKind::Punctuation(crate::lexer::Punctuation::Dot)
            ) {
                p.advance(); // consume dot
                if let Some(next_tok) = p.peek_non_trivia() {
                    if p.can_be_identifier_after_dot_token(next_tok) {
                        let part = p
                            .advance()
                            .expect_invariant("identifier after dot confirmed by peek");
                        name_span = Span {
                            start: name_span.start,
                            end: part.span.end,
                        };
                        continue;
                    }
                }
            }
        }
        break;
    }

    // Parse parameter list in parentheses
    let lparen = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["(".to_string()])?;
    if !matches!(
        lparen.kind,
        TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
    ) {
        return Err(crate::error::ParseError::unexpected_token(
            lparen.span,
            vec!["(".to_string()],
            crate::parser::core::Parser::token_description(lparen, p.source),
        ));
    }
    let params_start = lparen.span.start;
    let mut params_end = lparen.span.end;

    // Collect tokens until closing parenthesis
    let mut paren_depth = 1;
    while paren_depth > 0 {
        let tok = p
            .advance()
            .ok_or_eof(p.current_span(), vec![")".to_string()])?;
        params_end = tok.span.end;
        match tok.kind {
            TokenKind::Punctuation(crate::lexer::Punctuation::LParen) => paren_depth += 1,
            TokenKind::Punctuation(crate::lexer::Punctuation::RParen) => paren_depth -= 1,
            _ => {}
        }
    }
    let params_span = Span {
        start: params_start,
        end: params_end,
    };

    // Optional: COPY GRANTS, NOT NULL, MEMOIZABLE, and other clauses before RETURNS
    // Skip until we find RETURNS keyword
    while let Some(tok) = p.peek_non_trivia() {
        if matches!(tok.kind, TokenKind::Keyword(Keyword::Returns)) {
            break;
        }
        p.advance();
    }

    // Expect RETURNS keyword
    let returns_kw = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["RETURNS".to_string()])?;
    if !matches!(returns_kw.kind, TokenKind::Keyword(Keyword::Returns)) {
        return Err(crate::error::ParseError::unexpected_token(
            returns_kw.span,
            vec!["RETURNS".to_string()],
            crate::parser::core::Parser::token_description(returns_kw, p.source),
        ));
    }
    let returns_start = returns_kw.span.start;
    let mut returns_end = returns_kw.span.end;

    // Parse return type specification (can be simple type or TABLE(...))
    // Collect tokens until we hit LANGUAGE, AS, or RETURN keyword
    while let Some(tok) = p.peek_non_trivia() {
        if matches!(tok.kind, TokenKind::Keyword(Keyword::Language))
            || matches!(tok.kind, TokenKind::Keyword(Keyword::As))
            || matches!(tok.kind, TokenKind::Keyword(Keyword::Return))
        {
            break;
        }
        let t = p
            .advance()
            .expect_invariant("return type token consumed in CREATE FUNCTION");
        returns_end = t.span.end;
    }
    let returns_span = Span {
        start: returns_start,
        end: returns_end,
    };

    // Optional: LANGUAGE <name> (skip if present before AS)
    if let Some(tok) = p.peek_non_trivia() {
        if matches!(tok.kind, TokenKind::Keyword(Keyword::Language)) {
            p.advance();
            // Skip language name (SQL, plpgsql, etc.)
            if let Some(lang_tok) = p.peek_non_trivia() {
                if !matches!(lang_tok.kind, TokenKind::Keyword(Keyword::As)) {
                    p.advance();
                }
            }
        }
    }

    // Skip any optional clauses (CALLED ON NULL INPUT, COMMENT, MEMOIZABLE, etc.)
    // until AS (Snowflake/PostgreSQL/BigQuery) or RETURN (Databricks SQL UDF)
    while let Some(tok) = p.peek_non_trivia() {
        if matches!(tok.kind, TokenKind::Keyword(Keyword::As))
            || matches!(tok.kind, TokenKind::Keyword(Keyword::Return))
        {
            break;
        }
        p.advance();
    }

    // Expect AS (traditional function body) or RETURN (Databricks SQL UDF body)
    let body_intro_kw = p.advance().ok_or_eof(
        p.current_span(),
        vec!["AS".to_string(), "RETURN".to_string()],
    )?;
    let is_return_body = if matches!(body_intro_kw.kind, TokenKind::Keyword(Keyword::As)) {
        false
    } else if matches!(body_intro_kw.kind, TokenKind::Keyword(Keyword::Return)) {
        true
    } else {
        return Err(crate::error::ParseError::unexpected_token(
            body_intro_kw.span,
            vec!["AS".to_string(), "RETURN".to_string()],
            crate::parser::core::Parser::token_description(body_intro_kw, p.source),
        ));
    };

    // Parse function body
    // Body can be:
    // 1. String literal delimited by $$ or ' containing the function code
    // 2. BEGIN ... END block directly (for Snowflake Scripting)
    // 3. RETURN <expr> (Databricks SQL UDF)

    let mut body_start = body_intro_kw.span.start;
    let mut body_end = body_intro_kw.span.end;
    let mut had_delimiters = false;
    let mut delimiter_end = body_end;
    let mut opening_delimiter_token: Option<crate::cst::TokenId> = None;
    let mut closing_delimiter_token: Option<crate::cst::TokenId> = None;
    let mut body_stmt: Option<Box<AstStmt>> = None;

    if is_return_body {
        // Databricks SQL UDF: RETURN <expr>
        // Keep RETURN token inside body span for exact source preservation.
        while let Some(tok) = p.peek_non_trivia() {
            if matches!(
                tok.kind,
                TokenKind::Punctuation(crate::lexer::Punctuation::Semi)
            ) {
                break;
            }
            let t = p
                .advance()
                .expect_invariant("function RETURN body token consumed");
            body_end = t.span.end;
        }
    } else {
        p.skip_trivia();
        let body_start_tok = p
            .peek_non_trivia()
            .ok_or_eof(p.current_span(), vec!["function body".to_string()])?;
        body_start = body_start_tok.span.start;
        body_end = body_start;

        // If body starts with a dollar-quote delimiter (`$$` or `$tag$`), find
        // the matching close tag (same lexeme as the opener).
        if crate::parser::core::is_dollar_quote_tag(body_start_tok.lexeme(p.source)) {
            had_delimiters = true;
            let opening_delimiter = p
                .advance()
                .expect_invariant("Opening delimiter should be available"); // Skip opening $tag$
            opening_delimiter_token = Some(p.last_token_id());
            let open_tag_lo = opening_delimiter.span.start as usize;
            let open_tag_hi = opening_delimiter.span.end as usize;
            let body_content_start = opening_delimiter.span.end; // Body starts after opening delimiter
            let mut body_content_end = body_content_start;

            // Save parser position to parse body content
            let body_parse_start_idx = p.idx;

            // Find closing delimiter (same tag as the opener)
            while let Some(_tok) = p.peek_non_trivia() {
                let t = p.advance().expect_invariant(
                    "function body token consumed searching for closing delimiter",
                );
                if t.lexeme(p.source) == &p.source[open_tag_lo..open_tag_hi] {
                    // Body ends before the closing delimiter
                    closing_delimiter_token = Some(p.last_token_id());
                    delimiter_end = t.span.end; // Save closing delimiter position for overall span
                    break;
                }
                body_content_end = t.span.end;
            }

            // Set body_span to exclude delimiters (just the content)
            body_start = body_content_start;
            body_end = body_content_end;

            // Now try to parse the body content as Snowflake Scripting
            // Reset parser to start of body content
            let save_idx = p.idx;
            p.idx = body_parse_start_idx;

            // Try to parse the body content as a typed inner statement.
            //
            // Valid `$$ … $$` body shapes:
            //   - Scripting blocks: `BEGIN … END`, `DECLARE … BEGIN … END`
            //     (Snowflake Scripting, MySQL/Databricks compound).
            //   - Single SQL statement: a `SELECT` / DML / `RETURN <expr>`
            //     etc. — the PG `LANGUAGE SQL` single-statement form
            //     ("This can either be a single statement `RETURN
            //     expression` or a block `BEGIN ATOMIC; … END`" — PG
            //     CREATE FUNCTION docs) and the Snowflake SQL UDF
            //     "A SQL expression or Snowflake Scripting block" form.
            //
            // Picking BEGIN/DECLARE keywords explicitly first preserves
            // the existing scripting-block routing; everything else
            // falls through to the generic [`parse_flow_statement`]
            // dispatch so the body's statements are fully typed.
            if let Some(tok) = p.peek_non_trivia() {
                if matches!(tok.kind, TokenKind::Keyword(Keyword::Begin)) {
                    body_stmt = parse_block_stmt(p).map(Box::new);
                } else if matches!(tok.kind, TokenKind::Keyword(Keyword::Declare)) {
                    body_stmt = parse_scripting_block(p).map(Box::new);
                } else if let Ok(stmt) = p.parse_flow_statement() {
                    body_stmt = Some(Box::new(stmt));
                }
            }

            // Restore parser position to after closing $$
            p.idx = save_idx;
        }
        // If body starts with BEGIN or DECLARE, parse it as a scripting block
        else if matches!(
            body_start_tok.kind,
            TokenKind::Keyword(Keyword::Begin) | TokenKind::Keyword(Keyword::Declare)
        ) {
            // Try to parse the block using parse_scripting_block for DECLARE or parse_block_stmt for BEGIN
            // If it fails, fall back to collecting tokens
            let save_idx = p.idx;
            let block_result =
                if matches!(body_start_tok.kind, TokenKind::Keyword(Keyword::Declare)) {
                    parse_scripting_block(p)
                } else {
                    parse_block_stmt(p)
                };
            match block_result {
                Some(block_stmt) => {
                    body_end = block_stmt.span().end;
                    body_stmt = Some(Box::new(block_stmt));
                }
                None => {
                    // Restore position and collect tokens instead
                    p.idx = save_idx;
                    while let Some(tok) = p.peek_non_trivia() {
                        if matches!(
                            tok.kind,
                            TokenKind::Punctuation(crate::lexer::Punctuation::Semi)
                        ) {
                            break;
                        }
                        let t = p
                            .advance()
                            .expect_invariant("function body token consumed after parse failure");
                        body_end = t.span.end;
                    }
                }
            }
        }
        // Otherwise, collect until semicolon (for string literal bodies)
        else {
            while let Some(tok) = p.peek_non_trivia() {
                if matches!(
                    tok.kind,
                    TokenKind::Punctuation(crate::lexer::Punctuation::Semi)
                ) {
                    break;
                }
                let t = p
                    .advance()
                    .expect_invariant("function body token consumed for string literal body");
                body_end = t.span.end;
            }
        }
    }

    let body_span = Span {
        start: body_start,
        end: body_end,
    };

    // PostgreSQL puts LANGUAGE after body: AS $$...body...$$ LANGUAGE plpgsql
    // Consume trailing LANGUAGE <name> if present
    let mut trailing_end = if had_delimiters {
        delimiter_end
    } else {
        body_end
    };
    if let Some(tok) = p.peek_non_trivia() {
        if matches!(tok.kind, TokenKind::Keyword(Keyword::Language)) {
            let lang_kw = p.advance().expect_invariant("LANGUAGE keyword");
            trailing_end = lang_kw.span.end;
            // Consume language name (plpgsql, sql, etc.)
            if let Some(name_tok) = p.peek_non_trivia() {
                if !matches!(
                    name_tok.kind,
                    TokenKind::Punctuation(crate::lexer::Punctuation::Semi)
                ) {
                    let name = p.advance().expect_invariant("language name");
                    trailing_end = name.span.end;
                }
            }
        }
    }

    // Calculate the overall function span including delimiters
    // Don't consume semicolon - let outer wrapper handle it
    let func_end = trailing_end;

    let span = Span {
        start: func_start,
        end: func_end,
    };
    Ok(AstStmt::CreateFunction(Box::new(
        crate::ast::AstCreateFunctionStmt {
            node_id: p.id_gen.next(),
            span,
            create_span,
            or_replace_span,
            or_alter_span,
            temp_keyword_span,
            aggregate_keyword_span,
            function_keyword_span,
            if_not_exists_span,
            name_span,
            params_span,
            params: crate::parser::procedure_params::parse_procedure_params(
                params_span,
                p.source,
                p.dialect.procedure_param_grammar(),
                &p.id_gen,
            ),
            returns_span,
            body_span,
            body_stmt,
            opening_delimiter_token,
            closing_delimiter_token,
            definer,
        },
    )))
}

/// Parse CREATE [OR REPLACE] TABLE FUNCTION [IF NOT EXISTS] statement (BigQuery TVF)
///
/// Syntax:
///   CREATE [OR REPLACE] TABLE FUNCTION [IF NOT EXISTS]
///     [[project.]dataset.]function_name
///     ( [param_name { type | ANY TYPE | TABLE<col type, ...> } [, ...]] )
///     [RETURNS TABLE<col_name type [, ...]>]
///     [OPTIONS (option_list)]
///     AS sql_query
pub(crate) fn parse_create_table_function(p: &mut Parser<'_>) -> ParseResult<AstStmt> {
    use crate::error::ParseResultExt;

    let create_kw = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["CREATE".to_string()])?;
    if !matches!(create_kw.kind, TokenKind::Keyword(Keyword::Create)) {
        return Err(crate::error::ParseError::unexpected_token(
            create_kw.span,
            vec!["CREATE".to_string()],
            crate::parser::core::Parser::token_description(create_kw, p.source),
        ));
    }
    let func_start = create_kw.span.start;
    let create_span = create_kw.span;

    // Optional: OR REPLACE
    let mut or_replace_span: Option<Span> = None;
    if let Some(tok) = p.peek_non_trivia() {
        if matches!(tok.kind, TokenKind::Keyword(Keyword::Or)) {
            let or_tok = p.advance().expect_invariant("OR token should be available");
            let or_start = or_tok.span.start;
            if let Some(replace_tok) = p.peek_non_trivia() {
                if matches!(replace_tok.kind, TokenKind::Keyword(Keyword::Replace)) {
                    let replace = p
                        .advance()
                        .expect_invariant("REPLACE token should be available");
                    or_replace_span = Some(Span {
                        start: or_start,
                        end: replace.span.end,
                    });
                }
            }
        }
    }

    // Optional: TEMP or TEMPORARY keyword
    let mut temp_keyword_span: Option<Span> = None;
    if let Some(tok) = p.peek_non_trivia() {
        if matches!(
            tok.kind,
            TokenKind::Keyword(Keyword::Temp) | TokenKind::Keyword(Keyword::Temporary)
        ) {
            let temp_tok = p
                .advance()
                .expect_invariant("TEMP/TEMPORARY token should be available");
            temp_keyword_span = Some(temp_tok.span);
        }
    }

    // Expect TABLE keyword
    let table_kw = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["TABLE".to_string()])?;
    if !matches!(table_kw.kind, TokenKind::Keyword(Keyword::Table)) {
        return Err(crate::error::ParseError::unexpected_token(
            table_kw.span,
            vec!["TABLE".to_string()],
            crate::parser::core::Parser::token_description(table_kw, p.source),
        ));
    }
    let table_keyword_span = table_kw.span;

    // Expect FUNCTION keyword
    let func_kw = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["FUNCTION".to_string()])?;
    if !matches!(func_kw.kind, TokenKind::Keyword(Keyword::Function)) {
        return Err(crate::error::ParseError::unexpected_token(
            func_kw.span,
            vec!["FUNCTION".to_string()],
            crate::parser::core::Parser::token_description(func_kw, p.source),
        ));
    }
    let function_keyword_span = func_kw.span;

    // Optional: IF NOT EXISTS
    let mut if_not_exists_span: Option<Span> = None;
    if let Some(tok) = p.peek_non_trivia() {
        if matches!(tok.kind, TokenKind::Keyword(Keyword::If)) {
            let if_tok = p.advance().expect_invariant("IF token should be available");
            let if_start = if_tok.span.start;
            let mut ine_end = if_tok.span.end;
            if let Some(not_tok) = p.peek_non_trivia() {
                if matches!(not_tok.kind, TokenKind::Keyword(Keyword::Not)) {
                    let not = p
                        .advance()
                        .expect_invariant("NOT token should be available");
                    ine_end = not.span.end;
                    if let Some(exists_tok) = p.peek_non_trivia() {
                        if matches!(exists_tok.kind, TokenKind::Keyword(Keyword::Exists)) {
                            let exists = p
                                .advance()
                                .expect_invariant("EXISTS token should be available");
                            ine_end = exists.span.end;
                        }
                    }
                }
            }
            if_not_exists_span = Some(Span {
                start: if_start,
                end: ine_end,
            });
        }
    }

    // Parse function name (possibly qualified: project.dataset.name)
    let name_start_tok = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["function name".to_string()])?;
    let name_start = name_start_tok.span.start;
    let mut name_end = name_start_tok.span.end;
    // Consume dot-separated qualified name parts
    while let Some(tok) = p.peek_non_trivia() {
        if matches!(
            tok.kind,
            TokenKind::Punctuation(crate::lexer::Punctuation::Dot)
        ) {
            let dot = p
                .advance()
                .expect_invariant("dot consumed in qualified name");
            name_end = dot.span.end;
            if let Some(part) = p.peek_non_trivia() {
                if matches!(
                    part.kind,
                    TokenKind::Identifier { .. } | TokenKind::Keyword(_)
                ) {
                    let part_tok = p.advance().expect_invariant("name part consumed after dot");
                    name_end = part_tok.span.end;
                } else {
                    break;
                }
            }
        } else {
            break;
        }
    }
    let name_span = Span {
        start: name_start,
        end: name_end,
    };

    // Parse parameter list in parentheses (opaque — balanced paren tracking)
    // Params can include TABLE<col type, ...> which has angle brackets, not parens
    let lparen = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["(".to_string()])?;
    if !matches!(
        lparen.kind,
        TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
    ) {
        return Err(crate::error::ParseError::unexpected_token(
            lparen.span,
            vec!["(".to_string()],
            crate::parser::core::Parser::token_description(lparen, p.source),
        ));
    }
    let params_start = lparen.span.start;
    let mut params_end = lparen.span.end;
    let mut paren_depth = 1;
    while paren_depth > 0 {
        let tok = p
            .advance()
            .ok_or_eof(p.current_span(), vec![")".to_string()])?;
        params_end = tok.span.end;
        match tok.kind {
            TokenKind::Punctuation(crate::lexer::Punctuation::LParen) => paren_depth += 1,
            TokenKind::Punctuation(crate::lexer::Punctuation::RParen) => paren_depth -= 1,
            _ => {}
        }
    }
    let params_span = Span {
        start: params_start,
        end: params_end,
    };

    // Optional: RETURNS TABLE<col_name type [, ...]>
    let mut returns_start = params_end;
    let mut returns_end = params_end;
    if let Some(tok) = p.peek_non_trivia() {
        if matches!(tok.kind, TokenKind::Keyword(Keyword::Returns)) {
            let ret_kw = p
                .advance()
                .expect_invariant("RETURNS keyword consumed after peek");
            returns_start = ret_kw.span.start;
            returns_end = ret_kw.span.end;
            // Expect TABLE keyword after RETURNS
            if let Some(table_tok) = p.peek_non_trivia() {
                if matches!(table_tok.kind, TokenKind::Keyword(Keyword::Table)) {
                    let t = p
                        .advance()
                        .expect_invariant("TABLE keyword in RETURNS TABLE");
                    returns_end = t.span.end;
                }
            }
            // Expect < and consume until matching >
            if let Some(lt_tok) = p.peek_non_trivia() {
                if matches!(lt_tok.kind, TokenKind::Operator(crate::lexer::Operator::Lt)) {
                    let lt = p.advance().expect_invariant("< in RETURNS TABLE<...>");
                    returns_end = lt.span.end;
                    let mut angle_depth = 1;
                    while angle_depth > 0 {
                        let t = p
                            .advance()
                            .ok_or_eof(p.current_span(), vec![">".to_string()])?;
                        returns_end = t.span.end;
                        match t.kind {
                            TokenKind::Operator(crate::lexer::Operator::Lt) => angle_depth += 1,
                            TokenKind::Operator(crate::lexer::Operator::Gt) => angle_depth -= 1,
                            _ => {}
                        }
                    }
                }
            }
        }
    }
    let returns_span = Span {
        start: returns_start,
        end: returns_end,
    };

    // Optional: OPTIONS (...) — OPTIONS is an Identifier, not a keyword
    if let Some(tok) = p.peek_non_trivia() {
        if matches!(tok.kind, TokenKind::Identifier { .. })
            && tok.lexeme(p.source).eq_ignore_ascii_case("OPTIONS")
        {
            p.advance(); // consume OPTIONS
                         // Consume balanced parens
            if let Some(lp) = p.peek_non_trivia() {
                if matches!(
                    lp.kind,
                    TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
                ) {
                    p.advance(); // consume (
                    let mut depth = 1;
                    while depth > 0 {
                        let t = p
                            .advance()
                            .ok_or_eof(p.current_span(), vec![")".to_string()])?;
                        match t.kind {
                            TokenKind::Punctuation(crate::lexer::Punctuation::LParen) => depth += 1,
                            TokenKind::Punctuation(crate::lexer::Punctuation::RParen) => depth -= 1,
                            _ => {}
                        }
                    }
                }
            }
        }
    }

    // Expect AS keyword
    let as_kw = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["AS".to_string()])?;
    if !matches!(as_kw.kind, TokenKind::Keyword(Keyword::As)) {
        return Err(crate::error::ParseError::unexpected_token(
            as_kw.span,
            vec!["AS".to_string()],
            crate::parser::core::Parser::token_description(as_kw, p.source),
        ));
    }

    // Parse body: TVF bodies are SQL queries (SELECT statements)
    // Try to parse as a statement for semantic extraction; fall back to opaque span
    let body_start_tok = p
        .peek_non_trivia()
        .ok_or_eof(p.current_span(), vec!["query body".to_string()])?;
    let body_start = body_start_tok.span.start;
    let mut body_end = body_start;
    let mut body_stmt: Option<Box<AstStmt>> = None;

    // Try to parse the body as a SQL statement
    let save_idx = p.idx;
    match p.parse_statement() {
        Ok(stmt) => {
            body_end = stmt.span().end;
            body_stmt = Some(Box::new(stmt));
        }
        Err(_) => {
            // Parse failed — fall back to opaque span (consume until semicolon/EOF)
            p.idx = save_idx;
            let mut body_paren_depth = 0i32;
            while let Some(tok) = p.peek_non_trivia() {
                match tok.kind {
                    TokenKind::Punctuation(crate::lexer::Punctuation::Semi)
                        if body_paren_depth <= 0 =>
                    {
                        break
                    }
                    TokenKind::Eof => break,
                    TokenKind::Punctuation(crate::lexer::Punctuation::LParen) => {
                        body_paren_depth += 1;
                        let t = p.advance().expect_invariant("body token consumed");
                        body_end = t.span.end;
                    }
                    TokenKind::Punctuation(crate::lexer::Punctuation::RParen) => {
                        body_paren_depth -= 1;
                        let t = p.advance().expect_invariant("body token consumed");
                        body_end = t.span.end;
                    }
                    _ => {
                        let t = p.advance().expect_invariant("body token consumed");
                        body_end = t.span.end;
                    }
                }
            }
        }
    }

    let body_span = Span {
        start: body_start,
        end: body_end,
    };

    let func_end = body_end;
    let span = Span {
        start: func_start,
        end: func_end,
    };

    Ok(AstStmt::CreateTableFunction(Box::new(
        crate::ast::AstCreateTableFunctionStmt {
            node_id: p.id_gen.next(),
            span,
            create_span,
            or_replace_span,
            temp_keyword_span,
            table_keyword_span,
            function_keyword_span,
            if_not_exists_span,
            name_span,
            params_span,
            params: crate::parser::procedure_params::parse_procedure_params(
                params_span,
                p.source,
                p.dialect.procedure_param_grammar(),
                &p.id_gen,
            ),
            returns_span,
            body_span,
            body_stmt,
        },
    )))
}

/// Parse DROP TABLE FUNCTION [IF EXISTS] [[project.]dataset.]function_name
pub(crate) fn parse_drop_table_function(p: &mut Parser<'_>) -> ParseResult<AstStmt> {
    use crate::error::ParseResultExt;

    let drop_kw = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["DROP".to_string()])?;
    let keyword_span = drop_kw.span;
    let mut span = keyword_span;

    // Consume TABLE
    let table_tok = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["TABLE".to_string()])?;
    span.end = table_tok.span.end;

    // Consume FUNCTION
    let func_tok = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["FUNCTION".to_string()])?;
    let object_type_end = func_tok.span.end;
    span.end = object_type_end;

    let object_type_span = Some(Span {
        start: table_tok.span.start,
        end: object_type_end,
    });

    // Optional: IF EXISTS
    let mut if_exists_span: Option<Span> = None;
    if let Some(tok) = p.peek_non_trivia() {
        if matches!(tok.kind, TokenKind::Keyword(Keyword::If)) {
            let if_tok = p.advance().expect_invariant("IF confirmed by peek");
            let if_start = if_tok.span.start;
            if let Some(exists_tok) = p.peek_non_trivia() {
                if matches!(exists_tok.kind, TokenKind::Keyword(Keyword::Exists)) {
                    let ex = p.advance().expect_invariant("EXISTS confirmed by peek");
                    if_exists_span = Some(Span {
                        start: if_start,
                        end: ex.span.end,
                    });
                    span.end = ex.span.end;
                }
            }
        }
    }

    // Parse target name (possibly qualified)
    let mut target_name_span: Option<Span> = None;
    if let Some(tok) = p.peek_non_trivia() {
        if matches!(
            tok.kind,
            TokenKind::Identifier { .. } | TokenKind::Keyword(_)
        ) {
            let first = p.advance().expect_invariant("name token consumed");
            let name_start = first.span.start;
            let mut name_end = first.span.end;
            // Consume dot-separated parts
            while let Some(dot) = p.peek_non_trivia() {
                if matches!(
                    dot.kind,
                    TokenKind::Punctuation(crate::lexer::Punctuation::Dot)
                ) {
                    let d = p.advance().expect_invariant("dot consumed");
                    name_end = d.span.end;
                    if let Some(part) = p.peek_non_trivia() {
                        if matches!(
                            part.kind,
                            TokenKind::Identifier { .. } | TokenKind::Keyword(_)
                        ) {
                            let pt = p.advance().expect_invariant("name part consumed");
                            name_end = pt.span.end;
                        }
                    }
                } else {
                    break;
                }
            }
            target_name_span = Some(Span {
                start: name_start,
                end: name_end,
            });
            span.end = name_end;
        }
    }

    Ok(AstStmt::Drop(crate::ast::AstDrop {
        node_id: p.id_gen.next(),
        span,
        keyword_span,
        object_type_span,
        if_exists_span,
        target_name_span,
        cascade_restrict_span: None,
    }))
}

/// Result-based EXECUTE IMMEDIATE parser with INTO clause support
pub(crate) fn try_parse_execute_immediate_stmt(p: &mut Parser<'_>) -> ParseResult<AstStmt> {
    // Parse: EXECUTE IMMEDIATE <expr> [INTO :var1, :var2, ...] [USING (bind_vars)];
    let execute_kw = p.advance().ok_or_else(|| {
        ParseError::new(
            p.current_span(),
            ParseErrorKind::InvalidStatement {
                message: "Expected EXECUTE keyword".to_string(),
            },
        )
    })?;

    if !matches!(execute_kw.kind, TokenKind::Keyword(Keyword::Execute)) {
        return Err(ParseError::new(
            execute_kw.span,
            ParseErrorKind::InvalidStatement {
                message: "Expected EXECUTE keyword".to_string(),
            },
        ));
    }

    let stmt_start = execute_kw.span.start;

    // IMMEDIATE keyword. Snowflake / BigQuery / Databricks require it
    // (`EXECUTE IMMEDIATE <expr>`). PostgreSQL / Redshift PL/pgSQL use a
    // bare `EXECUTE <expr>` for dynamic SQL — `supports_plpgsql_dynamic_execute`
    // gates that relaxation so non-PG dialects keep the strict grammar.
    let immediate_span = match p.peek_non_trivia() {
        Some(tok) if matches!(tok.kind, TokenKind::Keyword(Keyword::Immediate)) => {
            let immediate_kw = p
                .advance()
                .expect_invariant("IMMEDIATE keyword consumed after peek match");
            Some(immediate_kw.span)
        }
        _ if p.dialect.supports_plpgsql_dynamic_execute() => None,
        Some(tok) => {
            return Err(ParseError::new(
                tok.span,
                ParseErrorKind::InvalidStatement {
                    message: format!(
                        "EXECUTE requires IMMEDIATE keyword, found {}",
                        Parser::token_description(tok, p.source)
                    ),
                },
            ));
        }
        None => {
            return Err(ParseError::new(
                p.current_span(),
                ParseErrorKind::InvalidStatement {
                    message: "EXECUTE requires IMMEDIATE keyword".to_string(),
                },
            ));
        }
    };

    // Snowflake `EXECUTE IMMEDIATE FROM <file_location> …` — executes SQL
    // loaded from a stage file. This is a distinct statement from the inline
    // `EXECUTE IMMEDIATE <expr>` string surface; branch before the expression
    // parser (which would choke on the `FROM` keyword).
    if let Some(immediate) = immediate_span {
        if matches!(
            p.peek_non_trivia(),
            Some(tok) if matches!(tok.kind, TokenKind::Keyword(Keyword::From))
        ) {
            return parse_execute_immediate_from(p, execute_kw.span, immediate);
        }
    }

    // The dynamic-SQL argument may be a `$$…$$` / `$tag$…$tag$` dollar-quoted
    // string. In dialects whose lexer does NOT treat `$$` as a string opener
    // (e.g. Snowflake, where `$$` is reserved for routine bodies handled by a
    // separate parser path), the opener still lexes as a standalone identifier
    // token; reassemble it here into a string literal so `EXECUTE IMMEDIATE
    // $$…$$` bodies are recognized as a static literal argument (and become
    // analyzable like any literal body). Dialects that already lex `$$` as a
    // string reach the same literal shape via the expression parser below.
    // Only for dialects whose lexer does NOT already treat `$$` as a string
    // (Snowflake et al.). Dialects with native dollar-quoted strings
    // (PostgreSQL / Redshift) already produce a string literal here — and the
    // expression parser handles their concat/nested-dollar shapes — so leave
    // those untouched.
    let dollar_opener = !p.dialect.supports_dollar_quoted_strings()
        && p.peek_non_trivia().is_some_and(|t| {
            matches!(t.kind, TokenKind::Identifier { .. })
                && crate::parser::core::is_dollar_quote_tag(t.lexeme(p.source))
        });
    let sql_expr = if dollar_opener {
        p.skip_trivia();
        let span = p.reassemble_dollar_quoted_span();
        AstExpr::Literal {
            node_id: p.id_gen.next(),
            literal: AstLiteral::String { span },
        }
    } else {
        // Parse the main SQL expression using scripting expression mode
        try_parse_expr_scripting(p).map_err(|_| {
            ParseError::invalid_expression(
                p.current_span(),
                "EXECUTE IMMEDIATE requires SQL expression".to_string(),
            )
        })?
    };

    // A rendered-template placeholder inside the executed string is an injection
    // splice; mark it so the dynamic-SQL classifier treats the argument as
    // dynamic, not a clean literal (same as the `EXEC(...)` dynamic form).
    let sql_expr = p.promote_placeholder_dynamic_sql_arg(sql_expr);

    let mut end = expr_span_end(&sql_expr);
    let mut into_vars: Vec<Span> = Vec::new();
    let mut using_args: Vec<AstExecuteUsingArg> = Vec::new();
    let mut using_lparen_span: Option<Span> = None;
    let mut using_rparen_span: Option<Span> = None;
    let mut using_span: Option<Span> = None;
    let mut into_span: Option<Span> = None;
    let mut into_strict_span: Option<Span> = None;

    // Parse optional INTO and USING clauses (in any order)
    // Snowflake allows: EXECUTE IMMEDIATE <expr> [INTO vars] [USING args]
    // OR: EXECUTE IMMEDIATE <expr> [USING args] [INTO vars]
    let mut parsed_into = false;
    let mut parsed_using = false;

    for _ in 0..2 {
        // Allow up to 2 optional clauses
        p.skip_trivia();
        let Some(tok) = p.peek_non_trivia() else {
            break;
        };

        // Try to parse INTO clause if not yet parsed
        if !parsed_into && matches!(tok.kind, TokenKind::Keyword(Keyword::Into)) {
            let into_kw = p
                .advance()
                .expect_invariant("INTO keyword consumed after match in EXECUTE IMMEDIATE");
            into_span = Some(into_kw.span);
            parsed_into = true;

            // PL/pgSQL `INTO STRICT <target>` modifier (PostgreSQL /
            // Redshift): assert exactly one row. STRICT lexes as an
            // Identifier; consume it as a modifier rather than the
            // first INTO target.
            p.skip_trivia();
            if let Some(strict_tok) = p.peek_non_trivia() {
                if matches!(strict_tok.kind, TokenKind::Identifier { .. })
                    && strict_tok.lexeme(p.source).eq_ignore_ascii_case("STRICT")
                {
                    let strict = p
                        .advance()
                        .expect_invariant("STRICT identifier consumed after peek match");
                    into_strict_span = Some(strict.span);
                }
            }

            // Parse comma-separated list of variable references (usually :varname)
            loop {
                p.skip_trivia();
                let var_tok = p.peek_non_trivia().ok_or_else(|| {
                    ParseError::new(
                        p.current_span(),
                        ParseErrorKind::InvalidStatement {
                            message: "INTO clause requires variable identifier".to_string(),
                        },
                    )
                })?;

                // Variables in INTO can be identifiers or scripting variable refs (:var)
                match &var_tok.kind {
                    TokenKind::Identifier { .. }
                    | TokenKind::Punctuation(crate::lexer::Punctuation::Colon) => {
                        let var_start = var_tok.span.start;
                        let _ = p.advance();

                        // If we got a colon, expect identifier next
                        let var_end = if matches!(
                            var_tok.kind,
                            TokenKind::Punctuation(crate::lexer::Punctuation::Colon)
                        ) {
                            let ident_tok = p.advance().ok_or_else(|| {
                                ParseError::new(
                                    p.current_span(),
                                    ParseErrorKind::InvalidStatement {
                                        message: "Expected identifier after : in INTO clause"
                                            .to_string(),
                                    },
                                )
                            })?;
                            ident_tok.span.end
                        } else {
                            var_tok.span.end
                        };

                        into_vars.push(Span {
                            start: var_start,
                            end: var_end,
                        });
                        end = var_end;

                        // Check for comma (more variables) or continue
                        p.skip_trivia();
                        if let Some(next_tok) = p.peek_non_trivia() {
                            if matches!(
                                next_tok.kind,
                                TokenKind::Punctuation(crate::lexer::Punctuation::Comma)
                            ) {
                                let _ = p.advance();
                                continue;
                            } else {
                                break;
                            }
                        } else {
                            break;
                        }
                    }
                    _ => {
                        return Err(ParseError::new(
                            var_tok.span,
                            ParseErrorKind::InvalidStatement {
                                message: format!(
                                    "INTO clause requires variable identifier, found {}",
                                    Parser::token_description(var_tok, p.source)
                                ),
                            },
                        ));
                    }
                }
            }
            continue; // Try next optional clause
        }

        // Try to parse USING clause if not yet parsed
        if !parsed_using && matches!(tok.kind, TokenKind::Keyword(Keyword::Using)) {
            let using_kw = p
                .advance()
                .expect_invariant("USING keyword consumed after match in EXECUTE IMMEDIATE");
            using_span = Some(using_kw.span);
            parsed_using = true;
            p.skip_trivia();

            // Check if parentheses are used (Snowflake style) or not (BigQuery style)
            // Snowflake: USING (expr, expr, ...)
            // BigQuery:  USING expr, expr, ...
            let first_tok = p.peek_non_trivia().ok_or_else(|| {
                ParseError::new(
                    p.current_span(),
                    ParseErrorKind::InvalidStatement {
                        message: "USING clause requires at least one expression".to_string(),
                    },
                )
            })?;

            let has_parens = matches!(
                first_tok.kind,
                TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
            );

            if has_parens {
                let lparen_tok = p
                    .advance()
                    .ok_or_eof(p.current_span(), vec!["(".to_string()])?;
                using_lparen_span = Some(lparen_tok.span);
            }

            // Parse comma-separated list of expressions
            loop {
                p.skip_trivia();
                let tok = p.peek_non_trivia().ok_or_else(|| {
                    ParseError::new(
                        p.current_span(),
                        ParseErrorKind::InvalidStatement {
                            message: "USING clause requires expression".to_string(),
                        },
                    )
                })?;

                // If we have parens, check for closing paren
                if has_parens
                    && matches!(
                        tok.kind,
                        TokenKind::Punctuation(crate::lexer::Punctuation::RParen)
                    )
                {
                    let rparen = p
                        .advance()
                        .expect_invariant("')' consumed after match in EXECUTE USING clause");
                    using_rparen_span = Some(rparen.span);
                    end = rparen.span.end;
                    break;
                }

                let arg_expr = try_parse_expr_scripting(p).map_err(|_| {
                    ParseError::invalid_expression(
                        p.current_span(),
                        "USING clause requires expression".to_string(),
                    )
                })?;
                end = arg_expr.span().end;

                // BigQuery named binding: `USING expr AS alias`. Only the
                // explicit AS form is grammar-legal here — gate on AS so a
                // bare identifier is never mis-read as an implicit alias.
                p.skip_trivia();
                let alias = match p.peek_non_trivia() {
                    Some(t) if matches!(t.kind, TokenKind::Keyword(Keyword::As)) => {
                        p.parse_optional_alias()
                    }
                    _ => None,
                };
                if let Some(ref a) = alias {
                    end = a.ident.span.end;
                }
                using_args.push(AstExecuteUsingArg {
                    node_id: p.id_gen.next(),
                    expr: arg_expr,
                    alias,
                });

                p.skip_trivia();
                let next_tok = match p.peek_non_trivia() {
                    Some(t) => t,
                    None => break, // EOF - end of USING clause (no parens case)
                };

                match next_tok.kind {
                    TokenKind::Punctuation(crate::lexer::Punctuation::Comma) => {
                        let _ = p.advance();
                        continue;
                    }
                    TokenKind::Punctuation(crate::lexer::Punctuation::RParen) if has_parens => {
                        let rparen = p.advance().expect_invariant(
                            "')' consumed in EXECUTE USING clause after expression",
                        );
                        using_rparen_span = Some(rparen.span);
                        end = rparen.span.end;
                        break;
                    }
                    TokenKind::Punctuation(crate::lexer::Punctuation::Semi) if !has_parens => {
                        // End of statement (no parens case) - don't consume semicolon
                        break;
                    }
                    TokenKind::Keyword(Keyword::Into) if !has_parens => {
                        // INTO clause follows (no parens case)
                        break;
                    }
                    _ if has_parens => {
                        return Err(ParseError::new(
                            next_tok.span,
                            ParseErrorKind::InvalidStatement {
                                message: format!(
                                    "Expected ',' or ')' in USING clause, found {}",
                                    Parser::token_description(next_tok, p.source)
                                ),
                            },
                        ));
                    }
                    _ => {
                        // Without parens, any other token ends the USING clause
                        break;
                    }
                }
            }
            continue; // Try next optional clause
        }

        // No more optional clauses to parse
        break;
    }

    // Don't consume semicolon - let outer wrapper handle it
    // Statement span ends at last parsed clause, not semicolon

    Ok(AstStmt::ExecuteImmediate {
        node_id: p.id_gen.next(),
        span: Span {
            start: stmt_start,
            end,
        },
        execute_span: execute_kw.span,
        immediate_span,
        sql_expr: Box::new(sql_expr),
        using_span,
        into_span,
        into_strict_span,
        using_args,
        using_lparen_span,
        using_rparen_span,
        into_vars,
        semicolon_token: None,
    })
}

/// Parse the Snowflake `EXECUTE IMMEDIATE FROM` form:
///   `EXECUTE IMMEDIATE FROM { @stage/path | '<rel_path>' | $$<rel_path>$$ }`
///     `[ USING ( <key> => <value> [, …] ) ] [ DRY_RUN = { TRUE | FALSE } ]`
/// The leading `EXECUTE IMMEDIATE` is already consumed; the next token is FROM.
fn parse_execute_immediate_from(
    p: &mut Parser<'_>,
    execute_span: Span,
    immediate_span: Span,
) -> ParseResult<AstStmt> {
    let from_tok = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["FROM".to_string()])?;
    let from_span = from_tok.span;

    // ── File location: a quoted/dollar relative path, or an `@…` stage path. ──
    p.skip_trivia();
    let loc_tok = p.peek_non_trivia().ok_or_else(|| {
        ParseError::new(
            p.current_span(),
            ParseErrorKind::InvalidStatement {
                message: "EXECUTE IMMEDIATE FROM requires a file location".to_string(),
            },
        )
    })?;
    let is_string = matches!(
        loc_tok.kind,
        TokenKind::Literal(crate::lexer::LiteralKind::String)
    );
    let is_dollar = !p.dialect.supports_dollar_quoted_strings()
        && matches!(loc_tok.kind, TokenKind::Identifier { .. })
        && crate::parser::core::is_dollar_quote_tag(loc_tok.lexeme(p.source));
    let loc_tok_span = loc_tok.span;

    let (location_kind, location_span) = if is_string {
        p.advance()
            .expect_invariant("relative-path string consumed after peek");
        (AstEifLocationKind::RelativePath, loc_tok_span)
    } else if is_dollar {
        // `$$./rel/file.sql$$` relative path in a dialect (Snowflake) whose
        // lexer does not natively produce a dollar-quoted string token.
        p.skip_trivia();
        let sp = p.reassemble_dollar_quoted_span();
        (AstEifLocationKind::RelativePath, sp)
    } else {
        // `@[<ns>.]<stage>/<path>/<file>` — an adjacent token run beginning
        // with `@` (mirrors the stage-ref capture in stage file commands).
        let stage_span = consume_stage_path_span(p).ok_or_else(|| {
            ParseError::new(
                loc_tok_span,
                ParseErrorKind::InvalidStatement {
                    message:
                        "EXECUTE IMMEDIATE FROM requires a stage path (@…) or quoted relative path"
                            .to_string(),
                },
            )
        })?;
        (AstEifLocationKind::StagePath, stage_span)
    };
    let mut end = location_span.end;

    // ── Optional USING ( k => v, … ) and DRY_RUN = TRUE|FALSE, in any order. ──
    let mut using_span: Option<Span> = None;
    let mut using_keys: Vec<Span> = Vec::new();
    let mut dry_run: Option<bool> = None;
    let mut dry_run_span: Option<Span> = None;

    for _ in 0..2 {
        p.skip_trivia();
        let (is_using, is_dry_run) = {
            let Some(tok) = p.peek_non_trivia() else {
                break;
            };
            (
                matches!(tok.kind, TokenKind::Keyword(Keyword::Using)),
                matches!(tok.kind, TokenKind::Identifier { .. })
                    && tok.lexeme(p.source).eq_ignore_ascii_case("DRY_RUN"),
            )
        };

        if using_span.is_none() && is_using {
            let using_kw = p.advance().expect_invariant("USING consumed after peek");
            using_span = Some(using_kw.span);
            end = using_kw.span.end;

            p.skip_trivia();
            let has_lparen = matches!(
                p.peek_non_trivia(),
                Some(t) if matches!(t.kind, TokenKind::Punctuation(Punctuation::LParen))
            );
            if has_lparen {
                let lp = p.advance().expect_invariant("USING ( consumed");
                end = lp.span.end;
                let mut depth = 1usize;
                while depth > 0 {
                    p.skip_trivia();
                    let Some((tspan, is_lp, is_rp, is_ident)) = p.peek_non_trivia().map(|t| {
                        (
                            t.span,
                            matches!(t.kind, TokenKind::Punctuation(Punctuation::LParen)),
                            matches!(t.kind, TokenKind::Punctuation(Punctuation::RParen)),
                            matches!(t.kind, TokenKind::Identifier { .. }),
                        )
                    }) else {
                        break;
                    };
                    end = tspan.end;
                    if is_lp {
                        depth += 1;
                        p.advance().expect_invariant("USING nested ( consumed");
                        continue;
                    }
                    if is_rp {
                        depth -= 1;
                        p.advance().expect_invariant("USING ) consumed");
                        continue;
                    }
                    // A `<key>` is an identifier at the top level (depth 1)
                    // immediately followed by `=>`; nested-paren operands sit
                    // at depth > 1 and are never mistaken for keys.
                    if depth == 1 && is_ident {
                        p.advance().expect_invariant("USING token consumed");
                        p.skip_trivia();
                        let is_arrow = matches!(
                            p.peek_non_trivia(),
                            Some(t) if matches!(t.kind, TokenKind::Operator(crate::lexer::Operator::EqGt))
                        );
                        if is_arrow {
                            using_keys.push(tspan);
                        }
                        continue;
                    }
                    p.advance().expect_invariant("USING value token consumed");
                }
            }
        } else if dry_run.is_none() && is_dry_run {
            let dr_kw = p.advance().expect_invariant("DRY_RUN consumed after peek");
            dry_run_span = Some(dr_kw.span);
            end = dr_kw.span.end;

            // `=`
            p.skip_trivia();
            let has_eq = matches!(
                p.peek_non_trivia(),
                Some(t) if matches!(t.kind, TokenKind::Operator(crate::lexer::Operator::Eq))
            );
            if has_eq {
                let eq = p.advance().expect_invariant("DRY_RUN = consumed");
                end = eq.span.end;
            }

            // value TRUE | FALSE
            p.skip_trivia();
            let val = p.peek_non_trivia().and_then(|t| {
                let lex = t.lexeme(p.source);
                if lex.eq_ignore_ascii_case("TRUE") {
                    Some(true)
                } else if lex.eq_ignore_ascii_case("FALSE") {
                    Some(false)
                } else {
                    None
                }
            });
            if val.is_some() {
                let vt = p.advance().expect_invariant("DRY_RUN value consumed");
                end = vt.span.end;
                dry_run = val;
            }
        } else {
            break;
        }
    }

    let ast = AstExecuteImmediateFrom {
        node_id: p.id_gen.next(),
        span: Span {
            start: execute_span.start,
            end,
        },
        execute_span,
        immediate_span,
        from_span,
        location_kind,
        location_span,
        using_span,
        using_keys,
        dry_run,
        dry_run_span,
    };
    Ok(AstStmt::ExecuteImmediateFrom(Box::new(ast)))
}

/// Consume an `@[<namespace>.]<stage>/<path>/<file>` stage path: the leading
/// `@` token plus all whitespace-adjacent path tokens. Returns the covering
/// span, or `None` if the next token does not begin with `@`.
fn consume_stage_path_span(p: &mut Parser<'_>) -> Option<Span> {
    let starts_with_at = p
        .peek_non_trivia()
        .map(|t| t.lexeme(p.source).starts_with('@'))
        .unwrap_or(false);
    if !starts_with_at {
        return None;
    }
    let head = p.advance().expect_invariant("@ stage-path head consumed");
    let mut span = head.span;
    while let Some((tstart, tend, is_term)) = p.peek_non_trivia().map(|t| {
        (
            t.span.start,
            t.span.end,
            matches!(
                t.kind,
                TokenKind::Punctuation(Punctuation::Semi) | TokenKind::Eof
            ),
        )
    }) {
        // A whitespace gap (or terminator) ends the contiguous path run.
        if is_term || tstart != span.end {
            break;
        }
        span.end = tend;
        p.advance().expect_invariant("stage-path token consumed");
    }
    Some(span)
}

pub(crate) fn try_parse_call_stmt(p: &mut Parser<'_>) -> ParseResult<AstStmt> {
    // Parse: CALL procedure_name([args]);
    let call_kw = p.advance().ok_or_else(|| {
        ParseError::new(
            p.current_span(),
            ParseErrorKind::InvalidStatement {
                message: "Expected CALL keyword".to_string(),
            },
        )
    })?;
    if !matches!(call_kw.kind, TokenKind::Keyword(Keyword::Call)) {
        return Err(ParseError::new(
            call_kw.span,
            ParseErrorKind::InvalidStatement {
                message: format!(
                    "Expected CALL keyword, found {}",
                    Parser::token_description(call_kw, p.source)
                ),
            },
        ));
    }

    let stmt_start = call_kw.span.start;
    let call_keyword_token = p.last_token_id();

    // Parse procedure name (can be qualified: schema.procedure or database.schema.procedure)
    // Collect tokens until we hit opening paren or semicolon
    p.skip_trivia();
    let first_name = p.peek_non_trivia().ok_or_else(|| {
        ParseError::new(
            p.current_span(),
            ParseErrorKind::InvalidStatement {
                message: "CALL requires procedure name".to_string(),
            },
        )
    })?;
    let name_start = first_name.span.start;
    let mut name_end = first_name.span.end;

    // Consume the identifier(s) and dots for qualified names
    while let Some(tok) = p.peek_non_trivia() {
        match &tok.kind {
            TokenKind::Identifier { .. }
            | TokenKind::Punctuation(crate::lexer::Punctuation::Dot) => {
                let t = p
                    .advance()
                    .expect_invariant("qualified name component consumed in CALL statement");
                name_end = t.span.end;
            }
            _ => break,
        }
    }

    let procedure_name_span = Span {
        start: name_start,
        end: name_end,
    };

    let mut end = name_end;
    let mut args_span = None;
    let mut lparen_token = None;
    let mut rparen_token = None;
    let mut typed_args: Vec<crate::ast::AstCallArg> = Vec::new();

    // Optional argument list in parentheses
    if let Some(tok) = p.peek_non_trivia() {
        if matches!(
            tok.kind,
            TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
        ) {
            let lparen = p
                .advance()
                .expect_invariant("'(' consumed after match in CALL arguments");
            lparen_token = Some(p.last_token_id());
            let args_start = lparen.span.start;
            let mut args_end = lparen.span.end;

            // Parse each argument as a typed expression with optional
            // `@name =` / `name =>` prefix. Loop until matching `)`.
            loop {
                p.skip_trivia();
                let peek = match p.peek_non_trivia() {
                    Some(t) => t,
                    None => break,
                };
                if matches!(
                    peek.kind,
                    TokenKind::Punctuation(crate::lexer::Punctuation::RParen)
                ) {
                    let rparen = p
                        .advance()
                        .expect_invariant("')' consumed in CALL arguments");
                    rparen_token = Some(p.last_token_id());
                    args_end = rparen.span.end;
                    break;
                }

                let arg_start = peek.span.start;
                let saved_idx = p.idx;

                // Named-arg detection: `@name =` (with `=` NOT
                // immediately followed by `>`) or `name =>`.
                let mut name_id: Option<crate::ast::AstIdentifier> = None;
                let mut name_op_span: Option<Span> = None;
                let is_at_var = matches!(
                    peek.kind,
                    TokenKind::Identifier {
                        kind: crate::lexer::IdentifierKind::AtVariable
                    }
                );
                let is_bare = matches!(
                    peek.kind,
                    TokenKind::Identifier {
                        kind: crate::lexer::IdentifierKind::Unquoted
                    }
                );
                if is_at_var || is_bare {
                    let name_span_candidate = peek.span;
                    let _ = p.advance();
                    if let Some(next) = p.peek() {
                        let next_kind = next.kind.clone();
                        let next_span = next.span;
                        if matches!(next_kind, TokenKind::Operator(crate::lexer::Operator::Eq)) {
                            let eq_span = next_span;
                            let _ = p.advance();
                            // Distinguish `=` vs `=>`.
                            let is_arrow = p
                                .peek()
                                .map(|n| {
                                    n.span.start == eq_span.end
                                        && matches!(
                                            n.kind,
                                            TokenKind::Operator(crate::lexer::Operator::Gt)
                                        )
                                })
                                .unwrap_or(false);
                            if is_arrow && is_bare {
                                let gt_span = p
                                    .advance()
                                    .expect_invariant("'>' consumed for => operator")
                                    .span;
                                name_id = Some(crate::ast::AstIdentifier {
                                    node_id: p.id_gen.next(),
                                    span: name_span_candidate,
                                });
                                name_op_span = Some(Span {
                                    start: eq_span.start,
                                    end: gt_span.end,
                                });
                            } else if !is_arrow && is_at_var {
                                name_id = Some(crate::ast::AstIdentifier {
                                    node_id: p.id_gen.next(),
                                    span: name_span_candidate,
                                });
                                name_op_span = Some(eq_span);
                            } else {
                                p.idx = saved_idx;
                            }
                        } else {
                            p.idx = saved_idx;
                        }
                    } else {
                        p.idx = saved_idx;
                    }
                }

                let expr = match p.parse_expr() {
                    Ok(e) => e,
                    Err(_) => {
                        // Expression parser bailed — fall back to raw
                        // span coverage by draining tokens up to the
                        // matching `)`.
                        p.idx = saved_idx;
                        let mut depth = 1u32;
                        while depth > 0 {
                            let tok = match p.peek_non_trivia() {
                                Some(t) => t,
                                None => break,
                            };
                            match tok.kind {
                                TokenKind::Punctuation(crate::lexer::Punctuation::LParen) => {
                                    depth += 1
                                }
                                TokenKind::Punctuation(crate::lexer::Punctuation::RParen) => {
                                    depth -= 1
                                }
                                _ => {}
                            }
                            let t = p
                                .advance()
                                .expect_invariant("token consumed in CALL fallback");
                            args_end = t.span.end;
                            if depth == 0 {
                                rparen_token = Some(p.last_token_id());
                                break;
                            }
                        }
                        typed_args.clear();
                        break;
                    }
                };
                let expr_end = expr_span_end(&expr);
                args_end = expr_end;
                typed_args.push(crate::ast::AstCallArg {
                    node_id: p.id_gen.next(),
                    span: Span {
                        start: arg_start,
                        end: expr_end,
                    },
                    name: name_id,
                    name_op_span,
                    value: expr,
                });

                // After each arg: expect `,` (continue) or `)` (end).
                p.skip_trivia();
                if let Some(sep) = p.peek_non_trivia() {
                    if matches!(
                        sep.kind,
                        TokenKind::Punctuation(crate::lexer::Punctuation::Comma)
                    ) {
                        let _ = p.advance();
                        continue;
                    }
                }
            }

            args_span = Some(Span {
                start: args_start,
                end: args_end,
            });
            end = args_end;
        }
    }

    // Don't consume semicolon - let outer wrapper handle it
    // Statement span ends at arguments, not semicolon

    // Create syntax node
    let syntax_id = {
        use crate::syntax::SyntaxCallStmt;
        let syntax_node = SyntaxCallStmt {
            call_keyword: call_keyword_token,
            l_paren: lparen_token,
            r_paren: rparen_token,
            semicolon: None,
            span: Span {
                start: stmt_start,
                end,
            },
        };
        Some(p.syntax_arena.alloc_call_stmt(syntax_node))
    };

    // Capture semicolon if present (don't consume - block loop will skip it)
    let semicolon_token = if let Some(tok) = p.peek_non_trivia() {
        if matches!(
            tok.kind,
            TokenKind::Punctuation(crate::lexer::Punctuation::Semi)
        ) {
            Some(p.current_token_id())
        } else {
            None
        }
    } else {
        None
    };

    Ok(AstStmt::Call {
        node_id: p.id_gen.next(),
        span: Span {
            start: stmt_start,
            end,
        },
        call_span: call_kw.span,
        procedure_name_span,
        args_span,
        args: typed_args,
        syntax_id,
        semicolon_token,
        odbc: None,
    })
}

/// True when the parser is at an ODBC call escape opener: `{` followed by
/// `call`, or by the `? =` return marker and then `call`.
pub(crate) fn is_odbc_call_escape_at(p: &Parser<'_>) -> bool {
    if matches!(
        p.peek_ahead(1).map(|t| &t.kind),
        Some(TokenKind::Keyword(Keyword::Call))
    ) {
        return true;
    }
    matches!(
        p.peek_ahead(1).map(|t| &t.kind),
        Some(TokenKind::Placeholder)
    ) && matches!(
        p.peek_ahead(2).map(|t| &t.kind),
        Some(TokenKind::Operator(crate::lexer::Operator::Eq))
    ) && matches!(
        p.peek_ahead(3).map(|t| &t.kind),
        Some(TokenKind::Keyword(Keyword::Call))
    )
}

/// Parse the ODBC call escape: `{call p(...)}` / `{? = call p(...)}`.
/// Delegates to [`try_parse_call_stmt`] for the CALL body; the braces and
/// optional `? =` return marker are recorded on the statement so the
/// formatter re-emits the whole span verbatim. Consumers see the same
/// `AstStmt::Call` as native CALL.
pub(crate) fn try_parse_odbc_call_stmt(p: &mut Parser<'_>) -> ParseResult<AstStmt> {
    let lcurly = p.advance().ok_or_else(|| {
        ParseError::new(
            p.current_span(),
            ParseErrorKind::InvalidStatement {
                message: "Expected '{' opening ODBC call escape".to_string(),
            },
        )
    })?;
    let lcurly_span = lcurly.span;

    // Optional `? =` return-value marker
    let mut return_marker_span = None;
    if let Some(tok) = p.peek_non_trivia() {
        if matches!(tok.kind, TokenKind::Placeholder) {
            let q = p
                .advance()
                .expect_invariant("Placeholder confirmed by peek");
            return_marker_span = Some(q.span);
            let eq_is_next = matches!(
                p.peek_non_trivia().map(|t| &t.kind),
                Some(TokenKind::Operator(crate::lexer::Operator::Eq))
            );
            if !eq_is_next {
                return Err(ParseError::new(
                    p.current_span(),
                    ParseErrorKind::InvalidStatement {
                        message: "Expected '=' after '?' in ODBC {? = call ...} escape".to_string(),
                    },
                ));
            }
            let _ = p.advance(); // consume =
        }
    }

    p.odbc_depth += 1;
    let inner = try_parse_call_stmt(p);
    p.odbc_depth -= 1;
    let mut stmt = inner?;

    let rcurly_span = p.expect_odbc_rcurly()?;

    // Re-capture the trailing semicolon: the inner capture saw `}` → None.
    let semicolon = if let Some(tok) = p.peek_non_trivia() {
        if matches!(
            tok.kind,
            TokenKind::Punctuation(crate::lexer::Punctuation::Semi)
        ) {
            Some(p.current_token_id())
        } else {
            None
        }
    } else {
        None
    };

    // try_parse_call_stmt always returns AstStmt::Call on success.
    if let AstStmt::Call {
        span,
        odbc,
        semicolon_token,
        ..
    } = &mut stmt
    {
        span.start = lcurly_span.start;
        span.end = rcurly_span.end;
        *odbc = Some(crate::ast::AstOdbcCallEscape { return_marker_span });
        *semicolon_token = semicolon;
    }
    Ok(stmt)
}

pub(crate) fn try_parse_begin_transaction_stmt(p: &mut Parser<'_>) -> ParseResult<AstStmt> {
    // Parse: BEGIN [WORK | TRANSACTION] [NAME <name>];
    let begin_kw = p.advance().ok_or_else(|| {
        ParseError::new(
            p.current_span(),
            ParseErrorKind::InvalidStatement {
                message: "Expected BEGIN keyword".to_string(),
            },
        )
    })?;

    if !matches!(begin_kw.kind, TokenKind::Keyword(Keyword::Begin)) {
        return Err(ParseError::new(
            begin_kw.span,
            ParseErrorKind::InvalidStatement {
                message: format!(
                    "Expected BEGIN keyword, found {}",
                    Parser::token_description(begin_kw, p.source)
                ),
            },
        ));
    }

    let stmt_start = begin_kw.span.start;
    let mut end = begin_kw.span.end;

    p.skip_trivia();

    // Optional WORK or TRANSACTION keyword
    if let Some(tok) = p.peek_non_trivia() {
        if matches!(tok.kind, TokenKind::Keyword(Keyword::Work))
            || matches!(tok.kind, TokenKind::Keyword(Keyword::Transaction))
        {
            let kw = p
                .advance()
                .expect_invariant("WORK/TRANSACTION keyword consumed in BEGIN TRANSACTION");
            end = kw.span.end;
            p.skip_trivia();
        }
    }

    // Optional NAME <name>
    if let Some(tok) = p.peek_non_trivia() {
        if p.can_be_identifier_token(tok) && tok.lexeme(p.source).eq_ignore_ascii_case("NAME") {
            p.advance(); // Skip NAME
            p.skip_trivia();

            // Get the transaction name
            if let Some(name_tok) = p.peek_non_trivia() {
                if p.can_be_identifier_token(name_tok) {
                    let name = p.advance().expect_invariant(
                        "transaction name identifier consumed after NAME in BEGIN",
                    );
                    end = name.span.end;
                } else {
                    return Err(ParseError::new(
                        name_tok.span,
                        ParseErrorKind::InvalidStatement {
                            message: "Expected transaction name identifier after NAME".to_string(),
                        },
                    ));
                }
            } else {
                return Err(ParseError::new(
                    p.current_span(),
                    ParseErrorKind::InvalidStatement {
                        message: "Expected transaction name identifier after NAME".to_string(),
                    },
                ));
            }
        }
    }

    // Don't consume semicolon - let outer wrapper handle it
    // Statement span ends at last parsed token, not semicolon

    Ok(AstStmt::BeginTransaction {
        node_id: p.id_gen.next(),
        span: Span {
            start: stmt_start,
            end,
        },
    })
}

pub(crate) fn try_parse_start_transaction_stmt(p: &mut Parser<'_>) -> ParseResult<AstStmt> {
    // Parse: START TRANSACTION [NAME <name>];
    let start_kw = p.advance().ok_or_else(|| {
        ParseError::new(
            p.current_span(),
            ParseErrorKind::InvalidStatement {
                message: "Expected START keyword".to_string(),
            },
        )
    })?;

    if !matches!(start_kw.kind, TokenKind::Keyword(Keyword::Start)) {
        return Err(ParseError::new(
            start_kw.span,
            ParseErrorKind::InvalidStatement {
                message: format!(
                    "Expected START keyword, found {}",
                    Parser::token_description(start_kw, p.source)
                ),
            },
        ));
    }

    let stmt_start = start_kw.span.start;
    p.skip_trivia();

    // Expect TRANSACTION keyword
    let transaction_kw = p.advance().ok_or_else(|| {
        ParseError::new(
            p.current_span(),
            ParseErrorKind::InvalidStatement {
                message: "START must be followed by TRANSACTION".to_string(),
            },
        )
    })?;
    if !matches!(
        transaction_kw.kind,
        TokenKind::Keyword(Keyword::Transaction)
    ) {
        return Err(ParseError::new(
            transaction_kw.span,
            ParseErrorKind::InvalidStatement {
                message: format!(
                    "START must be followed by TRANSACTION, found {}",
                    Parser::token_description(transaction_kw, p.source)
                ),
            },
        ));
    }

    let mut end = transaction_kw.span.end;
    p.skip_trivia();

    // Optional NAME <name>
    if let Some(tok) = p.peek_non_trivia() {
        if p.can_be_identifier_token(tok) && tok.lexeme(p.source).eq_ignore_ascii_case("NAME") {
            p.advance(); // Skip NAME
            p.skip_trivia();

            // Get the transaction name
            if let Some(name_tok) = p.peek_non_trivia() {
                if p.can_be_identifier_token(name_tok) {
                    let name = p
                        .advance()
                        .expect_invariant("transaction name identifier consumed in COMMIT NAME");
                    end = name.span.end;
                } else {
                    return Err(ParseError::new(
                        name_tok.span,
                        ParseErrorKind::InvalidStatement {
                            message: "Expected transaction name identifier after NAME".to_string(),
                        },
                    ));
                }
            } else {
                return Err(ParseError::new(
                    p.current_span(),
                    ParseErrorKind::InvalidStatement {
                        message: "Expected transaction name identifier after NAME".to_string(),
                    },
                ));
            }
        }
    }

    // Don't consume semicolon - let outer wrapper handle it
    // Statement span ends at last parsed token, not semicolon

    Ok(AstStmt::BeginTransaction {
        node_id: p.id_gen.next(),
        span: Span {
            start: stmt_start,
            end,
        },
    })
}

pub(crate) fn try_parse_commit_stmt(p: &mut Parser<'_>) -> ParseResult<AstStmt> {
    // Parse: COMMIT [WORK];
    let commit_kw = p.advance().ok_or_else(|| {
        ParseError::new(
            p.current_span(),
            ParseErrorKind::InvalidStatement {
                message: "Expected COMMIT keyword".to_string(),
            },
        )
    })?;

    if !matches!(commit_kw.kind, TokenKind::Keyword(Keyword::Commit)) {
        return Err(ParseError::new(
            commit_kw.span,
            ParseErrorKind::InvalidStatement {
                message: format!(
                    "Expected COMMIT keyword, found {}",
                    Parser::token_description(commit_kw, p.source)
                ),
            },
        ));
    }

    let stmt_start = commit_kw.span.start;
    let mut end = commit_kw.span.end;

    p.skip_trivia();

    // Optional WORK or TRANSACTION keyword
    if let Some(tok) = p.peek_non_trivia() {
        if matches!(
            tok.kind,
            TokenKind::Keyword(Keyword::Work) | TokenKind::Keyword(Keyword::Transaction)
        ) {
            let kw = p
                .advance()
                .expect_invariant("WORK/TRANSACTION keyword consumed after match in COMMIT");
            end = kw.span.end;
        }
    }

    // Don't consume semicolon - let outer wrapper handle it
    // Statement span ends at COMMIT or WORK/TRANSACTION keyword, not semicolon

    Ok(AstStmt::Commit {
        node_id: p.id_gen.next(),
        span: Span {
            start: stmt_start,
            end,
        },
    })
}

pub(crate) fn try_parse_rollback_stmt(p: &mut Parser<'_>) -> ParseResult<AstStmt> {
    // Parse: ROLLBACK [WORK];
    let rollback_kw = p.advance().ok_or_else(|| {
        ParseError::new(
            p.current_span(),
            ParseErrorKind::InvalidStatement {
                message: "Expected ROLLBACK keyword".to_string(),
            },
        )
    })?;

    if !matches!(rollback_kw.kind, TokenKind::Keyword(Keyword::Rollback)) {
        return Err(ParseError::new(
            rollback_kw.span,
            ParseErrorKind::InvalidStatement {
                message: format!(
                    "Expected ROLLBACK keyword, found {}",
                    Parser::token_description(rollback_kw, p.source)
                ),
            },
        ));
    }

    let stmt_start = rollback_kw.span.start;
    let mut end = rollback_kw.span.end;

    p.skip_trivia();

    // Optional WORK or TRANSACTION keyword
    if let Some(tok) = p.peek_non_trivia() {
        if matches!(
            tok.kind,
            TokenKind::Keyword(Keyword::Work) | TokenKind::Keyword(Keyword::Transaction)
        ) {
            let kw = p
                .advance()
                .expect_invariant("WORK/TRANSACTION keyword consumed after match in ROLLBACK");
            end = kw.span.end;
        }
    }

    // Don't consume semicolon - let outer wrapper handle it
    // Statement span ends at ROLLBACK or WORK/TRANSACTION keyword, not semicolon

    Ok(AstStmt::Rollback {
        node_id: p.id_gen.next(),
        span: Span {
            start: stmt_start,
            end,
        },
    })
}

/// Parse a GRANT statement.
/// Snowflake GRANT syntax is extremely complex with many forms, among them:
/// - GRANT privileges TO ROLE
/// - GRANT OWNERSHIP ON object_type TO ROLE
/// - GRANT privilege TO SHARE
///
/// We parse this as a span-only statement, preserving original formatting.
/// The statement is consumed until a semicolon or EOF.
pub(crate) fn try_parse_grant_stmt(p: &mut Parser<'_>) -> ParseResult<AstStmt> {
    crate::parser::grant::parse_grant(p)
}

/// Parse a REVOKE statement. Delegates to the typed parser in
/// `crate::parser::grant`; falls back to span-only `Unparsed` body
/// internally if typed parsing of the body fails.
pub(crate) fn try_parse_revoke_stmt(p: &mut Parser<'_>) -> ParseResult<AstStmt> {
    crate::parser::grant::parse_revoke(p)
}

/// Parse a DENY statement (MSSQL). Delegates to the typed parser in
/// `parser/mssql_deny.rs`. The typed parser is always-succeeding —
/// malformed DENY degrades to an empty-privilege / empty-grantee
/// `AstDeny`.
pub(crate) fn try_parse_deny_stmt(p: &mut Parser<'_>) -> ParseResult<AstStmt> {
    crate::parser::mssql_deny::parse_deny(p)
}

/// Parse a scripting block, returning a Result with error information.
pub(crate) fn try_parse_scripting_block_from_tokens(
    source: &str,
    tokens: &[Token],
) -> crate::error::ParseResult<AstStmt> {
    let mut parser = Parser::new(source, tokens);
    // Check if it starts with DECLARE or BEGIN
    if let Some(tok) = parser.peek_non_trivia() {
        if matches!(tok.kind, TokenKind::Keyword(Keyword::Declare)) {
            // DECLARE...BEGIN...END block
            return try_parse_scripting_block(&mut parser);
        }
    }
    // Just BEGIN...END block
    try_parse_block_stmt(&mut parser)
}

/// Result-based parser for DECLARE...BEGIN...END blocks.
pub(crate) fn try_parse_scripting_block(p: &mut Parser<'_>) -> ParseResult<AstStmt> {
    // Enter scripting mode for the entire block (DECLARE and BEGIN sections)
    // This enables :variable references and ? placeholders in cursor queries
    let prev_mode = p.enter_mode(crate::parser::core::ParserMode::Scripting);

    let mut decls = Vec::new();
    let mut _loop_iter = 0;
    loop {
        _loop_iter += 1;
        p.skip_trivia();
        let tok = p.peek_non_trivia().ok_or_else(|| {
            ParseError::new(
                p.current_span(),
                ParseErrorKind::InvalidStatement {
                    message: "Expected DECLARE or BEGIN keyword in scripting block".to_string(),
                },
            )
        })?;

        match tok.kind {
            TokenKind::Keyword(Keyword::Declare) => {
                let decl_stmt = crate::parser::scripting::try_parse_declare_stmt(p)?;
                // Standalone declaration types (CONDITION, HANDLER) are complete
                // statements — they don't form a preamble before BEGIN.
                if matches!(
                    &decl_stmt,
                    AstStmt::DeclareCondition { .. } | AstStmt::DeclareHandler(_)
                ) {
                    p.restore_mode(prev_mode);
                    return Ok(decl_stmt);
                }
                decls.push(decl_stmt);
            }
            // In a multi-line DECLARE header, subsequent variable declarations
            // start with bare identifiers on their own lines.
            TokenKind::Identifier { .. } => {
                let decl_stmt = crate::parser::scripting::try_parse_declare_stmt(p)?;
                if matches!(
                    &decl_stmt,
                    AstStmt::DeclareCondition { .. } | AstStmt::DeclareHandler(_)
                ) {
                    p.restore_mode(prev_mode);
                    return Ok(decl_stmt);
                }
                decls.push(decl_stmt);
            }
            TokenKind::Keyword(Keyword::Begin) => {
                break;
            }
            TokenKind::Punctuation(crate::lexer::Punctuation::Semi) => {
                // Skip semicolons between DECLARE and BEGIN
                p.advance();
                continue;
            }
            _ => {
                p.restore_mode(prev_mode);
                return Err(ParseError::new(
                    tok.span,
                    ParseErrorKind::UnexpectedToken {
                        expected: vec!["DECLARE or BEGIN".to_string()],
                        found: Parser::token_description(tok, p.source),
                    },
                ));
            }
        }
    }

    let block_stmt = try_parse_block_stmt(p)?;

    // Restore previous parser mode
    p.restore_mode(prev_mode);

    match block_stmt {
        AstStmt::Block(b) => {
            let span = b.span;
            let declare_span = b.declare_span;
            let declare_token = b.declare_token;
            let begin_span = b.begin_span;
            let begin_token = b.begin_token;
            let block_decls = b.decls;
            let body = b.body;
            let exception = b.exception;
            let end_span = b.end_span;
            let end_token = b.end_token;
            // If we parsed DECLARE statements, extend span to cover them
            // and extract the DECLARE keyword span from the first declaration
            let (adjusted_span, block_declare_span, block_declare_token) = if !decls.is_empty() {
                let first_decl = &decls[0];
                let (first_declare_kw_span, first_declare_token) = match first_decl {
                    AstStmt::Declare {
                        declare_span: Some(kw_span),
                        declare_token,
                        ..
                    } => (Some(*kw_span), *declare_token),
                    AstStmt::DeclareCursor {
                        declare_span,
                        declare_token,
                        ..
                    } => (Some(*declare_span), *declare_token),
                    _ => (None, None),
                };
                (
                    Span {
                        start: first_decl.span().start,
                        end: span.end,
                    },
                    first_declare_kw_span,
                    first_declare_token,
                )
            } else {
                (span, declare_span, declare_token)
            };

            // Capture semicolon if present (don't consume - block loop will skip it)
            let semicolon_token = if let Some(tok) = p.peek_non_trivia() {
                if matches!(
                    tok.kind,
                    TokenKind::Punctuation(crate::lexer::Punctuation::Semi)
                ) {
                    Some(p.current_token_id())
                } else {
                    None
                }
            } else {
                None
            };

            Ok(AstStmt::Block(Box::new(AstBlockStmt {
                node_id: p.id_gen.next(),
                span: adjusted_span,
                label_span: None,
                end_label_span: None,
                declare_span: block_declare_span,
                declare_token: block_declare_token,
                begin_span,
                begin_token,
                atomic_span: None,
                decls: [decls, block_decls].concat(),
                body,
                exception,
                end_span,
                end_token,
                semicolon_token,
            })))
        }
        _ => Err(ParseError::new(
            p.current_span(),
            ParseErrorKind::InvalidStatement {
                message: "Expected BEGIN...END block after DECLARE statements".to_string(),
            },
        )),
    }
}

/// Parse an MSSQL TRY...CATCH error handling block.
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
pub(crate) fn try_parse_mssql_try_catch(p: &mut Parser<'_>) -> ParseResult<AstStmt> {
    let _depth = p.track_depth("mssql_try_catch")?;

    // ── BEGIN TRY ──
    let begin_try_tok = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["BEGIN keyword".to_string()])?;
    if !matches!(begin_try_tok.kind, TokenKind::Keyword(Keyword::Begin)) {
        return Err(ParseError::new(
            begin_try_tok.span,
            ParseErrorKind::UnexpectedToken {
                expected: vec!["BEGIN keyword".to_string()],
                found: Parser::token_description(begin_try_tok, p.source),
            },
        ));
    }
    p.skip_trivia();
    let try_kw = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["TRY keyword".to_string()])?;
    if !matches!(try_kw.kind, TokenKind::Keyword(Keyword::Try)) {
        return Err(ParseError::new(
            try_kw.span,
            ParseErrorKind::UnexpectedToken {
                expected: vec!["TRY keyword".to_string()],
                found: Parser::token_description(try_kw, p.source),
            },
        ));
    }
    let begin_try_span = Span {
        start: begin_try_tok.span.start,
        end: try_kw.span.end,
    };

    // ── TRY body ──
    let (try_body, _try_errors) = parse_body_with_recovery(
        p,
        StmtContext::Block,
        begin_try_tok.span.start,
        &[BodyTerminator::End],
    );

    // ── END TRY ──
    let end_try_tok = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["END keyword".to_string()])?;
    if !matches!(end_try_tok.kind, TokenKind::Keyword(Keyword::End)) {
        return Err(ParseError::new(
            end_try_tok.span,
            ParseErrorKind::UnexpectedToken {
                expected: vec!["END keyword".to_string()],
                found: Parser::token_description(end_try_tok, p.source),
            },
        ));
    }
    p.skip_trivia();
    let end_try_kw = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["TRY keyword".to_string()])?;
    if !matches!(end_try_kw.kind, TokenKind::Keyword(Keyword::Try)) {
        return Err(ParseError::new(
            end_try_kw.span,
            ParseErrorKind::UnexpectedToken {
                expected: vec!["TRY keyword after END".to_string()],
                found: Parser::token_description(end_try_kw, p.source),
            },
        ));
    }
    let end_try_span = Span {
        start: end_try_tok.span.start,
        end: end_try_kw.span.end,
    };

    // ── BEGIN CATCH ──
    p.skip_trivia();
    let begin_catch_tok = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["BEGIN keyword".to_string()])?;
    if !matches!(begin_catch_tok.kind, TokenKind::Keyword(Keyword::Begin)) {
        return Err(ParseError::new(
            begin_catch_tok.span,
            ParseErrorKind::UnexpectedToken {
                expected: vec!["BEGIN keyword for CATCH block".to_string()],
                found: Parser::token_description(begin_catch_tok, p.source),
            },
        ));
    }
    p.skip_trivia();
    let catch_kw = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["CATCH keyword".to_string()])?;
    if !matches!(catch_kw.kind, TokenKind::Keyword(Keyword::Catch)) {
        return Err(ParseError::new(
            catch_kw.span,
            ParseErrorKind::UnexpectedToken {
                expected: vec!["CATCH keyword".to_string()],
                found: Parser::token_description(catch_kw, p.source),
            },
        ));
    }
    let begin_catch_span = Span {
        start: begin_catch_tok.span.start,
        end: catch_kw.span.end,
    };

    // ── CATCH body ──
    let (catch_body, _catch_errors) = parse_body_with_recovery(
        p,
        StmtContext::Block,
        begin_catch_tok.span.start,
        &[BodyTerminator::End],
    );

    // ── END CATCH ──
    let end_catch_tok = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["END keyword".to_string()])?;
    if !matches!(end_catch_tok.kind, TokenKind::Keyword(Keyword::End)) {
        return Err(ParseError::new(
            end_catch_tok.span,
            ParseErrorKind::UnexpectedToken {
                expected: vec!["END keyword".to_string()],
                found: Parser::token_description(end_catch_tok, p.source),
            },
        ));
    }
    p.skip_trivia();
    let end_catch_kw = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["CATCH keyword".to_string()])?;
    if !matches!(end_catch_kw.kind, TokenKind::Keyword(Keyword::Catch)) {
        return Err(ParseError::new(
            end_catch_kw.span,
            ParseErrorKind::UnexpectedToken {
                expected: vec!["CATCH keyword after END".to_string()],
                found: Parser::token_description(end_catch_kw, p.source),
            },
        ));
    }
    let end_catch_span = Span {
        start: end_catch_tok.span.start,
        end: end_catch_kw.span.end,
    };

    // Capture semicolon if present (don't consume — block loop will skip it)
    let semicolon_token = if let Some(semi_tok) = p.peek_non_trivia() {
        if matches!(
            semi_tok.kind,
            TokenKind::Punctuation(crate::lexer::Punctuation::Semi)
        ) {
            Some(p.current_token_id())
        } else {
            None
        }
    } else {
        None
    };

    let stmt_span = Span {
        start: begin_try_span.start,
        end: end_catch_span.end,
    };

    Ok(AstStmt::MssqlTryCatch(Box::new(
        crate::ast::AstMssqlTryCatch {
            node_id: p.id_gen.next(),
            span: stmt_span,
            begin_try_span,
            try_body,
            end_try_span,
            begin_catch_span,
            catch_body,
            end_catch_span,
            semicolon_token,
        },
    )))
}

// ════════════════════════════════════════════════════════════════════════════
// MSSQL-style IF...ELSE  (no THEN / END IF)
// ════════════════════════════════════════════════════════════════════════════

/// Parse a single statement for use as the body of MSSQL IF / WHILE.
///
/// In T-SQL, IF/WHILE bodies are exactly **one** statement, which may be a
/// `BEGIN...END` block when multiple statements are needed.
fn parse_mssql_body_statement(p: &mut Parser<'_>) -> ParseResult<AstStmt> {
    p.skip_trivia();
    let tok = p.peek_non_trivia().ok_or_else(|| {
        ParseError::unexpected_eof(p.current_span(), vec!["statement".to_string()])
    })?;

    match &tok.kind {
        // BEGIN can start: block | TRY...CATCH | TRANSACTION
        TokenKind::Keyword(Keyword::Begin) => {
            let saved = p.idx;
            let _ = p.advance();
            p.skip_trivia();

            let next_kind = p.peek_non_trivia().map(|t| t.kind.clone());
            p.idx = saved;

            match next_kind {
                Some(TokenKind::Keyword(Keyword::Try)) => try_parse_mssql_try_catch(p),
                Some(TokenKind::Keyword(Keyword::Transaction))
                | Some(TokenKind::Keyword(Keyword::Work)) => p.try_parse_begin_transaction_stmt(),
                _ => try_parse_block_stmt(p),
            }
        }
        // Nested control flow
        TokenKind::Keyword(Keyword::If) => try_parse_mssql_if(p),
        TokenKind::Keyword(Keyword::While) => try_parse_mssql_while(p),
        // Loop control
        TokenKind::Keyword(Keyword::Break)
        | TokenKind::Keyword(Keyword::Continue)
        | TokenKind::Keyword(Keyword::Exit) => try_parse_loop_control_stmt_in_block(p),
        // Return
        TokenKind::Keyword(Keyword::Return) => try_parse_return_stmt_in_block(p),
        // Standalone DECLARE (e.g. DECLARE @x INT = 5)
        TokenKind::Keyword(Keyword::Declare) => try_parse_declare_stmt(p),
        // Everything else: regular SQL (SELECT, SET, INSERT, UPDATE, etc.)
        _ => p.parse_flow_statement(),
    }
}

/// Parse MSSQL `IF condition statement [ELSE statement]`.
///
/// Unlike Snowflake's `IF...THEN...END IF`, T-SQL IF uses:
/// - No THEN keyword after the condition
/// - No END IF terminator
/// - Each branch is exactly **one** statement (use `BEGIN...END` for blocks)
pub(crate) fn try_parse_mssql_if(p: &mut Parser<'_>) -> ParseResult<AstStmt> {
    let _depth = p.track_depth("mssql_if")?;

    // ── IF keyword ──
    let if_tok = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["IF".to_string()])?;
    debug_assert!(matches!(if_tok.kind, TokenKind::Keyword(Keyword::If)));
    let if_span = if_tok.span;

    // ── Condition expression ──
    // Special case: MSSQL trigger predicates UPDATE(col) and COLUMNS_UPDATED()
    // These use keywords (UPDATE/INSERT) as function-like predicates.
    let cond_expr = {
        let maybe_trigger_pred = if let Some(tok) = p.peek_non_trivia() {
            matches!(
                tok.kind,
                TokenKind::Keyword(Keyword::Update) | TokenKind::Keyword(Keyword::Insert)
            ) && p.peek_ahead(1).is_some_and(|t| {
                matches!(
                    t.kind,
                    TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
                )
            })
        } else {
            false
        };
        if maybe_trigger_pred {
            // Parse UPDATE(col) / INSERT(col) as a function call expression
            let func_tok = p
                .advance()
                .ok_or_eof(p.current_span(), vec!["UPDATE or INSERT".to_string()])?;
            let func_start = func_tok.span.start;
            let _lparen = p
                .advance()
                .ok_or_eof(p.current_span(), vec!["(".to_string()])?;
            // Consume balanced parens
            let mut depth = 1u32;
            let mut paren_end = _lparen.span.end;
            while depth > 0 {
                let inner = p
                    .advance()
                    .ok_or_eof(p.current_span(), vec![")".to_string()])?;
                match inner.kind {
                    TokenKind::Punctuation(crate::lexer::Punctuation::LParen) => depth += 1,
                    TokenKind::Punctuation(crate::lexer::Punctuation::RParen) => {
                        depth -= 1;
                        if depth == 0 {
                            paren_end = inner.span.end;
                        }
                    }
                    _ => {}
                }
            }
            let span = Span {
                start: func_start,
                end: paren_end,
            };
            // Represent as placeholder with the full span (preserves text exactly)
            AstExpr::Placeholder {
                node_id: p.id_gen.next(),
                span,
            }
        } else {
            try_parse_expr_scripting(p).map_err(|_| {
                ParseError::invalid_expression(
                    p.current_span(),
                    "MSSQL IF requires a condition expression".to_string(),
                )
            })?
        }
    };
    let condition_span = cond_expr.span();

    // ── Then body: parse exactly one statement ──
    let then_stmt = parse_mssql_body_statement(p)?;
    let mut end = then_stmt.span().end;
    let then_body = vec![then_stmt];

    // ── Check for optional semicolon then ELSE ──
    // We lookahead past optional semicolons + trivia. If ELSE follows,
    // the semicolons are internal to the IF and we consume them.
    // If no ELSE, restore position so the script-level parser handles them.
    let saved_idx = p.idx;
    p.skip_trivia();

    // Consume any semicolons between then-body and ELSE
    while matches!(
        p.peek_non_trivia().map(|t| &t.kind),
        Some(TokenKind::Punctuation(crate::lexer::Punctuation::Semi))
    ) {
        p.advance()
            .ok_or_eof(p.current_span(), vec![";".to_string()])?;
        p.skip_trivia();
    }

    let has_else = matches!(
        p.peek_non_trivia().map(|t| &t.kind),
        Some(TokenKind::Keyword(Keyword::Else))
    );

    let (else_span, else_body) = if has_else {
        // ── ELSE keyword ──
        let else_tok = p
            .advance()
            .ok_or_eof(p.current_span(), vec!["ELSE".to_string()])?;
        let else_kw_span = else_tok.span;

        // ── Else body: parse exactly one statement ──
        let else_stmt = parse_mssql_body_statement(p)?;
        end = else_stmt.span().end;

        // Consume trailing semicolon after else body (same pattern as then-branch)
        if matches!(
            p.peek_non_trivia().map(|t| &t.kind),
            Some(TokenKind::Punctuation(crate::lexer::Punctuation::Semi))
        ) {
            let semi = p
                .advance()
                .ok_or_eof(p.current_span(), vec![";".to_string()])?;
            end = semi.span.end;
        }

        let else_body = vec![else_stmt];

        (Some(else_kw_span), else_body)
    } else {
        // No ELSE — restore position (don't consume the semicolons)
        p.idx = saved_idx;
        (None, Vec::new())
    };

    let stmt_span = Span {
        start: if_span.start,
        end,
    };

    Ok(AstStmt::MssqlIf(Box::new(crate::ast::AstMssqlIf {
        node_id: p.id_gen.next(),
        span: stmt_span,
        if_span,
        condition_span,
        then_body,
        else_span,
        else_body,
    })))
}

// ════════════════════════════════════════════════════════════════════════════
// MSSQL-style WHILE  (no DO / END WHILE)
// ════════════════════════════════════════════════════════════════════════════

/// Parse MSSQL `WHILE condition statement`.
///
/// Unlike Snowflake's `WHILE...DO...END WHILE`, T-SQL WHILE uses:
/// - No DO keyword after the condition
/// - No END WHILE terminator
/// - The body is exactly **one** statement (use `BEGIN...END` for blocks)
pub(crate) fn try_parse_mssql_while(p: &mut Parser<'_>) -> ParseResult<AstStmt> {
    let _depth = p.track_depth("mssql_while")?;

    // ── WHILE keyword ──
    let while_tok = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["WHILE".to_string()])?;
    debug_assert!(matches!(while_tok.kind, TokenKind::Keyword(Keyword::While)));
    let while_span = while_tok.span;

    // ── Condition expression ──
    let cond_expr = try_parse_expr_scripting(p).map_err(|_| {
        ParseError::invalid_expression(
            p.current_span(),
            "MSSQL WHILE requires a condition expression".to_string(),
        )
    })?;
    let condition_span = cond_expr.span();

    // ── Body: parse exactly one statement ──
    let body_stmt = parse_mssql_body_statement(p)?;
    let end = body_stmt.span().end;
    let body = vec![body_stmt];

    let stmt_span = Span {
        start: while_span.start,
        end,
    };

    Ok(AstStmt::MssqlWhile(Box::new(crate::ast::AstMssqlWhile {
        node_id: p.id_gen.next(),
        span: stmt_span,
        while_span,
        condition_span,
        body,
    })))
}

// ════════════════════════════════════════════════════════════════════════════
// MSSQL PRINT statement
// ════════════════════════════════════════════════════════════════════════════

/// Parse MSSQL `PRINT expression`.
///
/// Outputs a user-defined message to the client. The expression can be a string
/// literal, variable, or any string expression including concatenation.
pub(crate) fn try_parse_mssql_print(p: &mut Parser<'_>) -> ParseResult<AstStmt> {
    // ── PRINT keyword (Identifier token with lexeme "PRINT") ──
    let print_tok = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["PRINT".to_string()])?;
    let start = print_tok.span.start;

    // ── Expression ──
    let expr = try_parse_expr_scripting(p).map_err(|_| {
        ParseError::invalid_expression(p.current_span(), "PRINT requires an expression".to_string())
    })?;
    let end = expr.span().end;

    // Capture semicolon if present (don't consume - block loop will skip it)
    let semicolon_token = if let Some(semi_tok) = p.peek_non_trivia() {
        if matches!(
            semi_tok.kind,
            TokenKind::Punctuation(crate::lexer::Punctuation::Semi)
        ) {
            Some(p.current_token_id())
        } else {
            None
        }
    } else {
        None
    };

    let stmt_span = Span { start, end };

    Ok(AstStmt::MssqlPrint(Box::new(crate::ast::AstMssqlPrint {
        node_id: p.id_gen.next(),
        span: stmt_span,
        semicolon_token,
    })))
}

/// Parse T-SQL `RECONFIGURE [WITH OVERRIDE]`.
///
/// `RECONFIGURE` and `OVERRIDE` are Identifier tokens (not keywords);
/// `WITH` is a keyword.
pub(crate) fn try_parse_mssql_reconfigure(p: &mut Parser<'_>) -> ParseResult<AstStmt> {
    let kw = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["RECONFIGURE".to_string()])?;
    let start = kw.span.start;
    let mut end = kw.span.end;

    // Optional `WITH OVERRIDE`.
    let mut with_override_span = None;
    if let Some(with_tok) = p.peek_non_trivia() {
        if matches!(
            with_tok.kind,
            TokenKind::Keyword(crate::lexer::Keyword::With)
        ) {
            let with_start = with_tok.span.start;
            p.advance(); // consume WITH
            let over = p
                .peek_non_trivia()
                .filter(|t| {
                    matches!(t.kind, TokenKind::Identifier { .. })
                        && t.lexeme(p.source).eq_ignore_ascii_case("OVERRIDE")
                })
                .ok_or_else(|| {
                    ParseError::new(
                        p.current_span(),
                        ParseErrorKind::InvalidStatement {
                            message: "Expected OVERRIDE after RECONFIGURE WITH".to_string(),
                        },
                    )
                })?;
            let over_end = over.span.end;
            p.advance(); // consume OVERRIDE
            with_override_span = Some(Span {
                start: with_start,
                end: over_end,
            });
            end = over_end;
        }
    }

    Ok(AstStmt::Reconfigure {
        node_id: p.id_gen.next(),
        span: Span { start, end },
        with_override_span,
    })
}

/// Parse MSSQL `THROW` statement.
///
/// Two forms:
/// - Re-throw (inside CATCH): `THROW;`
/// - With arguments: `THROW error_number, message, state;`
pub(crate) fn try_parse_mssql_throw(p: &mut Parser<'_>) -> ParseResult<AstStmt> {
    let throw_tok = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["THROW".to_string()])?;
    let start = throw_tok.span.start;
    let mut end = throw_tok.span.end;

    // Check if this is a re-throw (no arguments — next token is `;` or statement boundary)
    let mut args_span = None;
    if let Some(next) = p.peek_non_trivia() {
        if !matches!(
            next.kind,
            TokenKind::Punctuation(crate::lexer::Punctuation::Semi)
        ) && !matches!(next.kind, TokenKind::Eof)
        {
            // Has arguments: consume everything until semicolon or statement boundary
            let args_start = next.span.start;
            let expr = try_parse_expr_scripting(p).map_err(|_| {
                ParseError::invalid_expression(
                    p.current_span(),
                    "THROW requires error_number as first argument".to_string(),
                )
            })?;
            let mut args_end = expr.span().end;

            // Consume remaining comma-separated arguments (message, state)
            while let Some(tok) = p.peek_non_trivia() {
                if matches!(
                    tok.kind,
                    TokenKind::Punctuation(crate::lexer::Punctuation::Comma)
                ) {
                    p.advance(); // consume comma
                    let arg = try_parse_expr_scripting(p).map_err(|_| {
                        ParseError::invalid_expression(
                            p.current_span(),
                            "THROW requires an expression after comma".to_string(),
                        )
                    })?;
                    args_end = arg.span().end;
                } else {
                    break;
                }
            }

            args_span = Some(Span {
                start: args_start,
                end: args_end,
            });
            end = args_end;
        }
    }

    // Capture semicolon if present (don't consume - block loop will skip it)
    let semicolon_token = if let Some(semi_tok) = p.peek_non_trivia() {
        if matches!(
            semi_tok.kind,
            TokenKind::Punctuation(crate::lexer::Punctuation::Semi)
        ) {
            Some(p.current_token_id())
        } else {
            None
        }
    } else {
        None
    };

    let stmt_span = Span { start, end };

    Ok(AstStmt::MssqlThrow(Box::new(crate::ast::AstMssqlThrow {
        node_id: p.id_gen.next(),
        span: stmt_span,
        args_span,
        semicolon_token,
    })))
}

/// Parse MSSQL `RAISERROR(msg, severity, state [, args...]) [WITH option [, ...]]`.
///
/// RAISERROR always has parenthesized arguments, optionally followed by WITH options.
pub(crate) fn try_parse_mssql_raiserror(p: &mut Parser<'_>) -> ParseResult<AstStmt> {
    let raiserror_tok = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["RAISERROR".to_string()])?;
    let start = raiserror_tok.span.start;
    let mut end = raiserror_tok.span.end;

    // Expect opening parenthesis
    if let Some(tok) = p.peek_non_trivia() {
        if matches!(
            tok.kind,
            TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
        ) {
            // Consume balanced parens (msg, severity, state, optional_args...)
            let lparen = p
                .advance()
                .ok_or_eof(p.current_span(), vec!["(".to_string()])?;
            let mut depth: u32 = 1;
            let mut last_end = lparen.span.end;
            while depth > 0 {
                let tok = p
                    .advance()
                    .ok_or_eof(p.current_span(), vec![")".to_string()])?;
                match tok.kind {
                    TokenKind::Punctuation(crate::lexer::Punctuation::LParen) => depth += 1,
                    TokenKind::Punctuation(crate::lexer::Punctuation::RParen) => depth -= 1,
                    TokenKind::Eof => {
                        return Err(ParseError::new(
                            tok.span,
                            ParseErrorKind::InvalidStatement {
                                message: "Unexpected EOF in RAISERROR arguments".to_string(),
                            },
                        ));
                    }
                    _ => {}
                }
                last_end = tok.span.end;
            }
            end = last_end;
        }
    }

    // Check for WITH options (LOG, NOWAIT, SETERROR)
    if let Some(with_tok) = p.peek_non_trivia() {
        if matches!(
            with_tok.kind,
            TokenKind::Keyword(crate::lexer::Keyword::With)
        ) {
            p.advance(); // consume WITH
                         // Consume comma-separated option identifiers
            loop {
                if let Some(opt_tok) = p.peek_non_trivia() {
                    if matches!(opt_tok.kind, TokenKind::Identifier { .. }) {
                        let opt = p
                            .advance()
                            .ok_or_eof(p.current_span(), vec!["option identifier".to_string()])?;
                        let opt_lexeme = opt.lexeme(p.source);
                        if opt_lexeme.eq_ignore_ascii_case("LOG")
                            || opt_lexeme.eq_ignore_ascii_case("NOWAIT")
                            || opt_lexeme.eq_ignore_ascii_case("SETERROR")
                        {
                            end = opt.span.end;
                        } else {
                            // Unknown option — still include it in span but stop
                            end = opt.span.end;
                            break;
                        }
                        // Check for comma to continue
                        if let Some(comma_tok) = p.peek_non_trivia() {
                            if matches!(
                                comma_tok.kind,
                                TokenKind::Punctuation(crate::lexer::Punctuation::Comma)
                            ) {
                                p.advance(); // consume comma
                                continue;
                            }
                        }
                        break;
                    }
                }
                break;
            }
        }
    }

    // Capture semicolon if present (don't consume - block loop will skip it)
    let semicolon_token = if let Some(semi_tok) = p.peek_non_trivia() {
        if matches!(
            semi_tok.kind,
            TokenKind::Punctuation(crate::lexer::Punctuation::Semi)
        ) {
            Some(p.current_token_id())
        } else {
            None
        }
    } else {
        None
    };

    let stmt_span = Span { start, end };

    Ok(AstStmt::MssqlRaiserror(Box::new(
        crate::ast::AstMssqlRaiserror {
            node_id: p.id_gen.next(),
            span: stmt_span,
            semicolon_token,
        },
    )))
}

/// Parse MSSQL `SET option ON/OFF` statement.
///
/// Forms:
/// - `SET NOCOUNT ON/OFF`
/// - `SET ANSI_NULLS ON/OFF`
/// - `SET IDENTITY_INSERT table ON/OFF` (table name between option and ON/OFF)
/// - `SET XACT_ABORT ON/OFF`
///
/// Called from SET dispatch when the dialect is MSSQL and the next token
/// is a known option identifier followed (eventually) by ON or OFF.
///
/// The SET keyword has NOT been consumed yet when this function is called.
pub(crate) fn try_parse_mssql_set_option(p: &mut Parser<'_>) -> ParseResult<AstStmt> {
    // Consume SET keyword
    let set_tok = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["SET".to_string()])?;
    let start = set_tok.span.start;

    // Consume option name (e.g., NOCOUNT, ANSI_NULLS, IDENTITY_INSERT)
    let option_tok = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["option name".to_string()])?;
    let option_span = option_tok.span;
    let option_kind = classify_mssql_set_option_kind(option_tok.lexeme(p.source));

    // Consume everything until ON, OFF, semicolon, EOF, or block-ending keyword.
    // Handles:
    //   SET NOCOUNT ON              → ON/OFF terminated
    //   SET IDENTITY_INSERT dbo.T ON → ON/OFF with intermediate tokens
    //   SET LOCK_TIMEOUT 30000     → numeric value, semicolon/EOF terminated
    //   SET DEADLOCK_PRIORITY LOW  → identifier value, semicolon/EOF terminated
    let mut end = option_tok.span.end;
    let value_span;
    let value;
    let mut isolation_level = None;
    if option_kind == AstMssqlSetOptionKind::TransactionIsolationLevel {
        // SET TRANSACTION ISOLATION LEVEL <level> — consume ISOLATION + LEVEL
        // and the 1–2 word level, captured typed (the generic last-token
        // value would mis-read e.g. REPEATABLE READ).
        let (lvl_end, lvl_span, lvl) = parse_mssql_isolation_level(p, option_tok.span.end);
        end = lvl_end;
        value_span = lvl_span;
        value = AstMssqlSetOptionValue::Identifier;
        isolation_level = lvl;
    } else {
        let mut last_value_span = option_tok.span; // fallback: option name itself as value
        let mut last_value_kind = AstMssqlSetOptionValue::Unparsed;
        loop {
            let tok = match p.peek_non_trivia() {
                Some(t) => t,
                None => {
                    // EOF — use last consumed token as value
                    value_span = last_value_span;
                    value = last_value_kind;
                    break;
                }
            };
            match &tok.kind {
                TokenKind::Keyword(Keyword::On) => {
                    let on_tok = p
                        .advance()
                        .ok_or_eof(p.current_span(), vec!["ON".to_string()])?;
                    value_span = on_tok.span;
                    end = on_tok.span.end;
                    value = AstMssqlSetOptionValue::On;
                    break;
                }
                TokenKind::Identifier { .. }
                    if tok.lexeme(p.source).eq_ignore_ascii_case("OFF") =>
                {
                    let off_tok = p
                        .advance()
                        .ok_or_eof(p.current_span(), vec!["OFF".to_string()])?;
                    value_span = off_tok.span;
                    end = off_tok.span.end;
                    value = AstMssqlSetOptionValue::Off;
                    break;
                }
                // Statement terminators — use last consumed value token
                TokenKind::Punctuation(crate::lexer::Punctuation::Semi) | TokenKind::Eof => {
                    value_span = last_value_span;
                    value = last_value_kind;
                    break;
                }
                // Block-ending keywords — don't consume, return what we have
                TokenKind::Keyword(Keyword::End)
                | TokenKind::Keyword(Keyword::Else)
                | TokenKind::Keyword(Keyword::Begin) => {
                    value_span = last_value_span;
                    value = last_value_kind;
                    break;
                }
                _ => {
                    // Consume intermediate tokens (e.g., table name in IDENTITY_INSERT dbo.MyTable ON,
                    // or numeric value in LOCK_TIMEOUT 30000, or identifier value in DEADLOCK_PRIORITY LOW)
                    // Track the typed shape of the last consumed token so a
                    // terminator-terminated form (LOCK_TIMEOUT 30000;) carries
                    // typed value identity in the AST.
                    let kind_classifier = match tok.kind {
                        TokenKind::Literal { .. } => AstMssqlSetOptionValue::NumericLiteral,
                        TokenKind::Identifier { .. } => AstMssqlSetOptionValue::Identifier,
                        _ => AstMssqlSetOptionValue::Unparsed,
                    };
                    let t = p
                        .advance()
                        .ok_or_eof(p.current_span(), vec!["SET value token".to_string()])?;
                    last_value_span = t.span;
                    last_value_kind = kind_classifier;
                    end = t.span.end;
                }
            }
        }
    }

    // Capture semicolon if present (don't consume - block loop will skip it)
    let semicolon_token = if let Some(semi_tok) = p.peek_non_trivia() {
        if matches!(
            semi_tok.kind,
            TokenKind::Punctuation(crate::lexer::Punctuation::Semi)
        ) {
            Some(p.current_token_id())
        } else {
            None
        }
    } else {
        None
    };

    Ok(AstStmt::MssqlSetOption(Box::new(
        crate::ast::AstMssqlSetOption {
            node_id: p.id_gen.next(),
            span: Span { start, end },
            option_span,
            value_span,
            option_kind,
            value,
            isolation_level,
            semicolon_token,
        },
    )))
}

/// Parse the tail of `SET TRANSACTION ISOLATION LEVEL <level>` after the
/// `TRANSACTION` keyword: consumes `ISOLATION` `LEVEL` then the 1–2 word level.
/// Returns `(end_pos, level_span, typed_level)`. Permissive: if the expected
/// words are absent it consumes what it can and returns `None` for the level.
fn parse_mssql_isolation_level(
    p: &mut Parser<'_>,
    option_end: u32,
) -> (u32, Span, Option<crate::ast::AstMssqlIsolationLevel>) {
    use crate::ast::AstMssqlIsolationLevel as L;
    let mut end = option_end;
    // Consume a word matching `want` (case-insensitive), advancing `end`.
    let mut eat = |p: &mut Parser<'_>, want: &str| -> bool {
        if let Some(t) = p.peek_non_trivia() {
            if t.lexeme(p.source).eq_ignore_ascii_case(want) {
                let t = p
                    .advance()
                    .expect_invariant("isolation-level word after peek");
                end = t.span.end;
                return true;
            }
        }
        false
    };
    eat(p, "ISOLATION");
    eat(p, "LEVEL");

    // Level: READ {UNCOMMITTED|COMMITTED} | REPEATABLE READ | SNAPSHOT | SERIALIZABLE
    let Some(first) = p.peek_non_trivia() else {
        return (end, Span { start: end, end }, None);
    };
    let level_start = first.span.start;
    let lexeme = first.lexeme(p.source).to_string();
    let level = if lexeme.eq_ignore_ascii_case("READ") {
        eat(p, "READ");
        if eat(p, "UNCOMMITTED") {
            Some(L::ReadUncommitted)
        } else if eat(p, "COMMITTED") {
            Some(L::ReadCommitted)
        } else {
            None
        }
    } else if lexeme.eq_ignore_ascii_case("REPEATABLE") {
        eat(p, "REPEATABLE");
        eat(p, "READ");
        Some(L::RepeatableRead)
    } else if lexeme.eq_ignore_ascii_case("SNAPSHOT") {
        eat(p, "SNAPSHOT");
        Some(L::Snapshot)
    } else if lexeme.eq_ignore_ascii_case("SERIALIZABLE") {
        eat(p, "SERIALIZABLE");
        Some(L::Serializable)
    } else {
        None
    };
    (
        end,
        Span {
            start: level_start,
            end,
        },
        level,
    )
}

/// Classify a T-SQL `SET <option>` keyword identifier into the typed
/// [`AstMssqlSetOptionKind`] closed enum. Parser is the single
/// text→typed conversion site;
/// downstream layers dispatch on the typed variant.
fn classify_mssql_set_option_kind(lexeme: &str) -> AstMssqlSetOptionKind {
    if lexeme.eq_ignore_ascii_case("IDENTITY_INSERT") {
        AstMssqlSetOptionKind::IdentityInsert
    } else if lexeme.eq_ignore_ascii_case("NOCOUNT") {
        AstMssqlSetOptionKind::NoCount
    } else if lexeme.eq_ignore_ascii_case("XACT_ABORT") {
        AstMssqlSetOptionKind::XactAbort
    } else if lexeme.eq_ignore_ascii_case("ANSI_NULLS") {
        AstMssqlSetOptionKind::AnsiNulls
    } else if lexeme.eq_ignore_ascii_case("QUOTED_IDENTIFIER") {
        AstMssqlSetOptionKind::QuotedIdentifier
    } else if lexeme.eq_ignore_ascii_case("ARITHABORT") {
        AstMssqlSetOptionKind::ArithAbort
    } else if lexeme.eq_ignore_ascii_case("CONCAT_NULL_YIELDS_NULL") {
        AstMssqlSetOptionKind::ConcatNullYieldsNull
    } else if lexeme.eq_ignore_ascii_case("LOCK_TIMEOUT") {
        AstMssqlSetOptionKind::LockTimeout
    } else if lexeme.eq_ignore_ascii_case("DEADLOCK_PRIORITY") {
        AstMssqlSetOptionKind::DeadlockPriority
    } else if lexeme.eq_ignore_ascii_case("ROWCOUNT") {
        AstMssqlSetOptionKind::RowCount
    } else if lexeme.eq_ignore_ascii_case("TRANSACTION") {
        // The full form is `SET TRANSACTION ISOLATION LEVEL <level>`;
        // the first identifier is `TRANSACTION` — classifying on it
        // covers the documented case.
        AstMssqlSetOptionKind::TransactionIsolationLevel
    } else {
        AstMssqlSetOptionKind::Other
    }
}

// ════════════════════════════════════════════════════════════════════════════
// MSSQL DROP TRIGGER
// ════════════════════════════════════════════════════════════════════════════

/// Parse MSSQL DROP TRIGGER statement.
///
/// Syntax:
/// ```sql
/// -- DML trigger:
/// DROP TRIGGER [ IF EXISTS ] [schema.]trigger_name [,...n] [;]
/// -- DDL trigger:
/// DROP TRIGGER [ IF EXISTS ] trigger_name [,...n] ON { DATABASE | ALL SERVER } [;]
/// ```
pub(crate) fn try_parse_drop_mssql_trigger(p: &mut Parser<'_>) -> ParseResult<AstStmt> {
    let _depth = p.track_depth("drop_mssql_trigger")?;

    // DROP
    let drop_tok = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["DROP".to_string()])?;
    let start = drop_tok.span.start;

    // TRIGGER
    let _trigger_tok = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["TRIGGER".to_string()])?;

    // Optional: IF EXISTS
    let mut if_exists = false;
    if let Some(tok) = p.peek_non_trivia() {
        if matches!(tok.kind, TokenKind::Keyword(Keyword::If)) {
            p.advance(); // IF
            if let Some(tok2) = p.peek_non_trivia() {
                if matches!(tok2.kind, TokenKind::Keyword(Keyword::Exists)) {
                    p.advance(); // EXISTS
                    if_exists = true;
                }
            }
        }
    }

    // Parse comma-separated trigger names
    let mut trigger_names: Vec<Span> = Vec::new();
    let first_name = p.parse_qualified_name_span()?;
    trigger_names.push(first_name);

    while let Some(tok) = p.peek_non_trivia() {
        if matches!(
            tok.kind,
            TokenKind::Punctuation(crate::lexer::Punctuation::Comma)
        ) {
            p.advance(); // consume comma
            let name = p.parse_qualified_name_span()?;
            trigger_names.push(name);
        } else {
            break;
        }
    }

    let mut end = trigger_names.last().unwrap().end;

    // Optional: ON { DATABASE | ALL SERVER }
    let mut scope_span: Option<Span> = None;
    if let Some(tok) = p.peek_non_trivia() {
        if matches!(tok.kind, TokenKind::Keyword(Keyword::On)) {
            let on_tok = p
                .advance()
                .ok_or_eof(p.current_span(), vec!["ON".to_string()])?;
            let scope_start = on_tok.span.start;
            if let Some(scope_tok) = p.peek_non_trivia() {
                if scope_tok.lexeme(p.source).eq_ignore_ascii_case("DATABASE") {
                    let db_tok = p
                        .advance()
                        .ok_or_eof(p.current_span(), vec!["DATABASE".to_string()])?;
                    end = db_tok.span.end;
                    scope_span = Some(Span {
                        start: scope_start,
                        end,
                    });
                } else if matches!(scope_tok.kind, TokenKind::Keyword(Keyword::All)) {
                    p.advance(); // ALL
                    if let Some(server_tok) = p.peek_non_trivia() {
                        if server_tok.lexeme(p.source).eq_ignore_ascii_case("SERVER") {
                            let srv_tok = p
                                .advance()
                                .ok_or_eof(p.current_span(), vec!["SERVER".to_string()])?;
                            end = srv_tok.span.end;
                            scope_span = Some(Span {
                                start: scope_start,
                                end,
                            });
                        }
                    }
                }
            }
        }
    }

    let stmt_span = Span { start, end };

    let ast = crate::ast::types::AstDropMssqlTrigger {
        node_id: p.id_gen.next(),
        span: stmt_span,
        if_exists,
        trigger_names,
        scope_span,
    };

    Ok(AstStmt::DropMssqlTrigger(Box::new(ast)))
}

// ════════════════════════════════════════════════════════════════════════════
// MSSQL CREATE [OR ALTER] TRIGGER
// ════════════════════════════════════════════════════════════════════════════

/// Parse MSSQL-style CREATE [OR ALTER] TRIGGER statement.
///
/// Syntax:
/// ```sql
/// CREATE [OR ALTER] TRIGGER [schema.]trigger_name
///   ON { table_or_view | DATABASE | ALL SERVER }
///   { AFTER | INSTEAD OF | FOR } { event [, event ...] }
///   [NOT FOR REPLICATION]
///   AS
///   BEGIN ... END
/// ```
pub(crate) fn try_parse_create_mssql_trigger(p: &mut Parser<'_>) -> ParseResult<AstStmt> {
    let _depth = p.track_depth("create_mssql_trigger")?;

    // CREATE
    let create_tok = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["CREATE".to_string()])?;
    let start = create_tok.span.start;

    // Optional: OR ALTER
    let mut or_alter_span: Option<Span> = None;
    if let Some(tok) = p.peek_non_trivia() {
        if matches!(tok.kind, TokenKind::Keyword(Keyword::Or)) {
            let or_tok = p.advance().expect_invariant("OR token");
            let or_start = or_tok.span.start;
            if let Some(next) = p.peek_non_trivia() {
                if matches!(next.kind, TokenKind::Keyword(Keyword::Alter)) {
                    let alter_tok = p.advance().expect_invariant("ALTER token");
                    or_alter_span = Some(Span {
                        start: or_start,
                        end: alter_tok.span.end,
                    });
                }
            }
        }
    }

    // TRIGGER keyword
    let trigger_tok = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["TRIGGER".to_string()])?;
    if !matches!(trigger_tok.kind, TokenKind::Keyword(Keyword::Trigger)) {
        return Err(ParseError::new(
            trigger_tok.span,
            ParseErrorKind::InvalidStatement {
                message: format!(
                    "Expected TRIGGER keyword, found '{}'",
                    Parser::token_description(trigger_tok, p.source)
                ),
            },
        ));
    }

    // Trigger name (possibly schema-qualified: dbo.trigger_name)
    let name_first = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["trigger name".to_string()])?;
    let name_start = name_first.span.start;
    let mut name_end = name_first.span.end;
    // Dot-separated qualified name
    while let Some(dot) = p.peek_non_trivia() {
        if !matches!(
            dot.kind,
            TokenKind::Punctuation(crate::lexer::Punctuation::Dot)
        ) {
            break;
        }
        p.advance(); // consume dot
        let part = p
            .advance()
            .ok_or_eof(p.current_span(), vec!["name part".to_string()])?;
        name_end = part.span.end;
    }
    let name_span = Span {
        start: name_start,
        end: name_end,
    };

    // ON keyword
    let on_tok = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["ON".to_string()])?;
    if !matches!(on_tok.kind, TokenKind::Keyword(Keyword::On)) {
        return Err(ParseError::new(
            on_tok.span,
            ParseErrorKind::InvalidStatement {
                message: format!(
                    "Expected ON keyword, found '{}'",
                    Parser::token_description(on_tok, p.source)
                ),
            },
        ));
    }

    // Target: table/view name, DATABASE, or ALL SERVER
    let target_first = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["trigger target".to_string()])?;
    let target_start = target_first.span.start;
    let mut target_end = target_first.span.end;

    let target_lexeme = target_first.lexeme(p.source);
    if target_lexeme.eq_ignore_ascii_case("ALL") {
        // ALL SERVER
        if let Some(server_tok) = p.peek_non_trivia() {
            if server_tok.lexeme(p.source).eq_ignore_ascii_case("SERVER") {
                let s = p
                    .advance()
                    .ok_or_eof(p.current_span(), vec!["SERVER".to_string()])?;
                target_end = s.span.end;
            }
        }
    } else if !target_lexeme.eq_ignore_ascii_case("DATABASE") {
        // Regular table/view name — handle qualified name (dbo.TableName)
        while let Some(dot) = p.peek_non_trivia() {
            if !matches!(
                dot.kind,
                TokenKind::Punctuation(crate::lexer::Punctuation::Dot)
            ) {
                break;
            }
            p.advance(); // consume dot
            let part = p
                .advance()
                .ok_or_eof(p.current_span(), vec!["table name part".to_string()])?;
            target_end = part.span.end;
        }
    }
    let target_span = Span {
        start: target_start,
        end: target_end,
    };

    // Timing: AFTER | INSTEAD OF | FOR
    let timing_tok = p.advance().ok_or_eof(
        p.current_span(),
        vec!["AFTER, INSTEAD OF, or FOR".to_string()],
    )?;
    let timing_start = timing_tok.span.start;
    let mut timing_end = timing_tok.span.end;
    let timing_lexeme = timing_tok.lexeme(p.source);

    if timing_lexeme.eq_ignore_ascii_case("INSTEAD") {
        // Expect OF
        let of_tok = p
            .advance()
            .ok_or_eof(p.current_span(), vec!["OF".to_string()])?;
        if !matches!(of_tok.kind, TokenKind::Keyword(Keyword::Of)) {
            return Err(ParseError::new(
                of_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: format!(
                        "Expected OF after INSTEAD, found '{}'",
                        Parser::token_description(of_tok, p.source)
                    ),
                },
            ));
        }
        timing_end = of_tok.span.end;
    } else if !matches!(timing_tok.kind, TokenKind::Keyword(Keyword::After))
        && !matches!(timing_tok.kind, TokenKind::Keyword(Keyword::For))
    {
        return Err(ParseError::new(
            timing_tok.span,
            ParseErrorKind::InvalidStatement {
                message: format!(
                    "Expected AFTER, INSTEAD OF, or FOR, found '{}'",
                    Parser::token_description(timing_tok, p.source)
                ),
            },
        ));
    }
    let timing_span = Span {
        start: timing_start,
        end: timing_end,
    };

    // Events: comma-separated list (INSERT, UPDATE, DELETE, or DDL event identifiers)
    let event_first = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["trigger event".to_string()])?;
    let events_start = event_first.span.start;
    let mut events_end = event_first.span.end;
    // Consume comma-separated events
    while let Some(comma) = p.peek_non_trivia() {
        if !matches!(
            comma.kind,
            TokenKind::Punctuation(crate::lexer::Punctuation::Comma)
        ) {
            break;
        }
        p.advance(); // consume comma
        let ev = p
            .advance()
            .ok_or_eof(p.current_span(), vec!["trigger event".to_string()])?;
        events_end = ev.span.end;
    }
    let events_span = Span {
        start: events_start,
        end: events_end,
    };

    // Optional: NOT FOR REPLICATION
    if let Some(tok) = p.peek_non_trivia() {
        if matches!(tok.kind, TokenKind::Keyword(Keyword::Not)) {
            // Peek ahead to check if it's NOT FOR REPLICATION
            let saved = p.idx;
            p.advance(); // NOT
            p.skip_trivia();
            let is_nfr = if let Some(for_tok) = p.peek_non_trivia() {
                if matches!(for_tok.kind, TokenKind::Keyword(Keyword::For)) {
                    p.advance(); // FOR
                    p.skip_trivia();
                    if let Some(rep_tok) = p.peek_non_trivia() {
                        rep_tok.lexeme(p.source).eq_ignore_ascii_case("REPLICATION")
                    } else {
                        false
                    }
                } else {
                    false
                }
            } else {
                false
            };
            if is_nfr {
                p.advance(); // consume REPLICATION
            } else {
                p.idx = saved; // restore — NOT was part of something else
            }
        }
    }

    // AS keyword
    let as_tok = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["AS".to_string()])?;
    if !matches!(as_tok.kind, TokenKind::Keyword(Keyword::As)) {
        return Err(ParseError::new(
            as_tok.span,
            ParseErrorKind::InvalidStatement {
                message: format!(
                    "Expected AS keyword, found '{}'",
                    Parser::token_description(as_tok, p.source)
                ),
            },
        ));
    }

    // Body: parse as BEGIN...END block or collect statements until END/GO/EOF
    let mut body: Vec<AstStmt> = Vec::new();
    let mut end = as_tok.span.end;

    p.skip_trivia();
    if let Some(begin_tok) = p.peek_non_trivia() {
        if matches!(begin_tok.kind, TokenKind::Keyword(Keyword::Begin)) {
            // Parse BEGIN...END block — this handles nested statements properly
            let block_stmt = try_parse_block_stmt(p)?;
            end = block_stmt.span().end;
            body.push(block_stmt);
        } else {
            // Single statement body (rare but valid in T-SQL)
            let stmt = parse_mssql_body_statement(p)?;
            end = stmt.span().end;
            body.push(stmt);
        }
    }

    let span = Span { start, end };

    Ok(AstStmt::CreateMssqlTrigger(Box::new(
        crate::ast::AstCreateMssqlTrigger {
            node_id: p.id_gen.next(),
            span,
            or_alter_span,
            name_span,
            target_span,
            timing_span,
            events_span,
            body,
        },
    )))
}

/// Result-based block statement parser with proper error propagation.
pub(crate) fn try_parse_block_stmt(p: &mut Parser<'_>) -> ParseResult<AstStmt> {
    try_parse_block_stmt_with_label(p, None)
}

/// Result-based block statement parser that accepts an optional preceding label.
pub(crate) fn try_parse_block_stmt_with_label(
    p: &mut Parser<'_>,
    label_span: Option<Span>,
) -> ParseResult<AstStmt> {
    // Parse a BEGIN ... [EXCEPTION ...] END; scripting block body.
    // Capture BEGIN token ID before advance
    let begin_token_id = p.current_token_id();
    let begin_tok = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["BEGIN keyword".to_string()])?;
    if !matches!(begin_tok.kind, TokenKind::Keyword(Keyword::Begin)) {
        return Err(ParseError::new(
            begin_tok.span,
            ParseErrorKind::UnexpectedToken {
                expected: vec!["BEGIN keyword".to_string()],
                found: Parser::token_description(begin_tok, p.source),
            },
        ));
    }
    let body_start = begin_tok.span.start;
    let mut body: Vec<AstStmt> = Vec::new();
    let mut exception_section: Option<AstExceptionSection> = None;

    // Check for Databricks BEGIN ATOMIC
    let atomic_span = if let Some(atomic_tok) = p.peek_non_trivia() {
        if atomic_tok.lexeme(p.source).eq_ignore_ascii_case("ATOMIC") {
            let at = p.advance().expect_invariant("ATOMIC consumed after BEGIN");
            Some(at.span)
        } else {
            None
        }
    } else {
        None
    };

    let mut _body_loop_iter = 0;
    loop {
        _body_loop_iter += 1;
        p.skip_trivia();
        let tok = match p.peek_non_trivia() {
            Some(t) => t,
            None => break,
        };
        match &tok.kind {
            // Skip semicolons between statements
            TokenKind::Punctuation(crate::lexer::Punctuation::Semi) => {
                p.advance();
                continue;
            }
            // EXCEPTION section starts here; capture a shallow span for everything
            // from EXCEPTION through the last WHEN handler, then continue looping
            // so that we can still hit the END arm and return a Block.
            TokenKind::Keyword(Keyword::Exception) => {
                let ex_token_id = p.current_token_id();
                let ex_kw = p
                    .advance()
                    .expect_invariant("EXCEPTION keyword consumed after match in block");
                let ex_start = ex_kw.span.start;
                let mut handlers = Vec::new();
                let mut ex_end = ex_kw.span.end;

                // Parse WHEN clauses
                loop {
                    p.skip_trivia();
                    let tok = match p.peek_non_trivia() {
                        Some(t) => t,
                        None => {
                            break;
                        }
                    };
                    match &tok.kind {
                        TokenKind::Keyword(Keyword::When) => {
                            let when_token_id = p.current_token_id();
                            let when_kw = p
                                .advance()
                                .expect_invariant("WHEN keyword consumed after match in EXCEPTION");
                            let handler_start = when_kw.span.start;

                            // Parse exception name(s) - can be multiple separated by OR
                            let mut exception_name_spans = Vec::new();
                            let mut exception_name_tokens = Vec::new();
                            loop {
                                p.skip_trivia();
                                let exception_name_tok = match p.peek_non_trivia() {
                                    Some(_) => {
                                        let name_token_id = p.current_token_id();
                                        let tok = p.advance().expect_invariant(
                                            "exception name consumed after peek in WHEN handler",
                                        );
                                        exception_name_tokens.push(Some(name_token_id));
                                        tok
                                    }
                                    None => break,
                                };
                                exception_name_spans.push(exception_name_tok.span);

                                // Check for OR keyword to continue parsing more exception names
                                p.skip_trivia();
                                if let Some(or_tok) = p.peek_non_trivia() {
                                    if matches!(or_tok.kind, TokenKind::Keyword(Keyword::Or)) {
                                        let _ = p.advance(); // consume OR
                                        continue; // parse next exception name
                                    }
                                }
                                break; // no OR, done parsing exception names
                            }

                            if exception_name_spans.is_empty() {
                                continue; // no exception names found, skip this handler
                            }

                            // Check for EXIT or CONTINUE keyword
                            let mut handler_type = ExceptionHandlerType::Simple; // default
                            if let Some(type_tok) = p.peek_non_trivia() {
                                match &type_tok.kind {
                                    TokenKind::Keyword(Keyword::Continue) => {
                                        let _ = p.advance();
                                        handler_type = ExceptionHandlerType::Continue;
                                    }
                                    TokenKind::Keyword(Keyword::Exit) => {
                                        let _ = p.advance();
                                        handler_type = ExceptionHandlerType::Exit;
                                    }
                                    _ => {}
                                }
                            }

                            // Optional THEN keyword
                            let mut then_span = None;
                            let mut then_token_id = None;
                            if let Some(then_tok) = p.peek_non_trivia() {
                                if matches!(then_tok.kind, TokenKind::Keyword(Keyword::Then)) {
                                    then_token_id = Some(p.current_token_id());
                                    let then_kw = p.advance().expect_invariant(
                                        "THEN keyword consumed after match in WHEN handler",
                                    );
                                    then_span = Some(then_kw.span);
                                }
                            }

                            // Parse handler body with error recovery
                            // Exception handler body terminates on WHEN or END
                            let handler_body_terminators =
                                &[BodyTerminator::When, BodyTerminator::End];
                            let (handler_body, _errors) = parse_body_with_recovery(
                                p,
                                StmtContext::ExceptionHandler,
                                0, // begin_start not needed for exception handlers
                                handler_body_terminators,
                            );

                            let handler_end = handler_body.last().map(|s| s.span().end).unwrap_or(
                                exception_name_spans
                                    .last()
                                    .map(|s| s.end)
                                    .unwrap_or(when_kw.span.end),
                            );

                            let handler_span = Span {
                                start: handler_start,
                                end: handler_end,
                            };
                            handlers.push(AstExceptionHandler {
                                node_id: p.id_gen.next(),
                                when_span: when_kw.span,
                                when_token: Some(when_token_id),
                                exception_name_spans,
                                exception_name_tokens,
                                handler_type,
                                then_span,
                                then_token: then_token_id,
                                body: handler_body,
                                span: handler_span,
                            });
                            ex_end = handler_end;
                        }
                        TokenKind::Keyword(Keyword::End) | TokenKind::Eof => {
                            break;
                        }
                        _ => {
                            // Skip unrecognized tokens in exception section
                            let t = p.advance().expect_invariant(
                                "unrecognized token skipped in exception section",
                            );
                            ex_end = t.span.end;
                        }
                    }
                }

                exception_section = Some(AstExceptionSection {
                    node_id: p.id_gen.next(),
                    keyword_span: ex_kw.span,
                    keyword_token: Some(ex_token_id),
                    handlers,
                    span: Span {
                        start: ex_start,
                        end: ex_end,
                    },
                });
                // Continue to outer loop to find END keyword
                continue;
            }
            // END terminates the block body (and any exception section parsing
            // has already been handled above when we saw EXCEPTION).
            TokenKind::Keyword(Keyword::End) => {
                // Capture END token ID before advance
                let end_token_id = p.current_token_id();
                let end_tok = p
                    .advance()
                    .expect_invariant("END keyword consumed after match in block");
                let end_span = Some(end_tok.span);
                let mut end = end_tok.span.end;

                // Optional end label (e.g., END my_label). A dollar-quote
                // delimiter (`$$` / `$tag$`) lexes as an Identifier but is the
                // body's closing delimiter, not a label — never consume it here,
                // or the enclosing `parse_dollar_block_body` cannot find the
                // closer (which drops `closing_delimiter_token` and breaks the
                // `$$ LANGUAGE plpgsql` round-trip).
                let mut end_label_span: Option<Span> = None;
                if let Some(lbl) = p.peek_non_trivia() {
                    if p.can_be_identifier_token(lbl)
                        && !matches!(
                            lbl.kind,
                            TokenKind::Punctuation(crate::lexer::Punctuation::Semi)
                        )
                        && !(p.dialect.supports_dollar_quoted_strings()
                            && crate::parser::core::is_dollar_quote_tag(lbl.lexeme(p.source)))
                    {
                        let ltok = p
                            .advance()
                            .expect_invariant("label identifier consumed after END in block");
                        end_label_span = Some(ltok.span);
                        end = ltok.span.end;
                    }
                }

                // Don't consume semicolon - span ends at END [label]
                let span = Span {
                    start: label_span.map_or(body_start, |ls| ls.start),
                    end,
                };

                // Capture semicolon if present (don't consume - block loop will skip it)
                let semicolon_token = if let Some(tok) = p.peek_non_trivia() {
                    if matches!(
                        tok.kind,
                        TokenKind::Punctuation(crate::lexer::Punctuation::Semi)
                    ) {
                        Some(p.current_token_id())
                    } else {
                        None
                    }
                } else {
                    None
                };

                return Ok(AstStmt::Block(Box::new(AstBlockStmt {
                    node_id: p.id_gen.next(),
                    span,
                    label_span,
                    end_label_span,
                    declare_span: None,
                    declare_token: None,
                    begin_span: begin_tok.span,
                    begin_token: Some(begin_token_id),
                    atomic_span,
                    decls: Vec::new(),
                    body,
                    exception: exception_section,
                    end_span,
                    end_token: Some(end_token_id),
                    semicolon_token,
                })));
            }
            // All other statements: use unified parser with error recovery
            _ => {
                // Track position for error recovery
                let stmt_start_pos = tok.span.start;
                let stmt_start_idx = p.idx;

                // Try Result-based parser for control flow statements
                // These get special error handling - propagate their errors
                if matches!(
                    tok.kind,
                    TokenKind::Keyword(Keyword::If)
                        | TokenKind::Keyword(Keyword::Case)
                        | TokenKind::Keyword(Keyword::While)
                        | TokenKind::Keyword(Keyword::For)
                        | TokenKind::Keyword(Keyword::Repeat)
                        | TokenKind::Keyword(Keyword::Loop)
                ) {
                    match try_parse_scripting_stmt(p, StmtContext::Block, body_start) {
                        Ok(stmt) => {
                            body.push(stmt);
                            continue;
                        }
                        Err(e) => {
                            // Propagate control flow statement errors - they should be detailed
                            return Err(e);
                        }
                    }
                }

                // Use Result-based parser for regular statements with error recovery
                match try_parse_scripting_stmt(p, StmtContext::Block, body_start) {
                    Ok(stmt) => {
                        body.push(stmt);
                        // Don't consume semicolon - let formatter handle it
                        continue;
                    }
                    Err(e) => {
                        // Check if this is a specific error we want to propagate
                        let error_msg = e.message().to_string();
                        if error_msg.contains("WITH clause")
                            || error_msg.contains("DECLARE statements must appear before BEGIN")
                        {
                            // This is a specific SQL syntax error we want to surface
                            return Err(e);
                        }

                        // Error recovery: create Error node and sync to next valid point
                        let block_terminators = &[BodyTerminator::Exception, BodyTerminator::End];
                        let (error_node, _sync_error) = create_error_and_sync(
                            p,
                            stmt_start_pos,
                            stmt_start_idx,
                            &e,
                            block_terminators,
                        );
                        body.push(error_node);
                        // Continue parsing - don't break
                        continue;
                    }
                }
            }
        }
    }
    // If we exit the loop without signal END, that's an error
    Err(ParseError::new(
        p.current_span(),
        ParseErrorKind::UnexpectedEof {
            expected: vec!["END keyword to close BEGIN block".to_string()],
        },
    ))
}

/// Backward-compatible Option-based wrapper for parse_block_stmt.
pub(crate) fn parse_block_stmt(p: &mut Parser<'_>) -> Option<AstStmt> {
    try_parse_block_stmt(p).ok()
}

pub(crate) fn parse_scripting_block(p: &mut Parser<'_>) -> Option<AstStmt> {
    // Use the Result-based version and convert to Option
    // This ensures we don't have duplicate logic and avoids infinite loops
    try_parse_scripting_block(p).ok()
}

/// Parse a SET session variable statement.
/// Snowflake syntax:
/// - Single: SET variable_name = expression
/// - Multiple: SET (var1, var2, ...) = (expr1, expr2, ...)
/// - From SELECT: SET variable_name = (SELECT ...)
pub(crate) fn try_parse_set_variable_stmt(p: &mut Parser<'_>) -> ParseResult<AstStmt> {
    use crate::ast::{AstIdentifier, AstStmt};

    // Consume SET keyword
    let set_tok = p.advance().ok_or_else(|| {
        ParseError::new(
            p.current_span(),
            ParseErrorKind::InvalidStatement {
                message: "Expected SET keyword".to_string(),
            },
        )
    })?;

    if !matches!(set_tok.kind, TokenKind::Keyword(Keyword::Set)) {
        return Err(ParseError::new(
            set_tok.span,
            ParseErrorKind::InvalidStatement {
                message: format!(
                    "Expected SET keyword, found {}",
                    Parser::token_description(set_tok, p.source)
                ),
            },
        ));
    }

    let stmt_start = set_tok.span.start;
    let set_span = set_tok.span;

    p.skip_trivia();

    // Check if this is tuple form: SET (var1, var2, ...) = ...
    let is_tuple_form = matches!(
        p.peek_non_trivia().map(|t| &t.kind),
        Some(TokenKind::Punctuation(crate::lexer::Punctuation::LParen))
    );

    let mut variable_names = Vec::new();

    if is_tuple_form {
        // Consume opening paren
        p.advance(); // (
        p.skip_trivia();

        // Parse comma-separated variable names
        loop {
            let name_tok = p.peek_non_trivia().ok_or_else(|| {
                ParseError::new(
                    p.current_span(),
                    ParseErrorKind::InvalidStatement {
                        message: "Expected variable name in SET statement".to_string(),
                    },
                )
            })?;

            if matches!(
                name_tok.kind,
                TokenKind::Punctuation(crate::lexer::Punctuation::RParen)
            ) {
                break;
            }

            // Parse identifier using parser helper (allows identifiers and contextual keywords)
            let ident = if p.can_be_identifier_token(name_tok) {
                let tok = p
                    .advance()
                    .expect_invariant("variable name identifier after peek");
                AstIdentifier {
                    node_id: p.id_gen.next(),
                    span: tok.span,
                }
            } else {
                return Err(ParseError::new(
                    name_tok.span,
                    ParseErrorKind::InvalidStatement {
                        message: format!(
                            "Expected variable name, found {}",
                            Parser::token_description(name_tok, p.source)
                        ),
                    },
                ));
            };
            variable_names.push(ident);

            p.skip_trivia();

            // Check for comma or closing paren
            if let Some(tok) = p.peek_non_trivia() {
                if matches!(
                    tok.kind,
                    TokenKind::Punctuation(crate::lexer::Punctuation::Comma)
                ) {
                    p.advance(); // ,
                    p.skip_trivia();
                } else if matches!(
                    tok.kind,
                    TokenKind::Punctuation(crate::lexer::Punctuation::RParen)
                ) {
                    break;
                }
            }
        }

        // Consume closing paren
        p.advance(); // )
        p.skip_trivia();
    } else {
        // Single variable form: SET variable_name = ...
        let name_tok = p.peek_non_trivia().ok_or_else(|| {
            ParseError::new(
                p.current_span(),
                ParseErrorKind::InvalidStatement {
                    message: "Expected variable name after SET".to_string(),
                },
            )
        })?;

        // Parse identifier using parser helper (allows identifiers and contextual keywords)
        let ident = if p.can_be_identifier_token(name_tok) {
            let tok = p
                .advance()
                .expect_invariant("variable name identifier after SET");
            AstIdentifier {
                node_id: p.id_gen.next(),
                span: tok.span,
            }
        } else {
            return Err(ParseError::new(
                name_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: format!(
                        "Expected variable name after SET, found {}",
                        Parser::token_description(name_tok, p.source)
                    ),
                },
            ));
        };
        variable_names.push(ident);
        p.skip_trivia();
    }

    // Expect =
    let eq_tok = p.peek_non_trivia().ok_or_else(|| {
        ParseError::new(
            p.current_span(),
            ParseErrorKind::InvalidStatement {
                message: "Expected '=' after variable name(s) in SET statement".to_string(),
            },
        )
    })?;

    if !matches!(eq_tok.kind, TokenKind::Operator(crate::lexer::Operator::Eq)) {
        return Err(ParseError::new(
            eq_tok.span,
            ParseErrorKind::InvalidStatement {
                message: format!(
                    "Expected '=' in SET statement, found {}",
                    Parser::token_description(eq_tok, p.source)
                ),
            },
        ));
    }
    p.advance(); // =
    p.skip_trivia();

    // Parse value expression(s)
    let mut values = Vec::new();

    // Check if values are in parentheses (tuple form or subquery)
    let values_in_parens = matches!(
        p.peek_non_trivia().map(|t| &t.kind),
        Some(TokenKind::Punctuation(crate::lexer::Punctuation::LParen))
    );

    // Check if RHS is a subquery: (SELECT ...)
    // This takes precedence over tuple expression parsing
    let is_subquery_rhs = if values_in_parens {
        // Look ahead: ( followed by SELECT
        let saved_idx = p.idx;
        p.advance(); // consume (
        p.skip_trivia();
        let is_select = matches!(
            p.peek_non_trivia().map(|t| &t.kind),
            Some(TokenKind::Keyword(Keyword::Select))
        );
        p.idx = saved_idx; // restore position
        is_select
    } else {
        false
    };

    if values_in_parens && is_tuple_form && !is_subquery_rhs {
        // Tuple form with expression list: (val1, val2, ...)
        p.advance(); // (
        p.skip_trivia();

        loop {
            if let Some(tok) = p.peek_non_trivia() {
                if matches!(
                    tok.kind,
                    TokenKind::Punctuation(crate::lexer::Punctuation::RParen)
                ) {
                    break;
                }
            }

            // Parse expression
            let expr = try_parse_expr_scripting(p)?;
            values.push(expr);

            p.skip_trivia();

            // Check for comma or closing paren
            if let Some(tok) = p.peek_non_trivia() {
                if matches!(
                    tok.kind,
                    TokenKind::Punctuation(crate::lexer::Punctuation::Comma)
                ) {
                    p.advance(); // ,
                    p.skip_trivia();
                } else if matches!(
                    tok.kind,
                    TokenKind::Punctuation(crate::lexer::Punctuation::RParen)
                ) {
                    break;
                }
            }
        }

        p.advance(); // )
    } else {
        // Single expression (may be a subquery in parentheses like (SELECT AS STRUCT ...))
        let expr = try_parse_expr_scripting(p)?;
        values.push(expr);
    }

    // Calculate end span
    let end = if !values.is_empty() {
        values
            .last()
            .map(crate::parser::scripting::expr_span_end)
            .unwrap_or(set_span.end)
    } else {
        set_span.end
    };

    // Handle optional semicolon
    p.skip_trivia();
    let final_end = if let Some(tok) = p.peek_non_trivia() {
        if matches!(
            tok.kind,
            TokenKind::Punctuation(crate::lexer::Punctuation::Semi)
        ) {
            let semi = p
                .advance()
                .expect_invariant("semicolon after peek in SET statement");
            semi.span.end
        } else {
            end
        }
    } else {
        end
    };

    Ok(AstStmt::SetVariable {
        node_id: p.id_gen.next(),
        span: Span {
            start: stmt_start,
            end: final_end,
        },
        set_span,
        variable_names,
        is_tuple_form,
        values,
    })
}

// =============================================================================
// Parser methods - scripting statement parsing
// =============================================================================

impl Parser<'_> {
    // Wrapper methods that delegate to the standalone functions above.
    // These allow calling as self.method() instead of module::function(self).

    pub(crate) fn try_parse_set_variable_stmt(&mut self) -> crate::error::ParseResult<AstStmt> {
        try_parse_set_variable_stmt(self)
    }

    pub(crate) fn try_parse_scripting_block(&mut self) -> crate::error::ParseResult<AstStmt> {
        try_parse_scripting_block(self)
    }

    pub(crate) fn try_parse_block_stmt(&mut self) -> crate::error::ParseResult<AstStmt> {
        try_parse_block_stmt(self)
    }

    pub(crate) fn try_parse_begin_transaction_stmt(
        &mut self,
    ) -> crate::error::ParseResult<AstStmt> {
        try_parse_begin_transaction_stmt(self)
    }

    pub(crate) fn try_parse_commit_stmt(&mut self) -> crate::error::ParseResult<AstStmt> {
        try_parse_commit_stmt(self)
    }

    pub(crate) fn try_parse_rollback_stmt(&mut self) -> crate::error::ParseResult<AstStmt> {
        try_parse_rollback_stmt(self)
    }

    pub(crate) fn try_parse_grant_stmt(&mut self) -> crate::error::ParseResult<AstStmt> {
        try_parse_grant_stmt(self)
    }

    pub(crate) fn try_parse_revoke_stmt(&mut self) -> crate::error::ParseResult<AstStmt> {
        try_parse_revoke_stmt(self)
    }

    pub(crate) fn try_parse_deny_stmt(&mut self) -> crate::error::ParseResult<AstStmt> {
        try_parse_deny_stmt(self)
    }

    pub(crate) fn try_parse_create_procedure(&mut self) -> crate::error::ParseResult<AstStmt> {
        try_parse_create_procedure(self)
    }
}

// ════════════════════════════════════════════════════════════════════════════
// MSSQL GOTO / Label helpers
// ════════════════════════════════════════════════════════════════════════════

/// Lookahead helper: returns `true` when the token at `idx` is an identifier
/// and the very next non-trivia token is a colon (`:`).  Used as a match guard
/// to distinguish `label_name:` declarations from regular identifiers.
pub(crate) fn is_mssql_label_at(tokens: &[Token], idx: usize) -> bool {
    // The token at `idx` is already known to be an Identifier (match guard).
    // Scan forward from idx+1, skipping trivia (comments/EOF), looking for Colon.
    let mut i = idx + 1;
    while i < tokens.len() {
        let kind = &tokens[i].kind;
        if matches!(
            kind,
            TokenKind::LineComment | TokenKind::BlockComment | TokenKind::Eof
        ) {
            i += 1;
            continue;
        }
        return matches!(
            kind,
            TokenKind::Punctuation(crate::lexer::Punctuation::Colon)
        );
    }
    false
}

/// Consume a label name + colon, then dispatch to the appropriate loop/block parser.
/// Called from both the Identifier and Keyword match arms when `is_label_before_loop_at` is true.
pub(crate) fn parse_label_and_dispatch(
    p: &mut Parser<'_>,
    begin_start: u32,
) -> ParseResult<AstStmt> {
    // Consume label name
    let label_tok = p.advance().expect_invariant("label name consumed");
    let label_start = label_tok.span.start;
    // Consume colon
    let colon_tok = p.advance().expect_invariant("colon consumed after label");
    let label_span = Some(Span {
        start: label_start,
        end: colon_tok.span.end,
    });
    // Now peek the keyword to route to the appropriate parser
    p.skip_trivia();
    let kw_tok = p.peek_non_trivia().ok_or_else(|| {
        ParseError::new(
            p.current_span(),
            ParseErrorKind::InvalidStatement {
                message: "Expected WHILE, LOOP, REPEAT, FOR, or BEGIN after label".to_string(),
            },
        )
    })?;
    match &kw_tok.kind {
        TokenKind::Keyword(Keyword::While) => {
            if p.dialect.uses_block_scoped_control_flow() {
                try_parse_mssql_while(p)
            } else {
                try_parse_while_stmt_in_block(p, begin_start, label_span)
            }
        }
        TokenKind::Keyword(Keyword::For) => try_parse_for_stmt_in_block(p, begin_start, label_span),
        TokenKind::Keyword(Keyword::Repeat) => {
            try_parse_repeat_stmt_in_block(p, begin_start, label_span)
        }
        TokenKind::Keyword(Keyword::Loop) => {
            try_parse_loop_stmt_in_block(p, begin_start, label_span)
        }
        TokenKind::Keyword(Keyword::Begin) => try_parse_block_stmt_with_label(p, label_span),
        _ => Err(ParseError::new(
            kw_tok.span,
            ParseErrorKind::InvalidStatement {
                message: format!(
                    "Expected WHILE, LOOP, REPEAT, FOR, or BEGIN after label, found {}",
                    Parser::token_description(kw_tok, p.source)
                ),
            },
        )),
    }
}

/// Check whether tokens at `idx` form `BULK INSERT` (two-token lookahead).
/// `idx` is the position of the BULK identifier.
pub(crate) fn is_mssql_bulk_insert_at(tokens: &[Token], idx: usize) -> bool {
    let mut i = idx + 1;
    while i < tokens.len() {
        let kind = &tokens[i].kind;
        if matches!(
            kind,
            TokenKind::LineComment | TokenKind::BlockComment | TokenKind::Eof
        ) {
            i += 1;
            continue;
        }
        return matches!(kind, TokenKind::Keyword(Keyword::Insert));
    }
    false
}

/// Check whether tokens at `idx` form a label before a loop/block keyword:
/// `name : WHILE|FOR|REPEAT|LOOP|BEGIN`. The name can be an Identifier or a
/// Keyword used as a label (e.g., `outer: WHILE ...`). Used as a match guard
/// to distinguish labels from assignment or other statements.
///
/// The caller's match arm guarantees `idx` is an Identifier or Keyword token.
/// This function excludes LEAVE/ITERATE (those are loop-control, not labels)
/// and the loop keywords themselves (WHILE/FOR/REPEAT/LOOP/BEGIN) to avoid
/// misinterpreting `WHILE cond DO ...` as a label.
pub(crate) fn is_label_before_loop_at(tokens: &[Token], idx: usize, source: &str) -> bool {
    let lexeme = tokens[idx].lexeme(source);
    // LEAVE/ITERATE are loop-control, not labels
    if lexeme.eq_ignore_ascii_case("LEAVE") || lexeme.eq_ignore_ascii_case("ITERATE") {
        return false;
    }
    // Loop/block keywords at this position are their own statements, not labels
    if matches!(
        tokens[idx].kind,
        TokenKind::Keyword(Keyword::While)
            | TokenKind::Keyword(Keyword::For)
            | TokenKind::Keyword(Keyword::Repeat)
            | TokenKind::Keyword(Keyword::Loop)
            | TokenKind::Keyword(Keyword::Begin)
            | TokenKind::Keyword(Keyword::Break)
            | TokenKind::Keyword(Keyword::Continue)
            | TokenKind::Keyword(Keyword::Exit)
    ) {
        return false;
    }
    // Scan forward from idx+1 skipping trivia, looking for Colon.
    let mut i = idx + 1;
    while i < tokens.len() {
        let kind = &tokens[i].kind;
        if matches!(
            kind,
            TokenKind::LineComment | TokenKind::BlockComment | TokenKind::Eof
        ) {
            i += 1;
            continue;
        }
        if !matches!(
            kind,
            TokenKind::Punctuation(crate::lexer::Punctuation::Colon)
        ) {
            return false;
        }
        // Found colon. Now look for the loop/block keyword after it.
        i += 1;
        while i < tokens.len() {
            let kind2 = &tokens[i].kind;
            if matches!(
                kind2,
                TokenKind::LineComment | TokenKind::BlockComment | TokenKind::Eof
            ) {
                i += 1;
                continue;
            }
            return matches!(
                kind2,
                TokenKind::Keyword(Keyword::While)
                    | TokenKind::Keyword(Keyword::For)
                    | TokenKind::Keyword(Keyword::Repeat)
                    | TokenKind::Keyword(Keyword::Loop)
                    | TokenKind::Keyword(Keyword::Begin)
            );
        }
        return false;
    }
    false
}

/// Parse MSSQL `WAITFOR DELAY 'time'` or `WAITFOR TIME 'time'`.
///
/// Delays execution for a specified interval (DELAY) or until a specified
/// wall-clock time (TIME).
pub(crate) fn try_parse_mssql_waitfor(p: &mut Parser<'_>) -> ParseResult<AstStmt> {
    // ── WAITFOR keyword (Identifier token with lexeme "WAITFOR") ──
    let waitfor_tok = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["WAITFOR".to_string()])?;
    let start = waitfor_tok.span.start;

    // ── DELAY or TIME (Identifier tokens) ──
    let kind_tok = p.advance().ok_or_eof(
        p.current_span(),
        vec!["DELAY".to_string(), "TIME".to_string()],
    )?;
    let kind_lexeme = kind_tok.lexeme(p.source);
    if !kind_lexeme.eq_ignore_ascii_case("DELAY") && !kind_lexeme.eq_ignore_ascii_case("TIME") {
        return Err(ParseError::new(
            kind_tok.span,
            ParseErrorKind::InvalidStatement {
                message: format!(
                    "Expected DELAY or TIME after WAITFOR, found '{}'",
                    kind_lexeme
                ),
            },
        ));
    }
    let kind_span = kind_tok.span;

    // ── Time string literal ──
    let value_tok = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["time string literal".to_string()])?;
    let value_span = value_tok.span;
    let end = value_span.end;

    // Capture semicolon if present
    let semicolon_token = if let Some(semi_tok) = p.peek_non_trivia() {
        if matches!(
            semi_tok.kind,
            TokenKind::Punctuation(crate::lexer::Punctuation::Semi)
        ) {
            Some(p.current_token_id())
        } else {
            None
        }
    } else {
        None
    };

    Ok(AstStmt::MssqlWaitfor(Box::new(
        crate::ast::AstMssqlWaitfor {
            node_id: p.id_gen.next(),
            span: Span { start, end },
            kind_span,
            value_span,
            semicolon_token,
        },
    )))
}

/// Parse MSSQL `GOTO label_name`.
///
/// Jumps unconditionally to the named label.
pub(crate) fn try_parse_mssql_goto(p: &mut Parser<'_>) -> ParseResult<AstStmt> {
    // ── GOTO keyword (Identifier token with lexeme "GOTO") ──
    let goto_tok = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["GOTO".to_string()])?;
    let start = goto_tok.span.start;

    // ── Target label name ──
    let label_tok = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["label name".to_string()])?;
    let label_span = label_tok.span;
    let end = label_span.end;

    // Capture semicolon if present (don't consume — block loop will skip it)
    let semicolon_token = if let Some(semi_tok) = p.peek_non_trivia() {
        if matches!(
            semi_tok.kind,
            TokenKind::Punctuation(crate::lexer::Punctuation::Semi)
        ) {
            Some(p.current_token_id())
        } else {
            None
        }
    } else {
        None
    };

    Ok(AstStmt::MssqlGoto(Box::new(crate::ast::AstMssqlGoto {
        node_id: p.id_gen.next(),
        span: Span { start, end },
        label_span,
        semicolon_token,
    })))
}

/// Parse MSSQL label declaration `label_name:`.
///
/// A label is an identifier immediately followed by a colon at statement level.
pub(crate) fn try_parse_mssql_label(p: &mut Parser<'_>) -> ParseResult<AstStmt> {
    // ── Label name (Identifier) ──
    let name_tok = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["label name".to_string()])?;
    let start = name_tok.span.start;
    let label_name_span = name_tok.span;

    // ── Colon ──
    let colon_tok = p
        .advance()
        .ok_or_eof(p.current_span(), vec![":".to_string()])?;
    let end = colon_tok.span.end;

    Ok(AstStmt::MssqlLabel(Box::new(crate::ast::AstMssqlLabel {
        node_id: p.id_gen.next(),
        span: Span { start, end },
        label_name_span,
    })))
}

/// Parse MSSQL `BULK INSERT table FROM 'filepath' [WITH (options)]`.
pub(crate) fn try_parse_mssql_bulk_insert(p: &mut Parser<'_>) -> ParseResult<AstStmt> {
    // ── BULK keyword (Identifier token with lexeme "BULK") ──
    let bulk_tok = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["BULK".to_string()])?;
    let start = bulk_tok.span.start;

    // ── INSERT keyword ──
    let insert_tok = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["INSERT".to_string()])?;
    if !matches!(insert_tok.kind, TokenKind::Keyword(Keyword::Insert)) {
        return Err(ParseError::new(
            insert_tok.span,
            ParseErrorKind::InvalidStatement {
                message: format!(
                    "Expected INSERT after BULK, found '{}'",
                    insert_tok.lexeme(p.source)
                ),
            },
        ));
    }

    // ── Table name (possibly schema-qualified: schema.table or [schema].[table]) ──
    let first_part = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["table name".to_string()])?;
    let table_start = first_part.span.start;
    let mut table_end = first_part.span.end;

    // Consume dot-separated parts
    while let Some(dot_tok) = p.peek_non_trivia() {
        if !matches!(
            dot_tok.kind,
            TokenKind::Punctuation(crate::lexer::Punctuation::Dot)
        ) {
            break;
        }
        p.advance(); // consume dot
        let part = p
            .advance()
            .ok_or_eof(p.current_span(), vec!["identifier after dot".to_string()])?;
        table_end = part.span.end;
    }
    let table_span = Span {
        start: table_start,
        end: table_end,
    };

    // ── FROM keyword ──
    let from_tok = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["FROM".to_string()])?;
    if !matches!(from_tok.kind, TokenKind::Keyword(Keyword::From)) {
        return Err(ParseError::new(
            from_tok.span,
            ParseErrorKind::InvalidStatement {
                message: format!(
                    "Expected FROM after table name in BULK INSERT, found '{}'",
                    from_tok.lexeme(p.source)
                ),
            },
        ));
    }

    // ── Filepath string literal ──
    let filepath_tok = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["filepath string".to_string()])?;
    let filepath_span = filepath_tok.span;
    let mut end = filepath_span.end;

    // ── Optional WITH (options) clause ──
    let options_span = if let Some(with_tok) = p.peek_non_trivia() {
        if matches!(with_tok.kind, TokenKind::Keyword(Keyword::With)) {
            let with_start = with_tok.span.start;
            p.advance(); // consume WITH

            // Expect opening paren
            let lparen_tok = p.peek_non_trivia().ok_or_else(|| {
                ParseError::new(
                    p.current_span(),
                    ParseErrorKind::InvalidStatement {
                        message: "Expected '(' after WITH in BULK INSERT".to_string(),
                    },
                )
            })?;
            if !matches!(
                lparen_tok.kind,
                TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
            ) {
                return Err(ParseError::new(
                    lparen_tok.span,
                    ParseErrorKind::InvalidStatement {
                        message: "Expected '(' after WITH in BULK INSERT".to_string(),
                    },
                ));
            }
            p.advance(); // consume LParen

            // Consume everything inside parens (balanced)
            let mut depth: u32 = 1;
            let mut last_span = p.current_span();
            while depth > 0 {
                let tok = p.advance().ok_or_eof(
                    p.current_span(),
                    vec!["closing ')' for WITH options".to_string()],
                )?;
                last_span = tok.span;
                match tok.kind {
                    TokenKind::Punctuation(crate::lexer::Punctuation::LParen) => depth += 1,
                    TokenKind::Punctuation(crate::lexer::Punctuation::RParen) => depth -= 1,
                    _ => {}
                }
            }

            let opts_end = last_span.end;
            end = opts_end;
            Some(Span {
                start: with_start,
                end: opts_end,
            })
        } else {
            None
        }
    } else {
        None
    };

    // Capture semicolon if present
    let semicolon_token = if let Some(semi_tok) = p.peek_non_trivia() {
        if matches!(
            semi_tok.kind,
            TokenKind::Punctuation(crate::lexer::Punctuation::Semi)
        ) {
            Some(p.current_token_id())
        } else {
            None
        }
    } else {
        None
    };

    Ok(AstStmt::MssqlBulkInsert(Box::new(
        crate::ast::AstMssqlBulkInsert {
            node_id: p.id_gen.next(),
            span: Span { start, end },
            table_span,
            filepath_span,
            options_span,
            semicolon_token,
        },
    )))
}

// ---------------------------------------------------------------------------
// Databricks SIGNAL / RESIGNAL / GET DIAGNOSTICS
// ---------------------------------------------------------------------------

/// Parse Databricks SIGNAL statement:
///   SIGNAL condition_name
///   SIGNAL SQLSTATE [VALUE] 'nnnnn'
///   SIGNAL condition_name SET MESSAGE_TEXT = '...', MESSAGE_ARGUMENTS = (...)
fn try_parse_signal_stmt(p: &mut Parser<'_>) -> ParseResult<AstStmt> {
    let signal_tok = p.advance().expect_invariant("SIGNAL consumed after match");
    let start = signal_tok.span.start;
    let mut end = signal_tok.span.end;

    // Parse condition specification (optional — bare SIGNAL is valid inside a handler)
    let mut condition_spec_start = None;
    let mut condition_spec_end = end;
    if let Some(next) = p.peek_non_trivia() {
        if !matches!(next.kind, TokenKind::Punctuation(Punctuation::Semi))
            && !matches!(next.kind, TokenKind::Keyword(Keyword::Set))
        {
            // Could be: SQLSTATE [VALUE] 'nnnnn' or condition_name
            condition_spec_start = Some(next.span.start);
            if next.lexeme(p.source).eq_ignore_ascii_case("SQLSTATE") {
                let sqlstate_tok = p.advance().expect_invariant("SQLSTATE consumed");
                condition_spec_end = sqlstate_tok.span.end;
                // Optional VALUE keyword
                if let Some(val_tok) = p.peek_non_trivia() {
                    if val_tok.lexeme(p.source).eq_ignore_ascii_case("VALUE") {
                        let v = p.advance().expect_invariant("VALUE consumed");
                        condition_spec_end = v.span.end;
                    }
                }
                // SQLSTATE value (string literal)
                if let Some(lit) = p.peek_non_trivia() {
                    if matches!(lit.kind, TokenKind::Literal(_)) {
                        let l = p.advance().expect_invariant("SQLSTATE value consumed");
                        condition_spec_end = l.span.end;
                    }
                }
            } else if p.can_be_identifier_token(next) {
                let name_tok = p.advance().expect_invariant("condition name consumed");
                condition_spec_end = name_tok.span.end;
            }
            end = condition_spec_end;
        }
    }

    let condition_spec_span = condition_spec_start.map(|s| Span {
        start: s,
        end: condition_spec_end,
    });

    // Parse optional SET clause
    let set_clause_span = parse_signal_set_clause(p, &mut end);

    // Optional semicolon
    let semicolon_token = consume_optional_semi(p, &mut end);

    let span = Span { start, end };
    Ok(AstStmt::Signal {
        node_id: p.id_gen.next(),
        span,
        signal_span: signal_tok.span,
        condition_spec_span,
        set_clause_span,
        semicolon_token,
    })
}

/// Parse Databricks RESIGNAL statement:
///   RESIGNAL
///   RESIGNAL SET MESSAGE_TEXT = '...'
fn try_parse_resignal_stmt(p: &mut Parser<'_>) -> ParseResult<AstStmt> {
    let resignal_tok = p
        .advance()
        .expect_invariant("RESIGNAL consumed after match");
    let start = resignal_tok.span.start;
    let mut end = resignal_tok.span.end;

    // Parse optional SET clause
    let set_clause_span = parse_signal_set_clause(p, &mut end);

    // Optional semicolon
    let semicolon_token = consume_optional_semi(p, &mut end);

    let span = Span { start, end };
    Ok(AstStmt::Resignal {
        node_id: p.id_gen.next(),
        span,
        resignal_span: resignal_tok.span,
        set_clause_span,
        semicolon_token,
    })
}

/// Parse the SET clause for SIGNAL/RESIGNAL:
///   SET MESSAGE_TEXT = '...', MESSAGE_ARGUMENTS = (...), ...
/// Returns the span covering the entire SET clause, or None.
fn parse_signal_set_clause(p: &mut Parser<'_>, end: &mut u32) -> Option<Span> {
    if let Some(set_tok) = p.peek_non_trivia() {
        if matches!(set_tok.kind, TokenKind::Keyword(Keyword::Set)) {
            let set_start = set_tok.span.start;
            let _ = p.advance(); // consume SET
            let mut set_end = set_tok.span.end;

            // Parse assignment items: item_name = value [, item_name = value ...]
            loop {
                p.skip_trivia();
                if let Some(name_tok) = p.peek_non_trivia() {
                    if !p.can_be_identifier_token(name_tok) {
                        break;
                    }
                    let n = p.advance().expect_invariant("SET item name consumed");
                    set_end = n.span.end;

                    // Expect =
                    p.skip_trivia();
                    if let Some(eq_tok) = p.peek_non_trivia() {
                        if matches!(eq_tok.kind, TokenKind::Operator(crate::lexer::Operator::Eq)) {
                            let e = p.advance().expect_invariant("= consumed");
                            set_end = e.span.end;
                        }
                    }

                    // Parse value — could be a string literal or a parenthesized expression
                    p.skip_trivia();
                    if let Some(val_tok) = p.peek_non_trivia() {
                        if matches!(val_tok.kind, TokenKind::Punctuation(Punctuation::LParen)) {
                            // Parenthesized value — consume balanced parens
                            let _ = p.advance(); // consume (
                            let mut depth = 1u32;
                            while depth > 0 {
                                if let Some(t) = p.advance() {
                                    match t.kind {
                                        TokenKind::Punctuation(Punctuation::LParen) => depth += 1,
                                        TokenKind::Punctuation(Punctuation::RParen) => depth -= 1,
                                        TokenKind::Eof => break,
                                        _ => {}
                                    }
                                    set_end = t.span.end;
                                } else {
                                    break;
                                }
                            }
                        } else if !matches!(val_tok.kind, TokenKind::Punctuation(Punctuation::Semi))
                            && !matches!(val_tok.kind, TokenKind::Eof)
                        {
                            let v = p.advance().expect_invariant("SET value consumed");
                            set_end = v.span.end;
                        }
                    }

                    // Check for comma to continue
                    p.skip_trivia();
                    if let Some(comma_tok) = p.peek_non_trivia() {
                        if matches!(comma_tok.kind, TokenKind::Punctuation(Punctuation::Comma)) {
                            let c = p.advance().expect_invariant("comma consumed");
                            set_end = c.span.end;
                            continue;
                        }
                    }
                }
                break;
            }

            *end = set_end;
            return Some(Span {
                start: set_start,
                end: set_end,
            });
        }
    }
    None
}

/// Parse Databricks GET DIAGNOSTICS CONDITION statement:
///   GET DIAGNOSTICS CONDITION condition_number var = item_name [, var = item_name ...]
fn try_parse_get_diagnostics_stmt(p: &mut Parser<'_>) -> ParseResult<AstStmt> {
    let get_tok = p.advance().expect_invariant("GET consumed after match");
    let start = get_tok.span.start;
    let mut end = get_tok.span.end;

    // Consume DIAGNOSTICS
    p.skip_trivia();
    if let Some(diag_tok) = p.peek_non_trivia() {
        if diag_tok
            .lexeme(p.source)
            .eq_ignore_ascii_case("DIAGNOSTICS")
        {
            let d = p.advance().expect_invariant("DIAGNOSTICS consumed");
            end = d.span.end;
        }
    }

    // Consume CONDITION
    p.skip_trivia();
    if let Some(cond_tok) = p.peek_non_trivia() {
        if cond_tok.lexeme(p.source).eq_ignore_ascii_case("CONDITION") {
            let c = p.advance().expect_invariant("CONDITION consumed");
            end = c.span.end;
        }
    }

    // Consume condition number (usually a literal number or identifier)
    p.skip_trivia();
    if let Some(num_tok) = p.peek_non_trivia() {
        if matches!(num_tok.kind, TokenKind::Literal(_)) || p.can_be_identifier_token(num_tok) {
            let n = p.advance().expect_invariant("condition number consumed");
            end = n.span.end;
        }
    }

    // Parse assignment items: var = item_name [, var = item_name ...]
    loop {
        p.skip_trivia();
        if let Some(var_tok) = p.peek_non_trivia() {
            if !p.can_be_identifier_token(var_tok)
                || matches!(var_tok.kind, TokenKind::Punctuation(Punctuation::Semi))
            {
                break;
            }
            let v = p.advance().expect_invariant("variable name consumed");
            end = v.span.end;

            // Expect =
            p.skip_trivia();
            if let Some(eq_tok) = p.peek_non_trivia() {
                if matches!(eq_tok.kind, TokenKind::Operator(crate::lexer::Operator::Eq)) {
                    let e = p.advance().expect_invariant("= consumed");
                    end = e.span.end;
                }
            }

            // Parse item name (MESSAGE_TEXT, RETURNED_SQLSTATE, etc.)
            p.skip_trivia();
            if let Some(item_tok) = p.peek_non_trivia() {
                if p.can_be_identifier_token(item_tok) {
                    let i = p.advance().expect_invariant("item name consumed");
                    end = i.span.end;
                }
            }

            // Check for comma
            p.skip_trivia();
            if let Some(comma_tok) = p.peek_non_trivia() {
                if matches!(comma_tok.kind, TokenKind::Punctuation(Punctuation::Comma)) {
                    let c = p.advance().expect_invariant("comma consumed");
                    end = c.span.end;
                    continue;
                }
            }
        }
        break;
    }

    // Optional semicolon
    let semicolon_token = consume_optional_semi(p, &mut end);

    let diagnostics_span = Span {
        start: get_tok.span.start,
        end,
    };
    let span = Span { start, end };
    Ok(AstStmt::GetDiagnostics {
        node_id: p.id_gen.next(),
        span,
        diagnostics_span,
        semicolon_token,
    })
}

/// Parse DECLARE CONDITION body:
///   DECLARE condition_name CONDITION FOR SQLSTATE [VALUE] 'nnnnn'
/// Called after DECLARE and condition_name have been consumed; peek is at "CONDITION".
fn try_parse_declare_condition_body(
    p: &mut Parser<'_>,
    start: u32,
    declare_span: Option<Span>,
    condition_name_span: Span,
) -> ParseResult<AstStmt> {
    let cond_tok = p.advance().expect_invariant("CONDITION consumed");
    let mut end = cond_tok.span.end;
    let spec_start = cond_tok.span.start;

    // Expect FOR
    p.skip_trivia();
    if let Some(for_tok) = p.peek_non_trivia() {
        if matches!(for_tok.kind, TokenKind::Keyword(Keyword::For)) {
            let f = p.advance().expect_invariant("FOR consumed");
            end = f.span.end;
        }
    }

    // Expect SQLSTATE
    p.skip_trivia();
    if let Some(ss_tok) = p.peek_non_trivia() {
        if ss_tok.lexeme(p.source).eq_ignore_ascii_case("SQLSTATE") {
            let s = p.advance().expect_invariant("SQLSTATE consumed");
            end = s.span.end;
        }
    }

    // Optional VALUE keyword
    p.skip_trivia();
    if let Some(val_tok) = p.peek_non_trivia() {
        if val_tok.lexeme(p.source).eq_ignore_ascii_case("VALUE") {
            let v = p.advance().expect_invariant("VALUE consumed");
            end = v.span.end;
        }
    }

    // SQLSTATE value (string literal)
    p.skip_trivia();
    if let Some(lit) = p.peek_non_trivia() {
        if matches!(lit.kind, TokenKind::Literal(_)) {
            let l = p.advance().expect_invariant("SQLSTATE value consumed");
            end = l.span.end;
        }
    }

    let condition_spec_span = Span {
        start: spec_start,
        end,
    };

    // Optional semicolon
    let semicolon_token = consume_optional_semi(p, &mut end);

    let span = Span { start, end };
    Ok(AstStmt::DeclareCondition {
        node_id: p.id_gen.next(),
        span,
        condition_name_span,
        condition_spec_span,
        declare_span,
        semicolon_token,
    })
}

/// Parse DECLARE HANDLER body:
///   DECLARE EXIT|CONTINUE HANDLER FOR condition_value [,...] statement
/// Called after DECLARE, EXIT/CONTINUE have been consumed; peek is at "HANDLER".
fn try_parse_declare_handler_body(
    p: &mut Parser<'_>,
    start: u32,
    declare_span: Option<Span>,
    handler_type: ExceptionHandlerType,
    handler_type_span: Span,
) -> ParseResult<AstStmt> {
    let handler_tok = p.advance().expect_invariant("HANDLER consumed");
    let handler_for_start = handler_tok.span.start;
    let mut end = handler_tok.span.end;

    // Expect FOR
    p.skip_trivia();
    if let Some(for_tok) = p.peek_non_trivia() {
        if matches!(for_tok.kind, TokenKind::Keyword(Keyword::For)) {
            let f = p.advance().expect_invariant("FOR consumed");
            end = f.span.end;
        }
    }
    let handler_for_span = Span {
        start: handler_for_start,
        end,
    };

    // Parse condition values (comma-separated). The parser is the single
    // site that classifies the lexeme into the closed-enum
    // `AstHandlerConditionKind`; downstream code reads the typed kind.
    use crate::ast::{AstHandlerCondition, AstHandlerConditionKind};
    let mut conditions: Vec<AstHandlerCondition> = Vec::new();
    loop {
        p.skip_trivia();
        if let Some(tok) = p.peek_non_trivia() {
            let cond_start = tok.span.start;
            let cond_end;
            let kind: AstHandlerConditionKind;

            if tok.lexeme(p.source).eq_ignore_ascii_case("SQLSTATE") {
                // SQLSTATE [VALUE] 'nnnnn'
                let ss = p.advance().expect_invariant("SQLSTATE consumed");
                let mut ss_end = ss.span.end;
                let mut value_keyword_span: Option<Span> = None;
                let mut value_literal_span: Option<Span> = None;

                // Optional VALUE
                p.skip_trivia();
                if let Some(val) = p.peek_non_trivia() {
                    if val.lexeme(p.source).eq_ignore_ascii_case("VALUE") {
                        let v = p.advance().expect_invariant("VALUE consumed");
                        value_keyword_span = Some(v.span);
                        ss_end = v.span.end;
                    }
                }
                // SQLSTATE value
                p.skip_trivia();
                if let Some(lit) = p.peek_non_trivia() {
                    if matches!(lit.kind, TokenKind::Literal(_)) {
                        let l = p.advance().expect_invariant("SQLSTATE value consumed");
                        value_literal_span = Some(l.span);
                        ss_end = l.span.end;
                    }
                }
                cond_end = ss_end;
                kind = AstHandlerConditionKind::SqlState {
                    value_keyword_span,
                    value_literal_span,
                };
            } else if tok.lexeme(p.source).eq_ignore_ascii_case("SQLEXCEPTION") {
                let t = p.advance().expect_invariant("SQLEXCEPTION consumed");
                cond_end = t.span.end;
                kind = AstHandlerConditionKind::SqlException;
            } else if tok.lexeme(p.source).eq_ignore_ascii_case("SQLWARNING") {
                let t = p.advance().expect_invariant("SQLWARNING consumed");
                cond_end = t.span.end;
                kind = AstHandlerConditionKind::SqlWarning;
            } else if matches!(tok.kind, TokenKind::Keyword(Keyword::Not)) {
                // NOT FOUND
                let not_tok = p.advance().expect_invariant("NOT consumed");
                let mut nf_end = not_tok.span.end;
                p.skip_trivia();
                if let Some(found_tok) = p.peek_non_trivia() {
                    if found_tok.lexeme(p.source).eq_ignore_ascii_case("FOUND") {
                        let f = p.advance().expect_invariant("FOUND consumed");
                        nf_end = f.span.end;
                    }
                }
                cond_end = nf_end;
                kind = AstHandlerConditionKind::NotFound;
            } else if p.can_be_identifier_token(tok) {
                // condition_name (user-defined condition name)
                let t = p.advance().expect_invariant("condition name consumed");
                cond_end = t.span.end;
                kind = AstHandlerConditionKind::NamedCondition { name_span: t.span };
            } else {
                break; // Not a condition value → end of condition list
            }

            conditions.push(AstHandlerCondition {
                span: Span {
                    start: cond_start,
                    end: cond_end,
                },
                kind,
            });

            // Check for comma to continue
            p.skip_trivia();
            if let Some(comma_tok) = p.peek_non_trivia() {
                if matches!(comma_tok.kind, TokenKind::Punctuation(Punctuation::Comma)) {
                    let _ = p.advance(); // consume comma
                    continue;
                }
            }
        }
        break;
    }

    // Parse handler action: either a compound BEGIN...END block or a single statement.
    // This mirrors the dispatch in try_parse_block_stmt's body loop: BEGIN is handled
    // separately because parse_statement() is the top-level SQL parser and doesn't
    // know about scripting blocks. We can't use try_parse_scripting_stmt here because
    // it routes DECLARE through try_parse_scripting_block, which can consume unrelated
    // preceding declarations from the enclosing scope.
    let handler_action = match p.peek_non_trivia().map(|t| t.kind.clone()) {
        Some(TokenKind::Keyword(Keyword::Begin)) => try_parse_block_stmt(p)?,
        _ => p.parse_statement()?,
    };
    end = handler_action.span().end;

    // Optional semicolon after the handler action
    let semicolon_token = consume_optional_semi(p, &mut end);

    let span = Span { start, end };
    Ok(AstStmt::DeclareHandler(Box::new(
        crate::ast::AstDeclareHandlerStmt {
            node_id: p.id_gen.next(),
            span,
            declare_span,
            handler_type,
            handler_type_span,
            handler_for_span,
            conditions,
            handler_action: Box::new(handler_action),
            semicolon_token,
        },
    )))
}

/// Helper: consume an optional trailing semicolon, update `end` span, and return TokenId
fn consume_optional_semi(p: &mut Parser<'_>, end: &mut u32) -> Option<crate::cst::TokenId> {
    p.skip_trivia();
    if let Some(semi_tok) = p.peek_non_trivia() {
        if matches!(semi_tok.kind, TokenKind::Punctuation(Punctuation::Semi)) {
            let semi_id = p.current_token_id();
            let s = p.advance().expect_invariant("semicolon consumed");
            *end = s.span.end;
            return Some(semi_id);
        }
    }
    None
}

#[cfg(test)]
mod grant_tests {
    use crate::error::ExpectInvariant;
    use crate::lexer::tokenize;
    use crate::parser::core::Parser;

    #[test]
    fn test_parse_two_grant_statements() {
        let sql = "GRANT SELECT ON TABLE lookup_data TO PUBLIC;\nGRANT USAGE ON WAREHOUSE compute_wh TO ROLE PUBLIC;";
        let tokens = tokenize(sql).tokens;
        let mut parser = Parser::new(sql, &tokens);
        let script = parser.try_parse_script().expect_invariant("Should parse");

        eprintln!("SQL: {}", sql);
        eprintln!("Statement count: {}", script.stmts.len());
        for (i, stmt) in script.stmts.iter().enumerate() {
            let span = stmt.span();
            let text = &sql[span.start as usize..span.end as usize];
            eprintln!("  {}. {:?} -> '{}'", i + 1, &stmt, text);
        }

        assert_eq!(
            script.stmts.len(),
            2,
            "Expected 2 statements, got {}",
            script.stmts.len()
        );
    }
}
