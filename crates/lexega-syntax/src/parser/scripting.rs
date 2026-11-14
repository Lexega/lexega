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
    AstExecuteImmediateFrom, AstExecuteUsingArg, AstExpr, AstForEachStmt, AstForIterable,
    AstForStmt, AstFunctionReturns, AstIdentifier, AstIfStmt, AstLiteral, AstLoopStmt,
    AstMssqlSetOptionKind, AstMssqlSetOptionValue, AstPerform, AstRaiseOption, AstRepeatStmt,
    AstReturnsClause, AstRoutineLanguage, AstStmt, AstWhileStmt, CaseBranch, ExceptionHandlerType,
    ExecuteAsMode, IfBranch,
};
use crate::dialect::LabelPosition;
use crate::error::{ExpectInvariant, ParseError, ParseErrorKind, ParseResult, ParseResultExt};
use crate::lexer::{Keyword, LiteralKind, Punctuation, Span, Token, TokenKind};
use crate::parser::core::{Parser, StatementContext};
use crate::parser::principal::{is_skippable, next_non_trivia_idx};
use crate::parser::set_operations::{
    try_parse_select_stmt_with_parser, try_parse_set_or_select_stmt,
};

/// Context for parsing scripting statements, determines what statements are allowed
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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
    /// The batch separator `GO`, where the dialect has one
    BatchSeparator,
    /// The delimiter (`$$`, `$tag$`) closing a dollar-quoted body
    DollarQuoteDelimiter,
}

impl BodyTerminator {
    /// Check if a token matches this terminator.
    fn matches(&self, tok: &Token, p: &Parser<'_>) -> bool {
        match self {
            BodyTerminator::End => matches!(tok.kind, TokenKind::Keyword(Keyword::End)),
            BodyTerminator::Elsif => matches!(tok.kind, TokenKind::Keyword(Keyword::Elsif)),
            BodyTerminator::Else => matches!(tok.kind, TokenKind::Keyword(Keyword::Else)),
            BodyTerminator::When => matches!(tok.kind, TokenKind::Keyword(Keyword::When)),
            BodyTerminator::Until => matches!(tok.kind, TokenKind::Keyword(Keyword::Until)),
            BodyTerminator::Exception => matches!(tok.kind, TokenKind::Keyword(Keyword::Exception)),
            BodyTerminator::BatchSeparator => p.is_batch_separator(tok),
            BodyTerminator::DollarQuoteDelimiter => p.delimits_dollar_quote(tok),
        }
    }

    /// Check if a token matches any of the given terminators.
    fn matches_any(tok: &Token, terminators: &[BodyTerminator], p: &Parser<'_>) -> bool {
        terminators.iter().any(|t| t.matches(tok, p))
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

    // A bare `END` in a statement of a body an `END` closes closes the body.
    let outer_end_closed = p.in_end_closed_body;
    p.in_end_closed_body |= terminators.contains(&BodyTerminator::End);
    // The statement last read, until a `;` ends it: text after it that
    // starts no statement and does not parse is its unread tail.
    let mut unterminated: Option<crate::ast::NodeId> = None;
    loop {
        p.skip_trivia();

        // Check for end of input
        let tok = match p.peek_non_trivia() {
            Some(t) => t,
            None => break,
        };

        // Check for body terminators
        if BodyTerminator::matches_any(tok, terminators, p) {
            break;
        }

        // Skip lone semicolons between statements
        if matches!(
            tok.kind,
            TokenKind::Punctuation(crate::lexer::Punctuation::Semi)
        ) {
            // Consume and skip semicolons between statements in block bodies
            p.advance();
            unterminated = None;
            continue;
        }

        // Track position for error recovery
        let stmt_start_pos = tok.span.start;
        let stmt_start_idx = p.idx;
        let before = unterminated.take();

        // Try to parse a statement
        match try_parse_scripting_stmt(p, context, begin_start) {
            Ok(stmt) => {
                let tail = text_kept_as_written(&stmt);
                unterminated = p.note_statement_read(before, stmt_start_idx, &stmt, tail);
                stmts.push(stmt);
            }
            Err(err) => {
                // Create error node and synchronize
                let (error_node, sync_error) =
                    create_error_and_sync(p, stmt_start_pos, stmt_start_idx, &err, terminators);
                let tail = Some(error_node.span());
                unterminated = p.note_statement_read(before, stmt_start_idx, &error_node, tail);
                stmts.push(error_node);
                errors.push(sync_error.unwrap_or(err));
            }
        }
    }
    p.in_end_closed_body = outer_end_closed;

    (stmts, errors)
}

/// Create an error node for unparseable content and synchronize to next valid point.
///
/// Scans forward until finding:
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

    // A compound statement that does not parse ends at its own `END <kw>`.
    if let Some(end_idx) = compound_statement_end(p, start_idx) {
        partial_tokens.extend(
            p.tokens[start_idx..end_idx]
                .iter()
                .filter(|t| !is_skippable(t))
                .take(max_tokens)
                .map(|t| format!("{:?}", t.kind)),
        );
        end_pos = p.tokens[end_idx - 1].span.end;
        p.idx = end_idx;
        advanced_any = true;
    } else if p.idx == start_idx {
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
        if BodyTerminator::matches_any(tok, terminators, p) {
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

        // Stop where a statement starts (don't consume).
        if advanced_any && p.starts_statement(p.idx, StatementContext::BodyRecovery) {
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

    // A secret in text no statement read is masked like a parsed one.
    p.record_unparsed_secrets(start_idx, p.idx);
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

/// The index just past a label written before a block or loop at `idx`
/// (`name :` or PL/pgSQL's `<< name >>`), with the label's span.
pub(crate) fn label_prefix_at(p: &Parser<'_>, idx: usize) -> Option<(usize, Span)> {
    let tokens = p.tokens;
    let first = tokens.get(idx)?;
    let named = |i: usize| p.can_be_label(i, LabelPosition::StatementLabel);
    let (after, close) = if matches!(
        first.kind,
        TokenKind::Operator(crate::lexer::Operator::LtLt)
    ) {
        let name = next_non_trivia_idx(tokens, idx + 1).filter(|&i| named(i))?;
        let close = next_non_trivia_idx(tokens, name + 1).filter(|&i| {
            matches!(
                tokens[i].kind,
                TokenKind::Operator(crate::lexer::Operator::GtGt)
            )
        })?;
        (close + 1, close)
    } else if named(idx) {
        let colon = next_non_trivia_idx(tokens, idx + 1).filter(|&i| {
            matches!(
                tokens[i].kind,
                TokenKind::Punctuation(crate::lexer::Punctuation::Colon)
            )
        })?;
        (colon + 1, colon)
    } else {
        return None;
    };
    Some((
        after,
        Span {
            start: first.span.start,
            end: tokens[close].span.end,
        },
    ))
}

/// The keywords one of which follows the `END` that closes a compound
/// statement opened by `opener`; empty for a keyword that opens none.
fn compound_closers(opener: &TokenKind) -> &'static [Keyword] {
    let TokenKind::Keyword(kw) = opener else {
        return &[];
    };
    if *kw == Keyword::If {
        &[Keyword::If]
    } else if *kw == Keyword::Case {
        &[Keyword::Case]
    } else if *kw == Keyword::While {
        &[Keyword::While, Keyword::Loop]
    } else if *kw == Keyword::For {
        &[Keyword::For, Keyword::Loop]
    } else if *kw == Keyword::Repeat {
        &[Keyword::Repeat]
    } else if *kw == Keyword::Loop {
        &[Keyword::Loop]
    } else {
        &[]
    }
}

/// The index just past the `END <kw>` that closes the compound statement
/// (`IF`, `CASE`, `WHILE`, `FOR`, `REPEAT` or `LOOP`, after any label)
/// starting at `start`. Every block, compound statement and `CASE` nested in
/// it closes with an `END` of its own; a compound statement opens only where
/// a statement starts. `None` where the dialect's control flow closes with no
/// `END <kw>`, or where the enclosing block's `END`, a dollar-quote delimiter
/// or the end of input comes first.
fn compound_statement_end(p: &Parser<'_>, start: usize) -> Option<usize> {
    if p.dialect.uses_block_scoped_control_flow() {
        return None;
    }
    let tokens = p.tokens;
    let mut opener = next_non_trivia_idx(tokens, start)?;
    if let Some((after, _)) = label_prefix_at(p, opener) {
        opener = next_non_trivia_idx(tokens, after)?;
    }
    let closers = compound_closers(&tokens[opener].kind);
    if closers.is_empty() {
        return None;
    }
    match walk_compound_level(p, opener, closers, |_| false)? {
        CompoundWalk::Closed(end) => Some(end),
        CompoundWalk::Stopped(_) => None,
    }
}

/// Where the header of a compound statement ends ([`compound_header_end`]).
enum HeaderEnd {
    /// At the keyword written after it.
    Keyword(usize),
    /// At the first statement of the body, no keyword being written.
    Statement(usize),
}

/// How a header that is not followed by its keyword ends.
#[derive(Clone, Copy)]
enum NoKeyword {
    /// At the first statement written at the header's level after it: a
    /// header such as an `IF` condition holds no statement there.
    FirstStatement,
    /// Where the statement closes with its own `END <kw>` (`kw` one of the
    /// keywords given), at the first statement written at its level: a
    /// header such as a `FOR` loop's query holds statements there.
    ClosedStatement(&'static [Keyword]),
}

/// Where the header written after token `after` ends, at the own level of
/// the compound statement `after` is part of (not inside a block, compound
/// statement or `CASE` nested in it): at the first of `keywords`, or where
/// none is written, as `no_keyword` says, at the first token there, outside
/// parentheses, that starts a statement or ends one. `None` where neither
/// is found, and where the dialect's control flow closes with no
/// `END <kw>`.
fn compound_header_end(
    p: &Parser<'_>,
    after: usize,
    keywords: &[Keyword],
    no_keyword: NoKeyword,
) -> Option<HeaderEnd> {
    if p.dialect.uses_block_scoped_control_flow() {
        return None;
    }
    let tokens = p.tokens;
    let mut parens = 0usize;
    let mut statement = None;
    let mut stop = |i: usize| {
        let mut semicolon = false;
        match &tokens[i].kind {
            TokenKind::Keyword(k) => {
                if keywords.contains(k) {
                    return true;
                }
            }
            TokenKind::Punctuation(punctuation) => match punctuation {
                Punctuation::LParen => parens += 1,
                Punctuation::RParen => parens = parens.saturating_sub(1),
                Punctuation::Semi => semicolon = true,
                Punctuation::LBracket
                | Punctuation::RBracket
                | Punctuation::LCurly
                | Punctuation::RCurly
                | Punctuation::Comma
                | Punctuation::Dot
                | Punctuation::Colon => {}
            },
            TokenKind::Identifier { .. }
            | TokenKind::Literal(_)
            | TokenKind::Operator(_)
            | TokenKind::LineComment
            | TokenKind::BlockComment
            | TokenKind::JinjaComment
            | TokenKind::JinjaExprOpen
            | TokenKind::JinjaExprClose
            | TokenKind::JinjaStmtOpen
            | TokenKind::JinjaStmtClose
            | TokenKind::JinjaPipe
            | TokenKind::JinjaTilde
            | TokenKind::JinjaDoubleStar
            | TokenKind::JinjaDoubleSlash
            | TokenKind::JinjaDoubleEq
            | TokenKind::JinjaAnd
            | TokenKind::JinjaOr
            | TokenKind::JinjaNot
            | TokenKind::JinjaIn
            | TokenKind::JinjaIs
            | TokenKind::JinjaTrue
            | TokenKind::JinjaFalse
            | TokenKind::JinjaNull
            | TokenKind::JinjaIf
            | TokenKind::JinjaElif
            | TokenKind::JinjaElse
            | TokenKind::JinjaEndIf
            | TokenKind::JinjaFor
            | TokenKind::JinjaEndFor
            | TokenKind::JinjaSet
            | TokenKind::JinjaEndSet
            | TokenKind::JinjaDocs
            | TokenKind::JinjaEndDocs
            | TokenKind::JinjaFilter
            | TokenKind::JinjaEndFilter
            | TokenKind::JinjaCall
            | TokenKind::JinjaEndCall
            | TokenKind::Placeholder
            | TokenKind::Eof
            | TokenKind::Unknown => {}
        }
        // The first statement of the body, or a `;` ending one; a `CASE`
        // here is an expression of the header.
        let starts = semicolon || p.starts_statement(i, StatementContext::CompoundHeader);
        if parens == 0 && statement.is_none() && starts {
            statement = Some(i);
            return matches!(no_keyword, NoKeyword::FirstStatement);
        }
        false
    };
    let closers = match no_keyword {
        NoKeyword::FirstStatement => &[][..],
        NoKeyword::ClosedStatement(closers) => closers,
    };
    match walk_compound_level(p, after, closers, &mut stop)? {
        CompoundWalk::Stopped(i) if Some(i) == statement => Some(HeaderEnd::Statement(i)),
        CompoundWalk::Stopped(i) => Some(HeaderEnd::Keyword(i)),
        CompoundWalk::Closed(_) => statement.map(HeaderEnd::Statement),
    }
}

/// Reads, with `read`, the header of a compound statement written after
/// token `after` (its `IF`, `ELSEIF`, `WHILE`, `WHEN` or `UNTIL`, or a
/// simple `CASE`'s operand after `CASE`), up to the keyword that follows it,
/// one of `openers`. Where the header does not read, it is one piece not
/// parsed ([`unparsed_header`]) up to where it ends
/// ([`compound_header_end`]): the keyword, or where no keyword is written,
/// the body's first statement (as `no_keyword` says); the statement goes on
/// from there, its body read. Fails as `read` fails where neither is found.
fn read_compound_header<T>(
    p: &mut Parser<'_>,
    after: usize,
    openers: &[Keyword],
    no_keyword: NoKeyword,
    read: impl FnOnce(&mut Parser<'_>) -> ParseResult<T>,
) -> ParseResult<Result<T, AstExpr>> {
    let errors = p.recovery_errors.len();
    let err = match read(p) {
        Ok(header) => return Ok(Ok(header)),
        Err(err) => err,
    };
    if err.kind.is_resource_exhaustion() {
        return Err(err);
    }
    let end = match compound_header_end(p, after, openers, no_keyword) {
        Some(HeaderEnd::Keyword(i) | HeaderEnd::Statement(i)) => i,
        None => return Err(err),
    };
    p.recovery_errors.truncate(errors);
    let from = next_non_trivia_idx(p.tokens, after + 1).map_or(end, |i| i.min(end));
    p.idx = end;
    Ok(Err(unparsed_header(p, from, end, &err)))
}

/// Takes the keyword a compound statement's header ended at, one of
/// `keywords`: its token id and span. Where the header ended at the body's
/// first statement, no keyword being written, takes nothing: no id, and an
/// empty span where the body starts.
fn take_header_keyword(
    p: &mut Parser<'_>,
    keywords: &[Keyword],
) -> (Option<crate::cst::TokenId>, Span) {
    p.skip_trivia();
    let next = p.peek_non_trivia();
    if let Some(tok) =
        next.filter(|t| matches!(&t.kind, TokenKind::Keyword(k) if keywords.contains(k)))
    {
        let id = p.current_token_id();
        let span = tok.span;
        p.advance();
        return (Some(id), span);
    }
    let at = next.map_or(p.current_span().start, |t| t.span.start);
    (None, Span { start: at, end: at })
}

/// Whether a compound statement takes the `END` at the parser's position
/// as its own: where every header keyword was written, as it is; where one
/// was not (`keyword_missing`), only an `END` followed by one of `closers`,
/// so such a statement that is never closed leaves the `END` to the block
/// around it.
fn takes_end(p: &Parser<'_>, keyword_missing: bool, closers: &[Keyword]) -> bool {
    !keyword_missing
        || next_non_trivia_idx(p.tokens, p.idx + 1).is_some_and(
            |i| matches!(&p.tokens[i].kind, TokenKind::Keyword(k) if closers.contains(k)),
        )
}

/// Where the text read so far ends: the end of the last token before the
/// parser's position, or `start` where none is.
fn end_of_read(p: &Parser<'_>, start: u32) -> u32 {
    p.tokens[..p.idx]
        .iter()
        .rev()
        .find(|t| !is_skippable(t))
        .map_or(start, |t| t.span.end.max(start))
}

/// The header of a compound statement written in the tokens `from..to` that
/// does not read, as one piece not parsed: an [`AstExpr::Error`] covering
/// it (empty, at `to`, where nothing is written), whose secrets are masked
/// as those of any text not parsed.
fn unparsed_header(p: &mut Parser<'_>, from: usize, to: usize, err: &ParseError) -> AstExpr {
    p.record_unparsed_secrets(from, to);
    let tokens = &p.tokens[from..to];
    let span = match (tokens.first(), tokens.last()) {
        (Some(first), Some(last)) => Span {
            start: first.span.start,
            end: last.span.end,
        },
        (None, _) | (_, None) => {
            let at = p.tokens.get(to).map_or(0, |t| t.span.start);
            Span { start: at, end: at }
        }
    };
    AstExpr::Error {
        node_id: p.id_gen.next(),
        span,
        message: err.message(),
        partial_tokens: tokens
            .iter()
            .filter(|t| !is_skippable(t))
            .take(10)
            .map(|t| format!("{:?}", t.kind))
            .collect(),
    }
}

/// Where [`walk_compound_level`] ended.
enum CompoundWalk {
    /// At a token of the statement's own level the caller stopped at.
    Stopped(usize),
    /// Just past the `END <kw>` closing the statement.
    Closed(usize),
}

/// Walks the tokens after `after` at one level of a compound statement:
/// every block, compound statement and `CASE` nested in it closes with an
/// `END` of its own, and a compound statement opens only where a statement
/// starts. Stops at the first token of this level `stop` accepts, or past
/// the `END <kw>` closing the level, `kw` one of `closers`. `None` where the
/// `END` closes with another keyword, or where a dollar-quote delimiter or
/// the end of input comes first.
fn walk_compound_level(
    p: &Parser<'_>,
    after: usize,
    closers: &[Keyword],
    mut stop: impl FnMut(usize) -> bool,
) -> Option<CompoundWalk> {
    let tokens = p.tokens;
    let keyword_at = |i: Option<usize>, set: &[Keyword]| {
        i.filter(|&i| matches!(&tokens[i].kind, TokenKind::Keyword(k) if set.contains(k)))
    };
    const COMPOUND: &[Keyword] = &[
        Keyword::If,
        Keyword::Case,
        Keyword::While,
        Keyword::For,
        Keyword::Repeat,
        Keyword::Loop,
    ];
    let mut depth = 1usize;
    let mut i = next_non_trivia_idx(tokens, after + 1)?;
    loop {
        if depth == 1 && stop(i) {
            return Some(CompoundWalk::Stopped(i));
        }
        let tok = &tokens[i];
        if p.delimits_dollar_quote(tok) {
            return None;
        }
        if matches!(tok.kind, TokenKind::Keyword(Keyword::End)) {
            let kind = keyword_at(next_non_trivia_idx(tokens, i + 1), COMPOUND);
            depth -= 1;
            if depth == 0 {
                return kind
                    .filter(|&k| {
                        matches!(&tokens[k].kind, TokenKind::Keyword(kw) if closers.contains(kw))
                    })
                    .map(|k| CompoundWalk::Closed(k + 1));
            }
            if let Some(k) = kind {
                i = k;
            }
        } else if matches!(tok.kind, TokenKind::Keyword(Keyword::Begin)) {
            let transaction = keyword_at(
                next_non_trivia_idx(tokens, i + 1),
                &[Keyword::Transaction, Keyword::Work],
            );
            if transaction.is_none() {
                depth += 1;
            }
        } else if matches!(tok.kind, TokenKind::Keyword(Keyword::Case))
            || p.starts_statement(i, StatementContext::CompoundOpener)
        {
            depth += 1;
        }
        i = next_non_trivia_idx(tokens, i + 1)?;
    }
}

pub(crate) fn expr_span_end(expr: &AstExpr) -> u32 {
    match expr {
        AstExpr::Literal {
            literal: AstLiteral::Number { span },
            ..
        }
        | AstExpr::Literal {
            literal: AstLiteral::Money { span, .. },
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
        AstExpr::Literal {
            literal: literal @ AstLiteral::Adjacent { .. },
            ..
        } => literal.span().end,
        AstExpr::Placeholder { span, .. } => span.end,
        AstExpr::JinjaPlaceholder { span, .. } => span.end,
        AstExpr::Ident {
            column_ref: col, ..
        } => col.name.span.end,
        AstExpr::BinaryOp { right, .. } => expr_span_end(right),
        AstExpr::LogicalChain { span, .. } | AstExpr::OperatorChain { span, .. } => span.end,
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
        AstExpr::SessionVarRef { span, .. } => span.end,
        AstExpr::QualifiedStar { span, .. } => span.end,
        AstExpr::UnqualifiedStar { span, .. } => span.end,
        AstExpr::Prior { span, .. } => span.end,
        AstExpr::ConnectByRoot { span, .. } => span.end,
        AstExpr::IsNull { span, .. } => span.end,
        AstExpr::IsPredicate { span, .. } => span.end,
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
            literal: AstLiteral::Money { span, .. },
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
        AstExpr::Literal {
            literal: literal @ AstLiteral::Adjacent { .. },
            ..
        } => literal.span().start,
        AstExpr::Placeholder { span, .. } => span.start,
        AstExpr::JinjaPlaceholder { span, .. } => span.start,
        AstExpr::Ident {
            column_ref: col, ..
        } => match &col.qualifier {
            Some(q) => q.span.start,
            None => col.name.span.start,
        },
        AstExpr::BinaryOp { left, .. } => expr_span_start(left),
        AstExpr::LogicalChain { span, .. } | AstExpr::OperatorChain { span, .. } => span.start,
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
        AstExpr::SessionVarRef { span, .. } => span.start,
        AstExpr::QualifiedStar { span, .. } => span.start,
        AstExpr::UnqualifiedStar { span, .. } => span.start,
        AstExpr::Prior { span, .. } => span.start,
        AstExpr::ConnectByRoot { span, .. } => span.start,
        AstExpr::IsNull { span, .. } => span.start,
        AstExpr::IsPredicate { span, .. } => span.start,
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
    // Statements nest in one another's bodies: each is one level of the
    // parse's recursion, refused past its stack budget.
    let _depth = p.track_depth("scripting_statement")?;
    // CRITICAL: Enter scripting mode so :var references in expressions are recognized
    let prev_mode = p.enter_mode(crate::parser::core::ParserMode::Scripting);

    p.skip_trivia();
    let read_at = ReadState::of(p).at(p.idx, Read::Statement(context));
    if let Some(failure) = p.failed_reads.reached(read_at) {
        p.restore_mode(prev_mode);
        return Err(p.failed_reads.replay(failure, &mut p.idx));
    }
    let tok = p.peek_non_trivia().ok_or_else(|| {
        ParseError::new(
            p.current_span(),
            ParseErrorKind::InvalidStatement {
                message: "Expected statement in scripting block".to_string(),
            },
        )
    })?;

    let result = match &tok.kind {
        // SAVEPOINT, T-SQL SAVE TRAN, RELEASE [SAVEPOINT]
        TokenKind::Identifier { .. } if is_savepoint_stmt_at(p) => try_parse_savepoint_stmt(p),

        // Branching statements - use Result-based parsers
        TokenKind::Keyword(Keyword::If) => {
            // Dialect gate (justified): MSSQL IF has no THEN/END IF — structurally
            // incompatible with Snowflake/BigQuery IF...THEN...END IF grammar.
            if p.dialect.uses_block_scoped_control_flow() {
                try_parse_mssql_if(p)
            } else {
                try_parse_if_stmt_in_block(p, context, begin_start)
            }
        }

        // CASE statements - use Result-based parser
        TokenKind::Keyword(Keyword::Case) => try_parse_case_stmt_in_block(p, context, begin_start),

        // Loop statements - use Result-based parsers
        TokenKind::Keyword(Keyword::While) => {
            // Dialect gate (justified): MSSQL WHILE has no DO/END WHILE — structurally
            // incompatible with Snowflake WHILE...DO...END WHILE grammar.
            if p.dialect.uses_block_scoped_control_flow() {
                try_parse_mssql_while(p, None)
            } else {
                try_parse_while_stmt_in_block(p, begin_start, None)
            }
        }

        TokenKind::Keyword(Keyword::For) => try_parse_for_stmt_in_block(p, begin_start, None),

        TokenKind::Keyword(Keyword::Repeat) => try_parse_repeat_stmt_in_block(p, begin_start, None),

        TokenKind::Keyword(Keyword::Loop) => try_parse_loop_stmt_in_block(p, begin_start, None),

        // PostgreSQL PL/pgSQL `FOREACH var [SLICE n] IN ARRAY expr LOOP … END LOOP`.
        // FOREACH is a non-reserved identifier (it lexes as an unquoted identifier,
        // like LEAVE/ITERATE), so recognize it by lexeme at statement start and route
        // to its dedicated parser. A quoted `"foreach"` carries quote characters in
        // its lexeme and is therefore excluded.
        TokenKind::Identifier { .. } if tok.lexeme(p.source).eq_ignore_ascii_case("foreach") => {
            try_parse_foreach_stmt_in_block(p, begin_start)
        }

        // SQL statements with WITH clause handling
        TokenKind::Keyword(Keyword::With) => {
            // Use Result-based parser which validates WITH + UPDATE
            try_parse_set_or_select_stmt(p)
        }

        // SELECT statements
        TokenKind::Keyword(Keyword::Select) => {
            let first = try_parse_select_stmt_with_parser(p)?;
            let mut select_stmt =
                crate::parser::set_operations::try_parse_set_operations_after(p, first)?;

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
            StmtContext::Block | StmtContext::ExceptionHandler if p.while_body_depth > 0 => {
                try_parse_loop_control_stmt_in_block(p)
            }
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
            ) || p
                .any_words_end(p.idx + 1, &[&["TRAN"], &["DISTRIBUTED"]])
                .is_some()
            {
                try_parse_begin_transaction_stmt(p)
            } else if matches!(next_kind, Some(TokenKind::Keyword(Keyword::Try))) {
                try_parse_mssql_try_catch(p)
            } else if p
                .any_words_end(p.idx + 1, &[&["DIALOG"], &["CONVERSATION"]])
                .is_some()
            {
                // T-SQL statements led by BEGIN that are not a block; neither
                // is read, as at the top level, so neither takes in the
                // block's END.
                Err(ParseError::new(
                    tok.span,
                    ParseErrorKind::InvalidStatement {
                        message: "BEGIN statement that is not a block is not read".to_string(),
                    },
                ))
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
        TokenKind::Identifier { .. } if is_cursor_move_at(p) => try_parse_fetch_cursor_stmt(p),

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
        TokenKind::Keyword(Keyword::Execute) if crate::parser::task::execute_task_at(p) => {
            crate::parser::task::try_parse_execute_task_stmt(p)
        }
        TokenKind::Keyword(Keyword::Execute) => {
            if p.dialect.supports_exec_procedure_call() {
                p.try_parse_mssql_exec_stmt()
            } else if p.dialect.supports_prepared_statement_execution()
                && !p.dialect.supports_plpgsql_dynamic_execute()
            {
                // MySQL's `EXECUTE st [USING @a, …]` runs a prepared
                // statement in a body as at the top level; a PL/pgSQL
                // body's `EXECUTE <expr>` is dynamic SQL, read below.
                p.try_parse_pg_execute_stmt()
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
        TokenKind::Identifier { .. } if is_label_before_loop_at(p, p.idx) => {
            parse_label_and_dispatch(p, begin_start)
        }

        // Label detection for keyword-named labels (e.g., `outer: WHILE ...`)
        // Keywords like OUTER tokenize as Keyword(Outer), not Identifier.
        TokenKind::Keyword(..) if is_label_before_loop_at(p, p.idx) => {
            parse_label_and_dispatch(p, begin_start)
        }

        // PL/pgSQL `<<name>>` before a block or loop
        TokenKind::Operator(crate::lexer::Operator::LtLt)
            if label_prefix_at(p, p.idx).is_some() =>
        {
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
                    when_span: None,
                    condition: None,
                    semicolon_token,
                })
            } else {
                Ok(AstStmt::Continue {
                    node_id: p.id_gen.next(),
                    span,
                    continue_span: ctrl_tok.span,
                    continue_token: Some(ctrl_token_id),
                    label_token,
                    when_span: None,
                    condition: None,
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
            if p.dialect.supports_statement_labels() && is_mssql_label_at(p, p.idx) =>
        {
            try_parse_mssql_label(p)
        }
        // SET: MSSQL SET option (NOCOUNT, LOCK_TIMEOUT, etc.) or variable assignment (SET @var = expr)
        TokenKind::Keyword(Keyword::Set) => {
            // `SET VAR x = …` assigns in every dialect.
            if next_non_trivia_idx(p.tokens, p.idx + 1)
                .is_some_and(|i| set_variable_keyword_at(p, i))
            {
                p.try_parse_set_variable_stmt()
            } else if p.dialect.supports_mysql_set_grammar() {
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
                            kind: crate::lexer::IdentifierKind::Unquoted,
                            ..
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
        // Any other statement led by a word the lexer leaves an identifier is
        // read by the statement parser the top level uses. One it cannot read
        // is not parsed, as at the top level, where a missing terminator would
        // let the text run on into the statements after it; elsewhere it is
        // kept as written up to its `;`. An assignment is read as one.
        // In a dollar-quoted routine or `DO` body, PL/pgSQL's `PERFORM`
        // leads a query read as a SELECT.
        TokenKind::Identifier { .. } if !assignment_follows(p) => {
            let saved_idx = p.idx;
            let read = if p.dollar_body_block_depth > 0
                && tok.lexeme(p.source).eq_ignore_ascii_case("PERFORM")
            {
                try_parse_perform_stmt(p)
            } else {
                p.parse_statement()
            };
            match read {
                Ok(stmt) => Ok(stmt),
                Err(e) if p.dialect.uses_optional_statement_terminators() => Err(e),
                Err(_) => {
                    p.idx = saved_idx;
                    let first_tok = p
                        .advance()
                        .expect_invariant("identifier consumed after match")
                        .clone();
                    Ok(parse_shallow_assign_stmt(p, first_tok))
                }
            }
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

    // A statement that failed where the parse ran out of stack might read
    // from a shallower depth: only other failures are kept.
    if let Err(error) = &result {
        if !error.kind.is_resource_exhaustion() {
            let failure = p.failed_reads.fail(p.idx, error.clone());
            p.failed_reads.stood([read_at], failure);
        }
    }

    // Restore parser mode before returning
    p.restore_mode(prev_mode);
    result
}

/// PL/pgSQL `PERFORM query;`: the query read by the SELECT parser with
/// `PERFORM` standing for `SELECT`, the set operations after it, and the `;`
/// that ends it. A query not read up to that `;` fails the statement.
fn try_parse_perform_stmt(p: &mut Parser<'_>) -> ParseResult<AstStmt> {
    let first = AstStmt::Select(p.try_parse_perform_query_boxed()?);
    let query = Box::new(crate::parser::set_operations::try_parse_set_operations_after(p, first)?);
    if !p
        .peek_non_trivia()
        .is_some_and(|t| matches!(t.kind, TokenKind::Punctuation(Punctuation::Semi)))
    {
        return Err(ParseError::new(
            p.current_span(),
            ParseErrorKind::InvalidStatement {
                message: "Expected ';' after the PERFORM query".to_string(),
            },
        ));
    }
    let semicolon_token = p.current_token_id();
    p.advance();
    Ok(AstStmt::Perform(Box::new(AstPerform {
        node_id: p.id_gen.next(),
        span: query.span(),
        query,
        semicolon_token,
    })))
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
        // If next token is semicolon or block-ending keyword, no expression;
        // nor where it leads the next statement of a script without
        // terminators (`CASE` starts a value there too).
        let leads_next = p.dialect.uses_optional_statement_terminators()
            && !matches!(next_tok.kind, TokenKind::Keyword(Keyword::Case))
            && p.leads_statement(
                p.tokens
                    .partition_point(|t| t.span.start < next_tok.span.start),
            );
        if matches!(
            next_tok.kind,
            TokenKind::Punctuation(crate::lexer::Punctuation::Semi)
                | TokenKind::Keyword(Keyword::End)
                | TokenKind::Keyword(Keyword::Else)
                | TokenKind::Keyword(Keyword::Elsif)
                | TokenKind::Keyword(Keyword::When)
                | TokenKind::Keyword(Keyword::Until)
                | TokenKind::Keyword(Keyword::Exception)
        ) || leads_next
        {
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
    let mut message_args = Vec::new();
    let mut using_options = Vec::new();

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
        if let Some(span) = parse_raise_message(p, &mut message_args) {
            message_span = Some(span);
            end = span.end;
        }
        // Optional USING option = expr [, …].
        if let Some(tok) = p.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::Using)) {
                let using_start = tok.span.start;
                if let Some(span) = parse_raise_using(p, &mut using_options) {
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
        message_args,
        using_options,
    })
}

/// Whether the next token ends a PostgreSQL `RAISE` payload run at the top
/// paren level: the terminator, a block-ending keyword, the end of input,
/// or — when `using_ends` — `USING`.
fn ends_raise_payload(p: &mut Parser<'_>, using_ends: bool) -> bool {
    let Some(tok) = p.peek_non_trivia() else {
        return true;
    };
    matches!(
        tok.kind,
        TokenKind::Eof
            | TokenKind::Punctuation(Punctuation::Semi)
            | TokenKind::Keyword(
                Keyword::End
                    | Keyword::Else
                    | Keyword::Elsif
                    | Keyword::When
                    | Keyword::Until
                    | Keyword::Exception
            )
    ) || (using_ends && matches!(tok.kind, TokenKind::Keyword(Keyword::Using)))
}

/// The PostgreSQL `RAISE` message payload up to `USING` or the end of the
/// statement: a `'format'` string with its arguments read as expressions
/// into `args`, or a `condition_name` / `SQLSTATE 'x'` kept as written. A
/// payload whose arguments do not all parse, up to where it ends, is kept
/// as written ([`consume_raise_payload`]) with `args` left empty. Returns
/// the payload's span; `None` when nothing precedes `USING` or the end.
fn parse_raise_message(p: &mut Parser<'_>, args: &mut Vec<AstExpr>) -> Option<Span> {
    let from = p.idx;
    let Some(format) = p
        .peek_non_trivia()
        .filter(|t| matches!(t.kind, TokenKind::Literal(LiteralKind::String)))
    else {
        return consume_raise_payload(p, true);
    };
    let start = format.span.start;
    let mut end = format.span.end;
    p.advance();
    let mut read = true;
    while read
        && matches!(
            p.peek_non_trivia().map(|t| &t.kind),
            Some(TokenKind::Punctuation(Punctuation::Comma))
        )
    {
        p.advance();
        match try_parse_expr_scripting(p) {
            Ok(arg) => {
                end = expr_span_end(&arg);
                args.push(arg);
            }
            Err(_) => read = false,
        }
    }
    if !read || !ends_raise_payload(p, true) {
        args.clear();
        p.idx = from;
        return consume_raise_payload(p, true);
    }
    // A secret is masked as a parsed one's is.
    p.record_secret_literals(from, p.idx);
    Some(Span { start, end })
}

/// The PostgreSQL `RAISE … USING option = expr [, …]` list, `USING` next,
/// each option read into `options` (`=` or `:=` between name and value).
/// A list that does not all parse, up to where it ends, is kept as written
/// ([`consume_raise_payload`]) with `options` left empty. Returns the span
/// from `USING` on.
fn parse_raise_using(p: &mut Parser<'_>, options: &mut Vec<AstRaiseOption>) -> Option<Span> {
    use crate::lexer::Operator;
    let from = p.idx;
    let using_tok = p.advance()?;
    let start = using_tok.span.start;
    let mut end = using_tok.span.end;
    let mut read = false;
    while let Some(name) = p
        .peek_non_trivia()
        .filter(|t| matches!(t.kind, TokenKind::Identifier { .. } | TokenKind::Keyword(_)))
    {
        let name_span = name.span;
        p.advance();
        if !matches!(
            p.peek_non_trivia().map(|t| &t.kind),
            Some(TokenKind::Operator(Operator::Eq | Operator::ColonEq))
        ) {
            break;
        }
        p.advance();
        let Ok(value) = try_parse_expr_scripting(p) else {
            break;
        };
        end = expr_span_end(&value);
        options.push(AstRaiseOption { name_span, value });
        if !matches!(
            p.peek_non_trivia().map(|t| &t.kind),
            Some(TokenKind::Punctuation(Punctuation::Comma))
        ) {
            read = true;
            break;
        }
        p.advance();
    }
    if !read || !ends_raise_payload(p, false) {
        options.clear();
        p.idx = from;
        return consume_raise_payload(p, false);
    }
    // A secret is masked as a parsed one's is.
    p.record_secret_literals(from, p.idx);
    Some(Span { start, end })
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
    let from = p.idx;
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
    // The text is not read: its secrets are recorded as unparsed text's are.
    p.record_unparsed_secrets(from, p.idx);
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
            kind: crate::ast::AstIdentifierKind::of(&name_tok.kind),
            templated: None,
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
    p.record_assigned_secret(name.span, &expr);
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
/// Returns the statement body and whether the END keyword was encountered.
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
    let if_at = p.idx;
    let if_token_id = p.current_token_id();
    let if_tok = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["IF".to_string()])?;

    let header = read_compound_header(
        p,
        if_at,
        &[Keyword::Then],
        NoKeyword::FirstStatement,
        |p| {
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
                            message:
                                "IF statement requires closing parenthesis ')' after condition"
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
            Ok((lparen_token_id, cond_expr, rparen_token_id))
        },
    )?;
    let (lparen_token_id, cond_expr, rparen_token_id) =
        header.unwrap_or_else(|unparsed| (None, unparsed, None));
    let (then_token_id, then_span) = take_header_keyword(p, &[Keyword::Then]);
    let condition_span = cond_expr.span();
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
        then_token: then_token_id,
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
                let elseif_at = p.idx;
                let elseif_token_id = p.current_token_id();
                let elseif_tok = p
                    .advance()
                    .expect_invariant("ELSIF keyword consumed after match");

                let header = read_compound_header(
                    p,
                    elseif_at,
                    &[Keyword::Then],
                    NoKeyword::FirstStatement,
                    |p| {
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
                                    message:
                                        "ELSEIF statement requires THEN keyword after condition"
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
                        Ok((elseif_lparen_token_id, cond_expr, elseif_rparen_token_id))
                    },
                )?;
                let (elseif_lparen_token_id, cond_expr, elseif_rparen_token_id) =
                    header.unwrap_or_else(|unparsed| (None, unparsed, None));
                let (then_token_id2, then_span) = take_header_keyword(p, &[Keyword::Then]);
                let condition_span = cond_expr.span();

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
                    then_token: then_token_id2,
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
    let keyword_missing = branches.iter().any(|b| b.then_token.is_none());
    if !takes_end(p, keyword_missing, &[Keyword::If]) {
        return Ok(AstStmt::If(Box::new(AstIfStmt {
            node_id: p.id_gen.next(),
            span: Span {
                start: begin_start,
                end: end_of_read(p, begin_start),
            },
            branches,
            else_span,
            else_token: else_token_id,
            else_body,
            end_span: None,
            end_token: None,
            end_if_token: None,
            semicolon_token: None,
        })));
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
    p.skip_trivia();
    let case_at = p.idx;
    let case_token_id = p.current_token_id();
    let case_tok = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["CASE".to_string()])?;
    let mut operand: Option<Box<AstExpr>> = None;
    let mut operand_span: Option<Span> = None;
    p.skip_trivia();
    let mut branches: Vec<CaseBranch> = Vec::new();

    // Check for optional operand (simple CASE vs searched CASE)
    if let Some(next) = p.peek_non_trivia() {
        if !matches!(next.kind, TokenKind::Keyword(Keyword::When)) {
            // This is a simple CASE with an operand: CASE <expr> WHEN ...
            let expr = read_compound_header(
                p,
                case_at,
                &[Keyword::When],
                NoKeyword::FirstStatement,
                |p| {
                    let expr = try_parse_expr_scripting(p).map_err(|_| {
                        ParseError::invalid_expression(
                            p.current_span(),
                            "CASE statement requires operand expression before first WHEN"
                                .to_string(),
                        )
                    })?;
                    p.skip_trivia();
                    match p.peek_non_trivia() {
                        Some(tok) if matches!(tok.kind, TokenKind::Keyword(Keyword::When)) => {
                            Ok(expr)
                        }
                        Some(tok) => Err(ParseError::new(
                            tok.span,
                            ParseErrorKind::InvalidStatement {
                                message: format!(
                                    "CASE statement requires WHEN after its operand, found {}",
                                    Parser::token_description(tok, p.source)
                                ),
                            },
                        )),
                        None => Err(ParseError::new(
                            p.current_span(),
                            ParseErrorKind::InvalidStatement {
                                message: "CASE statement requires at least one WHEN clause"
                                    .to_string(),
                            },
                        )),
                    }
                },
            )?
            .unwrap_or_else(|unparsed| unparsed);
            operand_span = Some(Span {
                start: expr_span_start(&expr),
                end: expr_span_end(&expr),
            });
            operand = Some(Box::new(expr));
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
                let when_at = p.idx;
                let when_token_id = p.current_token_id();
                let when_tok = p
                    .advance()
                    .expect_invariant("WHEN keyword consumed after match in CASE");
                p.skip_trivia();

                // A searched CASE's WHEN takes one condition; a simple CASE's
                // WHEN a comma list of values.
                let simple = operand.is_some();
                let header = read_compound_header(
                    p,
                    when_at,
                    &[Keyword::Then],
                    NoKeyword::FirstStatement,
                    |p| {
                        let read_value = |p: &mut Parser<'_>| {
                            try_parse_expr_scripting(p).map_err(|_| {
                                ParseError::invalid_expression(
                                    p.current_span(),
                                    "WHEN clause requires condition expression before THEN"
                                        .to_string(),
                                )
                            })
                        };
                        let cond_expr = read_value(p)?;
                        let mut more_values = Vec::new();
                        while simple
                            && p.peek_non_trivia().is_some_and(|t| {
                                matches!(t.kind, TokenKind::Punctuation(Punctuation::Comma))
                            })
                        {
                            p.skip_trivia();
                            p.advance();
                            more_values.push(read_value(p)?);
                        }

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
                        Ok((cond_expr, more_values))
                    },
                )?;
                let (cond_expr, more_values) =
                    header.unwrap_or_else(|unparsed| (unparsed, Vec::new()));
                let condition_span = Span {
                    start: expr_span_start(&cond_expr),
                    end: expr_span_end(more_values.last().unwrap_or(&cond_expr)),
                };
                let (then_token_id, then_span) = take_header_keyword(p, &[Keyword::Then]);

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
                    more_values,
                    condition_span,
                    then_span,
                    then_token: then_token_id,
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
    let keyword_missing = branches.iter().any(|b| b.then_token.is_none());
    if !takes_end(p, keyword_missing, &[Keyword::Case]) {
        return Ok(AstStmt::CaseStmt(Box::new(AstCaseStmt {
            node_id: p.id_gen.next(),
            span: Span {
                start: case_tok.span.start,
                end: end_of_read(p, case_tok.span.start),
            },
            case_span: case_tok.span,
            case_token: Some(case_token_id),
            operand,
            operand_span,
            branches,
            else_span,
            else_token: else_token_id,
            else_body,
            end_span: None,
            end_token: None,
            end_case_token: None,
            semicolon_token: None,
        })));
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
        operand,
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
    let while_at = p.idx;
    let while_token_id = p.current_token_id();
    let while_tok = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["WHILE".to_string()])?;
    let while_span = while_tok.span;

    let openers = [Keyword::Do, Keyword::Loop];
    let header = read_compound_header(p, while_at, &openers, NoKeyword::FirstStatement, |p| {
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
        Ok((lparen_token_id, cond_expr, rparen_token_id))
    })?;
    let (lparen_token_id, cond_expr, rparen_token_id) =
        header.unwrap_or_else(|unparsed| (None, unparsed, None));
    let condition_span = cond_expr.span();
    let (body_keyword_token_id, body_keyword_span) = take_header_keyword(p, &openers);

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
    p.skip_trivia();
    if !takes_end(
        p,
        body_keyword_token_id.is_none(),
        &[Keyword::While, Keyword::Loop],
    ) {
        let start = label_span.map_or(begin_start, |ls| ls.start);
        return Ok(AstStmt::While(Box::new(AstWhileStmt {
            node_id: p.id_gen.next(),
            span: Span {
                start,
                end: end_of_read(p, start),
            },
            label_span,
            end_label_span: None,
            while_span,
            while_token: Some(while_token_id),
            lparen_token: lparen_token_id,
            condition: Box::new(cond_expr),
            condition_span,
            rparen_token: rparen_token_id,
            body_keyword_span,
            body_keyword_token: body_keyword_token_id,
            body,
            end_span: None,
            end_token: None,
            end_while_token: None,
            semicolon_token: None,
        })));
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
        body_keyword_span,
        body_keyword_token: body_keyword_token_id,
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
    p.skip_trivia();
    let in_at = p.idx;
    let in_token_id = p.current_token_id();
    let _ = p.advance();
    let header_from = p.idx;

    // The range, cursor or query, up to DO or LOOP at the loop's own level;
    // where neither is written, up to the body's first statement. A header
    // that does not read, or has no DO or LOOP after it, is one piece not
    // parsed, and the loop's body is read.
    let openers = [Keyword::Do, Keyword::Loop];
    let missing_keyword = |at: Span| {
        ParseError::new(
            at,
            ParseErrorKind::InvalidStatement {
                message: "FOR loop requires DO or LOOP keyword".to_string(),
            },
        )
    };
    let (header_to, keyword_written) = match compound_header_end(
        p,
        in_at,
        &openers,
        NoKeyword::ClosedStatement(&[Keyword::For, Keyword::Loop]),
    ) {
        Some(HeaderEnd::Keyword(i)) => (i, true),
        Some(HeaderEnd::Statement(i)) => (i, false),
        // Control flow closing with no `END FOR`, or a loop not closed:
        // the first DO or LOOP written after `IN`; where there is none,
        // the rest of the input is the loop's.
        None => match p.tokens[header_from..]
            .iter()
            .position(|t| matches!(t.kind, TokenKind::Keyword(Keyword::Do | Keyword::Loop)))
        {
            Some(k) => (header_from + k, true),
            None => {
                p.idx = p.tokens.len();
                return Err(missing_keyword(p.current_span()));
            }
        },
    };
    let mut header_tokens = p.tokens[header_from..header_to]
        .iter()
        .filter(|t| !is_skippable(t));
    // An empty header (`FOR i IN DO`) spans the end of `IN`.
    let range_or_cursor_span = Span {
        start: header_tokens
            .clone()
            .next()
            .map_or(in_span.end, |t| t.span.start),
        end: header_tokens
            .next_back()
            .map_or(in_span.end, |t| t.span.end),
    };
    p.idx = header_to;
    let iterates = if keyword_written {
        match read_for_loop_header(p, header_from, header_to) {
            Ok(iterates) => iterates,
            Err(err) if err.kind.is_resource_exhaustion() => return Err(err),
            Err(err) => {
                AstForIterable::Expr(Box::new(unparsed_header(p, header_from, header_to, &err)))
            }
        }
    } else {
        let err = missing_keyword(p.current_span());
        AstForIterable::Expr(Box::new(unparsed_header(p, header_from, header_to, &err)))
    };

    let (body_keyword_token_id, body_keyword_span) = take_header_keyword(p, &openers);

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
        iterates,
        body_keyword_span,
        body_keyword_token: body_keyword_token_id,
        body,
        end_span: Some(end_span),
        end_token: Some(end_token_id),
        end_for_token: end_for_token_id,
        semicolon_token,
    })))
}

/// Reads a FOR loop's header, the tokens `from..to` between `IN` (or `AS`)
/// and `DO` / `LOOP`, by the existing readers: a statement, read as a body
/// statement is, where a query or `EXECUTE` starts it; else `[REVERSE] low
/// {TO | ..} high [BY step]`, each bound an expression; else one expression
/// (a cursor or a result set), a query in parentheses being the loop's
/// query. A part that does not read, or leaves a token unread, fails the
/// header.
fn read_for_loop_header(p: &mut Parser<'_>, from: usize, to: usize) -> ParseResult<AstForIterable> {
    let tokens = p.tokens;
    let header = &tokens[from..to];
    let fail = |span: Span, message: &str| {
        ParseError::new(
            span,
            ParseErrorKind::InvalidStatement {
                message: message.to_string(),
            },
        )
    };
    let Some(first) = header.first() else {
        return Err(fail(
            tokens[to].span,
            "FOR loop requires a range, a cursor or a query after IN",
        ));
    };
    let source = p.source;
    if p.starts_statement(from, StatementContext::LoopQuery) {
        let begin = first.span.start;
        return read_tokens_whole(p, from, to, |r| {
            try_parse_scripting_stmt(r, StmtContext::Loop, begin)
        })
        .map(|query| AstForIterable::Query(Box::new(query)));
    }
    let bound = |r: &mut Parser<'_>| try_parse_expr_scripting(r).map(Box::new);
    // The range's separator, outside parentheses: `TO`, or `..`.
    let mut depth = 0usize;
    let mut separator = None;
    for (i, t) in header.iter().enumerate() {
        match &t.kind {
            TokenKind::Punctuation(punctuation) => match punctuation {
                Punctuation::LParen | Punctuation::LBracket => depth += 1,
                Punctuation::RParen | Punctuation::RBracket => depth = depth.saturating_sub(1),
                Punctuation::Dot => {
                    let doubled = header.get(i + 1).is_some_and(|n| {
                        n.span.start == t.span.end
                            && matches!(n.kind, TokenKind::Punctuation(Punctuation::Dot))
                    });
                    if depth == 0 && doubled {
                        separator = Some((i, i + 2));
                        break;
                    }
                }
                Punctuation::LCurly
                | Punctuation::RCurly
                | Punctuation::Comma
                | Punctuation::Semi
                | Punctuation::Colon => {}
            },
            TokenKind::Keyword(k) => {
                if depth == 0 && *k == Keyword::To {
                    separator = Some((i, i + 1));
                    break;
                }
            }
            TokenKind::Identifier { .. }
            | TokenKind::Literal(_)
            | TokenKind::Operator(_)
            | TokenKind::LineComment
            | TokenKind::BlockComment
            | TokenKind::JinjaComment
            | TokenKind::JinjaExprOpen
            | TokenKind::JinjaExprClose
            | TokenKind::JinjaStmtOpen
            | TokenKind::JinjaStmtClose
            | TokenKind::JinjaPipe
            | TokenKind::JinjaTilde
            | TokenKind::JinjaDoubleStar
            | TokenKind::JinjaDoubleSlash
            | TokenKind::JinjaDoubleEq
            | TokenKind::JinjaAnd
            | TokenKind::JinjaOr
            | TokenKind::JinjaNot
            | TokenKind::JinjaIn
            | TokenKind::JinjaIs
            | TokenKind::JinjaTrue
            | TokenKind::JinjaFalse
            | TokenKind::JinjaNull
            | TokenKind::JinjaIf
            | TokenKind::JinjaElif
            | TokenKind::JinjaElse
            | TokenKind::JinjaEndIf
            | TokenKind::JinjaFor
            | TokenKind::JinjaEndFor
            | TokenKind::JinjaSet
            | TokenKind::JinjaEndSet
            | TokenKind::JinjaDocs
            | TokenKind::JinjaEndDocs
            | TokenKind::JinjaFilter
            | TokenKind::JinjaEndFilter
            | TokenKind::JinjaCall
            | TokenKind::JinjaEndCall
            | TokenKind::Placeholder
            | TokenKind::Eof
            | TokenKind::Unknown => {}
        }
    }
    let Some((low_end, high_from)) = separator else {
        return read_tokens_whole(p, from, to, bound).map(|expr| {
            if let AstExpr::ScalarSubquery { subquery, .. } = *expr {
                AstForIterable::Query(subquery)
            } else {
                AstForIterable::Expr(expr)
            }
        });
    };
    let reverse = header.len() > 1 && first.lexeme(source).eq_ignore_ascii_case("REVERSE");
    let low_from = usize::from(reverse);
    let step_at = header[high_from..]
        .iter()
        .position(|t| matches!(t.kind, TokenKind::Keyword(Keyword::By)))
        .map(|k| high_from + k);
    let low = read_tokens_whole(p, from + low_from, from + low_end, bound)?;
    let high = read_tokens_whole(
        p,
        from + high_from,
        from + step_at.unwrap_or(header.len()),
        bound,
    )?;
    let step = match step_at {
        Some(by) => Some(read_tokens_whole(p, from + by + 1, to, bound)?),
        None => None,
    };
    Ok(AstForIterable::Range {
        reverse,
        low,
        high,
        step,
    })
}

/// Runs `read` on a parser of its own over exactly `p.tokens[from..to]`
/// (then the end), so `p` consumes nothing; fails where the part is empty,
/// where `read` fails or recovers from an error, or where it leaves a token
/// of the part unread. What it reads is `p`'s as if read in place: its node
/// ids, syntax nodes and token ids are the script's, and the secrets it
/// records are `p`'s.
fn read_tokens_whole<T>(
    p: &mut Parser<'_>,
    from: usize,
    to: usize,
    read: impl FnOnce(&mut Parser<'_>) -> ParseResult<T>,
) -> ParseResult<T> {
    let at = p.current_span();
    let part = &p.tokens[from..to];
    let Some(last) = part.last() else {
        return Err(ParseError::new(
            at,
            ParseErrorKind::InvalidStatement {
                message: "FOR loop header part is empty".to_string(),
            },
        ));
    };
    let end = Span {
        start: last.span.end,
        end: last.span.end,
    };
    let mut tokens = part.to_vec();
    tokens.push(Token {
        kind: TokenKind::Eof,
        span: end,
        leading_trivia: Vec::new(),
        trailing_trivia: Vec::new(),
    });
    let mut reader = Parser::with_dialect(p.source, &tokens, p.dialect);
    reader.mode = p.mode;
    reader.dollar_body_block_depth = p.dollar_body_block_depth;
    reader.placeholder_spans = p.placeholder_spans.clone();
    reader.id_gen = std::rc::Rc::clone(&p.id_gen);
    reader.token_id_base = p.token_id_base + from as u32;
    reader.syntax_arena = std::mem::take(&mut p.syntax_arena);
    let read = read(&mut reader);
    p.syntax_arena = std::mem::take(&mut reader.syntax_arena);
    let value = read?;
    if let Some(unread) = reader.peek() {
        return Err(ParseError::unexpected_token(
            unread.span,
            vec!["DO or LOOP".to_string()],
            Parser::token_description(unread, p.source),
        ));
    }
    if let Some(err) = reader.recovery_errors.into_iter().next() {
        return Err(err);
    }
    p.redaction_spans.extend(reader.redaction_spans);
    p.cut_statements.extend(reader.cut_statements);
    p.setting_values.extend(reader.setting_values);
    p.bulk_options.extend(reader.bulk_options);
    p.held_names.extend(reader.held_names);
    Ok(value)
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
    let missing_until = |at: Span| {
        ParseError::new(
            at,
            ParseErrorKind::InvalidStatement {
                message: "REPEAT loop requires UNTIL keyword".to_string(),
            },
        )
    };
    if !reached_until {
        return Err(missing_until(p.current_span()));
    }

    // Validate UNTIL keyword
    let until_tok = p
        .peek_non_trivia()
        .ok_or_else(|| missing_until(p.current_span()))?;
    p.skip_trivia();
    let until_at = p.idx;
    let (until_token_id, until_span, until_condition) =
        if matches!(until_tok.kind, TokenKind::Keyword(Keyword::Until)) {
            let until_token_id = p.current_token_id();
            let until_kw = p
                .advance()
                .expect_invariant("UNTIL keyword consumed after match in REPEAT");
            // The condition (Snowflake writes it in parentheses), up to END REPEAT.
            let until_condition = read_compound_header(
                p,
                until_at,
                &[Keyword::End],
                NoKeyword::ClosedStatement(&[Keyword::Repeat]),
                |p| {
                    let condition = try_parse_expr_scripting(p).map_err(|_| {
                        ParseError::invalid_expression(
                            p.current_span(),
                            "REPEAT loop requires condition expression after UNTIL".to_string(),
                        )
                    })?;
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
                    Ok(condition)
                },
            )?
            .unwrap_or_else(|unparsed| unparsed);
            (Some(until_token_id), until_kw.span, until_condition)
        } else {
            // No UNTIL written before the loop's END: its condition is one
            // empty piece not parsed there, and the loop is read.
            let at = Span {
                start: until_tok.span.start,
                end: until_tok.span.start,
            };
            let missing = unparsed_header(p, until_at, until_at, &missing_until(until_tok.span));
            (None, at, missing)
        };
    let condition_span = until_condition.span();

    let end_tok = p
        .peek_non_trivia()
        .expect_invariant("END keyword follows the UNTIL condition");
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
        until_token: until_token_id,
        until_condition: Box::new(until_condition),
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

    // Optional label identifier; `WHEN` starts the condition, and a word
    // that leads a statement starts the next one.
    let mut label_token = None;
    if let Some(label_tok) = p.peek_non_trivia() {
        if p.can_be_identifier_token(label_tok)
            && !p.is_word(Some(label_tok), "WHEN")
            && !p.should_stop_scan_at_statement_start(label_tok)
        {
            label_token = Some(p.current_token_id());
            let lbl = p
                .advance()
                .expect_invariant("label identifier consumed in loop control statement");
            end = lbl.span.end;
        }
    }

    // PL/pgSQL `WHEN condition`.
    let mut when_span = None;
    let mut condition = None;
    if p.is_word(p.peek(), "WHEN") {
        let when = p.advance().expect_invariant("WHEN after peek");
        let cond = try_parse_expr_scripting(p)?;
        end = cond.span().end;
        when_span = Some(when.span);
        condition = Some(Box::new(cond));
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
            label_token,
            when_span,
            condition,
            semicolon_token,
        },
        TokenKind::Keyword(Keyword::Continue) => AstStmt::Continue {
            node_id: p.id_gen.next(),
            span,
            continue_span: ctrl_tok.span,
            continue_token: Some(ctrl_token_id),
            label_token,
            when_span,
            condition,
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

/// Where `stmt` is text no statement parser read, kept as written up to its
/// `;` as an assignment that has no assignment operator.
fn text_kept_as_written(stmt: &AstStmt) -> Option<Span> {
    if let AstStmt::Assign {
        assign_op_span: None,
        span,
        ..
    } = stmt
    {
        Some(*span)
    } else {
        None
    }
}

pub(crate) fn parse_shallow_assign_stmt(p: &mut Parser<'_>, first_tok: Token) -> AstStmt {
    let start_idx = p.idx.saturating_sub(1);
    let mut name_span = first_tok.span;
    let mut subscript_span = None;
    // A name of parts assigned to (`NEW.col := …`) is the whole name; the
    // subscripts after it (`arr[1] := …`) are kept beside it.
    if let Some((name, name_end, operator)) = assigned_name_end(p, start_idx) {
        name_span = name;
        if operator > name_end {
            subscript_span = Some(Span {
                start: p.tokens[name_end].span.start,
                end: p.tokens[operator - 1].span.end,
            });
        }
        p.idx = p.idx.max(operator);
    }
    let start = first_tok.span.start;
    let mut rhs_start: Option<u32> = None;
    let mut rhs_end: Option<u32> = None;
    let mut end = name_span.end;
    let mut found_colon_eq = false;
    let mut assign_op_span: Option<Span> = None;
    // `CASE` expressions open on the right side: each `END` closes one, and
    // only an `END` past them all ends the block.
    let mut open_cases = 0usize;

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
            TokenKind::Keyword(Keyword::End) if open_cases == 0 => break,
            TokenKind::Eof => break,
            _ => {
                if matches!(next.kind, TokenKind::Keyword(Keyword::Case)) {
                    open_cases += 1;
                } else if matches!(next.kind, TokenKind::Keyword(Keyword::End)) {
                    open_cases -= 1;
                }
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

    // A secret is masked like a parsed one where the right side is read,
    // and as in text no reader parsed where the statement is kept as written,
    // its unread value's literals with it.
    if let Some(value) = &expr {
        p.record_secret_literals(start_idx, p.idx);
        p.record_assigned_secret(name_span, value);
    } else {
        p.record_unparsed_secrets(start_idx, p.idx);
        if found_colon_eq {
            p.record_assigned_value(name_span, expr_span);
        }
    }
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
        subscript_span,
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
    let (start, declare_span, declare_token_id, name_tok) =
        if matches!(start_tok.kind, TokenKind::Keyword(Keyword::Declare)) {
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
                 // Databricks' `DECLARE [OR REPLACE] [VARIABLE] name …`: the words
                 // after DECLARE are the statement's keywords, written with it.
            let (declare_span, declare_token_id) = match declare_variable_words_end(p) {
                Some(last) => {
                    p.idx = last + 1;
                    let span = Span {
                        start: kw.span.start,
                        end: p.tokens[last].span.end,
                    };
                    (span, None)
                }
                None => (kw.span, declare_token_id),
            };
            let name_tok = p.advance().ok_or_else(|| {
                ParseError::new(
                    p.current_span(),
                    ParseErrorKind::InvalidStatement {
                        message: "Expected identifier after DECLARE".to_string(),
                    },
                )
            })?;
            (
                kw.span.start,
                Some(declare_span),
                declare_token_id,
                name_tok,
            )
        } else if p.can_be_identifier_token(start_tok) {
            let name_tok = p.advance().ok_or_else(|| {
                ParseError::new(
                    p.current_span(),
                    ParseErrorKind::InvalidStatement {
                        message: "Expected identifier in DECLARE".to_string(),
                    },
                )
            })?;
            (start_tok.span.start, None, None, name_tok)
        } else {
            return Err(ParseError::new(
                start_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: format!(
                        "Expected DECLARE keyword or identifier, found {}",
                        Parser::token_description(start_tok, p.source)
                    ),
                },
            ));
        };
    // DECLARE EXIT|CONTINUE HANDLER FOR condition_value [,...] statement:
    // EXIT and CONTINUE lead a handler, whether or not the dialect reserves
    // them as names.
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

    if !p.can_be_identifier_token(name_tok) {
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
    let name = AstIdentifier {
        node_id: p.id_gen.next(),
        span: name_tok.span,
        kind: crate::ast::AstIdentifierKind::of(&name_tok.kind),
        templated: None,
    };

    // Check for Databricks DECLARE condition_name CONDITION FOR SQLSTATE ...
    if let Some(cond_tok) = p.peek_non_trivia() {
        if cond_tok.lexeme(p.source).eq_ignore_ascii_case("CONDITION") {
            return try_parse_declare_condition_body(p, start, declare_span, name.span);
        }
    }

    // Check if this is a cursor declaration: DECLARE name [INSENSITIVE]
    // [SCROLL] CURSOR [option ...] FOR ..., the options ISO's and T-SQL's.
    let words_past = |mut i: usize, words: &[&str]| {
        while words.iter().any(|w| p.word_at(i, w)) {
            i += 1;
        }
        i
    };
    let cursor_at = words_past(p.idx, &["INSENSITIVE", "SCROLL"]);
    let for_at = words_past(
        cursor_at + 1,
        &[
            "LOCAL",
            "GLOBAL",
            "FORWARD_ONLY",
            "SCROLL",
            "STATIC",
            "KEYSET",
            "DYNAMIC",
            "FAST_FORWARD",
            "READ_ONLY",
            "SCROLL_LOCKS",
            "OPTIMISTIC",
            "TYPE_WARNING",
        ],
    );
    let declares_cursor = p
        .tokens
        .get(cursor_at)
        .is_some_and(|t| matches!(t.kind, TokenKind::Keyword(Keyword::Cursor)))
        && p.tokens
            .get(for_at)
            .is_some_and(|t| matches!(t.kind, TokenKind::Keyword(Keyword::For)));
    if declares_cursor {
        p.idx = cursor_at;
    }
    if let Some(cursor_tok) = p.peek_non_trivia() {
        if matches!(cursor_tok.kind, TokenKind::Keyword(Keyword::Cursor)) {
            let cursor_token_id = p.current_token_id();
            let cursor_idx = p.idx;
            let _ = p.advance(); // consume CURSOR
            if declares_cursor {
                p.idx = for_at;
            }

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
            // A cursor variable (T-SQL `@c CURSOR`): `CURSOR` is its type.
            p.idx = cursor_idx;
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
            let first_column_idx = p.idx;

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
            // The columns read as a `CREATE TABLE`'s are, for the values
            // they hold.
            let after_body = p.idx;
            let (columns, _, _) =
                p.parse_create_table_columns_and_constraints(first_column_idx, after_body - 1);
            p.idx = after_body;
            let column_defaults = columns
                .iter()
                .flat_map(|column| [column.default_expr_span, column.virtual_expr_span])
                .flatten()
                .collect();
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
                column_defaults,
            });
        }
    }

    // The variables: one, a list of names sharing one type and initialiser
    // (`a, b INT DEFAULT 0`), or T-SQL's list `@x INT = 1, @y INT, @c
    // CURSOR`, each read up to the `,` before the next `@variable`.
    let bound = declaration_bound(p);
    let mut names = vec![name];
    names.extend(read_declared_name_list(p, bound));
    let mut variables = read_declared_variables(p, names, bound)?;
    while next_declared_variable_at(p, p.idx, bound) {
        p.advance(); // ','
        let name_tok = p
            .advance()
            .expect_invariant("a variable follows the comma, as checked");
        let name = AstIdentifier {
            node_id: p.id_gen.next(),
            span: name_tok.span,
            kind: crate::ast::AstIdentifierKind::of(&name_tok.kind),
            templated: None,
        };
        variables.extend(read_declared_variables(p, vec![name], bound)?);
    }
    let end = variables.last().map_or(start, |variable| variable.span.end);

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
        variables,
    })
}

/// The index of the last of the words `OR REPLACE` and `VARIABLE` written
/// after `DECLARE` at the current token, in `DECLARE [OR REPLACE] [VARIABLE
/// | VAR] name …`; `None` where neither is. `VARIABLE` (or `VAR`) is that
/// keyword only where the dialect writes it there
/// ([`crate::dialect::Dialect::declare_has_variable_keyword`]) and a name
/// follows it (not `DEFAULT`, which starts the initialiser of a variable
/// named `variable`); elsewhere it is the variable's name.
fn declare_variable_words_end(p: &Parser<'_>) -> Option<usize> {
    let at = |i: usize| next_non_trivia_idx(p.tokens, i);
    let first = at(p.idx)?;
    let or_replace = (matches!(p.tokens[first].kind, TokenKind::Keyword(Keyword::Or)))
        .then(|| at(first + 1).filter(|&i| p.word_at(i, "REPLACE")))
        .flatten();
    let after_head = or_replace.map_or(Some(first), |last| at(last + 1));
    let variable = after_head
        .filter(|_| p.dialect.declare_has_variable_keyword())
        .filter(|&i| p.word_at(i, "VARIABLE") || p.word_at(i, "VAR"))
        .filter(|&i| {
            at(i + 1).is_some_and(|name| {
                let t = &p.tokens[name];
                p.can_be_identifier_token(t) && !t.lexeme(p.source).eq_ignore_ascii_case("DEFAULT")
            })
        });
    variable.or(or_replace)
}

/// Whether token `at`, before `bound`, is the `,` of a declaration list
/// followed by the next variable, a T-SQL `@variable`.
fn next_declared_variable_at(p: &Parser<'_>, at: usize, bound: usize) -> bool {
    at < bound
        && p.tokens.get(at).is_some_and(|t| {
            matches!(
                t.kind,
                TokenKind::Punctuation(crate::lexer::Punctuation::Comma)
            )
        })
        && p.tokens.get(at + 1).is_some_and(|t| {
            matches!(
                t.kind,
                TokenKind::Identifier {
                    kind: crate::lexer::IdentifierKind::AtVariable,
                    ..
                }
            )
        })
}

/// The names after the first of a list declared together (`a, b, c INT`):
/// each `,` before `bound` followed by a name, consumed with its name.
fn read_declared_name_list(p: &mut Parser<'_>, bound: usize) -> Vec<AstIdentifier> {
    let mut names = Vec::new();
    while p.idx < bound
        && p.peek().is_some_and(|t| {
            matches!(
                t.kind,
                TokenKind::Punctuation(crate::lexer::Punctuation::Comma)
            )
        })
        && p.peek_ahead(1)
            .is_some_and(|t| p.can_be_identifier_token(t))
    {
        p.advance(); // ','
        let Some(name_tok) = p.advance() else {
            break;
        };
        names.push(AstIdentifier {
            node_id: p.id_gen.next(),
            span: name_tok.span,
            kind: crate::ast::AstIdentifierKind::of(&name_tok.kind),
            templated: None,
        });
    }
    names
}

/// The variables `names` (one, or a list declared together) whose type
/// follows at the current token: `[AS] type [DEFAULT expr | := expr | =
/// expr]`, read once up to the `,` before the next variable or `bound`;
/// every name has that type and initialiser. An initialiser that does not
/// parse fails the declaration.
fn read_declared_variables(
    p: &mut Parser<'_>,
    names: Vec<AstIdentifier>,
    bound: usize,
) -> ParseResult<Vec<crate::ast::AstDeclaredVariable>> {
    // Where the variable ends: the next variable's `,`, outside parentheses.
    let mut item_end = p.idx;
    let mut depth = 0usize;
    while item_end < bound && !(depth == 0 && next_declared_variable_at(p, item_end, bound)) {
        let kind = &p.tokens[item_end].kind;
        if matches!(
            kind,
            TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
        ) {
            depth += 1;
        } else if matches!(
            kind,
            TokenKind::Punctuation(crate::lexer::Punctuation::RParen)
        ) {
            depth = depth.saturating_sub(1);
        }
        item_end += 1;
    }
    // The initialiser starts at the first `DEFAULT`, `:=` or `=` outside
    // parentheses (`=` is T-SQL's, PL/pgSQL's and Databricks'): no type
    // holds one there.
    let mut depth = 0usize;
    let init_at = (p.idx..item_end).find(|&i| {
        let t = &p.tokens[i];
        if matches!(
            t.kind,
            TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
        ) {
            depth += 1;
        } else if matches!(
            t.kind,
            TokenKind::Punctuation(crate::lexer::Punctuation::RParen)
        ) {
            depth = depth.saturating_sub(1);
        }
        depth == 0
            && (t.lexeme(p.source).eq_ignore_ascii_case("DEFAULT")
                || matches!(
                    t.kind,
                    TokenKind::Operator(
                        crate::lexer::Operator::ColonEq | crate::lexer::Operator::Eq
                    )
                ))
    });

    // The type: every token before the initialiser or the variable's end.
    let type_from = p.idx;
    let type_to = init_at.unwrap_or(item_end);
    let type_span = (type_to > type_from).then(|| Span {
        start: p.tokens[type_from].span.start,
        end: p.tokens[type_to - 1].span.end,
    });
    p.idx = type_to;

    let mut default_op_span = None;
    let mut default_op_token = None;
    let mut default_expr = None;
    let mut default_expr_span = None;
    if init_at.is_some() {
        let op_span = p.tokens[p.idx].span;
        default_op_span = Some(op_span);
        default_op_token = Some(p.current_token_id());
        p.advance(); // DEFAULT, := or =
        let expr = try_parse_expr_scripting(p)?;
        // The value is read once, for the first name naming a secret.
        if let Some(name) = names.iter().find(|name| p.names_a_secret(name.span)) {
            p.record_assigned_secret(name.span, &expr);
        }
        default_expr_span = Some(Span {
            start: op_span.start,
            end: expr.span().end,
        });
        default_expr = Some(Box::new(expr));
    }

    let names_end = names.last().map_or(p.current_span().start, |n| n.span.end);
    let end = default_expr
        .as_ref()
        .map(|expr| expr.span().end)
        .or(type_span.map(|ts| ts.end))
        .unwrap_or(names_end);
    // The initialiser is parsed once and held by the first name; every
    // name has its spans.
    Ok(names
        .into_iter()
        .map(|name| crate::ast::AstDeclaredVariable {
            span: Span {
                start: name.span.start,
                end,
            },
            name,
            type_span,
            default_op_span,
            default_op_token,
            default_expr: default_expr.take(),
            default_expr_span,
        })
        .collect())
}

/// Index of the token that ends the declaration at the current token: a
/// `;` or the end, or outside parentheses where a statement starts for a
/// declaration ([`StatementContext::Declaration`]).
fn declaration_bound(p: &Parser<'_>) -> usize {
    let mut depth = 0usize;
    let mut i = p.idx;
    while let Some(tok) = p.tokens.get(i) {
        let outside = depth == 0 && i > p.idx;
        if matches!(
            tok.kind,
            TokenKind::Punctuation(crate::lexer::Punctuation::Semi) | TokenKind::Eof
        ) || (outside && p.starts_statement(i, StatementContext::Declaration))
        {
            break;
        }
        if matches!(
            tok.kind,
            TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
        ) {
            depth += 1;
        } else if matches!(
            tok.kind,
            TokenKind::Punctuation(crate::lexer::Punctuation::RParen)
        ) {
            depth = depth.saturating_sub(1);
        }
        i += 1;
    }
    i
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

/// The directions a cursor's `FETCH` or `MOVE` reads.
const CURSOR_DIRECTIONS: &[&str] = &[
    "NEXT", "PRIOR", "FIRST", "LAST", "ABSOLUTE", "RELATIVE", "ALL", "FORWARD", "BACKWARD",
];

/// Of [`CURSOR_DIRECTIONS`], the words a query's row limit starts with too
/// (`FETCH NEXT 5 ROWS ONLY`).
const ROW_LIMIT_DIRECTIONS: &[&str] = &["NEXT", "FIRST"];

/// Whether the word at the current token is PostgreSQL's `MOVE`: a
/// direction, `FROM` / `IN`, or a cursor name ending the statement follows.
pub(crate) fn is_cursor_move_at(p: &Parser<'_>) -> bool {
    if !p.is_word(p.peek(), "MOVE") {
        return false;
    }
    let next = p.peek_ahead(1);
    let direction = CURSOR_DIRECTIONS.iter().any(|word| p.is_word(next, word));
    let named = next.is_some_and(|t| matches!(t.kind, TokenKind::Identifier { .. }))
        && p.peek_ahead(2)
            .is_none_or(|t| matches!(t.kind, TokenKind::Punctuation(Punctuation::Semi)));
    direction
        || named
        || next.is_some_and(|t| {
            matches!(
                t.kind,
                TokenKind::Keyword(Keyword::From | Keyword::In)
                    | TokenKind::Literal(crate::lexer::LiteralKind::Number)
            )
        })
}

pub(crate) fn try_parse_fetch_cursor_stmt(p: &mut Parser<'_>) -> ParseResult<AstStmt> {
    // Parse: { FETCH | MOVE } [[orientation] { FROM | IN }] [GLOBAL] cursor [INTO var1, var2, ...];
    // orientation: NEXT | PRIOR | FIRST | LAST | ABSOLUTE n | RELATIVE n |
    // ALL | n | FORWARD [n | ALL] | BACKWARD [n | ALL]
    let is_move = is_cursor_move_at(p);
    let fetch_kw = p.advance().ok_or_else(|| {
        ParseError::new(
            p.current_span(),
            ParseErrorKind::InvalidStatement {
                message: "Expected FETCH keyword".to_string(),
            },
        )
    })?;

    if !is_move && !matches!(fetch_kw.kind, TokenKind::Keyword(Keyword::Fetch)) {
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

    let (orientation, orientation_span) = read_fetch_orientation(p);
    if p.peek()
        .is_some_and(|t| matches!(t.kind, TokenKind::Keyword(Keyword::From | Keyword::In)))
    {
        p.advance();
    }
    // T-SQL's `GLOBAL` before a cursor's name.
    if p.is_word(p.peek(), "GLOBAL")
        && p.peek_ahead(1)
            .is_some_and(|t| matches!(t.kind, TokenKind::Identifier { .. }))
    {
        p.advance();
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
    if !matches!(cursor_tok.kind, TokenKind::Identifier { .. }) {
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
    let cursor_name_span = cursor_tok.span;

    // INTO var [, var …]: each variable after the first follows a comma.
    // MOVE reads no row into anything.
    let mut into_clause_span = Span {
        start: cursor_name_span.end,
        end: cursor_name_span.end,
    };
    let mut into_targets: Vec<crate::ast::AstIdentifier> = Vec::new();
    if let Some(into_tok) = p
        .peek()
        .filter(|t| !is_move && matches!(t.kind, TokenKind::Keyword(Keyword::Into)))
    {
        let into_start = into_tok.span.start;
        let mut into_end = into_tok.span.end;
        p.advance();
        while let Some(var_tok) = p
            .peek()
            .filter(|t| matches!(t.kind, TokenKind::Identifier { .. }))
        {
            let var_kind = crate::ast::AstIdentifierKind::of(&var_tok.kind);
            // A variable, or a field of one (`rec.col`, PL/pgSQL `NEW.col`).
            let var_span = p.take_name_or_token_span("variable name")?;
            into_end = var_span.end;
            into_targets.push(crate::ast::AstIdentifier {
                node_id: p.id_gen.next(),
                span: var_span,
                kind: var_kind,
                templated: None,
            });
            let more = p
                .peek()
                .is_some_and(|t| matches!(t.kind, TokenKind::Punctuation(Punctuation::Comma)))
                && p.peek_ahead(1)
                    .is_some_and(|t| matches!(t.kind, TokenKind::Identifier { .. }));
            if !more {
                break;
            }
            p.advance(); // ','
        }
        into_clause_span = Span {
            start: into_start,
            end: into_end,
        };
    }

    // Peek at semicolon to save token ID, but don't consume it
    let mut end = into_clause_span.end;
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
    Ok(AstStmt::FetchCursor {
        node_id: p.id_gen.next(),
        span,
        fetch_span: fetch_kw.span,
        move_span: is_move.then_some(fetch_kw.span),
        orientation,
        orientation_span,
        cursor_name_span,
        into_clause_span,
        into_targets,
        semicolon_token,
    })
}

/// The orientation of a `FETCH` at the current token, consumed where one is
/// written before its `FROM`: `NEXT`, `PRIOR`, `FIRST`, `LAST`, `ABSOLUTE
/// n` or `RELATIVE n`, with its span.
fn read_fetch_orientation(
    p: &mut Parser<'_>,
) -> (Option<crate::ast::AstFetchOrientation>, Option<Span>) {
    use crate::ast::{AstFetchCount as Count, AstFetchOrientation as Orientation};
    let followed_by_from = |p: &Parser<'_>, at: usize| {
        p.peek_ahead(at)
            .is_some_and(|t| matches!(t.kind, TokenKind::Keyword(Keyword::From | Keyword::In)))
    };
    // A count, `FROM` / `IN` after it; nothing consumed where none is. An
    // integer, read below the comparisons, so `5 IN c` is no `IN` test.
    let count_before_from = |p: &mut Parser<'_>| -> Option<AstExpr> {
        let (from, errors) = (p.idx, p.recovery_errors.len());
        let prev_mode = p.enter_mode(crate::parser::core::ParserMode::Scripting);
        let count = p.parse_add_expr_in_mode();
        p.restore_mode(prev_mode);
        match count {
            Ok(n) if followed_by_from(p, 0) => Some(n),
            Ok(_) | Err(_) => {
                p.idx = from;
                p.recovery_errors.truncate(errors);
                None
            }
        }
    };
    let Some(word_span) = p.peek().map(|t| t.span) else {
        return (None, None);
    };
    let ends = |end: u32| {
        Some(Span {
            start: word_span.start,
            end,
        })
    };
    let row = [
        ("NEXT", Orientation::Next),
        ("PRIOR", Orientation::Prior),
        ("FIRST", Orientation::First),
        ("LAST", Orientation::Last),
        ("ALL", Orientation::All),
    ]
    .into_iter()
    .find(|(name, _)| p.is_word(p.peek(), name));
    if let Some((_, orientation)) = row {
        if !followed_by_from(p, 1) {
            return (None, None);
        }
        p.advance();
        return (Some(orientation), Some(word_span));
    }
    let forward = p.is_word(p.peek(), "FORWARD");
    if forward || p.is_word(p.peek(), "BACKWARD") {
        let direction = if forward {
            Orientation::Forward
        } else {
            Orientation::Backward
        };
        if followed_by_from(p, 1) {
            p.advance();
            return (Some(direction(None)), Some(word_span));
        }
        if p.is_word(p.peek_ahead(1), "ALL") && followed_by_from(p, 2) {
            p.advance();
            let all = p.advance().expect_invariant("ALL after peek").span;
            return (Some(direction(Some(Count::All))), ends(all.end));
        }
        let from = p.idx;
        p.advance();
        return match count_before_from(p) {
            Some(n) => {
                let end = n.span().end;
                (Some(direction(Some(Count::Count(Box::new(n))))), ends(end))
            }
            None => {
                p.idx = from;
                (None, None)
            }
        };
    }
    let absolute = p.is_word(p.peek(), "ABSOLUTE");
    if absolute || p.is_word(p.peek(), "RELATIVE") {
        let from = p.idx;
        p.advance();
        let Some(n) = count_before_from(p) else {
            p.idx = from;
            return (None, None);
        };
        let span = ends(n.span().end);
        let orientation = if absolute {
            Orientation::Absolute(Box::new(n))
        } else {
            Orientation::Relative(Box::new(n))
        };
        return (Some(orientation), span);
    }
    // A count written alone (PostgreSQL `FETCH 5 FROM c`); a cursor's name
    // is no count.
    if p.peek()
        .is_some_and(|t| matches!(t.kind, TokenKind::Identifier { .. }))
    {
        return (None, None);
    }
    match count_before_from(p) {
        Some(n) => {
            let span = Some(n.span());
            (
                Some(Orientation::Forward(Some(Count::Count(Box::new(n))))),
                span,
            )
        }
        None => (None, None),
    }
}

/// Whether the `FETCH` at `idx` reads a cursor's row, not a query's row
/// limit (`FETCH { FIRST | NEXT } [n] { ROW | ROWS } …`): `FROM`, `IN` or
/// `INTO`, which no row limit holds, comes before `ROW`, `ROWS`, `ONLY`
/// or the end of the statement (`FETCH NEXT FROM c`, PostgreSQL `FETCH -1
/// FROM c`, `FETCH @c INTO @x`); a direction no row limit starts with
/// follows it ([`CURSOR_DIRECTIONS`]); or a cursor's name does (`FETCH c`,
/// T-SQL `FETCH GLOBAL c`), a word that is no session variable (`$n` is a
/// count) with `;`, `END`, the next statement or nothing after it. The one
/// decision: the query's clause reader reads every other `FETCH` as its
/// row limit.
pub(crate) fn fetch_reads_cursor_at(p: &Parser<'_>, idx: usize) -> bool {
    use crate::parser::principal::next_non_trivia_idx;
    let next = |from: usize| next_non_trivia_idx(p.tokens, from + 1);
    let Some(first) = next(idx) else {
        return false;
    };
    // The words up to the cursor's position, outside parentheses.
    let mut depth = 0usize;
    let mut at = Some(first);
    while let Some(i) = at {
        let kind = &p.tokens[i].kind;
        if depth == 0 {
            if matches!(
                kind,
                TokenKind::Keyword(Keyword::From | Keyword::In | Keyword::Into)
            ) {
                return true;
            }
            let ends = matches!(
                kind,
                TokenKind::Keyword(Keyword::Row | Keyword::Rows | Keyword::Only)
                    | TokenKind::Punctuation(Punctuation::Semi | Punctuation::RParen)
                    | TokenKind::Eof
            ) || (i > first && p.leads_statement(i));
            if ends {
                break;
            }
        }
        if matches!(kind, TokenKind::Punctuation(Punctuation::LParen)) {
            depth += 1;
        } else if matches!(kind, TokenKind::Punctuation(Punctuation::RParen)) {
            depth = depth.saturating_sub(1);
        }
        at = next(i);
    }
    let words = |list: &[&str]| list.iter().any(|word| p.word_at(first, word));
    if words(ROW_LIMIT_DIRECTIONS) {
        return false;
    }
    if words(CURSOR_DIRECTIONS) {
        return true;
    }
    // T-SQL's `GLOBAL` before the cursor's name.
    let name = match p.word_at(first, "GLOBAL") {
        true => match next(first) {
            Some(name) => name,
            None => return false,
        },
        false => first,
    };
    matches!(p.tokens[name].kind, TokenKind::Identifier { .. })
        && !p.is_session_variable(&p.tokens[name])
        && next(name).is_none_or(|after| {
            matches!(
                p.tokens[after].kind,
                TokenKind::Keyword(Keyword::Into | Keyword::End)
                    | TokenKind::Punctuation(Punctuation::Semi)
            ) || p.leads_statement(after)
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
    use crate::error::ExpectInvariant;

    let mut body_stmt: Option<Box<AstStmt>> = None;
    let mut closing_delimiter_token: Option<crate::cst::TokenId> = None;
    let mut body_end = body_content_start;
    let mut delimiter_end = body_content_start;
    p.dollar_bodies.push(open_tag_lo as u32);

    if p.peek_non_trivia().is_some() {
        // Save parser position in case parsing fails
        let save_idx = p.idx;

        match read_dollar_body_block(p) {
            Some(Ok(stmt)) => {
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
            failed => {
                // Not a block, or a block that does not parse: restore position
                // and collect tokens opaquely up to and including the matching
                // closer.
                p.idx = save_idx;

                let mut body_content_end = body_content_start;
                let mut closer_idx = None;
                while let Some(_tok) = p.peek_non_trivia() {
                    let t = p
                        .advance()
                        .expect_invariant("dollar body token consumed after peek");
                    if t.lexeme(p.source) == &p.source[open_tag_lo..open_tag_hi] {
                        closing_delimiter_token = Some(p.last_token_id());
                        delimiter_end = t.span.end;
                        closer_idx = Some(p.idx - 1);
                        break;
                    }
                    body_content_end = t.span.end;
                }
                body_end = body_content_end;
                if let Some(Err(err)) = failed {
                    let closer_idx = closer_idx.unwrap_or(p.idx);
                    body_stmt = Some(Box::new(failed_dollar_body(p, save_idx, closer_idx, &err)));
                }
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

/// The block a dollar-quoted body holds, read from its first token:
/// `[<<label>>] DECLARE … BEGIN … END` or `[<<label>>] BEGIN … END`. `None`
/// where the body does not start a block.
fn read_dollar_body_block(p: &mut Parser<'_>) -> Option<ParseResult<AstStmt>> {
    let first = next_non_trivia_idx(p.tokens, p.idx)?;
    let label = if matches!(
        p.tokens[first].kind,
        TokenKind::Operator(crate::lexer::Operator::LtLt)
    ) {
        label_prefix_at(p, first)
    } else {
        None
    };
    let keyword = match label {
        Some((after, _)) => next_non_trivia_idx(p.tokens, after)?,
        None => first,
    };
    let declare = matches!(p.tokens[keyword].kind, TokenKind::Keyword(Keyword::Declare));
    if !declare && !matches!(p.tokens[keyword].kind, TokenKind::Keyword(Keyword::Begin)) {
        return None;
    }
    let label = label.map(|(_, span)| span);
    p.idx = keyword;
    p.dollar_body_block_depth += 1;
    let block = if declare {
        try_parse_scripting_block_with_label(p, label).map(DeclareSection::into_stmt)
    } else {
        try_parse_block_stmt_with_label(p, label)
    };
    p.dollar_body_block_depth -= 1;
    Some(block)
}

/// A dollar-quoted body whose block does not parse, from `start_idx` to its
/// closing delimiter at `closer_idx`: the statement recovery's
/// `AstStmt::Error` over the whole body, its secrets recorded. The parser's
/// position is kept.
fn failed_dollar_body(
    p: &mut Parser<'_>,
    start_idx: usize,
    closer_idx: usize,
    err: &ParseError,
) -> AstStmt {
    let resume = p.idx;
    let start_pos = next_non_trivia_idx(p.tokens, start_idx)
        .map_or(p.current_span().start, |i| p.tokens[i].span.start);
    p.idx = closer_idx;
    let (error, _) = create_error_and_sync(
        p,
        start_pos,
        start_idx,
        err,
        &[BodyTerminator::DollarQuoteDelimiter],
    );
    p.idx = resume;
    error
}

/// The index just past a module option `{EXEC | EXECUTE} AS {CALLER | SELF
/// | OWNER | RESTRICTED CALLER | 'user_name'}` whose first token is
/// `tokens[idx]`, with the mode it names (`None` for `SELF` and a named
/// user, which no mode states); `None` where no such option starts there.
/// The option's `AS` never opens a body.
fn execute_as_option_at(
    tokens: &[Token],
    idx: usize,
    source: &str,
) -> Option<(usize, Option<ExecuteAsMode>)> {
    let significant = |from: usize| {
        (from..tokens.len()).find(|&i| {
            !matches!(
                tokens[i].kind,
                TokenKind::LineComment | TokenKind::BlockComment
            )
        })
    };
    let word = |tok: &Token| {
        matches!(
            tok.kind,
            TokenKind::Keyword(_)
                | TokenKind::Identifier {
                    kind: crate::lexer::IdentifierKind::Unquoted,
                    ..
                }
        )
        .then(|| tok.lexeme(source))
    };
    let exec = tokens.get(idx)?;
    let is_exec = matches!(exec.kind, TokenKind::Keyword(Keyword::Execute))
        || word(exec).is_some_and(|w| w.eq_ignore_ascii_case("EXEC"));
    let as_idx = significant(idx + 1)?;
    if !is_exec || !matches!(tokens[as_idx].kind, TokenKind::Keyword(Keyword::As)) {
        return None;
    }
    let target_idx = significant(as_idx + 1)?;
    let target = &tokens[target_idx];
    if matches!(
        target.kind,
        TokenKind::Literal(crate::lexer::LiteralKind::String)
    ) {
        return Some((target_idx + 1, None));
    }
    let target_word = word(target)?;
    if target_word.eq_ignore_ascii_case("RESTRICTED") {
        let caller_idx = significant(target_idx + 1)?;
        return word(&tokens[caller_idx])
            .is_some_and(|w| w.eq_ignore_ascii_case("CALLER"))
            .then_some((caller_idx + 1, Some(ExecuteAsMode::RestrictedCaller)));
    }
    let mode = if target_word.eq_ignore_ascii_case("CALLER") {
        Some(ExecuteAsMode::Caller)
    } else if target_word.eq_ignore_ascii_case("OWNER") {
        Some(ExecuteAsMode::Owner)
    } else if target_word.eq_ignore_ascii_case("SELF") {
        None
    } else {
        return None;
    };
    Some((target_idx + 1, mode))
}

/// Consumes the module option `{EXEC | EXECUTE} AS …` at the current token
/// ([`execute_as_option_at`]) and returns the mode it names; `None`,
/// consuming nothing, where the option does not start here.
fn take_execute_as_option(p: &mut Parser<'_>) -> Option<Option<ExecuteAsMode>> {
    p.skip_trivia();
    let (next, mode) = execute_as_option_at(p.tokens, p.idx, p.source)?;
    p.idx = next;
    Some(mode)
}

/// Reads a routine definition with no enclosing dollar-quoted block in force,
/// restoring the enclosing depth after on every path: a routine defined inside
/// a PL/pgSQL body is its own context, and only a block of its own body reads
/// `INTO` as variables.
fn read_routine_definition(
    p: &mut Parser<'_>,
    read: fn(&mut Parser<'_>) -> ParseResult<AstStmt>,
) -> ParseResult<AstStmt> {
    let enclosing_depth = std::mem::take(&mut p.dollar_body_block_depth);
    let definition = read(p);
    p.dollar_body_block_depth = enclosing_depth;
    definition
}

/// The statement a module definition is, from its first keyword
/// (`CREATE` or `ALTER`) and its `OR ALTER`.
fn definition_verb(
    first: &crate::lexer::Token,
    or_alter_span: Option<Span>,
) -> crate::ast::AstDefinitionVerb {
    if matches!(first.kind, TokenKind::Keyword(Keyword::Alter)) {
        crate::ast::AstDefinitionVerb::Alter
    } else if or_alter_span.is_some() {
        crate::ast::AstDefinitionVerb::CreateOrAlter
    } else {
        crate::ast::AstDefinitionVerb::Create
    }
}

/// Parse CREATE PROCEDURE statement, returning Result (for diagnostic error reporting).
pub(crate) fn try_parse_create_procedure(p: &mut Parser<'_>) -> ParseResult<AstStmt> {
    read_routine_definition(p, read_create_procedure)
}

fn read_create_procedure(p: &mut Parser<'_>) -> ParseResult<AstStmt> {
    use crate::error::{ExpectInvariant, ParseError, ParseErrorKind, ParseResultExt};

    // Parse: CREATE [OR REPLACE] PROCEDURE name(params) RETURNS type LANGUAGE SQL AS body
    // T-SQL's `ALTER PROC[EDURE] name … AS body` restates the definition and
    // is read the same way, `create_span` holding its `ALTER`.
    let create_span = p.current_span();
    let create_kw = p
        .advance()
        .ok_or_eof(create_span, vec!["CREATE".to_string()])?;
    if !matches!(
        create_kw.kind,
        TokenKind::Keyword(Keyword::Create) | TokenKind::Keyword(Keyword::Alter)
    ) {
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
    let verb = definition_verb(create_kw, or_alter_span);

    // Optional MySQL `DEFINER = { user | CURRENT_USER }` clause (precedes
    // PROCEDURE). Fully parsed into the typed security-context primitive,
    // not skipped — the body runs under this account's privileges.
    let definer = p.parse_definer_clause();

    // Expect PROCEDURE keyword
    let proc_span = p.current_span();
    let proc_kw = p
        .advance()
        .ok_or_eof(proc_span, vec!["PROCEDURE".to_string()])?;
    if !matches!(proc_kw.kind, TokenKind::Keyword(Keyword::Procedure))
        && !proc_kw.lexeme(p.source).eq_ignore_ascii_case("PROC")
    {
        return Err(ParseError::new(
            proc_kw.span,
            ParseErrorKind::InvalidSyntax {
                message: "Expected PROCEDURE after CREATE [OR REPLACE]".to_string(),
            },
        ));
    }
    let procedure_keyword_span = proc_kw.span;

    let name_span = p.parse_object_name_span()?;
    let name_end = name_span.end;

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
    let clauses_first = p.idx;
    while let Some(tok) = p.peek_non_trivia() {
        if matches!(
            tok.kind,
            TokenKind::Keyword(Keyword::Returns)
                | TokenKind::Keyword(Keyword::Language)
                | TokenKind::Keyword(Keyword::As)
                | TokenKind::Keyword(Keyword::Begin)
                | TokenKind::Keyword(Keyword::Declare)
        ) || execute_as_option_at(p.tokens, p.idx, p.source).is_some()
        {
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
            // Collect tokens until we hit LANGUAGE, AS or an `EXECUTE AS` option
            while let Some(tok) = p.peek_non_trivia() {
                if matches!(tok.kind, TokenKind::Keyword(Keyword::Language))
                    || matches!(tok.kind, TokenKind::Keyword(Keyword::As))
                    || execute_as_option_at(p.tokens, p.idx, p.source).is_some()
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

    // The body's language: `Sql` until a `LANGUAGE` clause, before or after
    // the body, names another.
    let mut language = take_language_clause(p).map_or(AstRoutineLanguage::Sql, |(named, _)| named);

    // Skip any optional clauses (CALLED ON NULL INPUT, COMMENT, T-SQL's
    // `WITH <procedure_option> [, …]`, etc.) until the body's AS; the `AS`
    // of an `EXECUTE AS` option is the option's.
    let mut found_as = false;
    // The mode the first `EXECUTE AS` option names; `SELF` and a named user
    // name a principal no mode states.
    let mut execute_as_mode: Option<ExecuteAsMode> = None;
    let mut search_path: Option<Vec<Span>> = None;
    while let Some(tok) = p.peek_non_trivia() {
        // If we hit BEGIN or DECLARE directly (without AS), BigQuery-style: body starts here
        if matches!(
            tok.kind,
            TokenKind::Keyword(Keyword::Begin) | TokenKind::Keyword(Keyword::Declare)
        ) {
            break;
        }
        if let Some(mode) = take_execute_as_option(p) {
            execute_as_mode = execute_as_mode.or(mode);
            continue;
        }
        if let Some((named, _)) = take_language_clause(p) {
            language = named;
            continue;
        }
        if let Some(path) = take_search_path_clause(p) {
            search_path = Some(path);
            continue;
        }
        if matches!(tok.kind, TokenKind::Keyword(Keyword::As)) {
            found_as = true;
            break;
        }
        p.advance();
    }
    p.record_setting_clause_secrets(clauses_first, p.idx);

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
    let mut body_statements: Vec<AstStmt> = Vec::new();
    let mut had_delimiters = false;
    let mut delimiter_end = body_start;
    let mut opening_delimiter_token: Option<crate::cst::TokenId> = None;
    let mut closing_delimiter_token: Option<crate::cst::TokenId> = None;
    let mut dollar_body: Option<Span> = None;

    // If body starts with a dollar-quote delimiter (`$$` or `$tag$`), parse the
    // body content and find the matching close tag (same lexeme as the opener).
    if p.delimits_dollar_quote(body_start_tok) {
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
        dollar_body = Some(Span {
            start: opening_delimiter.span.start,
            end: delimiter_end,
        });

        // Set body_span to exclude delimiters (just the content)
        body_start = body_content_start;
    }
    // Where terminators are optional (T-SQL) a body that is not one
    // `BEGIN … END` block is every statement up to the batch separator.
    else if p.dialect.uses_optional_statement_terminators() {
        let terminators = [BodyTerminator::BatchSeparator];
        let empty_body = BodyTerminator::BatchSeparator.matches(body_start_tok, p)
            || matches!(
                body_start_tok.kind,
                TokenKind::Punctuation(Punctuation::Semi)
            );
        if !empty_body {
            let first_idx = p.idx;
            match try_parse_scripting_stmt(p, StmtContext::Block, body_start) {
                Ok(block @ AstStmt::Block(_)) => {
                    body_end = block.span().end;
                    body_stmt_opt = Some(Box::new(block));
                }
                first => {
                    let first = match first {
                        Ok(stmt) => stmt,
                        Err(err) => {
                            create_error_and_sync(p, body_start, first_idx, &err, &terminators).0
                        }
                    };
                    let (rest, _errors) =
                        parse_body_with_recovery(p, StmtContext::Block, body_start, &terminators);
                    body_statements.push(first);
                    body_statements.extend(rest);
                    // The body ends at its last token, a `;` after its last
                    // statement included.
                    body_end = p.tokens[first_idx..p.idx]
                        .iter()
                        .rev()
                        .find(|t| {
                            !matches!(
                                t.kind,
                                TokenKind::Eof | TokenKind::LineComment | TokenKind::BlockComment
                            )
                        })
                        .map_or(body_start, |t| t.span.end);
                }
            }
        }
    }
    // If body starts with BEGIN or DECLARE, parse it as a scripting block
    else if matches!(
        body_start_tok.kind,
        TokenKind::Keyword(Keyword::Begin) | TokenKind::Keyword(Keyword::Declare)
    ) {
        // Try to parse the block using parse_scripting_block for DECLARE or parse_block_stmt for BEGIN
        // If it fails, fall back to collecting tokens. A `BEGIN` with no
        // `END` after it does not close: the rest of the input is not read
        // as its block.
        let save_idx = p.idx;
        let block_result = if matches!(body_start_tok.kind, TokenKind::Keyword(Keyword::Declare)) {
            parse_scripting_block(p)
        } else if p.end_written_after(save_idx) {
            parse_block_stmt(p)
        } else {
            None
        };
        match block_result {
            Some(block_stmt) => {
                body_end = block_stmt.span().end;
                // Store the parsed statement for recursive descent formatting
                body_stmt_opt = Some(Box::new(block_stmt));
            }
            None => {
                // A body that does not parse as a block is one statement not
                // parsed over its tokens to the first `;`, its secrets
                // recorded; what follows is read on.
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
                p.record_unparsed_secrets(save_idx, p.idx);
                body_stmt_opt = Some(Box::new(AstStmt::Error {
                    node_id: p.id_gen.next(),
                    span: Span {
                        start: body_start,
                        end: body_end,
                    },
                    message: "procedure body does not parse as a block".to_string(),
                    partial_tokens: p.tokens[save_idx..p.idx]
                        .iter()
                        .filter(|t| !is_skippable(t))
                        .take(10)
                        .map(|t| format!("{:?}", t.kind))
                        .collect(),
                }));
            }
        }
    }
    // Otherwise, collect until semicolon (for string literal bodies)
    else {
        let from = p.idx;
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
        p.record_string_body_secrets(from, p.idx);
    }
    let body_span = Span {
        start: body_start,
        end: body_end,
    };

    // PostgreSQL puts LANGUAGE after the body: AS $$...body...$$ LANGUAGE plpgsql
    let mut trailing_end = if had_delimiters {
        delimiter_end.max(body_end)
    } else {
        body_end
    };
    if had_delimiters {
        let trailing_first = p.idx;
        if let Some(end) = take_trailing_routine_options(p, &mut language, &mut search_path) {
            trailing_end = end;
        }
        p.record_setting_clause_secrets(trailing_first, p.idx);
    } else if let Some((named, end)) = take_language_clause(p) {
        language = named;
        trailing_end = end;
    }

    // Calculate the overall procedure span including delimiters
    // Don't consume semicolon - let outer wrapper handle it
    let proc_end = trailing_end;

    let span = Span {
        start: proc_start,
        end: proc_end,
    };
    if let Some(span) = dollar_body {
        p.note_routine_body(span, &language, body_stmt_opt.as_deref());
    }
    let params = p.read_procedure_params(params_span);
    Ok(AstStmt::CreateProcedure(Box::new(
        crate::ast::AstCreateProcedureStmt {
            node_id: p.id_gen.next(),
            span,
            create_span: create_kw_span,
            verb,
            or_replace_span,
            or_alter_span,
            procedure_keyword_span,
            name_span,
            params_span,
            params,
            returns_span,
            language,
            body_span,
            body_stmt: body_stmt_opt,
            body_statements,
            opening_delimiter_token,
            closing_delimiter_token,
            execute_as_mode,
            definer,
            search_path,
        },
    )))
}

/// Reads, at the cursor, the options PostgreSQL lets a routine write after
/// its body: `LANGUAGE`, `SET` of a setting (`search_path`'s entries kept in
/// `search_path`), `SECURITY` / `EXTERNAL SECURITY`, volatility,
/// `[NOT] LEAKPROOF`, the NULL-input forms, `PARALLEL`, `COST`, `ROWS`,
/// `SUPPORT` and `WINDOW`, each consumed; the end of the last, `None`
/// where none is written.
fn take_trailing_routine_options(
    p: &mut Parser<'_>,
    language: &mut AstRoutineLanguage,
    search_path: &mut Option<Vec<Span>>,
) -> Option<u32> {
    // `*` is any one token.
    const OPTIONS: &[&[&str]] = &[
        &["SECURITY", "*"],
        &["EXTERNAL", "SECURITY", "*"],
        &["IMMUTABLE"],
        &["STABLE"],
        &["VOLATILE"],
        &["STRICT"],
        &["LEAKPROOF"],
        &["NOT", "LEAKPROOF"],
        &["CALLED", "ON", "NULL", "INPUT"],
        &["RETURNS", "NULL", "ON", "NULL", "INPUT"],
        &["PARALLEL", "*"],
        &["COST", "*"],
        &["ROWS", "*"],
        &["SUPPORT", "*"],
        &["WINDOW"],
    ];
    let mut end = None;
    loop {
        p.skip_trivia();
        if let Some((named, at)) = take_language_clause(p) {
            *language = named;
            end = Some(at);
            continue;
        }
        let start = p.idx;
        if let Some(path) = take_search_path_clause(p) {
            *search_path = Some(path);
        } else if !take_setting_clause(p) {
            let past = OPTIONS.iter().find_map(|words| {
                words
                    .iter()
                    .enumerate()
                    .all(|(k, word)| {
                        p.tokens.get(start + k).is_some_and(|tok| {
                            !matches!(tok.kind, TokenKind::Eof | TokenKind::Punctuation(_))
                                && (*word == "*" || tok.lexeme(p.source).eq_ignore_ascii_case(word))
                        })
                    })
                    .then_some(start + words.len())
            });
            match past {
                Some(past) => p.idx = past,
                None => return end,
            }
        }
        end = p.tokens.get(p.idx.checked_sub(1)?).map(|tok| tok.span.end);
    }
}

/// Consumes a routine's `SET <setting> { TO | = } value [, …]` or `SET
/// <setting> FROM CURRENT` clause at the current token; false, consuming
/// nothing, where none starts here.
fn take_setting_clause(p: &mut Parser<'_>) -> bool {
    p.skip_trivia();
    let Some(set) = p.tokens.get(p.idx) else {
        return false;
    };
    if !matches!(set.kind, TokenKind::Keyword(Keyword::Set)) {
        return false;
    }
    let Some(setting) = next_non_trivia_idx(p.tokens, p.idx + 1) else {
        return false;
    };
    let named = p.tokens.get(setting).is_some_and(|tok| {
        matches!(tok.kind, TokenKind::Identifier { .. }) || p.can_be_identifier_token(tok)
    });
    let Some(assign) = next_non_trivia_idx(p.tokens, setting + 1).filter(|_| named) else {
        return false;
    };
    if p.word_at(assign, "FROM") && p.word_at(assign + 1, "CURRENT") {
        p.idx = assign + 2;
        return true;
    }
    let assigns = p.tokens.get(assign).is_some_and(|tok| {
        matches!(tok.kind, TokenKind::Keyword(Keyword::To)) || tok.lexeme(p.source) == "="
    });
    if !assigns {
        return false;
    }
    let mut at = assign + 1;
    loop {
        let value = p
            .tokens
            .get(at)
            .is_some_and(|tok| !matches!(tok.kind, TokenKind::Eof | TokenKind::Punctuation(_)));
        if !value {
            return false;
        }
        let comma = p
            .tokens
            .get(at + 1)
            .is_some_and(|tok| matches!(tok.kind, TokenKind::Punctuation(Punctuation::Comma)));
        if !comma {
            p.idx = at + 1;
            return true;
        }
        at += 2;
    }
}

/// Reads a `LANGUAGE <name>` clause at the cursor: the language it names and
/// where it ends. `None` where no `LANGUAGE` is written. A `LANGUAGE` that
/// names nothing (`;`, `AS` or an `EXECUTE AS` option follows) names SQL.
fn take_language_clause(p: &mut Parser<'_>) -> Option<(AstRoutineLanguage, u32)> {
    let keyword = p
        .peek_non_trivia()
        .filter(|tok| matches!(tok.kind, TokenKind::Keyword(Keyword::Language)))?;
    let mut end = keyword.span.end;
    p.advance();
    let mut language = AstRoutineLanguage::Sql;
    if let Some(name) = p.peek_non_trivia() {
        let ends_clause = matches!(
            name.kind,
            TokenKind::Punctuation(Punctuation::Semi) | TokenKind::Keyword(Keyword::As)
        ) || execute_as_option_at(p.tokens, p.idx, p.source).is_some();
        if !ends_clause {
            let written = name.lexeme(p.source);
            let value = if matches!(name.kind, TokenKind::Literal(LiteralKind::String)) {
                crate::lexer::decode_string_literal(written, p.dialect)
                    .filter(|string| string.closed)
                    .map_or_else(|| written.to_string(), |string| string.value)
            } else {
                crate::dialect::normalize_identifier_in(p.dialect, written)
            };
            language = AstRoutineLanguage::from_name(&value, written, p.dialect);
            end = name.span.end;
            p.advance();
        }
    }
    Some((language, end))
}

/// Whether MySQL's `CREATE [AGGREGATE] FUNCTION [IF NOT EXISTS] name RETURNS
/// type SONAME` starts at the current `CREATE`.
pub(crate) fn loadable_function_at(p: &Parser<'_>) -> bool {
    let mut i = p.idx + 1;
    if p.word_at(i, "AGGREGATE") {
        i += 1;
    }
    if !p.word_at(i, "FUNCTION") {
        return false;
    }
    i += 1;
    if p.word_at(i, "IF") && p.word_at(i + 1, "NOT") && p.word_at(i + 2, "EXISTS") {
        i += 3;
    }
    let Some(after_name) = p.object_name_end(i) else {
        return false;
    };
    p.word_at(after_name, "RETURNS") && p.word_at(after_name + 2, "SONAME")
}

/// MySQL's loadable function ([`loadable_function_at`]).
pub(crate) fn try_parse_mysql_loadable_function(p: &mut Parser<'_>) -> ParseResult<AstStmt> {
    let create_span = next(p, "CREATE")?;
    let aggregate_span = match p.is_word(p.peek(), "AGGREGATE") {
        true => Some(next(p, "AGGREGATE")?),
        false => None,
    };
    let function_span = next(p, "FUNCTION")?;
    let if_not_exists_span = match p.is_word(p.peek(), "IF") {
        true => {
            let start = next(p, "IF")?.start;
            next(p, "NOT")?;
            let end = next(p, "EXISTS")?.end;
            Some(Span { start, end })
        }
        false => None,
    };
    let name = p.parse_object_name_span()?;
    let returns_start = next(p, "RETURNS")?.start;
    let returns_end = next(p, "type")?.end;
    let soname_span = next(p, "SONAME")?;
    let library = p
        .peek()
        .filter(|t| {
            matches!(
                t.kind,
                TokenKind::Literal(crate::lexer::LiteralKind::String)
            )
        })
        .map(|t| t.span)
        .ok_or_else(|| {
            ParseError::new(
                soname_span,
                ParseErrorKind::InvalidStatement {
                    message: "SONAME requires the library's name as a string".to_string(),
                },
            )
        })?;
    p.advance();
    Ok(AstStmt::MysqlCreateLoadableFunction(Box::new(
        crate::ast::AstMysqlCreateLoadableFunction {
            node_id: p.id_gen.next(),
            span: Span {
                start: create_span.start,
                end: library.end,
            },
            create_span,
            aggregate_span,
            function_span,
            if_not_exists_span,
            name,
            returns_span: Span {
                start: returns_start,
                end: returns_end,
            },
            soname_span,
            library,
        },
    )))
}

/// The span of the next token, `what` naming it when the input ends.
fn next(p: &mut Parser<'_>, what: &str) -> ParseResult<Span> {
    p.advance()
        .map(|t| t.span)
        .ok_or_eof(p.current_span(), vec![what.to_string()])
}

pub(crate) fn parse_create_function(p: &mut Parser<'_>) -> ParseResult<AstStmt> {
    read_routine_definition(p, read_create_function)
}

fn read_create_function(p: &mut Parser<'_>) -> ParseResult<AstStmt> {
    // Parse: CREATE [OR REPLACE] [TEMP|TEMPORARY] [AGGREGATE] FUNCTION [IF NOT EXISTS]
    //        name(params) RETURNS type LANGUAGE SQL AS body
    // T-SQL's `ALTER FUNCTION name (params) RETURNS …` restates the
    // definition and is read the same way, `create_span` holding its `ALTER`.
    let create_kw = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["CREATE".to_string()])?;
    if !matches!(
        create_kw.kind,
        TokenKind::Keyword(Keyword::Create) | TokenKind::Keyword(Keyword::Alter)
    ) {
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
    let verb = definition_verb(create_kw, or_alter_span);

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

    let name_span = p.parse_object_name_span()?;

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
    let clauses_first = p.idx;

    // Clauses written before RETURNS (Snowflake's COPY GRANTS, PostgreSQL's
    // options where OUT parameters give the type). The scan stops at the
    // body or the statement's end: RETURNS is optional where the body or
    // OUT parameters give the type. The body's language is `Sql` until a
    // `LANGUAGE` clause, in any place before or after the body, names
    // another.
    let mut language = AstRoutineLanguage::Sql;
    while let Some(tok) = p.peek_non_trivia() {
        if matches!(
            tok.kind,
            TokenKind::Keyword(Keyword::Returns | Keyword::As | Keyword::Return | Keyword::Begin)
                | TokenKind::Punctuation(Punctuation::Semi)
        ) {
            break;
        }
        if let Some((named, _)) = take_language_clause(p) {
            language = named;
            continue;
        }
        p.advance();
    }
    let returns = read_returns_clause(p);
    if let Some((named, _)) = take_language_clause(p) {
        language = named;
    }

    // Skip any optional clauses (CALLED ON NULL INPUT, COMMENT, MEMOIZABLE,
    // T-SQL's `WITH <function_option> [, …]`, etc.) until AS
    // (Snowflake/PostgreSQL/BigQuery), RETURN (Databricks SQL UDF) or a
    // body's BEGIN; the `AS` of an `EXECUTE AS` option is the option's.
    let mut search_path: Option<Vec<Span>> = None;
    while let Some(tok) = p.peek_non_trivia() {
        if take_execute_as_option(p).is_some() {
            continue;
        }
        if let Some((named, _)) = take_language_clause(p) {
            language = named;
            continue;
        }
        if let Some(path) = take_search_path_clause(p) {
            search_path = Some(path);
            continue;
        }
        if matches!(tok.kind, TokenKind::Keyword(Keyword::As))
            || matches!(tok.kind, TokenKind::Keyword(Keyword::Return))
            || matches!(tok.kind, TokenKind::Keyword(Keyword::Begin))
        {
            break;
        }
        p.advance();
    }
    p.record_setting_clause_secrets(clauses_first, p.idx);

    // Expect AS (traditional function body) or RETURN (Databricks SQL UDF
    // body). A `BEGIN … END` body may follow the clauses directly: T-SQL's
    // `AS` is optional before it, and MySQL and Databricks write none.
    let body_opens_block = p
        .peek_non_trivia()
        .is_some_and(|t| matches!(t.kind, TokenKind::Keyword(Keyword::Begin)));
    let (is_return_body, body_intro_span) = if body_opens_block {
        (false, p.current_span())
    } else {
        let body_intro_kw = p.advance().ok_or_eof(
            p.current_span(),
            vec!["AS".to_string(), "RETURN".to_string()],
        )?;
        if matches!(body_intro_kw.kind, TokenKind::Keyword(Keyword::As)) {
            (false, body_intro_kw.span)
        } else if matches!(body_intro_kw.kind, TokenKind::Keyword(Keyword::Return)) {
            (true, body_intro_kw.span)
        } else {
            return Err(crate::error::ParseError::unexpected_token(
                body_intro_kw.span,
                vec!["AS".to_string(), "RETURN".to_string()],
                crate::parser::core::Parser::token_description(body_intro_kw, p.source),
            ));
        }
    };

    // Parse function body
    // Body can be:
    // 1. String literal delimited by $$ or ' containing the function code
    // 2. BEGIN ... END block directly (for Snowflake Scripting)
    // 3. RETURN <expr> (Databricks SQL UDF)

    let mut body_start = body_intro_span.start;
    let mut body_end = body_intro_span.end;
    let mut had_delimiters = false;
    let mut delimiter_end = body_end;
    let mut opening_delimiter_token: Option<crate::cst::TokenId> = None;
    let mut closing_delimiter_token: Option<crate::cst::TokenId> = None;
    let mut body_stmt: Option<Box<AstStmt>> = None;
    let mut dollar_open: Option<u32> = None;

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
        if p.delimits_dollar_quote(body_start_tok) {
            had_delimiters = true;
            let opening_delimiter = p
                .advance()
                .expect_invariant("Opening delimiter should be available"); // Skip opening $tag$
            opening_delimiter_token = Some(p.last_token_id());
            let open_tag_lo = opening_delimiter.span.start as usize;
            let open_tag_hi = opening_delimiter.span.end as usize;
            p.dollar_bodies.push(opening_delimiter.span.start);
            dollar_open = Some(opening_delimiter.span.start);
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
            let closer_idx = if closing_delimiter_token.is_some() {
                save_idx - 1
            } else {
                save_idx
            };
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
            match read_dollar_body_block(p) {
                Some(Ok(block)) => body_stmt = Some(Box::new(block)),
                Some(Err(err)) => {
                    body_stmt = Some(Box::new(failed_dollar_body(
                        p,
                        body_parse_start_idx,
                        closer_idx,
                        &err,
                    )));
                }
                None => {
                    if p.peek_non_trivia().is_some() {
                        if let Ok(stmt) = p.parse_flow_statement() {
                            body_stmt = Some(Box::new(stmt));
                        }
                    }
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
            // If it fails, fall back to collecting tokens. A `BEGIN` with no
            // `END` after it does not close: the rest of the input is not
            // read as its block.
            let save_idx = p.idx;
            let block_result =
                if matches!(body_start_tok.kind, TokenKind::Keyword(Keyword::Declare)) {
                    parse_scripting_block(p)
                } else if p.end_written_after(save_idx) {
                    parse_block_stmt(p)
                } else {
                    None
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
        // T-SQL inline table-valued function: `AS RETURN [(] query [)]`. The
        // body ends where the query does; it is kept as written, as a
        // body read to a terminator is.
        else if matches!(body_start_tok.kind, TokenKind::Keyword(Keyword::Return)) {
            body_end = p.advance().expect_invariant("RETURN after peek").span.end;
            let has_paren = p.peek_non_trivia().is_some_and(|t| {
                matches!(
                    t.kind,
                    TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
                )
            });
            if has_paren {
                body_end = p.advance().expect_invariant("`(` after peek").span.end;
            }
            let query_start_idx = p.idx;
            match p.parse_statement() {
                Ok(query) => {
                    body_end = query.span().end;
                    if has_paren {
                        if let Some(close) = p.peek_non_trivia() {
                            if matches!(
                                close.kind,
                                TokenKind::Punctuation(crate::lexer::Punctuation::RParen)
                            ) {
                                let close = p.advance().expect_invariant("`)` after peek");
                                body_end = close.span.end;
                            }
                        }
                    }
                }
                Err(_) => {
                    p.idx = query_start_idx;
                    while let Some(tok) = p.peek_non_trivia() {
                        if p.should_stop_scan_at_statement_start(tok)
                            || matches!(
                                tok.kind,
                                TokenKind::Punctuation(crate::lexer::Punctuation::Semi)
                            )
                        {
                            break;
                        }
                        let t = p
                            .advance()
                            .expect_invariant("function body token consumed after query failure");
                        body_end = t.span.end;
                    }
                }
            }
        }
        // Otherwise, collect until semicolon (for string literal bodies)
        else {
            let from = p.idx;
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
            p.record_string_body_secrets(from, p.idx);
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
    // A string body: the routine's options may follow it.
    if had_delimiters {
        let trailing_first = p.idx;
        if let Some(end) = take_trailing_routine_options(p, &mut language, &mut search_path) {
            trailing_end = end;
        }
        p.record_setting_clause_secrets(trailing_first, p.idx);
    }
    if let Some((named, end)) = take_language_clause(p) {
        language = named;
        trailing_end = end;
    }
    if let Some(start) = dollar_open {
        p.note_routine_body(
            Span {
                start,
                end: delimiter_end,
            },
            &language,
            body_stmt.as_deref(),
        );
    }

    // BigQuery's `OPTIONS (…)`, before `AS` or after the body.
    p.record_options_clause_secrets(clauses_first, p.idx);

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
            verb,
            or_replace_span,
            or_alter_span,
            temp_keyword_span,
            aggregate_keyword_span,
            function_keyword_span,
            if_not_exists_span,
            name_span,
            params_span,
            params: p.read_procedure_params(params_span),
            returns,
            body_span,
            body_stmt,
            opening_delimiter_token,
            closing_delimiter_token,
            definer,
            search_path,
        },
    )))
}

/// Consumes a routine's `SET search_path { TO | = } a [, b …]` clause at
/// the current token and returns the span of each entry; `None`,
/// consuming nothing, where no such clause starts here or it sets the
/// path `FROM CURRENT`.
fn take_search_path_clause(p: &mut Parser<'_>) -> Option<Vec<Span>> {
    p.skip_trivia();
    let set = p.tokens.get(p.idx)?;
    if !matches!(set.kind, TokenKind::Keyword(Keyword::Set)) {
        return None;
    }
    let names = |at: usize| {
        p.tokens
            .get(at)
            .is_some_and(|tok| tok.lexeme(p.source).eq_ignore_ascii_case("search_path"))
    };
    let parameter = next_non_trivia_idx(p.tokens, p.idx + 1)?;
    if !names(parameter) {
        return None;
    }
    let assign = next_non_trivia_idx(p.tokens, parameter + 1)?;
    let assigns = p.tokens.get(assign).is_some_and(|tok| {
        matches!(tok.kind, TokenKind::Keyword(Keyword::To)) || tok.lexeme(p.source) == "="
    });
    if !assigns {
        return None;
    }
    let mut entries = Vec::new();
    let mut at = next_non_trivia_idx(p.tokens, assign + 1)?;
    loop {
        let entry = p.tokens.get(at)?;
        let value = matches!(
            entry.kind,
            TokenKind::Identifier { .. } | TokenKind::Literal(LiteralKind::String)
        ) || p.can_be_identifier_token(entry);
        if !value {
            return None;
        }
        entries.push(entry.span);
        match next_non_trivia_idx(p.tokens, at + 1) {
            Some(next)
                if matches!(
                    p.tokens.get(next).map(|tok| &tok.kind),
                    Some(TokenKind::Punctuation(Punctuation::Comma))
                ) =>
            {
                at = next_non_trivia_idx(p.tokens, next + 1)?;
            }
            Some(_) | None => {
                p.idx = at + 1;
                return Some(entries);
            }
        }
    }
}

/// The `RETURNS` clause at the parser's position, if one is written: the
/// return type runs to LANGUAGE, AS, RETURN, a body's BEGIN or an
/// `EXECUTE AS` option.
fn read_returns_clause(p: &mut Parser<'_>) -> Option<AstReturnsClause> {
    let returns_kw = p
        .peek_non_trivia()
        .filter(|tok| tok.kind == TokenKind::Keyword(Keyword::Returns))?;
    let start = returns_kw.span.start;
    let mut end = returns_kw.span.end;
    p.advance();
    let mut first_words: [Option<&Token>; 2] = [None, None];
    while let Some(tok) = p.peek_non_trivia() {
        if matches!(
            tok.kind,
            TokenKind::Keyword(Keyword::Language | Keyword::As | Keyword::Return | Keyword::Begin)
        ) || execute_as_option_at(p.tokens, p.idx, p.source).is_some()
        {
            break;
        }
        let t = p
            .advance()
            .expect_invariant("return type token consumed in CREATE FUNCTION");
        if let Some(slot) = first_words.iter_mut().find(|slot| slot.is_none()) {
            *slot = Some(t);
        }
        end = t.span.end;
    }
    Some(AstReturnsClause {
        span: Span { start, end },
        kind: function_returns(first_words, p.source),
    })
}

/// What a `RETURNS` clause whose first two words are `first_words` says
/// one call returns: `SETOF` is a set; `TABLE`, alone or after a T-SQL
/// table variable, is rows; anything else is one value.
fn function_returns([first, second]: [Option<&Token>; 2], source: &str) -> AstFunctionReturns {
    let is_table = |word: &Token| word.kind == TokenKind::Keyword(Keyword::Table);
    let Some(first) = first else {
        return AstFunctionReturns::Scalar;
    };
    let table_variable = matches!(
        first.kind,
        TokenKind::Identifier {
            kind: crate::lexer::IdentifierKind::AtVariable,
            ..
        }
    );
    if matches!(first.kind, TokenKind::Identifier { .. })
        && first.lexeme(source).eq_ignore_ascii_case("SETOF")
    {
        AstFunctionReturns::Set
    } else if is_table(first) || (table_variable && second.is_some_and(is_table)) {
        AstFunctionReturns::Table
    } else {
        AstFunctionReturns::Scalar
    }
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

    let name_span = p.parse_object_name_span()?;

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
            p.record_option_list_secrets(p.idx);
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
            params: p.read_procedure_params(params_span),
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

    // Target name (possibly qualified)
    p.skip_trivia();
    let name_start = p.idx;
    let target_name = p.parse_object_ref().ok();
    if let Some(name) = &target_name {
        span.end = name.span.end;
    }
    let targets = target_name
        .iter()
        .map(|_| crate::ast::AstDropTarget {
            name: p.object_ref_of_range(name_start, p.idx, p.id_gen.next()),
            signature: None,
            params: Vec::new(),
        })
        .collect();

    Ok(AstStmt::Drop(crate::ast::AstDrop {
        node_id: p.id_gen.next(),
        span,
        keyword_span,
        object_type_span,
        if_exists_span,
        target_name,
        targets,
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
        && p.peek_non_trivia()
            .is_some_and(|t| p.delimits_dollar_quote(t));
    let sql_expr = if dollar_opener {
        let span = take_dollar_words_string(p, p.current_span())?;
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

                        // If we got a colon, expect identifier next
                        let var_end = if matches!(
                            var_tok.kind,
                            TokenKind::Punctuation(crate::lexer::Punctuation::Colon)
                        ) {
                            let _ = p.advance();
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
                            // A variable, or a field of one (PL/pgSQL
                            // `NEW.col`).
                            p.take_name_or_token_span("variable name")?.end
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
    let is_dollar = !p.dialect.supports_dollar_quoted_strings() && p.delimits_dollar_quote(loc_tok);
    let loc_tok_span = loc_tok.span;

    let (location_kind, location_span) = if is_string {
        p.advance()
            .expect_invariant("relative-path string consumed after peek");
        (AstEifLocationKind::RelativePath, loc_tok_span)
    } else if is_dollar {
        // `$$./rel/file.sql$$` relative path in a dialect (Snowflake) whose
        // lexer gives a dollar-quoted string as words, read by the one
        // literal reader up to the word its closing `$$` ends.
        let sp = take_dollar_words_string(p, loc_tok_span)?;
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

/// Consume the dollar-quoted string a lexer gives as words, opened by the
/// next word (`$$`, `$tag$`), through the word its closer ends
/// ([`Parser::one_literal_at`]); returns its span. A string with no closer
/// is an error at `at`: it is not read to the end of the text.
fn take_dollar_words_string(p: &mut Parser<'_>, at: Span) -> ParseResult<Span> {
    use crate::parser::principal::LiteralSpelling;
    let literal = p
        .one_literal_at(p.idx)
        .filter(|literal| literal.spelling == LiteralSpelling::DollarQuoted)
        .ok_or_else(|| {
            ParseError::new(
                at,
                ParseErrorKind::InvalidExpression {
                    message: "A `$$` string is not closed".to_string(),
                },
            )
        })?;
    let span = Span {
        start: p.tokens[literal.first].span.start,
        end: p.tokens[literal.past - 1].span.end,
    };
    p.idx = literal.past;
    Ok(span)
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
    // A first token that is no name is left where it stands: the statement
    // has no name to span.
    let Some(procedure_name_span) = p.take_name_span(crate::parser::core::NamePosition::Object)
    else {
        return Err(ParseError::new(
            first_name.span,
            ParseErrorKind::InvalidStatement {
                message: "CALL requires procedure name".to_string(),
            },
        ));
    };

    let mut end = procedure_name_span.end;
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

                // Named-arg detection: `@name =`, `name =>`, or PostgreSQL's
                // older `name :=` (the lexer reads `=>` and `:=` as one
                // token each).
                let mut name_id: Option<crate::ast::AstIdentifier> = None;
                let mut name_op_span: Option<Span> = None;
                let is_at_var = matches!(
                    peek.kind,
                    TokenKind::Identifier {
                        kind: crate::lexer::IdentifierKind::AtVariable,
                        ..
                    }
                );
                let is_name = !is_at_var && p.can_be_identifier_token(peek);
                if is_at_var || is_name {
                    let name_span_candidate = peek.span;
                    let _ = p.advance();
                    let operator = p.peek().map(|next| (next.kind.clone(), next.span));
                    let named = match operator {
                        Some((TokenKind::Operator(crate::lexer::Operator::Eq), op_span))
                            if is_at_var =>
                        {
                            Some((crate::ast::AstIdentifierKind::Variable, op_span))
                        }
                        Some((
                            TokenKind::Operator(
                                crate::lexer::Operator::EqGt | crate::lexer::Operator::ColonEq,
                            ),
                            op_span,
                        )) if is_name => Some((crate::ast::AstIdentifierKind::Name, op_span)),
                        Some(_) | None => None,
                    };
                    match named {
                        Some((kind, op_span)) => {
                            let _ = p.advance();
                            name_id = Some(crate::ast::AstIdentifier {
                                node_id: p.id_gen.next(),
                                span: name_span_candidate,
                                kind,
                                templated: None,
                            });
                            name_op_span = Some(op_span);
                        }
                        None => p.idx = saved_idx,
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

    // Optional WORK or TRANSACTION keyword; T-SQL's `TRAN` and `DISTRIBUTED
    // { TRAN | TRANSACTION }`.
    let mut after_tran = false;
    if let Some(past) = p.any_words_end(
        p.idx,
        &[
            &["DISTRIBUTED", "TRANSACTION"],
            &["DISTRIBUTED", "TRAN"],
            &["TRAN"],
        ],
    ) {
        end = p.tokens[past - 1].span.end;
        p.idx = past;
        after_tran = true;
    } else if let Some(tok) = p.peek_non_trivia() {
        if matches!(tok.kind, TokenKind::Keyword(Keyword::Work))
            || matches!(tok.kind, TokenKind::Keyword(Keyword::Transaction))
        {
            after_tran = matches!(tok.kind, TokenKind::Keyword(Keyword::Transaction));
            let kw = p
                .advance()
                .expect_invariant("WORK/TRANSACTION keyword consumed in BEGIN TRANSACTION");
            end = kw.span.end;
            p.skip_trivia();
        }
    }
    end = consume_tsql_transaction_tail(p, end, after_tran);

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
        characteristics: Vec::new(),
    })
}

/// Reads T-SQL's tail of a `BEGIN`, `COMMIT` or `ROLLBACK` of a transaction,
/// where terminators are optional: the transaction's (or savepoint's) name
/// or a variable holding it, which T-SQL writes only after `TRAN` /
/// `TRANSACTION` (`after_tran`), then `WITH MARK ['description']` or `WITH
/// (DELAYED_DURABILITY = …)`. A reserved word, a word that starts a
/// statement and a label (`name:`) are no name. Returns the end of what it
/// read, `end` if nothing.
fn consume_tsql_transaction_tail(p: &mut Parser<'_>, mut end: u32, after_tran: bool) -> u32 {
    if !p.dialect.uses_optional_statement_terminators() {
        return end;
    }
    let names_transaction = after_tran
        && p.peek_non_trivia().is_some_and(|tok| {
            let reserved = matches!(
                tok.kind,
                TokenKind::Identifier {
                    kind: crate::lexer::IdentifierKind::Unquoted,
                    ..
                }
            ) && p.dialect.is_reserved_keyword(tok.lexeme(p.source));
            matches!(tok.kind, TokenKind::Identifier { .. })
                && !reserved
                && !p.should_stop_scan_at_statement_start(tok)
                && !is_mssql_label_at(p, p.idx)
        });
    if names_transaction {
        end = p.advance().expect_invariant("name after peek").span.end;
    }
    let with_end = p
        .words_end(p.idx, &["WITH", "MARK"])
        .map(|k| {
            let described = p.tokens.get(k).is_some_and(|t| {
                matches!(
                    t.kind,
                    TokenKind::Literal(crate::lexer::LiteralKind::String)
                )
            });
            k + usize::from(described)
        })
        .or_else(|| p.words_end(p.idx, &["WITH"]).and_then(|k| p.parens_end(k)));
    if let Some(past) = with_end {
        end = p.tokens[past - 1].span.end;
        p.idx = past;
    }
    end
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

    // MySQL's characteristics, comma-separated.
    const CHARACTERISTICS: &[&[&str]] = &[
        &["WITH", "CONSISTENT", "SNAPSHOT"],
        &["READ", "WRITE"],
        &["READ", "ONLY"],
    ];
    let mut characteristics = Vec::new();
    while let Some(after) = p.any_words_end(p.idx, CHARACTERISTICS) {
        let span = Span {
            start: p.tokens[p.idx].span.start,
            end: p.tokens[after - 1].span.end,
        };
        characteristics.push(span);
        end = span.end;
        p.idx = after;
        let more = p
            .tokens
            .get(p.idx)
            .is_some_and(|t| matches!(t.kind, TokenKind::Punctuation(Punctuation::Comma)))
            && p.any_words_end(p.idx + 1, CHARACTERISTICS).is_some();
        if !more {
            break;
        }
        p.idx += 1;
    }

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
        characteristics,
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

    // Optional WORK or TRANSACTION keyword, or T-SQL's `TRAN`.
    let mut after_tran = false;
    if let Some(tok) = p.peek_non_trivia() {
        after_tran = matches!(tok.kind, TokenKind::Keyword(Keyword::Transaction))
            || p.word_at(p.idx, "TRAN");
        if after_tran || matches!(tok.kind, TokenKind::Keyword(Keyword::Work)) {
            let kw = p
                .advance()
                .expect_invariant("WORK/TRANSACTION keyword consumed after match in COMMIT");
            end = kw.span.end;
        }
    }
    end = consume_tsql_transaction_tail(p, end, after_tran);

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

    // Optional WORK or TRANSACTION keyword, or T-SQL's `TRAN`.
    let mut after_tran = false;
    if let Some(tok) = p.peek_non_trivia() {
        after_tran = matches!(tok.kind, TokenKind::Keyword(Keyword::Transaction))
            || p.word_at(p.idx, "TRAN");
        if after_tran || matches!(tok.kind, TokenKind::Keyword(Keyword::Work)) {
            let kw = p
                .advance()
                .expect_invariant("WORK/TRANSACTION keyword consumed after match in ROLLBACK");
            end = kw.span.end;
        }
    }
    // `TO [SAVEPOINT] name` (PostgreSQL, MySQL): back to a savepoint.
    let to_savepoint = p.is_word(p.peek(), "TO") && {
        let name_at = if p.is_word(p.peek_ahead(1), "SAVEPOINT") {
            2
        } else {
            1
        };
        p.peek_ahead(name_at)
            .is_some_and(|name| p.can_be_identifier_token(name))
    };
    if to_savepoint {
        p.advance();
        if p.is_word(p.peek(), "SAVEPOINT") {
            p.advance();
        }
        if let Some(name) = p.advance() {
            end = name.span.end;
        }
    } else {
        end = consume_tsql_transaction_tail(p, end, after_tran);
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

/// Whether a savepoint statement starts at the current token: `SAVEPOINT
/// name`, T-SQL `SAVE { TRAN | TRANSACTION } name`, or `RELEASE [SAVEPOINT]
/// name`, the name a name or an `@variable`.
pub(crate) fn is_savepoint_stmt_at(p: &Parser<'_>) -> bool {
    let name_at = |at: usize| {
        p.peek_ahead(at)
            .is_some_and(|name| p.can_be_identifier_token(name))
    };
    let first = p.peek();
    if p.is_word(first, "SAVEPOINT") {
        return name_at(1);
    }
    if p.is_word(first, "SAVE") {
        return (p.is_word(p.peek_ahead(1), "TRAN") || p.is_word(p.peek_ahead(1), "TRANSACTION"))
            && name_at(2);
    }
    if p.is_word(first, "RELEASE") {
        return if p.is_word(p.peek_ahead(1), "SAVEPOINT") {
            name_at(2)
        } else {
            name_at(1)
        };
    }
    false
}

/// A savepoint statement at the current token ([`is_savepoint_stmt_at`]).
pub(crate) fn try_parse_savepoint_stmt(p: &mut Parser<'_>) -> ParseResult<AstStmt> {
    let first = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["SAVEPOINT".to_string()])?;
    let start = first.span.start;
    let action = if first.lexeme(p.source).eq_ignore_ascii_case("RELEASE") {
        crate::ast::AstSavepointAction::Release
    } else {
        crate::ast::AstSavepointAction::Set
    };
    let mut keyword_end = first.span.end;
    let after_first = if first.lexeme(p.source).eq_ignore_ascii_case("SAVE") {
        Some("TRAN")
    } else if matches!(action, crate::ast::AstSavepointAction::Release) {
        Some("SAVEPOINT")
    } else {
        None
    };
    if let Some(word) = after_first {
        let second = p.peek();
        if p.is_word(second, word) || (word == "TRAN" && p.is_word(second, "TRANSACTION")) {
            if let Some(tok) = p.advance() {
                keyword_end = tok.span.end;
            }
        }
    }
    let name_tok = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["savepoint name".to_string()])?;
    if !p.can_be_identifier_token(name_tok) {
        return Err(ParseError::unexpected_token(
            name_tok.span,
            vec!["savepoint name".to_string()],
            Parser::token_description(name_tok, p.source),
        ));
    }
    Ok(AstStmt::Savepoint(Box::new(crate::ast::AstSavepoint {
        node_id: p.id_gen.next(),
        span: Span {
            start,
            end: name_tok.span.end,
        },
        action,
        keyword_span: Span {
            start,
            end: keyword_end,
        },
        name: AstIdentifier {
            node_id: p.id_gen.next(),
            span: name_tok.span,
            kind: crate::ast::AstIdentifierKind::of(&name_tok.kind),
            templated: None,
        },
    })))
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

/// One item of a block's declaration section, starting at `first`. An item
/// that does not parse is an `AstStmt::Error` over the whole declaration,
/// its `;` included, as a statement of a block's body is, and the section
/// goes on.
fn read_declaration_item(p: &mut Parser<'_>, first: &Token) -> AstStmt {
    let start_idx = p.idx;
    let bound = declaration_bound(p);
    // An item never reads past the `BEGIN` that ends the section.
    let parsed = try_parse_declare_stmt(p).and_then(|stmt| match p.tokens.get(bound) {
        Some(begin)
            if p.idx > bound && matches!(begin.kind, TokenKind::Keyword(Keyword::Begin)) =>
        {
            Err(ParseError::new(
                begin.span,
                ParseErrorKind::InvalidStatement {
                    message: "Expected `;` before the BEGIN that ends the declarations".to_string(),
                },
            ))
        }
        Some(_) | None => Ok(stmt),
    });
    match parsed {
        Ok(stmt) => stmt,
        Err(err) => {
            p.idx = bound;
            create_error_and_sync(p, first.span.start, start_idx, &err, &[]).0
        }
    }
}

/// Result-based parser for DECLARE...BEGIN...END blocks.
pub(crate) fn try_parse_scripting_block(p: &mut Parser<'_>) -> ParseResult<AstStmt> {
    try_parse_scripting_block_with_label(p, None).map(DeclareSection::into_stmt)
}

/// What a `DECLARE` section starts.
enum DeclareSection {
    /// `DECLARE … BEGIN … END`.
    Block(Box<AstBlockStmt>),
    /// A condition or handler declaration, a statement of its own.
    Standalone(AstStmt),
}

impl DeclareSection {
    fn into_stmt(self) -> AstStmt {
        match self {
            DeclareSection::Block(block) => AstStmt::Block(block),
            DeclareSection::Standalone(stmt) => stmt,
        }
    }
}

/// A `DECLARE … BEGIN … END` block written after the label `label`.
fn labelled_declare_block(p: &mut Parser<'_>, label: Span) -> ParseResult<AstStmt> {
    match try_parse_scripting_block_with_label(p, Some(label))? {
        DeclareSection::Block(block) => Ok(AstStmt::Block(block)),
        DeclareSection::Standalone(stmt) => Err(ParseError::new(
            stmt.span(),
            ParseErrorKind::InvalidStatement {
                message: "Expected a block after label".to_string(),
            },
        )),
    }
}

/// [`try_parse_scripting_block`] for a block written after `label`.
fn try_parse_scripting_block_with_label(
    p: &mut Parser<'_>,
    label: Option<Span>,
) -> ParseResult<DeclareSection> {
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
                let decl_stmt = read_declaration_item(p, tok);
                // Standalone declaration types (CONDITION, HANDLER) are complete
                // statements — they don't form a preamble before BEGIN.
                if matches!(
                    &decl_stmt,
                    AstStmt::DeclareCondition { .. } | AstStmt::DeclareHandler(_)
                ) {
                    p.restore_mode(prev_mode);
                    return Ok(DeclareSection::Standalone(decl_stmt));
                }
                decls.push(decl_stmt);
            }
            // In a multi-line DECLARE header, subsequent variable declarations
            // start with bare identifiers on their own lines.
            TokenKind::Identifier { .. } => {
                let decl_stmt = read_declaration_item(p, tok);
                if matches!(
                    &decl_stmt,
                    AstStmt::DeclareCondition { .. } | AstStmt::DeclareHandler(_)
                ) {
                    p.restore_mode(prev_mode);
                    return Ok(DeclareSection::Standalone(decl_stmt));
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

    let block_stmt = try_parse_block_stmt_with_label(p, label)?;

    // Restore previous parser mode
    p.restore_mode(prev_mode);

    match block_stmt {
        AstStmt::Block(b) => {
            let label_span = b.label_span;
            let end_label_span = b.end_label_span;
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
                        start: label_span.map_or(first_decl.span().start, |l| l.start),
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

            Ok(DeclareSection::Block(Box::new(AstBlockStmt {
                node_id: p.id_gen.next(),
                span: adjusted_span,
                label_span,
                end_label_span,
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

            // T-SQL's `BEGIN TRAN` / `BEGIN DISTRIBUTED TRAN[SACTION]`.
            if p.any_words_end(p.idx + 1, &[&["TRAN"], &["DISTRIBUTED"]])
                .is_some()
            {
                return p.try_parse_begin_transaction_stmt();
            }
            match next_kind {
                Some(TokenKind::Keyword(Keyword::Try)) => try_parse_mssql_try_catch(p),
                Some(TokenKind::Keyword(Keyword::Transaction))
                | Some(TokenKind::Keyword(Keyword::Work)) => p.try_parse_begin_transaction_stmt(),
                _ => try_parse_block_stmt(p),
            }
        }
        // Nested control flow
        TokenKind::Keyword(Keyword::If) => try_parse_mssql_if(p),
        TokenKind::Keyword(Keyword::While) => try_parse_mssql_while(p, None),
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
    // A trigger's `UPDATE(col)` predicate is an operand the expression
    // reader reads (`IF UPDATE(a) AND EXISTS (…)`).
    let cond_expr = try_parse_expr_scripting(p).map_err(|_| {
        ParseError::invalid_expression(
            p.current_span(),
            "MSSQL IF requires a condition expression".to_string(),
        )
    })?;
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
        condition: Box::new(cond_expr),
        then_body,
        else_span,
        else_body,
    })))
}

// ════════════════════════════════════════════════════════════════════════════
// MSSQL-style WHILE  (no DO / END WHILE)
// ════════════════════════════════════════════════════════════════════════════

/// Parse MSSQL `WHILE condition statement`, after `label_span` where a
/// label is written before it.
///
/// Unlike Snowflake's `WHILE...DO...END WHILE`, T-SQL WHILE uses:
/// - No DO keyword after the condition
/// - No END WHILE terminator
/// - The body is exactly **one** statement (use `BEGIN...END` for blocks)
pub(crate) fn try_parse_mssql_while(
    p: &mut Parser<'_>,
    label_span: Option<Span>,
) -> ParseResult<AstStmt> {
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
    p.while_body_depth += 1;
    let body_stmt = parse_mssql_body_statement(p);
    p.while_body_depth -= 1;
    let body_stmt = body_stmt?;
    let end = body_stmt.span().end;
    let body = vec![body_stmt];

    let stmt_span = Span {
        start: label_span.map_or(while_span.start, |label| label.start),
        end,
    };

    Ok(AstStmt::MssqlWhile(Box::new(crate::ast::AstMssqlWhile {
        node_id: p.id_gen.next(),
        span: stmt_span,
        label_span,
        while_span,
        condition_span,
        condition: Box::new(cond_expr),
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

/// The index past the T-SQL server command at `i` ([`AstStmt::MssqlServerCommand`]);
/// `None` where none is written there.
pub(crate) fn mssql_server_command_end(p: &Parser<'_>, i: usize) -> Option<usize> {
    let literal_at = |at: usize, kinds: &[crate::lexer::LiteralKind]| {
        p.tokens
            .get(at)
            .is_some_and(|t| matches!(&t.kind, TokenKind::Literal(kind) if kinds.contains(kind)))
    };
    let number = [crate::lexer::LiteralKind::Number];
    let head = p.tokens.get(i)?;
    if !p.dialect.is_reserved_keyword(head.lexeme(p.source)) {
        return None;
    }
    if p.word_at(i, "CHECKPOINT") {
        return Some(if literal_at(i + 1, &number) {
            i + 2
        } else {
            i + 1
        });
    }
    if p.word_at(i, "SHUTDOWN") {
        return Some(p.words_end(i + 1, &["WITH", "NOWAIT"]).unwrap_or(i + 1));
    }
    if !p.word_at(i, "KILL") {
        return None;
    }
    if let Some(at) = p.words_end(i + 1, &["QUERY", "NOTIFICATION", "SUBSCRIPTION"]) {
        return (p.word_at(at, "ALL") || literal_at(at, &number)).then_some(at + 1);
    }
    if let Some(at) = p.words_end(i + 1, &["STATS", "JOB"]) {
        return literal_at(at, &number).then_some(at + 1);
    }
    let id = [
        crate::lexer::LiteralKind::Number,
        crate::lexer::LiteralKind::String,
    ];
    if !literal_at(i + 1, &id) {
        return None;
    }
    Some(
        p.any_words_end(
            i + 2,
            &[
                &["WITH", "STATUSONLY"],
                &["WITH", "COMMIT"],
                &["WITH", "ROLLBACK"],
            ],
        )
        .unwrap_or(i + 2),
    )
}

/// Parse a T-SQL server command (`CHECKPOINT`, `KILL`, `SHUTDOWN`), kept
/// as written.
pub(crate) fn try_parse_mssql_server_command(p: &mut Parser<'_>) -> ParseResult<AstStmt> {
    let start = p.idx;
    let (Some(end), Some(first)) = (mssql_server_command_end(p, start), p.tokens.get(start)) else {
        return Err(ParseError::new(
            p.current_span(),
            ParseErrorKind::InvalidStatement {
                message: "Expected CHECKPOINT, KILL or SHUTDOWN".to_string(),
            },
        ));
    };
    let last = p.tokens.get(end - 1).map_or(first.span.end, |t| t.span.end);
    let span = Span {
        start: first.span.start,
        end: last,
    };
    p.idx = end;
    Ok(AstStmt::MssqlServerCommand {
        node_id: p.id_gen.next(),
        span,
    })
}

/// The MySQL administration statement at `i` and the index past it
/// ([`AstStmt::MysqlAdmin`]); `None` where none is written there, or where
/// its shape does not end the statement.
pub(crate) fn mysql_admin_at(
    p: &Parser<'_>,
    i: usize,
) -> Option<(crate::ast::AstMysqlAdminKind, usize)> {
    let (kind, end) = mysql_admin_shape(p, i)?;
    p.tokens
        .get(end)
        .is_none_or(|t| {
            matches!(
                t.kind,
                TokenKind::Punctuation(Punctuation::Semi) | TokenKind::Eof
            )
        })
        .then_some((kind, end))
}

fn mysql_admin_shape(p: &Parser<'_>, i: usize) -> Option<(crate::ast::AstMysqlAdminKind, usize)> {
    use crate::ast::{AstMysqlAdminKind as K, AstMysqlTableOperation as Op};
    let span_of = |from: usize, to: usize| Span {
        start: p.tokens[from].span.start,
        end: p.tokens[to - 1].span.end,
    };
    let comma_at = |at: usize| {
        p.tokens
            .get(at)
            .is_some_and(|t| matches!(t.kind, TokenKind::Punctuation(Punctuation::Comma)))
    };
    // `name, …`, each name's span.
    let names = |mut at: usize| {
        let mut spans = Vec::new();
        loop {
            let end = p.object_name_end(at)?;
            spans.push(span_of(at, end));
            if !comma_at(end) {
                return Some((spans, end));
            }
            at = end + 1;
        }
    };
    let binlog = |at: usize| {
        p.any_words_end(at, &[&["NO_WRITE_TO_BINLOG"], &["LOCAL"]])
            .unwrap_or(at)
    };
    let channel = |at: usize| {
        p.words_end(at, &["FOR", "CHANNEL"])
            .filter(|&name| p.is_word_at(name))
            .map_or(at, |name| name + 1)
    };

    let operations = [
        ("ANALYZE", Op::Analyze),
        ("OPTIMIZE", Op::Optimize),
        ("CHECK", Op::Check),
        ("CHECKSUM", Op::Checksum),
        ("REPAIR", Op::Repair),
    ];
    if let Some(&(_, operation)) = operations.iter().find(|(word, _)| p.word_at(i, word)) {
        let table_word = binlog(i + 1);
        let at = p.any_words_end(table_word, &[&["TABLE"], &["TABLES"]])?;
        let (tables, options_start) = names(at)?;
        let mut end = options_start;
        match operation {
            Op::Analyze => {
                if let Some(on) = p.any_words_end(
                    end,
                    &[&["UPDATE", "HISTOGRAM", "ON"], &["DROP", "HISTOGRAM", "ON"]],
                ) {
                    end = names(on)?.1;
                    let buckets = p.words_end(end, &["WITH"]).filter(|&n| {
                        p.tokens.get(n).is_some_and(|t| {
                            matches!(t.kind, TokenKind::Literal(LiteralKind::Number))
                        }) && p.word_at(n + 1, "BUCKETS")
                    });
                    end = buckets.map_or(end, |n| n + 2);
                    end = p
                        .any_words_end(end, &[&["AUTO", "UPDATE"], &["MANUAL", "UPDATE"]])
                        .unwrap_or(end);
                    let data = p.words_end(end, &["USING", "DATA"]).filter(|&d| {
                        p.tokens
                            .get(d)
                            .is_some_and(|t| matches!(t.kind, TokenKind::Literal(_)))
                    });
                    end = data.map_or(end, |d| d + 1);
                }
            }
            Op::Check => {
                while let Some(next) = p.any_words_end(
                    end,
                    &[
                        &["FOR", "UPGRADE"],
                        &["QUICK"],
                        &["FAST"],
                        &["MEDIUM"],
                        &["EXTENDED"],
                        &["CHANGED"],
                    ],
                ) {
                    end = next;
                }
            }
            Op::Checksum => {
                end = p
                    .any_words_end(end, &[&["QUICK"], &["EXTENDED"]])
                    .unwrap_or(end);
            }
            Op::Repair => {
                while let Some(next) =
                    p.any_words_end(end, &[&["QUICK"], &["EXTENDED"], &["USE_FRM"]])
                {
                    end = next;
                }
                // The bare `REPAIR TABLE t` is Databricks' REPAIR TABLE too,
                // whose reader keeps it.
                if table_word == i + 1 && tables.len() == 1 && end == options_start {
                    return None;
                }
            }
            Op::Optimize => {}
        }
        let options_span = (end > options_start).then(|| span_of(options_start, end));
        return Some((
            K::TableMaintenance {
                operation,
                tables,
                options_span,
            },
            end,
        ));
    }

    if p.word_at(i, "FLUSH") {
        let at = binlog(i + 1);
        if let Some(listed) = p.any_words_end(at, &[&["TABLES"], &["TABLE"]]) {
            let lock =
                |at: usize| p.any_words_end(at, &[&["WITH", "READ", "LOCK"], &["FOR", "EXPORT"]]);
            let (tables, end) = match lock(listed) {
                Some(end) => (Vec::new(), end),
                None => match names(listed) {
                    Some((tables, end)) => (tables, lock(end).unwrap_or(end)),
                    None => (Vec::new(), listed),
                },
            };
            return Some((K::Flush { tables }, end));
        }
        const OPTIONS: &[&[&str]] = &[
            &["BINARY", "LOGS"],
            &["ENGINE", "LOGS"],
            &["ERROR", "LOGS"],
            &["GENERAL", "LOGS"],
            &["RELAY", "LOGS"],
            &["SLOW", "LOGS"],
            &["HOSTS"],
            &["LOGS"],
            &["PRIVILEGES"],
            &["OPTIMIZER_COSTS"],
            &["STATUS"],
            &["USER_RESOURCES"],
        ];
        let end = p.comma_list_end(at, |option| p.any_words_end(option, OPTIONS).map(channel))?;
        return Some((K::Flush { tables: Vec::new() }, end));
    }

    if p.word_at(i, "KILL") {
        let named = p.any_words_end(i + 1, &[&["CONNECTION"], &["QUERY"]]);
        let id = named.unwrap_or(i + 1);
        // A literal id alone is T-SQL's server command.
        let literal = p
            .tokens
            .get(id)
            .is_some_and(|t| matches!(t.kind, TokenKind::Literal(_)));
        if named.is_none() && literal {
            return None;
        }
        let end = p.option_value_end(id)?;
        let end = p.parens_end(end).unwrap_or(end);
        return Some((
            K::Kill {
                id: span_of(id, end),
            },
            end,
        ));
    }

    if p.words_end(i, &["ALTER", "INSTANCE"]).is_some() {
        let end = p.any_words_end(
            i + 2,
            &[
                &["ENABLE", "INNODB", "REDO_LOG"],
                &["DISABLE", "INNODB", "REDO_LOG"],
                &["ROTATE", "INNODB", "MASTER", "KEY"],
                &["ROTATE", "BINLOG", "MASTER", "KEY"],
                &["RELOAD", "KEYRING"],
                &["RELOAD", "TLS"],
            ],
        )?;
        let end = channel(end);
        let end = p
            .words_end(end, &["NO", "ROLLBACK", "ON", "ERROR"])
            .unwrap_or(end);
        return Some((K::AlterInstance, end));
    }

    if p.word_at(i, "XA") {
        // `gtrid [, bqual [, formatID]]`.
        let xid = |at: usize| {
            p.comma_list_end(at, |part| {
                p.tokens
                    .get(part)
                    .is_some_and(|t| matches!(t.kind, TokenKind::Literal(_)))
                    .then_some(part + 1)
            })
        };
        let end = if let Some(at) = p.any_words_end(i + 1, &[&["START"], &["BEGIN"]]) {
            let end = xid(at)?;
            p.any_words_end(end, &[&["JOIN"], &["RESUME"]])
                .unwrap_or(end)
        } else if let Some(at) = p.words_end(i + 1, &["END"]) {
            let end = xid(at)?;
            p.any_words_end(end, &[&["SUSPEND", "FOR", "MIGRATE"], &["SUSPEND"]])
                .unwrap_or(end)
        } else if let Some(at) = p.words_end(i + 1, &["COMMIT"]) {
            let end = xid(at)?;
            p.words_end(end, &["ONE", "PHASE"]).unwrap_or(end)
        } else if let Some(at) = p.any_words_end(i + 1, &[&["PREPARE"], &["ROLLBACK"]]) {
            xid(at)?
        } else {
            let at = p.words_end(i + 1, &["RECOVER"])?;
            p.words_end(at, &["CONVERT", "XID"]).unwrap_or(at)
        };
        return Some((K::Xa, end));
    }

    if p.words_end(i, &["RENAME", "USER"]).is_some() {
        let mut renames = Vec::new();
        let mut at = i + 2;
        loop {
            let from_end = p.mysql_principal_end(at)?;
            let to = p.words_end(from_end, &["TO"])?;
            let to_end = p.mysql_principal_end(to)?;
            renames.push(crate::ast::AstMysqlUserRename {
                from: span_of(at, from_end),
                to: span_of(to, to_end),
            });
            if !comma_at(to_end) {
                return Some((K::RenameUser { renames }, to_end));
            }
            at = to_end + 1;
        }
    }
    None
}

/// Parse the MySQL administration statement [`mysql_admin_at`] recognises.
pub(crate) fn try_parse_mysql_admin(p: &mut Parser<'_>) -> ParseResult<AstStmt> {
    let start = p.idx;
    let Some((kind, end)) = mysql_admin_at(p, start) else {
        return Err(ParseError::new(
            p.current_span(),
            ParseErrorKind::InvalidStatement {
                message: "Expected a MySQL administration statement".to_string(),
            },
        ));
    };
    let span = Span {
        start: p.tokens[start].span.start,
        end: p.tokens[end - 1].span.end,
    };
    p.idx = end;
    Ok(AstStmt::MysqlAdmin(Box::new(crate::ast::AstMysqlAdmin {
        node_id: p.id_gen.next(),
        span,
        kind,
    })))
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
// MSSQL ENABLE / DISABLE TRIGGER
// ════════════════════════════════════════════════════════════════════════════

/// Whether the statement at `idx` is T-SQL's `{ ENABLE | DISABLE } TRIGGER`:
/// the word, then `TRIGGER`.
pub(crate) fn is_mssql_trigger_state_at(p: &Parser<'_>, idx: usize) -> bool {
    (p.word_at(idx, "ENABLE") || p.word_at(idx, "DISABLE"))
        && p.tokens
            .get(idx + 1)
            .is_some_and(|t| matches!(t.kind, TokenKind::Keyword(Keyword::Trigger)))
}

/// Parse T-SQL `{ ENABLE | DISABLE } TRIGGER { name [, …] | ALL } ON
/// { object | DATABASE | ALL SERVER }`. The statement ends with its scope.
pub(crate) fn try_parse_mssql_trigger_state(p: &mut Parser<'_>) -> ParseResult<AstStmt> {
    use crate::ast::types::{MssqlTriggerList, MssqlTriggerScope, MssqlTriggerStateAction};
    let _depth = p.track_depth("mssql_trigger_state")?;

    let action_tok = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["ENABLE or DISABLE".to_string()])?;
    let action = if action_tok.lexeme(p.source).eq_ignore_ascii_case("ENABLE") {
        MssqlTriggerStateAction::Enable
    } else {
        MssqlTriggerStateAction::Disable
    };
    p.advance()
        .ok_or_eof(p.current_span(), vec!["TRIGGER".to_string()])?;

    let triggers = if p
        .peek_non_trivia()
        .is_some_and(|t| matches!(t.kind, TokenKind::Keyword(Keyword::All)))
    {
        p.advance();
        MssqlTriggerList::All
    } else {
        let mut names = vec![p.parse_object_ref()?];
        while p
            .peek_non_trivia()
            .is_some_and(|t| matches!(t.kind, TokenKind::Punctuation(Punctuation::Comma)))
        {
            p.advance();
            names.push(p.parse_object_ref()?);
        }
        MssqlTriggerList::Named(names)
    };

    match p.peek_non_trivia() {
        Some(t) if matches!(t.kind, TokenKind::Keyword(Keyword::On)) => {
            p.advance();
        }
        Some(t) => {
            return Err(ParseError::unexpected_token(
                t.span,
                vec!["ON".to_string()],
                t.lexeme(p.source).to_string(),
            ))
        }
        None => {
            return Err(ParseError::unexpected_eof(
                p.current_span(),
                vec!["ON".to_string()],
            ))
        }
    }

    p.skip_trivia();
    let at = p.idx;
    let dot_at = |i: usize| {
        p.tokens
            .get(i)
            .is_some_and(|t| matches!(t.kind, TokenKind::Punctuation(Punctuation::Dot)))
    };
    let all_server = p
        .tokens
        .get(at)
        .is_some_and(|t| matches!(t.kind, TokenKind::Keyword(Keyword::All)))
        && p.word_at(at + 1, "SERVER");
    let database = p.word_at(at, "DATABASE") && !dot_at(at + 1);
    let (scope, end) = if all_server {
        p.advance();
        let server = p
            .advance()
            .ok_or_eof(p.current_span(), vec!["SERVER".to_string()])?;
        (MssqlTriggerScope::AllServer, server.span.end)
    } else if database {
        let database = p
            .advance()
            .ok_or_eof(p.current_span(), vec!["DATABASE".to_string()])?;
        (MssqlTriggerScope::Database, database.span.end)
    } else {
        let object = p.parse_object_ref()?;
        let end = object.span.end;
        (MssqlTriggerScope::Object(object), end)
    };

    Ok(AstStmt::MssqlTriggerState(Box::new(
        crate::ast::types::AstMssqlTriggerState {
            node_id: p.id_gen.next(),
            span: Span {
                start: action_tok.span.start,
                end,
            },
            action,
            triggers,
            scope,
        },
    )))
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

    // CREATE, or the ALTER of `ALTER TRIGGER`, which restates the definition
    let create_tok = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["CREATE".to_string()])?;
    if !matches!(
        create_tok.kind,
        TokenKind::Keyword(Keyword::Create) | TokenKind::Keyword(Keyword::Alter)
    ) {
        return Err(ParseError::unexpected_token(
            create_tok.span,
            vec!["CREATE".to_string(), "ALTER".to_string()],
            Parser::token_description(create_tok, p.source),
        ));
    }
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
    let verb = definition_verb(create_tok, or_alter_span);

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
    let name_span = p.parse_object_name_span()?;

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
    p.skip_trivia();
    let at = p.idx;
    // A database or server trigger fires on DDL and logon events, a
    // table's or a view's on rows written.
    let server_scope = p.word_at(at, "ALL") || p.word_at(at, "DATABASE");
    let target_span = if server_scope {
        let first = p
            .advance()
            .ok_or_eof(p.current_span(), vec!["trigger target".to_string()])?;
        let mut target_end = first.span.end;
        if p.word_at(at, "ALL") && p.word_at(at + 1, "SERVER") {
            let server = p
                .advance()
                .ok_or_eof(p.current_span(), vec!["SERVER".to_string()])?;
            target_end = server.span.end;
        }
        Span {
            start: first.span.start,
            end: target_end,
        }
    } else {
        p.parse_object_name_span()?
    };

    // `WITH <option> [, …]` before the timing: ENCRYPTION, EXECUTE AS …,
    // SCHEMABINDING, NATIVE_COMPILATION.
    let mut options_span = None;
    let mut execute_as_mode = None;
    if matches!(
        p.peek_non_trivia().map(|t| &t.kind),
        Some(TokenKind::Keyword(Keyword::With))
    ) {
        let with = p.advance().expect_invariant("WITH after peek").span;
        loop {
            match take_execute_as_option(p) {
                Some(mode) => execute_as_mode = execute_as_mode.or(mode),
                None => {
                    p.advance()
                        .ok_or_eof(p.current_span(), vec!["trigger option".to_string()])?;
                }
            }
            if matches!(
                p.peek_non_trivia().map(|t| &t.kind),
                Some(TokenKind::Punctuation(crate::lexer::Punctuation::Comma))
            ) {
                p.advance();
                continue;
            }
            break;
        }
        options_span = Some(Span {
            start: with.start,
            end: p.consumed_end().unwrap_or(with.end),
        });
    }

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
    use crate::ast::types::MssqlTriggerEvent;
    // Each event of a table's or a view's trigger is `INSERT`, `UPDATE` or
    // `DELETE`; each of a database or server trigger is a named event.
    let source = p.source;
    let event_of = |token: &Token| -> ParseResult<MssqlTriggerEvent> {
        if server_scope {
            return Ok(MssqlTriggerEvent::Named);
        }
        [
            (Keyword::Insert, MssqlTriggerEvent::Insert),
            (Keyword::Update, MssqlTriggerEvent::Update),
            (Keyword::Delete, MssqlTriggerEvent::Delete),
        ]
        .into_iter()
        .find(|(keyword, _)| token.kind == TokenKind::Keyword(*keyword))
        .map(|(_, event)| event)
        .ok_or_else(|| {
            ParseError::new(
                token.span,
                ParseErrorKind::InvalidStatement {
                    message: format!(
                        "Expected INSERT, UPDATE or DELETE, found '{}'",
                        Parser::token_description(token, source)
                    ),
                },
            )
        })
    };
    let mut events = vec![event_of(event_first)?];
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
        events.push(event_of(ev)?);
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
            verb,
            or_alter_span,
            name_span,
            target_span,
            options_span,
            execute_as_mode,
            timing_span,
            events_span,
            events,
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

    // The tokens this read stands at; where it fails, a read from any of
    // them fails alike.
    let state = ReadState::of(p).in_block();
    let mut read_from = Vec::new();
    let mut _body_loop_iter = 0;
    // The statement last read, until a `;` ends it: text after it that
    // starts no statement and does not parse is its unread tail.
    let mut unterminated: Option<crate::ast::NodeId> = None;
    let failure = loop {
        _body_loop_iter += 1;
        p.skip_trivia();
        if let Some(failure) = p.failed_reads.reached(state.at(p.idx, Read::BlockBody)) {
            break failure;
        }
        read_from.push(p.idx);
        let tok = match p.peek_non_trivia() {
            Some(t) => t,
            None => {
                // If we exit the loop without finding END, that's an error
                let eof = ParseError::new(
                    p.current_span(),
                    ParseErrorKind::UnexpectedEof {
                        expected: vec!["END keyword to close BEGIN block".to_string()],
                    },
                );
                break p.failed_reads.fail(p.idx, eof);
            }
        };
        let before = unterminated.take();
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
                // `$$ LANGUAGE plpgsql` round-trip). Where terminators are
                // optional (T-SQL, whose blocks take no label) the word after
                // `END` starts the next statement or is the batch separator.
                // The block's own label closes it whatever word it is.
                let label_name = label_span.and_then(|ls| {
                    let at = p.tokens.partition_point(|t| t.span.start < ls.start);
                    let at = if matches!(
                        p.tokens.get(at)?.kind,
                        TokenKind::Operator(crate::lexer::Operator::LtLt)
                    ) {
                        next_non_trivia_idx(p.tokens, at + 1)?
                    } else {
                        at
                    };
                    Some(p.tokens[at].lexeme(p.source))
                });
                let mut end_label_span: Option<Span> = None;
                if let Some(lbl) = p.peek_non_trivia() {
                    let closes_own_label = label_name
                        .is_some_and(|name| name.eq_ignore_ascii_case(lbl.lexeme(p.source)));
                    if closes_own_label
                        || (!p.dialect.uses_optional_statement_terminators()
                            && p.can_be_identifier_token(lbl)
                            && !matches!(
                                lbl.kind,
                                TokenKind::Punctuation(crate::lexer::Punctuation::Semi)
                            )
                            && !crate::parser::core::is_dollar_quote_delimiter(&lbl.kind))
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

                // Use Result-based parser for statements with error recovery; a
                // control-flow statement that does not parse ends at its own
                // `END <kw>`. A bare `END` in it closes the block.
                let outer_end_closed = std::mem::replace(&mut p.in_end_closed_body, true);
                let parsed = try_parse_scripting_stmt(p, StmtContext::Block, body_start);
                p.in_end_closed_body = outer_end_closed;
                match parsed {
                    Ok(stmt) => {
                        let tail = text_kept_as_written(&stmt);
                        unterminated = p.note_statement_read(before, stmt_start_idx, &stmt, tail);
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
                            break p.failed_reads.fail(p.idx, e);
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
                        let tail = Some(error_node.span());
                        unterminated =
                            p.note_statement_read(before, stmt_start_idx, &error_node, tail);
                        body.push(error_node);
                        // Continue parsing - don't break
                        continue;
                    }
                }
            }
        }
    };
    let read_from = read_from
        .into_iter()
        .map(|idx| state.at(idx, Read::BlockBody));
    p.failed_reads.stood(read_from, failure);
    Err(p.failed_reads.replay(failure, &mut p.idx))
}

/// The reads that failed: a block's body that no `END` closes before the
/// input ends, or that a statement in it fails, and a statement that does
/// not parse. What a read from a token reads depends only on the tokens and
/// on the parser's state there, not on what the read is part of: read again
/// from that token in that state, it reads the same to the same failure. So
/// the text a failed read covered is read once: a read that comes to a token
/// a failed read stood at fails there at once, as it did. A block's body is
/// read statement by statement; its read stood at each statement it read.
#[derive(Default)]
pub(crate) struct FailedReads {
    /// Each failure: the token the read failed at and its error.
    failures: Vec<(usize, ParseError)>,
    /// The failure a read standing at a token comes to.
    reached: std::collections::HashMap<ReadAt, usize>,
}

impl FailedReads {
    /// The failure a read standing at `at` comes to, if a failed read stood
    /// there.
    fn reached(&self, at: ReadAt) -> Option<usize> {
        self.reached.get(&at).copied()
    }

    /// Records a read failing at token `idx` with `error`.
    fn fail(&mut self, idx: usize, error: ParseError) -> usize {
        self.failures.push((idx, error));
        self.failures.len() - 1
    }

    /// Records that a read standing at each of `read_from` comes to
    /// `failure`.
    fn stood(&mut self, read_from: impl IntoIterator<Item = ReadAt>, failure: usize) {
        for from in read_from {
            self.reached.insert(from, failure);
        }
    }

    /// The error of `failure`, the parser placed at the token it failed at
    /// (`idx`).
    fn replay(&self, failure: usize, idx: &mut usize) -> ParseError {
        let (failed_at, error) = &self.failures[failure];
        *idx = *failed_at;
        error.clone()
    }
}

/// The parser's state a statement is read in: the mode, whether a bare
/// `END` in it closes the body around it, and whether it is in an ODBC
/// escape, a T-SQL `WHILE` body or a dollar-quoted body.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct ReadState {
    scripting: bool,
    end_closed: bool,
    odbc: bool,
    while_body: bool,
    dollar_body: bool,
}

impl ReadState {
    fn of(p: &Parser<'_>) -> Self {
        Self {
            scripting: matches!(p.mode, crate::parser::core::ParserMode::Scripting),
            end_closed: p.in_end_closed_body,
            odbc: p.odbc_depth > 0,
            while_body: p.while_body_depth > 0,
            dollar_body: p.dollar_body_block_depth > 0,
        }
    }

    /// The state a block's body is read in from this one: each of its
    /// statements is read as one a bare `END` in closes the block.
    fn in_block(self) -> Self {
        Self {
            end_closed: true,
            ..self
        }
    }

    /// A read of `what` in this state standing at token `idx`.
    fn at(self, idx: usize, what: Read) -> ReadAt {
        ReadAt {
            idx,
            what,
            state: self,
        }
    }
}

/// What is read from a token.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum Read {
    /// The rest of a block's body.
    BlockBody,
    /// One statement, in a body of this kind.
    Statement(StmtContext),
}

/// A token a read stands at, what it reads and the state it reads in.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct ReadAt {
    idx: usize,
    what: Read,
    state: ReadState,
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

/// Whether token `at`, written after `SET`, is the `VAR` / `VARIABLE`
/// keyword of an assignment (`SET VAR x = …`, `SET VARIABLE (x, y) = …`):
/// the word with a name or a `(` after it. `SET var = …` names `var`.
pub(crate) fn set_variable_keyword_at(p: &Parser<'_>, at: usize) -> bool {
    (p.word_at(at, "VAR") || p.word_at(at, "VARIABLE"))
        && next_non_trivia_idx(p.tokens, at + 1).is_some_and(|next| {
            let tok = &p.tokens[next];
            p.can_be_identifier_token(tok)
                || matches!(
                    tok.kind,
                    TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
                )
        })
}

/// The variable a `SET VAR` assignment names, written with its schema or
/// not (`x`, `session.x`, `system.session.x`): its last name part.
fn read_set_variable_name(p: &mut Parser<'_>) -> ParseResult<AstIdentifier> {
    let mut name = p
        .advance()
        .ok_or_eof(p.current_span(), vec!["variable name".to_string()])?;
    while p
        .peek()
        .is_some_and(|t| matches!(t.kind, TokenKind::Punctuation(Punctuation::Dot)))
        && p.peek_ahead(1)
            .is_some_and(|t| p.can_be_identifier_token(t))
    {
        p.advance(); // '.'
        name = p
            .advance()
            .ok_or_eof(p.current_span(), vec!["variable name".to_string()])?;
    }
    Ok(AstIdentifier {
        node_id: p.id_gen.next(),
        span: name.span,
        kind: crate::ast::AstIdentifierKind::of(&name.kind),
        templated: None,
    })
}

/// Parse a SET session variable statement.
/// Snowflake syntax:
/// - Single: SET variable_name = expression
/// - Multiple: SET (var1, var2, ...) = (expr1, expr2, ...)
/// - From SELECT: SET variable_name = (SELECT ...)
///
/// After the `VAR` / `VARIABLE` keyword ([`set_variable_keyword_at`]) a
/// name may carry its schema, and a list `x = e1, y = e2` assigns each.
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

    let variable_keyword = set_variable_keyword_at(p, p.idx);
    if variable_keyword {
        p.advance(); // VAR / VARIABLE
    }

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
                    kind: crate::ast::AstIdentifierKind::of(&tok.kind),
                    templated: None,
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
        let ident = if variable_keyword {
            read_set_variable_name(p)?
        } else if p.can_be_identifier_token(name_tok) {
            let tok = p
                .advance()
                .expect_invariant("variable name identifier after SET");
            AstIdentifier {
                node_id: p.id_gen.next(),
                span: tok.span,
                kind: crate::ast::AstIdentifierKind::of(&tok.kind),
                templated: None,
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

    // A compound assignment, `SET @v += expr` (an operator written against
    // `=`, as T-SQL has them, or `|=` / `&=`), assigns `@v <operator> expr`.
    p.skip_trivia();
    let compound = if is_tuple_form {
        None
    } else {
        p.compound_assignment_at()
    };
    // The operator before its `=`; a one-token `|=` is read as the `=`.
    let eq_in_operator = compound.as_ref().is_some_and(|c| c.tokens == 1);
    if compound.as_ref().is_some_and(|c| c.tokens == 2) {
        p.advance();
    }
    let compound = compound.map(|c| (c.operator, c.op_token, c.op_span));

    // Expect =
    let eq_tok = p.peek_non_trivia().ok_or_else(|| {
        ParseError::new(
            p.current_span(),
            ParseErrorKind::InvalidStatement {
                message: "Expected '=' after variable name(s) in SET statement".to_string(),
            },
        )
    })?;

    if !eq_in_operator && !matches!(eq_tok.kind, TokenKind::Operator(crate::lexer::Operator::Eq)) {
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
        let expr = match (compound, variable_names.first()) {
            (Some((operator, op_token, op_span)), Some(name)) => {
                let span = Span {
                    start: name.span.start,
                    end: expr.span().end,
                };
                let variable = AstExpr::Ident {
                    node_id: p.id_gen.next(),
                    column_ref: crate::ast::AstColumnRef {
                        node_id: p.id_gen.next(),
                        qualifier: None,
                        name: AstIdentifier {
                            node_id: p.id_gen.next(),
                            span: name.span,
                            kind: name.kind,
                            templated: None,
                        },
                    },
                };
                let syntax_id = p
                    .syntax_arena
                    .alloc_binary_op(crate::syntax::SyntaxBinaryOp {
                        op_token,
                        span: op_span,
                    });
                AstExpr::BinaryOp {
                    node_id: p.id_gen.next(),
                    left: Box::new(variable),
                    operator,
                    syntax_id,
                    right: Box::new(expr),
                    span,
                }
            }
            (Some(_), None) | (None, _) => expr,
        };
        values.push(expr);
        // `SET VAR x = e1, y = e2`: each name with its value.
        while variable_keyword
            && p.peek()
                .is_some_and(|t| matches!(t.kind, TokenKind::Punctuation(Punctuation::Comma)))
        {
            p.advance(); // ','
            variable_names.push(read_set_variable_name(p)?);
            let eq_tok = p
                .advance()
                .ok_or_eof(p.current_span(), vec!["=".to_string()])?;
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
            values.push(try_parse_expr_scripting(p)?);
        }
    }
    if let ([_, _, ..], [query]) = (variable_names.as_slice(), values.as_slice()) {
        // `SET (a, b) = (SELECT …)`: every name takes a column of the one
        // query, read once for the first name naming a secret.
        if let Some(name) = variable_names.iter().find(|n| p.names_a_secret(n.span)) {
            p.record_assigned_secret(name.span, query);
        }
    } else {
        for (name, value) in variable_names.iter().zip(&values) {
            p.record_assigned_secret(name.span, value);
        }
    }
    // A session's variable or a configuration parameter given a value.
    // Databricks' `SET VAR` gives a session's variable its value.
    let setting = match p.dialect.set_assigns() {
        crate::dialect::SetAssigns::Configuration => Some(!variable_keyword),
        crate::dialect::SetAssigns::SessionVariable => Some(false),
        crate::dialect::SetAssigns::ScriptVariable => None,
    };
    if let Some(configures) = setting {
        for value in &values {
            let name = variable_names
                .first()
                .filter(|_| configures && variable_names.len() == 1)
                .map(|name| name.span);
            p.record_setting_expression(name, value.span());
        }
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

/// Lookahead helper: whether the `ALTER PROCEDURE` / `ALTER FUNCTION` whose
/// tokens after the object keyword start at `idx` restates the module's
/// definition (T-SQL: a body after `AS`, a function's `RETURNS`) rather than
/// changes one of its properties. Reads to the statement's `;` or the end
/// of input; an `AS` of `EXECUTE AS` is a property.
pub(crate) fn is_module_definition_at(tokens: &[Token], idx: usize) -> bool {
    let mut depth = 0usize;
    let mut after_execute = false;
    for tok in tokens.iter().skip(idx) {
        let kind = &tok.kind;
        if matches!(
            kind,
            TokenKind::LineComment | TokenKind::BlockComment | TokenKind::Eof
        ) {
            continue;
        }
        if matches!(kind, TokenKind::Punctuation(Punctuation::LParen)) {
            depth += 1;
        } else if matches!(kind, TokenKind::Punctuation(Punctuation::RParen)) {
            depth = depth.saturating_sub(1);
        } else if depth == 0 {
            if matches!(kind, TokenKind::Punctuation(Punctuation::Semi)) {
                return false;
            }
            if matches!(kind, TokenKind::Keyword(Keyword::Returns))
                || (matches!(kind, TokenKind::Keyword(Keyword::As)) && !after_execute)
            {
                return true;
            }
        }
        after_execute = matches!(kind, TokenKind::Keyword(Keyword::Execute));
    }
    false
}

/// Lookahead helper: returns `true` when the token at `idx` is an identifier
/// and the very next non-trivia token is a colon (`:`) that starts no sqlcmd
/// command line (`t`↵`:r file`).  Used as a match guard to distinguish
/// `label_name:` declarations from regular identifiers.
pub(crate) fn is_mssql_label_at(p: &Parser<'_>, idx: usize) -> bool {
    let tokens = p.tokens;
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
        ) && !p.is_sqlcmd_command(&tokens[i]);
    }
    false
}

/// Consume a label name + colon, then dispatch to the appropriate loop/block parser.
/// Called from both the Identifier and Keyword match arms when `is_label_before_loop_at` is true.
pub(crate) fn parse_label_and_dispatch(
    p: &mut Parser<'_>,
    begin_start: u32,
) -> ParseResult<AstStmt> {
    // Consume the label (`name :` or `<< name >>`)
    let Some((after_label, label)) = label_prefix_at(p, p.idx) else {
        return Err(ParseError::new(
            p.current_span(),
            ParseErrorKind::InvalidStatement {
                message: "Expected a label".to_string(),
            },
        ));
    };
    p.idx = after_label;
    let label_span = Some(label);
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
                try_parse_mssql_while(p, label_span)
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
        TokenKind::Keyword(Keyword::Declare) => labelled_declare_block(p, label),
        _ => Err(ParseError::new(
            kw_tok.span,
            ParseErrorKind::InvalidStatement {
                message: format!(
                    "Expected WHILE, LOOP, REPEAT, FOR, DECLARE or BEGIN after label, found {}",
                    Parser::token_description(kw_tok, p.source)
                ),
            },
        )),
    }
}

/// Whether the name at the parser's cursor is assigned to (`name := …`,
/// `name = …`, PL/pgSQL's `NEW.col := …`).
fn assignment_follows(p: &Parser<'_>) -> bool {
    assigned_name_end(p, p.idx).is_some()
}

/// Where an assignment operator follows the name at `at` (read by
/// [`Parser::name_span_at`]; the word there where no name starts), and any
/// subscripts written after it (`arr[1]`, `js['a']`, `x[1:2]`): the name's
/// span, the index past the name, and the index of the operator.
fn assigned_name_end(p: &Parser<'_>, at: usize) -> Option<(Span, usize, usize)> {
    let (end, name) = p
        .name_span_at(at, crate::parser::core::NamePosition::Object)
        .or_else(|| p.tokens.get(at).map(|word| (at + 1, word.span)))?;
    let operator = subscripts_end(p, end);
    p.tokens
        .get(operator)
        .is_some_and(|t| {
            matches!(
                t.kind,
                TokenKind::Operator(crate::lexer::Operator::Eq | crate::lexer::Operator::ColonEq)
            )
        })
        .then_some((name, end, operator))
}

/// The index past the subscripts, each a balanced `[â¦]`, written from `at`;
/// `at` where none is.
fn subscripts_end(p: &Parser<'_>, at: usize) -> usize {
    let mut past = at;
    while p
        .tokens
        .get(past)
        .is_some_and(|t| matches!(t.kind, TokenKind::Punctuation(Punctuation::LBracket)))
    {
        let mut depth = 0usize;
        let mut close = None;
        for (i, t) in p.tokens.iter().enumerate().skip(past) {
            if matches!(t.kind, TokenKind::Punctuation(Punctuation::LBracket)) {
                depth += 1;
            } else if matches!(t.kind, TokenKind::Punctuation(Punctuation::RBracket)) {
                depth -= 1;
                if depth == 0 {
                    close = Some(i);
                    break;
                }
            } else if matches!(
                t.kind,
                TokenKind::Punctuation(Punctuation::Semi) | TokenKind::Eof
            ) {
                break;
            }
        }
        match close {
            Some(close) => past = close + 1,
            None => return at,
        }
    }
    past
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
pub(crate) fn is_label_before_loop_at(p: &Parser<'_>, idx: usize) -> bool {
    let tokens = p.tokens;
    let lexeme = tokens[idx].lexeme(p.source);
    // LEAVE/ITERATE are loop-control, not labels
    if lexeme.eq_ignore_ascii_case("LEAVE")
        || lexeme.eq_ignore_ascii_case("ITERATE")
        || !p.can_be_label(idx, LabelPosition::StatementLabel)
    {
        return false;
    }
    // A word that starts a statement here is that statement, not a label.
    if matches!(tokens[idx].kind, TokenKind::Keyword(Keyword::Exit))
        || p.starts_statement(idx, StatementContext::BodyRecovery)
    {
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
    let table_span = p.parse_object_name_span()?;

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

            // Consume everything inside parens (balanced), recording each
            // `name = value` option written at the list's own level.
            let mut depth: u32 = 1;
            let mut last_span = p.current_span();
            let mut item: Vec<crate::lexer::Token> = Vec::new();
            while depth > 0 {
                let tok = p.advance().ok_or_eof(
                    p.current_span(),
                    vec!["closing ')' for WITH options".to_string()],
                )?;
                last_span = tok.span;
                let ends_item = depth == 1
                    && matches!(
                        tok.kind,
                        TokenKind::Punctuation(
                            crate::lexer::Punctuation::Comma | crate::lexer::Punctuation::RParen
                        )
                    );
                match tok.kind {
                    TokenKind::Punctuation(crate::lexer::Punctuation::LParen) => depth += 1,
                    TokenKind::Punctuation(crate::lexer::Punctuation::RParen) => depth -= 1,
                    _ => {}
                }
                if ends_item {
                    if let [name, eq, value] = item.as_slice() {
                        if matches!(eq.kind, TokenKind::Operator(crate::lexer::Operator::Eq)) {
                            p.bulk_options.push(crate::ast::BulkOption {
                                name: name.span,
                                value: value.span,
                            });
                        }
                    }
                    item.clear();
                } else {
                    item.push(tok.clone());
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

/// Consume the next word if it is one of `words` (compared ignoring case),
/// returning its span.
fn take_word(p: &mut Parser<'_>, words: &[&str]) -> Option<Span> {
    let tok = p.peek_non_trivia()?;
    let lexeme = tok.lexeme(p.source);
    if !words.iter().any(|word| lexeme.eq_ignore_ascii_case(word)) {
        return None;
    }
    p.advance().map(|tok| tok.span)
}

/// Parse a GET DIAGNOSTICS statement:
///   GET [CURRENT | STACKED] DIAGNOSTICS [CONDITION condition_number]
///       var = item_name [, var = item_name ...]
/// Databricks's and MySQL's condition form and PL/pgSQL's statement and
/// exception form.
fn try_parse_get_diagnostics_stmt(p: &mut Parser<'_>) -> ParseResult<AstStmt> {
    let get_tok = p.advance().expect_invariant("GET consumed after match");
    let start = get_tok.span.start;
    let mut end = get_tok.span.end;

    if let Some(span) = take_word(p, &["CURRENT", "STACKED"]) {
        end = span.end;
    }
    if let Some(span) = take_word(p, &["DIAGNOSTICS"]) {
        end = span.end;
    }

    // Consume CONDITION and its number (usually a literal number or identifier)
    if let Some(span) = take_word(p, &["CONDITION"]) {
        end = span.end;
        p.skip_trivia();
        if let Some(num_tok) = p.peek_non_trivia() {
            if matches!(num_tok.kind, TokenKind::Literal(_)) || p.can_be_identifier_token(num_tok) {
                let n = p.advance().expect_invariant("condition number consumed");
                end = n.span.end;
            }
        }
    }

    // Parse assignment items: var = item_name [, var = item_name ...]
    let mut targets = Vec::new();
    loop {
        p.skip_trivia();
        if let Some(var_tok) = p.peek_non_trivia() {
            if !p.can_be_identifier_token(var_tok)
                || matches!(var_tok.kind, TokenKind::Punctuation(Punctuation::Semi))
            {
                break;
            }
            // A variable, or a field of one (PL/pgSQL `NEW.col`).
            let v = p.take_name_or_token_span("variable name")?;
            targets.push(v);
            end = v.end;

            // Expect = (or :=)
            p.skip_trivia();
            if let Some(eq_tok) = p.peek_non_trivia() {
                if matches!(
                    eq_tok.kind,
                    TokenKind::Operator(
                        crate::lexer::Operator::Eq | crate::lexer::Operator::ColonEq
                    )
                ) {
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
        targets,
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
            eprintln!("  {}. {:?} -> '{}'", i + 1, stmt, text);
        }

        assert_eq!(
            script.stmts.len(),
            2,
            "Expected 2 statements, got {}",
            script.stmts.len()
        );
    }
}
