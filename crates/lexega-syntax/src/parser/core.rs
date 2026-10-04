// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Core parser infrastructure.
//!
//! This module contains the main `Parser` struct and implements:
//!
//! - **Script parsing** for multi-statement input
//! - **Statement dispatching** to the per-statement parsers
//! - **Error recovery** at the statement boundary, and tolerant parsing
//!   that resynchronizes at the next statement
//! - **Recursion limits**: a depth and stack budget shared by every parse
//!   on the thread
//! - **Helper utilities** for token navigation
//!
//! ## Parser State
//!
//! The parser maintains:
//! - Current token index (`idx`)
//! - Token slice reference
//! - The dialect it parses for
//! - Mode flag (SQL vs Scripting)
//! - The spans of secret values seen so far, for redaction
//!
//! Parsing methods return `ParseResult`. A caller that can try another
//! form saves the token index, and restores it when the first form fails.

use std::rc::Rc;

use crate::ast::{
    AstScript, AstStmt, JinjaInlineBlock, JinjaInlineComment, JinjaInlineFragment,
    JinjaInlineFragmentKind, JinjaInlinePunctuation,
};
use crate::dialect::{Dialect, SnowflakeDialect};
use crate::error::{ExpectInvariant, ParseError, ParseErrorKind, ParseResult, ParseResultExt};
use crate::lexer::{Keyword, Operator, Punctuation, Span, Token, TokenKind};
use crate::syntax::{
    SyntaxJinjaInlineFragment, SyntaxJinjaInlineFragmentId, SyntaxJinjaInlineFragmentKind,
};

/// Parser mode determines how statements and expressions are interpreted.
///
/// - **SQL**: Standard SQL statements and expressions (SELECT, INSERT, CREATE, etc.)
///   - Expression syntax: `expr:field` for object access is allowed
///   - `:var` variable references are NOT allowed
/// - **Scripting**: Snowflake Scripting constructs (BEGIN/END, IF, LOOP, etc.)
///   - Expression syntax: `:var` for variable references is allowed
///   - `expr:field` for object access is NOT allowed (ambiguous with :var)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParserMode {
    /// Regular SQL statement and expression parsing
    Sql,
    /// Snowflake Scripting statement and expression parsing
    Scripting,
}

/// Context-sensitive identifier interpretation used by parser call sites.
///
/// Different parser contexts need different permissiveness:
/// - `Generic`: lexical identifier positions (types, function args, etc.)
/// - `Alias`: alias positions that must stop on clause boundaries
/// - `AfterDot`: qualified-name member positions (`schema.table`, `t.column`)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentifierContext {
    Generic,
    Alias,
    AfterDot,
}

///
/// The `Parser` maintains a token stream and current position, providing
/// methods for parsing expressions, statements, and complete scripts.
///
/// # Design
///
/// - **Recursive descent**: Each parsing method handles one grammar rule
/// - **Lookahead**: Uses `peek()` to guide parsing decisions without consuming
/// - **Backtracking**: Returns `Option<T>` to signal parse failure
/// - **Span tracking**: Every parsed node includes source location
/// - **Mode context**: Explicit SQL vs Scripting mode tracking
///
/// Recognizes a dollar-quote delimiter lexeme (`$$` or `$tag$`) as the lexer
/// emits it (an `Identifier{Unquoted}` whose text starts and ends with `$`).
/// Used by both the expression parser (reassembling a dollar-quoted string
/// literal) and the routine-body parsers (matching the opening/closing
/// delimiters of a `$$ … $$` / `$tag$ … $tag$` body). A plain identifier or a
/// positional parameter (`$1`) never matches (those don't end with `$`).
pub(crate) fn is_dollar_quote_tag(lexeme: &str) -> bool {
    lexeme.len() >= 2 && lexeme.starts_with('$') && lexeme.ends_with('$')
}

/// True when an object-property name (upper-cased) holds a secret value whose
/// span must be redacted from output surfaces. Recognition, not policy: these
/// property values are structurally credentials (passwords, cloud keys, SAS
/// tokens, OAuth secrets, the generic SECRET string). Public keys, ARNs, and
/// integration/role references are NOT secrets and are intentionally excluded.
pub fn is_credential_value_property(name_upper: &str) -> bool {
    matches!(
        name_upper,
        "PASSWORD"
            | "ADMIN_PASSWORD"
            | "AWS_SECRET_KEY"
            | "AWS_TOKEN"
            | "AZURE_SAS_TOKEN"
            | "GCS_SAS_TOKEN"
            | "MASTER_KEY"
            | "OAUTH_CLIENT_SECRET"
            | "OAUTH_ACCESS_TOKEN"
            | "OAUTH_REFRESH_TOKEN"
            | "CLIENT_SECRET"
            | "REFRESH_TOKEN"
            | "SECRET_STRING"
            | "PRIVATE_KEY"
            | "PRIVATE_KEY_PASSPHRASE"
    )
}

pub struct Parser<'a> {
    /// The original source text (for getting token text via spans)
    pub(crate) source: &'a str,
    pub(crate) tokens: &'a [Token],
    /// SQL dialect controlling keyword and feature support.
    #[allow(dead_code)] // Used in dialect-specific parsing but not all methods
    pub(crate) dialect: &'a dyn Dialect,
    pub(crate) idx: usize,
    /// Errors from `parse_expr_with_recovery` — tracks that error-recovery
    /// nodes (`AstExpr::Error`) were created during parsing.
    pub(crate) recovery_errors: Vec<ParseError>,
    /// Byte-spans of secret values (passwords, credential keys, secret strings)
    /// seen while parsing, so consumers that quote source text can mask
    /// them and a credential value never reaches an output.
    pub(crate) redaction_spans: Vec<crate::lexer::token::Span>,
    /// Byte-spans in the parsed text that a template stage produced for an
    /// UNRESOLVED reference (Jinja placeholder, undefined SnowSQL `&var`).
    /// A credential-value capture landing on one of these treats the value
    /// as "not a statically-known literal" — the value that will run is
    /// injected later — so it is not reported as a hard-coded value (the
    /// span is still redacted). Empty unless a caller installs them.
    pub(crate) placeholder_spans: Vec<crate::lexer::token::Span>,
    pub(crate) id_gen: Rc<crate::ast::NodeIdGenerator>,
    /// Current parsing mode (SQL, Scripting, or Expression)
    pub(crate) mode: ParserMode,
    /// Typed syntax arena - stores syntax nodes with explicit token ownership
    pub(crate) syntax_arena: crate::syntax::SyntaxArena,
    /// Nesting depth of ODBC escape clauses (`{d '…'}`, `{fn …}`, `{call …}`)
    /// currently being parsed. Non-zero enables `?` parameter markers in
    /// expression position (ODBC SQL is parameterized).
    pub(crate) odbc_depth: u32,
}

std::thread_local! {
    /// Depth of all in-flight parser recursion on this thread (statements,
    /// expressions, Jinja). Thread-local rather than a `Parser` field so the
    /// count survives error unwinding via [`DepthGuard`], and nested `Parser`
    /// instances on one thread share the budget of the one physical stack.
    static PARSE_DEPTH: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };

    /// Stack address of the outermost guarded frame (0 = no parse in flight).
    /// Anchors the stack-consumption measurement in [`track_depth`].
    static PARSE_STACK_ANCHOR: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Single limit for all parser recursion. Bounds AST depth; generous because
/// several guarded frames (~4) make up one source-level nesting step, so this
/// allows ~145 levels of parenthesis nesting. Stack safety is NOT this limit's
/// job: [`PARSE_STACK_BUDGET`] trips on measured consumption whatever the
/// per-frame cost of the build profile.
const MAX_PARSE_DEPTH: usize = 600;

/// Minimum stack size, in bytes, for any native thread that runs the parser.
/// A parse stops gracefully once it consumes `PARSE_STACK_BUDGET` bytes of
/// stack; a thread needs at least this much total stack so that trip happens
/// before the OS guard page. Linux/macOS main threads meet it by default; a
/// Windows binary reserves it with a `/STACK` link argument, and a worker
/// thread gets it from an explicit `stack_size` at spawn.
pub const MIN_PARSE_STACK_BYTES: usize = 8 * 1024 * 1024;

/// Stack bytes one parse may consume before erroring gracefully. Measured
/// against the real stack, so fat debug-build frames trip it early instead of
/// overflowing. Leaves 2 MiB of [`MIN_PARSE_STACK_BYTES`] for frames outside
/// the parser and the red zone.
#[cfg(not(target_arch = "wasm32"))]
const PARSE_STACK_BUDGET: usize = MIN_PARSE_STACK_BYTES - 2 * 1024 * 1024;
/// wasm32 has no threads and a small linear-memory stack (1 MiB by default).
#[cfg(target_arch = "wasm32")]
const PARSE_STACK_BUDGET: usize = 384 * 1024;

/// Decrements the depth counter on drop, so unwinding on any path —
/// including `?` early returns — never leaks a depth tick. Clears the stack
/// anchor when the outermost guard is released.
pub(crate) struct DepthGuard;

impl Drop for DepthGuard {
    fn drop(&mut self) {
        PARSE_DEPTH.with(|d| {
            let depth = d.get().saturating_sub(1);
            d.set(depth);
            if depth == 0 {
                PARSE_STACK_ANCHOR.with(|a| a.set(0));
            }
        });
    }
}

/// Track one level of parser recursion; errors once [`MAX_PARSE_DEPTH`] levels
/// or [`PARSE_STACK_BUDGET`] bytes of stack are consumed. Hold the returned
/// guard for the duration of the recursive scope.
pub(crate) fn track_depth(name: &str, span: Span) -> Result<DepthGuard, ParseError> {
    // Approximate stack position: the address of a fresh local. Compared
    // against the anchor recorded by the outermost guard; the stack grows
    // downward on every supported target, and saturating_sub keeps the
    // check inert if it ever does not.
    let probe = 0u8;
    let here = std::ptr::addr_of!(probe) as usize;
    PARSE_DEPTH.with(|d| {
        let new_depth = d.get() + 1;
        d.set(new_depth);
        if new_depth == 1 {
            PARSE_STACK_ANCHOR.with(|a| a.set(here));
        } else {
            let consumed = PARSE_STACK_ANCHOR.with(|a| a.get()).saturating_sub(here);
            if consumed > PARSE_STACK_BUDGET {
                // Decrement since we're returning an error (no DepthGuard to drop)
                d.set(new_depth.saturating_sub(1));
                return Err(ParseError::new(
                    span,
                    ParseErrorKind::StatementTooDeep {
                        context: name.to_string(),
                        depth: new_depth,
                    },
                ));
            }
        }
        if new_depth > MAX_PARSE_DEPTH {
            // Decrement since we're returning an error (no DepthGuard to drop)
            d.set(new_depth.saturating_sub(1));
            return Err(ParseError::new(
                span,
                ParseErrorKind::RecursionLimitExceeded {
                    limit: MAX_PARSE_DEPTH,
                    context: name.to_string(),
                },
            ));
        }
        Ok(())
    })?;
    Ok(DepthGuard)
}

impl<'a> Parser<'a> {
    /// Create a new parser with the default Snowflake dialect.
    pub(crate) fn new(source: &'a str, tokens: &'a [Token]) -> Self {
        Self::with_dialect(source, tokens, &SnowflakeDialect)
    }

    /// Create a new parser with an explicit dialect.
    ///
    /// This allows parsing SQL from different dialects (PostgreSQL, MySQL, etc.)
    /// with dialect-specific keyword and feature support.
    pub(crate) fn with_dialect(
        source: &'a str,
        tokens: &'a [Token],
        dialect: &'a dyn Dialect,
    ) -> Self {
        Parser {
            source,
            tokens,
            dialect,
            idx: 0,
            recovery_errors: Vec::new(),
            redaction_spans: Vec::new(),
            placeholder_spans: Vec::new(),
            id_gen: Rc::new(crate::ast::NodeIdGenerator::new()),
            mode: ParserMode::Sql,
            syntax_arena: crate::syntax::SyntaxArena::new(),
            odbc_depth: 0,
        }
    }

    /// Install the template-placeholder spans for this parse (formatter
    /// parses never set them).
    pub(crate) fn set_placeholder_spans(&mut self, spans: &[crate::lexer::token::Span]) {
        self.placeholder_spans = spans.to_vec();
    }

    /// True when `span` overlaps a template-placeholder span — the text at
    /// `span` is a render artifact standing in for an injected value, not
    /// content the author wrote.
    pub(crate) fn span_overlaps_placeholder(&self, span: crate::lexer::token::Span) -> bool {
        self.placeholder_spans
            .iter()
            .any(|p| p.start < span.end && span.start < p.end)
    }

    /// Promote a dynamic-SQL string argument that overlaps a rendered
    /// placeholder to [`crate::ast::AstLiteral::StringWithJinja`]. The render
    /// substitutes an undefined `{{ … }}` to a placeholder span; the string
    /// text no longer shows the hole, but the injected value splices in there
    /// at run time — the classic dynamic-SQL injection splice. Marking it
    /// StringWithJinja makes the dynamic-SQL classifier treat the argument as a
    /// dynamic Concat rather than a clean literal. A literal with no placeholder
    /// (or any non-string expression) is returned unchanged.
    pub(crate) fn promote_placeholder_dynamic_sql_arg(
        &self,
        expr: crate::ast::AstExpr,
    ) -> crate::ast::AstExpr {
        if let crate::ast::AstExpr::Literal {
            node_id,
            literal: crate::ast::AstLiteral::String { span },
        } = &expr
        {
            if self.span_overlaps_placeholder(*span) {
                return crate::ast::AstExpr::Literal {
                    node_id: *node_id,
                    literal: crate::ast::AstLiteral::StringWithJinja { span: *span },
                };
            }
        }
        expr
    }

    /// Track one level of parser recursion at the current token's span.
    /// Bind the returned guard (`let _depth = self.track_depth("ctx")?;`);
    /// its `Drop` releases the level on every exit path.
    #[inline]
    pub(crate) fn track_depth(&self, context: &str) -> Result<DepthGuard, ParseError> {
        track_depth(context, self.current_span())
    }

    /// Check whether any error-recovery nodes were created during parsing.
    /// Returns the accumulated errors from `parse_expr_with_recovery` calls.
    pub fn get_recovery_errors(&self) -> &[ParseError] {
        &self.recovery_errors
    }

    // ========== Token ID Helpers ==========

    /// Get the TokenId for the current token (before advance).
    #[inline]
    pub(crate) fn current_token_id(&self) -> crate::cst::TokenId {
        crate::cst::TokenId(self.idx as u32)
    }

    /// Get the TokenId for the most recently advanced token.
    /// Call this AFTER advance() to get the ID of the token just consumed.
    #[inline]
    pub(crate) fn last_token_id(&self) -> crate::cst::TokenId {
        crate::cst::TokenId((self.idx.saturating_sub(1)) as u32)
    }

    /// Reassemble a dollar-quoted run (`$$ … $$` / `$tag$ … $tag$`) starting at
    /// the current position into one span covering opener through matching
    /// closer, consuming every token in the run.
    ///
    /// PRECONDITION: the next token to be advanced is a dollar-quote opener — an
    /// `Identifier` whose lexeme satisfies [`is_dollar_quote_tag`]. Callers gate
    /// on `dialect.supports_dollar_quoted_strings()` and confirm the opener via a
    /// peek before calling.
    ///
    /// Under that dialect gate the lexer emits a dollar-quoted region as
    /// opening-delimiter + inner SQL tokens + closing-delimiter so routine bodies
    /// become analyzable statements; wherever the run is a STRING LITERAL instead
    /// (expression position, `COMMENT ON … IS`, …) it must collapse back to a
    /// single span. The matching closer is the next token whose lexeme equals the
    /// opener's — the lexer's opaque close-scan guarantees the inner region holds
    /// no occurrence of the tag, so the first match is the true closer. On EOF
    /// without a closer (unterminated) the span ends at the last consumed token.
    /// The value/opacity of the result derive from the span alone, never from the
    /// inner token kinds, so it is identical to a single-token literal.
    pub(crate) fn reassemble_dollar_quoted_span(&mut self) -> Span {
        let open = self
            .advance()
            .expect_invariant("dollar-quote opener available at reassembly entry");
        let open_lo = open.span.start as usize;
        let open_hi = open.span.end as usize;
        let start = open.span.start;
        let mut end = open.span.end;
        loop {
            let step = self.peek().map(|t| {
                let is_close = matches!(t.kind, TokenKind::Identifier { .. })
                    && t.lexeme(self.source) == &self.source[open_lo..open_hi];
                (t.span, is_close)
            });
            match step {
                Some((t_span, is_close)) => {
                    let _ = self.advance();
                    end = t_span.end;
                    if is_close {
                        break;
                    }
                }
                None => break, // EOF without closer (degraded); stop at last consumed
            }
        }
        Span { start, end }
    }

    // ========== Jinja CST Allocation Helpers ==========

    /// Allocate a JinjaBlockDelimiter with CST wiring.
    ///
    /// This is the central helper for allocating delimiter syntax nodes
    /// and linking them to AST nodes via syntax_id.
    ///
    /// # Arguments
    /// * `span` - Overall span covering the entire delimiter `{% if ... %}`
    /// * `kind` - Type of delimiter (If, Elif, Else, EndIf, For, EndFor, etc.)
    /// * `condition` - Optional parsed Jinja expression for If/For/Elif
    /// * `open_brace` - TokenId for the `{%` token
    /// * `keyword` - TokenId for the keyword token (if, elif, for, etc.)
    /// * `close_brace` - TokenId for the `%}` token
    ///
    /// # Returns
    /// `JinjaBlockDelimiter` with `syntax_id: Some(id)` linking to CST layer.
    pub(crate) fn alloc_jinja_delimiter(
        &mut self,
        span: crate::lexer::Span,
        kind: crate::ast::JinjaBlockKind,
        condition: Option<crate::ast::JinjaExpr>,
        open_brace: crate::cst::TokenId,
        keyword: crate::cst::TokenId,
        close_brace: crate::cst::TokenId,
    ) -> crate::ast::JinjaBlockDelimiter {
        use crate::ast::JinjaBlockDelimiter;
        use crate::syntax::jinja::SyntaxJinjaDelimiter;

        // Extract syntax_id from condition if present
        let expr_syntax_id = condition.as_ref().and_then(|e| e.syntax_id);

        // Construct CST node for delimiter with actual TokenIds
        let syntax_node = SyntaxJinjaDelimiter {
            open_brace,
            keyword,
            expr: expr_syntax_id,
            close_brace,
            span,
        };

        // Allocate CST node in arena
        let syntax_id = self.syntax_arena.alloc_jinja_delimiter(syntax_node);

        JinjaBlockDelimiter {
            node_id: self.id_gen.next(),
            span,
            kind,
            condition,
            syntax_id: Some(syntax_id),
        }
    }

    fn alloc_inline_fragment_node(
        &mut self,
        span: Span,
        kind: SyntaxJinjaInlineFragmentKind,
    ) -> SyntaxJinjaInlineFragmentId {
        let node = SyntaxJinjaInlineFragment { kind, span };
        self.syntax_arena.alloc_jinja_inline_fragment(node)
    }

    pub(crate) fn build_inline_comment_fragment(
        &mut self,
        token: &Token,
        token_id: crate::cst::TokenId,
    ) -> JinjaInlineFragment {
        let syntax_id = self.alloc_inline_fragment_node(
            token.span,
            SyntaxJinjaInlineFragmentKind::Comment { token: token_id },
        );

        JinjaInlineFragment {
            node_id: self.id_gen.next(),
            span: token.span,
            syntax_id: Some(syntax_id),
            kind: JinjaInlineFragmentKind::Comment(JinjaInlineComment {
                node_id: self.id_gen.next(),
                body_span: Self::shrink_comment_span(token.span),
            }),
        }
    }

    pub(crate) fn build_inline_punctuation_fragment(
        &mut self,
        token: &Token,
        token_id: crate::cst::TokenId,
    ) -> JinjaInlineFragment {
        let syntax_id = self.alloc_inline_fragment_node(
            token.span,
            SyntaxJinjaInlineFragmentKind::Punctuation {
                tokens: vec![token_id],
            },
        );

        JinjaInlineFragment {
            node_id: self.id_gen.next(),
            span: token.span,
            syntax_id: Some(syntax_id),
            kind: JinjaInlineFragmentKind::Punctuation(JinjaInlinePunctuation {
                token_kind: token.kind.clone(),
                span: token.span,
            }),
        }
    }

    pub(crate) fn build_inline_block_fragment(
        &mut self,
        opening: crate::ast::JinjaBlockDelimiter,
        content: Option<crate::ast::JinjaInlineBlockContent>,
        elif_branches: Vec<crate::ast::JinjaInlineElifBranch>,
        else_branch: Option<crate::ast::JinjaInlineElseBranch>,
        closing: Option<crate::ast::JinjaBlockDelimiter>,
    ) -> JinjaInlineFragment {
        let span = Span {
            start: opening.span.start,
            end: closing
                .as_ref()
                .map(|d| d.span.end)
                .unwrap_or(opening.span.end),
        };
        let opening_id = opening
            .syntax_id
            .expect_invariant("opening delimiter must have syntax id");
        let closing_id = closing.as_ref().and_then(|delimiter| delimiter.syntax_id);
        let syntax_id = self.alloc_inline_fragment_node(
            span,
            SyntaxJinjaInlineFragmentKind::InlineBlock {
                opening: opening_id,
                closing: closing_id,
            },
        );

        JinjaInlineFragment {
            node_id: self.id_gen.next(),
            span,
            syntax_id: Some(syntax_id),
            kind: JinjaInlineFragmentKind::InlineBlock(Box::new(JinjaInlineBlock {
                opening,
                content,
                elif_branches,
                else_branch,
                closing,
            })),
        }
    }

    fn shrink_comment_span(span: Span) -> Span {
        let start = span.start.saturating_add(2);
        let end = span.end.saturating_sub(2);
        if end <= start {
            Span { start, end: start }
        } else {
            Span { start, end }
        }
    }

    /// Check if current token is a Jinja statement opening: {% keyword
    /// Returns the JinjaBlockKind if detected, None otherwise.
    pub(crate) fn peek_jinja_block_kind(&self) -> Option<crate::ast::JinjaBlockKind> {
        use crate::ast::JinjaBlockKind;

        // Check for {% opening - use peek() not peek_non_trivia() because we want raw position
        let tok = self.peek()?;
        if !matches!(tok.kind, TokenKind::JinjaStmtOpen) {
            return None;
        }

        // Look ahead to the keyword after {%
        // Tokens don't have trivia as separate token types - trivia is in Token.leading_trivia
        let next_tok = self.peek_ahead(1)?;
        match next_tok.kind {
            TokenKind::JinjaIf => Some(JinjaBlockKind::If),
            TokenKind::JinjaElif => Some(JinjaBlockKind::Elif),
            TokenKind::JinjaElse => Some(JinjaBlockKind::Else),
            TokenKind::JinjaEndIf => Some(JinjaBlockKind::EndIf),
            TokenKind::JinjaFor => Some(JinjaBlockKind::For),
            TokenKind::JinjaEndFor => Some(JinjaBlockKind::EndFor),
            TokenKind::JinjaSet => Some(JinjaBlockKind::Set),
            TokenKind::JinjaEndSet => Some(JinjaBlockKind::EndSet),
            TokenKind::JinjaDocs => Some(JinjaBlockKind::Docs),
            TokenKind::JinjaEndDocs => Some(JinjaBlockKind::EndDocs),
            _ => None,
        }
    }

    /// Temporarily enter a different parser mode.
    /// Returns the previous mode so it can be restored.
    pub(crate) fn enter_mode(&mut self, new_mode: ParserMode) -> ParserMode {
        let old_mode = self.mode;
        self.mode = new_mode;
        old_mode
    }

    /// Restore a previous parser mode.
    pub(crate) fn restore_mode(&mut self, mode: ParserMode) {
        self.mode = mode;
    }

    /// **PRIMARY ENTRY POINT**: Parse a complete SQL script.
    ///
    /// This is the main entry point for parsing. It processes all tokens
    /// and returns a complete AST script with all statements.
    ///
    /// # Returns
    /// - `Ok(AstScript)` - Successfully parsed all statements
    /// - `Err(ParseError)` - Parse error with location and details
    pub fn parse(&mut self) -> ParseResult<AstScript> {
        self.try_parse_script()
    }

    /// Check if all non-trivia tokens have been consumed.
    /// Returns Ok(()) if all consumed, Err with details if tokens remain.
    pub(crate) fn verify_all_tokens_consumed(&mut self) -> Result<(), crate::error::ParseError> {
        // Skip any trailing trivia/EOF tokens
        self.skip_trivia();

        // Count total non-EOF tokens for diagnostics
        let non_eof_count = self
            .tokens
            .iter()
            .filter(|t| !matches!(t.kind, TokenKind::Eof))
            .count();

        // Check if we've consumed everything
        if self.idx >= self.tokens.len() {
            return Ok(());
        }

        // Find first unconsumed non-EOF token
        let mut unconsumed_tokens = Vec::new();
        for i in self.idx..self.tokens.len() {
            let tok = &self.tokens[i];
            if !matches!(tok.kind, TokenKind::Eof) {
                unconsumed_tokens.push((i, tok.clone()));
            }
        }

        if !unconsumed_tokens.is_empty() {
            let first_unconsumed = &unconsumed_tokens[0].1;
            let consumed_non_eof = self.tokens[0..self.idx]
                .iter()
                .filter(|t| !matches!(t.kind, TokenKind::Eof))
                .count();

            return Err(crate::error::ParseError::new(
                first_unconsumed.span,
                crate::error::ParseErrorKind::InvalidSyntax {
                    message: format!(
                        "DATA LOSS DETECTED: {} unconsumed token(s) after parsing. \
                        Parser consumed {}/{} non-EOF tokens ({}% of source). \
                        First unconsumed: {:?} at position {}. \
                        This indicates the parser silently ignored part of the input.",
                        unconsumed_tokens.len(),
                        consumed_non_eof,
                        non_eof_count,
                        (consumed_non_eof * 100) / non_eof_count.max(1),
                        first_unconsumed.kind,
                        first_unconsumed.span.start
                    ),
                },
            ));
        }

        Ok(())
    }

    /// Verify that AST spans cover all meaningful source content.
    /// This catches bugs where tokens are consumed but not added to AST.
    pub(crate) fn verify_span_coverage(
        &self,
        _source: &str,
        ast_span: crate::lexer::Span,
    ) -> Result<(), crate::error::ParseError> {
        // Get the last non-EOF, non-trivia token position
        let last_meaningful_pos = self
            .tokens
            .iter()
            .rev()
            .find(|t| !matches!(t.kind, TokenKind::Eof))
            .map(|t| t.span.end)
            .unwrap_or(0);

        // AST span should cover up to the last meaningful token
        if ast_span.end < last_meaningful_pos {
            let missing_chars = last_meaningful_pos - ast_span.end;
            let coverage_pct = (ast_span.end * 100) / last_meaningful_pos.max(1);

            return Err(crate::error::ParseError::new(
                crate::lexer::Span {
                    start: ast_span.end,
                    end: last_meaningful_pos,
                },
                crate::error::ParseErrorKind::InvalidSyntax {
                    message: format!(
                        "DATA LOSS DETECTED: AST spans only cover {} of {} source positions ({}% coverage). \
                        {} characters at end of input are not represented in the AST. \
                        This indicates tokens were consumed but not added to the syntax tree.",
                        ast_span.end,
                        last_meaningful_pos,
                        coverage_pct,
                        missing_chars
                    ),
                },
            ));
        }

        Ok(())
    }

    #[inline]
    pub(crate) fn skip_trivia(&mut self) {
        while self.idx < self.tokens.len() {
            let tok_kind = &self.tokens[self.idx].kind;
            // Note: JinjaComment is now trivia (TriviaKind::JinjaComment), not a token,
            // so it's automatically skipped as part of leading/trailing trivia.
            if !matches!(
                tok_kind,
                TokenKind::Eof | TokenKind::LineComment | TokenKind::BlockComment
            ) {
                break;
            }
            self.idx += 1;
        }
    }

    #[inline]
    pub(crate) fn peek_non_trivia(&mut self) -> Option<&'a Token> {
        self.skip_trivia();
        self.tokens.get(self.idx)
    }

    #[inline]
    pub(crate) fn advance(&mut self) -> Option<&'a Token> {
        while self.idx < self.tokens.len() {
            let t = &self.tokens[self.idx];
            self.idx += 1;
            if !matches!(t.kind, TokenKind::Eof) {
                return Some(t);
            }
        }
        None
    }

    /// Returns a non-EOF token if one exists, skipping EOF tokens.
    #[inline]
    pub(crate) fn peek(&self) -> Option<&'a Token> {
        // Fast path: check current token directly (common case)
        if let Some(t) = self.tokens.get(self.idx) {
            if !matches!(t.kind, TokenKind::Eof) {
                return Some(t);
            }
        }
        // Slow path: scan forward for non-EOF (rare - usually at end of input)
        let mut i = self.idx + 1;
        while i < self.tokens.len() {
            let t = &self.tokens[i];
            if !matches!(t.kind, TokenKind::Eof) {
                return Some(t);
            }
            i += 1;
        }
        None
    }

    // ========== End Expression Parsing ==========

    // ========== Flow Statement and Script Parsing ==========
    // ========== Result-returning APIs ==========

    /// Unwrap a statement-dispatch result, degrading any parse failure to
    /// [`AstStmt::OpaqueContent`] at the statement boundary so the rest of
    /// the script still parses. Every dispatch arm routes through this —
    /// scripting blocks included — making the statement boundary the single,
    /// uniform containment point. Exhaustion errors arrive here un-recovered
    /// from the intra-expression sites (anti-amplification, see
    /// [`ParseErrorKind::is_resource_exhaustion`]); block-internal failures
    /// are normally absorbed earlier by `parse_body_with_recovery`, so what
    /// reaches this catch is structural (missing END, malformed headers).
    fn stmt_or_opaque(
        &mut self,
        result: ParseResult<AstStmt>,
        saved_idx: usize,
        stmt_start: u32,
    ) -> AstStmt {
        match result {
            Ok(stmt) => stmt,
            Err(e) => self.opaque_recover(saved_idx, stmt_start, &e),
        }
    }

    /// Recover from a statement-level parse failure: rewind to the statement
    /// start, skip to the next top-level boundary, and preserve the region as
    /// [`AstStmt::OpaqueContent`] so the rest of the script still parses.
    fn opaque_recover(&mut self, saved_idx: usize, stmt_start: u32, _e: &ParseError) -> AstStmt {
        // The parser advanced while the statement parse was failing; restore
        // to the statement start so the scan covers ALL of its tokens.
        self.idx = saved_idx;
        let start = stmt_start;
        // A statement led by WITH carries its main query head at depth 0;
        // that head belongs to this statement, so the first one is consumed
        // rather than treated as a new-statement boundary.
        let (first_end, started_with_cte) = match self.peek() {
            Some(t) => (
                t.span.end,
                matches!(t.kind, TokenKind::Keyword(Keyword::With)),
            ),
            None => (stmt_start, false),
        };

        // Skip tokens until a top-level statement boundary:
        // - Semicolon at depth 0
        // - Next statement keyword (SELECT, INSERT, CREATE, …) at depth 0
        // - EOF
        // Depth tracking keeps a SELECT inside a CTE body or subquery from
        // being read as a new statement, which would otherwise fragment one
        // failed `WITH … (…) SELECT …` query into many opaque skips and
        // corrupt the statements after it.
        let mut end = first_end;
        let mut depth: i32 = 0;
        let mut pending_cte_head = started_with_cte;

        while let Some(t) = self.peek() {
            // Track nesting so boundaries inside a CTE body or subquery
            // are not mistaken for new statements.
            if matches!(
                t.kind,
                TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
                    | TokenKind::Punctuation(crate::lexer::Punctuation::LBracket)
            ) {
                depth += 1;
            } else if matches!(
                t.kind,
                TokenKind::Punctuation(crate::lexer::Punctuation::RParen)
                    | TokenKind::Punctuation(crate::lexer::Punctuation::RBracket)
            ) {
                depth = depth.saturating_sub(1);
            }

            // Boundaries are only meaningful at the top level.
            if depth == 0 {
                if matches!(
                    t.kind,
                    TokenKind::Punctuation(crate::lexer::Punctuation::Semi)
                ) {
                    end = t.span.end;
                    self.advance();
                    break;
                }

                // Check if this looks like the start of a new statement
                let is_stmt_keyword = matches!(
                    t.kind,
                    TokenKind::Keyword(Keyword::Select)
                        | TokenKind::Keyword(Keyword::Insert)
                        | TokenKind::Keyword(Keyword::Update)
                        | TokenKind::Keyword(Keyword::Delete)
                        | TokenKind::Keyword(Keyword::Merge)
                        | TokenKind::Keyword(Keyword::Create)
                        | TokenKind::Keyword(Keyword::Drop)
                        | TokenKind::Keyword(Keyword::Alter)
                        | TokenKind::Keyword(Keyword::Show)
                        | TokenKind::Keyword(Keyword::Truncate)
                        | TokenKind::Keyword(Keyword::Use)
                        | TokenKind::Keyword(Keyword::Begin)
                        | TokenKind::Keyword(Keyword::Declare)
                );

                if is_stmt_keyword && t.span.start > start {
                    // A WITH statement's own main query head (the first
                    // top-level SELECT/INSERT/UPDATE/DELETE/MERGE) belongs
                    // to this statement — consume it once, then resume
                    // detecting the genuinely next statement.
                    let is_query_head = matches!(
                        t.kind,
                        TokenKind::Keyword(Keyword::Select)
                            | TokenKind::Keyword(Keyword::Insert)
                            | TokenKind::Keyword(Keyword::Update)
                            | TokenKind::Keyword(Keyword::Delete)
                            | TokenKind::Keyword(Keyword::Merge)
                    );
                    if pending_cte_head && is_query_head {
                        pending_cte_head = false;
                    } else {
                        // Found next statement, don't consume it
                        break;
                    }
                }
            }

            end = t.span.end;
            self.advance();
        }

        // Debug: print the parse error that caused fallback to OpaqueContent
        #[cfg(debug_assertions)]
        {
            let debug_file = std::env::var("LEXEGA_DEBUG_FILE").unwrap_or_default();
            if !debug_file.is_empty() {
                eprintln!("DEBUG: OpaqueContent fallback in file: {}", debug_file);
            }
            eprintln!(
                "DEBUG: OpaqueContent fallback at [{start}..{end}], error: {:?}",
                _e
            );
            // Show tokens around error position
            let err_pos = _e.span.start as usize;
            let tokens_around: Vec<_> = self
                .tokens
                .iter()
                .filter(|t| {
                    t.span.start >= err_pos.saturating_sub(50) as u32
                        && t.span.end <= (err_pos + 50) as u32
                })
                .take(10)
                .map(|t| format!("{:?}@{}", t.kind, t.span.start))
                .collect();
            eprintln!("DEBUG: Tokens around error: {:?}", tokens_around);
        }

        // Create opaque content node that will be emitted verbatim
        AstStmt::OpaqueContent {
            node_id: self.id_gen.next(),
            span: Span { start, end },
        }
    }

    /// Parse a script, returning a Result with error information.
    pub(crate) fn try_parse_script(&mut self) -> crate::error::ParseResult<AstScript> {
        let mut stmts = Vec::new();
        let mut loop_count = 0;

        // Guard against infinite loops, but scale the cap with input size.
        // Each loop iteration should consume at least one non-trivia token (or EOF/;).
        // Using a dynamic cap prevents legitimate large scripts (thousands of statements)
        // from failing while still catching "no progress" parser bugs.
        let max_loops = self.tokens.len().saturating_add(128).max(1000);
        loop {
            loop_count += 1;
            if loop_count > max_loops {
                // Return error instead of panicking - this indicates parser is stuck
                let span = Span {
                    start: self.tokens.first().map(|t| t.span.start).unwrap_or(0),
                    end: self.tokens.last().map(|t| t.span.end).unwrap_or(0),
                };
                return Err(ParseError::new(
                    span,
                    ParseErrorKind::Internal {
                        message: format!(
                            "Parser loop exceeded {max_loops} iterations - possible infinite loop"
                        ),
                    },
                ));
            }
            self.skip_trivia();
            let tok = match self.peek_non_trivia() {
                Some(t) => t,
                None => break,
            };
            // Stop at EOF-equivalent.
            if matches!(tok.kind, TokenKind::Eof) {
                break;
            }
            // Skip lone semicolons between statements
            if matches!(
                tok.kind,
                TokenKind::Punctuation(crate::lexer::Punctuation::Semi)
            ) {
                let _ = self.advance();
                continue;
            }
            // For scripting blocks (BEGIN/DECLARE...BEGIN), parse via the dedicated
            // scripting entrypoint. Use Result-based version for better error messages.
            //
            // Dispatch position, captured so a failed statement can rewind and
            // degrade to OpaqueContent (see stmt_or_opaque/opaque_recover).
            let saved_idx = self.idx;
            let stmt_start = tok.span.start;
            let stmt = match &tok.kind {
                TokenKind::Keyword(Keyword::Declare) => {
                    let result = if self.dialect.declare_starts_block() {
                        // Snowflake/PG/MySQL: DECLARE...BEGIN...END is a single block
                        self.try_parse_scripting_block()
                    } else {
                        // BigQuery/MSSQL/Databricks: DECLARE is an independent top-level statement
                        crate::parser::scripting::try_parse_declare_stmt(self)
                    };
                    self.stmt_or_opaque(result, saved_idx, stmt_start)
                }
                TokenKind::Keyword(Keyword::Begin) => {
                    // Need to disambiguate: BEGIN TRANSACTION/WORK vs BEGIN TRY vs BEGIN...END block
                    // Per Snowflake docs:
                    //   - BEGIN [WORK | TRANSACTION] [NAME <name>] - transaction control
                    //   - BEGIN ... END - scripting block
                    // MSSQL:
                    //   - BEGIN TRY ... END TRY BEGIN CATCH ... END CATCH - error handling
                    // Transaction if followed by: semicolon, WORK, TRANSACTION, NAME, or EOF
                    // Otherwise it's a scripting block
                    let _ = self.advance(); // Skip BEGIN
                    self.skip_trivia();

                    let is_transaction = if let Some(next_tok) = self.peek_non_trivia() {
                        match &next_tok.kind {
                            // Explicit transaction keywords
                            TokenKind::Keyword(Keyword::Transaction)
                            | TokenKind::Keyword(Keyword::Work) => true,
                            // Semicolon = standalone BEGIN; transaction
                            TokenKind::Punctuation(crate::lexer::Punctuation::Semi) => true,
                            // NAME identifier for named transactions (BEGIN NAME T1)
                            TokenKind::Identifier { .. } => {
                                next_tok.lexeme(self.source).eq_ignore_ascii_case("NAME")
                            }
                            // Anything else = scripting block body
                            _ => false,
                        }
                    } else {
                        // No token after BEGIN = EOF, assume transaction
                        true
                    };

                    let is_try = if let Some(next_tok) = self.peek_non_trivia() {
                        matches!(next_tok.kind, TokenKind::Keyword(Keyword::Try))
                    } else {
                        false
                    };

                    self.idx = saved_idx; // Restore position

                    let result = if is_transaction {
                        self.try_parse_begin_transaction_stmt()
                    } else if is_try {
                        crate::parser::scripting::try_parse_mssql_try_catch(self)
                    } else {
                        // It's a BEGIN...END block
                        self.try_parse_block_stmt()
                    };
                    self.stmt_or_opaque(result, saved_idx, stmt_start)
                }
                // Jinja comment at statement level: {# comment #}
                TokenKind::JinjaComment => {
                    // Simple placeholder for comments
                    let jinja_tok = self.advance().ok_or_else(|| {
                        ParseError::unexpected_eof(
                            self.current_span(),
                            vec!["Jinja comment".to_string()],
                        )
                    })?;
                    AstStmt::JinjaPlaceholder {
                        node_id: self.id_gen.next(),
                        span: jinja_tok.span,
                        kind: crate::ast::JinjaKind::Comment,
                        expr: None,
                        stmt: None,
                    }
                }
                // Top-level label detection: identifier/keyword followed by colon followed by loop/block keyword
                // e.g., outer: BEGIN SELECT 1; END outer;
                TokenKind::Identifier { .. } | TokenKind::Keyword(..)
                    if crate::parser::scripting::is_label_before_loop_at(
                        self.tokens,
                        self.idx,
                        self.source,
                    ) =>
                {
                    let begin_start = tok.span.start;
                    let result =
                        crate::parser::scripting::parse_label_and_dispatch(self, begin_start);
                    self.stmt_or_opaque(result, saved_idx, stmt_start)
                }
                // All other statements - parse_flow_statement handles both regular and pipe chain cases
                _ => {
                    let result = self.parse_flow_statement();
                    self.stmt_or_opaque(result, saved_idx, stmt_start)
                }
            };
            // Advance parser position to after the parsed statement
            // For DECLARE blocks, we need to update our position
            if matches!(&stmt, AstStmt::Block { .. })
                && matches!(tok.kind, TokenKind::Keyword(Keyword::Declare))
            {
                // Find where the block ends and advance past it
                // The statement span tells us where it ends in the source
                let stmt_end = stmt.span().end;
                while let Some(t) = self.peek() {
                    if t.span.start >= stmt_end {
                        break;
                    }
                    self.advance();
                }
            }

            // Just push the statement directly
            stmts.push(stmt);
        }

        // Move the syntax arena into the AstScript
        let syntax_arena = std::mem::take(&mut self.syntax_arena);

        Ok(AstScript {
            node_id: self.id_gen.next(),
            stmts,
            syntax_arena,
            redaction_spans: std::mem::take(&mut self.redaction_spans),
        })
    }

    /// Parse a statement, returning a Result with error information.
    pub(crate) fn parse_statement(&mut self) -> crate::error::ParseResult<AstStmt> {
        use crate::error::{ExpectInvariant, ParseError, ParseErrorKind};

        // Guard against deep recursion
        let _depth = self.track_depth("parse_statement")?;

        self.skip_trivia();
        let first = self.peek_non_trivia().ok_or_else(|| {
            ParseError::unexpected_eof(self.current_span(), vec!["statement".to_string()])
        })?;

        let result = match &first.kind {
            // Jinja expression at statement level: {{ config(...) }}
            TokenKind::JinjaExprOpen => {
                let start_tok = self.advance().ok_or_else(|| {
                    ParseError::unexpected_eof(
                        self.current_span(),
                        vec!["Jinja expression".to_string()],
                    )
                })?;
                let start_span = start_tok.span;

                // Parse the inner expression
                let expr = self.parse_jinja_expr()?;

                // Consume closing delimiter
                let close_tok = self.advance().ok_or_else(|| {
                    ParseError::unexpected_eof(self.current_span(), vec!["}}".to_string()])
                })?;

                // Check for optional trailing semicolon
                let end = if let Some(semi_tok) = self.peek_non_trivia() {
                    if matches!(
                        semi_tok.kind,
                        TokenKind::Punctuation(crate::lexer::Punctuation::Semi)
                    ) {
                        let semi = self.advance().expect_invariant("semicolon after peek");
                        semi.span.end
                    } else {
                        close_tok.span.end
                    }
                } else {
                    close_tok.span.end
                };

                let full_span = Span {
                    start: start_span.start,
                    end,
                };

                Ok(AstStmt::JinjaPlaceholder {
                    node_id: self.id_gen.next(),
                    span: full_span,
                    kind: crate::ast::JinjaKind::Expression,
                    expr,
                    stmt: None,
                })
            }
            // Jinja statement block at statement level: {% if %} ... {% endif %}
            TokenKind::JinjaStmtOpen => {
                // Check if this is a control flow block (if/for)
                if let Some(kind) = self.peek_jinja_block_kind() {
                    match kind {
                        crate::ast::JinjaBlockKind::If | crate::ast::JinjaBlockKind::For => {
                            // Parse as Jinja statement block (multi-delimiter: opening + closing)
                            if let Some(block) = self.try_parse_jinja_stmt_block(kind) {
                                return Ok(AstStmt::JinjaConditionalStmt(Box::new(block)));
                            }
                        }
                        crate::ast::JinjaBlockKind::Docs => {
                            // Multi-line block: {% docs name %}...{% enddocs %}
                            return self.parse_docs_block();
                        }
                        crate::ast::JinjaBlockKind::Set => {
                            // Two forms of set:
                            // 1. Inline: {% set var = value %}
                            // 2. Block: {% set var %}...{% endset %}

                            let start_tok = self.advance().ok_or_else(|| {
                                ParseError::unexpected_eof(
                                    self.current_span(),
                                    vec!["{%".to_string()],
                                )
                            })?; // {%
                            let _open_brace_id = self.last_token_id();
                            let _keyword_tok = self.advance().ok_or_else(|| {
                                ParseError::unexpected_eof(
                                    self.current_span(),
                                    vec!["set keyword".to_string()],
                                )
                            })?; // set
                            let _keyword_id = self.last_token_id();

                            // Peek ahead to determine which form this is
                            // Look for variable name, then check if next token is = or %}
                            let var_name_tok = self.peek();
                            if let Some(var_tok) = var_name_tok {
                                if matches!(var_tok.kind, TokenKind::Identifier { .. }) {
                                    self.advance(); // consume variable name

                                    // Check next token
                                    if let Some(next_tok) = self.peek() {
                                        if matches!(next_tok.kind, TokenKind::JinjaStmtClose) {
                                            // Block form: {% set var %}...{% endset %}
                                            return self.parse_set_block(start_tok.span.start);
                                        }
                                        // Otherwise fall through to inline form
                                    }
                                    // Reset to before variable name for parse_jinja_set_stmt
                                    self.idx -= 1;
                                }
                            }

                            // Inline form: {% set var = value %}
                            let stmt = self.parse_jinja_set_stmt();

                            let close_tok = self.advance().ok_or_else(|| {
                                ParseError::unexpected_eof(
                                    self.current_span(),
                                    vec!["%}".to_string()],
                                )
                            })?; // %}
                            let _close_brace_id = self.last_token_id();

                            let full_span = Span {
                                start: start_tok.span.start,
                                end: close_tok.span.end,
                            };

                            return Ok(AstStmt::JinjaPlaceholder {
                                node_id: self.id_gen.next(),
                                span: full_span,
                                kind: crate::ast::JinjaKind::Statement,
                                expr: None,
                                stmt,
                            });
                        }
                        crate::ast::JinjaBlockKind::EndIf
                        | crate::ast::JinjaBlockKind::EndFor
                        | crate::ast::JinjaBlockKind::EndSet
                        | crate::ast::JinjaBlockKind::Else
                        | crate::ast::JinjaBlockKind::Elif
                        | crate::ast::JinjaBlockKind::EndDocs => {
                            // These are end/middle tags that should be handled within their parent blocks.
                            // If we see them at statement level, treat as simple placeholder.
                            // This can happen in test scenarios or malformed templates.
                            let start_tok = self.advance().ok_or_else(|| {
                                ParseError::unexpected_eof(
                                    self.current_span(),
                                    vec!["{%".to_string()],
                                )
                            })?; // {%
                            let _keyword_tok = self.advance().ok_or_else(|| {
                                ParseError::unexpected_eof(
                                    self.current_span(),
                                    vec!["jinja keyword".to_string()],
                                )
                            })?; // endif/endfor/else/elif/enddocs

                            // For elif, we might have a condition expression - skip it
                            // For now, just consume until %}
                            while let Some(tok) = self.peek() {
                                if matches!(tok.kind, TokenKind::JinjaStmtClose) {
                                    break;
                                }
                                let _ = self.advance();
                            }

                            let close_tok = self.advance().ok_or_else(|| {
                                ParseError::unexpected_eof(
                                    self.current_span(),
                                    vec!["%}".to_string()],
                                )
                            })?; // %}

                            let full_span = Span {
                                start: start_tok.span.start,
                                end: close_tok.span.end,
                            };

                            return Ok(AstStmt::JinjaPlaceholder {
                                node_id: self.id_gen.next(),
                                span: full_span,
                                kind: crate::ast::JinjaKind::Statement,
                                expr: None,
                                stmt: None,
                            });
                        }
                    }
                }
                // Fall through to error if not a recognized block
                let tok = first;
                Err(ParseError::new(
                    tok.span,
                    ParseErrorKind::InvalidStatement {
                        message: format!(
                            "Unexpected token '{}' at start of statement. Expected a SQL keyword (SELECT, INSERT, UPDATE, CREATE, etc.)",
                            tok.lexeme(self.source)
                        ),
                    },
                ))
            }
            // Jinja comment at statement level: {# comment #}
            TokenKind::JinjaComment => {
                // Simple placeholder for comments
                let jinja_tok = self.advance().ok_or_else(|| {
                    ParseError::unexpected_eof(
                        self.current_span(),
                        vec!["Jinja comment".to_string()],
                    )
                })?;
                Ok(AstStmt::JinjaPlaceholder {
                    node_id: self.id_gen.next(),
                    span: jinja_tok.span,
                    kind: crate::ast::JinjaKind::Comment,
                    expr: None,
                    stmt: None,
                })
            }
            // MSSQL batch separator: GO
            // Keep it as opaque content so formatter preserves it verbatim,
            // but parse it explicitly to avoid fallback-error recovery paths.
            TokenKind::Identifier { .. }
                if self.dialect.supports_go_batch_separator()
                    && first.lexeme(self.source).eq_ignore_ascii_case("GO") =>
            {
                let go_tok = self.advance().ok_or_else(|| {
                    ParseError::unexpected_eof(self.current_span(), vec!["GO".to_string()])
                })?;

                // Optional repeat count: GO <positive_integer>
                let mut count_span: Option<Span> = None;
                let mut end = go_tok.span.end;
                if let Some(next_tok) = self.peek_non_trivia() {
                    if matches!(
                        next_tok.kind,
                        TokenKind::Literal(crate::lexer::LiteralKind::Number)
                    ) {
                        let count_tok = self.advance().ok_or_else(|| {
                            ParseError::unexpected_eof(
                                self.current_span(),
                                vec!["GO repeat count".to_string()],
                            )
                        })?;
                        count_span = Some(count_tok.span);
                        end = count_tok.span.end;
                    }
                }

                Ok(AstStmt::GoBatchSeparator {
                    node_id: self.id_gen.next(),
                    span: Span {
                        start: go_tok.span.start,
                        end,
                    },
                    count_span,
                })
            }
            // Snowflake client file commands: PUT / GET / REMOVE / RM / LIST / LS.
            // Top-level statements (not CREATE/ALTER/DROP), keyed on the verb.
            TokenKind::Identifier { .. }
                if matches!(
                    first.lexeme(self.source).to_ascii_uppercase().as_str(),
                    "PUT" | "GET" | "REMOVE" | "RM" | "LIST" | "LS"
                ) =>
            {
                self.try_parse_stage_file_command()
            }
            // SET session variable statement
            TokenKind::Keyword(Keyword::Set) => {
                if self.dialect.supports_mysql_set_grammar() {
                    self.try_parse_mysql_set_stmt()
                } else if self.dialect.supports_session_config_set() {
                    self.try_parse_pg_set_stmt()
                } else if self.dialect.set_distinguishes_options() {
                    // MSSQL: distinguish SET option ON/OFF from SET @var = expr
                    // Lookahead: SET <ident> ... ON/OFF  vs  SET @var = expr
                    let saved_idx = self.idx;
                    let _ = self.advance(); // skip SET
                    self.skip_trivia();
                    let is_set_option = if let Some(next) = self.peek_non_trivia() {
                        matches!(
                            next.kind,
                            TokenKind::Identifier {
                                kind: crate::lexer::IdentifierKind::Unquoted
                            } // `SET TRANSACTION ISOLATION LEVEL <level>` — TRANSACTION
                              // is a keyword, not an unquoted identifier, so it needs an
                              // explicit gate to reach the set-option parser.
                        ) || matches!(next.kind, TokenKind::Keyword(Keyword::Transaction))
                    } else {
                        false
                    };
                    self.idx = saved_idx;
                    if is_set_option {
                        crate::parser::scripting::try_parse_mssql_set_option(self)
                    } else {
                        self.try_parse_set_variable_stmt()
                    }
                } else {
                    self.try_parse_set_variable_stmt()
                }
            }
            // SELECT statements and set operations (UNION/INTERSECT/EXCEPT)
            TokenKind::Keyword(Keyword::Select)
            | TokenKind::Keyword(Keyword::With)
            | TokenKind::Punctuation(crate::lexer::Punctuation::LParen) => {
                self.try_parse_set_or_select_stmt()
            }
            // MySQL `TABLE tbl [ORDER BY ...] [LIMIT ...]` — query-bearing,
            // routed through the query parser (recognized in set-operand).
            TokenKind::Keyword(Keyword::Table) if self.dialect.supports_table_query_statement() => {
                self.try_parse_set_or_select_stmt()
            }
            // Standalone VALUES query (PostgreSQL): VALUES (1,'a'), (2,'b') [ORDER BY ...] [LIMIT ...]
            TokenKind::Keyword(Keyword::Values) => self.try_parse_values_query_stmt(),
            TokenKind::Keyword(Keyword::Update) => self.try_parse_update_stmt_with_parser(),
            TokenKind::Keyword(Keyword::Delete) => self.try_parse_delete_stmt_with_parser(),
            TokenKind::Keyword(Keyword::Merge) => self.try_parse_merge_stmt_with_parser(),
            TokenKind::Keyword(Keyword::Alter) => {
                // Peek ahead to determine ALTER TABLE vs ALTER STAGE vs ALTER ROW ACCESS POLICY
                let saved_idx = self.idx;
                self.advance(); // Skip ALTER
                self.skip_trivia();

                // MySQL `ALTER [DEFINER = user] EVENT …` (scheduled job).
                // EVENT lexes as a bare identifier, so probe past an optional
                // DEFINER clause to confirm EVENT before the keyword chain.
                let is_alter_event = {
                    let probe = self.idx;
                    self.parse_definer_clause();
                    let yes = self
                        .peek_non_trivia()
                        .map(|t| t.lexeme(self.source).eq_ignore_ascii_case("EVENT"))
                        .unwrap_or(false);
                    self.idx = probe;
                    yes
                };

                if let Some(tok) = self.peek_non_trivia() {
                    let result = if is_alter_event {
                        self.idx = saved_idx;
                        self.try_parse_alter_event()
                    } else if matches!(tok.kind, TokenKind::Keyword(Keyword::Default)) {
                        // PostgreSQL `ALTER DEFAULT PRIVILEGES …`. Dispatched on
                        // DEFAULT (unambiguous: no other `ALTER DEFAULT` form).
                        self.idx = saved_idx;
                        self.try_parse_alter_default_privileges()
                    } else if matches!(tok.kind, TokenKind::Keyword(Keyword::Stage))
                        || tok.lexeme(self.source).eq_ignore_ascii_case("STAGE")
                    {
                        self.idx = saved_idx;
                        self.try_parse_alter_stage_stmt_with_parser()
                    } else if matches!(tok.kind, TokenKind::Keyword(Keyword::Row))
                        || tok.lexeme(self.source).eq_ignore_ascii_case("ROW")
                    {
                        // Check if it's ALTER ROW ACCESS POLICY
                        let _row_idx = self.idx;
                        self.advance(); // skip ROW
                        self.skip_trivia();
                        if let Some(access_tok) = self.peek_non_trivia() {
                            if matches!(access_tok.kind, TokenKind::Keyword(Keyword::Access))
                                || access_tok
                                    .lexeme(self.source)
                                    .eq_ignore_ascii_case("ACCESS")
                            {
                                self.idx = saved_idx;
                                self.try_parse_alter_row_access_policy_stmt()
                            } else {
                                // Not ALTER ROW ACCESS POLICY, try as ALTER TABLE
                                self.idx = saved_idx;
                                self.try_parse_alter_table_stmt_with_parser()
                            }
                        } else {
                            self.idx = saved_idx;
                            self.try_parse_alter_table_stmt_with_parser()
                        }
                    } else if matches!(tok.kind, TokenKind::Identifier { .. })
                        && tok.lexeme(self.source).eq_ignore_ascii_case("MASKING")
                    {
                        // ALTER MASKING POLICY
                        self.idx = saved_idx;
                        self.try_parse_alter_masking_policy()
                    } else if matches!(tok.kind, TokenKind::Identifier { .. })
                        && tok.lexeme(self.source).eq_ignore_ascii_case("NETWORK")
                    {
                        // ALTER NETWORK { POLICY | RULE } — peek the word
                        // after NETWORK to disambiguate.
                        let net_idx = self.idx;
                        self.advance(); // consume NETWORK
                        let is_rule = matches!(
                            self.peek_non_trivia(),
                            Some(t) if matches!(t.kind, TokenKind::Identifier { .. })
                                && t.lexeme(self.source).eq_ignore_ascii_case("RULE")
                        );
                        self.idx = net_idx;
                        self.idx = saved_idx;
                        if is_rule {
                            self.try_parse_alter_network_rule()
                        } else {
                            self.try_parse_alter_network_policy()
                        }
                    } else if matches!(tok.kind, TokenKind::Identifier { .. })
                        && tok.lexeme(self.source).eq_ignore_ascii_case("ALERT")
                    {
                        // ALTER ALERT (Snowflake)
                        self.idx = saved_idx;
                        self.try_parse_alter_alert()
                    } else if matches!(tok.kind, TokenKind::Identifier { .. })
                        && tok.lexeme(self.source).eq_ignore_ascii_case("RESOURCE")
                    {
                        // ALTER RESOURCE MONITOR (Snowflake)
                        self.idx = saved_idx;
                        self.try_parse_alter_resource_monitor()
                    } else if matches!(tok.kind, TokenKind::Identifier { .. })
                        && tok.lexeme(self.source).eq_ignore_ascii_case("COMPUTE")
                    {
                        // ALTER COMPUTE POOL (Snowflake)
                        self.idx = saved_idx;
                        self.try_parse_alter_compute_pool()
                    } else if matches!(tok.kind, TokenKind::Identifier { .. })
                        && tok.lexeme(self.source).eq_ignore_ascii_case("GIT")
                    {
                        // ALTER GIT REPOSITORY (Snowflake)
                        self.idx = saved_idx;
                        self.try_parse_alter_git_repository()
                    } else if matches!(tok.kind, TokenKind::Identifier { .. })
                        && tok.lexeme(self.source).eq_ignore_ascii_case("IMAGE")
                    {
                        // ALTER IMAGE REPOSITORY (Snowflake)
                        self.idx = saved_idx;
                        self.try_parse_alter_image_repository()
                    } else if matches!(tok.kind, TokenKind::Identifier { .. })
                        && tok.lexeme(self.source).eq_ignore_ascii_case("STREAMLIT")
                    {
                        // ALTER STREAMLIT (Snowflake)
                        self.idx = saved_idx;
                        self.try_parse_alter_streamlit()
                    } else if matches!(tok.kind, TokenKind::Identifier { .. })
                        && tok.lexeme(self.source).eq_ignore_ascii_case("NOTEBOOK")
                    {
                        // ALTER NOTEBOOK (Snowflake)
                        self.idx = saved_idx;
                        self.try_parse_alter_notebook()
                    } else if matches!(tok.kind, TokenKind::Identifier { .. })
                        && tok.lexeme(self.source).eq_ignore_ascii_case("SEMANTIC")
                    {
                        // ALTER SEMANTIC VIEW (Snowflake)
                        self.idx = saved_idx;
                        self.try_parse_alter_semantic_view()
                    } else if matches!(tok.kind, TokenKind::Identifier { .. })
                        && tok.lexeme(self.source).eq_ignore_ascii_case("CORTEX")
                    {
                        // ALTER CORTEX SEARCH SERVICE (Snowflake)
                        self.idx = saved_idx;
                        self.try_parse_alter_cortex_search_service()
                    } else if matches!(tok.kind, TokenKind::Identifier { .. })
                        && tok.lexeme(self.source).eq_ignore_ascii_case("LISTING")
                    {
                        // ALTER LISTING (Snowflake Marketplace)
                        self.idx = saved_idx;
                        self.try_parse_alter_listing()
                    } else if matches!(tok.kind, TokenKind::Identifier { .. })
                        && tok.lexeme(self.source).eq_ignore_ascii_case("SESSION")
                    {
                        // ALTER SESSION { POLICY | SET | UNSET } — peek the word
                        // after SESSION to split the policy-object ALTER from the
                        // session-parameter ALTER.
                        let sess_idx = self.idx;
                        self.advance(); // consume SESSION
                        let is_params = matches!(
                            self.peek_non_trivia(),
                            Some(t) if matches!(
                                t.kind,
                                TokenKind::Keyword(Keyword::Set) | TokenKind::Keyword(Keyword::Unset)
                            )
                        );
                        self.idx = sess_idx;
                        self.idx = saved_idx;
                        if is_params {
                            self.try_parse_alter_session()
                        } else {
                            self.try_parse_alter_session_policy()
                        }
                    } else if matches!(tok.kind, TokenKind::Identifier { .. })
                        && tok.lexeme(self.source).eq_ignore_ascii_case("PASSWORD")
                    {
                        // ALTER PASSWORD POLICY
                        self.idx = saved_idx;
                        self.try_parse_alter_password_policy()
                    } else if matches!(tok.kind, TokenKind::Identifier { .. })
                        && tok
                            .lexeme(self.source)
                            .eq_ignore_ascii_case("AUTHENTICATION")
                    {
                        // ALTER AUTHENTICATION POLICY
                        self.idx = saved_idx;
                        self.try_parse_alter_authentication_policy()
                    } else if matches!(tok.kind, TokenKind::Identifier { .. })
                        && tok.lexeme(self.source).eq_ignore_ascii_case("API")
                    {
                        // ALTER API INTEGRATION
                        self.idx = saved_idx;
                        self.try_parse_alter_api_integration()
                    } else if matches!(tok.kind, TokenKind::Keyword(Keyword::Notification)) {
                        // ALTER NOTIFICATION INTEGRATION
                        self.idx = saved_idx;
                        self.try_parse_alter_notification_integration()
                    } else if matches!(tok.kind, TokenKind::Identifier { .. })
                        && tok.lexeme(self.source).eq_ignore_ascii_case("EXTERNAL")
                    {
                        // ALTER EXTERNAL — peek ahead: DATA SOURCE, LOCATION,
                        // MODEL, or ACCESS INTEGRATION?
                        let saved_external = self.idx;
                        self.advance(); // skip EXTERNAL
                        self.skip_trivia();
                        let after_external = self.peek_non_trivia();
                        let is_data = after_external
                            .map(|t| {
                                matches!(t.kind, TokenKind::Identifier { .. })
                                    && t.lexeme(self.source).eq_ignore_ascii_case("DATA")
                            })
                            .unwrap_or(false);
                        let is_location = after_external
                            .map(|t| {
                                matches!(t.kind, TokenKind::Identifier { .. })
                                    && t.lexeme(self.source).eq_ignore_ascii_case("LOCATION")
                            })
                            .unwrap_or(false);
                        let is_model = after_external
                            .map(|t| {
                                matches!(t.kind, TokenKind::Identifier { .. })
                                    && t.lexeme(self.source).eq_ignore_ascii_case("MODEL")
                            })
                            .unwrap_or(false);
                        self.idx = saved_external;

                        if is_data {
                            // ALTER EXTERNAL DATA SOURCE (T-SQL / PolyBase)
                            self.idx = saved_idx;
                            self.try_parse_mssql_alter_external_data_source()
                        } else if is_location {
                            // ALTER EXTERNAL LOCATION (Databricks Unity Catalog)
                            self.idx = saved_idx;
                            self.try_parse_alter_external_location()
                        } else if is_model {
                            // ALTER EXTERNAL MODEL (SQL Server 2025)
                            self.idx = saved_idx;
                            self.try_parse_mssql_alter_external_model()
                        } else {
                            // ALTER EXTERNAL ACCESS INTEGRATION (Snowflake)
                            self.idx = saved_idx;
                            self.try_parse_alter_external_access_integration()
                        }
                    } else if matches!(tok.kind, TokenKind::Keyword(Keyword::Tag)) {
                        // ALTER TAG (Snowflake)
                        self.idx = saved_idx;
                        self.try_parse_alter_tag()
                    } else if matches!(tok.kind, TokenKind::Keyword(Keyword::File)) {
                        // ALTER FILE FORMAT (Snowflake)
                        self.idx = saved_idx;
                        self.try_parse_alter_file_format()
                    } else if matches!(tok.kind, TokenKind::Identifier { .. })
                        && tok.lexeme(self.source).eq_ignore_ascii_case("SECRET")
                    {
                        // ALTER SECRET (Snowflake)
                        self.idx = saved_idx;
                        self.try_parse_alter_secret()
                    } else if matches!(tok.kind, TokenKind::Identifier { .. })
                        && tok.lexeme(self.source).eq_ignore_ascii_case("AGGREGATION")
                    {
                        // ALTER AGGREGATION POLICY
                        self.idx = saved_idx;
                        self.try_parse_alter_aggregation_policy()
                    } else if matches!(tok.kind, TokenKind::Identifier { .. })
                        && tok.lexeme(self.source).eq_ignore_ascii_case("PROJECTION")
                    {
                        // ALTER PROJECTION POLICY
                        self.idx = saved_idx;
                        self.try_parse_alter_projection_policy()
                    } else if matches!(tok.kind, TokenKind::Keyword(Keyword::Join)) {
                        // ALTER JOIN POLICY (JOIN lexes as a keyword)
                        self.idx = saved_idx;
                        self.try_parse_alter_join_policy()
                    } else if matches!(tok.kind, TokenKind::Identifier { .. })
                        && tok.lexeme(self.source).eq_ignore_ascii_case("SCHEMA")
                    {
                        // ALTER SCHEMA
                        self.idx = saved_idx;
                        self.try_parse_alter_schema()
                    } else if (tok.lexeme(self.source).eq_ignore_ascii_case("SERVER")
                        || tok.lexeme(self.source).eq_ignore_ascii_case("DATABASE"))
                        && self
                            .tokens
                            .get(self.idx + 1)
                            .map(|t| t.lexeme(self.source).eq_ignore_ascii_case("AUDIT"))
                            .unwrap_or(false)
                    {
                        // ALTER SERVER AUDIT [SPECIFICATION] / ALTER DATABASE
                        // AUDIT SPECIFICATION — must win over ALTER DATABASE.
                        self.idx = saved_idx;
                        self.try_parse_mssql_audit_ddl_stmt(
                            crate::ast::types::AstMssqlAuditAction::Alter,
                        )
                    } else if self.peek_mssql_security_object_at(tok) {
                        // ALTER { MASTER|SYMMETRIC|ASYMMETRIC KEY |
                        // CERTIFICATE | [DATABASE SCOPED] CREDENTIAL } —
                        // must win over ALTER DATABASE.
                        self.idx = saved_idx;
                        self.try_parse_mssql_security_object_stmt(
                            crate::ast::types::AstMssqlAuditAction::Alter,
                        )
                    } else if tok.lexeme(self.source).eq_ignore_ascii_case("DATABASE")
                        && self
                            .tokens
                            .get(self.idx + 1)
                            .map(|t| t.lexeme(self.source).eq_ignore_ascii_case("ROLE"))
                            .unwrap_or(false)
                        && self
                            .tokens
                            .get(self.idx + 2)
                            .map(|t| {
                                self.can_be_identifier_token(t)
                                    || t.lexeme(self.source).eq_ignore_ascii_case("IF")
                            })
                            .unwrap_or(false)
                    {
                        // ALTER DATABASE ROLE <name> (Snowflake) — principal
                        // substrate. Must win over ALTER DATABASE; the name/IF
                        // guard leaves `ALTER DATABASE <db-named-role>` to it.
                        self.idx = saved_idx;
                        self.try_parse_alter_principal_stmt()
                    } else if matches!(tok.kind, TokenKind::Identifier { .. })
                        && tok.lexeme(self.source).eq_ignore_ascii_case("DATABASE")
                    {
                        // ALTER DATABASE
                        self.idx = saved_idx;
                        self.try_parse_alter_database()
                    } else if matches!(tok.kind, TokenKind::Keyword(Keyword::Storage)) {
                        // ALTER STORAGE — peek next: CREDENTIAL vs INTEGRATION
                        let saved_storage = self.idx;
                        self.advance(); // consume STORAGE
                        self.skip_trivia();
                        let after_storage = self.peek_non_trivia();
                        let is_credential = after_storage
                            .map(|t| {
                                matches!(t.kind, TokenKind::Identifier { .. })
                                    && t.lexeme(self.source).eq_ignore_ascii_case("CREDENTIAL")
                            })
                            .unwrap_or(false);
                        self.idx = saved_storage;

                        if is_credential {
                            // ALTER STORAGE CREDENTIAL (Databricks Unity Catalog)
                            self.idx = saved_idx;
                            self.try_parse_alter_storage_credential()
                        } else {
                            // ALTER [STORAGE] INTEGRATION
                            self.idx = saved_idx;
                            self.try_parse_alter_storage_integration()
                        }
                    } else if matches!(tok.kind, TokenKind::Keyword(Keyword::Integration))
                        || tok.lexeme(self.source).eq_ignore_ascii_case("INTEGRATION")
                    {
                        // ALTER INTEGRATION
                        self.idx = saved_idx;
                        self.try_parse_alter_storage_integration()
                    } else if tok.lexeme(self.source).eq_ignore_ascii_case("TASK") {
                        // ALTER TASK
                        self.idx = saved_idx;
                        crate::parser::task::try_parse_alter_task(self)
                    } else if tok.lexeme(self.source).eq_ignore_ascii_case("WAREHOUSE") {
                        // ALTER WAREHOUSE
                        self.idx = saved_idx;
                        crate::parser::warehouse::try_parse_alter_warehouse(self)
                    } else if tok.lexeme(self.source).eq_ignore_ascii_case("PIPE") {
                        // ALTER PIPE
                        self.idx = saved_idx;
                        crate::parser::pipe::try_parse_alter_pipe(self)
                    } else if tok.lexeme(self.source).eq_ignore_ascii_case("STREAM") {
                        // ALTER STREAM
                        self.idx = saved_idx;
                        crate::parser::stream::try_parse_alter_stream(self)
                    } else if tok.lexeme(self.source).eq_ignore_ascii_case("DYNAMIC") {
                        // ALTER DYNAMIC TABLE
                        self.idx = saved_idx;
                        crate::parser::dynamic_table::try_parse_alter_dynamic_table(self)
                    } else if matches!(tok.kind, TokenKind::Keyword(Keyword::Function)) {
                        // ALTER FUNCTION
                        self.idx = saved_idx;
                        crate::parser::alter_function::try_parse_alter_function(self)
                    } else if matches!(tok.kind, TokenKind::Keyword(Keyword::Procedure)) {
                        // ALTER PROCEDURE
                        self.idx = saved_idx;
                        crate::parser::alter_procedure::try_parse_alter_procedure(self)
                    } else if matches!(tok.kind, TokenKind::Identifier { .. })
                        && tok.lexeme(self.source).eq_ignore_ascii_case("SEQUENCE")
                    {
                        // ALTER SEQUENCE (PostgreSQL)
                        self.idx = saved_idx;
                        self.try_parse_alter_sequence_stmt()
                    } else if matches!(tok.kind, TokenKind::Keyword(Keyword::Trigger)) {
                        // ALTER TRIGGER (PostgreSQL)
                        self.idx = saved_idx;
                        self.try_parse_alter_pg_trigger_stmt()
                    } else if matches!(tok.kind, TokenKind::Keyword(Keyword::Type)) {
                        // ALTER TYPE (PostgreSQL)
                        self.idx = saved_idx;
                        self.try_parse_alter_type_stmt()
                    } else if matches!(tok.kind, TokenKind::Identifier { .. })
                        && tok.lexeme(self.source).eq_ignore_ascii_case("DOMAIN")
                    {
                        // ALTER DOMAIN (PostgreSQL)
                        self.idx = saved_idx;
                        self.try_parse_alter_domain_stmt()
                    } else if matches!(tok.kind, TokenKind::Keyword(Keyword::Policy)) {
                        // ALTER POLICY (PostgreSQL RLS)
                        self.idx = saved_idx;
                        self.try_parse_alter_pg_policy_stmt()
                    } else if matches!(tok.kind, TokenKind::Identifier { .. })
                        && tok.lexeme(self.source).eq_ignore_ascii_case("INDEX")
                    {
                        // ALTER INDEX (PostgreSQL)
                        self.idx = saved_idx;
                        self.try_parse_alter_index_stmt()
                    } else if matches!(tok.kind, TokenKind::Identifier { .. })
                        && tok.lexeme(self.source).eq_ignore_ascii_case("SYSTEM")
                    {
                        // ALTER SYSTEM (PostgreSQL runtime config)
                        self.idx = saved_idx;
                        self.try_parse_pg_alter_system_stmt()
                    } else if matches!(tok.kind, TokenKind::Identifier { .. })
                        && tok.lexeme(self.source).eq_ignore_ascii_case("PUBLICATION")
                    {
                        // ALTER PUBLICATION (PostgreSQL logical replication)
                        self.idx = saved_idx;
                        self.try_parse_pg_publication_stmt()
                    } else if matches!(tok.kind, TokenKind::Identifier { .. })
                        && tok.lexeme(self.source).eq_ignore_ascii_case("SUBSCRIPTION")
                    {
                        // ALTER SUBSCRIPTION (PostgreSQL logical replication)
                        self.idx = saved_idx;
                        self.try_parse_pg_subscription_stmt()
                    } else if matches!(tok.kind, TokenKind::Identifier { .. })
                        && tok.lexeme(self.source).eq_ignore_ascii_case("TABLESPACE")
                    {
                        // ALTER TABLESPACE (PostgreSQL storage management)
                        self.idx = saved_idx;
                        self.try_parse_pg_alter_tablespace_stmt()
                    } else if crate::parser::user_mapping::is_user_mapping_at(
                        self.tokens,
                        saved_idx,
                        self.source,
                    ) {
                        // ALTER USER MAPPING … FOR … (SQL/MED) — must win over
                        // the ALTER USER principal arm below, which would
                        // mislabel it as a role change.
                        self.idx = saved_idx;
                        self.try_parse_alter_user_mapping()
                    } else if matches!(tok.kind, TokenKind::Identifier { .. })
                        && tok.lexeme(self.source).eq_ignore_ascii_case("USER")
                    {
                        // ALTER USER — peek for the AUTHENTICATION POLICY
                        // attachment slice; otherwise fall through to the
                        // dialect-neutral principal substrate.
                        self.idx = saved_idx;
                        if self.peek_alter_user_authpol_attachment_at() {
                            self.try_parse_alter_user_authpol_attachment()
                        } else {
                            self.try_parse_alter_principal_stmt()
                        }
                    } else if matches!(tok.kind, TokenKind::Identifier { .. })
                        && tok.lexeme(self.source).eq_ignore_ascii_case("ROLE")
                    {
                        // ALTER ROLE — dialect-neutral principal substrate.
                        self.idx = saved_idx;
                        self.try_parse_alter_principal_stmt()
                    } else if matches!(tok.kind, TokenKind::Identifier { .. })
                        && tok.lexeme(self.source).eq_ignore_ascii_case("LOGIN")
                    {
                        // ALTER LOGIN (T-SQL) — dialect-neutral principal
                        // substrate.
                        self.idx = saved_idx;
                        self.try_parse_alter_principal_stmt()
                    } else if tok.lexeme(self.source).eq_ignore_ascii_case("SERVER")
                        && self
                            .tokens
                            .get(self.idx + 1)
                            .map(|t| t.lexeme(self.source).eq_ignore_ascii_case("ROLE"))
                            .unwrap_or(false)
                    {
                        // ALTER SERVER ROLE (T-SQL) — principal substrate
                        // with server scope. (Token stream is significant-
                        // only, so idx+1 is the next meaningful token.)
                        self.idx = saved_idx;
                        self.try_parse_alter_principal_stmt()
                    } else if tok.lexeme(self.source).eq_ignore_ascii_case("SERVER")
                        && self
                            .tokens
                            .get(self.idx + 1)
                            .map(|t| t.lexeme(self.source).eq_ignore_ascii_case("CONFIGURATION"))
                            .unwrap_or(false)
                        && self
                            .tokens
                            .get(self.idx + 2)
                            .map(|t| t.lexeme(self.source).eq_ignore_ascii_case("SET"))
                            .unwrap_or(false)
                    {
                        // ALTER SERVER CONFIGURATION SET … (T-SQL instance
                        // config) — distinct from the SQL/MED foreign server
                        // below. SERVER AUDIT / SERVER ROLE matched above.
                        // The `SET` peek is the sound discriminator: T-SQL
                        // CONFIGURATION takes no name and is always SET-led,
                        // whereas a PG/MySQL foreign server coincidentally named
                        // "configuration" is followed by VERSION/OPTIONS/OWNER/
                        // RENAME (never SET), so it falls through below.
                        self.idx = saved_idx;
                        self.try_parse_mssql_alter_server_configuration()
                    } else if tok.lexeme(self.source).eq_ignore_ascii_case("SERVER") {
                        // ALTER SERVER <name> … (SQL/MED foreign server,
                        // PostgreSQL / MySQL FDW).
                        self.idx = saved_idx;
                        self.try_parse_alter_foreign_server()
                    } else if tok.lexeme(self.source).eq_ignore_ascii_case("APPLICATION")
                        && self
                            .tokens
                            .get(self.idx + 1)
                            .map(|t| t.lexeme(self.source).eq_ignore_ascii_case("ROLE"))
                            .unwrap_or(false)
                    {
                        // ALTER APPLICATION ROLE (T-SQL) — principal substrate.
                        self.idx = saved_idx;
                        self.try_parse_alter_principal_stmt()
                    } else if tok.lexeme(self.source).eq_ignore_ascii_case("APPLICATION")
                        && self
                            .tokens
                            .get(self.idx + 1)
                            .map(|t| t.lexeme(self.source).eq_ignore_ascii_case("PACKAGE"))
                            .unwrap_or(false)
                    {
                        // ALTER APPLICATION PACKAGE (Snowflake Native Apps).
                        // Must follow the APPLICATION ROLE arm above.
                        self.idx = saved_idx;
                        self.try_parse_alter_application_package()
                    } else if tok.lexeme(self.source).eq_ignore_ascii_case("APPLICATION") {
                        // ALTER APPLICATION (Snowflake Native Apps consumer install).
                        self.idx = saved_idx;
                        self.try_parse_alter_application()
                    } else if tok
                        .lexeme(self.source)
                        .eq_ignore_ascii_case("AUTHORIZATION")
                    {
                        // ALTER AUTHORIZATION (T-SQL ownership transfer).
                        self.idx = saved_idx;
                        self.try_parse_alter_authorization_stmt()
                    } else if matches!(tok.kind, TokenKind::Identifier { .. })
                        && tok.lexeme(self.source).eq_ignore_ascii_case("ASSEMBLY")
                    {
                        // ALTER ASSEMBLY (T-SQL CLR assembly)
                        self.idx = saved_idx;
                        self.try_parse_alter_mssql_assembly()
                    } else if matches!(tok.kind, TokenKind::Keyword(Keyword::Group)) {
                        // ALTER GROUP (Redshift permission group) — GROUP lexes as
                        // Keyword(Group), not an identifier, so match the keyword.
                        // ADD/DROP USER / RENAME TO ride the principal options body.
                        self.idx = saved_idx;
                        self.try_parse_alter_principal_stmt()
                    } else if matches!(tok.kind, TokenKind::Identifier { .. })
                        && tok.lexeme(self.source).eq_ignore_ascii_case("ACCOUNT")
                    {
                        // ALTER ACCOUNT — peek for the AUTHENTICATION POLICY
                        // attachment slice; otherwise route to the generic
                        // ALTER ACCOUNT SET/UNSET property parser.
                        self.idx = saved_idx;
                        if self.peek_alter_account_authpol_attachment_at() {
                            self.try_parse_alter_account_authpol_attachment()
                        } else {
                            self.try_parse_alter_account_generic()
                        }
                    } else if matches!(tok.kind, TokenKind::Identifier { .. })
                        && tok.lexeme(self.source).eq_ignore_ascii_case("SHARE")
                    {
                        // ALTER SHARE (Snowflake data sharing)
                        self.idx = saved_idx;
                        self.try_parse_alter_share()
                    } else if matches!(tok.kind, TokenKind::Identifier { .. })
                        && tok.lexeme(self.source).eq_ignore_ascii_case("DATASHARE")
                    {
                        // ALTER DATASHARE (Redshift cross-account data sharing)
                        self.idx = saved_idx;
                        self.try_parse_alter_datashare()
                    } else if matches!(tok.kind, TokenKind::Identifier { .. })
                        && tok.lexeme(self.source).eq_ignore_ascii_case("SECURITY")
                        && self
                            .tokens
                            .get(self.idx + 1)
                            .map(|t| t.lexeme(self.source).eq_ignore_ascii_case("POLICY"))
                            .unwrap_or(false)
                    {
                        // ALTER SECURITY POLICY (T-SQL Row-Level Security)
                        self.idx = saved_idx;
                        self.try_parse_alter_mssql_security_policy()
                    } else if matches!(tok.kind, TokenKind::Identifier { .. })
                        && tok.lexeme(self.source).eq_ignore_ascii_case("SECURITY")
                    {
                        // ALTER SECURITY INTEGRATION (Snowflake)
                        self.idx = saved_idx;
                        self.try_parse_alter_security_integration()
                    } else if matches!(tok.kind, TokenKind::Identifier { .. })
                        && tok.lexeme(self.source).eq_ignore_ascii_case("REPLICATION")
                    {
                        // ALTER REPLICATION GROUP (Snowflake DR)
                        self.idx = saved_idx;
                        self.try_parse_alter_replication_group()
                    } else if matches!(tok.kind, TokenKind::Identifier { .. })
                        && tok.lexeme(self.source).eq_ignore_ascii_case("FAILOVER")
                    {
                        // ALTER FAILOVER GROUP (Snowflake DR)
                        self.idx = saved_idx;
                        self.try_parse_alter_failover_group()
                    } else if matches!(tok.kind, TokenKind::Identifier { .. })
                        && tok.lexeme(self.source).eq_ignore_ascii_case("MATERIALIZED")
                    {
                        // ALTER MATERIALIZED VIEW (BigQuery)
                        self.idx = saved_idx;
                        self.try_parse_alter_materialized_view()
                    } else if matches!(tok.kind, TokenKind::Keyword(Keyword::View)) {
                        // ALTER VIEW (BigQuery / Snowflake / PostgreSQL — permissive)
                        self.idx = saved_idx;
                        self.try_parse_alter_view()
                    } else if matches!(tok.kind, TokenKind::Identifier { .. })
                        && tok.lexeme(self.source).eq_ignore_ascii_case("RULE")
                    {
                        // ALTER RULE (PostgreSQL)
                        self.idx = saved_idx;
                        self.try_parse_pg_alter_rule_stmt()
                    } else if matches!(tok.kind, TokenKind::Identifier { .. })
                        && tok.lexeme(self.source).eq_ignore_ascii_case("VECTOR")
                    {
                        // ALTER VECTOR INDEX (BigQuery)
                        self.idx = saved_idx;
                        self.try_parse_bq_alter_vector_index()
                    } else if matches!(tok.kind, TokenKind::Identifier { .. })
                        && tok.lexeme(self.source).eq_ignore_ascii_case("MODEL")
                    {
                        // ALTER MODEL (BigQuery BQML)
                        self.idx = saved_idx;
                        self.try_parse_bq_alter_model()
                    } else if matches!(tok.kind, TokenKind::Identifier { .. })
                        && tok.lexeme(self.source).eq_ignore_ascii_case("CATALOG")
                    {
                        // ALTER CATALOG (Databricks Unity Catalog)
                        self.idx = saved_idx;
                        self.try_parse_alter_catalog()
                    } else if matches!(tok.kind, TokenKind::Identifier { .. })
                        && tok.lexeme(self.source).eq_ignore_ascii_case("VOLUME")
                    {
                        // ALTER VOLUME (Databricks Unity Catalog)
                        self.idx = saved_idx;
                        self.try_parse_alter_volume()
                    } else if matches!(tok.kind, TokenKind::Identifier { .. })
                        && tok.lexeme(self.source).eq_ignore_ascii_case("CREDENTIAL")
                    {
                        // Bare ALTER CREDENTIAL — dialect grammar decides
                        // (T-SQL identity/secret vs Databricks storage).
                        self.idx = saved_idx;
                        if self.dialect.bare_credential_is_identity_secret() {
                            self.try_parse_mssql_security_object_stmt(
                                crate::ast::types::AstMssqlAuditAction::Alter,
                            )
                        } else {
                            self.try_parse_alter_storage_credential()
                        }
                    } else if matches!(tok.kind, TokenKind::Identifier { .. })
                        && tok.lexeme(self.source).eq_ignore_ascii_case("SERVICE")
                    {
                        // ALTER SERVICE — peek next: MASTER (T-SQL SMK) or
                        // CREDENTIAL (Databricks)?
                        let saved_svc = self.idx;
                        self.advance(); // skip SERVICE
                        self.skip_trivia();
                        let after_svc = self.peek_non_trivia();
                        let after_svc_lex = after_svc.map(|t| t.lexeme(self.source));
                        let is_svc_master = after_svc_lex
                            .map(|l| l.eq_ignore_ascii_case("MASTER"))
                            .unwrap_or(false);
                        let is_svc_credential = after_svc
                            .map(|t| {
                                matches!(t.kind, TokenKind::Identifier { .. })
                                    && t.lexeme(self.source).eq_ignore_ascii_case("CREDENTIAL")
                            })
                            .unwrap_or(false);
                        self.idx = saved_svc;

                        if is_svc_master {
                            // ALTER SERVICE MASTER KEY (T-SQL encryption-root rotation)
                            self.idx = saved_idx;
                            self.try_parse_alter_service_master_key()
                        } else if is_svc_credential {
                            // ALTER SERVICE CREDENTIAL (Databricks Unity Catalog)
                            self.idx = saved_idx;
                            self.try_parse_alter_storage_credential()
                        } else {
                            // ALTER SERVICE (Snowflake / Snowpark Container Services)
                            self.idx = saved_idx;
                            self.try_parse_alter_service()
                        }
                    } else if matches!(tok.kind, TokenKind::Identifier { .. })
                        && tok.lexeme(self.source).eq_ignore_ascii_case("CONNECTION")
                    {
                        // ALTER CONNECTION (Databricks Unity Catalog)
                        self.idx = saved_idx;
                        self.try_parse_alter_connection()
                    } else if matches!(tok.kind, TokenKind::Keyword(Keyword::Table)) {
                        // Could be ALTER TABLE ... ENABLE/DISABLE TRIGGER or normal ALTER TABLE
                        // Peek ahead: ALTER TABLE <name> ENABLE/DISABLE
                        let table_saved = self.idx;
                        self.advance(); // skip TABLE
                        self.skip_trivia();
                        // Skip table name (may be schema.table)
                        while let Some(t) = self.peek_non_trivia() {
                            if matches!(
                                t.kind,
                                TokenKind::Identifier { .. } | TokenKind::Keyword(_)
                            ) {
                                self.advance();
                                if let Some(dot) = self.peek_non_trivia() {
                                    if matches!(
                                        dot.kind,
                                        TokenKind::Punctuation(crate::lexer::Punctuation::Dot)
                                    ) {
                                        self.advance(); // skip dot
                                        continue;
                                    }
                                }
                                break;
                            } else {
                                break;
                            }
                        }
                        self.skip_trivia();
                        // ENABLE/DISABLE is the trigger-state form ONLY when the
                        // tail is TRIGGER. ENABLE/DISABLE ROW LEVEL SECURITY is a
                        // normal ALTER TABLE action — divert it to the generic
                        // parser, not the trigger-state parser.
                        let is_trigger_state = if let Some(next) = self.peek_non_trivia() {
                            let is_enable =
                                matches!(next.kind, TokenKind::Keyword(Keyword::Enable));
                            let is_toggle = is_enable
                                || (matches!(next.kind, TokenKind::Identifier { .. })
                                    && next.lexeme(self.source).eq_ignore_ascii_case("DISABLE"));
                            if is_toggle {
                                self.advance(); // ENABLE | DISABLE
                                                // Optional REPLICA | ALWAYS (ENABLE only).
                                if is_enable {
                                    if let Some(t) = self.peek_non_trivia() {
                                        if matches!(t.kind, TokenKind::Identifier { .. })
                                            && (t
                                                .lexeme(self.source)
                                                .eq_ignore_ascii_case("REPLICA")
                                                || t.lexeme(self.source)
                                                    .eq_ignore_ascii_case("ALWAYS"))
                                        {
                                            self.advance();
                                        }
                                    }
                                }
                                self.peek_non_trivia().is_some_and(|t| {
                                    t.lexeme(self.source).eq_ignore_ascii_case("TRIGGER")
                                })
                            } else {
                                false
                            }
                        } else {
                            false
                        };
                        self.idx = table_saved;
                        if is_trigger_state {
                            // It's ALTER TABLE ... ENABLE/DISABLE TRIGGER
                            self.idx = saved_idx;
                            self.try_parse_pg_alter_table_trigger_state_stmt()
                        } else {
                            // Normal ALTER TABLE
                            self.idx = saved_idx;
                            self.try_parse_alter_table_stmt_with_parser()
                        }
                    } else {
                        self.idx = saved_idx;
                        self.try_parse_alter_table_stmt_with_parser()
                    };
                    result
                } else {
                    self.idx = saved_idx;
                    self.try_parse_alter_table_stmt_with_parser()
                }
            }
            TokenKind::Keyword(Keyword::Show) => self.try_parse_show_stmt_with_parser(),
            TokenKind::Keyword(Keyword::Describe) => {
                // Check for Databricks DESCRIBE HISTORY
                let saved = self.idx;
                self.advance(); // consume DESCRIBE
                if let Some(next) = self.peek_non_trivia() {
                    if matches!(next.kind, TokenKind::Identifier { .. })
                        && next.lexeme(self.source).eq_ignore_ascii_case("HISTORY")
                    {
                        self.idx = saved;
                        return self.try_parse_describe_history_stmt();
                    }
                }
                self.idx = saved;
                self.try_parse_describe_stmt_with_parser()
            }
            TokenKind::Keyword(Keyword::Use) => self.try_parse_use_stmt_with_parser(),
            TokenKind::Keyword(Keyword::Truncate) => self.try_parse_truncate_stmt_with_parser(),
            TokenKind::Keyword(Keyword::Rename)
                if crate::parser::mysql_rename_table::is_rename_table_at(self.tokens, self.idx) =>
            {
                // MySQL RENAME TABLE a TO b [, c TO d]
                self.try_parse_mysql_rename_table()
            }
            TokenKind::Keyword(Keyword::Drop)
                if crate::parser::user_mapping::is_user_mapping_at(
                    self.tokens,
                    self.idx,
                    self.source,
                ) =>
            {
                // DROP USER MAPPING … FOR … (SQL/MED) — must win over the
                // generic DROP parser, which would mislabel it as DROP USER.
                self.try_parse_drop_user_mapping()
            }
            TokenKind::Keyword(Keyword::Drop) => self.try_parse_drop_stmt_with_parser(),
            TokenKind::Keyword(Keyword::Copy) => {
                // Redshift:   COPY table FROM 's3://...' <inline-credential auth>
                // PostgreSQL: COPY table FROM/TO 'file' [WITH (...)]
                // Snowflake:  COPY INTO table FROM/TO ...
                if self.dialect.copy_has_inline_credentials() {
                    self.try_parse_redshift_copy_stmt()
                } else if self.dialect.supports_copy_to_from_table() {
                    self.try_parse_pg_copy_stmt()
                } else {
                    self.try_parse_copy_into_stmt_with_parser()
                }
            }
            // PostgreSQL: CLUSTER [table [USING index]]
            TokenKind::Keyword(Keyword::Cluster) if self.dialect.supports_cluster_statement() => {
                self.try_parse_pg_cluster_stmt()
            }
            // PostgreSQL: REFRESH MATERIALIZED VIEW
            TokenKind::Keyword(Keyword::Refresh)
                if self.dialect.supports_refresh_materialized_view() =>
            {
                self.try_parse_pg_refresh_matview_stmt()
            }
            TokenKind::Keyword(Keyword::Insert) => {
                // Route to unified INSERT parser that auto-detects multi-insert
                self.try_parse_insert_stmt_in_mode()
            }
            // MySQL REPLACE [INTO] — statement-position only, so no
            // collision with the REPLACE() function.
            TokenKind::Keyword(Keyword::Replace) => self.try_parse_replace_into_stmt(),
            // Transaction control statements
            TokenKind::Keyword(Keyword::Commit) => self.try_parse_commit_stmt(),
            TokenKind::Keyword(Keyword::Rollback) => self.try_parse_rollback_stmt(),
            // Procedure call
            TokenKind::Keyword(Keyword::Call) => {
                crate::parser::scripting::try_parse_call_stmt(self)
            }
            // ODBC call escape: {call p(...)} / {? = call p(...)}
            TokenKind::Punctuation(crate::lexer::Punctuation::LCurly)
                if crate::parser::scripting::is_odbc_call_escape_at(self) =>
            {
                crate::parser::scripting::try_parse_odbc_call_stmt(self)
            }
            // EXECUTE: dialect-gated
            //   MSSQL:      EXEC[UTE] proc_name @p1=val — procedure invocation
            //   PostgreSQL: EXECUTE name [(args)]  — prepared statement execution
            //   Snowflake:  EXECUTE IMMEDIATE expr — dynamic SQL
            TokenKind::Keyword(Keyword::Execute) => {
                if self.dialect.supports_exec_procedure_call() {
                    self.try_parse_mssql_exec_stmt()
                } else if self.dialect.supports_prepared_statement_execution() {
                    self.try_parse_pg_execute_stmt()
                } else {
                    crate::parser::scripting::try_parse_execute_immediate_stmt(self)
                }
            }
            // DCL statements (GRANT/REVOKE/DENY)
            //
            // GRANT grammars diverge enough across dialects (optional ON
            // clause, multi-grantee, class qualifiers, IAM-role principals)
            // that we dispatch to dialect-specific parsers keyed on the
            // dialect's declared GrantGrammar rather than branching inside the
            // shared Snowflake-shaped typed parser.
            TokenKind::Keyword(Keyword::Grant) => match self.dialect.grant_grammar() {
                crate::dialect::GrantGrammar::ClassQualifiedSecurable => {
                    crate::parser::mssql_grant::parse_grant_mssql(self)
                }
                crate::dialect::GrantGrammar::ObjectTypePrivilegeLevel => {
                    crate::parser::mysql_grant::parse_grant_mysql(self)
                }
                crate::dialect::GrantGrammar::IamRole => {
                    crate::parser::bq_grant::parse_grant_bq(self)
                }
                crate::dialect::GrantGrammar::Standard => self.try_parse_grant_stmt(),
            },
            TokenKind::Keyword(Keyword::Revoke) => match self.dialect.grant_grammar() {
                crate::dialect::GrantGrammar::ClassQualifiedSecurable => {
                    crate::parser::mssql_revoke::parse_revoke_mssql(self)
                }
                crate::dialect::GrantGrammar::ObjectTypePrivilegeLevel
                | crate::dialect::GrantGrammar::IamRole
                | crate::dialect::GrantGrammar::Standard => self.try_parse_revoke_stmt(),
            },
            TokenKind::Keyword(Keyword::Deny) => self.try_parse_deny_stmt(),
            // PostgreSQL: COMMENT ON
            TokenKind::Keyword(Keyword::Comment) => self.try_parse_comment_on_stmt(),
            // PostgreSQL: DO $$ ... $$
            TokenKind::Keyword(Keyword::Do) => self.try_parse_do_block_stmt(),
            TokenKind::Keyword(Keyword::Create) => {
                // Peek ahead to check what type of CREATE statement this is
                let saved_idx = self.idx;
                self.advance(); // Skip CREATE

                // Skip optional OR REPLACE / OR ALTER
                self.skip_trivia();
                if let Some(tok) = self.peek() {
                    if tok.lexeme(self.source).eq_ignore_ascii_case("OR") {
                        self.advance(); // OR
                        self.skip_trivia();
                        if let Some(tok) = self.peek() {
                            if tok.lexeme(self.source).eq_ignore_ascii_case("REPLACE")
                                || tok.lexeme(self.source).eq_ignore_ascii_case("ALTER")
                                || tok.lexeme(self.source).eq_ignore_ascii_case("REFRESH")
                            {
                                self.advance(); // REPLACE or ALTER or REFRESH
                                self.skip_trivia();
                            }
                        }
                    }
                }

                // Skip optional MySQL view `ALGORITHM = { … }` clause (precedes
                // DEFINER / SQL SECURITY / VIEW) so the dispatch lookahead
                // reaches VIEW. Lookahead only — the view parser rewinds and
                // re-consumes it. Require the `=` to avoid eating a view named
                // ALGORITHM.
                if let Some(tok) = self.peek() {
                    if tok.lexeme(self.source).eq_ignore_ascii_case("ALGORITHM")
                        && self
                            .peek_ahead(1)
                            .map(|t| matches!(t.kind, TokenKind::Operator(Operator::Eq)))
                            .unwrap_or(false)
                    {
                        self.advance(); // ALGORITHM
                        self.skip_trivia();
                        self.advance(); // =
                        self.skip_trivia();
                        self.advance(); // kind
                        self.skip_trivia();
                    }
                }

                // Skip optional MySQL `DEFINER = user` clause (precedes
                // EVENT / PROCEDURE / FUNCTION / TRIGGER / VIEW) so the
                // dispatch lookahead sees the real object keyword. Each
                // sub-parser rewinds to CREATE and re-consumes it.
                self.parse_definer_clause();

                // Skip optional MySQL view `SQL SECURITY { DEFINER | INVOKER }`
                // clause (precedes VIEW). Lookahead only — re-consumed by the
                // view parser.
                if let Some(tok) = self.peek() {
                    if tok.lexeme(self.source).eq_ignore_ascii_case("SQL")
                        && self
                            .peek_ahead(1)
                            .map(|t| t.lexeme(self.source).eq_ignore_ascii_case("SECURITY"))
                            .unwrap_or(false)
                    {
                        self.advance(); // SQL
                        self.skip_trivia();
                        self.advance(); // SECURITY
                        self.skip_trivia();
                        self.advance(); // DEFINER | INVOKER
                        self.skip_trivia();
                    }
                }

                // Databricks DLT: optional LIVE keyword before TABLE
                if let Some(tok) = self.peek() {
                    if tok.lexeme(self.source).eq_ignore_ascii_case("LIVE") {
                        self.advance();
                        self.skip_trivia();
                    }
                }

                // Skip optional SECURE keyword (for views)
                if let Some(tok) = self.peek() {
                    if tok.lexeme(self.source).eq_ignore_ascii_case("SECURE") {
                        self.advance();
                        self.skip_trivia();
                    }
                }

                // Skip temp modifiers: LOCAL/GLOBAL TEMP/TEMPORARY/VOLATILE/TRANSIENT
                if let Some(tok) = self.peek() {
                    if tok.lexeme(self.source).eq_ignore_ascii_case("LOCAL")
                        || tok.lexeme(self.source).eq_ignore_ascii_case("GLOBAL")
                    {
                        self.advance();
                        self.skip_trivia();
                    }
                    if let Some(tok) = self.peek() {
                        if tok.lexeme(self.source).eq_ignore_ascii_case("TEMP")
                            || tok.lexeme(self.source).eq_ignore_ascii_case("TEMPORARY")
                            || tok.lexeme(self.source).eq_ignore_ascii_case("VOLATILE")
                            || tok.lexeme(self.source).eq_ignore_ascii_case("TRANSIENT")
                            || tok.lexeme(self.source).eq_ignore_ascii_case("UNLOGGED")
                        {
                            self.advance();
                            self.skip_trivia();
                        }
                    }
                }

                // Skip optional RECURSIVE keyword (for views)
                if let Some(tok) = self.peek() {
                    if tok.lexeme(self.source).eq_ignore_ascii_case("RECURSIVE") {
                        self.advance();
                        self.skip_trivia();
                    }
                }

                // Skip AGGREGATE modifier only when followed by FUNCTION (BigQuery UDAF)
                // This distinguishes CREATE AGGREGATE FUNCTION (BigQuery) from
                // CREATE AGGREGATE name(...) (PostgreSQL)
                if let Some(tok) = self.peek() {
                    if tok.lexeme(self.source).eq_ignore_ascii_case("AGGREGATE") {
                        // Peek one more token ahead to check for FUNCTION
                        let agg_idx = self.idx;
                        self.advance();
                        self.skip_trivia();
                        if let Some(next_tok) = self.peek() {
                            if next_tok
                                .lexeme(self.source)
                                .eq_ignore_ascii_case("FUNCTION")
                            {
                                // AGGREGATE FUNCTION → skip AGGREGATE, leave cursor on FUNCTION
                                // (don't advance past FUNCTION — it becomes create_type_lexeme)
                            } else {
                                // Not followed by FUNCTION → restore (PostgreSQL CREATE AGGREGATE)
                                self.idx = agg_idx;
                            }
                        } else {
                            self.idx = agg_idx;
                        }
                    }
                }

                // Check what follows to determine statement type
                let create_type_lexeme = self.peek().map(|t| t.lexeme(self.source) as &str);
                // Token after the type lexeme — distinguishes two-token
                // types (`SERVER ROLE` vs Databricks `SERVER`). The token
                // stream is significant-only, so idx+1 is the next
                // meaningful token.
                let create_type_next_lexeme = self
                    .tokens
                    .get(self.idx + 1)
                    .map(|t| t.lexeme(self.source) as &str);
                // Token after the two-token type — disambiguates
                // `CREATE DATABASE ROLE <name>` (a Snowflake database role)
                // from `CREATE DATABASE <name>` where the database is named
                // `role`: the former is followed by a name token or `IF`.
                let create_type_third_is_name = self
                    .tokens
                    .get(self.idx + 2)
                    .map(|t| {
                        self.can_be_identifier_token(t)
                            || t.lexeme(self.source).eq_ignore_ascii_case("IF")
                    })
                    .unwrap_or(false);

                // Restore position
                self.idx = saved_idx;

                // Route based on CREATE type
                if create_type_lexeme
                    .map(|s| s.eq_ignore_ascii_case("DYNAMIC"))
                    .unwrap_or(false)
                {
                    // CREATE DYNAMIC TABLE
                    crate::parser::dynamic_table::try_parse_create_dynamic_table(self)
                } else if create_type_lexeme
                    .map(|s| {
                        s.eq_ignore_ascii_case("ICEBERG")
                            || s.eq_ignore_ascii_case("HYBRID")
                            || s.eq_ignore_ascii_case("EVENT")
                    })
                    .unwrap_or(false)
                    && create_type_next_lexeme
                        .map(|s| s.eq_ignore_ascii_case("TABLE"))
                        .unwrap_or(false)
                {
                    // CREATE { ICEBERG | HYBRID | EVENT } TABLE — Snowflake table
                    // variants. The kind keyword is captured by the table parser;
                    // routing only needs to reach it. These are treated as
                    // table-kind modifiers ONLY when immediately followed by TABLE,
                    // so a bare `CREATE EVENT <name>` is left for other handlers.
                    self.try_parse_create_table_stmt()
                } else if create_type_lexeme
                    .map(|s| s.eq_ignore_ascii_case("EVENT"))
                    .unwrap_or(false)
                {
                    // CREATE [DEFINER = user] EVENT <name> … (MySQL scheduled
                    // job). The EVENT TABLE arm above already claimed the
                    // `EVENT TABLE` form, so this is the bare scheduled event.
                    self.try_parse_create_event()
                } else if create_type_lexeme
                    .map(|s| s.eq_ignore_ascii_case("FILE"))
                    .unwrap_or(false)
                    && create_type_next_lexeme
                        .map(|s| s.eq_ignore_ascii_case("FORMAT"))
                        .unwrap_or(false)
                {
                    // CREATE [OR REPLACE] [{TEMP|TEMPORARY|VOLATILE}] FILE FORMAT
                    // (Snowflake). `FILE FORMAT` is two keywords; the single
                    // `FILE_FORMAT=` token in COPY/stage is unrelated.
                    self.try_parse_create_file_format()
                } else if create_type_lexeme
                    .map(|s| s.eq_ignore_ascii_case("TABLE"))
                    .unwrap_or(false)
                {
                    // Peek one more token ahead to distinguish CREATE TABLE vs CREATE TABLE FUNCTION
                    // We're at saved_idx, so we need to re-skip modifiers + TABLE and peek for FUNCTION
                    let saved_idx2 = self.idx;
                    // Re-skip to where create_type_lexeme was found (after modifiers)
                    // Skip CREATE
                    self.advance();
                    self.skip_trivia();
                    // Skip OR REPLACE
                    if let Some(tok) = self.peek() {
                        if tok.lexeme(self.source).eq_ignore_ascii_case("OR") {
                            self.advance();
                            self.skip_trivia();
                            if let Some(tok) = self.peek() {
                                if tok.lexeme(self.source).eq_ignore_ascii_case("REPLACE")
                                    || tok.lexeme(self.source).eq_ignore_ascii_case("ALTER")
                                    || tok.lexeme(self.source).eq_ignore_ascii_case("REFRESH")
                                {
                                    self.advance();
                                    self.skip_trivia();
                                }
                            }
                        }
                    }
                    // Optional LIVE before TABLE (Databricks DLT)
                    if let Some(tok) = self.peek() {
                        if tok.lexeme(self.source).eq_ignore_ascii_case("LIVE") {
                            self.advance();
                            self.skip_trivia();
                        }
                    }
                    // Skip SECURE, temp modifiers, RECURSIVE (same as above)
                    if let Some(tok) = self.peek() {
                        if tok.lexeme(self.source).eq_ignore_ascii_case("SECURE") {
                            self.advance();
                            self.skip_trivia();
                        }
                    }
                    if let Some(tok) = self.peek() {
                        if tok.lexeme(self.source).eq_ignore_ascii_case("LOCAL")
                            || tok.lexeme(self.source).eq_ignore_ascii_case("GLOBAL")
                        {
                            self.advance();
                            self.skip_trivia();
                        }
                        if let Some(tok) = self.peek() {
                            if tok.lexeme(self.source).eq_ignore_ascii_case("TEMP")
                                || tok.lexeme(self.source).eq_ignore_ascii_case("TEMPORARY")
                                || tok.lexeme(self.source).eq_ignore_ascii_case("VOLATILE")
                                || tok.lexeme(self.source).eq_ignore_ascii_case("TRANSIENT")
                                || tok.lexeme(self.source).eq_ignore_ascii_case("UNLOGGED")
                            {
                                self.advance();
                                self.skip_trivia();
                            }
                        }
                    }
                    if let Some(tok) = self.peek() {
                        if tok.lexeme(self.source).eq_ignore_ascii_case("RECURSIVE") {
                            self.advance();
                            self.skip_trivia();
                        }
                    }
                    // Now we should be at TABLE — skip it
                    self.advance();
                    self.skip_trivia();
                    // Check if next token is FUNCTION
                    let is_table_function = self
                        .peek()
                        .map(|t| t.lexeme(self.source).eq_ignore_ascii_case("FUNCTION"))
                        .unwrap_or(false);
                    self.idx = saved_idx2;

                    if is_table_function {
                        // CREATE TABLE FUNCTION (BigQuery TVF)
                        crate::parser::scripting::parse_create_table_function(self)
                    } else {
                        self.try_parse_create_table_stmt()
                    }
                } else if create_type_lexeme
                    .map(|s| s.eq_ignore_ascii_case("VIEW"))
                    .unwrap_or(false)
                {
                    self.try_parse_create_view_stmt_with_parser()
                } else if create_type_lexeme
                    .map(|s| s.eq_ignore_ascii_case("MATERIALIZED"))
                    .unwrap_or(false)
                {
                    // CREATE [OR REPLACE] [SECURE] MATERIALIZED VIEW ...
                    // The view parser handles the MATERIALIZED keyword internally
                    self.try_parse_create_view_stmt_with_parser()
                } else if create_type_lexeme
                    .map(|s| s.eq_ignore_ascii_case("STAGE"))
                    .unwrap_or(false)
                {
                    self.try_parse_create_stage_stmt_with_parser()
                } else if create_type_lexeme
                    .map(|s| s.eq_ignore_ascii_case("ROW"))
                    .unwrap_or(false)
                {
                    // CREATE ROW ACCESS POLICY
                    self.try_parse_create_row_access_policy()
                } else if create_type_lexeme
                    .map(|s| s.eq_ignore_ascii_case("MASKING"))
                    .unwrap_or(false)
                {
                    // CREATE MASKING POLICY
                    self.try_parse_create_masking_policy()
                } else if create_type_lexeme
                    .map(|s| s.eq_ignore_ascii_case("ALERT"))
                    .unwrap_or(false)
                {
                    // CREATE ALERT (Snowflake)
                    self.try_parse_create_alert()
                } else if create_type_lexeme
                    .map(|s| s.eq_ignore_ascii_case("RESOURCE"))
                    .unwrap_or(false)
                    && create_type_next_lexeme
                        .map(|s| s.eq_ignore_ascii_case("MONITOR"))
                        .unwrap_or(false)
                {
                    // CREATE RESOURCE MONITOR (Snowflake)
                    self.try_parse_create_resource_monitor()
                } else if create_type_lexeme
                    .map(|s| s.eq_ignore_ascii_case("COMPUTE"))
                    .unwrap_or(false)
                    && create_type_next_lexeme
                        .map(|s| s.eq_ignore_ascii_case("POOL"))
                        .unwrap_or(false)
                {
                    // CREATE COMPUTE POOL (Snowflake / Snowpark Container Services)
                    self.try_parse_create_compute_pool()
                } else if create_type_lexeme
                    .map(|s| s.eq_ignore_ascii_case("GIT"))
                    .unwrap_or(false)
                    && create_type_next_lexeme
                        .map(|s| s.eq_ignore_ascii_case("REPOSITORY"))
                        .unwrap_or(false)
                {
                    // CREATE GIT REPOSITORY (Snowflake)
                    self.try_parse_create_git_repository()
                } else if create_type_lexeme
                    .map(|s| s.eq_ignore_ascii_case("IMAGE"))
                    .unwrap_or(false)
                    && create_type_next_lexeme
                        .map(|s| s.eq_ignore_ascii_case("REPOSITORY"))
                        .unwrap_or(false)
                {
                    // CREATE IMAGE REPOSITORY (Snowflake / Snowpark Container Services)
                    self.try_parse_create_image_repository()
                } else if create_type_lexeme
                    .map(|s| s.eq_ignore_ascii_case("STREAMLIT"))
                    .unwrap_or(false)
                {
                    // CREATE STREAMLIT (Snowflake)
                    self.try_parse_create_streamlit()
                } else if create_type_lexeme
                    .map(|s| s.eq_ignore_ascii_case("NOTEBOOK"))
                    .unwrap_or(false)
                {
                    // CREATE NOTEBOOK (Snowflake)
                    self.try_parse_create_notebook()
                } else if create_type_lexeme
                    .map(|s| s.eq_ignore_ascii_case("SEMANTIC"))
                    .unwrap_or(false)
                    && create_type_next_lexeme
                        .map(|s| s.eq_ignore_ascii_case("VIEW"))
                        .unwrap_or(false)
                {
                    // CREATE SEMANTIC VIEW (Snowflake)
                    self.try_parse_create_semantic_view()
                } else if create_type_lexeme
                    .map(|s| s.eq_ignore_ascii_case("CORTEX"))
                    .unwrap_or(false)
                    && create_type_next_lexeme
                        .map(|s| s.eq_ignore_ascii_case("SEARCH"))
                        .unwrap_or(false)
                {
                    // CREATE CORTEX SEARCH SERVICE (Snowflake)
                    self.try_parse_create_cortex_search_service()
                } else if create_type_lexeme
                    .map(|s| s.eq_ignore_ascii_case("NETWORK"))
                    .unwrap_or(false)
                    && create_type_next_lexeme
                        .map(|s| s.eq_ignore_ascii_case("RULE"))
                        .unwrap_or(false)
                {
                    // CREATE NETWORK RULE (Snowflake)
                    self.try_parse_create_network_rule()
                } else if create_type_lexeme
                    .map(|s| s.eq_ignore_ascii_case("NETWORK"))
                    .unwrap_or(false)
                {
                    // CREATE NETWORK POLICY
                    self.try_parse_create_network_policy()
                } else if create_type_lexeme
                    .map(|s| s.eq_ignore_ascii_case("SESSION"))
                    .unwrap_or(false)
                {
                    // CREATE SESSION POLICY
                    self.try_parse_create_session_policy()
                } else if create_type_lexeme
                    .map(|s| s.eq_ignore_ascii_case("PASSWORD"))
                    .unwrap_or(false)
                {
                    // CREATE PASSWORD POLICY
                    self.try_parse_create_password_policy()
                } else if create_type_lexeme
                    .map(|s| s.eq_ignore_ascii_case("AUTHENTICATION"))
                    .unwrap_or(false)
                {
                    // CREATE AUTHENTICATION POLICY
                    self.try_parse_create_authentication_policy()
                } else if create_type_lexeme
                    .map(|s| s.eq_ignore_ascii_case("API"))
                    .unwrap_or(false)
                {
                    // CREATE API INTEGRATION
                    self.try_parse_create_api_integration()
                } else if create_type_lexeme
                    .map(|s| s.eq_ignore_ascii_case("NOTIFICATION"))
                    .unwrap_or(false)
                {
                    // CREATE NOTIFICATION INTEGRATION
                    self.try_parse_create_notification_integration()
                } else if create_type_lexeme
                    .map(|s| s.eq_ignore_ascii_case("SHARE"))
                    .unwrap_or(false)
                {
                    // CREATE SHARE (Snowflake data sharing)
                    self.try_parse_create_share()
                } else if create_type_lexeme
                    .map(|s| s.eq_ignore_ascii_case("DATASHARE"))
                    .unwrap_or(false)
                {
                    // CREATE DATASHARE (Redshift cross-account data sharing)
                    self.try_parse_create_datashare()
                } else if create_type_lexeme
                    .map(|s| s.eq_ignore_ascii_case("ASSEMBLY"))
                    .unwrap_or(false)
                {
                    // CREATE ASSEMBLY (T-SQL CLR assembly)
                    self.try_parse_create_mssql_assembly()
                } else if create_type_lexeme
                    .map(|s| s.eq_ignore_ascii_case("SECURITY"))
                    .unwrap_or(false)
                    && create_type_next_lexeme
                        .map(|s| s.eq_ignore_ascii_case("POLICY"))
                        .unwrap_or(false)
                {
                    // CREATE SECURITY POLICY (T-SQL Row-Level Security)
                    self.try_parse_create_mssql_security_policy()
                } else if create_type_lexeme
                    .map(|s| s.eq_ignore_ascii_case("SECURITY"))
                    .unwrap_or(false)
                {
                    // CREATE SECURITY INTEGRATION (Snowflake)
                    self.try_parse_create_security_integration()
                } else if create_type_lexeme
                    .map(|s| s.eq_ignore_ascii_case("EXTERNAL"))
                    .unwrap_or(false)
                {
                    // Disambiguate: CREATE EXTERNAL TABLE vs CREATE EXTERNAL ACCESS INTEGRATION vs CREATE EXTERNAL VOLUME
                    // Peek past modifiers and EXTERNAL to see what follows
                    let saved_idx2 = self.idx;
                    // Re-skip to where create_type_lexeme was found
                    self.advance(); // CREATE
                    self.skip_trivia();
                    // Skip optional OR { REPLACE | ALTER | REFRESH }
                    if let Some(tok) = self.peek() {
                        if tok.lexeme(self.source).eq_ignore_ascii_case("OR") {
                            self.advance();
                            self.skip_trivia();
                            if let Some(tok) = self.peek() {
                                if tok.lexeme(self.source).eq_ignore_ascii_case("REPLACE")
                                    || tok.lexeme(self.source).eq_ignore_ascii_case("ALTER")
                                    || tok.lexeme(self.source).eq_ignore_ascii_case("REFRESH")
                                {
                                    self.advance();
                                    self.skip_trivia();
                                }
                            }
                        }
                    }
                    // Skip optional SECURE (Snowflake `CREATE SECURE EXTERNAL
                    // FUNCTION`) so the token after EXTERNAL is peeked correctly.
                    if let Some(tok) = self.peek() {
                        if tok.lexeme(self.source).eq_ignore_ascii_case("SECURE") {
                            self.advance();
                            self.skip_trivia();
                        }
                    }
                    // Now at EXTERNAL — skip it
                    self.advance();
                    self.skip_trivia();
                    // Check what follows: TABLE → BQ external table, VOLUME → Databricks volume, else → SF integration
                    let next_after_external = self.peek();
                    let is_external_table = next_after_external
                        .map(|t| matches!(t.kind, TokenKind::Keyword(Keyword::Table)))
                        .unwrap_or(false);
                    let is_external_volume = next_after_external
                        .map(|t| {
                            matches!(t.kind, TokenKind::Identifier { .. })
                                && t.lexeme(self.source).eq_ignore_ascii_case("VOLUME")
                        })
                        .unwrap_or(false);
                    let is_external_location = next_after_external
                        .map(|t| {
                            matches!(t.kind, TokenKind::Identifier { .. })
                                && t.lexeme(self.source).eq_ignore_ascii_case("LOCATION")
                        })
                        .unwrap_or(false);
                    let is_external_model = next_after_external
                        .map(|t| {
                            matches!(t.kind, TokenKind::Identifier { .. })
                                && t.lexeme(self.source).eq_ignore_ascii_case("MODEL")
                        })
                        .unwrap_or(false);
                    let is_external_schema = next_after_external
                        .map(|t| {
                            matches!(t.kind, TokenKind::Identifier { .. })
                                && t.lexeme(self.source).eq_ignore_ascii_case("SCHEMA")
                        })
                        .unwrap_or(false);
                    let is_external_listing = next_after_external
                        .map(|t| {
                            matches!(t.kind, TokenKind::Identifier { .. })
                                && t.lexeme(self.source).eq_ignore_ascii_case("LISTING")
                        })
                        .unwrap_or(false);
                    // CREATE EXTERNAL DATA SOURCE (T-SQL / PolyBase): EXTERNAL
                    // followed by the identifier DATA.
                    let is_external_data_source = next_after_external
                        .map(|t| {
                            matches!(t.kind, TokenKind::Identifier { .. })
                                && t.lexeme(self.source).eq_ignore_ascii_case("DATA")
                        })
                        .unwrap_or(false);
                    // CREATE EXTERNAL FUNCTION (Snowflake): EXTERNAL followed by
                    // the FUNCTION keyword.
                    let is_external_function = next_after_external
                        .map(|t| matches!(t.kind, TokenKind::Keyword(Keyword::Function)))
                        .unwrap_or(false);
                    self.idx = saved_idx2;

                    if is_external_table {
                        // CREATE [OR REPLACE] EXTERNAL TABLE (BigQuery / Snowflake)
                        self.idx = saved_idx;
                        self.try_parse_create_external_table()
                    } else if is_external_schema {
                        // CREATE EXTERNAL SCHEMA (Redshift Spectrum / federated)
                        self.idx = saved_idx;
                        self.try_parse_create_external_schema()
                    } else if is_external_volume {
                        // CREATE EXTERNAL VOLUME (Databricks Unity Catalog)
                        self.idx = saved_idx;
                        self.try_parse_create_volume()
                    } else if is_external_location {
                        // CREATE EXTERNAL LOCATION (Databricks Unity Catalog)
                        self.idx = saved_idx;
                        self.try_parse_create_external_location()
                    } else if is_external_model {
                        // CREATE EXTERNAL MODEL (MSSQL SQL Server 2025)
                        self.idx = saved_idx;
                        self.try_parse_mssql_create_external_model()
                    } else if is_external_listing {
                        // CREATE EXTERNAL LISTING (Snowflake Marketplace)
                        self.idx = saved_idx;
                        self.try_parse_create_listing()
                    } else if is_external_data_source {
                        // CREATE EXTERNAL DATA SOURCE (T-SQL / PolyBase)
                        self.idx = saved_idx;
                        self.try_parse_mssql_create_external_data_source()
                    } else if is_external_function {
                        // CREATE EXTERNAL FUNCTION (Snowflake)
                        self.idx = saved_idx;
                        self.try_parse_create_external_function()
                    } else {
                        // CREATE EXTERNAL ACCESS INTEGRATION (Snowflake)
                        self.try_parse_create_external_access_integration()
                    }
                } else if create_type_lexeme
                    .map(|s| s.eq_ignore_ascii_case("LISTING"))
                    .unwrap_or(false)
                {
                    // CREATE LISTING (Snowflake — internal data exchange listing)
                    self.try_parse_create_listing()
                } else if create_type_lexeme
                    .map(|s| s.eq_ignore_ascii_case("MANAGED"))
                    .unwrap_or(false)
                    && create_type_next_lexeme
                        .map(|s| s.eq_ignore_ascii_case("ACCOUNT"))
                        .unwrap_or(false)
                {
                    // CREATE MANAGED ACCOUNT (Snowflake reader account)
                    self.try_parse_create_managed_account()
                } else if create_type_lexeme
                    .map(|s| s.eq_ignore_ascii_case("ACCOUNT"))
                    .unwrap_or(false)
                {
                    // CREATE ACCOUNT (Snowflake org-level account provisioning)
                    self.try_parse_create_account()
                } else if create_type_lexeme
                    .map(|s| s.eq_ignore_ascii_case("TAG"))
                    .unwrap_or(false)
                {
                    // CREATE TAG (Snowflake)
                    self.try_parse_create_tag()
                } else if create_type_lexeme
                    .map(|s| s.eq_ignore_ascii_case("SECRET"))
                    .unwrap_or(false)
                {
                    // CREATE SECRET (Snowflake)
                    self.try_parse_create_secret()
                } else if create_type_lexeme
                    .map(|s| s.eq_ignore_ascii_case("AGGREGATION"))
                    .unwrap_or(false)
                {
                    // CREATE AGGREGATION POLICY
                    self.try_parse_create_aggregation_policy()
                } else if create_type_lexeme
                    .map(|s| s.eq_ignore_ascii_case("PROJECTION"))
                    .unwrap_or(false)
                {
                    // CREATE PROJECTION POLICY
                    self.try_parse_create_projection_policy()
                } else if create_type_lexeme
                    .map(|s| s.eq_ignore_ascii_case("JOIN"))
                    .unwrap_or(false)
                {
                    // CREATE JOIN POLICY (Snowflake)
                    self.try_parse_create_join_policy()
                } else if create_type_lexeme
                    .map(|s| s.eq_ignore_ascii_case("DATA"))
                    .unwrap_or(false)
                    && create_type_next_lexeme
                        .map(|s| s.eq_ignore_ascii_case("METRIC"))
                        .unwrap_or(false)
                {
                    // CREATE DATA METRIC FUNCTION (Snowflake)
                    self.try_parse_create_data_metric_function()
                } else if (create_type_lexeme
                    .map(|s| s.eq_ignore_ascii_case("REPLICATION"))
                    .unwrap_or(false)
                    || create_type_lexeme
                        .map(|s| s.eq_ignore_ascii_case("FAILOVER"))
                        .unwrap_or(false))
                    && create_type_next_lexeme
                        .map(|s| s.eq_ignore_ascii_case("GROUP"))
                        .unwrap_or(false)
                {
                    // CREATE REPLICATION GROUP / CREATE FAILOVER GROUP (Snowflake)
                    self.try_parse_create_replication_failover_group()
                } else if create_type_lexeme
                    .map(|s| s.eq_ignore_ascii_case("STORAGE"))
                    .unwrap_or(false)
                {
                    // CREATE STORAGE — peek next: CREDENTIAL vs INTEGRATION
                    // Position is at saved_idx (before CREATE).
                    // We need to skip past CREATE [modifiers] STORAGE to peek the next token.
                    let saved_storage = self.idx;
                    self.advance(); // skip CREATE
                    self.skip_trivia();
                    // Skip modifiers (OR REPLACE, SECURE, temp, etc.) if any
                    while let Some(t) = self.peek_non_trivia() {
                        let lex = t.lexeme(self.source);
                        if lex.eq_ignore_ascii_case("OR")
                            || lex.eq_ignore_ascii_case("REPLACE")
                            || lex.eq_ignore_ascii_case("ALTER")
                            || lex.eq_ignore_ascii_case("SECURE")
                        {
                            self.advance();
                            self.skip_trivia();
                        } else {
                            break;
                        }
                    }
                    // Now should be at STORAGE
                    if let Some(t) = self.peek_non_trivia() {
                        if t.lexeme(self.source).eq_ignore_ascii_case("STORAGE") {
                            self.advance(); // skip STORAGE
                            self.skip_trivia();
                        }
                    }
                    let after_storage = self.peek_non_trivia();
                    let is_credential = after_storage
                        .map(|t| {
                            matches!(t.kind, TokenKind::Identifier { .. })
                                && t.lexeme(self.source).eq_ignore_ascii_case("CREDENTIAL")
                        })
                        .unwrap_or(false);
                    self.idx = saved_storage;

                    if is_credential {
                        // CREATE STORAGE CREDENTIAL (Databricks Unity Catalog)
                        self.idx = saved_idx;
                        self.try_parse_create_storage_credential()
                    } else {
                        // CREATE STORAGE INTEGRATION
                        self.try_parse_create_storage_integration()
                    }
                } else if create_type_lexeme
                    .map(|s| s.eq_ignore_ascii_case("CREDENTIAL"))
                    .unwrap_or(false)
                {
                    // Bare CREATE CREDENTIAL — the dialect grammar decides:
                    // T-SQL identity/secret credential vs Databricks storage
                    // credential.
                    self.idx = saved_idx;
                    if self.dialect.bare_credential_is_identity_secret() {
                        self.try_parse_mssql_security_object_stmt(
                            crate::ast::types::AstMssqlAuditAction::Create,
                        )
                    } else {
                        self.try_parse_create_storage_credential()
                    }
                } else if create_type_lexeme
                    .map(|s| s.eq_ignore_ascii_case("SERVICE"))
                    .unwrap_or(false)
                {
                    // CREATE SERVICE — peek next: CREDENTIAL?
                    // Position is saved_idx (before CREATE). Need to skip past CREATE [modifiers] SERVICE.
                    let saved_svc = self.idx;
                    self.advance(); // skip CREATE
                    self.skip_trivia();
                    // Skip modifiers
                    while let Some(t) = self.peek_non_trivia() {
                        let lex = t.lexeme(self.source);
                        if lex.eq_ignore_ascii_case("OR")
                            || lex.eq_ignore_ascii_case("REPLACE")
                            || lex.eq_ignore_ascii_case("ALTER")
                            || lex.eq_ignore_ascii_case("SECURE")
                        {
                            self.advance();
                            self.skip_trivia();
                        } else {
                            break;
                        }
                    }
                    // Now at SERVICE
                    if let Some(t) = self.peek_non_trivia() {
                        if t.lexeme(self.source).eq_ignore_ascii_case("SERVICE") {
                            self.advance(); // skip SERVICE
                            self.skip_trivia();
                        }
                    }
                    let after_svc = self.peek_non_trivia();
                    let is_svc_credential = after_svc
                        .map(|t| {
                            matches!(t.kind, TokenKind::Identifier { .. })
                                && t.lexeme(self.source).eq_ignore_ascii_case("CREDENTIAL")
                        })
                        .unwrap_or(false);
                    self.idx = saved_svc;

                    if is_svc_credential {
                        // CREATE SERVICE CREDENTIAL (Databricks Unity Catalog)
                        self.idx = saved_idx;
                        self.try_parse_create_storage_credential()
                    } else {
                        // CREATE SERVICE (Snowflake / Snowpark Container Services)
                        self.idx = saved_idx;
                        self.try_parse_create_service()
                    }
                } else if create_type_lexeme
                    .map(|s| s.eq_ignore_ascii_case("SERVER") || s.eq_ignore_ascii_case("DATABASE"))
                    .unwrap_or(false)
                    && create_type_next_lexeme
                        .map(|s| s.eq_ignore_ascii_case("AUDIT"))
                        .unwrap_or(false)
                {
                    // CREATE SERVER AUDIT [SPECIFICATION] / CREATE DATABASE
                    // AUDIT SPECIFICATION — must win over the Databricks
                    // CREATE SERVER and the CREATE DATABASE arms.
                    self.idx = saved_idx;
                    self.try_parse_mssql_audit_ddl_stmt(
                        crate::ast::types::AstMssqlAuditAction::Create,
                    )
                } else if crate::parser::mssql_security_object::is_mssql_security_object_pair(
                    create_type_lexeme,
                    create_type_next_lexeme,
                    self.dialect.bare_credential_is_identity_secret(),
                ) {
                    // CREATE { MASTER|SYMMETRIC|ASYMMETRIC KEY | CERTIFICATE
                    // | [DATABASE SCOPED] CREDENTIAL } — must win over the
                    // CREATE DATABASE arm.
                    self.idx = saved_idx;
                    self.try_parse_mssql_security_object_stmt(
                        crate::ast::types::AstMssqlAuditAction::Create,
                    )
                } else if create_type_lexeme
                    .map(|s| {
                        s.eq_ignore_ascii_case("SERVER") || s.eq_ignore_ascii_case("APPLICATION")
                    })
                    .unwrap_or(false)
                    && create_type_next_lexeme
                        .map(|s| s.eq_ignore_ascii_case("ROLE"))
                        .unwrap_or(false)
                {
                    // CREATE SERVER ROLE | CREATE APPLICATION ROLE (T-SQL) —
                    // dialect-neutral principal substrate. Must win over the
                    // Databricks CREATE SERVER arm below.
                    self.idx = saved_idx;
                    self.try_parse_create_principal_stmt()
                } else if create_type_lexeme
                    .map(|s| s.eq_ignore_ascii_case("DATABASE"))
                    .unwrap_or(false)
                    && create_type_next_lexeme
                        .map(|s| s.eq_ignore_ascii_case("ROLE"))
                        .unwrap_or(false)
                    && create_type_third_is_name
                {
                    // CREATE DATABASE ROLE <name> (Snowflake) — principal
                    // substrate. Must win over the CREATE DATABASE arm; the
                    // name/IF guard leaves `CREATE DATABASE <db-named-role>`
                    // to that arm.
                    self.idx = saved_idx;
                    self.try_parse_create_principal_stmt()
                } else if create_type_lexeme
                    .map(|s| s.eq_ignore_ascii_case("APPLICATION"))
                    .unwrap_or(false)
                    && create_type_next_lexeme
                        .map(|s| s.eq_ignore_ascii_case("PACKAGE"))
                        .unwrap_or(false)
                {
                    // CREATE APPLICATION PACKAGE (Snowflake Native Apps).
                    // Must follow the APPLICATION ROLE arm above (next-word peek).
                    self.try_parse_create_application_package()
                } else if create_type_lexeme
                    .map(|s| s.eq_ignore_ascii_case("APPLICATION"))
                    .unwrap_or(false)
                {
                    // CREATE APPLICATION (Snowflake Native Apps consumer install).
                    self.try_parse_create_application()
                } else if create_type_lexeme
                    .map(|s| s.eq_ignore_ascii_case("SERVER"))
                    .unwrap_or(false)
                    && crate::parser::foreign_server::is_foreign_server_at(
                        self.tokens,
                        saved_idx,
                        self.source,
                    )
                {
                    // CREATE SERVER … FOREIGN DATA WRAPPER (SQL/MED foreign
                    // server, PostgreSQL FDW) — must win over the Databricks
                    // Unity-Catalog CREATE SERVER arm below.
                    self.idx = saved_idx;
                    self.try_parse_create_foreign_server()
                } else if create_type_lexeme
                    .map(|s| {
                        s.eq_ignore_ascii_case("CONNECTION") || s.eq_ignore_ascii_case("SERVER")
                    })
                    .unwrap_or(false)
                {
                    // CREATE CONNECTION | CREATE SERVER (Databricks Unity Catalog)
                    self.idx = saved_idx;
                    self.try_parse_create_connection()
                } else if create_type_lexeme
                    .map(|s| s.eq_ignore_ascii_case("PROCEDURE"))
                    .unwrap_or(false)
                {
                    if create_type_next_lexeme
                        .map(|s| s.eq_ignore_ascii_case("SCOPED"))
                        .unwrap_or(false)
                    {
                        // CREATE [OR REPLACE] PROCEDURE SCOPED { TEMP |
                        // TEMPORARY } TABLE — a procedure-scoped temporary
                        // table (despite the PROCEDURE keyword). Route to the
                        // table parser, which recognizes the PROCEDURE SCOPED
                        // prefix.
                        self.idx = saved_idx;
                        self.try_parse_create_table_stmt()
                    } else {
                        self.try_parse_create_procedure()
                    }
                } else if create_type_lexeme
                    .map(|s| s.eq_ignore_ascii_case("FUNCTION"))
                    .unwrap_or(false)
                {
                    // Use the scripting parser's CREATE FUNCTION parser
                    crate::parser::scripting::parse_create_function(self)
                } else if create_type_lexeme
                    .map(|s| s.eq_ignore_ascii_case("DATABASE"))
                    .unwrap_or(false)
                {
                    // CREATE DATABASE
                    self.idx = saved_idx;
                    self.try_parse_create_database()
                } else if create_type_lexeme
                    .map(|s| s.eq_ignore_ascii_case("SCHEMA"))
                    .unwrap_or(false)
                {
                    // CREATE SCHEMA
                    self.idx = saved_idx;
                    self.try_parse_create_schema()
                } else if create_type_lexeme
                    .map(|s| s.eq_ignore_ascii_case("FLOW"))
                    .unwrap_or(false)
                {
                    // CREATE FLOW ... AS AUTO CDC INTO / APPLY CHANGES INTO (Databricks Lakeflow)
                    self.idx = saved_idx;
                    self.try_parse_create_flow_stmt()
                } else if create_type_lexeme
                    .map(|s| s.eq_ignore_ascii_case("TASK"))
                    .unwrap_or(false)
                {
                    // CREATE TASK
                    crate::parser::task::try_parse_create_task(self)
                } else if create_type_lexeme
                    .map(|s| s.eq_ignore_ascii_case("STREAM"))
                    .unwrap_or(false)
                {
                    // CREATE STREAM
                    crate::parser::stream::try_parse_create_stream(self)
                } else if create_type_lexeme
                    .map(|s| {
                        s.eq_ignore_ascii_case("INDEX")
                            || s.eq_ignore_ascii_case("UNIQUE")
                            // T-SQL index-type modifiers preceding INDEX
                            || s.eq_ignore_ascii_case("CLUSTERED")
                            || s.eq_ignore_ascii_case("NONCLUSTERED")
                            || s.eq_ignore_ascii_case("COLUMNSTORE")
                            // MySQL index kinds preceding INDEX
                            || s.eq_ignore_ascii_case("FULLTEXT")
                            || s.eq_ignore_ascii_case("SPATIAL")
                    })
                    .unwrap_or(false)
                {
                    // CREATE [UNIQUE] [CLUSTERED|NONCLUSTERED|COLUMNSTORE|FULLTEXT|SPATIAL] INDEX
                    self.try_parse_create_index_stmt()
                } else if create_type_lexeme
                    .map(|s| s.eq_ignore_ascii_case("SYNONYM"))
                    .unwrap_or(false)
                {
                    // CREATE SYNONYM name FOR object (T-SQL)
                    self.try_parse_create_synonym_stmt()
                } else if create_type_lexeme
                    .map(|s| s.eq_ignore_ascii_case("TYPE"))
                    .unwrap_or(false)
                {
                    // CREATE TYPE (PostgreSQL)
                    self.try_parse_create_type_stmt()
                } else if create_type_lexeme
                    .map(|s| s.eq_ignore_ascii_case("EXTENSION"))
                    .unwrap_or(false)
                {
                    // CREATE EXTENSION (PostgreSQL)
                    self.try_parse_create_extension_stmt()
                } else if create_type_lexeme
                    .map(|s| s.eq_ignore_ascii_case("SEQUENCE"))
                    .unwrap_or(false)
                {
                    // CREATE SEQUENCE (PostgreSQL)
                    self.idx = saved_idx;
                    self.try_parse_create_sequence_stmt()
                } else if create_type_lexeme
                    .map(|s| s.eq_ignore_ascii_case("TRIGGER"))
                    .unwrap_or(false)
                {
                    self.idx = saved_idx;
                    // Dialect gate (justified): MSSQL CREATE TRIGGER uses ON table AFTER/FOR
                    // while PG CREATE TRIGGER uses BEFORE/AFTER/INSTEAD OF ... ON table.
                    // The clause ordering is inverted, making token-based disambiguation
                    // impractical without full lookahead past the trigger name.
                    if self.dialect.trigger_lists_table_before_timing() {
                        // CREATE [OR ALTER] TRIGGER (MSSQL)
                        crate::parser::scripting::try_parse_create_mssql_trigger(self)
                    } else if self.dialect.trigger_has_inline_body() {
                        // CREATE [DEFINER=…] TRIGGER … FOR EACH ROW <body> (MySQL).
                        // Shares PG's BEFORE/AFTER…ON header but carries an inline
                        // body instead of EXECUTE FUNCTION — same justified gate.
                        self.try_parse_create_mysql_trigger()
                    } else {
                        // CREATE [OR REPLACE] TRIGGER (PostgreSQL)
                        self.try_parse_create_pg_trigger_stmt()
                    }
                } else if create_type_lexeme
                    .map(|s| s.eq_ignore_ascii_case("CONSTRAINT"))
                    .unwrap_or(false)
                {
                    // CREATE [OR REPLACE] CONSTRAINT TRIGGER (PostgreSQL)
                    self.idx = saved_idx;
                    self.try_parse_create_pg_trigger_stmt()
                } else if create_type_lexeme
                    .map(|s| s.eq_ignore_ascii_case("DOMAIN"))
                    .unwrap_or(false)
                {
                    // CREATE DOMAIN (PostgreSQL)
                    self.idx = saved_idx;
                    self.try_parse_create_domain_stmt()
                } else if create_type_lexeme
                    .map(|s| s.eq_ignore_ascii_case("POLICY"))
                    .unwrap_or(false)
                {
                    // CREATE POLICY (PostgreSQL RLS)
                    self.idx = saved_idx;
                    self.try_parse_create_pg_policy_stmt()
                } else if create_type_lexeme
                    .map(|s| s.eq_ignore_ascii_case("RULE"))
                    .unwrap_or(false)
                {
                    // CREATE [OR REPLACE] RULE (PostgreSQL)
                    self.idx = saved_idx;
                    self.try_parse_pg_create_rule_stmt()
                } else if create_type_lexeme
                    .map(|s| s.eq_ignore_ascii_case("AGGREGATE"))
                    .unwrap_or(false)
                {
                    // CREATE AGGREGATE (PostgreSQL)
                    self.idx = saved_idx;
                    self.try_parse_pg_create_aggregate_stmt()
                } else if create_type_lexeme
                    .map(|s| s.eq_ignore_ascii_case("OPERATOR"))
                    .unwrap_or(false)
                {
                    // CREATE OPERATOR (PostgreSQL)
                    self.idx = saved_idx;
                    self.try_parse_pg_create_operator_stmt()
                } else if create_type_lexeme
                    .map(|s| s.eq_ignore_ascii_case("PUBLICATION"))
                    .unwrap_or(false)
                {
                    // CREATE PUBLICATION (PostgreSQL logical replication)
                    self.idx = saved_idx;
                    self.try_parse_pg_publication_stmt()
                } else if create_type_lexeme
                    .map(|s| s.eq_ignore_ascii_case("SUBSCRIPTION"))
                    .unwrap_or(false)
                {
                    // CREATE SUBSCRIPTION (PostgreSQL logical replication)
                    self.idx = saved_idx;
                    self.try_parse_pg_subscription_stmt()
                } else if create_type_lexeme
                    .map(|s| s.eq_ignore_ascii_case("TABLESPACE"))
                    .unwrap_or(false)
                {
                    // CREATE TABLESPACE (PostgreSQL storage)
                    self.idx = saved_idx;
                    self.try_parse_pg_create_tablespace_stmt()
                } else if crate::parser::user_mapping::is_user_mapping_at(
                    self.tokens,
                    saved_idx,
                    self.source,
                ) {
                    // CREATE USER MAPPING … FOR … (SQL/MED foreign-server
                    // credential mapping) — must win over the CREATE USER
                    // principal arm below, which would mislabel it as role
                    // creation. The `FOR` clause distinguishes it from a plain
                    // CREATE USER whose user is named MAPPING (e.g. Snowflake).
                    self.idx = saved_idx;
                    self.try_parse_create_user_mapping()
                } else if create_type_lexeme
                    .map(|s| {
                        s.eq_ignore_ascii_case("ROLE")
                            || s.eq_ignore_ascii_case("USER")
                            || s.eq_ignore_ascii_case("GROUP")
                    })
                    .unwrap_or(false)
                {
                    // CREATE { ROLE | USER | GROUP } — dialect-neutral principal
                    // substrate (GROUP is the Redshift legacy permission group).
                    self.idx = saved_idx;
                    self.try_parse_create_principal_stmt()
                } else if create_type_lexeme
                    .map(|s| s.eq_ignore_ascii_case("SNAPSHOT"))
                    .unwrap_or(false)
                {
                    // CREATE SNAPSHOT TABLE (BigQuery)
                    self.idx = saved_idx;
                    self.try_parse_bq_create_snapshot_table()
                } else if create_type_lexeme
                    .map(|s| s.eq_ignore_ascii_case("SEARCH"))
                    .unwrap_or(false)
                {
                    // CREATE SEARCH INDEX (BigQuery)
                    self.idx = saved_idx;
                    self.try_parse_bq_create_search_index()
                } else if create_type_lexeme
                    .map(|s| s.eq_ignore_ascii_case("VECTOR"))
                    .unwrap_or(false)
                {
                    // CREATE [OR REPLACE] VECTOR INDEX — MSSQL or BigQuery
                    if self.dialect.vector_index_uses_with_options_clause() {
                        self.idx = saved_idx;
                        self.try_parse_mssql_create_vector_index()
                    } else {
                        self.idx = saved_idx;
                        self.try_parse_bq_create_vector_index()
                    }
                } else if create_type_lexeme
                    .map(|s| s.eq_ignore_ascii_case("MODEL"))
                    .unwrap_or(false)
                {
                    // CREATE [OR REPLACE] MODEL [IF NOT EXISTS] (BigQuery BQML)
                    self.idx = saved_idx;
                    self.try_parse_bq_create_model()
                } else if create_type_lexeme
                    .map(|s| s.eq_ignore_ascii_case("LOGIN"))
                    .unwrap_or(false)
                {
                    // CREATE LOGIN — dialect-neutral principal substrate.
                    self.idx = saved_idx;
                    self.try_parse_create_principal_stmt()
                } else if create_type_lexeme
                    .map(|s| s.eq_ignore_ascii_case("FOREIGN"))
                    .unwrap_or(false)
                    && create_type_next_lexeme
                        .map(|s| s.eq_ignore_ascii_case("TABLE"))
                        .unwrap_or(false)
                {
                    // CREATE FOREIGN TABLE (SQL/MED / PostgreSQL FDW) — must win
                    // over the Databricks CREATE FOREIGN CATALOG arm below.
                    self.idx = saved_idx;
                    self.try_parse_create_foreign_table()
                } else if create_type_lexeme
                    .map(|s| s.eq_ignore_ascii_case("CATALOG") || s.eq_ignore_ascii_case("FOREIGN"))
                    .unwrap_or(false)
                {
                    // CREATE [FOREIGN] CATALOG (Databricks Unity Catalog)
                    self.idx = saved_idx;
                    self.try_parse_create_catalog()
                } else if create_type_lexeme
                    .map(|s| s.eq_ignore_ascii_case("VOLUME"))
                    .unwrap_or(false)
                {
                    // CREATE VOLUME (Databricks Unity Catalog)
                    self.idx = saved_idx;
                    self.try_parse_create_volume()
                } else if create_type_lexeme
                    .map(|s| s.eq_ignore_ascii_case("WAREHOUSE"))
                    .unwrap_or(false)
                {
                    // CREATE WAREHOUSE
                    crate::parser::warehouse::try_parse_create_warehouse(self)
                } else if create_type_lexeme
                    .map(|s| s.eq_ignore_ascii_case("PIPE"))
                    .unwrap_or(false)
                {
                    // CREATE PIPE
                    crate::parser::pipe::try_parse_create_pipe(self)
                } else if create_type_lexeme
                    .map(|s| s.eq_ignore_ascii_case("FORMAT") || s.eq_ignore_ascii_case("FILE"))
                    .unwrap_or(false)
                {
                    // These CREATE statements are not yet fully supported
                    let create_type_name = create_type_lexeme.unwrap_or("UNKNOWN");
                    Err(ParseError::new(
                        self.current_span(),
                        ParseErrorKind::InvalidStatement {
                            message: format!(
                                "CREATE {} statements are not yet fully supported",
                                create_type_name
                            ),
                        },
                    ))
                } else if create_type_lexeme.is_none() {
                    Err(ParseError::new(
                        self.current_span(),
                        ParseErrorKind::InvalidStatement {
                            message: "CREATE statement requires object type (TABLE, PROCEDURE, FUNCTION, etc.)".to_string(),
                        },
                    ))
                } else {
                    // Unknown CREATE type
                    let create_type_name = create_type_lexeme.unwrap_or("UNKNOWN");
                    Err(ParseError::new(
                        self.current_span(),
                        ParseErrorKind::InvalidStatement {
                            message: format!(
                                "Unknown or unsupported CREATE {} statement",
                                create_type_name
                            ),
                        },
                    ))
                }
            }
            // Handle LISTEN (PostgreSQL pub/sub)
            TokenKind::Identifier { .. }
                if first.lexeme(self.source).eq_ignore_ascii_case("LISTEN") =>
            {
                self.try_parse_pg_listen_stmt()
            }
            // Handle NOTIFY (PostgreSQL pub/sub)
            TokenKind::Identifier { .. }
                if first.lexeme(self.source).eq_ignore_ascii_case("NOTIFY") =>
            {
                self.try_parse_pg_notify_stmt()
            }
            // Handle UNLISTEN (PostgreSQL pub/sub)
            TokenKind::Identifier { .. }
                if first.lexeme(self.source).eq_ignore_ascii_case("UNLISTEN") =>
            {
                self.try_parse_pg_unlisten_stmt()
            }
            // Handle LOCK [TABLE] (PostgreSQL explicit locking)
            TokenKind::Identifier { .. }
                if first.lexeme(self.source).eq_ignore_ascii_case("LOCK") =>
            {
                self.try_parse_pg_lock_table_stmt()
            }
            // Handle REASSIGN OWNED (PostgreSQL role management)
            TokenKind::Identifier { .. }
                if first.lexeme(self.source).eq_ignore_ascii_case("REASSIGN") =>
            {
                self.try_parse_pg_reassign_owned_stmt()
            }
            // Handle DISCARD (PostgreSQL maintenance)
            TokenKind::Identifier { .. }
                if first.lexeme(self.source).eq_ignore_ascii_case("DISCARD") =>
            {
                self.try_parse_pg_discard_stmt()
            }
            // Handle EXPLAIN (PostgreSQL) - wraps inner statement with analysis options
            TokenKind::Identifier { .. }
                if first.lexeme(self.source).eq_ignore_ascii_case("EXPLAIN") =>
            {
                self.try_parse_explain_stmt()
            }
            // Handle VACUUM (PostgreSQL)
            TokenKind::Identifier { .. }
                if first.lexeme(self.source).eq_ignore_ascii_case("VACUUM") =>
            {
                self.try_parse_vacuum_stmt()
            }
            // Handle UNLOAD (Redshift) — exports query results to an external location
            TokenKind::Identifier { .. }
                if first.lexeme(self.source).eq_ignore_ascii_case("UNLOAD") =>
            {
                self.try_parse_unload_stmt()
            }
            // Handle ANALYZE (PostgreSQL standalone statement)
            TokenKind::Identifier { .. }
                if first.lexeme(self.source).eq_ignore_ascii_case("ANALYZE") =>
            {
                self.try_parse_analyze_stmt()
            }
            // Handle REINDEX (PostgreSQL)
            TokenKind::Identifier { .. }
                if first.lexeme(self.source).eq_ignore_ascii_case("REINDEX") =>
            {
                self.try_parse_reindex_stmt()
            }
            // Handle PREPARE (PostgreSQL prepared statements)
            TokenKind::Identifier { .. }
                if first.lexeme(self.source).eq_ignore_ascii_case("PREPARE") =>
            {
                self.try_parse_pg_prepare_stmt()
            }
            // Handle DEALLOCATE (PostgreSQL prepared statements)
            TokenKind::Identifier { .. }
                if first.lexeme(self.source).eq_ignore_ascii_case("DEALLOCATE") =>
            {
                self.try_parse_pg_deallocate_stmt()
            }
            // Handle RESET (PostgreSQL session state)
            TokenKind::Identifier { .. }
                if first.lexeme(self.source).eq_ignore_ascii_case("RESET") =>
            {
                self.try_parse_pg_set_stmt()
            }
            // Handle EXPORT DATA / EXPORT MODEL (BigQuery)
            TokenKind::Identifier { .. }
                if first.lexeme(self.source).eq_ignore_ascii_case("EXPORT") =>
            {
                // Peek at next token to disambiguate DATA vs MODEL
                // Note: first is EXPORT (peeked, not consumed), so we must
                // advance past it before peeking the following token.
                let saved = self.idx;
                self.advance(); // consume EXPORT temporarily
                if let Some(next) = self.peek_non_trivia() {
                    if next.lexeme(self.source).eq_ignore_ascii_case("MODEL") {
                        self.idx = saved;
                        self.try_parse_bq_export_model()
                    } else {
                        self.idx = saved;
                        self.try_parse_bq_export_data()
                    }
                } else {
                    self.idx = saved;
                    self.try_parse_bq_export_data()
                }
            }
            // Handle LOAD DATA — MySQL `INFILE` form vs BigQuery `FROM FILES(...)`,
            // disambiguated structurally by an `INFILE` marker ahead.
            TokenKind::Identifier { .. }
                if first.lexeme(self.source).eq_ignore_ascii_case("LOAD") =>
            {
                if crate::parser::mysql_load_data::is_mysql_load_data_at(
                    self.tokens,
                    self.idx,
                    self.source,
                ) {
                    self.try_parse_mysql_load_data()
                } else {
                    self.try_parse_bq_load_data()
                }
            }
            // Handle ASSERT (BigQuery)
            TokenKind::Identifier { .. }
                if first.lexeme(self.source).eq_ignore_ascii_case("ASSERT") =>
            {
                self.try_parse_bq_assert()
            }
            // Handle OPTIMIZE (Databricks)
            TokenKind::Identifier { .. }
                if first.lexeme(self.source).eq_ignore_ascii_case("OPTIMIZE") =>
            {
                self.try_parse_optimize_stmt()
            }
            // Handle APPLY CHANGES INTO (Databricks Lakeflow legacy SQL)
            TokenKind::Identifier { .. }
                if first.lexeme(self.source).eq_ignore_ascii_case("APPLY") =>
            {
                let saved = self.idx;
                self.advance();
                let is_changes = self.peek_non_trivia().is_some_and(|t| {
                    matches!(t.kind, TokenKind::Identifier { .. })
                        && t.lexeme(self.source).eq_ignore_ascii_case("CHANGES")
                });
                self.idx = saved;

                if is_changes {
                    self.try_parse_apply_changes_into_stmt()
                } else {
                    Err(ParseError::new(
                        first.span,
                        ParseErrorKind::InvalidStatement {
                            message:
                                "Unsupported APPLY statement (expected APPLY CHANGES INTO ...)"
                                    .to_string(),
                        },
                    ))
                }
            }
            // Handle RESTORE. Disambiguate the T-SQL `RESTORE { DATABASE | LOG }
            // … FROM …` form from the Databricks time-travel
            // `RESTORE [TABLE] … TO {TIMESTAMP|VERSION}` form on the token after
            // RESTORE (DATABASE/LOG ⇒ T-SQL).
            TokenKind::Identifier { .. }
                if first.lexeme(self.source).eq_ignore_ascii_case("RESTORE") =>
            {
                if crate::parser::key_backup::is_mssql_key_backup_at(
                    self.tokens,
                    self.idx,
                    self.source,
                ) {
                    // RESTORE { SERVICE MASTER KEY | MASTER KEY } (key material)
                    self.try_parse_mssql_key_backup_stmt()
                } else if crate::parser::restore::is_mssql_restore_at(
                    self.tokens,
                    self.idx,
                    self.source,
                ) {
                    self.try_parse_mssql_restore_stmt()
                } else {
                    self.try_parse_restore_stmt()
                }
            }
            // Handle BACKUP { SERVICE MASTER KEY | MASTER KEY | CERTIFICATE |
            // ASYMMETRIC KEY } (T-SQL key-material export). Disjoint from the
            // DATABASE/LOG form by the object token; must precede it.
            TokenKind::Identifier { .. }
                if first.lexeme(self.source).eq_ignore_ascii_case("BACKUP")
                    && crate::parser::key_backup::is_mssql_key_backup_at(
                        self.tokens,
                        self.idx,
                        self.source,
                    ) =>
            {
                self.try_parse_mssql_key_backup_stmt()
            }
            // Handle BACKUP { DATABASE | LOG } (T-SQL data-protection utility —
            // BACKUP is an Identifier, not a Keyword). Guard on the next token
            // being DATABASE/LOG so a stray `BACKUP` identifier isn't hijacked.
            TokenKind::Identifier { .. }
                if first.lexeme(self.source).eq_ignore_ascii_case("BACKUP")
                    && crate::parser::backup::is_mssql_backup_at(
                        self.tokens,
                        self.idx,
                        self.source,
                    ) =>
            {
                self.try_parse_mssql_backup_stmt()
            }
            // Handle DBCC <command> (T-SQL database console command — DBCC is an
            // Identifier in our lexer). Guard on a command-name token following
            // so a stray `DBCC` identifier isn't hijacked.
            TokenKind::Identifier { .. }
                if first.lexeme(self.source).eq_ignore_ascii_case("DBCC")
                    && crate::parser::dbcc::is_mssql_dbcc_at(
                        self.tokens,
                        self.idx,
                        self.source,
                    ) =>
            {
                self.try_parse_mssql_dbcc_stmt()
            }
            // Handle ADD [COUNTER] SIGNATURE (T-SQL module signing — ADD is an
            // Identifier in our lexer). Guard on a following SIGNATURE/COUNTER so
            // a stray `ADD` identifier isn't hijacked.
            TokenKind::Identifier { .. }
                if first.lexeme(self.source).eq_ignore_ascii_case("ADD")
                    && crate::parser::add_signature::is_mssql_add_signature_at(
                        self.tokens,
                        self.idx,
                        self.source,
                    ) =>
            {
                self.try_parse_mssql_add_signature_stmt()
            }
            // Handle SETUSER ['username'] (T-SQL legacy database-context
            // impersonation — SETUSER is an Identifier). Statement-leading, so a
            // bare lexeme match suffices.
            TokenKind::Identifier { .. }
                if first.lexeme(self.source).eq_ignore_ascii_case("SETUSER") =>
            {
                self.try_parse_mssql_setuser_stmt()
            }
            // Handle T-SQL encryption-key activation (OPEN/CLOSE { MASTER |
            // SYMMETRIC } KEY). OPEN/CLOSE are Keywords shared with cursor ops;
            // a structural MASTER/SYMMETRIC+KEY (or leading ALL) lookahead
            // disambiguates. False guard ⇒ falls through to the existing
            // (cursor / opaque) handling.
            TokenKind::Keyword(Keyword::Open) | TokenKind::Keyword(Keyword::Close)
                if crate::parser::key_management::is_mssql_key_stmt_at(
                    self.tokens,
                    self.idx,
                    self.source,
                ) =>
            {
                self.try_parse_mssql_key_stmt()
            }
            // Handle IMPORT FOREIGN SCHEMA (PostgreSQL FDW bulk import — IMPORT
            // and SCHEMA are Identifiers, FOREIGN is a Keyword). Structural
            // FOREIGN-SCHEMA lookahead so a stray `IMPORT` ident isn't hijacked.
            TokenKind::Identifier { .. }
                if first.lexeme(self.source).eq_ignore_ascii_case("IMPORT")
                    && crate::parser::import_foreign_schema::is_import_foreign_schema_at(
                        self.tokens,
                        self.idx,
                        self.source,
                    ) =>
            {
                self.try_parse_import_foreign_schema()
            }
            // Handle CACHE TABLE (Databricks)
            TokenKind::Identifier { .. }
                if first.lexeme(self.source).eq_ignore_ascii_case("CACHE") =>
            {
                self.try_parse_cache_table_stmt()
            }
            // Handle UNCACHE TABLE (Databricks)
            TokenKind::Identifier { .. }
                if first.lexeme(self.source).eq_ignore_ascii_case("UNCACHE") =>
            {
                self.try_parse_uncache_table_stmt()
            }
            // Handle REPAIR TABLE (Databricks / SparkSQL)
            TokenKind::Identifier { .. }
                if first.lexeme(self.source).eq_ignore_ascii_case("REPAIR") =>
            {
                self.try_parse_repair_table_stmt()
            }
            // Handle MSCK REPAIR TABLE (Databricks / SparkSQL)
            TokenKind::Identifier { .. }
                if first.lexeme(self.source).eq_ignore_ascii_case("MSCK") =>
            {
                // Disambiguate MSCK REPAIR TABLE vs other possible MSCK-prefixed constructs
                let saved = self.idx;
                self.advance(); // consume MSCK temporarily
                let is_repair = self.peek_non_trivia().is_some_and(|t| {
                    matches!(t.kind, TokenKind::Identifier { .. })
                        && t.lexeme(self.source).eq_ignore_ascii_case("REPAIR")
                });
                self.idx = saved;

                if is_repair {
                    self.try_parse_msck_repair_table_stmt()
                } else {
                    Err(ParseError::new(
                        first.span,
                        ParseErrorKind::InvalidStatement {
                            message: "Unsupported MSCK-prefixed statement (expected MSCK REPAIR TABLE ...)".to_string(),
                        },
                    ))
                }
            }
            // Handle EXEC (MSSQL shorthand for EXECUTE — Identifier, not Keyword)
            // Dialect gate (justified): EXEC is an Identifier token; without the mssql guard,
            // `SELECT * FROM exec` or `EXEC` as a column alias would be hijacked.
            TokenKind::Identifier { .. }
                if first.lexeme(self.source).eq_ignore_ascii_case("EXEC")
                    && self.dialect.supports_exec_procedure_call() =>
            {
                self.try_parse_mssql_exec_stmt()
            }
            // Handle BULK INSERT (MSSQL bulk data import — BULK is Identifier, not Keyword)
            TokenKind::Identifier { .. }
                if first.lexeme(self.source).eq_ignore_ascii_case("BULK")
                    && self.dialect.supports_bulk_insert_statement()
                    && crate::parser::scripting::is_mssql_bulk_insert_at(self.tokens, self.idx) =>
            {
                crate::parser::scripting::try_parse_mssql_bulk_insert(self)
            }
            // Handle PRINT (MSSQL diagnostic output — Identifier, not Keyword)
            TokenKind::Identifier { .. }
                if first.lexeme(self.source).eq_ignore_ascii_case("PRINT")
                    && self.dialect.supports_print_statement() =>
            {
                crate::parser::scripting::try_parse_mssql_print(self)
            }
            // Handle RECONFIGURE (MSSQL apply sp_configure — Identifier, not Keyword)
            TokenKind::Identifier { .. }
                if first
                    .lexeme(self.source)
                    .eq_ignore_ascii_case("RECONFIGURE")
                    && self.dialect.supports_reconfigure_statement() =>
            {
                crate::parser::scripting::try_parse_mssql_reconfigure(self)
            }
            // Handle REVERT (MSSQL end-of-impersonation — Identifier, not Keyword)
            TokenKind::Identifier { .. }
                if first.lexeme(self.source).eq_ignore_ascii_case("REVERT")
                    && self.dialect.supports_revert_statement() =>
            {
                self.try_parse_mssql_revert_stmt()
            }
            // Handle THROW (MSSQL exception — Identifier, not Keyword)
            TokenKind::Identifier { .. }
                if first.lexeme(self.source).eq_ignore_ascii_case("THROW")
                    && self.dialect.supports_throw_statement() =>
            {
                crate::parser::scripting::try_parse_mssql_throw(self)
            }
            // Handle RAISERROR (MSSQL error — Identifier, not Keyword)
            TokenKind::Identifier { .. }
                if first.lexeme(self.source).eq_ignore_ascii_case("RAISERROR")
                    && self.dialect.supports_raiserror_statement() =>
            {
                crate::parser::scripting::try_parse_mssql_raiserror(self)
            }
            // Handle WAITFOR (MSSQL delay/wait — Identifier, not Keyword)
            TokenKind::Identifier { .. }
                if first.lexeme(self.source).eq_ignore_ascii_case("WAITFOR")
                    && self.dialect.supports_waitfor_statement() =>
            {
                crate::parser::scripting::try_parse_mssql_waitfor(self)
            }
            // Handle GOTO (MSSQL unconditional jump — Identifier, not Keyword)
            TokenKind::Identifier { .. }
                if first.lexeme(self.source).eq_ignore_ascii_case("GOTO")
                    && self.dialect.supports_goto_statement() =>
            {
                crate::parser::scripting::try_parse_mssql_goto(self)
            }
            // Handle MSSQL label declaration: identifier followed by colon at statement level
            TokenKind::Identifier { .. }
                if self.dialect.supports_statement_labels()
                    && crate::parser::scripting::is_mssql_label_at(self.tokens, self.idx) =>
            {
                crate::parser::scripting::try_parse_mssql_label(self)
            }
            // Handle LEAVE/ITERATE (BigQuery loop control - Identifiers, not Keywords)
            // LEAVE = BREAK, ITERATE = CONTINUE in BigQuery scripting
            TokenKind::Identifier { .. }
                if first.lexeme(self.source).eq_ignore_ascii_case("LEAVE")
                    || first.lexeme(self.source).eq_ignore_ascii_case("ITERATE") =>
            {
                // Build a Break or Continue AST node directly since
                // try_parse_loop_control_stmt_in_block expects Keyword tokens
                let is_leave = first.lexeme(self.source).eq_ignore_ascii_case("LEAVE");
                let ctrl_token_id = self.current_token_id();
                let ctrl_tok = self.advance().ok_or_else(|| {
                    ParseError::new(
                        self.current_span(),
                        ParseErrorKind::InvalidStatement {
                            message: "Expected LEAVE or ITERATE".to_string(),
                        },
                    )
                })?;
                let mut end = ctrl_tok.span.end;

                // Optional label identifier
                let mut label_token = None;
                if let Some(label_tok) = self.peek_non_trivia() {
                    if self.can_be_identifier_token(label_tok)
                        && !matches!(
                            label_tok.kind,
                            TokenKind::Punctuation(crate::lexer::Punctuation::Semi)
                        )
                    {
                        label_token = Some(self.current_token_id());
                        let lbl = self.advance().expect_invariant("label after LEAVE/ITERATE");
                        end = lbl.span.end;
                    }
                }

                let semicolon_token = if let Some(semi_tok) = self.peek_non_trivia() {
                    if matches!(
                        semi_tok.kind,
                        TokenKind::Punctuation(crate::lexer::Punctuation::Semi)
                    ) {
                        let semi_id = self.current_token_id();
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

                if is_leave {
                    Ok(AstStmt::Break {
                        node_id: self.id_gen.next(),
                        span,
                        break_span: ctrl_tok.span,
                        break_token: Some(ctrl_token_id),
                        label_token,
                        semicolon_token,
                    })
                } else {
                    Ok(AstStmt::Continue {
                        node_id: self.id_gen.next(),
                        span,
                        continue_span: ctrl_tok.span,
                        continue_token: Some(ctrl_token_id),
                        label_token,
                        semicolon_token,
                    })
                }
            }
            // Handle DESC as alias for DESCRIBE (only at statement start)
            TokenKind::Identifier { .. }
                if first.lexeme(self.source).eq_ignore_ascii_case("DESC") =>
            {
                // Check for Databricks DESC HISTORY
                let saved = self.idx;
                self.advance(); // consume DESC
                if let Some(next) = self.peek_non_trivia() {
                    if matches!(next.kind, TokenKind::Identifier { .. })
                        && next.lexeme(self.source).eq_ignore_ascii_case("HISTORY")
                    {
                        self.idx = saved;
                        return self.try_parse_describe_history_stmt();
                    }
                }
                self.idx = saved;
                self.try_parse_describe_stmt_with_parser()
            }
            // Handle UNDROP DATABASE/SCHEMA/TABLE/TYPE/TAG (UNDROP is an Identifier, not a Keyword)
            TokenKind::Identifier { .. }
                if first.lexeme(self.source).eq_ignore_ascii_case("UNDROP") =>
            {
                // Peek to see if next token is DATABASE, SCHEMA, TABLE, or TYPE
                let saved_idx = self.idx;
                self.advance(); // consume UNDROP
                if let Some(tok) = self.peek_non_trivia() {
                    if matches!(tok.kind, TokenKind::Identifier { .. })
                        && tok.lexeme(self.source).eq_ignore_ascii_case("DATABASE")
                    {
                        self.idx = saved_idx;
                        self.try_parse_undrop_database()
                    } else if matches!(tok.kind, TokenKind::Identifier { .. })
                        && tok.lexeme(self.source).eq_ignore_ascii_case("SCHEMA")
                    {
                        self.idx = saved_idx;
                        self.try_parse_undrop_schema()
                    } else if matches!(tok.kind, TokenKind::Keyword(Keyword::Table)) {
                        self.idx = saved_idx;
                        self.try_parse_undrop_table()
                    } else if matches!(tok.kind, TokenKind::Keyword(Keyword::Type)) {
                        // UNDROP TYPE name (Snowflake)
                        self.idx = saved_idx;
                        self.try_parse_undrop_type()
                    } else if matches!(tok.kind, TokenKind::Keyword(Keyword::Tag)) {
                        // UNDROP TAG name (Snowflake)
                        self.idx = saved_idx;
                        self.try_parse_undrop_tag()
                    } else {
                        self.idx = saved_idx;
                        Err(ParseError::new(
                            first.span,
                            ParseErrorKind::InvalidStatement {
                                message: "UNDROP requires DATABASE, SCHEMA, TABLE, TYPE, or TAG"
                                    .to_string(),
                            },
                        ))
                    }
                } else {
                    self.idx = saved_idx;
                    Err(ParseError::new(
                        first.span,
                        ParseErrorKind::InvalidStatement {
                            message: "UNDROP requires DATABASE, SCHEMA, TABLE, TYPE, or TAG"
                                .to_string(),
                        },
                    ))
                }
            }
            // Scripting statements: standalone (outside BEGIN..END blocks)
            // BigQuery allows these at top level without wrapping in BEGIN..END.
            // We delegate to the existing scripting parsers with StmtContext::Block
            // and begin_start = current token position.
            TokenKind::Keyword(Keyword::If) => {
                // Dialect gate (justified): MSSQL IF has no THEN/END IF — its grammar
                // is structurally incompatible with Snowflake/BigQuery IF...THEN...END IF.
                // Token-based disambiguation is possible (presence of THEN keyword) but
                // would require parsing the full condition first and backtracking.
                if self.dialect.uses_block_scoped_control_flow() {
                    crate::parser::scripting::try_parse_mssql_if(self)
                } else {
                    let begin_start = first.span.start;
                    crate::parser::scripting::try_parse_if_stmt_in_block(
                        self,
                        crate::parser::scripting::StmtContext::Block,
                        begin_start,
                    )
                }
            }
            TokenKind::Keyword(Keyword::Case) => {
                let begin_start = first.span.start;
                crate::parser::scripting::try_parse_case_stmt_in_block(
                    self,
                    crate::parser::scripting::StmtContext::Block,
                    begin_start,
                )
            }
            TokenKind::Keyword(Keyword::While) => {
                // Dialect gate (justified): MSSQL WHILE has no DO/END WHILE — its grammar
                // is structurally incompatible with Snowflake WHILE...DO...END WHILE.
                if self.dialect.uses_block_scoped_control_flow() {
                    crate::parser::scripting::try_parse_mssql_while(self)
                } else {
                    let begin_start = first.span.start;
                    crate::parser::scripting::try_parse_while_stmt_in_block(self, begin_start, None)
                }
            }
            TokenKind::Keyword(Keyword::For) => {
                let begin_start = first.span.start;
                crate::parser::scripting::try_parse_for_stmt_in_block(self, begin_start, None)
            }
            TokenKind::Keyword(Keyword::Repeat) => {
                let begin_start = first.span.start;
                crate::parser::scripting::try_parse_repeat_stmt_in_block(self, begin_start, None)
            }
            TokenKind::Keyword(Keyword::Loop) => {
                let begin_start = first.span.start;
                crate::parser::scripting::try_parse_loop_stmt_in_block(self, begin_start, None)
            }
            TokenKind::Keyword(Keyword::Break)
            | TokenKind::Keyword(Keyword::Exit)
            | TokenKind::Keyword(Keyword::Continue) => {
                crate::parser::scripting::try_parse_loop_control_stmt_in_block(self)
            }
            TokenKind::Keyword(Keyword::Return) => {
                crate::parser::scripting::try_parse_return_stmt_in_block(self)
            }
            TokenKind::Keyword(Keyword::Raise) => {
                crate::parser::scripting::try_parse_raise_stmt_in_block(self)
            }
            // SQL clause keywords that appear inside Jinja blocks
            // These are fragments that belong in SELECT statements, wrapped as ClauseFragment
            TokenKind::Keyword(Keyword::From) => self.try_parse_clause_fragment_as_stmt(),
            TokenKind::Keyword(Keyword::Where) => self.try_parse_clause_fragment_as_stmt(),
            TokenKind::Keyword(Keyword::Join)
            | TokenKind::Keyword(Keyword::Left)
            | TokenKind::Keyword(Keyword::Right)
            | TokenKind::Keyword(Keyword::Full)
            | TokenKind::Keyword(Keyword::Inner)
            | TokenKind::Keyword(Keyword::Cross) => self.try_parse_clause_fragment_as_stmt(),
            TokenKind::Keyword(Keyword::Having) => self.try_parse_clause_fragment_as_stmt(),
            TokenKind::Keyword(Keyword::And) | TokenKind::Keyword(Keyword::Or) => {
                self.try_parse_clause_fragment_as_stmt()
            }
            _ => {
                // Unrecognized statement start
                let tok = first;
                Err(ParseError::new(
                    tok.span,
                    ParseErrorKind::InvalidStatement {
                        message: format!(
                            "Unexpected token '{}' at start of statement. Expected a SQL keyword (SELECT, INSERT, UPDATE, CREATE, etc.)",
                            tok.lexeme(self.source)
                        ),
                    },
                ))
            }
        };
        result
    }

    /// Parse a flow statement (with pipe operators), returning a Result.
    /// Parse a statement with Result-based error handling, checking for pipe operators via lookahead.
    pub(crate) fn parse_flow_statement(&mut self) -> crate::error::ParseResult<AstStmt> {
        use crate::error::{ParseError, ParseErrorKind};

        // Guard against deep recursion
        let _depth = self.track_depth("parse_flow_statement")?;

        // Parse first statement naturally - parsers stop at pipe operators
        let chain_start_span = self
            .peek()
            .ok_or_else(|| {
                ParseError::new(
                    self.current_span(),
                    ParseErrorKind::InvalidStatement {
                        message: "Expected statement, found EOF".to_string(),
                    },
                )
            })?
            .span;

        let first_stmt = self.parse_statement()?;

        // Check if a pipe operator follows (natural lookahead)
        self.skip_trivia();
        if !matches!(
            self.peek_non_trivia().map(|t| &t.kind),
            Some(TokenKind::Operator(Operator::Pipe))
        ) {
            // No pipe - return single statement
            return Ok(first_stmt);
        }

        // Build pipe chain by continuing to parse statements
        let mut stmts = vec![first_stmt];

        while matches!(
            self.peek_non_trivia().map(|t| &t.kind),
            Some(TokenKind::Operator(Operator::Pipe))
        ) {
            // Consume pipe operator
            self.skip_trivia();
            let pipe_tok = self.advance().ok_or_else(|| {
                ParseError::new(
                    self.current_span(),
                    ParseErrorKind::InvalidSyntax {
                        message: "Expected pipe operator".to_string(),
                    },
                )
            })?;

            // Check for empty segment after pipe
            self.skip_trivia();
            if matches!(
                self.peek_non_trivia().map(|t| &t.kind),
                Some(TokenKind::Eof)
                    | Some(TokenKind::Punctuation(crate::lexer::Punctuation::Semi))
                    | None
            ) {
                return Err(ParseError::new(
                    pipe_tok.span,
                    ParseErrorKind::InvalidSyntax {
                        message: "Pipe operator (->> or |>) has empty statement after it"
                            .to_string(),
                    },
                ));
            }

            // Parse next statement (naturally stops at next pipe or statement end)
            let stmt = self.parse_statement()?;
            stmts.push(stmt);

            self.skip_trivia();
        }

        // Construct PipeChain with correct span
        let chain_span = Span {
            start: chain_start_span.start,
            end: stmts.last().unwrap().span().end,
        };
        Ok(AstStmt::PipeChain {
            node_id: self.id_gen.next(),
            span: chain_span,
            stmts,
        })
    }

    // ========== Helper methods for Result-based parsing ==========

    /// Get a span for the current parser position.
    /// Returns the span of the next token, or the last token if at EOF.
    #[inline]
    pub(crate) fn current_span(&self) -> Span {
        if let Some(tok) = self.peek() {
            tok.span
        } else if !self.tokens.is_empty() {
            self.tokens[self.tokens.len() - 1].span
        } else {
            Span { start: 0, end: 0 }
        }
    }

    /// Check if token is a statement-starting keyword.
    /// Used to detect statement boundaries in multi-statement scripts.
    pub(crate) fn is_statement_keyword(&self, tok: &Token) -> bool {
        let lexeme = tok.lexeme(self.source);
        lexeme.eq_ignore_ascii_case("ALTER")
            || lexeme.eq_ignore_ascii_case("CREATE")
            || lexeme.eq_ignore_ascii_case("DROP")
            || lexeme.eq_ignore_ascii_case("SELECT")
            || lexeme.eq_ignore_ascii_case("INSERT")
            || lexeme.eq_ignore_ascii_case("UPDATE")
            || lexeme.eq_ignore_ascii_case("DELETE")
            || lexeme.eq_ignore_ascii_case("TRUNCATE")
            || lexeme.eq_ignore_ascii_case("MERGE")
            || lexeme.eq_ignore_ascii_case("GRANT")
            || lexeme.eq_ignore_ascii_case("REVOKE")
            || lexeme.eq_ignore_ascii_case("EXPORT")
            || lexeme.eq_ignore_ascii_case("LOAD")
            || lexeme.eq_ignore_ascii_case("ASSERT")
    }

    /// Get a human-readable description of a token.
    pub(crate) fn token_description(tok: &Token, source: &str) -> String {
        match &tok.kind {
            TokenKind::Keyword(kw) => format!("{:?}", kw),
            TokenKind::Operator(_) => tok.lexeme(source).to_string(),
            TokenKind::Punctuation(_) => tok.lexeme(source).to_string(),
            TokenKind::Identifier { .. } => "identifier".to_string(),
            TokenKind::Literal(crate::lexer::LiteralKind::Number) => "number".to_string(),
            TokenKind::Literal(crate::lexer::LiteralKind::String) => "string".to_string(),
            TokenKind::Literal(_) => "literal".to_string(),
            TokenKind::Eof => "end of input".to_string(),
            _ => tok.lexeme(source).to_string(),
        }
    }

    /// Expect and consume a specific keyword, or return an error.
    pub(crate) fn expect_keyword(&mut self, expected: Keyword) -> crate::error::ParseResult<Span> {
        use crate::error::ParseError;

        let tok = self.peek().ok_or_else(|| {
            ParseError::unexpected_eof(self.current_span(), vec![format!("{:?}", expected)])
        })?;

        if let TokenKind::Keyword(kw) = &tok.kind {
            if *kw == expected {
                let span = tok.span;
                self.advance();
                return Ok(span);
            }
        }

        Err(ParseError::unexpected_token(
            tok.span,
            vec![format!("{:?}", expected)],
            Self::token_description(tok, self.source),
        ))
    }

    /// Parse a {% docs model_name %}...{% enddocs %} block.
    /// The content inside is documentation text, not SQL.
    /// Returns a JinjaPlaceholder spanning the entire block.
    fn parse_docs_block(&mut self) -> crate::error::ParseResult<AstStmt> {
        use crate::error::{ExpectInvariant, ParseError, ParseErrorKind};

        let opening_tok = self.peek().ok_or_else(|| {
            ParseError::unexpected_eof(self.current_span(), vec!["{% docs %}".to_string()])
        })?;
        let start = opening_tok.span.start;

        // Consume the entire opening delimiter {% docs name %}
        while let Some(tok) = self.peek() {
            let is_close = matches!(tok.kind, TokenKind::JinjaStmtClose);
            self.advance();
            if is_close {
                break;
            }
        }

        // Consume all tokens until we find {% enddocs %}
        loop {
            let tok = self.peek().ok_or_else(|| {
                ParseError::new(
                    self.current_span(),
                    ParseErrorKind::UnclosedJinjaBlock {
                        block_type: "docs".to_string(),
                        opening_span: crate::lexer::Span { start, end: start },
                    },
                )
            })?;

            // Check for {% enddocs %}
            if let Some(kind) = self.peek_jinja_block_kind() {
                if matches!(kind, crate::ast::JinjaBlockKind::EndDocs) {
                    // Consume the entire closing delimiter {% enddocs %}
                    let mut end = tok.span.end;
                    while let Some(tok) = self.peek() {
                        let is_close = matches!(tok.kind, TokenKind::JinjaStmtClose);
                        end = tok.span.end;
                        self.advance();
                        if is_close {
                            break;
                        }
                    }
                    return Ok(AstStmt::JinjaPlaceholder {
                        node_id: self.id_gen.next(),
                        span: crate::lexer::Span { start, end },
                        kind: crate::ast::JinjaKind::Statement,
                        expr: None,
                        stmt: None,
                    });
                }
            }

            // Consume the token (it's documentation content)
            self.advance().expect_invariant("peek confirmed token");
        }
    }

    fn parse_set_block(&mut self, start: u32) -> crate::error::ParseResult<AstStmt> {
        use crate::error::{ExpectInvariant, ParseError, ParseErrorKind};

        // Consume the closing delimiter of the opening tag (e.g., -%} or %})
        while let Some(tok) = self.peek() {
            let is_close = matches!(tok.kind, TokenKind::JinjaStmtClose);
            self.advance();
            if is_close {
                break;
            }
        }

        // Consume all tokens until we find {% endset %}
        loop {
            let tok = self.peek().ok_or_else(|| {
                ParseError::new(
                    self.current_span(),
                    ParseErrorKind::UnclosedJinjaBlock {
                        block_type: "set".to_string(),
                        opening_span: crate::lexer::Span { start, end: start },
                    },
                )
            })?;

            // Check for {% endset %}
            if matches!(tok.kind, TokenKind::JinjaStmtOpen) {
                // Look ahead to see if next token is 'endset'
                let saved_idx = self.idx;
                self.advance(); // consume {%

                if let Some(next_tok) = self.peek() {
                    if matches!(next_tok.kind, TokenKind::JinjaEndSet) {
                        // Found {% endset %}, consume the rest
                        let mut end = next_tok.span.end;
                        while let Some(tok) = self.peek() {
                            let is_close = matches!(tok.kind, TokenKind::JinjaStmtClose);
                            end = tok.span.end;
                            self.advance();
                            if is_close {
                                break;
                            }
                        }
                        return Ok(AstStmt::JinjaPlaceholder {
                            node_id: self.id_gen.next(),
                            span: crate::lexer::Span { start, end },
                            kind: crate::ast::JinjaKind::Statement,
                            expr: None,
                            stmt: None,
                        });
                    }
                }

                // Not {% endset %}, restore position and continue
                self.idx = saved_idx;
            }

            // Consume the token (it's block content)
            self.advance().expect_invariant("peek confirmed token");
        }
    }

    /// Try to parse a Jinja block that wraps full SQL statements.
    /// Returns None if the content isn't a valid statement-level block,
    /// allowing fallback to simple placeholder handling.
    pub fn try_parse_jinja_stmt_block(
        &mut self,
        opening_kind: crate::ast::JinjaBlockKind,
    ) -> Option<crate::ast::JinjaStmtBlock> {
        use crate::ast::{
            JinjaBlockKind, JinjaStmtBlock, JinjaStmtElifBranch, JinjaStmtElseBranch,
        };

        let saved_idx = self.idx;

        // Consume opening delimiter tokens
        let open_brace_tok = self.advance()?;
        let open_brace_id = self.last_token_id();
        let _keyword_tok = self.advance()?;
        let keyword_id = self.last_token_id();
        let condition = self.parse_jinja_expr().ok().flatten();
        let close_brace_tok = self.advance()?;
        let close_brace_id = self.last_token_id();
        let opening_span = Span {
            start: open_brace_tok.span.start,
            end: close_brace_tok.span.end,
        };
        let opening = self.alloc_jinja_delimiter(
            opening_span,
            opening_kind.clone(),
            condition,
            open_brace_id,
            keyword_id,
            close_brace_id,
        );

        // Determine what closes this block
        let closing_kind = match opening_kind {
            JinjaBlockKind::If => JinjaBlockKind::EndIf,
            JinjaBlockKind::For => JinjaBlockKind::EndFor,
            _ => {
                self.idx = saved_idx;
                return None;
            }
        };

        // Try to parse the content of the primary branch
        // This may include multiple statements/Jinja blocks
        // If parsing fails (e.g., partial statements), capture as opaque content
        self.skip_trivia();

        let then_stmts = match self.parse_jinja_block_content(&closing_kind) {
            Ok(stmts) => stmts,
            Err(_e) => {
                // Parsing failed - consume content as opaque until we hit elif/else/endif
                let _start = self
                    .peek()
                    .map(|t| t.span.start)
                    .unwrap_or(opening_span.end);
                let opaque_stmts = self.consume_opaque_jinja_branch_content(&closing_kind);
                if !opaque_stmts.is_empty() {
                    opaque_stmts
                } else {
                    // No content to salvage, give up on the whole block
                    self.idx = saved_idx;
                    return None;
                }
            }
        };

        // Now look for elif/else/endif
        self.skip_trivia();
        let mut elif_branches = Vec::new();
        let mut else_branch = None;

        // Handle elif branches (only for If blocks)
        if opening_kind == JinjaBlockKind::If {
            while let Some(_tok) = self.peek() {
                if let Some(kind) = self.peek_jinja_block_kind() {
                    if matches!(kind, JinjaBlockKind::Elif) {
                        let open_brace_tok = self.advance()?;
                        let open_brace_id = self.last_token_id();
                        let _keyword_tok = self.advance()?;
                        let keyword_id = self.last_token_id();
                        let condition = self.parse_jinja_expr().ok().flatten();
                        let close_brace_tok = self.advance()?;
                        let close_brace_id = self.last_token_id();
                        let elif_span = Span {
                            start: open_brace_tok.span.start,
                            end: close_brace_tok.span.end,
                        };
                        let elif_delimiter = self.alloc_jinja_delimiter(
                            elif_span,
                            JinjaBlockKind::Elif,
                            condition,
                            open_brace_id,
                            keyword_id,
                            close_brace_id,
                        );

                        self.skip_trivia();
                        let elif_stmts = match self.parse_jinja_block_content(&closing_kind) {
                            Ok(stmts) => stmts,
                            Err(_) => {
                                // Parsing failed - consume as opaque content
                                self.consume_opaque_jinja_branch_content(&closing_kind)
                            }
                        };

                        elif_branches.push(JinjaStmtElifBranch {
                            node_id: self.id_gen.next(),
                            delimiter: elif_delimiter,
                            stmts: elif_stmts,
                        });
                        self.skip_trivia();
                    } else {
                        break;
                    }
                } else {
                    break;
                }
            }
        }

        // Handle optional else branch
        if let Some(_tok) = self.peek() {
            if let Some(kind) = self.peek_jinja_block_kind() {
                if matches!(kind, JinjaBlockKind::Else) {
                    let open_brace_tok = self.advance()?;
                    let open_brace_id = self.last_token_id();
                    let _keyword_tok = self.advance()?;
                    let keyword_id = self.last_token_id();
                    let close_brace_tok = self.advance()?;
                    let close_brace_id = self.last_token_id();
                    let else_span = Span {
                        start: open_brace_tok.span.start,
                        end: close_brace_tok.span.end,
                    };
                    let else_delimiter = self.alloc_jinja_delimiter(
                        else_span,
                        JinjaBlockKind::Else,
                        None,
                        open_brace_id,
                        keyword_id,
                        close_brace_id,
                    );

                    self.skip_trivia();
                    let else_stmts = match self.parse_jinja_block_content(&closing_kind) {
                        Ok(stmts) => stmts,
                        Err(_) => {
                            // Parsing failed - consume as opaque content
                            self.consume_opaque_jinja_branch_content(&closing_kind)
                        }
                    };

                    else_branch = Some(JinjaStmtElseBranch {
                        node_id: self.id_gen.next(),
                        delimiter: else_delimiter,
                        stmts: else_stmts,
                    });
                    self.skip_trivia();
                }
            }
        }

        // Consume closing delimiter
        let _tok = self.peek()?;
        if let Some(kind) = self.peek_jinja_block_kind() {
            if kind == closing_kind {
                let open_brace_tok = self.advance()?;
                let open_brace_id = self.last_token_id();
                let _keyword_tok = self.advance()?;
                let keyword_id = self.last_token_id();
                let close_brace_tok = self.advance()?;
                let close_brace_id = self.last_token_id();
                let closing_span = Span {
                    start: open_brace_tok.span.start,
                    end: close_brace_tok.span.end,
                };
                let closing = self.alloc_jinja_delimiter(
                    closing_span,
                    closing_kind,
                    None,
                    open_brace_id,
                    keyword_id,
                    close_brace_id,
                );

                // Statement span should NOT include trailing semicolons
                // Semicolons are handled by formatter as gap content
                let span = Span {
                    start: opening.span.start,
                    end: closing.span.end,
                };
                return Some(JinjaStmtBlock {
                    node_id: self.id_gen.next(),
                    opening,
                    then_stmts,
                    elif_branches,
                    else_branch,
                    closing,
                    span,
                });
            }
        }

        // Missing closing delimiter - restore and fail
        self.idx = saved_idx;
        None
    }

    /// Parse the content of a Jinja block ({% if %}...{% endif %} or {% for %}...{% endfor %})
    /// This handles sequences of:
    /// - Jinja directives ({% set %}, {% macro %}, etc.)
    /// - Nested control blocks ({% if %}, {% for %})
    /// - SQL statements
    /// - Jinja expressions ({{ ... }})
    ///
    /// Returns a Vec of statements parsed.
    /// Consume content within a Jinja branch as opaque when parsing fails.
    /// Returns a vec with a single OpaqueContent statement covering the consumed tokens.
    fn consume_opaque_jinja_branch_content(
        &mut self,
        closing_kind: &crate::ast::JinjaBlockKind,
    ) -> Vec<crate::ast::AstStmt> {
        let start = self.peek().map(|t| t.span.start).unwrap_or(0);
        let mut end = start;

        // Consume tokens until we hit a Jinja delimiter or EOF
        loop {
            self.skip_trivia();

            // CRITICAL: Check for block-ending delimiters BEFORE consuming the token
            // This prevents consuming {% else %}, {% elif %}, {% endif %} as part of opaque content
            if let Some(kind) = self.peek_jinja_block_kind() {
                if kind == *closing_kind
                    || matches!(
                        kind,
                        crate::ast::JinjaBlockKind::Elif | crate::ast::JinjaBlockKind::Else
                    )
                {
                    break;
                }
            }

            if let Some(tok) = self.peek() {
                // Stop at EOF
                if matches!(tok.kind, TokenKind::Eof) {
                    break;
                }
                // Consume token
                if let Some(consumed) = self.advance() {
                    end = consumed.span.end;
                } else {
                    break;
                }
            } else {
                break;
            }
        }

        // Return opaque content statement if we consumed anything
        if end > start {
            #[cfg(debug_assertions)]
            if std::env::var("LEXEGA_DEBUG_PARSE").is_ok() {
                eprintln!(
                    "DEBUG: OpaqueContent from consume_opaque_jinja_branch_content [{}..{}]",
                    start, end
                );
            }
            vec![crate::ast::AstStmt::OpaqueContent {
                node_id: self.id_gen.next(),
                span: Span { start, end },
            }]
        } else {
            vec![]
        }
    }

    fn parse_jinja_block_content(
        &mut self,
        closing_kind: &crate::ast::JinjaBlockKind,
    ) -> crate::error::ParseResult<Vec<crate::ast::AstStmt>> {
        use crate::lexer::Keyword;

        let mut statements: Vec<crate::ast::AstStmt> = Vec::new();

        loop {
            self.skip_trivia();

            let tok = match self.peek() {
                Some(t) => t,
                None => break,
            };

            // Check for block-ending delimiters (endif, endfor, else, elif)
            if let Some(kind) = self.peek_jinja_block_kind() {
                // Stop at closing delimiter or branch delimiters
                if kind == *closing_kind
                    || matches!(
                        kind,
                        crate::ast::JinjaBlockKind::Elif | crate::ast::JinjaBlockKind::Else
                    )
                {
                    break;
                }
            }

            // Check for EOF or semicolon that would end a statement sequence
            if matches!(tok.kind, TokenKind::Eof) {
                break;
            }

            // Skip standalone semicolons (IMPORTANT: must consume them!)
            if matches!(
                tok.kind,
                TokenKind::Punctuation(crate::lexer::Punctuation::Semi)
            ) {
                self.advance(); // Consume the semicolon
                continue;
            }

            // Check for standalone set operators (UNION, INTERSECT, EXCEPT)
            // These appear inside Jinja blocks like {% if not loop.last %}UNION ALL{% endif %}
            // Capture them as opaque content to be emitted verbatim
            if let Some(_op_kind) = crate::parser::sql_stmt::is_set_op_keyword(&tok.kind) {
                let start = tok.span.start;
                // Consume the set operator keyword
                let op_tok = self.advance();
                let mut end = op_tok.map(|t| t.span.end).unwrap_or(start);
                self.skip_trivia();

                // Consume optional ALL/DISTINCT keyword
                if let Some(next) = self.peek() {
                    if matches!(
                        next.kind,
                        TokenKind::Keyword(Keyword::All) | TokenKind::Keyword(Keyword::Distinct)
                    ) {
                        if let Some(t) = self.advance() {
                            end = t.span.end;
                        }
                    }
                }

                // Create opaque content statement
                #[cfg(debug_assertions)]
                if std::env::var("LEXEGA_DEBUG_PARSE").is_ok() {
                    eprintln!(
                        "DEBUG: OpaqueContent from set_op_keyword [{}..{}]",
                        start, end
                    );
                }
                let opaque_stmt = crate::ast::AstStmt::OpaqueContent {
                    node_id: self.id_gen.next(),
                    span: Span { start, end },
                };
                statements.push(opaque_stmt);
                continue;
            }

            // Try to parse the next statement
            // If it's a statement keyword (SELECT, UPDATE, etc.) that fails to parse because
            // it's incomplete due to Jinja block boundaries, treat it as opaque content
            let is_stmt_keyword = matches!(
                tok.kind,
                TokenKind::Keyword(Keyword::Select)
                    | TokenKind::Keyword(Keyword::Insert)
                    | TokenKind::Keyword(Keyword::Update)
                    | TokenKind::Keyword(Keyword::Delete)
                    | TokenKind::Keyword(Keyword::Merge)
                    | TokenKind::Keyword(Keyword::With)
                    | TokenKind::Keyword(Keyword::Values)
            );

            let start_pos = tok.span.start;
            let stmt_result = self.parse_statement();

            match stmt_result {
                Ok(mut stmt) => {
                    // Successfully parsed - now capture semicolon if present
                    // Peek for semicolon after the statement (never consume it)
                    let captured_semicolon = if let Some(semi_tok) = self.peek_non_trivia() {
                        if matches!(
                            semi_tok.kind,
                            TokenKind::Punctuation(crate::lexer::Punctuation::Semi)
                        ) {
                            Some(self.current_token_id())
                        } else {
                            None
                        }
                    } else {
                        None
                    };

                    // Attach semicolon to statement if supported
                    match &mut stmt {
                        AstStmt::Select(ref mut s) => s.semicolon_token = captured_semicolon,
                        AstStmt::SetSelect(ref mut s) => s.semicolon_token = captured_semicolon,
                        AstStmt::Insert(ref mut s) => s.semicolon_token = captured_semicolon,
                        AstStmt::Update(ref mut s) => s.semicolon_token = captured_semicolon,
                        AstStmt::Delete(ref mut s) => s.semicolon_token = captured_semicolon,
                        AstStmt::Merge(ref mut s) => s.semicolon_token = captured_semicolon,
                        AstStmt::CreateTable(ref mut s) => s.semicolon_token = captured_semicolon,
                        AstStmt::CreateView(ref mut s) => s.semicolon_token = captured_semicolon,
                        AstStmt::Call {
                            ref mut semicolon_token,
                            ..
                        } => {
                            *semicolon_token = captured_semicolon;
                        }
                        AstStmt::Grant(ref mut g) => {
                            g.semicolon_token = captured_semicolon;
                        }
                        AstStmt::Revoke(ref mut r) => {
                            r.semicolon_token = captured_semicolon;
                        }
                        AstStmt::Deny(ref mut d) => {
                            d.semicolon_token = captured_semicolon;
                        }
                        AstStmt::ExecuteImmediate {
                            ref mut semicolon_token,
                            ..
                        } => {
                            *semicolon_token = captured_semicolon;
                        }
                        _ => {} // Other statement types don't support semicolon_token yet
                    }

                    statements.push(stmt);
                }
                Err(_parse_err) if is_stmt_keyword => {
                    // Statement keyword that failed to parse - likely a partial statement
                    // spanning Jinja block boundary. Consume until next Jinja delimiter and wrap as opaque.
                    let mut end_pos = start_pos;

                    loop {
                        self.skip_trivia();
                        if let Some(next_tok) = self.peek() {
                            // Stop at Jinja delimiters (closing or branch)
                            if let Some(kind) = self.peek_jinja_block_kind() {
                                if kind == *closing_kind
                                    || matches!(
                                        kind,
                                        crate::ast::JinjaBlockKind::Elif
                                            | crate::ast::JinjaBlockKind::Else
                                    )
                                {
                                    break;
                                }
                            }
                            // Stop at EOF
                            if matches!(next_tok.kind, TokenKind::Eof) {
                                break;
                            }

                            // Consume the token and update end position
                            if let Some(consumed) = self.advance() {
                                end_pos = consumed.span.end;
                            } else {
                                break;
                            }
                        } else {
                            break;
                        }
                    }

                    // Create opaque content for the incomplete statement
                    #[cfg(debug_assertions)]
                    if std::env::var("LEXEGA_DEBUG_PARSE").is_ok() {
                        eprintln!(
                            "DEBUG: OpaqueContent from incomplete statement [{}..{}]",
                            start_pos, end_pos
                        );
                    }
                    let opaque_stmt = crate::ast::AstStmt::OpaqueContent {
                        node_id: self.id_gen.next(),
                        span: Span {
                            start: start_pos,
                            end: end_pos,
                        },
                    };
                    statements.push(opaque_stmt);
                }
                Err(e) => {
                    // Non-statement keyword that failed - propagate the error
                    return Err(e);
                }
            }
        }

        // Return the statements (empty blocks like {% if %}{% endif %} are valid)
        Ok(statements)
    }

    /// Parse a SQL clause fragment (WHERE, JOIN, HAVING, etc.) that appears inside a Jinja block
    /// and wrap it as a ClauseFragment statement for proper AST representation.
    fn try_parse_clause_fragment_as_stmt(&mut self) -> crate::error::ParseResult<AstStmt> {
        use crate::error::{ParseError, ParseErrorKind};

        let start_tok = self.peek().ok_or_else(|| {
            ParseError::unexpected_eof(self.current_span(), vec!["clause keyword".to_string()])
        })?;
        let start_span = start_tok.span;

        // Parse as a StatementFragment (JOINs + WHERE + HAVING)
        let fragment = self.parse_statement_fragment(0)?.ok_or_else(|| {
            ParseError::new(
                start_span,
                ParseErrorKind::InvalidSyntax {
                    message: "Failed to parse clause fragment".to_string(),
                },
            )
        })?;

        let span = fragment.span;

        // Wrap the StatementFragment as a ClauseFragment statement
        Ok(AstStmt::ClauseFragment {
            node_id: self.id_gen.next(),
            fragment: Box::new(fragment),
            span,
        })
    }
}

// ============================================================================
// Tolerant Parsing (for LSP)
// ============================================================================

impl<'a> Parser<'a> {
    // ========== Tolerant Parsing API ==========

    /// Parse a script in tolerant mode, returning partial AST even on errors.
    ///
    /// This is the **primary entry point for LSP** parsing. Unlike `try_parse_script()`,
    /// this method:
    /// 1. Continues parsing after syntax errors
    /// 2. Creates `AstStmt::Error` nodes for unparseable regions
    /// 3. Synchronizes at statement boundaries (semicolons, statement keywords)
    /// 4. Returns all errors alongside the partial AST
    ///
    /// # Returns
    /// `TolerantParseResult<AstScript>` containing:
    /// - `ast`: The parsed script with Error nodes for unparseable regions
    /// - `errors`: All parse errors encountered
    /// - `is_complete`: Whether parsing succeeded without errors
    pub fn parse_tolerant(&mut self) -> crate::error::TolerantParseResult<AstScript> {
        use crate::error::TolerantParseResult;

        let mut stmts = Vec::new();
        let mut errors = Vec::new();

        loop {
            self.skip_trivia();

            // Check for end of input
            let tok = match self.peek_non_trivia() {
                Some(t) => t,
                None => break,
            };

            // Stop at EOF
            if matches!(tok.kind, TokenKind::Eof) {
                break;
            }

            // Skip lone semicolons between statements
            if matches!(
                tok.kind,
                TokenKind::Punctuation(crate::lexer::Punctuation::Semi)
            ) {
                let _ = self.advance();
                continue;
            }

            // Save position to detect infinite loops
            let loop_guard_idx = self.idx;

            // Try to parse a statement
            let stmt_start = tok.span.start;
            match self.try_parse_one_statement_tolerant() {
                Ok(stmt) => {
                    stmts.push(stmt);
                }
                Err(err) => {
                    // Create an error node and synchronize to next statement
                    let (error_node, sync_pos) = self.create_error_node_and_sync(stmt_start, &err);
                    stmts.push(error_node);
                    errors.push(err);

                    // Advance to sync position
                    while self.idx < sync_pos {
                        self.advance();
                    }
                }
            }

            // SAFETY: Ensure we always make progress to prevent infinite loops
            if self.idx == loop_guard_idx {
                // Force advance at least one token
                self.advance();
            }
        }

        // Move the syntax arena into the AstScript
        let syntax_arena = std::mem::take(&mut self.syntax_arena);

        let ast = AstScript {
            node_id: self.id_gen.next(),
            stmts,
            syntax_arena,
            redaction_spans: std::mem::take(&mut self.redaction_spans),
        };

        if errors.is_empty() {
            TolerantParseResult::success(ast)
        } else {
            TolerantParseResult::partial(ast, errors)
        }
    }

    /// Try to parse a single statement, returning error info on failure.
    /// This is the tolerant-mode version that captures error details.
    fn try_parse_one_statement_tolerant(&mut self) -> ParseResult<AstStmt> {
        // Save position for potential rollback
        let saved_idx = self.idx;

        // Attempt to parse using the normal statement parser
        let result = self.parse_statement();

        // If parse failed, restore position (sync will handle advancement)
        if result.is_err() {
            self.idx = saved_idx;
        }

        result
    }

    /// Create an Error node for unparseable content and find the next sync point.
    ///
    /// Returns: (error_node, sync_token_index)
    fn create_error_node_and_sync(&self, start_pos: u32, error: &ParseError) -> (AstStmt, usize) {
        // Find the next recovery point (semicolon or statement-starting keyword)
        let (end_pos, sync_idx, partial_tokens) = self.find_recovery_point(start_pos);

        let error_node = AstStmt::Error {
            node_id: self.id_gen.next(),
            span: Span {
                start: start_pos,
                end: end_pos,
            },
            message: error.message(),
            partial_tokens,
        };

        (error_node, sync_idx)
    }

    /// Find the next statement boundary for error recovery.
    ///
    /// Scans forward from current position to find:
    /// 1. A semicolon (end of statement)
    /// 2. A statement-starting keyword (SELECT, INSERT, CREATE, etc.)
    /// 3. End of input
    ///
    /// IMPORTANT: Always advances at least one token to prevent infinite loops.
    ///
    /// Returns: (end_position, sync_token_index, partial_token_summary)
    fn find_recovery_point(&self, start_pos: u32) -> (u32, usize, Vec<String>) {
        let mut end_pos = start_pos;
        let mut sync_idx = self.idx;
        let mut partial_tokens = Vec::new();
        let max_tokens_to_record = 10;
        let mut is_first_token = true;

        for i in self.idx..self.tokens.len() {
            let tok = &self.tokens[i];

            // Skip EOF tokens
            if matches!(tok.kind, TokenKind::Eof) {
                continue;
            }

            // Record token for diagnostics (limited count)
            if partial_tokens.len() < max_tokens_to_record {
                partial_tokens.push(format!("{:?}", tok.kind));
            }

            // Update end position
            end_pos = tok.span.end;

            // Check for recovery points - but SKIP the first token!
            // We must advance at least one token to avoid infinite loops.
            if !is_first_token && self.is_recovery_point(tok) {
                // If it's a semicolon, include it in the error region but sync after
                if matches!(
                    tok.kind,
                    TokenKind::Punctuation(crate::lexer::Punctuation::Semi)
                ) {
                    sync_idx = i + 1;
                } else {
                    // For statement keywords, sync AT this token (don't include in error)
                    end_pos = tok.span.start;
                    sync_idx = i;
                }
                break;
            }

            is_first_token = false;
            sync_idx = i + 1;
        }

        (end_pos, sync_idx, partial_tokens)
    }

    /// Check if a token is a valid recovery point (statement boundary).
    fn is_recovery_point(&self, tok: &Token) -> bool {
        use crate::lexer::Punctuation;

        match &tok.kind {
            // Semicolons end statements
            TokenKind::Punctuation(Punctuation::Semi) => true,

            // Statement-starting keywords indicate a new statement
            TokenKind::Keyword(kw) => self.is_statement_starting_keyword(kw),

            _ => false,
        }
    }

    /// Dialect-aware boundary detection for scanners that would otherwise consume
    /// until semicolon/EOF.
    ///
    /// For MSSQL, semicolons are optional in many scripts. Open-ended statement
    /// scanners should stop when the next top-level token clearly starts a new
    /// statement, a GO batch separator, or a clause boundary token that must not
    /// be consumed as an alias (e.g., OUTPUT after DELETE/UPDATE target table).
    pub(crate) fn should_stop_scan_at_statement_start(&self, tok: &Token) -> bool {
        if !self.dialect.uses_optional_statement_terminators() {
            return false;
        }

        match &tok.kind {
            TokenKind::Keyword(kw) => {
                self.is_statement_starting_keyword(kw) || matches!(kw, Keyword::Output)
            }
            TokenKind::Identifier { .. } => {
                let lex = tok.lexeme(self.source);
                lex.eq_ignore_ascii_case("GO")
                    || lex.eq_ignore_ascii_case("PRINT")
                    || lex.eq_ignore_ascii_case("EXEC")
                    || lex.eq_ignore_ascii_case("RECONFIGURE")
            }
            _ => false,
        }
    }

    /// Context-sensitive identifier check that centralizes dialect-aware parsing rules.
    ///
    /// Prefer this over direct `TokenKind::can_be_identifier()` in parser code.
    #[inline]
    pub(crate) fn can_be_identifier_in_context(
        &self,
        tok: &Token,
        context: IdentifierContext,
    ) -> bool {
        let is_unquoted_identifier = match &tok.kind {
            TokenKind::Identifier { .. } => true,
            TokenKind::Keyword(_) => {
                let lexeme = tok.lexeme(self.source);
                self.dialect.keyword_can_be_unquoted_identifier(lexeme)
            }
            _ => false,
        };

        match context {
            IdentifierContext::Generic => is_unquoted_identifier,
            IdentifierContext::AfterDot => tok.kind.can_be_identifier_after_dot(),
            IdentifierContext::Alias => {
                let is_unquoted_alias = match &tok.kind {
                    TokenKind::Identifier { .. } => {
                        let lexeme = tok.lexeme(self.source);
                        self.dialect.keyword_can_be_unquoted_alias(lexeme)
                    }
                    TokenKind::Keyword(_) => {
                        let lexeme = tok.lexeme(self.source);
                        self.dialect.keyword_can_be_unquoted_alias(lexeme)
                    }
                    _ => false,
                };

                if !is_unquoted_alias {
                    return false;
                }

                if self.should_stop_scan_at_statement_start(tok) {
                    return false;
                }
                true
            }
        }
    }

    #[inline]
    pub(crate) fn can_be_identifier_token(&self, tok: &Token) -> bool {
        self.can_be_identifier_in_context(tok, IdentifierContext::Generic)
    }

    #[inline]
    pub(crate) fn can_be_alias_token(&self, tok: &Token) -> bool {
        self.can_be_identifier_in_context(tok, IdentifierContext::Alias)
    }

    #[inline]
    pub(crate) fn can_be_identifier_after_dot_token(&self, tok: &Token) -> bool {
        self.can_be_identifier_in_context(tok, IdentifierContext::AfterDot)
    }

    /// Parse a dot-separated qualified name (e.g., `db.schema.name`).
    ///
    /// Accepts identifiers (quoted or unquoted) and string literals.
    /// For identifiers, continues consuming `.identifier` pairs for qualified names.
    /// For string literals, returns the literal span directly (no dot-chaining).
    /// Uses `can_be_identifier_token` for the first part and
    /// `can_be_identifier_after_dot_token` for parts after a dot.
    pub(crate) fn parse_qualified_name_span(&mut self) -> ParseResult<Span> {
        let first = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["identifier".to_string()])?;

        // String literals are valid in some name positions (e.g., USING SHARE 'provider.share1')
        if matches!(
            first.kind,
            TokenKind::Literal(crate::lexer::LiteralKind::String)
        ) {
            return Ok(first.span);
        }

        if !self.can_be_identifier_token(first) {
            return Err(ParseError::new(
                first.span,
                ParseErrorKind::InvalidStatement {
                    message: format!("Expected identifier, found '{}'", first.lexeme(self.source)),
                },
            ));
        }

        let start = first.span.start;
        let mut end = first.span.end;

        while let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Dot)) {
                self.advance(); // consume dot
                if let Some(next) = self.peek_non_trivia() {
                    if self.can_be_identifier_after_dot_token(next) {
                        let n = self
                            .advance()
                            .expect_invariant("identifier consumed after dot");
                        end = n.span.end;
                    } else {
                        break;
                    }
                } else {
                    break;
                }
            } else {
                break;
            }
        }

        Ok(Span { start, end })
    }

    /// Check if a keyword typically starts a new statement.
    fn is_statement_starting_keyword(&self, kw: &Keyword) -> bool {
        matches!(
            kw,
            // DML
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
            // DCL
                | Keyword::Grant
                | Keyword::Revoke
                | Keyword::Deny
            // Transaction control
                | Keyword::Begin
                | Keyword::Commit
                | Keyword::Rollback
            // Session/utility
                | Keyword::Use
                | Keyword::Show
                | Keyword::Describe
                | Keyword::Copy
                | Keyword::Call
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
            // Block delimiters (prevent END/ELSE from being consumed as aliases)
                | Keyword::End
                | Keyword::Else
                | Keyword::Try
                | Keyword::Catch
        )
    }
}

// ============================================================================
// Tests for Tolerant Parsing
// ============================================================================

#[cfg(test)]
mod recovery_fragmentation_tests {
    use super::*;
    use crate::lexer::tokenize;

    fn parse(sql: &str) -> AstScript {
        let tokens = tokenize(sql).tokens;
        let mut parser = Parser::new(sql, &tokens);
        parser
            .try_parse_script()
            .expect("tolerant parse always yields a script")
    }

    // A statement that fails to parse recovers as ONE OpaqueContent spanning
    // its whole extent — not one fragment per inner SELECT / CTE boundary —
    // and the statement that follows it still parses. Regression guard for the
    // depth-aware recovery resync: a depth-blind scan split a single failed
    // `WITH … (…) SELECT …` query into many opaque skips and corrupted the
    // statements after it.
    #[test]
    fn failed_cte_query_is_one_opaque_and_preserves_following_stmt() {
        // `SELECT 1 AS x 2 AS y` is unparseable (no comma between items).
        let sql = "WITH a AS (SELECT 1 AS x 2 AS y FROM t), b AS (SELECT * FROM a) \
                   SELECT * FROM b;\nSELECT id FROM real_table";
        let script = parse(sql);
        assert_eq!(
            script.stmts.len(),
            2,
            "broken CTE query must not fragment; stmts: {:?}",
            script.stmts
        );
        assert!(
            matches!(script.stmts.first(), Some(AstStmt::OpaqueContent { .. })),
            "the failed query is a single opaque statement; got {:?}",
            script.stmts.first()
        );
        assert!(
            matches!(script.stmts.last(), Some(AstStmt::Select(_))),
            "the following SELECT must be preserved; got {:?}",
            script.stmts.last()
        );
    }

    // A SELECT inside a failed statement's subquery must not be read as a new
    // statement boundary — depth tracking keeps it part of the failed query.
    #[test]
    fn inner_subquery_select_is_not_a_recovery_boundary() {
        let sql = "SELECT * FROM (SELECT 1 AS x 2 AS y) z;\nSELECT id FROM real_table";
        let script = parse(sql);
        assert_eq!(
            script.stmts.len(),
            2,
            "subquery failure must not fragment; stmts: {:?}",
            script.stmts
        );
        assert!(matches!(script.stmts.last(), Some(AstStmt::Select(_))));
    }
}

#[cfg(test)]
mod tolerant_parse_tests {
    use super::*;
    use crate::lexer::tokenize;

    #[test]
    fn test_tolerant_parse_all_valid() {
        let sql = "SELECT 1; SELECT 2; SELECT 3;";
        let tokens = tokenize(sql).tokens;
        let mut parser = Parser::new(sql, &tokens);

        let result = parser.parse_tolerant();

        assert!(result.is_complete, "Should complete without errors");
        assert!(result.errors.is_empty(), "Should have no errors");
        assert_eq!(result.ast.stmts.len(), 3, "Should have 3 statements");

        // All should be Select statements
        for stmt in &result.ast.stmts {
            assert!(
                matches!(stmt, AstStmt::Select(_)),
                "Should be Select: {:?}",
                stmt
            );
        }
    }

    #[test]
    fn test_tolerant_parse_single_error() {
        let sql = "SELECT 1; SELEKT bad syntax; SELECT 3;";
        let tokens = tokenize(sql).tokens;
        let mut parser = Parser::new(sql, &tokens);

        let result = parser.parse_tolerant();

        assert!(!result.is_complete, "Should have errors");
        assert_eq!(result.errors.len(), 1, "Should have 1 error");
        assert_eq!(
            result.ast.stmts.len(),
            3,
            "Should have 3 statements (including error)"
        );

        // First and third should be Select
        assert!(matches!(&result.ast.stmts[0], AstStmt::Select(_)));
        assert!(matches!(&result.ast.stmts[2], AstStmt::Select(_)));

        // Second should be Error
        assert!(matches!(&result.ast.stmts[1], AstStmt::Error { .. }));
    }

    #[test]
    fn test_tolerant_parse_multiple_errors() {
        let sql = "SELECT 1; BAD; ALSO BAD; SELECT 4;";
        let tokens = tokenize(sql).tokens;
        let mut parser = Parser::new(sql, &tokens);

        let result = parser.parse_tolerant();

        assert!(!result.is_complete, "Should have errors");
        assert!(result.errors.len() >= 2, "Should have at least 2 errors");

        // First and last should be Select
        assert!(matches!(
            result.ast.stmts.first().unwrap(),
            AstStmt::Select(_)
        ));
        assert!(matches!(
            result.ast.stmts.last().unwrap(),
            AstStmt::Select(_)
        ));
    }

    #[test]
    fn test_tolerant_parse_incomplete_statement() {
        // User is mid-edit - incomplete WHERE clause
        let sql = "SELECT * FROM users WHERE ";
        let tokens = tokenize(sql).tokens;
        let mut parser = Parser::new(sql, &tokens);

        let result = parser.parse_tolerant();

        // Should have at least one statement (possibly error)
        assert!(
            !result.ast.stmts.is_empty(),
            "Should have at least one statement"
        );
    }

    #[test]
    fn test_tolerant_parse_error_span() {
        let sql = "SELECT 1; INVALID STUFF HERE; SELECT 3;";
        let tokens = tokenize(sql).tokens;
        let mut parser = Parser::new(sql, &tokens);

        let result = parser.parse_tolerant();

        // Find the error node
        let error_node = result
            .ast
            .stmts
            .iter()
            .find(|s| matches!(&s, AstStmt::Error { .. }));
        assert!(error_node.is_some(), "Should have an error node");

        if let AstStmt::Error { span, message, .. } = &error_node.unwrap() {
            // Error span should be within the source bounds
            assert!(span.start >= 10, "Error should start after 'SELECT 1; '");
            assert!(
                span.end <= sql.len() as u32,
                "Error should end within source"
            );
            assert!(!message.is_empty(), "Error should have a message");
        }
    }

    #[test]
    fn test_tolerant_parse_empty_input() {
        let sql = "";
        let tokens = tokenize(sql).tokens;
        let mut parser = Parser::new(sql, &tokens);

        let result = parser.parse_tolerant();

        assert!(result.is_complete, "Empty input should be valid");
        assert!(result.errors.is_empty(), "Should have no errors");
        assert!(result.ast.stmts.is_empty(), "Should have no statements");
    }

    #[test]
    fn test_tolerant_parse_only_semicolons() {
        let sql = ";;;";
        let tokens = tokenize(sql).tokens;
        let mut parser = Parser::new(sql, &tokens);

        let result = parser.parse_tolerant();

        assert!(result.is_complete, "Only semicolons should be valid");
        assert!(result.ast.stmts.is_empty(), "Should have no statements");
    }

    #[test]
    fn test_tolerant_parse_recovery_at_keyword() {
        // Error followed immediately by a keyword
        let sql = "BAD SELECT 1;";
        let tokens = tokenize(sql).tokens;
        let mut parser = Parser::new(sql, &tokens);

        let result = parser.parse_tolerant();

        // Should recover and parse the SELECT
        let has_select = result
            .ast
            .stmts
            .iter()
            .any(|s| matches!(&s, AstStmt::Select(_)));
        assert!(has_select, "Should recover and parse SELECT");
    }

    #[test]
    fn test_error_node_has_partial_tokens() {
        let sql = "INVALID token stream here; SELECT 1;";
        let tokens = tokenize(sql).tokens;
        let mut parser = Parser::new(sql, &tokens);

        let result = parser.parse_tolerant();

        // Find error node and check it has token info
        if let Some(stmt) = result
            .ast
            .stmts
            .iter()
            .find(|s| matches!(&s, AstStmt::Error { .. }))
        {
            if let AstStmt::Error { partial_tokens, .. } = &stmt {
                assert!(
                    !partial_tokens.is_empty(),
                    "Error should have partial token info"
                );
            }
        }
    }
}
