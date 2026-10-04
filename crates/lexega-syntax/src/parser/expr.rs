// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Expression parsing
//!
//! This module handles parsing of all expression types:
//! - Primary expressions (literals, identifiers, function calls)
//! - Binary operators (arithmetic, comparison, logical)
//! - Unary operators (NOT, unary minus/plus)
//! - CASE expressions
//! - Subqueries in expressions

use crate::ast::*;
use crate::error::{ExpectInvariant, ParseError, ParseErrorKind, ParseResult};
use crate::lexer::{Keyword, Span, Token, TokenKind};
use crate::parser::core::{track_depth, Parser, ParserMode};
use crate::parser::scripting::expr_span_end;

/// Introducer of an ODBC escape clause in expression position.
#[derive(Debug, Clone, Copy)]
enum OdbcExprIntro {
    Literal(OdbcLiteralKind),
    Fn,
    Interval,
}

// ============================================================================
// Logical Chain Flattening
// ============================================================================

/// Threshold for converting nested BinaryOp OR/AND chains into LogicalChain.
/// Chains shorter than this remain as nested BinaryOp for simpler processing.
const LOGICAL_CHAIN_THRESHOLD: usize = 3;

/// Flatten deeply nested OR/AND chains into LogicalChain nodes.
/// This prevents stack overflow when walking expressions with 100s of conditions.
///
/// The function walks the expression tree iteratively and converts:
///   BinaryOp(a, OR, BinaryOp(b, OR, BinaryOp(c, OR, d)))
/// Into:
///   LogicalChain { operator: Or, operands: [a, b, c, d] }
///
/// Only chains of 3+ same-operator OR/AND are flattened.
pub(crate) fn flatten_logical_chains(expr: AstExpr) -> AstExpr {
    // Iterative work stack to avoid recursion during flattening
    // We use a vec of (expr, parent_idx, is_processed) tuples
    // where parent_idx points to where to store the result

    // For simplicity, we'll do a single pass that handles the top-level OR/AND chains
    // and recursively (but safely) flatten children
    flatten_expr(expr)
}

/// Recursively flatten an expression, converting long OR/AND chains.
fn flatten_expr(expr: AstExpr) -> AstExpr {
    match expr {
        // Check if this is an OR or AND chain that should be flattened
        AstExpr::BinaryOp {
            node_id: nid,
            operator,
            left,
            right,
            span,
            syntax_id,
        } if matches!(operator, BinaryOperator::Or | BinaryOperator::And) => {
            // Collect all operands in the chain
            let mut operands: Vec<Box<AstExpr>> = Vec::new();
            let mut syntax_ids: Vec<crate::syntax::SyntaxBinaryOpId> = Vec::new();

            // Use a work stack to collect chain elements iteratively
            collect_chain_operands(
                AstExpr::BinaryOp {
                    node_id: nid,
                    operator,
                    left,
                    right,
                    span,
                    syntax_id,
                },
                operator,
                &mut operands,
                &mut syntax_ids,
            );

            // If chain is long enough, create LogicalChain
            if operands.len() >= LOGICAL_CHAIN_THRESHOLD {
                // Recursively flatten children (they are already non-matching operator nodes)
                let flattened_operands: Vec<Box<AstExpr>> = operands
                    .into_iter()
                    .map(|op| Box::new(flatten_expr(*op)))
                    .collect();

                let chain_operator = match operator {
                    BinaryOperator::Or => LogicalChainOperator::Or,
                    BinaryOperator::And => LogicalChainOperator::And,
                    _ => unreachable!(),
                };

                AstExpr::LogicalChain {
                    node_id: nid,
                    operator: chain_operator,
                    operands: flattened_operands,
                    operator_syntax_ids: syntax_ids,
                    span,
                }
            } else {
                // Short chain - keep as nested BinaryOp but flatten children
                rebuild_binary_chain(operands, syntax_ids, operator, span)
            }
        }

        // Recursively flatten children for other expression types
        AstExpr::BinaryOp {
            node_id: nid,
            operator,
            left,
            right,
            span,
            syntax_id,
        } => AstExpr::BinaryOp {
            node_id: nid,
            operator,
            left: Box::new(flatten_expr(*left)),
            right: Box::new(flatten_expr(*right)),
            span,
            syntax_id,
        },

        AstExpr::Parenthesized {
            node_id: nid,
            expr: inner,
            syntax_id,
            span,
        } => AstExpr::Parenthesized {
            node_id: nid,
            expr: Box::new(flatten_expr(*inner)),
            syntax_id,
            span,
        },

        AstExpr::Case {
            node_id: nid,
            syntax_id,
            kind,
            operand,
            whens,
            else_expr,
            span,
        } => AstExpr::Case {
            node_id: nid,
            syntax_id,
            kind,
            operand: operand.map(|e| Box::new(flatten_expr(*e))),
            whens: whens
                .into_iter()
                .map(|w| {
                    Box::new(crate::ast::AstCaseWhen {
                        node_id: w.node_id,
                        prefix_inline_fragments: w.prefix_inline_fragments,
                        when_span: w.when_span,
                        cond: flatten_expr(w.cond),
                        then_span: w.then_span,
                        result: flatten_expr(w.result),
                        suffix_inline_fragments: w.suffix_inline_fragments,
                    })
                })
                .collect(),
            else_expr: else_expr.map(|e| Box::new(flatten_expr(*e))),
            span,
        },

        // Pass through other expression types unchanged
        // (they either have no children or children don't need flattening)
        other => other,
    }
}

/// Collect all operands from a chain of same-operator OR/AND expressions.
/// Uses iterative approach to avoid recursion.
#[allow(clippy::vec_box)] // fills `AstExpr::LogicalChain::operands`, a `Vec<Box<AstExpr>>`
fn collect_chain_operands(
    expr: AstExpr,
    target_op: BinaryOperator,
    operands: &mut Vec<Box<AstExpr>>,
    syntax_ids: &mut Vec<crate::syntax::SyntaxBinaryOpId>,
) {
    let mut stack = vec![expr];

    while let Some(current) = stack.pop() {
        match current {
            AstExpr::BinaryOp {
                node_id: _,
                operator,
                left,
                right,
                syntax_id,
                ..
            } if operator == target_op => {
                // This is part of the chain - push right first (so left is processed first)
                syntax_ids.push(syntax_id);
                stack.push(*right);
                stack.push(*left);
            }
            other => {
                // Not part of chain - this is an operand
                operands.push(Box::new(other));
            }
        }
    }

    // Syntax IDs are collected in reverse order (outermost to innermost)
    // but we need them in forward order (innermost to outermost) for formatting
    syntax_ids.reverse();
}

/// Rebuild a short chain back into nested BinaryOp nodes.
#[allow(clippy::vec_box)] // takes the operands `collect_chain_operands` gathered
fn rebuild_binary_chain(
    mut operands: Vec<Box<AstExpr>>,
    mut syntax_ids: Vec<crate::syntax::SyntaxBinaryOpId>,
    operator: BinaryOperator,
    overall_span: Span,
) -> AstExpr {
    // Start from the last operand and build backwards
    if operands.is_empty() {
        // Should not happen, but return a placeholder
        return AstExpr::Literal {
            node_id: crate::ast::NodeId::new(overall_span.start),
            literal: AstLiteral::Null { span: overall_span },
        };
    }

    // Flatten children first
    operands = operands
        .into_iter()
        .map(|op| Box::new(flatten_expr(*op)))
        .collect();

    // Build right-to-left
    let mut result = *operands.pop().unwrap();
    while let Some(left_operand) = operands.pop() {
        let syntax_id = syntax_ids
            .pop()
            .unwrap_or(crate::syntax::SyntaxBinaryOpId(0));
        let left_start = crate::parser::scripting::expr_span_start(&left_operand);
        let right_end = crate::parser::scripting::expr_span_end(&result);

        result = AstExpr::BinaryOp {
            node_id: crate::ast::NodeId::new(left_start),
            left: left_operand,
            operator,
            syntax_id,
            right: Box::new(result),
            span: Span {
                start: left_start,
                end: right_end,
            },
        };
    }

    result
}

// ============================================================================
// Pratt Parser: Binding Power Definitions
// ============================================================================

/// Binding power (precedence) for infix operators.
/// Higher values bind tighter. Returns (left_bp, right_bp).
/// Left-associative: r_bp = l_bp + 1
/// Right-associative: l_bp = r_bp + 1
#[inline]
pub(crate) fn infix_binding_power(
    tok: &Token,
    dialect: &dyn crate::dialect::Dialect,
) -> Option<(u8, u8)> {
    use crate::lexer::Operator;

    match &tok.kind {
        // OR - lowest precedence (left-associative)
        TokenKind::Keyword(Keyword::Or) => Some((10, 11)),

        // || as logical OR (MySQL): same precedence as OR keyword
        TokenKind::Operator(Operator::PipePipe) if !dialect.pipe_pipe_is_concat() => Some((10, 11)),

        // AND (left-associative)
        TokenKind::Keyword(Keyword::And) => Some((20, 21)),

        // Comparison operators: =, !=, <>, <, <=, >, >=, <=> (null-safe)
        TokenKind::Operator(Operator::Eq)
        | TokenKind::Operator(Operator::NotEq)
        | TokenKind::Operator(Operator::AngleNotEq)
        | TokenKind::Operator(Operator::Lt)
        | TokenKind::Operator(Operator::Le)
        | TokenKind::Operator(Operator::Gt)
        | TokenKind::Operator(Operator::Ge)
        | TokenKind::Operator(Operator::LtEqGt) => Some((30, 31)),

        // LIKE, ILIKE, RLIKE, REGEXP - same precedence as comparison
        TokenKind::Keyword(Keyword::Like)
        | TokenKind::Keyword(Keyword::Ilike)
        | TokenKind::Keyword(Keyword::Rlike)
        | TokenKind::Keyword(Keyword::Regexp) => Some((30, 31)),

        // Addition/subtraction and string concatenation (left-associative)
        // || as concat (Snowflake/PG) binds at arithmetic level
        TokenKind::Operator(Operator::Plus)
        | TokenKind::Operator(Operator::Minus)
        | TokenKind::Operator(Operator::PipePipe)  // concat case (guard above handles OR case)
        | TokenKind::Operator(Operator::LtMinusGt) => Some((40, 41)),

        // Multiplication/division/modulo (left-associative)
        TokenKind::Operator(Operator::Star)
        | TokenKind::Operator(Operator::Slash)
        | TokenKind::Operator(Operator::Percent) => Some((50, 51)),

        // PostgreSQL array/JSON operators - same precedence as comparison
        TokenKind::Operator(Operator::AtGt)          // @> contains
        | TokenKind::Operator(Operator::LtAt)        // <@ contained by
        | TokenKind::Operator(Operator::AmpAmp)      // && array overlap
        | TokenKind::Operator(Operator::RightArrow)  // -> JSON field (also used for policies)
        | TokenKind::Operator(Operator::MinusGtGt)   // ->> JSON field as text (PG/MySQL)
        | TokenKind::Operator(Operator::HashGt)      // #> JSON path
        | TokenKind::Operator(Operator::HashGtGt)    // #>> JSON path as text
        | TokenKind::Operator(Operator::AtQuestion)  // @? JSON contains
        | TokenKind::Operator(Operator::QuestionQuestion)  // ?? JSON exists
        => Some((30, 31)),

        // PostgreSQL regex operators - same precedence as LIKE
        TokenKind::Operator(Operator::Tilde)          // ~ regex match
        | TokenKind::Operator(Operator::RegexMatch)   // ~ regex match
        | TokenKind::Operator(Operator::RegexMatchI)  // ~* regex match case-insensitive
        | TokenKind::Operator(Operator::RegexNotMatch) // !~ regex not match
        | TokenKind::Operator(Operator::RegexNotMatchI) // !~* regex not match case-insensitive
        => Some((30, 31)),

        // Bit operators - between addition and multiplication
        TokenKind::Operator(Operator::LtLt)   // << left shift
        | TokenKind::Operator(Operator::GtGt) // >> right shift
        | TokenKind::Operator(Operator::Caret) // ^ XOR / power
        | TokenKind::Operator(Operator::Hash)  // # bitwise XOR (PostgreSQL)
        => Some((45, 46)),

        _ => None,
    }
}

/// Binding power for compound predicates that need special parsing.
/// Returns (left_bp, right_bp) at comparison level.
/// These predicates are: IS, IN, BETWEEN, LIKE, ILIKE, RLIKE
#[inline]
pub(crate) fn compound_predicate_binding_power(tok: &Token) -> Option<(u8, u8)> {
    match &tok.kind {
        TokenKind::Keyword(Keyword::Is)
        | TokenKind::Keyword(Keyword::In)
        | TokenKind::Keyword(Keyword::Not) // NOT IN, NOT LIKE, NOT BETWEEN
        | TokenKind::Keyword(Keyword::Between)
        | TokenKind::Keyword(Keyword::Like)
        | TokenKind::Keyword(Keyword::Ilike)
        | TokenKind::Keyword(Keyword::Rlike)
        | TokenKind::Keyword(Keyword::Regexp) => Some((30, 31)),
        _ => None,
    }
}

// ============================================================================
// Expression-level Error Recovery Infrastructure
// ============================================================================

/// Tokens that indicate the end of an expression context (for error recovery).
/// The paren_depth parameter tracks nested parentheses - when > 0, we're inside
/// a parenthesized expression or subquery and shouldn't treat FROM as a terminator.
#[inline]
pub(crate) fn is_expr_terminator(tok: &Token, paren_depth: i32) -> bool {
    match &tok.kind {
        TokenKind::Punctuation(crate::lexer::Punctuation::Comma)
        | TokenKind::Punctuation(crate::lexer::Punctuation::RParen)
        | TokenKind::Punctuation(crate::lexer::Punctuation::Semi)
        | TokenKind::Keyword(Keyword::Then)
        | TokenKind::Keyword(Keyword::Else)
        | TokenKind::Keyword(Keyword::End)
        | TokenKind::Keyword(Keyword::When)
        | TokenKind::Eof => true,
        // FROM and other clause keywords should only terminate expressions
        // when we're NOT inside parentheses (which indicate subqueries)
        TokenKind::Keyword(Keyword::From)
        | TokenKind::Keyword(Keyword::Where)
        | TokenKind::Keyword(Keyword::Group)
        | TokenKind::Keyword(Keyword::Having)
        | TokenKind::Keyword(Keyword::Order)
        | TokenKind::Keyword(Keyword::Limit)
        | TokenKind::Keyword(Keyword::Union)
        | TokenKind::Keyword(Keyword::Intersect)
        | TokenKind::Keyword(Keyword::Except)
        | TokenKind::Keyword(Keyword::Minus) => paren_depth == 0,
        _ => false,
    }
}

// Implementation methods will be added here via:
impl<'a> Parser<'a> {
    /// Try to parse an expression, on failure create an Error node and skip to a recovery point.
    /// Used for error-tolerant parsing in function arguments and other expression contexts.
    ///
    /// Returns:
    /// - `Ok(AstExpr)` on successful parse
    /// - `Ok(AstExpr::Error { .. })` on recoverable parse failure (creates error node, skips to recovery point)
    /// - `Err(ParseError)` on fatal errors (e.g., recursion limit exceeded)
    pub(crate) fn parse_expr_with_recovery(&mut self) -> ParseResult<AstExpr> {
        let start_pos = self.current_span().start;
        let start_idx = self.idx;

        // Try to parse normally
        let recovery_error = match self.parse_expr() {
            Ok(expr) => return Ok(expr),
            Err(e) => {
                // Fatal errors must not be recovered from
                if e.kind.is_resource_exhaustion() {
                    return Err(e);
                }
                e
            }
        };

        // An `Unknown` token is lexically-invalid content the lexer could not
        // close (an unterminated string, dollar-quote, or block comment that ran
        // to EOF). Never recover across it: propagate so the whole statement
        // surfaces as OpaqueContent rather than absorbing the invalid region —
        // and every statement lexically trapped inside it — into an error
        // expression consumers would treat as benign.
        if self
            .peek()
            .is_some_and(|t| matches!(t.kind, TokenKind::Unknown))
        {
            return Err(recovery_error);
        }

        // A failed expression that ran out looking for a closing `)` is an
        // unclosed paren: the `(` was consumed but never matched, so recovering
        // would silently absorb the following statement(s) into a truncated
        // expression — a file could then report zero findings and pass `--strict`.
        // Propagate, like the Unknown-token case above, so the statement surfaces
        // as OpaqueContent, counts toward coverage, and fails `--strict`,
        // mirroring create_table's unclosed-column-list rejection.
        let unclosed_paren = matches!(
            &*recovery_error.kind,
            ParseErrorKind::UnexpectedToken { expected, .. }
                | ParseErrorKind::UnexpectedEof { expected }
                if expected.iter().any(|e| e == ")")
        );
        if unclosed_paren {
            return Err(recovery_error);
        }

        // Recoverable failure — create error node and skip to recovery point
        let mut end_pos = start_pos;
        let mut partial_tokens = Vec::new();
        let max_tokens = 10;

        // Ensure we advance at least once to prevent infinite loops
        if self.idx == start_idx {
            if let Some(tok) = self.peek() {
                if partial_tokens.len() < max_tokens {
                    partial_tokens.push(format!("{:?}", tok.kind));
                }
                end_pos = tok.span.end;
                self.advance();
            }
        } else if let Some(prev) = self.idx.checked_sub(1).and_then(|i| self.tokens.get(i)) {
            // The failed parse already consumed tokens; the error node must cover
            // them so span coverage stays complete even if recovery stops
            // immediately at a statement boundary below.
            end_pos = end_pos.max(prev.span.end);
        }

        // Track parenthesis depth to avoid treating FROM inside subqueries as terminators
        let mut paren_depth = 0;

        // Skip tokens until we hit a recovery point
        while let Some(tok) = self.peek() {
            // Track parentheses to know when we're inside a subquery
            match &tok.kind {
                TokenKind::Punctuation(crate::lexer::Punctuation::LParen) => paren_depth += 1,
                TokenKind::Punctuation(crate::lexer::Punctuation::RParen) => {
                    paren_depth -= 1;
                    // If we've closed all parens and hit an RParen, stop here
                    if paren_depth < 0 {
                        break;
                    }
                }
                _ => {}
            }

            // A statement-starting keyword at the top level is the boundary of
            // this (already-failed) statement. Stop here so recovery never
            // consumes the following statement into this error node — e.g. an
            // unclosed `foo(a, b` must not swallow a trailing `GRANT …`.
            if paren_depth <= 0 && self.is_statement_keyword(tok) {
                break;
            }

            if is_expr_terminator(tok, paren_depth) {
                break;
            }
            if partial_tokens.len() < max_tokens {
                partial_tokens.push(format!("{:?}", tok.kind));
            }
            end_pos = tok.span.end;
            self.advance();
        }

        let error_msg = recovery_error.message().to_string();

        // Track that error recovery occurred (for post-parse validation)
        self.recovery_errors.push(recovery_error);

        Ok(AstExpr::Error {
            node_id: self.id_gen.next(),
            span: Span {
                start: start_pos,
                end: end_pos,
            },
            message: error_msg,
            partial_tokens,
        })
    }

    /// Check if a token is a recognized INTERVAL time unit (DAY, HOUR, MONTH, etc.)
    fn is_interval_time_unit(tok: &Token, source: &str) -> bool {
        let lexeme = tok.lexeme(source);
        matches!(
            lexeme.to_ascii_uppercase().as_str(),
            "DAY"
                | "DAYS"
                | "HOUR"
                | "HOURS"
                | "MINUTE"
                | "MINUTES"
                | "SECOND"
                | "SECONDS"
                | "MILLISECOND"
                | "MILLISECONDS"
                | "MICROSECOND"
                | "MICROSECONDS"
                | "MONTH"
                | "MONTHS"
                | "YEAR"
                | "YEARS"
                | "WEEK"
                | "WEEKS"
                | "QUARTER"
                | "QUARTERS"
        )
    }

    /// Parse the tail of an interval literal after the `INTERVAL` keyword (or
    /// the `{interval` ODBC introducer): value literal + optional time unit
    /// [TO unit]. Returns the end byte offset of the last consumed token.
    fn parse_interval_literal_tail(&mut self) -> ParseResult<u32> {
        // Accept string literal OR numeric literal after INTERVAL
        let value_tok = self.advance().ok_or_else(|| {
            ParseError::unexpected_eof(
                self.current_span(),
                vec!["literal after INTERVAL".to_string()],
            )
        })?;

        let is_valid_value = matches!(
            value_tok.kind,
            TokenKind::Literal(crate::lexer::LiteralKind::String)
                | TokenKind::Literal(crate::lexer::LiteralKind::Number)
        );

        if !is_valid_value {
            return Err(ParseError::unexpected_token(
                value_tok.span,
                vec!["string or numeric literal".to_string()],
                Parser::token_description(value_tok, self.source),
            ));
        }

        let mut end = value_tok.span.end;

        // Optionally consume time unit (DAY, HOUR, MONTH, YEAR, SECOND, MINUTE, etc.)
        // These are typically identifiers or keywords
        if let Some(unit_tok) = self.peek() {
            if Self::is_interval_time_unit(unit_tok, self.source) {
                let unit = self
                    .advance()
                    .expect_invariant("time unit token after peek");
                end = unit.span.end;

                // Check for range form: unit TO unit (e.g., HOUR TO SECOND)
                if let Some(to_tok) = self.peek() {
                    if matches!(to_tok.kind, TokenKind::Keyword(Keyword::To)) {
                        // Peek ahead to confirm the token after TO is also a time unit
                        let save_idx = self.idx;
                        self.advance(); // consume TO
                        if let Some(end_unit_tok) = self.peek() {
                            if Self::is_interval_time_unit(end_unit_tok, self.source) {
                                let end_unit =
                                    self.advance().expect_invariant("end time unit after peek");
                                end = end_unit.span.end;
                            } else {
                                // TO was not followed by a time unit — restore
                                self.idx = save_idx;
                            }
                        } else {
                            // EOF after TO — restore
                            self.idx = save_idx;
                        }
                    }
                }
            }
        }

        Ok(end)
    }

    /// Try to parse an ODBC escape clause in expression position:
    /// `{d '…'}` / `{t '…'}` / `{ts '…'}` / `{guid '…'}` / `{fn F(args)}` /
    /// `{interval …}`. Returns `Ok(None)` with the parser position unchanged
    /// when the braces are not an ODBC escape — the Snowflake object literal
    /// `{key: value}` owns `{` otherwise. Escapes desugar to the native AST
    /// node, marked so consumers can canonicalize the type name while the
    /// formatter re-emits the braced span verbatim.
    fn try_parse_odbc_expr_escape(&mut self) -> ParseResult<Option<AstExpr>> {
        let save_idx = self.idx;
        let lcurly = match self.advance() {
            Some(t) => t,
            None => {
                self.idx = save_idx;
                return Ok(None);
            }
        };

        let intro_kind = match self.peek() {
            Some(intro) => Self::classify_odbc_intro(intro, self.source),
            None => None,
        };
        let Some(intro_kind) = intro_kind else {
            self.idx = save_idx;
            return Ok(None);
        };

        // Disambiguation guard: the introducer must begin an escape body, not
        // an object-literal `key:` pair. Literal kinds additionally require
        // the string value, so malformed escapes keep today's object-literal
        // diagnostics and opaque fallback.
        let probe_idx = self.idx;
        self.advance(); // introducer
        let next_ok = match self.peek() {
            Some(next) => match intro_kind {
                OdbcExprIntro::Literal(_) => matches!(
                    next.kind,
                    TokenKind::Literal(crate::lexer::LiteralKind::String)
                ),
                OdbcExprIntro::Fn | OdbcExprIntro::Interval => !matches!(
                    next.kind,
                    TokenKind::Punctuation(crate::lexer::Punctuation::Colon)
                ),
            },
            None => false,
        };
        self.idx = probe_idx;
        if !next_ok {
            self.idx = save_idx;
            return Ok(None);
        }

        self.odbc_depth += 1;
        let result = self.parse_odbc_expr_escape_inner(lcurly.span, intro_kind);
        self.odbc_depth -= 1;
        result.map(Some)
    }

    /// Classify the token after `{` as an ODBC escape introducer.
    fn classify_odbc_intro(tok: &Token, source: &str) -> Option<OdbcExprIntro> {
        if matches!(tok.kind, TokenKind::Keyword(Keyword::Interval)) {
            return Some(OdbcExprIntro::Interval);
        }
        if !matches!(
            tok.kind,
            TokenKind::Identifier {
                kind: crate::lexer::IdentifierKind::Unquoted
            }
        ) {
            return None;
        }
        let lexeme = tok.lexeme(source);
        if lexeme.eq_ignore_ascii_case("d") {
            Some(OdbcExprIntro::Literal(OdbcLiteralKind::Date))
        } else if lexeme.eq_ignore_ascii_case("t") {
            Some(OdbcExprIntro::Literal(OdbcLiteralKind::Time))
        } else if lexeme.eq_ignore_ascii_case("ts") {
            Some(OdbcExprIntro::Literal(OdbcLiteralKind::Timestamp))
        } else if lexeme.eq_ignore_ascii_case("guid") {
            Some(OdbcExprIntro::Literal(OdbcLiteralKind::Guid))
        } else if lexeme.eq_ignore_ascii_case("fn") {
            Some(OdbcExprIntro::Fn)
        } else {
            None
        }
    }

    /// Parse a probe-validated ODBC expression escape. Position is on the
    /// introducer (the `{` is already consumed).
    fn parse_odbc_expr_escape_inner(
        &mut self,
        lcurly_span: Span,
        intro: OdbcExprIntro,
    ) -> ParseResult<AstExpr> {
        let intro_tok = self
            .advance()
            .expect_invariant("ODBC introducer validated by probe");
        let intro_span = intro_tok.span;
        match intro {
            OdbcExprIntro::Literal(kind) => {
                let value_tok = self
                    .advance()
                    .expect_invariant("string literal validated by probe");
                let rcurly_span = self.expect_odbc_rcurly()?;
                Ok(AstExpr::TypedStringLiteral {
                    node_id: self.id_gen.next(),
                    type_name_span: intro_span,
                    value_span: value_tok.span,
                    odbc_kind: Some(kind),
                    span: Span {
                        start: lcurly_span.start,
                        end: rcurly_span.end,
                    },
                })
            }
            OdbcExprIntro::Fn => {
                let mut inner = self.parse_primary_expr_in_mode()?;
                let rcurly_span = self.expect_odbc_rcurly()?;
                if let AstExpr::FunctionCall { odbc_fn, span, .. } = &mut inner {
                    *odbc_fn = true;
                    *span = Span {
                        start: lcurly_span.start,
                        end: rcurly_span.end,
                    };
                } else {
                    return Err(ParseError::invalid_expression(
                        inner.span(),
                        "ODBC {fn ...} escape must wrap a scalar function call".to_string(),
                    ));
                }
                Ok(inner)
            }
            OdbcExprIntro::Interval => {
                self.parse_interval_literal_tail()?;
                let rcurly_span = self.expect_odbc_rcurly()?;
                // Same treatment as the native INTERVAL literal: an opaque
                // string literal emitted verbatim; the span (and thus the
                // literal text consumers read) includes the braces.
                Ok(AstExpr::Literal {
                    node_id: self.id_gen.next(),
                    literal: AstLiteral::String {
                        span: Span {
                            start: lcurly_span.start,
                            end: rcurly_span.end,
                        },
                    },
                })
            }
        }
    }

    /// Consume the closing `}` of an ODBC escape clause.
    pub(crate) fn expect_odbc_rcurly(&mut self) -> ParseResult<Span> {
        let tok = self.advance().ok_or_else(|| {
            ParseError::unexpected_eof(self.current_span(), vec!["}".to_string()])
        })?;
        if matches!(
            tok.kind,
            TokenKind::Punctuation(crate::lexer::Punctuation::RCurly)
        ) {
            Ok(tok.span)
        } else {
            Err(ParseError::unexpected_token(
                tok.span,
                vec!["}".to_string()],
                Parser::token_description(tok, self.source),
            ))
        }
    }

    /// Parse a comma-separated list of expressions.
    /// Returns None if parsing fails, Some(list) on success.
    ///
    /// Note: This is used ONLY for lists without Jinja control flow.
    /// Lists with Jinja use the opaque-span path instead.
    pub(crate) fn parse_expr_list(
        &mut self,
        parse_item: impl Fn(&mut Self) -> Option<AstExpr>,
    ) -> Option<Vec<AstExpr>> {
        let mut list: Vec<AstExpr> = Vec::new();

        loop {
            let next = self.peek()?;

            match &next.kind {
                TokenKind::Punctuation(crate::lexer::Punctuation::RParen) => {
                    return Some(list);
                }
                TokenKind::Punctuation(crate::lexer::Punctuation::Comma) => {
                    self.advance();
                    continue;
                }
                _ => {
                    let item = parse_item(self)?;
                    list.push(item);
                }
            }
        }
    }

    // ========== Expression Parsing Methods ==========

    /// Helper: Parse EXCLUDE/EXCEPT modifier for star projections
    /// Syntax: EXCLUDE ( col1 [, col2, ...] )
    /// OR: EXCLUDE col1 (single column, no parentheses)
    /// OR (BigQuery): EXCEPT ( col1 [, col2, ...] )
    pub(crate) fn parse_star_exclude(&mut self) -> ParseResult<Option<crate::ast::AstExclude>> {
        use crate::ast::{AstColumnRef, AstExclude, AstIdentifier};
        use crate::error::ParseResultExt;

        let keyword_tok = match self.peek() {
            Some(t) => t,
            None => return Ok(None),
        };
        let is_exclude = matches!(keyword_tok.kind, TokenKind::Keyword(Keyword::Exclude));
        let is_except = matches!(keyword_tok.kind, TokenKind::Keyword(Keyword::Except));
        if !is_exclude && !is_except {
            return Ok(None);
        }

        // For EXCEPT, only parse as star modifier in dialects that support it
        // and only when followed by '(' to disambiguate from set operator EXCEPT.
        if is_except {
            if !self.dialect.except_is_star_modifier() {
                return Ok(None);
            }
            let has_lparen = self.peek_ahead(1).is_some_and(|t| {
                matches!(
                    t.kind,
                    TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
                )
            });
            if !has_lparen {
                return Ok(None);
            }
        }

        // Capture EXCLUDE keyword token ID before advancing
        let exclude_keyword_id = self.current_token_id();
        let keyword_name = if is_except { "EXCEPT" } else { "EXCLUDE" };
        let exclude_span = self
            .advance()
            .ok_or_eof(self.current_span(), vec![keyword_name.to_string()])?
            .span;

        let mut columns = Vec::new();

        // Check if we have parentheses or direct column
        let next = self.peek().ok_or_eof(
            self.current_span(),
            vec!["identifier".to_string(), "(".to_string()],
        )?;
        let has_parens = matches!(
            next.kind,
            TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
        );

        let lparen_id = if has_parens {
            let id = self.current_token_id();
            self.advance(); // consume lparen
            Some(id)
        } else {
            None
        };

        loop {
            // Check for closing paren if we started with one
            if has_parens {
                if let Some(tok) = self.peek() {
                    if matches!(
                        tok.kind,
                        TokenKind::Punctuation(crate::lexer::Punctuation::RParen)
                    ) {
                        let closing = self
                            .advance()
                            .ok_or_eof(self.current_span(), vec![")".to_string()])?;
                        let rparen_id = self.last_token_id();
                        let span = Span {
                            start: exclude_span.start,
                            end: closing.span.end,
                        };
                        // Allocate syntax node
                        let syntax_exclude = crate::syntax::SyntaxExclude {
                            exclude_keyword: exclude_keyword_id,
                            lparen: lparen_id,
                            rparen: Some(rparen_id),
                            span,
                        };
                        let syntax_id = self.syntax_arena.alloc_exclude(syntax_exclude);
                        return Ok(Some(AstExclude {
                            node_id: self.id_gen.next(),
                            syntax_id: Some(syntax_id),
                            exclude_span,
                            columns,
                            has_parens,
                            span,
                        }));
                    }
                }
            }

            // Parse column name
            let tok = match self.peek() {
                Some(t) => t,
                None => break,
            };
            if !self.can_be_identifier_token(tok) {
                if has_parens {
                    // Error: expected column name
                    return Err(ParseError::unexpected_token(
                        tok.span,
                        vec!["identifier".to_string(), ")".to_string()],
                        Parser::token_description(tok, self.source),
                    ));
                } else {
                    // Without parens, we need at least one column
                    if columns.is_empty() {
                        return Err(ParseError::unexpected_token(
                            tok.span,
                            vec!["identifier".to_string(), "(".to_string()],
                            Parser::token_description(tok, self.source),
                        ));
                    }
                    break;
                }
            }

            let first_span = self
                .advance()
                .ok_or_eof(self.current_span(), vec!["identifier".to_string()])?
                .span;
            let mut qualifier = None;
            let mut name_span = first_span;

            // Check for qualified identifier: t.col
            if let Some(dot_tok) = self.peek() {
                let is_dot = matches!(
                    dot_tok.kind,
                    TokenKind::Punctuation(crate::lexer::Punctuation::Dot)
                ) || (matches!(
                    dot_tok.kind,
                    TokenKind::Literal(crate::lexer::LiteralKind::Number)
                ) && dot_tok.lexeme(self.source) == ".");
                if is_dot {
                    self.advance(); // consume dot
                    if let Some(second_tok) = self.advance() {
                        // After dot, any keyword can be an identifier
                        if self.can_be_identifier_after_dot_token(second_tok) {
                            qualifier = Some(AstObjectRef {
                                node_id: self.id_gen.next(),
                                span: first_span,
                                // Column qualifier: per-part decomposition
                                // is not currently maintained on the
                                // expr-side (see `AstObjectRef::parts`).
                                parts: None,
                                identifier_arg: None,
                            });
                            name_span = second_tok.span;
                        }
                    }
                }
            }

            columns.push(AstColumnRef {
                node_id: self.id_gen.next(),
                qualifier,
                name: AstIdentifier {
                    node_id: self.id_gen.next(),
                    span: name_span,
                },
            });

            // If no parens, we only parse one column
            if !has_parens {
                break;
            }

            // Check for comma (continue) or closing paren (done)
            if let Some(next) = self.peek() {
                match next.kind {
                    TokenKind::Punctuation(crate::lexer::Punctuation::Comma) => {
                        self.advance();
                    }
                    TokenKind::Punctuation(crate::lexer::Punctuation::RParen) => {
                        let closing = self
                            .advance()
                            .ok_or_eof(self.current_span(), vec![")".to_string()])?;
                        let rparen_id = self.last_token_id();
                        let span = Span {
                            start: exclude_span.start,
                            end: closing.span.end,
                        };
                        // Allocate syntax node
                        let syntax_exclude = crate::syntax::SyntaxExclude {
                            exclude_keyword: exclude_keyword_id,
                            lparen: lparen_id,
                            rparen: Some(rparen_id),
                            span,
                        };
                        let syntax_id = self.syntax_arena.alloc_exclude(syntax_exclude);
                        return Ok(Some(AstExclude {
                            node_id: self.id_gen.next(),
                            syntax_id: Some(syntax_id),
                            exclude_span,
                            columns,
                            has_parens,
                            span,
                        }));
                    }
                    _ => break,
                }
            } else {
                break;
            }
        }

        // If we get here, use last column end for span
        let end = columns
            .last()
            .map(|c| c.name.span.end)
            .unwrap_or(exclude_span.end);
        let span = Span {
            start: exclude_span.start,
            end,
        };
        // Allocate syntax node
        let syntax_exclude = crate::syntax::SyntaxExclude {
            exclude_keyword: exclude_keyword_id,
            lparen: lparen_id,
            rparen: None,
            span,
        };
        let syntax_id = self.syntax_arena.alloc_exclude(syntax_exclude);
        Ok(Some(AstExclude {
            node_id: self.id_gen.next(),
            syntax_id: Some(syntax_id),
            exclude_span,
            columns,
            has_parens,
            span,
        }))
    }

    /// Helper: Parse REPLACE modifier for star projections
    /// Syntax: REPLACE ( expr AS col1 [, expr AS col2, ...] )
    fn parse_star_replace(&mut self) -> ParseResult<Option<crate::ast::AstReplace>> {
        use crate::ast::{AstColumnRef, AstIdentifier, AstReplace, AstReplaceItem};
        use crate::error::ParseResultExt;

        let replace_tok = match self.peek() {
            Some(t) => t,
            None => return Ok(None),
        };
        if !matches!(replace_tok.kind, TokenKind::Keyword(Keyword::Replace)) {
            return Ok(None);
        }
        // Capture REPLACE keyword token ID before advancing
        let replace_keyword_id = self.current_token_id();
        let replace_span = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["REPLACE".to_string()])?
            .span;

        // Capture lparen token ID before advancing
        let lparen_id = self.current_token_id();
        let lparen = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["(".to_string()])?;
        if !matches!(
            lparen.kind,
            TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
        ) {
            return Err(ParseError::unexpected_token(
                lparen.span,
                vec!["(".to_string()],
                Parser::token_description(lparen, self.source),
            ));
        }

        let mut items = Vec::new();
        while let Some(rparen_check) = self.peek() {
            // Parse expression
            if matches!(
                rparen_check.kind,
                TokenKind::Punctuation(crate::lexer::Punctuation::RParen)
            ) {
                self.advance();
                break;
            }

            let expr = self.parse_expr()?;

            // Expect AS
            let as_tok = self
                .advance()
                .ok_or_eof(self.current_span(), vec!["AS".to_string()])?;
            if !matches!(as_tok.kind, TokenKind::Keyword(Keyword::As)) {
                return Err(ParseError::unexpected_token(
                    as_tok.span,
                    vec!["AS".to_string()],
                    Parser::token_description(as_tok, self.source),
                ));
            }

            // Expect column name
            let col_tok = self
                .advance()
                .ok_or_eof(self.current_span(), vec!["identifier".to_string()])?;
            if !self.can_be_identifier_token(col_tok) {
                return Err(ParseError::unexpected_token(
                    col_tok.span,
                    vec!["identifier".to_string()],
                    Parser::token_description(col_tok, self.source),
                ));
            }

            // Create dummy syntax node (this parser doesn't have arena access yet)
            let syntax_id = crate::syntax::SyntaxReplaceItemId(0);
            items.push(AstReplaceItem {
                node_id: self.id_gen.next(),
                syntax_id,
                expr,
                as_span: as_tok.span,
                column: AstColumnRef {
                    node_id: self.id_gen.next(),
                    qualifier: None,
                    name: AstIdentifier {
                        node_id: self.id_gen.next(),
                        span: col_tok.span,
                    },
                },
            });

            // Check for comma or closing paren
            if let Some(next) = self.peek() {
                match next.kind {
                    TokenKind::Punctuation(crate::lexer::Punctuation::Comma) => {
                        self.advance();
                    }
                    TokenKind::Punctuation(crate::lexer::Punctuation::RParen) => {
                        let closing = self
                            .advance()
                            .ok_or_eof(self.current_span(), vec![")".to_string()])?;
                        let rparen_id = self.last_token_id();
                        let span = Span {
                            start: replace_span.start,
                            end: closing.span.end,
                        };
                        // Allocate syntax node
                        let syntax_replace = crate::syntax::SyntaxReplace {
                            replace_keyword: replace_keyword_id,
                            lparen: lparen_id,
                            rparen: rparen_id,
                            span,
                        };
                        let syntax_id = self.syntax_arena.alloc_replace(syntax_replace);
                        return Ok(Some(AstReplace {
                            node_id: self.id_gen.next(),
                            syntax_id: Some(syntax_id),
                            replace_span,
                            items,
                            span,
                        }));
                    }
                    _ => break,
                }
            } else {
                break;
            }
        }

        // If we get here, no closing paren - use last item end
        let end = items
            .last()
            .map(|i| i.column.name.span.end)
            .unwrap_or(replace_span.end);
        let span = Span {
            start: replace_span.start,
            end,
        };
        // Allocate syntax node (rparen not found, using last valid position)
        let rparen_id = self.last_token_id();
        let syntax_replace = crate::syntax::SyntaxReplace {
            replace_keyword: replace_keyword_id,
            lparen: lparen_id,
            rparen: rparen_id,
            span,
        };
        let syntax_id = self.syntax_arena.alloc_replace(syntax_replace);
        Ok(Some(AstReplace {
            node_id: self.id_gen.next(),
            syntax_id: Some(syntax_id),
            replace_span,
            items,
            span,
        }))
    }

    /// Helper: Parse RENAME modifier for star projections
    /// Syntax: RENAME ( col1 AS alias1 [, col2 AS alias2, ...] )
    /// OR: RENAME col1 AS alias1
    fn parse_star_rename(&mut self) -> ParseResult<Option<crate::ast::AstRename>> {
        use crate::ast::{AstColumnRef, AstIdentifier, AstRename, AstRenameItem};
        use crate::error::ParseResultExt;

        let rename_tok = match self.peek() {
            Some(t) => t,
            None => return Ok(None),
        };
        if !matches!(rename_tok.kind, TokenKind::Keyword(Keyword::Rename)) {
            return Ok(None);
        }
        // Capture RENAME keyword token ID before advancing
        let rename_keyword_id = self.current_token_id();
        let rename_span = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["RENAME".to_string()])?
            .span;

        let mut items = Vec::new();

        // Check if we have parentheses or direct column
        let next = match self.peek() {
            Some(t) => t,
            None => {
                // EOF after RENAME — return what we have
                let span = Span {
                    start: rename_span.start,
                    end: rename_span.end,
                };
                let syntax_rename = crate::syntax::SyntaxRename {
                    rename_keyword: rename_keyword_id,
                    lparen: None,
                    rparen: None,
                    span,
                };
                let syntax_id = self.syntax_arena.alloc_rename(syntax_rename);
                return Ok(Some(AstRename {
                    node_id: self.id_gen.next(),
                    syntax_id: Some(syntax_id),
                    rename_span,
                    items,
                    has_parens: false,
                    span,
                }));
            }
        };
        let has_parens = matches!(
            next.kind,
            TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
        );

        let lparen_id = if has_parens {
            let id = self.current_token_id();
            self.advance(); // consume lparen
            Some(id)
        } else {
            None
        };

        loop {
            // Check for closing paren if we started with one
            if has_parens {
                if let Some(tok) = self.peek() {
                    if matches!(
                        tok.kind,
                        TokenKind::Punctuation(crate::lexer::Punctuation::RParen)
                    ) {
                        self.advance();
                        break;
                    }
                }
            }

            // Parse column name
            let col_tok = match self.peek() {
                Some(t) => t,
                None => break,
            };
            if !self.can_be_identifier_token(col_tok) {
                if has_parens {
                    // Empty list or end of list
                    break;
                } else {
                    return Ok(None);
                }
            }
            let col_span = self
                .advance()
                .ok_or_eof(self.current_span(), vec!["identifier".to_string()])?
                .span;

            // Check for AS (optional in some contexts)
            let mut as_span: Option<Span> = None;
            if let Some(as_tok) = self.peek() {
                if matches!(as_tok.kind, TokenKind::Keyword(Keyword::As)) {
                    let consumed_as = self
                        .advance()
                        .ok_or_eof(self.current_span(), vec!["AS".to_string()])?; // Consume AS keyword
                    as_span = Some(consumed_as.span);
                }
            }

            // Parse alias
            let alias_tok = self
                .advance()
                .ok_or_eof(self.current_span(), vec!["identifier".to_string()])?;
            if !self.can_be_identifier_token(alias_tok) {
                return Err(ParseError::unexpected_token(
                    alias_tok.span,
                    vec!["identifier".to_string()],
                    Parser::token_description(alias_tok, self.source),
                ));
            }

            // Create dummy syntax node (this parser doesn't have arena access yet)
            let syntax_id = crate::syntax::SyntaxRenameItemId(0);
            items.push(AstRenameItem {
                node_id: self.id_gen.next(),
                syntax_id,
                column: AstColumnRef {
                    node_id: self.id_gen.next(),
                    qualifier: None,
                    name: AstIdentifier {
                        node_id: self.id_gen.next(),
                        span: col_span,
                    },
                },
                as_span,
                alias: AstIdentifier {
                    node_id: self.id_gen.next(),
                    span: alias_tok.span,
                },
            });

            if !has_parens {
                // Single rename without parens
                break;
            }

            // Check for comma or closing paren
            if let Some(next) = self.peek() {
                match next.kind {
                    TokenKind::Punctuation(crate::lexer::Punctuation::Comma) => {
                        self.advance();
                    }
                    TokenKind::Punctuation(crate::lexer::Punctuation::RParen) => {
                        let closing = self
                            .advance()
                            .ok_or_eof(self.current_span(), vec![")".to_string()])?;
                        let rparen_id = self.last_token_id();
                        let span = Span {
                            start: rename_span.start,
                            end: closing.span.end,
                        };
                        // Allocate syntax node
                        let syntax_rename = crate::syntax::SyntaxRename {
                            rename_keyword: rename_keyword_id,
                            lparen: lparen_id,
                            rparen: Some(rparen_id),
                            span,
                        };
                        let syntax_id = self.syntax_arena.alloc_rename(syntax_rename);
                        return Ok(Some(AstRename {
                            node_id: self.id_gen.next(),
                            syntax_id: Some(syntax_id),
                            rename_span,
                            items,
                            has_parens,
                            span,
                        }));
                    }
                    _ => break,
                }
            } else {
                break;
            }
        }

        // If we get here, no closing paren - use last item end
        let end = items
            .last()
            .map(|i| i.alias.span.end)
            .unwrap_or(rename_span.end);
        let span = Span {
            start: rename_span.start,
            end,
        };
        // Allocate syntax node
        let syntax_rename = crate::syntax::SyntaxRename {
            rename_keyword: rename_keyword_id,
            lparen: lparen_id,
            rparen: None,
            span,
        };
        let syntax_id = self.syntax_arena.alloc_rename(syntax_rename);
        Ok(Some(AstRename {
            node_id: self.id_gen.next(),
            syntax_id: Some(syntax_id),
            rename_span,
            items,
            has_parens,
            span,
        }))
    }

    /// Parse a data type specification for CAST operations.
    /// Supports: TYPE, TYPE(precision), TYPE(precision, scale)
    pub(crate) fn parse_data_type(&mut self) -> Option<ParseResult<AstDataType>> {
        let type_tok = self.peek()?;
        if !self.can_be_identifier_token(type_tok) {
            return None;
        }
        let name_span = self.advance()?.span;

        // Check for compound INTERVAL types: INTERVAL YEAR [(p)] [TO MONTH], etc.
        {
            let name_text = &self.source[name_span.start as usize..name_span.end as usize];
            if name_text.eq_ignore_ascii_case("INTERVAL") {
                if let Some(unit_tok) = self.peek() {
                    let is_interval_unit = matches!(unit_tok.kind, TokenKind::Identifier { .. })
                        && {
                            let upper = unit_tok.lexeme(self.source).to_ascii_uppercase();
                            matches!(
                                upper.as_str(),
                                "YEAR" | "MONTH" | "DAY" | "HOUR" | "MINUTE" | "SECOND"
                            )
                        };
                    if is_interval_unit {
                        let unit_tok = match self.advance() {
                            Some(t) => t,
                            None => {
                                return Some(Err(ParseError::unexpected_eof(
                                    self.current_span(),
                                    vec!["interval unit".to_string()],
                                )))
                            }
                        };
                        let mut end = unit_tok.span.end;

                        // Optional precision: (p) or (p, fsp)
                        if let Some(lp) = self.peek() {
                            if matches!(
                                lp.kind,
                                TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
                            ) {
                                self.advance(); // consume (
                                let mut depth: u32 = 1;
                                while depth > 0 {
                                    let next = match self.advance() {
                                        Some(t) => t,
                                        None => {
                                            return Some(Err(ParseError::unexpected_eof(
                                                self.current_span(),
                                                vec![")".to_string()],
                                            )))
                                        }
                                    };
                                    match next.kind {
                                        TokenKind::Punctuation(
                                            crate::lexer::Punctuation::LParen,
                                        ) => depth += 1,
                                        TokenKind::Punctuation(
                                            crate::lexer::Punctuation::RParen,
                                        ) => depth -= 1,
                                        _ => {}
                                    }
                                    end = next.span.end;
                                }
                            }
                        }

                        // Optional TO target_unit [(precision)]
                        if let Some(to_tok) = self.peek() {
                            if matches!(to_tok.kind, TokenKind::Keyword(crate::lexer::Keyword::To))
                            {
                                self.advance(); // consume TO

                                // Expect target unit
                                let target = match self.advance() {
                                    Some(t) if matches!(t.kind, TokenKind::Identifier { .. }) && {
                                        let upper = t.lexeme(self.source).to_ascii_uppercase();
                                        matches!(upper.as_str(), "YEAR" | "MONTH" | "DAY" | "HOUR" | "MINUTE" | "SECOND")
                                    } => t,
                                    Some(t) => return Some(Err(ParseError::unexpected_token(
                                        t.span,
                                        vec!["interval unit (YEAR, MONTH, DAY, HOUR, MINUTE, SECOND)".to_string()],
                                        t.lexeme(self.source).to_string(),
                                    ))),
                                    None => return Some(Err(ParseError::unexpected_eof(
                                        self.current_span(),
                                        vec!["interval unit after TO".to_string()],
                                    ))),
                                };
                                end = target.span.end;

                                // Optional precision on target unit
                                if let Some(lp) = self.peek() {
                                    if matches!(
                                        lp.kind,
                                        TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
                                    ) {
                                        self.advance(); // consume (
                                        let mut depth: u32 = 1;
                                        while depth > 0 {
                                            let next = match self.advance() {
                                                Some(t) => t,
                                                None => {
                                                    return Some(Err(ParseError::unexpected_eof(
                                                        self.current_span(),
                                                        vec![")".to_string()],
                                                    )))
                                                }
                                            };
                                            match next.kind {
                                                TokenKind::Punctuation(
                                                    crate::lexer::Punctuation::LParen,
                                                ) => depth += 1,
                                                TokenKind::Punctuation(
                                                    crate::lexer::Punctuation::RParen,
                                                ) => depth -= 1,
                                                _ => {}
                                            }
                                            end = next.span.end;
                                        }
                                    }
                                }
                            }
                        }

                        let span = Span {
                            start: name_span.start,
                            end,
                        };
                        let syntax_id = self.syntax_arena.alloc_compound_interval(
                            crate::syntax::SyntaxCompoundInterval { span },
                        );
                        return Some(Ok(AstDataType::CompoundInterval { syntax_id, span }));
                    }
                }
            }
        }

        // Check for optional precision/scale
        if let Some(lp) = self.peek() {
            if matches!(
                lp.kind,
                TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
            ) {
                let lparen_token_id = self.current_token_id();
                let lparen_span = self.advance()?.span;

                // Parse precision (must be a number or MAX for MSSQL types like VARCHAR(MAX))
                let precision_tok = match self.peek() {
                    Some(t) => t,
                    None => {
                        return Some(Err(ParseError::unexpected_eof(
                            Span {
                                start: lparen_span.end,
                                end: lparen_span.end,
                            },
                            vec!["number (precision) or MAX".to_string()],
                        )))
                    }
                };
                let is_max_keyword = matches!(precision_tok.kind, TokenKind::Identifier { .. })
                    && precision_tok
                        .lexeme(self.source)
                        .eq_ignore_ascii_case("MAX");
                if !matches!(
                    precision_tok.kind,
                    TokenKind::Literal(crate::lexer::LiteralKind::Number)
                ) && !is_max_keyword
                {
                    return Some(Err(ParseError::unexpected_token(
                        precision_tok.span,
                        vec!["number (precision) or MAX".to_string()],
                        precision_tok.lexeme(self.source).to_string(),
                    )));
                }
                let precision_span = self.advance()?.span;

                // Check for optional scale after comma
                if let Some(comma) = self.peek() {
                    if matches!(
                        comma.kind,
                        TokenKind::Punctuation(crate::lexer::Punctuation::Comma)
                    ) {
                        let comma_token_id = self.current_token_id();
                        let comma_span = self.advance()?.span;

                        // Parse scale (must be a number)
                        let scale_tok = match self.peek() {
                            Some(t) => t,
                            None => {
                                return Some(Err(ParseError::unexpected_eof(
                                    Span {
                                        start: comma_span.end,
                                        end: comma_span.end,
                                    },
                                    vec!["number (scale)".to_string()],
                                )))
                            }
                        };
                        if !matches!(
                            scale_tok.kind,
                            TokenKind::Literal(crate::lexer::LiteralKind::Number)
                        ) {
                            return Some(Err(ParseError::unexpected_token(
                                scale_tok.span,
                                vec!["number (scale)".to_string()],
                                scale_tok.lexeme(self.source).to_string(),
                            )));
                        }
                        let scale_span = self.advance()?.span;

                        // Expect closing paren
                        let rparen_token_id = self.current_token_id();
                        let rp = match self.advance() {
                            Some(t) => t,
                            None => {
                                return Some(Err(ParseError::unexpected_eof(
                                    Span {
                                        start: scale_span.end,
                                        end: scale_span.end,
                                    },
                                    vec![")".to_string()],
                                )))
                            }
                        };
                        if !matches!(
                            rp.kind,
                            TokenKind::Punctuation(crate::lexer::Punctuation::RParen)
                        ) {
                            return Some(Err(ParseError::unexpected_token(
                                rp.span,
                                vec![")".to_string()],
                                rp.lexeme(self.source).to_string(),
                            )));
                        }
                        let rparen_span = rp.span;

                        let span = Span {
                            start: name_span.start,
                            end: rparen_span.end,
                        };

                        // Allocate syntax node
                        let syntax_id = self.syntax_arena.alloc_type_precision_scale(
                            crate::syntax::SyntaxTypePrecisionScale {
                                l_paren: lparen_token_id,
                                comma: comma_token_id,
                                r_paren: rparen_token_id,
                                span,
                            },
                        );

                        return Some(Ok(AstDataType::WithPrecisionScale {
                            syntax_id,
                            name_span,
                            precision_span,
                            scale_span,
                        }));
                    }
                }

                // Just precision, no scale
                let rparen_token_id = self.current_token_id();
                let rp = match self.advance() {
                    Some(t) => t,
                    None => {
                        return Some(Err(ParseError::unexpected_eof(
                            Span {
                                start: precision_span.end,
                                end: precision_span.end,
                            },
                            vec![")".to_string()],
                        )))
                    }
                };
                if !matches!(
                    rp.kind,
                    TokenKind::Punctuation(crate::lexer::Punctuation::RParen)
                ) {
                    return Some(Err(ParseError::unexpected_token(
                        rp.span,
                        vec![")".to_string()],
                        rp.lexeme(self.source).to_string(),
                    )));
                }
                let rparen_span = rp.span;

                let span = Span {
                    start: name_span.start,
                    end: rparen_span.end,
                };

                // Allocate syntax node
                let syntax_id =
                    self.syntax_arena
                        .alloc_type_precision(crate::syntax::SyntaxTypePrecision {
                            l_paren: lparen_token_id,
                            r_paren: rparen_token_id,
                            span,
                        });

                return Some(Ok(AstDataType::WithPrecision {
                    syntax_id,
                    name_span,
                    precision_span,
                }));
            }
        }

        // Check for angle-bracket parameterized types: ARRAY<STRING>, STRUCT<a INT64, b STRING>
        // BigQuery uses this syntax for generic type parameters
        if let Some(lt_tok) = self.peek() {
            if matches!(lt_tok.kind, TokenKind::Operator(crate::lexer::Operator::Lt)) {
                // Consume the '<' and parse until matching '>'
                self.advance(); // consume '<'
                let mut depth: u32 = 1;

                // Consume tokens until matching '>' is found, tracking nested angle brackets
                while depth > 0 {
                    let next = match self.advance() {
                        Some(t) => t,
                        None => {
                            return Some(Err(ParseError::unexpected_eof(
                                self.current_span(),
                                vec![">".to_string()],
                            )));
                        }
                    };
                    match next.kind {
                        TokenKind::Operator(crate::lexer::Operator::Lt) => {
                            depth += 1;
                        }
                        TokenKind::Operator(crate::lexer::Operator::Gt) => {
                            depth -= 1;
                        }
                        TokenKind::Operator(crate::lexer::Operator::GtGt) => {
                            // >> is tokenized as a single GtGt token but closes two levels
                            // of angle brackets (e.g., ARRAY<STRUCT<a INT64, b STRING>>)
                            depth = depth.saturating_sub(2);
                        }
                        _ => {}
                    }
                }

                let param_span = Span {
                    start: name_span.start,
                    end: self.tokens[self.idx - 1].span.end,
                };

                let syntax_id = self.syntax_arena.alloc_parameterized_type(
                    crate::syntax::SyntaxParameterizedType { span: param_span },
                );

                return Some(Ok(AstDataType::Parameterized {
                    syntax_id,
                    span: param_span,
                }));
            }
        }

        // Simple type without parameters
        Some(Ok(AstDataType::Simple { name_span }))
    }

    /// Helper to get the end position of a data type for span calculation.
    pub(crate) fn data_type_span_end(&self, dtype: &AstDataType) -> u32 {
        match dtype {
            AstDataType::Simple { name_span } => name_span.end,
            AstDataType::WithPrecision { syntax_id, .. } => {
                self.syntax_arena.get_type_precision(*syntax_id).span.end
            }
            AstDataType::WithPrecisionScale { syntax_id, .. } => {
                self.syntax_arena
                    .get_type_precision_scale(*syntax_id)
                    .span
                    .end
            }
            AstDataType::Parameterized { span, .. } => span.end,
            AstDataType::CompoundInterval { span, .. } => span.end,
        }
    }

    pub(crate) fn parse_primary_expr_in_mode(&mut self) -> ParseResult<AstExpr> {
        let _guard = track_depth("parse_primary_expr_in_mode", self.current_span())?;

        let tok = self.peek().ok_or_else(|| {
            ParseError::unexpected_eof(self.current_span(), vec!["expression".to_string()])
        })?;

        // PostgreSQL/Redshift dollar-quoted string literal at expression
        // position. The lexer emits a dollar-quoted region as opening-delimiter
        // + inner tokens + closing-delimiter (so procedure bodies become
        // analyzable statements); at an EXPRESSION position the run is a string
        // literal, so reassemble opener-through-matching-closer into one
        // `AstExpr::Literal(String)`. The span covers the whole region and the
        // value is derived from the span alone — never from inner token kinds —
        // so opacity/value are identical to the pre-change single-token form.
        // Gated on the dialect flag (Snowflake's `$$` is a genuine identifier).
        let is_dollar_string = self.dialect.supports_dollar_quoted_strings()
            && matches!(tok.kind, TokenKind::Identifier { .. })
            && crate::parser::core::is_dollar_quote_tag(tok.lexeme(self.source));
        if is_dollar_string {
            // Reassemble opener-through-matching-closer into one literal span
            // (shared with `COMMENT ON … IS $$…$$`); the value is derived from
            // the span alone, so opacity/value match the pre-change single token.
            let span = self.reassemble_dollar_quoted_span();
            return Ok(AstExpr::Literal {
                node_id: self.id_gen.next(),
                literal: AstLiteral::String { span },
            });
        }

        // Redshift `APPROXIMATE <aggregate>(...)` prefix — e.g.
        // `APPROXIMATE COUNT(DISTINCT x)`, `APPROXIMATE PERCENTILE_DISC(...)`.
        // `APPROXIMATE` lexes as an identifier, so only treat it as the
        // aggregate modifier when immediately followed by a function call
        // (name + `(`); otherwise a column literally named "approximate"
        // still parses. The modifier is threaded into the call builder so the
        // CST token is recorded for byte-exact emission and the call node
        // records the approximate-aggregate marker.
        let is_approximate_prefix = matches!(tok.kind, TokenKind::Identifier { .. })
            && tok.lexeme(self.source).eq_ignore_ascii_case("APPROXIMATE");
        if is_approximate_prefix {
            let save_idx = self.idx;
            let approx_tok = self
                .advance()
                .expect_invariant("APPROXIMATE identifier available after peek");
            let approx_span = approx_tok.span;
            let approx_token_id = self.last_token_id();
            let next_is_name = matches!(
                self.peek().map(|t| &t.kind),
                Some(TokenKind::Identifier { .. })
            );
            if next_is_name {
                let name_tok = self
                    .advance()
                    .expect_invariant("function name available after peek");
                let name_span = name_tok.span;
                if matches!(
                    self.peek().map(|t| &t.kind),
                    Some(TokenKind::Punctuation(crate::lexer::Punctuation::LParen))
                ) {
                    let mut call = self.parse_function_call_from_lparen(
                        name_span,
                        Some((approx_token_id, approx_span)),
                    )?;
                    // Extend the call span to cover the APPROXIMATE keyword.
                    if let AstExpr::FunctionCall { span, .. } = &mut call {
                        span.start = approx_span.start;
                    } else if let AstExpr::WindowFn { span, .. } = &mut call {
                        span.start = approx_span.start;
                    }
                    return Ok(call);
                }
            }
            // Not the APPROXIMATE-aggregate form — restore and parse normally.
            self.idx = save_idx;
        }

        let tok = self.peek().ok_or_else(|| {
            ParseError::unexpected_eof(self.current_span(), vec!["expression".to_string()])
        })?;

        match &tok.kind {
            // Placeholder for bind parameters: ? (scripting mode, or inside an
            // ODBC escape clause — ODBC SQL is parameterized)
            TokenKind::Placeholder
                if matches!(self.mode, ParserMode::Scripting) || self.odbc_depth > 0 =>
            {
                let placeholder_tok = self.advance().ok_or_else(|| {
                    ParseError::unexpected_eof(self.current_span(), vec!["?".to_string()])
                })?;
                Ok(AstExpr::Placeholder {
                    node_id: self.id_gen.next(),
                    span: placeholder_tok.span,
                })
            }
            // NEW: Jinja expression with parsed content: {{ expr }}
            TokenKind::JinjaExprOpen => {
                let start_span = tok.span;
                self.advance(); // consume {{
                let open_token_id = self.last_token_id();

                // Try to parse the Jinja expression
                if let Ok(Some(jinja_expr)) = self.parse_jinja_expr() {
                    // Expect closing }}
                    if let Some(close_tok) = self.peek() {
                        if matches!(close_tok.kind, TokenKind::JinjaExprClose) {
                            let mut end_pos = close_tok.span.end;
                            self.advance(); // consume }}
                            let close_token_id = self.last_token_id();

                            // Check for adjacent tokens after }}: {{ prefix }}column_name pattern
                            // This handles dbt patterns like dynamic column name prefixes
                            while let Some(next) = self.peek() {
                                // Check if next token is immediately adjacent (no whitespace)
                                if next.span.start == end_pos {
                                    match &next.kind {
                                        TokenKind::JinjaComment => {
                                            let tok = self
                                                .advance()
                                                .expect_invariant("JinjaComment token after peek");
                                            end_pos = tok.span.end;
                                        }
                                        _ if self.can_be_identifier_token(next) => {
                                            let tok = self.advance().expect_invariant(
                                                "identifier-like token after peek",
                                            );
                                            end_pos = tok.span.end;
                                        }
                                        TokenKind::Literal(
                                            crate::lexer::LiteralKind::StringFragment,
                                        ) => {
                                            let tok = self.advance().expect_invariant(
                                                "StringFragment token after peek",
                                            );
                                            end_pos = tok.span.end;
                                        }
                                        TokenKind::JinjaExprOpen => {
                                            // Adjacent Jinja expression: {{ a }}{{ b }}
                                            self.advance(); // consume {{
                                                            // Consume until }}
                                            while let Some(inner) = self.peek() {
                                                if matches!(inner.kind, TokenKind::JinjaExprClose) {
                                                    end_pos = inner.span.end;
                                                    self.advance();
                                                    break;
                                                }
                                                self.advance();
                                            }
                                        }
                                        _ => break,
                                    }
                                } else {
                                    break;
                                }
                            }

                            // Create CST node for the interpolation
                            let syntax_node = crate::syntax::SyntaxJinjaInterpolation {
                                open_expr: open_token_id,
                                expr: jinja_expr.syntax_id,
                                close_expr: close_token_id,
                                span: Span {
                                    start: start_span.start,
                                    end: end_pos,
                                },
                            };
                            let syntax_id =
                                self.syntax_arena.alloc_jinja_interpolation(syntax_node);

                            return Ok(AstExpr::JinjaPlaceholder {
                                node_id: self.id_gen.next(),
                                kind: crate::ast::JinjaKind::Expression,
                                span: Span {
                                    start: start_span.start,
                                    end: end_pos,
                                },
                                expr: Some(jinja_expr),
                                syntax_id: Some(syntax_id),
                            });
                        }
                    }
                }

                // Fallback: treat as opaque placeholder if parsing failed
                Ok(AstExpr::JinjaPlaceholder {
                    node_id: self.id_gen.next(),
                    kind: crate::ast::JinjaKind::Expression,
                    span: Span {
                        start: start_span.start,
                        end: start_span.end + 4, // Approximate span for {{}}
                    },
                    expr: None,
                    syntax_id: None,
                })
            }
            // NEW: Jinja statement with parsed content: {% stmt %}
            TokenKind::JinjaStmtOpen => {
                // Check if this is a control flow block ({% if %}, {% for %})
                if let Some(kind) = self.peek_jinja_block_kind() {
                    match kind {
                        crate::ast::JinjaBlockKind::If | crate::ast::JinjaBlockKind::For => {
                            // Parse as a full conditional expression
                            if let Ok(Some(conditional)) = self.parse_jinja_conditional_expr(kind) {
                                return Ok(conditional);
                            }
                            // Fall through to placeholder if conditional parse fails
                        }
                        _ => {
                            // Other block types (set, docs, etc.) - parse as placeholder
                        }
                    }
                }

                // Parse as simple placeholder: {% stmt %}
                let start_span = tok.span;
                self.advance(); // consume {%

                // Try to parse the Jinja expression (statements can contain expressions)
                if let Ok(Some(jinja_expr)) = self.parse_jinja_expr() {
                    // Expect closing %}
                    if let Some(close_tok) = self.peek() {
                        if matches!(close_tok.kind, TokenKind::JinjaStmtClose) {
                            let end_span = close_tok.span;
                            self.advance(); // consume %}

                            return Ok(AstExpr::JinjaPlaceholder {
                                node_id: self.id_gen.next(),
                                kind: crate::ast::JinjaKind::Statement,
                                span: Span {
                                    start: start_span.start,
                                    end: end_span.end,
                                },
                                expr: Some(jinja_expr),
                                syntax_id: None,
                            });
                        }
                    }
                }

                // Fallback: treat as opaque placeholder if parsing failed
                Ok(AstExpr::JinjaPlaceholder {
                    node_id: self.id_gen.next(),
                    kind: crate::ast::JinjaKind::Statement,
                    span: Span {
                        start: start_span.start,
                        end: start_span.end + 4, // Approximate span for {%%}
                    },
                    expr: None,
                    syntax_id: None,
                })
            }
            // Jinja comments at expression level: {# comment #}
            TokenKind::JinjaComment => {
                let jinja_tok = self.advance().ok_or_else(|| {
                    ParseError::unexpected_eof(
                        self.current_span(),
                        vec!["Jinja comment".to_string()],
                    )
                })?;
                Ok(AstExpr::JinjaPlaceholder {
                    node_id: self.id_gen.next(),
                    kind: crate::ast::JinjaKind::Comment,
                    span: jinja_tok.span,
                    expr: None,
                    syntax_id: None,
                })
            }
            // Scripting variable reference :my_var.
            // Note: Variable names can be keywords (e.g., :pattern, :like, :select)
            TokenKind::Punctuation(crate::lexer::Punctuation::Colon)
                if matches!(self.mode, ParserMode::Scripting) =>
            {
                let colon_token_id = self.current_token_id();
                let colon_tok = self.advance().ok_or_else(|| {
                    ParseError::unexpected_eof(self.current_span(), vec![":".to_string()])
                })?;
                let next = self.peek().ok_or_else(|| {
                    ParseError::unexpected_eof(self.current_span(), vec!["identifier".to_string()])
                })?;
                if self.can_be_identifier_token(next) {
                    let ident_tok = self.advance().expect_invariant(
                        "identifier token confirmed by peek for scripting variable",
                    );
                    let span = Span {
                        start: colon_tok.span.start,
                        end: ident_tok.span.end,
                    };

                    // Build and allocate syntax node for scripting variable
                    let syntax_var = crate::syntax::SyntaxScriptingVar {
                        colon: colon_token_id,
                        span: colon_tok.span,
                    };
                    let syntax_id = self.syntax_arena.alloc_scripting_var(syntax_var);

                    Ok(AstExpr::ScriptingVarRef {
                        node_id: self.id_gen.next(),
                        syntax_id,
                        name_span: ident_tok.span,
                        span,
                    })
                } else {
                    Err(ParseError::invalid_expression(
                        next.span,
                        "Expected identifier after : for scripting variable".to_string(),
                    ))
                }
            }
            // [NOT] EXISTS (SELECT ...)
            TokenKind::Keyword(Keyword::Not) | TokenKind::Keyword(Keyword::Exists) => {
                let mut not_span: Option<Span> = None;
                let mut not_token_id: Option<crate::cst::TokenId> = None;
                let first_token_id = self.current_token_id();
                let first_tok = self.advance().ok_or_else(|| {
                    ParseError::unexpected_eof(
                        self.current_span(),
                        vec!["NOT or EXISTS".to_string()],
                    )
                })?;
                let (exists_tok, exists_token_id) = match &first_tok.kind {
                    TokenKind::Keyword(Keyword::Not) => {
                        not_span = Some(first_tok.span);
                        not_token_id = Some(first_token_id);
                        let next = self.peek().ok_or_else(|| {
                            ParseError::unexpected_eof(
                                self.current_span(),
                                vec!["EXISTS or expression".to_string()],
                            )
                        })?;
                        match &next.kind {
                            TokenKind::Keyword(Keyword::Exists) => {
                                let exists_tid = self.current_token_id();
                                let exists_tok = self.advance().ok_or_else(|| {
                                    ParseError::unexpected_eof(
                                        self.current_span(),
                                        vec!["EXISTS".to_string()],
                                    )
                                })?;
                                (exists_tok, exists_tid)
                            }
                            // Handle NOT (expr) or NOT expr as prefix boolean negation
                            _ => {
                                // Parse the operand after NOT recursively
                                let operand = self.parse_expr_bp(25)?; // binding power just above AND (20)
                                let span = Span {
                                    start: first_tok.span.start,
                                    end: crate::parser::scripting::expr_span_end(&operand),
                                };

                                // Create BinaryOp with NOT operator (semantically wrong but matches existing structure)
                                let syntax_id = self.syntax_arena.alloc_binary_op(
                                    crate::syntax::SyntaxBinaryOp {
                                        op_token: first_token_id,
                                        span: first_tok.span,
                                    },
                                );

                                // Use a dummy left operand (empty span boolean)
                                let dummy_lhs = AstExpr::Literal {
                                    node_id: self.id_gen.next(),
                                    literal: AstLiteral::Boolean {
                                        span: Span {
                                            start: first_tok.span.start,
                                            end: first_tok.span.start,
                                        },
                                    },
                                };

                                return Ok(AstExpr::BinaryOp {
                                    syntax_id,
                                    left: Box::new(dummy_lhs),
                                    operator: crate::ast::BinaryOperator::Not,
                                    right: Box::new(operand),
                                    span,
                                    node_id: self.id_gen.next(),
                                });
                            }
                        }
                    }
                    TokenKind::Keyword(Keyword::Exists) => (first_tok, first_token_id),
                    _ => {
                        return Err(ParseError::invalid_expression(
                            self.current_span(),
                            "Expected NOT or EXISTS".to_string(),
                        ))
                    }
                };
                // Expect "( <subquery> )"; we reuse the SELECT entrypoint
                // to keep this focused on EXISTS only.
                let lparen_token_id = self.current_token_id();
                let lp = self.advance().ok_or_else(|| {
                    ParseError::unexpected_eof(self.current_span(), vec!["(".to_string()])
                })?;
                if !matches!(
                    lp.kind,
                    TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
                ) {
                    return Err(ParseError::unexpected_token(
                        lp.span,
                        vec!["(".to_string()],
                        Parser::token_description(lp, self.source),
                    ));
                }

                // Parse subquery using natural descent
                let subquery = self.try_parse_set_or_select_stmt().ok().ok_or_else(|| {
                    ParseError::invalid_expression(
                        self.current_span(),
                        "Expected SELECT subquery in EXISTS".to_string(),
                    )
                })?;

                // Expect closing paren
                let rparen_token_id = self.current_token_id();
                let rparen = if let Some(tok) = self.advance() {
                    if !matches!(
                        tok.kind,
                        TokenKind::Punctuation(crate::lexer::Punctuation::RParen)
                    ) {
                        return Err(ParseError::unexpected_token(
                            tok.span,
                            vec![")".to_string()],
                            Parser::token_description(tok, self.source),
                        ));
                    }
                    tok
                } else {
                    return Err(ParseError::new(
                        lp.span,
                        ParseErrorKind::UnexpectedEof {
                            expected: vec![")".to_string()],
                        },
                    ));
                };

                let span = Span {
                    start: not_span.unwrap_or(exists_tok.span).start,
                    end: rparen.span.end,
                };

                // Build and allocate syntax node for EXISTS subquery
                let syntax_exists = crate::syntax::SyntaxExistsSubquery {
                    not_keyword: not_token_id,
                    exists_keyword: exists_token_id,
                    lparen: lparen_token_id,
                    rparen: rparen_token_id,
                    span: Span {
                        start: not_span.unwrap_or(exists_tok.span).start,
                        end: exists_tok.span.end,
                    },
                };
                let syntax_id = self.syntax_arena.alloc_exists_subquery(syntax_exists);

                Ok(AstExpr::ExistsSubquery {
                    node_id: self.id_gen.next(),
                    syntax_id,
                    subquery: Box::new(subquery),
                    negated: not_token_id.is_some(),
                    span,
                })
            }
            // Unary plus for numeric literals and positional refs so that
            // expressions like +1 and +$1 tokenize and round-trip cleanly.
            TokenKind::Operator(crate::lexer::Operator::Plus) => {
                let plus_tok = self.advance().expect_invariant("+ after peek");
                let next = self.peek().ok_or_else(|| {
                    ParseError::unexpected_eof(
                        self.current_span(),
                        vec!["number or position ref".to_string()],
                    )
                })?;
                match &next.kind {
                    TokenKind::Literal(crate::lexer::LiteralKind::Number) => {
                        let num_tok = self.advance().expect_invariant("number after peek");
                        let span = Span {
                            start: plus_tok.span.start,
                            end: num_tok.span.end,
                        };
                        Ok(AstExpr::Literal {
                            node_id: self.id_gen.next(),
                            literal: AstLiteral::Number { span },
                        })
                    }
                    TokenKind::Literal(crate::lexer::LiteralKind::Position) => {
                        let pos_tok = self.advance().expect_invariant("position after peek");
                        let full_span = Span {
                            start: plus_tok.span.start,
                            end: pos_tok.span.end,
                        };
                        let dollar_span = Span {
                            start: full_span.start + 1,
                            end: full_span.start + 2,
                        };
                        let index_span = Span {
                            start: dollar_span.end,
                            end: full_span.end,
                        };
                        Ok(AstExpr::PositionRef {
                            node_id: self.id_gen.next(),
                            qualifier: None,
                            dot_span: None,
                            dollar_span,
                            index_span,
                        })
                    }
                    _ => Err(ParseError::invalid_expression(
                        plus_tok.span,
                        "Expected number or positional ref after +".to_string(),
                    )),
                }
            }
            // Unary minus for numeric literals, positional refs, and general expressions
            TokenKind::Operator(crate::lexer::Operator::Minus) => {
                let minus_token_id = self.current_token_id();
                let minus_tok = self.advance().expect_invariant("- after peek");
                let next = self.peek().ok_or_else(|| {
                    ParseError::unexpected_eof(self.current_span(), vec!["expression".to_string()])
                })?;

                // Fast path for literal numbers and positional refs to preserve
                // the simple -1 and -$1 forms without creating a binary op node
                match &next.kind {
                    TokenKind::Literal(crate::lexer::LiteralKind::Number) => {
                        let num_tok = self.advance().expect_invariant("number after peek");
                        let span = Span {
                            start: minus_tok.span.start,
                            end: num_tok.span.end,
                        };
                        Ok(AstExpr::Literal {
                            node_id: self.id_gen.next(),
                            literal: AstLiteral::Number { span },
                        })
                    }
                    TokenKind::Literal(crate::lexer::LiteralKind::Position) => {
                        let pos_tok = self.advance().expect_invariant("position after peek");
                        let full_span = Span {
                            start: minus_tok.span.start,
                            end: pos_tok.span.end,
                        };
                        let dollar_span = Span {
                            start: full_span.start + 1,
                            end: full_span.start + 2,
                        };
                        let index_span = Span {
                            start: dollar_span.end,
                            end: full_span.end,
                        };
                        Ok(AstExpr::PositionRef {
                            node_id: self.id_gen.next(),
                            qualifier: None,
                            dot_span: None,
                            dollar_span,
                            index_span,
                        })
                    }
                    // General case: parse the expression after minus as a unary operation
                    // This handles cases like -p_days, -(x + y), -func(), etc.
                    _ => {
                        // Parse the operand at primary expression level to avoid
                        // precedence issues (e.g., -a*b should be -(a*b) not (-a)*b)
                        let operand = self.parse_expr()?;
                        let span = Span {
                            start: minus_tok.span.start,
                            end: operand.span().end,
                        };
                        // Represent as a binary op with implicit zero on the left
                        let zero_lit = AstExpr::Literal {
                            node_id: self.id_gen.next(),
                            literal: AstLiteral::Number {
                                span: Span {
                                    start: minus_tok.span.start,
                                    end: minus_tok.span.start,
                                },
                            },
                        };
                        let operator = crate::ast::BinaryOperator::Minus;
                        let syntax_id =
                            self.syntax_arena
                                .alloc_binary_op(crate::syntax::SyntaxBinaryOp {
                                    op_token: minus_token_id,
                                    span: minus_tok.span,
                                });
                        Ok(AstExpr::BinaryOp {
                            node_id: self.id_gen.next(),
                            left: Box::new(zero_lit),
                            operator,
                            syntax_id,
                            right: Box::new(operand),
                            span,
                        })
                    }
                }
            }
            // Positional column reference: $<n>
            TokenKind::Literal(crate::lexer::LiteralKind::Position) => {
                let pos_tok = self.advance().expect_invariant("position after peek");
                let full_span = pos_tok.span;
                let dollar_span = Span {
                    start: full_span.start,
                    end: full_span.start + 1,
                };
                let index_span = Span {
                    start: full_span.start + 1,
                    end: full_span.end,
                };
                Ok(AstExpr::PositionRef {
                    node_id: self.id_gen.next(),
                    qualifier: None,
                    dot_span: None,
                    dollar_span,
                    index_span,
                })
            }
            TokenKind::Literal(crate::lexer::LiteralKind::Number) => {
                let tok = self.advance().expect_invariant("number after peek");
                Ok(AstExpr::Literal {
                    node_id: self.id_gen.next(),
                    literal: AstLiteral::Number { span: tok.span },
                })
            }
            TokenKind::Literal(crate::lexer::LiteralKind::String) => {
                let tok = self.advance().expect_invariant("string after peek");
                Ok(AstExpr::Literal {
                    node_id: self.id_gen.next(),
                    literal: AstLiteral::String { span: tok.span },
                })
            }
            TokenKind::Literal(crate::lexer::LiteralKind::StringFragment) => {
                // String fragment indicates a SQL string containing Jinja expressions.
                // Parse the entire interpolated string: 'prefix{{ expr }}middle{{ expr2 }}suffix'
                self.parse_string_with_jinja()
            }
            TokenKind::Literal(crate::lexer::LiteralKind::Boolean) => {
                let tok = self.advance().expect_invariant("boolean after peek");
                Ok(AstExpr::Literal {
                    node_id: self.id_gen.next(),
                    literal: AstLiteral::Boolean { span: tok.span },
                })
            }
            TokenKind::Literal(crate::lexer::LiteralKind::Null) => {
                let tok = self.advance().expect_invariant("null after peek");
                Ok(AstExpr::Literal {
                    node_id: self.id_gen.next(),
                    literal: AstLiteral::Null { span: tok.span },
                })
            }
            // INTERVAL value [unit [TO unit]]
            // Snowflake: INTERVAL 'value' [unit] — string literal only
            // BigQuery:  INTERVAL int_expr unit — integer + required unit
            //            INTERVAL 'string' unit TO unit — range form
            // We parse this as a literal spanning from INTERVAL through the optional time range
            TokenKind::Keyword(Keyword::Interval) => {
                let interval_tok = self.advance().expect_invariant("INTERVAL after peek");
                let start = interval_tok.span.start;
                let end = self.parse_interval_literal_tail()?;

                // Return as a string literal with the span covering INTERVAL ... [unit [TO unit]]
                // The formatter will emit the source tokens verbatim
                Ok(AstExpr::Literal {
                    node_id: self.id_gen.next(),
                    literal: AstLiteral::String {
                        span: Span { start, end },
                    },
                })
            }
            // Allow certain keywords to be used as function names when followed by '('
            // This handles RLIKE(...), ILIKE(...), LIKE(...), REPLACE(...), IF(...), etc. which can be both
            // infix operators/control flow and function calls depending on syntax
            // Also handles MATCH_RECOGNIZE functions: FIRST(...), LAST(...), NEXT(...)
            // GROUPING(...) is the aggregate companion to GROUPING SETS / CUBE / ROLLUP
            // VALUES(col) is MySQL's ON DUPLICATE KEY UPDATE accessor for
            // the would-be-inserted value; only call-shaped uses match.
            TokenKind::Keyword(
                Keyword::Rlike
                | Keyword::Regexp
                | Keyword::Ilike
                | Keyword::Like
                | Keyword::First
                | Keyword::Last
                | Keyword::Next
                | Keyword::Replace
                | Keyword::If
                | Keyword::Insert
                | Keyword::Grouping
                | Keyword::Values,
            ) => {
                // Peek ahead to see if this is followed by '('
                let save_idx = self.idx;
                let tok = self.advance().expect_invariant("keyword after peek");

                if let Some(next) = self.peek() {
                    if matches!(
                        next.kind,
                        TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
                    ) {
                        // This is a function call - use the shared helper
                        let expr = self.parse_function_call_from_lparen(tok.span, None)?;
                        return Ok(expr);
                    }
                }

                // Not a function call, restore position and return error
                // to let comparison operator parsing handle it
                self.idx = save_idx;
                Err(ParseError::invalid_expression(
                    tok.span,
                    "Unexpected SELECT keyword in expression context".to_string(),
                ))
            }
            // Unqualified star: * [EXCLUDE ...] [REPLACE ...] [RENAME ...]
            // Used in SELECT list when mixed with other columns
            TokenKind::Operator(crate::lexer::Operator::Star) => {
                let star_tok = self.advance().expect_invariant("* after peek");
                let mut span = star_tok.span;

                // Parse optional modifiers: EXCLUDE/EXCEPT, REPLACE, RENAME
                let exclude = {
                    let excl = self.parse_star_exclude()?;
                    if let Some(ref e) = excl {
                        span.end = e.exclude_span.end;
                        if !e.columns.is_empty() {
                            if let Some(last_col) = e.columns.last() {
                                span.end = last_col.name.span.end;
                            }
                        }
                    }
                    excl
                };

                let replace = if let Some(next) = self.peek() {
                    if matches!(next.kind, TokenKind::Keyword(Keyword::Replace)) {
                        let repl = self.parse_star_replace()?;
                        if let Some(ref r) = repl {
                            span.end = r.replace_span.end;
                            if !r.items.is_empty() {
                                if let Some(last_item) = r.items.last() {
                                    span.end = last_item.column.name.span.end;
                                }
                            }
                        }
                        repl
                    } else {
                        None
                    }
                } else {
                    None
                };

                let rename = if let Some(next) = self.peek() {
                    if matches!(next.kind, TokenKind::Keyword(Keyword::Rename)) {
                        let ren = self.parse_star_rename()?;
                        if let Some(ref r) = ren {
                            span.end = r.rename_span.end;
                            if !r.items.is_empty() {
                                if let Some(last_item) = r.items.last() {
                                    span.end = last_item.alias.span.end;
                                }
                            }
                        }
                        ren
                    } else {
                        None
                    }
                } else {
                    None
                };

                Ok(AstExpr::UnqualifiedStar {
                    node_id: self.id_gen.next(),
                    star_span: star_tok.span,
                    exclude: exclude.map(Box::new),
                    replace: replace.map(Box::new),
                    rename: rename.map(Box::new),
                    span,
                })
            }
            TokenKind::Identifier { .. } => {
                let tok = self.advance().expect_invariant("identifier after peek");

                // BigQuery raw/byte string prefix: r'...', b'...', rb'...', br'...'
                // The lexer produces the prefix as a separate Identifier token
                // immediately adjacent to the string literal.
                let lexeme = tok.lexeme(self.source);
                if matches!(
                    lexeme,
                    "r" | "R" | "b" | "B" | "rb" | "RB" | "Rb" | "rB" | "br" | "BR" | "Br" | "bR"
                ) {
                    if let Some(next) = self.peek() {
                        if matches!(
                            next.kind,
                            TokenKind::Literal(crate::lexer::LiteralKind::String)
                        ) && next.span.start == tok.span.end
                        {
                            let str_tok = self
                                .advance()
                                .expect_invariant("string literal after prefix");
                            let combined_span = Span {
                                start: tok.span.start,
                                end: str_tok.span.end,
                            };
                            return Ok(AstExpr::Literal {
                                node_id: self.id_gen.next(),
                                literal: crate::ast::AstLiteral::String {
                                    span: combined_span,
                                },
                            });
                        }
                    }
                }

                let ident = AstIdentifier {
                    node_id: self.id_gen.next(),
                    span: tok.span,
                };

                // Check for qualified star: identifier.*
                if let Some(dot_tok) = self.peek() {
                    let is_dot = match &dot_tok.kind {
                        TokenKind::Punctuation(crate::lexer::Punctuation::Dot) => true,
                        TokenKind::Literal(crate::lexer::LiteralKind::Number)
                            if dot_tok.lexeme(self.source) == "." =>
                        {
                            true
                        }
                        _ => false,
                    };
                    if is_dot {
                        // Look ahead one more token to see if it's a star (skip trivia/comments)
                        let save_idx = self.idx;
                        let _ = self.advance(); // consume dot
                        if let Some(star_tok) = self.peek_non_trivia() {
                            if matches!(
                                star_tok.kind,
                                TokenKind::Operator(crate::lexer::Operator::Star)
                            ) {
                                // This is identifier.* - parse as QualifiedStar
                                let star = self
                                    .advance()
                                    .expect_invariant("Star token should be available after peek");
                                let qualifier = AstObjectRef {
                                    node_id: self.id_gen.next(),
                                    span: tok.span,
                                    parts: None, // column qualifier; see AstObjectRef::parts
                                    identifier_arg: None,
                                };

                                let mut span = Span {
                                    start: tok.span.start,
                                    end: star.span.end,
                                };

                                // Parse optional modifiers: EXCLUDE/EXCEPT, REPLACE, RENAME
                                let exclude = {
                                    let excl = self.parse_star_exclude()?;
                                    if let Some(ref e) = excl {
                                        span.end = e.exclude_span.end;
                                        if !e.columns.is_empty() {
                                            if let Some(last_col) = e.columns.last() {
                                                span.end = last_col.name.span.end;
                                            }
                                        }
                                    }
                                    excl
                                };

                                let replace = if let Some(next) = self.peek() {
                                    if matches!(next.kind, TokenKind::Keyword(Keyword::Replace)) {
                                        let repl = self.parse_star_replace()?;
                                        if let Some(ref r) = repl {
                                            span.end = r.replace_span.end;
                                            if !r.items.is_empty() {
                                                if let Some(last_item) = r.items.last() {
                                                    span.end = last_item.column.name.span.end;
                                                }
                                            }
                                        }
                                        repl
                                    } else {
                                        None
                                    }
                                } else {
                                    None
                                };

                                let rename = if let Some(next) = self.peek() {
                                    if matches!(next.kind, TokenKind::Keyword(Keyword::Rename)) {
                                        let ren = self.parse_star_rename()?;
                                        if let Some(ref r) = ren {
                                            span.end = r.rename_span.end;
                                            if !r.items.is_empty() {
                                                if let Some(last_item) = r.items.last() {
                                                    span.end = last_item.alias.span.end;
                                                }
                                            }
                                        }
                                        ren
                                    } else {
                                        None
                                    }
                                } else {
                                    None
                                };

                                return Ok(AstExpr::QualifiedStar {
                                    node_id: self.id_gen.next(),
                                    qualifier,
                                    star_span: star.span,
                                    exclude: exclude.map(Box::new),
                                    replace: replace.map(Box::new),
                                    rename: rename.map(Box::new),
                                    span,
                                });
                            }
                        }
                        // Not a star, restore position and continue with normal qualified identifier parsing
                        self.idx = save_idx;
                    }
                }

                // Qualified identifier: handles multi-level qualified names like db.schema.table.col
                // or Jinja patterns like "{{this.database}}".{{target.schema}}.func(args)
                // Also handles t.{{ jinja_var }} for Jinja expressions as member names.
                let mut qualifier: Option<AstObjectRef> = None;
                let mut name_span = ident.span;
                let full_qualifier_start = ident.span.start;

                // Loop to handle multi-level qualification (db.schema.table.column)
                loop {
                    if let Some(dot_tok) = self.peek() {
                        let is_dot = match &dot_tok.kind {
                            TokenKind::Punctuation(crate::lexer::Punctuation::Dot) => true,
                            TokenKind::Literal(crate::lexer::LiteralKind::Number)
                                if dot_tok.lexeme(self.source) == "." =>
                            {
                                true
                            }
                            _ => false,
                        };
                        if is_dot {
                            let save_idx = self.idx;
                            let dot_tok = self.advance().expect_invariant("dot after peek"); // consume '.' token

                            // Check what comes after the dot (skip trivia/comments)
                            if let Some(second) = self.peek_non_trivia() {
                                // Handle qualified position reference: src.$1 (terminal - don't loop)
                                if matches!(
                                    second.kind,
                                    TokenKind::Literal(crate::lexer::LiteralKind::Position)
                                ) {
                                    let pos_tok =
                                        self.advance().expect_invariant("position after peek");
                                    let full_span = pos_tok.span;
                                    let dollar_span = Span {
                                        start: full_span.start,
                                        end: full_span.start + 1,
                                    };
                                    let index_span = Span {
                                        start: full_span.start + 1,
                                        end: full_span.end,
                                    };
                                    return Ok(AstExpr::PositionRef {
                                        node_id: self.id_gen.next(),
                                        qualifier: Some(AstObjectRef {
                                            node_id: self.id_gen.next(),
                                            span: Span {
                                                start: full_qualifier_start,
                                                end: name_span.end,
                                            },
                                            parts: None, // column qualifier; see AstObjectRef::parts
                                            identifier_arg: None,
                                        }),
                                        dot_span: Some(dot_tok.span),
                                        dollar_span,
                                        index_span,
                                    });
                                } else if self.can_be_identifier_after_dot_token(second) {
                                    // Regular identifier: extend the qualified name (any keyword allowed after dot)
                                    let second =
                                        self.advance().expect_invariant("peek confirmed token");
                                    // Push the current name into the qualifier, make second the new name
                                    qualifier = Some(AstObjectRef {
                                        node_id: self.id_gen.next(),
                                        span: Span {
                                            start: full_qualifier_start,
                                            end: name_span.end,
                                        },
                                        parts: None, // column qualifier; see AstObjectRef::parts
                                        identifier_arg: None,
                                    });
                                    name_span = second.span;
                                    // Continue loop to check for more dots
                                    continue;
                                } else if matches!(second.kind, TokenKind::JinjaExprOpen) {
                                    // Jinja expression as member: t.{{ col_name }}
                                    // Parse the Jinja expression and use its span as the name
                                    let jinja_start = second.span.start;
                                    self.advance(); // consume {{

                                    // Consume tokens until we hit }}
                                    let mut jinja_end = second.span.end;
                                    while let Some(inner) = self.peek() {
                                        if matches!(inner.kind, TokenKind::JinjaExprClose) {
                                            jinja_end = inner.span.end;
                                            self.advance(); // consume }}
                                            break;
                                        }
                                        self.advance();
                                    }

                                    // Push current name into qualifier, make Jinja the new name
                                    qualifier = Some(AstObjectRef {
                                        node_id: self.id_gen.next(),
                                        span: Span {
                                            start: full_qualifier_start,
                                            end: name_span.end,
                                        },
                                        parts: None, // column qualifier; see AstObjectRef::parts
                                        identifier_arg: None,
                                    });
                                    name_span = Span {
                                        start: jinja_start,
                                        end: jinja_end,
                                    };
                                    // Continue loop to check for more dots after Jinja
                                    continue;
                                } else {
                                    // Not a valid member access, restore position
                                    self.idx = save_idx;
                                }
                            }
                        }
                    }
                    // No more dots or couldn't extend qualification
                    break;
                }
                let _base_ident = AstIdentifier {
                    node_id: self.id_gen.next(),
                    span: name_span,
                };
                // TRY_CAST(expr AS type) - handle as special identifier function
                if tok.lexeme(self.source).eq_ignore_ascii_case("TRY_CAST") && qualifier.is_none() {
                    // tok is already the TRY_CAST token (from advance above in Identifier branch)
                    let try_cast_tok = tok;
                    let try_cast_token_id = self.last_token_id(); // The token we just consumed (TRY_CAST)
                    let lp = self.advance().ok_or_else(|| {
                        ParseError::unexpected_eof(self.current_span(), vec!["(".to_string()])
                    })?;
                    let lparen_token_id = self.last_token_id(); // Capture immediately after advance
                    if !matches!(
                        lp.kind,
                        TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
                    ) {
                        return Err(ParseError::unexpected_token(
                            lp.span,
                            vec!["(".to_string()],
                            Parser::token_description(lp, self.source),
                        ));
                    }
                    let expr = self.parse_expr()?;
                    let as_tok = self.advance().ok_or_else(|| {
                        ParseError::unexpected_eof(self.current_span(), vec!["AS".to_string()])
                    })?;
                    let as_token_id = self.last_token_id(); // Capture immediately after advance
                    if !matches!(as_tok.kind, TokenKind::Keyword(Keyword::As)) {
                        return Err(ParseError::unexpected_token(
                            as_tok.span,
                            vec!["AS".to_string()],
                            Parser::token_description(as_tok, self.source),
                        ));
                    }
                    let target_type = match self.parse_data_type().ok_or_else(|| {
                        ParseError::invalid_expression(
                            self.current_span(),
                            "Expected data type in TRY_CAST".to_string(),
                        )
                    })? {
                        Ok(t) => t,
                        Err(_) => {
                            // Error already stored by parse_data_type
                            return Err(ParseError::invalid_expression(
                                self.current_span(),
                                "Expected data type in TRY_CAST".to_string(),
                            ));
                        }
                    };
                    let rp = self.advance().ok_or_else(|| {
                        ParseError::unexpected_eof(self.current_span(), vec![")".to_string()])
                    })?;
                    let rparen_token_id = self.last_token_id(); // Capture immediately after advance
                    if !matches!(
                        rp.kind,
                        TokenKind::Punctuation(crate::lexer::Punctuation::RParen)
                    ) {
                        return Err(ParseError::unexpected_token(
                            rp.span,
                            vec![")".to_string()],
                            Parser::token_description(rp, self.source),
                        ));
                    }
                    let span = Span {
                        start: try_cast_tok.span.start,
                        end: rp.span.end,
                    };

                    // Build and allocate syntax node
                    let syntax_try_cast = crate::syntax::SyntaxTryCast {
                        try_cast_keyword: try_cast_token_id,
                        l_paren: lparen_token_id,
                        as_keyword: as_token_id,
                        r_paren: rparen_token_id,
                        span,
                    };
                    let syntax_id = self.syntax_arena.alloc_try_cast(syntax_try_cast);

                    return Ok(AstExpr::TryCast {
                        node_id: self.id_gen.next(),
                        syntax_id,
                        expr: Box::new(expr),
                        target_type,
                        span,
                    });
                }
                // SAFE_CAST(expr AS type) - BigQuery's equivalent of TRY_CAST
                // Returns NULL on conversion failure instead of raising an error
                if tok.lexeme(self.source).eq_ignore_ascii_case("SAFE_CAST") && qualifier.is_none()
                {
                    let safe_cast_tok = tok;
                    let safe_cast_token_id = self.last_token_id();
                    let lp = self.advance().ok_or_else(|| {
                        ParseError::unexpected_eof(self.current_span(), vec!["(".to_string()])
                    })?;
                    let lparen_token_id = self.last_token_id();
                    if !matches!(
                        lp.kind,
                        TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
                    ) {
                        return Err(ParseError::unexpected_token(
                            lp.span,
                            vec!["(".to_string()],
                            Parser::token_description(lp, self.source),
                        ));
                    }
                    let expr = self.parse_expr()?;
                    let as_tok = self.advance().ok_or_else(|| {
                        ParseError::unexpected_eof(self.current_span(), vec!["AS".to_string()])
                    })?;
                    let as_token_id = self.last_token_id();
                    if !matches!(as_tok.kind, TokenKind::Keyword(Keyword::As)) {
                        return Err(ParseError::unexpected_token(
                            as_tok.span,
                            vec!["AS".to_string()],
                            Parser::token_description(as_tok, self.source),
                        ));
                    }
                    let target_type = match self.parse_data_type().ok_or_else(|| {
                        ParseError::invalid_expression(
                            self.current_span(),
                            "Expected data type in SAFE_CAST".to_string(),
                        )
                    })? {
                        Ok(t) => t,
                        Err(_) => {
                            return Err(ParseError::invalid_expression(
                                self.current_span(),
                                "Expected data type in SAFE_CAST".to_string(),
                            ));
                        }
                    };
                    let rp = self.advance().ok_or_else(|| {
                        ParseError::unexpected_eof(self.current_span(), vec![")".to_string()])
                    })?;
                    let rparen_token_id = self.last_token_id();
                    if !matches!(
                        rp.kind,
                        TokenKind::Punctuation(crate::lexer::Punctuation::RParen)
                    ) {
                        return Err(ParseError::unexpected_token(
                            rp.span,
                            vec![")".to_string()],
                            Parser::token_description(rp, self.source),
                        ));
                    }
                    let span = Span {
                        start: safe_cast_tok.span.start,
                        end: rp.span.end,
                    };

                    let syntax_safe_cast = crate::syntax::SyntaxSafeCast {
                        safe_cast_keyword: safe_cast_token_id,
                        l_paren: lparen_token_id,
                        as_keyword: as_token_id,
                        r_paren: rparen_token_id,
                        span,
                    };
                    let syntax_id = self.syntax_arena.alloc_safe_cast(syntax_safe_cast);

                    return Ok(AstExpr::SafeCast {
                        node_id: self.id_gen.next(),
                        syntax_id,
                        expr: Box::new(expr),
                        target_type,
                        span,
                    });
                }
                // EXTRACT(field FROM expr) - handle special date/time extraction syntax
                // Also supports EXTRACT(field, expr) - comma-separated function call syntax
                // We try the FROM syntax first, if FROM is not found we fall back to regular function parsing
                if tok.lexeme(self.source).eq_ignore_ascii_case("EXTRACT") && qualifier.is_none() {
                    let save_idx = self.idx;
                    // tok is already the EXTRACT token (from advance above in Identifier branch)
                    let extract_tok = tok;
                    let extract_token_id = self.last_token_id();

                    // Check if followed by '('
                    if let Some(lp) = self.advance() {
                        let lparen_token_id = self.last_token_id();
                        if matches!(
                            lp.kind,
                            TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
                        ) {
                            // Parse field name (e.g., DOW, YEAR, MONTH, DAY, HOUR, etc.)
                            if let Some(field_tok) = self.advance() {
                                // Field can be an identifier or keyword (some are reserved like YEAR, MONTH, DAY)
                                if self.can_be_identifier_token(field_tok)
                                    || matches!(field_tok.kind, TokenKind::Identifier { .. })
                                {
                                    let field_span = field_tok.span;
                                    // Check if next token is FROM keyword - if so, use special syntax
                                    if let Some(maybe_from) = self.peek_non_trivia() {
                                        if matches!(
                                            maybe_from.kind,
                                            TokenKind::Keyword(Keyword::From)
                                        ) {
                                            // This is EXTRACT(field FROM expr) syntax
                                            let _from_tok = self
                                                .advance()
                                                .expect_invariant("FROM keyword after peek");
                                            let from_token_id = self.last_token_id();

                                            // Parse the expression to extract from
                                            let expr = self.parse_expr()?;
                                            // Expect closing paren
                                            let rp = self.advance().ok_or_else(|| {
                                                ParseError::unexpected_eof(
                                                    self.current_span(),
                                                    vec![")".to_string()],
                                                )
                                            })?;
                                            let rparen_token_id = self.last_token_id();
                                            if !matches!(
                                                rp.kind,
                                                TokenKind::Punctuation(
                                                    crate::lexer::Punctuation::RParen
                                                )
                                            ) {
                                                return Err(ParseError::unexpected_token(
                                                    rp.span,
                                                    vec![")".to_string()],
                                                    Parser::token_description(rp, self.source),
                                                ));
                                            }
                                            let span = Span {
                                                start: extract_tok.span.start,
                                                end: rp.span.end,
                                            };

                                            // Build and allocate syntax node
                                            let syntax_extract = crate::syntax::SyntaxExtract {
                                                extract_token: extract_token_id,
                                                lparen: lparen_token_id,
                                                from_token: from_token_id,
                                                rparen: rparen_token_id,
                                                span,
                                            };
                                            let syntax_id =
                                                self.syntax_arena.alloc_extract(syntax_extract);

                                            return Ok(AstExpr::Extract {
                                                node_id: self.id_gen.next(),
                                                syntax_id,
                                                field_span,
                                                expr: Box::new(expr),
                                                span,
                                            });
                                        }
                                    }
                                }
                            }
                        }
                    }
                    // Not EXTRACT(field FROM expr) syntax, fall back to regular function parsing
                    self.idx = save_idx;
                }
                // POSITION(needle IN haystack) - special ANSI syntax for substring search
                // Also supports POSITION(needle, haystack) - comma-separated function call syntax
                // We try the IN syntax first, if IN is not found we fall back to regular function parsing
                if tok.lexeme(self.source).eq_ignore_ascii_case("POSITION") && qualifier.is_none() {
                    let save_idx = self.idx;
                    let position_tok = tok;
                    let position_token_id = self.last_token_id();

                    // Check if followed by '('
                    if let Some(lp) = self.advance() {
                        let lparen_token_id = self.last_token_id();
                        if matches!(
                            lp.kind,
                            TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
                        ) {
                            // Parse the needle expression (substring to find)
                            // Use parse_add_expr_in_mode to avoid consuming IN as an operator
                            if let Ok(needle) = self.parse_add_expr_in_mode() {
                                // Check if next token is IN keyword - if so, use special syntax
                                if let Some(maybe_in) = self.peek_non_trivia() {
                                    if matches!(maybe_in.kind, TokenKind::Keyword(Keyword::In)) {
                                        // This is POSITION(needle IN haystack) syntax
                                        let _in_tok = self
                                            .advance()
                                            .expect_invariant("IN keyword after peek");
                                        let in_token_id = self.last_token_id();

                                        // Parse the haystack expression (string to search in)
                                        // Use parse_add_expr_in_mode to avoid issues with operators
                                        let haystack = self.parse_add_expr_in_mode()?;
                                        // Expect closing paren
                                        let rp = self.advance().ok_or_else(|| {
                                            ParseError::unexpected_eof(
                                                self.current_span(),
                                                vec![")".to_string()],
                                            )
                                        })?;
                                        let rparen_token_id = self.last_token_id();
                                        if !matches!(
                                            rp.kind,
                                            TokenKind::Punctuation(
                                                crate::lexer::Punctuation::RParen
                                            )
                                        ) {
                                            return Err(ParseError::unexpected_token(
                                                rp.span,
                                                vec![")".to_string()],
                                                Parser::token_description(rp, self.source),
                                            ));
                                        }
                                        let span = Span {
                                            start: position_tok.span.start,
                                            end: rp.span.end,
                                        };

                                        // Build and allocate syntax node
                                        let syntax_position = crate::syntax::SyntaxPosition {
                                            position_token: position_token_id,
                                            lparen: lparen_token_id,
                                            in_token: in_token_id,
                                            rparen: rparen_token_id,
                                            span,
                                        };
                                        let syntax_id =
                                            self.syntax_arena.alloc_position(syntax_position);

                                        return Ok(AstExpr::Position {
                                            node_id: self.id_gen.next(),
                                            syntax_id,
                                            needle: Box::new(needle),
                                            haystack: Box::new(haystack),
                                            span,
                                        });
                                    }
                                }
                            }
                        }
                    }
                    // Not POSITION(needle IN haystack) syntax, fall back to regular function parsing
                    self.idx = save_idx;
                }
                // TRIM([BOTH|LEADING|TRAILING] [chars] FROM source) - ANSI trim syntax.
                // Also supports TRIM(source) / TRIM(source, chars) comma forms, which
                // fall back to regular function parsing when no FROM separator appears.
                if tok.lexeme(self.source).eq_ignore_ascii_case("TRIM") && qualifier.is_none() {
                    let save_idx = self.idx;
                    let trim_tok = tok;
                    let trim_token_id = self.last_token_id();

                    if let Some(lp) = self.advance() {
                        let lparen_token_id = self.last_token_id();
                        if matches!(
                            lp.kind,
                            TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
                        ) {
                            // Optional trim-spec keyword (BOTH/LEADING/TRAILING are
                            // identifiers). Captured as a span so the formatter emits
                            // it byte-exact from source, mirroring EXTRACT's field.
                            let mut spec_span: Option<Span> = None;
                            if let Some(spec_tok) = self.peek_non_trivia() {
                                if matches!(spec_tok.kind, TokenKind::Identifier { .. }) {
                                    let lx = spec_tok.lexeme(self.source);
                                    let is_spec = lx.eq_ignore_ascii_case("BOTH")
                                        || lx.eq_ignore_ascii_case("LEADING")
                                        || lx.eq_ignore_ascii_case("TRAILING");
                                    if is_spec {
                                        let consumed = self
                                            .advance()
                                            .expect_invariant("trim-spec keyword after peek");
                                        spec_span = Some(consumed.span);
                                    }
                                }
                            }

                            // Resolve the optional trim-characters expr and the FROM token.
                            // Either FROM appears directly (no chars), or a chars expr
                            // precedes FROM.
                            let mut chars: Option<Box<AstExpr>> = None;
                            let mut from_token_id: Option<crate::cst::TokenId> = None;
                            if matches!(
                                self.peek_non_trivia().map(|t| &t.kind),
                                Some(TokenKind::Keyword(Keyword::From))
                            ) {
                                self.advance().expect_invariant("FROM keyword after peek");
                                from_token_id = Some(self.last_token_id());
                            } else if let Ok(first) = self.parse_expr() {
                                if matches!(
                                    self.peek_non_trivia().map(|t| &t.kind),
                                    Some(TokenKind::Keyword(Keyword::From))
                                ) {
                                    self.advance().expect_invariant("FROM keyword after peek");
                                    from_token_id = Some(self.last_token_id());
                                    chars = Some(Box::new(first));
                                }
                            }

                            // FROM present ⇒ definitively ANSI trim; commit and propagate
                            // errors (mirrors EXTRACT/POSITION).
                            if let Some(from_token_id) = from_token_id {
                                let source = self.parse_expr()?;
                                let rp = self.advance().ok_or_else(|| {
                                    ParseError::unexpected_eof(
                                        self.current_span(),
                                        vec![")".to_string()],
                                    )
                                })?;
                                let rparen_token_id = self.last_token_id();
                                if !matches!(
                                    rp.kind,
                                    TokenKind::Punctuation(crate::lexer::Punctuation::RParen)
                                ) {
                                    return Err(ParseError::unexpected_token(
                                        rp.span,
                                        vec![")".to_string()],
                                        Parser::token_description(rp, self.source),
                                    ));
                                }
                                let span = Span {
                                    start: trim_tok.span.start,
                                    end: rp.span.end,
                                };
                                let syntax_trim = crate::syntax::SyntaxTrim {
                                    trim_token: trim_token_id,
                                    lparen: lparen_token_id,
                                    from_token: from_token_id,
                                    rparen: rparen_token_id,
                                    span,
                                };
                                let syntax_id = self.syntax_arena.alloc_trim(syntax_trim);
                                return Ok(AstExpr::Trim {
                                    node_id: self.id_gen.next(),
                                    syntax_id,
                                    spec_span,
                                    chars,
                                    source: Box::new(source),
                                    span,
                                });
                            }
                        }
                    }
                    // Not ANSI TRIM(... FROM ...) syntax, fall back to function parsing
                    self.idx = save_idx;
                }
                // SUBSTRING(source FROM start [FOR length]) - ANSI substring syntax.
                // The comma form SUBSTRING(source, start, length) falls back to a
                // regular function call (no FROM/FOR separator present).
                if tok.lexeme(self.source).eq_ignore_ascii_case("SUBSTRING") && qualifier.is_none()
                {
                    let save_idx = self.idx;
                    let substring_tok = tok;
                    let substring_token_id = self.last_token_id();

                    if let Some(lp) = self.advance() {
                        let lparen_token_id = self.last_token_id();
                        if matches!(
                            lp.kind,
                            TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
                        ) {
                            if let Ok(source) = self.parse_expr() {
                                let next_is_from = matches!(
                                    self.peek_non_trivia().map(|t| &t.kind),
                                    Some(TokenKind::Keyword(Keyword::From))
                                );
                                let next_is_for = matches!(
                                    self.peek_non_trivia().map(|t| &t.kind),
                                    Some(TokenKind::Keyword(Keyword::For))
                                );
                                // FROM/FOR present ⇒ ANSI substring; commit and propagate.
                                if next_is_from || next_is_for {
                                    let mut from_token_id: Option<crate::cst::TokenId> = None;
                                    let mut from_expr: Option<Box<AstExpr>> = None;
                                    let mut for_token_id: Option<crate::cst::TokenId> = None;
                                    let mut for_expr: Option<Box<AstExpr>> = None;
                                    if next_is_from {
                                        self.advance().expect_invariant("FROM keyword after peek");
                                        from_token_id = Some(self.last_token_id());
                                        from_expr = Some(Box::new(self.parse_expr()?));
                                    }
                                    if matches!(
                                        self.peek_non_trivia().map(|t| &t.kind),
                                        Some(TokenKind::Keyword(Keyword::For))
                                    ) {
                                        self.advance().expect_invariant("FOR keyword after peek");
                                        for_token_id = Some(self.last_token_id());
                                        for_expr = Some(Box::new(self.parse_expr()?));
                                    }
                                    let rp = self.advance().ok_or_else(|| {
                                        ParseError::unexpected_eof(
                                            self.current_span(),
                                            vec![")".to_string()],
                                        )
                                    })?;
                                    let rparen_token_id = self.last_token_id();
                                    if !matches!(
                                        rp.kind,
                                        TokenKind::Punctuation(crate::lexer::Punctuation::RParen)
                                    ) {
                                        return Err(ParseError::unexpected_token(
                                            rp.span,
                                            vec![")".to_string()],
                                            Parser::token_description(rp, self.source),
                                        ));
                                    }
                                    let span = Span {
                                        start: substring_tok.span.start,
                                        end: rp.span.end,
                                    };
                                    let syntax_substring = crate::syntax::SyntaxSubstring {
                                        substring_token: substring_token_id,
                                        lparen: lparen_token_id,
                                        from_token: from_token_id,
                                        for_token: for_token_id,
                                        rparen: rparen_token_id,
                                        span,
                                    };
                                    let syntax_id =
                                        self.syntax_arena.alloc_substring(syntax_substring);
                                    return Ok(AstExpr::Substring {
                                        node_id: self.id_gen.next(),
                                        syntax_id,
                                        source: Box::new(source),
                                        from: from_expr,
                                        for_len: for_expr,
                                        span,
                                    });
                                }
                            }
                        }
                    }
                    // Not ANSI SUBSTRING(... FROM ...) syntax, fall back to function parsing
                    self.idx = save_idx;
                }
                // IDENTIFIER(...) explicit Snowflake identifier. Parse the argument
                // expression in the current mode so scripting bindings like
                // IDENTIFIER(:table_name) are accepted inside scripting blocks.
                // Only treat as IDENTIFIER() function if followed by '(' - otherwise
                // treat "identifier" as a regular column name.
                if tok.lexeme(self.source).eq_ignore_ascii_case("IDENTIFIER") && qualifier.is_none()
                {
                    if let Some(next) = self.peek() {
                        if matches!(
                            next.kind,
                            TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
                        ) {
                            // Consume '('
                            self.advance();
                            let arg_expr = self.parse_expr()?;
                            let rp = self.advance().ok_or_else(|| {
                                ParseError::unexpected_eof(
                                    self.current_span(),
                                    vec![")".to_string()],
                                )
                            })?;
                            if !matches!(
                                rp.kind,
                                TokenKind::Punctuation(crate::lexer::Punctuation::RParen)
                            ) {
                                return Err(ParseError::unexpected_token(
                                    rp.span,
                                    vec![")".to_string()],
                                    Parser::token_description(rp, self.source),
                                ));
                            }
                            let span = Span {
                                start: tok.span.start,
                                end: rp.span.end,
                            };
                            return Ok(AstExpr::ExplSnowIdent {
                                node_id: self.id_gen.next(),
                                ident_span: tok.span,
                                arg: Box::new(arg_expr),
                                span,
                            });
                        }
                    }
                    // If not followed by '(', fall through to treat as regular identifier
                }

                // dbt ref() function: ref('model') or ref('package', 'model')
                // Falls back to regular function call if arguments don't match dbt pattern
                if tok.lexeme(self.source).eq_ignore_ascii_case("ref") && qualifier.is_none() {
                    if let Some(next) = self.peek() {
                        if matches!(
                            next.kind,
                            TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
                        ) {
                            let save_idx = self.idx;
                            match self.parse_dbt_ref(tok.span) {
                                Ok(expr) => return Ok(expr),
                                Err(_) => {
                                    self.idx = save_idx;
                                    // Fall through to generic function call parser
                                }
                            }
                        }
                    }
                }

                // dbt source() function: source('source_name', 'table_name')
                // Falls back to regular function call if arguments don't match dbt pattern
                if tok.lexeme(self.source).eq_ignore_ascii_case("source") && qualifier.is_none() {
                    if let Some(next) = self.peek() {
                        if matches!(
                            next.kind,
                            TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
                        ) {
                            let save_idx = self.idx;
                            match self.parse_dbt_source(tok.span) {
                                Ok(expr) => return Ok(expr),
                                Err(_) => {
                                    self.idx = save_idx;
                                    // Fall through to generic function call parser
                                }
                            }
                        }
                    }
                }

                // dbt var() function: var('name') or var('name', default)
                // Falls back to regular function call if argument isn't a string literal
                // (e.g., SQL VAR(x) aggregate function)
                if tok.lexeme(self.source).eq_ignore_ascii_case("var") && qualifier.is_none() {
                    if let Some(next) = self.peek() {
                        if matches!(
                            next.kind,
                            TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
                        ) {
                            let save_idx = self.idx;
                            match self.parse_dbt_var(tok.span) {
                                Ok(expr) => return Ok(expr),
                                Err(_) => {
                                    self.idx = save_idx;
                                    // Fall through to generic function call parser
                                }
                            }
                        }
                    }
                }

                // dbt config() function: config(materialized='table', ...)
                // Falls back to regular function call if arguments don't match dbt pattern
                if tok.lexeme(self.source).eq_ignore_ascii_case("config") && qualifier.is_none() {
                    if let Some(next) = self.peek() {
                        if matches!(
                            next.kind,
                            TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
                        ) {
                            let save_idx = self.idx;
                            match self.parse_dbt_config(tok.span) {
                                Ok(expr) => return Ok(expr),
                                Err(_) => {
                                    self.idx = save_idx;
                                    // Fall through to generic function call parser
                                }
                            }
                        }
                    }
                }

                // dbt this reference: this or this()
                if tok.lexeme(self.source).eq_ignore_ascii_case("this") && qualifier.is_none() {
                    // Check if followed by ()
                    if let Some(next) = self.peek() {
                        if matches!(
                            next.kind,
                            TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
                        ) {
                            let lp = self.advance().expect_invariant("( after peek");
                            let rp = self.advance().ok_or_else(|| {
                                ParseError::unexpected_eof(
                                    self.current_span(),
                                    vec![")".to_string()],
                                )
                            })?;
                            if !matches!(
                                rp.kind,
                                TokenKind::Punctuation(crate::lexer::Punctuation::RParen)
                            ) {
                                return Err(ParseError::unexpected_token(
                                    rp.span,
                                    vec![")".to_string()],
                                    Parser::token_description(rp, self.source),
                                ));
                            }
                            let span = Span {
                                start: tok.span.start,
                                end: rp.span.end,
                            };
                            return Ok(AstExpr::DbtThis {
                                node_id: self.id_gen.next(),
                                this_span: tok.span,
                                parens: Some((lp.span, rp.span)),
                                span,
                            });
                        }
                    }
                    // Plain 'this' without parens
                    return Ok(AstExpr::DbtThis {
                        node_id: self.id_gen.next(),
                        this_span: tok.span,
                        parens: None,
                        span: tok.span,
                    });
                }

                // All window functions (ROW_NUMBER, RANK, NTILE, LAG, LEAD, etc.) are handled
                // by the generic function call parser below, which properly delegates to
                // parse_function_call_from_lparen -> parse_window_spec for OVER clauses.
                // This ensures consistent handling of ORDER BY ASC/DESC and all window function variants.

                // Typed string literals: DATE '2024-01-15', TIMESTAMP '...', NUMERIC '...', JSON '...', etc.
                // BigQuery syntax where a type name followed by a string literal creates a typed literal.
                // Must check BEFORE function call detection (DATE(...) is a function, DATE '...' is a literal).
                if qualifier.is_none() {
                    let lexeme = tok.lexeme(self.source);
                    let is_typed_literal_prefix = lexeme.eq_ignore_ascii_case("DATE")
                        || lexeme.eq_ignore_ascii_case("TIME")
                        || lexeme.eq_ignore_ascii_case("DATETIME")
                        || lexeme.eq_ignore_ascii_case("TIMESTAMP")
                        || lexeme.eq_ignore_ascii_case("NUMERIC")
                        || lexeme.eq_ignore_ascii_case("BIGNUMERIC")
                        || lexeme.eq_ignore_ascii_case("DECIMAL")
                        || lexeme.eq_ignore_ascii_case("BIGDECIMAL")
                        || lexeme.eq_ignore_ascii_case("JSON");
                    if is_typed_literal_prefix {
                        if let Some(next) = self.peek() {
                            if matches!(
                                next.kind,
                                TokenKind::Literal(crate::lexer::LiteralKind::String)
                            ) {
                                let str_tok = self.advance().unwrap();
                                let span = Span {
                                    start: tok.span.start,
                                    end: str_tok.span.end,
                                };
                                return Ok(AstExpr::TypedStringLiteral {
                                    node_id: self.id_gen.next(),
                                    type_name_span: tok.span,
                                    value_span: str_tok.span,
                                    odbc_kind: None,
                                    span,
                                });
                            }
                        }
                    }
                }

                // Generic function call like COUNT(*), SUM(x), AVG(salary), window functions, etc.
                // Use the shared helper that handles all function call syntax.
                //
                // Special case: STRUCT<type_params>(...) - BigQuery typed STRUCT constructor
                // The angle brackets contain type parameters, not comparison operators.
                // We consume them here and extend name_span to include STRUCT<...>.
                if qualifier.is_none() {
                    if let Some(lt) = self.peek() {
                        if matches!(lt.kind, TokenKind::Operator(crate::lexer::Operator::Lt)) {
                            let lex = tok.lexeme(self.source);
                            if lex.eq_ignore_ascii_case("STRUCT")
                                || lex.eq_ignore_ascii_case("ARRAY")
                            {
                                // Consume angle-bracket type parameters: <field_name type, ...>
                                // Use depth tracking to handle nested angle brackets like STRUCT<a STRUCT<b INT64>>
                                self.advance(); // consume <
                                let mut depth: u32 = 1;
                                let mut last_end = lt.span.end;
                                while depth > 0 {
                                    if let Some(inner) = self.advance() {
                                        last_end = inner.span.end;
                                        match inner.kind {
                                            TokenKind::Operator(crate::lexer::Operator::Lt) => {
                                                depth += 1;
                                            }
                                            TokenKind::Operator(crate::lexer::Operator::Gt) => {
                                                depth -= 1;
                                            }
                                            TokenKind::Operator(crate::lexer::Operator::GtGt) => {
                                                // >> closes two levels at once
                                                depth = depth.saturating_sub(2);
                                            }
                                            _ => {}
                                        }
                                    } else {
                                        break; // EOF inside type params — let function call parser handle error
                                    }
                                }
                                // Extend name_span to include STRUCT<...>
                                name_span = Span {
                                    start: name_span.start,
                                    end: last_end,
                                };
                            }
                        }
                    }
                }
                if let Some(lp) = self.peek() {
                    if matches!(
                        lp.kind,
                        TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
                    ) {
                        // When there's a qualifier (e.g., SAFE.JSON_VALUE, schema.func),
                        // extend the function name span to include qualifier + dot so the
                        // formatter emits the full qualified reference.
                        let full_name_span = if qualifier.is_some() {
                            Span {
                                start: full_qualifier_start,
                                end: name_span.end,
                            }
                        } else {
                            name_span
                        };
                        let expr = self.parse_function_call_from_lparen(full_name_span, None)?;
                        return Ok(expr);
                    }
                }

                // BigQuery typed ARRAY constructor: ARRAY<type>[elem, ...]
                // After consuming angle brackets above, name_span covers ARRAY<type>.
                // If the next token is LBracket, parse as array literal.
                if let Some(lb_tok) = self.peek() {
                    if matches!(
                        lb_tok.kind,
                        TokenKind::Punctuation(crate::lexer::Punctuation::LBracket)
                    ) {
                        let lex = tok.lexeme(self.source);
                        if lex.eq_ignore_ascii_case("ARRAY") {
                            let lbracket_token_id = self.current_token_id();
                            let lb = self.advance().expect_invariant("[ after peek");
                            let mut elements: Vec<AstExpr> = Vec::new();
                            loop {
                                let next = self.peek().ok_or_else(|| {
                                    ParseError::unexpected_eof(
                                        self.current_span(),
                                        vec!["]".to_string()],
                                    )
                                })?;
                                match &next.kind {
                                    TokenKind::Punctuation(crate::lexer::Punctuation::RBracket) => {
                                        let rbracket_token_id = self.current_token_id();
                                        let rb = self
                                            .advance()
                                            .expect_invariant("RBracket token confirmed by peek");
                                        let span = Span {
                                            start: name_span.start,
                                            end: rb.span.end,
                                        };
                                        let syntax_array = crate::syntax::SyntaxArrayLiteral {
                                            l_bracket: lbracket_token_id,
                                            r_bracket: rbracket_token_id,
                                            span: Span {
                                                start: lb.span.start,
                                                end: rb.span.end,
                                            },
                                        };
                                        let syntax_id =
                                            self.syntax_arena.alloc_array_literal(syntax_array);
                                        return Ok(AstExpr::Array {
                                            syntax_id,
                                            elements,
                                            span,
                                            node_id: self.id_gen.next(),
                                            has_array_keyword: true,
                                            array_keyword_span: Some(name_span),
                                        });
                                    }
                                    _ => {
                                        let elem = self.parse_expr()?;
                                        elements.push(elem);
                                        if let Some(sep) = self.peek() {
                                            match sep.kind {
                                                TokenKind::Punctuation(
                                                    crate::lexer::Punctuation::Comma,
                                                ) => {
                                                    let _ = self.advance();
                                                }
                                                TokenKind::Punctuation(
                                                    crate::lexer::Punctuation::RBracket,
                                                ) => {
                                                    continue;
                                                }
                                                _ => {
                                                    return Err(ParseError::unexpected_token(
                                                        sep.span,
                                                        vec![",".to_string(), "]".to_string()],
                                                        Parser::token_description(sep, self.source),
                                                    ));
                                                }
                                            }
                                        } else {
                                            return Err(ParseError::new(
                                                lb.span,
                                                ParseErrorKind::UnexpectedEof {
                                                    expected: vec![
                                                        ",".to_string(),
                                                        "]".to_string(),
                                                    ],
                                                },
                                            ));
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                // Check for identifier followed by adjacent Jinja: column_name{{ suffix }}
                // This handles dbt patterns like dynamic column names
                let start_pos = if let Some(q) = &qualifier {
                    q.span.start
                } else {
                    name_span.start
                };
                let mut end_pos = name_span.end;

                while let Some(next) = self.peek() {
                    // Check if next token is immediately adjacent (no whitespace)
                    if next.span.start == end_pos {
                        match &next.kind {
                            TokenKind::JinjaComment => {
                                let tok = self
                                    .advance()
                                    .expect_invariant("JinjaComment token after peek");
                                end_pos = tok.span.end;
                            }
                            _ if self.can_be_identifier_token(next) => {
                                let tok = self
                                    .advance()
                                    .expect_invariant("identifier-like token after peek");
                                end_pos = tok.span.end;
                            }
                            TokenKind::Literal(crate::lexer::LiteralKind::StringFragment) => {
                                let tok = self
                                    .advance()
                                    .expect_invariant("StringFragment token after peek");
                                end_pos = tok.span.end;
                            }
                            TokenKind::JinjaExprOpen => {
                                // Adjacent Jinja expression: column_name{{ suffix }}
                                self.advance(); // consume {{
                                                // Consume until }}
                                while let Some(inner) = self.peek() {
                                    if matches!(inner.kind, TokenKind::JinjaExprClose) {
                                        end_pos = inner.span.end;
                                        self.advance();
                                        break;
                                    }
                                    self.advance();
                                }
                            }
                            _ => break,
                        }
                    } else {
                        break;
                    }
                }

                // If we consumed additional tokens, return as JinjaPlaceholder with expanded span
                if end_pos != name_span.end {
                    return Ok(AstExpr::JinjaPlaceholder {
                        node_id: self.id_gen.next(),
                        kind: crate::ast::JinjaKind::Expression,
                        span: Span {
                            start: start_pos,
                            end: end_pos,
                        },
                        expr: None,
                        syntax_id: None,
                    });
                }

                Ok(AstExpr::Ident {
                    node_id: self.id_gen.next(),
                    column_ref: crate::ast::AstColumnRef {
                        node_id: self.id_gen.next(),
                        qualifier,
                        name: AstIdentifier {
                            node_id: self.id_gen.next(),
                            span: name_span,
                        },
                    },
                })
            }
            // CASE expression: CASE [expr] WHEN ... END
            // Handles both forms:
            // - Searched CASE: CASE WHEN condition THEN result END
            // - Simple CASE: CASE expr WHEN value THEN result END
            TokenKind::Keyword(Keyword::Case) => {
                let case_tok = self.advance().expect_invariant("CASE after peek");
                self.parse_case_expr(case_tok)?.ok_or_else(|| {
                    ParseError::invalid_expression(
                        case_tok.span,
                        "Expected CASE expression".to_string(),
                    )
                })
            }
            // CAST(expr AS type)
            TokenKind::Keyword(Keyword::Cast) => {
                let cast_tok = self.advance().expect_invariant("CAST after peek");
                let cast_token_id = self.last_token_id();
                let lp = self.advance().ok_or_else(|| {
                    ParseError::unexpected_eof(self.current_span(), vec!["(".to_string()])
                })?;
                let lparen_token_id = self.last_token_id();
                if !matches!(
                    lp.kind,
                    TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
                ) {
                    return Err(ParseError::unexpected_token(
                        lp.span,
                        vec!["(".to_string()],
                        Parser::token_description(lp, self.source),
                    ));
                }
                let expr = self.parse_expr()?;
                let as_tok = self.advance().ok_or_else(|| {
                    ParseError::unexpected_eof(self.current_span(), vec!["AS".to_string()])
                })?;
                let as_token_id = self.last_token_id();
                if !matches!(as_tok.kind, TokenKind::Keyword(Keyword::As)) {
                    return Err(ParseError::unexpected_token(
                        as_tok.span,
                        vec!["AS".to_string()],
                        Parser::token_description(as_tok, self.source),
                    ));
                }
                let target_type = match self.parse_data_type().ok_or_else(|| {
                    ParseError::invalid_expression(
                        self.current_span(),
                        "Expected data type in CAST".to_string(),
                    )
                })? {
                    Ok(t) => t,
                    Err(_) => {
                        return Err(ParseError::invalid_expression(
                            self.current_span(),
                            "Expected data type in CAST".to_string(),
                        ));
                    }
                };
                let rp = self.advance().ok_or_else(|| {
                    ParseError::unexpected_eof(self.current_span(), vec![")".to_string()])
                })?;
                let rparen_token_id = self.last_token_id();
                if !matches!(
                    rp.kind,
                    TokenKind::Punctuation(crate::lexer::Punctuation::RParen)
                ) {
                    return Err(ParseError::unexpected_token(
                        rp.span,
                        vec![")".to_string()],
                        Parser::token_description(rp, self.source),
                    ));
                }
                let span = Span {
                    start: cast_tok.span.start,
                    end: rp.span.end,
                };

                let syntax_cast = crate::syntax::SyntaxCastExpr {
                    cast_keyword: cast_token_id,
                    l_paren: lparen_token_id,
                    as_keyword: as_token_id,
                    r_paren: rparen_token_id,
                    span,
                };
                let syntax_id = self.syntax_arena.alloc_cast_expr(syntax_cast);

                Ok(AstExpr::Cast {
                    node_id: self.id_gen.next(),
                    syntax_id,
                    expr: Box::new(expr),
                    target_type,
                    span,
                })
            }
            // PRIOR expression for hierarchical queries
            TokenKind::Keyword(Keyword::Prior) => {
                let prior_tok = self.advance().expect_invariant("PRIOR after peek");
                let expr = self.parse_mul_expr_in_mode()?;
                let span = Span {
                    start: prior_tok.span.start,
                    end: expr_span_end(&expr),
                };
                Ok(AstExpr::Prior {
                    node_id: self.id_gen.next(),
                    prior_span: prior_tok.span,
                    expr: Box::new(expr),
                    span,
                })
            }
            // Handle contextual keywords that can be identifiers (e.g., FINAL, TYPE, CASE when not followed by WHEN)
            TokenKind::Keyword(_) if self.can_be_identifier_token(tok) => {
                let keyword_tok = self.advance().expect_invariant("keyword after peek");

                // Check for qualified reference: keyword.identifier or keyword.*
                if let Some(dot_tok) = self.peek() {
                    if matches!(
                        dot_tok.kind,
                        TokenKind::Punctuation(crate::lexer::Punctuation::Dot)
                    ) {
                        let _ = self.advance(); // consume dot
                        if let Some(next_tok) = self.peek_non_trivia() {
                            // Handle keyword.*
                            if matches!(
                                next_tok.kind,
                                TokenKind::Operator(crate::lexer::Operator::Star)
                            ) {
                                let star = self.advance().expect_invariant("star after peek");
                                return Ok(AstExpr::QualifiedStar {
                                    node_id: self.id_gen.next(),
                                    qualifier: AstObjectRef {
                                        node_id: self.id_gen.next(),
                                        span: keyword_tok.span,
                                        parts: None, // column qualifier; see AstObjectRef::parts
                                        identifier_arg: None,
                                    },
                                    star_span: star.span,
                                    exclude: None,
                                    replace: None,
                                    rename: None,
                                    span: Span {
                                        start: keyword_tok.span.start,
                                        end: star.span.end,
                                    },
                                });
                            }
                            // Handle keyword.identifier (qualified column reference)
                            else if self.can_be_identifier_token(next_tok) {
                                let ident_tok =
                                    self.advance().expect_invariant("identifier after peek");
                                // Check for qualified function call: keyword.func(...)
                                if let Some(lp) = self.peek() {
                                    if matches!(
                                        lp.kind,
                                        TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
                                    ) {
                                        let full_span = Span {
                                            start: keyword_tok.span.start,
                                            end: ident_tok.span.end,
                                        };
                                        return self
                                            .parse_function_call_from_lparen(full_span, None);
                                    }
                                }
                                return Ok(AstExpr::Ident {
                                    node_id: self.id_gen.next(),
                                    column_ref: crate::ast::AstColumnRef {
                                        node_id: self.id_gen.next(),
                                        qualifier: Some(AstObjectRef {
                                            node_id: self.id_gen.next(),
                                            span: keyword_tok.span,
                                            parts: None, // column qualifier; see AstObjectRef::parts
                                            identifier_arg: None,
                                        }),
                                        name: AstIdentifier {
                                            node_id: self.id_gen.next(),
                                            span: ident_tok.span,
                                        },
                                    },
                                });
                            }
                        }
                    }
                }

                // Check if this looks like a function call: keyword(...)
                if let Some(lp) = self.peek() {
                    if matches!(
                        lp.kind,
                        TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
                    ) {
                        return self.parse_function_call_from_lparen(keyword_tok.span, None);
                    }
                }

                // Treat keyword as simple identifier (no dot or no valid continuation after dot)
                Ok(AstExpr::Ident {
                    node_id: self.id_gen.next(),
                    column_ref: crate::ast::AstColumnRef {
                        node_id: self.id_gen.next(),
                        qualifier: None,
                        name: AstIdentifier {
                            node_id: self.id_gen.next(),
                            span: keyword_tok.span,
                        },
                    },
                })
            }
            TokenKind::Punctuation(crate::lexer::Punctuation::LParen) => {
                let lparen_tok = self.advance().expect_invariant("( after peek");
                let lparen_token_id = self.last_token_id();

                // Snowflake RESULTSET assignment form:
                //   `rs := (EXECUTE IMMEDIATE :stmt USING (a, b));`
                // The parenthesized RHS expression is a statement-form
                // EXECUTE IMMEDIATE that returns a RESULTSET. Wrap the
                // parsed `AstStmt::ExecuteImmediate` in a
                // [`AstExpr::ScalarSubquery`] (same shape used for
                // parenthesized SELECT) so downstream walkers reach the
                // EXECUTE IMMEDIATE through the expression tree.
                if let Some(next) = self.peek() {
                    if matches!(next.kind, TokenKind::Keyword(Keyword::Execute)) {
                        let saved_idx = self.idx;
                        let ei_result =
                            crate::parser::scripting::try_parse_execute_immediate_stmt(self);
                        match ei_result {
                            Ok(ei_stmt) => {
                                let rparen_tok = if let Some(tok) = self.advance() {
                                    if !matches!(
                                        tok.kind,
                                        TokenKind::Punctuation(crate::lexer::Punctuation::RParen)
                                    ) {
                                        return Err(ParseError::unexpected_token(
                                            tok.span,
                                            vec![")".to_string()],
                                            Parser::token_description(tok, self.source),
                                        ));
                                    }
                                    tok
                                } else {
                                    return Err(ParseError::new(
                                        lparen_tok.span,
                                        ParseErrorKind::UnexpectedEof {
                                            expected: vec![")".to_string()],
                                        },
                                    ));
                                };
                                let span = Span {
                                    start: lparen_tok.span.start,
                                    end: rparen_tok.span.end,
                                };
                                let rparen_token_id = self.last_token_id();
                                let syntax_subquery = crate::syntax::SyntaxSubquery {
                                    l_paren: lparen_token_id,
                                    select_span: ei_stmt.span(),
                                    r_paren: rparen_token_id,
                                    span,
                                };
                                let syntax_id = self.syntax_arena.alloc_subquery(syntax_subquery);
                                return Ok(AstExpr::ScalarSubquery {
                                    syntax_id,
                                    subquery: Box::new(ei_stmt),
                                    span,
                                    node_id: self.id_gen.next(),
                                });
                            }
                            Err(err) => {
                                if err.kind.is_resource_exhaustion() {
                                    return Err(err);
                                }
                                // Restore and fall through to other
                                // parenthesized-expression branches.
                                self.idx = saved_idx;
                            }
                        }
                    }
                }

                // Check if this is a scalar subquery: (SELECT ...)
                // Peek ahead to see if the next token is SELECT
                if let Some(next) = self.peek() {
                    if matches!(next.kind, TokenKind::Keyword(Keyword::Select)) {
                        // Save parser index in case SELECT parsing fails
                        let saved_idx = self.idx;

                        // This is a scalar subquery - parse using natural descent
                        let subquery_result = self.try_parse_set_or_select_stmt();

                        match subquery_result {
                            Ok(subquery) => {
                                // Expect closing paren
                                let rparen_tok = if let Some(tok) = self.advance() {
                                    if !matches!(
                                        tok.kind,
                                        TokenKind::Punctuation(crate::lexer::Punctuation::RParen)
                                    ) {
                                        return Err(ParseError::unexpected_token(
                                            tok.span,
                                            vec![")".to_string()],
                                            Parser::token_description(tok, self.source),
                                        ));
                                    }
                                    tok
                                } else {
                                    return Err(ParseError::new(
                                        lparen_tok.span,
                                        ParseErrorKind::UnexpectedEof {
                                            expected: vec![")".to_string()],
                                        },
                                    ));
                                };

                                let span = Span {
                                    start: lparen_tok.span.start,
                                    end: rparen_tok.span.end,
                                };

                                // Use lparen_token_id captured BEFORE advance, rparen is the last consumed token
                                let rparen_token_id = self.last_token_id();

                                let syntax_subquery = crate::syntax::SyntaxSubquery {
                                    l_paren: lparen_token_id,
                                    select_span: subquery.span(),
                                    r_paren: rparen_token_id,
                                    span,
                                };
                                let syntax_id = self.syntax_arena.alloc_subquery(syntax_subquery);

                                return Ok(AstExpr::ScalarSubquery {
                                    syntax_id,
                                    subquery: Box::new(subquery),
                                    span,
                                    node_id: self.id_gen.next(),
                                });
                            }
                            Err(err) => {
                                // Fatal errors (e.g., recursion limit) must not be recovered from
                                if err.kind.is_resource_exhaustion() {
                                    return Err(err);
                                }
                                // SELECT parsing failed - restore parser index to after the lparen
                                // and treat this as a regular parenthesized expression instead
                                self.idx = saved_idx;
                                // Fall through to parse as regular parenthesized expression
                            }
                        }
                    }
                }

                // Not a scalar subquery - parse as regular parenthesized expression
                let inner_expr = self.parse_expr()?;

                // Check for row value constructor: (expr, expr, ...)
                // If we see a comma after the first expression, this is a tuple/row constructor
                if let Some(tok) = self.peek() {
                    if matches!(
                        tok.kind,
                        TokenKind::Punctuation(crate::lexer::Punctuation::Comma)
                    ) {
                        // This is a row constructor - collect all elements
                        let mut elements = vec![inner_expr];
                        let mut commas = Vec::new();

                        while let Some(t) = self.peek() {
                            if matches!(
                                t.kind,
                                TokenKind::Punctuation(crate::lexer::Punctuation::Comma)
                            ) {
                                let comma_token_id = self.current_token_id();
                                self.advance(); // consume comma
                                commas.push(comma_token_id);

                                // Parse next element
                                let elem = self.parse_expr()?;
                                elements.push(elem);
                            } else {
                                break;
                            }
                        }

                        // Expect closing paren
                        let rparen_tok = if let Some(next) = self.advance() {
                            if !matches!(
                                next.kind,
                                TokenKind::Punctuation(crate::lexer::Punctuation::RParen)
                            ) {
                                return Err(ParseError::unexpected_token(
                                    next.span,
                                    vec![")".to_string()],
                                    Parser::token_description(next, self.source),
                                ));
                            }
                            next
                        } else {
                            return Err(ParseError::new(
                                lparen_tok.span,
                                ParseErrorKind::UnexpectedEof {
                                    expected: vec![")".to_string()],
                                },
                            ));
                        };

                        let span = Span {
                            start: lparen_tok.span.start,
                            end: rparen_tok.span.end,
                        };

                        let rparen_token_id = self.last_token_id();

                        let syntax_row = crate::syntax::SyntaxRowConstructor {
                            l_paren: lparen_token_id,
                            commas,
                            r_paren: rparen_token_id,
                            span,
                        };
                        let syntax_id = self.syntax_arena.alloc_row_constructor(syntax_row);

                        return Ok(AstExpr::RowConstructor {
                            syntax_id,
                            elements,
                            span,
                            node_id: self.id_gen.next(),
                        });
                    }
                }

                // Handle Jinja blocks that appear after the expression but before the closing paren
                // Pattern: (col = 1 {% if cond %}AND col2 = 2{% endif %})
                // We consume all tokens until we find the matching closing paren
                let final_expr = if let Some(tok) = self.peek() {
                    if matches!(tok.kind, TokenKind::JinjaStmtOpen) {
                        // Jinja block inside paren - consume until matching RParen
                        let mut paren_depth = 1; // We're inside one lparen already
                        let start_pos = inner_expr.span().start;
                        let mut end_pos = inner_expr.span().end;

                        while let Some(t) = self.peek() {
                            match &t.kind {
                                TokenKind::Punctuation(crate::lexer::Punctuation::LParen) => {
                                    paren_depth += 1;
                                    end_pos = t.span.end;
                                    self.advance();
                                }
                                TokenKind::Punctuation(crate::lexer::Punctuation::RParen) => {
                                    paren_depth -= 1;
                                    if paren_depth == 0 {
                                        // Found matching RParen, don't consume it
                                        break;
                                    }
                                    end_pos = t.span.end;
                                    self.advance();
                                }
                                TokenKind::Eof => break,
                                _ => {
                                    end_pos = t.span.end;
                                    self.advance();
                                }
                            }
                        }

                        // Create a placeholder that spans from inner_expr start to end of consumed content
                        AstExpr::JinjaPlaceholder {
                            kind: crate::ast::JinjaKind::Statement,
                            span: Span {
                                start: start_pos,
                                end: end_pos,
                            },
                            expr: None,
                            syntax_id: None,
                            node_id: self.id_gen.next(),
                        }
                    } else {
                        inner_expr
                    }
                } else {
                    inner_expr
                };

                // Expect ')'
                let rparen_tok = if let Some(next) = self.advance() {
                    if !matches!(
                        next.kind,
                        TokenKind::Punctuation(crate::lexer::Punctuation::RParen)
                    ) {
                        return Err(ParseError::unexpected_token(
                            next.span,
                            vec![")".to_string()],
                            Parser::token_description(next, self.source),
                        ));
                    }
                    next
                } else {
                    return Err(ParseError::new(
                        lparen_tok.span,
                        ParseErrorKind::UnexpectedEof {
                            expected: vec![")".to_string()],
                        },
                    ));
                };

                // Create a Parenthesized expression to preserve the parentheses
                let span = Span {
                    start: lparen_tok.span.start,
                    end: rparen_tok.span.end,
                };

                // Capture token IDs for syntax layer
                let rparen_token_id = self.last_token_id();

                let syntax_paren_expr = crate::syntax::SyntaxParenExpr {
                    l_paren: lparen_token_id,
                    inner_span: final_expr.span(),
                    r_paren: rparen_token_id,
                    span,
                };
                let syntax_id = self.syntax_arena.alloc_paren_expr(syntax_paren_expr);

                Ok(AstExpr::Parenthesized {
                    syntax_id,
                    expr: Box::new(final_expr),
                    span,
                    node_id: self.id_gen.next(),
                })
            }
            TokenKind::Punctuation(crate::lexer::Punctuation::LBracket) => {
                // Array literal: [expr, expr, ...]
                let lbracket_token_id = self.current_token_id();
                let lb = self.advance().expect_invariant("[ after peek");
                let mut elements: Vec<AstExpr> = Vec::new();
                loop {
                    let next = self.peek().ok_or_else(|| {
                        ParseError::unexpected_eof(self.current_span(), vec!["]".to_string()])
                    })?;
                    match &next.kind {
                        TokenKind::Punctuation(crate::lexer::Punctuation::RBracket) => {
                            let rbracket_token_id = self.current_token_id(); // Before advancing
                            let rb = self.advance().expect_invariant(
                                "RBracket token confirmed by peek for empty array",
                            );
                            let span = Span {
                                start: lb.span.start,
                                end: rb.span.end,
                            };

                            // Build and allocate syntax node
                            let syntax_array = crate::syntax::SyntaxArrayLiteral {
                                l_bracket: lbracket_token_id,
                                r_bracket: rbracket_token_id,
                                span,
                            };
                            let syntax_id = self.syntax_arena.alloc_array_literal(syntax_array);

                            return Ok(AstExpr::Array {
                                syntax_id,
                                elements,
                                span,
                                node_id: self.id_gen.next(),
                                has_array_keyword: false,
                                array_keyword_span: None,
                            });
                        }
                        _ => {
                            let elem = self.parse_expr()?;
                            elements.push(elem);
                            if let Some(sep) = self.peek() {
                                match sep.kind {
                                    TokenKind::Punctuation(crate::lexer::Punctuation::Comma) => {
                                        let _ = self.advance();
                                    }
                                    TokenKind::Punctuation(crate::lexer::Punctuation::RBracket) => {
                                        continue;
                                    }
                                    _ => {
                                        return Err(ParseError::unexpected_token(
                                            sep.span,
                                            vec![",".to_string(), "]".to_string()],
                                            Parser::token_description(sep, self.source),
                                        ));
                                    }
                                }
                            } else {
                                return Err(ParseError::new(
                                    lb.span,
                                    ParseErrorKind::UnexpectedEof {
                                        expected: vec![",".to_string(), "]".to_string()],
                                    },
                                ));
                            }
                        }
                    }
                }
            }
            TokenKind::Punctuation(crate::lexer::Punctuation::LCurly) => {
                // ODBC escape clause ({d '…'}, {fn …}, {interval …}) takes
                // precedence; probe miss falls through to the object literal
                // with the parser position untouched.
                if let Some(escape) = self.try_parse_odbc_expr_escape()? {
                    return Ok(escape);
                }
                // Object literal: {key: value, ...} or {} for empty object
                // Snowflake syntax equivalent to OBJECT_CONSTRUCT()
                let lcurly_token_id = self.current_token_id();
                let lb = self.advance().expect_invariant("{ after peek");
                let mut entries: Vec<(AstExpr, AstExpr)> = Vec::new();
                loop {
                    let next = self.peek().ok_or_else(|| {
                        ParseError::unexpected_eof(self.current_span(), vec!["}".to_string()])
                    })?;
                    match &next.kind {
                        TokenKind::Punctuation(crate::lexer::Punctuation::RCurly) => {
                            let rcurly_token_id = self.current_token_id();
                            let rb = self.advance().expect_invariant(
                                "RCurly token confirmed by peek for empty object",
                            );
                            let span = Span {
                                start: lb.span.start,
                                end: rb.span.end,
                            };

                            // Build and allocate syntax node
                            let syntax_obj = crate::syntax::SyntaxObjectLiteral {
                                l_curly: lcurly_token_id,
                                r_curly: rcurly_token_id,
                                span,
                            };
                            let syntax_id = self.syntax_arena.alloc_object_literal(syntax_obj);

                            return Ok(AstExpr::Object {
                                syntax_id,
                                entries,
                                span,
                                node_id: self.id_gen.next(),
                            });
                        }
                        _ => {
                            // Parse key (identifier or string literal)
                            // Use primary expression only to avoid consuming `:` as postfix operator
                            let key = self.parse_primary_expr_in_mode()?;

                            // Expect colon separator
                            let colon = self.advance().ok_or_else(|| {
                                ParseError::unexpected_eof(
                                    self.current_span(),
                                    vec![":".to_string()],
                                )
                            })?;
                            if !matches!(
                                colon.kind,
                                TokenKind::Punctuation(crate::lexer::Punctuation::Colon)
                            ) {
                                return Err(ParseError::unexpected_token(
                                    colon.span,
                                    vec![":".to_string()],
                                    Parser::token_description(colon, self.source),
                                ));
                            }

                            // Parse value (full expression allowed)
                            let value = self.parse_expr()?;
                            entries.push((key, value));

                            if let Some(sep) = self.peek() {
                                match sep.kind {
                                    TokenKind::Punctuation(crate::lexer::Punctuation::Comma) => {
                                        let _ = self.advance();
                                    }
                                    TokenKind::Punctuation(crate::lexer::Punctuation::RCurly) => {
                                        continue;
                                    }
                                    _ => {
                                        return Err(ParseError::unexpected_token(
                                            sep.span,
                                            vec![",".to_string(), "}".to_string()],
                                            Parser::token_description(sep, self.source),
                                        ));
                                    }
                                }
                            } else {
                                return Err(ParseError::new(
                                    lb.span,
                                    ParseErrorKind::UnexpectedEof {
                                        expected: vec![",".to_string(), "}".to_string()],
                                    },
                                ));
                            }
                        }
                    }
                }
            }
            // General keyword handling: keywords can be used as identifiers in many contexts
            // (table names, column names, aliases, etc.). This catch-all branch handles keywords
            // that don't have special expression syntax (like CAST, PRIOR, CASE above).
            // However, certain clause keywords should never be treated as identifiers in expressions.
            TokenKind::Keyword(kw) => {
                // Reject primary clause-introducing keywords that should never be identifiers in expressions
                match kw {
                    Keyword::Select
                    | Keyword::From
                    | Keyword::Where
                    | Keyword::Group
                    | Keyword::Order
                    | Keyword::Having
                    | Keyword::Limit
                    | Keyword::Union
                    | Keyword::Intersect
                    | Keyword::Except
                    | Keyword::Minus
                    | Keyword::With
                    | Keyword::Into
                    | Keyword::Values
                    | Keyword::Set
                    | Keyword::Delete
                    | Keyword::Update
                    | Keyword::Insert
                    | Keyword::Create
                    | Keyword::Merge
                    | Keyword::Call
                    | Keyword::Execute
                    | Keyword::Begin
                    | Keyword::Commit
                    | Keyword::Rollback
                    | Keyword::Declare
                    | Keyword::If
                    | Keyword::While
                    | Keyword::For
                    | Keyword::Loop
                    | Keyword::Repeat
                    | Keyword::Return
                    | Keyword::Open
                    | Keyword::Close
                    | Keyword::Fetch
                    | Keyword::When
                    | Keyword::Then
                    | Keyword::Else
                    | Keyword::End
                    | Keyword::Exception
                    | Keyword::By
                    | Keyword::Join => {
                        return Err(ParseError::invalid_expression(
                            self.current_span(),
                            "Unexpected clause keyword in expression".to_string(),
                        ));
                    }
                    _ => {}
                }

                let tok = self.advance().expect_invariant("keyword after peek");

                // Check for qualified identifier: keyword.col
                let mut qualifier: Option<AstObjectRef> = None;
                let mut name_span = tok.span;
                if let Some(dot_tok) = self.peek() {
                    let is_dot = match &dot_tok.kind {
                        TokenKind::Punctuation(crate::lexer::Punctuation::Dot) => true,
                        TokenKind::Literal(crate::lexer::LiteralKind::Number)
                            if dot_tok.lexeme(self.source) == "." =>
                        {
                            true
                        }
                        _ => false,
                    };
                    if is_dot {
                        let _ = self.advance(); // consume '.' token
                        if let Some(second) = self.advance() {
                            // Accept both identifiers and keywords as the second part
                            if self.can_be_identifier_token(second) {
                                qualifier = Some(AstObjectRef {
                                    node_id: self.id_gen.next(),
                                    span: tok.span,
                                    parts: None, // column qualifier; see AstObjectRef::parts
                                    identifier_arg: None,
                                });
                                name_span = second.span;
                            }
                        }
                    }
                }

                // Check if this looks like a function call: keyword(...)
                if qualifier.is_none() {
                    if let Some(lp) = self.peek() {
                        if matches!(
                            lp.kind,
                            TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
                        ) {
                            // Looks like a function call - parse it
                            let expr = self.parse_function_call_from_lparen(name_span, None)?;
                            return Ok(expr);
                        }
                    }
                }

                // Otherwise, treat as a column reference
                Ok(AstExpr::Ident {
                    node_id: self.id_gen.next(),
                    column_ref: crate::ast::AstColumnRef {
                        node_id: self.id_gen.next(),
                        qualifier,
                        name: AstIdentifier {
                            node_id: self.id_gen.next(),
                            span: name_span,
                        },
                    },
                })
            }
            _ => Err(ParseError::invalid_expression(
                self.current_span(),
                "Expected primary expression".to_string(),
            )),
        }
    }
}
