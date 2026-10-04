// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Table reference and JOIN parsing
//!
//! This module handles parsing of table references and JOIN operations:
//! - Table factors (table names, subqueries, table functions)
//! - JOIN operations (INNER, LEFT, RIGHT, FULL, CROSS)
//! - JOIN conditions (ON, USING)
//! - LATERAL joins
//! - Table aliases
//! - MATCH_CONDITION

use crate::ast::*;
use crate::cst::TokenId;
use crate::error::{ExpectInvariant, ParseError, ParseErrorKind, ParseResult, ParseResultExt};
use crate::lexer::{Keyword, Span, Token, TokenKind};
use crate::parser::core::Parser;
use crate::parser::select::InlineFragmentCollection;

/// Result of parsing an alias with optional column list for VALUES clause
struct ValuesAliasWithColumns {
    alias: Option<AstIdentifier>,
    as_token: Option<TokenId>,
    columns: Option<Vec<AstIdentifier>>,
    lparen_id: Option<TokenId>,
    rparen_id: Option<TokenId>,
}

/// Check if a lexeme matches a clause/join keyword that terminates table alias parsing.
/// This avoids allocating a String for case-insensitive comparison.
#[inline]
fn is_table_clause_keyword(lexeme: &str) -> bool {
    lexeme.eq_ignore_ascii_case("WHERE")
        || lexeme.eq_ignore_ascii_case("GROUP")
        || lexeme.eq_ignore_ascii_case("ORDER")
        || lexeme.eq_ignore_ascii_case("HAVING")
        || lexeme.eq_ignore_ascii_case("QUALIFY")
        || lexeme.eq_ignore_ascii_case("LIMIT")
        || lexeme.eq_ignore_ascii_case("OFFSET")
        || lexeme.eq_ignore_ascii_case("FOR")  // FOR UPDATE clause
        || lexeme.eq_ignore_ascii_case("UNION")
        || lexeme.eq_ignore_ascii_case("INTERSECT")
        || lexeme.eq_ignore_ascii_case("EXCEPT")
        || lexeme.eq_ignore_ascii_case("JOIN")
        || lexeme.eq_ignore_ascii_case("INNER")
        || lexeme.eq_ignore_ascii_case("LEFT")
        || lexeme.eq_ignore_ascii_case("RIGHT")
        || lexeme.eq_ignore_ascii_case("FULL")
        || lexeme.eq_ignore_ascii_case("CROSS")
        || lexeme.eq_ignore_ascii_case("NATURAL")
        || lexeme.eq_ignore_ascii_case("MATCH_RECOGNIZE")
        || lexeme.eq_ignore_ascii_case("PIVOT")
        || lexeme.eq_ignore_ascii_case("UNPIVOT")
}

/// Map a T-SQL simple-keyword table-hint lexeme to its typed
/// [`crate::ast::AstTableHintKind`] variant. Parser-layer text →
/// typed-AST conversion: every documented simple keyword has its
/// own variant; permissively-admitted unrecognized identifiers
/// land in [`crate::ast::AstTableHintKind::OtherSimple`] so the
/// AST surface stays closed-enum and downstream consumers do not
/// re-parse the hint name from source text.
#[inline]
fn classify_simple_table_hint_keyword(lexeme: &str) -> crate::ast::AstTableHintKind {
    use crate::ast::AstTableHintKind;
    if lexeme.eq_ignore_ascii_case("NOLOCK") {
        AstTableHintKind::NoLock
    } else if lexeme.eq_ignore_ascii_case("READUNCOMMITTED") {
        AstTableHintKind::ReadUncommitted
    } else if lexeme.eq_ignore_ascii_case("READCOMMITTED") {
        AstTableHintKind::ReadCommitted
    } else if lexeme.eq_ignore_ascii_case("READCOMMITTEDLOCK") {
        AstTableHintKind::ReadCommittedLock
    } else if lexeme.eq_ignore_ascii_case("REPEATABLEREAD") {
        AstTableHintKind::RepeatableRead
    } else if lexeme.eq_ignore_ascii_case("SERIALIZABLE") {
        AstTableHintKind::Serializable
    } else if lexeme.eq_ignore_ascii_case("SNAPSHOT") {
        AstTableHintKind::Snapshot
    } else if lexeme.eq_ignore_ascii_case("UPDLOCK") {
        AstTableHintKind::UpdLock
    } else if lexeme.eq_ignore_ascii_case("HOLDLOCK") {
        AstTableHintKind::HoldLock
    } else if lexeme.eq_ignore_ascii_case("ROWLOCK") {
        AstTableHintKind::RowLock
    } else if lexeme.eq_ignore_ascii_case("PAGLOCK") {
        AstTableHintKind::PagLock
    } else if lexeme.eq_ignore_ascii_case("TABLOCK") {
        AstTableHintKind::TabLock
    } else if lexeme.eq_ignore_ascii_case("TABLOCKX") {
        AstTableHintKind::TabLockX
    } else if lexeme.eq_ignore_ascii_case("XLOCK") {
        AstTableHintKind::XLock
    } else if lexeme.eq_ignore_ascii_case("READPAST") {
        AstTableHintKind::ReadPast
    } else if lexeme.eq_ignore_ascii_case("NOWAIT") {
        AstTableHintKind::NoWait
    } else if lexeme.eq_ignore_ascii_case("NOEXPAND") {
        AstTableHintKind::NoExpand
    } else if lexeme.eq_ignore_ascii_case("FORCESCAN") {
        AstTableHintKind::ForceScan
    } else if lexeme.eq_ignore_ascii_case("KEEPIDENTITY") {
        AstTableHintKind::KeepIdentity
    } else if lexeme.eq_ignore_ascii_case("KEEPDEFAULTS") {
        AstTableHintKind::KeepDefaults
    } else if lexeme.eq_ignore_ascii_case("IGNORE_CONSTRAINTS") {
        AstTableHintKind::IgnoreConstraints
    } else if lexeme.eq_ignore_ascii_case("IGNORE_TRIGGERS") {
        AstTableHintKind::IgnoreTriggers
    } else {
        AstTableHintKind::OtherSimple
    }
}

/// Check if a lexeme is a table-specific clause keyword (SAMPLE, AT, CHANGES, etc.)
#[inline]
fn is_table_specific_clause(lexeme: &str) -> bool {
    lexeme.eq_ignore_ascii_case("MATCH_RECOGNIZE")
        || lexeme.eq_ignore_ascii_case("SAMPLE")
        || lexeme.eq_ignore_ascii_case("TABLESAMPLE")
        || lexeme.eq_ignore_ascii_case("CHANGES")
        || lexeme.eq_ignore_ascii_case("PIVOT")
        || lexeme.eq_ignore_ascii_case("UNPIVOT")
        || lexeme.eq_ignore_ascii_case("AT")
        || lexeme.eq_ignore_ascii_case("BEFORE")
}

// Implementation methods will be added here via:
/// A second alias after PIVOT / UNPIVOT / MATCH_RECOGNIZE: the alias, its
/// `AS` token, the column list, and the list's parentheses.
type SecondAliasWithColumns = (
    Option<AstIdentifier>,
    Option<TokenId>,
    Option<Vec<AstIdentifier>>,
    Option<TokenId>,
    Option<TokenId>,
);

/// What precedes a JOIN keyword: the join kind, whether it is an APPLY, the
/// `DIRECTED`, `LATERAL` and `ASOF` keyword spans, and where the modifiers
/// start.
type JoinModifiers = (
    crate::ast::AstJoinKind,
    bool,
    Option<Span>,
    Option<Span>,
    Option<Span>,
    u32,
);

impl<'a> Parser<'a> {
    /// Parse Databricks/Spark-style lateral view generator syntax:
    /// LATERAL VIEW [OUTER] generator_fn(...) [table_alias] [AS col_alias[, ...]]
    fn parse_lateral_view_factor(
        &mut self,
        lateral_start: u32,
    ) -> ParseResult<Option<Box<AstTableRef>>> {
        let view_tok = self.peek().ok_or_else(|| {
            ParseError::new(
                self.current_span(),
                ParseErrorKind::InvalidSyntax {
                    message: "Expected VIEW after LATERAL".to_string(),
                },
            )
        })?;

        if !matches!(view_tok.kind, TokenKind::Keyword(Keyword::View)) {
            return Err(ParseError::new(
                view_tok.span,
                ParseErrorKind::InvalidSyntax {
                    message: "Expected VIEW after LATERAL".to_string(),
                },
            ));
        }
        self.advance(); // consume VIEW

        // Optional OUTER keyword
        if let Some(tok) = self.peek() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::Outer)) {
                self.advance(); // consume OUTER
            }
        }

        // Generator function call (e.g., explode(...), posexplode(...), inline(...))
        let table_func = self.parse_expr_with_recovery()?;
        let mut name_end = table_func.span().end;

        // Optional table alias (e.g., exploded)
        let (alias, as_token) = self
            .parse_simple_alias_with_as()
            .map(|(ident, as_tok)| (Some(ident), as_tok))
            .unwrap_or((None, None));
        if let Some(ref a) = alias {
            name_end = name_end.max(a.span.end);
        }

        // Optional result alias section (e.g., AS item)
        let (
            result_alias,
            second_as_token,
            result_alias_columns,
            result_alias_columns_lparen,
            result_alias_columns_rparen,
        ) = self.parse_optional_second_alias_with_columns();

        let time_travel = None;
        let sample = None;
        let changes = None;
        let pivot = None;
        let unpivot = None;
        let match_recognize = None;

        let name = AstObjectRef {
            node_id: self.id_gen.next(),
            span: Span {
                start: lateral_start,
                end: table_func.span().end,
            },
            // LATERAL VIEW <function>: not a dotted identifier; the
            // span covers `LATERAL <call>(...)`. Consumers must treat
            // this as opaque.
            parts: None,
            identifier_arg: None,
        };

        let complete_span = crate::parser::sql_stmt::calculate_table_ref_span(
            name.span,
            &alias,
            &None,
            &time_travel,
            &sample,
            &changes,
            &pivot,
            &unpivot,
            &match_recognize,
            &None, // table_hints (not applicable for stage paths)
        );

        let syntax_id = if alias.is_some() || result_alias.is_some() {
            let syntax_ref = crate::syntax::SyntaxTableRef {
                as_keyword: as_token,
                result_alias_as_keyword: second_as_token,
                subquery_lparen: None,
                subquery_rparen: None,
                alias_columns_lparen: None,
                alias_columns_rparen: None,
                result_alias_columns_lparen,
                result_alias_columns_rparen,
                span: complete_span,
            };
            Some(self.syntax_arena.alloc_table_ref(syntax_ref))
        } else {
            None
        };

        Ok(Some(Box::new(crate::parser::sql_stmt::build_table_ref(
            self.id_gen.next(),
            Span {
                start: complete_span.start,
                end: complete_span.end.max(name_end),
            },
            name,
            alias,
            None, // alias_columns
            result_alias,
            result_alias_columns,
            None, // subquery
            None, // subquery_lparen_span
            None, // subquery_rparen_span
            None, // values
            None, // lateral keyword span (already part of name span)
            time_travel,
            sample,
            changes,
            None, // stage_options
            Some(Box::new(table_func)),
            None, // with_offset
            pivot,
            unpivot,
            match_recognize,
            None, // table_hints
            syntax_id,
        ))))
    }

    /// Parse optional second alias with optional column list: [AS] alias [(col1, col2, ...)]
    /// Used after PIVOT/UNPIVOT clauses which can have column renames
    fn parse_optional_second_alias_with_columns(&mut self) -> SecondAliasWithColumns {
        let mut second_alias = None;
        let mut second_as_token = None;
        let mut alias_columns = None;
        let mut columns_lparen = None;
        let mut columns_rparen = None;

        if let Some(next_tok) = self.peek() {
            // Check for AS keyword
            if matches!(next_tok.kind, TokenKind::Keyword(Keyword::As)) {
                second_as_token = Some(self.current_token_id());
                self.advance(); // consume AS
            }

            // Check for identifier (after AS or standalone)
            if let Some(alias_tok) = self.peek() {
                if self.can_be_alias_token(alias_tok)
                    && !self.is_databricks_time_travel_ahead()
                    && !self.should_stop_scan_at_statement_start(alias_tok)
                {
                    let alias_lexeme = alias_tok.lexeme(self.source);
                    let is_clause_keyword = is_table_clause_keyword(alias_lexeme)
                        || self.dialect.is_clause_boundary_keyword(alias_lexeme);
                    let is_match_condition_call = alias_tok
                        .lexeme(self.source)
                        .eq_ignore_ascii_case("MATCH_CONDITION")
                        && self.peek_ahead(1).is_some_and(|tok| {
                            matches!(
                                tok.kind,
                                TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
                            )
                        });

                    if !is_clause_keyword && !is_match_condition_call {
                        let alias_tok = self.advance().expect_invariant("alias token");
                        second_alias = Some(AstIdentifier {
                            node_id: self.id_gen.next(),
                            span: alias_tok.span,
                        });

                        // Parse optional column list after alias: (col1, col2, ...)
                        // This is used for PIVOT ... AS p (col1, col2, col3, ...)
                        if let Some(lparen) = self.peek() {
                            if matches!(
                                lparen.kind,
                                TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
                            ) {
                                columns_lparen = Some(self.current_token_id());
                                self.advance(); // consume '('
                                let mut columns = Vec::new();

                                while let Some(col_tok) = self.peek() {
                                    if matches!(
                                        col_tok.kind,
                                        TokenKind::Punctuation(crate::lexer::Punctuation::RParen)
                                    ) {
                                        columns_rparen = Some(self.current_token_id());
                                        self.advance(); // consume ')' - end of list
                                        break;
                                    }
                                    if matches!(
                                        col_tok.kind,
                                        TokenKind::Punctuation(crate::lexer::Punctuation::Comma)
                                    ) {
                                        self.advance(); // consume ','
                                        continue;
                                    }
                                    if self.can_be_identifier_token(col_tok) {
                                        let col_tok =
                                            self.advance().expect_invariant("column token");
                                        columns.push(AstIdentifier {
                                            node_id: self.id_gen.next(),
                                            span: col_tok.span,
                                        });
                                    } else {
                                        break; // unexpected token
                                    }
                                }

                                if !columns.is_empty() {
                                    alias_columns = Some(columns);
                                }
                            }
                        }
                    }
                }
            }
        }

        (
            second_alias,
            second_as_token,
            alias_columns,
            columns_lparen,
            columns_rparen,
        )
    }

    /// Parse optional alias with column list for VALUES clause: AS t (col1, col2)
    fn parse_values_alias_with_columns(&mut self) -> ValuesAliasWithColumns {
        let mut alias = None;
        let mut as_token = None;
        let mut columns = None;
        let mut lparen_id = None;
        let mut rparen_id = None;

        // Check for AS keyword
        if let Some(tok) = self.peek() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::As)) {
                as_token = Some(self.current_token_id());
                self.advance(); // consume AS
            }
        }

        // Check for alias identifier
        if let Some(alias_tok) = self.peek() {
            if self.can_be_alias_token(alias_tok)
                && !self.is_databricks_time_travel_ahead()
                && !self.should_stop_scan_at_statement_start(alias_tok)
            {
                let is_clause_keyword = is_table_clause_keyword(alias_tok.lexeme(self.source));
                if !is_clause_keyword {
                    let alias_tok = self.advance().expect_invariant("alias token");
                    alias = Some(AstIdentifier {
                        node_id: self.id_gen.next(),
                        span: alias_tok.span,
                    });

                    // Parse optional column list: (col1, col2, ...)
                    if let Some(lparen) = self.peek() {
                        if matches!(
                            lparen.kind,
                            TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
                        ) {
                            self.advance(); // consume '('
                            lparen_id = Some(self.last_token_id());
                            let mut col_list = Vec::new();

                            while let Some(col_tok) = self.peek() {
                                if matches!(
                                    col_tok.kind,
                                    TokenKind::Punctuation(crate::lexer::Punctuation::RParen)
                                ) {
                                    self.advance(); // consume ')'
                                    rparen_id = Some(self.last_token_id());
                                    break;
                                }
                                if matches!(
                                    col_tok.kind,
                                    TokenKind::Punctuation(crate::lexer::Punctuation::Comma)
                                ) {
                                    self.advance(); // consume ','
                                    continue;
                                }
                                if self.can_be_identifier_token(col_tok) {
                                    let col_tok = self.advance().expect_invariant("column token");
                                    col_list.push(AstIdentifier {
                                        node_id: self.id_gen.next(),
                                        span: col_tok.span,
                                    });
                                } else {
                                    break; // unexpected token
                                }
                            }

                            if !col_list.is_empty() {
                                columns = Some(col_list);
                            }
                        }
                    }
                }
            }
        }

        ValuesAliasWithColumns {
            alias,
            as_token,
            columns,
            lparen_id,
            rparen_id,
        }
    }

    /// Check if a keyword at current position starts a join construct or clause.
    /// Uses lookahead to distinguish "LEFT JOIN" from "AS left".
    /// Safely peek ahead N tokens from current position
    /// Returns None if position is out of bounds
    #[inline]
    pub(crate) fn peek_ahead(&self, n: usize) -> Option<&Token> {
        let pos = self.idx.checked_add(n)?;
        self.tokens.get(pos)
    }

    /// Check if the current position has a Databricks time travel pattern:
    ///   TIMESTAMP AS OF ... | VERSION AS OF ...
    /// Used to prevent alias parsing from consuming VERSION/TIMESTAMP.
    fn is_databricks_time_travel_ahead(&self) -> bool {
        let tok = match self.peek() {
            Some(t) => t,
            None => return false,
        };
        // First token must be Identifier with lexeme TIMESTAMP or VERSION
        let lexeme = tok.lexeme(self.source);
        if !lexeme.eq_ignore_ascii_case("TIMESTAMP") && !lexeme.eq_ignore_ascii_case("VERSION") {
            return false;
        }
        // Second token must be AS
        if let Some(as_tok) = self.peek_ahead(1) {
            if !matches!(as_tok.kind, TokenKind::Keyword(Keyword::As)) {
                return false;
            }
        } else {
            return false;
        }
        // Third token must be OF
        if let Some(of_tok) = self.peek_ahead(2) {
            matches!(of_tok.kind, TokenKind::Keyword(Keyword::Of))
        } else {
            false
        }
    }

    /// Check if a keyword at current position starts a join or clause pattern
    /// Returns true if the keyword cannot be used as an identifier in this context
    fn is_join_or_clause_keyword(&self) -> bool {
        let tok = match self.peek() {
            Some(t) => t,
            None => return false,
        };

        let kw = match &tok.kind {
            TokenKind::Keyword(k) => k,
            _ => return false,
        };

        // Definite clause keywords - always introduce clauses
        match kw {
            Keyword::Where
            | Keyword::Group
            | Keyword::Order
            | Keyword::Having
            | Keyword::Qualify
            | Keyword::Limit
            | Keyword::Offset
            | Keyword::For  // FOR UPDATE clause
            | Keyword::Union
            | Keyword::Intersect
            | Keyword::Except
            | Keyword::Minus
            | Keyword::Fetch
            | Keyword::Set
            | Keyword::MatchRecognize => return true,
            _ => {}
        }

        // Join constraint keywords - always part of join syntax
        match kw {
            Keyword::Join | Keyword::On | Keyword::Using => return true,
            _ => {}
        }

        // Keywords that require lookahead to determine context
        match kw {
            Keyword::Directed => {
                // DIRECTED JOIN vs AS directed
                self.peek_ahead(1)
                    .map(|t| matches!(t.kind, TokenKind::Keyword(Keyword::Join)))
                    .unwrap_or(false)
            }

            Keyword::Connect => {
                // CONNECT BY vs AS connect
                self.peek_ahead(1)
                    .map(|t| matches!(t.kind, TokenKind::Keyword(Keyword::By)))
                    .unwrap_or(false)
            }

            Keyword::Start => {
                // START WITH vs AS start
                self.peek_ahead(1)
                    .map(|t| matches!(t.kind, TokenKind::Keyword(Keyword::With)))
                    .unwrap_or(false)
            }

            // Join type keywords that may be followed by OUTER/DIRECTED/JOIN
            Keyword::Inner
            | Keyword::Left
            | Keyword::Right
            | Keyword::Full
            | Keyword::Cross
            | Keyword::Outer => self.lookahead_join_pattern(),

            // ASOF is a standalone join type, cannot be combined with LEFT/RIGHT/FULL
            Keyword::Asof => self
                .peek_ahead(1)
                .map(|t| matches!(t.kind, TokenKind::Keyword(Keyword::Join)))
                .unwrap_or(false),

            Keyword::Natural => self.lookahead_natural_join_pattern(),

            _ => false,
        }
    }

    /// Check if current position starts a join pattern like "LEFT JOIN", "LEFT OUTER JOIN", or "LEFT DIRECTED JOIN"
    /// Assumes current token is a join type keyword (INNER, LEFT, RIGHT, FULL, CROSS)
    fn lookahead_join_pattern(&self) -> bool {
        let first = match self.peek() {
            Some(t) => t,
            None => return false,
        };

        let next = match self.peek_ahead(1) {
            Some(t) => t,
            None => return false,
        };

        // T-SQL APPLY: {CROSS|OUTER} APPLY
        if matches!(next.kind, TokenKind::Identifier { .. })
            && next.lexeme(self.source).eq_ignore_ascii_case("APPLY")
        {
            return matches!(
                first.kind,
                TokenKind::Keyword(Keyword::Cross | Keyword::Outer)
            );
        }

        match &next.kind {
            // Direct patterns: LEFT JOIN, INNER JOIN, etc.
            TokenKind::Keyword(Keyword::Join) => true,

            // LEFT DIRECTED JOIN
            TokenKind::Keyword(Keyword::Directed) => self
                .peek_ahead(2)
                .map(|t| matches!(t.kind, TokenKind::Keyword(Keyword::Join)))
                .unwrap_or(false),

            // LEFT OUTER JOIN
            TokenKind::Keyword(Keyword::Outer) => self
                .peek_ahead(2)
                .map(|t| matches!(t.kind, TokenKind::Keyword(Keyword::Join)))
                .unwrap_or(false),

            _ => false,
        }
    }

    /// Check if current NATURAL keyword starts a join pattern
    /// Handles: NATURAL JOIN, NATURAL INNER/CROSS JOIN, NATURAL LEFT/RIGHT/FULL [OUTER/ASOF] JOIN
    fn lookahead_natural_join_pattern(&self) -> bool {
        let next = match self.peek_ahead(1) {
            Some(t) => t,
            None => return false,
        };

        match &next.kind {
            // NATURAL JOIN
            TokenKind::Keyword(Keyword::Join) => true,

            // NATURAL INNER JOIN, NATURAL CROSS JOIN
            TokenKind::Keyword(Keyword::Inner | Keyword::Cross) => self
                .peek_ahead(2)
                .map(|t| matches!(t.kind, TokenKind::Keyword(Keyword::Join)))
                .unwrap_or(false),

            // NATURAL LEFT/RIGHT/FULL [OUTER/ASOF] JOIN
            TokenKind::Keyword(Keyword::Left | Keyword::Right | Keyword::Full) => {
                let tok_2 = match self.peek_ahead(2) {
                    Some(t) => t,
                    None => return false,
                };

                match &tok_2.kind {
                    // NATURAL LEFT JOIN
                    TokenKind::Keyword(Keyword::Join) => true,

                    // NATURAL LEFT OUTER JOIN
                    TokenKind::Keyword(Keyword::Outer) => self
                        .peek_ahead(3)
                        .map(|t| matches!(t.kind, TokenKind::Keyword(Keyword::Join)))
                        .unwrap_or(false),

                    _ => false,
                }
            }

            _ => false,
        }
    }

    /// Parse LATERAL table function: LATERAL function_name(...)
    /// This is used for table functions like FLATTEN that don't use TABLE(...) wrapper
    fn parse_lateral_table_function(
        &mut self,
        start_pos: u32,
        lateral_keyword_span: Option<Span>,
    ) -> Option<Box<AstTableRef>> {
        // Parse the function call expression with error recovery
        let func_expr = self.parse_expr_with_recovery().ok()?;
        let func_end = func_expr.span().end;

        // Name span covers the call expression itself.
        let name = AstObjectRef {
            node_id: self.id_gen.next(),
            span: Span {
                start: start_pos,
                end: func_end,
            },
            // Table-valued function call (UNNEST/FLATTEN/ML.PREDICT/
            // GENERATE_SERIES/...): the name is the call expression,
            // not a dotted identifier.
            parts: None,
            identifier_arg: None,
        };

        self.finish_table_function_parse(
            start_pos,
            name,
            Some(Box::new(func_expr)),
            lateral_keyword_span,
        )
        .ok()
        .flatten()
    }

    /// Finish parsing a table-valued function reference once the
    /// inner call expression and the canonical `name` span have been
    /// determined. Handles every trailing construct shared by the
    /// two TVF entry points — `LATERAL fn(...)` and `TABLE(fn(...))`
    /// — namely:
    ///
    /// - optional T-SQL TVF schema clause (`OPENJSON(...) WITH (...)`)
    /// - optional alias and alias-with-columns (BigQuery
    ///   `UNNEST(arr) AS u(val)`)
    /// - optional `WITH OFFSET [AS alias]` (BigQuery)
    /// - optional `SAMPLE` clause
    /// - optional `PIVOT` / `UNPIVOT` (mutually exclusive)
    /// - optional `MATCH_RECOGNIZE`
    /// - composite span calculation
    /// - `SyntaxTableRef` allocation when an alias is present
    /// - final `AstTableRef` construction with `tvf_schema_span`
    ///
    /// Both entry points must funnel through here so the wrapper
    /// grammar stays in lockstep — see commit history for the
    /// regression that bit `FROM TABLE(f()) PIVOT(...)`.
    fn finish_table_function_parse(
        &mut self,
        start_pos: u32,
        name: AstObjectRef,
        func_expr_opt: Option<Box<AstExpr>>,
        lateral_keyword_span: Option<Span>,
    ) -> ParseResult<Option<Box<AstTableRef>>> {
        let name_span_end = name.span.end;

        // Parse optional TVF schema clause: OPENJSON(...) WITH (colName type [path], ...)
        let tvf_schema_span = self.try_parse_tvf_with_clause();

        // Parse optional alias with AS token tracking
        let (alias, as_token) = self
            .parse_simple_alias_with_as()
            .map(|(alias, as_tok)| (Some(alias), as_tok))
            .unwrap_or((None, None));

        // Parse optional column list after alias: AS u(col1, col2, ...)
        // Used in BigQuery: UNNEST(arr) AS u(val)
        let mut alias_columns: Option<Vec<AstIdentifier>> = None;
        let mut alias_columns_lparen: Option<TokenId> = None;
        let mut alias_columns_rparen: Option<TokenId> = None;
        let mut alias_columns_end: Option<u32> = None;
        if alias.is_some() {
            if let Some(lparen) = self.peek() {
                if matches!(
                    lparen.kind,
                    TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
                ) {
                    alias_columns_lparen = Some(self.current_token_id());
                    self.advance(); // consume '('
                    let mut columns = Vec::new();

                    while let Some(col_tok) = self.peek() {
                        if matches!(
                            col_tok.kind,
                            TokenKind::Punctuation(crate::lexer::Punctuation::RParen)
                        ) {
                            alias_columns_rparen = Some(self.current_token_id());
                            let rparen_tok = self.advance().expect_invariant("RParen after peek"); // consume ')'
                            alias_columns_end = Some(rparen_tok.span.end);
                            break;
                        }
                        if matches!(
                            col_tok.kind,
                            TokenKind::Punctuation(crate::lexer::Punctuation::Comma)
                        ) {
                            self.advance(); // consume ','
                            continue;
                        }
                        if self.can_be_identifier_token(col_tok) {
                            let col_tok = self.advance().expect_invariant("column token");
                            columns.push(AstIdentifier {
                                node_id: self.id_gen.next(),
                                span: col_tok.span,
                            });
                        } else {
                            break; // unexpected token
                        }
                    }

                    if !columns.is_empty() {
                        alias_columns = Some(columns);
                    }
                }
            }
        }

        // Parse optional WITH OFFSET [AS alias] (BigQuery UNNEST modifier)
        let with_offset = self.parse_with_offset_clause();

        // Parse optional CHANGES clause (Snowflake: CHANGES(INFORMATION => ...) AT(...))
        let changes = self.parse_changes_clause()?.map(Box::new);

        // Parse optional time-travel clause (Snowflake AT/BEFORE, BigQuery FOR SYSTEM_TIME AS OF).
        // Mutually exclusive with CHANGES (CHANGES carries its own AT sub-clause).
        let time_travel = if changes.is_none() {
            self.parse_time_travel_clause()?
        } else {
            None
        };

        // Parse optional SAMPLE clause
        let sample = self.parse_sample_clause()?;

        // Parse optional PIVOT or UNPIVOT clause (mutually exclusive)
        // and MATCH_RECOGNIZE — same wrapper grammar as the standard
        // table-ref path. Without these the outer parse-script
        // dispatcher sees `PIVOT` / `UNPIVOT` / `MATCH_RECOGNIZE` as
        // the start of a new statement and falls back to OpaqueContent.
        let pivot = self.parse_pivot_clause()?;
        let unpivot = if pivot.is_none() {
            self.parse_unpivot_clause()?
        } else {
            None
        };
        let match_recognize = self.parse_match_recognize().ok().flatten();

        // Calculate complete span including function, alias, columns,
        // WITH OFFSET, TVF schema, changes, time_travel, sample, pivot/unpivot, MATCH_RECOGNIZE.
        let complete_end = match_recognize
            .as_ref()
            .map(|m| m.span.end)
            .or_else(|| unpivot.as_ref().map(|u| u.span.end))
            .or_else(|| pivot.as_ref().map(|p| p.span.end))
            .or_else(|| sample.as_ref().map(|s| s.span.end))
            .or_else(|| {
                time_travel.as_deref().map(|tt| match tt {
                    crate::ast::AstTimeTravelClause::SnowflakeAtBefore(at) => at.span.end,
                    crate::ast::AstTimeTravelClause::ForSystemTime(fst) => fst.span.end,
                    crate::ast::AstTimeTravelClause::DatabricksAsOf(dbx) => dbx.span.end,
                })
            })
            .or_else(|| changes.as_deref().map(|c| c.span.end))
            .or_else(|| with_offset.as_ref().map(|wo| wo.span.end))
            .or(alias_columns_end)
            .or_else(|| alias.as_ref().map(|a| a.span.end))
            .or_else(|| tvf_schema_span.map(|s| s.end))
            .unwrap_or(name_span_end);
        let complete_span = Span {
            start: start_pos,
            end: complete_end,
        };

        // Create SyntaxTableRef if we have an alias
        let syntax_id = if let Some(ref alias_ident) = alias {
            let syntax_ref = crate::syntax::SyntaxTableRef {
                as_keyword: as_token,
                result_alias_as_keyword: None,
                subquery_lparen: None,
                subquery_rparen: None,
                alias_columns_lparen,
                alias_columns_rparen,
                result_alias_columns_lparen: None,
                result_alias_columns_rparen: None,
                span: alias_ident.span, // Use alias span for now
            };
            Some(self.syntax_arena.alloc_table_ref(syntax_ref))
        } else {
            None
        };

        let mut table_ref = crate::parser::sql_stmt::build_table_ref(
            self.id_gen.next(),
            complete_span,
            name,
            alias,
            alias_columns,
            None, // result_alias
            None, // result_alias_columns
            None, // subquery
            None, // subquery_lparen_span
            None, // subquery_rparen_span
            None, // values
            lateral_keyword_span,
            time_travel,
            sample.map(Box::new),
            changes,
            None, // stage_options
            func_expr_opt,
            with_offset.map(Box::new),
            pivot.map(Box::new),
            unpivot.map(Box::new),
            match_recognize.map(Box::new),
            None, // table_hints
            syntax_id,
        );
        table_ref.tvf_schema_span = tvf_schema_span;
        Ok(Some(Box::new(table_ref)))
    }

    /// Parse simple alias with AS token tracking: [AS] identifier
    /// Returns (alias, as_token) where as_token is Some(TokenId) if AS keyword was present
    /// Used by table functions and TABLE(...) syntax
    fn parse_simple_alias_with_as(&mut self) -> Option<(AstIdentifier, Option<TokenId>)> {
        if let Some(next_tok) = self.peek() {
            match &next_tok.kind {
                TokenKind::Keyword(Keyword::As) => {
                    if let Some(alias_tok) = self.peek_ahead(1) {
                        if self.can_be_alias_token(alias_tok) {
                            let as_token_id = self.current_token_id();
                            self.advance()?; // consume AS
                            let alias_tok = self.advance()?;
                            return Some((
                                AstIdentifier {
                                    node_id: self.id_gen.next(),
                                    span: alias_tok.span,
                                },
                                Some(as_token_id),
                            ));
                        }
                    }
                }
                TokenKind::Identifier { .. } => {
                    if self.should_stop_scan_at_statement_start(next_tok) {
                        return None;
                    }

                    // Check if this identifier is a clause boundary keyword (e.g. WINDOW in PG)
                    let lexeme = next_tok.lexeme(self.source);
                    if is_table_clause_keyword(lexeme)
                        || is_table_specific_clause(lexeme)
                        || self.dialect.is_clause_boundary_keyword(lexeme)
                    {
                        return None;
                    }
                    // Databricks: don't consume VERSION/TIMESTAMP as alias if followed by AS OF
                    if self.is_databricks_time_travel_ahead() {
                        return None;
                    }
                    let alias_tok = self.advance()?;
                    return Some((
                        AstIdentifier {
                            node_id: self.id_gen.next(),
                            span: alias_tok.span,
                        },
                        None, // No AS keyword
                    ));
                }
                _ => {}
            }
        }
        None
    }

    /// Parse optional TVF schema clause: `WITH (colName type [path] [AS JSON], ...)`.
    /// Used by OPENJSON, OPENXML, OPENROWSET and similar T-SQL table-valued functions.
    /// Returns the span covering `WITH (...)` if found, None otherwise.
    fn try_parse_tvf_with_clause(&mut self) -> Option<Span> {
        // Must see WITH followed by ( (not WITH OFFSET, not WITH identifier)
        let tok = self.peek()?;
        if !matches!(tok.kind, TokenKind::Keyword(Keyword::With)) {
            return None;
        }
        let next = self.peek_ahead(1)?;
        if !matches!(
            next.kind,
            TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
        ) {
            return None;
        }

        // Consume WITH
        let with_tok = self.advance()?;
        let start = with_tok.span.start;

        // Consume balanced (...)
        let _lparen = self.advance()?; // consume (
        let mut depth: u32 = 1;
        let mut end = _lparen.span.end;

        while depth > 0 {
            let tok = self.advance()?;
            match tok.kind {
                TokenKind::Punctuation(crate::lexer::Punctuation::LParen) => depth += 1,
                TokenKind::Punctuation(crate::lexer::Punctuation::RParen) => {
                    depth -= 1;
                    if depth == 0 {
                        end = tok.span.end;
                    }
                }
                TokenKind::Eof => return None,
                _ => {}
            }
        }

        Some(Span { start, end })
    }

    /// Parse optional WITH OFFSET [AS alias] clause (BigQuery UNNEST modifier).
    /// Returns Some(AstWithOffset) if WITH OFFSET is found, None otherwise.
    fn parse_with_offset_clause(&mut self) -> Option<crate::ast::AstWithOffset> {
        // Check for WITH followed by OFFSET
        let tok = self.peek()?;
        if !matches!(tok.kind, TokenKind::Keyword(Keyword::With)) {
            return None;
        }
        // Peek ahead to confirm the next token is OFFSET
        let next = self.peek_ahead(1)?;
        if !matches!(next.kind, TokenKind::Keyword(Keyword::Offset)) {
            return None;
        }

        // Consume WITH
        let with_tok = self.advance()?;
        let start = with_tok.span.start;
        let with_span = with_tok.span;

        // Consume OFFSET
        let offset_tok = self.advance()?;
        let offset_span = offset_tok.span;
        let mut end = offset_tok.span.end;

        // Parse optional alias: [AS] identifier
        let (alias, as_span) =
            if let Some((alias_ident, as_token_id)) = self.parse_simple_alias_with_as() {
                end = alias_ident.span.end;
                let as_sp = as_token_id.map(|tid| self.tokens[tid.0 as usize].span);
                (Some(alias_ident), as_sp)
            } else {
                (None, None)
            };

        Some(crate::ast::AstWithOffset {
            span: Span { start, end },
            with_span,
            offset_span,
            as_span,
            alias,
        })
    }

    pub(crate) fn parse_table_factor(
        &mut self,
        select_span: Span,
    ) -> ParseResult<Option<Box<AstTableRef>>> {
        // Guard against excessive recursion (prevents stack overflow)
        let _depth = self.track_depth("table reference")?;

        // Check for optional ONLY keyword (PostgreSQL: exclude child tables in inheritance)
        // We check it here so we can set it on whatever table ref is returned.
        let only_span: Option<Span> = self
            .peek()
            .filter(|tok| matches!(tok.kind, TokenKind::Keyword(Keyword::Only)))
            .map(|_| {
                let tok = self.advance().expect_invariant("ONLY confirmed by peek"); // consume ONLY
                tok.span
            });

        let result = self.parse_table_factor_impl(select_span);

        let mut result = result?;

        // Apply ONLY span to the returned table ref
        if let Some(ospan) = only_span {
            if let Some(ref mut tref) = result {
                tref.only_span = Some(ospan);
            }
        }

        Ok(result)
    }

    /// True when the parser is at an ODBC outer-join escape opener: `{`
    /// followed by the unquoted `oj` introducer.
    fn is_odbc_oj_at(&self) -> bool {
        let Some(next) = self.peek_ahead(1) else {
            return false;
        };
        matches!(
            next.kind,
            TokenKind::Identifier {
                kind: crate::lexer::IdentifierKind::Unquoted
            }
        ) && next.lexeme(self.source).eq_ignore_ascii_case("oj")
    }

    /// Parse the body of an ODBC `{oj …}` escape after `{` and `oj` are
    /// consumed: a table factor plus its join chain, closed by `}`. Mirrors
    /// the parenthesised joined-table path with braces as the delimiters.
    fn parse_odbc_oj_body(
        &mut self,
        lcurly_span: Span,
        oj_span: Span,
    ) -> ParseResult<Option<Box<AstTableRef>>> {
        let inner_factor = self.parse_table_factor(lcurly_span)?;
        let Some(mut inner) = inner_factor else {
            return Err(ParseError::new(
                lcurly_span,
                ParseErrorKind::InvalidSyntax {
                    message: "Expected a table reference inside ODBC {oj ...} escape".to_string(),
                },
            ));
        };
        self.parse_join_chain(&mut inner)?;
        let inner_join_count = inner.joins.len() as u16;
        let rcurly_span = self.expect_odbc_rcurly()?;
        inner.paren_group = Some(Box::new(crate::ast::ParenGroupInfo {
            lparen_span: lcurly_span,
            rparen_span: rcurly_span,
            inner_join_count,
            odbc_oj_span: Some(oj_span),
        }));
        inner.span.start = lcurly_span.start;
        inner.span.end = rcurly_span.end;
        Ok(Some(inner))
    }

    /// Helper: parse a table name from an already-consumed token
    /// Used when we've determined a keyword (like TABLE) should be treated as a table name
    fn parse_table_name_from_token(
        &mut self,
        ident_tok: Token,
        lateral_keyword_span: Option<Span>,
        _select_span: Span,
    ) -> Option<Box<AstTableRef>> {
        // This is the same logic as the generic table-name identifier path
        // We've already consumed ident_tok, so start from there
        let mut end_span = ident_tok.span.end;
        let identifier_arg: Option<Box<AstExpr>> = None;
        // Per-identifier-token spans for the structurally dotted name.
        // Each entry is one identifier token's exact span — by
        // construction trivia-free (the lexer emits comments and
        // whitespace as their own tokens, never folded into an
        // identifier token). Downstream consumers that need to
        // decompose `db.schema.table` MUST iterate this instead of
        // byte-slicing `name.span` and splitting on `.`, because the
        // merged span necessarily covers any trivia between parts.
        let mut parts: Vec<Option<Span>> = vec![Some(ident_tok.span)];

        // Handle qualified identifiers: db.schema.table or schema.table.
        // T-SQL allows omitted components (`master..tbl`): a dot
        // immediately followed by another dot is an empty slot, recorded
        // as `None` so the positional db/schema/name decomposition stays
        // correct downstream.
        while let Some(dot_tok) = self.peek() {
            if matches!(
                dot_tok.kind,
                TokenKind::Punctuation(crate::lexer::Punctuation::Dot)
            ) {
                let dot_end = dot_tok.span.end;
                self.advance(); // consume dot
                                // Next should be identifier or keyword - after dot, ANY keyword is allowed
                if let Some(next_tok) = self.peek() {
                    if self.can_be_identifier_after_dot_token(next_tok) {
                        let next = self.advance()?;
                        end_span = next.span.end;
                        parts.push(Some(next.span));
                    } else if matches!(
                        next_tok.kind,
                        TokenKind::Punctuation(crate::lexer::Punctuation::Dot)
                    ) {
                        // Omitted component (`a..b`): empty slot, the next
                        // loop iteration consumes the following dot.
                        end_span = dot_end;
                        parts.push(None);
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

        // Create object ref from the parsed name
        let name = AstObjectRef {
            node_id: self.id_gen.next(),
            span: Span {
                start: ident_tok.span.start,
                end: end_span,
            },
            parts: Some(parts),
            identifier_arg,
        };

        // Parse optional alias
        let (alias, _as_token) = if let Some((ident, tok)) = self.parse_simple_alias_with_as() {
            (Some(ident), tok)
        } else {
            (None, None)
        };

        // Parse optional time travel (dialect-gated: Snowflake AT/BEFORE or BigQuery FOR SYSTEM_TIME AS OF)
        let time_travel = self.parse_time_travel_clause().ok().flatten();

        // Parse optional sample
        let sample = self.parse_sample_clause().ok().flatten();

        // Build the table ref
        Some(Box::new(crate::parser::sql_stmt::build_table_ref(
            self.id_gen.next(),
            name.span,
            name,
            alias,
            None, // alias_columns
            None, // result_alias
            None, // result_alias_columns
            None, // subquery
            None, // subquery_lparen_span
            None, // subquery_rparen_span
            None, // values
            lateral_keyword_span,
            time_travel,
            sample.map(Box::new),
            None, // changes
            None, // stage_options
            None, // table_function
            None, // with_offset
            None, // pivot
            None, // unpivot
            None, // match_recognize
            None, // table_hints
            None, // syntax_id
        )))
    }

    fn parse_table_factor_impl(
        &mut self,
        select_span: Span,
    ) -> ParseResult<Option<Box<AstTableRef>>> {
        // Check for optional LATERAL keyword
        let mut lateral_start = None;
        let lateral_keyword_span = self
            .peek()
            .filter(|tok| matches!(tok.kind, TokenKind::Keyword(Keyword::Lateral)))
            .map(|tok| {
                lateral_start = Some(tok.span.start);
                self.advance()
                    .expect_invariant("LATERAL keyword should be available after peek")
                    .span
            });
        let lateral = lateral_keyword_span.is_some();

        // Databricks/Spark: LATERAL VIEW [OUTER] explode(...)
        if lateral {
            if let Some(tok) = self.peek() {
                if matches!(tok.kind, TokenKind::Keyword(Keyword::View)) {
                    return self.parse_lateral_view_factor(lateral_start.unwrap_or(tok.span.start));
                }
            }
        }

        // Note: ONLY keyword is parsed in parse_table_factor() wrapper and applied after return

        // Special case: LATERAL function_name(...) where function is not wrapped in TABLE()
        // Example: LATERAL FLATTEN(...) vs LATERAL TABLE(FLATTEN(...))
        if lateral {
            // Peek at next two tokens to detect function call pattern
            let first = self.peek();
            let second = first.and_then(|_| self.peek_ahead(1));

            // Pattern: (identifier | keyword but not TABLE) followed by '('
            if let (Some(tok), Some(next)) = (first, second) {
                // Check if it's TABLE keyword - if so, fall through to TABLE(...) handling below
                let is_table_keyword = matches!(tok.kind, TokenKind::Keyword(Keyword::Table));

                if !is_table_keyword {
                    let is_callable = self.can_be_identifier_token(tok);
                    let has_lparen = matches!(
                        next.kind,
                        TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
                    );

                    if is_callable && has_lparen {
                        let start_pos = tok.span.start;
                        return Ok(
                            self.parse_lateral_table_function(start_pos, lateral_keyword_span)
                        );
                    }
                }
            }
        }

        // Check for Jinja control block at start of table reference
        // Example: FROM {% if prod %}production{% else %}development{% endif %}.orders
        let peek_kind = self.peek_jinja_block_kind();
        if let Some(kind) = peek_kind {
            if matches!(
                kind,
                crate::ast::JinjaBlockKind::If | crate::ast::JinjaBlockKind::For
            ) {
                // Parse table name as Jinja conditional expression wrapped in an AstObjectRef
                let result = self.parse_jinja_wrapped_table_reference(select_span, lateral)?;
                return Ok(result.map(Box::new));
            }
        }

        let tok = match self.peek() {
            Some(t) => t,
            None => return Ok(None),
        };
        match &tok.kind {
            // ODBC outer-join escape: `{oj t1 LEFT OUTER JOIN t2 ON …}` — the
            // standard parenthesised joined-table with braces + introducer.
            // Parsed permissively (any join chain); recorded on ParenGroupInfo
            // for verbatim brace re-emission.
            TokenKind::Punctuation(crate::lexer::Punctuation::LCurly) if self.is_odbc_oj_at() => {
                let lcurly_tok = self.advance().expect_invariant("LCurly confirmed by peek");
                let lcurly_span = lcurly_tok.span;
                let oj_tok = self
                    .advance()
                    .expect_invariant("oj introducer confirmed by guard");
                let oj_span = oj_tok.span;
                self.odbc_depth += 1;
                let result = self.parse_odbc_oj_body(lcurly_span, oj_span);
                self.odbc_depth -= 1;
                result
            }
            // TABLE(function_call) for UDTFs
            TokenKind::Keyword(Keyword::Table) => {
                // Check if TABLE is followed by '(' - if so, it's a table function
                // If not, treat it as a regular table name (fall through to identifier case)
                let next = self.peek_ahead(1);
                let has_lparen = next.is_some_and(|t| {
                    matches!(
                        t.kind,
                        TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
                    )
                });

                if !has_lparen {
                    // TABLE without '(' - treat as regular table name
                    // Let it fall through to the generic identifier table-name path below
                    // by not consuming and proceeding to the next match arm
                    // Since we can't actually fall through in Rust, we need to duplicate the logic
                    // or restructure. For now, just consume and process as identifier
                    let ident_tok = self.advance().expect_invariant("just peeked TABLE");
                    // Continue with the identifier logic from line 947...
                    // Rather than duplicate 100+ lines, just set end_span and continue below
                    return Ok(self.parse_table_name_from_token(
                        ident_tok.clone(),
                        lateral_keyword_span,
                        select_span,
                    ));
                }

                // TABLE(...) - parse as table function
                let table_tok = self.advance().expect_invariant("just peeked TABLE");
                let start_span = table_tok.span.start;

                // Expect '('
                let lp = self
                    .peek()
                    .ok_or_eof(self.current_span(), vec!["(".to_string()])?;
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
                self.advance(); // consume '('

                // Save the position to try parsing as expression
                let saved_idx = self.idx;

                // Try to parse as a function call expression
                let func_expr = self.parse_expr().ok();

                // Check if we successfully parsed and reached the closing paren
                let parsed_ok = if let Some(ref _expr) = func_expr {
                    if let Some(rp) = self.peek() {
                        matches!(
                            rp.kind,
                            TokenKind::Punctuation(crate::lexer::Punctuation::RParen)
                        )
                    } else {
                        false
                    }
                } else {
                    false
                };

                // If parsing failed, restore position and fall back to span collection
                let (end_span, func_expr_opt) = if parsed_ok {
                    let rp_tok = self.advance().expect_invariant("just checked RParen");
                    (rp_tok.span.end, func_expr.map(Box::new))
                } else {
                    // Restore position and collect as span
                    self.idx = saved_idx;
                    let mut depth: usize = 1;
                    let mut end = start_span;
                    while let Some(t) = self.advance() {
                        match t.kind {
                            TokenKind::Punctuation(crate::lexer::Punctuation::LParen) => depth += 1,
                            TokenKind::Punctuation(crate::lexer::Punctuation::RParen) => {
                                depth -= 1;
                                end = t.span.end;
                                if depth == 0 {
                                    break;
                                }
                            }
                            _ => {}
                        }
                    }
                    (end, None)
                };

                let name = AstObjectRef {
                    node_id: self.id_gen.next(),
                    span: Span {
                        start: start_span,
                        end: end_span,
                    },
                    // Span covers a parenthesized region (subquery /
                    // function-call shape captured by the surrounding
                    // paren scan above), not a dotted identifier.
                    parts: None,
                    identifier_arg: None,
                };

                // Delegate trailing-construct parsing (alias, alias
                // columns, TVF schema, WITH OFFSET, SAMPLE, PIVOT,
                // UNPIVOT, MATCH_RECOGNIZE, span calculation, AST
                // build) to the shared helper used by the LATERAL
                // form. Keeping a single funnel prevents the two
                // entry points from drifting apart again.
                self.finish_table_function_parse(
                    start_span,
                    name,
                    func_expr_opt,
                    lateral_keyword_span,
                )
            }
            // VALUES clause directly in FROM (Snowflake allows: FROM VALUES (...) AS t (cols))
            TokenKind::Keyword(Keyword::Values) => {
                let start_span = tok.span.start;

                // Parse the VALUES clause
                let values = self
                    .parse_values()
                    .ok_or_eof(self.current_span(), vec!["VALUES clause".to_string()])?;
                let end_span = values.span.end;

                // Parse optional alias with column list: AS t (col1, col2)
                let values_alias = self.parse_values_alias_with_columns();
                let alias = values_alias.alias;
                let as_token = values_alias.as_token;
                let alias_columns = values_alias.columns;
                let alias_columns_lparen_id = values_alias.lparen_id;
                let alias_columns_rparen_id = values_alias.rparen_id;

                // Calculate complete span
                let name_span = Span {
                    start: start_span,
                    end: alias
                        .as_ref()
                        .map(|a| a.span.end)
                        .or_else(|| {
                            alias_columns
                                .as_ref()
                                .and_then(|cols| cols.last().map(|c| c.span.end))
                        })
                        .unwrap_or(end_span),
                };

                let name = AstObjectRef {
                    node_id: self.id_gen.next(),
                    span: name_span,
                    // VALUES alias: span covers the alias region, not
                    // a dotted identifier name.
                    parts: None,
                    identifier_arg: None,
                };

                // Create SyntaxTableRef for VALUES with alias tracking
                let syntax_id = if alias.is_some() || alias_columns.is_some() {
                    let syntax_ref = crate::syntax::SyntaxTableRef {
                        as_keyword: as_token,
                        result_alias_as_keyword: None,
                        subquery_lparen: None,
                        subquery_rparen: None,
                        alias_columns_lparen: alias_columns_lparen_id,
                        alias_columns_rparen: alias_columns_rparen_id,
                        result_alias_columns_lparen: None,
                        result_alias_columns_rparen: None,
                        span: name_span,
                    };
                    Some(self.syntax_arena.alloc_table_ref(syntax_ref))
                } else {
                    None
                };

                Ok(Some(Box::new(crate::parser::sql_stmt::build_table_ref(
                    self.id_gen.next(),
                    name_span,
                    name,
                    alias,
                    alias_columns,
                    None,                   // result_alias
                    None,                   // result_alias_columns
                    None,                   // subquery
                    None,                   // subquery_lparen_span
                    None,                   // subquery_rparen_span
                    Some(Box::new(values)), // values
                    lateral_keyword_span,   // lateral keyword span
                    None,                   // time_travel
                    None,                   // sample
                    None,                   // changes
                    None,                   // stage_options
                    None,                   // table_function
                    None,                   // with_offset
                    None,                   // pivot
                    None,                   // unpivot
                    None,                   // match_recognize
                    None,                   // table_hints
                    syntax_id,              // syntax_id
                ))))
            }
            TokenKind::Punctuation(crate::lexer::Punctuation::LParen) => {
                self.parse_table_factor_lparen(lateral_keyword_span)
            }
            // Accept both identifiers and keywords as table names (context-sensitive parsing)
            _ if self.can_be_identifier_token(tok) => {
                self.parse_table_factor_identifier(lateral_keyword_span)
            }
            // Snowflake stage references: @[namespace.]stage_name[/path]
            // Followed by optional ( FILE_FORMAT => ..., PATTERN => ... )
            TokenKind::Unknown => {
                let tok = self
                    .peek()
                    .ok_or_eof(self.current_span(), vec!["@".to_string()])?;
                if tok.lexeme(self.source) != "@" {
                    return Ok(None);
                }

                let at_tok = self.advance().expect_invariant("just peeked @"); // consume '@'
                let start_span = at_tok.span.start;

                // Parse stage name (can be qualified: namespace.stage or just stage)
                let first_part = self
                    .peek()
                    .ok_or_eof(self.current_span(), vec!["identifier".to_string()])?;
                if !self.can_be_identifier_token(first_part) {
                    return Err(ParseError::unexpected_token(
                        first_part.span,
                        vec!["identifier".to_string()],
                        Parser::token_description(first_part, self.source),
                    ));
                }
                let first_tok = self.advance().expect_invariant("just peeked identifier");
                let mut end_span = first_tok.span.end;

                // Check for dot and continue parsing qualified name
                while let Some(dot_tok) = self.peek() {
                    if matches!(
                        dot_tok.kind,
                        TokenKind::Punctuation(crate::lexer::Punctuation::Dot)
                    ) {
                        self.advance(); // consume dot
                                        // Check for identifier or keyword after dot (or slash for path)
                        if let Some(next_tok) = self.peek() {
                            if self.can_be_identifier_after_dot_token(next_tok) {
                                let next_tok =
                                    self.advance().expect_invariant("just peeked identifier");
                                end_span = next_tok.span.end;
                            } else if matches!(
                                next_tok.kind,
                                TokenKind::Operator(crate::lexer::Operator::Slash)
                            ) {
                                // Path segment starting with slash
                                break;
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

                // Parse optional path segments: /path/to/files/
                // Note: In Snowflake, slashes can appear after stage name
                // We'll just consume tokens until we hit something that's not a valid path character
                while let Some(next_tok) = self.peek() {
                    match &next_tok.kind {
                        TokenKind::Operator(crate::lexer::Operator::Slash) => {
                            let slash = self.advance().expect_invariant("just peeked slash");
                            end_span = slash.span.end;
                        }
                        TokenKind::Punctuation(crate::lexer::Punctuation::Dot) => {
                            // Allow dots inside stage paths (e.g. file.csv)
                            let dot = self.advance().expect_invariant("just peeked dot");
                            end_span = dot.span.end;

                            // Common case: extension token after dot
                            if let Some(after_dot) = self.peek() {
                                if self.can_be_identifier_after_dot_token(after_dot) {
                                    let part =
                                        self.advance().expect_invariant("just peeked extension");
                                    end_span = part.span.end;
                                }
                            }
                        }
                        _ if self.can_be_identifier_token(next_tok) => {
                            let path_part =
                                self.advance().expect_invariant("just peeked path part");
                            end_span = path_part.span.end;
                        }
                        _ => break,
                    }
                }

                let name = AstObjectRef {
                    node_id: self.id_gen.next(),
                    span: Span {
                        start: start_span,
                        end: end_span,
                    },
                    // Stage path (e.g. `@my_stage/path/file.csv`): not a
                    // dotted identifier, so no parts; consumers read the
                    // stage reference from the span.
                    parts: None,
                    identifier_arg: None,
                };

                // Parse optional stage options: ( FILE_FORMAT => 'format', PATTERN => 'regex' )
                let stage_options = if let Some(lparen) = self.peek() {
                    if matches!(
                        lparen.kind,
                        TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
                    ) {
                        let lparen_start = lparen.span.start;
                        self.advance(); // consume '('

                        // Consume everything until we find the matching ')'
                        let mut depth = 1;
                        let mut end_pos = lparen_start;
                        while let Some(t) = self.advance() {
                            match t.kind {
                                TokenKind::Punctuation(crate::lexer::Punctuation::LParen) => {
                                    depth += 1;
                                }
                                TokenKind::Punctuation(crate::lexer::Punctuation::RParen) => {
                                    depth -= 1;
                                    end_pos = t.span.end;
                                    if depth == 0 {
                                        break;
                                    }
                                }
                                _ => {}
                            }
                        }

                        Some(crate::ast::AstStageOptions {
                            node_id: self.id_gen.next(),
                            span: Span {
                                start: lparen_start,
                                end: end_pos,
                            },
                        })
                    } else {
                        None
                    }
                } else {
                    None
                };

                // Parse optional alias with AS tracking
                let mut alias = None;
                let mut as_token = None;
                if let Some(next_tok) = self.peek() {
                    match &next_tok.kind {
                        TokenKind::Keyword(Keyword::As) => {
                            if let Some(alias_tok) = self.peek_ahead(1) {
                                if self.can_be_alias_token(alias_tok) {
                                    as_token = Some(self.current_token_id());
                                    self.advance(); // consume AS
                                    let alias_tok =
                                        self.advance().expect_invariant("just peeked alias");
                                    alias = Some(AstIdentifier {
                                        node_id: self.id_gen.next(),
                                        span: alias_tok.span,
                                    });
                                }
                            }
                        }
                        TokenKind::Identifier { .. }
                            if !self.should_stop_scan_at_statement_start(next_tok) =>
                        {
                            // Check if this identifier is a clause keyword
                            let is_clause_keyword =
                                is_table_clause_keyword(next_tok.lexeme(self.source));

                            if !is_clause_keyword {
                                let alias_tok =
                                    self.advance().expect_invariant("just peeked identifier");
                                alias = Some(AstIdentifier {
                                    node_id: self.id_gen.next(),
                                    span: alias_tok.span,
                                });
                            }
                        }
                        _ => {}
                    }
                }

                // Create SyntaxTableRef if we have an alias
                let syntax_id = if alias.is_some() {
                    let syntax_ref = crate::syntax::SyntaxTableRef {
                        as_keyword: as_token,
                        result_alias_as_keyword: None,
                        subquery_lparen: None,
                        subquery_rparen: None,
                        alias_columns_lparen: None,
                        alias_columns_rparen: None,
                        result_alias_columns_lparen: None,
                        result_alias_columns_rparen: None,
                        span: name.span,
                    };
                    Some(self.syntax_arena.alloc_table_ref(syntax_ref))
                } else {
                    None
                };

                Ok(Some(Box::new(crate::parser::sql_stmt::build_table_ref(
                    self.id_gen.next(),
                    name.span,
                    name,
                    alias,
                    None, // alias_columns
                    None, // result_alias
                    None, // result_alias_columns
                    None, // subquery
                    None, // subquery_lparen_span
                    None, // subquery_rparen_span
                    None, // values
                    lateral_keyword_span,
                    None, // time_travel
                    None, // sample
                    None, // changes
                    stage_options,
                    None,      // table_function
                    None,      // with_offset
                    None,      // pivot
                    None,      // unpivot
                    None,      // match_recognize
                    None,      // table_hints
                    syntax_id, // syntax_id with AS tracking
                ))))
            }
            // Allow positional pipe input references like FROM $1 to be
            // modeled as a regular table reference whose object name span
            // covers the $n token. This keeps the AST simple while still
            // round-tripping Snowflake's pipe-number FROM syntax.
            TokenKind::Literal(crate::lexer::LiteralKind::Position) => {
                let pos_tok = self
                    .advance()
                    .expect_invariant("just peeked position literal");
                let name = AstObjectRef {
                    node_id: self.id_gen.next(),
                    span: pos_tok.span,
                    // Snowflake positional pipe input (`$1`): single
                    // token, not a dotted identifier.
                    parts: None,
                    identifier_arg: None,
                };
                Ok(Some(Box::new(crate::parser::sql_stmt::build_table_ref(
                    self.id_gen.next(),
                    name.span,
                    name,
                    None, // alias
                    None, // alias_columns
                    None, // result_alias
                    None, // result_alias_columns
                    None, // subquery
                    None, // subquery_lparen_span
                    None, // subquery_rparen_span
                    None, // values
                    lateral_keyword_span,
                    None, // time_travel
                    None, // sample
                    None, // changes
                    None, // stage_options
                    None, // table_function
                    None, // with_offset
                    None, // pivot
                    None, // unpivot
                    None, // match_recognize
                    None, // table_hints
                    None, // syntax_id
                ))))
            }
            // Jinja expression as table name: FROM {{ table_name }} or FROM {{ ref('model') }}
            TokenKind::JinjaExprOpen => {
                let start_tok = self.advance().expect_invariant("just peeked {{"); // consume {{
                let start_span = start_tok.span.start;

                // Parse the Jinja expression content
                let jinja_expr = self.parse_jinja_expr()?;

                // Expect closing }}
                let close_tok = if let Some(tok) = self.peek() {
                    if matches!(tok.kind, TokenKind::JinjaExprClose) {
                        self.advance().expect_invariant("just peeked }}")
                    } else {
                        return Err(ParseError::unexpected_token(
                            tok.span,
                            vec!["}}".to_string()],
                            Parser::token_description(tok, self.source),
                        ));
                    }
                } else {
                    return Err(ParseError::new(
                        start_tok.span,
                        ParseErrorKind::UnexpectedEof {
                            expected: vec!["}}".to_string()],
                        },
                    ));
                };

                let mut end_span = close_tok.span.end;

                // Handle qualified identifiers with Jinja: schema.{{ table }} or {{ schema }}.table
                while let Some(dot_tok) = self.peek() {
                    if matches!(
                        dot_tok.kind,
                        TokenKind::Punctuation(crate::lexer::Punctuation::Dot)
                    ) {
                        self.advance(); // consume dot

                        // After dot, accept identifier, keyword, or another Jinja expression
                        if let Some(next_tok) = self.peek() {
                            match &next_tok.kind {
                                TokenKind::JinjaExprOpen => {
                                    // Another Jinja expression after dot
                                    self.advance(); // consume {{
                                    let _ = self.parse_jinja_expr()?;

                                    if let Some(close) = self.peek() {
                                        if matches!(close.kind, TokenKind::JinjaExprClose) {
                                            let close_tok =
                                                self.advance().expect_invariant("just peeked }}");
                                            end_span = close_tok.span.end;
                                        } else {
                                            return Err(ParseError::unexpected_token(
                                                close.span,
                                                vec!["}}".to_string()],
                                                Parser::token_description(close, self.source),
                                            ));
                                        }
                                    }
                                }
                                _ if self.can_be_identifier_after_dot_token(next_tok) => {
                                    let next_tok =
                                        self.advance().expect_invariant("just peeked identifier");
                                    end_span = next_tok.span.end;
                                }
                                _ => {
                                    return Err(ParseError::unexpected_token(
                                        next_tok.span,
                                        vec!["identifier or Jinja expression".to_string()],
                                        Parser::token_description(next_tok, self.source),
                                    ));
                                }
                            }
                        } else {
                            return Err(ParseError::new(
                                dot_tok.span,
                                ParseErrorKind::UnexpectedEof {
                                    expected: vec!["identifier or Jinja expression".to_string()],
                                },
                            ));
                        }
                    } else {
                        break;
                    }
                }

                let name = AstObjectRef {
                    node_id: self.id_gen.next(),
                    span: Span {
                        start: start_span,
                        end: end_span,
                    },
                    // Jinja-templated table name: not a
                    // structurally-decomposable dotted identifier, so no
                    // parts.
                    parts: None,
                    identifier_arg: jinja_expr.map(Box::new).map(|e| {
                        Box::new(AstExpr::JinjaPlaceholder {
                            node_id: self.id_gen.next(),
                            kind: crate::ast::JinjaKind::Expression,
                            span: Span {
                                start: start_span,
                                end: end_span,
                            },
                            expr: Some(*e),
                            syntax_id: None,
                        })
                    }),
                };

                // Parse optional alias with AS tracking
                let mut alias = None;
                let mut as_token = None;
                if let Some(next_tok) = self.peek() {
                    match &next_tok.kind {
                        TokenKind::Keyword(Keyword::As) => {
                            if let Some(alias_tok) = self.peek_ahead(1) {
                                if self.can_be_alias_token(alias_tok) {
                                    as_token = Some(self.current_token_id());
                                    self.advance(); // consume AS
                                    let alias_tok =
                                        self.advance().expect_invariant("just peeked alias");
                                    alias = Some(AstIdentifier {
                                        node_id: self.id_gen.next(),
                                        span: alias_tok.span,
                                    });
                                }
                            }
                        }
                        TokenKind::Identifier { .. }
                            if !self.should_stop_scan_at_statement_start(next_tok) =>
                        {
                            // Check if this identifier is a table clause keyword like SAMPLE
                            let is_table_clause =
                                is_table_specific_clause(next_tok.lexeme(self.source));
                            let is_clause_keyword =
                                is_table_clause_keyword(next_tok.lexeme(self.source));

                            if !is_table_clause
                                && !is_clause_keyword
                                && !self.is_databricks_time_travel_ahead()
                            {
                                let alias_tok =
                                    self.advance().expect_invariant("just peeked identifier");
                                alias = Some(AstIdentifier {
                                    node_id: self.id_gen.next(),
                                    span: alias_tok.span,
                                });
                            }
                        }
                        _ => {}
                    }
                }

                // Parse optional CHANGES clause or time travel clause (mutually exclusive)
                let changes = self.parse_changes_clause()?;
                let time_travel = if changes.is_none() {
                    self.parse_time_travel_clause()?
                } else {
                    None
                };

                // Parse optional SAMPLE clause (after Jinja table name)
                let sample = self.parse_sample_clause()?;

                // Parse optional PIVOT or UNPIVOT clause (mutually exclusive)
                let pivot = self.parse_pivot_clause()?;
                let unpivot = if pivot.is_none() {
                    self.parse_unpivot_clause()?
                } else {
                    None
                };

                // Parse optional MATCH_RECOGNIZE clause
                let match_recognize = self.parse_match_recognize().ok().flatten();

                // Try to parse alias again if we haven't got one yet (handles "FROM {{ table }} AT (...) alias")
                if alias.is_none() {
                    if let Some(next_tok) = self.peek() {
                        match &next_tok.kind {
                            TokenKind::Keyword(Keyword::As) => {
                                if let Some(alias_tok) = self.peek_ahead(1) {
                                    if self.can_be_alias_token(alias_tok) {
                                        as_token = Some(self.current_token_id());
                                        self.advance(); // consume AS
                                        let alias_tok =
                                            self.advance().expect_invariant("just peeked alias");
                                        alias = Some(AstIdentifier {
                                            node_id: self.id_gen.next(),
                                            span: alias_tok.span,
                                        });
                                    }
                                }
                            }
                            TokenKind::Identifier { .. } => {
                                let is_clause_keyword =
                                    is_table_clause_keyword(next_tok.lexeme(self.source));

                                if !is_clause_keyword {
                                    let alias_tok =
                                        self.advance().expect_invariant("just peeked identifier");
                                    alias = Some(AstIdentifier {
                                        node_id: self.id_gen.next(),
                                        span: alias_tok.span,
                                    });
                                }
                            }
                            TokenKind::Keyword(_) => {
                                let is_dialect_boundary = self
                                    .dialect
                                    .is_clause_boundary_keyword(next_tok.lexeme(self.source));
                                if self.can_be_alias_token(next_tok)
                                    && !self.is_join_or_clause_keyword()
                                    && !is_dialect_boundary
                                {
                                    let alias_tok = self
                                        .advance()
                                        .expect_invariant("just peeked keyword-alias");
                                    alias = Some(AstIdentifier {
                                        node_id: self.id_gen.next(),
                                        span: alias_tok.span,
                                    });
                                }
                            }
                            _ => {}
                        }
                    }
                }

                // Box the optional clauses
                let sample = sample.map(Box::new);
                let changes = changes.map(Box::new);
                let match_recognize = match_recognize.map(Box::new);
                let pivot = pivot.map(Box::new);
                let unpivot = unpivot.map(Box::new);

                // Calculate complete span including all clauses
                let complete_span = crate::parser::sql_stmt::calculate_table_ref_span(
                    name.span,
                    &alias,
                    &None,
                    &time_travel,
                    &sample,
                    &changes,
                    &pivot,
                    &unpivot,
                    &match_recognize,
                    &None, // table_hints (not applicable for lateral subquery)
                );

                // Create SyntaxTableRef if we have an alias
                let syntax_id = if alias.is_some() {
                    let syntax_ref = crate::syntax::SyntaxTableRef {
                        as_keyword: as_token,
                        result_alias_as_keyword: None,
                        subquery_lparen: None,
                        subquery_rparen: None,
                        alias_columns_lparen: None,
                        alias_columns_rparen: None,
                        result_alias_columns_lparen: None,
                        result_alias_columns_rparen: None,
                        span: complete_span,
                    };
                    Some(self.syntax_arena.alloc_table_ref(syntax_ref))
                } else {
                    None
                };

                Ok(Some(Box::new(crate::parser::sql_stmt::build_table_ref(
                    self.id_gen.next(),
                    complete_span,
                    name,
                    alias,
                    None, // alias_columns
                    None, // result_alias
                    None, // result_alias_columns
                    None, // subquery
                    None, // subquery_lparen_span
                    None, // subquery_rparen_span
                    None, // values
                    lateral_keyword_span,
                    time_travel,
                    sample,
                    changes,
                    None, // stage_options
                    None, // table_function
                    None, // with_offset
                    pivot,
                    unpivot,
                    match_recognize,
                    None,      // table_hints
                    syntax_id, // syntax_id with AS tracking
                ))))
            }
            _ => Ok(None),
        }
    }

    /// Parses a parenthesized table factor: `(SELECT ...)`, `(VALUES ...)`, or `LATERAL (SELECT ...)`.
    /// Extracted from `parse_table_factor_impl` to reduce stack frame size of the main dispatch.
    fn parse_table_factor_lparen(
        &mut self,
        lateral_keyword_span: Option<Span>,
    ) -> ParseResult<Option<Box<AstTableRef>>> {
        // (SELECT ...) [alias] or LATERAL (SELECT ...) or (VALUES ...) or
        // (tbl1 a JOIN tbl2 b ON …) — standard "joined_table" production.
        let lparen_tok = self.advance().expect_invariant("just peeked LParen"); // consume '('
        let lparen_tok_id = self.last_token_id();
        let lparen_span = lparen_tok.span;

        // Save idx so we can rewind for the paren-group fall-through if the inner
        // turns out to be a joined-table chain rather than a SELECT/VALUES body.
        let saved_inner_idx = self.idx;

        // Check if this is a VALUES clause
        let is_values = if let Some(first_tok) = self.peek() {
            matches!(first_tok.kind, TokenKind::Keyword(Keyword::Values))
        } else {
            false
        };

        // Parse the subquery/VALUES body using natural descent
        // No token slicing - just parse from current position
        let (subquery, values) = if is_values {
            // Parse VALUES clause
            let values_result = self.parse_values();
            (None, values_result)
        } else {
            // Parse SELECT/WITH subquery directly - skip full statement dispatch
            // This reduces call depth and avoids stack overflow in debug builds
            match self.try_parse_set_or_select_stmt() {
                Ok(stmt) => {
                    // Accept SELECT or SetSelect (UNION/INTERSECT/EXCEPT) as subquery
                    match &stmt {
                        AstStmt::Select(_) | AstStmt::SetSelect(_) => (Some(Box::new(stmt)), None),
                        // A pipe chain is not accepted as a subquery.
                        AstStmt::PipeChain { .. } => (None, None),
                        _ => (None, None),
                    }
                }
                Err(e) => {
                    // Check if this is a fatal error (like recursion limit)
                    if e.kind.is_resource_exhaustion() {
                        return Err(e); // Propagate fatal error
                    }
                    // Parse failed - return None to continue with fallback logic
                    (None, None)
                }
            }
        };

        // Paren-group fall-through: if the inner wasn't a SELECT/SetSelect/VALUES
        // and we're not staring at `)`, re-interpret as a parenthesised joined-table
        // (standard SQL `joined_table` production: `(t1 a JOIN t2 b ON …)`).
        if subquery.is_none() && values.is_none() {
            let next_is_rparen = self.peek().is_some_and(|t| {
                matches!(
                    t.kind,
                    TokenKind::Punctuation(crate::lexer::Punctuation::RParen)
                )
            });
            if !next_is_rparen {
                self.idx = saved_inner_idx;
                let inner_factor = self.parse_table_factor(lparen_span)?;
                if let Some(mut inner) = inner_factor {
                    self.parse_join_chain(&mut inner)?;
                    let inner_join_count = inner.joins.len() as u16;
                    // Expect closing `)` for the paren group
                    let rparen_tok = match self.peek() {
                        Some(t)
                            if matches!(
                                t.kind,
                                TokenKind::Punctuation(crate::lexer::Punctuation::RParen)
                            ) =>
                        {
                            self.advance().expect_invariant("RParen confirmed by peek")
                        }
                        Some(t) => {
                            return Err(ParseError::new(
                                t.span,
                                ParseErrorKind::InvalidSyntax {
                                    message: "Expected ')' to close parenthesised join group"
                                        .to_string(),
                                },
                            ));
                        }
                        None => {
                            return Err(ParseError::new(
                                lparen_span,
                                ParseErrorKind::InvalidSyntax {
                                    message: "Missing closing ')' for parenthesised join group"
                                        .to_string(),
                                },
                            ));
                        }
                    };
                    let rparen_span = rparen_tok.span;
                    inner.paren_group = Some(Box::new(crate::ast::ParenGroupInfo {
                        lparen_span,
                        rparen_span,
                        inner_join_count,
                        odbc_oj_span: None,
                    }));
                    inner.span.start = lparen_span.start;
                    inner.span.end = rparen_span.end;
                    if let Some(lat_span) = lateral_keyword_span {
                        inner.lateral_keyword_span = Some(lat_span);
                        inner.span.start = lat_span.start;
                    }
                    return Ok(Some(inner));
                }
                // parse_table_factor returned None — nothing parseable inside `(`.
                // Fall through to the existing path which will surface the
                // "Expected ')'" error for a clearer diagnostic.
            }
        }

        // Expect closing paren
        let (rparen_tok_id, rparen_span) = if let Some(tok) = self.peek() {
            if matches!(
                tok.kind,
                TokenKind::Punctuation(crate::lexer::Punctuation::RParen)
            ) {
                let tok = self.advance().expect_invariant("just peeked RParen");
                let tok_id = self.last_token_id();
                let tok_span = tok.span;
                (tok_id, tok_span)
            } else {
                return Err(ParseError::new(
                    tok.span,
                    ParseErrorKind::InvalidSyntax {
                        message: "Expected ')' to close subquery or VALUES clause".to_string(),
                    },
                ));
            }
        } else {
            return Err(ParseError::new(
                lparen_span,
                ParseErrorKind::InvalidSyntax {
                    message: "Missing closing ')' for subquery or VALUES clause".to_string(),
                },
            ));
        };

        // Calculate name_span to include the closing paren
        let name_span = Span {
            start: lparen_span.start,
            end: rparen_span.end,
        };
        let name = AstObjectRef {
            node_id: self.id_gen.next(),
            span: name_span,
            // Subquery name span: covers `(SELECT ...)` parens, not a
            // dotted identifier.
            parts: None,
            identifier_arg: None,
        };

        // Parse optional CHANGES clause or time travel clause (mutually exclusive)
        // CHANGES has its own AT/BEFORE inside it
        let changes = self.parse_changes_clause()?;
        let time_travel = if changes.is_none() {
            self.parse_time_travel_clause()?
        } else {
            None
        };
        // Parse optional SAMPLE clause (can come after either)
        let sample = self.parse_sample_clause()?;

        // Parse first optional alias (can appear before PIVOT/UNPIVOT/MATCH_RECOGNIZE)
        // This handles: FROM (SELECT ...) alias PIVOT (...)
        let mut alias = None;
        let mut as_token = None;
        let mut alias_columns = None;
        let mut alias_columns_lparen_id = None;
        let mut alias_columns_rparen_id = None;
        if let Some(next_tok) = self.peek() {
            if self.can_be_alias_token(next_tok)
                || matches!(next_tok.kind, TokenKind::Keyword(Keyword::As))
            {
                if matches!(next_tok.kind, TokenKind::Keyword(Keyword::As))
                    && self
                        .peek_ahead(1)
                        .is_some_and(|alias_tok| self.can_be_alias_token(alias_tok))
                {
                    as_token = Some(self.current_token_id());
                    self.advance(); // consume AS
                }
                if let Some(alias_tok) = self.peek() {
                    if self.can_be_alias_token(alias_tok) {
                        // Check if this identifier is actually a clause keyword
                        let is_clause_keyword =
                            is_table_clause_keyword(alias_tok.lexeme(self.source))
                                || self
                                    .dialect
                                    .is_clause_boundary_keyword(alias_tok.lexeme(self.source));

                        // Special case: MATCH_CONDITION followed by '(' is not an alias
                        let is_match_condition_call = if alias_tok
                            .lexeme(self.source)
                            .eq_ignore_ascii_case("MATCH_CONDITION")
                        {
                            self.peek_ahead(1).is_some_and(|tok| {
                                matches!(
                                    tok.kind,
                                    TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
                                )
                            })
                        } else {
                            false
                        };

                        if !is_clause_keyword && !is_match_condition_call {
                            let alias_tok =
                                self.advance().expect_invariant("just peeked identifier");
                            alias = Some(AstIdentifier {
                                node_id: self.id_gen.next(),
                                span: alias_tok.span,
                            });

                            // Parse optional column list after alias: (col1, col2, ...)
                            if let Some(lparen) = self.peek() {
                                if matches!(
                                    lparen.kind,
                                    TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
                                ) {
                                    self.advance(); // consume '('
                                    alias_columns_lparen_id = Some(self.last_token_id());
                                    let mut columns = Vec::new();

                                    loop {
                                        if let Some(col_tok) = self.peek() {
                                            if self.can_be_identifier_token(col_tok) {
                                                let col_tok = self
                                                    .advance()
                                                    .expect_invariant("just peeked column");
                                                columns.push(AstIdentifier {
                                                    node_id: self.id_gen.next(),
                                                    span: col_tok.span,
                                                });

                                                // Check for comma or closing paren
                                                if let Some(next) = self.peek() {
                                                    if matches!(
                                                        next.kind,
                                                        TokenKind::Punctuation(
                                                            crate::lexer::Punctuation::Comma
                                                        )
                                                    ) {
                                                        self.advance(); // consume ','
                                                        continue;
                                                    } else if matches!(
                                                        next.kind,
                                                        TokenKind::Punctuation(
                                                            crate::lexer::Punctuation::RParen
                                                        )
                                                    ) {
                                                        self.advance(); // consume ')'
                                                        alias_columns_rparen_id =
                                                            Some(self.last_token_id());
                                                        break;
                                                    }
                                                }
                                                break;
                                            } else if matches!(
                                                col_tok.kind,
                                                TokenKind::Punctuation(
                                                    crate::lexer::Punctuation::RParen
                                                )
                                            ) {
                                                self.advance(); // consume ')' - empty list
                                                alias_columns_rparen_id =
                                                    Some(self.last_token_id());
                                                break;
                                            }
                                        }
                                        break;
                                    }

                                    if !columns.is_empty() {
                                        alias_columns = Some(columns);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // Parse optional PIVOT or UNPIVOT clause (mutually exclusive)
        let pivot = self.parse_pivot_clause()?;
        let unpivot = if pivot.is_none() {
            self.parse_unpivot_clause()?
        } else {
            None
        };

        // Parse optional MATCH_RECOGNIZE clause
        let match_recognize = self.parse_match_recognize()?;

        // Parse second optional alias (after PIVOT/UNPIVOT/MATCH_RECOGNIZE) - with optional column list
        let (
            second_alias,
            second_as_token,
            second_alias_columns,
            result_alias_columns_lparen,
            result_alias_columns_rparen,
        ) = self.parse_optional_second_alias_with_columns();

        // If PIVOT/UNPIVOT is present, use second alias (after PIVOT/UNPIVOT) as the result alias
        // For MATCH_RECOGNIZE: keep both aliases if both present (table alias + result alias)
        let (result_alias, result_alias_columns) = if pivot.is_some() || unpivot.is_some() {
            // For subquery/VALUES: keep the first alias — it defines column names for the
            // source expression (e.g., (VALUES ...) AS unpvt(cols) PIVOT (...) AS pvt).
            // Unlike parse_table_factor_identifier, here alias belongs to the derived
            // table / VALUES constructor and must be preserved.
            (second_alias, second_alias_columns) // Return second alias as result_alias
        } else if second_alias.is_some() {
            // MATCH_RECOGNIZE with second alias: keep first as table alias, second as result alias
            (second_alias, second_alias_columns)
        } else {
            (None, None)
        };

        let sample = sample.map(Box::new);
        let changes = changes.map(Box::new);
        let match_recognize = match_recognize.map(Box::new);
        let pivot = pivot.map(Box::new);
        let unpivot = unpivot.map(Box::new);

        let complete_span = crate::parser::sql_stmt::calculate_table_ref_span(
            name.span,
            &alias,
            &alias_columns,
            &time_travel,
            &sample,
            &changes,
            &pivot,
            &unpivot,
            &match_recognize,
            &None, // table_hints (not applicable for subquery table ref)
        );
        // For subquery and VALUES cases, pass the lparen/rparen SPANS for build_table_ref
        let subquery_lparen_span = if subquery.is_some() || values.is_some() {
            Some(lparen_span)
        } else {
            None
        };
        let subquery_rparen_span = if subquery.is_some() || values.is_some() {
            Some(rparen_span)
        } else {
            None
        };

        // Also capture token IDs for CST
        let subquery_lparen_id = if subquery.is_some() || values.is_some() {
            Some(lparen_tok_id)
        } else {
            None
        };
        let subquery_rparen_id = if subquery.is_some() || values.is_some() {
            Some(rparen_tok_id)
        } else {
            None
        };

        // Create SyntaxTableRef for subquery/VALUES with wrapper parens
        let syntax_id = if subquery.is_some()
            || values.is_some()
            || alias.is_some()
            || result_alias.is_some()
        {
            let syntax_ref = crate::syntax::SyntaxTableRef {
                as_keyword: as_token,
                result_alias_as_keyword: second_as_token,
                subquery_lparen: subquery_lparen_id,
                subquery_rparen: subquery_rparen_id,
                alias_columns_lparen: alias_columns_lparen_id,
                alias_columns_rparen: alias_columns_rparen_id,
                result_alias_columns_lparen,
                result_alias_columns_rparen,
                span: complete_span,
            };
            Some(self.syntax_arena.alloc_table_ref(syntax_ref))
        } else {
            None
        };

        let table_ref = Box::new(crate::parser::sql_stmt::build_table_ref(
            self.id_gen.next(),
            complete_span,
            name,
            alias,
            alias_columns,
            result_alias,
            result_alias_columns,
            subquery,
            subquery_lparen_span,
            subquery_rparen_span,
            values.map(Box::new),
            lateral_keyword_span,
            time_travel,
            sample,
            changes,
            None, // stage_options
            None, // table_function
            None, // with_offset
            pivot,
            unpivot,
            match_recognize,
            None,      // table_hints
            syntax_id, // syntax_id with AS and subquery paren tracking
        ));
        Ok(Some(table_ref))
    }

    /// Parses a table factor starting with an identifier or keyword-as-identifier.
    /// Handles qualified names (db.schema.table), IDENTIFIER(...), TABLE(...) UDTFs,
    /// table-valued functions, aliases, time travel, PIVOT/UNPIVOT, MATCH_RECOGNIZE, etc.
    /// Extracted from `parse_table_factor_impl` to reduce stack frame size of the main dispatch.
    fn parse_table_factor_identifier(
        &mut self,
        lateral_keyword_span: Option<Span>,
    ) -> ParseResult<Option<Box<AstTableRef>>> {
        let lateral = lateral_keyword_span.is_some();
        // tok is still the peeked token (not yet consumed)
        let tok = self.peek().expect_invariant("caller verified token exists");

        // Check if this is a table-valued function (e.g., UNNEST in BigQuery,
        // GENERATE_SERIES in PostgreSQL) by checking dialect + lookahead for '('
        {
            let name = tok.lexeme(self.source);
            if self.dialect.is_table_valued_function(name) {
                if let Some(next) = self.peek_ahead(1) {
                    if matches!(
                        next.kind,
                        TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
                    ) {
                        let start_pos = tok.span.start;
                        return Ok(
                            self.parse_lateral_table_function(start_pos, lateral_keyword_span)
                        );
                    }
                }
            }
        }

        // Treat a leading IDENTIFIER token as a generic table name, but
        // also handle the Snowflake IDENTIFIER(...) helper when followed
        // by '(' so that constructs like FROM IDENTIFIER(:table_name)
        // are accepted inside scripting blocks. We slice the full span
        // from IDENTIFIER through the closing ')' into the AstObjectRef.
        // Also handle TABLE(function_call) for UDTFs.
        let ident_tok = self.advance().expect_invariant("just peeked identifier");
        let mut end_span = ident_tok.span.end;
        let mut identifier_arg: Option<Box<AstExpr>> = None;
        // Per-identifier-token spans for the structurally dotted name.
        // See `AstObjectRef::parts` for the rationale: each entry must
        // be the exact span of one identifier token, never wider, so
        // downstream consumers can decompose `db.schema.table` without
        // re-parsing the merged span (which would drag in any trivia
        // emitted between parts). Set to `None` below if we enter
        // `TABLE(...)`, `IDENTIFIER(...)`, or hit a Jinja interpolation
        // inside the dotted-name loop — in those cases the name is not
        // a structurally-decomposable dotted identifier.
        let mut parts: Option<Vec<Option<Span>>> = Some(vec![Some(ident_tok.span)]);

        // Handle TABLE(function_call) for UDTFs
        if ident_tok.lexeme(self.source).eq_ignore_ascii_case("TABLE") {
            if let Some(lp) = self.peek() {
                if matches!(
                    lp.kind,
                    TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
                ) {
                    parts = None;
                    let _ = self.advance(); // consume '('
                    let mut depth: usize = 1;
                    while let Some(t) = self.advance() {
                        match t.kind {
                            TokenKind::Punctuation(crate::lexer::Punctuation::LParen) => depth += 1,
                            TokenKind::Punctuation(crate::lexer::Punctuation::RParen) => {
                                depth -= 1;
                                end_span = t.span.end;
                                if depth == 0 {
                                    break;
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
        } else if ident_tok
            .lexeme(self.source)
            .eq_ignore_ascii_case("IDENTIFIER")
        {
            // IDENTIFIER(string_literal | session_var | bind_var | scripting_var)
            // Try to parse the argument expression for formatter support
            if let Some(lp) = self.peek() {
                if matches!(
                    lp.kind,
                    TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
                ) {
                    parts = None;
                    self.advance(); // consume '('

                    // Save position to try parsing
                    let saved_idx = self.idx;

                    // Try to parse the argument expression
                    let arg_expr = self.parse_expr().ok();

                    // Check if parsing succeeded and we have closing paren
                    let parsed_ok = if let Some(ref _expr) = arg_expr {
                        if let Some(rp) = self.peek() {
                            matches!(
                                rp.kind,
                                TokenKind::Punctuation(crate::lexer::Punctuation::RParen)
                            )
                        } else {
                            false
                        }
                    } else {
                        false
                    };

                    if parsed_ok {
                        // Successfully parsed - consume closing paren
                        if let Some(rp_tok) = self.advance() {
                            end_span = rp_tok.span.end;
                        }
                        // Store parsed argument for later use
                        identifier_arg = arg_expr.map(Box::new);
                    } else {
                        // Fall back to span collection
                        self.idx = saved_idx;
                        let mut depth: usize = 1;
                        let mut found_closing = false;
                        while let Some(t) = self.advance() {
                            match t.kind {
                                TokenKind::Punctuation(crate::lexer::Punctuation::LParen) => {
                                    depth += 1
                                }
                                TokenKind::Punctuation(crate::lexer::Punctuation::RParen) => {
                                    depth -= 1;
                                    end_span = t.span.end;
                                    if depth == 0 {
                                        found_closing = true;
                                        break;
                                    }
                                }
                                _ => {}
                            }
                        }
                        if !found_closing {
                            return Err(ParseError::new(
                                ident_tok.span,
                                ParseErrorKind::InvalidSyntax {
                                    message: "Missing closing ')' for IDENTIFIER(...) function"
                                        .to_string(),
                                },
                            ));
                        }
                    }
                }
            }
        } else if lateral {
            // LATERAL followed by a regular table name (not a function call)
            // This shouldn't normally happen as function calls are handled above,
            // but keep for safety
        }

        // Handle qualified identifiers: db.schema.table or schema.table or schema.{{ table }}
        // Continue consuming dot-separated identifiers or Jinja expressions
        while let Some(dot_tok) = self.peek() {
            if matches!(
                dot_tok.kind,
                TokenKind::Punctuation(crate::lexer::Punctuation::Dot)
            ) {
                self.advance(); // consume dot
                                // Check for identifier, keyword, or Jinja expression after dot
                if let Some(next_tok) = self.peek() {
                    match &next_tok.kind {
                        TokenKind::JinjaExprOpen => {
                            // Jinja expression after dot: schema.{{ table }}
                            // The name is no longer a clean dotted identifier
                            // chain. Drop parts to None
                            // so consumers don't try to decompose a name
                            // whose middle segment is a templated value.
                            parts = None;
                            self.advance(); // consume {{
                            let _ = self.parse_jinja_expr()?;

                            if let Some(close) = self.peek() {
                                if matches!(close.kind, TokenKind::JinjaExprClose) {
                                    let close_tok =
                                        self.advance().expect_invariant("just peeked }}");
                                    end_span = close_tok.span.end;
                                } else {
                                    return Err(ParseError::unexpected_token(
                                        close.span,
                                        vec!["}}".to_string()],
                                        Parser::token_description(close, self.source),
                                    ));
                                }
                            } else {
                                return Err(ParseError::new(
                                    next_tok.span,
                                    ParseErrorKind::UnexpectedEof {
                                        expected: vec!["}}".to_string()],
                                    },
                                ));
                            }
                        }
                        _ if self.can_be_identifier_after_dot_token(next_tok) => {
                            let next_tok =
                                self.advance().expect_invariant("just peeked identifier");
                            end_span = next_tok.span.end;
                            if let Some(p) = parts.as_mut() {
                                p.push(Some(next_tok.span));
                            }
                        }
                        TokenKind::Punctuation(crate::lexer::Punctuation::Dot) => {
                            // T-SQL omitted component (`master..tbl`): empty
                            // slot recorded as `None`; the next iteration
                            // consumes the following dot.
                            end_span = dot_tok.span.end;
                            if let Some(p) = parts.as_mut() {
                                p.push(None);
                            }
                        }
                        _ => {
                            // Dot not followed by identifier or Jinja - error
                            return Err(ParseError::unexpected_token(
                                next_tok.span,
                                vec!["identifier or Jinja expression".to_string()],
                                Parser::token_description(next_tok, self.source),
                            ));
                        }
                    }
                } else {
                    return Err(ParseError::new(
                        dot_tok.span,
                        ParseErrorKind::UnexpectedEof {
                            expected: vec!["identifier or Jinja expression".to_string()],
                        },
                    ));
                }
            } else {
                break;
            }
        }

        let name = AstObjectRef {
            node_id: self.id_gen.next(),
            span: Span {
                start: ident_tok.span.start,
                end: end_span,
            },
            parts,
            identifier_arg,
        };

        // Check if qualified name is followed by '(' — table-valued function call
        // e.g., ML.PREDICT(...), ML.EVALUATE(...), schema.my_tvf(...)
        if let Some(lp) = self.peek() {
            if matches!(
                lp.kind,
                TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
            ) {
                // Consume balanced parens to get the full function call span
                let mut depth: usize = 0;
                let tvf_start = ident_tok.span.start;
                let mut tvf_end = end_span;
                while let Some(t) = self.advance() {
                    match t.kind {
                        TokenKind::Punctuation(crate::lexer::Punctuation::LParen) => depth += 1,
                        TokenKind::Punctuation(crate::lexer::Punctuation::RParen) => {
                            depth -= 1;
                            tvf_end = t.span.end;
                            if depth == 0 {
                                break;
                            }
                        }
                        _ => {}
                    }
                }
                let tvf_name = AstObjectRef {
                    node_id: self.id_gen.next(),
                    span: Span {
                        start: tvf_start,
                        end: tvf_end,
                    },
                    // Table-valued function call detected after a
                    // qualified prefix (`schema.my_tvf(...)`): the
                    // name span now covers the whole call, so it is
                    // no longer a structurally-decomposable identifier.
                    parts: None,
                    identifier_arg: None,
                };
                let alias = self
                    .parse_simple_alias_with_as()
                    .map(|(alias, _as_tok)| alias);
                let final_end = alias.as_ref().map(|a| a.span.end).unwrap_or(tvf_end);
                return Ok(Some(Box::new(AstTableRef {
                    node_id: self.id_gen.next(),
                    name: Box::new(tvf_name),
                    prefix_inline_fragments: Box::new(Vec::new()),
                    suffix_inline_fragments: Box::new(Vec::new()),
                    alias: alias.map(Box::new),
                    alias_columns: None,
                    result_alias: None,
                    result_alias_columns: None,
                    subquery: None,
                    subquery_lparen_span: None,
                    subquery_rparen_span: None,
                    paren_group: None,
                    values: None,
                    lateral_keyword_span,
                    only_span: None,
                    time_travel: None,
                    sample: None,
                    changes: None,
                    stage_options: None,
                    table_function: None,
                    tvf_schema_span: None,
                    with_offset: None,
                    pivot: None,
                    unpivot: None,
                    match_recognize: None,
                    table_hints: None,
                    index_hints: None,
                    partition_selection: None,
                    joins: Box::new(Vec::new()),
                    syntax_id: None,
                    span: Span {
                        start: tvf_start,
                        end: final_end,
                    },
                })));
            }
        }

        // MySQL partition selection: `tbl PARTITION (p0, p1)` — between the
        // table name and the alias (dialect-gated inside).
        let partition_selection = self.try_parse_partition_selection()?;

        // Optional alias (AS identifier or just identifier) - try to parse EARLY to handle "FROM table alias AT (...)"
        // but we'll try again after clauses to handle "FROM table AT (...) alias"
        let mut alias = None;
        let mut as_token = None;
        if let Some(next_tok) = self.peek() {
            match &next_tok.kind {
                TokenKind::Keyword(Keyword::As) => {
                    if let Some(alias_tok) = self.peek_ahead(1) {
                        // Accept both identifiers and keywords as aliases (context-sensitive parsing)
                        if self.can_be_alias_token(alias_tok) {
                            let as_tok_id = self.current_token_id();
                            self.advance(); // consume AS
                            let alias_tok = self.advance().expect_invariant("just peeked alias");
                            alias = Some(AstIdentifier {
                                node_id: self.id_gen.next(),
                                span: alias_tok.span,
                            });
                            as_token = Some(as_tok_id);
                        }
                    }
                }
                TokenKind::Identifier { .. } => {
                    if self.should_stop_scan_at_statement_start(next_tok) {
                        // MSSQL semicolonless scripts: don't consume next statement start as alias
                    } else {
                        // Check if this identifier is actually a table clause keyword
                        let is_table_clause =
                            is_table_specific_clause(next_tok.lexeme(self.source));

                        // Check if it's a query clause keyword or dialect-specific boundary
                        let is_query_clause = is_table_clause_keyword(next_tok.lexeme(self.source))
                            || self
                                .dialect
                                .is_clause_boundary_keyword(next_tok.lexeme(self.source));

                        // Special case: MATCH_CONDITION followed by '(' is not an alias
                        // (it's part of ASOF JOIN syntax)
                        let is_match_condition_call = if next_tok
                            .lexeme(self.source)
                            .eq_ignore_ascii_case("MATCH_CONDITION")
                        {
                            self.peek_ahead(1).is_some_and(|tok| {
                                matches!(
                                    tok.kind,
                                    TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
                                )
                            })
                        } else {
                            false
                        };

                        // Only consume as alias if it's not a clause keyword and not table clause
                        // Table clauses can appear before OR after alias, so don't consume them yet
                        if !is_table_clause
                            && !is_query_clause
                            && !is_match_condition_call
                            && !self.is_databricks_time_travel_ahead()
                        {
                            let alias_tok =
                                self.advance().expect_invariant("just peeked identifier");
                            alias = Some(AstIdentifier {
                                node_id: self.id_gen.next(),
                                span: alias_tok.span,
                            });
                        }
                    }
                }
                TokenKind::Keyword(_) => {
                    // Keywords can be used as table aliases (context-sensitive parsing)
                    // Use lookahead to determine if this keyword starts a new clause/construct
                    // Also check dialect-specific clause boundaries (e.g., RETURNING in PostgreSQL)
                    let is_dialect_boundary = self
                        .dialect
                        .is_clause_boundary_keyword(next_tok.lexeme(self.source));
                    if self.can_be_alias_token(next_tok)
                        && !self.is_join_or_clause_keyword()
                        && !is_dialect_boundary
                        && !self.should_stop_scan_at_statement_start(next_tok)
                    {
                        let alias_tok =
                            self.advance().expect_invariant("just peeked keyword-alias");
                        alias = Some(AstIdentifier {
                            node_id: self.id_gen.next(),
                            span: alias_tok.span,
                        });
                    }
                }
                _ => {}
            }
        }

        // T-SQL table hints: WITH (NOLOCK), WITH (UPDLOCK, HOLDLOCK), etc.
        // Must come after alias resolution (FROM t alias WITH (NOLOCK))
        // and before CHANGES/time_travel (T-SQL doesn't have those anyway).
        let table_hints = self.try_parse_table_hint_clause()?;

        // MySQL index hints: USE|FORCE|IGNORE INDEX|KEY [...] (...) — after
        // the alias, before joins (dialect-gated inside).
        let index_hints = self.try_parse_index_hints()?;

        // Parse optional CHANGES clause or time travel clause (mutually exclusive)
        let changes = self.parse_changes_clause()?;
        let time_travel = if changes.is_none() {
            self.parse_time_travel_clause()?
        } else {
            None
        };
        // Parse optional SAMPLE clause
        let sample = self.parse_sample_clause()?;

        // Parse optional PIVOT or UNPIVOT clause (mutually exclusive)
        let pivot = self.parse_pivot_clause()?;
        let unpivot = if pivot.is_none() {
            self.parse_unpivot_clause()?
        } else {
            None
        };

        // Parse optional MATCH_RECOGNIZE clause
        let match_recognize = self.parse_match_recognize()?;

        // Parse second optional alias (after PIVOT/UNPIVOT/MATCH_RECOGNIZE) - with column list for PIVOT
        let (
            second_alias,
            second_as_token,
            second_alias_columns,
            result_alias_columns_lparen,
            result_alias_columns_rparen,
        ) = if pivot.is_some() || unpivot.is_some() || match_recognize.is_some() {
            self.parse_optional_second_alias_with_columns()
        } else {
            (None, None, None, None, None)
        };

        // Determine which aliases to use based on transform presence
        let (result_alias, result_alias_columns) = if pivot.is_some() || unpivot.is_some() {
            // For PIVOT/UNPIVOT: second alias becomes result_alias, first is discarded
            alias = None;
            (second_alias, second_alias_columns)
        } else if second_alias.is_some() {
            // MATCH_RECOGNIZE with second alias: keep first as table alias, second as result alias
            (second_alias, second_alias_columns)
        } else {
            (None, None)
        };

        // Try to parse alias again if we haven't got one yet (handles "FROM table AT (...) alias")
        if alias.is_none() && result_alias.is_none() {
            if let Some(next_tok) = self.peek() {
                match &next_tok.kind {
                    TokenKind::Keyword(Keyword::As) => {
                        if let Some(alias_tok) = self.peek_ahead(1) {
                            if self.can_be_alias_token(alias_tok) {
                                let as_tok_id = self.current_token_id();
                                self.advance(); // consume AS
                                let alias_tok =
                                    self.advance().expect_invariant("just peeked alias");
                                alias = Some(AstIdentifier {
                                    node_id: self.id_gen.next(),
                                    span: alias_tok.span,
                                });
                                as_token = Some(as_tok_id);
                            }
                        }
                    }
                    TokenKind::Identifier { .. } => {
                        if !self.should_stop_scan_at_statement_start(next_tok) {
                            let is_clause_keyword =
                                is_table_clause_keyword(next_tok.lexeme(self.source));

                            let is_dialect_boundary = self
                                .dialect
                                .is_clause_boundary_keyword(next_tok.lexeme(self.source));

                            let is_match_condition_call = if next_tok
                                .lexeme(self.source)
                                .eq_ignore_ascii_case("MATCH_CONDITION")
                            {
                                self.peek_ahead(1).is_some_and(|tok| {
                                    matches!(
                                        tok.kind,
                                        TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
                                    )
                                })
                            } else {
                                false
                            };

                            if !is_clause_keyword
                                && !is_dialect_boundary
                                && !is_match_condition_call
                            {
                                let alias_tok =
                                    self.advance().expect_invariant("just peeked identifier");
                                alias = Some(AstIdentifier {
                                    node_id: self.id_gen.next(),
                                    span: alias_tok.span,
                                });
                            }
                        }
                    }
                    TokenKind::Keyword(_) => {
                        let is_dialect_boundary = self
                            .dialect
                            .is_clause_boundary_keyword(next_tok.lexeme(self.source));
                        if self.can_be_alias_token(next_tok)
                            && !self.is_join_or_clause_keyword()
                            && !is_dialect_boundary
                            && !self.should_stop_scan_at_statement_start(next_tok)
                        {
                            let alias_tok =
                                self.advance().expect_invariant("just peeked keyword-alias");
                            alias = Some(AstIdentifier {
                                node_id: self.id_gen.next(),
                                span: alias_tok.span,
                            });
                        }
                    }
                    _ => {}
                }
            }
        }

        let sample = sample.map(Box::new);
        let changes = changes.map(Box::new);
        let match_recognize = match_recognize.map(Box::new);
        let pivot = pivot.map(Box::new);
        let unpivot = unpivot.map(Box::new);

        let mut complete_span = crate::parser::sql_stmt::calculate_table_ref_span(
            name.span,
            &alias,
            &None,
            &time_travel,
            &sample,
            &changes,
            &pivot,
            &unpivot,
            &match_recognize,
            &table_hints,
        );
        // Index hints follow the alias; extend the ref span over them.
        if let Some(last_hint) = index_hints.as_ref().and_then(|h| h.last()) {
            complete_span.end = complete_span.end.max(last_hint.span.end);
        }
        // Partition selection precedes the alias; extend when no alias followed.
        if let Some(ps) = partition_selection.as_ref() {
            complete_span.end = complete_span.end.max(ps.span.end);
        }

        // Create SyntaxTableRef if we have an alias or result_alias (simple table case)
        let syntax_id = if alias.is_some() || result_alias.is_some() {
            let syntax_ref = crate::syntax::SyntaxTableRef {
                as_keyword: as_token,
                result_alias_as_keyword: second_as_token,
                subquery_lparen: None,
                subquery_rparen: None,
                alias_columns_lparen: None,
                alias_columns_rparen: None,
                result_alias_columns_lparen,
                result_alias_columns_rparen,
                span: complete_span,
            };
            Some(self.syntax_arena.alloc_table_ref(syntax_ref))
        } else {
            None
        };

        let mut table_ref = crate::parser::sql_stmt::build_table_ref(
            self.id_gen.next(),
            complete_span,
            name,
            alias,
            None,                 // alias_columns
            result_alias,         // result_alias
            result_alias_columns, // result_alias_columns
            None,                 // subquery
            None,                 // subquery_lparen_span
            None,                 // subquery_rparen_span
            None,                 // values
            lateral_keyword_span,
            time_travel,
            sample,
            changes,
            None, // stage_options
            None, // table_function
            None, // with_offset
            pivot,
            unpivot,
            match_recognize,
            table_hints,
            syntax_id, // syntax_id with AS tracking
        );
        table_ref.index_hints = index_hints;
        table_ref.partition_selection = partition_selection;
        Ok(Some(Box::new(table_ref)))
    }

    fn parse_join_modifiers(&mut self) -> crate::error::ParseResult<Option<JoinModifiers>> {
        let first = match self.peek() {
            Some(t) => t,
            None => return Ok(None),
        };
        // Only proceed if the first token is a known join modifier.
        match &first.kind {
            TokenKind::Keyword(Keyword::Inner)
            | TokenKind::Keyword(Keyword::Left)
            | TokenKind::Keyword(Keyword::Right)
            | TokenKind::Keyword(Keyword::Full)
            | TokenKind::Keyword(Keyword::Cross)
            | TokenKind::Keyword(Keyword::Outer)
            | TokenKind::Keyword(Keyword::Asof)
            | TokenKind::Keyword(Keyword::Natural)
            | TokenKind::Keyword(Keyword::Directed)
            | TokenKind::Keyword(Keyword::Lateral) => {}
            _ => return Ok(None),
        }

        let mut kind = crate::ast::AstJoinKind::Inner;
        let mut natural = false;
        let mut directed_keyword_span = None;
        let mut lateral_keyword_span = None;
        let mut asof_keyword_span = None;
        let mut apply = false;
        let mut modifier_span_start = first.span.start;
        let mut saw_any = false;
        let mut saw_explicit_type = matches!(
            first.kind,
            TokenKind::Keyword(Keyword::Inner)
                | TokenKind::Keyword(Keyword::Left)
                | TokenKind::Keyword(Keyword::Right)
                | TokenKind::Keyword(Keyword::Full),
        );

        // Consume one or more modifier tokens (NATURAL, INNER/LEFT/RIGHT/FULL, CROSS, DIRECTED, optional OUTER).
        while let Some(tok) = self.peek() {
            match &tok.kind {
                TokenKind::Keyword(Keyword::Natural) => {
                    let nat_tok = self
                        .advance()
                        .expect_invariant("NATURAL keyword should be available after peek");
                    if !saw_any {
                        modifier_span_start = nat_tok.span.start;
                    }
                    natural = true;
                    saw_any = true;
                }
                TokenKind::Keyword(Keyword::Inner) => {
                    let inner_tok = self
                        .advance()
                        .expect_invariant("INNER keyword should be available after peek");
                    if !saw_any {
                        modifier_span_start = inner_tok.span.start;
                    }
                    kind = if natural {
                        crate::ast::AstJoinKind::NaturalInner
                    } else {
                        crate::ast::AstJoinKind::Inner
                    };
                    saw_any = true;
                    saw_explicit_type = true;
                }
                TokenKind::Keyword(Keyword::Left) => {
                    let left_tok = self
                        .advance()
                        .expect_invariant("LEFT keyword should be available after peek");
                    if !saw_any {
                        modifier_span_start = left_tok.span.start;
                    }
                    // Optional OUTER
                    if let Some(next) = self.peek() {
                        if matches!(next.kind, TokenKind::Keyword(Keyword::Outer)) {
                            let _ = self.advance();
                        }
                    }
                    kind = if natural {
                        crate::ast::AstJoinKind::NaturalLeftOuter
                    } else {
                        crate::ast::AstJoinKind::LeftOuter
                    };
                    saw_any = true;
                    saw_explicit_type = true;
                }
                TokenKind::Keyword(Keyword::Right) => {
                    let right_tok = self
                        .advance()
                        .expect_invariant("RIGHT keyword should be available after peek");
                    if !saw_any {
                        modifier_span_start = right_tok.span.start;
                    }
                    if let Some(next) = self.peek() {
                        if matches!(next.kind, TokenKind::Keyword(Keyword::Outer)) {
                            let _ = self.advance();
                        }
                    }
                    kind = if natural {
                        crate::ast::AstJoinKind::NaturalRightOuter
                    } else {
                        crate::ast::AstJoinKind::RightOuter
                    };
                    saw_any = true;
                    saw_explicit_type = true;
                }
                TokenKind::Keyword(Keyword::Full) => {
                    let full_tok = self
                        .advance()
                        .expect_invariant("FULL keyword should be available after peek");
                    if !saw_any {
                        modifier_span_start = full_tok.span.start;
                    }
                    if let Some(next) = self.peek() {
                        if matches!(next.kind, TokenKind::Keyword(Keyword::Outer)) {
                            let _ = self.advance();
                        }
                    }
                    kind = if natural {
                        crate::ast::AstJoinKind::NaturalFullOuter
                    } else {
                        crate::ast::AstJoinKind::FullOuter
                    };
                    saw_any = true;
                    saw_explicit_type = true;
                }
                TokenKind::Keyword(Keyword::Directed) => {
                    let directed_tok = self
                        .advance()
                        .expect_invariant("DIRECTED keyword should be available after peek");
                    directed_keyword_span = Some(directed_tok.span);
                    saw_any = true;
                }
                TokenKind::Keyword(Keyword::Lateral) => {
                    let lateral_tok = self
                        .advance()
                        .expect_invariant("LATERAL keyword should be available after peek");
                    lateral_keyword_span = Some(lateral_tok.span);
                    saw_any = true;
                }
                TokenKind::Keyword(Keyword::Cross) => {
                    let cross_tok = self
                        .advance()
                        .expect_invariant("CROSS keyword should be available after peek");
                    if !saw_any {
                        modifier_span_start = cross_tok.span.start;
                    }
                    kind = crate::ast::AstJoinKind::Cross;
                    saw_any = true;
                }
                TokenKind::Keyword(Keyword::Outer) => {
                    let outer_tok = self
                        .advance()
                        .expect_invariant("OUTER keyword should be available after peek");
                    if !saw_any {
                        modifier_span_start = outer_tok.span.start;
                    }
                    // T-SQL OUTER APPLY has left-preserving semantics.
                    kind = crate::ast::AstJoinKind::LeftOuter;
                    saw_any = true;
                    saw_explicit_type = true;
                }
                TokenKind::Keyword(Keyword::Asof) => {
                    let asof_tok = self
                        .advance()
                        .expect_invariant("ASOF keyword should be available after peek");
                    if !saw_any {
                        modifier_span_start = asof_tok.span.start;
                    }
                    // ASOF JOIN is a special join type in Snowflake
                    // It cannot be combined with LEFT/RIGHT/FULL modifiers
                    // It requires MATCH_CONDITION syntax (not yet fully implemented)
                    kind = crate::ast::AstJoinKind::Asof;
                    asof_keyword_span = Some(asof_tok.span);
                    saw_any = true;
                    saw_explicit_type = true;
                }
                _ => break,
            }
        }

        // T-SQL APPLY: {CROSS|OUTER} APPLY
        if let Some(next_tok) = self.peek() {
            if matches!(next_tok.kind, TokenKind::Identifier { .. })
                && next_tok.lexeme(self.source).eq_ignore_ascii_case("APPLY")
            {
                if !matches!(
                    kind,
                    crate::ast::AstJoinKind::Cross | crate::ast::AstJoinKind::LeftOuter
                ) || natural
                    || directed_keyword_span.is_some()
                {
                    return Err(ParseError::new(
                        next_tok.span,
                        ParseErrorKind::InvalidSyntax {
                            message: "APPLY must be preceded by CROSS or OUTER".to_string(),
                        },
                    ));
                }

                apply = true;
            }
        }

        if !saw_any {
            Ok(None)
        } else {
            // Enforce Snowflake's DIRECTED rule: except for CROSS, DIRECTED
            // must appear with an explicit join type keyword.
            if directed_keyword_span.is_some()
                && !saw_explicit_type
                && !matches!(kind, crate::ast::AstJoinKind::Cross)
            {
                return Err(ParseError::new(
                    Span {
                        start: modifier_span_start,
                        end: modifier_span_start,
                    },
                    ParseErrorKind::InvalidSyntax {
                        message: "DIRECTED must be used with LEFT, RIGHT, FULL, or CROSS JOIN"
                            .to_string(),
                    },
                ));
            }
            // Handle bare NATURAL JOIN without an explicit side keyword by
            // defaulting it to NATURAL INNER JOIN.
            let final_kind = if natural && matches!(kind, crate::ast::AstJoinKind::Inner) {
                crate::ast::AstJoinKind::NaturalInner
            } else {
                kind
            };
            Ok(Some((
                final_kind,
                apply,
                directed_keyword_span,
                lateral_keyword_span,
                asof_keyword_span,
                modifier_span_start,
            )))
        }
    }

    /// Parse MATCH_CONDITION clause for ASOF JOIN
    /// Syntax: MATCH_CONDITION ( comparison_expr )
    fn parse_match_condition(&mut self) -> Option<crate::ast::AstMatchCondition> {
        // Look for MATCH_CONDITION keyword (case-insensitive identifier)
        let tok = self.peek()?;

        // MATCH_CONDITION is not a reserved keyword in lexer, check as identifier
        let is_match_condition = match &tok.kind {
            TokenKind::Identifier { .. } => tok
                .lexeme(self.source)
                .eq_ignore_ascii_case("MATCH_CONDITION"),
            _ => false,
        };

        if !is_match_condition {
            return None;
        }

        let match_kw_start = tok.span.start;
        self.advance(); // consume MATCH_CONDITION

        // Expect opening parenthesis
        let lparen = self.peek()?;
        if !matches!(
            lparen.kind,
            TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
        ) {
            return None;
        }
        self.advance(); // consume '('

        // Parse the comparison expression with error recovery
        let condition = self.parse_expr_with_recovery().ok()?;

        // Expect closing parenthesis
        let rparen = self.peek()?;
        if !matches!(
            rparen.kind,
            TokenKind::Punctuation(crate::lexer::Punctuation::RParen)
        ) {
            return None;
        }
        let match_kw_end = rparen.span.end;
        self.advance(); // consume ')'

        Some(crate::ast::AstMatchCondition {
            node_id: self.id_gen.next(),
            condition,
            span: Span {
                start: match_kw_start,
                end: match_kw_end,
            },
        })
    }

    pub(crate) fn parse_join_chain(&mut self, base: &mut AstTableRef) -> ParseResult<()> {
        loop {
            let InlineFragmentCollection {
                fragments: mut prefix_inline_fragments,
            } = self.collect_leading_inline_fragments();

            let first_tok = match self.peek() {
                Some(t) => t,
                None => {
                    // No more tokens; attach any collected inline fragments to the base table
                    base.suffix_inline_fragments.extend(prefix_inline_fragments);
                    if let Some(last) = base.suffix_inline_fragments.last() {
                        base.span.end = base.span.end.max(last.span.end);
                    }
                    break;
                }
            };
            // If we see a bare DIRECTED followed by JOIN, treat it as a
            // hard syntax error scenario at the SELECT level. The join-chain
            // helper itself just stops; the caller (SELECT parser) will see
            // that a dangling JOIN keyword remains and fail the whole parse.
            if matches!(first_tok.kind, TokenKind::Keyword(Keyword::Directed)) {
                // Look ahead for JOIN after DIRECTED.
                let save_idx = self.idx;
                let _ = self.advance();
                let after = self.peek();
                self.idx = save_idx;
                if let Some(tok) = after {
                    if matches!(tok.kind, TokenKind::Keyword(Keyword::Join)) {
                        // Break on DIRECTED JOIN pattern
                        break;
                    }
                }
            }

            // Check for bare JOIN keyword (without modifiers)
            let is_bare_join = matches!(first_tok.kind, TokenKind::Keyword(Keyword::Join));

            let (
                kind,
                apply,
                directed_keyword_span,
                lateral_keyword_span,
                asof_keyword_span,
                modifier_span_start,
            ) = if is_bare_join {
                // Bare JOIN defaults to INNER JOIN
                (
                    crate::ast::AstJoinKind::Inner,
                    false,
                    None,
                    None,
                    None,
                    first_tok.span.start,
                )
            } else {
                match self.parse_join_modifiers() {
                    Ok(Some(v)) => v,
                    Ok(None) => {
                        // Not a JOIN; stash any inline fragments onto the base and stop
                        base.suffix_inline_fragments.extend(prefix_inline_fragments);
                        if let Some(last) = base.suffix_inline_fragments.last() {
                            base.span.end = base.span.end.max(last.span.end);
                        }
                        break;
                    }
                    Err(e) => return Err(e),
                }
            };

            let join_kw = match self.peek() {
                Some(t) => t,
                None => {
                    base.suffix_inline_fragments.extend(prefix_inline_fragments);
                    if let Some(last) = base.suffix_inline_fragments.last() {
                        base.span.end = base.span.end.max(last.span.end);
                    }
                    break;
                }
            };
            let expect_apply = apply;
            let is_join_keyword = matches!(join_kw.kind, TokenKind::Keyword(Keyword::Join));
            let is_apply_ident = matches!(join_kw.kind, TokenKind::Identifier { .. })
                && join_kw.lexeme(self.source).eq_ignore_ascii_case("APPLY");

            if (!expect_apply && !is_join_keyword) || (expect_apply && !is_apply_ident) {
                // Not actually a JOIN, rewind not supported so just stop.
                base.suffix_inline_fragments.extend(prefix_inline_fragments);
                if let Some(last) = base.suffix_inline_fragments.last() {
                    base.span.end = base.span.end.max(last.span.end);
                }
                break;
            }
            let join_op_tok = self
                .advance()
                .expect_invariant("JOIN/APPLY token should be available after peek"); // consume JOIN or APPLY
                                                                                      // Collect inline fragments between JOIN keyword and table factor
            let InlineFragmentCollection {
                fragments: join_mid_inline_fragments,
            } = self.collect_leading_inline_fragments();
            if !join_mid_inline_fragments.is_empty() {
                prefix_inline_fragments.extend(join_mid_inline_fragments);
            }
            // Right-hand table: reuse table-factor parser so joins can target
            // subqueries or aliased tables in future extensions.
            let right = match self.parse_table_factor(Span {
                start: modifier_span_start,
                end: join_kw.span.end,
            }) {
                Ok(Some(t)) => t,
                Ok(None) => {
                    // No table reference found
                    return Err(ParseError::new(
                        join_kw.span,
                        ParseErrorKind::InvalidSyntax {
                            message: if expect_apply {
                                "Expected table reference after APPLY keyword".to_string()
                            } else {
                                "Expected table reference after JOIN keyword".to_string()
                            },
                        },
                    ));
                }
                Err(e) => {
                    return Err(e);
                }
            };

            // For ASOF JOIN, try to parse optional MATCH_CONDITION before ON/USING
            let is_asof = matches!(kind, crate::ast::AstJoinKind::Asof);
            let match_condition = if is_asof {
                self.parse_match_condition().map(Box::new)
            } else {
                None
            };

            let mut span_end = right
                .alias
                .as_ref()
                .map_or(right.name.span.end, |a| a.span.end);

            // Consume inline fragments between table factor and join condition keywords
            let InlineFragmentCollection {
                fragments: between_table_and_constraint,
            } = self.collect_leading_inline_fragments();
            if !between_table_and_constraint.is_empty() {
                prefix_inline_fragments.extend(between_table_and_constraint);
            }

            // Optional join condition: ON <expr> or USING(...).
            let mut constraint = crate::ast::AstJoinConstraint::None;
            if !expect_apply {
                if let Some(next) = self.peek() {
                    match &next.kind {
                        TokenKind::Keyword(Keyword::On) => {
                            let _on_tok = self
                                .advance()
                                .expect_invariant("ON token available after peek");
                            match self.parse_expr_in_mode() {
                                Ok(expr) => {
                                    span_end = expr.span().end;
                                    constraint = crate::ast::AstJoinConstraint::On(Box::new(expr));
                                }
                                Err(e) => {
                                    return Err(e);
                                }
                            }
                        }
                        TokenKind::Keyword(Keyword::Using) => {
                            // Minimal USING parser: USING (col1, col2, ...)
                            let using_tok = self
                                .advance()
                                .expect_invariant("USING token available after peek");

                            // Expect opening parenthesis
                            let lp = match self.advance() {
                                Some(t) => t,
                                None => {
                                    return Err(ParseError::unexpected_eof(
                                        using_tok.span,
                                        vec!["(".to_string()],
                                    ));
                                }
                            };

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

                            let mut cols = Vec::new();

                            loop {
                                let tok = match self.peek() {
                                    Some(t) => t,
                                    None => {
                                        return Err(ParseError::unexpected_eof(
                                            lp.span,
                                            vec!["identifier or )".to_string()],
                                        ));
                                    }
                                };

                                match &tok.kind {
                                    _ if self.can_be_identifier_token(tok) => {
                                        let ident_tok = self.advance().expect_invariant(
                                            "Identifier should be available after peek",
                                        );
                                        cols.push(AstIdentifier {
                                            node_id: self.id_gen.next(),
                                            span: ident_tok.span,
                                        });
                                    }
                                    TokenKind::Punctuation(crate::lexer::Punctuation::Comma) => {
                                        let _ = self.advance();
                                        continue;
                                    }
                                    TokenKind::Punctuation(crate::lexer::Punctuation::RParen) => {
                                        let rparen_tok = self
                                            .advance()
                                            .expect_invariant("')' should be available after peek");
                                        span_end = rparen_tok.span.end;
                                        break;
                                    }
                                    _ => {
                                        return Err(ParseError::unexpected_token(
                                            tok.span,
                                            vec![
                                                "identifier".to_string(),
                                                ",".to_string(),
                                                ")".to_string(),
                                            ],
                                            Parser::token_description(tok, self.source),
                                        ));
                                    }
                                }
                            }

                            // found_rparen is always true here — errors return Err directly

                            if cols.is_empty() {
                                return Err(ParseError::new(
                                    Span {
                                        start: using_tok.span.start,
                                        end: span_end,
                                    },
                                    ParseErrorKind::InvalidSyntax {
                                        message: "USING clause requires at least one column"
                                            .to_string(),
                                    },
                                ));
                            }

                            constraint = crate::ast::AstJoinConstraint::Using(cols);
                        }
                        _ => {}
                    }
                }
            }

            let InlineFragmentCollection {
                fragments: suffix_inline_fragments,
            } = self.collect_trailing_inline_fragments();
            if let Some(last) = suffix_inline_fragments.last() {
                span_end = span_end.max(last.span.end);
            }

            let span = Span {
                start: modifier_span_start,
                end: span_end,
            };

            let join = crate::ast::AstJoin {
                node_id: self.id_gen.next(),
                kind,
                apply_keyword_span: if expect_apply {
                    Some(join_op_tok.span)
                } else {
                    None
                },
                directed_keyword_span,
                lateral_keyword_span,
                asof_keyword_span,
                match_condition, // Use the parsed MATCH_CONDITION
                prefix_inline_fragments,
                right,
                constraint,
                suffix_inline_fragments,
                span,
            };
            base.span.end = base.span.end.max(span_end);
            base.joins.push(Box::new(join));
        }
        Ok(())
    }

    // ── T-SQL Table Hints ──────────────────────────────────────────────────

    /// Try to parse a T-SQL table hint clause: `WITH (<hint> [, <hint>] ...)`
    ///
    /// Returns `Ok(None)` if the next tokens are not `WITH (` in MSSQL dialect.
    /// This uses dialect branching because `WITH` conflicts with CTE syntax.
    /// Parse MySQL index hints after a table reference (dialect-gated):
    /// `{USE|FORCE|IGNORE} {INDEX|KEY} [FOR {JOIN|ORDER BY|GROUP BY}]
    /// (idx, ...)`, space-separated list. `USE` is a keyword; FORCE/IGNORE
    /// lex as identifiers (alias capture stops at them via
    /// `is_clause_boundary_keyword`). `USE INDEX ()` (empty list) and
    /// `PRIMARY` as an index name are legal.
    /// MySQL partition selection on a table reference:
    /// `tbl PARTITION (p0, p1) [[AS] alias]`. Recognized only when PARTITION
    /// is immediately followed by `(` — window/DDL `PARTITION BY` is followed
    /// by BY, never `(` (dialect-gated inside).
    pub(crate) fn try_parse_partition_selection(
        &mut self,
    ) -> crate::error::ParseResult<Option<Box<crate::ast::AstPartitionSelection>>> {
        use crate::error::ExpectInvariant;
        use crate::lexer::{Punctuation, TokenKind};

        if !self.dialect.supports_table_partition_selection() {
            return Ok(None);
        }
        let Some(head) = self.peek() else {
            return Ok(None);
        };
        if !matches!(head.kind, TokenKind::Keyword(Keyword::Partition)) {
            return Ok(None);
        }
        let lparen_ahead = self
            .peek_ahead(1)
            .is_some_and(|t| matches!(t.kind, TokenKind::Punctuation(Punctuation::LParen)));
        if !lparen_ahead {
            return Ok(None);
        }

        let partition_kw_span = self
            .advance()
            .expect_invariant("PARTITION confirmed by peek")
            .span;
        let lparen_span = self
            .advance()
            .expect_invariant("LParen confirmed by peek_ahead")
            .span;

        let mut partition_name_spans: Vec<Span> = Vec::new();
        loop {
            let tok = self.peek().ok_or_else(|| {
                ParseError::new(
                    lparen_span,
                    ParseErrorKind::UnexpectedEof {
                        expected: vec!["partition name or ')'".to_string()],
                    },
                )
            })?;
            match &tok.kind {
                TokenKind::Punctuation(Punctuation::RParen) => break,
                TokenKind::Punctuation(Punctuation::Comma) => {
                    self.advance();
                }
                _ if self.can_be_identifier_token(tok) => {
                    let name_tok = self.advance().expect_invariant("just peeked identifier");
                    partition_name_spans.push(name_tok.span);
                }
                _ => {
                    return Err(ParseError::unexpected_token(
                        tok.span,
                        vec!["partition name".to_string(), ")".to_string()],
                        Parser::token_description(tok, self.source),
                    ));
                }
            }
        }
        let rparen_span = self
            .advance()
            .expect_invariant("RParen confirmed by peek")
            .span;

        Ok(Some(Box::new(crate::ast::AstPartitionSelection {
            node_id: self.id_gen.next(),
            partition_kw_span,
            lparen_span,
            partition_name_spans,
            rparen_span,
            span: Span {
                start: partition_kw_span.start,
                end: rparen_span.end,
            },
        })))
    }

    #[allow(clippy::box_collection)] // the type of `AstTableRef::index_hints`: one pointer when absent
    pub(crate) fn try_parse_index_hints(
        &mut self,
    ) -> crate::error::ParseResult<Option<Box<Vec<crate::ast::AstIndexHint>>>> {
        use crate::ast::{AstIndexHint, AstIndexHintKind, AstIndexHintScope};
        use crate::error::ExpectInvariant;
        use crate::lexer::{Punctuation, TokenKind};

        if !self.dialect.supports_index_hints() {
            return Ok(None);
        }

        let mut hints: Vec<AstIndexHint> = Vec::new();
        while let Some(head) = self.peek() {
            // Hint head: USE (keyword) or FORCE/IGNORE (unquoted identifier),
            // followed by INDEX (identifier) or KEY (keyword).
            let kind = match &head.kind {
                TokenKind::Keyword(Keyword::Use) => Some(AstIndexHintKind::Use),
                TokenKind::Identifier {
                    kind: crate::lexer::IdentifierKind::Unquoted,
                } => {
                    let lex = head.lexeme(self.source);
                    if lex.eq_ignore_ascii_case("FORCE") {
                        Some(AstIndexHintKind::Force)
                    } else if lex.eq_ignore_ascii_case("IGNORE") {
                        Some(AstIndexHintKind::Ignore)
                    } else {
                        None
                    }
                }
                _ => None,
            };
            let Some(kind) = kind else { break };
            let next_is_index_word = self.peek_ahead(1).is_some_and(|t| match &t.kind {
                TokenKind::Keyword(Keyword::Key) => true,
                TokenKind::Identifier {
                    kind: crate::lexer::IdentifierKind::Unquoted,
                } => t.lexeme(self.source).eq_ignore_ascii_case("INDEX"),
                _ => false,
            });
            if !next_is_index_word {
                break;
            }

            let kind_tok = self
                .advance()
                .expect_invariant("hint head confirmed by peek");
            let kind_span = kind_tok.span;
            let index_kw_span = self
                .advance()
                .expect_invariant("INDEX/KEY confirmed by peek_ahead")
                .span;

            // Optional scope: FOR JOIN | FOR ORDER BY | FOR GROUP BY.
            let mut scope: Option<(AstIndexHintScope, Span)> = None;
            if let Some(for_tok) = self.peek() {
                if matches!(for_tok.kind, TokenKind::Keyword(Keyword::For)) {
                    let for_span = for_tok.span;
                    self.advance(); // FOR
                    let scope_tok = self.peek().ok_or_else(|| {
                        crate::error::ParseError::unexpected_eof(
                            self.current_span(),
                            vec!["JOIN".into(), "ORDER BY".into(), "GROUP BY".into()],
                        )
                    })?;
                    let (scope_kind, needs_by) = match &scope_tok.kind {
                        TokenKind::Keyword(Keyword::Join) => (AstIndexHintScope::Join, false),
                        TokenKind::Keyword(Keyword::Order) => (AstIndexHintScope::OrderBy, true),
                        TokenKind::Keyword(Keyword::Group) => (AstIndexHintScope::GroupBy, true),
                        _ => {
                            return Err(crate::error::ParseError::unexpected_token(
                                scope_tok.span,
                                vec!["JOIN".into(), "ORDER BY".into(), "GROUP BY".into()],
                                Parser::token_description(scope_tok, self.source),
                            ));
                        }
                    };
                    let mut scope_end = self
                        .advance()
                        .expect_invariant("scope keyword confirmed by peek")
                        .span
                        .end;
                    if needs_by {
                        let by_tok = self.peek().ok_or_else(|| {
                            crate::error::ParseError::unexpected_eof(
                                self.current_span(),
                                vec!["BY".into()],
                            )
                        })?;
                        if !matches!(by_tok.kind, TokenKind::Keyword(Keyword::By)) {
                            return Err(crate::error::ParseError::unexpected_token(
                                by_tok.span,
                                vec!["BY".into()],
                                Parser::token_description(by_tok, self.source),
                            ));
                        }
                        scope_end = self
                            .advance()
                            .expect_invariant("BY confirmed by peek")
                            .span
                            .end;
                    }
                    scope = Some((
                        scope_kind,
                        Span {
                            start: for_span.start,
                            end: scope_end,
                        },
                    ));
                }
            }

            // Parenthesized index list (empty is legal for USE).
            let lparen_tok = self.peek().ok_or_else(|| {
                crate::error::ParseError::unexpected_eof(self.current_span(), vec!["(".into()])
            })?;
            if !matches!(lparen_tok.kind, TokenKind::Punctuation(Punctuation::LParen)) {
                return Err(crate::error::ParseError::unexpected_token(
                    lparen_tok.span,
                    vec!["(".into()],
                    Parser::token_description(lparen_tok, self.source),
                ));
            }
            let lparen_span = self
                .advance()
                .expect_invariant("LParen confirmed by peek")
                .span;

            let mut index_name_spans: Vec<Span> = Vec::new();
            loop {
                let tok = self.peek().ok_or_else(|| {
                    crate::error::ParseError::unexpected_eof(
                        self.current_span(),
                        vec![")".into(), "index name".into()],
                    )
                })?;
                if matches!(tok.kind, TokenKind::Punctuation(Punctuation::RParen)) {
                    break;
                }
                if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Comma)) {
                    self.advance();
                    continue;
                }
                // Index names are identifiers; PRIMARY (keyword) is legal.
                if self.can_be_identifier_token(tok)
                    || matches!(tok.kind, TokenKind::Keyword(Keyword::Primary))
                {
                    let name_tok = self
                        .advance()
                        .expect_invariant("index name confirmed by peek");
                    index_name_spans.push(name_tok.span);
                    continue;
                }
                return Err(crate::error::ParseError::unexpected_token(
                    tok.span,
                    vec![")".into(), "index name".into()],
                    Parser::token_description(tok, self.source),
                ));
            }
            let rparen_span = self
                .advance()
                .expect_invariant("RParen confirmed by peek")
                .span;

            hints.push(AstIndexHint {
                node_id: self.id_gen.next(),
                kind,
                kind_span,
                index_kw_span,
                scope,
                lparen_span,
                index_name_spans,
                rparen_span,
                span: Span {
                    start: kind_span.start,
                    end: rparen_span.end,
                },
            });
        }

        if hints.is_empty() {
            Ok(None)
        } else {
            Ok(Some(Box::new(hints)))
        }
    }

    pub(crate) fn try_parse_table_hint_clause(
        &mut self,
    ) -> crate::error::ParseResult<Option<Box<crate::ast::AstTableHintClause>>> {
        use crate::lexer::{Keyword, Punctuation, TokenKind};

        // Only parse table hints in dialects that support them (MSSQL/T-SQL)
        if !self.dialect.supports_table_hints() {
            return Ok(None);
        }

        // Disambiguate: WITH ( = table hints, WITH identifier = CTE
        let is_hint = match (self.peek(), self.peek_ahead(1)) {
            (Some(with_tok), Some(next_tok)) => {
                matches!(with_tok.kind, TokenKind::Keyword(Keyword::With))
                    && matches!(next_tok.kind, TokenKind::Punctuation(Punctuation::LParen))
            }
            _ => false,
        };

        if !is_hint {
            return Ok(None);
        }

        // Consume WITH
        let with_tok = self
            .advance()
            .expect_invariant("WITH keyword confirmed by peek");
        let with_keyword_span = with_tok.span;

        // Consume (
        let _lparen_tok = self.advance().expect_invariant("LParen confirmed by peek");
        let start = with_keyword_span.start;

        // Parse comma-separated hints
        let mut hints = Vec::new();
        while let Some(tok) = self.peek() {
            if matches!(tok.kind, TokenKind::Punctuation(Punctuation::RParen)) {
                break;
            }

            let hint = self.parse_single_table_hint()?;
            hints.push(hint);

            // Expect comma or closing paren
            if let Some(tok) = self.peek() {
                if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Comma)) {
                    self.advance(); // consume comma
                    continue;
                }
            }
            break;
        }

        // Consume )
        let rparen_tok = self.peek().ok_or_else(|| {
            crate::error::ParseError::new(
                self.current_span(),
                crate::error::ParseErrorKind::InvalidSyntax {
                    message: "Expected ')' to close table hint clause".to_string(),
                },
            )
        })?;
        if !matches!(rparen_tok.kind, TokenKind::Punctuation(Punctuation::RParen)) {
            return Err(crate::error::ParseError::unexpected_token(
                rparen_tok.span,
                vec![")".to_string()],
                crate::parser::core::Parser::token_description(rparen_tok, self.source),
            ));
        }
        let rparen_tok = self.advance().expect_invariant("RParen confirmed");

        let span = Span {
            start,
            end: rparen_tok.span.end,
        };

        Ok(Some(Box::new(crate::ast::AstTableHintClause {
            node_id: self.id_gen.next(),
            with_keyword_span,
            hints,
            span,
        })))
    }

    /// Parse a single table hint inside `WITH (...)`.
    ///
    /// Handles:
    /// - Simple hints: NOLOCK, UPDLOCK, HOLDLOCK, ROWLOCK, TABLOCK, TABLOCKX,
    ///   PAGLOCK, XLOCK, READPAST, READCOMMITTED, READCOMMITTEDLOCK,
    ///   READUNCOMMITTED, REPEATABLEREAD, SERIALIZABLE, SNAPSHOT, NOWAIT,
    ///   NOEXPAND, FORCESCAN, KEEPIDENTITY, KEEPDEFAULTS, IGNORE_CONSTRAINTS,
    ///   IGNORE_TRIGGERS
    /// - INDEX(val, ...) or INDEX = (val)
    /// - FORCESEEK or FORCESEEK(index(col, ...))
    /// - SPATIAL_WINDOW_MAX_CELLS = N
    fn parse_single_table_hint(&mut self) -> crate::error::ParseResult<crate::ast::AstTableHint> {
        let tok = self.peek().ok_or_else(|| {
            crate::error::ParseError::new(
                self.current_span(),
                crate::error::ParseErrorKind::InvalidSyntax {
                    message: "Expected table hint name".to_string(),
                },
            )
        })?;

        let hint_name = tok.lexeme(self.source);
        let _hint_start = tok.span.start;

        // Route to specific hint parser based on name
        if hint_name.eq_ignore_ascii_case("INDEX") {
            return self.parse_index_hint();
        }
        if hint_name.eq_ignore_ascii_case("FORCESEEK") {
            return self.parse_forceseek_hint();
        }
        if hint_name.eq_ignore_ascii_case("SPATIAL_WINDOW_MAX_CELLS") {
            return self.parse_spatial_window_max_cells_hint();
        }

        // Classify simple-keyword hints into typed AST variants.
        //
        // Parser-layer text dispatch is the canonical site for
        // text → typed-AST conversion: post-parse code consumes the
        // typed variants without further source-text inspection.
        // Unrecognized keywords fall through to `OtherSimple` so the
        // permissive parser still admits database-validated forms
        // without breaking the closed-enum surface.
        let kind = classify_simple_table_hint_keyword(hint_name);

        let hint_tok = self
            .advance()
            .expect_invariant("hint token confirmed by peek");
        let span = hint_tok.span;

        Ok(crate::ast::AstTableHint {
            node_id: self.id_gen.next(),
            kind,
            span,
        })
    }

    /// Parse INDEX hint: `INDEX(val [, ...])` or `INDEX = (val)`
    fn parse_index_hint(&mut self) -> crate::error::ParseResult<crate::ast::AstTableHint> {
        use crate::lexer::{Operator, Punctuation, TokenKind};

        let index_tok = self.advance().expect_invariant("INDEX token");
        let start = index_tok.span.start;

        // Check for INDEX = (...) form vs INDEX(...) form
        let _uses_equals = if let Some(tok) = self.peek() {
            if matches!(tok.kind, TokenKind::Operator(Operator::Eq)) {
                self.advance(); // consume =
                true
            } else {
                false
            }
        } else {
            false
        };

        // Expect (
        let lparen = self.peek().ok_or_else(|| {
            crate::error::ParseError::new(
                self.current_span(),
                crate::error::ParseErrorKind::InvalidSyntax {
                    message: "Expected '(' after INDEX in table hint".to_string(),
                },
            )
        })?;
        if !matches!(lparen.kind, TokenKind::Punctuation(Punctuation::LParen)) {
            return Err(crate::error::ParseError::unexpected_token(
                lparen.span,
                vec!["(".to_string()],
                crate::parser::core::Parser::token_description(lparen, self.source),
            ));
        }
        self.advance(); // consume (

        // Parse comma-separated index values (names or integer IDs)
        let mut values = Vec::new();
        while let Some(tok) = self.peek() {
            if matches!(tok.kind, TokenKind::Punctuation(Punctuation::RParen)) {
                break;
            }

            let val_tok = self.advance().ok_or_else(|| {
                crate::error::ParseError::new(
                    self.current_span(),
                    crate::error::ParseErrorKind::InvalidSyntax {
                        message: "Expected index value in INDEX hint".to_string(),
                    },
                )
            })?;
            values.push(val_tok.span);

            if let Some(tok) = self.peek() {
                if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Comma)) {
                    self.advance(); // consume comma
                    continue;
                }
            }
            break;
        }

        // Consume )
        let rparen = self.advance().ok_or_else(|| {
            crate::error::ParseError::new(
                self.current_span(),
                crate::error::ParseErrorKind::InvalidSyntax {
                    message: "Expected ')' to close INDEX hint".to_string(),
                },
            )
        })?;

        let span = Span {
            start,
            end: rparen.span.end,
        };

        Ok(crate::ast::AstTableHint {
            node_id: self.id_gen.next(),
            kind: crate::ast::AstTableHintKind::Index { values },
            span,
        })
    }

    /// Parse FORCESEEK hint: `FORCESEEK` or `FORCESEEK(index_name(col [, ...]))`
    fn parse_forceseek_hint(&mut self) -> crate::error::ParseResult<crate::ast::AstTableHint> {
        use crate::lexer::{Punctuation, TokenKind};

        let forceseek_tok = self.advance().expect_invariant("FORCESEEK token");
        let start = forceseek_tok.span.start;
        let mut end = forceseek_tok.span.end;

        let mut index_name = None;
        let mut columns = Vec::new();

        // Check for optional (index_name(col, ...))
        if let Some(tok) = self.peek() {
            if matches!(tok.kind, TokenKind::Punctuation(Punctuation::LParen)) {
                self.advance(); // consume (

                // Parse index name
                let idx_tok = self.advance().ok_or_else(|| {
                    crate::error::ParseError::new(
                        self.current_span(),
                        crate::error::ParseErrorKind::InvalidSyntax {
                            message: "Expected index name in FORCESEEK hint".to_string(),
                        },
                    )
                })?;
                index_name = Some(idx_tok.span);

                // Parse column list: (col1, col2, ...)
                if let Some(tok) = self.peek() {
                    if matches!(tok.kind, TokenKind::Punctuation(Punctuation::LParen)) {
                        self.advance(); // consume (

                        while let Some(tok) = self.peek() {
                            if matches!(tok.kind, TokenKind::Punctuation(Punctuation::RParen)) {
                                break;
                            }

                            let col_tok = self.advance().ok_or_else(|| {
                                crate::error::ParseError::new(
                                    self.current_span(),
                                    crate::error::ParseErrorKind::InvalidSyntax {
                                        message: "Expected column name in FORCESEEK hint"
                                            .to_string(),
                                    },
                                )
                            })?;
                            columns.push(col_tok.span);

                            if let Some(tok) = self.peek() {
                                if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Comma)) {
                                    self.advance(); // consume comma
                                    continue;
                                }
                            }
                            break;
                        }

                        // Consume inner )
                        let _inner_rparen = self.advance().ok_or_else(|| {
                            crate::error::ParseError::new(
                                self.current_span(),
                                crate::error::ParseErrorKind::InvalidSyntax {
                                    message: "Expected ')' to close FORCESEEK column list"
                                        .to_string(),
                                },
                            )
                        })?;
                    }
                }

                // Consume outer )
                let outer_rparen = self.advance().ok_or_else(|| {
                    crate::error::ParseError::new(
                        self.current_span(),
                        crate::error::ParseErrorKind::InvalidSyntax {
                            message: "Expected ')' to close FORCESEEK hint".to_string(),
                        },
                    )
                })?;
                end = outer_rparen.span.end;
            }
        }

        let span = Span { start, end };

        Ok(crate::ast::AstTableHint {
            node_id: self.id_gen.next(),
            kind: crate::ast::AstTableHintKind::ForceSeek {
                index_name,
                columns,
            },
            span,
        })
    }

    /// Parse SPATIAL_WINDOW_MAX_CELLS hint: `SPATIAL_WINDOW_MAX_CELLS = N`
    fn parse_spatial_window_max_cells_hint(
        &mut self,
    ) -> crate::error::ParseResult<crate::ast::AstTableHint> {
        use crate::lexer::{Operator, TokenKind};

        let keyword_tok = self
            .advance()
            .expect_invariant("SPATIAL_WINDOW_MAX_CELLS token");
        let start = keyword_tok.span.start;

        // Expect =
        let eq_tok = self.peek().ok_or_else(|| {
            crate::error::ParseError::new(
                self.current_span(),
                crate::error::ParseErrorKind::InvalidSyntax {
                    message: "Expected '=' after SPATIAL_WINDOW_MAX_CELLS".to_string(),
                },
            )
        })?;
        if !matches!(eq_tok.kind, TokenKind::Operator(Operator::Eq)) {
            return Err(crate::error::ParseError::unexpected_token(
                eq_tok.span,
                vec!["=".to_string()],
                crate::parser::core::Parser::token_description(eq_tok, self.source),
            ));
        }
        self.advance(); // consume =

        // Expect integer value
        let val_tok = self.advance().ok_or_else(|| {
            crate::error::ParseError::new(
                self.current_span(),
                crate::error::ParseErrorKind::InvalidSyntax {
                    message: "Expected integer value for SPATIAL_WINDOW_MAX_CELLS".to_string(),
                },
            )
        })?;
        let value = val_tok.span;

        let span = Span {
            start,
            end: val_tok.span.end,
        };

        Ok(crate::ast::AstTableHint {
            node_id: self.id_gen.next(),
            kind: crate::ast::AstTableHintKind::SpatialWindowMaxCells { value },
            span,
        })
    }
}
