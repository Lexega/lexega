// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! CREATE VIEW / CREATE MATERIALIZED VIEW statement parser module
//!
//! Handles parsing of CREATE VIEW and CREATE MATERIALIZED VIEW statements
//! with full multi-dialect support:
//!
//! **Shared (all dialects):**
//! - OR REPLACE, IF NOT EXISTS, AS SELECT query
//!
//! **Snowflake CREATE VIEW:**
//! - SECURE, TEMPORARY/VOLATILE, RECURSIVE modifiers
//! - Column definitions with masking/projection policies and tags
//! - View-level policies (ROW ACCESS, AGGREGATION, JOIN)
//! - Tags, contacts, change tracking, copy grants
//!
//! **Snowflake CREATE MATERIALIZED VIEW:**
//! - SECURE, COPY GRANTS, column lists with policies
//! - CLUSTER BY, COMMENT, ROW ACCESS POLICY, AGGREGATION POLICY, TAG
//!
//! **BigQuery CREATE MATERIALIZED VIEW:**
//! - PARTITION BY, CLUSTER BY, OPTIONS(...)
//! - AS REPLICA OF (cross-region replication variant)
//!
//! **PostgreSQL CREATE VIEW:**
//! - WITH ( security_invoker / security_barrier / check_option [= value], ... )

use crate::ast::{
    AstCreateView, AstCreateViewColumn, AstObjectProperty, AstStmt, AstViewCheckOptionMode,
};
use crate::error::{ExpectInvariant, ParseError, ParseErrorKind, ParseResultExt};
use crate::lexer::{Keyword, Span, TokenKind};
use crate::parser::core::Parser;

/// Result of parsing view-level options (policies, tags, change tracking, etc.)
struct CreateViewOptions {
    row_access_policy_span: Option<Span>,
    aggregation_policy_span: Option<Span>,
    join_policy_span: Option<Span>,
    tag_span: Option<Span>,
    with_contact_span: Option<Span>,
    change_tracking_span: Option<Span>,
    copy_grants_span: Option<Span>,
    comment_span: Option<Span>,
    /// PostgreSQL `WITH ( option [= value], ... )` clause.
    with_options_span: Option<Span>,
    with_options: Vec<AstObjectProperty>,
}

/// Helper function to find the matching closing parenthesis starting from current index
/// Returns the index of the closing paren, or end_idx if not found
fn find_matching_paren(tokens: &[crate::lexer::Token], start_idx: usize, end_idx: usize) -> usize {
    let mut depth: usize = 0;
    let mut idx = start_idx;

    while idx < end_idx {
        match tokens[idx].kind {
            TokenKind::Punctuation(crate::lexer::Punctuation::LParen) => {
                depth = depth.saturating_add(1);
            }
            TokenKind::Punctuation(crate::lexer::Punctuation::RParen) => {
                if depth == 0 {
                    return idx;
                }
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return idx;
                }
            }
            _ => {}
        }
        idx += 1;
    }
    end_idx
}

/// Helper function to check if a lexeme starts a view option (case-insensitive)
#[inline]
fn is_view_option_starter_lexeme(lexeme: &str) -> bool {
    lexeme.eq_ignore_ascii_case("ROW")
        || lexeme.eq_ignore_ascii_case("WITH")
        || lexeme.eq_ignore_ascii_case("AGGREGATION")
        || lexeme.eq_ignore_ascii_case("JOIN")
        || lexeme.eq_ignore_ascii_case("TAG")
        || lexeme.eq_ignore_ascii_case("CONTACT")
        || lexeme.eq_ignore_ascii_case("CHANGE_TRACKING")
        || lexeme.eq_ignore_ascii_case("COPY")
        || lexeme.eq_ignore_ascii_case("COMMENT")
}

/// Helper for view options boundary checking (ROW ACCESS POLICY stops at these)
#[inline]
fn is_view_options_boundary(lexeme: &str) -> bool {
    lexeme.eq_ignore_ascii_case("AGGREGATION")
        || lexeme.eq_ignore_ascii_case("JOIN")
        || lexeme.eq_ignore_ascii_case("TAG")
        || lexeme.eq_ignore_ascii_case("CHANGE_TRACKING")
        || lexeme.eq_ignore_ascii_case("COPY")
        || lexeme.eq_ignore_ascii_case("COMMENT")
        || lexeme.eq_ignore_ascii_case("AS")
}

/// Helper for AGGREGATION boundary checking
#[inline]
fn is_view_options_boundary_agg(lexeme: &str) -> bool {
    lexeme.eq_ignore_ascii_case("JOIN")
        || lexeme.eq_ignore_ascii_case("TAG")
        || lexeme.eq_ignore_ascii_case("CHANGE_TRACKING")
        || lexeme.eq_ignore_ascii_case("COPY")
        || lexeme.eq_ignore_ascii_case("COMMENT")
        || lexeme.eq_ignore_ascii_case("AS")
}

/// Helper for JOIN POLICY boundary checking
#[inline]
fn is_view_options_boundary_join(lexeme: &str) -> bool {
    lexeme.eq_ignore_ascii_case("TAG")
        || lexeme.eq_ignore_ascii_case("CHANGE_TRACKING")
        || lexeme.eq_ignore_ascii_case("COPY")
        || lexeme.eq_ignore_ascii_case("COMMENT")
        || lexeme.eq_ignore_ascii_case("AS")
}

/// Try to parse a CREATE VIEW statement
pub(crate) fn try_parse_create_view_stmt_with_parser(
    parser: &mut Parser,
) -> crate::error::ParseResult<AstStmt> {
    let create_tok = parser
        .advance()
        .ok_or_eof(parser.current_span(), vec!["CREATE".to_string()])?;
    let keyword_span = create_tok.span;
    let mut span = keyword_span;
    let mut or_replace_span: Option<Span> = None;
    let mut or_alter_span: Option<Span> = None;
    let mut algorithm_span: Option<Span> = None;
    let mut definer: Option<crate::ast::AstDefiner> = None;
    let mut sql_security: Option<crate::ast::AstViewSqlSecurity> = None;
    let mut secure_span: Option<Span> = None;
    let mut temp_kind_span: Option<Span> = None;
    let mut recursive_span: Option<Span> = None;
    let mut materialized_span: Option<Span> = None;
    let mut if_not_exists_span: Option<Span> = None;
    let mut name_span: Option<Span> = None;
    let mut columns_span: Option<Span> = None;
    let mut columns: Vec<AstCreateViewColumn> = Vec::new();

    // Optional OR REPLACE / OR ALTER
    if let Some(tok) = parser.peek() {
        if tok.lexeme(parser.source).eq_ignore_ascii_case("OR") {
            let or_tok = parser
                .advance()
                .expect_invariant("OR keyword should be available after peek");
            if let Some(next_tok) = parser.peek() {
                if next_tok
                    .lexeme(parser.source)
                    .eq_ignore_ascii_case("REPLACE")
                {
                    let rep = parser
                        .advance()
                        .expect_invariant("REPLACE keyword should be available after peek");
                    or_replace_span = Some(Span {
                        start: or_tok.span.start,
                        end: rep.span.end,
                    });
                    span.end = rep.span.end;
                } else if next_tok.lexeme(parser.source).eq_ignore_ascii_case("ALTER") {
                    let alt = parser
                        .advance()
                        .expect_invariant("ALTER keyword should be available after peek");
                    or_alter_span = Some(Span {
                        start: or_tok.span.start,
                        end: alt.span.end,
                    });
                    span.end = alt.span.end;
                }
            }
        }
    }

    // Optional MySQL view-prelude clauses, in their fixed grammar order:
    //   [ALGORITHM = {UNDEFINED|MERGE|TEMPTABLE}] [DEFINER = user]
    //   [SQL SECURITY {DEFINER|INVOKER}]
    // All precede VIEW and are MySQL-specific, so they don't collide with the
    // Snowflake/PG SECURE/temp/RECURSIVE modifiers below (which never co-occur).

    // ALGORITHM = <kind> (recognition-only perf hint). ALGORITHM lexes as an
    // identifier; require the `=` to disambiguate from a view named ALGORITHM.
    if let Some(tok) = parser.peek_non_trivia() {
        if tok.lexeme(parser.source).eq_ignore_ascii_case("ALGORITHM")
            && matches!(
                parser.peek_ahead(1).map(|t| &t.kind),
                Some(TokenKind::Operator(crate::lexer::Operator::Eq))
            )
        {
            let algo_start = parser.current_span().start;
            let _ = parser.advance(); // ALGORITHM
            let _ = parser.advance(); // =
            let kind_tok = parser
                .advance()
                .ok_or_eof(parser.current_span(), vec!["algorithm kind".to_string()])?;
            algorithm_span = Some(Span {
                start: algo_start,
                end: kind_tok.span.end,
            });
            span.end = kind_tok.span.end;
        }
    }

    // DEFINER = user — reuse the shared typed parser (also handles CURRENT_USER
    // and the quoted / unquoted `user@host` forms). No-op unless DEFINER leads.
    if let Some(d) = parser.parse_definer_clause() {
        span.end = d.span.end;
        definer = Some(d);
    }

    // SQL SECURITY { DEFINER | INVOKER }
    if let Some(tok) = parser.peek_non_trivia() {
        if tok.lexeme(parser.source).eq_ignore_ascii_case("SQL")
            && parser
                .peek_ahead(1)
                .map(|t| t.lexeme(parser.source).eq_ignore_ascii_case("SECURITY"))
                .unwrap_or(false)
        {
            let sec_start = parser.current_span().start;
            let _ = parser.advance(); // SQL
            let _ = parser.advance(); // SECURITY
            let mode_tok = parser.advance().ok_or_eof(
                parser.current_span(),
                vec!["DEFINER or INVOKER".to_string()],
            )?;
            let lx = mode_tok.lexeme(parser.source);
            let mode = if lx.eq_ignore_ascii_case("INVOKER") {
                crate::ast::ViewSqlSecurityMode::Invoker
            } else {
                // DEFINER (the MySQL default) — also the fallback for any other
                // token, which a permissive parser tolerates rather than failing.
                crate::ast::ViewSqlSecurityMode::Definer
            };
            let sql_security_span = Span {
                start: sec_start,
                end: mode_tok.span.end,
            };
            span.end = mode_tok.span.end;
            sql_security = Some(crate::ast::AstViewSqlSecurity {
                span: sql_security_span,
                mode,
            });
        }
    }

    // Optional SECURE keyword
    if let Some(tok) = parser.peek() {
        if tok.lexeme(parser.source).eq_ignore_ascii_case("SECURE") {
            let sec_tok = parser
                .advance()
                .expect_invariant("SECURE keyword should be available after peek");
            secure_span = Some(sec_tok.span);
            span.end = sec_tok.span.end;
        }
    }

    // Optional temp/volatile modifiers
    // Syntax: [ { [ { LOCAL | GLOBAL } ] TEMP | TEMPORARY | VOLATILE } ]
    if let Some(tok) = parser.peek() {
        let mut start_span: Option<Span> = None;
        let mut end_span: Option<Span> = None;

        // Check for optional LOCAL or GLOBAL prefix
        if tok.lexeme(parser.source).eq_ignore_ascii_case("LOCAL")
            || tok.lexeme(parser.source).eq_ignore_ascii_case("GLOBAL")
        {
            let t = parser
                .advance()
                .expect_invariant("LOCAL/GLOBAL keyword should be available after peek");
            start_span = Some(t.span);
            end_span = Some(t.span);

            // After LOCAL/GLOBAL, check for view type keyword
            if let Some(tok2) = parser.peek() {
                if tok2.lexeme(parser.source).eq_ignore_ascii_case("TEMP")
                    || tok2.lexeme(parser.source).eq_ignore_ascii_case("TEMPORARY")
                    || tok2.lexeme(parser.source).eq_ignore_ascii_case("VOLATILE")
                {
                    let t2 = parser.advance().expect_invariant(
                        "TEMP/TEMPORARY/VOLATILE keyword should be available after peek",
                    );
                    end_span = Some(t2.span);
                }
            }
        } else if tok.lexeme(parser.source).eq_ignore_ascii_case("TEMP")
            || tok.lexeme(parser.source).eq_ignore_ascii_case("TEMPORARY")
            || tok.lexeme(parser.source).eq_ignore_ascii_case("VOLATILE")
        {
            // No LOCAL/GLOBAL prefix, just view type keyword
            let t = parser.advance().expect_invariant(
                "View type keyword (TEMP/TEMPORARY/VOLATILE) should be available after peek",
            );
            start_span = Some(t.span);
            end_span = Some(t.span);
        }

        // Set temp_kind_span if we found any view type keywords
        if let (Some(start), Some(end)) = (start_span, end_span) {
            temp_kind_span = Some(Span {
                start: start.start,
                end: end.end,
            });
            span.end = end.end;
        }
    }

    // Optional RECURSIVE keyword
    if let Some(tok) = parser.peek() {
        if tok.lexeme(parser.source).eq_ignore_ascii_case("RECURSIVE") {
            let rec_tok = parser
                .advance()
                .expect_invariant("RECURSIVE keyword should be available after peek");
            recursive_span = Some(rec_tok.span);
            span.end = rec_tok.span.end;
        }
    }

    // Optional MATERIALIZED keyword (CREATE MATERIALIZED VIEW)
    // MATERIALIZED tokenizes as Identifier, not Keyword — match via lexeme
    if let Some(tok) = parser.peek() {
        if tok
            .lexeme(parser.source)
            .eq_ignore_ascii_case("MATERIALIZED")
        {
            let mat_tok = parser
                .advance()
                .expect_invariant("MATERIALIZED identifier should be available after peek");
            materialized_span = Some(mat_tok.span);
            span.end = mat_tok.span.end;
        }
    }

    // Expect VIEW keyword
    let view_tok = parser.advance().ok_or_else(|| {
        ParseError::new(
            parser.current_span(),
            ParseErrorKind::InvalidStatement {
                message: "CREATE VIEW requires VIEW keyword".to_string(),
            },
        )
    })?;
    if !view_tok.lexeme(parser.source).eq_ignore_ascii_case("VIEW") {
        return Err(ParseError::new(
            view_tok.span,
            ParseErrorKind::InvalidStatement {
                message: format!(
                    "Expected VIEW keyword, found {}",
                    Parser::token_description(view_tok, parser.source)
                ),
            },
        ));
    }
    let view_keyword_span = view_tok.span;
    span.end = view_tok.span.end;

    // Optional IF NOT EXISTS
    if let Some(tok) = parser.peek() {
        if tok.lexeme(parser.source).eq_ignore_ascii_case("IF") {
            let if_tok = parser
                .advance()
                .expect_invariant("IF keyword should be available after peek");
            if let Some(not_tok) = parser.peek() {
                if not_tok.lexeme(parser.source).eq_ignore_ascii_case("NOT") {
                    let _not_t = parser
                        .advance()
                        .expect_invariant("NOT keyword should be available after peek");
                    if let Some(exists_tok) = parser.peek() {
                        if exists_tok
                            .lexeme(parser.source)
                            .eq_ignore_ascii_case("EXISTS")
                        {
                            let ex = parser
                                .advance()
                                .expect_invariant("EXISTS keyword should be available after peek");
                            if_not_exists_span = Some(Span {
                                start: if_tok.span.start,
                                end: ex.span.end,
                            });
                            span.end = ex.span.end;
                        }
                    }
                }
            }
        }
    }

    // Capture view name up to '(' or AS or clause keywords
    let name_start_idx = parser.idx;
    while let Some(tok) = parser.peek() {
        if parser.should_stop_scan_at_statement_start(tok) {
            break;
        }
        match tok.kind {
            TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
            | TokenKind::Keyword(Keyword::As)
            | TokenKind::Keyword(Keyword::Partition)
            | TokenKind::Keyword(Keyword::Cluster)
            | TokenKind::Eof
            | TokenKind::Punctuation(crate::lexer::Punctuation::Semi)
            | TokenKind::Operator(crate::lexer::Operator::Pipe) => break,
            _ if is_view_option_starter_lexeme(tok.lexeme(parser.source)) => break,
            // BigQuery OPTIONS is an Identifier — break if materialized view
            _ if materialized_span.is_some()
                && tok.lexeme(parser.source).eq_ignore_ascii_case("OPTIONS") =>
            {
                break
            }
            _ => {
                let _ = parser.advance();
            }
        }
    }
    let name_end_idx = parser.idx;
    if name_end_idx > name_start_idx {
        let first = &parser.tokens[name_start_idx];
        let last = &parser.tokens[name_end_idx - 1];
        name_span = Some(Span {
            start: first.span.start,
            end: last.span.end,
        });
        span.end = last.span.end;
    }

    // Optional column list starting with '('
    let mut column_list_id: Option<crate::syntax::SyntaxViewColumnListId> = None;
    if let Some(tok) = parser.peek() {
        if matches!(
            tok.kind,
            TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
        ) {
            // Parse column list using forward parsing
            let result = try_parse_view_column_list(parser)?;
            columns = result.0;
            column_list_id = result.1;
            columns_span = result.2;
            if let Some(cols_span) = columns_span {
                span.end = cols_span.end;
            }
        }
    }

    // Parse view-level options (policies, tags, etc.)
    // For materialized views, also stop at PARTITION BY, CLUSTER BY, and OPTIONS
    let options_start_idx = parser.idx;
    while let Some(tok) = parser.peek() {
        if parser.should_stop_scan_at_statement_start(tok) {
            break;
        }
        match tok.kind {
            TokenKind::Keyword(Keyword::As)
            | TokenKind::Keyword(Keyword::Partition)
            | TokenKind::Keyword(Keyword::Cluster)
            | TokenKind::Eof
            | TokenKind::Punctuation(crate::lexer::Punctuation::Semi)
            | TokenKind::Operator(crate::lexer::Operator::Pipe) => break,
            _ if materialized_span.is_some()
                && tok.lexeme(parser.source).eq_ignore_ascii_case("OPTIONS") =>
            {
                break
            }
            _ => {
                let _ = parser.advance();
            }
        }
    }
    let options_end_idx = parser.idx;

    // Capture full options span to prevent data loss
    let options_span = if options_end_idx > options_start_idx {
        let first = &parser.tokens[options_start_idx];
        let last = &parser.tokens[options_end_idx - 1];
        Some(Span {
            start: first.span.start,
            end: last.span.end,
        })
    } else {
        None
    };

    // Parse the view options
    let options = parse_create_view_options(parser, options_start_idx, options_end_idx);
    let row_access_policy_span = options.row_access_policy_span;
    let aggregation_policy_span = options.aggregation_policy_span;
    let join_policy_span = options.join_policy_span;
    let tag_span = options.tag_span;
    let with_contact_span = options.with_contact_span;
    let change_tracking_span = options.change_tracking_span;
    let copy_grants_span = options.copy_grants_span;
    let mut comment_span = options.comment_span;
    let with_options_span = options.with_options_span;
    let with_options = options.with_options;

    // Update span to include options
    if options_end_idx > options_start_idx {
        let last = &parser.tokens[options_end_idx - 1];
        span.end = last.span.end;
    }

    // ---- Materialized view specific clauses: PARTITION BY, CLUSTER BY, OPTIONS ----
    let mut partition_by_span: Option<Span> = None;
    let mut cluster_by_span: Option<Span> = None;
    let mut bq_options_span: Option<Span> = None;

    if materialized_span.is_some() {
        // PARTITION BY expr (BigQuery)
        if let Some(tok) = parser.peek() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::Partition)) {
                let part_tok = parser.advance().expect_invariant("PARTITION after peek");
                let part_start = part_tok.span.start;
                // Consume BY
                if let Some(by_tok) = parser.peek() {
                    if matches!(by_tok.kind, TokenKind::Keyword(Keyword::By)) {
                        parser.advance(); // consume BY
                    }
                }
                // Consume the partition expression — everything until CLUSTER, OPTIONS, AS, or ;
                while let Some(t) = parser.peek() {
                    match t.kind {
                        TokenKind::Keyword(Keyword::As)
                        | TokenKind::Keyword(Keyword::Cluster)
                        | TokenKind::Eof
                        | TokenKind::Punctuation(crate::lexer::Punctuation::Semi) => break,
                        _ if t.lexeme(parser.source).eq_ignore_ascii_case("OPTIONS") => break,
                        _ => {
                            parser.advance();
                        }
                    }
                }
                let part_end = parser.tokens[parser.idx.saturating_sub(1)].span.end;
                partition_by_span = Some(Span {
                    start: part_start,
                    end: part_end,
                });
                span.end = part_end;
            }
        }

        // CLUSTER BY (exprs) (BigQuery / Snowflake)
        if let Some(tok) = parser.peek() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::Cluster)) {
                let cluster_tok = parser.advance().expect_invariant("CLUSTER after peek");
                let cluster_start = cluster_tok.span.start;
                // Consume BY
                if let Some(by_tok) = parser.peek() {
                    if matches!(by_tok.kind, TokenKind::Keyword(Keyword::By)) {
                        parser.advance(); // consume BY
                    }
                }
                // Consume the cluster expression — may be parenthesized or comma-separated list
                // Stop at OPTIONS, AS, or ;
                let mut paren_depth: u32 = 0;
                while let Some(t) = parser.peek() {
                    match t.kind {
                        TokenKind::Punctuation(crate::lexer::Punctuation::LParen) => {
                            paren_depth += 1;
                            parser.advance();
                        }
                        TokenKind::Punctuation(crate::lexer::Punctuation::RParen) => {
                            paren_depth = paren_depth.saturating_sub(1);
                            parser.advance();
                            if paren_depth == 0 {
                                break;
                            }
                        }
                        TokenKind::Keyword(Keyword::As)
                        | TokenKind::Eof
                        | TokenKind::Punctuation(crate::lexer::Punctuation::Semi)
                            if paren_depth == 0 =>
                        {
                            break
                        }
                        _ if paren_depth == 0
                            && t.lexeme(parser.source).eq_ignore_ascii_case("OPTIONS") =>
                        {
                            break
                        }
                        // BQ can have unparenthesized CLUSTER BY col1, col2 — stop at AS or OPTIONS
                        TokenKind::Keyword(Keyword::Partition) if paren_depth == 0 => break,
                        _ => {
                            parser.advance();
                        }
                    }
                }
                let cluster_end = parser.tokens[parser.idx.saturating_sub(1)].span.end;
                cluster_by_span = Some(Span {
                    start: cluster_start,
                    end: cluster_end,
                });
                span.end = cluster_end;
            }
        }

        // OPTIONS(...) (BigQuery)
        // OPTIONS tokenizes as Identifier — match via lexeme
        if let Some(tok) = parser.peek() {
            if tok.lexeme(parser.source).eq_ignore_ascii_case("OPTIONS") {
                let options_tok = parser.advance().expect_invariant("OPTIONS after peek");
                let options_start = options_tok.span.start;
                // Consume parenthesized options list
                let mut paren_depth: u32 = 0;
                while let Some(t) = parser.peek() {
                    match t.kind {
                        TokenKind::Punctuation(crate::lexer::Punctuation::LParen) => {
                            paren_depth += 1;
                            parser.advance();
                        }
                        TokenKind::Punctuation(crate::lexer::Punctuation::RParen) => {
                            paren_depth = paren_depth.saturating_sub(1);
                            parser.advance();
                            if paren_depth == 0 {
                                break;
                            }
                        }
                        TokenKind::Eof
                        | TokenKind::Punctuation(crate::lexer::Punctuation::Semi) => break,
                        _ => {
                            parser.advance();
                        }
                    }
                }
                let options_end = parser.tokens[parser.idx.saturating_sub(1)].span.end;
                bq_options_span = Some(Span {
                    start: options_start,
                    end: options_end,
                });
                span.end = options_end;
            }
        }
    }

    // After materialized-view-specific clauses (PARTITION BY, CLUSTER BY, OPTIONS),
    // there may be remaining view options like COMMENT = '...' that appear after
    // CLUSTER BY in Snowflake syntax. Reuse the existing options parser.
    if materialized_span.is_some() {
        let trailing_start = parser.idx;
        while let Some(tok) = parser.peek() {
            if parser.should_stop_scan_at_statement_start(tok) {
                break;
            }
            match tok.kind {
                TokenKind::Keyword(Keyword::As)
                | TokenKind::Eof
                | TokenKind::Punctuation(crate::lexer::Punctuation::Semi) => break,
                _ => {
                    parser.advance();
                }
            }
        }
        let trailing_end = parser.idx;
        if trailing_end > trailing_start {
            let trailing = parse_create_view_options(parser, trailing_start, trailing_end);
            if comment_span.is_none() {
                comment_span = trailing.comment_span;
            }
            span.end = parser.tokens[trailing_end - 1].span.end;
        }
    }

    // Expect AS keyword
    let as_tok = parser.peek().ok_or_else(|| {
        ParseError::new(
            parser.current_span(),
            ParseErrorKind::InvalidStatement {
                message: "CREATE VIEW requires AS keyword before query definition".to_string(),
            },
        )
    })?;
    if !as_tok.lexeme(parser.source).eq_ignore_ascii_case("AS") {
        return Err(ParseError::new(
            as_tok.span,
            ParseErrorKind::InvalidStatement {
                message: format!(
                    "Expected AS keyword in CREATE VIEW, found {}",
                    Parser::token_description(as_tok, parser.source)
                ),
            },
        ));
    }
    parser.advance(); // consume AS

    // Check for BigQuery AS REPLICA OF source_view variant
    // REPLICA tokenizes as Identifier — match via lexeme
    let mut replica_of_span: Option<Span> = None;
    if materialized_span.is_some() {
        if let Some(tok) = parser.peek() {
            if tok.lexeme(parser.source).eq_ignore_ascii_case("REPLICA") {
                let replica_tok = parser.advance().expect_invariant("REPLICA after peek");
                let replica_start = replica_tok.span.start;
                // Consume OF keyword
                if let Some(of_tok) = parser.peek() {
                    if matches!(of_tok.kind, TokenKind::Keyword(Keyword::Of)) {
                        parser.advance(); // consume OF
                    }
                }
                // Consume the source view name (qualified name: project.dataset.view)
                while let Some(t) = parser.peek() {
                    match t.kind {
                        TokenKind::Eof
                        | TokenKind::Punctuation(crate::lexer::Punctuation::Semi) => break,
                        TokenKind::Identifier { .. }
                        | TokenKind::Punctuation(crate::lexer::Punctuation::Dot) => {
                            parser.advance();
                        }
                        _ => break,
                    }
                }
                let replica_end = parser.tokens[parser.idx.saturating_sub(1)].span.end;
                replica_of_span = Some(Span {
                    start: replica_start,
                    end: replica_end,
                });
                span.end = replica_end;
            }
        }
    }

    // Parse query or skip if REPLICA OF was found
    let query_result: Result<Box<AstStmt>, Span> = if replica_of_span.is_some() {
        // No query for REPLICA OF — use a dummy Err span
        Err(Span { start: 0, end: 0 })
    } else {
        // Check for optional opening parenthesis before the query
        let has_opening_paren = if let Some(tok) = parser.peek() {
            matches!(
                tok.kind,
                TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
            )
        } else {
            false
        };

        if has_opening_paren {
            parser.advance(); // consume opening paren
        }

        // Parse the SELECT query
        let query_start_idx = parser.idx;
        let query = parser.parse_statement();
        match query {
            Ok(stmt) => {
                span.end = stmt.span().end;

                // If there was an opening paren, expect and consume closing paren
                if has_opening_paren {
                    if let Some(closing_tok) = parser.peek() {
                        if matches!(
                            closing_tok.kind,
                            TokenKind::Punctuation(crate::lexer::Punctuation::RParen)
                        ) {
                            let closing = parser
                                .advance()
                                .expect_invariant("Closing paren should be available after peek");
                            span.end = closing.span.end;
                        }
                    }
                }

                Ok(Box::new(stmt))
            }
            Err(_) => {
                // Fallback: capture unparsed query span
                let mut query_end_idx = parser.idx;
                while query_end_idx < parser.tokens.len() {
                    let tok = &parser.tokens[query_end_idx];
                    if parser.should_stop_scan_at_statement_start(tok) {
                        break;
                    }
                    if matches!(
                        tok.kind,
                        TokenKind::Eof
                            | TokenKind::Punctuation(crate::lexer::Punctuation::Semi)
                            | TokenKind::Operator(crate::lexer::Operator::Pipe)
                    ) {
                        break;
                    }
                    query_end_idx += 1;
                }
                if query_end_idx > query_start_idx {
                    let first = &parser.tokens[query_start_idx];
                    let last = &parser.tokens[query_end_idx - 1];
                    let query_span = Span {
                        start: first.span.start,
                        end: last.span.end,
                    };
                    span.end = query_span.end;
                    parser.idx = query_end_idx;
                    Err(query_span)
                } else {
                    return Err(ParseError::new(
                        parser.current_span(),
                        ParseErrorKind::InvalidStatement {
                            message: "CREATE VIEW AS clause requires a SELECT statement"
                                .to_string(),
                        },
                    ));
                }
            }
        }
    };

    // Redshift late-binding view: trailing `WITH NO SCHEMA BINDING` after the query.
    // NO/SCHEMA/BINDING lex as identifiers, so match by lexeme. Use save/restore so a
    // partial match (e.g. a trailing CTE-style WITH) does not consume tokens.
    let mut with_no_schema_binding_span: Option<Span> = None;
    {
        let save_idx = parser.idx;
        let is_with = parser
            .peek_non_trivia()
            .map(|t| matches!(t.kind, TokenKind::Keyword(Keyword::With)))
            .unwrap_or(false);
        if is_with {
            let with_start = parser
                .advance()
                .expect_invariant("WITH after peek")
                .span
                .start;
            if let Some(no_tok) = parser.peek_non_trivia() {
                if no_tok.lexeme(parser.source).eq_ignore_ascii_case("NO") {
                    parser.advance(); // NO
                    if let Some(schema_tok) = parser.peek_non_trivia() {
                        if schema_tok
                            .lexeme(parser.source)
                            .eq_ignore_ascii_case("SCHEMA")
                        {
                            parser.advance(); // SCHEMA
                            if let Some(binding_tok) = parser.peek_non_trivia() {
                                if binding_tok
                                    .lexeme(parser.source)
                                    .eq_ignore_ascii_case("BINDING")
                                {
                                    let binding_end = binding_tok.span.end;
                                    parser.advance(); // BINDING
                                    with_no_schema_binding_span = Some(Span {
                                        start: with_start,
                                        end: binding_end,
                                    });
                                    span.end = binding_end;
                                }
                            }
                        }
                    }
                }
            }
        }
        if with_no_schema_binding_span.is_none() {
            parser.idx = save_idx;
        }
    }

    // PostgreSQL materialized view: trailing `WITH [NO] DATA` after the query.
    // DATA lexes as an identifier; match by lexeme with save/restore so a partial
    // match (e.g. a following CTE-style WITH) does not consume tokens.
    let mut with_data_clause_span: Option<Span> = None;
    {
        let save_idx = parser.idx;
        let is_with = parser
            .peek_non_trivia()
            .map(|t| matches!(t.kind, TokenKind::Keyword(Keyword::With)))
            .unwrap_or(false);
        if is_with {
            let with_start = parser
                .advance()
                .expect_invariant("WITH after peek")
                .span
                .start;
            // Optional NO
            if let Some(no_tok) = parser.peek_non_trivia() {
                if no_tok.lexeme(parser.source).eq_ignore_ascii_case("NO") {
                    parser.advance(); // NO
                }
            }
            if let Some(data_tok) = parser.peek_non_trivia() {
                if data_tok.lexeme(parser.source).eq_ignore_ascii_case("DATA") {
                    let data_end = data_tok.span.end;
                    parser.advance(); // DATA
                    with_data_clause_span = Some(Span {
                        start: with_start,
                        end: data_end,
                    });
                    span.end = data_end;
                }
            }
        }
        if with_data_clause_span.is_none() {
            parser.idx = save_idx;
        }
    }

    // MySQL / PostgreSQL updatable view: trailing `WITH [CASCADED|LOCAL] CHECK
    // OPTION` after the query. CASCADED/LOCAL/OPTION lex as identifiers; match
    // by lexeme with save/restore so a partial match does not consume tokens.
    let mut with_check_option_span: Option<Span> = None;
    let mut with_check_option_mode: Option<AstViewCheckOptionMode> = None;
    {
        let save_idx = parser.idx;
        let is_with = parser
            .peek_non_trivia()
            .map(|t| matches!(t.kind, TokenKind::Keyword(Keyword::With)))
            .unwrap_or(false);
        if is_with {
            let with_start = parser
                .advance()
                .expect_invariant("WITH after peek")
                .span
                .start;
            let mut mode = AstViewCheckOptionMode::Default;
            if let Some(m_tok) = parser.peek_non_trivia() {
                if m_tok.lexeme(parser.source).eq_ignore_ascii_case("CASCADED") {
                    parser.advance(); // CASCADED
                    mode = AstViewCheckOptionMode::Cascaded;
                } else if m_tok.lexeme(parser.source).eq_ignore_ascii_case("LOCAL") {
                    parser.advance(); // LOCAL
                    mode = AstViewCheckOptionMode::Local;
                }
            }
            if let Some(check_tok) = parser.peek_non_trivia() {
                if check_tok
                    .lexeme(parser.source)
                    .eq_ignore_ascii_case("CHECK")
                {
                    parser.advance(); // CHECK
                    if let Some(option_tok) = parser.peek_non_trivia() {
                        if option_tok
                            .lexeme(parser.source)
                            .eq_ignore_ascii_case("OPTION")
                        {
                            let option_end = option_tok.span.end;
                            parser.advance(); // OPTION
                            with_check_option_span = Some(Span {
                                start: with_start,
                                end: option_end,
                            });
                            with_check_option_mode = Some(mode);
                            span.end = option_end;
                        }
                    }
                }
            }
        }
        if with_check_option_span.is_none() {
            parser.idx = save_idx;
        }
    }

    // Parse optional WITH ROW ACCESS POLICY after the query (view-specific syntax)
    // Note: According to Snowflake docs, ROW ACCESS POLICY goes BEFORE AS, not after
    // So this section is unused - the policy is already parsed in parse_create_view_options
    // Keeping this placeholder in case we find edge cases where it appears after SELECT

    // Use row policy from view options (parsed before AS clause)
    let final_row_access_policy_span = row_access_policy_span;

    let name_span = name_span.ok_or_else(|| {
        ParseError::new(
            parser.current_span(),
            ParseErrorKind::InvalidStatement {
                message: "CREATE VIEW requires view name".to_string(),
            },
        )
    })?;

    let stmt = AstCreateView {
        node_id: parser.id_gen.next(),
        span,
        keyword_span,
        or_replace_span,
        or_alter_span,
        secure_span,
        algorithm_span,
        definer,
        sql_security,
        temp_kind_span,
        recursive_span,
        view_keyword_span,
        if_not_exists_span,
        name_span,
        columns_span,
        column_list_id,
        columns,
        row_access_policy_span: final_row_access_policy_span,
        aggregation_policy_span,
        join_policy_span,
        tag_span,
        with_contact_span,
        change_tracking_span,
        copy_grants_span,
        comment_span,
        with_options_span,
        with_options,
        options_span,
        query: query_result,
        semicolon_token: None,
        // Materialized view extensions
        materialized_span,
        partition_by_span,
        cluster_by_span,
        bq_options_span,
        replica_of_span,
        with_no_schema_binding_span,
        with_data_clause_span,
        with_check_option_span,
        with_check_option_mode,
    };

    Ok(AstStmt::CreateView(Box::new(stmt)))
}

/// Parse view column list with forward parsing: (col1 [attrs], col2 [attrs], ...)
///
/// Returns: (ast_columns, syntax_id, full_span)
fn try_parse_view_column_list(
    parser: &mut Parser,
) -> crate::error::ParseResult<(
    Vec<AstCreateViewColumn>,
    Option<crate::syntax::SyntaxViewColumnListId>,
    Option<Span>,
)> {
    use crate::syntax::SyntaxViewColumnList;

    // Expect opening paren
    let lparen_token_id = parser.current_token_id();
    let lparen = parser
        .advance()
        .ok_or_eof(parser.current_span(), vec!["(".to_string()])?;
    if !matches!(
        lparen.kind,
        TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
    ) {
        return Err(ParseError::unexpected_token(
            lparen.span,
            vec!["(".to_string()],
            Parser::token_description(lparen, parser.source),
        ));
    }

    let mut ast_columns = Vec::new();
    let mut syntax_column_ids = Vec::new();
    let mut comma_token_ids = Vec::new();

    // Parse columns until closing paren
    loop {
        // Check for closing paren
        if let Some(tok) = parser.peek() {
            if matches!(
                tok.kind,
                TokenKind::Punctuation(crate::lexer::Punctuation::RParen)
            ) {
                break;
            }
        } else {
            return Err(ParseError::unexpected_eof(
                parser.current_span(),
                vec![")".to_string()],
            ));
        }

        // Parse one column definition
        let (ast_col, syntax_col_id) = try_parse_single_view_column(parser)?;
        ast_columns.push(ast_col);
        syntax_column_ids.push(syntax_col_id);

        // Check for comma or closing paren
        if let Some(tok) = parser.peek() {
            if matches!(
                tok.kind,
                TokenKind::Punctuation(crate::lexer::Punctuation::Comma)
            ) {
                let comma_token_id = parser.current_token_id();
                parser.advance(); // consume comma
                comma_token_ids.push(comma_token_id);
            } else if !matches!(
                tok.kind,
                TokenKind::Punctuation(crate::lexer::Punctuation::RParen)
            ) {
                return Err(ParseError::unexpected_token(
                    tok.span,
                    vec![",".to_string(), ")".to_string()],
                    Parser::token_description(tok, parser.source),
                ));
            }
        }
    }

    // Consume closing paren
    let rparen_token_id = parser.current_token_id();
    let rparen = parser
        .advance()
        .ok_or_eof(parser.current_span(), vec![")".to_string()])?;

    let full_span = Span {
        start: lparen.span.start,
        end: rparen.span.end,
    };

    // Build syntax node
    let syntax_list = SyntaxViewColumnList {
        l_paren: lparen_token_id,
        r_paren: rparen_token_id,
        columns: syntax_column_ids,
        commas: comma_token_ids,
        span: full_span,
    };

    let syntax_id = parser.syntax_arena.alloc_view_column_list(syntax_list);

    Ok((ast_columns, Some(syntax_id), Some(full_span)))
}

/// Parse a single view column definition with forward parsing
///
/// Syntax: column_name [COMMENT 'text'] [[WITH] MASKING POLICY name [USING (...)]]
///         [[WITH] PROJECTION POLICY name] [[WITH] TAG (...)]
///
/// Returns: (AstCreateViewColumn, SyntaxViewColumnId)
fn try_parse_single_view_column(
    parser: &mut Parser,
) -> crate::error::ParseResult<(AstCreateViewColumn, crate::syntax::SyntaxViewColumnId)> {
    use crate::syntax::{
        SyntaxViewColumn, SyntaxViewColumnComment, SyntaxViewColumnMaskingPolicy,
        SyntaxViewColumnProjectionPolicy, SyntaxViewColumnTag,
    };

    // Parse column name
    let name_token_id = parser.current_token_id();
    let name_tok = parser
        .advance()
        .ok_or_eof(parser.current_span(), vec!["column name".to_string()])?;
    let column_start = name_tok.span.start;
    let name_span = name_tok.span;
    let mut column_end = name_tok.span.end;

    // Parse optional attributes
    let mut comment_span: Option<Span> = None;
    let mut comment_id: Option<crate::syntax::SyntaxViewColumnCommentId> = None;
    let mut masking_policy_span: Option<Span> = None;
    let mut masking_policy_id: Option<crate::syntax::SyntaxViewColumnMaskingPolicyId> = None;
    let mut projection_policy_span: Option<Span> = None;
    let mut projection_policy_id: Option<crate::syntax::SyntaxViewColumnProjectionPolicyId> = None;
    let mut tag_span: Option<Span> = None;
    let mut tag_id: Option<crate::syntax::SyntaxViewColumnTagId> = None;

    while let Some(tok) = parser.peek() {
        // Stop at comma or closing paren
        if matches!(
            tok.kind,
            TokenKind::Punctuation(crate::lexer::Punctuation::Comma)
                | TokenKind::Punctuation(crate::lexer::Punctuation::RParen)
        ) {
            break;
        }

        // COMMENT '<string>'
        if comment_id.is_none() && tok.lexeme(parser.source).eq_ignore_ascii_case("COMMENT") {
            let comment_keyword_id = parser.current_token_id();
            let comment_keyword = parser
                .advance()
                .expect_invariant("COMMENT keyword: checked in if-let above");

            if let Some(str_tok) = parser.peek() {
                if matches!(
                    str_tok.kind,
                    TokenKind::Literal(crate::lexer::LiteralKind::String)
                ) {
                    let string_literal_id = parser.current_token_id();
                    let string_literal = parser
                        .advance()
                        .expect_invariant("string literal: verified by matches! check above");
                    column_end = string_literal.span.end;

                    let span = Span {
                        start: comment_keyword.span.start,
                        end: string_literal.span.end,
                    };
                    comment_span = Some(span);
                    let comment_node = SyntaxViewColumnComment {
                        comment_keyword: comment_keyword_id,
                        string_literal: string_literal_id,
                        span,
                    };
                    comment_id = Some(parser.syntax_arena.alloc_view_column_comment(comment_node));
                    continue;
                }
            }
            continue;
        }

        // [WITH] MASKING POLICY | PROJECTION POLICY | TAG
        if tok.lexeme(parser.source).eq_ignore_ascii_case("WITH") {
            if let Some(next_tok) = parser.peek_ahead(1) {
                // WITH MASKING POLICY
                if masking_policy_id.is_none()
                    && next_tok
                        .lexeme(parser.source)
                        .eq_ignore_ascii_case("MASKING")
                {
                    let with_keyword_id = parser.current_token_id();
                    let with_tok = parser
                        .advance()
                        .expect_invariant("WITH keyword: checked in outer if-let");
                    let attr_start = with_tok.span.start;

                    let masking_keyword_id = parser.current_token_id();
                    parser.advance(); // MASKING

                    if let Some(policy_tok) = parser.peek() {
                        if policy_tok
                            .lexeme(parser.source)
                            .eq_ignore_ascii_case("POLICY")
                        {
                            let policy_keyword_id = parser.current_token_id();
                            parser.advance(); // POLICY

                            if let Some(name_tok) = parser.peek() {
                                if parser.can_be_identifier_token(name_tok) {
                                    let policy_name_id = parser.current_token_id();
                                    let name_span = parser.parse_qualified_name_span().expect_invariant("WITH MASKING POLICY name: verified can_be_identifier above");
                                    let mut attr_end = name_span.end;

                                    // Optional USING clause
                                    let mut using_keyword = None;
                                    let mut using_l_paren = None;
                                    let mut using_r_paren = None;

                                    if let Some(using_tok) = parser.peek() {
                                        if using_tok
                                            .lexeme(parser.source)
                                            .eq_ignore_ascii_case("USING")
                                        {
                                            using_keyword = Some(parser.current_token_id());
                                            parser.advance();

                                            if let Some(lparen_tok) = parser.peek() {
                                                if matches!(
                                                    lparen_tok.kind,
                                                    TokenKind::Punctuation(
                                                        crate::lexer::Punctuation::LParen
                                                    )
                                                ) {
                                                    using_l_paren = Some(parser.current_token_id());
                                                    parser.advance();

                                                    // Skip to matching rparen
                                                    let mut depth = 1;
                                                    while depth > 0 {
                                                        if let Some(t) = parser.peek() {
                                                            if matches!(t.kind, TokenKind::Punctuation(crate::lexer::Punctuation::LParen)) {
                                                                depth += 1;
                                                            } else if matches!(t.kind, TokenKind::Punctuation(crate::lexer::Punctuation::RParen)) {
                                                                depth -= 1;
                                                                if depth == 0 {
                                                                    using_r_paren = Some(parser.current_token_id());
                                                                    let rparen = parser.advance().expect_invariant("WITH MASKING USING closing paren: verified RParen match above");
                                                                    attr_end = rparen.span.end;
                                                                    break;
                                                                }
                                                            }
                                                            parser.advance();
                                                        } else {
                                                            break;
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }

                                    column_end = attr_end;
                                    let span = Span {
                                        start: attr_start,
                                        end: attr_end,
                                    };
                                    masking_policy_span = Some(span);
                                    let masking_node = SyntaxViewColumnMaskingPolicy {
                                        with_keyword: Some(with_keyword_id),
                                        masking_keyword: masking_keyword_id,
                                        policy_keyword: policy_keyword_id,
                                        policy_name: policy_name_id,
                                        using_keyword,
                                        using_l_paren,
                                        using_r_paren,
                                        span,
                                    };
                                    masking_policy_id = Some(
                                        parser
                                            .syntax_arena
                                            .alloc_view_column_masking_policy(masking_node),
                                    );
                                    continue;
                                }
                            }
                        }
                    }
                    continue;
                } else if projection_policy_id.is_none()
                    && next_tok
                        .lexeme(parser.source)
                        .eq_ignore_ascii_case("PROJECTION")
                {
                    // WITH PROJECTION POLICY
                    let with_keyword_id = parser.current_token_id();
                    let with_tok = parser
                        .advance()
                        .expect_invariant("WITH keyword: checked in outer if-let");
                    let attr_start = with_tok.span.start;

                    let projection_keyword_id = parser.current_token_id();
                    parser.advance(); // PROJECTION

                    if let Some(policy_tok2) = parser.peek() {
                        if policy_tok2
                            .lexeme(parser.source)
                            .eq_ignore_ascii_case("POLICY")
                        {
                            let policy_keyword_id = parser.current_token_id();
                            parser.advance(); // POLICY

                            if let Some(name_tok) = parser.peek() {
                                if parser.can_be_identifier_token(name_tok) {
                                    let policy_name_id = parser.current_token_id();
                                    let name_span = parser
                                        .parse_qualified_name_span()
                                        .expect_invariant(
                                        "projection policy name: verified can_be_identifier above",
                                    );
                                    column_end = name_span.end;

                                    let span = Span {
                                        start: attr_start,
                                        end: column_end,
                                    };
                                    projection_policy_span = Some(span);
                                    let projection_node = SyntaxViewColumnProjectionPolicy {
                                        with_keyword: Some(with_keyword_id),
                                        projection_keyword: projection_keyword_id,
                                        policy_keyword: policy_keyword_id,
                                        policy_name: policy_name_id,
                                        span,
                                    };
                                    projection_policy_id = Some(
                                        parser
                                            .syntax_arena
                                            .alloc_view_column_projection_policy(projection_node),
                                    );
                                    continue;
                                }
                            }
                        }
                    }
                    continue;
                } else if tag_id.is_none()
                    && next_tok.lexeme(parser.source).eq_ignore_ascii_case("TAG")
                {
                    // WITH TAG
                    let with_keyword_id = parser.current_token_id();
                    let with_tok = parser
                        .advance()
                        .expect_invariant("WITH keyword: checked in outer if-let");
                    let attr_start = with_tok.span.start;

                    let tag_keyword_id = parser.current_token_id();
                    parser.advance(); // TAG

                    if let Some(lparen_tok) = parser.peek() {
                        if matches!(
                            lparen_tok.kind,
                            TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
                        ) {
                            let l_paren_id = parser.current_token_id();
                            parser.advance();

                            let mut depth = 1;
                            let mut r_paren_id = None;
                            while depth > 0 {
                                if let Some(t) = parser.peek() {
                                    if matches!(
                                        t.kind,
                                        TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
                                    ) {
                                        depth += 1;
                                    } else if matches!(
                                        t.kind,
                                        TokenKind::Punctuation(crate::lexer::Punctuation::RParen)
                                    ) {
                                        depth -= 1;
                                        if depth == 0 {
                                            r_paren_id = Some(parser.current_token_id());
                                            let rparen = parser.advance().expect_invariant(
                                                "closing paren: verified RParen match above",
                                            );
                                            column_end = rparen.span.end;
                                            break;
                                        }
                                    }
                                    parser.advance();
                                } else {
                                    break;
                                }
                            }

                            if let Some(r_paren) = r_paren_id {
                                let span = Span {
                                    start: attr_start,
                                    end: column_end,
                                };
                                tag_span = Some(span);
                                let tag_node = SyntaxViewColumnTag {
                                    with_keyword: Some(with_keyword_id),
                                    tag_keyword: tag_keyword_id,
                                    l_paren: l_paren_id,
                                    r_paren,
                                    span,
                                };
                                tag_id = Some(parser.syntax_arena.alloc_view_column_tag(tag_node));
                                continue;
                            }
                        }
                    }
                    continue;
                }
            }
        }

        // MASKING POLICY (without WITH)
        if masking_policy_id.is_none() && tok.lexeme(parser.source).eq_ignore_ascii_case("MASKING")
        {
            let masking_keyword_id = parser.current_token_id();
            let masking_tok = parser
                .advance()
                .expect_invariant("MASKING keyword: checked in if-let above");
            let attr_start = masking_tok.span.start;

            if let Some(policy_tok) = parser.peek() {
                if policy_tok
                    .lexeme(parser.source)
                    .eq_ignore_ascii_case("POLICY")
                {
                    let policy_keyword_id = parser.current_token_id();
                    parser.advance();

                    if let Some(name_tok) = parser.peek() {
                        if parser.can_be_identifier_token(name_tok) {
                            let policy_name_id = parser.current_token_id();
                            let name_span = parser.parse_qualified_name_span().expect_invariant(
                                "masking policy name: verified can_be_identifier above",
                            );
                            let mut attr_end = name_span.end;

                            // Optional USING clause
                            let mut using_keyword = None;
                            let mut using_l_paren = None;
                            let mut using_r_paren = None;

                            if let Some(using_tok) = parser.peek() {
                                if using_tok
                                    .lexeme(parser.source)
                                    .eq_ignore_ascii_case("USING")
                                {
                                    using_keyword = Some(parser.current_token_id());
                                    parser.advance();

                                    if let Some(lparen_tok) = parser.peek() {
                                        if matches!(
                                            lparen_tok.kind,
                                            TokenKind::Punctuation(
                                                crate::lexer::Punctuation::LParen
                                            )
                                        ) {
                                            using_l_paren = Some(parser.current_token_id());
                                            parser.advance();

                                            let mut depth = 1;
                                            while depth > 0 {
                                                if let Some(t) = parser.peek() {
                                                    if matches!(
                                                        t.kind,
                                                        TokenKind::Punctuation(
                                                            crate::lexer::Punctuation::LParen
                                                        )
                                                    ) {
                                                        depth += 1;
                                                    } else if matches!(
                                                        t.kind,
                                                        TokenKind::Punctuation(
                                                            crate::lexer::Punctuation::RParen
                                                        )
                                                    ) {
                                                        depth -= 1;
                                                        if depth == 0 {
                                                            using_r_paren =
                                                                Some(parser.current_token_id());
                                                            let rparen = parser.advance().expect_invariant("USING closing paren: verified RParen match above");
                                                            attr_end = rparen.span.end;
                                                            break;
                                                        }
                                                    }
                                                    parser.advance();
                                                } else {
                                                    break;
                                                }
                                            }
                                        }
                                    }
                                }
                            }

                            column_end = attr_end;
                            let span = Span {
                                start: attr_start,
                                end: attr_end,
                            };
                            masking_policy_span = Some(span);
                            let masking_node = SyntaxViewColumnMaskingPolicy {
                                with_keyword: None,
                                masking_keyword: masking_keyword_id,
                                policy_keyword: policy_keyword_id,
                                policy_name: policy_name_id,
                                using_keyword,
                                using_l_paren,
                                using_r_paren,
                                span,
                            };
                            masking_policy_id = Some(
                                parser
                                    .syntax_arena
                                    .alloc_view_column_masking_policy(masking_node),
                            );
                            continue;
                        }
                    }
                }
            }
            continue;
        }

        // PROJECTION POLICY (without WITH)
        if projection_policy_id.is_none()
            && tok.lexeme(parser.source).eq_ignore_ascii_case("PROJECTION")
        {
            let projection_keyword_id = parser.current_token_id();
            let projection_tok = parser
                .advance()
                .expect_invariant("PROJECTION keyword: checked in if-let above");
            let attr_start = projection_tok.span.start;

            if let Some(policy_tok) = parser.peek() {
                if policy_tok
                    .lexeme(parser.source)
                    .eq_ignore_ascii_case("POLICY")
                {
                    let policy_keyword_id = parser.current_token_id();
                    parser.advance();

                    if let Some(name_tok) = parser.peek() {
                        if parser.can_be_identifier_token(name_tok) {
                            let policy_name_id = parser.current_token_id();
                            let name_span = parser.parse_qualified_name_span().expect_invariant(
                                "projection policy name: verified can_be_identifier above",
                            );
                            column_end = name_span.end;

                            let span = Span {
                                start: attr_start,
                                end: column_end,
                            };
                            projection_policy_span = Some(span);
                            let projection_node = SyntaxViewColumnProjectionPolicy {
                                with_keyword: None,
                                projection_keyword: projection_keyword_id,
                                policy_keyword: policy_keyword_id,
                                policy_name: policy_name_id,
                                span,
                            };
                            projection_policy_id = Some(
                                parser
                                    .syntax_arena
                                    .alloc_view_column_projection_policy(projection_node),
                            );
                            continue;
                        }
                    }
                }
            }
            continue;
        }

        // TAG (without WITH)
        if tag_id.is_none() && tok.lexeme(parser.source).eq_ignore_ascii_case("TAG") {
            let tag_keyword_id = parser.current_token_id();
            let tag_tok = parser
                .advance()
                .expect_invariant("TAG keyword: checked in if-let above");
            let attr_start = tag_tok.span.start;

            if let Some(lparen_tok) = parser.peek() {
                if matches!(
                    lparen_tok.kind,
                    TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
                ) {
                    let l_paren_id = parser.current_token_id();
                    parser.advance();

                    let mut depth = 1;
                    let mut r_paren_id = None;
                    while depth > 0 {
                        if let Some(t) = parser.peek() {
                            if matches!(
                                t.kind,
                                TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
                            ) {
                                depth += 1;
                            } else if matches!(
                                t.kind,
                                TokenKind::Punctuation(crate::lexer::Punctuation::RParen)
                            ) {
                                depth -= 1;
                                if depth == 0 {
                                    r_paren_id = Some(parser.current_token_id());
                                    let rparen = parser.advance().expect_invariant(
                                        "TAG closing paren: verified RParen match above",
                                    );
                                    column_end = rparen.span.end;
                                    break;
                                }
                            }
                            parser.advance();
                        } else {
                            break;
                        }
                    }

                    if let Some(r_paren) = r_paren_id {
                        let span = Span {
                            start: attr_start,
                            end: column_end,
                        };
                        tag_span = Some(span);
                        let tag_node = SyntaxViewColumnTag {
                            with_keyword: None,
                            tag_keyword: tag_keyword_id,
                            l_paren: l_paren_id,
                            r_paren,
                            span,
                        };
                        tag_id = Some(parser.syntax_arena.alloc_view_column_tag(tag_node));
                        continue;
                    }
                }
            }
            continue;
        }

        // Skip unrecognized token
        parser.advance();
    }

    // Build syntax node
    let column_span = Span {
        start: column_start,
        end: column_end,
    };

    let syntax_column = SyntaxViewColumn {
        name: name_token_id,
        comment_id,
        masking_policy_id,
        projection_policy_id,
        tag_id,
        span: column_span,
    };

    let syntax_id = parser.syntax_arena.alloc_view_column(syntax_column);

    // Build AST node
    let ast_column = AstCreateViewColumn {
        node_id: parser.id_gen.next(),
        name_span,
        comment_span,
        masking_policy_span,
        projection_policy_span,
        tag_span,
        full_span: column_span,
    };

    Ok((ast_column, syntax_id))
}

/// Parse view-level options (policies, tags, change tracking, etc.)
fn parse_create_view_options(
    parser: &Parser,
    start_idx: usize,
    end_idx: usize,
) -> CreateViewOptions {
    let mut row_access_policy_span = None;
    let mut aggregation_policy_span = None;
    let mut join_policy_span = None;
    let mut tag_span = None;
    let mut with_contact_span = None;
    let mut change_tracking_span = None;
    let mut copy_grants_span = None;
    let mut comment_span = None;
    let mut with_options_span = None;
    let mut with_options: Vec<AstObjectProperty> = Vec::new();

    let mut idx = start_idx;
    while idx < end_idx {
        let tok = &parser.tokens[idx];

        if tok.lexeme(parser.source).eq_ignore_ascii_case("ROW")
            || tok.lexeme(parser.source).eq_ignore_ascii_case("WITH")
        {
            // Check for ROW ACCESS POLICY or WITH ROW ACCESS POLICY
            let start = tok.span.start;
            let mut is_row_access = false;
            let mut temp_idx = idx;

            if tok.lexeme(parser.source).eq_ignore_ascii_case("WITH") {
                temp_idx += 1;
                if temp_idx < end_idx {
                    let next = &parser.tokens[temp_idx];
                    if next.lexeme(parser.source).eq_ignore_ascii_case("ROW") {
                        is_row_access = true;
                    }
                }
            } else if tok.lexeme(parser.source).eq_ignore_ascii_case("ROW") {
                is_row_access = true;
            }

            if is_row_access {
                // Scan to end of policy clause (before next keyword)
                while idx < end_idx {
                    let t = &parser.tokens[idx];
                    if is_view_options_boundary(t.lexeme(parser.source)) {
                        break;
                    }
                    idx += 1;
                }
                let end = parser.tokens[idx.saturating_sub(1)].span.end;
                row_access_policy_span = Some(Span { start, end });
                continue;
            }

            // PostgreSQL view options: WITH ( option [= value], ... )
            if tok.lexeme(parser.source).eq_ignore_ascii_case("WITH")
                && idx + 1 < end_idx
                && matches!(
                    parser.tokens[idx + 1].kind,
                    TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
                )
            {
                let close_idx = find_matching_paren(parser.tokens, idx + 2, end_idx);
                let mut i = idx + 2;
                while i < close_idx {
                    if matches!(
                        parser.tokens[i].kind,
                        TokenKind::Punctuation(crate::lexer::Punctuation::Comma)
                    ) {
                        i += 1;
                        continue;
                    }
                    let name_span = parser.tokens[i].span;
                    i += 1;
                    // Optional `= value`; value runs to the next top-level comma.
                    let mut value_span: Option<Span> = None;
                    if i < close_idx
                        && matches!(
                            parser.tokens[i].kind,
                            TokenKind::Operator(crate::lexer::Operator::Eq)
                        )
                    {
                        i += 1;
                        let value_start = i;
                        let mut depth: usize = 0;
                        while i < close_idx {
                            let vk = &parser.tokens[i].kind;
                            if matches!(
                                vk,
                                TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
                            ) {
                                depth += 1;
                            } else if matches!(
                                vk,
                                TokenKind::Punctuation(crate::lexer::Punctuation::RParen)
                            ) {
                                depth = depth.saturating_sub(1);
                            } else if depth == 0
                                && matches!(
                                    vk,
                                    TokenKind::Punctuation(crate::lexer::Punctuation::Comma)
                                )
                            {
                                break;
                            }
                            i += 1;
                        }
                        if i > value_start {
                            value_span = Some(Span {
                                start: parser.tokens[value_start].span.start,
                                end: parser.tokens[i - 1].span.end,
                            });
                        }
                    }
                    with_options.push(AstObjectProperty {
                        name_span,
                        value_span,
                    });
                }
                let end_tok_idx = close_idx.min(end_idx.saturating_sub(1));
                with_options_span = Some(Span {
                    start,
                    end: parser.tokens[end_tok_idx].span.end,
                });
                idx = close_idx + 1;
                continue;
            }
        }

        if tok
            .lexeme(parser.source)
            .eq_ignore_ascii_case("AGGREGATION")
        {
            let start = tok.span.start;
            while idx < end_idx {
                let t = &parser.tokens[idx];
                if is_view_options_boundary_agg(t.lexeme(parser.source)) {
                    break;
                }
                idx += 1;
            }
            let end = parser.tokens[idx.saturating_sub(1)].span.end;
            aggregation_policy_span = Some(Span { start, end });
            continue;
        }

        if tok.lexeme(parser.source).eq_ignore_ascii_case("JOIN") {
            // Check if this is "JOIN POLICY" not a query JOIN
            let start = tok.span.start;
            let temp_idx = idx + 1;
            if temp_idx < end_idx {
                let next = &parser.tokens[temp_idx];
                if next.lexeme(parser.source).eq_ignore_ascii_case("POLICY") {
                    while idx < end_idx {
                        let t = &parser.tokens[idx];
                        if is_view_options_boundary_join(t.lexeme(parser.source)) {
                            break;
                        }
                        idx += 1;
                    }
                    let end = parser.tokens[idx.saturating_sub(1)].span.end;
                    join_policy_span = Some(Span { start, end });
                    continue;
                }
            }
        }

        if tok.lexeme(parser.source).eq_ignore_ascii_case("TAG") {
            let start = tok.span.start;
            idx += 1;
            // Find opening paren, then use helper to find matching close
            while idx < end_idx {
                let t = &parser.tokens[idx];
                if matches!(
                    t.kind,
                    TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
                ) {
                    let close_idx = find_matching_paren(parser.tokens, idx + 1, end_idx);
                    idx = close_idx + 1;
                    break;
                }
                idx += 1;
            }
            let end = parser.tokens[idx.saturating_sub(1)].span.end;
            tag_span = Some(Span { start, end });
            continue;
        }

        if tok.lexeme(parser.source).eq_ignore_ascii_case("CONTACT") {
            let start = tok.span.start;
            idx += 1;
            if idx < end_idx
                && matches!(
                    parser.tokens[idx].kind,
                    TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
                )
            {
                let close_idx = find_matching_paren(parser.tokens, idx + 1, end_idx);
                idx = close_idx + 1;
            }
            let end = parser.tokens[idx.saturating_sub(1)].span.end;
            with_contact_span = Some(Span { start, end });
            continue;
        }

        if tok
            .lexeme(parser.source)
            .eq_ignore_ascii_case("CHANGE_TRACKING")
        {
            let start = tok.span.start;
            idx += 1;
            // CHANGE_TRACKING = TRUE/FALSE
            while idx < end_idx {
                let t = &parser.tokens[idx];
                if t.lexeme(parser.source).eq_ignore_ascii_case("TRUE")
                    || t.lexeme(parser.source).eq_ignore_ascii_case("FALSE")
                {
                    idx += 1;
                    break;
                }
                idx += 1;
            }
            let end = parser.tokens[idx.saturating_sub(1)].span.end;
            change_tracking_span = Some(Span { start, end });
            continue;
        }

        if tok.lexeme(parser.source).eq_ignore_ascii_case("COPY") {
            let start = tok.span.start;
            idx += 1;
            if idx < end_idx {
                let next = &parser.tokens[idx];
                if next.lexeme(parser.source).eq_ignore_ascii_case("GRANTS") {
                    idx += 1;
                    let end = parser.tokens[idx - 1].span.end;
                    copy_grants_span = Some(Span { start, end });
                    continue;
                }
            }
        }

        if tok.lexeme(parser.source).eq_ignore_ascii_case("COMMENT") {
            let start = tok.span.start;
            idx += 1;
            // COMMENT = 'string'
            while idx < end_idx {
                let t = &parser.tokens[idx];
                if matches!(
                    t.kind,
                    TokenKind::Literal(crate::lexer::LiteralKind::String)
                ) {
                    idx += 1;
                    break;
                }
                idx += 1;
            }
            let end = parser.tokens[idx.saturating_sub(1)].span.end;
            comment_span = Some(Span { start, end });
            continue;
        }

        idx += 1;
    }

    CreateViewOptions {
        row_access_policy_span,
        aggregation_policy_span,
        join_policy_span,
        tag_span,
        with_contact_span,
        change_tracking_span,
        copy_grants_span,
        comment_span,
        with_options_span,
        with_options,
    }
}

// =============================================================================
// Parser methods - CREATE VIEW parsing
// =============================================================================

impl Parser<'_> {
    // Wrapper method that delegates to the standalone function above.

    pub(crate) fn try_parse_create_view_stmt_with_parser(
        &mut self,
    ) -> crate::error::ParseResult<AstStmt> {
        try_parse_create_view_stmt_with_parser(self)
    }
}
