// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

// CREATE TABLE statement parsing
// Extracted from core.rs to reduce monolithic file size

use crate::ast::{
    AstCreateTable, AstCreateTableColumn, AstCreateTableConstraint, AstCreateTableVariant, AstExpr,
    AstObjectRef, AstStmt, AstTimeTravel,
};
use crate::error::{ExpectInvariant, ParseError, ParseErrorKind, ParseResult, ParseResultExt};
use crate::lexer::{Keyword, Span, TokenKind};
use crate::parser::core::Parser;
use crate::parser::tag::TagListShape;

/// Helper function to check if a token starts a table option
#[inline]
fn is_table_option_starter(lexeme: &str) -> bool {
    lexeme.eq_ignore_ascii_case("CLUSTER")
        || lexeme.eq_ignore_ascii_case("PARTITION")
        || lexeme.eq_ignore_ascii_case("COPY")
        || lexeme.eq_ignore_ascii_case("DATA_RETENTION_TIME_IN_DAYS")
        || lexeme.eq_ignore_ascii_case("MAX_DATA_EXTENSION_TIME_IN_DAYS")
        || lexeme.eq_ignore_ascii_case("ENABLE_SCHEMA_EVOLUTION")
        || lexeme.eq_ignore_ascii_case("CHANGE_TRACKING")
        || lexeme.eq_ignore_ascii_case("DEFAULT_DDL_COLLATION")
        || lexeme.eq_ignore_ascii_case("ROW")
        || lexeme.eq_ignore_ascii_case("AGGREGATION")
        || lexeme.eq_ignore_ascii_case("JOIN")
        || lexeme.eq_ignore_ascii_case("STORAGE")
        || lexeme.eq_ignore_ascii_case("TAG")
        || lexeme.eq_ignore_ascii_case("WITH")
        || lexeme.eq_ignore_ascii_case("COMMENT")
        // Redshift physical-layout options.
        || lexeme.eq_ignore_ascii_case("DISTSTYLE")
        || lexeme.eq_ignore_ascii_case("DISTKEY")
        || lexeme.eq_ignore_ascii_case("SORTKEY")
        || lexeme.eq_ignore_ascii_case("COMPOUND")
        || lexeme.eq_ignore_ascii_case("INTERLEAVED")
        || lexeme.eq_ignore_ascii_case("BACKUP")
}

/// Helper to check if a lexeme is a time travel clause boundary keyword
#[inline]
fn is_time_travel_boundary(lexeme: &str) -> bool {
    lexeme.eq_ignore_ascii_case("AT")
        || lexeme.eq_ignore_ascii_case("BEFORE")
        || lexeme.eq_ignore_ascii_case("USING")
        || lexeme.eq_ignore_ascii_case("FROM")
}

/// Helper to check if a lexeme is a column tail clause keyword
#[inline]
/// Storage keyword closing a generated-column expression:
/// MySQL `VIRTUAL`/`STORED`, PG `STORED`, MSSQL `PERSISTED`.
pub(crate) fn is_generated_storage_lexeme(lexeme: &str) -> bool {
    lexeme.eq_ignore_ascii_case("VIRTUAL")
        || lexeme.eq_ignore_ascii_case("STORED")
        || lexeme.eq_ignore_ascii_case("PERSISTED")
}

pub(crate) fn is_column_tail_clause_lexeme(lexeme: &str) -> bool {
    lexeme.eq_ignore_ascii_case("DEFAULT")
        || lexeme.eq_ignore_ascii_case("NOT")
        || lexeme.eq_ignore_ascii_case("CONSTRAINT")
        || lexeme.eq_ignore_ascii_case("PRIMARY")
        || lexeme.eq_ignore_ascii_case("UNIQUE")
        || lexeme.eq_ignore_ascii_case("FOREIGN")
        || lexeme.eq_ignore_ascii_case("CHECK")
        || lexeme.eq_ignore_ascii_case("REFERENCES")
        || lexeme.eq_ignore_ascii_case("MASKING")
        || lexeme.eq_ignore_ascii_case("TAG")
        || lexeme.eq_ignore_ascii_case("COMMENT")
        || lexeme.eq_ignore_ascii_case("COLLATE")
        || lexeme.eq_ignore_ascii_case("IDENTITY")
        || lexeme.eq_ignore_ascii_case("AUTOINCREMENT")
        || lexeme.eq_ignore_ascii_case("AUTO_INCREMENT")
}

/// A policy clause as read: the policy's name and the columns of the list
/// written after it.
pub(crate) struct PolicyClause {
    /// The index past the clause.
    pub(crate) next: usize,
    pub(crate) policy: AstObjectRef,
    pub(crate) columns: Vec<Span>,
}

impl PolicyClause {
    /// The policy and columns of `clause`, empty where none was read.
    pub(crate) fn parts(clause: Option<Self>) -> (Option<AstObjectRef>, Vec<Span>) {
        clause
            .map(|c| (Some(c.policy), c.columns))
            .unwrap_or_default()
    }
}

/// The policies a table's options name.
#[derive(Default)]
struct TablePolicies {
    row_access: Option<PolicyClause>,
    aggregation: Option<PolicyClause>,
    join: Option<PolicyClause>,
    row_filter: Option<PolicyClause>,
}

impl TablePolicies {
    /// `self`, each policy it does not hold taken from `other`.
    fn or(self, other: Self) -> Self {
        Self {
            row_access: self.row_access.or(other.row_access),
            aggregation: self.aggregation.or(other.aggregation),
            join: self.join.or(other.join),
            row_filter: self.row_filter.or(other.row_filter),
        }
    }
}

/// `span`, widened to cover `held` where one is held.
fn joined(held: Option<Span>, span: Span) -> Span {
    held.map_or(span, |held| Span {
        start: held.start.min(span.start),
        end: held.end.max(span.end),
    })
}

/// A `PARTITION OF parent …` clause as read.
struct PartitionOfClause {
    /// The index past the clause: its column list and its bound.
    next: usize,
    parent: AstObjectRef,
}

/// The tables the options of a table name as its sources.
#[derive(Default)]
struct TableSources {
    copy: Option<AstObjectRef>,
    partition_of: Option<AstObjectRef>,
    inherits: Vec<AstObjectRef>,
}

impl TableSources {
    /// `self`, each source it does not hold taken from `other`.
    fn or(self, other: Self) -> Self {
        Self {
            copy: self.copy.or(other.copy),
            partition_of: self.partition_of.or(other.partition_of),
            inherits: if self.inherits.is_empty() {
                other.inherits
            } else {
                self.inherits
            },
        }
    }
}

impl Parser<'_> {
    /// Parse column definitions and constraints within CREATE TABLE, and
    /// the tables of its `LIKE table` items.
    pub(crate) fn parse_create_table_columns_and_constraints(
        &mut self,
        start_idx: usize,
        end_idx: usize,
    ) -> (
        Vec<AstCreateTableColumn>,
        Vec<AstCreateTableConstraint>,
        Vec<crate::ast::AstTableLikeItem>,
    ) {
        let mut columns = Vec::new();
        let mut constraints = Vec::new();
        let mut like_elements = Vec::new();

        if end_idx <= start_idx {
            return (columns, constraints, like_elements);
        }

        // Find comma separators for items
        let mut items_ranges = Vec::new();
        let mut item_start = start_idx;
        let mut depth = 0;

        for i in start_idx..end_idx {
            let t = &self.tokens[i];
            match &t.kind {
                TokenKind::Punctuation(crate::lexer::Punctuation::LParen) => depth += 1,
                TokenKind::Punctuation(crate::lexer::Punctuation::RParen) => depth -= 1,
                TokenKind::Punctuation(crate::lexer::Punctuation::Comma) if depth == 0 => {
                    items_ranges.push((item_start, i));
                    item_start = i + 1;
                }
                _ => {}
            }
        }
        if item_start < end_idx {
            items_ranges.push((item_start, end_idx));
        }

        // Process each item
        for (item_start_idx, item_end_idx) in items_ranges {
            if let Some(table) = self.like_element_in(item_start_idx, item_end_idx) {
                like_elements.push(table);
                continue;
            }
            self.build_create_table_item(
                item_start_idx,
                item_end_idx,
                &mut columns,
                &mut constraints,
            );
        }

        (columns, constraints, like_elements)
    }

    /// The column-list item `LIKE table [INCLUDING …]` in tokens
    /// `start..end`; `None` for any other item.
    fn like_element_in(&self, start: usize, end: usize) -> Option<crate::ast::AstTableLikeItem> {
        let like = self.tokens.get(start)?;
        if !matches!(like.kind, TokenKind::Keyword(Keyword::Like)) {
            return None;
        }
        let last = self.tokens.get(end.checked_sub(1)?)?;
        self.object_ref_at(start + 1, self.id_gen.next())
            .filter(|(next, _)| *next <= end)
            .map(|(_, table)| crate::ast::AstTableLikeItem {
                table,
                span: Span {
                    start: like.span.start,
                    end: last.span.end,
                },
            })
    }

    /// Parse table variant (LIKE, CLONE, AS SELECT, etc.) and associated spans
    #[allow(clippy::type_complexity)]
    fn parse_create_table_variant(
        &mut self,
        span: &mut Span,
    ) -> (
        AstCreateTableVariant,
        Option<Span>,                       // like_source_span
        Option<Span>,                       // clone_source_span
        Option<Result<Box<AstStmt>, Span>>, // ctas_query - parsed AST or fallback span
        Option<Span>,                       // time_travel_at_span
        Option<Span>,                       // time_travel_before_span
        Option<AstTimeTravel>,              // time_travel (structured)
        Option<Span>,                       // using_template_span
        Option<Span>,                       // from_archive_span
        Option<Span>,                       // from_snapshot_set_span
        Option<crate::ast::CloneKind>,      // clone_kind (Databricks DEEP/SHALLOW)
        Option<Span>,                       // clone_kind_span (Databricks DEEP/SHALLOW keyword)
        Option<Span>,                       // clone_tblproperties_span (Databricks)
        Option<Span>,                       // clone_location_span (Databricks)
        Option<Span>,         // clone_temporal_span (Databricks TIMESTAMP/VERSION AS OF)
        Option<AstObjectRef>, // like_source
        Option<AstObjectRef>, // clone_source
    ) {
        let mut variant = AstCreateTableVariant::Plain;
        let mut like_source_span = None;
        let mut clone_source_span = None;
        let mut like_source = None;
        let mut clone_source = None;
        let mut ctas_query_span = None;
        let mut time_travel_at_span = None;
        let mut time_travel_before_span = None;
        let mut time_travel_obj = None;
        let mut using_template_span = None;
        let mut from_archive_span = None;
        let mut from_snapshot_set_span = None;
        let mut clone_kind = None;
        let mut clone_kind_span = None;
        let mut clone_tblproperties_span = None;
        let mut clone_location_span = None;
        let mut clone_temporal_span = None;

        let is_using_template_start = |parser: &Parser<'_>| {
            parser.peek().is_some_and(|t| {
                t.lexeme(parser.source).eq_ignore_ascii_case("USING")
                    && parser
                        .tokens
                        .get(parser.idx + 1)
                        .is_some_and(|n| n.lexeme(parser.source).eq_ignore_ascii_case("TEMPLATE"))
            })
        };

        // Databricks: Check for DEEP/SHALLOW prefix before CLONE
        if let Some(tok) = self.peek() {
            if (tok.lexeme(self.source).eq_ignore_ascii_case("DEEP")
                || tok.lexeme(self.source).eq_ignore_ascii_case("SHALLOW"))
                && self
                    .tokens
                    .get(self.idx + 1)
                    .is_some_and(|t| t.lexeme(self.source).eq_ignore_ascii_case("CLONE"))
            {
                clone_kind = Some(if tok.lexeme(self.source).eq_ignore_ascii_case("DEEP") {
                    crate::ast::CloneKind::Deep
                } else {
                    crate::ast::CloneKind::Shallow
                });
                clone_kind_span = Some(tok.span); // Capture the DEEP/SHALLOW span
                self.advance(); // consume DEEP/SHALLOW
                                // Now peek() will see CLONE, falling through to the existing CLONE branch
            }
        }

        if let Some(tok) = self.peek() {
            if tok.lexeme(self.source).eq_ignore_ascii_case("LIKE") {
                let start = tok.span.start;
                self.advance();
                // The source's name is read whole: a part named like an
                // option (`d1.copy.src`) does not end it.
                self.skip_trivia();
                like_source = self.parse_object_ref().ok();
                let mut end = like_source.as_ref().map_or(start, |name| name.span.end);
                while let Some(t) = self.peek() {
                    match t.kind {
                        TokenKind::Eof
                        | TokenKind::Punctuation(crate::lexer::Punctuation::Semi)
                        | TokenKind::Operator(crate::lexer::Operator::Pipe) => break,
                        _ if is_table_option_starter(t.lexeme(self.source)) => break,
                        _ => {
                            let t2 = self.advance().expect_invariant(
                                "LIKE source token should be available after peek",
                            );
                            end = t2.span.end;
                        }
                    }
                }
                like_source_span = Some(Span { start, end });
                variant = AstCreateTableVariant::Like;
                span.end = end;
            } else if tok.lexeme(self.source).eq_ignore_ascii_case("CLONE") {
                let start = tok.span.start;
                self.advance();
                let source_start_idx = self.idx;
                // The source's name is read whole: a part named like a
                // clause (`d1.version.src`) does not end it.
                self.skip_trivia();
                clone_source = self.parse_object_ref().ok();

                // Capture source until time-travel or major clauses
                while let Some(t) = self.peek() {
                    if t.lexeme(self.source).eq_ignore_ascii_case("AT")
                        || t.lexeme(self.source).eq_ignore_ascii_case("BEFORE")
                        || t.lexeme(self.source).eq_ignore_ascii_case("USING")
                        || t.lexeme(self.source).eq_ignore_ascii_case("FROM")
                        // Databricks temporal + options
                        || t.lexeme(self.source).eq_ignore_ascii_case("TIMESTAMP")
                        || t.lexeme(self.source).eq_ignore_ascii_case("VERSION")
                        || t.lexeme(self.source).eq_ignore_ascii_case("TBLPROPERTIES")
                        || t.lexeme(self.source).eq_ignore_ascii_case("LOCATION")
                        // Table options (COPY GRANTS/TAGS, CLUSTER BY, etc.)
                        || is_table_option_starter(t.lexeme(self.source))
                    {
                        break;
                    }
                    match t.kind {
                        TokenKind::Eof
                        | TokenKind::Punctuation(crate::lexer::Punctuation::Semi)
                        | TokenKind::Operator(crate::lexer::Operator::Pipe) => break,
                        _ => {
                            self.advance();
                        }
                    }
                }

                let source_end_idx = self.idx;
                let mut end = start;
                if source_end_idx > source_start_idx {
                    let last = &self.tokens[source_end_idx - 1];
                    end = last.span.end;
                    clone_source_span = Some(Span { start, end });
                }
                variant = AstCreateTableVariant::Clone;
                span.end = end;

                // Parse optional time-travel clause using parse_time_travel()
                // This will properly parse AT/BEFORE (TIMESTAMP => ...) etc
                if let Some(t) = self.peek() {
                    if t.lexeme(self.source).eq_ignore_ascii_case("AT")
                        || t.lexeme(self.source).eq_ignore_ascii_case("BEFORE")
                    {
                        // Store the parsed time travel structure
                        if let Some(tt) = self.parse_time_travel().ok().flatten() {
                            time_travel_at_span = Some(tt.span);
                            span.end = tt.span.end;
                            time_travel_obj = Some(tt);
                        }
                    }
                }

                // Legacy: Also check for time travel clauses via span search (fallback)
                if time_travel_at_span.is_none() {
                    let (at_span, before_span) = self.parse_time_travel_clauses(source_end_idx);
                    time_travel_at_span = at_span;
                    time_travel_before_span = before_span;
                    if let Some(s) = &time_travel_at_span {
                        span.end = span.end.max(s.end);
                    }
                    if let Some(s) = &time_travel_before_span {
                        span.end = span.end.max(s.end);
                    }

                    // Advance parser position past the time travel clause
                    if time_travel_at_span.is_some() || time_travel_before_span.is_some() {
                        // Find the end position of the time travel clause
                        let max_end = time_travel_at_span
                            .as_ref()
                            .map(|s| s.end)
                            .max(time_travel_before_span.as_ref().map(|s| s.end))
                            .unwrap_or(span.end);

                        // Advance self.idx to the token after the time travel clause
                        while self.idx < self.tokens.len() {
                            let t = &self.tokens[self.idx];
                            if t.span.start >= max_end {
                                break;
                            }
                            self.idx += 1;
                        }
                    }
                }

                // Databricks temporal spec: TIMESTAMP AS OF / VERSION AS OF
                if clone_temporal_span.is_none() && time_travel_obj.is_none() {
                    if let Some(t) = self.peek() {
                        if t.lexeme(self.source).eq_ignore_ascii_case("TIMESTAMP")
                            || t.lexeme(self.source).eq_ignore_ascii_case("VERSION")
                        {
                            let temporal_start = t.span.start;
                            self.advance(); // consume TIMESTAMP/VERSION

                            // Expect AS OF <value>
                            if let Some(as_tok) = self.peek() {
                                if matches!(as_tok.kind, TokenKind::Keyword(Keyword::As)) {
                                    self.advance(); // consume AS
                                    if let Some(of_tok) = self.peek() {
                                        if matches!(of_tok.kind, TokenKind::Keyword(Keyword::Of)) {
                                            self.advance(); // consume OF
                                                            // Consume value expression (string literal, number, or expression)
                                            if let Some(val_tok) = self.advance() {
                                                let temporal_end = val_tok.span.end;
                                                clone_temporal_span = Some(Span {
                                                    start: temporal_start,
                                                    end: temporal_end,
                                                });
                                                span.end = temporal_end;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                // Databricks TBLPROPERTIES (...)
                if let Some(t) = self.peek() {
                    if t.lexeme(self.source).eq_ignore_ascii_case("TBLPROPERTIES") {
                        let tblprops_start = t.span.start;
                        self.advance(); // consume TBLPROPERTIES
                        self.record_option_list_secrets(self.idx);
                        // Consume balanced parentheses
                        if let Some(lp) = self.peek() {
                            if matches!(
                                lp.kind,
                                TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
                            ) {
                                let mut depth: usize = 0;
                                while let Some(t2) = self.advance() {
                                    match t2.kind {
                                        TokenKind::Punctuation(
                                            crate::lexer::Punctuation::LParen,
                                        ) => depth += 1,
                                        TokenKind::Punctuation(
                                            crate::lexer::Punctuation::RParen,
                                        ) => {
                                            depth -= 1;
                                            if depth == 0 {
                                                clone_tblproperties_span = Some(Span {
                                                    start: tblprops_start,
                                                    end: t2.span.end,
                                                });
                                                span.end = t2.span.end;
                                                break;
                                            }
                                        }
                                        TokenKind::Eof => break,
                                        _ => {}
                                    }
                                }
                            }
                        }
                    }
                }

                // Databricks LOCATION 'path'
                if let Some(t) = self.peek() {
                    if t.lexeme(self.source).eq_ignore_ascii_case("LOCATION") {
                        let loc_start = t.span.start;
                        self.advance(); // consume LOCATION
                        if let Some(val) = self.advance() {
                            clone_location_span = Some(Span {
                                start: loc_start,
                                end: val.span.end,
                            });
                            span.end = val.span.end;
                        }
                    }
                }
            } else if tok.lexeme(self.source).eq_ignore_ascii_case("AS")
                || (matches!(tok.kind, TokenKind::Keyword(Keyword::Select))
                    && !self.should_stop_scan_at_statement_start(tok))
            {
                // CTAS: table options have already been parsed, now consume AS and the query
                // According to Snowflake docs:
                // CREATE TABLE name [(cols)] [CLUSTER BY ...] [COPY GRANTS] AS query
                // MySQL writes the query without `AS` as well. Where a
                // statement needs no terminator, a `SELECT` here is the next
                // statement.
                variant = AstCreateTableVariant::Ctas;
                let as_start = tok.span.start;
                if tok.lexeme(self.source).eq_ignore_ascii_case("AS") {
                    self.advance(); // Consume AS
                }

                // Check if we're at a Jinja block boundary ({% endif %}, {% endfor %}, etc.)
                // This allows incomplete CTAS fragments like: CREATE TABLE x AS {% endif %}
                // which will be completed by a SELECT outside the Jinja block
                let at_jinja_boundary = if let Some(next_tok) = self.peek() {
                    matches!(
                        next_tok.kind,
                        TokenKind::JinjaStmtOpen | TokenKind::JinjaStmtClose
                    )
                } else {
                    false
                };

                if at_jinja_boundary {
                    // Incomplete CTAS fragment - this is valid in Jinja templates
                    // The query will come after the Jinja block closes
                    // Store as None to indicate incomplete fragment
                    span.end = self.peek().map(|t| t.span.start).unwrap_or(as_start + 2);
                    ctas_query_span = None;
                } else {
                    // Try to parse the query as a SELECT or SetSelect
                    let query_start_idx = self.idx;
                    let parse_result = self.parse_statement();

                    match parse_result {
                        Ok(stmt) => {
                            // Successfully parsed - store the AST
                            match &stmt {
                                AstStmt::Select(_) | AstStmt::SetSelect(_) => {
                                    span.end = stmt.span().end;
                                    ctas_query_span = Some(Ok(Box::new(stmt)));
                                }
                                _ => {
                                    // Unexpected statement type - fallback to span capture
                                    let mut end = as_start;
                                    while let Some(t) = self.peek() {
                                        match t.kind {
                                            TokenKind::Eof
                                            | TokenKind::Punctuation(
                                                crate::lexer::Punctuation::Semi,
                                            )
                                            | TokenKind::Operator(crate::lexer::Operator::Pipe) => {
                                                break
                                            }
                                            _ => {
                                                let t2 = self
                                                    .advance()
                                                    .expect_invariant("CTAS query fallback token should be available after peek");
                                                end = t2.span.end;
                                            }
                                        }
                                    }
                                    ctas_query_span = Some(Err(Span {
                                        start: as_start,
                                        end,
                                    }));
                                    span.end = end;
                                }
                            }
                        }
                        Err(_) => {
                            // Parse failed - reset position and capture as span
                            self.idx = query_start_idx;
                            let mut end = as_start;
                            while let Some(t) = self.peek() {
                                match t.kind {
                                    TokenKind::Eof
                                    | TokenKind::Punctuation(crate::lexer::Punctuation::Semi)
                                    | TokenKind::Operator(crate::lexer::Operator::Pipe) => break,
                                    _ => {
                                        let t2 = self.advance().expect_invariant(
                                            "CTAS query span token should be available after peek",
                                        );
                                        end = t2.span.end;
                                    }
                                }
                            }
                            ctas_query_span = Some(Err(Span {
                                start: as_start,
                                end,
                            }));
                            span.end = end;
                        }
                    }
                }
            } else if is_using_template_start(self) {
                let start = tok.span.start;
                let mut end = start;
                while let Some(t) = self.peek() {
                    match t.kind {
                        TokenKind::Eof
                        | TokenKind::Punctuation(crate::lexer::Punctuation::Semi)
                        | TokenKind::Operator(crate::lexer::Operator::Pipe) => break,
                        _ => {
                            let t2 = self.advance().expect_invariant(
                                "USING template token should be available after peek",
                            );
                            end = t2.span.end;
                        }
                    }
                }
                using_template_span = Some(Span { start, end });
                variant = AstCreateTableVariant::UsingTemplate;
                span.end = end;
            } else if tok.lexeme(self.source).eq_ignore_ascii_case("FROM") {
                let start = tok.span.start;
                let mut end = start;
                let mut seen_archive = false;
                let mut seen_snapshot_set = false;

                while let Some(t) = self.peek() {
                    if t.lexeme(self.source).eq_ignore_ascii_case("ARCHIVE") {
                        seen_archive = true;
                    }
                    if t.lexeme(self.source).eq_ignore_ascii_case("SNAPSHOT") {
                        seen_snapshot_set = true;
                    }
                    match t.kind {
                        TokenKind::Eof
                        | TokenKind::Punctuation(crate::lexer::Punctuation::Semi)
                        | TokenKind::Operator(crate::lexer::Operator::Pipe) => break,
                        _ => {
                            let t2 = self.advance().expect_invariant(
                                "FROM archive/snapshot token should be available after peek",
                            );
                            end = t2.span.end;
                        }
                    }
                }

                let span_src = Span { start, end };
                if seen_snapshot_set {
                    from_snapshot_set_span = Some(span_src);
                    variant = AstCreateTableVariant::FromSnapshotSet;
                } else if seen_archive {
                    from_archive_span = Some(span_src);
                    variant = AstCreateTableVariant::FromArchive;
                }
                span.end = end;
            }
        }

        (
            variant,
            like_source_span,
            clone_source_span,
            ctas_query_span,
            time_travel_at_span,
            time_travel_before_span,
            time_travel_obj,
            using_template_span,
            from_archive_span,
            from_snapshot_set_span,
            clone_kind,
            clone_kind_span,
            clone_tblproperties_span,
            clone_location_span,
            clone_temporal_span,
            like_source,
            clone_source,
        )
    }

    /// Parse AT/BEFORE time-travel clauses for CLONE/CTAS
    fn parse_time_travel_clauses(&self, start_idx: usize) -> (Option<Span>, Option<Span>) {
        let mut time_travel_at_span = None;
        let mut time_travel_before_span = None;
        let mut i = start_idx;

        while i < self.tokens.len() {
            let t = &self.tokens[i];

            if matches!(
                t.kind,
                TokenKind::Eof
                    | TokenKind::Punctuation(crate::lexer::Punctuation::Semi)
                    | TokenKind::Operator(crate::lexer::Operator::Pipe)
            ) || t.lexeme(self.source).eq_ignore_ascii_case("USING")
                || t.lexeme(self.source).eq_ignore_ascii_case("FROM")
            {
                break;
            }

            if t.lexeme(self.source).eq_ignore_ascii_case("AT") {
                let start = t.span.start;
                let mut j = i + 1;
                let mut end_at = t.span.end;

                while j < self.tokens.len() {
                    let t2 = &self.tokens[j];
                    if matches!(
                        t2.kind,
                        TokenKind::Eof
                            | TokenKind::Punctuation(crate::lexer::Punctuation::Semi)
                            | TokenKind::Operator(crate::lexer::Operator::Pipe)
                    ) || is_time_travel_boundary(t2.lexeme(self.source))
                    {
                        break;
                    }
                    end_at = t2.span.end;
                    j += 1;
                }

                time_travel_at_span = Some(Span { start, end: end_at });
                i = j;
                continue;
            }

            if t.lexeme(self.source).eq_ignore_ascii_case("BEFORE") {
                let start = t.span.start;
                let mut j = i + 1;
                let mut end_before = t.span.end;

                while j < self.tokens.len() {
                    let t2 = &self.tokens[j];
                    if matches!(
                        t2.kind,
                        TokenKind::Eof
                            | TokenKind::Punctuation(crate::lexer::Punctuation::Semi)
                            | TokenKind::Operator(crate::lexer::Operator::Pipe)
                    ) || is_time_travel_boundary(t2.lexeme(self.source))
                    {
                        break;
                    }
                    end_before = t2.span.end;
                    j += 1;
                }

                time_travel_before_span = Some(Span {
                    start,
                    end: end_before,
                });
                i = j;
                continue;
            }

            i += 1;
        }

        (time_travel_at_span, time_travel_before_span)
    }

    /// The policy clause that `alternatives` open at `i`: the policy's name
    /// after them and, where `columns_after` is written after the name, the
    /// parenthesised column list that follows it. `None` where neither
    /// alternative is written or no name follows.
    fn policy_clause_at(
        &self,
        i: usize,
        alternatives: &[&[&str]],
        columns_after: Option<&[&str]>,
    ) -> Option<PolicyClause> {
        let (next, policy) =
            self.object_ref_at(self.any_words_end(i, alternatives)?, self.id_gen.next())?;
        let listed = columns_after
            .and_then(|words| self.words_end(next, words))
            .and_then(|open| Some((open, self.parens_end(open)?)));
        Some(match listed {
            Some((open, end)) => PolicyClause {
                next: end,
                policy,
                columns: self.column_spans_in_parens(open),
            },
            None => PolicyClause {
                next,
                policy,
                columns: Vec::new(),
            },
        })
    }

    /// `[WITH] MASKING POLICY name [USING (col, …)]` at `i`.
    pub(crate) fn masking_policy_at(&self, i: usize) -> Option<PolicyClause> {
        self.policy_clause_at(
            i,
            &[&["WITH", "MASKING", "POLICY"], &["MASKING", "POLICY"]],
            Some(&["USING"]),
        )
    }

    /// Databricks `MASK function [USING COLUMNS (col, …)]` at `i`.
    pub(crate) fn mask_function_at(&self, i: usize) -> Option<PolicyClause> {
        self.policy_clause_at(i, &[&["MASK"]], Some(&["USING", "COLUMNS"]))
    }

    /// `[WITH] PROJECTION POLICY name` at `i`.
    pub(crate) fn projection_policy_at(&self, i: usize) -> Option<PolicyClause> {
        self.policy_clause_at(
            i,
            &[&["WITH", "PROJECTION", "POLICY"], &["PROJECTION", "POLICY"]],
            None,
        )
    }

    /// `[WITH] ROW ACCESS POLICY name [ON (col, …)]` at `i`.
    pub(crate) fn row_access_policy_at(&self, i: usize) -> Option<PolicyClause> {
        self.policy_clause_at(
            i,
            &[
                &["WITH", "ROW", "ACCESS", "POLICY"],
                &["ROW", "ACCESS", "POLICY"],
            ],
            Some(&["ON"]),
        )
    }

    /// Databricks `[WITH] ROW FILTER function [ON (col, …)]` at `i`.
    fn row_filter_at(&self, i: usize) -> Option<PolicyClause> {
        self.policy_clause_at(
            i,
            &[&["WITH", "ROW", "FILTER"], &["ROW", "FILTER"]],
            Some(&["ON"]),
        )
    }

    /// `[WITH] AGGREGATION POLICY name` at `i`.
    pub(crate) fn aggregation_policy_at(&self, i: usize) -> Option<PolicyClause> {
        self.policy_clause_at(
            i,
            &[
                &["WITH", "AGGREGATION", "POLICY"],
                &["AGGREGATION", "POLICY"],
            ],
            None,
        )
    }

    /// `[WITH] JOIN POLICY name` at `i`.
    pub(crate) fn join_policy_at(&self, i: usize) -> Option<PolicyClause> {
        self.policy_clause_at(i, &[&["WITH", "JOIN", "POLICY"], &["JOIN", "POLICY"]], None)
    }

    /// The single-token names of the `(col, …)` that opens at `open`.
    pub(crate) fn column_spans_in_parens(&self, open: usize) -> Vec<Span> {
        self.parens_end(open)
            .and_then(|end| self.parse_constraint_column_list(open, end))
            .unwrap_or_default()
    }

    /// The index past the names the policy or tag option at `i` holds:
    /// `ROW ACCESS POLICY name [ON (…)]`, `ROW FILTER name [ON (…)]`,
    /// `AGGREGATION POLICY name`, `JOIN POLICY name`, `TAG ( name = value
    /// [, …] )`, each with the `WITH` that may open it. `None` for any other
    /// option, or where its names are not read whole.
    fn option_names_end(&self, i: usize) -> Option<usize> {
        use crate::parser::core::NamePosition;
        if let Some(clause) = self
            .row_access_policy_at(i)
            .or_else(|| self.row_filter_at(i))
            .or_else(|| self.aggregation_policy_at(i))
            .or_else(|| self.join_policy_at(i))
        {
            return Some(clause.next);
        }
        let open = self.any_words_end(i, &[&["WITH", "TAG"], &["TAG"]])?;
        let close_end = self.parens_end(open)?;
        let tag = |j: usize| {
            self.name_span_at(j, NamePosition::Object)
                .and_then(|(next, _)| self.eq_value_end(next))
        };
        (self.comma_list_end(open + 1, tag)? + 1 == close_end).then_some(close_end)
    }

    /// The `PARTITION OF parent [(columns)] { FOR VALUES … | DEFAULT }` clause
    /// at `i`. The bound is read through its parentheses (`IN (…)`,
    /// `FROM (…) TO (…)`, `WITH (…)`); one that is not written that way ends
    /// the clause where it was last read.
    fn partition_of_at(&self, i: usize) -> Option<PartitionOfClause> {
        let name_at = self.words_end(i, &["PARTITION", "OF"])?;
        let (mut next, parent) = self.object_ref_at(name_at, self.id_gen.next())?;
        if let Some(end) = self.parens_end(next) {
            next = end;
        }
        if let Some(end) = self.words_end(next, &["DEFAULT"]) {
            next = end;
        } else if let Some(values) = self.words_end(next, &["FOR", "VALUES"]) {
            next = values;
            let listed = |at: usize| self.parens_end(at);
            if let Some(end) = self
                .any_words_end(next, &[&["IN"], &["WITH"]])
                .and_then(listed)
            {
                next = end;
            } else if let Some(end) = self
                .words_end(next, &["FROM"])
                .and_then(listed)
                .and_then(|to| self.words_end(to, &["TO"]))
                .and_then(listed)
            {
                next = end;
            }
        }
        Some(PartitionOfClause { next, parent })
    }

    /// The tables of the `INHERITS (a, b)` clause written outside any
    /// parentheses in tokens `start..end`.
    fn inherits_in(&self, start: usize, end: usize) -> Vec<AstObjectRef> {
        let mut i = start;
        while i < end {
            if let Some(after) = self.parens_end(i) {
                i = after;
            } else if self.word_at(i, "INHERITS") {
                return self.object_ref_list_at(i + 1);
            } else {
                i += 1;
            }
        }
        Vec::new()
    }

    /// Parse table options (CLUSTER BY, COPY GRANTS, COPY TAGS, DATA_RETENTION, etc.)
    #[allow(clippy::type_complexity)]
    fn parse_create_table_options(
        &mut self,
        options_start_idx: usize,
        options_end_idx: usize,
    ) -> (
        Option<Span>,                       // cluster_by_span
        Option<Vec<AstExpr>>,               // cluster_by_exprs
        Option<Span>,                       // copy_grants_span
        Option<Span>,                       // copy_tags_span
        Option<Span>,                       // data_retention_time_in_days_span
        Option<Span>,                       // max_data_extension_time_in_days_span
        Option<Span>,                       // default_ddl_collation_span
        Option<Span>,                       // row_access_policy_span
        Option<Span>,                       // aggregation_policy_span
        Option<Span>,                       // join_policy_span
        Option<Span>,                       // storage_lifecycle_policy_span
        Option<Span>,                       // tag_span
        Option<Span>,                       // enable_schema_evolution_span
        Option<Span>,                       // table_comment_span
        Option<Span>,                       // with_row_access_policy_span
        Option<Span>,                       // with_contact_span
        Option<Span>,                       // change_tracking_span
        Option<Span>,                       // partition_by_span
        Option<crate::ast::AstDistStyle>,   // dist_style (Redshift)
        bool,                               // dist_key_present (Redshift)
        Option<crate::ast::AstSortKeySpec>, // sort_key (Redshift)
        Option<crate::ast::AstBackupMode>,  // backup (Redshift)
        Vec<crate::ast::AstTagRef>,         // tags
        TablePolicies,                      // the policies the options name
        TableSources,                       // the tables the options name
    ) {
        let mut cluster_by_span = None;
        let mut cluster_by_exprs = None;
        let mut copy_grants_span = None;
        let mut copy_tags_span = None;
        let mut data_retention_time_in_days_span = None;
        let mut max_data_extension_time_in_days_span = None;
        let mut default_ddl_collation_span = None;
        let mut row_access_policy_span = None;
        let mut aggregation_policy_span = None;
        let mut join_policy_span = None;
        let mut storage_lifecycle_policy_span = None;
        let mut tag_span = None;
        let mut enable_schema_evolution_span = None;
        let mut table_comment_span = None;
        let mut with_row_access_policy_span = None;
        let mut with_contact_span = None;
        let mut change_tracking_span = None;
        let mut partition_by_span = None;
        let mut dist_style: Option<crate::ast::AstDistStyle> = None;
        let mut dist_key_present = false;
        let mut sort_key: Option<crate::ast::AstSortKeySpec> = None;
        let mut backup: Option<crate::ast::AstBackupMode> = None;
        let mut tags: Vec<crate::ast::AstTagRef> = Vec::new();
        let mut policies = TablePolicies::default();
        let mut sources = TableSources::default();

        if options_end_idx <= options_start_idx {
            return (
                cluster_by_span,
                cluster_by_exprs,
                copy_grants_span,
                copy_tags_span,
                data_retention_time_in_days_span,
                max_data_extension_time_in_days_span,
                default_ddl_collation_span,
                row_access_policy_span,
                aggregation_policy_span,
                join_policy_span,
                storage_lifecycle_policy_span,
                tag_span,
                enable_schema_evolution_span,
                table_comment_span,
                with_row_access_policy_span,
                with_contact_span,
                change_tracking_span,
                partition_by_span,
                dist_style,
                dist_key_present,
                sort_key,
                backup,
                tags,
                policies,
                sources,
            );
        }
        sources.inherits = self.inherits_in(options_start_idx, options_end_idx);

        // Find option starter keywords
        let mut i = options_start_idx;
        let mut starter_indices = Vec::new();
        while i < options_end_idx {
            let tok = &self.tokens[i];
            if is_table_option_starter(tok.lexeme(self.source)) {
                starter_indices.push(i);
                // The names a policy or tag option holds are read whole, so
                // no part of them starts an option (`TAG (gov.comment.t = 'x')`);
                // nor does the bound of a partition.
                if let Some(next) = self
                    .partition_of_at(i)
                    .map(|clause| clause.next)
                    .or_else(|| self.option_names_end(i))
                    .filter(|&next| next <= options_end_idx)
                {
                    i = next;
                    continue;
                }
            }
            i += 1;
        }

        // Process each option
        for (pos, &start_idx) in starter_indices.iter().enumerate() {
            let tok = &self.tokens[start_idx];
            let lexeme = &tok.lexeme(self.source);
            let end_idx = if pos + 1 < starter_indices.len() {
                starter_indices[pos + 1]
            } else {
                options_end_idx
            };

            let start_span = tok.span.start;
            let end_span = self.tokens[end_idx - 1].span.end;
            let opt_span = Span {
                start: start_span,
                end: end_span,
            };

            // A policy whose name is read whole; the options below hold the
            // clauses whose names are not.
            let in_options =
                |clause: PolicyClause| (clause.next <= options_end_idx).then_some(clause);
            if let Some(clause) = self.row_access_policy_at(start_idx).and_then(in_options) {
                if self.word_at(start_idx, "WITH") {
                    with_row_access_policy_span = Some(opt_span);
                } else {
                    row_access_policy_span = Some(opt_span);
                }
                policies.row_access = Some(clause);
            } else if let Some(clause) = self.row_filter_at(start_idx).and_then(in_options) {
                // A row filter is the row access policy of Databricks: its
                // clause takes the span of one.
                if self.word_at(start_idx, "WITH") {
                    with_row_access_policy_span = Some(opt_span);
                } else {
                    row_access_policy_span = Some(opt_span);
                }
                policies.row_filter = Some(clause);
            } else if let Some(clause) = self.aggregation_policy_at(start_idx).and_then(in_options)
            {
                aggregation_policy_span = Some(opt_span);
                policies.aggregation = Some(clause);
            } else if let Some(clause) = self.join_policy_at(start_idx).and_then(in_options) {
                join_policy_span = Some(opt_span);
                policies.join = Some(clause);
            } else if lexeme.eq_ignore_ascii_case("CLUSTER") {
                cluster_by_span = Some(opt_span);
                // Try to parse CLUSTER BY expressions using smart parsing
                cluster_by_exprs = self.parse_cluster_by_expressions(start_idx, end_idx);
            } else if let Some(clause) = self
                .partition_of_at(start_idx)
                .filter(|clause| clause.next <= options_end_idx)
            {
                partition_by_span = Some(joined(partition_by_span, opt_span));
                sources.partition_of = Some(clause.parent);
            } else if lexeme.eq_ignore_ascii_case("PARTITION") {
                // A partition that is itself partitioned: both clauses.
                partition_by_span = Some(joined(partition_by_span, opt_span));
            } else if lexeme.eq_ignore_ascii_case("COPY") {
                // COPY TAGS, COPY GRANTS, or BigQuery's COPY table
                if start_idx + 1 < options_end_idx {
                    let next_lexeme = self.tokens[start_idx + 1].lexeme(self.source);
                    if next_lexeme.eq_ignore_ascii_case("TAGS") {
                        copy_tags_span = Some(opt_span);
                    } else if next_lexeme.eq_ignore_ascii_case("GRANTS") {
                        copy_grants_span = Some(opt_span);
                    } else if let Some((_, table)) = self
                        .object_ref_at(start_idx + 1, self.id_gen.next())
                        .filter(|(next, _)| *next <= options_end_idx)
                    {
                        sources.copy = Some(table);
                    } else {
                        copy_grants_span = Some(opt_span);
                    }
                } else {
                    copy_grants_span = Some(opt_span);
                }
            } else if lexeme.eq_ignore_ascii_case("DATA_RETENTION_TIME_IN_DAYS") {
                data_retention_time_in_days_span = Some(opt_span);
            } else if lexeme.eq_ignore_ascii_case("MAX_DATA_EXTENSION_TIME_IN_DAYS") {
                max_data_extension_time_in_days_span = Some(opt_span);
            } else if lexeme.eq_ignore_ascii_case("DEFAULT_DDL_COLLATION") {
                default_ddl_collation_span = Some(opt_span);
            } else if lexeme.eq_ignore_ascii_case("ROW") {
                // Check if this is ROW ACCESS POLICY
                if start_idx + 1 < options_end_idx {
                    let next_tok = &self.tokens[start_idx + 1];
                    if next_tok.lexeme(self.source).eq_ignore_ascii_case("ACCESS") {
                        row_access_policy_span = Some(opt_span);
                    }
                }
            } else if lexeme.eq_ignore_ascii_case("AGGREGATION") {
                aggregation_policy_span = Some(opt_span);
            } else if lexeme.eq_ignore_ascii_case("JOIN") {
                join_policy_span = Some(opt_span);
            } else if lexeme.eq_ignore_ascii_case("STORAGE") {
                storage_lifecycle_policy_span = Some(opt_span);
            } else if let Some(open) = self.any_words_end(start_idx, &[&["WITH", "TAG"], &["TAG"]])
            {
                tag_span = Some(opt_span);
                if let Some((_, read)) =
                    self.parenthesised_tag_list_at(open, TagListShape::Assignments)
                {
                    tags = read;
                }
            } else if lexeme.eq_ignore_ascii_case("ENABLE_SCHEMA_EVOLUTION") {
                enable_schema_evolution_span = Some(opt_span);
            } else if lexeme.eq_ignore_ascii_case("COMMENT") {
                table_comment_span = Some(opt_span);
            } else if lexeme.eq_ignore_ascii_case("WITH") {
                // Distinguish WITH ROW ACCESS POLICY vs WITH <other>
                if start_idx + 1 < options_end_idx {
                    let next_tok = &self.tokens[start_idx + 1];
                    if next_tok.lexeme(self.source).eq_ignore_ascii_case("ROW") {
                        with_row_access_policy_span = Some(opt_span);
                    } else {
                        with_contact_span = Some(opt_span);
                    }
                }
            } else if lexeme.eq_ignore_ascii_case("CHANGE_TRACKING") {
                change_tracking_span = Some(opt_span);
            } else if lexeme.eq_ignore_ascii_case("DISTSTYLE") {
                // DISTSTYLE { EVEN | KEY | ALL | AUTO } — value token follows.
                if start_idx + 1 < options_end_idx {
                    let v = self.tokens[start_idx + 1].lexeme(self.source);
                    if v.eq_ignore_ascii_case("EVEN") {
                        dist_style = Some(crate::ast::AstDistStyle::Even);
                    } else if v.eq_ignore_ascii_case("KEY") {
                        dist_style = Some(crate::ast::AstDistStyle::Key);
                    } else if v.eq_ignore_ascii_case("ALL") {
                        dist_style = Some(crate::ast::AstDistStyle::All);
                    } else if v.eq_ignore_ascii_case("AUTO") {
                        dist_style = Some(crate::ast::AstDistStyle::Auto);
                    }
                }
            } else if lexeme.eq_ignore_ascii_case("DISTKEY") {
                dist_key_present = true;
            } else if lexeme.eq_ignore_ascii_case("COMPOUND") {
                // COMPOUND SORTKEY (...)
                if start_idx + 1 < options_end_idx
                    && self.tokens[start_idx + 1]
                        .lexeme(self.source)
                        .eq_ignore_ascii_case("SORTKEY")
                {
                    sort_key = Some(crate::ast::AstSortKeySpec::Compound);
                }
            } else if lexeme.eq_ignore_ascii_case("INTERLEAVED") {
                // INTERLEAVED SORTKEY (...)
                if start_idx + 1 < options_end_idx
                    && self.tokens[start_idx + 1]
                        .lexeme(self.source)
                        .eq_ignore_ascii_case("SORTKEY")
                {
                    sort_key = Some(crate::ast::AstSortKeySpec::Interleaved);
                }
            } else if lexeme.eq_ignore_ascii_case("SORTKEY") {
                // Bare SORTKEY (...) is compound; do not overwrite an explicit
                // COMPOUND/INTERLEAVED prefix already recorded.
                if sort_key.is_none() {
                    sort_key = Some(crate::ast::AstSortKeySpec::Compound);
                }
            } else if lexeme.eq_ignore_ascii_case("BACKUP") {
                // BACKUP { YES | NO } — value token follows.
                if start_idx + 1 < options_end_idx {
                    let v = self.tokens[start_idx + 1].lexeme(self.source);
                    if v.eq_ignore_ascii_case("NO") {
                        backup = Some(crate::ast::AstBackupMode::No);
                    } else if v.eq_ignore_ascii_case("YES") {
                        backup = Some(crate::ast::AstBackupMode::Yes);
                    }
                }
            }
        }

        (
            cluster_by_span,
            cluster_by_exprs,
            copy_grants_span,
            copy_tags_span,
            data_retention_time_in_days_span,
            max_data_extension_time_in_days_span,
            default_ddl_collation_span,
            row_access_policy_span,
            aggregation_policy_span,
            join_policy_span,
            storage_lifecycle_policy_span,
            tag_span,
            enable_schema_evolution_span,
            table_comment_span,
            with_row_access_policy_span,
            with_contact_span,
            change_tracking_span,
            partition_by_span,
            dist_style,
            dist_key_present,
            sort_key,
            backup,
            tags,
            policies,
            sources,
        )
    }
    pub(crate) fn try_parse_create_table_stmt(&mut self) -> crate::error::ParseResult<AstStmt> {
        use crate::error::{ExpectInvariant, ParseError, ParseErrorKind, ParseResultExt};

        let create_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["CREATE".to_string()])?; // CREATE
        let keyword_span = create_tok.span;
        let mut span = keyword_span;
        // Databricks `REPLACE TABLE`: the leading keyword is the replace.
        let mut or_replace_span: Option<Span> =
            matches!(create_tok.kind, TokenKind::Keyword(Keyword::Replace)).then_some(keyword_span);
        let mut temp_kind_span: Option<Span> = None;
        let mut persistence: Option<crate::ast::AstTablePersistence> = None;
        let mut table_kind: Option<crate::ast::AstTableKind> = None;
        let mut table_kind_span: Option<Span> = None;

        let mut columns_span: Option<Span> = None;
        let mut lparen_span: Option<Span> = None;
        let mut rparen_span: Option<Span> = None;

        let retention_span: Option<Span> = None;

        let mut columns: Vec<AstCreateTableColumn> = Vec::new();
        let mut like_elements: Vec<crate::ast::AstTableLikeItem> = Vec::new();
        let mut constraints: Vec<AstCreateTableConstraint> = Vec::new();

        // Optional OR REPLACE / OR ALTER (Snowflake) / OR REFRESH (Databricks
        // DLT). `OR ALTER` alters a table that exists, and `OR REFRESH`
        // declares a pipeline table that the pipeline updates, rather than
        // replacing it: each is consumed, and is no `or_replace_span`.
        if let Some(tok) = self.peek() {
            if tok.lexeme(self.source).eq_ignore_ascii_case("OR") {
                let or_tok = self
                    .advance()
                    .expect_invariant("OR keyword should be available after peek");
                if let Some(rep_tok) = self.peek() {
                    if rep_tok.lexeme(self.source).eq_ignore_ascii_case("REPLACE") {
                        let rep = self
                            .advance()
                            .expect_invariant("REPLACE keyword should be available after peek");
                        or_replace_span = Some(Span {
                            start: or_tok.span.start,
                            end: rep.span.end,
                        });
                        span.end = rep.span.end;
                    } else if rep_tok.lexeme(self.source).eq_ignore_ascii_case("ALTER")
                        || rep_tok.lexeme(self.source).eq_ignore_ascii_case("REFRESH")
                    {
                        let word = self.advance().expect_invariant(
                            "ALTER/REFRESH keyword should be available after peek",
                        );
                        span.end = word.span.end;
                    }
                }
            }
        }

        // Optional Snowflake procedure-scoped temp-table prefix:
        // `PROCEDURE SCOPED { TEMP | TEMPORARY } TABLE` declares a table that
        // lives only for the current stored-procedure execution. Despite the
        // PROCEDURE keyword it creates a TABLE; the dispatcher routes it here
        // when SCOPED follows PROCEDURE. The TEMP/TEMPORARY keyword is left for
        // the temp-modifier block below, so the table is also marked temporary.
        let mut scoped_span: Option<Span> = None;
        if let Some(tok) = self.peek() {
            if tok.lexeme(self.source).eq_ignore_ascii_case("PROCEDURE")
                && self
                    .tokens
                    .get(self.idx + 1)
                    .is_some_and(|t| t.lexeme(self.source).eq_ignore_ascii_case("SCOPED"))
            {
                let proc_tok = self
                    .advance()
                    .expect_invariant("PROCEDURE keyword should be available after peek");
                let scoped_tok = self
                    .advance()
                    .expect_invariant("SCOPED identifier should be available after peek");
                scoped_span = Some(Span {
                    start: proc_tok.span.start,
                    end: scoped_tok.span.end,
                });
                span.end = scoped_tok.span.end;
            }
        }

        // Optional temp/transient modifiers as a single span.
        // Syntax: [ { [ { LOCAL | GLOBAL } ] TEMP | TEMPORARY | VOLATILE | TRANSIENT } ]
        if let Some(tok) = self.peek() {
            let mut start_span: Option<Span> = None;
            let mut end_span: Option<Span> = None;

            // Check for optional LOCAL or GLOBAL prefix
            if tok.lexeme(self.source).eq_ignore_ascii_case("LOCAL")
                || tok.lexeme(self.source).eq_ignore_ascii_case("GLOBAL")
            {
                let t = self
                    .advance()
                    .expect_invariant("LOCAL/GLOBAL keyword should be available after peek");
                start_span = Some(t.span);
                end_span = Some(t.span);

                // After LOCAL/GLOBAL, check for table type keyword
                if let Some(tok2) = self.peek() {
                    if tok2.lexeme(self.source).eq_ignore_ascii_case("TEMP")
                        || tok2.lexeme(self.source).eq_ignore_ascii_case("TEMPORARY")
                        || tok2.lexeme(self.source).eq_ignore_ascii_case("VOLATILE")
                    {
                        let t2 = self.advance().expect_invariant(
                            "TEMP/TEMPORARY/VOLATILE keyword should be available after peek",
                        );
                        end_span = Some(t2.span);
                        persistence = Some(crate::ast::AstTablePersistence::Temporary);
                    }
                }
            } else if tok.lexeme(self.source).eq_ignore_ascii_case("TEMP")
                || tok.lexeme(self.source).eq_ignore_ascii_case("TEMPORARY")
                || tok.lexeme(self.source).eq_ignore_ascii_case("VOLATILE")
                || tok.lexeme(self.source).eq_ignore_ascii_case("TRANSIENT")
            {
                // No LOCAL/GLOBAL prefix, just table type keyword
                let t = self
                    .advance()
                    .expect_invariant("Table type keyword (TEMP/TEMPORARY/VOLATILE/TRANSIENT) should be available after peek");
                persistence = Some(if t.lexeme(self.source).eq_ignore_ascii_case("TRANSIENT") {
                    crate::ast::AstTablePersistence::Transient
                } else {
                    crate::ast::AstTablePersistence::Temporary
                });
                start_span = Some(t.span);
                end_span = Some(t.span);
            }

            // PostgreSQL `UNLOGGED`: a persistent table whose writes skip
            // the write-ahead log. Consumed; it is not a temporary table.
            if start_span.is_none() && tok.lexeme(self.source).eq_ignore_ascii_case("UNLOGGED") {
                let t = self
                    .advance()
                    .expect_invariant("UNLOGGED keyword should be available after peek");
                span.end = t.span.end;
            }

            // Set temp_kind_span if we found any table type keywords
            if let (Some(start), Some(end)) = (start_span, end_span) {
                temp_kind_span = Some(Span {
                    start: start.start,
                    end: end.end,
                });
                span.end = end.end;
            }
        }

        // Optional Databricks `STREAMING` modifier: a streaming table is a
        // table, so the word is consumed and marks nothing; before `LIVE` it
        // opens that modifier's span.
        let mut streaming_span: Option<Span> = None;
        if self
            .peek()
            .is_some_and(|t| t.lexeme(self.source).eq_ignore_ascii_case("STREAMING"))
            && (self.word_at(self.idx + 1, "TABLE") || self.word_at(self.idx + 1, "LIVE"))
        {
            let streaming = self
                .advance()
                .expect_invariant("STREAMING keyword should be available after peek");
            span.end = streaming.span.end;
            streaming_span = Some(streaming.span);
        }

        // Optional Databricks DLT modifier: LIVE TABLE
        if let Some(tok) = self.peek() {
            if tok.lexeme(self.source).eq_ignore_ascii_case("LIVE") {
                let live_tok = self
                    .advance()
                    .expect_invariant("LIVE keyword should be available after peek");
                span.end = live_tok.span.end;
                temp_kind_span = Some(match temp_kind_span.or(streaming_span) {
                    Some(existing) => Span {
                        start: existing.start,
                        end: live_tok.span.end,
                    },
                    None => live_tok.span,
                });
            }
        }

        // Optional Snowflake table-kind variant: ICEBERG | HYBRID | EVENT,
        // captured only when immediately followed by TABLE (so a bare
        // `CREATE EVENT <name>` is left for other handlers).
        if let Some(tok) = self.peek() {
            let kind = if tok.lexeme(self.source).eq_ignore_ascii_case("ICEBERG") {
                Some(crate::ast::AstTableKind::Iceberg)
            } else if tok.lexeme(self.source).eq_ignore_ascii_case("HYBRID") {
                Some(crate::ast::AstTableKind::Hybrid)
            } else if tok.lexeme(self.source).eq_ignore_ascii_case("EVENT") {
                Some(crate::ast::AstTableKind::Event)
            } else {
                None
            };
            if let Some(k) = kind {
                if self
                    .tokens
                    .get(self.idx + 1)
                    .is_some_and(|t| t.lexeme(self.source).eq_ignore_ascii_case("TABLE"))
                {
                    let kind_tok = self
                        .advance()
                        .expect_invariant("table-kind keyword should be available after peek");
                    table_kind = Some(k);
                    table_kind_span = Some(kind_tok.span);
                    span.end = kind_tok.span.end;
                }
            }
        }

        // Expect TABLE keyword; if we see PROCEDURE instead, surface a clear
        // not-yet-supported error to keep tests and user experience aligned.
        let table_tok = self.advance().ok_or_else(|| {
            ParseError::new(
                self.current_span(),
                ParseErrorKind::InvalidStatement {
                    message: "CREATE TABLE requires TABLE keyword".to_string(),
                },
            )
        })?;
        if table_tok
            .lexeme(self.source)
            .eq_ignore_ascii_case("PROCEDURE")
        {
            return Err(ParseError::new(
                table_tok.span,
                ParseErrorKind::InvalidStatement {
                    message:
                        "CREATE PROCEDURE statements are not yet fully supported in this context"
                            .to_string(),
                },
            ));
        }
        if !table_tok.lexeme(self.source).eq_ignore_ascii_case("TABLE") {
            return Err(ParseError::new(
                table_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: format!(
                        "Expected TABLE keyword, found {}",
                        Parser::token_description(table_tok, self.source)
                    ),
                },
            ));
        }
        let table_keyword_span: Option<Span> = Some(table_tok.span);
        span.end = table_tok.span.end;

        // Capture table name up to '(', LIKE, CLONE, AS, USING, FROM, or table
        // options. The name region is `[IF NOT EXISTS] part ('.' part)*`, where a
        // part may be an identifier, a keyword usable as an identifier, or a Jinja
        // expression (`{{ ... }}`) in a templated model. The scan stays permissive
        // (Jinja tokens are absorbed), but at a *name-part position* — the first
        // token, and each token right after a '.' — a clause/option keyword sitting
        // there IS the name and must be consumed, not treated as the start of a
        // CLONE/COPY/CLUSTER/... clause; an unquoted keyword name (e.g. `clone`,
        // `copy`, `tag`) is the name, not the start of a clause.
        // Consume an optional IF NOT EXISTS prefix so the scan lands on the name,
        // keeping the following part-position logic correct across dialects.
        let mut if_not_exists_span = None;
        if self
            .peek()
            .is_some_and(|t| t.lexeme(self.source).eq_ignore_ascii_case("IF"))
            && self
                .tokens
                .get(self.idx + 1)
                .is_some_and(|t| t.lexeme(self.source).eq_ignore_ascii_case("NOT"))
            && self
                .tokens
                .get(self.idx + 2)
                .is_some_and(|t| t.lexeme(self.source).eq_ignore_ascii_case("EXISTS"))
        {
            let if_tok = self
                .advance()
                .expect_invariant("IF should be available after peek");
            self.advance();
            let exists = self
                .advance()
                .expect_invariant("EXISTS should be available after peek");
            span.end = exists.span.end;
            if_not_exists_span = Some(Span {
                start: if_tok.span.start,
                end: exists.span.end,
            });
        }
        let name_start_idx = self.idx;
        // `IDENTIFIER(<expression>)` names the table by its argument.
        let identifier_call = self.identifier_argument_at(name_start_idx);
        if let Some((end, _)) = &identifier_call {
            self.idx = *end;
        }

        let mut at_part_start = true;
        while let Some(tok) = self.peek() {
            if identifier_call.is_some() {
                break;
            }
            if at_part_start
                && (self.can_be_identifier_token(tok)
                    || matches!(tok.kind, TokenKind::JinjaExprOpen))
            {
                let _ = self.advance();
                at_part_start = false;
                continue;
            }
            if self.should_stop_scan_at_statement_start(tok)
                || self.ends_create_table_name_at(self.idx)
            {
                break;
            }
            match tok.kind {
                TokenKind::Punctuation(crate::lexer::Punctuation::Dot) => {
                    let _ = self.advance();
                    at_part_start = true;
                }
                TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
                | TokenKind::Keyword(Keyword::Like)
                | TokenKind::Keyword(Keyword::As)
                | TokenKind::Keyword(Keyword::Using)
                | TokenKind::Keyword(Keyword::From)
                | TokenKind::Eof
                | TokenKind::Punctuation(crate::lexer::Punctuation::Semi)
                | TokenKind::Operator(crate::lexer::Operator::Pipe) => break,
                _ if tok.lexeme(self.source).eq_ignore_ascii_case("CLONE") => break,
                // Databricks: DEEP/SHALLOW before CLONE
                _ if (tok.lexeme(self.source).eq_ignore_ascii_case("DEEP")
                    || tok.lexeme(self.source).eq_ignore_ascii_case("SHALLOW"))
                    && self
                        .tokens
                        .get(self.idx + 1)
                        .is_some_and(|t| t.lexeme(self.source).eq_ignore_ascii_case("CLONE")) =>
                {
                    break
                }
                _ if is_table_option_starter(tok.lexeme(self.source)) => break,
                // `OPTIONS (…)` / `TBLPROPERTIES (…)` written straight after the name.
                _ if ["OPTIONS", "TBLPROPERTIES"]
                    .iter()
                    .any(|w| tok.lexeme(self.source).eq_ignore_ascii_case(w)) =>
                {
                    break
                }
                _ => {
                    let _ = self.advance();
                }
            }
        }
        let name_end_idx = self.idx;
        let mut name: Option<crate::ast::AstObjectRef> = None;
        if name_end_idx > name_start_idx {
            let node_id = self.id_gen.next();
            let mut read = self.object_ref_of_range(name_start_idx, name_end_idx, node_id);
            match identifier_call {
                Some((_, argument)) => read.identifier_arg = Some(Box::new(argument)),
                // `identifier` written before its column list is a one-part name.
                None if read.parts.is_none()
                    && name_end_idx == name_start_idx + 1
                    && self.word_at(name_start_idx, "IDENTIFIER") =>
                {
                    read.parts = Some(vec![Some(crate::ast::AstNamePart::Word(
                        self.tokens[name_start_idx].span,
                    ))]);
                }
                None => {}
            }
            span.end = read.span.end;
            name = Some(read);
        }

        // Optional column list starting with '('. Capture balanced parentheses.
        if let Some(tok) = self.peek() {
            if matches!(
                tok.kind,
                TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
            ) {
                let start = tok.span.start;
                // Capture the opening paren span
                lparen_span = Some(tok.span);
                let mut depth: usize = 0;
                while let Some(t) = self.advance() {
                    match t.kind {
                        TokenKind::Punctuation(crate::lexer::Punctuation::LParen) => depth += 1,
                        TokenKind::Punctuation(crate::lexer::Punctuation::RParen) => {
                            if depth == 0 {
                                break;
                            }
                            depth -= 1;
                            if depth == 0 {
                                // Capture the closing paren span
                                rparen_span = Some(t.span);
                                columns_span = Some(Span {
                                    start,
                                    end: t.span.end,
                                });
                                span.end = t.span.end;
                                break;
                            }
                        }
                        _ => {}
                    }
                }
                // The loop only sets `columns_span` when it consumed the matching
                // ')'. A `None` here means the '(' ran to EOF unclosed — reject it
                // as a parse error so the statement surfaces as OpaqueContent
                // rather than silently absorbing every following statement into a
                // truncated column list.
                if columns_span.is_none() {
                    return Err(ParseError::new(
                        Span {
                            start,
                            end: start + 1,
                        },
                        ParseErrorKind::UnexpectedEof {
                            expected: vec![")".to_string()],
                        },
                    ));
                }
            }
        }

        // Parse table options BEFORE checking for variant keywords
        // This ensures CLUSTER BY, COPY GRANTS, etc. are consumed before we look for AS/LIKE/CLONE
        let options_start_idx = self.idx;

        // Consume table options until we hit a variant keyword or end
        while let Some(tok) = self.peek() {
            if self.should_stop_scan_at_statement_start(tok) {
                break;
            }
            let using_template_start = tok.lexeme(self.source).eq_ignore_ascii_case("USING")
                && self
                    .tokens
                    .get(self.idx + 1)
                    .is_some_and(|t| t.lexeme(self.source).eq_ignore_ascii_case("TEMPLATE"));
            // A partition's bound (`FROM (…) TO (…)`) is part of its option.
            if let Some(clause) = self.partition_of_at(self.idx) {
                self.idx = clause.next;
                continue;
            }
            match tok.kind {
                TokenKind::Keyword(Keyword::Like)
                | TokenKind::Keyword(Keyword::As)
                | TokenKind::Keyword(Keyword::From)
                // MySQL's query written without `AS`.
                | TokenKind::Keyword(Keyword::Select)
                | TokenKind::Eof
                | TokenKind::Punctuation(crate::lexer::Punctuation::Semi)
                | TokenKind::Operator(crate::lexer::Operator::Pipe) => break,
                _ if using_template_start => break,
                _ if tok.lexeme(self.source).eq_ignore_ascii_case("CLONE") => break,
                // Databricks: DEEP/SHALLOW before CLONE
                _ if (tok.lexeme(self.source).eq_ignore_ascii_case("DEEP")
                    || tok.lexeme(self.source).eq_ignore_ascii_case("SHALLOW"))
                    && self
                        .tokens
                        .get(self.idx + 1)
                        .is_some_and(|t| t.lexeme(self.source).eq_ignore_ascii_case("CLONE")) =>
                {
                    break
                }
                _ => {
                    // A data source's `OPTIONS (…)`, `TBLPROPERTIES (…)`.
                    if ["OPTIONS", "TBLPROPERTIES"]
                        .iter()
                        .any(|w| tok.lexeme(self.source).eq_ignore_ascii_case(w))
                    {
                        self.record_property_list_secrets(self.idx + 1);
                    }
                    let _ = self.advance();
                }
            }
        }
        let options_end_idx = self.idx;

        // Parse the table options we just consumed
        let options_result = self.parse_create_table_options(options_start_idx, options_end_idx);
        let mut cluster_by_span: Option<Span> = options_result.0;
        let mut cluster_by_exprs: Option<Vec<AstExpr>> = options_result.1;
        let mut copy_grants_span: Option<Span> = options_result.2;
        let mut copy_tags_span: Option<Span> = options_result.3;
        let mut data_retention_time_in_days_span: Option<Span> = options_result.4;
        let mut max_data_extension_time_in_days_span: Option<Span> = options_result.5;
        let mut default_ddl_collation_span: Option<Span> = options_result.6;
        let mut row_access_policy_span: Option<Span> = options_result.7;
        let mut aggregation_policy_span: Option<Span> = options_result.8;
        let mut join_policy_span: Option<Span> = options_result.9;
        let mut storage_lifecycle_policy_span: Option<Span> = options_result.10;
        let mut tag_span: Option<Span> = options_result.11;
        let mut enable_schema_evolution_span: Option<Span> = options_result.12;
        let mut table_comment_span: Option<Span> = options_result.13;
        let mut with_row_access_policy_span: Option<Span> = options_result.14;
        let mut with_contact_span: Option<Span> = options_result.15;
        let mut change_tracking_span: Option<Span> = options_result.16;
        let mut partition_by_span: Option<Span> = options_result.17;
        let mut dist_style: Option<crate::ast::AstDistStyle> = options_result.18;
        let mut dist_key_present: bool = options_result.19;
        let mut sort_key: Option<crate::ast::AstSortKeySpec> = options_result.20;
        let mut backup: Option<crate::ast::AstBackupMode> = options_result.21;
        let mut tags: Vec<crate::ast::AstTagRef> = options_result.22;
        let mut policies: TablePolicies = options_result.23;
        let mut sources: TableSources = options_result.24;

        // Set table_options_span from parsed options
        let mut table_options_span = None;
        if options_end_idx > options_start_idx {
            let first = &self.tokens[options_start_idx];
            let last = &self.tokens[options_end_idx - 1];
            table_options_span = Some(Span {
                start: first.span.start,
                end: last.span.end,
            });
            span.end = last.span.end;
        }

        // NOW check for variant keywords (LIKE, CLONE, AS, etc.)
        // Since table options are already consumed, we're positioned right at the variant keyword
        let variant_result = self.parse_create_table_variant(&mut span);
        let mut variant: AstCreateTableVariant = variant_result.0;
        let like_source_span: Option<Span> = variant_result.1;
        let clone_source_span: Option<Span> = variant_result.2;
        let ctas_query: Option<Result<Box<AstStmt>, Span>> = variant_result.3;
        let _time_travel_at_span: Option<Span> = variant_result.4;
        let _time_travel_before_span: Option<Span> = variant_result.5;
        let time_travel: Option<AstTimeTravel> = variant_result.6;
        let using_template_span: Option<Span> = variant_result.7;
        let from_archive_span: Option<Span> = variant_result.8;
        let from_snapshot_set_span: Option<Span> = variant_result.9;
        let clone_kind: Option<crate::ast::CloneKind> = variant_result.10;
        let clone_kind_span: Option<Span> = variant_result.11;
        let clone_tblproperties_span: Option<Span> = variant_result.12;
        let clone_location_span: Option<Span> = variant_result.13;
        let clone_temporal_span: Option<Span> = variant_result.14;
        let like_source: Option<AstObjectRef> = variant_result.15;
        let clone_source: Option<AstObjectRef> = variant_result.16;
        if variant == AstCreateTableVariant::Plain && sources.copy.is_some() {
            variant = AstCreateTableVariant::Copy;
        }

        // Scan for post-variant COPY GRANTS/TAGS (e.g., CREATE TABLE t LIKE s COPY GRANTS)
        // Only applies to LIKE/CLONE variants where options can follow the source table.
        if matches!(
            variant,
            AstCreateTableVariant::Like | AstCreateTableVariant::Clone
        ) {
            let post_variant_start_idx = self.idx;
            while let Some(tok) = self.peek() {
                if self.should_stop_scan_at_statement_start(tok) {
                    break;
                }
                match tok.kind {
                    TokenKind::Eof
                    | TokenKind::Punctuation(crate::lexer::Punctuation::Semi)
                    | TokenKind::Operator(crate::lexer::Operator::Pipe) => break,
                    _ => {
                        let _ = self.advance();
                    }
                }
            }
            let post_variant_end_idx = self.idx;

            if post_variant_end_idx > post_variant_start_idx {
                let post =
                    self.parse_create_table_options(post_variant_start_idx, post_variant_end_idx);
                cluster_by_span = cluster_by_span.or(post.0);
                cluster_by_exprs = cluster_by_exprs.or(post.1);
                copy_grants_span = copy_grants_span.or(post.2);
                copy_tags_span = copy_tags_span.or(post.3);
                data_retention_time_in_days_span = data_retention_time_in_days_span.or(post.4);
                max_data_extension_time_in_days_span =
                    max_data_extension_time_in_days_span.or(post.5);
                default_ddl_collation_span = default_ddl_collation_span.or(post.6);
                row_access_policy_span = row_access_policy_span.or(post.7);
                aggregation_policy_span = aggregation_policy_span.or(post.8);
                join_policy_span = join_policy_span.or(post.9);
                storage_lifecycle_policy_span = storage_lifecycle_policy_span.or(post.10);
                if tag_span.is_none() {
                    tags = post.22;
                }
                tag_span = tag_span.or(post.11);
                enable_schema_evolution_span = enable_schema_evolution_span.or(post.12);
                table_comment_span = table_comment_span.or(post.13);
                with_row_access_policy_span = with_row_access_policy_span.or(post.14);
                with_contact_span = with_contact_span.or(post.15);
                change_tracking_span = change_tracking_span.or(post.16);
                partition_by_span = partition_by_span.or(post.17);
                dist_style = dist_style.or(post.18);
                dist_key_present = dist_key_present || post.19;
                sort_key = sort_key.or(post.20);
                backup = backup.or(post.21);
                policies = policies.or(post.23);
                sources = sources.or(post.24);

                // Update table_options_span to include post-variant options
                let post_first = &self.tokens[post_variant_start_idx];
                let post_last = &self.tokens[post_variant_end_idx - 1];
                let post_span = Span {
                    start: post_first.span.start,
                    end: post_last.span.end,
                };
                table_options_span = Some(match table_options_span {
                    Some(existing) => Span {
                        start: existing.start.min(post_span.start),
                        end: existing.end.max(post_span.end),
                    },
                    None => post_span,
                });
                span.end = span.end.max(post_span.end);
            }
        }

        // Update span to include CTAS query if present
        if let Some(query_result) = &ctas_query {
            let query_end = match query_result {
                Ok(stmt) => stmt.span().end,
                Err(span) => span.end,
            };
            span.end = query_end;
        }

        // Shallow column/constraint splitter inside columns_span, if present.
        if let Some(cols_span) = columns_span {
            // Find token indices corresponding to the interior of the outer ( ... ).
            let mut start_idx_opt: Option<usize> = None;
            let mut end_idx_opt: Option<usize> = None;
            for (i, tok) in self.tokens.iter().enumerate() {
                if tok.span.start == cols_span.start {
                    start_idx_opt = Some(i + 1); // token after '('
                }
                if tok.span.end == cols_span.end {
                    end_idx_opt = Some(i); // index of ')'
                    break;
                }
            }
            if let (Some(inner_start), Some(inner_end)) = (start_idx_opt, end_idx_opt) {
                if inner_end > inner_start {
                    let result =
                        self.parse_create_table_columns_and_constraints(inner_start, inner_end);
                    columns = result.0;
                    constraints = result.1;
                    like_elements = result.2;
                }
            }
        }

        // Note: Snowflake allows multiple PRIMARY KEY constraints (both inline and out-of-line)
        // on the same column. This is valid syntax per the official documentation.
        // We parse and preserve all constraints without validation here.

        let name = name.ok_or_else(|| {
            ParseError::new(
                self.current_span(),
                ParseErrorKind::InvalidStatement {
                    message: "CREATE TABLE requires table name".to_string(),
                },
            )
        })?;
        let table_keyword_span = table_keyword_span.ok_or_else(|| {
            ParseError::new(
                self.current_span(),
                ParseErrorKind::InvalidStatement {
                    message: "CREATE TABLE requires TABLE keyword".to_string(),
                },
            )
        })?;
        let (row_access_policy, row_access_policy_columns) =
            PolicyClause::parts(policies.row_access);
        let (aggregation_policy, _) = PolicyClause::parts(policies.aggregation);
        let (join_policy, _) = PolicyClause::parts(policies.join);
        let (row_filter_function, row_filter_columns) = PolicyClause::parts(policies.row_filter);
        let stmt = AstCreateTable {
            node_id: self.id_gen.next(),
            span,
            keyword_span,
            or_replace_span,
            scoped_span,
            temp_kind_span,
            persistence,
            table_kind,
            table_kind_span,
            table_keyword_span,
            if_not_exists_span,
            name,
            columns_span,
            semicolon_token: None,
            lparen_span,
            rparen_span,
            variant,
            like_source_span,
            clone_source_span,
            like_source,
            clone_source,
            copy_source: sources.copy,
            partition_of: sources.partition_of,
            inherits: sources.inherits,
            like_elements,
            clone_kind,
            clone_kind_span,
            clone_tblproperties_span,
            clone_location_span,
            clone_temporal_span,
            ctas_query,
            time_travel: time_travel
                .map(|tt| Box::new(crate::ast::AstTimeTravelClause::SnowflakeAtBefore(tt))),
            table_options_span,
            cluster_by_span,
            cluster_by_exprs,
            dist_style,
            dist_key_present,
            sort_key,
            backup,
            partition_by_span,
            copy_grants_span,
            copy_tags_span,
            retention_span,
            change_tracking_span,
            data_retention_time_in_days_span,
            max_data_extension_time_in_days_span,
            default_ddl_collation_span,
            row_access_policy_span,
            row_access_policy,
            row_access_policy_columns,
            aggregation_policy_span,
            aggregation_policy,
            join_policy_span,
            join_policy,
            row_filter_function,
            row_filter_columns,
            storage_lifecycle_policy_span,
            tag_span,
            tags,
            enable_schema_evolution_span,
            table_comment_span,
            with_row_access_policy_span,
            with_contact_span,
            using_template_span,
            from_archive_span,
            from_snapshot_set_span,
            columns,
            constraints,
        };
        Ok(AstStmt::CreateTable(Box::new(stmt)))
    }

    /// Whether the token at `i`, after a `CREATE TABLE` name's first part,
    /// starts what follows the name: MySQL's query written without `AS`
    /// (`SELECT`, or `IGNORE` / `REPLACE` before it or before `AS`), a
    /// table option written `word = value`, or PostgreSQL's `ON COMMIT …`,
    /// `WITHOUT OIDS` or `TABLESPACE …`.
    fn ends_create_table_name_at(&self, i: usize) -> bool {
        let select = |at: usize| {
            self.tokens
                .get(at)
                .is_some_and(|t| matches!(t.kind, TokenKind::Keyword(Keyword::Select)))
        };
        let assigned = self.is_word_at(i)
            && self
                .tokens
                .get(i + 1)
                .is_some_and(|t| matches!(t.kind, TokenKind::Operator(crate::lexer::Operator::Eq)));
        select(i)
            || ((self.word_at(i, "IGNORE") || self.word_at(i, "REPLACE"))
                && (select(i + 1) || self.word_at(i + 1, "AS")))
            || assigned
            || (self.word_at(i, "ON") && self.word_at(i + 1, "COMMIT"))
            || (self.word_at(i, "WITHOUT") && self.word_at(i + 1, "OIDS"))
            || self.word_at(i, "TABLESPACE")
    }

    /// True when tokens at `i` start a `GENERATED ALWAYS` / `GENERATED BY
    /// DEFAULT` clause (PG / MySQL / Databricks generated or identity columns).
    fn is_generated_clause_at(&self, i: usize, end_idx: usize) -> bool {
        if i + 1 >= end_idx
            || !self.tokens[i]
                .lexeme(self.source)
                .eq_ignore_ascii_case("GENERATED")
        {
            return false;
        }
        let next = self.tokens[i + 1].lexeme(self.source);
        next.eq_ignore_ascii_case("ALWAYS")
            || (next.eq_ignore_ascii_case("BY")
                && i + 2 < end_idx
                && self.tokens[i + 2]
                    .lexeme(self.source)
                    .eq_ignore_ascii_case("DEFAULT"))
    }

    /// The column definition written over the tokens `start_idx..end_idx`,
    /// read as a `CREATE TABLE` column is; `None` where they are no column.
    pub(crate) fn column_as_created(
        &mut self,
        start_idx: usize,
        end_idx: usize,
    ) -> Option<AstCreateTableColumn> {
        let mut columns = Vec::new();
        let mut constraints = Vec::new();
        self.build_create_table_item(start_idx, end_idx, &mut columns, &mut constraints);
        columns.pop()
    }

    fn build_create_table_item(
        &mut self,
        start_idx: usize,
        end_idx: usize,
        columns: &mut Vec<AstCreateTableColumn>,
        constraints: &mut Vec<AstCreateTableConstraint>,
    ) {
        if end_idx <= start_idx {
            return;
        }
        // The item is read by its tokens, not by the expression parser.
        self.record_unparsed_secrets(start_idx, end_idx);
        let first = &self.tokens[start_idx];
        let last = &self.tokens[end_idx - 1];
        let full_span = Span {
            start: first.span.start,
            end: last.span.end,
        };
        // Classify by first non-EOF token in the item.
        let mut j = start_idx;
        while j < end_idx {
            let t0 = &self.tokens[j];
            if matches!(t0.kind, TokenKind::Eof) {
                j += 1;
                continue;
            }
            // PostgreSQL's `EXCLUDE [USING method] (…)` is a constraint, not a
            // column named `exclude`.
            let excludes = t0.lexeme(self.source).eq_ignore_ascii_case("EXCLUDE")
                && self.tokens.get(j + 1).is_some_and(|next| {
                    next.lexeme(self.source).eq_ignore_ascii_case("USING")
                        || matches!(
                            next.kind,
                            TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
                        )
                });
            // An index definition, MySQL's `{KEY | INDEX} [name] (…)` and
            // `{FULLTEXT | SPATIAL} [KEY | INDEX] …`, T-SQL's `INDEX name …`,
            // is an item of the table, not a column, where the dialect
            // reserves the word that leads it (no column is named by it).
            let lead = t0.lexeme(self.source);
            let indexes = ["KEY", "INDEX", "FULLTEXT", "SPATIAL"]
                .iter()
                .any(|word| lead.eq_ignore_ascii_case(word))
                && matches!(
                    t0.kind,
                    TokenKind::Keyword(_) | TokenKind::Identifier { .. }
                )
                && self.dialect.is_reserved_keyword(lead);
            let is_constraint_keyword = indexes
                || t0.lexeme(self.source).eq_ignore_ascii_case("CONSTRAINT")
                || t0.lexeme(self.source).eq_ignore_ascii_case("PRIMARY")
                || t0.lexeme(self.source).eq_ignore_ascii_case("UNIQUE")
                || t0.lexeme(self.source).eq_ignore_ascii_case("FOREIGN")
                || t0.lexeme(self.source).eq_ignore_ascii_case("CHECK")
                || excludes;
            if is_constraint_keyword {
                // Try to parse constraint details with smart fallback
                let details = self.parse_constraint_details(start_idx, end_idx);
                let expressions = self.constraint_expressions(start_idx, end_idx);
                constraints.push(AstCreateTableConstraint {
                    node_id: self.id_gen.next(),
                    full_span,
                    details,
                    expressions,
                });
            } else {
                // Column-level splitting for 3.3: name/type and key constraint spans.
                let mut name_span: Option<Span> = None;
                let mut type_span: Option<Span> = None;
                let mut collate_span: Option<Span> = None;
                let mut not_null_span: Option<Span> = None;
                let mut default_expr_span: Option<Span> = None;
                // Where the `DEFAULT` keyword of `default_expr_span` is: after
                // the `CONSTRAINT name` that names it, where one does.
                let mut default_keyword_at: Option<u32> = None;
                // Where a `CONSTRAINT name` naming the column's default starts.
                let mut default_named_from: Option<u32> = None;
                let mut identity_or_autoincrement_span: Option<Span> = None;
                let mut generated_always_span: Option<Span> = None;
                let mut virtual_expr_span: Option<Span> = None;
                let mut storage_keyword_span: Option<Span> = None;
                let mut inline_constraint_id: Option<crate::syntax::SyntaxInlineConstraintId> =
                    None;
                let mut foreign_key: Option<crate::ast::AstConstraintDetails> = None;
                let mut key: Option<crate::ast::AstColumnKey> = None;
                let mut not_null_after_constraint = false;
                let mut masking_policy_span: Option<Span> = None;
                let mut masking_policy: Option<AstObjectRef> = None;
                let mut masking_policy_using: Vec<Span> = Vec::new();
                let mut projection_policy: Option<AstObjectRef> = None;
                let mut tag_span: Option<Span> = None;
                let mut tags: Vec<crate::ast::AstTagRef> = Vec::new();
                let mut comment_span: Option<Span> = None;
                // The parenthesized condition of the column's own `CHECK`.
                let mut inline_check_span: Option<Span> = None;

                // Simple heuristic pass over the item tokens.
                let mut i = start_idx;
                // 1) First identifier â†’ name_span.
                while i < end_idx {
                    let t = &self.tokens[i];
                    if self.can_be_identifier_token(t) {
                        name_span = Some(t.span);
                        i += 1;
                        break;
                    }
                    i += 1;
                }

                // 2) Type tokens up to first constraint keyword. Generated-column
                // clauses (`AS ( expr )`, `GENERATED ALWAYS ...`) end the type run;
                // MSSQL typeless computed columns (`name AS expr`) leave it None.
                let mut type_start: Option<u32> = None;
                while i < end_idx {
                    let t = &self.tokens[i];
                    if is_column_tail_clause_lexeme(t.lexeme(self.source)) {
                        break;
                    }
                    if matches!(t.kind, TokenKind::Keyword(Keyword::As))
                        || self.is_generated_clause_at(i, end_idx)
                    {
                        break;
                    }
                    // These clauses stay in the type run; their names are kept.
                    if projection_policy.is_none() {
                        projection_policy = self.projection_policy_at(i).map(|c| c.policy);
                    }
                    if masking_policy.is_none() {
                        if let Some(clause) = self.mask_function_at(i) {
                            masking_policy = Some(clause.policy);
                            masking_policy_using = clause.columns;
                        }
                    }
                    if type_start.is_none() {
                        type_start = Some(t.span.start);
                    }
                    type_span = Some(Span {
                        start: type_start
                            .expect_invariant("type_start should be set in previous line"),
                        end: t.span.end,
                    });
                    i += 1;
                }

                // 3) Constraint-like tails: carve NOT NULL, DEFAULT expr, IDENTITY/AUTOINCREMENT,
                // MASKING POLICY, TAG, COMMENT, COLLATE.
                while i < end_idx {
                    let t = &self.tokens[i];
                    // GENERATED ALWAYS | GENERATED BY DEFAULT prefix. When followed
                    // by `AS IDENTITY` (identity column, not an expression), fold the
                    // AS into the prefix so the IDENTITY branch carves contiguously.
                    if generated_always_span.is_none() && self.is_generated_clause_at(i, end_idx) {
                        let start = t.span.start;
                        let mut j2 = i + 1;
                        if self.tokens[j2]
                            .lexeme(self.source)
                            .eq_ignore_ascii_case("BY")
                        {
                            j2 += 2; // BY DEFAULT
                        } else {
                            j2 += 1; // ALWAYS
                        }
                        let mut end = self.tokens[j2 - 1].span.end;
                        if j2 + 1 < end_idx
                            && matches!(self.tokens[j2].kind, TokenKind::Keyword(Keyword::As))
                            && self.tokens[j2 + 1]
                                .lexeme(self.source)
                                .eq_ignore_ascii_case("IDENTITY")
                        {
                            end = self.tokens[j2].span.end;
                            j2 += 1;
                        }
                        generated_always_span = Some(Span { start, end });
                        i = j2;
                        continue;
                    }
                    // Generated/virtual/computed expression: `AS ( expr )` or
                    // MSSQL unparenthesized `AS expr` (bounded by tail-clause or
                    // storage keywords). Span includes the AS keyword.
                    if virtual_expr_span.is_none()
                        && matches!(t.kind, TokenKind::Keyword(Keyword::As))
                    {
                        let start = t.span.start;
                        let mut end = t.span.end;
                        let mut j2 = i + 1;
                        if j2 < end_idx
                            && matches!(
                                self.tokens[j2].kind,
                                TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
                            )
                        {
                            let mut depth: usize = 0;
                            while j2 < end_idx {
                                let t2 = &self.tokens[j2];
                                end = t2.span.end;
                                j2 += 1;
                                if matches!(
                                    t2.kind,
                                    TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
                                ) {
                                    depth += 1;
                                } else if matches!(
                                    t2.kind,
                                    TokenKind::Punctuation(crate::lexer::Punctuation::RParen)
                                ) {
                                    depth -= 1;
                                    if depth == 0 {
                                        break;
                                    }
                                }
                            }
                        } else {
                            let mut depth: usize = 0;
                            while j2 < end_idx {
                                let t2 = &self.tokens[j2];
                                let lex = t2.lexeme(self.source);
                                if depth == 0
                                    && (is_column_tail_clause_lexeme(lex)
                                        || is_generated_storage_lexeme(lex))
                                {
                                    break;
                                }
                                if matches!(
                                    t2.kind,
                                    TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
                                ) {
                                    depth += 1;
                                } else if matches!(
                                    t2.kind,
                                    TokenKind::Punctuation(crate::lexer::Punctuation::RParen)
                                ) {
                                    depth = depth.saturating_sub(1);
                                }
                                end = t2.span.end;
                                j2 += 1;
                            }
                        }
                        // Absorb trailing tokens until a known clause boundary so
                        // the reconstructing formatter never drops unclaimed
                        // tokens (greedy-until-boundary, like the other carves).
                        // WITH only bounds when it starts [WITH] MASKING / TAG.
                        while j2 < end_idx {
                            let t2 = &self.tokens[j2];
                            let lex = t2.lexeme(self.source);
                            if is_column_tail_clause_lexeme(lex)
                                || is_generated_storage_lexeme(lex)
                                || (lex.eq_ignore_ascii_case("WITH") && j2 + 1 < end_idx && {
                                    let nx = self.tokens[j2 + 1].lexeme(self.source);
                                    nx.eq_ignore_ascii_case("MASKING")
                                        || nx.eq_ignore_ascii_case("TAG")
                                })
                            {
                                break;
                            }
                            end = t2.span.end;
                            j2 += 1;
                        }
                        virtual_expr_span = Some(Span { start, end });
                        i = j2;
                        continue;
                    }
                    // Storage keyword closing a generated expression.
                    if storage_keyword_span.is_none()
                        && virtual_expr_span.is_some()
                        && is_generated_storage_lexeme(t.lexeme(self.source))
                    {
                        storage_keyword_span = Some(t.span);
                        i += 1;
                        continue;
                    }
                    // Column-level COLLATE '<spec>' immediately after type.
                    if collate_span.is_none()
                        && t.lexeme(self.source).eq_ignore_ascii_case("COLLATE")
                    {
                        let start = t.span.start;
                        let mut end = t.span.end;
                        let mut j2 = i + 1;
                        while j2 < end_idx {
                            let t2 = &self.tokens[j2];
                            end = t2.span.end;
                            j2 += 1;
                            // Stop after the string literal or first non-string token.
                            if matches!(
                                t2.kind,
                                TokenKind::Literal(crate::lexer::LiteralKind::String)
                            ) {
                                break;
                            }
                        }
                        collate_span = Some(Span { start, end });
                        i = j2;
                        continue;
                    }
                    // IDENTITY / AUTOINCREMENT / MySQL AUTO_INCREMENT clause: capture from
                    // keyword through its trailing parenthesized argument list if present.
                    if identity_or_autoincrement_span.is_none()
                        && (t.lexeme(self.source).eq_ignore_ascii_case("IDENTITY")
                            || t.lexeme(self.source).eq_ignore_ascii_case("AUTOINCREMENT")
                            || t.lexeme(self.source).eq_ignore_ascii_case("AUTO_INCREMENT"))
                    {
                        let start = t.span.start;
                        let mut end = t.span.end;
                        let mut j2 = i + 1;
                        if j2 < end_idx {
                            if let TokenKind::Punctuation(crate::lexer::Punctuation::LParen) =
                                self.tokens[j2].kind
                            {
                                let mut depth: usize = 0;
                                while j2 < end_idx {
                                    let t2 = &self.tokens[j2];
                                    match t2.kind {
                                        TokenKind::Punctuation(
                                            crate::lexer::Punctuation::LParen,
                                        ) => {
                                            depth += 1;
                                        }
                                        TokenKind::Punctuation(
                                            crate::lexer::Punctuation::RParen,
                                        ) => {
                                            if depth == 0 {
                                                end = t2.span.end;
                                                j2 += 1;
                                                break;
                                            }
                                            depth -= 1;
                                        }
                                        _ => {}
                                    }
                                    end = t2.span.end;
                                    j2 += 1;
                                }
                            } else {
                                end = self.tokens[j2 - 1].span.end;
                            }
                        }
                        identity_or_autoincrement_span = Some(Span { start, end });
                        // Continue scanning to allow NOT NULL / DEFAULT after identity.
                        i = j2;
                        continue;
                    }
                    // A projection policy or a Databricks mask written after
                    // another clause: its name is kept, its tokens are read
                    // past.
                    if projection_policy.is_none() {
                        if let Some(clause) = self
                            .projection_policy_at(i)
                            .filter(|clause| clause.next <= end_idx)
                        {
                            projection_policy = Some(clause.policy);
                            i = clause.next;
                            continue;
                        }
                    }
                    if masking_policy.is_none() {
                        if let Some(clause) = self
                            .mask_function_at(i)
                            .filter(|clause| clause.next <= end_idx)
                        {
                            masking_policy = Some(clause.policy);
                            masking_policy_using = clause.columns;
                            i = clause.next;
                            continue;
                        }
                    }
                    // Column-level masking policy: [WITH] MASKING POLICY ...
                    // Triggers on MASKING, or on a leading WITH directly before it.
                    if masking_policy_span.is_none()
                        && (t.lexeme(self.source).eq_ignore_ascii_case("MASKING")
                            || (t.lexeme(self.source).eq_ignore_ascii_case("WITH")
                                && i + 1 < end_idx
                                && self.tokens[i + 1]
                                    .lexeme(self.source)
                                    .eq_ignore_ascii_case("MASKING")))
                    {
                        let start = t.span.start;
                        let mut end = self.tokens[i].span.end;
                        let mut j2 = i + 1;
                        // The policy's name is read whole: a part named like a
                        // clause (`gov.comment.p`) does not end the clause.
                        if let Some(clause) = self
                            .masking_policy_at(i)
                            .filter(|clause| clause.next <= end_idx)
                        {
                            j2 = clause.next;
                            end = self.tokens[clause.next - 1].span.end;
                            masking_policy = Some(clause.policy);
                            masking_policy_using = clause.columns;
                        }
                        while j2 < end_idx {
                            let t2 = &self.tokens[j2];
                            if is_column_tail_clause_lexeme(t2.lexeme(self.source))
                                && !t2.lexeme(self.source).eq_ignore_ascii_case("MASKING")
                            {
                                break;
                            }
                            end = t2.span.end;
                            j2 += 1;
                        }
                        masking_policy_span = Some(Span { start, end });
                        i = j2;
                        continue;
                    }
                    // Column-level [WITH] TAG (...) clause.
                    if tag_span.is_none()
                        && (t.lexeme(self.source).eq_ignore_ascii_case("TAG")
                            || (t.lexeme(self.source).eq_ignore_ascii_case("WITH")
                                && i + 1 < end_idx
                                && self.tokens[i + 1]
                                    .lexeme(self.source)
                                    .eq_ignore_ascii_case("TAG")))
                    {
                        let tag_at = if t.lexeme(self.source).eq_ignore_ascii_case("TAG") {
                            i
                        } else {
                            i + 1
                        };
                        if let Some((_, read)) =
                            self.parenthesised_tag_list_at(tag_at + 1, TagListShape::Assignments)
                        {
                            tags = read;
                        }
                        let start = t.span.start;
                        let mut end = t.span.end;
                        let mut j2 = i + 1;
                        let mut depth: usize = 0;
                        while j2 < end_idx {
                            let t2 = &self.tokens[j2];
                            // Stop TAG span before the next column tail clause start so that
                            // subsequent clauses (e.g. COMMENT) can be carved separately.
                            if depth == 0
                                && is_column_tail_clause_lexeme(t2.lexeme(self.source))
                                && !t2.lexeme(self.source).eq_ignore_ascii_case("TAG")
                            {
                                break;
                            }
                            match t2.kind {
                                TokenKind::Punctuation(crate::lexer::Punctuation::LParen) => {
                                    depth += 1;
                                }
                                TokenKind::Punctuation(crate::lexer::Punctuation::RParen) => {
                                    if depth == 0 {
                                        end = t2.span.end;
                                        j2 += 1;
                                        break;
                                    }
                                    depth -= 1;
                                }
                                _ => {}
                            }
                            end = t2.span.end;
                            j2 += 1;
                        }
                        tag_span = Some(Span { start, end });
                        // Do not consume trailing COMMENT; allow separate comment_span carving.
                        i = j2;
                        continue;
                    }
                    // Column-level COMMENT '...' clause.
                    if comment_span.is_none()
                        && t.lexeme(self.source).eq_ignore_ascii_case("COMMENT")
                    {
                        let start = t.span.start;
                        let mut end = t.span.end;
                        let mut j2 = i + 1;
                        while j2 < end_idx {
                            let t2 = &self.tokens[j2];
                            end = t2.span.end;
                            j2 += 1;
                            if matches!(
                                t2.kind,
                                TokenKind::Literal(crate::lexer::LiteralKind::String)
                            ) {
                                break;
                            }
                        }
                        comment_span = Some(Span { start, end });
                        i = j2;
                        continue;
                    }
                    if t.lexeme(self.source).eq_ignore_ascii_case("NOT") {
                        // Expect NULL immediately after.
                        if i + 1 < end_idx {
                            let t2 = &self.tokens[i + 1];
                            if t2.lexeme(self.source).eq_ignore_ascii_case("NULL") {
                                not_null_span = Some(Span {
                                    start: t.span.start,
                                    end: t2.span.end,
                                });
                                i += 2;
                                continue;
                            }
                        }
                    }
                    // T-SQL names a column's default: `CONSTRAINT name DEFAULT …`.
                    if default_expr_span.is_none()
                        && default_named_from.is_none()
                        && t.lexeme(self.source).eq_ignore_ascii_case("CONSTRAINT")
                        && i + 2 < end_idx
                        && self.can_be_identifier_token(&self.tokens[i + 1])
                        && self.tokens[i + 2]
                            .lexeme(self.source)
                            .eq_ignore_ascii_case("DEFAULT")
                    {
                        default_named_from = Some(t.span.start);
                        i += 2;
                        continue;
                    }
                    if t.lexeme(self.source).eq_ignore_ascii_case("DEFAULT") {
                        let start = t.span.start;
                        let mut j2 = i + 1;
                        let mut end = t.span.end;
                        while j2 < end_idx {
                            let t2 = &self.tokens[j2];
                            if is_column_tail_clause_lexeme(t2.lexeme(self.source))
                                && !t2.lexeme(self.source).eq_ignore_ascii_case("DEFAULT")
                            {
                                break;
                            }
                            end = t2.span.end;
                            j2 += 1;
                        }
                        default_keyword_at = Some(start);
                        default_expr_span = Some(Span {
                            start: default_named_from.unwrap_or(start),
                            end,
                        });
                        i = j2;
                        continue;
                    }
                    // Inline constraints: CONSTRAINT name PRIMARY KEY | UNIQUE | FOREIGN KEY REFERENCES ... | CHECK (...) | REFERENCES table(col)
                    if inline_constraint_id.is_none()
                        && (t.lexeme(self.source).eq_ignore_ascii_case("CONSTRAINT")
                            || t.lexeme(self.source).eq_ignore_ascii_case("PRIMARY")
                            || t.lexeme(self.source).eq_ignore_ascii_case("UNIQUE")
                            || t.lexeme(self.source).eq_ignore_ascii_case("FOREIGN")
                            || t.lexeme(self.source).eq_ignore_ascii_case("CHECK")
                            || t.lexeme(self.source).eq_ignore_ascii_case("REFERENCES"))
                    {
                        let constraint_start = t.span.start;
                        let mut j2 = i;

                        // Parse constraint structure and capture tokens
                        let mut constraint_keyword: Option<crate::cst::TokenId> = None;
                        let mut constraint_name: Option<crate::cst::TokenId> = None;
                        let mut constraint_type_keyword: Option<crate::cst::TokenId> = None;
                        let mut key_keyword: Option<crate::cst::TokenId> = None;
                        let mut references_keyword: Option<crate::cst::TokenId> = None;
                        let mut on_keyword: Option<crate::cst::TokenId> = None;
                        let mut action_trigger_keyword: Option<crate::cst::TokenId> = None;
                        let mut action_keyword: Option<crate::cst::TokenId> = None;

                        // CONSTRAINT keyword
                        if self.tokens[j2]
                            .lexeme(self.source)
                            .eq_ignore_ascii_case("CONSTRAINT")
                        {
                            constraint_keyword = Some(crate::cst::TokenId(j2 as u32));
                            j2 += 1;
                            // Constraint name (identifier)
                            if j2 < end_idx && self.can_be_identifier_token(&self.tokens[j2]) {
                                constraint_name = Some(crate::cst::TokenId(j2 as u32));
                                j2 += 1;
                            }
                        }

                        // Constraint type: PRIMARY, UNIQUE, FOREIGN, CHECK, or REFERENCES
                        // REFERENCES by itself is shorthand for FOREIGN KEY REFERENCES
                        let mut initial_references_target_start: Option<u32> = None;
                        if j2 < end_idx {
                            let type_tok = &self.tokens[j2];
                            if type_tok.lexeme(self.source).eq_ignore_ascii_case("PRIMARY")
                                || type_tok.lexeme(self.source).eq_ignore_ascii_case("UNIQUE")
                                || type_tok.lexeme(self.source).eq_ignore_ascii_case("FOREIGN")
                                || type_tok.lexeme(self.source).eq_ignore_ascii_case("CHECK")
                                || type_tok
                                    .lexeme(self.source)
                                    .eq_ignore_ascii_case("REFERENCES")
                            {
                                constraint_type_keyword = Some(crate::cst::TokenId(j2 as u32));

                                // For REFERENCES, also set references_keyword since it IS the constraint
                                // and set up target start for the next token
                                if type_tok
                                    .lexeme(self.source)
                                    .eq_ignore_ascii_case("REFERENCES")
                                {
                                    references_keyword = Some(crate::cst::TokenId(j2 as u32));
                                    if j2 + 1 < end_idx {
                                        initial_references_target_start =
                                            Some(self.tokens[j2 + 1].span.start);
                                    }
                                }

                                j2 += 1;

                                // KEY keyword (after PRIMARY/FOREIGN)
                                if j2 < end_idx
                                    && self.tokens[j2]
                                        .lexeme(self.source)
                                        .eq_ignore_ascii_case("KEY")
                                {
                                    key_keyword = Some(crate::cst::TokenId(j2 as u32));
                                    j2 += 1;
                                }
                            }
                        }

                        // Scan rest of constraint for REFERENCES, ON DELETE/UPDATE CASCADE/etc.
                        let mut depth: i32 = 0;
                        let mut constraint_end = self.tokens[j2.saturating_sub(1)].span.end;
                        let mut check_expr_span: Option<Span> = None;
                        let mut references_target_span: Option<Span> = None;
                        // Initialize with value from REFERENCES-as-constraint-type case
                        let mut references_target_start: Option<u32> =
                            initial_references_target_start;

                        while j2 < end_idx {
                            let t2 = &self.tokens[j2];

                            // Track parenthesis depth for CHECK (...) expressions
                            match t2.kind {
                                TokenKind::Punctuation(crate::lexer::Punctuation::LParen) => {
                                    depth += 1
                                }
                                TokenKind::Punctuation(crate::lexer::Punctuation::RParen) => {
                                    depth = depth.saturating_sub(1);
                                }
                                _ => {}
                            }

                            // Capture CHECK expression span (starts at first LParen after CHECK)
                            if check_expr_span.is_none()
                                && constraint_type_keyword.is_some()
                                && self.tokens[constraint_type_keyword.unwrap().0 as usize]
                                    .lexeme(self.source)
                                    .eq_ignore_ascii_case("CHECK")
                                && matches!(
                                    t2.kind,
                                    TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
                                )
                            {
                                let check_start = t2.span.start;
                                // Find matching closing paren
                                let mut check_depth = 1;
                                let mut check_j = j2 + 1;
                                while check_j < end_idx && check_depth > 0 {
                                    match self.tokens[check_j].kind {
                                        TokenKind::Punctuation(
                                            crate::lexer::Punctuation::LParen,
                                        ) => check_depth += 1,
                                        TokenKind::Punctuation(
                                            crate::lexer::Punctuation::RParen,
                                        ) => check_depth -= 1,
                                        _ => {}
                                    }
                                    check_j += 1;
                                }
                                if check_depth == 0 {
                                    check_expr_span = Some(Span {
                                        start: check_start,
                                        end: self.tokens[check_j - 1].span.end,
                                    });
                                }
                            }

                            // A `NOT NULL` after the constraint is the column's.
                            if depth == 0
                                && t2.lexeme(self.source).eq_ignore_ascii_case("NOT")
                                && self.tokens.get(j2 + 1).is_some_and(|next| {
                                    j2 + 1 < end_idx
                                        && next.lexeme(self.source).eq_ignore_ascii_case("NULL")
                                })
                            {
                                not_null_after_constraint = true;
                            }

                            // Stop at clauses that come AFTER constraints
                            if depth == 0
                                && (t2.lexeme(self.source).eq_ignore_ascii_case("COMMENT")
                                    || t2.lexeme(self.source).eq_ignore_ascii_case("MASKING")
                                    || t2.lexeme(self.source).eq_ignore_ascii_case("TAG"))
                            {
                                break;
                            }

                            // Capture REFERENCES keyword
                            if references_keyword.is_none()
                                && t2.lexeme(self.source).eq_ignore_ascii_case("REFERENCES")
                            {
                                references_keyword = Some(crate::cst::TokenId(j2 as u32));
                                // Start of references target is the next token
                                if j2 + 1 < end_idx {
                                    references_target_start = Some(self.tokens[j2 + 1].span.start);
                                }
                            }

                            // Capture ON keyword (for referential actions)
                            if on_keyword.is_none()
                                && t2.lexeme(self.source).eq_ignore_ascii_case("ON")
                            {
                                on_keyword = Some(crate::cst::TokenId(j2 as u32));
                                // End of references target is just before ON keyword
                                if let Some(ref_start) = references_target_start {
                                    references_target_span = Some(Span {
                                        start: ref_start,
                                        end: self.tokens[j2.saturating_sub(1)].span.end,
                                    });
                                }
                            }

                            // Capture DELETE/UPDATE keyword (after ON)
                            if on_keyword.is_some()
                                && action_trigger_keyword.is_none()
                                && (t2.lexeme(self.source).eq_ignore_ascii_case("DELETE")
                                    || t2.lexeme(self.source).eq_ignore_ascii_case("UPDATE"))
                            {
                                action_trigger_keyword = Some(crate::cst::TokenId(j2 as u32));
                            }

                            // Capture action keyword (CASCADE, SET NULL, etc.)
                            if action_trigger_keyword.is_some()
                                && action_keyword.is_none()
                                && (t2.lexeme(self.source).eq_ignore_ascii_case("CASCADE")
                                    || t2.lexeme(self.source).eq_ignore_ascii_case("SET")
                                    || t2.lexeme(self.source).eq_ignore_ascii_case("RESTRICT")
                                    || t2.lexeme(self.source).eq_ignore_ascii_case("NO"))
                            {
                                action_keyword = Some(crate::cst::TokenId(j2 as u32));
                            }

                            constraint_end = t2.span.end;
                            j2 += 1;
                        }

                        // If we have REFERENCES but no ON keyword, span extends to end of constraint
                        if references_keyword.is_some() && references_target_span.is_none() {
                            if let Some(ref_start) = references_target_start {
                                references_target_span = Some(Span {
                                    start: ref_start,
                                    end: constraint_end,
                                });
                            }
                        }

                        if let Some(crate::cst::TokenId(references)) = references_keyword {
                            foreign_key = self.foreign_key_at(
                                references as usize + 1,
                                end_idx,
                                name_span.into_iter().collect(),
                                constraint_name.map(|id| self.tokens[id.0 as usize].span),
                            );
                        }

                        // A `PRIMARY KEY` or `UNIQUE` is a key of this column.
                        key = constraint_type_keyword.and_then(|type_kw| {
                            let word = self.tokens[type_kw.0 as usize].lexeme(self.source);
                            if word.eq_ignore_ascii_case("PRIMARY") {
                                Some(crate::ast::AstColumnKey::PrimaryKey)
                            } else if word.eq_ignore_ascii_case("UNIQUE") {
                                Some(crate::ast::AstColumnKey::Unique)
                            } else {
                                None
                            }
                        });

                        inline_check_span = check_expr_span;
                        // Create syntax node only if we have a valid constraint type
                        if let Some(type_kw) = constraint_type_keyword {
                            let constraint_node = crate::syntax::SyntaxInlineConstraint {
                                constraint_keyword,
                                constraint_name,
                                constraint_type_keyword: type_kw,
                                key_keyword,
                                references_keyword,
                                references_target_span,
                                on_keyword,
                                action_trigger_keyword,
                                action_keyword,
                                check_expr_span,
                                span: Span {
                                    start: constraint_start,
                                    end: constraint_end,
                                },
                            };
                            inline_constraint_id =
                                Some(self.syntax_arena.alloc_inline_constraint(constraint_node));
                        }

                        i = j2;
                        continue;
                    }
                    i += 1;
                }

                // The expressions the column holds, each after its keyword.
                let default_expr = default_expr_span
                    .and_then(|span| {
                        self.expr_after_keyword(Span {
                            start: default_keyword_at.unwrap_or(span.start),
                            end: span.end,
                        })
                    })
                    .map(Box::new);
                let virtual_expr = virtual_expr_span
                    .and_then(|span| self.expr_after_keyword(span))
                    .map(Box::new);
                let check_expr = inline_check_span
                    .and_then(|span| self.expr_written_at(span))
                    .map(Box::new);
                columns.push(AstCreateTableColumn {
                    node_id: self.id_gen.next(),
                    full_span,
                    name_span,
                    type_span,
                    collate_span,
                    not_null_span,
                    default_expr_span,
                    identity_or_autoincrement_span,
                    generated_always_span,
                    virtual_expr_span,
                    storage_keyword_span,
                    inline_constraint_id,
                    foreign_key,
                    key,
                    not_null: not_null_span.is_some() || not_null_after_constraint,
                    masking_policy_span,
                    masking_policy,
                    masking_policy_using,
                    projection_policy,
                    tag_span,
                    tags,
                    comment_span,
                    default_expr,
                    virtual_expr,
                    check_expr,
                    check_span: inline_check_span,
                });
            }
            break;
        }
    }

    /// Every expression the constraint written over the tokens
    /// `start_idx..end_idx` holds: a `CHECK`'s condition, an `EXCLUDE`'s
    /// elements and `WHERE` predicate, a T-SQL `DEFAULT … FOR`'s value; none
    /// for a key. `None` where one of them is not one expression, or a
    /// string literal is written outside them.
    pub(crate) fn constraint_expressions(
        &mut self,
        start_idx: usize,
        end_idx: usize,
    ) -> Option<Vec<AstExpr>> {
        use crate::lexer::{IdentifierKind, LiteralKind, Punctuation};
        let end_idx = end_idx.min(self.tokens.len());
        let source = self.source;
        let tokens = self.tokens;
        let word = |i: usize| (i < end_idx).then(|| tokens[i].lexeme(source));
        let is = |i: usize, w: &str| word(i).is_some_and(|l| l.eq_ignore_ascii_case(w));
        let opens = |i: usize| {
            i < end_idx && matches!(tokens[i].kind, TokenKind::Punctuation(Punctuation::LParen))
        };
        // The `)` closing the `(` at `open`.
        let closing = |open: usize| {
            let mut depth = 0usize;
            for (k, tok) in tokens.iter().enumerate().take(end_idx).skip(open) {
                if matches!(tok.kind, TokenKind::Punctuation(Punctuation::LParen)) {
                    depth += 1;
                } else if matches!(tok.kind, TokenKind::Punctuation(Punctuation::RParen)) {
                    depth -= 1;
                    if depth == 0 {
                        return Some(k);
                    }
                }
            }
            None
        };
        // The first token from `from` to `to` that is `w` outside parentheses.
        let outside = |from: usize, to: usize, w: &str| {
            let mut depth = 0usize;
            for (k, tok) in tokens.iter().enumerate().take(to).skip(from) {
                if matches!(tok.kind, TokenKind::Punctuation(Punctuation::LParen)) {
                    depth += 1;
                } else if matches!(tok.kind, TokenKind::Punctuation(Punctuation::RParen)) {
                    depth = depth.saturating_sub(1);
                } else if depth == 0 && tok.lexeme(source).eq_ignore_ascii_case(w) {
                    return Some(k);
                }
            }
            None
        };
        let span_of = |from: usize, to: usize| {
            (from < to).then(|| Span {
                start: tokens[from].span.start,
                end: tokens[to - 1].span.end,
            })
        };
        let mut i = start_idx;
        if is(i, "CONSTRAINT") {
            i += 2;
        }
        // The token ranges read as expressions.
        let mut read: Vec<(usize, usize)> = Vec::new();
        if is(i, "CHECK") && opens(i + 1) {
            read.push((i + 1, closing(i + 1)? + 1));
        } else if is(i, "EXCLUDE") {
            let mut open = i + 1;
            if is(open, "USING") {
                open += 2;
            }
            if !opens(open) {
                return None;
            }
            let close = closing(open)?;
            let mut from = open + 1;
            while from < close {
                let to = outside(from, close, ",").unwrap_or(close);
                read.push((from, outside(from, to, "WITH")?));
                from = to + 1;
            }
            if let Some(at) = outside(close + 1, end_idx, "WHERE") {
                if !opens(at + 1) {
                    return None;
                }
                read.push((at + 1, closing(at + 1)? + 1));
            }
        } else if is(i, "DEFAULT") {
            read.push((i + 1, outside(i + 1, end_idx, "FOR")?));
        } else if !(is(i, "PRIMARY") || is(i, "UNIQUE") || is(i, "FOREIGN") || is(i, "REFERENCES"))
        {
            return None;
        }
        let unread_literal = (start_idx..end_idx).any(|k| {
            matches!(
                tokens[k].kind,
                TokenKind::Literal(LiteralKind::String | LiteralKind::StringFragment)
                    | TokenKind::Unknown
                    | TokenKind::Identifier {
                        kind: IdentifierKind::DollarQuoteDelimiter,
                        ..
                    }
            ) && !read.iter().any(|&(from, to)| from <= k && k < to)
        });
        if unread_literal {
            return None;
        }
        read.into_iter()
            .map(|(from, to)| self.expr_written_at(span_of(from, to)?))
            .collect()
    }

    /// The value of the T-SQL `[CONSTRAINT name] DEFAULT <value> FOR
    /// <column>` constraint written from `start_idx` to `end_idx`.
    pub(crate) fn constraint_default(&self, start_idx: usize, end_idx: usize) -> Option<Span> {
        let end_idx = end_idx.min(self.tokens.len());
        let is = |i: usize, w: &str| {
            i < end_idx && self.tokens[i].lexeme(self.source).eq_ignore_ascii_case(w)
        };
        let mut i = start_idx;
        if is(i, "CONSTRAINT") {
            i += 2;
        }
        if !is(i, "DEFAULT") {
            return None;
        }
        let first = i + 1;
        let mut depth = 0usize;
        let mut last = None;
        for k in first..end_idx {
            let kind = &self.tokens[k].kind;
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
            } else if depth == 0 && is(k, "FOR") {
                break;
            }
            last = Some(k);
        }
        let last = last?;
        Some(Span {
            start: self.tokens.get(first)?.span.start,
            end: self.tokens.get(last)?.span.end,
        })
    }

    /// Parse constraint details for PRIMARY KEY, UNIQUE, or FOREIGN KEY.
    /// Returns None if the constraint cannot be parsed (e.g., CHECK constraints,
    /// or complex property clauses that we don't handle yet).
    ///
    /// This method uses safe token access through bounds checking since it operates
    /// on a pre-determined token range from build_create_table_item. The range
    /// represents a single table constraint item isolated by comma separation.
    pub(crate) fn parse_constraint_details(
        &mut self,
        start_idx: usize,
        end_idx: usize,
    ) -> Option<crate::ast::AstConstraintDetails> {
        if end_idx <= start_idx {
            return None;
        }

        let mut idx = start_idx;
        let mut constraint_name: Option<Span> = None;

        // Helper to safely get token at index
        let get_token = |i: usize| -> Option<&crate::lexer::Token> {
            if i < end_idx && i < self.tokens.len() {
                Some(&self.tokens[i])
            } else {
                None
            }
        };

        // Skip to first non-EOF token
        while idx < end_idx {
            if let Some(tok) = get_token(idx) {
                if !matches!(tok.kind, TokenKind::Eof) {
                    break;
                }
            }
            idx += 1;
        }

        if idx >= end_idx {
            return None;
        }

        // Check for optional CONSTRAINT <name>
        let first_tok = get_token(idx)?;

        if first_tok
            .lexeme(self.source)
            .eq_ignore_ascii_case("CONSTRAINT")
        {
            idx += 1;
            // Next token should be the constraint name
            if let Some(name_tok) = get_token(idx) {
                if self.can_be_identifier_token(name_tok) {
                    constraint_name = Some(name_tok.span);
                    idx += 1;
                }
            }
        }

        // Find the constraint type keyword
        while idx < end_idx {
            if let Some(tok) = get_token(idx) {
                if !matches!(tok.kind, TokenKind::Eof) {
                    break;
                }
            }
            idx += 1;
        }

        if idx >= end_idx {
            return None;
        }

        let constraint_type_tok = get_token(idx)?;

        if constraint_type_tok
            .lexeme(self.source)
            .eq_ignore_ascii_case("PRIMARY")
        {
            // Expect: PRIMARY KEY (col1, col2, ...)
            idx += 1;
            let key_tok = get_token(idx)?;
            if !key_tok.lexeme(self.source).eq_ignore_ascii_case("KEY") {
                return None;
            }
            idx += 1;

            // Parse column list
            let columns = self.parse_constraint_column_list(idx, end_idx)?;

            Some(crate::ast::AstConstraintDetails {
                node_id: self.id_gen.next(),
                name: constraint_name,
                kind: crate::ast::AstConstraintKind::PrimaryKey { columns },
            })
        } else if constraint_type_tok
            .lexeme(self.source)
            .eq_ignore_ascii_case("UNIQUE")
        {
            // Expect: UNIQUE [KEY | INDEX | CLUSTERED | NONCLUSTERED]
            // [index_name] [USING …] (col1, col2, ...); the index's name,
            // where written, is the key's (MySQL).
            idx += 1;
            let word = |i: usize, words: &[&str]| {
                get_token(i).is_some_and(|tok| {
                    words
                        .iter()
                        .any(|word| tok.lexeme(self.source).eq_ignore_ascii_case(word))
                })
            };
            if word(idx, &["KEY", "INDEX", "CLUSTERED", "NONCLUSTERED"]) {
                idx += 1;
            }
            let opens = get_token(idx + 1).is_some_and(|tok| {
                matches!(
                    tok.kind,
                    TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
                )
            });
            let index_name = get_token(idx)
                .filter(|tok| {
                    self.can_be_identifier_token(tok)
                        && !word(idx, &["USING"])
                        && (opens || word(idx + 1, &["USING"]))
                })
                .map(|tok| tok.span);
            let constraint_name = index_name.or(constraint_name);

            // Parse column list
            let columns = self.parse_constraint_column_list(idx, end_idx)?;

            Some(crate::ast::AstConstraintDetails {
                node_id: self.id_gen.next(),
                name: constraint_name,
                kind: crate::ast::AstConstraintKind::Unique { columns },
            })
        } else if constraint_type_tok
            .lexeme(self.source)
            .eq_ignore_ascii_case("FOREIGN")
        {
            // Expect: FOREIGN KEY (col1, ...) REFERENCES table (ref_col1, ...)
            idx += 1;
            let key_tok = get_token(idx)?;
            if !key_tok.lexeme(self.source).eq_ignore_ascii_case("KEY") {
                return None;
            }
            idx += 1;

            // Parse column list
            let columns = self.parse_constraint_column_list(idx, end_idx)?;

            // Find REFERENCES keyword
            let mut ref_idx = idx;
            while ref_idx < end_idx {
                if let Some(tok) = get_token(ref_idx) {
                    if tok.lexeme(self.source).eq_ignore_ascii_case("REFERENCES") {
                        break;
                    }
                }
                ref_idx += 1;
            }

            if ref_idx >= end_idx {
                return None; // No REFERENCES found
            }

            ref_idx += 1; // Skip REFERENCES keyword

            self.foreign_key_at(ref_idx, end_idx, columns, constraint_name)
        } else if constraint_type_tok
            .lexeme(self.source)
            .eq_ignore_ascii_case("CHECK")
        {
            // We don't parse CHECK constraints yet - fall back to span
            None
        } else {
            None
        }
    }

    /// The foreign key `name [(ref_col, …)]` of `columns` whose referenced
    /// table's name starts at token `target` (just past `REFERENCES`), read
    /// within `tokens[..end_idx]`. `None` where no name starts there or a
    /// column list opened after it cannot be read.
    pub(crate) fn foreign_key_at(
        &mut self,
        target: usize,
        end_idx: usize,
        columns: Vec<Span>,
        name: Option<Span>,
    ) -> Option<crate::ast::AstConstraintDetails> {
        if target >= end_idx {
            return None;
        }
        let table_id = self.id_gen.next();
        let (name_end, references_table) = self
            .object_ref_at(target, table_id)
            .filter(|(name_end, _)| *name_end <= end_idx)?;
        let list_opens = name_end < end_idx
            && matches!(
                self.tokens[name_end].kind,
                TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
            );
        let references_columns = if list_opens {
            self.parse_constraint_column_list(name_end, end_idx)?
        } else {
            Vec::new()
        };
        Some(crate::ast::AstConstraintDetails {
            node_id: self.id_gen.next(),
            name,
            kind: crate::ast::AstConstraintKind::ForeignKey {
                columns,
                references_table,
                references_columns,
            },
        })
    }

    /// Helper to parse a parenthesized column list: (col1, col2, ...)
    /// Returns the span of each element's column name, its first
    /// identifier: what follows it (`ASC`, `DESC`, an operator class) is
    /// not a column.
    ///
    /// This method uses safe token access through bounds checking since it operates
    /// on a pre-determined token range.
    fn parse_constraint_column_list(&self, start_idx: usize, end_idx: usize) -> Option<Vec<Span>> {
        let mut idx = start_idx;

        // Helper to safely get token at index
        let get_token = |i: usize| -> Option<&crate::lexer::Token> {
            if i < end_idx && i < self.tokens.len() {
                Some(&self.tokens[i])
            } else {
                None
            }
        };

        // Skip to opening paren
        while idx < end_idx {
            if let Some(tok) = get_token(idx) {
                if matches!(
                    tok.kind,
                    TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
                ) {
                    break;
                }
            }
            idx += 1;
        }

        if idx >= end_idx {
            return None; // No opening paren
        }

        idx += 1; // Skip opening paren
        let mut columns = Vec::new();
        let mut depth = 1;
        // Whether the element at depth 1 has named no column yet.
        let mut unnamed = true;

        while idx < end_idx && depth > 0 {
            if let Some(tok) = get_token(idx) {
                match &tok.kind {
                    TokenKind::Punctuation(crate::lexer::Punctuation::LParen) => {
                        depth += 1;
                        idx += 1;
                    }
                    TokenKind::Punctuation(crate::lexer::Punctuation::RParen) => {
                        depth -= 1;
                        if depth == 0 {
                            break;
                        }
                        idx += 1;
                    }
                    _ if self.can_be_identifier_token(tok) && depth == 1 => {
                        // Only collect identifiers/keywords at depth 1 (not nested)
                        if unnamed {
                            columns.push(tok.span);
                            unnamed = false;
                        }
                        idx += 1;
                    }
                    TokenKind::Punctuation(crate::lexer::Punctuation::Comma) => {
                        unnamed |= depth == 1;
                        idx += 1;
                    }
                    TokenKind::Eof => {
                        idx += 1;
                    }
                    _ => {
                        idx += 1;
                    }
                }
            } else {
                break;
            }
        }

        if columns.is_empty() {
            None
        } else {
            Some(columns)
        }
    }

    /// Parse CLUSTER BY expressions: CLUSTER BY (expr1, expr2, ...)
    /// Uses smart parsing: tries to parse expressions, falls back to None on failure.
    ///
    /// This allows the formatter to work with structured expression data when parsing
    /// succeeds, while preserving backward compatibility via cluster_by_span.
    fn parse_cluster_by_expressions(
        &mut self,
        start_idx: usize,
        end_idx: usize,
    ) -> Option<Vec<AstExpr>> {
        // Save current parser position
        let saved_idx = self.idx;

        // Find "CLUSTER BY (" pattern
        let mut idx = start_idx;
        let mut found_cluster = false;
        let mut found_by = false;
        let mut paren_idx = None;

        while idx < end_idx {
            if idx >= self.tokens.len() {
                break;
            }
            let tok = &self.tokens[idx];

            if !found_cluster && tok.lexeme(self.source).eq_ignore_ascii_case("CLUSTER") {
                found_cluster = true;
                idx += 1;
                continue;
            }

            if found_cluster && !found_by && tok.lexeme(self.source).eq_ignore_ascii_case("BY") {
                found_by = true;
                idx += 1;
                continue;
            }

            if found_cluster
                && found_by
                && matches!(
                    tok.kind,
                    TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
                )
            {
                paren_idx = Some(idx);
                break;
            }

            idx += 1;
        }

        let paren_idx = match paren_idx {
            Some(p) => p,
            None => {
                self.idx = saved_idx;
                return None; // No opening paren found
            }
        };

        // Find matching closing paren
        let mut depth = 0;
        let mut close_paren_idx = None;
        idx = paren_idx;

        while idx < end_idx {
            if idx >= self.tokens.len() {
                break;
            }
            let tok = &self.tokens[idx];

            match &tok.kind {
                TokenKind::Punctuation(crate::lexer::Punctuation::LParen) => {
                    depth += 1;
                }
                TokenKind::Punctuation(crate::lexer::Punctuation::RParen) => {
                    depth -= 1;
                    if depth == 0 {
                        close_paren_idx = Some(idx);
                        break;
                    }
                }
                _ => {}
            }
            idx += 1;
        }

        let close_paren_idx = match close_paren_idx {
            Some(c) => c,
            None => {
                self.idx = saved_idx;
                return None; // No closing paren found
            }
        };

        // Now parse expressions between parens using streaming parser
        self.idx = paren_idx + 1; // Position after opening paren
        let mut exprs = Vec::new();

        loop {
            // Check if we've reached the closing paren
            if self.idx >= close_paren_idx {
                break;
            }

            // Try to parse an expression
            let expr = match self.parse_expr() {
                Ok(e) => e,
                Err(_) => {
                    // Parse failed - restore position and return None (fallback to span)
                    self.idx = saved_idx;
                    return None;
                }
            };

            exprs.push(expr);

            // Check for comma or closing paren
            if self.idx >= self.tokens.len() || self.idx >= close_paren_idx {
                break;
            }

            let tok = &self.tokens[self.idx];
            if matches!(
                tok.kind,
                TokenKind::Punctuation(crate::lexer::Punctuation::Comma)
            ) {
                self.idx += 1; // Skip comma
                continue;
            } else if matches!(
                tok.kind,
                TokenKind::Punctuation(crate::lexer::Punctuation::RParen)
            ) {
                // Reached closing paren
                break;
            } else {
                // Unexpected token - fall back to span
                self.idx = saved_idx;
                return None;
            }
        }

        // Restore parser position
        self.idx = saved_idx;

        if exprs.is_empty() {
            None
        } else {
            Some(exprs)
        }
    }

    /// Parse UNDROP TABLE statement.
    pub(crate) fn try_parse_undrop_table(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("undrop_table")?;

        // UNDROP - Identifier, not keyword!
        let undrop_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["UNDROP".to_string()])?;
        let undrop_span = undrop_tok.span;

        // TABLE - this IS a keyword (unlike DATABASE/SCHEMA which are identifiers)
        let table_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["TABLE".to_string()])?;

        if !matches!(table_tok.kind, TokenKind::Keyword(Keyword::Table)) {
            return Err(ParseError::new(
                table_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: format!("Expected TABLE, found '{}'", table_tok.lexeme(self.source)),
                },
            ));
        }
        let table_span = table_tok.span;

        // Table name (may be qualified: db.schema.table)
        let name_span = self.parse_qualified_name_span()?;

        let span = Span {
            start: undrop_span.start,
            end: name_span.end,
        };

        Ok(AstStmt::UndropTable(Box::new(crate::ast::AstUndropTable {
            node_id: self.id_gen.next(),
            span,
            undrop_span,
            table_span,
            name_span,
        })))
    }
}
