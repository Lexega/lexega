// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

// CREATE TABLE statement parsing
// Extracted from core.rs to reduce monolithic file size

use crate::ast::{
    AstCreateTable, AstCreateTableColumn, AstCreateTableConstraint, AstCreateTableVariant, AstExpr,
    AstStmt, AstTimeTravel,
};
use crate::error::{ExpectInvariant, ParseError, ParseErrorKind, ParseResult, ParseResultExt};
use crate::lexer::{Keyword, Span, TokenKind};
use crate::parser::core::Parser;

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

impl Parser<'_> {
    /// Parse column definitions and constraints within CREATE TABLE
    fn parse_create_table_columns_and_constraints(
        &mut self,
        start_idx: usize,
        end_idx: usize,
    ) -> (Vec<AstCreateTableColumn>, Vec<AstCreateTableConstraint>) {
        let mut columns = Vec::new();
        let mut constraints = Vec::new();

        if end_idx <= start_idx {
            return (columns, constraints);
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
            self.build_create_table_item(
                item_start_idx,
                item_end_idx,
                &mut columns,
                &mut constraints,
            );
        }

        (columns, constraints)
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
        Option<Span>, // clone_temporal_span (Databricks TIMESTAMP/VERSION AS OF)
    ) {
        let mut variant = AstCreateTableVariant::Plain;
        let mut like_source_span = None;
        let mut clone_source_span = None;
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
                let mut end = start;
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
            } else if tok.lexeme(self.source).eq_ignore_ascii_case("AS") {
                // CTAS: table options have already been parsed, now consume AS and the query
                // According to Snowflake docs:
                // CREATE TABLE name [(cols)] [CLUSTER BY ...] [COPY GRANTS] AS query
                variant = AstCreateTableVariant::Ctas;
                let as_start = tok.span.start;
                self.advance(); // Consume AS

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
            );
        }

        // Find option starter keywords
        let mut i = options_start_idx;
        let mut starter_indices = Vec::new();
        while i < options_end_idx {
            let tok = &self.tokens[i];
            if is_table_option_starter(tok.lexeme(self.source)) {
                starter_indices.push(i);
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

            if lexeme.eq_ignore_ascii_case("CLUSTER") {
                cluster_by_span = Some(opt_span);
                // Try to parse CLUSTER BY expressions using smart parsing
                cluster_by_exprs = self.parse_cluster_by_expressions(start_idx, end_idx);
            } else if lexeme.eq_ignore_ascii_case("PARTITION") {
                partition_by_span = Some(opt_span);
            } else if lexeme.eq_ignore_ascii_case("COPY") {
                // Distinguish COPY GRANTS from COPY TAGS
                if start_idx + 1 < options_end_idx {
                    let next_lexeme = self.tokens[start_idx + 1].lexeme(self.source);
                    if next_lexeme.eq_ignore_ascii_case("TAGS") {
                        copy_tags_span = Some(opt_span);
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
            } else if lexeme.eq_ignore_ascii_case("TAG") {
                tag_span = Some(opt_span);
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
        )
    }
    pub(crate) fn try_parse_create_table_stmt(&mut self) -> crate::error::ParseResult<AstStmt> {
        use crate::error::{ExpectInvariant, ParseError, ParseErrorKind, ParseResultExt};

        let create_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["CREATE".to_string()])?; // CREATE
        let keyword_span = create_tok.span;
        let mut span = keyword_span;
        let mut or_replace_span: Option<Span> = None;
        let mut temp_kind_span: Option<Span> = None;
        let mut table_kind: Option<crate::ast::AstTableKind> = None;
        let mut table_kind_span: Option<Span> = None;

        let mut columns_span: Option<Span> = None;
        let mut lparen_span: Option<Span> = None;
        let mut rparen_span: Option<Span> = None;

        let retention_span: Option<Span> = None;

        let mut columns: Vec<AstCreateTableColumn> = Vec::new();
        let mut constraints: Vec<AstCreateTableConstraint> = Vec::new();

        // Optional OR REPLACE / OR REFRESH (Databricks DLT)
        if let Some(tok) = self.peek() {
            if tok.lexeme(self.source).eq_ignore_ascii_case("OR") {
                let or_tok = self
                    .advance()
                    .expect_invariant("OR keyword should be available after peek");
                if let Some(rep_tok) = self.peek() {
                    if rep_tok.lexeme(self.source).eq_ignore_ascii_case("REPLACE")
                        || rep_tok.lexeme(self.source).eq_ignore_ascii_case("REFRESH")
                    {
                        let rep = self.advance().expect_invariant(
                            "REPLACE/REFRESH keyword should be available after peek",
                        );
                        or_replace_span = Some(Span {
                            start: or_tok.span.start,
                            end: rep.span.end,
                        });
                        span.end = rep.span.end;
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
                start_span = Some(t.span);
                end_span = Some(t.span);
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

        // Optional Databricks DLT modifier: LIVE TABLE
        if let Some(tok) = self.peek() {
            if tok.lexeme(self.source).eq_ignore_ascii_case("LIVE") {
                let live_tok = self
                    .advance()
                    .expect_invariant("LIVE keyword should be available after peek");
                span.end = live_tok.span.end;
                temp_kind_span = Some(match temp_kind_span {
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
        // CLONE/COPY/CLUSTER/... clause. Missing that left name_span None for an
        // unquoted keyword name (e.g. `clone`, `copy`, `tag`) and dropped the whole
        // statement to OpaqueContent. name_span stays inclusive of the IF NOT
        // EXISTS prefix, matching the AstCreateTable contract (no separate field).
        let name_start_idx = self.idx;

        // Consume an optional IF NOT EXISTS prefix so the scan lands on the name,
        // keeping the following part-position logic correct across dialects.
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
            self.advance();
            self.advance();
            self.advance();
        }

        let mut at_part_start = true;
        while let Some(tok) = self.peek() {
            if at_part_start
                && (self.can_be_identifier_token(tok)
                    || matches!(tok.kind, TokenKind::JinjaExprOpen))
            {
                let _ = self.advance();
                at_part_start = false;
                continue;
            }
            if self.should_stop_scan_at_statement_start(tok) {
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
                _ => {
                    let _ = self.advance();
                }
            }
        }
        let name_end_idx = self.idx;
        let mut name_span: Option<Span> = None;
        if name_end_idx > name_start_idx {
            let first = &self.tokens[name_start_idx];
            let last = &self.tokens[name_end_idx - 1];
            name_span = Some(Span {
                start: first.span.start,
                end: last.span.end,
            });
            span.end = last.span.end;
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
            match tok.kind {
                TokenKind::Keyword(Keyword::Like)
                | TokenKind::Keyword(Keyword::As)
                | TokenKind::Keyword(Keyword::From)
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
        let variant: AstCreateTableVariant = variant_result.0;
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
                }
            }
        }

        // Note: Snowflake allows multiple PRIMARY KEY constraints (both inline and out-of-line)
        // on the same column. This is valid syntax per the official documentation.
        // We parse and preserve all constraints without validation here.

        let name_span = name_span.ok_or_else(|| {
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
        let stmt = AstCreateTable {
            node_id: self.id_gen.next(),
            span,
            keyword_span,
            or_replace_span,
            scoped_span,
            temp_kind_span,
            table_kind,
            table_kind_span,
            table_keyword_span,
            name_span,
            columns_span,
            semicolon_token: None,
            lparen_span,
            rparen_span,
            variant,
            like_source_span,
            clone_source_span,
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
            aggregation_policy_span,
            join_policy_span,
            storage_lifecycle_policy_span,
            tag_span,
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
            let is_constraint_keyword = t0.lexeme(self.source).eq_ignore_ascii_case("CONSTRAINT")
                || t0.lexeme(self.source).eq_ignore_ascii_case("PRIMARY")
                || t0.lexeme(self.source).eq_ignore_ascii_case("UNIQUE")
                || t0.lexeme(self.source).eq_ignore_ascii_case("FOREIGN")
                || t0.lexeme(self.source).eq_ignore_ascii_case("CHECK");
            if is_constraint_keyword {
                // Try to parse constraint details with smart fallback
                let details = self.parse_constraint_details(start_idx, end_idx);
                constraints.push(AstCreateTableConstraint {
                    node_id: self.id_gen.next(),
                    full_span,
                    details,
                });
            } else {
                // Column-level splitting for 3.3: name/type and key constraint spans.
                let mut name_span: Option<Span> = None;
                let mut type_span: Option<Span> = None;
                let mut collate_span: Option<Span> = None;
                let mut not_null_span: Option<Span> = None;
                let mut default_expr_span: Option<Span> = None;
                let mut identity_or_autoincrement_span: Option<Span> = None;
                let mut generated_always_span: Option<Span> = None;
                let mut virtual_expr_span: Option<Span> = None;
                let mut storage_keyword_span: Option<Span> = None;
                let mut inline_constraint_id: Option<crate::syntax::SyntaxInlineConstraintId> =
                    None;
                let mut masking_policy_span: Option<Span> = None;
                let mut tag_span: Option<Span> = None;
                let mut comment_span: Option<Span> = None;

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
                        default_expr_span = Some(Span { start, end });
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
                    masking_policy_span,
                    tag_span,
                    comment_span,
                });
            }
            break;
        }
    }

    /// Parse constraint details for PRIMARY KEY, UNIQUE, or FOREIGN KEY.
    /// Returns None if the constraint cannot be parsed (e.g., CHECK constraints,
    /// or complex property clauses that we don't handle yet).
    ///
    /// This method uses safe token access through bounds checking since it operates
    /// on a pre-determined token range from build_create_table_item. The range
    /// represents a single table constraint item isolated by comma separation.
    fn parse_constraint_details(
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
            // Expect: UNIQUE (col1, col2, ...)
            idx += 1;

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

            // Parse referenced table name (can be qualified: db.schema.table)
            let mut table_start: Option<u32> = None;
            let mut table_end: Option<u32> = None;

            while ref_idx < end_idx {
                if let Some(tok) = get_token(ref_idx) {
                    match &tok.kind {
                        TokenKind::Identifier { .. }
                        | TokenKind::Punctuation(crate::lexer::Punctuation::Dot) => {
                            if table_start.is_none() {
                                table_start = Some(tok.span.start);
                            }
                            table_end = Some(tok.span.end);
                            ref_idx += 1;
                        }
                        TokenKind::Punctuation(crate::lexer::Punctuation::LParen) => {
                            break; // Found start of column list
                        }
                        TokenKind::Eof => {
                            ref_idx += 1;
                        }
                        _ => {
                            break;
                        }
                    }
                } else {
                    break;
                }
            }

            let references_table = if let (Some(start), Some(end)) = (table_start, table_end) {
                Span { start, end }
            } else {
                return None; // No table name found
            };

            // Parse referenced column list
            let references_columns = self.parse_constraint_column_list(ref_idx, end_idx)?;

            Some(crate::ast::AstConstraintDetails {
                node_id: self.id_gen.next(),
                name: constraint_name,
                kind: crate::ast::AstConstraintKind::ForeignKey {
                    columns,
                    references_table,
                    references_columns,
                },
            })
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

    /// Helper to parse a parenthesized column list: (col1, col2, ...)
    /// Returns spans for each column identifier.
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
                        columns.push(tok.span);
                        idx += 1;
                    }
                    TokenKind::Punctuation(crate::lexer::Punctuation::Comma) => {
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
