// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Parser for the T-SQL / PolyBase `CREATE EXTERNAL DATA SOURCE` statement.
//!
//! `CREATE EXTERNAL DATA SOURCE <name> WITH ( LOCATION = '...'
//!  [, TYPE = HADOOP | BLOB_STORAGE | RDBMS | SHARD_MAP_MANAGER]
//!  [, CREDENTIAL = <name>] [, PUSHDOWN = ON | OFF] [, ...] )`
//!
//! Registers a federated endpoint (Hadoop cluster, Azure blob, remote
//! RDBMS, sharded DB). Recognition lifts neutral primitives only — the
//! LOCATION URI scheme, the typed TYPE class, whether a CREDENTIAL is
//! referenced, and PUSHDOWN. The raw LOCATION literal is never surfaced:
//! PolyBase connection strings can embed credentials.
//!
//! Dispatched from the `CREATE EXTERNAL` disambiguator in `core.rs` when the
//! token after EXTERNAL is the identifier `DATA`.
//!
//! Token reference (`--debug-tokens`, mssql dialect):
//!   EXTERNAL / DATA / SOURCE / LOCATION / CREDENTIAL / PUSHDOWN / HADOOP
//!     / BLOB_STORAGE                       → Identifier (not Keyword!)
//!   WITH / TYPE                            → Keyword
//!   = → Operator(Eq); '...' → Literal(String)

use crate::ast::types::{
    AstExternalDataSourceType, AstMssqlAlterExternalDataSource, AstMssqlCreateExternalDataSource,
    AstStmt,
};
use crate::error::{ParseError, ParseErrorKind, ParseResult, ParseResultExt};
use crate::lexer::{Keyword, Operator, Punctuation, Span, TokenKind};
use crate::parser::core::Parser;

impl<'a> Parser<'a> {
    pub(crate) fn try_parse_mssql_create_external_data_source(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("create_external_data_source")?;
        let start_span = self.current_span();

        // 1. CREATE [OR { REPLACE | ALTER }] EXTERNAL DATA SOURCE keywords.
        //    The dispatch guard guarantees CREATE / EXTERNAL / DATA; SOURCE is
        //    validated here. The dispatch already peeked past the OR modifier,
        //    but rewound to CREATE, so it is re-consumed here (the contract for
        //    every CREATE parser).
        let create_tok = self
            .advance()
            .ok_or_eof(start_span, vec!["CREATE".to_string()])?;
        let start = create_tok.span.start;
        // Optional `OR REPLACE` / `OR ALTER` / `OR REFRESH`.
        let mut or_replace = false;
        if matches!(
            self.peek_non_trivia().map(|t| &t.kind),
            Some(TokenKind::Keyword(Keyword::Or))
        ) {
            self.advance()
                .ok_or_eof(self.current_span(), vec!["OR".to_string()])?;
            let modifier = self
                .advance()
                .ok_or_eof(self.current_span(), vec!["REPLACE".to_string()])?;
            let lex = modifier.lexeme(self.source);
            if lex.eq_ignore_ascii_case("REPLACE")
                || lex.eq_ignore_ascii_case("ALTER")
                || lex.eq_ignore_ascii_case("REFRESH")
            {
                or_replace = true;
            }
        }
        self.advance()
            .ok_or_eof(self.current_span(), vec!["EXTERNAL".to_string()])?;
        self.advance()
            .ok_or_eof(self.current_span(), vec!["DATA".to_string()])?;
        let source_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["SOURCE".to_string()])?;
        if !source_tok
            .lexeme(self.source)
            .eq_ignore_ascii_case("SOURCE")
        {
            return Err(ParseError::new(
                source_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: "Expected SOURCE after CREATE EXTERNAL DATA".to_string(),
                },
            ));
        }
        let keyword_span = Span {
            start,
            end: source_tok.span.end,
        };

        // 2. Optional IF NOT EXISTS, then the data-source name (possibly qualified).
        let if_not_exists = self.parse_optional_if_not_exists()?.is_some();
        let name_span = self.parse_qualified_name_span()?;
        let mut end = name_span.end;

        // 3. Optional WITH ( <key = value>, ... ) property bag. Walk the
        //    balanced paren group, lifting recognition primitives.
        let mut props = EdsProps::default();

        if matches!(
            self.peek_non_trivia().map(|t| &t.kind),
            Some(TokenKind::Keyword(Keyword::With))
        ) {
            self.advance()
                .ok_or_eof(self.current_span(), vec!["WITH".to_string()])?;
            let lparen = self
                .advance()
                .ok_or_eof(self.current_span(), vec!["(".to_string()])?;
            if !matches!(lparen.kind, TokenKind::Punctuation(Punctuation::LParen)) {
                return Err(ParseError::new(
                    lparen.span,
                    ParseErrorKind::InvalidStatement {
                        message: "Expected ( after WITH in CREATE EXTERNAL DATA SOURCE".to_string(),
                    },
                ));
            }
            end = lparen.span.end;

            // depth starts at 1 (inside the WITH paren). Recognize each
            // depth-1 `<key> =` pair and classify its value token.
            let mut depth: u32 = 1;
            while depth > 0 {
                let tok = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec![")".to_string()])?;
                end = tok.span.end;
                match tok.kind {
                    TokenKind::Punctuation(Punctuation::LParen) => {
                        depth += 1;
                        continue;
                    }
                    TokenKind::Punctuation(Punctuation::RParen) => {
                        depth = depth.saturating_sub(1);
                        continue;
                    }
                    _ => {}
                }
                if depth != 1 {
                    continue;
                }
                // A key is followed by `=`. Identify the key, then read value.
                let is_type_key = matches!(tok.kind, TokenKind::Keyword(Keyword::Type));
                let key_lex = tok.lexeme(self.source);
                let Some(key) = EdsProps::key_of(is_type_key, key_lex) else {
                    continue;
                };
                if !matches!(
                    self.peek_non_trivia().map(|t| &t.kind),
                    Some(TokenKind::Operator(Operator::Eq))
                ) {
                    continue;
                }
                self.advance()
                    .ok_or_eof(self.current_span(), vec!["=".to_string()])?;
                let val = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["value".to_string()])?;
                end = val.span.end;
                props.ingest(key, val.lexeme(self.source));
            }
        }

        // 4. Trailing semicolon stays out of the statement span (mod.rs gap
        //    emission owns it), matching sibling parsers.
        let stmt_span = Span { start, end };
        let ast = AstMssqlCreateExternalDataSource {
            node_id: self.id_gen.next(),
            span: stmt_span,
            keyword_span,
            or_replace,
            if_not_exists,
            name_span,
            location_present: props.location_present,
            location_scheme: props.location_scheme,
            source_type: props.source_type,
            credential_present: props.credential_present,
            pushdown: props.pushdown,
        };
        Ok(AstStmt::MssqlCreateExternalDataSource(Box::new(ast)))
    }

    /// `ALTER EXTERNAL DATA SOURCE <name> SET { LOCATION = '…' |
    /// CREDENTIAL = <name> | … }`. Reconfigures an existing endpoint.
    ///
    /// Dispatched from the `ALTER EXTERNAL` disambiguator in `core.rs` when the
    /// token after EXTERNAL is the identifier `DATA`. The property tail uses an
    /// unparenthesized comma list (`SET k = v, …`) rather than CREATE's
    /// `WITH (…)`; the scan classifies every recognized `<key> =` pair to the
    /// depth-0 terminator, so both the `SET` list and a parenthesized form lift
    /// the same neutral primitives.
    pub(crate) fn try_parse_mssql_alter_external_data_source(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("alter_external_data_source")?;
        let start_span = self.current_span();

        // 1. ALTER EXTERNAL DATA SOURCE keywords. The dispatch guard guarantees
        //    ALTER / EXTERNAL / DATA; SOURCE is validated here.
        let alter_tok = self
            .advance()
            .ok_or_eof(start_span, vec!["ALTER".to_string()])?;
        let start = alter_tok.span.start;
        self.advance()
            .ok_or_eof(self.current_span(), vec!["EXTERNAL".to_string()])?;
        self.advance()
            .ok_or_eof(self.current_span(), vec!["DATA".to_string()])?;
        let source_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["SOURCE".to_string()])?;
        if !source_tok
            .lexeme(self.source)
            .eq_ignore_ascii_case("SOURCE")
        {
            return Err(ParseError::new(
                source_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: "Expected SOURCE after ALTER EXTERNAL DATA".to_string(),
                },
            ));
        }
        let keyword_span = Span {
            start,
            end: source_tok.span.end,
        };

        // 2. Data-source name (possibly qualified).
        let name_span = self.parse_qualified_name_span()?;
        let mut end = name_span.end;

        // 3. Property tail: scan to the depth-0 terminator, classifying each
        //    recognized `<key> = <value>` pair. Paren punctuation (a rare
        //    `WITH (…)` form) is depth-tracked but otherwise transparent — the
        //    governance primitives are the same at any depth.
        let mut props = EdsProps::default();
        let mut depth: u32 = 0;
        while let Some(peeked) = self.peek_non_trivia() {
            match peeked.kind {
                TokenKind::Eof => break,
                TokenKind::Punctuation(Punctuation::Semi) if depth == 0 => break,
                _ => {}
            }
            let tok = self
                .advance()
                .ok_or_eof(self.current_span(), vec![";".to_string()])?;
            end = tok.span.end;
            match tok.kind {
                TokenKind::Punctuation(Punctuation::LParen) => {
                    depth += 1;
                    continue;
                }
                TokenKind::Punctuation(Punctuation::RParen) => {
                    depth = depth.saturating_sub(1);
                    continue;
                }
                _ => {}
            }
            let is_type_key = matches!(tok.kind, TokenKind::Keyword(Keyword::Type));
            let key_lex = tok.lexeme(self.source);
            let Some(key) = EdsProps::key_of(is_type_key, key_lex) else {
                continue;
            };
            if !matches!(
                self.peek_non_trivia().map(|t| &t.kind),
                Some(TokenKind::Operator(Operator::Eq))
            ) {
                continue;
            }
            self.advance()
                .ok_or_eof(self.current_span(), vec!["=".to_string()])?;
            let val = self
                .advance()
                .ok_or_eof(self.current_span(), vec!["value".to_string()])?;
            end = val.span.end;
            props.ingest(key, val.lexeme(self.source));
        }

        let stmt_span = Span { start, end };
        let ast = AstMssqlAlterExternalDataSource {
            node_id: self.id_gen.next(),
            span: stmt_span,
            keyword_span,
            name_span,
            location_present: props.location_present,
            location_scheme: props.location_scheme,
            source_type: props.source_type,
            credential_present: props.credential_present,
            pushdown: props.pushdown,
        };
        Ok(AstStmt::MssqlAlterExternalDataSource(Box::new(ast)))
    }
}

/// Shared recognition accumulator for an external-data-source property bag.
/// Both the CREATE `WITH (…)` walk and the ALTER `SET …` scan classify their
/// `<key> = <value>` pairs through [`EdsProps::key_of`] + [`EdsProps::ingest`]
/// so the value-classification logic exists in exactly one place.
#[derive(Default)]
struct EdsProps {
    location_present: bool,
    location_scheme: Option<String>,
    source_type: Option<AstExternalDataSourceType>,
    credential_present: bool,
    pushdown: Option<bool>,
}

impl EdsProps {
    /// Canonical key name when a property key is one Lexega lifts, else `None`.
    /// `is_type_key` distinguishes the `TYPE` keyword (lexed as a keyword, not
    /// an identifier) from same-spelled identifiers.
    fn key_of(is_type_key: bool, key_lex: &str) -> Option<&'static str> {
        if is_type_key {
            Some("TYPE")
        } else if key_lex.eq_ignore_ascii_case("LOCATION") {
            Some("LOCATION")
        } else if key_lex.eq_ignore_ascii_case("CREDENTIAL") {
            Some("CREDENTIAL")
        } else if key_lex.eq_ignore_ascii_case("PUSHDOWN") {
            Some("PUSHDOWN")
        } else {
            None
        }
    }

    /// Fold a recognized `<key> = <value>` pair into the accumulator.
    fn ingest(&mut self, key: &'static str, val_lex: &str) {
        match key {
            "LOCATION" => {
                self.location_present = true;
                self.location_scheme = scheme_of_literal(val_lex);
            }
            "TYPE" => {
                self.source_type = classify_source_type(val_lex);
            }
            "CREDENTIAL" => {
                self.credential_present = true;
            }
            "PUSHDOWN" => {
                self.pushdown = if val_lex.eq_ignore_ascii_case("ON") {
                    Some(true)
                } else if val_lex.eq_ignore_ascii_case("OFF") {
                    Some(false)
                } else {
                    None
                };
            }
            _ => {}
        }
    }
}

/// Lowercased URI scheme of a quoted location literal — the chars before
/// `://`. Returns `None` when the literal has no scheme separator.
fn scheme_of_literal(lexeme: &str) -> Option<String> {
    let inner = lexeme
        .strip_prefix('\'')
        .and_then(|s| s.strip_suffix('\''))
        .unwrap_or(lexeme);
    inner
        .split_once("://")
        .map(|(scheme, _)| scheme.to_ascii_lowercase())
        .filter(|s| !s.is_empty())
}

/// Map a TYPE value lexeme to its documented class. Unknown values yield
/// `None` (the construct is still recognized via `location_*`).
fn classify_source_type(lexeme: &str) -> Option<AstExternalDataSourceType> {
    if lexeme.eq_ignore_ascii_case("HADOOP") {
        Some(AstExternalDataSourceType::Hadoop)
    } else if lexeme.eq_ignore_ascii_case("BLOB_STORAGE") {
        Some(AstExternalDataSourceType::BlobStorage)
    } else if lexeme.eq_ignore_ascii_case("RDBMS") {
        Some(AstExternalDataSourceType::Rdbms)
    } else if lexeme.eq_ignore_ascii_case("SHARD_MAP_MANAGER") {
        Some(AstExternalDataSourceType::ShardMapManager)
    } else {
        None
    }
}
