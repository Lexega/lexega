// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Parsers for Databricks Unity Catalog DDL statements.
//!
//! - `CREATE [FOREIGN] CATALOG [IF NOT EXISTS] name [clauses...]`
//! - `ALTER CATALOG [name] { action }`
//! - `DROP CATALOG [IF EXISTS] name [RESTRICT | CASCADE]`
//!
//! Token reference (--debug-tokens --dialect databricks):
//!   CATALOG    → Identifier (NOT Keyword)
//!   MANAGED    → Identifier
//!   LOCATION   → Identifier
//!   SHARE      → Identifier
//!   CONNECTION → Identifier
//!   COLLATION  → Identifier
//!   OPTIONS    → Identifier
//!   TAGS       → Identifier
//!   PREDICTIVE → Identifier
//!   OPTIMIZATION → Identifier
//!   DISABLE    → Identifier
//!   INHERIT    → Identifier
//!   CASCADE    → Identifier
//!   RESTRICT   → Identifier
//!   FOREIGN    → Keyword(Foreign)
//!   USING      → Keyword(Using)
//!   COMMENT    → Keyword(Comment)
//!   DEFAULT    → Keyword(Default)
//!   SET        → Keyword(Set)
//!   UNSET      → Keyword(Unset)
//!   OWNER      → Keyword(Owner)
//!   TO         → Keyword(To)
//!   ENABLE     → Keyword(Enable)

use crate::ast::types::{
    AlterCatalogActionKind, AstAlterCatalog, AstCreateCatalog, AstDropCatalog, AstStmt,
};
use crate::error::{ParseError, ParseErrorKind, ParseResult, ParseResultExt};
use crate::lexer::{Keyword, Punctuation, Span, TokenKind};
use crate::parser::core::Parser;

impl<'a> Parser<'a> {
    // -----------------------------------------------------------------------
    // CREATE [FOREIGN] CATALOG [IF NOT EXISTS] name [clauses...]
    // -----------------------------------------------------------------------

    pub(crate) fn try_parse_create_catalog(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("create_catalog")?;
        let start = self.current_span().start;

        // Caller resets idx to before CREATE. We consume everything.
        // CREATE
        let _create_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["CREATE".to_string()])?;

        // Skip optional OR REPLACE
        if let Some(tok) = self.peek_non_trivia() {
            if tok.lexeme(self.source).eq_ignore_ascii_case("OR") {
                let or_idx = self.idx;
                self.advance(); // OR
                if let Some(rep_tok) = self.peek_non_trivia() {
                    if rep_tok.lexeme(self.source).eq_ignore_ascii_case("REPLACE") {
                        self.advance(); // REPLACE
                    } else {
                        self.idx = or_idx;
                    }
                } else {
                    self.idx = or_idx;
                }
            }
        }

        // Check for optional FOREIGN
        let mut is_foreign = false;
        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::Foreign)) {
                self.advance(); // consume FOREIGN
                is_foreign = true;
            }
        }

        // CATALOG (Identifier, NOT Keyword)
        let catalog_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["CATALOG".to_string()])?;
        if !catalog_tok
            .lexeme(self.source)
            .eq_ignore_ascii_case("CATALOG")
        {
            return Err(ParseError::new(
                catalog_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: format!(
                        "Expected CATALOG, found '{}'",
                        catalog_tok.lexeme(self.source)
                    ),
                },
            ));
        }
        // Optional IF NOT EXISTS
        let if_not_exists = self.parse_optional_if_not_exists()?.is_some();

        // Catalog name (required, possibly backtick-quoted)
        let catalog_name_span = self.parse_qualified_name_span()?;
        let mut end = catalog_name_span.end;

        // Parse optional clauses
        let mut comment_span = None;
        let mut managed_location_span = None;
        let mut using_share_span = None;
        let mut using_connection_span = None;
        let mut default_collation_span = None;
        let mut options_span = None;

        while let Some(tok) = self.peek_non_trivia() {
            // Check for statement terminators
            if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Semi))
                || matches!(tok.kind, TokenKind::Eof)
            {
                break;
            }

            let lexeme_upper = tok.lexeme(self.source).to_uppercase();

            match lexeme_upper.as_str() {
                // COMMENT 'string'
                "COMMENT" => {
                    let clause_start = tok.span.start;
                    self.advance(); // COMMENT
                    let string_tok = self
                        .advance()
                        .ok_or_eof(self.current_span(), vec!["string literal".to_string()])?;
                    end = string_tok.span.end;
                    comment_span = Some(Span {
                        start: clause_start,
                        end,
                    });
                }
                // MANAGED LOCATION 'path'
                "MANAGED" => {
                    let clause_start = tok.span.start;
                    self.advance(); // MANAGED
                                    // LOCATION (Identifier)
                    let loc_tok = self
                        .advance()
                        .ok_or_eof(self.current_span(), vec!["LOCATION".to_string()])?;
                    if !loc_tok.lexeme(self.source).eq_ignore_ascii_case("LOCATION") {
                        return Err(ParseError::new(
                            loc_tok.span,
                            ParseErrorKind::InvalidStatement {
                                message: format!(
                                    "Expected LOCATION, found '{}'",
                                    loc_tok.lexeme(self.source)
                                ),
                            },
                        ));
                    }
                    // String literal path
                    let path_tok = self
                        .advance()
                        .ok_or_eof(self.current_span(), vec!["path string".to_string()])?;
                    end = path_tok.span.end;
                    managed_location_span = Some(Span {
                        start: clause_start,
                        end,
                    });
                }
                // USING SHARE provider.share  OR  USING CONNECTION name
                "USING" => {
                    let clause_start = tok.span.start;
                    self.advance(); // USING
                    let next_tok = self.peek_non_trivia().ok_or_else(|| {
                        ParseError::new(
                            self.current_span(),
                            ParseErrorKind::InvalidStatement {
                                message: "Expected SHARE or CONNECTION after USING".to_string(),
                            },
                        )
                    })?;
                    let next_upper = next_tok.lexeme(self.source).to_uppercase();

                    if next_upper == "SHARE" {
                        self.advance(); // SHARE
                                        // provider.share (qualified name)
                        let name_span = self.parse_qualified_name_span()?;
                        end = name_span.end;
                        using_share_span = Some(Span {
                            start: clause_start,
                            end,
                        });
                    } else if next_upper == "CONNECTION" {
                        self.advance(); // CONNECTION
                        let conn_name_span = self.parse_qualified_name_span()?;
                        end = conn_name_span.end;
                        using_connection_span = Some(Span {
                            start: clause_start,
                            end,
                        });
                    } else {
                        // Unknown USING clause — stop
                        break;
                    }
                }
                // DEFAULT COLLATION name
                "DEFAULT" => {
                    let clause_start = tok.span.start;
                    self.advance(); // DEFAULT
                    let coll_tok = self
                        .advance()
                        .ok_or_eof(self.current_span(), vec!["COLLATION".to_string()])?;
                    if !coll_tok
                        .lexeme(self.source)
                        .eq_ignore_ascii_case("COLLATION")
                    {
                        return Err(ParseError::new(
                            coll_tok.span,
                            ParseErrorKind::InvalidStatement {
                                message: format!(
                                    "Expected COLLATION, found '{}'",
                                    coll_tok.lexeme(self.source)
                                ),
                            },
                        ));
                    }
                    // Collation name
                    let name_tok = self
                        .advance()
                        .ok_or_eof(self.current_span(), vec!["collation name".to_string()])?;
                    end = name_tok.span.end;
                    default_collation_span = Some(Span {
                        start: clause_start,
                        end,
                    });
                }
                // OPTIONS (key = value, ...)
                "OPTIONS" => {
                    let clause_start = tok.span.start;
                    self.advance(); // OPTIONS
                    let paren_span = self.consume_balanced_parens()?;
                    end = paren_span.end;
                    options_span = Some(Span {
                        start: clause_start,
                        end,
                    });
                }
                _ => {
                    // Unknown clause — stop
                    break;
                }
            }
        }

        let stmt = AstCreateCatalog {
            node_id: self.id_gen.next(),
            span: Span { start, end },
            is_foreign,
            if_not_exists,
            catalog_name_span,
            comment_span,
            managed_location_span,
            using_share_span,
            using_connection_span,
            default_collation_span,
            options_span,
        };
        Ok(AstStmt::CreateCatalog(Box::new(stmt)))
    }

    // -----------------------------------------------------------------------
    // ALTER CATALOG [catalog_name] { action }
    // -----------------------------------------------------------------------

    /// Called after idx is reset to before ALTER by the caller.
    pub(crate) fn try_parse_alter_catalog(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("alter_catalog")?;
        let start = self.current_span().start;

        // ALTER — consume it (caller resets idx to before ALTER)
        let _alter_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["ALTER".to_string()])?;

        // CATALOG (Identifier)
        let catalog_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["CATALOG".to_string()])?;
        if !catalog_tok
            .lexeme(self.source)
            .eq_ignore_ascii_case("CATALOG")
        {
            return Err(ParseError::new(
                catalog_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: format!(
                        "Expected CATALOG, found '{}'",
                        catalog_tok.lexeme(self.source)
                    ),
                },
            ));
        }
        let end;

        // Peek to decide if next token is catalog_name or an action keyword.
        // Action keywords: SET, UNSET, OWNER, ENABLE, DEFAULT, OPTIONS
        // Also: DISABLE, INHERIT (Identifiers)
        // If next token is one of these action introducers, catalog name is omitted.
        let catalog_name_span = self.parse_optional_catalog_name()?;
        let _ = &catalog_name_span;

        // Parse action
        let action_start = self.current_span().start;
        let tok = self.peek_non_trivia().ok_or_else(|| {
            ParseError::new(
                self.current_span(),
                ParseErrorKind::InvalidStatement {
                    message: "Expected ALTER CATALOG action".to_string(),
                },
            )
        })?;

        let tok_upper = tok.lexeme(self.source).to_uppercase();
        let action_kind: AlterCatalogActionKind;

        match tok_upper.as_str() {
            // [SET] OWNER TO principal
            "OWNER" => {
                self.advance(); // OWNER
                                // TO
                let to_tok = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["TO".to_string()])?;
                let _ = to_tok;
                // principal (qualified name — may be backtick-quoted)
                let principal_span = self.parse_qualified_name_span()?;
                end = principal_span.end;
                action_kind = AlterCatalogActionKind::OwnerTo;
            }
            "SET" => {
                self.advance(); // SET
                                // Peek next to distinguish SET TAGS vs SET OWNER TO
                let next = self.peek_non_trivia().ok_or_else(|| {
                    ParseError::new(
                        self.current_span(),
                        ParseErrorKind::InvalidStatement {
                            message: "Expected TAGS or OWNER after SET".to_string(),
                        },
                    )
                })?;
                let next_upper = next.lexeme(self.source).to_uppercase();

                if next_upper == "TAGS" {
                    self.advance(); // TAGS
                    let paren_span = self.consume_balanced_parens()?;
                    end = paren_span.end;
                    action_kind = AlterCatalogActionKind::SetTags;
                } else if next_upper == "OWNER" {
                    self.advance(); // OWNER
                    let to_tok = self
                        .advance()
                        .ok_or_eof(self.current_span(), vec!["TO".to_string()])?;
                    let _ = to_tok;
                    let principal_span = self.parse_qualified_name_span()?;
                    end = principal_span.end;
                    action_kind = AlterCatalogActionKind::OwnerTo;
                } else {
                    // Unknown SET action - consume to end of statement
                    end = self.consume_until_semi_or_eof()?;
                    action_kind = AlterCatalogActionKind::Options; // fallback
                }
            }
            "UNSET" => {
                self.advance(); // UNSET
                                // TAGS (Identifier)
                let tags_tok = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["TAGS".to_string()])?;
                let _ = tags_tok;
                let paren_span = self.consume_balanced_parens()?;
                end = paren_span.end;
                action_kind = AlterCatalogActionKind::UnsetTags;
            }
            "ENABLE" => {
                self.advance(); // ENABLE
                                // PREDICTIVE OPTIMIZATION
                let pred_tok = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["PREDICTIVE".to_string()])?;
                let _ = pred_tok;
                let opt_tok = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["OPTIMIZATION".to_string()])?;
                end = opt_tok.span.end;
                action_kind = AlterCatalogActionKind::EnablePredictiveOptimization;
            }
            "DISABLE" => {
                self.advance(); // DISABLE
                let pred_tok = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["PREDICTIVE".to_string()])?;
                let _ = pred_tok;
                let opt_tok = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["OPTIMIZATION".to_string()])?;
                end = opt_tok.span.end;
                action_kind = AlterCatalogActionKind::DisablePredictiveOptimization;
            }
            "INHERIT" => {
                self.advance(); // INHERIT
                let pred_tok = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["PREDICTIVE".to_string()])?;
                let _ = pred_tok;
                let opt_tok = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["OPTIMIZATION".to_string()])?;
                end = opt_tok.span.end;
                action_kind = AlterCatalogActionKind::InheritPredictiveOptimization;
            }
            "DEFAULT" => {
                self.advance(); // DEFAULT
                let coll_tok = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["COLLATION".to_string()])?;
                let _ = coll_tok;
                let name_tok = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["collation name".to_string()])?;
                end = name_tok.span.end;
                action_kind = AlterCatalogActionKind::DefaultCollation;
            }
            "OPTIONS" => {
                self.advance(); // OPTIONS
                let paren_span = self.consume_balanced_parens()?;
                end = paren_span.end;
                action_kind = AlterCatalogActionKind::Options;
            }
            _ => {
                return Err(ParseError::new(
                    tok.span,
                    ParseErrorKind::InvalidStatement {
                        message: format!(
                            "Unknown ALTER CATALOG action: '{}'",
                            tok.lexeme(self.source)
                        ),
                    },
                ));
            }
        }

        let action_span = Span {
            start: action_start,
            end,
        };

        let stmt = AstAlterCatalog {
            node_id: self.id_gen.next(),
            span: Span { start, end },
            catalog_name_span,
            action_kind,
            action_span,
        };
        Ok(AstStmt::AlterCatalog(Box::new(stmt)))
    }

    /// Peek-based check: if next token looks like an action keyword rather than
    /// a catalog name, return None.
    fn parse_optional_catalog_name(&mut self) -> ParseResult<Option<Span>> {
        let tok = match self.peek_non_trivia() {
            Some(t) => t,
            None => return Ok(None),
        };
        let upper = tok.lexeme(self.source).to_uppercase();

        // These tokens start ALTER CATALOG actions — so if we see one next,
        // catalog_name was omitted (defaults to hive_metastore).
        let is_action_keyword = matches!(
            upper.as_str(),
            "SET" | "UNSET" | "OWNER" | "ENABLE" | "DISABLE" | "INHERIT" | "DEFAULT" | "OPTIONS"
        );

        if is_action_keyword {
            Ok(None)
        } else {
            let name_span = self.parse_qualified_name_span()?;
            Ok(Some(name_span))
        }
    }

    // -----------------------------------------------------------------------
    // DROP CATALOG [IF EXISTS] catalog_name [RESTRICT | CASCADE]
    // -----------------------------------------------------------------------

    /// Called after idx is reset to before DROP by the caller.
    pub(crate) fn try_parse_drop_catalog(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("drop_catalog")?;
        let start = self.current_span().start;

        // DROP — consume it (caller resets idx to before DROP)
        let _drop_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["DROP".to_string()])?;

        // CATALOG (Identifier)
        let catalog_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["CATALOG".to_string()])?;
        if !catalog_tok
            .lexeme(self.source)
            .eq_ignore_ascii_case("CATALOG")
        {
            return Err(ParseError::new(
                catalog_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: format!(
                        "Expected CATALOG, found '{}'",
                        catalog_tok.lexeme(self.source)
                    ),
                },
            ));
        }
        // Optional IF EXISTS
        let if_exists = self.parse_optional_if_exists()?.is_some();

        // Catalog name (required)
        let catalog_name_span = self.parse_qualified_name_span()?;
        let mut end = catalog_name_span.end;

        // Optional RESTRICT | CASCADE
        let mut cascade = false;
        let mut restrict = false;
        if let Some(tok) = self.peek_non_trivia() {
            let upper = tok.lexeme(self.source).to_uppercase();
            if upper == "CASCADE" {
                self.advance();
                end = tok.span.end;
                cascade = true;
            } else if upper == "RESTRICT" {
                self.advance();
                end = tok.span.end;
                restrict = true;
            }
        }

        let stmt = AstDropCatalog {
            node_id: self.id_gen.next(),
            span: Span { start, end },
            if_exists,
            catalog_name_span,
            cascade,
            restrict,
        };
        Ok(AstStmt::DropCatalog(Box::new(stmt)))
    }
}
