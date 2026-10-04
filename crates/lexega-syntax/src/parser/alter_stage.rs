// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

// ALTER STAGE statement parsing
//
// Implements full parsing for ALTER STAGE statements including:
// - RENAME TO
// - SET/UNSET TAG (governance)
// - SET ENCRYPTION (security governance)
// - SET URL, CREDENTIALS, STORAGE_INTEGRATION (access control)
// - SET FILE_FORMAT, COMMENT, USE_PRIVATELINK_ENDPOINT
// - SET DIRECTORY, REFRESH (data discovery/compliance)

use crate::ast::{
    AstAlterStage, AstAlterStageAction, AstAlterStageActionKind, AstStageCredentialOption, AstStmt,
};
use crate::ast::{
    AstUnknownClause, RefreshDirectoryAction, SetCredentialsAction, SetDirectoryAction,
    SetEncryptionAction, SetFileFormatAction, SetStageTagAction, SetStorageIntegrationAction,
    SetUrlAction, UnknownKind, UnsetStageTagAction,
};
use crate::error::{ExpectInvariant, ParseError, ParseErrorKind, ParseResult, ParseResultExt};
use crate::lexer::{Keyword, Operator, Punctuation, Span, TokenKind};
use crate::parser::core::Parser;
use crate::parser::create_stage::{try_parse_credential_option, unquote_sql_string};

/// Return value from `parse_parenthesized_spec` — full span plus paren token IDs.
struct ParenSpec {
    /// Span from lparen.start to rparen.end (includes both delimiters).
    span: Span,
    /// TokenId for the opening parenthesis.
    lparen_token: crate::cst::TokenId,
    /// TokenId for the closing parenthesis.
    rparen_token: crate::cst::TokenId,
}

/// Consume tokens until the matching `)` is reached. Caller must have
/// already consumed the opening `(`. Returns the closing-paren TokenId
/// and its end byte offset. Used as the shape-divergence fallback when
/// `try_parse_credential_option` rejects the body.
fn consume_until_balanced_rparen(p: &mut Parser<'_>) -> ParseResult<(crate::cst::TokenId, u32)> {
    let mut depth = 1;
    loop {
        let tok = p.peek_non_trivia().ok_or_else(|| {
            ParseError::new(
                p.current_span(),
                ParseErrorKind::UnexpectedEof {
                    expected: vec![")".to_string()],
                },
            )
        })?;
        if matches!(tok.kind, TokenKind::Punctuation(Punctuation::LParen)) {
            depth += 1;
            p.advance();
            continue;
        }
        if matches!(tok.kind, TokenKind::Punctuation(Punctuation::RParen)) {
            depth -= 1;
            let consumed = p
                .advance()
                .expect_invariant("RParen consumed after kind match");
            if depth == 0 {
                return Ok((p.last_token_id(), consumed.span.end));
            }
            continue;
        }
        p.advance();
    }
}

impl<'a> Parser<'a> {
    pub(crate) fn try_parse_alter_stage_stmt_with_parser(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("alter_stage")?;

        // ALTER
        let alter_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["ALTER".to_string()])?;
        let alter_span = alter_tok.span;
        let alter_keyword = self.last_token_id();

        // STAGE
        let stage_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["STAGE".to_string()])?;
        if !matches!(stage_tok.kind, TokenKind::Keyword(Keyword::Stage))
            && !stage_tok.lexeme(self.source).eq_ignore_ascii_case("STAGE")
        {
            return Err(ParseError::new(
                stage_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: "Expected STAGE after ALTER".to_string(),
                },
            ));
        }
        let stage_span = stage_tok.span;
        let stage_keyword = self.last_token_id();

        // Optional IF EXISTS
        let (if_exists_span, if_keyword, exists_keyword) = self.parse_if_exists_clause_stage()?;

        // Stage name
        let name_span = self.parse_stage_name()?;

        // Parse action(s) with defensive unknown handling
        let actions_start = self.current_span().start;
        let (action, additional_actions, extras) = self.parse_alter_stage_action_defensive()?;
        let actions_end = action.span.end;

        let action_span = Span {
            start: actions_start,
            end: actions_end,
        };
        let stmt_span = Span {
            start: alter_span.start,
            end: actions_end,
        };

        // Build CST
        let syntax_action = crate::syntax::SyntaxAlterStageAction {
            leading_keyword: Some(alter_keyword),
            span: action_span,
        };
        let syntax_action_id = self.syntax_arena.alloc_alter_stage_action(syntax_action);

        let syntax_stmt = crate::syntax::SyntaxAlterStageStmt {
            alter_keyword,
            stage_keyword,
            if_keyword,
            exists_keyword,
            name_span,
            action: syntax_action_id,
            span: stmt_span,
        };
        let syntax_stmt_id = self.syntax_arena.alloc_alter_stage_stmt(syntax_stmt);

        Ok(AstStmt::AlterStage(Box::new(AstAlterStage {
            node_id: self.id_gen.next(),
            span: stmt_span,
            syntax_id: Some(syntax_stmt_id),
            alter_span,
            stage_span,
            if_exists_span,
            name_span,
            action_span,
            action,
            additional_actions,
            extras, // Unknown actions captured here
        })))
    }

    fn parse_if_exists_clause_stage(
        &mut self,
    ) -> ParseResult<(
        Option<Span>,
        Option<crate::cst::TokenId>,
        Option<crate::cst::TokenId>,
    )> {
        if let Some(tok) = self.peek_non_trivia() {
            if tok.lexeme(self.source).eq_ignore_ascii_case("IF") {
                let if_tok = self
                    .advance()
                    .expect_invariant("IF keyword consumed after lexeme match");
                let if_keyword = Some(self.last_token_id());

                if let Some(exists_tok) = self.peek_non_trivia() {
                    if exists_tok
                        .lexeme(self.source)
                        .eq_ignore_ascii_case("EXISTS")
                    {
                        let e = self
                            .advance()
                            .expect_invariant("EXISTS keyword consumed after lexeme match");
                        let exists_keyword = Some(self.last_token_id());
                        let if_exists_span = Some(Span {
                            start: if_tok.span.start,
                            end: e.span.end,
                        });
                        return Ok((if_exists_span, if_keyword, exists_keyword));
                    }
                }

                return Err(ParseError::new(
                    if_tok.span,
                    ParseErrorKind::InvalidStatement {
                        message: "ALTER STAGE IF requires EXISTS".to_string(),
                    },
                ));
            }
        }
        Ok((None, None, None))
    }

    fn parse_stage_name(&mut self) -> ParseResult<Span> {
        // Parse identifier (possibly qualified: db.schema.stage)
        let first_tok = if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Identifier { .. }) {
                self.advance()
                    .expect_invariant("identifier consumed after kind match")
            } else {
                return Err(ParseError::new(
                    tok.span,
                    ParseErrorKind::UnexpectedToken {
                        expected: vec!["identifier".to_string()],
                        found: tok.lexeme(self.source).to_string(),
                    },
                ));
            }
        } else {
            return Err(ParseError::new(
                self.current_span(),
                ParseErrorKind::UnexpectedEof {
                    expected: vec!["stage name".to_string()],
                },
            ));
        };

        let start_pos = first_tok.span.start;
        let mut end_pos = first_tok.span.end;

        // Handle qualified names (db.schema.stage)
        while let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Dot)) {
                self.advance();
                // Consume next identifier
                if let Some(next_tok) = self.peek_non_trivia() {
                    if matches!(next_tok.kind, TokenKind::Identifier { .. }) {
                        let t = self
                            .advance()
                            .expect_invariant("qualified identifier consumed after kind match");
                        end_pos = t.span.end;
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

        Ok(Span {
            start: start_pos,
            end: end_pos,
        })
    }

    /// Parse ALTER STAGE action with defensive unknown handling.
    /// Returns (primary_action, extras) where extras contains unknown actions.
    ///
    /// This implements the defensive design pattern: when encountering unrecognized
    /// ALTER STAGE actions, we capture them as AstUnknownClause instead of failing.
    /// This allows the parser to handle new Snowflake features without breaking.
    fn parse_alter_stage_action_defensive(
        &mut self,
    ) -> ParseResult<(
        AstAlterStageAction,
        Vec<AstAlterStageAction>,
        Vec<AstUnknownClause>,
    )> {
        let mut extras = Vec::new();
        let (action, additional_actions) = self.parse_alter_stage_action(&mut extras)?;

        // Note: Unknown SET properties are already added to extras by parse_set_property.
        // Only add here for completely unknown action types (not SET with unknown props).
        // Check if this is a top-level unknown action (not already captured in extras)
        if let AstAlterStageActionKind::Unknown { span } = &action.kind {
            // Only add if not already in extras (SET already adds its unknowns)
            let already_captured = extras.iter().any(|e| e.span == *span);
            if !already_captured {
                let introducer = if span.start < span.end {
                    Some(Span {
                        start: span.start,
                        end: span.start + 1,
                    })
                } else {
                    None
                };

                extras.push(AstUnknownClause {
                    introducer,
                    span: *span,
                    kind: UnknownKind::Clause,
                    node_id: self.id_gen.next(),
                });
            }
        }

        Ok((action, additional_actions, extras))
    }

    fn action_kind_span(&self, action_kind: &AstAlterStageActionKind, default_start: u32) -> Span {
        let end = match action_kind {
            AstAlterStageActionKind::RenameTo { new_name_span, .. } => new_name_span.end,
            AstAlterStageActionKind::SetTag(boxed) => boxed.assignments_span.end,
            AstAlterStageActionKind::UnsetTag(boxed) => boxed.tags_span.end,
            AstAlterStageActionKind::SetEncryption(boxed) => boxed
                .encryption_spec_span
                .map(|s| s.end)
                .unwrap_or_else(|| {
                    boxed
                        .kms_key_id_span
                        .as_ref()
                        .or(boxed.master_key_span.as_ref())
                        .or(boxed.encryption_type_span.as_ref())
                        .or(boxed.type_spec_span.as_ref())
                        .map(|s| s.end)
                        .unwrap_or(default_start)
                }),
            AstAlterStageActionKind::SetUrl(boxed) => boxed.url_value_span.end,
            AstAlterStageActionKind::SetCredentials(boxed) => boxed.credentials_spec_span.end,
            AstAlterStageActionKind::SetStorageIntegration(boxed) => {
                boxed.integration_name_span.end
            }
            AstAlterStageActionKind::SetFileFormat(boxed) => boxed.format_spec_span.end,
            AstAlterStageActionKind::SetComment {
                comment_value_span, ..
            } => comment_value_span.end,
            AstAlterStageActionKind::SetUsePrivatelink { value_span, .. } => value_span.end,
            AstAlterStageActionKind::SetDirectory(boxed) => boxed.enable_spec_span.end,
            AstAlterStageActionKind::RefreshDirectory(boxed) => boxed
                .subpath_span
                .as_ref()
                .map(|s| s.end)
                .unwrap_or(boxed.refresh_span.end),
            AstAlterStageActionKind::Set {
                parameters_span, ..
            } => parameters_span.end,
            AstAlterStageActionKind::Unknown { span } => span.end,
        };

        let start = match action_kind {
            AstAlterStageActionKind::RenameTo {
                rename_span,
                new_name_span,
                ..
            } => rename_span.map(|s| s.start).unwrap_or(new_name_span.start),
            AstAlterStageActionKind::SetTag(boxed) => boxed
                .set_span
                .or(boxed.tag_span)
                .map(|s| s.start)
                .unwrap_or(default_start),
            AstAlterStageActionKind::UnsetTag(boxed) => boxed
                .unset_span
                .or(boxed.tag_span)
                .map(|s| s.start)
                .unwrap_or(default_start),
            AstAlterStageActionKind::SetEncryption(boxed) => boxed
                .set_span
                .or(boxed.encryption_span)
                .map(|s| s.start)
                .unwrap_or(default_start),
            AstAlterStageActionKind::SetUrl(boxed) => boxed
                .set_span
                .or(boxed.url_span)
                .map(|s| s.start)
                .unwrap_or(default_start),
            AstAlterStageActionKind::SetCredentials(boxed) => boxed
                .set_span
                .or(boxed.credentials_span)
                .map(|s| s.start)
                .unwrap_or(default_start),
            AstAlterStageActionKind::SetStorageIntegration(boxed) => boxed
                .set_span
                .or(boxed.storage_integration_span)
                .map(|s| s.start)
                .unwrap_or(default_start),
            AstAlterStageActionKind::SetFileFormat(boxed) => boxed
                .set_span
                .or(boxed.file_format_span)
                .map(|s| s.start)
                .unwrap_or(default_start),
            AstAlterStageActionKind::SetComment {
                set_span,
                comment_span,
                ..
            } => set_span
                .or(*comment_span)
                .map(|s| s.start)
                .unwrap_or(default_start),
            AstAlterStageActionKind::SetUsePrivatelink {
                set_span,
                use_privatelink_span,
                ..
            } => set_span
                .or(*use_privatelink_span)
                .map(|s| s.start)
                .unwrap_or(default_start),
            AstAlterStageActionKind::SetDirectory(boxed) => boxed
                .set_span
                .or(boxed.directory_span)
                .map(|s| s.start)
                .unwrap_or(default_start),
            AstAlterStageActionKind::RefreshDirectory(boxed) => boxed.refresh_span.start,
            AstAlterStageActionKind::Set {
                set_span,
                parameters_span,
            } => set_span.map(|s| s.start).unwrap_or(parameters_span.start),
            AstAlterStageActionKind::Unknown { span } => span.start,
        };

        Span { start, end }
    }

    fn parse_alter_stage_action(
        &mut self,
        extras: &mut Vec<AstUnknownClause>,
    ) -> ParseResult<(AstAlterStageAction, Vec<AstAlterStageAction>)> {
        let start = self.current_span().start;

        // Peek at next keyword
        let Some(tok) = self.peek_non_trivia() else {
            return Err(ParseError::new(
                self.current_span(),
                ParseErrorKind::UnexpectedEof {
                    expected: vec!["ALTER STAGE action".to_string()],
                },
            ));
        };

        let (action_kind, additional_kinds) =
            if tok.lexeme(self.source).eq_ignore_ascii_case("RENAME") {
                (self.parse_rename_to_action()?, Vec::new())
            } else if tok.lexeme(self.source).eq_ignore_ascii_case("SET") {
                self.parse_set_action_stage(extras)?
            } else if tok.lexeme(self.source).eq_ignore_ascii_case("UNSET") {
                (self.parse_unset_action_stage()?, Vec::new())
            } else if tok.lexeme(self.source).eq_ignore_ascii_case("REFRESH") {
                (self.parse_refresh_action()?, Vec::new())
            } else {
                // Unknown action - consume rest as span
                let span = self.consume_until_statement_end()?;
                (AstAlterStageActionKind::Unknown { span }, Vec::new())
            };

        let primary_span = self.action_kind_span(&action_kind, start);

        let primary_action = AstAlterStageAction {
            node_id: self.id_gen.next(),
            span: primary_span,
            syntax_id: None,
            kind: action_kind,
        };

        let mut additional_actions = Vec::new();
        for kind in additional_kinds {
            let span = self.action_kind_span(&kind, start);
            additional_actions.push(AstAlterStageAction {
                node_id: self.id_gen.next(),
                span,
                syntax_id: None,
                kind,
            });
        }

        Ok((primary_action, additional_actions))
    }

    fn parse_rename_to_action(&mut self) -> ParseResult<AstAlterStageActionKind> {
        // RENAME
        let rename_tok = self
            .advance()
            .expect_invariant("RENAME keyword consumed after caller lexeme check");
        let rename_span = Some(rename_tok.span);

        // TO
        let to_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["TO".to_string()])?;
        let to_span = Some(to_tok.span);

        // New name
        let new_name_span = self.parse_stage_name()?;

        Ok(AstAlterStageActionKind::RenameTo {
            rename_span,
            to_span,
            new_name_span,
        })
    }

    fn parse_set_action_stage(
        &mut self,
        extras: &mut Vec<AstUnknownClause>,
    ) -> ParseResult<(AstAlterStageActionKind, Vec<AstAlterStageActionKind>)> {
        // SET
        let set_tok = self
            .advance()
            .expect_invariant("SET keyword consumed after caller lexeme check");
        let set_span = Some(set_tok.span);

        // Parse the first property (becomes the primary action)
        let primary_action = self.parse_set_property(set_span, extras)?;
        let mut additional_actions = Vec::new();

        // Loop to parse additional properties until statement end
        while let Some(tok) = self.peek_non_trivia() {
            // Stop at semicolon
            if matches!(
                tok.kind,
                TokenKind::Punctuation(crate::lexer::Punctuation::Semi)
            ) {
                break;
            }
            // Stop at statement keywords (next statement starting)
            if self.is_statement_keyword(tok) {
                break;
            }

            // Must be another property - parse it
            // Additional properties don't have SET prefix, so pass None
            let additional = self.parse_set_property(None, extras)?;

            // Preserve known additional properties for governance analysis
            if !matches!(additional, AstAlterStageActionKind::Unknown { .. }) {
                additional_actions.push(additional);
            }
        }

        Ok((primary_action, additional_actions))
    }

    /// Parse a single SET property (known or unknown)
    fn parse_set_property(
        &mut self,
        set_span: Option<Span>,
        extras: &mut Vec<AstUnknownClause>,
    ) -> ParseResult<AstAlterStageActionKind> {
        // Peek at next token to determine which SET variant
        let Some(tok) = self.peek_non_trivia() else {
            return Err(ParseError::new(
                self.current_span(),
                ParseErrorKind::UnexpectedEof {
                    expected: vec!["SET parameter".to_string()],
                },
            ));
        };

        if tok.lexeme(self.source).eq_ignore_ascii_case("TAG") {
            self.parse_set_tag_action(set_span)
        } else if tok.lexeme(self.source).eq_ignore_ascii_case("ENCRYPTION") {
            self.parse_set_encryption_action(set_span)
        } else if tok.lexeme(self.source).eq_ignore_ascii_case("URL") {
            self.parse_set_url_action(set_span)
        } else if tok.lexeme(self.source).eq_ignore_ascii_case("CREDENTIALS") {
            self.parse_set_credentials_action(set_span)
        } else if tok
            .lexeme(self.source)
            .eq_ignore_ascii_case("STORAGE_INTEGRATION")
        {
            self.parse_set_storage_integration_action(set_span)
        } else if tok.lexeme(self.source).eq_ignore_ascii_case("FILE_FORMAT") {
            self.parse_set_file_format_action(set_span)
        } else if tok.lexeme(self.source).eq_ignore_ascii_case("COMMENT") {
            self.parse_set_comment_action(set_span)
        } else if tok
            .lexeme(self.source)
            .eq_ignore_ascii_case("USE_PRIVATELINK_ENDPOINT")
        {
            self.parse_set_use_privatelink_action(set_span)
        } else if tok.lexeme(self.source).eq_ignore_ascii_case("DIRECTORY") {
            self.parse_set_directory_action(set_span)
        } else {
            // Unknown SET property - capture as unknown clause
            let property_tok = self
                .advance()
                .expect_invariant("property token consumed after peek in else branch");
            let property_start = property_tok.span.start;
            let mut end_pos = property_tok.span.end;

            // Consume until next property or statement end
            // Properties are IDENTIFIER = VALUE, so consume = and value
            if let Some(eq_tok) = self.peek_non_trivia() {
                if matches!(eq_tok.kind, TokenKind::Operator(Operator::Eq)) {
                    self.advance(); // consume =
                                    // Consume value (could be simple value or parenthesized)
                    if let Some(val_tok) = self.peek_non_trivia() {
                        if matches!(val_tok.kind, TokenKind::Punctuation(Punctuation::LParen)) {
                            // Parenthesized value - consume until matching )
                            end_pos = self.consume_balanced_parens()?.end;
                        } else {
                            // Simple value
                            let v = self
                                .advance()
                                .expect_invariant("value token consumed after peek in else branch");
                            end_pos = v.span.end;
                        }
                    }
                }
            }

            let unknown_span = Span {
                start: set_span.map(|s| s.start).unwrap_or(property_start),
                end: end_pos,
            };

            // Add to extras for governance tracking
            extras.push(AstUnknownClause {
                introducer: Some(property_tok.span),
                span: unknown_span,
                kind: UnknownKind::Property,
                node_id: self.id_gen.next(),
            });

            Ok(AstAlterStageActionKind::Unknown { span: unknown_span })
        }
    }

    fn parse_set_tag_action(
        &mut self,
        set_span: Option<Span>,
    ) -> ParseResult<AstAlterStageActionKind> {
        // TAG
        let tag_tok = self
            .advance()
            .expect_invariant("TAG keyword consumed after caller lexeme check");
        let tag_span = Some(tag_tok.span);

        // Parse tag assignments until statement end
        let _assignments_start = self.current_span().start;
        let assignments_span = self.consume_until_statement_end()?;

        Ok(AstAlterStageActionKind::SetTag(Box::new(
            SetStageTagAction {
                set_span,
                tag_span,
                assignments_span,
            },
        )))
    }

    fn parse_set_encryption_action(
        &mut self,
        set_span: Option<Span>,
    ) -> ParseResult<AstAlterStageActionKind> {
        // ENCRYPTION
        let encryption_tok = self
            .advance()
            .expect_invariant("ENCRYPTION keyword consumed after caller lexeme check");
        let encryption_span = Some(encryption_tok.span);

        // Expect = ( ... )
        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Operator(Operator::Eq)) {
                self.advance();
            }
        }

        let mut type_spec_span = None;
        let mut encryption_type_span = None;
        let mut master_key_span = None;
        let mut kms_key_id_span = None;
        let mut encryption_spec_span = None;
        let mut lparen_token = None;
        let mut rparen_token = None;

        // Expect (
        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Punctuation(Punctuation::LParen)) {
                let lparen = self
                    .advance()
                    .expect_invariant("LParen consumed after kind match");
                let paren_start = lparen.span.start;
                lparen_token = Some(self.last_token_id());

                // Parse encryption parameters until )
                while let Some(tok) = self.peek_non_trivia() {
                    if matches!(tok.kind, TokenKind::Punctuation(Punctuation::RParen)) {
                        let rparen = self
                            .advance()
                            .expect_invariant("RParen consumed after kind match");
                        rparen_token = Some(self.last_token_id());
                        encryption_spec_span = Some(Span {
                            start: paren_start,
                            end: rparen.span.end,
                        });
                        break;
                    }

                    if tok.lexeme(self.source).eq_ignore_ascii_case("TYPE") {
                        let type_start = tok.span.start;
                        self.advance();
                        // Expect =
                        if let Some(eq_tok) = self.peek_non_trivia() {
                            if matches!(eq_tok.kind, TokenKind::Operator(Operator::Eq)) {
                                self.advance();
                            }
                        }
                        // Get encryption type value
                        if let Some(val_tok) = self.peek_non_trivia() {
                            self.advance();
                            encryption_type_span = Some(val_tok.span);
                            type_spec_span = Some(Span {
                                start: type_start,
                                end: val_tok.span.end,
                            });
                        }
                    } else if tok.lexeme(self.source).eq_ignore_ascii_case("MASTER_KEY") {
                        let key_start = tok.span.start;
                        self.advance();
                        // Expect =
                        if let Some(eq_tok) = self.peek_non_trivia() {
                            if matches!(eq_tok.kind, TokenKind::Operator(Operator::Eq)) {
                                self.advance();
                            }
                        }
                        // Get key value
                        if let Some(val_tok) = self.peek_non_trivia() {
                            self.advance();
                            master_key_span = Some(Span {
                                start: key_start,
                                end: val_tok.span.end,
                            });
                        }
                    } else if tok.lexeme(self.source).eq_ignore_ascii_case("KMS_KEY_ID") {
                        let key_start = tok.span.start;
                        self.advance();
                        // Expect =
                        if let Some(eq_tok) = self.peek_non_trivia() {
                            if matches!(eq_tok.kind, TokenKind::Operator(Operator::Eq)) {
                                self.advance();
                            }
                        }
                        // Get key value
                        if let Some(val_tok) = self.peek_non_trivia() {
                            self.advance();
                            kms_key_id_span = Some(Span {
                                start: key_start,
                                end: val_tok.span.end,
                            });
                        }
                    } else {
                        self.advance();
                    }
                }
            }
        }

        Ok(AstAlterStageActionKind::SetEncryption(Box::new(
            SetEncryptionAction {
                set_span,
                encryption_span,
                encryption_spec_span,
                type_spec_span,
                encryption_type_span,
                master_key_span,
                kms_key_id_span,
                lparen_token,
                rparen_token,
            },
        )))
    }

    fn parse_set_url_action(
        &mut self,
        set_span: Option<Span>,
    ) -> ParseResult<AstAlterStageActionKind> {
        // URL
        let url_tok = self
            .advance()
            .expect_invariant("URL keyword consumed after caller lexeme check");
        let url_span = Some(url_tok.span);

        // Expect =
        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Operator(Operator::Eq)) {
                self.advance();
            }
        }

        // Get URL value (string literal)
        let (url_value_span, url_text) = if let Some(tok) = self.peek_non_trivia() {
            let consumed = self
                .advance()
                .expect_invariant("URL value token consumed after peek");
            let text = if matches!(
                consumed.kind,
                TokenKind::Literal(crate::lexer::LiteralKind::String)
            ) {
                unquote_sql_string(consumed.lexeme(self.source))
            } else {
                String::new()
            };
            (tok.span, text)
        } else {
            return Err(ParseError::new(
                self.current_span(),
                ParseErrorKind::UnexpectedEof {
                    expected: vec!["URL value".to_string()],
                },
            ));
        };

        Ok(AstAlterStageActionKind::SetUrl(Box::new(SetUrlAction {
            set_span,
            url_span,
            url_value_span,
            url_text,
        })))
    }

    fn parse_set_credentials_action(
        &mut self,
        set_span: Option<Span>,
    ) -> ParseResult<AstAlterStageActionKind> {
        // CREDENTIALS
        let cred_tok = self
            .advance()
            .expect_invariant("CREDENTIALS keyword consumed after caller lexeme check");
        let credentials_span = Some(cred_tok.span);

        // Expect = ( ... )
        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Operator(Operator::Eq)) {
                self.advance();
            }
        }

        // Consume the opening paren and capture its TokenId.
        let lparen_tok = self.peek_non_trivia().ok_or_else(|| {
            ParseError::new(
                self.current_span(),
                ParseErrorKind::UnexpectedEof {
                    expected: vec!["(".to_string()],
                },
            )
        })?;
        if !matches!(lparen_tok.kind, TokenKind::Punctuation(Punctuation::LParen)) {
            return Err(ParseError::new(
                lparen_tok.span,
                ParseErrorKind::UnexpectedToken {
                    expected: vec!["(".to_string()],
                    found: lparen_tok.lexeme(self.source).to_string(),
                },
            ));
        }
        let lparen_consumed = self
            .advance()
            .expect_invariant("LParen consumed after kind match");
        let lparen_token = self.last_token_id();
        let span_start = lparen_consumed.span.start;

        // Decompose `KEY = VALUE` triples until ')'. On shape divergence
        // (nested paren, unexpected tokens) fall through to depth-tracked
        // consumption that records nothing typed for that span — same
        // permissive contract as `parse_credentials_clause` in CREATE STAGE.
        let mut options: Vec<AstStageCredentialOption> = Vec::new();
        let (rparen_token, span_end) = loop {
            let next = self.peek_non_trivia().ok_or_else(|| {
                ParseError::new(
                    self.current_span(),
                    ParseErrorKind::UnexpectedEof {
                        expected: vec![")".to_string()],
                    },
                )
            })?;
            if matches!(next.kind, TokenKind::Punctuation(Punctuation::RParen)) {
                let close = self
                    .advance()
                    .expect_invariant("RParen consumed after kind match");
                break (self.last_token_id(), close.span.end);
            }
            if matches!(next.kind, TokenKind::Punctuation(Punctuation::Comma)) {
                self.advance();
                continue;
            }
            match try_parse_credential_option(self) {
                Some(opt) => options.push(opt),
                None => {
                    // Shape divergence — depth-walk through the rest of
                    // the body and return the closing-paren token info.
                    let (rparen_id, end) = consume_until_balanced_rparen(self)?;
                    break (rparen_id, end);
                }
            }
        };

        let credentials_spec_span = Span {
            start: span_start,
            end: span_end,
        };
        // Individual credential values are masked by `try_parse_credential_option`
        // (shared across CREATE / ALTER STAGE and COPY INTO).

        Ok(AstAlterStageActionKind::SetCredentials(Box::new(
            SetCredentialsAction {
                set_span,
                credentials_span,
                credentials_spec_span,
                lparen_token: Some(lparen_token),
                rparen_token: Some(rparen_token),
                options,
            },
        )))
    }

    fn parse_set_storage_integration_action(
        &mut self,
        set_span: Option<Span>,
    ) -> ParseResult<AstAlterStageActionKind> {
        // STORAGE_INTEGRATION
        let si_tok = self
            .advance()
            .expect_invariant("STORAGE_INTEGRATION keyword consumed after caller lexeme check");
        let storage_integration_span = Some(si_tok.span);

        // Expect =
        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Operator(Operator::Eq)) {
                self.advance();
            }
        }

        // Get integration name (may be qualified: db.schema.name)
        let integration_name_span = self.parse_qualified_name_span()?;

        Ok(AstAlterStageActionKind::SetStorageIntegration(Box::new(
            SetStorageIntegrationAction {
                set_span,
                storage_integration_span,
                integration_name_span,
            },
        )))
    }

    fn parse_set_file_format_action(
        &mut self,
        set_span: Option<Span>,
    ) -> ParseResult<AstAlterStageActionKind> {
        // FILE_FORMAT
        let ff_tok = self
            .advance()
            .expect_invariant("FILE_FORMAT keyword consumed after caller lexeme check");
        let file_format_span = Some(ff_tok.span);

        // Expect = ( ... )
        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Operator(Operator::Eq)) {
                self.advance();
            }
        }

        let ParenSpec {
            span: format_spec_span,
            lparen_token,
            rparen_token,
        } = self.parse_parenthesized_spec()?;

        Ok(AstAlterStageActionKind::SetFileFormat(Box::new(
            SetFileFormatAction {
                set_span,
                file_format_span,
                format_spec_span,
                lparen_token: Some(lparen_token),
                rparen_token: Some(rparen_token),
            },
        )))
    }

    fn parse_set_comment_action(
        &mut self,
        set_span: Option<Span>,
    ) -> ParseResult<AstAlterStageActionKind> {
        // COMMENT
        let comment_tok = self
            .advance()
            .expect_invariant("COMMENT keyword consumed after caller lexeme check");
        let comment_span = Some(comment_tok.span);

        // Expect =
        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Operator(Operator::Eq)) {
                self.advance();
            }
        }

        // Get comment value
        let comment_value_span = if let Some(tok) = self.peek_non_trivia() {
            self.advance();
            tok.span
        } else {
            return Err(ParseError::new(
                self.current_span(),
                ParseErrorKind::UnexpectedEof {
                    expected: vec!["comment value".to_string()],
                },
            ));
        };

        Ok(AstAlterStageActionKind::SetComment {
            set_span,
            comment_span,
            comment_value_span,
        })
    }

    fn parse_set_use_privatelink_action(
        &mut self,
        set_span: Option<Span>,
    ) -> ParseResult<AstAlterStageActionKind> {
        // USE_PRIVATELINK_ENDPOINT
        let pl_tok = self.advance().expect_invariant(
            "USE_PRIVATELINK_ENDPOINT keyword consumed after caller lexeme check",
        );
        let use_privatelink_span = Some(pl_tok.span);

        // Expect =
        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Operator(Operator::Eq)) {
                self.advance();
            }
        }

        // Get value (TRUE/FALSE)
        let value_span = if let Some(tok) = self.peek_non_trivia() {
            self.advance();
            tok.span
        } else {
            return Err(ParseError::new(
                self.current_span(),
                ParseErrorKind::UnexpectedEof {
                    expected: vec!["TRUE or FALSE".to_string()],
                },
            ));
        };

        Ok(AstAlterStageActionKind::SetUsePrivatelink {
            set_span,
            use_privatelink_span,
            value_span,
        })
    }

    fn parse_set_directory_action(
        &mut self,
        set_span: Option<Span>,
    ) -> ParseResult<AstAlterStageActionKind> {
        // DIRECTORY
        let dir_tok = self
            .advance()
            .expect_invariant("DIRECTORY keyword consumed after caller lexeme check");
        let directory_span = Some(dir_tok.span);

        // Expect = ( ENABLE = TRUE | FALSE )
        if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Operator(Operator::Eq)) {
                self.advance();
            }
        }

        let ParenSpec {
            span: enable_spec_span,
            lparen_token,
            rparen_token,
        } = self.parse_parenthesized_spec()?;

        Ok(AstAlterStageActionKind::SetDirectory(Box::new(
            SetDirectoryAction {
                set_span,
                directory_span,
                enable_spec_span,
                lparen_token: Some(lparen_token),
                rparen_token: Some(rparen_token),
            },
        )))
    }

    fn parse_unset_action_stage(&mut self) -> ParseResult<AstAlterStageActionKind> {
        // UNSET
        let unset_tok = self
            .advance()
            .expect_invariant("UNSET keyword consumed after caller lexeme check");
        let unset_span = Some(unset_tok.span);

        // Peek at next token
        let Some(tok) = self.peek_non_trivia() else {
            return Err(ParseError::new(
                self.current_span(),
                ParseErrorKind::UnexpectedEof {
                    expected: vec!["UNSET parameter".to_string()],
                },
            ));
        };

        if tok.lexeme(self.source).eq_ignore_ascii_case("TAG") {
            self.parse_unset_tag_action(unset_span)
        } else {
            // Generic UNSET
            let parameters_span = self.consume_until_statement_end()?;
            Ok(AstAlterStageActionKind::Set {
                set_span: unset_span,
                parameters_span,
            })
        }
    }

    fn parse_unset_tag_action(
        &mut self,
        unset_span: Option<Span>,
    ) -> ParseResult<AstAlterStageActionKind> {
        // TAG
        let tag_tok = self
            .advance()
            .expect_invariant("TAG keyword consumed after caller lexeme check");
        let tag_span = Some(tag_tok.span);

        // Parse tag names until statement end
        let tags_span = self.consume_until_statement_end()?;

        Ok(AstAlterStageActionKind::UnsetTag(Box::new(
            UnsetStageTagAction {
                unset_span,
                tag_span,
                tags_span,
            },
        )))
    }

    fn parse_refresh_action(&mut self) -> ParseResult<AstAlterStageActionKind> {
        // REFRESH
        let refresh_tok = self
            .advance()
            .expect_invariant("REFRESH keyword consumed after caller lexeme check");
        let refresh_span = refresh_tok.span;

        // Optional SUBPATH = '...'
        let subpath_span = if let Some(tok) = self.peek_non_trivia() {
            if tok.lexeme(self.source).eq_ignore_ascii_case("SUBPATH") {
                let subpath_start = tok.span.start;
                self.advance();
                // Expect =
                if let Some(eq_tok) = self.peek_non_trivia() {
                    if matches!(eq_tok.kind, TokenKind::Operator(Operator::Eq)) {
                        self.advance();
                    }
                }
                // Get subpath value
                if let Some(val_tok) = self.peek_non_trivia() {
                    self.advance();
                    Some(Span {
                        start: subpath_start,
                        end: val_tok.span.end,
                    })
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        };

        Ok(AstAlterStageActionKind::RefreshDirectory(Box::new(
            RefreshDirectoryAction {
                refresh_span,
                subpath_span,
            },
        )))
    }

    fn parse_parenthesized_spec(&mut self) -> ParseResult<ParenSpec> {
        // Expect (
        let (start, lparen_token) = if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Punctuation(Punctuation::LParen)) {
                let span = tok.span;
                self.advance();
                let token_id = self.last_token_id();
                (span.start, token_id)
            } else {
                return Err(ParseError::new(
                    tok.span,
                    ParseErrorKind::UnexpectedToken {
                        expected: vec!["(".to_string()],
                        found: tok.lexeme(self.source).to_string(),
                    },
                ));
            }
        } else {
            return Err(ParseError::new(
                self.current_span(),
                ParseErrorKind::UnexpectedEof {
                    expected: vec!["(".to_string()],
                },
            ));
        };

        // Consume until )
        let mut depth = 1;
        let mut end = start;
        let mut rparen_token = lparen_token; // placeholder, will be overwritten
        while let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Punctuation(Punctuation::LParen)) {
                depth += 1;
            } else if matches!(tok.kind, TokenKind::Punctuation(Punctuation::RParen)) {
                depth -= 1;
                if depth == 0 {
                    let t = self
                        .advance()
                        .expect_invariant("RParen consumed after kind match in loop");
                    rparen_token = self.last_token_id();
                    end = t.span.end;
                    break;
                }
            }
            let t = self
                .advance()
                .expect_invariant("token consumed in balanced paren loop");
            end = t.span.end;
        }

        Ok(ParenSpec {
            span: Span { start, end },
            lparen_token,
            rparen_token,
        })
    }

    fn consume_until_statement_end(&mut self) -> ParseResult<Span> {
        let start = self.current_span().start;
        let mut end = start;

        while let Some(tok) = self.peek_non_trivia() {
            // Stop at semicolon or statement-ending keywords
            if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Semi)) {
                break;
            }
            if self.is_statement_keyword(tok) {
                break;
            }

            let t = self
                .advance()
                .expect_invariant("token consumed in statement-end loop");
            end = t.span.end;
        }

        Ok(Span { start, end })
    }

    /// Consume tokens until matching closing paren, handling nested parens
    pub(crate) fn consume_balanced_parens(&mut self) -> ParseResult<Span> {
        let lparen = self
            .advance()
            .expect_invariant("LParen consumed after caller verified"); // consume opening (
        let start = lparen.span.start;
        let mut end = lparen.span.end;
        let mut depth = 1;

        while depth > 0 {
            let Some(tok) = self.peek_non_trivia() else {
                return Err(ParseError::new(
                    Span { start, end },
                    ParseErrorKind::UnexpectedEof {
                        expected: vec![")".to_string()],
                    },
                ));
            };

            if matches!(tok.kind, TokenKind::Punctuation(Punctuation::LParen)) {
                depth += 1;
            } else if matches!(tok.kind, TokenKind::Punctuation(Punctuation::RParen)) {
                depth -= 1;
            }

            let t = self
                .advance()
                .expect_invariant("token consumed in balanced paren loop");
            end = t.span.end;
        }

        Ok(Span { start, end })
    }
}
