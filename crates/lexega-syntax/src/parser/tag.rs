// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Parser for Snowflake TAG statements.
//!
//! Implements:
//! - `CREATE [OR REPLACE] TAG [IF NOT EXISTS] name [ALLOWED_VALUES 'v' [, ...]]`
//!   `[PROPAGATE = mode [ON_CONFLICT = resolution]] [COMMENT = '<string>']`
//! - `ALTER TAG [IF EXISTS] name { RENAME TO | ADD/DROP ALLOWED_VALUES | SET <props> |`
//!   `UNSET <prop> | SET/UNSET MASKING POLICY ... | UNSET DCM PROJECT }`
//! - UNDROP TAG name
//!
//! DROP TAG routes through the generic `AstStmt::Drop` parser.
//!
//! Token reference:
//! - TAG is Keyword::Tag; ALLOWED_VALUES / PROPAGATE / ON_CONFLICT / MASKING /
//!   FORCE / ADD / DCM / PROJECT / UNDROP are Identifiers
//! - ALLOWED_VALUES takes no `=`; PROPAGATE / ON_CONFLICT / COMMENT take `=`
//! - ON_CONFLICT value is a bare identifier OR a string literal
//! - `ADD ALLOWED_VALUES` vs `DROP ALLOWED_VALUES`: ADD is Identifier, DROP is Keyword

use crate::ast::AstStmt;
use crate::ast::{
    AstAlterTag, AstAlterTagAction, AstAlterTagActionKind, AstCreateTag, AstTagAllowedValues,
    AstTagOnConflict, AstTagPolicyRef, AstTagPropagate, AstTagUnsetProperty, AstUndropTag,
};
use crate::error::{ExpectInvariant, ParseError, ParseErrorKind, ParseResult, ParseResultExt};
use crate::lexer::{Keyword, Operator, Punctuation, Span, TokenKind};
use crate::parser::core::Parser;

impl<'a> Parser<'a> {
    /// Parse CREATE TAG statement.
    pub(crate) fn try_parse_create_tag(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("create_tag")?;

        // CREATE
        let create_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["CREATE".to_string()])?;
        let create_span = create_tok.span;

        // Optional OR REPLACE
        let or_replace_span = if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::Or)) {
                let or_tok = self.advance().expect_invariant("OR keyword after peek");
                let replace_tok = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["REPLACE".to_string()])?;
                if !matches!(replace_tok.kind, TokenKind::Keyword(Keyword::Replace)) {
                    return Err(ParseError::new(
                        replace_tok.span,
                        ParseErrorKind::InvalidStatement {
                            message: "Expected REPLACE after OR".to_string(),
                        },
                    ));
                }
                Some(Span {
                    start: or_tok.span.start,
                    end: replace_tok.span.end,
                })
            } else {
                None
            }
        } else {
            None
        };

        // TAG (Keyword)
        let tag_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["TAG".to_string()])?;
        if !matches!(tag_tok.kind, TokenKind::Keyword(Keyword::Tag)) {
            return Err(ParseError::new(
                tag_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: "Expected TAG keyword".to_string(),
                },
            ));
        }
        let tag_span = tag_tok.span;

        // Optional IF NOT EXISTS
        let if_not_exists_span = if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::If)) {
                let if_tok = self.advance().expect_invariant("IF keyword after peek");
                let not_tok = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["NOT".to_string()])?;
                if !matches!(not_tok.kind, TokenKind::Keyword(Keyword::Not)) {
                    return Err(ParseError::new(
                        not_tok.span,
                        ParseErrorKind::InvalidStatement {
                            message: "Expected NOT after IF".to_string(),
                        },
                    ));
                }
                let exists_tok = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["EXISTS".to_string()])?;
                if !matches!(exists_tok.kind, TokenKind::Keyword(Keyword::Exists)) {
                    return Err(ParseError::new(
                        exists_tok.span,
                        ParseErrorKind::InvalidStatement {
                            message: "Expected EXISTS after IF NOT".to_string(),
                        },
                    ));
                }
                Some(Span {
                    start: if_tok.span.start,
                    end: exists_tok.span.end,
                })
            } else {
                None
            }
        } else {
            None
        };

        // Tag name (may be qualified)
        let name_span = self.parse_qualified_name_span()?;
        let mut end = name_span.end;

        // Optional properties in any order (permissive; Snowflake requires
        // ALLOWED_VALUES first but we don't enforce ordering).
        let mut allowed_values: Option<AstTagAllowedValues> = None;
        let mut propagate: Option<AstTagPropagate> = None;
        let mut on_conflict: Option<AstTagOnConflict> = None;
        let mut comment_span: Option<Span> = None;

        while let Some(tok) = self.peek_non_trivia() {
            match &tok.kind {
                TokenKind::Identifier { .. }
                    if tok
                        .lexeme(self.source)
                        .eq_ignore_ascii_case("ALLOWED_VALUES") =>
                {
                    let values = self.parse_tag_allowed_values()?;
                    end = values.values_span.end;
                    allowed_values = Some(values);
                }
                TokenKind::Identifier { .. }
                    if tok.lexeme(self.source).eq_ignore_ascii_case("PROPAGATE") =>
                {
                    let prop = self.parse_tag_propagate()?;
                    end = prop.value_span.end;
                    propagate = Some(prop);
                }
                TokenKind::Identifier { .. }
                    if tok.lexeme(self.source).eq_ignore_ascii_case("ON_CONFLICT") =>
                {
                    let oc = self.parse_tag_on_conflict()?;
                    end = oc.value_span.end;
                    on_conflict = Some(oc);
                }
                TokenKind::Keyword(Keyword::Comment) => {
                    let span = self.parse_tag_comment_clause()?;
                    end = span.end;
                    comment_span = Some(span);
                }
                _ => break,
            }
        }

        let stmt_span = Span {
            start: create_span.start,
            end,
        };

        let ast = AstCreateTag {
            node_id: self.id_gen.next(),
            span: stmt_span,
            create_span,
            or_replace_span,
            tag_span,
            if_not_exists_span,
            name_span,
            allowed_values,
            propagate,
            on_conflict,
            comment_span,
            extras: Vec::new(),
        };
        Ok(AstStmt::CreateTag(Box::new(ast)))
    }

    /// Parse ALTER TAG statement.
    pub(crate) fn try_parse_alter_tag(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("alter_tag")?;

        // ALTER
        let alter_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["ALTER".to_string()])?;
        let alter_span = alter_tok.span;

        // TAG (Keyword)
        let tag_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["TAG".to_string()])?;
        if !matches!(tag_tok.kind, TokenKind::Keyword(Keyword::Tag)) {
            return Err(ParseError::new(
                tag_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: "Expected TAG keyword".to_string(),
                },
            ));
        }
        let tag_span = tag_tok.span;

        // Optional IF EXISTS
        let if_exists_span = if let Some(tok) = self.peek_non_trivia() {
            if matches!(tok.kind, TokenKind::Keyword(Keyword::If)) {
                let if_tok = self.advance().expect_invariant("IF keyword after peek");
                let exists_tok = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["EXISTS".to_string()])?;
                if !matches!(exists_tok.kind, TokenKind::Keyword(Keyword::Exists)) {
                    return Err(ParseError::new(
                        exists_tok.span,
                        ParseErrorKind::InvalidStatement {
                            message: "Expected EXISTS after IF".to_string(),
                        },
                    ));
                }
                Some(Span {
                    start: if_tok.span.start,
                    end: exists_tok.span.end,
                })
            } else {
                None
            }
        } else {
            None
        };

        // Tag name
        let name_span = self.parse_qualified_name_span()?;

        // Action
        let action = match self.parse_alter_tag_action() {
            Ok(a) => a,
            Err(e) => {
                return Err(e);
            }
        };
        let action_span = action.span;

        let stmt_span = Span {
            start: alter_span.start,
            end: action_span.end,
        };

        let ast = AstAlterTag {
            node_id: self.id_gen.next(),
            span: stmt_span,
            alter_span,
            tag_span,
            if_exists_span,
            name_span,
            action_span,
            action,
        };
        Ok(AstStmt::AlterTag(Box::new(ast)))
    }

    /// Parse UNDROP TAG statement.
    pub(crate) fn try_parse_undrop_tag(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("undrop_tag")?;

        // UNDROP (Identifier)
        let undrop_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["UNDROP".to_string()])?;
        let undrop_span = undrop_tok.span;

        // TAG (Keyword)
        let tag_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["TAG".to_string()])?;
        if !matches!(tag_tok.kind, TokenKind::Keyword(Keyword::Tag)) {
            return Err(ParseError::new(
                tag_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: "Expected TAG keyword".to_string(),
                },
            ));
        }
        let tag_span = tag_tok.span;

        // Tag name
        let name_span = self.parse_qualified_name_span()?;

        let stmt_span = Span {
            start: undrop_span.start,
            end: name_span.end,
        };

        let ast = AstUndropTag {
            node_id: self.id_gen.next(),
            span: stmt_span,
            undrop_span,
            tag_span,
            name_span,
        };
        Ok(AstStmt::UndropTag(Box::new(ast)))
    }

    // ───────────────────────── helpers ─────────────────────────

    /// Parse the ALTER TAG action.
    fn parse_alter_tag_action(&mut self) -> ParseResult<AstAlterTagAction> {
        let action_tok = self.peek_non_trivia().ok_or_eof(
            self.current_span(),
            vec!["RENAME, ADD, DROP, SET, or UNSET".to_string()],
        )?;
        let action_start = action_tok.span.start;

        let (kind, action_end) = match &action_tok.kind {
            // RENAME TO <new_name>
            TokenKind::Keyword(Keyword::Rename) => {
                self.advance(); // consume RENAME
                let rename_span = action_tok.span;

                let to_tok = self
                    .advance()
                    .ok_or_eof(self.current_span(), vec!["TO".to_string()])?;
                if !matches!(to_tok.kind, TokenKind::Keyword(Keyword::To)) {
                    return Err(ParseError::new(
                        to_tok.span,
                        ParseErrorKind::InvalidStatement {
                            message: "Expected TO after RENAME".to_string(),
                        },
                    ));
                }

                let new_name_span = self.parse_qualified_name_span()?;
                let end = new_name_span.end;
                (
                    AstAlterTagActionKind::RenameTo {
                        rename_span,
                        to_span: Some(to_tok.span),
                        new_name_span,
                    },
                    end,
                )
            }

            // ADD ALLOWED_VALUES … (ADD is an Identifier)
            TokenKind::Identifier { .. }
                if action_tok.lexeme(self.source).eq_ignore_ascii_case("ADD") =>
            {
                self.advance(); // consume ADD
                let values = self.parse_tag_allowed_values()?;
                let end = values.values_span.end;
                (
                    AstAlterTagActionKind::AddAllowedValues {
                        add_span: action_tok.span,
                        values,
                    },
                    end,
                )
            }

            // DROP ALLOWED_VALUES … (DROP is a Keyword)
            TokenKind::Keyword(Keyword::Drop) => {
                self.advance(); // consume DROP
                let values = self.parse_tag_allowed_values()?;
                let end = values.values_span.end;
                (
                    AstAlterTagActionKind::DropAllowedValues {
                        drop_span: action_tok.span,
                        values,
                    },
                    end,
                )
            }

            // SET — masking-policy form or combined property form
            TokenKind::Keyword(Keyword::Set) => {
                self.advance(); // consume SET
                let set_span = action_tok.span;

                let next_tok = self.peek_non_trivia().ok_or_eof(
                    self.current_span(),
                    vec!["MASKING POLICY or tag property".to_string()],
                )?;
                if matches!(next_tok.kind, TokenKind::Identifier { .. })
                    && next_tok.lexeme(self.source).eq_ignore_ascii_case("MASKING")
                {
                    // SET MASKING POLICY p [, MASKING POLICY p2 …] [FORCE]
                    let policies = self.parse_tag_masking_policy_list()?;
                    let mut end = policies
                        .last()
                        .map(|p| p.name_span.end)
                        .unwrap_or(set_span.end);

                    let force_span = if let Some(tok) = self.peek_non_trivia() {
                        if matches!(tok.kind, TokenKind::Identifier { .. })
                            && tok.lexeme(self.source).eq_ignore_ascii_case("FORCE")
                        {
                            let force_tok = self.advance().expect_invariant("FORCE after peek");
                            end = force_tok.span.end;
                            Some(force_tok.span)
                        } else {
                            None
                        }
                    } else {
                        None
                    };

                    (
                        AstAlterTagActionKind::SetMaskingPolicies {
                            set_span,
                            policies,
                            force_span,
                        },
                        end,
                    )
                } else {
                    // SET [ALLOWED_VALUES …] [PROPAGATE = … [ON_CONFLICT = …]] [COMMENT = …]
                    let mut allowed_values: Option<AstTagAllowedValues> = None;
                    let mut propagate: Option<AstTagPropagate> = None;
                    let mut on_conflict: Option<AstTagOnConflict> = None;
                    let mut comment_span: Option<Span> = None;
                    let mut end = set_span.end;
                    let mut matched_any = false;

                    while let Some(tok) = self.peek_non_trivia() {
                        match &tok.kind {
                            TokenKind::Identifier { .. }
                                if tok
                                    .lexeme(self.source)
                                    .eq_ignore_ascii_case("ALLOWED_VALUES") =>
                            {
                                let values = self.parse_tag_allowed_values()?;
                                end = values.values_span.end;
                                allowed_values = Some(values);
                                matched_any = true;
                            }
                            TokenKind::Identifier { .. }
                                if tok.lexeme(self.source).eq_ignore_ascii_case("PROPAGATE") =>
                            {
                                let prop = self.parse_tag_propagate()?;
                                end = prop.value_span.end;
                                propagate = Some(prop);
                                matched_any = true;
                            }
                            TokenKind::Identifier { .. }
                                if tok.lexeme(self.source).eq_ignore_ascii_case("ON_CONFLICT") =>
                            {
                                let oc = self.parse_tag_on_conflict()?;
                                end = oc.value_span.end;
                                on_conflict = Some(oc);
                                matched_any = true;
                            }
                            TokenKind::Keyword(Keyword::Comment) => {
                                let span = self.parse_tag_comment_clause()?;
                                end = span.end;
                                comment_span = Some(span);
                                matched_any = true;
                            }
                            _ => break,
                        }
                    }

                    if !matched_any {
                        return Err(ParseError::new(
                            self.current_span(),
                            ParseErrorKind::InvalidStatement {
                                message:
                                    "Expected ALLOWED_VALUES, PROPAGATE, ON_CONFLICT, COMMENT, \
                                     or MASKING POLICY after SET"
                                        .to_string(),
                            },
                        ));
                    }

                    (
                        AstAlterTagActionKind::Set {
                            set_span,
                            allowed_values,
                            propagate,
                            on_conflict,
                            comment_span,
                        },
                        end,
                    )
                }
            }

            // UNSET — masking-policy form, DCM PROJECT, or single property
            TokenKind::Keyword(Keyword::Unset) => {
                self.advance(); // consume UNSET
                let unset_span = action_tok.span;

                let next_tok = self.peek_non_trivia().ok_or_eof(
                    self.current_span(),
                    vec!["MASKING POLICY or tag property".to_string()],
                )?;
                if matches!(next_tok.kind, TokenKind::Identifier { .. })
                    && next_tok.lexeme(self.source).eq_ignore_ascii_case("MASKING")
                {
                    // UNSET MASKING POLICY p [, MASKING POLICY p2 …]
                    let policies = self.parse_tag_masking_policy_list()?;
                    let end = policies
                        .last()
                        .map(|p| p.name_span.end)
                        .unwrap_or(unset_span.end);
                    (
                        AstAlterTagActionKind::UnsetMaskingPolicies {
                            unset_span,
                            policies,
                        },
                        end,
                    )
                } else if matches!(next_tok.kind, TokenKind::Identifier { .. })
                    && next_tok.lexeme(self.source).eq_ignore_ascii_case("DCM")
                {
                    // UNSET DCM PROJECT
                    let dcm_tok = self.advance().expect_invariant("DCM after peek");
                    let project_tok = self
                        .advance()
                        .ok_or_eof(self.current_span(), vec!["PROJECT".to_string()])?;
                    if !matches!(project_tok.kind, TokenKind::Identifier { .. })
                        || !project_tok
                            .lexeme(self.source)
                            .eq_ignore_ascii_case("PROJECT")
                    {
                        return Err(ParseError::new(
                            project_tok.span,
                            ParseErrorKind::InvalidStatement {
                                message: "Expected PROJECT after DCM".to_string(),
                            },
                        ));
                    }
                    let dcm_project_span = Span {
                        start: dcm_tok.span.start,
                        end: project_tok.span.end,
                    };
                    (
                        AstAlterTagActionKind::UnsetDcmProject {
                            unset_span,
                            dcm_project_span,
                        },
                        dcm_project_span.end,
                    )
                } else {
                    // UNSET { ALLOWED_VALUES | PROPAGATE | ON_CONFLICT | COMMENT }
                    let prop_tok = self.advance().ok_or_eof(
                        self.current_span(),
                        vec!["ALLOWED_VALUES, PROPAGATE, ON_CONFLICT, or COMMENT".to_string()],
                    )?;
                    let lexeme = prop_tok.lexeme(self.source);
                    let property = if matches!(prop_tok.kind, TokenKind::Keyword(Keyword::Comment))
                    {
                        AstTagUnsetProperty::Comment {
                            span: prop_tok.span,
                        }
                    } else if matches!(prop_tok.kind, TokenKind::Identifier { .. })
                        && lexeme.eq_ignore_ascii_case("ALLOWED_VALUES")
                    {
                        AstTagUnsetProperty::AllowedValues {
                            span: prop_tok.span,
                        }
                    } else if matches!(prop_tok.kind, TokenKind::Identifier { .. })
                        && lexeme.eq_ignore_ascii_case("PROPAGATE")
                    {
                        AstTagUnsetProperty::Propagate {
                            span: prop_tok.span,
                        }
                    } else if matches!(prop_tok.kind, TokenKind::Identifier { .. })
                        && lexeme.eq_ignore_ascii_case("ON_CONFLICT")
                    {
                        AstTagUnsetProperty::OnConflict {
                            span: prop_tok.span,
                        }
                    } else {
                        return Err(ParseError::new(
                            prop_tok.span,
                            ParseErrorKind::InvalidStatement {
                                message: "Expected ALLOWED_VALUES, PROPAGATE, ON_CONFLICT, \
                                          COMMENT, MASKING POLICY, or DCM PROJECT after UNSET"
                                    .to_string(),
                            },
                        ));
                    };
                    let end = prop_tok.span.end;
                    (
                        AstAlterTagActionKind::Unset {
                            unset_span,
                            property,
                        },
                        end,
                    )
                }
            }

            _ => {
                return Err(ParseError::new(
                    action_tok.span,
                    ParseErrorKind::InvalidStatement {
                        message: "Expected RENAME, ADD, DROP, SET, or UNSET".to_string(),
                    },
                ));
            }
        };

        Ok(AstAlterTagAction {
            node_id: self.id_gen.next(),
            span: Span {
                start: action_start,
                end: action_end,
            },
            kind,
        })
    }

    /// Parse `ALLOWED_VALUES '<v1>' [, ...]`. The keyword is consumed
    /// here; no `=` separates it from the literal list.
    fn parse_tag_allowed_values(&mut self) -> ParseResult<AstTagAllowedValues> {
        let keyword_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["ALLOWED_VALUES".to_string()])?;
        let keyword_span = keyword_tok.span;

        let mut value_spans: Vec<Span> = Vec::new();
        let first_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["string literal".to_string()])?;
        if !matches!(first_tok.kind, TokenKind::Literal(_)) {
            return Err(ParseError::new(
                first_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: "Expected string literal after ALLOWED_VALUES".to_string(),
                },
            ));
        }
        value_spans.push(first_tok.span);
        let mut end = first_tok.span.end;

        while let Some(tok) = self.peek_non_trivia() {
            if !matches!(tok.kind, TokenKind::Punctuation(Punctuation::Comma)) {
                break;
            }
            self.advance(); // consume comma
            let value_tok = self
                .advance()
                .ok_or_eof(self.current_span(), vec!["string literal".to_string()])?;
            if !matches!(value_tok.kind, TokenKind::Literal(_)) {
                return Err(ParseError::new(
                    value_tok.span,
                    ParseErrorKind::InvalidStatement {
                        message: "Expected string literal in ALLOWED_VALUES list".to_string(),
                    },
                ));
            }
            value_spans.push(value_tok.span);
            end = value_tok.span.end;
        }

        Ok(AstTagAllowedValues {
            keyword_span,
            values_span: Span {
                start: value_spans
                    .first()
                    .map(|s| s.start)
                    .unwrap_or(keyword_span.end),
                end,
            },
            value_spans,
        })
    }

    /// Parse `PROPAGATE = <mode>`.
    fn parse_tag_propagate(&mut self) -> ParseResult<AstTagPropagate> {
        let keyword_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["PROPAGATE".to_string()])?;
        let keyword_span = keyword_tok.span;
        self.expect_eq_operator("PROPAGATE")?;
        let value_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["propagation mode".to_string()])?;
        Ok(AstTagPropagate {
            keyword_span,
            value_span: value_tok.span,
        })
    }

    /// Parse `ON_CONFLICT = <resolution>` (identifier or string literal).
    fn parse_tag_on_conflict(&mut self) -> ParseResult<AstTagOnConflict> {
        let keyword_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["ON_CONFLICT".to_string()])?;
        let keyword_span = keyword_tok.span;
        self.expect_eq_operator("ON_CONFLICT")?;
        let value_tok = self.advance().ok_or_eof(
            self.current_span(),
            vec!["conflict resolution value".to_string()],
        )?;
        Ok(AstTagOnConflict {
            keyword_span,
            value_span: value_tok.span,
        })
    }

    /// Parse `COMMENT = '<string>'`; returns the span covering the full clause.
    fn parse_tag_comment_clause(&mut self) -> ParseResult<Span> {
        let comment_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["COMMENT".to_string()])?;
        self.expect_eq_operator("COMMENT")?;
        let value_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["string literal".to_string()])?;
        Ok(Span {
            start: comment_tok.span.start,
            end: value_tok.span.end,
        })
    }

    /// Parse `MASKING POLICY <name> [, MASKING POLICY <name> ...]`.
    /// The caller has peeked MASKING but not consumed it.
    fn parse_tag_masking_policy_list(&mut self) -> ParseResult<Vec<AstTagPolicyRef>> {
        let mut policies = Vec::new();
        loop {
            // MASKING (Identifier)
            let masking_tok = self
                .advance()
                .ok_or_eof(self.current_span(), vec!["MASKING".to_string()])?;
            if !matches!(masking_tok.kind, TokenKind::Identifier { .. })
                || !masking_tok
                    .lexeme(self.source)
                    .eq_ignore_ascii_case("MASKING")
            {
                return Err(ParseError::new(
                    masking_tok.span,
                    ParseErrorKind::InvalidStatement {
                        message: "Expected MASKING keyword".to_string(),
                    },
                ));
            }
            // POLICY (Keyword)
            let policy_tok = self
                .advance()
                .ok_or_eof(self.current_span(), vec!["POLICY".to_string()])?;
            if !matches!(policy_tok.kind, TokenKind::Keyword(Keyword::Policy)) {
                return Err(ParseError::new(
                    policy_tok.span,
                    ParseErrorKind::InvalidStatement {
                        message: "Expected POLICY after MASKING".to_string(),
                    },
                ));
            }
            let name_span = self.parse_qualified_name_span()?;
            policies.push(AstTagPolicyRef {
                masking_policy_span: Span {
                    start: masking_tok.span.start,
                    end: policy_tok.span.end,
                },
                name_span,
            });

            // Continue only on `, MASKING POLICY …`
            match self.peek_non_trivia() {
                Some(tok) if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Comma)) => {
                    self.advance(); // consume comma
                }
                _ => break,
            }
        }
        Ok(policies)
    }

    /// Consume `=` or error with the owning property name.
    fn expect_eq_operator(&mut self, after: &str) -> ParseResult<()> {
        let eq_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["=".to_string()])?;
        if !matches!(eq_tok.kind, TokenKind::Operator(Operator::Eq)) {
            return Err(ParseError::new(
                eq_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: format!("Expected '=' after {after}"),
                },
            ));
        }
        Ok(())
    }
}
