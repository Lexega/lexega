// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Parser for DROP NETWORK POLICY statements.
//!
//! Syntax:
//!   DROP NETWORK POLICY [IF EXISTS] name

use crate::ast::AstDropNetworkPolicy;
use crate::ast::AstStmt;
use crate::error::{ExpectInvariant, ParseError, ParseErrorKind, ParseResult, ParseResultExt};
use crate::lexer::{Keyword, Span, TokenKind};
use crate::parser::core::Parser;
use crate::syntax::SyntaxDropNetworkPolicy;

impl<'a> Parser<'a> {
    pub(crate) fn try_parse_drop_network_policy(&mut self) -> ParseResult<AstStmt> {
        let _depth = self.track_depth("drop_network_policy")?;

        // DROP
        let drop_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["DROP".to_string()])?;
        let drop_span = drop_tok.span;
        let drop_token_id = self.last_token_id();

        // NETWORK (Identifier, NOT Keyword!)
        let network_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["NETWORK".to_string()])?;

        if !matches!(network_tok.kind, TokenKind::Identifier { .. })
            || !network_tok
                .lexeme(self.source)
                .eq_ignore_ascii_case("NETWORK")
        {
            return Err(ParseError::new(
                network_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: "Expected NETWORK keyword".to_string(),
                },
            ));
        }
        let network_span = network_tok.span;

        // POLICY
        let policy_tok = self
            .advance()
            .ok_or_eof(self.current_span(), vec!["POLICY".to_string()])?;
        if !matches!(policy_tok.kind, TokenKind::Keyword(Keyword::Policy)) {
            return Err(ParseError::new(
                policy_tok.span,
                ParseErrorKind::InvalidStatement {
                    message: "Expected POLICY keyword".to_string(),
                },
            ));
        }
        let policy_span = policy_tok.span;
        let policy_token_id = self.last_token_id();

        // Optional IF EXISTS
        let (if_exists_span, if_token_id, exists_token_id) =
            if let Some(tok) = self.peek_non_trivia() {
                if matches!(tok.kind, TokenKind::Keyword(Keyword::If)) {
                    let if_tok = self.advance().expect_invariant("IF keyword after peek");
                    let if_span = if_tok.span;
                    let if_token_id = self.last_token_id();

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
                    let exists_span = exists_tok.span;
                    let exists_token_id = self.last_token_id();

                    let if_exists_span = Span {
                        start: if_span.start,
                        end: exists_span.end,
                    };
                    (
                        Some(if_exists_span),
                        Some(if_token_id),
                        Some(exists_token_id),
                    )
                } else {
                    (None, None, None)
                }
            } else {
                (None, None, None)
            };

        // Policy name
        let policy_name_span = self.parse_qualified_name_span()?;

        // Statement span
        let stmt_span = Span {
            start: drop_span.start,
            end: policy_name_span.end,
        };

        // Build syntax node
        let syntax_node = SyntaxDropNetworkPolicy {
            drop_keyword: drop_token_id,
            network_span,
            policy_keyword: policy_token_id,
            if_keyword: if_token_id,
            exists_keyword: exists_token_id,
            policy_name_span,
            span: stmt_span,
        };
        let syntax_id = self.syntax_arena.alloc_drop_network_policy(syntax_node);

        // Build AST node
        let ast = AstDropNetworkPolicy {
            node_id: self.id_gen.next(),
            span: stmt_span,
            syntax_id: Some(syntax_id),
            drop_span,
            network_span,
            policy_span,
            if_exists_span,
            policy_name_span,
        };
        Ok(AstStmt::DropNetworkPolicy(Box::new(ast)))
    }
}
