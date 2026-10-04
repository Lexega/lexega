// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Jinja Statement Parser
//!
//! Parses Jinja statements that perform actions (assignment, imports, etc.)
//! rather than evaluate to values.
//!
//! ## Supported Statements
//!
//! - `{% set variable = value %}` - Variable assignment
//! - `{% set ns.attr = value %}` - Attribute assignment  
//! - `{% set a, b = values %}` - Tuple unpacking
//! - `{% do expression %}` - Execute for side effects
//!
//! ## Grammar
//!
//! ```text
//! stmt := set_stmt | do_stmt
//! set_stmt := 'set' (identifier | attribute | tuple) '=' expr
//! do_stmt := 'do' expr
//! tuple := identifier (',' identifier)+
//! attribute := expr '.' identifier
//! ```

use crate::ast::jinja::JinjaStmt;
#[cfg(test)]
use crate::error::ExpectInvariant;
use crate::lexer::{Punctuation, Span, TokenKind};
use crate::parser::Parser;

impl<'a> Parser<'a> {
    /// Parse a Jinja {% set %} statement.
    ///
    /// Assumes the opening `{%` and `set` keyword have already been consumed.
    /// Parses up to (but not including) the closing `%}`.
    ///
    /// Supports:
    /// - Simple assignment: `variable = value`
    /// - Attribute assignment: `ns.attr = value`
    /// - Tuple unpacking: `a, b, c = value`
    pub(crate) fn parse_jinja_set_stmt(&mut self) -> Option<JinjaStmt> {
        let start_pos = self.current_span().start;

        // Note: Caller should have already consumed {% and 'set' keyword
        // and should provide those TokenIds if CST integration is needed

        // Parse the left-hand side (target)
        // Could be:
        // 1. Simple identifier: `x`
        // 2. Tuple: `x, y, z`
        // 3. Attribute: `ns.attr`

        // Try to parse first identifier
        let first_tok = self.peek()?;
        if !matches!(first_tok.kind, TokenKind::Identifier { .. }) {
            return None;
        }

        let first_name = first_tok.lexeme(self.source).to_string();
        self.advance()?;

        // Check what comes next
        match self.peek()?.kind {
            // Tuple unpacking: x, y, z = ...
            TokenKind::Punctuation(Punctuation::Comma) => {
                let mut targets = vec![first_name];

                // Consume remaining identifiers
                while matches!(
                    self.peek()?.kind,
                    TokenKind::Punctuation(Punctuation::Comma)
                ) {
                    self.advance()?; // consume comma
                    let ident_tok = self.peek()?;
                    if let TokenKind::Identifier { .. } = ident_tok.kind {
                        targets.push(ident_tok.lexeme(self.source).to_string());
                        self.advance()?;
                    } else {
                        return None; // Expected identifier after comma
                    }
                }

                // Expect = sign
                if !matches!(
                    self.peek()?.kind,
                    TokenKind::Operator(crate::lexer::Operator::Eq)
                ) {
                    return None;
                }
                self.advance()?; // consume =

                // Parse value expression
                let value = match self.parse_jinja_expr() {
                    Ok(Some(e)) => e,
                    _ => return None,
                };
                let end_pos = self.current_span().end;

                Some(JinjaStmt::set_unpack(
                    targets,
                    value,
                    Span {
                        start: start_pos,
                        end: end_pos,
                    },
                ))
            }

            // Attribute assignment: x.attr = ...
            TokenKind::Punctuation(Punctuation::Dot) => {
                self.advance()?; // consume dot

                let attr_tok = self.peek()?;
                if !matches!(attr_tok.kind, TokenKind::Identifier { .. }) {
                    return None;
                }
                let attr_name = attr_tok.lexeme(self.source);
                self.advance()?;

                // Expect = sign
                if !matches!(
                    self.peek()?.kind,
                    TokenKind::Operator(crate::lexer::Operator::Eq)
                ) {
                    return None;
                }
                self.advance()?; // consume =

                // Parse value expression
                let value = match self.parse_jinja_expr() {
                    Ok(Some(e)) => e,
                    _ => return None,
                };
                let end_pos = self.current_span().end;

                // Create target expression (simple name)
                let target_span = Span {
                    start: start_pos,
                    end: start_pos + first_name.len() as u32,
                };
                let target = crate::ast::JinjaExpr::name(first_name, target_span);

                Some(JinjaStmt::set_attribute(
                    target,
                    attr_name,
                    value,
                    Span {
                        start: start_pos,
                        end: end_pos,
                    },
                ))
            }

            // Simple assignment: x = ...
            TokenKind::Operator(crate::lexer::Operator::Eq) => {
                self.advance()?; // consume =

                // Parse value expression
                let value = match self.parse_jinja_expr() {
                    Ok(Some(e)) => e,
                    _ => return None,
                };
                let end_pos = self.current_span().end;

                Some(JinjaStmt::set(
                    first_name,
                    value,
                    Span {
                        start: start_pos,
                        end: end_pos,
                    },
                ))
            }

            _ => None, // Unexpected token after identifier
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lexer::tokenize;

    fn parse_set_stmt(source: &str) -> Option<JinjaStmt> {
        let tokens = tokenize(source).tokens;
        let mut parser = Parser::new(source, &tokens);

        // Skip {% and set tokens
        parser.advance(); // {%
        parser.advance(); // set

        parser.parse_jinja_set_stmt()
    }

    #[test]
    fn test_simple_assignment() {
        let stmt = parse_set_stmt("{% set x = 42 %}").expect_invariant("Should parse");

        match stmt.kind {
            crate::ast::jinja::JinjaStmtKind::Set { target, value } => {
                assert_eq!(target, "x");
                match value.kind {
                    crate::ast::JinjaExprKind::Literal { value } => {
                        assert_eq!(value, crate::ast::JinjaLiteralValue::Integer(42));
                    }
                    _ => panic!("Expected literal value"),
                }
            }
            _ => panic!("Expected Set statement"),
        }
    }

    #[test]
    fn test_list_assignment() {
        let stmt = parse_set_stmt("{% set items = [1, 2, 3] %}").expect_invariant("Should parse");

        match stmt.kind {
            crate::ast::jinja::JinjaStmtKind::Set { target, .. } => {
                assert_eq!(target, "items");
            }
            _ => panic!("Expected Set statement"),
        }
    }

    #[test]
    fn test_tuple_unpacking() {
        let stmt = parse_set_stmt("{% set x, y, z = coords %}").expect_invariant("Should parse");

        match stmt.kind {
            crate::ast::jinja::JinjaStmtKind::SetUnpack { targets, .. } => {
                assert_eq!(targets, vec!["x", "y", "z"]);
            }
            _ => panic!("Expected SetUnpack statement"),
        }
    }
}
