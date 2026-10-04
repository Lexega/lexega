// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

use crate::cst::TokenId;
use crate::lexer::Span;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxJinjaDelimiterId(pub u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxJinjaExprId(pub u32);

/// CST node for Jinja expression interpolation: {{ expr }}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxJinjaInterpolationId(pub u32);

/// CST structure for {{ expr }} with individual tokens.
#[derive(Debug, Clone)]
pub struct SyntaxJinjaInterpolation {
    /// TokenId for the `{{` opening delimiter
    pub open_expr: TokenId,
    /// The parsed expression inside (optional if parsing failed)
    pub expr: Option<SyntaxJinjaExprId>,
    /// TokenId for the `}}` closing delimiter
    pub close_expr: TokenId,
    /// Span covering the entire {{ ... }} construct
    pub span: Span,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxJinjaArgId(pub u32);

#[derive(Debug, Clone, Copy)]
pub struct SyntaxJinjaBinaryOpTokens {
    pub primary: TokenId,
    pub secondary: Option<TokenId>,
}

#[derive(Debug, Clone, Copy)]
pub struct SyntaxJinjaFilterArgs {
    pub lparen: TokenId,
    pub rparen: TokenId,
}

#[derive(Debug, Clone)]
pub struct SyntaxJinjaDelimiter {
    pub open_brace: TokenId,
    pub keyword: TokenId,
    pub expr: Option<SyntaxJinjaExprId>,
    pub close_brace: TokenId,
    pub span: Span,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxJinjaStmtId(pub u32);

#[derive(Debug, Clone)]
pub struct SyntaxJinjaStmt {
    pub open_brace: TokenId,
    pub keyword: TokenId,
    pub expr: Option<SyntaxJinjaExprId>,
    pub close_brace: TokenId,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct SyntaxJinjaExpr {
    pub kind: SyntaxJinjaExprKind,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub enum SyntaxJinjaExprKind {
    Literal {
        token: TokenId,
    },
    Name {
        token: TokenId,
    },
    Attribute {
        base: SyntaxJinjaExprId,
        dot: TokenId,
        attr: TokenId,
    },
    Subscript {
        base: SyntaxJinjaExprId,
        lbracket: TokenId,
        index: SyntaxJinjaExprId,
        rbracket: TokenId,
    },
    Tuple {
        lparen: TokenId,
        items: Vec<SyntaxJinjaExprId>,
        rparen: TokenId,
    },
    List {
        lbracket: TokenId,
        items: Vec<SyntaxJinjaExprId>,
        rbracket: TokenId,
    },
    Dict {
        lcurly: TokenId,
        pairs: Vec<(SyntaxJinjaExprId, TokenId, SyntaxJinjaExprId)>, // (key, colon, value)
        rcurly: TokenId,
    },
    BinaryOp {
        left: SyntaxJinjaExprId,
        op_tokens: SyntaxJinjaBinaryOpTokens,
        right: SyntaxJinjaExprId,
    },
    UnaryOp {
        op: TokenId,
        expr: SyntaxJinjaExprId,
    },
    Call {
        callee: SyntaxJinjaExprId,
        lparen: TokenId,
        args: Vec<SyntaxJinjaArgId>,
        rparen: TokenId,
    },
    Filter {
        expr: SyntaxJinjaExprId,
        pipe: TokenId,
        filter: TokenId,
        args: Option<(SyntaxJinjaFilterArgs, Vec<SyntaxJinjaArgId>)>,
    },
    Test {
        expr: SyntaxJinjaExprId,
        is_keyword: TokenId,
        not_keyword: Option<TokenId>,
        test_name: TokenId,
        args: Option<(SyntaxJinjaFilterArgs, Vec<SyntaxJinjaArgId>)>,
    },
    Conditional {
        then_expr: SyntaxJinjaExprId,
        if_keyword: TokenId,
        condition: SyntaxJinjaExprId,
        else_keyword: Option<TokenId>,
        else_expr: Option<SyntaxJinjaExprId>,
    },
}

#[derive(Debug, Clone)]
pub struct SyntaxJinjaArg {
    pub kind: SyntaxJinjaArgKind,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub enum SyntaxJinjaArgKind {
    Positional {
        expr: SyntaxJinjaExprId,
    },
    Keyword {
        name: TokenId,
        eq: TokenId,
        value: SyntaxJinjaExprId,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxJinjaInlineFragmentId(pub u32);

#[derive(Debug, Clone)]
pub struct SyntaxJinjaInlineFragment {
    pub kind: SyntaxJinjaInlineFragmentKind,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub enum SyntaxJinjaInlineFragmentKind {
    Comment {
        token: TokenId,
    },
    InlineBlock {
        opening: SyntaxJinjaDelimiterId,
        closing: Option<SyntaxJinjaDelimiterId>,
    },
    Punctuation {
        tokens: Vec<TokenId>,
    },
}
