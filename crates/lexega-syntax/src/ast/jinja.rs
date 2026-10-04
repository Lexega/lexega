// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Jinja Template Expression AST
//!
//! This module defines the Abstract Syntax Tree for Jinja template expressions
//! that appear in SQL templates. It provides a semantic representation of
//! Jinja syntax, so a template's expressions can be inspected without
//! rendering it.
//!
//! ## Design Principles
//!
//! 1. **Separate from SQL AST**: Jinja has its own expression language distinct from SQL
//! 2. **Type-safe operators**: Explicit enums for binary/unary operators
//! 3. **Box-based allocation**: Matches existing semantic AST pattern (not arena-based)
//! 4. **Graceful degradation**: Optional - SQL can parse without Jinja expression parsing
//!
//! ## Architecture
//!
//! ```text
//! Jinja Source: {% if target.name == 'prod' %}
//!       ↓
//! Lexer: {%, if, target, ., name, ==, 'prod', %}
//!       ↓
//! Parser: JinjaExpr::BinaryOp {
//!           left: Attribute { base: Name("target"), attr: "name" },
//!           op: Eq,
//!           right: Literal(String("prod"))
//!         }
//! ```

use crate::lexer::Span;
use crate::syntax::{SyntaxJinjaArgId, SyntaxJinjaExprId};

// =============================================================================
// Jinja Statement Types
// =============================================================================

/// A Jinja statement (distinct from expressions).
///
/// Jinja statements perform actions rather than evaluate to values:
/// - `{% set variable = value %}` - Variable assignment
/// - `{% import 'template' as name %}` - Template import
/// - `{% macro name(args) %}...{% endmacro %}` - Macro definition
/// - `{% do expression %}` - Execute expression for side effects
///
/// Unlike expressions, statements don't return values and can't be nested
/// in most contexts.
#[derive(Debug, Clone, PartialEq)]
pub struct JinjaStmt {
    pub node_id: crate::ast::NodeId,
    pub kind: JinjaStmtKind,
    pub span: Span,
    /// Optional link to CST node for token-based formatting
    pub syntax_id: Option<crate::syntax::jinja::SyntaxJinjaStmtId>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum JinjaStmtKind {
    /// Variable assignment: `{% set variable = value %}`
    ///
    /// Example:
    /// ```jinja
    /// {% set user_count = 100 %}
    /// {% set items = [1, 2, 3] %}
    /// {% set config = {'key': 'value'} %}
    /// ```
    Set {
        /// Variable name being assigned
        target: String,
        /// Value expression
        value: Box<JinjaExpr>,
    },

    /// Namespace assignment: `{% set ns.variable = value %}`
    ///
    /// Example:
    /// ```jinja
    /// {% set ns = namespace(counter=0) %}
    /// {% set ns.counter = ns.counter + 1 %}
    /// ```
    SetAttribute {
        /// Namespace object
        target: Box<JinjaExpr>,
        /// Attribute name
        attr: String,
        /// Value expression
        value: Box<JinjaExpr>,
    },

    /// Tuple unpacking assignment: `{% set a, b, c = values %}`
    ///
    /// Example:
    /// ```jinja
    /// {% set x, y, z = get_coordinates() %}
    /// ```
    SetUnpack {
        /// Variable names being assigned
        targets: Vec<String>,
        /// Value expression (must be iterable)
        value: Box<JinjaExpr>,
    },

    /// Execute expression for side effects: `{% do expression %}`
    ///
    /// Example:
    /// ```jinja
    /// {% do items.append(new_item) %}
    /// ```
    Do { expr: Box<JinjaExpr> },
}

// =============================================================================
// Core Expression Types
// =============================================================================

/// A Jinja template expression.
///
/// Represents any expression that can appear in Jinja contexts:
/// - Inside `{{ ... }}` delimiters (expression output)
/// - In `{% if condition %}` (control flow condition)
/// - In `{% for var in iterable %}` (loop iterator)
/// - In filter chains, function arguments, etc.
///
/// Uses `Box<JinjaExpr>` for child nodes to match the semantic AST pattern
/// used by `AstExpr` in the SQL AST.
#[derive(Debug, Clone, PartialEq)]
pub struct JinjaExpr {
    pub node_id: crate::ast::NodeId,
    /// The kind/variant of this expression
    pub kind: JinjaExprKind,
    /// Source location of this expression
    pub span: Span,
    /// Optional link into the typed syntax arena
    pub syntax_id: Option<SyntaxJinjaExprId>,
}

/// The kind of Jinja expression.
///
/// This enum covers all expression forms in Jinja2 template language:
/// - Literals (strings, numbers, booleans)
/// - Variable references
/// - Attribute/subscript access
/// - Binary/unary operations
/// - Function calls
/// - Filters and tests
/// - Conditional expressions
#[derive(Debug, Clone, PartialEq)]
pub enum JinjaExprKind {
    /// Literal value: `'string'`, `42`, `true`, `false`, `null`/`none`
    ///
    /// Examples:
    /// ```jinja
    /// {{ 'hello' }}
    /// {{ 42 }}
    /// {{ true }}
    /// ```
    Literal { value: JinjaLiteralValue },

    /// Variable/identifier reference: `var_name`, `config`, `target`, `loop`
    ///
    /// Examples:
    /// ```jinja
    /// {{ user_name }}
    /// {% if is_prod %}
    /// {% for item in items %}
    /// ```
    Name(String),

    /// Attribute access: `obj.attr`
    ///
    /// Examples:
    /// ```jinja
    /// {{ target.name }}
    /// {{ config.schema }}
    /// {{ loop.index }}
    /// ```
    Attribute {
        /// The base object expression
        base: Box<JinjaExpr>,
        /// The attribute name
        attr: String,
    },

    /// Subscript/index access: `obj[key]`, `list[0]`
    ///
    /// Examples:
    /// ```jinja
    /// {{ config['key'] }}
    /// {{ users[0] }}
    /// {{ nested['a']['b'] }}
    /// ```
    Subscript {
        /// The base object/list expression
        base: Box<JinjaExpr>,
        /// The index/key expression
        index: Box<JinjaExpr>,
    },

    /// Binary operation: `left op right`
    ///
    /// Examples:
    /// ```jinja
    /// {{ x == y }}
    /// {{ a + b }}
    /// {{ enabled and active }}
    /// {{ count > 10 }}
    /// ```
    BinaryOp {
        /// Left operand
        left: Box<JinjaExpr>,
        /// Operator
        op: JinjaBinaryOp,
        /// Right operand
        right: Box<JinjaExpr>,
    },

    /// Unary operation: `op expr`
    ///
    /// Examples:
    /// ```jinja
    /// {{ not active }}
    /// {{ -5 }}
    /// ```
    UnaryOp {
        /// Operator
        op: JinjaUnaryOp,
        /// Operand expression
        expr: Box<JinjaExpr>,
    },

    /// Function call: `func(arg1, arg2, key=value)`
    ///
    /// Examples:
    /// ```jinja
    /// {{ ref('customers') }}
    /// {{ source('raw', 'orders') }}
    /// {{ range(10) }}
    /// {{ dict(a=1, b=2) }}
    /// ```
    Call {
        /// The function expression (typically a Name)
        callee: Box<JinjaExpr>,
        /// Function arguments (positional and keyword)
        args: Vec<JinjaArg>,
    },

    /// Filter application: `expr | filter_name(args)`
    ///
    /// Examples:
    /// ```jinja
    /// {{ name | upper }}
    /// {{ text | default('N/A') }}
    /// {{ items | length }}
    /// {{ value | round(2) }}
    /// ```
    Filter {
        /// The expression being filtered
        expr: Box<JinjaExpr>,
        /// Filter name
        filter: String,
        /// Optional filter arguments
        args: Vec<JinjaArg>,
    },

    /// Test application: `expr is test_name`
    ///
    /// Examples:
    /// ```jinja
    /// {% if var is defined %}
    /// {% if value is none %}
    /// {% if x is divisibleby(3) %}
    /// ```
    Test {
        /// The expression being tested
        expr: Box<JinjaExpr>,
        /// Test name
        test: String,
        /// Optional test arguments
        args: Vec<JinjaArg>,
    },

    /// Inline conditional: `expr if condition else alt`
    ///
    /// Examples:
    /// ```jinja
    /// {{ 'prod' if is_prod else 'dev' }}
    /// {{ value if value else 0 }}
    /// ```
    Conditional {
        /// The expression returned if condition is true
        then_expr: Box<JinjaExpr>,
        /// The condition to test
        condition: Box<JinjaExpr>,
        /// Optional expression returned if condition is false
        else_expr: Option<Box<JinjaExpr>>,
    },

    /// Tuple literal: `(a, b, c)`
    ///
    /// Examples:
    /// ```jinja
    /// {{ (1, 2, 3) }}
    /// {% for x, y in pairs %}
    /// ```
    Tuple { elements: Vec<JinjaExpr> },

    /// List literal: `[a, b, c]`
    ///
    /// Examples:
    /// ```jinja
    /// {{ [1, 2, 3] }}
    /// {{ ['a', 'b', 'c'] }}
    /// ```
    List { elements: Vec<JinjaExpr> },

    /// Dictionary literal: `{key: value, ...}`
    ///
    /// Examples:
    /// ```jinja
    /// {{ {'a': 1, 'b': 2} }}
    /// {{ {key: value for key, value in items} }}
    /// ```
    Dict { pairs: Vec<(JinjaExpr, JinjaExpr)> },
}

// =============================================================================
// Literal Values
// =============================================================================

/// A literal value in Jinja templates.
#[derive(Debug, Clone, PartialEq)]
pub enum JinjaLiteralValue {
    /// String literal: `'hello'`, `"world"`
    String(String),
    /// Integer literal: `42`, `-10`
    Integer(i64),
    /// Float literal: `3.14`, `-2.5`
    Float(f64),
    /// Boolean literal: `true`, `false`
    Boolean(bool),
    /// Null/None literal: `null`, `none`
    Null,
}

// =============================================================================
// Operators
// =============================================================================

/// Binary operators in Jinja expressions.
///
/// Covers comparison, logical, arithmetic, string, and membership operators.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum JinjaBinaryOp {
    // ===== Comparison Operators =====
    /// Equality: `==`
    Eq,
    /// Inequality: `!=`
    Ne,
    /// Less than: `<`
    Lt,
    /// Less than or equal: `<=`
    Le,
    /// Greater than: `>`
    Gt,
    /// Greater than or equal: `>=`
    Ge,

    // ===== Logical Operators =====
    /// Logical AND: `and`
    And,
    /// Logical OR: `or`
    Or,

    // ===== Arithmetic Operators =====
    /// Addition: `+`
    Add,
    /// Subtraction: `-`
    Sub,
    /// Multiplication: `*`
    Mul,
    /// Division: `/`
    Div,
    /// Floor division: `//`
    FloorDiv,
    /// Modulo: `%`
    Mod,
    /// Exponentiation: `**`
    Pow,

    // ===== String Operators =====
    /// String concatenation: `~`
    Concat,

    // ===== Membership Operators =====
    /// Membership test: `in`
    In,
    /// Negative membership test: `not in`
    NotIn,
}

impl JinjaBinaryOp {
    /// Returns the precedence level of this operator (higher = tighter binding).
    ///
    /// Precedence hierarchy (from lowest to highest):
    /// 1. `or` (10)
    /// 2. `and` (20)
    /// 3. `not` (30) - unary, handled separately
    /// 4. Comparisons: `==`, `!=`, `<`, `>`, etc. (40)
    /// 5. `in`, `not in` (40)
    /// 6. String concat: `~` (50)
    /// 7. Add/Sub: `+`, `-` (60)
    /// 8. Mul/Div/Mod: `*`, `/`, `//`, `%` (70)
    /// 9. Unary: `-`, `+` (80) - handled separately
    /// 10. Power: `**` (90)
    /// 11. Filters: `|` (100) - handled separately
    pub fn precedence(self) -> u8 {
        match self {
            Self::Or => 10,
            Self::And => 20,
            Self::Eq | Self::Ne | Self::Lt | Self::Le | Self::Gt | Self::Ge => 40,
            Self::In | Self::NotIn => 40,
            Self::Concat => 50,
            Self::Add | Self::Sub => 60,
            Self::Mul | Self::Div | Self::FloorDiv | Self::Mod => 70,
            Self::Pow => 90,
        }
    }

    /// Returns true if this operator is left-associative.
    ///
    /// Most operators are left-associative (a op b op c = (a op b) op c).
    /// Power (`**`) is right-associative (a ** b ** c = a ** (b ** c)).
    pub fn is_left_associative(self) -> bool {
        !matches!(self, Self::Pow)
    }
}

/// Unary operators in Jinja expressions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum JinjaUnaryOp {
    /// Logical negation: `not expr`
    Not,
    /// Numeric negation: `-expr`
    Neg,
    /// Numeric positive: `+expr`
    Pos,
}

impl JinjaUnaryOp {
    /// Returns the precedence level of this operator.
    pub fn precedence(self) -> u8 {
        match self {
            Self::Not => 30,
            Self::Neg | Self::Pos => 80,
        }
    }
}

// =============================================================================
// Function/Filter Arguments
// =============================================================================

/// An argument in a function call or filter application.
#[derive(Debug, Clone, PartialEq)]
pub struct JinjaArg {
    pub node_id: crate::ast::NodeId,
    /// The argument kind (positional vs keyword)
    pub kind: JinjaArgKind,
    /// Source span covering the entire argument
    pub span: Span,
    /// Optional link into the typed syntax arena
    pub syntax_id: Option<SyntaxJinjaArgId>,
}

/// Kinds of Jinja arguments.
#[derive(Debug, Clone, PartialEq)]
pub enum JinjaArgKind {
    /// Positional argument: `func(expr)`
    Positional(JinjaExpr),
    /// Keyword argument: `func(key=expr)`
    Keyword { name: String, value: JinjaExpr },
}

// =============================================================================
// Helper Constructors
// =============================================================================

impl JinjaExpr {
    /// Create a name/identifier expression.
    pub fn name(name: impl Into<String>, span: Span) -> Self {
        Self {
            kind: JinjaExprKind::Name(name.into()),
            span,
            syntax_id: None,
            node_id: crate::ast::NodeId::new(span.start),
        }
    }

    /// Create a string literal expression.
    pub fn string(value: impl Into<String>, span: Span) -> Self {
        Self {
            kind: JinjaExprKind::Literal {
                value: JinjaLiteralValue::String(value.into()),
            },
            span,
            syntax_id: None,
            node_id: crate::ast::NodeId::new(span.start),
        }
    }

    /// Create an integer literal expression.
    pub fn integer(value: i64, span: Span) -> Self {
        Self {
            kind: JinjaExprKind::Literal {
                value: JinjaLiteralValue::Integer(value),
            },
            span,
            syntax_id: None,
            node_id: crate::ast::NodeId::new(span.start),
        }
    }

    /// Create a boolean literal expression.
    pub fn boolean(value: bool, span: Span) -> Self {
        Self {
            kind: JinjaExprKind::Literal {
                value: JinjaLiteralValue::Boolean(value),
            },
            span,
            syntax_id: None,
            node_id: crate::ast::NodeId::new(span.start),
        }
    }

    /// Create a null literal expression.
    pub fn null(span: Span) -> Self {
        Self {
            kind: JinjaExprKind::Literal {
                value: JinjaLiteralValue::Null,
            },
            span,
            syntax_id: None,
            node_id: crate::ast::NodeId::new(span.start),
        }
    }

    /// Create an attribute access expression.
    pub fn attribute(base: JinjaExpr, attr: impl Into<String>, span: Span) -> Self {
        Self {
            kind: JinjaExprKind::Attribute {
                base: Box::new(base),
                attr: attr.into(),
            },
            span,
            syntax_id: None,
            node_id: crate::ast::NodeId::new(span.start),
        }
    }

    /// Create a binary operation expression.
    pub fn binary(left: JinjaExpr, op: JinjaBinaryOp, right: JinjaExpr, span: Span) -> Self {
        Self {
            kind: JinjaExprKind::BinaryOp {
                left: Box::new(left),
                op,
                right: Box::new(right),
            },
            span,
            syntax_id: None,
            node_id: crate::ast::NodeId::new(span.start),
        }
    }

    /// Create a function call expression.
    pub fn call(callee: JinjaExpr, args: Vec<JinjaArg>, span: Span) -> Self {
        Self {
            kind: JinjaExprKind::Call {
                callee: Box::new(callee),
                args,
            },
            span,
            syntax_id: None,
            node_id: crate::ast::NodeId::new(span.start),
        }
    }
}

impl JinjaArg {
    /// Create a positional argument with default (unset) syntax linkage.
    pub fn positional(expr: JinjaExpr, span: Span) -> Self {
        Self {
            kind: JinjaArgKind::Positional(expr),
            span,
            syntax_id: None,
            node_id: crate::ast::NodeId::new(span.start),
        }
    }

    /// Create a keyword argument with default (unset) syntax linkage.
    pub fn keyword(name: impl Into<String>, value: JinjaExpr, span: Span) -> Self {
        Self {
            kind: JinjaArgKind::Keyword {
                name: name.into(),
                value,
            },
            span,
            syntax_id: None,
            node_id: crate::ast::NodeId::new(span.start),
        }
    }
}

impl JinjaStmt {
    /// Create a simple variable assignment statement.
    pub fn set(target: impl Into<String>, value: JinjaExpr, span: Span) -> Self {
        Self {
            kind: JinjaStmtKind::Set {
                target: target.into(),
                value: Box::new(value),
            },
            span,
            syntax_id: None,
            node_id: crate::ast::NodeId::new(span.start),
        }
    }

    /// Create an attribute assignment statement.
    pub fn set_attribute(
        target: JinjaExpr,
        attr: impl Into<String>,
        value: JinjaExpr,
        span: Span,
    ) -> Self {
        Self {
            kind: JinjaStmtKind::SetAttribute {
                target: Box::new(target),
                attr: attr.into(),
                value: Box::new(value),
            },
            span,
            syntax_id: None,
            node_id: crate::ast::NodeId::new(span.start),
        }
    }

    /// Create a tuple unpacking SET statement: `{% set a, b, c = value %}`
    pub fn set_unpack(targets: Vec<String>, value: JinjaExpr, span: Span) -> Self {
        Self {
            kind: JinjaStmtKind::SetUnpack {
                targets,
                value: Box::new(value),
            },
            span,
            syntax_id: None,
            node_id: crate::ast::NodeId::new(span.start),
        }
    }

    /// Create a do statement.
    pub fn do_expr(expr: JinjaExpr, span: Span) -> Self {
        Self {
            kind: JinjaStmtKind::Do {
                expr: Box::new(expr),
            },
            span,
            syntax_id: None,
            node_id: crate::ast::NodeId::new(span.start),
        }
    }
}

// =============================================================================
// Display Implementations (for debugging/error messages)
// ============================================================================="

impl std::fmt::Display for JinjaBinaryOp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Eq => "==",
            Self::Ne => "!=",
            Self::Lt => "<",
            Self::Le => "<=",
            Self::Gt => ">",
            Self::Ge => ">=",
            Self::And => "and",
            Self::Or => "or",
            Self::Add => "+",
            Self::Sub => "-",
            Self::Mul => "*",
            Self::Div => "/",
            Self::FloorDiv => "//",
            Self::Mod => "%",
            Self::Pow => "**",
            Self::Concat => "~",
            Self::In => "in",
            Self::NotIn => "not in",
        };
        write!(f, "{}", s)
    }
}

impl std::fmt::Display for JinjaUnaryOp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Not => "not",
            Self::Neg => "-",
            Self::Pos => "+",
        };
        write!(f, "{}", s)
    }
}

impl std::fmt::Display for JinjaLiteralValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::String(s) => write!(f, "'{}'", s.replace('\'', "\\'")),
            Self::Integer(i) => write!(f, "{}", i),
            Self::Float(fl) => write!(f, "{}", fl),
            Self::Boolean(b) => write!(f, "{}", if *b { "true" } else { "false" }),
            Self::Null => write!(f, "null"),
        }
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn span(start: u32, end: u32) -> Span {
        Span { start, end }
    }

    #[test]
    fn test_name_expression() {
        let expr = JinjaExpr::name("target", span(0, 6));
        assert!(matches!(expr.kind, JinjaExprKind::Name(ref name) if name == "target"));
        assert_eq!(expr.span, span(0, 6));
    }

    #[test]
    fn test_string_literal() {
        let expr = JinjaExpr::string("hello", span(0, 7));
        match expr.kind {
            JinjaExprKind::Literal {
                value: JinjaLiteralValue::String(ref s),
            } => {
                assert_eq!(s, "hello");
            }
            _ => panic!("Expected string literal"),
        }
    }

    #[test]
    fn test_attribute_access() {
        let base = JinjaExpr::name("target", span(0, 6));
        let expr = JinjaExpr::attribute(base, "name", span(0, 11));

        match expr.kind {
            JinjaExprKind::Attribute { ref base, ref attr } => {
                assert!(matches!(base.kind, JinjaExprKind::Name(ref n) if n == "target"));
                assert_eq!(attr, "name");
            }
            _ => panic!("Expected attribute access"),
        }
    }

    #[test]
    fn test_binary_operation() {
        let left = JinjaExpr::name("x", span(0, 1));
        let right = JinjaExpr::integer(10, span(5, 7));
        let expr = JinjaExpr::binary(left, JinjaBinaryOp::Gt, right, span(0, 7));

        match expr.kind {
            JinjaExprKind::BinaryOp {
                ref left,
                op,
                ref right,
            } => {
                assert!(matches!(left.kind, JinjaExprKind::Name(ref n) if n == "x"));
                assert_eq!(op, JinjaBinaryOp::Gt);
                assert!(matches!(
                    right.kind,
                    JinjaExprKind::Literal {
                        value: JinjaLiteralValue::Integer(10)
                    }
                ));
            }
            _ => panic!("Expected binary operation"),
        }
    }

    #[test]
    fn test_function_call() {
        let callee = JinjaExpr::name("ref", span(0, 3));
        let arg = JinjaExpr::string("customers", span(4, 15));
        let args = vec![JinjaArg::positional(arg.clone(), arg.span)];
        let expr = JinjaExpr::call(callee, args, span(0, 16));

        match expr.kind {
            JinjaExprKind::Call {
                ref callee,
                ref args,
            } => {
                assert!(matches!(callee.kind, JinjaExprKind::Name(ref n) if n == "ref"));
                assert_eq!(args.len(), 1);
                match &args[0].kind {
                    JinjaArgKind::Positional(ref arg_expr) => {
                        assert!(matches!(
                            arg_expr.kind,
                            JinjaExprKind::Literal { value: JinjaLiteralValue::String(ref s) }
                            if s == "customers"
                        ));
                    }
                    _ => panic!("Expected positional argument"),
                }
            }
            _ => panic!("Expected function call"),
        }
    }

    #[test]
    fn test_operator_precedence() {
        // Verify precedence hierarchy
        assert!(JinjaBinaryOp::Or.precedence() < JinjaBinaryOp::And.precedence());
        assert!(JinjaBinaryOp::And.precedence() < JinjaBinaryOp::Eq.precedence());
        assert!(JinjaBinaryOp::Eq.precedence() < JinjaBinaryOp::Add.precedence());
        assert!(JinjaBinaryOp::Add.precedence() < JinjaBinaryOp::Mul.precedence());
        assert!(JinjaBinaryOp::Mul.precedence() < JinjaBinaryOp::Pow.precedence());
    }

    #[test]
    fn test_operator_associativity() {
        // Most operators are left-associative
        assert!(JinjaBinaryOp::Add.is_left_associative());
        assert!(JinjaBinaryOp::Mul.is_left_associative());
        assert!(JinjaBinaryOp::And.is_left_associative());

        // Power is right-associative
        assert!(!JinjaBinaryOp::Pow.is_left_associative());
    }

    #[test]
    fn test_operator_display() {
        assert_eq!(JinjaBinaryOp::Eq.to_string(), "==");
        assert_eq!(JinjaBinaryOp::And.to_string(), "and");
        assert_eq!(JinjaBinaryOp::Concat.to_string(), "~");
        assert_eq!(JinjaUnaryOp::Not.to_string(), "not");
    }
}
