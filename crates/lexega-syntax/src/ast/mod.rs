// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Abstract Syntax Tree (AST) module.
//!
//! All SQL dialects share a unified AST structure with optional fields
//! for dialect-specific features. This allows runtime dialect selection
//! and single-binary distribution.

pub mod node_id;
pub use node_id::{NodeId, NodeIdGenerator};

pub mod jinja;
pub use jinja::{
    JinjaArg, JinjaArgKind, JinjaBinaryOp, JinjaExpr, JinjaExprKind, JinjaLiteralValue, JinjaStmt,
    JinjaStmtKind, JinjaUnaryOp,
};

// Main AST definitions
pub mod types;
pub use types::*;

// All dialect-specific types are now in ast.rs with optional fields
