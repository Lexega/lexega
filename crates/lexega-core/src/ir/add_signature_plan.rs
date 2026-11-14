// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! IR-side carrier for the T-SQL `ADD [COUNTER] SIGNATURE` statement.
//!
//! Sibling-tier fact alongside [`super::MssqlAssemblyPlan`]: a typed projection
//! of [`crate::ast::types::AstMssqlAddSignature`] that downstream
//! `derive_facts_from_add_signature_plan` folds into a public
//! `StatementFacts.mssql_add_signature` carrier.
//!
//! The lowering carries the governance-bearing primitives: whether it is a
//! counter-signature, the signer kind, and each inline password that unlocks
//! the signer's private key. Which combination is dangerous (privilege
//! delegation, a hardcoded password) is a YAML verdict.

use crate::ast::types::{AstMssqlAddSignature, SignerKind};
use crate::ast::NodeId;
use crate::ir::span_extract::string_literal_values;
use crate::lexer::token::Span;

#[derive(Debug, Clone)]
pub struct MssqlAddSignaturePlan {
    pub counter: bool,
    pub signer_kind: SignerKind,
    /// Each inline `WITH PASSWORD = '…'` that unlocks the signer, decoded.
    pub password_literals: Vec<String>,
    pub node_id: NodeId,
    pub span: Span,
}

/// Lower a typed [`AstMssqlAddSignature`] into a [`MssqlAddSignaturePlan`].
pub fn lower_add_signature_to_plan(
    s: &AstMssqlAddSignature,
    source: &str,
) -> MssqlAddSignaturePlan {
    MssqlAddSignaturePlan {
        counter: s.counter,
        signer_kind: s.signer_kind,
        password_literals: string_literal_values(&s.password_literal_spans, source),
        node_id: s.node_id,
        span: s.span,
    }
}
