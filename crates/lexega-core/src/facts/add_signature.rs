// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Customer-facing facts for the T-SQL `ADD [COUNTER] SIGNATURE` statement.
//!
//! Populated on [`crate::facts::StatementFacts::mssql_add_signature`].
//! Projected from
//! [`crate::ir::add_signature_plan::MssqlAddSignaturePlan`] via
//! `derive_facts_from_add_signature_plan`.
//!
//! Signing a module delegates the signer's privileges to it. Three recognition
//! primitives are surfaced: whether it is a counter-signature, the signer kind,
//! and whether an inline password unlocks the signer's private key. Which
//! combination is dangerous is a YAML verdict. The password value is redacted
//! at parse time and never appears here.
//!
//! Predicate example:
//! ```yaml
//! triggers:
//!   all_of:
//!     - kind: mssql_add_signature
//!     - mssql_add_signature.password_present: true
//! ```

use serde::{Deserialize, Serialize};

#[cfg(feature = "schema")]
use schemars::JsonSchema;

/// What signs the module.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum SignerKind {
    /// `BY CERTIFICATE name`.
    Certificate,
    /// `BY ASYMMETRIC KEY name`.
    AsymmetricKey,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct MssqlAddSignatureFacts {
    /// `true` for `ADD COUNTER SIGNATURE` (signs an existing signature).
    pub counter: bool,
    /// Whether the module is signed by a certificate or an asymmetric key.
    pub signer_kind: SignerKind,
    /// `true` when an inline `WITH PASSWORD = '…'` unlocks the signer's private
    /// key — a hardcoded credential. The value is redacted.
    pub password_present: bool,
}
