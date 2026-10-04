// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Name-free structural fingerprint encoder.
//!
//! Consumers that key on the structure of an IR fragment — repeated
//! subqueries, scalar signatures, pairing an aggregate across two
//! versions of a statement — need a stable, deterministic string
//! identity so two structurally-equal expressions hash to the same key.
//!
//! `format!("{:?}", x)` is not that identity: its text follows the
//! type's variant and field names, so a rename would change every key.
//!
//! [`Fingerprint::fingerprint_into`] emits a deterministic token
//! stream that does NOT contain IR variant or field names — only
//! decimal discriminant indices and payload bytes (operator
//! spellings, literal text, ids). The output is collision-free for
//! distinct variants of the same enum within one type's encoding.

/// Write a name-free structural fingerprint of `self` into `out`.
///
/// Implementations must be:
/// - Deterministic: same input → same bytes.
/// - Variant-injective: two distinct variants of the same enum
///   produce distinguishable prefixes (decimal discriminant index
///   followed by a non-digit separator).
/// - Name-free: no Rust type / variant / field identifiers appear
///   in the output.
pub trait Fingerprint {
    fn fingerprint_into(&self, out: &mut String);
}

use super::plan::{JoinKind, SetOpKind, SymbolId};
use super::scalar::{ComparisonOp, Lit, Quantifier, SqlType, UnaryOpKind};

impl Fingerprint for JoinKind {
    fn fingerprint_into(&self, out: &mut String) {
        let idx: u8 = match self {
            JoinKind::Inner => 0,
            JoinKind::LeftOuter => 1,
            JoinKind::RightOuter => 2,
            JoinKind::FullOuter => 3,
            JoinKind::Cross => 4,
            JoinKind::Asof => 5,
            JoinKind::LeftSemi => 6,
            JoinKind::RightSemi => 7,
            JoinKind::LeftAnti => 8,
            JoinKind::RightAnti => 9,
        };
        push_u8(out, idx);
    }
}

impl Fingerprint for SetOpKind {
    fn fingerprint_into(&self, out: &mut String) {
        let idx: u8 = match self {
            SetOpKind::UnionAll => 0,
            SetOpKind::UnionDistinct => 1,
            SetOpKind::IntersectAll => 2,
            SetOpKind::IntersectDistinct => 3,
            SetOpKind::ExceptAll => 4,
            SetOpKind::ExceptDistinct => 5,
        };
        push_u8(out, idx);
    }
}

impl Fingerprint for ComparisonOp {
    fn fingerprint_into(&self, out: &mut String) {
        out.push_str(self.as_sql_str());
    }
}

impl Fingerprint for UnaryOpKind {
    fn fingerprint_into(&self, out: &mut String) {
        out.push_str(self.as_sql_str());
    }
}

impl Fingerprint for Quantifier {
    fn fingerprint_into(&self, out: &mut String) {
        out.push(match self {
            Quantifier::Any => '0',
            Quantifier::All => '1',
        });
    }
}

impl Fingerprint for SqlType {
    fn fingerprint_into(&self, out: &mut String) {
        // `repr` is the catalog-reported type string (already
        // upper-cased at construction). Payload bytes, not a
        // metadata string.
        out.push_str(&self.repr);
    }
}

impl Fingerprint for SymbolId {
    fn fingerprint_into(&self, out: &mut String) {
        push_u32(out, self.0);
    }
}

impl Fingerprint for Lit {
    fn fingerprint_into(&self, out: &mut String) {
        // Discriminant prefix + ':' + payload. The ':' separator
        // is the boundary between variant tag and payload, so a
        // variant with no payload still terminates cleanly.
        match self {
            Lit::Null => out.push_str("0:"),
            Lit::Bool(b) => {
                out.push_str("1:");
                out.push(if *b { '1' } else { '0' });
            }
            Lit::Integer(s) => {
                out.push_str("2:");
                out.push_str(s);
            }
            Lit::Float(s) => {
                out.push_str("3:");
                out.push_str(s);
            }
            Lit::Str(s) => {
                out.push_str("4:");
                push_len_prefixed(out, s);
            }
            Lit::Bytes { tag, value } => {
                out.push_str("5:");
                push_len_prefixed(out, tag);
                push_len_prefixed(out, value);
            }
            Lit::Typed { type_name, value } => {
                out.push_str("6:");
                push_len_prefixed(out, type_name);
                push_len_prefixed(out, value);
            }
            Lit::Variant(s) => {
                out.push_str("7:");
                push_len_prefixed(out, s);
            }
        }
    }
}

fn push_u8(out: &mut String, n: u8) {
    use std::fmt::Write;
    let _ = write!(out, "{}", n);
}

fn push_u32(out: &mut String, n: u32) {
    use std::fmt::Write;
    let _ = write!(out, "{}", n);
}

/// Length-prefixed payload — `<len>:<bytes>`. Eliminates the
/// ambiguity where two distinct `(a, b)` byte pairs would collide
/// after concatenation (e.g. `("ab", "c")` vs `("a", "bc")`).
fn push_len_prefixed(out: &mut String, s: &str) {
    use std::fmt::Write;
    let _ = write!(out, "{}:{}", s.len(), s);
}
