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
use super::scalar::{ComparisonOp, Lit, NonValue, NonValueArg, Quantifier, SqlType, UnaryOpKind};
use crate::ast::{ArgKeyword, AstTextSearchModifierKind, DatePart, NormalForm, TrimSide, Weekday};

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
            Lit::Variant(s) | Lit::Variable { written: s, .. } => {
                out.push_str("7:");
                push_len_prefixed(out, s);
            }
        }
    }
}

impl Fingerprint for NonValueArg {
    fn fingerprint_into(&self, out: &mut String) {
        use std::fmt::Write;
        let _ = write!(out, "{}:", self.position);
        match &self.value {
            NonValue::Type(t) => {
                out.push_str("0:");
                push_len_prefixed(out, &t.repr);
            }
            NonValue::Unit(part) => {
                out.push_str("1:");
                push_date_part(out, *part);
            }
            NonValue::Keyword(keyword) => {
                out.push_str("2:");
                push_arg_keyword(out, *keyword);
            }
            NonValue::Name(name) => {
                out.push_str("3:");
                push_len_prefixed(out, name.as_str());
            }
        }
    }
}

fn push_date_part(out: &mut String, part: DatePart) {
    let idx: u8 = match part {
        DatePart::Millennium => 0,
        DatePart::Century => 1,
        DatePart::Decade => 2,
        DatePart::Year => 3,
        DatePart::IsoYear => 4,
        DatePart::YearOfWeek => 5,
        DatePart::YearOfWeekIso => 6,
        DatePart::Quarter => 7,
        DatePart::Month => 8,
        DatePart::Week => 9,
        DatePart::IsoWeek => 10,
        DatePart::WeekStarting(day) => {
            out.push_str("11.");
            push_u8(out, weekday_index(day));
            return;
        }
        DatePart::Day => 12,
        DatePart::DayOfWeek => 13,
        DatePart::DayOfWeekIso => 14,
        DatePart::DayOfYear => 15,
        DatePart::Hour => 16,
        DatePart::Minute => 17,
        DatePart::Second => 18,
        DatePart::Millisecond => 19,
        DatePart::Microsecond => 20,
        DatePart::Nanosecond => 21,
        DatePart::Epoch => 22,
        DatePart::EpochMillisecond => 23,
        DatePart::EpochMicrosecond => 24,
        DatePart::EpochNanosecond => 25,
        DatePart::Timezone => 26,
        DatePart::TimezoneHour => 27,
        DatePart::TimezoneMinute => 28,
        DatePart::Julian => 29,
        DatePart::Date => 30,
        DatePart::Time => 31,
        DatePart::DateTime => 32,
        DatePart::SecondMicrosecond => 33,
        DatePart::MinuteMicrosecond => 34,
        DatePart::MinuteSecond => 35,
        DatePart::HourMicrosecond => 36,
        DatePart::HourSecond => 37,
        DatePart::HourMinute => 38,
        DatePart::DayMicrosecond => 39,
        DatePart::DaySecond => 40,
        DatePart::DayMinute => 41,
        DatePart::DayHour => 42,
        DatePart::YearMonth => 43,
    };
    push_u8(out, idx);
}

fn weekday_index(day: Weekday) -> u8 {
    match day {
        Weekday::Sunday => 0,
        Weekday::Monday => 1,
        Weekday::Tuesday => 2,
        Weekday::Wednesday => 3,
        Weekday::Thursday => 4,
        Weekday::Friday => 5,
        Weekday::Saturday => 6,
    }
}

fn push_arg_keyword(out: &mut String, keyword: ArgKeyword) {
    let (kind, idx): (u8, u8) = match keyword {
        ArgKeyword::Trim(side) => (
            0,
            match side {
                TrimSide::Both => 0,
                TrimSide::Leading => 1,
                TrimSide::Trailing => 2,
            },
        ),
        ArgKeyword::NormalForm(form) => (
            1,
            match form {
                NormalForm::Nfc => 0,
                NormalForm::Nfd => 1,
                NormalForm::Nfkc => 2,
                NormalForm::Nfkd => 3,
            },
        ),
        ArgKeyword::TextSearch(mode) => (
            2,
            match mode {
                AstTextSearchModifierKind::Boolean => 0,
                AstTextSearchModifierKind::NaturalLanguage => 1,
                AstTextSearchModifierKind::NaturalLanguageQueryExpansion => 2,
                AstTextSearchModifierKind::QueryExpansion => 3,
            },
        ),
    };
    push_u8(out, kind);
    out.push('.');
    push_u8(out, idx);
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
