// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Public literal-value and data-type taxonomy.
//!
//! Typed numeric / temporal / interval distinctions enable predicates
//! like `literal: { gt: 100 }` to evaluate numerically rather than
//! lexicographically.

use std::collections::BTreeMap;

use chrono::{DateTime, FixedOffset, NaiveDate, NaiveTime};
use serde::{Deserialize, Serialize};

#[cfg(feature = "schema")]
use schemars::JsonSchema;

use super::identity::IdentName;

/// A typed SQL literal. Comparison operators (`gt` / `lt` / etc.)
/// behave by kind: numeric for `integer` / `float` / `decimal`,
/// chronological for `date` / `time` / `timestamp` / `interval`,
/// lexicographic for `string`. Other kinds only support `eq` / `neq`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum LiteralValue {
    Null,
    Bool {
        value: bool,
    },
    Integer {
        value: i64,
    },
    Decimal {
        precision: Option<u8>,
        scale: Option<u8>,
        repr: String,
    },
    Float {
        value: f64,
    },
    String {
        value: String,
    },
    Date {
        value: NaiveDate,
    },
    Time {
        value: NaiveTime,
    },
    Timestamp {
        value: DateTime<FixedOffset>,
    },
    Interval(IntervalValue),
    Bytes {
        value: Vec<u8>,
    },
    Array {
        elements: Vec<LiteralValue>,
    },
    /// JSON / dictionary literal. Field names use `String` (not
    /// `IdentName`) because object keys can be arbitrary strings, not
    /// SQL identifiers.
    Object {
        fields: BTreeMap<String, LiteralValue>,
    },
    /// Dialect-specific or unparseable literal. Predicates match against
    /// `repr` only.
    Other {
        repr: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct IntervalValue {
    pub years: i32,
    pub months: i32,
    pub days: i32,
    pub hours: i32,
    pub minutes: i32,
    pub seconds: i32,
    pub microseconds: i32,
}

/// Typed SQL data type. Catalog-driven for column refs; parser-driven
/// for cast expressions and ALTER TABLE column type changes.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct DataType {
    pub kind: DataTypeKind,
    pub precision: Option<u32>,
    pub scale: Option<u32>,
    pub length: Option<u32>,
    pub element_type: Option<Box<DataType>>,
    pub key_type: Option<Box<DataType>>,
    pub fields: Vec<DataTypeField>,
    pub timezone: Option<String>,
    /// Dialect-original spelling, preserved for `matches:` glob
    /// predicates over dialect-specific shapes.
    pub raw: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum DataTypeKind {
    // Numeric
    Boolean,
    TinyInt,
    SmallInt,
    Integer,
    BigInt,
    Real,
    Double,
    Numeric,
    Decimal,

    // String
    Char,
    Varchar,
    Text,
    NChar,
    NVarchar,
    Clob,

    // Binary
    Binary,
    Varbinary,
    Blob,
    Bytes,

    // Temporal
    Date,
    Time,
    Timestamp,
    TimestampTz,
    TimestampLtz,
    TimestampNtz,
    Interval,

    // Structured
    Array,
    Map,
    Object,
    Struct,
    Variant,
    Json,
    Jsonb,

    // Misc
    Uuid,
    Geography,
    Geometry,
    Vector,

    // Network
    Inet,
    Cidr,
    MacAddr,

    /// Dialect-specific type kinds. Predicates can fall back to
    /// `data_type.raw: { matches: ... }` for matching on the original
    /// spelling.
    Other(IdentName),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub struct DataTypeField {
    pub name: Option<IdentName>,
    pub data_type: DataType,
    pub nullable: bool,
}
