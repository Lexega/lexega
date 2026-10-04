// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Parsed predicate AST + parser.
//!
//! Two-stage compile: parse YAML / JSON to a `Predicate` AST (this
//! file), then compile the AST to a closure (`compile.rs`). YAML/JSON
//! syntax errors surface here; type errors surface in compile.

use crate::facts::LiteralValue;

/// Parsed predicate AST. Closure-compiled at rule-load time; never
/// evaluated directly at runtime.
#[derive(Debug, Clone, PartialEq)]
pub enum Predicate {
    /// `all_of: [Predicate, ...]` — boolean AND.
    AllOf(Vec<Predicate>),
    /// `any_of: [Predicate, ...]` — boolean OR.
    AnyOf(Vec<Predicate>),
    /// `not: Predicate` — boolean NOT.
    Not(Box<Predicate>),
    /// Scalar match: `<path>: <op-block>`.
    Scalar(ScalarMatch),
    /// Relational quantifier match: `<path>: { exists | all | none | each | count }`.
    Relational(RelationalMatch),
}

/// `<path>: <op-block>` against a scalar field.
#[derive(Debug, Clone, PartialEq)]
pub struct ScalarMatch {
    pub path: FieldPath,
    pub op: ScalarOp,
}

/// Scalar operator. Maps to the YAML op-block.
#[derive(Debug, Clone, PartialEq)]
pub enum ScalarOp {
    /// `path: <literal>` sugar for `{ eq: <literal> }`.
    Eq(PredicateLiteral),
    /// `path: { eq: <literal> }`.
    EqExplicit(PredicateLiteral),
    /// `path: { neq: <literal> }`.
    Neq(PredicateLiteral),
    /// `path: { gt: <literal> }`.
    Gt(PredicateLiteral),
    /// `path: { lt: <literal> }`.
    Lt(PredicateLiteral),
    /// `path: { gte: <literal> }`.
    Gte(PredicateLiteral),
    /// `path: { lte: <literal> }`.
    Lte(PredicateLiteral),
    /// `path: { matches: <glob> }`.
    Matches(String),
    /// `path: { in: [<literal>, ...] }`.
    In(Vec<PredicateLiteral>),
    /// `path: { not_in: [<literal>, ...] }`.
    NotIn(Vec<PredicateLiteral>),
    /// `path: { contains: <literal> }` for `Vec<scalar>` fields.
    Contains(PredicateLiteral),
    /// `path: { contains_any: [<literal>, ...] }`.
    ContainsAny(Vec<PredicateLiteral>),
    /// `path: { contains_all: [<literal>, ...] }`.
    ContainsAll(Vec<PredicateLiteral>),
    /// `path: { exists: <bool> }` for `Option<T>` fields.
    Exists(bool),
    /// `path: { is_null: <bool> }` — same as `Exists` but for nullable scalar.
    IsNull(bool),
    /// `path: { range: { low, high, low_inclusive, high_inclusive } }`.
    Range {
        low: PredicateLiteral,
        high: PredicateLiteral,
        low_inclusive: bool,
        high_inclusive: bool,
    },
}

/// `<path>: { quantifier: ... }` against a relation field.
#[derive(Debug, Clone, PartialEq)]
pub struct RelationalMatch {
    pub path: FieldPath,
    pub quantifier: Quantifier,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Quantifier {
    /// `{ exists: Predicate }` — ∃ T. P(T). Vacuous (`any` sugar)
    /// uses `Exists(AllOf(vec![]))`.
    Exists(Box<Predicate>),
    /// `{ all: Predicate }` — ∀ T. P(T).
    All(Box<Predicate>),
    /// `{ none: Predicate }` — ¬∃ T. P(T).
    None(Box<Predicate>),
    /// `{ each: Predicate }` — per-witness emission driver.
    Each(Box<Predicate>),
    /// `{ count: <numeric-op-block> }`.
    Count(NumericOp),
}

/// Numeric op-block restricted to the integer-domain operations valid
/// on collection sizes.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum NumericOp {
    Eq(u64),
    Neq(u64),
    Gt(u64),
    Lt(u64),
    Gte(u64),
    Lte(u64),
}

/// Literal values usable in predicate op-blocks. Maps to a subset of
/// `LiteralValue` plus untagged shapes (bare strings, bare numbers)
/// that the YAML parser commonly produces.
#[derive(Debug, Clone, PartialEq)]
pub enum PredicateLiteral {
    Bool(bool),
    Integer(i64),
    Float(f64),
    String(String),
    /// `null` literal in YAML.
    Null,
    /// Pre-typed reference for richer literal shapes (e.g. `Decimal`,
    /// `Date`, `Timestamp`). Authored by callers wiring up programmatic
    /// rules; typically not produced by the YAML parser.
    Typed(LiteralValue),
}

/// Dotted-path field reference. Each segment is a `FieldName` token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldPath {
    pub segments: Vec<FieldName>,
}

impl FieldPath {
    pub fn parse(s: &str) -> Self {
        Self {
            segments: s
                .split('.')
                .filter(|seg| !seg.is_empty())
                .map(FieldName::parse)
                .collect(),
        }
    }

    pub fn render(&self) -> String {
        self.segments
            .iter()
            .map(FieldName::render)
            .collect::<Vec<_>>()
            .join(".")
    }
}

/// One segment of a field path. Either a named field or a numeric index
/// into a `Vec<T>` field (`scopes.0`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldName {
    Named(String),
    Index(u32),
}

impl FieldName {
    pub fn parse(seg: &str) -> Self {
        if let Ok(idx) = seg.parse::<u32>() {
            Self::Index(idx)
        } else {
            Self::Named(seg.to_string())
        }
    }

    pub fn render(&self) -> String {
        match self {
            Self::Named(s) => s.clone(),
            Self::Index(i) => i.to_string(),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────
// Parser — serde value → typed AST.
// ─────────────────────────────────────────────────────────────────────

/// Errors raised during the parse stage (YAML/JSON value → typed AST).
/// Distinct from compile-time errors (type mismatches against the
/// `StatementFacts` schema), which surface in `compile.rs`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// The predicate node was empty (no recognized keys).
    EmptyPredicate,
    /// More than one logical-combinator key (`all_of` / `any_of` / `not`)
    /// at the same level.
    AmbiguousCombinator { keys: Vec<String> },
    /// The op-block map had no recognized op key.
    UnknownOp { keys: Vec<String> },
    /// A literal value couldn't be parsed (e.g. nested object where a
    /// scalar was expected).
    InvalidLiteral { context: String },
    /// Quantifier op (e.g. `exists:`) was used on a path with no nested
    /// predicate.
    EmptyQuantifier { quantifier: String },
    /// The field name is empty.
    EmptyPath,
    /// Custom parse failure with explanatory message.
    Other(String),
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyPredicate => write!(f, "predicate is empty"),
            Self::AmbiguousCombinator { keys } => {
                write!(f, "ambiguous combinator at predicate node: {:?}", keys)
            }
            Self::UnknownOp { keys } => {
                write!(f, "no recognized op-block key in: {:?}", keys)
            }
            Self::InvalidLiteral { context } => {
                write!(f, "invalid literal: {}", context)
            }
            Self::EmptyQuantifier { quantifier } => {
                write!(f, "{} quantifier with empty body", quantifier)
            }
            Self::EmptyPath => write!(f, "empty field path"),
            Self::Other(msg) => write!(f, "{}", msg),
        }
    }
}

impl std::error::Error for ParseError {}

/// Parse a `serde_json::Value` (or analogous) into a typed `Predicate`
/// AST. The YAML deserializer hands us a value tree; we recognize the
/// predicate shape from the keys present.
pub fn parse_predicate(value: &serde_json::Value) -> Result<Predicate, ParseError> {
    let map = match value {
        serde_json::Value::Object(m) => m,
        _ => {
            return Err(ParseError::Other(format!(
                "predicate must be a YAML/JSON object, got {:?}",
                value
            )))
        }
    };

    if map.is_empty() {
        return Err(ParseError::EmptyPredicate);
    }

    // Logical combinators have priority and are mutually exclusive at a level.
    let combinator_keys: Vec<&String> = map
        .keys()
        .filter(|k| matches!(k.as_str(), "all_of" | "any_of" | "not"))
        .collect();
    if combinator_keys.len() > 1 {
        return Err(ParseError::AmbiguousCombinator {
            keys: combinator_keys.iter().map(|s| s.to_string()).collect(),
        });
    }
    if let Some(key) = combinator_keys.into_iter().next() {
        return parse_combinator(key, &map[key]);
    }

    // Otherwise: a scalar match or a relational match keyed by a path.
    // Each top-level key is a path; each value is either a literal
    // (sugar for eq) or an op-block.
    if map.len() == 1 {
        let (path_str, val) = map.iter().next().expect("non-empty map");
        return parse_path_match(path_str, val);
    }

    // Multiple keys at the predicate level imply implicit `all_of`.
    let inner: Result<Vec<_>, _> = map.iter().map(|(k, v)| parse_path_match(k, v)).collect();
    Ok(Predicate::AllOf(inner?))
}

fn parse_combinator(key: &str, value: &serde_json::Value) -> Result<Predicate, ParseError> {
    match key {
        "all_of" | "any_of" => {
            let arr = match value {
                serde_json::Value::Array(a) => a,
                _ => {
                    return Err(ParseError::Other(format!(
                        "{} must be an array of predicates",
                        key
                    )))
                }
            };
            let parts: Result<Vec<_>, _> = arr.iter().map(parse_predicate).collect();
            Ok(if key == "all_of" {
                Predicate::AllOf(parts?)
            } else {
                Predicate::AnyOf(parts?)
            })
        }
        "not" => Ok(Predicate::Not(Box::new(parse_predicate(value)?))),
        _ => Err(ParseError::Other(format!("unknown combinator: {}", key))),
    }
}

fn parse_path_match(path_str: &str, value: &serde_json::Value) -> Result<Predicate, ParseError> {
    if path_str.is_empty() {
        return Err(ParseError::EmptyPath);
    }
    let path = FieldPath::parse(path_str);

    // Bare scalar literal → sugar for `{ eq: <literal> }`.
    if !matches!(value, serde_json::Value::Object(_)) {
        let lit = parse_literal(value)?;
        return Ok(Predicate::Scalar(ScalarMatch {
            path,
            op: ScalarOp::Eq(lit),
        }));
    }

    // String alias for a quantifier with no body — `path: any`.
    // (Handled above as a non-object value.)

    let map = match value {
        serde_json::Value::Object(m) => m,
        _ => unreachable!(),
    };

    // Quantifier op-blocks live alongside scalar op-blocks; check first.
    if let Some(inner) = map.get("exists") {
        // `exists: <bool>` is the scalar Option-presence op; `exists:
        // <predicate-or-bool>` with predicate-shaped value is the
        // relational quantifier.
        return parse_quantifier_or_exists(path, "exists", inner);
    }
    if let Some(inner) = map.get("all") {
        return Ok(Predicate::Relational(RelationalMatch {
            path,
            quantifier: Quantifier::All(Box::new(parse_predicate(inner)?)),
        }));
    }
    if let Some(inner) = map.get("none") {
        return Ok(Predicate::Relational(RelationalMatch {
            path,
            quantifier: Quantifier::None(Box::new(parse_predicate(inner)?)),
        }));
    }
    if let Some(inner) = map.get("each") {
        // Mirror `exists: {}` sugar — treat an empty inner block as
        // a vacuous-truth predicate ("every element qualifies as a
        // witness"). Customer rules like `query.or_tautologies: { each: {} }`
        // depend on this to fan out per element when no per-element
        // filter is needed.
        let nested = parse_predicate(inner).or_else(|e| {
            if matches!(e, ParseError::EmptyPredicate) {
                Ok(Predicate::AllOf(vec![]))
            } else {
                Err(e)
            }
        })?;
        return Ok(Predicate::Relational(RelationalMatch {
            path,
            quantifier: Quantifier::Each(Box::new(nested)),
        }));
    }
    if let Some(inner) = map.get("count") {
        let count_op = parse_numeric_op(inner)?;
        return Ok(Predicate::Relational(RelationalMatch {
            path,
            quantifier: Quantifier::Count(count_op),
        }));
    }

    // Otherwise it's a scalar op-block.
    let op = parse_scalar_op(map)?;
    Ok(Predicate::Scalar(ScalarMatch { path, op }))
}

fn parse_quantifier_or_exists(
    path: FieldPath,
    _key: &str,
    inner: &serde_json::Value,
) -> Result<Predicate, ParseError> {
    // `exists: <bool>` → scalar Option-presence op.
    if let serde_json::Value::Bool(b) = inner {
        return Ok(Predicate::Scalar(ScalarMatch {
            path,
            op: ScalarOp::Exists(*b),
        }));
    }
    // `exists: { ...predicate... }` or `exists: { }` → relational quantifier.
    let nested = parse_predicate(inner).or_else(|e| {
        // Treat empty `{}` as vacuous-truth predicate (matches every element).
        if matches!(e, ParseError::EmptyPredicate) {
            Ok(Predicate::AllOf(vec![]))
        } else {
            Err(e)
        }
    })?;
    Ok(Predicate::Relational(RelationalMatch {
        path,
        quantifier: Quantifier::Exists(Box::new(nested)),
    }))
}

fn parse_scalar_op(
    map: &serde_json::Map<String, serde_json::Value>,
) -> Result<ScalarOp, ParseError> {
    let keys: Vec<&str> = map.keys().map(String::as_str).collect();

    macro_rules! get {
        ($key:literal) => {
            map.get($key)
        };
    }

    if let Some(v) = get!("eq") {
        return Ok(ScalarOp::EqExplicit(parse_literal(v)?));
    }
    if let Some(v) = get!("neq") {
        return Ok(ScalarOp::Neq(parse_literal(v)?));
    }
    if let Some(v) = get!("gt") {
        return Ok(ScalarOp::Gt(parse_literal(v)?));
    }
    if let Some(v) = get!("lt") {
        return Ok(ScalarOp::Lt(parse_literal(v)?));
    }
    if let Some(v) = get!("gte") {
        return Ok(ScalarOp::Gte(parse_literal(v)?));
    }
    if let Some(v) = get!("lte") {
        return Ok(ScalarOp::Lte(parse_literal(v)?));
    }
    if let Some(v) = get!("matches") {
        let s = match v {
            serde_json::Value::String(s) => s.clone(),
            _ => {
                return Err(ParseError::InvalidLiteral {
                    context: "matches: requires string glob".to_string(),
                })
            }
        };
        return Ok(ScalarOp::Matches(s));
    }
    if let Some(v) = get!("in") {
        return Ok(ScalarOp::In(parse_literal_list(v)?));
    }
    if let Some(v) = get!("not_in") {
        return Ok(ScalarOp::NotIn(parse_literal_list(v)?));
    }
    if let Some(v) = get!("contains") {
        return Ok(ScalarOp::Contains(parse_literal(v)?));
    }
    if let Some(v) = get!("contains_any") {
        return Ok(ScalarOp::ContainsAny(parse_literal_list(v)?));
    }
    if let Some(v) = get!("contains_all") {
        return Ok(ScalarOp::ContainsAll(parse_literal_list(v)?));
    }
    if let Some(v) = get!("is_null") {
        let b = match v {
            serde_json::Value::Bool(b) => *b,
            _ => {
                return Err(ParseError::InvalidLiteral {
                    context: "is_null: requires bool".to_string(),
                })
            }
        };
        return Ok(ScalarOp::IsNull(b));
    }
    if let Some(v) = get!("range") {
        return parse_range_op(v);
    }

    Err(ParseError::UnknownOp {
        keys: keys.iter().map(|s| s.to_string()).collect(),
    })
}

fn parse_range_op(value: &serde_json::Value) -> Result<ScalarOp, ParseError> {
    let map = match value {
        serde_json::Value::Object(m) => m,
        _ => {
            return Err(ParseError::InvalidLiteral {
                context: "range: requires object".to_string(),
            })
        }
    };
    let low = parse_literal(
        map.get("low")
            .ok_or_else(|| ParseError::Other("range: missing low".to_string()))?,
    )?;
    let high = parse_literal(
        map.get("high")
            .ok_or_else(|| ParseError::Other("range: missing high".to_string()))?,
    )?;
    let low_inclusive = map
        .get("low_inclusive")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(true);
    let high_inclusive = map
        .get("high_inclusive")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(true);
    Ok(ScalarOp::Range {
        low,
        high,
        low_inclusive,
        high_inclusive,
    })
}

fn parse_numeric_op(value: &serde_json::Value) -> Result<NumericOp, ParseError> {
    let map = match value {
        serde_json::Value::Object(m) => m,
        // Bare number → sugar for `eq: <n>`.
        serde_json::Value::Number(n) => {
            let v = n.as_u64().ok_or_else(|| ParseError::InvalidLiteral {
                context: "count: requires non-negative integer".to_string(),
            })?;
            return Ok(NumericOp::Eq(v));
        }
        _ => {
            return Err(ParseError::InvalidLiteral {
                context: "count: requires numeric op-block".to_string(),
            })
        }
    };
    let extract = |k: &str| -> Result<Option<u64>, ParseError> {
        match map.get(k) {
            Some(v) => v
                .as_u64()
                .map(Some)
                .ok_or_else(|| ParseError::InvalidLiteral {
                    context: format!("count.{}: requires non-negative integer", k),
                }),
            None => Ok(None),
        }
    };
    if let Some(v) = extract("eq")? {
        return Ok(NumericOp::Eq(v));
    }
    if let Some(v) = extract("neq")? {
        return Ok(NumericOp::Neq(v));
    }
    if let Some(v) = extract("gt")? {
        return Ok(NumericOp::Gt(v));
    }
    if let Some(v) = extract("lt")? {
        return Ok(NumericOp::Lt(v));
    }
    if let Some(v) = extract("gte")? {
        return Ok(NumericOp::Gte(v));
    }
    if let Some(v) = extract("lte")? {
        return Ok(NumericOp::Lte(v));
    }
    Err(ParseError::UnknownOp {
        keys: map.keys().cloned().collect(),
    })
}

fn parse_literal(value: &serde_json::Value) -> Result<PredicateLiteral, ParseError> {
    Ok(match value {
        serde_json::Value::Null => PredicateLiteral::Null,
        serde_json::Value::Bool(b) => PredicateLiteral::Bool(*b),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                PredicateLiteral::Integer(i)
            } else if let Some(f) = n.as_f64() {
                PredicateLiteral::Float(f)
            } else {
                return Err(ParseError::InvalidLiteral {
                    context: format!("number out of range: {}", n),
                });
            }
        }
        serde_json::Value::String(s) => PredicateLiteral::String(s.clone()),
        serde_json::Value::Array(_) | serde_json::Value::Object(_) => {
            return Err(ParseError::InvalidLiteral {
                context: format!("expected scalar literal, got {:?}", value),
            })
        }
    })
}

fn parse_literal_list(value: &serde_json::Value) -> Result<Vec<PredicateLiteral>, ParseError> {
    let arr = match value {
        serde_json::Value::Array(a) => a,
        _ => {
            return Err(ParseError::InvalidLiteral {
                context: "expected array of literals".to_string(),
            })
        }
    };
    arr.iter().map(parse_literal).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(yaml: &str) -> Predicate {
        let v: serde_json::Value =
            serde_yaml_ng::from_str(yaml).expect("yaml parses to value tree");
        parse_predicate(&v).expect("predicate parses")
    }

    #[test]
    fn parse_scalar_eq_sugar() {
        let pred = p("kind: select");
        match pred {
            Predicate::Scalar(ScalarMatch {
                path,
                op: ScalarOp::Eq(PredicateLiteral::String(s)),
            }) => {
                assert_eq!(path.render(), "kind");
                assert_eq!(s, "select");
            }
            other => panic!("unexpected: {:?}", other),
        }
    }

    #[test]
    fn parse_all_of_combinator() {
        let pred = p(r#"
all_of:
  - kind: select
  - query.has_where: false
"#);
        match pred {
            Predicate::AllOf(parts) => assert_eq!(parts.len(), 2),
            other => panic!("unexpected: {:?}", other),
        }
    }

    #[test]
    fn parse_exists_quantifier() {
        let pred = p(r#"
query.scopes:
  exists:
    has_where: true
"#);
        match pred {
            Predicate::Relational(RelationalMatch {
                path,
                quantifier: Quantifier::Exists(_),
            }) => assert_eq!(path.render(), "query.scopes"),
            other => panic!("unexpected: {:?}", other),
        }
    }

    #[test]
    fn parse_count_op() {
        let pred = p(r#"
query.scopes:
  count: { gt: 3 }
"#);
        match pred {
            Predicate::Relational(RelationalMatch {
                path,
                quantifier: Quantifier::Count(NumericOp::Gt(3)),
            }) => assert_eq!(path.render(), "query.scopes"),
            other => panic!("unexpected: {:?}", other),
        }
    }

    #[test]
    fn parse_matches_op() {
        let pred = p(r#"
table.canonical: { matches: "PROD.*" }
"#);
        match pred {
            Predicate::Scalar(ScalarMatch {
                path,
                op: ScalarOp::Matches(glob),
            }) => {
                assert_eq!(path.render(), "table.canonical");
                assert_eq!(glob, "PROD.*");
            }
            other => panic!("unexpected: {:?}", other),
        }
    }

    #[test]
    fn parse_in_list() {
        let pred = p(r#"
kind: { in: [select, set_select, insert] }
"#);
        match pred {
            Predicate::Scalar(ScalarMatch {
                path: _,
                op: ScalarOp::In(items),
            }) => assert_eq!(items.len(), 3),
            other => panic!("unexpected: {:?}", other),
        }
    }

    #[test]
    fn parse_not_combinator() {
        let pred = p(r#"
not:
  query.has_where: false
"#);
        match pred {
            Predicate::Not(_) => {}
            other => panic!("unexpected: {:?}", other),
        }
    }

    #[test]
    fn empty_predicate_is_error() {
        let v = serde_json::json!({});
        assert!(matches!(
            parse_predicate(&v),
            Err(ParseError::EmptyPredicate)
        ));
    }

    #[test]
    fn unknown_op_is_error() {
        let v = serde_json::json!({ "kind": { "absolutely_not_an_op": "foo" } });
        assert!(matches!(
            parse_predicate(&v),
            Err(ParseError::UnknownOp { .. })
        ));
    }

    #[test]
    fn ambiguous_combinator_is_error() {
        let v = serde_json::json!({
            "all_of": [],
            "any_of": [],
        });
        assert!(matches!(
            parse_predicate(&v),
            Err(ParseError::AmbiguousCombinator { .. })
        ));
    }
}
