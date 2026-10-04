// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Keyword case conversion cache for performance
//!
//! Caches common SQL keywords in uppercase/lowercase/titlecase to avoid
//! repeated string allocations during formatting.
//!
//! Uses phf (perfect hash function) for compile-time hash maps with O(1)
//! lookups and zero runtime initialization cost.

use phf::phf_map;

/// Uppercase keyword cache (compile-time perfect hash map)
static UPPER_CACHE: phf::Map<&'static str, &'static str> = phf_map! {
    "select" => "SELECT",
    "from" => "FROM",
    "where" => "WHERE",
    "and" => "AND",
    "or" => "OR",
    "not" => "NOT",
    "in" => "IN",
    "as" => "AS",
    "on" => "ON",
    "join" => "JOIN",
    "left" => "LEFT",
    "right" => "RIGHT",
    "inner" => "INNER",
    "outer" => "OUTER",
    "full" => "FULL",
    "cross" => "CROSS",
    "group" => "GROUP",
    "by" => "BY",
    "having" => "HAVING",
    "order" => "ORDER",
    "limit" => "LIMIT",
    "offset" => "OFFSET",
    "insert" => "INSERT",
    "into" => "INTO",
    "values" => "VALUES",
    "update" => "UPDATE",
    "set" => "SET",
    "delete" => "DELETE",
    "create" => "CREATE",
    "table" => "TABLE",
    "view" => "VIEW",
    "index" => "INDEX",
    "drop" => "DROP",
    "alter" => "ALTER",
    "truncate" => "TRUNCATE",
    "begin" => "BEGIN",
    "end" => "END",
    "if" => "IF",
    "then" => "THEN",
    "else" => "ELSE",
    "elseif" => "ELSEIF",
    "elsif" => "ELSIF",
    "case" => "CASE",
    "when" => "WHEN",
    "declare" => "DECLARE",
    "let" => "LET",
    "return" => "RETURN",
    "for" => "FOR",
    "while" => "WHILE",
    "loop" => "LOOP",
    "repeat" => "REPEAT",
    "primary" => "PRIMARY",
    "key" => "KEY",
    "foreign" => "FOREIGN",
    "references" => "REFERENCES",
    "unique" => "UNIQUE",
    "null" => "NULL",
    "default" => "DEFAULT",
    "check" => "CHECK",
    "constraint" => "CONSTRAINT",
    "with" => "WITH",
    "using" => "USING",
    "exists" => "EXISTS",
    "union" => "UNION",
    "intersect" => "INTERSECT",
    "except" => "EXCEPT",
    "all" => "ALL",
    "distinct" => "DISTINCT",
    "like" => "LIKE",
    "between" => "BETWEEN",
    "is" => "IS",
    "true" => "TRUE",
    "false" => "FALSE",
    "cast" => "CAST",
    "over" => "OVER",
    "partition" => "PARTITION",
    "window" => "WINDOW",
    "row" => "ROW",
    "rows" => "ROWS",
    "range" => "RANGE",
    "unbounded" => "UNBOUNDED",
    "preceding" => "PRECEDING",
    "following" => "FOLLOWING",
    "current" => "CURRENT",
    "first" => "FIRST",
    "last" => "LAST",
    "match_recognize" => "MATCH_RECOGNIZE",
    "measures" => "MEASURES",
    "copy" => "COPY",
    "merge" => "MERGE",
    "matched" => "MATCHED",
    "use" => "USE",
    "show" => "SHOW",
    "describe" => "DESCRIBE",
    "explain" => "EXPLAIN",
    "exception" => "EXCEPTION",
};

/// Lowercase keyword cache
static LOWER_CACHE: phf::Map<&'static str, &'static str> = phf_map! {
    "select" => "select",
    "from" => "from",
    "where" => "where",
    "and" => "and",
    "or" => "or",
    "not" => "not",
    "in" => "in",
    "as" => "as",
    "on" => "on",
    "join" => "join",
    "left" => "left",
    "right" => "right",
    "inner" => "inner",
    "outer" => "outer",
    "full" => "full",
    "cross" => "cross",
    "group" => "group",
    "by" => "by",
    "having" => "having",
    "order" => "order",
    "limit" => "limit",
    "offset" => "offset",
    "insert" => "insert",
    "into" => "into",
    "values" => "values",
    "update" => "update",
    "set" => "set",
    "delete" => "delete",
    "create" => "create",
    "table" => "table",
    "view" => "view",
    "index" => "index",
    "drop" => "drop",
    "alter" => "alter",
    "truncate" => "truncate",
    "begin" => "begin",
    "end" => "end",
    "if" => "if",
    "then" => "then",
    "else" => "else",
    "elseif" => "elseif",
    "elsif" => "elsif",
    "case" => "case",
    "when" => "when",
    "declare" => "declare",
    "let" => "let",
    "return" => "return",
    "for" => "for",
    "while" => "while",
    "loop" => "loop",
    "repeat" => "repeat",
    "primary" => "primary",
    "key" => "key",
    "foreign" => "foreign",
    "references" => "references",
    "unique" => "unique",
    "null" => "null",
    "default" => "default",
    "check" => "check",
    "constraint" => "constraint",
    "with" => "with",
    "using" => "using",
    "exists" => "exists",
    "union" => "union",
    "intersect" => "intersect",
    "except" => "except",
    "all" => "all",
    "distinct" => "distinct",
    "like" => "like",
    "between" => "between",
    "is" => "is",
    "true" => "true",
    "false" => "false",
    "cast" => "cast",
    "over" => "over",
    "partition" => "partition",
    "window" => "window",
    "row" => "row",
    "rows" => "rows",
    "range" => "range",
    "unbounded" => "unbounded",
    "preceding" => "preceding",
    "following" => "following",
    "current" => "current",
    "first" => "first",
    "last" => "last",
    "match_recognize" => "match_recognize",
    "measures" => "measures",
    "copy" => "copy",
    "merge" => "merge",
    "matched" => "matched",
    "use" => "use",
    "show" => "show",
    "describe" => "describe",
    "explain" => "explain",
    "exception" => "exception",
};

/// Titlecase keyword cache
static TITLE_CACHE: phf::Map<&'static str, &'static str> = phf_map! {
    "select" => "Select",
    "from" => "From",
    "where" => "Where",
    "and" => "And",
    "or" => "Or",
    "not" => "Not",
    "in" => "In",
    "as" => "As",
    "on" => "On",
    "join" => "Join",
    "left" => "Left",
    "right" => "Right",
    "inner" => "Inner",
    "outer" => "Outer",
    "full" => "Full",
    "cross" => "Cross",
    "group" => "Group",
    "by" => "By",
    "having" => "Having",
    "order" => "Order",
    "limit" => "Limit",
    "offset" => "Offset",
    "insert" => "Insert",
    "into" => "Into",
    "values" => "Values",
    "update" => "Update",
    "set" => "Set",
    "delete" => "Delete",
    "create" => "Create",
    "table" => "Table",
    "view" => "View",
    "index" => "Index",
    "drop" => "Drop",
    "alter" => "Alter",
    "truncate" => "Truncate",
    "begin" => "Begin",
    "end" => "End",
    "if" => "If",
    "then" => "Then",
    "else" => "Else",
    "elseif" => "Elseif",
    "elsif" => "Elsif",
    "case" => "Case",
    "when" => "When",
    "declare" => "Declare",
    "let" => "Let",
    "return" => "Return",
    "for" => "For",
    "while" => "While",
    "loop" => "Loop",
    "repeat" => "Repeat",
    "primary" => "Primary",
    "key" => "Key",
    "foreign" => "Foreign",
    "references" => "References",
    "unique" => "Unique",
    "null" => "Null",
    "default" => "Default",
    "check" => "Check",
    "constraint" => "Constraint",
    "with" => "With",
    "using" => "Using",
    "exists" => "Exists",
    "union" => "Union",
    "intersect" => "Intersect",
    "except" => "Except",
    "all" => "All",
    "distinct" => "Distinct",
    "like" => "Like",
    "between" => "Between",
    "is" => "Is",
    "true" => "True",
    "false" => "False",
    "cast" => "Cast",
    "over" => "Over",
    "partition" => "Partition",
    "window" => "Window",
    "row" => "Row",
    "rows" => "Rows",
    "range" => "Range",
    "unbounded" => "Unbounded",
    "preceding" => "Preceding",
    "following" => "Following",
    "current" => "Current",
    "first" => "First",
    "last" => "Last",
    "match_recognize" => "Match_Recognize",
    "measures" => "Measures",
    "copy" => "Copy",
    "merge" => "Merge",
    "matched" => "Matched",
    "use" => "Use",
    "show" => "Show",
    "describe" => "Describe",
    "explain" => "Explain",
    "exception" => "Exception",
};

use std::borrow::Cow;

/// Get uppercase keyword (zero-allocation for cached keywords)
///
/// Returns Cow::Borrowed for cached keywords, Cow::Owned for others.
///
/// # Performance
/// - **O(1)** lookup with zero allocations for 60+ common keywords
/// - **O(n)** allocation only for non-cached keywords
#[inline]
pub fn get_upper_keyword(keyword: &str) -> Cow<'static, str> {
    // Try direct lookup first (works if keyword is already lowercase)
    if let Some(&cached) = UPPER_CACHE.get(keyword) {
        return Cow::Borrowed(cached);
    }

    // Fast path for short keywords: use stack buffer
    if keyword.len() <= 32 {
        let mut buf = [0u8; 32];
        let bytes = keyword.as_bytes();
        buf[..bytes.len()].copy_from_slice(bytes);
        buf[..bytes.len()].make_ascii_lowercase();
        // ASCII lowercase of valid UTF-8 is always valid UTF-8
        if let Ok(lower) = std::str::from_utf8(&buf[..bytes.len()]) {
            if let Some(&cached) = UPPER_CACHE.get(lower) {
                return Cow::Borrowed(cached);
            }
        }
    }

    // Slow path: not cached, compute
    Cow::Owned(keyword.to_uppercase())
}

/// Get lowercase keyword (zero-allocation for cached keywords)
#[inline]
pub fn get_lower_keyword(keyword: &str) -> Cow<'static, str> {
    // Try direct lookup first (works if keyword is already lowercase)
    if let Some(&cached) = LOWER_CACHE.get(keyword) {
        return Cow::Borrowed(cached);
    }

    // Fast path for short keywords: use stack buffer
    if keyword.len() <= 32 {
        let mut buf = [0u8; 32];
        let bytes = keyword.as_bytes();
        buf[..bytes.len()].copy_from_slice(bytes);
        buf[..bytes.len()].make_ascii_lowercase();
        // ASCII lowercase of valid UTF-8 is always valid UTF-8
        if let Ok(lower) = std::str::from_utf8(&buf[..bytes.len()]) {
            if let Some(&cached) = LOWER_CACHE.get(lower) {
                return Cow::Borrowed(cached);
            }
            // Return the lowercased version (must allocate since buf is on stack)
            return Cow::Owned(lower.to_string());
        }
    }

    // Slow path: allocate
    Cow::Owned(keyword.to_lowercase())
}

/// Get titlecase keyword (zero-allocation for cached keywords)
#[inline]
pub fn get_title_keyword(keyword: &str) -> Cow<'static, str> {
    // Try direct lookup first (works if keyword is already lowercase)
    if let Some(&cached) = TITLE_CACHE.get(keyword) {
        return Cow::Borrowed(cached);
    }

    // Fast path for short keywords: use stack buffer
    if keyword.len() <= 32 {
        let mut buf = [0u8; 32];
        let bytes = keyword.as_bytes();
        buf[..bytes.len()].copy_from_slice(bytes);
        buf[..bytes.len()].make_ascii_lowercase();
        // ASCII lowercase of valid UTF-8 is always valid UTF-8
        if let Ok(lower) = std::str::from_utf8(&buf[..bytes.len()]) {
            if let Some(&cached) = TITLE_CACHE.get(lower) {
                return Cow::Borrowed(cached);
            }
        }
    }

    // Slow path: compute title case
    let lower = keyword.to_lowercase();
    let mut chars = lower.chars();
    Cow::Owned(match chars.next() {
        None => String::new(),
        Some(first) => first
            .to_uppercase()
            .chain(chars.flat_map(|c| c.to_lowercase()))
            .collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_upper_keyword_cached() {
        let result = get_upper_keyword("select");
        assert_eq!(result, "SELECT");
    }

    #[test]
    fn test_upper_keyword_uncached() {
        let result = get_upper_keyword("foobar");
        assert_eq!(result, "FOOBAR");
    }

    #[test]
    fn test_lower_keyword_cached() {
        let result = get_lower_keyword("SELECT");
        assert_eq!(result, "select");
    }

    #[test]
    fn test_lower_keyword_uncached() {
        let result = get_lower_keyword("FOOBAR");
        assert_eq!(result, "foobar");
    }

    #[test]
    fn test_title_keyword_cached() {
        let result = get_title_keyword("SELECT");
        assert_eq!(result, "Select");
    }

    #[test]
    fn test_title_keyword_uncached() {
        let result = get_title_keyword("FOOBAR");
        assert_eq!(result, "Foobar");
    }

    #[test]
    fn test_cache_coverage() {
        // Verify all cached keywords work for all cases
        for &keyword in &["select", "from", "where", "join"] {
            let upper = get_upper_keyword(keyword);
            assert!(upper
                .chars()
                .all(|c| c.is_uppercase() || !c.is_alphabetic()));

            let lower = get_lower_keyword(keyword);
            assert!(lower
                .chars()
                .all(|c| c.is_lowercase() || !c.is_alphabetic()));

            let title = get_title_keyword(keyword);
            let mut chars = title.chars();
            if let Some(first) = chars.next() {
                assert!(first.is_uppercase());
            }
        }
    }
}
