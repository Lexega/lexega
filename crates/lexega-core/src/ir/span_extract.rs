// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Span → typed-value extractors used by IR plan construction.
//!
//! These helpers re-tokenize a `Span` slice of the original source to
//! recover a typed payload (string literal, integer literal, qualified
//! table reference) that the AST stores as an untyped span. They live in
//! the IR layer because every consumer is inside IR plan construction
//! (`policy_plan.rs`, `integration_plan.rs`, `lower.rs`), the single layer
//! that needs the typed value.

use crate::context::node_metadata::TableRef;
use crate::ir::utils::slice_span;
use crate::ir::SessionContext;
use crate::lexer::Span;

/// Extract a SQL string literal's content from a span covering its
/// quoted form. Handles single-quote and double-quote delimited
/// strings; unescapes doubled single quotes (`''` → `'`). Returns
/// `None` when the span text is not quoted.
pub fn extract_string_literal_value(span: Span, source: &str) -> Option<String> {
    decode_string_literal_text(slice_span(source, span)?)
}

/// Decode a SQL string literal's raw (quoted) text to its content.
/// Strips matching single/double-quote delimiters and unescapes doubled
/// single quotes (`''` → `'`); also decodes PostgreSQL dollar-quoted
/// literals (`$$…$$` / `$tag$…$tag$`), whose value is the verbatim inner
/// content (dollar quoting performs no escape processing). Returns `None`
/// when the text is not a recognized string literal. The string-input
/// sibling of [`extract_string_literal_value`] for callers that already
/// hold the literal text (not a span) — e.g. the dynamic-SQL classifier's
/// `ScalarExpr::Lit::Str`, which carries the raw quoted slice.
pub fn decode_string_literal_text(raw: &str) -> Option<String> {
    let raw = raw.trim();
    // PostgreSQL/Redshift escape-string literal `E'…'` / `e'…'`: same
    // quote-doubling as a regular literal, plus C-style backslash escapes.
    // Only when an `E`/`e` actually precedes a quote (a bare identifier
    // starting with `e` is left intact).
    if let Some(rest) = raw
        .strip_prefix(['E', 'e'])
        .filter(|rest| rest.starts_with('\''))
    {
        if rest.len() >= 2 && rest.ends_with('\'') {
            return Some(decode_escape_string_inner(&rest[1..rest.len() - 1]));
        }
    }
    // Strip an optional national-character prefix (T-SQL `N'...'`); only
    // when it actually precedes a quote, so a bare identifier starting
    // with `n` is left intact.
    let raw = raw
        .strip_prefix(['N', 'n'])
        .filter(|rest| rest.starts_with('\'') || rest.starts_with('"'))
        .unwrap_or(raw);
    // PostgreSQL dollar-quoted literal: `$tag$…$tag$` (tag may be empty:
    // `$$…$$`). The opening tag runs to the second `$`; the value is the
    // verbatim bytes between matching open/close tags — NO unescaping.
    if let Some(decoded) = decode_dollar_quoted(raw) {
        return Some(decoded);
    }
    if raw.len() >= 2 && raw.starts_with('"') && raw.ends_with('"') {
        // Not expected for SQL string literals here, but keep best-effort.
        return Some(raw[1..raw.len() - 1].to_string());
    }
    if raw.len() >= 2 && raw.starts_with('\'') && raw.ends_with('\'') {
        // Unescape doubled single quotes: '' -> '
        let inner = &raw[1..raw.len() - 1];
        return Some(inner.replace("''", "'"));
    }
    None
}

/// Decode a quoted string literal AND produce a byte-offset map from the
/// decoded text back into `raw`. `map[i]` is the byte offset within `raw` of
/// the source byte that produced decoded byte `i`. `map` has one more entry
/// than `decoded` has bytes (the final entry is the source offset just past
/// the decoded content), so a half-open decoded span from `a` to `b` maps to
/// the source span from `map[a]` to `map[b]`.
///
/// Handles the cases whose source→decoded transform is offset-trackable:
/// dollar-quoted (`$$…$$`, verbatim — identity map), double-quoted (`"…"`),
/// and single-quoted (`'…'` / `N'…'`) with `''`→`'` un-doubling (each `''`
/// collapses two source bytes to one, shifting the map). Returns `None` for
/// `E'…'` backslash-escape strings (offsets not tracked here) and anything
/// [`decode_string_literal_text`] cannot decode — callers fall back to a
/// coarse location for those rare forms.
pub fn decode_string_literal_text_with_map(raw: &str) -> Option<(String, Vec<u32>)> {
    let lead = (raw.len() - raw.trim_start().len()) as u32;
    let t = raw.trim();
    // Escape-strings are not offset-mapped (rare in dynamic-SQL bodies).
    if t.strip_prefix(['E', 'e'])
        .filter(|rest| rest.starts_with('\''))
        .is_some()
    {
        return None;
    }
    // Optional national-character prefix `N'…'` / `n'…'`.
    let (body, prefix) = match t
        .strip_prefix(['N', 'n'])
        .filter(|rest| rest.starts_with('\'') || rest.starts_with('"'))
    {
        Some(rest) => (rest, 1u32),
        None => (t, 0u32),
    };
    let base = lead + prefix; // offset within `raw` where `body` begins

    // Dollar-quoted: verbatim content, linear map.
    if let Some((inner, content_off)) = decode_dollar_quoted_content(body) {
        let start = base + content_off;
        let map: Vec<u32> = (0..=inner.len() as u32).map(|i| start + i).collect();
        return Some((inner.to_string(), map));
    }
    // Double-quoted: strip quotes, linear map.
    if body.len() >= 2 && body.starts_with('"') && body.ends_with('"') {
        let inner = &body[1..body.len() - 1];
        let start = base + 1;
        let map: Vec<u32> = (0..=inner.len() as u32).map(|i| start + i).collect();
        return Some((inner.to_string(), map));
    }
    // Single-quoted with `''`→`'` un-doubling.
    if body.len() >= 2 && body.starts_with('\'') && body.ends_with('\'') {
        let inner = &body[1..body.len() - 1];
        let inner_base = base + 1;
        let mut out = String::with_capacity(inner.len());
        let mut map: Vec<u32> = Vec::with_capacity(inner.len() + 1);
        let bytes = inner.as_bytes();
        let mut i = 0usize;
        while i < bytes.len() {
            if bytes[i] == b'\'' && bytes.get(i + 1) == Some(&b'\'') {
                map.push(inner_base + i as u32);
                out.push('\'');
                i += 2;
            } else {
                let ch = inner.get(i..).and_then(|s| s.chars().next())?;
                let len = ch.len_utf8();
                for k in 0..len {
                    map.push(inner_base + (i + k) as u32);
                }
                out.push(ch);
                i += len;
            }
        }
        map.push(inner_base + bytes.len() as u32);
        return Some((out, map));
    }
    None
}

/// Like [`decode_dollar_quoted`] but also returns the byte offset within
/// `raw` where the verbatim content begins (i.e. the open-tag length).
fn decode_dollar_quoted_content(raw: &str) -> Option<(&str, u32)> {
    let rest = raw.strip_prefix('$')?;
    let second = rest.find('$')?;
    let tag_end = second + 2;
    let tag = &raw[..tag_end];
    let tag_inner = &rest[..second];
    if !tag_inner.chars().all(|c| c.is_alphanumeric() || c == '_') {
        return None;
    }
    if raw.len() >= 2 * tag.len() && raw.ends_with(tag) {
        Some((&raw[tag.len()..raw.len() - tag.len()], tag.len() as u32))
    } else {
        None
    }
}

/// Decode a PostgreSQL dollar-quoted literal (`$$…$$` / `$tag$…$tag$`) to
/// its verbatim inner content, or `None` when `raw` is not a well-formed
/// dollar-quoted run. The tag is the run from the leading `$` to the next
/// `$` inclusive (empty tag = `$$`); a valid tag's inner chars are
/// identifier characters, and the same tag must close the run. Dollar
/// quoting does no escape processing, so the content is returned as-is.
fn decode_dollar_quoted(raw: &str) -> Option<String> {
    let rest = raw.strip_prefix('$')?;
    let second = rest.find('$')?;
    let tag_end = second + 2; // index just past the closing `$` of the open tag
    let tag = &raw[..tag_end];
    let tag_inner = &rest[..second];
    if !tag_inner.chars().all(|c| c.is_alphanumeric() || c == '_') {
        return None;
    }
    if raw.len() >= 2 * tag.len() && raw.ends_with(tag) {
        return Some(raw[tag.len()..raw.len() - tag.len()].to_string());
    }
    None
}

/// Decode the inner body (between the outer quotes) of a PostgreSQL/Redshift
/// escape-string literal `E'…'`. Unescapes doubled quotes (`''` → `'`) and
/// the quote-affecting C-style escapes (`\'` → `'`, `\\` → `\`); any other
/// `\x` is passed through verbatim — the quote handling is what the
/// downstream re-lex needs to keep string boundaries correct.
fn decode_escape_string_inner(inner: &str) -> String {
    let mut out = String::with_capacity(inner.len());
    let mut chars = inner.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\\' => match chars.next() {
                Some('\'') => out.push('\''),
                Some('\\') => out.push('\\'),
                Some(other) => {
                    out.push('\\');
                    out.push(other);
                }
                None => out.push('\\'),
            },
            '\'' => {
                // Doubled '' -> single '
                if chars.peek() == Some(&'\'') {
                    chars.next();
                }
                out.push('\'');
            }
            _ => out.push(c),
        }
    }
    out
}

/// Extract an integer literal value from a span. The span may cover the
/// full property clause (e.g. `PASSWORD_MIN_LENGTH = 12`) or just the
/// value side; tokenize and pick the first integer literal.
pub fn extract_integer_literal_value(span: Span, source: &str) -> Option<i32> {
    use crate::lexer::{tokenize, LiteralKind, TokenKind};

    let start = span.start as usize;
    let end = span.end as usize;
    if start >= end || end > source.len() {
        return None;
    }

    let text = &source[start..end];
    let lex_result = tokenize(text);

    for token in &lex_result.tokens {
        if let TokenKind::Literal(LiteralKind::Number) = token.kind {
            if let Ok(val) = token.lexeme(text).parse::<i32>() {
                return Some(val);
            }
        }
    }
    None
}

/// Extract a [`TableRef`] from a span that covers a (possibly prefixed)
/// object reference. Handles forms like:
/// - `target_table`
/// - `INTO target_table t`
/// - `TABLE(target_table)`
/// - `IDENTIFIER('schema.table')` (returns a placeholder)
/// - `@stage_name` (stage reference)
///
/// Applies session defaults conservatively: fills `db` from the session
/// when no qualifier was present, and only fills `schema` when the
/// reference was fully unqualified.
pub fn extract_table_ref_from_object_span(
    span: Span,
    source: &str,
    session: &SessionContext,
) -> Option<TableRef> {
    use crate::lexer::{tokenize, Keyword, TokenKind};

    let start = span.start as usize;
    let end = span.end as usize;
    if start >= end || end > source.len() {
        return None;
    }

    let text = &source[start..end];
    if let Some(stage_name) = extract_stage_reference_prefix(text) {
        return Some(TableRef {
            server: None,
            db: None,
            schema: None,
            name: stage_name,
            span: Some(span),
        });
    }

    let lex_result = tokenize(text);

    // Best-effort parsing for spans like:
    // - "INTO target_table t"
    // - "TABLE(target_table)"
    // - "IDENTIFIER('schema.table')" (returns a placeholder)
    //
    // For anything opaque/dynamic (Jinja, IDENTIFIER(), TABLE(<func>(...))),
    // we return a stable placeholder instead of None so writes/reads aren't dropped.
    // Preserve quotes in identifier strings for case sensitivity detection
    let mut parts: Vec<String> = Vec::new();
    let mut last_was_dot = false;
    let mut saw_table_keyword = false;
    let mut i = 0usize;

    let tokens = &lex_result.tokens;
    while i < tokens.len() {
        let token = &tokens[i];
        match &token.kind {
            // Skip common keywords that appear as span prefixes but are
            // not part of the table name. `Using` is included because
            // MERGE's `using_span` starts at the USING keyword token.
            TokenKind::Keyword(Keyword::Into)
            | TokenKind::Keyword(Keyword::As)
            | TokenKind::Keyword(Keyword::Using) => {
                i += 1;
                continue;
            }
            TokenKind::Keyword(Keyword::Table) => {
                saw_table_keyword = true;
                i += 1;
                continue;
            }
            // Skip parentheses and commas (common in TABLE(...), IDENTIFIER(...))
            TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
            | TokenKind::Punctuation(crate::lexer::Punctuation::RParen)
            | TokenKind::Punctuation(crate::lexer::Punctuation::Comma) => {
                i += 1;
                continue;
            }
            // Dot separator for qualified names
            TokenKind::Punctuation(crate::lexer::Punctuation::Dot) => {
                last_was_dot = true;
                i += 1;
                continue;
            }
            // Identifier-like token (Identifier or Keyword) - part of the table name.
            TokenKind::Identifier { .. } | TokenKind::Keyword(_) => {
                let lexeme = token.lexeme(text).trim();
                if lexeme.is_empty() {
                    i += 1;
                    continue;
                }

                // If this is TABLE(<identifier>(...)), treat it as a table function and do not
                // interpret the function name as a table.
                if saw_table_keyword && parts.is_empty() {
                    // Lookahead to next token
                    if (i + 1) < tokens.len()
                        && matches!(
                            tokens[i + 1].kind,
                            TokenKind::Punctuation(crate::lexer::Punctuation::LParen)
                        )
                    {
                        // TABLE(function_call(...)) => opaque; return placeholder at end
                        parts.clear();
                        break;
                    }
                }

                // If we already have parts and last token wasn't a dot,
                // this is likely an alias hint, not part of qualified name
                if !parts.is_empty() && !last_was_dot {
                    break;
                }

                // Preserve quotes for case sensitivity detection via normalize_identifier()
                parts.push(lexeme.to_string());
                last_was_dot = false;
                i += 1;
                continue;
            }
            // Stop at other tokens once we started collecting identifiers
            _ => {
                if !parts.is_empty() {
                    break;
                }
                i += 1;
            }
        }
    }

    // Build TableRef from collected parts
    let mut table_ref = match parts.len() {
        0 => TableRef {
            server: None,
            db: None,
            schema: None,
            name: format!("table_{}", span.start),
            span: Some(span),
        },
        1 => TableRef {
            server: None,
            db: None,
            schema: None,
            name: parts[0].clone(),
            span: Some(span),
        },
        2 => TableRef {
            server: None,
            db: None,
            schema: Some(parts[0].clone()),
            name: parts[1].clone(),
            span: Some(span),
        },
        3 => TableRef {
            server: None,
            db: Some(parts[0].clone()),
            schema: Some(parts[1].clone()),
            name: parts[2].clone(),
            span: Some(span),
        },
        _ => {
            // Four or more parts: T-SQL `server.database.schema.object`.
            // Take the last four positions so the object name is never
            // dropped (anything beyond four is folded into the server slot).
            let n = parts.len();
            TableRef {
                server: Some(parts[..n - 3].join(".")),
                db: Some(parts[n - 3].clone()),
                schema: Some(parts[n - 2].clone()),
                name: parts[n - 1].clone(),
                span: Some(span),
            }
        }
    };

    // Apply session defaults conservatively.
    // - If table had no explicit db qualifier, fill db from session.
    // - Only fill schema from session when the table was fully unqualified.
    let db_was_none = table_ref.db.is_none();

    if db_was_none {
        if let Some(db) = &session.db {
            table_ref.db = Some(db.clone());
        }
    }

    if db_was_none && table_ref.schema.is_none() {
        if let Some(schema) = &session.schema {
            table_ref.schema = Some(schema.clone());
        }
    }

    Some(table_ref)
}

/// Detect a `@stage_name` prefix on a raw span text and return the
/// stage's name including the leading `@`. Stops at the first
/// whitespace outside a quoted segment. Returns `None` for inputs
/// that do not begin with `@` or that contain only a bare `@`.
fn extract_stage_reference_prefix(raw: &str) -> Option<String> {
    let trimmed = raw.trim_start();
    if !trimmed.starts_with('@') {
        return None;
    }

    let mut out = String::new();
    let mut in_quote = false;
    for ch in trimmed.chars() {
        if ch == '"' {
            in_quote = !in_quote;
            out.push(ch);
            continue;
        }
        if ch.is_whitespace() && !in_quote {
            break;
        }
        out.push(ch);
    }

    if out == "@" {
        None
    } else {
        Some(out)
    }
}

/// Fill `db` and `schema` on a `TableRef` from the session defaults
/// when the reference was unqualified. Mirrors the conservative rule
/// applied at parse time:
/// - `db` is filled when not already set.
/// - `schema` is filled only when the reference was fully unqualified
///   (i.e. `db` was also unset).
pub fn apply_session_defaults_to_table_ref(table: &mut TableRef, session: &SessionContext) {
    let db_was_none = table.db.is_none();
    if db_was_none {
        if let Some(db) = &session.db {
            table.db = Some(db.clone());
        }
    }
    if db_was_none && table.schema.is_none() {
        if let Some(schema) = &session.schema {
            table.schema = Some(schema.clone());
        }
    }
}

#[cfg(test)]
mod with_map_tests {
    use super::decode_string_literal_text_with_map;

    #[test]
    fn plain_single_quoted_maps_each_byte() {
        // "'abc'": ' a b c ' -> "abc"; each decoded byte maps to its source.
        let (d, m) = decode_string_literal_text_with_map("'abc'").unwrap();
        assert_eq!(d, "abc");
        assert_eq!(m, vec![1, 2, 3, 4]); // end entry points past 'c' (the closing quote)
    }

    #[test]
    fn doubled_quote_shifts_the_map() {
        // "'a''b'": '' (offsets 2,3) collapses to one ' (decoded idx 1) -> the
        // 'b' after it (source offset 4) is reached by skipping two bytes.
        let (d, m) = decode_string_literal_text_with_map("'a''b'").unwrap();
        assert_eq!(d, "a'b");
        assert_eq!(m, vec![1, 2, 4, 5]);
    }

    #[test]
    fn national_prefix_is_accounted_for() {
        // "N'x'": prefix N + opening quote -> content 'x' at source offset 2.
        let (d, m) = decode_string_literal_text_with_map("N'x'").unwrap();
        assert_eq!(d, "x");
        assert_eq!(m, vec![2, 3]);
    }

    #[test]
    fn dollar_quoted_is_linear() {
        // "$$ab$$": verbatim content begins at offset 2.
        let (d, m) = decode_string_literal_text_with_map("$$ab$$").unwrap();
        assert_eq!(d, "ab");
        assert_eq!(m, vec![2, 3, 4]);
    }

    #[test]
    fn escape_string_is_not_mapped() {
        // E'…' backslash-escape strings are not offset-mapped here.
        assert!(decode_string_literal_text_with_map("E'x'").is_none());
    }
}
