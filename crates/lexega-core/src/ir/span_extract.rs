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
/// strings; unescapes doubled single quotes (`''` → `'`), and backslash
/// escapes as [`decode_string_literal_text`] reads them. Returns `None`
/// when the span text is not quoted.
pub fn extract_string_literal_value(span: Span, source: &str) -> Option<String> {
    decode_string_literal_text(slice_span(source, span)?)
}

/// The value of each string literal at `spans`, decoded as
/// [`extract_string_literal_value`] decodes it; a literal that does not
/// decode keeps its text as written, so it is still one value.
pub(crate) fn string_literal_values(spans: &[Span], source: &str) -> Vec<String> {
    spans
        .iter()
        .filter_map(|&span| {
            extract_string_literal_value(span, source)
                .or_else(|| slice_span(source, span).map(str::to_string))
        })
        .collect()
}

/// The joined value of adjacent string literals a dialect reads as one
/// (`'a' 'b'` is `ab`), each part decoded as [`extract_string_literal_value`]
/// decodes it. `None` where a part is no closed string literal.
pub(crate) fn joined_string_literal_value(parts: &[Span], source: &str) -> Option<String> {
    parts
        .iter()
        .map(|part| extract_string_literal_value(*part, source))
        .collect()
}

/// [`joined_string_literal_value`] written as one single-quoted literal that
/// decodes back to it in the dialect in force: `'` doubled, and `\` doubled
/// where that dialect reads backslash escapes.
pub(crate) fn joined_string_literal_text(parts: &[Span], source: &str) -> Option<String> {
    let value = joined_string_literal_value(parts, source)?;
    let mut escaped = value.replace('\'', "''");
    if crate::ir::normalize::dialect_in_force().backslash_escapes_in_single_quoted_strings() {
        escaped = escaped.replace('\\', "\\\\");
    }
    Some(format!("'{escaped}'"))
}

/// Decode a SQL string literal's raw text, surrounding white space
/// ignored, to its value: [`crate::lexer::decode_string_literal`], read as
/// the dialect of the analysis running on the thread reads it (Snowflake
/// outside every analysis): backslash escapes where that dialect reads
/// them in a plain string, and in an `E'…'` string. Returns `None` when
/// the text is not one closed string literal. The string-input sibling of
/// [`extract_string_literal_value`] for callers that already hold the
/// literal text (not a span) — e.g. the dynamic-SQL classifier's
/// `ScalarExpr::Lit::Str`, which carries the raw quoted slice.
pub fn decode_string_literal_text(raw: &str) -> Option<String> {
    decoded_literal(raw, crate::ir::normalize::dialect_in_force().as_ref())
        .map(|(_, decoded)| decoded.value)
}

/// [`decode_string_literal_text`] AND a byte-offset map from the decoded
/// text back into `raw`, read in the same dialect. `map[i]` is the byte
/// offset within `raw` of the source that produced decoded byte `i` (the
/// start of a doubled quote or a backslash escape). `map` has one more
/// entry than `decoded` has bytes (the final entry is the source offset
/// just past the decoded content), so a half-open decoded span from `a` to
/// `b` maps to the source span from `map[a]` to `map[b]`.
pub fn decode_string_literal_text_with_map(raw: &str) -> Option<(String, Vec<u32>)> {
    decode_string_literal_text_with_map_in(raw, crate::ir::normalize::dialect_in_force().as_ref())
}

/// [`decode_string_literal_text_with_map`], read as `dialect` reads it.
pub(crate) fn decode_string_literal_text_with_map_in(
    raw: &str,
    dialect: &dyn crate::dialect::Dialect,
) -> Option<(String, Vec<u32>)> {
    let (lead, decoded) = decoded_literal(raw, dialect)?;
    let mut map = Vec::with_capacity(decoded.value.len() + 1);
    for (c, source) in decoded.value.chars().zip(&decoded.sources) {
        let last = source.end.saturating_sub(source.start).saturating_sub(1);
        for k in 0..c.len_utf8() as u32 {
            map.push(lead + source.start + k.min(last));
        }
    }
    map.push(lead + decoded.content.end);
    Some((decoded.value, map))
}

/// The value of the closed string literal `text` writes, white space around
/// it ignored, read as the dialect in force reads it. `None` for text that
/// is no string literal of that dialect: a `"…"` it reads as a name, a bare
/// word, a number.
pub(crate) fn string_literal_value(text: &str) -> Option<String> {
    let dialect = crate::ir::normalize::dialect_in_force();
    let text = text.trim();
    let decoded = crate::lexer::decode_string_literal(text, dialect.as_ref())?;
    let opener = text.get(..decoded.content.start as usize)?;
    let is_name = opener.ends_with('"') && !dialect.supports_double_quoted_strings();
    (decoded.closed && !is_name).then_some(decoded.value)
}

/// The value of the string literal `text` writes, or `text` itself, white
/// space around it ignored, where it writes none.
pub(crate) fn literal_value_or_text(text: &str) -> String {
    string_literal_value(text).unwrap_or_else(|| text.trim().to_string())
}

/// [`literal_value_or_text`], with a quoted name read without its quotes.
pub(crate) fn literal_value_or_name(text: &str) -> String {
    string_literal_value(text).unwrap_or_else(|| {
        crate::catalog::provider::strip_quoting(text.trim())
            .0
            .to_string()
    })
}

/// One `key=value` entry of a connection string a string literal writes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WrittenConnectionEntry {
    /// The key as written.
    pub(crate) key: String,
    /// The value, inside the `"…"` or `{…}` that may delimit it; `None`
    /// where a placeholder overlaps it.
    pub(crate) value: Option<String>,
}

/// The value of the closed string literal written at `span`, decoded as
/// the dialect in force reads it, with the source span of each byte.
struct WrittenValue {
    value: String,
    map: Vec<u32>,
    at: u32,
}

impl WrittenValue {
    fn read(span: Span, source: &str) -> Option<Self> {
        let (value, map) = decode_string_literal_text_with_map(slice_span(source, span)?)?;
        Some(Self {
            value,
            map,
            at: span.start,
        })
    }

    /// Whether a placeholder overlaps the source that writes `range` of the
    /// value: a render or a substitution wrote it, so it is no literal.
    fn filled(&self, range: &std::ops::Range<usize>, placeholders: &[Span]) -> bool {
        let written = Span {
            start: self.at + self.map[range.start],
            end: self.at + self.map[range.end],
        };
        placeholders.iter().any(|p| p.overlaps(written))
    }
}

/// The password of each URL the string literal written at `span` holds with
/// user information ([`lexega_syntax::secrets::url_password_ranges`]),
/// decoded. A password a placeholder overlaps is left out.
pub(crate) fn url_password_literals(
    span: Span,
    source: &str,
    placeholders: &[Span],
) -> Vec<String> {
    let Some(written) = WrittenValue::read(span, source) else {
        return Vec::new();
    };
    lexega_syntax::secrets::url_password_ranges(&written.value)
        .into_iter()
        .filter(|range| !written.filled(range, placeholders))
        .map(|range| written.value[range].to_string())
        .collect()
}

/// The entries of the connection string the string literal written at
/// `span` holds ([`lexega_syntax::secrets::connection_string_entries`]),
/// decoded.
pub(crate) fn connection_string_entries(
    span: Span,
    source: &str,
    placeholders: &[Span],
) -> Vec<WrittenConnectionEntry> {
    let Some(written) = WrittenValue::read(span, source) else {
        return Vec::new();
    };
    lexega_syntax::secrets::connection_string_entries(&written.value)
        .into_iter()
        .map(|entry| WrittenConnectionEntry {
            key: written.value[entry.key].to_string(),
            value: (!written.filled(&entry.value, placeholders))
                .then(|| written.value[entry.value].to_string()),
        })
        .collect()
}

/// The strings of T-SQL `OPENROWSET`'s `'data source';'user';'password'`
/// run written at `span` ([`lexega_syntax::secrets::connection_call_strings`]),
/// decoded, each under the key [`lexega_syntax::secrets::LOGIN_RUN_KEYS`]
/// names its place by. A string a placeholder overlaps has no value.
pub(crate) fn login_run_entries(
    span: Span,
    source: &str,
    placeholders: &[Span],
) -> Vec<WrittenConnectionEntry> {
    use crate::lexer::TokenKind;
    let Some(text) = slice_span(source, span) else {
        return Vec::new();
    };
    let dialect = crate::ir::normalize::dialect_in_force();
    let tokens: Vec<crate::lexer::Token> =
        crate::lexer::tokenize_with_dialect(text, dialect.as_ref())
            .tokens
            .into_iter()
            .filter(|t| {
                !matches!(
                    t.kind,
                    TokenKind::LineComment | TokenKind::BlockComment | TokenKind::JinjaComment
                )
            })
            .collect();
    lexega_syntax::secrets::connection_call_strings(&tokens)
        .into_iter()
        .filter_map(|string| {
            let key = lexega_syntax::secrets::LOGIN_RUN_KEYS.get(string.place_in_run?)?;
            let token = tokens.get(string.token)?.span;
            let literal = Span {
                start: span.start + token.start,
                end: span.start + token.end,
            };
            let written = WrittenValue::read(literal, source)?;
            let whole = 0..written.value.len();
            Some(WrittenConnectionEntry {
                key: (*key).to_string(),
                value: (!written.filled(&whole, placeholders)).then(|| written.value.clone()),
            })
        })
        .collect()
}

/// The closed string literal `raw` writes, decoded as `dialect` reads it,
/// and the offset of its text in `raw` past the leading white space.
fn decoded_literal(
    raw: &str,
    dialect: &dyn crate::dialect::Dialect,
) -> Option<(u32, crate::lexer::DecodedString)> {
    let lead = (raw.len() - raw.trim_start().len()) as u32;
    crate::lexer::decode_string_literal(raw.trim(), dialect)
        .filter(|decoded| decoded.closed)
        .map(|decoded| (lead, decoded))
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

    session.place(&mut table_ref.db, &mut table_ref.schema);
    Some(table_ref)
}

/// Fill `db` and `schema` on a `TableRef` from the session defaults
/// when the reference was unqualified. Mirrors the conservative rule
/// applied at parse time:
/// - `db` is filled when not already set.
/// - `schema` is filled only when the reference was fully unqualified
///   (i.e. `db` was also unset).
pub fn apply_session_defaults_to_table_ref(table: &mut TableRef, session: &SessionContext) {
    let (db, schema) = session_default_parts(table, session);
    let (db, schema) = (db.map(str::to_string), schema.map(str::to_string));
    table.db = db;
    table.schema = schema;
}

/// The `db` and `schema` parts of `table` with the session defaults for
/// the parts it omits, by the rule of
/// [`apply_session_defaults_to_table_ref`].
pub(crate) fn session_default_parts<'a>(
    table: &'a TableRef,
    session: &'a SessionContext,
) -> (Option<&'a str>, Option<&'a str>) {
    let db = table.db.as_deref().or(session.db.as_deref());
    let schema = match (&table.db, &table.schema) {
        (None, None) => session.schema.as_deref(),
        (Some(_), None) | (None, Some(_)) | (Some(_), Some(_)) => table.schema.as_deref(),
    };
    (db, schema)
}

#[cfg(test)]
mod session_default_tests {
    use super::{apply_session_defaults_to_table_ref, session_default_parts};
    use crate::context::node_metadata::TableRef;
    use crate::ir::SessionContext;

    #[test]
    fn a_default_fills_only_the_part_the_reference_omits() {
        let session = SessionContext {
            db: Some("d".to_string()),
            schema: Some("s".to_string()),
            search_path: Vec::new(),
        };
        let bare = TableRef::new("t".to_string());
        let cases = [
            (bare.clone(), (Some("d"), Some("s"))),
            // A schema written under no database takes the database only.
            (
                bare.clone().with_schema("x".to_string()),
                (Some("d"), Some("x")),
            ),
            // A database written with no schema takes no default schema.
            (bare.clone().with_db("y".to_string()), (Some("y"), None)),
            (
                bare.clone()
                    .with_db("y".to_string())
                    .with_schema("x".to_string()),
                (Some("y"), Some("x")),
            ),
        ];
        for (table, parts) in cases {
            assert_eq!(session_default_parts(&table, &session), parts, "{table:?}");
            let mut filled = table.clone();
            apply_session_defaults_to_table_ref(&mut filled, &session);
            assert_eq!((filled.db.as_deref(), filled.schema.as_deref()), parts);
            let none = SessionContext::default();
            assert_eq!(
                session_default_parts(&table, &none),
                (table.db.as_deref(), table.schema.as_deref())
            );
        }
    }
}

#[cfg(test)]
mod dialect_in_force_tests {
    use super::{literal_value_or_name, literal_value_or_text, string_literal_value};
    use crate::ir::normalize::set_normalization_dialect;

    #[test]
    fn a_literal_is_read_as_the_dialect_in_force_reads_it() {
        {
            let _snowflake = set_normalization_dialect("snowflake");
            assert_eq!(string_literal_value("'a\\'b'").as_deref(), Some("a'b"));
            assert_eq!(string_literal_value(" 'it''s' ").as_deref(), Some("it's"));
            assert_eq!(
                string_literal_value("$$./x.sql$$").as_deref(),
                Some("./x.sql")
            );
            // A double-quoted name is no string; neither is an unclosed one.
            assert_eq!(string_literal_value("\"Name\""), None);
            assert_eq!(string_literal_value("'open"), None);
            assert_eq!(literal_value_or_name("\"Name\""), "Name");
            assert_eq!(literal_value_or_text(" @v "), "@v");
        }
        {
            let _postgres = set_normalization_dialect("postgresql");
            assert_eq!(string_literal_value("'a\\'b'").as_deref(), Some("a\\'b"));
            assert_eq!(string_literal_value("E'a\\'b'").as_deref(), Some("a'b"));
        }
        {
            let _mysql = set_normalization_dialect("mysql");
            assert_eq!(string_literal_value("\"a\\tb\"").as_deref(), Some("a\tb"));
        }
        {
            let _mssql = set_normalization_dialect("mssql");
            assert_eq!(string_literal_value("N'it''s'").as_deref(), Some("it's"));
        }
    }

    #[test]
    fn snowflake_tag_and_session_values_read_backslash_escapes() {
        let _snowflake = set_normalization_dialect("snowflake");
        let sql = "CREATE TAG t ALLOWED_VALUES 'a''b', 'c\\'d'; \
                   ALTER SESSION SET QUERY_TAG = 'e\\'f';";
        let script =
            crate::parse_sql_with_dialect(sql, &crate::dialect::SnowflakeDialect).expect("parses");
        let crate::ast::AstStmt::CreateTag(tag) = &script.stmts[0] else {
            panic!("a CREATE TAG: {:?}", script.stmts[0]);
        };
        let plan = crate::ir::lower_create_tag_to_tag_plan(tag, sql);
        let Some(crate::ir::TagAlterActionIr::SetAllowedValues { values }) =
            plan.alter_actions.first()
        else {
            panic!("allowed values: {:?}", plan.alter_actions);
        };
        assert_eq!(values, &["a'b", "c'd"]);
        let crate::ast::AstStmt::AlterSession(session) = &script.stmts[1] else {
            panic!("an ALTER SESSION: {:?}", script.stmts[1]);
        };
        let plan = crate::ir::lower_alter_session_to_session_plan(session, sql);
        let crate::ir::SessionAction::Set { params } = &plan.action else {
            panic!("a SET: {:?}", plan.action);
        };
        assert_eq!(params[0].value, "e'f");
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
    fn escape_string_maps_each_escape_to_its_start() {
        // E'a\nb''c': `\n` (offsets 3,4) and `''` (offsets 6,7) are one byte each.
        let (d, m) = decode_string_literal_text_with_map("E'a\\nb''c'").unwrap();
        assert_eq!(d, "a\nb'c");
        assert_eq!(m, vec![2, 3, 5, 6, 8, 9]);
    }

    #[test]
    fn a_plain_string_keeps_its_backslash_and_a_double_quoted_one_undoubles() {
        let _postgres = crate::ir::normalize::set_normalization_dialect("postgresql");
        assert_eq!(
            super::decode_string_literal_text("'a\\'b'").as_deref(),
            Some("a\\'b")
        );
        assert_eq!(
            super::decode_string_literal_text(" \"a\"\"b\" ").as_deref(),
            Some("a\"b")
        );
        assert_eq!(super::decode_string_literal_text("'open"), None);
        assert_eq!(super::decode_string_literal_text("X'41'"), None);
    }

    #[test]
    fn a_string_is_decoded_as_the_dialect_in_force_reads_it() {
        for dialect in ["snowflake", "mysql", "bigquery", "databricks"] {
            let _scope = crate::ir::normalize::set_normalization_dialect(dialect);
            assert_eq!(
                super::decode_string_literal_text("'a\\'b'").as_deref(),
                Some("a'b"),
                "{dialect}"
            );
            let (d, m) = decode_string_literal_text_with_map("'a\\'b'").unwrap();
            assert_eq!((d.as_str(), m), ("a'b", vec![1, 2, 4, 5]), "{dialect}");
        }
        for dialect in ["postgresql", "redshift", "mssql"] {
            let _scope = crate::ir::normalize::set_normalization_dialect(dialect);
            assert_eq!(
                super::decode_string_literal_text("'dom\\usr'").as_deref(),
                Some("dom\\usr"),
                "{dialect}"
            );
            assert_eq!(
                super::decode_string_literal_text("'it''s'").as_deref(),
                Some("it's"),
                "{dialect}"
            );
        }
    }
}
