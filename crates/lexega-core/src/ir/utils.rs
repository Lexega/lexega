// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Small cross-cutting utilities used by IR construction and analysis.

use crate::lexer::Span;

/// The parts of a relation's name as written, `None` for an omitted part
/// (`db..name`): a quoted path is read as its parts where the dialect reads
/// it so (BigQuery's `` `p.d.t` `` is `` `p` ``, `` `d` ``, `` `t` ``). The
/// one place a relation's written parts are read; every relation built from
/// SQL text takes its parts from here.
pub(crate) fn relation_written_parts(written: Vec<Option<String>>) -> Vec<Option<String>> {
    let present: Vec<&str> = written.iter().flatten().map(String::as_str).collect();
    let pieces = crate::dialect::relation_written_parts(&present);
    if pieces.len() == present.len() {
        return written;
    }
    pieces.into_iter().map(Some).collect()
}

/// The span of each part of the dotted name `raw`, which starts at `start`
/// of the source: a dot inside quotes (`"…"`, `` `…` ``, `[…]`) separates
/// nothing. Each part is as written, untrimmed; an empty last part (a
/// trailing dot) is dropped. The one reading of where a dotted name splits.
pub(crate) fn dotted_name_segments(raw: &str, start: u32) -> Vec<Span> {
    let mut out = Vec::new();
    let mut from = 0usize;
    let mut close: Option<char> = None;
    let mut chars = raw.char_indices().peekable();
    let span = |from: usize, to: usize| Span {
        start: start + from as u32,
        end: start + to as u32,
    };
    while let Some((at, ch)) = chars.next() {
        match close {
            // `]]` inside brackets is a `]` of the name.
            Some(']') if ch == ']' && chars.peek().is_some_and(|&(_, next)| next == ']') => {
                chars.next();
            }
            Some(quote) if ch == quote => close = None,
            Some(_) => {}
            None => match ch {
                '"' | '`' => close = Some(ch),
                '[' => close = Some(']'),
                '.' => {
                    out.push(span(from, at));
                    from = at + 1;
                }
                _ => {}
            },
        }
    }
    if from < raw.len() {
        out.push(span(from, raw.len()));
    }
    out
}

/// Slice the source text covered by a span, or `None` if the span is out of range.
pub fn slice_span(source: &str, span: Span) -> Option<&str> {
    source.get(span.start as usize..span.end as usize)
}

/// The name `IDENTIFIER(…)`, written as `raw`, names: the one its string
/// writes, or the text its variable (`$v`, `:v`) is known to hold at the
/// statement being lowered ([`crate::ir::statement_values`]); `None` for
/// any other text, and for a variable whose text the script does not say.
pub(crate) fn identifier_string_name(raw: &str) -> Option<String> {
    use crate::lexer::{LiteralKind, Punctuation, TokenKind};
    const WORD: &str = "IDENTIFIER";
    let raw = raw.trim();
    if !raw.get(..WORD.len())?.eq_ignore_ascii_case(WORD) {
        return None;
    }
    let dialect = crate::ir::normalize::dialect_in_force();
    let lexed = crate::lexer::tokenize_with_dialect(raw, dialect.as_ref());
    let [word, open, argument @ .., close, end] = lexed.tokens.as_slice() else {
        return None;
    };
    let shaped = word.lexeme(raw).eq_ignore_ascii_case(WORD)
        && matches!(open.kind, TokenKind::Punctuation(Punctuation::LParen))
        && matches!(close.kind, TokenKind::Punctuation(Punctuation::RParen))
        && matches!(end.kind, TokenKind::Eof);
    if !shaped {
        return None;
    }
    match argument {
        [literal] if matches!(literal.kind, TokenKind::Literal(LiteralKind::String)) => {
            crate::ir::span_extract::string_literal_value(literal.lexeme(raw))
        }
        // `$v`, where the dialect reads `$name` as a session variable.
        [variable]
            if dialect.dollar_name_is_session_variable()
                && matches!(variable.kind, TokenKind::Identifier { .. }) =>
        {
            let name = variable.lexeme(raw).strip_prefix('$')?;
            if name.starts_with('$') {
                return None;
            }
            variable_text(true, name)
        }
        // `:v`, a scripting variable.
        [colon, name]
            if matches!(colon.kind, TokenKind::Punctuation(Punctuation::Colon))
                && matches!(
                    name.kind,
                    TokenKind::Identifier { .. } | TokenKind::Keyword(_)
                ) =>
        {
            variable_text(false, name.lexeme(raw))
        }
        _ => None,
    }
}

/// The text the `IDENTIFIER(…)` argument `argument` writes: the string a
/// literal writes, or the text a variable (`$v`, `:v`) is known to hold at
/// the statement being lowered.
fn identifier_argument_text(source: &str, argument: &crate::ast::AstExpr) -> Option<String> {
    use crate::ast::AstExpr;
    let argument = crate::ir::dynamic_sql::unparenthesized(argument);
    if let AstExpr::SessionVarRef { name_span, .. } = argument {
        return variable_text(true, slice_span(source, *name_span)?);
    }
    if let AstExpr::ScriptingVarRef { name_span, .. } = argument {
        return variable_text(false, slice_span(source, *name_span)?);
    }
    crate::ir::span_extract::string_literal_value(slice_span(source, argument.span())?)
}

/// The text the variable written `written` is known to hold at the
/// statement being lowered, `session` for `$v`.
fn variable_text(session: bool, written: &str) -> Option<String> {
    crate::ir::statement_values::value_in_force(
        session,
        &crate::ir::dynamic_sql::variable_key(written),
    )
}

/// The text of the one name `raw` writes before an argument list that ends
/// it (`s1."MyFn"` of `s1."MyFn"(INT)`, `IDENTIFIER('f')` of
/// `IDENTIFIER('f')(INT)`); `None` where `raw` is not one name followed by
/// one argument list.
fn name_before_argument_list(raw: &str) -> Option<&str> {
    use crate::lexer::{Punctuation, TokenKind};
    let dialect = crate::ir::normalize::dialect_in_force();
    let lexed = crate::lexer::tokenize_with_dialect(raw, dialect.as_ref());
    let [written @ .., close, end] = lexed.tokens.as_slice() else {
        return None;
    };
    if !matches!(close.kind, TokenKind::Punctuation(Punctuation::RParen))
        || !matches!(end.kind, TokenKind::Eof)
    {
        return None;
    }
    // The `(` the last `)` closes, and no list of names before it.
    let mut depth = 1usize;
    let mut open = None;
    for (at, token) in written.iter().enumerate().rev() {
        match token.kind {
            TokenKind::Punctuation(Punctuation::RParen) => depth += 1,
            TokenKind::Punctuation(Punctuation::LParen) => {
                depth -= 1;
                if depth == 0 {
                    open = Some(at);
                    break;
                }
            }
            _ => {}
        }
    }
    let open = open.filter(|&at| at > 0)?;
    let mut depth = 0usize;
    for token in &written[..open] {
        match token.kind {
            TokenKind::Punctuation(Punctuation::LParen) => depth += 1,
            TokenKind::Punctuation(Punctuation::RParen) => depth = depth.checked_sub(1)?,
            TokenKind::Punctuation(Punctuation::Comma) if depth == 0 => return None,
            _ => {}
        }
    }
    raw.get(..written[open].span.start as usize)
        .map(str::trim_end)
}

/// The parts of the routine `name` names, as [`written_name_parts`] gives
/// them, or, for a name written with its argument list (`DROP FUNCTION
/// s1."MyFn"(INT)`), those of the name before the list.
pub(crate) fn routine_name_parts(
    source: &str,
    name: &crate::ast::AstObjectRef,
) -> Option<(Option<String>, Option<String>, String)> {
    written_name_parts(source, name)
        .or_else(|| text_name_parts(name_before_argument_list(slice_span(source, name.span)?)?))
}

/// The `[[db.]schema.]name` parts the text `written` spells, each as
/// written ([`relation_written_parts`]); `None` for none or more than three.
pub(crate) fn text_name_parts(written: &str) -> Option<(Option<String>, Option<String>, String)> {
    match crate::ir::lower_ddl::relation_parts_written(written).as_slice() {
        [n] => Some((None, None, n.clone())),
        [s, n] => Some((None, Some(s.clone()), n.clone())),
        [d, s, n] => Some((Some(d.clone()), Some(s.clone()), n.clone())),
        _ => None,
    }
}

/// The `[[db.]schema.]name` parts `name` spells, each as written, or, for
/// `IDENTIFIER(…)`, as the text it names writes them
/// ([`identifier_string_name`]); `None` where the parser did not read it as
/// one to three parts (a list of names, an argument list, `IDENTIFIER(…)` of
/// any other argument, an omitted part).
pub(crate) fn written_name_parts(
    source: &str,
    name: &crate::ast::AstObjectRef,
) -> Option<(Option<String>, Option<String>, String)> {
    let written: Vec<String> = match name.parts.as_ref() {
        Some(parts) => parts
            .iter()
            .map(|part| slice_span(source, part.as_ref()?.span()).map(str::to_string))
            .collect::<Option<_>>()?,
        None => {
            let value = match name.identifier_arg.as_ref() {
                Some(argument) => identifier_argument_text(source, argument)?,
                // An `IDENTIFIER('…')` read without its argument.
                None => identifier_string_name(slice_span(source, name.span)?)?,
            };
            let parts = crate::ir::lower::split_dotted_name(&value);
            if parts.iter().any(String::is_empty) {
                return None;
            }
            parts
        }
    };
    let written: Vec<String> = relation_written_parts(written.into_iter().map(Some).collect())
        .into_iter()
        .flatten()
        .collect();
    match written.as_slice() {
        [n] => Some((None, None, (*n).to_string())),
        [s, n] => Some((None, Some((*s).to_string()), (*n).to_string())),
        [d, s, n] => Some((
            Some((*d).to_string()),
            Some((*s).to_string()),
            (*n).to_string(),
        )),
        _ => None,
    }
}

#[cfg(test)]
mod dotted_name_tests {
    use super::*;

    fn parts(raw: &str) -> Vec<&str> {
        dotted_name_segments(raw, 0)
            .into_iter()
            .map(|segment| slice_span(raw, segment).unwrap_or(""))
            .collect()
    }

    /// A dot inside any quoting splits nothing; `]]` stays inside brackets.
    #[test]
    fn a_dotted_name_splits_only_at_dots_outside_quotes() {
        assert_eq!(parts("db.sch.t"), ["db", "sch", "t"]);
        assert_eq!(parts(r#""a.b".t"#), [r#""a.b""#, "t"]);
        assert_eq!(parts("`a.b`.t"), ["`a.b`", "t"]);
        assert_eq!(parts("[a.b].t"), ["[a.b]", "t"]);
        assert_eq!(parts("[a]].b].t"), ["[a]].b]", "t"]);
        assert_eq!(parts("db..t"), ["db", "", "t"]);
        assert_eq!(parts("db."), ["db"]);
    }

    /// A relation's parts are read once: a BigQuery path is its parts, a
    /// quoted name holding dots elsewhere is one part, an omitted part
    /// stays omitted.
    #[test]
    fn a_relations_parts_follow_the_dialects_path_rule() {
        let written = |parts: &[Option<&str>]| -> Vec<Option<String>> {
            parts.iter().map(|part| part.map(str::to_string)).collect()
        };
        {
            let _bigquery = crate::ir::normalize::set_normalization_dialect("bigquery");
            assert_eq!(
                relation_written_parts(written(&[Some("`p.d.t`")])),
                written(&[Some("`p`"), Some("`d`"), Some("`t`")])
            );
        }
        let _snowflake = crate::ir::normalize::default_folding();
        assert_eq!(
            relation_written_parts(written(&[Some(r#""p.d.t""#)])),
            written(&[Some(r#""p.d.t""#)])
        );
        assert_eq!(
            relation_written_parts(written(&[Some("db"), None, Some("t")])),
            written(&[Some("db"), None, Some("t")])
        );
    }
}
