// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! SnowSQL client-driver variable substitution (`&var` / `&{var}`).
//!
//! SnowSQL — the Snowflake CLI — performs textual variable substitution on SQL
//! text before the server parses it. This module replays that substitution as a
//! line-preserving pre-pass so `&var`-parameterized scripts reach the parser as
//! ordinary SQL. It is gated on [`Dialect::supports_snowsql_substitution`] and
//! runs only inside the analysis render seam — never the formatter, which must
//! echo the original `&var` text byte-for-byte.
//!
//! Recognition is **driven by the lexer**, not by raw line text. The source is
//! tokenized first, and the substitution pass consults the lexer's authoritative
//! trivia/token boundaries:
//! - Comments are `Trivia` (never tokens), so a `!define` sitting inside a
//!   `/* … */` block comment produces no `!`/`define` tokens and is correctly
//!   ignored — both for intent detection and for harvesting.
//! - String literals are `Literal(String)` tokens. SnowSQL substitutes `&var`
//!   inside strings (documented), so the pass does too — but a `!define` that
//!   happens to fall inside a multi-line string is not treated as a directive.
//!
//! Spec (docs.snowflake.com/en/user-guide/snowsql-use):
//! - `&name` / `&{name}` reference a variable; name chars are `[0-9a-zA-Z_]`,
//!   case-insensitive. The braced form disambiguates a name followed by a name
//!   char (`&{a}_b`).
//! - `!define name=value` defines a variable (no spaces around `=`).
//! - `&&` is an escaped literal `&`.
//!
//! Two behaviors here are this engine's documented inference (the docs define
//! neither): activation requires an explicit intent marker (`!define`, `!set
//! variable_substitution`, or a braced `&{...}`) in real code/string — bare
//! `&name` alone does not activate, because it collides with URL query strings
//! and bitwise operands; and a `&` is a reference only when immediately followed
//! by a name char or `{`.
//!
//! Limitation (inherent to SnowSQL): once substitution is active, an unspaced
//! `a&b` whose `b` matches a *defined* variable is substituted greedily, exactly
//! as SnowSQL does — `&` is resolved textually before the lexer sees it. This is
//! irreducible: the same `prefix&name` shape is also legitimate value
//! concatenation (`tbl_&env`), so skipping it to protect bitwise SQL would break
//! concatenation instead. The blast radius is bounded two ways: spaced `a & b`
//! never substitutes (the adjacency rule), and only *defined* names resolve — an
//! undefined `&b` becomes an identifier placeholder, never a corrupted value.
//!
//! ## Snowflake CLI `<% var %>` (STANDARD templating)
//!
//! The newer Snowflake CLI (`snow`) additionally supports a `<% name %>`
//! placeholder (Jinja-delimited; enabled by default alongside the legacy `&var`).
//! Values come from the same `-D` / project `env` sources the analyzer already
//! loads as a [`VariableContext`], so this pre-pass recognizes the two documented
//! client forms — `<% name %>` and the project-context `<% ctx.env.name %>` /
//! `<% env.name %>` — on a single line and substitutes the value (or an identifier
//! placeholder when undefined, exactly like `&var`). Any other inner expression
//! (a filter, a multi-line body) is left verbatim, degrading to today's unparsed
//! behavior rather than guessing. `<%` is unambiguous — unlike bare `&`, it can't
//! be valid Snowflake SQL — so its presence alone is intent. Name resolution
//! shares the `&var` map and is therefore case-insensitive here (the CLI is
//! case-sensitive): a lenient simplification that only ever resolves more.

use crate::dialect::{Dialect, DialectRef};
use crate::template::context::value_to_string;
use crate::template::records::{PlaceholderKind, PlaceholderRecord};
use crate::template::spans::{comment_spans, in_spans, is_name_byte, string_spans, utf8_len};
use crate::template::VariableContext;
use serde_json::Value;
use std::borrow::Cow;
use std::collections::HashMap;

/// Output of [`preprocess`]: the (possibly rewritten) SQL plus one placeholder
/// record per undefined `&var`. The records feed the analyzer's placeholder
/// stats so unresolved variables lower analysis confidence, exactly like an
/// unresolved Jinja reference.
pub struct SnowsqlPrep<'a> {
    pub sql: Cow<'a, str>,
    pub placeholders: Vec<PlaceholderRecord>,
}

impl<'a> SnowsqlPrep<'a> {
    fn borrowed(src: &'a str) -> Self {
        Self {
            sql: Cow::Borrowed(src),
            placeholders: Vec::new(),
        }
    }
}

/// ASCII case-insensitive prefix test.
fn starts_with_ci(s: &str, prefix: &str) -> bool {
    s.len() >= prefix.len() && s.as_bytes()[..prefix.len()].eq_ignore_ascii_case(prefix.as_bytes())
}

/// A directive word (`!define`/`!set`) must be followed by whitespace or end of
/// input, so `!definex` is not `!define`.
fn is_directive_word(rest: &str, word: &str) -> bool {
    starts_with_ci(rest, word)
        && rest[word.len()..]
            .chars()
            .next()
            .is_none_or(|c| c.is_whitespace())
}

/// Cheap substring pre-filter — avoids tokenizing files with no marker at all.
/// May be a false positive (e.g. a marker that turns out to be inside a
/// comment); [`has_intent`] refines it after tokenization.
fn cheap_has_marker(src: &str) -> bool {
    if src.contains("&{") || src.contains("<%") {
        return true;
    }
    for line in src.lines() {
        let t = line.trim_start();
        if starts_with_ci(t, "!define") {
            return true;
        }
        if starts_with_ci(t, "!set") && t.to_ascii_lowercase().contains("variable_substitution") {
            return true;
        }
    }
    false
}

/// Region-aware intent: a substitution marker in real code/string (not a
/// comment). A braced `&{` counts in code or string; `!define` / `!set
/// variable_substitution` count only at a code line-start outside strings.
fn has_intent(
    src: &str,
    comments: &[(usize, usize)],
    strings: &[(usize, usize)],
    ext: Option<&VariableContext>,
) -> bool {
    let bytes = src.as_bytes();
    let mut i = 0;
    while i + 1 < bytes.len() {
        if !in_spans(i, comments) {
            // A braced `&{…}` (SnowSQL) or a `<%…%>` (Snowflake CLI) outside a
            // comment is intent. `<%` is unambiguous, so its mere presence
            // activates; a bare `&name` still needs the ext-resolution check below.
            if bytes[i] == b'&' && bytes[i + 1] == b'{' {
                return true;
            }
            if bytes[i] == b'<' && bytes[i + 1] == b'%' {
                return true;
            }
        }
        i += 1;
    }
    let mut offset = 0;
    for line in src.split_inclusive('\n') {
        let first = offset + (line.len() - line.trim_start().len());
        let t = line.trim_start();
        if !in_spans(first, comments) && !in_spans(first, strings) {
            if is_directive_word(t, "!define") {
                return true;
            }
            if is_directive_word(t, "!set")
                && t.to_ascii_lowercase().contains("variable_substitution")
            {
                return true;
            }
        }
        offset += line.len();
    }
    // A `&ref` whose name an externally-provided value resolves is itself intent.
    if let Some(ctx) = ext {
        if !ctx.variables().is_empty() {
            let mut i = 0;
            while i + 1 < bytes.len() {
                if bytes[i] == b'&' {
                    if bytes[i + 1] == b'&' {
                        i += 2; // escaped `&&`, not a reference
                        continue;
                    }
                    if !in_spans(i, comments) {
                        let nstart = if bytes[i + 1] == b'{' { i + 2 } else { i + 1 };
                        let nend = read_name_end(bytes, nstart);
                        if nend > nstart && ext_lookup(ctx, &src[nstart..nend]).is_some() {
                            return true;
                        }
                    }
                }
                i += 1;
            }
        }
    }
    false
}

/// Replay SnowSQL `&var` substitution as a line-preserving pre-pass when the
/// dialect's client driver performs it and the source declares intent. Returns
/// `Borrowed` when nothing is rewritten.
///
/// `ext_vars` carries externally-provided values (the `--var` / `VariableContext`
/// the analyzer already loads — the analog of SnowSQL's `-D` / `[variables]`):
/// an in-file `!define` overrides them, and a provided value that matches a `&ref`
/// is itself activation intent, so externally-parameterized scripts with no
/// in-file marker still resolve.
pub fn preprocess<'a>(
    src: &'a str,
    dialect: &Option<DialectRef>,
    ext_vars: Option<&VariableContext>,
) -> SnowsqlPrep<'a> {
    let snow;
    let d: &dyn Dialect = match dialect {
        Some(d) if d.supports_snowsql_substitution() => d.as_ref(),
        Some(_) => return SnowsqlPrep::borrowed(src),
        None => {
            // The no-dialect path is the documented Snowflake default.
            snow = crate::dialect::snowflake();
            snow.as_ref()
        }
    };
    let has_ext = ext_vars.is_some_and(|c| !c.variables().is_empty());
    if !(cheap_has_marker(src) || has_ext && src.contains('&')) {
        return SnowsqlPrep::borrowed(src);
    }
    let lex = crate::lexer::tokenize_with_dialect(src, d);
    let comments = comment_spans(&lex.tokens);
    let strings = string_spans(&lex.tokens);
    if !has_intent(src, &comments, &strings, ext_vars) {
        return SnowsqlPrep::borrowed(src);
    }
    let (sql, placeholders) = substitute(src, &comments, &strings, ext_vars);
    SnowsqlPrep {
        sql: Cow::Owned(sql),
        placeholders,
    }
}

/// Line-preserving substitution pass. Walks `src` with the lexer-derived comment
/// and string spans: comment regions are copied verbatim (no substitution, no
/// directive harvesting), `&var` is substituted everywhere else (code and
/// strings, per spec), and `!define`/`!set` are recognized only at a code
/// line-start outside strings.
fn substitute(
    src: &str,
    comments: &[(usize, usize)],
    strings: &[(usize, usize)],
    ext: Option<&VariableContext>,
) -> (String, Vec<PlaceholderRecord>) {
    let bytes = src.as_bytes();
    let len = bytes.len();
    let mut out = String::with_capacity(len);
    let mut vars: HashMap<String, String> = HashMap::new();
    // Seed with externally-provided values; an in-file `!define` encountered
    // during the pass overrides them (SnowSQL's `-D` is available from the start,
    // a later REPL `!define` wins).
    if let Some(ctx) = ext {
        for (k, v) in ctx.variables() {
            vars.insert(k.to_ascii_lowercase(), value_to_string(v));
        }
    }
    let mut placeholders: Vec<PlaceholderRecord> = Vec::new();
    let mut p = 0;
    let mut ci = 0; // comment-span cursor (monotonic)
    let mut si = 0; // string-span cursor (monotonic)
    let mut at_line_start = true;
    while p < len {
        // Comment region: copy verbatim.
        while ci < comments.len() && comments[ci].1 <= p {
            ci += 1;
        }
        if ci < comments.len() && comments[ci].0 <= p {
            let end = comments[ci].1;
            out.push_str(&src[p..end]);
            p = end;
            at_line_start = false;
            continue;
        }
        let b = bytes[p];
        if b == b'\n' {
            out.push('\n');
            p += 1;
            at_line_start = true;
            continue;
        }
        if b == b'\r' {
            out.push('\r');
            p += 1;
            continue;
        }
        if b == b' ' || b == b'\t' {
            out.push(b as char);
            p += 1;
            continue;
        }
        while si < strings.len() && strings[si].1 <= p {
            si += 1;
        }
        let in_string = si < strings.len() && strings[si].0 <= p;
        // `!define` / `!set` directive — only at a code line-start outside strings.
        if at_line_start && !in_string {
            let rest = &src[p..];
            let is_define = is_directive_word(rest, "!define");
            if is_define || is_directive_word(rest, "!set") {
                let nl = src[p..].find('\n').map_or(len, |k| p + k);
                // Clip at a trailing comment so it isn't absorbed into the value.
                let cstart = comments.get(ci).map_or(len, |&(s, _)| s);
                let end = nl.min(cstart);
                if is_define {
                    if let Some((name, value)) = parse_define(src[p..end].trim_end()) {
                        vars.insert(name.to_ascii_lowercase(), value.to_string());
                    }
                }
                // Blank the directive, preserving byte count (no newline in range).
                for _ in p..end {
                    out.push(' ');
                }
                p = end;
                at_line_start = false;
                continue;
            }
        }
        at_line_start = false;
        // Snowflake CLI `<% name %>` / `<% ctx.env.name %>` (STANDARD templating).
        if b == b'<' && p + 1 < len && bytes[p + 1] == b'%' {
            if let Some((name, close_end)) = read_snow_template(src, p) {
                emit_var(name, &vars, &mut out, &mut placeholders);
                p = close_end;
                continue;
            }
        }
        if b == b'&' {
            // Escaped `&&` → literal `&`.
            if p + 1 < len && bytes[p + 1] == b'&' {
                out.push('&');
                p += 2;
                continue;
            }
            // Braced `&{name}`.
            if p + 1 < len && bytes[p + 1] == b'{' {
                if let Some(close) = read_braced_close(bytes, p + 2) {
                    emit_var(&src[p + 2..close], &vars, &mut out, &mut placeholders);
                    p = close + 1;
                    continue;
                }
                out.push('&');
                p += 1;
                continue;
            }
            // Unbraced `&name`.
            let name_end = read_name_end(bytes, p + 1);
            if name_end > p + 1 {
                emit_var(&src[p + 1..name_end], &vars, &mut out, &mut placeholders);
                p = name_end;
                continue;
            }
            // Bare `&` — leave as-is (bitwise/operator).
            out.push('&');
            p += 1;
            continue;
        }
        // Ordinary character — copy one UTF-8 scalar verbatim.
        let cl = utf8_len(b);
        out.push_str(&src[p..p + cl]);
        p += cl;
    }
    (out, placeholders)
}

/// Parse `!define name=value` (no spaces around `=`, per spec). `line` already
/// starts (case-insensitively) with `!define`. Returns `None` if malformed.
fn parse_define(line: &str) -> Option<(&str, &str)> {
    let rest = line["!define".len()..].trim_start();
    let eq = rest.find('=')?;
    let name = rest[..eq].trim_end();
    if name.is_empty() || !name.bytes().all(is_name_byte) {
        return None;
    }
    let value = rest[eq + 1..].trim_end();
    Some((name, value))
}

/// If `bytes[start..]` is `[0-9a-zA-Z_]+}`, return the index of the `}`.
fn read_braced_close(bytes: &[u8], start: usize) -> Option<usize> {
    let mut j = start;
    while j < bytes.len() && is_name_byte(bytes[j]) {
        j += 1;
    }
    if j > start && j < bytes.len() && bytes[j] == b'}' {
        Some(j)
    } else {
        None
    }
}

/// Index past the maximal `[0-9a-zA-Z_]` run starting at `start`.
fn read_name_end(bytes: &[u8], start: usize) -> usize {
    let mut j = start;
    while j < bytes.len() && is_name_byte(bytes[j]) {
        j += 1;
    }
    j
}

/// If `src[start..]` (with `src[start..start+2] == "<%"`) begins a single-line
/// Snowflake CLI `<% … %>` template whose body is one of the documented client
/// forms — `<% name %>` or the project-context `<% ctx.env.name %>` /
/// `<% env.name %>` — return the bare variable identifier and the byte index just
/// past the closing `%>`. Returns `None` for a multi-line region or any other
/// inner expression (a filter, a path), which is then left verbatim rather than
/// guessed at.
fn read_snow_template(src: &str, start: usize) -> Option<(&str, usize)> {
    let bytes = src.as_bytes();
    let open = start + 2; // past `<%`
    let mut j = open;
    while j + 1 < bytes.len() {
        if bytes[j] == b'\n' {
            return None; // multi-line — not a client var template
        }
        if bytes[j] == b'%' && bytes[j + 1] == b'>' {
            let inner = src[open..j].trim();
            // Jinja whitespace-control markers `<%- … -%>`.
            let inner = inner.strip_prefix('-').unwrap_or(inner).trim_start();
            let inner = inner.strip_suffix('-').unwrap_or(inner).trim_end();
            // Documented project-context prefix.
            let name = inner
                .strip_prefix("ctx.env.")
                .or_else(|| inner.strip_prefix("env."))
                .unwrap_or(inner);
            let nb = name.as_bytes();
            if !nb.is_empty() && !nb[0].is_ascii_digit() && nb.iter().all(|&b| is_name_byte(b)) {
                return Some((name, j + 2));
            }
            return None; // e.g. a filter/expression — leave verbatim
        }
        j += 1;
    }
    None
}

/// Case-insensitive lookup in the external variable context (SnowSQL variable
/// names are case-insensitive; the `--var` keys may be any case).
fn ext_lookup<'a>(ctx: &'a VariableContext, name: &str) -> Option<&'a Value> {
    ctx.get(name).or_else(|| {
        ctx.variables()
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v)
    })
}

/// Emit the value of `name` (case-insensitive) if defined; otherwise emit the
/// bare name as an identifier placeholder (so the SQL still parses) and record a
/// placeholder for it so the unresolved variable lowers analysis confidence —
/// the same treatment an unresolved Jinja ref gets.
fn emit_var(
    name: &str,
    vars: &HashMap<String, String>,
    out: &mut String,
    placeholders: &mut Vec<PlaceholderRecord>,
) {
    if let Some(value) = vars.get(&name.to_ascii_lowercase()) {
        out.push_str(value);
        return;
    }
    let start = out.len();
    out.push_str(name);
    let id = placeholders.len() as u32;
    placeholders.push(PlaceholderRecord {
        placeholder_id: id,
        kind: PlaceholderKind::Var,
        origin: name.to_string(),
        source_position: start,
        render_start: start,
        render_end: out.len(),
        placeholder_text: name.to_string(),
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dialect::dialect_from_name;

    fn snow() -> Option<DialectRef> {
        dialect_from_name("snowflake")
    }

    fn run(src: &str) -> String {
        preprocess(src, &snow(), None).sql.into_owned()
    }

    fn line_count(s: &str) -> usize {
        s.bytes().filter(|&b| b == b'\n').count()
    }

    #[test]
    fn define_then_reference_substitutes_value() {
        let out = run("!define tablename=CUSTOMERS\nSELECT * FROM &tablename;\n");
        assert!(out.contains("FROM CUSTOMERS;"), "{out}");
        assert!(!out.contains("!define"), "meta line not blanked: {out}");
    }

    #[test]
    fn braced_form_disambiguates_trailing_name_char() {
        let out = run("!define snowshell=bash\nSELECT '&{snowshell}_shell';\n");
        assert!(out.contains("'bash_shell'"), "{out}");
    }

    #[test]
    fn double_ampersand_is_escaped_literal() {
        let out = run("!set variable_substitution=true\nSELECT '&&notvar';\n");
        assert!(out.contains("'&notvar'"), "{out}");
    }

    #[test]
    fn undefined_reference_becomes_identifier_placeholder() {
        let out = run("!define a=1\nSELECT &b;\n");
        assert!(out.contains("SELECT b;"), "{out}");
    }

    #[test]
    fn bare_ampersand_with_space_is_left_alone() {
        let out = run("!define a=1\nSELECT x & y;\n");
        assert!(out.contains("x & y"), "{out}");
    }

    #[test]
    fn line_count_is_preserved() {
        let src = "!define t=C\nSELECT &t\nFROM x\nWHERE 1=1;\n";
        let out = run(src);
        assert_eq!(line_count(src), line_count(&out), "line count drift: {out}");
    }

    #[test]
    fn no_intent_marker_leaves_source_untouched() {
        let src = "SELECT 'http://x?a=1&b=2' AS u;\n";
        let out = preprocess(src, &snow(), None);
        assert!(
            matches!(out.sql, Cow::Borrowed(_)),
            "rewrote a no-marker file"
        );
        assert_eq!(out.sql, src);
    }

    #[test]
    fn non_snowsql_dialect_is_not_substituted() {
        let pg = dialect_from_name("postgresql");
        let src = "!define t=C\nSELECT &t;\n";
        let out = preprocess(src, &pg, None);
        assert!(
            matches!(out.sql, Cow::Borrowed(_)),
            "substituted under postgresql"
        );
    }

    #[test]
    fn no_dialect_defaults_to_snowflake() {
        let src = "!define t=CUSTOMERS\nSELECT * FROM &t;\n";
        let out = preprocess(src, &None, None);
        assert!(out.sql.contains("FROM CUSTOMERS"), "{}", out.sql);
    }

    #[test]
    fn later_definition_wins_sequentially() {
        let out = run("!define t=A\nSELECT &t;\n!define t=B\nSELECT &t;\n");
        assert!(out.contains("SELECT A;"), "{out}");
        assert!(out.contains("SELECT B;"), "{out}");
    }

    // --- trivia-awareness ---

    #[test]
    fn define_inside_block_comment_is_ignored() {
        // A real `!define x=USERS` in code must win; the `!define x=PUBLIC`
        // commented out in a /* */ block must NOT be harvested.
        let out = run("!define x=USERS\n/*\n!define x=PUBLIC\n*/\nGRANT SELECT ON t TO &x;\n");
        assert!(out.contains("TO USERS"), "code define should win: {out}");
        assert!(!out.contains("TO PUBLIC"), "comment define leaked: {out}");
    }

    #[test]
    fn ampersand_inside_line_comment_is_not_substituted() {
        // `&t` inside a `--` comment is trivia and must be left verbatim.
        let out = run("!define t=USERS\nSELECT 1; -- see &t here\n");
        assert!(
            out.contains("-- see &t here"),
            "comment was rewritten: {out}"
        );
    }

    #[test]
    fn braced_marker_only_in_comment_does_not_activate() {
        // The only `&{` is inside a block comment → no real intent → no rewrite.
        let src = "/* &{x} */\nSELECT 'a&b' AS u;\n";
        let out = preprocess(src, &snow(), None);
        assert!(
            matches!(out.sql, Cow::Borrowed(_)),
            "activated on a commented marker: {}",
            out.sql
        );
    }

    #[test]
    fn define_inside_string_is_not_a_directive() {
        // A line starting with `!define` inside a multi-line string literal must
        // not be harvested; the real define drives substitution.
        let out = run("!define x=USERS\nSELECT '\n!define x=PUBLIC\n' AS body, &x AS who;\n");
        assert!(
            out.contains("USERS AS who"),
            "real define should drive &x: {out}"
        );
        assert!(
            !out.contains("PUBLIC AS who"),
            "string define leaked: {out}"
        );
    }

    // --- external variable resolution (--var / VariableContext) ---

    #[test]
    fn external_var_resolves_and_activates_without_marker() {
        let mut ctx = VariableContext::new();
        ctx.load_from_cli_args(&["db=PROD".to_string()])
            .expect("load var");
        // Bare `&db`, no in-file marker — activated by the provided external var.
        let out = preprocess("SELECT * FROM &db.t;\n", &snow(), Some(&ctx))
            .sql
            .into_owned();
        assert!(out.contains("FROM PROD.t"), "{out}");
    }

    #[test]
    fn in_file_define_overrides_external_var() {
        let mut ctx = VariableContext::new();
        ctx.load_from_cli_args(&["t=EXTERNAL".to_string()])
            .expect("load var");
        let out = preprocess("!define t=INFILE\nSELECT &t;\n", &snow(), Some(&ctx))
            .sql
            .into_owned();
        assert!(out.contains("SELECT INFILE"), "{out}");
    }

    #[test]
    fn external_var_lookup_is_case_insensitive() {
        let mut ctx = VariableContext::new();
        ctx.load_from_cli_args(&["db=PROD".to_string()])
            .expect("load var");
        let out = preprocess(
            "!set variable_substitution=true\nSELECT &DB;\n",
            &snow(),
            Some(&ctx),
        )
        .sql
        .into_owned();
        assert!(out.contains("SELECT PROD"), "{out}");
    }

    // --- placeholder records for undefined vars (confidence signal) ---

    #[test]
    fn undefined_var_records_a_placeholder() {
        let prep = preprocess("!define a=1\nDROP TABLE &ghost;\n", &snow(), None);
        assert_eq!(
            prep.placeholders.len(),
            1,
            "expected one placeholder for &ghost"
        );
        let ph = &prep.placeholders[0];
        assert_eq!(ph.origin, "ghost");
        assert!(matches!(ph.kind, PlaceholderKind::Var));
        // The record points at the bare name in the substituted SQL.
        assert_eq!(&prep.sql[ph.render_start..ph.render_end], "ghost");
    }

    #[test]
    fn resolved_vars_record_no_placeholder() {
        let prep = preprocess("!define t=USERS\nDROP TABLE &t;\n", &snow(), None);
        assert!(
            prep.placeholders.is_empty(),
            "a defined var must not be a placeholder"
        );
    }

    // --- Snowflake CLI `<% var %>` (STANDARD templating) ---

    fn ctx_with(pairs: &[&str]) -> VariableContext {
        let mut ctx = VariableContext::new();
        ctx.load_from_cli_args(&pairs.iter().map(|s| s.to_string()).collect::<Vec<_>>())
            .expect("load var");
        ctx
    }

    fn run_ext(src: &str, ctx: &VariableContext) -> String {
        preprocess(src, &snow(), Some(ctx)).sql.into_owned()
    }

    #[test]
    fn snow_template_resolves_external_var() {
        let out = run_ext(
            "SELECT * FROM <% database %>.t;\n",
            &ctx_with(&["database=PROD"]),
        );
        assert!(out.contains("FROM PROD.t"), "{out}");
    }

    #[test]
    fn snow_template_ctx_env_prefix_resolves() {
        let out = run_ext(
            "GRANT USAGE ON DATABASE d TO <% ctx.env.role %>;\n",
            &ctx_with(&["role=ENG"]),
        );
        assert!(out.contains("TO ENG;"), "{out}");
    }

    #[test]
    fn snow_template_no_inner_whitespace_resolves() {
        let out = run_ext(
            "SELECT * FROM t ORDER BY <%col%>;\n",
            &ctx_with(&["col=Country"]),
        );
        assert!(out.contains("ORDER BY Country;"), "{out}");
    }

    #[test]
    fn snow_template_activates_without_ampersand_marker() {
        // A pure `<% %>` script (no `&var`, no `!define`) activates on `<%` alone.
        let out = run_ext("SELECT * FROM <% t %>;\n", &ctx_with(&["t=CUSTOMERS"]));
        assert!(out.contains("FROM CUSTOMERS;"), "{out}");
    }

    #[test]
    fn snow_template_undefined_becomes_placeholder() {
        let prep = preprocess("SELECT * FROM <% missing %>;\n", &snow(), None);
        assert!(prep.sql.contains("FROM missing;"), "{}", prep.sql);
        assert_eq!(prep.placeholders.len(), 1, "expected one placeholder");
        assert_eq!(prep.placeholders[0].origin, "missing");
    }

    #[test]
    fn snow_template_line_count_preserved() {
        let src = "SELECT <% t %>\nFROM x\nWHERE 1=1;\n";
        let out = run_ext(src, &ctx_with(&["t=C"]));
        assert_eq!(line_count(src), line_count(&out), "line drift: {out}");
    }

    #[test]
    fn snow_template_in_comment_left_verbatim() {
        // The code `<% t %>` resolves; the one inside the `--` comment does not.
        let out = run_ext(
            "SELECT * FROM <% t %>; -- from <% t %>\n",
            &ctx_with(&["t=CUSTOMERS"]),
        );
        assert!(
            out.contains("FROM CUSTOMERS;"),
            "code template not resolved: {out}"
        );
        assert!(
            out.contains("-- from <% t %>"),
            "comment template was resolved: {out}"
        );
    }

    #[test]
    fn snow_template_multiline_left_verbatim() {
        // A `<% %>` spanning a newline is not a client var template — leave it.
        let src = "SELECT <% t\n%> FROM x;\n";
        let out = run_ext(src, &ctx_with(&["t=C"]));
        assert!(
            out.contains("<% t\n%>"),
            "multi-line template substituted: {out}"
        );
    }

    #[test]
    fn snow_template_filter_expression_left_verbatim() {
        // A non-identifier body (a Jinja filter) is out of the client-var scope.
        let src = "SELECT <% name | upper %>;\n";
        let out = run_ext(src, &ctx_with(&["name=x"]));
        assert!(
            out.contains("<% name | upper %>"),
            "filter body substituted: {out}"
        );
    }

    #[test]
    fn snow_template_gated_to_snowflake() {
        let pg = dialect_from_name("postgresql");
        let out = preprocess("SELECT <% t %>;\n", &pg, Some(&ctx_with(&["t=C"])));
        assert!(
            matches!(out.sql, Cow::Borrowed(_)),
            "substituted under pg: {}",
            out.sql
        );
    }
}
