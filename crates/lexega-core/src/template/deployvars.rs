// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Deployment-pipeline variable substitution (`${VAR}` and friends).
//!
//! CI deployment tooling commonly rewrites SQL text before it reaches the
//! warehouse — envsubst-style `${NAME}`, sqlcmd `$(NAME)`, or a homegrown
//! replacement with shop-specific delimiters. This module replays that
//! substitution as a line-preserving pre-pass so parameterized scripts reach
//! the parser as ordinary SQL, with resolved names flowing into the same facts
//! policy predicates already match on. It runs only inside the analysis render
//! seam — never the formatter, which must echo the marker text byte-for-byte.
//!
//! Unlike the SnowSQL pass this is **not dialect-gated**: any dialect can be
//! deployed through a substituting pipeline. The dialect is used only to
//! tokenize for the lexer's authoritative comment/string boundaries.
//!
//! Degradation contract for an **unresolved** marker:
//! - in code, it becomes the bare logical name (`${ELT_DB}` → identifier
//!   `ELT_DB`) plus a placeholder record — analysis proceeds keyed on the
//!   stable logical identity with lowered confidence, the same treatment an
//!   unresolved SnowSQL `&var` or Jinja ref gets. Without this pass the text
//!   mis-parses: `$` lexes as an identifier, so `USE ${ELT_DB}` would name a
//!   database `$` and leave `{ELT_DB}` as opaque content.
//! - inside a string literal, it is left **verbatim** (rewriting literal
//!   content would corrupt values; the text already parses) but still
//!   recorded, so confidence reflects it.
//!
//! A **resolved** marker substitutes everywhere, code and strings —
//! deployment-tool substitution is textual, exactly like the tools it replays.
//! Markers inside comments are never touched or recorded.
//!
//! Recognition is deliberately narrow: `prefix` + identifier
//! (`[A-Za-z_][A-Za-z0-9_]*`) + `suffix`, nothing else. `${}`, `${1x}`,
//! `${a b}` are not markers and are copied verbatim — a shop whose scheme
//! allows richer expressions renders before analysis instead.

use crate::dialect::{Dialect, DialectRef};
use crate::template::context::value_to_string;
use crate::template::records::{PlaceholderKind, PlaceholderRecord};
use crate::template::spans::{comment_spans, is_name_byte, string_spans, utf8_len};
use crate::template::VariableContext;
use std::borrow::Cow;

/// One recognized delimiter pair, e.g. `${` / `}`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubstitutionSyntax {
    pub prefix: String,
    pub suffix: String,
}

impl SubstitutionSyntax {
    /// Validated custom delimiter pair. Delimiters must be non-empty and free
    /// of whitespace — a whitespace delimiter would break the line-preserving
    /// invariant the source map depends on.
    pub fn new(
        prefix: impl Into<String>,
        suffix: impl Into<String>,
    ) -> Result<Self, SubstitutionConfigError> {
        let prefix = prefix.into();
        let suffix = suffix.into();
        if prefix.is_empty() || suffix.is_empty() {
            return Err(SubstitutionConfigError::EmptyDelimiter);
        }
        if let Some(d) = [&prefix, &suffix]
            .iter()
            .find(|d| d.chars().any(char::is_whitespace))
        {
            return Err(SubstitutionConfigError::WhitespaceDelimiter((*d).clone()));
        }
        Ok(Self { prefix, suffix })
    }

    /// `${name}` — shell/envsubst, Liquibase, Flyway.
    pub fn dollar_brace() -> Self {
        Self {
            prefix: "${".to_string(),
            suffix: "}".to_string(),
        }
    }

    /// `$(name)` — sqlcmd scripting variables.
    pub fn dollar_paren() -> Self {
        Self {
            prefix: "$(".to_string(),
            suffix: ")".to_string(),
        }
    }

    /// Resolve a preset name (the config `presets` vocabulary).
    pub fn from_preset_name(name: &str) -> Result<Self, SubstitutionConfigError> {
        match name {
            "dollar-brace" => Ok(Self::dollar_brace()),
            "dollar-paren" => Ok(Self::dollar_paren()),
            other => Err(SubstitutionConfigError::UnknownPreset(other.to_string())),
        }
    }

    /// Resolve a `--var-syntax` value: a preset name, or a marker shape — the
    /// delimiters written around the word `NAME`, e.g. `%%NAME%%`.
    pub fn from_cli_value(value: &str) -> Result<Self, SubstitutionConfigError> {
        if let Ok(preset) = Self::from_preset_name(value) {
            return Ok(preset);
        }
        match value.split_once(MARKER_SHAPE_NAME) {
            Some((prefix, suffix)) if !suffix.contains(MARKER_SHAPE_NAME) => {
                Self::new(prefix, suffix)
            }
            Some(_) | None => Err(SubstitutionConfigError::UnknownSyntax(value.to_string())),
        }
    }
}

/// The word that stands for the variable name in a marker shape.
const MARKER_SHAPE_NAME: &str = "NAME";

/// The set of marker syntaxes the pre-pass recognizes. `Default` is
/// `${name}` alone; an empty set disables the pass entirely.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubstitutionConfig {
    pub syntaxes: Vec<SubstitutionSyntax>,
}

impl Default for SubstitutionConfig {
    fn default() -> Self {
        Self {
            syntaxes: vec![SubstitutionSyntax::dollar_brace()],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubstitutionConfigError {
    UnknownPreset(String),
    /// Neither a preset name nor a marker shape.
    UnknownSyntax(String),
    EmptyDelimiter,
    WhitespaceDelimiter(String),
}

impl std::fmt::Display for SubstitutionConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SubstitutionConfigError::UnknownPreset(name) => write!(
                f,
                "unknown variable syntax preset '{name}' (known presets: dollar-brace, dollar-paren)"
            ),
            SubstitutionConfigError::UnknownSyntax(value) => write!(
                f,
                "unknown variable syntax '{value}' (expected a preset — dollar-brace, dollar-paren — or a marker shape with the word NAME between its delimiters, such as %%NAME%%)"
            ),
            SubstitutionConfigError::EmptyDelimiter => {
                write!(f, "variable syntax delimiters must be non-empty")
            }
            SubstitutionConfigError::WhitespaceDelimiter(d) => write!(
                f,
                "variable syntax delimiter '{d}' must not contain whitespace"
            ),
        }
    }
}

impl std::error::Error for SubstitutionConfigError {}

/// Output of [`preprocess`]: the (possibly rewritten) SQL plus one placeholder
/// record per unresolved marker. The records feed the analyzer's placeholder
/// stats so unresolved variables lower analysis confidence, exactly like an
/// unresolved SnowSQL `&var` or Jinja reference. When `sql` is `Borrowed`, any
/// record offsets index the input text itself (unresolved-in-string markers
/// are recorded without rewriting).
pub struct DeployVarsPrep<'a> {
    pub sql: Cow<'a, str>,
    pub placeholders: Vec<PlaceholderRecord>,
}

impl<'a> DeployVarsPrep<'a> {
    fn borrowed(src: &'a str) -> Self {
        Self {
            sql: Cow::Borrowed(src),
            placeholders: Vec::new(),
        }
    }
}

/// The unresolved deployment variables a run has already warned about, so
/// each is reported once however many sources reference it.
#[derive(Debug, Default)]
pub struct UnresolvedVariables {
    warned: std::sync::Mutex<std::collections::HashSet<String>>,
}

impl UnresolvedVariables {
    /// The warning for the variables in `placeholders` not reported before;
    /// `None` when there is nothing new to say.
    pub fn warning(&self, placeholders: &[PlaceholderRecord]) -> Option<String> {
        if placeholders.is_empty() {
            return None;
        }
        let mut fresh = Vec::new();
        if let Ok(mut warned) = self.warned.lock() {
            for record in placeholders {
                if warned.insert(record.origin.clone()) {
                    fresh.push(record.origin.clone());
                }
            }
        }
        if fresh.is_empty() {
            return None;
        }
        Some(format!(
            "⚠️  Unresolved deployment variable(s): {}. Set values with --var NAME=VALUE or --var-env NAME; analysis continues with the variable name at lower confidence.",
            fresh.join(", ")
        ))
    }
}

/// Replay deployment-pipeline variable substitution as a line-preserving
/// pre-pass. Returns `Borrowed` when nothing is rewritten.
///
/// `ext_vars` carries externally-provided values (the `--var` / `--var-env` /
/// `VariableContext` the analyzer already loads). Lookup is exact-case first
/// with an ASCII-case-insensitive fallback.
pub fn preprocess<'a>(
    src: &'a str,
    dialect: &Option<DialectRef>,
    config: &SubstitutionConfig,
    ext_vars: Option<&VariableContext>,
) -> DeployVarsPrep<'a> {
    if config.syntaxes.is_empty() {
        return DeployVarsPrep::borrowed(src);
    }
    // Cheap substring pre-filter — avoids tokenizing files with no marker.
    if !config
        .syntaxes
        .iter()
        .any(|s| src.contains(s.prefix.as_str()))
    {
        return DeployVarsPrep::borrowed(src);
    }
    // Tokenize only for comment/string boundaries; the no-dialect path uses
    // the documented Snowflake default, same as the SnowSQL pass.
    let snow;
    let d: &dyn Dialect = match dialect {
        Some(d) => d.as_ref(),
        None => {
            snow = crate::dialect::snowflake();
            snow.as_ref()
        }
    };
    let lex = crate::lexer::tokenize_with_dialect(src, d);
    let comments = comment_spans(&lex.tokens);
    let strings = string_spans(&lex.tokens);
    let (out, placeholders) = substitute(src, config, &comments, &strings, ext_vars);
    if out == src {
        // Record offsets index `src`, which IS the output — composes with
        // `extend_placeholder_spans_if_current` without an owned copy.
        DeployVarsPrep {
            sql: Cow::Borrowed(src),
            placeholders,
        }
    } else {
        DeployVarsPrep {
            sql: Cow::Owned(out),
            placeholders,
        }
    }
}

/// Line-preserving substitution pass. Comment regions are copied verbatim;
/// markers are recognized in code and strings per the module contract.
fn substitute(
    src: &str,
    config: &SubstitutionConfig,
    comments: &[(usize, usize)],
    strings: &[(usize, usize)],
    ext: Option<&VariableContext>,
) -> (String, Vec<PlaceholderRecord>) {
    let bytes = src.as_bytes();
    let len = bytes.len();
    let mut out = String::with_capacity(len);
    let mut placeholders: Vec<PlaceholderRecord> = Vec::new();
    // Longest prefix wins where one configured prefix is a prefix of another.
    let mut syntaxes: Vec<&SubstitutionSyntax> = config.syntaxes.iter().collect();
    syntaxes.sort_by_key(|s| std::cmp::Reverse(s.prefix.len()));
    let mut p = 0;
    let mut ci = 0; // comment-span cursor (monotonic)
    let mut si = 0; // string-span cursor (monotonic)
    while p < len {
        while ci < comments.len() && comments[ci].1 <= p {
            ci += 1;
        }
        if ci < comments.len() && comments[ci].0 <= p {
            let end = comments[ci].1;
            out.push_str(&src[p..end]);
            p = end;
            continue;
        }
        while si < strings.len() && strings[si].1 <= p {
            si += 1;
        }
        let in_string = si < strings.len() && strings[si].0 <= p;
        if let Some((name, marker_end)) = read_marker(src, p, &syntaxes) {
            let marker = Marker {
                text: &src[p..marker_end],
                start: p,
                name,
                in_string,
            };
            emit_marker(&marker, ext, &mut out, &mut placeholders);
            p = marker_end;
            continue;
        }
        let cl = utf8_len(bytes[p]);
        out.push_str(&src[p..p + cl]);
        p += cl;
    }
    (out, placeholders)
}

/// If a configured marker starts at `p`, return its variable name and the byte
/// index just past the suffix. A marker is prefix + identifier
/// (`[A-Za-z_][A-Za-z0-9_]*`) + suffix; anything else is not a marker.
fn read_marker<'a>(
    src: &'a str,
    p: usize,
    syntaxes: &[&SubstitutionSyntax],
) -> Option<(&'a str, usize)> {
    let bytes = src.as_bytes();
    for syn in syntaxes {
        if !src[p..].starts_with(syn.prefix.as_str()) {
            continue;
        }
        let name_start = p + syn.prefix.len();
        if name_start >= bytes.len() {
            continue;
        }
        let b0 = bytes[name_start];
        if !(b0 == b'_' || b0.is_ascii_alphabetic()) {
            continue;
        }
        let mut j = name_start + 1;
        while j < bytes.len() && is_name_byte(bytes[j]) {
            j += 1;
        }
        if src[j..].starts_with(syn.suffix.as_str()) {
            return Some((&src[name_start..j], j + syn.suffix.len()));
        }
    }
    None
}

/// One recognized marker occurrence: its full source text, byte offset, the
/// variable name inside it, and whether it sits inside a string literal.
struct Marker<'a> {
    text: &'a str,
    start: usize,
    name: &'a str,
    in_string: bool,
}

/// Emit the marker's value if resolved; otherwise degrade per the module
/// contract (bare logical name in code, verbatim in strings) and record a
/// placeholder so the unresolved variable lowers analysis confidence.
fn emit_marker(
    marker: &Marker<'_>,
    ext: Option<&VariableContext>,
    out: &mut String,
    placeholders: &mut Vec<PlaceholderRecord>,
) {
    if let Some(value) = ext.and_then(|ctx| ctx.get_ci(marker.name)) {
        out.push_str(&value_to_string(value));
        return;
    }
    let start = out.len();
    if marker.in_string {
        out.push_str(marker.text);
    } else {
        out.push_str(marker.name);
    }
    let id = placeholders.len() as u32;
    let emitted = out[start..].to_string();
    placeholders.push(PlaceholderRecord {
        placeholder_id: id,
        kind: PlaceholderKind::EnvVar,
        origin: marker.name.to_string(),
        source_position: marker.start,
        render_start: start,
        render_end: out.len(),
        placeholder_text: emitted,
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dialect::dialect_from_name;
    use crate::template::VariableSource;
    use serde_json::Value;

    fn vars(pairs: &[(&str, &str)]) -> VariableContext {
        let mut ctx = VariableContext::new();
        for (k, v) in pairs {
            ctx.set(
                k.to_string(),
                Value::String(v.to_string()),
                VariableSource::Cli,
            );
        }
        ctx
    }

    fn run(src: &str, pairs: &[(&str, &str)]) -> String {
        let ctx = vars(pairs);
        preprocess(src, &None, &SubstitutionConfig::default(), Some(&ctx))
            .sql
            .into_owned()
    }

    #[test]
    fn resolved_use_substitutes() {
        assert_eq!(run("USE ${ELT_DB};", &[("ELT_DB", "ELT")]), "USE ELT;");
    }

    #[test]
    fn unresolved_becomes_bare_name_with_record() {
        let prep = preprocess(
            "USE ${ELT_DB};",
            &None,
            &SubstitutionConfig::default(),
            None,
        );
        assert_eq!(prep.sql, "USE ELT_DB;");
        assert_eq!(prep.placeholders.len(), 1);
        let r = &prep.placeholders[0];
        assert_eq!(r.kind, PlaceholderKind::EnvVar);
        assert_eq!(r.origin, "ELT_DB");
        assert_eq!(&prep.sql[r.render_start..r.render_end], "ELT_DB");
    }

    #[test]
    fn no_marker_is_borrowed() {
        let prep = preprocess("SELECT 1;", &None, &SubstitutionConfig::default(), None);
        assert!(matches!(prep.sql, Cow::Borrowed(_)));
        assert!(prep.placeholders.is_empty());
    }

    #[test]
    fn marker_in_comment_is_untouched() {
        let src = "-- deploy sets ${ELT_DB}\nSELECT 1; /* ${x} */";
        let prep = preprocess(src, &None, &SubstitutionConfig::default(), None);
        assert!(matches!(prep.sql, Cow::Borrowed(_)));
        assert!(prep.placeholders.is_empty());
    }

    #[test]
    fn resolved_in_string_substitutes() {
        assert_eq!(
            run("SELECT '${ELT_DB}';", &[("ELT_DB", "ELT")]),
            "SELECT 'ELT';"
        );
    }

    #[test]
    fn unresolved_in_string_is_verbatim_with_record() {
        let src = "SELECT '${awsKey}';";
        let prep = preprocess(src, &None, &SubstitutionConfig::default(), None);
        assert!(matches!(prep.sql, Cow::Borrowed(_)));
        assert_eq!(prep.placeholders.len(), 1);
        let r = &prep.placeholders[0];
        assert_eq!(&prep.sql[r.render_start..r.render_end], "${awsKey}");
    }

    #[test]
    fn malformed_markers_are_untouched() {
        for src in ["SELECT ${};", "SELECT ${1x};", "SELECT ${a b};"] {
            let prep = preprocess(src, &None, &SubstitutionConfig::default(), None);
            assert!(matches!(prep.sql, Cow::Borrowed(_)), "src: {src}");
            assert!(prep.placeholders.is_empty(), "src: {src}");
        }
    }

    #[test]
    fn dollar_paren_is_off_by_default() {
        let prep = preprocess("USE $(db);", &None, &SubstitutionConfig::default(), None);
        assert!(matches!(prep.sql, Cow::Borrowed(_)));
        assert!(prep.placeholders.is_empty());
    }

    #[test]
    fn dollar_paren_opt_in_under_mssql() {
        let cfg = SubstitutionConfig {
            syntaxes: vec![
                SubstitutionSyntax::dollar_brace(),
                SubstitutionSyntax::dollar_paren(),
            ],
        };
        let ctx = vars(&[("db", "ELT")]);
        let prep = preprocess("USE $(db);", &dialect_from_name("mssql"), &cfg, Some(&ctx));
        assert_eq!(prep.sql, "USE ELT;");
    }

    #[test]
    fn custom_delimiters() {
        let cfg = SubstitutionConfig {
            syntaxes: vec![SubstitutionSyntax::new("%%", "%%").unwrap()],
        };
        let ctx = vars(&[("ELT_DB", "ELT")]);
        let prep = preprocess("USE %%ELT_DB%%;", &None, &cfg, Some(&ctx));
        assert_eq!(prep.sql, "USE ELT;");
    }

    #[test]
    fn syntax_validation_rejects_bad_delimiters() {
        assert_eq!(
            SubstitutionSyntax::new("", "}"),
            Err(SubstitutionConfigError::EmptyDelimiter)
        );
        assert_eq!(
            SubstitutionSyntax::new("$ {", "}"),
            Err(SubstitutionConfigError::WhitespaceDelimiter(
                "$ {".to_string()
            ))
        );
        assert_eq!(
            SubstitutionSyntax::from_preset_name("percent"),
            Err(SubstitutionConfigError::UnknownPreset(
                "percent".to_string()
            ))
        );
    }

    #[test]
    fn cli_value_is_a_preset_or_a_marker_shape() {
        assert_eq!(
            SubstitutionSyntax::from_cli_value("dollar-paren"),
            Ok(SubstitutionSyntax::dollar_paren())
        );
        assert_eq!(
            SubstitutionSyntax::from_cli_value("%%NAME%%"),
            SubstitutionSyntax::new("%%", "%%")
        );
        assert_eq!(
            SubstitutionSyntax::from_cli_value("${NAME}"),
            Ok(SubstitutionSyntax::dollar_brace())
        );
        // A shape names the variable position exactly once, between delimiters.
        for value in ["percent", "<<NAME>>NAME"] {
            assert_eq!(
                SubstitutionSyntax::from_cli_value(value),
                Err(SubstitutionConfigError::UnknownSyntax(value.to_string()))
            );
        }
        assert_eq!(
            SubstitutionSyntax::from_cli_value("NAME}"),
            Err(SubstitutionConfigError::EmptyDelimiter)
        );
        assert_eq!(
            SubstitutionSyntax::from_cli_value("< NAME>"),
            Err(SubstitutionConfigError::WhitespaceDelimiter(
                "< ".to_string()
            ))
        );
    }

    #[test]
    fn adjacent_markers_and_suffix_text() {
        assert_eq!(
            run("SELECT ${a}${b}, ${a}_x;", &[("a", "1"), ("b", "2")]),
            "SELECT 12, 1_x;"
        );
    }

    #[test]
    fn exact_case_beats_case_insensitive_fallback() {
        let ctx = vars(&[("db", "lower"), ("DB", "upper")]);
        let prep = preprocess(
            "USE ${DB};",
            &None,
            &SubstitutionConfig::default(),
            Some(&ctx),
        );
        assert_eq!(prep.sql, "USE upper;");
    }

    #[test]
    fn case_insensitive_fallback_resolves() {
        let ctx = vars(&[("elt_db", "ELT")]);
        assert_eq!(
            preprocess(
                "USE ${ELT_DB};",
                &None,
                &SubstitutionConfig::default(),
                Some(&ctx)
            )
            .sql,
            "USE ELT;"
        );
    }

    #[test]
    fn line_count_is_preserved() {
        let src = "USE ${ELT_DB};\nSELECT 1\nFROM ${ELT_DB}.s.${tbl};\n";
        let out = run(src, &[("ELT_DB", "ELT")]);
        assert_eq!(src.lines().count(), out.lines().count());
        assert_eq!(out, "USE ELT;\nSELECT 1\nFROM ELT.s.tbl;\n");
    }

    #[test]
    fn substitutes_under_any_dialect() {
        for d in ["postgresql", "mssql", "mysql", "bigquery", "databricks"] {
            let ctx = vars(&[("ELT_DB", "ELT")]);
            let prep = preprocess(
                "USE ${ELT_DB};",
                &dialect_from_name(d),
                &SubstitutionConfig::default(),
                Some(&ctx),
            );
            assert_eq!(prep.sql, "USE ELT;", "dialect: {d}");
        }
    }

    #[test]
    fn pg_dollar_quoted_body_gets_in_code_treatment() {
        // The lexer models dollar-quoted bodies as CODE (LexMode::DollarBody
        // tokenizes the body — they are procedure bodies, not opaque strings),
        // so a marker inside one degrades like any in-code marker: bare name +
        // record. envsubst-style tools substitute there too.
        let src = "SELECT $body$ ${v} $body$;";
        let prep = preprocess(
            src,
            &dialect_from_name("postgresql"),
            &SubstitutionConfig::default(),
            None,
        );
        assert_eq!(prep.sql, "SELECT $body$ v $body$;");
        assert_eq!(prep.placeholders.len(), 1);
    }

    #[test]
    fn empty_config_disables_pass() {
        let cfg = SubstitutionConfig { syntaxes: vec![] };
        let prep = preprocess("USE ${ELT_DB};", &None, &cfg, None);
        assert!(matches!(prep.sql, Cow::Borrowed(_)));
        assert!(prep.placeholders.is_empty());
    }
}
