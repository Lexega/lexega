// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Cross-dialect procedure / function parameter parser.
//!
//! Consumes the raw text inside the parent statement's `params_span`
//! and produces a [`Vec<AstProcedureParam>`], so consumers can match
//! parameters positionally and by name at call sites.
//!
//! # Per-dialect grammar
//!
//! | Dialect      | Shape                                                          |
//! |--------------|----------------------------------------------------------------|
//! | T-SQL        | `@name TYPE [= default] [OUTPUT|OUT|READONLY]`                  |
//! | PostgreSQL   | `[IN|OUT|INOUT|VARIADIC] [name] TYPE [DEFAULT expr]`            |
//! | Snowflake    | `name TYPE [DEFAULT expr]` (no OUT — return via RETURNS)        |
//! | MySQL        | `[IN|OUT|INOUT] name TYPE`                                      |
//! | BigQuery     | `[name] TYPE`                                                   |
//! | Databricks   | `name TYPE`                                                     |
//!
//! # Permissiveness
//!
//! Unknown / unparseable parameter shapes degrade to `mode = In` and
//! parsing continues, mirroring the principal-source classifier
//! pattern. Mode-keyword detection is the only text-→-typed step;
//! downstream consumers read [`ProcedureParamMode`] not the source.

use crate::ast::{AstProcedureParam, ProcedureParamMode};
use crate::dialect::ProcedureParamGrammar;
use crate::lexer::Span;

/// Dispatcher entry point.
///
/// `params_span` is the parent struct's `params_span` (covers the
/// outer parentheses inclusive). Per-grammar helpers below operate on
/// the inner text. `grammar` is the dialect's declared parameter grammar
/// shape ([`crate::dialect::Dialect::procedure_param_grammar`]).
pub fn parse_procedure_params(
    params_span: Span,
    source: &str,
    grammar: ProcedureParamGrammar,
    id_gen: &crate::ast::NodeIdGenerator,
) -> Vec<AstProcedureParam> {
    let inner = inner_text(params_span, source);
    if inner.trim().is_empty() {
        return Vec::new();
    }
    let inner_offset = inner_start_offset(params_span, source);
    let sections = split_top_level(inner, inner_offset);
    let mut out = Vec::with_capacity(sections.len());
    for sec in sections {
        let param = match grammar {
            ProcedureParamGrammar::AtPrefixedTrailingMode => parse_tsql_param(&sec, source, id_gen),
            ProcedureParamGrammar::LeadingModeOptionalName => parse_pg_param(&sec, source, id_gen),
            ProcedureParamGrammar::LeadingModeRequiredName => {
                parse_mysql_param(&sec, source, id_gen)
            }
            ProcedureParamGrammar::OptionalNameThenType => parse_bq_param(&sec, source, id_gen),
            ProcedureParamGrammar::NameThenType => parse_snowflake_param(&sec, source, id_gen),
        };
        if let Some(p) = param {
            out.push(p);
        }
    }
    out
}

/// One pre-split parameter section: the substring covering one
/// parameter declaration, with absolute-source span coordinates.
#[derive(Debug, Clone)]
struct ParamSection {
    span: Span,
    text: String,
}

fn inner_text(params_span: Span, source: &str) -> &str {
    let start = params_span.start as usize;
    let end = params_span.end as usize;
    let raw = source.get(start..end).unwrap_or("");
    // Strip a single leading `(` and trailing `)` if present.
    let trimmed = raw.trim();
    let stripped = trimmed
        .strip_prefix('(')
        .map(|s| s.strip_suffix(')').unwrap_or(s))
        .unwrap_or(trimmed);
    stripped
}

fn inner_start_offset(params_span: Span, source: &str) -> u32 {
    let start = params_span.start as usize;
    let end = params_span.end as usize;
    let raw = source.get(start..end).unwrap_or("");
    let trim_left = raw.len() - raw.trim_start().len();
    let after_paren = raw[trim_left..]
        .strip_prefix('(')
        .map(|_| trim_left + 1)
        .unwrap_or(trim_left);
    params_span.start + after_paren as u32
}

/// Split inner text on top-level commas (paren / bracket / quote
/// aware). Each section span is absolute to `source`.
fn split_top_level(inner: &str, inner_offset: u32) -> Vec<ParamSection> {
    let mut out = Vec::new();
    let mut depth = 0i32;
    let mut in_str: Option<char> = None;
    let mut section_start: usize = 0;
    let bytes = inner.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        let ch = b as char;
        match (in_str, ch) {
            (Some(q), c) if c == q => in_str = None,
            (Some(_), _) => {}
            (None, '\'') | (None, '"') => in_str = Some(ch),
            (None, '(') | (None, '[') => depth += 1,
            (None, ')') | (None, ']') => depth -= 1,
            (None, ',') if depth == 0 => {
                push_section(&mut out, inner, section_start, i, inner_offset);
                section_start = i + 1;
            }
            _ => {}
        }
    }
    push_section(&mut out, inner, section_start, inner.len(), inner_offset);
    out
}

fn push_section(
    out: &mut Vec<ParamSection>,
    inner: &str,
    start: usize,
    end: usize,
    inner_offset: u32,
) {
    if end <= start {
        return;
    }
    let raw = &inner[start..end];
    let text = raw.trim().to_string();
    if text.is_empty() {
        return;
    }
    // Compute absolute span: skip leading whitespace.
    let leading_ws = raw.len() - raw.trim_start().len();
    let trailing_ws = raw.len() - raw.trim_end().len();
    let abs_start = inner_offset + (start as u32) + leading_ws as u32;
    let abs_end = inner_offset + (end as u32) - trailing_ws as u32;
    out.push(ParamSection {
        span: Span {
            start: abs_start,
            end: abs_end,
        },
        text,
    });
}

/// Tokenize a parameter section into whitespace-delimited word slices
/// with absolute-source spans. Skips inside parens / brackets / quotes
/// — the type expression `DECIMAL(10, 2)` stays a single token.
fn tokenize_param(sec: &ParamSection) -> Vec<(String, Span)> {
    let mut out = Vec::new();
    let bytes = sec.text.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        while i < bytes.len() && (bytes[i] as char).is_ascii_whitespace() {
            i += 1;
        }
        if i >= bytes.len() {
            break;
        }
        let start = i;
        // Handle `=` and `:=` as own tokens.
        if bytes[i] as char == '=' {
            let end = i + 1;
            out.push((
                "=".to_string(),
                Span {
                    start: sec.span.start + start as u32,
                    end: sec.span.start + end as u32,
                },
            ));
            i = end;
            continue;
        }
        if i + 1 < bytes.len() && bytes[i] as char == ':' && bytes[i + 1] as char == '=' {
            let end = i + 2;
            out.push((
                ":=".to_string(),
                Span {
                    start: sec.span.start + start as u32,
                    end: sec.span.start + end as u32,
                },
            ));
            i = end;
            continue;
        }
        // Consume a "word" — atom that may include nested parens/brackets.
        let mut depth = 0i32;
        let mut in_str: Option<char> = None;
        while i < bytes.len() {
            let c = bytes[i] as char;
            if let Some(q) = in_str {
                if c == q {
                    in_str = None;
                }
                i += 1;
                continue;
            }
            match c {
                '\'' | '"' => {
                    in_str = Some(c);
                    i += 1;
                }
                '(' | '[' => {
                    depth += 1;
                    i += 1;
                }
                ')' | ']' => {
                    depth -= 1;
                    i += 1;
                }
                c if c.is_ascii_whitespace() && depth == 0 => break,
                ',' | '=' if depth == 0 => break,
                _ => i += 1,
            }
        }
        let end = i;
        out.push((
            sec.text[start..end].to_string(),
            Span {
                start: sec.span.start + start as u32,
                end: sec.span.start + end as u32,
            },
        ));
    }
    out
}

/// T-SQL: `@name TYPE [= default] [OUTPUT | OUT | READONLY]`
fn parse_tsql_param(
    sec: &ParamSection,
    _source: &str,
    id_gen: &crate::ast::NodeIdGenerator,
) -> Option<AstProcedureParam> {
    let toks = tokenize_param(sec);
    if toks.is_empty() {
        return None;
    }
    let mut idx = 0usize;
    let name = if toks[idx].0.starts_with('@') {
        let n = toks[idx].clone();
        idx += 1;
        Some(n)
    } else {
        return None;
    };
    let typ = toks.get(idx).cloned();
    if typ.is_some() {
        idx += 1;
    }
    // Optional default after `=`.
    let default_after_eq = toks.get(idx).map(|t| t.0.as_str() == "=").unwrap_or(false);
    let _ = default_after_eq;
    // Mode keyword: scan remaining tokens for OUTPUT / OUT.
    let mut mode = ProcedureParamMode::In;
    for (lex, _) in &toks[idx..] {
        let up = lex.to_ascii_uppercase();
        if up == "OUTPUT" || up == "OUT" {
            mode = ProcedureParamMode::Out;
            break;
        }
    }
    Some(AstProcedureParam {
        node_id: id_gen.next(),
        span: sec.span,
        name_span: name.map(|n| n.1),
        type_span: typ.map(|t| t.1),
        mode,
        default_expr: None,
    })
}

/// PostgreSQL: `[IN|OUT|INOUT|VARIADIC] [name] TYPE [DEFAULT expr]`
/// — param name optional (unnamed OUT permitted).
fn parse_pg_param(
    sec: &ParamSection,
    _source: &str,
    id_gen: &crate::ast::NodeIdGenerator,
) -> Option<AstProcedureParam> {
    let toks = tokenize_param(sec);
    if toks.is_empty() {
        return None;
    }
    let mut idx = 0usize;
    let mut mode = ProcedureParamMode::In;
    if let Some(first) = toks.get(idx) {
        match first.0.to_ascii_uppercase().as_str() {
            "IN" => {
                mode = ProcedureParamMode::In;
                idx += 1;
            }
            "OUT" => {
                mode = ProcedureParamMode::Out;
                idx += 1;
            }
            "INOUT" => {
                mode = ProcedureParamMode::InOut;
                idx += 1;
            }
            "VARIADIC" => {
                mode = ProcedureParamMode::Variadic;
                idx += 1;
            }
            _ => {}
        }
    }
    // After the mode keyword: either `name type` or `type` (unnamed OUT).
    let remaining = &toks[idx..];
    if remaining.is_empty() {
        return None;
    }
    let (name_span, type_span) = if remaining.len() >= 2 && !is_pg_builtin_type(&remaining[0].0) {
        (Some(remaining[0].1), Some(remaining[1].1))
    } else {
        (None, Some(remaining[0].1))
    };
    Some(AstProcedureParam {
        node_id: id_gen.next(),
        span: sec.span,
        name_span,
        type_span,
        mode,
        default_expr: None,
    })
}

fn is_pg_builtin_type(lex: &str) -> bool {
    let up = lex.to_ascii_uppercase();
    matches!(
        up.as_str(),
        "INTEGER"
            | "INT"
            | "INT4"
            | "BIGINT"
            | "INT8"
            | "SMALLINT"
            | "INT2"
            | "TEXT"
            | "VARCHAR"
            | "CHAR"
            | "BOOLEAN"
            | "BOOL"
            | "REAL"
            | "DOUBLE"
            | "NUMERIC"
            | "DECIMAL"
            | "DATE"
            | "TIMESTAMP"
            | "TIMESTAMPTZ"
            | "JSON"
            | "JSONB"
            | "UUID"
            | "BYTEA"
            | "SERIAL"
    )
}

/// Snowflake: `name TYPE [DEFAULT expr]`.
fn parse_snowflake_param(
    sec: &ParamSection,
    _source: &str,
    id_gen: &crate::ast::NodeIdGenerator,
) -> Option<AstProcedureParam> {
    let toks = tokenize_param(sec);
    if toks.is_empty() {
        return None;
    }
    let name_span = Some(toks[0].1);
    let type_span = toks.get(1).map(|t| t.1);
    Some(AstProcedureParam {
        node_id: id_gen.next(),
        span: sec.span,
        name_span,
        type_span,
        mode: ProcedureParamMode::In,
        default_expr: None,
    })
}

/// MySQL: `[IN|OUT|INOUT] name TYPE`.
fn parse_mysql_param(
    sec: &ParamSection,
    _source: &str,
    id_gen: &crate::ast::NodeIdGenerator,
) -> Option<AstProcedureParam> {
    let toks = tokenize_param(sec);
    if toks.is_empty() {
        return None;
    }
    let mut idx = 0usize;
    let mut mode = ProcedureParamMode::In;
    if let Some(first) = toks.get(idx) {
        match first.0.to_ascii_uppercase().as_str() {
            "IN" => {
                idx += 1;
            }
            "OUT" => {
                mode = ProcedureParamMode::Out;
                idx += 1;
            }
            "INOUT" => {
                mode = ProcedureParamMode::InOut;
                idx += 1;
            }
            _ => {}
        }
    }
    let remaining = &toks[idx..];
    if remaining.is_empty() {
        return None;
    }
    Some(AstProcedureParam {
        node_id: id_gen.next(),
        span: sec.span,
        name_span: Some(remaining[0].1),
        type_span: remaining.get(1).map(|t| t.1),
        mode,
        default_expr: None,
    })
}

/// BigQuery: `[name] TYPE`.
fn parse_bq_param(
    sec: &ParamSection,
    _source: &str,
    id_gen: &crate::ast::NodeIdGenerator,
) -> Option<AstProcedureParam> {
    let toks = tokenize_param(sec);
    if toks.is_empty() {
        return None;
    }
    let (name_span, type_span) = if toks.len() >= 2 {
        (Some(toks[0].1), Some(toks[1].1))
    } else {
        (None, Some(toks[0].1))
    };
    Some(AstProcedureParam {
        node_id: id_gen.next(),
        span: sec.span,
        name_span,
        type_span,
        mode: ProcedureParamMode::In,
        default_expr: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn idg() -> crate::ast::NodeIdGenerator {
        crate::ast::NodeIdGenerator::new()
    }

    #[test]
    fn empty_params_returns_empty() {
        let src = "()";
        let span = Span { start: 0, end: 2 };
        let v = parse_procedure_params(span, src, ProcedureParamGrammar::NameThenType, &idg());
        assert!(v.is_empty());
    }

    #[test]
    fn tsql_output_param_detected() {
        let src = "(@input NVARCHAR(100), @result INT OUTPUT)";
        let span = Span {
            start: 0,
            end: src.len() as u32,
        };
        let v = parse_procedure_params(
            span,
            src,
            ProcedureParamGrammar::AtPrefixedTrailingMode,
            &idg(),
        );
        assert_eq!(v.len(), 2);
        assert!(matches!(v[0].mode, ProcedureParamMode::In));
        assert!(matches!(v[1].mode, ProcedureParamMode::Out));
    }

    #[test]
    fn pg_inout_param_detected() {
        let src = "(IN x INTEGER, INOUT y INTEGER, OUT z INTEGER)";
        let span = Span {
            start: 0,
            end: src.len() as u32,
        };
        let v = parse_procedure_params(
            span,
            src,
            ProcedureParamGrammar::LeadingModeOptionalName,
            &idg(),
        );
        assert_eq!(v.len(), 3);
        assert!(matches!(v[0].mode, ProcedureParamMode::In));
        assert!(matches!(v[1].mode, ProcedureParamMode::InOut));
        assert!(matches!(v[2].mode, ProcedureParamMode::Out));
    }

    #[test]
    fn snowflake_named_typed_params() {
        let src = "(input STRING, n NUMBER)";
        let span = Span {
            start: 0,
            end: src.len() as u32,
        };
        let v = parse_procedure_params(span, src, ProcedureParamGrammar::NameThenType, &idg());
        assert_eq!(v.len(), 2);
        assert!(v.iter().all(|p| matches!(p.mode, ProcedureParamMode::In)));
        assert!(v[0].name_span.is_some());
        assert!(v[0].type_span.is_some());
    }
}
