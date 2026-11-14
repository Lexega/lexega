// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Every name position of the parser, in every shape its dialect writes a
//! name in, as `tests/fixtures/name_positions.tsv` lists them: what the
//! parser makes of each form is pinned, with whether the tree of a form
//! read whole keeps a span of its name. Every parser function that reads a
//! name through the shared
//! reader has a form, or is listed in `tests/fixtures/name_position_exempt.txt`
//! with the reason it has none.
//!
//! `LEXEGA_UPDATE_NAME_POSITIONS=1` rewrites the pins; the diff is reviewed.

mod parser_source;

use lexega_syntax::{dialect, parse_sql_with_dialect, AstStmt, DialectRef};
use parser_source::parser_functions;
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

const FAMILY: &str = "tests/fixtures/name_positions.tsv";
const EXEMPT: &str = "tests/fixtures/name_position_exempt.txt";
const UPDATE: &str = "LEXEGA_UPDATE_NAME_POSITIONS";

/// The calls through which a parser function reads a name with the shared
/// reader.
const SHARED_READS: [&str; 11] = [
    "read_object_name(",
    "parse_qualified_name_span(",
    "parse_object_name_span(",
    "parse_object_ref(",
    "parse_required_object_ref(",
    "object_ref_at(",
    "object_ref_of_range(",
    "object_name_end(",
    "take_name_span(",
    "name_span_at(",
    "identifier_argument_at(",
];

struct Row {
    id: String,
    dialect: String,
    reader: String,
    pin: String,
    form: String,
}

fn family_path() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(FAMILY)
}

fn rows(text: &str) -> Vec<Row> {
    text.lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| {
            let cols: Vec<&str> = line.split('\t').collect();
            let [id, dialect, _family, _position, _shape, reader, pin, form] = cols.as_slice()
            else {
                panic!("{FAMILY}: not eight columns: `{line}`");
            };
            Row {
                id: id.to_string(),
                dialect: dialect.to_string(),
                reader: reader.to_string(),
                pin: pin.to_string(),
                form: form.to_string(),
            }
        })
        .collect()
}

fn dialect_of(code: &str) -> DialectRef {
    match code {
        "sf" => dialect::snowflake(),
        "pg" => dialect::postgres(),
        "rs" => dialect::redshift(),
        "bq" => dialect::bigquery(),
        "dbx" => dialect::databricks(),
        "mysql" => dialect::mysql(),
        "mssql" => dialect::mssql(),
        other => panic!("{FAMILY}: no dialect `{other}`"),
    }
}

/// What the parser makes of `form`: the statements it parsed and those it
/// skipped, or the error it gave; and, where it skipped none and the form
/// marks its name, whether a span of the tree covers exactly that name.
fn measure(dialect: &DialectRef, form: &str) -> String {
    let sql = form.replace(['«', '»'], "");
    let script = match parse_sql_with_dialect(&sql, &**dialect) {
        Ok(script) => script,
        Err(e) => return format!("error {:?}", e.kind),
    };
    let skipped = script
        .stmts
        .iter()
        .filter(|stmt| matches!(stmt, AstStmt::OpaqueContent { .. }))
        .count();
    let pin = format!(
        "parsed={} skipped={}",
        script.stmts.len() - skipped,
        skipped
    );
    match (form.find('«'), form.find('»')) {
        (Some(open), Some(close)) if skipped == 0 => {
            let (start, end) = (open, close - '«'.len_utf8());
            let name = format!("Span {{ start: {start}, end: {end} }}");
            let kept = format!("{:?}", script.stmts).contains(&name);
            format!("{pin} name={}", if kept { "kept" } else { "dropped" })
        }
        _ => pin,
    }
}

#[test]
fn every_name_position_parses_as_pinned() {
    let path = family_path();
    let text = fs::read_to_string(&path).expect("the name-position family");
    let rows = rows(&text);
    assert!(rows.len() >= 3000, "{FAMILY}: {} rows", rows.len());
    let mut moved = Vec::new();
    let mut pins = std::collections::BTreeMap::new();
    for row in &rows {
        let pin = measure(&dialect_of(&row.dialect), &row.form);
        if pin != row.pin {
            moved.push(format!("{}: pinned `{}`, now `{pin}`", row.id, row.pin));
        }
        pins.insert(row.id.clone(), pin);
    }
    if std::env::var(UPDATE).is_ok() {
        let rewritten: String = text
            .lines()
            .map(|line| {
                let cols: Vec<&str> = line.split('\t').collect();
                match (line.starts_with('#'), pins.get(cols[0])) {
                    (false, Some(pin)) if cols.len() == 8 => {
                        let mut cols = cols.clone();
                        cols[6] = pin;
                        format!("{}\n", cols.join("\t"))
                    }
                    _ => format!("{line}\n"),
                }
            })
            .collect();
        fs::write(&path, rewritten).expect("rewrite the family");
    } else {
        assert!(
            moved.is_empty(),
            "{} forms parse otherwise than pinned (rewrite with {UPDATE}=1 and review):\n{}",
            moved.len(),
            moved.join("\n")
        );
    }
}

#[test]
fn every_parser_function_that_reads_a_name_has_a_form() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let reading: BTreeSet<String> = parser_functions()
        .into_iter()
        .filter(|(_, text)| SHARED_READS.iter().any(|call| text.contains(call)))
        .map(|(site, _)| site)
        .collect();
    let text = fs::read_to_string(family_path()).expect("the name-position family");
    let with_form: BTreeSet<String> = rows(&text)
        .into_iter()
        .flat_map(|row| {
            row.reader
                .split(',')
                .filter(|reader| *reader != "-")
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .collect();
    let exempt_text = fs::read_to_string(root.join(EXEMPT)).expect("the exempt list");
    let mut exempt = BTreeSet::new();
    for line in exempt_text.lines().filter(|line| !line.is_empty()) {
        let (site, reason) = line
            .split_once('\t')
            .unwrap_or_else(|| panic!("{EXEMPT}: no reason on `{line}`"));
        assert!(
            !reason.trim().is_empty(),
            "{EXEMPT}: empty reason on `{site}`"
        );
        exempt.insert(site.to_string());
    }
    let without: Vec<&String> = reading
        .iter()
        .filter(|site| !with_form.contains(*site) && !exempt.contains(*site))
        .collect();
    let gone: Vec<&String> = with_form
        .iter()
        .chain(&exempt)
        .filter(|site| !reading.contains(*site))
        .collect();
    let both: Vec<&String> = with_form.intersection(&exempt).collect();
    assert!(
        without.is_empty() && gone.is_empty() && both.is_empty(),
        "reads a name and has no form in {FAMILY} nor a reason in {EXEMPT}: {without:#?}\n\
         named but reads no name: {gone:#?}\nboth a form and a reason: {both:#?}"
    );
}
