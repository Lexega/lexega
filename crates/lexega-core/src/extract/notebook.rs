// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! SQL extraction from Jupyter notebook (.ipynb) files.
//!
//! Jupyter notebooks are JSON files with a well-defined schema. SQL cells
//! are identified by the `%sql` or `%%sql` magic prefix in code cells.
//! This is deterministic — we parse structured JSON, not arbitrary text.

use std::path::Path;

use serde::Deserialize;
use serde_json::value::RawValue;

use super::{python, ExtractError, ExtractedSql, OffsetMap, SqlCallPattern, SqlEmbedding};
use crate::analyzer::LineIndex;

/// Minimal representation of a Jupyter notebook (v4 schema), each cell's
/// source kept as written in the file.
#[derive(Deserialize)]
struct Notebook<'a> {
    #[serde(borrow)]
    cells: Vec<Cell<'a>>,
}

#[derive(Deserialize)]
struct Cell<'a> {
    cell_type: String,
    /// Cell source — a single string or an array of line strings.
    #[serde(borrow)]
    source: &'a RawValue,
}

/// A cell's text, and where each byte of it is written in the notebook's
/// JSON.
struct CellText {
    text: String,
    map: OffsetMap,
}

impl CellText {
    /// The text of the cell source `raw` (a string or an array of strings)
    /// of `notebook`, the JSON text it is part of.
    fn read(raw: &RawValue, notebook: &str) -> Result<Self, serde_json::Error> {
        let parts: Vec<&RawValue> = match serde_json::from_str(raw.get()) {
            Ok(parts) => parts,
            Err(_) => vec![raw],
        };
        let mut cell = CellText {
            text: String::new(),
            map: OffsetMap::default(),
        };
        for part in parts {
            let decoded: String = serde_json::from_str(part.get())?;
            if let Some(at) = offset_in(notebook, part.get()) {
                map_json_string(&mut cell.map, part.get(), at, cell.text.len());
            }
            cell.text.push_str(&decoded);
        }
        Ok(cell)
    }
}

/// Where `inner`, a slice of `outer`, begins in it.
fn offset_in(outer: &str, inner: &str) -> Option<usize> {
    let at = (inner.as_ptr() as usize).checked_sub(outer.as_ptr() as usize)?;
    (at + inner.len() <= outer.len()).then_some(at)
}

/// Add to `map` where the decoded text of the JSON string `raw`, written at
/// byte `at` of the notebook, lies once it is decoded from byte `decoded`
/// of a cell's text on: in runs from its opening quote and after each
/// escape.
fn map_json_string(map: &mut OffsetMap, raw: &str, at: usize, decoded: usize) {
    let Some(body) = raw.strip_prefix('"') else {
        return;
    };
    let at = at + 1;
    let (mut read, mut written) = (0, decoded);
    map.push(written, at);
    while let Some(next) = body.get(read..).and_then(|rest| rest.chars().next()) {
        match next {
            '"' => break,
            '\\' => {
                let (raw_len, decoded_len) = json_escape_len(&body[read..]);
                read += raw_len;
                written += decoded_len;
                map.push(written, at + read);
            }
            other => {
                read += other.len_utf8();
                written += other.len_utf8();
            }
        }
    }
}

/// The length of the JSON escape `escape` begins with, and of the UTF-8
/// text it stands for.
fn json_escape_len(escape: &str) -> (usize, usize) {
    let unit = |from: usize| {
        escape
            .get(from..from + 4)
            .and_then(|hex| u32::from_str_radix(hex, 16).ok())
    };
    match escape.as_bytes().get(1) {
        Some(b'u') => match unit(2) {
            // A surrogate pair: one character outside the basic plane.
            Some(0xD800..=0xDBFF) if escape.get(6..8) == Some("\\u") => (12, 4),
            Some(code) => (6, char::from_u32(code).map_or(3, char::len_utf8)),
            None => (2, 1),
        },
        Some(_) => (2, 1),
        None => (1, 0),
    }
}

/// Extract SQL fragments from a Jupyter notebook (.ipynb) file.
///
/// Identifies code cells that begin with `%sql` or `%%sql` magic commands
/// and extracts the SQL content: for `%sql`, the rest of the cell, on the
/// magic's line or after a line break. Also detects `%sql` lines inside a
/// Python cell, and reads the Python in the other code cells as a `.py` file
/// is read, for the calls `patterns` name. Each fragment is placed where its
/// text is written in the notebook's JSON.
///
/// A file that is no notebook is an error.
pub fn extract_sql(
    source: &str,
    file_path: &Path,
    patterns: &[SqlCallPattern],
) -> Result<Vec<ExtractedSql>, ExtractError> {
    let invalid = |e: serde_json::Error| ExtractError::InvalidNotebook(e.to_string());
    let notebook: Notebook = serde_json::from_str(source).map_err(invalid)?;
    let lines = LineIndex::new(source);

    let mut results = Vec::new();
    let mut python_cells: Vec<PythonCell> = Vec::new();

    for cell in &notebook.cells {
        let read = CellText::read(cell.source, source).map_err(invalid)?;
        if cell.cell_type != "code" {
            continue;
        }
        let cell_source = read.text.as_str();
        let trimmed = cell_source.trim_start();
        let magic_at = cell_source.len() - trimmed.len();
        // The magic SQL in `cell_source` from byte `from` to `to`, as a
        // fragment placed where its text is written.
        let magic_sql = |from: usize, to: usize| {
            let text = &cell_source[from..to];
            let sql = text.trim();
            let sql_at = from + text.len() - text.trim_start().len();
            (!sql.is_empty()).then(|| {
                ExtractedSql::placed_in(
                    sql.to_string(),
                    file_path,
                    (source, &lines),
                    &OffsetMap::starting_at(sql_at).then(&read.map, sql.len()),
                    SqlEmbedding::NotebookMagicSql,
                    false,
                )
            })
        };

        // %%sql cell magic — entire cell is SQL
        if let Some(after_prefix) = trimmed.strip_prefix("%%sql") {
            let body_at = magic_at + "%%sql".len();
            // %%sql is a cell magic — SQL starts on the next line; all
            // on its line where there is none.
            let sql_at = after_prefix
                .find('\n')
                .map_or(body_at, |newline_pos| body_at + newline_pos + 1);
            results.extend(magic_sql(sql_at, cell_source.len()));
        }
        // %sql line magic — the rest of the cell is SQL, from the
        // magic's line or from the lines after it
        else if trimmed
            .strip_prefix("%sql")
            .is_some_and(|rest| rest.starts_with(char::is_whitespace))
        {
            results.extend(magic_sql(magic_at + "%sql".len(), cell_source.len()));
        }
        // Multi-line %sql (each line after %sql on its own line)
        else {
            // Check each line for %sql prefix
            let mut line_at = 0;
            for line in cell_source.split_inclusive('\n') {
                let text = line.trim_end_matches(['\r', '\n']);
                let line_trimmed = text.trim_start();
                if line_trimmed.starts_with("%sql ") || line_trimmed.starts_with("%sql\t") {
                    let sql_at = line_at + text.len() - line_trimmed.len() + "%sql".len();
                    results.extend(magic_sql(sql_at, line_at + text.len()));
                }
                line_at += line.len();
            }
            // Another cell magic (`%%bash`, …) holds no Python.
            if !trimmed.starts_with("%%") {
                python_cells.push(PythonCell {
                    text: without_ipython_syntax(cell_source),
                    cell: read,
                });
            }
        }
    }

    // The cells share one namespace, so the Python in them is one module: a
    // query assigned in one cell and run in a later one is found. Where the
    // module does not parse (one cell is not Python), each cell is read alone.
    let notebook_text = (source, &lines);
    let mut found = python_in_cells(&python_cells, file_path, patterns, notebook_text);
    if found.is_empty() && python_cells.len() > 1 {
        for cell in &python_cells {
            found.extend(python_in_cells(
                std::slice::from_ref(cell),
                file_path,
                patterns,
                notebook_text,
            ));
        }
    }
    results.extend(found);
    results.sort_by_key(|fragment| (fragment.origin.line, fragment.origin.column));

    Ok(results)
}

/// The Python of a code cell, ready to join with the others.
struct PythonCell {
    /// The cell's text with IPython lines emptied.
    text: String,
    /// The cell's text as written, and where it is in the notebook.
    cell: CellText,
}

/// The fragments in `cells` read as one Python module, each placed where it
/// is written in `notebook`, the notebook's JSON text and its line index.
fn python_in_cells(
    cells: &[PythonCell],
    file_path: &Path,
    patterns: &[SqlCallPattern],
    notebook: (&str, &LineIndex),
) -> Vec<ExtractedSql> {
    let mut module = String::new();
    // Where each byte of the module is in the notebook: each line of a cell
    // where that line is written, an emptied line at its end.
    let mut placed = OffsetMap::default();
    for cell in cells {
        let mut to_cell = OffsetMap::default();
        let start = module.len();
        let mut written = 0;
        for (line, as_written) in cell
            .text
            .split_inclusive('\n')
            .zip(cell.cell.text.split_inclusive('\n'))
        {
            to_cell.push(
                module.len() - start,
                written + as_written.len() - line.len(),
            );
            module.push_str(line);
            written += as_written.len();
        }
        if !module.ends_with('\n') {
            module.push('\n');
        }
        for (from, to) in to_cell.then(&cell.cell.map, module.len() - start).0 {
            placed.push(start + from, to);
        }
    }
    let module_lines = LineIndex::new(&module);
    python::extract_sql(&module, file_path, patterns)
        .into_iter()
        .filter_map(|fragment| {
            let at =
                module_lines.offset_at(&module, fragment.origin.line, fragment.origin.column)?;
            let map = OffsetMap::starting_at(at).then(&placed, fragment.sql.len());
            Some(ExtractedSql::placed_in(
                fragment.sql,
                file_path,
                notebook,
                &map,
                fragment.embedding,
                fragment.has_interpolation,
            ))
        })
        .collect()
}

/// `cell` with each IPython line magic (`%…`) and shell escape (`!…`) line
/// emptied, so the Python around it parses and the line numbers hold.
fn without_ipython_syntax(cell: &str) -> String {
    cell.split_inclusive('\n')
        .map(|line| {
            let text = line.trim_end_matches(['\r', '\n']);
            if text.trim_start().starts_with(['%', '!']) {
                &line[text.len()..]
            } else {
                line
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn patterns() -> Vec<SqlCallPattern> {
        SqlCallPattern::spark_defaults()
    }

    fn extract(nb: &str) -> Vec<ExtractedSql> {
        extract_sql(nb, &PathBuf::from("test.ipynb"), &patterns()).expect("a notebook")
    }

    /// A notebook as Jupyter writes one: each line of a cell's source a
    /// string on a line of its own.
    fn make_notebook(cells: &[(&str, &str)]) -> String {
        let cells: Vec<serde_json::Value> = cells
            .iter()
            .map(|(cell_type, source)| {
                let lines: Vec<&str> = source.split_inclusive('\n').collect();
                serde_json::json!({"cell_type": cell_type, "metadata": {}, "outputs": [], "source": lines})
            })
            .collect();
        serde_json::to_string_pretty(&serde_json::json!({
            "cells": cells,
            "metadata": {"kernelspec": {"language": "python"}},
            "nbformat": 4,
            "nbformat_minor": 5
        }))
        .expect("a notebook")
    }

    /// The line and column where `text` is first written in `nb`.
    fn written_at(nb: &str, text: &str) -> (usize, usize) {
        let at = nb.find(text).expect("written");
        let place = crate::analyzer::LineIndex::new(nb).position(nb, at);
        (place.line, place.column)
    }

    #[test]
    fn test_cell_magic_sql() {
        let nb = make_notebook(&[("code", "%%sql\nSELECT * FROM events")]);
        let results = extract(&nb);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].sql, "SELECT * FROM events");
        assert_eq!(results[0].embedding, SqlEmbedding::NotebookMagicSql);
    }

    #[test]
    fn test_line_magic_sql() {
        let nb = make_notebook(&[("code", "%sql SELECT count(*) FROM users")]);
        let results = extract(&nb);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].sql, "SELECT count(*) FROM users");
    }

    #[test]
    fn test_non_sql_cell_ignored() {
        let nb = make_notebook(&[
            ("code", "x = 1 + 2"),
            ("markdown", "# Analysis"),
            ("code", "%%sql\nDROP TABLE tmp"),
        ]);
        let results = extract(&nb);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].sql, "DROP TABLE tmp");
    }

    #[test]
    fn test_empty_sql_ignored() {
        let nb = make_notebook(&[("code", "%%sql\n   ")]);
        let results = extract(&nb);
        assert_eq!(results.len(), 0);
    }

    #[test]
    fn test_invalid_json() {
        let error = extract_sql("not json", &PathBuf::from("bad.ipynb"), &patterns())
            .expect_err("a file that is no JSON is no notebook");
        assert!(matches!(error, ExtractError::InvalidNotebook(_)));
        assert!(error
            .to_string()
            .starts_with("not a valid Jupyter notebook"));
    }

    #[test]
    fn test_a_query_assigned_in_one_cell_is_found_where_a_later_cell_runs_it() {
        let nb = make_notebook(&[
            (
                "code",
                "%pip install requests\nq = \"DROP TABLE prod.users\"",
            ),
            ("code", "import os"),
            ("code", "spark.sql(q)"),
            ("code", "%%bash\nls"),
        ]);
        let results = extract(&nb);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].sql, "DROP TABLE prod.users");
        // Placed where the string is written in the notebook.
        let origin = (results[0].origin.line, results[0].origin.column);
        assert_eq!(origin, written_at(&nb, "DROP TABLE prod.users"));
    }

    #[test]
    fn test_cells_that_reassign_a_query_run_each_value() {
        let nb = make_notebook(&[
            ("code", "q = \"DROP TABLE a.first\"\nspark.sql(q)"),
            ("code", "q = \"DROP TABLE b.second\"\nspark.sql(q)"),
        ]);
        let results = extract(&nb);
        let sql: Vec<&str> = results.iter().map(|r| r.sql.as_str()).collect();
        assert_eq!(sql, ["DROP TABLE a.first", "DROP TABLE b.second"]);
    }

    #[test]
    fn test_a_cell_that_is_no_python_does_not_hide_the_others() {
        let nb = make_notebook(&[
            ("code", "def broken(:"),
            ("code", "spark.sql(\"DROP TABLE t\")"),
        ]);
        let results = extract(&nb);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].sql, "DROP TABLE t");
    }

    #[test]
    fn test_line_magic_sql_on_the_next_line() {
        let nb = make_notebook(&[("code", "%sql\nDELETE FROM orders")]);
        let results = extract(&nb);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].sql, "DELETE FROM orders");
        let origin = (results[0].origin.line, results[0].origin.column);
        assert_eq!(origin, written_at(&nb, "DELETE FROM orders"));
    }

    #[test]
    fn test_python_calls_in_code_cells() {
        let nb = make_notebook(&[
            ("markdown", "# notes"),
            (
                "code",
                "%pip install requests\n!ls\nspark.sql(\"DROP TABLE prod.users\")",
            ),
            ("code", "cursor.execute('SELECT 1')"),
        ]);
        let results = extract(&nb);
        let found: Vec<(&str, SqlEmbedding, usize)> = results
            .iter()
            .map(|f| (f.sql.as_str(), f.embedding, f.origin.line))
            .collect();
        let line = |text: &str| written_at(&nb, text).0;
        assert_eq!(
            found,
            [
                (
                    "DROP TABLE prod.users",
                    SqlEmbedding::SparkSqlCall,
                    line("DROP TABLE prod.users")
                ),
                ("SELECT 1", SqlEmbedding::ExecuteCall, line("SELECT 1")),
            ]
        );
    }

    // A cell's SQL is placed on the line of the notebook file its text is
    // written on, its column counted in characters and UTF-16 units past
    // the escapes the file writes before it.
    #[test]
    fn a_cells_sql_is_placed_where_the_notebook_writes_it() {
        let nb = make_notebook(&[
            ("markdown", "# notes\n"),
            ("code", "%%sql\nSELECT 1;\nSELECT \"ñ€😀\" AS a, x = NULL"),
        ]);
        assert!(
            nb.contains(r#"    "SELECT \"ñ€😀\" AS a, x = NULL""#),
            "{nb}"
        );
        let fragment = extract(&nb).into_iter().next().expect("the cell");
        let x = fragment.sql.find("x = NULL").expect("x");
        let place = fragment.place(x);
        assert_eq!((place.line, place.column, place.utf16_column), (18, 31, 32));
        assert_eq!((place.line, place.column), written_at(&nb, "x = NULL"));
        let select = fragment.place(0);
        assert_eq!((select.line, select.column), written_at(&nb, "SELECT 1"));
    }

    // A magic cell's SQL is placed where its text is written, after the
    // magic and any blank line; a Python string's column counts
    // characters.
    #[test]
    fn a_magic_cells_sql_is_placed_where_it_begins() {
        let nb = make_notebook(&[
            ("code", "%sql DELETE FROM main.sales.ia"),
            ("code", "\n%sql DELETE FROM a.b"),
            ("code", "%%sql\n\n  DELETE FROM x"),
            (
                "code",
                "x = 1\n%sql DELETE FROM main.sales.id\nñ = 1; spark.sql(\"DELETE FROM main.sales.ie\")",
            ),
        ]);
        let found: Vec<(String, (usize, usize))> = extract(&nb)
            .into_iter()
            .map(|f| (f.sql, (f.origin.line, f.origin.column)))
            .collect();
        let at = |sql: &str| (sql.to_string(), written_at(&nb, sql));
        assert_eq!(
            found,
            [
                at("DELETE FROM main.sales.ia"),
                at("DELETE FROM a.b"),
                at("DELETE FROM x"),
                at("DELETE FROM main.sales.id"),
                at("DELETE FROM main.sales.ie"),
            ]
        );
    }

    #[test]
    fn test_multiple_sql_cells() {
        let nb = make_notebook(&[
            ("code", "%%sql\nCREATE TABLE t1 (id INT)"),
            ("code", "%%sql\nINSERT INTO t1 VALUES (1)"),
            ("code", "%%sql\nSELECT * FROM t1"),
        ]);
        let results = extract(&nb);
        assert_eq!(results.len(), 3);
    }
}
