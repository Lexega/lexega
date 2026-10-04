// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! SQL extraction from Jupyter notebook (.ipynb) files.
//!
//! Jupyter notebooks are JSON files with a well-defined schema. SQL cells
//! are identified by the `%sql` or `%%sql` magic prefix in code cells.
//! This is deterministic — we parse structured JSON, not arbitrary text.

use std::path::Path;

use serde::Deserialize;

use super::{ExtractedSql, SqlEmbedding};

/// Minimal representation of a Jupyter notebook (v4 schema).
#[derive(Deserialize)]
struct Notebook {
    cells: Vec<Cell>,
    #[serde(default)]
    metadata: NotebookMetadata,
}

#[derive(Deserialize, Default)]
struct NotebookMetadata {
    #[serde(default)]
    kernelspec: Option<KernelSpec>,
}

#[derive(Deserialize)]
struct KernelSpec {
    #[serde(default)]
    language: Option<String>,
}

#[derive(Deserialize)]
struct Cell {
    cell_type: String,
    /// Cell source — can be a single string or array of line strings.
    source: CellSource,
}

/// Jupyter cell source is either a single string or an array of strings.
#[derive(Deserialize)]
#[serde(untagged)]
enum CellSource {
    Single(String),
    Lines(Vec<String>),
}

impl CellSource {
    /// Concatenate cell source lines into a single string.
    fn concat(&self) -> String {
        match self {
            CellSource::Single(s) => s.clone(),
            CellSource::Lines(lines) => lines.join(""),
        }
    }

    /// Count the number of source lines (for tracking cell boundaries).
    fn line_count(&self) -> u32 {
        match self {
            CellSource::Single(s) => s.lines().count().max(1) as u32,
            CellSource::Lines(lines) => lines.len().max(1) as u32,
        }
    }
}

/// Extract SQL fragments from a Jupyter notebook (.ipynb) file.
///
/// Identifies code cells that begin with `%sql` or `%%sql` magic commands
/// and extracts the SQL content. Also detects inline `%sql SELECT ...` usage
/// on a single line.
#[must_use]
pub fn extract_sql(source: &str, file_path: &Path) -> Vec<ExtractedSql> {
    let notebook: Notebook = match serde_json::from_str(source) {
        Ok(nb) => nb,
        Err(_) => return Vec::new(), // Invalid JSON — nothing to extract
    };

    let mut results = Vec::new();
    let mut cumulative_line: u32 = 1; // Track approximate line in notebook

    for cell in &notebook.cells {
        if cell.cell_type == "code" {
            let cell_source = cell.source.concat();
            let trimmed = cell_source.trim_start();

            // %%sql cell magic — entire cell is SQL
            if trimmed.starts_with("%%sql") {
                let after_prefix = trimmed.strip_prefix("%%sql").unwrap_or("");
                // %%sql is a cell magic — SQL starts on the next line
                let sql_body = if let Some(newline_pos) = after_prefix.find('\n') {
                    &after_prefix[newline_pos + 1..]
                } else {
                    // All on same line (unlikely for %%sql, but handle it)
                    after_prefix.trim()
                };
                let sql_text = sql_body.trim();
                if !sql_text.is_empty() {
                    results.push(ExtractedSql {
                        sql: sql_text.to_string(),
                        origin_file: file_path.to_path_buf(),
                        origin_line: cumulative_line + 1, // +1 for the magic line
                        origin_col: 0,
                        embedding: SqlEmbedding::NotebookMagicSql,
                        dialect_hint: infer_dialect(&notebook.metadata),
                        has_interpolation: false,
                    });
                }
            }
            // %sql line magic — single-line SQL after the magic prefix
            else if trimmed.starts_with("%sql ") || trimmed.starts_with("%sql\t") {
                let sql = trimmed.strip_prefix("%sql").unwrap_or("").trim();
                if !sql.is_empty() {
                    results.push(ExtractedSql {
                        sql: sql.to_string(),
                        origin_file: file_path.to_path_buf(),
                        origin_line: cumulative_line,
                        origin_col: 0,
                        embedding: SqlEmbedding::NotebookMagicSql,
                        dialect_hint: infer_dialect(&notebook.metadata),
                        has_interpolation: false,
                    });
                }
            }
            // Multi-line %sql (each line after %sql on its own line)
            else {
                // Check each line for %sql prefix
                for (i, line) in cell_source.lines().enumerate() {
                    let line_trimmed = line.trim_start();
                    if line_trimmed.starts_with("%sql ") || line_trimmed.starts_with("%sql\t") {
                        let sql = line_trimmed.strip_prefix("%sql").unwrap_or("").trim();
                        if !sql.is_empty() {
                            results.push(ExtractedSql {
                                sql: sql.to_string(),
                                origin_file: file_path.to_path_buf(),
                                origin_line: cumulative_line + i as u32,
                                origin_col: 0,
                                embedding: SqlEmbedding::NotebookMagicSql,
                                dialect_hint: infer_dialect(&notebook.metadata),
                                has_interpolation: false,
                            });
                        }
                    }
                }
            }
        }

        cumulative_line += cell.source.line_count();
        cumulative_line += 1; // Account for cell boundary
    }

    results
}

/// Infer dialect from notebook metadata (kernelspec language).
fn infer_dialect(metadata: &NotebookMetadata) -> Option<String> {
    if let Some(ref ks) = metadata.kernelspec {
        if let Some(ref lang) = ks.language {
            let lang_lower = lang.to_ascii_lowercase();
            if lang_lower.contains("sql") || lang_lower.contains("spark") {
                return Some("databricks".to_string());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn make_notebook(cells: &[(&str, &str)]) -> String {
        let cells_json: Vec<String> = cells
            .iter()
            .map(|(cell_type, source)| {
                let lines: Vec<String> = source
                    .lines()
                    .map(|l| format!("\"{}\\n\"", l.replace('\"', "\\\"")))
                    .collect();
                format!(
                    r#"{{"cell_type": "{}", "source": [{}], "metadata": {{}}, "outputs": []}}"#,
                    cell_type,
                    lines.join(", ")
                )
            })
            .collect();

        format!(
            r#"{{"nbformat": 4, "nbformat_minor": 5, "cells": [{}], "metadata": {{"kernelspec": {{"language": "python"}}}}}}"#,
            cells_json.join(", ")
        )
    }

    #[test]
    fn test_cell_magic_sql() {
        let nb = make_notebook(&[("code", "%%sql\nSELECT * FROM events")]);
        let results = extract_sql(&nb, &PathBuf::from("test.ipynb"));
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].sql, "SELECT * FROM events");
        assert_eq!(results[0].embedding, SqlEmbedding::NotebookMagicSql);
    }

    #[test]
    fn test_line_magic_sql() {
        let nb = make_notebook(&[("code", "%sql SELECT count(*) FROM users")]);
        let results = extract_sql(&nb, &PathBuf::from("test.ipynb"));
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
        let results = extract_sql(&nb, &PathBuf::from("test.ipynb"));
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].sql, "DROP TABLE tmp");
    }

    #[test]
    fn test_empty_sql_ignored() {
        let nb = make_notebook(&[("code", "%%sql\n   ")]);
        let results = extract_sql(&nb, &PathBuf::from("test.ipynb"));
        assert_eq!(results.len(), 0);
    }

    #[test]
    fn test_invalid_json() {
        let results = extract_sql("not json", &PathBuf::from("bad.ipynb"));
        assert_eq!(results.len(), 0);
    }

    #[test]
    fn test_multiple_sql_cells() {
        let nb = make_notebook(&[
            ("code", "%%sql\nCREATE TABLE t1 (id INT)"),
            ("code", "%%sql\nINSERT INTO t1 VALUES (1)"),
            ("code", "%%sql\nSELECT * FROM t1"),
        ]);
        let results = extract_sql(&nb, &PathBuf::from("test.ipynb"));
        assert_eq!(results.len(), 3);
    }
}
