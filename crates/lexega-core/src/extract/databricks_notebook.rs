// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! SQL extraction from Databricks `.py` notebook files.
//!
//! Databricks notebooks stored as source have a deterministic format:
//!
//! - **Header**: `# Databricks notebook source` (first line)
//! - **Cell delimiter**: `# COMMAND ----------` (separates cells)
//! - **SQL magic cells**: Lines prefixed with `# MAGIC %sql`
//! - **Other magic types**: `# MAGIC %md`, `# MAGIC %scala`, `# MAGIC %r`
//!
//! This parser operates on the file-format specification — no heuristics.

use std::path::Path;

use super::{python, ExtractedSql, OffsetMap, SqlCallPattern, SqlEmbedding};
use crate::analyzer::LineIndex;

/// The mandatory header for Databricks `.py` notebooks.
const DATABRICKS_HEADER: &str = "# Databricks notebook source";

/// The cell delimiter in Databricks notebooks.
const CELL_DELIMITER: &str = "# COMMAND ----------";

/// The magic prefix for the SQL declaration line.
const SQL_MAGIC_PREFIX: &str = "# MAGIC %sql";

/// The generic magic prefix for subsequent content lines.
const MAGIC_PREFIX: &str = "# MAGIC ";

/// Check whether a file is a Databricks notebook by examining its first line.
#[must_use]
pub fn is_databricks_notebook(source: &str) -> bool {
    source
        .trim_start_matches('\u{feff}') // BOM
        .lines()
        .next()
        .map(|line| line.trim() == DATABRICKS_HEADER)
        .unwrap_or(false)
}

/// Extract SQL fragments from a Databricks Python notebook.
///
/// Splits the file into cells at `# COMMAND ----------` boundaries, then
/// collects cells where every non-blank, non-comment line starts with
/// `# MAGIC %sql`. The SQL content is reassembled with the magic prefix
/// stripped, each line placed where it begins behind that prefix. The file
/// is also Python (every magic line and delimiter is a comment), so the
/// calls `patterns` names in its Python cells are extracted as from a plain
/// `.py` file. Fragments come in file order.
pub fn extract_sql(
    source: &str,
    file_path: &Path,
    patterns: &[SqlCallPattern],
) -> Vec<ExtractedSql> {
    if !is_databricks_notebook(source) {
        return Vec::new();
    }

    let mut results = python::extract_sql(source, file_path, patterns);
    let lines = LineIndex::new(source);

    // Split into cells by the delimiter.
    // First cell is the header + first code cell.
    let mut cell_at = 0;
    for cell_text in source.split(CELL_DELIMITER) {
        // Check if this cell is a SQL magic cell: its SQL lines, each with
        // the byte of the file it begins at.
        let mut sql_lines: Vec<(&str, usize)> = Vec::new();
        let mut is_sql_cell = false;

        let mut line_at = cell_at;
        for raw_line in cell_text.split_inclusive('\n') {
            let line = raw_line.strip_suffix('\n').unwrap_or(raw_line);
            let line = line.strip_suffix('\r').unwrap_or(line);
            let at = line_at;
            line_at += raw_line.len();
            let trimmed = line.trim();
            // The byte of the file `skip` bytes into the trimmed line.
            let start_at = |skip: usize| at + (line.len() - line.trim_start().len()) + skip;

            // Skip empty lines and the header
            if trimmed.is_empty() || trimmed == DATABRICKS_HEADER {
                continue;
            }

            // Skip plain comments (non-magic)
            if trimmed.starts_with('#') && !trimmed.starts_with("# MAGIC") {
                continue;
            }

            if is_sql_cell {
                // Already identified as SQL cell — collect continuation lines
                if let Some(content) = trimmed.strip_prefix(MAGIC_PREFIX) {
                    sql_lines.push((content, start_at(MAGIC_PREFIX.len())));
                } else if trimmed == "# MAGIC" {
                    // Empty magic line → blank SQL line
                    sql_lines.push(("", start_at(trimmed.len())));
                } else {
                    // Non-magic line interrupts the SQL cell
                    is_sql_cell = false;
                    sql_lines.clear();
                    break;
                }
            } else {
                // Not yet identified — look for the %sql marker
                if let Some(after_prefix) = trimmed.strip_prefix(SQL_MAGIC_PREFIX) {
                    is_sql_cell = true;
                    // Check for inline SQL on the same line: # MAGIC %sql SELECT 1
                    let inline = after_prefix.strip_prefix(' ').unwrap_or(after_prefix);
                    if !inline.is_empty() {
                        let skip = trimmed.len() - inline.len();
                        sql_lines.push((inline, start_at(skip)));
                    }
                } else if trimmed.starts_with("# MAGIC") {
                    // Different magic type (%md, %scala, etc.) — not a SQL cell
                    break;
                } else {
                    // Regular Python code — not a magic cell at all
                    break;
                }
            }
        }

        if is_sql_cell {
            results.extend(cell_sql(&sql_lines, file_path, (source, &lines)));
        }

        cell_at += cell_text.len() + CELL_DELIMITER.len();
    }

    results.sort_by_key(|fragment| (fragment.origin.line, fragment.origin.column));
    results
}

/// The fragment a SQL cell's `lines` hold, each with the byte of the file
/// `host` it begins at: their text without the blank lines and whitespace
/// around it, each line placed where it begins. None where the cell holds
/// no SQL.
fn cell_sql(
    lines: &[(&str, usize)],
    file_path: &Path,
    host: (&str, &LineIndex),
) -> Option<ExtractedSql> {
    let first = lines.iter().position(|(text, _)| !text.trim().is_empty())?;
    let ((head, head_at), rest) = lines[first..].split_first()?;
    let lead = head.len() - head.trim_start().len();
    let mut sql = head[lead..].to_string();
    let mut map = OffsetMap::starting_at(head_at + lead);
    for (text, at) in rest {
        sql.push('\n');
        map.push(sql.len(), *at);
        sql.push_str(text);
    }
    sql.truncate(sql.trim_end().len());
    Some(ExtractedSql::placed_in(
        sql,
        file_path,
        host,
        &map,
        SqlEmbedding::DatabricksMagicSql,
        false,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_is_databricks_notebook() {
        assert!(is_databricks_notebook(
            "# Databricks notebook source\nx = 1"
        ));
        assert!(!is_databricks_notebook("# regular python\nx = 1"));
        assert!(!is_databricks_notebook(""));
    }

    #[test]
    fn test_is_databricks_notebook_with_bom() {
        assert!(is_databricks_notebook(
            "\u{feff}# Databricks notebook source\nx = 1"
        ));
    }

    #[test]
    fn test_simple_sql_cell() {
        let source = r#"# Databricks notebook source

x = 1

# COMMAND ----------

# MAGIC %sql
# MAGIC SELECT * FROM catalog.schema.events
# MAGIC WHERE date > '2024-01-01'
"#;
        let results = extract_sql(source, &PathBuf::from("notebook.py"), &[]);
        assert_eq!(results.len(), 1);
        assert!(results[0]
            .sql
            .contains("SELECT * FROM catalog.schema.events"));
        assert!(results[0].sql.contains("WHERE date > '2024-01-01'"));
        assert_eq!(results[0].embedding, SqlEmbedding::DatabricksMagicSql);
    }

    #[test]
    fn a_python_cells_sql_calls_are_extracted_in_file_order() {
        let source = r#"# Databricks notebook source

spark.sql("CREATE TABLE t1 (id INT)")

# COMMAND ----------

# MAGIC %sql
# MAGIC INSERT INTO t1 VALUES (1)

# COMMAND ----------

query = "DROP TABLE t1"
spark.sql(sqlQuery=query)
"#;
        let results = extract_sql(
            source,
            &PathBuf::from("notebook.py"),
            &SqlCallPattern::spark_defaults(),
        );
        let found: Vec<(&str, usize, SqlEmbedding)> = results
            .iter()
            .map(|fragment| {
                (
                    fragment.sql.as_str(),
                    fragment.origin.line,
                    fragment.embedding,
                )
            })
            .collect();
        assert_eq!(
            found,
            [
                ("CREATE TABLE t1 (id INT)", 3, SqlEmbedding::SparkSqlCall),
                // A cell is placed where its SQL begins, the line after its
                // `%sql` line.
                (
                    "INSERT INTO t1 VALUES (1)",
                    8,
                    SqlEmbedding::DatabricksMagicSql
                ),
                // A variable's string is placed where it is assigned.
                ("DROP TABLE t1", 12, SqlEmbedding::SparkSqlCall),
            ]
        );
    }

    #[test]
    fn test_multiple_sql_cells() {
        let source = r#"# Databricks notebook source

# COMMAND ----------

# MAGIC %sql
# MAGIC CREATE TABLE t1 (id INT)

# COMMAND ----------

x = spark.sql("other")

# COMMAND ----------

# MAGIC %sql
# MAGIC DROP TABLE t1
"#;
        let results = extract_sql(source, &PathBuf::from("notebook.py"), &[]);
        assert_eq!(results.len(), 2);
        assert!(results[0].sql.contains("CREATE TABLE t1"));
        assert!(results[1].sql.contains("DROP TABLE t1"));
    }

    #[test]
    fn test_markdown_cell_ignored() {
        let source = r#"# Databricks notebook source

# COMMAND ----------

# MAGIC %md
# MAGIC # Analysis Notebook

# COMMAND ----------

# MAGIC %sql
# MAGIC SELECT 1
"#;
        let results = extract_sql(source, &PathBuf::from("notebook.py"), &[]);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].sql, "SELECT 1");
    }

    #[test]
    fn test_python_cell_ignored() {
        let source = r#"# Databricks notebook source

x = 1
y = x + 2

# COMMAND ----------

# MAGIC %sql
# MAGIC SELECT 1
"#;
        let results = extract_sql(source, &PathBuf::from("notebook.py"), &[]);
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_not_databricks_notebook() {
        let source = "# Regular Python file\nimport os\n";
        let results = extract_sql(source, &PathBuf::from("script.py"), &[]);
        assert_eq!(results.len(), 0);
    }

    #[test]
    fn every_sql_cell_is_placed_at_the_line_its_sql_begins_on() {
        let source = "# Databricks notebook source\n# MAGIC %sql SELECT 1\n\n# COMMAND ----------\n\n# MAGIC %sql SELECT 2\n\n# COMMAND ----------\n# MAGIC %sql\n# MAGIC SELECT 3\n";
        let lines: Vec<(String, usize)> = extract_sql(source, &PathBuf::from("notebook.py"), &[])
            .into_iter()
            .map(|fragment| (fragment.sql, fragment.origin.line))
            .collect();
        assert_eq!(
            lines,
            [
                ("SELECT 1".to_string(), 2),
                ("SELECT 2".to_string(), 6),
                ("SELECT 3".to_string(), 10),
            ]
        );
    }

    // A cell's SQL is placed at the line and column where it begins, behind
    // the `# MAGIC ` prefix, past a blank magic line; a Python string's
    // column counts characters.
    #[test]
    fn a_cells_sql_is_placed_where_it_begins_behind_its_magic_prefix() {
        let source = "# Databricks notebook source\n# MAGIC %sql\n# MAGIC DELETE FROM main.sales.nb\n\n# COMMAND ----------\n\n# MAGIC %sql DELETE FROM main.sales.inl\n\n# COMMAND ----------\n\n# MAGIC %sql\n# MAGIC\n# MAGIC SELECT 1;\n# MAGIC   DELETE FROM main.sales.third\n\n# COMMAND ----------\n\nñ = 1; spark.sql(\"DELETE FROM main.sales.py\")\n";
        let fragments = extract_sql(
            source,
            &PathBuf::from("notebook.py"),
            &SqlCallPattern::spark_defaults(),
        );
        // The third cell's second line, column 3 (`DELETE`), is the file's
        // line 14, column 11.
        let place = |sql_offset: usize| {
            fragments
                .get(2)
                .map(|third| third.place(sql_offset))
                .map(|at| (at.line, at.column))
        };
        assert_eq!(place(12), Some((14, 11)));
        assert_eq!(place(0), Some((13, 9)));
        let found: Vec<(String, usize, usize)> = fragments
            .into_iter()
            .map(|fragment| (fragment.sql, fragment.origin.line, fragment.origin.column))
            .collect();
        let at = |sql: &str, line: usize, col: usize| (sql.to_string(), line, col);
        assert_eq!(
            found,
            [
                at("DELETE FROM main.sales.nb", 3, 9),
                at("DELETE FROM main.sales.inl", 7, 14),
                at("SELECT 1;\n  DELETE FROM main.sales.third", 13, 9),
                at("DELETE FROM main.sales.py", 18, 19),
            ]
        );
    }

    // A column in a cell's SQL counts the characters before it on the
    // file's line, and its UTF-16 units, inside the SQL as before it.
    #[test]
    fn a_column_in_a_cells_sql_counts_characters_not_bytes() {
        let source = "# Databricks notebook source\n# MAGIC %sql\n# MAGIC SELECT 'ñ€' AS a;\n# MAGIC SELECT '😀中' AS b; DELETE FROM main.sales.c\n";
        let fragments = extract_sql(source, &PathBuf::from("notebook.py"), &[]);
        let cell = fragments.first().expect("the cell");
        let delete = cell.sql.find("DELETE").expect("delete");
        let at = cell.place(delete);
        assert_eq!((at.line, at.column, at.utf16_column), (4, 27, 28));
    }

    #[test]
    fn test_inline_sql_magic() {
        let source = r#"# Databricks notebook source

# COMMAND ----------

# MAGIC %sql SELECT count(*) FROM users
"#;
        let results = extract_sql(source, &PathBuf::from("notebook.py"), &[]);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].sql, "SELECT count(*) FROM users");
    }

    #[test]
    fn test_empty_sql_cell_ignored() {
        let source = r#"# Databricks notebook source

# COMMAND ----------

# MAGIC %sql

"#;
        let results = extract_sql(source, &PathBuf::from("notebook.py"), &[]);
        assert_eq!(results.len(), 0);
    }
}
