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

use super::{ExtractedSql, SqlCallPattern, SqlEmbedding};

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
/// stripped.
pub fn extract_sql(
    source: &str,
    file_path: &Path,
    _patterns: &[SqlCallPattern],
) -> Vec<ExtractedSql> {
    if !is_databricks_notebook(source) {
        return Vec::new();
    }

    let mut results = Vec::new();

    // Split into cells by the delimiter.
    // First cell is the header + first code cell.
    let cells: Vec<&str> = source.split(CELL_DELIMITER).collect();

    let mut line_offset: u32 = 1; // 1-indexed line number

    for cell_text in &cells {
        let cell_lines: Vec<&str> = cell_text.lines().collect();
        let cell_line_count = cell_lines.len() as u32;

        // Check if this cell is a SQL magic cell
        let mut sql_lines: Vec<&str> = Vec::new();
        let mut is_sql_cell = false;
        let mut first_sql_line: u32 = 0;

        for (i, line) in cell_lines.iter().enumerate() {
            let trimmed = line.trim();

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
                    sql_lines.push(content);
                } else if trimmed == "# MAGIC" {
                    // Empty magic line → blank SQL line
                    sql_lines.push("");
                } else {
                    // Non-magic line interrupts the SQL cell
                    is_sql_cell = false;
                    sql_lines.clear();
                    break;
                }
            } else {
                // Not yet identified — look for the %sql marker
                if trimmed.starts_with(SQL_MAGIC_PREFIX) {
                    is_sql_cell = true;
                    first_sql_line = line_offset + i as u32;
                    // Check for inline SQL on the same line: # MAGIC %sql SELECT 1
                    let after_prefix = trimmed.strip_prefix(SQL_MAGIC_PREFIX).unwrap_or("");
                    let inline = after_prefix.strip_prefix(' ').unwrap_or(after_prefix);
                    if !inline.is_empty() {
                        sql_lines.push(inline);
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

        if is_sql_cell && !sql_lines.is_empty() {
            let sql = sql_lines.join("\n").trim().to_string();
            if !sql.is_empty() {
                results.push(ExtractedSql {
                    sql,
                    origin_file: file_path.to_path_buf(),
                    origin_line: first_sql_line,
                    origin_col: 0,
                    embedding: SqlEmbedding::DatabricksMagicSql,
                    dialect_hint: Some("databricks".to_string()),
                    has_interpolation: false,
                });
            }
        }

        // Advance line counter: cell lines + 1 for the delimiter line
        line_offset += cell_line_count + 1;
    }

    results
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
        assert_eq!(results[0].dialect_hint.as_deref(), Some("databricks"));
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
