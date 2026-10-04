// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! SQL extraction from host-language files.
//!
//! This module extracts SQL fragments from non-SQL files (Python scripts,
//! Jupyter notebooks, Databricks notebooks) using deterministic, AST-based
//! parsing — no regex heuristics.
//!
//! # Supported Surfaces
//!
//! | Surface | Parser | Module |
//! |---------|--------|--------|
//! | `.py` files with `spark.sql()` | ruff_python_parser (full AST) | [`python`] |
//! | `.ipynb` Jupyter notebooks | serde_json (JSON schema) | [`notebook`] |
//! | Databricks `.py` notebooks | File format spec parser | [`databricks_notebook`] |
//!
//! # Architecture
//!
//! The extraction layer sits **before** the Lexer → Parser → Analyzer
//! pipeline. Each extractor produces `Vec<ExtractedSql>` — self-contained SQL
//! fragments with source-location metadata — which are then fed individually
//! through the normal analysis pipeline.
//!
//! ```text
//! Source File (.py, .ipynb)
//!     ↓
//! SQL Extractor (this module)
//!     ↓
//! Vec<ExtractedSql>
//!     ↓
//! [Existing pipeline: Lexer → Parser → Analyzer]
//! ```
//!
//! # Zero Heuristics
//!
//! - Python extraction uses a real Python AST parser (ruff), not regex
//! - Notebook extraction parses JSON per the `.ipynb` schema spec
//! - Databricks notebook markers are a defined file format, not guesses

pub mod python;

pub mod databricks_notebook;
pub mod notebook;

use std::path::{Path, PathBuf};

/// A SQL fragment extracted from a host-language file.
#[derive(Debug, Clone)]
pub struct ExtractedSql {
    /// The raw SQL text (quotes/magic prefix stripped).
    pub sql: String,
    /// Original file path.
    pub origin_file: PathBuf,
    /// 1-based line number in the origin file where the SQL starts.
    pub origin_line: u32,
    /// 0-based column offset in the origin file.
    pub origin_col: u32,
    /// How the SQL was embedded.
    pub embedding: SqlEmbedding,
    /// Dialect hint inferred from the embedding context.
    pub dialect_hint: Option<String>,
    /// Whether the SQL contains interpolation placeholders
    /// (f-strings, s-strings) that couldn't be resolved statically.
    pub has_interpolation: bool,
}

/// How SQL was embedded in the host file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SqlEmbedding {
    /// Standalone `.sql` file (passthrough, no extraction needed).
    StandaloneFile,
    /// `spark.sql("...")` or similar `.sql()` method call.
    SparkSqlCall,
    /// `cursor.execute("...")` or similar `.execute()` method call.
    ExecuteCall,
    /// `%sql` magic cell in a Jupyter notebook.
    NotebookMagicSql,
    /// `# MAGIC %sql` in a Databricks `.py` notebook.
    DatabricksMagicSql,
}

/// Configuration for which SQL execution APIs to extract from.
#[derive(Debug, Clone)]
pub struct SqlCallPattern {
    /// Method name to match (e.g., "sql", "execute", "read_sql").
    pub method_name: String,
    /// Which positional argument holds the SQL (0-based).
    pub sql_arg_position: usize,
    /// Optional: keyword argument name for the SQL (e.g., "statement").
    pub sql_kwarg_name: Option<String>,
    /// What kind of embedding this represents.
    pub embedding: SqlEmbedding,
}

impl SqlCallPattern {
    /// The default patterns for Databricks/PySpark.
    pub fn spark_defaults() -> Vec<Self> {
        vec![
            // spark.sql("...")
            SqlCallPattern {
                method_name: "sql".to_string(),
                sql_arg_position: 0,
                sql_kwarg_name: None,
                embedding: SqlEmbedding::SparkSqlCall,
            },
            // cursor.execute("...")
            SqlCallPattern {
                method_name: "execute".to_string(),
                sql_arg_position: 0,
                sql_kwarg_name: None,
                embedding: SqlEmbedding::ExecuteCall,
            },
        ]
    }
}

/// Determine the appropriate extractor for a file based on its extension.
///
/// Returns `None` for `.sql` files (passthrough) and unsupported extensions.
pub fn extractor_for_file(path: &Path) -> Option<FileKind> {
    let ext = path.extension()?.to_str()?;
    match ext {
        "py" => {
            // Check if it's a Databricks notebook (has the header marker)
            // We can't know without reading the file, so return Python
            // and let the caller check for Databricks markers.
            Some(FileKind::Python)
        }
        "ipynb" => Some(FileKind::JupyterNotebook),
        "sql" => None, // Passthrough — handled by existing pipeline
        _ => None,
    }
}

/// The kind of host-language file detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileKind {
    /// Python source file (may be a regular script or Databricks notebook).
    Python,
    /// Jupyter notebook (JSON format).
    JupyterNotebook,
}

/// Extract SQL fragments from a file, auto-detecting the file type.
///
/// For `.sql` files, returns `None` (caller should use the normal pipeline).
/// For unsupported extensions, returns `None`.
///
/// The `patterns` parameter controls which method calls are recognized as
/// SQL execution APIs.
pub fn extract_sql_from_file(
    path: &Path,
    source: &str,
    patterns: &[SqlCallPattern],
) -> Option<Vec<ExtractedSql>> {
    match extractor_for_file(path)? {
        FileKind::Python => {
            // Check for Databricks notebook header first
            if databricks_notebook::is_databricks_notebook(source) {
                Some(databricks_notebook::extract_sql(source, path, patterns))
            } else {
                // Regular Python file — full AST-based extraction
                Some(python::extract_sql(source, path, patterns))
            }
        }
        FileKind::JupyterNotebook => Some(notebook::extract_sql(source, path)),
    }
}
