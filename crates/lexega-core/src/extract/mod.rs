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

use crate::analyzer::{LineIndex, TextPosition};

/// A SQL fragment extracted from a host-language file.
#[derive(Debug, Clone)]
pub struct ExtractedSql {
    /// The raw SQL text (quotes/magic prefix stripped).
    pub sql: String,
    /// Original file path.
    pub origin_file: PathBuf,
    /// Where the SQL text begins in the origin file (after a string's prefix
    /// and opening quotes, or a cell's magic).
    pub origin: TextPosition,
    /// Where later parts of the SQL lie in the origin file, in the order of
    /// the bytes of `sql` they place.
    pub placed: Vec<SqlPlace>,
    /// How the SQL was embedded.
    pub embedding: SqlEmbedding,
    /// Whether the SQL contains interpolation placeholders
    /// (f-strings, s-strings) that couldn't be resolved statically.
    pub has_interpolation: bool,
}

/// A byte of a fragment's SQL placed in its origin file. The SQL from it up
/// to the next placed byte (from the first byte, [`ExtractedSql::origin`])
/// is the file's text there, unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SqlPlace {
    /// The byte of the SQL.
    pub offset: usize,
    /// Its place in the file.
    pub at: TextPosition,
}

impl ExtractedSql {
    /// A fragment of `sql`, whose bytes `map` takes to bytes of `host`, the
    /// text of the file it was extracted from (`lines` its line index).
    pub(crate) fn placed_in(
        sql: String,
        origin_file: &Path,
        (host, lines): (&str, &LineIndex),
        map: &OffsetMap,
        embedding: SqlEmbedding,
        has_interpolation: bool,
    ) -> Self {
        let mut placed: Vec<SqlPlace> = map
            .0
            .iter()
            .map(|&(offset, to)| SqlPlace {
                offset,
                at: lines.position(host, to),
            })
            .collect();
        let origin = match placed.first() {
            Some(first) if first.offset == 0 => placed.remove(0).at,
            Some(_) | None => TextPosition::line_start(1),
        };
        Self {
            sql,
            origin_file: origin_file.to_path_buf(),
            origin,
            placed,
            embedding,
            has_interpolation,
        }
    }

    /// The place in the origin file of byte `offset` of [`Self::sql`].
    pub fn place(&self, offset: usize) -> TextPosition {
        let before = self.placed.partition_point(|place| place.offset <= offset);
        let (from, at) = match before.checked_sub(1).and_then(|i| self.placed.get(i)) {
            Some(place) => (place.offset, place.at),
            None => (0, self.origin),
        };
        at.after(self.sql.get(from..offset).unwrap_or_default())
    }
}

/// A map of the byte offsets of one text into another: each entry `(from,
/// to)` takes the first text from `from` up to the next entry onto the
/// second from `to`, unchanged. Entries are in order of `from`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct OffsetMap(Vec<(usize, usize)>);

impl OffsetMap {
    /// A text that is the other's from byte `to` on.
    pub(crate) fn starting_at(to: usize) -> Self {
        Self(vec![(0, to)])
    }

    /// Add that the first text from `from` is the second's from `to`;
    /// entries come in order of `from`.
    pub(crate) fn push(&mut self, from: usize, to: usize) {
        match self.0.last_mut() {
            Some(last) if last.0 >= from => *last = (from, to),
            Some(_) | None => self.0.push((from, to)),
        }
    }

    /// Where byte `at` of the first text is in the second.
    pub(crate) fn map(&self, at: usize) -> usize {
        let before = self.0.partition_point(|&(from, _)| from <= at);
        match before.checked_sub(1).and_then(|i| self.0.get(i)) {
            Some(&(from, to)) => to + (at - from),
            None => at,
        }
    }

    /// This map, of a first text of `len` bytes, followed by `then`, from
    /// the second text into a third.
    pub(crate) fn then(&self, then: &OffsetMap, len: usize) -> OffsetMap {
        let mut out = OffsetMap::default();
        for (i, &(from, to)) in self.0.iter().enumerate() {
            let end = self.0.get(i + 1).map_or(len, |next| next.0);
            out.push(from, then.map(to));
            let run_end = to + (end - from);
            for &(cut, target) in &then.0 {
                if cut > to && cut < run_end {
                    out.push(from + (cut - to), target);
                }
            }
        }
        out
    }
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
            // spark.sql("...") or spark.sql(sqlQuery="...")
            SqlCallPattern {
                method_name: "sql".to_string(),
                sql_arg_position: 0,
                sql_kwarg_name: Some("sqlQuery".to_string()),
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

/// Why a file's SQL could not be extracted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExtractError {
    /// A `.ipynb` file that is no Jupyter notebook; the reason is the JSON
    /// reader's.
    InvalidNotebook(String),
}

impl std::fmt::Display for ExtractError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExtractError::InvalidNotebook(reason) => {
                write!(f, "not a valid Jupyter notebook: {reason}")
            }
        }
    }
}

impl std::error::Error for ExtractError {}

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
) -> Option<Result<Vec<ExtractedSql>, ExtractError>> {
    match extractor_for_file(path)? {
        FileKind::Python => {
            // Check for Databricks notebook header first
            if databricks_notebook::is_databricks_notebook(source) {
                Some(Ok(databricks_notebook::extract_sql(source, path, patterns)))
            } else {
                // Regular Python file — full AST-based extraction
                Some(Ok(python::extract_sql(source, path, patterns)))
            }
        }
        FileKind::JupyterNotebook => Some(notebook::extract_sql(source, path, patterns)),
    }
}

/// How a file's bytes encode its text, as its byte-order mark says. A file
/// without a mark is UTF-8.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceEncoding {
    Utf8,
    /// UTF-8 behind the mark `EF BB BF`.
    Utf8Bom,
    /// UTF-16, little-endian, behind the mark `FF FE` (SQL Server
    /// Management Studio's "Unicode").
    Utf16Le,
    /// UTF-16, big-endian, behind the mark `FE FF`.
    Utf16Be,
}

impl SourceEncoding {
    /// `text` as a file of this encoding holds it, its mark first.
    pub fn encode(self, text: &str) -> Vec<u8> {
        match self {
            SourceEncoding::Utf8 => text.as_bytes().to_vec(),
            SourceEncoding::Utf8Bom => [&[0xEF, 0xBB, 0xBF][..], text.as_bytes()].concat(),
            SourceEncoding::Utf16Le => [0xFF, 0xFE]
                .into_iter()
                .chain(text.encode_utf16().flat_map(u16::to_le_bytes))
                .collect(),
            SourceEncoding::Utf16Be => [0xFE, 0xFF]
                .into_iter()
                .chain(text.encode_utf16().flat_map(u16::to_be_bytes))
                .collect(),
        }
    }
}

/// A file's text, without its byte-order mark, and the encoding it was
/// read in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceText {
    pub text: String,
    pub encoding: SourceEncoding,
}

/// Why a file's bytes are no text ([`decode_source`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceDecodeError {
    /// No mark, or the UTF-8 mark, and bytes that are not UTF-8 from
    /// `valid_up_to`.
    NotUtf8 { valid_up_to: usize },
    /// A UTF-16 mark and an odd number of bytes after it.
    OddUtf16Length,
    /// A UTF-16 mark and units that are no UTF-16 text (an unpaired
    /// surrogate).
    InvalidUtf16,
}

impl std::fmt::Display for SourceDecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SourceDecodeError::NotUtf8 { valid_up_to } => write!(
                f,
                "not UTF-8 text (invalid from byte {valid_up_to}); save it as UTF-8, or as UTF-16 with a byte-order mark"
            ),
            SourceDecodeError::OddUtf16Length => {
                write!(f, "a UTF-16 byte-order mark, then an odd number of bytes")
            }
            SourceDecodeError::InvalidUtf16 => {
                write!(f, "a UTF-16 byte-order mark, then bytes that are not UTF-16 text")
            }
        }
    }
}

impl std::error::Error for SourceDecodeError {}

/// `text` without a leading UTF-8 byte-order mark.
pub fn strip_bom(text: &str) -> &str {
    text.strip_prefix('\u{FEFF}').unwrap_or(text)
}

/// The text of a source file's `bytes`: UTF-8, with or without its mark, or
/// UTF-16 of either byte order behind its mark.
pub fn decode_source(bytes: &[u8]) -> Result<SourceText, SourceDecodeError> {
    let utf16 = |body: &[u8], unit: fn([u8; 2]) -> u16| {
        if !body.len().is_multiple_of(2) {
            return Err(SourceDecodeError::OddUtf16Length);
        }
        let units: Vec<u16> = body
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| unit([pair[0], pair[1]]))
            .collect();
        String::from_utf16(&units).map_err(|_| SourceDecodeError::InvalidUtf16)
    };
    let utf8 = |body: &[u8]| {
        std::str::from_utf8(body)
            .map(str::to_string)
            .map_err(|e| SourceDecodeError::NotUtf8 {
                valid_up_to: e.valid_up_to(),
            })
    };
    if let Some(body) = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]) {
        return Ok(SourceText {
            text: utf8(body)?,
            encoding: SourceEncoding::Utf8Bom,
        });
    }
    if let Some(body) = bytes.strip_prefix(&[0xFF, 0xFE]) {
        return Ok(SourceText {
            text: utf16(body, u16::from_le_bytes)?,
            encoding: SourceEncoding::Utf16Le,
        });
    }
    if let Some(body) = bytes.strip_prefix(&[0xFE, 0xFF]) {
        return Ok(SourceText {
            text: utf16(body, u16::from_be_bytes)?,
            encoding: SourceEncoding::Utf16Be,
        });
    }
    Ok(SourceText {
        text: utf8(bytes)?,
        encoding: SourceEncoding::Utf8,
    })
}

#[cfg(test)]
mod decode_source_tests {
    use super::{decode_source, SourceDecodeError, SourceEncoding};

    #[test]
    fn each_mark_reads_its_encoding_and_writes_it_back() {
        let text = "SELECT 'é' FROM t;\n";
        for encoding in [
            SourceEncoding::Utf8,
            SourceEncoding::Utf8Bom,
            SourceEncoding::Utf16Le,
            SourceEncoding::Utf16Be,
        ] {
            let bytes = encoding.encode(text);
            let read = decode_source(&bytes).expect("decodes");
            assert_eq!(read.text, text, "{encoding:?}");
            assert_eq!(read.encoding, encoding);
        }
        // SQL Server Management Studio's "Unicode": the mark, then UTF-16LE.
        assert_eq!(
            decode_source(&[0xFF, 0xFE, b'S', 0, b';', 0])
                .expect("decodes")
                .text,
            "S;"
        );
    }

    #[test]
    fn bytes_that_are_no_text_are_an_error() {
        assert_eq!(
            decode_source(&[b'a', 0xFF, b'b']),
            Err(SourceDecodeError::NotUtf8 { valid_up_to: 1 })
        );
        assert_eq!(
            decode_source(&[0xFF, 0xFE, b'a']),
            Err(SourceDecodeError::OddUtf16Length)
        );
        // An unpaired high surrogate.
        assert_eq!(
            decode_source(&[0xFF, 0xFE, 0x00, 0xD8]),
            Err(SourceDecodeError::InvalidUtf16)
        );
    }
}

#[cfg(test)]
mod place_tests {
    use super::*;

    // A fragment's byte is placed from the last placed byte before it, its
    // column counted in characters and UTF-16 units; a map followed by
    // another places bytes where the second takes them.
    #[test]
    fn a_fragment_byte_is_placed_through_its_maps() {
        let host = "x = 'ñ€'; q(\"select '😀' as a\\\"b, x = null\")\n";
        let lines = LineIndex::new(host);
        let sql = "select '😀' as a\"b, x = null";
        let start = host.find("select").expect("select");
        // The escape `\"` is two bytes of the host for one of the SQL.
        let quote = sql.find('"').expect("quote");
        let mut map = OffsetMap::starting_at(start);
        map.push(quote + 1, host.find("b, x").expect("b"));
        let fragment = ExtractedSql::placed_in(
            sql.to_string(),
            Path::new("q.py"),
            (host, &lines),
            &map,
            SqlEmbedding::SparkSqlCall,
            false,
        );
        let x = sql.find("x =").expect("x");
        let expected = lines.position(host, host.find("x = null").expect("x"));
        assert_eq!(fragment.place(x), expected);
        assert_eq!(
            (expected.line, expected.column, expected.utf16_column),
            (1, 34, 35)
        );
        assert_eq!(fragment.origin, lines.position(host, start));

        let inner = OffsetMap::starting_at(2);
        let composed = inner.then(&map, sql.len() - 2);
        assert_eq!(composed.map(x - 2), map.map(x));
        assert_eq!(composed.map(0), map.map(2));
    }
}
