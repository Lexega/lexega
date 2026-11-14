// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! The parser's source, cut into its functions, as the guards over it read
//! it. Comments are not code, and a module declared under `#[cfg(test)]` is
//! not counted.

use std::fs;
use std::path::Path;

const PARSER: &str = "src/parser";

/// `text` without the modules it declares under `#[cfg(test)]` and
/// without its comment lines. Such a module starts at the left margin and
/// ends at the next closing brace there.
pub fn code_of(text: &str) -> String {
    const OPEN: &str = "\n#[cfg(test)]\nmod ";
    let mut kept = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find(OPEN) {
        kept.push_str(&rest[..start]);
        let module = &rest[start + OPEN.len()..];
        let declaration = module.lines().next().unwrap_or_default();
        rest = if declaration.trim_end().ends_with(';') {
            &module[declaration.len()..]
        } else {
            match module.find("\n}") {
                Some(end) => &module[end + 2..],
                None => "",
            }
        };
    }
    kept.push_str(rest);
    kept.lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .map(|line| format!("{line}\n"))
        .collect()
}

pub fn is_ident_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// The name a line declares a function by, if it does.
fn declared_fn(line: &str) -> Option<&str> {
    let mut rest = line.trim_start();
    for prefix in ["pub(crate) ", "pub ", "const ", "async "] {
        rest = rest.strip_prefix(prefix).unwrap_or(rest);
    }
    let name = rest.strip_prefix("fn ")?;
    let end = name.find(|c: char| !is_ident_char(c))?;
    Some(&name[..end])
}

/// `code` cut into its functions: each one's name and its text, up to the
/// next function declared.
pub fn functions(code: &str) -> Vec<(&str, String)> {
    let mut out: Vec<(&str, String)> = Vec::new();
    for line in code.lines() {
        match declared_fn(line) {
            Some(name) => out.push((name, format!("{line}\n"))),
            None => {
                if let Some((_, text)) = out.last_mut() {
                    text.push_str(line);
                    text.push('\n');
                }
            }
        }
    }
    out
}

/// Every function of the parser's source files, in file order: its
/// `file.rs::function` and its text.
pub fn parser_functions() -> Vec<(String, String)> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files: Vec<_> = fs::read_dir(root.join(PARSER))
        .expect("parser directory")
        .map(|entry| entry.expect("directory entry").path())
        .filter(|path| path.extension().is_some_and(|e| e == "rs"))
        .collect();
    files.sort();
    assert!(files.len() >= 50, "found {} parser files", files.len());
    let mut out = Vec::new();
    for path in &files {
        let file = path
            .file_name()
            .and_then(|n| n.to_str())
            .expect("file name");
        let code = code_of(&fs::read_to_string(path).expect("readable source"));
        for (function, text) in functions(&code) {
            out.push((format!("{file}::{function}"), text));
        }
    }
    out
}
