// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! The parser functions that read a name token by token are the ones
//! `tests/fixtures/name_readers.txt` lists, each with its reason.
//!
//! A function reads a name by hand where its code tests a token for the
//! `.` punctuation, or binds a local whose name has the word `name` to a
//! single token taken with `advance()`. Every other name is read through
//! the shared reader. Comments are not code, and a module declared under
//! `#[cfg(test)]` is not counted. A function that starts to read a name
//! by hand, or stops, fails the test until the list says so.

mod parser_source;

use parser_source::{code_of, functions, is_ident_char, parser_functions};
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

const LIST: &str = "tests/fixtures/name_readers.txt";

/// Whether `text` binds a local whose name has the word `name` to one
/// token taken with `advance()`: `let [mut] <x>_name_<y> = <recv>.advance()`.
fn binds_a_name_to_one_token(text: &str) -> bool {
    text.match_indices("let ").any(|(at, _)| {
        let rest = text[at + 4..].trim_start();
        let rest = rest.strip_prefix("mut ").unwrap_or(rest);
        let end = rest.find(|c: char| !is_ident_char(c)).unwrap_or(rest.len());
        let binding = &rest[..end];
        if !binding.split('_').any(|word| word == "name") {
            return false;
        }
        let Some(value) = rest[end..].trim_start().strip_prefix('=') else {
            return false;
        };
        if value.starts_with('=') {
            return false;
        }
        let value = value.trim_start();
        let receiver = value
            .find(|c: char| !is_ident_char(c))
            .unwrap_or(value.len());
        value[receiver..].trim_start().starts_with(".advance()")
    })
}

/// Whether a function's text reads a name by hand.
fn reads_a_name_by_hand(text: &str) -> bool {
    text.contains("Punctuation::Dot") || binds_a_name_to_one_token(text)
}

#[test]
fn the_scan_tells_a_hand_reader_from_a_function_that_is_none() {
    assert!(reads_a_name_by_hand(
        "if matches!(tok.kind, TokenKind::Punctuation(Punctuation::Dot)) {}"
    ));
    assert!(reads_a_name_by_hand(
        "let policy_name_tok = self.advance().ok_or_else(|| err)?;"
    ));
    assert!(reads_a_name_by_hand(
        "let name_tok = self\n        .advance()\n        .ok_or_eof(span, v)?;"
    ));
    assert!(reads_a_name_by_hand(
        "let mut name_span = p.advance()?.span;"
    ));
    assert!(!reads_a_name_by_hand("let rename_tok = self.advance()?;"));
    assert!(!reads_a_name_by_hand(
        "let name_span = self.parse_object_name_span()?;"
    ));
    assert!(!reads_a_name_by_hand("let name = self.peek_non_trivia();"));
    // What only a test module or a comment does is not the file's.
    let file = "fn f() {}\n#[cfg(test)]\nmod tests {\n    fn g() {\n        \
                let name_tok = p.advance();\n    }\n}\n\
                /// Reads `Punctuation::Dot`.\nfn h() {\n    // Punctuation::Dot\n}\n";
    let code = code_of(file);
    assert_eq!(code, "fn f() {}\nfn h() {\n}\n");
    let parts = functions(&code);
    assert_eq!(parts.len(), 2);
    assert!(parts.iter().all(|(_, text)| !reads_a_name_by_hand(text)));
    // A function's text runs to the next declaration.
    let parts = functions("fn a() {\n    let x = 1;\n}\npub(crate) fn b() {\n}\n");
    assert_eq!(parts[0].0, "a");
    assert_eq!(parts[1].0, "b");
    assert!(parts[0].1.contains("let x"));
}

#[test]
fn the_parser_functions_that_read_a_name_by_hand_are_the_listed_ones() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let readers: BTreeSet<String> = parser_functions()
        .into_iter()
        .filter(|(_, text)| reads_a_name_by_hand(text))
        .map(|(site, _)| site)
        .collect();

    let list = fs::read_to_string(root.join(LIST)).expect("the list of name readers");
    let mut listed = Vec::new();
    for line in list.lines().filter(|line| !line.is_empty()) {
        let (site, reason) = line
            .split_once('\t')
            .unwrap_or_else(|| panic!("{LIST}: no reason on `{line}`"));
        assert!(
            !reason.trim().is_empty(),
            "{LIST}: empty reason on `{site}`"
        );
        listed.push(site.to_string());
    }
    let unlisted: Vec<&String> = readers
        .iter()
        .filter(|site| !listed.contains(site))
        .collect();
    let gone: Vec<&String> = listed
        .iter()
        .filter(|site| !readers.contains(*site))
        .collect();
    assert!(
        unlisted.is_empty() && gone.is_empty(),
        "{LIST} differs.\nreads a name by hand and is not listed: {unlisted:#?}\n\
         listed and reads none: {gone:#?}"
    );
    let ordered: Vec<String> = readers.into_iter().collect();
    assert_eq!(listed, ordered, "{LIST} is not in order");
}
