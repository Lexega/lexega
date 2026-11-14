// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Whether a statement whose name is written in a given shape is read
//! whole, the name with it.

use lexega_syntax::{parse_sql_with_dialect, AstStmt, DialectRef};

/// Parses each of `forms` under `dialect`: it is one statement, read
/// whole. Where the name under test is written between `«` and `»`, a span
/// of the statement's tree covers exactly the name; a statement that keeps
/// no span of that name is written without the marks.
pub fn reads_whole(dialect: &DialectRef, forms: &[&str]) {
    for form in forms {
        let sql = form.replace(['«', '»'], "");
        let script =
            parse_sql_with_dialect(&sql, &**dialect).unwrap_or_else(|e| panic!("{sql}: {e:?}"));
        let [stmt] = script.stmts.as_slice() else {
            panic!("{sql}: expected one statement, got {:?}", script.stmts);
        };
        assert!(
            !matches!(stmt, AstStmt::OpaqueContent { .. }),
            "{sql}: not read: {stmt:?}"
        );
        if let (Some(open), Some(close)) = (form.find('«'), form.find('»')) {
            let (start, end) = (open, close - '«'.len_utf8());
            let name = format!("Span {{ start: {start}, end: {end} }}");
            assert!(
                format!("{stmt:?}").contains(&name),
                "{sql}: no span holds the name `{}`: {stmt:?}",
                &sql[start..end]
            );
        }
    }
}
