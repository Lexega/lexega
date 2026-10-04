// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

use lexega_syntax::parse_sql;
fn main() {
    let sql = "INSERT INTO t VALUES (1,2), (3);";
    match parse_sql(sql) {
        Ok(ast) => println!("Parsed OK: {:?}", ast),
        Err(e) => println!("Parse error: {:?}", e),
    }
}
