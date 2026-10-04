// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

use lexega_syntax::format_sql;
fn main() {
    let sql = "SELECT * FROM {% if is_prod %}production{% else %}development{% endif %}.orders";
    println!("SQL: {}", sql);
    match format_sql(sql) {
        Ok(f) => println!("Formatted:\n{}", f),
        Err(e) => println!("Error: {:?}", e),
    }
}
