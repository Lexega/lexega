// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

use lexega_syntax::{parse_script, tokenize};

fn main() {
    let src = r#"
CREATE PROCEDURE my_proc(x NUMBER)
RETURNS NUMBER
AS
BEGIN
  RETURN x;
END;
"#;

    println!("Source:\n{}", src);
    println!("\n=== Tokenizing ===");
    let tokens = tokenize(src).tokens;

    println!("Token count: {}", tokens.len());
    for (i, tok) in tokens.iter().take(20).enumerate() {
        println!("{}: {:?} '{}'", i, tok.kind, tok.lexeme(src));
    }

    println!("\n=== Parsing ===");
    match parse_script(src, &tokens) {
        Some(script) => {
            println!("SUCCESS! Got {} statement(s)", script.stmts.len());
            for stmt in &script.stmts {
                println!("Statement: {:?}", stmt);
            }
        }
        None => {
            println!("FAILED to parse");
        }
    }
}
