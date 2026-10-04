// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

use lexega_syntax::lexer;

fn main() {
    let sql = "SELECT /* block comment */ id -- line comment\nFROM users";
    let tokens = lexer::tokenize(sql);

    println!("Total tokens: {}", tokens.tokens.len());
    for (i, token) in tokens.tokens.iter().enumerate() {
        println!("\nToken {}: {:?}", i, token.kind);
        println!("  Lexeme: '{}'", token.lexeme(sql));
        println!("  Span: {}..{}", token.span.start, token.span.end);
        println!("  Leading trivia: {} items", token.leading_trivia.len());
        for (j, trivia) in token.leading_trivia.iter().enumerate() {
            let trivia_text = &sql[trivia.span.start as usize..trivia.span.end as usize];
            println!("    Trivia {}: {:?} = '{}'", j, trivia.kind, trivia_text);
        }
        println!("  Trailing trivia: {} items", token.trailing_trivia.len());
        for (j, trivia) in token.trailing_trivia.iter().enumerate() {
            let trivia_text = &sql[trivia.span.start as usize..trivia.span.end as usize];
            println!("    Trivia {}: {:?} = '{}'", j, trivia.kind, trivia_text);
        }
    }
}
