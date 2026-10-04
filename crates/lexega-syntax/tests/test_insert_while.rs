// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

use lexega_syntax::{lexer::tokenize, parser::parse_script};

fn main() {
    // Test outside any loop
    let test_outside = r#"
CREATE OR REPLACE PROCEDURE test()
RETURNS VARCHAR
LANGUAGE SQL
AS
BEGIN
    INSERT INTO t (ts) VALUES (CURRENT_TIMESTAMP());
    RETURN 'test';
END;
"#;
    println!("1. INSERT with CURRENT_TIMESTAMP() outside loop:");
    match parse_script(test_outside, &tokenize(test_outside).tokens) {
        Some(_) => println!("   ✓ Parses OK\n"),
        None => println!("   ✗ FAILS\n"),
    }

    // Test in single WHILE
    let test_in_while = r#"
CREATE OR REPLACE PROCEDURE test()
RETURNS VARCHAR
LANGUAGE SQL
AS
BEGIN
    WHILE (TRUE) DO
        INSERT INTO t (ts) VALUES (CURRENT_TIMESTAMP());
        BREAK;
    END WHILE;
    RETURN 'test';
END;
"#;
    println!("2. INSERT with CURRENT_TIMESTAMP() in WHILE loop:");
    match parse_script(test_in_while, &tokenize(test_in_while).tokens) {
        Some(_) => println!("   ✓ Parses OK\n"),
        None => println!("   ✗ FAILS\n"),
    }

    // Test in nested WHILE
    let test_nested = r#"
CREATE OR REPLACE PROCEDURE test()
RETURNS VARCHAR
LANGUAGE SQL
AS
BEGIN
    WHILE (TRUE) DO
        WHILE (TRUE) DO
            INSERT INTO t (ts) VALUES (CURRENT_TIMESTAMP());
            BREAK;
        END WHILE;
        BREAK;
    END WHILE;
    RETURN 'test';
END;
"#;
    println!("3. INSERT with CURRENT_TIMESTAMP() in nested WHILE:");
    match parse_script(test_nested, &tokenize(test_nested).tokens) {
        Some(_) => println!("   ✓ Parses OK\n"),
        None => println!("   ✗ FAILS\n"),
    }
}
