// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

use lexega_syntax::{format_sql_with_config, FormatterConfig};

#[test]
fn test_call_with_comments() {
    let input = "CALL /* after CALL */ other_procedure /* after name */ ( /* open */ 'arg1' /* in args */, 123 /* second arg */ ); /* after CALL semicolon */ -- trailing CALL";
    let result = format_sql_with_config(input, &FormatterConfig::default())
        .expect("formatting should succeed");
    println!("INPUT:\n{}", input);
    println!("\nOUTPUT:\n{}", result);

    // Check that we don't duplicate comments
    let comment_count_in_input = input.matches("/* open */").count()
        + input.matches("/* in args */").count()
        + input.matches("/* second arg */").count();
    let comment_count_in_output = result.matches("/* open */").count()
        + result.matches("/* in args */").count()
        + result.matches("/* second arg */").count();

    assert_eq!(
        comment_count_in_input, comment_count_in_output,
        "Comment duplication detected"
    );
}
