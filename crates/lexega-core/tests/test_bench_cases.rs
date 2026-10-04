// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

use lexega_core::context::RenderContext;
use lexega_core::formatter::Formatter;
use lexega_core::lexer::tokenize;
use lexega_core::parser::parse_script;

fn format_sql(source: &str) -> Result<String, String> {
    let tokens = tokenize(source);
    let script = parse_script(source, &tokens.tokens).ok_or_else(|| "Parse failed".to_string())?;
    let context = RenderContext::from_source(source.to_string());
    let formatter = Formatter::new();
    let result = formatter
        .format_script(context, &script)
        .map_err(|e| format!("{:?}", e))?;
    result
        .formatted()
        .map(|f| f.formatted_sql().to_string())
        .ok_or_else(|| "Formatting failed".to_string())
}

#[test]
fn test_bench_simple_select() {
    let sql = "SELECT id, name, email FROM users WHERE active = true ORDER BY created_at DESC";
    let result = format_sql(sql);
    assert!(result.is_ok(), "Failed: {:?}", result.err());
}

#[test]
fn test_bench_select_with_join() {
    let sql = r#"
        SELECT u.id, u.name, o.order_id, o.total
        FROM users u
        LEFT JOIN orders o ON u.id = o.user_id
        WHERE u.active = true
        ORDER BY u.created_at DESC
    "#;
    let result = format_sql(sql);
    assert!(result.is_ok(), "Failed: {:?}", result.err());
}

#[test]
fn test_bench_simple_ddl() {
    let sql = "DROP TABLE IF EXISTS staging.temp_data";
    let result = format_sql(sql);
    assert!(result.is_ok(), "Failed: {:?}", result.err());
}

#[test]
fn test_bench_scripting_no_comments() {
    let sql = r#"
BEGIN
    LET x := 10;
    LET y := 20;
    LET z := x + y;
    RETURN z;
END;
"#;
    let result = format_sql(sql);
    assert!(result.is_ok(), "Failed: {:?}", result.err());
}

#[test]
fn test_bench_scripting_with_comments() {
    let sql = r#"
-- Leading comment
BEGIN
    -- Before x
    LET x := 10;
    -- Before y
    LET y := 20;
    /* Block comment
       spanning multiple lines */
    LET z := x + y;
    -- Before return
    RETURN z;
END;
-- Trailing comment
"#;
    let result = format_sql(sql);
    assert!(result.is_ok(), "Failed: {:?}", result.err());
}

#[test]
fn test_bench_nested_blocks_no_comments() {
    let sql = r#"
BEGIN
    LET x := 10;
    IF (x > 5) THEN
        BEGIN
            LET y := 20;
            LET z := x + y;
            IF (z > 25) THEN
                BEGIN
                    LET a := 100;
                    RETURN a;
                END;
            END IF;
        END;
    END IF;
END;
"#;
    let result = format_sql(sql);
    assert!(result.is_ok(), "Failed: {:?}", result.err());
}

#[test]
fn test_bench_nested_blocks_with_comments() {
    let sql = r#"
-- Outer block
BEGIN
    -- Initialize x
    LET x := 10;
    -- Check threshold
    IF (x > 5) THEN
        -- Inner block level 1
        BEGIN
            -- Calculate y
            LET y := 20;
            -- Calculate z
            LET z := x + y;
            -- Check result
            IF (z > 25) THEN
                -- Inner block level 2
                BEGIN
                    -- Final value
                    LET a := 100;
                    -- Return result
                    RETURN a;
                END;
            END IF;
        END;
    END IF;
END;
"#;
    let result = format_sql(sql);
    assert!(result.is_ok(), "Failed: {:?}", result.err());
}

#[test]
fn test_bench_large_script_no_comments() {
    let mut sql = String::from("BEGIN\n");
    for i in 0..100 {
        sql.push_str(&format!("    LET var_{} := {};\n", i, i));
    }
    sql.push_str("    RETURN var_99;\nEND;");

    let result = format_sql(&sql);
    assert!(result.is_ok(), "Failed: {:?}", result.err());
}

#[test]
fn test_bench_large_script_with_comments() {
    let mut sql = String::from("-- Large block\nBEGIN\n");
    for i in 0..100 {
        sql.push_str(&format!(
            "    -- Variable {}\n    LET var_{} := {};\n",
            i, i, i
        ));
    }
    sql.push_str("    -- Final return\n    RETURN var_99;\nEND;\n-- End of block");

    let result = format_sql(&sql);
    assert!(result.is_ok(), "Failed: {:?}", result.err());
}

#[test]
fn test_bench_deeply_nested_blocks() {
    let sql = r#"
BEGIN
    LET x := 1;
    IF (x > 0) THEN
        BEGIN
            LET y := 2;
            IF (y > 0) THEN
                BEGIN
                    LET z := 3;
                    IF (z > 0) THEN
                        BEGIN
                            LET a := 4;
                            IF (a > 0) THEN
                                BEGIN
                                    LET b := 5;
                                    RETURN b;
                                END;
                            END IF;
                        END;
                    END IF;
                END;
            END IF;
        END;
    END IF;
END;
"#;
    let result = format_sql(sql);
    assert!(result.is_ok(), "Failed: {:?}", result.err());
}

#[test]
fn test_bench_scaling_nesting_depth() {
    for depth in [1, 2, 3, 4, 5].iter() {
        let mut sql = String::new();

        // Build nested BEGIN blocks
        for i in 0..*depth {
            sql.push_str(&format!("{}BEGIN\n", "    ".repeat(i)));
            sql.push_str(&format!("{}LET x_{} := {};\n", "    ".repeat(i + 1), i, i));
        }

        // Add innermost statement
        sql.push_str(&format!(
            "{}RETURN x_{};\n",
            "    ".repeat(*depth),
            depth - 1
        ));

        // Close all blocks
        for i in (0..*depth).rev() {
            sql.push_str(&format!("{}END;\n", "    ".repeat(i)));
        }

        let result = format_sql(&sql);
        assert!(
            result.is_ok(),
            "Failed at depth {}: {:?}",
            depth,
            result.err()
        );
    }
}
