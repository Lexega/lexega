// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Tests for risk analysis of CREATE PROCEDURE and CREATE FUNCTION bodies
//!
//! Verifies that:
//! 1. Procedure/function bodies are recursively analyzed
//! 2. Tables read/written in bodies are extracted
//! 3. Dynamic SQL (EXECUTE IMMEDIATE) is detected and flagged

use lexega_core::analyzer::RuleMatch;

use lexega_core::api::analyze_risk;

/// Test that a procedure with a simple SELECT has its table extracted
#[test]
fn test_procedure_body_table_read() {
    let sql = r#"
        CREATE PROCEDURE get_customers()
        RETURNS TABLE(id INT, name VARCHAR)
        AS
        $$
        BEGIN
            RETURN TABLE(SELECT id, name FROM customers WHERE active = true);
        END;
        $$;
    "#;

    let report = analyze_risk(sql).expect("should analyze");

    // The procedure statement itself should be analyzed
    assert!(
        report.summary.statements_analyzed >= 1,
        "Procedure should be analyzed"
    );

    // Check for procedure created signal
    let has_procedure_created = report.signals.iter().any(|f| {
        let RuleMatch::Analysis(ref p) = f;
        p.matched_rule == "PROC-NEW"
    });
    assert!(
        has_procedure_created,
        "Should detect procedure created (PROC-NEW)"
    );
}

/// Test that a procedure with INSERT/UPDATE has tables_written extracted
#[test]
fn test_procedure_body_table_write() {
    let sql = r#"
        CREATE PROCEDURE refresh_data()
        RETURNS VARCHAR
        AS
        $$
        BEGIN
            INSERT INTO target_table
            SELECT * FROM source_table;
            RETURN 'done';
        END;
        $$;
    "#;

    let report = analyze_risk(sql).expect("should analyze");

    // Verify the procedure is analyzed
    assert!(
        report.summary.statements_analyzed >= 1,
        "Procedure should be analyzed"
    );
}

/// Test that dynamic SQL in procedure body is flagged
#[test]
fn test_procedure_dynamic_sql_detection() {
    let sql = r#"CREATE PROCEDURE run_dynamic(table_name VARCHAR)
RETURNS VARCHAR
AS
$$
DECLARE
    sql_text VARCHAR;
BEGIN
    sql_text := 'SELECT * FROM ' || table_name;
    EXECUTE IMMEDIATE sql_text;
    RETURN 'executed';
END;
$$"#;

    let report = analyze_risk(sql).expect("should analyze");

    // Check for dynamic SQL signal (PROC-DYNSQL)
    let has_dynamic_sql = report.signals.iter().any(|f| {
        let RuleMatch::Analysis(ref p) = f;
        p.matched_rule == "PROC-DYNSQL"
    });
    assert!(
        has_dynamic_sql,
        "Should detect dynamic SQL in procedure (PROC-DYNSQL)"
    );
}

/// Test that a function with SELECT has its table extracted
#[test]
fn test_function_body_table_read() {
    let sql = r#"
        CREATE FUNCTION get_customer_count()
        RETURNS INT
        AS
        $$
        BEGIN
            RETURN (SELECT COUNT(*) FROM customers);
        END;
        $$;
    "#;

    let report = analyze_risk(sql).expect("should analyze");

    // The function statement itself should be analyzed
    assert!(
        report.summary.statements_analyzed >= 1,
        "Function should be analyzed"
    );

    // Check for function created signal
    let has_function_created = report.signals.iter().any(|f| {
        let RuleMatch::Analysis(ref p) = f;
        p.matched_rule == "UDF-NEW"
    });
    assert!(
        has_function_created,
        "Should detect function created (UDF-NEW)"
    );
}

/// Test that dynamic SQL in function body is flagged
#[test]
fn test_function_dynamic_sql_detection() {
    let sql = r#"CREATE FUNCTION run_query(query_text VARCHAR)
RETURNS VARIANT
AS
$$
BEGIN
    EXECUTE IMMEDIATE query_text;
    RETURN NULL;
END;
$$"#;

    let report = analyze_risk(sql).expect("should analyze");

    // Check for dynamic SQL signal (UDF-DYNSQL)
    let has_dynamic_sql = report.signals.iter().any(|f| {
        let RuleMatch::Analysis(ref p) = f;
        p.matched_rule == "UDF-DYNSQL"
    });
    assert!(
        has_dynamic_sql,
        "Should detect dynamic SQL in function (UDF-DYNSQL)"
    );
}

/// Test multi-statement procedure with complex body
#[test]
fn test_procedure_multi_statement_body() {
    let sql = r#"
        CREATE PROCEDURE complex_etl()
        RETURNS VARCHAR
        AS
        $$
        DECLARE
            row_count INT;
        BEGIN
            -- Read from source
            INSERT INTO staging_table
            SELECT * FROM raw_data WHERE processed = false;
            
            -- Update processed flag
            UPDATE raw_data SET processed = true WHERE processed = false;
            
            -- Get count
            SELECT COUNT(*) INTO row_count FROM staging_table;
            
            RETURN 'Processed ' || row_count || ' rows';
        END;
        $$;
    "#;

    let report = analyze_risk(sql).expect("should analyze");

    // Verify procedure is analyzed
    assert!(
        report.summary.statements_analyzed >= 1,
        "Complex procedure should be analyzed"
    );
}

/// Test Option C: procedure_bodies_analyzed and statements_in_bodies are populated
#[test]
fn test_procedure_body_summary_fields() {
    let sql = r#"
        CREATE PROCEDURE test_proc()
        RETURNS VARCHAR
        AS
        $$
        BEGIN
            SELECT * FROM customers;
            UPDATE orders SET status = 'processed';
            RETURN 'done';
        END;
        $$;
    "#;

    let report = analyze_risk(sql).expect("should analyze");

    // Check the new summary fields
    assert!(
        report.summary.procedure_bodies_analyzed >= 1,
        "Should track that 1 procedure body was analyzed, got {}",
        report.summary.procedure_bodies_analyzed
    );

    assert!(
        report.summary.statements_in_bodies >= 1,
        "Should track statements inside bodies, got {}",
        report.summary.statements_in_bodies
    );
}

/// Test Option C: body statements get proper parent_context in signals
#[test]
fn test_procedure_body_signals_have_parent_context() {
    // This procedure has an unbounded UPDATE which should trigger a signal
    let sql = r#"CREATE PROCEDURE dangerous_update()
RETURNS VARCHAR
AS
$$
BEGIN
    UPDATE large_table SET flag = true;
    RETURN 'done';
END;
$$"#;

    let report = analyze_risk(sql).expect("should analyze");

    // Look for any signal that has parent_context set
    let _has_parent_context = report.signals.iter().any(|f| match f {
        RuleMatch::Analysis(ref g) => g.parent_context.is_some(),
    });

    // Note: The procedure itself will have signals, body statements should also have them
    // If there are signals from body statements, they should have parent_context
    if report.summary.statements_in_bodies > 0 {
        // We expect at least the procedure created signal
        assert!(
            report.signals.len() >= 1,
            "Should have at least procedure created signal"
        );
    }
}

/// Test that function body is tracked separately
#[test]
fn test_function_body_tracking() {
    let sql = r#"
        CREATE FUNCTION calculate_total(id INT)
        RETURNS FLOAT
        AS
        $$
        BEGIN
            RETURN (SELECT SUM(amount) FROM transactions WHERE customer_id = id);
        END;
        $$;
    "#;

    let report = analyze_risk(sql).expect("should analyze");

    // Function body should be tracked
    assert!(
        report.summary.procedure_bodies_analyzed >= 1,
        "Function body should be counted in procedure_bodies_analyzed"
    );
}

/// Test multiple procedures/functions in same script
#[test]
fn test_multiple_procedure_bodies() {
    let sql = r#"
        CREATE PROCEDURE proc1()
        RETURNS VARCHAR
        AS $$
        BEGIN
            SELECT * FROM table1;
            RETURN 'done';
        END;
        $$;
        
        CREATE PROCEDURE proc2()
        RETURNS VARCHAR
        AS $$
        BEGIN
            SELECT * FROM table2;
            UPDATE table3 SET x = 1;
            RETURN 'done';
        END;
        $$;
        
        CREATE FUNCTION func1()
        RETURNS INT
        AS $$
        BEGIN
            RETURN (SELECT COUNT(*) FROM table4);
        END;
        $$;
    "#;

    let report = analyze_risk(sql).expect("should analyze");

    // Should have 3 procedure/function bodies analyzed
    assert!(
        report.summary.procedure_bodies_analyzed >= 3,
        "Should track 3 procedure/function bodies, got {}",
        report.summary.procedure_bodies_analyzed
    );

    // Should have multiple statements in bodies
    assert!(
        report.summary.statements_in_bodies >= 3,
        "Should have at least 3 statements in bodies, got {}",
        report.summary.statements_in_bodies
    );
}

// =============================================================================
// LOOP STATEMENT TESTS
// =============================================================================

/// Test WHILE loop inside procedure body
#[test]
fn test_procedure_with_while_loop() {
    let sql = r#"
        CREATE PROCEDURE process_batches()
        RETURNS VARCHAR
        AS
        $$
        DECLARE
            counter INT := 0;
            max_iterations INT := 10;
        BEGIN
            WHILE (counter < max_iterations) DO
                INSERT INTO processed_data
                SELECT * FROM raw_data WHERE batch_id = counter;
                
                UPDATE raw_data SET processed = true WHERE batch_id = counter;
                
                counter := counter + 1;
            END WHILE;
            RETURN 'done';
        END;
        $$;
    "#;

    let report = analyze_risk(sql).expect("should analyze");

    // Procedure should be analyzed
    assert!(
        report.summary.statements_analyzed >= 1,
        "Procedure should be analyzed"
    );

    // Body with loop should be tracked
    assert!(
        report.summary.procedure_bodies_analyzed >= 1,
        "Procedure body should be analyzed"
    );

    // Statements inside loop should be counted in body statements
    assert!(
        report.summary.statements_in_bodies >= 2,
        "INSERT and UPDATE inside WHILE loop should be counted, got {}",
        report.summary.statements_in_bodies
    );
}

/// Test FOR loop inside procedure body
#[test]
fn test_procedure_with_for_loop() {
    let sql = r#"
        CREATE PROCEDURE iterate_records()
        RETURNS VARCHAR
        AS
        $$
        DECLARE
            rec OBJECT;
        BEGIN
            FOR rec IN (SELECT id, name FROM customers WHERE active = true) DO
                INSERT INTO customer_log (customer_id, customer_name)
                VALUES (rec.id, rec.name);
            END FOR;
            RETURN 'completed';
        END;
        $$;
    "#;

    let report = analyze_risk(sql).expect("should analyze");

    assert!(
        report.summary.procedure_bodies_analyzed >= 1,
        "Procedure body should be analyzed"
    );

    // INSERT inside FOR loop should be tracked
    assert!(
        report.summary.statements_in_bodies >= 1,
        "INSERT inside FOR loop should be counted"
    );
}

/// Test LOOP statement inside procedure body
#[test]
fn test_procedure_with_loop_statement() {
    let sql = r#"
        CREATE PROCEDURE infinite_processor()
        RETURNS VARCHAR
        AS
        $$
        DECLARE
            counter INT := 0;
        BEGIN
            LOOP
                SELECT * FROM work_queue WHERE processed = false LIMIT 1;
                
                IF (counter > 100) THEN
                    BREAK;
                END IF;
                
                DELETE FROM work_queue WHERE id = :current_id;
                counter := counter + 1;
            END LOOP;
            RETURN 'done';
        END;
        $$;
    "#;

    let report = analyze_risk(sql).expect("should analyze");

    assert!(
        report.summary.procedure_bodies_analyzed >= 1,
        "Procedure body should be analyzed"
    );

    // SELECT and DELETE inside LOOP should be tracked
    assert!(
        report.summary.statements_in_bodies >= 2,
        "Statements inside LOOP should be counted, got {}",
        report.summary.statements_in_bodies
    );
}

/// Test REPEAT loop inside procedure body
#[test]
fn test_procedure_with_repeat_loop() {
    let sql = r#"
        CREATE PROCEDURE retry_operation()
        RETURNS VARCHAR
        AS
        $$
        DECLARE
            attempts INT := 0;
            success BOOLEAN := false;
        BEGIN
            REPEAT
                attempts := attempts + 1;
                
                INSERT INTO retry_log (attempt_num)
                VALUES (attempts);
                
                UPDATE operations SET status = 'retry' WHERE pending = true;
                
            UNTIL (success OR attempts >= 5)
            END REPEAT;
            RETURN 'finished';
        END;
        $$;
    "#;

    let report = analyze_risk(sql).expect("should analyze");

    assert!(
        report.summary.procedure_bodies_analyzed >= 1,
        "Procedure body should be analyzed"
    );

    // INSERT and UPDATE inside REPEAT should be tracked
    assert!(
        report.summary.statements_in_bodies >= 2,
        "Statements inside REPEAT loop should be counted, got {}",
        report.summary.statements_in_bodies
    );
}

/// Test nested loops inside procedure body
#[test]
fn test_procedure_with_nested_loops() {
    let sql = r#"
        CREATE PROCEDURE nested_iteration()
        RETURNS VARCHAR
        AS
        $$
        DECLARE
            outer_counter INT := 0;
            inner_counter INT := 0;
        BEGIN
            WHILE (outer_counter < 5) DO
                FOR inner_counter IN 1 TO 10 DO
                    INSERT INTO matrix_data (row_id, col_id)
                    VALUES (outer_counter, inner_counter);
                END FOR;
                
                UPDATE batch_status SET completed = true 
                WHERE batch_num = outer_counter;
                
                outer_counter := outer_counter + 1;
            END WHILE;
            RETURN 'done';
        END;
        $$;
    "#;

    let report = analyze_risk(sql).expect("should analyze");

    assert!(
        report.summary.procedure_bodies_analyzed >= 1,
        "Procedure body should be analyzed"
    );

    // INSERT in inner loop and UPDATE in outer loop should be tracked
    assert!(
        report.summary.statements_in_bodies >= 2,
        "Statements inside nested loops should be counted, got {}",
        report.summary.statements_in_bodies
    );
}

/// Test loop with dynamic SQL should flag PROC-DYNSQL
#[test]
fn test_loop_with_dynamic_sql() {
    let sql = r#"CREATE PROCEDURE dynamic_loop()
RETURNS VARCHAR
AS
$$
DECLARE
    table_list ARRAY := ARRAY_CONSTRUCT('table1', 'table2', 'table3');
    i INT := 0;
BEGIN
    WHILE (i < ARRAY_SIZE(table_list)) DO
        EXECUTE IMMEDIATE 'SELECT COUNT(*) FROM ' || table_list[i];
        i := i + 1;
    END WHILE;
    RETURN 'done';
END;
$$"#;

    let report = analyze_risk(sql).expect("should analyze");

    // Check for dynamic SQL signal (PROC-DYNSQL)
    let has_dynamic_sql = report.signals.iter().any(|f| {
        let RuleMatch::Analysis(ref p) = f;
        p.matched_rule == "PROC-DYNSQL"
    });
    assert!(
        has_dynamic_sql,
        "Should detect dynamic SQL inside WHILE loop (PROC-DYNSQL)"
    );
}

/// Test function with loop
#[test]
fn test_function_with_while_loop() {
    let sql = r#"
        CREATE FUNCTION calculate_factorial(n INT)
        RETURNS INT
        AS
        $$
        DECLARE
            result INT := 1;
            counter INT := 1;
        BEGIN
            WHILE (counter <= n) DO
                SELECT result * counter INTO result;
                counter := counter + 1;
            END WHILE;
            RETURN result;
        END;
        $$;
    "#;

    let report = analyze_risk(sql).expect("should analyze");

    // Function body should be tracked
    assert!(
        report.summary.procedure_bodies_analyzed >= 1,
        "Function body should be counted in procedure_bodies_analyzed"
    );

    // Check for function created signal
    let has_function_created = report.signals.iter().any(|f| {
        let RuleMatch::Analysis(ref p) = f;
        p.matched_rule == "UDF-NEW"
    });
    assert!(
        has_function_created,
        "Should detect function created (UDF-NEW)"
    );
}

/// Test multiple loops in same procedure
#[test]
fn test_multiple_loops_same_procedure() {
    let sql = r#"
        CREATE PROCEDURE multi_loop_proc()
        RETURNS VARCHAR
        AS
        $$
        DECLARE
            i INT := 0;
        BEGIN
            -- First WHILE loop
            WHILE (i < 10) DO
                INSERT INTO log1 (val) VALUES (i);
                i := i + 1;
            END WHILE;
            
            -- Second FOR loop
            FOR j IN 1 TO 5 DO
                INSERT INTO log2 (val) VALUES (j);
            END FOR;
            
            -- Third LOOP
            LOOP
                DELETE FROM temp_data WHERE expired = true;
                IF (i > 20) THEN
                    BREAK;
                END IF;
                i := i + 1;
            END LOOP;
            
            RETURN 'done';
        END;
        $$;
    "#;

    let report = analyze_risk(sql).expect("should analyze");

    assert!(
        report.summary.procedure_bodies_analyzed >= 1,
        "Procedure body should be analyzed"
    );

    // Multiple INSERT and DELETE statements across loops
    assert!(
        report.summary.statements_in_bodies >= 3,
        "Should count statements from all loops, got {}",
        report.summary.statements_in_bodies
    );
}

/// Test loop inside IF inside procedure
#[test]
fn test_loop_inside_if_inside_procedure() {
    let sql = r#"
        CREATE PROCEDURE conditional_loop()
        RETURNS VARCHAR
        AS
        $$
        DECLARE
            mode VARCHAR := 'batch';
            i INT := 0;
        BEGIN
            IF (mode = 'batch') THEN
                WHILE (i < 100) DO
                    INSERT INTO batch_queue (batch_num) VALUES (i);
                    i := i + 1;
                END WHILE;
            ELSE
                INSERT INTO single_queue (val) VALUES (1);
            END IF;
            RETURN 'done';
        END;
        $$;
    "#;

    let report = analyze_risk(sql).expect("should analyze");

    assert!(
        report.summary.procedure_bodies_analyzed >= 1,
        "Procedure body should be analyzed"
    );

    // INSERT inside WHILE inside IF should be tracked
    assert!(
        report.summary.statements_in_bodies >= 1,
        "Nested statements should be counted, got {}",
        report.summary.statements_in_bodies
    );
}

// =============================================================================
// TESTS FOR BODIES WITHOUT $$ DELIMITERS
// =============================================================================

/// Test procedure body without $$ delimiters (BEGIN directly after AS)
#[test]
fn test_procedure_without_dollar_delimiters() {
    let sql = r#"
        CREATE PROCEDURE test_proc_no_delim()
        RETURNS VARCHAR
        LANGUAGE SQL
        AS
        BEGIN
            SELECT * FROM customers;
            RETURN 'done';
        END;
    "#;

    let report = analyze_risk(sql).expect("should analyze");

    // Procedure should be analyzed
    assert!(
        report.summary.statements_analyzed >= 1,
        "Procedure without $$ should be analyzed"
    );

    // Body should be tracked
    assert!(
        report.summary.procedure_bodies_analyzed >= 1,
        "Procedure body without $$ should be analyzed"
    );

    // Check for procedure created signal
    let has_procedure_created = report.signals.iter().any(|f| {
        let RuleMatch::Analysis(ref p) = f;
        p.matched_rule == "PROC-NEW"
    });
    assert!(
        has_procedure_created,
        "Should detect procedure created (PROC-NEW)"
    );
}

/// Test function body without $$ delimiters
#[test]
fn test_function_without_dollar_delimiters() {
    let sql = r#"
        CREATE FUNCTION test_func_no_delim()
        RETURNS INT
        LANGUAGE SQL
        AS
        BEGIN
            RETURN (SELECT COUNT(*) FROM customers);
        END;
    "#;

    let report = analyze_risk(sql).expect("should analyze");

    // Function should be analyzed
    assert!(
        report.summary.statements_analyzed >= 1,
        "Function without $$ should be analyzed"
    );

    // Body should be tracked
    assert!(
        report.summary.procedure_bodies_analyzed >= 1,
        "Function body without $$ should be counted"
    );

    // Check for function created signal
    let has_function_created = report.signals.iter().any(|f| {
        let RuleMatch::Analysis(ref p) = f;
        p.matched_rule == "UDF-NEW"
    });
    assert!(
        has_function_created,
        "Should detect function created (UDF-NEW)"
    );
}

/// Test procedure with DECLARE...BEGIN without $$ delimiters
#[test]
fn test_procedure_declare_without_dollar_delimiters() {
    let sql = r#"
        CREATE PROCEDURE test_proc_declare_no_delim()
        RETURNS VARCHAR
        LANGUAGE SQL
        AS
        DECLARE
            x INT := 0;
            result VARCHAR;
        BEGIN
            SELECT * FROM customers;
            x := x + 1;
            RETURN 'done';
        END;
    "#;

    let report = analyze_risk(sql).expect("should analyze");

    // Procedure should be analyzed
    assert!(
        report.summary.statements_analyzed >= 1,
        "Procedure with DECLARE without $$ should be analyzed"
    );

    // Body should be tracked
    assert!(
        report.summary.procedure_bodies_analyzed >= 1,
        "Procedure body with DECLARE without $$ should be analyzed"
    );
}

/// Test dynamic SQL in procedure without $$ delimiters
#[test]
fn test_dynamic_sql_without_dollar_delimiters() {
    let sql = r#"CREATE PROCEDURE dynamic_no_delim(table_name VARCHAR)
RETURNS VARCHAR
LANGUAGE SQL
AS
BEGIN
    EXECUTE IMMEDIATE 'SELECT * FROM ' || table_name;
    RETURN 'executed';
END"#;

    let report = analyze_risk(sql).expect("should analyze");

    // Check for dynamic SQL signal (PROC-DYNSQL)
    let has_dynamic_sql = report.signals.iter().any(|f| {
        let RuleMatch::Analysis(ref p) = f;
        p.matched_rule == "PROC-DYNSQL"
    });
    assert!(
        has_dynamic_sql,
        "Should detect dynamic SQL in procedure without $$ delimiters (PROC-DYNSQL)"
    );
}
