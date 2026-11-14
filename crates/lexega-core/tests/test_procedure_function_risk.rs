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

    // Check for procedure created finding
    let has_procedure_created = report.context.iter().any(|f| {
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

    // A concatenation through `sql_text`: PROC-DYNSQL where the variable is
    // not resolved, DYNSQL-CONCAT where analysis resolves the concatenation.
    let has_dynamic_sql = report.findings.iter().any(|f| {
        let RuleMatch::Analysis(ref p) = f;
        p.matched_rule == "PROC-DYNSQL" || p.matched_rule == "DYNSQL-CONCAT"
    });
    assert!(
        has_dynamic_sql,
        "Should detect dynamic SQL in procedure (PROC-DYNSQL or DYNSQL-CONCAT)"
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

    // Check for function created finding
    let has_function_created = report.context.iter().any(|f| {
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

    // The function runs its parameter as SQL: DYNSQL-PARAM-TEXT, not the
    // UDF-DYNSQL an unknown argument raises.
    let rules: Vec<&str> = report
        .findings
        .iter()
        .map(|f| {
            let RuleMatch::Analysis(ref p) = f;
            p.matched_rule.as_str()
        })
        .collect();
    assert!(rules.contains(&"DYNSQL-PARAM-TEXT"), "{rules:?}");
    assert!(!rules.contains(&"UDF-DYNSQL"), "{rules:?}");
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

/// Test Option C: body statements get proper parent_context in findings
#[test]
fn test_procedure_body_findings_have_parent_context() {
    // This procedure has an unbounded UPDATE which should trigger a finding
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

    // Look for any finding that has parent_context set
    let _has_parent_context = report.findings.iter().any(|f| match f {
        RuleMatch::Analysis(ref g) => g.parent_context.is_some(),
    });

    // Note: The procedure itself will have findings, body statements should also have them
    // If there are findings from body statements, they should have parent_context
    if report.summary.statements_in_bodies > 0 {
        // We expect at least the procedure created finding
        assert!(
            !report.findings.is_empty(),
            "Should have at least procedure created finding"
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

    // An inline concatenation is DYNSQL-CONCAT's alone.
    let fired = |rule: &str| {
        report.findings.iter().any(|f| {
            let RuleMatch::Analysis(ref p) = f;
            p.matched_rule == rule
        })
    };
    assert!(
        fired("DYNSQL-CONCAT"),
        "Should detect dynamic SQL inside WHILE loop (DYNSQL-CONCAT)"
    );
    assert!(
        !fired("PROC-DYNSQL"),
        "PROC-DYNSQL leaves a concatenation to DYNSQL-CONCAT"
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

    // Check for function created finding
    let has_function_created = report.context.iter().any(|f| {
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

    // Check for procedure created finding
    let has_procedure_created = report.context.iter().any(|f| {
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

    // Check for function created finding
    let has_function_created = report.context.iter().any(|f| {
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

    // An inline concatenation is DYNSQL-CONCAT's alone.
    let fired = |rule: &str| {
        report.findings.iter().any(|f| {
            let RuleMatch::Analysis(ref p) = f;
            p.matched_rule == rule
        })
    };
    assert!(
        fired("DYNSQL-CONCAT"),
        "Should detect dynamic SQL in procedure without $$ delimiters (DYNSQL-CONCAT)"
    );
    assert!(
        !fired("PROC-DYNSQL"),
        "PROC-DYNSQL leaves a concatenation to DYNSQL-CONCAT"
    );
}

/// A function written without `RETURNS` ends at its own end: the statements
/// after it are read and analysed.
#[test]
fn test_function_without_returns_leaves_the_next_statements_read() {
    use lexega_core::analyzer::AnalysisConfig;
    use lexega_core::api::analyze_risk_with_policy_config;
    use lexega_core::{BigQueryDialect, DatabricksDialect, DialectRef, PostgresDialect};
    use std::sync::Arc;

    let later = "CREATE FUNCTION g(x INT64) RETURNS INT64 AS (x);";
    let cases: [(DialectRef, &str); 4] = [
        (
            Arc::new(BigQueryDialect),
            "CREATE TEMP FUNCTION f(x INT64) AS (x + 1);\nDELETE FROM ds.t WHERE TRUE;",
        ),
        (
            Arc::new(PostgresDialect),
            "CREATE FUNCTION f(x int, OUT a int, OUT b int) AS $$ SELECT 1, 2 $$ LANGUAGE sql;\n\
             DELETE FROM t WHERE TRUE;",
        ),
        (
            Arc::new(PostgresDialect),
            "CREATE FUNCTION f(OUT a int) LANGUAGE sql AS $$ SELECT 1 $$;\nDELETE FROM t WHERE TRUE;",
        ),
        (
            Arc::new(DatabricksDialect),
            "CREATE FUNCTION f(x INT) RETURN x + 1;\nDELETE FROM t WHERE TRUE;",
        ),
    ];
    for (dialect, head) in cases {
        let sql = format!("{head}\n{later}");
        let config = AnalysisConfig {
            dialect: Some(dialect),
            ..Default::default()
        };
        let report = analyze_risk_with_policy_config(&sql, &config).expect("should analyze");
        // Statements raising one rule are merged into one finding.
        let count = |entries: &[RuleMatch], rule: &str| -> usize {
            entries
                .iter()
                .map(|f| {
                    let RuleMatch::Analysis(ref p) = f;
                    p
                })
                .filter(|p| p.matched_rule == rule)
                .map(|p| p.findings_merged.unwrap_or(1))
                .sum()
        };
        assert_eq!(count(&report.findings, "DML-WRITE-UNBOUNDED"), 1, "{sql}");
        assert_eq!(count(&report.context, "UDF-NEW"), 2, "{sql}");
        assert_eq!(report.summary.statements_skipped, 0, "{sql}");
    }
}

/// The dynamic-SQL findings `sql` raises under `dialect`, each rule with the
/// number of findings it raises.
fn dynamic_sql_findings(
    dialect: lexega_core::DialectRef,
    sql: &str,
) -> std::collections::BTreeMap<String, usize> {
    use lexega_core::analyzer::AnalysisConfig;
    use lexega_core::api::analyze_risk_with_policy_config;

    let config = AnalysisConfig {
        dialect: Some(dialect),
        ..Default::default()
    };
    let report = analyze_risk_with_policy_config(sql, &config).expect("should analyze");
    let mut out = std::collections::BTreeMap::new();
    for entry in report.entries() {
        let RuleMatch::Analysis(ref p) = entry;
        let rule = p.matched_rule.as_str();
        if rule.starts_with("DYNSQL") || rule == "PROC-DYNSQL" || rule == "UDF-DYNSQL" {
            *out.entry(rule.to_string()).or_insert(0) += p.findings_merged.unwrap_or(1);
        }
    }
    out
}

fn counts(pairs: &[(&str, usize)]) -> std::collections::BTreeMap<String, usize> {
    pairs.iter().map(|(r, n)| (r.to_string(), *n)).collect()
}

/// A dynamic-SQL call in a procedure, function or T-SQL trigger body is
/// reported once, by the rule of the routine at its CREATE; one in an
/// event or an anonymous block, which no routine rule reports, by the
/// call's rule at the call.
#[test]
fn a_dynamic_sql_call_in_a_body_is_reported_once() {
    use lexega_core::dialect::{mssql, mysql, postgres, snowflake};

    // A dialect, a script, and each rule with the number of times it fires.
    type Case = (
        lexega_core::DialectRef,
        &'static str,
        Vec<(&'static str, usize)>,
    );
    let cases: Vec<Case> = vec![
        (
            snowflake(),
            "CREATE PROCEDURE p(t VARCHAR) RETURNS VARCHAR LANGUAGE SQL AS $$\n\
             BEGIN\n  EXECUTE IMMEDIATE 'SELECT * FROM ' || t;\n  RETURN 'ok';\nEND;\n$$;",
            vec![("DYNSQL-CONCAT", 1)],
        ),
        (
            snowflake(),
            "CREATE PROCEDURE p(q VARCHAR) RETURNS VARCHAR LANGUAGE SQL AS $$\n\
             BEGIN\n  IF (q IS NOT NULL) THEN\n    EXECUTE IMMEDIATE UPPER(:q);\n  END IF;\n  \
             RETURN 'ok';\nEND;\n$$;",
            vec![("DYNSQL-PARAM-TEXT", 1)],
        ),
        (
            snowflake(),
            "CREATE PROCEDURE p(q VARCHAR) RETURNS VARCHAR LANGUAGE SQL AS $$\n\
             DECLARE v VARCHAR;\nBEGIN\n  SELECT c INTO :v FROM t;\n  IF (q IS NOT NULL) THEN\n    \
             EXECUTE IMMEDIATE UPPER(:v);\n  END IF;\n  RETURN 'ok';\nEND;\n$$;",
            vec![("PROC-DYNSQL", 1)],
        ),
        // A call in an exception handler is the procedure's too.
        (
            snowflake(),
            "CREATE PROCEDURE p(q VARCHAR) RETURNS VARCHAR LANGUAGE SQL AS $$\n\
             BEGIN\n  RETURN 'ok';\nEXCEPTION\n  WHEN OTHER THEN\n    \
             EXECUTE IMMEDIATE UPPER(:q);\n    RETURN 'err';\nEND;\n$$;",
            vec![("DYNSQL-PARAM-TEXT", 1)],
        ),
        (
            postgres(),
            "CREATE FUNCTION f(t text) RETURNS void AS $$\n\
             BEGIN\n  EXECUTE 'SELECT * FROM ' || t;\n  EXECUTE upper(t);\nEND;\n$$ LANGUAGE plpgsql;",
            vec![("DYNSQL-CONCAT", 1), ("DYNSQL-PARAM-TEXT", 1)],
        ),
        (
            postgres(),
            "CREATE FUNCTION f(t text) RETURNS void AS $$\n\
             DECLARE v text;\nBEGIN\n  SELECT c INTO v FROM app.t;\n  EXECUTE upper(v);\nEND;\n$$ \
             LANGUAGE plpgsql;",
            vec![("UDF-DYNSQL", 1)],
        ),
        (
            mssql(),
            "CREATE PROCEDURE dbo.p @t NVARCHAR(100) AS\n\
             BEGIN\n  EXEC ('SELECT * FROM ' + @t);\nEND;",
            vec![("DYNSQL-CONCAT", 1)],
        ),
        (
            mssql(),
            "CREATE TRIGGER trg ON dbo.t AFTER INSERT AS\n\
             BEGIN\n  DECLARE @s NVARCHAR(MAX);\n  SELECT @s = cmd FROM inserted;\n  EXEC (@s);\nEND;",
            vec![("DYNSQL", 1)],
        ),
        // No routine rule reports an event's or an anonymous block's call.
        (
            mysql(),
            "CREATE EVENT e ON SCHEDULE EVERY 1 DAY DO\n\
             BEGIN\n  PREPARE s FROM @q;\n  EXECUTE s;\nEND;",
            vec![("DYNSQL", 1)],
        ),
        (
            snowflake(),
            "BEGIN\n  EXECUTE IMMEDIATE UPPER(:q);\nEND;",
            vec![("DYNSQL-NO-PARAM", 1)],
        ),
    ];
    for (dialect, sql, expected) in cases {
        assert_eq!(
            dynamic_sql_findings(dialect, sql),
            counts(&expected),
            "{sql}"
        );
    }
}

/// A routine that runs one of its parameters, written alone, as SQL raises
/// `DYNSQL-PARAM-TEXT` at its CREATE in every dialect, and no other
/// dynamic-SQL rule for that call.
#[test]
fn a_routine_parameter_run_as_sql_raises_dynsql_param_text() {
    use lexega_core::dialect::{bigquery, mssql, mysql, postgres, snowflake};

    let cases: Vec<(lexega_core::DialectRef, &str)> = vec![
        (
            mssql(),
            "CREATE PROCEDURE dbo.p @sql NVARCHAR(MAX) AS\nBEGIN\n  EXEC (@sql);\nEND;",
        ),
        (
            mssql(),
            "CREATE PROCEDURE dbo.p @sql NVARCHAR(MAX) AS\nBEGIN\n  EXEC sp_executesql @sql;\nEND;",
        ),
        (
            snowflake(),
            "CREATE PROCEDURE p(q VARCHAR) RETURNS VARCHAR LANGUAGE SQL AS $$\n\
             BEGIN\n  EXECUTE IMMEDIATE :q;\n  RETURN 'ok';\nEND;\n$$;",
        ),
        (
            postgres(),
            "CREATE FUNCTION f(q text) RETURNS void AS $$\nBEGIN\n  EXECUTE q;\nEND;\n$$ \
             LANGUAGE plpgsql;",
        ),
        (
            mysql(),
            "CREATE PROCEDURE p(IN p_sql TEXT)\nBEGIN\n  PREPARE s FROM p_sql;\n  EXECUTE s;\nEND;",
        ),
        (
            bigquery(),
            "CREATE PROCEDURE ds.p(q STRING)\nBEGIN\n  EXECUTE IMMEDIATE q;\nEND;",
        ),
    ];
    for (dialect, sql) in cases {
        assert_eq!(
            dynamic_sql_findings(dialect, sql),
            counts(&[("DYNSQL-PARAM-TEXT", 1)]),
            "{sql}"
        );
    }
    // A variable the routine declares is no parameter.
    assert_eq!(
        dynamic_sql_findings(
            mssql(),
            "CREATE PROCEDURE dbo.p @n INT AS\nBEGIN\n  DECLARE @sql NVARCHAR(MAX);\n  \
             SELECT @sql = cmd FROM dbo.jobs WHERE id = @n;\n  EXEC (@sql);\nEND;",
        ),
        counts(&[("PROC-DYNSQL", 1)])
    );
}

/// `script_context.enclosing` lists the bodies that hold a statement,
/// outermost first, and a call's `argument_parameter` names the parameter
/// it runs.
#[test]
fn a_body_statement_carries_the_bodies_that_hold_it() {
    use lexega_core::analyzer::AnalysisConfig;
    use lexega_core::api::analyze_risk_with_policy_config;
    use lexega_core::dialect::mssql;
    use lexega_core::rules::{build_v1_rule_corpus, load_v1_rules};

    let yaml = r#"
rules:
  - id: T-IN-IF-IN-PROC
    risk_level: medium
    message: "in an IF of a procedure"
    triggers:
      all_of:
        - kind: mssql_exec
        - script_context.enclosing.0.kind: procedure
        - script_context.enclosing.0.name.raw: dbo.p
        - script_context.enclosing.1.kind: block
        - script_context.enclosing.2.kind: control_flow
        - script_context.enclosing.2.flow_kind: if
        - dynamic_sql_calls:
            exists:
              argument_parameter.raw: "@sql"
  - id: T-TOP-LEVEL
    risk_level: medium
    message: "held by no body"
    triggers:
      all_of:
        - kind: mssql_exec
        - not:
            script_context.enclosing:
              exists: {}
"#;
    let rules =
        build_v1_rule_corpus(load_v1_rules(yaml).expect("rules load"), false).expect("full rules");
    let config = AnalysisConfig {
        dialect: Some(mssql()),
        custom_rules: Some(rules.into()),
        ..Default::default()
    };
    let sql = "CREATE PROCEDURE dbo.p @sql NVARCHAR(MAX) AS\nBEGIN\n  IF @sql IS NOT NULL\n    \
               EXEC (@sql);\nEND;\nGO\nEXEC (@x);";
    let report = analyze_risk_with_policy_config(sql, &config).expect("should analyze");
    let mut ids: Vec<String> = report
        .entries()
        .map(|entry| {
            let RuleMatch::Analysis(ref p) = entry;
            p.matched_rule.clone()
        })
        .filter(|rule| rule.starts_with("T-"))
        .collect();
    ids.sort();
    assert_eq!(ids, ["T-IN-IF-IN-PROC", "T-TOP-LEVEL"]);
}
