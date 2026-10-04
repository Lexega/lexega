// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

// Complex stored procedure tests based on Snowflake documentation patterns
use lexega_syntax::ast::AstStmt;
use lexega_syntax::parse_sql;

#[test]
fn parse_procedure_with_nested_loops_and_cursors() {
    let src = r#"
CREATE OR REPLACE PROCEDURE process_batches(batch_size INTEGER)
RETURNS VARCHAR
LANGUAGE SQL
AS
DECLARE
    total_rows INTEGER DEFAULT 0;
    batch_count INTEGER DEFAULT 0;
    current_batch INTEGER DEFAULT 0;
    done BOOLEAN DEFAULT FALSE;
    c1 CURSOR FOR SELECT id, name FROM employees WHERE active = TRUE;
    row_id INTEGER;
    row_name VARCHAR;
BEGIN
    OPEN c1;
    
    WHILE (NOT done) DO
        LET current_batch := 0;
        
        WHILE (current_batch < batch_size) DO
            FETCH c1 INTO row_id, row_name;
            
            IF (SQLNOTFOUND) THEN
                LET done := TRUE;
                BREAK;
            END IF;
            
            INSERT INTO processed_employees (id, name, processed_at)
            VALUES (row_id, row_name, CURRENT_TIMESTAMP());
            
            LET current_batch := current_batch + 1;
            LET total_rows := total_rows + 1;
        END WHILE;
        
        LET batch_count := batch_count + 1;
    END WHILE;
    
    CLOSE c1;
    
    RETURN 'Processed ' || total_rows || ' rows in ' || batch_count || ' batches';
END;
"#;
    let script =
        parse_sql(src).expect("failed to parse complex procedure with nested loops and cursors");
    assert_eq!(script.stmts.len(), 1);

    match &script.stmts[0] {
        AstStmt::CreateProcedure(proc_stmt) => {
            let name_span = proc_stmt.name_span;
            let body_span = proc_stmt.body_span;
            let name = &src[name_span.start as usize..name_span.end as usize];
            assert_eq!(name, "process_batches");

            let body_text = &src[body_span.start as usize..body_span.end as usize];
            assert!(body_text.to_uppercase().contains("DECLARE"));
            assert!(body_text.to_uppercase().contains("CURSOR"));
            assert!(body_text.to_uppercase().contains("WHILE"));
            assert!(body_text.to_uppercase().contains("SQLNOTFOUND"));
            assert!(body_text.to_uppercase().contains("BREAK"));
        }
        _ => panic!("expected CreateProcedure statement"),
    }
}

#[test]
fn parse_procedure_with_exception_handling_and_cleanup() {
    let src = r#"
CREATE OR REPLACE PROCEDURE safe_data_migration(source_table VARCHAR, dest_table VARCHAR)
RETURNS VARCHAR
LANGUAGE SQL
AS
DECLARE
    rows_copied INTEGER DEFAULT 0;
    error_msg VARCHAR;
    migration_log_id INTEGER;
BEGIN
    -- Start migration logging
    INSERT INTO migration_log (start_time, status) 
    VALUES (CURRENT_TIMESTAMP(), 'RUNNING')
    RETURNING id INTO migration_log_id;
    
    -- Copy data directly
    INSERT INTO IDENTIFIER(:dest_table) 
    SELECT * FROM IDENTIFIER(:source_table);
    LET rows_copied := SQLROWCOUNT;
    
    -- Validate data
    IF (rows_copied = 0) THEN
        RAISE EXCEPTION -20001, 'No data found in source table';
    END IF;
    
    -- Update log
    UPDATE migration_log 
    SET end_time = CURRENT_TIMESTAMP(), 
        status = 'SUCCESS',
        rows_migrated = :rows_copied
    WHERE id = :migration_log_id;
    
    RETURN 'Success: migrated ' || rows_copied || ' rows';
EXCEPTION
    WHEN STATEMENT_ERROR THEN
        LET error_msg := SQLERRM;
        
        -- Update log with error
        UPDATE migration_log 
        SET end_time = CURRENT_TIMESTAMP(), 
            status = 'FAILED',
            error_message = :error_msg
        WHERE id = :migration_log_id;
        
        RAISE;
    WHEN OTHER THEN
        -- Handle unexpected errors
        LET error_msg := SQLERRM;
        UPDATE migration_log 
        SET status = 'FAILED',
            error_message = :error_msg
        WHERE id = :migration_log_id;
        RAISE;
END;
"#;
    let script = parse_sql(src).expect("failed to parse procedure with exception handling");
    assert_eq!(script.stmts.len(), 1);

    match &script.stmts[0] {
        AstStmt::CreateProcedure(proc_stmt) => {
            let body_span = proc_stmt.body_span;
            let body_text = &src[body_span.start as usize..body_span.end as usize];
            assert!(body_text.to_uppercase().contains("EXCEPTION"));
            assert!(body_text.to_uppercase().contains("RAISE"));
            assert!(body_text.to_uppercase().contains("SQLROWCOUNT"));
            assert!(body_text.to_uppercase().contains("IDENTIFIER"));
        }
        _ => panic!("expected CreateProcedure statement"),
    }
}

#[test]
fn parse_procedure_with_dynamic_sql() {
    let src = r#"
CREATE OR REPLACE PROCEDURE dynamic_table_analyzer(table_name VARCHAR, schema_name VARCHAR)
RETURNS VARIANT
LANGUAGE SQL
AS
DECLARE
    sql_stmt VARCHAR;
    row_count INTEGER;
    column_count INTEGER;
    result VARIANT;
    query_id VARCHAR;
BEGIN
    -- Build dynamic SQL for row count
    LET sql_stmt := 'SELECT COUNT(*) FROM ' || :schema_name || '.' || :table_name;
    
    -- Execute dynamic SQL and capture query ID
    EXECUTE IMMEDIATE :sql_stmt INTO :row_count;
    LET query_id := SQLID;
    
    -- Build dynamic SQL for column count
    LET sql_stmt := 'SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ?';
    
    EXECUTE IMMEDIATE :sql_stmt 
        USING (schema_name, table_name) 
        INTO :column_count;
    
    -- Build result variant
    LET result := OBJECT_CONSTRUCT(
        'table_name', :table_name,
        'schema_name', :schema_name,
        'row_count', :row_count,
        'column_count', :column_count,
        'query_id', :query_id,
        'analyzed_at', CURRENT_TIMESTAMP()
    );
    
    RETURN result;
END;
"#;
    let script = parse_sql(src).expect("failed to parse procedure with dynamic SQL");
    assert_eq!(script.stmts.len(), 1);

    match &script.stmts[0] {
        AstStmt::CreateProcedure(proc_stmt) => {
            let body_span = proc_stmt.body_span;
            let body_text = &src[body_span.start as usize..body_span.end as usize];
            assert!(body_text.to_uppercase().contains("EXECUTE IMMEDIATE"));
            assert!(body_text.to_uppercase().contains("USING"));
            assert!(body_text.to_uppercase().contains("SQLID"));
            assert!(body_text.to_uppercase().contains("OBJECT_CONSTRUCT"));
        }
        _ => panic!("expected CreateProcedure statement"),
    }
}

#[test]
fn parse_procedure_with_resultset_operations() {
    let src = r#"
CREATE OR REPLACE PROCEDURE get_employee_summary(dept_id INTEGER)
RETURNS TABLE(employee_id INTEGER, full_name VARCHAR, salary NUMBER)
LANGUAGE SQL
AS
DECLARE
    emp_cursor CURSOR FOR SELECT id, first_name, last_name, salary FROM employees WHERE department_id = :dept_id;
    result_data RESULTSET;
BEGIN
    -- Open cursor and get resultset
    OPEN emp_cursor;
    
    -- Convert cursor to resultset
    LET result_data := RESULTSET_FROM_CURSOR(emp_cursor);
    
    -- Process resultset if needed
    IF (SQLROWCOUNT > 0) THEN
        RETURN TABLE(result_data);
    ELSE
        -- Return empty resultset
        LET result_data := (SELECT NULL::INTEGER AS employee_id, NULL::VARCHAR AS full_name, NULL::NUMBER AS salary WHERE 1=0);
        RETURN TABLE(result_data);
    END IF;
END;
"#;
    let script = parse_sql(src).expect("failed to parse procedure with resultset");
    assert_eq!(script.stmts.len(), 1);

    match &script.stmts[0] {
        AstStmt::CreateProcedure(proc_stmt) => {
            let returns_span = proc_stmt.returns_span;
            let body_span = proc_stmt.body_span;
            let returns = &src[returns_span.start as usize..returns_span.end as usize];
            assert!(returns.to_uppercase().contains("TABLE"));

            let body_text = &src[body_span.start as usize..body_span.end as usize];
            assert!(body_text.to_uppercase().contains("RESULTSET"));
            assert!(body_text.to_uppercase().contains("CURSOR"));
        }
        _ => panic!("expected CreateProcedure statement"),
    }
}

#[test]
fn parse_procedure_with_case_statement() {
    let src = r#"
CREATE OR REPLACE PROCEDURE categorize_order(order_total NUMBER)
RETURNS VARCHAR
LANGUAGE SQL
AS
DECLARE
    category VARCHAR;
    discount_pct NUMBER DEFAULT 0;
BEGIN
    CASE
        WHEN order_total < 100 THEN
            LET category := 'SMALL';
            LET discount_pct := 0;
        WHEN order_total < 500 THEN
            LET category := 'MEDIUM';
            LET discount_pct := 5;
        WHEN order_total < 1000 THEN
            LET category := 'LARGE';
            LET discount_pct := 10;
        ELSE
            LET category := 'ENTERPRISE';
            LET discount_pct := 15;
    END CASE;
    
    RETURN category || ' order with ' || discount_pct || '% discount';
END;
"#;
    let script = parse_sql(src).expect("failed to parse procedure with CASE");
    assert_eq!(script.stmts.len(), 1);

    match &script.stmts[0] {
        AstStmt::CreateProcedure(proc_stmt) => {
            let body_span = proc_stmt.body_span;
            let body_text = &src[body_span.start as usize..body_span.end as usize];
            assert!(body_text.to_uppercase().contains("CASE"));
            assert!(body_text.to_uppercase().contains("WHEN"));
            assert!(body_text.to_uppercase().contains("END CASE"));
        }
        _ => panic!("expected CreateProcedure statement"),
    }
}

#[test]
fn parse_procedure_with_for_loop() {
    let src = r#"
CREATE OR REPLACE PROCEDURE iterate_results()
RETURNS INTEGER
LANGUAGE SQL
AS
DECLARE
    total INTEGER DEFAULT 0;
    rec RECORD;
BEGIN
    FOR rec IN (SELECT amount FROM transactions WHERE status = 'COMPLETE') DO
        LET total := total + rec.amount;
    END FOR;
    
    RETURN total;
END;
"#;
    let script = parse_sql(src).expect("failed to parse procedure with FOR loop");
    assert_eq!(script.stmts.len(), 1);

    match &script.stmts[0] {
        AstStmt::CreateProcedure(proc_stmt) => {
            let body_span = proc_stmt.body_span;
            let body_text = &src[body_span.start as usize..body_span.end as usize];
            assert!(body_text.to_uppercase().contains("FOR"));
            assert!(body_text.to_uppercase().contains("IN"));
            assert!(body_text.to_uppercase().contains("END FOR"));
        }
        _ => panic!("expected CreateProcedure statement"),
    }
}

#[test]
fn parse_procedure_with_repeat_loop() {
    let src = r#"
CREATE OR REPLACE PROCEDURE countdown_example(start_value INTEGER)
RETURNS VARCHAR
LANGUAGE SQL
AS
DECLARE
    counter INTEGER;
    iterations INTEGER DEFAULT 0;
BEGIN
    LET counter := start_value;
    
    REPEAT
        LET counter := counter - 1;
        LET iterations := iterations + 1;
        INSERT INTO log_table (iteration, counter_value) VALUES (:iterations, :counter);
    UNTIL (counter <= 0)
    END REPEAT;
    
    RETURN 'Completed ' || iterations || ' iterations';
END;
"#;
    let script = parse_sql(src).expect("failed to parse procedure with REPEAT loop");
    assert_eq!(script.stmts.len(), 1);

    match &script.stmts[0] {
        AstStmt::CreateProcedure(proc_stmt) => {
            let body_span = proc_stmt.body_span;
            let body_text = &src[body_span.start as usize..body_span.end as usize];
            assert!(body_text.to_uppercase().contains("REPEAT"));
            assert!(body_text.to_uppercase().contains("UNTIL"));
            assert!(body_text.to_uppercase().contains("END REPEAT"));
        }
        _ => panic!("expected CreateProcedure statement"),
    }
}

#[test]
fn parse_function_with_complex_logic() {
    let src = r#"
CREATE OR REPLACE FUNCTION calculate_bonus(employee_id INTEGER, base_salary NUMBER)
RETURNS NUMBER
LANGUAGE SQL
AS
DECLARE
    years_of_service INTEGER;
    performance_rating NUMBER;
    bonus NUMBER DEFAULT 0;
    bonus_pct NUMBER;
BEGIN
    -- Get employee info
    SELECT DATEDIFF(year, hire_date, CURRENT_DATE()), last_performance_rating
    INTO years_of_service, performance_rating
    FROM employees
    WHERE id = :employee_id;
    
    -- Calculate bonus percentage based on years of service
    CASE
        WHEN years_of_service < 2 THEN
            LET bonus_pct := 0.03;
        WHEN years_of_service < 5 THEN
            LET bonus_pct := 0.05;
        WHEN years_of_service < 10 THEN
            LET bonus_pct := 0.08;
        ELSE
            LET bonus_pct := 0.12;
    END CASE;
    
    -- Adjust for performance
    IF (performance_rating >= 4.5) THEN
        LET bonus_pct := bonus_pct * 1.5;
    ELSIF (performance_rating >= 3.5) THEN
        LET bonus_pct := bonus_pct * 1.2;
    ELSIF (performance_rating < 2.0) THEN
        LET bonus_pct := bonus_pct * 0.5;
    END IF;
    
    LET bonus := base_salary * bonus_pct;
    
    -- Cap bonus at 20% of salary
    IF (bonus > base_salary * 0.20) THEN
        LET bonus := base_salary * 0.20;
    END IF;
    
    RETURN bonus;
END;
"#;
    let script = parse_sql(src).expect("failed to parse function with complex logic");
    assert_eq!(script.stmts.len(), 1);

    match &script.stmts[0] {
        AstStmt::CreateFunction(func_stmt) => {
            let name_span = func_stmt.name_span;
            let body_span = func_stmt.body_span;
            let name = &src[name_span.start as usize..name_span.end as usize];
            assert_eq!(name, "calculate_bonus");

            let body_text = &src[body_span.start as usize..body_span.end as usize];
            assert!(body_text.to_uppercase().contains("CASE"));
            assert!(body_text.to_uppercase().contains("IF"));
            assert!(body_text.to_uppercase().contains("ELSIF"));
        }
        _ => panic!("expected CreateFunction statement"),
    }
}

#[test]
fn parse_procedure_with_transaction_control() {
    let src = r#"
CREATE OR REPLACE PROCEDURE multi_table_update(batch_id INTEGER)
RETURNS VARCHAR
LANGUAGE SQL
AS
DECLARE
    updated_count INTEGER DEFAULT 0;
BEGIN
    BEGIN TRANSACTION;
    
    -- Update main table
    UPDATE orders SET status = 'PROCESSED' WHERE batch_id = :batch_id;
    LET updated_count := SQLROWCOUNT;
    
    -- Update audit table
    INSERT INTO order_audit (batch_id, updated_count, updated_at)
    VALUES (:batch_id, :updated_count, CURRENT_TIMESTAMP());
    
    -- Update summary
    MERGE INTO batch_summary bs
    USING (SELECT :batch_id AS id, :updated_count AS cnt) src
    ON bs.batch_id = src.id
    WHEN MATCHED THEN
        UPDATE SET orders_processed = bs.orders_processed + src.cnt
    WHEN NOT MATCHED THEN
        INSERT (batch_id, orders_processed) VALUES (src.id, src.cnt);
    
    COMMIT;
    
    RETURN 'Updated ' || updated_count || ' orders';
EXCEPTION
    WHEN OTHER THEN
        ROLLBACK;
        RAISE;
END;
"#;
    let script = parse_sql(src).expect("failed to parse procedure with transaction control");
    assert_eq!(script.stmts.len(), 1);

    match &script.stmts[0] {
        AstStmt::CreateProcedure(proc_stmt) => {
            let body_span = proc_stmt.body_span;
            let body_text = &src[body_span.start as usize..body_span.end as usize];
            assert!(body_text.to_uppercase().contains("BEGIN TRANSACTION"));
            assert!(body_text.to_uppercase().contains("COMMIT"));
            assert!(body_text.to_uppercase().contains("ROLLBACK"));
            assert!(body_text.to_uppercase().contains("MERGE"));
        }
        _ => panic!("expected CreateProcedure statement"),
    }
}

#[test]
fn parse_procedure_with_continue_statement() {
    let src = r#"
CREATE OR REPLACE PROCEDURE process_valid_records()
RETURNS VARCHAR
LANGUAGE SQL
AS
DECLARE
    processed INTEGER DEFAULT 0;
    skipped INTEGER DEFAULT 0;
    rec RECORD;
BEGIN
    FOR rec IN (SELECT id, status, amount FROM orders) DO
        -- Skip invalid records
        IF (rec.status = 'CANCELLED' OR rec.amount <= 0) THEN
            LET skipped := skipped + 1;
            CONTINUE;
        END IF;
        
        -- Process valid record
        UPDATE orders SET processed = TRUE WHERE id = rec.id;
        LET processed := processed + 1;
    END FOR;
    
    RETURN 'Processed: ' || processed || ', Skipped: ' || skipped;
END;
"#;
    let script = parse_sql(src).expect("failed to parse procedure with CONTINUE");
    assert_eq!(script.stmts.len(), 1);

    match &script.stmts[0] {
        AstStmt::CreateProcedure(proc_stmt) => {
            let body_span = proc_stmt.body_span;
            let body_text = &src[body_span.start as usize..body_span.end as usize];
            assert!(body_text.to_uppercase().contains("CONTINUE"));
            assert!(body_text.to_uppercase().contains("FOR"));
        }
        _ => panic!("expected CreateProcedure statement"),
    }
}

// Additional function and procedure tests

#[test]
fn parse_minimal_function() {
    // Simplest possible function
    let src = r#"
CREATE OR REPLACE FUNCTION test_func(emp_id INTEGER)
RETURNS NUMBER
LANGUAGE SQL
AS
BEGIN
    RETURN 0;
END;
"#;
    let script = parse_sql(src);
    assert!(script.is_ok(), "failed to parse minimal function");
}

#[test]
fn parse_function_with_declare() {
    let src = r#"
CREATE OR REPLACE FUNCTION test_func(emp_id INTEGER)
RETURNS NUMBER
LANGUAGE SQL
AS
DECLARE
    years INTEGER;
BEGIN
    RETURN 0;
END;
"#;
    let script = parse_sql(src);
    assert!(script.is_ok(), "failed to parse function with DECLARE");
}

#[test]
fn parse_function_with_select_into() {
    let src = r#"
CREATE OR REPLACE FUNCTION test_func(emp_id INTEGER)
RETURNS NUMBER
LANGUAGE SQL
AS
DECLARE
    years INTEGER;
BEGIN
    SELECT DATEDIFF(year, hire_date, CURRENT_DATE())
    INTO years
    FROM employees
    WHERE id = :emp_id;
    
    RETURN years;
END;
"#;
    let script = parse_sql(src);
    assert!(script.is_ok(), "failed to parse function with SELECT INTO");
}

#[test]
fn parse_function_with_case_in_body() {
    let src = r#"
CREATE OR REPLACE FUNCTION test_func(years INTEGER)
RETURNS NUMBER
LANGUAGE SQL
AS
DECLARE
    pct NUMBER;
BEGIN
    CASE
        WHEN years < 2 THEN
            LET pct := 0.03;
        WHEN years < 5 THEN
            LET pct := 0.05;
        ELSE
            LET pct := 0.12;
    END CASE;
    
    RETURN pct;
END;
"#;
    let script = parse_sql(src);
    assert!(script.is_ok(), "failed to parse function with CASE");
}

#[test]
fn parse_procedure_with_language_sql() {
    let src = r#"
CREATE OR REPLACE PROCEDURE test_proc()
RETURNS VARCHAR
LANGUAGE SQL
AS
DECLARE
    x VARCHAR;
BEGIN
    LET x := 'test';
    RETURN x;
END;
"#;
    let script = parse_sql(src);
    assert!(
        script.is_ok(),
        "failed to parse CREATE PROCEDURE with LANGUAGE SQL"
    );
}

#[test]
fn parse_procedure_with_migration_logic() {
    let src = r#"
CREATE OR REPLACE PROCEDURE safe_data_migration(source_table VARCHAR, dest_table VARCHAR)
RETURNS VARCHAR
LANGUAGE SQL
AS
DECLARE
    rows_copied INTEGER DEFAULT 0;
    error_msg VARCHAR;
    migration_log_id INTEGER;
BEGIN
    -- Start migration logging
    INSERT INTO migration_log (start_time, status) 
    VALUES (CURRENT_TIMESTAMP(), 'RUNNING')
    RETURNING id INTO migration_log_id;
    
    -- Create temporary staging table
    CREATE TEMPORARY TABLE staging AS SELECT * FROM IDENTIFIER(:source_table) WHERE 1=0;
    
    -- Copy data in chunks
    INSERT INTO staging SELECT * FROM IDENTIFIER(:source_table);
    LET rows_copied := SQLROWCOUNT;
    
    -- Validate data
    IF (rows_copied = 0) THEN
        RAISE EXCEPTION -20001, 'No data found in source table';
    END IF;
    
    -- Move to destination
    INSERT INTO IDENTIFIER(:dest_table) SELECT * FROM staging;
    
    -- Update log
    UPDATE migration_log 
    SET end_time = CURRENT_TIMESTAMP(), 
        status = 'SUCCESS',
        rows_migrated = :rows_copied
    WHERE id = :migration_log_id;
    
    DROP TABLE staging;
    
    RETURN 'Success: migrated ' || rows_copied || ' rows';
EXCEPTION
    WHEN STATEMENT_ERROR THEN
        LET error_msg := SQLERRM;
        
        -- Clean up temporary table if it exists
        BEGIN TRANSACTION;
        DROP TABLE IF EXISTS staging;
        COMMIT;
        
        -- Update log with error
        UPDATE migration_log 
        SET end_time = CURRENT_TIMESTAMP(), 
            status = 'FAILED',
            error_message = :error_msg
        WHERE id = :migration_log_id;
        
        RAISE;
    WHEN OTHER THEN
        -- Handle unexpected errors
        LET error_msg := SQLERRM;
        UPDATE migration_log 
        SET status = 'FAILED',
            error_message = :error_msg
        WHERE id = :migration_log_id;
        RAISE;
END;
"#;
    let script = parse_sql(src);
    assert!(
        script.is_ok(),
        "failed to parse procedure with complex migration logic"
    );
}
