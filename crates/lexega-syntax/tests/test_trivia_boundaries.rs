// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

/// Synthetic tests for trivia handling at specific boundary points in the formatter.
/// These target edge cases that may not be fully covered by golden file tests:
/// - EOF trailing comments (no semicolon)
/// - Comments between MATCH_RECOGNIZE clauses (PATTERN/DEFINE)
/// - Comments around window frame boundaries
/// - Comments at subquery closing parens
/// - Comments in deeply nested contexts
///
/// These tests rely on the formatter's built-in verification (SpanTracker) which
/// validates that all source bytes are accounted for. If any comments were lost,
/// the formatter would fail during span validation.
use lexega_syntax::{format_sql_with_config, parse_stmt_from_str, FormatterConfig};

// ============================================================================
// EOF and Trailing Comment Tests
// ============================================================================

#[test]
fn test_eof_trailing_comment_no_semicolon() {
    let sql = "SELECT 1 AS x -- trailing comment at EOF";
    let formatted = format_sql_with_config(sql, &FormatterConfig::default())
        .expect("should format - SpanTracker validates no data loss");

    // Verify output is valid SQL
    parse_stmt_from_str(&formatted).expect("formatted output should parse");
}

#[test]
fn test_eof_block_comment_no_semicolon() {
    let sql = "SELECT 1 /* block at EOF */";
    let formatted = format_sql_with_config(sql, &FormatterConfig::default())
        .expect("should format - SpanTracker validates no data loss");

    // Verify output is valid SQL
    parse_stmt_from_str(&formatted).expect("formatted output should parse");
}

#[test]
fn test_eof_multiple_trailing_comments() {
    let sql = "SELECT 1 -- first\n-- second\n/* third */";
    let formatted = format_sql_with_config(sql, &FormatterConfig::default())
        .expect("should format - SpanTracker validates no data loss");

    // Verify output is valid SQL
    parse_stmt_from_str(&formatted).expect("formatted output should parse");
}

// ============================================================================
// MATCH_RECOGNIZE Trivia Tests
// ============================================================================

#[test]
fn test_match_recognize_pattern_define_comments() {
    let sql = r#"
SELECT * FROM t
MATCH_RECOGNIZE (
    /* before PATTERN */ PATTERN /* after PATTERN */ (A B) /* after pattern expr */
    /* before DEFINE */ DEFINE /* after DEFINE */ A AS a > 0 /* after A */, B AS b > 0 /* after B */
)
"#;
    let formatted = format_sql_with_config(sql, &FormatterConfig::default())
        .expect("should format - SpanTracker validates no data loss");

    // Verify output is valid SQL
    parse_stmt_from_str(&formatted).expect("formatted output should parse");
}

#[test]
fn test_match_recognize_measures_comments() {
    let sql = r#"
SELECT * FROM t
MATCH_RECOGNIZE (
    /* before MEASURES */ MEASURES /* after MEASURES */ 
        COUNT(*) /* after count */ AS /* after AS */ cnt /* after alias */
    PATTERN (A)
    DEFINE A AS a > 0
)
"#;
    let formatted = format_sql_with_config(sql, &FormatterConfig::default())
        .expect("should format - SpanTracker validates no data loss");

    // Verify output is valid SQL
    parse_stmt_from_str(&formatted).expect("formatted output should parse");
}

#[test]
fn test_match_recognize_one_row_per_match_comments() {
    let sql = r#"
SELECT * FROM t
MATCH_RECOGNIZE (
    /* before ONE ROW */ ONE /* after ONE */ ROW /* after ROW */ PER /* after PER */ MATCH /* after MATCH */
    PATTERN (A)
    DEFINE A AS a > 0
)
"#;
    let formatted = format_sql_with_config(sql, &FormatterConfig::default())
        .expect("should format - SpanTracker validates no data loss");

    // Verify output is valid SQL
    parse_stmt_from_str(&formatted).expect("formatted output should parse");
}

// ============================================================================
// Window Frame Boundary Tests
// ============================================================================

#[test]
fn test_window_frame_rows_between_comments() {
    let sql = r#"
SELECT 
    SUM(val) OVER (
        ORDER BY id
        /* before ROWS */ ROWS /* after ROWS */ 
        /* before BETWEEN */ BETWEEN /* after BETWEEN */ 
        /* before UNBOUNDED */ UNBOUNDED /* after UNBOUNDED */ 
        /* before PRECEDING */ PRECEDING /* after PRECEDING */ 
        /* before AND */ AND /* after AND */ 
        /* before CURRENT */ CURRENT /* after CURRENT */ 
        /* before ROW */ ROW /* after ROW */
    ) AS running_sum
FROM t
"#;
    let formatted = format_sql_with_config(sql, &FormatterConfig::default())
        .expect("should format - SpanTracker validates no data loss");

    // Verify output is valid SQL
    parse_stmt_from_str(&formatted).expect("formatted output should parse");
}

#[test]
fn test_window_frame_range_comments() {
    let sql = r#"
SELECT 
    AVG(val) OVER (
        ORDER BY ts
        /* before RANGE */ RANGE /* after RANGE */ 
        BETWEEN /* after BETWEEN */ 
        INTERVAL /* after INTERVAL */ '1' /* after value */ DAY /* after unit */ PRECEDING /* after preceding */
        AND CURRENT ROW
    ) AS moving_avg
FROM t
"#;
    let formatted = format_sql_with_config(sql, &FormatterConfig::default())
        .expect("should format - SpanTracker validates no data loss");

    // Verify output is valid SQL
    parse_stmt_from_str(&formatted).expect("formatted output should parse");
}

// ============================================================================
// Subquery and Paren Boundary Tests
// ============================================================================

#[test]
fn test_comments_at_subquery_close_paren() {
    let sql = r#"
SELECT (
    SELECT MAX(x)
    FROM inner_table
    /* comment before close paren */
) /* comment after close paren */ AS max_val
FROM outer_table
"#;
    let formatted = format_sql_with_config(sql, &FormatterConfig::default())
        .expect("should format - SpanTracker validates no data loss");

    // Verify output is valid SQL
    parse_stmt_from_str(&formatted).expect("formatted output should parse");
}

#[test]
fn test_comments_in_deeply_nested_subqueries() {
    let sql = r#"
SELECT (
    /* level 1 */ SELECT (
        /* level 2 */ SELECT (
            /* level 3 */ SELECT 1 /* innermost */
        ) /* close 3 */
    ) /* close 2 */
) /* close 1 */
FROM t
"#;
    let formatted = format_sql_with_config(sql, &FormatterConfig::default())
        .expect("should format - SpanTracker validates no data loss");

    // Verify output is valid SQL
    parse_stmt_from_str(&formatted).expect("formatted output should parse");
}

#[test]
fn test_comments_in_correlated_subquery() {
    let sql = r#"
SELECT *
FROM outer_t o
WHERE EXISTS (
    /* correlated subquery */ SELECT 1
    FROM inner_t i
    WHERE i.id /* join condition */ = /* equals */ o.id /* outer ref */
    /* end of exists */
)
"#;
    let formatted = format_sql_with_config(sql, &FormatterConfig::default())
        .expect("should format - SpanTracker validates no data loss");

    // Verify output is valid SQL
    parse_stmt_from_str(&formatted).expect("formatted output should parse");
}

// ============================================================================
// CTE and WITH Clause Trivia Tests
// ============================================================================

#[test]
fn test_cte_with_trailing_comma_comments() {
    let sql = r#"
WITH
    /* before cte1 */ cte1 AS /* after AS */ (
        SELECT 1
    ) /* after cte1 */ , /* after comma */
    /* before cte2 */ cte2 AS (
        SELECT 2
    ) /* after cte2 */
SELECT * FROM cte1
"#;
    let formatted = format_sql_with_config(sql, &FormatterConfig::default())
        .expect("should format - SpanTracker validates no data loss");

    // Verify output is valid SQL
    parse_stmt_from_str(&formatted).expect("formatted output should parse");
}

#[test]
fn test_recursive_cte_comments() {
    let sql = r#"
WITH RECURSIVE /* after RECURSIVE */ cte /* after name */ (n) /* after cols */ AS /* after AS */ (
    /* base case */ SELECT 1
    UNION ALL
    /* recursive case */ SELECT n + 1 FROM cte WHERE n < 10
)
SELECT * FROM cte
"#;
    let formatted = format_sql_with_config(sql, &FormatterConfig::default())
        .expect("should format - SpanTracker validates no data loss");

    // Verify output is valid SQL
    parse_stmt_from_str(&formatted).expect("formatted output should parse");
}

// ============================================================================
// CASE Expression Trivia Tests
// ============================================================================

#[test]
fn test_case_when_then_else_comments() {
    let sql = r#"
SELECT
    CASE /* after CASE */
        /* before WHEN */ WHEN /* after WHEN */ x = 1 /* after condition */ THEN /* after THEN */ 'one' /* after result */
        WHEN x = 2 THEN 'two'
        /* before ELSE */ ELSE /* after ELSE */ 'other' /* after else result */
    END /* after END */ AS result
FROM t
"#;
    let formatted = format_sql_with_config(sql, &FormatterConfig::default())
        .expect("should format - SpanTracker validates no data loss");

    // Verify output is valid SQL
    parse_stmt_from_str(&formatted).expect("formatted output should parse");
}

#[test]
fn test_searched_case_nested_comments() {
    let sql = r#"
SELECT
    CASE
        WHEN (/* in condition */ x > 0 AND y > 0 /* end condition */) THEN 'positive'
        WHEN (x < 0) THEN 'negative'
        ELSE /* default */ 'zero'
    END
FROM t
"#;
    let formatted = format_sql_with_config(sql, &FormatterConfig::default())
        .expect("should format - SpanTracker validates no data loss");

    // Verify output is valid SQL
    parse_stmt_from_str(&formatted).expect("formatted output should parse");
}

// ============================================================================
// SET Operations Trivia Tests
// ============================================================================

#[test]
fn test_union_intersect_except_comments() {
    let sql = r#"
SELECT 1 /* first query */
/* before UNION */ UNION /* after UNION */ ALL /* after ALL */
/* before second */ SELECT 2 /* second query */
INTERSECT /* after INTERSECT */
SELECT 3 /* third query */
EXCEPT /* after EXCEPT */
SELECT 4 /* fourth query */
"#;
    let formatted = format_sql_with_config(sql, &FormatterConfig::default())
        .expect("should format - SpanTracker validates no data loss");

    // Verify output is valid SQL
    parse_stmt_from_str(&formatted).expect("formatted output should parse");
}

// ============================================================================
// Complex Expression Trivia Tests
// ============================================================================

#[test]
fn test_array_literal_comments() {
    let sql = r#"
SELECT [
    /* first */ 1, /* after 1 */
    /* second */ 2, /* after 2 */
    /* third */ 3 /* after 3 */
] /* after array */ AS arr
FROM t
"#;
    let formatted = format_sql_with_config(sql, &FormatterConfig::default())
        .expect("should format - SpanTracker validates no data loss");

    // Verify output is valid SQL
    parse_stmt_from_str(&formatted).expect("formatted output should parse");
}

#[test]
fn test_object_literal_comments() {
    let sql = r#"
SELECT OBJECT_CONSTRUCT(
    /* key1 */ 'name', /* sep */ 'John', /* val1 */
    'age', 30 /* val2 */
) /* after object */ AS obj
FROM t
"#;
    let formatted = format_sql_with_config(sql, &FormatterConfig::default())
        .expect("should format - SpanTracker validates no data loss");

    // Verify output is valid SQL
    parse_stmt_from_str(&formatted).expect("formatted output should parse");
}

// ============================================================================
// DML Statement Trivia Tests (INSERT, UPDATE, DELETE)
// ============================================================================

#[test]
fn test_insert_values_comments() {
    let sql = r#"
INSERT /* after INSERT */ INTO /* after INTO */ my_table /* table name */ (
    /* before id */ id /* col1 */, /* comma1 */
    /* before name */ name /* col2 */, /* comma2 */
    /* before value */ value /* col3 */ /* after cols */
) /* close cols */ VALUES /* after VALUES */ (
    /* before val1 */ 1 /* val1 */, /* comma1 */
    /* before val2 */ 'test' /* val2 */, /* comma2 */
    /* before val3 */ 100 /* val3 */ /* after values */
) /* close values */
"#;
    let formatted = format_sql_with_config(sql, &FormatterConfig::default())
        .expect("should format - SpanTracker validates no data loss");

    // Verify output is valid SQL
    parse_stmt_from_str(&formatted).expect("formatted output should parse");
}

#[test]
fn test_insert_select_comments() {
    let sql = r#"
INSERT /* after INSERT */ INTO /* after INTO */ target_table /* table */
SELECT /* after SELECT */
    /* before col1 */ id /* col1 */, /* comma */
    /* before col2 */ name /* col2 */
FROM /* after FROM */ source_table /* source */
WHERE /* after WHERE */ status /* col */ = /* equals */ 'active' /* value */
"#;
    let formatted = format_sql_with_config(sql, &FormatterConfig::default())
        .expect("should format - SpanTracker validates no data loss");

    // Verify output is valid SQL
    parse_stmt_from_str(&formatted).expect("formatted output should parse");
}

#[test]
fn test_update_comments() {
    let sql = r#"
UPDATE /* after UPDATE */ my_table /* table */ SET /* after SET */
    /* before col1 */ col1 /* col1 */ = /* equals1 */ 'new_value' /* val1 */, /* comma */
    /* before col2 */ col2 /* col2 */ = /* equals2 */ col2 /* old */ + /* plus */ 1 /* increment */
WHERE /* after WHERE */
    /* before condition */ id /* id col */ > /* gt */ 100 /* hundred */ AND /* and */
    /* before condition2 */ status /* status col */ = /* eq */ 'active' /* value */
"#;
    let formatted = format_sql_with_config(sql, &FormatterConfig::default())
        .expect("should format - SpanTracker validates no data loss");

    // Verify output is valid SQL
    parse_stmt_from_str(&formatted).expect("formatted output should parse");
}

#[test]
fn test_delete_comments() {
    let sql = r#"
DELETE /* after DELETE */ FROM /* after FROM */ my_table /* table */
WHERE /* after WHERE */
    /* before condition */ id /* id col */ IN /* in */ (
        /* before val1 */ 1 /* val1 */, /* comma1 */
        /* before val2 */ 2 /* val2 */, /* comma2 */
        /* before val3 */ 3 /* val3 */
    ) /* close in */
    OR /* or keyword */
    /* before condition2 */ created_at /* col */ < /* lt */ CURRENT_DATE /* func */ () /* args */
"#;
    let formatted = format_sql_with_config(sql, &FormatterConfig::default())
        .expect("should format - SpanTracker validates no data loss");

    // Verify output is valid SQL
    parse_stmt_from_str(&formatted).expect("formatted output should parse");
}

#[test]
fn test_merge_full_comments() {
    let sql = r#"
MERGE /* after MERGE */ INTO /* after INTO */ target /* table */ USING /* after USING */ (
    SELECT /* in source */ id /* col */, /* comma */ value /* col2 */ FROM /* from */ src /* src table */
) /* close source */ source /* alias */ ON /* after ON */ (
    target /* qual */ . /* dot */ id /* col */ = /* eq */ source /* qual2 */ . /* dot2 */ id /* col2 */
) /* close on */
WHEN /* when1 */ MATCHED /* matched */ THEN /* then1 */ UPDATE /* update */ SET /* set */
    value /* col */ = /* eq */ source /* qual */ . /* dot */ value /* col2 */
WHEN /* when2 */ NOT /* not */ MATCHED /* matched2 */ THEN /* then2 */ INSERT /* insert */ (
    id /* col1 */, /* comma */ value /* col2 */
) /* close cols */ VALUES /* values */ (
    source /* qual */ . /* dot */ id /* val1 */, /* comma */ source /* qual2 */ . /* dot2 */ value /* val2 */
) /* close values */
"#;
    let formatted = format_sql_with_config(sql, &FormatterConfig::default())
        .expect("should format - SpanTracker validates no data loss");

    // Verify output is valid SQL
    parse_stmt_from_str(&formatted).expect("formatted output should parse");
}

// ============================================================================
// COPY INTO Statement Trivia Tests
// ============================================================================

#[test]
fn test_copy_into_table_comments() {
    let sql = r#"
COPY /* after COPY */ INTO /* after INTO */ my_table /* table */ (
    /* before col1 */ col1 /* col1 */, /* comma */
    /* before col2 */ col2 /* col2 */
) /* close cols */
FROM /* after FROM */ @my_stage /* stage */ / /* slash */ path /* path */ / /* slash */ file.csv /* file */
FILE_FORMAT /* format kw */ = /* eq */ (
    /* before type */ TYPE /* type kw */ = /* eq */ 'CSV' /* csv */, /* comma */
    /* before skip */ SKIP_HEADER /* skip kw */ = /* eq */ 1 /* value */
) /* close format */
"#;
    let formatted = format_sql_with_config(sql, &FormatterConfig::default())
        .expect("should format - SpanTracker validates no data loss");

    // Verify output is valid SQL
    parse_stmt_from_str(&formatted).expect("formatted output should parse");
}

#[test]
fn test_copy_into_location_comments() {
    let sql = r#"
COPY /* after COPY */ INTO /* after INTO */ @my_stage /* stage */ / /* slash */ output /* path */
FROM /* after FROM */ (
    SELECT /* in select */ * /* star */ FROM /* from */ my_table /* table */
) /* close select */
FILE_FORMAT /* format kw */ = /* eq */ ( /* open format */
    TYPE /* type */ = /* eq */ 'PARQUET' /* parquet */
) /* close format */
"#;
    let formatted = format_sql_with_config(sql, &FormatterConfig::default())
        .expect("should format - SpanTracker validates no data loss");

    // Verify output is valid SQL
    parse_stmt_from_str(&formatted).expect("formatted output should parse");
}

// ============================================================================
// CREATE PROCEDURE/FUNCTION Trivia Tests
// ============================================================================

#[test]
fn test_create_procedure_comments() {
    let sql = r#"
CREATE /* create */ OR /* or */ REPLACE /* replace */ PROCEDURE /* procedure */ my_proc /* name */ (
    /* before param */ p1 /* param1 */ NUMBER /* type */
) /* close params */
RETURNS /* returns */ NUMBER /* return type */
LANGUAGE /* language */ SQL /* sql */
AS /* as */
/* before $$ */ $$ /* open delimiter */
/* body comment */
BEGIN /* begin */
    RETURN /* return */ p1 /* param */ + /* plus */ 1 /* one */;
END /* end */;
/* after body */ $$ /* close delimiter */
"#;
    let formatted = format_sql_with_config(sql, &FormatterConfig::default())
        .expect("should format - SpanTracker validates no data loss");

    // Verify output is valid SQL
    parse_stmt_from_str(&formatted).expect("formatted output should parse");
}

#[test]
fn test_create_function_comments() {
    let sql = r#"
CREATE /* create */ FUNCTION /* function */ my_func /* name */ (
    /* before param */ x /* param1 */ NUMBER /* type */
) /* close params */
RETURNS /* returns */ NUMBER /* return type */
AS /* as */ /* before $$ */ $$ /* open $$ */
    /* inside body */ x /* x */ * /* multiply */ 2 /* two */
/* before close */ $$ /* close $$ */
"#;
    let formatted = format_sql_with_config(sql, &FormatterConfig::default())
        .expect("should format - SpanTracker validates no data loss");

    // Verify output is valid SQL
    parse_stmt_from_str(&formatted).expect("formatted output should parse");
}

// ============================================================================
// FLATTEN and LATERAL Trivia Tests
// ============================================================================

#[test]
fn test_flatten_comments() {
    let sql = r#"
SELECT /* select */
    /* before f */ f /* alias */ . /* dot */ value /* col */ :: /* cast */ STRING /* type */
FROM /* from */
    my_table /* table */ t /* alias */, /* comma */
    /* before lateral */ LATERAL /* lateral */ FLATTEN /* flatten */ (
        /* before input */ INPUT /* input kw */ => /* arrow */ t /* qual */ . /* dot */ json_col /* col */
    ) /* close flatten */ f /* alias */
"#;
    let formatted = format_sql_with_config(sql, &FormatterConfig::default())
        .expect("should format - SpanTracker validates no data loss");

    // Verify output is valid SQL
    parse_stmt_from_str(&formatted).expect("formatted output should parse");
}

#[test]
fn test_lateral_subquery_comments() {
    let sql = r#"
SELECT /* select */ * /* star */
FROM /* from */
    my_table /* table */ t /* alias */, /* comma */
    /* before lateral */ LATERAL /* lateral */ (
        SELECT /* inner select */ * /* star */
        FROM /* inner from */ other_table /* other */
        WHERE /* where */ id /* id */ = /* eq */ t /* outer */ . /* dot */ ref_id /* ref */
    ) /* close lateral */ sub /* alias */
"#;
    let formatted = format_sql_with_config(sql, &FormatterConfig::default())
        .expect("should format - SpanTracker validates no data loss");

    // Verify output is valid SQL
    parse_stmt_from_str(&formatted).expect("formatted output should parse");
}

// ============================================================================
// Scripting Statements Trivia Tests
// ============================================================================

#[test]
fn test_declare_comments() {
    let sql = r#"
DECLARE /* declare */
    /* before var1 */ var1 /* var1 */ NUMBER /* type */ := /* assign */ 10 /* value */; /* semi */
    /* before var2 */ var2 /* var2 */ STRING /* type */ DEFAULT /* default */ 'test' /* value */; /* semi */
BEGIN /* begin */
    SELECT /* select */ var1 /* var1 */;
END /* end */;
"#;
    let formatted = format_sql_with_config(sql, &FormatterConfig::default())
        .expect("should format - SpanTracker validates no data loss");

    // Verify output is valid SQL
    parse_stmt_from_str(&formatted).expect("formatted output should parse");
}

#[test]
fn test_if_statement_comments() {
    let sql = r#"
BEGIN /* begin */
    /* before if */ IF /* if */ (
        /* condition */ x /* x */ > /* gt */ 0 /* zero */
    ) /* close cond */ THEN /* then */
        /* in then */ SELECT /* select */ 'positive' /* value */;
    /* before elseif */ ELSEIF /* elseif */ (
        x /* x */ < /* lt */ 0 /* zero */
    ) /* close cond */ THEN /* then */
        SELECT /* select */ 'negative' /* value */;
    /* before else */ ELSE /* else */
        SELECT /* select */ 'zero' /* value */;
    /* before end if */ END /* end */ IF /* if */;
END /* end */;
"#;
    let formatted = format_sql_with_config(sql, &FormatterConfig::default())
        .expect("should format - SpanTracker validates no data loss");

    // Verify output is valid SQL
    parse_stmt_from_str(&formatted).expect("formatted output should parse");
}

#[test]
fn test_while_loop_comments() {
    let sql = r#"
BEGIN /* begin */
    /* before while */ WHILE /* while */ (
        /* condition */ counter /* counter */ < /* lt */ 10 /* ten */
    ) /* close cond */ DO /* do */
        /* in loop */ LET /* set */ counter /* counter */ := /* eq */ counter /* counter */ + /* plus */ 1 /* one */;
    /* before end while */ END /* end */ WHILE /* while */;
END /* end */;
"#;
    let formatted = format_sql_with_config(sql, &FormatterConfig::default())
        .expect("should format - SpanTracker validates no data loss");

    // Verify output is valid SQL
    parse_stmt_from_str(&formatted).expect("formatted output should parse");
}

#[test]
fn test_for_loop_comments() {
    let sql = r#"
BEGIN /* begin */
    /* before for */ FOR /* for */ rec /* rec */ IN /* in */ (
        SELECT /* select */ * /* star */ FROM /* from */ my_table /* table */
    ) /* close cursor */ DO /* do */
        /* in loop */ INSERT /* insert */ INTO /* into */ output /* output */ VALUES /* values */ (
            rec /* rec */ . /* dot */ id /* id */
        ) /* close values */;
    /* before end for */ END /* end */ FOR /* for */;
END /* end */;
"#;
    let formatted = format_sql_with_config(sql, &FormatterConfig::default())
        .expect("should format - SpanTracker validates no data loss");

    // Verify output is valid SQL
    parse_stmt_from_str(&formatted).expect("formatted output should parse");
}

// ============================================================================
// Transaction Statement Trivia Tests
// ============================================================================

#[test]
fn test_transaction_comments() {
    let sql = r#"
BEGIN /* begin */ TRANSACTION /* transaction */ NAME /* name */ my_txn /* txn name */;
/* statement 1 */ INSERT /* insert */ INTO /* into */ t /* table */ VALUES /* values */ ( 1 /* value */ );
/* statement 2 */ UPDATE /* update */ t /* table */ SET /* set */ x /* col */ = /* eq */ 2 /* value */;
COMMIT /* commit */ WORK /* work */;
"#;
    let formatted = format_sql_with_config(sql, &FormatterConfig::default())
        .expect("should format - SpanTracker validates no data loss");

    // Verify output is valid SQL
    parse_stmt_from_str(&formatted).expect("formatted output should parse");
}

#[test]
fn test_rollback_comments() {
    let sql = r#"
BEGIN /* begin */ TRANSACTION /* transaction */;
UPDATE /* update */ accounts /* table */ SET /* set */ balance /* col */ = /* eq */ balance /* col */ - /* minus */ 100 /* value */;
/* before rollback */ ROLLBACK /* rollback */ WORK /* work */;
"#;
    let formatted = format_sql_with_config(sql, &FormatterConfig::default())
        .expect("should format - SpanTracker validates no data loss");

    // Verify output is valid SQL
    parse_stmt_from_str(&formatted).expect("formatted output should parse");
}

// ============================================================================
// VALUES Clause and Multi-Insert Trivia Tests
// ============================================================================

#[test]
fn test_values_clause_comments() {
    let sql = r#"
SELECT /* select */ * /* star */ FROM /* from */ (
    VALUES /* values */
        /* row1 */ ( /* open1 */ 1 /* val1 */, /* comma */ 'a' /* val2 */ ) /* close1 */, /* comma */
        /* row2 */ ( /* open2 */ 2 /* val1 */, /* comma */ 'b' /* val2 */ ) /* close2 */, /* comma */
        /* row3 */ ( /* open3 */ 3 /* val1 */, /* comma */ 'c' /* val2 */ ) /* close3 */
) /* close values */ AS /* as */ t /* alias */ (
    /* before col1 */ id /* col1 */, /* comma */
    /* before col2 */ name /* col2 */
) /* close cols */
"#;
    let formatted = format_sql_with_config(sql, &FormatterConfig::default())
        .expect("should format - SpanTracker validates no data loss");

    // Verify output is valid SQL
    parse_stmt_from_str(&formatted).expect("formatted output should parse");
}

#[test]
fn test_multi_insert_all_comments() {
    let sql = r#"
INSERT /* insert */ ALL /* all */
    /* before into1 */ INTO /* into1 */ table1 /* table1 */ VALUES /* values1 */ (
        id /* col1 */, /* comma */ name /* col2 */
    ) /* close1 */
    /* before into2 */ INTO /* into2 */ table2 /* table2 */ (
        /* before col */ col1 /* col1 */
    ) /* close cols */ VALUES /* values2 */ (
        value /* col */
    ) /* close2 */
SELECT /* select */ * /* star */ FROM /* from */ source /* source */
"#;
    let formatted = format_sql_with_config(sql, &FormatterConfig::default())
        .expect("should format - SpanTracker validates no data loss");

    // Verify output is valid SQL
    parse_stmt_from_str(&formatted).expect("formatted output should parse");
}
