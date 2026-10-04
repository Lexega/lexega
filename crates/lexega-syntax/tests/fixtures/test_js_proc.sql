CREATE OR REPLACE PROCEDURE log_row_count(table_name STRING)
RETURNS STRING
LANGUAGE JAVASCRIPT
EXECUTE AS CALLER
AS
$$
    // Count the rows of the table named by the argument.
    var stmt = snowflake.createStatement({
        sqlText: "SELECT COUNT(*) FROM IDENTIFIER(?)",
        binds: [TABLE_NAME]
    });
    var rs = stmt.execute();
    rs.next();
    return "rows: " + rs.getColumnValue(1);
$$;
