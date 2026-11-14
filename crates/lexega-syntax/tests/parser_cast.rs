// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

// Tests for CAST, TRY_CAST, and :: operator
use lexega_syntax::parse_stmt_from_str;

#[test]
fn test_cast_basic() {
    let sql = "SELECT CAST(id AS VARCHAR) FROM users;";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Failed to parse basic CAST");
}

#[test]
fn test_cast_with_precision() {
    let sql = "SELECT CAST(id AS VARCHAR(50)) FROM users;";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Failed to parse CAST with precision");
}

#[test]
fn test_cast_with_precision_and_scale() {
    let sql = "SELECT CAST('9.8765' AS NUMBER(5,2)) FROM data;";
    let result = parse_stmt_from_str(sql);
    assert!(
        result.is_some(),
        "Failed to parse CAST with precision and scale"
    );
}

#[test]
fn test_cast_to_integer() {
    let sql = "SELECT CAST(amount AS INTEGER) FROM orders;";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Failed to parse CAST to INTEGER");
}

#[test]
fn test_cast_to_date() {
    let sql = "SELECT CAST('2024-05-09' AS DATE) FROM events;";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Failed to parse CAST to DATE");
}

#[test]
fn test_cast_to_timestamp() {
    let sql = "SELECT CAST(date_col AS TIMESTAMP) FROM logs;";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Failed to parse CAST to TIMESTAMP");
}

#[test]
fn test_cast_to_decimal() {
    let sql = "SELECT CAST(price AS DECIMAL(10,2)) FROM products;";
    let result = parse_stmt_from_str(sql);
    assert!(
        result.is_some(),
        "Failed to parse CAST to DECIMAL with precision and scale"
    );
}

#[test]
fn test_cast_nested_expression() {
    let sql = "SELECT CAST(amount * 1.1 AS NUMBER(10,2)) FROM orders;";
    let result = parse_stmt_from_str(sql);
    assert!(
        result.is_some(),
        "Failed to parse CAST with nested expression"
    );
}

#[test]
fn test_try_cast_basic() {
    let sql = "SELECT TRY_CAST(value AS INTEGER) FROM data;";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Failed to parse basic TRY_CAST");
}

#[test]
fn test_try_cast_with_precision() {
    let sql = "SELECT TRY_CAST(text AS VARCHAR(100)) FROM strings;";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Failed to parse TRY_CAST with precision");
}

#[test]
fn test_try_cast_with_precision_and_scale() {
    let sql = "SELECT TRY_CAST(value AS NUMBER(10,4)) FROM measurements;";
    let result = parse_stmt_from_str(sql);
    assert!(
        result.is_some(),
        "Failed to parse TRY_CAST with precision and scale"
    );
}

#[test]
fn test_try_cast_returns_null_on_failure() {
    let sql = "SELECT TRY_CAST('invalid' AS DATE) FROM data;";
    let result = parse_stmt_from_str(sql);
    assert!(
        result.is_some(),
        "Failed to parse TRY_CAST that would return NULL"
    );
}

#[test]
fn test_double_colon_cast_basic() {
    let sql = "SELECT id::VARCHAR FROM users;";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Failed to parse :: cast operator");
}

#[test]
fn test_double_colon_cast_with_precision() {
    let sql = "SELECT id::VARCHAR(50) FROM users;";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Failed to parse :: cast with precision");
}

#[test]
fn test_double_colon_cast_with_precision_and_scale() {
    let sql = "SELECT amount::NUMBER(10,2) FROM orders;";
    let result = parse_stmt_from_str(sql);
    assert!(
        result.is_some(),
        "Failed to parse :: cast with precision and scale"
    );
}

#[test]
fn test_double_colon_cast_to_date() {
    let sql = "SELECT '2024-05-09'::DATE FROM events;";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Failed to parse :: cast to DATE");
}

#[test]
fn test_double_colon_cast_to_integer() {
    let sql = "SELECT value::INTEGER FROM data;";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Failed to parse :: cast to INTEGER");
}

#[test]
fn test_double_colon_cast_column_reference() {
    let sql = "SELECT users.id::VARCHAR FROM users;";
    let result = parse_stmt_from_str(sql);
    assert!(
        result.is_some(),
        "Failed to parse :: cast on qualified column"
    );
}

#[test]
fn test_cast_in_where_clause() {
    let sql = "SELECT * FROM users WHERE CAST(age AS VARCHAR) = '25';";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Failed to parse CAST in WHERE clause");
}

#[test]
fn test_double_colon_in_where_clause() {
    let sql = "SELECT * FROM orders WHERE amount::VARCHAR LIKE '100%';";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Failed to parse :: cast in WHERE clause");
}

#[test]
fn test_cast_with_function_call() {
    let sql = "SELECT CAST(COUNT(*) AS VARCHAR) FROM users;";
    let result = parse_stmt_from_str(sql);
    assert!(result.is_some(), "Failed to parse CAST with function call");
}

#[test]
fn test_try_cast_with_coalesce() {
    let sql =
        "SELECT TRY_CAST(value AS INTEGER) FROM data WHERE TRY_CAST(value AS INTEGER) IS NOT NULL;";
    let result = parse_stmt_from_str(sql);
    assert!(
        result.is_some(),
        "Failed to parse TRY_CAST in WHERE with IS NOT NULL"
    );
}

#[test]
fn test_multiple_casts_in_select() {
    let sql = "SELECT CAST(id AS VARCHAR), amount::NUMBER(10,2), TRY_CAST(date AS DATE) FROM data;";
    let result = parse_stmt_from_str(sql);
    assert!(
        result.is_some(),
        "Failed to parse multiple different cast types in SELECT"
    );
}

#[test]
fn test_cast_in_comparison() {
    let sql = "SELECT * FROM users WHERE CAST(age AS INTEGER) > 18;";
    let result = parse_stmt_from_str(sql);
    assert!(
        result.is_some(),
        "Failed to parse CAST in comparison expression"
    );
}

#[test]
fn test_double_colon_in_arithmetic() {
    let sql = "SELECT amount::NUMBER(10,2) * 1.1 FROM orders;";
    let result = parse_stmt_from_str(sql);
    assert!(
        result.is_some(),
        "Failed to parse :: cast in arithmetic expression"
    );
}

// Note: CAST with scalar subquery requires careful parenthesis handling
// Example that works: SELECT CAST(COUNT(*) AS VARCHAR) FROM users;

#[test]
fn test_cast_case_expression() {
    let sql =
        "SELECT CAST(CASE WHEN age > 18 THEN 'adult' ELSE 'minor' END AS VARCHAR(10)) FROM users;";
    let result = parse_stmt_from_str(sql);
    assert!(
        result.is_some(),
        "Failed to parse CAST with CASE expression"
    );
}

const CONVERSION_FORMS: [(&str, &str); 5] = [
    (
        "mssql",
        "select convert(varchar( 10 ),Name ,120) a, try_convert(decimal( 10 ,2 ), Name) b, CONVERT(Int, Name), convert(NVARCHAR(max), Name), Convert(Date, Name, 23) from Users where TRY_CONVERT(int, Name) = 1;",
    ),
    (
        "mssql",
        "select CONVERT( /* to */ INT /* t */ , name) from t; select {fn CONVERT(Name, SQL_VARCHAR)} from t;",
    ),
    (
        "mysql",
        "select convert(Name, signed) a, CONVERT(Name,CHAR( 10 )) b, convert(Name, decimal(10,2)) from Users;",
    ),
    (
        "redshift",
        "select convert(integer, Name), CONVERT(varchar(10),Name) from Users;",
    ),
    ("snowflake", "select convert(Int, Name) from Users;"),
];

/// The arguments of the call in the first select item of `sql`, read in
/// `dialect`: `type <text>` for a data type, `unit` / `keyword` for a no
/// value, `<KEYWORD> value|type|name <text>` for one a keyword introduces,
/// `value <text>` for any other.
fn conversion_arguments(sql: &str, dialect: &str) -> Vec<String> {
    use lexega_syntax::ast::{AstFunctionArg, AstProjectionKind, ProjectionItemKind};
    use lexega_syntax::{AstExpr, AstStmt};
    let dialect = lexega_syntax::dialect_from_name(dialect).expect("dialect");
    let script = lexega_syntax::parse_sql_with_dialect(sql, dialect.as_ref()).expect("parses");
    let Some(AstStmt::Select(select)) = script.stmts.first() else {
        panic!("not a SELECT: {sql}");
    };
    let AstProjectionKind::Columns(items) = &select.projection.kind else {
        panic!("no select list: {sql}");
    };
    let ProjectionItemKind::SelectItem(item) = &items[0].kind else {
        panic!("no select item: {sql}");
    };
    let AstExpr::FunctionCall { args, .. } = &item.expr else {
        panic!("no call: {sql}");
    };
    let text = |span: lexega_syntax::Span| &sql[span.start as usize..span.end as usize];
    args.iter()
        .map(|arg| match arg.as_ref() {
            AstFunctionArg::DataType { span, .. } => format!("type {}", text(*span)),
            AstFunctionArg::NonValue {
                value: lexega_syntax::ast::AstNonValue::Unit(_),
                span,
            } => format!("unit {}", text(*span)),
            AstFunctionArg::NonValue {
                value: lexega_syntax::ast::AstNonValue::Keyword(_),
                span,
            } => format!("keyword {}", text(*span)),
            AstFunctionArg::Positional(expr) => format!("value {}", text(expr.span())),
            AstFunctionArg::Introduced {
                keyword_span,
                value,
            } => {
                let what = match value {
                    lexega_syntax::ast::AstIntroducedValue::Expr(_) => "value",
                    lexega_syntax::ast::AstIntroducedValue::DataType { .. } => "type",
                    lexega_syntax::ast::AstIntroducedValue::Name(_) => "name",
                };
                format!(
                    "{} {what} {}",
                    text(*keyword_span).to_ascii_uppercase(),
                    text(value.span())
                )
            }
            other @ (AstFunctionArg::Named { .. }
            | AstFunctionArg::Lambda { .. }
            | AstFunctionArg::AliasedArg { .. }
            | AstFunctionArg::BulkArg { .. }
            | AstFunctionArg::Unparsed { .. }
            | AstFunctionArg::Table { .. }) => format!("other {other:?}"),
        })
        .collect()
}

#[test]
fn a_conversion_type_argument_is_read_as_a_type() {
    for (dialect, sql, expected) in [
        (
            "mssql",
            "SELECT CONVERT(INT, name) FROM t",
            &["type INT", "value name"][..],
        ),
        (
            "mssql",
            "SELECT convert(varchar(10), name, 120) FROM t",
            &["type varchar(10)", "value name", "value 120"],
        ),
        (
            "mssql",
            "SELECT TRY_CONVERT(DECIMAL(10, 2), name) FROM t",
            &["type DECIMAL(10, 2)", "value name"],
        ),
        (
            "mssql",
            "SELECT CONVERT(NVARCHAR(MAX), name) FROM t",
            &["type NVARCHAR(MAX)", "value name"],
        ),
        (
            "mssql",
            "SELECT CONVERT(DATE, name, 23) FROM t",
            &["type DATE", "value name", "value 23"],
        ),
        (
            "redshift",
            "SELECT CONVERT(INTEGER, name) FROM t",
            &["type INTEGER", "value name"],
        ),
        (
            "mysql",
            "SELECT CONVERT(name, SIGNED) FROM t",
            &["value name", "type SIGNED"],
        ),
        (
            "mysql",
            "SELECT CONVERT(name, CHAR(10)) FROM t",
            &["value name", "type CHAR(10)"],
        ),
        // A routine of a schema and a dialect with no such function read
        // every argument as a value; an ODBC escape reads ODBC's own
        // grammar, where the type is second.
        (
            "mssql",
            "SELECT dbo.CONVERT(INT, name) FROM t",
            &["value INT", "value name"],
        ),
        (
            "mssql",
            "SELECT {fn CONVERT(name, SQL_VARCHAR)} FROM t",
            &["value name", "type SQL_VARCHAR"],
        ),
        (
            "snowflake",
            "SELECT CONVERT(INT, name) FROM t",
            &["value INT", "value name"],
        ),
        // A type argument that is not a type reads as a value.
        (
            "mssql",
            "SELECT CONVERT(@t, name) FROM t",
            &["value @t", "value name"],
        ),
    ] {
        assert_eq!(
            conversion_arguments(sql, dialect),
            expected,
            "{dialect}: {sql}"
        );
    }
}

#[test]
fn a_date_part_or_keyword_argument_is_read_as_no_value() {
    for (dialect, sql, expected) in [
        (
            "snowflake",
            "SELECT DATEADD(day, 1, name) FROM t",
            &["unit day", "value 1", "value name"][..],
        ),
        (
            "snowflake",
            "SELECT datediff(YY, a, b) FROM t",
            &["unit YY", "value a", "value b"],
        ),
        (
            "snowflake",
            "SELECT LAST_DAY(name, week) FROM t",
            &["value name", "unit week"],
        ),
        (
            "snowflake",
            "SELECT TRUNC(name, week) FROM t",
            &["value name", "unit week"],
        ),
        (
            "bigquery",
            "SELECT DATE_DIFF(a, b, WEEK(MONDAY)) FROM t",
            &["value a", "value b", "unit WEEK(MONDAY)"],
        ),
        (
            "bigquery",
            "SELECT TIMESTAMP_TRUNC(a, DAY, 'UTC') FROM t",
            &["value a", "unit DAY", "value 'UTC'"],
        ),
        (
            "bigquery",
            "SELECT NORMALIZE(name, NFKC) FROM t",
            &["value name", "keyword NFKC"],
        ),
        (
            "postgresql",
            "SELECT normalize(name, nfd) FROM t",
            &["value name", "keyword nfd"],
        ),
        (
            "databricks",
            "SELECT DATEADD(WEEK, 1, d) FROM t",
            &["unit WEEK", "value 1", "value d"],
        ),
        (
            "mysql",
            "SELECT TIMESTAMPADD(SQL_TSI_DAY, 1, d) FROM t",
            &["unit SQL_TSI_DAY", "value 1", "value d"],
        ),
        (
            "mysql",
            "SELECT GET_FORMAT(DATE, 'USA') FROM t",
            &["type DATE", "value 'USA'"],
        ),
        (
            "mssql",
            "SELECT DATEADD(m, 1, d) FROM t",
            &["unit m", "value 1", "value d"],
        ),
        (
            "mssql",
            "SELECT DATEPART(iso_week, d) FROM t",
            &["unit iso_week", "value d"],
        ),
        (
            "mssql",
            "SELECT IDENTITY(INT, 1, 1) FROM t",
            &["type INT", "value 1", "value 1"],
        ),
        (
            "mssql",
            "SELECT {fn TIMESTAMPADD(SQL_TSI_DAY, 1, d)} FROM t",
            &["unit SQL_TSI_DAY", "value 1", "value d"],
        ),
        (
            "redshift",
            "SELECT DATEDIFF(qtr, a, b) FROM t",
            &["unit qtr", "value a", "value b"],
        ),
        // A string, a word the dialect names no part, an expression, a
        // part where its row takes another number of arguments, a numeric
        // TRUNC, a call of a schema's routine, and a function the dialect
        // has no row for: values.
        (
            "snowflake",
            "SELECT DATEADD('day', 1, name) FROM t",
            &["value 'day'", "value 1", "value name"],
        ),
        (
            "snowflake",
            "SELECT DATEADD(nosuchpart, 1, name) FROM t",
            &["value nosuchpart", "value 1", "value name"],
        ),
        (
            "snowflake",
            "SELECT DATEADD(day + 1, 1, name) FROM t",
            &["value day + 1", "value 1", "value name"],
        ),
        (
            "databricks",
            "SELECT DATEDIFF(day, start) FROM t",
            &["value day", "value start"],
        ),
        (
            "snowflake",
            "SELECT TRUNC(x, 2) FROM t",
            &["value x", "value 2"],
        ),
        (
            "mssql",
            "SELECT dbo.DATEADD(day, 1, d) FROM t",
            &["value day", "value 1", "value d"],
        ),
        (
            "postgresql",
            "SELECT date_trunc(month, d) FROM t",
            &["value month", "value d"],
        ),
    ] {
        assert_eq!(
            conversion_arguments(sql, dialect),
            expected,
            "{dialect}: {sql}"
        );
    }
}

/// The expression of the first select item of `sql`, read in `dialect`.
fn first_item(sql: &str, dialect: &str) -> lexega_syntax::AstExpr {
    use lexega_syntax::ast::{AstProjectionKind, ProjectionItemKind};
    use lexega_syntax::AstStmt;
    let dialect = lexega_syntax::dialect_from_name(dialect).expect("dialect");
    let script = lexega_syntax::parse_sql_with_dialect(sql, dialect.as_ref()).expect("parses");
    let Some(AstStmt::Select(select)) = script.stmts.first() else {
        panic!("not a SELECT: {sql}: {:?}", script.stmts.first());
    };
    let AstProjectionKind::Columns(items) = &select.projection.kind else {
        panic!("no select list: {sql}");
    };
    let ProjectionItemKind::SelectItem(item) = &items[0].kind else {
        panic!("no select item: {sql}");
    };
    item.expr.clone()
}

#[test]
fn an_extract_of_a_week_starting_on_a_day_is_read() {
    let sql = "SELECT EXTRACT(WEEK(MONDAY) FROM d) AS w FROM t";
    let expr = first_item(sql, "bigquery");
    assert!(
        matches!(expr, lexega_syntax::AstExpr::Extract { .. }),
        "{expr:?}"
    );
}

#[test]
fn an_extract_field_and_a_trim_side_are_read_typed() {
    use lexega_syntax::ast::{DatePart, TrimSide, Weekday};
    use lexega_syntax::AstExpr;
    for (dialect, sql, expected) in [
        (
            "snowflake",
            "SELECT EXTRACT(year FROM d) FROM t",
            Some(DatePart::Year),
        ),
        (
            "snowflake",
            "SELECT EXTRACT(dw FROM d) FROM t",
            Some(DatePart::DayOfWeek),
        ),
        (
            "postgresql",
            "SELECT EXTRACT(EPOCH FROM d) FROM t",
            Some(DatePart::Epoch),
        ),
        (
            "mysql",
            "SELECT EXTRACT(YEAR_MONTH FROM d) FROM t",
            Some(DatePart::YearMonth),
        ),
        (
            "bigquery",
            "SELECT EXTRACT(WEEK(MONDAY) FROM d) FROM t",
            Some(DatePart::WeekStarting(Weekday::Monday)),
        ),
        ("snowflake", "SELECT EXTRACT(nosuch FROM d) FROM t", None),
    ] {
        let AstExpr::Extract { part, .. } = first_item(sql, dialect) else {
            panic!("not an EXTRACT: {sql}");
        };
        assert_eq!(part, expected, "{dialect}: {sql}");
    }
    for (sql, expected) in [
        (
            "SELECT TRIM(LEADING 'x' FROM s) FROM t",
            Some(TrimSide::Leading),
        ),
        (
            "SELECT TRIM(trailing FROM s) FROM t",
            Some(TrimSide::Trailing),
        ),
        ("SELECT TRIM(BOTH 'x' FROM s) FROM t", Some(TrimSide::Both)),
        ("SELECT TRIM('x' FROM s) FROM t", None),
    ] {
        let AstExpr::Trim { spec, .. } = first_item(sql, "postgresql") else {
            panic!("not a TRIM: {sql}");
        };
        assert_eq!(spec.map(|(side, _)| side), expected, "{sql}");
    }
}

const PART_FORMS: [(&str, &str); 4] = [
    (
        "snowflake",
        "select dateadd(Day, 1,Name) a, DATEDIFF( /* p */ yy , a, b), last_day(Name,WEEK) from Users;",
    ),
    (
        "bigquery",
        "select DATE_DIFF(a, b, week( monday )), normalize(Name,nfkc) from Users;",
    ),
    (
        "mssql",
        "select DateAdd(M, 1, Name), datepart(ISO_WEEK,Name), {fn TIMESTAMPADD(SQL_TSI_DAY, 1, Name)} from Users;",
    ),
    (
        "mysql",
        "select TIMESTAMPDIFF(week,a,b), get_format(Date, 'USA') from Users;",
    ),
];

#[test]
fn a_date_part_or_keyword_argument_formats_as_its_call_did() {
    use lexega_syntax::{format_sql_with_config, FormatterConfig, IdentifierCase, KeywordCase};
    let cases = [
        (IdentifierCase::Preserve, KeywordCase::Upper),
        (IdentifierCase::Upper, KeywordCase::Upper),
        (IdentifierCase::Lower, KeywordCase::Lower),
    ];
    // The text the expression path gave each form before the arguments
    // were read as no values.
    let expected: [[&str; 3]; 4] = [
        [
            "SELECT\n    dateadd(Day, 1, Name) a,\n    DATEDIFF( /* p */ yy, a, b),\n    last_day(Name, WEEK)\nFROM Users;",
            "SELECT\n    DATEADD(DAY, 1, NAME) A,\n    DATEDIFF( /* p */ YY, A, B),\n    LAST_DAY(NAME, WEEK)\nFROM USERS;",
            "select\n    dateadd(day, 1, name) a,\n    datediff( /* p */ yy, a, b),\n    last_day(name, week)\nfrom users;",
        ],
        [
            "SELECT DATE_DIFF(a, b, week(monday)), normalize(Name, nfkc)\nFROM Users;",
            "SELECT DATE_DIFF(A, B, WEEK(MONDAY)), NORMALIZE(NAME, NFKC)\nFROM USERS;",
            "select date_diff(a, b, week(monday)), normalize(name, nfkc)\nfrom users;",
        ],
        [
            "SELECT\n    DateAdd(M, 1, Name),\n    datepart(ISO_WEEK, Name),\n    {fn TIMESTAMPADD(SQL_TSI_DAY, 1, Name)}\nFROM Users;",
            "SELECT\n    DATEADD(M, 1, NAME),\n    DATEPART(ISO_WEEK, NAME),\n    {fn TIMESTAMPADD(SQL_TSI_DAY, 1, Name)}\nFROM USERS;",
            "select\n    dateadd(m, 1, name),\n    datepart(iso_week, name),\n    {fn TIMESTAMPADD(SQL_TSI_DAY, 1, Name)}\nfrom users;",
        ],
        [
            "SELECT TIMESTAMPDIFF(week, a, b), get_format(Date, 'USA')\nFROM Users;",
            "SELECT TIMESTAMPDIFF(WEEK, A, B), GET_FORMAT(DATE, 'USA')\nFROM USERS;",
            "select timestampdiff(week, a, b), get_format(date, 'USA')\nfrom users;",
        ],
    ];
    let mut got = Vec::new();
    for ((dialect, sql), expected) in PART_FORMS.into_iter().zip(expected) {
        for ((case, keyword), expected) in cases.into_iter().zip(expected) {
            let config = FormatterConfig {
                dialect: lexega_syntax::dialect_from_name(dialect).expect("dialect"),
                identifier_case: case,
                keyword_case: keyword,
                ..FormatterConfig::default()
            };
            let formatted = format_sql_with_config(sql, &config).expect("formats");
            if formatted != expected {
                got.push(format!("{dialect} {case:?}: {formatted:?}"));
            }
            lexega_syntax::verify_formatting_safe_with_dialect(
                sql,
                &formatted,
                config.dialect.as_ref(),
            )
            .expect("safe");
        }
    }
    assert!(got.is_empty(), "{}", got.join("\n"));
}

#[test]
fn a_conversion_type_argument_formats_as_its_call_did() {
    use lexega_syntax::{format_sql_with_config, FormatterConfig, IdentifierCase, KeywordCase};
    let cases = [
        (IdentifierCase::Preserve, KeywordCase::Upper),
        (IdentifierCase::Upper, KeywordCase::Upper),
        (IdentifierCase::Lower, KeywordCase::Lower),
    ];
    let expected: [[&str; 3]; 5] = [
        [
            "SELECT\n    convert(varchar(10), Name, 120)   a,\n    try_convert(decimal(10, 2), Name) b,\n    CONVERT(Int, Name),\n    convert(NVARCHAR(max), Name),\n    Convert(Date, Name, 23)\nFROM Users\nWHERE\n    TRY_CONVERT(int, Name) = 1;",
            "SELECT\n    CONVERT(VARCHAR(10), NAME, 120)   A,\n    TRY_CONVERT(DECIMAL(10, 2), NAME) B,\n    CONVERT(INT, NAME),\n    CONVERT(NVARCHAR(MAX), NAME),\n    CONVERT(DATE, NAME, 23)\nFROM USERS\nWHERE\n    TRY_CONVERT(INT, NAME) = 1;",
            "select\n    convert(varchar(10), name, 120)   a,\n    try_convert(decimal(10, 2), name) b,\n    convert(int, name),\n    convert(nvarchar(max), name),\n    convert(date, name, 23)\nfrom users\nwhere\n    try_convert(int, name) = 1;",
        ],
        [
            "SELECT CONVERT( /* to */ INT /* t */ , name)\nFROM t;\n\nSELECT {fn CONVERT(Name, SQL_VARCHAR)}\nFROM t;",
            "SELECT CONVERT( /* to */ INT /* t */ , NAME)\nFROM T;\n\nSELECT {fn CONVERT(Name, SQL_VARCHAR)}\nFROM T;",
            "select convert( /* to */ int /* t */ , name)\nfrom t;\n\nselect {fn CONVERT(Name, SQL_VARCHAR)}\nfrom t;",
        ],
        [
            "SELECT\n    convert(Name, signed)   a,\n    CONVERT(Name, CHAR(10)) b,\n    convert(Name, decimal(10, 2))\nFROM Users;",
            "SELECT\n    CONVERT(NAME, SIGNED)   A,\n    CONVERT(NAME, CHAR(10)) B,\n    CONVERT(NAME, DECIMAL(10, 2))\nFROM USERS;",
            "select\n    convert(name, signed)   a,\n    convert(name, char(10)) b,\n    convert(name, decimal(10, 2))\nfrom users;",
        ],
        [
            "SELECT convert(integer, Name), CONVERT(varchar(10), Name)\nFROM Users;",
            "SELECT CONVERT(INTEGER, NAME), CONVERT(VARCHAR(10), NAME)\nFROM USERS;",
            "select convert(integer, name), convert(varchar(10), name)\nfrom users;",
        ],
        [
            "SELECT convert(Int, Name)\nFROM Users;",
            "SELECT CONVERT(INT, NAME)\nFROM USERS;",
            "select convert(int, name)\nfrom users;",
        ],
    ];
    for ((dialect, sql), expected) in CONVERSION_FORMS.into_iter().zip(expected) {
        for ((case, keyword), expected) in cases.into_iter().zip(expected) {
            let config = FormatterConfig {
                dialect: lexega_syntax::dialect_from_name(dialect).expect("dialect"),
                identifier_case: case,
                keyword_case: keyword,
                ..FormatterConfig::default()
            };
            let formatted = format_sql_with_config(sql, &config).expect("formats");
            assert_eq!(formatted, expected, "{dialect} {case:?}: {sql}");
            lexega_syntax::verify_formatting_safe_with_dialect(
                sql,
                &formatted,
                config.dialect.as_ref(),
            )
            .expect("formatting keeps every token");
        }
    }
}

#[test]
fn an_argument_a_keyword_introduces_is_read_with_its_keyword() {
    for (dialect, sql, expected) in [
        (
            "postgresql",
            "SELECT OVERLAY(email PLACING 'x' FROM 2 FOR 3) FROM u",
            &[
                "value email",
                "PLACING value 'x'",
                "FROM value 2",
                "FOR value 3",
            ][..],
        ),
        (
            "databricks",
            "SELECT overlay(email placing 'x' from 2) FROM u",
            &["value email", "PLACING value 'x'", "FROM value 2"][..],
        ),
        (
            "postgresql",
            "SELECT XMLELEMENT(NAME foo, email) FROM u",
            &["NAME name foo", "value email"][..],
        ),
        (
            "mysql",
            "SELECT CONVERT(name USING utf8mb4) FROM u",
            &["value name", "USING name utf8mb4"][..],
        ),
        (
            "mysql",
            "SELECT CHAR(65, 66 USING utf8mb4) FROM u",
            &["value 65", "value 66", "USING name utf8mb4"][..],
        ),
        (
            "mysql",
            "SELECT WEIGHT_STRING(email AS CHAR(4)) FROM u",
            &["value email", "AS type CHAR(4)"][..],
        ),
        (
            "mssql",
            "SELECT TRY_PARSE(email AS DATE USING 'en-US') FROM u",
            &["value email", "AS type DATE", "USING value 'en-US'"][..],
        ),
        (
            "mysql",
            "SELECT CONVERT(name, UNSIGNED INTEGER) FROM u",
            &["value name", "type UNSIGNED INTEGER"][..],
        ),
        // The function's word written as a value: no keyword there.
        (
            "postgresql",
            "SELECT XMLELEMENT(name, email) FROM u",
            &["value name", "value email"][..],
        ),
    ] {
        assert_eq!(
            conversion_arguments(sql, dialect),
            expected,
            "{dialect}: {sql}"
        );
    }
    // A function that takes no such keyword reads `AS` as a STRUCT field's alias.
    let got = conversion_arguments("SELECT STRUCT(1 AS x) FROM u", "bigquery");
    assert!(
        got.len() == 1 && got[0].starts_with("other AliasedArg"),
        "{got:?}"
    );
}

#[test]
fn an_argument_a_keyword_introduces_formats_without_a_comma() {
    use lexega_syntax::{format_sql_with_config, FormatterConfig};
    for (dialect, sql, expected) in [
        (
            "postgresql",
            "select overlay(email  placing 'x'  from 2 for 3) from u",
            "SELECT overlay(email PLACING 'x' FROM 2 FOR 3)\nFROM u",
        ),
        (
            "mysql",
            "select char(65,66  using utf8mb4), weight_string(email as char(4)) from u",
            "SELECT char(65, 66 USING utf8mb4), weight_string(email AS char(4))\nFROM u",
        ),
        (
            "mssql",
            "select try_parse(email as date using 'en-US') from u",
            "SELECT try_parse(email AS date USING 'en-US')\nFROM u",
        ),
    ] {
        let config = FormatterConfig {
            dialect: lexega_syntax::dialect_from_name(dialect).expect("dialect"),
            ..FormatterConfig::default()
        };
        let formatted = format_sql_with_config(sql, &config).expect("formats");
        assert_eq!(formatted, expected, "{dialect}: {sql}");
        let again = format_sql_with_config(&formatted, &config).expect("formats");
        assert_eq!(again, formatted, "{dialect}: idempotent");
    }
}

#[test]
fn a_compound_interval_unit_is_read_where_the_dialect_takes_one() {
    assert_eq!(
        conversion_arguments(
            "SELECT DATE_ADD(d, INTERVAL '1:30' HOUR_MINUTE) FROM u",
            "mysql"
        ),
        ["value d", "value INTERVAL '1:30' HOUR_MINUTE"]
    );
    // Elsewhere the word is no unit: the interval ends before it.
    let sql = "SELECT INTERVAL '1' HOUR_MINUTE FROM u";
    let expr = first_item(sql, "snowflake");
    let span = expr.span();
    assert_eq!(
        &sql[span.start as usize..span.end as usize],
        "INTERVAL '1'",
        "{expr:?}"
    );
}

#[test]
fn an_odbc_extract_or_position_keeps_its_braces() {
    use lexega_syntax::{format_sql_with_config, AstExpr, FormatterConfig};
    for (sql, escape) in [
        (
            "SELECT {fn EXTRACT(YEAR FROM d)} FROM u",
            "{fn EXTRACT(YEAR FROM d)}",
        ),
        (
            "SELECT {fn POSITION('a' IN d)} FROM u",
            "{fn POSITION('a' IN d)}",
        ),
    ] {
        let expr = first_item(sql, "mssql");
        let odbc = match &expr {
            AstExpr::Extract { odbc_fn, .. } | AstExpr::Position { odbc_fn, .. } => {
                odbc_fn.is_some()
            }
            other => panic!("{sql}: {other:?}"),
        };
        assert!(odbc, "{sql}");
        let span = expr.span();
        assert_eq!(&sql[span.start as usize..span.end as usize], escape);
        let config = FormatterConfig {
            dialect: lexega_syntax::dialect_from_name("mssql").expect("dialect"),
            ..FormatterConfig::default()
        };
        let formatted = format_sql_with_config(sql, &config).expect("formats");
        assert!(formatted.contains(escape), "{formatted}");
    }
    // Not in an escape: no flag.
    let expr = first_item("SELECT EXTRACT(YEAR FROM d) FROM u", "mssql");
    assert!(
        matches!(expr, AstExpr::Extract { odbc_fn: None, .. }),
        "{expr:?}"
    );
}
