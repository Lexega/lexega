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

#[test]
fn a_call_with_no_name_to_read_is_one_unparsed_statement() {
    use lexega_syntax::{parse_sql, verify_formatting_safe, AstStmt};
    // `ILIKE` and `UNION` are words Snowflake reserves and `1` is a number:
    // none of them is a name.
    for sql in ["CALL ilike(1)", "CALL union(1, 2);", "CALL 1"] {
        let script = parse_sql(sql).unwrap_or_else(|e| panic!("{sql}: {e:?}"));
        let [AstStmt::OpaqueContent { span, .. }] = script.stmts.as_slice() else {
            panic!(
                "{sql}: expected one unparsed statement, got {:?}",
                script.stmts
            );
        };
        assert_eq!(&sql[span.start as usize..span.end as usize], sql);
        let formatted = format_sql_with_config(sql, &FormatterConfig::default())
            .unwrap_or_else(|e| panic!("{sql}: {e:?}"));
        verify_formatting_safe(sql, &formatted)
            .unwrap_or_else(|e| panic!("{sql}: {e}\n{formatted}"));
    }
    // A word Snowflake does not reserve names the procedure.
    for (sql, name) in [("CALL left(1)", "left"), ("CALL replace(1, 2);", "replace")] {
        let script = parse_sql(sql).unwrap_or_else(|e| panic!("{sql}: {e:?}"));
        let [AstStmt::Call {
            procedure_name_span: span,
            ..
        }] = script.stmts.as_slice()
        else {
            panic!("{sql}: expected one CALL, got {:?}", script.stmts);
        };
        assert_eq!(&sql[span.start as usize..span.end as usize], name);
    }
    // The statement after it starts after it: no token is read twice.
    let sql = "CALL ilike(1); SELECT 2";
    let script = parse_sql(sql).unwrap_or_else(|e| panic!("{sql}: {e:?}"));
    let written: Vec<&str> = script
        .stmts
        .iter()
        .map(|stmt| {
            let span = stmt.span();
            &sql[span.start as usize..span.end as usize]
        })
        .collect();
    assert_eq!(written, ["CALL ilike(1);", "SELECT 2"]);
    assert!(
        matches!(script.stmts[1], AstStmt::Select(_)),
        "{:?}",
        script.stmts
    );
}

#[test]
fn a_call_argument_written_name_arrow_value_names_its_parameter() {
    use lexega_syntax::{dialect, parse_sql_with_dialect, AstStmt};
    let sql = "CALL set_pwd(p => 'a', 2, q => 3);";
    for dialect in [dialect::postgres(), dialect::snowflake()] {
        let script = parse_sql_with_dialect(sql, dialect.as_ref())
            .unwrap_or_else(|e| panic!("{}: {e:?}", dialect.name()));
        let [AstStmt::Call { args, .. }] = script.stmts.as_slice() else {
            panic!(
                "{}: expected one CALL, got {:?}",
                dialect.name(),
                script.stmts
            );
        };
        let written = |span: lexega_syntax::Span| &sql[span.start as usize..span.end as usize];
        let names: Vec<Option<&str>> = args
            .iter()
            .map(|arg| arg.name.as_ref().map(|name| written(name.span)))
            .collect();
        assert_eq!(names, [Some("p"), None, Some("q")], "{}", dialect.name());
        let values: Vec<&str> = args.iter().map(|arg| written(arg.value.span())).collect();
        assert_eq!(values, ["'a'", "2", "3"], "{}", dialect.name());
    }
}

#[test]
fn a_call_argument_written_name_colon_equals_value_names_its_parameter() {
    use lexega_syntax::{dialect, parse_sql_with_dialect, verify_formatting_safe_with_dialect};
    use lexega_syntax::{AstExpr, AstStmt};
    let sql = "CALL fill(s := NEW.status, 2, q := 3);";
    let postgres = dialect::postgres();
    let script = parse_sql_with_dialect(sql, postgres.as_ref()).unwrap_or_else(|e| panic!("{e:?}"));
    let [AstStmt::Call { args, .. }] = script.stmts.as_slice() else {
        panic!("expected one CALL, got {:?}", script.stmts);
    };
    let written = |span: lexega_syntax::Span| &sql[span.start as usize..span.end as usize];
    let names: Vec<Option<&str>> = args
        .iter()
        .map(|arg| arg.name.as_ref().map(|name| written(name.span)))
        .collect();
    assert_eq!(names, [Some("s"), None, Some("q")]);
    let ops: Vec<Option<&str>> = args
        .iter()
        .map(|arg| arg.name_op_span.map(written))
        .collect();
    assert_eq!(ops, [Some(":="), None, Some(":=")]);
    assert!(
        matches!(args[0].value, AstExpr::Ident { .. }),
        "{:?}",
        args[0].value
    );
    let whole: Vec<&str> = args.iter().map(|arg| written(arg.span)).collect();
    assert_eq!(whole, ["s := NEW.status", "2", "q := 3"]);
    let config = FormatterConfig {
        dialect: postgres.clone(),
        ..Default::default()
    };
    let formatted = format_sql_with_config(sql, &config).unwrap_or_else(|e| panic!("{e}"));
    verify_formatting_safe_with_dialect(sql, &formatted, postgres.as_ref())
        .unwrap_or_else(|e| panic!("{sql} -> {formatted}: {e}"));
}

#[test]
fn a_calls_arguments_are_formatted_as_written() {
    use lexega_syntax::verify_formatting_safe;
    for sql in [
        "CALL p(a + b, 'x', CAST(1 AS INT), x => 1);",
        "CALL p(1 IS NULL, NOT a);",
        "CALL p($$a b$$);",
        "CALL p();",
        "BEGIN\n  CALL p(CAST(:v AS INT));\nEND;",
    ] {
        let formatted = format_sql_with_config(sql, &FormatterConfig::default())
            .unwrap_or_else(|e| panic!("{sql}: {e}"));
        verify_formatting_safe(sql, &formatted)
            .unwrap_or_else(|e| panic!("{sql} -> {formatted}: {e}"));
    }
}
