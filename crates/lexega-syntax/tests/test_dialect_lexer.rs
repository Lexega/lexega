// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

/// Tests for dialect-aware lexer behavior.
///
/// These tests verify that the same source text produces DIFFERENT tokens
/// depending on which dialect is active. This is the core proof that
/// dialect separation lives at the lexer level.
use lexega_syntax::ast::{
    AstGroupByVariant, AstIsPredicate, AstLiteral, AstProjectionKind, BinaryOperator,
    ProjectionItemKind,
};
use lexega_syntax::dialect::{
    bigquery, databricks, mssql, mysql, postgres, redshift, snowflake, MySqlDialect,
    PostgresDialect, SnowflakeDialect,
};
use lexega_syntax::lexer::tokenize_with_dialect;
use lexega_syntax::{
    format_sql_with_config, parse_sql_with_dialect, verify_formatting_safe_with_dialect, AstExpr,
    AstSelect, AstStmt, Dialect, DialectRef, FormatterConfig, IdentifierKind, LiteralKind,
    Operator, TokenKind, WordOperator,
};

// ============================================================================
// Helper: extract significant tokens (skip EOF)
// ============================================================================

fn token_kinds(sql: &str, dialect: &dyn lexega_syntax::Dialect) -> Vec<TokenKind> {
    let result = tokenize_with_dialect(sql, dialect);
    result
        .tokens
        .iter()
        .filter(|t| !matches!(t.kind, TokenKind::Eof))
        .map(|t| t.kind.clone())
        .collect()
}

fn token_lexemes<'a>(sql: &'a str, dialect: &dyn lexega_syntax::Dialect) -> Vec<&'a str> {
    let result = tokenize_with_dialect(sql, dialect);
    result
        .tokens
        .iter()
        .filter(|t| !matches!(t.kind, TokenKind::Eof))
        .map(|t| t.lexeme(sql))
        .collect()
}

#[test]
fn the_second_dot_of_two_dots_is_never_a_decimal_point() {
    let dialects: [DialectRef; 6] = [
        postgres(),
        snowflake(),
        mssql(),
        mysql(),
        bigquery(),
        databricks(),
    ];
    for dialect in &dialects {
        for (sql, words) in [
            ("1..10", vec!["1", ".", ".", "10"]),
            ("a..2", vec!["a", ".", ".", "2"]),
            ("1 .. 10", vec!["1", ".", ".", "10"]),
            (
                "SELECT * FROM db..t",
                vec!["SELECT", "*", "FROM", "db", ".", ".", "t"],
            ),
            (
                "SELECT .5, 1.5, 1., x.y",
                vec!["SELECT", ".5", ",", "1.5", ",", "1.", ",", "x", ".", "y"],
            ),
        ] {
            assert_eq!(
                token_lexemes(sql, dialect.as_ref()),
                words,
                "{sql} [{}]",
                dialect.name()
            );
        }
    }
}

#[test]
fn a_template_expression_whose_brace_closes_nothing_ends_at_its_next_double_brace() {
    // `}` at `2}` closes nothing: the next `}}` closes the expression, and
    // the string and its statement end where they are written.
    let sql = "INSERT INTO grid VALUES (1, '{{1,2},{3,4}}');\nDELETE FROM grid;";
    assert_eq!(
        token_lexemes(sql, &PostgresDialect),
        vec![
            "INSERT", "INTO", "grid", "VALUES", "(", "1", ",", "'", "{{", "1", ",", "2", "}", ",",
            "{", "3", ",", "4", "}}", "'", ")", ";", "DELETE", "FROM", "grid", ";",
        ]
    );
    // A balanced expression lexes as before: the `}` of `{'a': 1}` closes
    // its `{`, and `}}` closes the expression.
    let sql = "SELECT '{{ {'a': 1}['a'] }}' AS x;";
    assert_eq!(
        token_lexemes(sql, &PostgresDialect),
        vec![
            "SELECT", "'", "{{", "{", "'a'", ":", "1", "}", "[", "'a'", "]", "}}", "'", "AS", "x",
            ";",
        ]
    );
}

#[test]
fn a_quote_inside_snowflake_dollar_words_ends_at_the_closing_dollars() {
    for (sql, words) in [
        (
            "SELECT $$it's$$ AS a;\nDROP TABLE x;",
            vec![
                "SELECT", "$$", "it", "'s", "$$", "AS", "a", ";", "DROP", "TABLE", "x", ";",
            ],
        ),
        (
            "SELECT $$ it's $$ AS a;",
            vec!["SELECT", "$$", "it", "'s ", "$$", "AS", "a", ";"],
        ),
    ] {
        assert_eq!(token_lexemes(sql, &SnowflakeDialect), words, "{sql}");
        let kinds = token_kinds(sql, &SnowflakeDialect);
        assert!(
            kinds.contains(&TokenKind::Literal(LiteralKind::StringFragment))
                && !kinds.contains(&TokenKind::Unknown),
            "{sql}: {kinds:?}"
        );
    }
    // A string written whole inside the `$$` words is one string, and one
    // after the closer is read as before.
    let sql = "EXECUTE IMMEDIATE $$SELECT 'a'$$; SELECT 'it''s';";
    assert_eq!(
        token_lexemes(sql, &SnowflakeDialect),
        vec![
            "EXECUTE",
            "IMMEDIATE",
            "$$",
            "SELECT",
            "'a'",
            "$$",
            ";",
            "SELECT",
            "'it''s'",
            ";"
        ]
    );
}

#[test]
fn a_double_quote_or_a_comment_inside_snowflake_dollar_words_ends_at_the_closing_dollars() {
    for (sql, words) in [
        (
            "SELECT $$say \"hi$$ AS a;",
            vec!["SELECT", "$$", "say", "\"hi", "$$", "AS", "a", ";"],
        ),
        (
            "SELECT $$ a -- b $$ AS a;",
            vec!["SELECT", "$$", "a", "$$", "AS", "a", ";"],
        ),
        (
            "SELECT $$2024--01$$ AS a;",
            vec!["SELECT", "$$", "2024", "$$", "AS", "a", ";"],
        ),
        (
            "SELECT $$a /* b$$ AS a;",
            vec!["SELECT", "$$", "a", "$$", "AS", "a", ";"],
        ),
    ] {
        assert_eq!(token_lexemes(sql, &SnowflakeDialect), words, "{sql}");
        assert!(
            !token_kinds(sql, &SnowflakeDialect).contains(&TokenKind::Unknown),
            "{sql}"
        );
    }
}

// ============================================================================
// GATE 1: Double-Quote Semantics ("..." → identifier vs string)
// ============================================================================

#[test]
fn test_double_quote_snowflake_is_identifier() {
    let sql = r#""my_column""#;
    let kinds = token_kinds(sql, &SnowflakeDialect);
    assert_eq!(kinds.len(), 1);
    assert!(
        matches!(
            kinds[0],
            TokenKind::Identifier {
                kind: IdentifierKind::Quoted,
                ..
            }
        ),
        "Snowflake should lex \"...\" as a quoted identifier, got {:?}",
        kinds[0]
    );
}

#[test]
fn test_double_quote_postgres_is_identifier() {
    let sql = r#""my_column""#;
    let kinds = token_kinds(sql, &PostgresDialect);
    assert_eq!(kinds.len(), 1);
    assert!(
        matches!(
            kinds[0],
            TokenKind::Identifier {
                kind: IdentifierKind::Quoted,
                ..
            }
        ),
        "PostgreSQL should lex \"...\" as a quoted identifier, got {:?}",
        kinds[0]
    );
}

#[test]
fn test_double_quote_mysql_is_string() {
    let sql = r#""hello world""#;
    let kinds = token_kinds(sql, &MySqlDialect);
    assert_eq!(kinds.len(), 1);
    assert!(
        matches!(kinds[0], TokenKind::Literal(LiteralKind::String)),
        "MySQL should lex \"...\" as a string literal, got {:?}",
        kinds[0]
    );
}

#[test]
fn test_double_quote_divergence() {
    // The same SQL produces different token kinds depending on dialect
    let sql = r#"SELECT "active" FROM users"#;

    let sf_kinds = token_kinds(sql, &SnowflakeDialect);
    let pg_kinds = token_kinds(sql, &PostgresDialect);
    let my_kinds = token_kinds(sql, &MySqlDialect);

    // Snowflake & Postgres: "active" is an identifier
    assert!(matches!(
        sf_kinds[1],
        TokenKind::Identifier {
            kind: IdentifierKind::Quoted,
            ..
        }
    ));
    assert!(matches!(
        pg_kinds[1],
        TokenKind::Identifier {
            kind: IdentifierKind::Quoted,
            ..
        }
    ));

    // MySQL: "active" is a string literal
    assert!(matches!(
        my_kinds[1],
        TokenKind::Literal(LiteralKind::String)
    ));
}

// ============================================================================
// GATE 2: Backtick Identifiers (MySQL only)
// ============================================================================

#[test]
fn test_backtick_mysql_is_identifier() {
    let sql = "`my_table`";
    let kinds = token_kinds(sql, &MySqlDialect);
    assert_eq!(kinds.len(), 1);
    assert!(
        matches!(
            kinds[0],
            TokenKind::Identifier {
                kind: IdentifierKind::Quoted,
                ..
            }
        ),
        "MySQL should lex `...` as a quoted identifier, got {:?}",
        kinds[0]
    );
}

#[test]
fn test_backtick_mysql_with_escaped_backtick() {
    let sql = "`my``table`";
    let kinds = token_kinds(sql, &MySqlDialect);
    assert_eq!(kinds.len(), 1);
    assert!(matches!(
        kinds[0],
        TokenKind::Identifier {
            kind: IdentifierKind::Quoted,
            ..
        }
    ));
    // Full lexeme includes outer backticks and escaped inner backtick
    let lexemes = token_lexemes(sql, &MySqlDialect);
    assert_eq!(lexemes[0], "`my``table`");
}

#[test]
fn test_backtick_snowflake_not_identifier() {
    // Snowflake doesn't use backticks for identifiers
    let sql = "`my_table`";
    let kinds = token_kinds(sql, &SnowflakeDialect);
    // Should NOT produce a single quoted identifier token
    assert!(
        !matches!(
            kinds.first(),
            Some(TokenKind::Identifier {
                kind: IdentifierKind::Quoted,
                ..
            })
        ),
        "Snowflake should NOT lex backticks as quoted identifiers"
    );
}

#[test]
fn test_backtick_mysql_full_query() {
    let sql = "SELECT `id`, `name` FROM `users` WHERE `status` = 'active'";
    let lexemes = token_lexemes(sql, &MySqlDialect);
    assert!(lexemes.contains(&"`id`"));
    assert!(lexemes.contains(&"`name`"));
    assert!(lexemes.contains(&"`users`"));
    assert!(lexemes.contains(&"`status`"));
}

// ============================================================================
// GATE 3: Hash Comments (# → comment vs operator)
// ============================================================================

#[test]
fn test_hash_mysql_is_comment() {
    let sql = "SELECT 1 # this is a comment";
    let kinds = token_kinds(sql, &MySqlDialect);
    // The # comment should be consumed as trivia, not as tokens
    // We should only see: SELECT, 1
    assert_eq!(
        kinds.len(),
        2,
        "MySQL should treat # as line comment, got {:?}",
        kinds
    );
}

#[test]
fn test_hash_snowflake_not_comment() {
    let sql = "SELECT 1 # 2";
    let kinds = token_kinds(sql, &SnowflakeDialect);
    // Snowflake treats # as an operator — should produce more than 2 tokens
    assert!(
        kinds.len() > 2,
        "Snowflake should NOT treat # as comment, got {:?}",
        kinds
    );
}

#[test]
fn test_hash_mysql_comment_in_trivia() {
    let sql = "# full line comment\nSELECT 1";
    let result = tokenize_with_dialect(sql, &MySqlDialect);
    let non_eof: Vec<_> = result
        .tokens
        .iter()
        .filter(|t| !matches!(t.kind, TokenKind::Eof))
        .collect();
    assert_eq!(non_eof.len(), 2); // SELECT, 1
                                  // The first token (SELECT) should have the comment as leading trivia
    assert!(
        !non_eof[0].leading_trivia.is_empty(),
        "Hash comment should appear as leading trivia on first token"
    );
}

// ============================================================================
// GATE 4: E-String Literals (PostgreSQL only)
// ============================================================================

#[test]
fn test_estring_postgres_is_string() {
    let sql = r"E'hello\nworld'";
    let kinds = token_kinds(sql, &PostgresDialect);
    assert_eq!(
        kinds.len(),
        1,
        "PostgreSQL E'...' should be a single string token, got {:?}",
        kinds
    );
    assert!(
        matches!(kinds[0], TokenKind::Literal(LiteralKind::String)),
        "PostgreSQL E'...' should be a string literal, got {:?}",
        kinds[0]
    );
}

#[test]
fn test_estring_postgres_lowercase() {
    let sql = r"e'tab\there'";
    let kinds = token_kinds(sql, &PostgresDialect);
    assert_eq!(kinds.len(), 1);
    assert!(matches!(kinds[0], TokenKind::Literal(LiteralKind::String)));
}

#[test]
fn test_estring_snowflake_is_identifier_then_string() {
    // In Snowflake, E is just an identifier, followed by a string literal
    let sql = r"E'hello'";
    let kinds = token_kinds(sql, &SnowflakeDialect);
    assert!(
        kinds.len() >= 2,
        "Snowflake should lex E and '...' as separate tokens, got {:?}",
        kinds
    );
}

#[test]
fn test_estring_postgres_with_escapes() {
    let sql = r"E'it''s a \\ backslash'";
    let kinds = token_kinds(sql, &PostgresDialect);
    assert_eq!(kinds.len(), 1);
    assert!(matches!(kinds[0], TokenKind::Literal(LiteralKind::String)));
    let lexemes = token_lexemes(sql, &PostgresDialect);
    assert_eq!(lexemes[0], sql); // Full lexeme preserved
}

#[test]
fn test_estring_mysql_is_identifier_then_string() {
    // MySQL doesn't support E'...' — E is an identifier
    let sql = r"E'hello'";
    let kinds = token_kinds(sql, &MySqlDialect);
    assert!(
        kinds.len() >= 2,
        "MySQL should NOT lex E'...' as a single token"
    );
}

// ============================================================================
// GATE 5: Dollar-Quoted Strings (PostgreSQL only)
// ============================================================================

/// Assert a bare `<tag>…<tag>` dollar-quoted region is recognized as one
/// correctly-delimited unit under the canonical token shape. Dollar-quoted
/// regions now lex as opening-delimiter + inner tokens + closing-delimiter in
/// the single token stream (so PG/Redshift procedure bodies become first-class
/// analyzable statements). The opacity property is preserved structurally: the
/// first and last significant tokens are the matching delimiter (lexeme == tag),
/// and the close tag sits at the very end of the input — proving inner content
/// (apostrophes, semicolons, SQL) did NOT prematurely close the region.
fn assert_dollar_quoted_region(sql: &str, dialect: &dyn lexega_syntax::Dialect, tag: &str) {
    let result = tokenize_with_dialect(sql, dialect);
    let sig: Vec<_> = result
        .tokens
        .iter()
        .filter(|t| !matches!(t.kind, TokenKind::Eof))
        .collect();
    assert!(
        sig.len() >= 2,
        "opener + closer at minimum, got {:?}",
        sig.iter().map(|t| t.lexeme(sql)).collect::<Vec<_>>()
    );
    let first = sig.first().expect("opening delimiter");
    let last = sig.last().expect("closing delimiter");
    assert_eq!(first.lexeme(sql), tag, "opening delimiter");
    assert_eq!(last.lexeme(sql), tag, "closing delimiter matches opener");
    assert_eq!(
        last.span.end as usize,
        sql.len(),
        "close tag at end of region — inner content did not prematurely close it"
    );
}

#[test]
fn test_dollar_quote_postgres_empty_tag() {
    assert_dollar_quoted_region("$$hello world$$", &PostgresDialect, "$$");
}

#[test]
fn test_dollar_quote_postgres_named_tag() {
    // Inner `;` must not close the region (opacity preserved at the new granularity).
    assert_dollar_quoted_region("$fn$SELECT 1;$fn$", &PostgresDialect, "$fn$");
}

#[test]
fn test_dollar_quote_postgres_with_inner_quotes() {
    // Dollar-quoting avoids escaping single quotes: inner apostrophes must not
    // swallow or prematurely close the region.
    assert_dollar_quoted_region("$$it's a 'test'$$", &PostgresDialect, "$$");
}

#[test]
fn test_dollar_quote_snowflake_is_not_string() {
    // Snowflake uses $1, $2 for positional params and $ident for identifiers
    let sql = "$$hello$$";
    let kinds = token_kinds(sql, &SnowflakeDialect);
    // Should NOT be a single string literal
    assert!(
        !(kinds.len() == 1 && matches!(kinds[0], TokenKind::Literal(LiteralKind::String))),
        "Snowflake should NOT lex $$...$$ as a dollar-quoted string"
    );
}

#[test]
fn test_dollar_quote_postgres_nested_sql() {
    // Real-world PL/pgSQL: function body containing SQL. The inner SQL (with its
    // `'active'` literal and `;`) is now lexed as ordinary tokens between the
    // `$body$` delimiters, so the body is analyzable; the region stays correctly
    // delimited (close `$body$` found at the end despite the inner `;`/quotes).
    let sql = r#"$body$
        SELECT count(*) FROM users WHERE status = 'active';
    $body$"#;
    assert_dollar_quoted_region(sql, &PostgresDialect, "$body$");
}

#[test]
fn test_dollar_quote_postgres_nested_different_tag() {
    // A DIFFERENT-tag dollar quote nested inside an outer body. The inner
    // `$sql$…$sql$` is recognized as its own delimited region (opener + inner
    // tokens + closer), NOT fused into an identifier like `$sql$SELECT`, and
    // the outer `$func$` still closes at the very end — its boundary is not
    // corrupted by the nested region. Regression test for nested dynamic-SQL
    // dollar fragments built inside a routine body.
    let sql = r#"$func$ EXECUTE $sql$SELECT 1;$sql$ || x; $func$"#;
    let result = tokenize_with_dialect(sql, &PostgresDialect);
    let lexemes: Vec<&str> = result
        .tokens
        .iter()
        .filter(|t| !matches!(t.kind, TokenKind::Eof))
        .map(|t| t.lexeme(sql))
        .collect();
    assert_eq!(
        lexemes.first(),
        Some(&"$func$"),
        "outer opener first; got {:?}",
        lexemes
    );
    assert_eq!(
        lexemes.last(),
        Some(&"$func$"),
        "outer closer last (boundary intact); got {:?}",
        lexemes
    );
    assert_eq!(
        lexemes.iter().filter(|l| **l == "$sql$").count(),
        2,
        "nested $sql$ recognized as opener + closer, not fused to an identifier; got {:?}",
        lexemes
    );
}

#[test]
fn a_dollar_quote_delimiter_has_a_kind_of_its_own() {
    let delimiter = TokenKind::Identifier {
        kind: IdentifierKind::DollarQuoteDelimiter,
        word_operator: None,
    };
    let word = TokenKind::Identifier {
        kind: IdentifierKind::Unquoted,
        word_operator: None,
    };
    let dollar_tokens = |sql: &str, dialect: &dyn Dialect| -> Vec<(String, TokenKind)> {
        tokenize_with_dialect(sql, dialect)
            .tokens
            .iter()
            .filter(|t| t.lexeme(sql).starts_with('$'))
            .map(|t| (t.lexeme(sql).to_string(), t.kind.clone()))
            .collect()
    };
    let delimiters = |tags: &[&str]| -> Vec<(String, TokenKind)> {
        tags.iter()
            .map(|tag| (tag.to_string(), delimiter.clone()))
            .collect()
    };
    for dialect in [postgres(), redshift()] {
        // Every delimiter of a closed dollar quote, one nested in another's
        // body included.
        assert_eq!(
            dollar_tokens("SELECT $q$a $$b$$ c$q$, $$d$$", dialect.as_ref()),
            delimiters(&["$q$", "$$", "$$", "$q$", "$$", "$$"]),
            "[{}]",
            dialect.name()
        );
        assert_eq!(
            dollar_tokens(
                "DO $$ BEGIN INSERT INTO t VALUES ($q$x$q$ +); END $$;",
                dialect.as_ref()
            ),
            delimiters(&["$$", "$q$", "$q$", "$$"]),
            "[{}]",
            dialect.name()
        );
        // A tag with no closer inside the body it is written in opens
        // nothing: it is a name.
        assert_eq!(
            dollar_tokens("$$ x $q$ y $$", dialect.as_ref()),
            vec![
                ("$$".to_string(), delimiter.clone()),
                ("$q$".to_string(), word.clone()),
                ("$$".to_string(), delimiter.clone()),
            ],
            "[{}]",
            dialect.name()
        );
    }
    // Snowflake gives a `$$…$$` string's content as words, its opening and
    // closing `$$` as delimiters of their own, written against the content
    // or not; `$name` stays a name.
    let lexemes_and_delimiters = |sql: &str, dialect: &dyn Dialect| -> Vec<(String, bool)> {
        tokenize_with_dialect(sql, dialect)
            .tokens
            .iter()
            .filter(|t| !matches!(t.kind, TokenKind::Eof))
            .map(|t| (t.lexeme(sql).to_string(), t.kind == delimiter))
            .collect()
    };
    let expected = |tokens: &[(&str, bool)]| -> Vec<(String, bool)> {
        tokens
            .iter()
            .map(|(lexeme, is_delimiter)| (lexeme.to_string(), *is_delimiter))
            .collect()
    };
    assert_eq!(
        lexemes_and_delimiters("SELECT $$a$$, $$ b c$$, $x", &SnowflakeDialect),
        expected(&[
            ("SELECT", false),
            ("$$", true),
            ("a", false),
            ("$$", true),
            (",", false),
            ("$$", true),
            ("b", false),
            ("c", false),
            ("$$", true),
            (",", false),
            ("$x", false),
        ])
    );
    // A `$$` with no closer opens a string the text ends inside of.
    assert_eq!(
        lexemes_and_delimiters("SELECT $$a FROM t", &SnowflakeDialect),
        expected(&[
            ("SELECT", false),
            ("$$", true),
            ("a", false),
            ("FROM", false),
            ("t", false),
        ])
    );
    // Where `$$` is no string (MySQL), a word starting with it is a name.
    assert_eq!(
        dollar_tokens("SELECT $$a$$", &MySqlDialect),
        vec![("$$a$$".to_string(), word.clone())]
    );
}

// ============================================================================
// CROSS-DIALECT: Same SQL, Different Tokens
// ============================================================================

#[test]
fn test_mysql_fatal_four_all_resolved() {
    // MySQL SQL that a Snowflake-only lexer cannot tokenize. All four cases
    // tokenize correctly under the MySQL dialect.
    let dialect = MySqlDialect;

    // 1. Backtick identifiers
    let kinds = token_kinds("`users`", &dialect);
    assert_eq!(kinds.len(), 1);
    assert!(matches!(
        kinds[0],
        TokenKind::Identifier {
            kind: IdentifierKind::Quoted,
            ..
        }
    ));

    // 2. Double-quote strings
    let kinds = token_kinds(r#""active""#, &dialect);
    assert_eq!(kinds.len(), 1);
    assert!(matches!(kinds[0], TokenKind::Literal(LiteralKind::String)));

    // 3. Hash comments
    let kinds = token_kinds("SELECT 1 # comment", &dialect);
    assert_eq!(kinds.len(), 2); // SELECT, 1

    // 4. || as logical OR — still tokenizes as PipePipe operator,
    //    but the dialect.pipe_pipe_is_concat() returns false for MySQL
    assert!(!dialect.pipe_pipe_is_concat());
}

#[test]
fn test_complete_mysql_query() {
    // A realistic MySQL query using all MySQL-specific syntax
    let sql = r#"SELECT `u`.`id`, `u`.`name`
FROM `users` AS `u`
WHERE `u`.`status` = "active"  # filter active users
AND `u`.`age` > 18"#;

    let result = tokenize_with_dialect(sql, &MySqlDialect);
    let kinds: Vec<_> = result
        .tokens
        .iter()
        .filter(|t| !matches!(t.kind, TokenKind::Eof))
        .map(|t| t.kind.clone())
        .collect();

    // Should tokenize without unknown/error tokens
    assert!(
        !kinds.iter().any(|k| matches!(k, TokenKind::Unknown)),
        "MySQL query should have no Unknown tokens, got kinds: {:?}",
        kinds
    );
}

#[test]
fn test_complete_postgres_query() {
    // A realistic PostgreSQL query using PG-specific syntax
    let sql = r"SELECT id, E'hello\nworld' AS greeting,
       $$dollar string$$ AS body
FROM users
WHERE name = 'test'";

    let result = tokenize_with_dialect(sql, &PostgresDialect);
    let kinds: Vec<_> = result
        .tokens
        .iter()
        .filter(|t| !matches!(t.kind, TokenKind::Eof))
        .map(|t| t.kind.clone())
        .collect();

    // Should tokenize without unknown/error tokens
    assert!(
        !kinds.iter().any(|k| matches!(k, TokenKind::Unknown)),
        "PostgreSQL query should have no Unknown tokens, got kinds: {:?}",
        kinds
    );

    // Verify E-string is a single string token
    let lexemes = token_lexemes(sql, &PostgresDialect);
    assert!(
        lexemes.contains(&r"E'hello\nworld'"),
        "Should contain E-string as single lexeme"
    );
    // The dollar-quoted region is delimited by two `$$` tokens in the canonical
    // stream (opener + inner `dollar`/`string` + closer); the inner content is
    // ordinary tokens, not Unknown (asserted above).
    assert_eq!(
        lexemes.iter().filter(|l| **l == "$$").count(),
        2,
        "dollar-quoted string is bracketed by two $$ delimiters, got: {:?}",
        lexemes
    );
}

// ============================================================================
// REGRESSION: Snowflake Unchanged
// ============================================================================

#[test]
fn test_snowflake_basic_query_unchanged() {
    let sql = "SELECT id, name FROM \"MY_TABLE\" WHERE status = 'active'";
    let kinds = token_kinds(sql, &SnowflakeDialect);

    // "MY_TABLE" should be a quoted identifier
    assert!(
        kinds.iter().any(|k| matches!(
            k,
            TokenKind::Identifier {
                kind: IdentifierKind::Quoted,
                ..
            }
        )),
        "Snowflake double-quoted identifier should still work"
    );

    // 'active' should be a string literal
    assert!(
        kinds
            .iter()
            .any(|k| matches!(k, TokenKind::Literal(LiteralKind::String))),
        "Snowflake single-quoted string should still work"
    );

    // No unknown tokens
    assert!(
        !kinds.iter().any(|k| matches!(k, TokenKind::Unknown)),
        "Snowflake basic query should have no Unknown tokens"
    );
}

#[test]
fn test_snowflake_positional_params_still_work() {
    // $1, $2 positional params must still work in Snowflake
    let sql = "SELECT $1, $2 FROM @my_stage";
    let kinds = token_kinds(sql, &SnowflakeDialect);
    assert!(
        kinds
            .iter()
            .any(|k| matches!(k, TokenKind::Literal(LiteralKind::Position))),
        "Snowflake $1 positional params must still work"
    );
}

#[test]
fn test_snowflake_dollar_identifiers_still_work() {
    // $identifier must still work in Snowflake
    let sql = "SELECT $my_var FROM t";
    let kinds = token_kinds(sql, &SnowflakeDialect);
    assert!(
        kinds
            .iter()
            .any(|k| matches!(k, TokenKind::Identifier { .. })),
        "Snowflake $identifier must still work"
    );
}

// ============================================================================
// Dialect Trait Properties
// ============================================================================

#[test]
fn test_mysql_dialect_properties() {
    let d = MySqlDialect;
    assert_eq!(d.name(), "mysql");
    assert_eq!(d.identifier_quote_char(), '`');
    assert!(d.supports_double_quoted_strings());
    assert!(d.hash_is_line_comment());
    assert!(!d.pipe_pipe_is_concat());
    assert!(!d.supports_escape_string_literals());
    assert!(!d.supports_dollar_quoted_strings());
    assert!(!d.supports_merge());
    assert!(!d.supports_qualify());
    assert!(!d.supports_time_travel());
    assert!(!d.supports_type_cast_operator());
    assert!(d.supports_json_operators());
    assert_eq!(d.max_identifier_length(), Some(64));
}

#[test]
fn test_dialect_ref_mysql() {
    let d = mysql();
    assert_eq!(d.name(), "mysql");
    assert_eq!(d.identifier_quote_char(), '`');
}

// ============================================================================
// Regression: Jinja inside a PostgreSQL dollar-quoted body
// ============================================================================
//
// `$${{ ... }}$$` (a dbt-templated PG function body, pre-render) used to drop
// the dollar-body context when the inner Jinja closed: the body was never
// popped, the bounded EOF fired early, and the lexer's "EOF != source end"
// invariant panicked (silent truncation in release). The lexer must always
// consume the whole source and terminate with EOF at source end.

fn last_token_reaches_source_end(sql: &str, dialect: &dyn lexega_syntax::Dialect) {
    let result = tokenize_with_dialect(sql, dialect);
    let last = result.tokens.last().expect("at least an EOF token");
    assert!(
        matches!(last.kind, TokenKind::Eof),
        "last token must be EOF for {sql:?}, got {:?}",
        last.kind
    );
    assert_eq!(
        last.span.end as usize,
        sql.len(),
        "lexer must consume entire source for {sql:?} (truncation bug)"
    );
}

#[test]
fn pg_jinja_inside_dollar_quote_does_not_truncate() {
    let pg = PostgresDialect;
    last_token_reaches_source_end("select $${{ x }}$$ as x;", &pg);
    last_token_reaches_source_end("select $${{ a }}$$, $${{ b }}$$;", &pg);
    // whitespace-stripping Jinja close forms (-%} / -}}) inside the body
    last_token_reaches_source_end("select $${%- if z -%}q{%- endif -%}$$ c;", &pg);
    last_token_reaches_source_end("select $$pre {{ v }} post$$ as x;", &pg);
}

#[test]
fn pg_clean_dollar_quote_and_outer_jinja_still_lex() {
    let pg = PostgresDialect;
    // No regression on the cases that already worked.
    last_token_reaches_source_end("select $$ hello $$ as x;", &pg);
    last_token_reaches_source_end("select {{ x }} from t;", &pg);
    last_token_reaches_source_end(
        "create function f() returns int as $$ select 1 $$ language sql;",
        &pg,
    );
}

/// The kind of the first token of `sql` written `lexeme`.
fn kind_of(sql: &str, lexeme: &str, dialect: &dyn Dialect) -> TokenKind {
    tokenize_with_dialect(sql, dialect)
        .tokens
        .into_iter()
        .find(|t| t.lexeme(sql) == lexeme)
        .map(|t| t.kind)
        .unwrap_or_else(|| panic!("no token {lexeme:?} in {sql:?}"))
}

/// The one `SELECT` of `sql`.
fn select_of(sql: &str, dialect: &dyn Dialect) -> AstSelect {
    let script = parse_sql_with_dialect(sql, dialect)
        .unwrap_or_else(|e| panic!("{sql:?} should parse under {}: {e:?}", dialect.name()));
    match script.stmts.into_iter().next() {
        Some(AstStmt::Select(select)) => *select,
        other => panic!("expected a SELECT for {sql:?}, got {other:?}"),
    }
}

/// The right side of the comparison in the `WHERE` of `sql`.
fn where_right(sql: &str, dialect: &dyn Dialect) -> AstExpr {
    let select = select_of(sql, dialect);
    let clause = select.where_clause.expect("where clause");
    match clause.expr {
        AstExpr::BinaryOp { right, .. } => *right,
        other => panic!("expected a comparison, got {other:?}"),
    }
}

#[test]
fn a_dollar_number_is_a_parameter_in_postgres_and_a_column_in_snowflake() {
    let sql = "SELECT * FROM t WHERE id = $1";
    for dialect in [postgres(), redshift()] {
        assert_eq!(
            kind_of(sql, "$1", dialect.as_ref()),
            TokenKind::Literal(LiteralKind::Parameter),
            "{}",
            dialect.name()
        );
        match where_right(sql, dialect.as_ref()) {
            AstExpr::Placeholder { span, .. } => {
                assert_eq!(&sql[span.start as usize..span.end as usize], "$1");
            }
            other => panic!("{}: expected a placeholder, got {other:?}", dialect.name()),
        }
    }
    for dialect in [snowflake(), bigquery(), databricks(), mysql()] {
        assert_eq!(
            kind_of(sql, "$1", dialect.as_ref()),
            TokenKind::Literal(LiteralKind::Position),
            "{}",
            dialect.name()
        );
        match where_right(sql, dialect.as_ref()) {
            AstExpr::PositionRef {
                qualifier: None, ..
            } => {}
            other => panic!(
                "{}: expected a positional column, got {other:?}",
                dialect.name()
            ),
        }
    }

    // A signed parameter and one as a grouping expression parse as a
    // parameter does anywhere else.
    let pg = postgres();
    let sql = "SELECT +$1, -$2 FROM t GROUP BY $3";
    let select = select_of(sql, pg.as_ref());
    let AstProjectionKind::Columns(items) = &select.projection.kind else {
        panic!("expected a column list, got {:?}", select.projection.kind);
    };
    let written: Vec<&str> = items
        .iter()
        .map(|item| match &item.kind {
            ProjectionItemKind::SelectItem(item) => match &item.expr {
                AstExpr::Placeholder { span, .. } => &sql[span.start as usize..span.end as usize],
                other => panic!("expected a placeholder, got {other:?}"),
            },
            other => panic!("expected a select item, got {other:?}"),
        })
        .collect();
    assert_eq!(written, ["+$1", "-$2"]);
    let group_by = select.group_by.as_ref().expect("group by");
    let AstGroupByVariant::Standard(keys) = &group_by.variant else {
        panic!("expected plain grouping keys, got {:?}", group_by.variant);
    };
    assert!(
        matches!(keys.as_slice(), [key] if matches!(key.expr, AstExpr::Placeholder { .. })),
        "{keys:?}"
    );

    // After a qualifier it is a position under every dialect.
    for dialect in [
        snowflake(),
        postgres(),
        redshift(),
        bigquery(),
        databricks(),
        mysql(),
        mssql(),
    ] {
        let select = select_of("SELECT src.$1 FROM t src", dialect.as_ref());
        let AstProjectionKind::Columns(items) = &select.projection.kind else {
            panic!("expected a column list, got {:?}", select.projection.kind);
        };
        assert!(
            matches!(
                items.as_slice(),
                [item] if matches!(
                    &item.kind,
                    ProjectionItemKind::SelectItem(item) if matches!(
                        item.expr,
                        AstExpr::PositionRef { qualifier: Some(_), .. }
                    )
                )
            ),
            "{}: {items:?}",
            dialect.name()
        );
    }
}

#[test]
fn a_signed_position_is_the_position_token_alone() {
    let sql = "SELECT - $1, + $2 FROM t";
    let select = select_of(sql, snowflake().as_ref());
    let AstProjectionKind::Columns(items) = &select.projection.kind else {
        panic!("expected a column list, got {:?}", select.projection.kind);
    };
    let exprs: Vec<&AstExpr> = items
        .iter()
        .map(|item| match &item.kind {
            ProjectionItemKind::SelectItem(item) => &item.expr,
            other => panic!("expected a select item, got {other:?}"),
        })
        .collect();
    let position = |expr: &AstExpr| match expr {
        AstExpr::PositionRef {
            qualifier: None,
            dollar_span,
            index_span,
            ..
        } => (
            &sql[dollar_span.start as usize..dollar_span.end as usize],
            &sql[index_span.start as usize..index_span.end as usize],
        ),
        other => panic!("expected a positional column, got {other:?}"),
    };
    let [negated, plus] = exprs.as_slice() else {
        panic!("expected two items, got {exprs:?}");
    };
    // The minus is kept, as a subtraction from nothing.
    let AstExpr::BinaryOp {
        operator: BinaryOperator::Minus,
        right,
        span,
        ..
    } = negated
    else {
        panic!("expected a negation, got {negated:?}");
    };
    assert_eq!(&sql[span.start as usize..span.end as usize], "- $1");
    assert_eq!(position(right), ("$", "1"));
    assert_eq!(position(plus), ("$", "2"));
}

/// The text a money literal was written as and its amount.
fn money<'a>(sql: &'a str, expr: &AstExpr) -> (&'a str, &'a str) {
    match expr {
        AstExpr::Literal {
            literal: AstLiteral::Money { span, amount_span },
            ..
        } => (
            &sql[span.start as usize..span.end as usize],
            &sql[amount_span.start as usize..amount_span.end as usize],
        ),
        other => panic!("expected a money literal, got {other:?}"),
    }
}

#[test]
fn a_dollar_number_is_a_money_literal_in_tsql() {
    let tsql = mssql();
    let sql = "SELECT name FROM items WHERE price > $100";
    assert_eq!(
        kind_of(sql, "$100", tsql.as_ref()),
        TokenKind::Literal(LiteralKind::Money)
    );
    assert_eq!(
        money(sql, &where_right(sql, tsql.as_ref())),
        ("$100", "100")
    );
    // The fraction is part of the one token.
    let sql = "SELECT name FROM items WHERE price > $1.50";
    assert_eq!(
        kind_of(sql, "$1.50", tsql.as_ref()),
        TokenKind::Literal(LiteralKind::Money)
    );
    assert_eq!(
        money(sql, &where_right(sql, tsql.as_ref())),
        ("$1.50", "1.50")
    );
    // Signed: the plus is in the literal's text, the minus is a negation
    // of the literal alone.
    let sql = "SELECT +$5, -$7.25 FROM items";
    let select = select_of(sql, tsql.as_ref());
    let AstProjectionKind::Columns(items) = &select.projection.kind else {
        panic!("expected a column list, got {:?}", select.projection.kind);
    };
    let exprs: Vec<&AstExpr> = items
        .iter()
        .map(|item| match &item.kind {
            ProjectionItemKind::SelectItem(item) => &item.expr,
            other => panic!("expected a select item, got {other:?}"),
        })
        .collect();
    let [plus, negated] = exprs.as_slice() else {
        panic!("expected two items, got {exprs:?}");
    };
    assert_eq!(money(sql, plus), ("+$5", "5"));
    let AstExpr::BinaryOp {
        operator: BinaryOperator::Minus,
        right,
        ..
    } = negated
    else {
        panic!("expected a negation, got {negated:?}");
    };
    assert_eq!(money(sql, right), ("$7.25", "7.25"));
    // The formatter writes each as it was written.
    let config = FormatterConfig {
        dialect: mssql(),
        ..FormatterConfig::default()
    };
    for sql in [
        "SELECT name FROM items WHERE price > $100;",
        "UPDATE items SET price = $5 WHERE id = 1;",
        "INSERT INTO items (price) VALUES ($100);",
        "SELECT $1.50 AS fee, +$5 AS tip FROM items GROUP BY $1.50;",
    ] {
        let formatted =
            format_sql_with_config(sql, &config).unwrap_or_else(|e| panic!("{sql}: {e:?}"));
        verify_formatting_safe_with_dialect(sql, &formatted, tsql.as_ref())
            .unwrap_or_else(|e| panic!("{sql}: {e}\n{formatted}"));
    }
}

// ============================================================================
// Operators one dialect has and another does not
// ============================================================================

/// The token of a name that is also `operator` in the lexer's dialect.
fn word_operator(operator: WordOperator) -> TokenKind {
    TokenKind::Identifier {
        kind: IdentifierKind::Unquoted,
        word_operator: Some(operator),
    }
}

/// The `WHERE` of `sql`, which is one `SELECT` whose predicate runs to the
/// end of the text.
fn whole_where(sql: &str, dialect: &dyn Dialect) -> AstExpr {
    let script = parse_sql_with_dialect(sql, dialect)
        .unwrap_or_else(|e| panic!("{sql:?} should parse under {}: {e:?}", dialect.name()));
    let [AstStmt::Select(select)] = script.stmts.as_slice() else {
        panic!(
            "{}: expected one SELECT for {sql:?}, got {:?}",
            dialect.name(),
            script.stmts
        );
    };
    let expr = &select.where_clause.as_ref().expect("where clause").expr;
    assert_eq!(
        expr.span().end as usize,
        sql.len(),
        "{}: the predicate of {sql:?} stops short: {expr:?}",
        dialect.name()
    );
    expr.clone()
}

/// The operator and operands of a binary operation.
fn binary(expr: &AstExpr) -> (BinaryOperator, &AstExpr, &AstExpr) {
    match expr {
        AstExpr::BinaryOp {
            operator,
            left,
            right,
            ..
        } => (*operator, left, right),
        other => panic!("expected a binary operation, got {other:?}"),
    }
}

/// The operators and operands of a run of operators of one level.
fn run(expr: &AstExpr) -> (Vec<BinaryOperator>, Vec<&AstExpr>) {
    match expr {
        AstExpr::OperatorChain {
            operators,
            operands,
            ..
        } => (
            operators.iter().map(|op| op.operator).collect(),
            operands.iter().map(AsRef::as_ref).collect(),
        ),
        other => panic!("expected a run of operators, got {other:?}"),
    }
}

/// `expr` as it was written.
fn written<'a>(sql: &'a str, expr: &AstExpr) -> &'a str {
    let span = expr.span();
    &sql[span.start as usize..span.end as usize]
}

/// Formats `sql` under `dialect` and checks that no token was lost.
fn formatted(sql: &str, dialect: &DialectRef) -> String {
    let config = FormatterConfig {
        dialect: dialect.clone(),
        ..FormatterConfig::default()
    };
    let formatted = format_sql_with_config(sql, &config).unwrap_or_else(|e| panic!("{sql}: {e:?}"));
    verify_formatting_safe_with_dialect(sql, &formatted, dialect.as_ref())
        .unwrap_or_else(|e| panic!("{sql}: {e}\n{formatted}"));
    formatted
}

fn every_dialect_but_mysql() -> [DialectRef; 6] {
    [
        snowflake(),
        postgres(),
        redshift(),
        bigquery(),
        databricks(),
        mssql(),
    ]
}

#[test]
fn mysql_double_ampersand_is_and() {
    let my = mysql();
    let sql = "SELECT * FROM t WHERE NOT (c > 0 && d > 0)";
    assert_eq!(
        kind_of(sql, "&&", my.as_ref()),
        TokenKind::Operator(Operator::AmpAmpAnd)
    );
    // `NOT` of the conjunction of the two comparisons.
    let predicate = whole_where(sql, my.as_ref());
    let (not, _, negated) = binary(&predicate);
    assert_eq!(not, BinaryOperator::Not);
    let AstExpr::Parenthesized { expr, .. } = negated else {
        panic!("expected parentheses, got {negated:?}");
    };
    let (and, left, right) = binary(expr);
    assert_eq!(and, BinaryOperator::LogicalAnd);
    assert_eq!(
        (written(sql, left), written(sql, right)),
        ("c > 0", "d > 0")
    );

    // It binds as `AND` does: tighter than `OR`, looser than a comparison.
    let sql = "SELECT * FROM t WHERE a = 1 OR b = 2 && c = 3";
    let predicate = whole_where(sql, my.as_ref());
    let (or, left, right) = binary(&predicate);
    assert_eq!(or, BinaryOperator::Or);
    assert_eq!(written(sql, left), "a = 1");
    let (and, left, right) = binary(right);
    assert_eq!(and, BinaryOperator::LogicalAnd);
    assert_eq!(
        (written(sql, left), written(sql, right)),
        ("b = 2", "c = 3")
    );

    // The formatter writes it where it stood.
    let formatted = formatted("SELECT * FROM t WHERE c > 0 && d > 0;", &my);
    assert!(formatted.contains("c > 0 && d > 0"), "{formatted}");
}

#[test]
fn double_ampersand_is_array_overlap_outside_mysql() {
    let sql = "SELECT * FROM t WHERE arr && other";
    for dialect in every_dialect_but_mysql() {
        assert_eq!(
            kind_of(sql, "&&", dialect.as_ref()),
            TokenKind::Operator(Operator::AmpAmp),
            "{}",
            dialect.name()
        );
        let predicate = whole_where(sql, dialect.as_ref());
        let (overlap, left, right) = binary(&predicate);
        assert_eq!(overlap, BinaryOperator::ArrayOverlap, "{}", dialect.name());
        assert_eq!((written(sql, left), written(sql, right)), ("arr", "other"));
    }
    // It binds as a comparison does.
    let pg = postgres();
    let sql = "SELECT * FROM t WHERE a && b AND c && d";
    let predicate = whole_where(sql, pg.as_ref());
    let (and, left, right) = binary(&predicate);
    assert_eq!(and, BinaryOperator::And);
    assert_eq!(
        (written(sql, left), written(sql, right)),
        ("a && b", "c && d")
    );
}

fn every_dialect() -> [DialectRef; 7] {
    [
        snowflake(),
        postgres(),
        redshift(),
        bigquery(),
        databricks(),
        mssql(),
        mysql(),
    ]
}

#[test]
fn bitwise_and_or_and_shifts_are_the_same_tokens_in_every_dialect() {
    let sql = "SELECT a & b | c << 1 >> 2 FROM t";
    for dialect in every_dialect() {
        let name = dialect.name();
        for (lexeme, operator) in [
            ("&", Operator::Amp),
            ("|", Operator::Bar),
            ("<<", Operator::LtLt),
            (">>", Operator::GtGt),
        ] {
            assert_eq!(
                kind_of(sql, lexeme, dialect.as_ref()),
                TokenKind::Operator(operator),
                "{lexeme} in {name}"
            );
        }
    }
    // The compound assignments stay one token each.
    let ms = mssql();
    assert_eq!(
        kind_of("SET @f &= 4", "&=", ms.as_ref()),
        TokenKind::Operator(Operator::AmpEq)
    );
    assert_eq!(
        kind_of("SET @f |= 4", "|=", ms.as_ref()),
        TokenKind::Operator(Operator::PipeEq)
    );
}

#[test]
fn the_operators_around_the_bitwise_ones_are_unchanged() {
    for dialect in every_dialect() {
        let name = dialect.name();
        assert_eq!(
            kind_of("SELECT a || b", "||", dialect.as_ref()),
            TokenKind::Operator(Operator::PipePipe),
            "{name}"
        );
    }
    for dialect in [snowflake(), postgres(), redshift(), databricks()] {
        assert_eq!(
            kind_of("SELECT a #> b", "#>", dialect.as_ref()),
            TokenKind::Operator(Operator::HashGt),
            "{}",
            dialect.name()
        );
    }
    assert_eq!(
        kind_of("FROM t |> WHERE a", "|>", bigquery().as_ref()),
        TokenKind::Operator(Operator::PipeGt)
    );
    // `#` starts a comment in MySQL and is the operator in PostgreSQL.
    let sql = "SELECT a # b";
    assert_eq!(token_lexemes(sql, mysql().as_ref()), ["SELECT", "a"]);
    assert_eq!(
        kind_of(sql, "#", postgres().as_ref()),
        TokenKind::Operator(Operator::Hash)
    );
    // The binary `~` is the regex match.
    let pg = postgres();
    let sql = "SELECT * FROM t WHERE name ~ 'x'";
    let (regex, _, _) = binary(&whole_where(sql, pg.as_ref()));
    assert_eq!(regex, BinaryOperator::RegexMatch);
}

#[test]
fn caret_is_exponent_in_postgres_and_xor_elsewhere() {
    let sql = "SELECT * FROM t WHERE a ^ 2 = 4";
    for dialect in every_dialect() {
        let name = dialect.name();
        let postgres = name == postgres().name();
        assert_eq!(
            kind_of(sql, "^", dialect.as_ref()),
            TokenKind::Operator(if postgres {
                Operator::Power
            } else {
                Operator::Caret
            }),
            "{name}"
        );
        let predicate = whole_where(sql, dialect.as_ref());
        let (_, caret, _) = binary(&predicate);
        let (operator, left, right) = binary(caret);
        let expected = if postgres {
            BinaryOperator::Exponent
        } else {
            BinaryOperator::BitwiseXor
        };
        assert_eq!(operator, expected, "{name}");
        assert_eq!((written(sql, left), written(sql, right)), ("a", "2"));
    }
}

#[test]
fn bitwise_operators_bind_below_addition_and_above_comparison() {
    for dialect in every_dialect() {
        let name = dialect.name();
        let dialect = dialect.as_ref();

        // `a + b << 2` is `(a + b) << 2`.
        let sql = "SELECT * FROM t WHERE a + b << 2 = 8";
        let predicate = whole_where(sql, dialect);
        let (equal, shifted, _) = binary(&predicate);
        assert_eq!(equal, BinaryOperator::Equal, "{name}");
        let (shift, sum, _) = binary(shifted);
        assert_eq!(shift, BinaryOperator::LeftShift, "{name}");
        assert_eq!(written(sql, sum), "a + b", "{name}");

        // `flags & 4 = 4 AND tenant_id = 1` keeps the tenant predicate.
        let sql = "SELECT * FROM t WHERE flags & 4 = 4 AND tenant_id = 1";
        let predicate = whole_where(sql, dialect);
        let (and, masked, tenant) = binary(&predicate);
        assert_eq!(and, BinaryOperator::And, "{name}");
        assert_eq!(written(sql, masked), "flags & 4 = 4", "{name}");
        assert_eq!(written(sql, tenant), "tenant_id = 1", "{name}");

        // One level, left to right.
        let sql = "SELECT * FROM t WHERE a | b & c >> 1 = 0";
        let predicate = whole_where(sql, dialect);
        let (_, chain, _) = binary(&predicate);
        let (operators, operands) = run(chain);
        assert_eq!(
            operators,
            [
                BinaryOperator::BitwiseOr,
                BinaryOperator::BitwiseAnd,
                BinaryOperator::RightShift
            ],
            "{name}"
        );
        let operands: Vec<&str> = operands.iter().map(|e| written(sql, e)).collect();
        assert_eq!(operands, ["a", "b", "c", "1"], "{name}");
    }
}

#[test]
fn exponent_binds_above_multiplication_and_a_prefix_tilde_binds_the_operand() {
    let pg = postgres();
    let sql = "SELECT * FROM t WHERE a * b ^ 2 = 0";
    let predicate = whole_where(sql, pg.as_ref());
    let (_, product, _) = binary(&predicate);
    let (multiply, left, power) = binary(product);
    assert_eq!(multiply, BinaryOperator::Multiply);
    assert_eq!(written(sql, left), "a");
    assert_eq!(binary(power).0, BinaryOperator::Exponent);

    let sql = "SELECT * FROM t WHERE a ^ 2 ^ 3 = 0";
    let predicate = whole_where(sql, pg.as_ref());
    let (_, chain, _) = binary(&predicate);
    let (_, left, _) = binary(chain);
    assert_eq!(written(sql, left), "a ^ 2");

    for dialect in every_dialect() {
        let name = dialect.name();
        let sql = "SELECT * FROM t WHERE ~flags & 4 = 0 AND tenant_id = 1";
        let predicate = whole_where(sql, dialect.as_ref());
        let (and, comparison, tenant) = binary(&predicate);
        assert_eq!(and, BinaryOperator::And, "{name}");
        assert_eq!(written(sql, tenant), "tenant_id = 1", "{name}");
        let (_, masked, _) = binary(comparison);
        let (bitand, inverted, _) = binary(masked);
        assert_eq!(bitand, BinaryOperator::BitwiseAnd, "{name}");
        let (not, _, operand) = binary(inverted);
        assert_eq!(not, BinaryOperator::BitwiseNot, "{name}");
        assert_eq!(written(sql, operand), "flags", "{name}");
        assert_eq!(written(sql, inverted), "~flags", "{name}");

        // A prefix `~` binds tighter than `*`.
        let sql = "SELECT * FROM t WHERE ~a * b = 0";
        let predicate = whole_where(sql, dialect.as_ref());
        let (_, product, _) = binary(&predicate);
        let (multiply, left, _) = binary(product);
        assert_eq!(multiply, BinaryOperator::Multiply, "{name}");
        assert_eq!(written(sql, left), "~a", "{name}");
    }
}

#[test]
fn bitwise_expressions_are_written_back_as_they_were() {
    let sources = [
        "UPDATE t SET flags = flags | 4 WHERE id = 1",
        "DELETE FROM t WHERE flags & 4 = 4 AND tenant_id = 1",
        "SELECT ~flags, a << 2, b >> 1, c ^ d FROM t",
        "SELECT a & ~b | c FROM t",
        "SET @f &= 4",
    ];
    for dialect in every_dialect() {
        for sql in sources {
            formatted(sql, &dialect);
        }
    }
    let pg = postgres();
    let written_back = formatted("SELECT a * b ^ 2, ~c, d # e FROM t", &pg);
    assert!(written_back.contains("b ^ 2"), "{written_back}");
    assert!(written_back.contains("~c"), "{written_back}");
}

#[test]
fn mysql_xor_is_a_logical_operator() {
    let my = mysql();
    let sql = "SELECT * FROM t WHERE c IS NOT NULL XOR d > 0";
    assert_eq!(
        kind_of(sql, "XOR", my.as_ref()),
        word_operator(WordOperator::Xor)
    );
    let predicate = whole_where(sql, my.as_ref());
    let (xor, left, right) = binary(&predicate);
    assert_eq!(xor, BinaryOperator::Xor);
    assert!(
        matches!(
            left,
            AstExpr::IsNull {
                not_span: Some(_),
                ..
            }
        ),
        "{left:?}"
    );
    assert_eq!(
        (written(sql, left), written(sql, right)),
        ("c IS NOT NULL", "d > 0")
    );

    // Between `OR` and `AND`: `a OR (b XOR (c AND d))`.
    let sql = "SELECT * FROM t WHERE a OR b xor c AND d";
    let predicate = whole_where(sql, my.as_ref());
    let (or, left, right) = binary(&predicate);
    assert_eq!(or, BinaryOperator::Or);
    assert_eq!(written(sql, left), "a");
    let (xor, left, right) = binary(right);
    assert_eq!(xor, BinaryOperator::Xor);
    assert_eq!((written(sql, left), written(sql, right)), ("b", "c AND d"));
    // And it groups from the left: one run.
    let sql = "SELECT * FROM t WHERE a XOR b XOR c";
    let predicate = whole_where(sql, my.as_ref());
    let (operators, operands) = run(&predicate);
    assert_eq!(operators, [BinaryOperator::Xor, BinaryOperator::Xor]);
    let operands: Vec<&str> = operands.iter().map(|e| written(sql, e)).collect();
    assert_eq!(operands, ["a", "b", "c"]);

    let formatted = formatted("SELECT * FROM t WHERE c IS NOT NULL XOR d > 0;", &my);
    assert!(formatted.contains("c IS NOT NULL XOR d > 0"), "{formatted}");
}

/// The expressions of the select list of `select`.
fn select_items(select: &AstSelect) -> Vec<&AstExpr> {
    let AstProjectionKind::Columns(items) = &select.projection.kind else {
        panic!("expected a column list, got {:?}", select.projection.kind);
    };
    items
        .iter()
        .map(|item| match &item.kind {
            ProjectionItemKind::SelectItem(item) => &item.expr,
            other => panic!("expected a select item, got {other:?}"),
        })
        .collect()
}

#[test]
fn mysql_div_and_mod_are_arithmetic() {
    let my = mysql();
    let sql = "SELECT a DIV b, a MOD b FROM t WHERE a DIV 2 > 0";
    assert_eq!(
        kind_of(sql, "DIV", my.as_ref()),
        word_operator(WordOperator::IntegerDivide)
    );
    assert_eq!(
        kind_of(sql, "MOD", my.as_ref()),
        word_operator(WordOperator::Modulo)
    );
    let predicate = whole_where(sql, my.as_ref());
    let (greater, left, right) = binary(&predicate);
    assert_eq!(greater, BinaryOperator::GreaterThan);
    assert_eq!((written(sql, left), written(sql, right)), ("a DIV 2", "0"));
    assert_eq!(binary(left).0, BinaryOperator::IntegerDivide);
    let select = select_of(sql, my.as_ref());
    let items = select_items(&select);
    let [quotient, remainder] = items.as_slice() else {
        panic!("expected two items, got {items:?}");
    };
    assert_eq!(binary(quotient).0, BinaryOperator::IntegerDivide);
    assert_eq!(written(sql, quotient), "a DIV b");
    assert_eq!(binary(remainder).0, BinaryOperator::Modulo);
    assert_eq!(written(sql, remainder), "a MOD b");

    // They bind as `*` and `/` do, from the left.
    let sql = "SELECT * FROM t WHERE a + b div c * d mod e > 0";
    let predicate = whole_where(sql, my.as_ref());
    let (_, sum, _) = binary(&predicate);
    let (plus, left, right) = binary(sum);
    assert_eq!(plus, BinaryOperator::Plus);
    assert_eq!(
        (written(sql, left), written(sql, right)),
        ("a", "b div c * d mod e")
    );
    let (operators, operands) = run(right);
    assert_eq!(
        operators,
        [
            BinaryOperator::IntegerDivide,
            BinaryOperator::Multiply,
            BinaryOperator::Modulo
        ]
    );
    let operands: Vec<&str> = operands.iter().map(|e| written(sql, e)).collect();
    assert_eq!(operands, ["b", "c", "d", "e"]);

    // Before a parenthesis `MOD` is the function where an operand is
    // due, and the operator after one.
    let sql = "SELECT * FROM t WHERE MOD(a, 2) = a MOD (b + 1)";
    let predicate = whole_where(sql, my.as_ref());
    let (equal, left, right) = binary(&predicate);
    assert_eq!(equal, BinaryOperator::Equal);
    assert!(matches!(left, AstExpr::FunctionCall { .. }), "{left:?}");
    assert_eq!(binary(right).0, BinaryOperator::Modulo);
    assert_eq!(written(sql, right), "a MOD (b + 1)");

    let formatted = formatted("SELECT a DIV b, MOD(a, 2) FROM t WHERE a MOD 2 = 1;", &my);
    assert!(formatted.contains("a DIV b"), "{formatted}");
    assert!(formatted.contains("MOD(a, 2)"), "{formatted}");
    assert!(formatted.contains("a MOD 2 = 1"), "{formatted}");
}

#[test]
fn databricks_div_is_integer_division() {
    let dbx = databricks();
    let sql = "SELECT a DIV b FROM t WHERE a div 2 > 0";
    assert_eq!(
        kind_of(sql, "DIV", dbx.as_ref()),
        word_operator(WordOperator::IntegerDivide)
    );
    let predicate = whole_where(sql, dbx.as_ref());
    let (greater, left, right) = binary(&predicate);
    assert_eq!(greater, BinaryOperator::GreaterThan);
    assert_eq!((written(sql, left), written(sql, right)), ("a div 2", "0"));
    assert_eq!(binary(left).0, BinaryOperator::IntegerDivide);
    let select = select_of(sql, dbx.as_ref());
    let items = select_items(&select);
    let [quotient] = items.as_slice() else {
        panic!("expected one item, got {items:?}");
    };
    assert_eq!(binary(quotient).0, BinaryOperator::IntegerDivide);
    assert_eq!(written(sql, quotient), "a DIV b");

    // It binds as `*` and `/` do.
    let sql = "SELECT * FROM t WHERE a + b div c * d > 0";
    let predicate = whole_where(sql, dbx.as_ref());
    let (_, sum, _) = binary(&predicate);
    let (plus, left, right) = binary(sum);
    assert_eq!(plus, BinaryOperator::Plus);
    assert_eq!(
        (written(sql, left), written(sql, right)),
        ("a", "b div c * d")
    );
    let (operators, operands) = run(right);
    assert_eq!(
        operators,
        [BinaryOperator::IntegerDivide, BinaryOperator::Multiply]
    );
    let operands: Vec<&str> = operands.iter().map(|e| written(sql, e)).collect();
    assert_eq!(operands, ["b", "c", "d"]);

    // `mod` is a function there and no infix operator.
    assert_word_is_a_column("mod", &dbx);

    let formatted = formatted("SELECT a DIV b FROM t WHERE a div 2 > 0;", &dbx);
    assert!(formatted.contains("SELECT a DIV b"), "{formatted}");
    assert!(formatted.contains("a div 2 > 0"), "{formatted}");
}

/// `word` is a column wherever `dialect` reads it in `SELECT <word>, t.<word>
/// FROM t WHERE <word> > 0`.
fn assert_word_is_a_column(word: &str, dialect: &DialectRef) {
    let sql = format!("SELECT {word}, t.{word} FROM t WHERE {word} > 0");
    assert_eq!(
        kind_of(&sql, word, dialect.as_ref()),
        TokenKind::Identifier {
            kind: IdentifierKind::Unquoted,
            word_operator: None,
        },
        "{word} under {}",
        dialect.name()
    );
    let predicate = whole_where(&sql, dialect.as_ref());
    let (greater, left, _) = binary(&predicate);
    assert_eq!(greater, BinaryOperator::GreaterThan);
    assert!(
        matches!(left, AstExpr::Ident { .. }),
        "{word} under {}: {left:?}",
        dialect.name()
    );
    // As an alias, where an operator would stand.
    let sql = format!("SELECT a {word} FROM t");
    let select = select_of(&sql, dialect.as_ref());
    let AstProjectionKind::Columns(items) = &select.projection.kind else {
        panic!("expected a column list, got {:?}", select.projection.kind);
    };
    assert!(
        matches!(
            items.as_slice(),
            [item] if matches!(
                &item.kind,
                ProjectionItemKind::SelectItem(item) if item.alias.is_some()
            )
        ),
        "{word} under {}: {items:?}",
        dialect.name()
    );
}

#[test]
fn a_mysql_word_operator_is_an_identifier_elsewhere() {
    for dialect in every_dialect_but_mysql() {
        // Spark has the integer division too.
        let has_div = dialect.name() == databricks().name();
        for word in ["xor", "XOR", "div", "DIV", "mod", "MOD"] {
            if has_div && word.eq_ignore_ascii_case("div") {
                continue;
            }
            assert_word_is_a_column(word, &dialect);
        }
        // And `MOD` a function to call.
        let sql = "SELECT * FROM t WHERE MOD(a, 2) = 1";
        let predicate = whole_where(sql, dialect.as_ref());
        let (_, left, _) = binary(&predicate);
        assert!(
            matches!(left, AstExpr::FunctionCall { .. }),
            "{}: {left:?}",
            dialect.name()
        );
    }
}

/// The operand of a NULL test, and whether the test is negated.
fn null_test(expr: &AstExpr) -> (&AstExpr, bool) {
    match expr {
        AstExpr::IsNull { expr, not_span, .. } => (expr, not_span.is_some()),
        other => panic!("expected a NULL test, got {other:?}"),
    }
}

#[test]
fn postgres_postfix_isnull_is_a_null_test() {
    for dialect in [postgres(), redshift()] {
        let name = dialect.name();
        let sql = "SELECT * FROM a LEFT JOIN b ON a.id = b.id WHERE b.y ISNULL";
        assert_eq!(
            kind_of(sql, "ISNULL", dialect.as_ref()),
            word_operator(WordOperator::IsNull),
            "{name}"
        );
        let predicate = whole_where(sql, dialect.as_ref());
        let (tested, negated) = null_test(&predicate);
        assert!(!negated, "{name}");
        assert!(
            matches!(tested, AstExpr::Ident { .. }),
            "{name}: {tested:?}"
        );
        assert_eq!(written(sql, &predicate), "b.y ISNULL", "{name}");

        // It binds as `IS NULL` does: after a comparison, before `OR`.
        let sql = "SELECT * FROM t WHERE a = b isnull OR c";
        let predicate = whole_where(sql, dialect.as_ref());
        let (or, left, _) = binary(&predicate);
        assert_eq!(or, BinaryOperator::Or, "{name}");
        let (tested, negated) = null_test(left);
        assert!(!negated, "{name}");
        assert_eq!(written(sql, tested), "a = b", "{name}");

        // Where an operand is due, the word before a parenthesis is a
        // function.
        let sql = "SELECT * FROM t WHERE isnull(a) = b";
        let predicate = whole_where(sql, dialect.as_ref());
        let (_, left, _) = binary(&predicate);
        assert!(
            matches!(left, AstExpr::FunctionCall { .. }),
            "{name}: {left:?}"
        );

        let postfix = formatted("SELECT * FROM t WHERE c ISNULL AND d > 0;", &dialect);
        assert!(postfix.contains("c ISNULL\n"), "{name}: {postfix}");
        // And the spelled-out test as it was.
        let spelled = formatted(
            "SELECT * FROM t WHERE c IS NULL AND d IS NOT NULL;",
            &dialect,
        );
        assert!(spelled.contains("c IS NULL\n"), "{name}: {spelled}");
        assert!(spelled.contains("d IS NOT NULL;"), "{name}: {spelled}");
    }
}

#[test]
fn postgres_postfix_notnull_is_a_not_null_test() {
    for dialect in [postgres(), redshift()] {
        let name = dialect.name();
        let sql = "SELECT * FROM t WHERE c NOTNULL AND d > 0";
        assert_eq!(
            kind_of(sql, "NOTNULL", dialect.as_ref()),
            word_operator(WordOperator::NotNull),
            "{name}"
        );
        let predicate = whole_where(sql, dialect.as_ref());
        let (and, left, right) = binary(&predicate);
        assert_eq!(and, BinaryOperator::And, "{name}");
        let (tested, negated) = null_test(left);
        assert!(negated, "{name}");
        assert_eq!(written(sql, tested), "c", "{name}");
        assert_eq!(
            (written(sql, left), written(sql, right)),
            ("c NOTNULL", "d > 0"),
            "{name}"
        );

        // Of a sum, and under `NOT`.
        let sql = "SELECT * FROM t WHERE NOT a + b notnull";
        let predicate = whole_where(sql, dialect.as_ref());
        let (not, _, negated_test) = binary(&predicate);
        assert_eq!(not, BinaryOperator::Not, "{name}");
        let (tested, negated) = null_test(negated_test);
        assert!(negated, "{name}");
        assert_eq!(written(sql, tested), "a + b", "{name}");

        let postfix = formatted(
            "SELECT c NOTNULL AS has_c FROM t WHERE c NOTNULL;",
            &dialect,
        );
        assert!(
            postfix.contains("SELECT c NOTNULL AS has_c"),
            "{name}: {postfix}"
        );
        assert!(postfix.contains("c NOTNULL;"), "{name}: {postfix}");
    }
}

#[test]
fn a_postfix_null_test_word_is_an_identifier_elsewhere() {
    for dialect in [snowflake(), bigquery(), databricks(), mysql(), mssql()] {
        for word in ["isnull", "ISNULL", "notnull", "NOTNULL"] {
            assert_word_is_a_column(word, &dialect);
        }
        // And `ISNULL` a function to call.
        let sql = "SELECT * FROM t WHERE ISNULL(a, 0) = 1";
        let predicate = whole_where(sql, dialect.as_ref());
        let (_, left, _) = binary(&predicate);
        assert!(
            matches!(left, AstExpr::FunctionCall { .. }),
            "{}: {left:?}",
            dialect.name()
        );
    }
}

// ============================================================================
// A word that is also an operator is a name wherever a name is read
// ============================================================================

/// The kinds of the statements of `sql`, each as its variant is named, after
/// checking that `sql` formats with every token present.
fn statement_kinds(sql: &str, dialect: &DialectRef) -> Vec<String> {
    let script = parse_sql_with_dialect(sql, dialect.as_ref())
        .unwrap_or_else(|e| panic!("{sql:?} should parse under {}: {e:?}", dialect.name()));
    formatted(sql, dialect);
    script
        .stmts
        .iter()
        .map(|stmt| {
            format!("{stmt:?}")
                .chars()
                .take_while(char::is_ascii_alphanumeric)
                .collect()
        })
        .collect()
}

/// A statement with `{w}` where a name stands, and the kind it parses to.
type NameSite = (&'static str, &'static str);

/// Name positions every dialect has.
const NAME_SITES: &[NameSite] = &[
    ("SELECT * FROM {w}", "Select"),
    ("CREATE TABLE t (a int, {w} int)", "CreateTable"),
    ("SELECT {w} FROM t", "Select"),
    ("SELECT t.{w} FROM t", "Select"),
    ("SELECT {w}(a) FROM t", "Select"),
    ("SELECT a FROM t ORDER BY {w}", "Select"),
    ("SELECT a FROM t GROUP BY {w}", "Select"),
    ("SELECT a FROM t JOIN u ON t.{w} = u.{w}", "Select"),
    ("INSERT INTO {w} ({w}) VALUES (1)", "Insert"),
    ("UPDATE {w} SET {w} = 1 WHERE {w} = 2", "Update"),
    ("DELETE FROM {w} WHERE {w} = 1", "Delete"),
    ("DROP TABLE {w}", "Drop"),
    ("CALL {w}(1)", "Call"),
    ("CALL s.{w}(1)", "Call"),
    ("USE {w}", "Use"),
    ("ALTER TABLE s.{w} RENAME TO {w}", "AlterTable"),
];

const MYSQL_NAME_SITES: &[NameSite] = &[
    (
        "CREATE FUNCTION {w}(a INT) RETURNS INT RETURN a",
        "CreateFunction",
    ),
    (
        "CREATE FUNCTION s.{w}(a INT) RETURNS INT RETURN a",
        "CreateFunction",
    ),
    (
        "CREATE PROCEDURE {w}() BEGIN SELECT 1; END",
        "CreateProcedure",
    ),
    (
        "CREATE PROCEDURE s.{w}() BEGIN SELECT 1; END",
        "CreateProcedure",
    ),
    ("GRANT SELECT ON db.{w} TO 'u'@'h'", "Grant"),
    ("SET {w} = 1", "MysqlSet"),
];

const POSTGRES_NAME_SITES: &[NameSite] = &[
    (
        "CREATE FUNCTION {w}(a int) RETURNS int AS $$ SELECT a $$ LANGUAGE sql",
        "CreateFunction",
    ),
    (
        "CREATE FUNCTION s.{w}(a int) RETURNS int AS $$ SELECT a $$ LANGUAGE sql",
        "CreateFunction",
    ),
    (
        "CREATE PROCEDURE {w}() LANGUAGE sql AS $$ SELECT 1 $$",
        "CreateProcedure",
    ),
    (
        "CREATE PROCEDURE s.{w}() LANGUAGE sql AS $$ SELECT 1 $$",
        "CreateProcedure",
    ),
    ("GRANT SELECT ON s.{w} TO u", "Grant"),
];

const REDSHIFT_NAME_SITES: &[NameSite] = &[
    (
        "CREATE FUNCTION {w}(a int) RETURNS int STABLE AS $$ SELECT $1 $$ LANGUAGE sql",
        "CreateFunction",
    ),
    (
        "CREATE FUNCTION s.{w}(a int) RETURNS int STABLE AS $$ SELECT $1 $$ LANGUAGE sql",
        "CreateFunction",
    ),
    (
        "CREATE PROCEDURE {w}() AS $$ BEGIN NULL; END; $$ LANGUAGE plpgsql",
        "CreateProcedure",
    ),
    (
        "CREATE PROCEDURE s.{w}() AS $$ BEGIN NULL; END; $$ LANGUAGE plpgsql",
        "CreateProcedure",
    ),
    ("GRANT SELECT ON s.{w} TO u", "Grant"),
];

/// Every site with every word parses to one statement of the site's kind,
/// as it does with a name that is no operator anywhere.
fn assert_words_are_names(dialect: &DialectRef, words: &[&str], own: &[NameSite]) {
    for (template, kind) in NAME_SITES.iter().chain(own) {
        for word in words.iter().chain(&["zz"]) {
            for word in [word.to_string(), word.to_uppercase()] {
                let sql = template.replace("{w}", &word);
                assert_eq!(
                    statement_kinds(&sql, dialect),
                    [*kind],
                    "{}: {sql}",
                    dialect.name()
                );
            }
        }
    }
}

const DATABRICKS_NAME_SITES: &[NameSite] = &[
    (
        "CREATE FUNCTION {w}(a INT) RETURNS INT RETURN a",
        "CreateFunction",
    ),
    (
        "CREATE FUNCTION s.{w}(a INT) RETURNS INT RETURN a",
        "CreateFunction",
    ),
    ("GRANT SELECT ON s.{w} TO u", "Grant"),
];

/// Whether `sql` parses, in `dialect`, as the one statement `kind`.
fn reads_as(sql: &str, dialect: &DialectRef, kind: &str) -> bool {
    parse_sql_with_dialect(sql, dialect.as_ref()).is_ok() && statement_kinds(sql, dialect) == [kind]
}

#[test]
fn a_word_operator_is_a_name_wherever_a_name_is_read() {
    assert_words_are_names(&databricks(), &["div"], DATABRICKS_NAME_SITES);
    assert_words_are_names(&mysql(), &["xor", "div", "mod"], MYSQL_NAME_SITES);
    assert_words_are_names(&postgres(), &["isnull", "notnull"], POSTGRES_NAME_SITES);
    assert_words_are_names(&redshift(), &["isnull", "notnull"], REDSHIFT_NAME_SITES);
}

#[test]
fn a_word_operator_is_a_label_where_the_dialect_does_not_reserve_it() {
    let column_label = "SELECT a AS {w} FROM t";
    let table_alias = "SELECT a FROM t {w}";
    // Databricks does not reserve DIV.
    for site in [column_label, table_alias] {
        let sql = site.replace("{w}", "div");
        assert!(reads_as(&sql, &databricks(), "Select"), "{sql}");
    }
    // MySQL 8.0 reserves XOR, DIV and MOD.
    for word in ["xor", "div", "mod"] {
        for site in [column_label, table_alias] {
            let sql = site.replace("{w}", word);
            assert!(!reads_as(&sql, &mysql(), "Select"), "{sql}");
        }
    }
    for word in ["isnull", "notnull"] {
        // PostgreSQL takes any keyword as a column label after AS, and a
        // type-or-function-name keyword as no table alias.
        let sql = column_label.replace("{w}", word);
        assert!(reads_as(&sql, &postgres(), "Select"), "{sql}");
        let sql = table_alias.replace("{w}", word);
        assert!(!reads_as(&sql, &postgres(), "Select"), "{sql}");
        // Redshift reserves both.
        for site in [column_label, table_alias] {
            let sql = site.replace("{w}", word);
            assert!(!reads_as(&sql, &redshift(), "Select"), "{sql}");
        }
    }
}

#[test]
fn a_binary_word_operator_with_no_operand_after_it_is_an_alias() {
    let my = mysql();
    // MySQL 8.0 reserves its word operators: no bare alias there.
    for word in ["xor", "div", "mod"] {
        let sql = format!("SELECT a {word} FROM t");
        assert!(!reads_as(&sql, &my, "Select"), "{sql}");
    }
    for (dialect, word) in [(&databricks(), "div")] {
        for sql in [
            format!("SELECT a {word} FROM t"),
            format!("SELECT a {word}, b FROM t"),
        ] {
            assert_eq!(statement_kinds(&sql, dialect), ["Select"], "{sql}");
            let select = select_of(&sql, dialect.as_ref());
            let AstProjectionKind::Columns(items) = &select.projection.kind else {
                panic!("expected a column list, got {:?}", select.projection.kind);
            };
            assert!(
                matches!(
                    &items[0].kind,
                    ProjectionItemKind::SelectItem(item)
                        if item.alias.is_some() && matches!(item.expr, AstExpr::Ident { .. })
                ),
                "{sql}: {items:?}"
            );
        }
    }
    // Before an operand it is the operator.
    let sql = "SELECT a mod b, c FROM t";
    let select = select_of(sql, my.as_ref());
    let items = select_items(&select);
    assert_eq!(binary(items[0]).0, BinaryOperator::Modulo);
}

// ============================================================================
// Number literals: radix prefixes, digit separators, type suffixes
// ============================================================================

#[test]
fn a_number_literal_is_one_token_by_its_dialects_grammar() {
    let one_number = |dialect: &DialectRef, text: &str| {
        let sql = format!("SELECT {text} FROM t");
        let result = tokenize_with_dialect(&sql, dialect.as_ref());
        let number = result
            .tokens
            .iter()
            .find(|t| t.lexeme(&sql) == text)
            .unwrap_or_else(|| {
                panic!(
                    "{text:?} is not one token under {}: {:?}",
                    dialect.name(),
                    token_lexemes(&sql, dialect.as_ref())
                )
            });
        assert_eq!(
            number.kind,
            TokenKind::Literal(LiteralKind::Number),
            "{text:?} under {}",
            dialect.name()
        );
    };
    let read = [
        (mssql(), &["0x41", "0X41", "0xABcd"][..]),
        (mysql(), &["0x41", "0b0101"][..]),
        (
            postgres(),
            &[
                "0x1F",
                "0X1F",
                "0o17",
                "0O17",
                "0b101",
                "0B101",
                "1_000_000",
                "0xFFFF_FFFF",
                "0o_755",
                "1.618_034",
            ][..],
        ),
        (bigquery(), &["0x1F", "0X1F"][..]),
        (
            databricks(),
            &["10L", "10l", "2Y", "3S", "1.5D", "2F", "1.5BD", "1e3D"][..],
        ),
    ];
    for (dialect, texts) in &read {
        for text in *texts {
            one_number(dialect, text);
        }
    }

    // Spellings a dialect does not read stay the number and the word after it.
    let split = [
        (mysql(), "0X41", ["0", "X41"]),
        (mysql(), "0B01", ["0", "B01"]),
        (mysql(), "0o17", ["0", "o17"]),
        (mssql(), "0b01", ["0", "b01"]),
        (bigquery(), "0o17", ["0", "o17"]),
        (snowflake(), "0x41", ["0", "x41"]),
        (redshift(), "0x41", ["0", "x41"]),
        (databricks(), "0x41", ["0", "x41"]),
        (mssql(), "1_000", ["1", "_000"]),
        (snowflake(), "10L", ["10", "L"]),
        (databricks(), "1.5L", ["1.5", "L"]),
        (databricks(), "10Lx", ["10", "Lx"]),
    ];
    for (dialect, text, expected) in &split {
        let sql = format!("SELECT {text} FROM t");
        let lexemes = token_lexemes(&sql, dialect.as_ref());
        assert_eq!(
            &lexemes[1..3],
            expected,
            "{text:?} under {}",
            dialect.name()
        );
    }
}

#[test]
fn a_statement_holding_a_radix_literal_is_read_whole() {
    for dialect in [mssql(), mysql(), postgres(), bigquery()] {
        for sql in [
            "UPDATE t SET c = 0x4142 WHERE id = 1",
            "DELETE FROM t WHERE c = 0x0105;",
            "INSERT INTO t (c) VALUES (0x4142)",
            "SELECT id FROM t WHERE c = 0x01;",
        ] {
            let script = parse_sql_with_dialect(sql, dialect.as_ref())
                .unwrap_or_else(|e| panic!("{sql:?} under {}: {e:?}", dialect.name()));
            assert_eq!(script.stmts.len(), 1, "{sql:?} under {}", dialect.name());
            assert!(
                !matches!(script.stmts[0], AstStmt::OpaqueContent { .. }),
                "{sql:?} under {}: {:?}",
                dialect.name(),
                script.stmts[0]
            );
        }
    }
    let script = parse_sql_with_dialect(
        "DECLARE @c VARBINARY(100) = 0x00\nSET @c = 0xAB\nTRUNCATE TABLE t",
        mssql().as_ref(),
    )
    .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(script.stmts.len(), 3, "{:?}", script.stmts);
}

#[test]
fn a_name_the_lexer_marks_with_at_keeps_its_mark() {
    use lexega_syntax::ast::AstIdentifierKind;
    let kind = |sql: &str, dialect: &dyn Dialect| match where_right(sql, dialect) {
        AstExpr::Ident { column_ref, .. } => column_ref.name.kind,
        other => panic!("{sql}: expected a name, got {other:?}"),
    };
    for dialect in [mssql(), mysql()] {
        for sql in [
            "SELECT * FROM t WHERE c = @p",
            "SELECT * FROM t WHERE c = @@ROWCOUNT",
        ] {
            assert_eq!(
                kind(sql, dialect.as_ref()),
                AstIdentifierKind::Variable,
                "{sql}"
            );
        }
        assert_eq!(
            kind("SELECT * FROM t WHERE c = p", dialect.as_ref()),
            AstIdentifierKind::Name
        );
    }
    assert_eq!(
        kind("SELECT * FROM t WHERE c = p", postgres().as_ref()),
        AstIdentifierKind::Name
    );
}

#[test]
fn a_dollar_name_is_a_session_variable_where_the_dialect_says_so() {
    let sql = "SELECT $q, $Q_2 FROM t WHERE c = $q";
    let select = select_of(sql, snowflake().as_ref());
    let AstProjectionKind::Columns(items) = &select.projection.kind else {
        panic!("expected a column list, got {:?}", select.projection.kind);
    };
    let read: Vec<(&str, &str)> = items
        .iter()
        .map(|item| match &item.kind {
            ProjectionItemKind::SelectItem(item) => match &item.expr {
                AstExpr::SessionVarRef {
                    name_span, span, ..
                } => (
                    &sql[name_span.start as usize..name_span.end as usize],
                    &sql[span.start as usize..span.end as usize],
                ),
                other => panic!("expected a session variable, got {other:?}"),
            },
            other => panic!("expected a select item, got {other:?}"),
        })
        .collect();
    assert_eq!(read, vec![("q", "$q"), ("Q_2", "$Q_2")]);
    assert!(matches!(
        where_right(sql, snowflake().as_ref()),
        AstExpr::SessionVarRef { .. }
    ));
    let config = FormatterConfig {
        dialect: snowflake(),
        ..FormatterConfig::default()
    };
    let formatted = format_sql_with_config(sql, &config).expect("formats");
    verify_formatting_safe_with_dialect(sql, &formatted, config.dialect.as_ref())
        .expect("formats safely");

    // A position and a `$$…$$` string are read as before.
    assert!(matches!(
        where_right("SELECT * FROM t WHERE c = $1", snowflake().as_ref()),
        AstExpr::PositionRef { .. }
    ));
    assert!(matches!(
        where_right("SELECT * FROM t WHERE c = $$a b$$", snowflake().as_ref()),
        AstExpr::Literal {
            literal: AstLiteral::String { .. },
            ..
        }
    ));

    // Where the dialect does not read `$name` so, it is a name.
    for dialect in [
        postgres(),
        redshift(),
        bigquery(),
        databricks(),
        mysql(),
        mssql(),
    ] {
        assert!(
            !dialect.dollar_name_is_session_variable(),
            "{}",
            dialect.name()
        );
    }
    assert!(snowflake().dollar_name_is_session_variable());
    for dialect in [mysql(), mssql(), databricks()] {
        assert!(
            matches!(
                where_right("SELECT * FROM t WHERE c = $q", dialect.as_ref()),
                AstExpr::Ident { .. }
            ),
            "{}",
            dialect.name()
        );
    }
}

// ─── the operators that cut a statement ────────────────────────────────

#[test]
fn postgres_operator_symbols_are_tokens_in_postgres_alone() {
    let pg = postgres();
    for (sql, lexeme, operator) in [
        ("SELECT a @@ b", "@@", Operator::AtAt),
        ("SELECT a @? b", "@?", Operator::AtQuestion),
        ("SELECT @ a", "@", Operator::At),
        ("SELECT a ^@ b", "^@", Operator::CaretAt),
        ("SELECT |/ a", "|/", Operator::BarSlash),
        ("SELECT a ?| b", "?|", Operator::QuestionBar),
        ("SELECT a ?& b", "?&", Operator::QuestionAmp),
    ] {
        assert_eq!(
            kind_of(sql, lexeme, pg.as_ref()),
            TokenKind::Operator(operator),
            "{sql}"
        );
    }
    // A `?` alone is a placeholder token, and `|/*` opens a comment.
    assert_eq!(
        kind_of("SELECT a ? b", "?", pg.as_ref()),
        TokenKind::Placeholder
    );
    assert_eq!(
        token_lexemes("SELECT a |/* c */ b", pg.as_ref()),
        ["SELECT", "a", "|", "b"]
    );

    // Elsewhere `@` is a stage, a variable or a time-travel separator, and
    // `?` before `|` or `&` a placeholder.
    let sf = snowflake();
    assert_eq!(
        kind_of("SELECT * FROM @stage", "@", sf.as_ref()),
        TokenKind::Unknown
    );
    let my = mysql();
    assert_eq!(
        token_kinds("SELECT ?|?", my.as_ref()),
        [
            TokenKind::Keyword(lexega_syntax::Keyword::Select),
            TokenKind::Placeholder,
            TokenKind::Operator(Operator::Bar),
            TokenKind::Placeholder,
        ]
    );
    assert!(matches!(
        kind_of("SELECT @@version", "@@version", my.as_ref()),
        TokenKind::Identifier { .. }
    ));
    assert_eq!(
        kind_of("SELECT a ^@b", "^", mssql().as_ref()),
        TokenKind::Operator(Operator::Caret)
    );
}

#[test]
fn a_bang_is_an_operator_token_in_every_dialect() {
    for dialect in every_dialect() {
        let name = dialect.name();
        for (sql, lexeme, operator) in [
            ("SELECT ! a", "!", Operator::Bang),
            ("SELECT a !< b", "!<", Operator::BangLt),
            ("SELECT a !> b", "!>", Operator::BangGt),
            ("SELECT a != b", "!=", Operator::NotEq),
        ] {
            assert_eq!(
                kind_of(sql, lexeme, dialect.as_ref()),
                TokenKind::Operator(operator),
                "{sql} in {name}"
            );
        }
    }
}

/// `dialect`'s reading of `sql`, one `UPDATE` read to its end: its `WHERE`
/// as written, and its one assignment's value.
fn update_read_whole(sql: &str, dialect: &DialectRef) -> (String, AstExpr) {
    let script = parse_sql_with_dialect(sql, dialect.as_ref())
        .unwrap_or_else(|e| panic!("{sql:?} should parse under {}: {e:?}", dialect.name()));
    let [AstStmt::Update(update)] = script.stmts.as_slice() else {
        panic!(
            "{}: expected one UPDATE for {sql:?}, got {:?}",
            dialect.name(),
            script.stmts
        );
    };
    assert!(script.cut_statements.is_empty(), "{sql}");
    assert_eq!(update.span.end as usize, sql.len(), "{sql}");
    let filter = update.where_clause.as_ref().expect("where clause");
    let [assignment] = update.set_assignments.as_slice() else {
        panic!("expected one assignment in {sql:?}");
    };
    (
        written(sql, filter).to_string(),
        (*assignment.value).clone(),
    )
}

#[test]
fn the_operators_that_cut_a_statement_are_read() {
    use BinaryOperator as B;
    for (dialect, operator, written_value) in [
        (postgres(), B::QueryMatch, "name @@ to_tsquery('x')"),
        (postgres(), B::QueryMatch, "doc @@ '$.a == 1'"),
        (postgres(), B::JsonExistsAny, "tags ?| array['a','b']"),
        (postgres(), B::JsonExistsAll, "tags ?& array['a','b']"),
        (postgres(), B::JsonExists, "tags ? 'a'"),
        (postgres(), B::JsonContains, "doc @? '$.a'"),
        (postgres(), B::StartsWith, "name ^@ 'x'"),
        (postgres(), B::Equal, "id OPERATOR(pg_catalog.=) 2"),
        (postgres(), B::Overlaps, "(d1, d2) OVERLAPS (d3, d4)"),
        (postgres(), B::GreaterThan, "|/ id > 2"),
        (postgres(), B::GreaterThan, "@ id > 2"),
        (mysql(), B::SoundsLike, "name SOUNDS LIKE 'x'"),
        (mysql(), B::MemberOf, "3 MEMBER OF (doc)"),
        (mysql(), B::Equal, "name = BINARY 'x'"),
        (mssql(), B::GreaterThanOrEqual, "id !< 1"),
        (mssql(), B::LessThanOrEqual, "id !> 1"),
    ] {
        let sql = format!("UPDATE users SET flag = {written_value} WHERE id = 1");
        let (filter, value) = update_read_whole(&sql, &dialect);
        assert_eq!(filter, "id = 1", "{sql}");
        assert_eq!(binary(&value).0, operator, "{sql}");
        let sql = format!("UPDATE users SET flag = 1 WHERE {written_value} AND id = 1");
        let (filter, _) = update_read_whole(&sql, &dialect);
        assert_eq!(filter, format!("{written_value} AND id = 1"), "{sql}");
        formatted(&sql, &dialect);
    }
}

#[test]
fn a_prefix_operator_binds_as_its_dialect_binds_it() {
    let pg = postgres();
    // `|/` and `@` take their operand up to PostgreSQL's other operators:
    // `|/ a + b > 2` is `(|/ (a + b)) > 2`.
    for (sql, prefix, operand) in [
        (
            "SELECT * FROM t WHERE |/ a + b > 2",
            BinaryOperator::SquareRoot,
            "a + b",
        ),
        (
            "SELECT * FROM t WHERE @ a - b > 2",
            BinaryOperator::AbsoluteValue,
            "a - b",
        ),
    ] {
        let predicate = whole_where(sql, pg.as_ref());
        let (greater, left, _) = binary(&predicate);
        assert_eq!(greater, BinaryOperator::GreaterThan, "{sql}");
        let (operator, _, right) = binary(left);
        assert_eq!(operator, prefix, "{sql}");
        assert_eq!(written(sql, right), operand, "{sql}");
        formatted(sql, &pg);
    }
    // MySQL's `!` and `BINARY` take one operand: `!a = b` is `(!a) = b`.
    let my = mysql();
    for (sql, prefix) in [
        ("SELECT * FROM t WHERE !a = b", BinaryOperator::Not),
        (
            "SELECT * FROM t WHERE BINARY a = b",
            BinaryOperator::BinaryCast,
        ),
    ] {
        let predicate = whole_where(sql, my.as_ref());
        let (equal, left, right) = binary(&predicate);
        assert_eq!(equal, BinaryOperator::Equal, "{sql}");
        assert_eq!(written(sql, right), "b", "{sql}");
        let (operator, _, operand) = binary(left);
        assert_eq!(operator, prefix, "{sql}");
        assert_eq!(written(sql, operand), "a", "{sql}");
        formatted(sql, &my);
    }
    // Where the dialect does not reserve `BINARY` it is a name.
    let sql = "SELECT binary x FROM t";
    let select = select_of(sql, snowflake().as_ref());
    assert!(
        matches!(select_items(&select).as_slice(), [AstExpr::Ident { .. }]),
        "{:?}",
        select.projection
    );
}

#[test]
fn a_placeholder_is_read_where_an_operand_starts() {
    for dialect in every_dialect() {
        let sql = "SELECT * FROM t WHERE id = ? AND n IN (?, ?)";
        whole_where(sql, dialect.as_ref());
        assert!(
            matches!(
                where_right("SELECT * FROM t WHERE id = ?", dialect.as_ref()),
                AstExpr::Placeholder { .. }
            ),
            "{}",
            dialect.name()
        );
    }
}

#[test]
fn a_positional_bind_is_a_placeholder_where_an_operand_starts() {
    for dialect in every_dialect() {
        let name = dialect.name();
        let sql = "SELECT * FROM t WHERE id = :1 AND n IN (:2, :10)";
        whole_where(sql, dialect.as_ref());
        let bind_sql = "SELECT * FROM t WHERE id = :1";
        let bind = where_right(bind_sql, dialect.as_ref());
        assert!(
            matches!(bind, AstExpr::Placeholder { .. }),
            "{name}: {bind:?}"
        );
        assert_eq!(written(bind_sql, &bind), ":1", "{name}");
        formatted(sql, &dialect);
    }
}

/// The `IS [NOT] <predicate>` of `expr`: what it tests and whether `NOT`
/// is written.
fn is_test(expr: &AstExpr) -> (AstIsPredicate, bool) {
    match expr {
        AstExpr::IsPredicate {
            predicate,
            not_span,
            ..
        } => (*predicate, not_span.is_some()),
        other => panic!("expected an IS test, got {other:?}"),
    }
}

#[test]
fn an_is_predicate_is_read_in_every_dialect() {
    use AstIsPredicate as P;
    for dialect in every_dialect() {
        let name = dialect.name();
        for (written_test, predicate, negated) in [
            ("a IS TRUE", P::True, false),
            ("a IS NOT FALSE", P::False, true),
            ("doc IS JSON", P::JsonValue, false),
            ("doc IS NOT JSON VALUE", P::JsonValue, true),
            ("doc IS JSON ARRAY", P::JsonArray, false),
            ("doc IS JSON OBJECT", P::JsonObject, false),
            ("doc IS JSON SCALAR", P::JsonScalar, false),
            ("name IS NORMALIZED", P::NfcNormalized, false),
            ("name IS NOT NFD NORMALIZED", P::NfdNormalized, true),
            ("name IS NFKC NORMALIZED", P::NfkcNormalized, false),
            ("name IS NFKD NORMALIZED", P::NfkdNormalized, false),
        ] {
            let sql = format!("SELECT * FROM t WHERE {written_test} AND id = 1");
            let predicate_read = whole_where(&sql, dialect.as_ref());
            let (_, left, _) = binary(&predicate_read);
            assert_eq!(is_test(left), (predicate, negated), "{name}: {sql}");
            assert_eq!(written(&sql, left), written_test, "{name}: {sql}");
            formatted(&sql, &dialect);
        }
        // `IS [NOT] UNKNOWN` is the NULL test.
        let sql = "SELECT * FROM t WHERE a IS NOT UNKNOWN AND id = 1";
        let predicate_read = whole_where(sql, dialect.as_ref());
        let (_, left, _) = binary(&predicate_read);
        let (tested, negated) = null_test(left);
        assert!(negated, "{name}");
        assert_eq!(written(sql, tested), "a", "{name}");
        formatted(sql, &dialect);
    }
}
