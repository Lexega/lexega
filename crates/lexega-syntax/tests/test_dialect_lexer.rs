// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

/// Tests for dialect-aware lexer behavior.
///
/// These tests verify that the same source text produces DIFFERENT tokens
/// depending on which dialect is active. This is the core proof that
/// dialect separation lives at the lexer level.
use lexega_syntax::dialect::{mysql, MySqlDialect, PostgresDialect, SnowflakeDialect};
use lexega_syntax::lexer::tokenize_with_dialect;
use lexega_syntax::{Dialect, IdentifierKind, LiteralKind, TokenKind};

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
                kind: IdentifierKind::Quoted
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
                kind: IdentifierKind::Quoted
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
            kind: IdentifierKind::Quoted
        }
    ));
    assert!(matches!(
        pg_kinds[1],
        TokenKind::Identifier {
            kind: IdentifierKind::Quoted
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
                kind: IdentifierKind::Quoted
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
            kind: IdentifierKind::Quoted
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
            kinds.get(0),
            Some(TokenKind::Identifier {
                kind: IdentifierKind::Quoted
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
            kind: IdentifierKind::Quoted
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
                kind: IdentifierKind::Quoted
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
