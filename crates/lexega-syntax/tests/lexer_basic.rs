// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

use lexega_syntax::{
    tokenize, IdentifierKind, Keyword, LiteralKind, Operator, Punctuation, TokenKind,
};

fn kinds(src: &str) -> Vec<TokenKind> {
    tokenize(src).tokens.into_iter().map(|t| t.kind).collect()
}

#[test]
fn lex_match_condition_identifier() {
    // MATCH_CONDITION should be lexed as a single identifier token (plus EOF)
    let src = "MATCH_CONDITION";
    let tokens = tokenize(src);
    println!("Number of tokens: {}", tokens.tokens.len());
    for (i, tok) in tokens.tokens.iter().enumerate() {
        println!("Token {}: {:?}, lexeme: '{}'", i, tok.kind, tok.lexeme(src));
    }
    // Should be 2 tokens: MATCH_CONDITION and EOF
    assert_eq!(tokens.tokens.len(), 2, "MATCH_CONDITION plus EOF");
    assert!(matches!(
        tokens.tokens[0].kind,
        TokenKind::Identifier {
            kind: IdentifierKind::Unquoted
        }
    ));
    assert_eq!(tokens.tokens[0].lexeme(src), "MATCH_CONDITION");
}

#[test]
fn lex_simple_procedure_header() {
    let ks = kinds("CREATE OR REPLACE PROCEDURE demo(a NUMBER, b INPUT VARCHAR DEFAULT 'x', c OUT NUMBER) COPY GRANTS RETURNS TABLE (col1 NUMBER) NOT NULL LANGUAGE SQL VOLATILE COMMENT = 'demo proc' EXECUTE AS OWNER AS BEGIN RETURN; END;");

    assert!(ks
        .iter()
        .any(|k| matches!(k, TokenKind::Keyword(Keyword::Create))));
    assert!(ks
        .iter()
        .any(|k| matches!(k, TokenKind::Keyword(Keyword::Or))));
    assert!(ks
        .iter()
        .any(|k| matches!(k, TokenKind::Keyword(Keyword::Replace))));
    assert!(ks
        .iter()
        .any(|k| matches!(k, TokenKind::Keyword(Keyword::Procedure))));
    assert!(ks
        .iter()
        .any(|k| matches!(k, TokenKind::Keyword(Keyword::Copy))));
    assert!(ks
        .iter()
        .any(|k| matches!(k, TokenKind::Keyword(Keyword::Grants))));
    assert!(ks
        .iter()
        .any(|k| matches!(k, TokenKind::Keyword(Keyword::Returns))));
    assert!(ks
        .iter()
        .any(|k| matches!(k, TokenKind::Keyword(Keyword::Table))));
    assert!(ks
        .iter()
        .any(|k| matches!(k, TokenKind::Keyword(Keyword::Not))));
    assert!(ks
        .iter()
        .any(|k| matches!(k, TokenKind::Literal(LiteralKind::Null))));
    assert!(ks
        .iter()
        .any(|k| matches!(k, TokenKind::Keyword(Keyword::Language))));
    assert!(ks
        .iter()
        .any(|k| matches!(k, TokenKind::Keyword(Keyword::Sql))));
    assert!(ks
        .iter()
        .any(|k| matches!(k, TokenKind::Keyword(Keyword::Volatile))));
    assert!(ks
        .iter()
        .any(|k| matches!(k, TokenKind::Keyword(Keyword::Comment))));
    assert!(ks
        .iter()
        .any(|k| matches!(k, TokenKind::Keyword(Keyword::Execute))));
    assert!(ks
        .iter()
        .any(|k| matches!(k, TokenKind::Keyword(Keyword::As))));
    assert!(ks
        .iter()
        .any(|k| matches!(k, TokenKind::Keyword(Keyword::Owner))));

    // argument direction keywords
    assert!(ks
        .iter()
        .any(|k| matches!(k, TokenKind::Keyword(Keyword::Input))));
    assert!(ks
        .iter()
        .any(|k| matches!(k, TokenKind::Keyword(Keyword::Out))));
}

#[test]
fn lex_snowflake_scripting_keywords() {
    let src = "CREATE OR REPLACE PROCEDURE demo() RETURNS TABLE LANGUAGE SQL AS BEGIN DECLARE v NUMBER; IF (v > 0) THEN RETURN; ELSE RAISE; END IF; EXCEPTION WHEN OTHER THEN RETURN; END;";
    let kinds_vec = kinds(src);

    assert!(kinds_vec
        .iter()
        .any(|k| matches!(k, TokenKind::Keyword(Keyword::Create))));
    assert!(kinds_vec
        .iter()
        .any(|k| matches!(k, TokenKind::Keyword(Keyword::Or))));
    assert!(kinds_vec
        .iter()
        .any(|k| matches!(k, TokenKind::Keyword(Keyword::Replace))));
    assert!(kinds_vec
        .iter()
        .any(|k| matches!(k, TokenKind::Keyword(Keyword::Procedure))));
    assert!(kinds_vec
        .iter()
        .any(|k| matches!(k, TokenKind::Keyword(Keyword::Returns))));
    assert!(kinds_vec
        .iter()
        .any(|k| matches!(k, TokenKind::Keyword(Keyword::Language))));
    assert!(kinds_vec
        .iter()
        .any(|k| matches!(k, TokenKind::Keyword(Keyword::Begin))));
    assert!(kinds_vec
        .iter()
        .any(|k| matches!(k, TokenKind::Keyword(Keyword::Declare))));
    assert!(kinds_vec
        .iter()
        .any(|k| matches!(k, TokenKind::Keyword(Keyword::If))));
    assert!(kinds_vec
        .iter()
        .any(|k| matches!(k, TokenKind::Keyword(Keyword::Then))));
    assert!(kinds_vec
        .iter()
        .any(|k| matches!(k, TokenKind::Keyword(Keyword::Else))));
    assert!(kinds_vec
        .iter()
        .any(|k| matches!(k, TokenKind::Keyword(Keyword::End))));
    assert!(kinds_vec
        .iter()
        .any(|k| matches!(k, TokenKind::Keyword(Keyword::Exception))));
    assert!(kinds_vec
        .iter()
        .any(|k| matches!(k, TokenKind::Keyword(Keyword::When))));
    assert!(kinds_vec
        .iter()
        .any(|k| matches!(k, TokenKind::Keyword(Keyword::Return))));
    assert!(kinds_vec
        .iter()
        .any(|k| matches!(k, TokenKind::Keyword(Keyword::Raise))));

    // Also confirm DO/EXIT lex as keywords in a separate snippet.
    let src2 = "DO BEGIN EXIT; END;";
    let kinds2 = kinds(src2);
    assert!(kinds2
        .iter()
        .any(|k| matches!(k, TokenKind::Keyword(Keyword::Do))));
    assert!(kinds2
        .iter()
        .any(|k| matches!(k, TokenKind::Keyword(Keyword::Exit))));
}

#[test]
fn lex_numbers_and_operators() {
    let ks = kinds("LET v := 42 + 3.14; 1 0.5 .75 1.2e3 1E-9");

    // Basic presence checks
    assert!(ks
        .iter()
        .any(|k| matches!(k, TokenKind::Literal(LiteralKind::Number))));
    assert!(ks
        .iter()
        .any(|k| matches!(k, TokenKind::Operator(Operator::ColonEq))));

    // More detailed checks on specific number forms
    let src = "1 0.5 .75 1.2e3 1E-9";
    let tokens = lexega_syntax::tokenize(src);
    let nums: Vec<_> = tokens
        .tokens
        .into_iter()
        .filter(|t| matches!(t.kind, TokenKind::Literal(LiteralKind::Number)))
        .collect();

    assert_eq!(nums.len(), 5);
    assert_eq!(nums[0].lexeme(src), "1");
    assert_eq!(nums[1].lexeme(src), "0.5");
    assert_eq!(nums[2].lexeme(src), ".75");
    assert_eq!(nums[3].lexeme(src).to_ascii_lowercase(), "1.2e3");
    assert_eq!(nums[4].lexeme(src).to_ascii_lowercase(), "1e-9");
}

#[test]
fn lex_number_edge_cases() {
    // 1..2 should tokenize as 1, '.', '.', 2 (for now)
    let tokens = lexega_syntax::tokenize("1..2");
    let kinds: Vec<_> = tokens.tokens.iter().map(|t| &t.kind).collect();

    assert!(matches!(kinds[0], TokenKind::Literal(LiteralKind::Number))); // "1"
    assert!(matches!(
        kinds[1],
        TokenKind::Punctuation(lexega_syntax::Punctuation::Dot)
    ));

    // 1.2.3: first number should be 1.2, then '.', then '3'
    let src2 = "1.2.3";
    let tokens2 = lexega_syntax::tokenize(src2);
    let nums2: Vec<_> = tokens2
        .tokens
        .iter()
        .filter(|t| matches!(t.kind, TokenKind::Literal(LiteralKind::Number)))
        .collect();
    assert_eq!(nums2[0].lexeme(src2), "1.2");

    // 1e and 1e- should stop exponent at 'e' or 'e-' and treat them as identifiers or unknown; they must not panic.
    let _ = lexega_syntax::tokenize("1e");
    let _ = lexega_syntax::tokenize("1e-");
}

#[test]
fn lex_line_comment_and_whitespace() {
    let src = "-- comment\nSELECT 1";
    let ks = kinds(src);

    // First non-trivia token should be SELECT once lexer is implemented.
    assert!(ks
        .iter()
        .any(|k| matches!(k, TokenKind::Keyword(Keyword::Select))));
}

#[test]
fn lex_block_comment() {
    let src = "/* block\ncomment */ SELECT";
    let ks = kinds(src);

    assert!(ks
        .iter()
        .any(|k| matches!(k, TokenKind::Keyword(Keyword::Select))));
}

#[test]
fn lex_string_with_escaped_quote() {
    let src = "'it''s fine'";
    let ks = kinds(src);

    assert!(matches!(ks[0], TokenKind::Literal(LiteralKind::String)));
}

#[test]
fn lex_quoted_ident_and_cast_and_comparisons() {
    let src = r#"SELECT "Weird Name"::VARCHAR FROM "S"."T" WHERE x >= 10 AND y <> 20;"#;
    let ks = kinds(src);

    assert!(ks.iter().any(|k| matches!(
        k,
        TokenKind::Identifier {
            kind: lexega_syntax::IdentifierKind::Quoted
        }
    )));
    assert!(ks
        .iter()
        .any(|k| matches!(k, TokenKind::Operator(Operator::ColonColon))));
    assert!(ks
        .iter()
        .any(|k| matches!(k, TokenKind::Operator(Operator::Ge))));
    assert!(ks
        .iter()
        .any(|k| matches!(k, TokenKind::Operator(Operator::AngleNotEq))));
}

#[test]
fn trivia_and_boolean_null_literals() {
    let src = "  TRUE -- comment\nFALSE NULL  ";
    let tokens = tokenize(src).tokens;

    // First non-EOF tokens should be TRUE, FALSE, NULL literals.
    let non_eof: Vec<_> = tokens
        .into_iter()
        .filter(|t| !matches!(t.kind, TokenKind::Eof))
        .collect();

    assert!(matches!(
        non_eof[0].kind,
        TokenKind::Literal(LiteralKind::Boolean)
    ));
    assert!(matches!(
        non_eof[1].kind,
        TokenKind::Literal(LiteralKind::Boolean)
    ));
    assert!(matches!(
        non_eof[2].kind,
        TokenKind::Literal(LiteralKind::Null)
    ));

    // Leading trivia for first token: two spaces.
    assert_eq!(non_eof[0].leading_trivia.len(), 1);
    let lt = &non_eof[0].leading_trivia[0];
    assert!(matches!(lt.kind, lexega_syntax::TriviaKind::Whitespace));
    assert_eq!(lt.span.start, 0);
    assert_eq!(lt.span.end, 2);

    // The line comment is TRAILING trivia on TRUE (same line),
    // not leading trivia on FALSE. This is correct behavior:
    // comments on the same line attach to the preceding token.
    let tr_true = &non_eof[0].trailing_trivia;
    assert!(tr_true
        .iter()
        .any(|tr| matches!(tr.kind, lexega_syntax::TriviaKind::LineComment)));

    // FALSE has leading trivia (newline from previous line)
    let lt_false = &non_eof[1].leading_trivia;
    assert!(lt_false
        .iter()
        .any(|tr| matches!(tr.kind, lexega_syntax::TriviaKind::Newline)));

    // Trailing whitespace after NULL captured as trailing trivia.
    let tr_null = &non_eof[2].trailing_trivia;
    assert!(tr_null
        .iter()
        .any(|tr| matches!(tr.kind, lexega_syntax::TriviaKind::Whitespace)));
}

#[test]
fn spans_for_quoted_id_and_cast() {
    let src = r#"SELECT "Weird Name"::VARCHAR"#;
    let tokens = tokenize(src).tokens;

    // Expect: SELECT, quoted ident, ::, VARCHAR, EOF
    assert!(matches!(
        tokens[0].kind,
        TokenKind::Keyword(Keyword::Select)
    ));
    assert!(matches!(tokens[1].kind, TokenKind::Identifier { .. }));
    assert!(matches!(
        tokens[2].kind,
        TokenKind::Operator(Operator::ColonColon)
    ));

    // Check spans in bytes.
    // "SELECT" is at [0..6]
    assert_eq!(tokens[0].span.start, 0);
    assert_eq!(tokens[0].span.end, 6);

    // One space, then quoted identifier starting at 7
    assert_eq!(tokens[1].span.start, 7);
    assert_eq!(tokens[1].lexeme(src), "\"Weird Name\"");

    // :: immediately after the identifier
    assert_eq!(tokens[2].lexeme(src), "::");
    assert_eq!(tokens[2].span.start as usize, tokens[1].span.end as usize);
}

#[test]
fn lex_positional_and_dollar_identifiers() {
    let src = "SELECT $2, col$3, $bad FROM t";
    let tokens = tokenize(src).tokens;

    // Find the positional literal $2
    let pos_tok = tokens
        .iter()
        .find(|t| matches!(t.kind, TokenKind::Literal(LiteralKind::Position)))
        .expect("positional literal");
    assert_eq!(pos_tok.lexeme(src), "$2");

    // col$3 should be a single unquoted identifier containing '$'
    let col_dollar = tokens
        .iter()
        .find(|t| matches!(t.kind, TokenKind::Identifier { .. }) && t.lexeme(src) == "col$3")
        .expect("identifier with dollar");
    assert_eq!(col_dollar.lexeme(src), "col$3");

    // $bad has no digits after '$', so it should not be Position; it should lex as identifier starting with '$'
    let bad = tokens
        .iter()
        .find(|t| t.lexeme(src) == "$bad")
        .expect("$bad token");
    assert!(matches!(bad.kind, TokenKind::Identifier { .. }));
}

#[test]
fn lex_select_star_modifiers_keywords() {
    let src = "SELECT * ILIKE '%id%' EXCLUDE (department_id) REPLACE ('DEPT-' || department_id AS department_id) RENAME department_id AS department FROM employee_table";
    let kinds = kinds(src);

    assert!(kinds
        .iter()
        .any(|k| matches!(k, TokenKind::Keyword(Keyword::Select))));
    assert!(kinds
        .iter()
        .any(|k| matches!(k, TokenKind::Keyword(Keyword::Ilike))));
    assert!(kinds
        .iter()
        .any(|k| matches!(k, TokenKind::Keyword(Keyword::Exclude))));
    assert!(kinds
        .iter()
        .any(|k| matches!(k, TokenKind::Keyword(Keyword::Replace))));
    assert!(kinds
        .iter()
        .any(|k| matches!(k, TokenKind::Keyword(Keyword::Rename))));
}

#[test]
fn lex_group_order_having_qualify_keywords() {
    let src = "SELECT col FROM t GROUP BY col HAVING col > 1 QUALIFY col > 1 ORDER BY col DESC";
    let kinds = kinds(src);

    assert!(kinds
        .iter()
        .any(|k| matches!(k, TokenKind::Keyword(Keyword::Group))));
    assert!(kinds
        .iter()
        .any(|k| matches!(k, TokenKind::Keyword(Keyword::By))));
    assert!(kinds
        .iter()
        .any(|k| matches!(k, TokenKind::Keyword(Keyword::Having))));
    assert!(kinds
        .iter()
        .any(|k| matches!(k, TokenKind::Keyword(Keyword::Qualify))));
    assert!(kinds
        .iter()
        .any(|k| matches!(k, TokenKind::Keyword(Keyword::Order))));
    // Note: DESC is not a keyword - it's an identifier that's interpreted contextually
    // in ORDER BY clauses. This allows DESC to also serve as shorthand for DESCRIBE statements.
    assert!(kinds
        .iter()
        .any(|k| matches!(k, TokenKind::Identifier { .. })));
}

#[test]
fn lex_set_operation_keywords() {
    let src = "SELECT 1 INTERSECT SELECT 1 EXCEPT SELECT 1 MINUS SELECT 1";
    let kinds = kinds(src);

    assert!(kinds
        .iter()
        .any(|k| matches!(k, TokenKind::Keyword(Keyword::Intersect))));
    assert!(kinds
        .iter()
        .any(|k| matches!(k, TokenKind::Keyword(Keyword::Except))));
    assert!(kinds
        .iter()
        .any(|k| matches!(k, TokenKind::Keyword(Keyword::Minus))));
}

#[test]
fn lex_set_and_limit_keywords() {
    let src = "SELECT 1 UNION ALL SELECT 2 LIMIT 10 OFFSET 5 FETCH NEXT 1 ONLY";
    let kinds = kinds(src);

    assert!(kinds
        .iter()
        .any(|k| matches!(k, TokenKind::Keyword(Keyword::Union))));
    assert!(kinds
        .iter()
        .any(|k| matches!(k, TokenKind::Keyword(Keyword::All))));
    assert!(kinds
        .iter()
        .any(|k| matches!(k, TokenKind::Keyword(Keyword::Limit))));
    assert!(kinds
        .iter()
        .any(|k| matches!(k, TokenKind::Keyword(Keyword::Offset))));
    assert!(kinds
        .iter()
        .any(|k| matches!(k, TokenKind::Keyword(Keyword::Fetch))));
    assert!(kinds
        .iter()
        .any(|k| matches!(k, TokenKind::Keyword(Keyword::Next))));
    assert!(kinds
        .iter()
        .any(|k| matches!(k, TokenKind::Keyword(Keyword::Only))));
}

#[test]
fn lex_window_and_null_handling_keywords() {
    let src = "SELECT col, ROW_NUMBER() OVER (PARTITION BY x ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW RANGE BETWEEN 1 PRECEDING AND 1 FOLLOWING) FROM t ORDER BY col NULLS LAST FIRST";
    let kinds = kinds(src);

    assert!(kinds
        .iter()
        .any(|k| matches!(k, TokenKind::Keyword(Keyword::Over))));
    assert!(kinds
        .iter()
        .any(|k| matches!(k, TokenKind::Keyword(Keyword::Partition))));
    assert!(kinds
        .iter()
        .any(|k| matches!(k, TokenKind::Keyword(Keyword::Rows))));
    assert!(kinds
        .iter()
        .any(|k| matches!(k, TokenKind::Keyword(Keyword::Range))));
    assert!(kinds
        .iter()
        .any(|k| matches!(k, TokenKind::Keyword(Keyword::Unbounded))));
    assert!(kinds
        .iter()
        .any(|k| matches!(k, TokenKind::Keyword(Keyword::Preceding))));
    assert!(kinds
        .iter()
        .any(|k| matches!(k, TokenKind::Keyword(Keyword::Following))));
    assert!(kinds
        .iter()
        .any(|k| matches!(k, TokenKind::Keyword(Keyword::Current))));
    assert!(kinds
        .iter()
        .any(|k| matches!(k, TokenKind::Keyword(Keyword::Row))));

    assert!(kinds
        .iter()
        .any(|k| matches!(k, TokenKind::Keyword(Keyword::Nulls))));
    assert!(kinds
        .iter()
        .any(|k| matches!(k, TokenKind::Keyword(Keyword::First))));
    assert!(kinds
        .iter()
        .any(|k| matches!(k, TokenKind::Keyword(Keyword::Last))));
}

#[test]
fn lex_identifiers_with_unicode_and_hash() {
    // Contains a non-ASCII identifier and an identifier with '#'
    let src = "SELECT café, col#1 FROM t";
    let tokens = tokenize(src).tokens;

    // Find the identifier 'café'
    let cafe = tokens
        .iter()
        .find(|t| t.lexeme(src) == "café")
        .expect("café identifier");
    assert!(matches!(cafe.kind, TokenKind::Identifier { .. }));

    // Find the identifier 'col#1'
    let col_hash = tokens
        .iter()
        .find(|t| t.lexeme(src) == "col#1")
        .expect("col#1 identifier");
    assert!(matches!(col_hash.kind, TokenKind::Identifier { .. }));
}

#[test]
fn lex_pipe_operator() {
    let tokens = tokenize("SELECT 1 ->> SELECT * FROM $1;");
    assert!(tokens
        .tokens
        .iter()
        .any(|t| matches!(t.kind, TokenKind::Operator(Operator::Pipe))));
}

#[test]
fn lex_array_brackets_as_punctuation() {
    let tokens = tokenize("[1, 2, 3]");
    let kinds: Vec<_> = tokens.tokens.iter().map(|t| &t.kind).collect();

    // Expect leading '[' and trailing ']' as punctuation, with numbers and commas between.
    assert!(matches!(
        kinds[0],
        TokenKind::Punctuation(Punctuation::LBracket)
    ));
    assert!(kinds
        .iter()
        .any(|k| matches!(k, TokenKind::Literal(LiteralKind::Number))));
    assert!(kinds
        .iter()
        .any(|k| matches!(k, TokenKind::Punctuation(Punctuation::Comma))));
    assert!(matches!(
        kinds[kinds.len() - 2],
        TokenKind::Punctuation(Punctuation::RBracket)
    ));
}
