// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Tests for MATCH_RECOGNIZE pattern matching

use lexega_syntax::{ast, parse_stmt_from_str};

/// Helper function to parse and extract SELECT statement
fn parse_select(sql: &str) -> ast::AstSelect {
    match parse_stmt_from_str(sql) {
        Some(ast::AstStmt::Select(select)) => select.as_ref().clone(),
        _ => panic!("Failed to parse as SELECT: {}", sql),
    }
}

#[test]
fn test_match_recognize_basic() {
    let input = r#"
        SELECT * FROM stock_price
        MATCH_RECOGNIZE (
            ORDER BY price_date
            PATTERN (UP+)
            DEFINE UP AS price > LAG(price)
        )
    "#;
    let sel = parse_select(input);

    assert_eq!(sel.from.len(), 1);
    let table_ref = &sel.from[0];
    assert!(table_ref.match_recognize.is_some());

    let mr = table_ref.match_recognize.as_ref().unwrap();
    assert!(mr.partition_by.is_none());
    assert!(mr.order_by.is_some());
    assert!(mr.measures.is_empty());
    assert_eq!(mr.define.len(), 1);
    assert_eq!(mr.define[0].symbol, "UP");
}

#[test]
fn test_match_recognize_with_partition_by() {
    let input = r#"
        SELECT * FROM stock_price
        MATCH_RECOGNIZE (
            PARTITION BY company
            ORDER BY price_date
            PATTERN (UP+)
            DEFINE UP AS price > LAG(price)
        )
    "#;
    let sel = parse_select(input);

    let mr = sel.from[0].match_recognize.as_ref().unwrap();
    assert!(mr.partition_by.is_some());
    assert_eq!(mr.partition_by.as_ref().unwrap().len(), 1);
}

#[test]
fn test_match_recognize_with_multiple_partitions() {
    let input = r#"
        SELECT * FROM stock_price
        MATCH_RECOGNIZE (
            PARTITION BY company, region
            ORDER BY price_date
            PATTERN (UP+)
            DEFINE UP AS price > LAG(price)
        )
    "#;
    let sel = parse_select(input);

    let mr = sel.from[0].match_recognize.as_ref().unwrap();
    assert!(mr.partition_by.is_some());
    assert_eq!(mr.partition_by.as_ref().unwrap().len(), 2);
}

#[test]
fn test_match_recognize_with_measures() {
    let input = r#"
        SELECT * FROM stock_price
        MATCH_RECOGNIZE (
            ORDER BY price_date
            MEASURES 
                MATCH_NUMBER() AS match_num,
                FIRST(price) AS start_price,
                LAST(price) AS end_price
            PATTERN (UP+)
            DEFINE UP AS price > LAG(price)
        )
    "#;
    let sel = parse_select(input);

    let mr = sel.from[0].match_recognize.as_ref().unwrap();
    assert_eq!(mr.measures.len(), 3);
    assert_eq!(
        mr.measures[0].alias.span.start < mr.measures[0].alias.span.end,
        true
    );
}

#[test]
fn test_match_recognize_one_row_per_match() {
    let input = r#"
        SELECT * FROM stock_price
        MATCH_RECOGNIZE (
            ORDER BY price_date
            ONE ROW PER MATCH
            PATTERN (UP+)
            DEFINE UP AS price > LAG(price)
        )
    "#;
    let sel = parse_select(input);

    let mr = sel.from[0].match_recognize.as_ref().unwrap();
    assert!(mr.rows_per_match.is_some());
    match mr.rows_per_match {
        Some(ast::AstRowsPerMatch::OneRowPerMatch) => { /* Success */ }
        _ => panic!("Expected OneRowPerMatch"),
    }
}

#[test]
fn test_match_recognize_all_rows_per_match() {
    let input = r#"
        SELECT * FROM stock_price
        MATCH_RECOGNIZE (
            ORDER BY price_date
            ALL ROWS PER MATCH
            PATTERN (UP+)
            DEFINE UP AS price > LAG(price)
        )
    "#;
    let sel = parse_select(input);

    let mr = sel.from[0].match_recognize.as_ref().unwrap();
    assert!(mr.rows_per_match.is_some());
    match mr.rows_per_match {
        Some(ast::AstRowsPerMatch::AllRowsPerMatch { .. }) => { /* Success */ }
        _ => panic!("Expected AllRowsPerMatch"),
    }
}

#[test]
fn test_match_recognize_omit_empty_matches() {
    let input = r#"
        SELECT * FROM stock_price
        MATCH_RECOGNIZE (
            ORDER BY price_date
            ALL ROWS PER MATCH OMIT EMPTY MATCHES
            PATTERN (UP*)
            DEFINE UP AS price > LAG(price)
        )
    "#;
    let sel = parse_select(input);

    let mr = sel.from[0].match_recognize.as_ref().unwrap();
    match &mr.rows_per_match {
        Some(ast::AstRowsPerMatch::AllRowsPerMatch { empty_matches }) => {
            assert!(matches!(
                empty_matches,
                Some(ast::AstEmptyMatchesMode::Omit)
            ));
        }
        _ => panic!("Expected AllRowsPerMatch with Omit"),
    }
}

#[test]
fn test_match_recognize_with_unmatched_rows() {
    let input = r#"
        SELECT * FROM stock_price
        MATCH_RECOGNIZE (
            ORDER BY price_date
            ALL ROWS PER MATCH WITH UNMATCHED ROWS
            PATTERN (UP+)
            DEFINE UP AS price > LAG(price)
        )
    "#;
    let sel = parse_select(input);

    let mr = sel.from[0].match_recognize.as_ref().unwrap();
    match &mr.rows_per_match {
        Some(ast::AstRowsPerMatch::AllRowsPerMatch { empty_matches }) => {
            assert!(matches!(
                empty_matches,
                Some(ast::AstEmptyMatchesMode::WithUnmatched)
            ));
        }
        _ => panic!("Expected AllRowsPerMatch with WithUnmatched"),
    }
}

#[test]
fn test_match_recognize_after_match_skip_past_last_row() {
    let input = r#"
        SELECT * FROM stock_price
        MATCH_RECOGNIZE (
            ORDER BY price_date
            AFTER MATCH SKIP PAST LAST ROW
            PATTERN (UP+)
            DEFINE UP AS price > LAG(price)
        )
    "#;
    let sel = parse_select(input);

    let mr = sel.from[0].match_recognize.as_ref().unwrap();
    assert!(mr.after_match_skip.is_some());
    assert!(matches!(
        mr.after_match_skip,
        Some(ast::AstAfterMatchSkip::PastLastRow)
    ));
}

#[test]
fn test_match_recognize_after_match_skip_to_next_row() {
    let input = r#"
        SELECT * FROM stock_price
        MATCH_RECOGNIZE (
            ORDER BY price_date
            AFTER MATCH SKIP TO NEXT ROW
            PATTERN (UP+)
            DEFINE UP AS price > LAG(price)
        )
    "#;
    let sel = parse_select(input);

    let mr = sel.from[0].match_recognize.as_ref().unwrap();
    assert!(matches!(
        mr.after_match_skip,
        Some(ast::AstAfterMatchSkip::ToNextRow)
    ));
}

#[test]
fn test_match_recognize_after_match_skip_to_first_symbol() {
    let input = r#"
        SELECT * FROM stock_price
        MATCH_RECOGNIZE (
            ORDER BY price_date
            AFTER MATCH SKIP TO FIRST UP
            PATTERN (UP+)
            DEFINE UP AS price > LAG(price)
        )
    "#;
    let sel = parse_select(input);

    let mr = sel.from[0].match_recognize.as_ref().unwrap();
    match &mr.after_match_skip {
        Some(ast::AstAfterMatchSkip::ToFirstSymbol(sym)) => {
            assert_eq!(sym, "UP");
        }
        _ => panic!("Expected ToFirstSymbol"),
    }
}

#[test]
fn test_match_recognize_after_match_skip_to_last_symbol() {
    let input = r#"
        SELECT * FROM stock_price
        MATCH_RECOGNIZE (
            ORDER BY price_date
            AFTER MATCH SKIP TO LAST UP
            PATTERN (UP+)
            DEFINE UP AS price > LAG(price)
        )
    "#;
    let sel = parse_select(input);

    let mr = sel.from[0].match_recognize.as_ref().unwrap();
    match &mr.after_match_skip {
        Some(ast::AstAfterMatchSkip::ToLastSymbol(sym)) => {
            assert_eq!(sym, "UP");
        }
        _ => panic!("Expected ToLastSymbol"),
    }
}

#[test]
fn test_match_recognize_pattern_storage() {
    let input = r#"
        SELECT * FROM stock_price
        MATCH_RECOGNIZE (
            ORDER BY price_date
            PATTERN (DOWN+ UP+)
            DEFINE 
                DOWN AS price < LAG(price),
                UP AS price > LAG(price)
        )
    "#;
    let sel = parse_select(input);

    let mr = sel.from[0].match_recognize.as_ref().unwrap();
    assert!(mr.pattern.pattern_text.contains("DOWN"));
    assert!(mr.pattern.pattern_text.contains("UP"));
}

#[test]
fn test_match_recognize_multiple_defines() {
    let input = r#"
        SELECT * FROM stock_price
        MATCH_RECOGNIZE (
            ORDER BY price_date
            PATTERN (DOWN+ UP+)
            DEFINE 
                DOWN AS price < LAG(price),
                UP AS price > LAG(price)
        )
    "#;
    let sel = parse_select(input);

    let mr = sel.from[0].match_recognize.as_ref().unwrap();
    assert_eq!(mr.define.len(), 2);
    assert_eq!(mr.define[0].symbol, "DOWN");
    assert_eq!(mr.define[1].symbol, "UP");
}

#[test]
fn test_match_recognize_v_shape_pattern() {
    let input = r#"
        SELECT * FROM stock_price_history
        MATCH_RECOGNIZE(
            PARTITION BY company
            ORDER BY price_date
            MEASURES
                MATCH_NUMBER() AS match_number,
                FIRST(price_date) AS start_date,
                LAST(price_date) AS end_date
            ONE ROW PER MATCH
            AFTER MATCH SKIP TO LAST row_with_price_increase
            PATTERN(row_before_decrease row_with_price_decrease+ row_with_price_increase+)
            DEFINE
                row_with_price_decrease AS price < LAG(price),
                row_with_price_increase AS price > LAG(price)
        )
    "#;
    let sel = parse_select(input);

    let mr = sel.from[0].match_recognize.as_ref().unwrap();
    assert!(mr.partition_by.is_some());
    assert!(mr.order_by.is_some());
    assert_eq!(mr.measures.len(), 3);
    assert!(matches!(
        mr.rows_per_match,
        Some(ast::AstRowsPerMatch::OneRowPerMatch)
    ));
    assert_eq!(mr.define.len(), 2);
}

#[test]
fn test_match_recognize_with_subquery() {
    let input = r#"
        SELECT * FROM (
            SELECT * FROM stock_price WHERE price > 0
        )
        MATCH_RECOGNIZE (
            ORDER BY price_date
            PATTERN (UP+)
            DEFINE UP AS price > LAG(price)
        )
    "#;
    let sel = parse_select(input);

    assert_eq!(sel.from.len(), 1);
    let table_ref = &sel.from[0];
    assert!(table_ref.subquery.is_some());
    assert!(table_ref.match_recognize.is_some());
}

#[test]
fn test_match_recognize_with_table_alias() {
    let input = r#"
        SELECT * FROM stock_price
        MATCH_RECOGNIZE (
            ORDER BY price_date
            PATTERN (UP+)
            DEFINE UP AS price > LAG(price)
        ) AS mr_result
    "#;
    let sel = parse_select(input);

    let table_ref = &sel.from[0];
    assert!(table_ref.match_recognize.is_some());
    assert!(table_ref.result_alias.is_some());
}

#[test]
fn test_match_recognize_complex_pattern() {
    let input = r#"
        SELECT * FROM data
        MATCH_RECOGNIZE (
            PARTITION BY id
            ORDER BY timestamp
            MEASURES
                CLASSIFIER() AS symbol_name,
                MATCH_SEQUENCE_NUMBER() AS seq_num
            ALL ROWS PER MATCH
            PATTERN (A+ B{2,5} C*)
            DEFINE
                A AS value > 10,
                B AS value BETWEEN 5 AND 10,
                C AS value < 5
        )
    "#;
    let sel = parse_select(input);

    let mr = sel.from[0].match_recognize.as_ref().unwrap();
    assert!(mr.partition_by.is_some());
    assert_eq!(mr.measures.len(), 2);
    assert!(matches!(
        mr.rows_per_match,
        Some(ast::AstRowsPerMatch::AllRowsPerMatch { .. })
    ));
    assert_eq!(mr.define.len(), 3);
    assert!(mr.pattern.pattern_text.contains("A"));
    assert!(mr.pattern.pattern_text.contains("B"));
    assert!(mr.pattern.pattern_text.contains("C"));
}
