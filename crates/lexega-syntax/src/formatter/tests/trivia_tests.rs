// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Tests for CST-based trivia preservation in the formatter

#[cfg(test)]
mod tests {
    use crate::format_sql;

    /// Test that leading comments before SELECT are preserved
    #[test]
    fn test_leading_comment_before_select() {
        let input = "-- This is a comment\nSELECT a FROM t";
        let result = format_sql(input).expect("formatting should succeed");

        // The comment should appear in the output
        assert!(
            result.contains("-- This is a comment"),
            "Leading comment should be preserved. Got: {}",
            result
        );
    }

    /// Test that inline comments after columns are preserved
    #[test]
    fn test_inline_comment_after_column() {
        let input = "SELECT a, -- first column\n       b FROM t";
        let result = format_sql(input).expect("formatting should succeed");

        // The inline comment should appear in the output
        assert!(
            result.contains("-- first column"),
            "Inline comment should be preserved. Got: {}",
            result
        );
    }

    /// Test that block comments are preserved
    #[test]
    fn test_block_comment_preserved() {
        let input = "SELECT /* important */ a FROM t";
        let result = format_sql(input).expect("formatting should succeed");

        // The block comment should appear in the output
        assert!(
            result.contains("/* important */"),
            "Block comment should be preserved. Got: {}",
            result
        );
    }

    /// Test that comments between clauses are preserved
    #[test]
    fn test_comment_between_clauses() {
        let input = "SELECT a\n-- Filter condition\nFROM t WHERE x = 1";
        let result = format_sql(input).expect("formatting should succeed");

        // The comment should appear in the output
        assert!(
            result.contains("-- Filter condition"),
            "Comment between clauses should be preserved. Got: {}",
            result
        );
    }

    /// Test that comments before WHERE are preserved
    #[test]
    fn test_comment_before_where() {
        let input = "SELECT a FROM t\n-- Filter by status\nWHERE status = 'active'";
        let result = format_sql(input).expect("formatting should succeed");

        assert!(
            result.contains("-- Filter by status"),
            "Comment before WHERE should be preserved. Got: {}",
            result
        );
    }

    /// Test that comments before GROUP BY are preserved
    #[test]
    fn test_comment_before_group_by() {
        let input = "SELECT a, COUNT(*) FROM t WHERE x = 1\n-- Aggregate by category\nGROUP BY a";
        let result = format_sql(input).expect("formatting should succeed");

        assert!(
            result.contains("-- Aggregate by category"),
            "Comment before GROUP BY should be preserved. Got: {}",
            result
        );
    }

    /// Test that comments before ORDER BY are preserved
    #[test]
    fn test_comment_before_order_by() {
        let input = "SELECT a FROM t\n-- Sort by name\nORDER BY a";
        let result = format_sql(input).expect("formatting should succeed");

        assert!(
            result.contains("-- Sort by name"),
            "Comment before ORDER BY should be preserved. Got: {}",
            result
        );
    }

    /// Test that comments before LIMIT are preserved
    #[test]
    fn test_comment_before_limit() {
        let input = "SELECT a FROM t ORDER BY a\n-- Only first 10\nLIMIT 10";
        let result = format_sql(input).expect("formatting should succeed");

        assert!(
            result.contains("-- Only first 10"),
            "Comment before LIMIT should be preserved. Got: {}",
            result
        );
    }

    /// Test that comments in WITH clause are preserved
    #[test]
    fn test_comment_in_with_clause() {
        let input = "-- CTE definitions\nWITH cte AS (SELECT 1) SELECT * FROM cte";
        let result = format_sql(input).expect("formatting should succeed");

        assert!(
            result.contains("-- CTE definitions"),
            "Comment before WITH should be preserved. Got: {}",
            result
        );
    }

    /// Test that comments before JOIN are preserved
    #[test]
    fn test_comment_before_join() {
        let input = "SELECT * FROM t1\n-- Join customer data\nJOIN t2 ON t1.id = t2.id";
        let result = format_sql(input).expect("formatting should succeed");

        assert!(
            result.contains("-- Join customer data"),
            "Comment before JOIN should be preserved. Got: {}",
            result
        );
    }

    /// Test that comments in CASE expression are preserved
    #[test]
    fn test_comment_in_case() {
        let input = "SELECT\n-- Categorize status\nCASE WHEN x = 1 THEN 'a' ELSE 'b' END FROM t";
        let result = format_sql(input).expect("formatting should succeed");

        assert!(
            result.contains("-- Categorize status"),
            "Comment before CASE should be preserved. Got: {}",
            result
        );
    }

    /// Test that comments in window function PARTITION BY are preserved
    #[test]
    fn test_comment_in_window_partition_by() {
        let input = "SELECT ROW_NUMBER() OVER (\n-- Partition by region\nPARTITION BY region ORDER BY id) FROM t";
        let result = format_sql(input).expect("formatting should succeed");

        assert!(
            result.contains("-- Partition by region"),
            "Comment before PARTITION BY should be preserved. Got: {}",
            result
        );
    }

    /// Test that comments in window function ORDER BY are preserved
    #[test]
    fn test_comment_in_window_order_by() {
        let input = "SELECT ROW_NUMBER() OVER (PARTITION BY region\n-- Order by creation date\nORDER BY created_at) FROM t";
        let result = format_sql(input).expect("formatting should succeed");

        assert!(
            result.contains("-- Order by creation date"),
            "Comment before ORDER BY in window should be preserved. Got: {}",
            result
        );
    }

    /// Test that comments before various SQL keywords are preserved (broader coverage)
    #[test]
    fn test_comments_before_various_keywords() {
        // Test DISTINCT
        let input = "SELECT\n-- Use distinct\nDISTINCT a FROM t";
        let result = format_sql(input).expect("formatting should succeed");
        assert!(
            result.contains("-- Use distinct"),
            "Comment before DISTINCT should be preserved. Got: {}",
            result
        );

        // Test INNER JOIN
        let input2 = "SELECT * FROM t1\n-- Inner join\nINNER JOIN t2 ON t1.id = t2.id";
        let result2 = format_sql(input2).expect("formatting should succeed");
        assert!(
            result2.contains("-- Inner join"),
            "Comment before INNER JOIN should be preserved. Got: {}",
            result2
        );

        // Test LEFT JOIN
        let input3 =
            "SELECT * FROM t1\n-- Left join for optional data\nLEFT JOIN t2 ON t1.id = t2.id";
        let result3 = format_sql(input3).expect("formatting should succeed");
        assert!(
            result3.contains("-- Left join for optional data"),
            "Comment before LEFT JOIN should be preserved. Got: {}",
            result3
        );
    }
}
