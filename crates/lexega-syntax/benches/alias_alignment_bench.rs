// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Benchmark for AS alias alignment feature
//!
//! Compares performance with and without post-hoc alignment padding.
//! Run with: cargo bench --bench alias_alignment_bench

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use lexega_syntax::{format_script_with_config, try_parse_script_from_str, FormatterConfig};

const STRESS_TEST_SQL: &str = r#"
-- Stress test for alias alignment with complex expressions
SELECT
    -- Simple columns
    id AS identifier,
    name AS customer_name,
    
    -- CASE expressions (multi-line)
    CASE 
        WHEN status = 1 THEN 'Active'
        WHEN status = 2 THEN 'Inactive'
        WHEN status = 3 THEN 'Pending Review'
        WHEN status = 4 THEN 'Archived'
        WHEN status = 5 THEN 'Deleted'
        ELSE 'Unknown Status'
    END AS status_description,
    
    -- Nested CASE
    CASE
        WHEN region = 'US' THEN
            CASE
                WHEN state IN ('CA', 'NY', 'TX') THEN 'Major State'
                ELSE 'Other State'
            END
        WHEN region = 'EU' THEN 'European'
        ELSE 'International'
    END AS region_category,
    
    -- Subquery
    (
        SELECT COUNT(*)
        FROM orders o
        WHERE o.customer_id = c.id AND o.status = 'completed'
    ) AS order_count,
    
    -- Deeply nested subquery
    (
        SELECT MAX(amount)
        FROM (
            SELECT amount
            FROM transactions t
            WHERE t.customer_id = c.id
            ORDER BY created_at DESC
            LIMIT 10
        ) recent_txns
    ) AS max_recent_amount,
    
    -- Function calls
    COALESCE(preferred_name, first_name, 'Guest') AS display_name,
    NVL2(phone, 'Has Phone', 'No Phone') AS phone_status,
    CONCAT(first_name, ' ', last_name) AS full_name,
    
    -- Window functions
    ROW_NUMBER() OVER (
        PARTITION BY region
        ORDER BY created_at DESC
    ) AS region_rank,
    SUM(lifetime_value) OVER (
        PARTITION BY segment
        ORDER BY created_at ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW
    ) AS running_segment_total,
    
    -- Complex arithmetic
    (revenue - cost) / NULLIF(revenue, 0) * 100 AS margin_percent,
    
    -- Very long single-line expression
    DATEDIFF('day', DATE_TRUNC('month', created_at), CURRENT_DATE()) AS days_since_month_start,
    
    -- IFF/conditional
    IFF(is_premium = TRUE, 'Premium', 'Standard') AS tier,
    
    -- DECODE
    DECODE(priority, 1, 'Critical', 2, 'High', 3, 'Medium', 4, 'Low', 'Unassigned') AS priority_label,
    
    -- TRY_CAST and data type handling
    TRY_CAST(metadata:score AS FLOAT) AS parsed_score,
    
    -- Semi-structured access
    payload:user:preferences:theme::STRING AS user_theme,
    
    -- Simple literal at the end
    'constant' AS constant_value
FROM customers c
WHERE is_active = TRUE;
"#;

const SIMPLE_SQL: &str = r#"
SELECT
    id AS user_id,
    name AS user_name,
    DECODE(status, 'A', 'Active', 'I', 'Inactive', 'P', 'Pending', 'Unknown') AS status_desc,
    created_at AS signup_date
FROM users;
"#;

const MANY_COLUMNS_SQL: &str = r#"
SELECT
    col1 AS alias1,
    col2 AS alias2,
    col3 AS alias3,
    col4 AS alias4,
    col5 AS alias5,
    col6 AS alias6,
    col7 AS alias7,
    col8 AS alias8,
    col9 AS alias9,
    col10 AS alias10,
    col11 AS alias11,
    col12 AS alias12,
    col13 AS alias13,
    col14 AS alias14,
    col15 AS alias15,
    col16 AS alias16,
    col17 AS alias17,
    col18 AS alias18,
    col19 AS alias19,
    col20 AS alias20,
    CONCAT(col1, col2, col3) AS combined_value,
    CASE WHEN col1 > 0 THEN 'positive' ELSE 'non-positive' END AS sign_description
FROM large_table;
"#;

fn bench_format_with_alignment(c: &mut Criterion) {
    let mut group = c.benchmark_group("alias_alignment");

    // Pre-parse all SQL to isolate formatting time
    let stress_script = try_parse_script_from_str(STRESS_TEST_SQL).unwrap();
    let simple_script = try_parse_script_from_str(SIMPLE_SQL).unwrap();
    let many_cols_script = try_parse_script_from_str(MANY_COLUMNS_SQL).unwrap();

    // Config WITHOUT alignment
    let config_no_align = {
        let mut cfg = FormatterConfig::default();
        cfg.align_select_aliases = false;
        cfg
    };

    // Config WITH alignment (default max width)
    let config_with_align = {
        let mut cfg = FormatterConfig::default();
        cfg.align_select_aliases = true;
        cfg.alias_align_max_width = 60;
        cfg
    };

    // Config WITH alignment (high max width - more work)
    let config_with_align_wide = {
        let mut cfg = FormatterConfig::default();
        cfg.align_select_aliases = true;
        cfg.alias_align_max_width = 100;
        cfg
    };

    // Benchmark: Stress test SQL
    group.bench_with_input(
        BenchmarkId::new("stress_test", "no_alignment"),
        &(&stress_script, &config_no_align),
        |b, (script, config)| {
            b.iter(|| {
                format_script_with_config(black_box(STRESS_TEST_SQL), script, config).unwrap()
            })
        },
    );

    group.bench_with_input(
        BenchmarkId::new("stress_test", "with_alignment_60"),
        &(&stress_script, &config_with_align),
        |b, (script, config)| {
            b.iter(|| {
                format_script_with_config(black_box(STRESS_TEST_SQL), script, config).unwrap()
            })
        },
    );

    group.bench_with_input(
        BenchmarkId::new("stress_test", "with_alignment_100"),
        &(&stress_script, &config_with_align_wide),
        |b, (script, config)| {
            b.iter(|| {
                format_script_with_config(black_box(STRESS_TEST_SQL), script, config).unwrap()
            })
        },
    );

    // Benchmark: Simple SQL (4 columns)
    group.bench_with_input(
        BenchmarkId::new("simple_4col", "no_alignment"),
        &(&simple_script, &config_no_align),
        |b, (script, config)| {
            b.iter(|| format_script_with_config(black_box(SIMPLE_SQL), script, config).unwrap())
        },
    );

    group.bench_with_input(
        BenchmarkId::new("simple_4col", "with_alignment"),
        &(&simple_script, &config_with_align),
        |b, (script, config)| {
            b.iter(|| format_script_with_config(black_box(SIMPLE_SQL), script, config).unwrap())
        },
    );

    // Benchmark: Many columns (22 columns)
    group.bench_with_input(
        BenchmarkId::new("many_cols_22", "no_alignment"),
        &(&many_cols_script, &config_no_align),
        |b, (script, config)| {
            b.iter(|| {
                format_script_with_config(black_box(MANY_COLUMNS_SQL), script, config).unwrap()
            })
        },
    );

    group.bench_with_input(
        BenchmarkId::new("many_cols_22", "with_alignment"),
        &(&many_cols_script, &config_with_align),
        |b, (script, config)| {
            b.iter(|| {
                format_script_with_config(black_box(MANY_COLUMNS_SQL), script, config).unwrap()
            })
        },
    );

    group.finish();
}

criterion_group!(benches, bench_format_with_alignment);
criterion_main!(benches);
