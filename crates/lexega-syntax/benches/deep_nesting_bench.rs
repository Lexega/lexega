// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use lexega_syntax::{format_sql_with_config, FormatterConfig};
use std::fs;

/// Benchmark formatting deeply nested SQL structures to ensure
/// recursion protection doesn't significantly impact performance
/// even at the edge of acceptable nesting depths.

fn format_50_level_nested_subqueries(c: &mut Criterion) {
    let sql = fs::read_to_string("tests/fixtures/test_nesting_50.sql")
        .expect("Failed to read test_nesting_50.sql");
    let config = FormatterConfig::default();

    c.bench_function("format_50_level_nested_subqueries", |b| {
        b.iter(|| {
            let result = format_sql_with_config(black_box(&sql), black_box(&config));
            black_box(result)
        });
    });
}

fn format_40_level_ctes(c: &mut Criterion) {
    let sql = fs::read_to_string("tests/fixtures/test_cte_40deep.sql")
        .expect("Failed to read test_cte_40deep.sql");
    let config = FormatterConfig::default();

    c.bench_function("format_40_level_ctes", |b| {
        b.iter(|| {
            let result = format_sql_with_config(black_box(&sql), black_box(&config));
            black_box(result)
        });
    });
}

fn reject_305_level_pathological(c: &mut Criterion) {
    let sql =
        fs::read_to_string("tests/fixtures/test_depth.sql").expect("Failed to read test_depth.sql");
    let config = FormatterConfig::default();

    c.bench_function("reject_305_level_pathological", |b| {
        b.iter(|| {
            // This should fail fast with RecursionLimitExceeded
            let result = format_sql_with_config(black_box(&sql), black_box(&config));
            black_box(result)
        });
    });
}

criterion_group!(
    deep_nesting,
    format_50_level_nested_subqueries,
    format_40_level_ctes,
    reject_305_level_pathological
);
criterion_main!(deep_nesting);
