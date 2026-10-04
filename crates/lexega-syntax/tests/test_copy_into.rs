// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! UNIT TESTS: COPY INTO statement parsing with AST validation.
//!
//! Unit tests with inline SQL and AST structure validation: they verify
//! specific AST node types.

use lexega_syntax::{try_parse_stmt_from_str, AstStmt};

#[test]
fn test_copy_into_table_basic() {
    let sql = "COPY INTO my_table FROM @my_stage";
    let result = try_parse_stmt_from_str(sql);
    assert!(result.is_ok(), "Failed to parse: {:?}", result.err());

    if let Ok(stmt) = result {
        match stmt {
            AstStmt::CopyIntoTable { .. } => {
                println!("✓ Successfully parsed COPY INTO <table>");
            }
            _ => panic!("Expected CopyIntoTable, got {:?}", stmt),
        }
    }
}

#[test]
fn test_copy_into_table_with_file_format() {
    let sql =
        "COPY INTO orders FROM @my_stage/data/ FILE_FORMAT = (TYPE = CSV FIELD_DELIMITER = ',')";
    let result = try_parse_stmt_from_str(sql);
    assert!(result.is_ok(), "Failed to parse: {:?}", result.err());

    if let Ok(stmt) = result {
        match stmt {
            AstStmt::CopyIntoTable { .. } => {
                println!("✓ Successfully parsed COPY INTO <table> with FILE_FORMAT");
            }
            _ => panic!("Expected CopyIntoTable, got {:?}", stmt),
        }
    }
}

#[test]
fn test_copy_into_location_basic() {
    let sql = "COPY INTO @my_stage FROM my_table";
    let result = try_parse_stmt_from_str(sql);
    assert!(result.is_ok(), "Failed to parse: {:?}", result.err());

    if let Ok(stmt) = result {
        match stmt {
            AstStmt::CopyIntoLocation { .. } => {
                println!("✓ Successfully parsed COPY INTO <location>");
            }
            _ => panic!("Expected CopyIntoLocation, got {:?}", stmt),
        }
    }
}

#[test]
fn test_copy_into_location_from_query() {
    let sql = "COPY INTO @my_stage FROM (SELECT * FROM orders WHERE status = 'COMPLETE')";
    let result = try_parse_stmt_from_str(sql);
    assert!(result.is_ok(), "Failed to parse: {:?}", result.err());

    if let Ok(stmt) = result {
        match stmt {
            AstStmt::CopyIntoLocation { .. } => {
                println!("✓ Successfully parsed COPY INTO <location> FROM query");
            }
            _ => panic!("Expected CopyIntoLocation, got {:?}", stmt),
        }
    }
}

#[test]
fn test_copy_into_s3_location() {
    let sql = "COPY INTO 's3://mybucket/data/' FROM my_table FILE_FORMAT = (TYPE = PARQUET)";
    let result = try_parse_stmt_from_str(sql);
    assert!(result.is_ok(), "Failed to parse: {:?}", result.err());

    if let Ok(stmt) = result {
        match stmt {
            AstStmt::CopyIntoLocation { .. } => {
                println!("✓ Successfully parsed COPY INTO S3 location");
            }
            _ => panic!("Expected CopyIntoLocation, got {:?}", stmt),
        }
    }
}

#[test]
fn test_copy_into_table_from_s3() {
    let sql = "COPY INTO orders FROM 's3://mybucket/data/' CREDENTIALS = (AWS_KEY_ID='xxx' AWS_SECRET_KEY='yyy')";
    let result = try_parse_stmt_from_str(sql);
    assert!(result.is_ok(), "Failed to parse: {:?}", result.err());

    if let Ok(stmt) = result {
        match stmt {
            AstStmt::CopyIntoTable { .. } => {
                println!("✓ Successfully parsed COPY INTO <table> FROM S3");
            }
            _ => panic!("Expected CopyIntoTable, got {:?}", stmt),
        }
    }
}

#[test]
fn test_copy_into_with_partition_by() {
    let sql = "COPY INTO @stage/path/ FROM my_table PARTITION BY (region, year)";
    let result = try_parse_stmt_from_str(sql);
    assert!(result.is_ok(), "Failed to parse: {:?}", result.err());

    if let Ok(stmt) = result {
        match stmt {
            AstStmt::CopyIntoLocation { .. } => {
                println!("✓ Successfully parsed COPY INTO with PARTITION BY");
            }
            _ => panic!("Expected CopyIntoLocation, got {:?}", stmt),
        }
    }
}

#[test]
fn test_copy_into_complex_options() {
    let sql = r#"COPY INTO my_table 
        FROM @my_stage/data/
        FILES = ('file1.csv', 'file2.csv')
        PATTERN = '.*sales.*\\.csv'
        FILE_FORMAT = (TYPE = CSV SKIP_HEADER = 1 FIELD_OPTIONALLY_ENCLOSED_BY = '"')
        ON_ERROR = CONTINUE
        FORCE = TRUE"#;
    let result = try_parse_stmt_from_str(sql);
    assert!(result.is_ok(), "Failed to parse: {:?}", result.err());

    if let Ok(stmt) = result {
        match stmt {
            AstStmt::CopyIntoTable { .. } => {
                println!("✓ Successfully parsed COPY INTO with complex options");
            }
            _ => panic!("Expected CopyIntoTable, got {:?}", stmt),
        }
    }
}
