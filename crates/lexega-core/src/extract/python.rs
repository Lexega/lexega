// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! AST-based SQL extraction from Python source files.
//!
//! Uses ruff_python_parser (the Ruff Python parser) to parse Python source
//! into a full AST, then walks the tree to find SQL execution calls like
//! `spark.sql("...")`, `cursor.execute("...")`, etc.
//!
//! This is deterministic — no regex heuristics. The Python AST tells us
//! exactly which string literals are arguments to which function calls.

use std::path::Path;

use ruff_python_ast::{self as ast, Expr, FStringPart, InterpolatedStringElement, Stmt};
use ruff_python_parser::parse_module;

#[cfg(test)]
use super::SqlEmbedding;
use super::{ExtractedSql, OffsetMap, SqlCallPattern};

/// Extract SQL fragments from a Python source file using full AST parsing.
///
/// Walks the Python AST looking for method calls matching the given patterns
/// (e.g., `spark.sql("...")`, `cursor.execute("...")`), and extracts the SQL
/// string argument from each call.
///
/// Also performs simple constant propagation: if a string literal is assigned
/// to a variable and that variable is passed to a SQL call, the string is
/// extracted.
#[must_use]
pub fn extract_sql(
    source: &str,
    file_path: &Path,
    patterns: &[SqlCallPattern],
) -> Vec<ExtractedSql> {
    let parsed = match parse_module(source) {
        Ok(parsed) => parsed,
        Err(_) => return Vec::new(), // Invalid Python — nothing to extract
    };

    let module = parsed.into_syntax();

    // Where each line of the source starts, to place what is found.
    let line_index = SourceLines {
        source,
        lines: crate::analyzer::LineIndex::new(source),
    };

    // String constant assignments, for simple propagation.
    // e.g., `query = "SELECT * FROM table"` → { "query": "SELECT * FROM table" }
    let string_vars = collect_string_assignments(&module.body);

    // The SQL execution calls, found by walking the AST.
    let mut results = Vec::new();
    visit_stmts(
        &module.body,
        file_path,
        source,
        patterns,
        &string_vars,
        &line_index,
        &mut results,
    );
    results
}

/// The source being read, and where each of its lines starts.
struct SourceLines<'a> {
    source: &'a str,
    lines: crate::analyzer::LineIndex,
}

/// Simple constant propagation: collect `name = "string"` assignments.
fn collect_string_assignments(body: &[Stmt]) -> Vec<StringAssignment> {
    let mut vars = Vec::new();
    collect_string_assignments_recursive(body, &mut vars);
    vars
}

fn collect_string_assignments_recursive(body: &[Stmt], vars: &mut Vec<StringAssignment>) {
    for stmt in body {
        match stmt {
            Stmt::Assign(assign) => {
                // query = "SELECT ..."
                if assign.targets.len() == 1 {
                    if let Expr::Name(name) = &assign.targets[0] {
                        if let (Some(sql), Some(text_at)) = (
                            extract_string_value(&assign.value),
                            content_start(&assign.value),
                        ) {
                            vars.push(StringAssignment {
                                name: name.id.to_string(),
                                value: sql,
                                assigned_at: assign.range.start().to_u32(),
                                text_at,
                            });
                        }
                    }
                }
            }
            // Recurse into function bodies, class bodies, etc.
            Stmt::FunctionDef(func) => {
                collect_string_assignments_recursive(&func.body, vars);
            }
            Stmt::ClassDef(cls) => {
                collect_string_assignments_recursive(&cls.body, vars);
            }
            Stmt::If(if_stmt) => {
                collect_string_assignments_recursive(&if_stmt.body, vars);
                for clause in &if_stmt.elif_else_clauses {
                    collect_string_assignments_recursive(&clause.body, vars);
                }
            }
            Stmt::For(for_stmt) => {
                collect_string_assignments_recursive(&for_stmt.body, vars);
            }
            Stmt::While(while_stmt) => {
                collect_string_assignments_recursive(&while_stmt.body, vars);
            }
            Stmt::With(with_stmt) => {
                collect_string_assignments_recursive(&with_stmt.body, vars);
            }
            Stmt::Try(try_stmt) => {
                collect_string_assignments_recursive(&try_stmt.body, vars);
                for handler in &try_stmt.handlers {
                    let ast::ExceptHandler::ExceptHandler(h) = handler;
                    collect_string_assignments_recursive(&h.body, vars);
                }
                collect_string_assignments_recursive(&try_stmt.finalbody, vars);
                collect_string_assignments_recursive(&try_stmt.orelse, vars);
            }
            _ => {}
        }
    }
}

/// Extract a plain string value from an expression, if it is a string literal.
/// A variable assigned a string literal: its name, the string, where the
/// assignment begins and where the string's text begins.
struct StringAssignment {
    name: String,
    value: String,
    assigned_at: u32,
    text_at: u32,
}

/// Where the text of the string literal or f-string `expr` begins in the
/// source: after the prefix and opening quotes of its first part. None for
/// an expression that is no string.
fn content_start(expr: &Expr) -> Option<u32> {
    ast::StringLike::try_from(expr)
        .ok()?
        .parts()
        .next()
        .map(|part| part.content_range().start().to_u32())
}

fn extract_string_value(expr: &Expr) -> Option<String> {
    match expr {
        Expr::StringLiteral(s) => Some(s.value.to_str().to_string()),
        _ => None,
    }
}

/// Extract SQL from an f-string, replacing interpolated parts with placeholders.
/// Returns (sql_skeleton, has_interpolation).
fn extract_fstring_skeleton(fstring: &ast::ExprFString) -> Option<(String, bool)> {
    let mut sql = String::new();
    let mut placeholder_count = 0u32;
    let mut has_interpolation = false;

    for part in fstring.value.as_slice() {
        match part {
            FStringPart::Literal(lit) => {
                sql.push_str(&lit.value);
            }
            FStringPart::FString(f) => {
                for element in f.elements.iter() {
                    match element {
                        InterpolatedStringElement::Literal(lit) => {
                            sql.push_str(&lit.value);
                        }
                        InterpolatedStringElement::Interpolation(_) => {
                            has_interpolation = true;
                            placeholder_count += 1;
                            sql.push_str(&format!("__INTERP_{}__", placeholder_count));
                        }
                    }
                }
            }
        }
    }

    if sql.trim().is_empty() {
        None
    } else {
        Some((sql, has_interpolation))
    }
}

/// Recursively visit statements to find SQL execution calls.
fn visit_stmts(
    body: &[Stmt],
    file_path: &Path,
    source: &str,
    patterns: &[SqlCallPattern],
    string_vars: &[StringAssignment],
    line_index: &SourceLines,
    results: &mut Vec<ExtractedSql>,
) {
    for stmt in body {
        visit_stmt(
            stmt,
            file_path,
            source,
            patterns,
            string_vars,
            line_index,
            results,
        );
    }
}

fn visit_stmt(
    stmt: &Stmt,
    file_path: &Path,
    source: &str,
    patterns: &[SqlCallPattern],
    string_vars: &[StringAssignment],
    line_index: &SourceLines,
    results: &mut Vec<ExtractedSql>,
) {
    // Check if this statement is an expression containing a SQL call.
    if let Stmt::Expr(expr_stmt) = stmt {
        if let Expr::Call(call) = expr_stmt.value.as_ref() {
            try_extract_sql_call(
                call,
                file_path,
                source,
                patterns,
                string_vars,
                line_index,
                results,
            );
        }
    }

    // Also look for SQL calls in assignment values:
    // result = spark.sql("...")
    if let Stmt::Assign(assign) = stmt {
        if let Expr::Call(call) = assign.value.as_ref() {
            try_extract_sql_call(
                call,
                file_path,
                source,
                patterns,
                string_vars,
                line_index,
                results,
            );
        }
    }

    // Recurse into compound statements.
    match stmt {
        Stmt::FunctionDef(func) => {
            visit_stmts(
                &func.body,
                file_path,
                source,
                patterns,
                string_vars,
                line_index,
                results,
            );
        }
        Stmt::ClassDef(cls) => {
            visit_stmts(
                &cls.body,
                file_path,
                source,
                patterns,
                string_vars,
                line_index,
                results,
            );
        }
        Stmt::If(if_stmt) => {
            visit_stmts(
                &if_stmt.body,
                file_path,
                source,
                patterns,
                string_vars,
                line_index,
                results,
            );
            for clause in &if_stmt.elif_else_clauses {
                visit_stmts(
                    &clause.body,
                    file_path,
                    source,
                    patterns,
                    string_vars,
                    line_index,
                    results,
                );
            }
        }
        Stmt::For(for_stmt) => {
            visit_stmts(
                &for_stmt.body,
                file_path,
                source,
                patterns,
                string_vars,
                line_index,
                results,
            );
            visit_stmts(
                &for_stmt.orelse,
                file_path,
                source,
                patterns,
                string_vars,
                line_index,
                results,
            );
        }
        Stmt::While(while_stmt) => {
            visit_stmts(
                &while_stmt.body,
                file_path,
                source,
                patterns,
                string_vars,
                line_index,
                results,
            );
            visit_stmts(
                &while_stmt.orelse,
                file_path,
                source,
                patterns,
                string_vars,
                line_index,
                results,
            );
        }
        Stmt::With(with_stmt) => {
            visit_stmts(
                &with_stmt.body,
                file_path,
                source,
                patterns,
                string_vars,
                line_index,
                results,
            );
        }
        Stmt::Try(try_stmt) => {
            visit_stmts(
                &try_stmt.body,
                file_path,
                source,
                patterns,
                string_vars,
                line_index,
                results,
            );
            for handler in &try_stmt.handlers {
                let ast::ExceptHandler::ExceptHandler(h) = handler;
                visit_stmts(
                    &h.body,
                    file_path,
                    source,
                    patterns,
                    string_vars,
                    line_index,
                    results,
                );
            }
            visit_stmts(
                &try_stmt.finalbody,
                file_path,
                source,
                patterns,
                string_vars,
                line_index,
                results,
            );
            visit_stmts(
                &try_stmt.orelse,
                file_path,
                source,
                patterns,
                string_vars,
                line_index,
                results,
            );
        }
        _ => {}
    }
}

/// Try to extract SQL from a function call if it matches a known SQL execution pattern.
fn try_extract_sql_call(
    call: &ast::ExprCall,
    file_path: &Path,
    _source: &str,
    patterns: &[SqlCallPattern],
    string_vars: &[StringAssignment],
    line_index: &SourceLines,
    results: &mut Vec<ExtractedSql>,
) {
    // Determine the method name from the call.
    // We handle: obj.method(...) → Attribute node with attr = method name
    let method_name = match call.func.as_ref() {
        Expr::Attribute(attr) => attr.attr.as_str(),
        _ => return,
    };

    // Find a matching pattern.
    let pattern = match patterns.iter().find(|p| p.method_name == method_name) {
        Some(p) => p,
        None => return,
    };

    // Extract the SQL argument.
    let sql_arg = get_sql_argument(call, pattern, string_vars);
    let Some((sql_text, has_interpolation, arg_offset)) = sql_arg else {
        return;
    };

    // The string's text runs on from where it begins, its lines the file's.
    results.push(ExtractedSql::placed_in(
        sql_text,
        file_path,
        (line_index.source, &line_index.lines),
        &OffsetMap::starting_at(arg_offset as usize),
        pattern.embedding,
        has_interpolation,
    ));
}

/// Get the SQL string from a call's arguments.
/// Returns (sql_text, has_interpolation, byte_offset_of_the_sql_text).
fn get_sql_argument(
    call: &ast::ExprCall,
    pattern: &SqlCallPattern,
    string_vars: &[StringAssignment],
) -> Option<(String, bool, u32)> {
    // Try positional argument first.
    if let Some(arg) = call.arguments.args.get(pattern.sql_arg_position) {
        if let Some(result) = extract_sql_from_expr(arg, string_vars) {
            return Some(result);
        }
    }

    // Try keyword argument if configured.
    if let Some(ref kwarg_name) = pattern.sql_kwarg_name {
        for kw in call.arguments.keywords.iter() {
            if let Some(ref arg_ident) = kw.arg {
                let ident_str: &str = arg_ident.as_str();
                if ident_str == kwarg_name.as_str() {
                    if let Some(result) = extract_sql_from_expr(&kw.value, string_vars) {
                        return Some(result);
                    }
                }
            }
        }
    }

    None
}

/// Extract SQL text from an expression node.
/// Returns (sql_text, has_interpolation, byte offset where the SQL text
/// begins, after any string prefix and opening quotes).
fn extract_sql_from_expr(
    expr: &Expr,
    string_vars: &[StringAssignment],
) -> Option<(String, bool, u32)> {
    use ruff_text_size::Ranged;

    match expr {
        // Direct string literal: spark.sql("SELECT ...")
        Expr::StringLiteral(s) => {
            let sql = s.value.to_str().to_string();
            if sql.trim().is_empty() {
                None
            } else {
                Some((sql, false, content_start(expr)?))
            }
        }

        // F-string: spark.sql(f"SELECT * FROM {schema}.events")
        Expr::FString(f) => {
            let (skeleton, has_interp) = extract_fstring_skeleton(f)?;
            Some((skeleton, has_interp, content_start(expr)?))
        }

        // Variable reference: spark.sql(query) where query = "SELECT ..."
        Expr::Name(name) => {
            let var_name = name.id.as_str();
            let used_at = name.range().start().to_u32();
            // The nearest assignment written before the use; with none, the
            // last one (a function reading a module name assigned below it).
            let mut assigned = string_vars.iter().filter(|var| var.name == var_name);
            let var = assigned
                .clone()
                .rfind(|var| var.assigned_at < used_at)
                .or_else(|| assigned.next_back())?;
            Some((var.value.clone(), false, var.text_at))
        }

        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn default_patterns() -> Vec<SqlCallPattern> {
        SqlCallPattern::spark_defaults()
    }

    #[test]
    fn test_spark_sql_simple() {
        let source = r#"
spark.sql("SELECT * FROM events")
"#;
        let results = extract_sql(source, &PathBuf::from("test.py"), &default_patterns());
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].sql, "SELECT * FROM events");
        assert!(!results[0].has_interpolation);
        assert_eq!(results[0].embedding, SqlEmbedding::SparkSqlCall);
    }

    #[test]
    fn test_spark_sql_triple_quoted() {
        let source = r#"
spark.sql("""
    CREATE TABLE gold.dim_customer
    AS SELECT * FROM silver.customers
""")
"#;
        let results = extract_sql(source, &PathBuf::from("test.py"), &default_patterns());
        assert_eq!(results.len(), 1);
        assert!(results[0].sql.contains("CREATE TABLE gold.dim_customer"));
        assert!(results[0].sql.contains("SELECT * FROM silver.customers"));
    }

    #[test]
    fn test_spark_sql_fstring() {
        let source = r#"
schema = "gold"
spark.sql(f"SELECT * FROM {schema}.events WHERE id = {event_id}")
"#;
        let results = extract_sql(source, &PathBuf::from("test.py"), &default_patterns());
        assert_eq!(results.len(), 1);
        assert!(results[0].has_interpolation);
        assert!(results[0].sql.contains("__INTERP_1__"));
        assert!(results[0].sql.contains("__INTERP_2__"));
        assert!(results[0].sql.contains("SELECT * FROM"));
    }

    #[test]
    fn test_spark_sql_variable() {
        let source = r#"
query = "DROP TABLE users"
spark.sql(query)
"#;
        let results = extract_sql(source, &PathBuf::from("test.py"), &default_patterns());
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].sql, "DROP TABLE users");
    }

    #[test]
    fn a_reassigned_variable_runs_the_value_written_before_each_call() {
        let source = r#"
q = "DROP TABLE a.first"
spark.sql(q)
q = "DROP TABLE b.second"
spark.sql(q)

def later():
    spark.sql(tail)

tail = "DROP TABLE c.third"
"#;
        let results = extract_sql(source, &PathBuf::from("test.py"), &default_patterns());
        let sql: Vec<&str> = results.iter().map(|r| r.sql.as_str()).collect();
        assert_eq!(
            sql,
            [
                "DROP TABLE a.first",
                "DROP TABLE b.second",
                "DROP TABLE c.third"
            ]
        );
        assert_eq!(results[0].origin.line, 2);
        assert_eq!(results[1].origin.line, 4);
    }

    #[test]
    fn spark_sql_by_its_keyword_argument() {
        let source = r#"
spark.sql(sqlQuery="SELECT * FROM events")
spark.sql(args={"x": 1}, sqlQuery=f"SELECT * FROM {schema}.events")
"#;
        let results = extract_sql(source, &PathBuf::from("test.py"), &default_patterns());
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].sql, "SELECT * FROM events");
        assert_eq!(results[0].embedding, SqlEmbedding::SparkSqlCall);
        assert!(results[1].has_interpolation);
        assert!(results[1].sql.contains(".events"));
    }

    #[test]
    fn test_cursor_execute() {
        let source = r#"
cursor.execute("GRANT SELECT ON TABLE events TO analysts")
"#;
        let results = extract_sql(source, &PathBuf::from("test.py"), &default_patterns());
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].sql, "GRANT SELECT ON TABLE events TO analysts");
        assert_eq!(results[0].embedding, SqlEmbedding::ExecuteCall);
    }

    #[test]
    fn test_multiple_calls() {
        let source = r#"
spark.sql("DROP TABLE IF EXISTS staging.raw_events")
spark.sql("CREATE TABLE staging.raw_events AS SELECT * FROM source")
result = spark.sql("SELECT count(*) FROM staging.raw_events")
"#;
        let results = extract_sql(source, &PathBuf::from("test.py"), &default_patterns());
        assert_eq!(results.len(), 3);
    }

    #[test]
    fn test_nested_in_function() {
        let source = r#"
def run_etl():
    spark.sql("DROP TABLE IF EXISTS tmp")
    spark.sql("CREATE TABLE tmp AS SELECT 1")
"#;
        let results = extract_sql(source, &PathBuf::from("test.py"), &default_patterns());
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_no_sql_calls() {
        let source = r#"
x = 1 + 2
print("hello world")
spark.read.table("events")
"#;
        let results = extract_sql(source, &PathBuf::from("test.py"), &default_patterns());
        assert_eq!(results.len(), 0);
    }

    #[test]
    fn test_empty_string_ignored() {
        let source = r#"
spark.sql("")
spark.sql("   ")
"#;
        let results = extract_sql(source, &PathBuf::from("test.py"), &default_patterns());
        assert_eq!(results.len(), 0);
    }

    #[test]
    fn test_line_numbers() {
        let source = "line1\nline2\nspark.sql(\"SELECT 1\")\nline4\n";
        let results = extract_sql(source, &PathBuf::from("test.py"), &default_patterns());
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].origin.line, 3);
    }

    // The column where a string's SQL begins counts the characters before
    // it on its line, and its UTF-16 units, not their bytes.
    #[test]
    fn the_column_where_the_sql_begins_counts_characters() {
        let source = "ñame = 1; spark.sql(\"DELETE FROM main.sales.b\")\nñ = 1; spark.sql(f\"DELETE FROM main.sales.{t}\")\nx = '😀'; spark.sql(\"DELETE FROM main.sales.c\")\n";
        let found: Vec<(usize, usize, usize)> =
            extract_sql(source, &PathBuf::from("test.py"), &default_patterns())
                .iter()
                .map(|fragment| {
                    (
                        fragment.origin.line,
                        fragment.origin.column,
                        fragment.origin.utf16_column,
                    )
                })
                .collect();
        assert_eq!(found, [(1, 22, 22), (2, 20, 20), (3, 21, 22)]);
    }

    #[test]
    fn test_implicit_string_concat() {
        let source = r#"
spark.sql(
    "SELECT * FROM events "
    "WHERE date > '2024-01-01' "
    "ORDER BY event_time"
)
"#;
        let results = extract_sql(source, &PathBuf::from("test.py"), &default_patterns());
        assert_eq!(results.len(), 1);
        assert!(results[0].sql.contains("SELECT * FROM events"));
        assert!(results[0].sql.contains("WHERE date"));
        assert!(results[0].sql.contains("ORDER BY"));
    }

    #[test]
    fn test_sql_in_try_except() {
        let source = r#"
try:
    spark.sql("DROP TABLE sensitive_data")
except Exception as e:
    spark.sql("SELECT 1")
"#;
        let results = extract_sql(source, &PathBuf::from("test.py"), &default_patterns());
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_dynamic_concat_not_extracted() {
        let source = r#"
table = "events"
spark.sql("SELECT * FROM " + table)
"#;
        let results = extract_sql(source, &PathBuf::from("test.py"), &default_patterns());
        // BinOp (string concat) is not a string literal — correctly not extracted.
        assert_eq!(results.len(), 0);
    }
}
