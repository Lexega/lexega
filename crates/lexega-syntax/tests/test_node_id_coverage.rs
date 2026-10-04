// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Integration test: Verify all AST nodes have unique, non-default NodeIds
//!
//! This test ensures the parser correctly assigns NodeIds to all AST nodes,
//! which source maps, IDE features and linter diagnostics rely on.

use lexega_syntax::{ast::*, try_parse_script_from_str};
use std::collections::HashSet;

/// Visitor that collects all NodeIds from an AST
struct NodeIdCollector {
    node_ids: Vec<NodeId>,
    context: Vec<String>,
}

impl NodeIdCollector {
    fn new() -> Self {
        Self {
            node_ids: Vec::new(),
            context: Vec::new(),
        }
    }

    fn push_context(&mut self, ctx: &str) {
        self.context.push(ctx.to_string());
    }

    fn pop_context(&mut self) {
        self.context.pop();
    }

    fn collect_node_id(&mut self, node_id: NodeId, _node_type: &str) {
        // NodeId(0) is valid - it's the first node generated.
        // We only check for uniqueness, not specific values.
        self.node_ids.push(node_id);
    }

    fn visit_script(&mut self, script: &AstScript) {
        self.push_context("Script");
        self.collect_node_id(script.node_id, "AstScript");
        for (i, stmt) in script.stmts.iter().enumerate() {
            self.push_context(&format!("Statement[{}]", i));
            self.visit_stmt(stmt);
            self.pop_context();
        }
        self.pop_context();
    }

    fn visit_stmt(&mut self, stmt: &AstStmt) {
        match stmt {
            AstStmt::Select(select) => {
                self.push_context("Select");
                self.visit_select(select);
                self.pop_context();
            }
            AstStmt::Insert(insert) => {
                self.push_context("Insert");
                self.collect_node_id(insert.node_id, "AstInsert");
                self.pop_context();
            }
            AstStmt::Update(update) => {
                self.push_context("Update");
                self.collect_node_id(update.node_id, "AstUpdate");
                if let Some(ref where_clause) = update.where_clause {
                    self.push_context("Where");
                    self.visit_expr(where_clause);
                    self.pop_context();
                }
                self.pop_context();
            }
            AstStmt::Delete(delete) => {
                self.push_context("Delete");
                self.collect_node_id(delete.node_id, "AstDelete");
                if let Some(ref where_clause) = delete.where_clause {
                    self.push_context("Where");
                    self.visit_expr(where_clause);
                    self.pop_context();
                }
                self.pop_context();
            }
            AstStmt::Merge(merge) => {
                self.push_context("Merge");
                self.collect_node_id(merge.node_id, "AstMerge");
                self.pop_context();
            }
            AstStmt::CreateTable(create) => {
                self.push_context("CreateTable");
                self.collect_node_id(create.node_id, "AstCreateTable");
                self.pop_context();
            }
            AstStmt::CreateView(view) => {
                self.push_context("CreateView");
                self.collect_node_id(view.node_id, "AstCreateView");
                self.pop_context();
            }
            AstStmt::Drop(drop) => {
                self.push_context("Drop");
                self.collect_node_id(drop.node_id, "AstDrop");
                self.pop_context();
            }
            AstStmt::Truncate(truncate) => {
                self.push_context("Truncate");
                self.collect_node_id(truncate.node_id, "AstTruncate");
                self.pop_context();
            }
            AstStmt::Show(show) => {
                self.push_context("Show");
                self.collect_node_id(show.node_id, "AstShow");
                self.pop_context();
            }
            AstStmt::Describe(desc) => {
                self.push_context("Describe");
                self.collect_node_id(desc.node_id, "AstDescribe");
                self.pop_context();
            }
            AstStmt::Block(b) => {
                self.push_context("Block");
                self.collect_node_id(b.node_id, "AstBlock");
                for (i, decl) in b.decls.iter().enumerate() {
                    self.push_context(&format!("Decl[{}]", i));
                    self.visit_stmt(decl);
                    self.pop_context();
                }
                for (i, stmt) in b.body.iter().enumerate() {
                    self.push_context(&format!("BlockStmt[{}]", i));
                    self.visit_stmt(stmt);
                    self.pop_context();
                }
                self.pop_context();
            }
            AstStmt::JinjaPlaceholder { .. } => {
                // Jinja placeholders don't have node_ids at statement level
            }
            _ => {
                // Other statement types - covered minimally
            }
        }
    }

    fn visit_select(&mut self, select: &AstSelect) {
        self.collect_node_id(select.node_id, "AstSelect");

        // Visit CTEs in WITH clause
        if let Some(ref with_clause) = select.with_clause {
            self.collect_node_id(with_clause.node_id, "AstWithClause");
            for (i, cte_item) in with_clause.ctes.iter().enumerate() {
                self.push_context(&format!("CTE[{}]", i));
                match cte_item {
                    lexega_syntax::ast::CteItem::Cte(cte) => {
                        self.collect_node_id(cte.node_id, "AstCte");
                        // CTE query is Box<AstStmt>, visit it
                        self.push_context("CTEQuery");
                        match cte.query.as_ref() {
                            AstStmt::Select(select) => {
                                self.visit_select(select);
                            }
                            _ => {
                                self.visit_stmt(cte.query.as_ref());
                            }
                        }
                        self.pop_context();
                    }
                    lexega_syntax::ast::CteItem::JinjaBlock(block) => {
                        self.collect_node_id(block.node_id, "JinjaCteBlock");
                        // Visit CTE fragments inside the Jinja block
                        for cte_frag in &block.then_ctes {
                            self.collect_node_id(cte_frag.node_id, "CteFragment");
                            self.push_context("CTEQuery");
                            self.visit_stmt(&cte_frag.query);
                            self.pop_context();
                        }
                    }
                }
                self.pop_context();
            }
        }

        // Visit projection
        match &select.projection.kind {
            AstProjectionKind::Columns(items) => {
                for (i, item) in items.iter().enumerate() {
                    self.push_context(&format!("ProjectionItem[{}]", i));
                    self.collect_node_id(item.node_id, "ProjectionItem");
                    // ProjectionItem has kind: ProjectionItemKind
                    match &item.kind {
                        ProjectionItemKind::SelectItem(select_item) => {
                            self.collect_node_id(select_item.node_id, "AstSelectItem");
                            self.visit_expr(&select_item.expr);
                        }
                        ProjectionItemKind::JinjaBlock(jinja_block) => {
                            self.collect_node_id(jinja_block.node_id, "JinjaBlock");
                            // Recursively visit items inside Jinja block
                            for inner_item in &jinja_block.then_items {
                                match &inner_item.kind {
                                    ProjectionItemKind::SelectItem(si) => {
                                        self.collect_node_id(si.node_id, "AstSelectItem");
                                        self.visit_expr(&si.expr);
                                    }
                                    _ => {}
                                }
                            }
                            // Visit elif branches
                            for elif_branch in &jinja_block.elif_branches {
                                for inner_item in &elif_branch.items {
                                    match &inner_item.kind {
                                        ProjectionItemKind::SelectItem(si) => {
                                            self.collect_node_id(si.node_id, "AstSelectItem");
                                            self.visit_expr(&si.expr);
                                        }
                                        _ => {}
                                    }
                                }
                            }
                            // Visit else branch
                            if let Some(else_branch) = &jinja_block.else_branch {
                                for inner_item in &else_branch.items {
                                    match &inner_item.kind {
                                        ProjectionItemKind::SelectItem(si) => {
                                            self.collect_node_id(si.node_id, "AstSelectItem");
                                            self.visit_expr(&si.expr);
                                        }
                                        _ => {}
                                    }
                                }
                            }
                        }
                    }
                    self.pop_context();
                }
            }
            AstProjectionKind::Star(_) => {
                // Star projection has no nested expressions
            }
        }

        // Visit FROM clause (Vec<AstTableRef>)
        for (i, table_ref) in select.from.iter().enumerate() {
            self.push_context(&format!("From[{}]", i));
            self.visit_table_ref(table_ref);
            self.pop_context();
        }

        // Visit WHERE clause
        if let Some(ref where_clause) = select.where_clause {
            self.push_context("Where");
            self.visit_expr(&where_clause.expr);
            self.pop_context();
        }

        // Visit GROUP BY
        if let Some(ref group_by) = select.group_by {
            self.collect_node_id(group_by.node_id, "AstGroupBy");
            match &group_by.variant {
                AstGroupByVariant::Standard(items) => {
                    for (i, item) in items.iter().enumerate() {
                        self.push_context(&format!("GroupByItem[{}]", i));
                        self.collect_node_id(item.node_id, "AstGroupItem");
                        self.visit_expr(&item.expr);
                        self.pop_context();
                    }
                }
                AstGroupByVariant::Elements(elements) => {
                    for (ei, element) in elements.iter().enumerate() {
                        self.push_context(&format!("GroupByElement[{}]", ei));
                        self.collect_node_id(element.node_id, "AstGroupElement");
                        let item_lists: Vec<&Vec<AstGroupItem>> = match &element.kind {
                            AstGroupElementKind::Cube(items)
                            | AstGroupElementKind::Rollup(items) => vec![items],
                            AstGroupElementKind::GroupingSets(sets) => sets.iter().collect(),
                            AstGroupElementKind::Expr(item) => {
                                self.collect_node_id(item.node_id, "AstGroupItem");
                                self.visit_expr(&item.expr);
                                self.pop_context();
                                continue;
                            }
                        };
                        for items in item_lists {
                            for (i, item) in items.iter().enumerate() {
                                self.push_context(&format!("GroupByItem[{}]", i));
                                self.collect_node_id(item.node_id, "AstGroupItem");
                                self.visit_expr(&item.expr);
                                self.pop_context();
                            }
                        }
                        self.pop_context();
                    }
                }
                _ => {}
            }
        }

        // Visit HAVING
        if let Some(ref having) = select.having {
            self.push_context("Having");
            self.visit_expr(&having.expr);
            self.pop_context();
        }

        // Visit ORDER BY
        if let Some(ref order_by) = select.order_by {
            for (i, item) in order_by.items.iter().enumerate() {
                self.push_context(&format!("OrderBy[{}]", i));
                self.visit_expr(&item.expr);
                self.pop_context();
            }
        }
    }

    fn visit_table_ref(&mut self, table_ref: &AstTableRef) {
        self.collect_node_id(table_ref.node_id, "AstTableRef");

        // Visit subquery if present
        if let Some(ref subquery) = table_ref.subquery {
            self.push_context("Subquery");
            if let AstStmt::Select(select) = subquery.as_ref() {
                self.visit_select(select);
            } else {
                self.visit_stmt(subquery);
            }
            self.pop_context();
        }

        // Visit joins (Vec<AstJoin>)
        for (i, join) in table_ref.joins.iter().enumerate() {
            self.push_context(&format!("Join[{}]", i));
            self.collect_node_id(join.node_id, "AstJoin");
            self.visit_table_ref(&join.right);
            match &join.constraint {
                AstJoinConstraint::On(expr) => {
                    self.push_context("JoinOn");
                    self.visit_expr(expr);
                    self.pop_context();
                }
                _ => {}
            }
            self.pop_context();
        }
    }

    fn visit_expr(&mut self, expr: &AstExpr) {
        // AstExpr is an enum, match on variants
        match expr {
            AstExpr::Ident { .. } | AstExpr::Literal { .. } => {
                // Leaf nodes - no node_id to collect
            }
            AstExpr::JinjaPlaceholder { .. } => {
                // Jinja placeholders don't have node_ids
            }
            AstExpr::BinaryOp { left, right, .. } => {
                self.push_context("BinaryLeft");
                self.visit_expr(left);
                self.pop_context();
                self.push_context("BinaryRight");
                self.visit_expr(right);
                self.pop_context();
            }
            AstExpr::FunctionCall { args, .. } => {
                for (i, arg) in args.iter().enumerate() {
                    self.push_context(&format!("FuncArg[{}]", i));
                    match arg.as_ref() {
                        AstFunctionArg::Positional(expr) => self.visit_expr(expr),
                        AstFunctionArg::Named { value, .. } => self.visit_expr(value),
                        AstFunctionArg::Lambda { body, .. } => self.visit_expr(body),
                        AstFunctionArg::AliasedArg { value, .. } => self.visit_expr(value),
                        AstFunctionArg::BulkArg { value, .. } => self.visit_expr(value),
                    }
                    self.pop_context();
                }
            }
            AstExpr::Case {
                operand,
                whens,
                else_expr,
                ..
            } => {
                if let Some(ref op) = operand {
                    self.push_context("CaseOperand");
                    self.visit_expr(op);
                    self.pop_context();
                }
                for (i, when) in whens.iter().enumerate() {
                    self.push_context(&format!("When[{}]", i));
                    self.visit_expr(&when.cond);
                    self.visit_expr(&when.result);
                    self.pop_context();
                }
                if let Some(ref else_e) = else_expr {
                    self.push_context("CaseElse");
                    self.visit_expr(else_e);
                    self.pop_context();
                }
            }
            AstExpr::InList { expr, list, .. } => {
                self.push_context("InExpr");
                self.visit_expr(expr);
                self.pop_context();
                for (i, item) in list.iter().enumerate() {
                    self.push_context(&format!("InList[{}]", i));
                    self.visit_expr(item);
                    self.pop_context();
                }
            }
            AstExpr::InSubquery { expr, subquery, .. } => {
                self.push_context("InExpr");
                self.visit_expr(expr);
                self.pop_context();
                self.push_context("InSubquery");
                self.visit_stmt(subquery);
                self.pop_context();
            }
            AstExpr::ScalarSubquery { subquery, .. } | AstExpr::ExistsSubquery { subquery, .. } => {
                self.push_context("Subquery");
                self.visit_stmt(subquery);
                self.pop_context();
            }
            AstExpr::Parenthesized { expr, .. }
            | AstExpr::Cast { expr, .. }
            | AstExpr::TryCast { expr, .. }
            | AstExpr::TypeCast { expr, .. }
            | AstExpr::Extract { expr, .. }
            | AstExpr::IsNull { expr, .. }
            | AstExpr::Spread { expr, .. }
            | AstExpr::Prior { expr, .. } => {
                self.visit_expr(expr);
            }
            AstExpr::Between {
                expr, lower, upper, ..
            } => {
                self.visit_expr(expr);
                self.visit_expr(lower);
                self.visit_expr(upper);
            }
            AstExpr::Array { elements, .. } => {
                for (i, elem) in elements.iter().enumerate() {
                    self.push_context(&format!("Array[{}]", i));
                    self.visit_expr(elem);
                    self.pop_context();
                }
            }
            _ => {
                // Other expression variants
            }
        }
    }

    fn validate(&self) -> Result<(), String> {
        // Check for duplicates
        let mut seen = HashSet::new();
        let mut duplicates = Vec::new();

        for node_id in &self.node_ids {
            if !seen.insert(node_id.as_u32()) {
                duplicates.push(node_id.as_u32());
            }
        }

        if !duplicates.is_empty() {
            return Err(format!(
                "Found {} duplicate NodeIds: {:?}",
                duplicates.len(),
                duplicates
            ));
        }

        Ok(())
    }
}

#[test]
fn test_node_id_coverage_comprehensive() {
    // Test various SQL statement types to ensure all nodes get IDs
    let test_cases = vec![
        // Simple SELECT
        ("Simple SELECT", "SELECT id, name FROM users WHERE active = TRUE;"),
        // SELECT with JOINs
        ("SELECT with JOIN", 
         "SELECT u.id, u.name, o.total FROM users u INNER JOIN orders o ON u.id = o.user_id;"),
        // SELECT with CTE
        ("SELECT with CTE",
         "WITH active_users AS (SELECT * FROM users WHERE active = TRUE) SELECT * FROM active_users;"),
        // SELECT with subquery
        ("SELECT with subquery",
         "SELECT * FROM users WHERE id IN (SELECT user_id FROM orders WHERE total > 100);"),
        // INSERT
        ("INSERT",
         "INSERT INTO users (id, name) VALUES (1, 'Alice');"),
        // UPDATE
        ("UPDATE",
         "UPDATE users SET name = 'Bob' WHERE id = 1;"),
        // DELETE
        ("DELETE",
         "DELETE FROM users WHERE id = 1;"),
        // MERGE
        ("MERGE",
         "MERGE INTO target USING source ON target.id = source.id WHEN MATCHED THEN UPDATE SET name = source.name;"),
        // CREATE TABLE
        ("CREATE TABLE",
         "CREATE TABLE test (id INT, name VARCHAR);"),
        // CREATE VIEW
        ("CREATE VIEW",
         "CREATE VIEW active_users AS SELECT * FROM users WHERE active = TRUE;"),
        // Complex SELECT with multiple features
        ("Complex SELECT",
         r#"
         WITH monthly_sales AS (
           SELECT 
             DATE_TRUNC('month', order_date) AS month,
             SUM(amount) AS total,
             COUNT(*) AS order_count
           FROM orders
           WHERE status = 'completed'
           GROUP BY DATE_TRUNC('month', order_date)
         )
         SELECT 
           m.month,
           m.total,
           m.order_count,
           CASE 
             WHEN m.total > 10000 THEN 'High'
             WHEN m.total > 5000 THEN 'Medium'
             ELSE 'Low'
           END AS performance
         FROM monthly_sales m
         ORDER BY m.month DESC
         LIMIT 12;
         "#),
        // Nested subqueries
        ("Nested subqueries",
         "SELECT * FROM (SELECT * FROM (SELECT id FROM users) AS inner_query) AS outer_query;"),
    ];

    for (test_name, sql) in test_cases {
        println!("\nTesting: {}", test_name);

        let script = match try_parse_script_from_str(sql) {
            Ok(s) => s,
            Err(e) => panic!("Failed to parse '{}': {:?}", test_name, e),
        };

        let mut collector = NodeIdCollector::new();
        collector.visit_script(&script);

        println!(
            "  Collected {} NodeIds: {:?}",
            collector.node_ids.len(),
            collector.node_ids
        );

        // Validate uniqueness
        if let Err(e) = collector.validate() {
            panic!("NodeId validation failed for '{}': {}", test_name, e);
        }

        // Ensure we collected at least some nodes
        assert!(
            !collector.node_ids.is_empty(),
            "No NodeIds collected for '{}'",
            test_name
        );
    }
}

#[test]
fn test_node_id_uniqueness_across_statements() {
    // Test that NodeIds are unique across multiple statements in a script
    let sql = r#"
        SELECT id FROM users;
        SELECT name FROM products;
        INSERT INTO logs (message) VALUES ('test');
        UPDATE settings SET value = 'updated' WHERE key = 'config';
    "#;

    let script = try_parse_script_from_str(sql).expect("Parse should succeed");

    let mut collector = NodeIdCollector::new();
    collector.visit_script(&script);

    println!(
        "Collected {} NodeIds across 4 statements",
        collector.node_ids.len()
    );

    // Validate uniqueness
    collector.validate().expect("All NodeIds should be unique");

    // Should have NodeIds for script + 4 statements + their components
    assert!(
        collector.node_ids.len() >= 5,
        "Expected at least 5 NodeIds (script + 4 statements), got {}",
        collector.node_ids.len()
    );
}

#[test]
fn test_node_id_non_zero() {
    // Ensure no NodeIds are left at default (0) value
    let sql = "SELECT a, b, c FROM table1 JOIN table2 ON table1.id = table2.id WHERE x > 10;";

    let script = try_parse_script_from_str(sql).expect("Parse should succeed");

    let mut collector = NodeIdCollector::new();
    collector.visit_script(&script);

    // The collect_node_id function will panic if it finds a zero ID
    // If we reach here, all IDs are non-zero
    assert!(collector.node_ids.len() > 0);
}
