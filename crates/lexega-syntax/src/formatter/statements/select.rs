// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! SELECT statement formatter

use crate::ast::{
    AstExpr, AstGroupBy, AstOrderBy, AstProjection, AstProjectionKind, AstSelect, AstStmt,
    AstTableRef, AstTop, AstWithClause, FromItem, FromItemKind, ProjectionItem, ProjectionItemKind,
};
use crate::formatter::printer::Printer;
use crate::formatter::FormatterError;
use crate::lexer::Span;

/// Macro to wrap a block with recursion tracking
/// Automatically calls enter_recursion() at start and exit_recursion() on all paths
macro_rules! with_recursion_guard {
    ($printer:expr, $context:expr, $body:block) => {{
        $printer.enter_recursion($context)?;
        let result = (|| -> Result<(), FormatterError> { $body })();
        $printer.exit_recursion();
        result
    }};
}

/// Count effective number of projection items (unboxed version for Jinja branches)
fn count_effective_projection_items_unboxed(items: &[ProjectionItem]) -> usize {
    items
        .iter()
        .map(|item| {
            match &item.kind {
                ProjectionItemKind::SelectItem(_) => 1,
                ProjectionItemKind::JinjaBlock(jinja) => {
                    // Count items in all branches (then + elif + else)
                    let mut total = count_effective_projection_items_unboxed(&jinja.then_items);
                    for elif_branch in &jinja.elif_branches {
                        total += count_effective_projection_items_unboxed(&elif_branch.items);
                    }
                    if let Some(else_branch) = &jinja.else_branch {
                        total += count_effective_projection_items_unboxed(&else_branch.items);
                    }
                    total.max(1) // At least count as 1 item even if empty
                }
            }
        })
        .sum()
}

/// Count effective number of projection items, recursively counting items inside Jinja blocks
fn count_effective_projection_items(items: &[Box<ProjectionItem>]) -> usize {
    items
        .iter()
        .map(|item| {
            match &item.kind {
                ProjectionItemKind::SelectItem(_) => 1,
                ProjectionItemKind::JinjaBlock(jinja) => {
                    // Count items in all branches (then + elif + else)
                    let mut total = count_effective_projection_items_unboxed(&jinja.then_items);
                    for elif_branch in &jinja.elif_branches {
                        total += count_effective_projection_items_unboxed(&elif_branch.items);
                    }
                    if let Some(else_branch) = &jinja.else_branch {
                        total += count_effective_projection_items_unboxed(&else_branch.items);
                    }
                    total.max(1) // At least count as 1 item even if empty
                }
            }
        })
        .sum()
}

/// Format a SELECT statement (dispatcher for AstStmt)
/// Accepts AstStmt to handle both plain SELECT and set operations (UNION/INTERSECT/EXCEPT)
pub fn format_select(printer: &mut Printer, stmt: &AstStmt) -> Result<(), FormatterError> {
    // MySQL `TABLE tbl [ORDER BY ...] [LIMIT ...]` surface form — re-emit
    // verbatim from the span; the synthetic `SELECT *` projection that makes
    // it analyzable is never formatted. This is the single chokepoint for
    // formatting any SELECT (top-level, subquery, set-op operand, CTE body).
    if let AstStmt::Select(select) = stmt {
        if select.table_syntax_span.is_some() {
            printer.push_span(select.span);
            return Ok(());
        }
    }
    match stmt {
        AstStmt::Select(select) => format_select_inner(printer, select),
        AstStmt::SetSelect(set_select) => super::set_select::format_set_select(printer, set_select),
        // Writable CTEs: DML statements can appear as CTE query bodies
        AstStmt::Insert(insert) => super::dml::format_insert(printer, insert),
        AstStmt::Update(update) => super::dml::format_update(printer, update),
        AstStmt::Delete(delete) => super::dml::format_delete(printer, delete),
        _ => {
            // Fallback: emit span as-is for any other statement type
            printer.push_span(stmt.span());
            Ok(())
        }
    }
}

/// Format a SELECT statement (internal implementation)
fn format_select_inner(printer: &mut Printer, select: &AstSelect) -> Result<(), FormatterError> {
    with_recursion_guard!(printer, "SELECT statement", {
        // Set source cursor to start of this statement for trivia tracking
        printer.reset_token_index_at(select.span.start);

        // Emit any leading comments attached to this SELECT statement (V2 gap-based)
        printer.emit_comments_before(select.span.start);

        // Format WITH clause (CTEs) if present
        if let Some(ref with_clause) = select.with_clause {
            format_with_clause(printer, with_clause)?;
            printer.newline();
        }

        // Emit opening paren if this SELECT is parenthesized (e.g., in set operations)
        if let Some(paren_id) = select.paren_syntax_id {
            if let Some(subquery) = printer.get_subquery(paren_id) {
                printer.push_token_id(subquery.l_paren);
            }
        }

        // SELECT keyword
        printer.push_keyword_span(select.select_span);

        // BigQuery SELECT AS STRUCT / SELECT AS VALUE qualifier
        if let Some(ref qualifier_span) = select.select_as_qualifier {
            printer.push(" ");
            printer.push_span(*qualifier_span);
        }

        // Set quantifier (DISTINCT/ALL)
        if let Some(quantifier) = select.set_quantifier.as_deref() {
            printer.push(" ");
            match quantifier {
                crate::ast::AstSetQuantifier::All => {
                    if let Some(span) = select.set_quantifier_span {
                        printer.push_keyword_span(span);
                    } else {
                        printer.push_keyword("ALL");
                    }
                }
                crate::ast::AstSetQuantifier::Distinct => {
                    if let Some(span) = select.set_quantifier_span {
                        printer.push_keyword_span(span);
                    } else {
                        printer.push_keyword("DISTINCT");
                    }
                }
                crate::ast::AstSetQuantifier::DistinctOn { syntax_id, exprs } => {
                    // Get token IDs from syntax node
                    let (distinct_token, on_token, lparen, rparen) = printer
                        .syntax_arena()
                        .map(|arena| {
                            let syntax = arena.get_distinct_on(*syntax_id);
                            (
                                syntax.distinct_token,
                                syntax.on_token,
                                syntax.lparen,
                                syntax.rparen,
                            )
                        })
                        .unwrap_or({
                            // This should not happen in practice
                            (
                                crate::cst::TokenId(0),
                                crate::cst::TokenId(0),
                                crate::cst::TokenId(0),
                                crate::cst::TokenId(0),
                            )
                        });

                    // Emit tokens (now no borrow conflict)
                    if distinct_token.0 > 0 {
                        printer.push_token_id(distinct_token);
                        printer.push(" ");
                        printer.push_token_id(on_token);
                        printer.push(" ");
                        printer.push_token_id(lparen);
                    } else {
                        // Fallback: synthesize tokens
                        printer.push_keyword("DISTINCT");
                        printer.push(" ");
                        printer.push_keyword("ON");
                        printer.push(" ");
                        printer.push_char('(');
                    }

                    // Format expressions
                    for (i, expr) in exprs.iter().enumerate() {
                        if i > 0 {
                            printer.push_char(',');
                            printer.push(" ");
                        }
                        format_expression(printer, expr)?;
                    }

                    if rparen.0 > 0 {
                        printer.push_token_id(rparen);
                    } else {
                        printer.push_char(')');
                    }
                }
            }
        }

        // TOP clause (Snowflake/SQL Server)
        if let Some(ref top) = select.top {
            printer.push(" ");
            format_top_clause(printer, top)?;
        }

        // Projection (SELECT list)
        // Check if we should use multiline format
        // Use multiline only if: config says yes AND more than 2 columns
        // Count items recursively to account for Jinja blocks containing multiple items
        let multiline_projection = match &select.projection.kind {
            AstProjectionKind::Columns(items) => {
                let effective_item_count = count_effective_projection_items(items);
                printer.config().select_items_on_newlines && effective_item_count > 2
            }
            _ => false,
        };

        if multiline_projection {
            printer.newline();
            // Always indent when multiline, regardless of indent_select_items config
            // because Jinja blocks need proper nesting
            printer.indent_up();
            format_projection(printer, &select.projection, true)?;
            printer.indent_down();
        } else {
            printer.push(" ");
            format_projection(printer, &select.projection, false)?;
        }

        // INTO clause. Two shapes:
        //   - ScriptingVars: `INTO :var1, :var2` (Snowflake / MySQL / Oracle).
        //   - NewTable: `INTO [TEMP|TEMPORARY|UNLOGGED] tbl [ON filegroup]`
        //     (MSSQL / PostgreSQL CTAS).
        if let Some(it) = select.into_target.as_deref() {
            match it {
                crate::ast::AstSelectIntoTarget::ScriptingVars(vars) if !vars.is_empty() => {
                    printer.push(" ");
                    printer.push_keyword("INTO");
                    for (idx, var_span) in vars.iter().enumerate() {
                        if idx > 0 {
                            printer.push_comma();
                        }
                        if printer.config().space_after_comma || idx == 0 {
                            printer.space();
                        }
                        printer.push_span(*var_span);
                    }
                }
                crate::ast::AstSelectIntoTarget::ScriptingVars(_) => {
                    // Empty list — no INTO emission.
                }
                crate::ast::AstSelectIntoTarget::NewTable(nt) => {
                    printer.push(" ");
                    printer.push_keyword_span(nt.into_span);
                    if let Some(kw_span) = nt.temp_keyword_span {
                        printer.space();
                        printer.push_keyword_span(kw_span);
                    }
                    printer.space();
                    printer.push_span(nt.name.span);
                    if let Some(fg) = &nt.on_filegroup {
                        printer.space();
                        printer.push_keyword_span(fg.on_span);
                        printer.space();
                        printer.push_span(fg.filegroup_span);
                    }
                }
                crate::ast::AstSelectIntoTarget::OutFile(of) => {
                    // MySQL file export. Trailing-position INTO (written
                    // after FROM/WHERE/LIMIT) is emitted after the LIMIT
                    // section below to preserve source order.
                    if !into_outfile_is_trailing(select, of) {
                        printer.push(" ");
                        format_into_outfile(printer, of)?;
                    }
                }
            }
        }

        // FROM clause
        if !select.from.is_empty() {
            printer.newline_if_needed();
            // Search for FROM keyword after SELECT span
            format_from_clause_tracked(printer, &select.from, select.select_span.end)?;
        }

        // Jinja statement fragments (WHERE/JOIN/HAVING wrapped in {% if %}/{% for %})
        // These need to be output BEFORE the standalone WHERE clause
        for fragment in &select.statement_fragments {
            printer.newline();
            format_jinja_statement_fragment(printer, fragment)?;
        }

        // WHERE clause
        if let Some(ref where_clause) = select.where_clause {
            printer.newline_if_needed();
            // Search after last FROM table or SELECT if no FROM
            let search_after = select
                .from
                .last()
                .map(|t| get_from_item_span(t).end)
                .unwrap_or(select.select_span.end);
            format_where_clause_tracked(printer, where_clause, search_after)?;
        }

        // GROUP BY clause
        if let Some(ref group_by) = select.group_by {
            printer.newline_if_needed();
            // Search after WHERE or FROM or SELECT
            let search_after = select
                .where_clause
                .as_ref()
                .map(|c| c.span.end)
                .or_else(|| select.from.last().map(|t| get_from_item_span(t).end))
                .unwrap_or(select.select_span.end);
            format_group_by_clause_tracked(printer, group_by, search_after)?;
        }

        // HAVING clause
        if let Some(ref having) = select.having {
            printer.newline_if_needed();
            // Search after GROUP BY or WHERE or FROM or SELECT
            let search_after = select
                .group_by
                .as_ref()
                .map(|g| g.span.end)
                .or_else(|| select.where_clause.as_ref().map(|c| c.span.end))
                .or_else(|| select.from.last().map(|t| get_from_item_span(t).end))
                .unwrap_or(select.select_span.end);
            format_having_clause_tracked(printer, having, search_after)?;
        }

        // QUALIFY clause (Snowflake-specific)
        if let Some(ref qualify) = select.qualify {
            printer.newline_if_needed();
            // Search after HAVING or GROUP BY or WHERE or FROM or SELECT
            let search_after = select
                .having
                .as_ref()
                .map(|c| c.span.end)
                .or_else(|| select.group_by.as_ref().map(|g| g.span.end))
                .or_else(|| select.where_clause.as_ref().map(|c| c.span.end))
                .or_else(|| select.from.last().map(|t| get_from_item_span(t).end))
                .unwrap_or(select.select_span.end);
            format_qualify_clause_tracked(printer, qualify, search_after)?;
        }

        // CONNECT BY clause (hierarchical queries)
        if let Some(ref connect_by) = select.connect_by {
            format_connect_by_clause(printer, connect_by)?;
        }

        // WINDOW clause (named window definitions, PostgreSQL)
        if let Some(ref window_clause) = select.window_clause {
            printer.newline_if_needed();
            format_window_clause(printer, window_clause)?;
        }

        // ORDER BY clause
        if let Some(ref order_by) = select.order_by {
            printer.newline_if_needed();
            // Search after WINDOW or CONNECT BY or QUALIFY or HAVING or GROUP BY or WHERE or FROM or SELECT
            let search_after = select
                .window_clause
                .as_ref()
                .map(|c| c.span.end)
                .or_else(|| select.connect_by.as_ref().map(|c| c.span.end))
                .or_else(|| select.qualify.as_ref().map(|c| c.span.end))
                .or_else(|| select.having.as_ref().map(|c| c.span.end))
                .or_else(|| select.group_by.as_ref().map(|g| g.span.end))
                .or_else(|| select.where_clause.as_ref().map(|c| c.span.end))
                .or_else(|| select.from.last().map(|t| get_from_item_span(t).end))
                .unwrap_or(select.select_span.end);
            format_order_by_clause_tracked(printer, order_by, search_after)?;
        }

        // Dialect extension clauses that occur before LIMIT/OFFSET.
        for clause_span in select.pre_limit_extension_clauses.iter() {
            printer.newline_if_needed();
            printer.push_span(*clause_span);
        }

        // LIMIT / OFFSET / FETCH. `prev_end` is the clause immediately before
        // them — ORDER BY when present, else the last body clause — used to
        // locate the keyword in source.
        let limit_prev_end = select
            .order_by
            .as_ref()
            .map(|o| o.span.end)
            .or_else(|| select.qualify.as_ref().map(|c| c.span.end))
            .or_else(|| select.having.as_ref().map(|c| c.span.end))
            .or_else(|| select.group_by.as_ref().map(|g| g.span.end))
            .or_else(|| select.where_clause.as_ref().map(|c| c.span.end))
            .or_else(|| select.from.last().map(|t| get_from_item_span(t).end))
            .unwrap_or(select.select_span.end);
        format_limit_offset_tail(
            printer,
            select.limit.as_deref(),
            select.offset.as_deref(),
            select.limit_keyword_span,
            select.fetch_clause_span,
            select.offset_keyword_span,
            select.limit_offset_comma_span,
            limit_prev_end,
        )?;

        // Trailing-position INTO OUTFILE/DUMPFILE (MySQL writes it after
        // FROM/WHERE/LIMIT, before the locking clause).
        if let Some(crate::ast::AstSelectIntoTarget::OutFile(of)) = select.into_target.as_deref() {
            if into_outfile_is_trailing(select, of) {
                printer.newline_if_needed();
                format_into_outfile(printer, of)?;
            }
        }

        // Format FOR UPDATE/SHARE locking clauses if present
        if let Some(ref for_locking) = select.for_update {
            for for_update in for_locking.iter() {
                printer.newline_if_needed();
                printer.push_span(for_update.for_update_span); // "FOR UPDATE" / "FOR SHARE" / etc.

                // Format OF table_name [, ...] if present
                if let Some(of_kw_span) = for_update.of_keyword_span {
                    printer.space();
                    printer.push_span(of_kw_span); // "OF"
                    for (i, tbl_span) in for_update.of_tables.iter().enumerate() {
                        if i == 0 {
                            printer.space();
                        } else {
                            // Emit comma and whitespace between table names
                            printer.emit_all_tokens_until(tbl_span.start);
                        }
                        printer.push_span(*tbl_span);
                    }
                }

                // Format wait policy if present
                if let Some(ref wait_policy) = for_update.wait_policy {
                    printer.space();
                    match wait_policy {
                        crate::ast::ForUpdateWaitPolicy::NoWait { nowait_span } => {
                            printer.push_span(*nowait_span); // "NOWAIT"
                        }
                        crate::ast::ForUpdateWaitPolicy::Wait {
                            wait_span,
                            duration,
                        } => {
                            printer.push_span(*wait_span); // "WAIT"
                            printer.space();
                            format_expression(printer, duration)?;
                        }
                        crate::ast::ForUpdateWaitPolicy::SkipLocked { skip_locked_span } => {
                            printer.push_span(*skip_locked_span); // "SKIP LOCKED"
                        }
                    }
                }
            }
        }

        // MSSQL FOR JSON / FOR XML clause (raw span pass-through)
        if let Some(for_json_xml_span) = select.for_json_xml {
            printer.newline_if_needed();
            printer.push_span(for_json_xml_span);
        }

        // Dialect extension clauses that trail standard SELECT clauses.
        for clause_span in select.post_locking_extension_clauses.iter() {
            printer.newline_if_needed();
            printer.push_span(*clause_span);
        }

        // Emit closing paren if this SELECT is parenthesized (e.g., in set operations)
        if let Some(paren_id) = select.paren_syntax_id {
            if let Some(subquery) = printer.get_subquery(paren_id) {
                printer.push_token_id(subquery.r_paren);
            }
        }

        // Emit semicolon if captured from scripting context
        if let Some(semi_id) = select.semicolon_token {
            printer.push_token_id(semi_id);
        }

        Ok(())
    })
}

pub fn format_with_clause(
    printer: &mut Printer,
    with: &AstWithClause,
) -> Result<(), FormatterError> {
    use crate::ast::CteItem;

    with_recursion_guard!(printer, "WITH clause", {
        // push_keyword_span handles trivia automatically via centralized emission
        printer.push_keyword_span(with.with_span);

        if let Some(recursive_span) = with.recursive_span {
            printer.push(" ");
            // push_keyword_span handles trivia automatically
            printer.push_keyword_span(recursive_span);
        }

        // Check if CTEs should be on newlines
        let ctes_on_newline = printer.config().cte_name_on_newline;
        let leading_comma =
            printer.config().comma_style == crate::formatter::config::CommaStyle::Leading;

        if ctes_on_newline {
            printer.newline_if_needed();
            printer.indent_up();
        } else {
            printer.push(" ");
        }

        let cte_count = with.ctes.len();
        let mut prev_cte_end: Option<u32> = None;
        for (i, cte_item) in with.ctes.iter().enumerate() {
            // First item: add alignment padding for leading comma style
            if i == 0 && leading_comma && ctes_on_newline && cte_count > 1 {
                let padding = if printer.config().space_after_comma {
                    2
                } else {
                    1
                };
                printer.push_alignment_padding(padding);
            } else if i > 0 {
                // Use source comma to preserve trailing trivia (comments after comma)
                let next_start = match cte_item {
                    CteItem::Cte(cte) => cte.name.span.start,
                    CteItem::JinjaBlock(block) => block.opening.span.start,
                };

                if leading_comma && ctes_on_newline {
                    // Leading comma style: newline, then comma before current item
                    printer.newline_if_needed();
                    if let Some(end_pos) = prev_cte_end {
                        printer.push_comma_from_source(end_pos, next_start);
                    } else {
                        printer.push_comma();
                    }
                    if printer.config().space_after_comma {
                        printer.space();
                    }
                } else {
                    // Trailing comma style: comma after previous item
                    if let Some(end_pos) = prev_cte_end {
                        printer.push_comma_from_source(end_pos, next_start);
                    } else {
                        printer.push_comma();
                    }
                    if ctes_on_newline {
                        printer.newline_if_needed();
                    } else if printer.config().space_after_comma {
                        printer.space();
                    }
                }
            }

            match cte_item {
                CteItem::JinjaBlock(block) => {
                    // Format Jinja CTE block - output opening, format CTE fragments, output closing
                    format_jinja_cte_block(printer, block)?;
                    prev_cte_end = Some(block.closing.span.end);
                }
                CteItem::Cte(cte) => {
                    // Get syntax node
                    let syntax = printer.get_cte(cte.syntax_id).ok_or_else(|| {
                        FormatterError::MissingSyntaxNode("SyntaxCte".to_string())
                    })?;

                    // CTE name
                    format_identifier(printer, &cte.name)?;

                    // Column list if present
                    if !cte.column_list.is_empty() {
                        printer.push(" (");
                        for (j, col) in cte.column_list.iter().enumerate() {
                            if j > 0 {
                                printer.push_comma();
                                if printer.config().space_after_comma {
                                    printer.space();
                                }
                            }
                            format_identifier(printer, col)?;
                        }
                        printer.push(")");
                    }

                    printer.push(" ");
                    printer.push_token_id(syntax.as_keyword);
                    printer.push(" ");
                    // Use lparen token from syntax node to preserve trailing trivia
                    printer.push_token_id(syntax.l_paren);

                    // Apply CTE indent style
                    use crate::formatter::config::CteIndentStyle;
                    let saved_indent = printer.indent_level();

                    match printer.config().cte_indent_style {
                        CteIndentStyle::Standard => {
                            // Normal indentation - SELECT at same level as AS
                            printer.newline_if_needed();
                            printer.indent_up();
                        }
                        CteIndentStyle::FlushLeft => {
                            // No extra indentation - decrement current level
                            printer.newline_if_needed();
                            for _ in 0..saved_indent {
                                printer.indent_down();
                            }
                        }
                        CteIndentStyle::DoubleIndent => {
                            // Double indentation
                            printer.newline_if_needed();
                            printer.indent_up();
                            printer.indent_up();
                        }
                    }

                    // Recursively format CTE query
                    super::format_select(printer, cte.query.as_ref())?;

                    // Restore indentation
                    match printer.config().cte_indent_style {
                        CteIndentStyle::Standard => {
                            printer.indent_down();
                            printer.newline_if_needed();
                        }
                        CteIndentStyle::FlushLeft => {
                            // Restore original indent level
                            for _ in 0..saved_indent {
                                printer.indent_up();
                            }
                            printer.newline_if_needed();
                        }
                        CteIndentStyle::DoubleIndent => {
                            printer.indent_down();
                            printer.indent_down();
                            printer.newline_if_needed();
                        }
                    }

                    // Push the closing paren from syntax node with trivia preserved
                    printer.push_token_id(syntax.r_paren);
                    prev_cte_end = Some(cte.span.end);
                }
            }
        }

        // Close CTE newline indentation
        if ctes_on_newline {
            printer.indent_down();
        }

        Ok(())
    })
}

/// Format a Jinja CTE block ({% for %}...{% endfor %} or {% if %}...{% endif %} generating CTEs)
fn format_jinja_cte_block(
    printer: &mut Printer,
    block: &crate::ast::JinjaCteBlock,
) -> Result<(), FormatterError> {
    // Output opening {% if %} or {% for %}
    printer.format_jinja_delimiter(&block.opening)?;
    printer.newline();

    // Format CTE fragments in the primary branch
    for (i, fragment) in block.then_ctes.iter().enumerate() {
        if i > 0 {
            printer.newline();
        }
        format_cte_fragment(printer, fragment)?;
    }
    printer.newline();

    // Format elif branches
    for elif in &block.elif_branches {
        printer.format_jinja_delimiter(&elif.delimiter)?;
        printer.newline();
        for (i, fragment) in elif.ctes.iter().enumerate() {
            if i > 0 {
                printer.newline();
            }
            format_cte_fragment(printer, fragment)?;
        }
        printer.newline();
    }

    // Format else branch
    if let Some(else_branch) = &block.else_branch {
        printer.format_jinja_delimiter(&else_branch.delimiter)?;
        printer.newline();
        for (i, fragment) in else_branch.ctes.iter().enumerate() {
            if i > 0 {
                printer.newline();
            }
            format_cte_fragment(printer, fragment)?;
        }
        printer.newline();
    }

    // Output closing {% endif %} or {% endfor %}
    printer.format_jinja_delimiter(&block.closing)?;

    Ok(())
}

/// Format a CTE fragment inside a Jinja block
fn format_cte_fragment(
    printer: &mut Printer,
    fragment: &crate::ast::CteFragment,
) -> Result<(), FormatterError> {
    // Output the CTE name with identifier case formatting
    printer.push_identifier_span_v2(fragment.name_span);

    // Column list if present
    if !fragment.column_list.is_empty() {
        printer.push(" (");
        for (i, col) in fragment.column_list.iter().enumerate() {
            if i > 0 {
                printer.push_comma();
                if printer.config().space_after_comma {
                    printer.space();
                }
            }
            format_identifier(printer, col)?;
        }
        printer.push(")");
    }

    printer.push(" ");
    printer.push_keyword_span(fragment.as_span);
    printer.push(" ");

    // Push the opening paren with trivia preserved
    printer.push_span(fragment.lparen_span);

    // Apply CTE indent style
    use crate::formatter::config::CteIndentStyle;
    let saved_indent = printer.indent_level();

    match printer.config().cte_indent_style {
        CteIndentStyle::Standard => {
            printer.newline_if_needed();
            printer.indent_up();
        }
        CteIndentStyle::FlushLeft => {
            printer.newline_if_needed();
            for _ in 0..saved_indent {
                printer.indent_down();
            }
        }
        CteIndentStyle::DoubleIndent => {
            printer.newline_if_needed();
            printer.indent_up();
            printer.indent_up();
        }
    }

    // Format the CTE query
    super::format_select(printer, fragment.query.as_ref())?;

    // Restore indentation
    match printer.config().cte_indent_style {
        CteIndentStyle::Standard => {
            printer.indent_down();
            printer.newline_if_needed();
        }
        CteIndentStyle::FlushLeft => {
            for _ in 0..saved_indent {
                printer.indent_up();
            }
            printer.newline_if_needed();
        }
        CteIndentStyle::DoubleIndent => {
            printer.indent_down();
            printer.indent_down();
            printer.newline_if_needed();
        }
    }

    // Push the closing paren with trivia preserved
    printer.push_span(fragment.rparen_span);

    // Emit any trailing inline fragments (e.g., conditional commas/comments)
    emit_suffix_inline_fragments(printer, &fragment.suffix_inline_fragments);

    Ok(())
}

pub(crate) fn format_top_clause(printer: &mut Printer, top: &AstTop) -> Result<(), FormatterError> {
    // TOP keyword
    printer.push_keyword_span(top.top_span);
    printer.push(" ");

    // Format the expression (handles Parenthesized via syntax arena, or bare Literal)
    format_expression(printer, &top.expr)?;

    // PERCENT keyword (T-SQL: SELECT TOP 10 PERCENT ...)
    if let Some(percent_span) = top.percent_span {
        printer.push(" ");
        printer.push_span(percent_span);
    }

    // WITH TIES keywords (T-SQL: SELECT TOP 10 WITH TIES ...)
    if let Some(with_ties_span) = top.with_ties_span {
        printer.push(" ");
        printer.push_span(with_ties_span);
    }

    Ok(())
}

/// Emit an `EXCLUDE`/`EXCEPT` column-exclusion clause. Shared by the
/// star-attached form (`* EXCLUDE (a)`) and the Redshift projection-level
/// trailing form (`SELECT *, x EXCLUDE (a)`). The caller emits the leading space.
fn format_exclude(
    printer: &mut Printer,
    excl: &crate::ast::AstExclude,
) -> Result<(), FormatterError> {
    // Use CST token if available
    if let Some(syntax_id) = excl.syntax_id {
        let syntax_node_opt = printer.get_exclude(syntax_id);
        if let Some(syntax_node) = syntax_node_opt {
            let exclude_keyword = syntax_node.exclude_keyword;
            let lparen_id = syntax_node.lparen;
            let rparen_id = syntax_node.rparen;
            printer.push_token_id(exclude_keyword);
            if let Some(lparen) = lparen_id {
                printer.push(" ");
                printer.push_token_id(lparen);
            } else {
                printer.push(" ");
            }
            // Format columns - emit tokens between items to preserve commas and their trivia
            for (idx, col) in excl.columns.iter().enumerate() {
                // For items after the first, emit all tokens from previous item end to current item start
                // This captures commas and any comments attached to them
                if idx > 0 {
                    let col_start = col
                        .qualifier
                        .as_ref()
                        .map(|q| q.span.start)
                        .unwrap_or(col.name.span.start);
                    printer.emit_all_tokens_until(col_start);
                }
                // Format column: [qualifier.]name
                if let Some(ref qualifier) = col.qualifier {
                    format_object_ref(printer, qualifier)?;
                    printer.emit_all_tokens_until(col.name.span.start);
                }
                format_identifier(printer, &col.name)?;
            }
            // Emit tokens from last column to rparen (captures trailing comments)
            if let Some(rparen) = rparen_id {
                printer.push_token_id(rparen);
            }
        } else {
            // No syntax node - fallback
            printer.push_keyword_span(excl.exclude_span);
            if excl.has_parens {
                printer.push(" (");
            } else {
                printer.push(" ");
            }
            for (i, col) in excl.columns.iter().enumerate() {
                if i > 0 {
                    printer.push_comma();
                    if printer.config().space_after_comma {
                        printer.space();
                    }
                }
                if let Some(ref qualifier) = col.qualifier {
                    format_object_ref(printer, qualifier)?;
                    printer.emit_all_tokens_until(col.name.span.start);
                }
                format_identifier(printer, &col.name)?;
            }
            if excl.has_parens {
                printer.push(")");
            }
        }
    } else {
        // Fallback: use span (legacy path)
        printer.push_keyword_span(excl.exclude_span);
        if excl.has_parens {
            printer.push(" (");
        } else {
            printer.push(" ");
        }
        for (i, col) in excl.columns.iter().enumerate() {
            if i > 0 {
                printer.push_comma();
                if printer.config().space_after_comma {
                    printer.space();
                }
            }
            if let Some(ref qualifier) = col.qualifier {
                format_object_ref(printer, qualifier)?;
                printer.emit_all_tokens_until(col.name.span.start);
            }
            format_identifier(printer, &col.name)?;
        }
        if excl.has_parens {
            printer.push(")");
        }
    }
    Ok(())
}

fn format_projection(
    printer: &mut Printer,
    projection: &AstProjection,
    multiline: bool,
) -> Result<(), FormatterError> {
    match &projection.kind {
        AstProjectionKind::Star(star_proj) => {
            // Format table qualifier if present
            if let Some(ref qualifier) = star_proj.qualifier {
                format_object_ref(printer, qualifier)?;
                printer.emit_all_tokens_until(star_proj.star_span.start);
            }
            // Use star_span to preserve trailing trivia on the star itself
            printer.push_span(star_proj.star_span);

            // Format ILIKE modifier
            if let Some(ref ilike) = star_proj.ilike {
                printer.push(" ");
                printer.push_keyword_span(ilike.ilike_span);
                printer.push(" ");
                printer.push_span(ilike.pattern_span);
            }

            // Format EXCLUDE modifier (star-attached)
            if let Some(ref excl) = star_proj.exclude {
                printer.push(" ");
                format_exclude(printer, excl)?;
            }

            // Format REPLACE modifier
            if let Some(ref repl) = star_proj.replace {
                printer.push(" ");
                // Use CST token if available
                if let Some(syntax_id) = repl.syntax_id {
                    if let Some(syntax_node) = printer.get_replace(syntax_id) {
                        let replace_keyword = syntax_node.replace_keyword;
                        let lparen = syntax_node.lparen;
                        let rparen = syntax_node.rparen;
                        printer.push_token_id(replace_keyword);
                        printer.push(" ");
                        printer.push_token_id(lparen);
                        // Format items - emit tokens between items to preserve commas and their trivia
                        for (idx, item) in repl.items.iter().enumerate() {
                            // For items after the first, emit all tokens from previous item end to current item start
                            if idx > 0 {
                                printer.emit_all_tokens_until(item.expr.span().start);
                            }
                            format_expression(printer, &item.expr)?;
                            printer.push(" ");
                            printer.push_keyword_span(item.as_span);
                            printer.push(" ");
                            if let Some(ref qualifier) = item.column.qualifier {
                                format_object_ref(printer, qualifier)?;
                                printer.emit_all_tokens_until(item.column.name.span.start);
                            }
                            format_identifier(printer, &item.column.name)?;
                        }
                        // Emit tokens from last item to rparen (captures trailing comments)
                        printer.push_token_id(rparen);
                    } else {
                        // No syntax node - fallback
                        printer.push_keyword_span(repl.replace_span);
                        printer.push(" (");
                        for (i, item) in repl.items.iter().enumerate() {
                            if i > 0 {
                                printer.push_comma();
                                if printer.config().space_after_comma {
                                    printer.space();
                                }
                            }
                            format_expression(printer, &item.expr)?;
                            printer.push(" ");
                            printer.push_keyword("AS");
                            printer.push(" ");
                            if let Some(ref qualifier) = item.column.qualifier {
                                format_object_ref(printer, qualifier)?;
                                printer.emit_all_tokens_until(item.column.name.span.start);
                            }
                            format_identifier(printer, &item.column.name)?;
                        }
                        printer.push(")");
                    }
                } else {
                    // Fallback: use span (legacy path)
                    printer.push_keyword_span(repl.replace_span);
                    printer.push(" (");
                    for (i, item) in repl.items.iter().enumerate() {
                        if i > 0 {
                            printer.push_comma();
                            if printer.config().space_after_comma {
                                printer.space();
                            }
                        }
                        format_expression(printer, &item.expr)?;
                        printer.push(" ");
                        printer.push_keyword("AS");
                        printer.push(" ");
                        if let Some(ref qualifier) = item.column.qualifier {
                            format_object_ref(printer, qualifier)?;
                            printer.emit_all_tokens_until(item.column.name.span.start);
                        }
                        format_identifier(printer, &item.column.name)?;
                    }
                    printer.push(")");
                }
            }

            // Format RENAME modifier
            if let Some(ref ren) = star_proj.rename {
                printer.push(" ");
                // Use CST token if available
                if let Some(syntax_id) = ren.syntax_id {
                    if let Some(syntax_node) = printer.get_rename(syntax_id) {
                        let rename_keyword = syntax_node.rename_keyword;
                        let lparen_id = syntax_node.lparen;
                        let rparen_id = syntax_node.rparen;
                        printer.push_token_id(rename_keyword);
                        if let Some(lparen) = lparen_id {
                            printer.push(" ");
                            printer.push_token_id(lparen);
                        } else {
                            printer.push(" ");
                        }
                        // Format items - emit tokens between items to preserve commas and their trivia
                        for (idx, item) in ren.items.iter().enumerate() {
                            // For items after the first, emit all tokens from previous item end to current item start
                            if idx > 0 {
                                let item_start = item
                                    .column
                                    .qualifier
                                    .as_ref()
                                    .map(|q| q.span.start)
                                    .unwrap_or(item.column.name.span.start);
                                printer.emit_all_tokens_until(item_start);
                            }
                            if let Some(ref qualifier) = item.column.qualifier {
                                format_object_ref(printer, qualifier)?;
                                printer.emit_all_tokens_until(item.column.name.span.start);
                            }
                            format_identifier(printer, &item.column.name)?;
                            if let Some(as_span) = item.as_span {
                                printer.push(" ");
                                printer.push_keyword_span(as_span);
                            }
                            printer.push(" ");
                            format_identifier(printer, &item.alias)?;
                        }
                        // Emit tokens from last item to rparen (captures trailing comments)
                        if let Some(rparen) = rparen_id {
                            printer.push_token_id(rparen);
                        }
                    } else {
                        // No syntax node - fallback
                        printer.push_keyword_span(ren.rename_span);
                        if ren.has_parens {
                            printer.push(" (");
                        } else {
                            printer.push(" ");
                        }
                        for (i, item) in ren.items.iter().enumerate() {
                            if i > 0 {
                                printer.push_comma();
                                if printer.config().space_after_comma {
                                    printer.space();
                                }
                            }
                            if let Some(ref qualifier) = item.column.qualifier {
                                format_object_ref(printer, qualifier)?;
                                printer.emit_all_tokens_until(item.column.name.span.start);
                            }
                            format_identifier(printer, &item.column.name)?;
                            printer.push(" ");
                            printer.push_keyword("AS");
                            printer.push(" ");
                            format_identifier(printer, &item.alias)?;
                        }
                        if ren.has_parens {
                            printer.push(")");
                        }
                    }
                } else {
                    // Fallback: use span (legacy path)
                    printer.push_keyword_span(ren.rename_span);
                    if ren.has_parens {
                        printer.push(" (");
                    } else {
                        printer.push(" ");
                    }
                    for (i, item) in ren.items.iter().enumerate() {
                        if i > 0 {
                            printer.push_comma();
                            if printer.config().space_after_comma {
                                printer.space();
                            }
                        }
                        if let Some(ref qualifier) = item.column.qualifier {
                            format_object_ref(printer, qualifier)?;
                            printer.emit_all_tokens_until(item.column.name.span.start);
                        }
                        format_identifier(printer, &item.column.name)?;
                        printer.push(" ");
                        printer.push_keyword("AS");
                        printer.push(" ");
                        format_identifier(printer, &item.alias)?;
                    }
                    if ren.has_parens {
                        printer.push(")");
                    }
                }
            }

            // Emit any trailing Jinja content (comments, etc.) between modifiers and projection.span
            // This handles cases like: SELECT * {# comment #} FROM t
            if projection.span.end > star_proj.star_span.end {
                // Determine actual end of modifiers
                let modifier_end = star_proj
                    .rename
                    .as_ref()
                    .map(|r| r.span.end)
                    .or_else(|| star_proj.replace.as_ref().map(|r| r.span.end))
                    .or_else(|| star_proj.exclude.as_ref().map(|e| e.span.end))
                    .or_else(|| star_proj.ilike.as_ref().map(|i| i.span.end))
                    .unwrap_or(star_proj.star_span.end);

                if projection.span.end > modifier_end {
                    let gap_start = modifier_end as usize;
                    let gap_end = projection.span.end as usize;
                    let gap_text = {
                        let source = printer.source();
                        if gap_end <= source.len() {
                            Some(source[gap_start..gap_end].to_string())
                        } else {
                            None
                        }
                    };
                    if let Some(text) = gap_text {
                        let trimmed = text.trim();
                        if !trimmed.is_empty() {
                            // Emit a space before the gap content if needed
                            if !text.starts_with(' ') && !text.starts_with('\n') {
                                printer.space();
                            }
                            printer.push(trimmed);
                        }
                    }
                }
            }
            Ok(())
        }
        AstProjectionKind::Columns(items) => {
            if items.is_empty() {
                return Ok(());
            }

            let align_aliases = multiline && printer.config().align_select_aliases;
            let max_alignment_width = printer.config().alias_align_max_width;

            let leading_comma =
                printer.config().comma_style == crate::formatter::config::CommaStyle::Leading;

            // Track padding insertion points for post-hoc alignment
            // Each entry: (insert_position, last_line_width)
            let mut alignment_points: Vec<(usize, usize)> = Vec::new();

            let item_count = items.len();

            for (i, item) in items.iter().enumerate() {
                let is_last = i == item_count - 1;

                if i == 0 && leading_comma && multiline && item_count > 1 {
                    // First item with leading comma style: add padding to align with subsequent ", item" lines
                    // Padding is 1 (for comma) + 1 (space after comma if enabled)
                    let padding = if printer.config().space_after_comma {
                        2
                    } else {
                        1
                    };
                    printer.push_alignment_padding(padding);
                } else if i > 0 {
                    // Check if the previous item is a JinjaBlock with trailing commas in branches.
                    let prev_item = &items[i - 1];
                    let prev_has_internal_commas = match &prev_item.kind {
                        crate::ast::ProjectionItemKind::JinjaBlock(jinja) => {
                            jinja_block_has_trailing_commas_in_branches(jinja)
                        }
                        _ => false,
                    };

                    if !prev_has_internal_commas {
                        if leading_comma && multiline {
                            printer.newline_if_needed();
                            // Leading comma style - emit comma before current item
                            let prev_span = get_projection_item_span(prev_item);
                            let curr_span = get_projection_item_span(item);
                            printer.push_comma_from_source(prev_span.end, curr_span.start);
                            if printer.config().space_after_comma {
                                printer.space();
                            }
                        } else {
                            // Trailing comma style - comma was emitted after previous item
                            if multiline {
                                printer.newline_if_needed();
                            } else {
                                printer.space();
                            }
                        }
                    } else if multiline {
                        printer.newline_if_needed();
                    }
                }

                let alignment_info =
                    format_projection_item_collect_alignment(printer, item, align_aliases)?;
                if let Some(info) = alignment_info {
                    alignment_points.push(info);
                }

                // Trailing comma style - emit comma after item (not last)
                // Note: For inline projections (multiline=false), always use trailing comma style
                // because leading comma only makes sense when items are on separate lines
                if (!leading_comma || !multiline) && !is_last {
                    // Check if this item has internal commas (Jinja block with trailing commas)
                    let has_internal_commas = match &item.kind {
                        crate::ast::ProjectionItemKind::JinjaBlock(jinja) => {
                            jinja_block_has_trailing_commas_in_branches(jinja)
                        }
                        _ => false,
                    };

                    if !has_internal_commas {
                        // Emit comma with its trivia from source
                        let item_span = get_projection_item_span(item);
                        let next_span = get_projection_item_span(&items[i + 1]);
                        printer.push_comma_from_source(item_span.end, next_span.start);
                    }
                } else if !leading_comma
                    && is_last
                    && (item.has_trailing_comma || printer.config().trailing_commas)
                {
                    // Last item: preserve existing trailing comma OR add one if configured
                    printer.push_comma();
                }
            }

            // Post-hoc alignment: insert padding at recorded positions
            if align_aliases && !alignment_points.is_empty() {
                // Find the max last-line width, respecting the configured cap
                let max_width = alignment_points.iter().map(|(_, w)| *w).max().unwrap_or(0);

                // Apply cap if configured (0 = no cap)
                let target_width = if max_alignment_width > 0 {
                    max_width.min(max_alignment_width)
                } else {
                    max_width
                };

                // Insert padding at each point (in reverse order to preserve positions)
                for (insert_pos, last_line_width) in alignment_points.into_iter().rev() {
                    if last_line_width <= target_width {
                        let padding_needed = target_width - last_line_width;
                        if padding_needed > 0 {
                            printer.insert_padding_at(insert_pos, padding_needed);
                        }
                    }
                }
            }

            Ok(())
        }
    }?;

    // Redshift projection-level trailing `EXCLUDE (cols)` clause, emitted at its
    // original position after the whole list (e.g. `SELECT *, x EXCLUDE (a)`).
    if let Some(ref excl) = projection.exclude {
        printer.push(" ");
        format_exclude(printer, excl)?;
    }
    Ok(())
}

fn format_projection_item(
    printer: &mut Printer,
    item: &ProjectionItem,
    max_expr_width: usize,
) -> Result<(), FormatterError> {
    // Emit leading Jinja comments/blocks (e.g., {# comment #} before {% if %} block)
    emit_prefix_inline_fragments(printer, &item.prefix_inline_fragments);

    match &item.kind {
        ProjectionItemKind::SelectItem(select_item) => {
            // NOTE: Trivia is emitted by format_expression which calls push_span internally.

            // Track position before formatting expression
            let start_pos = printer.output_pos();

            // Assignment-projection target (`@v =` / `@v :=`) precedes the
            // expression; its spans are not inside expr and must be emitted
            // here or the variable + operator tokens are lost.
            if let Some(at) = &select_item.assign_target {
                printer.push_span(at.target.span);
                printer.push(" ");
                printer.push_span(at.assign_op_span);
                printer.push(" ");
            }

            // Recursively format expression
            format_expression(printer, &select_item.expr)?;

            // Measure the width of the last line only (for multi-line expressions)
            // We trim leading whitespace (indentation) since alignment is relative to content
            let end_pos = printer.output_pos();
            let output_slice = &printer.output_string()[start_pos..end_pos];
            let last_line = output_slice.lines().last().unwrap_or(output_slice);
            let last_line_width = last_line.trim_start().len();

            // Format alias if present
            if let Some(ref alias) = select_item.alias {
                // Calculate padding for alignment if enabled
                if max_expr_width > 0 && last_line_width <= max_expr_width {
                    let padding = max_expr_width - last_line_width + 1; // +1 for minimum space
                    for _ in 0..padding {
                        printer.push(" ");
                    }
                } else {
                    printer.push(" ");
                }

                if let Some(as_span) = alias.as_span {
                    printer.push_keyword_span(as_span);
                    printer.push(" ");
                }
                format_identifier(printer, &alias.ident)?;
            }
            // Emit trailing Jinja tokens (comments, inline control flow, embedded punctuation)
            // These are preserved from the source to maintain patterns like:
            // - id {# comment #}, name
            // - col {% if not loop.last %},{% endif %}
            emit_suffix_inline_fragments(printer, &item.suffix_inline_fragments);

            Ok(())
        }
        ProjectionItemKind::JinjaBlock(jinja) => {
            // Check if we should preserve original or format
            if printer.config().jinja_preserve_original {
                // Extract entire Jinja block as-is from source - use push_span for trivia
                printer.push_span(jinja.span);
            } else {
                // Format Jinja block using recursive descent
                format_jinja_block_projection(printer, jinja, max_expr_width)?;
            }

            // Format alias if present on the ProjectionItem
            // e.g., {% if %}a{% else %}b{% endif %} AS alias
            if let Some(ref alias) = item.alias {
                printer.push(" ");
                if let Some(as_span) = alias.as_span {
                    printer.push_keyword_span(as_span);
                    printer.push(" ");
                }
                format_identifier(printer, &alias.ident)?;
            }

            // Emit trailing Jinja tokens (comments, inline control flow like {% if not loop.last %},{% endif %})
            emit_suffix_inline_fragments(printer, &item.suffix_inline_fragments);

            Ok(())
        }
    }
}

/// Like format_projection_item, but collects alignment information for post-hoc padding.
/// Returns Some((insert_position, last_line_width)) if the item has an alias to align.
fn format_projection_item_collect_alignment(
    printer: &mut Printer,
    item: &ProjectionItem,
    collect_alignment: bool,
) -> Result<Option<(usize, usize)>, FormatterError> {
    // Emit leading Jinja comments/blocks (e.g., {# comment #} before {% if %} block)
    emit_prefix_inline_fragments(printer, &item.prefix_inline_fragments);

    match &item.kind {
        ProjectionItemKind::SelectItem(select_item) => {
            // NOTE: Trivia is emitted by format_expression which calls push_span internally.

            // Track position before formatting expression
            let start_pos = printer.output_pos();

            // Assignment-projection target (`@v =` / `@v :=`) precedes the
            // expression; its spans are not inside expr and must be emitted
            // here or the variable + operator tokens are lost.
            if let Some(at) = &select_item.assign_target {
                printer.push_span(at.target.span);
                printer.push(" ");
                printer.push_span(at.assign_op_span);
                printer.push(" ");
            }

            // Recursively format expression
            format_expression(printer, &select_item.expr)?;

            // Measure the width of the last line only (for multi-line expressions)
            // We trim leading whitespace (indentation) since alignment is relative to content
            let end_pos = printer.output_pos();
            let output_slice = &printer.output_string()[start_pos..end_pos];

            let last_line = output_slice.lines().last().unwrap_or(output_slice);
            let last_line_width = last_line.trim_start().len();

            // Alignment info to return
            let mut alignment_info: Option<(usize, usize)> = None;

            // Format alias if present
            if let Some(ref alias) = select_item.alias {
                // Record position BEFORE adding the single space (where padding would be inserted)
                let padding_insert_pos = printer.output_pos();

                // Always add just one space for now; padding will be inserted later
                printer.push(" ");

                // Collect alignment info for all expressions (single and multi-line)
                // For multi-line expressions like CASE, the last_line_width is just "END" (3 chars)
                // which means they'll get more padding to align with longer single-line expressions
                if collect_alignment {
                    alignment_info = Some((padding_insert_pos, last_line_width));
                }

                if let Some(as_span) = alias.as_span {
                    printer.push_keyword_span(as_span);
                    printer.push(" ");
                }
                format_identifier(printer, &alias.ident)?;
            }
            // Emit trailing Jinja tokens (comments, inline control flow, embedded punctuation)
            emit_suffix_inline_fragments(printer, &item.suffix_inline_fragments);

            Ok(alignment_info)
        }
        ProjectionItemKind::JinjaBlock(jinja) => {
            // Check if we should preserve original or format
            if printer.config().jinja_preserve_original {
                // Extract entire Jinja block as-is from source - use push_span for trivia
                printer.push_span(jinja.span);
            } else {
                // Format Jinja block using recursive descent (no alignment for Jinja blocks)
                format_jinja_block_projection(printer, jinja, 0)?;
            }

            // Format alias if present on the ProjectionItem
            if let Some(ref alias) = item.alias {
                printer.push(" ");
                if let Some(as_span) = alias.as_span {
                    printer.push_keyword_span(as_span);
                    printer.push(" ");
                }
                format_identifier(printer, &alias.ident)?;
            }

            // Emit trailing Jinja tokens (comments, inline control flow like {% if not loop.last %},{% endif %})
            emit_suffix_inline_fragments(printer, &item.suffix_inline_fragments);

            Ok(None)
        }
    }
}

fn emit_prefix_inline_fragments(
    printer: &mut Printer,
    fragments: &[crate::ast::JinjaInlineFragment],
) {
    for fragment in fragments {
        printer.push_span(fragment.span);
        printer.newline();
    }
}

/// Format the content of a Jinja inline block branch
fn format_inline_block_content(
    printer: &mut Printer,
    content: &Option<crate::ast::JinjaInlineBlockContent>,
) {
    use crate::ast::JinjaInlineBlockContent;

    if let Some(content) = content {
        match content {
            JinjaInlineBlockContent::Expr(expr) => {
                if let Err(_e) = format_expression(printer, expr) {
                    // Fallback: extract span from expression
                    printer.push_span(expr.span());
                }
            }
            JinjaInlineBlockContent::ProjectionItem(item) => {
                // Format the projection item properly through the standard path
                // This ensures trivia is emitted correctly for all nested content
                if let Err(_e) = format_projection_item(printer, item, 0) {
                    // Fallback: extract span from projection item
                    let span = get_projection_item_span(item);
                    printer.push_span(span);
                }
            }
            JinjaInlineBlockContent::Joins(joins) => {
                // Format JOIN clauses
                for join in joins {
                    printer.newline();
                    // Use default widths for inline block joins
                    if let Err(_e) = format_join(printer, join, 0, 0) {
                        // Fallback to span
                        printer.push_span(join.span);
                    }
                }
            }
            JinjaInlineBlockContent::WhereClause(expr) => {
                // Format WHERE clause
                printer.newline();
                printer.push_keyword("WHERE");
                printer.space();
                if let Err(_e) = format_expression(printer, expr) {
                    printer.push_span(expr.span());
                }
            }
            JinjaInlineBlockContent::JoinsAndWhere {
                joins,
                where_clause,
            } => {
                // Format JOIN clauses followed by WHERE clause
                for join in joins {
                    printer.newline();
                    // Use default widths for inline block joins
                    if let Err(_e) = format_join(printer, join, 0, 0) {
                        // Fallback to span
                        printer.push_span(join.span);
                    }
                }
                // Format WHERE clause after the JOINs
                printer.newline();
                printer.push_keyword("WHERE");
                printer.space();
                if let Err(_e) = format_expression(printer, where_clause) {
                    printer.push_span(where_clause.span());
                }
            }
            JinjaInlineBlockContent::NestedFragment(nested) => {
                // Recursively format nested Jinja fragment
                emit_suffix_inline_fragments(printer, std::slice::from_ref(nested.as_ref()));
            }
            JinjaInlineBlockContent::Punctuation(punct) => {
                // Emit the punctuation token using push_span to properly advance source position
                // This ensures emit_all_tokens_until won't duplicate it
                printer.push_span(punct.span);
            }
        }
    }
}

fn emit_suffix_inline_fragments(
    printer: &mut Printer,
    fragments: &[crate::ast::JinjaInlineFragment],
) {
    use crate::ast::JinjaInlineFragmentKind;

    for fragment in fragments {
        // Emit trivia (comments) from current position up to the fragment
        printer.emit_trivia_until(fragment.span.start, false);

        match &fragment.kind {
            JinjaInlineFragmentKind::InlineBlock(block) => {
                // Format opening delimiter
                if let Err(_e) = printer.format_jinja_delimiter(&block.opening) {
                    // Fallback to span if delimiter formatting fails
                    printer.push_span(block.opening.span);
                }

                // Format parsed content if available
                format_inline_block_content(printer, &block.content);

                // Format elif branches
                for elif_branch in &block.elif_branches {
                    if let Err(_e) = printer.format_jinja_delimiter(&elif_branch.delimiter) {
                        printer.push_span(elif_branch.delimiter.span);
                    }
                    format_inline_block_content(printer, &elif_branch.content);
                }

                // Format else branch
                if let Some(else_branch) = &block.else_branch {
                    if let Err(_e) = printer.format_jinja_delimiter(&else_branch.delimiter) {
                        printer.push_span(else_branch.delimiter.span);
                    }
                    format_inline_block_content(printer, &else_branch.content);
                }

                // Format closing delimiter if present
                if let Some(closing) = &block.closing {
                    // Emit any tokens (like commas) between content and closing delimiter
                    printer.emit_all_tokens_until(closing.span.start);

                    if let Err(_e) = printer.format_jinja_delimiter(closing) {
                        printer.push_span(closing.span);
                    }

                    // CRITICAL: After emit_all_tokens_until, source_position may not be advanced
                    // We must explicitly ensure it's at least at the closing delimiter's end
                    // to prevent re-emitting the gap between content and closing
                    if printer.get_source_position() < closing.span.end {
                        printer.set_source_position(closing.span.end);
                    }
                } else {
                    // No closing delimiter - advance to end of fragment to prevent re-emission
                    if printer.get_source_position() < fragment.span.end {
                        printer.set_source_position(fragment.span.end);
                    }
                }
            }
            JinjaInlineFragmentKind::Comment(_comment) => {
                // For comments, push_span already advances source_position
                printer.push_span(fragment.span);
            }
            JinjaInlineFragmentKind::Punctuation(_punct) => {
                // For punctuation, push_span already advances source_position
                printer.push_span(fragment.span);
            }
        }
    }
}

/// Format a Jinja block in a SELECT projection with configurable formatting.
/// Uses proper recursive descent - delegates to format_jinja_branch for each branch.
fn format_jinja_block_projection(
    printer: &mut Printer,
    jinja: &crate::ast::JinjaBlock,
    max_expr_width: usize,
) -> Result<(), FormatterError> {
    // Format opening delimiter ({% if condition %} or {% for item in list %})
    // Use CST-based formatting for proper trivia preservation
    printer.format_jinja_delimiter(&jinja.opening)?;

    // Format primary "then" branch via recursive delegation
    format_jinja_branch(
        printer,
        &jinja.then_statements,
        &jinja.then_items,
        max_expr_width,
    )?;

    // Format elif branches via recursive delegation
    for elif_branch in &jinja.elif_branches {
        printer.newline();
        printer.format_jinja_delimiter(&elif_branch.delimiter)?;

        format_jinja_branch(
            printer,
            &elif_branch.statements,
            &elif_branch.items,
            max_expr_width,
        )?;
    }

    // Format else branch via recursive delegation
    if let Some(else_branch) = &jinja.else_branch {
        printer.newline();
        printer.format_jinja_delimiter(&else_branch.delimiter)?;

        format_jinja_branch(
            printer,
            &else_branch.statements,
            &else_branch.items,
            max_expr_width,
        )?;
    }

    // Format closing delimiter ({% endif %} or {% endfor %})
    // Use CST-based formatting for proper trailing trivia preservation
    printer.newline();
    printer.format_jinja_delimiter(&jinja.closing)?;

    // Emit any trailing comments after the closing delimiter up to the end of the block span.
    // These are comments like: {% endif %} /* comment */
    // They are leading trivia of the next token but should be emitted as part of this block.
    // Use the unified trivia emitter (no trailing flag since we're consuming the gap).
    printer.emit_trivia_until(jinja.span.end, false);

    Ok(())
}

/// Format projection items inside a Jinja branch (then/elif/else).
/// Proper recursive descent: delegates to format_projection_item for each item.
/// Respects printer's indent context - no manual loops.
fn format_jinja_branch(
    printer: &mut Printer,
    statements: &[crate::ast::JinjaStmt],
    items: &[crate::ast::ProjectionItem],
    max_expr_width: usize,
) -> Result<(), FormatterError> {
    let format_sql = printer.config().jinja_format_sql_content;

    if !format_sql {
        // If not formatting SQL content, extract as-is from source
        // This preserves the original formatting inside Jinja branches

        // First output statements if any
        for stmt in statements {
            printer.newline();
            let stmt_text = printer.extract_span(stmt.span).to_string();
            printer.push(&stmt_text);
        }

        if !items.is_empty() {
            printer.newline();
            let first_span = get_projection_item_span(&items[0]);
            let last_span = get_projection_item_span(&items[items.len() - 1]);
            let jinja_content = printer
                .extract_span(crate::lexer::Span {
                    start: first_span.start,
                    end: last_span.end,
                })
                .to_string();
            printer.push(&jinja_content);
        }
        return Ok(());
    }

    // Format SQL content - use printer's indent context
    printer.newline();
    printer.indent_up();

    // Format {% set %} statements first
    for stmt in statements {
        format_jinja_set_statement(printer, stmt)?;
        printer.newline();
    }

    // Then format projection items
    for (i, item) in items.iter().enumerate() {
        if i > 0 || !statements.is_empty() {
            printer.newline();
        }
        // Recursive delegation to existing formatter
        format_projection_item(printer, item, max_expr_width)?;

        // Respect the item's trailing comma (preserves dbt conditional comma patterns)
        if item.has_trailing_comma {
            printer.push(",");
        }
    }

    printer.indent_down();
    Ok(())
}

/// Format a {% set %} Jinja statement
fn format_jinja_set_statement(
    printer: &mut Printer,
    stmt: &crate::ast::JinjaStmt,
) -> Result<(), FormatterError> {
    // If no syntax_id, fall back to span-based approach
    let Some(syntax_id) = stmt.syntax_id else {
        let stmt_text = printer.extract_span(stmt.span).to_string();
        printer.push(&stmt_text);
        return Ok(());
    };

    // Get syntax arena and copy token IDs to avoid borrow checker issues
    let (open_brace, keyword, close_brace) = {
        let Some(arena) = printer.syntax_arena() else {
            let stmt_text = printer.extract_span(stmt.span).to_string();
            printer.push(&stmt_text);
            return Ok(());
        };

        // Look up the statement and copy token IDs
        let syntax_stmt = arena.get_jinja_stmt(syntax_id);
        (
            syntax_stmt.open_brace,
            syntax_stmt.keyword,
            syntax_stmt.close_brace,
        )
    };

    // Emit tokens using push_token_id which handles trivia automatically
    printer.push_token_id(open_brace);
    printer.space();
    printer.push_token_id(keyword);

    // Emit tokens between keyword and close brace (variable = value)
    let keyword_idx = keyword.0 as usize;
    let close_idx = close_brace.0 as usize;

    for token_idx in (keyword_idx + 1)..close_idx {
        printer.space();
        printer.push_token_id(crate::cst::TokenId(token_idx as u32));
    }

    printer.space();
    printer.push_token_id(close_brace);

    Ok(())
}

/// Get the span for a projection item
fn get_projection_item_span(item: &crate::ast::ProjectionItem) -> crate::lexer::Span {
    match &item.kind {
        crate::ast::ProjectionItemKind::SelectItem(select_item) => select_item.span,
        crate::ast::ProjectionItemKind::JinjaBlock(jinja) => jinja.span,
    }
}

/// Check if a Jinja block has trailing commas in all its branches.
/// This is the dbt pattern: {% if cond %}col1,{% else %}col2,{% endif %}
/// where the comma is inside each branch, not after the block.
fn jinja_block_has_trailing_commas_in_branches(jinja: &crate::ast::JinjaBlock) -> bool {
    // Check the "then" branch - must have at least one item with trailing comma
    let then_has_comma = jinja.then_items.iter().any(|item| item.has_trailing_comma);

    // Check elif branches (if any)
    let elif_all_have_comma = jinja
        .elif_branches
        .iter()
        .all(|branch| branch.items.iter().any(|item| item.has_trailing_comma));

    // Check else branch (if present)
    let else_has_comma = match &jinja.else_branch {
        Some(else_branch) => else_branch.items.iter().any(|item| item.has_trailing_comma),
        None => true, // If no else branch, then branch comma suffices
    };

    then_has_comma && elif_all_have_comma && else_has_comma
}

/// Helper to extract the span from a FromItem (either TableRef or JinjaBlock)
/// Whether an INTO OUTFILE/DUMPFILE clause was written in the trailing
/// position (after FROM) rather than directly after the projection.
fn into_outfile_is_trailing(
    select: &crate::ast::AstSelect,
    of: &crate::ast::AstSelectIntoOutfile,
) -> bool {
    select
        .from
        .first()
        .map(get_from_item_span)
        .is_some_and(|from_span| of.into_span.start > from_span.start)
}

/// Emit `INTO OUTFILE 'file' [options]` / `INTO DUMPFILE 'file'`.
fn format_into_outfile(
    printer: &mut Printer,
    of: &crate::ast::AstSelectIntoOutfile,
) -> Result<(), FormatterError> {
    printer.push_keyword_span(of.into_span);
    printer.space();
    printer.push_keyword_span(of.kind_span);
    printer.space();
    printer.push_span(of.file_span);
    if let Some(opts) = of.options_span {
        printer.space();
        printer.push_span(opts);
    }
    Ok(())
}

fn get_from_item_span(item: &FromItem) -> Span {
    match &item.kind {
        FromItemKind::TableRef(table_ref) => table_ref.span,
        FromItemKind::JinjaBlock(jinja_block) => jinja_block.span,
        FromItemKind::JinjaTableName(jinja_name) => jinja_name.span,
    }
}

fn format_from_clause_tracked(
    printer: &mut Printer,
    items: &[FromItem],
    after_pos: u32,
) -> Result<(), FormatterError> {
    if items.is_empty() {
        return Ok(());
    }

    // Track FROM keyword by searching in source
    printer.push_keyword_after("FROM", after_pos);

    // Check if any table has JOINs - if so, we need indentation for the whole FROM section
    let has_joins = items.iter().any(|item| {
        if let FromItemKind::TableRef(table_ref) = &item.kind {
            !table_ref.joins.is_empty()
        } else {
            false
        }
    });

    let multi_line = printer.config().from_tables_on_newlines && items.len() > 1;
    let needs_indent = printer.config().indent_from_tables && (multi_line || has_joins);
    let leading_comma =
        printer.config().comma_style == crate::formatter::config::CommaStyle::Leading;

    if multi_line || (has_joins && printer.config().joins_on_newlines) {
        printer.newline_if_needed();
        if needs_indent {
            printer.indent_up();
        }
    } else {
        // For single table without joins, if we're at line start (due to trailing comment on FROM),
        // add newline and indent - otherwise just space
        if printer.get_at_line_start() {
            printer.newline_if_needed();
            if printer.config().indent_from_tables {
                printer.indent_up();
            }
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    // Find and emit the comma from source (with its trailing trivia)
                    let prev_end = if let FromItemKind::TableRef(table_ref) = &items[i - 1].kind {
                        table_ref.span.end
                    } else {
                        0
                    };

                    let curr_start = if let FromItemKind::TableRef(table_ref) = &item.kind {
                        table_ref.span.start
                    } else {
                        u32::MAX
                    };

                    if prev_end > 0 && curr_start < u32::MAX {
                        printer.push_comma_from_source(prev_end, curr_start);
                    } else {
                        printer.push_comma();
                    }

                    // Always add space after comma in FROM clauses for readability
                    if printer.config().space_after_comma {
                        printer.space();
                    }
                }
                format_from_item(printer, item)?;
            }
            if printer.config().indent_from_tables {
                printer.indent_down();
            }
            return Ok(());
        } else {
            printer.push(" ");
        }
    }

    for (i, item) in items.iter().enumerate() {
        // First item: add alignment padding for leading comma style
        if i == 0 && leading_comma && multi_line && items.len() > 1 {
            let padding = if printer.config().space_after_comma {
                2
            } else {
                1
            };
            printer.push_alignment_padding(padding);
        } else if i > 0 {
            // Find span positions for comma handling
            let prev_end = if let FromItemKind::TableRef(table_ref) = &items[i - 1].kind {
                table_ref.span.end
            } else {
                0 // Fallback for non-TableRef items
            };

            let curr_start = if let FromItemKind::TableRef(table_ref) = &item.kind {
                table_ref.span.start
            } else {
                u32::MAX // Fallback
            };

            if leading_comma && multi_line {
                // Leading comma style: newline, then comma before current item
                printer.newline_if_needed();
                if prev_end > 0 && curr_start < u32::MAX {
                    printer.push_comma_from_source(prev_end, curr_start);
                } else {
                    printer.push_comma();
                }
                if printer.config().space_after_comma {
                    printer.space();
                }
            } else {
                // Trailing comma style: comma after previous item
                if prev_end > 0 && curr_start < u32::MAX {
                    printer.push_comma_from_source(prev_end, curr_start);
                } else {
                    printer.push_comma();
                }
                if multi_line {
                    printer.newline_if_needed();
                } else {
                    // Always add space after comma in FROM clauses for readability
                    // (FROM t1,t2 looks wrong; FROM t1, t2 is correct)
                    if printer.config().space_after_comma {
                        printer.space();
                    }
                }
            }
        }
        format_from_item(printer, item)?;
    }

    if needs_indent {
        printer.indent_down();
    }

    Ok(())
}

/// Format a FROM clause item (either a table ref or Jinja block)
fn format_from_item(printer: &mut Printer, item: &FromItem) -> Result<(), FormatterError> {
    match &item.kind {
        FromItemKind::TableRef(table_ref) => {
            format_table_ref(printer, table_ref)?;
        }
        FromItemKind::JinjaBlock(jinja_block) => {
            format_from_jinja_block(printer, jinja_block)?;
        }
        FromItemKind::JinjaTableName(jinja_name) => {
            format_jinja_table_name(printer, jinja_name)?;
        }
    }
    Ok(())
}

/// Format a Jinja block that produces a table name (with optional continuation)
/// Example: {% if prod %}schema1{% else %}schema2{% endif %}.orders
fn format_jinja_table_name(
    printer: &mut Printer,
    jinja: &crate::ast::JinjaTableNameBlock,
) -> Result<(), FormatterError> {
    // Opening delimiter: {% if condition %}
    printer.format_jinja_delimiter(&jinja.opening)?;

    // Then branch content (schema/table name fragment)
    printer.push_span(jinja.then_content);

    // Elif branches
    for elif_branch in &jinja.elif_branches {
        printer.push_span(elif_branch.delimiter.span);
        printer.push_span(elif_branch.content);
    }

    // Else branch
    if let Some(else_branch) = &jinja.else_branch {
        printer.format_jinja_delimiter(&else_branch.delimiter)?;
        printer.push_span(else_branch.content);
    }

    // Closing delimiter: {% endif %}
    printer.format_jinja_delimiter(&jinja.closing)?;

    // Continuation after the Jinja block (e.g., ".orders")
    if let Some(continuation) = jinja.continuation {
        printer.push_span(continuation);
    }

    // Alias (includes AS keyword if present)
    if let Some(alias) = &jinja.alias {
        printer.push(" ");
        if let Some(as_span) = alias.as_span {
            printer.push_span(as_span);
            printer.push(" ");
        }
        printer.push_identifier_span_v2(alias.ident.span);
    }

    Ok(())
}

/// Format a Jinja block in FROM clause ({% if %} ... table refs/joins ... {% endif %})
fn format_from_jinja_block(
    printer: &mut Printer,
    jinja: &crate::ast::FromJinjaBlock,
) -> Result<(), FormatterError> {
    let indent_delimiters = printer.config().jinja_indent_delimiters;

    // Opening delimiter: {% if condition %} or {% for item in list %}
    if indent_delimiters && !printer.get_at_line_start() {
        printer.newline();
    }
    printer.format_jinja_delimiter(&jinja.opening)?;

    // Then branch items
    printer.newline();
    printer.indent_up();
    for item in &jinja.then_items {
        format_from_item(printer, item)?;
    }
    printer.indent_down();

    // Elif branches
    for elif_branch in &jinja.elif_branches {
        if indent_delimiters {
            printer.newline();
        } else {
            printer.push(" ");
        }
        printer.format_jinja_delimiter(&elif_branch.delimiter)?;
        printer.newline();
        printer.indent_up();
        for item in &elif_branch.items {
            format_from_item(printer, item)?;
        }
        printer.indent_down();
    }

    // Else branch
    if let Some(else_branch) = &jinja.else_branch {
        if indent_delimiters {
            printer.newline();
        } else {
            printer.push(" ");
        }
        printer.format_jinja_delimiter(&else_branch.delimiter)?;
        printer.newline();
        printer.indent_up();
        for item in &else_branch.items {
            format_from_item(printer, item)?;
        }
        printer.indent_down();
    }

    // Closing delimiter: {% endif %} or {% endfor %}
    if indent_delimiters {
        printer.newline();
    } else {
        printer.push(" ");
    }
    printer.format_jinja_delimiter(&jinja.closing)?;

    Ok(())
}

/// Format a Jinja block wrapping statement fragments (JOINs + WHERE + HAVING)
/// Example: FROM table {% if is_incremental() %}LEFT JOIN ... WHERE ...{% endif %}
fn format_jinja_statement_fragment(
    printer: &mut Printer,
    fragment: &crate::ast::JinjaStatementFragment,
) -> Result<(), FormatterError> {
    let indent_delimiters = printer.config().jinja_indent_delimiters;

    // Opening delimiter: {% if condition %} or {% for item in list %}
    // Add newline if indenting delimiters, or if not already at line start
    if indent_delimiters || !printer.get_at_line_start() {
        printer.newline();
    }
    printer.format_jinja_delimiter(&fragment.opening)?;

    // Then branch fragment (JOINs + WHERE + HAVING)
    printer.indent_up();
    format_statement_fragment(printer, &fragment.then_fragment)?;
    printer.indent_down();

    // Elif branches
    for elif_branch in &fragment.elif_branches {
        if indent_delimiters {
            printer.newline();
        } else {
            printer.push(" ");
        }
        printer.format_jinja_delimiter(&elif_branch.delimiter)?;
        printer.indent_up();
        format_statement_fragment(printer, &elif_branch.fragment)?;
        printer.indent_down();
    }

    // Else branch
    if let Some(else_branch) = &fragment.else_branch {
        if indent_delimiters {
            printer.newline();
        } else {
            printer.push(" ");
        }
        printer.format_jinja_delimiter(&else_branch.delimiter)?;
        printer.indent_up();
        format_statement_fragment(printer, &else_branch.fragment)?;
        printer.indent_down();
    }

    // Closing delimiter: {% endif %} or {% endfor %}
    if indent_delimiters {
        printer.newline();
    } else {
        printer.push(" ");
    }
    printer.format_jinja_delimiter(&fragment.closing)?;

    Ok(())
}

/// Format a statement fragment (JOINs + WHERE + HAVING)
/// Formats each component individually to apply formatting rules
fn format_statement_fragment(
    printer: &mut Printer,
    fragment: &crate::ast::StatementFragment,
) -> Result<(), FormatterError> {
    // Format FROM clause if present (for fragments that start with FROM)
    if let Some(ref from_items) = fragment.from_items {
        printer.newline();
        printer.push_keyword("FROM");
        printer.space();

        for (i, item) in from_items.iter().enumerate() {
            if i > 0 {
                printer.push_comma();
                if printer.config().space_after_comma {
                    printer.space();
                }
            }
            format_from_item(printer, item)?;
        }
    }

    // Calculate alignment widths for JOINs if needed
    let (max_join_keyword_width, max_table_width) = if printer.config().joins_on_newlines
        && (printer.config().align_joins || printer.config().align_join_conditions)
    {
        calculate_join_alignment_widths(printer, &fragment.joins)
    } else {
        (0, 0)
    };

    // Format JOINs
    for join in &fragment.joins {
        if printer.config().joins_on_newlines {
            printer.newline_if_needed();
        }
        format_join(printer, join, max_join_keyword_width, max_table_width)?;
    }

    // Format WHERE clause
    if let Some(ref where_condition_clause) = fragment.where_clause {
        printer.newline();
        // Extract WHERE keyword span (first few bytes of the clause span)
        let where_kw_span = Span {
            start: where_condition_clause.span.start,
            end: where_condition_clause.span.start + 5, // "WHERE" is 5 bytes
        };
        printer.push_keyword_span(where_kw_span);

        // Emit prefix inline fragments
        emit_prefix_inline_fragments(printer, &where_condition_clause.prefix_inline_fragments);

        // Check if expression is a Jinja conditional that needs indentation
        let is_jinja_conditional = matches!(
            where_condition_clause.expr,
            AstExpr::JinjaConditional { .. }
        );
        let needs_indent = is_jinja_conditional && printer.config().jinja_indent_delimiters;

        if needs_indent {
            // For Jinja conditionals with indent enabled, add newline and indent
            printer.newline();
            printer.indent_up();
            format_expression(printer, &where_condition_clause.expr)?;
            printer.indent_down();
        } else if printer.config().where_conditions_on_newlines {
            // Regular WHERE with boolean splitting
            printer.push(" ");
            format_expression_with_boolean_splitting(printer, &where_condition_clause.expr, 1)?;
        } else {
            // Inline WHERE
            printer.push(" ");
            format_expression(printer, &where_condition_clause.expr)?;
        }

        // Emit suffix inline fragments
        emit_suffix_inline_fragments(printer, &where_condition_clause.suffix_inline_fragments);

        // Emit continuation fragments
        for (op_keyword, cont_expr) in &where_condition_clause.continuation_fragments {
            printer.push(" ");
            printer.push_keyword(&format!("{:?}", op_keyword).to_uppercase());
            printer.push(" ");
            format_expression(printer, cont_expr)?;
        }
    }

    // Format GROUP BY clause
    if let Some(ref group_by) = fragment.group_by {
        printer.newline();
        // Use format_group_by_body instead of format_group_by_clause_tracked
        // to avoid the after_pos tracking (since we're in a statement fragment)

        // Emit prefix inline fragments
        emit_prefix_inline_fragments(printer, &group_by.prefix_inline_fragments);

        // Extract GROUP keyword span
        let group_kw_span = Span {
            start: group_by.span.start,
            end: group_by.span.start + 5, // "GROUP" is 5 bytes
        };
        printer.push_keyword_span(group_kw_span);
        printer.push(" ");

        // Extract BY keyword span (comes after "GROUP ")
        let by_kw_span = Span {
            start: group_by.span.start + 6, // After "GROUP "
            end: group_by.span.start + 8,   // "BY" is 2 bytes
        };
        printer.push_keyword_span(by_kw_span);

        format_group_by_body(printer, group_by)?;
        emit_suffix_inline_fragments(printer, &group_by.suffix_inline_fragments);
    }

    // Format HAVING clause
    if let Some(ref having_condition_clause) = fragment.having_clause {
        printer.newline();
        // Extract HAVING keyword span (first few bytes of the clause span)
        let having_kw_span = Span {
            start: having_condition_clause.span.start,
            end: having_condition_clause.span.start + 6, // "HAVING" is 6 bytes
        };
        printer.push_keyword_span(having_kw_span);

        // Emit prefix inline fragments
        emit_prefix_inline_fragments(printer, &having_condition_clause.prefix_inline_fragments);

        printer.push(" ");

        // Check if we should split boolean operators
        if printer.config().where_conditions_on_newlines {
            format_expression_with_boolean_splitting(printer, &having_condition_clause.expr, 1)?;
        } else {
            format_expression(printer, &having_condition_clause.expr)?;
        }

        // Emit suffix inline fragments
        emit_suffix_inline_fragments(printer, &having_condition_clause.suffix_inline_fragments);

        // Emit continuation fragments
        for (op_keyword, cont_expr) in &having_condition_clause.continuation_fragments {
            printer.push(" ");
            printer.push_keyword(&format!("{:?}", op_keyword).to_uppercase());
            printer.push(" ");
            format_expression(printer, cont_expr)?;
        }
    }

    Ok(())
}

/// Helper function to format table alias and optional column list
/// Extracted from closure to reduce stack frame size for deeply nested queries
fn format_table_alias_helper(
    printer: &mut Printer,
    table: &AstTableRef,
) -> Result<(), FormatterError> {
    if let Some(ref alias) = table.alias {
        printer.space();

        // Use CST to check if AS keyword was present in source
        if let Some(syntax_id) = table.syntax_id {
            if let Some(syntax_ref) = printer.get_table_ref(syntax_id) {
                if let Some(as_token_id) = syntax_ref.as_keyword {
                    // AS keyword was present in source - emit it with trivia
                    printer.push_keyword_token_id(as_token_id);
                    printer.space();
                }
                // else: alias without AS keyword - don't emit AS
            }
        }

        format_identifier(printer, alias)?;
    }

    // Format column aliases if present: AS t(col1, col2, ...)
    if let Some(ref cols) = table.alias_columns {
        // Emit opening paren using CST token ID
        if let Some(syntax_id) = table.syntax_id {
            if let Some(syntax_ref) = printer.get_table_ref(syntax_id) {
                if let Some(lparen_id) = syntax_ref.alias_columns_lparen {
                    printer.push_token_id(lparen_id);
                } else {
                    printer.push("(");
                }
            } else {
                printer.push("(");
            }
        } else {
            printer.push("(");
        }

        for (i, col) in cols.iter().enumerate() {
            if i > 0 {
                printer.push_comma();
                if printer.config().space_after_comma {
                    printer.space();
                }
            }
            format_identifier(printer, col)?;
        }

        // Emit closing paren using CST token ID
        if let Some(syntax_id) = table.syntax_id {
            if let Some(syntax_ref) = printer.get_table_ref(syntax_id) {
                if let Some(rparen_id) = syntax_ref.alias_columns_rparen {
                    printer.push_token_id(rparen_id);
                } else {
                    printer.push(")");
                }
            } else {
                printer.push(")");
            }
        } else {
            printer.push(")");
        }
    }
    Ok(())
}

pub fn format_table_ref(printer: &mut Printer, table: &AstTableRef) -> Result<(), FormatterError> {
    with_recursion_guard!(printer, "table reference", {
        emit_prefix_inline_fragments(printer, &table.prefix_inline_fragments);

        // Paren-group opener: `(t1 a JOIN t2 b ON …)` standard joined_table.
        // Body+inner-joins format normally; the closing `)` is emitted between
        // inner joins (count from `ParenGroupInfo::inner_join_count`) and any
        // outer joins inside the JOIN loop below.
        if let Some(pg) = table.paren_group.as_deref() {
            if let Some(lat_span) = table.lateral_keyword_span {
                printer.push_keyword_span(lat_span);
                printer.space();
            }
            printer.push_span(pg.lparen_span);
            // ODBC {oj …} form: emit the introducer + explicit separator so
            // the following table name doesn't token-merge with `oj`.
            if let Some(oj_span) = pg.odbc_oj_span {
                printer.push_span(oj_span);
                printer.space();
            }
        }

        // Handle subquery: (SELECT ...)
        if let Some(ref subquery) = table.subquery {
            if table.lateral_keyword_span.is_some() {
                printer.push_keyword("LATERAL");
                printer.space();
            }

            // Emit opening paren using CST token ID
            if let Some(syntax_id) = table.syntax_id {
                if let Some(syntax) = printer.get_table_ref(syntax_id) {
                    if let Some(lparen_id) = syntax.subquery_lparen {
                        printer.push_token_id(lparen_id);
                    } else {
                        printer.push("(");
                    }
                } else {
                    printer.push("(");
                }
            } else {
                printer.push("(");
            }

            // Format the SELECT without additional parentheses (we already emitted them above)
            if printer.config().indent_subqueries {
                printer.newline();
                printer.indent_up();
            }
            format_select(printer, subquery.as_ref())?;
            if printer.config().indent_subqueries {
                printer.indent_down();
                printer.newline();
            }

            // Emit closing paren using CST token ID
            if let Some(syntax_id) = table.syntax_id {
                if let Some(syntax) = printer.get_table_ref(syntax_id) {
                    if let Some(rparen_id) = syntax.subquery_rparen {
                        printer.push_token_id(rparen_id);
                    } else {
                        printer.push(")");
                    }
                } else {
                    printer.push(")");
                }
            } else {
                printer.push(")");
            }
        } else if let Some(ref values) = table.values {
            // Handle VALUES clause: FROM VALUES (...) or FROM (VALUES (...))
            // Only wrap in parens if the original had wrapping parens (subquery_lparen set)
            if table.lateral_keyword_span.is_some() {
                printer.push_keyword("LATERAL");
                printer.space();
            }

            // Determine if VALUES was wrapped in parens (subquery-style) or bare
            let has_wrapper_parens = table
                .syntax_id
                .and_then(|id| printer.get_table_ref(id))
                .and_then(|s| s.subquery_lparen)
                .is_some();

            // Emit opening paren using CST token ID (only if wrapper parens exist)
            if has_wrapper_parens {
                if let Some(syntax_id) = table.syntax_id {
                    if let Some(syntax) = printer.get_table_ref(syntax_id) {
                        if let Some(lparen_id) = syntax.subquery_lparen {
                            printer.push_token_id(lparen_id);
                        }
                    }
                }
            }

            // Format VALUES body
            if let Some(id) = values.syntax_id {
                if let Some(syntax) = printer.get_values(id) {
                    let keyword_id = syntax.values_keyword;
                    printer.push_keyword_token_id(keyword_id);
                } else {
                    printer.push_keyword("VALUES");
                }
            } else {
                printer.push_keyword("VALUES");
            }

            let multiline = printer.config().insert_values_on_newlines && values.rows.len() > 1;

            if multiline {
                printer.newline();
                printer.indent_up();
            } else {
                printer.space();
            }

            for (idx, row) in values.rows.iter().enumerate() {
                if idx > 0 {
                    printer.push_comma();
                    if multiline {
                        printer.newline();
                    } else if printer.config().space_after_comma {
                        printer.space();
                    }
                }

                // Emit row opening paren with trivia from CST
                if let Some(id) = values.syntax_id {
                    if let Some(syntax) = printer.get_values(id) {
                        if idx < syntax.row_lparens.len() {
                            let lparen_id = syntax.row_lparens[idx];
                            printer.push_token_id(lparen_id);
                        } else {
                            printer.push("(");
                        }
                    } else {
                        printer.push("(");
                    }
                } else {
                    printer.push("(");
                }

                for (i, expr) in row.iter().enumerate() {
                    if i > 0 {
                        printer.push_comma();
                        if printer.config().space_after_comma {
                            printer.space();
                        }
                    }
                    format_expression(printer, expr)?;
                }

                // Emit row closing paren with trivia from CST
                if let Some(id) = values.syntax_id {
                    if let Some(syntax) = printer.get_values(id) {
                        if idx < syntax.row_rparens.len() {
                            let rparen_id = syntax.row_rparens[idx];
                            printer.push_token_id(rparen_id);
                        } else {
                            printer.push(")");
                        }
                    } else {
                        printer.push(")");
                    }
                } else {
                    printer.push(")");
                }
            }

            if multiline {
                printer.indent_down();
                printer.newline();
            }

            // Emit closing paren using CST token ID (only if wrapper parens exist)
            if has_wrapper_parens {
                if let Some(syntax_id) = table.syntax_id {
                    if let Some(syntax) = printer.get_table_ref(syntax_id) {
                        if let Some(rparen_id) = syntax.subquery_rparen {
                            printer.push_token_id(rparen_id);
                        }
                    }
                }
            }
        } else if let Some(ref table_func) = table.table_function {
            let source = printer.source();
            let name_text = if (table.name.span.end as usize) <= source.len()
                && (table.name.span.start as usize) <= (table.name.span.end as usize)
            {
                &source[table.name.span.start as usize..table.name.span.end as usize]
            } else {
                ""
            };

            // Databricks/Spark generator form: LATERAL VIEW [OUTER] explode(...)
            // Keep the original phrase from source instead of rewriting to TABLE(...).
            if table.lateral_keyword_span.is_none()
                && name_text.to_ascii_uppercase().contains("LATERAL VIEW")
            {
                printer.push_span(table.name.span);
            } else if table.lateral_keyword_span.is_some() {
                // LATERAL UDTF (e.g., LATERAL FLATTEN(...)) — emit LATERAL keyword then function
                printer.push_keyword("LATERAL");
                printer.space();
                format_expression(printer, table_func)?;
            } else {
                // Check if the function is a dialect-recognized table-valued function
                // (e.g., UNNEST in BigQuery) — these are emitted directly without TABLE() wrapper
                let func_name = name_text;
                // Extract just the first word (function name) from the span
                let first_word = func_name
                    .split(|c: char| !c.is_alphanumeric() && c != '_')
                    .next()
                    .unwrap_or("");
                let is_tvf = printer.dialect().is_table_valued_function(first_word);
                if is_tvf {
                    // Direct table-valued function call (e.g., UNNEST([1,2,3]))
                    format_expression(printer, table_func)?;
                } else {
                    // Non-lateral UDTF uses TABLE(...) wrapper (Snowflake style)
                    printer.push_keyword("TABLE");
                    printer.push("(");
                    format_expression(printer, table_func)?;
                    printer.push(")");
                }
            }
        } else {
            // Regular table name
            if let Some(only_span) = table.only_span {
                printer.push_keyword_span(only_span);
                printer.space();
            }
            format_object_ref(printer, &table.name)?;
        }

        // Format MySQL partition selection: tbl PARTITION (p0, p1) — between
        // the table name and the alias.
        if let Some(ref ps) = table.partition_selection {
            printer.push(" ");
            printer.push_span(ps.span);
        }

        // Format TVF schema clause: OPENJSON(...) WITH (colName type path, ...)
        if let Some(schema_span) = table.tvf_schema_span {
            printer.push(" ");
            printer.push_span(schema_span);
        }

        // Format stage options: ( FILE_FORMAT => '...', PATTERN => '...' )
        if let Some(ref stage_opts) = table.stage_options {
            printer.space();
            printer.push_span(stage_opts.span);
        }

        // Determine which aliases to output and when
        // - alias: table alias (before transforms) - output before PIVOT/UNPIVOT/MATCH_RECOGNIZE
        // - result_alias: result alias (after transforms) - output after PIVOT/UNPIVOT/MATCH_RECOGNIZE

        // For identifier table refs: parser moves the sole alias to result_alias when PIVOT/UNPIVOT
        // follows, so alias is None and only result_alias is emitted after the transform.
        // For VALUES/subquery table refs: alias belongs to the source expression (e.g.,
        // `VALUES (...) AS unpvt(cols)`) and result_alias belongs to the PIVOT (`PIVOT (...) AS pvt`).
        // Both should be emitted in their respective positions.
        // Only defer alias when it would be redundant (alias is the sole alias moved to result_alias).
        let defer_alias = table.alias.is_none()
            && table.result_alias.is_some()
            && (table.pivot.is_some() || table.unpivot.is_some());

        // Format alias if present and NOT deferred
        if !defer_alias {
            format_table_alias_helper(printer, table)?;
        }

        // Format WITH OFFSET [AS alias] (BigQuery UNNEST modifier)
        if let Some(ref with_offset) = table.with_offset {
            printer.space();
            printer.push_keyword_span(with_offset.with_span);
            printer.space();
            printer.push_keyword_span(with_offset.offset_span);
            if let Some(ref offset_alias) = with_offset.alias {
                printer.space();
                if let Some(as_sp) = with_offset.as_span {
                    printer.push_keyword_span(as_sp);
                    printer.space();
                }
                printer.push_span(offset_alias.span);
            }
        }

        // Format T-SQL table hints: WITH (NOLOCK), WITH (UPDLOCK, HOLDLOCK), etc.
        if let Some(ref hints) = table.table_hints {
            printer.push(" ");
            printer.push_span(hints.span);
        }

        // Format MySQL index hints: USE INDEX (...), FORCE INDEX FOR JOIN (...)
        if let Some(ref index_hints) = table.index_hints {
            for hint in index_hints.iter() {
                printer.push(" ");
                printer.push_span(hint.span);
            }
        }

        // Format time travel clause: AT (TIMESTAMP => expr) or BEFORE (...) or FOR SYSTEM_TIME AS OF
        if let Some(ref time_travel) = table.time_travel {
            printer.push(" ");
            match time_travel.as_ref() {
                crate::ast::AstTimeTravelClause::SnowflakeAtBefore(tt) => {
                    format_time_travel(printer, tt)?;
                }
                crate::ast::AstTimeTravelClause::ForSystemTime(fst) => {
                    printer.push_span(fst.span);
                }
                crate::ast::AstTimeTravelClause::DatabricksAsOf(dbx) => {
                    printer.push_span(dbx.span);
                }
            }
        }

        // Format sample clause: SAMPLE BERNOULLI (10) SEED (42)
        if let Some(ref sample) = table.sample {
            printer.push(" ");
            format_sample_clause(printer, sample)?;
        }

        // Format changes clause: CHANGES (INFORMATION => DEFAULT) AT (...)
        if let Some(ref changes) = table.changes {
            printer.push(" ");
            format_changes_clause(printer, changes)?;
        }

        // Format PIVOT clause: PIVOT (aggregate FOR column IN (values))
        if let Some(ref pivot) = table.pivot {
            printer.push(" ");
            format_pivot_clause(printer, pivot)?;
        }

        // Format UNPIVOT clause: UNPIVOT (value_col FOR name_col IN (columns))
        if let Some(ref unpivot) = table.unpivot {
            printer.push(" ");
            format_unpivot_clause(printer, unpivot)?;
        }

        // Format MATCH_RECOGNIZE clause
        if let Some(ref match_rec) = table.match_recognize {
            if printer.config().match_recognize_on_newline {
                printer.newline();
            } else {
                printer.push(" ");
            }
            format_match_recognize(printer, match_rec)?;
        }

        // Format result_alias if present (after PIVOT/UNPIVOT/MATCH_RECOGNIZE)
        if let Some(ref result_alias) = table.result_alias {
            printer.space();

            // Use CST to check if AS keyword was present in source for result_alias
            if let Some(syntax_id) = table.syntax_id {
                if let Some(syntax_ref) = printer.get_table_ref(syntax_id) {
                    if let Some(as_token_id) = syntax_ref.result_alias_as_keyword {
                        // AS keyword was present in source - emit it with trivia
                        printer.push_keyword_token_id(as_token_id);
                        printer.space();
                    }
                    // else: result_alias without AS keyword - don't emit AS
                }
            }

            format_identifier(printer, result_alias)?;

            // Format result_alias_columns if present: AS p(col1, col2, ...)
            // Emit parens via CST token IDs so the source `(`/`)` are consumed
            // (advancing the source cursor); raw pushes would leave the source
            // `)` unconsumed and the statement catch-up would re-emit it.
            if let Some(ref cols) = table.result_alias_columns {
                let (lparen_id, rparen_id) = table
                    .syntax_id
                    .and_then(|sid| printer.get_table_ref(sid))
                    .map(|s| (s.result_alias_columns_lparen, s.result_alias_columns_rparen))
                    .unwrap_or((None, None));

                if let Some(lparen_id) = lparen_id {
                    printer.push_token_id(lparen_id);
                } else {
                    printer.push("(");
                }
                for (i, col) in cols.iter().enumerate() {
                    if i > 0 {
                        printer.push_comma();
                        if printer.config().space_after_comma {
                            printer.space();
                        }
                    }
                    format_identifier(printer, col)?;
                }
                if let Some(rparen_id) = rparen_id {
                    printer.push_token_id(rparen_id);
                } else {
                    printer.push(")");
                }
            }
        }

        // Calculate alignment widths if needed
        let (max_join_keyword_width, max_table_width) = if printer.config().joins_on_newlines
            && (printer.config().align_joins || printer.config().align_join_conditions)
        {
            calculate_join_alignment_widths(printer, &table.joins)
        } else {
            (0, 0)
        };

        // Format JOINs. For paren-grouped table-refs, the closing `)` is emitted
        // between the inner-joins (first N) and any outer joins. When the count
        // equals `table.joins.len()` (all joins inside), the `)` is emitted after
        // the loop ends.
        let paren_inner_count = table
            .paren_group
            .as_deref()
            .map(|pg| pg.inner_join_count as usize);
        for (idx, join) in table.joins.iter().enumerate() {
            if Some(idx) == paren_inner_count {
                if let Some(pg) = table.paren_group.as_deref() {
                    printer.push_span(pg.rparen_span);
                }
            }
            if printer.config().joins_on_newlines {
                printer.newline_if_needed();
            }
            format_join(printer, join, max_join_keyword_width, max_table_width)?;
        }
        // All joins were inside the parens (or there were none) — close after loop.
        if let Some(pg) = table.paren_group.as_deref() {
            let inner_count = paren_inner_count.unwrap_or(0);
            if inner_count >= table.joins.len() {
                printer.push_span(pg.rparen_span);
            }
        }

        emit_suffix_inline_fragments(printer, &table.suffix_inline_fragments);

        Ok(())
    })
}

/// Format AT/BEFORE time travel clause
/// Syntax: {AT | BEFORE} (TIMESTAMP => expr | OFFSET => expr | STATEMENT => expr | STREAM => expr)
fn format_time_travel(
    printer: &mut Printer,
    time_travel: &crate::ast::AstTimeTravel,
) -> Result<(), FormatterError> {
    // Emit the entire time travel clause from source span
    // This preserves exact syntax including parentheses, spacing, etc.
    printer.push_span(time_travel.span);
    Ok(())
}

/// Format SAMPLE clause
/// Syntax: [SAMPLE | TABLESAMPLE] [BERNOULLI | ROW | SYSTEM | BLOCK] (size) [SEED | REPEATABLE (seed)]
fn format_sample_clause(
    printer: &mut Printer,
    sample: &crate::ast::AstSampleClause,
) -> Result<(), FormatterError> {
    // Emit the entire sample clause span - push_span handles trivia and advances source_position
    printer.push_span(sample.span);
    Ok(())
}

/// Format CHANGES clause for change tracking
/// Syntax: CHANGES (INFORMATION => {DEFAULT | APPEND_ONLY}) AT|BEFORE (...) [END (...)]
fn format_changes_clause(
    printer: &mut Printer,
    changes: &crate::ast::AstChangesClause,
) -> Result<(), FormatterError> {
    use crate::ast::{AstChangesInformation, AstTimeTravelKind};

    printer.push_keyword("CHANGES");
    printer.push(" ");
    printer.push("(");
    printer.push_keyword("INFORMATION");
    printer.push(" ");
    printer.push("=>");
    printer.push(" ");

    match changes.information {
        AstChangesInformation::Default => printer.push_keyword("DEFAULT"),
        AstChangesInformation::AppendOnly => printer.push_keyword("APPEND_ONLY"),
    }

    printer.push(")");
    printer.push(" ");

    // AT or BEFORE clause
    format_time_travel(printer, &changes.at_before)?;

    // Optional END clause
    if let Some(ref end) = changes.end {
        printer.push(" ");
        printer.push_keyword("END");
        printer.push(" ");
        printer.push("(");

        match &end.kind {
            AstTimeTravelKind::Timestamp(expr) => {
                printer.push_keyword("TIMESTAMP");
                printer.push(" ");
                printer.push("=>");
                printer.push(" ");
                format_expression(printer, expr)?;
            }
            AstTimeTravelKind::Offset(expr) => {
                printer.push_keyword("OFFSET");
                printer.push(" ");
                printer.push("=>");
                printer.push(" ");
                format_expression(printer, expr)?;
            }
            AstTimeTravelKind::Statement(expr) => {
                printer.push_keyword("STATEMENT");
                printer.push(" ");
                printer.push("=>");
                printer.push(" ");
                format_expression(printer, expr)?;
            }
            AstTimeTravelKind::Stream(expr) => {
                printer.push_keyword("STREAM");
                printer.push(" ");
                printer.push("=>");
                printer.push(" ");
                format_expression(printer, expr)?;
            }
        }

        printer.push(")");
    }

    Ok(())
}

/// Format PIVOT clause
/// Syntax: PIVOT (aggregate_func(column) [AS alias] FOR column IN (value1 [AS alias1], ...))
fn format_pivot_clause(
    printer: &mut Printer,
    pivot: &crate::ast::AstPivotClause,
) -> Result<(), FormatterError> {
    use crate::ast::AstPivotInValues;

    printer.push_keyword_span(pivot.pivot_span);
    printer.push("(");

    // Aggregate function(s)
    for (idx, agg) in pivot.aggregates.iter().enumerate() {
        if idx > 0 {
            printer.push_comma();
            if printer.config().space_after_comma {
                printer.space();
            }
        }
        format_expression(printer, &agg.expr)?;

        // Optional AS alias for aggregate
        if let Some(ref alias) = agg.alias {
            printer.push(" ");
            if let Some(as_span) = agg.as_span {
                printer.push_keyword_span(as_span);
            } else {
                printer.push_keyword("AS");
            }
            printer.push(" ");
            format_identifier(printer, alias)?;
        }
    }

    printer.push(" ");
    printer.push_keyword_span(pivot.for_span);
    printer.push(" ");
    format_expression(printer, &pivot.for_column)?;
    printer.push(" ");
    printer.push_keyword_span(pivot.in_span);
    printer.push(" ");
    printer.push("(");

    // Format IN values
    match &pivot.in_values {
        AstPivotInValues::ValueList(values) => {
            for (idx, value) in values.iter().enumerate() {
                if idx > 0 {
                    printer.push_comma();
                    if printer.config().space_after_comma {
                        printer.space();
                    }
                }
                format_expression(printer, &value.value)?;
                if let Some(ref alias) = value.alias {
                    printer.push(" ");
                    if let Some(as_span) = value.as_span {
                        printer.push_keyword_span(as_span);
                    } else {
                        printer.push_keyword("AS");
                    }
                    printer.push(" ");
                    format_identifier(printer, alias)?;
                }
            }
        }
        AstPivotInValues::OpaqueList(span) => {
            // Contains Jinja - preserve as-is
            printer.push_span(*span);
        }
        AstPivotInValues::Any(order_by) => {
            printer.push_keyword("ANY");
            if let Some(ref order_items) = order_by {
                printer.push(" ");
                printer.push_keyword("ORDER BY");
                printer.push(" ");
                for (idx, item) in order_items.iter().enumerate() {
                    if idx > 0 {
                        printer.push_comma();
                        if printer.config().space_after_comma {
                            printer.space();
                        }
                    }
                    // Format expression
                    format_expression(printer, &item.expr)?;
                    // Format ASC/DESC
                    if let Some(asc) = item.asc {
                        printer.push(" ");
                        printer.push_keyword(if asc { "ASC" } else { "DESC" });
                    }
                    // Format NULLS FIRST/LAST
                    if let Some(nulls_first) = item.nulls_first {
                        printer.push(" ");
                        printer.push_keyword("NULLS");
                        printer.push(" ");
                        printer.push_keyword(if nulls_first { "FIRST" } else { "LAST" });
                    }
                }
            }
        }
        AstPivotInValues::Subquery(select) => {
            format_select(printer, select)?;
        }
    }

    printer.push(")");

    // Optional DEFAULT ON NULL
    if let Some(ref default_expr) = pivot.default_on_null {
        printer.push(" ");
        if let Some(default_on_null_span) = pivot.default_on_null_span {
            printer.push_keyword_span(default_on_null_span);
        } else {
            printer.push_keyword("DEFAULT ON NULL");
        }
        printer.push(" ");
        printer.push("(");
        format_expression(printer, default_expr)?;
        printer.push(")");
    }

    printer.push(")");
    Ok(())
}

/// Format UNPIVOT clause
/// Syntax: UNPIVOT [INCLUDE NULLS | EXCLUDE NULLS] (value_col FOR name_col IN (col1 [AS alias1], ...))
fn format_unpivot_clause(
    printer: &mut Printer,
    unpivot: &crate::ast::AstUnpivotClause,
) -> Result<(), FormatterError> {
    printer.push_keyword_span(unpivot.unpivot_span);

    // INCLUDE/EXCLUDE NULLS
    if let Some(include_exclude_nulls_span) = unpivot.include_exclude_nulls_span {
        printer.push(" ");
        printer.push_keyword_span(include_exclude_nulls_span);
    } else if unpivot.include_nulls {
        printer.push(" ");
        printer.push_keyword("INCLUDE NULLS");
    } else {
        printer.push(" ");
        printer.push_keyword("EXCLUDE NULLS");
    }

    printer.push(" ");
    printer.push("(");

    // value_column(s) FOR name_column
    if unpivot.value_columns.len() > 1 {
        printer.push("(");
        for (idx, vc) in unpivot.value_columns.iter().enumerate() {
            if idx > 0 {
                printer.push_comma();
                if printer.config().space_after_comma {
                    printer.space();
                }
            }
            format_identifier(printer, vc)?;
        }
        printer.push(")");
    } else if let Some(vc) = unpivot.value_columns.first() {
        format_identifier(printer, vc)?;
    }
    printer.push(" ");
    printer.push_keyword_span(unpivot.for_span);
    printer.push(" ");
    format_identifier(printer, &unpivot.name_column)?;
    printer.push(" ");
    printer.push_keyword_span(unpivot.in_span);
    printer.push(" ");
    printer.push("(");

    // Columns to unpivot
    for (idx, col) in unpivot.columns.iter().enumerate() {
        if idx > 0 {
            printer.push_comma();
            if printer.config().space_after_comma {
                printer.space();
            }
        }
        if col.columns.len() > 1 {
            printer.push("(");
            for (cidx, c) in col.columns.iter().enumerate() {
                if cidx > 0 {
                    printer.push_comma();
                    if printer.config().space_after_comma {
                        printer.space();
                    }
                }
                format_identifier(printer, c)?;
            }
            printer.push(")");
        } else if let Some(c) = col.columns.first() {
            format_identifier(printer, c)?;
        }
        if let Some(ref alias) = col.alias {
            printer.push(" ");
            if let Some(as_span) = col.as_span {
                printer.push_keyword_span(as_span);
            } else {
                printer.push_keyword("AS");
            }
            printer.push(" ");
            format_identifier(printer, alias)?;
        }
    }

    printer.push(")");
    printer.push(")");
    Ok(())
}

/// Format MATCH_RECOGNIZE clause
/// Syntax: MATCH_RECOGNIZE (
///     PARTITION BY ...
///     ORDER BY ...
///     MEASURES ... AS alias, ...
///     [ONE ROW PER MATCH | ALL ROWS PER MATCH ...]
///     [AFTER MATCH SKIP ...]
///     PATTERN (...)
///     DEFINE symbol AS condition, ...
/// )
fn format_match_recognize(
    printer: &mut Printer,
    mr: &crate::ast::AstMatchRecognize,
) -> Result<(), FormatterError> {
    use crate::formatter::config::{
        MatchRecognizeDefineStyle, MatchRecognizeFormat, MatchRecognizeMeasuresStyle,
    };

    // MATCH_RECOGNIZE is fully token-tracked; if syntax metadata is missing,
    // preserve source exactly instead of synthesizing clause text.
    let Some(syntax_id) = mr.syntax_id else {
        printer.push_span(mr.span);
        return Ok(());
    };
    if printer.get_match_recognize(syntax_id).is_none() {
        printer.push_span(mr.span);
        return Ok(());
    }

    // Use captured MATCH_RECOGNIZE keyword token
    if let Some(syntax_mr) = printer.get_match_recognize(syntax_id) {
        printer.push_keyword_token_id(syntax_mr.match_recognize_keyword);
        // Use the actual lparen token to preserve trivia
        printer.push_token_id(syntax_mr.mr_lparen);
    } else {
        printer.push_span(mr.span);
        return Ok(());
    }

    let expanded = matches!(
        printer.config().match_recognize_format,
        MatchRecognizeFormat::Expanded
    );

    if expanded {
        printer.newline();
        printer.indent_up();
    }

    // PARTITION BY clause
    if let Some(ref partition_exprs) = mr.partition_by {
        if expanded {
            // Use token IDs for proper trivia handling
            if let Some(syntax_id) = mr.syntax_id {
                if let Some(syntax_mr) = printer.get_match_recognize(syntax_id) {
                    if let Some(partition_kw_id) = syntax_mr.partition_keyword {
                        printer.push_keyword_token_id(partition_kw_id);
                        if let Some(by_kw_id) = syntax_mr.partition_by_keyword {
                            printer.push(" ");
                            printer.push_keyword_token_id(by_kw_id);
                        } else {
                            printer.push(" ");
                            printer.push_keyword("BY");
                        }
                        printer.push(" ");
                    } else {
                        printer.push_keyword("PARTITION BY");
                        printer.push(" ");
                    }
                } else {
                    printer.push_keyword("PARTITION BY");
                    printer.push(" ");
                }
            } else {
                printer.push_keyword("PARTITION BY");
                printer.push(" ");
            }
        } else {
            printer.push(" ");
            if let Some(syntax_id) = mr.syntax_id {
                if let Some(syntax_mr) = printer.get_match_recognize(syntax_id) {
                    if let Some(partition_kw_id) = syntax_mr.partition_keyword {
                        printer.push_keyword_token_id(partition_kw_id);
                        if let Some(by_kw_id) = syntax_mr.partition_by_keyword {
                            printer.push(" ");
                            printer.push_keyword_token_id(by_kw_id);
                        } else {
                            printer.push(" ");
                            printer.push_keyword("BY");
                        }
                    } else {
                        printer.push_keyword("PARTITION BY");
                    }
                } else {
                    printer.push_keyword("PARTITION BY");
                }
            } else {
                printer.push_keyword("PARTITION BY");
            }
            printer.push(" ");
        }

        // Emit expressions with comma tokens for trivia preservation
        for (idx, expr) in partition_exprs.iter().enumerate() {
            if idx > 0 {
                // Use captured comma token if available
                if let Some(syntax_id) = mr.syntax_id {
                    if let Some(syntax_mr) = printer.get_match_recognize(syntax_id) {
                        let comma_idx = idx - 1;
                        if (comma_idx as u8) < syntax_mr.partition_by_comma_count {
                            printer.push_token_id(syntax_mr.partition_by_commas[comma_idx]);
                        } else {
                            printer.push(",");
                        }
                    } else {
                        printer.push(",");
                    }
                } else {
                    printer.push(",");
                }
                printer.push(" ");
            }
            format_expression(printer, expr)?;
        }

        if expanded {
            printer.newline();
        }
    }

    // ORDER BY clause
    if let Some(ref order_by) = mr.order_by {
        if expanded && mr.partition_by.is_some() {
            // Already on newline
        } else if expanded {
            // First clause
        } else {
            printer.push(" ");
        }

        // Use token IDs for ORDER and BY keywords
        if let Some(syntax_id) = mr.syntax_id {
            if let Some(syntax_mr) = printer.get_match_recognize(syntax_id) {
                if let Some(order_kw_id) = syntax_mr.order_keyword {
                    printer.push_keyword_token_id(order_kw_id);
                    printer.push(" ");
                    if let Some(by_kw_id) = syntax_mr.order_by_keyword {
                        printer.push_keyword_token_id(by_kw_id);
                    } else {
                        printer.push_keyword("BY");
                    }
                    printer.push(" ");
                } else {
                    printer.push_keyword("ORDER BY");
                    printer.push(" ");
                }
            } else {
                printer.push_keyword("ORDER BY");
                printer.push(" ");
            }
        } else {
            printer.push_keyword("ORDER BY");
            printer.push(" ");
        }

        for (idx, item) in order_by.items.iter().enumerate() {
            if idx > 0 {
                // Use captured comma token if available
                if let Some(syntax_id) = mr.syntax_id {
                    if let Some(syntax_mr) = printer.get_match_recognize(syntax_id) {
                        let comma_idx = idx - 1;
                        if (comma_idx as u8) < syntax_mr.order_by_comma_count {
                            printer.push_token_id(syntax_mr.order_by_commas[comma_idx]);
                        } else {
                            printer.push(",");
                        }
                    } else {
                        printer.push(",");
                    }
                } else {
                    printer.push(",");
                }
                printer.push(" ");
            }
            format_expression(printer, &item.expr)?;
            if let Some(asc) = item.asc {
                printer.push(" ");
                printer.push_keyword(if asc { "ASC" } else { "DESC" });
            }
            if let Some(nulls_first) = item.nulls_first {
                printer.push(" ");
                printer.push_keyword("NULLS");
                printer.push(" ");
                printer.push_keyword(if nulls_first { "FIRST" } else { "LAST" });
            }
            // Emit trailing trivia after each order item (preserves inline comments)
            printer.emit_trivia_until(item.span.end, true);
        }

        if expanded {
            printer.newline();
        }
    }

    // MEASURES clause
    if !mr.measures.is_empty() {
        if !expanded && (mr.partition_by.is_some() || mr.order_by.is_some()) {
            printer.push(" ");
        }

        // Use token ID if available for proper trivia handling
        if let Some(syntax_id) = mr.syntax_id {
            if let Some(syntax_mr) = printer.get_match_recognize(syntax_id) {
                if let Some(measures_kw_id) = syntax_mr.measures_keyword {
                    printer.push_keyword_token_id(measures_kw_id);
                } else {
                    printer.push_keyword("MEASURES");
                }
            } else {
                printer.push_keyword("MEASURES");
            }
        } else {
            printer.push_keyword("MEASURES");
        }

        // Determine if MEASURES should be multiline
        let measures_multiline = if expanded {
            match printer.config().match_recognize_measures_style {
                MatchRecognizeMeasuresStyle::Inline => false,
                MatchRecognizeMeasuresStyle::OnePerLine => true,
                MatchRecognizeMeasuresStyle::Threshold(n) => mr.measures.len() > n,
            }
        } else {
            false
        };

        if measures_multiline {
            let leading_comma =
                printer.config().comma_style == crate::formatter::config::CommaStyle::Leading;
            printer.indent_up();
            for (idx, measure) in mr.measures.iter().enumerate() {
                let is_last = idx == mr.measures.len() - 1;

                if leading_comma {
                    printer.newline();
                    if idx > 0 {
                        // Use captured comma token if available
                        if let Some(syntax_id) = mr.syntax_id {
                            if let Some(syntax_mr) = printer.get_match_recognize(syntax_id) {
                                let comma_idx = idx - 1;
                                if (comma_idx as u8) < syntax_mr.measures_comma_count {
                                    printer.push_token_id(syntax_mr.measures_commas[comma_idx]);
                                } else {
                                    printer.push(",");
                                }
                            } else {
                                printer.push(",");
                            }
                        } else {
                            printer.push(",");
                        }
                        if printer.config().space_after_comma {
                            printer.space();
                        }
                    }
                } else {
                    printer.newline();
                }

                // Output semantic modifier if present (use captured token)
                if let Some(modifier) = measure.semantic_modifier {
                    if let Some(syntax_id) = measure.syntax_id {
                        if let Some(syntax_measure) = printer.get_measure_item(syntax_id) {
                            if let Some(mod_token) = syntax_measure.semantic_modifier {
                                printer.push_keyword_token_id(mod_token);
                            } else {
                                match modifier {
                                    crate::ast::AstMeasureSemanticModifier::Running => {
                                        printer.push_keyword("RUNNING");
                                    }
                                    crate::ast::AstMeasureSemanticModifier::Final => {
                                        printer.push_keyword("FINAL");
                                    }
                                }
                            }
                        } else {
                            match modifier {
                                crate::ast::AstMeasureSemanticModifier::Running => {
                                    printer.push_keyword("RUNNING");
                                }
                                crate::ast::AstMeasureSemanticModifier::Final => {
                                    printer.push_keyword("FINAL");
                                }
                            }
                        }
                    } else {
                        match modifier {
                            crate::ast::AstMeasureSemanticModifier::Running => {
                                printer.push_keyword("RUNNING");
                            }
                            crate::ast::AstMeasureSemanticModifier::Final => {
                                printer.push_keyword("FINAL");
                            }
                        }
                    }
                    printer.push(" ");
                }

                format_expression(printer, &measure.expr)?;
                printer.push(" ");

                // Use captured AS keyword token if available
                if let Some(syntax_id) = measure.syntax_id {
                    if let Some(syntax_measure) = printer.get_measure_item(syntax_id) {
                        printer.push_keyword_token_id(syntax_measure.as_keyword);
                    } else {
                        printer.push_keyword("AS");
                    }
                } else {
                    printer.push_keyword("AS");
                }
                printer.push(" ");
                format_identifier(printer, &measure.alias)?;

                // Emit trailing trivia for this measure (preserves inline comments)
                printer.emit_trivia_until(measure.span.end, true);

                if !leading_comma && !is_last {
                    // Use captured comma token if available
                    if let Some(syntax_id) = mr.syntax_id {
                        if let Some(syntax_mr) = printer.get_match_recognize(syntax_id) {
                            let comma_idx = idx;
                            if (comma_idx as u8) < syntax_mr.measures_comma_count {
                                printer.push_token_id(syntax_mr.measures_commas[comma_idx]);
                            } else {
                                printer.push(",");
                            }
                        } else {
                            printer.push(",");
                        }
                    } else {
                        printer.push(",");
                    }
                }
            }
            printer.indent_down();
        } else {
            printer.push(" ");
            for (idx, measure) in mr.measures.iter().enumerate() {
                if idx > 0 {
                    // Use captured comma token if available
                    if let Some(syntax_id) = mr.syntax_id {
                        if let Some(syntax_mr) = printer.get_match_recognize(syntax_id) {
                            let comma_idx = idx - 1;
                            if (comma_idx as u8) < syntax_mr.measures_comma_count {
                                printer.push_token_id(syntax_mr.measures_commas[comma_idx]);
                            } else {
                                printer.push(",");
                            }
                        } else {
                            printer.push(",");
                        }
                    } else {
                        printer.push(",");
                    }
                    printer.push(" ");
                }

                // Output semantic modifier if present (use captured token)
                if let Some(modifier) = measure.semantic_modifier {
                    if let Some(syntax_id) = measure.syntax_id {
                        if let Some(syntax_measure) = printer.get_measure_item(syntax_id) {
                            if let Some(mod_token) = syntax_measure.semantic_modifier {
                                printer.push_keyword_token_id(mod_token);
                            } else {
                                match modifier {
                                    crate::ast::AstMeasureSemanticModifier::Running => {
                                        printer.push_keyword("RUNNING");
                                    }
                                    crate::ast::AstMeasureSemanticModifier::Final => {
                                        printer.push_keyword("FINAL");
                                    }
                                }
                            }
                        } else {
                            match modifier {
                                crate::ast::AstMeasureSemanticModifier::Running => {
                                    printer.push_keyword("RUNNING");
                                }
                                crate::ast::AstMeasureSemanticModifier::Final => {
                                    printer.push_keyword("FINAL");
                                }
                            }
                        }
                    } else {
                        match modifier {
                            crate::ast::AstMeasureSemanticModifier::Running => {
                                printer.push_keyword("RUNNING");
                            }
                            crate::ast::AstMeasureSemanticModifier::Final => {
                                printer.push_keyword("FINAL");
                            }
                        }
                    }
                    printer.push(" ");
                }

                format_expression(printer, &measure.expr)?;
                printer.push(" ");

                // Use captured AS keyword token if available
                if let Some(syntax_id) = measure.syntax_id {
                    if let Some(syntax_measure) = printer.get_measure_item(syntax_id) {
                        printer.push_keyword_token_id(syntax_measure.as_keyword);
                    } else {
                        printer.push_keyword("AS");
                    }
                } else {
                    printer.push_keyword("AS");
                }
                printer.push(" ");
                format_identifier(printer, &measure.alias)?;

                // Emit trailing trivia for this measure (preserves inline comments)
                printer.emit_trivia_until(measure.span.end, true);
            }
        }

        if expanded {
            printer.newline();
        }
    }

    // Rows per match - emit all keyword tokens from CST
    if let Some(ref rows_per_match) = mr.rows_per_match {
        if !expanded {
            printer.push(" ");
        }

        // Emit all keyword tokens using their token IDs from CST
        if let Some(syntax_id) = mr.syntax_id {
            if let Some(syntax_mr) = printer.get_match_recognize(syntax_id) {
                let token_count = syntax_mr.rows_per_match_token_count as usize;
                if token_count > 0 {
                    // Emit all tokens with proper keyword casing and trivia
                    for (idx, &token_id) in syntax_mr.rows_per_match_tokens[..token_count]
                        .iter()
                        .enumerate()
                    {
                        if idx > 0 {
                            printer.push(" ");
                        }
                        printer.push_keyword_token_id(token_id);
                    }
                } else {
                    format_rows_per_match_fallback(printer, rows_per_match);
                }
            } else {
                format_rows_per_match_fallback(printer, rows_per_match);
            }
        } else {
            format_rows_per_match_fallback(printer, rows_per_match);
        }

        if expanded {
            printer.newline();
        }
    }

    // After match skip - emit all keyword tokens from CST
    if let Some(ref after_match) = mr.after_match_skip {
        if !expanded {
            printer.push(" ");
        }

        // Emit all keyword tokens using their token IDs from CST
        if let Some(syntax_id) = mr.syntax_id {
            if let Some(syntax_mr) = printer.get_match_recognize(syntax_id) {
                let token_count = syntax_mr.after_match_skip_token_count as usize;
                if token_count > 0 {
                    // Emit all tokens with proper keyword casing and trivia
                    for (idx, &token_id) in syntax_mr.after_match_skip_tokens[..token_count]
                        .iter()
                        .enumerate()
                    {
                        if idx > 0 {
                            printer.push(" ");
                        }
                        printer.push_keyword_token_id(token_id);
                    }
                } else {
                    format_after_match_skip_fallback(printer, after_match);
                }
            } else {
                format_after_match_skip_fallback(printer, after_match);
            }
        } else {
            format_after_match_skip_fallback(printer, after_match);
        }

        if expanded {
            printer.newline();
        }
    } else if mr.rows_per_match.is_some() {
        // No after_match_skip, emit trivia from rows_per_match to PATTERN
        if let Some(syntax_id) = mr.syntax_id {
            if let Some(syntax_mr) = printer.get_match_recognize(syntax_id) {
                let pattern_pos = printer
                    .get_token_by_id(syntax_mr.pattern_keyword)
                    .map(|t| t.span.start);
                if let Some(pos) = pattern_pos {
                    printer.emit_trivia_until(pos, false);
                    printer.set_source_position(pos);
                }
            }
        }
    }

    // PATTERN clause - use direct source extraction to preserve trivia (comments)
    // NOTE: We cannot use emit_all_tokens_until() here because source_position
    // may have been advanced past the PATTERN content by MEASURES formatting.
    // Instead, we extract the pattern content directly from source using spans.
    if !expanded {
        printer.push(" ");
    }

    // Extract pattern span information before mutable operations (borrow checker)
    // Also extract pattern_keyword, pattern_lparen, and pattern_rparen token IDs for CST-based emission
    let pattern_span_info: Option<(
        crate::cst::TokenId,
        crate::cst::TokenId,
        crate::cst::TokenId,
    )> = if let Some(syntax_id) = mr.syntax_id {
        printer.get_match_recognize(syntax_id).map(|syntax_mr| {
            (
                syntax_mr.pattern_keyword,
                syntax_mr.pattern_lparen,
                syntax_mr.pattern_rparen,
            )
        })
    } else {
        None
    };

    if let Some((pattern_kw_id, pattern_lparen_id, pattern_rparen_id)) = pattern_span_info {
        // Emit PATTERN keyword and opening paren
        printer.push_keyword_token_id(pattern_kw_id);
        printer.push(" ");
        printer.push_token_id(pattern_lparen_id);

        // Emit all pattern tokens from the captured Vec to preserve trivia
        if let Some(syntax_id) = mr.syntax_id {
            if let Some(syntax_mr) = printer.get_match_recognize(syntax_id) {
                for (idx, &token_id) in syntax_mr.pattern_tokens.iter().enumerate() {
                    if idx > 0 {
                        if let Some(token) = printer.get_token_by_id(token_id) {
                            let is_quantifier = matches!(
                                token.kind,
                                crate::lexer::TokenKind::Operator(
                                    crate::lexer::Operator::Plus | crate::lexer::Operator::Star
                                )
                            );
                            if !is_quantifier {
                                printer.push(" ");
                            }
                        } else {
                            printer.push(" ");
                        }
                    }
                    printer.push_token_id(token_id);
                }
            }
        }

        // Emit closing paren
        printer.push_token_id(pattern_rparen_id);
    } else {
        // Fallback - use pattern_text from AST (may lose comments)
        printer.push_keyword("PATTERN");
        printer.push(" ");
        printer.push("(");
        printer.push(&mr.pattern.pattern_text);
        printer.push(")");
    }

    // Emit all tokens/trivia up to DEFINE keyword to capture trailing comments
    if let Some(syntax_id) = mr.syntax_id {
        if let Some(syntax_mr) = printer.get_match_recognize(syntax_id) {
            if !mr.define.is_empty() {
                let define_token = printer.get_token_by_id(syntax_mr.define_keyword);
                if let Some(tok) = define_token {
                    printer.emit_all_tokens_until(tok.span.start);
                }
            } else {
                // No DEFINE clause, emit up to closing paren
                let rparen_token = printer.get_token_by_id(syntax_mr.mr_rparen);
                if let Some(tok) = rparen_token {
                    printer.emit_all_tokens_until(tok.span.start);
                }
            }
        }
    }

    if expanded {
        printer.newline();
    }

    // DEFINE clause
    if !mr.define.is_empty() {
        if !expanded {
            printer.push(" ");
        }

        // Use syntax layer for DEFINE keyword if available
        if let Some(syntax_id) = mr.syntax_id {
            if let Some(syntax_mr) = printer.get_match_recognize(syntax_id) {
                printer.push_keyword_token_id(syntax_mr.define_keyword);
            } else {
                printer.push_keyword("DEFINE");
            }
        } else {
            printer.push_keyword("DEFINE");
        };

        // Determine if DEFINE should be multiline
        let define_multiline = if expanded {
            match printer.config().match_recognize_define_style {
                MatchRecognizeDefineStyle::Inline => false,
                MatchRecognizeDefineStyle::OnePerLine => true,
                MatchRecognizeDefineStyle::Threshold(n) => mr.define.len() > n,
            }
        } else {
            false
        };

        if define_multiline {
            let leading_comma =
                printer.config().comma_style == crate::formatter::config::CommaStyle::Leading;
            printer.indent_up();
            for (idx, def) in mr.define.iter().enumerate() {
                let is_last = idx == mr.define.len() - 1;

                if leading_comma {
                    printer.newline();
                    if idx > 0 {
                        // Use captured comma token if available
                        if let Some(syntax_id) = mr.syntax_id {
                            if let Some(syntax_mr) = printer.get_match_recognize(syntax_id) {
                                let comma_idx = idx - 1;
                                if (comma_idx as u8) < syntax_mr.define_comma_count {
                                    printer.push_token_id(syntax_mr.define_commas[comma_idx]);
                                } else {
                                    printer.push(",");
                                }
                            } else {
                                printer.push(",");
                            }
                        } else {
                            printer.push(",");
                        }
                        if printer.config().space_after_comma {
                            printer.space();
                        }
                    }
                } else {
                    printer.newline();
                }

                // When CST is available, use token IDs for proper trivia/comment preservation
                if let Some(syntax_id) = def.syntax_id {
                    if let Some(syntax_def) = printer.get_define_symbol(syntax_id) {
                        // Emit symbol token
                        printer.push_keyword_token_id(syntax_def.symbol_token);
                        printer.push(" ");
                        // Emit AS keyword token
                        printer.push_keyword_token_id(syntax_def.as_keyword);
                        printer.push(" ");
                        // Format expression
                        format_expression(printer, &def.expr)?;
                        // Emit trailing trivia
                        printer.emit_trivia_until(def.span.end, true);
                    } else {
                        printer.push(&def.symbol);
                        printer.push(" ");
                        printer.push_keyword("AS");
                        printer.push(" ");
                        format_expression(printer, &def.expr)?;
                        printer.emit_trivia_until(def.span.end, true);
                    }
                } else {
                    printer.push(&def.symbol);
                    printer.push(" ");
                    printer.push_keyword("AS");
                    printer.push(" ");
                    format_expression(printer, &def.expr)?;
                    printer.emit_trivia_until(def.span.end, true);
                }

                if !leading_comma && !is_last {
                    // Use captured comma token if available
                    if let Some(syntax_id) = mr.syntax_id {
                        if let Some(syntax_mr) = printer.get_match_recognize(syntax_id) {
                            let comma_idx = idx;
                            if (comma_idx as u8) < syntax_mr.define_comma_count {
                                printer.push_token_id(syntax_mr.define_commas[comma_idx]);
                            } else {
                                printer.push(",");
                            }
                        } else {
                            printer.push(",");
                        }
                    } else {
                        printer.push(",");
                    }
                }
            }
            printer.indent_down();
        } else {
            printer.push(" ");
            for (idx, def) in mr.define.iter().enumerate() {
                if idx > 0 {
                    // Use captured comma token if available
                    if let Some(syntax_id) = mr.syntax_id {
                        if let Some(syntax_mr) = printer.get_match_recognize(syntax_id) {
                            let comma_idx = idx - 1;
                            if (comma_idx as u8) < syntax_mr.define_comma_count {
                                printer.push_token_id(syntax_mr.define_commas[comma_idx]);
                            } else {
                                printer.push(",");
                            }
                        } else {
                            printer.push(",");
                        }
                    } else {
                        printer.push(",");
                    }
                    printer.push(" ");
                }

                // When CST is available, use token IDs for proper trivia/comment preservation
                if let Some(syntax_id) = def.syntax_id {
                    if let Some(syntax_def) = printer.get_define_symbol(syntax_id) {
                        // Emit symbol token
                        printer.push_keyword_token_id(syntax_def.symbol_token);
                        printer.push(" ");
                        // Emit AS keyword token
                        printer.push_keyword_token_id(syntax_def.as_keyword);
                        printer.push(" ");
                        // Format expression
                        format_expression(printer, &def.expr)?;
                        // Emit trailing trivia
                        printer.emit_trivia_until(def.span.end, true);
                    } else {
                        printer.push(&def.symbol);
                        printer.push(" ");
                        printer.push_keyword("AS");
                        printer.push(" ");
                        format_expression(printer, &def.expr)?;
                        printer.emit_trivia_until(def.span.end, true);
                    }
                } else {
                    printer.push(&def.symbol);
                    printer.push(" ");
                    printer.push_keyword("AS");
                    printer.push(" ");
                    format_expression(printer, &def.expr)?;
                    printer.emit_trivia_until(def.span.end, true);
                }
            }
        }
    }

    if expanded {
        printer.indent_down();
        printer.newline();
    }

    // Use the actual rparen token to preserve trivia
    if let Some(syntax_id) = mr.syntax_id {
        if let Some(syntax_mr) = printer.get_match_recognize(syntax_id) {
            printer.push_token_id(syntax_mr.mr_rparen);
            // Emit trailing trivia after closing paren (e.g., /* match alias */)
            printer.emit_trivia_until(mr.span.end, true);
        } else {
            printer.push(")");
        }
    } else {
        printer.push(")");
    }
    Ok(())
}

/// Calculate alignment widths for JOIN keywords and table references
fn calculate_join_alignment_widths(
    printer: &Printer,
    joins: &[Box<crate::ast::AstJoin>],
) -> (usize, usize) {
    use crate::ast::AstJoinKind;

    let mut max_join_keyword_width = 0;
    let mut max_table_width = 0;

    for join in joins {
        // Calculate JOIN keyword width
        let join_keyword_width = if join.apply_keyword_span.is_some() {
            match join.kind {
                AstJoinKind::Cross => "CROSS APPLY".len(),
                AstJoinKind::LeftOuter => "OUTER APPLY".len(),
                _ => "APPLY".len(),
            }
        } else {
            match join.kind {
                AstJoinKind::Inner => "JOIN".len(),
                AstJoinKind::LeftOuter => "LEFT OUTER JOIN".len(),
                AstJoinKind::RightOuter => "RIGHT OUTER JOIN".len(),
                AstJoinKind::FullOuter => "FULL OUTER JOIN".len(),
                AstJoinKind::Cross => "CROSS JOIN".len(),
                AstJoinKind::Asof => "ASOF JOIN".len(),
                AstJoinKind::NaturalInner => "NATURAL JOIN".len(),
                AstJoinKind::NaturalLeftOuter => "NATURAL LEFT OUTER JOIN".len(),
                AstJoinKind::NaturalRightOuter => "NATURAL RIGHT OUTER JOIN".len(),
                AstJoinKind::NaturalFullOuter => "NATURAL FULL OUTER JOIN".len(),
            }
        };
        max_join_keyword_width = max_join_keyword_width.max(join_keyword_width);

        // Calculate table reference width if align_join_conditions is enabled
        if printer.config().align_join_conditions {
            let mut temp_printer = Printer::new(
                printer.config(),
                printer.source(),
                None, // No CST needed for width measurement
            );
            if format_join_table_ref(&mut temp_printer, &join.right).is_ok() {
                let output = temp_printer.output_string();
                let width = output.len();
                max_table_width = max_table_width.max(width);
            }
        }
    }

    (max_join_keyword_width, max_table_width)
}

/// Format just the table reference part of a join (for width calculation)
fn format_join_table_ref(printer: &mut Printer, table: &AstTableRef) -> Result<(), FormatterError> {
    emit_prefix_inline_fragments(printer, &table.prefix_inline_fragments);

    if let Some(ref subquery) = table.subquery {
        super::format_select(printer, subquery.as_ref())?;
    } else if let Some(ref table_func) = table.table_function {
        // Check dialect for table-valued function handling
        let source = printer.source();
        let func_name = &source[table.name.span.start as usize..table.name.span.end as usize];
        let first_word = func_name
            .split(|c: char| !c.is_alphanumeric() && c != '_')
            .next()
            .unwrap_or("");
        let is_tvf = printer.dialect().is_table_valued_function(first_word);
        if table.lateral_keyword_span.is_some() {
            printer.push_keyword("LATERAL");
            printer.push(" ");
            format_expression(printer, table_func)?;
        } else if is_tvf {
            format_expression(printer, table_func)?;
        } else {
            printer.push_keyword("TABLE");
            printer.push("(");
            format_expression(printer, table_func)?;
            printer.push(")");
        }
    } else {
        format_object_ref(printer, &table.name)?;
    }

    // Format TVF schema clause: OPENJSON(...) WITH (colName type path, ...)
    if let Some(schema_span) = table.tvf_schema_span {
        printer.push(" ");
        printer.push_span(schema_span);
    }

    if let Some(ref alias) = table.alias {
        printer.push(" ");
        format_identifier(printer, alias)?;
    }

    emit_suffix_inline_fragments(printer, &table.suffix_inline_fragments);

    Ok(())
}

fn format_join(
    printer: &mut Printer,
    join: &crate::ast::AstJoin,
    max_join_keyword_width: usize,
    max_table_width: usize,
) -> Result<(), FormatterError> {
    use crate::ast::{AstJoinConstraint, AstJoinKind};

    if !printer.config().joins_on_newlines {
        printer.push(" ");
    }

    emit_prefix_inline_fragments(printer, &join.prefix_inline_fragments);

    // NOTE: Trivia is emitted automatically by push_keyword() when it finds the token.

    // Reset token index to the start of this join's span so that keyword lookup
    // functions like has_keyword_before() can find keywords for THIS join, not a prior one.
    printer.reset_token_index_at(join.span.start);

    // Emit DIRECTED keyword if present (comes before join type)
    if join.directed_keyword_span.is_some() {
        printer.push_keyword("DIRECTED");
        printer.push(" ");
    }

    // Emit LATERAL keyword if present (comes before join type)
    if join.lateral_keyword_span.is_some() {
        printer.push_keyword("LATERAL");
        printer.push(" ");
    }

    // Format join kind and calculate its width
    // When normalize_join_keywords is false (default), preserve source keywords
    // When true, output the fully expanded form (e.g., LEFT OUTER JOIN)
    let normalize = printer.config().normalize_join_keywords;

    if join.apply_keyword_span.is_some() {
        let join_keyword_width = match join.kind {
            AstJoinKind::Cross => {
                printer.push_keyword("CROSS");
                printer.push(" ");
                printer.push_keyword("APPLY");
                "CROSS APPLY".len()
            }
            AstJoinKind::LeftOuter => {
                printer.push_keyword("OUTER");
                printer.push(" ");
                printer.push_keyword("APPLY");
                "OUTER APPLY".len()
            }
            _ => {
                printer.push_keyword("APPLY");
                "APPLY".len()
            }
        };

        if printer.config().align_joins
            && max_join_keyword_width > 0
            && join_keyword_width < max_join_keyword_width
        {
            let padding = max_join_keyword_width - join_keyword_width;
            for _ in 0..padding {
                printer.push(" ");
            }
        }

        printer.push(" ");

        let table_start_pos = printer.output_string().len();
        format_table_ref(printer, &join.right)?;
        let table_end_pos = printer.output_string().len();
        let _table_width = table_end_pos - table_start_pos;

        emit_suffix_inline_fragments(printer, &join.suffix_inline_fragments);
        return Ok(());
    }

    let join_keyword_width = match join.kind {
        AstJoinKind::Inner => {
            // Check if source had explicit INNER keyword
            let has_inner = printer.has_keyword_before("INNER", "JOIN");
            if has_inner {
                printer.push_keyword("INNER");
                printer.push(" ");
                printer.push_keyword("JOIN");
                "INNER JOIN".len()
            } else {
                printer.push_keyword("JOIN");
                "JOIN".len()
            }
        }
        AstJoinKind::LeftOuter => {
            printer.push_keyword("LEFT");
            printer.push(" ");
            // Check if source had OUTER keyword (preserve it) or if normalizing (add it)
            let has_outer = printer.has_keyword_before("OUTER", "JOIN");
            if normalize || has_outer {
                printer.push_keyword("OUTER");
                printer.push(" ");
            }
            printer.push_keyword("JOIN");
            if normalize || has_outer {
                "LEFT OUTER JOIN".len()
            } else {
                "LEFT JOIN".len()
            }
        }
        AstJoinKind::RightOuter => {
            printer.push_keyword("RIGHT");
            printer.push(" ");
            let has_outer = printer.has_keyword_before("OUTER", "JOIN");
            if normalize || has_outer {
                printer.push_keyword("OUTER");
                printer.push(" ");
            }
            printer.push_keyword("JOIN");
            if normalize || has_outer {
                "RIGHT OUTER JOIN".len()
            } else {
                "RIGHT JOIN".len()
            }
        }
        AstJoinKind::FullOuter => {
            printer.push_keyword("FULL");
            printer.push(" ");
            let has_outer = printer.has_keyword_before("OUTER", "JOIN");
            if normalize || has_outer {
                printer.push_keyword("OUTER");
                printer.push(" ");
            }
            printer.push_keyword("JOIN");
            if normalize || has_outer {
                "FULL OUTER JOIN".len()
            } else {
                "FULL JOIN".len()
            }
        }
        AstJoinKind::Cross => {
            printer.push_keyword("CROSS");
            printer.push(" ");
            printer.push_keyword("JOIN");
            "CROSS JOIN".len()
        }
        AstJoinKind::Asof => {
            printer.push_keyword("ASOF");
            printer.push(" ");
            printer.push_keyword("JOIN");
            "ASOF JOIN".len()
        }
        AstJoinKind::NaturalInner => {
            printer.push_keyword("NATURAL");
            printer.push(" ");
            // Check if source had explicit INNER keyword
            let has_inner = printer.has_keyword_before("INNER", "JOIN");
            if has_inner {
                printer.push_keyword("INNER");
                printer.push(" ");
            }
            printer.push_keyword("JOIN");
            if has_inner {
                "NATURAL INNER JOIN".len()
            } else {
                "NATURAL JOIN".len()
            }
        }
        AstJoinKind::NaturalLeftOuter => {
            printer.push_keyword("NATURAL");
            printer.push(" ");
            printer.push_keyword("LEFT");
            printer.push(" ");
            let has_outer = printer.has_keyword_before("OUTER", "JOIN");
            if normalize || has_outer {
                printer.push_keyword("OUTER");
                printer.push(" ");
            }
            printer.push_keyword("JOIN");
            if normalize || has_outer {
                "NATURAL LEFT OUTER JOIN".len()
            } else {
                "NATURAL LEFT JOIN".len()
            }
        }
        AstJoinKind::NaturalRightOuter => {
            printer.push_keyword("NATURAL");
            printer.push(" ");
            printer.push_keyword("RIGHT");
            printer.push(" ");
            let has_outer = printer.has_keyword_before("OUTER", "JOIN");
            if normalize || has_outer {
                printer.push_keyword("OUTER");
                printer.push(" ");
            }
            printer.push_keyword("JOIN");
            if normalize || has_outer {
                "NATURAL RIGHT OUTER JOIN".len()
            } else {
                "NATURAL RIGHT JOIN".len()
            }
        }
        AstJoinKind::NaturalFullOuter => {
            printer.push_keyword("NATURAL");
            printer.push(" ");
            printer.push_keyword("FULL");
            printer.push(" ");
            let has_outer = printer.has_keyword_before("OUTER", "JOIN");
            if normalize || has_outer {
                printer.push_keyword("OUTER");
                printer.push(" ");
            }
            printer.push_keyword("JOIN");
            if normalize || has_outer {
                "NATURAL FULL OUTER JOIN".len()
            } else {
                "NATURAL FULL JOIN".len()
            }
        }
    };

    // Apply JOIN keyword alignment if enabled
    if printer.config().align_joins
        && max_join_keyword_width > 0
        && join_keyword_width < max_join_keyword_width
    {
        let padding = max_join_keyword_width - join_keyword_width;
        for _ in 0..padding {
            printer.push(" ");
        }
    }

    printer.push(" ");

    // Track position before table reference for ON clause alignment
    let table_start_pos = printer.output_string().len();

    // Format right table (which may have more joins recursively)
    format_table_ref(printer, &join.right)?;

    // Format MATCH_CONDITION for ASOF JOIN (before ON clause).
    // Emit the whole `MATCH_CONDITION ( … )` clause from its source span, as the
    // sibling Snowflake sub-clauses (SAMPLE/time-travel/CHANGES) do: this consumes
    // the keyword, both parens, and the inner expression, advancing the source
    // cursor. Synthesizing the parens left the source `)` unconsumed — when no ON
    // clause followed, the statement catch-up then re-emitted it.
    if let Some(ref match_cond) = join.match_condition {
        printer.push(" ");
        printer.push_span(match_cond.span);
    }

    // Calculate table reference width for ON clause alignment
    let table_end_pos = printer.output_string().len();
    let table_width = table_end_pos - table_start_pos;

    // Format join constraint
    match &join.constraint {
        AstJoinConstraint::On(expr) => {
            // Check if ON clause should be on newline
            if printer.config().join_on_clause_on_newline {
                printer.newline();
                if printer.config().indent_join_on_clause {
                    printer.indent_up();
                }
                printer.push_keyword("ON");
                printer.push(" ");
            } else {
                // Apply ON clause alignment if enabled
                if printer.config().align_join_conditions
                    && max_table_width > 0
                    && table_width < max_table_width
                {
                    let padding = max_table_width - table_width + 1;
                    for _ in 0..padding {
                        printer.push(" ");
                    }
                } else {
                    printer.push(" ");
                }

                printer.push_keyword("ON");
                printer.push(" ");
            }

            // Check if we should split boolean operators
            if printer.config().where_conditions_on_newlines {
                format_expression_with_boolean_splitting(printer, expr, 1)?;
            } else {
                format_expression(printer, expr)?;
            }

            // Restore indent if we added it
            if printer.config().join_on_clause_on_newline && printer.config().indent_join_on_clause
            {
                printer.indent_down();
            }
        }
        AstJoinConstraint::Using(columns) => {
            // Check if USING clause should be on newline
            if printer.config().join_on_clause_on_newline {
                printer.newline();
                if printer.config().indent_join_on_clause {
                    printer.indent_up();
                }
            } else {
                printer.push(" ");
            }

            printer.push_keyword("USING");
            printer.push(" (");
            for (i, col) in columns.iter().enumerate() {
                if i > 0 {
                    printer.push_comma();
                    if printer.config().space_after_comma {
                        printer.space();
                    }
                }
                format_identifier(printer, col)?;
            }
            printer.push(")");

            // Restore indent if we added it
            if printer.config().join_on_clause_on_newline && printer.config().indent_join_on_clause
            {
                printer.indent_down();
            }
        }
        AstJoinConstraint::None => {
            // No constraint (e.g., CROSS JOIN, NATURAL JOIN)
        }
    }

    emit_suffix_inline_fragments(printer, &join.suffix_inline_fragments);

    Ok(())
}

fn format_where_clause_tracked(
    printer: &mut Printer,
    clause: &crate::ast::ConditionClause,
    after_pos: u32,
) -> Result<(), FormatterError> {
    printer.push_keyword_after("WHERE", after_pos);

    emit_prefix_inline_fragments(printer, &clause.prefix_inline_fragments);

    let expr = &clause.expr;
    // Check if expression is a Jinja conditional that needs indentation
    let is_jinja_conditional = matches!(expr, AstExpr::JinjaConditional { .. });
    let needs_indent = is_jinja_conditional && printer.config().jinja_indent_delimiters;

    if needs_indent {
        // For Jinja conditionals with indent enabled, add newline and indent
        printer.newline();
        printer.indent_up();
        format_expression(printer, expr)?;
        printer.indent_down();
    } else if printer.config().where_conditions_on_newlines {
        // Regular WHERE with boolean splitting - indent the first condition too
        printer.newline();
        printer.indent_up();
        format_expression_with_boolean_splitting(printer, expr, 0)?;
        printer.indent_down();
    } else {
        // Inline WHERE
        printer.push(" ");
        format_expression(printer, expr)?;
    }

    emit_suffix_inline_fragments(printer, &clause.suffix_inline_fragments);

    // Format continuation expressions after Jinja blocks (e.g., AND expr3 after {% endif %})
    // Example: WHERE expr1 {% if %}AND expr2{% endif %} AND expr3
    for (operator_keyword, continuation_expr) in &clause.continuation_fragments {
        printer.newline();
        let keyword_str = match operator_keyword {
            crate::lexer::Keyword::And => "AND",
            crate::lexer::Keyword::Or => "OR",
            _ => continue, // Skip unexpected keywords
        };
        printer.push_keyword(keyword_str);
        printer.push(" ");
        format_expression(printer, continuation_expr)?;
    }

    Ok(())
}

fn format_group_by_clause_tracked(
    printer: &mut Printer,
    group_by: &AstGroupBy,
    after_pos: u32,
) -> Result<(), FormatterError> {
    // If the GROUP BY is wrapped in a Jinja block, emit the opening delimiter first
    if !group_by.prefix_inline_fragments.is_empty() {
        emit_prefix_inline_fragments(printer, &group_by.prefix_inline_fragments);
    }

    // For JinjaPlaceholder, the Jinja macro generates the entire GROUP BY clause
    // (e.g., {{ dbt_utils.group_by(n=13) }} -> GROUP BY 1, 2, 3, ...)
    // So we should NOT emit GROUP BY keywords - just the Jinja span
    if matches!(
        &group_by.variant,
        crate::ast::AstGroupByVariant::JinjaPlaceholder(_)
    ) {
        format_group_by_body(printer, group_by)?;
        emit_suffix_inline_fragments(printer, &group_by.suffix_inline_fragments);
        return Ok(());
    }

    // Use CST token IDs if available, otherwise fall back to search
    let use_cst = group_by.syntax_id.is_some() && printer.syntax_arena().is_some();

    if use_cst {
        let syntax_id = group_by.syntax_id.unwrap();
        let syntax_node = *printer.syntax_arena().unwrap().get_group_by(syntax_id);
        printer.push_keyword_token_id(syntax_node.group_keyword);
        printer.push(" ");
        printer.push_keyword_token_id(syntax_node.by_keyword);
    } else {
        // Fallback if syntax_id or syntax arena not available
        printer.push_keyword_after("GROUP", after_pos);
        printer.push(" ");
        printer.push_keyword("BY");
    }

    format_group_by_body(printer, group_by)?;
    emit_suffix_inline_fragments(printer, &group_by.suffix_inline_fragments);
    Ok(())
}

fn format_group_by_body(
    printer: &mut Printer,
    group_by: &AstGroupBy,
) -> Result<(), FormatterError> {
    use crate::ast::AstGroupByVariant;

    match &group_by.variant {
        AstGroupByVariant::All => {
            printer.push(" ");
            printer.push_keyword("ALL");
        }
        AstGroupByVariant::Standard(items) => {
            let multiline = printer.config().group_by_items_on_newlines && items.len() > 1;
            // Indent when items are on newlines (unless explicitly disabled)
            let should_indent = multiline && printer.config().indent_group_by_items;
            let leading_comma =
                printer.config().comma_style == crate::formatter::config::CommaStyle::Leading;

            if multiline {
                printer.newline_if_needed();
                if should_indent {
                    printer.indent_up();
                }
            } else {
                printer.push(" ");
            }

            // Track previous item end for comma search
            let mut prev_end: Option<u32> = None;
            for (i, item) in items.iter().enumerate() {
                let is_first = i == 0;

                if is_first && leading_comma && multiline && items.len() > 1 {
                    // First item with leading comma style: add padding to align with ", item" lines
                    let padding = if printer.config().space_after_comma {
                        2
                    } else {
                        1
                    };
                    printer.push_alignment_padding(padding);
                } else if let Some(prev) = prev_end {
                    // Not first item
                    let item_start = item.expr.span().start;
                    if leading_comma && multiline {
                        printer.newline_if_needed();
                        printer.push_comma_from_source(prev, item_start);
                        if printer.config().space_after_comma {
                            printer.space();
                        }
                    } else {
                        // Trailing comma style
                        printer.push_comma_from_source(prev, item_start);
                        if multiline {
                            printer.newline_if_needed();
                        } else if printer.config().space_after_comma {
                            printer.space();
                        }
                    }
                }
                format_expression(printer, &item.expr)?;
                prev_end = Some(item.expr.span().end);
            }

            if should_indent {
                printer.indent_down();
            }
        }
        AstGroupByVariant::Elements(elements) => {
            use crate::ast::AstGroupElementKind;
            printer.push(" ");
            for (i, element) in elements.iter().enumerate() {
                if i > 0 {
                    printer.push_comma();
                    if printer.config().space_after_comma {
                        printer.space();
                    }
                }
                match &element.kind {
                    AstGroupElementKind::Expr(item) => {
                        format_expression(printer, &item.expr)?;
                    }
                    AstGroupElementKind::Cube(items) => {
                        format_group_paren_op(printer, "CUBE", items)?;
                    }
                    AstGroupElementKind::Rollup(items) => {
                        format_group_paren_op(printer, "ROLLUP", items)?;
                    }
                    AstGroupElementKind::GroupingSets(sets) => {
                        format_group_grouping_sets(printer, sets)?;
                    }
                }
            }
        }
        AstGroupByVariant::JinjaPlaceholder(span) => {
            // Emit the Jinja placeholder as-is from source
            // No leading space needed - the caller handles this for JinjaPlaceholder
            printer.push_span(*span);
        }
    }

    // MySQL `WITH ROLLUP` / legacy T-SQL `WITH CUBE` suffix, byte-exact from source.
    if let Some(modifier_span) = group_by.with_modifier_span {
        printer.space();
        printer.push_span(modifier_span);
    }

    Ok(())
}

/// Format a `CUBE(...)` / `ROLLUP(...)` grouping operator, starting at the
/// keyword (no leading separator — the caller emits it).
fn format_group_paren_op(
    printer: &mut Printer,
    keyword: &str,
    items: &[crate::ast::AstGroupItem],
) -> Result<(), FormatterError> {
    printer.push_keyword(keyword);
    printer.push("(");
    let mut prev_end: Option<u32> = None;
    for item in items.iter() {
        if let Some(prev) = prev_end {
            printer.push_comma_from_source(prev, item.expr.span().start);
            if printer.config().space_after_comma {
                printer.space();
            }
        }
        format_expression(printer, &item.expr)?;
        prev_end = Some(item.expr.span().end);
    }
    printer.push(")");
    Ok(())
}

/// Format a `GROUPING SETS(...)` operator, starting at the keyword.
fn format_group_grouping_sets(
    printer: &mut Printer,
    sets: &[Vec<crate::ast::AstGroupItem>],
) -> Result<(), FormatterError> {
    printer.push_keyword("GROUPING SETS");
    printer.push("(");
    for (i, set) in sets.iter().enumerate() {
        if i > 0 {
            printer.push_comma();
            if printer.config().space_after_comma {
                printer.space();
            }
        }
        printer.push("(");
        let mut prev_end: Option<u32> = None;
        for item in set.iter() {
            if let Some(prev) = prev_end {
                printer.push_comma_from_source(prev, item.expr.span().start);
                if printer.config().space_after_comma {
                    printer.space();
                }
            }
            format_expression(printer, &item.expr)?;
            prev_end = Some(item.expr.span().end);
        }
        printer.push(")");
    }
    printer.push(")");
    Ok(())
}

fn format_having_clause_tracked(
    printer: &mut Printer,
    clause: &crate::ast::ConditionClause,
    after_pos: u32,
) -> Result<(), FormatterError> {
    printer.push_keyword_after("HAVING", after_pos);

    emit_prefix_inline_fragments(printer, &clause.prefix_inline_fragments);

    let expr = &clause.expr;
    // Check if expression is a Jinja conditional that needs indentation
    let is_jinja_conditional = matches!(expr, AstExpr::JinjaConditional { .. });
    let needs_indent = is_jinja_conditional && printer.config().jinja_indent_delimiters;

    if needs_indent {
        // For Jinja conditionals with indent enabled, add newline and indent
        printer.newline();
        printer.indent_up();
        format_expression(printer, expr)?;
        printer.indent_down();
    } else {
        // Regular HAVING
        printer.push(" ");
        format_expression(printer, expr)?;
    }

    emit_suffix_inline_fragments(printer, &clause.suffix_inline_fragments);
    Ok(())
}

fn format_qualify_clause_tracked(
    printer: &mut Printer,
    clause: &crate::ast::ConditionClause,
    after_pos: u32,
) -> Result<(), FormatterError> {
    printer.push_keyword_after("QUALIFY", after_pos);

    emit_prefix_inline_fragments(printer, &clause.prefix_inline_fragments);

    let expr = &clause.expr;
    // Check if expression is a Jinja conditional that needs indentation
    let is_jinja_conditional = matches!(expr, AstExpr::JinjaConditional { .. });
    let needs_indent = is_jinja_conditional && printer.config().jinja_indent_delimiters;

    if needs_indent {
        // For Jinja conditionals with indent enabled, add newline and indent
        printer.newline();
        printer.indent_up();
        format_expression(printer, expr)?;
        printer.indent_down();
    } else {
        // Regular QUALIFY
        printer.push(" ");
        format_expression(printer, expr)?;
    }

    emit_suffix_inline_fragments(printer, &clause.suffix_inline_fragments);
    Ok(())
}

/// Format CONNECT BY clause for hierarchical queries
/// Handles: START WITH <condition> CONNECT BY <conditions> [ORDER SIBLINGS BY ...]
fn format_connect_by_clause(
    printer: &mut Printer,
    connect_by: &crate::ast::AstConnectBy,
) -> Result<(), FormatterError> {
    // START WITH clause (optional)
    if let Some(start_with_span) = connect_by.start_with_span {
        printer.newline_if_needed();
        printer.emit_comments_before(start_with_span.start);
        printer.push_keyword("START");
        printer.push(" ");
        printer.push_keyword("WITH");
        printer.push(" ");

        // Format the START WITH condition
        if let Some(ref condition) = connect_by.start_with_condition {
            format_expression(printer, condition)?;
        }
    }

    // CONNECT BY clause
    printer.newline_if_needed();
    printer.emit_comments_before(connect_by.connect_by_span.start);
    printer.push_keyword("CONNECT");
    printer.push(" ");
    printer.push_keyword("BY");
    printer.push(" ");

    // Format CONNECT BY conditions (joined by AND in source)
    for (idx, condition) in connect_by.conditions.iter().enumerate() {
        if idx > 0 {
            printer.push(" ");
            printer.push_keyword("AND");
            printer.push(" ");
        }
        format_expression(printer, condition)?;
    }

    // ORDER SIBLINGS BY clause (optional)
    if let Some(ref order_siblings) = connect_by.order_siblings_by {
        printer.newline_if_needed();
        printer.push_keyword("ORDER");
        printer.push(" ");
        printer.push_keyword("SIBLINGS");
        printer.push(" ");
        printer.push_keyword("BY");
        format_order_by_body(printer, order_siblings)?;
    }

    Ok(())
}

pub(crate) fn format_order_by_clause_tracked(
    printer: &mut Printer,
    order_by: &AstOrderBy,
    after_pos: u32,
) -> Result<(), FormatterError> {
    printer.push_keyword_after("ORDER", after_pos);
    printer.push(" ");
    printer.push_keyword("BY");

    emit_prefix_inline_fragments(printer, &order_by.prefix_inline_fragments);
    format_order_by_body(printer, order_by)?;
    emit_suffix_inline_fragments(printer, &order_by.suffix_inline_fragments);
    Ok(())
}

fn format_order_by_body(
    printer: &mut Printer,
    order_by: &AstOrderBy,
) -> Result<(), FormatterError> {
    let multiline = printer.config().order_by_items_on_newlines && order_by.items.len() > 1;
    // Indent when items are on newlines (unless explicitly disabled)
    let should_indent = multiline && printer.config().indent_order_by_items;
    let leading_comma =
        printer.config().comma_style == crate::formatter::config::CommaStyle::Leading;

    if multiline {
        printer.newline();
        if should_indent {
            printer.indent_up();
        }
    } else {
        printer.push(" ");
    }

    let mut prev_item_end: Option<u32> = None;
    for (i, item) in order_by.items.iter().enumerate() {
        let is_first = i == 0;

        if is_first && leading_comma && multiline && order_by.items.len() > 1 {
            // First item with leading comma style: add padding to align with ", item" lines
            let padding = if printer.config().space_after_comma {
                2
            } else {
                1
            };
            printer.push_alignment_padding(padding);
        } else if i > 0 {
            // Not first item - emit comma
            if leading_comma && multiline {
                printer.newline_if_needed();
                if let Some(end_pos) = prev_item_end {
                    printer.push_comma_from_source(end_pos, item.span.start);
                } else {
                    printer.push_comma();
                }
                if printer.config().space_after_comma {
                    printer.space();
                }
            } else {
                // Trailing comma style
                if let Some(end_pos) = prev_item_end {
                    printer.push_comma_from_source(end_pos, item.span.start);
                } else {
                    printer.push_comma();
                }
                if multiline {
                    printer.newline_if_needed();
                } else if printer.config().space_after_comma {
                    printer.space();
                }
            }
        }

        // Format expression
        format_expression(printer, &item.expr)?;

        // Format ASC/DESC
        if let Some(asc) = item.asc {
            printer.push(" ");
            printer.push_keyword(if asc { "ASC" } else { "DESC" });
        }

        // Format NULLS FIRST/LAST
        if let Some(nulls_first) = item.nulls_first {
            printer.push(" ");
            printer.push_keyword("NULLS");
            printer.push(" ");
            printer.push_keyword(if nulls_first { "FIRST" } else { "LAST" });
        }

        prev_item_end = Some(item.span.end);
    }

    if should_indent {
        printer.indent_down();
    }

    Ok(())
}

/// Format WITHIN GROUP clause for ordered aggregate functions (LISTAGG, PERCENTILE_CONT, etc.)
/// Syntax: WITHIN GROUP (ORDER BY expr [ASC|DESC], ...)
fn format_within_group_clause(
    printer: &mut Printer,
    wg: &crate::ast::AstWithinGroup,
) -> Result<(), FormatterError> {
    printer.push(" ");
    printer.push_keyword_span(wg.within_span);
    printer.push(" ");
    printer.push_keyword_span(wg.group_span);
    printer.push(" (");
    printer.push_keyword("ORDER");
    printer.push(" ");
    printer.push_keyword("BY");
    printer.push(" ");

    // Format order by items
    for (i, item) in wg.order_by.iter().enumerate() {
        if i > 0 {
            printer.push_comma();
            if printer.config().space_after_comma {
                printer.space();
            }
        }

        // Format expression
        format_expression(printer, &item.expr)?;

        // Format ASC/DESC
        if let Some(asc) = item.asc {
            printer.push(" ");
            printer.push_keyword(if asc { "ASC" } else { "DESC" });
        }

        // Format NULLS FIRST/LAST
        if let Some(nulls_first) = item.nulls_first {
            printer.push(" ");
            printer.push_keyword("NULLS");
            printer.push(" ");
            printer.push_keyword(if nulls_first { "FIRST" } else { "LAST" });
        }
    }

    printer.push(")");
    Ok(())
}

fn format_filter_clause(
    printer: &mut Printer,
    fc: &crate::ast::AstFilterClause,
) -> Result<(), FormatterError> {
    // Emit entire FILTER (WHERE expr) as a span from source
    printer.push(" ");
    printer.push_span(fc.span);
    Ok(())
}

/// Emit the trailing LIMIT / OFFSET / FETCH of a query expression, handling
/// ANSI `OFFSET … FETCH`, MySQL `LIMIT off, cnt`, and Snowflake `LIMIT … OFFSET`
/// orderings. `prev_end` is the source position of the clause immediately
/// before LIMIT/OFFSET (ORDER BY end, or the query body end when absent), used
/// to locate the keyword in source. Shared by the SELECT and set-op formatters.
pub(crate) fn format_limit_offset_tail(
    printer: &mut Printer,
    limit: Option<&AstExpr>,
    offset: Option<&AstExpr>,
    limit_keyword_span: Option<crate::lexer::Span>,
    fetch_clause_span: Option<crate::lexer::Span>,
    offset_keyword_span: Option<crate::lexer::Span>,
    limit_offset_comma_span: Option<crate::lexer::Span>,
    prev_end: u32,
) -> Result<(), FormatterError> {
    // ANSI: OFFSET precedes FETCH. Snowflake: LIMIT precedes OFFSET.
    let is_ansi_offset_fetch = offset_keyword_span.is_some()
        && fetch_clause_span.is_some()
        && offset_keyword_span.map(|s| s.start) < fetch_clause_span.map(|s| s.start);

    if is_ansi_offset_fetch {
        if let Some(offset) = offset {
            printer.newline_if_needed();
            format_offset_clause_tracked(printer, offset, prev_end, offset_keyword_span)?;
        }
        if let Some(limit) = limit {
            printer.newline_if_needed();
            let search_after = offset.map(|e| e.span().end).unwrap_or(prev_end);
            format_limit_clause_tracked(printer, limit, search_after, fetch_clause_span)?;
        }
    } else if limit_offset_comma_span.is_some() {
        // MySQL `LIMIT offset, count` — re-emit the comma form in source order
        // (offset precedes count); never synthesize OFFSET.
        if let (Some(comma_span), Some(offset), Some(limit)) =
            (limit_offset_comma_span, offset, limit)
        {
            printer.newline_if_needed();
            if let Some(kw_span) = limit_keyword_span {
                printer.push_keyword_span(kw_span);
            } else {
                printer.push_keyword("LIMIT");
            }
            printer.push(" ");
            format_expression(printer, offset)?;
            printer.push_span(comma_span);
            printer.push(" ");
            format_expression(printer, limit)?;
        }
    } else {
        if let Some(limit) = limit {
            printer.newline_if_needed();
            format_limit_clause_tracked(printer, limit, prev_end, fetch_clause_span)?;
        }
        if let Some(offset) = offset {
            printer.newline_if_needed();
            let search_after = limit.map(|e| e.span().end).unwrap_or(prev_end);
            format_offset_clause_tracked(printer, offset, search_after, offset_keyword_span)?;
        }
    }
    Ok(())
}

pub(crate) fn format_limit_clause_tracked(
    printer: &mut Printer,
    expr: &AstExpr,
    after_pos: u32,
    fetch_clause_span: Option<crate::lexer::Span>,
) -> Result<(), FormatterError> {
    // If FETCH syntax was used (ANSI style), emit the original FETCH clause verbatim
    if let Some(span) = fetch_clause_span {
        printer.push_span(span);
        return Ok(());
    }

    // Otherwise, LIMIT syntax was used - emit LIMIT keyword and expression
    printer.push_keyword_after("LIMIT", after_pos);
    printer.push(" ");
    format_expression(printer, expr)?;
    Ok(())
}

pub(crate) fn format_offset_clause_tracked(
    printer: &mut Printer,
    expr: &AstExpr,
    after_pos: u32,
    offset_keyword_span: Option<crate::lexer::Span>,
) -> Result<(), FormatterError> {
    // If the OFFSET clause was captured as a raw Jinja block, emit it verbatim
    if let AstExpr::JinjaPlaceholder {
        span,
        kind: crate::ast::JinjaKind::Statement,
        ..
    } = expr
    {
        printer.push_span(*span);
        return Ok(());
    }

    // If we have the original OFFSET...ROW/ROWS span (ANSI syntax), use it for the keyword portion
    if let Some(span) = offset_keyword_span {
        // Emit the entire "OFFSET <expr> [ROW|ROWS]" span verbatim
        printer.push_span(span);
        return Ok(());
    }

    // Otherwise, emit synthesized OFFSET keyword (Snowflake LIMIT...OFFSET syntax)
    printer.push_keyword_after("OFFSET", after_pos);
    printer.push(" ");
    format_expression(printer, expr)?;
    Ok(())
}

/// Format an identifier with configured case transformation
fn format_identifier(
    printer: &mut Printer,
    ident: &crate::ast::AstIdentifier,
) -> Result<(), FormatterError> {
    // push_identifier_span_v2 handles trivia and identifier case formatting
    printer.push_identifier_span_v2(ident.span);
    Ok(())
}

/// Format an object reference (table/schema name) with configured case transformation
fn format_object_ref(
    printer: &mut Printer,
    obj: &crate::ast::AstObjectRef,
) -> Result<(), FormatterError> {
    // push_identifier_span_v2 handles trivia and identifier case formatting
    printer.push_identifier_span_v2(obj.span);
    Ok(())
}

pub fn format_expression(printer: &mut Printer, expr: &AstExpr) -> Result<(), FormatterError> {
    with_recursion_guard!(printer, "expression", {
        // Leading trivia is handled by push_span/push_keyword_span/push_identifier_span centrally
        // No manual emission needed here

        match expr {
        AstExpr::Literal{ literal: lit, .. } => {
            // Use push_span to preserve trivia on literals
            printer.push_span(lit.span());
            Ok(())
        }

        AstExpr::Ident{ column_ref: col_ref, .. } => {
            // Format column reference: [qualifier.]column_name
            if let Some(ref qualifier) = col_ref.qualifier {
                format_object_ref(printer, qualifier)?;
                // Explicitly emit the dot - emit_all_tokens_until may fail if source_position
                // has advanced past this point due to prior expression formatting
                printer.push(".");
            }
            format_identifier(printer, &col_ref.name)?;
            Ok(())
        }

        AstExpr::Placeholder { span , ..} => {
            // Preserve placeholder exactly as-is
            printer.push_span(*span);
            Ok(())
        }

        AstExpr::JinjaPlaceholder { span, syntax_id, .. } => {
            // Use CST tokens when available for proper trivia emission
            if let Some(interp_id) = syntax_id {
                printer.format_jinja_interpolation(*interp_id)?;
                // Emit any tokens after the interpolation but still within the span
                // This handles concatenated identifiers like {{ prefix }}column_name
                printer.emit_all_tokens_until(span.end);
                Ok(())
            } else {
                // Fallback: Preserve Jinja exactly as-is
                printer.push_span(*span);
                Ok(())
            }
        }

        AstExpr::PositionRef {
            qualifier,
            dot_span,
            dollar_span,
            index_span,
            ..
        } => {
            // Handle qualified position refs: src.$1
            if let Some(qual) = qualifier {
                printer.push_span(qual.span);
                if let Some(dot) = dot_span {
                    printer.push_span(*dot);
                }
            }
            // Dollar sign (may be empty for implicit $ in GROUP BY: "1" instead of "$1")
            if dollar_span.start < dollar_span.end {
                printer.push_span(*dollar_span);
            }
            // Index part - use push_span to preserve trailing trivia
            printer.push_span(*index_span);
            Ok(())
        }

        AstExpr::InList {
            syntax_id,
            expr,
            list,
            ..
        } => {
            // Format: <expr> [NOT] IN (item1, item2, ...)
            format_expression(printer, expr)?;

            let syntax_in = printer
                .get_in_list(*syntax_id)
                .ok_or_else(|| FormatterError::MissingSyntaxNode("SyntaxInList".to_string()))?;

            if let Some(not_kw) = syntax_in.not_keyword {
                printer.push(" ");
                printer.push_keyword_token_id(not_kw);
            }

            printer.push(" ");
            printer.push_keyword_token_id(syntax_in.in_keyword);

            // Determine if we should format multiline
            // items_per_line = 0 means inline, N > 0 means multiline with N items per line
            let item_count = list.len();
            let items_per_line = printer.config().in_list_items_per_line;
            let threshold = printer.config().in_list_threshold;
            let should_multiline = items_per_line > 0 && item_count >= threshold;

            if should_multiline {
                // Multiline format
                let leading_comma = printer.config().comma_style == crate::formatter::config::CommaStyle::Leading;
                let items_per_line = printer.config().in_list_items_per_line.max(1);

                // Emit leading trivia for open paren via push_token_id
                printer.push(" ");
                printer.push_token_id(syntax_in.l_paren);
                printer.newline();
                printer.indent_up();

                for (i, item) in list.iter().enumerate() {
                    // First item: add alignment padding for leading comma style (only if starting a new line)
                    if i == 0 && leading_comma && item_count > 1 {
                        let padding = if printer.config().space_after_comma { 2 } else { 1 };
                        printer.push_alignment_padding(padding);
                    } else if i > 0 {
                        // Check if we should start a new line
                        let start_new_line = i % items_per_line == 0;

                        if leading_comma && start_new_line {
                            // Leading comma style on new line: newline then comma
                            printer.newline();
                            printer.push_comma();
                            if printer.config().space_after_comma {
                                printer.space();
                            }
                        } else {
                            // Trailing comma style or same line continuation
                            printer.push_comma();
                            if start_new_line {
                                printer.newline();
                            } else if printer.config().space_after_comma {
                                printer.space();
                            }
                        }
                    }
                    format_expression(printer, item)?;
                }

                printer.indent_down();
                printer.newline();
                // Emit trivia before close paren, then the paren itself, then trailing trivia
                printer.push_token_id(syntax_in.r_paren);
            } else {
                // Inline format
                printer.push(" ");
                printer.push_token_id(syntax_in.l_paren);

                for (i, item) in list.iter().enumerate() {
                    if i > 0 {
                        printer.push_comma();
                        if printer.config().space_after_comma {
                            printer.space();
                        }
                    }
                    format_expression(printer, item)?;
                }

                // Emit trivia before close paren, then the paren itself, then trailing trivia
                printer.push_token_id(syntax_in.r_paren);
            }

            Ok(())
        }

        AstExpr::InListOpaque {
            expr,
            not_span,
            in_span,
            list_span,
            ..
        } => {
            // IN list with Jinja - preserve list as-is
            format_expression(printer, expr)?;

            if not_span.is_some() {
                printer.push(" ");
                printer.push_keyword("NOT");
            }

            printer.push(" ");
            let in_text = printer.extract_span(*in_span).to_string();
            printer.push_keyword(&in_text);
            printer.push(" ");

            printer.push_span(*list_span);
            Ok(())
        }

        AstExpr::ExplSnowIdent { ident_span, arg, .. } => {
            // Emit IDENTIFIER(...) using span for the keyword
            printer.push_span(*ident_span);
            printer.push("(");
            format_expression(printer, arg)?;
            printer.push(")");
            Ok(())
        }

        AstExpr::BinaryOp {
            left,
            operator,
            syntax_id,
            right,
            ..
        } => {
            use crate::ast::BinaryOperator;
            // Special case: NOT operator is represented as BinaryOp with Boolean literal on left
            let is_not_operator = matches!(operator, BinaryOperator::Not) &&
                matches!(left.as_ref(), AstExpr::Literal{ literal: crate::ast::AstLiteral::Boolean { .. }, .. });

            if is_not_operator {
                // Format as unary NOT - get operator token for trivia
                if let Some(syntax) = printer.get_binary_op(*syntax_id) {
                    printer.push_token_id(syntax.op_token);
                } else {
                    printer.push_keyword("not");
                }
                printer.push(" ");
                format_expression(printer, right)?;
            } else {
                // Normal binary operator - format left, operator, right
                format_expression(printer, left)?;

                // Determine if operator is a keyword
                let is_keyword_op = matches!(
                    operator,
                    BinaryOperator::And | BinaryOperator::Or | BinaryOperator::Not |
                    BinaryOperator::Like | BinaryOperator::ILike | BinaryOperator::RLike
                );

                // Apply spacing before operator
                if printer.config().spaces_around_operators {
                    printer.push(" ");
                }

                // Emit operator token with trivia
                if let Some(syntax) = printer.get_binary_op(*syntax_id) {
                    printer.push_token_id(syntax.op_token);
                } else {
                    // Fallback: reconstruct operator text (should not happen)
                    let op_str = match operator {
                        BinaryOperator::Plus => "+",
                        BinaryOperator::Minus => "-",
                        BinaryOperator::Multiply => "*",
                        BinaryOperator::Divide => "/",
                        BinaryOperator::Modulo => "%",
                        BinaryOperator::Equal => "=",
                        BinaryOperator::NotEqual => "!=",
                        BinaryOperator::LessThan => "<",
                        BinaryOperator::LessThanOrEqual => "<=",
                        BinaryOperator::GreaterThan => ">",
                        BinaryOperator::GreaterThanOrEqual => ">=",
                        BinaryOperator::NullSafeEqual => "<=>",
                        BinaryOperator::And => "AND",
                        BinaryOperator::Or => "OR",
                        BinaryOperator::LogicalOr => "||",
                        BinaryOperator::Not => "NOT",
                        BinaryOperator::Concat => "||",
                        BinaryOperator::Like => "LIKE",
                        BinaryOperator::ILike => "ILIKE",
                        BinaryOperator::RLike => "RLIKE",
                        BinaryOperator::Distance => "<->",
                        // PostgreSQL array operators
                        BinaryOperator::ArrayContains => "@>",
                        BinaryOperator::ArrayContainedBy => "<@",
                        BinaryOperator::ArrayOverlap => "&&",
                        // PostgreSQL JSON operators
                        BinaryOperator::JsonField => "->",
                        BinaryOperator::JsonFieldText => "->>",
                        BinaryOperator::JsonPath => "#>",
                        BinaryOperator::JsonPathText => "#>>",
                        BinaryOperator::JsonContains => "@?",
                        BinaryOperator::JsonExists => "??",
                        // PostgreSQL regex operators
                        BinaryOperator::RegexMatch => "~",
                        BinaryOperator::RegexMatchI => "~*",
                        BinaryOperator::RegexNotMatch => "!~",
                        BinaryOperator::RegexNotMatchI => "!~*",
                        // Bitwise operators
                        BinaryOperator::LeftShift => "<<",
                        BinaryOperator::RightShift => ">>",
                        BinaryOperator::BitwiseXor => "^",
                        BinaryOperator::BitwiseXorPg => "#",
                    };
                    if is_keyword_op {
                        printer.push_keyword(op_str);
                    } else {
                        printer.push(op_str);
                    }
                }

                // Apply spacing after operator
                if printer.config().spaces_around_operators {
                    printer.push(" ");
                }

                // Recursively format right operand
                format_expression(printer, right)?;
            }

            Ok(())
        }

        // Flattened logical chain (OR/AND) - iterate operands without deep recursion
        AstExpr::LogicalChain {
            operator,
            operands,
            operator_syntax_ids,
            ..
        } => {
            use crate::ast::LogicalChainOperator;
            let op_str = match operator {
                LogicalChainOperator::Or => "OR",
                LogicalChainOperator::And => "AND",
            };
            for (i, operand) in operands.iter().enumerate() {
                if i > 0 {
                    // Add spacing before operator
                    if printer.config().spaces_around_operators {
                        printer.push(" ");
                    }
                    // Emit operator token with trivia if available
                    if i - 1 < operator_syntax_ids.len() {
                        if let Some(syntax) = printer.get_binary_op(operator_syntax_ids[i - 1]) {
                            printer.push_token_id(syntax.op_token);
                        } else {
                            printer.push_keyword(op_str);
                        }
                    } else {
                        printer.push_keyword(op_str);
                    }
                    // Add spacing after operator
                    if printer.config().spaces_around_operators {
                        printer.push(" ");
                    }
                }
                format_expression(printer, operand)?;
            }
            Ok(())
        }

        AstExpr::Case {
            syntax_id,
            operand,
            whens,
            else_expr,
            span,
            ..
        } => {
            // Get CASE keyword span from syntax node for proper trivia handling
            let case_span = if let Some(syntax) = printer.get_case_expr(*syntax_id) {
                // Use the CASE keyword token span for trivia-aware formatting
                if let Some(token) = printer.get_token_by_id(syntax.case_keyword) {
                    token.span
                } else {
                    // Fallback: use expression span start
                    Span { start: span.start, end: span.start + 4 }
                }
            } else {
                // Fallback if syntax not available
                Span { start: span.start, end: span.start + 4 }
            };
            format_case_expression(
                printer,
                case_span,
                operand.as_deref(),
                whens,
                else_expr.as_deref(),
            )
        }

        AstExpr::InSubquery {
            syntax_id,
            expr,
            subquery,
            ..
        } => {
            // Format left expression
            format_expression(printer, expr)?;

            // Get syntax node for structural tokens
            let syntax_in = printer
                .get_in_subquery(*syntax_id)
                .ok_or_else(|| FormatterError::MissingSyntaxNode("SyntaxInSubquery".to_string()))?;

            // Format NOT if present
            if let Some(not_token_id) = syntax_in.not_keyword {
                printer.push(" ");
                printer.push_keyword_token_id(not_token_id);
            }

            // Format IN keyword
            printer.push(" ");
            printer.push_keyword_token_id(syntax_in.in_keyword);
            printer.push(" ");

            // Get lparen and rparen spans from CST for trivia preservation
            let lparen_span = printer.get_token_by_id(syntax_in.l_paren).map(|t| t.span);
            let rparen_span = printer.get_token_by_id(syntax_in.r_paren).map(|t| t.span);

            // Format subquery with parens (passing spans to preserve trivia)
            format_subquery_with_spans(printer, subquery, lparen_span, rparen_span)?;

            Ok(())
        }

        AstExpr::ExistsSubquery {
            syntax_id,
            subquery,
            ..
        } => {
            // Get syntax node for structural tokens
            let syntax_exists = printer
                .get_exists_subquery(*syntax_id)
                .ok_or_else(|| FormatterError::MissingSyntaxNode("SyntaxExistsSubquery".to_string()))?;

            // Format NOT if present
            if let Some(not_token_id) = syntax_exists.not_keyword {
                printer.push_keyword_token_id(not_token_id);
                printer.push(" ");
            }

            // Format EXISTS keyword
            printer.push_keyword_token_id(syntax_exists.exists_keyword);
            printer.push(" ");

            // Get the lparen and rparen tokens to access their trivia
            let lparen_token = printer.get_token_by_id(syntax_exists.lparen);
            let rparen_token = printer.get_token_by_id(syntax_exists.rparen);
            let lparen_span = lparen_token.map(|t| t.span);
            let rparen_span = rparen_token.map(|t| t.span);

            // Format subquery with proper paren token emission for trivia preservation
            format_subquery_with_spans(printer, subquery, lparen_span, rparen_span)?;
            Ok(())
        }

        AstExpr::Spread { stars_span, expr, .. } => {
            // Trivia is handled centrally by push_span
            printer.push_span(*stars_span);
            format_expression(printer, expr)?;
            Ok(())
        }

        AstExpr::Array { elements, has_array_keyword, array_keyword_span, .. } => {
            if *has_array_keyword {
                if let Some(kw_span) = array_keyword_span {
                    // Emit from source to preserve ARRAY<type> annotation
                    printer.push_span(*kw_span);
                } else {
                    printer.push_keyword("ARRAY");
                }
            }
            printer.push("[");
            for (i, elem) in elements.iter().enumerate() {
                if i > 0 {
                    printer.push_comma();
                    if printer.config().space_after_comma {
                        printer.space();
                    }
                }
                format_expression(printer, elem)?;
            }
            printer.push("]");
            Ok(())
        }

        AstExpr::Object { entries, .. } => {
            printer.push("{");
            for (i, (key, value)) in entries.iter().enumerate() {
                if i > 0 {
                    printer.push_comma();
                    if printer.config().space_after_comma {
                        printer.space();
                    }
                }
                format_expression(printer, key)?;
                printer.push(":");
                if printer.config().space_after_comma {
                    printer.space();
                }
                format_expression(printer, value)?;
            }
            printer.push("}");
            Ok(())
        }

        AstExpr::WindowFn {
            func_name,
            approximate,
            lparen_span,
            quantifier,
            args,
            rparen_span,
            within_group,
            filter,
            window,
            ..
        } => {
            // Redshift `APPROXIMATE` modifier precedes the (windowed) function name.
            if let Some(approx_span) = approximate {
                printer.push_keyword_span(*approx_span);
                printer.push(" ");
            }
            // Function name
            format_identifier(printer, func_name)?;
            printer.push_span(*lparen_span);

            // Optional DISTINCT/ALL - use span for trivia
            if let Some((_quant, quant_span)) = quantifier {
                printer.push_keyword_span(*quant_span);
                if !args.is_empty() {
                    printer.push(" ");
                }
            }

            // Arguments
            for (i, arg) in args.iter().enumerate() {
                if i > 0 {
                    printer.push_comma();
                    if printer.config().space_after_comma {
                        printer.space();
                    }
                }
                format_function_arg(printer, arg)?;
            }

            // Use rparen_span to preserve trailing trivia (e.g., /* after agg */)
            printer.push_span(*rparen_span);

            // WITHIN GROUP clause
            if let Some(ref wg) = within_group {
                format_within_group_clause(printer, wg)?;
            }

            // FILTER (WHERE ...) clause
            if let Some(ref fc) = filter {
                format_filter_clause(printer, fc)?;
            }

            // OVER clause - use syntax layer for token access
            // The SyntaxOverClause owns the OVER keyword, parens, and clause keywords
            let syntax_over = printer.get_over_clause(window.syntax_id)
                .ok_or_else(|| FormatterError::MissingSyntaxNode("SyntaxOverClause".to_string()))?;
            // IGNORE NULLS / RESPECT NULLS clause (from CST)
            if let Some(null_handling_kw) = syntax_over.null_handling_keyword {
                printer.push(" ");
                printer.push_keyword_token_id(null_handling_kw);
                if let Some(nulls_kw) = syntax_over.nulls_keyword {
                    printer.push(" ");
                    printer.push_keyword_token_id(nulls_kw);
                }
            }
            // Emit OVER keyword (present for all OVER clauses, absent for WINDOW defs)
            if let Some(over_kw) = syntax_over.over_keyword {
                printer.push(" ");
                printer.push_keyword_token_id(over_kw);
            }

            // Check if this is a bare window reference: OVER w (no parens)
            if syntax_over.l_paren.is_none() {
                // Bare reference: just emit the window name
                if let Some(name_span) = window.existing_window_name {
                    printer.push(" ");
                    printer.push_span(name_span);
                }
                return Ok(());
            }

            printer.push(" ");
            // Emit opening paren with trivia
            printer.push_token_id(syntax_over.l_paren.unwrap());

            // Emit existing window name reference if present: OVER (w ORDER BY ...)
            if let Some(name_span) = window.existing_window_name {
                printer.push_span(name_span);
                // Add space before any following clauses
                let has_more = !window.partition_by.is_empty()
                    || !window.order_by.is_empty()
                    || window.frame.is_some();
                if has_more {
                    printer.push(" ");
                }
            }

            // Check if window clauses should be on newlines
            let has_content = !window.partition_by.is_empty()
                || !window.order_by.is_empty()
                || window.frame.is_some();
            let should_expand = has_content
                && (printer.config().partition_by_on_newline
                    || printer.config().order_by_in_window_on_newline);

            if should_expand && printer.config().indent_window_function_clauses {
                printer.newline();
                printer.indent_up();
            }

            format_window_spec(printer, window)?;

            if should_expand && printer.config().indent_window_function_clauses {
                printer.indent_down();
                printer.newline();
            }

            // Emit closing paren with trivia
            printer.push_token_id(syntax_over.r_paren.unwrap());

            Ok(())
        }

        AstExpr::WindowExpr {
            base,
            window,
            ..
        } => {
            // Format the base expression (e.g., APPROX_QUANTILES(val, 100)[OFFSET(50)])
            format_expression(printer, base)?;

            // Format the OVER clause using the syntax layer
            let syntax_over = printer.get_over_clause(window.syntax_id)
                .ok_or_else(|| FormatterError::MissingSyntaxNode("SyntaxOverClause for WindowExpr".to_string()))?;

            // Emit OVER keyword
            if let Some(over_kw) = syntax_over.over_keyword {
                printer.push(" ");
                printer.push_keyword_token_id(over_kw);
            }

            // Check if this is a bare window reference: OVER w (no parens)
            if syntax_over.l_paren.is_none() {
                if let Some(name_span) = window.existing_window_name {
                    printer.push(" ");
                    printer.push_span(name_span);
                }
                return Ok(());
            }

            printer.push(" ");
            printer.push_token_id(syntax_over.l_paren.unwrap());

            // Emit existing window name reference if present
            if let Some(name_span) = window.existing_window_name {
                printer.push_span(name_span);
                let has_more = !window.partition_by.is_empty()
                    || !window.order_by.is_empty()
                    || window.frame.is_some();
                if has_more {
                    printer.push(" ");
                }
            }

            let has_content = !window.partition_by.is_empty()
                || !window.order_by.is_empty()
                || window.frame.is_some();
            let should_expand = has_content
                && (printer.config().partition_by_on_newline
                    || printer.config().order_by_in_window_on_newline);

            if should_expand && printer.config().indent_window_function_clauses {
                printer.newline();
                printer.indent_up();
            }

            format_window_spec(printer, window)?;

            if should_expand && printer.config().indent_window_function_clauses {
                printer.indent_down();
                printer.newline();
            }

            printer.push_token_id(syntax_over.r_paren.unwrap());

            Ok(())
        }

        AstExpr::TvfWithSchema {
            func_call,
            with_schema_span,
            ..
        } => {
            format_expression(printer, func_call)?;
            printer.push(" ");
            printer.push_span(*with_schema_span);
            Ok(())
        }

        AstExpr::QuantifiedSubquery {
            left,
            operator,
            syntax_id,
            quantifier: _,
            subquery,
            ..
        } => {
            use crate::ast::BinaryOperator;
            format_expression(printer, left)?;

            printer.push(" ");
            // Emit operator token with trivia
            if let Some(syntax) = printer.get_quantified_subquery(*syntax_id) {
                printer.push_token_id(syntax.op_token);
            } else {
                // Fallback: reconstruct operator text
                let op_str = match operator {
                    BinaryOperator::Equal => "=",
                    BinaryOperator::NotEqual => "!=",
                    BinaryOperator::LessThan => "<",
                    BinaryOperator::LessThanOrEqual => "<=",
                    BinaryOperator::GreaterThan => ">",
                    BinaryOperator::GreaterThanOrEqual => ">=",
                    _ => "=", // Default to equality for other ops
                };
                printer.push(op_str);
            }
            printer.push(" ");

            // Emit quantifier keyword with trivia
            if let Some(syntax) = printer.get_quantified_subquery(*syntax_id) {
                printer.push_keyword_token_id(syntax.quantifier_keyword);
            } else {
                // Fallback based on AstQuantifier enum
                printer.push_keyword("ANY"); // or ALL - we don't have access to quantifier here
            }
            printer.push(" ");

            format_subquery(printer, subquery)?;
            Ok(())
        }

        AstExpr::ScriptingVarRef {
            syntax_id,
            name_span,
            ..
        } => {
            // Get syntax node for colon token
            let syntax_var = printer
                .get_scripting_var(*syntax_id)
                .ok_or_else(|| FormatterError::MissingSyntaxNode("SyntaxScriptingVarRef".to_string()))?;

            // Emit colon token via syntax layer
            printer.push_token_id(syntax_var.colon);
            // Emit variable name
            printer.push_span(*name_span);
            Ok(())
        }

        AstExpr::QualifiedStar {
            qualifier,
            star_span,
            exclude,
            replace,
            rename,
            ..
        } => {
            // Format qualifier and star separately to avoid emitting modifiers twice
            format_object_ref(printer, qualifier)?;
            printer.push(".");
            printer.push_span(*star_span);

            // Format EXCLUDE modifier
            if let Some(excl) = exclude {
                printer.push(" ");
                if let Some(syntax_id) = excl.syntax_id {
                    let syntax_node_opt = printer.get_exclude(syntax_id);
                    if let Some(syntax_node) = syntax_node_opt {
                        printer.push_token_id(syntax_node.exclude_keyword);
                        if let Some(lparen) = syntax_node.lparen {
                            printer.push(" ");
                            printer.push_token_id(lparen);
                        } else {
                            printer.push(" ");
                        }
                        for (idx, col) in excl.columns.iter().enumerate() {
                            if idx > 0 {
                                let col_start = col.qualifier.as_ref()
                                    .map(|q| q.span.start)
                                    .unwrap_or(col.name.span.start);
                                printer.emit_all_tokens_until(col_start);
                            }
                            if let Some(ref qualifier) = col.qualifier {
                                format_object_ref(printer, qualifier)?;
                                printer.emit_all_tokens_until(col.name.span.start);
                            }
                            format_identifier(printer, &col.name)?;
                        }
                        if let Some(rparen) = syntax_node.rparen {
                            printer.push_token_id(rparen);
                        }
                    } else {
                        printer.push_keyword_span(excl.exclude_span);
                        if excl.has_parens {
                            printer.push(" (");
                        } else {
                            printer.push(" ");
                        }
                        for (i, col) in excl.columns.iter().enumerate() {
                            if i > 0 {
                                printer.push(", ");
                            }
                            if let Some(ref qualifier) = col.qualifier {
                                format_object_ref(printer, qualifier)?;
                                printer.emit_all_tokens_until(col.name.span.start);
                            }
                            format_identifier(printer, &col.name)?;
                        }
                        if excl.has_parens {
                            printer.push(")");
                        }
                    }
                } else {
                    printer.push_keyword_span(excl.exclude_span);
                    if excl.has_parens {
                        printer.push(" (");
                    } else {
                        printer.push(" ");
                    }
                    for (i, col) in excl.columns.iter().enumerate() {
                        if i > 0 {
                            printer.push(", ");
                        }
                        if let Some(ref qualifier) = col.qualifier {
                            format_object_ref(printer, qualifier)?;
                            printer.emit_all_tokens_until(col.name.span.start);
                        }
                        format_identifier(printer, &col.name)?;
                    }
                    if excl.has_parens {
                        printer.push(")");
                    }
                }
            }

            // Format REPLACE modifier
            if let Some(repl) = replace {
                printer.push(" ");
                if let Some(syntax_id) = repl.syntax_id {
                    if let Some(syntax_node) = printer.get_replace(syntax_id) {
                        printer.push_token_id(syntax_node.replace_keyword);
                        printer.push(" ");
                        printer.push_token_id(syntax_node.lparen);
                        for (idx, item) in repl.items.iter().enumerate() {
                            if idx > 0 {
                                printer.emit_all_tokens_until(item.expr.span().start);
                            }
                            format_expression(printer, &item.expr)?;
                            printer.push(" ");
                            printer.push_keyword_span(item.as_span);
                            printer.push(" ");
                            if let Some(ref qualifier) = item.column.qualifier {
                                format_object_ref(printer, qualifier)?;
                                printer.emit_all_tokens_until(item.column.name.span.start);
                            }
                            format_identifier(printer, &item.column.name)?;
                        }
                        printer.push_token_id(syntax_node.rparen);
                    } else {
                        printer.push_keyword_span(repl.replace_span);
                        printer.push(" (");
                        for (i, item) in repl.items.iter().enumerate() {
                            if i > 0 {
                                printer.push(", ");
                            }
                            format_expression(printer, &item.expr)?;
                            printer.push(" ");
                            printer.push_keyword("AS");
                            printer.push(" ");
                            if let Some(ref qualifier) = item.column.qualifier {
                                format_object_ref(printer, qualifier)?;
                                printer.emit_all_tokens_until(item.column.name.span.start);
                            }
                            format_identifier(printer, &item.column.name)?;
                        }
                        printer.push(")");
                    }
                } else {
                    printer.push_keyword_span(repl.replace_span);
                    printer.push(" (");
                    for (i, item) in repl.items.iter().enumerate() {
                        if i > 0 {
                            printer.push(", ");
                        }
                        format_expression(printer, &item.expr)?;
                        printer.push(" ");
                        printer.push_keyword("AS");
                        printer.push(" ");
                        if let Some(ref qualifier) = item.column.qualifier {
                            format_object_ref(printer, qualifier)?;
                            printer.emit_all_tokens_until(item.column.name.span.start);
                        }
                        format_identifier(printer, &item.column.name)?;
                    }
                    printer.push(")");
                }
            }

            // Format RENAME modifier
            if let Some(ren) = rename {
                printer.push(" ");
                if let Some(syntax_id) = ren.syntax_id {
                    if let Some(syntax_node) = printer.get_rename(syntax_id) {
                        printer.push_token_id(syntax_node.rename_keyword);
                        if let Some(lparen) = syntax_node.lparen {
                            printer.push(" ");
                            printer.push_token_id(lparen);
                        } else {
                            printer.push(" ");
                        }
                        for (idx, item) in ren.items.iter().enumerate() {
                            if idx > 0 {
                                let item_start = item.column.qualifier.as_ref()
                                    .map(|q| q.span.start)
                                    .unwrap_or(item.column.name.span.start);
                                printer.emit_all_tokens_until(item_start);
                            }
                            if let Some(ref qualifier) = item.column.qualifier {
                                format_object_ref(printer, qualifier)?;
                                printer.emit_all_tokens_until(item.column.name.span.start);
                            }
                            format_identifier(printer, &item.column.name)?;
                            if let Some(as_span) = item.as_span {
                                printer.push(" ");
                                printer.push_keyword_span(as_span);
                            }
                            printer.push(" ");
                            format_identifier(printer, &item.alias)?;
                        }
                        if let Some(rparen) = syntax_node.rparen {
                            printer.push_token_id(rparen);
                        }
                    } else {
                        printer.push_keyword_span(ren.rename_span);
                        if ren.has_parens {
                            printer.push(" (");
                        } else {
                            printer.push(" ");
                        }
                        for (i, item) in ren.items.iter().enumerate() {
                            if i > 0 {
                                printer.push(", ");
                            }
                            if let Some(ref qualifier) = item.column.qualifier {
                                format_object_ref(printer, qualifier)?;
                                printer.emit_all_tokens_until(item.column.name.span.start);
                            }
                            format_identifier(printer, &item.column.name)?;
                            printer.push(" ");
                            printer.push_keyword("AS");
                            printer.push(" ");
                            format_identifier(printer, &item.alias)?;
                        }
                        if ren.has_parens {
                            printer.push(")");
                        }
                    }
                } else {
                    printer.push_keyword_span(ren.rename_span);
                    if ren.has_parens {
                        printer.push(" (");
                    } else {
                        printer.push(" ");
                    }
                    for (i, item) in ren.items.iter().enumerate() {
                        if i > 0 {
                            printer.push(", ");
                        }
                        if let Some(ref qualifier) = item.column.qualifier {
                            format_object_ref(printer, qualifier)?;
                            printer.emit_all_tokens_until(item.column.name.span.start);
                        }
                        format_identifier(printer, &item.column.name)?;
                        printer.push(" ");
                        printer.push_keyword("AS");
                        printer.push(" ");
                        format_identifier(printer, &item.alias)?;
                    }
                    if ren.has_parens {
                        printer.push(")");
                    }
                }
            }

            Ok(())
        }

        AstExpr::UnqualifiedStar {
            star_span,
            exclude,
            replace,
            rename,
            ..
        } => {
            // Emit the star token with its trivia
            printer.push_span(*star_span);

            // Format EXCLUDE modifier
            if let Some(excl) = exclude {
                printer.push(" ");
                if let Some(syntax_id) = excl.syntax_id {
                    let syntax_node_opt = printer.get_exclude(syntax_id);
                    if let Some(syntax_node) = syntax_node_opt {
                        printer.push_token_id(syntax_node.exclude_keyword);
                        if let Some(lparen) = syntax_node.lparen {
                            printer.push(" ");
                            printer.push_token_id(lparen);
                        } else {
                            printer.push(" ");
                        }
                        for (idx, col) in excl.columns.iter().enumerate() {
                            if idx > 0 {
                                let col_start = col.qualifier.as_ref()
                                    .map(|q| q.span.start)
                                    .unwrap_or(col.name.span.start);
                                printer.emit_all_tokens_until(col_start);
                            }
                            if let Some(ref qualifier) = col.qualifier {
                                format_object_ref(printer, qualifier)?;
                                printer.emit_all_tokens_until(col.name.span.start);
                            }
                            format_identifier(printer, &col.name)?;
                        }
                        if let Some(rparen) = syntax_node.rparen {
                            printer.push_token_id(rparen);
                        }
                    } else {
                        printer.push_keyword_span(excl.exclude_span);
                        if excl.has_parens {
                            printer.push(" (");
                        } else {
                            printer.push(" ");
                        }
                        for (i, col) in excl.columns.iter().enumerate() {
                            if i > 0 {
                                printer.push(", ");
                            }
                            if let Some(ref qualifier) = col.qualifier {
                                format_object_ref(printer, qualifier)?;
                                printer.emit_all_tokens_until(col.name.span.start);
                            }
                            format_identifier(printer, &col.name)?;
                        }
                        if excl.has_parens {
                            printer.push(")");
                        }
                    }
                } else {
                    printer.push_keyword_span(excl.exclude_span);
                    if excl.has_parens {
                        printer.push(" (");
                    } else {
                        printer.push(" ");
                    }
                    for (i, col) in excl.columns.iter().enumerate() {
                        if i > 0 {
                            printer.push(", ");
                        }
                        if let Some(ref qualifier) = col.qualifier {
                            format_object_ref(printer, qualifier)?;
                            printer.emit_all_tokens_until(col.name.span.start);
                        }
                        format_identifier(printer, &col.name)?;
                    }
                    if excl.has_parens {
                        printer.push(")");
                    }
                }
            }

            // Format REPLACE modifier
            if let Some(repl) = replace {
                printer.push(" ");
                if let Some(syntax_id) = repl.syntax_id {
                    if let Some(syntax_node) = printer.get_replace(syntax_id) {
                        printer.push_token_id(syntax_node.replace_keyword);
                        printer.push(" ");
                        printer.push_token_id(syntax_node.lparen);
                        for (idx, item) in repl.items.iter().enumerate() {
                            if idx > 0 {
                                printer.emit_all_tokens_until(item.expr.span().start);
                            }
                            format_expression(printer, &item.expr)?;
                            printer.push(" ");
                            printer.push_keyword("AS");
                            printer.push(" ");
                            if let Some(ref qualifier) = item.column.qualifier {
                                format_object_ref(printer, qualifier)?;
                                printer.emit_all_tokens_until(item.column.name.span.start);
                            }
                            format_identifier(printer, &item.column.name)?;
                        }
                        printer.push_token_id(syntax_node.rparen);
                    } else {
                        printer.push_keyword_span(repl.replace_span);
                        printer.push(" (");
                        for (i, item) in repl.items.iter().enumerate() {
                            if i > 0 {
                                printer.push(", ");
                            }
                            format_expression(printer, &item.expr)?;
                            printer.push(" ");
                            printer.push_keyword("AS");
                            printer.push(" ");
                            if let Some(ref qualifier) = item.column.qualifier {
                                format_object_ref(printer, qualifier)?;
                                printer.emit_all_tokens_until(item.column.name.span.start);
                            }
                            format_identifier(printer, &item.column.name)?;
                        }
                        printer.push(")");
                    }
                } else {
                    printer.push_keyword_span(repl.replace_span);
                    printer.push(" (");
                    for (i, item) in repl.items.iter().enumerate() {
                        if i > 0 {
                            printer.push(", ");
                        }
                        format_expression(printer, &item.expr)?;
                        printer.push(" ");
                        printer.push_keyword("AS");
                        printer.push(" ");
                        if let Some(ref qualifier) = item.column.qualifier {
                            format_object_ref(printer, qualifier)?;
                            printer.emit_all_tokens_until(item.column.name.span.start);
                        }
                        format_identifier(printer, &item.column.name)?;
                    }
                    printer.push(")");
                }
            }

            // Format RENAME modifier
            if let Some(ren) = rename {
                printer.push(" ");
                if let Some(syntax_id) = ren.syntax_id {
                    if let Some(syntax_node) = printer.get_rename(syntax_id) {
                        printer.push_token_id(syntax_node.rename_keyword);
                        if let Some(lparen) = syntax_node.lparen {
                            printer.push(" ");
                            printer.push_token_id(lparen);
                        } else {
                            printer.push(" ");
                        }
                        for (idx, item) in ren.items.iter().enumerate() {
                            if idx > 0 {
                                let item_start = item.column.qualifier.as_ref()
                                    .map(|q| q.span.start)
                                    .unwrap_or(item.column.name.span.start);
                                printer.emit_all_tokens_until(item_start);
                            }
                            if let Some(ref qualifier) = item.column.qualifier {
                                format_object_ref(printer, qualifier)?;
                                printer.emit_all_tokens_until(item.column.name.span.start);
                            }
                            format_identifier(printer, &item.column.name)?;
                            printer.push(" ");
                            printer.push_keyword("AS");
                            printer.push(" ");
                            format_identifier(printer, &item.alias)?;
                        }
                        if let Some(rparen) = syntax_node.rparen {
                            printer.push_token_id(rparen);
                        }
                    } else {
                        printer.push_keyword_span(ren.rename_span);
                        if ren.has_parens {
                            printer.push(" (");
                        } else {
                            printer.push(" ");
                        }
                        for (i, item) in ren.items.iter().enumerate() {
                            if i > 0 {
                                printer.push(", ");
                            }
                            if let Some(ref qualifier) = item.column.qualifier {
                                format_object_ref(printer, qualifier)?;
                                printer.emit_all_tokens_until(item.column.name.span.start);
                            }
                            format_identifier(printer, &item.column.name)?;
                            printer.push(" ");
                            printer.push_keyword("AS");
                            printer.push(" ");
                            format_identifier(printer, &item.alias)?;
                        }
                        if ren.has_parens {
                            printer.push(")");
                        }
                    }
                } else {
                    printer.push_keyword_span(ren.rename_span);
                    if ren.has_parens {
                        printer.push(" (");
                    } else {
                        printer.push(" ");
                    }
                    for (i, item) in ren.items.iter().enumerate() {
                        if i > 0 {
                            printer.push(", ");
                        }
                        if let Some(ref qualifier) = item.column.qualifier {
                            format_object_ref(printer, qualifier)?;
                            printer.emit_all_tokens_until(item.column.name.span.start);
                        }
                        format_identifier(printer, &item.column.name)?;
                        printer.push(" ");
                        printer.push_keyword("AS");
                        printer.push(" ");
                        format_identifier(printer, &item.alias)?;
                    }
                    if ren.has_parens {
                        printer.push(")");
                    }
                }
            }

            Ok(())
        }

        AstExpr::Prior { expr, .. } => {
            printer.push_keyword("PRIOR");
            printer.push(" ");
            format_expression(printer, expr)?;
            Ok(())
        }

        AstExpr::IsNull {
            expr,
            is_span,
            not_span,
            null_span,
            ..
        } => {
            format_expression(printer, expr)?;

            printer.push(" ");
            printer.push_keyword_span(*is_span);

            if let Some(not) = not_span {
                printer.push(" ");
                printer.push_keyword_span(*not);
            }

            printer.push(" ");
            printer.push_keyword_span(*null_span);

            Ok(())
        }

        AstExpr::IsDistinctFrom {
            left,
            right,
            is_span,
            not_span,
            distinct_span,
            from_span,
            ..
        } => {
            format_expression(printer, left)?;

            printer.push(" ");
            printer.push_keyword_span(*is_span);

            if let Some(not) = not_span {
                printer.push(" ");
                printer.push_keyword_span(*not);
            }

            printer.push(" ");
            printer.push_keyword_span(*distinct_span);
            printer.push(" ");
            printer.push_keyword_span(*from_span);
            printer.push(" ");

            format_expression(printer, right)?;

            Ok(())
        }

        AstExpr::Like {
            expr,
            not_span,
            like_kind_span,
            pattern,
            escape_clause,
            odbc_escape_span,
            ..
        } => {
            format_expression(printer, expr)?;

            if let Some(not) = not_span {
                printer.push(" ");
                printer.push_keyword_span(*not);
            }

            printer.push(" ");
            printer.push_keyword_span(*like_kind_span);
            printer.push(" ");

            format_expression(printer, pattern)?;

            if let Some(odbc) = odbc_escape_span {
                // ODBC form {escape 'c'}: emit the braced clause verbatim.
                printer.push(" ");
                printer.push_span(*odbc);
            } else if let Some(ref escape) = escape_clause {
                printer.push(" ");
                // The AST has no span for the ESCAPE keyword, so it is
                // emitted as text.
                printer.push_keyword("ESCAPE");
                printer.push(" ");
                format_expression(printer, escape)?;
            }

            Ok(())
        }

        AstExpr::SimilarTo {
            expr,
            not_span,
            similar_to_span,
            pattern,
            escape_clause,
            odbc_escape_span,
            ..
        } => {
            format_expression(printer, expr)?;

            if let Some(not) = not_span {
                printer.push(" ");
                printer.push_keyword_span(*not);
            }

            printer.push(" ");
            printer.push_span(*similar_to_span);
            printer.push(" ");

            format_expression(printer, pattern)?;

            if let Some(odbc) = odbc_escape_span {
                // ODBC form {escape 'c'}: emit the braced clause verbatim.
                printer.push(" ");
                printer.push_span(*odbc);
            } else if let Some(ref escape) = escape_clause {
                printer.push(" ");
                printer.push_keyword("ESCAPE");
                printer.push(" ");
                format_expression(printer, escape)?;
            }

            Ok(())
        }

        AstExpr::Cast {
            syntax_id,
            expr,
            target_type,
            ..
        } => {
            let syntax_cast = printer
                .get_cast_expr(*syntax_id)
                .ok_or_else(|| FormatterError::MissingSyntaxNode("SyntaxCastExpr".to_string()))?;

            printer.push_keyword_token_id(syntax_cast.cast_keyword);
            printer.push_token_id(syntax_cast.l_paren);
            format_expression(printer, expr)?;
            printer.push(" ");
            printer.push_keyword_token_id(syntax_cast.as_keyword);
            printer.push(" ");
            format_data_type(printer, target_type)?;
            printer.push_token_id(syntax_cast.r_paren);
            Ok(())
        }

        AstExpr::TryCast {
            syntax_id,
            expr,
            target_type,
            ..
        } => {
            let syntax_try_cast = printer
                .get_try_cast(*syntax_id)
                .ok_or_else(|| FormatterError::MissingSyntaxNode("SyntaxTryCast".to_string()))?;

            printer.push_keyword_token_id(syntax_try_cast.try_cast_keyword);
            printer.push_token_id(syntax_try_cast.l_paren);
            format_expression(printer, expr)?;
            printer.push(" ");
            printer.push_keyword_token_id(syntax_try_cast.as_keyword);
            printer.push(" ");
            format_data_type(printer, target_type)?;
            printer.push_token_id(syntax_try_cast.r_paren);
            Ok(())
        }

        AstExpr::SafeCast {
            syntax_id,
            expr,
            target_type,
            ..
        } => {
            let syntax_safe_cast = printer
                .get_safe_cast(*syntax_id)
                .ok_or_else(|| FormatterError::MissingSyntaxNode("SyntaxSafeCast".to_string()))?;

            printer.push_keyword_token_id(syntax_safe_cast.safe_cast_keyword);
            printer.push_token_id(syntax_safe_cast.l_paren);
            format_expression(printer, expr)?;
            printer.push(" ");
            printer.push_keyword_token_id(syntax_safe_cast.as_keyword);
            printer.push(" ");
            format_data_type(printer, target_type)?;
            printer.push_token_id(syntax_safe_cast.r_paren);
            Ok(())
        }

        AstExpr::TypedStringLiteral {
            type_name_span,
            value_span,
            odbc_kind,
            span,
            ..
        } => {
            // ODBC escape form ({d '…'}): braces + introducer are surface
            // syntax owned by the whole span — emit verbatim (Pattern A).
            if odbc_kind.is_some() {
                printer.push_span(*span);
                return Ok(());
            }
            // Emit type name (as identifier, not keyword — lexer tokenizes as Identifier)
            printer.push_identifier_span(*type_name_span);
            printer.push(" ");
            // Emit string literal
            printer.push_span(*value_span);
            Ok(())
        }

        AstExpr::TypeCast {
            syntax_id,
            expr,
            target_type,
            ..
        } => {
            format_expression(printer, expr)?;
            // Get syntax node for :: token
            let syntax_type_cast = printer
                .get_type_cast(*syntax_id)
                .ok_or_else(|| FormatterError::MissingSyntaxNode("SyntaxTypeCast".to_string()))?;
            // Emit :: token via syntax layer
            printer.push_token_id(syntax_type_cast.double_colon);
            format_data_type(printer, target_type)?;
            Ok(())
        }

        AstExpr::Extract {
            syntax_id,
            field_span,
            expr,
            ..
        } => {
            // Get syntax node for EXTRACT tokens
            let syntax_extract = printer
                .get_extract(*syntax_id)
                .ok_or_else(|| FormatterError::MissingSyntaxNode("SyntaxExtract".to_string()))?;
            // Emit EXTRACT keyword
            printer.push_token_id(syntax_extract.extract_token);
            printer.push_token_id(syntax_extract.lparen);
            // Emit field name (e.g., DOW, YEAR, MONTH)
            printer.push_span(*field_span);
            printer.push(" ");
            printer.push_keyword_token_id(syntax_extract.from_token);
            printer.push(" ");
            format_expression(printer, expr)?;
            printer.push_token_id(syntax_extract.rparen);
            Ok(())
        }

        AstExpr::MatchAgainst {
            match_call,
            against_span,
            lparen_span,
            search,
            modifier,
            rparen_span,
            ..
        } => {
            // MATCH(cols) AGAINST ('search' [modifier]) — all structural
            // tokens carried as spans on the AST node.
            format_expression(printer, match_call)?;
            printer.push(" ");
            printer.push_keyword_span(*against_span);
            printer.push(" ");
            printer.push_span(*lparen_span);
            format_expression(printer, search)?;
            if let Some(m) = modifier {
                printer.push(" ");
                printer.push_span(m.span);
            }
            printer.push_span(*rparen_span);
            Ok(())
        }

        AstExpr::Position {
            syntax_id,
            needle,
            haystack,
            ..
        } => {
            // Get syntax node for POSITION tokens
            let syntax_position = printer
                .get_position(*syntax_id)
                .ok_or_else(|| FormatterError::MissingSyntaxNode("SyntaxPosition".to_string()))?;
            // Emit POSITION keyword
            printer.push_token_id(syntax_position.position_token);
            printer.push_token_id(syntax_position.lparen);
            // Emit needle expression
            format_expression(printer, needle)?;
            printer.push(" ");
            printer.push_keyword_token_id(syntax_position.in_token);
            printer.push(" ");
            // Emit haystack expression
            format_expression(printer, haystack)?;
            printer.push_token_id(syntax_position.rparen);
            Ok(())
        }

        AstExpr::Trim {
            syntax_id,
            spec_span,
            chars,
            source,
            ..
        } => {
            // Get syntax node for TRIM structural tokens
            let syntax_trim = printer
                .get_trim(*syntax_id)
                .ok_or_else(|| FormatterError::MissingSyntaxNode("SyntaxTrim".to_string()))?;
            printer.push_token_id(syntax_trim.trim_token);
            printer.push_token_id(syntax_trim.lparen);
            // Optional trim-spec keyword (BOTH/LEADING/TRAILING) — emit from the
            // AST span so source casing is preserved (mirrors EXTRACT's field).
            if let Some(spec) = spec_span {
                printer.push_span(*spec);
                printer.push(" ");
            }
            // Optional trim-characters expression
            if let Some(chars_expr) = chars {
                format_expression(printer, chars_expr)?;
                printer.push(" ");
            }
            printer.push_keyword_token_id(syntax_trim.from_token);
            printer.push(" ");
            format_expression(printer, source)?;
            printer.push_token_id(syntax_trim.rparen);
            Ok(())
        }

        AstExpr::Substring {
            syntax_id,
            source,
            from,
            for_len,
            ..
        } => {
            // Get syntax node for SUBSTRING tokens
            let syntax_substring = printer
                .get_substring(*syntax_id)
                .ok_or_else(|| FormatterError::MissingSyntaxNode("SyntaxSubstring".to_string()))?;
            printer.push_token_id(syntax_substring.substring_token);
            printer.push_token_id(syntax_substring.lparen);
            format_expression(printer, source)?;
            // FROM start (token + expr are set together by the parser)
            if let (Some(from_tok), Some(from_expr)) = (syntax_substring.from_token, from) {
                printer.push(" ");
                printer.push_keyword_token_id(from_tok);
                printer.push(" ");
                format_expression(printer, from_expr)?;
            }
            // FOR length
            if let (Some(for_tok), Some(for_expr)) = (syntax_substring.for_token, for_len) {
                printer.push(" ");
                printer.push_keyword_token_id(for_tok);
                printer.push(" ");
                format_expression(printer, for_expr)?;
            }
            printer.push_token_id(syntax_substring.rparen);
            Ok(())
        }

        AstExpr::Collate {
            syntax_id,
            expr,
            ..
        } => {
            format_expression(printer, expr)?;
            // Get syntax node for COLLATE keyword and spec literal
            let syntax_collate = printer
                .get_collate(*syntax_id)
                .ok_or_else(|| FormatterError::MissingSyntaxNode("SyntaxCollate".to_string()))?;
            // Emit COLLATE keyword with space
            printer.push(" ");
            printer.push_keyword_token_id(syntax_collate.collate_keyword);
            printer.push(" ");
            printer.push_token_id(syntax_collate.spec_literal);
            Ok(())
        }

        AstExpr::Between {
            syntax_id,
            expr,
            lower,
            upper,
            ..
        } => {
            format_expression(printer, expr)?;

            let syntax_between = printer
                .get_between_expr(*syntax_id)
                .ok_or_else(|| FormatterError::MissingSyntaxNode("SyntaxBetweenExpr".to_string()))?;

            if let Some(not_kw) = syntax_between.not_keyword {
                printer.push(" ");
                printer.push_keyword_token_id(not_kw);
            }

            printer.push(" ");
            printer.push_keyword_token_id(syntax_between.between_keyword);

            if let Some(sym_kw) = syntax_between.symmetric_keyword {
                printer.push(" ");
                printer.push_keyword_token_id(sym_kw);
            }

            printer.push(" ");

            format_expression(printer, lower)?;

            printer.push(" ");
            printer.push_keyword_token_id(syntax_between.and_keyword);
            printer.push(" ");

            format_expression(printer, upper)?;

            Ok(())
        }

        AstExpr::FunctionCall {
            syntax_id,
            odbc_fn,
            func_name,
            quantifier,
            args,
            order_by_span,
            separator_span,
            within_group,
            filter,
            span,
            ..
        } => {
            // ODBC escape form ({fn F(args)}): span covers the braces — emit
            // verbatim (Pattern A) so the escape survives round-trips.
            if *odbc_fn {
                printer.push_span(*span);
                return Ok(());
            }
            // Redshift `APPROXIMATE` aggregate modifier precedes the function
            // name (`APPROXIMATE COUNT(DISTINCT x)`). Emit it from the CST token
            // before the name. Copy the token id out so the immutable borrow of
            // the syntax node ends before the `&mut` emit calls below.
            let approximate_keyword = printer
                .get_function_call(*syntax_id)
                .ok_or_else(|| FormatterError::MissingSyntaxNode("SyntaxFunctionCall".to_string()))?
                .approximate_keyword;
            if let Some(approx_tok) = approximate_keyword {
                printer.push_keyword_token_id(approx_tok);
                printer.push(" ");
            }

            // Function name identifier (semantic AST); tokens come from syntax layer
            format_identifier(printer, func_name)?;

            let syntax_fn = printer
                .get_function_call(*syntax_id)
                .ok_or_else(|| FormatterError::MissingSyntaxNode("SyntaxFunctionCall".to_string()))?;

            // Opening paren - use token ID to preserve trivia
            printer.push_token_id(syntax_fn.l_paren);

            // Optional DISTINCT/ALL - use syntax-layer token for trivia
            if let (Some(_), Some(distinct_token)) = (quantifier, syntax_fn.distinct_keyword) {
                printer.push_keyword_token_id(distinct_token);
                if !args.is_empty() {
                    printer.push(" ");
                }
            }

            // Arguments - track previous arg end for comma search
            let mut prev_end: Option<u32> = None;
            for arg in args.iter() {
                if let Some(prev) = prev_end {
                    // Search for comma between previous arg and this arg
                    let arg_start = get_function_arg_span(arg).start;
                    printer.push_comma_from_source(prev, arg_start);
                    if printer.config().space_after_comma {
                        printer.space();
                    }
                }
                format_function_arg(printer, arg)?;
                prev_end = Some(get_function_arg_span(arg).end);
            }

            // Aggregate ORDER BY clause (e.g., ARRAY_AGG(x ORDER BY y DESC))
            if let Some(ob_span) = order_by_span {
                printer.push(" ");
                printer.push_span(*ob_span);
            }

            // MySQL GROUP_CONCAT SEPARATOR 'str' tail
            if let Some(sep_span) = separator_span {
                printer.push(" ");
                printer.push_span(*sep_span);
            }

            // Closing paren - use token ID to preserve trivia
            printer.push_token_id(syntax_fn.r_paren);

            // WITHIN GROUP clause
            if let Some(ref wg) = within_group {
                format_within_group_clause(printer, wg)?;
            }

            // FILTER (WHERE ...) clause
            if let Some(ref fc) = filter {
                format_filter_clause(printer, fc)?;
            }

            Ok(())
        }

        AstExpr::ScalarSubquery { syntax_id, subquery, .. } => {
            let syntax_sub = printer
                .get_subquery(*syntax_id)
                .ok_or_else(|| FormatterError::MissingSyntaxNode("SyntaxSubquery".to_string()))?;

            // Use syntax-layer parens to preserve trivia
            printer.push_token_id(syntax_sub.l_paren);
            format_select(printer, subquery)?;
            printer.push_token_id(syntax_sub.r_paren);
            Ok(())
        }

        AstExpr::SubqueryArg { subquery, .. } => {
            // Subquery as function argument — format with proper indentation
            // e.g., ARRAY(SELECT ...) → ARRAY(\n    SELECT...\n)
            // Parens belong to function call, we just handle the SELECT with indentation
            printer.newline();
            printer.indent_up();
            format_select(printer, subquery)?;
            printer.indent_down();
            printer.newline();
            Ok(())
        }

        AstExpr::Parenthesized { syntax_id, expr, .. } => {
            use crate::formatter::config::ParenthesizedExprStyle;

            let syntax_paren = printer.get_paren_expr(*syntax_id)
                .ok_or_else(|| FormatterError::MissingSyntaxNode("SyntaxParenExpr".to_string()))?;
            let style = printer.config().parenthesized_expr_style;
            printer.push_token_id(syntax_paren.l_paren);
            match style {
                ParenthesizedExprStyle::Expanded => {
                    printer.newline();
                    printer.indent_up();
                    format_expression(printer, expr)?;
                    printer.indent_down();
                    printer.newline();
                }
                ParenthesizedExprStyle::Compact => {
                    format_expression(printer, expr)?;
                }
            }
            printer.push_token_id(syntax_paren.r_paren);
            Ok(())
        }

        AstExpr::RowConstructor { syntax_id, elements, .. } => {
            let syntax_row = printer.get_row_constructor(*syntax_id)
                .ok_or_else(|| FormatterError::MissingSyntaxNode("SyntaxRowConstructor".to_string()))?;
            printer.push_token_id(syntax_row.l_paren);
            for (i, elem) in elements.iter().enumerate() {
                format_expression(printer, elem)?;
                if i < syntax_row.commas.len() {
                    printer.push_token_id(syntax_row.commas[i]);
                    printer.push(" ");
                }
            }
            printer.push_token_id(syntax_row.r_paren);
            Ok(())
        }

        AstExpr::ArraySubscript { syntax_id, base, index, .. } => {
            format_expression(printer, base)?;
            let syntax_subscript = printer
                .get_array_subscript(*syntax_id)
                .ok_or_else(|| FormatterError::MissingSyntaxNode("SyntaxArraySubscript".to_string()))?;
            printer.push_token_id(syntax_subscript.l_bracket);
            format_expression(printer, index)?;
            printer.push_token_id(syntax_subscript.r_bracket);
            Ok(())
        }

        AstExpr::ObjectFieldColon {
            syntax_id,
            base,
            field_span,
            ..
        } => {
            format_expression(printer, base)?;
            // Get syntax node for colon token
            let syntax_colon = printer
                .get_colon_field(*syntax_id)
                .ok_or_else(|| FormatterError::MissingSyntaxNode("SyntaxObjectFieldColon".to_string()))?;
            // Emit colon token via syntax layer
            printer.push_token_id(syntax_colon.colon);
            // Emit field name
            printer.push_span(*field_span);
            Ok(())
        }

        AstExpr::ObjectFieldBracket {
            syntax_id,
            base,
            field,
            ..
        } => {
            format_expression(printer, base)?;
            // Get syntax node for bracket tokens
            let syntax_bracket = printer
                .get_bracket_field(*syntax_id)
                .ok_or_else(|| FormatterError::MissingSyntaxNode("SyntaxObjectFieldBracket".to_string()))?;
            // Emit [ token via syntax layer
            printer.push_token_id(syntax_bracket.l_bracket);
            format_expression(printer, field)?;
            // Emit ] token via syntax layer
            printer.push_token_id(syntax_bracket.r_bracket);
            Ok(())
        }

        AstExpr::ObjectFieldDot {
            syntax_id,
            base,
            field_span,
            ..
        } => {
            format_expression(printer, base)?;
            // Get syntax node for dot token
            let syntax_dot = printer
                .get_dot_field(*syntax_id)
                .ok_or_else(|| FormatterError::MissingSyntaxNode("SyntaxObjectFieldDot".to_string()))?;
            // Emit dot token via syntax layer
            printer.push_token_id(syntax_dot.dot);
            // Emit field name
            printer.push_span(*field_span);
            Ok(())
        }

        AstExpr::MethodCall {
            syntax_id,
            base,
            method_name_span,
            args,
            lparen_span,
            rparen_span,
            ..
        } => {
            format_expression(printer, base)?;

            // Get syntax node for dot token
            let syntax_dot = printer
                .get_dot_field(*syntax_id)
                .ok_or_else(|| FormatterError::MissingSyntaxNode("SyntaxDotField for MethodCall".to_string()))?;

            // Emit dot token via syntax layer
            printer.push_token_id(syntax_dot.dot);
            // Emit method name
            printer.push_span(*method_name_span);
            // Emit ( from source
            printer.push_span(*lparen_span);
            // Emit args with commas from source
            let mut prev_end: Option<u32> = None;
            for arg in args.iter() {
                if let Some(prev) = prev_end {
                    let arg_start = arg.span().start;
                    printer.push_comma_from_source(prev, arg_start);
                    if printer.config().space_after_comma {
                        printer.space();
                    }
                }
                format_expression(printer, arg)?;
                prev_end = Some(arg.span().end);
            }
            // Emit ) from source
            printer.push_span(*rparen_span);
            Ok(())
        }

        AstExpr::QualifiedStarFromExpr {
            base,
            star_span,
            ..
        } => {
            format_expression(printer, base)?;
            printer.push(".");
            printer.push_span(*star_span);
            Ok(())
        }

        AstExpr::JinjaConditional {
            opening,
            then_body,
            elif_branches,
            else_branch,
            closing,
            ..
        } => {
            // Check if we should preserve original or format
            if printer.config().jinja_preserve_original {
                // Extract entire Jinja conditional as-is
                let jinja_text = printer.extract_span(opening.span).to_string();
                let closing_text = printer.extract_span(closing.span).to_string();
                let combined = format!("{} ... {}", jinja_text, closing_text);
                printer.push(&combined);
                return Ok(());
            }

            // Format Jinja conditional using recursive descent
            format_jinja_conditional_expr(
                printer,
                opening,
                then_body,
                elif_branches.as_ref(),
                else_branch,
                closing,
            )?;
            Ok(())
        }

        AstExpr::AtTimeZone {
            syntax_id,
            expr,
            zone,
            ..
        } => {
            // Format the inner expression
            format_expression(printer, expr)?;

            // Get CST node for structural tokens
            let syntax = printer
                .get_at_time_zone(*syntax_id)
                .ok_or_else(|| FormatterError::MissingSyntaxNode("SyntaxAtTimeZone".to_string()))?;

            // Emit AT keyword token
            printer.push(" ");
            printer.push_token_id(syntax.at_token);

            if let Some(local_token) = syntax.local_token {
                // AT LOCAL
                printer.push(" ");
                printer.push_keyword_token_id(local_token);
            } else {
                // AT TIME ZONE zone_expr
                if let Some(time_token) = syntax.time_token {
                    printer.push(" ");
                    printer.push_token_id(time_token);
                }
                if let Some(zone_token) = syntax.zone_token {
                    printer.push(" ");
                    printer.push_token_id(zone_token);
                }
                // Format the zone expression
                if let Some(zone_expr) = zone {
                    printer.push(" ");
                    format_expression(printer, zone_expr)?;
                }
            }
            Ok(())
        }

        // dbt expressions - preserve as-is (they render to table references)
        AstExpr::DbtRef { span, .. }
        | AstExpr::DbtSource { span, .. }
        | AstExpr::DbtVar { span, .. }
        | AstExpr::DbtConfig { span, .. }
        | AstExpr::DbtThis { span, .. }
        // Error nodes - preserve source span exactly
        | AstExpr::Error { span, .. } => {
            printer.push_span(*span);
            Ok(())
        }
    }?;
        Ok(())
    })
}

/// Format a Jinja conditional expression ({% if %} ... {% endif %}) in WHERE/HAVING/etc.
/// Uses proper recursive descent - delegates to format_jinja_body for each branch.
fn format_jinja_conditional_expr(
    printer: &mut Printer,
    opening: &crate::ast::JinjaBlockDelimiter,
    then_body: &crate::ast::JinjaBody,
    elif_branches: &[(crate::ast::JinjaBlockDelimiter, crate::ast::JinjaBody)],
    else_branch: &Option<Box<(crate::ast::JinjaBlockDelimiter, crate::ast::JinjaBody)>>,
    closing: &crate::ast::JinjaBlockDelimiter,
) -> Result<(), FormatterError> {
    let format_sql = printer.config().jinja_format_sql_content;
    let indent_delimiters = printer.config().jinja_indent_delimiters;

    // Format opening delimiter {% if condition %}
    // Use push_span to preserve trivia
    if indent_delimiters && !printer.get_at_line_start() {
        printer.newline();
    }
    printer.push_span(opening.span);

    // Format then body via recursive delegation
    if format_sql {
        printer.newline();
        printer.indent_up();
    }
    format_jinja_body(printer, then_body)?;
    if format_sql {
        printer.indent_down();
    }

    // Format elif branches via recursive delegation
    for (elif_delim, elif_body) in elif_branches {
        if indent_delimiters {
            printer.newline();
        } else {
            printer.push(" ");
        }
        printer.push_span(elif_delim.span);

        if format_sql {
            printer.newline();
            printer.indent_up();
        }
        format_jinja_body(printer, elif_body)?;
        if format_sql {
            printer.indent_down();
        }
    }

    // Format else branch via recursive delegation
    if let Some((else_delim, else_body)) = else_branch.as_deref() {
        if indent_delimiters {
            printer.newline();
        } else {
            printer.push(" ");
        }
        printer.push_span(else_delim.span);

        if format_sql {
            printer.newline();
            printer.indent_up();
        }
        format_jinja_body(printer, else_body)?;
        if format_sql {
            printer.indent_down();
        }
    }

    // Format closing delimiter {% endif %}
    // Use push_span to preserve trailing trivia
    if indent_delimiters {
        printer.newline();
    } else {
        printer.push(" ");
    }
    printer.push_span(closing.span);

    Ok(())
}

/// Format Jinja body content (expression or unparsed span).
/// Proper recursive descent: delegates back to format_expression for parsed expressions.
fn format_jinja_body(
    printer: &mut Printer,
    body: &crate::ast::JinjaBody,
) -> Result<(), FormatterError> {
    use crate::ast::JinjaBody;

    match body {
        JinjaBody::Expression(expr) => {
            // Add space before expression content (only if not at line start to preserve indent)
            if printer.config().spaces_around_operators && !printer.get_at_line_start() {
                printer.push(" ");
            }
            // Recursive delegation to expression formatter
            format_expression(printer, expr)?;
        }
        JinjaBody::Unparsed(span) => {
            // Use push_span to properly track trivia and advance token index
            // This prevents double-emission of comments that are within the span
            if !printer.get_at_line_start() {
                printer.push(" ");
            }
            printer.push_span(*span);
        }
    }

    Ok(())
}

/// Format expression with boolean operator splitting for WHERE/JOIN ON clauses.
/// When enabled, AND/OR operators cause newlines and indentation.
fn format_expression_with_boolean_splitting(
    printer: &mut Printer,
    expr: &AstExpr,
    extra_indent: usize,
) -> Result<(), FormatterError> {
    use crate::formatter::config::BooleanOperatorPosition;

    match expr {
        AstExpr::BinaryOp {
            left,
            operator,
            syntax_id,
            right,
            ..
        } => {
            use crate::ast::BinaryOperator;

            // Special case: NOT operator is represented as BinaryOp with Boolean literal on left
            let is_not_operator = matches!(operator, BinaryOperator::Not)
                && matches!(
                    left.as_ref(),
                    AstExpr::Literal {
                        literal: crate::ast::AstLiteral::Boolean { .. },
                        ..
                    }
                );

            if is_not_operator {
                // Format as unary NOT - only format operator and right operand
                if let Some(syntax) = printer.get_binary_op(*syntax_id) {
                    printer.push_token_id(syntax.op_token);
                } else {
                    printer.push_keyword("NOT");
                }
                printer.push(" ");
                format_expression_with_boolean_splitting(printer, right, extra_indent)?;
                return Ok(());
            }

            let is_boolean = matches!(operator, BinaryOperator::And | BinaryOperator::Or);

            if is_boolean {
                // Recursively format left side (which may also have boolean ops)
                format_expression_with_boolean_splitting(printer, left, extra_indent)?;

                // Get operator text for case conversion
                let op_str = match operator {
                    BinaryOperator::And => "AND",
                    BinaryOperator::Or => "OR",
                    _ => unreachable!(),
                };

                // Determine operator placement
                match printer.config().boolean_operator_position {
                    BooleanOperatorPosition::End => {
                        // Operator at end of line
                        if printer.config().spaces_around_operators {
                            printer.push(" ");
                        }

                        if let Some(syntax) = printer.get_binary_op(*syntax_id) {
                            printer.push_token_id(syntax.op_token);
                        } else if printer.config().uppercase_boolean_operators {
                            printer.push_keyword(op_str);
                        } else {
                            printer.push(&op_str.to_lowercase());
                        }

                        // Newline and indent for right side
                        // Use newline_if_needed in case a trailing line comment already added one
                        printer.newline_if_needed();
                        // Apply extra indentation beyond current level
                        for _ in 0..extra_indent {
                            printer.indent_up();
                        }
                    }
                    BooleanOperatorPosition::Start => {
                        // Newline first, then operator at start
                        // Use newline_if_needed in case a trailing line comment already added one
                        printer.newline_if_needed();
                        // Apply extra indentation beyond current level
                        for _ in 0..extra_indent {
                            printer.indent_up();
                        }

                        if let Some(syntax) = printer.get_binary_op(*syntax_id) {
                            printer.push_token_id(syntax.op_token);
                        } else if printer.config().uppercase_boolean_operators {
                            printer.push_keyword(op_str);
                        } else {
                            printer.push(&op_str.to_lowercase());
                        }

                        if printer.config().spaces_around_operators {
                            printer.push(" ");
                        }
                    }
                }

                // Recursively format right side
                format_expression_with_boolean_splitting(printer, right, extra_indent)?;

                // Restore indent level
                for _ in 0..extra_indent {
                    printer.indent_down();
                }

                Ok(())
            } else {
                // Non-boolean operator: format normally (inline)
                format_expression(printer, left)?;

                if printer.config().spaces_around_operators {
                    printer.push(" ");
                }

                // Emit operator token with trivia
                if let Some(syntax) = printer.get_binary_op(*syntax_id) {
                    printer.push_token_id(syntax.op_token);
                } else {
                    // Fallback: reconstruct operator text
                    let op_str = match operator {
                        BinaryOperator::Plus => "+",
                        BinaryOperator::Minus => "-",
                        BinaryOperator::Multiply => "*",
                        BinaryOperator::Divide => "/",
                        BinaryOperator::Modulo => "%",
                        BinaryOperator::Equal => "=",
                        BinaryOperator::NotEqual => "!=",
                        BinaryOperator::LessThan => "<",
                        BinaryOperator::LessThanOrEqual => "<=",
                        BinaryOperator::GreaterThan => ">",
                        BinaryOperator::GreaterThanOrEqual => ">=",
                        BinaryOperator::Concat => "||",
                        BinaryOperator::LogicalOr => "||",
                        BinaryOperator::Like => "LIKE",
                        BinaryOperator::ILike => "ILIKE",
                        BinaryOperator::RLike => "RLIKE",
                        _ => "??", // should not reach here for And/Or/Not
                    };
                    let is_keyword = matches!(
                        operator,
                        BinaryOperator::Like | BinaryOperator::ILike | BinaryOperator::RLike
                    );
                    if is_keyword {
                        printer.push_keyword(op_str);
                    } else {
                        printer.push(op_str);
                    }
                }

                if printer.config().spaces_around_operators {
                    printer.push(" ");
                }

                format_expression(printer, right)?;
                Ok(())
            }
        }

        AstExpr::Parenthesized {
            syntax_id, expr, ..
        } => {
            // Handle parenthesized expressions with boolean splitting inside
            use crate::formatter::config::ParenthesizedExprStyle;

            let syntax_paren = printer
                .get_paren_expr(*syntax_id)
                .ok_or_else(|| FormatterError::MissingSyntaxNode("SyntaxParenExpr".to_string()))?;

            let style = printer.config().parenthesized_expr_style;
            printer.push_token_id(syntax_paren.l_paren);

            match style {
                ParenthesizedExprStyle::Expanded => {
                    printer.newline();
                    printer.indent_up();
                    format_expression_with_boolean_splitting(printer, expr, extra_indent)?;
                    printer.indent_down();
                    printer.newline();
                }
                ParenthesizedExprStyle::Compact => {
                    format_expression_with_boolean_splitting(printer, expr, extra_indent)?;
                }
            }

            printer.push_token_id(syntax_paren.r_paren);
            Ok(())
        }

        AstExpr::RowConstructor {
            syntax_id,
            elements,
            ..
        } => {
            let syntax_row = printer.get_row_constructor(*syntax_id).ok_or_else(|| {
                FormatterError::MissingSyntaxNode("SyntaxRowConstructor".to_string())
            })?;

            printer.push_token_id(syntax_row.l_paren);

            for (i, elem) in elements.iter().enumerate() {
                format_expression(printer, elem)?;
                if i < syntax_row.commas.len() {
                    printer.push_token_id(syntax_row.commas[i]);
                    printer.push(" ");
                }
            }

            printer.push_token_id(syntax_row.r_paren);
            Ok(())
        }

        // For all other expression types, delegate to normal formatter
        _ => format_expression(printer, expr),
    }
}

/// Get the span of a function argument (for comma search)
fn get_function_arg_span(arg: &crate::ast::AstFunctionArg) -> crate::lexer::Span {
    use crate::ast::AstFunctionArg;
    match arg {
        AstFunctionArg::Positional(expr) => expr.span(),
        AstFunctionArg::Named { name, value, .. } => {
            // Span from name start to value end
            crate::lexer::Span {
                start: name.span.start,
                end: value.span().end,
            }
        }
        AstFunctionArg::Lambda { span, .. } => *span,
        AstFunctionArg::AliasedArg { value, alias, .. } => {
            // Span from value start to alias end
            crate::lexer::Span {
                start: value.span().start,
                end: alias.span.end,
            }
        }
        AstFunctionArg::BulkArg { bulk_span, value } => crate::lexer::Span {
            start: bulk_span.start,
            end: value.span().end,
        },
    }
}

fn format_function_arg(
    printer: &mut Printer,
    arg: &crate::ast::AstFunctionArg,
) -> Result<(), FormatterError> {
    use crate::ast::AstFunctionArg;
    match arg {
        AstFunctionArg::Positional(expr) => format_expression(printer, expr),
        AstFunctionArg::Named { name, value, .. } => {
            format_identifier(printer, name)?;
            printer.push(" => ");
            format_expression(printer, value)
        }
        AstFunctionArg::Lambda { params, body, .. } => {
            // Lambda: x -> expr  or  (x, y) -> expr
            if params.len() == 1 {
                format_identifier(printer, &params[0])?;
            } else {
                printer.push("(");
                for (i, param) in params.iter().enumerate() {
                    if i > 0 {
                        printer.push_comma();
                        if printer.config().space_after_comma {
                            printer.space();
                        }
                    }
                    format_identifier(printer, param)?;
                }
                printer.push(")");
            }
            printer.push(" -> ");
            format_expression(printer, body)
        }
        AstFunctionArg::AliasedArg {
            value,
            as_span,
            alias,
        } => {
            // Aliased arg: expr AS name (BigQuery STRUCT constructor)
            format_expression(printer, value)?;
            printer.space();
            printer.push_keyword_span(*as_span);
            printer.space();
            format_identifier(printer, alias)
        }
        AstFunctionArg::BulkArg { bulk_span, value } => {
            // OPENROWSET(BULK '<file>', …): emit the BULK keyword then a single
            // space before the file-path value (the literal formatter does not
            // re-emit the inter-token trivia).
            printer.push_keyword_span(*bulk_span);
            printer.space();
            format_expression(printer, value)
        }
    }
}

fn format_data_type(
    printer: &mut Printer,
    data_type: &crate::ast::AstDataType,
) -> Result<(), FormatterError> {
    use crate::ast::AstDataType;
    match data_type {
        AstDataType::Simple { name_span } => {
            // Use push_span to preserve trivia on data type name
            printer.push_span(*name_span);
        }
        AstDataType::WithPrecision {
            syntax_id,
            name_span,
            precision_span,
            ..
        } => {
            let syntax = printer.get_type_precision(*syntax_id).ok_or_else(|| {
                FormatterError::MissingSyntaxNode("SyntaxTypePrecision".to_string())
            })?;

            printer.push_span(*name_span);
            printer.push_token_id(syntax.l_paren);
            printer.push_span(*precision_span);
            printer.push_token_id(syntax.r_paren);
        }
        AstDataType::WithPrecisionScale {
            syntax_id,
            name_span,
            precision_span,
            scale_span,
            ..
        } => {
            let syntax = printer
                .get_type_precision_scale(*syntax_id)
                .ok_or_else(|| {
                    FormatterError::MissingSyntaxNode("SyntaxTypePrecisionScale".to_string())
                })?;

            printer.push_span(*name_span);
            printer.push_token_id(syntax.l_paren);
            printer.push_span(*precision_span);
            printer.push_token_id(syntax.comma);
            if printer.config().space_after_comma {
                printer.space();
            }
            printer.push_span(*scale_span);
            printer.push_token_id(syntax.r_paren);
        }
        AstDataType::Parameterized { span, .. } => {
            // Emit parameterized types (e.g., ARRAY<STRING>, STRUCT<a INT64>) as raw source
            // to preserve exact whitespace between field names and types.
            printer.push_raw_source(*span);
        }
        AstDataType::CompoundInterval { span, .. } => {
            // Emit compound interval types (e.g., INTERVAL YEAR TO MONTH) as raw source.
            printer.push_raw_source(*span);
        }
    }
    Ok(())
}

fn format_window_spec(
    printer: &mut Printer,
    window: &crate::ast::AstWindowSpec,
) -> Result<(), FormatterError> {
    // Get the syntax node that owns the clause keywords
    let syntax_over = printer
        .get_over_clause(window.syntax_id)
        .ok_or_else(|| FormatterError::MissingSyntaxNode("SyntaxOverClause".to_string()))?;

    // PARTITION BY
    if !window.partition_by.is_empty() {
        if printer.config().partition_by_on_newline {
            // Already on newline from OVER clause handling
        }

        // Emit PARTITION keyword using syntax layer
        if let Some(partition_id) = syntax_over.partition_keyword {
            printer.push_keyword_token_id(partition_id);
        } else {
            printer.push_keyword("PARTITION");
        }
        printer.push(" ");
        // Emit BY keyword using syntax layer
        if let Some(by_id) = syntax_over.partition_by_keyword {
            printer.push_keyword_token_id(by_id);
        } else {
            printer.push_keyword("BY");
        }
        printer.push(" ");

        for (i, expr) in window.partition_by.iter().enumerate() {
            if i > 0 {
                printer.push_comma();
                if printer.config().space_after_comma {
                    printer.space();
                }
            }
            format_expression(printer, expr)?;
        }
    }

    // ORDER BY
    if !window.order_by.is_empty() {
        if !window.partition_by.is_empty() {
            if printer.config().order_by_in_window_on_newline {
                printer.newline();
            } else {
                printer.push(" ");
            }
        }
        // Emit ORDER keyword using syntax layer
        if let Some(order_id) = syntax_over.order_keyword {
            printer.push_keyword_token_id(order_id);
        } else {
            printer.push_keyword("ORDER");
        }
        printer.push(" ");
        // Emit BY keyword using syntax layer
        if let Some(by_id) = syntax_over.order_by_keyword {
            printer.push_keyword_token_id(by_id);
        } else {
            printer.push_keyword("BY");
        }
        printer.push(" ");

        for (i, order_item) in window.order_by.iter().enumerate() {
            if i > 0 {
                printer.push_comma();
                if printer.config().space_after_comma {
                    printer.space();
                }
            }
            format_expression(printer, &order_item.expr)?;

            // Get syntax node if available
            let syntax_node = order_item
                .syntax_id
                .and_then(|id| printer.get_order_item(id));

            if let Some(asc) = order_item.asc {
                printer.push(" ");
                if let Some(syntax) = syntax_node {
                    if let Some(dir_token_id) = syntax.direction_keyword {
                        printer.push_keyword_token_id(dir_token_id);
                    } else {
                        // Fallback if syntax node doesn't have keyword (shouldn't happen)
                        let dir_text = if asc { "ASC" } else { "DESC" };
                        printer.push_keyword(dir_text);
                    }
                } else {
                    // No syntax node - generate keyword
                    let dir_text = if asc { "ASC" } else { "DESC" };
                    printer.push_keyword(dir_text);
                }
            }

            if let Some(nulls_first) = order_item.nulls_first {
                printer.push(" ");
                if let Some(syntax) = syntax_node {
                    if let Some(nulls_token_id) = syntax.nulls_keyword {
                        printer.push_keyword_token_id(nulls_token_id);
                        printer.push(" ");
                        if let Some(order_token_id) = syntax.nulls_order_keyword {
                            printer.push_keyword_token_id(order_token_id);
                        } else {
                            // Fallback if order keyword missing (shouldn't happen)
                            let nulls_text = if nulls_first { "FIRST" } else { "LAST" };
                            printer.push_keyword(nulls_text);
                        }
                    } else {
                        // No NULLS keyword in syntax node - generate
                        printer.push_keyword("NULLS");
                        printer.push(" ");
                        let nulls_text = if nulls_first { "FIRST" } else { "LAST" };
                        printer.push_keyword(nulls_text);
                    }
                } else {
                    // No syntax node - generate keywords
                    printer.push_keyword("NULLS");
                    printer.push(" ");
                    let nulls_text = if nulls_first { "FIRST" } else { "LAST" };
                    printer.push_keyword(nulls_text);
                }
            }
        }
    }

    // Frame clause (ROWS/RANGE BETWEEN ...)
    if let Some(ref frame) = window.frame {
        use crate::formatter::config::WindowFrameStyle;

        // Check if frame should be on newline
        let has_preceding_clauses = !window.partition_by.is_empty() || !window.order_by.is_empty();
        if has_preceding_clauses {
            match printer.config().window_frame_style {
                WindowFrameStyle::Expanded => {
                    printer.newline();
                }
                WindowFrameStyle::Compact => {
                    printer.push(" ");
                }
            }
        }

        // Format frame: ROWS|RANGE BETWEEN start AND end
        // Emit trivia at frame kind span
        printer.push_keyword_span(frame.kind_span);

        printer.push(" ");

        // Start bound
        if frame.end.is_some() {
            if let Some(between_span) = frame.between_span {
                printer.push_keyword_span(between_span);
            } else {
                printer.push_keyword("BETWEEN");
            }
            printer.push(" ");
        }

        format_frame_bound(printer, &frame.start)?;

        // End bound
        if let Some(ref end) = frame.end {
            printer.push(" ");
            if let Some(and_span) = frame.and_span {
                printer.push_keyword_span(and_span);
            } else {
                printer.push_keyword("AND");
            }
            printer.push(" ");
            format_frame_bound(printer, end)?;
        }
    }

    Ok(())
}

fn format_frame_bound(
    printer: &mut Printer,
    bound: &crate::ast::AstFrameBound,
) -> Result<(), FormatterError> {
    use crate::ast::AstFrameBoundKind;

    // Leading trivia is handled by push_keyword's token scanning or format_expression's push_* calls

    match bound.kind {
        AstFrameBoundKind::UnboundedPreceding => {
            printer.push_keyword("UNBOUNDED");
            printer.push(" ");
            printer.push_keyword("PRECEDING");
        }
        AstFrameBoundKind::UnboundedFollowing => {
            printer.push_keyword("UNBOUNDED");
            printer.push(" ");
            printer.push_keyword("FOLLOWING");
        }
        AstFrameBoundKind::CurrentRow => {
            printer.push_keyword("CURRENT");
            printer.push(" ");
            printer.push_keyword("ROW");
        }
        AstFrameBoundKind::Preceding => {
            if let Some(ref value) = bound.value {
                format_expression(printer, value)?;
                printer.push(" ");
            }
            printer.push_keyword("PRECEDING");
        }
        AstFrameBoundKind::Following => {
            if let Some(ref value) = bound.value {
                format_expression(printer, value)?;
                printer.push(" ");
            }
            printer.push_keyword("FOLLOWING");
        }
    }

    Ok(())
}

/// Format a WINDOW clause: WINDOW w AS (...) [, w2 AS (...)]
fn format_window_clause(
    printer: &mut Printer,
    clause: &crate::ast::AstWindowClause,
) -> Result<(), FormatterError> {
    // Emit WINDOW keyword from source span
    printer.push_keyword_span(clause.window_keyword_span);

    for (i, def) in clause.definitions.iter().enumerate() {
        if i > 0 {
            printer.push(",");
        }
        printer.newline();
        printer.indent_up();

        // Emit window name
        printer.push_span(def.name_span);
        printer.push(" ");

        // Emit AS keyword
        printer.push_keyword_span(def.as_keyword_span);
        printer.push(" ");

        // Get syntax node for the window spec
        let syntax_over = printer
            .get_over_clause(def.window_spec.syntax_id)
            .ok_or_else(|| {
                FormatterError::MissingSyntaxNode("SyntaxOverClause for WINDOW def".to_string())
            })?;

        // Emit opening paren
        if let Some(lp) = syntax_over.l_paren {
            printer.push_token_id(lp);
        } else {
            printer.push("(");
        }

        // Emit existing window name reference if present
        if let Some(name_span) = def.window_spec.existing_window_name {
            printer.push_span(name_span);
            let has_more = !def.window_spec.partition_by.is_empty()
                || !def.window_spec.order_by.is_empty()
                || def.window_spec.frame.is_some();
            if has_more {
                printer.push(" ");
            }
        }

        format_window_spec(printer, &def.window_spec)?;

        // Emit closing paren
        if let Some(rp) = syntax_over.r_paren {
            printer.push_token_id(rp);
        } else {
            printer.push(")");
        }

        printer.indent_down();
    }

    Ok(())
}

/// Format a subquery with proper parenthesis placement and indentation
fn format_subquery(printer: &mut Printer, subquery: &AstStmt) -> Result<(), FormatterError> {
    format_subquery_with_spans(printer, subquery, None, None)
}

/// Format a subquery with proper parenthesis placement and indentation
/// Optionally uses lparen_span and rparen_span to emit trivia from source tokens
fn format_subquery_with_spans(
    printer: &mut Printer,
    subquery: &AstStmt,
    lparen_span: Option<crate::lexer::Span>,
    rparen_span: Option<crate::lexer::Span>,
) -> Result<(), FormatterError> {
    printer.enter_recursion("subquery formatting")?;

    let result = (|| -> Result<(), FormatterError> {
        use crate::formatter::config::SubqueryParenStyle;

        // Helper to emit opening paren with or without trivia
        let emit_lparen = |p: &mut Printer| {
            if let Some(span) = lparen_span {
                p.push_span(span);
            } else {
                p.push("(");
            }
        };

        // Helper to emit closing paren with or without trivia
        let emit_rparen = |p: &mut Printer| {
            if let Some(span) = rparen_span {
                p.push_span(span);
            } else {
                p.push(")");
            }
        };

        match printer.config().subquery_paren_style {
            SubqueryParenStyle::SameLine => {
                // Opening paren on same line: (
                emit_lparen(printer);
                if printer.config().indent_subqueries {
                    printer.newline();
                    printer.indent_up();
                }
                format_select(printer, subquery)?;
                if printer.config().indent_subqueries {
                    printer.indent_down();
                    printer.newline();
                }
                emit_rparen(printer);
            }
            SubqueryParenStyle::NewLine => {
                // Opening paren on new line, closing on same line as content
                printer.newline();
                emit_lparen(printer);
                if printer.config().indent_subqueries {
                    printer.newline();
                    printer.indent_up();
                }
                format_select(printer, subquery)?;
                if printer.config().indent_subqueries {
                    printer.indent_down();
                }
                emit_rparen(printer);
            }
            SubqueryParenStyle::NewLineClosing => {
                // Opening paren on new line, closing paren on new line too
                printer.newline();
                emit_lparen(printer);
                if printer.config().indent_subqueries {
                    printer.newline();
                    printer.indent_up();
                }
                format_select(printer, subquery)?;
                if printer.config().indent_subqueries {
                    printer.indent_down();
                }
                printer.newline();
                emit_rparen(printer);
            }
        }

        Ok(())
    })();

    printer.exit_recursion();
    result
}

/// Maximum WHEN-condition width for CASE THEN alignment.
///
/// Measures the true formatted width of each condition via a scratch printer
/// (same idiom as `calculate_max_update_column_width`) rather than a source-text
/// heuristic, so alignment padding is a pure function of formatted output and the
/// formatter stays idempotent across re-format passes.
fn calculate_max_when_width(printer: &Printer, whens: &[Box<crate::ast::AstCaseWhen>]) -> usize {
    whens
        .iter()
        .filter_map(|when| {
            // Synthetic Jinja WHENs carry no real condition — they emit the
            // placeholder without WHEN/THEN and never participate in alignment.
            let is_synthetic_jinja = matches!(&when.cond, AstExpr::JinjaPlaceholder { .. })
                && matches!(&when.result, AstExpr::JinjaPlaceholder { .. })
                && when.cond.span() == when.result.span();
            if is_synthetic_jinja {
                return None;
            }
            // No CST needed for width measurement.
            let mut temp_printer = Printer::new(printer.config(), printer.source(), None);
            if format_expression(&mut temp_printer, &when.cond).is_ok() {
                let output = temp_printer.output_string();
                // Last-line width handles multi-line conditions.
                Some(output.lines().last().unwrap_or(output).len())
            } else {
                None
            }
        })
        .max()
        .unwrap_or(0)
}

/// Format a CASE expression with proper indentation and alignment
fn format_case_expression(
    printer: &mut Printer,
    case_span: crate::lexer::Span,
    operand: Option<&AstExpr>,
    whens: &[Box<crate::ast::AstCaseWhen>],
    else_expr: Option<&AstExpr>,
) -> Result<(), FormatterError> {
    // Check if this is a simple CASE that should be kept compact
    let is_simple = whens.len() == 1 && else_expr.is_some();
    let should_compact = printer.config().case_style_compact && is_simple;

    // CASE keyword - use span to emit trivia
    printer.push_keyword_span(case_span);

    // Simple CASE: CASE operand WHEN ...
    if let Some(operand_expr) = operand {
        if printer.config().case_expression_on_newline && !should_compact {
            printer.newline();
            if printer.config().indent_case_then {
                printer.indent_up();
            }
            format_expression(printer, operand_expr)?;
            if printer.config().indent_case_then {
                printer.indent_down();
            }
        } else {
            printer.push(" ");
            format_expression(printer, operand_expr)?;
        }
    }

    if should_compact {
        // Compact format: CASE WHEN cond THEN result ELSE result END
        printer.push(" ");
        printer.push_keyword("WHEN");
        printer.push(" ");
        format_expression(printer, &whens[0].cond)?;
        printer.push(" ");
        printer.push_keyword("THEN");
        printer.push(" ");
        format_expression(printer, &whens[0].result)?;

        if let Some(else_result) = else_expr {
            printer.push(" ");
            printer.push_keyword("ELSE");
            printer.push(" ");
            format_expression(printer, else_result)?;
        }

        printer.push(" ");
        printer.push_keyword("END");
        return Ok(());
    }

    // Max WHEN-condition width for THEN alignment, measured from the true
    // formatted output (not the source span). Measuring the source text and
    // guessing operator spacing drifts on re-format (already-spaced source
    // re-inflates the guess), breaking idempotency; measuring the formatted
    // width makes padding a fixed point.
    let max_when_width = if printer.config().case_when_aligned {
        calculate_max_when_width(printer, whens)
    } else {
        0
    };

    // Format WHEN clauses
    for when in whens {
        // Check if this is a synthetic WHEN created for a Jinja control flow statement
        // ({% for %}, {% endfor %}, {% if %}, etc.)
        // In this case, both cond and result are JinjaPlaceholder with the same span
        let is_synthetic_jinja = matches!(&when.cond, AstExpr::JinjaPlaceholder { .. })
            && matches!(&when.result, AstExpr::JinjaPlaceholder { .. })
            && when.cond.span() == when.result.span();

        if is_synthetic_jinja {
            // Just output the Jinja token once, without WHEN/THEN keywords
            printer.newline_if_needed();
            if printer.config().indent_case_then {
                printer.indent_up();
            }
            format_expression(printer, &when.cond)?;
            if printer.config().indent_case_then {
                printer.indent_down();
            }
            continue;
        }

        printer.newline_if_needed();

        // Indent WHEN if configured
        if printer.config().indent_case_then {
            printer.indent_up();
        }

        // WHEN keyword and condition
        printer.push_keyword("WHEN");
        printer.push(" ");

        let when_start_pos = printer.len();
        format_expression(printer, &when.cond)?;
        let when_expr_len = printer.len() - when_start_pos;

        // THEN keyword with optional alignment
        if printer.config().case_when_aligned && max_when_width > 0 {
            // Pad to the widest condition, then two spaces before THEN. Emit as a
            // single string: push(" ") no-ops against a preceding space (the
            // double-space guard), which would swallow the alignment padding.
            let spaces = max_when_width.saturating_sub(when_expr_len) + 2;
            printer.push(&" ".repeat(spaces));
        } else {
            printer.push(" ");
        }
        printer.push_keyword("THEN");
        printer.push(" ");

        // THEN result expression
        format_expression(printer, &when.result)?;

        if printer.config().indent_case_then {
            printer.indent_down();
        }
    }

    // ELSE clause
    if let Some(else_result) = else_expr {
        printer.newline_if_needed();

        if printer.config().indent_case_then {
            printer.indent_up();
        }

        printer.push_keyword("ELSE");

        // Align the ELSE result with the THEN results. A WHEN result starts at
        // column: "WHEN " (5) + max_when_width + "  " (2) + "THEN " (5) = max+12.
        // "ELSE" is 4 chars, so it needs max+8 spaces to reach the same column.
        // Emit as one string (the double-space guard would collapse the run).
        if printer.config().case_when_aligned && max_when_width > 0 {
            printer.push(&" ".repeat(max_when_width + 8));
        } else {
            printer.push(" ");
        }

        format_expression(printer, else_result)?;

        if printer.config().indent_case_then {
            printer.indent_down();
        }
    }

    // END keyword
    printer.newline_if_needed();
    printer.push_keyword("END");

    Ok(())
}

/// Fallback formatting for rows_per_match when token IDs are not available
fn format_rows_per_match_fallback(
    printer: &mut Printer,
    rows_per_match: &crate::ast::AstRowsPerMatch,
) {
    match rows_per_match {
        crate::ast::AstRowsPerMatch::OneRowPerMatch => {
            printer.push_keyword("ONE ROW PER MATCH");
        }
        crate::ast::AstRowsPerMatch::AllRowsPerMatch { empty_matches } => {
            printer.push_keyword("ALL ROWS PER MATCH");
            if let Some(mode) = empty_matches {
                printer.push(" ");
                match mode {
                    crate::ast::AstEmptyMatchesMode::Show => {
                        printer.push_keyword("SHOW EMPTY MATCHES");
                    }
                    crate::ast::AstEmptyMatchesMode::Omit => {
                        printer.push_keyword("OMIT EMPTY MATCHES");
                    }
                    crate::ast::AstEmptyMatchesMode::WithUnmatched => {
                        printer.push_keyword("WITH UNMATCHED ROWS");
                    }
                }
            }
        }
    }
}

/// Fallback formatting for after_match_skip when token IDs are not available
fn format_after_match_skip_fallback(
    printer: &mut Printer,
    after_match: &crate::ast::AstAfterMatchSkip,
) {
    printer.push_keyword("AFTER MATCH SKIP");
    printer.push(" ");

    match after_match {
        crate::ast::AstAfterMatchSkip::PastLastRow => {
            printer.push_keyword("PAST LAST ROW");
        }
        crate::ast::AstAfterMatchSkip::ToNextRow => {
            printer.push_keyword("TO NEXT ROW");
        }
        crate::ast::AstAfterMatchSkip::ToFirstSymbol(symbol) => {
            printer.push_keyword("TO FIRST");
            printer.push(" ");
            printer.push(symbol);
        }
        crate::ast::AstAfterMatchSkip::ToLastSymbol(symbol) => {
            printer.push_keyword("TO LAST");
            printer.push(" ");
            printer.push(symbol);
        }
    }
}
