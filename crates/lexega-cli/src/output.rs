// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Report rendering: Markdown summaries and the fact / signal / rule
//! explanation views.

use lexega_core::analyzer;
use lexega_core::analyzer::PlaceholderStats;

/// Truncate message for table display
pub fn truncate_for_table(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len - 3])
    }
}

pub fn print_analyze_markdown(
    report: &lexega_core::analyzer::AnalysisReport,
    input_path: &str,
    placeholder_stats: &PlaceholderStats,
    depth_note: Option<&str>,
) {
    use lexega_core::analyzer::RiskLevel;

    let summary = &report.summary;

    // Header with summary
    let risk_emoji = if summary.critical_count > 0 {
        "🔴"
    } else if summary.high_count > 0 {
        "🟠"
    } else if summary.medium_count > 0 {
        "🟡"
    } else {
        "🟢"
    };

    // Extract file/directory name for display
    let input_name = std::path::Path::new(input_path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(input_path);

    println!("## {} Semantic Analysis: `{}`", risk_emoji, input_name);
    println!();
    println!(
        "**{} statements analyzed** | **{} signals**",
        summary.statements_analyzed, summary.total_reported_signals
    );
    println!();

    // Quick confidence indicator
    let confidence_str = match (&summary.render_completeness, &summary.analysis_confidence) {
        (lexega_core::analyzer::RenderCompleteness::NotRendered, _) => {
            "🔴 **LOW** - template could not be rendered; analysis ran on template text"
        }
        (
            lexega_core::analyzer::RenderCompleteness::Full,
            lexega_core::analyzer::ConfidenceLevel::High,
        ) => "✅ **HIGH** - full render, no placeholders",
        (
            lexega_core::analyzer::RenderCompleteness::Partial,
            lexega_core::analyzer::ConfidenceLevel::High,
        )
        | (
            lexega_core::analyzer::RenderCompleteness::PartialLowImpactOnly,
            lexega_core::analyzer::ConfidenceLevel::High,
        ) => "✅ **HIGH** - partial render, low-impact only",
        (_, lexega_core::analyzer::ConfidenceLevel::Medium) => {
            "⚠️ **MEDIUM** - some high-impact placeholders"
        }
        (_, _) => "🔴 **LOW** - significant placeholders in critical zones",
    };
    println!("**Confidence**: {}", confidence_str);
    println!();
    if let Some(note) = depth_note {
        println!("**Note**: {}", note);
        println!();
    }

    // Collect and sort signals by severity (RiskLevel derives Ord,
    // Info < … < Critical); stable sort keeps report order within a level.
    let mut signals_by_level: Vec<_> = report.signals.iter().collect();
    signals_by_level.sort_by_key(|signal| std::cmp::Reverse(signal.risk_level()));

    // Critical signals
    let critical_signals: Vec<_> = signals_by_level
        .iter()
        .filter(|s| matches!(s.risk_level(), RiskLevel::Critical))
        .collect();

    if !critical_signals.is_empty() {
        println!(
            "### 🔴 Critical ({})
",
            summary.critical_count
        );
        println!("| Signal | Location |");
        println!("|--------|----------|");
        for signal in &critical_signals {
            let location = get_signal_location(signal);
            let message = truncate_for_table(signal.message(), 60);
            println!("| {} | {} |", message, location);
        }
        println!();
    }

    // High signals
    let high_signals: Vec<_> = signals_by_level
        .iter()
        .filter(|s| matches!(s.risk_level(), RiskLevel::High))
        .collect();

    if !high_signals.is_empty() {
        println!(
            "### 🟠 High Risk ({})
",
            summary.high_count
        );
        println!("| Signal | Location |");
        println!("|--------|----------|");
        for signal in &high_signals {
            let location = get_signal_location(signal);
            let message = truncate_for_table(signal.message(), 60);
            println!("| {} | {} |", message, location);
        }
        println!();
    }

    // Medium signals
    let medium_signals: Vec<_> = signals_by_level
        .iter()
        .filter(|s| matches!(s.risk_level(), RiskLevel::Medium))
        .collect();

    if !medium_signals.is_empty() {
        println!(
            "### 🟡 Medium ({})
",
            summary.medium_count
        );
        println!("| Signal | Location |");
        println!("|--------|----------|");
        for signal in &medium_signals {
            let location = get_signal_location(signal);
            let message = truncate_for_table(signal.message(), 60);
            println!("| {} | {} |", message, location);
        }
        println!();
    }

    // Low signals (only show if no higher severity signals exist)
    let low_signals: Vec<_> = signals_by_level
        .iter()
        .filter(|s| matches!(s.risk_level(), RiskLevel::Low))
        .collect();

    if !low_signals.is_empty()
        && summary.critical_count == 0
        && summary.high_count == 0
        && summary.medium_count == 0
    {
        println!(
            "### 🟢 Low ({})
",
            summary.low_count
        );
        println!("| Signal | Location |");
        println!("|--------|----------|");
        for signal in &low_signals {
            let location = get_signal_location(signal);
            let message = truncate_for_table(signal.message(), 60);
            println!("| {} | {} |", message, location);
        }
        println!();
    }

    // Positive signals
    if !report.positive_signals.is_empty() {
        println!(
            "### ✅ Positive Signals ({})
",
            report.positive_signals.len()
        );
        for signal in &report.positive_signals {
            println!("- ✓ {}", signal.message);
            if let Some(details) = &signal.details {
                println!("  - {}", details);
            }
        }
        println!();
    }

    // Details section (collapsible) - expanded signal info
    if !report.signals.is_empty() {
        println!("<details>");
        println!("<summary>📋 Signal Details</summary>");
        println!();

        for signal in &signals_by_level {
            let icon = match signal.risk_level() {
                RiskLevel::Critical => "🔴",
                RiskLevel::High => "🟠",
                RiskLevel::Medium => "🟡",
                RiskLevel::Low => "🟢",
                RiskLevel::Info => "ℹ️",
            };

            println!("#### {} {}", icon, signal.message());

            // Show evidence
            let evidence = signal.evidence();
            if !evidence.is_empty() {
                println!();
                for ev in evidence.iter().take(5) {
                    if let lexega_core::analyzer::RiskEvidence::RuleMatch {
                        line_number,
                        statement_preview,
                        signal_value,
                        location,
                        ..
                    } = ev
                    {
                        let mut parts = Vec::new();
                        if let Some(line) = line_number {
                            parts.push(format!("Line {}", line));
                        }
                        if !signal_value.is_empty() {
                            parts.push(format!("`{}`", signal_value));
                        }
                        if let Some(preview) = statement_preview {
                            if !preview.is_empty() {
                                parts.push(format!("`{}`", preview));
                            }
                        }
                        // Add clickable location link
                        if let Some(loc) = location {
                            parts.push(loc.clone());
                        }
                        if !parts.is_empty() {
                            println!("- {}", parts.join(" • "));
                        }
                    }
                }
                if evidence.len() > 5 {
                    println!("- *(+{} more occurrences)*", evidence.len() - 5);
                }
                println!();
            }
        }

        println!("</details>");
        println!();
    }

    // Transparency section (collapsible)
    println!("<details>");
    println!("<summary>🔍 Analysis Transparency</summary>");
    println!();
    println!("| Metric | Value |");
    println!("|--------|-------|");
    println!(
        "| SQL Statements Analyzed | {} |",
        summary.statements_analyzed
    );
    if summary.statements_skipped > 0 {
        println!(
            "| Unrecognized (could not parse, no analysis) | {} |",
            summary.statements_skipped
        );
    }
    if summary.jinja_blocks > 0 {
        println!("| Jinja Blocks | {} |", summary.jinja_blocks);
    }
    if placeholder_stats.total > 0 {
        println!(
            "| Placeholders | {} ({} high-impact, {} low-impact) |",
            placeholder_stats.total, placeholder_stats.high_impact, placeholder_stats.low_impact
        );
    }
    println!("| Tables Read | {} |", summary.tables_read);
    if summary.tables_written > 0 {
        println!("| Tables Written | {} |", summary.tables_written);
    }
    if summary.ddl_operations > 0 {
        println!("| DDL Operations | {} |", summary.ddl_operations);
    }
    if summary.cross_database {
        let dbs: Vec<String> = summary.databases_accessed.iter().cloned().collect();
        println!("| Cross-Database | Yes ({}) |", dbs.join(", "));
    }
    if summary.cross_schema {
        println!("| Cross-Schema | Yes |");
    }
    println!();
    println!("</details>");
}

/// Extract location string from signal evidence
pub fn get_signal_location(signal: &lexega_core::analyzer::RuleMatch) -> String {
    let evidence = signal.evidence();
    if evidence.is_empty() {
        return "—".to_string();
    }

    // Get first evidence with line number
    for ev in evidence {
        if let lexega_core::analyzer::RiskEvidence::RuleMatch {
            line_number: Some(line),
            ..
        } = ev
        {
            if evidence.len() > 1 {
                return format!("Line {} (+{} more)", line, evidence.len() - 1);
            } else {
                return format!("Line {}", line);
            }
        }
    }

    "—".to_string()
}

pub fn print_signal_explanation(report: &analyzer::AnalysisReport, source: &str, format: &str) {
    // Build the line index once. Used to map source spans on
    // `StatementExplanation` entries to 1-indexed line numbers for
    // display.
    let line_index = analyzer::LineIndex::new(source);

    // Per-family evaluators each push one `StatementExplanation` per
    // statement they handled — the same statement can therefore appear
    // multiple times in `report.statement_explanations` with disjoint
    // rule subsets. Merge by source span so the customer sees a single
    // block per statement, with the union of matched rule IDs.
    let mut by_span: std::collections::BTreeMap<(u32, u32), (String, Vec<String>)> =
        std::collections::BTreeMap::new();
    for e in &report.statement_explanations {
        let key = e.source_span.map(|s| (s.start, s.end)).unwrap_or((0, 0));
        let entry = by_span
            .entry(key)
            .or_insert_with(|| (e.statement_preview.clone(), Vec::new()));
        for r in &e.matched_rules {
            if !entry.1.contains(r) {
                entry.1.push(r.clone());
            }
        }
    }
    for (_, rules) in by_span.values_mut() {
        rules.sort();
    }

    if !by_span.is_empty() {
        // Trace mode was enabled - we have per-statement breakdown.
        let line_for = |start: u32, end: u32| -> usize {
            if start == 0 && end == 0 {
                0
            } else {
                line_index.get_line_number(lexega_core::lexer::token::Span { start, end })
            }
        };

        if format == "json" {
            let statements: Vec<_> = by_span
                .iter()
                .map(|((start, end), (preview, rules))| {
                    serde_json::json!({
                        "line": line_for(*start, *end),
                        "source_span": { "start": *start, "end": *end },
                        "preview": preview,
                        "matched_rules": rules,
                    })
                })
                .collect();
            let output = serde_json::json!({
                "mode": "statement_explanations",
                "statements": statements,
            });
            println!(
                "{}",
                serde_json::to_string_pretty(&output).unwrap_or_else(|e| {
                    eprintln!("Error serializing explanation JSON: {}", e);
                    std::process::exit(1);
                })
            );
        } else if format == "yaml" {
            println!("mode: statement_explanations");
            println!("statements:");
            for ((start, end), (preview, rules)) in &by_span {
                println!("  - line: {}", line_for(*start, *end));
                println!("    source_span: {{ start: {}, end: {} }}", start, end);
                println!("    preview: {:?}", preview);
                if rules.is_empty() {
                    println!("    matched_rules: []");
                } else {
                    println!("    matched_rules:");
                    for r in rules {
                        println!("      - {}", r);
                    }
                }
            }
        } else {
            println!("Signal Explanation (by Statement)");
            println!("==================================");
            println!();
            for ((start, end), (preview, rules)) in &by_span {
                println!("Line {}:", line_for(*start, *end));
                println!("  {}", preview);
                println!();
                if rules.is_empty() {
                    println!("  No rules matched");
                } else {
                    println!("  matched rules:");
                    for r in rules {
                        println!("    - {}", r);
                    }
                }
                println!();
            }
        }
    } else {
        // No per-statement data — the explain surface lives entirely
        // in `statement_explanations` (trace-mode populated). Nothing
        // to render outside trace mode.
        if format == "json" {
            let output = serde_json::json!({
                "mode": "global_signals",
                "note": "Run with --trace for per-statement breakdown",
            });
            println!(
                "{}",
                serde_json::to_string_pretty(&output).unwrap_or_else(|e| {
                    eprintln!("Error serializing explanation JSON: {}", e);
                    std::process::exit(1);
                })
            );
        } else if format == "yaml" {
            println!("mode: global_signals");
            println!("note: Run with --trace for per-statement breakdown");
        } else {
            println!("Signal Explanation (Global View)");
            println!("=================================");
            println!();
            println!("Note: For per-statement breakdown, run with --trace");
        }
    }
}

/// Render `report.statement_signals[].facts` — the per-statement
/// [`lexega_core::facts::StatementFacts`] tree the rules were evaluated
/// against. Populated only in trace mode. JSON output serializes
/// `StatementFacts` directly.
///
/// GROUP BY modifiers (`ROLLUP` / `CUBE` / `GROUPING SETS` /
/// `GROUP BY ALL`) are not on `ScopeFacts`, so the display shows the
/// GROUP BY expressions without them.
pub fn print_fact_explanation(report: &analyzer::AnalysisReport, _source: &str, format: &str) {
    use lexega_core::facts::query::{ScopeKind, TableAccessKind};

    if report.statement_signals.is_empty() {
        eprintln!("Error: --explain-facts requires --trace mode to populate semantic info");
        eprintln!("Try: analyze query.sql --explain-facts (trace is auto-enabled)");
        return;
    }

    if format == "json" {
        // Public-schema JSON: serialize each `StatementFacts` carrier
        // verbatim. The schemars-derived shape is the customer contract.
        let mut facts_json = Vec::new();
        for sig in &report.statement_signals {
            if let Some(ref facts) = sig.facts {
                facts_json.push(serde_json::json!({
                    "line": sig.line_number,
                    "statement": sig.statement_preview.clone(),
                    "facts": facts,
                }));
            }
        }
        let out = serde_json::json!({
            "mode": "statement_facts",
            "total_statements": facts_json.len(),
            "statements": facts_json,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&out).unwrap_or_else(|e| {
                eprintln!("Error serializing facts JSON: {}", e);
                std::process::exit(1);
            })
        );
        return;
    }

    println!("Statement Facts Explanation");
    println!("===========================");
    println!();

    let mut found_any = false;
    for sig in &report.statement_signals {
        let Some(ref facts) = sig.facts else { continue };
        found_any = true;
        println!("Line {}:", sig.line_number);
        println!("  {}", sig.statement_preview);
        println!();
        println!("  Statement Kind: {:?}", facts.kind);

        // Dynamic-SQL taint facts: the recognized dynamic-SQL surface, the
        // argument shape (literal / concat / format / unknown) that drives the
        // injection rules, its parameterization, and the taint splice positions
        // (position × quoting). Gathered from the statement-level field and from
        // any procedure/function body, so `EXEC`, `sp_executesql`, and
        // `EXECUTE IMMEDIATE` — inline or inside a body — all surface here.
        let mut dyn_calls = Vec::new();
        dyn_calls.extend(facts.dynamic_sql_calls.iter());
        if let Some(ddl) = facts.ddl.as_ref() {
            if let Some(body) = ddl.procedure.as_ref().and_then(|p| p.body.as_ref()) {
                dyn_calls.extend(body.dynamic_sql_calls.iter());
            }
            if let Some(body) = ddl.function.as_ref().and_then(|f| f.body.as_ref()) {
                dyn_calls.extend(body.dynamic_sql_calls.iter());
            }
        }
        if !dyn_calls.is_empty() {
            println!("  Dynamic SQL Calls ({}):", dyn_calls.len());
            for call in &dyn_calls {
                println!(
                    "    - {:?}: argument={:?}, parameterization={:?}",
                    call.surface, call.argument, call.parameterization
                );
                if !call.taint_splices.is_empty() {
                    let splices: Vec<String> = call
                        .taint_splices
                        .iter()
                        .map(|s| format!("{:?}/{:?}", s.position, s.quoting))
                        .collect();
                    println!("      Taint splices: {}", splices.join(", "));
                }
            }
        }

        if let Some(query) = facts.query.as_ref() {
            if !query.reads_table.is_empty() {
                println!(
                    "  Tables Read: {}",
                    query
                        .reads_table
                        .iter()
                        .map(|t| t.table.canonical.clone())
                        .collect::<Vec<_>>()
                        .join(", ")
                );
            }
            if !query.writes_table.is_empty() {
                println!(
                    "  Tables Written: {}",
                    query
                        .writes_table
                        .iter()
                        .map(|t| t.table.canonical.clone())
                        .collect::<Vec<_>>()
                        .join(", ")
                );
            }
            if !query.schemas_touched.is_empty() {
                println!(
                    "  Schemas Touched: {}",
                    query
                        .schemas_touched
                        .iter()
                        .map(|s| s.normalized.clone())
                        .collect::<Vec<_>>()
                        .join(", ")
                );
            }

            // Top-level query flags.
            if query.has_where {
                println!("  Has WHERE: true");
            }
            if query.has_tautology_where {
                println!("  Has Tautology WHERE: true");
            }
            if query.has_limit {
                println!("  Has LIMIT: true");
            }
            if query.has_qualify {
                println!("  Has QUALIFY: true");
            }
            if query.has_having {
                println!("  Has HAVING: true");
            }
            if query.has_distinct {
                println!("  Has DISTINCT: true");
            }
            if query.has_implicit_cross_join {
                println!("  Has Implicit CROSS JOIN: true");
            }

            // CTEs / Derived tables surfaced by walking the scope list.
            let ctes: Vec<&_> = query
                .scopes
                .iter()
                .filter(|s| matches!(s.kind, ScopeKind::Cte { .. }))
                .collect();
            if !ctes.is_empty() {
                println!("  CTEs Defined ({}):", ctes.len());
                for scope in &ctes {
                    if let ScopeKind::Cte { name, recursive } = &scope.kind {
                        let rec = if *recursive { " (RECURSIVE)" } else { "" };
                        println!("    - {}{}", name.raw, rec);
                        let bases: Vec<String> = scope
                            .tables
                            .iter()
                            .filter(|t| t.access_kind == TableAccessKind::Read)
                            .map(|t| t.table.canonical.clone())
                            .collect();
                        if !bases.is_empty() {
                            println!("      Base tables: {}", bases.join(", "));
                        }
                    }
                }
            }

            let derived: Vec<&_> = query
                .scopes
                .iter()
                .filter(|s| matches!(s.kind, ScopeKind::DerivedTable { .. }))
                .collect();
            if !derived.is_empty() {
                println!("  Derived Tables ({}):", derived.len());
                for scope in &derived {
                    if let ScopeKind::DerivedTable { alias } = &scope.kind {
                        println!("    - {} (subquery)", alias.raw);
                        let bases: Vec<String> = scope
                            .tables
                            .iter()
                            .filter(|t| t.access_kind == TableAccessKind::Read)
                            .map(|t| t.table.canonical.clone())
                            .collect();
                        if !bases.is_empty() {
                            println!("      Base tables: {}", bases.join(", "));
                        }
                    }
                }
            }

            // Per-scope summary — counts and key contents.
            println!("  Scopes ({}):", query.scopes.len());
            for scope in &query.scopes {
                let kind_label = match &scope.kind {
                    ScopeKind::Outer => "outer".to_string(),
                    ScopeKind::Cte { name, .. } => format!("cte:{}", name.raw),
                    ScopeKind::DerivedTable { alias } => format!("derived:{}", alias.raw),
                    ScopeKind::ScalarSubquery => "scalar_subquery".to_string(),
                    ScopeKind::InSubquery => "in_subquery".to_string(),
                    ScopeKind::ExistsSubquery => "exists_subquery".to_string(),
                    ScopeKind::LateralSubquery => "lateral_subquery".to_string(),
                };
                println!("    - {}:", kind_label);
                if !scope.tables.is_empty() {
                    println!("        tables: {}", scope.tables.len());
                }
                if !scope.joins.is_empty() {
                    println!("        joins: {}", scope.joins.len());
                    for join in &scope.joins {
                        println!(
                            "          - {:?}: {} ⋈ {}",
                            join.kind, join.left.canonical, join.right.canonical
                        );
                    }
                }
                if !scope.where_predicates.is_empty() {
                    println!("        where_predicates: {}", scope.where_predicates.len());
                }
                if !scope.having_predicates.is_empty() {
                    println!(
                        "        having_predicates: {}",
                        scope.having_predicates.len()
                    );
                }
                if !scope.projections.is_empty() {
                    println!("        projections: {}", scope.projections.len());
                }
                if !scope.aggregates.is_empty() {
                    println!("        aggregates ({}):", scope.aggregates.len());
                    for agg in &scope.aggregates {
                        let dist = if agg.distinct { "DISTINCT " } else { "" };
                        let arg_count = agg.args.len();
                        println!(
                            "          - {:?}({}arity={}){}",
                            agg.function,
                            dist,
                            arg_count,
                            if agg.on_nullable_argument {
                                " [nullable arg]"
                            } else {
                                ""
                            }
                        );
                    }
                }
                if !scope.window_functions.is_empty() {
                    println!("        window_functions: {}", scope.window_functions.len());
                }
                if !scope.set_operations.is_empty() {
                    println!("        set_operations ({}):", scope.set_operations.len());
                    for op in &scope.set_operations {
                        println!("          - {:?} ({} branches)", op.kind, op.branch_count);
                    }
                }
                if !scope.star_projections.is_empty() {
                    println!("        star_projections: {}", scope.star_projections.len());
                }
                if !scope.group_by.is_empty() {
                    // GROUP BY modifiers (ROLLUP / CUBE / GROUPING SETS /
                    // ALL) are not on ScopeFacts, so the display shows only
                    // the column count.
                    println!("        group_by: {} expr(s)", scope.group_by.len());
                }
                if !scope.order_by.is_empty() {
                    println!("        order_by ({}):", scope.order_by.len());
                    for ob in &scope.order_by {
                        println!("          - {:?} ({:?})", ob.direction, ob.nulls);
                    }
                }
                if let Some(lim) = scope.limit.as_ref() {
                    let has_offset = lim.offset.is_some();
                    if has_offset {
                        println!("        limit: yes, offset: yes");
                    } else {
                        println!("        limit: yes");
                    }
                }
                if scope.qualify.is_some() {
                    println!("        qualify: yes");
                }
            }
        }

        // Family-specific summaries — just presence + key fields.
        if let Some(ddl) = facts.ddl.as_ref() {
            println!("  DDL: {:?}", ddl.action);
            if let Some(target) = ddl.target.as_ref() {
                println!("    target: {:?} {}", target.kind, target.name.canonical);
            }
        }
        if let Some(priv_facts) = facts.privilege.as_ref() {
            println!("  Privilege: {:?}", priv_facts.kind);
            if let Some(target) = priv_facts.target.as_ref() {
                println!("    target: {:?} {}", target.kind, target.name.canonical);
            }
            if !priv_facts.grantees.is_empty() {
                println!("    grantees: {}", priv_facts.grantees.len());
            }
        }
        if let Some(policy) = facts.policy.as_ref() {
            println!("  Policy: {:?}", policy.kind);
        }
        if let Some(att) = facts.policy_attachment.as_ref() {
            println!(
                "  Policy Attachment: {:?} {:?} on {:?}",
                att.verb, att.target_kind, att.principal_kind
            );
        }
        if let Some(integration) = facts.integration.as_ref() {
            println!("  Integration: {:?}", integration.kind);
        }
        if let Some(use_stmt) = facts.use_stmt.as_ref() {
            println!("  USE: {:?}", use_stmt.target);
        }
        if let Some(comment) = facts.comment.as_ref() {
            println!("  COMMENT ON: {:?}", comment.target_kind);
        }

        println!();
    }

    if !found_any {
        println!("No statement facts extracted.");
        println!("This may indicate that statements were skipped or had no extractable facts.");
    }
}

/// Render `report.statement_explanations` — the v1 rule-engine
/// introspection surface populated when `trace_mode` is on. One block
/// per statement: matched rule IDs, then rejected rule IDs with their
/// path-level rejection reasons (e.g. `kind eq "grant" (actual: "select")`).
///
/// JSON/YAML callers don't invoke this — the
/// `statement_explanations` field serializes automatically via the
/// `AnalysisReport`'s `Serialize` derive. This is for the text /
/// markdown / `--verbose` paths.
pub fn print_rule_explanation(report: &analyzer::AnalysisReport) {
    if report.statement_explanations.is_empty() {
        println!("Rule Evaluation Explanation");
        println!("===========================");
        println!();
        println!("No statement explanations recorded.");
        println!("Run with --trace or --verbose to populate per-statement rule traces.");
        println!();
        return;
    }

    println!("Rule Evaluation Explanation (--verbose)");
    println!("=======================================");
    println!();
    for entry in &report.statement_explanations {
        let header = if entry.statement_preview.is_empty() {
            "Statement:".to_string()
        } else {
            format!("Statement: {}", entry.statement_preview)
        };
        println!("{}", header);

        if let Some(span) = entry.source_span {
            println!("  span: [{}..{}]", span.start, span.end);
        }

        if !entry.matched_rules.is_empty() {
            println!("  matched ({}):", entry.matched_rules.len());
            for rule_id in &entry.matched_rules {
                println!("    + {}", rule_id);
            }
        }

        if !entry.rejected_rules.is_empty() {
            println!("  rejected ({}):", entry.rejected_rules.len());
            for rejected in &entry.rejected_rules {
                println!("    - {}", rejected.rule_id);
                // Surface up to the first 3 unmatched paths per rule
                // so the trace stays scannable; full list is in the
                // serialized JSON / YAML output.
                const MAX_REASONS: usize = 3;
                let reasons = &rejected.explanation.unmatched_paths;
                for reason in reasons.iter().take(MAX_REASONS) {
                    println!("        why: {}", reason);
                }
                if reasons.len() > MAX_REASONS {
                    println!(
                        "        … {} more rejection path(s) (see JSON output for full trace)",
                        reasons.len() - MAX_REASONS
                    );
                }
            }
        }

        if entry.matched_rules.is_empty() && entry.rejected_rules.is_empty() {
            println!("  (no rules evaluated against this statement)");
        }
        println!();
    }
}
