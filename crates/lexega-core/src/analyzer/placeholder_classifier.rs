// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Placeholder Impact Zone Classifier
//!
//! Classifies placeholders based on their position in rendered SQL.
//! Uses lightweight token scanning to determine the SQL clause context
//! (WHERE, FROM, JOIN, SELECT, etc.) without full parsing.

use crate::analyzer::ImpactZone;
use crate::lexer::{tokenize, Keyword, Punctuation, TokenKind};
use crate::template::records::PlaceholderRecord;

/// Classify a placeholder's impact zone based on its position in rendered SQL
///
/// This function tokenizes the SQL and tracks clause context to determine
/// where the placeholder appears (WHERE, FROM, SELECT, etc.)
pub fn classify_placeholder(rendered_sql: &str, placeholder: &PlaceholderRecord) -> ImpactZone {
    // Control-flow placeholders (no position) are not in SQL output
    if placeholder.render_start == 0
        && placeholder.render_end == 0
        && !placeholder.placeholder_text.starts_with("__LEXEGA_PH_")
    {
        return ImpactZone::Other; // Control flow, not in SQL
    }

    // If placeholder wasn't found in output (render_start/end still 0 but is sentinel)
    // it may have been in a false branch - treat as Other
    if placeholder.render_start == 0 && placeholder.render_end == 0 {
        return ImpactZone::Other;
    }

    let placeholder_byte_pos = placeholder.render_start;

    // Tokenize and track clause context
    let lex_result = tokenize(rendered_sql);

    // Track the current clause context as we scan tokens
    let mut current_zone = ImpactZone::Unknown;
    let mut paren_depth = 0;
    let mut zone_at_paren_start: Vec<ImpactZone> = Vec::new();

    // Track if we're in specific statement types
    let mut in_select = false;
    let mut in_insert = false;
    let mut in_update = false;
    let mut in_delete = false;
    let mut in_merge = false;
    let mut _in_create = false;
    let mut _in_alter = false;
    let mut _in_drop = false;

    for token in &lex_result.tokens {
        let token_start = token.span.start as usize;
        let token_end = token.span.end as usize;

        // If we've passed the placeholder position, return current zone
        if token_start > placeholder_byte_pos {
            return current_zone;
        }

        // If this token IS the placeholder, return current zone
        if token_start <= placeholder_byte_pos && token_end > placeholder_byte_pos {
            return current_zone;
        }

        // Track parentheses for subquery/nested context
        match &token.kind {
            TokenKind::Punctuation(Punctuation::LParen) => {
                zone_at_paren_start.push(current_zone.clone());
                paren_depth += 1;
            }
            TokenKind::Punctuation(Punctuation::RParen) if paren_depth > 0 => {
                paren_depth -= 1;
                if let Some(prev_zone) = zone_at_paren_start.pop() {
                    current_zone = prev_zone;
                }
            }
            _ => {}
        }

        // Track statement type and clause keywords
        if let TokenKind::Keyword(kw) = &token.kind {
            match kw {
                // Statement starters
                Keyword::Select => {
                    in_select = true;
                    in_insert = false;
                    in_update = false;
                    in_delete = false;
                    in_merge = false;
                    current_zone = ImpactZone::Select;
                }
                Keyword::Insert => {
                    in_insert = true;
                    current_zone = ImpactZone::DmlTarget;
                }
                Keyword::Update => {
                    in_update = true;
                    current_zone = ImpactZone::DmlTarget;
                }
                Keyword::Delete => {
                    in_delete = true;
                    current_zone = ImpactZone::DmlTarget;
                }
                Keyword::Merge => {
                    in_merge = true;
                    current_zone = ImpactZone::DmlTarget;
                }
                Keyword::Create => {
                    _in_create = true;
                    current_zone = ImpactZone::DdlObject;
                }
                Keyword::Alter => {
                    _in_alter = true;
                    current_zone = ImpactZone::DdlObject;
                }
                Keyword::Drop => {
                    _in_drop = true;
                    current_zone = ImpactZone::DdlObject;
                }

                // Clause transitions within SELECT
                Keyword::From if in_select => {
                    current_zone = ImpactZone::From;
                }
                Keyword::Where => {
                    current_zone = ImpactZone::Where;
                }
                Keyword::Join
                | Keyword::Inner
                | Keyword::Left
                | Keyword::Right
                | Keyword::Full
                | Keyword::Cross
                | Keyword::Natural => {
                    if in_select || in_update || in_delete || in_merge {
                        current_zone = ImpactZone::Join;
                    }
                }
                Keyword::On if matches!(current_zone, ImpactZone::Join | ImpactZone::From) => {
                    current_zone = ImpactZone::Join; // ON clause is part of JOIN
                }
                Keyword::Having => {
                    current_zone = ImpactZone::Having;
                }
                Keyword::Qualify => {
                    current_zone = ImpactZone::Qualify;
                }
                Keyword::Group | Keyword::Order => {
                    current_zone = ImpactZone::OrderBy; // Low impact
                }
                Keyword::Limit | Keyword::Offset | Keyword::Fetch => {
                    current_zone = ImpactZone::Limit;
                }

                // INSERT-specific
                Keyword::Into if in_insert => {
                    current_zone = ImpactZone::DmlTarget;
                }
                Keyword::Values if in_insert => {
                    current_zone = ImpactZone::Other; // Values are data, not structure
                }

                // UPDATE-specific
                Keyword::Set if in_update => {
                    current_zone = ImpactZone::Other; // SET values, not structure
                }

                // Common table expressions
                Keyword::With => {
                    // CTE context - reset to generic, will be Select/From within
                    current_zone = ImpactZone::Other;
                }

                // USING clause (MERGE, DELETE)
                Keyword::Using if in_merge || in_delete => {
                    current_zone = ImpactZone::From;
                }

                // WHEN clause in MERGE
                Keyword::When if in_merge => {
                    current_zone = ImpactZone::Where; // WHEN conditions are like WHERE
                }

                _ => {}
            }
        }
    }

    // The placeholder's recorded position lies in no token.
    current_zone
}

/// Statistics from placeholder classification
#[derive(Debug, Clone, Default)]
pub struct PlaceholderStats {
    pub total: usize,
    pub high_impact: usize,
    pub low_impact: usize,
    pub unknown: usize, // Subset of high_impact (Unknown zone = couldn't classify)
    pub by_source: std::collections::HashMap<String, usize>,
    pub by_kind: std::collections::HashMap<String, usize>,
    pub by_zone: std::collections::HashMap<ImpactZone, usize>,
}

impl PlaceholderStats {
    /// Top placeholder sources: count desc, then name asc, truncated to 5 —
    /// the deterministic shape `PlaceholderSummary` serializes (the backing
    /// map iterates in per-process random order).
    pub fn top_sources(&self) -> Vec<(String, usize)> {
        Self::top_entries(&self.by_source)
    }

    /// Top placeholder kinds, same ordering contract as [`Self::top_sources`].
    pub fn top_kinds(&self) -> Vec<(String, usize)> {
        Self::top_entries(&self.by_kind)
    }

    fn top_entries(map: &std::collections::HashMap<String, usize>) -> Vec<(String, usize)> {
        let mut entries: Vec<_> = map.iter().map(|(k, v)| (k.clone(), *v)).collect();
        entries.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        entries.truncate(5);
        entries
    }

    /// Fold another stats bundle into this one — e.g. SnowSQL `&var`
    /// placeholder counts merged into the Jinja render's counts so both
    /// lower analysis confidence through one carrier.
    pub fn absorb(&mut self, other: &PlaceholderStats) {
        self.total += other.total;
        self.high_impact += other.high_impact;
        self.low_impact += other.low_impact;
        self.unknown += other.unknown;
        for (k, v) in &other.by_source {
            *self.by_source.entry(k.clone()).or_insert(0) += v;
        }
        for (k, v) in &other.by_kind {
            *self.by_kind.entry(k.clone()).or_insert(0) += v;
        }
        for (k, v) in &other.by_zone {
            *self.by_zone.entry(k.clone()).or_insert(0) += v;
        }
    }
}

/// Compute classification statistics from placeholders and rendered SQL
pub fn compute_placeholder_stats(
    rendered_sql: &str,
    placeholders: &[PlaceholderRecord],
) -> PlaceholderStats {
    let mut stats = PlaceholderStats {
        total: placeholders.len(),
        ..Default::default()
    };

    for placeholder in placeholders {
        let zone = classify_placeholder(rendered_sql, placeholder);

        if zone == ImpactZone::Unknown {
            stats.unknown += 1;
            stats.high_impact += 1; // Unknown is always counted as high-impact
        } else if zone.is_high_impact() {
            stats.high_impact += 1;
        } else {
            stats.low_impact += 1;
        }

        *stats
            .by_source
            .entry(placeholder.origin.clone())
            .or_insert(0) += 1;
        *stats
            .by_kind
            .entry(format!("{:?}", placeholder.kind))
            .or_insert(0) += 1;
        *stats.by_zone.entry(zone).or_insert(0) += 1;
    }

    stats
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::template::records::PlaceholderKind;

    fn make_placeholder(id: u32, start: usize, end: usize) -> PlaceholderRecord {
        PlaceholderRecord {
            placeholder_id: id,
            kind: PlaceholderKind::Relation,
            origin: "ref".to_string(),
            source_position: 0,
            render_start: start,
            render_end: end,
            placeholder_text: format!("__LEXEGA_PH_{:06X}__", id),
        }
    }

    #[test]
    fn test_classify_from_clause() {
        let sql = "SELECT * FROM __LEXEGA_PH_000001__";
        let placeholder = make_placeholder(1, 14, 32); // Position of placeholder

        let zone = classify_placeholder(sql, &placeholder);
        assert!(
            matches!(zone, ImpactZone::From),
            "Expected From, got {:?}",
            zone
        );
        assert!(zone.is_high_impact());
    }

    #[test]
    fn test_classify_where_clause() {
        let sql = "SELECT * FROM table_a WHERE __LEXEGA_PH_000001__ = 1";
        let placeholder = make_placeholder(1, 28, 46);

        let zone = classify_placeholder(sql, &placeholder);
        assert!(
            matches!(zone, ImpactZone::Where),
            "Expected Where, got {:?}",
            zone
        );
        assert!(zone.is_high_impact());
    }

    #[test]
    fn test_classify_select_clause() {
        let sql = "SELECT __LEXEGA_PH_000001__, b FROM table_a";
        let placeholder = make_placeholder(1, 7, 25);

        let zone = classify_placeholder(sql, &placeholder);
        assert!(
            matches!(zone, ImpactZone::Select),
            "Expected Select, got {:?}",
            zone
        );
        assert!(!zone.is_high_impact());
    }

    #[test]
    fn test_classify_join_clause() {
        let sql = "SELECT * FROM a JOIN __LEXEGA_PH_000001__ ON a.id = b.id";
        let placeholder = make_placeholder(1, 21, 39);

        let zone = classify_placeholder(sql, &placeholder);
        assert!(
            matches!(zone, ImpactZone::Join),
            "Expected Join, got {:?}",
            zone
        );
        assert!(zone.is_high_impact());
    }

    #[test]
    fn test_control_flow_placeholder() {
        let sql = "SELECT * FROM table_a";
        // Control flow placeholder (not in output)
        let placeholder = PlaceholderRecord {
            placeholder_id: 1,
            kind: PlaceholderKind::AdapterCall,
            origin: "adapter.get_relation".to_string(),
            source_position: 0,
            render_start: 0,
            render_end: 0,
            placeholder_text: "[control-flow:adapter.get_relation]".to_string(),
        };

        let zone = classify_placeholder(sql, &placeholder);
        assert!(
            matches!(zone, ImpactZone::Other),
            "Expected Other, got {:?}",
            zone
        );
        assert!(!zone.is_high_impact());
    }
}
