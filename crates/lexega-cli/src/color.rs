// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Terminal color for CLI text output. Hand-rolled ANSI gated on a
//! single resolved on/off decision so escape codes never leak into
//! pipes, files, or non-text output formats. One typed severity->color
//! mapping; no per-call-site styling.

use lexega_core::analyzer::RiskLevel;
use std::io::IsTerminal;

/// User's `--color` preference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColorChoice {
    Auto,
    Always,
    Never,
}

impl ColorChoice {
    pub fn from_cli_arg(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "auto" => Some(ColorChoice::Auto),
            "always" | "yes" | "on" => Some(ColorChoice::Always),
            "never" | "no" | "off" => Some(ColorChoice::Never),
            _ => None,
        }
    }
}

/// Resolved color emitter. `enabled` is decided once at construction.
pub struct Palette {
    enabled: bool,
}

impl Palette {
    /// `Auto` enables color only when stdout is a terminal and
    /// `NO_COLOR` is unset/empty (<https://no-color.org>).
    /// `Always`/`Never` force the decision regardless of TTY.
    pub fn resolve(choice: ColorChoice) -> Self {
        let enabled = match choice {
            ColorChoice::Always => true,
            ColorChoice::Never => false,
            ColorChoice::Auto => {
                let no_color = std::env::var_os("NO_COLOR")
                    .map(|v| !v.is_empty())
                    .unwrap_or(false);
                !no_color && std::io::stdout().is_terminal()
            }
        };
        Palette { enabled }
    }

    /// Wrap `text` in an SGR sequence + reset. No-op when disabled, so
    /// callers always get back printable output.
    fn paint(&self, code: &str, text: &str) -> String {
        if self.enabled {
            format!("\x1b[{}m{}\x1b[0m", code, text)
        } else {
            text.to_string()
        }
    }

    fn severity_code(level: RiskLevel) -> &'static str {
        match level {
            RiskLevel::Critical => "1;91", // bold bright-red
            RiskLevel::High => "91",       // bright-red
            RiskLevel::Medium => "33",     // yellow
            RiskLevel::Low => "34",        // blue
            RiskLevel::Info => "2",        // dim
        }
    }

    /// Color `text` by risk level (severity tags, summary counts).
    pub fn severity(&self, level: RiskLevel, text: &str) -> String {
        self.paint(Self::severity_code(level), text)
    }

    /// Bold (section headers, report title).
    pub fn bold(&self, text: &str) -> String {
        self.paint("1", text)
    }

    /// Dim (subordinate evidence: previews, locations, the ↳ marker).
    pub fn dim(&self, text: &str) -> String {
        self.paint("2", text)
    }

    /// Rule identifiers within evidence lines.
    pub fn rule_id(&self, text: &str) -> String {
        self.paint("36", text) // cyan
    }

    /// Positive / passing markers.
    pub fn success(&self, text: &str) -> String {
        self.paint("32", text) // green
    }
}
