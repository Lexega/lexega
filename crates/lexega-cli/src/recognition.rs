// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! The recognition build: every source is analyzed with the facts its own
//! structure determines, and templates are analyzed as written.

use std::process;

use lexega_core::analyzer::{AnalysisConfig, AnalysisReport};
use lexega_core::catalog::CatalogIndex;
use lexega_core::dialect::DialectRef;
use lexega_core::rules::Rule;
use lexega_core::template::{
    has_jinja_syntax, render_substituted, RenderArtifacts, SubstitutionConfig, UnresolvedVariables,
    VariableContext,
};
use lexega_core::Engine;

use crate::extension::{
    Capability, Extension, FormatRenderOptions, FormatRenderer, PolicyGate, PolicySetup, Session,
    SessionOptions,
};
use crate::io::{load_catalog_index_from_uri, load_variable_context};
use crate::usage::print_top_usage;

/// Why a template comes back unrendered.
const NOT_RENDERED: &str = "this build does not render templates";

/// The extension of the recognition build. It provides no [`Capability`].
pub struct Recognition;

impl Extension for Recognition {
    fn version(&self) -> String {
        format!("lexega {} (recognition)", env!("CARGO_PKG_VERSION"))
    }

    fn tool_name(&self) -> &'static str {
        "lexega"
    }

    fn offers(&self, _capability: Capability) -> bool {
        false
    }

    fn authorize(&self, _program: &str, needs: &[Capability]) {
        let mut missing: Vec<Capability> = Vec::new();
        for capability in needs {
            if !missing.contains(capability) {
                missing.push(*capability);
            }
        }
        if missing.is_empty() {
            return;
        }
        eprintln!("Error: this run uses features this build does not include:");
        for capability in &missing {
            eprintln!("  - {}", capability.label());
        }
        eprintln!();
        eprintln!("They are part of the full build: https://lexega.com");
        process::exit(1);
    }

    fn open_session(&self, options: SessionOptions<'_>) -> Result<Box<dyn Session>, String> {
        Ok(Box::new(RecognitionSession::open(options)?))
    }

    fn policy_gate(&self, _setup: &PolicySetup<'_>) -> Result<Box<dyn PolicyGate>, String> {
        Err("this build has no policy gate".to_string())
    }

    fn format_renderer(
        &self,
        _options: &FormatRenderOptions<'_>,
    ) -> Result<Box<dyn FormatRenderer>, String> {
        Ok(Box::new(Unrendered))
    }

    fn run_command(&self, _command: &str, _args: &[String]) -> bool {
        false
    }

    fn usage(&self, program: &str) {
        print_top_usage(program);
    }
}

/// The `fmt` renderer of a build that renders no templates.
struct Unrendered;

impl FormatRenderer for Unrendered {
    fn render(&mut self, _source: &str) -> Result<String, String> {
        Err(NOT_RENDERED.to_string())
    }
}

/// A session over the recognition engine.
pub struct RecognitionSession {
    vars: VariableContext,
    substitution: SubstitutionConfig,
    unresolved: UnresolvedVariables,
    custom_rules: Option<Vec<Rule>>,
    trace_mode: bool,
    verbose_mode: bool,
    catalog: Option<CatalogIndex>,
    dialect: Option<DialectRef>,
}

impl RecognitionSession {
    pub fn open(options: SessionOptions<'_>) -> Result<Self, String> {
        let vars = load_variable_context(
            options.jinja_vars,
            options.jinja_var_files,
            options.snowsql_configs,
            options.env_allowlist,
        )
        .map_err(|e| format!("Error loading variables: {}", e))?;
        let catalog = match options.catalog_path {
            Some(path) => Some(
                load_catalog_index_from_uri(path, options.catalog_provider)
                    .map_err(|e| format!("Failed to load catalog: {}", e))?,
            ),
            None => None,
        };
        Ok(Self {
            vars,
            substitution: options.substitution.clone(),
            unresolved: UnresolvedVariables::default(),
            custom_rules: options.custom_rules,
            trace_mode: options.trace_mode,
            verbose_mode: options.verbose_mode,
            catalog,
            dialect: None,
        })
    }
}

impl Session for RecognitionSession {
    fn dialect(&self) -> Option<DialectRef> {
        self.dialect.clone()
    }

    fn set_dialect(&mut self, dialect: Option<DialectRef>) {
        self.dialect = dialect;
    }

    fn render(&self, input: &str) -> Result<RenderArtifacts, String> {
        render_substituted(
            input,
            &self.dialect,
            &self.substitution,
            Some(&self.vars),
            |unresolved| {
                if let Some(warning) = self.unresolved.warning(unresolved) {
                    eprintln!("{}", warning);
                }
            },
            |sql| {
                Ok(if has_jinja_syntax(sql) {
                    RenderArtifacts::not_rendered(sql.to_string(), NOT_RENDERED.to_string())
                } else {
                    RenderArtifacts::raw(sql.to_string())
                })
            },
        )
    }

    fn analyze(
        &self,
        render: &RenderArtifacts,
        source_file: Option<&str>,
    ) -> Result<AnalysisReport, String> {
        let config = AnalysisConfig {
            custom_rules: self.custom_rules.clone(),
            trace_mode: self.trace_mode,
            verbose_mode: self.verbose_mode,
            dialect: self.dialect.clone(),
            ..Default::default()
        };
        Engine::recognition()
            .analyze_risk_with_source_map(render, &config, self.catalog.as_ref(), source_file)
            .map_err(|e| format!("Analysis error: {}", e))
    }
}
