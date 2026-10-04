// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Output builder with automatic span tracking
//!
//! Printer is responsible for:
//! - Building formatted output string
//! - Tracking indentation
//! - Recording span mappings automatically (statement-level)
//! - Keyword case conversion
//! - Whitespace normalization
//! - CST-based trivia preservation (comments, whitespace)
//!
//! ## Newline Architecture
//!
//! **Core Principle**: The formatter controls structural newlines. Line comment trivia
//! ALWAYS includes its mandatory newline (syntactic requirement).
//!
//! Trivia emission uses the V2 source_position cursor plus a single trivia
//! emitter (`emit_trivia_until`), triggered by `push_span`/`push_keyword_span`.
//! - Line comments: text + newline (mandatory - line comment extends to EOL)
//! - Block comments: text only; formatter decides on whitespace/newlines.
//!
//! `TriviaInfo` indicates whether trivia was emitted and whether the source
//! already contained newlines so callers can avoid double-spacing.
//!
//! ## Centralized Trivia Architecture
//!
//! All trivia emission goes through a single path: span-based output methods.
//! When outputting a span, the printer automatically:
//! 1. Emits leading trivia for all tokens up to the span start
//! 2. Outputs the span content
//! 3. Emits trailing trivia for the span's token
//!
//! Statement formatters should rely on push_span(), push_keyword_span(), etc.

use crate::context::span_map::MappingKind;
use crate::context::{FormattedContext, RenderContext};
use crate::cst::Cst;
use crate::formatter::config::{FormatterConfig, IndentStyle, KeywordCase, NewlineStyle};
use crate::formatter::span_tracker::SpanTracker;
use crate::lexer::{Span, TriviaKind};

/// Output builder with automatic span tracking and CST-based trivia preservation
pub struct Printer<'a> {
    /// Formatter configuration
    config: &'a FormatterConfig,

    /// Source text (for reference)
    source: &'a str,

    /// Output buffer
    output: String,

    /// Automatic span tracking (statement-level only)
    span_tracker: SpanTracker,

    /// CST for trivia access (optional - None for legacy mode)
    cst: Option<&'a Cst>,

    /// Typed syntax arena - owns structural tokens (parens, keywords)
    /// Formatter looks up token IDs here, then uses CST to get actual tokens.
    syntax_arena: Option<&'a crate::syntax::SyntaxArena>,

    /// Current indentation level
    indent_level: usize,

    /// Current line position (for alignment)
    line_position: usize,

    /// Whether we're at start of line (for indentation)
    at_line_start: bool,

    /// Token-level tracking enabled (for template rendering)
    token_tracking_enabled: bool,

    /// Last extracted span (for automatic tracking in push())
    last_extracted_span: Option<Span>,

    /// Next token index in CST - used for O(1) amortized token lookup
    /// We process tokens in source order, so we only ever scan forward.
    next_token_idx: usize,

    /// REWORK: Source position cursor (everything before this has been consumed/emitted)
    /// Invariant: All content from 0..source_position has been processed.
    source_position: u32,

    /// Recursion depth tracking (to prevent stack overflow)
    recursion_depth: usize,

    /// Maximum recursion depth allowed (default: 100)
    max_recursion_depth: usize,
}

impl<'a> Printer<'a> {
    /// Create new printer with CST-based trivia support
    ///
    /// # Arguments
    /// * `config` - Formatter configuration
    /// * `source` - Source text
    /// * `cst` - Optional CST for trivia access (None for legacy mode without comments)
    pub fn new(config: &'a FormatterConfig, source: &'a str, cst: Option<&'a Cst>) -> Self {
        let estimated_capacity = (source.len() as f32 * 1.8) as usize;

        Self {
            config,
            source,
            output: String::with_capacity(estimated_capacity),
            span_tracker: SpanTracker::new(),
            cst,
            syntax_arena: None,
            indent_level: 0,
            line_position: 0,
            at_line_start: true,
            token_tracking_enabled: false,
            last_extracted_span: None,
            next_token_idx: 0,
            source_position: 0,
            recursion_depth: 0,
            max_recursion_depth: 150,
        }
    }

    /// Set the syntax arena for token lookups
    ///
    /// The syntax arena owns structural tokens (parens, keywords).
    /// Call this after creating the printer to enable syntax-layer token access.
    pub fn set_syntax_arena(&mut self, arena: &'a crate::syntax::SyntaxArena) {
        self.syntax_arena = Some(arena);
    }

    /// Get the syntax arena reference (if available)
    pub fn syntax_arena(&self) -> Option<&crate::syntax::SyntaxArena> {
        self.syntax_arena
    }

    /// Enter a recursive formatting call
    ///
    /// Returns error if recursion depth exceeds limit.
    /// Must be paired with `exit_recursion()` on all code paths.
    pub fn enter_recursion(
        &mut self,
        context: &str,
    ) -> Result<(), crate::formatter::FormatterError> {
        self.recursion_depth += 1;
        if self.recursion_depth > self.max_recursion_depth {
            return Err(crate::formatter::FormatterError::RecursionLimit(format!(
                "Recursion limit exceeded while formatting {}: maximum depth is {}",
                context, self.max_recursion_depth
            )));
        }
        Ok(())
    }

    /// Exit a recursive formatting call
    ///
    /// Must be called on all code paths after `enter_recursion()`.
    pub fn exit_recursion(&mut self) {
        if self.recursion_depth > 0 {
            self.recursion_depth -= 1;
        }
    }

    /// Enable token-level tracking (for template rendering only)
    ///
    /// Call this before formatting starts if the source contains Jinja templates.
    /// This enables fine-grained span tracking needed for reverse mapping.
    pub fn enable_token_tracking(&mut self) {
        self.token_tracking_enabled = true;
        self.span_tracker.enable_token_tracking();
    }

    /// Get CST reference (if available)
    pub fn cst(&self) -> Option<&Cst> {
        self.cst
    }

    /// Get the current token index for debugging
    pub fn get_token_index(&self) -> usize {
        self.next_token_idx
    }

    /// Get a token by its ID from the CST.
    ///
    /// This is used by the syntax layer to access tokens by ID.
    /// Returns None if CST is not available.
    pub fn get_token_by_id(&self, id: crate::cst::TokenId) -> Option<&crate::lexer::Token> {
        self.cst.map(|cst| cst.get_token(id))
    }

    /// Push a token by its ID, preserving trivia.
    ///
    /// This is the preferred method for emitting structural tokens (parens, keywords)
    /// that are tracked in the syntax layer. It:
    /// 1. Looks up the token by ID
    /// 2. Emits leading trivia
    /// 3. Emits the token's lexeme
    /// 4. Emits trailing trivia
    pub fn push_token_id(&mut self, id: crate::cst::TokenId) {
        if let Some(cst) = self.cst {
            let token = cst.get_token(id);
            // Emit the token's span (which handles trivia)
            self.push_span(token.span);
        }
    }

    /// Push a keyword token by ID with keyword case conversion applied.
    ///
    /// Similar to push_token_id, but applies keyword casing from config.
    /// Use this for SQL keywords (SELECT, FROM, WHERE, IN, etc.) when you have a TokenId.
    pub fn push_keyword_token_id(&mut self, id: crate::cst::TokenId) {
        if let Some(cst) = self.cst {
            let token = cst.get_token(id);
            // Use push_keyword_span to apply keyword casing
            self.push_keyword_span(token.span);
        }
    }

    // =========================================================================
    // =========================================================================
    // CST node access — zero-copy wrappers over SyntaxArena
    //
    // Returns Option<&'a SyntaxFoo> with explicit 'a lifetime tied to the
    // arena, NOT to &self. This means:
    //   1. Zero copies/clones — callers get a direct reference into the arena
    //   2. No borrow conflicts — callers can interleave CST reads with
    //      Printer writes because the returned &'a ref doesn't borrow Printer
    // =========================================================================

    pub fn get_alter_aggregation_policy_action(
        &self,
        id: crate::syntax::SyntaxAlterAggregationPolicyActionId,
    ) -> Option<&'a crate::syntax::SyntaxAlterAggregationPolicyAction> {
        self.syntax_arena
            .map(|arena| arena.get_alter_aggregation_policy_action(id))
    }

    pub fn get_alter_aggregation_policy_stmt(
        &self,
        id: crate::syntax::SyntaxAlterAggregationPolicyStmtId,
    ) -> Option<&'a crate::syntax::SyntaxAlterAggregationPolicy> {
        self.syntax_arena
            .map(|arena| arena.get_alter_aggregation_policy_stmt(id))
    }

    pub fn get_alter_api_integration_action(
        &self,
        id: crate::syntax::SyntaxAlterApiIntegrationActionId,
    ) -> Option<&'a crate::syntax::SyntaxAlterApiIntegrationAction> {
        self.syntax_arena
            .map(|arena| arena.get_alter_api_integration_action(id))
    }

    pub fn get_alter_api_integration_stmt(
        &self,
        id: crate::syntax::SyntaxAlterApiIntegrationStmtId,
    ) -> Option<&'a crate::syntax::SyntaxAlterApiIntegration> {
        self.syntax_arena
            .map(|arena| arena.get_alter_api_integration_stmt(id))
    }

    pub fn get_alter_authentication_policy_action(
        &self,
        id: crate::syntax::SyntaxAlterAuthenticationPolicyActionId,
    ) -> Option<&'a crate::syntax::SyntaxAlterAuthenticationPolicyAction> {
        self.syntax_arena
            .map(|arena| arena.get_alter_authentication_policy_action(id))
    }

    pub fn get_alter_authentication_policy_stmt(
        &self,
        id: crate::syntax::SyntaxAlterAuthenticationPolicyStmtId,
    ) -> Option<&'a crate::syntax::SyntaxAlterAuthenticationPolicy> {
        self.syntax_arena
            .map(|arena| arena.get_alter_authentication_policy_stmt(id))
    }

    pub fn get_alter_domain_stmt(
        &self,
        id: crate::syntax::SyntaxAlterDomainStmtId,
    ) -> Option<&'a crate::syntax::SyntaxAlterDomainStmt> {
        self.syntax_arena
            .map(|arena| arena.get_alter_domain_stmt(id))
    }

    pub fn get_alter_dynamic_table_stmt(
        &self,
        id: crate::syntax::SyntaxAlterDynamicTableStmtId,
    ) -> Option<&'a crate::syntax::SyntaxAlterDynamicTableStmt> {
        self.syntax_arena
            .map(|arena| arena.get_alter_dynamic_table_stmt(id))
    }

    pub fn get_alter_external_access_integration_action(
        &self,
        id: crate::syntax::SyntaxAlterExternalAccessIntegrationActionId,
    ) -> Option<&'a crate::syntax::SyntaxAlterExternalAccessIntegrationAction> {
        self.syntax_arena
            .map(|arena| arena.get_alter_external_access_integration_action(id))
    }

    pub fn get_alter_external_access_integration_stmt(
        &self,
        id: crate::syntax::SyntaxAlterExternalAccessIntegrationStmtId,
    ) -> Option<&'a crate::syntax::SyntaxAlterExternalAccessIntegration> {
        self.syntax_arena
            .map(|arena| arena.get_alter_external_access_integration_stmt(id))
    }

    pub fn get_alter_index_stmt(
        &self,
        id: crate::syntax::SyntaxAlterIndexStmtId,
    ) -> Option<&'a crate::syntax::SyntaxAlterIndexStmt> {
        self.syntax_arena
            .map(|arena| arena.get_alter_index_stmt(id))
    }

    pub fn get_alter_masking_policy_action(
        &self,
        id: crate::syntax::SyntaxAlterMaskingPolicyActionId,
    ) -> Option<&'a crate::syntax::SyntaxAlterMaskingPolicyAction> {
        self.syntax_arena
            .map(|arena| arena.get_alter_masking_policy_action(id))
    }

    pub fn get_alter_masking_policy_stmt(
        &self,
        id: crate::syntax::SyntaxAlterMaskingPolicyStmtId,
    ) -> Option<&'a crate::syntax::SyntaxAlterMaskingPolicyStmt> {
        self.syntax_arena
            .map(|arena| arena.get_alter_masking_policy_stmt(id))
    }

    pub fn get_alter_network_policy_action(
        &self,
        id: crate::syntax::SyntaxAlterNetworkPolicyActionId,
    ) -> Option<&'a crate::syntax::SyntaxAlterNetworkPolicyAction> {
        self.syntax_arena
            .map(|arena| arena.get_alter_network_policy_action(id))
    }

    pub fn get_alter_network_policy_stmt(
        &self,
        id: crate::syntax::SyntaxAlterNetworkPolicyId,
    ) -> Option<&'a crate::syntax::SyntaxAlterNetworkPolicy> {
        self.syntax_arena
            .map(|arena| arena.get_alter_network_policy_stmt(id))
    }

    pub fn get_alter_password_policy_action(
        &self,
        id: crate::syntax::SyntaxAlterPasswordPolicyActionId,
    ) -> Option<&'a crate::syntax::SyntaxAlterPasswordPolicyAction> {
        self.syntax_arena
            .map(|arena| arena.get_alter_password_policy_action(id))
    }

    pub fn get_alter_password_policy_stmt(
        &self,
        id: crate::syntax::SyntaxAlterPasswordPolicyStmtId,
    ) -> Option<&'a crate::syntax::SyntaxAlterPasswordPolicy> {
        self.syntax_arena
            .map(|arena| arena.get_alter_password_policy_stmt(id))
    }

    pub fn get_alter_pg_policy_stmt(
        &self,
        id: crate::syntax::SyntaxAlterPgPolicyStmtId,
    ) -> Option<&'a crate::syntax::SyntaxAlterPgPolicyStmt> {
        self.syntax_arena
            .map(|arena| arena.get_alter_pg_policy_stmt(id))
    }

    pub fn get_alter_pg_trigger_stmt(
        &self,
        id: crate::syntax::SyntaxAlterPgTriggerStmtId,
    ) -> Option<&'a crate::syntax::SyntaxAlterPgTriggerStmt> {
        self.syntax_arena
            .map(|arena| arena.get_alter_pg_trigger_stmt(id))
    }

    pub fn get_alter_projection_policy_action(
        &self,
        id: crate::syntax::SyntaxAlterProjectionPolicyActionId,
    ) -> Option<&'a crate::syntax::SyntaxAlterProjectionPolicyAction> {
        self.syntax_arena
            .map(|arena| arena.get_alter_projection_policy_action(id))
    }

    pub fn get_alter_projection_policy_stmt(
        &self,
        id: crate::syntax::SyntaxAlterProjectionPolicyStmtId,
    ) -> Option<&'a crate::syntax::SyntaxAlterProjectionPolicy> {
        self.syntax_arena
            .map(|arena| arena.get_alter_projection_policy_stmt(id))
    }

    pub fn get_alter_row_access_policy_action(
        &self,
        id: crate::syntax::SyntaxAlterRowAccessPolicyActionId,
    ) -> Option<&'a crate::syntax::SyntaxAlterRowAccessPolicyAction> {
        self.syntax_arena
            .map(|arena| arena.get_alter_row_access_policy_action(id))
    }

    pub fn get_alter_row_access_policy_stmt(
        &self,
        id: crate::syntax::SyntaxAlterRowAccessPolicyStmtId,
    ) -> Option<&'a crate::syntax::SyntaxAlterRowAccessPolicyStmt> {
        self.syntax_arena
            .map(|arena| arena.get_alter_row_access_policy_stmt(id))
    }

    pub fn get_alter_sequence_stmt(
        &self,
        id: crate::syntax::SyntaxAlterSequenceStmtId,
    ) -> Option<&'a crate::syntax::SyntaxAlterSequenceStmt> {
        self.syntax_arena
            .map(|arena| arena.get_alter_sequence_stmt(id))
    }

    pub fn get_alter_session_policy_action(
        &self,
        id: crate::syntax::SyntaxAlterSessionPolicyActionId,
    ) -> Option<&'a crate::syntax::SyntaxAlterSessionPolicyAction> {
        self.syntax_arena
            .map(|arena| arena.get_alter_session_policy_action(id))
    }

    pub fn get_alter_session_policy_stmt(
        &self,
        id: crate::syntax::SyntaxAlterSessionPolicyStmtId,
    ) -> Option<&'a crate::syntax::SyntaxAlterSessionPolicy> {
        self.syntax_arena
            .map(|arena| arena.get_alter_session_policy_stmt(id))
    }

    pub fn get_alter_stage_action(
        &self,
        id: crate::syntax::SyntaxAlterStageActionId,
    ) -> Option<&'a crate::syntax::SyntaxAlterStageAction> {
        self.syntax_arena
            .map(|arena| arena.get_alter_stage_action(id))
    }

    pub fn get_alter_stage_stmt(
        &self,
        id: crate::syntax::SyntaxAlterStageStmtId,
    ) -> Option<&'a crate::syntax::SyntaxAlterStageStmt> {
        self.syntax_arena
            .map(|arena| arena.get_alter_stage_stmt(id))
    }

    pub fn get_alter_storage_integration_action(
        &self,
        id: crate::syntax::SyntaxAlterStorageIntegrationActionId,
    ) -> Option<&'a crate::syntax::SyntaxAlterStorageIntegrationAction> {
        self.syntax_arena
            .map(|arena| arena.get_alter_storage_integration_action(id))
    }

    pub fn get_alter_storage_integration_stmt(
        &self,
        id: crate::syntax::SyntaxAlterStorageIntegrationStmtId,
    ) -> Option<&'a crate::syntax::SyntaxAlterStorageIntegration> {
        self.syntax_arena
            .map(|arena| arena.get_alter_storage_integration_stmt(id))
    }

    pub fn get_alter_stream_action(
        &self,
        id: crate::syntax::SyntaxAlterStreamActionId,
    ) -> Option<&'a crate::syntax::SyntaxAlterStreamAction> {
        self.syntax_arena
            .map(|arena| arena.get_alter_stream_action(id))
    }

    pub fn get_alter_stream_stmt(
        &self,
        id: crate::syntax::SyntaxAlterStreamStmtId,
    ) -> Option<&'a crate::syntax::SyntaxAlterStreamStmt> {
        self.syntax_arena
            .map(|arena| arena.get_alter_stream_stmt(id))
    }

    pub fn get_alter_table_action(
        &self,
        id: crate::syntax::SyntaxAlterTableActionId,
    ) -> Option<&'a crate::syntax::SyntaxAlterTableAction> {
        self.syntax_arena
            .map(|arena| arena.get_alter_table_action(id))
    }

    pub fn get_alter_table_action_list(
        &self,
        id: crate::syntax::SyntaxAlterTableActionListId,
    ) -> Option<&'a crate::syntax::SyntaxAlterTableActionList> {
        self.syntax_arena
            .map(|arena| arena.get_alter_table_action_list(id))
    }

    pub fn get_alter_table_stmt(
        &self,
        id: crate::syntax::SyntaxAlterTableStmtId,
    ) -> Option<&'a crate::syntax::SyntaxAlterTableStmt> {
        self.syntax_arena
            .map(|arena| arena.get_alter_table_stmt(id))
    }

    pub fn get_alter_type_stmt(
        &self,
        id: crate::syntax::SyntaxAlterTypeStmtId,
    ) -> Option<&'a crate::syntax::SyntaxAlterTypeStmt> {
        self.syntax_arena.map(|arena| arena.get_alter_type_stmt(id))
    }

    pub fn get_analyze_stmt(
        &self,
        id: crate::syntax::SyntaxAnalyzeStmtId,
    ) -> Option<&'a crate::syntax::SyntaxAnalyzeStmt> {
        self.syntax_arena.map(|arena| arena.get_analyze_stmt(id))
    }

    pub fn get_array_literal(
        &self,
        id: crate::syntax::SyntaxArrayLiteralId,
    ) -> Option<&'a crate::syntax::SyntaxArrayLiteral> {
        self.syntax_arena.map(|arena| arena.get_array_literal(id))
    }

    pub fn get_array_subscript(
        &self,
        id: crate::syntax::SyntaxArraySubscriptId,
    ) -> Option<&'a crate::syntax::SyntaxArraySubscript> {
        self.syntax_arena.map(|arena| arena.get_array_subscript(id))
    }

    pub fn get_at_time_zone(
        &self,
        id: crate::syntax::SyntaxAtTimeZoneId,
    ) -> Option<&'a crate::syntax::SyntaxAtTimeZone> {
        self.syntax_arena.map(|arena| arena.get_at_time_zone(id))
    }

    pub fn get_between_expr(
        &self,
        id: crate::syntax::SyntaxBetweenExprId,
    ) -> Option<&'a crate::syntax::SyntaxBetweenExpr> {
        self.syntax_arena.map(|arena| arena.get_between_expr(id))
    }

    pub fn get_binary_op(
        &self,
        id: crate::syntax::SyntaxBinaryOpId,
    ) -> Option<&'a crate::syntax::SyntaxBinaryOp> {
        self.syntax_arena.map(|arena| arena.get_binary_op(id))
    }

    pub fn get_bracket_field(
        &self,
        id: crate::syntax::SyntaxBracketFieldId,
    ) -> Option<&'a crate::syntax::SyntaxBracketField> {
        self.syntax_arena.map(|arena| arena.get_bracket_field(id))
    }

    pub fn get_call_stmt(
        &self,
        id: crate::syntax::SyntaxCallStmtId,
    ) -> Option<&'a crate::syntax::SyntaxCallStmt> {
        self.syntax_arena.map(|arena| arena.get_call_stmt(id))
    }

    pub fn get_case_expr(
        &self,
        id: crate::syntax::SyntaxCaseExprId,
    ) -> Option<&'a crate::syntax::SyntaxCaseExpr> {
        self.syntax_arena.map(|arena| arena.get_case_expr(id))
    }

    pub fn get_cast_expr(
        &self,
        id: crate::syntax::SyntaxCastExprId,
    ) -> Option<&'a crate::syntax::SyntaxCastExpr> {
        self.syntax_arena.map(|arena| arena.get_cast_expr(id))
    }

    pub fn get_collate(
        &self,
        id: crate::syntax::SyntaxCollateId,
    ) -> Option<&'a crate::syntax::SyntaxCollate> {
        self.syntax_arena.map(|arena| arena.get_collate(id))
    }

    pub fn get_colon_field(
        &self,
        id: crate::syntax::SyntaxColonFieldId,
    ) -> Option<&'a crate::syntax::SyntaxColonField> {
        self.syntax_arena.map(|arena| arena.get_colon_field(id))
    }

    pub fn get_comment_on_stmt(
        &self,
        id: crate::syntax::SyntaxCommentOnStmtId,
    ) -> Option<&'a crate::syntax::SyntaxCommentOnStmt> {
        self.syntax_arena.map(|arena| arena.get_comment_on_stmt(id))
    }

    pub fn get_create_aggregation_policy(
        &self,
        id: crate::syntax::SyntaxCreateAggregationPolicyId,
    ) -> Option<&'a crate::syntax::SyntaxCreateAggregationPolicy> {
        self.syntax_arena
            .map(|arena| arena.get_create_aggregation_policy(id))
    }

    pub fn get_create_api_integration(
        &self,
        id: crate::syntax::SyntaxCreateApiIntegrationId,
    ) -> Option<&'a crate::syntax::SyntaxCreateApiIntegration> {
        self.syntax_arena
            .map(|arena| arena.get_create_api_integration(id))
    }

    pub fn get_create_authentication_policy(
        &self,
        id: crate::syntax::SyntaxCreateAuthenticationPolicyId,
    ) -> Option<&'a crate::syntax::SyntaxCreateAuthenticationPolicy> {
        self.syntax_arena
            .map(|arena| arena.get_create_authentication_policy(id))
    }

    pub fn get_create_domain_stmt(
        &self,
        id: crate::syntax::SyntaxCreateDomainStmtId,
    ) -> Option<&'a crate::syntax::SyntaxCreateDomainStmt> {
        self.syntax_arena
            .map(|arena| arena.get_create_domain_stmt(id))
    }

    pub fn get_create_extension_stmt(
        &self,
        id: crate::syntax::SyntaxCreateExtensionStmtId,
    ) -> Option<&'a crate::syntax::SyntaxCreateExtensionStmt> {
        self.syntax_arena
            .map(|arena| arena.get_create_extension_stmt(id))
    }

    pub fn get_create_external_access_integration(
        &self,
        id: crate::syntax::SyntaxCreateExternalAccessIntegrationId,
    ) -> Option<&'a crate::syntax::SyntaxCreateExternalAccessIntegration> {
        self.syntax_arena
            .map(|arena| arena.get_create_external_access_integration(id))
    }

    pub fn get_create_index_stmt(
        &self,
        id: crate::syntax::SyntaxCreateIndexStmtId,
    ) -> Option<&'a crate::syntax::SyntaxCreateIndexStmt> {
        self.syntax_arena
            .map(|arena| arena.get_create_index_stmt(id))
    }

    pub fn get_create_masking_policy(
        &self,
        id: crate::syntax::SyntaxCreateMaskingPolicyId,
    ) -> Option<&'a crate::syntax::SyntaxCreateMaskingPolicy> {
        self.syntax_arena
            .map(|arena| arena.get_create_masking_policy(id))
    }

    pub fn get_create_network_policy(
        &self,
        id: crate::syntax::SyntaxCreateNetworkPolicyId,
    ) -> Option<&'a crate::syntax::SyntaxCreateNetworkPolicy> {
        self.syntax_arena
            .map(|arena| arena.get_create_network_policy(id))
    }

    pub fn get_create_password_policy(
        &self,
        id: crate::syntax::SyntaxCreatePasswordPolicyId,
    ) -> Option<&'a crate::syntax::SyntaxCreatePasswordPolicy> {
        self.syntax_arena
            .map(|arena| arena.get_create_password_policy(id))
    }

    pub fn get_create_pg_policy_stmt(
        &self,
        id: crate::syntax::SyntaxCreatePgPolicyStmtId,
    ) -> Option<&'a crate::syntax::SyntaxCreatePgPolicyStmt> {
        self.syntax_arena
            .map(|arena| arena.get_create_pg_policy_stmt(id))
    }

    pub fn get_create_pg_trigger_stmt(
        &self,
        id: crate::syntax::SyntaxCreatePgTriggerStmtId,
    ) -> Option<&'a crate::syntax::SyntaxCreatePgTriggerStmt> {
        self.syntax_arena
            .map(|arena| arena.get_create_pg_trigger_stmt(id))
    }

    pub fn get_create_projection_policy(
        &self,
        id: crate::syntax::SyntaxCreateProjectionPolicyId,
    ) -> Option<&'a crate::syntax::SyntaxCreateProjectionPolicy> {
        self.syntax_arena
            .map(|arena| arena.get_create_projection_policy(id))
    }

    pub fn get_create_row_access_policy(
        &self,
        id: crate::syntax::SyntaxCreateRowAccessPolicyId,
    ) -> Option<&'a crate::syntax::SyntaxCreateRowAccessPolicy> {
        self.syntax_arena
            .map(|arena| arena.get_create_row_access_policy(id))
    }

    pub fn get_create_sequence_stmt(
        &self,
        id: crate::syntax::SyntaxCreateSequenceStmtId,
    ) -> Option<&'a crate::syntax::SyntaxCreateSequenceStmt> {
        self.syntax_arena
            .map(|arena| arena.get_create_sequence_stmt(id))
    }

    pub fn get_create_session_policy(
        &self,
        id: crate::syntax::SyntaxCreateSessionPolicyId,
    ) -> Option<&'a crate::syntax::SyntaxCreateSessionPolicy> {
        self.syntax_arena
            .map(|arena| arena.get_create_session_policy(id))
    }

    pub fn get_create_storage_integration(
        &self,
        id: crate::syntax::SyntaxCreateStorageIntegrationId,
    ) -> Option<&'a crate::syntax::SyntaxCreateStorageIntegration> {
        self.syntax_arena
            .map(|arena| arena.get_create_storage_integration(id))
    }

    pub fn get_create_stream(
        &self,
        id: crate::syntax::SyntaxCreateStreamId,
    ) -> Option<&'a crate::syntax::SyntaxCreateStream> {
        self.syntax_arena.map(|arena| arena.get_create_stream(id))
    }

    pub fn get_create_type_stmt(
        &self,
        id: crate::syntax::SyntaxCreateTypeStmtId,
    ) -> Option<&'a crate::syntax::SyntaxCreateTypeStmt> {
        self.syntax_arena
            .map(|arena| arena.get_create_type_stmt(id))
    }

    pub fn get_cte(&self, id: crate::syntax::SyntaxCteId) -> Option<&'a crate::syntax::SyntaxCte> {
        self.syntax_arena.map(|arena| arena.get_cte(id))
    }

    pub fn get_define_symbol(
        &self,
        id: crate::syntax::SyntaxDefineSymbolId,
    ) -> Option<&'a crate::syntax::SyntaxDefineSymbol> {
        self.syntax_arena.map(|arena| arena.get_define_symbol(id))
    }

    pub fn get_describe_history_stmt(
        &self,
        id: crate::syntax::SyntaxDescribeHistoryStmtId,
    ) -> Option<&'a crate::syntax::SyntaxDescribeHistoryStmt> {
        self.syntax_arena
            .map(|arena| arena.get_describe_history_stmt(id))
    }

    pub fn get_distinct_on(
        &self,
        id: crate::syntax::SyntaxDistinctOnId,
    ) -> Option<&'a crate::syntax::SyntaxDistinctOn> {
        self.syntax_arena.map(|arena| arena.get_distinct_on(id))
    }

    pub fn get_do_block_stmt(
        &self,
        id: crate::syntax::SyntaxDoBlockStmtId,
    ) -> Option<&'a crate::syntax::SyntaxDoBlockStmt> {
        self.syntax_arena.map(|arena| arena.get_do_block_stmt(id))
    }

    pub fn get_dot_field(
        &self,
        id: crate::syntax::SyntaxDotFieldId,
    ) -> Option<&'a crate::syntax::SyntaxDotField> {
        self.syntax_arena.map(|arena| arena.get_dot_field(id))
    }

    pub fn get_drop_aggregation_policy(
        &self,
        id: crate::syntax::SyntaxDropAggregationPolicyId,
    ) -> Option<&'a crate::syntax::SyntaxDropAggregationPolicy> {
        self.syntax_arena
            .map(|arena| arena.get_drop_aggregation_policy(id))
    }

    pub fn get_drop_all_row_access_policies(
        &self,
        id: crate::syntax::SyntaxDropAllRowAccessPoliciesId,
    ) -> Option<&'a crate::syntax::SyntaxDropAllRowAccessPolicies> {
        self.syntax_arena
            .map(|arena| arena.get_drop_all_row_access_policies(id))
    }

    pub fn get_drop_api_integration(
        &self,
        id: crate::syntax::SyntaxDropApiIntegrationId,
    ) -> Option<&'a crate::syntax::SyntaxDropApiIntegration> {
        self.syntax_arena
            .map(|arena| arena.get_drop_api_integration(id))
    }

    pub fn get_drop_authentication_policy(
        &self,
        id: crate::syntax::SyntaxDropAuthenticationPolicyId,
    ) -> Option<&'a crate::syntax::SyntaxDropAuthenticationPolicy> {
        self.syntax_arena
            .map(|arena| arena.get_drop_authentication_policy(id))
    }

    pub fn get_drop_domain_stmt(
        &self,
        id: crate::syntax::SyntaxDropDomainStmtId,
    ) -> Option<&'a crate::syntax::SyntaxDropDomainStmt> {
        self.syntax_arena
            .map(|arena| arena.get_drop_domain_stmt(id))
    }

    pub fn get_drop_external_access_integration(
        &self,
        id: crate::syntax::SyntaxDropExternalAccessIntegrationId,
    ) -> Option<&'a crate::syntax::SyntaxDropExternalAccessIntegration> {
        self.syntax_arena
            .map(|arena| arena.get_drop_external_access_integration(id))
    }

    pub fn get_drop_masking_policy(
        &self,
        id: crate::syntax::SyntaxDropMaskingPolicyId,
    ) -> Option<&'a crate::syntax::SyntaxDropMaskingPolicy> {
        self.syntax_arena
            .map(|arena| arena.get_drop_masking_policy(id))
    }

    pub fn get_drop_network_policy(
        &self,
        id: crate::syntax::SyntaxDropNetworkPolicyId,
    ) -> Option<&'a crate::syntax::SyntaxDropNetworkPolicy> {
        self.syntax_arena
            .map(|arena| arena.get_drop_network_policy(id))
    }

    pub fn get_drop_password_policy(
        &self,
        id: crate::syntax::SyntaxDropPasswordPolicyId,
    ) -> Option<&'a crate::syntax::SyntaxDropPasswordPolicy> {
        self.syntax_arena
            .map(|arena| arena.get_drop_password_policy(id))
    }

    pub fn get_drop_pg_policy_stmt(
        &self,
        id: crate::syntax::SyntaxDropPgPolicyStmtId,
    ) -> Option<&'a crate::syntax::SyntaxDropPgPolicyStmt> {
        self.syntax_arena
            .map(|arena| arena.get_drop_pg_policy_stmt(id))
    }

    pub fn get_drop_pg_trigger_stmt(
        &self,
        id: crate::syntax::SyntaxDropPgTriggerStmtId,
    ) -> Option<&'a crate::syntax::SyntaxDropPgTriggerStmt> {
        self.syntax_arena
            .map(|arena| arena.get_drop_pg_trigger_stmt(id))
    }

    pub fn get_drop_projection_policy(
        &self,
        id: crate::syntax::SyntaxDropProjectionPolicyId,
    ) -> Option<&'a crate::syntax::SyntaxDropProjectionPolicy> {
        self.syntax_arena
            .map(|arena| arena.get_drop_projection_policy(id))
    }

    pub fn get_drop_row_access_policy(
        &self,
        id: crate::syntax::SyntaxDropRowAccessPolicyId,
    ) -> Option<&'a crate::syntax::SyntaxDropRowAccessPolicy> {
        self.syntax_arena
            .map(|arena| arena.get_drop_row_access_policy(id))
    }

    pub fn get_drop_session_policy(
        &self,
        id: crate::syntax::SyntaxDropSessionPolicyId,
    ) -> Option<&'a crate::syntax::SyntaxDropSessionPolicy> {
        self.syntax_arena
            .map(|arena| arena.get_drop_session_policy(id))
    }

    pub fn get_drop_storage_integration(
        &self,
        id: crate::syntax::SyntaxDropStorageIntegrationId,
    ) -> Option<&'a crate::syntax::SyntaxDropStorageIntegration> {
        self.syntax_arena
            .map(|arena| arena.get_drop_storage_integration(id))
    }

    pub fn get_drop_stream(
        &self,
        id: crate::syntax::SyntaxDropStreamId,
    ) -> Option<&'a crate::syntax::SyntaxDropStream> {
        self.syntax_arena.map(|arena| arena.get_drop_stream(id))
    }

    pub fn get_exclude(
        &self,
        id: crate::syntax::SyntaxExcludeId,
    ) -> Option<&'a crate::syntax::SyntaxExclude> {
        self.syntax_arena.map(|arena| arena.get_exclude(id))
    }

    pub fn get_exists_subquery(
        &self,
        id: crate::syntax::SyntaxExistsSubqueryId,
    ) -> Option<&'a crate::syntax::SyntaxExistsSubquery> {
        self.syntax_arena.map(|arena| arena.get_exists_subquery(id))
    }

    pub fn get_extract(
        &self,
        id: crate::syntax::SyntaxExtractId,
    ) -> Option<&'a crate::syntax::SyntaxExtract> {
        self.syntax_arena.map(|arena| arena.get_extract(id))
    }

    pub fn get_function_call(
        &self,
        id: crate::syntax::SyntaxFunctionCallId,
    ) -> Option<&'a crate::syntax::SyntaxFunctionCall> {
        self.syntax_arena.map(|arena| arena.get_function_call(id))
    }

    pub fn get_group_by(
        &self,
        id: crate::syntax::SyntaxGroupById,
    ) -> Option<&'a crate::syntax::SyntaxGroupBy> {
        self.syntax_arena.map(|arena| arena.get_group_by(id))
    }

    pub fn get_in_list(
        &self,
        id: crate::syntax::SyntaxInListId,
    ) -> Option<&'a crate::syntax::SyntaxInList> {
        self.syntax_arena.map(|arena| arena.get_in_list(id))
    }

    pub fn get_in_subquery(
        &self,
        id: crate::syntax::SyntaxInSubqueryId,
    ) -> Option<&'a crate::syntax::SyntaxInSubquery> {
        self.syntax_arena.map(|arena| arena.get_in_subquery(id))
    }

    pub fn get_inline_constraint(
        &self,
        id: crate::syntax::SyntaxInlineConstraintId,
    ) -> Option<&'a crate::syntax::SyntaxInlineConstraint> {
        self.syntax_arena
            .map(|arena| arena.get_inline_constraint(id))
    }

    pub fn get_jinja_arg(
        &self,
        id: crate::syntax::jinja::SyntaxJinjaArgId,
    ) -> Option<&'a crate::syntax::jinja::SyntaxJinjaArg> {
        self.syntax_arena.map(|arena| arena.get_jinja_arg(id))
    }

    pub fn get_jinja_delimiter(
        &self,
        id: crate::syntax::jinja::SyntaxJinjaDelimiterId,
    ) -> Option<&'a crate::syntax::jinja::SyntaxJinjaDelimiter> {
        self.syntax_arena.map(|arena| arena.get_jinja_delimiter(id))
    }

    pub fn get_jinja_expr(
        &self,
        id: crate::syntax::jinja::SyntaxJinjaExprId,
    ) -> Option<&'a crate::syntax::jinja::SyntaxJinjaExpr> {
        self.syntax_arena.map(|arena| arena.get_jinja_expr(id))
    }

    pub fn get_jinja_inline_fragment(
        &self,
        id: crate::syntax::jinja::SyntaxJinjaInlineFragmentId,
    ) -> Option<&'a crate::syntax::jinja::SyntaxJinjaInlineFragment> {
        self.syntax_arena
            .map(|arena| arena.get_jinja_inline_fragment(id))
    }

    pub fn get_jinja_interpolation(
        &self,
        id: crate::syntax::jinja::SyntaxJinjaInterpolationId,
    ) -> Option<&'a crate::syntax::jinja::SyntaxJinjaInterpolation> {
        self.syntax_arena
            .map(|arena| arena.get_jinja_interpolation(id))
    }

    pub fn get_jinja_stmt(
        &self,
        id: crate::syntax::jinja::SyntaxJinjaStmtId,
    ) -> Option<&'a crate::syntax::jinja::SyntaxJinjaStmt> {
        self.syntax_arena.map(|arena| arena.get_jinja_stmt(id))
    }

    pub fn get_match_recognize(
        &self,
        id: crate::syntax::SyntaxMatchRecognizeId,
    ) -> Option<&'a crate::syntax::SyntaxMatchRecognize> {
        self.syntax_arena.map(|arena| arena.get_match_recognize(id))
    }

    pub fn get_measure_item(
        &self,
        id: crate::syntax::SyntaxMeasureItemId,
    ) -> Option<&'a crate::syntax::SyntaxMeasureItem> {
        self.syntax_arena.map(|arena| arena.get_measure_item(id))
    }

    pub fn get_merge_insert_values(
        &self,
        id: crate::syntax::SyntaxMergeInsertValuesId,
    ) -> Option<&'a crate::syntax::SyntaxMergeInsertValues> {
        self.syntax_arena
            .map(|arena| arena.get_merge_insert_values(id))
    }

    pub fn get_object_literal(
        &self,
        id: crate::syntax::SyntaxObjectLiteralId,
    ) -> Option<&'a crate::syntax::SyntaxObjectLiteral> {
        self.syntax_arena.map(|arena| arena.get_object_literal(id))
    }

    pub fn get_optimize_stmt(
        &self,
        id: crate::syntax::SyntaxOptimizeStmtId,
    ) -> Option<&'a crate::syntax::SyntaxOptimizeStmt> {
        self.syntax_arena.map(|arena| arena.get_optimize_stmt(id))
    }

    pub fn get_order_item(
        &self,
        id: crate::syntax::SyntaxOrderItemId,
    ) -> Option<&'a crate::syntax::SyntaxOrderItem> {
        self.syntax_arena.map(|arena| arena.get_order_item(id))
    }

    pub fn get_over_clause(
        &self,
        id: crate::syntax::SyntaxOverClauseId,
    ) -> Option<&'a crate::syntax::SyntaxOverClause> {
        self.syntax_arena.map(|arena| arena.get_over_clause(id))
    }

    pub fn get_parameterized_type(
        &self,
        id: crate::syntax::SyntaxParameterizedTypeId,
    ) -> Option<&'a crate::syntax::SyntaxParameterizedType> {
        self.syntax_arena
            .map(|arena| arena.get_parameterized_type(id))
    }

    pub fn get_paren_expr(
        &self,
        id: crate::syntax::SyntaxParenExprId,
    ) -> Option<&'a crate::syntax::SyntaxParenExpr> {
        self.syntax_arena.map(|arena| arena.get_paren_expr(id))
    }

    pub fn get_pg_copy_stmt(
        &self,
        id: crate::syntax::SyntaxPgCopyStmtId,
    ) -> Option<&'a crate::syntax::SyntaxPgCopyStmt> {
        self.syntax_arena.map(|arena| arena.get_pg_copy_stmt(id))
    }

    pub fn get_pg_deallocate_stmt(
        &self,
        id: crate::syntax::SyntaxPgDeallocateStmtId,
    ) -> Option<&'a crate::syntax::SyntaxPgDeallocateStmt> {
        self.syntax_arena
            .map(|arena| arena.get_pg_deallocate_stmt(id))
    }

    pub fn get_pg_execute_stmt(
        &self,
        id: crate::syntax::SyntaxPgExecuteStmtId,
    ) -> Option<&'a crate::syntax::SyntaxPgExecuteStmt> {
        self.syntax_arena.map(|arena| arena.get_pg_execute_stmt(id))
    }

    pub fn get_pg_prepare_stmt(
        &self,
        id: crate::syntax::SyntaxPgPrepareStmtId,
    ) -> Option<&'a crate::syntax::SyntaxPgPrepareStmt> {
        self.syntax_arena.map(|arena| arena.get_pg_prepare_stmt(id))
    }

    pub fn get_pg_refresh_matview_stmt(
        &self,
        id: crate::syntax::SyntaxPgRefreshMatviewStmtId,
    ) -> Option<&'a crate::syntax::SyntaxPgRefreshMatviewStmt> {
        self.syntax_arena
            .map(|arena| arena.get_pg_refresh_matview_stmt(id))
    }

    pub fn get_position(
        &self,
        id: crate::syntax::SyntaxPositionId,
    ) -> Option<&'a crate::syntax::SyntaxPosition> {
        self.syntax_arena.map(|arena| arena.get_position(id))
    }

    pub fn get_trim(
        &self,
        id: crate::syntax::SyntaxTrimId,
    ) -> Option<&'a crate::syntax::SyntaxTrim> {
        self.syntax_arena.map(|arena| arena.get_trim(id))
    }

    pub fn get_substring(
        &self,
        id: crate::syntax::SyntaxSubstringId,
    ) -> Option<&'a crate::syntax::SyntaxSubstring> {
        self.syntax_arena.map(|arena| arena.get_substring(id))
    }

    pub fn get_quantified_subquery(
        &self,
        id: crate::syntax::SyntaxQuantifiedSubqueryId,
    ) -> Option<&'a crate::syntax::SyntaxQuantifiedSubquery> {
        self.syntax_arena
            .map(|arena| arena.get_quantified_subquery(id))
    }

    pub fn get_reindex_stmt(
        &self,
        id: crate::syntax::SyntaxReindexStmtId,
    ) -> Option<&'a crate::syntax::SyntaxReindexStmt> {
        self.syntax_arena.map(|arena| arena.get_reindex_stmt(id))
    }

    pub fn get_rename(
        &self,
        id: crate::syntax::SyntaxRenameId,
    ) -> Option<&'a crate::syntax::SyntaxRename> {
        self.syntax_arena.map(|arena| arena.get_rename(id))
    }

    pub fn get_rename_item(
        &self,
        id: crate::syntax::SyntaxRenameItemId,
    ) -> Option<&'a crate::syntax::SyntaxRenameItem> {
        self.syntax_arena.map(|arena| arena.get_rename_item(id))
    }

    pub fn get_replace(
        &self,
        id: crate::syntax::SyntaxReplaceId,
    ) -> Option<&'a crate::syntax::SyntaxReplace> {
        self.syntax_arena.map(|arena| arena.get_replace(id))
    }

    pub fn get_replace_item(
        &self,
        id: crate::syntax::SyntaxReplaceItemId,
    ) -> Option<&'a crate::syntax::SyntaxReplaceItem> {
        self.syntax_arena.map(|arena| arena.get_replace_item(id))
    }

    pub fn get_restore_stmt(
        &self,
        id: crate::syntax::SyntaxRestoreStmtId,
    ) -> Option<&'a crate::syntax::SyntaxRestoreStmt> {
        self.syntax_arena.map(|arena| arena.get_restore_stmt(id))
    }

    pub fn get_syntax_returning(
        &self,
        id: crate::syntax::SyntaxReturningId,
    ) -> Option<&'a crate::syntax::SyntaxReturning> {
        self.syntax_arena.map(|arena| arena.get_returning(id))
    }

    pub fn get_row_constructor(
        &self,
        id: crate::syntax::SyntaxRowConstructorId,
    ) -> Option<&'a crate::syntax::SyntaxRowConstructor> {
        self.syntax_arena.map(|arena| arena.get_row_constructor(id))
    }

    pub fn get_safe_cast(
        &self,
        id: crate::syntax::SyntaxSafeCastId,
    ) -> Option<&'a crate::syntax::SyntaxSafeCast> {
        self.syntax_arena.map(|arena| arena.get_safe_cast(id))
    }

    pub fn get_scripting_var(
        &self,
        id: crate::syntax::SyntaxScriptingVarId,
    ) -> Option<&'a crate::syntax::SyntaxScriptingVar> {
        self.syntax_arena.map(|arena| arena.get_scripting_var(id))
    }

    pub fn get_set_operator(
        &self,
        id: crate::syntax::SyntaxSetOperatorId,
    ) -> Option<&'a crate::syntax::SyntaxSetOperator> {
        self.syntax_arena.map(|arena| arena.get_set_operator(id))
    }

    pub fn get_statement(
        &self,
        id: crate::syntax::SyntaxStatementId,
    ) -> Option<&'a crate::syntax::SyntaxStatement> {
        self.syntax_arena.map(|arena| arena.get_statement(id))
    }

    pub fn get_subquery(
        &self,
        id: crate::syntax::SyntaxSubqueryId,
    ) -> Option<&'a crate::syntax::SyntaxSubquery> {
        self.syntax_arena.map(|arena| arena.get_subquery(id))
    }

    pub fn get_table_ref(
        &self,
        id: crate::syntax::SyntaxTableRefId,
    ) -> Option<&'a crate::syntax::SyntaxTableRef> {
        self.syntax_arena.map(|arena| arena.get_table_ref(id))
    }

    pub fn get_try_cast(
        &self,
        id: crate::syntax::SyntaxTryCastId,
    ) -> Option<&'a crate::syntax::SyntaxTryCast> {
        self.syntax_arena.map(|arena| arena.get_try_cast(id))
    }

    pub fn get_type_cast(
        &self,
        id: crate::syntax::SyntaxTypeCastId,
    ) -> Option<&'a crate::syntax::SyntaxTypeCast> {
        self.syntax_arena.map(|arena| arena.get_type_cast(id))
    }

    pub fn get_type_precision(
        &self,
        id: crate::syntax::SyntaxTypePrecisionId,
    ) -> Option<&'a crate::syntax::SyntaxTypePrecision> {
        self.syntax_arena.map(|arena| arena.get_type_precision(id))
    }

    pub fn get_type_precision_scale(
        &self,
        id: crate::syntax::SyntaxTypePrecisionScaleId,
    ) -> Option<&'a crate::syntax::SyntaxTypePrecisionScale> {
        self.syntax_arena
            .map(|arena| arena.get_type_precision_scale(id))
    }

    pub fn get_vacuum_stmt(
        &self,
        id: crate::syntax::SyntaxVacuumStmtId,
    ) -> Option<&'a crate::syntax::SyntaxVacuumStmt> {
        self.syntax_arena.map(|arena| arena.get_vacuum_stmt(id))
    }

    pub fn get_values(
        &self,
        id: crate::syntax::SyntaxValuesId,
    ) -> Option<&'a crate::syntax::SyntaxValues> {
        self.syntax_arena.map(|arena| arena.get_values(id))
    }

    pub fn get_view_column(
        &self,
        id: crate::syntax::SyntaxViewColumnId,
    ) -> Option<&'a crate::syntax::SyntaxViewColumn> {
        self.syntax_arena.map(|arena| arena.get_view_column(id))
    }

    pub fn get_view_column_comment(
        &self,
        id: crate::syntax::SyntaxViewColumnCommentId,
    ) -> Option<&'a crate::syntax::SyntaxViewColumnComment> {
        self.syntax_arena
            .map(|arena| arena.get_view_column_comment(id))
    }

    pub fn get_view_column_list(
        &self,
        id: crate::syntax::SyntaxViewColumnListId,
    ) -> Option<&'a crate::syntax::SyntaxViewColumnList> {
        self.syntax_arena
            .map(|arena| arena.get_view_column_list(id))
    }

    pub fn get_view_column_masking_policy(
        &self,
        id: crate::syntax::SyntaxViewColumnMaskingPolicyId,
    ) -> Option<&'a crate::syntax::SyntaxViewColumnMaskingPolicy> {
        self.syntax_arena
            .map(|arena| arena.get_view_column_masking_policy(id))
    }

    pub fn get_view_column_projection_policy(
        &self,
        id: crate::syntax::SyntaxViewColumnProjectionPolicyId,
    ) -> Option<&'a crate::syntax::SyntaxViewColumnProjectionPolicy> {
        self.syntax_arena
            .map(|arena| arena.get_view_column_projection_policy(id))
    }

    pub fn get_view_column_tag(
        &self,
        id: crate::syntax::SyntaxViewColumnTagId,
    ) -> Option<&'a crate::syntax::SyntaxViewColumnTag> {
        self.syntax_arena.map(|arena| arena.get_view_column_tag(id))
    }

    /// Access the dialect for dialect-specific formatting decisions
    pub fn dialect(&self) -> &dyn crate::dialect::Dialect {
        self.config.dialect.as_ref()
    }

    /// Debug: get current token index
    pub fn debug_next_token_idx(&self) -> usize {
        self.next_token_idx
    }

    /// Reset the token index to start at a specific source position
    ///
    /// Advances the token index to the first token at or after the given position.
    ///
    /// CRITICAL: This does NOT advance source_position. The source position cursor
    /// is only advanced by trivia emission (emit_trivia_until). This ensures that
    /// comments between the current position and `pos` are not skipped.
    pub fn reset_token_index_at(&mut self, pos: u32) {
        if let Some(cst) = self.cst {
            // Binary search to find first token at or after pos
            let tokens = &cst.tokens;
            let mut left = 0;
            let mut right = tokens.len();
            while left < right {
                let mid = left + (right - left) / 2;
                if tokens[mid].span.start < pos {
                    left = mid + 1;
                } else {
                    right = mid;
                }
            }
            self.next_token_idx = left;
        } else {
            self.next_token_idx = 0;
        }
    }

    // =========================================================================
    // NEW Source Position-Based Trivia Emission (REWORK)
    // =========================================================================
    //
    // The new approach maintains a single monotonically-advancing `source_position`
    // that tracks how far in the source we've consumed.
    //
    // Key invariant: All content from 0..source_position has been processed.
    //
    // Benefits:
    // - No duplicate tracking needed (position only moves forward)
    // - No lost comments (emit_trivia_until emits everything in range)
    // - Simpler logic to reason about

    /// Get the current source position cursor
    #[inline]
    pub fn get_source_position(&self) -> u32 {
        self.source_position
    }

    /// Set the source position cursor (use with caution)
    ///
    /// This should only be used when starting to format a new statement
    /// or when resetting state. Normal formatting should let the push
    /// methods advance the position automatically.
    #[inline]
    pub fn set_source_position(&mut self, pos: u32) {
        self.source_position = pos;
    }

    /// Emit CST trivia up to `target`, optionally including trailing trivia for the
    /// token that owns `target`.
    ///
    /// This is the single entry point for CST-based trivia emission. All callers
    /// must route through this function.
    ///
    /// # Arguments
    /// * `target` - The source position to emit trivia up to
    /// * `include_owner_trailing` - If true, also emit trailing trivia of the token that contains `target`
    pub fn emit_trivia_until(&mut self, target: u32, include_owner_trailing: bool) {
        // CRITICAL: Early return if target is at or before current position and not including owner trailing
        if target <= self.source_position && !include_owner_trailing {
            return;
        }

        let cst = match self.cst {
            Some(cst) => cst,
            None => {
                if target > self.source_position {
                    self.source_position = target;
                }
                return;
            }
        };

        let tokens = &cst.tokens;
        let mut max_emitted_end = self.source_position;
        let mut idx = self.next_token_idx;

        while idx < tokens.len() {
            let token = &tokens[idx];
            let token_contains_target = token.span.start <= target && target <= token.span.end;

            if token.span.end <= self.source_position
                && !(include_owner_trailing && token_contains_target)
            {
                idx += 1;
                continue;
            }

            let token_starts_after_target = token.span.start >= target;

            for trivia in &token.leading_trivia {
                if trivia.span.end <= self.source_position {
                    continue;
                }
                if trivia.span.start < target {
                    self.emit_trivia_item(trivia);
                    if trivia.span.end > max_emitted_end {
                        max_emitted_end = trivia.span.end;
                    }
                }
            }

            for trivia in &token.trailing_trivia {
                if trivia.span.end <= self.source_position {
                    continue;
                }
                if trivia.span.start < target || (include_owner_trailing && token_contains_target) {
                    self.emit_trivia_item(trivia);
                    if trivia.span.end > max_emitted_end {
                        max_emitted_end = trivia.span.end;
                    }
                }
            }

            if include_owner_trailing && token_contains_target {
                idx += 1;
                break;
            }

            if token_contains_target || token_starts_after_target {
                break;
            }

            idx += 1;
        }

        self.next_token_idx = idx;

        // CRITICAL: Always advance source_position to ensure progress
        // If we emitted something, advance to where we emitted.
        // If we emitted nothing, advance to at least target to prevent infinite loops.
        // Without this, repeated calls with the same target would never make progress.
        if max_emitted_end > self.source_position {
            self.source_position = max_emitted_end;
        } else if target > self.source_position {
            self.source_position = target;
        }
        // else: target <= source_position, we're already past it, no change needed
    }

    /// Emit all tokens (including punctuation like commas) from the current position
    /// up to the target position.
    ///
    /// Unlike `emit_trivia_until` which only emits comments/whitespace, this function
    /// emits actual token content (like `,` or `AND`) that appears before the target.
    ///
    /// This is needed for cases like `{% if x %} col, {% endif %}` where the comma
    /// is a token between the content and the closing delimiter.
    ///
    /// NOTE: This does NOT advance source_position past the last emitted token.
    /// The trivia in the gap between our last token and `target` will be emitted
    /// by the next push_span/emit_trivia_until call.
    pub fn emit_all_tokens_until(&mut self, target: u32) {
        if target <= self.source_position {
            return;
        }

        let cst = match self.cst {
            Some(cst) => cst,
            None => {
                // No CST - can't emit tokens, don't advance position
                return;
            }
        };

        let tokens = &cst.tokens;

        // Find and emit all tokens that are within our range
        let mut processed_until_idx = self.next_token_idx;
        for (idx, token) in tokens.iter().enumerate().skip(self.next_token_idx) {
            // Skip tokens we've already passed
            if token.span.end <= self.source_position {
                processed_until_idx = idx + 1;
                continue;
            }

            // Stop if this token starts at or after our target
            if token.span.start >= target {
                break;
            }

            // Emit this token with appropriate casing based on token type
            // Keywords get keyword casing, identifiers get identifier casing
            if matches!(token.kind, crate::lexer::TokenKind::Keyword(_)) {
                self.push_keyword_span(token.span);
            } else if matches!(token.kind, crate::lexer::TokenKind::Identifier { .. }) {
                self.push_identifier_span(token.span);
            } else {
                // Punctuation, literals, etc. - emit as-is
                self.push_span(token.span);
            }

            processed_until_idx = idx + 1;
        }

        // Update next_token_idx to avoid reprocessing same tokens
        self.next_token_idx = processed_until_idx;

        // DO NOT advance source_position here - let the next emit_trivia_until
        // call handle any trivia in the remaining gap up to `target`
    }

    /// Emit a single trivia item (comment) with proper formatting
    ///
    /// This is the unified trivia emission point for the new architecture.
    /// - Line comments: emit text + mandatory newline
    /// - Block comments: emit text, check source for newline after
    fn emit_trivia_item(&mut self, trivia: &crate::lexer::token::Trivia) {
        let start = trivia.span.start as usize;
        let end = trivia.span.end as usize;
        if end > self.source.len() {
            return;
        }

        let text = &self.source[start..end];

        match trivia.kind {
            TriviaKind::LineComment => {
                // Check if the line comment was on its own line in the source
                // by scanning backwards from the comment start to find if there's a newline
                // before any non-whitespace characters
                let was_on_own_line = if start > 0 {
                    let mut pos = start;
                    let mut found_newline = false;
                    while pos > 0 {
                        pos -= 1;
                        let ch = self.source.as_bytes()[pos];
                        if ch == b'\n' || ch == b'\r' {
                            found_newline = true;
                            break;
                        } else if ch != b' ' && ch != b'\t' {
                            // Found a non-whitespace character before signal newline
                            break;
                        }
                    }
                    found_newline || pos == 0
                } else {
                    true // At start of file, treat as own line
                };

                // Line comments: if it was on its own line in source, preserve that
                if was_on_own_line && !self.at_line_start {
                    self.newline();
                }

                if self.at_line_start {
                    self.write_indent();
                } else if !self.output.ends_with(' ') && !self.output.ends_with('\n') {
                    self.output.push(' ');
                }
                self.output.push_str(text.trim());
                self.at_line_start = false;
                self.newline(); // MANDATORY - line comment extends to EOL
            }
            TriviaKind::BlockComment => {
                // Block comments: space before (if not at line start), text, trailing space/newline

                // Check if the block comment was on its own line in source (preceded by newline)
                let was_on_own_line = if start > 0 {
                    let mut pos = start;
                    let mut found_newline = false;
                    while pos > 0 {
                        pos -= 1;
                        let ch = self.source.as_bytes()[pos];
                        if ch == b'\n' || ch == b'\r' {
                            found_newline = true;
                            break;
                        } else if ch != b' ' && ch != b'\t' {
                            break;
                        }
                    }
                    found_newline || pos == 0
                } else {
                    true
                };

                // Check if IMMEDIATELY followed by a newline in source (no intervening whitespace)
                // This is critical for idempotency: if original has `*/ ON`, we emit `*/ ` (space)
                // and let other code handle the newline. We only emit newline if source has `*/\n`.
                let followed_by_newline = if end < self.source.len() {
                    let next_ch = self.source.as_bytes()[end];
                    next_ch == b'\n' || next_ch == b'\r'
                } else {
                    false
                };

                // If comment was on its own line, ensure we start on a new line
                if was_on_own_line && !self.at_line_start {
                    self.newline();
                }

                if self.at_line_start {
                    self.write_indent();
                } else if !self.output.ends_with(' ') && !self.output.ends_with('\n') {
                    self.output.push(' ');
                }
                self.output.push_str(text.trim());

                // Preserve newline after block comment if source had it
                if followed_by_newline {
                    self.newline();
                } else {
                    self.output.push(' ');
                }
                self.at_line_start = followed_by_newline;
            }
            TriviaKind::JinjaComment => {
                // Jinja comments {# ... #}: same handling as block comments
                if self.at_line_start {
                    self.write_indent();
                } else if !self.output.ends_with(' ') && !self.output.ends_with('\n') {
                    self.output.push(' ');
                }
                self.output.push_str(text.trim());
                self.output.push(' '); // Always add trailing space for consistency
                self.at_line_start = false;
            }
            TriviaKind::MysqlVersionComment => {
                // MySQL version comments /*!50100 ... */: preserve like block comments.
                // These contain executable SQL in MySQL, so we must not lose them.
                if self.at_line_start {
                    self.write_indent();
                } else if !self.output.ends_with(' ') && !self.output.ends_with('\n') {
                    self.output.push(' ');
                }
                self.output.push_str(text.trim());
                let followed_by_newline = if end < self.source.len() {
                    let next_ch = self.source.as_bytes()[end];
                    next_ch == b'\n' || next_ch == b'\r'
                } else {
                    false
                };
                if followed_by_newline {
                    self.newline();
                } else {
                    self.output.push(' ');
                }
                self.at_line_start = followed_by_newline;
            }
            TriviaKind::Whitespace | TriviaKind::Newline => {
                // Ignore - formatter controls whitespace
            }
        }
    }

    /// Emit all remaining trivia from current position to end of source (V2)
    ///
    /// Call this after formatting the last statement to ensure trailing comments
    /// are preserved.
    pub fn emit_remaining_trivia_v2(&mut self) {
        let source_len = self.source.len() as u32;
        self.emit_trivia_until(source_len, false);
    }

    /// Push exact source text without any processing
    ///
    /// Emits the raw source bytes from the given span, including all whitespace
    /// and comment trivia, without:
    /// - Keyword/identifier case conversion
    /// - Trivia processing (no automatic space after block comments)
    /// - Indentation insertion
    /// - Any formatting transformations
    ///
    /// This is useful when you need to preserve the exact original formatting
    /// of a code region, such as return type clauses with embedded comments.
    ///
    /// IMPORTANT:
    /// - Emits trivia up to span.start first
    /// - Then outputs raw source bytes exactly as they appear
    /// - source_position is advanced to span.end
    pub fn push_raw_source(&mut self, span: Span) {
        let start = span.start as usize;
        let end = span.end as usize;

        if start > end || end > self.source.len() {
            return;
        }

        // Emit any trivia between current position and span start
        self.emit_trivia_until(span.start, false);

        let text = &self.source[start..end];

        // Push raw text without any processing
        self.output.push_str(text);
        self.line_position += text.len();

        // Check if we're now at line start (text ended with newline)
        self.at_line_start = text.ends_with('\n');

        // Advance source position past this span
        // This tells the trivia system we've already handled everything up to here
        self.source_position = span.end;

        // Emit trailing trivia for the span
        self.emit_trivia_until(span.end, true);
    }

    /// Push identifier from source span with case conversion (V2)
    ///
    /// Uses the new source_position-based trivia emission.
    #[inline]
    pub fn push_identifier_span_v2(&mut self, span: Span) {
        use crate::formatter::config::IdentifierCase;

        // Step 1: Emit all trivia in the gap
        self.emit_trivia_until(span.start, false);

        // Check case config first to determine if we need to allocate
        let needs_transform = !matches!(self.config.identifier_case, IdentifierCase::Preserve);

        if needs_transform {
            let identifier = self.extract_span(span);
            let formatted = match self.config.identifier_case {
                IdentifierCase::Preserve => unreachable!(),
                IdentifierCase::Upper => identifier.to_uppercase(),
                IdentifierCase::Lower => identifier.to_lowercase(),
            };

            if self.token_tracking_enabled {
                self.push_tracked(&formatted, span);
            } else {
                self.push(&formatted);
            }
        } else {
            // Preserve case - extract to owned String to avoid borrow conflict
            let text_owned = self.extract_span(span).to_string();
            if self.token_tracking_enabled {
                self.push_tracked(&text_owned, span);
            } else {
                self.push(&text_owned);
            }
        }

        // Advance source position
        self.source_position = span.end;
        self.emit_trivia_until(span.end, true);
    }

    // =========================================================================
    // Span tracking (statement-level only)
    // =========================================================================

    /// Begin tracking a source span (STATEMENT-LEVEL ONLY)
    ///
    /// ARCHITECTURAL CONSTRAINT: Only call this for TOP-LEVEL statements.
    /// SpanMap requires a PARTITION (no gaps, no overlaps, no nesting).
    ///
    /// For nested AST nodes (clauses, expressions), DO NOT call this.
    /// Use manual position tracking via output_pos() if needed.
    ///
    /// Must be paired with end_span().
    pub fn begin_span(&mut self, source_span: Span, kind: MappingKind) {
        self.span_tracker
            .begin(source_span, self.output.len(), kind);
    }

    /// End tracking current span (STATEMENT-LEVEL ONLY)
    ///
    /// Call this after formatting top-level statement.
    pub fn end_span(&mut self) {
        self.span_tracker.end(self.output.len());
    }

    /// Get current output position (for manual node tracking if needed)
    #[inline]
    pub fn output_pos(&self) -> usize {
        self.output.len()
    }

    /// Get formatter configuration
    #[inline]
    pub fn config(&self) -> &FormatterConfig {
        self.config
    }

    /// Get source text (for extracting spans)
    #[inline]
    pub fn source(&self) -> &str {
        self.source
    }

    /// Extract text from source using span (safe with bounds checking)
    ///
    /// Returns empty string if span is out of bounds.
    #[inline]
    pub fn extract_span(&self, span: Span) -> &str {
        let start = span.start as usize;
        let end = span.end as usize;

        if start <= end && end <= self.source.len() {
            &self.source[start..end]
        } else {
            ""
        }
    }

    /// Push alignment padding - whitespace that is intentionally added for alignment purposes.
    /// Unlike push(), this will NOT be skipped even at line start.
    #[inline]
    pub fn push_alignment_padding(&mut self, spaces: usize) {
        if spaces == 0 {
            return;
        }
        // If at line start, write indent first, then add padding
        if self.at_line_start {
            self.write_indent();
        }
        for _ in 0..spaces {
            self.output.push(' ');
        }
        self.line_position += spaces;
        self.at_line_start = false;
    }

    /// Push text to output
    ///
    /// If token tracking is enabled and extract_span() was called just before this,
    /// automatically tracks the token-level mapping.
    ///
    /// NOTE: If pushing a single space and the output already ends with a space,
    /// the push is skipped to prevent double-spacing issues with trivia emission.
    #[inline]
    pub fn push(&mut self, text: &str) {
        // Prevent double-spacing: if pushing a single space and output already ends with space, skip
        if text == " " && self.output.ends_with(' ') {
            return;
        }

        // Check if text has any non-whitespace
        let has_content = text.bytes().any(|b| !b.is_ascii_whitespace());

        // If at line start and text has content, write indent first
        if self.at_line_start && has_content {
            self.write_indent();
        }

        // If at line start and text is only whitespace, skip it
        // But we MUST clear at_line_start flag to prevent skipping ALL subsequent whitespace
        if self.at_line_start && !has_content {
            self.at_line_start = false;
            return;
        }

        let output_start = self.output.len();
        self.output.push_str(text);
        let output_end = self.output.len();

        // Auto-track if we have a remembered span from extract_span()
        if self.token_tracking_enabled {
            if let Some(span) = self.last_extracted_span.take() {
                self.span_tracker
                    .track_token(span, output_start, output_end);
            }
        }

        self.line_position += text.len();
        self.at_line_start = false;
    }

    /// Push text to output with token-level tracking
    ///
    /// Use this instead of push() when formatting templates that need reverse mapping.
    /// The source_span tracks where this text came from in the original source.
    pub fn push_tracked(&mut self, text: &str, source_span: Span) {
        if self.at_line_start && !text.trim().is_empty() {
            self.write_indent();
        }

        let output_start = self.output.len();
        self.output.push_str(text);
        let output_end = self.output.len();

        // Track token-level mapping if enabled
        if self.token_tracking_enabled {
            self.span_tracker
                .track_token(source_span, output_start, output_end);
        }

        self.line_position += text.len();
        self.at_line_start = false;
    }

    /// Push text from a source span (extracts and tracks in one call)
    ///
    /// This is the recommended method for formatters: replaces the pattern of
    /// `extract_span().to_string()` + `push()` with a single tracked call.
    ///
    /// CRITICAL: This method emits leading trivia for all tokens up to the span,
    /// and trailing trivia for the token at the span, ensuring comments are preserved.
    ///
    /// Uses the NEW source_position-based trivia emission (V2 architecture).
    ///
    /// Statement formatters should use this method (or push_keyword_span) instead
    /// of manually managing trivia.
    #[inline]
    pub fn push_span(&mut self, span: Span) {
        let start = span.start as usize;
        let end = span.end as usize;

        if start > end || end > self.source.len() {
            return;
        }

        let text = &self.source[start..end];

        // V2 ARCHITECTURE: Emit all trivia in the gap from current position to span start
        self.emit_trivia_until(span.start, false);

        // Token tracking path needs allocation
        if self.token_tracking_enabled {
            let text_owned = text.to_string();
            self.push_tracked(&text_owned, span);
        } else {
            // Fast path: push directly without allocation
            // Use bytes for faster check - most SQL is ASCII
            if self.at_line_start && !text.is_empty() {
                let first_byte = text.as_bytes()[0];
                if !first_byte.is_ascii_whitespace() {
                    self.write_indent();
                }
            }
            // Block comments already add trailing space, no need for ensure_space_after_block_comment
            self.output.push_str(text);
            self.line_position += text.len();
            self.at_line_start = false;
        }

        // V2 ARCHITECTURE: Advance source position past this span
        self.source_position = span.end;

        // V2 ARCHITECTURE: Emit trailing trivia for the token at this span
        self.emit_trivia_until(span.end, true);
    }

    /// Push keyword from source span with case conversion and trivia emission
    ///
    /// Extracts text from span, emits leading and trailing trivia, applies keyword casing.
    /// Also updates the source cursor past this keyword.
    ///
    /// Uses the NEW source_position-based trivia emission (V2 architecture).
    ///
    /// This is the preferred method for keywords when you have the source span.
    /// Statement formatters should use this instead of push_keyword() when possible.
    #[inline]
    pub fn push_keyword_span(&mut self, span: Span) {
        use crate::formatter::keyword_cache::*;

        // V2 ARCHITECTURE: Emit all trivia in the gap
        self.emit_trivia_until(span.start, false);

        let keyword = self.extract_span(span);
        let formatted = match self.config.keyword_case {
            KeywordCase::Upper => get_upper_keyword(keyword),
            KeywordCase::Lower => get_lower_keyword(keyword),
            KeywordCase::Title => get_title_keyword(keyword),
            KeywordCase::Preserve => std::borrow::Cow::Owned(keyword.to_string()),
        };

        if self.token_tracking_enabled {
            self.push_tracked(&formatted, span);
        } else {
            self.push(&formatted);
        }

        // V2 ARCHITECTURE: Advance source position past this keyword
        self.source_position = span.end;
        self.emit_trivia_until(span.end, true);
    }

    /// Push identifier from source span with case conversion and trivia emission
    ///
    /// Extracts text from span, emits leading and trailing trivia, applies identifier casing.
    /// Also updates the source cursor past this identifier.
    ///
    /// Uses the NEW source_position-based trivia emission (V2 architecture).
    ///
    /// This is the preferred method for identifiers when you have the source span.
    #[inline]
    pub fn push_identifier_span(&mut self, span: Span) {
        use crate::formatter::config::IdentifierCase;

        // V2 ARCHITECTURE: Emit all trivia in the gap
        self.emit_trivia_until(span.start, false);

        // Check case config first to determine if we need to allocate
        let needs_transform = !matches!(self.config.identifier_case, IdentifierCase::Preserve);

        if needs_transform {
            let identifier = self.extract_span(span);
            let formatted = match self.config.identifier_case {
                IdentifierCase::Preserve => unreachable!(),
                IdentifierCase::Upper => identifier.to_uppercase(),
                IdentifierCase::Lower => identifier.to_lowercase(),
            };

            if self.token_tracking_enabled {
                self.push_tracked(&formatted, span);
            } else {
                self.push(&formatted);
            }
        } else {
            // Preserve case - extract to owned String
            let text_owned = self.extract_span(span).to_string();
            if self.token_tracking_enabled {
                self.push_tracked(&text_owned, span);
            } else {
                self.push(&text_owned);
            }
        }

        // V2 ARCHITECTURE: Advance source position
        self.source_position = span.end;
        self.emit_trivia_until(span.end, true);
    }

    /// Push single character
    #[inline]
    pub fn push_char(&mut self, ch: char) {
        if self.at_line_start && !ch.is_whitespace() {
            self.write_indent();
        }

        self.output.push(ch);
        self.line_position += 1;
        self.at_line_start = false;
    }

    /// Push keyword with configured case and automatic trivia emission
    ///
    /// Scans forward from the current token index to find the keyword,
    /// emits any leading trivia (comments), then outputs the keyword with proper casing,
    /// and finally emits trailing trivia (same-line comments).
    /// This is O(1) amortized since we only ever scan forward.
    ///
    /// Uses the V2 source_position-based trivia emission architecture.
    ///
    /// IMPORTANT: This method skips tokens that are inside Jinja blocks ({{ ... }} or {% ... %}).
    /// This prevents false matches like `from` in `{{ dbt_utils.star(from=ref('orders')) }}`
    /// being mistaken for the SQL FROM keyword.
    #[inline]
    pub fn push_keyword(&mut self, keyword: &str) {
        use crate::formatter::keyword_cache::*;
        use crate::lexer::TokenKind;

        // Track the token we found so we can emit its trailing trivia after push
        let mut found_token_span: Option<Span> = None;

        // If we have a CST, find the keyword token
        if let Some(cst) = self.cst {
            // Track Jinja nesting depth - only match keywords at depth 0 (outside Jinja)
            let mut jinja_depth: i32 = 0;

            // Scan forward from current position (O(1) amortized)
            // Use eq_ignore_ascii_case directly - no allocation needed
            while self.next_token_idx < cst.tokens.len() {
                let token = &cst.tokens[self.next_token_idx];

                // Skip tokens we've already processed (before source_position)
                // This prevents re-matching tokens from nested scopes (like subqueries)
                if token.span.end <= self.source_position {
                    self.next_token_idx += 1;
                    continue;
                }

                // Track Jinja block depth
                match &token.kind {
                    TokenKind::JinjaExprOpen | TokenKind::JinjaStmtOpen => {
                        jinja_depth += 1;
                    }
                    TokenKind::JinjaExprClose | TokenKind::JinjaStmtClose => {
                        jinja_depth -= 1;
                    }
                    _ => {}
                }

                // Only match keywords when outside Jinja blocks (depth == 0)
                if jinja_depth == 0 {
                    // Check if this token matches the keyword (case-insensitive)
                    // Match both Keywords and Identifiers since ASC/DESC/NULLS/FIRST/LAST
                    // are often lexed as identifiers in ORDER BY context
                    let is_keyword_or_ident = matches!(
                        &token.kind,
                        TokenKind::Keyword(_) | TokenKind::Identifier { .. }
                    );

                    if is_keyword_or_ident
                        && token.lexeme(self.source).eq_ignore_ascii_case(keyword)
                    {
                        // Found the matching token - record its span
                        found_token_span = Some(token.span);
                        break;
                    }
                }

                // NOT the token we're looking for - skip
                self.next_token_idx += 1;
            }
        }

        // If we found the token, use V2 architecture to emit with trivia
        if let Some(span) = found_token_span {
            // V2: Emit gap up to this token
            self.emit_trivia_until(span.start, false);

            let formatted = match self.config.keyword_case {
                KeywordCase::Upper => get_upper_keyword(keyword),
                KeywordCase::Lower => get_lower_keyword(keyword),
                KeywordCase::Title => get_title_keyword(keyword),
                KeywordCase::Preserve => std::borrow::Cow::Owned(keyword.to_string()),
            };

            self.push(&formatted);

            // V2: Advance source position and emit trailing trivia
            self.source_position = span.end;
            self.emit_trivia_until(span.end, true);

            // NOTE: emit_trivia_until with include_owner_trailing=true already advances
            // next_token_idx past the matched token, so no need to increment here
        } else {
            // No CST or keyword not found - just push the formatted keyword
            let formatted = match self.config.keyword_case {
                KeywordCase::Upper => get_upper_keyword(keyword),
                KeywordCase::Lower => get_lower_keyword(keyword),
                KeywordCase::Title => get_title_keyword(keyword),
                KeywordCase::Preserve => std::borrow::Cow::Owned(keyword.to_string()),
            };
            self.push(&formatted);
        }
    }

    /// Check if a keyword exists in source before another keyword
    ///
    /// Useful for preserving optional keywords like INNER in "INNER JOIN".
    /// Returns true if `keyword` appears before `before_keyword` in the token stream.
    /// Does NOT advance the token index.
    pub fn has_keyword_before(&self, keyword: &str, before_keyword: &str) -> bool {
        use crate::lexer::TokenKind;

        let cst = match self.cst {
            Some(cst) => cst,
            None => return false,
        };

        let mut idx = self.next_token_idx;
        while idx < cst.tokens.len() {
            let token = &cst.tokens[idx];
            if let TokenKind::Keyword(_) = &token.kind {
                if token.lexeme(self.source).eq_ignore_ascii_case(keyword) {
                    return true;
                }
                if token
                    .lexeme(self.source)
                    .eq_ignore_ascii_case(before_keyword)
                {
                    return false; // Found the "before" keyword first
                }
            }
            idx += 1;
        }
        false
    }

    /// Push keyword by searching for it after a known position
    ///
    /// Sets the token index to start at `after_pos`, then finds and emits the keyword.
    /// Use this when you don't have the keyword's span from the AST, but know roughly where it is.
    ///
    /// Example: `printer.push_keyword_after("FROM", select_keyword_span.end);`
    ///
    /// This method also emits any leading trivia (comments) attached to the keyword token.
    pub fn push_keyword_after(&mut self, keyword: &str, after_pos: u32) {
        // Reset token index to start searching from after_pos
        self.reset_token_index_at(after_pos);
        // push_keyword will scan forward to find the keyword
        self.push_keyword(keyword);
    }

    /// Add newline
    ///
    /// **ARCHITECTURE**:
    /// - Line comment newlines are added by trivia emission (syntactic requirement)
    /// - Block comment newlines are controlled by the formatter using this method
    /// - The formatter uses `TriviaInfo.source_had_newline` to decide if block comments
    ///   should be followed by newlines
    ///
    /// NOTE: If the output already ends with a newline (ignoring trailing whitespace/indent),
    /// this is a no-op to prevent double newlines from trivia emission followed by explicit newline() calls.
    #[inline]
    pub fn newline(&mut self) {
        // Prevent double newlines: check if output ends with newline (ignoring trailing whitespace)
        // Limit scan to last 64 bytes (more than enough for any reasonable indentation)
        let bytes = self.output.as_bytes();
        let scan_len = bytes.len().min(64);
        let ends_with_newline = bytes[bytes.len() - scan_len..]
            .iter()
            .rev()
            .find(|&&b| b != b' ' && b != b'\t')
            .is_some_and(|&b| b == b'\n' || b == b'\r');
        if ends_with_newline {
            return;
        }
        match self.config.newline_style {
            NewlineStyle::Unix => self.output.push('\n'),
            NewlineStyle::Windows => self.output.push_str("\r\n"),
        }
        self.line_position = 0;
        self.at_line_start = true;
    }

    /// Add newline only if not already at line start
    ///
    /// Use this after emitting trivia or when unsure if a newline was just added.
    #[inline]
    pub fn newline_if_needed(&mut self) {
        if !self.at_line_start {
            self.newline();
        }
    }

    /// Ensure there is a blank line (two newlines) at the current position.
    ///
    /// Used between top-level statements to ensure visual separation.
    #[inline]
    pub fn ensure_blank_line(&mut self) {
        // Check if output already ends with blank line
        let output = self.output.as_str();
        let double_newline = if matches!(self.config.newline_style, NewlineStyle::Windows) {
            "\r\n\r\n"
        } else {
            "\n\n"
        };

        if output.ends_with(double_newline) {
            // Already have blank line
            return;
        }

        // Force a blank line between statements.
        // Use push_newline_raw() to bypass the "no double newlines" guard in newline()
        let single_newline = if matches!(self.config.newline_style, NewlineStyle::Windows) {
            "\r\n"
        } else {
            "\n"
        };

        if output.ends_with(single_newline) {
            // Already have one newline, add one more for blank line
            self.push_newline_raw();
        } else {
            // No newline yet, add two
            self.push_newline_raw();
            self.push_newline_raw();
        }
    }

    /// Push a raw newline without checking for existing newlines.
    /// Use this only in ensure_blank_line() where we explicitly want multiple newlines.
    #[inline]
    fn push_newline_raw(&mut self) {
        match self.config.newline_style {
            NewlineStyle::Unix => self.output.push('\n'),
            NewlineStyle::Windows => self.output.push_str("\r\n"),
        }
        self.line_position = 0;
        self.at_line_start = true;
    }

    /// Add space
    #[inline]
    pub fn space(&mut self) {
        self.push(" ");
    }

    /// Add space only if the output doesn't already end with a space or newline.
    /// This prevents double-spacing when block comments have already added trailing space.
    #[inline]
    pub fn space_if_needed(&mut self) {
        let ends_space = self.output.ends_with(' ');
        let ends_newline = self.output.ends_with('\n');
        if !ends_space && !ends_newline {
            self.push(" ");
        }
    }

    /// Increase indentation level
    #[inline]
    pub fn indent_up(&mut self) {
        self.indent_level += 1;
    }

    /// Decrease indentation level
    #[inline]
    pub fn indent_down(&mut self) {
        if self.indent_level > 0 {
            self.indent_level -= 1;
        }
    }

    /// Get current indentation level (for debugging)
    #[inline]
    pub fn get_indent_level(&self) -> usize {
        self.indent_level
    }

    /// Check if at start of line (for debugging)
    #[inline]
    pub fn get_at_line_start(&self) -> bool {
        self.at_line_start
    }

    /// Write indentation (internal)
    #[inline]
    fn write_indent(&mut self) {
        let indent_chars = match self.config.indent_style {
            IndentStyle::Spaces(n) => n * self.indent_level,
            IndentStyle::Tabs => self.indent_level,
        };

        if indent_chars == 0 {
            return;
        }

        // Pre-compute indent string to avoid per-character push
        let indent_char = match self.config.indent_style {
            IndentStyle::Spaces(_) => ' ',
            IndentStyle::Tabs => '\t',
        };

        // Use repeat to efficiently create the indent string
        self.output
            .extend(std::iter::repeat_n(indent_char, indent_chars));
    }

    /// Get current output length (for testing)
    #[inline]
    pub fn len(&self) -> usize {
        self.output.len()
    }

    /// Check if output is empty (for testing)
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.output.is_empty()
    }

    /// Get current indentation level (for testing)
    #[inline]
    pub fn indent_level(&self) -> usize {
        self.indent_level
    }

    /// Push comma with configured style
    pub fn push_comma(&mut self) {
        use crate::formatter::config::CommaStyle;
        match self.config.comma_style {
            CommaStyle::Trailing => {
                self.push(",");
            }
            CommaStyle::Leading => {
                // Leading comma handled by caller (push before item)
                self.push(",");
            }
        }
    }

    /// Push comma from source, preserving trivia (comments) attached to the comma token.
    ///
    /// This searches for a comma token in the range [start, end) and emits it with its
    /// leading and trailing trivia. This is important for preserving comments like:
    ///   `col1, /* comment after comma */`
    ///
    /// Uses V2 source_position-based trivia emission architecture.
    ///
    /// If no comma is found in the range, does nothing (no fallback comma insertion).
    pub fn push_comma_from_source(&mut self, start: u32, end: u32) {
        use crate::lexer::{Punctuation, TokenKind};

        let cst = match self.cst {
            Some(cst) => cst,
            None => {
                // No CST available - must add comma since we can't verify source
                self.push(",");
                return;
            }
        };

        let tokens = &cst.tokens;

        // Search for comma token in range
        for token in tokens {
            // Skip tokens before our range
            if token.span.end <= start {
                continue;
            }

            // Stop if we've passed the range
            if token.span.start >= end {
                break;
            }

            // Check if this is a comma
            if matches!(token.kind, TokenKind::Punctuation(Punctuation::Comma)) {
                // Found the comma - use V2 architecture
                self.emit_trivia_until(token.span.start, false);
                self.push(",");
                self.source_position = token.span.end;
                self.emit_trivia_until(token.span.end, true);
                return;
            }
        }

        // No comma found in source range - do NOT add one
        // The caller should only call this when there's supposed to be a comma
    }

    /// Emit comments that appear before a given source position (CST-based)
    ///
    /// Uses V2 source_position-based trivia emission architecture.
    /// Emits all trivia in the gap from current position to source_pos.
    pub fn emit_comments_before(&mut self, source_pos: u32) {
        // V2: Just emit the gap up to the target position
        self.emit_trivia_until(source_pos, false);
    }

    /// Finalize formatting and return updated context
    ///
    /// This validates span coverage and builds FormattedContext.
    ///
    /// Nested node spans are populated via two mechanisms:
    /// 1. Explicit: Formatters called set_formatted_span() during formatting (precise)
    /// 2. Proportional: update_formatted_spans() fills in remaining nodes (approximate)
    pub fn finish(
        self,
        context: RenderContext,
        _has_template: bool,
    ) -> Result<RenderContext, crate::formatter::FormatterError> {
        // 1. Finalize statement-level span tracking (partition)
        let span_map = self
            .span_tracker
            .finish(self.source, self.output.len())
            .map_err(|e| crate::formatter::FormatterError::SpanTracking(e.to_string()))?;

        // 2. Build FormattedContext with SpanMap (CST has trivia, no separate TriviaMap needed)
        let formatted_ctx = FormattedContext::new(self.output, span_map.clone())
            .map_err(|e| crate::formatter::FormatterError::InvalidContext(format!("{:?}", e)))?;

        // 3. Add to RenderContext
        let context = context.with_formatted(formatted_ctx);

        Ok(context)
    }

    /// Create printer for testing (without CST - legacy mode)
    #[cfg(test)]
    pub fn new_for_test(config: &'a FormatterConfig, source: &'a str) -> Self {
        Self::new(config, source, None)
    }

    /// Get output string (for width calculations in alignment)
    pub fn output_string(&self) -> &str {
        &self.output
    }

    /// Insert padding spaces at a specific position in the output.
    /// Used for post-hoc alignment of AS aliases.
    pub fn insert_padding_at(&mut self, position: usize, num_spaces: usize) {
        if position <= self.output.len() && num_spaces > 0 {
            let padding: String = " ".repeat(num_spaces);
            self.output.insert_str(position, &padding);
        }
    }

    /// Get output string (for testing)
    #[cfg(test)]
    pub fn output(&self) -> &str {
        &self.output
    }

    // =========================================================================
    // Jinja CST-Based Formatting
    // =========================================================================

    /// Format a Jinja delimiter using CST tokens for proper trivia preservation.
    ///
    /// Emits each token individually: `{%`, keyword, expression (if present),
    /// `%}`.
    ///
    /// **Benefits**:
    /// - Proper trivia (comments/whitespace) preservation on each token
    /// - Can normalize spacing: `{%if x%}` → `{% if x %}`
    /// - Enables expression formatting/validation
    pub fn format_jinja_delimiter(
        &mut self,
        delimiter: &crate::ast::JinjaBlockDelimiter,
    ) -> Result<(), crate::formatter::FormatterError> {
        // If no syntax_id, fall back to old span-based approach
        let Some(syntax_id) = delimiter.syntax_id else {
            self.push_span(delimiter.span);
            return Ok(());
        };

        // Get syntax arena (required for CST access)
        let Some(arena) = self.syntax_arena else {
            self.push_span(delimiter.span);
            return Ok(());
        };

        // Look up the delimiter in the syntax arena
        let syntax_delim = arena.get_jinja_delimiter(syntax_id);

        // Emit open brace: {%
        self.push_token_id(syntax_delim.open_brace);

        // Emit keyword: if, elif, else, endif, for, endfor, set
        self.space();
        self.push_token_id(syntax_delim.keyword);

        // Emit expression (if present): condition for if/elif, iterator for for
        if let Some(expr_id) = syntax_delim.expr {
            self.space();
            self.format_jinja_expr(expr_id)?;
        } else {
            // No parsed expression (e.g., FOR loops with complex syntax like {% for a, b in items %})
            // Emit all tokens between keyword and close_brace
            let keyword_idx = syntax_delim.keyword.0 as usize;
            let close_idx = syntax_delim.close_brace.0 as usize;

            if self.cst.is_some() {
                for token_idx in (keyword_idx + 1)..close_idx {
                    self.space();
                    self.push_token_id(crate::cst::TokenId(token_idx as u32));
                }
            }
        }

        // Emit close brace: %}
        self.space();
        self.push_token_id(syntax_delim.close_brace);

        // push_token_id automatically emits trailing trivia via the unified emitter,
        // so no manual trivia handling is needed here.

        Ok(())
    }

    /// Format a Jinja expression using CST tokens for proper trivia preservation.
    ///
    /// Recursively formats Jinja expressions from the typed syntax tree.
    /// Each token (operators, punctuation, identifiers) is emitted individually
    /// with its trivia, enabling proper comment placement.
    ///
    /// **Examples**:
    /// - `target.name` → formats base, dot, attr tokens separately
    /// - `x == 'prod'` → formats left, operator, right tokens separately
    /// - `ref('model')` → formats callee, lparen, args, rparen separately
    fn format_jinja_expr(
        &mut self,
        expr_id: crate::syntax::SyntaxJinjaExprId,
    ) -> Result<(), crate::formatter::FormatterError> {
        use crate::syntax::SyntaxJinjaExprKind;

        let arena = self.syntax_arena.ok_or_else(|| {
            crate::formatter::FormatterError::InvalidContext(
                "Syntax arena required for Jinja expression formatting".to_string(),
            )
        })?;

        let expr = arena.get_jinja_expr(expr_id);

        match &expr.kind {
            SyntaxJinjaExprKind::Literal { token } => {
                self.push_token_id(*token);
            }

            SyntaxJinjaExprKind::Name { token } => {
                self.push_token_id(*token);
            }

            SyntaxJinjaExprKind::Attribute { base, dot, attr } => {
                self.format_jinja_expr(*base)?;
                self.push_token_id(*dot); // No space before dot
                self.push_token_id(*attr); // No space after dot
            }

            SyntaxJinjaExprKind::Subscript {
                base,
                lbracket,
                index,
                rbracket,
            } => {
                self.format_jinja_expr(*base)?;
                self.push_token_id(*lbracket); // No space before [
                self.format_jinja_expr(*index)?;
                self.push_token_id(*rbracket);
            }

            SyntaxJinjaExprKind::BinaryOp {
                left,
                op_tokens,
                right,
            } => {
                self.format_jinja_expr(*left)?;
                self.space();
                self.push_token_id(op_tokens.primary);
                if let Some(secondary) = op_tokens.secondary {
                    self.space();
                    self.push_token_id(secondary);
                }
                self.space();
                self.format_jinja_expr(*right)?;
            }

            SyntaxJinjaExprKind::UnaryOp { op, expr } => {
                self.push_token_id(*op);
                self.space();
                self.format_jinja_expr(*expr)?;
            }

            SyntaxJinjaExprKind::Call {
                callee,
                lparen,
                args,
                rparen,
            } => {
                self.format_jinja_expr(*callee)?;
                self.push_token_id(*lparen); // No space before (
                for (i, arg_id) in args.iter().enumerate() {
                    if i > 0 {
                        self.push(",");
                        self.space();
                    }
                    self.format_jinja_arg(*arg_id)?;
                }
                self.push_token_id(*rparen);
            }

            SyntaxJinjaExprKind::Filter {
                expr,
                pipe,
                filter,
                args,
            } => {
                self.format_jinja_expr(*expr)?;
                self.space();
                self.push_token_id(*pipe);
                self.space();
                self.push_token_id(*filter);
                if let Some((filter_args, args_list)) = args {
                    self.push_token_id(filter_args.lparen);
                    for (i, arg_id) in args_list.iter().enumerate() {
                        if i > 0 {
                            self.push(",");
                            self.space();
                        }
                        self.format_jinja_arg(*arg_id)?;
                    }
                    self.push_token_id(filter_args.rparen);
                }
            }

            SyntaxJinjaExprKind::Test {
                expr,
                is_keyword,
                not_keyword,
                test_name,
                args,
            } => {
                self.format_jinja_expr(*expr)?;
                self.space();
                self.push_token_id(*is_keyword);
                if let Some(not_tok) = not_keyword {
                    self.space();
                    self.push_token_id(*not_tok);
                }
                self.space();
                self.push_token_id(*test_name);
                if let Some((test_args, args_list)) = args {
                    self.push_token_id(test_args.lparen);
                    for (i, arg_id) in args_list.iter().enumerate() {
                        if i > 0 {
                            self.push(",");
                            self.space();
                        }
                        self.format_jinja_arg(*arg_id)?;
                    }
                    self.push_token_id(test_args.rparen);
                }
            }

            SyntaxJinjaExprKind::Conditional {
                then_expr,
                if_keyword,
                condition,
                else_keyword,
                else_expr,
            } => {
                self.format_jinja_expr(*then_expr)?;
                self.space();
                self.push_token_id(*if_keyword);
                self.space();
                self.format_jinja_expr(*condition)?;
                if let (Some(else_kw), Some(else_e)) = (else_keyword, else_expr) {
                    self.space();
                    self.push_token_id(*else_kw);
                    self.space();
                    self.format_jinja_expr(*else_e)?;
                }
            }

            SyntaxJinjaExprKind::Tuple {
                lparen,
                items,
                rparen,
            } => {
                self.push_token_id(*lparen);
                for (i, item_id) in items.iter().enumerate() {
                    if i > 0 {
                        self.push(",");
                        self.space();
                    }
                    self.format_jinja_expr(*item_id)?;
                }
                self.push_token_id(*rparen);
            }

            SyntaxJinjaExprKind::List {
                lbracket,
                items,
                rbracket,
            } => {
                self.push_token_id(*lbracket);
                for (i, item_id) in items.iter().enumerate() {
                    if i > 0 {
                        self.push(",");
                        self.space();
                    }
                    self.format_jinja_expr(*item_id)?;
                }
                self.push_token_id(*rbracket);
            }

            SyntaxJinjaExprKind::Dict {
                lcurly,
                pairs,
                rcurly,
            } => {
                self.push_token_id(*lcurly);
                for (i, (key_id, colon_id, value_id)) in pairs.iter().enumerate() {
                    if i > 0 {
                        self.push(",");
                        self.space();
                    }
                    self.format_jinja_expr(*key_id)?;
                    self.push_token_id(*colon_id); // colon with no space before
                    self.space(); // space after colon
                    self.format_jinja_expr(*value_id)?;
                }
                self.push_token_id(*rcurly);
            }
        }

        Ok(())
    }

    /// Format a Jinja function/filter argument (positional or keyword).
    fn format_jinja_arg(
        &mut self,
        arg_id: crate::syntax::SyntaxJinjaArgId,
    ) -> Result<(), crate::formatter::FormatterError> {
        use crate::syntax::SyntaxJinjaArgKind;

        let arena = self.syntax_arena.ok_or_else(|| {
            crate::formatter::FormatterError::InvalidContext(
                "Syntax arena required for Jinja argument formatting".to_string(),
            )
        })?;

        let arg = arena.get_jinja_arg(arg_id);

        match &arg.kind {
            SyntaxJinjaArgKind::Positional { expr } => {
                self.format_jinja_expr(*expr)?;
            }
            SyntaxJinjaArgKind::Keyword { name, eq, value } => {
                self.push_token_id(*name);
                self.push_token_id(*eq); // No spaces around = in keyword args
                self.format_jinja_expr(*value)?;
            }
        }

        Ok(())
    }

    /// Format a Jinja expression interpolation {{ expr }} using CST tokens.
    ///
    /// This method emits `{{`, the inner expression, and `}}` individually,
    /// ensuring that trailing trivia (like comments) attached to the `}}` token
    /// are properly preserved.
    ///
    /// **Example**:
    /// ```sql
    /// {{ result2 }} /* comment */
    /// ```
    /// Without CST tokens, the comment would be lost. With CST tokens,
    /// the `}}` token carries the trailing comment.
    pub fn format_jinja_interpolation(
        &mut self,
        interp_id: crate::syntax::SyntaxJinjaInterpolationId,
    ) -> Result<(), crate::formatter::FormatterError> {
        let arena = self.syntax_arena.ok_or_else(|| {
            crate::formatter::FormatterError::InvalidContext(
                "Syntax arena required for Jinja interpolation formatting".to_string(),
            )
        })?;

        let interp = arena.get_jinja_interpolation(interp_id);

        // Emit {{ token
        self.push_token_id(interp.open_expr);

        // Emit inner expression if parsed
        if let Some(expr_id) = interp.expr {
            // Use space_if_needed to avoid double spacing when block comments
            // have already added trailing space via emit_trivia_item
            self.space_if_needed();
            self.format_jinja_expr(expr_id)?;
            self.space_if_needed();
        }

        // Emit }} token
        self.push_token_id(interp.close_expr);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_context() -> RenderContext {
        RenderContext::from_source("SELECT 1".to_string())
    }

    #[test]
    fn test_printer_creation() {
        let config = FormatterConfig::default();
        let source = "SELECT 1";
        let printer = Printer::new(&config, source, None);

        assert_eq!(printer.indent_level(), 0);
        assert_eq!(printer.len(), 0);
        assert!(printer.is_empty());
    }

    #[test]
    fn test_push_text() {
        let config = FormatterConfig::default();
        let source = "SELECT 1";
        let mut printer = Printer::new(&config, source, None);

        printer.push("SELECT");
        assert_eq!(printer.len(), 6);
        assert!(!printer.is_empty());
    }

    #[test]
    fn test_keyword_case() {
        let mut config = FormatterConfig::default();
        config.keyword_case = KeywordCase::Upper;
        let source = "SELECT 1";
        let mut printer = Printer::new(&config, source, None);

        printer.push_keyword("select");
        // Note: Can't directly access output, but len should be 6
        assert_eq!(printer.len(), 6);
    }

    #[test]
    fn test_indentation() {
        let mut config = FormatterConfig::default();
        config.indent_style = IndentStyle::Spaces(2);
        let source = "SELECT 1";
        let mut printer = Printer::new(&config, source, None);

        printer.indent_up();
        assert_eq!(printer.indent_level(), 1);

        printer.newline();
        printer.push("SELECT");
        // Should have 2 spaces + "SELECT" = 8 chars
        assert_eq!(printer.len(), 8 + 1); // +1 for newline

        printer.indent_down();
        assert_eq!(printer.indent_level(), 0);
    }

    #[test]
    fn test_span_tracking() {
        let config = FormatterConfig::default();
        let source = "SELECT 1";
        let mut printer = Printer::new(&config, source, None);

        printer.begin_span(Span { start: 0, end: 8 }, MappingKind::Reformatted);
        printer.push("SELECT");
        printer.space();
        printer.push("1");
        printer.end_span();

        let context = test_context();
        let result = printer.finish(context, false);
        assert!(result.is_ok());
    }
}
