// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! DDL statement formatters (DROP, TRUNCATE, CREATE TABLE, CREATE VIEW, etc.)

use crate::ast::{
    AstAlterTable, AstAlterTableAction, AstAlterTableActionKind, AstCreateTable,
    AstCreateTableColumn, AstCreateTableConstraint, AstCreateTableVariant, AstCreateView, AstDrop,
    AstTruncate,
};
use crate::formatter::printer::Printer;
use crate::formatter::FormatterError;
use crate::lexer::Span;

/// Format DROP statement
///
/// Examples:
/// - DROP TABLE users
/// - DROP VIEW IF EXISTS user_view
/// - DROP SCHEMA reporting CASCADE
pub fn format_drop(printer: &mut Printer, drop: &AstDrop) -> Result<(), FormatterError> {
    // DROP keyword - use push_keyword_span for trivia preservation
    printer.push_keyword_span(drop.keyword_span);
    printer.space();

    // Object type (TABLE, VIEW, etc.) - use push_keyword_span for keyword casing
    if let Some(obj_span) = drop.object_type_span {
        printer.push_keyword_span(obj_span);
        printer.space();
    }

    // IF EXISTS - use push_keyword_span for keyword casing
    if let Some(if_exists_span) = drop.if_exists_span {
        printer.push_span(if_exists_span);
        printer.space();
    }

    // Object name - use push_identifier_span_v2 for identifier casing
    if let Some(name_span) = drop.target_name_span {
        printer.push_identifier_span_v2(name_span);
    }

    // CASCADE/RESTRICT - use push_keyword_span for keyword casing
    if let Some(cr_span) = drop.cascade_restrict_span {
        printer.space();
        printer.push_keyword_span(cr_span);
    }

    Ok(())
}

/// Format TRUNCATE statement
///
/// Examples:
/// - TRUNCATE TABLE users
/// - TRUNCATE users
/// - TRUNCATE TABLE IF EXISTS staging.raw_data
pub fn format_truncate(
    printer: &mut Printer,
    truncate: &AstTruncate,
) -> Result<(), FormatterError> {
    // TRUNCATE keyword - use push_keyword_span for trivia preservation
    printer.push_keyword_span(truncate.keyword_span);
    printer.space();

    // TABLE keyword (optional) - use push_keyword_span for keyword casing
    if let Some(table_span) = truncate.table_span {
        printer.push_keyword_span(table_span);
        printer.space();
    }

    // IF EXISTS - use push_keyword_span for keyword casing
    if let Some(if_exists_span) = truncate.if_exists_span {
        printer.push_span(if_exists_span);
        printer.space();
    }

    // Table name - use push_identifier_span_v2 for identifier casing
    if let Some(table_span) = truncate.target_table_span {
        printer.push_identifier_span_v2(table_span);
    }

    Ok(())
}

/// Format ALTER TABLE statement.
///
/// Emits each keyword, identifier, and action span individually so the output
/// proves the parser actually understood the structure rather than passing
/// through an opaque blob.
pub fn format_alter_table(
    printer: &mut Printer,
    alter: &AstAlterTable,
) -> Result<(), FormatterError> {
    // ALTER keyword
    printer.push_keyword_span(alter.alter_span);
    printer.space();

    // TABLE keyword
    printer.push_keyword_span(alter.table_span);

    // IF EXISTS (optional)
    if let Some(if_exists_span) = alter.if_exists_span {
        printer.space();
        printer.push_span(if_exists_span);
    }

    // Table name
    printer.space();
    printer.push_identifier_span_v2(alter.name_span);

    // Actions
    for (i, action) in alter.actions.iter().enumerate() {
        if i > 0 {
            // Multiple actions are comma-separated in some dialects
            printer.push(",");
        }
        printer.newline();
        printer.indent_up();
        format_alter_table_action(printer, action)?;
        printer.indent_down();
    }

    Ok(())
}

/// Format a single ALTER TABLE action by matching on the action kind and
/// emitting each keyword span individually.
fn format_alter_table_action(
    printer: &mut Printer,
    action: &AstAlterTableAction,
) -> Result<(), FormatterError> {
    use AstAlterTableActionKind::*;

    match &action.kind {
        // ====================================================================
        // Core DDL Actions
        // ====================================================================
        RenameTo {
            rename_span,
            to_span,
            new_name_span,
        } => {
            emit_opt_keyword(printer, *rename_span, true);
            emit_opt_keyword(printer, *to_span, false);
            printer.space();
            printer.push_identifier_span_v2(*new_name_span);
        }
        RenameColumn {
            rename_span,
            column_span,
            old_name_span,
            to_span,
            new_name_span,
        } => {
            emit_opt_keyword(printer, *rename_span, true);
            emit_opt_keyword(printer, *column_span, false);
            printer.space();
            printer.push_identifier_span_v2(*old_name_span);
            emit_opt_keyword(printer, *to_span, false);
            printer.space();
            printer.push_identifier_span_v2(*new_name_span);
        }
        SwapWith {
            swap_span,
            with_span,
            other_table_span,
        } => {
            emit_opt_keyword(printer, *swap_span, true);
            emit_opt_keyword(printer, *with_span, false);
            printer.space();
            printer.push_identifier_span_v2(*other_table_span);
        }
        AddColumn {
            add_span,
            column_span,
            columns_span,
            columns,
        } => {
            emit_opt_keyword(printer, *add_span, true);
            emit_opt_keyword(printer, *column_span, false);
            if columns.is_empty() {
                // Fallback: emit columns_span verbatim
                printer.space();
                printer.push_span(*columns_span);
            } else {
                for (ci, col) in columns.iter().enumerate() {
                    if ci > 0 {
                        printer.push(",");
                    }
                    printer.space();
                    printer.push_span(col.full_span);
                }
            }
        }
        DropColumn {
            drop_span,
            column_span,
            columns_span,
            columns,
        } => {
            emit_opt_keyword(printer, *drop_span, true);
            emit_opt_keyword(printer, *column_span, false);
            if columns.is_empty() {
                printer.space();
                printer.push_span(*columns_span);
            } else {
                for (ci, col_span) in columns.iter().enumerate() {
                    if ci > 0 {
                        printer.push(",");
                    }
                    printer.space();
                    printer.push_identifier_span_v2(*col_span);
                }
            }
        }
        AlterColumn {
            alter_span,
            column_span,
            column_name_span,
            operation_span,
        } => {
            emit_opt_keyword(printer, *alter_span, true);
            emit_opt_keyword(printer, *column_span, false);
            printer.space();
            printer.push_identifier_span_v2(*column_name_span);
            printer.space();
            printer.push_span(*operation_span);
        }

        // ====================================================================
        // Constraint Actions
        // ====================================================================
        AddConstraint {
            add_span,
            constraint_span,
            details_span,
        } => {
            emit_opt_keyword(printer, *add_span, true);
            emit_opt_keyword(printer, *constraint_span, false);
            printer.space();
            printer.push_span(*details_span);
        }
        DropConstraint {
            drop_span,
            constraint_span,
            name_span,
        } => {
            emit_opt_keyword(printer, *drop_span, true);
            emit_opt_keyword(printer, *constraint_span, false);
            printer.space();
            printer.push_identifier_span_v2(*name_span);
        }

        // ====================================================================
        // Clustering Actions
        // ====================================================================
        ClusterBy {
            cluster_span,
            by_span,
            exprs_span,
            exprs: _,
            is_none: _,
        } => {
            emit_opt_keyword(printer, *cluster_span, true);
            emit_opt_keyword(printer, *by_span, false);
            printer.space();
            printer.push_span(*exprs_span);
        }
        DropClusteringKey {
            drop_span,
            clustering_span,
            key_span,
        } => {
            emit_opt_keyword(printer, *drop_span, true);
            emit_opt_keyword(printer, *clustering_span, false);
            emit_opt_keyword(printer, *key_span, false);
        }
        SuspendRecluster {
            suspend_span,
            recluster_span,
        } => {
            emit_opt_keyword(printer, *suspend_span, true);
            emit_opt_keyword(printer, *recluster_span, false);
        }
        ResumeRecluster {
            resume_span,
            recluster_span,
        } => {
            emit_opt_keyword(printer, *resume_span, true);
            emit_opt_keyword(printer, *recluster_span, false);
        }

        // ====================================================================
        // Parameter Actions
        // ====================================================================
        Set {
            set_span,
            parameters_span,
        } => {
            emit_opt_keyword(printer, *set_span, true);
            printer.space();
            printer.push_span(*parameters_span);
        }
        Unset {
            unset_span,
            parameters_span,
        } => {
            emit_opt_keyword(printer, *unset_span, true);
            printer.space();
            printer.push_span(*parameters_span);
        }

        // ====================================================================
        // Governance & Policy Actions
        // ====================================================================
        AddRowAccessPolicy(inner) => {
            emit_opt_keyword(printer, inner.add_span, true);
            emit_opt_keyword(printer, inner.row_span, false);
            emit_opt_keyword(printer, inner.access_span, false);
            emit_opt_keyword(printer, inner.policy_span, false);
            printer.space();
            printer.push_identifier_span_v2(inner.policy_name_span);
            emit_opt_keyword(printer, inner.on_span, false);
            printer.space();
            printer.push_span(inner.columns_span);
        }
        DropRowAccessPolicy {
            drop_span,
            row_span,
            access_span,
            policy_span,
            policy_name_span,
            if_exists_span,
        } => {
            emit_opt_keyword(printer, *drop_span, true);
            emit_opt_keyword(printer, *row_span, false);
            emit_opt_keyword(printer, *access_span, false);
            emit_opt_keyword(printer, *policy_span, false);
            printer.space();
            printer.push_identifier_span_v2(*policy_name_span);
            if let Some(ie) = if_exists_span {
                printer.space();
                printer.push_span(*ie);
            }
        }
        DropAllRowAccessPolicies {
            drop_span,
            all_span,
            row_span,
            access_span,
            policies_span,
        } => {
            emit_opt_keyword(printer, *drop_span, true);
            emit_opt_keyword(printer, *all_span, false);
            emit_opt_keyword(printer, *row_span, false);
            emit_opt_keyword(printer, *access_span, false);
            emit_opt_keyword(printer, *policies_span, false);
        }
        SetRowFilter {
            set_span,
            row_span,
            filter_span,
            function_name_span,
            on_span,
            columns_span,
        } => {
            emit_opt_keyword(printer, *set_span, true);
            emit_opt_keyword(printer, *row_span, false);
            emit_opt_keyword(printer, *filter_span, false);
            printer.space();
            printer.push_identifier_span_v2(*function_name_span);
            emit_opt_keyword(printer, *on_span, false);
            printer.space();
            printer.push_span(*columns_span);
        }
        DropRowFilter {
            drop_span,
            row_span,
            filter_span,
        } => {
            emit_opt_keyword(printer, *drop_span, true);
            emit_opt_keyword(printer, *row_span, false);
            emit_opt_keyword(printer, *filter_span, false);
        }
        SetAggregationPolicy {
            set_span,
            aggregation_span,
            policy_span,
            policy_name_span,
            entity_key_span,
            entity_key_columns: _,
            force_span,
        } => {
            emit_opt_keyword(printer, *set_span, true);
            emit_opt_keyword(printer, *aggregation_span, false);
            emit_opt_keyword(printer, *policy_span, false);
            printer.space();
            printer.push_identifier_span_v2(*policy_name_span);
            if let Some(ek) = entity_key_span {
                printer.space();
                printer.push_span(*ek);
            }
            emit_opt_keyword(printer, *force_span, false);
        }
        UnsetAggregationPolicy {
            unset_span,
            aggregation_span,
            policy_span,
        } => {
            emit_opt_keyword(printer, *unset_span, true);
            emit_opt_keyword(printer, *aggregation_span, false);
            emit_opt_keyword(printer, *policy_span, false);
        }
        SetJoinPolicy {
            set_span,
            join_span,
            policy_span,
            policy_name_span,
            force_span,
        } => {
            emit_opt_keyword(printer, *set_span, true);
            emit_opt_keyword(printer, *join_span, false);
            emit_opt_keyword(printer, *policy_span, false);
            printer.space();
            printer.push_identifier_span_v2(*policy_name_span);
            emit_opt_keyword(printer, *force_span, false);
        }
        UnsetJoinPolicy {
            unset_span,
            join_span,
            policy_span,
        } => {
            emit_opt_keyword(printer, *unset_span, true);
            emit_opt_keyword(printer, *join_span, false);
            emit_opt_keyword(printer, *policy_span, false);
        }
        SetColumnMaskingPolicy(inner) => {
            emit_opt_keyword(printer, inner.alter_span, true);
            emit_opt_keyword(printer, inner.column_span, false);
            printer.space();
            printer.push_identifier_span_v2(inner.column_name_span);
            emit_opt_keyword(printer, inner.set_span, false);
            emit_opt_keyword(printer, inner.masking_span, false);
            emit_opt_keyword(printer, inner.policy_span, false);
            printer.space();
            printer.push_identifier_span_v2(inner.policy_name_span);
            if let Some(using) = inner.using_span {
                printer.space();
                printer.push_span(using);
            }
            emit_opt_keyword(printer, inner.force_span, false);
        }
        UnsetColumnMaskingPolicy {
            alter_span,
            column_span,
            column_name_span,
            unset_span,
            masking_span,
            policy_span,
        } => {
            emit_opt_keyword(printer, *alter_span, true);
            emit_opt_keyword(printer, *column_span, false);
            printer.space();
            printer.push_identifier_span_v2(*column_name_span);
            emit_opt_keyword(printer, *unset_span, false);
            emit_opt_keyword(printer, *masking_span, false);
            emit_opt_keyword(printer, *policy_span, false);
        }
        SetColumnMask {
            alter_span,
            column_span,
            column_name_span,
            set_span,
            mask_span,
            function_name_span,
        } => {
            emit_opt_keyword(printer, *alter_span, true);
            emit_opt_keyword(printer, *column_span, false);
            printer.space();
            printer.push_identifier_span_v2(*column_name_span);
            emit_opt_keyword(printer, *set_span, false);
            emit_opt_keyword(printer, *mask_span, false);
            printer.space();
            printer.push_identifier_span_v2(*function_name_span);
        }
        DropColumnMask {
            alter_span,
            column_span,
            column_name_span,
            drop_span,
            mask_span,
        } => {
            emit_opt_keyword(printer, *alter_span, true);
            emit_opt_keyword(printer, *column_span, false);
            printer.space();
            printer.push_identifier_span_v2(*column_name_span);
            emit_opt_keyword(printer, *drop_span, false);
            emit_opt_keyword(printer, *mask_span, false);
        }
        SetColumnProjectionPolicy(inner) => {
            emit_opt_keyword(printer, inner.alter_span, true);
            emit_opt_keyword(printer, inner.column_span, false);
            printer.space();
            printer.push_identifier_span_v2(inner.column_name_span);
            emit_opt_keyword(printer, inner.set_span, false);
            emit_opt_keyword(printer, inner.projection_span, false);
            emit_opt_keyword(printer, inner.policy_span, false);
            printer.space();
            printer.push_identifier_span_v2(inner.policy_name_span);
            emit_opt_keyword(printer, inner.force_span, false);
        }
        UnsetColumnProjectionPolicy {
            alter_span,
            column_span,
            column_name_span,
            unset_span,
            projection_span,
            policy_span,
        } => {
            emit_opt_keyword(printer, *alter_span, true);
            emit_opt_keyword(printer, *column_span, false);
            printer.space();
            printer.push_identifier_span_v2(*column_name_span);
            emit_opt_keyword(printer, *unset_span, false);
            emit_opt_keyword(printer, *projection_span, false);
            emit_opt_keyword(printer, *policy_span, false);
        }

        // ====================================================================
        // Tag Actions
        // ====================================================================
        SetTag {
            set_span,
            tag_span,
            assignments_span,
        } => {
            emit_opt_keyword(printer, *set_span, true);
            emit_opt_keyword(printer, *tag_span, false);
            printer.space();
            printer.push_span(*assignments_span);
        }
        UnsetTag {
            unset_span,
            tag_span,
            tags_span,
        } => {
            emit_opt_keyword(printer, *unset_span, true);
            emit_opt_keyword(printer, *tag_span, false);
            printer.space();
            printer.push_span(*tags_span);
        }
        SetColumnTag {
            alter_span,
            column_span,
            column_name_span,
            set_span,
            tag_span,
            assignments_span,
        } => {
            emit_opt_keyword(printer, *alter_span, true);
            emit_opt_keyword(printer, *column_span, false);
            printer.space();
            printer.push_identifier_span_v2(*column_name_span);
            emit_opt_keyword(printer, *set_span, false);
            emit_opt_keyword(printer, *tag_span, false);
            printer.space();
            printer.push_span(*assignments_span);
        }
        UnsetColumnTag {
            alter_span,
            column_span,
            column_name_span,
            unset_span,
            tag_span,
            tags_span,
        } => {
            emit_opt_keyword(printer, *alter_span, true);
            emit_opt_keyword(printer, *column_span, false);
            printer.space();
            printer.push_identifier_span_v2(*column_name_span);
            emit_opt_keyword(printer, *unset_span, false);
            emit_opt_keyword(printer, *tag_span, false);
            printer.space();
            printer.push_span(*tags_span);
        }

        // ====================================================================
        // Search Optimization
        // ====================================================================
        AddSearchOptimization {
            add_span,
            search_span,
            optimization_span,
            on_clause_span,
        } => {
            emit_opt_keyword(printer, *add_span, true);
            emit_opt_keyword(printer, *search_span, false);
            emit_opt_keyword(printer, *optimization_span, false);
            if let Some(on) = on_clause_span {
                printer.space();
                printer.push_span(*on);
            }
        }
        DropSearchOptimization {
            drop_span,
            search_span,
            optimization_span,
            on_clause_span,
        } => {
            emit_opt_keyword(printer, *drop_span, true);
            emit_opt_keyword(printer, *search_span, false);
            emit_opt_keyword(printer, *optimization_span, false);
            if let Some(on) = on_clause_span {
                printer.space();
                printer.push_span(*on);
            }
        }

        // ====================================================================
        // Data Quality & Metrics
        // ====================================================================
        SetDataMetricSchedule {
            set_span,
            schedule_span,
        } => {
            emit_opt_keyword(printer, *set_span, true);
            printer.space();
            printer.push_span(*schedule_span);
        }
        UnsetDataMetricSchedule {
            unset_span,
            schedule_span,
        } => {
            emit_opt_keyword(printer, *unset_span, true);
            emit_opt_keyword(printer, *schedule_span, false);
        }
        AddDataMetricFunction {
            add_span,
            data_span,
            metric_span,
            function_span,
            function_name_span,
            on_span,
            columns_span,
        } => {
            emit_opt_keyword(printer, *add_span, true);
            emit_opt_keyword(printer, *data_span, false);
            emit_opt_keyword(printer, *metric_span, false);
            emit_opt_keyword(printer, *function_span, false);
            printer.space();
            printer.push_identifier_span_v2(*function_name_span);
            emit_opt_keyword(printer, *on_span, false);
            printer.space();
            printer.push_span(*columns_span);
        }
        DropDataMetricFunction {
            drop_span,
            data_span,
            metric_span,
            function_span,
            function_name_span,
            on_span,
            columns_span,
        } => {
            emit_opt_keyword(printer, *drop_span, true);
            emit_opt_keyword(printer, *data_span, false);
            emit_opt_keyword(printer, *metric_span, false);
            emit_opt_keyword(printer, *function_span, false);
            printer.space();
            printer.push_identifier_span_v2(*function_name_span);
            emit_opt_keyword(printer, *on_span, false);
            printer.space();
            printer.push_span(*columns_span);
        }

        // ====================================================================
        // Storage Lifecycle
        // ====================================================================
        AddStorageLifecyclePolicy {
            add_span,
            storage_span,
            lifecycle_span,
            policy_span,
            policy_name_span,
            on_span,
            columns_span,
        } => {
            emit_opt_keyword(printer, *add_span, true);
            emit_opt_keyword(printer, *storage_span, false);
            emit_opt_keyword(printer, *lifecycle_span, false);
            emit_opt_keyword(printer, *policy_span, false);
            printer.space();
            printer.push_identifier_span_v2(*policy_name_span);
            emit_opt_keyword(printer, *on_span, false);
            printer.space();
            printer.push_span(*columns_span);
        }
        DropStorageLifecyclePolicy {
            drop_span,
            storage_span,
            lifecycle_span,
            policy_span,
        } => {
            emit_opt_keyword(printer, *drop_span, true);
            emit_opt_keyword(printer, *storage_span, false);
            emit_opt_keyword(printer, *lifecycle_span, false);
            emit_opt_keyword(printer, *policy_span, false);
        }

        // ====================================================================
        // BigQuery-specific Actions
        // ====================================================================
        SetOptions {
            set_span,
            options_span,
            options_list_span,
        } => {
            emit_opt_keyword(printer, *set_span, true);
            emit_opt_keyword(printer, *options_span, false);
            printer.space();
            printer.push_span(*options_list_span);
        }
        SetDefaultCollate {
            set_span,
            default_span,
            collate_span,
            collation_span,
        } => {
            emit_opt_keyword(printer, *set_span, true);
            emit_opt_keyword(printer, *default_span, false);
            emit_opt_keyword(printer, *collate_span, false);
            printer.space();
            printer.push_span(*collation_span);
        }
        DropPrimaryKey {
            drop_span,
            primary_span,
            key_span,
            if_exists_span,
        } => {
            emit_opt_keyword(printer, *drop_span, true);
            emit_opt_keyword(printer, *primary_span, false);
            emit_opt_keyword(printer, *key_span, false);
            if let Some(ie) = if_exists_span {
                printer.space();
                printer.push_span(*ie);
            }
        }
        AlterColumnSetOptions {
            alter_span,
            column_span,
            column_name_span,
            set_span,
            options_span,
            options_list_span,
        } => {
            emit_opt_keyword(printer, *alter_span, true);
            emit_opt_keyword(printer, *column_span, false);
            printer.space();
            printer.push_identifier_span_v2(*column_name_span);
            emit_opt_keyword(printer, *set_span, false);
            emit_opt_keyword(printer, *options_span, false);
            printer.space();
            printer.push_span(*options_list_span);
        }
        AlterColumnDropNotNull {
            alter_span,
            column_span,
            column_name_span,
            drop_span,
            not_span,
            null_span,
        } => {
            emit_opt_keyword(printer, *alter_span, true);
            emit_opt_keyword(printer, *column_span, false);
            printer.space();
            printer.push_identifier_span_v2(*column_name_span);
            emit_opt_keyword(printer, *drop_span, false);
            emit_opt_keyword(printer, *not_span, false);
            emit_opt_keyword(printer, *null_span, false);
        }
        AlterColumnSetDataType {
            alter_span,
            column_span,
            column_name_span,
            set_span,
            data_span,
            type_span,
            data_type_span,
        } => {
            emit_opt_keyword(printer, *alter_span, true);
            emit_opt_keyword(printer, *column_span, false);
            printer.space();
            printer.push_identifier_span_v2(*column_name_span);
            emit_opt_keyword(printer, *set_span, false);
            emit_opt_keyword(printer, *data_span, false);
            emit_opt_keyword(printer, *type_span, false);
            printer.space();
            printer.push_span(*data_type_span);
        }
        AlterColumnSetDefault {
            alter_span,
            column_span,
            column_name_span,
            set_span,
            default_span,
            expr_span,
        } => {
            emit_opt_keyword(printer, *alter_span, true);
            emit_opt_keyword(printer, *column_span, false);
            printer.space();
            printer.push_identifier_span_v2(*column_name_span);
            emit_opt_keyword(printer, *set_span, false);
            emit_opt_keyword(printer, *default_span, false);
            printer.space();
            printer.push_span(*expr_span);
        }
        AlterColumnDropDefault {
            alter_span,
            column_span,
            column_name_span,
            drop_span,
            default_span,
        } => {
            emit_opt_keyword(printer, *alter_span, true);
            emit_opt_keyword(printer, *column_span, false);
            printer.space();
            printer.push_identifier_span_v2(*column_name_span);
            emit_opt_keyword(printer, *drop_span, false);
            emit_opt_keyword(printer, *default_span, false);
        }

        // ====================================================================
        // Databricks Table Properties Actions
        // ====================================================================
        SetTblProperties {
            set_span,
            tblproperties_span,
            properties_span,
        } => {
            emit_opt_keyword(printer, *set_span, true);
            emit_opt_keyword(printer, *tblproperties_span, false);
            printer.space();
            printer.push_span(*properties_span);
        }
        UnsetTblProperties {
            unset_span,
            tblproperties_span,
            if_exists_span,
            keys_span,
        } => {
            emit_opt_keyword(printer, *unset_span, true);
            emit_opt_keyword(printer, *tblproperties_span, false);
            if let Some(ie) = if_exists_span {
                printer.space();
                printer.push_span(*ie);
            }
            printer.space();
            printer.push_span(*keys_span);
        }

        // ====================================================================
        // Row Level Security toggle
        // ====================================================================
        RowLevelSecurity { keyword_span, .. } => {
            printer.push_span(*keyword_span);
        }

        // ====================================================================
        // Fallback Variants
        // ====================================================================
        GovernanceSpan { span } | Unknown { span } => {
            printer.push_span(*span);
        }
    }

    Ok(())
}

/// Helper: emit an optional keyword span with a leading space.
/// If `first` is true, no leading space is emitted (start of action).
#[inline]
fn emit_opt_keyword(printer: &mut Printer, span: Option<Span>, first: bool) {
    if let Some(s) = span {
        if !first {
            printer.space();
        }
        printer.push_keyword_span(s);
    }
}

/// Emit table options (CLUSTER BY, COPY GRANTS, TAG, etc.)
/// Returns true if any options were emitted
fn emit_table_options(
    printer: &mut Printer,
    table: &AstCreateTable,
) -> Result<bool, FormatterError> {
    // Collect ALL table-level option spans first
    let mut all_table_option_spans: Vec<Span> = [
        table.cluster_by_span,
        table.partition_by_span,
        table.copy_grants_span,
        table.copy_tags_span,
        table.table_comment_span,
        table.retention_span,
        table.change_tracking_span,
        table.data_retention_time_in_days_span,
        table.max_data_extension_time_in_days_span,
        table.default_ddl_collation_span,
        table.row_access_policy_span,
        table.aggregation_policy_span,
        table.join_policy_span,
        table.storage_lifecycle_policy_span,
        table.tag_span,
        table.enable_schema_evolution_span,
        table.with_row_access_policy_span,
        table.with_contact_span,
    ]
    .iter()
    .filter_map(|s| *s)
    .collect();

    // Check if we have any individual options
    let has_individual_options = !all_table_option_spans.is_empty();

    // Add table_options_span as fallback if no individual options
    if !has_individual_options {
        if let Some(span) = table.table_options_span {
            all_table_option_spans.push(span);
        }
    }

    // Emit all table options as one combined span to avoid trivia duplication
    if !all_table_option_spans.is_empty() {
        let first_start = all_table_option_spans
            .iter()
            .map(|s| s.start)
            .min()
            .unwrap();
        let last_end = all_table_option_spans.iter().map(|s| s.end).max().unwrap();
        let combined_span = Span {
            start: first_start,
            end: last_end,
        };

        printer.newline();
        printer.push_span(combined_span);
        return Ok(true);
    }

    Ok(false)
}

/// Format CREATE TABLE statement
pub fn format_create_table(
    printer: &mut Printer,
    table: &AstCreateTable,
) -> Result<(), FormatterError> {
    // CREATE keyword - use push_keyword_span to emit trivia
    printer.push_keyword_span(table.keyword_span);

    // OR REPLACE (if present) - use push_span for proper trivia emission
    if let Some(or_replace_span) = table.or_replace_span {
        printer.space();
        printer.push_span(or_replace_span);
    }

    // PROCEDURE SCOPED prefix (procedure-scoped temporary table) - emitted
    // before the TEMP/TEMPORARY modifier, matching source order.
    if let Some(scoped_span) = table.scoped_span {
        printer.space();
        printer.push_span(scoped_span);
    }

    // TEMP/TEMPORARY/TRANSIENT (if present) - use push_span for proper trivia emission
    if let Some(temp_span) = table.temp_kind_span {
        printer.space();
        printer.push_span(temp_span);
    }

    // ICEBERG/HYBRID/EVENT table-kind variant (if present)
    if let Some(kind_span) = table.table_kind_span {
        printer.space();
        printer.push_span(kind_span);
    }

    // TABLE keyword - use push_keyword_span
    printer.space();
    printer.push_keyword_span(table.table_keyword_span);

    // Table name - use push_identifier_span_v2 for identifier casing
    printer.space();
    printer.push_identifier_span_v2(table.name_span);

    // Handle different CREATE TABLE variants
    match table.variant {
        AstCreateTableVariant::Plain => {
            // Column definitions
            if let Some(_columns_span) = table.columns_span {
                // Use lparen_span to properly emit trivia for opening paren
                if let Some(lparen) = table.lparen_span {
                    printer.emit_comments_before(lparen.start);
                    printer.space();
                    printer.push_span(lparen);
                } else {
                    printer.space();
                    printer.push_char('(');
                }
                printer.newline();
                printer.indent_up();

                for (idx, col) in table.columns.iter().enumerate() {
                    format_table_column(printer, col, idx > 0)?;
                }

                // Constraints
                for constraint in &table.constraints {
                    format_table_constraint(printer, constraint)?;
                }

                printer.indent_down();
                printer.newline();
                // Use rparen_span to properly emit trivia for closing paren
                if let Some(rparen) = table.rparen_span {
                    printer.push_span(rparen);
                } else {
                    printer.push_char(')');
                }
            }
        }
        AstCreateTableVariant::Like => {
            // CREATE TABLE ... LIKE source_table
            // Note: like_source_span includes "LIKE source_table" from parser
            if let Some(like_span) = table.like_source_span {
                printer.emit_comments_before(like_span.start);
                printer.newline();
                // The span already includes the LIKE keyword, so just emit the span
                printer.push_span(like_span);
            }
        }
        AstCreateTableVariant::Clone => {
            // CREATE TABLE ... [DEEP|SHALLOW] CLONE source_table [AT|BEFORE (...)] [TIMESTAMP|VERSION AS OF ...] [TBLPROPERTIES (...)] [LOCATION '...']
            // Databricks: DEEP/SHALLOW prefix, TIMESTAMP/VERSION AS OF, TBLPROPERTIES, LOCATION
            // Snowflake: AT/BEFORE time travel

            // Emit DEEP/SHALLOW clone kind if present (Databricks)
            if let Some(kind_span) = table.clone_kind_span {
                printer.emit_comments_before(kind_span.start);
                printer.newline();
                printer.push_span(kind_span);
            }

            // Emit CLONE source
            if let Some(clone_span) = table.clone_source_span {
                printer.emit_comments_before(clone_span.start);
                if table.clone_kind_span.is_some() {
                    printer.space(); // Space after DEEP/SHALLOW
                } else {
                    printer.newline();
                }
                // The span already includes the CLONE keyword, so just emit the span
                printer.push_span(clone_span);

                // Time travel (AT/BEFORE for Snowflake)
                if let Some(time_travel) = &table.time_travel {
                    let tt_span = match time_travel.as_ref() {
                        crate::ast::AstTimeTravelClause::SnowflakeAtBefore(tt) => tt.span,
                        crate::ast::AstTimeTravelClause::ForSystemTime(fst) => fst.span,
                        crate::ast::AstTimeTravelClause::DatabricksAsOf(dbx) => dbx.span,
                    };
                    printer.emit_comments_before(tt_span.start);
                    printer.space();
                    printer.push_span(tt_span);
                }
            }

            // Emit TIMESTAMP/VERSION AS OF if present (Databricks)
            if let Some(temporal_span) = table.clone_temporal_span {
                printer.emit_comments_before(temporal_span.start);
                printer.space();
                printer.push_span(temporal_span);
            }

            // Emit TBLPROPERTIES if present (Databricks)
            if let Some(tblprops_span) = table.clone_tblproperties_span {
                printer.emit_comments_before(tblprops_span.start);
                printer.newline();
                printer.push_span(tblprops_span);
            }

            // Emit LOCATION if present (Databricks)
            if let Some(loc_span) = table.clone_location_span {
                printer.emit_comments_before(loc_span.start);
                printer.newline();
                printer.push_span(loc_span);
            }
        }
        AstCreateTableVariant::Ctas => {
            // CREATE TABLE ... (cols) AS SELECT ...
            // First emit column definitions if present
            if let Some(_columns_span) = table.columns_span {
                // Use lparen_span to properly emit trivia for opening paren
                if let Some(lparen) = table.lparen_span {
                    printer.emit_comments_before(lparen.start);
                    printer.space();
                    printer.push_span(lparen);
                } else {
                    printer.space();
                    printer.push_char('(');
                }
                printer.newline();
                printer.indent_up();

                for (idx, col) in table.columns.iter().enumerate() {
                    format_table_column(printer, col, idx > 0)?;
                }

                // Constraints (if any in CTAS)
                for constraint in &table.constraints {
                    format_table_constraint(printer, constraint)?;
                }

                printer.indent_down();
                printer.newline();
                // Use rparen_span to properly emit trivia for closing paren
                if let Some(rparen) = table.rparen_span {
                    printer.push_span(rparen);
                } else {
                    printer.push_char(')');
                }
            }

            // Emit table options BEFORE the AS keyword for CTAS
            // (e.g., CLUSTER BY, COPY GRANTS, etc.)
            emit_table_options(printer, table)?;

            // Always emit AS for CTAS (even if query is incomplete/missing for Jinja fragments)
            printer.newline();
            printer.push_keyword("AS");

            // Then emit the query if present
            if let Some(ctas_result) = &table.ctas_query {
                printer.newline();

                match ctas_result {
                    Ok(parsed_select) => {
                        // Format the parsed SELECT/SetSelect statement
                        printer.emit_comments_before(parsed_select.span().start);
                        super::format_select(printer, parsed_select.as_ref())?;
                    }
                    Err(query_span) => {
                        // Fallback: extract unparsed span as-is
                        printer.emit_comments_before(query_span.start);
                        printer.push_span(*query_span);
                    }
                }
            }

            // Skip the table options emission at the end (already done above)
            // by setting a flag - actually we need to restructure this
            // For now, emit semicolon if present and return early
            if let Some(semi_id) = table.semicolon_token {
                printer.push_token_id(semi_id);
            }
            return Ok(());
        }
        AstCreateTableVariant::UsingTemplate => {
            if let Some(template_span) = table.using_template_span {
                printer.emit_comments_before(template_span.start);
                printer.newline();
                printer.push_span(template_span);
            }
        }
        AstCreateTableVariant::FromArchive => {
            if let Some(archive_span) = table.from_archive_span {
                printer.emit_comments_before(archive_span.start);
                printer.newline();
                printer.push_span(archive_span);
            }
        }
        AstCreateTableVariant::FromSnapshotSet => {
            if let Some(snapshot_span) = table.from_snapshot_set_span {
                printer.emit_comments_before(snapshot_span.start);
                printer.newline();
                printer.push_span(snapshot_span);
            }
        }
    }

    // Table options - use shared helper
    // (CTAS variant handles this separately and returns early)
    emit_table_options(printer, table)?;

    // Emit semicolon if present (scripting context)
    if let Some(semi_id) = table.semicolon_token {
        printer.push_token_id(semi_id);
    }

    Ok(())
}

/// Format a single table column definition
fn format_table_column(
    printer: &mut Printer,
    col: &AstCreateTableColumn,
    needs_comma: bool,
) -> Result<(), FormatterError> {
    // Emit comma FIRST (before any leading comments for this column)
    // This ensures idempotent output: comma comes before the column's leading trivia
    if needs_comma {
        printer.push_char(',');
        printer.newline();
    }

    printer.emit_comments_before(col.full_span.start);

    // Column name - use push_identifier_span_v2 for identifier casing
    if let Some(name_span) = col.name_span {
        printer.push_identifier_span_v2(name_span);

        if let Some(type_span) = col.type_span {
            printer.space();
            printer.push_span(type_span);
        }
    }

    // Column constraints/options - emit in SOURCE ORDER to avoid trivia duplication
    // when reordering (e.g., NOT NULL before COLLATE in source, but COLLATE before NOT NULL in output)
    //
    // Collect all option spans with their source positions
    let mut options: Vec<Span> = [
        col.collate_span,
        col.not_null_span,
        col.default_expr_span,
        col.identity_or_autoincrement_span,
        col.generated_always_span,
        col.virtual_expr_span,
        col.storage_keyword_span,
    ]
    .iter()
    .filter_map(|s| *s)
    .collect();

    // Sort by source position (start offset)
    options.sort_by_key(|span| span.start);

    // Emit in source order
    for option_span in options {
        printer.space();
        printer.push_span(option_span);
    }

    // Inline constraint - emit using CST token IDs for keywords, spans for complex content
    if let Some(constraint_id) = col.inline_constraint_id {
        // Copy constraint data from syntax arena (SyntaxInlineConstraint is Copy)
        let constraint = if let Some(syntax_arena) = printer.syntax_arena() {
            *syntax_arena.get_inline_constraint(constraint_id)
        } else {
            return Err(FormatterError::NotImplemented(
                "Syntax arena not available".to_string(),
            ));
        };

        printer.space();

        // CONSTRAINT keyword and name
        if let Some(kw) = constraint.constraint_keyword {
            printer.push_keyword_token_id(kw);
            if let Some(name) = constraint.constraint_name {
                printer.space();
                printer.push_token_id(name);
            }
            printer.space();
        }

        // Constraint type keyword (PRIMARY, UNIQUE, FOREIGN, CHECK)
        printer.push_keyword_token_id(constraint.constraint_type_keyword);

        // KEY keyword (after PRIMARY/FOREIGN)
        if let Some(key_kw) = constraint.key_keyword {
            printer.space();
            printer.push_keyword_token_id(key_kw);
        }

        // CHECK expression: emit the parenthesized expression
        if let Some(check_span) = constraint.check_expr_span {
            printer.space();
            printer.push_span(check_span);
        }

        // FOREIGN KEY references: REFERENCES table(col) ON DELETE CASCADE
        // Skip the REFERENCES keyword if it's the same token as constraint_type_keyword
        // (happens when column is defined as: col INT REFERENCES table(col))
        if let Some(ref_kw) = constraint.references_keyword {
            // Only emit REFERENCES if it's a separate token from constraint_type_keyword
            if ref_kw != constraint.constraint_type_keyword {
                printer.space();
                printer.push_keyword_token_id(ref_kw);
            }

            // Emit table(col1, col2) part
            if let Some(target_span) = constraint.references_target_span {
                printer.space();
                printer.push_span(target_span);
            }

            // ON DELETE/UPDATE action
            if let Some(on_kw) = constraint.on_keyword {
                printer.space();
                printer.push_keyword_token_id(on_kw);

                if let Some(action_trigger) = constraint.action_trigger_keyword {
                    printer.space();
                    printer.push_keyword_token_id(action_trigger);

                    if let Some(action) = constraint.action_keyword {
                        printer.space();
                        printer.push_keyword_token_id(action);
                    }
                }
            }
        }
    }

    // Remaining column options
    for option_span in [col.masking_policy_span, col.tag_span, col.comment_span]
        .iter()
        .filter_map(|s| *s)
    {
        printer.space();
        printer.push_span(option_span);
    }

    Ok(())
}

/// Format a table-level constraint
fn format_table_constraint(
    printer: &mut Printer,
    constraint: &AstCreateTableConstraint,
) -> Result<(), FormatterError> {
    printer.emit_comments_before(constraint.full_span.start);
    printer.push_char(',');
    printer.newline();
    // Use push_span to preserve trailing trivia (comments)
    printer.push_span(constraint.full_span);

    Ok(())
}

/// Format CREATE VIEW statement
pub fn format_create_view(
    printer: &mut Printer,
    view: &AstCreateView,
) -> Result<(), FormatterError> {
    // CREATE keyword - use push_keyword_span for trivia preservation
    printer.push_keyword_span(view.keyword_span);

    // OR REPLACE (if present) - use push_span for trivia preservation
    if let Some(or_replace_span) = view.or_replace_span {
        printer.space();
        printer.push_span(or_replace_span);
    }

    // OR ALTER (if present, MSSQL) - use push_span for trivia preservation
    if let Some(or_alter_span) = view.or_alter_span {
        printer.space();
        printer.push_span(or_alter_span);
    }

    // MySQL view prelude (ALGORITHM / DEFINER / SQL SECURITY), in grammar order,
    // emitted verbatim so the clauses round-trip byte-exact. MySQL-only, so they
    // never co-occur with the SECURE/temp/RECURSIVE/MATERIALIZED modifiers.
    if let Some(algorithm_span) = view.algorithm_span {
        printer.space();
        printer.push_span(algorithm_span);
    }
    if let Some(definer) = view.definer.as_ref() {
        printer.space();
        printer.push_span(definer.span);
    }
    if let Some(sql_security) = view.sql_security.as_ref() {
        printer.space();
        printer.push_span(sql_security.span);
    }

    // SECURE (if present) - use push_span for trivia preservation
    if let Some(secure_span) = view.secure_span {
        printer.space();
        printer.push_span(secure_span);
    }

    // TEMP/TEMPORARY (if present) - use push_span for trivia preservation
    if let Some(temp_span) = view.temp_kind_span {
        printer.space();
        printer.push_span(temp_span);
    }

    // RECURSIVE (if present) - use push_span for trivia preservation
    if let Some(recursive_span) = view.recursive_span {
        printer.space();
        printer.push_span(recursive_span);
    }

    // MATERIALIZED (if present) - materialized view
    if let Some(mat_span) = view.materialized_span {
        printer.space();
        printer.push_span(mat_span);
    }

    // VIEW keyword - use push_span for trivia preservation
    printer.space();
    printer.push_span(view.view_keyword_span);

    // IF NOT EXISTS (if present) - use push_span for trivia preservation
    if let Some(if_not_exists_span) = view.if_not_exists_span {
        printer.space();
        printer.push_span(if_not_exists_span);
    }

    // View name - use push_identifier_span_v2 for identifier casing
    printer.space();
    printer.push_identifier_span_v2(view.name_span);

    // Column list (if present) - use CST syntax nodes for trivia preservation
    if let Some(column_list_id) = view.column_list_id {
        // Retrieve column list data from syntax arena
        let column_list_data = if let Some(syntax_arena) = printer.syntax_arena() {
            let col_list = syntax_arena.get_view_column_list(column_list_id);

            // Extract all needed data before mutating printer
            let l_paren = col_list.l_paren;
            let r_paren = col_list.r_paren;
            let commas = col_list.commas.clone();

            // Extract column attribute IDs
            let columns_data: Vec<_> = col_list
                .columns
                .iter()
                .map(|&col_id| {
                    let col = syntax_arena.get_view_column(col_id);

                    // Extract all attribute node data to avoid borrowing issues
                    let comment_data = col.comment_id.map(|id| {
                        let c = syntax_arena.get_view_column_comment(id);
                        (c.comment_keyword, c.string_literal)
                    });

                    let masking_data = col.masking_policy_id.map(|id| {
                        let m = syntax_arena.get_view_column_masking_policy(id);
                        (
                            m.with_keyword,
                            m.masking_keyword,
                            m.policy_keyword,
                            m.policy_name,
                            m.using_keyword,
                            m.using_l_paren,
                            m.using_r_paren,
                        )
                    });

                    let projection_data = col.projection_policy_id.map(|id| {
                        let p = syntax_arena.get_view_column_projection_policy(id);
                        (
                            p.with_keyword,
                            p.projection_keyword,
                            p.policy_keyword,
                            p.policy_name,
                        )
                    });

                    let tag_data = col.tag_id.map(|id| {
                        let t = syntax_arena.get_view_column_tag(id);
                        (t.with_keyword, t.tag_keyword, t.l_paren, t.r_paren)
                    });

                    (
                        col.name,
                        col.span.start,
                        comment_data,
                        masking_data,
                        projection_data,
                        tag_data,
                    )
                })
                .collect();

            Some((l_paren, r_paren, commas, columns_data))
        } else {
            None
        };

        if let Some((l_paren, r_paren, commas, columns_data)) = column_list_data {
            printer.space();
            printer.push_token_id(l_paren);
            printer.newline();
            printer.indent_up();

            for (i, (name_id, col_start, comment_data, masking_data, projection_data, tag_data)) in
                columns_data.iter().enumerate()
            {
                // Emit comments before this column
                printer.emit_comments_before(*col_start);

                // Column name
                printer.push_token_id(*name_id);

                // Emit column attributes using extracted TokenId data
                // COMMENT attribute
                if let Some((comment_kw, string_lit)) = comment_data {
                    printer.space();
                    printer.push_token_id(*comment_kw);
                    printer.space();
                    printer.push_token_id(*string_lit);
                }

                // MASKING POLICY attribute
                if let Some((
                    with_kw,
                    masking_kw,
                    policy_kw,
                    policy_name,
                    using_kw,
                    using_lparen,
                    using_rparen,
                )) = masking_data
                {
                    printer.space();
                    if let Some(with_kw) = with_kw {
                        printer.push_token_id(*with_kw);
                        printer.space();
                    }
                    printer.push_token_id(*masking_kw);
                    printer.space();
                    printer.push_token_id(*policy_kw);
                    printer.space();
                    printer.push_token_id(*policy_name);
                    if let Some(using_kw) = using_kw {
                        printer.space();
                        printer.push_token_id(*using_kw);
                        if let (Some(lparen), Some(rparen)) = (using_lparen, using_rparen) {
                            printer.space();
                            printer.push_token_id(*lparen);
                            // Emit all tokens between parens
                            let rparen_start = printer.get_token_by_id(*rparen).unwrap().span.start;
                            printer.emit_all_tokens_until(rparen_start);
                            printer.push_token_id(*rparen);
                        }
                    }
                }

                // PROJECTION POLICY attribute
                if let Some((with_kw, projection_kw, policy_kw, policy_name)) = projection_data {
                    printer.space();
                    if let Some(with_kw) = with_kw {
                        printer.push_token_id(*with_kw);
                        printer.space();
                    }
                    printer.push_token_id(*projection_kw);
                    printer.space();
                    printer.push_token_id(*policy_kw);
                    printer.space();
                    printer.push_token_id(*policy_name);
                }

                // TAG attribute
                if let Some((with_kw, tag_kw, lparen, rparen)) = tag_data {
                    printer.space();
                    if let Some(with_kw) = with_kw {
                        printer.push_token_id(*with_kw);
                        printer.space();
                    }
                    printer.push_token_id(*tag_kw);
                    printer.space();
                    printer.push_token_id(*lparen);
                    // Emit all tokens between parens
                    let rparen_start = printer.get_token_by_id(*rparen).unwrap().span.start;
                    printer.emit_all_tokens_until(rparen_start);
                    printer.push_token_id(*rparen);
                }

                // Emit comma after this column (if not the last one)
                if i < commas.len() {
                    printer.push_token_id(commas[i]);
                    printer.newline();
                }
            }

            printer.indent_down();
            printer.newline();
            printer.push_token_id(r_paren);
        } else {
            // Fallback if no syntax arena
            if let Some(columns_span) = view.columns_span {
                printer.space();
                printer.push_span(columns_span);
            }
        }
    } else if let Some(columns_span) = view.columns_span {
        // Fallback: use raw span if columns not parsed with CST
        printer.space();
        printer.push_span(columns_span);
    }

    // View-level options - use push_span for trivia preservation
    // For materialized views, COMMENT may appear after CLUSTER BY, so handle it separately
    let mat_clauses_start = view
        .partition_by_span
        .or(view.cluster_by_span)
        .or(view.bq_options_span)
        .map(|s| s.start);

    for option_span in [
        view.row_access_policy_span,
        view.aggregation_policy_span,
        view.join_policy_span,
        view.tag_span,
        view.with_contact_span,
        view.change_tracking_span,
        view.copy_grants_span,
        // PostgreSQL WITH ( option [= value], ... ) — emitted byte-exact
        view.with_options_span,
        // Only emit comment here if it's before materialized clauses (or no materialized clauses)
        view.comment_span
            .filter(|cs| mat_clauses_start.is_none_or(|ms| cs.start < ms)),
    ]
    .iter()
    .filter_map(|s| *s)
    {
        printer.newline();
        printer.push_span(option_span);
    }

    // Materialized view clauses: PARTITION BY, CLUSTER BY, OPTIONS
    if let Some(part_span) = view.partition_by_span {
        printer.newline();
        printer.push_span(part_span);
    }
    if let Some(cluster_span) = view.cluster_by_span {
        printer.newline();
        printer.push_span(cluster_span);
    }
    if let Some(bq_opts_span) = view.bq_options_span {
        printer.newline();
        printer.push_span(bq_opts_span);
    }

    // Emit COMMENT after materialized clauses if it appears after them in source
    if let Some(cs) = view.comment_span {
        if mat_clauses_start.is_some_and(|ms| cs.start >= ms) {
            printer.newline();
            printer.push_span(cs);
        }
    }

    // AS keyword and SELECT query (or REPLICA OF)
    printer.newline();
    printer.push_keyword("AS");

    if let Some(replica_span) = view.replica_of_span {
        // AS REPLICA OF source_view
        printer.space();
        printer.push_span(replica_span);
    } else {
        printer.newline();

        match &view.query {
            Ok(parsed_select) => {
                // Format the parsed SELECT/SetSelect statement
                use crate::formatter::statements::select::format_select;
                format_select(printer, parsed_select.as_ref())?;
            }
            Err(query_span) => {
                // Query couldn't be parsed, extract span as-is
                if query_span.start != 0 || query_span.end != 0 {
                    printer.emit_comments_before(query_span.start);
                    printer.push_span(*query_span);
                }
            }
        }
    }

    // Redshift late-binding view marker, emitted after the query body.
    if let Some(binding_span) = view.with_no_schema_binding_span {
        printer.newline();
        printer.push_span(binding_span);
    }

    // PostgreSQL materialized view `WITH [NO] DATA`, emitted after the query body.
    if let Some(data_span) = view.with_data_clause_span {
        printer.newline();
        printer.push_span(data_span);
    }

    // MySQL / PostgreSQL `WITH [CASCADED|LOCAL] CHECK OPTION`, after the query body.
    if let Some(check_span) = view.with_check_option_span {
        printer.newline();
        printer.push_span(check_span);
    }

    // Emit semicolon if present (scripting/Jinja context)
    if let Some(semi_id) = view.semicolon_token {
        printer.push_token_id(semi_id);
    }

    Ok(())
}
