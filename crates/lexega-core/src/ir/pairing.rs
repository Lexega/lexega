// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Which body column a column listed by a reference is.

use std::collections::BTreeMap;

use super::column::ColumnId;
use super::plan::{CteBinding, CteBody, DemandedColumn, ProjectItem, RelPlan};
use super::scalar::{ScalarExpr, ScopeId};
use super::schema::{ColumnPositions, Position};
use super::visitor::{walk_rel_plan, RelPlanVisitor};
use crate::ast::NodeId;

/// The columns a `CteRef` lists, each with the slot of its binding it
/// takes: the explicit columns by position, then the demanded ones by
/// the slot recorded for them. Empty for any other node.
pub fn cte_slots(reference: &RelPlan) -> impl Iterator<Item = (usize, ColumnId)> + '_ {
    let (columns, demanded): (&[ColumnId], &[DemandedColumn]) = match reference {
        RelPlan::CteRef {
            columns, demanded, ..
        } => (columns, demanded),
        RelPlan::Scan { .. }
        | RelPlan::Values { .. }
        | RelPlan::ModelRef { .. }
        | RelPlan::Project { .. }
        | RelPlan::Filter { .. }
        | RelPlan::Aggregate { .. }
        | RelPlan::Window { .. }
        | RelPlan::Join { .. }
        | RelPlan::SetOp { .. }
        | RelPlan::Sort { .. }
        | RelPlan::Limit { .. }
        | RelPlan::Insert { .. }
        | RelPlan::Update { .. }
        | RelPlan::Delete { .. }
        | RelPlan::Merge { .. }
        | RelPlan::MultiInsert { .. }
        | RelPlan::Explain { .. }
        | RelPlan::CreateAsQuery { .. }
        | RelPlan::CreateTableForm { .. }
        | RelPlan::WithScope { .. }
        | RelPlan::DerivedTable { .. }
        | RelPlan::TableFunction { .. }
        | RelPlan::Unnest { .. }
        | RelPlan::Pivot { .. }
        | RelPlan::Unpivot { .. }
        | RelPlan::MatchRecognize { .. }
        | RelPlan::ConnectBy { .. }
        | RelPlan::TableSample { .. }
        | RelPlan::InvalidInput { .. }
        | RelPlan::ParseRecovery { .. }
        | RelPlan::Opaque { .. } => (&[], &[]),
    };
    columns
        .iter()
        .enumerate()
        .map(|(slot, column)| (slot, *column))
        .chain(demanded.iter().map(|d| (d.slot as usize, d.column)))
}

/// The columns a `DerivedTable` lists that the plan pairs with a body
/// column, each with that column. Empty for any other node.
pub(crate) fn derived_table_pairs(
    reference: &RelPlan,
) -> impl Iterator<Item = (ColumnId, ColumnId)> + '_ {
    let (columns, body_columns): (&[ColumnId], &[Option<ColumnId>]) = match reference {
        RelPlan::DerivedTable {
            columns,
            body_columns,
            ..
        } => (columns, body_columns),
        RelPlan::Scan { .. }
        | RelPlan::Values { .. }
        | RelPlan::CteRef { .. }
        | RelPlan::ModelRef { .. }
        | RelPlan::Project { .. }
        | RelPlan::Filter { .. }
        | RelPlan::Aggregate { .. }
        | RelPlan::Window { .. }
        | RelPlan::Join { .. }
        | RelPlan::SetOp { .. }
        | RelPlan::Sort { .. }
        | RelPlan::Limit { .. }
        | RelPlan::Insert { .. }
        | RelPlan::Update { .. }
        | RelPlan::Delete { .. }
        | RelPlan::Merge { .. }
        | RelPlan::MultiInsert { .. }
        | RelPlan::Explain { .. }
        | RelPlan::CreateAsQuery { .. }
        | RelPlan::CreateTableForm { .. }
        | RelPlan::WithScope { .. }
        | RelPlan::TableFunction { .. }
        | RelPlan::Unnest { .. }
        | RelPlan::Pivot { .. }
        | RelPlan::Unpivot { .. }
        | RelPlan::MatchRecognize { .. }
        | RelPlan::ConnectBy { .. }
        | RelPlan::TableSample { .. }
        | RelPlan::InvalidInput { .. }
        | RelPlan::ParseRecovery { .. }
        | RelPlan::Opaque { .. } => (&[], &[]),
    };
    columns
        .iter()
        .zip(body_columns)
        .filter_map(|(column, body)| body.map(|body| (*column, body)))
}

/// The body column a column listed by `reference` is, if the plan knows.
/// Reads `reference` for one lookup; a reader of many columns of one plan
/// holds a `SlotIndex` instead.
pub fn body_column(
    reference: &RelPlan,
    column: ColumnId,
    bindings_in_scope: &[&CteBinding],
) -> Option<ColumnId> {
    let (_, pairing) = pairings(reference).find(|(listed, _)| *listed == column)?;
    pairing.body_column(|scope| bindings_in_scope.iter().copied().find(|b| b.scope == scope))
}

/// Where a column a reference lists is paired.
#[derive(Debug, Clone, Copy)]
enum Pairing {
    /// Listed by a `CteRef` of the binding of `scope`, at `slot`.
    Slot { scope: ScopeId, slot: usize },
    /// Listed by a `DerivedTable`: the body column the plan pairs it with,
    /// if any.
    Body(Option<ColumnId>),
}

impl Pairing {
    /// The body column the pairing leads to, a slot's in the binding
    /// `binding` gives for its scope.
    fn body_column<'b>(
        self,
        binding: impl FnOnce(ScopeId) -> Option<&'b CteBinding>,
    ) -> Option<ColumnId> {
        match self {
            Pairing::Slot { scope, slot } => {
                binding(scope)?.slot_columns.get(slot).copied().flatten()
            }
            Pairing::Body(body) => body,
        }
    }
}

/// Each column `reference` lists with its pairing, a column's first
/// pairing first: a `CteRef`'s at each slot ([`cte_slots`]), a
/// `DerivedTable`'s with the body column the plan pairs it with
/// ([`derived_table_pairs`]), then with none. Empty for any other node.
fn pairings(reference: &RelPlan) -> impl Iterator<Item = (ColumnId, Pairing)> + '_ {
    let (scope, derived): (Option<ScopeId>, &[ColumnId]) = match reference {
        RelPlan::CteRef { scope, .. } => (Some(*scope), &[]),
        RelPlan::DerivedTable { columns, .. } => (None, columns),
        RelPlan::Scan { .. }
        | RelPlan::Values { .. }
        | RelPlan::ModelRef { .. }
        | RelPlan::Project { .. }
        | RelPlan::Filter { .. }
        | RelPlan::Aggregate { .. }
        | RelPlan::Window { .. }
        | RelPlan::Join { .. }
        | RelPlan::SetOp { .. }
        | RelPlan::Sort { .. }
        | RelPlan::Limit { .. }
        | RelPlan::Insert { .. }
        | RelPlan::Update { .. }
        | RelPlan::Delete { .. }
        | RelPlan::Merge { .. }
        | RelPlan::MultiInsert { .. }
        | RelPlan::Explain { .. }
        | RelPlan::CreateAsQuery { .. }
        | RelPlan::CreateTableForm { .. }
        | RelPlan::WithScope { .. }
        | RelPlan::TableFunction { .. }
        | RelPlan::Unnest { .. }
        | RelPlan::Pivot { .. }
        | RelPlan::Unpivot { .. }
        | RelPlan::MatchRecognize { .. }
        | RelPlan::ConnectBy { .. }
        | RelPlan::TableSample { .. }
        | RelPlan::InvalidInput { .. }
        | RelPlan::ParseRecovery { .. }
        | RelPlan::Opaque { .. } => (None, &[]),
    };
    let slots = scope.into_iter().flat_map(move |scope| {
        cte_slots(reference).map(move |(slot, column)| (column, Pairing::Slot { scope, slot }))
    });
    let paired =
        derived_table_pairs(reference).map(|(column, body)| (column, Pairing::Body(Some(body))));
    let unpaired = derived.iter().map(|column| (*column, Pairing::Body(None)));
    slots.chain(paired).chain(unpaired)
}

/// Where each column a `CteRef` or a `DerivedTable` of a plan lists is
/// paired, and the slot of each binding each column is paired with: found
/// in one walk of the plan, nested plans included, and read without
/// searching a reference's columns or a binding's slots.
#[derive(Debug, Default)]
pub(crate) struct SlotIndex {
    /// Each column a reference lists, as the first reference in the walk
    /// listing it pairs it first, with that reference's node id.
    listed: BTreeMap<ColumnId, (NodeId, Pairing)>,
    /// Each column a binding pairs with a slot, at its first such slot, by
    /// the binding's scope.
    binding_slots: BTreeMap<(ScopeId, ColumnId), usize>,
}

impl SlotIndex {
    /// One walk over `root`, nested plans included.
    #[cfg(test)]
    pub(crate) fn of(root: &RelPlan) -> Self {
        let mut index = IndexWalk(Self::default());
        index.visit_rel_plan(root);
        index.0
    }

    /// The slot of its binding at which `reference`, a `CteRef`, first
    /// lists `column`; `None` where it lists no such column.
    #[cfg(test)]
    pub(crate) fn slot(&self, reference: &RelPlan, column: ColumnId) -> Option<usize> {
        match self.listing(reference, column)? {
            Pairing::Slot { slot, .. } => Some(slot),
            Pairing::Body(_) => None,
        }
    }

    /// As [`body_column`]: the body column a column listed by `reference`
    /// is, if the plan knows, a slot's in the binding of
    /// `bindings_in_scope` with the reference's scope.
    #[cfg(test)]
    pub(crate) fn body_column(
        &self,
        reference: &RelPlan,
        column: ColumnId,
        bindings_in_scope: &[&CteBinding],
    ) -> Option<ColumnId> {
        self.listing(reference, column)?
            .body_column(|scope| bindings_in_scope.iter().copied().find(|b| b.scope == scope))
    }

    /// The first slot of the binding of `scope` that is paired with
    /// `column`.
    #[cfg(test)]
    pub(crate) fn binding_slot(&self, scope: ScopeId, column: ColumnId) -> Option<usize> {
        self.binding_slots.get(&(scope, column)).copied()
    }

    /// How `reference` pairs `column`, where it lists it.
    #[cfg(test)]
    fn listing(&self, reference: &RelPlan, column: ColumnId) -> Option<Pairing> {
        let (node, pairing) = self.listed.get(&column)?;
        (*node == reference.node_id()).then_some(*pairing)
    }

    /// How the first reference listing `column` pairs it.
    fn pairing(&self, column: ColumnId) -> Option<Pairing> {
        self.listed.get(&column).map(|(_, pairing)| *pairing)
    }

    /// Records the columns `plan`, a reference, lists and the slots of the
    /// bindings `plan`, a `WITH`, binds.
    fn record(&mut self, plan: &RelPlan) {
        let node = plan.node_id();
        for (column, pairing) in pairings(plan) {
            self.listed.entry(column).or_insert((node, pairing));
        }
        if let RelPlan::WithScope { ctes, .. } = plan {
            for binding in ctes {
                for (slot, column) in binding.slot_columns.iter().enumerate() {
                    if let Some(column) = column {
                        self.binding_slots
                            .entry((binding.scope, *column))
                            .or_insert(slot);
                    }
                }
            }
        }
    }
}

/// Builds a [`SlotIndex`] in one walk.
#[cfg(test)]
struct IndexWalk(SlotIndex);

#[cfg(test)]
impl<'p> RelPlanVisitor<'p> for IndexWalk {
    fn visit_rel_plan(&mut self, plan: &'p RelPlan) {
        self.0.record(plan);
        walk_rel_plan(self, plan);
    }
}

/// The step's column for each slot of a recursive binding, `None` where
/// the plan knows none; empty for a binding that does not recur.
#[cfg(test)]
pub(crate) fn step_columns(binding: &CteBinding) -> Vec<Option<ColumnId>> {
    step_positions(binding)
        .into_iter()
        .map(Position::column)
        .collect()
}

/// What the step of a recursive binding says of each slot: for a slot
/// that is a position of the body, the step's column there, a column the
/// step does not know, or none where the step lists every column and has
/// none there; none for a slot whose column the anchor does not place.
/// Empty for a binding that does not recur.
pub fn step_positions(binding: &CteBinding) -> Vec<Position> {
    match &binding.body {
        CteBody::Recursive { anchor, step, .. } => recursive_step_positions(
            binding.declared_columns.as_ref().map(Vec::len),
            anchor,
            step,
            &binding.slot_columns,
        ),
        CteBody::NonRecursive(_) => Vec::new(),
    }
}

/// As `step_columns`, for a binding whose slots are paired with
/// `slot_columns` over `anchor` and `step` with `declared` names. A slot
/// that is a position of the body takes the step's column there: each
/// declared name, with no declared list each column the anchor places,
/// and a later slot paired with a column the anchor places. A slot
/// paired with a column the anchor lists without placing, or with none,
/// has no position.
pub(crate) fn recursive_step_columns(
    declared: Option<usize>,
    anchor: &RelPlan,
    step: &RelPlan,
    slot_columns: &[Option<ColumnId>],
) -> Vec<Option<ColumnId>> {
    recursive_step_positions(declared, anchor, step, slot_columns)
        .into_iter()
        .map(Position::column)
        .collect()
}

/// As [`step_positions`], for a binding whose slots are paired with
/// `slot_columns` over `anchor` and `step` with `declared` names.
fn recursive_step_positions(
    declared: Option<usize>,
    anchor: &RelPlan,
    step: &RelPlan,
    slot_columns: &[Option<ColumnId>],
) -> Vec<Position> {
    let anchor = anchor.positional_columns();
    let placed = recursive_placed_slots(declared, &anchor);
    let step = step.positional_columns();
    slot_columns
        .iter()
        .enumerate()
        .map(|(slot, column)| {
            let position = match slot < placed {
                true => Some(slot),
                false => {
                    column.and_then(|column| anchor.known.iter().position(|known| *known == column))
                }
            };
            position.map_or(Position::Absent, |position| step.at(position))
        })
        .collect()
}

/// How many leading slots of a recursive binding are positions of its
/// body: each of its `declared` names, or with no declared list each
/// column its anchor places.
pub(crate) fn recursive_placed_slots(declared: Option<usize>, anchor: &ColumnPositions) -> usize {
    declared.unwrap_or(anchor.known.len())
}

/// How many leading slots of `binding` are the columns at the first
/// positions of its rows: its declared names and the columns its body
/// places.
pub(crate) fn placed_slots(binding: &CteBinding) -> usize {
    let named = binding.declared_columns.as_ref().map(Vec::len);
    match &binding.body {
        CteBody::NonRecursive(body) => named
            .unwrap_or(0)
            .max(body.positional_columns().known.len()),
        CteBody::Recursive { anchor, .. } => {
            recursive_placed_slots(named, &anchor.positional_columns())
        }
    }
}

/// What each slot of `binding` is in its body: the column it is paired
/// with; a column the plan does not know, where the slot is a position
/// past the columns an open body places; or none, where the body lists
/// every column and has none there, or lists no column of a demanded
/// name.
pub fn slot_positions(binding: &CteBinding) -> Vec<Position> {
    let body = match &binding.body {
        CteBody::NonRecursive(body) => body.positional_columns(),
        CteBody::Recursive { anchor, .. } => anchor.positional_columns(),
    };
    let placed = placed_slots(binding);
    binding
        .slot_columns
        .iter()
        .enumerate()
        .map(|(slot, column)| match column {
            Some(column) => Position::Column(*column),
            None if slot < placed => match body.at(slot) {
                Position::Unknown => Position::Unknown,
                Position::Column(_) | Position::Absent => Position::Absent,
            },
            None => Position::Absent,
        })
        .collect()
}

/// Follows `body_column` and bare-column projection items down to a
/// table-origin column of a source. Builds the plan's steps for one
/// lookup; a reader resolving many columns of one plan holds a
/// `PairingSteps` instead.
pub fn source_column(root: &RelPlan, column: ColumnId) -> Option<ColumnId> {
    PairingSteps::of(root).source_column(column)
}

/// The pairing steps of a plan, built once: where each column a source or
/// a bare-column projection item lists leads one step down, the plan's
/// [`SlotIndex`] for the columns a reference lists, and every binding of
/// the plan by its scope.
pub(crate) struct PairingSteps<'p> {
    steps: BTreeMap<ColumnId, Step>,
    slots: SlotIndex,
    bindings: BTreeMap<ScopeId, &'p CteBinding>,
}

impl<'p> PairingSteps<'p> {
    /// One walk over `root`, nested plans included.
    pub(crate) fn of(root: &'p RelPlan) -> Self {
        let mut steps = Self {
            steps: BTreeMap::new(),
            slots: SlotIndex::default(),
            bindings: BTreeMap::new(),
        };
        steps.visit_rel_plan(root);
        steps
    }

    /// Follows the steps from `column` down to a table-origin column of
    /// a source; `None` where a step is missing or a pairing is none.
    pub(crate) fn source_column(&self, column: ColumnId) -> Option<ColumnId> {
        let mut current = column;
        // Each step moves to a column another node lists or reads; a chain
        // longer than the steps recorded has a cycle.
        for _ in 0..=self.steps.len() + self.slots.listed.len() {
            match self.steps.get(&current) {
                Some(Step::Table) => return Some(current),
                Some(Step::Copy(read)) => current = *read,
                None => current = self.body_column(current)?,
            }
        }
        None
    }

    /// The body column `column`, a column a `CteRef` or a `DerivedTable`
    /// of the plan lists, is paired with; `None` where it is listed by no
    /// reference or its pairing is none.
    pub(crate) fn body_column(&self, column: ColumnId) -> Option<ColumnId> {
        self.slots
            .pairing(column)?
            .body_column(|scope| self.bindings.get(&scope).copied())
    }

    /// Every column a `CteRef` or a `DerivedTable` of the plan lists.
    pub(crate) fn reference_columns(&self) -> impl Iterator<Item = ColumnId> + '_ {
        self.slots.listed.keys().copied()
    }

    fn record(&mut self, column: ColumnId, step: Step) {
        self.steps.entry(column).or_insert(step);
    }
}

/// Where a column a source or a projection item lists leads one step down.
enum Step {
    /// Listed by a table source.
    Table,
    /// A projection item that is a bare column.
    Copy(ColumnId),
}

impl<'p> RelPlanVisitor<'p> for PairingSteps<'p> {
    fn visit_rel_plan(&mut self, plan: &'p RelPlan) {
        self.slots.record(plan);
        match plan {
            RelPlan::Scan { columns, .. } | RelPlan::ModelRef { columns, .. } => {
                for column in columns {
                    self.record(*column, Step::Table);
                }
            }
            RelPlan::Project { items, .. } => {
                for item in items {
                    match item {
                        ProjectItem::Expr(expr) => {
                            if let ScalarExpr::Column { column, .. } = &expr.expr {
                                self.record(expr.output, Step::Copy(*column));
                            }
                        }
                        ProjectItem::Star(_) => {}
                    }
                }
            }
            RelPlan::WithScope { ctes, .. } => {
                for binding in ctes {
                    self.bindings.entry(binding.scope).or_insert(binding);
                }
            }
            RelPlan::Values { .. }
            | RelPlan::CteRef { .. }
            | RelPlan::DerivedTable { .. }
            | RelPlan::Filter { .. }
            | RelPlan::Aggregate { .. }
            | RelPlan::Window { .. }
            | RelPlan::Join { .. }
            | RelPlan::SetOp { .. }
            | RelPlan::Sort { .. }
            | RelPlan::Limit { .. }
            | RelPlan::Insert { .. }
            | RelPlan::Update { .. }
            | RelPlan::Delete { .. }
            | RelPlan::Merge { .. }
            | RelPlan::MultiInsert { .. }
            | RelPlan::Explain { .. }
            | RelPlan::CreateAsQuery { .. }
            | RelPlan::CreateTableForm { .. }
            | RelPlan::TableFunction { .. }
            | RelPlan::Unnest { .. }
            | RelPlan::Pivot { .. }
            | RelPlan::Unpivot { .. }
            | RelPlan::MatchRecognize { .. }
            | RelPlan::ConnectBy { .. }
            | RelPlan::TableSample { .. }
            | RelPlan::InvalidInput { .. }
            | RelPlan::ParseRecovery { .. }
            | RelPlan::Opaque { .. } => {}
        }
        walk_rel_plan(self, plan);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::plan::CteBody;
    use crate::ir::{
        lower_query_full_with_bindings, CatalogDialect, FunctionCatalog, SessionContext, StrictMode,
    };
    use crate::lexer::tokenize;
    use crate::parser::parse_script;

    fn lower(src: &str) -> RelPlan {
        let tokens = tokenize(src);
        let script = parse_script(src, &tokens.tokens).expect("parse");
        assert_eq!(script.stmts.len(), 1, "expected single statement");
        let catalog = FunctionCatalog::for_dialect(CatalogDialect::Default);
        let session = SessionContext::default();
        let (plan, _catalog_ctx, _bindings, _facts) = lower_query_full_with_bindings(
            &script.stmts[0],
            src,
            StrictMode::Permissive,
            &catalog,
            &session,
            None,
        )
        .expect("lower");
        plan
    }

    const EXPLICIT_SLOT: &str = "WITH c AS (SELECT id AS x FROM users) SELECT x FROM c";

    #[test]
    fn an_explicit_slot_is_paired_by_position() {
        let _folding = crate::ir::normalize::default_folding();
        let plan = lower(EXPLICIT_SLOT);
        let RelPlan::WithScope { ctes, body, .. } = &plan else {
            panic!("expected a WITH scope: {plan:#?}");
        };
        let CteBody::NonRecursive(cte_body) = &ctes[0].body else {
            panic!("expected a non-recursive body: {plan:#?}");
        };
        let RelPlan::Project {
            input: reference, ..
        } = body.as_ref()
        else {
            panic!("expected a projection over the reference: {plan:#?}");
        };
        let RelPlan::CteRef { columns, .. } = reference.as_ref() else {
            panic!("expected a CTE reference: {plan:#?}");
        };
        let body_output = cte_body.output_schema();
        assert_eq!(body_output.len(), 1, "{plan:#?}");
        assert_eq!(
            body_column(reference, columns[0], &[&ctes[0]]),
            Some(body_output[0]),
            "{plan:#?}"
        );
    }

    #[test]
    fn a_derived_table_column_is_paired_by_position() {
        let _folding = crate::ir::normalize::default_folding();
        let plan = lower("SELECT x FROM (SELECT id AS x FROM users) d");
        let RelPlan::Project { input: derived, .. } = &plan else {
            panic!("expected a projection: {plan:#?}");
        };
        let RelPlan::DerivedTable { input, columns, .. } = derived.as_ref() else {
            panic!("expected a derived table: {plan:#?}");
        };
        let inner_output = input.output_schema();
        assert_eq!(inner_output.len(), 1, "{plan:#?}");
        assert_eq!(
            body_column(derived, columns[0], &[]),
            Some(inner_output[0]),
            "{plan:#?}"
        );
    }

    #[test]
    fn the_slot_index_answers_as_each_reference_pairs_its_columns() {
        let _folding = crate::ir::normalize::default_folding();
        let plan = lower(
            "WITH c AS (SELECT id AS x, id AS y FROM users) \
             SELECT a.x, b.y, d.z FROM c a JOIN c b ON a.x = b.x \
             JOIN (SELECT id AS z FROM orders) d ON d.z = a.y",
        );
        struct References<'p> {
            nodes: Vec<&'p RelPlan>,
            bindings: Vec<&'p CteBinding>,
        }
        impl<'p> RelPlanVisitor<'p> for References<'p> {
            fn visit_rel_plan(&mut self, plan: &'p RelPlan) {
                if matches!(plan, RelPlan::CteRef { .. } | RelPlan::DerivedTable { .. }) {
                    self.nodes.push(plan);
                }
                if let RelPlan::WithScope { ctes, .. } = plan {
                    self.bindings.extend(ctes);
                }
                walk_rel_plan(self, plan);
            }
        }
        let mut found = References {
            nodes: Vec::new(),
            bindings: Vec::new(),
        };
        found.visit_rel_plan(&plan);
        assert_eq!(found.nodes.len(), 3, "{plan:#?}");
        let index = SlotIndex::of(&plan);
        let listed: Vec<ColumnId> = found
            .nodes
            .iter()
            .flat_map(|node| pairings(node).map(|(column, _)| column))
            .collect();
        for node in &found.nodes {
            for column in &listed {
                let answer = index.body_column(node, *column, &found.bindings);
                assert_eq!(
                    answer,
                    body_column(node, *column, &found.bindings),
                    "{column:?} of {node:#?}"
                );
                let slot = cte_slots(node).find(|(_, c)| c == column).map(|(s, _)| s);
                assert_eq!(index.slot(node, *column), slot, "{column:?} of {node:#?}");
                // A reference pairs its own columns, none of another's.
                let own = pairings(node).any(|(c, _)| c == *column);
                assert_eq!(answer.is_some(), own, "{column:?} of {node:#?}");
            }
        }
        let binding = found.bindings[0];
        for (slot, column) in binding.slot_columns.iter().enumerate() {
            let column = column.expect("each slot of the binding is paired");
            assert_eq!(index.binding_slot(binding.scope, column), Some(slot));
        }
    }

    #[test]
    fn source_column_walks_to_the_scan() {
        let _folding = crate::ir::normalize::default_folding();
        let plan = lower(EXPLICIT_SLOT);
        let RelPlan::WithScope { ctes, .. } = &plan else {
            panic!("expected a WITH scope: {plan:#?}");
        };
        let CteBody::NonRecursive(cte_body) = &ctes[0].body else {
            panic!("expected a non-recursive body: {plan:#?}");
        };
        let RelPlan::Project { input: scan, .. } = cte_body.as_ref() else {
            panic!("expected a projection in the body: {plan:#?}");
        };
        let RelPlan::Scan { columns, .. } = scan.as_ref() else {
            panic!("expected the users scan: {plan:#?}");
        };
        assert_eq!(columns.len(), 1, "{plan:#?}");
        let root_output = plan.output_schema();
        assert_eq!(root_output.len(), 1, "{plan:#?}");
        assert_eq!(
            source_column(&plan, root_output[0]),
            Some(columns[0]),
            "{plan:#?}"
        );
    }
}
