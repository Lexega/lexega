// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Column identity of a lowered plan: whether each column of each source
//! has one id, and whether sources and nested plans are distinct.

use std::collections::{BTreeMap, BTreeSet};

use super::column::{BindingTable, ColumnBinding, ColumnId, ColumnOrigin};
use super::plan::{CteBinding, ProjectItem, RelPlan, ReturningItem, StarQualifier};
use super::scalar::{ScalarExpr, ScopeId};
use super::visitor::{walk_rel_plan, walk_scalar_expr, RelPlanVisitor};
use crate::ast::NodeId;
use crate::context::node_metadata::IdentKey;
use crate::ir::normalize::NameKind;

/// One way a plan can break column identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum IdentityCheck {
    /// Two sources or DML targets share a node id, or one carries the id
    /// of a DML node, a `Project`, an `Aggregate`, a `SetOp` or a
    /// `WithScope`. A DML node's `target_node` counts as a source id; the
    /// DML node's own id does not. One violation per offending source or
    /// target.
    SourceIds,
    /// Two nested plans have roots with one node id. One violation per
    /// nested plan after the first with that root id.
    NoCopies,
    /// Two table-origin ids have one (table node, normalized name). One
    /// violation per id after the first for that pair.
    OneIdPerColumn,
    /// A table-origin id names a source of the plan that does not list it.
    /// One violation per id; an id is listed if any source sharing its
    /// table node lists it. A DML target is a source that lists its
    /// `target_read_columns`.
    Listed,
    /// An expression reads a table-origin id whose source is inside a CTE
    /// body, a derived table's input or a set-operation branch that does
    /// not contain the reading node. One violation per distinct (reading
    /// node, column); a read is contained if any source sharing the id's
    /// table node encloses the reader. A DML target is a source where its
    /// DML node is. An id whose table node is no source is left to
    /// `Attributed`.
    Contained,
    /// A table-origin id names a node that is neither a source of the
    /// plan nor a DML target. One violation per id. Lowering gives a
    /// column it can choose no source for an unattributed origin, so a
    /// plan it built has none. Not reported where the root is
    /// `InvalidInput`, `ParseRecovery` or `Opaque`: lowering built no
    /// plan there, and the sources its ids name (the row a policy
    /// reads, the scans of a policy's body or of the lowering that
    /// stopped) are not in it.
    Attributed,
    /// A join's `USING` entry whose `left` is not readable in the left
    /// input or whose `right` is not readable in the right. One violation
    /// per entry. A column is readable in an input when the input's
    /// output schema holds it: a `USING` join lists its merged columns.
    UsingDefined,
    /// A column a `CteRef` or a `DerivedTable` lists has neither a
    /// pairing nor an explicit `None`: its slot is past the binding's
    /// `slot_columns`, its position past the derived table's
    /// `body_columns`, or its `CteRef` names a scope no `WithScope`
    /// of the plan binds. One violation per column.
    Paired,
    /// A star's `enumerated` names a node that is no source of the star's
    /// block: none of the sources its `Project`'s input reaches without
    /// entering a source or a nested plan. The plan does not record which
    /// items a star produced, so whether each reads a column of an
    /// enumerated source is not checked. One violation per entry. Or a
    /// star says it is complete and left a source out: a source of its
    /// block for an unqualified star, the one it names for a qualified
    /// one; `expr.*` is never complete. One violation per star. Or a
    /// star's `itemized` names a column its `Project`'s input does not
    /// yield. One violation per column. Or a star, of a projection or
    /// of a `RETURNING` list, does not have `unplaced` expression items
    /// directly before it. One violation per star.
    StarSources,
    /// An expression reads a computed-origin id whose producing node is
    /// a node of the plan, and no node of that id lists the column in
    /// its output schema. One violation per id. Not asked of the id of
    /// an `INSERT`, `UPDATE`, `DELETE`, `MERGE` or multi-table `INSERT`:
    /// such a statement yields no rows, and the columns it writes and
    /// returns are its own. Nor of a lambda's parameter read in that
    /// lambda's body: the lambda binds it and no node yields it.
    Produced,
}

/// One break of an [`IdentityCheck`], at a node and, where one is
/// involved, a column.
#[derive(Debug)]
pub struct IdentityViolation {
    pub check: IdentityCheck,
    pub node: NodeId,
    pub column: Option<ColumnId>,
}

/// Every break of column identity in `plan`, nested plans included.
/// A nested plan whose root id was already seen is reported as a copy
/// and not walked again.
pub fn check_plan_identity(plan: &RelPlan, bindings: &BindingTable) -> Vec<IdentityViolation> {
    let unattributed = match is_terminal(plan) {
        true => Unattributed::Unchecked,
        false => Unattributed::Reported,
    };
    check_identity(&[plan], bindings, unattributed)
}

/// Every break of column identity in `plans`, checked together: the
/// plans one statement holds in its expressions when lowering returns
/// no plan for the statement itself. `bindings` is that statement's.
///
/// `host` is the statement's node. The expressions that hold the plans
/// range over a row no plan has a source for (the arguments a policy
/// declares, the row of the table it is attached to), and the columns
/// of that row are table columns on the statement's node. A table
/// column on `host` is therefore attributed. One on any other node
/// that is no source of `plans` is reported as
/// [`IdentityCheck::Attributed`], and every other check is as
/// [`check_plan_identity`] makes it.
pub fn check_hosted_plan_identity(
    plans: &[&RelPlan],
    bindings: &BindingTable,
    host: NodeId,
) -> Vec<IdentityViolation> {
    check_identity(plans, bindings, Unattributed::ReportedOff(host))
}

/// What becomes of a table-origin id that names no source of the plans.
#[derive(Clone, Copy)]
enum Unattributed {
    Reported,
    /// Reported unless it is on this node.
    ReportedOff(NodeId),
    Unchecked,
}

fn check_identity(
    plans: &[&RelPlan],
    bindings: &BindingTable,
    unattributed: Unattributed,
) -> Vec<IdentityViolation> {
    let mut record = Record::default();
    for plan in plans {
        record.visit_rel_plan(plan);
    }
    let sources = record.sources_by_id();

    let mut violations = Vec::new();
    record.source_ids(&sources, &mut violations);
    violations.extend(record.copies.iter().map(|&node| IdentityViolation {
        check: IdentityCheck::NoCopies,
        node,
        column: None,
    }));
    table_columns(&sources, unattributed, bindings, &mut violations);
    record.contained(&sources, bindings, &mut violations);
    using_defined(&record.nodes, &mut violations);
    paired(&record.nodes, &record.bindings, &mut violations);
    star_sources(&record.nodes, &mut violations);
    record.produced(bindings, &mut violations);
    violations
}

/// What a node is to column identity.
enum Role<'p> {
    /// Owns table columns and lists `listed`.
    Source {
        listed: &'p [ColumnId],
    },
    /// A DML statement, or a `Project`, `Aggregate`, `SetOp` or `WithScope`
    /// block: an id no source may carry.
    StatementOrBlock,
    Other,
}

struct NodeRecord<'p> {
    plan: &'p RelPlan,
    id: NodeId,
    role: Role<'p>,
    /// Regions enclosing the node, outermost first.
    regions: Vec<usize>,
    /// Index into `Record::nodes` of the `Project` whose input holds the
    /// node, short of a source or a nested plan between them.
    block: Option<usize>,
}

/// A DML target: a source, placed where its DML node is, that lists the
/// columns the statement reads of it.
struct Target<'p> {
    id: NodeId,
    /// Index into `Record::nodes` of the DML node.
    dml: usize,
    listed: &'p [ColumnId],
}

/// The sources that carry one node id.
#[derive(Default)]
struct SourceGroup {
    /// Indices into `Record::nodes`: a source's own, a target's DML node's.
    nodes: Vec<usize>,
    /// Every column any of them lists.
    listed: BTreeSet<ColumnId>,
}

/// One walk's record of every node, every read and every nested plan.
#[derive(Default)]
struct Record<'p> {
    nodes: Vec<NodeRecord<'p>>,
    /// Indices into `nodes` of the plans being walked, innermost last.
    open: Vec<usize>,
    /// Open regions: CTE bodies, derived-table inputs and set-operation
    /// branches, each numbered once.
    regions: Vec<usize>,
    next_region: usize,
    /// (reading node, column) for every column an expression reads,
    /// but a parameter of a lambda that encloses the expression.
    reads: BTreeSet<(usize, ColumnId)>,
    /// The parameters of the lambdas being walked, innermost last.
    parameters: Vec<ColumnId>,
    /// The target of every DML node and every multi-table `INTO` target.
    targets: Vec<Target<'p>>,
    nested_roots: BTreeSet<NodeId>,
    copies: Vec<NodeId>,
    /// Every binding of every `WithScope`, by scope.
    bindings: BTreeMap<ScopeId, &'p CteBinding>,
    /// Set while a nested plan's root is entered.
    entering_nested: bool,
}

impl<'p> RelPlanVisitor<'p> for Record<'p> {
    fn visit_rel_plan(&mut self, plan: &'p RelPlan) {
        let region = self
            .open
            .last()
            .is_some_and(|&parent| opens_region(self.nodes[parent].plan, plan));
        if region {
            self.regions.push(self.next_region);
            self.next_region += 1;
        }
        let nested = std::mem::take(&mut self.entering_nested);
        let block = match self.open.last() {
            Some(&parent) if !nested => child_block(&self.nodes[parent], parent),
            Some(_) | None => None,
        };
        let index = self.nodes.len();
        self.nodes.push(NodeRecord {
            plan,
            id: plan.node_id(),
            role: role(plan),
            regions: self.regions.clone(),
            block,
        });
        push_targets(plan, index, &mut self.targets);
        if let RelPlan::WithScope { ctes, .. } = plan {
            self.bindings
                .extend(ctes.iter().map(|binding| (binding.scope, binding)));
        }
        self.open.push(index);
        walk_rel_plan(self, plan);
        self.open.pop();
        if region {
            self.regions.pop();
        }
    }

    fn visit_scalar_expr(&mut self, expr: &'p ScalarExpr) {
        if let ScalarExpr::Column { column, .. }
        | ScalarExpr::OuterRef { column, .. }
        | ScalarExpr::PatternVarRef { column, .. } = expr
        {
            // A lambda binds its parameters: no node yields one.
            let bound = self.parameters.contains(column);
            if let (false, Some(&reader)) = (bound, self.open.last()) {
                self.reads.insert((reader, *column));
            }
        }
        let outside = self.parameters.len();
        if let ScalarExpr::Lambda { params, .. } = expr {
            self.parameters.extend(params.iter().map(|param| param.id));
        }
        walk_scalar_expr(self, expr);
        self.parameters.truncate(outside);
    }

    fn visit_subquery(&mut self, plan: &'p RelPlan, _correlates_with: &'p [ColumnId]) {
        let root = plan.node_id();
        if self.nested_roots.insert(root) {
            self.entering_nested = true;
            self.visit_rel_plan(plan);
        } else {
            self.copies.push(root);
        }
    }
}

impl Record<'_> {
    /// Every source and every DML target, grouped by node id.
    fn sources_by_id(&self) -> BTreeMap<NodeId, SourceGroup> {
        let mut sources: BTreeMap<NodeId, SourceGroup> = BTreeMap::new();
        for (index, node) in self.nodes.iter().enumerate() {
            match node.role {
                Role::Source { listed } => {
                    let group = sources.entry(node.id).or_default();
                    group.nodes.push(index);
                    group.listed.extend(listed.iter().copied());
                }
                Role::StatementOrBlock | Role::Other => {}
            }
        }
        for target in &self.targets {
            let group = sources.entry(target.id).or_default();
            group.nodes.push(target.dml);
            group.listed.extend(target.listed.iter().copied());
        }
        sources
    }

    /// One violation per source or DML target whose id another source,
    /// target, statement or block also carries.
    fn source_ids(
        &self,
        sources: &BTreeMap<NodeId, SourceGroup>,
        violations: &mut Vec<IdentityViolation>,
    ) {
        let blocks: BTreeSet<NodeId> = self
            .nodes
            .iter()
            .filter(|node| match node.role {
                Role::StatementOrBlock => true,
                Role::Source { .. } | Role::Other => false,
            })
            .map(|node| node.id)
            .collect();
        for (&id, group) in sources {
            if group.nodes.len() > 1 || blocks.contains(&id) {
                violations.extend(group.nodes.iter().map(|_| IdentityViolation {
                    check: IdentityCheck::SourceIds,
                    node: id,
                    column: None,
                }));
            }
        }
    }

    /// One violation per (reading node, column) where no source the column
    /// names encloses the reader in every region that encloses the source.
    fn contained(
        &self,
        sources: &BTreeMap<NodeId, SourceGroup>,
        bindings: &BindingTable,
        violations: &mut Vec<IdentityViolation>,
    ) {
        for &(reader, column) in &self.reads {
            let Some((table_node, _)) = bindings.get(column).and_then(table_origin) else {
                continue;
            };
            let Some(group) = sources.get(&table_node) else {
                continue;
            };
            let reader_regions = &self.nodes[reader].regions;
            let in_scope = group
                .nodes
                .iter()
                .any(|&source| reader_regions.starts_with(&self.nodes[source].regions));
            if !in_scope {
                violations.push(IdentityViolation {
                    check: IdentityCheck::Contained,
                    node: self.nodes[reader].id,
                    column: Some(column),
                });
            }
        }
    }

    /// One violation per computed-origin id an expression reads that no
    /// node of its producing node's id lists, where that id is a node's
    /// and no DML statement's.
    fn produced(&self, bindings: &BindingTable, violations: &mut Vec<IdentityViolation>) {
        let mut by_id: BTreeMap<NodeId, Vec<&RelPlan>> = BTreeMap::new();
        for node in &self.nodes {
            by_id.entry(node.id).or_default().push(node.plan);
        }
        // What the nodes of an id list; `None` for a DML statement's id.
        let mut listed: BTreeMap<NodeId, Option<BTreeSet<ColumnId>>> = BTreeMap::new();
        let read: BTreeSet<ColumnId> = self.reads.iter().map(|&(_, column)| column).collect();
        for column in read {
            let Some(producer) = bindings.get(column).and_then(computed_at) else {
                continue;
            };
            let Some(nodes) = by_id.get(&producer) else {
                continue;
            };
            let listed = listed.entry(producer).or_insert_with(|| {
                let writes = nodes.iter().any(|node| {
                    matches!(
                        node,
                        RelPlan::Insert { .. }
                            | RelPlan::Update { .. }
                            | RelPlan::Delete { .. }
                            | RelPlan::Merge { .. }
                            | RelPlan::MultiInsert { .. }
                    )
                });
                (!writes).then(|| nodes.iter().flat_map(|node| node.output_schema()).collect())
            });
            if listed
                .as_ref()
                .is_some_and(|listed| !listed.contains(&column))
            {
                violations.push(IdentityViolation {
                    check: IdentityCheck::Produced,
                    node: producer,
                    column: Some(column),
                });
            }
        }
    }
}

/// Checks over every table-origin id the binding table holds: a second id
/// for one (table node, name), an id its sources do not list, an id that
/// names no source. The last is as `unattributed` says.
fn table_columns(
    sources: &BTreeMap<NodeId, SourceGroup>,
    unattributed: Unattributed,
    bindings: &BindingTable,
    violations: &mut Vec<IdentityViolation>,
) {
    let mut names: BTreeSet<(NodeId, IdentKey)> = BTreeSet::new();
    for (&id, binding) in bindings.iter() {
        let Some((table_node, column_name)) = table_origin(binding) else {
            continue;
        };
        let mut violation = |check| {
            violations.push(IdentityViolation {
                check,
                node: table_node,
                column: Some(id),
            })
        };
        if !names.insert((table_node, IdentKey::new_as(column_name, NameKind::Column))) {
            violation(IdentityCheck::OneIdPerColumn);
        }
        match sources.get(&table_node) {
            Some(group) if !group.listed.contains(&id) => violation(IdentityCheck::Listed),
            Some(_) => {}
            None => match unattributed {
                Unattributed::Reported => violation(IdentityCheck::Attributed),
                Unattributed::ReportedOff(host) if host == table_node => {}
                Unattributed::ReportedOff(_) => violation(IdentityCheck::Attributed),
                Unattributed::Unchecked => {}
            },
        }
    }
}

/// Whether `root` is a node lowering returns in place of a plan.
fn is_terminal(root: &RelPlan) -> bool {
    match root {
        RelPlan::InvalidInput { .. } | RelPlan::ParseRecovery { .. } | RelPlan::Opaque { .. } => {
            true
        }
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
        | RelPlan::DerivedTable { .. }
        | RelPlan::TableFunction { .. }
        | RelPlan::Unnest { .. }
        | RelPlan::Pivot { .. }
        | RelPlan::Unpivot { .. }
        | RelPlan::MatchRecognize { .. }
        | RelPlan::ConnectBy { .. }
        | RelPlan::TableSample { .. } => false,
    }
}

/// One violation per `USING` entry of a join whose side column is not
/// readable in that side.
fn using_defined(nodes: &[NodeRecord<'_>], violations: &mut Vec<IdentityViolation>) {
    for node in nodes {
        let RelPlan::Join {
            left, right, using, ..
        } = node.plan
        else {
            continue;
        };
        if using.is_empty() {
            continue;
        }
        let in_left = readable(left);
        let in_right = readable(right);
        for column in using {
            if !in_left.contains(&column.left) || !in_right.contains(&column.right) {
                violations.push(IdentityViolation {
                    check: IdentityCheck::UsingDefined,
                    node: node.id,
                    column: Some(column.merged),
                });
            }
        }
    }
}

/// One violation per column a `CteRef` or a `DerivedTable` lists that
/// the plan pairs with nothing, not even an explicit `None`.
fn paired(
    nodes: &[NodeRecord<'_>],
    bindings: &BTreeMap<ScopeId, &CteBinding>,
    violations: &mut Vec<IdentityViolation>,
) {
    for node in nodes {
        let unpaired: Vec<ColumnId> = match node.plan {
            RelPlan::CteRef {
                scope,
                columns,
                demanded,
                ..
            } => {
                let slot_columns = bindings
                    .get(scope)
                    .map_or(&[][..], |binding| binding.slot_columns.as_slice());
                let explicit = columns
                    .iter()
                    .enumerate()
                    .filter(|(slot, _)| slot_columns.get(*slot).is_none())
                    .map(|(_, column)| *column);
                let demanded = demanded
                    .iter()
                    .filter(|d| {
                        usize::try_from(d.slot)
                            .map_or(true, |slot| slot_columns.get(slot).is_none())
                    })
                    .map(|d| d.column);
                explicit.chain(demanded).collect()
            }
            RelPlan::DerivedTable {
                columns,
                body_columns,
                ..
            } => columns
                .iter()
                .enumerate()
                .filter(|(position, _)| body_columns.get(*position).is_none())
                .map(|(_, column)| *column)
                .collect(),
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
            | RelPlan::Opaque { .. } => Vec::new(),
        };
        violations.extend(unpaired.into_iter().map(|column| IdentityViolation {
            check: IdentityCheck::Paired,
            node: node.id,
            column: Some(column),
        }));
    }
}

/// One violation per entry of a star's `enumerated` that is no source of
/// the star's block, and one per star, of a projection or of a
/// `RETURNING` list, that does not have `unplaced` expression items
/// directly before it.
fn star_sources(nodes: &[NodeRecord<'_>], violations: &mut Vec<IdentityViolation>) {
    let in_block: BTreeSet<(usize, NodeId)> = nodes
        .iter()
        .filter_map(|node| match node.role {
            Role::Source { .. } => node.block.map(|block| (block, node.id)),
            Role::StatementOrBlock | Role::Other => None,
        })
        .collect();
    for (index, node) in nodes.iter().enumerate() {
        if let RelPlan::Insert {
            returning: Some(returning),
            ..
        }
        | RelPlan::Update {
            returning: Some(returning),
            ..
        }
        | RelPlan::Delete {
            returning: Some(returning),
            ..
        }
        | RelPlan::Merge {
            returning: Some(returning),
            ..
        } = node.plan
        {
            for (at, item) in returning.items.iter().enumerate() {
                let ReturningItem::Star(star) = item else {
                    continue;
                };
                let own = at
                    .checked_sub(star.unplaced)
                    .map_or(&[][..], |first| &returning.items[first..at]);
                let all_items = own.iter().all(|item| match item {
                    ReturningItem::Expr { .. } => true,
                    ReturningItem::Star(_) => false,
                });
                if own.len() != star.unplaced || !all_items {
                    violations.push(IdentityViolation {
                        check: IdentityCheck::StarSources,
                        node: node.id,
                        column: None,
                    });
                }
            }
        }
        let RelPlan::Project { items, input, .. } = node.plan else {
            continue;
        };
        for (at, item) in items.iter().enumerate() {
            let ProjectItem::Star(star) = item else {
                continue;
            };
            let own = at
                .checked_sub(star.unplaced)
                .map_or(&[][..], |first| &items[first..at]);
            let all_items = own.iter().all(|item| match item {
                ProjectItem::Expr(_) => true,
                ProjectItem::Star(_) => false,
            });
            if own.len() != star.unplaced || !all_items {
                violations.push(IdentityViolation {
                    check: IdentityCheck::StarSources,
                    node: node.id,
                    column: None,
                });
            }
            if !star.itemized.is_empty() {
                let below = input.output_schema();
                for column in &star.itemized {
                    if !below.contains(column) {
                        violations.push(IdentityViolation {
                            check: IdentityCheck::StarSources,
                            node: node.id,
                            column: Some(*column),
                        });
                    }
                }
            }
            for &source in &star.enumerated {
                if !in_block.contains(&(index, source)) {
                    violations.push(IdentityViolation {
                        check: IdentityCheck::StarSources,
                        node: node.id,
                        column: None,
                    });
                }
            }
            let left_out = match &star.qualifier {
                StarQualifier::Unqualified => in_block
                    .range((index, NodeId::new(0))..)
                    .take_while(|(block, _)| *block == index)
                    .any(|(_, source)| !star.enumerated.contains(source)),
                StarQualifier::Named(_) => star.enumerated.is_empty(),
                StarQualifier::FromExpr(_) => true,
            };
            if star.complete && left_out {
                violations.push(IdentityViolation {
                    check: IdentityCheck::StarSources,
                    node: node.id,
                    column: None,
                });
            }
        }
    }
}

/// The block a child of `parent`, at index `index`, is in: `parent` when
/// it is a `Project`, none when it is a source, else `parent`'s.
fn child_block(parent: &NodeRecord<'_>, index: usize) -> Option<usize> {
    if matches!(parent.plan, RelPlan::Project { .. }) {
        return Some(index);
    }
    match parent.role {
        Role::Source { .. } => None,
        Role::StatementOrBlock | Role::Other => parent.block,
    }
}

/// The columns readable in a join input: its output schema, which holds
/// the merged columns of the `USING` joins it is made of.
fn readable(input: &RelPlan) -> BTreeSet<ColumnId> {
    input.output_schema().into_iter().collect()
}

/// The node a computed-origin id is produced at.
fn computed_at(binding: &ColumnBinding) -> Option<NodeId> {
    match &binding.origin {
        ColumnOrigin::Computed { producing_node, .. }
        | ColumnOrigin::Merged { producing_node, .. } => Some(*producing_node),
        ColumnOrigin::Table { .. }
        | ColumnOrigin::SetOp { .. }
        | ColumnOrigin::OuterRef { .. }
        | ColumnOrigin::RecursiveRef { .. }
        | ColumnOrigin::Unattributed { .. } => None,
    }
}

fn table_origin(binding: &ColumnBinding) -> Option<(NodeId, &str)> {
    match &binding.origin {
        ColumnOrigin::Table {
            table_node,
            column_name,
            ..
        } => Some((*table_node, column_name.as_str())),
        ColumnOrigin::Computed { .. }
        | ColumnOrigin::Merged { .. }
        | ColumnOrigin::SetOp { .. }
        | ColumnOrigin::OuterRef { .. }
        | ColumnOrigin::RecursiveRef { .. }
        | ColumnOrigin::Unattributed { .. } => None,
    }
}

/// Whether `child`, entered from `parent`, is a region of its own: a CTE
/// body (each branch of a recursive one), a derived table's input or a
/// set-operation branch.
fn opens_region(parent: &RelPlan, child: &RelPlan) -> bool {
    match parent {
        RelPlan::DerivedTable { input, .. } => std::ptr::eq(input.as_ref(), child),
        RelPlan::SetOp { .. } => true,
        RelPlan::WithScope { body, .. } => !std::ptr::eq(body.as_ref(), child),
        RelPlan::Scan { .. }
        | RelPlan::Values { .. }
        | RelPlan::CteRef { .. }
        | RelPlan::ModelRef { .. }
        | RelPlan::Project { .. }
        | RelPlan::Filter { .. }
        | RelPlan::Aggregate { .. }
        | RelPlan::Window { .. }
        | RelPlan::Join { .. }
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
        | RelPlan::Opaque { .. } => false,
    }
}

fn role(plan: &RelPlan) -> Role<'_> {
    match plan {
        RelPlan::Scan { columns, .. }
        | RelPlan::Values { columns, .. }
        | RelPlan::CteRef { columns, .. }
        | RelPlan::ModelRef { columns, .. }
        | RelPlan::DerivedTable { columns, .. } => Role::Source { listed: columns },
        RelPlan::TableFunction { output_columns, .. } => Role::Source {
            listed: output_columns,
        },
        RelPlan::Insert { .. }
        | RelPlan::Update { .. }
        | RelPlan::Delete { .. }
        | RelPlan::Merge { .. }
        | RelPlan::MultiInsert { .. }
        | RelPlan::Project { .. }
        | RelPlan::Aggregate { .. }
        | RelPlan::SetOp { .. }
        | RelPlan::WithScope { .. } => Role::StatementOrBlock,
        RelPlan::Filter { .. }
        | RelPlan::Window { .. }
        | RelPlan::Join { .. }
        | RelPlan::Sort { .. }
        | RelPlan::Limit { .. }
        | RelPlan::Explain { .. }
        | RelPlan::CreateAsQuery { .. }
        | RelPlan::CreateTableForm { .. }
        | RelPlan::Unnest { .. }
        | RelPlan::Pivot { .. }
        | RelPlan::Unpivot { .. }
        | RelPlan::MatchRecognize { .. }
        | RelPlan::ConnectBy { .. }
        | RelPlan::TableSample { .. }
        | RelPlan::InvalidInput { .. }
        | RelPlan::ParseRecovery { .. }
        | RelPlan::Opaque { .. } => Role::Other,
    }
}

/// Push the target of the DML node `plan`, at index `dml`, and each of
/// its multi-table `INTO` targets.
fn push_targets<'p>(plan: &'p RelPlan, dml: usize, out: &mut Vec<Target<'p>>) {
    match plan {
        RelPlan::Insert {
            target_node,
            target_read_columns,
            ..
        }
        | RelPlan::Update {
            target_node,
            target_read_columns,
            ..
        }
        | RelPlan::Delete {
            target_node,
            target_read_columns,
            ..
        }
        | RelPlan::Merge {
            target_node,
            target_read_columns,
            ..
        } => out.push(Target {
            id: *target_node,
            dml,
            listed: target_read_columns,
        }),
        RelPlan::MultiInsert {
            unconditional_clauses,
            when_clauses,
            else_clauses,
            ..
        } => {
            let whens = when_clauses.iter().flat_map(|when| &when.targets);
            out.extend(
                unconditional_clauses
                    .iter()
                    .chain(whens)
                    .chain(else_clauses)
                    .map(|target| Target {
                        id: target.target_node,
                        dml,
                        listed: &target.target_read_columns,
                    }),
            );
        }
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
        | RelPlan::Opaque { .. } => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::plan::{GroupingSpec, ProjectItem};
    use crate::ir::{
        lower_query_full_with_bindings, CatalogDialect, FunctionCatalog, SessionContext, StrictMode,
    };
    use crate::lexer::tokenize;
    use crate::parser::parse_script;

    fn lower_with_bindings(src: &str) -> (RelPlan, BindingTable) {
        let tokens = tokenize(src);
        let script = parse_script(src, &tokens.tokens).expect("parse");
        assert_eq!(script.stmts.len(), 1, "expected single statement");
        let catalog = FunctionCatalog::for_dialect(CatalogDialect::Default);
        let session = SessionContext::default();
        let (plan, _catalog_ctx, bindings, _facts) = lower_query_full_with_bindings(
            &script.stmts[0],
            src,
            StrictMode::Permissive,
            &catalog,
            &session,
            None,
        )
        .expect("lower");
        (plan, bindings)
    }

    fn assert_breaks_plan(plan: &RelPlan, bindings: &BindingTable, check: IdentityCheck) {
        let violations = check_plan_identity(plan, bindings);
        assert!(
            violations.iter().any(|v| v.check == check),
            "no {check:?} violation in {violations:?}\n{plan:#?}"
        );
    }

    #[test]
    fn two_scans_with_one_id_are_reported() {
        let _folding = crate::ir::normalize::default_folding();
        let (mut plan, bindings) = lower_with_bindings(
            "UPDATE users SET name = a.amount FROM orders a, orders b \
             WHERE a.id = users.id AND b.user_id = users.id",
        );
        let RelPlan::Update {
            from: Some(from), ..
        } = &mut plan
        else {
            panic!("expected Update with FROM, got {plan:#?}");
        };
        let RelPlan::Join { left, right, .. } = from.as_mut() else {
            panic!("expected a Join, got {from:#?}");
        };
        let (RelPlan::Scan { node_id: a, .. }, RelPlan::Scan { node_id: b, .. }) =
            (left.as_mut(), right.as_mut())
        else {
            panic!("expected two Scans");
        };
        *b = *a;
        let violations = check_plan_identity(&plan, &bindings);
        let shared: Vec<_> = violations
            .iter()
            .filter(|v| v.check == IdentityCheck::SourceIds)
            .collect();
        assert_eq!(shared.len(), 2, "{violations:?}\n{plan:#?}");
    }

    #[test]
    fn a_target_sharing_a_sources_id_is_reported() {
        let _folding = crate::ir::normalize::default_folding();
        let (mut plan, bindings) =
            lower_with_bindings("DELETE FROM users USING orders o WHERE o.user_id = users.id");
        let RelPlan::Delete {
            using: Some(using),
            target_node,
            ..
        } = &mut plan
        else {
            panic!("expected Delete with USING, got {plan:#?}");
        };
        *target_node = using.node_id();
        assert_breaks_plan(&plan, &bindings, IdentityCheck::SourceIds);
    }

    #[test]
    fn a_target_lists_what_is_read_from_it() {
        let _folding = crate::ir::normalize::default_folding();
        let (mut plan, bindings) =
            lower_with_bindings("UPDATE users SET name = email WHERE users.id = 1");
        let violations = check_plan_identity(&plan, &bindings);
        assert!(violations.is_empty(), "{violations:?}\n{plan:#?}");
        let RelPlan::Update {
            target_read_columns,
            ..
        } = &mut plan
        else {
            panic!("expected Update, got {plan:#?}");
        };
        assert_eq!(target_read_columns.len(), 2, "{plan:#?}");
        target_read_columns.pop();
        let violations = check_plan_identity(&plan, &bindings);
        let checks: Vec<IdentityCheck> = violations.iter().map(|v| v.check).collect();
        assert_eq!(checks, vec![IdentityCheck::Listed], "{plan:#?}");
    }

    #[test]
    fn a_nested_plan_held_twice_is_reported() {
        let _folding = crate::ir::normalize::default_folding();
        let (mut plan, bindings) = lower_with_bindings(
            "SELECT (SELECT MAX(o.amount) FROM orders o WHERE o.user_id = u.id) AS m, \
             COUNT(*) AS n FROM users u GROUP BY 1",
        );
        let RelPlan::Project { input, items, .. } = &mut plan else {
            panic!("expected Project, got {plan:#?}");
        };
        let RelPlan::Aggregate {
            grouping: GroupingSpec::Standard(keys),
            ..
        } = input.as_ref()
        else {
            panic!("expected Aggregate with one key list, got {input:#?}");
        };
        let ProjectItem::Expr(item) = &mut items[0] else {
            panic!("expected an expression item, got {:#?}", items[0]);
        };
        item.expr = keys[0].expr.clone();
        assert_breaks_plan(&plan, &bindings, IdentityCheck::NoCopies);
    }

    #[test]
    fn a_second_id_of_one_table_column_is_reported() {
        let _folding = crate::ir::normalize::default_folding();
        let (mut plan, mut bindings) =
            lower_with_bindings("SELECT u.email FROM users u WHERE u.email IS NOT NULL");
        let RelPlan::Project { input, .. } = &mut plan else {
            panic!("expected Project, got {plan:#?}");
        };
        let RelPlan::Filter { predicate, .. } = input.as_mut() else {
            panic!("expected Filter under the Project, got {input:#?}");
        };
        let ScalarExpr::UnaryOp { arg, .. } = predicate else {
            panic!("expected IS NOT NULL, got {predicate:#?}");
        };
        let ScalarExpr::Column { column, .. } = arg.as_mut() else {
            panic!("expected a column under IS NOT NULL, got {arg:#?}");
        };
        let shared = bindings.get(*column).expect("binding").clone();
        let second = ColumnId::new(bindings.len() as u32);
        bindings.insert(ColumnBinding {
            id: second,
            ..shared
        });
        *column = second;
        assert_breaks_plan(&plan, &bindings, IdentityCheck::OneIdPerColumn);
    }

    #[test]
    fn a_table_column_its_source_does_not_list_is_reported() {
        let _folding = crate::ir::normalize::default_folding();
        let (mut plan, bindings) = lower_with_bindings("SELECT u.id FROM users u ORDER BY u.email");
        let RelPlan::Sort { input, .. } = &mut plan else {
            panic!("expected Sort, got {plan:#?}");
        };
        let RelPlan::Project { input, .. } = input.as_mut() else {
            panic!("expected Project under the Sort, got {input:#?}");
        };
        let RelPlan::Scan { columns, .. } = input.as_mut() else {
            panic!("expected Scan under the Project, got {input:#?}");
        };
        assert_eq!(columns.len(), 2, "{plan:#?}");
        columns.pop();
        assert_breaks_plan(&plan, &bindings, IdentityCheck::Listed);
    }

    /// The bindings and the root `Project` of a `WithScope` whose body is
    /// a projection over a `CteRef`, with the reference's slot pairing.
    fn star_cte_reference(
        plan: &mut RelPlan,
    ) -> (
        &mut Vec<CteBinding>,
        &mut Vec<ProjectItem>,
        Vec<Option<ColumnId>>,
    ) {
        let RelPlan::WithScope { ctes, body, .. } = plan else {
            panic!("expected WithScope, got {plan:#?}");
        };
        let RelPlan::Project { items, input, .. } = body.as_mut() else {
            panic!("expected a Project over a CteRef as the body");
        };
        let RelPlan::CteRef { demanded, .. } = input.as_ref() else {
            panic!("expected a CteRef under the Project, got {input:#?}");
        };
        assert_eq!(ctes.len(), 1, "expected one binding, got {ctes:#?}");
        let paired = demanded
            .iter()
            .map(|d| ctes[0].slot_columns.get(d.slot as usize).copied().flatten())
            .collect();
        (ctes, items, paired)
    }

    #[test]
    fn a_body_column_read_outside_its_body_is_reported() {
        let _folding = crate::ir::normalize::default_folding();
        let (mut plan, bindings) =
            lower_with_bindings("WITH c AS (SELECT * FROM users) SELECT x.name FROM c x");
        let (_, items, paired) = star_cte_reference(&mut plan);
        let [Some(scan_name)] = paired[..] else {
            panic!("expected one demanded column paired with a scan column: {plan:#?}");
        };
        let [ProjectItem::Expr(item)] = items.as_mut_slice() else {
            panic!("expected one expression item, got {items:#?}");
        };
        let ScalarExpr::Column { column, .. } = &mut item.expr else {
            panic!("expected a column read, got {:#?}", item.expr);
        };
        *column = scan_name;
        assert_breaks_plan(&plan, &bindings, IdentityCheck::Contained);
    }

    #[test]
    fn a_reference_column_without_a_pairing_is_reported() {
        let _folding = crate::ir::normalize::default_folding();
        let (mut plan, bindings) =
            lower_with_bindings("WITH c AS (SELECT * FROM users) SELECT x.name FROM c x");
        let (ctes, _, _) = star_cte_reference(&mut plan);
        ctes[0].slot_columns.clear();
        assert_breaks_plan(&plan, &bindings, IdentityCheck::Paired);
        let (mut plan, bindings) = lower_with_bindings("SELECT d.x FROM (SELECT id FROM users) d");
        let RelPlan::Project { input, .. } = &mut plan else {
            panic!("expected Project, got {plan:#?}");
        };
        let RelPlan::DerivedTable { body_columns, .. } = input.as_mut() else {
            panic!("expected a DerivedTable under the Project, got {input:#?}");
        };
        body_columns.clear();
        assert_breaks_plan(&plan, &bindings, IdentityCheck::Paired);
    }

    #[test]
    fn a_star_cte_reference_is_clean() {
        let _folding = crate::ir::normalize::default_folding();
        let (plan, bindings) = lower_with_bindings(
            "WITH c AS (SELECT * FROM users) \
             SELECT x.name, y.name AS yn FROM c x LEFT JOIN c y ON y.id = x.id",
        );
        let violations = check_plan_identity(&plan, &bindings);
        assert!(violations.is_empty(), "{violations:?}\n{plan:#?}");
    }

    #[test]
    fn a_slot_paired_with_a_returned_column_is_clean() {
        let _folding = crate::ir::normalize::default_folding();
        use crate::ir::plan::{CteBody, ReturningItem};
        let (mut plan, bindings) = lower_with_bindings(
            "WITH w AS (DELETE FROM users WHERE id = 1 RETURNING id, email) \
             SELECT email FROM w",
        );
        let RelPlan::WithScope { ctes, .. } = &mut plan else {
            panic!("expected WithScope, got {plan:#?}");
        };
        let CteBody::NonRecursive(body) = &ctes[0].body else {
            panic!("expected a non-recursive body, got {ctes:#?}");
        };
        let RelPlan::Delete {
            returning: Some(returning),
            ..
        } = body.as_ref()
        else {
            panic!("expected a DELETE with a RETURNING list, got {body:#?}");
        };
        let returned: Vec<Option<ColumnId>> = returning
            .items
            .iter()
            .map(|item| match item {
                ReturningItem::Expr { output, .. } => *output,
                ReturningItem::Star(_) => None,
            })
            .collect();
        assert!(returned.iter().all(Option::is_some), "{returning:#?}");
        assert_eq!(ctes[0].slot_columns, returned);
        let violations = check_plan_identity(&plan, &bindings);
        assert!(violations.is_empty(), "{violations:?}\n{plan:#?}");
        // The pairing is still asked for.
        let RelPlan::WithScope { ctes, .. } = &mut plan else {
            panic!("expected WithScope, got {plan:#?}");
        };
        ctes[0].slot_columns.clear();
        assert_breaks_plan(&plan, &bindings, IdentityCheck::Paired);
    }

    #[test]
    fn a_second_branch_reads_the_first_branchs_column() {
        let _folding = crate::ir::normalize::default_folding();
        let (mut plan, bindings) =
            lower_with_bindings("SELECT id FROM users UNION ALL SELECT id FROM orders");
        let RelPlan::SetOp { inputs, .. } = &mut plan else {
            panic!("expected SetOp, got {plan:#?}");
        };
        let [first, second] = inputs.as_mut_slice() else {
            panic!("expected two branches, got {inputs:#?}");
        };
        let RelPlan::Project { items, .. } = first.as_ref() else {
            panic!("expected Project in the first branch, got {first:#?}");
        };
        let [ProjectItem::Expr(first_item)] = items.as_slice() else {
            panic!("expected one expression item, got {items:#?}");
        };
        let read = first_item.expr.clone();
        let RelPlan::Project { items, .. } = second.as_mut() else {
            panic!("expected Project in the second branch, got {second:#?}");
        };
        let [ProjectItem::Expr(second_item)] = items.as_mut_slice() else {
            panic!("expected one expression item, got {items:#?}");
        };
        second_item.expr = read;
        assert_breaks_plan(&plan, &bindings, IdentityCheck::Contained);
    }

    #[test]
    fn a_table_column_on_a_node_that_is_no_source_is_reported() {
        let _folding = crate::ir::normalize::default_folding();
        let (mut plan, mut bindings) = lower_with_bindings("SELECT u.email FROM users u");
        let RelPlan::Project { items, node_id, .. } = &mut plan else {
            panic!("expected Project, got {plan:#?}");
        };
        let [ProjectItem::Expr(item)] = items.as_mut_slice() else {
            panic!("expected one expression item, got {items:#?}");
        };
        let ScalarExpr::Column { column, span } = &mut item.expr else {
            panic!("expected a column read, got {:#?}", item.expr);
        };
        // A table column of the block itself, read in place of the scan's.
        let on_block = ColumnId::new(bindings.len() as u32);
        bindings.insert(ColumnBinding {
            id: on_block,
            display_name: "EMAIL".to_string(),
            origin: ColumnOrigin::Table {
                table_node: *node_id,
                column_name: "email".to_string(),
                span: *span,
            },
            ty: None,
            explicit_alias: None,
        });
        *column = on_block;
        let violations = check_plan_identity(&plan, &bindings);
        let checks: Vec<IdentityCheck> = violations.iter().map(|v| v.check).collect();
        assert_eq!(checks, vec![IdentityCheck::Attributed], "{plan:#?}");
    }

    #[test]
    fn the_ids_of_a_statement_with_no_plan_name_no_source_of_it() {
        let _folding = crate::ir::normalize::default_folding();
        // A policy's parameters, and the columns of a scan in its body.
        let (plan, bindings) = lower_with_bindings(
            "CREATE ROW ACCESS POLICY p AS (customer_id NUMBER) RETURNS BOOLEAN -> \
             EXISTS (SELECT 1 FROM allowed ac WHERE ac.id = customer_id)",
        );
        assert!(matches!(plan, RelPlan::Opaque { .. }), "{plan:#?}");
        assert!(
            bindings.iter().any(|(_, b)| table_origin(b).is_some()),
            "expected a table column among the bindings"
        );
        let violations = check_plan_identity(&plan, &bindings);
        assert!(violations.is_empty(), "{violations:?}");
    }

    /// The plans held in the body of the row access policy `src`, its
    /// bindings and the statement's node.
    fn policy_body_plans(src: &str) -> (Vec<RelPlan>, BindingTable, NodeId) {
        use crate::ir::policy_facts::PolicyStatementFacts;
        use crate::ir::visitor::ScalarExprVisitor;
        struct Held(Vec<RelPlan>);
        impl<'a> ScalarExprVisitor<'a> for Held {
            fn visit_scalar_subquery(&mut self, plan: &'a RelPlan, _correlates: &'a [ColumnId]) {
                self.0.push(plan.clone());
            }
        }
        let tokens = tokenize(src);
        let script = parse_script(src, &tokens.tokens).expect("parse");
        let catalog = FunctionCatalog::for_dialect(CatalogDialect::Default);
        let session = SessionContext::default();
        let (_plan, _catalog_ctx, bindings, _facts, policy) =
            crate::ir::lower_query_full_with_bindings_models_and_policy_facts(
                &script.stmts[0],
                src,
                StrictMode::Permissive,
                &catalog,
                &session,
                None,
                None,
            )
            .expect("lower");
        let Some(PolicyStatementFacts::RowAccess(fact)) = policy else {
            panic!("expected row access policy facts, got {policy:#?}");
        };
        let mut held = Held(Vec::new());
        if let Some(body) = &fact.body {
            held.visit_scalar_expr(body);
        }
        (held.0, bindings, script.stmts[0].node_id())
    }

    #[test]
    fn a_policys_own_columns_are_attributed_to_its_statement() {
        let _folding = crate::ir::normalize::default_folding();
        // Two plans in one body: each one's scan is a source of the set.
        let (plans, bindings, host) = policy_body_plans(
            "CREATE ROW ACCESS POLICY p AS (customer_id NUMBER) RETURNS BOOLEAN -> \
             EXISTS (SELECT 1 FROM allowed ac WHERE ac.id = customer_id) \
             OR EXISTS (SELECT 1 FROM admins ad WHERE ad.id = customer_id)",
        );
        let plans: Vec<&RelPlan> = plans.iter().collect();
        assert_eq!(plans.len(), 2);
        let violations = check_hosted_plan_identity(&plans, &bindings, host);
        assert!(violations.is_empty(), "{violations:?}");
        // Alone, with no host, the argument's column names no source.
        let checks: Vec<IdentityCheck> = check_plan_identity(plans[0], &bindings)
            .iter()
            .map(|v| v.check)
            .collect();
        assert!(checks.contains(&IdentityCheck::Attributed), "{checks:?}");
    }

    #[test]
    fn a_table_column_on_neither_a_source_nor_the_host_is_reported() {
        let _folding = crate::ir::normalize::default_folding();
        let (plans, mut bindings, host) = policy_body_plans(
            "CREATE ROW ACCESS POLICY p AS (customer_id NUMBER) RETURNS BOOLEAN -> \
             EXISTS (SELECT 1 FROM allowed ac WHERE ac.id = customer_id)",
        );
        let plans: Vec<&RelPlan> = plans.iter().collect();
        let RelPlan::Project { node_id, span, .. } = plans[0] else {
            panic!("expected a Project, got {:#?}", plans[0]);
        };
        let stray = ColumnId::new(bindings.len() as u32);
        bindings.insert(ColumnBinding {
            id: stray,
            display_name: "ID".to_string(),
            origin: ColumnOrigin::Table {
                table_node: *node_id,
                column_name: "id".to_string(),
                span: *span,
            },
            ty: None,
            explicit_alias: None,
        });
        let violations = check_hosted_plan_identity(&plans, &bindings, host);
        let reported: Vec<(IdentityCheck, Option<ColumnId>)> =
            violations.iter().map(|v| (v.check, v.column)).collect();
        assert_eq!(
            reported,
            vec![(IdentityCheck::Attributed, Some(stray))],
            "{:#?}",
            plans[0]
        );
    }

    #[test]
    fn a_name_no_source_is_chosen_for_is_clean() {
        let _folding = crate::ir::normalize::default_folding();
        for src in [
            "SELECT a FROM t1 JOIN t2 ON t1.k = t2.k",
            "SELECT zz.a FROM t1",
            "UPDATE t SET a = b FROM u, v",
            "INSERT INTO t (id) VALUES (my_var)",
        ] {
            let (plan, bindings) = lower_with_bindings(src);
            let violations = check_plan_identity(&plan, &bindings);
            assert!(violations.is_empty(), "{src}: {violations:?}\n{plan:#?}");
        }
    }

    #[test]
    fn a_using_side_column_its_input_cannot_read_is_reported() {
        let _folding = crate::ir::normalize::default_folding();
        let (mut plan, bindings) =
            lower_with_bindings("SELECT id FROM users u JOIN orders o USING (id)");
        let RelPlan::Project { input, .. } = &mut plan else {
            panic!("expected Project, got {plan:#?}");
        };
        let RelPlan::Join { using, .. } = input.as_mut() else {
            panic!("expected Join under the Project, got {input:#?}");
        };
        let [column] = using.as_mut_slice() else {
            panic!("expected one USING column, got {using:#?}");
        };
        column.left = column.right;
        assert_breaks_plan(&plan, &bindings, IdentityCheck::UsingDefined);
    }

    #[test]
    fn a_column_read_that_its_producing_node_does_not_list_is_reported() {
        let _folding = crate::ir::normalize::default_folding();
        let (mut plan, bindings) =
            lower_with_bindings("SELECT id FROM users u JOIN orders o USING (id)");
        let RelPlan::Project { input, .. } = &mut plan else {
            panic!("expected Project, got {plan:#?}");
        };
        let RelPlan::Join { using, .. } = input.as_mut() else {
            panic!("expected Join under the Project, got {input:#?}");
        };
        // The select item still reads the merged column the join made.
        using.clear();
        assert_breaks_plan(&plan, &bindings, IdentityCheck::Produced);
    }

    /// The id of the one parameter of the lambda the second argument of
    /// the call in the first select item of `plan` is.
    fn lambda_parameter(plan: &RelPlan) -> ColumnId {
        let RelPlan::Project { items, .. } = plan else {
            panic!("expected Project, got {plan:#?}");
        };
        let Some(ProjectItem::Expr(item)) = items.first() else {
            panic!("expected an expression item, got {items:#?}");
        };
        let ScalarExpr::FuncCall { args, .. } = &item.expr else {
            panic!("expected a call, got {item:#?}");
        };
        let Some(ScalarExpr::Lambda { params, .. }) = args.get(1) else {
            panic!("expected a lambda argument, got {args:#?}");
        };
        params[0].id
    }

    #[test]
    fn a_lambda_parameter_read_in_its_body_is_clean() {
        let _folding = crate::ir::normalize::default_folding();
        for sql in [
            "SELECT filter_arr(arr, x -> x > 5) AS f FROM t",
            "SELECT filter_arr(arr, name -> name = email) AS f FROM t",
            "SELECT transform(arr, x -> filter_arr(x, y -> y > x)) AS f FROM t",
            "WITH w AS (SELECT email, arr FROM t) \
             SELECT filter_arr(arr, name -> name = email) AS f FROM w",
        ] {
            let (plan, bindings) = lower_with_bindings(sql);
            let violations = check_plan_identity(&plan, &bindings);
            assert!(violations.is_empty(), "{sql}: {violations:?}\n{plan:#?}");
        }
    }

    #[test]
    fn a_lambda_parameter_read_outside_its_lambda_is_reported() {
        let _folding = crate::ir::normalize::default_folding();
        let (mut plan, bindings) =
            lower_with_bindings("SELECT filter_arr(arr, x -> x > 5) AS f, arr AS g FROM t");
        let parameter = lambda_parameter(&plan);
        let RelPlan::Project { items, .. } = &mut plan else {
            panic!("expected Project, got {plan:#?}");
        };
        let Some(ProjectItem::Expr(second)) = items.get_mut(1) else {
            panic!("expected a second expression item, got {items:#?}");
        };
        let span = second.span;
        second.expr = ScalarExpr::Column {
            column: parameter,
            span,
        };
        assert_breaks_plan(&plan, &bindings, IdentityCheck::Produced);
    }

    #[test]
    fn a_column_a_statement_writes_and_reads_back_is_clean() {
        let _folding = crate::ir::normalize::default_folding();
        let (plan, bindings) = lower_with_bindings(
            "INSERT INTO users (id, name) VALUES (1, 'a') RETURNING id, upper(name)",
        );
        let violations = check_plan_identity(&plan, &bindings);
        assert!(violations.is_empty(), "{violations:?}\n{plan:#?}");
    }

    #[test]
    fn a_using_join_is_clean() {
        let _folding = crate::ir::normalize::default_folding();
        let (plan, bindings) =
            lower_with_bindings("SELECT id FROM users u JOIN orders o USING (id)");
        let violations = check_plan_identity(&plan, &bindings);
        assert!(violations.is_empty(), "{violations:?}\n{plan:#?}");
    }

    #[test]
    fn a_source_on_its_blocks_id_is_reported() {
        let _folding = crate::ir::normalize::default_folding();
        let (mut plan, bindings) = lower_with_bindings("SELECT 1");
        let RelPlan::Project { input, node_id, .. } = &mut plan else {
            panic!("expected Project, got {plan:#?}");
        };
        let RelPlan::Values {
            node_id: values_node,
            ..
        } = input.as_mut()
        else {
            panic!("expected Values under the Project, got {input:#?}");
        };
        *values_node = *node_id;
        assert_breaks_plan(&plan, &bindings, IdentityCheck::SourceIds);
    }

    #[test]
    fn a_star_naming_a_source_outside_its_block_is_reported() {
        let _folding = crate::ir::normalize::default_folding();
        let (mut plan, bindings) = lower_with_bindings("SELECT * FROM (SELECT a FROM t) d");
        assert!(
            check_plan_identity(&plan, &bindings).is_empty(),
            "{plan:#?}"
        );
        let RelPlan::Project { input, items, .. } = &mut plan else {
            panic!("expected Project, got {plan:#?}");
        };
        let RelPlan::DerivedTable { input: body, .. } = input.as_ref() else {
            panic!("expected a DerivedTable under the Project, got {input:#?}");
        };
        let RelPlan::Project { input: scan, .. } = body.as_ref() else {
            panic!("expected a Project as the body, got {body:#?}");
        };
        let inner = scan.node_id();
        let Some(ProjectItem::Star(star)) = items.last_mut() else {
            panic!("expected the star last, got {items:#?}");
        };
        star.enumerated.push(inner);
        assert_breaks_plan(&plan, &bindings, IdentityCheck::StarSources);
    }

    #[test]
    fn a_star_that_says_it_is_complete_over_a_source_it_left_out_is_reported() {
        let _folding = crate::ir::normalize::default_folding();
        for sql in [
            "SELECT * FROM (SELECT a FROM t) d JOIN x ON x.a = d.a",
            "SELECT x.* FROM (SELECT a FROM t) d JOIN x ON x.a = d.a",
        ] {
            let (mut plan, bindings) = lower_with_bindings(sql);
            assert!(
                check_plan_identity(&plan, &bindings).is_empty(),
                "{plan:#?}"
            );
            let RelPlan::Project { items, .. } = &mut plan else {
                panic!("expected Project, got {plan:#?}");
            };
            let Some(ProjectItem::Star(star)) = items.last_mut() else {
                panic!("expected the star last, got {items:#?}");
            };
            assert!(!star.complete, "{sql}");
            star.complete = true;
            assert_breaks_plan(&plan, &bindings, IdentityCheck::StarSources);
        }
    }

    #[test]
    fn a_star_that_itemized_a_column_its_input_does_not_yield_is_reported() {
        let _folding = crate::ir::normalize::default_folding();
        let (mut plan, bindings) = lower_with_bindings(
            "SELECT * FROM t PIVOT (SUM(amount) FOR quarter IN ('Q1', 'Q2')) p",
        );
        assert!(
            check_plan_identity(&plan, &bindings).is_empty(),
            "{plan:#?}"
        );
        let RelPlan::Project { items, .. } = &mut plan else {
            panic!("expected Project, got {plan:#?}");
        };
        let [ProjectItem::Expr(first), .., ProjectItem::Star(star)] = items.as_mut_slice() else {
            panic!("expected items and the star last, got {items:#?}");
        };
        assert_eq!(star.itemized.len(), 2);
        // An item's own output is no column of the projection's input.
        star.itemized.push(first.output);
        assert_breaks_plan(&plan, &bindings, IdentityCheck::StarSources);
    }

    #[test]
    fn a_star_that_counts_more_items_than_precede_it_is_reported() {
        let _folding = crate::ir::normalize::default_folding();
        let sql = "SELECT d.a AS first, * FROM (SELECT a, b FROM t) d";
        for wrong in [3, 4] {
            let (mut plan, bindings) = lower_with_bindings(sql);
            assert!(
                check_plan_identity(&plan, &bindings).is_empty(),
                "{plan:#?}"
            );
            let RelPlan::Project { items, .. } = &mut plan else {
                panic!("expected Project, got {plan:#?}");
            };
            let Some(ProjectItem::Star(star)) = items.last_mut() else {
                panic!("expected the star last, got {items:#?}");
            };
            // The derived table places both of its columns.
            assert_eq!(star.unplaced, 0, "{sql}");
            star.unplaced = wrong;
            let violations = check_plan_identity(&plan, &bindings);
            let reported = violations
                .iter()
                .any(|v| v.check == IdentityCheck::StarSources);
            // Three items precede the star.
            assert_eq!(reported, wrong > 3, "{violations:?}");
        }
    }

    #[test]
    fn a_plain_select_is_clean() {
        let _folding = crate::ir::normalize::default_folding();
        let (plan, bindings) = lower_with_bindings("SELECT id FROM users WHERE id = 1");
        let violations = check_plan_identity(&plan, &bindings);
        assert!(violations.is_empty(), "{violations:?}\n{plan:#?}");
    }
}
