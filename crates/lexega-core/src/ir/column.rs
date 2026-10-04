// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Stable column identity for the Relational IR.
//!
//! A `ColumnId` is allocated once when a column first appears (from a base table
//! scan, a projection, a set-op unification, or a correlated outer reference) and
//! threads unchanged through every downstream `RelPlan` node. Dataflow analyses
//! key off `ColumnId`, not `(table, name)` strings.
//!
//! # BindingTable
//!
//! Every `ColumnId` allocated during lowering has a companion
//! [`ColumnBinding`] entry in a [`BindingTable`] side-table. The
//! allocator owns the table: there is no way to allocate
//! a `ColumnId` without simultaneously emitting its binding, which is
//! the compile-time guarantee that every id reachable in a lowered
//! plan is name-resolvable for downstream analyses (name-keyed
//! lineage, dialect transpilation, canonicalization rewrites).

use crate::ast::NodeId;
use crate::context::node_metadata::IdentKey;
use crate::lexer::Span;
use std::collections::BTreeMap;
use std::fmt;

/// Stable identifier for a single column value flowing through the IR.
///
/// Allocated by a [`ColumnIdAllocator`] during lowering. Two `ColumnId`s
/// compare equal iff they reference the same logical column binding.
///
/// The inner `u32` has no semantic meaning beyond uniqueness within one
/// analysis session; do **not** serialize it or compare across sessions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ColumnId(u32);

impl ColumnId {
    #[inline]
    pub fn new(raw: u32) -> Self {
        ColumnId(raw)
    }

    #[inline]
    pub fn as_u32(self) -> u32 {
        self.0
    }
}

impl fmt::Display for ColumnId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "c{}", self.0)
    }
}

/// Monotonic allocator for [`ColumnId`]s that simultaneously
/// populates a [`BindingTable`] side-table.
///
/// One allocator per lowered statement (or per script, if columns cross
/// statement boundaries via scripting variables — see `ScriptPlan`).
///
/// The only way to mint a [`ColumnId`] is via [`Self::fresh`], which
/// takes the origin + display name up front and records the binding
/// atomically. This is the mechanism that guarantees every id
/// reachable in a lowered plan has a populated binding; there is no
/// parameterless `fresh()` to tempt a silent gap.
#[derive(Debug, Default, Clone)]
pub struct ColumnIdAllocator {
    next: u32,
    bindings: BindingTable,
}

impl ColumnIdAllocator {
    pub fn new() -> Self {
        Self {
            next: 0,
            bindings: BindingTable::new(),
        }
    }

    /// Allocate a fresh [`ColumnId`] and atomically record its
    /// [`ColumnBinding`] in the internal [`BindingTable`].
    ///
    /// The `display_name` is the name as the user would write it
    /// post-alias resolution (for SetOp-unified ids, the first
    /// branch's display name is conventional). Empty strings are
    /// tolerated for anonymous intermediate columns but should be
    /// avoided when a meaningful name is in scope.
    pub fn fresh(&mut self, origin: ColumnOrigin, display_name: impl Into<String>) -> ColumnId {
        let id = ColumnId(self.next);
        self.next = self.next.checked_add(1).expect("ColumnId overflow");
        let binding = ColumnBinding {
            id,
            display_name: display_name.into(),
            origin,
            ty: None,
            explicit_alias: None,
        };
        self.bindings.insert(binding);
        id
    }

    /// Stamp a user-typed projection alias onto an existing binding.
    ///
    /// Called by `lower_projection_item` when a `ProjectExpr` wraps a
    /// direct `Column` reference with an `AS <alias>`. The stamping is
    /// gated to [`ColumnOrigin::Computed`] bindings — aggregate / window /
    /// expression outputs — so multi-alias patterns on table columns
    /// (`SELECT t.c AS a, t.c AS b`) cannot collapse to a single alias on
    /// the underlying table-origin binding. Downstream analyses
    /// (diff, lineage) can then recover the user's alias from the
    /// `BindingTable` directly instead of re-walking projections.
    pub fn stamp_alias_if_computed(&mut self, id: ColumnId, alias: IdentKey) {
        self.bindings.stamp_alias_if_computed(id, alias);
    }

    /// Total number of ids allocated (== number of bindings recorded).
    pub fn count(&self) -> u32 {
        self.next
    }

    /// Borrowed view of the accumulated binding side-table.
    pub fn bindings(&self) -> &BindingTable {
        &self.bindings
    }

    /// Consume the allocator and return the populated
    /// [`BindingTable`]. Called at the end of lowering by the
    /// bindings-returning entry points.
    pub fn into_bindings(self) -> BindingTable {
        self.bindings
    }

    /// Test-only shortcut: allocate a [`ColumnId`] with a
    /// placeholder [`ColumnOrigin::Computed`] origin and empty
    /// display name. Non-test code MUST go through
    /// [`Self::fresh`] so every site explicitly names the column's
    /// origin; this helper exists solely to keep IR unit tests that
    /// only care about plan/scalar structure concise.
    #[cfg(test)]
    pub(crate) fn fresh_test(&mut self) -> ColumnId {
        self.fresh(
            ColumnOrigin::Computed {
                producing_node: crate::ast::NodeId::new(0),
                expr_span: crate::lexer::Span { start: 0, end: 0 },
            },
            String::new(),
        )
    }
}

/// Side-table mapping every allocated [`ColumnId`] to its
/// [`ColumnBinding`].
///
/// Populated atomically by [`ColumnIdAllocator::fresh`]. Every
/// `ColumnId` that appears in a lowered [`crate::ir::RelPlan`] has a
/// corresponding entry; callers can treat [`Self::get`] as total for
/// ids produced by the same allocator session.
///
/// Iteration is in allocation order, so anything projected from a walk
/// over the table is deterministic.
#[derive(Debug, Default, Clone)]
pub struct BindingTable {
    entries: BTreeMap<ColumnId, ColumnBinding>,
}

impl BindingTable {
    pub fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }

    pub fn insert(&mut self, binding: ColumnBinding) {
        self.entries.insert(binding.id, binding);
    }

    pub fn get(&self, id: ColumnId) -> Option<&ColumnBinding> {
        self.entries.get(&id)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&ColumnId, &ColumnBinding)> {
        self.entries.iter()
    }

    /// True iff every `ColumnId` produced by `allocator` has a
    /// binding in this table. Used by the lowering tests as a
    /// compile-time-complemented invariant check.
    pub fn covers(&self, allocator: &ColumnIdAllocator) -> bool {
        (0..allocator.count()).all(|i| self.entries.contains_key(&ColumnId(i)))
    }

    /// Stamp a user-typed projection alias onto an existing binding.
    ///
    /// Gated to [`ColumnOrigin::Computed`] bindings; see
    /// [`ColumnIdAllocator::stamp_alias_if_computed`] for the rationale.
    /// Silently no-ops when the id is absent (defensive — every id reachable
    /// in a lowered plan has a binding) or when an alias is already stamped
    /// (first-write-wins; aggregate / window outputs have a single natural
    /// wrapping projection so this only triggers in degenerate cases).
    pub fn stamp_alias_if_computed(&mut self, id: ColumnId, alias: IdentKey) {
        let Some(binding) = self.entries.get_mut(&id) else {
            return;
        };
        if !matches!(binding.origin, ColumnOrigin::Computed { .. }) {
            return;
        }
        if binding.explicit_alias.is_some() {
            return;
        }
        binding.explicit_alias = Some(alias);
    }
}

/// The full binding record for a [`ColumnId`].
///
/// Stored in a side-table keyed by `ColumnId`, not inlined into `RelPlan`
/// nodes, so plan equality stays structural.
#[derive(Debug, Clone)]
pub struct ColumnBinding {
    pub id: ColumnId,
    /// Human-readable name as the user would write it (post-alias resolution).
    pub display_name: String,
    pub origin: ColumnOrigin,
    /// Optional resolved SQL type. `None` when the catalog cannot resolve it.
    pub ty: Option<crate::ir::scalar::SqlType>,
    /// User-typed alias from the wrapping `ProjectExpr` when this binding
    /// is referenced directly (`Column(id)`) and the projection carries
    /// `AS <alias>`. Stamped only for [`ColumnOrigin::Computed`] bindings
    /// — see [`BindingTable::stamp_alias_if_computed`]. Lets downstream
    /// analyses (e.g. diff aggregate pairing) recover the user's name
    /// without re-walking enclosing projections.
    pub explicit_alias: Option<IdentKey>,
}

/// Where a column's value originates.
///
/// Correlated outer references get their own variant so subquery
/// analyses do not need to re-scan the parent plan.
#[derive(Debug, Clone)]
pub enum ColumnOrigin {
    /// Direct reference to a base-table column.
    ///
    /// `table_node` is the `NodeId` of the AST table reference (useful for
    /// mapping back to source spans); `column_name` is the raw identifier
    /// text — normalization happens at lookup time.
    Table {
        table_node: NodeId,
        column_name: String,
        span: Span,
    },
    /// Computed by an expression in some ancestor plan node.
    Computed {
        producing_node: NodeId,
        expr_span: Span,
    },
    /// Produced by a set-op (UNION / INTERSECT / EXCEPT) that unified inputs.
    ///
    /// Each entry is a column from one input, in input order.
    SetOp { inputs: Vec<ColumnId> },
    /// Reference to a column from an outer query scope (correlation).
    OuterRef {
        scope: crate::ir::scalar::ScopeId,
        outer_column: ColumnId,
    },
    /// Recursive CTE self-reference. `binding_index` is the column position
    /// within the recursive CTE's output schema.
    RecursiveRef { binding_index: u32 },
}
