// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! The one id of each column of each source of a statement.

use std::collections::BTreeMap;

use super::column::ColumnId;
use crate::ast::NodeId;
use crate::context::node_metadata::IdentKey;

/// The one id of each (source, column) of the statement being lowered.
#[derive(Debug, Default)]
pub(crate) struct ColumnRegistry {
    sources: BTreeMap<NodeId, SourceColumns>,
    /// Every (source, id), in allocation order.
    order: Vec<(NodeId, ColumnId)>,
}

/// The registered columns of one source.
#[derive(Debug, Default)]
struct SourceColumns {
    by_name: BTreeMap<IdentKey, ColumnId>,
    /// The source's names and ids, in allocation order.
    in_order: Vec<(IdentKey, ColumnId)>,
}

impl ColumnRegistry {
    pub(crate) fn get(&self, source: NodeId, name: &IdentKey) -> Option<ColumnId> {
        self.sources.get(&source)?.by_name.get(name).copied()
    }

    /// Returns the existing id, or records `fresh`.
    pub(crate) fn get_or_insert(
        &mut self,
        source: NodeId,
        name: &IdentKey,
        fresh: impl FnOnce() -> ColumnId,
    ) -> ColumnId {
        if let Some(id) = self.get(source, name) {
            return id;
        }
        let id = fresh();
        let columns = self.sources.entry(source).or_default();
        columns.by_name.insert(name.clone(), id);
        columns.in_order.push((name.clone(), id));
        self.order.push((source, id));
        id
    }

    /// Every (source, id), in allocation order, for the listing pass.
    pub(crate) fn listed(&self) -> impl Iterator<Item = (NodeId, ColumnId)> + '_ {
        self.order.iter().copied()
    }

    /// The names and ids registered on `source`, in allocation order.
    pub(crate) fn named_columns_of(
        &self,
        source: NodeId,
    ) -> impl Iterator<Item = (&IdentKey, ColumnId)> + '_ {
        self.sources
            .get(&source)
            .into_iter()
            .flat_map(|columns| columns.in_order.iter().map(|(name, id)| (name, *id)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_second_request_returns_the_first_id() {
        let _folding = crate::ir::normalize::default_folding();
        let mut registry = ColumnRegistry::default();
        let source = NodeId::new(7);
        let other = NodeId::new(8);
        let email = IdentKey::new("email");
        let first = registry.get_or_insert(source, &email, || ColumnId::new(1));
        let second = registry.get_or_insert(source, &IdentKey::new("EMAIL"), || ColumnId::new(2));
        assert_eq!(first, second);
        assert_eq!(registry.get(source, &email), Some(first));
        assert_eq!(registry.get(other, &email), None);
        let on_other = registry.get_or_insert(other, &email, || ColumnId::new(3));
        assert_ne!(first, on_other);
        assert_eq!(
            registry.listed().collect::<Vec<_>>(),
            vec![(source, first), (other, on_other)]
        );
    }

    #[test]
    fn a_sources_columns_come_in_allocation_order() {
        let _folding = crate::ir::normalize::default_folding();
        let mut registry = ColumnRegistry::default();
        let source = NodeId::new(7);
        let other = NodeId::new(8);
        let zeta = registry.get_or_insert(source, &IdentKey::new("zeta"), || ColumnId::new(1));
        let on_other = registry.get_or_insert(other, &IdentKey::new("alpha"), || ColumnId::new(2));
        let alpha = registry.get_or_insert(source, &IdentKey::new("alpha"), || ColumnId::new(3));
        registry.get_or_insert(source, &IdentKey::new("ZETA"), || ColumnId::new(4));
        assert_eq!(
            registry.named_columns_of(source).collect::<Vec<_>>(),
            vec![
                (&IdentKey::new("zeta"), zeta),
                (&IdentKey::new("alpha"), alpha)
            ]
        );
        assert_eq!(
            registry.named_columns_of(other).collect::<Vec<_>>(),
            vec![(&IdentKey::new("alpha"), on_other)]
        );
        assert_eq!(registry.named_columns_of(NodeId::new(9)).count(), 0);
    }
}
