// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! The texts the script's variables are known to hold at the statement being
//! lowered, read where a name is written `IDENTIFIER($v)` or `IDENTIFIER(:v)`.

use crate::context::node_metadata::IdentKey;
use std::cell::RefCell;
use std::collections::BTreeMap;

/// A variable as a statement reads it: whether it is a session variable
/// (`$v`) or one of the statement's own scope (`:v`), and its key.
pub(crate) type ReadVariable = (bool, IdentKey);

thread_local! {
    // The values of the statements the thread is lowering, outermost first.
    static IN_FORCE: RefCell<Vec<BTreeMap<ReadVariable, String>>> =
        const { RefCell::new(Vec::new()) };
}

/// The values known at one statement, in force while it lives
/// ([`crate::ScriptContextFold::enter_statement`]). A statement lowered
/// inside another reads its own.
#[must_use = "the values are in force only while the guard lives"]
#[derive(Debug)]
pub struct StatementValues {
    /// How many scopes the thread holds with this one.
    depth: usize,
}

impl StatementValues {
    pub(crate) fn enter(values: BTreeMap<ReadVariable, String>) -> Self {
        let depth = IN_FORCE.with(|open| {
            let mut open = open.borrow_mut();
            open.push(values);
            open.len()
        });
        Self { depth }
    }
}

impl Drop for StatementValues {
    fn drop(&mut self) {
        // At thread exit the list is already gone, with every scope in it.
        let _ = IN_FORCE.try_with(|open| {
            if let Ok(mut open) = open.try_borrow_mut() {
                open.truncate(self.depth.saturating_sub(1));
            }
        });
    }
}

/// The text the variable `key` is known to hold at the statement being
/// lowered, `session` for `$v`; `None` outside every statement scope, and
/// for a variable whose text the script does not say.
pub(crate) fn value_in_force(session: bool, key: &IdentKey) -> Option<String> {
    IN_FORCE
        .try_with(|open| {
            open.try_borrow()
                .ok()
                .and_then(|open| open.last()?.get(&(session, key.clone())).cloned())
        })
        .ok()
        .flatten()
}
