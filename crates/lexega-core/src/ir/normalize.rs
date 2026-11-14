// Copyright (c) 2025-2026 Lexega LLC
// SPDX-License-Identifier: BUSL-1.1

//! Dialect scopes: the identifier folding and the other dialect state a
//! thread uses while it analyses a script in one dialect.
//!
//! The folding itself — [`normalize_identifier`] and its configuration — is
//! the syntax crate's, re-exported here; a scope sets the thread's folding
//! on entry and puts back the one it found when it ends.
//!
//! - [`set_normalization_dialect`] - Fold as a dialect does until the scope it returns is dropped
//! - `LEXEGA_IDENTIFIER_CASE=ignore_quoted` folds quoted identifiers as well

use crate::facts::reasoning::DialectHold;
use lexega_syntax::dialect::{
    dialect_from_name, replace_thread_normalization, snowflake, thread_normalization, DialectRef,
    ThreadNormalization,
};
pub use lexega_syntax::dialect::{
    is_ignore_quoted_active, normalize_identifier, normalize_identifier_as, normalize_string_name,
    CaseFold, NameKind, NormalizationConfig, QuotedHandling,
};
use std::cell::{Cell, RefCell};

thread_local! {
    // The dialect scopes the thread is inside, outermost first, and the id
    // its next scope gets. An id is never given twice on a thread. A scope
    // still open when its thread ends is not ended: its provider's hold is
    // dropped with the list and nothing here is put back.
    static OPEN_SCOPES: RefCell<Vec<OpenScope>> = const { RefCell::new(Vec::new()) };
    static NEXT_SCOPE: Cell<u64> = const { Cell::new(0) };
}

/// A dialect scope its thread is inside, with what the thread had before
/// it.
struct OpenScope {
    id: u64,
    /// The dialect the scope reads string literals as.
    dialect: DialectRef,
    normalization: Option<ThreadNormalization>,
    /// The provider's hold, once the provider has adopted the dialect.
    provider: Option<Box<dyn DialectHold>>,
}

impl OpenScope {
    /// Put the thread back where the scope found it: the folding, then the
    /// provider's state. A hold that ends another scope as it drops finds
    /// the thread where this scope found it.
    fn end(self) {
        replace_thread_normalization(self.normalization);
        drop(self.provider);
    }
}

/// Scopes taken off the thread's list, outermost first, to be ended
/// innermost first. Dropped with scopes left, when a hold panicked as it
/// was dropped, it still ends them.
struct Ending(Vec<OpenScope>);

impl Ending {
    fn end_all(&mut self) {
        while let Some(scope) = self.0.pop() {
            scope.end();
        }
    }
}

impl Drop for Ending {
    fn drop(&mut self) {
        self.end_all();
    }
}

/// The dialect of the innermost dialect scope the thread is inside;
/// Snowflake outside every scope, as names are folded there.
pub(crate) fn dialect_in_force() -> DialectRef {
    OPEN_SCOPES
        .try_with(|open| {
            open.try_borrow()
                .ok()
                .and_then(|open| open.last().map(|scope| scope.dialect.clone()))
        })
        .ok()
        .flatten()
        .unwrap_or_else(snowflake)
}

/// How many dialect scopes the thread is inside.
pub(crate) fn dialect_scope_depth() -> usize {
    OPEN_SCOPES.with(|open| open.borrow().len())
}

/// Open a dialect scope on the thread, inside the ones already open: the
/// thread folds and reads as `dialect_name` until the scope ends. Returns
/// the scope's id.
pub(crate) fn enter_dialect_scope(dialect_name: &str) -> u64 {
    let id = NEXT_SCOPE.get();
    NEXT_SCOPE.set(id + 1);
    let folding = NormalizationConfig::from_dialect(dialect_name);
    let scope = OpenScope {
        id,
        dialect: dialect_from_name(dialect_name).unwrap_or_else(snowflake),
        normalization: replace_thread_normalization(Some(ThreadNormalization::scoped(folding))),
        provider: None,
    };
    OPEN_SCOPES.with(|open| open.borrow_mut().push(scope));
    id
}

/// Give the open scope `id` the provider's hold, to drop when the scope
/// ends.
pub(crate) fn hold_in_dialect_scope(id: u64, hold: Box<dyn DialectHold>) {
    // A hold no open scope takes is dropped outside the borrow.
    let unkept =
        OPEN_SCOPES.with(
            |open| match open.borrow_mut().iter_mut().find(|scope| scope.id == id) {
                Some(scope) => scope.provider.replace(hold),
                None => Some(hold),
            },
        );
    drop(unkept);
}

/// End the scope `id` and every scope opened inside it, innermost first,
/// and return how many that ended: one where `id` was the innermost, none
/// where a scope around it had ended it already.
pub(crate) fn leave_dialect_scope(id: u64) -> usize {
    // Taken off the list first: a provider's hold is dropped outside the
    // borrow. A thread that is ending may have dropped the list already,
    // and its scopes with it.
    let mut ending = Ending(
        OPEN_SCOPES
            .try_with(|open| {
                let mut open = open.borrow_mut();
                match open.iter().position(|scope| scope.id == id) {
                    Some(at) => open.split_off(at),
                    None => Vec::new(),
                }
            })
            .unwrap_or_default(),
    );
    let count = ending.0.len();
    ending.end_all();
    count
}

/// Read the environment's identifier-case override again. Inside a dialect
/// scope the thread keeps the scope's dialect; outside any it goes back to
/// the default folding. Only the innermost open scope reads it again: a
/// scope around it folds, once the inner one ends, as it did when the inner
/// one was opened. Only tests call it.
pub fn reset_identifier_case_mode_cache() {
    let kept = thread_normalization()
        .filter(|_| dialect_scope_depth() > 0)
        .map(|folding| ThreadNormalization::scoped(folding.dialect()));
    replace_thread_normalization(kept);
}

/// Fold names on the current thread as `dialect_name` does, fold direction
/// and quote characters, and read text as it does, until the returned scope
/// is dropped. The analysis provider's dialect state stays as it is.
///
/// An analysis entry point adopts its own dialect in full and does not read
/// this; tests call it to fold the names they build.
pub fn set_normalization_dialect(dialect_name: &str) -> crate::DialectScope {
    crate::DialectScope {
        id: enter_dialect_scope(dialect_name),
        _thread: std::marker::PhantomData,
    }
}

/// The default folding, for a unit test that folds names without going
/// through an analysis entry point.
#[cfg(test)]
pub(crate) fn default_folding() -> crate::DialectScope {
    set_normalization_dialect("snowflake")
}

/// The folding in force inside the innermost open dialect scope; `None`
/// outside every scope. What a name-keyed store records as the folding it
/// was keyed under.
pub(crate) fn scoped_folding() -> Option<NormalizationConfig> {
    let scoped = OPEN_SCOPES
        .try_with(|open| open.try_borrow().is_ok_and(|open| !open.is_empty()))
        .unwrap_or(false);
    if scoped {
        thread_normalization().map(|folding| folding.in_force())
    } else {
        None
    }
}

/// Whether a store whose keys were made from `keyed`, the part `of` the
/// folding its keys depend on, may be read or written now: always outside a
/// scope or where it recorded none, else only where that part is the same.
pub(crate) fn keys_read_alike<T: PartialEq>(
    keyed: &Option<T>,
    of: fn(&NormalizationConfig) -> T,
) -> bool {
    match (keyed, scoped_folding()) {
        (Some(keyed), Some(now)) => *keyed == of(&now),
        (Some(_), None) | (None, Some(_)) | (None, None) => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::panic::{catch_unwind, AssertUnwindSafe};

    /// How the thread folds a bare name, and the dialect it reads text as.
    fn state() -> (String, String) {
        (
            normalize_identifier("Abc"),
            dialect_in_force().name().to_string(),
        )
    }

    /// A hold that ends a scope opened before its own as it is dropped.
    struct EndsAnother {
        _outer: crate::DialectScope,
    }

    impl DialectHold for EndsAnother {}

    /// A hold that fails as it is dropped.
    struct PanicsOnDrop;

    impl DialectHold for PanicsOnDrop {}

    impl Drop for PanicsOnDrop {
        fn drop(&mut self) {
            panic!("the hold fails");
        }
    }

    #[test]
    fn a_name_folded_with_no_scope_open_is_refused_in_a_debug_build() {
        let folded = catch_unwind(|| normalize_identifier("Abc"));
        assert_eq!(folded.is_err(), cfg!(debug_assertions));
        let asked = catch_unwind(is_ignore_quoted_active);
        assert_eq!(asked.is_err(), cfg!(debug_assertions));
        let _folding = default_folding();
        assert_eq!(normalize_identifier("Abc"), "ABC");
    }

    #[test]
    fn a_folding_set_by_name_lasts_as_long_as_its_scope() {
        let _folding = default_folding();
        let before = state();
        {
            let _set = set_normalization_dialect("postgresql");
            assert_eq!(state(), ("abc".to_string(), "postgresql".to_string()));
            assert_eq!(dialect_scope_depth(), 2);
        }
        assert_eq!(state(), before);
        assert_eq!(dialect_scope_depth(), 1);
    }

    #[test]
    fn a_hold_that_ends_an_outer_scope_leaves_the_thread_where_that_scope_found_it() {
        let _folding = default_folding();
        let before = state();
        let outer = set_normalization_dialect("postgresql");
        let inner = enter_dialect_scope("mssql");
        hold_in_dialect_scope(inner, Box::new(EndsAnother { _outer: outer }));
        assert_eq!(leave_dialect_scope(inner), 1);
        assert_eq!(state(), before);
        assert_eq!(dialect_scope_depth(), 1);
    }

    #[test]
    fn a_hold_that_panics_as_it_drops_leaves_the_scopes_around_it_ended() {
        let _folding = default_folding();
        let before = state();
        let outer = enter_dialect_scope("postgresql");
        let middle = enter_dialect_scope("mssql");
        hold_in_dialect_scope(middle, Box::new(PanicsOnDrop));
        let _inner = enter_dialect_scope("databricks");
        let unwound = catch_unwind(AssertUnwindSafe(|| leave_dialect_scope(outer)));
        assert!(unwound.is_err());
        assert_eq!(state(), before);
        assert_eq!(dialect_scope_depth(), 1);
    }

    /// The thread's folding cell, as stored.
    type Cell = Option<(NormalizationConfig, NormalizationConfig)>;

    fn cell() -> Cell {
        thread_normalization().map(|folding| (folding.dialect(), folding.in_force()))
    }

    /// Runs `pattern` on a thread that has opened no scope and folded no
    /// name: its folding cell is unset.
    fn on_a_fresh_thread(pattern: impl FnOnce() + Send + 'static) {
        if let Err(panic) = std::thread::spawn(pattern).join() {
            std::panic::resume_unwind(panic);
        }
    }

    /// A scope that folds and reads as `dialect_name`.
    fn scope(dialect_name: &str) -> crate::DialectScope {
        crate::DialectScope {
            id: enter_dialect_scope(dialect_name),
            _thread: std::marker::PhantomData,
        }
    }

    #[test]
    fn a_fresh_thread_reads_text_as_a_scope_that_names_no_dialect_does() {
        on_a_fresh_thread(|| {
            let fresh = dialect_in_force().name().to_string();
            let _scope = crate::adopt_dialect(None, &crate::facts::reasoning::RecognitionOnly);
            assert_eq!(fresh, dialect_in_force().name());
            assert_eq!(fresh, "snowflake");
        });
    }

    #[test]
    fn the_outermost_scope_leaves_the_folding_cell_as_it_found_it() {
        on_a_fresh_thread(|| {
            let before = cell();
            assert_eq!(before, None);
            let outermost = scope("postgresql");
            assert_ne!(cell(), before);
            drop(outermost);
            assert_eq!(cell(), before);
            assert_eq!(dialect_scope_depth(), 0);
        });
    }

    #[test]
    fn two_scopes_dropped_outer_first_leave_the_folding_cell_as_the_outer_found_it() {
        on_a_fresh_thread(|| {
            let before = cell();
            let outer = scope("postgresql");
            let inner = scope("databricks");
            let reported = catch_unwind(AssertUnwindSafe(move || drop(outer))).is_err();
            assert_eq!(reported, cfg!(debug_assertions));
            assert_eq!(cell(), before);
            drop(inner);
            assert_eq!(cell(), before);
            assert_eq!(dialect_scope_depth(), 0);
        });
    }

    #[test]
    fn a_panic_through_the_outermost_scope_leaves_the_folding_cell_as_it_found_it() {
        on_a_fresh_thread(|| {
            let before = cell();
            let unwound = catch_unwind(|| {
                let _outermost = scope("postgresql");
                panic!("through the scope");
            });
            assert!(unwound.is_err());
            assert_eq!(cell(), before);
            assert_eq!(dialect_scope_depth(), 0);
        });
    }

    #[test]
    fn an_adopted_outermost_scope_leaves_the_folding_cell_as_it_found_it() {
        on_a_fresh_thread(|| {
            let before = cell();
            let dialect = crate::dialect::postgres();
            let adopted = crate::adopt_dialect(
                Some(dialect.as_ref()),
                &crate::facts::reasoning::RecognitionOnly,
            );
            assert_ne!(cell(), before);
            drop(adopted);
            assert_eq!(cell(), before);
            assert_eq!(dialect_scope_depth(), 0);
        });
    }

    #[test]
    fn an_outermost_scope_whose_hold_panics_leaves_the_folding_cell_as_it_found_it() {
        on_a_fresh_thread(|| {
            let before = cell();
            let outermost = enter_dialect_scope("postgresql");
            hold_in_dialect_scope(outermost, Box::new(PanicsOnDrop));
            let unwound = catch_unwind(|| leave_dialect_scope(outermost));
            assert!(unwound.is_err());
            assert_eq!(cell(), before);
            assert_eq!(dialect_scope_depth(), 0);
        });
    }
}
