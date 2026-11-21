//! Cooperative per-file analysis time budget.
//!
//! Analysis cannot be preempted, so the budget is enforced at the points where
//! the scanner can stop: during parsing (tree-sitter progress callback) and
//! between rule engines. A file that exceeds the budget at one of those points
//! is abandoned and reported as timed out. A single rule that never returns is
//! not interruptible.

use std::cell::Cell;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Default per-file budget in milliseconds.
pub const DEFAULT_FILE_TIMEOUT_SECS: u64 = 120;

static FILE_TIMEOUT_MS: AtomicU64 = AtomicU64::new(DEFAULT_FILE_TIMEOUT_SECS * 1000);

thread_local! {
    static DEADLINE: Cell<Option<Instant>> = const { Cell::new(None) };
}

/// Set the per-file budget used by subsequent scans. `None` disables it.
pub fn set_file_timeout(timeout: Option<Duration>) {
    let ms = timeout.map_or(0, |d| (d.as_millis() as u64).max(1));
    FILE_TIMEOUT_MS.store(ms, Ordering::Relaxed);
}

/// The currently configured per-file budget.
pub fn file_timeout() -> Option<Duration> {
    match FILE_TIMEOUT_MS.load(Ordering::Relaxed) {
        0 => None,
        ms => Some(Duration::from_millis(ms)),
    }
}

/// Installs a deadline for the current thread while alive.
pub(crate) struct FileBudgetGuard(Option<Instant>);

impl FileBudgetGuard {
    pub(crate) fn start(budget: Option<Duration>) -> Self {
        let previous = DEADLINE.with(|d| d.replace(budget.map(|b| Instant::now() + b)));
        Self(previous)
    }
}

impl Drop for FileBudgetGuard {
    fn drop(&mut self) {
        DEADLINE.with(|d| d.set(self.0));
    }
}

/// Whether the current thread's file budget is used up.
pub(crate) fn expired() -> bool {
    DEADLINE
        .with(|d| d.get())
        .is_some_and(|d| Instant::now() >= d)
}

pub(crate) fn has_deadline() -> bool {
    DEADLINE.with(|d| d.get()).is_some()
}
