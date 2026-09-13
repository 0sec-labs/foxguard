//! Bundled (patched) tree-sitter-bash grammar binding.
//!
//! The upstream crate v0.23.3 and v0.25.1 both lack the `<>` (LT_GT)
//! read-write redirect operator. This module exposes a patched grammar
//! compiled directly from `vendor/tree-sitter-bash/src/` via `build.rs`,
//! with all C symbols prefixed (`foxguard_tree_sitter_bash*`) so it never
//! collides with a potentially-linked upstream `tree-sitter-bash` crate.
//!
//! grammar.js change: added `'<>'` to the `file_redirect` rule's operator choice.

use tree_sitter_language::LanguageFn;

extern "C" {
    fn foxguard_tree_sitter_bash() -> *const ();
}

/// The tree-sitter [`LanguageFn`] for our patched Bash grammar.
// SAFETY: this generated C entry point returns the immutable, static grammar
// descriptor expected by LanguageFn; build.rs namespaces it without changing ABI.
pub(crate) const BASH_LANGUAGE: LanguageFn =
    unsafe { LanguageFn::from_raw(foxguard_tree_sitter_bash) };
