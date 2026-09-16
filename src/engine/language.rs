//! Bundled tree-sitter grammar bindings.
//!
//! `build.rs` namespaces each grammar and its external scanner so downstream
//! applications can also link the upstream crates without symbol collisions.

use tree_sitter_language::LanguageFn;

extern "C" {
    fn foxguard_tree_sitter_bash() -> *const ();
    fn foxguard_tree_sitter_c() -> *const ();
    fn foxguard_tree_sitter_javascript() -> *const ();
    fn foxguard_tree_sitter_typescript() -> *const ();
    fn foxguard_tree_sitter_tsx() -> *const ();
}

/// The tree-sitter [`LanguageFn`] for our patched Bash grammar.
// SAFETY: this generated C entry point returns the immutable, static grammar
// descriptor expected by LanguageFn; build.rs namespaces it without changing ABI.
pub(crate) const BASH_LANGUAGE: LanguageFn =
    unsafe { LanguageFn::from_raw(foxguard_tree_sitter_bash) };

// SAFETY: each generated entry point returns an immutable static grammar
// descriptor with the same ABI as the upstream tree-sitter binding.
pub(crate) const C_LANGUAGE: LanguageFn = unsafe { LanguageFn::from_raw(foxguard_tree_sitter_c) };
pub(crate) const JAVASCRIPT_LANGUAGE: LanguageFn =
    unsafe { LanguageFn::from_raw(foxguard_tree_sitter_javascript) };
pub(crate) const TYPESCRIPT_LANGUAGE: LanguageFn =
    unsafe { LanguageFn::from_raw(foxguard_tree_sitter_typescript) };
pub(crate) const TSX_LANGUAGE: LanguageFn =
    unsafe { LanguageFn::from_raw(foxguard_tree_sitter_tsx) };
