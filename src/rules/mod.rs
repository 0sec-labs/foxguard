pub mod common;
pub mod config;
pub mod cross_file;
pub mod csharp;
pub mod go;
pub mod go_taint;
pub mod java;
pub mod javascript;
pub mod javascript_taint;
pub mod kotlin;
pub mod manifest;
pub mod php;
pub mod python;
pub mod python_aliases;
pub mod python_taint;
pub mod ruby;
pub mod rust_lang;
pub mod semgrep_compat;
pub mod semgrep_taint;
pub mod swift;
pub mod taint_engine;

use crate::{Finding, Language, Severity};
use std::path::Path;

/// Macro to reduce boilerplate in `impl Rule for …` blocks.
///
/// # Variant 1 — rules that only implement `check`:
///
/// ```ignore
/// impl_rule! {
///     SomeRule,
///     id = "py/some-rule",
///     severity = Severity::High,
///     cwe = Some("CWE-123"),
///     description = "Some description",
///     language = Language::Python,
///     fn check(&self, source, tree) {
///         // …body using `self`, `source`, `tree`…
///     }
/// }
/// ```
///
/// # Variant 2 — rules that implement `check_with_context` (auto-generates
///   a delegating `check`):
///
/// ```ignore
/// impl_rule! {
///     SomeRule,
///     id = "py/some-rule",
///     severity = Severity::High,
///     cwe = Some("CWE-123"),
///     description = "Some description",
///     language = Language::Python,
///     fn check_with_context(&self, source, tree, ctx) {
///         // …body using `self`, `source`, `tree`, `ctx`…
///     }
/// }
/// ```
#[macro_export]
macro_rules! impl_rule {
    // ── Variant 1: check only ──────────────────────────────────────────────
    (
        $struct:ty,
        id = $id:expr,
        severity = $sev:expr,
        cwe = $cwe:expr,
        description = $desc:expr,
        language = $lang:expr,
        fn check($self_:ident, $src:ident, $tree:ident) { $($check_body:tt)* }
    ) => {
        impl $crate::rules::Rule for $struct {
            fn id(&self) -> &str { $id }
            fn severity(&self) -> $crate::Severity { $sev }
            fn cwe(&self) -> Option<&str> { $cwe }
            fn description(&self) -> &str { $desc }
            fn language(&self) -> $crate::Language { $lang }
            fn check(&self, $src: &str, $tree: &tree_sitter::Tree) -> Vec<$crate::Finding> {
                let $self_ = self;
                $($check_body)*
            }
        }
    };

    // ── Variant 1b: check only, with cnsa2_deadline ──────────────────────
    (
        $struct:ty,
        id = $id:expr,
        severity = $sev:expr,
        cwe = $cwe:expr,
        description = $desc:expr,
        language = $lang:expr,
        cnsa2_deadline = $deadline:expr,
        fn check($self_:ident, $src:ident, $tree:ident) { $($check_body:tt)* }
    ) => {
        impl $crate::rules::Rule for $struct {
            fn id(&self) -> &str { $id }
            fn severity(&self) -> $crate::Severity { $sev }
            fn cwe(&self) -> Option<&str> { $cwe }
            fn description(&self) -> &str { $desc }
            fn language(&self) -> $crate::Language { $lang }
            fn cnsa2_deadline(&self) -> Option<&'static str> { Some($deadline) }
            fn check(&self, $src: &str, $tree: &tree_sitter::Tree) -> Vec<$crate::Finding> {
                let $self_ = self;
                $($check_body)*
            }
        }
    };

    // ── Variant 2: check_with_context (auto-generates delegating check) ──
    (
        $struct:ty,
        id = $id:expr,
        severity = $sev:expr,
        cwe = $cwe:expr,
        description = $desc:expr,
        language = $lang:expr,
        fn check_with_context($self_:ident, $src:ident, $tree:ident, $ctx:ident) { $($check_body:tt)* }
    ) => {
        impl $crate::rules::Rule for $struct {
            fn id(&self) -> &str { $id }
            fn severity(&self) -> $crate::Severity { $sev }
            fn cwe(&self) -> Option<&str> { $cwe }
            fn description(&self) -> &str { $desc }
            fn language(&self) -> $crate::Language { $lang }
            fn check(&self, source: &str, tree: &tree_sitter::Tree) -> Vec<$crate::Finding> {
                self.check_with_context(source, tree, &$crate::rules::FileContext::default())
            }
            fn check_with_context(
                &self,
                $src: &str,
                $tree: &tree_sitter::Tree,
                $ctx: &$crate::rules::FileContext<'_>,
            ) -> Vec<$crate::Finding> {
                let $self_ = self;
                $($check_body)*
            }
        }
    };

    // ── Variant 2b: check_with_context, with cnsa2_deadline ──────────────
    (
        $struct:ty,
        id = $id:expr,
        severity = $sev:expr,
        cwe = $cwe:expr,
        description = $desc:expr,
        language = $lang:expr,
        cnsa2_deadline = $deadline:expr,
        fn check_with_context($self_:ident, $src:ident, $tree:ident, $ctx:ident) { $($check_body:tt)* }
    ) => {
        impl $crate::rules::Rule for $struct {
            fn id(&self) -> &str { $id }
            fn severity(&self) -> $crate::Severity { $sev }
            fn cwe(&self) -> Option<&str> { $cwe }
            fn description(&self) -> &str { $desc }
            fn language(&self) -> $crate::Language { $lang }
            fn cnsa2_deadline(&self) -> Option<&'static str> { Some($deadline) }
            fn check(&self, source: &str, tree: &tree_sitter::Tree) -> Vec<$crate::Finding> {
                self.check_with_context(source, tree, &$crate::rules::FileContext::default())
            }
            fn check_with_context(
                &self,
                $src: &str,
                $tree: &tree_sitter::Tree,
                $ctx: &$crate::rules::FileContext<'_>,
            ) -> Vec<$crate::Finding> {
                let $self_ = self;
                $($check_body)*
            }
        }
    };
}

/// Per-file analysis context shared across all rules running on a single file.
///
/// Computed once after parsing in the scanner and handed to each rule via
/// `check_with_context`. Rules that need nothing from it can continue to
/// implement `check` directly and rely on the default trait method.
#[derive(Default)]
pub struct FileContext<'a> {
    /// Python import alias table. `None` for non-Python files.
    pub python_aliases: Option<&'a common::AliasTable>,
    /// JavaScript/TypeScript import alias table. `None` for non-JS files.
    pub javascript_aliases: Option<&'a common::AliasTable>,
    /// Go import alias table. `None` for non-Go files.
    pub go_aliases: Option<&'a common::AliasTable>,
    /// Cross-file taint summaries from pass 1. Keyed by canonical file path.
    /// `None` when cross-file analysis is not available (e.g. single-file scan).
    pub cross_file_summaries: Option<&'a cross_file::CrossFileSummaryMap>,
    /// Python import-to-file-path resolution map for the current file.
    /// Maps local import names to resolved file paths on disk.
    pub python_import_paths: Option<&'a std::collections::HashMap<String, std::path::PathBuf>>,
    /// JavaScript import-to-file-path resolution map for the current file.
    /// Maps local import names / module specifiers to resolved file paths on disk.
    pub javascript_import_paths: Option<&'a std::collections::HashMap<String, std::path::PathBuf>>,
    /// Go same-package file paths. All `.go` files in the same directory
    /// share the same package and can call each other's functions.
    /// Excludes the current file itself.
    pub go_same_package_paths: Option<Vec<std::path::PathBuf>>,
}

/// A security rule that checks parsed source code for vulnerabilities.
pub trait Rule: Send + Sync {
    fn id(&self) -> &str;
    fn severity(&self) -> Severity;
    fn cwe(&self) -> Option<&str>;
    fn description(&self) -> &str;
    fn language(&self) -> Language;
    fn applies_to_path(&self, _path: &Path) -> bool {
        true
    }
    fn check(&self, source: &str, tree: &tree_sitter::Tree) -> Vec<Finding>;

    /// Context-aware variant. Defaults to calling `check` so every existing
    /// rule works unchanged. Rules that need the per-file context (e.g.
    /// Python import aliases) override this instead of `check`.
    fn check_with_context(
        &self,
        source: &str,
        tree: &tree_sitter::Tree,
        _ctx: &FileContext<'_>,
    ) -> Vec<Finding> {
        self.check(source, tree)
    }

    /// Apply per-rule options from config. Rules that support tuning override
    /// this to parse their options from the YAML value. Returns an error
    /// message if the options are invalid.
    fn configure(&mut self, _opts: &serde_yaml::Value) -> Result<(), String> {
        Ok(())
    }

    /// CNSA 2.0 transition deadline for findings from this rule, as a
    /// `"YYYY"` string (e.g. `"2030"`, `"2033"`), or `None` for rules that
    /// are not quantum-related. Consumed by [`crate::compliance`] at
    /// finding emission / post-processing time to populate
    /// `Finding.cnsa2_deadline`. See that module for the per-class
    /// mapping and NSA source citations. Rules must declare their own
    /// deadline via the `cnsa2_deadline = "..."` arm of [`impl_rule!`]
    /// so this trait stays the single source of truth (no substring
    /// matching on rule IDs in a central module — see PR #231 review).
    fn cnsa2_deadline(&self) -> Option<&'static str> {
        None
    }
}

/// Registry holding all available rules.
pub struct RuleRegistry {
    rules: Vec<Box<dyn Rule>>,
    /// Rule IDs that are opt-in only (not active unless explicitly enabled).
    opt_in_ids: std::collections::HashSet<String>,
}

impl Default for RuleRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl RuleRegistry {
    pub fn empty() -> Self {
        Self {
            rules: Vec::new(),
            opt_in_ids: std::collections::HashSet::new(),
        }
    }

    pub fn new() -> Self {
        let mut registry = Self::empty();

        // Register JavaScript rules
        registry.register(Box::new(javascript::NoEval));
        registry.register(Box::new(javascript::NoHardcodedSecret));
        registry.register(Box::new(javascript::NoSqlInjection));
        registry.register(Box::new(javascript::NoXssInnerHtml));
        registry.register(Box::new(javascript::NoCommandInjection));
        registry.register(Box::new(javascript::NoDocumentWrite));
        registry.register(Box::new(javascript::NoOpenRedirect));
        registry.register(Box::new(javascript::NoWeakCrypto));
        registry.register(Box::new(javascript::PqVulnerableCrypto));
        registry.register(Box::new(javascript::NoPathTraversal));
        registry.register(Box::new(javascript::NoSsrf));
        registry.register(Box::new(javascript::NoPrototypePollution));
        registry.register(Box::new(javascript::NoUnsafeRegex));
        registry.register(Box::new(javascript::NoCorsStar));
        registry.register(Box::new(javascript::ExpressNoHardcodedSessionSecret));
        registry.register(Box::new(javascript::ExpressCookieNoSecure));
        registry.register(Box::new(javascript::ExpressCookieNoHttpOnly));
        registry.register(Box::new(javascript::ExpressCookieNoSameSite));
        registry.register(Box::new(javascript::ExpressSessionSaveUninitializedTrue));
        registry.register(Box::new(javascript::ExpressSessionResaveTrue));
        registry.register(Box::new(javascript::ExpressDirectResponseWrite));
        registry.register(Box::new(javascript::JwtHardcodedSecret));
        registry.register(Box::new(javascript::JwtNoneAlgorithm));
        registry.register(Box::new(javascript::JwtIgnoreExpiration));
        registry.register(Box::new(javascript::JwtDecodeWithoutVerify));
        registry.register(Box::new(javascript::JwtVerifyMissingAlgorithms));
        registry.register(Box::new(javascript::NoUnsafeFormatString));
        registry.register(Box::new(javascript::TaintXssInnerHtml));
        registry.register(Box::new(javascript::TaintSqlInjection));
        registry.register(Box::new(javascript::TaintEval));
        registry.register(Box::new(javascript::TaintCommandInjection));
        registry.register(Box::new(javascript::TaintSsrf));
        registry.register(Box::new(javascript::TaintSsti));
        registry.register(Box::new(javascript::TaintXpathInjection));
        registry.register(Box::new(javascript::TaintLdapInjection));
        registry.register(Box::new(javascript::TaintLogInjection));
        registry.register(Box::new(javascript::TaintXxe));
        registry.register(Box::new(javascript::NoUnsafeDeserialization));
        registry.register_opt_in(Box::new(javascript::HardcodedCryptoAlgorithm));
        registry.register(Box::new(javascript::TaintNosqlInjection));

        // Register Python rules
        registry.register(Box::new(python::NoEval));
        registry.register(Box::new(python::NoHardcodedSecret));
        registry.register(Box::new(python::NoSqlInjection));
        registry.register(Box::new(python::NoCommandInjection));
        registry.register(Box::new(python::NoPathTraversal));
        registry.register(Box::new(python::NoSsrf));
        registry.register(Box::new(python::NoWeakCrypto));
        registry.register(Box::new(python::PqVulnerableCrypto));
        registry.register(Box::new(python::NoPickle));
        registry.register(Box::new(python::NoYamlLoad));
        registry.register(Box::new(python::NoDebugTrue));
        registry.register(Box::new(python::NoOpenRedirect));
        registry.register(Box::new(python::NoCorsStar));
        registry.register(Box::new(python::FlaskDebugMode));
        registry.register(Box::new(python::DjangoSecretKeyHardcoded));
        registry.register(Box::new(python::FlaskSecretKeyHardcoded));
        registry.register(Box::new(python::SessionCookieSecureDisabled));
        registry.register(Box::new(python::SessionCookieHttpOnlyDisabled));
        registry.register(Box::new(python::SessionCookieSameSiteDisabled));
        registry.register(Box::new(python::CsrfCookieSecureDisabled));
        registry.register(Box::new(python::CsrfCookieHttpOnlyDisabled));
        registry.register(Box::new(python::CsrfCookieSameSiteDisabled));
        registry.register(Box::new(python::CsrfExempt));
        registry.register(Box::new(python::WtfCsrfDisabled));
        registry.register(Box::new(python::WtfCsrfCheckDefaultDisabled));
        registry.register(Box::new(python::DjangoAllowedHostsWildcard));
        registry.register(Box::new(python::SecureSslRedirectDisabled));
        registry.register(Box::new(python::TaintPickleDeserialization));
        registry.register(Box::new(python::TaintEvalFromRequest));
        registry.register(Box::new(python::TaintCommandInjectionFromRequest));
        registry.register(Box::new(python::TaintSsrfFromRequest));
        registry.register(Box::new(python::TaintYamlLoadFromRequest));
        registry.register(Box::new(python::TaintSqlInjectionFromRequest));
        registry.register(Box::new(python::TaintSsti));
        registry.register(Box::new(python::TaintXpathInjection));
        registry.register(Box::new(python::TaintLdapInjection));
        registry.register(Box::new(python::TaintLogInjection));
        registry.register(Box::new(python::TaintXxe));
        registry.register(Box::new(python::JwtNoVerify));
        registry.register(Box::new(python::JwtHardcodedSecret));
        registry.register_opt_in(Box::new(python::HardcodedCryptoAlgorithm));
        registry.register(Box::new(python::TaintNosqlInjection));

        // Register Go rules
        registry.register(Box::new(go::NoSqlInjection));
        registry.register(Box::new(go::NoCommandInjection));
        registry.register(Box::new(go::NoHardcodedSecret));
        registry.register(Box::new(go::NoWeakCrypto));
        registry.register(Box::new(go::PqVulnerableCrypto));
        registry.register(Box::new(go::NoSsrf));
        registry.register(Box::new(go::InsecureTlsSkipVerify));
        registry.register(Box::new(go::GinNoTrustedProxies));
        registry.register(Box::new(go::NetHttpNoTimeout));
        registry.register(Box::new(go::TaintCommandInjection));
        registry.register(Box::new(go::TaintSqlInjection));
        registry.register(Box::new(go::TaintSsrf));
        registry.register(Box::new(go::TaintSsti));
        registry.register(Box::new(go::TaintXpathInjection));
        registry.register(Box::new(go::TaintLdapInjection));
        registry.register(Box::new(go::TaintLogInjection));
        registry.register(Box::new(go::NoUnsafeDeserialization));
        registry.register(Box::new(go::JwtNoVerify));
        registry.register(Box::new(go::JwtHardcodedSecret));
        registry.register(Box::new(go::TaintNosqlInjection));
        registry.register(Box::new(go::TaintPathTraversal));

        // Register Java rules
        registry.register(Box::new(java::NoSqlInjection));
        registry.register(Box::new(java::NoCommandInjection));
        registry.register(Box::new(java::NoUnsafeDeserialization));
        registry.register(Box::new(java::NoSsrf));
        registry.register(Box::new(java::NoPathTraversal));
        registry.register(Box::new(java::NoWeakCrypto));
        registry.register(Box::new(java::PqVulnerableCrypto));
        registry.register(Box::new(java::NoHardcodedSecret));
        registry.register(Box::new(java::NoXxe));
        registry.register(Box::new(java::SpringCsrfDisabled));
        registry.register(Box::new(java::SpringCorsPermissive));
        registry.register(Box::new(java::NoXss));
        registry.register_opt_in(Box::new(java::HardcodedCryptoAlgorithm));

        // Register PHP rules
        registry.register(Box::new(php::NoEval));
        registry.register(Box::new(php::NoCommandInjection));
        registry.register(Box::new(php::NoSqlInjection));
        registry.register(Box::new(php::NoUnserialize));
        registry.register(Box::new(php::NoFileInclusion));
        registry.register(Box::new(php::NoWeakCrypto));
        registry.register(Box::new(php::NoHardcodedSecret));
        registry.register(Box::new(php::NoSsrf));
        registry.register(Box::new(php::NoExtract));
        registry.register(Box::new(php::NoPregEval));

        // Register Ruby rules
        registry.register(Box::new(ruby::NoEval));
        registry.register(Box::new(ruby::NoCommandInjection));
        registry.register(Box::new(ruby::NoSqlInjection));
        registry.register(Box::new(ruby::NoMassAssignment));
        registry.register(Box::new(ruby::NoUnsafeDeserialization));
        registry.register(Box::new(ruby::NoOpenRedirect));
        registry.register(Box::new(ruby::NoCsrfSkip));
        registry.register(Box::new(ruby::NoHtmlSafe));
        registry.register(Box::new(ruby::NoHardcodedSecret));
        registry.register(Box::new(ruby::NoWeakCrypto));
        registry.register(Box::new(ruby::NoSsrf));
        registry.register(Box::new(ruby::NoPathTraversal));

        // Register C# rules
        registry.register(Box::new(csharp::NoSqlInjection));
        registry.register(Box::new(csharp::NoCommandInjection));
        registry.register(Box::new(csharp::NoUnsafeDeserialization));
        registry.register(Box::new(csharp::NoSsrf));
        registry.register(Box::new(csharp::NoPathTraversal));
        registry.register(Box::new(csharp::NoWeakCrypto));
        registry.register(Box::new(csharp::NoHardcodedSecret));
        registry.register(Box::new(csharp::NoXxe));
        registry.register(Box::new(csharp::NoLdapInjection));
        registry.register(Box::new(csharp::NoCorsStar));

        // Register Swift rules
        registry.register(Box::new(swift::NoHardcodedSecret));
        registry.register(Box::new(swift::NoCommandInjection));
        registry.register(Box::new(swift::NoWeakCrypto));
        registry.register(Box::new(swift::NoInsecureTransport));
        registry.register(Box::new(swift::NoEvalJs));
        registry.register(Box::new(swift::NoSqlInjection));
        registry.register(Box::new(swift::NoInsecureKeychain));
        registry.register(Box::new(swift::NoTlsDisabled));
        registry.register(Box::new(swift::NoPathTraversal));
        registry.register(Box::new(swift::NoSsrf));

        // Register Kotlin rules
        registry.register(Box::new(kotlin::NoSqlInjection));
        registry.register(Box::new(kotlin::NoCommandInjection));
        registry.register(Box::new(kotlin::NoUnsafeDeserialization));
        registry.register(Box::new(kotlin::NoSsrf));
        registry.register(Box::new(kotlin::NoPathTraversal));
        registry.register(Box::new(kotlin::NoWeakCrypto));
        registry.register(Box::new(kotlin::NoHardcodedSecret));
        registry.register(Box::new(kotlin::NoXxe));
        registry.register(Box::new(kotlin::NoCorsStar));
        registry.register(Box::new(kotlin::NoEval));
        registry.register(Box::new(kotlin::TaintSqlInjection));
        registry.register(Box::new(kotlin::TaintCommandInjection));
        registry.register(Box::new(kotlin::TaintSsrf));

        // Register Rust rules
        registry.register(Box::new(rust_lang::UnsafeBlock));
        registry.register(Box::new(rust_lang::TransmuteUsage));
        registry.register(Box::new(rust_lang::NoCommandInjection));
        registry.register(Box::new(rust_lang::NoSqlInjection));
        registry.register(Box::new(rust_lang::NoWeakHash));
        registry.register(Box::new(rust_lang::PqVulnerableCrypto));
        registry.register(Box::new(rust_lang::NoHardcodedSecret));
        registry.register(Box::new(rust_lang::TlsVerifyDisabled));
        registry.register(Box::new(rust_lang::NoSsrf));
        registry.register(Box::new(rust_lang::NoPathTraversal));
        registry.register(Box::new(rust_lang::NoUnwrapInLib));

        // Register config file rules
        registry.register(Box::new(config::NginxPqVulnerableTls));
        registry.register(Box::new(config::ApachePqVulnerableTls));
        registry.register(Box::new(config::HAProxyPqVulnerableTls));
        registry.register(Box::new(config::DockerfileInsecureTlsEnv));

        // Register manifest rules (dependency-level PQ scanning)
        registry.register(Box::new(manifest::CargoLockPqCrypto));
        registry.register(Box::new(manifest::RequirementsTxtPqCrypto));

        registry
    }

    pub fn register(&mut self, rule: Box<dyn Rule>) {
        self.rules.push(rule);
    }

    /// Register a rule that is opt-in only (not active by default).
    /// Users enable it via `scan.enable_rules` in config.
    pub fn register_opt_in(&mut self, rule: Box<dyn Rule>) {
        self.opt_in_ids.insert(rule.id().to_string());
        self.rules.push(rule);
    }

    pub fn rules_for_language(&self, language: Language) -> Vec<&dyn Rule> {
        self.rules
            .iter()
            .filter(|r| r.language() == language)
            .map(|r| r.as_ref())
            .collect()
    }

    /// Apply per-rule options from config. Warns on stderr for unknown rule IDs
    /// and returns errors for invalid option values.
    pub fn configure_rules(
        &mut self,
        rule_options: &std::collections::HashMap<String, serde_yaml::Value>,
    ) -> Result<Vec<String>, String> {
        let mut warnings = Vec::new();
        for (rule_id, opts) in rule_options {
            let Some(rule) = self.rules.iter_mut().find(|r| r.id() == rule_id) else {
                warnings.push(format!("rule_options: unknown rule '{}'", rule_id));
                continue;
            };
            rule.configure(opts)
                .map_err(|e| format!("rule_options: invalid config for '{}': {}", rule_id, e))?;
        }
        Ok(warnings)
    }

    #[allow(dead_code)]
    pub fn all_rules(&self) -> &[Box<dyn Rule>] {
        &self.rules
    }

    /// Apply `scan.enable_rules` (allowlist) and `scan.disable_rules`
    /// (denylist) from the loaded config to the active rule set.
    ///
    /// Semantics:
    /// - If `enable` is non-empty, only rules whose id is in `enable` are
    ///   retained (intersection with the full registry).
    /// - If `disable` is non-empty, rules whose id is in `disable` are
    ///   removed. Applied after `enable`, so IDs appearing in both lists
    ///   are disabled.
    /// - Both empty → no change.
    ///
    /// Returns the set of IDs from `enable` or `disable` that do not
    /// correspond to any registered rule. Callers should surface these
    /// as a single warning so users catch typos without failing the scan.
    pub fn apply_rule_filter(&mut self, enable: &[String], disable: &[String]) -> Vec<String> {
        self.apply_rule_filter_with_known(enable, disable, &std::collections::HashSet::new())
    }

    pub fn apply_rule_filter_with_known(
        &mut self,
        enable: &[String],
        disable: &[String],
        additional_known: &std::collections::HashSet<String>,
    ) -> Vec<String> {
        let known: std::collections::HashSet<&str> = self.rules.iter().map(|r| r.id()).collect();

        let mut unknown: Vec<String> = Vec::new();
        let mut seen_unknown: std::collections::HashSet<&str> = std::collections::HashSet::new();
        for id in enable.iter().chain(disable.iter()) {
            if !known.contains(id.as_str())
                && !additional_known.contains(id.as_str())
                && seen_unknown.insert(id.as_str())
            {
                unknown.push(id.clone());
            }
        }

        if !enable.is_empty() {
            // Explicit allowlist: keep only these rules (overrides opt-in).
            let enable_set: std::collections::HashSet<&str> =
                enable.iter().map(|s| s.as_str()).collect();
            self.rules.retain(|r| enable_set.contains(r.id()));
        } else {
            // No explicit allowlist: strip opt-in-only rules.
            self.rules.retain(|r| !self.opt_in_ids.contains(r.id()));
        }

        if !disable.is_empty() {
            let disable_set: std::collections::HashSet<&str> =
                disable.iter().map(|s| s.as_str()).collect();
            self.rules.retain(|r| !disable_set.contains(r.id()));
        }

        unknown
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[allow(dead_code)]
    fn rule_ids(registry: &RuleRegistry) -> Vec<String> {
        registry.rules.iter().map(|r| r.id().to_string()).collect()
    }

    fn has_rule(registry: &RuleRegistry, id: &str) -> bool {
        registry.rules.iter().any(|r| r.id() == id)
    }

    #[test]
    fn apply_rule_filter_strips_opt_in_when_both_lists_empty() {
        let mut registry = RuleRegistry::new();
        let before_count = registry.rules.len();
        let unknown = registry.apply_rule_filter(&[], &[]);
        assert!(unknown.is_empty());
        // Opt-in rules are stripped when no explicit enable list is given.
        assert!(registry.rules.len() < before_count);
        assert!(!has_rule(&registry, "js/hardcoded-crypto-algorithm"));
        assert!(!has_rule(&registry, "py/hardcoded-crypto-algorithm"));
        assert!(!has_rule(&registry, "java/hardcoded-crypto-algorithm"));
    }

    #[test]
    fn apply_rule_filter_allowlist_keeps_only_listed_ids() {
        let mut registry = RuleRegistry::new();
        let unknown =
            registry.apply_rule_filter(&["py/no-eval".to_string(), "js/no-eval".to_string()], &[]);
        assert!(unknown.is_empty());
        assert_eq!(registry.rules.len(), 2);
        assert!(has_rule(&registry, "py/no-eval"));
        assert!(has_rule(&registry, "js/no-eval"));
    }

    #[test]
    fn apply_rule_filter_denylist_removes_listed_ids() {
        let mut registry = RuleRegistry::new();
        let opt_in_count = registry.opt_in_ids.len();
        let before_count = registry.rules.len();
        let unknown = registry.apply_rule_filter(&[], &["py/no-eval".to_string()]);
        assert!(unknown.is_empty());
        // Denylist removes py/no-eval, and opt-in rules are also stripped.
        assert_eq!(registry.rules.len(), before_count - 1 - opt_in_count);
        assert!(!has_rule(&registry, "py/no-eval"));
    }

    #[test]
    fn apply_rule_filter_both_intersects_then_subtracts() {
        // enable = {py/no-eval, py/no-sql-injection}; disable = {py/no-eval}
        // Expected: only py/no-sql-injection remains.
        let mut registry = RuleRegistry::new();
        let unknown = registry.apply_rule_filter(
            &["py/no-eval".to_string(), "py/no-sql-injection".to_string()],
            &["py/no-eval".to_string()],
        );
        assert!(unknown.is_empty());
        assert_eq!(registry.rules.len(), 1);
        assert!(has_rule(&registry, "py/no-sql-injection"));
        assert!(!has_rule(&registry, "py/no-eval"));
    }

    #[test]
    fn apply_rule_filter_reports_unknown_rule_ids() {
        let mut registry = RuleRegistry::new();
        let unknown = registry.apply_rule_filter(
            &["py/no-eval".to_string(), "py/does-not-exist".to_string()],
            &["another/typo".to_string()],
        );
        assert_eq!(unknown.len(), 2);
        assert!(unknown.contains(&"py/does-not-exist".to_string()));
        assert!(unknown.contains(&"another/typo".to_string()));
        // Real rule still applies (allowlist kept py/no-eval, denylist had no matches).
        assert!(has_rule(&registry, "py/no-eval"));
    }

    #[test]
    fn apply_rule_filter_deduplicates_unknown_ids() {
        let mut registry = RuleRegistry::new();
        let unknown = registry.apply_rule_filter(
            &["py/typo".to_string(), "py/typo".to_string()],
            &["py/typo".to_string()],
        );
        assert_eq!(unknown, vec!["py/typo".to_string()]);
    }

    #[test]
    fn configure_rules_warns_on_unknown_rule_id() {
        let mut registry = RuleRegistry::new();
        let mut opts = std::collections::HashMap::new();
        opts.insert("py/does-not-exist".to_string(), serde_yaml::Value::Null);
        let warnings = registry.configure_rules(&opts).unwrap();
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("py/does-not-exist"));
    }

    #[test]
    fn configure_rules_no_warning_for_known_rule() {
        let mut registry = RuleRegistry::new();
        let mut opts = std::collections::HashMap::new();
        opts.insert("py/no-eval".to_string(), serde_yaml::Value::Null);
        let warnings = registry.configure_rules(&opts).unwrap();
        assert!(warnings.is_empty());
    }

    #[test]
    fn configure_rules_empty_options_is_no_op() {
        let mut registry = RuleRegistry::new();
        let opts = std::collections::HashMap::new();
        let warnings = registry.configure_rules(&opts).unwrap();
        assert!(warnings.is_empty());
    }
}
