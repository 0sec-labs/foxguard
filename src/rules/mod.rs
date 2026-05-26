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
pub mod kotlin_taint;
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

/// YAML rule packs that ship inside the `foxguard` binary.
///
/// These are loaded by [`RuleRegistry::new`] on the same footing as the
/// hand-written Rust rules: no CLI flag required. The `queries/` subtrees
/// hold CodeQL `.ql` files and pack lockfiles that have nothing to do with
/// Semgrep matching, so they are skipped at load time (see
/// `walk_embedded_dir` in `semgrep_compat.rs`).
///
/// See `rules/README.md` for the on-disk layout.
static BUNDLED_RULES: include_dir::Dir<'_> = include_dir::include_dir!("$CARGO_MANIFEST_DIR/rules");

/// Languages with built-in taint specs wired into the scanner.
///
/// Taint support is intentionally narrower than syntax-only AST rules: each
/// language here has source/sink specs plus scanner dispatch in
/// `builtin_taint_specs_for_language` and `engine/scanner.rs`. When adding a
/// new taint-backed language, start with `docs/taint-tracking.md` so the
/// engine choice, source model, and sanitizer behavior stay consistent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaintEngine {
    Go,
    JavaScript,
    Kotlin,
    Python,
}

#[derive(Debug, Clone)]
pub struct RegistryTaintSpec {
    pub rule_id: &'static str,
    pub language: Language,
    pub engine: TaintEngine,
    pub spec: taint_engine::TaintSpec,
}

pub struct AnalysisPlan<'a> {
    pub ast_rules: Vec<&'a dyn Rule>,
    pub taint_specs: Vec<RegistryTaintSpec>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AstAnalysisRequirement {
    SyntaxTree,
    FileContext,
}

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
///
/// Optional declarative metadata:
///   * `cnsa2_deadline = "YYYY"` — sets [`Rule::cnsa2_deadline`] for
///     quantum-related rules.
///   * `applies_to_filename = "NAME"` — restricts the rule to files whose
///     basename equals `NAME` (e.g. `"Cargo.lock"`, `"requirements.txt"`).
///     Useful for manifest/lockfile rules that parse the source themselves
///     rather than relying on tree-sitter.
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

    // ── Variant 1c: check only, with cnsa2_deadline + applies_to_filename ──
    //
    // For rules that only fire on files with a specific basename (e.g.
    // `Cargo.lock`, `requirements.txt`). The check body typically ignores
    // the `tree` argument and parses `source` itself with a format-specific
    // parser (TOML, line-oriented, …). Use this arm instead of writing the
    // trait impl by hand so metadata (cwe, severity, cnsa2_deadline) stays
    // declarative and consistent with every other rule.
    (
        $struct:ty,
        id = $id:expr,
        severity = $sev:expr,
        cwe = $cwe:expr,
        description = $desc:expr,
        language = $lang:expr,
        cnsa2_deadline = $deadline:expr,
        applies_to_filename = $filename:expr,
        fn check($self_:ident, $src:ident, $tree:ident) { $($check_body:tt)* }
    ) => {
        impl $crate::rules::Rule for $struct {
            fn id(&self) -> &str { $id }
            fn severity(&self) -> $crate::Severity { $sev }
            fn cwe(&self) -> Option<&str> { $cwe }
            fn description(&self) -> &str { $desc }
            fn language(&self) -> $crate::Language { $lang }
            fn cnsa2_deadline(&self) -> Option<&'static str> { Some($deadline) }
            fn applies_to_path(&self, path: &std::path::Path) -> bool {
                path.file_name().and_then(|f| f.to_str()) == Some($filename)
            }
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
            fn ast_analysis_requirement(&self) -> $crate::rules::AstAnalysisRequirement {
                $crate::rules::AstAnalysisRequirement::FileContext
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
            fn ast_analysis_requirement(&self) -> $crate::rules::AstAnalysisRequirement {
                $crate::rules::AstAnalysisRequirement::FileContext
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

macro_rules! register_rules {
    ($registry:expr, [$($rule:path),+ $(,)?]) => {
        $(
            $registry.register(Box::new($rule));
        )+
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

    fn ast_analysis_requirement(&self) -> AstAnalysisRequirement {
        AstAnalysisRequirement::SyntaxTree
    }

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
    fn configure(&mut self, _opts: &serde_yaml_ng::Value) -> Result<(), String> {
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

        register_rules!(
            registry,
            [
                javascript::NoEval,
                javascript::NoHardcodedSecret,
                javascript::NoSqlInjection,
                javascript::NoXssInnerHtml,
                javascript::NoCommandInjection,
                javascript::NoDocumentWrite,
                javascript::NoOpenRedirect,
                javascript::NoWeakCrypto,
                javascript::PqVulnerableCrypto,
                javascript::NoPathTraversal,
                javascript::NoSsrf,
                javascript::NoPrototypePollution,
                javascript::NoUnsafeRegex,
                javascript::NoCorsStar,
                javascript::ExpressNoHardcodedSessionSecret,
                javascript::ExpressCookieNoSecure,
                javascript::ExpressCookieNoHttpOnly,
                javascript::ExpressCookieNoSameSite,
                javascript::ExpressSessionSaveUninitializedTrue,
                javascript::ExpressSessionResaveTrue,
                javascript::ExpressDirectResponseWrite,
                javascript::JwtHardcodedSecret,
                javascript::JwtNoneAlgorithm,
                javascript::JwtIgnoreExpiration,
                javascript::JwtDecodeWithoutVerify,
                javascript::JwtVerifyMissingAlgorithms,
                javascript::NoUnsafeFormatString,
                javascript::TaintXssInnerHtml,
                javascript::TaintSqlInjection,
                javascript::TaintEval,
                javascript::TaintCommandInjection,
                javascript::TaintSsrf,
                javascript::TaintSsti,
                javascript::TaintXpathInjection,
                javascript::TaintLdapInjection,
                javascript::TaintLogInjection,
                javascript::TaintXxe,
                javascript::NoUnsafeDeserialization,
            ]
        );
        registry.register_opt_in(Box::new(javascript::HardcodedCryptoAlgorithm));
        register_rules!(registry, [javascript::TaintNosqlInjection]);

        register_rules!(
            registry,
            [
                python::NoEval,
                python::NoHardcodedSecret,
                python::NoSqlInjection,
                python::NoCommandInjection,
                python::NoPathTraversal,
                python::NoSsrf,
                python::NoWeakCrypto,
                python::PqVulnerableCrypto,
                python::NoPickle,
                python::NoYamlLoad,
                python::NoDebugTrue,
                python::NoOpenRedirect,
                python::NoCorsStar,
                python::FlaskDebugMode,
                python::DjangoSecretKeyHardcoded,
                python::FlaskSecretKeyHardcoded,
                python::SessionCookieSecureDisabled,
                python::SessionCookieHttpOnlyDisabled,
                python::SessionCookieSameSiteDisabled,
                python::CsrfCookieSecureDisabled,
                python::CsrfCookieHttpOnlyDisabled,
                python::CsrfCookieSameSiteDisabled,
                python::CsrfExempt,
                python::WtfCsrfDisabled,
                python::WtfCsrfCheckDefaultDisabled,
                python::DjangoAllowedHostsWildcard,
                python::SecureSslRedirectDisabled,
                python::TaintPickleDeserialization,
                python::TaintEvalFromRequest,
                python::TaintCommandInjectionFromRequest,
                python::TaintSsrfFromRequest,
                python::TaintYamlLoadFromRequest,
                python::TaintSqlInjectionFromRequest,
                python::TaintSsti,
                python::TaintXpathInjection,
                python::TaintLdapInjection,
                python::TaintLogInjection,
                python::TaintXxe,
                python::JwtNoVerify,
                python::JwtHardcodedSecret,
            ]
        );
        registry.register_opt_in(Box::new(python::HardcodedCryptoAlgorithm));
        register_rules!(registry, [python::TaintNosqlInjection]);

        register_rules!(
            registry,
            [
                go::NoSqlInjection,
                go::NoCommandInjection,
                go::NoHardcodedSecret,
                go::NoWeakCrypto,
                go::PqVulnerableCrypto,
                go::NoSsrf,
                go::InsecureTlsSkipVerify,
                go::MissingSslMinVersion,
                go::CookieMissingSecure,
                go::CookieMissingHttpOnly,
                go::MathRandomUsed,
                go::GinNoTrustedProxies,
                go::NetHttpNoTimeout,
                go::TaintCommandInjection,
                go::TaintSqlInjection,
                go::TaintSsrf,
                go::TaintSsti,
                go::TaintXpathInjection,
                go::TaintLdapInjection,
                go::TaintLogInjection,
                go::NoUnsafeDeserialization,
                go::JwtNoVerify,
                go::JwtHardcodedSecret,
                go::TaintNosqlInjection,
                go::TaintPathTraversal,
            ]
        );

        register_rules!(
            registry,
            [
                java::NoSqlInjection,
                java::NoCommandInjection,
                java::NoUnsafeDeserialization,
                java::NoSsrf,
                java::NoPathTraversal,
                java::NoWeakCrypto,
                java::PqVulnerableCrypto,
                java::NoHardcodedSecret,
                java::NoXxe,
                java::SpringCsrfDisabled,
                java::SpringCorsPermissive,
                java::NoXss,
            ]
        );
        registry.register_opt_in(Box::new(java::HardcodedCryptoAlgorithm));

        register_rules!(
            registry,
            [
                php::NoEval,
                php::NoCommandInjection,
                php::NoSqlInjection,
                php::NoUnserialize,
                php::NoFileInclusion,
                php::NoWeakCrypto,
                php::NoHardcodedSecret,
                php::NoSsrf,
                php::NoExtract,
                php::NoPregEval,
            ]
        );

        register_rules!(
            registry,
            [
                ruby::NoEval,
                ruby::NoCommandInjection,
                ruby::NoSqlInjection,
                ruby::NoMassAssignment,
                ruby::NoUnsafeDeserialization,
                ruby::NoOpenRedirect,
                ruby::NoCsrfSkip,
                ruby::NoHtmlSafe,
                ruby::NoHardcodedSecret,
                ruby::NoWeakCrypto,
                ruby::NoSsrf,
                ruby::NoPathTraversal,
            ]
        );

        register_rules!(
            registry,
            [
                csharp::NoSqlInjection,
                csharp::NoCommandInjection,
                csharp::NoUnsafeDeserialization,
                csharp::NoSsrf,
                csharp::NoPathTraversal,
                csharp::NoWeakCrypto,
                csharp::NoHardcodedSecret,
                csharp::NoXxe,
                csharp::NoLdapInjection,
                csharp::NoCorsStar,
            ]
        );

        register_rules!(
            registry,
            [
                swift::NoHardcodedSecret,
                swift::NoCommandInjection,
                swift::NoWeakCrypto,
                swift::NoInsecureTransport,
                swift::NoEvalJs,
                swift::NoSqlInjection,
                swift::NoInsecureKeychain,
                swift::NoTlsDisabled,
                swift::NoPathTraversal,
                swift::NoSsrf,
            ]
        );

        register_rules!(
            registry,
            [
                kotlin::NoSqlInjection,
                kotlin::NoCommandInjection,
                kotlin::NoUnsafeDeserialization,
                kotlin::NoSsrf,
                kotlin::NoPathTraversal,
                kotlin::NoWeakCrypto,
                kotlin::NoHardcodedSecret,
                kotlin::NoXxe,
                kotlin::NoCorsStar,
                kotlin::NoEval,
                kotlin::TaintSqlInjection,
                kotlin::TaintCommandInjection,
                kotlin::TaintSsrf,
            ]
        );

        register_rules!(
            registry,
            [
                rust_lang::UnsafeBlock,
                rust_lang::TransmuteUsage,
                rust_lang::NoCommandInjection,
                rust_lang::NoSqlInjection,
                rust_lang::NoWeakHash,
                rust_lang::PqVulnerableCrypto,
                rust_lang::NoHardcodedSecret,
                rust_lang::TlsVerifyDisabled,
                rust_lang::NoSsrf,
                rust_lang::NoPathTraversal,
                rust_lang::NoUnwrapInLib,
            ]
        );

        register_rules!(
            registry,
            [
                config::NginxPqVulnerableTls,
                config::ApachePqVulnerableTls,
                config::HAProxyPqVulnerableTls,
                config::DockerfileInsecureTlsEnv,
                manifest::CargoLockPqCrypto,
                manifest::RequirementsTxtPqCrypto,
                manifest::PoetryLockPqCrypto,
                manifest::PipfileLockPqCrypto,
                manifest::PnpmLockPqCrypto,
                manifest::PackageLockPqCrypto,
            ]
        );

        // Register bundled YAML rule packs (currently the kernel
        // dirty-frag-class pack). These ship inside the binary via the
        // `include_dir!` blob above; they are treated as built-in rules so
        // `--no-builtins` suppresses them too. Users who want the kernel
        // pack but not the Rust rules can lean on `--rules <path>` against
        // an external clone — `--no-builtins` means "no foxguard-shipped
        // rules at all".
        for rule in semgrep_compat::load_semgrep_rules_from_embedded(&BUNDLED_RULES) {
            registry.register(rule);
        }

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

    pub fn taint_specs_for_language(&self, language: Language) -> Vec<RegistryTaintSpec> {
        let enabled_rule_ids: std::collections::HashSet<&str> = self
            .rules
            .iter()
            .filter(|rule| rule.language() == language)
            .map(|rule| rule.id())
            .collect();

        builtin_taint_specs_for_language(language)
            .into_iter()
            .filter(|spec| enabled_rule_ids.contains(spec.rule_id))
            .collect()
    }

    pub fn analysis_plan_for_path<'a>(
        &'a self,
        language: Language,
        path: &Path,
    ) -> AnalysisPlan<'a> {
        let taint_specs = self.taint_specs_for_language(language);
        let taint_rule_ids: std::collections::HashSet<&str> =
            taint_specs.iter().map(|spec| spec.rule_id).collect();

        let ast_rules = self
            .rules
            .iter()
            .filter(|rule| {
                rule.language() == language
                    && rule.applies_to_path(path)
                    && !taint_rule_ids.contains(rule.id())
            })
            .map(|rule| rule.as_ref())
            .collect();

        let taint_specs = taint_specs
            .into_iter()
            .filter(|spec| {
                self.rules.iter().any(|rule| {
                    rule.id() == spec.rule_id
                        && rule.language() == language
                        && rule.applies_to_path(path)
                })
            })
            .collect();

        AnalysisPlan {
            ast_rules,
            taint_specs,
        }
    }

    /// Apply per-rule options from config. Warns on stderr for unknown rule IDs
    /// and returns errors for invalid option values.
    pub fn configure_rules(
        &mut self,
        rule_options: &std::collections::HashMap<String, serde_yaml_ng::Value>,
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

fn builtin_taint_specs_for_language(language: Language) -> Vec<RegistryTaintSpec> {
    match language {
        Language::Go => go::go_taint_rule_specs()
            .into_iter()
            .map(|(rule_id, spec)| RegistryTaintSpec {
                rule_id,
                language,
                engine: TaintEngine::Go,
                spec,
            })
            .collect(),
        Language::JavaScript => javascript::js_taint_rule_specs()
            .into_iter()
            .map(|(rule_id, spec)| RegistryTaintSpec {
                rule_id,
                language,
                engine: TaintEngine::JavaScript,
                spec,
            })
            .collect(),
        Language::Python => python::python_taint_rule_specs()
            .into_iter()
            .map(|(rule_id, spec)| RegistryTaintSpec {
                rule_id,
                language,
                engine: TaintEngine::Python,
                spec,
            })
            .collect(),
        Language::Kotlin => kotlin_taint::kotlin_taint_rule_specs()
            .into_iter()
            .map(|(rule_id, spec)| RegistryTaintSpec {
                rule_id,
                language,
                engine: TaintEngine::Kotlin,
                spec,
            })
            .collect(),
        _ => Vec::new(),
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
    fn registry_exposes_enabled_taint_specs() {
        let mut registry = RuleRegistry::new();
        let unknown = registry.apply_rule_filter(
            &[
                "py/taint-eval".to_string(),
                "py/taint-sql-injection".to_string(),
                "py/no-eval".to_string(),
            ],
            &[],
        );
        assert!(unknown.is_empty());

        let specs = registry.taint_specs_for_language(Language::Python);
        let ids: std::collections::BTreeSet<&str> = specs.iter().map(|spec| spec.rule_id).collect();
        assert_eq!(ids.len(), 2);
        assert!(ids.contains("py/taint-eval"));
        assert!(ids.contains("py/taint-sql-injection"));
        assert!(specs.iter().all(|spec| spec.language == Language::Python
            && spec.engine == TaintEngine::Python
            && !spec.spec.sinks.is_empty()));
    }

    #[test]
    fn analysis_plan_splits_taint_specs_from_ast_rules() {
        let mut registry = RuleRegistry::new();
        let unknown = registry.apply_rule_filter(
            &["py/taint-eval".to_string(), "py/no-eval".to_string()],
            &[],
        );
        assert!(unknown.is_empty());

        let plan = registry.analysis_plan_for_path(Language::Python, Path::new("app.py"));
        assert_eq!(plan.ast_rules.len(), 1);
        assert_eq!(plan.ast_rules[0].id(), "py/no-eval");
        assert_eq!(plan.taint_specs.len(), 1);
        assert_eq!(plan.taint_specs[0].rule_id, "py/taint-eval");
    }

    #[test]
    fn configure_rules_warns_on_unknown_rule_id() {
        let mut registry = RuleRegistry::new();
        let mut opts = std::collections::HashMap::new();
        opts.insert("py/does-not-exist".to_string(), serde_yaml_ng::Value::Null);
        let warnings = registry.configure_rules(&opts).unwrap();
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("py/does-not-exist"));
    }

    #[test]
    fn configure_rules_no_warning_for_known_rule() {
        let mut registry = RuleRegistry::new();
        let mut opts = std::collections::HashMap::new();
        opts.insert("py/no-eval".to_string(), serde_yaml_ng::Value::Null);
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

    /// Proves the kernel dirty-frag YAML pack is loaded by default — i.e.
    /// without the user passing `--rules rules/kernel/dirty-frag-class/`.
    /// Before this change the pack only fired when explicitly opted into;
    /// now it ships inside the binary via `include_dir!` and registers on
    /// the same `RuleRegistry::new()` call as the Rust rules.
    ///
    /// The CodeQL-engine rule
    /// (`kernel/dirty-frag/esp-shared-frag-decrypt-guard-codeql`) is
    /// intentionally skipped by the Semgrep loader — Agent B's CodeQL
    /// bridge owns that one.
    #[test]
    fn bundled_kernel_dirty_frag_rules_load_by_default() {
        let registry = RuleRegistry::new();
        let ids: std::collections::HashSet<&str> = registry.rules.iter().map(|r| r.id()).collect();

        // Five Semgrep-engine rules in the pack (the sixth is CodeQL).
        let expected = [
            "semgrep/kernel/dirty-frag/skb-inplace-skcipher-no-cow",
            "semgrep/kernel/dirty-frag/skb-inplace-aead-no-cow",
            "semgrep/kernel/dirty-frag/scatterwalk-store-on-shared-sgl",
            "semgrep/kernel/dirty-frag/scatterwalk-store-on-shared-sgl-authencesn",
            "semgrep/kernel/dirty-frag/rxrpc-verify-response-dispatch",
        ];
        for id in expected {
            assert!(
                ids.contains(id),
                "expected bundled rule {} to be registered by default, got: {:?}",
                id,
                ids.iter()
                    .filter(|i| i.starts_with("semgrep/kernel"))
                    .collect::<Vec<_>>()
            );
        }

        // CodeQL-engine rule must NOT be picked up by the Semgrep loader.
        assert!(
            !ids.contains("semgrep/kernel/dirty-frag/esp-shared-frag-decrypt-guard-codeql"),
            "CodeQL rule leaked into the Semgrep registry"
        );
    }

    /// `--no-builtins` must suppress the bundled YAML pack too, not just
    /// the Rust rules. This is the explicit design decision documented in
    /// `build_registry` in `src/app.rs`.
    #[test]
    fn empty_registry_does_not_load_bundled_rules() {
        let registry = RuleRegistry::empty();
        assert!(registry.rules.is_empty());
    }
}
