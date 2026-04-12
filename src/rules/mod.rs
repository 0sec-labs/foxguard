pub mod common;
pub mod cross_file;
pub mod csharp;
pub mod go;
pub mod go_taint;
pub mod java;
pub mod javascript;
pub mod javascript_taint;
pub mod kotlin;
pub mod php;
pub mod python;
pub mod python_aliases;
pub mod python_taint;
pub mod ruby;
pub mod rust_lang;
pub mod semgrep_compat;
pub mod semgrep_taint;
pub mod swift;

use crate::{Finding, Language, Severity};
use std::path::Path;

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
}

/// Registry holding all available rules.
pub struct RuleRegistry {
    rules: Vec<Box<dyn Rule>>,
}

impl Default for RuleRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl RuleRegistry {
    pub fn empty() -> Self {
        Self { rules: Vec::new() }
    }

    pub fn new() -> Self {
        let mut registry = Self { rules: Vec::new() };

        // Register JavaScript rules
        registry.register(Box::new(javascript::NoEval));
        registry.register(Box::new(javascript::NoHardcodedSecret));
        registry.register(Box::new(javascript::NoSqlInjection));
        registry.register(Box::new(javascript::NoXssInnerHtml));
        registry.register(Box::new(javascript::NoCommandInjection));
        registry.register(Box::new(javascript::NoDocumentWrite));
        registry.register(Box::new(javascript::NoOpenRedirect));
        registry.register(Box::new(javascript::NoWeakCrypto));
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

        // Register Python rules
        registry.register(Box::new(python::NoEval));
        registry.register(Box::new(python::NoHardcodedSecret));
        registry.register(Box::new(python::NoSqlInjection));
        registry.register(Box::new(python::NoCommandInjection));
        registry.register(Box::new(python::NoPathTraversal));
        registry.register(Box::new(python::NoSsrf));
        registry.register(Box::new(python::NoWeakCrypto));
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

        // Register Go rules
        registry.register(Box::new(go::NoSqlInjection));
        registry.register(Box::new(go::NoCommandInjection));
        registry.register(Box::new(go::NoHardcodedSecret));
        registry.register(Box::new(go::NoWeakCrypto));
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

        // Register Java rules
        registry.register(Box::new(java::NoSqlInjection));
        registry.register(Box::new(java::NoCommandInjection));
        registry.register(Box::new(java::NoUnsafeDeserialization));
        registry.register(Box::new(java::NoSsrf));
        registry.register(Box::new(java::NoPathTraversal));
        registry.register(Box::new(java::NoWeakCrypto));
        registry.register(Box::new(java::NoHardcodedSecret));
        registry.register(Box::new(java::NoXxe));
        registry.register(Box::new(java::SpringCsrfDisabled));
        registry.register(Box::new(java::SpringCorsPermissive));

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

        // Register Rust rules
        registry.register(Box::new(rust_lang::UnsafeBlock));
        registry.register(Box::new(rust_lang::TransmuteUsage));
        registry.register(Box::new(rust_lang::NoCommandInjection));
        registry.register(Box::new(rust_lang::NoSqlInjection));
        registry.register(Box::new(rust_lang::NoWeakHash));
        registry.register(Box::new(rust_lang::NoHardcodedSecret));
        registry.register(Box::new(rust_lang::TlsVerifyDisabled));
        registry.register(Box::new(rust_lang::NoSsrf));
        registry.register(Box::new(rust_lang::NoPathTraversal));
        registry.register(Box::new(rust_lang::NoUnwrapInLib));

        registry
    }

    pub fn register(&mut self, rule: Box<dyn Rule>) {
        self.rules.push(rule);
    }

    pub fn rules_for_language(&self, language: Language) -> Vec<&dyn Rule> {
        self.rules
            .iter()
            .filter(|r| r.language() == language)
            .map(|r| r.as_ref())
            .collect()
    }

    #[allow(dead_code)]
    pub fn all_rules(&self) -> &[Box<dyn Rule>] {
        &self.rules
    }
}
