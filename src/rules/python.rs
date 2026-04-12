use crate::rules::common::{get_source_line, make_finding, walk_tree};
use crate::rules::{FileContext, Rule};
use crate::{Finding, Language, Severity};
use regex::Regex;
use std::borrow::Cow;

// ─── Helpers ──────────────────────────────────────────────────────────────────

/// Resolve a raw callee text through the per-file Python import alias table.
/// Returns the canonical dotted path when an alias matches, otherwise the
/// input unchanged. Falls back to the raw text when no alias table is
/// available (e.g. under the legacy `check` entry point used by some unit
/// tests).
fn resolve_callee<'a>(func_text: &'a str, ctx: &'a FileContext<'_>) -> Cow<'a, str> {
    match ctx.python_aliases {
        Some(aliases) => aliases.resolve(func_text),
        None => Cow::Borrowed(func_text),
    }
}

// ─── Rule 1: no-eval ─────────────────────────────────────────────────────────

pub struct NoEval;

impl Rule for NoEval {
    fn id(&self) -> &str {
        "py/no-eval"
    }
    fn severity(&self) -> Severity {
        Severity::Critical
    }
    fn cwe(&self) -> Option<&str> {
        Some("CWE-95")
    }
    fn description(&self) -> &str {
        "Use of eval()/exec() allows arbitrary code execution"
    }
    fn language(&self) -> Language {
        Language::Python
    }

    fn check(&self, source: &str, tree: &tree_sitter::Tree) -> Vec<Finding> {
        self.check_with_context(source, tree, &FileContext::default())
    }

    fn check_with_context(
        &self,
        source: &str,
        tree: &tree_sitter::Tree,
        ctx: &FileContext<'_>,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            if node.kind() == "call" {
                if let Some(func) = node.child_by_field_name("function") {
                    let func_text = &src[func.byte_range()];
                    let resolved = resolve_callee(func_text, ctx);
                    if resolved.as_ref() == "eval" || resolved.as_ref() == "exec" {
                        findings.push(make_finding(
                            self.id(),
                            self.severity(),
                            self.cwe(),
                            &format!(
                                "{}() allows arbitrary code execution — avoid using it with untrusted input",
                                resolved
                            ),
                            node,
                            src,
                        ));
                    }
                }
            }
        });
        findings
    }
}

// ─── Rule 2: no-hardcoded-secret ─────────────────────────────────────────────

pub struct NoHardcodedSecret;

impl Rule for NoHardcodedSecret {
    fn id(&self) -> &str {
        "py/no-hardcoded-secret"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn cwe(&self) -> Option<&str> {
        Some("CWE-798")
    }
    fn description(&self) -> &str {
        "Hardcoded secret or credential detected"
    }
    fn language(&self) -> Language {
        Language::Python
    }

    fn check(&self, source: &str, tree: &tree_sitter::Tree) -> Vec<Finding> {
        let mut findings = Vec::new();
        let secret_pattern =
            Regex::new(r"(?i)(password|secret|api_?key|token|auth|credential|private_?key)")
                .unwrap();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            // assignment: password = "hardcoded"
            if node.kind() == "assignment" {
                if let (Some(left), Some(right)) = (
                    node.child_by_field_name("left"),
                    node.child_by_field_name("right"),
                ) {
                    let left_text = &src[left.byte_range()];
                    if secret_pattern.is_match(left_text) && right.kind() == "string" {
                        let val = &src[right.byte_range()];
                        // Strip quotes and check length
                        let inner = val
                            .trim_start_matches("f\"")
                            .trim_start_matches("f'")
                            .trim_matches(|c| c == '"' || c == '\'');
                        if inner.len() >= 4 {
                            findings.push(make_finding(
                                self.id(),
                                self.severity(),
                                self.cwe(),
                                &format!(
                                    "Hardcoded secret in '{}' — use environment variables or a secrets manager",
                                    left_text
                                ),
                                node,
                                src,
                            ));
                        }
                    }
                }
            }
        });
        findings
    }
}

// ─── Rule 3: no-sql-injection ────────────────────────────────────────────────

pub struct NoSqlInjection;

impl Rule for NoSqlInjection {
    fn id(&self) -> &str {
        "py/no-sql-injection"
    }
    fn severity(&self) -> Severity {
        Severity::Critical
    }
    fn cwe(&self) -> Option<&str> {
        Some("CWE-89")
    }
    fn description(&self) -> &str {
        "Potential SQL injection via string formatting"
    }
    fn language(&self) -> Language {
        Language::Python
    }

    fn check(&self, source: &str, tree: &tree_sitter::Tree) -> Vec<Finding> {
        let mut findings = Vec::new();
        let sql_pattern =
            Regex::new(r"(?i)(SELECT\s+.{0,40}\s+FROM|INSERT\s+INTO|UPDATE\s+.{0,40}\s+SET|DELETE\s+FROM|DROP\s+TABLE|ALTER\s+TABLE|CREATE\s+TABLE|EXEC\s+)").unwrap();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            // Detect f-strings with SQL: f"SELECT * FROM users WHERE id = {user_id}"
            if node.kind() == "string" {
                let text = &src[node.byte_range()];
                if (text.starts_with("f\"")
                    || text.starts_with("f'")
                    || text.starts_with("f\"\"\""))
                    && sql_pattern.is_match(text)
                {
                    findings.push(make_finding(
                        self.id(),
                        self.severity(),
                        self.cwe(),
                        "SQL query built with f-string — use parameterized queries",
                        node,
                        src,
                    ));
                }
            }

            // Detect: "SELECT ... WHERE id = %s" % user_id
            if node.kind() == "binary_operator" {
                if let Some(op) = node.child_by_field_name("operator") {
                    if &src[op.byte_range()] == "%" {
                        if let Some(left) = node.child_by_field_name("left") {
                            if left.kind() == "string" {
                                let text = &src[left.byte_range()];
                                if sql_pattern.is_match(text) {
                                    findings.push(make_finding(
                                        self.id(),
                                        self.severity(),
                                        self.cwe(),
                                        "SQL query built with % formatting — use parameterized queries",
                                        node,
                                        src,
                                    ));
                                }
                            }
                        }
                    }
                }
            }

            // Detect: "SELECT ... WHERE id = {}".format(user_id)
            if node.kind() == "call" {
                if let Some(func) = node.child_by_field_name("function") {
                    if func.kind() == "attribute" {
                        if let Some(attr) = func.child_by_field_name("attribute") {
                            if &src[attr.byte_range()] == "format" {
                                if let Some(obj) = func.child_by_field_name("object") {
                                    if obj.kind() == "string" {
                                        let text = &src[obj.byte_range()];
                                        if sql_pattern.is_match(text) {
                                            findings.push(make_finding(
                                                self.id(),
                                                self.severity(),
                                                self.cwe(),
                                                "SQL query built with .format() — use parameterized queries",
                                                node,
                                                src,
                                            ));
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Detect string concatenation with SQL: "SELECT * FROM users WHERE id = " + user_id
            if node.kind() == "binary_operator" {
                if let Some(op) = node.child_by_field_name("operator") {
                    if &src[op.byte_range()] == "+" {
                        if let Some(left) = node.child_by_field_name("left") {
                            if left.kind() == "string" {
                                let text = &src[left.byte_range()];
                                if sql_pattern.is_match(text) {
                                    findings.push(make_finding(
                                        self.id(),
                                        self.severity(),
                                        self.cwe(),
                                        "SQL query built with string concatenation — use parameterized queries",
                                        node,
                                        src,
                                    ));
                                }
                            }
                        }
                    }
                }
            }
        });
        findings
    }
}

// ─── Rule 4: no-command-injection ───────────────────────────────────────────

pub struct NoCommandInjection;

impl Rule for NoCommandInjection {
    fn id(&self) -> &str {
        "py/no-command-injection"
    }
    fn severity(&self) -> Severity {
        Severity::Critical
    }
    fn cwe(&self) -> Option<&str> {
        Some("CWE-78")
    }
    fn description(&self) -> &str {
        "Potential command injection via os.system/subprocess with user input"
    }
    fn language(&self) -> Language {
        Language::Python
    }

    fn check(&self, source: &str, tree: &tree_sitter::Tree) -> Vec<Finding> {
        self.check_with_context(source, tree, &FileContext::default())
    }

    fn check_with_context(
        &self,
        source: &str,
        tree: &tree_sitter::Tree,
        ctx: &FileContext<'_>,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();
        let dangerous_fns = [
            "os.system",
            "os.popen",
            "subprocess.call",
            "subprocess.run",
            "subprocess.Popen",
            "subprocess.check_output",
            "subprocess.check_call",
        ];

        walk_tree(tree.root_node(), source, &mut |node, src| {
            if node.kind() == "call" {
                if let Some(func) = node.child_by_field_name("function") {
                    let func_text = &src[func.byte_range()];
                    let resolved = resolve_callee(func_text, ctx);
                    if dangerous_fns.contains(&resolved.as_ref()) {
                        if let Some(args) = node.child_by_field_name("arguments") {
                            if let Some(first_arg) = args.named_child(0) {
                                // Flag if argument is not a plain string literal
                                let is_dynamic = match first_arg.kind() {
                                    "string" => {
                                        let text = &src[first_arg.byte_range()];
                                        text.starts_with("f\"") || text.starts_with("f'")
                                    }
                                    "concatenated_string"
                                    | "binary_operator"
                                    | "identifier"
                                    | "call" => true,
                                    _ => false,
                                };
                                if is_dynamic {
                                    findings.push(make_finding(
                                        self.id(),
                                        self.severity(),
                                        self.cwe(),
                                        &format!(
                                            "{}() called with dynamic argument — risk of command injection",
                                            resolved
                                        ),
                                        node,
                                        src,
                                    ));
                                }
                            }
                        }
                    }
                }
            }
        });
        findings
    }
}

// ─── Rule 5: no-path-traversal ──────────────────────────────────────────────

pub struct NoPathTraversal;

impl Rule for NoPathTraversal {
    fn id(&self) -> &str {
        "py/no-path-traversal"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn cwe(&self) -> Option<&str> {
        Some("CWE-22")
    }
    fn description(&self) -> &str {
        "Potential path traversal via open() with user input"
    }
    fn language(&self) -> Language {
        Language::Python
    }

    fn check(&self, source: &str, tree: &tree_sitter::Tree) -> Vec<Finding> {
        self.check_with_context(source, tree, &FileContext::default())
    }

    fn check_with_context(
        &self,
        source: &str,
        tree: &tree_sitter::Tree,
        ctx: &FileContext<'_>,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            if node.kind() == "call" {
                if let Some(func) = node.child_by_field_name("function") {
                    let func_text = &src[func.byte_range()];
                    let resolved = resolve_callee(func_text, ctx);
                    let sink_fns = ["open", "os.remove", "os.unlink", "os.listdir", "os.scandir"];
                    if sink_fns.contains(&resolved.as_ref()) {
                        if let Some(args) = node.child_by_field_name("arguments") {
                            if let Some(first_arg) = args.named_child(0) {
                                // Flag if path uses concatenation or f-string
                                let is_dynamic = match first_arg.kind() {
                                    "binary_operator" | "concatenated_string" | "identifier" => {
                                        true
                                    }
                                    "string" => {
                                        let text = &src[first_arg.byte_range()];
                                        text.starts_with("f\"") || text.starts_with("f'")
                                    }
                                    _ => false,
                                };
                                if is_dynamic {
                                    findings.push(make_finding(
                                        self.id(),
                                        self.severity(),
                                        self.cwe(),
                                        &format!(
                                            "{}() called with dynamic path — validate and sanitize to prevent path traversal",
                                            resolved
                                        ),
                                        node,
                                        src,
                                    ));
                                }
                            }
                        }
                    }
                }
            }
        });
        findings
    }
}

// ─── Rule 6: no-weak-crypto ────────────────────────────────────────────────

pub struct NoSsrf;

impl Rule for NoSsrf {
    fn id(&self) -> &str {
        "py/no-ssrf"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn cwe(&self) -> Option<&str> {
        Some("CWE-918")
    }
    fn description(&self) -> &str {
        "Potential SSRF via dynamic outbound request URL"
    }
    fn language(&self) -> Language {
        Language::Python
    }

    fn check(&self, source: &str, tree: &tree_sitter::Tree) -> Vec<Finding> {
        self.check_with_context(source, tree, &FileContext::default())
    }

    fn check_with_context(
        &self,
        source: &str,
        tree: &tree_sitter::Tree,
        ctx: &FileContext<'_>,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();
        let request_fns = [
            "requests.get",
            "requests.post",
            "requests.put",
            "requests.delete",
            "requests.head",
            "requests.patch",
            "requests.request",
            "httpx.get",
            "httpx.post",
            "httpx.put",
            "httpx.delete",
            "httpx.request",
            "urllib.request.urlopen",
        ];

        walk_tree(tree.root_node(), source, &mut |node, src| {
            if node.kind() != "call" {
                return;
            }

            let Some(func) = node.child_by_field_name("function") else {
                return;
            };
            let func_text = &src[func.byte_range()];
            let resolved = resolve_callee(func_text, ctx);
            if !request_fns.contains(&resolved.as_ref()) {
                return;
            }

            let Some(args) = node.child_by_field_name("arguments") else {
                return;
            };

            let url_arg = if resolved.as_ref() == "requests.request"
                || resolved.as_ref() == "httpx.request"
            {
                args.named_child(1)
            } else {
                args.named_child(0)
            };
            let Some(url_arg) = url_arg else {
                return;
            };

            let is_dynamic = match url_arg.kind() {
                "string" => {
                    let text = &src[url_arg.byte_range()];
                    text.starts_with("f\"") || text.starts_with("f'")
                }
                "identifier" | "call" | "subscript" | "attribute" | "binary_operator" => true,
                _ => false,
            };

            if is_dynamic {
                findings.push(make_finding(
                    self.id(),
                    self.severity(),
                    self.cwe(),
                    &format!(
                        "{} called with dynamic URL — validate and allowlist outbound destinations to prevent SSRF",
                        resolved
                    ),
                    node,
                    src,
                ));
            }
        });

        findings
    }
}

// ─── Rule 6: no-weak-crypto ────────────────────────────────────────────────

pub struct NoWeakCrypto;

impl Rule for NoWeakCrypto {
    fn id(&self) -> &str {
        "py/no-weak-crypto"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn cwe(&self) -> Option<&str> {
        Some("CWE-327")
    }
    fn description(&self) -> &str {
        "Use of weak cryptographic hash (MD5/SHA1)"
    }
    fn language(&self) -> Language {
        Language::Python
    }

    fn check(&self, source: &str, tree: &tree_sitter::Tree) -> Vec<Finding> {
        self.check_with_context(source, tree, &FileContext::default())
    }

    fn check_with_context(
        &self,
        source: &str,
        tree: &tree_sitter::Tree,
        ctx: &FileContext<'_>,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            if node.kind() == "call" {
                if let Some(func) = node.child_by_field_name("function") {
                    let func_text = &src[func.byte_range()];
                    let resolved = resolve_callee(func_text, ctx);
                    if resolved.as_ref() == "hashlib.md5" || resolved.as_ref() == "hashlib.sha1" {
                        let algo = if resolved.as_ref().contains("md5") {
                            "MD5"
                        } else {
                            "SHA1"
                        };
                        findings.push(make_finding(
                            self.id(),
                            self.severity(),
                            self.cwe(),
                            &format!(
                                "hashlib.{}() is cryptographically weak — use sha256 or stronger",
                                algo.to_lowercase()
                            ),
                            node,
                            src,
                        ));
                    }

                    // hashlib.new('md5') / hashlib.new('sha1')
                    if resolved.as_ref() == "hashlib.new" {
                        if let Some(args) = node.child_by_field_name("arguments") {
                            if let Some(first_arg) = args.named_child(0) {
                                if first_arg.kind() == "string" {
                                    let val = &src[first_arg.byte_range()];
                                    let inner = val.trim_matches(|c| c == '"' || c == '\'');
                                    if inner == "md5" || inner == "sha1" {
                                        findings.push(make_finding(
                                            self.id(),
                                            self.severity(),
                                            self.cwe(),
                                            &format!(
                                                "hashlib.new('{}') is cryptographically weak — use sha256 or stronger",
                                                inner
                                            ),
                                            node,
                                            src,
                                        ));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        });
        findings
    }
}

// ─── Rule 7: no-pickle ─────────────────────────────────────────────────────

pub struct NoPickle;

impl Rule for NoPickle {
    fn id(&self) -> &str {
        "py/no-pickle"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn cwe(&self) -> Option<&str> {
        Some("CWE-502")
    }
    fn description(&self) -> &str {
        "Deserialization of untrusted data via pickle"
    }
    fn language(&self) -> Language {
        Language::Python
    }

    fn check(&self, source: &str, tree: &tree_sitter::Tree) -> Vec<Finding> {
        self.check_with_context(source, tree, &FileContext::default())
    }

    fn check_with_context(
        &self,
        source: &str,
        tree: &tree_sitter::Tree,
        ctx: &FileContext<'_>,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();
        let dangerous_fns = [
            "pickle.loads",
            "pickle.load",
            "cPickle.loads",
            "cPickle.load",
        ];

        walk_tree(tree.root_node(), source, &mut |node, src| {
            if node.kind() == "call" {
                if let Some(func) = node.child_by_field_name("function") {
                    let func_text = &src[func.byte_range()];
                    let resolved = resolve_callee(func_text, ctx);
                    if dangerous_fns.contains(&resolved.as_ref()) {
                        findings.push(make_finding(
                            self.id(),
                            self.severity(),
                            self.cwe(),
                            &format!(
                                "{}() deserializes untrusted data — can execute arbitrary code",
                                resolved
                            ),
                            node,
                            src,
                        ));
                    }
                }
            }
        });
        findings
    }
}

// ─── Rule 8: no-yaml-load ──────────────────────────────────────────────────

pub struct NoYamlLoad;

impl Rule for NoYamlLoad {
    fn id(&self) -> &str {
        "py/no-yaml-load"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn cwe(&self) -> Option<&str> {
        Some("CWE-502")
    }
    fn description(&self) -> &str {
        "yaml.load() without SafeLoader can execute arbitrary code"
    }
    fn language(&self) -> Language {
        Language::Python
    }

    fn check(&self, source: &str, tree: &tree_sitter::Tree) -> Vec<Finding> {
        self.check_with_context(source, tree, &FileContext::default())
    }

    fn check_with_context(
        &self,
        source: &str,
        tree: &tree_sitter::Tree,
        ctx: &FileContext<'_>,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            if node.kind() == "call" {
                if let Some(func) = node.child_by_field_name("function") {
                    let func_text = &src[func.byte_range()];
                    let resolved = resolve_callee(func_text, ctx);
                    if resolved.as_ref() == "yaml.load" {
                        // Check if SafeLoader or safe_load is used
                        if let Some(args) = node.child_by_field_name("arguments") {
                            let args_text = &src[args.byte_range()];
                            if !args_text.contains("SafeLoader")
                                && !args_text.contains("safe_load")
                                && !args_text.contains("BaseLoader")
                            {
                                findings.push(make_finding(
                                    self.id(),
                                    self.severity(),
                                    self.cwe(),
                                    "yaml.load() without SafeLoader — use yaml.safe_load() or pass Loader=SafeLoader",
                                    node,
                                    src,
                                ));
                            }
                        }
                    }
                }
            }
        });
        findings
    }
}

// ─── Rule 9: no-debug-true (Django DEBUG = True) ──────────────────────────

pub struct NoDebugTrue;

impl Rule for NoDebugTrue {
    fn id(&self) -> &str {
        "py/no-debug-true"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn cwe(&self) -> Option<&str> {
        Some("CWE-489")
    }
    fn description(&self) -> &str {
        "DEBUG = True left enabled — disable in production"
    }
    fn language(&self) -> Language {
        Language::Python
    }

    fn check(&self, source: &str, tree: &tree_sitter::Tree) -> Vec<Finding> {
        let mut findings = Vec::new();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            // Detect: DEBUG = True (Django settings pattern)
            if node.kind() == "assignment" {
                if let (Some(left), Some(right)) = (
                    node.child_by_field_name("left"),
                    node.child_by_field_name("right"),
                ) {
                    let left_text = &src[left.byte_range()];
                    let right_text = &src[right.byte_range()];
                    if left_text == "DEBUG" && right_text == "True" {
                        findings.push(make_finding(
                            self.id(),
                            self.severity(),
                            self.cwe(),
                            "DEBUG = True — ensure debug mode is disabled in production (Django CWE-489)",
                            node,
                            src,
                        ));
                    }
                }
            }
        });
        findings
    }
}

// ─── Rule 12: flask-debug-mode ────────────────────────────────────────────

pub struct FlaskDebugMode;

impl Rule for FlaskDebugMode {
    fn id(&self) -> &str {
        "py/flask-debug-mode"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn cwe(&self) -> Option<&str> {
        Some("CWE-489")
    }
    fn description(&self) -> &str {
        "Flask app.run(debug=True) exposes debugger and reloader in production"
    }
    fn language(&self) -> Language {
        Language::Python
    }

    fn check(&self, source: &str, tree: &tree_sitter::Tree) -> Vec<Finding> {
        let mut findings = Vec::new();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            // Detect: app.run(debug=True) specifically as a call expression
            if node.kind() == "call" {
                if let Some(func) = node.child_by_field_name("function") {
                    if func.kind() == "attribute" {
                        if let Some(attr) = func.child_by_field_name("attribute") {
                            if &src[attr.byte_range()] == "run" {
                                if let Some(args) = node.child_by_field_name("arguments") {
                                    let args_text = &src[args.byte_range()];
                                    if args_text.contains("debug=True")
                                        || args_text.contains("debug = True")
                                    {
                                        findings.push(make_finding(
                                            self.id(),
                                            self.severity(),
                                            self.cwe(),
                                            "Flask app.run(debug=True) — exposes Werkzeug debugger, disable in production",
                                            node,
                                            src,
                                        ));
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Detect: app.debug = True
            if node.kind() == "assignment" {
                if let (Some(left), Some(right)) = (
                    node.child_by_field_name("left"),
                    node.child_by_field_name("right"),
                ) {
                    let left_text = &src[left.byte_range()];
                    let right_text = &src[right.byte_range()];
                    if left_text.ends_with(".debug") && right_text == "True" {
                        findings.push(make_finding(
                            self.id(),
                            self.severity(),
                            self.cwe(),
                            "app.debug = True — exposes debugger, disable in production",
                            node,
                            src,
                        ));
                    }
                }
            }
        });
        findings
    }
}

// ─── Rule 13: django-secret-key-hardcoded ─────────────────────────────────

pub struct DjangoSecretKeyHardcoded;

impl Rule for DjangoSecretKeyHardcoded {
    fn id(&self) -> &str {
        "py/django-secret-key-hardcoded"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn cwe(&self) -> Option<&str> {
        Some("CWE-798")
    }
    fn description(&self) -> &str {
        "Django SECRET_KEY hardcoded in source code"
    }
    fn language(&self) -> Language {
        Language::Python
    }

    fn check(&self, source: &str, tree: &tree_sitter::Tree) -> Vec<Finding> {
        let mut findings = Vec::new();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            // Detect: SECRET_KEY = "some-literal-string"
            if node.kind() == "assignment" {
                if let (Some(left), Some(right)) = (
                    node.child_by_field_name("left"),
                    node.child_by_field_name("right"),
                ) {
                    let left_text = &src[left.byte_range()];
                    if left_text == "SECRET_KEY" && right.kind() == "string" {
                        let val = &src[right.byte_range()];
                        let inner = val.trim_matches(|c| c == '"' || c == '\'');
                        if inner.len() >= 4 {
                            findings.push(make_finding(
                                self.id(),
                                self.severity(),
                                self.cwe(),
                                "Django SECRET_KEY is hardcoded — use an environment variable or secrets manager",
                                node,
                                src,
                            ));
                        }
                    }
                }
            }
        });
        findings
    }
}

// ─── Rule 10: no-open-redirect ──────────────────────────────────────────────

pub struct NoOpenRedirect;

impl Rule for NoOpenRedirect {
    fn id(&self) -> &str {
        "py/no-open-redirect"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn cwe(&self) -> Option<&str> {
        Some("CWE-601")
    }
    fn description(&self) -> &str {
        "Open redirect via redirect() with user-controlled input"
    }
    fn language(&self) -> Language {
        Language::Python
    }

    fn check(&self, source: &str, tree: &tree_sitter::Tree) -> Vec<Finding> {
        let mut findings = Vec::new();
        let redirect_fns = ["redirect", "HttpResponseRedirect"];

        walk_tree(tree.root_node(), source, &mut |node, src| {
            if node.kind() == "call" {
                if let Some(func) = node.child_by_field_name("function") {
                    let func_text = &src[func.byte_range()];
                    let func_name = func_text.rsplit('.').next().unwrap_or(func_text);
                    if redirect_fns.contains(&func_name) {
                        if let Some(args) = node.child_by_field_name("arguments") {
                            if let Some(first_arg) = args.named_child(0) {
                                // Flag if redirect target is not a string literal
                                let is_dynamic = match first_arg.kind() {
                                    "string" => {
                                        let text = &src[first_arg.byte_range()];
                                        text.starts_with("f\"") || text.starts_with("f'")
                                    }
                                    "identifier" | "call" | "subscript" | "attribute"
                                    | "binary_operator" => true,
                                    _ => false,
                                };
                                if is_dynamic {
                                    findings.push(make_finding(
                                        self.id(),
                                        self.severity(),
                                        self.cwe(),
                                        &format!(
                                            "{}() with dynamic URL — validate target to prevent open redirect",
                                            func_name
                                        ),
                                        node,
                                        src,
                                    ));
                                }
                            }
                        }
                    }
                }
            }
        });
        findings
    }
}

// ─── Rule 11: no-cors-star ─────────────────────────────────────────────────

pub struct NoCorsStar;

impl Rule for NoCorsStar {
    fn id(&self) -> &str {
        "py/no-cors-star"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn cwe(&self) -> Option<&str> {
        Some("CWE-942")
    }
    fn description(&self) -> &str {
        "CORS misconfiguration allowing all origins"
    }
    fn language(&self) -> Language {
        Language::Python
    }

    fn check(&self, source: &str, tree: &tree_sitter::Tree) -> Vec<Finding> {
        let mut findings = Vec::new();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            // Detect: CORS_ALLOW_ALL_ORIGINS = True or CORS_ORIGIN_ALLOW_ALL = True
            if node.kind() == "assignment" {
                if let (Some(left), Some(right)) = (
                    node.child_by_field_name("left"),
                    node.child_by_field_name("right"),
                ) {
                    let left_text = &src[left.byte_range()];
                    let right_text = &src[right.byte_range()];
                    if (left_text == "CORS_ALLOW_ALL_ORIGINS"
                        || left_text == "CORS_ORIGIN_ALLOW_ALL")
                        && right_text == "True"
                    {
                        findings.push(make_finding(
                            self.id(),
                            self.severity(),
                            self.cwe(),
                            &format!("{} = True — restrict CORS to specific origins", left_text),
                            node,
                            src,
                        ));
                    }
                }
            }

            // Detect: Access-Control-Allow-Origin header set to "*"
            if node.kind() == "call" {
                if let Some(func) = node.child_by_field_name("function") {
                    let func_text = &src[func.byte_range()];
                    if func_text.contains("header") || func_text.contains("Header") {
                        let node_text = &src[node.byte_range()];
                        if node_text.contains("Access-Control-Allow-Origin")
                            && node_text.contains("*")
                        {
                            findings.push(make_finding(
                                self.id(),
                                self.severity(),
                                self.cwe(),
                                "Access-Control-Allow-Origin set to '*' — restrict to specific origins",
                                node,
                                src,
                            ));
                        }
                    }
                }
            }

            // Detect: allow_origins=["*"] in CORS middleware
            if node.kind() == "keyword_argument" {
                if let (Some(name), Some(value)) = (
                    node.child_by_field_name("name"),
                    node.child_by_field_name("value"),
                ) {
                    let name_text = &src[name.byte_range()];
                    if name_text == "allow_origins" || name_text == "origins" {
                        let value_text = &src[value.byte_range()];
                        if value_text.contains("\"*\"") || value_text.contains("'*'") {
                            findings.push(make_finding(
                                self.id(),
                                self.severity(),
                                self.cwe(),
                                "CORS allow_origins includes '*' — restrict to specific origins",
                                node,
                                src,
                            ));
                        }
                    }
                }
            }
        });
        findings
    }
}

// ─── Rule 14: flask-secret-key-hardcoded ──────────────────────────────────

pub struct FlaskSecretKeyHardcoded;

impl Rule for FlaskSecretKeyHardcoded {
    fn id(&self) -> &str {
        "py/flask-secret-key-hardcoded"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn cwe(&self) -> Option<&str> {
        Some("CWE-798")
    }
    fn description(&self) -> &str {
        "Flask SECRET_KEY hardcoded in source code"
    }
    fn language(&self) -> Language {
        Language::Python
    }

    fn check(&self, source: &str, tree: &tree_sitter::Tree) -> Vec<Finding> {
        let mut findings = Vec::new();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            if node.kind() != "assignment" {
                return;
            }

            let (Some(left), Some(right)) = (
                node.child_by_field_name("left"),
                node.child_by_field_name("right"),
            ) else {
                return;
            };

            if right.kind() != "string" {
                return;
            }

            let left_text = &src[left.byte_range()];
            let is_flask_secret = left_text == "app.secret_key"
                || (left_text.contains("config") && left_text.contains("SECRET_KEY"));
            if !is_flask_secret {
                return;
            }

            let val = &src[right.byte_range()];
            let inner = val.trim_matches(|c| c == '"' || c == '\'');
            if inner.len() < 4 {
                return;
            }

            findings.push(make_finding(
                self.id(),
                self.severity(),
                self.cwe(),
                "Flask SECRET_KEY is hardcoded — use an environment variable or secrets manager",
                node,
                src,
            ));
        });

        findings
    }
}

// ─── Rule 15: session-cookie-secure-disabled ──────────────────────────────

pub struct SessionCookieSecureDisabled;

impl Rule for SessionCookieSecureDisabled {
    fn id(&self) -> &str {
        "py/session-cookie-secure-disabled"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn cwe(&self) -> Option<&str> {
        Some("CWE-614")
    }
    fn description(&self) -> &str {
        "SESSION_COOKIE_SECURE disabled in source code"
    }
    fn language(&self) -> Language {
        Language::Python
    }

    fn check(&self, source: &str, tree: &tree_sitter::Tree) -> Vec<Finding> {
        let mut findings = Vec::new();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            if node.kind() != "assignment" {
                return;
            }

            let (Some(left), Some(right)) = (
                node.child_by_field_name("left"),
                node.child_by_field_name("right"),
            ) else {
                return;
            };

            let left_text = &src[left.byte_range()];
            let right_text = &src[right.byte_range()];
            let is_session_cookie_secure =
                left_text == "SESSION_COOKIE_SECURE" || left_text.contains("SESSION_COOKIE_SECURE");
            if is_session_cookie_secure && right_text == "False" {
                findings.push(make_finding(
                    self.id(),
                    self.severity(),
                    self.cwe(),
                    "SESSION_COOKIE_SECURE = False — session cookies may be sent over HTTP",
                    node,
                    src,
                ));
            }
        });

        findings
    }
}

// ─── Rule 16: session-cookie-httponly-disabled ────────────────────────────

pub struct SessionCookieHttpOnlyDisabled;

impl Rule for SessionCookieHttpOnlyDisabled {
    fn id(&self) -> &str {
        "py/session-cookie-httponly-disabled"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn cwe(&self) -> Option<&str> {
        Some("CWE-1004")
    }
    fn description(&self) -> &str {
        "SESSION_COOKIE_HTTPONLY disabled in source code"
    }
    fn language(&self) -> Language {
        Language::Python
    }

    fn check(&self, source: &str, tree: &tree_sitter::Tree) -> Vec<Finding> {
        let mut findings = Vec::new();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            if node.kind() != "assignment" {
                return;
            }

            let (Some(left), Some(right)) = (
                node.child_by_field_name("left"),
                node.child_by_field_name("right"),
            ) else {
                return;
            };

            let left_text = &src[left.byte_range()];
            let right_text = &src[right.byte_range()];
            let is_session_cookie_httponly = left_text == "SESSION_COOKIE_HTTPONLY"
                || left_text.contains("SESSION_COOKIE_HTTPONLY");
            if is_session_cookie_httponly && right_text == "False" {
                findings.push(make_finding(
                    self.id(),
                    self.severity(),
                    self.cwe(),
                    "SESSION_COOKIE_HTTPONLY = False — session cookies may be exposed to client-side scripts",
                    node,
                    src,
                ));
            }
        });

        findings
    }
}

// ─── Rule 17: session-cookie-samesite-disabled ────────────────────────────

pub struct SessionCookieSameSiteDisabled;

impl Rule for SessionCookieSameSiteDisabled {
    fn id(&self) -> &str {
        "py/session-cookie-samesite-disabled"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn cwe(&self) -> Option<&str> {
        Some("CWE-352")
    }
    fn description(&self) -> &str {
        "SESSION_COOKIE_SAMESITE disabled in source code"
    }
    fn language(&self) -> Language {
        Language::Python
    }

    fn check(&self, source: &str, tree: &tree_sitter::Tree) -> Vec<Finding> {
        let mut findings = Vec::new();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            if node.kind() != "assignment" {
                return;
            }

            let (Some(left), Some(right)) = (
                node.child_by_field_name("left"),
                node.child_by_field_name("right"),
            ) else {
                return;
            };

            let left_text = &src[left.byte_range()];
            let right_text = &src[right.byte_range()];
            let is_session_cookie_samesite = left_text == "SESSION_COOKIE_SAMESITE"
                || left_text.contains("SESSION_COOKIE_SAMESITE");
            let disabled = right_text == "None"
                || right_text == "\"None\""
                || right_text == "'None'"
                || right_text == "\"none\""
                || right_text == "'none'"
                || right_text == "False";
            if is_session_cookie_samesite && disabled {
                findings.push(make_finding(
                    self.id(),
                    self.severity(),
                    self.cwe(),
                    "SESSION_COOKIE_SAMESITE disabled — set it to 'Lax' or 'Strict' to reduce CSRF risk",
                    node,
                    src,
                ));
            }
        });

        findings
    }
}

// ─── Rule 18: csrf-cookie-secure-disabled ─────────────────────────────────

pub struct CsrfCookieSecureDisabled;

impl Rule for CsrfCookieSecureDisabled {
    fn id(&self) -> &str {
        "py/csrf-cookie-secure-disabled"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn cwe(&self) -> Option<&str> {
        Some("CWE-614")
    }
    fn description(&self) -> &str {
        "CSRF_COOKIE_SECURE disabled in source code"
    }
    fn language(&self) -> Language {
        Language::Python
    }

    fn check(&self, source: &str, tree: &tree_sitter::Tree) -> Vec<Finding> {
        let mut findings = Vec::new();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            if node.kind() != "assignment" {
                return;
            }

            let (Some(left), Some(right)) = (
                node.child_by_field_name("left"),
                node.child_by_field_name("right"),
            ) else {
                return;
            };

            let left_text = &src[left.byte_range()];
            let right_text = &src[right.byte_range()];
            let is_csrf_cookie_secure =
                left_text == "CSRF_COOKIE_SECURE" || left_text.contains("CSRF_COOKIE_SECURE");
            if is_csrf_cookie_secure && right_text == "False" {
                findings.push(make_finding(
                    self.id(),
                    self.severity(),
                    self.cwe(),
                    "CSRF_COOKIE_SECURE = False — CSRF cookies may be sent over HTTP",
                    node,
                    src,
                ));
            }
        });

        findings
    }
}

// ─── Rule 19: csrf-cookie-httponly-disabled ───────────────────────────────

pub struct CsrfCookieHttpOnlyDisabled;

impl Rule for CsrfCookieHttpOnlyDisabled {
    fn id(&self) -> &str {
        "py/csrf-cookie-httponly-disabled"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn cwe(&self) -> Option<&str> {
        Some("CWE-1004")
    }
    fn description(&self) -> &str {
        "CSRF_COOKIE_HTTPONLY disabled in source code"
    }
    fn language(&self) -> Language {
        Language::Python
    }

    fn check(&self, source: &str, tree: &tree_sitter::Tree) -> Vec<Finding> {
        let mut findings = Vec::new();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            if node.kind() != "assignment" {
                return;
            }

            let (Some(left), Some(right)) = (
                node.child_by_field_name("left"),
                node.child_by_field_name("right"),
            ) else {
                return;
            };

            let left_text = &src[left.byte_range()];
            let right_text = &src[right.byte_range()];
            let is_csrf_cookie_httponly =
                left_text == "CSRF_COOKIE_HTTPONLY" || left_text.contains("CSRF_COOKIE_HTTPONLY");
            if is_csrf_cookie_httponly && right_text == "False" {
                findings.push(make_finding(
                    self.id(),
                    self.severity(),
                    self.cwe(),
                    "CSRF_COOKIE_HTTPONLY = False — CSRF cookies may be exposed to client-side scripts",
                    node,
                    src,
                ));
            }
        });

        findings
    }
}

// ─── Rule 20: csrf-cookie-samesite-disabled ───────────────────────────────

pub struct CsrfCookieSameSiteDisabled;

impl Rule for CsrfCookieSameSiteDisabled {
    fn id(&self) -> &str {
        "py/csrf-cookie-samesite-disabled"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn cwe(&self) -> Option<&str> {
        Some("CWE-352")
    }
    fn description(&self) -> &str {
        "CSRF_COOKIE_SAMESITE disabled in source code"
    }
    fn language(&self) -> Language {
        Language::Python
    }

    fn check(&self, source: &str, tree: &tree_sitter::Tree) -> Vec<Finding> {
        let mut findings = Vec::new();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            if node.kind() != "assignment" {
                return;
            }

            let (Some(left), Some(right)) = (
                node.child_by_field_name("left"),
                node.child_by_field_name("right"),
            ) else {
                return;
            };

            let left_text = &src[left.byte_range()];
            let right_text = &src[right.byte_range()];
            let is_csrf_cookie_samesite =
                left_text == "CSRF_COOKIE_SAMESITE" || left_text.contains("CSRF_COOKIE_SAMESITE");
            let disabled = right_text == "None"
                || right_text == "\"None\""
                || right_text == "'None'"
                || right_text == "\"none\""
                || right_text == "'none'"
                || right_text == "False";
            if is_csrf_cookie_samesite && disabled {
                findings.push(make_finding(
                    self.id(),
                    self.severity(),
                    self.cwe(),
                    "CSRF_COOKIE_SAMESITE disabled — set it to 'Lax' or 'Strict' to reduce CSRF risk",
                    node,
                    src,
                ));
            }
        });

        findings
    }
}

// ─── Rule 21: csrf-exempt ──────────────────────────────────────────────────

pub struct CsrfExempt;

impl Rule for CsrfExempt {
    fn id(&self) -> &str {
        "py/csrf-exempt"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn cwe(&self) -> Option<&str> {
        Some("CWE-352")
    }
    fn description(&self) -> &str {
        "View marked csrf_exempt"
    }
    fn language(&self) -> Language {
        Language::Python
    }

    fn check(&self, source: &str, tree: &tree_sitter::Tree) -> Vec<Finding> {
        let mut findings = Vec::new();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            let text = &src[node.byte_range()];
            if node.kind() == "decorator" && text.contains("csrf_exempt") {
                findings.push(make_finding(
                    self.id(),
                    self.severity(),
                    self.cwe(),
                    "@csrf_exempt disables CSRF protection — prefer scoped exemptions or validated alternative controls",
                    node,
                    src,
                ));
            }
        });

        findings
    }
}

// ─── Rule 22: wtf-csrf-disabled ───────────────────────────────────────────

pub struct WtfCsrfDisabled;

impl Rule for WtfCsrfDisabled {
    fn id(&self) -> &str {
        "py/wtf-csrf-disabled"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn cwe(&self) -> Option<&str> {
        Some("CWE-352")
    }
    fn description(&self) -> &str {
        "Flask-WTF CSRF protection disabled in source code"
    }
    fn language(&self) -> Language {
        Language::Python
    }

    fn check(&self, source: &str, tree: &tree_sitter::Tree) -> Vec<Finding> {
        let mut findings = Vec::new();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            if node.kind() != "assignment" {
                return;
            }

            let (Some(left), Some(right)) = (
                node.child_by_field_name("left"),
                node.child_by_field_name("right"),
            ) else {
                return;
            };

            let left_text = &src[left.byte_range()];
            let right_text = &src[right.byte_range()];
            if left_text.contains("WTF_CSRF_ENABLED") && right_text == "False" {
                findings.push(make_finding(
                    self.id(),
                    self.severity(),
                    self.cwe(),
                    "Flask-WTF CSRF protection disabled — keep WTF_CSRF_ENABLED enabled",
                    node,
                    src,
                ));
            }
        });

        findings
    }
}

// ─── Rule 23: wtf-csrf-check-default-disabled ─────────────────────────────

pub struct WtfCsrfCheckDefaultDisabled;

impl Rule for WtfCsrfCheckDefaultDisabled {
    fn id(&self) -> &str {
        "py/wtf-csrf-check-default-disabled"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn cwe(&self) -> Option<&str> {
        Some("CWE-352")
    }
    fn description(&self) -> &str {
        "Flask-WTF default CSRF checks disabled in source code"
    }
    fn language(&self) -> Language {
        Language::Python
    }

    fn check(&self, source: &str, tree: &tree_sitter::Tree) -> Vec<Finding> {
        let mut findings = Vec::new();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            if node.kind() != "assignment" {
                return;
            }

            let (Some(left), Some(right)) = (
                node.child_by_field_name("left"),
                node.child_by_field_name("right"),
            ) else {
                return;
            };

            let left_text = &src[left.byte_range()];
            let right_text = &src[right.byte_range()];
            if left_text.contains("WTF_CSRF_CHECK_DEFAULT") && right_text == "False" {
                findings.push(make_finding(
                    self.id(),
                    self.severity(),
                    self.cwe(),
                    "Flask-WTF default CSRF checks disabled — keep WTF_CSRF_CHECK_DEFAULT enabled",
                    node,
                    src,
                ));
            }
        });

        findings
    }
}

// ─── Rule 24: django-allowed-hosts-wildcard ───────────────────────────────

pub struct DjangoAllowedHostsWildcard;

impl Rule for DjangoAllowedHostsWildcard {
    fn id(&self) -> &str {
        "py/django-allowed-hosts-wildcard"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn cwe(&self) -> Option<&str> {
        Some("CWE-346")
    }
    fn description(&self) -> &str {
        "Django ALLOWED_HOSTS allows all hosts"
    }
    fn language(&self) -> Language {
        Language::Python
    }

    fn check(&self, source: &str, tree: &tree_sitter::Tree) -> Vec<Finding> {
        let mut findings = Vec::new();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            if node.kind() != "assignment" {
                return;
            }

            let (Some(left), Some(right)) = (
                node.child_by_field_name("left"),
                node.child_by_field_name("right"),
            ) else {
                return;
            };

            let left_text = &src[left.byte_range()];
            let right_text = &src[right.byte_range()];
            if left_text.contains("ALLOWED_HOSTS") && right_text.contains("\"*\"") {
                findings.push(make_finding(
                    self.id(),
                    self.severity(),
                    self.cwe(),
                    "Django ALLOWED_HOSTS contains '*' — restrict hostnames explicitly to reduce host header abuse risk",
                    node,
                    src,
                ));
            }
        });

        findings
    }
}

// ─── Rule 25: secure-ssl-redirect-disabled ────────────────────────────────

pub struct SecureSslRedirectDisabled;

impl Rule for SecureSslRedirectDisabled {
    fn id(&self) -> &str {
        "py/secure-ssl-redirect-disabled"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn cwe(&self) -> Option<&str> {
        Some("CWE-319")
    }
    fn description(&self) -> &str {
        "Django SECURE_SSL_REDIRECT disabled in source code"
    }
    fn language(&self) -> Language {
        Language::Python
    }

    fn check(&self, source: &str, tree: &tree_sitter::Tree) -> Vec<Finding> {
        let mut findings = Vec::new();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            if node.kind() != "assignment" {
                return;
            }

            let (Some(left), Some(right)) = (
                node.child_by_field_name("left"),
                node.child_by_field_name("right"),
            ) else {
                return;
            };

            let left_text = &src[left.byte_range()];
            let right_text = &src[right.byte_range()];
            if left_text.contains("SECURE_SSL_REDIRECT") && right_text == "False" {
                findings.push(make_finding(
                    self.id(),
                    self.severity(),
                    self.cwe(),
                    "SECURE_SSL_REDIRECT = False — enable HTTPS redirect in production-facing Django deployments",
                    node,
                    src,
                ));
            }
        });

        findings
    }
}

// ─── Rule: taint-pickle-deserialization ────────────────────────────────────
//
// Proof-of-concept rule exercising the new per-function taint engine.
// Fires when Flask-style untrusted input reaches a pickle deserialization
// sink within a single function body. Coexists with `py/no-pickle`:
//
//   - `py/no-pickle` is the conservative direct-sink rule. It fires on any
//     call to `pickle.loads(...)` regardless of what the argument is.
//   - `py/taint-pickle-deserialization` fires only when the argument is
//     provably reachable from a known untrusted source within the same
//     function. Higher precision, lower recall.
//
// Scope and limitations are documented in `docs/taint-tracking.md` and in
// the doc comment on `python_taint`. Intraprocedural only, flow-insensitive,
// no sanitizers yet.

use crate::rules::python_taint::{self, python_taint_sources, NodeMatcher, TaintSpec};

/// Convenience: build a `Call` sink matcher where the canonical path and
/// the finding description are the same string. Used by every taint rule
/// below to keep spec definitions short.
fn call_sink(canonical: &str) -> NodeMatcher {
    NodeMatcher::Call {
        canonical: canonical.into(),
        description: canonical.into(),
    }
}

/// Shared mapper from engine-level `TaintFinding` to the public `Finding`
/// shape, parameterized by the rule's metadata and a description template
/// that receives the source and sink descriptions.
struct TaintRuleMeta<'a> {
    rule_id: &'a str,
    severity: Severity,
    cwe: Option<&'a str>,
    fix_suggestion: Option<&'a str>,
}

fn map_taint_findings(
    meta: &TaintRuleMeta<'_>,
    source: &str,
    tree: &tree_sitter::Tree,
    ctx: &FileContext<'_>,
    spec: &TaintSpec,
    format_description: impl Fn(&str, &str) -> String,
) -> Vec<Finding> {
    let raw = python_taint::analyze_tree(tree.root_node(), source, spec, ctx.python_aliases);
    raw.into_iter()
        .map(|t| Finding {
            rule_id: meta.rule_id.to_string(),
            severity: meta.severity,
            cwe: meta.cwe.map(|s| s.to_string()),
            description: format_description(&t.source_description, &t.sink_description),
            file: String::new(),
            line: t.sink_line,
            column: t.sink_column,
            end_line: t.sink_end_line,
            end_column: t.sink_end_column,
            snippet: get_source_line(source, t.sink_start_byte),
            source_line: Some(t.source_line),
            source_description: Some(t.source_description),
            sink_line: Some(t.sink_line),
            sink_description: Some(t.sink_description),
            fix_suggestion: meta.fix_suggestion.map(|s| s.to_string()),
        })
        .collect()
}

pub struct TaintPickleDeserialization;

impl TaintPickleDeserialization {
    fn spec() -> TaintSpec {
        TaintSpec {
            sources: python_taint_sources(),
            sinks: vec![
                call_sink("pickle.loads"),
                call_sink("pickle.load"),
                call_sink("cPickle.loads"),
                call_sink("cPickle.load"),
            ],
            sanitizers: vec![],
        }
    }
}

impl Rule for TaintPickleDeserialization {
    fn id(&self) -> &str {
        "py/taint-pickle-deserialization"
    }
    fn severity(&self) -> Severity {
        Severity::Critical
    }
    fn cwe(&self) -> Option<&str> {
        Some("CWE-502")
    }
    fn description(&self) -> &str {
        "Untrusted input reaches pickle deserialization sink"
    }
    fn language(&self) -> Language {
        Language::Python
    }

    fn check(&self, source: &str, tree: &tree_sitter::Tree) -> Vec<Finding> {
        self.check_with_context(source, tree, &FileContext::default())
    }

    fn check_with_context(
        &self,
        source: &str,
        tree: &tree_sitter::Tree,
        ctx: &FileContext<'_>,
    ) -> Vec<Finding> {
        let meta = TaintRuleMeta {
            rule_id: self.id(),
            severity: self.severity(),
            cwe: self.cwe(),
            fix_suggestion: Some(
                "Use `json` or `msgpack` instead of pickle for untrusted data: `json.loads(data)`",
            ),
        };
        map_taint_findings(&meta, source, tree, ctx, &Self::spec(), |src, sink| {
            format!(
                "{} reaches {} — untrusted input can execute arbitrary code via pickle",
                src, sink
            )
        })
    }
}

// ─── py/taint-eval ────────────────────────────────────────────────────────
pub struct TaintEvalFromRequest;

impl TaintEvalFromRequest {
    fn spec() -> TaintSpec {
        TaintSpec {
            sources: python_taint_sources(),
            sinks: vec![call_sink("eval"), call_sink("exec")],
            sanitizers: vec![],
        }
    }
}

impl Rule for TaintEvalFromRequest {
    fn id(&self) -> &str {
        "py/taint-eval"
    }
    fn severity(&self) -> Severity {
        Severity::Critical
    }
    fn cwe(&self) -> Option<&str> {
        Some("CWE-95")
    }
    fn description(&self) -> &str {
        "Untrusted input reaches eval/exec sink"
    }
    fn language(&self) -> Language {
        Language::Python
    }

    fn check(&self, source: &str, tree: &tree_sitter::Tree) -> Vec<Finding> {
        self.check_with_context(source, tree, &FileContext::default())
    }

    fn check_with_context(
        &self,
        source: &str,
        tree: &tree_sitter::Tree,
        ctx: &FileContext<'_>,
    ) -> Vec<Finding> {
        let meta = TaintRuleMeta {
            rule_id: self.id(),
            severity: self.severity(),
            cwe: self.cwe(),
            fix_suggestion: Some(
                "Use `ast.literal_eval()` for safe evaluation, or remove eval/exec entirely",
            ),
        };
        map_taint_findings(&meta, source, tree, ctx, &Self::spec(), |src, sink| {
            format!(
                "{} reaches {} — untrusted input can execute arbitrary Python code",
                src, sink
            )
        })
    }
}

// ─── py/taint-command-injection ──────────────────────────────────────────
pub struct TaintCommandInjectionFromRequest;

impl TaintCommandInjectionFromRequest {
    fn spec() -> TaintSpec {
        TaintSpec {
            sources: python_taint_sources(),
            sinks: vec![
                call_sink("os.system"),
                call_sink("os.popen"),
                call_sink("subprocess.run"),
                call_sink("subprocess.Popen"),
                call_sink("subprocess.call"),
                call_sink("subprocess.check_call"),
                call_sink("subprocess.check_output"),
            ],
            sanitizers: vec![],
        }
    }
}

impl Rule for TaintCommandInjectionFromRequest {
    fn id(&self) -> &str {
        "py/taint-command-injection"
    }
    fn severity(&self) -> Severity {
        Severity::Critical
    }
    fn cwe(&self) -> Option<&str> {
        Some("CWE-78")
    }
    fn description(&self) -> &str {
        "Untrusted input reaches OS command execution sink"
    }
    fn language(&self) -> Language {
        Language::Python
    }

    fn check(&self, source: &str, tree: &tree_sitter::Tree) -> Vec<Finding> {
        self.check_with_context(source, tree, &FileContext::default())
    }

    fn check_with_context(
        &self,
        source: &str,
        tree: &tree_sitter::Tree,
        ctx: &FileContext<'_>,
    ) -> Vec<Finding> {
        let meta = TaintRuleMeta {
            rule_id: self.id(),
            severity: self.severity(),
            cwe: self.cwe(),
            fix_suggestion: Some("Use `shlex.quote()` to escape arguments, or pass a list to `subprocess.run([...])` instead of a shell string"),
        };
        map_taint_findings(&meta, source, tree, ctx, &Self::spec(), |src, sink| {
            format!(
                "{} reaches {} — untrusted input can inject OS commands",
                src, sink
            )
        })
    }
}

// ─── py/taint-ssrf ────────────────────────────────────────────────────────
pub struct TaintSsrfFromRequest;

impl TaintSsrfFromRequest {
    fn spec() -> TaintSpec {
        TaintSpec {
            sources: python_taint_sources(),
            sinks: vec![
                call_sink("urllib.request.urlopen"),
                call_sink("requests.get"),
                call_sink("requests.post"),
                call_sink("requests.put"),
                call_sink("requests.delete"),
                call_sink("requests.request"),
                call_sink("httpx.get"),
                call_sink("httpx.post"),
            ],
            sanitizers: vec![],
        }
    }
}

impl Rule for TaintSsrfFromRequest {
    fn id(&self) -> &str {
        "py/taint-ssrf"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn cwe(&self) -> Option<&str> {
        Some("CWE-918")
    }
    fn description(&self) -> &str {
        "Untrusted input reaches outbound HTTP sink (potential SSRF)"
    }
    fn language(&self) -> Language {
        Language::Python
    }

    fn check(&self, source: &str, tree: &tree_sitter::Tree) -> Vec<Finding> {
        self.check_with_context(source, tree, &FileContext::default())
    }

    fn check_with_context(
        &self,
        source: &str,
        tree: &tree_sitter::Tree,
        ctx: &FileContext<'_>,
    ) -> Vec<Finding> {
        let meta = TaintRuleMeta {
            rule_id: self.id(),
            severity: self.severity(),
            cwe: self.cwe(),
            fix_suggestion: Some(
                "Validate URLs against an allowlist of permitted hosts before making requests",
            ),
        };
        map_taint_findings(&meta, source, tree, ctx, &Self::spec(), |src, sink| {
            format!(
                "{} reaches {} — untrusted input can drive server-side request forgery",
                src, sink
            )
        })
    }
}

// ─── py/taint-yaml-load ──────────────────────────────────────────────────
pub struct TaintYamlLoadFromRequest;

impl TaintYamlLoadFromRequest {
    fn spec() -> TaintSpec {
        TaintSpec {
            sources: python_taint_sources(),
            sinks: vec![
                call_sink("yaml.load"),
                call_sink("yaml.unsafe_load"),
                call_sink("yaml.full_load"),
            ],
            sanitizers: vec![],
        }
    }
}

impl Rule for TaintYamlLoadFromRequest {
    fn id(&self) -> &str {
        "py/taint-yaml-load"
    }
    fn severity(&self) -> Severity {
        Severity::Critical
    }
    fn cwe(&self) -> Option<&str> {
        Some("CWE-502")
    }
    fn description(&self) -> &str {
        "Untrusted input reaches unsafe YAML loader"
    }
    fn language(&self) -> Language {
        Language::Python
    }

    fn check(&self, source: &str, tree: &tree_sitter::Tree) -> Vec<Finding> {
        self.check_with_context(source, tree, &FileContext::default())
    }

    fn check_with_context(
        &self,
        source: &str,
        tree: &tree_sitter::Tree,
        ctx: &FileContext<'_>,
    ) -> Vec<Finding> {
        let meta = TaintRuleMeta {
            rule_id: self.id(),
            severity: self.severity(),
            cwe: self.cwe(),
            fix_suggestion: Some(
                "Use `yaml.safe_load()` instead of `yaml.load()` for untrusted input",
            ),
        };
        map_taint_findings(&meta, source, tree, ctx, &Self::spec(), |src, sink| {
            format!(
                    "{} reaches {} — untrusted input can execute arbitrary code via YAML deserialization",
                    src, sink
                )
        })
    }
}

// ─── py/taint-sql-injection ──────────────────────────────────────────────
pub struct TaintSqlInjectionFromRequest;

impl TaintSqlInjectionFromRequest {
    fn spec() -> TaintSpec {
        TaintSpec {
            sources: python_taint_sources(),
            // DB execute APIs can live on any object (`cursor`, `conn`,
            // `db`, `session`…). Rather than enumerate every plausible
            // receiver name, match the final method name via `MethodName`.
            // This intentionally over-approximates — any `.execute(...)`
            // called with tainted input is flagged.
            sinks: vec![
                NodeMatcher::MethodName {
                    method: "execute".into(),
                    description: "cursor/connection.execute".into(),
                },
                NodeMatcher::MethodName {
                    method: "executemany".into(),
                    description: "cursor/connection.executemany".into(),
                },
                NodeMatcher::MethodName {
                    method: "executescript".into(),
                    description: "sqlite3.Cursor.executescript".into(),
                },
            ],
            sanitizers: vec![],
        }
    }
}

impl Rule for TaintSqlInjectionFromRequest {
    fn id(&self) -> &str {
        "py/taint-sql-injection"
    }
    fn severity(&self) -> Severity {
        Severity::Critical
    }
    fn cwe(&self) -> Option<&str> {
        Some("CWE-89")
    }
    fn description(&self) -> &str {
        "Untrusted input reaches DB execute sink"
    }
    fn language(&self) -> Language {
        Language::Python
    }

    fn check(&self, source: &str, tree: &tree_sitter::Tree) -> Vec<Finding> {
        self.check_with_context(source, tree, &FileContext::default())
    }

    fn check_with_context(
        &self,
        source: &str,
        tree: &tree_sitter::Tree,
        ctx: &FileContext<'_>,
    ) -> Vec<Finding> {
        let meta = TaintRuleMeta {
            rule_id: self.id(),
            severity: self.severity(),
            cwe: self.cwe(),
            fix_suggestion: Some("Use parameterized queries: `cur.execute(\"SELECT * FROM users WHERE name = ?\", (name,))`"),
        };
        map_taint_findings(&meta, source, tree, ctx, &Self::spec(), |src, sink| {
            format!("{} reaches {} — untrusted input can inject SQL", src, sink)
        })
    }
}
