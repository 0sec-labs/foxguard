use crate::rules::common::{make_finding, walk_tree};
use crate::rules::Rule;
use crate::{Finding, Language, Severity};
use regex::Regex;

/// Returns `true` if a tree-sitter `string` node contains interpolation
/// children (i.e., `#{}` segments). Plain string literals like `"ls -la"`
/// return `false`; strings like `"#{cmd}"` return `true`.
fn has_interpolation(string_node: tree_sitter::Node) -> bool {
    let mut cursor = string_node.walk();
    for child in string_node.children(&mut cursor) {
        // tree-sitter-ruby uses "interpolation" for `#{}` segments
        if child.kind() == "interpolation" {
            return true;
        }
    }
    false
}

// ─── Rule 1: no-eval ──────────────────────────────────────────────────────────

pub struct NoEval;

impl Rule for NoEval {
    fn id(&self) -> &str {
        "rb/no-eval"
    }
    fn severity(&self) -> Severity {
        Severity::Critical
    }
    fn cwe(&self) -> Option<&str> {
        Some("CWE-95")
    }
    fn description(&self) -> &str {
        "Use of eval or similar dynamic code execution"
    }
    fn language(&self) -> Language {
        Language::Ruby
    }

    fn check(&self, source: &str, tree: &tree_sitter::Tree) -> Vec<Finding> {
        let mut findings = Vec::new();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            let method_name = match node.kind() {
                "call" => node
                    .child_by_field_name("method")
                    .map(|m| &src[m.byte_range()]),
                "command" => node
                    .child_by_field_name("name")
                    .map(|m| &src[m.byte_range()]),
                _ => None,
            };

            if let Some(name) = method_name {
                // Only flag eval and instance_eval — class_eval/module_eval are
                // standard Ruby metaprogramming patterns used by every framework
                if name == "eval" || name == "instance_eval" {
                    findings.push(make_finding(
                        self.id(),
                        self.severity(),
                        self.cwe(),
                        &format!(
                            "{} executes arbitrary code — avoid dynamic evaluation",
                            name
                        ),
                        node,
                        src,
                    ));
                }
            }
        });
        findings
    }
}

// ─── Rule 2: no-command-injection ─────────────────────────────────────────────

pub struct NoCommandInjection;

impl Rule for NoCommandInjection {
    fn id(&self) -> &str {
        "rb/no-command-injection"
    }
    fn severity(&self) -> Severity {
        Severity::Critical
    }
    fn cwe(&self) -> Option<&str> {
        Some("CWE-78")
    }
    fn description(&self) -> &str {
        "Potential command injection via system/exec/spawn or backtick execution"
    }
    fn language(&self) -> Language {
        Language::Ruby
    }

    fn check(&self, source: &str, tree: &tree_sitter::Tree) -> Vec<Finding> {
        let mut findings = Vec::new();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            // Detect backtick/subshell execution
            if node.kind() == "subshell" {
                findings.push(make_finding(
                    self.id(),
                    self.severity(),
                    self.cwe(),
                    "Backtick/subshell command execution — risk of command injection",
                    node,
                    src,
                ));
                return;
            }

            let method_name = match node.kind() {
                "call" => node
                    .child_by_field_name("method")
                    .map(|m| &src[m.byte_range()]),
                "command" => node
                    .child_by_field_name("name")
                    .map(|m| &src[m.byte_range()]),
                _ => None,
            };

            if let Some(name) = method_name {
                if name == "system" || name == "exec" || name == "spawn" {
                    // Check if the first argument is a plain string literal
                    // (no interpolation). If so, skip — it's safe.
                    let first_arg = node
                        .child_by_field_name("arguments")
                        .and_then(|a| a.named_child(0))
                        .or_else(|| {
                            // For command-style calls like `system "ls"`,
                            // args are in an argument_list child.
                            node.named_child(1).and_then(|c| {
                                if c.kind() == "argument_list" {
                                    c.named_child(0)
                                } else {
                                    Some(c)
                                }
                            })
                        });

                    let is_safe_literal = first_arg.is_some_and(|arg| {
                        // A `string` node without any `string_content` siblings
                        // that are interpolation is a plain literal.
                        arg.kind() == "string" && !has_interpolation(arg)
                    });

                    if !is_safe_literal {
                        findings.push(make_finding(
                            self.id(),
                            self.severity(),
                            self.cwe(),
                            &format!(
                                "{} called — risk of command injection with dynamic arguments",
                                name
                            ),
                            node,
                            src,
                        ));
                    }
                }
            }

            // Detect %x strings (parsed as subshell or string node with %x prefix)
            if node.kind() == "string" {
                let text = &src[node.byte_range()];
                if text.starts_with("%x") {
                    findings.push(make_finding(
                        self.id(),
                        self.severity(),
                        self.cwe(),
                        "%x command execution — risk of command injection",
                        node,
                        src,
                    ));
                }
            }
        });
        findings
    }
}

// ─── Rule 3: no-sql-injection ─────────────────────────────────────────────────

pub struct NoSqlInjection;

impl Rule for NoSqlInjection {
    fn id(&self) -> &str {
        "rb/no-sql-injection"
    }
    fn severity(&self) -> Severity {
        Severity::Critical
    }
    fn cwe(&self) -> Option<&str> {
        Some("CWE-89")
    }
    fn description(&self) -> &str {
        "Potential SQL injection via string interpolation in query methods"
    }
    fn language(&self) -> Language {
        Language::Ruby
    }

    fn check(&self, source: &str, tree: &tree_sitter::Tree) -> Vec<Finding> {
        let mut findings = Vec::new();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            let method_name = match node.kind() {
                "call" => node
                    .child_by_field_name("method")
                    .map(|m| &src[m.byte_range()]),
                "command" => node
                    .child_by_field_name("name")
                    .map(|m| &src[m.byte_range()]),
                _ => None,
            };

            if let Some(name) = method_name {
                if name == "where" || name == "find_by_sql" || name == "execute" {
                    // Check if any argument contains string interpolation
                    let node_text = &src[node.byte_range()];
                    if node_text.contains("#{") {
                        findings.push(make_finding(
                            self.id(),
                            self.severity(),
                            self.cwe(),
                            &format!(
                                "String interpolation in {} — use parameterized queries to prevent SQL injection",
                                name
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

// ─── Rule 4: no-mass-assignment ───────────────────────────────────────────────

pub struct NoMassAssignment;

impl Rule for NoMassAssignment {
    fn id(&self) -> &str {
        "rb/no-mass-assignment"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn cwe(&self) -> Option<&str> {
        Some("CWE-915")
    }
    fn description(&self) -> &str {
        "Mass assignment via permit! allows all parameters"
    }
    fn language(&self) -> Language {
        Language::Ruby
    }

    fn check(&self, source: &str, tree: &tree_sitter::Tree) -> Vec<Finding> {
        let mut findings = Vec::new();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            if node.kind() == "call" {
                if let Some(method) = node.child_by_field_name("method") {
                    let name = &src[method.byte_range()];
                    if name == "permit!" {
                        findings.push(make_finding(
                            self.id(),
                            self.severity(),
                            self.cwe(),
                            "permit! allows all parameters — use permit(:field1, :field2) to whitelist",
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

// ─── Rule 5: no-unsafe-deserialization ────────────────────────────────────────

pub struct NoUnsafeDeserialization;

impl Rule for NoUnsafeDeserialization {
    fn id(&self) -> &str {
        "rb/no-unsafe-deserialization"
    }
    fn severity(&self) -> Severity {
        Severity::Critical
    }
    fn cwe(&self) -> Option<&str> {
        Some("CWE-502")
    }
    fn description(&self) -> &str {
        "Unsafe deserialization via Marshal.load or YAML.load"
    }
    fn language(&self) -> Language {
        Language::Ruby
    }

    fn check(&self, source: &str, tree: &tree_sitter::Tree) -> Vec<Finding> {
        let mut findings = Vec::new();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            if node.kind() == "call" {
                if let (Some(receiver), Some(method)) = (
                    node.child_by_field_name("receiver"),
                    node.child_by_field_name("method"),
                ) {
                    let recv = &src[receiver.byte_range()];
                    let meth = &src[method.byte_range()];

                    if (recv == "Marshal" && meth == "load")
                        || (recv == "YAML" && (meth == "load" || meth == "unsafe_load"))
                    {
                        findings.push(make_finding(
                            self.id(),
                            self.severity(),
                            self.cwe(),
                            &format!(
                                "{}.{} can execute arbitrary code — use YAML.safe_load or safer alternatives",
                                recv, meth
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

// ─── Rule 6: no-open-redirect ─────────────────────────────────────────────────

pub struct NoOpenRedirect;

impl Rule for NoOpenRedirect {
    fn id(&self) -> &str {
        "rb/no-open-redirect"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn cwe(&self) -> Option<&str> {
        Some("CWE-601")
    }
    fn description(&self) -> &str {
        "Potential open redirect via redirect_to with dynamic argument"
    }
    fn language(&self) -> Language {
        Language::Ruby
    }

    fn check(&self, source: &str, tree: &tree_sitter::Tree) -> Vec<Finding> {
        let mut findings = Vec::new();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            let is_redirect = match node.kind() {
                "call" => node
                    .child_by_field_name("method")
                    .map(|m| &src[m.byte_range()] == "redirect_to")
                    .unwrap_or(false),
                "command" => node
                    .child_by_field_name("name")
                    .map(|m| &src[m.byte_range()] == "redirect_to")
                    .unwrap_or(false),
                _ => false,
            };

            if is_redirect {
                // Check if the argument is a string literal (safe) or dynamic (unsafe)
                let node_text = &src[node.byte_range()];
                // If it contains variable interpolation or is not a simple string, flag it
                let has_literal_only = node_text.contains("redirect_to \"")
                    || node_text.contains("redirect_to '")
                    || node_text.contains("redirect_to(\"")
                    || node_text.contains("redirect_to('");

                if !has_literal_only {
                    findings.push(make_finding(
                        self.id(),
                        self.severity(),
                        self.cwe(),
                        "redirect_to with dynamic argument — validate URL to prevent open redirect",
                        node,
                        src,
                    ));
                }
            }
        });
        findings
    }
}

// ─── Rule 7: no-csrf-skip ────────────────────────────────────────────────────

pub struct NoCsrfSkip;

impl Rule for NoCsrfSkip {
    fn id(&self) -> &str {
        "rb/no-csrf-skip"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn cwe(&self) -> Option<&str> {
        Some("CWE-352")
    }
    fn description(&self) -> &str {
        "CSRF protection disabled via skip_before_action"
    }
    fn language(&self) -> Language {
        Language::Ruby
    }

    fn check(&self, source: &str, tree: &tree_sitter::Tree) -> Vec<Finding> {
        let mut findings = Vec::new();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            let method_name = match node.kind() {
                "call" => node
                    .child_by_field_name("method")
                    .map(|m| &src[m.byte_range()]),
                "command" => node
                    .child_by_field_name("name")
                    .map(|m| &src[m.byte_range()]),
                _ => None,
            };

            if let Some(name) = method_name {
                if name == "skip_before_action" {
                    let text = &src[node.byte_range()];
                    if text.contains("verify_authenticity_token") {
                        findings.push(make_finding(
                            self.id(),
                            self.severity(),
                            self.cwe(),
                            "skip_before_action :verify_authenticity_token disables CSRF protection",
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

// ─── Rule 8: no-html-safe ─────────────────────────────────────────────────────

pub struct NoHtmlSafe;

impl Rule for NoHtmlSafe {
    fn id(&self) -> &str {
        "rb/no-html-safe"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn cwe(&self) -> Option<&str> {
        Some("CWE-79")
    }
    fn description(&self) -> &str {
        "Potential XSS via html_safe or raw()"
    }
    fn language(&self) -> Language {
        Language::Ruby
    }

    fn check(&self, source: &str, tree: &tree_sitter::Tree) -> Vec<Finding> {
        let mut findings = Vec::new();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            // Detect .html_safe on non-literal receivers
            if node.kind() == "call" {
                if let Some(method) = node.child_by_field_name("method") {
                    let name = &src[method.byte_range()];
                    if name == "html_safe" {
                        if let Some(receiver) = node.child_by_field_name("receiver") {
                            // Only flag non-string-literal receivers
                            if receiver.kind() != "string" {
                                findings.push(make_finding(
                                    self.id(),
                                    self.severity(),
                                    self.cwe(),
                                    ".html_safe on dynamic content — risk of XSS",
                                    node,
                                    src,
                                ));
                            }
                        }
                    }
                }
            }

            // Detect raw() calls
            let is_raw = match node.kind() {
                "call" => node
                    .child_by_field_name("method")
                    .map(|m| &src[m.byte_range()] == "raw")
                    .unwrap_or(false),
                "command" => node
                    .child_by_field_name("name")
                    .map(|m| &src[m.byte_range()] == "raw")
                    .unwrap_or(false),
                _ => false,
            };

            if is_raw {
                findings.push(make_finding(
                    self.id(),
                    self.severity(),
                    self.cwe(),
                    "raw() bypasses HTML escaping — risk of XSS",
                    node,
                    src,
                ));
            }
        });
        findings
    }
}

// ─── Rule 9: no-hardcoded-secret ──────────────────────────────────────────────

pub struct NoHardcodedSecret;

impl Rule for NoHardcodedSecret {
    fn id(&self) -> &str {
        "rb/no-hardcoded-secret"
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
        Language::Ruby
    }

    fn check(&self, source: &str, tree: &tree_sitter::Tree) -> Vec<Finding> {
        let mut findings = Vec::new();
        let secret_pattern =
            Regex::new(r"(?i)(password|secret|api_?key|token|auth|credential|private_?key)")
                .unwrap();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            // assignment: variable = "hardcoded"
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
                            .trim_start_matches(['"', '\''])
                            .trim_end_matches(['"', '\'']);
                        if inner.len() >= 4 {
                            findings.push(make_finding(
                                self.id(),
                                self.severity(),
                                self.cwe(),
                                &format!(
                                    "Hardcoded secret in '{}' — use environment variables",
                                    left_text.trim()
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

// ─── Rule 10: no-ssrf ────────────────────────────────────────────────────────

pub struct NoSsrf;

impl Rule for NoSsrf {
    fn id(&self) -> &str {
        "rb/no-ssrf"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn cwe(&self) -> Option<&str> {
        Some("CWE-918")
    }
    fn description(&self) -> &str {
        "Potential SSRF via dynamic outbound HTTP request URL"
    }
    fn language(&self) -> Language {
        Language::Ruby
    }

    fn check(&self, source: &str, tree: &tree_sitter::Tree) -> Vec<Finding> {
        let mut findings = Vec::new();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            match node.kind() {
                // Calls with a receiver: URI.open(...), Net::HTTP.get(...),
                // HTTParty.get(...), Faraday.get(...), RestClient.get(...)
                // Also bare calls: open(url), open url
                "call" => {
                    let method = node.child_by_field_name("method");
                    let receiver = node.child_by_field_name("receiver");

                    let http_methods = ["get", "post", "put", "patch", "delete", "head"];

                    let (is_ssrf_call, label) = match (receiver, method) {
                        (Some(recv_node), Some(meth_node)) => {
                            let recv = &src[recv_node.byte_range()];
                            let meth = &src[meth_node.byte_range()];
                            let matched = (recv == "URI" && meth == "open")
                                || (recv == "Net::HTTP" && http_methods.contains(&meth))
                                || (recv == "HTTParty" && http_methods.contains(&meth))
                                || (recv == "Faraday" && http_methods.contains(&meth))
                                || (recv == "RestClient" && http_methods.contains(&meth));
                            (matched, format!("{}.{}", recv, meth))
                        }
                        // Bare call: open url  (no receiver, method = "open")
                        (None, Some(meth_node)) => {
                            let meth = &src[meth_node.byte_range()];
                            (meth == "open", "open".to_string())
                        }
                        _ => (false, String::new()),
                    };

                    if !is_ssrf_call {
                        return;
                    }

                    // Check if the first argument is dynamic (not a string literal)
                    // Arguments can be in an "arguments" field or as argument_list named child
                    let first_arg = node
                        .child_by_field_name("arguments")
                        .and_then(|a| a.named_child(0))
                        .or_else(|| {
                            // For bare calls like `open url`, args are in an argument_list child
                            node.named_child(1).and_then(|c| {
                                if c.kind() == "argument_list" {
                                    c.named_child(0)
                                } else {
                                    Some(c)
                                }
                            })
                        });

                    if let Some(arg) = first_arg {
                        if arg.kind() != "string" {
                            let mut finding = make_finding(
                                self.id(),
                                self.severity(),
                                self.cwe(),
                                &format!(
                                    "{} called with dynamic URL — validate against an allowlist to prevent SSRF",
                                    label
                                ),
                                node,
                                src,
                            );
                            finding.fix_suggestion = Some(
                                "Validate URLs against an allowlist before making HTTP requests"
                                    .to_string(),
                            );
                            findings.push(finding);
                        }
                    }
                }

                // Command-style bare calls (e.g. open url without parens)
                "command" => {
                    let Some(name_node) = node.child_by_field_name("name") else {
                        return;
                    };
                    let name = &src[name_node.byte_range()];
                    if name != "open" {
                        return;
                    }

                    // For command nodes, check if the argument is a string literal
                    let is_literal = if let Some(arg) = node.named_child(1) {
                        arg.kind() == "string"
                            || (arg.kind() == "argument_list"
                                && arg.named_child(0).is_some_and(|a| a.kind() == "string"))
                    } else {
                        false
                    };

                    if !is_literal {
                        let mut finding = make_finding(
                            self.id(),
                            self.severity(),
                            self.cwe(),
                            "open called with dynamic URL — validate against an allowlist to prevent SSRF",
                            node,
                            src,
                        );
                        finding.fix_suggestion = Some(
                            "Validate URLs against an allowlist before making HTTP requests"
                                .to_string(),
                        );
                        findings.push(finding);
                    }
                }
                _ => {}
            }
        });
        findings
    }
}

// ─── Rule 11: no-path-traversal ──────────────────────────────────────────────

pub struct NoPathTraversal;

impl Rule for NoPathTraversal {
    fn id(&self) -> &str {
        "rb/no-path-traversal"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn cwe(&self) -> Option<&str> {
        Some("CWE-22")
    }
    fn description(&self) -> &str {
        "Potential path traversal via dynamic file path"
    }
    fn language(&self) -> Language {
        Language::Ruby
    }

    fn check(&self, source: &str, tree: &tree_sitter::Tree) -> Vec<Finding> {
        let mut findings = Vec::new();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            match node.kind() {
                // Calls with a receiver: File.read(...), File.open(...),
                // IO.read(...), File.write(...), FileUtils.cp(...)
                // Also bare calls: send_file(path), send_file path
                "call" => {
                    let method = node.child_by_field_name("method");
                    let receiver = node.child_by_field_name("receiver");

                    let (is_path_sink, label) = match (receiver, method) {
                        (Some(recv_node), Some(meth_node)) => {
                            let recv = &src[recv_node.byte_range()];
                            let meth = &src[meth_node.byte_range()];
                            let matched = (recv == "File"
                                && (meth == "read"
                                    || meth == "open"
                                    || meth == "write"
                                    || meth == "delete"
                                    || meth == "readlines"
                                    || meth == "binread"))
                                || (recv == "IO" && (meth == "read" || meth == "readlines"))
                                || (recv == "FileUtils"
                                    && (meth == "cp"
                                        || meth == "mv"
                                        || meth == "rm"
                                        || meth == "mkdir_p"));
                            (matched, format!("{}.{}", recv, meth))
                        }
                        // Bare call: send_file path  (no receiver)
                        (None, Some(meth_node)) => {
                            let meth = &src[meth_node.byte_range()];
                            (meth == "send_file", "send_file".to_string())
                        }
                        _ => (false, String::new()),
                    };

                    if !is_path_sink {
                        return;
                    }

                    // Check if the first argument is dynamic (not a string literal)
                    let first_arg = node
                        .child_by_field_name("arguments")
                        .and_then(|a| a.named_child(0))
                        .or_else(|| {
                            node.named_child(1).and_then(|c| {
                                if c.kind() == "argument_list" {
                                    c.named_child(0)
                                } else {
                                    Some(c)
                                }
                            })
                        });

                    if let Some(arg) = first_arg {
                        if arg.kind() != "string" {
                            let mut finding = make_finding(
                                self.id(),
                                self.severity(),
                                self.cwe(),
                                &format!(
                                    "{} called with dynamic path — validate to prevent path traversal",
                                    label
                                ),
                                node,
                                src,
                            );
                            finding.fix_suggestion = Some(
                                "Validate file paths and ensure they don't escape the intended directory"
                                    .to_string(),
                            );
                            findings.push(finding);
                        }
                    }
                }

                // Command-style bare calls (e.g. send_file path without parens)
                "command" => {
                    let Some(name_node) = node.child_by_field_name("name") else {
                        return;
                    };
                    let name = &src[name_node.byte_range()];
                    if name != "send_file" {
                        return;
                    }

                    let is_literal = if let Some(arg) = node.named_child(1) {
                        arg.kind() == "string"
                            || (arg.kind() == "argument_list"
                                && arg.named_child(0).is_some_and(|a| a.kind() == "string"))
                    } else {
                        false
                    };

                    if !is_literal {
                        let mut finding = make_finding(
                            self.id(),
                            self.severity(),
                            self.cwe(),
                            "send_file called with dynamic path — validate to prevent path traversal",
                            node,
                            src,
                        );
                        finding.fix_suggestion = Some(
                            "Validate file paths and ensure they don't escape the intended directory"
                                .to_string(),
                        );
                        findings.push(finding);
                    }
                }
                _ => {}
            }
        });
        findings
    }
}

// ─── Rule 12: no-weak-crypto ──────────────────────────────────────────────────

pub struct NoWeakCrypto;

impl Rule for NoWeakCrypto {
    fn id(&self) -> &str {
        "rb/no-weak-crypto"
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
        Language::Ruby
    }

    fn check(&self, source: &str, tree: &tree_sitter::Tree) -> Vec<Finding> {
        let mut findings = Vec::new();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            // Detect Digest::MD5, Digest::SHA1 via scope_resolution nodes
            if node.kind() == "scope_resolution" {
                let text = &src[node.byte_range()];
                if text == "Digest::MD5" || text == "Digest::SHA1" {
                    let algo = if text.contains("MD5") { "MD5" } else { "SHA1" };
                    findings.push(make_finding(
                        self.id(),
                        self.severity(),
                        self.cwe(),
                        &format!(
                            "{} is cryptographically weak — use SHA-256 or stronger",
                            algo
                        ),
                        node,
                        src,
                    ));
                }
            }
        });
        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tree_sitter::Parser;

    fn parse_ruby(source: &str) -> tree_sitter::Tree {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_ruby::LANGUAGE.into())
            .unwrap();
        parser.parse(source, None).unwrap()
    }

    #[allow(dead_code)]
    fn dump_tree(node: tree_sitter::Node, src: &str, depth: usize) {
        let indent = "  ".repeat(depth);
        let text = &src[node.byte_range()];
        let short = if text.len() > 60 { &text[..60] } else { text };
        eprintln!(
            "{}kind={:?} named_children={} text={:?}",
            indent,
            node.kind(),
            node.named_child_count(),
            short.replace('\n', "\\n")
        );
        for i in 0..node.named_child_count() {
            if let Some(c) = node.named_child(i) {
                dump_tree(c, src, depth + 1);
            }
        }
    }

    #[test]
    fn debug_open_url_tree() {
        let source = "open url\nsend_file path\n";
        let tree = parse_ruby(source);
        dump_tree(tree.root_node(), source, 0);
    }

    #[test]
    fn test_ssrf_detects_all_patterns() {
        let source = "URI.open(user_input)\nNet::HTTP.get(user_url)\nHTTParty.get(url)\nFaraday.get(url)\nRestClient.get(url)\nopen url\n";
        let tree = parse_ruby(source);
        let rule = NoSsrf;
        let findings = rule.check(source, &tree);
        assert_eq!(
            findings.len(),
            6,
            "Expected 6 SSRF findings, got {}",
            findings.len()
        );
    }

    #[test]
    fn test_path_traversal_detects_all_patterns() {
        let source = "File.read(user_input)\nFile.open(user_input)\nIO.read(user_input)\nFile.write(path, data)\nFileUtils.cp(src, dst)\nsend_file path\n";
        let tree = parse_ruby(source);
        let rule = NoPathTraversal;
        let findings = rule.check(source, &tree);
        assert_eq!(
            findings.len(),
            6,
            "Expected 6 path traversal findings, got {}",
            findings.len()
        );
    }

    #[test]
    fn test_command_injection_skips_plain_string_literal() {
        let source = r#"system("ls -la")"#;
        let tree = parse_ruby(source);
        let rule = NoCommandInjection;
        let findings = rule.check(source, &tree);
        assert_eq!(
            findings.len(),
            0,
            "system() with a plain string literal should NOT fire"
        );
    }

    #[test]
    fn test_command_injection_fires_on_variable() {
        let source = "system(user_input)";
        let tree = parse_ruby(source);
        let rule = NoCommandInjection;
        let findings = rule.check(source, &tree);
        assert_eq!(
            findings.len(),
            1,
            "system() with a variable argument should fire"
        );
    }

    #[test]
    fn test_command_injection_fires_on_interpolated_string() {
        let source = r##"system("#{cmd}")"##;
        let tree = parse_ruby(source);
        let rule = NoCommandInjection;
        let findings = rule.check(source, &tree);
        assert_eq!(
            findings.len(),
            1,
            "system() with an interpolated string should fire"
        );
    }

    #[test]
    fn test_command_injection_skips_exec_with_literal() {
        let source = r#"exec("echo hello")"#;
        let tree = parse_ruby(source);
        let rule = NoCommandInjection;
        let findings = rule.check(source, &tree);
        assert_eq!(
            findings.len(),
            0,
            "exec() with a plain string literal should NOT fire"
        );
    }
}
