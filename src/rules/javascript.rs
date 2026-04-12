use crate::impl_rule;
use crate::rules::common::{get_source_line, make_finding, walk_tree};
use crate::rules::FileContext;
use crate::{Finding, Language, Severity};
use regex::Regex;

// ─── Rule 1: no-eval ─────────────────────────────────────────────────────────

pub struct NoEval;

impl_rule! {
    NoEval,
    id = "js/no-eval",
    severity = Severity::Critical,
    cwe = Some("CWE-95"),
    description = "Use of eval() allows arbitrary code execution",
    language = Language::JavaScript,
    fn check(_self, source, tree) {

        let mut findings = Vec::new();
        walk_tree(tree.root_node(), source, &mut |node, src| {
            // Look for call_expression where the function is `eval`
            if node.kind() == "call_expression" {
                if let Some(func) = node.child_by_field_name("function") {
                    let func_text = &src[func.byte_range()];
                    if func_text == "eval" {
                        findings.push(make_finding(
                            _self.id(),
                            _self.severity(),
                            _self.cwe(),
                            _self.description(),
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

impl_rule! {
    NoHardcodedSecret,
    id = "js/no-hardcoded-secret",
    severity = Severity::High,
    cwe = Some("CWE-798"),
    description = "Hardcoded secret or credential detected",
    language = Language::JavaScript,
    fn check(_self, source, tree) {

        let mut findings = Vec::new();
        let secret_pattern =
            Regex::new(r"(?i)(password|secret|api_?key|token|auth|credential|private_?key)")
                .unwrap();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            // variable_declarator: const password = "hardcoded"
            if node.kind() == "variable_declarator" {
                if let (Some(name_node), Some(value_node)) = (
                    node.child_by_field_name("name"),
                    node.child_by_field_name("value"),
                ) {
                    let name = &src[name_node.byte_range()];
                    let value_kind = value_node.kind();
                    if secret_pattern.is_match(name)
                        && (value_kind == "string" || value_kind == "template_string")
                    {
                        let val = &src[value_node.byte_range()];
                        // Skip empty strings and short placeholders
                        let inner = val.trim_matches(|c| c == '"' || c == '\'' || c == '`');
                        if inner.len() >= 4 {
                            findings.push(make_finding(
                                _self.id(),
                                _self.severity(),
                                _self.cwe(),
                                &format!(
                                    "Hardcoded secret in variable '{}' — avoid committing credentials",
                                    name
                                ),
                                node,
                                src,
                            ));
                        }
                    }
                }
            }

            // assignment_expression: obj.password = "hardcoded"
            if node.kind() == "assignment_expression" {
                if let (Some(left), Some(right)) = (
                    node.child_by_field_name("left"),
                    node.child_by_field_name("right"),
                ) {
                    let left_text = &src[left.byte_range()];
                    let right_kind = right.kind();
                    if secret_pattern.is_match(left_text)
                        && (right_kind == "string" || right_kind == "template_string")
                    {
                        let val = &src[right.byte_range()];
                        let inner = val.trim_matches(|c| c == '"' || c == '\'' || c == '`');
                        if inner.len() >= 4 {
                            findings.push(make_finding(
                                _self.id(),
                                _self.severity(),
                                _self.cwe(),
                                &format!(
                                    "Hardcoded secret assigned to '{}' — use environment variables instead",
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

impl_rule! {
    NoSqlInjection,
    id = "js/no-sql-injection",
    severity = Severity::Critical,
    cwe = Some("CWE-89"),
    description = "Potential SQL injection via string concatenation or template literal",
    language = Language::JavaScript,
    fn check(_self, source, tree) {

        let mut findings = Vec::new();
        // Require SQL keyword followed by SQL structure (FROM, INTO, SET, WHERE, TABLE, VALUES)
        // This avoids matching plain English like res.send('delete ' + name)
        let sql_pattern = Regex::new(
            r"(?i)(SELECT\s+.{0,40}\s+FROM|INSERT\s+INTO|UPDATE\s+.{0,40}\s+SET|DELETE\s+FROM|DROP\s+TABLE|ALTER\s+TABLE|CREATE\s+TABLE|EXEC\s+)"
        ).unwrap();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            // Detect: query("SELECT * FROM users WHERE id = " + userId)
            if node.kind() == "binary_expression" {
                if let Some(op) = node.child_by_field_name("operator") {
                    if &src[op.byte_range()] == "+" {
                        if let Some(left) = node.child_by_field_name("left") {
                            let left_text = &src[left.byte_range()];
                            if (left.kind() == "string" || left.kind() == "template_string")
                                && sql_pattern.is_match(left_text)
                            {
                                findings.push(make_finding(
                                    _self.id(),
                                    _self.severity(),
                                    _self.cwe(),
                                    "SQL query built with string concatenation — use parameterized queries",
                                    node,
                                    src,
                                ));
                            }
                        }
                    }
                }
            }

            // Detect template literals with SQL: `SELECT * FROM users WHERE id = ${id}`
            if node.kind() == "template_string" {
                let text = &src[node.byte_range()];
                if sql_pattern.is_match(text) {
                    // Check it has interpolation
                    let mut cursor = node.walk();
                    let has_substitution = node
                        .children(&mut cursor)
                        .any(|c| c.kind() == "template_substitution");
                    if has_substitution {
                        findings.push(make_finding(
                            _self.id(),
                            _self.severity(),
                            _self.cwe(),
                            "SQL query built with template literal interpolation — use parameterized queries",
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

// ─── Rule 4: no-xss-innerhtml ────────────────────────────────────────────────

pub struct NoXssInnerHtml;

impl_rule! {
    NoXssInnerHtml,
    id = "js/no-xss-innerhtml",
    severity = Severity::High,
    cwe = Some("CWE-79"),
    description = "Assignment to innerHTML may lead to XSS",
    language = Language::JavaScript,
    fn check(_self, source, tree) {

        let mut findings = Vec::new();
        walk_tree(tree.root_node(), source, &mut |node, src| {
            // assignment_expression where left side ends with .innerHTML
            if node.kind() == "assignment_expression" {
                if let Some(left) = node.child_by_field_name("left") {
                    if left.kind() == "member_expression" {
                        if let Some(prop) = left.child_by_field_name("property") {
                            let prop_text = &src[prop.byte_range()];
                            if prop_text == "innerHTML" || prop_text == "outerHTML" {
                                // Check if right side is NOT a string literal (string literals are usually safe)
                                if let Some(right) = node.child_by_field_name("right") {
                                    if right.kind() != "string" {
                                        findings.push(make_finding(
                                            _self.id(),
                                            _self.severity(),
                                            _self.cwe(),
                                            &format!(
                                                "Assignment to {} with dynamic content — use textContent or sanitize HTML",
                                                prop_text
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

// ─── Rule 5: no-command-injection ────────────────────────────────────────────

pub struct NoCommandInjection;

impl_rule! {
    NoCommandInjection,
    id = "js/no-command-injection",
    severity = Severity::Critical,
    cwe = Some("CWE-78"),
    description = "Potential command injection via exec/spawn with dynamic input",
    language = Language::JavaScript,
    fn check(_self, source, tree) {

        let mut findings = Vec::new();
        let dangerous_fns = [
            "exec",
            "execSync",
            "spawn",
            "spawnSync",
            "execFile",
            "execFileSync",
        ];

        walk_tree(tree.root_node(), source, &mut |node, src| {
            if node.kind() == "call_expression" {
                if let Some(func) = node.child_by_field_name("function") {
                    let func_text = &src[func.byte_range()];

                    // Match child_process.exec(...) or exec(...)
                    let func_name = func_text.rsplit('.').next().unwrap_or(func_text);

                    if dangerous_fns.contains(&func_name) {
                        if let Some(args) = node.child_by_field_name("arguments") {
                            if let Some(first_arg) = args.named_child(0) {
                                let kind = first_arg.kind();
                                // Flag if the argument is not a plain string literal
                                // (template strings with substitution, identifiers, binary expressions, etc.)
                                let is_dynamic = match kind {
                                    "string" => false,
                                    "template_string" => {
                                        let mut cursor = first_arg.walk();
                                        let has_sub = first_arg
                                            .children(&mut cursor)
                                            .any(|c| c.kind() == "template_substitution");
                                        has_sub
                                    }
                                    _ => true,
                                };

                                if is_dynamic {
                                    findings.push(make_finding(
                                        _self.id(),
                                        _self.severity(),
                                        _self.cwe(),
                                        &format!(
                                            "{}() called with dynamic argument — risk of command injection",
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

// ─── Rule 6: no-document-write ──────────────────────────────────────────────

pub struct NoDocumentWrite;

impl_rule! {
    NoDocumentWrite,
    id = "js/no-document-write",
    severity = Severity::High,
    cwe = Some("CWE-79"),
    description = "document.write() can lead to XSS vulnerabilities",
    language = Language::JavaScript,
    fn check(_self, source, tree) {

        let mut findings = Vec::new();
        walk_tree(tree.root_node(), source, &mut |node, src| {
            if node.kind() == "call_expression" {
                if let Some(func) = node.child_by_field_name("function") {
                    let func_text = &src[func.byte_range()];
                    if func_text == "document.write" || func_text == "document.writeln" {
                        findings.push(make_finding(
                            _self.id(),
                            _self.severity(),
                            _self.cwe(),
                            "document.write() can inject arbitrary HTML — use DOM APIs instead",
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

// ─── Rule 7: no-open-redirect ───────────────────────────────────────────────

pub struct NoOpenRedirect;

impl_rule! {
    NoOpenRedirect,
    id = "js/no-open-redirect",
    severity = Severity::Medium,
    cwe = Some("CWE-601"),
    description = "Open redirect via assignment to window.location with user input",
    language = Language::JavaScript,
    fn check(_self, source, tree) {

        let mut findings = Vec::new();
        walk_tree(tree.root_node(), source, &mut |node, src| {
            if node.kind() == "assignment_expression" {
                if let Some(left) = node.child_by_field_name("left") {
                    let left_text = &src[left.byte_range()];
                    if left_text == "window.location"
                        || left_text == "window.location.href"
                        || left_text == "location.href"
                        || left_text == "document.location"
                        || left_text == "document.location.href"
                    {
                        if let Some(right) = node.child_by_field_name("right") {
                            // Flag if right side is not a string literal
                            if right.kind() != "string" {
                                findings.push(make_finding(
                                    _self.id(),
                                    _self.severity(),
                                    _self.cwe(),
                                    "Assignment to window.location with dynamic value — risk of open redirect",
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

// ─── Rule 8: no-weak-crypto ────────────────────────────────────────────────

pub struct NoWeakCrypto;

impl_rule! {
    NoWeakCrypto,
    id = "js/no-weak-crypto",
    severity = Severity::Medium,
    cwe = Some("CWE-327"),
    description = "Use of weak cryptographic hash (MD5/SHA1)",
    language = Language::JavaScript,
    fn check(_self, source, tree) {

        let mut findings = Vec::new();
        walk_tree(tree.root_node(), source, &mut |node, src| {
            // Detect: createHash('md5') or createHash('sha1')
            if node.kind() == "call_expression" {
                if let Some(func) = node.child_by_field_name("function") {
                    let func_text = &src[func.byte_range()];
                    let func_name = func_text.rsplit('.').next().unwrap_or(func_text);
                    if func_name == "createHash" {
                        if let Some(args) = node.child_by_field_name("arguments") {
                            if let Some(first_arg) = args.named_child(0) {
                                if first_arg.kind() == "string" {
                                    let val = &src[first_arg.byte_range()];
                                    let inner = val.trim_matches(|c| c == '"' || c == '\'');
                                    if inner == "md5" || inner == "sha1" {
                                        findings.push(make_finding(
                                            _self.id(),
                                            _self.severity(),
                                            _self.cwe(),
                                            &format!(
                                                "createHash('{}') uses a weak hash — use sha256 or stronger",
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

// ─── Rule 9: no-path-traversal ─────────────────────────────────────────────

pub struct NoPathTraversal;

impl_rule! {
    NoPathTraversal,
    id = "js/no-path-traversal",
    severity = Severity::High,
    cwe = Some("CWE-22"),
    description = "Potential path traversal via fs operations with user input",
    language = Language::JavaScript,
    fn check(_self, source, tree) {

        let mut findings = Vec::new();
        let fs_fns = [
            "readFile",
            "readFileSync",
            "writeFile",
            "writeFileSync",
            "appendFile",
            "appendFileSync",
            "createReadStream",
            "createWriteStream",
            "readdir",
            "readdirSync",
            "unlink",
            "unlinkSync",
            "stat",
            "statSync",
            "access",
            "accessSync",
        ];

        walk_tree(tree.root_node(), source, &mut |node, src| {
            if node.kind() == "call_expression" {
                if let Some(func) = node.child_by_field_name("function") {
                    let func_text = &src[func.byte_range()];
                    let func_name = func_text.rsplit('.').next().unwrap_or(func_text);
                    if fs_fns.contains(&func_name) {
                        if let Some(args) = node.child_by_field_name("arguments") {
                            if let Some(first_arg) = args.named_child(0) {
                                // Flag if path argument uses concatenation or template
                                let kind = first_arg.kind();
                                if kind == "binary_expression" || kind == "template_string" {
                                    findings.push(make_finding(
                                        _self.id(),
                                        _self.severity(),
                                        _self.cwe(),
                                        &format!(
                                            "{}() called with dynamic path — validate and sanitize to prevent path traversal",
                                            func_name
                                        ),
                                        node,
                                        src,
                                    ));
                                }
                            }
                        }
                    }

                    if func_name == "sendFile" || func_name == "download" {
                        if let Some(args) = node.child_by_field_name("arguments") {
                            if let Some(first_arg) = args.named_child(0) {
                                let is_dynamic = matches!(
                                    first_arg.kind(),
                                    "binary_expression"
                                        | "template_string"
                                        | "identifier"
                                        | "member_expression"
                                        | "subscript_expression"
                                        | "call_expression"
                                );
                                if is_dynamic {
                                    findings.push(make_finding(
                                        _self.id(),
                                        _self.severity(),
                                        _self.cwe(),
                                        &format!(
                                            "{}() called with dynamic path — validate and sanitize to prevent path traversal",
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

// ─── Rule 10: no-prototype-pollution ────────────────────────────────────────

pub struct NoSsrf;

impl_rule! {
    NoSsrf,
    id = "js/no-ssrf",
    severity = Severity::High,
    cwe = Some("CWE-918"),
    description = "Potential SSRF via dynamic outbound request URL",
    language = Language::JavaScript,
    fn check(_self, source, tree) {

        let mut findings = Vec::new();
        let request_fns = [
            "fetch",
            "axios",
            "axios.get",
            "axios.post",
            "axios.put",
            "axios.delete",
            "axios.request",
            "got",
            "got.get",
            "got.post",
            "got.put",
            "got.delete",
            "superagent.get",
            "superagent.post",
            "http.get",
            "http.request",
            "https.get",
            "https.request",
        ];

        walk_tree(tree.root_node(), source, &mut |node, src| {
            if node.kind() != "call_expression" {
                return;
            }

            let Some(func) = node.child_by_field_name("function") else {
                return;
            };
            let func_text = &src[func.byte_range()];
            if !request_fns.contains(&func_text) {
                return;
            }

            let Some(args) = node.child_by_field_name("arguments") else {
                return;
            };
            let Some(first_arg) = args.named_child(0) else {
                return;
            };

            let is_dynamic = match first_arg.kind() {
                "string" => false,
                "object" => {
                    let arg_text = &src[first_arg.byte_range()];
                    arg_text.contains("url:")
                        && !arg_text.contains("url: \"")
                        && !arg_text.contains("url: '")
                }
                "template_string"
                | "binary_expression"
                | "identifier"
                | "member_expression"
                | "call_expression"
                | "subscript_expression" => true,
                _ => false,
            };

            if is_dynamic {
                findings.push(make_finding(
                    _self.id(),
                    _self.severity(),
                    _self.cwe(),
                    &format!(
                        "{} called with dynamic URL — validate and allowlist outbound destinations to prevent SSRF",
                        func_text
                    ),
                    node,
                    src,
                ));
            }
        });

        findings

    }
}

// ─── Rule 10: no-prototype-pollution ────────────────────────────────────────

pub struct NoPrototypePollution;

impl_rule! {
    NoPrototypePollution,
    id = "js/no-prototype-pollution",
    severity = Severity::High,
    cwe = Some("CWE-1321"),
    description = "Potential prototype pollution via dynamic property assignment",
    language = Language::JavaScript,
    fn check(_self, source, tree) {

        let mut findings = Vec::new();
        walk_tree(tree.root_node(), source, &mut |node, src| {
            // Detect: obj[key][subkey] = value where keys are identifiers (not literals)
            if node.kind() == "assignment_expression" {
                if let Some(left) = node.child_by_field_name("left") {
                    if left.kind() == "subscript_expression" {
                        if let Some(index) = left.child_by_field_name("index") {
                            // Flag if the index is a variable (not a string/number literal)
                            if index.kind() == "identifier" {
                                // Check if it's nested: obj[a][b] = value
                                if let Some(object) = left.child_by_field_name("object") {
                                    if object.kind() == "subscript_expression" {
                                        findings.push(make_finding(
                                            _self.id(),
                                            _self.severity(),
                                            _self.cwe(),
                                            "Nested dynamic property assignment — risk of prototype pollution",
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

// ─── Rule 11: no-unsafe-regex ───────────────────────────────────────────────

pub struct NoUnsafeRegex;

impl_rule! {
    NoUnsafeRegex,
    id = "js/no-unsafe-regex",
    severity = Severity::Medium,
    cwe = Some("CWE-1333"),
    description = "Potentially catastrophic backtracking regex pattern",
    language = Language::JavaScript,
    fn check(_self, source, tree) {

        let mut findings = Vec::new();
        // Patterns known to cause catastrophic backtracking: nested quantifiers
        let dangerous_pattern =
            Regex::new(r"(\([^)]*[+*][^)]*\)[+*]|\([^)]*\|[^)]*\)[+*])").unwrap();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            // Detect regex literals: /pattern/
            if node.kind() == "regex" {
                let regex_text = &src[node.byte_range()];
                if dangerous_pattern.is_match(regex_text) {
                    findings.push(make_finding(
                        _self.id(),
                        _self.severity(),
                        _self.cwe(),
                        "Regex with nested quantifiers may cause catastrophic backtracking (ReDoS)",
                        node,
                        src,
                    ));
                }
            }

            // Detect: new RegExp("pattern")
            if node.kind() == "new_expression" {
                if let Some(constructor) = node.child_by_field_name("constructor") {
                    let ctor_text = &src[constructor.byte_range()];
                    if ctor_text == "RegExp" {
                        if let Some(args) = node.child_by_field_name("arguments") {
                            if let Some(first_arg) = args.named_child(0) {
                                if first_arg.kind() == "string" {
                                    let pattern_text = &src[first_arg.byte_range()];
                                    if dangerous_pattern.is_match(pattern_text) {
                                        findings.push(make_finding(
                                            _self.id(),
                                            _self.severity(),
                                            _self.cwe(),
                                            "RegExp with nested quantifiers may cause catastrophic backtracking (ReDoS)",
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

// ─── Rule 12: express-no-hardcoded-session-secret ─────────────────────────

pub struct ExpressNoHardcodedSessionSecret;

impl_rule! {
    ExpressNoHardcodedSessionSecret,
    id = "js/express-no-hardcoded-session-secret",
    severity = Severity::High,
    cwe = Some("CWE-798"),
    description = "Hardcoded session secret in express-session configuration",
    language = Language::JavaScript,
    fn check(_self, source, tree) {

        let mut findings = Vec::new();
        walk_tree(tree.root_node(), source, &mut |node, src| {
            // Detect: session({ secret: "literal" }) — look for a pair with key "secret"
            // inside a call to session()
            if node.kind() == "pair" {
                if let (Some(key), Some(value)) = (
                    node.child_by_field_name("key"),
                    node.child_by_field_name("value"),
                ) {
                    let key_text = &src[key.byte_range()];
                    let key_inner = key_text.trim_matches(|c| c == '"' || c == '\'');
                    if key_inner == "secret" && value.kind() == "string" {
                        // Check the context: is this inside a call_expression that looks like session()?
                        // Walk up to check if we're in an arguments > object > call_expression chain
                        let val = &src[value.byte_range()];
                        let inner = val.trim_matches(|c| c == '"' || c == '\'');
                        if inner.len() >= 4 {
                            findings.push(make_finding(
                                _self.id(),
                                _self.severity(),
                                _self.cwe(),
                                "Hardcoded session secret — use an environment variable instead",
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

// ─── Rule 13: express-cookie-no-secure ────────────────────────────────────

pub struct ExpressCookieNoSecure;

impl_rule! {
    ExpressCookieNoSecure,
    id = "js/express-cookie-no-secure",
    severity = Severity::Medium,
    cwe = Some("CWE-614"),
    description = "Cookie configuration missing secure flag",
    language = Language::JavaScript,
    fn check(_self, source, tree) {

        let mut findings = Vec::new();
        walk_tree(tree.root_node(), source, &mut |node, src| {
            // Look for object literals with a "cookie" key whose value is an object
            // that does NOT contain secure: true
            if node.kind() == "pair" {
                if let (Some(key), Some(value)) = (
                    node.child_by_field_name("key"),
                    node.child_by_field_name("value"),
                ) {
                    let key_text = &src[key.byte_range()];
                    let key_inner = key_text.trim_matches(|c| c == '"' || c == '\'');
                    if key_inner == "cookie" && value.kind() == "object" {
                        let obj_text = &src[value.byte_range()];
                        if !obj_text.contains("secure")
                            || obj_text.contains("secure: false")
                            || obj_text.contains("secure:false")
                        {
                            findings.push(make_finding(
                                _self.id(),
                                _self.severity(),
                                _self.cwe(),
                                "Cookie configuration missing 'secure: true' — cookies may be sent over HTTP",
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

// ─── Rule 14: express-cookie-no-httponly ───────────────────────────────────

pub struct ExpressCookieNoHttpOnly;

impl_rule! {
    ExpressCookieNoHttpOnly,
    id = "js/express-cookie-no-httponly",
    severity = Severity::Medium,
    cwe = Some("CWE-1004"),
    description = "Cookie configuration missing httpOnly flag",
    language = Language::JavaScript,
    fn check(_self, source, tree) {

        let mut findings = Vec::new();
        walk_tree(tree.root_node(), source, &mut |node, src| {
            if node.kind() == "pair" {
                if let (Some(key), Some(value)) = (
                    node.child_by_field_name("key"),
                    node.child_by_field_name("value"),
                ) {
                    let key_text = &src[key.byte_range()];
                    let key_inner = key_text.trim_matches(|c| c == '"' || c == '\'');
                    if key_inner == "cookie" && value.kind() == "object" {
                        let obj_text = &src[value.byte_range()];
                        if !obj_text.contains("httpOnly")
                            || obj_text.contains("httpOnly: false")
                            || obj_text.contains("httpOnly:false")
                        {
                            findings.push(make_finding(
                                _self.id(),
                                _self.severity(),
                                _self.cwe(),
                                "Cookie configuration missing 'httpOnly: true' — cookies accessible to JavaScript",
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

// ─── Rule 15: express-cookie-no-samesite ──────────────────────────────────

pub struct ExpressCookieNoSameSite;

impl_rule! {
    ExpressCookieNoSameSite,
    id = "js/express-cookie-no-samesite",
    severity = Severity::Medium,
    cwe = Some("CWE-352"),
    description = "Cookie configuration missing sameSite protection",
    language = Language::JavaScript,
    fn check(_self, source, tree) {

        let mut findings = Vec::new();
        walk_tree(tree.root_node(), source, &mut |node, src| {
            if node.kind() == "pair" {
                if let (Some(key), Some(value)) = (
                    node.child_by_field_name("key"),
                    node.child_by_field_name("value"),
                ) {
                    let key_text = &src[key.byte_range()];
                    let key_inner = key_text.trim_matches(|c| c == '"' || c == '\'');
                    if key_inner == "cookie" && value.kind() == "object" {
                        let obj_text = &src[value.byte_range()];
                        let has_same_site = obj_text.contains("sameSite");
                        let none_mode = obj_text.contains("sameSite: \"none\"")
                            || obj_text.contains("sameSite:'none'")
                            || obj_text.contains("sameSite: 'none'")
                            || obj_text.contains("sameSite:\"none\"")
                            || obj_text.contains("sameSite: false")
                            || obj_text.contains("sameSite:false");
                        if !has_same_site || none_mode {
                            findings.push(make_finding(
                                _self.id(),
                                _self.severity(),
                                _self.cwe(),
                                "Cookie configuration missing a safe sameSite setting — set sameSite to 'lax' or 'strict'",
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

// ─── Rule 16: express-session-saveuninitialized-true ──────────────────────

pub struct ExpressSessionSaveUninitializedTrue;

impl_rule! {
    ExpressSessionSaveUninitializedTrue,
    id = "js/express-session-saveuninitialized-true",
    severity = Severity::Medium,
    cwe = Some("CWE-359"),
    description = "express-session configured with saveUninitialized: true",
    language = Language::JavaScript,
    fn check(_self, source, tree) {

        let mut findings = Vec::new();
        walk_tree(tree.root_node(), source, &mut |node, src| {
            if node.kind() != "pair" {
                return;
            }

            let (Some(key), Some(value)) = (
                node.child_by_field_name("key"),
                node.child_by_field_name("value"),
            ) else {
                return;
            };

            let key_text = &src[key.byte_range()];
            let key_inner = key_text.trim_matches(|c| c == '"' || c == '\'');
            let value_text = &src[value.byte_range()];
            if key_inner == "saveUninitialized" && value_text == "true" {
                findings.push(make_finding(
                    _self.id(),
                    _self.severity(),
                    _self.cwe(),
                    "express-session saveUninitialized: true stores sessions before consent or login state is established",
                    node,
                    src,
                ));
            }
        });
        findings

    }
}

// ─── Rule 17: express-session-resave-true ─────────────────────────────────

pub struct ExpressSessionResaveTrue;

impl_rule! {
    ExpressSessionResaveTrue,
    id = "js/express-session-resave-true",
    severity = Severity::Medium,
    cwe = Some("CWE-384"),
    description = "express-session configured with resave: true",
    language = Language::JavaScript,
    fn check(_self, source, tree) {

        let mut findings = Vec::new();
        walk_tree(tree.root_node(), source, &mut |node, src| {
            if node.kind() != "pair" {
                return;
            }

            let (Some(key), Some(value)) = (
                node.child_by_field_name("key"),
                node.child_by_field_name("value"),
            ) else {
                return;
            };

            let key_text = &src[key.byte_range()];
            let key_inner = key_text.trim_matches(|c| c == '"' || c == '\'');
            let value_text = &src[value.byte_range()];
            if key_inner == "resave" && value_text == "true" {
                findings.push(make_finding(
                    _self.id(),
                    _self.severity(),
                    _self.cwe(),
                    "express-session resave: true can overwrite sessions unnecessarily — prefer resave: false unless your store requires it",
                    node,
                    src,
                ));
            }
        });
        findings

    }
}

// ─── Rule 18: express-direct-response-write ───────────────────────────────

pub struct ExpressDirectResponseWrite;

impl_rule! {
    ExpressDirectResponseWrite,
    id = "js/express-direct-response-write",
    severity = Severity::High,
    cwe = Some("CWE-79"),
    description = "XSS via direct response write with user input",
    language = Language::JavaScript,
    fn check(_self, source, tree) {

        let mut findings = Vec::new();
        // Match user-controlled input objects
        let user_input_re = Regex::new(r"^req\.(params|query|body|headers)(\b|\[|\.)").unwrap();
        // Sanitization wrappers that neutralise XSS risk
        let sanitize_re = Regex::new(
            r"(?i)(escapeHtml|escape|sanitize|encode|encodeURIComponent|encodeURI|htmlEncode|xss|purify|DOMPurify|validator|parseInt|parseFloat|Number|String)\s*\("
        ).unwrap();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            // Detect: res.send(req.query.foo), res.write(req.body.bar)
            if node.kind() == "call_expression" {
                if let Some(func) = node.child_by_field_name("function") {
                    if func.kind() == "member_expression" {
                        if let Some(obj) = func.child_by_field_name("object") {
                            let obj_text = &src[obj.byte_range()];
                            // Only flag res.send/write/end, not arbitrary objects
                            if obj_text != "res" && !obj_text.ends_with(".res") {
                                return;
                            }
                        }
                        if let Some(prop) = func.child_by_field_name("property") {
                            let prop_text = &src[prop.byte_range()];
                            if prop_text == "send" || prop_text == "write" {
                                if let Some(args) = node.child_by_field_name("arguments") {
                                    let args_text = &src[args.byte_range()];
                                    // Skip if any sanitization wrapper is present
                                    if sanitize_re.is_match(args_text) {
                                        return;
                                    }
                                    // Check each direct argument for user input
                                    let mut cursor = args.walk();
                                    for arg in args.children(&mut cursor) {
                                        // Skip punctuation (parens, commas)
                                        if arg.kind() == "("
                                            || arg.kind() == ")"
                                            || arg.kind() == ","
                                        {
                                            continue;
                                        }
                                        // Only flag when the argument is a direct member/subscript
                                        // expression starting with req.params/query/body/headers.
                                        // Binary expressions (concatenation), call expressions
                                        // (wrapping functions), and template literals are NOT
                                        // direct -- they mix or transform the input.
                                        let kind = arg.kind();
                                        if kind != "member_expression" && kind != "identifier" {
                                            continue;
                                        }
                                        let arg_text = &src[arg.byte_range()];
                                        if user_input_re.is_match(arg_text.trim()) {
                                            findings.push(make_finding(
                                                _self.id(),
                                                _self.severity(),
                                                _self.cwe(),
                                                &format!(
                                                    "res.{}() called with user input — risk of reflected XSS, sanitize before sending",
                                                    prop_text
                                                ),
                                                node,
                                                src,
                                            ));
                                            break; // one finding per call
                                        }
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

// ─── Rule 19: jwt-hardcoded-secret ────────────────────────────────────────

pub struct JwtHardcodedSecret;

impl_rule! {
    JwtHardcodedSecret,
    id = "js/jwt-hardcoded-secret",
    severity = Severity::High,
    cwe = Some("CWE-798"),
    description = "JWT signing or verification with a hardcoded secret",
    language = Language::JavaScript,
    fn check(_self, source, tree) {

        let mut findings = Vec::new();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            if node.kind() != "call_expression" {
                return;
            }

            let Some(func) = node.child_by_field_name("function") else {
                return;
            };
            let func_text = &src[func.byte_range()];
            if func_text != "jwt.sign"
                && func_text != "jwt.verify"
                && func_text != "jsonwebtoken.sign"
                && func_text != "jsonwebtoken.verify"
            {
                return;
            }

            let Some(args) = node.child_by_field_name("arguments") else {
                return;
            };
            let Some(secret_arg) = args.named_child(1) else {
                return;
            };
            if secret_arg.kind() != "string" && secret_arg.kind() != "template_string" {
                return;
            }

            let secret = &src[secret_arg.byte_range()];
            let inner = secret.trim_matches(|c| c == '"' || c == '\'' || c == '`');
            if inner.len() < 4 {
                return;
            }

            findings.push(make_finding(
                _self.id(),
                _self.severity(),
                _self.cwe(),
                "JWT secret is hardcoded — load signing keys from environment or a secrets manager",
                node,
                src,
            ));
        });

        findings

    }
}

// ─── Rule 20: jwt-none-algorithm ───────────────────────────────────────────

pub struct JwtNoneAlgorithm;

impl_rule! {
    JwtNoneAlgorithm,
    id = "js/jwt-none-algorithm",
    severity = Severity::High,
    cwe = Some("CWE-347"),
    description = "JWT configured to use the 'none' algorithm",
    language = Language::JavaScript,
    fn check(_self, source, tree) {

        let mut findings = Vec::new();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            if node.kind() != "call_expression" {
                return;
            }

            let Some(func) = node.child_by_field_name("function") else {
                return;
            };
            let func_text = &src[func.byte_range()];
            if func_text != "jwt.sign"
                && func_text != "jwt.verify"
                && func_text != "jsonwebtoken.sign"
                && func_text != "jsonwebtoken.verify"
            {
                return;
            }

            let Some(args) = node.child_by_field_name("arguments") else {
                return;
            };
            let Some(options_arg) = args.named_child(2) else {
                return;
            };
            if options_arg.kind() != "object" {
                return;
            }

            let options_text = &src[options_arg.byte_range()];
            let uses_none = options_text.contains("algorithm: \"none\"")
                || options_text.contains("algorithm:'none'")
                || options_text.contains("algorithm: 'none'")
                || options_text.contains("algorithm:\"none\"")
                || options_text.contains("algorithms: [\"none\"]")
                || options_text.contains("algorithms:['none']")
                || options_text.contains("algorithms: ['none']")
                || options_text.contains("algorithms:[\"none\"]");
            if !uses_none {
                return;
            }

            findings.push(make_finding(
                _self.id(),
                _self.severity(),
                _self.cwe(),
                "JWT configured with algorithm 'none' — require a signed algorithm such as HS256 or RS256",
                node,
                src,
            ));
        });

        findings

    }
}

// ─── Rule 21: jwt-ignore-expiration ────────────────────────────────────────

pub struct JwtIgnoreExpiration;

impl_rule! {
    JwtIgnoreExpiration,
    id = "js/jwt-ignore-expiration",
    severity = Severity::High,
    cwe = Some("CWE-613"),
    description = "JWT verification configured to ignore token expiration",
    language = Language::JavaScript,
    fn check(_self, source, tree) {

        let mut findings = Vec::new();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            if node.kind() != "call_expression" {
                return;
            }

            let Some(func) = node.child_by_field_name("function") else {
                return;
            };
            let func_text = &src[func.byte_range()];
            if func_text != "jwt.verify" && func_text != "jsonwebtoken.verify" {
                return;
            }

            let Some(args) = node.child_by_field_name("arguments") else {
                return;
            };
            let Some(options_arg) = args.named_child(2) else {
                return;
            };
            if options_arg.kind() != "object" {
                return;
            }

            let options_text = &src[options_arg.byte_range()];
            let ignores_expiration = options_text.contains("ignoreExpiration: true")
                || options_text.contains("ignoreExpiration:true");
            if !ignores_expiration {
                return;
            }

            findings.push(make_finding(
                _self.id(),
                _self.severity(),
                _self.cwe(),
                "JWT verification ignores expiration — reject expired tokens instead of setting ignoreExpiration: true",
                node,
                src,
            ));
        });

        findings

    }
}

// ─── Rule 22: jwt-decode-without-verify ────────────────────────────────────

pub struct JwtDecodeWithoutVerify;

impl_rule! {
    JwtDecodeWithoutVerify,
    id = "js/jwt-decode-without-verify",
    severity = Severity::High,
    cwe = Some("CWE-347"),
    description = "JWT decoded without signature verification",
    language = Language::JavaScript,
    fn check(_self, source, tree) {

        let mut findings = Vec::new();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            if node.kind() != "call_expression" {
                return;
            }

            let Some(func) = node.child_by_field_name("function") else {
                return;
            };
            let func_text = &src[func.byte_range()];
            if func_text != "jwt.decode" && func_text != "jsonwebtoken.decode" {
                return;
            }

            findings.push(make_finding(
                _self.id(),
                _self.severity(),
                _self.cwe(),
                "JWT decoded without verification — use jwt.verify() when authenticity matters",
                node,
                src,
            ));
        });

        findings

    }
}

// ─── Rule 23: jwt-verify-missing-algorithms ───────────────────────────────

pub struct JwtVerifyMissingAlgorithms;

impl_rule! {
    JwtVerifyMissingAlgorithms,
    id = "js/jwt-verify-missing-algorithms",
    severity = Severity::High,
    cwe = Some("CWE-347"),
    description = "JWT verification without an explicit algorithms allowlist",
    language = Language::JavaScript,
    fn check(_self, source, tree) {

        let mut findings = Vec::new();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            if node.kind() != "call_expression" {
                return;
            }

            let Some(func) = node.child_by_field_name("function") else {
                return;
            };
            let func_text = &src[func.byte_range()];
            if func_text != "jwt.verify" && func_text != "jsonwebtoken.verify" {
                return;
            }

            let Some(args) = node.child_by_field_name("arguments") else {
                return;
            };

            let Some(options_arg) = args.named_child(2) else {
                findings.push(make_finding(
                    _self.id(),
                    _self.severity(),
                    _self.cwe(),
                    "JWT verification does not restrict allowed algorithms — pass an explicit algorithms allowlist",
                    node,
                    src,
                ));
                return;
            };

            if options_arg.kind() != "object" {
                return;
            }

            let options_text = &src[options_arg.byte_range()];
            if !options_text.contains("algorithms") {
                findings.push(make_finding(
                    _self.id(),
                    _self.severity(),
                    _self.cwe(),
                    "JWT verification does not restrict allowed algorithms — pass an explicit algorithms allowlist",
                    node,
                    src,
                ));
            }
        });

        findings

    }
}

// ─── Rule 24: no-cors-star ─────────────────────────────────────────────────

pub struct NoCorsStar;

impl_rule! {
    NoCorsStar,
    id = "js/no-cors-star",
    severity = Severity::Medium,
    cwe = Some("CWE-942"),
    description = "CORS misconfiguration allowing all origins",
    language = Language::JavaScript,
    fn check(_self, source, tree) {

        let mut findings = Vec::new();
        walk_tree(tree.root_node(), source, &mut |node, src| {
            // Detect: setHeader("Access-Control-Allow-Origin", "*")
            if node.kind() == "call_expression" {
                if let Some(func) = node.child_by_field_name("function") {
                    let func_text = &src[func.byte_range()];
                    let func_name = func_text.rsplit('.').next().unwrap_or(func_text);
                    if func_name == "setHeader" || func_name == "set" || func_name == "header" {
                        if let Some(args) = node.child_by_field_name("arguments") {
                            let arg_count = args.named_child_count();
                            if arg_count >= 2 {
                                if let (Some(first), Some(second)) =
                                    (args.named_child(0), args.named_child(1))
                                {
                                    if first.kind() == "string" && second.kind() == "string" {
                                        let header_name = &src[first.byte_range()];
                                        let header_val = &src[second.byte_range()];
                                        let name_inner =
                                            header_name.trim_matches(|c| c == '"' || c == '\'');
                                        let val_inner =
                                            header_val.trim_matches(|c| c == '"' || c == '\'');
                                        if name_inner
                                            .eq_ignore_ascii_case("Access-Control-Allow-Origin")
                                            && val_inner == "*"
                                        {
                                            findings.push(make_finding(
                                                _self.id(),
                                                _self.severity(),
                                                _self.cwe(),
                                                "Access-Control-Allow-Origin set to '*' — restrict to specific origins",
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

            // Detect: { origin: "*" } in cors config objects
            if node.kind() == "pair" {
                if let (Some(key), Some(value)) = (
                    node.child_by_field_name("key"),
                    node.child_by_field_name("value"),
                ) {
                    let key_text = &src[key.byte_range()];
                    let key_inner = key_text.trim_matches(|c| c == '"' || c == '\'');
                    if key_inner == "origin" && value.kind() == "string" {
                        let val_text = &src[value.byte_range()];
                        let val_inner = val_text.trim_matches(|c| c == '"' || c == '\'');
                        if val_inner == "*" {
                            findings.push(make_finding(
                                _self.id(),
                                _self.severity(),
                                _self.cwe(),
                                "CORS origin set to '*' — restrict to specific origins",
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

// ─── Rule: no-unsafe-format-string ───────────────────────────────────────────

pub struct NoUnsafeFormatString;

impl_rule! {
    NoUnsafeFormatString,
    id = "js/no-unsafe-format-string",
    severity = Severity::Medium,
    cwe = Some("CWE-134"),
    description = "Template literal with variables in console/logging function may enable log injection",
    language = Language::JavaScript,
    fn check(_self, source, tree) {

        let mut findings = Vec::new();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            if node.kind() == "call_expression" {
                if let Some(func) = node.child_by_field_name("function") {
                    let func_text = &src[func.byte_range()];
                    // console.error, console.log, console.warn, console.info, util.format
                    if matches!(
                        func_text,
                        "console.error"
                            | "console.log"
                            | "console.warn"
                            | "console.info"
                            | "util.format"
                    ) {
                        if let Some(args) = node.child_by_field_name("arguments") {
                            let mut cursor = args.walk();
                            for arg in args.children(&mut cursor) {
                                if arg.kind() == "template_string" {
                                    // Check if template string has interpolation
                                    let mut has_interpolation = false;
                                    let mut inner_cursor = arg.walk();
                                    for child in arg.children(&mut inner_cursor) {
                                        if child.kind() == "template_substitution" {
                                            has_interpolation = true;
                                            break;
                                        }
                                    }
                                    if has_interpolation {
                                        findings.push(make_finding(
                                            _self.id(),
                                            _self.severity(),
                                            _self.cwe(),
                                            "Template literal with variables in logging function — user-controlled values may forge log entries",
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

// ─── Rule: no-unsafe-deserialization ───────────────────────────────────────

pub struct NoUnsafeDeserialization;

impl_rule! {
    NoUnsafeDeserialization,
    id = "js/no-unsafe-deserialization",
    severity = Severity::Critical,
    cwe = Some("CWE-502"),
    description = "Unsafe deserialization of untrusted data",
    language = Language::JavaScript,
    fn check(_self, source, tree) {

        let mut findings = Vec::new();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            if node.kind() != "call_expression" {
                return;
            }

            let Some(func) = node.child_by_field_name("function") else {
                return;
            };
            let func_text = &src[func.byte_range()];

            // node-serialize: serialize.unserialize() / unserialize()
            if func_text == "serialize.unserialize"
                || func_text == "unserialize"
                || func_text == "cryo.parse"
                || func_text == "funcster.deepDeserialize"
            {
                findings.push(make_finding(
                    _self.id(),
                    _self.severity(),
                    _self.cwe(),
                    "Avoid deserializing untrusted data with node-serialize. Use JSON.parse() for structured data.",
                    node,
                    src,
                ));
                return;
            }

            // yaml.load() / jsyaml.load() without safe schema
            if func_text == "yaml.load" || func_text == "jsyaml.load" {
                // Check if a safe schema option is provided
                if let Some(args) = node.child_by_field_name("arguments") {
                    let args_text = &src[args.byte_range()];
                    // Safe if schema is explicitly set to a safe variant
                    if args_text.contains("SAFE_SCHEMA")
                        || args_text.contains("JSON_SCHEMA")
                        || args_text.contains("FAILSAFE_SCHEMA")
                        || args_text.contains("safeLoad")
                    {
                        return;
                    }
                }
                findings.push(make_finding(
                    _self.id(),
                    _self.severity(),
                    _self.cwe(),
                    "Avoid deserializing untrusted data with node-serialize. Use JSON.parse() for structured data.",
                    node,
                    src,
                ));
            }
        });

        findings

    }
}

// ─── js/taint-xss-innerhtml ───────────────────────────────────────────────
//
// Intraprocedural taint rule: fires when untrusted Express-style input
// (`req.body`, `req.query`, ...) reaches an `innerHTML`/`outerHTML`
// assignment or a `document.write` call. Uses the engine in
// `javascript_taint` the same way `python::TaintPickleDeserialization`
// uses `python_taint`.

use crate::rules::javascript_taint::{
    self, javascript_taint_sources, NodeMatcher as JsNodeMatcher, TaintSpec as JsTaintSpec,
};

struct JsTaintRuleMeta<'a> {
    rule_id: &'a str,
    severity: Severity,
    cwe: Option<&'a str>,
    fix_suggestion: Option<&'a str>,
}

fn map_js_taint_findings(
    meta: &JsTaintRuleMeta<'_>,
    source: &str,
    tree: &tree_sitter::Tree,
    ctx: &FileContext<'_>,
    spec: &JsTaintSpec,
    format_description: impl Fn(&str, &str) -> String,
) -> Vec<Finding> {
    // Build cross-file info if both summaries and import paths are available.
    let cross_file_info = match (ctx.cross_file_summaries, ctx.javascript_import_paths) {
        (Some(summaries), Some(import_paths)) => Some(javascript_taint::CrossFileInfo {
            import_to_path: import_paths,
            summaries,
            current_rule_id: meta.rule_id,
        }),
        _ => None,
    };
    let raw = javascript_taint::analyze_tree_with_cross_file(
        tree.root_node(),
        source,
        spec,
        ctx.javascript_aliases,
        cross_file_info.as_ref(),
    );
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

pub struct TaintXssInnerHtml;

impl TaintXssInnerHtml {
    fn spec() -> JsTaintSpec {
        JsTaintSpec {
            sources: javascript_taint_sources(),
            sinks: vec![
                JsNodeMatcher::MemberAssign {
                    field: "innerHTML".into(),
                    description: "innerHTML assignment".into(),
                },
                JsNodeMatcher::MemberAssign {
                    field: "outerHTML".into(),
                    description: "outerHTML assignment".into(),
                },
                JsNodeMatcher::Call {
                    canonical: "document.write".into(),
                    description: "document.write".into(),
                },
                JsNodeMatcher::Call {
                    canonical: "document.writeln".into(),
                    description: "document.writeln".into(),
                },
            ],
            sanitizers: vec![
                JsNodeMatcher::Call {
                    canonical: "DOMPurify.sanitize".into(),
                    description: "DOMPurify.sanitize".into(),
                },
                JsNodeMatcher::Call {
                    canonical: "sanitizeHtml".into(),
                    description: "sanitizeHtml".into(),
                },
                JsNodeMatcher::Call {
                    canonical: "xss".into(),
                    description: "xss".into(),
                },
                JsNodeMatcher::Call {
                    canonical: "escape".into(),
                    description: "escape".into(),
                },
                JsNodeMatcher::Call {
                    canonical: "encodeURIComponent".into(),
                    description: "encodeURIComponent".into(),
                },
            ],
        }
    }
}

impl_rule! {
    TaintXssInnerHtml,
    id = "js/taint-xss-innerhtml",
    severity = Severity::High,
    cwe = Some("CWE-79"),
    description = "Untrusted input reaches innerHTML or document.write sink",
    language = Language::JavaScript,
    fn check_with_context(_self, source, tree, ctx) {

        let meta = JsTaintRuleMeta {
            rule_id: _self.id(),
            severity: _self.severity(),
            cwe: _self.cwe(),
            fix_suggestion: Some("Use `DOMPurify.sanitize()` or `textContent` instead of `innerHTML`/`document.write`"),
        };
        map_js_taint_findings(&meta, source, tree, ctx, &Self::spec(), |src, sink| {
            format!("{} reaches {} — untrusted input can lead to XSS", src, sink)
        })

    }
}

// ─── js/taint-sql-injection ───────────────────────────────────────────────
//
// Intraprocedural taint rule: fires when untrusted Express/Next/etc input
// (`req.body`, `req.query`, `searchParams.get(...)`, ...) reaches a SQL
// execute sink. Sinks are identified by method name on any receiver,
// matching the common JS SQL client conventions (`db.query`, `pool.query`,
// `connection.execute`, `sequelize.query`, `knex.raw`). This is noisier
// than the canonical-callee approach but catches the realistic shape of
// server-side JS apps where database handles are ad-hoc variables.

pub struct TaintSqlInjection;

impl TaintSqlInjection {
    fn spec() -> JsTaintSpec {
        JsTaintSpec {
            sources: javascript_taint_sources(),
            sinks: vec![
                JsNodeMatcher::MethodName {
                    method: "query".into(),
                    description: "SQL .query() call".into(),
                },
                JsNodeMatcher::MethodName {
                    method: "execute".into(),
                    description: "SQL .execute() call".into(),
                },
                JsNodeMatcher::MethodName {
                    method: "raw".into(),
                    description: "SQL .raw() call (knex-style)".into(),
                },
            ],
            sanitizers: vec![
                JsNodeMatcher::MethodName {
                    method: "escape".into(),
                    description: "mysql .escape()".into(),
                },
                JsNodeMatcher::MethodName {
                    method: "escapeLiteral".into(),
                    description: "pg .escapeLiteral()".into(),
                },
            ],
        }
    }
}

impl_rule! {
    TaintSqlInjection,
    id = "js/taint-sql-injection",
    severity = Severity::Critical,
    cwe = Some("CWE-89"),
    description = "Untrusted input reaches a SQL execute sink — possible SQL injection",
    language = Language::JavaScript,
    fn check_with_context(_self, source, tree, ctx) {

        let meta = JsTaintRuleMeta {
            rule_id: _self.id(),
            severity: _self.severity(),
            cwe: _self.cwe(),
            fix_suggestion: Some("Use parameterized queries: `db.query(\"SELECT * FROM users WHERE name = $1\", [name])`"),
        };
        map_js_taint_findings(&meta, source, tree, ctx, &Self::spec(), |src, sink| {
            format!("{} reaches {} — untrusted input can inject SQL", src, sink)
        })

    }
}

// ─── js/taint-eval ──────────────────────────────────────────────────────
//
// Intraprocedural taint rule: fires when untrusted input reaches `eval()`
// or `new Function(...)`. CWE-95 (Improper Neutralization of Directives
// in Dynamically Evaluated Code).

pub struct TaintEval;

impl TaintEval {
    fn spec() -> JsTaintSpec {
        JsTaintSpec {
            sources: javascript_taint_sources(),
            sinks: vec![
                JsNodeMatcher::Call {
                    canonical: "eval".into(),
                    description: "eval() call".into(),
                },
                JsNodeMatcher::Call {
                    canonical: "Function".into(),
                    description: "new Function() call".into(),
                },
            ],
            sanitizers: vec![],
        }
    }
}

impl_rule! {
    TaintEval,
    id = "js/taint-eval",
    severity = Severity::Critical,
    cwe = Some("CWE-95"),
    description = "Untrusted input reaches eval or Function — arbitrary code execution",
    language = Language::JavaScript,
    fn check_with_context(_self, source, tree, ctx) {

        let meta = JsTaintRuleMeta {
            rule_id: _self.id(),
            severity: _self.severity(),
            cwe: _self.cwe(),
            fix_suggestion: Some(
                "Remove `eval()`/`new Function()` and use safe alternatives like `JSON.parse()`",
            ),
        };
        map_js_taint_findings(&meta, source, tree, ctx, &Self::spec(), |src, sink| {
            format!(
                "{} reaches {} — untrusted input can execute arbitrary code",
                src, sink
            )
        })

    }
}

// ─── js/taint-command-injection ─────────────────────────────────────────
//
// Intraprocedural taint rule: fires when untrusted input reaches a
// child-process execution sink. CWE-78 (OS Command Injection).

pub struct TaintCommandInjection;

impl TaintCommandInjection {
    fn spec() -> JsTaintSpec {
        JsTaintSpec {
            sources: javascript_taint_sources(),
            sinks: vec![
                JsNodeMatcher::Call {
                    canonical: "child_process.exec".into(),
                    description: "child_process.exec()".into(),
                },
                JsNodeMatcher::Call {
                    canonical: "child_process.execSync".into(),
                    description: "child_process.execSync()".into(),
                },
                JsNodeMatcher::Call {
                    canonical: "child_process.spawn".into(),
                    description: "child_process.spawn()".into(),
                },
                JsNodeMatcher::Call {
                    canonical: "child_process.spawnSync".into(),
                    description: "child_process.spawnSync()".into(),
                },
                JsNodeMatcher::Call {
                    canonical: "child_process.execFile".into(),
                    description: "child_process.execFile()".into(),
                },
            ],
            sanitizers: vec![
                JsNodeMatcher::Call {
                    canonical: "shellescape".into(),
                    description: "shellescape".into(),
                },
                JsNodeMatcher::Call {
                    canonical: "shell-escape".into(),
                    description: "shell-escape".into(),
                },
                JsNodeMatcher::Call {
                    canonical: "escapeShellArg".into(),
                    description: "escapeShellArg".into(),
                },
            ],
        }
    }
}

impl_rule! {
    TaintCommandInjection,
    id = "js/taint-command-injection",
    severity = Severity::Critical,
    cwe = Some("CWE-78"),
    description = "Untrusted input reaches a command execution sink — OS command injection",
    language = Language::JavaScript,
    fn check_with_context(_self, source, tree, ctx) {

        let meta = JsTaintRuleMeta {
            rule_id: _self.id(),
            severity: _self.severity(),
            cwe: _self.cwe(),
            fix_suggestion: Some("Pass arguments as an array to `child_process.execFile()` instead of building a shell string"),
        };
        map_js_taint_findings(&meta, source, tree, ctx, &Self::spec(), |src, sink| {
            format!(
                "{} reaches {} — untrusted input can inject OS commands",
                src, sink
            )
        })

    }
}

// ─── js/taint-ssrf ──────────────────────────────────────────────────────
//
// Intraprocedural taint rule: fires when untrusted input reaches an
// outbound HTTP request sink. CWE-918 (Server-Side Request Forgery).

pub struct TaintSsrf;

impl TaintSsrf {
    fn spec() -> JsTaintSpec {
        JsTaintSpec {
            sources: javascript_taint_sources(),
            sinks: vec![
                JsNodeMatcher::Call {
                    canonical: "fetch".into(),
                    description: "fetch() call".into(),
                },
                JsNodeMatcher::Call {
                    canonical: "http.get".into(),
                    description: "http.get() call".into(),
                },
                JsNodeMatcher::Call {
                    canonical: "http.request".into(),
                    description: "http.request() call".into(),
                },
                JsNodeMatcher::Call {
                    canonical: "https.get".into(),
                    description: "https.get() call".into(),
                },
                JsNodeMatcher::Call {
                    canonical: "https.request".into(),
                    description: "https.request() call".into(),
                },
                JsNodeMatcher::Call {
                    canonical: "axios.get".into(),
                    description: "axios.get() call".into(),
                },
                JsNodeMatcher::Call {
                    canonical: "axios.post".into(),
                    description: "axios.post() call".into(),
                },
                JsNodeMatcher::Call {
                    canonical: "axios.request".into(),
                    description: "axios.request() call".into(),
                },
                JsNodeMatcher::Call {
                    canonical: "got".into(),
                    description: "got() call".into(),
                },
                JsNodeMatcher::Call {
                    canonical: "got.get".into(),
                    description: "got.get() call".into(),
                },
                JsNodeMatcher::Call {
                    canonical: "got.post".into(),
                    description: "got.post() call".into(),
                },
            ],
            sanitizers: vec![],
        }
    }
}

impl_rule! {
    TaintSsrf,
    id = "js/taint-ssrf",
    severity = Severity::High,
    cwe = Some("CWE-918"),
    description = "Untrusted input reaches an HTTP request sink — possible SSRF",
    language = Language::JavaScript,
    fn check_with_context(_self, source, tree, ctx) {

        let meta = JsTaintRuleMeta {
            rule_id: _self.id(),
            severity: _self.severity(),
            cwe: _self.cwe(),
            fix_suggestion: Some(
                "Validate URLs against an allowlist of permitted hosts before making requests",
            ),
        };
        map_js_taint_findings(&meta, source, tree, ctx, &Self::spec(), |src, sink| {
            format!(
                "{} reaches {} — untrusted input can cause server-side request forgery",
                src, sink
            )
        })

    }
}

// ─── js/taint-ssti ─────────────────────────────────────────────────────
//
// Intraprocedural taint rule: fires when untrusted input reaches a
// template rendering sink. CWE-1336 (Server-Side Template Injection).

pub struct TaintSsti;

impl TaintSsti {
    pub(crate) fn spec() -> JsTaintSpec {
        JsTaintSpec {
            sources: javascript_taint_sources(),
            sinks: vec![
                JsNodeMatcher::Call {
                    canonical: "ejs.render".into(),
                    description: "ejs.render() call".into(),
                },
                JsNodeMatcher::Call {
                    canonical: "ejs.renderFile".into(),
                    description: "ejs.renderFile() call".into(),
                },
                JsNodeMatcher::Call {
                    canonical: "pug.render".into(),
                    description: "pug.render() call".into(),
                },
                JsNodeMatcher::Call {
                    canonical: "pug.renderFile".into(),
                    description: "pug.renderFile() call".into(),
                },
                JsNodeMatcher::Call {
                    canonical: "Handlebars.compile".into(),
                    description: "Handlebars.compile() call".into(),
                },
                JsNodeMatcher::Call {
                    canonical: "handlebars.compile".into(),
                    description: "handlebars.compile() call".into(),
                },
                JsNodeMatcher::Call {
                    canonical: "nunjucks.renderString".into(),
                    description: "nunjucks.renderString() call".into(),
                },
                JsNodeMatcher::Call {
                    canonical: "mustache.render".into(),
                    description: "mustache.render() call".into(),
                },
            ],
            sanitizers: vec![],
        }
    }
}

impl_rule! {
    TaintSsti,
    id = "js/taint-ssti",
    severity = Severity::Critical,
    cwe = Some("CWE-1336"),
    description = "Untrusted input reaches a template rendering sink — possible server-side template injection",
    language = Language::JavaScript,
    fn check_with_context(_self, source, tree, ctx) {

        let meta = JsTaintRuleMeta {
            rule_id: _self.id(),
            severity: _self.severity(),
            cwe: _self.cwe(),
            fix_suggestion: Some("Use pre-compiled templates with auto-escaping instead of rendering user input as template strings"),
        };
        map_js_taint_findings(&meta, source, tree, ctx, &Self::spec(), |src, sink| {
            format!(
                "{} reaches {} — untrusted input can inject server-side templates",
                src, sink
            )
        })

    }
}

// ─── js/taint-xpath-injection ──────────────────────────────────────────
//
// Intraprocedural taint rule: fires when untrusted input reaches an
// XPath evaluation sink. CWE-643 (XPath Injection).

pub struct TaintXpathInjection;

impl TaintXpathInjection {
    pub(crate) fn spec() -> JsTaintSpec {
        JsTaintSpec {
            sources: javascript_taint_sources(),
            sinks: vec![
                JsNodeMatcher::Call {
                    canonical: "xpath.select".into(),
                    description: "xpath.select() call".into(),
                },
                JsNodeMatcher::Call {
                    canonical: "xpath.evaluate".into(),
                    description: "xpath.evaluate() call".into(),
                },
                JsNodeMatcher::Call {
                    canonical: "document.evaluate".into(),
                    description: "document.evaluate() call".into(),
                },
                JsNodeMatcher::Call {
                    canonical: "dom.evaluate".into(),
                    description: "dom.evaluate() call".into(),
                },
            ],
            sanitizers: vec![],
        }
    }
}

impl_rule! {
    TaintXpathInjection,
    id = "js/taint-xpath-injection",
    severity = Severity::High,
    cwe = Some("CWE-643"),
    description = "Untrusted input reaches an XPath evaluation sink — possible XPath injection",
    language = Language::JavaScript,
    fn check_with_context(_self, source, tree, ctx) {

        let meta = JsTaintRuleMeta {
            rule_id: _self.id(),
            severity: _self.severity(),
            cwe: _self.cwe(),
            fix_suggestion: Some(
                "Validate and sanitize user input before building XPath expressions",
            ),
        };
        map_js_taint_findings(&meta, source, tree, ctx, &Self::spec(), |src, sink| {
            format!(
                "{} reaches {} — untrusted input can inject XPath expressions",
                src, sink
            )
        })

    }
}

// ─── js/taint-ldap-injection ───────────────────────────────────────────
//
// Intraprocedural taint rule: fires when untrusted input reaches an
// LDAP operation sink. CWE-90 (LDAP Injection).

pub struct TaintLdapInjection;

impl TaintLdapInjection {
    pub(crate) fn spec() -> JsTaintSpec {
        JsTaintSpec {
            sources: javascript_taint_sources(),
            sinks: vec![
                JsNodeMatcher::Call {
                    canonical: "client.search".into(),
                    description: "LDAP client.search() call".into(),
                },
                JsNodeMatcher::Call {
                    canonical: "ldap.search".into(),
                    description: "LDAP ldap.search() call".into(),
                },
                JsNodeMatcher::Call {
                    canonical: "conn.search".into(),
                    description: "LDAP conn.search() call".into(),
                },
                JsNodeMatcher::Call {
                    canonical: "client.bind".into(),
                    description: "LDAP client.bind() call".into(),
                },
                JsNodeMatcher::Call {
                    canonical: "ldap.bind".into(),
                    description: "LDAP ldap.bind() call".into(),
                },
                JsNodeMatcher::Call {
                    canonical: "conn.bind".into(),
                    description: "LDAP conn.bind() call".into(),
                },
            ],
            sanitizers: vec![],
        }
    }
}

impl_rule! {
    TaintLdapInjection,
    id = "js/taint-ldap-injection",
    severity = Severity::High,
    cwe = Some("CWE-90"),
    description = "Untrusted input reaches an LDAP operation sink — possible LDAP injection",
    language = Language::JavaScript,
    fn check_with_context(_self, source, tree, ctx) {

        let meta = JsTaintRuleMeta {
            rule_id: _self.id(),
            severity: _self.severity(),
            cwe: _self.cwe(),
            fix_suggestion: Some("Use ldap-escape or sanitize special LDAP characters before building filter strings"),
        };
        map_js_taint_findings(&meta, source, tree, ctx, &Self::spec(), |src, sink| {
            format!(
                "{} reaches {} — untrusted input can inject LDAP filters",
                src, sink
            )
        })

    }
}

// ─── Rule: taint-log-injection ────────────────────────────────────────────

pub struct TaintLogInjection;

impl TaintLogInjection {
    pub(crate) fn spec() -> JsTaintSpec {
        JsTaintSpec {
            sources: javascript_taint_sources(),
            sinks: vec![
                JsNodeMatcher::Call {
                    canonical: "console.log".into(),
                    description: "console.log".into(),
                },
                JsNodeMatcher::Call {
                    canonical: "console.error".into(),
                    description: "console.error".into(),
                },
                JsNodeMatcher::MethodName {
                    method: "warn".into(),
                    description: "warn() (matches console.warn, logger.warn, etc.)".into(),
                },
                JsNodeMatcher::MethodName {
                    method: "info".into(),
                    description: "info() (matches console.info, logger.info, etc.)".into(),
                },
                JsNodeMatcher::MethodName {
                    method: "debug".into(),
                    description: "debug() (matches console.debug, logger.debug, etc.)".into(),
                },
            ],
            sanitizers: vec![],
        }
    }
}

impl_rule! {
    TaintLogInjection,
    id = "js/taint-log-injection",
    severity = Severity::Medium,
    cwe = Some("CWE-117"),
    description = "Untrusted input reaches a logging sink — possible log injection",
    language = Language::JavaScript,
    fn check_with_context(_self, source, tree, ctx) {

        let meta = JsTaintRuleMeta {
            rule_id: _self.id(),
            severity: _self.severity(),
            cwe: _self.cwe(),
            fix_suggestion: Some(
                "Sanitize user input before logging — strip newlines and control characters",
            ),
        };
        map_js_taint_findings(&meta, source, tree, ctx, &Self::spec(), |src, sink| {
            format!(
                "{} reaches {} — untrusted input can forge log entries",
                src, sink
            )
        })

    }
}

// ─── js/taint-xxe ─────────────────────────────────────────────────────
pub struct TaintXxe;

impl TaintXxe {
    pub(crate) fn spec() -> JsTaintSpec {
        JsTaintSpec {
            sources: javascript_taint_sources(),
            sinks: vec![
                JsNodeMatcher::MethodName {
                    method: "parseString".into(),
                    description: "xml2js.parseString / xml parser".into(),
                },
                JsNodeMatcher::MethodName {
                    method: "parseXml".into(),
                    description: "libxmljs.parseXml".into(),
                },
                JsNodeMatcher::MethodName {
                    method: "parseFromString".into(),
                    description: "DOMParser.parseFromString".into(),
                },
            ],
            sanitizers: vec![],
        }
    }
}

impl_rule! {
    TaintXxe,
    id = "js/taint-xxe",
    severity = Severity::High,
    cwe = Some("CWE-611"),
    description = "Untrusted input reaches an XML parser — possible XML External Entity (XXE) injection",
    language = Language::JavaScript,
    fn check_with_context(_self, source, tree, ctx) {

        let meta = JsTaintRuleMeta {
            rule_id: _self.id(),
            severity: _self.severity(),
            cwe: _self.cwe(),
            fix_suggestion: Some("Disable external entity resolution in XML parser configuration"),
        };
        map_js_taint_findings(&meta, source, tree, ctx, &Self::spec(), |src, sink| {
            format!(
                "{} reaches {} — untrusted input can trigger XML External Entity processing",
                src, sink
            )
        })

    }
}

// ─── js/taint-nosql-injection ──────────────────────────────────────────
//
// Intraprocedural taint rule: fires when untrusted Express/Next/etc input
// reaches a MongoDB query sink (mongoose/mongodb driver patterns).

pub struct TaintNosqlInjection;

impl TaintNosqlInjection {
    fn spec() -> JsTaintSpec {
        JsTaintSpec {
            sources: javascript_taint_sources(),
            sinks: vec![
                // Use specific Call matchers for .find() to avoid matching
                // Array.prototype.find() (issue #141).
                JsNodeMatcher::Call {
                    canonical: "collection.find".into(),
                    description: "MongoDB collection.find()".into(),
                },
                JsNodeMatcher::Call {
                    canonical: "db.find".into(),
                    description: "MongoDB db.find()".into(),
                },
                JsNodeMatcher::Call {
                    canonical: "model.find".into(),
                    description: "Mongoose model.find()".into(),
                },
                JsNodeMatcher::Call {
                    canonical: "Model.find".into(),
                    description: "Mongoose Model.find()".into(),
                },
                JsNodeMatcher::MethodName {
                    method: "findOne".into(),
                    description: "MongoDB .findOne() call".into(),
                },
                JsNodeMatcher::MethodName {
                    method: "updateOne".into(),
                    description: "MongoDB .updateOne() call".into(),
                },
                JsNodeMatcher::MethodName {
                    method: "updateMany".into(),
                    description: "MongoDB .updateMany() call".into(),
                },
                JsNodeMatcher::MethodName {
                    method: "deleteOne".into(),
                    description: "MongoDB .deleteOne() call".into(),
                },
                JsNodeMatcher::MethodName {
                    method: "deleteMany".into(),
                    description: "MongoDB .deleteMany() call".into(),
                },
                JsNodeMatcher::MethodName {
                    method: "aggregate".into(),
                    description: "MongoDB .aggregate() call".into(),
                },
                JsNodeMatcher::MethodName {
                    method: "countDocuments".into(),
                    description: "MongoDB .countDocuments() call".into(),
                },
            ],
            sanitizers: vec![],
        }
    }
}

impl_rule! {
    TaintNosqlInjection,
    id = "js/taint-nosql-injection",
    severity = Severity::High,
    cwe = Some("CWE-943"),
    description = "Untrusted input reaches a MongoDB query sink — possible NoSQL injection",
    language = Language::JavaScript,
    fn check_with_context(_self, source, tree, ctx) {

        let meta = JsTaintRuleMeta {
            rule_id: _self.id(),
            severity: _self.severity(),
            cwe: _self.cwe(),
            fix_suggestion: Some("Validate and sanitize user input before using in MongoDB queries. Use mongo-sanitize to strip $ operators."),
        };
        map_js_taint_findings(&meta, source, tree, ctx, &Self::spec(), |src, sink| {
            format!(
                "{} reaches {} — untrusted input can inject NoSQL operators",
                src, sink
            )
        })

    }
}

/// Returns the taint rule ID and spec pairs for all JavaScript taint rules.
/// Used by the scanner's pass 1 to extract cross-file summaries: each
/// rule's sinks are tested against function bodies with synthetic
/// per-parameter sources.
pub fn js_taint_rule_specs() -> Vec<(&'static str, JsTaintSpec)> {
    vec![
        ("js/taint-xss-innerhtml", TaintXssInnerHtml::spec()),
        ("js/taint-sql-injection", TaintSqlInjection::spec()),
        ("js/taint-eval", TaintEval::spec()),
        ("js/taint-command-injection", TaintCommandInjection::spec()),
        ("js/taint-ssrf", TaintSsrf::spec()),
        ("js/taint-ssti", TaintSsti::spec()),
        ("js/taint-xpath-injection", TaintXpathInjection::spec()),
        ("js/taint-ldap-injection", TaintLdapInjection::spec()),
        ("js/taint-log-injection", TaintLogInjection::spec()),
        ("js/taint-xxe", TaintXxe::spec()),
        ("js/taint-nosql-injection", TaintNosqlInjection::spec()),
    ]
}
