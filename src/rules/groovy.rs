//! Groovy rules: Gradle build scripts, Jenkinsfiles and Grails sources.
//!
//! The grammar is a tree-sitter Groovy grammar that understands GString
//! interpolation (`gstring_brace_interpolation` / `gstring_dollar_interpolation`),
//! Jenkins-style command chains (`sh "..."`) and pipeline blocks. Single-quoted
//! and triple-single-quoted strings never interpolate, so they are treated as
//! constants.

use std::collections::HashSet;
use std::sync::OnceLock;

use regex::Regex;

use crate::impl_rule;
use crate::rules::common::{
    hardcoded_secret_re, is_high_signal_secret_name, is_secret_value_long_enough,
    looks_like_secret_value, make_finding, walk_tree,
};
use crate::{Finding, Language, Severity};

type Node<'a> = tree_sitter::Node<'a>;

fn text<'a>(node: Node, src: &'a str) -> &'a str {
    &src[node.byte_range()]
}

fn is_string(node: Node) -> bool {
    node.kind() == "string_literal"
}

fn has_interpolation(node: Node) -> bool {
    let mut cursor = node.walk();
    let found = node.children(&mut cursor).any(|c| {
        matches!(
            c.kind(),
            "gstring_brace_interpolation" | "gstring_dollar_interpolation"
        )
    });
    found
}

/// A string literal without GString interpolation.
fn is_constant_string(node: Node) -> bool {
    is_string(node) && !has_interpolation(node)
}

/// Content of a string literal with its quotes removed.
fn string_inner<'a>(node: Node, src: &'a str) -> &'a str {
    let raw = text(node, src);
    for q in ["\"\"\"", "'''", "\"", "'", "/"] {
        if raw.len() >= 2 * q.len() && raw.starts_with(q) && raw.ends_with(q) {
            return &raw[q.len()..raw.len() - q.len()];
        }
    }
    raw
}

/// True for expressions whose value can vary at run time: interpolated
/// GStrings, `+` concatenation containing a non-constant operand, or any
/// non-literal expression.
fn is_dynamic(node: Node) -> bool {
    match node.kind() {
        "string_literal" => has_interpolation(node),
        "parenthesized_expression" => node.named_child(0).is_some_and(is_dynamic),
        "binary_expression" => {
            let mut cursor = node.walk();
            let any = node.named_children(&mut cursor).any(is_dynamic);
            any
        }
        "list_literal" => {
            let mut cursor = node.walk();
            let any = node.named_children(&mut cursor).any(is_dynamic);
            any
        }
        "number_literal" | "boolean_literal" | "null_literal" => false,
        _ => true,
    }
}

/// Rightmost identifier of an expression (`a.b.c` -> `c`, `x` -> `x`).
fn leaf_name<'a>(node: Node, src: &'a str) -> Option<&'a str> {
    match node.kind() {
        "identifier" => Some(text(node, src)),
        "field_access" => node.child_by_field_name("field").map(|f| text(f, src)),
        _ => None,
    }
}

/// Method name of a `method_invocation` (`a.b()` -> `b`, `f()` -> `f`).
fn invocation_name<'a>(node: Node, src: &'a str) -> Option<&'a str> {
    node.child_by_field_name("function")
        .and_then(|f| leaf_name(f, src))
}

/// Receiver of `recv.method(...)`, if the call has one.
fn invocation_receiver(node: Node) -> Option<Node> {
    let f = node.child_by_field_name("function")?;
    if f.kind() == "field_access" {
        f.child_by_field_name("object")
    } else {
        None
    }
}

fn invocation_args(node: Node) -> Vec<Node> {
    let Some(args) = node.child_by_field_name("arguments") else {
        return Vec::new();
    };
    let mut cursor = args.walk();
    let v = args.named_children(&mut cursor).collect();
    v
}

// ─── Rule 1: groovy/no-hardcoded-secret ───────────────────────────────────

pub struct NoHardcodedSecret;

fn secret_value_flagged(
    name: &str,
    value: Node,
    src: &str,
    thresholds: crate::rules::common::SecretScanThresholds,
) -> bool {
    if !is_constant_string(value) || !hardcoded_secret_re().is_match(name) {
        return false;
    }
    let inner = string_inner(value, src);
    if !is_secret_value_long_enough(inner, thresholds) {
        return false;
    }
    is_high_signal_secret_name(name) || looks_like_secret_value(inner)
}

impl_rule! {
    NoHardcodedSecret,
    id = "groovy/no-hardcoded-secret",
    severity = Severity::High,
    cwe = Some("CWE-798"),
    description = "Hardcoded secret or credential detected",
    language = Language::Groovy,
    fn check_with_context(_self, source, tree, ctx) {
        let mut findings: Vec<Finding> = Vec::new();
        walk_tree(tree.root_node(), source, &mut |node, src| {
            // (name, value) pair for every shape that binds a name to a value.
            let pair: Option<(&str, Node)> = match node.kind() {
                // `String token = '...'` and `def x = '...'`
                "variable_declarator" | "local_variable_declaration" => {
                    match (node.child_by_field_name("name"), node.child_by_field_name("value")) {
                        (Some(n), Some(v)) if n.kind() == "identifier" => Some((text(n, src), v)),
                        _ => None,
                    }
                }
                // `password = '...'`, `env.API_KEY = '...'`, `ext.apiKey = '...'`
                "assignment_expression" => {
                    match (node.child_by_field_name("left"), node.child_by_field_name("right")) {
                        (Some(l), Some(r)) => leaf_name(l, src).map(|n| (n, r)),
                        _ => None,
                    }
                }
                // `[password: '...']`
                "map_entry" => {
                    match (node.child_by_field_name("key"), node.child_by_field_name("value")) {
                        (Some(k), Some(v)) => leaf_name(k, src).map(|n| (n, v)),
                        _ => None,
                    }
                }
                // `foo(password: '...')`
                "named_argument" => {
                    match (node.child_by_field_name("key"), node.child_by_field_name("value")) {
                        (Some(k), Some(v)) => leaf_name(k, src).map(|n| (n, v)),
                        _ => None,
                    }
                }
                // Gradle DSL: `credentials { password 'abc...' }`
                "command_chain" => {
                    match (node.child_by_field_name("receiver"), node.child_by_field_name("argument")) {
                        (Some(r), Some(a)) if r.kind() == "identifier" => Some((text(r, src), a)),
                        _ => None,
                    }
                }
                _ => None,
            };
            if let Some((name, value)) = pair {
                if secret_value_flagged(name, value, src, ctx.secret_thresholds) {
                    findings.push(make_finding(
                        _self.id(),
                        _self.severity(),
                        _self.cwe(),
                        &format!(
                            "Hardcoded secret in '{}' — read it from credentials()/environment or a secret manager",
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

// ─── Rule 2: groovy/no-command-injection ──────────────────────────────────

pub struct NoCommandInjection;

/// Names bound (anywhere in the file) to a dynamically built string or list,
/// so `cmd.execute()` on such a variable is treated like `"...${x}".execute()`.
fn dynamic_command_vars(root: Node, src: &str) -> HashSet<String> {
    let mut out = HashSet::new();
    walk_tree(root, src, &mut |node, s| {
        let pair = match node.kind() {
            "variable_declarator" | "local_variable_declaration" => (
                node.child_by_field_name("name"),
                node.child_by_field_name("value"),
            ),
            "assignment_expression" => (
                node.child_by_field_name("left"),
                node.child_by_field_name("right"),
            ),
            _ => (None, None),
        };
        if let (Some(n), Some(v)) = pair {
            if n.kind() == "identifier"
                && matches!(
                    v.kind(),
                    "string_literal" | "binary_expression" | "list_literal"
                )
                && is_dynamic(v)
            {
                out.insert(text(n, s).to_string());
            }
        }
    });
    out
}

impl_rule! {
    NoCommandInjection,
    id = "groovy/no-command-injection",
    severity = Severity::Critical,
    cwe = Some("CWE-78"),
    description = "Potential command injection via String.execute(), Runtime.exec or ProcessBuilder with dynamic input",
    language = Language::Groovy,
    fn check(_self, source, tree) {
        let mut findings: Vec<Finding> = Vec::new();
        let dyn_vars = dynamic_command_vars(tree.root_node(), source);
        walk_tree(tree.root_node(), source, &mut |node, src| {
            let mut report = |msg: &str| {
                findings.push(make_finding(
                    _self.id(), _self.severity(), _self.cwe(), msg, node, src,
                ));
            };
            match node.kind() {
                "method_invocation" => {
                    let Some(name) = invocation_name(node, src) else { return };
                    let args = invocation_args(node);
                    let receiver = invocation_receiver(node);
                    match (name, receiver) {
                        // "ls ${dir}".execute(), ["sh", "-c", cmd].execute(),
                        // cmd.execute() where cmd was built dynamically
                        ("execute", Some(r)) => {
                            let dynamic_receiver = match r.kind() {
                                "identifier" => dyn_vars.contains(text(r, src)),
                                "string_literal" | "binary_expression" | "list_literal"
                                | "parenthesized_expression" => is_dynamic(r),
                                _ => false,
                            };
                            if dynamic_receiver {
                                report("String/List.execute() on a dynamically built command — risk of command injection");
                            }
                        }
                        // Runtime.getRuntime().exec(cmd)
                        ("exec", Some(r))
                            if text(r, src).contains("Runtime") =>
                        {
                            if args.first().is_some_and(|a| is_dynamic(*a)) {
                                report("Runtime.exec() called with dynamic argument — risk of command injection");
                            }
                        }
                        _ => {}
                    }
                }
                // new ProcessBuilder("sh", "-c", cmd)
                "object_creation_expression" => {
                    let is_pb = node
                        .child_by_field_name("type")
                        .is_some_and(|t| text(t, src).ends_with("ProcessBuilder"));
                    if is_pb {
                        let mut cursor = node.walk();
                        let args: Vec<Node> = node
                            .child_by_field_name("arguments")
                            .map(|a| a.named_children(&mut cursor).collect())
                            .unwrap_or_default();
                        if args.iter().any(|a| is_dynamic(*a)) {
                            report("ProcessBuilder created with dynamic argument — risk of command injection");
                        }
                    }
                }
                _ => {}
            }
        });
        findings
    }
}

// ─── Rule 3: groovy/no-unsafe-eval ────────────────────────────────────────

pub struct NoUnsafeEval;

fn shell_receiver_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)(GroovyShell|GroovyClassLoader|GroovyScriptEngine|shell|loader)")
            .expect("static Groovy shell regex should compile")
    })
}

impl_rule! {
    NoUnsafeEval,
    id = "groovy/no-unsafe-eval",
    severity = Severity::Critical,
    cwe = Some("CWE-95"),
    description = "Dynamic Groovy script evaluation (Eval, GroovyShell, GroovyClassLoader) of non-constant input",
    language = Language::Groovy,
    fn check(_self, source, tree) {
        let mut findings: Vec<Finding> = Vec::new();
        walk_tree(tree.root_node(), source, &mut |node, src| {
            if node.kind() != "method_invocation" {
                return;
            }
            let Some(name) = invocation_name(node, src) else { return };
            let args = invocation_args(node);
            let Some(last) = args.last().copied() else { return };
            if !is_dynamic(last) {
                return;
            }
            let receiver = invocation_receiver(node).map(|r| text(r, src));
            let msg = match (receiver, name) {
                (Some("Eval"), "me" | "x" | "xy" | "xyz") => {
                    "Eval.* evaluates Groovy source built from non-constant input"
                }
                (Some(r), "evaluate" | "parse" | "run")
                    if shell_receiver_re().is_match(r) =>
                {
                    "GroovyShell evaluates Groovy source built from non-constant input"
                }
                (Some(r), "parseClass") if shell_receiver_re().is_match(r) => {
                    "GroovyClassLoader.parseClass compiles Groovy source built from non-constant input"
                }
                // Jenkins `evaluate(readFile(...))` / Script#evaluate(String)
                (None, "evaluate") => {
                    "evaluate() executes Groovy source built from non-constant input"
                }
                _ => return,
            };
            findings.push(make_finding(
                _self.id(), _self.severity(), _self.cwe(), msg, node, src,
            ));
        });
        findings
    }
}

// ─── Rule 4: groovy/jenkins-sh-interpolation ──────────────────────────────

pub struct JenkinsShInterpolation;

const SHELL_STEPS: &[&str] = &["sh", "bat", "powershell", "pwsh"];

fn user_input_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?x)
            \bparams\b
            | \bBRANCH_NAME\b | \bTAG_NAME\b | \bCHANGE_[A-Z_]+\b | \bGIT_BRANCH\b
            | \bgit_branch\b | \bbranchName\b | \bbranch_name\b
            | \bcurrentBuild\.(description|displayName)\b
            | \bpayload\b | \bgithub\.event\b
            ",
        )
        .expect("static Jenkins user-input regex should compile")
    })
}

/// Text of every interpolation inside a GString.
fn interpolations<'a>(node: Node, src: &'a str) -> Vec<&'a str> {
    let mut cursor = node.walk();
    let v = node
        .children(&mut cursor)
        .filter(|c| {
            matches!(
                c.kind(),
                "gstring_brace_interpolation" | "gstring_dollar_interpolation"
            )
        })
        .map(|c| text(c, src))
        .collect();
    v
}

/// The script argument of a Jenkins shell step, given the step's arguments.
fn script_arg<'a>(args: &[Node<'a>], src: &str) -> Option<Node<'a>> {
    for a in args {
        if a.kind() == "named_argument" {
            if a.child_by_field_name("key")
                .is_some_and(|k| text(k, src) == "script")
            {
                return a.child_by_field_name("value");
            }
        } else {
            return Some(*a);
        }
    }
    None
}

impl_rule! {
    JenkinsShInterpolation,
    id = "groovy/jenkins-sh-interpolation",
    severity = Severity::High,
    cwe = Some("CWE-78"),
    description = "Jenkins sh/bat step interpolates user-controlled input (params, branch or change metadata) into a shell script",
    language = Language::Groovy,
    fn check(_self, source, tree) {
        let mut findings: Vec<Finding> = Vec::new();
        walk_tree(tree.root_node(), source, &mut |node, src| {
            let script: Option<Node> = match node.kind() {
                // sh "echo ${params.X}"
                "command_chain" => {
                    let step = node.child_by_field_name("receiver");
                    let arg = node.child_by_field_name("argument");
                    match (step, arg) {
                        (Some(s), Some(a))
                            if s.kind() == "identifier" && SHELL_STEPS.contains(&text(s, src)) =>
                        {
                            Some(a)
                        }
                        _ => None,
                    }
                }
                // sh("echo ${params.X}") / sh(script: "...", returnStdout: true)
                "method_invocation" => {
                    let step = node.child_by_field_name("function");
                    match step {
                        Some(s)
                            if s.kind() == "identifier" && SHELL_STEPS.contains(&text(s, src)) =>
                        {
                            script_arg(&invocation_args(node), src)
                        }
                        _ => None,
                    }
                }
                // sh script: "..." (the grammar splits this into `sh` + label)
                "labeled_statement" => {
                    let is_script_label = node
                        .child_by_field_name("label")
                        .is_some_and(|l| text(l, src) == "script");
                    let prev = node.prev_named_sibling();
                    let is_step = prev.is_some_and(|p| {
                        p.kind() == "expression_statement"
                            && SHELL_STEPS.contains(&text(p, src).trim())
                    });
                    if is_script_label && is_step {
                        node.child_by_field_name("statement")
                            .and_then(|s| if s.kind() == "expression_statement" { s.named_child(0) } else { Some(s) })
                    } else {
                        None
                    }
                }
                _ => None,
            };
            let Some(script) = script else { return };
            if !is_string(script) || !has_interpolation(script) {
                return;
            }
            // Single-quoted strings never interpolate; only GStrings reach here.
            let raw = text(script, src);
            if raw.starts_with('\'') {
                return;
            }
            if let Some(hit) = interpolations(script, src)
                .into_iter()
                .find(|i| user_input_re().is_match(i))
            {
                findings.push(make_finding(
                    _self.id(),
                    _self.severity(),
                    _self.cwe(),
                    &format!(
                        "User-controlled value {} is interpolated into a shell step by Groovy before the shell runs — pass it via environment variables and quote it in single-quoted script",
                        hit
                    ),
                    node,
                    src,
                ));
            }
        });
        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::parser::parse_file;
    use crate::rules::Rule;

    fn check_rule(rule: &dyn Rule, source: &str) -> Vec<Finding> {
        let tree = parse_file(source, Language::Groovy).expect("parse failed");
        rule.check(source, &tree)
    }

    // ─── secrets ──────────────────────────────────────────────────────────

    #[test]
    fn secret_flags_declaration_assignment_and_gradle_dsl() {
        let src = r#"
def password = "hunter2hunter2"
String apiKey = 'abcd1234efgh'
ext.db_password = "s3cr3tvalue99"
credentials {
    username 'bob'
    password 'abcd1234xyz'
}
publish(password: 'abcd1234xyz')
def cfg = [secret: 'abcd1234xyz']
"#;
        let findings = check_rule(&NoHardcodedSecret, src);
        assert_eq!(findings.len(), 6, "{findings:?}");
    }

    #[test]
    fn secret_ignores_env_interpolation_and_non_secret_names() {
        let src = r#"
def password = System.getenv("DB_PASSWORD")
def token = "${env.TOKEN_VALUE}"
def author = 'someone-long-name'
def url = 'https://example.com'
password = credentials('db-password')
"#;
        let findings = check_rule(&NoHardcodedSecret, src);
        assert!(findings.is_empty(), "{findings:?}");
    }

    // ─── command injection ────────────────────────────────────────────────

    #[test]
    fn command_injection_flags_dynamic_execute_and_exec() {
        let src = r#"
"ls ${dir}".execute()
"rm -rf $dir".execute()
def cmd = "ls " + dir
cmd.execute()
Runtime.getRuntime().exec(cmd)
new ProcessBuilder("sh", "-c", cmd).start()
"#;
        let findings = check_rule(&NoCommandInjection, src);
        assert_eq!(findings.len(), 5, "{findings:?}");
    }

    #[test]
    fn command_injection_ignores_constant_commands() {
        let src = r#"
'ls -la'.execute()
"ls -la".execute()
Runtime.getRuntime().exec("ls")
new ProcessBuilder("ls", "-la").start()
def fixed = "uname"
fixed.execute()
"#;
        let findings = check_rule(&NoCommandInjection, src);
        assert!(findings.is_empty(), "{findings:?}");
    }

    // ─── eval ─────────────────────────────────────────────────────────────

    #[test]
    fn eval_flags_groovyshell_and_eval() {
        let src = r#"
new GroovyShell().evaluate(code)
Eval.me(code)
def shell = new GroovyShell()
shell.parse(userScript)
loader.parseClass(text)
evaluate(readFile('x.groovy'))
"#;
        let findings = check_rule(&NoUnsafeEval, src);
        assert_eq!(findings.len(), 5, "{findings:?}");
    }

    #[test]
    fn eval_ignores_constant_scripts() {
        let src = r#"
Eval.me('1 + 1')
new GroovyShell().evaluate("println 1")
other.parse(code)
"#;
        let findings = check_rule(&NoUnsafeEval, src);
        assert!(findings.is_empty(), "{findings:?}");
    }

    // ─── jenkins sh ───────────────────────────────────────────────────────

    #[test]
    fn jenkins_sh_flags_user_input() {
        let src = r#"
pipeline {
  stages { stage('a') { steps {
    sh "echo ${params.BRANCH}"
    sh(script: "build ${env.BRANCH_NAME}", returnStdout: true)
    sh("git checkout $CHANGE_BRANCH")
    sh script: "deploy ${params.ENV}"
    bat "del ${params.FILE}"
  } } }
}
"#;
        let findings = check_rule(&JenkinsShInterpolation, src);
        assert_eq!(findings.len(), 5, "{findings:?}");
    }

    #[test]
    fn jenkins_sh_ignores_safe_forms() {
        let src = r#"
pipeline {
  stages { stage('a') { steps {
    sh 'echo $BRANCH'
    sh "make -j${env.BUILD_NUMBER}"
    sh(script: "echo ${env.WORKSPACE}")
    sh '''
      echo "$PARAM"
    '''
    echo "${params.X}"
  } } }
}
"#;
        let findings = check_rule(&JenkinsShInterpolation, src);
        assert!(findings.is_empty(), "{findings:?}");
    }
}
