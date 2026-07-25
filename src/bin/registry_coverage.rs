//! Registry-coverage measurement harness.
//!
//! Walks a directory of real Semgrep registry rule YAML (e.g. a clone of
//! <https://github.com/semgrep/semgrep-rules>), runs every rule through
//! foxguard's existing Semgrep-compat loader, and reports how well the loader
//! covers the registry today:
//!
//! - total rule files / total rules / rules loaded OK / rules skipped
//! - a histogram of *why* rules are skipped, keyed by the unsupported
//!   operator/key (e.g. `metavariable-pattern`, `focus-metavariable`,
//!   `mode: taint (non-python)`, generic mode, ...)
//! - a per-language breakdown
//! - a priority-ordered backlog: which missing operator, if implemented,
//!   would unlock the most registry rules
//!
//! This is a MEASUREMENT tool. It does not bundle any rule into the binary and
//! it does not mutate the loader. It classifies each rule two ways and keeps
//! them consistent:
//!
//! 1. A static classifier over the raw YAML that mirrors the loader's
//!    supported-operator subset (so we can attribute a precise skip reason —
//!    the loader itself collapses many rejections into a single coarse error
//!    or a silent no-op matcher).
//! 2. The real loader (`parse_semgrep_str`) run per single-rule document, used
//!    as a ground-truth cross-check that "supported" rules actually produce a
//!    live foxguard rule object.
//!
//! ## How to run
//!
//! ```sh
//! # 1. Snapshot the real registry (gitignored, never committed):
//! git clone --depth 1 https://github.com/semgrep/semgrep-rules .registry-snapshot
//!
//! # 2. Run the harness and regenerate the markdown report:
//! cargo run --release --bin registry_coverage -- .registry-snapshot
//!
//! # Optional: write the report somewhere else (default: docs/parity/registry-coverage.md)
//! cargo run --release --bin registry_coverage -- .registry-snapshot --out docs/parity/registry-coverage.md
//! ```

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use foxguard::rules::semgrep_compat::parse_semgrep_str;
use serde_yaml_ng::Value as Yaml;

/// Top-level / structural keys that do not affect whether foxguard can match a
/// rule. Their presence never makes a rule "unsupported".
const STRUCTURAL_KEYS: &[&str] = &[
    "id",
    "message",
    "severity",
    "languages",
    "language",
    "metadata",
    "paths",
    "mode",
    // Cosmetic / autofix / engine-tuning keys the loader simply ignores —
    // they don't change whether the *match* itself is supported.
    "fix",
    "fix-regex",
    "options",
    "min-version",
    "max-version",
    "engine",
    "script",
    "script_path",
    "query",
    "database",
];

/// Pattern operators the compat loader implements (see `build_matcher` in
/// `src/rules/semgrep_compat.rs` and `docs/compatibility.md`).
const SUPPORTED_PATTERN_OPERATORS: &[&str] = &[
    "pattern",
    "pattern-regex",
    "pattern-either",
    "pattern-not",
    "pattern-not-regex",
    "pattern-inside",
    "pattern-not-inside",
    "patterns",
    "metavariable-regex",
    "metavariable-comparison",
    "metavariable-pattern",
    "focus-metavariable",
    "metavariable-analysis",
];

/// Languages the compat loader maps to a real foxguard parser
/// (see `map_language`), plus `regex` which is handled by the regex-mode
/// engine (not a tree-sitter grammar). Anything else is an unsupported-language skip.
fn language_supported(lang: &str) -> bool {
    matches!(
        lang.to_lowercase().as_str(),
        "javascript"
            | "js"
            | "typescript"
            | "ts"
            | "jsx"
            | "tsx"
            | "python"
            | "py"
            | "go"
            | "golang"
            | "ruby"
            | "rb"
            | "java"
            | "php"
            | "rust"
            | "rs"
            | "csharp"
            | "c#"
            | "cs"
            | "swift"
            | "kotlin"
            | "kt"
            | "c"
            | "hcl"
            | "terraform"
            | "tf"
            | "solidity"
            | "sol"
            | "yaml"
            | "yml"
            // `languages: [regex]` rules are handled by the regex-mode engine
            // (pure pattern-regex against raw text, no tree-sitter parse needed).
            | "regex"
            // Dockerfile grammar (tree-sitter-containerfile).
            | "dockerfile"
            | "docker"
            // Bash grammar (tree-sitter-bash).
            | "bash"
            | "sh"
            // OCaml grammar (tree-sitter-ocaml).
            | "ocaml"
            | "ml"
            | "mli"
            // Scala grammar (tree-sitter-scala).
            | "scala"
            | "sc"
            // Elixir grammar (tree-sitter-elixir).
            | "elixir"
            | "ex"
            | "exs"
            // JSON grammar (tree-sitter-json).
            | "json"
            // Apex grammar (tree-sitter-sfapex).
            | "apex"
            // Clojure grammar (tree-sitter-clojure-orchard).
            | "clojure"
            | "clj"
            | "cljs"
            | "cljc"
            // HTML grammar (tree-sitter-html).
            | "html"
            | "htm"
            // XML grammar (tree-sitter-xml).
            | "xml"
            // Dart grammar (tree-sitter-dart).
            | "dart"
    )
}

/// Taint mode is compiled for Python / JavaScript / Go / Java / C / Kotlin / Ruby / PHP
/// (see `src/rules/semgrep_taint.rs`).
fn taint_language_supported(lang: &str) -> bool {
    matches!(
        lang.to_lowercase().as_str(),
        "python"
            | "py"
            | "javascript"
            | "js"
            | "typescript"
            | "ts"
            | "go"
            | "golang"
            | "java"
            | "c"
            | "kotlin"
            | "kt"
            | "ruby"
            | "rb"
            | "php"
            | "csharp"
            | "cs"
            | "c#"
            | "bash"
            | "sh"
            | "shell"
            | "solidity"
            | "sol"
            | "scala"
            | "apex"
            | "swift"
    )
}

#[derive(Debug)]
enum Outcome {
    /// Loader produces a live, non-empty matcher for this rule.
    Loaded,
    /// Rule is skipped / degraded. The string is the dominant blocking reason
    /// (the operator/key that needs implementing to unlock it).
    Skipped(String),
}

#[derive(Default)]
struct Stats {
    files_total: usize,
    files_parse_error: usize,
    rules_total: usize,
    rules_loaded: usize,
    rules_skipped: usize,
    /// skip reason -> count
    skip_histogram: BTreeMap<String, usize>,
    /// language -> (loaded, skipped)
    per_language: BTreeMap<String, (usize, usize)>,
    /// language -> skip reason -> count
    per_language_reasons: BTreeMap<String, BTreeMap<String, usize>>,
}

impl Stats {
    fn record(&mut self, lang: &str, outcome: &Outcome) {
        self.rules_total += 1;
        let entry = self.per_language.entry(lang.to_string()).or_default();
        match outcome {
            Outcome::Loaded => {
                self.rules_loaded += 1;
                entry.0 += 1;
            }
            Outcome::Skipped(reason) => {
                self.rules_skipped += 1;
                entry.1 += 1;
                *self.skip_histogram.entry(reason.clone()).or_default() += 1;
                *self
                    .per_language_reasons
                    .entry(lang.to_string())
                    .or_default()
                    .entry(reason.clone())
                    .or_default() += 1;
            }
        }
    }
}

/// Recursively collect every mapping key that appears anywhere under `node`.
/// Used to detect unsupported operators nested inside `patterns:` /
/// `pattern-either:` / taint blocks.
fn collect_keys(node: &Yaml, out: &mut Vec<String>) {
    match node {
        Yaml::Mapping(map) => {
            for (k, v) in map {
                if let Some(key) = k.as_str() {
                    out.push(key.to_string());
                }
                collect_keys(v, out);
            }
        }
        Yaml::Sequence(seq) => {
            for item in seq {
                collect_keys(item, out);
            }
        }
        _ => {}
    }
}

/// Extract the languages list (handles both `languages: [..]` and the rare
/// singular `language:`).
fn rule_languages(rule: &Yaml) -> Vec<String> {
    if let Some(seq) = rule.get("languages").and_then(Yaml::as_sequence) {
        return seq
            .iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect();
    }
    if let Some(one) = rule.get("language").and_then(Yaml::as_str) {
        return vec![one.to_string()];
    }
    if let Some(one) = rule.get("languages").and_then(Yaml::as_str) {
        return vec![one.to_string()];
    }
    Vec::new()
}

/// Pick the representative language bucket for reporting. The loader maps
/// js/ts/jsx/tsx onto one JavaScript parser, so collapse those.
fn language_bucket(langs: &[String]) -> String {
    if langs.is_empty() {
        return "<none>".to_string();
    }
    let first = langs[0].to_lowercase();
    match first.as_str() {
        "js" | "jsx" | "tsx" | "ts" | "typescript" => "javascript".to_string(),
        "golang" => "go".to_string(),
        "py" => "python".to_string(),
        "rb" => "ruby".to_string(),
        "kt" => "kotlin".to_string(),
        "rs" => "rust".to_string(),
        "c#" | "cs" => "csharp".to_string(),
        "generic" => "generic".to_string(),
        "regex" => "regex".to_string(),
        other => other.to_string(),
    }
}

/// Classify a single rule node into Loaded / Skipped(reason).
///
/// The reason string is chosen to name the single operator/key whose absence
/// blocks the rule, so the histogram tells us what to build next.
fn classify_rule(rule: &Yaml) -> Outcome {
    let langs = rule_languages(rule);

    // --- Engine bridges: not pattern rules, handled by their own bridge ---
    if let Some(engine) = rule.get("engine").and_then(Yaml::as_str) {
        let e = engine.to_lowercase();
        if e == "coccinelle" || e == "codeql" {
            return Outcome::Skipped(format!("engine: {e} (bridge, not pattern)"));
        }
    }

    // --- Unsupported language(s) ---
    if langs.is_empty() {
        return Outcome::Skipped("no/unknown languages".to_string());
    }
    let mode = rule.get("mode").and_then(Yaml::as_str).unwrap_or("search");

    // --- Mode handling ---
    match mode {
        "taint" => {
            // Taint compiles for python/js/ts/go/java/c/kotlin today.
            if !langs.iter().any(|l| taint_language_supported(l)) {
                return Outcome::Skipped(format!(
                    "mode: taint (unsupported language: {})",
                    language_bucket(&langs)
                ));
            }
            // Even on supported langs, the taint bridge only accepts a narrow
            // source/sink shape. Detect operators it rejects inside the
            // source/sink/sanitizer blocks.
            // The taint bridge supports `pattern` / `pattern-either` /
            // `patterns:` inside those blocks (see semgrep_taint.rs +
            // docs/compatibility.md). `patterns:` blocks undergo graceful
            // degradation: expressible `pattern:`/`pattern-either:` sub-items
            // are compiled; constraint-only sub-items (pattern-inside, etc.)
            // are dropped with a warning making the matcher broader. The real
            // loader (ground_truth) is the authoritative accept/reject for
            // taint rules now — no static pre-classification needed here.
            // `pattern-propagators` is now compiled by the loader (the
            // "argument taints receiver" subset, see semgrep_taint.rs); rules
            // that use it are ground-truthed like any other taint rule rather
            // than hard-skipped.
            return ground_truth(rule, "mode: taint (unsupported shape)");
        }
        "search" => {}
        other => {
            return Outcome::Skipped(format!("mode: {other}"));
        }
    }

    // --- Search-mode pattern rules: scan for unsupported operators ---
    let mut keys = Vec::new();
    collect_keys(rule, &mut keys);

    // Priority-ordered list of unsupported operators. The first one present is
    // reported as the blocking reason (these are roughly ordered by how
    // central they are to the rule's match).
    const UNSUPPORTED_OPERATORS: &[&str] = &[
        // metavariable-pattern / metavariable-comparison / focus-metavariable /
        // metavariable-analysis / metavariable-type are now implemented by the
        // loader — they fall through to ground_truth below. (For the enforceable
        // statically-typed languages; unenforceable ones are skipped by the
        // loader itself and surface via ground_truth.)
        "pattern-sources",
        "pattern-sinks",
        "pattern-sanitizers",
        "pattern-propagators",
        "semgrep-internal-metavariable-name",
        "join",
    ];

    for op in UNSUPPORTED_OPERATORS {
        if keys.iter().any(|k| k == op) {
            return Outcome::Skipped((*op).to_string());
        }
    }

    // Generic mode (languages: [generic]) — tokenized spacegrep matching;
    // foxguard routes these to `generic_mode.rs`. We now attempt to load
    // them via the real loader; rules that produce no live matcher are
    // reported as skipped with a generic-mode reason.
    if langs.iter().any(|l| l.eq_ignore_ascii_case("generic")) {
        return ground_truth(rule, "generic mode (languages: [generic])");
    }

    // `languages: [regex]` rules with no pattern-regex anywhere cannot be compiled
    // by the regex-mode engine (it only supports pattern-regex, not AST patterns).
    if langs.iter().any(|l| l.eq_ignore_ascii_case("regex"))
        && !keys.iter().any(|k| k == "pattern-regex")
    {
        return Outcome::Skipped("regex language (no pattern-regex)".to_string());
    }

    // No supported language among the declared ones.
    if !langs.iter().any(|l| language_supported(l)) {
        return Outcome::Skipped(format!("unsupported language: {}", language_bucket(&langs)));
    }

    // Does the rule even declare a pattern operator the loader understands?
    let has_supported_pattern = keys
        .iter()
        .any(|k| SUPPORTED_PATTERN_OPERATORS.contains(&k.as_str()));
    if !has_supported_pattern {
        // No recognizable pattern source at all -> loader builds a no-op matcher.
        // Name the most prominent unknown operator if there is one, else generic.
        let unknown = keys
            .iter()
            .find(|k| {
                !STRUCTURAL_KEYS.contains(&k.as_str())
                    && !SUPPORTED_PATTERN_OPERATORS.contains(&k.as_str())
                    && !k.starts_with("pattern")
            })
            .cloned();
        return Outcome::Skipped(
            unknown.unwrap_or_else(|| "no supported pattern operator".to_string()),
        );
    }

    // Looks supported by the static classifier — confirm with the real loader.
    ground_truth(rule, "loader rejected (other)")
}

/// Run the rule through the real `parse_semgrep_str` (as a one-rule document)
/// to confirm the static classification. Returns Loaded only when the loader
/// emits at least one live rule object.
fn ground_truth(rule: &Yaml, fallback_reason: &str) -> Outcome {
    // Wrap the single rule in a fresh `rules:` document.
    let doc = Yaml::Mapping({
        let mut m = serde_yaml_ng::Mapping::new();
        m.insert(
            Yaml::String("rules".into()),
            Yaml::Sequence(vec![rule.clone()]),
        );
        m
    });
    let content = match serde_yaml_ng::to_string(&doc) {
        Ok(c) => c,
        Err(_) => return Outcome::Skipped(fallback_reason.to_string()),
    };
    match parse_semgrep_str(&content, "<registry-coverage>") {
        Ok(rules) if !rules.is_empty() => Outcome::Loaded,
        Ok(_) => Outcome::Skipped(fallback_reason.to_string()),
        Err(_) => Outcome::Skipped(fallback_reason.to_string()),
    }
}

fn is_rule_yaml(path: &Path) -> bool {
    let ext = path.extension().and_then(|s| s.to_str());
    if !matches!(ext, Some("yaml" | "yml")) {
        return false;
    }
    // Skip semgrep's own test fixtures (`*.test.yaml`) and obvious non-rule docs.
    let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
    if name.ends_with(".test.yaml") || name.ends_with(".test.yml") {
        return false;
    }
    true
}

/// Build a `PathBuf` from a CLI-provided string, rejecting parent-directory
/// (`..`) traversal segments. This is a developer-facing measurement tool, but
/// validating the arg keeps the path handling honest (and avoids the
/// `rs/no-path-traversal` foxguard rule firing on our own code).
fn cli_path(raw: &str) -> PathBuf {
    // This is the validating wrapper itself; the `..` traversal check below is
    // exactly what the rule asks for, so suppress it on this one line.
    let candidate = PathBuf::from(raw); // foxguard: ignore[rs/no-path-traversal]
    if candidate
        .components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        eprintln!("error: path '{raw}' contains a '..' traversal segment; refusing.");
        std::process::exit(2);
    }
    candidate
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut root: Option<PathBuf> = None;
    let mut out = PathBuf::from("docs/parity/registry-coverage.md");
    // `--list-skips <lang>` prints one `id\treason` line per skipped rule in the
    // given language bucket to stderr — a debugging aid for attributing skips to
    // specific registry rules (measurement only; does not affect the report).
    let mut list_skips: Option<String> = None;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--out" => {
                i += 1;
                if let Some(p) = args.get(i) {
                    out = cli_path(p);
                }
            }
            "--list-skips" => {
                i += 1;
                list_skips = args.get(i).map(|s| s.to_lowercase());
            }
            other => root = Some(cli_path(other)),
        }
        i += 1;
    }

    let Some(root) = root else {
        eprintln!(
            "usage: registry_coverage <registry-dir> [--out docs/parity/registry-coverage.md]\n\
             \n\
             Snapshot the registry first (gitignored):\n  \
             git clone --depth 1 https://github.com/semgrep/semgrep-rules .registry-snapshot"
        );
        std::process::exit(2);
    };

    if !root.exists() {
        eprintln!(
            "error: registry dir '{}' does not exist.\n\
             Clone it first:\n  \
             git clone --depth 1 https://github.com/semgrep/semgrep-rules .registry-snapshot",
            root.display()
        );
        std::process::exit(2);
    }

    let mut stats = Stats::default();

    let walker = walkdir::WalkDir::new(&root)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file() && is_rule_yaml(e.path()))
        // Skip the snapshot's own VCS metadata.
        .filter(|e| !e.path().components().any(|c| c.as_os_str() == ".git"));

    for entry in walker {
        let content = match std::fs::read_to_string(entry.path()) {
            Ok(c) => c,
            Err(_) => continue,
        };
        let doc: Yaml = match serde_yaml_ng::from_str(&content) {
            Ok(d) => d,
            Err(_) => {
                stats.files_total += 1;
                stats.files_parse_error += 1;
                continue;
            }
        };
        let Some(rules) = doc.get("rules").and_then(Yaml::as_sequence) else {
            // Not a rule file (template, schema, etc.) — don't count it.
            continue;
        };
        stats.files_total += 1;

        for rule in rules {
            let langs = rule_languages(rule);
            let bucket = language_bucket(&langs);
            // The live loader is the ground truth for loaded-vs-skipped. The
            // static `classify_rule` is used only to *attribute* a skip reason
            // when the loader genuinely rejects the rule — otherwise the metric
            // drifts stale every time the loader gains a new capability.
            let outcome = match ground_truth(rule, "") {
                Outcome::Loaded => Outcome::Loaded,
                Outcome::Skipped(_) => match classify_rule(rule) {
                    Outcome::Skipped(reason) => Outcome::Skipped(reason),
                    Outcome::Loaded => Outcome::Skipped("loader rejected (other)".to_string()),
                },
            };
            if let (Some(want), Outcome::Skipped(reason)) = (&list_skips, &outcome) {
                if bucket.eq_ignore_ascii_case(want) {
                    let id = rule.get("id").and_then(Yaml::as_str).unwrap_or("<no-id>");
                    eprintln!("SKIP\t{bucket}\t{id}\t{reason}");
                }
            }
            stats.record(&bucket, &outcome);
        }
    }

    let report = render_report(&root, &stats);
    if let Some(parent) = out.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Err(e) = std::fs::write(&out, &report) {
        eprintln!("error: failed to write report to {}: {e}", out.display());
        std::process::exit(1);
    }

    // Also echo the headline numbers to stdout for CI / interactive use.
    let load_rate = pct(stats.rules_loaded, stats.rules_total);
    println!(
        "registry-coverage: {} files, {} rules, {} loaded ({:.1}%), {} skipped",
        stats.files_total, stats.rules_total, stats.rules_loaded, load_rate, stats.rules_skipped
    );
    println!("report written to {}", out.display());
}

/// A skip reason is a "language gap" (needs a new grammar) rather than an
/// "operator gap" (implementable in the matcher) when it names a missing
/// language/grammar family.
fn is_language_gap(reason: &str) -> bool {
    reason.starts_with("unsupported language:")
        || reason.starts_with("generic mode")
        // "regex language (no pattern-regex)" — the rule itself is malformed
        // (only AST patterns in a regex-mode rule); classify as operator gap.
        || reason.starts_with("no/unknown languages")
        // `mode: taint (unsupported language: <lang>)` is gated on the taint
        // engine supporting that language's grammar — treat as a language axis.
        || reason.starts_with("mode: taint (unsupported language")
}

fn pct(n: usize, d: usize) -> f64 {
    if d == 0 {
        0.0
    } else {
        100.0 * n as f64 / d as f64
    }
}

fn render_report(root: &Path, stats: &Stats) -> String {
    use std::fmt::Write;
    let mut s = String::new();

    let today = "2026-07-05";
    let _ = writeln!(s, "# Semgrep registry coverage");
    let _ = writeln!(s);
    let _ = writeln!(
        s,
        "> Status: {today}. Generated by `cargo run --release --bin registry_coverage -- {}`.",
        root.display()
    );
    let _ = writeln!(s, "> Living document — regenerate after loader changes.");
    let _ = writeln!(s);
    let _ = writeln!(
        s,
        "Measures how well foxguard's existing Semgrep-compat YAML loader \
         (`src/rules/semgrep_compat.rs`) handles a snapshot of the real \
         [semgrep-rules](https://github.com/semgrep/semgrep-rules) registry. \
         Each rule is classified by whether the loader produces a live matcher, \
         and skips are attributed to the single unsupported operator/key that \
         blocks them. This drives the parity roadmap: build the operator at the \
         top of the priority list to unlock the most rules."
    );
    let _ = writeln!(s);

    // --- Overall ---
    let _ = writeln!(s, "## Overall");
    let _ = writeln!(s);
    let _ = writeln!(s, "| Metric | Value |");
    let _ = writeln!(s, "|---|---|");
    let _ = writeln!(s, "| Rule files scanned | {} |", stats.files_total);
    let _ = writeln!(
        s,
        "| Files with YAML parse errors | {} |",
        stats.files_parse_error
    );
    let _ = writeln!(s, "| Total rules | {} |", stats.rules_total);
    let _ = writeln!(
        s,
        "| Rules loaded OK | {} ({:.1}%) |",
        stats.rules_loaded,
        pct(stats.rules_loaded, stats.rules_total)
    );
    let _ = writeln!(
        s,
        "| Rules skipped | {} ({:.1}%) |",
        stats.rules_skipped,
        pct(stats.rules_skipped, stats.rules_total)
    );
    let _ = writeln!(s);
    let _ = writeln!(
        s,
        "**Headline load rate: {:.1}%** ({} / {} rules).",
        pct(stats.rules_loaded, stats.rules_total),
        stats.rules_loaded,
        stats.rules_total
    );
    let _ = writeln!(s);

    // --- Skip histogram (sorted by frequency) ---
    let _ = writeln!(s, "## Skip-reason histogram");
    let _ = writeln!(s);
    let _ = writeln!(
        s,
        "Sorted by frequency. The reason names the operator/key that blocks the \
         rule today."
    );
    let _ = writeln!(s);
    let mut sorted: Vec<(&String, &usize)> = stats.skip_histogram.iter().collect();
    sorted.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
    let _ = writeln!(s, "| Skip reason | Rules | % of skipped | % of all rules |");
    let _ = writeln!(s, "|---|---:|---:|---:|");
    for (reason, count) in &sorted {
        let _ = writeln!(
            s,
            "| `{}` | {} | {:.1}% | {:.1}% |",
            reason,
            count,
            pct(**count, stats.rules_skipped),
            pct(**count, stats.rules_total)
        );
    }
    let _ = writeln!(s);

    // --- Priority order ---
    // Split the backlog into two axes the team works independently:
    //  - operator/feature gaps inside the matcher (implementable in
    //    semgrep_compat.rs / semgrep_taint.rs)
    //  - missing tree-sitter language grammars (a separate, heavier lift)
    let (lang_reasons, op_reasons): (Vec<_>, Vec<_>) = sorted
        .iter()
        .partition(|(reason, _)| is_language_gap(reason));

    let _ = writeln!(s, "## Priority order — operator/feature backlog");
    let _ = writeln!(s);
    let _ = writeln!(
        s,
        "Matcher capabilities (implementable in `semgrep_compat.rs` / \
         `semgrep_taint.rs`) ranked by how many registry rules each would \
         unlock. These are independent of adding new language grammars. Build \
         top-down."
    );
    let _ = writeln!(s);
    let _ = writeln!(s, "| Rank | Capability to add | Rules unlocked |");
    let _ = writeln!(s, "|---:|---|---:|");
    for (rank, (reason, count)) in op_reasons.iter().enumerate() {
        let _ = writeln!(s, "| {} | `{}` | {} |", rank + 1, reason, count);
    }
    let op_total: usize = op_reasons.iter().map(|(_, c)| **c).sum();
    let _ = writeln!(s);
    let _ = writeln!(
        s,
        "Operator/feature gaps account for **{} rules** ({:.1}% of all rules). \
         Closing the top of this list is the highest-leverage parity work that \
         does not require a new parser.",
        op_total,
        pct(op_total, stats.rules_total)
    );
    let _ = writeln!(s);

    let _ = writeln!(s, "## Priority order — missing language grammars");
    let _ = writeln!(s);
    let _ = writeln!(
        s,
        "Rules foxguard cannot run because it has no tree-sitter grammar for the \
         target language (a separate, heavier lift than matcher operators)."
    );
    let _ = writeln!(s);
    let _ = writeln!(s, "| Rank | Language to add | Rules unlocked |");
    let _ = writeln!(s, "|---:|---|---:|");
    for (rank, (reason, count)) in lang_reasons.iter().enumerate() {
        let _ = writeln!(s, "| {} | `{}` | {} |", rank + 1, reason, count);
    }
    let lang_total: usize = lang_reasons.iter().map(|(_, c)| **c).sum();
    let _ = writeln!(s);
    let _ = writeln!(
        s,
        "Missing-grammar gaps account for **{} rules** ({:.1}% of all rules).",
        lang_total,
        pct(lang_total, stats.rules_total)
    );
    let _ = writeln!(s);

    // --- Per-language breakdown ---
    let _ = writeln!(s, "## Per-language breakdown");
    let _ = writeln!(s);
    let _ = writeln!(
        s,
        "Language is the rule's first declared language (js/ts/jsx/tsx \
         collapsed to `javascript`, matching the loader)."
    );
    let _ = writeln!(s);
    let _ = writeln!(s, "| Language | Total | Loaded | Skipped | Load rate |");
    let _ = writeln!(s, "|---|---:|---:|---:|---:|");
    let mut langs: Vec<(&String, &(usize, usize))> = stats.per_language.iter().collect();
    langs.sort_by(|a, b| {
        let at = a.1 .0 + a.1 .1;
        let bt = b.1 .0 + b.1 .1;
        bt.cmp(&at).then(a.0.cmp(b.0))
    });
    for (lang, (loaded, skipped)) in &langs {
        let total = *loaded + *skipped;
        let _ = writeln!(
            s,
            "| {} | {} | {} | {} | {:.1}% |",
            lang,
            total,
            loaded,
            skipped,
            pct(*loaded, total)
        );
    }
    let _ = writeln!(s);

    // --- Top skip reason per language ---
    let _ = writeln!(s, "## Top skip reasons per language");
    let _ = writeln!(s);
    for (lang, reasons) in &stats.per_language_reasons {
        let mut rs: Vec<(&String, &usize)> = reasons.iter().collect();
        if rs.is_empty() {
            continue;
        }
        rs.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
        let top: Vec<String> = rs
            .iter()
            .take(3)
            .map(|(r, c)| format!("`{r}` ({c})"))
            .collect();
        let _ = writeln!(s, "- **{}**: {}", lang, top.join(", "));
    }
    let _ = writeln!(s);

    let _ = writeln!(
        s,
        "---\n\nRegenerate with `cargo run --release --bin registry_coverage -- <registry-dir>`. \
         The registry snapshot is gitignored (`.registry-snapshot/`) and never committed."
    );

    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(yaml: &str) -> Yaml {
        // Test-only helper; panics on malformed inline fixtures are intentional.
        // (The inline ignores keep older foxguard builds — which predate the
        // `#[cfg(test)]` exclusion in `rs/no-unwrap-in-lib` — from flagging
        // these test-only expects.)
        // foxguard: ignore[rs/no-unwrap-in-lib]
        let doc: Yaml = serde_yaml_ng::from_str(yaml).expect("test fixture is valid YAML");
        // foxguard: ignore[rs/no-unwrap-in-lib]
        let rules = doc
            .get("rules")
            .and_then(Yaml::as_sequence)
            .expect("test fixture has a rules: sequence");
        // foxguard: ignore[rs/no-unwrap-in-lib]
        rules
            .first()
            .cloned()
            .expect("test fixture has at least one rule")
    }

    #[test]
    fn simple_supported_rule_loads() {
        let r = rule(
            r#"
rules:
  - id: eval-call
    pattern: eval(...)
    message: no eval
    severity: ERROR
    languages: [python]
"#,
        );
        assert!(matches!(classify_rule(&r), Outcome::Loaded));
    }

    #[test]
    fn metavariable_pattern_now_loads() {
        // metavariable-pattern is implemented by the loader — the classifier must
        // no longer pre-skip it; ground_truth confirms a live matcher.
        let r = rule(
            r#"
rules:
  - id: mvp
    patterns:
      - pattern: foo($X)
      - metavariable-pattern:
          metavariable: $X
          pattern: bar(...)
    message: m
    severity: WARNING
    languages: [python]
"#,
        );
        assert!(matches!(classify_rule(&r), Outcome::Loaded));
    }

    #[test]
    fn focus_metavariable_now_loads() {
        let r = rule(
            r#"
rules:
  - id: focus
    patterns:
      - pattern: foo($X)
      - focus-metavariable: $X
    message: m
    severity: WARNING
    languages: [java]
"#,
        );
        assert!(matches!(classify_rule(&r), Outcome::Loaded));
    }

    #[test]
    fn generic_mode_simple_pattern_now_loads() {
        // A simple `pattern: foo` generic rule now goes through the real loader
        // and produces a live rule — classify_rule should return Loaded.
        let r = rule(
            r#"
rules:
  - id: gen
    pattern: foo
    message: m
    severity: INFO
    languages: [generic]
"#,
        );
        // The loader produces live rules → Loaded (no longer hard-skipped).
        assert!(
            matches!(classify_rule(&r), Outcome::Loaded),
            "simple generic pattern: rule should now load"
        );
    }

    #[test]
    fn generic_mode_patterns_block_now_loads() {
        // A `patterns:` AND-block generic rule should now load.
        let r = rule(
            r#"
rules:
  - id: gen-patterns
    patterns:
      - pattern: ssl_protocols ...
      - pattern-not: ssl_protocols TLSv1_3
    message: m
    severity: WARNING
    languages: [generic]
"#,
        );
        assert!(
            matches!(classify_rule(&r), Outcome::Loaded),
            "generic patterns: rule should now load"
        );
    }

    #[test]
    fn unsupported_language_is_skipped() {
        // COBOL has no supported grammar — it must be skipped.
        let r = rule(
            r#"
rules:
  - id: cobol-rule
    pattern: foo
    message: m
    severity: INFO
    languages: [cobol]
"#,
        );
        match classify_rule(&r) {
            Outcome::Skipped(reason) => assert_eq!(reason, "unsupported language: cobol"),
            other => panic!("expected skip, got {other:?}"),
        }
    }

    #[test]
    fn apex_language_loads() {
        // Apex now has a real grammar (tree-sitter-sfapex), so search-mode
        // Apex rules must load.
        let r = rule(
            r#"
rules:
  - id: apex-rule
    pattern-regex: 'System\.debug'
    message: m
    severity: INFO
    languages: [apex]
"#,
        );
        assert!(matches!(classify_rule(&r), Outcome::Loaded));
    }

    #[test]
    fn yaml_language_loads() {
        let r = rule(
            r#"
rules:
  - id: yaml-rule
    pattern: "key: $VALUE"
    message: found key
    severity: INFO
    languages: [yaml]
"#,
        );
        assert!(matches!(classify_rule(&r), Outcome::Loaded));
    }

    #[test]
    fn non_python_taint_is_a_language_gap() {
        // Elixir is still an unsupported language for taint mode.
        let r = rule(
            r#"
rules:
  - id: elixir-taint
    mode: taint
    pattern-sources:
      - pattern: source()
    pattern-sinks:
      - pattern: sink(...)
    message: m
    severity: ERROR
    languages: [elixir]
"#,
        );
        match classify_rule(&r) {
            Outcome::Skipped(reason) => {
                assert!(reason.contains("unsupported language"));
                assert!(is_language_gap(&reason));
            }
            other => panic!("expected skip, got {other:?}"),
        }
    }

    #[test]
    fn ruby_taint_now_loads() {
        // Ruby taint is bridged now — a simple source/sink rule must load.
        let r = rule(
            r#"
rules:
  - id: ruby-taint
    mode: taint
    pattern-sources:
      - pattern: gets($X)
    pattern-sinks:
      - pattern: system($X)
    message: m
    severity: ERROR
    languages: [ruby]
"#,
        );
        assert!(matches!(classify_rule(&r), Outcome::Loaded));
    }

    #[test]
    fn java_taint_now_loads() {
        // Java taint is bridged now — a simple source/sink rule must load.
        let r = rule(
            r#"
rules:
  - id: java-taint
    mode: taint
    pattern-sources:
      - pattern: request.getParameter($X)
    pattern-sinks:
      - pattern: Runtime.exec($X)
    message: m
    severity: ERROR
    languages: [java]
"#,
        );
        assert!(matches!(classify_rule(&r), Outcome::Loaded));
    }

    #[test]
    fn language_vs_operator_gap_partition() {
        assert!(is_language_gap("unsupported language: hcl"));
        assert!(is_language_gap("generic mode (languages: [generic])"));
        assert!(!is_language_gap("metavariable-pattern"));
        assert!(!is_language_gap("focus-metavariable"));
        // "regex language (no pattern-regex)" is an operator gap: the rule is
        // malformed (no regex pattern), not a missing grammar.
        assert!(!is_language_gap("regex language (no pattern-regex)"));
    }
}
