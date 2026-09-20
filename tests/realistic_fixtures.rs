// Integration test for the realistic test corpus (issue #35).
//
// Each fixture under `tests/fixtures/realistic/` is a small-but-complete
// vulnerable application for one supported framework. We pin the exact
// total finding count and the exact count per taint rule. Any rule
// addition or engine change will break these counts, which is the whole
// point: it forces explicit acknowledgment of precision shifts.
//
// The fixtures also contain NEAR-MISS functions whose line ranges must
// not contain any `*/taint-*` findings. We check that indirectly by
// pinning the total taint-finding count per file — if a NEAR-MISS
// function started firing, the total would change.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;

fn foxguard_cmd() -> Command {
    // `--config /dev/null` isolates the test from any developer-local
    // `.foxguard.yml` in CARGO_MANIFEST_DIR. The repo's own baseline
    // suppresses dozens of findings in tests/fixtures/* for self-scan
    // hygiene, which would otherwise leak into every realistic-fixture
    // "expected_total" assertion.
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_foxguard"));
    cmd.args(["--config", "/dev/null"]);
    cmd
}

fn fixture_path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("realistic")
        .join(name)
}

fn scan_json_findings(stdout: &[u8], file: &str) -> Vec<serde_json::Value> {
    let report: serde_json::Value = serde_json::from_slice(stdout)
        .unwrap_or_else(|e| panic!("invalid JSON output for {}: {}", file, e));
    report["findings"]
        .as_array()
        .cloned()
        .expect("JSON report missing findings array")
}

/// Scan a realistic fixture and assert exact total finding count and
/// exact per-taint-rule counts. `taint_counts` lists every taint rule
/// that must fire, with the expected count. Any taint rule observed in
/// the output that is not in `taint_counts` (or with a different count)
/// fails the test — this catches accidental false positives on the
/// NEAR-MISS sections.
fn assert_fixture(file: &str, expected_total: usize, taint_counts: &[(&str, usize)]) {
    let path = fixture_path(file);
    let output = foxguard_cmd()
        .args([path.to_str().unwrap(), "-f", "json"])
        .output()
        .unwrap_or_else(|e| panic!("failed to run foxguard on {}: {}", file, e));

    let findings = scan_json_findings(&output.stdout, file);

    assert_eq!(
        findings.len(),
        expected_total,
        "{}: expected {} total findings, got {}. findings={:?}",
        file,
        expected_total,
        findings.len(),
        findings
            .iter()
            .map(|f| f["rule_id"].as_str().unwrap_or(""))
            .collect::<Vec<_>>()
    );

    let mut counts: HashMap<&str, usize> = HashMap::new();
    for f in &findings {
        if let Some(rule) = f["rule_id"].as_str() {
            *counts.entry(rule).or_insert(0) += 1;
        }
    }

    // Every expected taint rule must fire exactly the expected number
    // of times.
    for (rule, want) in taint_counts {
        let got = counts.get(rule).copied().unwrap_or(0);
        assert_eq!(
            got, *want,
            "{}: taint rule {} expected {} times, got {}. counts={:?}",
            file, rule, want, got, counts
        );
    }

    // Any taint finding for a rule NOT in `taint_counts` is an
    // unexpected false positive — likely on the NEAR-MISS section.
    let expected_rules: std::collections::HashSet<&str> =
        taint_counts.iter().map(|(r, _)| *r).collect();
    for (rule, count) in &counts {
        if rule.contains("/taint-") && !expected_rules.contains(rule) {
            panic!(
                "{}: unexpected taint rule {} fired {} times (likely NEAR-MISS false positive). counts={:?}",
                file, rule, count, counts
            );
        }
    }
}

#[test]
fn realistic_flask_app() {
    assert_fixture(
        "flask_app.py",
        14,
        &[
            ("py/taint-pickle-deserialization", 1),
            ("py/taint-eval", 1),
            ("py/taint-command-injection", 2),
            ("py/taint-ssrf", 1),
            ("py/taint-yaml-load", 1),
            ("py/taint-sql-injection", 1),
        ],
    );
}

#[test]
fn realistic_django_views() {
    assert_fixture(
        "django_views.py",
        9,
        &[
            ("py/taint-command-injection", 2),
            ("py/taint-sql-injection", 1),
            ("py/taint-ssrf", 1),
            ("py/taint-pickle-deserialization", 1),
        ],
    );
}

#[test]
fn realistic_fastapi_app() {
    assert_fixture(
        "fastapi_app.py",
        8,
        &[
            ("py/taint-eval", 1),
            ("py/taint-pickle-deserialization", 1),
            ("py/taint-ssrf", 1),
        ],
    );
}

#[test]
fn realistic_cli_tool() {
    assert_fixture(
        "cli_tool.py",
        9,
        &[("py/taint-command-injection", 2), ("py/taint-eval", 2)],
    );
}

#[test]
fn realistic_express_app() {
    assert_fixture("express_app.js", 12, &[("js/taint-xss-innerhtml", 5)]);
}

#[test]
fn realistic_nextjs_handlers() {
    assert_fixture("nextjs_handlers.ts", 7, &[("js/taint-xss-innerhtml", 3)]);
}

#[test]
fn realistic_hono_app() {
    assert_fixture("hono_app.ts", 7, &[("js/taint-xss-innerhtml", 3)]);
}

#[test]
fn realistic_java_spring_controller() {
    assert_fixture(
        "java_spring_controller.java",
        4,
        &[
            ("java/taint-command-injection", 1),
            ("java/taint-sql-injection", 1),
            ("java/taint-ssrf", 1),
            ("java/taint-unsafe-deserialization", 1),
        ],
    );
}

/// Multi-file Django fixture (issue #48). Cross-file taint analysis
/// (issue #46) propagates taint from `views.py` into `queries.py`
/// helpers via function taint summaries. In-file flows fire as before,
/// plus two new cross-file flows:
///   - `py/taint-sql-injection`: request.GET["name"] → queries.run_query → cur.execute
///   - `py/taint-pickle-deserialization`: request.body → queries.load_blob → pickle.loads
#[test]
fn realistic_django_shop_multifile() {
    assert_fixture(
        "django_shop",
        8,
        &[
            ("py/taint-command-injection", 1),
            ("py/taint-ssrf", 1),
            ("py/taint-sql-injection", 1),
            ("py/taint-pickle-deserialization", 1),
        ],
    );
}

/// Multi-file Express fixture (issue #48). In-file SQL injection in
/// `routes.js::/user` fires under `js/taint-sql-injection`. Cross-file
/// flows via `services.runQuery` and `services.evalExpression` fire after
/// issue #46 (cross-file summaries).
#[test]
fn realistic_express_api_multifile() {
    assert_fixture(
        "express_api",
        10,
        &[
            ("js/taint-sql-injection", 2),
            ("js/taint-command-injection", 1),
            ("js/taint-eval", 2),
        ],
    );
}

/// Multi-file Next.js App Router fixture (issue #48). Same shape as
/// the Express fixture: in-file SQL injection via `request.nextUrl`
/// → `db.query` fires; cross-file flows into `actions.ts` do not
/// fire yet and will light up after issue #46.
#[test]
fn realistic_next_app_multifile() {
    assert_fixture("next_app", 4, &[("js/taint-sql-injection", 1)]);
}

/// Multi-file Gin fixture (issue #48). `handlers.go` holds request
/// sources, `store.go` holds a SQL execute helper tainted across the
/// file boundary. In-file taint flows fire (command injection in the
/// closure, SSRF in `proxyFetch`). Cross-file flow via
/// `runQuery(name)` in `handlers.go` → `db.Query` in `store.go`
/// fires as `go/taint-sql-injection` after issue #46.
#[test]
fn realistic_gin_service_multifile() {
    assert_fixture(
        "gin_service",
        6,
        &[
            ("go/taint-command-injection", 1),
            ("go/taint-sql-injection", 1),
            ("go/taint-ssrf", 1),
        ],
    );
}

/// Multi-hop chain fixture (issue #175). Three-file Python chain:
/// views.py (source) → middleware.py (passthrough) → queries.py (sink).
/// Return-taint propagation through middleware.transform() enables the
/// taint to flow from request.GET through the passthrough and into
/// queries.run_query's SQL sink.
#[test]
fn realistic_django_chain_multihop() {
    assert_fixture("django_chain", 2, &[("py/taint-sql-injection", 1)]);
}

/// Bounded multi-hop chain where the MIDDLE helper itself makes the
/// cross-file call. Three-file Python chain:
/// views.py (source) → service.handle() → db.run_query() (sink), where
/// `service.handle` forwards its argument to `db.run_query` in a THIRD file.
/// Unlike `django_chain` (caller orchestrates both hops), this chain is only
/// found once `service.handle`'s summary is composed one hop deeper against
/// `db.run_query`'s summary (the scanner's bounded multi-hop fixpoint).
#[test]
fn realistic_python_multihop_composed() {
    assert_fixture("python_multihop", 2, &[("py/taint-sql-injection", 1)]);
}

/// The chain above must only resolve on a full-directory scan: scanning any
/// single file in isolation finds no taint finding (the sink file still trips
/// the single-file regex heuristic `py/no-sql-injection`, but no `*/taint-*`
/// rule fires because no source is present in any single file).
#[test]
fn realistic_python_multihop_single_file_finds_no_taint() {
    assert_fixture("python_multihop/views.py", 0, &[]);
    assert_fixture("python_multihop/service.py", 0, &[]);
    assert_fixture("python_multihop/db.py", 1, &[]);
}

/// Negative multi-hop: identical shape to `python_multihop` but the middle
/// helper runs the value through `escape_string()` (a configured SQL
/// sanitizer) before forwarding it. The sanitizer collapses the value to
/// clean, so the composed summary records no sink flow and the chain BREAKS —
/// no taint finding on a directory scan (only the sink file's regex hit).
#[test]
fn realistic_python_multihop_sanitizer_breaks_chain() {
    assert_fixture("python_multihop_sanitized", 1, &[]);
}

/// Multi-hop chain fixture (issue #175). Three-file JS chain:
/// routes.js (source) → transform.js (passthrough) → services.js (sink).
#[test]
fn realistic_express_chain_multihop() {
    assert_fixture("express_chain", 2, &[("js/taint-sql-injection", 1)]);
}

/// Bounded multi-hop chain where the MIDDLE helper itself makes the
/// cross-file call. Three-file JS chain:
/// routes.js (source) → service.handle() → store.runQuery() (sink), where
/// `service.handle` forwards its argument to `store.runQuery` in a THIRD file.
/// Unlike `express_chain` (caller orchestrates both hops), this chain is only
/// found once `service.handle`'s summary is composed one hop deeper against
/// `store.runQuery`'s summary (the scanner's bounded multi-hop fixpoint).
#[test]
fn realistic_js_multihop_composed() {
    assert_fixture("js_multihop", 2, &[("js/taint-sql-injection", 1)]);
}

/// Parameterizing SQL template tags (Drizzle / postgres.js `sql`, Prisma
/// `$queryRaw`) bind `${}` as parameters, so they are not concatenation sinks
/// and must not be reported. The escape hatches and untagged forms in the same
/// fixture must still be: `sql.raw(...)`, a plain interpolated template, a
/// `"..." + userId` concatenation, and an unrecognised tag the rule cannot
/// vouch for.
#[test]
fn realistic_js_sql_tagged_templates_only_flag_real_sinks() {
    assert_fixture("js_sql_tagged_templates.js", 4, &[]);
}

/// The JS chain above must only resolve on a full-directory scan: scanning any
/// single file in isolation finds no taint finding (the sink file still trips
/// the single-file regex heuristic `js/no-sql-injection`, but no `*/taint-*`
/// rule fires because no source is present in any single file).
#[test]
fn realistic_js_multihop_single_file_finds_no_taint() {
    assert_fixture("js_multihop/routes.js", 0, &[]);
    assert_fixture("js_multihop/service.js", 0, &[]);
    assert_fixture("js_multihop/store.js", 1, &[]);
}

/// Negative multi-hop: identical shape to `js_multihop` but the middle helper
/// runs the value through `mysql.escape()` (a configured SQL sanitizer) before
/// forwarding it. The sanitizer collapses the value to clean, so the composed
/// summary records no sink flow and the chain BREAKS — no taint finding on a
/// directory scan (only the sink file's regex hit).
#[test]
fn realistic_js_multihop_sanitizer_breaks_chain() {
    assert_fixture("js_multihop_sanitized", 1, &[]);
}

/// Multi-hop chain fixture (issue #175). Three-file Go chain:
/// handlers.go (source) → transform.go (passthrough) → store.go (sink).
#[test]
fn realistic_gin_chain_multihop() {
    assert_fixture("gin_chain", 2, &[("go/taint-sql-injection", 1)]);
}

/// Bounded multi-hop chain where the MIDDLE helper itself makes the same-package
/// cross-file call. Three-file Go chain:
/// handlers.go (source) → loadFile() → readData() (os.ReadFile sink), where
/// `loadFile` forwards its argument to `readData` in a THIRD file of the same
/// package. Only found once `loadFile`'s summary is composed one hop deeper
/// against `readData`'s summary (the scanner's bounded multi-hop fixpoint). Uses
/// `go/taint-path-traversal` because that Go rule has a configured sanitizer
/// (`filepath.Clean`), which the negative variant below uses to break the chain
/// (`go/taint-sql-injection` has no sanitizer to test that path with).
#[test]
fn realistic_go_multihop_composed() {
    assert_fixture("go_multihop", 1, &[("go/taint-path-traversal", 1)]);
}

/// The Go chain above must only resolve on a full-directory scan: scanning any
/// single file in isolation finds no taint finding, since no source is present
/// in any single file and `name` is only ever a bare parameter.
#[test]
fn realistic_go_multihop_single_file_finds_no_taint() {
    assert_fixture("go_multihop/handlers.go", 0, &[]);
    assert_fixture("go_multihop/service.go", 0, &[]);
    assert_fixture("go_multihop/store.go", 0, &[]);
}

/// Negative multi-hop: identical shape to `go_multihop` but the middle helper
/// runs the value through `filepath.Clean()` (a configured path-traversal
/// sanitizer) before forwarding it. The sanitizer collapses the value to clean,
/// so the composed summary records no sink flow and the chain BREAKS — no
/// finding at all on a directory scan.
#[test]
fn realistic_go_multihop_sanitizer_breaks_chain() {
    assert_fixture("go_multihop_sanitized", 0, &[]);
}

/// Bounded multi-hop chain where the MIDDLE helper itself makes the
/// same-package (same-directory) cross-file call. Three-file Java chain:
/// SearchHandler.search() (source) → Service.process() → QueryHelper.runQuery()
/// (executeQuery sink), where `Service.process` forwards its argument to
/// `QueryHelper.runQuery` in a THIRD file of the same directory. Java uses its
/// OWN name-based, same-directory summary machinery (not the shared adapter),
/// but the scanner-side fixpoint is the same: the chain is only found once
/// `Service.process`'s summary is composed one hop deeper against
/// `QueryHelper.runQuery`'s summary. The concatenation in the sink file also
/// trips the conservative `java/no-sql-injection` regex.
#[test]
fn realistic_java_multihop_composed() {
    assert_fixture("java_multihop", 2, &[("java/taint-sql-injection", 1)]);
}

/// The Java chain above must only resolve on a full-directory scan: scanning
/// any single file in isolation finds no taint finding (the sink file still
/// trips the single-file regex heuristic `java/no-sql-injection`, but no
/// `*/taint-*` rule fires because no source is present in any single file).
#[test]
fn realistic_java_multihop_single_file_finds_no_taint() {
    assert_fixture("java_multihop/SearchHandler.java", 0, &[]);
    assert_fixture("java_multihop/Service.java", 0, &[]);
    assert_fixture("java_multihop/QueryHelper.java", 1, &[]);
}

/// Negative multi-hop: identical shape to `java_multihop` but the middle helper
/// breaks the chain. Java's built-in taint rules ship NO configured sanitizers
/// (every `TaintSpec` has `sanitizers: vec![]`), so — unlike the Python/JS/Go
/// negatives that route the value through a real sanitizer call — this fixture
/// breaks the chain by replacing the tainted parameter with a constant before
/// the cross-file call. The composition is taint-flow-sensitive, so the clean
/// argument records no sink flow and the chain BREAKS: no taint finding on a
/// directory scan (only the sink file's regex hit remains).
#[test]
fn realistic_java_multihop_break_breaks_chain() {
    assert_fixture("java_multihop_broken", 1, &[]);
}

/// Bounded multi-hop chain where the MIDDLE helper itself makes the
/// same-directory cross-file call. Three-file C# chain:
/// SearchHandler.Search() (source) → Service.Forward() → QueryHelper.RunQuery()
/// (SqlCommand sink), where `Service.Forward` forwards its argument to
/// `QueryHelper.RunQuery` in a THIRD file of the same directory. C# uses its OWN
/// name-based, same-directory summary machinery (not the shared adapter), but
/// the scanner-side fixpoint is the same: the chain is only found once
/// `Service.Forward`'s summary is composed one hop deeper against
/// `QueryHelper.RunQuery`'s summary.
#[test]
fn realistic_csharp_multihop_composed() {
    assert_fixture("csharp_multihop", 1, &[("csharp/taint-sql-injection", 1)]);
}

/// The C# chain above must only resolve on a full-directory scan: scanning any
/// single file in isolation finds no taint finding (no source is present in any
/// single file, and `term` is only ever a bare parameter).
#[test]
fn realistic_csharp_multihop_single_file_finds_no_taint() {
    assert_fixture("csharp_multihop/SearchHandler.cs", 0, &[]);
    assert_fixture("csharp_multihop/Service.cs", 0, &[]);
    assert_fixture("csharp_multihop/QueryHelper.cs", 0, &[]);
}

/// Negative multi-hop: identical shape to `csharp_multihop` but the middle
/// helper passes a clean constant to the sink helper instead of forwarding its
/// tainted parameter. The composition is taint-flow-sensitive, so the clean
/// argument records no sink flow and the chain BREAKS: no finding on a directory
/// scan. (C#'s rules ship sanitizers, so a sanitizer call would break it too.)
#[test]
fn realistic_csharp_multihop_break_breaks_chain() {
    assert_fixture("csharp_multihop_broken", 0, &[]);
}

/// Bounded multi-hop chain where the MIDDLE helper itself makes the
/// same-directory cross-file call. Three-file Ruby chain:
/// SearchController#search (params source) → Service#forward →
/// CommandHelper#run_cmd (system() sink), where `Service#forward` forwards its
/// argument to `CommandHelper#run_cmd` in a THIRD file of the same directory.
/// The chain is only found once `Service#forward`'s summary is composed one hop
/// deeper against `run_cmd`'s summary. The `system(arg)` call in the sink file
/// also trips the conservative `rb/no-command-injection` regex.
#[test]
fn realistic_ruby_multihop_composed() {
    assert_fixture("ruby_multihop", 2, &[("rb/taint-command-injection", 1)]);
}

/// The Ruby chain above must only resolve on a full-directory scan: scanning any
/// single file in isolation finds no taint finding (the sink file still trips
/// the single-file regex heuristic `rb/no-command-injection`, but no `*/taint-*`
/// rule fires because no source reaches a resolved sink in any single file).
#[test]
fn realistic_ruby_multihop_single_file_finds_no_taint() {
    assert_fixture("ruby_multihop/search_controller.rb", 0, &[]);
    assert_fixture("ruby_multihop/service.rb", 0, &[]);
    assert_fixture("ruby_multihop/command_helper.rb", 1, &[]);
}

/// Negative multi-hop: identical shape to `ruby_multihop` but the middle helper
/// passes a clean constant to the sink helper instead of forwarding its tainted
/// parameter. The composition is taint-flow-sensitive, so the chain BREAKS: no
/// taint finding on a directory scan (only the sink file's regex hit remains).
/// (Ruby's rules ship sanitizers, so a sanitizer call would break it too.)
#[test]
fn realistic_ruby_multihop_break_breaks_chain() {
    assert_fixture("ruby_multihop_broken", 1, &[]);
}

/// Bounded multi-hop chain where the MIDDLE helper itself makes the
/// same-directory cross-file call. Three-file PHP chain:
/// search() ($_GET source) → forward() → run_cmd() (system() sink), where
/// `forward` forwards its argument to `run_cmd` in a THIRD file of the same
/// directory. The chain is only found once `forward`'s summary is composed one
/// hop deeper against `run_cmd`'s summary. The `system($arg)` call in the sink
/// file also trips the conservative `php/no-command-injection` regex.
#[test]
fn realistic_php_multihop_composed() {
    assert_fixture("php_multihop", 2, &[("php/taint-command-injection", 1)]);
}

/// The PHP chain above must only resolve on a full-directory scan: scanning any
/// single file in isolation finds no taint finding (the sink file still trips
/// the single-file regex heuristic `php/no-command-injection`, but no `*/taint-*`
/// rule fires because no source reaches a resolved sink in any single file).
#[test]
fn realistic_php_multihop_single_file_finds_no_taint() {
    assert_fixture("php_multihop/search_handler.php", 0, &[]);
    assert_fixture("php_multihop/service.php", 0, &[]);
    assert_fixture("php_multihop/command_helper.php", 1, &[]);
}

/// Negative multi-hop: identical shape to `php_multihop` but the middle helper
/// passes a clean constant to the sink helper instead of forwarding its tainted
/// parameter. The composition is taint-flow-sensitive, so the chain BREAKS: no
/// taint finding on a directory scan (only the sink file's regex hit remains).
/// (PHP's rules ship sanitizers, so a sanitizer call would break it too.)
#[test]
fn realistic_php_multihop_break_breaks_chain() {
    assert_fixture("php_multihop_broken", 1, &[]);
}

/// Bounded multi-hop chain where the MIDDLE helper itself makes the
/// same-directory cross-file call. Three-file Kotlin chain:
/// handle() (call.receiveText source) → forward() → runQuery() (executeQuery
/// sink), where `forward` forwards its argument to `runQuery` in a THIRD file of
/// the same directory. The chain is only found once `forward`'s summary is
/// composed one hop deeper against `runQuery`'s summary. The concatenation in
/// the sink file also trips the conservative `kt/no-sql-injection` regex.
#[test]
fn realistic_kotlin_multihop_composed() {
    assert_fixture("kotlin_multihop", 2, &[("kt/taint-sql-injection", 1)]);
}

/// The Kotlin chain above must only resolve on a full-directory scan: scanning
/// any single file in isolation finds no taint finding (the sink file still
/// trips the single-file regex heuristic `kt/no-sql-injection`, but no
/// `*/taint-*` rule fires because no source reaches a resolved sink in any
/// single file).
#[test]
fn realistic_kotlin_multihop_single_file_finds_no_taint() {
    assert_fixture("kotlin_multihop/SearchHandler.kt", 0, &[]);
    assert_fixture("kotlin_multihop/Service.kt", 0, &[]);
    assert_fixture("kotlin_multihop/QueryHelper.kt", 1, &[]);
}

/// Negative multi-hop: identical shape to `kotlin_multihop` but the middle
/// helper passes a clean constant to the sink helper instead of forwarding its
/// tainted parameter. The built-in Kotlin rules ship NO configured sanitizers
/// and the engine's tainted-name set is add-only (Kotlin params are `val`), so a
/// fresh clean local passed to the helper is the break mechanism. The
/// composition is taint-flow-sensitive, so the chain BREAKS: no taint finding on
/// a directory scan (only the sink file's regex hit remains).
#[test]
fn realistic_kotlin_multihop_break_breaks_chain() {
    assert_fixture("kotlin_multihop_broken", 1, &[]);
}

#[test]
fn realistic_gin_app() {
    // Three planted vulnerabilities (command injection, SQL
    // injection, SSRF) — one per go/taint-* rule. The conservative
    // go/no-* counterparts coexist on the same lines, plus the
    // go/gin-no-trusted-proxies rule fires on gin.Default() in
    // main(). Total = 3 taint + 3 conservative injection + 1
    // gin-no-trusted-proxies = 7.
    assert_fixture(
        "gin_app.go",
        7,
        &[
            ("go/taint-command-injection", 1),
            ("go/taint-sql-injection", 1),
            ("go/taint-ssrf", 1),
        ],
    );
}
