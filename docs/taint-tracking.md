# Taint tracking in foxguard

This document describes foxguard's taint engine. It is intended for rule authors and contributors, not end users.

## Why taint at all

Pure AST pattern matching can answer "is this dangerous sink used anywhere?" It cannot answer "is untrusted data reaching this sink?" Those are different questions. The conservative rules (`py/no-pickle`, `py/no-command-injection`, etc.) answer the first and are the right default for a local-first scanner: fast, zero false negatives on the sink itself, high recall at the cost of precision.

The taint engine answers the second, on a narrower footprint. It lets us ship rules that fire only when there is a provable flow from a known source into a known sink within a single function. Higher precision, lower recall. The two rule classes coexist.

## Scope

The taint engine supports:

- **Built-in taint rules for 14 languages**: Python, JavaScript/TypeScript, Go, Java, C, Kotlin, C#, Ruby, PHP, Swift, Bash, Solidity, Scala, and Apex. Each has source/sink specs wired into the scanner (`builtin_taint_specs_for_language`) and a grammar-aware engine (`src/rules/*_taint.rs`) sharing the same user-facing trace surface (`TaintSpec`, `NodeMatcher`, `TaintFinding`, `analyze_tree`). `.ts` and `.tsx` files use dedicated tree-sitter TypeScript/TSX grammars, then run through the JavaScript-compatible rule and taint surface where semantics align.
- **Intraprocedural**: each function body is analyzed independently.
- **Flow-insensitive**: statements are processed in source order. Reassigning a tainted variable to a clean value drops the taint. Branches are not modeled — taint observed in one branch of an `if` persists through the fall-through.
- **One level of attribute propagation**: `x.y` is tainted when `x` is tainted.
- **Nested subscript chains**: `x[k1][k2]...[kn]` is tainted whenever any link in the chain (or its root) is tainted. Keys are not distinguished — taint is propagated regardless of which key is read.
- **One level of wrapping-call propagation**: `bytes(x)` is tainted when `x` is tainted. This covers the common "sanitize by retype" anti-pattern.
- **Method-call propagation on tainted roots**: `x.foo(...)` is tainted whenever the receiver `x` (or any attribute/subscript chain rooted at a tainted value) is tainted. Conservative tainted-in → tainted-out — method calls on literal receivers like `"foo".upper()` stay clean. Mirrors the wrapping-call rule and lets common shapes such as `request.args.get("cmd")` and `req.body.toString()` flow into downstream sinks. Sanitizers still short-circuit this rule.
- **F-string / template-literal interpolation propagation**: a Python f-string `f"... {expr} ..."` (or a JavaScript template literal `` `... ${expr} ...` ``) is tainted when any interpolated inner expression is tainted. Plain strings with no interpolation remain clean. Conservative tainted-in → tainted-out.
- **Tuple/list destructuring with flow-insensitive conservative semantics**: `a, b = expr1, expr2` and `[a, b] = [expr1, expr2]` pair targets with RHS elements when the arities match, so only the matching slot carries taint. When the RHS is a single opaque expression (e.g. `a, b = helper()`), the engine conservatively taints *every* LHS target — we lack the type info to pick the right slot.
- **Alias-aware sinks and sources**: the engine resolves callees and source roots through the per-file import alias table already introduced for issue #7.
- **Sanitizer support (collapsed to "clean")**: calls whose callee matches a `TaintSpec.sanitizers` entry produce a clean value even when their arguments were tainted. See the section below for the exact semantics.
- **Same-file interprocedural return propagation (v1)**: a helper whose body returns a tainted expression marks its return as tainted, and bare calls to that helper elsewhere in the same file propagate the taint into the caller. See the dedicated section below for the exact scope.
- **Supported Python source frameworks**: Flask (`request.data|form|args|values|json|files|cookies`, `request.get_data|get_json`), Django (`request.POST|GET|COOKIES|FILES|META|headers|body`), FastAPI/Starlette (`request.query_params|path_params|headers|cookies`, `await request.body|json|form|stream`), plus CLI-tool sources (`sys.argv`, `sys.stdin.read|readline`, `input()`, `os.environ`, `os.getenv`). Handler parameters named `request` or `req` are treated as implicit sources. Method calls on tainted receivers (e.g. `request.GET.get("x")`, `os.environ.get("X")`) are tracked via subscript access today; the method-call path is handled once issue #27 lands.

Known limitations:

- **Multi-hop interprocedural chains**: only one level of helper-call propagation is supported. A helper that itself calls another helper is not tracked through the deeper hop.
- **Cross-file**: Cross-file taint is supported for 8 languages via two-pass function summary analysis — Python (import resolution), JavaScript (require/import/export default), Go (same-package), Java, C#, Ruby, PHP, and Kotlin (the latter five resolve helper calls by name within the same directory, a same-package/same-namespace proxy). C and the remaining first-party taint languages are intra-file today. all eight additionally compose **bounded multi-hop** chains where a cross-file helper itself calls another cross-file helper (`A → f → g → sink`); see "Bounded multi-hop cross-file taint" below. Python/JS/Go/PHP share the engine-agnostic composition driver; Java, C#, Ruby, and Kotlin run their own name-based composition over the same scanner-side fixpoint. The name-based cross-file passes (Java/C#/Ruby/PHP/Kotlin) resolve a helper-method call to a summarized method *by method name* within the same directory; they do not model type-based instance dispatch, interface/subclass dispatch, overload selection by parameter type, cross-package/namespace (`import`/`using`) resolution, or partial classes. See "Supported Java frameworks" below.
- **Instance and class methods in interprocedural summaries**: only top-level `function_declaration`s and `const/let/var foo = ...` arrow/function-expression helpers are summarized. `obj.method()` and `self.helper()` calls are not looked up in the summary map.
- **Argument taint propagation**: helper summaries are computed with only their parameters' taint sources seeded (via `ParamName`). Passing an already-tainted local into a helper does not influence the helper's return summary — pass 1 analyzes helpers with a conservative view of their parameters.
- **Per-finding sanitization**: Semgrep's `mode: taint` distinguishes "this specific flow was sanitized" from "the value is now clean"; it can still fire on secondary flows that bypassed the sanitizer along a different path. foxguard's v1 collapses both cases into "clean" and does not track per-finding sanitization state.
- **Field sensitivity**: `d["key"]` is tainted because `d` is. Different keys are not distinguished.
- **Object attribute propagation beyond one level**: `x.y.z` is tainted when `x` is tainted, but the engine does not persist taint on `x.y` as a distinct name.
- **Dynamic import forms**: `importlib.import_module(...)` does not interact with the alias table, so sinks reached through it are not recognized.
- **First-party taint languages (14)**: Python, JavaScript/TypeScript, Go, Java, C, Kotlin, C#, Ruby, PHP, Swift, Bash, Solidity, Scala, and Apex all have built-in first-party taint rules wired into the default scanner registry (no `--rules` needed). Rust, Haskell, and the remaining source languages have no taint engine today. JavaScript/TypeScript uses the same scope as Python (intraprocedural, flow-insensitive, one-level subscript propagation, template-literal and wrapping-call propagation, collapse-to-clean sanitizers) with a `JsImportAliases` table for `import`/`require` forms. Go (see "Supported Go frameworks" below) uses `GoImportAliases` for grouped / aliased import specs and the same flow-insensitive, one-level propagation semantics, plus native multi-return destructuring and binary `+` string-concatenation propagation.

## API

Each language engine lives under `src/rules/*_taint.rs`. The public surface is four items:

```rust
pub enum NodeMatcher {
    Attribute { root: String, field: String, description: String },
    Call      { canonical: String,           description: String },
    ParamName { names: Vec<String>,          description: String },
}

pub struct TaintSpec {
    pub sources: Vec<NodeMatcher>,
    pub sinks: Vec<NodeMatcher>,
    pub sanitizers: Vec<NodeMatcher>, // see "Sanitizers" below
}

pub struct TaintFinding { /* sink location + source/sink descriptions */ }

pub fn analyze_tree(
    root: Node<'_>,
    source: &str,
    spec: &TaintSpec,
    aliases: Option<&ImportAliases>,
) -> Vec<TaintFinding>;
```

Nothing about Flask, pickle, or any other library is baked into the engine. A rule that wants to use taint tracking builds its own `TaintSpec`, hands it to `analyze_tree`, and maps the returned `TaintFinding`s to `Finding`s. The first consumer is `py/taint-pickle-deserialization` in `src/rules/python.rs` and is a good worked example.

### `NodeMatcher` kinds

- **`Attribute { root, field, description }`** — matches `root.field` and `root.intermediate.field` chains where the leftmost identifier equals `root`. The engine also tries the alias-resolved form of the leftmost, so one spec entry with `root: "request"` covers both `from flask import request` and `def handler(request)`.
- **`Call { canonical, description }`** — matches a call whose callee resolves (raw *or* alias-resolved) to `canonical`. Use for method-call sources like `request.get_json()` and for sinks like `pickle.loads`.
- **`ParamName { names, description }`** — matches function parameters whose name is in `names`. Used to mark implicit sources (e.g. a Flask handler signature `def handler(request):` should treat `request` as untrusted without any assignment).

## Interprocedural (v1)

Issue #19 extends the engine with one level of same-file interprocedural return propagation. The implementation runs two passes over each file:

1. **Pass 1 — return summaries.** Every eligible function in the file is walked with the same expression-taint machinery used in pass 2, but with an empty summary map. For each function, the first tainted `return` expression discovered becomes the function's summary value (`Some(description)`); otherwise the summary is `None`.

2. **Pass 2 — analysis with summaries.** The usual per-function walk runs again, but now `expression_taint` resolves a bare-identifier call whose name is in the summary map by returning the summarized description, decorated with ` (via <callee>)` so findings show the helper chain.

The worked example:

```python
def get_user_input():
    return request.data          # summary: Some("flask.request.data")

def handler():
    data = get_user_input()      # pass 2: data ← "flask.request.data (via get_user_input)"
    return pickle.loads(data)    # fires with that description
```

produces a finding whose message reads `flask.request.data (via get_user_input) reaches pickle.loads`.

Scope and limitations:

- **Eligible helpers.** Python: all `function_definition`s are summarized by their simple name. JavaScript/TypeScript: top-level `function_declaration`s and `const/let/var name = arrow_function | function_expression` declarators. Methods on classes/objects (`class Foo { bar() {} }`, `{ helper: function() {} }`) are not summarized.
- **Single hop only.** Pass 1 runs each helper with an empty summary map, so a helper that itself calls another helper sees the inner call as untyped and cannot recognize its return. A two-hop chain like `handler → middle → source` is *not* caught. This limitation is pinned by a `multi_hop_chain_is_out_of_scope_v1` unit test in each engine.
- **Bare identifier callees.** `handler()` looks up `handler` in the summary map. `obj.handler()`, `self.helper()`, and aliased forms of method calls do not. Rationale: method calls need receiver/type information the engine does not model.
- **Name collisions are last-write-wins.** If two functions in the same file share a simple name (e.g. an outer `def helper` and a nested `def helper` inside another function), one summary will overwrite the other during pass 1. This is a known v1 limitation — fix by making summaries scope-aware when it stops being hypothetical.
- **Argument-based taint is not threaded through helpers.** A helper's summary is computed using only its own parameter sources (`ParamName` matchers); passing an already-tainted local in as an argument does not retroactively taint the helper's return.

## Bounded multi-hop cross-file taint (Python, JavaScript, Go, Java, C#, Ruby, PHP, Kotlin)

The base cross-file pass ([`FunctionTaintSummary`], `params_to_sink` +
`params_to_return`) resolves a **single** cross-file hop: a source in file A
flowing through an imported helper `f()` in file B and into a sink is found.
Two chained shapes exist:

- **Orchestrator (already handled by the base pass).** File A itself makes both
  calls: `y = f(x); g(y)` where `f` (file B) is a passthrough
  (`params_to_return`) and `g` (file C) sinks its argument. `expression_taint`
  taints `y` from `f`'s return, then `g(y)` fires. This is really two
  independent single hops glued by a local in A (see the `django_chain`
  fixture).

- **Nested helper (the genuine multi-hop, added here).** File A calls `f()`
  (file B), and `f`'s *own body* calls `g()` (file C) which sinks the value:
  `A → f → g → sink`, where `f` never contains a sink itself. This was missed,
  because pass-1 summary extraction ran with cross-file resolution *disabled*,
  so `f`'s summary recorded nothing and A saw an empty summary for `f`.

### How the nested case is composed

After the per-file base summaries are built, the scanner runs a **bounded
fix-point** that composes them one hop deeper
([`compose_cross_file_summaries`], driving
`extract_cross_file_summary_for_function_cf` with cross-file resolution
*enabled* against the current summary snapshot). The identical driver runs for
**Python**, **JavaScript**, and **Go** — each per-language
`compose_cross_file_summaries` supplies only the language, its rule specs, and
the same cross-file resolution context its single-hop pass uses (Python and JS
resolve callees via the file's **import map**; Go resolves them **same-package**
across sibling `.go` files in the directory). The composition machinery
(`extract_cross_file_summary_for_function_cf`, `merge_from`) is engine-agnostic
and shared verbatim.

**Java, C#, Ruby, and Kotlin** reach the same result through their OWN
machinery. These engines do not route cross-file resolution through the shared
`extract_cross_file_summary_for_function_cf` path; each has a bespoke name-based,
**same-directory** summary extractor and its own
`compose_cross_file_summaries` that re-implements the per-file step directly:
for each function it seeds one parameter at a time as a synthetic source,
propagates intra-file taint, and — for every helper call that resolves to a
same-directory sibling summary — records a `params_to_sink` entry when a tainted
argument lands on a param the sibling already sinks. **PHP** is adapter-based and
already routes cross-file calls through its adapter, so its
`compose_cross_file_summaries` reuses the shared
`extract_cross_file_summary_for_function_cf` driver (like Python/JS/Go) with the
same-directory `CrossFileInfo` supplied. In every case the scanner-side fixpoint
(the round loop, snapshot, `merge_from` union, and `MAX_MULTIHOP_ROUNDS` cap) is
identical across all eight languages. One deliberate
simplification: Java's base summary already over-approximates
`params_to_return` (any call carrying a tainted argument is treated as
returning taint), so composition only needs to add the cross-file
`params_to_sink` fact — the genuinely missing single-extra-hop
(`A → f → g → sink`, `f` forwarding its param to `g`). The shared merge
machinery (`merge_from`) is reused:

- Each round re-analyzes every function against an immutable snapshot of the
  previous round's summaries. If `f`'s body calls `g()` cross-file and `g`
  sinks its argument, `f`'s summary gains that `params_to_sink` entry (and
  likewise `params_to_return` for passthrough-through-a-helper). New flows are
  merged in by **union** ([`FunctionTaintSummary::merge_from`]); base flows are
  never removed.
- Pass 2 then consumes the composed summaries unchanged, so the caller in file
  A fires on `f(tainted)`.

### The bound and the cycle guard

- **Hop bound.** Each fix-point round advances the frontier by exactly one hop,
  so the number of rounds *is* the extra-hop depth. The scanner caps this at
  `MAX_MULTIHOP_ROUNDS = 5` (in `src/engine/scanner.rs`). A chain deeper than
  ~5 cross-file hops is not fully composed — a deliberate, documented cap, not
  an unbounded interprocedural fix-point.
- **Termination / cycle guard.** Summaries grow monotonically over a finite
  lattice (`#params × #rules`), and the loop stops early the first round that
  adds nothing (`changed == false`). Composition only *reads* precomputed
  summaries — it never recurses into a callee's body across files — so a cyclic
  or mutually-recursive helper graph (`f → g → f`) cannot loop forever within a
  round, and the round cap is a hard backstop across rounds.
- **Sanitizers still break the chain.** During composition a cross-file finding
  for any rule can surface in any analysis pass, so every pass carries the
  **union** of all rules' sanitizers (over-approximating sanitization — a
  false-negative-only direction that never loses a base flow, since those are
  merged in). A value run through a sanitizer in the middle helper therefore
  yields no composed sink flow and the chain breaks. Covered per language by the
  positive/negative fixture pairs: `python_multihop` /
  `python_multihop_sanitized` (SQL, `escape_string`), `js_multihop` /
  `js_multihop_sanitized` (SQL, `mysql.escape()`), and `go_multihop` /
  `go_multihop_sanitized`. The Go pair uses `go/taint-path-traversal` (sanitized
  with `filepath.Clean`) rather than SQL because `go/taint-sql-injection` ships
  no configured sanitizer — so path-traversal is the Go rule that exercises the
  sanitizer-breaks-chain guarantee cleanly.
- **Java has no configured sanitizer to break the chain with.** Every built-in
  Java `TaintSpec` declares `sanitizers: vec![]` (see "Java-specific engine
  notes" below — the Java rules deliberately ship no sanitizers), so there is no
  sanitizer call the Java negative fixture can route a value through. The Java
  composition is still taint-flow-sensitive, so its negative pair
  (`java_multihop` / `java_multihop_broken`) breaks the chain the only way
  available without a custom rule: the middle helper replaces its tainted
  parameter with a constant before the cross-file call. A clean argument records
  no composed `params_to_sink` and the chain does not resolve — the same
  observable guarantee, exercised without a sanitizer call. (The composition
  still unions all rules' sanitizers into every pass, so a custom Java rule that
  *does* declare a sanitizer would break the chain the usual way.)
- **C#, Ruby, PHP, and Kotlin** are covered by their own positive/negative
  fixture pairs: `csharp_multihop` / `csharp_multihop_broken` (SQL),
  `ruby_multihop` / `ruby_multihop_broken` (command injection), `php_multihop` /
  `php_multihop_broken` (command injection), and `kotlin_multihop` /
  `kotlin_multihop_broken` (SQL). C#, Ruby, and PHP ship configured sanitizers
  (so a sanitizer call would break the chain the usual way), but for symmetry
  their negatives break the chain the same taint-flow-sensitive way Java's does —
  the middle helper passes a clean constant to the sink helper instead of
  forwarding its parameter. Kotlin ships **no** configured sanitizers and its
  tainted-name set is add-only (Kotlin parameters are `val`, never cleared), so
  the clean-constant break is the *only* mechanism available for Kotlin.

### Still not modeled

- **All eight cross-file engines compose multi-hop.** The composition fix-point
  is wired for Python, JavaScript, Go, Java, C#, Ruby, PHP, and Kotlin (each
  gated the same way its single-hop cross-file pass is: Python and JS on import
  resolution, Go/Java/C#/Ruby/PHP/Kotlin on same-package/same-directory, all
  requiring >1 file of that language). Python/JS/Go/PHP share the engine-agnostic
  `extract_cross_file_summary_for_function_cf` driver; **Java, C#, Ruby, and
  Kotlin** each run their own name-based `compose_cross_file_summaries` over the
  identical scanner-side fixpoint. C is intra-file only and has no cross-file or
  multi-hop pass.
- **Chains deeper than the hop cap** (`> MAX_MULTIHOP_ROUNDS` extra hops).
- **Taint through mutable state** — e.g. a value stored into a field/module
  global in one file and read back in another — is not tracked; only
  parameter→sink and parameter→return dataflow is summarized.
- **Method/receiver dispatch across files** (`obj.method()`, instance/interface
  dispatch) — resolution is still import-name / same-package based, as in the
  base pass.

## Sanitizers

A sanitizer is a call that turns a tainted value into a clean one. Populate `TaintSpec.sanitizers` with `NodeMatcher::Call` entries whose `canonical` is the dotted callee path you want the engine to recognize:

```rust
TaintSpec {
    sources: vec![/* ... */],
    sinks:   vec![/* ... */],
    sanitizers: vec![NodeMatcher::Call {
        canonical: "html.escape".into(),
        description: "html.escape".into(),
    }],
}
```

With that spec:

```python
raw = request.data            # tainted
clean = html.escape(raw)      # sanitized → clean
document.write(clean)         # NOT reported
document.write(raw)           # still reported — `raw` was never rewritten
```

Semantics:

- **Collapse to clean.** When a call's callee resolves (raw *or* alias-resolved) to a sanitizer's `canonical`, the engine treats the whole call expression as producing a clean value, regardless of whether any argument was tainted.
- **The input variable is unaffected.** `clean = sanitize(raw)` does not clear `raw`; only the RHS expression is "clean", so subsequent uses of `raw` still flow.
- **Only `NodeMatcher::Call` is meaningful as a sanitizer.** `Attribute` and `ParamName` matchers in the `sanitizers` list are ignored — sanitizers are always calls.
- **Wrapping-call propagation is bypassed for sanitizers.** `bytes(tainted)` preserves taint (by the wrapping-call rule) *unless* `bytes` is in the sanitizer list, in which case it is treated as clean.

Per-finding sanitization (Semgrep's `mode: taint` style, where a sanitizer cleans one flow but secondary flows bypassing it still fire) is still out of scope. If that matters for a rule, open an issue describing the concrete case.

## Adding a new taint rule

1. Define a struct in the appropriate rules module (e.g. `python.rs`).
2. Build a `TaintSpec` with your sources, sinks, and (once supported) sanitizers.
3. Implement `Rule::check_with_context` to call `python_taint::analyze_tree` with the spec and the context's alias table.
4. Map each `TaintFinding` to a `Finding` with a description that mentions both the source and the sink — users want to know *why* a flow was flagged.
5. Register the rule in `src/rules/mod.rs`.
6. Add positive + negative fixtures in `tests/fixtures/` and an integration test asserting exact finding counts.

The `py/taint-pickle-deserialization` rule is ~120 lines and is the canonical example.

## What real-world usage looks like

For a hand-crafted but more realistic picture of what the engine fires on,
see the fixtures under `tests/fixtures/realistic/`. Each file there is a
small-but-complete vulnerable application for one supported framework —
`flask_app.py`, `django_views.py`, `fastapi_app.py`, `cli_tool.py`,
`express_app.js`, `nextjs_handlers.ts`, `hono_app.ts` — with idiomatic
routing, helper functions that exercise interprocedural return
propagation, and 2–3 `NEAR MISS` functions per file whose patterns the
engine must not flag (literal arguments, reassignment to literals,
tainted values that never reach a sink). The integration test
`tests/realistic_fixtures.rs` pins the exact total finding count and the
exact count per taint rule for every file, which is the bar we hold the
engine to when adding new sources or sinks.

## Coexistence with conservative rules

Taint rules do not replace direct-sink rules. For example, `py/no-pickle` fires on every `pickle.loads` call; `py/taint-pickle-deserialization` fires only on the subset where a flow is provable. A user may see both findings on the same line, with different messages. That is intended — the two rules encode different questions and should be silenced independently if the user wants to suppress one but not the other.

## Performance

The taint engines run only for languages with enabled taint-backed rules. Each walk is over the already-parsed AST with small in-memory state. No additional parsing, no network, no disk. Go, Python, and JavaScript batch compatible taint rules to avoid repeated summary walks; Kotlin, C, Ruby, and PHP use lightweight intrafile dispatchers. Java and C# use an intrafile dispatcher plus an optional cross-file pass that only runs when more than one file of that language is scanned.

## Semgrep-compatible YAML bridge

Issue #17 added a narrow YAML bridge so existing Semgrep `mode: taint` rules can be loaded with `--rules` and compiled into the same `TaintSpec` that native rules build by hand. The bridge lives in [`src/rules/semgrep_taint.rs`](../src/rules/semgrep_taint.rs); see the [compatibility reference](./compatibility.md) for the exact subset of Semgrep's taint schema that is supported and what falls back to "skip with warning".

A minimum working YAML rule looks like this:

```yaml
rules:
  - id: semgrep-pickle-taint
    mode: taint
    languages: [python]
    severity: ERROR
    message: "Untrusted Flask input reaches pickle.loads"
    metadata:
      cwe: "CWE-502"
    pattern-sources:
      - pattern: request.data
      - pattern: request.form
      - pattern: request.get_json($X)
      - pattern: request
    pattern-sinks:
      - pattern: pickle.loads($X)
      - pattern: pickle.load($X)
```

Load it with `foxguard --no-builtins --rules path/to/rule.yml target/` and each compiled rule becomes a regular foxguard `Rule` backed by the same intraprocedural engine described above.

## Supported JavaScript / TypeScript frameworks

Issue #32 extended `javascript_taint_sources()` with framework-specific
sources beyond the original Express surface. The helper is organized
top-to-bottom by framework; add new entries to the matching section.

| Framework    | Sources that work today                                                                 | Requires #27 (method-call receiver propagation)                                                          |
| ------------ | --------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------- |
| Express      | `req.body`, `req.query`, `req.params`, `req.headers`, `req.cookies` (same for `request`), `ParamName: req`/`request` | —                                                                                                        |
| Next.js      | `request.nextUrl.*` (via `Attribute` + `ParamName: request`)                            | `request.headers.get(...)`, `request.cookies.get(...)`, `request.json()`, `request.formData()`          |
| Hono         | `c.req.query()`, `c.req.param()`, `c.req.header()`, `c.req.json()`, `c.req.formData()`, `c.req.parseBody()`, `c.req` attribute access | —                                                                                                        |
| Fastify      | Shares the Express attribute surface (`request.body` / `.query` / `.params` / `.headers` / `.cookies`) | Method-based Fastify helpers (none commonly used) would need #27                                         |
| SvelteKit    | `event.request`, `event.params`, `event.url` attribute chains                            | `event.request.json()`, `event.request.formData()`                                                      |
| Deno         | `Deno.args[...]`, `Deno.env.get(...)`                                                   | —                                                                                                        |

Two deliberate non-additions:

- **Hono's `c`** is not a `ParamName` source. `c` is too common a local
  identifier in generic JS to be treated as an untrusted receiver
  without type information.
- **SvelteKit's `event`** is not a `ParamName` source either. DOM event
  handlers (`onClick(event)`, `addEventListener("click", (event) => ...)`)
  use the same name and would flood false positives.

Because the engine only walks function bodies, Deno top-level scripts
that want taint coverage should wrap their logic in a named function.

## Supported Go frameworks

Issue #31 added a third engine (`src/rules/go_taint.rs`) and three
first-consumer rules: `go/taint-command-injection` (CWE-78),
`go/taint-sql-injection` (CWE-89), and `go/taint-ssrf` (CWE-918). The
sources are shared across every rule via `go_taint_sources()`.

| Framework    | Sources that work today                                                                                      |
| ------------ | ------------------------------------------------------------------------------------------------------------ |
| net/http     | `ParamName: r`/`req`/`request`; attribute access on `r.URL`, `r.Header`, `r.Body`, `r.Form`; method calls `r.FormValue`, `r.PostFormValue`, `r.URL.Query` |
| Gin          | `c.Query`, `c.PostForm`, `c.Param`, `c.GetHeader`, `c.GetQuery`, `c.GetString`, `c.FormValue`, `c.Request` attribute chain |
| Echo         | `c.QueryParam`, `c.Param`, `c.FormValue` (Param/FormValue shared with Gin)                                    |
| Fiber        | `c.Params`, `c.Query`, `c.FormValue` (Query/FormValue shared with Gin)                                        |
| Generic      | `os.Getenv`, `os.Args`                                                                                        |

Gin / Echo / Fiber handlers all bind the context to `c`. `c` is
intentionally **not** seeded as a `ParamName` source because
single-letter locals named `c` are extremely common in generic Go.
We rely on the explicit method-call matchers above instead. The
`r`/`req`/`request` pattern in net/http handlers IS seeded via
`ParamName` because those names are idiomatic for the
`*http.Request` parameter.

### Go-specific engine notes

- **Interprocedural summary keying.** Pass 1 records a summary keyed
  by each function / method's simple name. Method declarations use
  the bare method name, so a file that defines both `func foo()` and
  `func (s *S) foo()` will last-write-wins. A call site finds a
  matching entry for either a bare `foo()` identifier call or a
  selector-expression call whose trailing field is `foo`
  (`anything.foo(...)`). This intentionally over-approximates
  method-call propagation for v1.
- **Multi-return destructuring.** Go's native `a, b := f()` shape is
  handled in `short_var_declaration`, `var_spec`, and
  `assignment_statement` uniformly. If the RHS expression list and
  LHS identifier list have matching arity, taint is paired
  element-wise; otherwise (the typical `a, b := f()` case where the
  RHS is a single multi-return call) the policy is conservative: if
  the single RHS expression is tainted at all, every LHS name is
  tainted.
- **String concatenation.** Go uses `+` for string concatenation just
  like JavaScript, so `binary_expression` propagates taint from
  either operand. `fmt.Sprintf("prefix %s", tainted)` is handled by
  the generic wrapping-call rule — any tainted argument taints the
  result unless the callee matches a declared sanitizer.

### Go-specific out-of-scope

- **Dot imports** (`import . "fmt"`): names become unqualified and
  the alias table would need full unqualified-name rewriting.
  Documented out of scope for v1.
- **Side-effect imports** (`import _ "foo"`): introduce no names, so
  the alias table records nothing.
- **Interface dispatch**: a call through an interface type
  (`handler.ServeHTTP(w, r)`) is resolved as a method-name lookup
  only. Concrete implementers of the interface are not considered.
- **Closure bodies**: `func_literal` closures (anonymous functions)
  are now analyzed alongside top-level `function_declaration` and
  `method_declaration` nodes (issue #55). Each closure gets its own
  independent taint state seeded from its parameter list.
- **Cross-package imports**: alias resolution only covers the
  file-local `import` statement; calls to functions in imported
  packages are matched by canonical dotted path, not by tracing into
  their source.

## Supported Java frameworks

Issue #449 added `src/rules/java_taint.rs` and four first-consumer
rules:

| Rule | CWE | Sink families |
| ---- | --- | ------------- |
| `java/taint-command-injection` | CWE-78 | `Runtime.exec(...)`, `new ProcessBuilder(...)` |
| `java/taint-sql-injection` | CWE-89 | `executeQuery`, `execute`, `prepareStatement`, JPA `createQuery` / `createNativeQuery` |
| `java/taint-ssrf` | CWE-918 | `new URL(...)`, `new URI(...)`, Spring `RestTemplate` request methods |
| `java/taint-unsafe-deserialization` | CWE-502 | `new ObjectInputStream(...)`, `new XMLDecoder(...)`, `Yaml.load(...)` |

Sources currently covered:

| Framework / surface | Sources |
| ------------------- | ------- |
| Servlet APIs | `request` / `req` calls to `getParameter`, `getParameterMap`, `getParameterValues`, `getHeader`, `getHeaders`, `getQueryString`, `getInputStream`, `getReader`, `getCookies` |
| Spring MVC | Parameters annotated with `@RequestParam`, `@RequestBody`, `@PathVariable`, `@RequestHeader`, `@CookieValue`, `@ModelAttribute` |
| Generic service inputs | `System.getenv(...)` |

### Java-specific engine notes

- **Why Java first, not C#**: Java already had broad AST rules, Semgrep
  parity coverage, and Java fixtures in this repo, so #449 chose Java as
  the lower-risk next taint engine.
- **Scope**: method, constructor, and lambda bodies are analyzed
  independently.
- **Cross-file (name-based, same-package proxy)**: when more than one Java
  file is scanned, pass 1 builds a [`FunctionTaintSummary`] for every method
  declaration (keyed by the bare method name, last-write-wins on collisions),
  recording which parameters reach a sink (`params_to_sink`) and which flow to
  a return value (`params_to_return`). Pass 2 resolves a `method_invocation`
  to a summary whenever the invoked method name matches a summarized method in
  a *sibling file of the same directory* (used as a same-package proxy, the
  way the Go engine treats same-directory `.go` files). A tainted argument
  landing on a parameter with a recorded sink flow produces a cross-file
  finding in the caller file, labelled `... (via cross-file call to <name>)`.
  This is deliberately the **tractable subset**: resolution is by method name
  and argument arity only.
  - **Bounded multi-hop (composed).** A middle helper that itself forwards its
    parameter into another same-directory helper which sinks it
    (`A → f → g → sink`) IS captured: after the base summaries are built, the
    scanner runs `java_taint::compose_cross_file_summaries` in a bounded
    fixpoint that lifts a same-directory helper's `params_to_sink` into the
    forwarding method's own summary. See "Bounded multi-hop cross-file taint"
    above for the mechanism, bound, and the `java_multihop` /
    `java_multihop_broken` fixtures.
  - **Not covered** (needs a Java type/symbol table the engine does not
    build): type-based instance-method dispatch (`helper.process(x)` resolving
    via `helper`'s declared type → class → file), interface/subclass dispatch,
    overload selection by parameter *types*, `import`-based class resolution
    across packages/directories, and cross-file chains deeper than the hop cap.
    Name-based resolution intentionally over-approximates: any same-package
    method whose name and arity match will resolve, regardless of the
    receiver's declared type.
- **Propagation**: local variables, assignment, string concatenation,
  constructor wrappers, nested source calls, and method calls on tainted
  receivers propagate taint.
- **Sanitizers**: the engine honors `TaintSpec.sanitizers`, but the
  built-in Java rules intentionally declare no sanitizers. For these
  vulnerability classes, the preferred fixes are structural: prepared
  statements, fixed executable names and validated argument arrays,
  outbound host allowlists, and avoiding Java native deserialization for
  request data.

## Supported C# frameworks

`src/rules/csharp_taint.rs` ships six first-consumer rules. Unlike the
Java engine, the C# engine carries a shared sanitizer list (HTML/URL
encoders, `SqlParameter`, numeric conversions, path canonicalizers).

| Rule | CWE | Sink families |
| ---- | --- | ------------- |
| `csharp/taint-sql-injection` | CWE-89 | `new SqlCommand(...)` / `OleDbCommand` / `MySqlCommand`, `ExecuteReader` / `ExecuteNonQuery` / `ExecuteScalar` / `ExecuteXmlReader`, EF Core `FromSqlRaw` / `ExecuteSqlRaw`, Dapper `Query` / `Execute` |
| `csharp/taint-command-injection` | CWE-78 | `Process.Start(...)`, `new ProcessStartInfo(...)` plus its `.Arguments` / `.FileName` assignments |
| `csharp/taint-xss` | CWE-79 | `Response.Write(...)` |
| `csharp/taint-open-redirect` | CWE-601 | `Response.Redirect(...)` |
| `csharp/taint-xxe` | CWE-611 | `XmlReader.Create(...)`, `XmlDocument.LoadXml(...)`, `XmlDocument.Load(...)` |
| `csharp/taint-unsafe-load` | CWE-502 | `Assembly.Load(...)`, `Assembly.LoadFrom(...)`, `Activator.CreateInstance(...)`, `Type.GetType(...)` |

Sources currently covered:

| Framework / surface | Sources |
| ------------------- | ------- |
| ASP.NET (System.Web) | `Request.QueryString`, `Request.Form`, `Request.Params`, `Request.Cookies`, `Request.Headers`, `Request.RawUrl`, `Request.Url`, `Request.Path`, `Request.UserAgent`, `Request.ServerVariables`, `HttpContext.Request` |
| Console / stdin | `Console.ReadLine()`, `Console.Read()`, `Console.ReadKey()` |
| Environment / CLI args | `Environment.GetEnvironmentVariable()`, `Environment.GetCommandLineArgs()` |

### C#-specific engine notes

- **Scope**: method, constructor, local-function, lambda, and anonymous
  method bodies are analyzed independently for intra-file flows.
- **Cross-file (name-based, same-namespace proxy)**: when more than one C#
  file is scanned, a two-pass analysis runs. Pass 1 summarizes each method /
  local function by treating every parameter as a synthetic source and
  recording which parameter indices reach a sink (`params_to_sink`) or the
  return value (`params_to_return`). Pass 2 resolves a helper-method call to
  a summarized method *by method name* in a *sibling file of the same
  directory* (used as a same-namespace proxy, the way Java treats
  same-directory files and Go treats same-directory `.go` files). A tainted
  argument landing on a parameter with a recorded sink flow produces a
  cross-file finding in the caller file, labelled
  `... (via cross-file call to <name>)`. Argument count is honored only as a
  positional bound (the flow's parameter index must be a valid argument
  index), not as a strict overload discriminator.
  - **Bounded multi-hop is modeled**: a cross-file helper that itself forwards
    its parameter into another same-directory helper which sinks it
    (`A → f → g → sink`) is composed by the scanner's bounded multi-hop fixpoint
    (see above).
  - **Not modeled**: `using`/namespace resolution across directories,
    type-based instance dispatch through interfaces or subclasses, overload
    selection by parameter *type* (only positional arity is honored), partial
    classes split across files, extension methods, and cross-file chains deeper
    than the hop cap. These need
    a C# type/symbol table the engine does not build. Name-based resolution
    intentionally over-approximates: any same-directory method whose name and
    arity match the call resolves, regardless of the receiver's declared type.
- **Dotted sources**: the primary ASP.NET sources are dotted
  (`Request.QueryString`, `Request.Form`). They arrive as `Attribute`
  matchers and are matched against `member_access_expression` and
  `element_access_expression` nodes (`Request.QueryString["key"]`), not
  bare identifiers. This is the "bridge lesson from Ruby" called out in
  the `csharp_taint.rs` header — the same engine serves both the
  first-party rules and the Semgrep YAML bridge.
- **Propagation**: local variables, assignments, `+` string
  concatenation, interpolated strings (`$"...{expr}..."`), member/element
  access on tainted receivers, and call arguments propagate taint.
- **Sanitizers**: `HttpUtility.HtmlEncode` / `HtmlAttributeEncode` /
  `UrlEncode`, `HtmlEncoder.Default.Encode`, `SqlParameter`,
  `int.Parse` / `Convert.ToInt32` / `Convert.ToInt64`, and
  `Path.GetFileName` / `Path.GetFullPath` collapse taint to clean.

Known precision limitations of the v1 sink set are documented in the
repository; in particular, several sink entries are receiver-less
method-name matchers (`Load`, `Write`, `Redirect`, `Start`, `Query`,
`Execute`) and can over-match unrelated same-named methods. Track narrow,
receiver-constrained sink variants as a follow-up.

## Supported Ruby frameworks

`src/rules/ruby_taint.rs` ships five first-consumer rules. The engine reuses
the shared source/sanitizer catalogs (`ruby_taint_sources`,
`ruby_taint_sanitizers`) and selects a rule-specific subset of
`ruby_taint_sinks`.

| Rule | CWE | Sink families |
| ---- | --- | ------------- |
| `rb/taint-command-injection` | CWE-78 | `system`, `exec`, `spawn` (bare and `Kernel.*`), `eval`, `instance_eval` |
| `rb/taint-sql-injection` | CWE-89 | ActiveRecord `where`, `find_by_sql`, `connection.execute` |
| `rb/taint-xss` | CWE-79 | `raw(...)`, `.html_safe` |
| `rb/taint-unsafe-deserialization` | CWE-502 | `Marshal.load`, `YAML.load`, `YAML.unsafe_load` |
| `rb/taint-open-redirect` | CWE-601 | `redirect_to` |

Sources currently covered:

| Framework / surface | Sources |
| ------------------- | ------- |
| Rails / Sinatra / Rack | `params[...]`, `request.params`, `request.body`, `request.env`, the `request` / `req` handler parameter |
| CLI / stdin | `gets`, `STDIN.gets`, `STDIN.read`, `STDIN.readline` |
| Environment | `ENV[...]`, `ENV.fetch` |

### Ruby-specific engine notes

- **Scope**: each `method` / `singleton_method` body is analyzed
  independently (including methods nested inside `class` / `module`
  bodies). Top-level code outside any method definition is not analyzed.
  There is no Ruby cross-file or type-resolution pass yet.
- **Sources**: the primary Rails source is `params`, modeled as a
  `ParamName` matcher. It matches both the bare identifier and the
  `params[:key]` `element_reference` shape, so controller actions that call
  the implicit `params` method (not just ones that take a `params` formal
  argument) are covered.
- **Propagation**: local variables, assignments, string interpolation
  (`"...#{expr}..."`), binary `+` concatenation, subscript/element-reference
  on tainted receivers, and call arguments propagate taint. Backtick / `%x`
  subshells with tainted interpolation are flagged directly.
- **Sanitizers**: `Shellwords.escape`, `ERB::Util.html_escape`,
  `CGI.escapeHTML`, and `sanitize` collapse taint to clean.
- **Argument-only sink matching**: the v1 engine checks a sink call's
  *arguments* for taint, not its receiver. Argument-style sinks (`system(x)`,
  `raw(x)`, `Marshal.load(x)`, `redirect_to(x)`, `where("...#{x}...")`) fire
  end-to-end. Receiver-style XSS (`.html_safe` on a tainted receiver) is
  matched as a sink but its receiver is not inspected, so the receiver-taint
  form does not produce a finding yet — track receiver-taint handling as a
  follow-up.
- **ActiveRecord parameter binding**: `where("col = ?", val)` is safe in
  practice, but the engine does not model `?` binding and flags a tainted
  second argument. This is the same precision limitation the C# engine
  documents for `SqlCommand` parameterization.

## Open questions for the full #10

- **Cross-function propagation.** The first step — "trust the return of helpers whose body we can see in the same file" — landed in issue #19 as a single-hop, name-keyed summary pass. Next steps: multi-hop propagation via fixed-point iteration over the summary map, scope-aware keys that distinguish nested definitions, argument-based taint threading so callers' tainted arguments influence helper summaries, then cross-file via module symbol tables. Each is its own issue.
- **Broader pattern surface in the YAML bridge.** `pattern-either` inside source/sink/sanitizer blocks is supported (including nested `pattern-either:` flattening). `pattern-inside` / `metavariable-pattern` constraints and per-finding sanitization semantics are still unsupported; the bridge drops such entries with a warning rather than partially loading them.

Contributions and concrete counter-examples welcome on #10.
