# Taint tracking in foxguard

This document describes the intraprocedural taint engine added as a proof of concept for issue #10. It is intended for rule authors and contributors, not end users.

## Why taint at all

Pure AST pattern matching can answer "is this dangerous sink used anywhere?" It cannot answer "is untrusted data reaching this sink?" Those are different questions. The conservative rules (`py/no-pickle`, `py/no-command-injection`, etc.) answer the first and are the right default for a local-first scanner: fast, zero false negatives on the sink itself, high recall at the cost of precision.

The taint engine answers the second, on a narrower footprint. It lets us ship rules that fire only when there is a provable flow from a known source into a known sink within a single function. Higher precision, lower recall. The two rule classes coexist.

## Scope of the POC

In scope:

- **Two languages**: Python and JavaScript/TypeScript, each with its own engine (`src/rules/python_taint.rs` and `src/rules/javascript_taint.rs`) sharing an identical surface (`TaintSpec`, `NodeMatcher`, `TaintFinding`, `analyze_tree`). `.ts` files are parsed through tree-sitter-javascript, so the JS engine also covers TypeScript source.
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

Out of scope for this PR, tracked under #10 as follow-ups:

- **Multi-hop interprocedural chains**: only one level of helper-call propagation is supported. A helper that itself calls another helper is not tracked through the deeper hop.
- **Cross-file**: no module boundary crossing.
- **Instance and class methods in interprocedural summaries**: only top-level `function_declaration`s and `const/let/var foo = ...` arrow/function-expression helpers are summarized. `obj.method()` and `self.helper()` calls are not looked up in the summary map.
- **Argument taint propagation**: helper summaries are computed with only their parameters' taint sources seeded (via `ParamName`). Passing an already-tainted local into a helper does not influence the helper's return summary — pass 1 analyzes helpers with a conservative view of their parameters.
- **Per-finding sanitization**: Semgrep's `mode: taint` distinguishes "this specific flow was sanitized" from "the value is now clean"; it can still fire on secondary flows that bypassed the sanitizer along a different path. foxguard's v1 collapses both cases into "clean" and does not track per-finding sanitization state.
- **Field sensitivity**: `d["key"]` is tainted because `d` is. Different keys are not distinguished.
- **Object attribute propagation beyond one level**: `x.y.z` is tainted when `x` is tainted, but the engine does not persist taint on `x.y` as a distinct name.
- **Dynamic import forms**: `importlib.import_module(...)` does not interact with the alias table, so sinks reached through it are not recognized.
- **Other languages**: Go, Java, Ruby, PHP, C#, Swift, Rust etc. have no taint engine yet. Adding one per language is expected — the shape of the Python and JavaScript engines is intended to serve as a template. JavaScript/TypeScript uses the same scope as Python (intraprocedural, flow-insensitive, one-level subscript propagation, template-literal and wrapping-call propagation, collapse-to-clean sanitizers) with a `JsImportAliases` table for `import`/`require` forms.

## API

The engine lives in `src/rules/python_taint.rs`. The public surface is four items:

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

Taint rules do not replace direct-sink rules. In the POC, `py/no-pickle` fires on every `pickle.loads` call; `py/taint-pickle-deserialization` fires only on the subset where a flow is provable. A user may see both findings on the same line, with different messages. That is intended — the two rules encode different questions and should be silenced independently if the user wants to suppress one but not the other.

## Performance

The taint engine runs once per file, only on Python, and only when the file contains function definitions. The walk is a single pass over the AST with a small `HashMap` as state. No additional parsing, no network, no disk. On the existing `vulnerable.py` fixture the taint rule adds microseconds to a run that was already sub-millisecond.

## Semgrep-compatible YAML bridge

Issue #17 added a narrow YAML bridge so existing Semgrep `mode: taint` rules can be loaded with `--rules` and compiled into the same `TaintSpec` that native rules build by hand. The bridge lives in [`src/rules/semgrep_taint.rs`](../src/rules/semgrep_taint.rs); see [COMPATIBILITY.md](../COMPATIBILITY.md) for the exact subset of Semgrep's taint schema that is supported and what falls back to "skip with warning".

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

## Open questions for the full #10

- **Cross-function propagation.** The first step — "trust the return of helpers whose body we can see in the same file" — landed in issue #19 as a single-hop, name-keyed summary pass. Next steps: multi-hop propagation via fixed-point iteration over the summary map, scope-aware keys that distinguish nested definitions, argument-based taint threading so callers' tainted arguments influence helper summaries, then cross-file via module symbol tables. Each is its own issue.
- **Broader pattern surface in the YAML bridge.** `pattern-either` inside source/sink/sanitizer blocks is supported (including nested `pattern-either:` flattening). `pattern-inside` / `metavariable-pattern` constraints and per-finding sanitization semantics are still unsupported; the bridge drops such entries with a warning rather than partially loading them.

Contributions and concrete counter-examples welcome on #10.
