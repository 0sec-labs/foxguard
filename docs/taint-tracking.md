# Taint tracking in foxguard

This document describes the intraprocedural taint engine added as a proof of concept for issue #10. It is intended for rule authors and contributors, not end users.

## Why taint at all

Pure AST pattern matching can answer "is this dangerous sink used anywhere?" It cannot answer "is untrusted data reaching this sink?" Those are different questions. The conservative rules (`py/no-pickle`, `py/no-command-injection`, etc.) answer the first and are the right default for a local-first scanner: fast, zero false negatives on the sink itself, high recall at the cost of precision.

The taint engine answers the second, on a narrower footprint. It lets us ship rules that fire only when there is a provable flow from a known source into a known sink within a single function. Higher precision, lower recall. The two rule classes coexist.

## Scope of the POC

In scope:

- **One language**: Python.
- **Intraprocedural**: each function body is analyzed independently.
- **Flow-insensitive**: statements are processed in source order. Reassigning a tainted variable to a clean value drops the taint. Branches are not modeled — taint observed in one branch of an `if` persists through the fall-through.
- **One level of attribute and subscript propagation**: `x.y` and `x[k]` are tainted when `x` is tainted.
- **One level of wrapping-call propagation**: `bytes(x)` is tainted when `x` is tainted. This covers the common "sanitize by retype" anti-pattern.
- **Alias-aware sinks and sources**: the engine resolves callees and source roots through the per-file import alias table already introduced for issue #7.

Out of scope for this PR, tracked under #10 as follow-ups:

- **Interprocedural**: no cross-function analysis. A helper `def get_data(): return request.data` will not taint callers.
- **Cross-file**: no module boundary crossing.
- **Sanitizer support**: `TaintSpec.sanitizers` exists on the struct so the YAML bridge in the next PR has a slot to fill, but the engine does not consult it yet. Every flow is reported.
- **Field sensitivity**: `d["key"]` is tainted because `d` is. Different keys are not distinguished.
- **Object attribute propagation beyond one level**: `x.y.z` is tainted when `x` is tainted, but the engine does not persist taint on `x.y` as a distinct name.
- **Dynamic import forms**: `importlib.import_module(...)` does not interact with the alias table, so sinks reached through it are not recognized.
- **Other languages**: JS/TS, Go, Java, etc. have no taint engine yet. Adding one per language is expected — the shape of the current Python engine is intended to serve as a template.

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
    pub sanitizers: Vec<NodeMatcher>, // reserved — see "Scope"
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

## Adding a new taint rule

1. Define a struct in the appropriate rules module (e.g. `python.rs`).
2. Build a `TaintSpec` with your sources, sinks, and (once supported) sanitizers.
3. Implement `Rule::check_with_context` to call `python_taint::analyze_tree` with the spec and the context's alias table.
4. Map each `TaintFinding` to a `Finding` with a description that mentions both the source and the sink — users want to know *why* a flow was flagged.
5. Register the rule in `src/rules/mod.rs`.
6. Add positive + negative fixtures in `tests/fixtures/` and an integration test asserting exact finding counts.

The `py/taint-pickle-deserialization` rule is ~120 lines and is the canonical example.

## Coexistence with conservative rules

Taint rules do not replace direct-sink rules. In the POC, `py/no-pickle` fires on every `pickle.loads` call; `py/taint-pickle-deserialization` fires only on the subset where a flow is provable. A user may see both findings on the same line, with different messages. That is intended — the two rules encode different questions and should be silenced independently if the user wants to suppress one but not the other.

## Performance

The taint engine runs once per file, only on Python, and only when the file contains function definitions. The walk is a single pass over the AST with a small `HashMap` as state. No additional parsing, no network, no disk. On the existing `vulnerable.py` fixture the taint rule adds microseconds to a run that was already sub-millisecond.

## Open questions for the full #10

- **Sanitizer semantics.** Semgrep's `mode: taint` distinguishes "sanitized value" from "killed taint". Do we track the difference, or collapse them into "clean" for v1?
- **Cross-function propagation.** The first step beyond intraprocedural is probably "trust the return type of helpers whose body we can see in the same file", then cross-file via module symbol tables. Each step adds real complexity and should be its own issue.
- **YAML bridge.** The next PR will map Semgrep-style `pattern-sources` / `pattern-sinks` YAML into `TaintSpec`. The main open question is how much of Semgrep's pattern language we need to support for real-world taint rules to work — probably just `pattern:` and `pattern-either:` to start.

Contributions and concrete counter-examples welcome on #10.
