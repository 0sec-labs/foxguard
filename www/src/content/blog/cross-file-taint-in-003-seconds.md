---
title: "Cross-file taint in 0.03 seconds"
date: "2026-04-12"
description: "foxguard 0.6.0 traces taint across file boundaries for Python, JavaScript, and Go. Here is how the two-pass architecture works, and why it is fast."
readTime: "5 min read"
---

Most security scanners that offer cross-file taint analysis make you wait for it. CodeQL takes minutes. Semgrep Pro is a paid product. The open-source alternatives stop at file boundaries.

foxguard 0.6.0 traces taint across files in all three taint languages — Python, JavaScript, and Go — and the Django shop fixture scans in 0.03 seconds.

This post explains how.

## The problem

Single-file taint tracking catches the easy cases. The source and the sink are in the same function, or at least the same file. You call `request.args.get("host")` and then `os.system("ping " + host)` on the next line, and the engine sees the flow.

Real codebases do not work that way.

```python
# views.py
from . import queries

def search(request):
    name = request.GET["name"]
    return queries.run_query(name)
```

```python
# queries.py
def run_query(name):
    cur.execute("SELECT * FROM users WHERE name = '" + name + "'")
```

The source is in `views.py`. The sink is in `queries.py`. A single-file engine sees two clean files — `views.py` calls a function it knows nothing about, and `queries.py` has a parameter it knows nothing about. Neither file, analyzed alone, has a provable taint flow.

To see the vulnerability, you need to know two things:

1. `run_query`'s first parameter reaches a SQL injection sink.
2. `views.search` calls `run_query` with untrusted input.

Fact 1 comes from analyzing `queries.py`. Fact 2 comes from analyzing `views.py` with fact 1 in hand. That is a two-pass problem.

## Two passes

foxguard solves this with a parallel two-pass scan.

**Pass 1: summarize.** For every file, extract function-level taint summaries. For each exported function, run the existing taint engine with each parameter treated as a synthetic source. If parameter 0 reaches a SQL injection sink, record that. If parameter 1 flows to the return value, record that too.

The summaries are small: a function name, a list of parameter-to-sink flows, and a list of parameter-to-return flows. They fit in a `HashMap<PathBuf, Vec<FunctionTaintSummary>>`.

**Pass 2: analyze.** Run the normal scan, but with the summary map available. When the engine encounters a call to an imported function, it resolves the callee against the summaries. If the caller passes tainted data as argument 0, and the summary says argument 0 reaches a SQL sink, emit a finding.

Both passes run in parallel via rayon. Pass 1 is embarrassingly parallel — every file is independent. Pass 2 is also parallel — summaries are read-only shared state, no locks needed.

## Import resolution

The hard part is not the taint analysis. The hard part is figuring out which function in which file a call expression refers to. Each language does this differently:

**Python.** `from . import queries` means `queries.py` in the same directory. `from .queries import run_query` means the `run_query` function in `queries.py`. foxguard resolves sibling files and relative imports by walking the filesystem relative to the importing file.

**JavaScript.** `const services = require('./services')` or `import { runQuery } from './services'`. The specifier `./services` could resolve to `services.js`, `services.ts`, `services.mjs`, `services/index.js`, or half a dozen other paths. foxguard probes each extension in order until it finds a file.

**Go.** All `.go` files in the same directory are in the same package. No import is needed — `handlers.go` can call `runQuery()` defined in `store.go` directly. foxguard builds a directory-to-files index and treats all sibling files as available for cross-file resolution.

None of this requires a package manager, a lockfile, or a network call. It is pure filesystem resolution, and it covers the patterns that matter for security — the application code where sources and sinks live.

## Why it is fast

The naive approach to cross-file analysis is a whole-program call graph. Parse everything, build a graph, solve a fixpoint. That is what CodeQL does, and it is why CodeQL takes minutes.

foxguard does something simpler. The summaries are **one-level deep**. Pass 1 asks: "if this function's parameters are tainted, what happens?" It does not chase the parameters through further function calls in other files. It only looks at what happens inside the function body itself.

This means foxguard will miss a three-file chain: `views.py` → `services.py` → `queries.py`. The source is in file 1, the intermediate call is in file 2, and the sink is in file 3. Two-level summaries would catch it, but one-level is the 80/20 point — most real request handlers call a helper that directly hits the sink.

The tradeoff buys speed. Pass 1 is linear in the number of files times the number of functions. Pass 2 is linear in the number of files times the number of calls. No fixpoint, no iteration, no exponential blowup. The whole thing finishes in milliseconds.

## What it looks like

```
$ foxguard tests/fixtures/realistic/django_shop/ --explain

views.py
  52:12  CRITICAL  py/taint-sql-injection (CWE-89)
         django.request.GET reaches cursor.execute (via cross-file call to run_query)
    source → views.py:51   django.request.GET
    sink   → views.py:52   cursor.execute (via cross-file call to run_query)
  Fix: Use parameterized queries: cur.execute("SELECT * FROM users WHERE name = ?", (name,))
```

The finding tells you the source, the sink, the cross-file call chain, and how to fix it. In 0.03 seconds.

## What is next

One-level summaries are the starting point. Multi-hop chains (file A → file B → file C) need recursive summary application — tractable without a fixpoint, just more passes. Custom sanitizer recognition across files is another gap: if `utils.py` defines `safe_query()` that parameterizes everything, pass 2 should know that.

Both are on the roadmap. Neither changes the architecture — the two-pass design extends naturally.

---

*foxguard is an open-source security scanner written in Rust. 170+ built-in rules, 10 languages, cross-file taint tracking for Python, JavaScript, and Go. [Try it](https://github.com/PwnKit-Labs/foxguard): `npx foxguard .`*
