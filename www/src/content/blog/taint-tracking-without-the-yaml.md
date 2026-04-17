---
title: "Taint tracking, without the YAML"
date: "2026-04-11"
description: "foxguard ships intraprocedural taint tracking for Python, JavaScript, and Go — built into the scanner, not bolted on as YAML rules. Here is what that gets you and where it stops."
readTime: "6 min read"
---

Most security scanners treat taint tracking as a YAML feature.

You write a rule. You declare sources. You declare sinks. You maybe declare sanitizers. You run the scanner. If any one of those declarations is wrong or missing, the rule silently does nothing, or it fires on everything.

That is a lot of infrastructure for a developer to maintain before they catch their first real bug.

**foxguard 0.5.0 ships taint tracking the other way around.**

It is built into the scanner. It knows about Flask, Django, FastAPI, Express, Next.js, Hono, Fastify, SvelteKit, Deno, Gin, and `net/http` out of the box. You install foxguard. You run it. You get taint findings.

No rule file. No sources block. No sinks block.

## What intraprocedural means

The engine follows untrusted input from a request source, through assignments, method calls, string concatenation, and f-string interpolation, into dangerous sinks — **inside a single function.**

It does same-file interprocedural too: if a helper function returns tainted data, the engine knows that, and a caller in the same file inherits the taint.

It stops at file boundaries. It does not follow taint across imports yet. That is a real limit and we will say more about it below.

## A Flask example

Here is a realistic Flask handler:

```python
@app.route("/ping")
def ping():
    host = request.args.get("host", "localhost")
    os.system("ping -c 1 " + host)
    return "ok"
```

`request.args.get` is a Flask source. `os.system` is a command injection sink. `host` is tainted. The binary `+` propagates taint to the full string. The scanner fires `py/taint-command-injection` on line 4.

That is the whole rule. The engine does the reasoning.

The same holds if you rename `host`, wrap it in another variable, pass it through a helper in the same file, or interpolate it into an f-string. Each of those was a separate false negative in a naive AST-only scanner. The engine closes them.

## A JavaScript example

```js
app.get("/fetch", (req, res) => {
    const url = req.query.url;
    fetch(url).then(r => r.text()).then(body => res.send(body));
});
```

`req.query` is an Express source. `fetch` is an SSRF sink. The finding is `js/taint-ssrf`. You did not write a YAML rule. You installed foxguard and ran it.

## A Go example

```go
func search(w http.ResponseWriter, r *http.Request) {
    q := r.URL.Query().Get("q")
    db.Exec("SELECT * FROM items WHERE name = '" + q + "'")
}
```

`r.URL.Query().Get` is a `net/http` source. `db.Exec` is a SQL injection sink. `go/taint-sql-injection` fires. Same engine, same shape.

## Near-misses that should not fire

The engine has to be quiet when the code is fine. That is half the work.

```python
@app.route("/static-eval")
def static_eval():
    _ignored = request.args["expr"]   # read, but discarded
    return str(eval("1 + 1"))         # sink receives a literal
```

No finding. The tainted value never reaches the sink.

```python
@app.route("/healthz")
def healthz():
    os.system("uptime")               # literal, not tainted
    return "ok"
```

No finding. There is no source in this function at all.

Those two cases are not hypothetical. They are the two most common false positives in rule-based scanners, because rule-based scanners match the dangerous primitive (`eval`, `os.system`) and not the dangerous use.

The engine matches the dangerous use. That is the whole point.

## What you do not have to write

Every rule below is built in. You do not configure any of this.

**Python sources.** `request.args`, `request.form`, `request.json`, `request.data`, `request.files`, `request.headers`, `request.cookies` (Flask and Django variants), `Request.query_params` and body readers (FastAPI), CLI `sys.argv`, `input()`, `os.environ.get`, env var reads.

**JavaScript sources.** `req.query`, `req.params`, `req.body`, `req.headers`, `req.cookies` (Express, Fastify), Next.js `request.nextUrl`, Hono `c.req.*`, SvelteKit `event.url`, `event.params`, Deno `Deno.env.get`.

**Go sources.** `r.URL.Query()`, `r.PostFormValue`, `r.FormValue`, `r.Header`, Gin `c.Query`, `c.PostForm`, `c.GetHeader`.

**Sinks (all languages).** command execution, SQL queries, template rendering (SSTI), SSRF fetchers, XPath injection, LDAP injection. **Python additionally:** `eval`, `pickle.loads`, `yaml.load`. **JavaScript additionally:** `eval`, `innerHTML` (XSS).

You get all of that the moment you install foxguard.

## Cross-file taint (new)

As of 0.6.0, foxguard traces taint **across file boundaries** for all three taint languages. If your source is in `views.py` and your sink is in `queries.py`, the engine connects them.

It works in two passes: pass 1 builds function-level taint summaries for every file, pass 2 resolves imported calls against those summaries. The whole thing runs in parallel and adds negligible overhead — the Django shop fixture scans in 0.03s.

```python
# views.py
from . import queries
def search(request):
    name = request.GET["name"]
    return queries.run_query(name)   # ← cross-file taint fires here

# queries.py
def run_query(name):
    cur.execute("SELECT * FROM users WHERE name = '" + name + "'")
```

The same works for JavaScript (`require`/`import` resolution) and Go (same-package function calls).

## Where it stops

Honesty matters here. These are the things the engine does **not** do yet:

- **Cross-function with loops.** Tainted data that threads through a list comprehension or a loop back into a sink is tracked on the simple cases, not all of them.
- **Custom sanitizers.** If you wrap your command execution in a helper that quotes everything via `shlex.quote`, foxguard does not know that helper is safe unless the sanitizer is one of the built-in ones.
- **Aliasing through containers.** If taint goes into a dict and comes back out with a different key, the engine will miss some of those paths.

Those are deliberate tradeoffs. The engine catches most real request-handler bugs without the precision loss you get from whole-program pointer analysis. `--explain` shows source-to-sink dataflow traces, and every taint finding includes a fix suggestion.

## Why this belongs in the scanner, not in YAML

The argument for built-in taint tracking is the same argument as built-in framework rules:

- **Zero configuration is the point.** A local scanner that makes you write a rule file before it catches a real bug has already lost the local loop.
- **Framework semantics are not generic.** `request.args.get("host", "localhost")` is tainted. `request.args.get("host", "localhost").startswith("10.")` is still tainted. `os.environ["FOXGUARD_API_KEY"]` is tainted in some threat models and not in others. The scanner has to know which calls mean what in which framework. That knowledge does not live in YAML, it lives in the rule registry.
- **The YAML bridge is still there.** If you have existing `mode: taint` rules, foxguard also loads them — the bridge supports `pattern-sources`, `pattern-sinks`, `pattern-sanitizers`, and `pattern-either` combinations. But the bridge is a migration path, not the primary product.

If you want to write your own taint rules, you can. You should not have to just to catch a command injection on Flask.

## The bar

The bar for taint tracking in a local scanner is the same bar from the last post:

- fast enough to run without thinking
- precise enough that a finding feels worth reading
- scoped enough that developers know what to do next

foxguard moves toward that bar on the dataflow axis. Same-file, framework-aware, zero configuration. You install it, you run it, you get real taint findings on real code.

The YAML is optional. That is how it should be.

---

*foxguard is an open-source security scanner written in Rust. 170+ built-in rules, 10 languages, cross-file taint tracking for Python, JavaScript, Go, and Kotlin. Semgrep/OpenGrep-compatible YAML bridge. [Try it](https://github.com/PwnKit-Labs/foxguard): `npx foxguard .`*
