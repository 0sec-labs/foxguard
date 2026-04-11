# Precision and false-positive methodology

This document describes how foxguard measures rule precision, how the built-in
rules are classified, and the known false-positive patterns we have seen and
tuned for. It is the honest, technical counterpart to the marketing-facing
coverage table in the [README](../README.md).

It is also the document [issue #9](https://github.com/PwnKit-Labs/foxguard/issues/9)
asks for: rather than publishing a single global "precision number" that would
be meaningless without a corpus, we publish a per-rule tier classification
based on how each rule is implemented, and an explicit list of the false-positive
patterns we already know about.

If you want the one-line version: foxguard rules fall into three tiers — tight
structural matches, intentionally-loud conservative sink rules, and
heuristic/regex-based rules — plus a fourth taint-based tier that trades recall
for precision. We have not yet published labeled precision numbers on a real
corpus; that work is tracked in issue #9 as a follow-up.

## Section 1: Methodology

foxguard measures rule quality with three artifacts that all live in the repo:

1. **Positive fixtures** under `tests/fixtures/vulnerable_*.{py,js,rs,...}`
   and `tests/fixtures/vulnerable.{py,js,go,rs,java,php,rb,cs,swift}`. These
   are hand-crafted files with one vulnerable flow per function. Every handler
   should fire exactly once for the rule it targets. The integration tests in
   `tests/` assert that: if a positive fixture stops matching, CI fails. This
   is our **recall floor**.

2. **Negative fixtures** under `tests/fixtures/safe*.{py,js,go}`,
   `tests/fixtures/safe_py_taint.py`, `tests/fixtures/safe_js_taint.js`, and
   `tests/fixtures/safe_py_aliases.py`. These contain patterns that *look*
   dangerous but are not — for example, Django settings that read
   `SECRET_KEY` from `os.environ`, SQL-ish strings with no interpolation, or
   import aliases that rename safe functions. The integration tests assert
   these produce **zero findings**. This is our **precision floor** for the
   patterns we already know about.

   Sitting between the one-function-per-case positive fixtures and the real-
   world corpus scans is a **realistic test corpus** under
   `tests/fixtures/realistic/`. Each file there is a small-but-complete
   vulnerable application for one supported framework (Flask, Django,
   FastAPI, a CLI tool, Express, Next.js, Hono) with idiomatic routing,
   helper functions that exercise interprocedural propagation, and 2–3
   explicitly-labelled `NEAR MISS` functions per file whose patterns the
   engine might be tempted to flag but should not. The integration test
   `tests/realistic_fixtures.rs` pins the exact total finding count and the
   exact count per taint rule for every file. Any rule addition or engine
   change that shifts these counts forces explicit acknowledgement — which
   is how we catch end-to-end precision regressions that neither the
   single-function fixtures nor the public corpus scan would notice.

3. **Real-world corpus scans.** We have run foxguard against the latest HEAD of
   Express, Flask, Gin, Laravel, Rails (actionpack), Spring Petclinic, and a
   Next.js starter — 799 files, 369 findings, 0.86 seconds total. Numbers and
   per-repo breakdown are in the blog post
   [*I scanned Express, Flask, Rails, Gin, and Laravel for security
   issues*](https://foxguard.dev/blog/scanning-top-frameworks). That scan is
   the basis for the tier classifications in Section 2 — rules that produced
   review-worthy findings on framework source code versus rules that stayed
   silent are what informed the tight/conservative/heuristic split.

### Metrics we track

- **Recall on positive fixtures:** `(# findings on positive fixture) /
  (# expected findings)`. For well-constructed fixtures this is 1.0, and CI
  fails if it drops. This does **not** measure recall on real code — a hand-
  crafted fixture is not a representative corpus.
- **False-positive footprint on real code:** the count of findings our
  engineers reviewed on the seven-framework corpus and classified as "not a
  real issue." We have not done this exhaustively and we are not publishing a
  number we cannot defend. Section 3 lists every false-positive *pattern* we
  found and fixed; that is the honest version of the metric we can stand
  behind today.
- **Noise ratio:** findings in test/example/vendored directories versus
  findings in production code. foxguard ships a built-in noise filter in
  `src/engine/scanner.rs` that skips `vendor/`, `node_modules/`,
  `__fixtures__/`, `__mocks__/`, `dist/`, `build/`, `.next/`, `coverage/`,
  and `.cache/`, and also skips `.min.js`/`.min.css` files and any file whose
  first line is longer than 1000 characters (a minified-bundle heuristic).
  This is the single biggest FP-reduction lever and it runs by default.

### What this methodology is not

It is not a published per-rule precision table backed by a labeled corpus.
Issue #9 scopes that as a separate effort — it requires pinning a set of OSS
repos by SHA, labeling every finding TP/FP/unsure with a one-line
justification, and wiring the result into CI. We have not done that yet. This
document is the predecessor: it describes how we *think* about precision and
which rules we already know are loose, so users can set expectations before
they scan.

## Section 2: Rule classifications

Every built-in rule is placed in one of four tiers based on how its
implementation decides to fire. The tier is a property of the *rule design*,
not of a measured FP rate. The rule IDs below are the exact identifiers
emitted in foxguard's output and match the strings in `src/rules/*.rs`.

### Tier 1 — Tight (structural match on a specific shape)

These rules match a very specific AST or configuration shape where a positive
match is almost always a real issue. Expected FP rate is low.

**JavaScript / TypeScript**

- `js/jwt-none-algorithm` — flags `algorithm: 'none'` in a `jsonwebtoken`
  options object. The shape is unambiguous.
- `js/jwt-hardcoded-secret`, `js/jwt-ignore-expiration`,
  `js/jwt-decode-without-verify`, `js/jwt-verify-missing-algorithms` — all
  structural matches on `jsonwebtoken` call shapes.
- `js/express-no-hardcoded-session-secret`,
  `js/express-cookie-no-secure`, `js/express-cookie-no-httponly`,
  `js/express-cookie-no-samesite`,
  `js/express-session-saveuninitialized-true`,
  `js/express-session-resave-true` — all match on Express
  `session()`/`cookie()` option objects with a specific key/value.
- `js/no-cors-star` — `cors({ origin: '*' })` or equivalent.

**Python**

- `py/django-secret-key-hardcoded`, `py/flask-secret-key-hardcoded` —
  assignment to `SECRET_KEY` with a string literal, excluding values that
  come from `os.environ`/`os.getenv`.
- `py/flask-debug-mode`, `py/no-debug-true` — `app.run(debug=True)` and
  `DEBUG = True` at module scope.
- `py/session-cookie-*`, `py/csrf-cookie-*`, `py/wtf-csrf-*`,
  `py/django-allowed-hosts-wildcard`, `py/secure-ssl-redirect-disabled`,
  `py/csrf-exempt` — all structural matches on Django/Flask-WTF config keys.

**Rust**

- `rs/tls-verify-disabled` — `danger_accept_invalid_certs(true)` in reqwest
  or `danger().set_certificate_verifier(...)` in rustls.
- `rs/transmute-usage` — any call to `std::mem::transmute`. Rare enough in
  real code to be worth flagging on sight.

**Go**

- `go/gin-no-trusted-proxies` — `SetTrustedProxies(nil)` on a Gin engine.
- `go/insecure-tls-skip-verify` — `InsecureSkipVerify: true` in a
  `tls.Config` literal.
- `go/net-http-no-timeout` — `http.Server{...}` struct literal with no
  `ReadTimeout`/`WriteTimeout` field.

**Java**

- `java/spring-csrf-disabled`, `java/spring-cors-permissive` — structural
  matches on Spring Security builder calls.
- `java/no-xxe` — specific parser factory configurations.

**C#**

- `cs/no-xxe`, `cs/no-cors-star` — structural matches on
  `XmlReaderSettings`/`UseCors` call shapes.

**PHP**

- `php/no-extract` — any call to `extract()` on a superglobal.

**Swift**

- `swift/no-tls-disabled`, `swift/no-insecure-transport`,
  `swift/no-insecure-keychain` — configuration-value matches on
  `URLSessionConfiguration`, `NSAppTransportSecurity`, and Keychain
  attribute dictionaries.

Rationale: a match here requires the user to have written out the specific
dangerous shape. The regex-or-pattern surface is narrow enough that benign
code almost never looks like this.

### Tier 2 — Conservative (intentional high-recall sink rules)

These rules fire on *any* occurrence of a dangerous primitive, with no
attempt to decide whether the data is user-controlled. They are deliberately
loud. The point is recall: you will get a finding every time the primitive
is used, and it is the reviewer's job to decide whether that use is safe in
context. In exchange, you get zero false negatives on the primitive itself.

- `py/no-eval`, `py/no-pickle`, `py/no-yaml-load` — any call to `eval`,
  `pickle.loads`, `yaml.load` (without `SafeLoader`). Alias-aware via
  `ImportAliases`.
- `rs/unsafe-block` — every `unsafe { }` block.
- `rs/no-unwrap-in-lib` — every `.unwrap()` in a `lib.rs` target.
- `php/no-eval`, `php/no-unserialize`, `php/no-preg-eval`,
  `php/no-file-inclusion` — any occurrence of the dangerous primitive.
- `rb/no-eval` — `eval` and `instance_eval` calls. `class_eval`/`module_eval`
  are deliberately excluded (see Section 3).
- `java/no-unsafe-deserialization` — `ObjectInputStream.readObject` on any
  stream.
- `cs/no-unsafe-deserialization` — `BinaryFormatter` / `NetDataContractSerializer`.
- `swift/no-eval-js` — `WKWebView.evaluateJavaScript`.

Rationale: if you use one of these primitives, you own the review. foxguard
will not pretend to know whether the input is sanitized. The rule doc string
says "avoid" or "review" rather than "this is definitely a bug."

### Tier 3 — Heuristic (pattern- or regex-based, context-dependent)

These rules match on patterns that *correlate* with bugs but need human
context to confirm. They are where most known false positives live.

- `js/no-sql-injection` — requires a SQL keyword followed by SQL structure
  (`SELECT ... FROM`, `INSERT INTO`, `UPDATE ... SET`, `DELETE FROM`,
  `DROP/ALTER/CREATE TABLE`, `EXEC`) in the literal, plus string
  concatenation or template interpolation. See commit `13ea1ae` — earlier
  versions matched `res.send('delete ' + name)` and were retightened.
- `py/no-sql-injection`, `go/no-sql-injection`, `rb/no-sql-injection`,
  `php/no-sql-injection`, `java/no-sql-injection`, `cs/no-sql-injection`,
  `rs/no-sql-injection`, `swift/no-sql-injection` — same family, same
  limitation: without taint we cannot tell whether the interpolated value is
  user-controlled.
- `js/no-hardcoded-secret`, `py/no-hardcoded-secret`, and the per-language
  equivalents — regex on variable names (`password`, `secret`, `api_key`,
  `token`, `auth`, `credential`, `private_key`) assigned to string literals
  of length ≥ 4. Matches test fixtures with `password = "hunter2"` as
  intended; will also match legitimate constants named `*_TOKEN_HEADER` or
  `API_KEY_PARAM` that hold a parameter *name* rather than a value.
- `js/no-xss-innerhtml`, `js/no-document-write`, `js/no-unsafe-format-string`
  — flag dangerous DOM sinks without deciding whether the argument is
  tainted.
- `js/no-command-injection`, `py/no-command-injection`, and the per-language
  equivalents — flag `exec`/`spawn`/`Runtime.exec`/`os.system`/`shell=True`
  on any argument, not only tainted ones.
- `js/no-ssrf`, `py/no-ssrf`, `go/no-ssrf`, `rs/no-ssrf`, etc. — flag HTTP
  client calls with any non-constant URL argument.
- `js/no-path-traversal`, `py/no-path-traversal`, etc. — flag filesystem
  calls with path concatenation.
- `js/no-prototype-pollution`, `js/no-unsafe-regex` — AST patterns that
  correlate with bugs but require reviewer judgement.
- `py/no-weak-crypto`, and `*/no-weak-crypto` family — flag `md5`, `sha1`,
  `DES`, `RC4`. False positive on legitimate non-security uses (content
  addressing, cache keys, Git-compatible hashing).

Rationale: these rules answer "is a dangerous primitive used with
non-constant input?" Without flow analysis we cannot answer the stronger
question "is that input user-controlled?" The taint rules below are the
precision-focused alternative.

### Tier 4 — Taint (flow-sensitive, precision-first)

These rules reuse the intraprocedural taint engine documented in
[docs/taint-tracking.md](./taint-tracking.md). They fire only when the engine
can prove a flow from a known source (e.g. `request.args.get`, `req.body`)
into a known sink (e.g. `pickle.loads`, `innerHTML`) within a single function
body, with no intervening sanitizer. They have **near-zero false positives
within their scope** but higher false negatives than their conservative
counterparts — anything interprocedural, cross-file, or involving a flow
shape the engine does not model will be missed.

Python source coverage spans Flask, Django, and FastAPI/Starlette request
attributes, plus common CLI-tool inputs (`sys.argv`, `sys.stdin`, `input()`,
`os.environ`, `os.getenv`). Handler parameters named `request` or `req` are
treated as implicit sources. See `python_taint_sources()` in
`src/rules/python_taint.rs` for the canonical list.

- `py/taint-pickle-deserialization`
- `py/taint-eval`
- `py/taint-command-injection`
- `py/taint-ssrf`
- `py/taint-yaml-load`
- `py/taint-sql-injection`
- `js/taint-xss-innerhtml`
- `go/taint-command-injection`
- `go/taint-sql-injection`
- `go/taint-ssrf`

Go source coverage spans net/http handler parameters (`r`, `req`,
`request`), Gin `*Context` methods (`c.Query`, `c.PostForm`, `c.Param`,
`c.GetHeader`, `c.FormValue`, ...), Echo `c.QueryParam`, Fiber
`c.Params` / `c.Query`, and generic `os.Getenv` / `os.Args`. The
engine propagates taint through method calls on tainted receivers,
`fmt.Sprintf` wrapping, `+` string concatenation, one-level selector
and index chains, and Go's native multi-return destructuring
(`a, b := f()`). Interprocedural return summaries are computed per
file and keyed by function / method simple name. See
`go_taint_sources()` in `src/rules/go_taint.rs` for the canonical
source list and `docs/taint-tracking.md` for the full scope.

The taint rules and the Tier-2 conservative rules are meant to coexist. If
you want loud-and-safe, keep the Tier-2 rules on. If you want
quieter-and-precise on a subset of classes, rely on the taint rules. Both
run by default.

## Section 3: Known false-positive patterns

These are patterns we have seen produce false positives and have explicitly
tuned for. Every item here is verifiable in the code or the git log.

- **SQL injection on plain English.** Earlier versions of
  `js/no-sql-injection` flagged `res.send('delete ' + name)` because
  `delete` is a SQL keyword. Fixed in commit
  [`13ea1ae`](https://github.com/PwnKit-Labs/foxguard/commit/13ea1ae) by
  requiring a full SQL structure in the regex (`SELECT ... FROM`,
  `INSERT INTO`, `UPDATE ... SET`, `DELETE FROM`, `DROP TABLE`, etc.) rather
  than a bare keyword. See `src/rules/javascript.rs` around the
  `NoSqlInjection` rule.
- **Minified JavaScript fixtures.** Bundled jQuery-style
  `!function(e){...}(...)` triggered `js/no-command-injection` and
  `js/no-eval` because the bundles genuinely contain `eval`/`Function`. We
  skip `.min.js` files and files whose first line exceeds 1000 characters
  (see `is_noise_path` and `is_minified` in `src/engine/scanner.rs`).
- **Rails metaprogramming.** `class_eval` and `module_eval` are standard
  Ruby metaprogramming used by Rails, ActiveRecord, and every halfway-serious
  Ruby gem. `rb/no-eval` only flags `eval` and `instance_eval`
  (`src/rules/ruby.rs` around line 86).
- **Django `SECRET_KEY` from the environment.**
  `py/django-secret-key-hardcoded` and `py/flask-secret-key-hardcoded` do
  not fire when the RHS is a call to `os.environ.get`, `os.getenv`, or a
  subscript of `os.environ`. The negative fixture
  `tests/fixtures/safe.py` covers this.
- **Test/example/generated code.** foxguard's default noise filter skips
  `vendor/`, `node_modules/`, `__fixtures__/`, `__mocks__/`, `dist/`,
  `build/`, `.next/`, `coverage/`, `.cache/`, plus `.min.js`/`.min.css`
  files and any file that looks minified by the first-line-length heuristic.
  This is the single biggest source of noise in a default scan and it is on
  by default. Users who want to scan these paths can pass them explicitly.
- **Import aliases.** `py/no-pickle` and friends are alias-aware
  (`src/rules/python_aliases.rs`). `from pickle import loads as deserialize`
  followed by `deserialize(x)` fires the rule; `from safe_module import loads`
  followed by `loads(x)` does not.

## Section 4: How to report a false positive

If foxguard fires on code you believe is safe, open a GitHub issue with the
label **`false-positive`**. Include:

1. The rule ID exactly as emitted (e.g. `js/no-sql-injection`).
2. The smallest self-contained source snippet that reproduces the finding.
3. One or two sentences explaining why the finding is not a real issue —
   what the reviewer would have checked in their head.

We treat false-positive reports as bugs against the rule, not against the
user. If the pattern is general enough to add to the negative-fixture suite,
we do that as part of the fix so it cannot regress silently.

## Section 5: How to suppress a finding

Two mechanisms, documented more fully in the main
[README](../README.md#suppressing-deliberate-findings):

- **Inline ignores** — the `foxguard: ignore` and `foxguard: ignore[rule-id]`
  comment directives suppress a finding on the next non-empty, non-comment
  code line (or on the current line when placed as a trailing comment).
  Use these for one-off deliberate patterns. Inline ignores apply to code
  scanning findings, not to `foxguard secrets`.
- **Repo-local baselines** — `scan.baseline` and `secrets.baseline` in
  `.foxguard.yml` (see the [Configuration](../README.md#configuration)
  section of the README) snapshot the existing set of findings so legacy
  issues stop blocking adoption. New findings still fail the run; previously
  accepted findings do not.

Prefer inline ignores for deliberate patterns (it keeps the justification
next to the code) and baselines for gradual rollout on legacy repositories.

---

*This document tracks [issue #9](https://github.com/PwnKit-Labs/foxguard/issues/9).
The labeled-corpus follow-up — pinned OSS repos, TP/FP labels per finding,
per-rule precision table in CI — is scoped separately in the same issue.*
