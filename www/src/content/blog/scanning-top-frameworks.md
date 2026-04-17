---
title: "I scanned Express, Flask, Rails, Gin, and Laravel for security issues"
date: "2026-04-04"
description: "What happens when you point a fast security scanner at the most popular web frameworks? 369 findings across 799 files in under a second."
readTime: "5 min read"
---

What happens when you point a security scanner at the source code of the frameworks everyone uses?

I ran [foxguard](https://github.com/PwnKit-Labs/foxguard) against the latest HEAD of Express, Flask, Gin, Laravel, Rails, Spring Petclinic, and a Next.js example. All seven repos scanned in **0.86 seconds total**.

## Results

| Repository | Files | Time | Findings |
|---|---|---|---|
| Express.js | 141 | 0.15s | 60 |
| Flask | 83 | 0.12s | 40 |
| Gin | 99 | 0.08s | 26 |
| Laravel | 29 | 0.01s | 1 |
| Rails (actionpack) | 356 | 0.30s | 173 |
| Spring Petclinic | 47 | 0.02s | 4 |
| Next.js (with-supabase) | 44 | 0.03s | 0 |

Not every finding is a vulnerability. Framework source code is *supposed* to handle dangerous primitives — that's what frameworks do. But several patterns are worth looking at.

## Express: hardcoded secrets in examples

Express ships example applications with hardcoded session secrets:

```js
// examples/session/index.js
secret: 'keyboard cat'

// examples/cookie-sessions/index.js
app.use(cookieSession({ secret: 'manny is cool' }));
```

These aren't vulnerabilities in Express itself. But developers copy-paste examples as starting points. "keyboard cat" has probably made it into more production apps than anyone wants to admit.

The downloads example also has a path traversal vector — `req.params.file` comes from a wildcard URL route and gets passed to `res.download()` with a `root` option, but the wildcard accepts `..` segments.

## Flask: exec() and SHA-1

Flask's `Config.from_pyfile()` uses `exec()` to load Python config files:

```python
# src/flask/config.py
exec(compile(config_file.read(), filename, "exec"), d.__dict__)
```

This is by design — Python config files are Python code. But if an attacker can write to the config path, this is code execution. It's a known trade-off, not a bug.

More interesting: Flask uses SHA-1 in its session cookie signing fallback:

```python
# src/flask/sessions.py
return hashlib.sha1(string)
```

SHA-1 is cryptographically broken. FIPS-compliant environments will reject this. It's in the fallback path, not the default, but it's still there.

## Rails: Marshal.load and metaprogramming

Rails actionpack produced the most findings (173), which reflects Ruby's metaprogramming-heavy style.

The genuinely security-relevant finding: `Marshal.load` for cookie deserialization. `Marshal.load` can instantiate arbitrary Ruby objects, enabling remote code execution if cookie data is tampered with. Rails mitigates this with signed/encrypted cookies, but the underlying primitive is dangerous by nature.

Rails also uses `eval` and `instance_eval` extensively for route generation and dynamic method creation. foxguard intentionally skips `class_eval` and `module_eval` — those are standard Ruby patterns, not security issues.

## Gin: missing trusted proxies

Gin's convenience package (`ginS`) creates a default engine without calling `SetTrustedProxies()`:

```go
// ginS/gins.go
return gin.Default()
```

Any application using `ginS` trusts all proxies by default, allowing IP spoofing via `X-Forwarded-For`. Most Gin users configure this themselves, but the default is permissive.

## The clean ones

**Next.js with-supabase**: zero findings. Modern server components with Supabase auth helpers have no obvious anti-patterns.

**Spring Petclinic**: 4 findings, all in test code (RestTemplate with dynamic URLs). The production code is clean — Spring's defaults are good.

**Laravel**: 1 finding — a `require` with a variable path in the maintenance mode entry point. Low risk since the base path is hardcoded.

## What I learned

**Example code is a real attack surface.** Developers copy examples. "keyboard cat" in Express examples has probably shipped to production thousands of times.

**Frameworks use dangerous primitives on purpose.** Flask's `exec()`, Rails' `Marshal.load`, and `eval` are intentional design choices. The security question isn't whether the primitive exists, but whether the surrounding assumptions hold.

**Modern frameworks have better defaults.** Next.js and Spring Petclinic came back clean. Newer frameworks learned from the mistakes of older ones.

**Fast scanning changes behavior.** All seven repos scanned in under a second. When security checks are this fast, you actually run them. That's the whole point.

---

*foxguard is an open-source security scanner written in Rust. 170+ built-in rules, 10 languages, sub-second scans. [Try it](https://github.com/PwnKit-Labs/foxguard): `npx foxguard .`*
