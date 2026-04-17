---
title: "Use Semgrep in CI. Use foxguard on save."
date: "2026-04-08"
description: "Most teams do not have a security-tooling problem. They have a loop problem. Heavy scanners belong in CI. Local scanners need to be fast enough to stay on."
readTime: "4 min read"
---

Most teams do not have a security-tooling problem.

They have a **loop problem**.

The pattern usually looks like this:

- security scanning exists
- it runs in CI
- it is respected in theory
- developers almost never run it locally

That is not because engineers are lazy. It is because a 10-second, 20-second, or 30-second scan does not belong in the same loop as editing, saving, and committing.

## The wrong expectation

Too many security tools are asked to do two incompatible jobs at once:

1. be the broad, policy-heavy scanner for CI and compliance
2. also be the instant feedback tool developers keep running locally

Those are different products.

CI scanners can afford to be heavier. They can download rules, do deeper analysis, and gate merges.

Local scanners need a different property above all else:

**they need to be fast enough that nobody thinks about them.**

If running the tool changes the rhythm of editing code, the tool loses the local slot and gets pushed back into CI.

## The practical split

The workflow that makes the most sense is:

- **Semgrep or OpenGrep in CI** when you want the broadest external rule ecosystem
- **foxguard locally** for built-in framework-aware checks, changed-file scans, secrets checks, and fast pre-commit feedback

That split is more honest than pretending one tool has to be everything.

foxguard is deliberately built around that local slot:

- single Rust binary
- no JVM startup
- no Python runtime
- no network calls
- built-in rules first
- optional Semgrep/OpenGrep-compatible YAML subset as a bridge

The bridge matters because migration usually fails when it is all-or-nothing.

Teams already have existing YAML rules. They should be able to keep the useful part of that investment without dragging the full CI toolchain into every save.

## What local scanning should catch

The local tool does not need to be the final authority on every security decision.

It needs to catch the mistakes developers actually want to fix while context is still fresh:

- SQL injection
- unsafe command execution
- reflected response writes
- weak crypto defaults
- session and JWT misconfiguration
- hardcoded secrets
- framework-specific mistakes that show up in real repos

That is enough to change behavior.

Once developers trust that the tool is fast and useful, they keep it on. That is the hard part.

## Why "full compatibility" is the wrong goal

It sounds attractive to promise full Semgrep compatibility for local use.

In practice, that promise often creates the wrong incentives:

- the engine grows
- the scope grows
- the startup path gets heavier
- the compatibility story gets harder to explain
- local performance becomes negotiable

For the local slot, a narrower and explicit compatibility surface is better than a vague “supports everything” claim.

The right question is not:

> can this tool theoretically run every rule?

The right question is:

> will developers actually run it before they push?

## The adoption path that works

If you are trying to improve local security feedback, the rollout should be boring:

1. turn on built-in local scanning
2. add changed-file scans and pre-commit hooks
3. baseline existing noise
4. bring over only the external YAML rules that materially help
5. keep the heavy policy checks in CI

That gives you a cleaner split:

- local loop for speed and behavior
- CI for depth and enforcement

Trying to force one tool to dominate both layers usually just means the local layer loses.

## The point

Developers do not need more scanners they are supposed to run.

They need one that survives the edit loop.

That is the whole bet behind foxguard.

---

*foxguard is an open-source security scanner written in Rust. 170+ built-in rules, 10 languages, sub-second local scans, and a focused Semgrep/OpenGrep-compatible YAML bridge. [Try it](https://github.com/PwnKit-Labs/foxguard): `npx foxguard .`*
