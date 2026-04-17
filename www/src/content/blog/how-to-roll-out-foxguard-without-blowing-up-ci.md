---
title: "How to roll out foxguard without blowing up CI"
date: "2026-04-07"
description: "The fastest way to get developers to hate a security tool is to drop it into CI with no rollout plan. Here is the boring rollout path that actually works."
readTime: "5 min read"
---

The fastest way to get developers to hate a security tool is simple:

add it to CI,
fail builds immediately,
and dump a pile of old findings on every open pull request.

That is not a security win. It is just a trust failure with extra steps.

If you want foxguard to stick, the rollout needs to be boring.

## The wrong rollout

This is the path that looks strict and serious but usually backfires:

1. add the scanner to CI
2. run it on the whole repo
3. fail on everything it finds
4. tell the team to clean it up over time

What actually happens:

- developers stop trusting the signal
- new and old findings get mixed together
- pull requests inherit unrelated noise
- the scanner becomes “that thing security added”

You do not want that.

## The rollout that works

foxguard is easiest to adopt when you split the problem into phases:

1. make local feedback fast
2. separate old findings from new ones
3. tighten CI only after the team trusts the tool

That is the entire game.

## Phase 1: put it in the local loop first

Start with the smallest useful path:

```sh
npx foxguard --changed .
```

That keeps the feedback scoped to what a developer is already touching.

Then install the local hook:

```sh
foxguard init
```

That gives the repo a starter config and a pre-commit path without making CI the first place people see the tool.

The goal in this phase is not enforcement. It is behavior.

If developers see fast, relevant findings on their own changes, they learn the signal before the tool gets any power.

## Phase 2: baseline the old noise

If the repo already has problems, treat that as history, not as a reason to block every future change.

Generate a baseline once:

```sh
foxguard baseline --output .foxguard/baseline.json .
```

Then apply it in normal scans:

```sh
foxguard --baseline .foxguard/baseline.json .
```

That changes the conversation from:

> “why is this tool yelling about 200 things I didn’t touch?”

to:

> “why did this PR introduce a new security issue?”

That distinction is the difference between adoption and rejection.

## Phase 3: make CI narrow before you make it strict

When you add foxguard to CI, start with changed files or baseline-backed scans.

For example:

```sh
npx foxguard@latest --baseline .foxguard/baseline.json .
```

or, in workflows built around modified files, use the changed-file mode locally and keep full scans for scheduled or pre-release checks.

The important thing is that CI should initially answer:

> did this change make the security posture worse?

not:

> does this repository contain every historical security smell we have ever tolerated?

Those are different policies.

## When to tighten the gate

You can move from advisory to blocking once three things are true:

- developers have seen the tool locally
- the baseline is in place
- the finding quality is good enough that a failed build feels justified

If one of those is missing, it is probably too early to make the gate hard.

Strictness is not what makes a rollout credible.

Signal quality is.

## Where the Semgrep/OpenGrep bridge fits

If a team already has Semgrep or OpenGrep YAML rules, do not make migration all-or-nothing.

The practical path is:

- start with foxguard built-ins
- keep the local loop fast
- bring over only the external YAML rules that materially help

That gives you a bridge without dragging a whole heavyweight policy surface into every save.

The point of the bridge is adoption, not mimicry.

## A good default sequence

If I were rolling foxguard into a real codebase, I would do it in this order:

1. `foxguard --changed .` locally
2. `foxguard init`
3. generate a baseline
4. add baseline-backed CI
5. only then decide what should fail the build

That sequence keeps the feedback loop sane and makes the tool feel like it is helping rather than policing.

## The point

Security tooling fails adoption when it shows up as a wall of debt.

It succeeds when it helps developers catch the new mistake while they still remember writing it.

That is why the rollout matters as much as the engine.

---

*foxguard is an open-source security scanner written in Rust. 170+ built-in rules, 10 languages, sub-second local scans, and a focused Semgrep/OpenGrep-compatible YAML bridge. [Try it](https://github.com/PwnKit-Labs/foxguard): `npx foxguard .`*
