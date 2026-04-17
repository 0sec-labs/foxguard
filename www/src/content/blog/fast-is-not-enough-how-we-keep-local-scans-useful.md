---
title: "Fast is not enough: how we keep local scans useful"
date: "2026-04-06"
description: "A local security scanner does not win just by being fast. It wins when developers trust the findings enough to keep it enabled."
readTime: "5 min read"
---

A local security scanner does not win just by being fast.

Fast gets you into the loop.

**Signal quality is what lets you stay there.**

If a scanner is instant but noisy, developers learn the same lesson they learn with every other noisy tool:

ignore it,
work around it,
or turn it off.

That means “fast” is necessary, but it is not enough.

## The real local-standard

For CI tools, a little friction is acceptable.

For local tools, the standard is harsher:

- fast enough to run without thinking
- precise enough that a finding feels worth reading
- scoped enough that developers know what to do next

If any one of those breaks, the tool loses the local slot.

That is why local security scanning is harder than it looks.

## The easy way to get it wrong

There are a few common failure modes:

### 1. Match the dangerous primitive, not the dangerous use

This is how you end up flagging every use of `eval`, every crypto call, or every dynamic response helper without enough surrounding context.

That makes the scanner feel literal instead of useful.

### 2. Ignore framework semantics

A local scanner that does not understand how developers actually use Express, Django, Rails, Spring, or Gin turns into a generic AST pattern matcher.

Generic pattern matching is helpful sometimes, but it is not enough to earn trust in day-to-day code.

### 3. Mix old debt with new mistakes

If every scan drags in historical repo noise, developers stop associating findings with the change they just made.

The feedback becomes less actionable the moment it stops being local to the change.

## What foxguard tries to do instead

foxguard is built around a few boring but important constraints.

### Fast is table stakes

If the scan is not sub-second on the kinds of repos people actually touch, nothing else matters. It goes back into CI.

That is the starting point, not the finish line.

### Built-ins first

The default product is not “bring every external rule engine into the editor.”

The default product is:

- built-in checks
- framework-aware logic
- focused local feedback

That lets the rules be shaped around local usefulness instead of theoretical completeness.

### Compatibility is a bridge, not an identity

foxguard supports a focused Semgrep/OpenGrep-compatible YAML subset because teams already have rule investments.

But the bridge should not dominate the product.

The moment compatibility becomes the whole identity, local performance and clarity start losing ground to surface-area creep.

## Precision work is product work

One of the easiest traps in security tooling is treating false positive reduction as maintenance.

It is not maintenance.

It is core product work.

If you tighten a rule so it:

- understands real SQL structure instead of any string concatenation
- skips known Ruby metaprogramming patterns that are normal
- distinguishes framework defaults from arbitrary dynamic code

that is not polish.

That is adoption work.

The scanner becomes more believable every time a developer thinks:

> yeah, that one is fair

That moment matters more than adding ten mediocre rules.

## Why changed-file mode matters

One of the cleanest ways to preserve usefulness is to keep the scope tight.

That is why changed-file scans matter so much locally.

When the scanner is looking at the code you just touched, the finding feels connected to your current context.

That makes it easier to evaluate, easier to fix, and harder to dismiss as random repo archaeology.

Speed helps with that.

Scope helps just as much.

## What a good local finding feels like

A good local security finding should feel like:

- I see why this matched
- I understand the risk
- I know what code to change
- fixing it now is cheaper than dealing with it later

If the finding creates confusion before it creates action, it is not done yet.

That is true even if the rule is technically correct.

## The trade-off we are willing to make

There is always pressure to promise more:

- more rule formats
- more compatibility
- more language surface
- more “full engine” parity

Some of that growth is real progress.

Some of it just makes the local loop worse.

The trade-off foxguard should keep making is:

prefer a tighter, more explicit, more useful local tool over a broader but blurrier one.

That will look less impressive in a feature matrix.

It will work better in a developer workflow.

## The point

The local slot is earned, not claimed.

Fast gets you a chance.

Useful keeps you installed.

That is the bar.

---

*foxguard is an open-source security scanner written in Rust. 170+ built-in rules, 10 languages, sub-second local scans, and a focused Semgrep/OpenGrep-compatible YAML bridge. [Try it](https://github.com/PwnKit-Labs/foxguard): `npx foxguard .`*
