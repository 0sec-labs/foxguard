---
title: "The CNSA 2.0 deadlines we got wrong (and what we did about it)"
date: "2026-05-08"
description: "Compliance tooling that prints dates without citations is just a different kind of vibes. Here is how we noticed our PQ scanner was doing exactly that, and how we fixed it."
readTime: "6 min read"
---

Compliance tooling that prints dates without citations is just a different kind of vibes. Here is how we noticed our PQ scanner was doing exactly that, and how we fixed it.

The [v0.8 launch post](/blog/foxguard-0-8-0-pq-crypto-audit) mentioned, in five honest lines, that the first pass at CNSA 2.0 annotations had unsourced dates and we rewrote the file. This post is the longer version of that paragraph, because the failure mode is more interesting than the fix and shows up across compliance tooling more broadly.

## What was actually wrong

The first attempt at CNSA 2.0 annotations (PR [#231](https://github.com/PwnKit-Labs/foxguard/pull/231)) did the obvious thing. There were a few deadline year strings in a module, and a function that decided which deadline applied to a finding by looking at the rule ID:

```rust
// roughly what the first pass looked like
fn deadline_for(rule_id: &str) -> Option<&'static str> {
    if rule_id.contains("signing") {
        Some("2030")
    } else if rule_id.contains("tls") || rule_id.contains("crypto") {
        Some("2033")
    } else {
        None
    }
}
```

There were two real problems with this, and a third quieter one.

**The dates were not sourced.** The years were correct in the sense that they came out of skimming a CNSA 2.0 explainer blog and a couple of vendor reproductions of the NSA timeline table. They were not pinned to a primary source, and a reader who wanted to audit the claim had no place to start. "Where does the 2033 come from?" had no answer in the source tree.

**The mapping was a substring heuristic.** A rule named `js/pq-vulnerable-crypto` matched the `crypto` arm and got annotated. Rename it to `js/pq-deprecated-primitives` for unrelated reasons and it silently stops being annotated. Add a rule named `js/no-weak-crypto` that has nothing to do with PQ and it gets annotated anyway. Both directions of the bug are silent.

**The tests didn't notice.** They asserted the function returned the expected year for a known input. They didn't assert that every PQ rule in the registry was covered, or that non-PQ rules weren't false-positively tagged.

If you are building a compliance scanner, this is the worst combination: dates the user can't verify, applied through a heuristic that drifts as the rule set evolves.

## How the review caught it

A code-review pass on the PR pushed back on the dates and the heuristic at the same time. The wording was something like "where does this date come from? and what stops a typo from silently dropping the annotation?" — both reasonable questions that didn't have answers. The PR was sent back. PR [#240](https://github.com/PwnKit-Labs/foxguard/pull/240) landed the data-shape change (a `cnsa2_deadline` field on findings). PR [#245](https://github.com/PwnKit-Labs/foxguard/pull/245) landed the rewrite of the compliance module that this post is about.

The honest framing: the first pass shipped fast because the dates *felt* right, and felt-right is the easiest thing to ship. The second pass took longer because every constant had to be tied to a primary source before it could be merged.

## How we fixed it

Three structural changes, all visible in [`src/compliance.rs`](https://github.com/PwnKit-Labs/foxguard/blob/main/src/compliance.rs).

**Every deadline constant carries an inline NSA citation.** The module has a `deadlines` submodule and each constant is a doc-commented `pub const` that quotes the language from the source document and gives the document's identifier:

```rust
/// Software & firmware signing — exclusive use of CNSA 2.0 by end of 2030.
///
/// Source: NSA CNSA 2.0 FAQ (Dec 2024, v2.1), transition-timeline table:
/// *"Software and firmware signing: Support and prefer by 2025;
/// exclusive use by 2030."* This is the earliest per-class deadline in
/// CNSA 2.0 because hash-based signatures (LMS/XMSS) and ML-DSA are
/// already standardized and fieldable.
pub const SOFTWARE_FIRMWARE_SIGNING: &str = "2030";

/// Web browsers / servers / cloud services — exclusive use by end of 2033.
///
/// Source: NSA CNSA 2.0 FAQ (Dec 2024, v2.1), transition-timeline table:
/// *"Cloud services and web browsers/servers: Support and prefer by
/// 2025; exclusive use by 2033."*
pub const WEB_AND_CLOUD: &str = "2033";
```

The two primary sources are cross-referenced at the top of the file: the [NSA CNSA 2.0 FAQ v2.1 (Dec 2024)](https://media.defense.gov/2022/Sep/07/2003071836/-1/-1/0/CSI_CNSA_2.0_FAQ_.PDF) for the per-class transition-timeline table, and the [NSA CSA *CNSA 2.0 Algorithms* publication (May 2025, v1.0)](https://media.defense.gov/2025/May/30/2003728741/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS.PDF) for the algorithm-set definitions. The 2035 NSS-wide outer limit comes from [White House NSM-10 (May 2022)](https://www.whitehouse.gov/briefing-room/statements-releases/2022/05/04/national-security-memorandum-on-promoting-united-states-leadership-in-quantum-computing-while-mitigating-risks-to-vulnerable-cryptographic-systems/). If you want to audit a date the tool prints, the chain is two clicks long.

**The module-level doc comment forbids substring matching on rule IDs**, by name and with the reasoning, so a future contributor who is tempted to "just check if the ID contains crypto" sees the prior failure mode written down. Excerpt:

```rust
//! ## Design notes (addresses PR #231 review)
//!
//! - **No substring matching on rule IDs.** The deadline is a property of the
//!   rule itself (declared in `impl_rule!`), so this module simply consults
//!   the registry. Renaming or adding a rule cannot silently drop its
//!   annotation.
//! - **No hardcoded dates without citations.** Every year used below is tied
//!   to a specific NSA document URL and quoted language.
```

**The deadline is declarative rule metadata.** Each rule in the registry declares its CNSA 2.0 class via a `cnsa2_deadline` arm on the `impl_rule!` macro. The compliance module just consults the registry:

```rust
pub fn annotate_cnsa2_deadlines(findings: &mut [Finding], registry: &RuleRegistry) {
    let map: HashMap<&str, &'static str> = registry
        .all_rules()
        .iter()
        .filter_map(|r| r.cnsa2_deadline().map(|d| (r.id(), d)))
        .collect();

    for f in findings.iter_mut() {
        if let Some(deadline) = map.get(f.rule_id.as_str()) {
            f.cnsa2_deadline = Some((*deadline).to_string());
        }
    }
}
```

There is no string-matching path. Renaming a rule cannot accidentally drop its annotation, because the deadline travels with the rule definition, not with the ID. A guardrail test walks the registry and asserts that every rule with a declared deadline uses one of the canonical constants, which catches a fat-fingered date string before it ships.

The fix-by-audience split that PR [#256](https://github.com/PwnKit-Labs/foxguard/pull/256) landed lives at the rule-remediation layer, separately. ML-KEM-1024 / ML-DSA-87 for NSS, ML-KEM-768 / ML-DSA-65 for commercial — covered in that PR's description, not this file. The point is that the compliance module is the canonical source for the *date*; the rule's remediation text is the canonical source for the *parameter sets*. Each artifact is responsible for one thing.

## Why this matters generally

A few patterns showed up in the review process that aren't specific to foxguard.

**For a compliance scanner, the dates are the product.** A taint engine that flags one false-positive SQL injection has wasted a developer's afternoon. A compliance tool that prints `migrate before end of 2030` for the wrong rule has either undermined a real migration plan or fabricated a deadline that ends up in a customer slide. Getting dates wrong silently is worse than throwing an error, because nobody goes back and checks. "Why does this say 2030?" should have a one-line answer that points at a single file.

**Auditing a tool's claims should be a pointer, not a project.** The thing the rewrite optimised for was: a reader who wants to verify any specific date can do it by reading [`src/compliance.rs`](https://github.com/PwnKit-Labs/foxguard/blob/main/src/compliance.rs) and clicking through to the cited PDF. They don't have to grep the codebase, read other modules, or trust a derived heuristic. One file, every constant cited, primary sources linked.

**Rule-ID substring matching is a recurring class of bug.** It shows up in SAST tooling, in compliance scanners, in CI lints — anywhere there's a rule registry and a property that wants to be derived from the rule. Each instance starts the same way: the rule IDs encode the right semantics today, the substring check is two lines, and shipping is faster than building the metadata path. Each instance fails the same way: someone renames a rule, or adds a sibling rule whose ID contains the same word, and the derived property silently drifts. The pattern is worth naming because it tends to be re-invented rather than recognized. Declarative metadata on the rule itself — not a heuristic on the ID — is the only structurally safe option.

## What's still hard

Honest list of things the rewrite didn't solve:

**NSA's transition timelines are themselves nuanced.** The FAQ table splits NSS by equipment class — software/firmware signing, traditional networking equipment, web browsers and servers, cloud services, operating systems, niche/legacy/custom — and each class has its own "support and prefer" milestone and its own "exclusive use" deadline. We surface only the exclusive-use deadline because that is the one users care about, but a rule that touches both networking equipment (2030) and a web service (2033) has a real ambiguity that a single annotation can't capture. Today we map by rule, not by file context, and that's a known simplification.

**The ML-KEM-1024 / ML-DSA-87 vs ML-KEM-768 / ML-DSA-65 split is real and matters.** NSS deployments need the highest parameter sets per CNSA 2.0; general commercial use defaults to NIST category III. Plenty of post-quantum tooling collapses these into one recommendation and ends up wrong for one audience. foxguard's remediation text now splits cleanly per [#256](https://github.com/PwnKit-Labs/foxguard/pull/256), but the split is a permanent piece of complexity, not a one-time fix.

**Dependency-level PQ scanning needs more lockfiles.** v0.8 walks `Cargo.lock` and `requirements.txt`. `Pipfile.lock`, `poetry.lock`, `uv.lock`, `package-lock.json`, and `pnpm-lock.yaml` ([#262](https://github.com/PwnKit-Labs/foxguard/issues/262)) would close most of the modern Python and Node gap. CNSA 2.0 deadlines apply just as much to a transitive dependency as to a direct call, and right now the answer for a Node project is partial.

## Closer

The deal is simple: every CNSA 2.0 date the tool prints is grounded in [`src/compliance.rs`](https://github.com/PwnKit-Labs/foxguard/blob/main/src/compliance.rs), and that file cites primary NSA sources for every constant. If you find an error — a misquoted date, a class assigned to the wrong deadline, a citation that doesn't say what we say it says — [open an issue](https://github.com/PwnKit-Labs/foxguard/issues/new). The audit surface is one file by design.

For the broader v0.8 picture, the [launch post](/blog/foxguard-0-8-0-pq-crypto-audit) covers the PQ rules, the CycloneDX 1.6 CBOM output, and the dependency walking. This post was just about the part we got wrong first.

---

*foxguard is an open-source security scanner written in Rust. [GitHub](https://github.com/PwnKit-Labs/foxguard) · [foxguard.dev](https://foxguard.dev).*
