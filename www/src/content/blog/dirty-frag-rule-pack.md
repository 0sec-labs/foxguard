---
title: "Dirty Frag is a bug class — here's the foxguard rule pack"
date: "2026-05-08"
description: "We shipped C language support and three structural rules for the Dirty Frag class on the day the advisory landed. They're regex-shaped triage funnels, not proofs — but they catch the calibration sites and they're already in the npm release."
readTime: "5 min read"
---

## What dropped on Wednesday

On 2026-05-07, Hyunwoo Kim ([@v4bel](https://github.com/V4bel)) posted [Dirty Frag](https://www.openwall.com/lists/oss-security/2026/05/07/8) to oss-security. It's not a single CVE — it's a structural pattern. Userspace pins page-cache pages through `splice` / `vmsplice` with `MSG_SPLICE_PAGES`, the kernel parks those pages in an `sk_buff` fragment slot, and the receive-side AEAD or skcipher decrypts in place because nobody called `skb_cow_data` on the unsafe path. The decrypt writes plaintext back into the file's page cache. It's a sibling of Dirty Pipe (2022) and Copy Fail. The HN thread reached #4 with 560 points by the time we shipped this rule pack. The upstream ESP fix (`f4c50a4034e62ab75f1d5cdd191dd5f9c77fdff4`) extends the `skip_cow` gate with `!skb_has_shared_frag(skb)`. RxRPC's fix is still on lore as of today.

Our read: the splice-frag-then-in-place-crypto shape is going to recur in any subsystem that takes external pages and AEAD-decrypts them. Time to write rules.

## What we shipped

[PR #297](https://github.com/0sec-labs/foxguard/pull/297) merged on the day the advisory landed. It adds C as a first-class scanner language (`tree-sitter-c`, `Language::C`, `.c` / `.h` extensions, Semgrep-compat `languages: [c]`) plus three rules under `rules/kernel/dirty-frag-class/`. Six calibration fixtures (three vulnerable, three safe) ship with it; `cargo test --test kernel_dirty_frag` is 6/6.

```sh
$ npx foxguard@latest --no-builtins \
    --rules rules/kernel/dirty-frag-class/ \
    tests/fixtures/kernel/dirty-frag/
foxguard v0.8.0 · scanning...
  .../aead_no_cow_vulnerable.c · 1 issue
    █  CRITICAL  In-place AEAD decrypt on skb without a dominating cow/unshare gate (Dirty Frag class). …
    █   semgrep/kernel/dirty-frag/skb-inplace-aead-no-cow (CWE-787)  line 27:1
    █   aead_request_set_crypt(req, sg, sg, len, iv);

  .../scatterwalk_store_vulnerable.c · 1 issue
  .../skcipher_no_cow_vulnerable.c · 1 issue

  3 issues  6 files · 0.01s
```

Three positives, three clean negatives, one parser bump, and a rule directory you can point at any kernel tree.

## The structural pattern, in foxguard's language

Here's `skb-inplace-aead-no-cow.yaml` verbatim. It's the rule that flags the pre-patch ESP sites:

```yaml
rules:
  - id: kernel/dirty-frag/skb-inplace-aead-no-cow
    pattern-regex: '(?ms)^\s*aead_request_set_crypt\s*\([^}]*?crypto_aead_decrypt\s*\('
    pattern-not-regex: '(?s)\b(?:skb_cow_data|skb_copy|skb_unshare|skb_make_writable|pskb_expand_head)\s*\([^}]*?aead_request_set_crypt\s*\([^}]*?crypto_aead_decrypt\s*\('
    message: |
      In-place AEAD decrypt on skb without a dominating cow/unshare gate
      (Dirty Frag class). Verify skb_cow_data / skb_unshare / skb_make_writable /
      pskb_expand_head is reached on the unsafe path before
      aead_request_set_crypt(req, sg, sg, ...) + crypto_aead_decrypt(req).
      See oss-security 2026-05-07 advisory.
    severity: ERROR
    languages: [c]
    metadata:
      cwe: "CWE-787"
```

Two regexes, one logical AND-NOT. The positive looks for an `aead_request_set_crypt` call followed within the same C function body by `crypto_aead_decrypt` — `[^}]*?` is the cheap way to say "without leaving the brace block." The negative says "if a cow / unshare / make-writable / expand-head call appears earlier in the same span, suppress." That's the entire reasoning the rule does. The skcipher rule is the same shape with `skcipher_request_set_crypt` / `crypto_skcipher_decrypt`. The scatterwalk rule flags the four-byte STORE primitive (`scatterwalk_map_and_copy(..., out=1)` after `aead_request_set_crypt`) that appears in `crypto/authencesn.c::crypto_authenc_esn_decrypt`.

This is structural triage, not a theorem. It survives renames and minor refactors, it catches the five calibration sites named in the advisory, and it runs at tree-sitter speed against a full kernel checkout.

## What we deliberately don't claim

This rule pack does **not** detect Dirty Frag. It flags the structural pattern. The difference matters:

- **No backreferences.** Rust regex can't enforce `arg2 == arg3` on `aead_request_set_crypt(req, src, dst, …)`, so the rule fires on any `set_crypt` → `decrypt` sequence in a function. Legitimate non-in-place crypto (`src != dst`) trips the same regex.
- **The cow suppression is coarse.** `pattern-not-regex` filters when the cow regex overlaps the positive's span. That approximates "cow appears earlier in the same function" — it is not a dominating-call analysis. A `skb_cow_data` behind an unrelated branch still suppresses.
- **Macros are invisible.** Tree-sitter sees the post-preprocessor source. The kernel reaches the cow gate through `pskb_*` macros and inline helpers; macro-only paths get missed unless the direct name also appears.
- **No taint to the splice source.** The actual bug requires the page provenance to come from `splice` / `vmsplice` + `MSG_SPLICE_PAGES`. The rule fires on the in-place idiom regardless of where the SGL came from. Expect false positives on TLS, dm-crypt, fscrypt, and offload-crypto paths — they legitimately decrypt in place after a cow we can't model.

We also haven't run this against a real kernel checkout yet. The Tier 1 sibling list — `net/ipv4/ah4.c`, `net/ipv6/ah6.c`, `net/ipv4/ipcomp.c`, `net/ipv6/ipcomp6.c`, RxGK — is plausible-but-untested. If you point the pack at a tree and it lights up, that's a triage funnel, not a finding. Don't file CVEs off regex hits.

## The plan beyond regex

Path-sensitive cow-gate analysis lives in two issues we have open:

- [foxguard #295](https://github.com/0sec-labs/foxguard/issues/295) — Coccinelle integration. Coccinelle's `@@` metavariables can express `arg2 == arg3` directly, and SmPL has structural understanding of dominators. That's where the in-place property gets a real proof.
- [foxguard #296](https://github.com/0sec-labs/foxguard/issues/296) — CodeQL integration. CodeQL's data-flow library can carry SGL provenance from `MSG_SPLICE_PAGES` to the AEAD call, which is the actual bug-class invariant.

The variant-hunt orchestrator that walks a kernel tree, fans out to all three engines (foxguard regex, Coccinelle, CodeQL), and reconciles the hits is tracked internally. The foxguard rules are the cheap fast-pass — first sieve, not last word.

## Try it

```sh
git clone --depth=1 https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git
npx foxguard@latest --no-builtins \
  --rules rules/kernel/dirty-frag-class/ \
  linux/
```

The rule files live at [rules/kernel/dirty-frag-class/](https://github.com/0sec-labs/foxguard/tree/main/rules/kernel/dirty-frag-class) on `main`. Calibration tests at [tests/kernel_dirty_frag.rs](https://github.com/0sec-labs/foxguard/blob/main/tests/kernel_dirty_frag.rs) are 6/6 against the included fixtures. PR [#297](https://github.com/0sec-labs/foxguard/pull/297) has the full rationale, and the original Dirty Frag write-up is at [V4bel/dirtyfrag](https://github.com/V4bel/dirtyfrag/blob/master/assets/write-up.md) — credit where it's due.

If you find a sibling site with this pack, open an issue. If you find a false positive, also open an issue — the negative-regex list is best-effort and grows.

---

*foxguard is an open-source security scanner written in Rust. [GitHub](https://github.com/0sec-labs/foxguard) · [foxguard.dev](https://foxguard.dev).*
