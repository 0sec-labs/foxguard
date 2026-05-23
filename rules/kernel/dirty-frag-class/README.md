# Linux kernel Dirty Frag rule pack

## Bug class

Dirty Frag is a memory-corruption class in the Linux kernel's SKB fragment handling, disclosed by Hyunwoo Kim (@v4bel) on oss-security on 2026-05-07. The root cause: in-place AEAD / skcipher decrypt over an `skb` whose pages were pinned by `MSG_SPLICE_PAGES`. The destination scatterlist aliases caller-pinned memory, so a STORE — decrypt write-back, or `scatterwalk_map_and_copy(..., out=1)` / `memcpy_to_sglist` — lands in shared frag pages regardless of AEAD auth result. The shape is structurally similar to the earlier Wnd-style shared-frag class. Upstream fixed the canonical ESP site in commit [`f4c50a4034e62ab75f1d5cdd191dd5f9c77fdff4`](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f4c50a4034e62ab75f1d5cdd191dd5f9c77fdff4) by extending `skip_cow` with `!skb_has_shared_frag(skb)`. Primary advisory: <https://www.openwall.com/lists/oss-security/2026/05/07/8> (also embedded in each rule's `metadata.references`).

## Rules in this pack

| File | Engine | Severity | Summary |
|------|--------|----------|---------|
| [`skb-inplace-aead-no-cow.yaml`](skb-inplace-aead-no-cow.yaml) | semgrep regex (C) | ERROR | `aead_request_set_crypt(req, sg, sg, ...)` + `crypto_aead_decrypt(req)` in the same function with no dominating `skb_cow_data` / `skb_unshare` / `skb_make_writable` / `pskb_expand_head`. Excludes `crypto/**`. Calibrated against pre-patch `esp_input` / `esp6_input`. |
| [`skb-inplace-skcipher-no-cow.yaml`](skb-inplace-skcipher-no-cow.yaml) | semgrep regex (C) | ERROR | Same shape for `skcipher_request_set_crypt` + `crypto_skcipher_decrypt`. Excludes `crypto/**`. Calibrated against `net/rxrpc/rxkad.c::rxkad_verify_packet_1`. |
| [`scatterwalk-store-on-shared-sgl.yaml`](scatterwalk-store-on-shared-sgl.yaml) | semgrep regex (C) | ERROR | `aead_request_set_crypt` followed by `scatterwalk_map_and_copy(..., out=1)` or `memcpy_to_sglist(...)` — the secondary STORE primitive used by Copy Fail / authenc clones. Excludes `crypto/**`. |
| [`scatterwalk-store-on-shared-sgl-authencesn.yaml`](scatterwalk-store-on-shared-sgl-authencesn.yaml) | semgrep regex (C) | ERROR | Narrow exception that re-enables the STORE rule against `crypto/authencesn*.c` — the one confirmed advisory site inside `crypto/**`. |
| [`rxrpc-verify-response-dispatch.yaml`](rxrpc-verify-response-dispatch.yaml) | semgrep regex (C) | WARNING | Triage funnel for `net/rxrpc/conn_event.c`: flags `RXRPC_PACKET_TYPE_RESPONSE` dispatch into `conn->security->verify_response(conn, skb)`. Not a write primitive — the actual STORE is in the backend (rxkad), flagged by the skcipher rule. |
| [`esp-shared-frag-decrypt-guard-codeql.yaml`](esp-shared-frag-decrypt-guard-codeql.yaml) | codeql | ERROR | Companion `engine: codeql` rule that calibrates against the upstream ESP fix; points at [`queries/kernel/dirty-frag-esp-shared-frag-decrypt-guard.ql`](queries/kernel/dirty-frag-esp-shared-frag-decrypt-guard.ql). |

All semgrep rules here are **syntactic / structural** — they prove neither SGL aliasing nor cow-gate unreachability. Path-sensitive confirmation (CodeQL or Coccinelle) is required for definitive flagging; each rule's header comment documents its recall and precision caveats.

## How to run

```sh
foxguard --rules rules/kernel/dirty-frag-class/ ./linux/
```

The loader walks the directory recursively and registers every `*.yaml` / `*.yml` it finds. Built-in Rust rules still run; pass `--no-builtins` to scope a run to this pack only.

## Companion CodeQL queries

`queries/` is a CodeQL pack — [`qlpack.yml`](queries/qlpack.yml) declares `foxguard/kernel-dirty-frag-queries` depending on `codeql/cpp-all` (upstream [CodeQL pack format](https://docs.github.com/en/code-security/codeql-cli/codeql-cli-reference/about-ql-packs)). The `engine: codeql` YAML above references the `.ql` files by relative path, but queries only execute when a built CodeQL database is supplied via `--codeql-db` (or `FOXGUARD_CODEQL_DB`). Without one, the rule is loaded and counted, then skipped with a notice — see `scan_with_notices` in [`src/engine/codeql.rs`](../../../src/engine/codeql.rs). The queries directory is static reference material in foxguard's default mode.

## Tests

[`tests/kernel_dirty_frag.rs`](../../../tests/kernel_dirty_frag.rs) is the calibration suite — 19 tests covering positive fixtures (must flag), negative fixtures (must not flag — dominating cow gate, `out=0`, non-aliased SGL, encrypt-side, template wrappers), and sibling sites (AH, ipcomp, MACsec, TLS-cow, RxRPC dispatch, authencesn `memcpy_to_sglist`). Each test loads a single YAML via `parse_semgrep_file`, parses the matching fixture under `tests/fixtures/kernel/dirty-frag/` with `tree-sitter-c`, and asserts the finding count. Use it as the template when adding fixtures for a new shape.
