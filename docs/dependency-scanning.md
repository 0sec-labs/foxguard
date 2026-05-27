# Dependency Vulnerability Scanning

foxguard can scan supported dependency lockfiles against OSV advisories.

```sh
foxguard sca .
foxguard --sca . --format json
foxguard sca . --sca-offline --sca-db ./osv-advisories.json
foxguard sca . --sca-cache .foxguard/osv-cache.json
```

Supported manifests:

- `Cargo.lock` (`crates.io`)
- `package-lock.json` (`npm`)
- `pnpm-lock.yaml` (`npm`)
- `requirements.txt` (`PyPI`, exact `==` pins only)
- `poetry.lock` (`PyPI`)
- `Pipfile.lock` (`PyPI`)

`foxguard sca` runs dependency vulnerability scanning only. `foxguard --sca`
adds dependency vulnerability findings to a normal source scan, so existing
manifest rules, including post-quantum dependency checks, continue to run.

## OSV Lookup

Online mode sends package ecosystem, normalized package name, installed
version, and package URL to OSV's batch query API. Findings include the OSV
vulnerability id, dependency name, installed version, fixed version when OSV
reports one, advisory severity when present, package URL, ecosystem, source
database, and dependency path.

## Offline And Cache

`--sca-offline` never queries the network. Use it with one of:

- `--sca-db <path>`: local OSV JSON, JSONL, or a directory containing those
  files. Local matching supports exact `affected[].versions` entries and
  simple introduced/fixed event ranges.
- `--sca-cache <path>`: a foxguard OSV cache previously written by an online
  run.

Without `--sca-db` or an existing `--sca-cache`, offline mode emits a notice
and skips OSV vulnerability lookup. The normal scanner and PQ manifest rules
still run without network access.

In online mode, `--sca-cache <path>` writes fresh OSV results. If the network
query fails and the cache exists, foxguard falls back to the cache and emits a
notice.
