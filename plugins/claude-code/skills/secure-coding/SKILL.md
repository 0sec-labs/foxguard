---
description: Apply foxguard's secure-coding patterns when writing or fixing security-sensitive code. Use proactively when handling user input, shelling out, building SQL, doing file I/O, fetching URLs, generating randomness, or touching crypto.
---

Use this guidance when writing or fixing code that touches any of these surfaces. Match the language patterns to what foxguard's rules look for so the auto-scan stays clean.

## Command execution

- Never pass concatenated strings to a shell. Use argument lists.
  - Python: `subprocess.run(["git", "log", branch], check=True)` — never `subprocess.run(f"git log {branch}", shell=True)`.
  - Node: `execFile("git", ["log", branch])` — never `exec(`git log ${branch}`)`.
  - Go: `exec.Command("git", "log", branch)` — never `exec.Command("sh", "-c", "git log "+branch)`.
- If a shell is genuinely required, validate the input against a strict allowlist regex first.

## SQL

- Use parameterized queries everywhere. `cursor.execute("SELECT * FROM u WHERE id = ?", (uid,))` — not f-strings or `%`.
- ORMs are fine; raw `query.format(...)` / `+` concat is not.

## Path traversal

- Resolve and bound paths: `Path(root).resolve() / Path(name).name` — strip directory components from untrusted names.
- Reject inputs that contain `..`, absolute paths, or null bytes before joining.

## SSRF

- For outbound HTTP from user-supplied URLs: parse the URL, resolve the host, and reject private/loopback/link-local ranges (`10.0.0.0/8`, `127.0.0.0/8`, `169.254.0.0/16`, `172.16.0.0/12`, `192.168.0.0/16`, `::1`, `fc00::/7`, `fe80::/10`) and metadata endpoints (`169.254.169.254`).
- Prefer an allowlist over a denylist when the destinations are known.

## Secrets

- Read from env / secrets manager, never from string literals. `os.getenv("API_TOKEN")` — not `API_TOKEN = "sk-..."`.
- Even in tests, prefer fixtures from env or a vault. High-entropy strings in code will be flagged.
- Never log secrets. Redact before logging.

## Randomness

- Security-sensitive: `secrets.token_urlsafe`, `crypto.randomBytes`, `OsRng`, `crypto/rand`. Never `random.random()`, `Math.random()`, `rand()`, `math/rand`.
- Non-security (jitter, sampling): the fast PRNGs are fine.

## Crypto

- New code: AES-GCM or ChaCha20-Poly1305 for symmetric; Ed25519 for signatures; X25519 for key agreement (until PQ rollout). Never DES, 3DES, RC4, MD5, SHA-1.
- Asymmetric crypto in long-lived security paths: prefer hybrid suites (X25519+ML-KEM) where the toolchain supports it. Use `/foxguard:pq-audit` to find legacy usage.
- Password hashing: argon2id or bcrypt. Never plain SHA-2 or unsalted hashes.

## Deserialization

- Never `pickle.load`, `yaml.load` (use `safe_load`), `Marshal.load`, or `unserialize` on untrusted input.
- For JSON, deserialize into a typed schema (pydantic, zod, serde) — don't trust the shape.

When you finish a fix, the PostToolUse hook will re-scan the file and confirm it's clean. If a finding persists, read the rule's description carefully — the remediation is usually one of the patterns above.
