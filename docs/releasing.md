# Releasing foxguard

## Normal flow

1. Write release notes at `docs/releases/vX.Y.Z.md` for the version to publish.

2. Start from a clean working tree on a **dedicated release branch**; the new
   release-note file is the only allowed uncommitted change.

3. Run:

   ```sh
   ./scripts/release.sh X.Y.Z
   ```

   That script:
   - verifies that the versioned release note exists under `docs/releases/`
   - blocks on any unrelated dirty or staged changes
   - checks the tag does not exist locally or on the remote
   - bumps Cargo, npm, and VS Code extension versions
   - refreshes `Cargo.lock` and `vscode-extension/package-lock.json`
   - updates README action-install refs
   - runs the verification suite
   - prints instructions — **it does not commit, push, or tag**

4. Review the changes, commit them on the release branch, push, and open a
   pull request against `main`:

   ```sh
   git add Cargo.toml Cargo.lock
   git add packages/npm/package.json
   git add vscode-extension/package.json vscode-extension/package-lock.json
   git add README.md docs/releases/vX.Y.Z.md
   git commit -m "Prepare vX.Y.Z release metadata"
   git push origin <release-branch>
   # then open the PR on GitHub
   ```

5. After the PR passes required checks (CI, review) and merges to `main`,
   tag the merge commit and push:

   ```sh
   git switch main
   git pull --ff-only
   git tag vX.Y.Z
   git push origin vX.Y.Z
   ```

   The tag push triggers the GitHub `Release` workflow, which:
   - verifies secrets exist
   - verifies tag/version alignment across all metadata files
   - builds Linux and macOS binaries for x86_64/aarch64, and Windows x86_64
   - creates or updates the GitHub Release with checksums and attestations
   - publishes crates.io
   - publishes npm
   - publishes native CLI wheels to PyPI using trusted publishing
   - publishes the VS Code extension
   - publishes the GitHub App image to GHCR

## Required GitHub secrets

- `CARGO_REGISTRY_TOKEN`
- `NPM_TOKEN`
- `VSCE_PAT`

## PyPI setup and validation

Before the first PyPI release, sign in to the maintainer's PyPI account and
configure a [pending trusted publisher](https://pypi.org/manage/account/publishing/):

- Project: `foxguard`
- Owner: `0sec-labs`
- Repository: `foxguard`
- Workflow: `workflow.yml` (the publisher, not `python-wheels.yml`)
- Environment: `pypi`

Create the GitHub `pypi` environment with release-tag restrictions and appropriate
maintainer approval. No long-lived PyPI token is needed. A pending publisher does
not reserve the package name; the first successful upload creates the project.
An absent public PyPI page alone does not establish name availability.

`pyproject.toml` derives the version from Cargo, so no additional version bump is
needed. Maturin packages only the `foxguard` CLI, not helper or server binaries.
The wheel workflow runs on pull requests and can be dispatched without publishing.
It builds and installs wheels on Linux (glibc 2.28+, x86_64/aarch64), macOS
(x86_64/aarch64), and Windows x86_64, then checks the installed version and scans
both vulnerable and clean Python inputs. Python 3.9+ is required; no Rust compiler
or runtime download is needed to install a supported wheel. Alpine/musl wheels
and source distributions are not published by this workflow.

Local packaging smoke check:

```sh
uvx maturin build --release --locked --out target/python-wheels
uv venv target/python-venv
uv pip install --python target/python-venv/bin/python --no-index --no-deps target/python-wheels/*.whl
target/python-venv/bin/python scripts/smoke-python-wheel.py
uvx twine check --strict target/python-wheels/*.whl
```

Do not advertise `pip install foxguard` until the first upload succeeds and a
fresh environment can install and run it from PyPI. Use a new patch release after
merging packaging changes; do not move the already-published `v0.13.0` tag.

## Reruns and partial success

The release workflow is intended to be rerun-safe.

- **GitHub Release:** safe to rerun for the same tag
- **crates.io:** rerun is treated as success if that version already exists
- **npm:** rerun is treated as success if that version already exists
- **VS Code Marketplace:** rerun is treated as success if that version already exists
- **PyPI:** existing wheel filenames are skipped; missing platform wheels can
  publish on a rerun. Never replace an already-published wheel.

This matters when one registry publishes successfully and another fails later
in the workflow.

## Recovery rules

If a release fails:

1. Check which registries already published the target version.
2. Fix the real cause on `main`.
3. If the tag should point to the fixed commit:
   - **Only if the version has NOT been published to any registry:**
     delete the GitHub Release, delete the remote tag, recreate the tag on
     the fixed commit, and push the tag again.
   - **If the version was already published to one or more registries:**
     do NOT move or delete the tag — registries treat published versions
     as immutable. Instead, publish a new patch version (for example,
     `v0.13.1` after `v0.13.0`) containing the fix.

4. If the tag already points to the correct commit and only a registry
   publish failed transiently, rerunning the workflow should be enough.

## Notes

- Keep `Cargo.lock` in sync with release metadata commits.
- The release script runs `cargo update --workspace --offline` after bumping
  the workspace version, preserving locked registry and Git dependencies.
  Dependencies must already be cached for offline resolution.
- Do not hand-publish from local scripts; the GitHub tag workflow is the
  source of truth.