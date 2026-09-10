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
   - publishes the VS Code extension
   - publishes the GitHub App image to GHCR

## Required GitHub secrets

- `CARGO_REGISTRY_TOKEN`
- `NPM_TOKEN`
- `VSCE_PAT`

## Reruns and partial success

The release workflow is intended to be rerun-safe.

- **GitHub Release:** safe to rerun for the same tag
- **crates.io:** rerun is treated as success if that version already exists
- **npm:** rerun is treated as success if that version already exists
- **VS Code Marketplace:** rerun is treated as success if that version already exists

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