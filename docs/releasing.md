# Releasing foxguard

## Normal flow

1. Write and review `docs/releases/vX.Y.Z.md` for the version to publish.
2. Start from a clean `main`; the new release-note file is the only allowed uncommitted change.
3. Run:

```sh
./scripts/release.sh X.Y.Z
```

That script:

- verifies that the versioned release note exists under `docs/releases/`
- bumps Cargo, npm, and VS Code extension versions
- refreshes `vscode-extension/package-lock.json`
- runs the verification suite
- commits release metadata to `main`
- pushes `main`
- creates and pushes the `v*` tag

The tag triggers the GitHub `Release` workflow, which:

- verifies secrets exist
- verifies tag/version alignment
- builds release binaries
- creates or updates the GitHub Release
- publishes crates.io
- publishes npm
- publishes the VS Code extension

## Required GitHub secrets

- `CARGO_REGISTRY_TOKEN`
- `NPM_TOKEN`
- `VSCE_PAT`

## Reruns and partial success

The release workflow is intended to be rerun-safe.

- GitHub Release: safe to rerun for the same tag
- crates.io: rerun is treated as success if that version already exists
- npm: rerun is treated as success if that version already exists
- VS Code Marketplace: rerun is treated as success if that version already exists

This matters when one registry publishes successfully and another fails later in the workflow.

## Recovery rules

If a release fails:

1. Check which registries already published the target version
2. Fix the real cause on `main`
3. If the tag should point to the fixed commit:
   - delete the GitHub Release
   - delete the remote tag
   - recreate the tag on the fixed commit
   - push the tag again

If the tag already points to the correct commit and only a registry publish failed transiently, rerunning the workflow should be enough.

## Notes

- Keep `Cargo.lock` in sync with release metadata commits
- Do not hand-publish from local scripts anymore; the GitHub tag workflow is the source of truth
