const assert = require("assert");
const fs = require("fs");
const os = require("os");
const path = require("path");

const { getBinaryName, getCachePaths } = require("../bin/foxguard");

const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "foxguard-npm-cache-"));

const darwinX64 = getCachePaths("x86_64-apple-darwin", "darwin", tempRoot);
const darwinArm64 = getCachePaths("aarch64-apple-darwin", "darwin", tempRoot);
const windowsX64 = getCachePaths("x86_64-pc-windows-msvc", "win32", tempRoot);

assert.notStrictEqual(
  darwinX64.cacheDir,
  darwinArm64.cacheDir,
  "cache directories should be target-specific",
);
assert.notStrictEqual(
  darwinX64.cachedBin,
  darwinArm64.cachedBin,
  "binary paths should be target-specific",
);
assert.notStrictEqual(
  darwinX64.versionFile,
  darwinArm64.versionFile,
  "version markers should be target-specific",
);
assert.strictEqual(
  path.basename(darwinX64.cachedBin),
  getBinaryName("darwin"),
  "non-Windows cache should use the plain binary name",
);
assert.strictEqual(
  path.basename(windowsX64.cachedBin),
  getBinaryName("win32"),
  "Windows cache should keep the .exe suffix",
);

console.log("foxguard npm cache path tests passed");
