import * as assert from "assert";

import { isSupportedFile } from "./supportedFiles";

for (const filePath of [
  "Example.kt",
  "Example.kts",
  "native/module.c",
  "native/include/module.h",
]) {
  assert.strictEqual(isSupportedFile(filePath), true, `${filePath} should be supported`);
}

for (const filePath of [
  "notes.txt",
  "native/module.cpp",
]) {
  assert.strictEqual(isSupportedFile(filePath), false, `${filePath} should not be supported`);
}

assert.strictEqual(isSupportedFile("SRC/APP.KT"), true, "extension matching should be case-insensitive");

console.log("All supportedFiles tests passed.");
