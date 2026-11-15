import * as assert from "assert";

import { quoteForCmd } from "./shellArgs";

assert.strictEqual(quoteForCmd("src/app.ts"), "src/app.ts");
assert.strictEqual(quoteForCmd("my dir\\a.ts"), '"my dir\\a.ts"');
for (const bad of ["a&calc.exe", "a|b", 'a"b', "%PATH%", "a^b", "a>b", "a\nb", "a!b"]) {
  assert.throws(() => quoteForCmd(bad), /unsafe argument/, `${bad} should be rejected`);
}
