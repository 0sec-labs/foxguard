import * as assert from "assert";
import * as fs from "fs";
import * as path from "path";
import { extractFindings } from "./report";


const CONTRACT_FIXTURE = JSON.parse(
  fs.readFileSync(
    path.resolve(__dirname, "../../tests/contracts/native-report-v1.json"),
    "utf8"
  )
);

// ── Tests ────────────────────────────────────────────────────────────


// The repository-level fixture is the contract shared with non-Rust clients.
{
  const result = extractFindings(CONTRACT_FIXTURE);
  assert.strictEqual(result.length, 1);
  assert.strictEqual(result[0].rule_id, "js/taint-command-injection");
  assert.strictEqual(result[0].severity, "critical");
  assert.strictEqual(result[0].line, 12);
}

// Legacy bare array (older CLI)
{
  const result = extractFindings(CONTRACT_FIXTURE.findings);
  assert.strictEqual(result[0].rule_id, "js/taint-command-injection");
}

// Envelope with zero findings
{
  const result = extractFindings({ schema_version: "1.0.0", findings: [] });
  assert.strictEqual(result.length, 0);
}

// Missing or malformed report containers must not become a clean result.
assert.throws(() => extractFindings({ schema_version: "1.0.0" }));
assert.throws(() => extractFindings({ findings: {} }));


console.log("All extractFindings tests passed.");
