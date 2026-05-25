/**
 * Lightweight tests for `extractFindings` — the envelope/legacy parser.
 *
 * Run with: npx tsx src/extractFindings.test.ts
 * (No VS Code runtime required.)
 */

import * as assert from "assert";

// ── Inline copies of types + function (no VS Code dep) ──────────────

interface Finding {
  rule_id: string;
  severity: "low" | "medium" | "high" | "critical";
  cwe: string | null;
  description: string;
  file: string;
  line: number;
  column: number;
  end_line: number;
  end_column: number;
  snippet: string;
  fix_suggestion?: string;
}

interface ReportEnvelope {
  schema_version: string;
  findings: Finding[];
}

function extractFindings(parsed: ReportEnvelope | Finding[]): Finding[] {
  if (Array.isArray(parsed)) {
    return parsed;
  }
  return parsed.findings ?? [];
}

// ── Fixtures ─────────────────────────────────────────────────────────

const SAMPLE_FINDING: Finding = {
  rule_id: "js/no-eval",
  severity: "high",
  cwe: "CWE-95",
  description: "Use of eval()",
  file: "src/app.js",
  line: 10,
  column: 3,
  end_line: 10,
  end_column: 15,
  snippet: "eval(input)",
};

const ENVELOPE_OUTPUT: ReportEnvelope = {
  schema_version: "1.0.0",
  findings: [SAMPLE_FINDING],
};

// ── Tests ────────────────────────────────────────────────────────────

// Versioned envelope (current CLI)
{
  const result = extractFindings(ENVELOPE_OUTPUT);
  assert.strictEqual(result.length, 1);
  assert.strictEqual(result[0].rule_id, "js/no-eval");
}

// Legacy bare array (older CLI)
{
  const result = extractFindings([SAMPLE_FINDING]);
  assert.strictEqual(result.length, 1);
  assert.strictEqual(result[0].rule_id, "js/no-eval");
}

// Envelope with zero findings
{
  const result = extractFindings({ schema_version: "1.0.0", findings: [] });
  assert.strictEqual(result.length, 0);
}

// Legacy empty array
{
  const result = extractFindings([]);
  assert.strictEqual(result.length, 0);
}

// Simulated JSON.parse round-trip — envelope
{
  const raw = JSON.stringify(ENVELOPE_OUTPUT);
  const parsed = JSON.parse(raw);
  const result = extractFindings(parsed);
  assert.strictEqual(result.length, 1);
}

// Simulated JSON.parse round-trip — bare array
{
  const raw = JSON.stringify([SAMPLE_FINDING]);
  const parsed = JSON.parse(raw);
  const result = extractFindings(parsed);
  assert.strictEqual(result.length, 1);
}

console.log("All extractFindings tests passed.");
