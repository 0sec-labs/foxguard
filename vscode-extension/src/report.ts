/** Fields consumed from `foxguard --format json` findings. */
export interface Finding {
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

/** Accept report envelopes and legacy arrays, but never invent a clean report. */
export function extractFindings(parsed: unknown): Finding[] {
  const findings = Array.isArray(parsed)
    ? parsed
    : parsed !== null && typeof parsed === "object" && "findings" in parsed
      ? parsed.findings
      : undefined;
  if (!Array.isArray(findings)) {
    throw new Error("Invalid scanner report: expected a findings array.");
  }
  return findings as Finding[];
}
