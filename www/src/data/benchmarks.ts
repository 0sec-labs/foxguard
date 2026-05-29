// Speed benchmark across three multi-language SAST tools. Median of 3 runs on
// Apple Silicon, 2026-05-29. foxguard 0.8.1 (built-ins) vs Semgrep 1.156 &
// OpenGrep 1.22 (both `--config auto`, identical findings). Reproduce with
// benchmarks/run-multi.sh.

export interface ToolResult {
  tool: string;
  seconds: number;
  /** Marks foxguard — styled as the winner. */
  winner?: boolean;
}

export interface BenchmarkRow {
  repo: string;
  files: number;
  tools: ToolResult[];
}

export const benchmarkRows: BenchmarkRow[] = [
  {
    repo: 'express',
    files: 141,
    tools: [
      { tool: 'foxguard', seconds: 0.292, winner: true },
      { tool: 'Semgrep', seconds: 5.472 },
      { tool: 'OpenGrep', seconds: 5.541 },
    ],
  },
  {
    repo: 'flask',
    files: 83,
    tools: [
      { tool: 'foxguard', seconds: 0.398, winner: true },
      { tool: 'Semgrep', seconds: 8.005 },
      { tool: 'OpenGrep', seconds: 8.683 },
    ],
  },
  {
    repo: 'gin',
    files: 99,
    tools: [
      { tool: 'foxguard', seconds: 0.318, winner: true },
      { tool: 'Semgrep', seconds: 4.923 },
      { tool: 'OpenGrep', seconds: 4.553 },
    ],
  },
];

function winnerSeconds(row: BenchmarkRow): number {
  return (row.tools.find((t) => t.winner) ?? row.tools[0]).seconds;
}

/** Nx faster vs Semgrep — the recognized multi-language baseline. */
export function speedMultiplier(row: BenchmarkRow): string {
  const baseline = row.tools.find((t) => t.tool === 'Semgrep') ?? row.tools[1];
  return Math.round(baseline.seconds / winnerSeconds(row)).toLocaleString() + 'x';
}
