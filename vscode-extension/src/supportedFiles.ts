import * as path from "path";

/** File extensions foxguard supports for single-file editor scans. */
const SUPPORTED_EXTENSIONS = new Set([
  ".js", ".jsx", ".mjs", ".cjs",
  ".ts", ".tsx", ".mts", ".cts",
  ".py", ".pyw",
  ".go",
  ".rb", ".rake",
  ".java",
  ".php",
  ".rs",
  ".cs",
  ".swift",
  ".kt", ".kts",
  ".c", ".h",
]);

export function isSupportedFile(filePath: string): boolean {
  const ext = path.extname(filePath).toLowerCase();
  return SUPPORTED_EXTENSIONS.has(ext);
}
