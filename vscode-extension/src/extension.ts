import * as vscode from "vscode";
import { execFile } from "child_process";
import * as path from "path";

/** Mirrors the JSON output of `foxguard --format json`. */
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

/** Versioned envelope emitted by the CLI JSON reporter (v1.0.0+). */
interface ReportEnvelope {
  schema_version: string;
  findings: Finding[];
}

/**
 * Extract the findings array from CLI stdout.  Current foxguard wraps
 * findings in a {@link ReportEnvelope}; older versions emitted a bare
 * `Finding[]`.  This helper handles both shapes so the extension stays
 * backward-compatible.
 */
function extractFindings(parsed: ReportEnvelope | Finding[]): Finding[] {
  if (Array.isArray(parsed)) {
    return parsed;                   // legacy bare array
  }
  return parsed.findings ?? [];      // versioned envelope
}

/** File extensions foxguard supports. */
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
]);

const SEVERITY_ORDER: Record<string, number> = {
  low: 0, medium: 1, high: 2, critical: 3,
};

let diagnosticCollection: vscode.DiagnosticCollection;
let outputChannel: vscode.OutputChannel;
let statusBarItem: vscode.StatusBarItem;
let cachedBinary: string | null | undefined;

export function activate(context: vscode.ExtensionContext): void {
  diagnosticCollection = vscode.languages.createDiagnosticCollection("foxguard");
  outputChannel = vscode.window.createOutputChannel("foxguard");

  // Status bar item
  statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 0);
  statusBarItem.command = "foxguard.scanFile";
  statusBarItem.text = "$(shield) foxguard";
  statusBarItem.tooltip = "Click to scan current file";
  context.subscriptions.push(diagnosticCollection, outputChannel, statusBarItem);

  // Show status bar when a supported file is active
  context.subscriptions.push(
    vscode.window.onDidChangeActiveTextEditor((editor) => {
      updateStatusBar(editor);
    })
  );
  updateStatusBar(vscode.window.activeTextEditor);

  // Scan on save
  context.subscriptions.push(
    vscode.workspace.onDidSaveTextDocument((doc) => scanDocument(doc))
  );

  // Scan on open
  context.subscriptions.push(
    vscode.workspace.onDidOpenTextDocument((doc) => {
      // Small delay to let the editor settle
      setTimeout(() => scanDocument(doc), 500);
    })
  );

  // Manual scan command
  context.subscriptions.push(
    vscode.commands.registerCommand("foxguard.scanFile", () => {
      const editor = vscode.window.activeTextEditor;
      if (editor) {
        scanDocument(editor.document);
      }
    })
  );

  // Scan workspace command
  context.subscriptions.push(
    vscode.commands.registerCommand("foxguard.scanWorkspace", () => {
      scanWorkspace();
    })
  );

  // Clear diagnostics when file closed
  context.subscriptions.push(
    vscode.workspace.onDidCloseTextDocument((doc) => {
      diagnosticCollection.delete(doc.uri);
    })
  );

  // Scan all open files on activation
  vscode.workspace.textDocuments.forEach((doc) => scanDocument(doc));

  outputChannel.appendLine("foxguard extension activated");
}

export function deactivate(): void {
  diagnosticCollection?.dispose();
}

// ---------------------------------------------------------------------------
// Status bar
// ---------------------------------------------------------------------------

function updateStatusBar(editor: vscode.TextEditor | undefined): void {
  if (editor && isSupportedFile(editor.document.uri.fsPath)) {
    statusBarItem.show();
  } else {
    statusBarItem.hide();
  }
}

function setStatusScanning(): void {
  statusBarItem.text = "$(loading~spin) foxguard";
  statusBarItem.tooltip = "Scanning...";
}

function setStatusDone(count: number): void {
  if (count === 0) {
    statusBarItem.text = "$(shield) foxguard";
    statusBarItem.tooltip = "No issues found";
  } else {
    statusBarItem.text = `$(warning) foxguard: ${count}`;
    statusBarItem.tooltip = `${count} security issue${count === 1 ? "" : "s"} found`;
  }
}

// ---------------------------------------------------------------------------
// Core scanning logic
// ---------------------------------------------------------------------------

function isSupportedFile(filePath: string): boolean {
  const ext = path.extname(filePath).toLowerCase();
  return SUPPORTED_EXTENSIONS.has(ext);
}

function mapSeverity(severity: string): vscode.DiagnosticSeverity {
  switch (severity) {
    case "critical":
    case "high":
      return vscode.DiagnosticSeverity.Error;
    case "medium":
      return vscode.DiagnosticSeverity.Warning;
    case "low":
      return vscode.DiagnosticSeverity.Information;
    default:
      return vscode.DiagnosticSeverity.Information;
  }
}

function severityEmoji(severity: string): string {
  switch (severity) {
    case "critical": return "CRITICAL";
    case "high": return "HIGH";
    case "medium": return "MEDIUM";
    case "low": return "LOW";
    default: return severity.toUpperCase();
  }
}

function meetsMinSeverity(severity: string, minSeverity: string): boolean {
  return (SEVERITY_ORDER[severity] ?? 0) >= (SEVERITY_ORDER[minSeverity] ?? 0);
}

async function resolveBinary(): Promise<string | null | undefined> {
  if (cachedBinary !== undefined) {
    return cachedBinary;
  }

  const config = vscode.workspace.getConfiguration("foxguard");
  const customPath = config.get<string>("path", "").trim();

  if (customPath) {
    cachedBinary = customPath;
    return cachedBinary;
  }

  // Check PATH
  const found = await new Promise<boolean>((resolve) => {
    execFile("foxguard", ["--version"], (err) => resolve(!err));
  });
  if (found) {
    cachedBinary = "foxguard";
    return cachedBinary;
  }

  // Try npx
  const npxFound = await new Promise<boolean>((resolve) => {
    execFile("npx", ["foxguard", "--version"], { timeout: 15000 }, (err) => resolve(!err));
  });
  if (npxFound) {
    cachedBinary = null; // sentinel: use npx
    return cachedBinary;
  }

  cachedBinary = undefined; // not found
  return cachedBinary;
}

function scanDocument(document: vscode.TextDocument): void {
  const filePath = document.uri.fsPath;

  if (!isSupportedFile(filePath)) {
    return;
  }

  // Don't scan untitled or virtual documents
  if (document.uri.scheme !== "file") {
    return;
  }

  const config = vscode.workspace.getConfiguration("foxguard");
  const minSeverity = config.get<string>("severity", "low");

  setStatusScanning();

  resolveBinary().then((binary) => {
    if (binary === undefined) {
      statusBarItem.text = "$(shield) foxguard (not installed)";
      vscode.window
        .showInformationMessage(
          "foxguard not found. Install it to enable security scanning.",
          "Install with npm",
          "Install with brew"
        )
        .then((choice) => {
          if (choice) {
            const terminal = vscode.window.createTerminal("foxguard");
            terminal.show();
            if (choice === "Install with brew") {
              terminal.sendText("brew install peaktwilight/tap/foxguard");
            } else {
              terminal.sendText("npm install -g foxguard");
            }
          }
        });
      return;
    }

    let command: string;
    let args: string[];

    if (binary === null) {
      command = "npx";
      args = ["foxguard", "--format", "json", filePath];
    } else {
      command = binary;
      args = ["--format", "json", filePath];
    }

    if (minSeverity && minSeverity !== "low") {
      args.splice(args.indexOf("--format"), 0, "--severity", minSeverity);
    }

    execFile(
      command,
      args,
      { maxBuffer: 10 * 1024 * 1024, timeout: 30_000 },
      (error, stdout, stderr) => {
        if (stderr) {
          outputChannel.appendLine(stderr.trim());
        }

        if (!stdout.trim()) {
          diagnosticCollection.set(document.uri, []);
          setStatusDone(0);
          return;
        }

        let findings: Finding[];
        try {
          findings = extractFindings(JSON.parse(stdout));
        } catch (e) {
          outputChannel.appendLine(`Parse error: ${e}`);
          setStatusDone(0);
          return;
        }

        const diagnostics: vscode.Diagnostic[] = findings
          .filter((f) => meetsMinSeverity(f.severity, minSeverity))
          .map((f) => {
            const range = new vscode.Range(
              Math.max(0, f.line - 1),
              Math.max(0, f.column - 1),
              Math.max(0, f.end_line - 1),
              Math.max(0, f.end_column - 1)
            );

            const sev = severityEmoji(f.severity);
            const cweTag = f.cwe ? ` (${f.cwe})` : "";
            const fixHint = f.fix_suggestion ? `\nFix: ${f.fix_suggestion}` : "";
            const message = `[${sev}] ${f.description}${cweTag}${fixHint}`;

            const diag = new vscode.Diagnostic(
              range,
              message,
              mapSeverity(f.severity)
            );
            diag.source = "foxguard";
            diag.code = {
              value: f.rule_id,
              target: vscode.Uri.parse(
                `https://github.com/0sec-labs/foxguard#built-in-coverage`
              ),
            };
            return diag;
          });

        diagnosticCollection.set(document.uri, diagnostics);
        setStatusDone(diagnostics.length);

        if (diagnostics.length > 0) {
          outputChannel.appendLine(
            `${path.basename(filePath)}: ${diagnostics.length} issue${diagnostics.length === 1 ? "" : "s"}`
          );
        }
      }
    );
  });
}

// ---------------------------------------------------------------------------
// Workspace scan
// ---------------------------------------------------------------------------

async function scanWorkspace(): Promise<void> {
  const folders = vscode.workspace.workspaceFolders;
  if (!folders) {
    vscode.window.showInformationMessage("No workspace folder open.");
    return;
  }

  const binary = await resolveBinary();
  if (binary === undefined) {
    vscode.window.showInformationMessage("foxguard not found. Install it first.");
    return;
  }

  const rootPath = folders[0].uri.fsPath;

  vscode.window.withProgress(
    {
      location: vscode.ProgressLocation.Notification,
      title: "foxguard: scanning workspace...",
      cancellable: false,
    },
    () => {
      return new Promise<void>((resolve) => {
        let command: string;
        let args: string[];

        if (binary === null) {
          command = "npx";
          args = ["foxguard", "--format", "json", rootPath];
        } else {
          command = binary;
          args = ["--format", "json", rootPath];
        }

        execFile(
          command,
          args,
          { maxBuffer: 50 * 1024 * 1024, timeout: 120_000 },
          (error, stdout, stderr) => {
            if (!stdout.trim()) {
              vscode.window.showInformationMessage("foxguard: no issues found in workspace.");
              resolve();
              return;
            }

            let findings: Finding[];
            try {
              findings = extractFindings(JSON.parse(stdout));
            } catch {
              resolve();
              return;
            }

            // Group by file
            const byFile = new Map<string, Finding[]>();
            for (const f of findings) {
              const existing = byFile.get(f.file) || [];
              existing.push(f);
              byFile.set(f.file, existing);
            }

            // Set diagnostics per file
            for (const [filePath, fileFindings] of byFile) {
              const uri = vscode.Uri.file(filePath);
              const diagnostics = fileFindings.map((f) => {
                const range = new vscode.Range(
                  Math.max(0, f.line - 1),
                  Math.max(0, f.column - 1),
                  Math.max(0, f.end_line - 1),
                  Math.max(0, f.end_column - 1)
                );

                const sev = severityEmoji(f.severity);
                const cweTag = f.cwe ? ` (${f.cwe})` : "";
                const fixHint = f.fix_suggestion ? `\nFix: ${f.fix_suggestion}` : "";
                const diag = new vscode.Diagnostic(
                  range,
                  `[${sev}] ${f.description}${cweTag}${fixHint}`,
                  mapSeverity(f.severity)
                );
                diag.source = "foxguard";
                diag.code = {
                  value: f.rule_id,
                  target: vscode.Uri.parse(
                    `https://github.com/0sec-labs/foxguard#built-in-coverage`
                  ),
                };
                return diag;
              });
              diagnosticCollection.set(uri, diagnostics);
            }

            vscode.window.showInformationMessage(
              `foxguard: ${findings.length} issue${findings.length === 1 ? "" : "s"} in ${byFile.size} file${byFile.size === 1 ? "" : "s"}.`
            );
            resolve();
          }
        );
      });
    }
  );
}
