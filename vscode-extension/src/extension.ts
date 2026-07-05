import * as vscode from "vscode";
import { spawn } from "child_process";
import * as crypto from "crypto";
import * as fs from "fs";
import * as path from "path";
import { isSupportedFile } from "./supportedFiles";

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

interface ConfigMutationResult {
  config_path: string;
  added: boolean;
}

interface ProcessResult {
  stdout: string;
  stderr: string;
}

interface ProcessOptions {
  cwd?: string;
  maxBuffer?: number;
  timeout?: number;
  allowNonZero?: boolean;
}

const configMutationQueues = new Map<string, Promise<void>>();

function runProcess(command: string, args: string[], options: ProcessOptions = {}): Promise<ProcessResult> {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { // foxguard: ignore[js/no-command-injection]
      cwd: options.cwd,
      shell: process.platform === "win32",
      windowsHide: true,
    });

    let stdout = "";
    let stderr = "";
    let settled = false;
    const maxBuffer = options.maxBuffer ?? 1024 * 1024;

    const timer = options.timeout
      ? setTimeout(() => {
          if (settled) {
            return;
          }
          settled = true;
          child.kill();
          reject(new Error(`command timed out after ${options.timeout}ms`));
        }, options.timeout)
      : undefined;

    child.stdout?.on("data", (chunk: Buffer) => {
      stdout += chunk.toString();
      if (stdout.length + stderr.length > maxBuffer && !settled) {
        settled = true;
        child.kill();
        reject(new Error("command output exceeded maxBuffer"));
      }
    });

    child.stderr?.on("data", (chunk: Buffer) => {
      stderr += chunk.toString();
      if (stdout.length + stderr.length > maxBuffer && !settled) {
        settled = true;
        child.kill();
        reject(new Error("command output exceeded maxBuffer"));
      }
    });

    child.on("error", (error) => {
      if (settled) {
        return;
      }
      settled = true;
      if (timer) {
        clearTimeout(timer);
      }
      reject(error);
    });

    child.on("close", (code) => {
      if (settled) {
        return;
      }
      settled = true;
      if (timer) {
        clearTimeout(timer);
      }
      if (code === 0 || options.allowNonZero) {
        resolve({ stdout, stderr });
      } else {
        reject(new Error(stderr.trim() || `command exited with code ${code}`));
      }
    });
  });
}

async function withConfigMutationQueue<T>(configPath: string, operation: () => Promise<T>): Promise<T> {
  const key = path.resolve(configPath);
  const previous = configMutationQueues.get(key) ?? Promise.resolve();
  const run = previous.catch(() => undefined).then(operation);
  const next = run.then(() => undefined, () => undefined);
  configMutationQueues.set(key, next);

  try {
    return await run;
  } finally {
    if (configMutationQueues.get(key) === next) {
      configMutationQueues.delete(key);
    }
  }
}

function parseConfigMutationResult(stdout: string): ConfigMutationResult {
  const parsed = JSON.parse(stdout) as Partial<ConfigMutationResult>;
  if (typeof parsed.config_path !== "string" || typeof parsed.added !== "boolean") {
    throw new Error("invalid config edit response shape");
  }
  return parsed as ConfigMutationResult;
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

const SEVERITY_ORDER: Record<string, number> = {
  low: 0, medium: 1, high: 2, critical: 3,
};

// ---------------------------------------------------------------------------
// Inline-comment prefix per language (mirrors foxguard's comment_markers())
// ---------------------------------------------------------------------------

/** Map VS Code language IDs to inline comment prefixes. */
function commentPrefix(languageId: string): string {
  switch (languageId) {
    case "python":
    case "ruby":
    case "dockerfile":
    case "shellscript":
    case "yaml":
      return "#";
    case "php":
    case "javascript":
    case "javascriptreact":
    case "typescript":
    case "typescriptreact":
    case "go":
    case "java":
    case "rust":
    case "csharp":
    case "swift":
    case "kotlin":
    case "c":
    case "cpp":
      return "//";
    default:
      return "//";
  }
}

// ---------------------------------------------------------------------------
// Fingerprint — mirrors Rust's fingerprint_finding_with_file()
// ---------------------------------------------------------------------------

/**
 * Compute the SHA-256 fingerprint for a finding, matching the Rust CLI's
 * `fingerprint_finding_with_file` exactly: each field separated by a NUL byte.
 */
function fingerprintFinding(
  ruleId: string,
  file: string,
  line: number,
  column: number,
  endLine: number,
  endColumn: number,
  description: string,
): string {
  const h = crypto.createHash("sha256");
  h.update(ruleId);
  h.update("\0");
  h.update(file);
  h.update("\0");
  h.update(String(line));
  h.update("\0");
  h.update(String(column));
  h.update("\0");
  h.update(String(endLine));
  h.update("\0");
  h.update(String(endColumn));
  h.update("\0");
  h.update(description);
  return h.digest("hex");
}

// ---------------------------------------------------------------------------
// Baseline file helpers
// ---------------------------------------------------------------------------

interface BaselineEntry {
  fingerprint: string;
  rule_id: string;
  file: string;
  line: number;
}

interface BaselineFile {
  version: number;
  entries: BaselineEntry[];
}

function readBaseline(baselinePath: string): BaselineFile {
  if (fs.existsSync(baselinePath)) {
    try {
      return JSON.parse(fs.readFileSync(baselinePath, "utf-8"));
    } catch {
      // Corrupted — start fresh
    }
  }
  return { version: 1, entries: [] };
}

function writeBaseline(baselinePath: string, baseline: BaselineFile): void {
  const dir = path.dirname(baselinePath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  fs.writeFileSync(baselinePath, JSON.stringify(baseline, null, 2) + "\n");
}

// ---------------------------------------------------------------------------
// Config file helpers (scan.ignore_rules in .foxguard.yml)
// ---------------------------------------------------------------------------

async function addIgnoreRuleToConfig(
  scanPath: string,
  configPath: string,
  relPath: string,
  ruleId: string,
): Promise<ConfigMutationResult> {
  return await withConfigMutationQueue(configPath, async () => {
    const binary = await resolveBinary();
    if (binary === undefined) {
      throw new Error("foxguard not found");
    }

    let command: string;
    let args: string[];
    if (binary === null) {
      command = "npx";
      args = [
        "foxguard",
        "internal",
        "add-scan-ignore-rule",
        "--scan-path", scanPath,
        "--config", configPath,
        "--file", relPath,
        "--rule-id", ruleId,
      ];
    } else {
      command = binary;
      args = [
        "internal",
        "add-scan-ignore-rule",
        "--scan-path", scanPath,
        "--config", configPath,
        "--file", relPath,
        "--rule-id", ruleId,
      ];
    }

    const { stdout } = await runProcess(command, args, {
      cwd: scanPath,
      maxBuffer: 1024 * 1024,
      timeout: 30_000,
    });

    try {
      return parseConfigMutationResult(stdout);
    } catch (parseError) {
      throw new Error(`invalid config edit response: ${parseError}`);
    }
  });
}

// ---------------------------------------------------------------------------
// CodeAction provider
// ---------------------------------------------------------------------------

class FoxguardCodeActionProvider implements vscode.CodeActionProvider {
  public static readonly providedCodeActionKinds = [
    vscode.CodeActionKind.QuickFix,
  ];

  provideCodeActions(
    document: vscode.TextDocument,
    range: vscode.Range | vscode.Selection,
    context: vscode.CodeActionContext,
  ): vscode.CodeAction[] {
    const actions: vscode.CodeAction[] = [];

    for (const diag of context.diagnostics) {
      if (diag.source !== "foxguard") {
        continue;
      }

      const ruleId = typeof diag.code === "object" && diag.code !== null
        ? String((diag.code as { value: string | number }).value)
        : String(diag.code ?? "unknown");

      // 1) Suppress this finding (inline comment)
      const inlineAction = new vscode.CodeAction(
        `Suppress this finding (inline: foxguard: ignore[${ruleId}])`,
        vscode.CodeActionKind.QuickFix,
      );
      inlineAction.diagnostics = [diag];
      inlineAction.command = {
        title: "Suppress inline",
        command: "foxguard.suppressInline",
        arguments: [document.uri, diag],
      };
      inlineAction.isPreferred = false;
      actions.push(inlineAction);

      // 2) Suppress this rule for this file
      const fileAction = new vscode.CodeAction(
        `Suppress ${ruleId} for this file (.foxguard.yml)`,
        vscode.CodeActionKind.QuickFix,
      );
      fileAction.diagnostics = [diag];
      fileAction.command = {
        title: "Suppress in config",
        command: "foxguard.suppressInConfig",
        arguments: [document.uri, diag],
      };
      actions.push(fileAction);

      // 3) Add to baseline
      const baselineAction = new vscode.CodeAction(
        `Add to baseline (.foxguard/baseline.json)`,
        vscode.CodeActionKind.QuickFix,
      );
      baselineAction.diagnostics = [diag];
      baselineAction.command = {
        title: "Add to baseline",
        command: "foxguard.addToBaseline",
        arguments: [document.uri, diag],
      };
      actions.push(baselineAction);
    }

    return actions;
  }
}

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

  // ---- Code action provider (suppress / ignore / baseline) ----
  context.subscriptions.push(
    vscode.languages.registerCodeActionsProvider(
      { scheme: "file" },
      new FoxguardCodeActionProvider(),
      { providedCodeActionKinds: FoxguardCodeActionProvider.providedCodeActionKinds },
    ),
  );

  // Command: suppress inline
  context.subscriptions.push(
    vscode.commands.registerCommand(
      "foxguard.suppressInline",
      async (uri: vscode.Uri, diag: vscode.Diagnostic) => {
        const doc = await vscode.workspace.openTextDocument(uri);
        const editor = await vscode.window.showTextDocument(doc);
        const ruleId = extractRuleId(diag);
        const prefix = commentPrefix(doc.languageId);
        const targetLine = diag.range.start.line;
        const lineText = doc.lineAt(targetLine).text;
        const indent = lineText.match(/^\s*/)?.[0] ?? "";

        await editor.edit((editBuilder) => {
          editBuilder.insert(
            new vscode.Position(targetLine, 0),
            `${indent}${prefix} foxguard: ignore[${ruleId}]\n`,
          );
        });
        await doc.save();
      },
    ),
  );

  // Command: suppress in .foxguard.yml
  context.subscriptions.push(
    vscode.commands.registerCommand(
      "foxguard.suppressInConfig",
      async (uri: vscode.Uri, diag: vscode.Diagnostic) => {
        const ruleId = extractRuleId(diag);
        const workspaceFolder = vscode.workspace.getWorkspaceFolder(uri);
        const rootPath = workspaceFolder?.uri.fsPath ?? path.dirname(uri.fsPath);
        const configPath = path.join(rootPath, ".foxguard.yml");
        const relPath = path.relative(rootPath, uri.fsPath);

        try {
          const result = await addIgnoreRuleToConfig(rootPath, configPath, relPath, ruleId);
          if (result.added) {
            outputChannel.appendLine(
              `Suppressed ${ruleId} for ${relPath} in ${result.config_path}`,
            );
            vscode.window.showInformationMessage(
              `foxguard: added ${ruleId} ignore for ${relPath} to .foxguard.yml`,
            );
          } else {
            vscode.window.showInformationMessage(
              `foxguard: ${ruleId} already suppressed for ${relPath}`,
            );
          }
        } catch (error) {
          const message = error instanceof Error ? error.message : String(error);
          outputChannel.appendLine(`Failed to update .foxguard.yml: ${message}`);
          vscode.window.showErrorMessage(
            `foxguard: failed to update .foxguard.yml: ${message}`,
          );
        }
      },
    ),
  );

  // Command: add to baseline
  context.subscriptions.push(
    vscode.commands.registerCommand(
      "foxguard.addToBaseline",
      async (uri: vscode.Uri, diag: vscode.Diagnostic) => {
        const ruleId = extractRuleId(diag);
        const workspaceFolder = vscode.workspace.getWorkspaceFolder(uri);
        const rootPath = workspaceFolder?.uri.fsPath ?? path.dirname(uri.fsPath);
        const baselinePath = path.join(rootPath, ".foxguard", "baseline.json");
        const relPath = path.relative(rootPath, uri.fsPath);

        // Diagnostic range is 0-based; findings use 1-based lines/columns
        const line = diag.range.start.line + 1;
        const column = diag.range.start.character + 1;
        const endLine = diag.range.end.line + 1;
        const endColumn = diag.range.end.character + 1;

        // Extract the raw description (strip severity prefix and CWE/fix suffixes
        // so the fingerprint matches what the CLI produces)
        const description = extractDescription(diag.message);

        const fp = fingerprintFinding(ruleId, relPath, line, column, endLine, endColumn, description);

        const baseline = readBaseline(baselinePath);
        if (baseline.entries.some((e) => e.fingerprint === fp)) {
          vscode.window.showInformationMessage(
            `foxguard: finding already in baseline`,
          );
          return;
        }

        baseline.entries.push({
          fingerprint: fp,
          rule_id: ruleId,
          file: relPath,
          line,
        });
        writeBaseline(baselinePath, baseline);

        outputChannel.appendLine(
          `Added ${ruleId} at ${relPath}:${line} to baseline (fingerprint: ${fp.slice(0, 12)}...)`,
        );
        vscode.window.showInformationMessage(
          `foxguard: added finding to .foxguard/baseline.json`,
        );
      },
    ),
  );

  // Scan all open files on activation
  vscode.workspace.textDocuments.forEach((doc) => scanDocument(doc));

  outputChannel.appendLine("foxguard extension activated");
}

export function deactivate(): void {
  diagnosticCollection?.dispose();
}

// ---------------------------------------------------------------------------
// Diagnostic helpers
// ---------------------------------------------------------------------------

/** Extract the rule ID from a foxguard diagnostic's `.code` property. */
function extractRuleId(diag: vscode.Diagnostic): string {
  if (typeof diag.code === "object" && diag.code !== null) {
    return String((diag.code as { value: string | number }).value);
  }
  return String(diag.code ?? "unknown");
}

/**
 * Extract the raw description from a diagnostic message.
 *
 * Diagnostic messages are formatted as:
 *   `[SEVERITY] description (CWE-xxx)\nFix: suggestion`
 *
 * The fingerprint in the Rust CLI uses only `finding.description`,
 * so we strip the bracketed severity prefix and CWE/fix suffixes.
 */
function extractDescription(message: string): string {
  // Strip "[HIGH] " etc.
  let desc = message.replace(/^\[(?:CRITICAL|HIGH|MEDIUM|LOW)\]\s*/, "");
  // Strip trailing "\nFix: ..." if present
  const fixIdx = desc.indexOf("\nFix: ");
  if (fixIdx !== -1) {
    desc = desc.slice(0, fixIdx);
  }
  // Strip trailing " (CWE-xxx)"
  desc = desc.replace(/\s*\(CWE-\d+\)$/, "");
  return desc;
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
  const found = await runProcess("foxguard", ["--version"], { timeout: 15_000 })
    .then(() => true, () => false);
  if (found) {
    cachedBinary = "foxguard";
    return cachedBinary;
  }

  // Try npx
  const npxFound = await runProcess("npx", ["foxguard", "--version"], { timeout: 15_000 })
    .then(() => true, () => false);
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

    // foxguard: ignore[js/no-command-injection]
    runProcess(command, args, { maxBuffer: 10 * 1024 * 1024, timeout: 30_000, allowNonZero: true })
      .then(({ stdout, stderr }) => {
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
      })
      .catch((error) => {
        outputChannel.appendLine(`Scan failed: ${error instanceof Error ? error.message : String(error)}`);
        setStatusDone(0);
      });
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

        // foxguard: ignore[js/no-command-injection]
        runProcess(command, args, { maxBuffer: 50 * 1024 * 1024, timeout: 120_000, allowNonZero: true })
          .then(({ stdout }) => {
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
          })
          .catch((error) => {
            outputChannel.appendLine(`Workspace scan failed: ${error instanceof Error ? error.message : String(error)}`);
            resolve();
          });
      });
    }
  );
}
