import * as vscode from "vscode";
import { spawn } from "child_process";
import * as crypto from "crypto";
import * as fs from "fs";
import * as path from "path";
import { isSupportedFile } from "./supportedFiles";
import { extractFindings, type Finding } from "./report";
import { ScanController } from "./scanController";


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
  allowFindingExit?: boolean;
  signal?: AbortSignal;
}


const configMutationQueues = new Map<string, Promise<void>>();
const terminatingProcesses = new Set<Promise<void>>();

// ---------------------------------------------------------------------------
// Cancellation sentinel — distinguishes intentional abort from process errors
// ---------------------------------------------------------------------------

class ScanCancelledError extends Error {
  constructor() {
    super("Scan cancelled");
    this.name = "ScanCancelledError";
  }
}

// ---------------------------------------------------------------------------
// Process execution
// ---------------------------------------------------------------------------

function runProcess(command: string, args: string[], options: ProcessOptions = {}): Promise<ProcessResult> {
  return new Promise((resolve, reject) => {
    if (options.signal?.aborted) {
      reject(new ScanCancelledError());
      return;
    }
    const child = spawn(command, args, { // foxguard: ignore[js/no-command-injection]
      cwd: options.cwd,
      shell: process.platform === "win32",
      detached: process.platform !== "win32",
      windowsHide: true,
    });
    let stdout = "";
    let stderr = "";
    let bytes = 0;
    let settled = false;
    let terminating = false;
    let timer: NodeJS.Timeout | undefined;
    const maxBuffer = options.maxBuffer ?? 1024 * 1024;

    const terminate = (): void => {
      if (terminating || child.pid === undefined) {
        return;
      }
      terminating = true;
      const pid = child.pid;
      const cleanup = new Promise<void>((done) => {
        if (process.platform === "win32") {
          // Keep the parent alive until taskkill has identified its descendants.
          const killer = spawn(
            path.join(process.env.SystemRoot || "C:\\Windows", "System32", "taskkill.exe"),
            ["/PID", String(pid), "/T", "/F"],
            { windowsHide: true },
          );
          const deadline = setTimeout(() => {
            killer.kill();
            child.kill();
            done();
          }, 1000);
          killer.once("error", (error) => {
            console.error("foxguard process-tree cleanup failed:", error);
            child.kill();
            clearTimeout(deadline);
            done();
          });
          killer.once("close", (code) => {
            if (code !== 0 && child.exitCode === null) {
              child.kill();
            }
            clearTimeout(deadline);
            done();
          });
        } else {
          const signalGroup = (signal: NodeJS.Signals): void => {
            try {
              process.kill(-pid, signal);
            } catch (error) {
              if ((error as NodeJS.ErrnoException).code !== "ESRCH") {
                console.error("foxguard process-group cleanup failed:", error);
              }
            }
          };
          signalGroup("SIGTERM");
          // The group can outlive its leader; do not cancel escalation on the
          // parent's exit while a wrapper's descendants are still running.
          setTimeout(() => {
            signalGroup("SIGKILL");
            done();
          }, 500);
        }
      });
      terminatingProcesses.add(cleanup);
      void cleanup.then(() => terminatingProcesses.delete(cleanup));
    };

    const finish = (error?: Error): void => {
      if (settled) {
        return;
      }
      settled = true;
      clearTimeout(timer);
      options.signal?.removeEventListener("abort", abort);
      child.stdout?.removeListener("data", onStdout);
      child.stderr?.removeListener("data", onStderr);
      child.stdout?.resume();
      child.stderr?.resume();
      if (error) {
        reject(error);
      } else {
        resolve({ stdout, stderr });
      }
    };
    const abort = (): void => {
      finish(new ScanCancelledError());
      terminate();
    };
    const append = (chunk: string, isError: boolean): void => {
      if (settled) {
        return;
      }
      bytes += Buffer.byteLength(chunk);
      if (bytes > maxBuffer) {
        finish(new Error("command output exceeded maxBuffer"));
        terminate();
      } else if (isError) {
        stderr += chunk;
      } else {
        stdout += chunk;
      }
    };
    const onStdout = (chunk: string): void => append(chunk, false);
    const onStderr = (chunk: string): void => append(chunk, true);
    child.stdout?.setEncoding("utf8").on("data", onStdout);
    child.stderr?.setEncoding("utf8").on("data", onStderr);
    child.once("error", (error) => finish(error));
    child.once("close", (code) => {
      finish(code === 0 || (options.allowFindingExit && code === 1)
        ? undefined : new Error(stderr.trim() || `command exited with code ${code}`));
    });
    options.signal?.addEventListener("abort", abort, { once: true });
    if (options.timeout) {
      timer = setTimeout(() => {
        finish(new Error(`command timed out after ${options.timeout}ms`));
        terminate();
      }, options.timeout);
    }
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
    case "haskell":
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
const scanCtrl = new ScanController();
const pendingOpenScans = new Map<string, NodeJS.Timeout>();
const failedDocuments = new Set<string>();
let active = false;
let binaryGeneration = 0;
let binaryMissing = false;
let binaryResolution: Promise<string | null | undefined> | undefined;
let binaryDiscovery: AbortController | undefined;

export function activate(context: vscode.ExtensionContext): void {
  active = true;
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
      const key = doc.uri.toString();
      scanCtrl.cancelDocScan(key);
      clearTimeout(pendingOpenScans.get(key));
      pendingOpenScans.set(key, setTimeout(() => {
        pendingOpenScans.delete(key);
        scanDocument(doc);
      }, 500));
    })
  );

  // Cancel in-flight document scan when the user edits the file
  // (the scan results would be for a stale version).
  context.subscriptions.push(
    vscode.workspace.onDidChangeTextDocument((e) => {
      if (e.document.uri.scheme === "file") {
        const key = e.document.uri.toString();
        clearTimeout(pendingOpenScans.get(key));
        pendingOpenScans.delete(key);
        scanCtrl.cancelDocScan(key);
        updateStatusBar(vscode.window.activeTextEditor);
      }
    })
  );

  // Cancel scans on configuration changes (severity, binary path, etc.)
  context.subscriptions.push(
    vscode.workspace.onDidChangeConfiguration((e) => {
      if (e.affectsConfiguration("foxguard")) {
        scanCtrl.cancelAll();
        for (const timer of pendingOpenScans.values()) {
          clearTimeout(timer);
        }
        pendingOpenScans.clear();
        failedDocuments.clear();
        binaryGeneration += 1;
        binaryDiscovery?.abort();
        binaryResolution = undefined;
        binaryMissing = false;
        cachedBinary = undefined; // force re-resolve
        vscode.workspace.textDocuments.forEach((doc) => scanDocument(doc));
        updateStatusBar(vscode.window.activeTextEditor);
      }
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

  // Clear diagnostics when file closed; cancel any in-flight scan for it
  context.subscriptions.push(
    vscode.workspace.onDidCloseTextDocument((doc) => {
      const key = doc.uri.toString();
      clearTimeout(pendingOpenScans.get(key));
      pendingOpenScans.delete(key);
      failedDocuments.delete(key);
      if (doc.uri.scheme === "file") {
        scanCtrl.cancelDocScan(doc.uri.toString());
      }
      diagnosticCollection.delete(doc.uri);
      updateStatusBar(vscode.window.activeTextEditor);
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

export async function deactivate(): Promise<void> {
  active = false;
  binaryGeneration += 1;
  scanCtrl.cancelAll();
  binaryDiscovery?.abort();
  binaryResolution = undefined;
  for (const timer of pendingOpenScans.values()) {
    clearTimeout(timer);
  }
  pendingOpenScans.clear();
  await Promise.all(terminatingProcesses);
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
  if (!active) {
    return;
  }
  if (!editor || editor.document.uri.scheme !== "file" || !isSupportedFile(editor.document.uri.fsPath)) {
    statusBarItem.hide();
    return;
  }
  statusBarItem.show();
  if (scanCtrl.running) {
    setStatusScanning();
  } else if (editor.document.isDirty) {
    statusBarItem.text = "$(shield) foxguard (save to scan)";
    statusBarItem.tooltip = "Save this document to scan its current contents.";
  } else if (binaryMissing) {
    statusBarItem.text = "$(shield) foxguard (not installed)";
    statusBarItem.tooltip = "Install foxguard or configure foxguard.path.";
  } else if (failedDocuments.has(editor.document.uri.toString())) {
    setStatusFailed();
  } else {
    setStatusDone(diagnosticCollection.get(editor.document.uri)?.length ?? 0);
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

function setStatusFailed(): void {
  statusBarItem.text = "$(error) foxguard";
  statusBarItem.tooltip = "Scan failed. See the foxguard output for details.";
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
  if (binaryResolution) {
    return binaryResolution;
  }
  const customPath = vscode.workspace.getConfiguration("foxguard").get<string>("path", "").trim();
  if (customPath) {
    cachedBinary = customPath;
    return customPath;
  }
  const generation = binaryGeneration;
  const discovery = new AbortController();
  binaryDiscovery = discovery;
  const resolution = (async (): Promise<string | null | undefined> => {
    const found = await runProcess("foxguard", ["--version"], {
      timeout: 15_000, signal: discovery.signal,
    }).then(() => true, () => false);
    if (found) {
      return "foxguard";
    }
    if (generation !== binaryGeneration) {
      return undefined;
    }
    const npxFound = await runProcess("npx", ["foxguard", "--version"], {
      timeout: 15_000, signal: discovery.signal,
    }).then(() => true, () => false);
    return npxFound ? null : undefined;
  })();
  binaryResolution = resolution;
  try {
    const binary = await resolution;
    if (generation === binaryGeneration) {
      cachedBinary = binary;
    }
    return binary;
  } finally {
    if (binaryResolution === resolution) {
      binaryResolution = undefined;
      binaryDiscovery = undefined;
    }
  }
}

async function scanDocument(document: vscode.TextDocument): Promise<void> {
  const filePath = document.uri.fsPath;
  const key = document.uri.toString();
  if (!active || document.uri.scheme !== "file" || !isSupportedFile(filePath)) {
    return;
  }
  clearTimeout(pendingOpenScans.get(key));
  pendingOpenScans.delete(key);
  if (document.isClosed || document.isDirty) {
    scanCtrl.cancelDocScan(key);
    updateStatusBar(vscode.window.activeTextEditor);
    return;
  }
  const request = scanCtrl.startDocScan(key);
  const version = document.version;
  const minSeverity = vscode.workspace.getConfiguration("foxguard").get<string>("severity", "low");
  const current = (): boolean => active && scanCtrl.isDocCurrent(key, request)
    && !document.isClosed && !document.isDirty && document.version === version;
  updateStatusBar(vscode.window.activeTextEditor);
  try {
    const binary = await resolveBinary();
    if (!current()) {
      return;
    }
    if (binary === undefined) {
      binaryMissing = true;
      void vscode.window.showInformationMessage(
        "foxguard not found. Install it to enable security scanning.",
        "Install with npm", "Install prebuilt binary",
      ).then((choice) => {
        if (choice && active) {
          const terminal = vscode.window.createTerminal("foxguard");
          terminal.show();
          terminal.sendText(choice === "Install prebuilt binary"
            ? "curl -fsSL https://foxguard.dev/install.sh | sh" : "npm install -g foxguard");
        }
      });
      return;
    }
    binaryMissing = false;
    const args = ["--format", "json", filePath];
    if (minSeverity !== "low") {
      args.unshift("--severity", minSeverity);
    }
    if (binary === null) {
      args.unshift("foxguard");
    }
    const { stdout, stderr } = await runProcess(binary ?? "npx", args, {
      maxBuffer: 10 * 1024 * 1024,
      timeout: 30_000,
      allowFindingExit: true,
      signal: request.signal,
    });
    if (!current()) {
      return;
    }
    if (!stdout.trim()) {
      throw new Error("Scanner returned an empty report.");
    }
    const findings = extractFindings(JSON.parse(stdout));
    const diagnostics = findingsToDiagnostics(findings.filter((finding) => meetsMinSeverity(finding.severity, minSeverity)));
    if (stderr.trim()) {
      outputChannel.appendLine(stderr.trim());
    }
    diagnosticCollection.set(document.uri, diagnostics);
    failedDocuments.delete(key);
    outputChannel.appendLine(`${path.basename(filePath)}: ${diagnostics.length} issue${diagnostics.length === 1 ? "" : "s"}`);
  } catch (error) {
    if (!(error instanceof ScanCancelledError) && current()) {
      failedDocuments.add(key);
      outputChannel.appendLine(`Scan failed: ${error instanceof Error ? error.message : String(error)}`);
    }
  } finally {
    scanCtrl.finishDocScan(key, request);
    updateStatusBar(vscode.window.activeTextEditor);
  }
}

// ---------------------------------------------------------------------------
// Workspace scan
// ---------------------------------------------------------------------------

async function scanWorkspace(): Promise<void> {
  if (!active) {
    return;
  }
  const folder = vscode.workspace.workspaceFolders?.[0];
  if (!folder) {
    void vscode.window.showInformationMessage("No workspace folder open.");
    return;
  }
  const rootPath = folder.uri.fsPath;
  const contains = (key: string): boolean => {
    const uri = vscode.Uri.parse(key);
    const relative = path.relative(rootPath, uri.fsPath);
    return uri.scheme === "file" && relative !== ".."
      && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative);
  };
  const request = scanCtrl.startWsScan(contains);
  for (const [key, timer] of pendingOpenScans) {
    if (contains(key)) {
      clearTimeout(timer);
      pendingOpenScans.delete(key);
    }
  }
  const documents = new Map(vscode.workspace.textDocuments.map((document) => [
    document.uri.toString(), { document, version: document.version, dirty: document.isDirty },
  ]));
  const minSeverity = vscode.workspace.getConfiguration("foxguard").get<string>("severity", "low");
  const current = (): boolean => active && scanCtrl.isWsCurrent(request);
  updateStatusBar(vscode.window.activeTextEditor);
  try {
    await vscode.window.withProgress({
      location: vscode.ProgressLocation.Notification,
      title: "foxguard: scanning workspace...",
      cancellable: true,
    }, async (_progress, token) => {
      const cancellation = token.onCancellationRequested(() => request.abort());
      try {
        if (token.isCancellationRequested) {
          request.abort();
        }
        const binary = await resolveBinary();
        if (!current()) {
          return;
        }
        if (binary === undefined) {
          binaryMissing = true;
          void vscode.window.showInformationMessage("foxguard not found. Install it first.");
          return;
        }
        binaryMissing = false;
        const args = ["--format", "json", rootPath];
        if (minSeverity !== "low") {
          args.unshift("--severity", minSeverity);
        }
        if (binary === null) {
          args.unshift("foxguard");
        }
        const { stdout, stderr } = await runProcess(binary ?? "npx", args, {
          maxBuffer: 50 * 1024 * 1024,
          timeout: 120_000,
          allowFindingExit: true,
          signal: request.signal,
        });
        if (!current()) {
          return;
        }
        if (!stdout.trim()) {
          throw new Error("Scanner returned an empty report.");
        }
        const findings = extractFindings(JSON.parse(stdout));
        const byFile = new Map<string, { uri: vscode.Uri; findings: Finding[] }>();
        for (const [key, snapshot] of documents) {
          if (contains(key)) {
            byFile.set(key, { uri: snapshot.document.uri, findings: [] });
          }
        }
        // A valid clean result clears old diagnostics, but only within this
        // workspace and only for files whose scan ownership is unchanged.
        diagnosticCollection.forEach((uri) => {
          if (contains(uri.toString())) {
            byFile.set(uri.toString(), { uri, findings: [] });
          }
        });
        for (const finding of findings) {
          const uri = vscode.Uri.file(path.resolve(rootPath, finding.file));
          const key = uri.toString();
          const group = byFile.get(key) ?? { uri, findings: [] };
          group.findings.push(finding);
          byFile.set(key, group);
        }
        let published = 0;
        let skipped = 0;
        const updates: Array<{ key: string; uri: vscode.Uri; diagnostics: vscode.Diagnostic[] }> = [];
        for (const [key, group] of byFile) {
          const snapshot = documents.get(key);
          const document = vscode.workspace.textDocuments.find((candidate) => candidate.uri.toString() === key);
          if (!scanCtrl.canPublishWorkspace(request, key)
            || snapshot?.document.isClosed
            || snapshot?.dirty
            || document && (!snapshot || document !== snapshot.document
              || document.isDirty || document.version !== snapshot.version)) {
            skipped += 1;
            continue;
          }
          const diagnostics = findingsToDiagnostics(group.findings.filter((finding) => meetsMinSeverity(finding.severity, minSeverity)));
          updates.push({ key, uri: group.uri, diagnostics });
          published += diagnostics.length;
        }
        // Prepare every diagnostic before committing any file, so a malformed
        // later finding cannot leave a partially updated failed report.
        for (const update of updates) {
          diagnosticCollection.set(update.uri, update.diagnostics);
          failedDocuments.delete(update.key);
        }
        if (stderr.trim()) {
          outputChannel.appendLine(stderr.trim());
        }
        void vscode.window.showInformationMessage(
          `foxguard: published ${published} issue${published === 1 ? "" : "s"}.`
          + (skipped ? ` ${skipped} changed or out-of-scope file${skipped === 1 ? "" : "s"} left unchanged.` : ""),
        );
      } finally {
        cancellation.dispose();
      }
    });
  } catch (error) {
    if (!(error instanceof ScanCancelledError) && current()) {
      for (const document of vscode.workspace.textDocuments) {
        if (contains(document.uri.toString())) {
          failedDocuments.add(document.uri.toString());
        }
      }
      outputChannel.appendLine(`Workspace scan failed: ${error instanceof Error ? error.message : String(error)}`);
      void vscode.window.showErrorMessage("foxguard workspace scan failed. See the foxguard output for details.");
    }
  } finally {
    scanCtrl.finishWsScan(request);
    updateStatusBar(vscode.window.activeTextEditor);
  }
}

function findingsToDiagnostics(findings: Finding[]): vscode.Diagnostic[] {
  return findings.map((finding) => {
    const range = new vscode.Range(
      Math.max(0, finding.line - 1), Math.max(0, finding.column - 1),
      Math.max(0, finding.end_line - 1), Math.max(0, finding.end_column - 1),
    );
    const cwe = finding.cwe ? ` (${finding.cwe})` : "";
    const fix = finding.fix_suggestion ? `\nFix: ${finding.fix_suggestion}` : "";
    const diagnostic = new vscode.Diagnostic(
      range, `[${severityEmoji(finding.severity)}] ${finding.description}${cwe}${fix}`,
      mapSeverity(finding.severity),
    );
    diagnostic.source = "foxguard";
    diagnostic.code = {
      value: finding.rule_id,
      target: vscode.Uri.parse("https://github.com/0sec-labs/foxguard#built-in-coverage"),
    };
    return diagnostic;
  });
}