import * as vscode from 'vscode';
import * as path from 'path';
import { Finding, FindingSeverity } from '../models/finding';
import { ProjectScanReport } from '../scanner/scanner';

export class DiagnosticsProvider {
  private readonly _collection: vscode.DiagnosticCollection;

  constructor() {
    this._collection = vscode.languages.createDiagnosticCollection('flutter-supabase-helper');
  }

  updateDiagnostics(report: ProjectScanReport): void {
    this._collection.clear();
    const byFile = new Map<string, vscode.Diagnostic[]>();

    for (const finding of report.findings) {
      if (finding.isSuggestion) continue;
      if (!finding.filePath) continue;

      const absolutePath = this._resolveAbsolute(report.context.rootPath, finding.filePath);
      if (!absolutePath) continue;

      const diag = this._findingToDiagnostic(finding, absolutePath);
      if (!byFile.has(absolutePath)) byFile.set(absolutePath, []);
      byFile.get(absolutePath)!.push(diag);
    }

    for (const [filePath, diags] of byFile) {
      try {
        const uri = vscode.Uri.file(filePath);
        this._collection.set(uri, diags);
      } catch {
        // Skip files with invalid paths
      }
    }
  }

  clearDiagnostics(): void {
    this._collection.clear();
  }

  dispose(): void {
    this._collection.dispose();
  }

  private _findingToDiagnostic(finding: Finding, absolutePath: string): vscode.Diagnostic {
    const startLine = Math.max(0, (finding.line ?? 1) - 1);
    const startCol = Math.max(0, (finding.column ?? 1) - 1);
    // When AST gave us precise endLine/endColumn, use them so the squiggle
    // covers exactly the offending node rather than the whole line.
    const hasPreciseRange =
      finding.endLine != null && finding.endColumn != null;
    const endLine = hasPreciseRange
      ? Math.max(startLine, (finding.endLine as number) - 1)
      : startLine;
    const endCol = hasPreciseRange
      ? Math.max(0, (finding.endColumn as number) - 1)
      : Number.MAX_SAFE_INTEGER;
    const range = new vscode.Range(startLine, startCol, endLine, endCol);
    const severity = this._mapSeverity(finding.severity);

    const message = finding.risk
      ? `${finding.message}\n→ Risk: ${finding.risk}`
      : finding.message;

    const diag = new vscode.Diagnostic(range, message, severity);
    diag.source = 'Flutter Supabase Helper';
    diag.code = finding.code;

    try {
      diag.relatedInformation = [
        new vscode.DiagnosticRelatedInformation(
          new vscode.Location(
            vscode.Uri.file(absolutePath),
            new vscode.Position(startLine, startCol),
          ),
          `Fix: ${finding.fix}`,
        ),
      ];
    } catch {
      // Skip related info if file URI creation fails
    }

    return diag;
  }

  private _mapSeverity(severity?: FindingSeverity): vscode.DiagnosticSeverity {
    switch (severity) {
      case FindingSeverity.high: return vscode.DiagnosticSeverity.Error;
      case FindingSeverity.medium: return vscode.DiagnosticSeverity.Warning;
      case FindingSeverity.low: return vscode.DiagnosticSeverity.Information;
      default: return vscode.DiagnosticSeverity.Hint;
    }
  }

  private _resolveAbsolute(rootPath: string, filePath: string): string | null {
    if (path.isAbsolute(filePath)) {
      return filePath;
    }
    return path.join(rootPath, filePath);
  }
}
