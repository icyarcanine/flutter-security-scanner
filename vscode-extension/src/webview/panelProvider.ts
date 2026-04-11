import * as vscode from 'vscode';
import * as path from 'path';
import * as fs from 'fs';
import { ProjectScanReport } from '../scanner/scanner';
import { Finding } from '../models/finding';

export class PanelProvider {
  private static _panel: vscode.WebviewPanel | undefined;
  private static _context: vscode.ExtensionContext | undefined;

  static initialize(context: vscode.ExtensionContext): void {
    PanelProvider._context = context;
  }

  static showReport(report: ProjectScanReport): void {
    const ctx = PanelProvider._context;
    if (!ctx) { return; }

    if (PanelProvider._panel) {
      PanelProvider._panel.reveal(vscode.ViewColumn.Two);
    } else {
      PanelProvider._panel = vscode.window.createWebviewPanel(
        'flutterSupabaseHelper',
        'Flutter Supabase Helper',
        vscode.ViewColumn.Two,
        {
          enableScripts: true,
          retainContextWhenHidden: true,
          localResourceRoots: [vscode.Uri.joinPath(ctx.extensionUri, 'media')],
        },
      );

      PanelProvider._panel.onDidDispose(() => {
        PanelProvider._panel = undefined;
      });

      PanelProvider._panel.webview.onDidReceiveMessage(async (message) => {
        if (message.command === 'openFile') {
          const { filePath, line } = message;
          try {
            const doc = await vscode.workspace.openTextDocument(filePath);
            const editor = await vscode.window.showTextDocument(doc, vscode.ViewColumn.One);
            const lineNum = Math.max(0, (line ?? 1) - 1);
            editor.revealRange(
              new vscode.Range(lineNum, 0, lineNum, 0),
              vscode.TextEditorRevealType.InCenter,
            );
            editor.selection = new vscode.Selection(lineNum, 0, lineNum, 0);
          } catch (e) {
            vscode.window.showErrorMessage(`Could not open file: ${filePath}`);
          }
        }
      });
    }

    PanelProvider._panel.webview.html = PanelProvider._getHtml(
      PanelProvider._panel.webview,
      ctx,
      report,
    );
  }

  static close(): void {
    PanelProvider._panel?.dispose();
  }

  private static _getHtml(
    webview: vscode.Webview,
    ctx: vscode.ExtensionContext,
    report: ProjectScanReport,
  ): string {
    const mediaDir = path.join(ctx.extensionPath, 'media');

    let htmlContent = '';
    let cssContent = '';
    let jsContent = '';

    try {
      htmlContent = fs.readFileSync(path.join(mediaDir, 'webview.html'), 'utf8');
      cssContent = fs.readFileSync(path.join(mediaDir, 'webview.css'), 'utf8');
      jsContent = fs.readFileSync(path.join(mediaDir, 'webview.js'), 'utf8');
    } catch {
      // Fallback if media files missing
      return `<html><body><p>Media files not found. Please rebuild the extension.</p></body></html>`;
    }

    const nonce = PanelProvider._nonce();
    const findings = report.findings.map(f => PanelProvider._serializeFinding(f, report.context.rootPath));

    const reportData = JSON.stringify({
      findings,
      rootPath: report.context.rootPath,
      issueCount: report.issueCount,
      suggestionCount: report.suggestionCount,
      highCount: report.highCount,
      mediumCount: report.mediumCount,
      lowCount: report.lowCount,
      astSuccessRate: report.astSuccessRate,
      scanDurationMs: report.scanDurationMs,
      totalFiles: report.totalFiles,
    });

    // Inject CSS, JS, and data into HTML template
    let html = htmlContent
      .replace('{{STYLE}}', `<style nonce="${nonce}">${cssContent}</style>`)
      .replace('{{SCRIPT}}', `<script nonce="${nonce}">
const vscode = acquireVsCodeApi();
const REPORT_DATA = ${reportData};
${jsContent}
</script>`)
      .replace(/{{NONCE}}/g, nonce);

    return html;
  }

  private static _serializeFinding(finding: Finding, rootPath: string): Record<string, unknown> {
    let absolutePath: string | undefined;
    if (finding.filePath) {
      if (finding.filePath.startsWith('/') || /^[A-Za-z]:/.test(finding.filePath)) {
        absolutePath = finding.filePath;
      } else {
        absolutePath = path.join(rootPath, finding.filePath);
      }
    }

    return {
      severity: finding.severity,
      category: finding.category,
      confidence: finding.confidence,
      code: finding.code,
      message: finding.message,
      fix: finding.fix,
      risk: finding.risk,
      filePath: finding.filePath,
      absolutePath,
      line: finding.line,
      isSuggestion: finding.isSuggestion,
      astUsed: finding.astUsed ?? null,
    };
  }

  private static _nonce(): string {
    let text = '';
    const possible = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    for (let i = 0; i < 32; i++) {
      text += possible.charAt(Math.floor(Math.random() * possible.length));
    }
    return text;
  }
}
