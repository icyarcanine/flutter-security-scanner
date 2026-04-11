import * as vscode from 'vscode';
import { ProjectScanner } from '../scanner/scanner';
import { DiagnosticsProvider } from '../diagnostics/diagnosticsProvider';
import { PanelProvider } from '../webview/panelProvider';

export async function scanWorkspace(
  diagnostics: DiagnosticsProvider,
  statusBar: vscode.StatusBarItem,
): Promise<void> {
  const workspaceFolders = vscode.workspace.workspaceFolders;
  if (!workspaceFolders || workspaceFolders.length === 0) {
    vscode.window.showInformationMessage(
      'Flutter Supabase Helper: No workspace folder open.',
    );
    return;
  }

  const rootPath = workspaceFolders[0].uri.fsPath;
  const config = vscode.workspace.getConfiguration('flutterSupabaseHelper');
  const includeSuggestions = config.get<boolean>('includeSuggestions', true);

  statusBar.text = '$(sync~spin) Scanning…';
  statusBar.show();

  try {
    const report = await vscode.window.withProgress(
      {
        location: vscode.ProgressLocation.Notification,
        title: 'Flutter Supabase Helper',
        cancellable: false,
      },
      async (progress) => {
        progress.report({ message: 'Analyzing project files…' });

        const scanner = new ProjectScanner(includeSuggestions);
        return scanner.scan(rootPath);
      },
    );

    diagnostics.updateDiagnostics(report);
    PanelProvider.showReport(report);

    const issues = report.issueCount;
    const suggestions = report.suggestionCount;
    const duration = report.scanDurationMs;
    const files = report.totalFiles;

    if (issues === 0 && suggestions === 0) {
      statusBar.text = '$(shield) No Issues';
      vscode.window.showInformationMessage(
        `Flutter Supabase Helper: No issues found. Scanned ${files} files in ${duration}ms.`
      );
    } else {
      statusBar.text = `$(warning) ${issues} issue${issues !== 1 ? 's' : ''}`;
      const msg = `Flutter Supabase Helper: Found ${issues} issue${issues !== 1 ? 's' : ''}` +
        (suggestions > 0 ? ` and ${suggestions} suggestion${suggestions !== 1 ? 's' : ''}` : '') +
        `. Scanned ${files} files in ${duration}ms.`;
      vscode.window.showWarningMessage(msg, 'View Report').then(choice => {
        if (choice === 'View Report') {
          PanelProvider.showReport(report);
        }
      });
    }
  } catch (err) {
    statusBar.text = '$(shield) Scan';
    const message = err instanceof Error ? err.message : String(err);
    vscode.window.showErrorMessage(`Flutter Supabase Helper scan failed: ${message}`);
  }
}
