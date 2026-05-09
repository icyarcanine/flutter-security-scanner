import * as vscode from 'vscode';
import { ProjectScanner } from '../scanner/scanner';
import { DiagnosticsProvider } from '../diagnostics/diagnosticsProvider';
import { PanelProvider } from '../webview/panelProvider';

export async function scanFile(diagnostics: DiagnosticsProvider): Promise<void> {
  const editor = vscode.window.activeTextEditor;
  if (!editor) {
    vscode.window.showInformationMessage(
      'Flutter Supabase Security Scanner: No active editor. Open a Dart file from your Flutter project.',
    );
    return;
  }

  const workspaceFolders = vscode.workspace.workspaceFolders;
  if (!workspaceFolders || workspaceFolders.length === 0) {
    vscode.window.showInformationMessage(
      'Flutter Supabase Security Scanner: No workspace folder open.',
    );
    return;
  }

  // Determine which workspace folder contains the active file
  const fileUri = editor.document.uri;
  const wsFolder = vscode.workspace.getWorkspaceFolder(fileUri) ?? workspaceFolders[0];
  const rootPath = wsFolder.uri.fsPath;

  const config = vscode.workspace.getConfiguration('flutterSupabaseSecurityScanner');
  const includeSuggestions = config.get<boolean>('includeSuggestions', true);
  const disabledRules = config.get<string[]>('disabledRules', []) ?? [];

  try {
    const report = await vscode.window.withProgress(
      {
        location: vscode.ProgressLocation.Notification,
        title: 'Flutter Supabase Security Scanner: Scanning…',
        cancellable: false,
      },
      async () => {
        const scanner = new ProjectScanner({ includeSuggestions, disabledRules });
        return scanner.scan(rootPath);
      },
    );

    diagnostics.updateDiagnostics(report);
    PanelProvider.showReport(report);

    const issues = report.issueCount;
    if (issues === 0) {
      vscode.window.showInformationMessage('Flutter Supabase Security Scanner: No issues found!');
    } else {
      vscode.window.showWarningMessage(
        `Flutter Supabase Security Scanner: Found ${issues} issue${issues !== 1 ? 's' : ''}.`,
        'View Report',
      ).then(choice => {
        if (choice === 'View Report') { PanelProvider.showReport(report); }
      });
    }
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    vscode.window.showErrorMessage(`Flutter Supabase Security Scanner scan failed: ${message}`);
  }
}
