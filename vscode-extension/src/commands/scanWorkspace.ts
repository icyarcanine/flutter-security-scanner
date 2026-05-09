import * as vscode from 'vscode';
import { ProjectScanner, ProjectScanReport } from '../scanner/scanner';
import { DiagnosticsProvider } from '../diagnostics/diagnosticsProvider';
import { PanelProvider } from '../webview/panelProvider';
import { mergeReports } from '../scanner/mergeReports';

export async function scanWorkspace(
  diagnostics: DiagnosticsProvider,
  statusBar: vscode.StatusBarItem,
): Promise<void> {
  const workspaceFolders = vscode.workspace.workspaceFolders;
  if (!workspaceFolders || workspaceFolders.length === 0) {
    vscode.window.showInformationMessage(
      'Flutter Supabase Security Scanner: No workspace folder open.',
    );
    return;
  }

  const config = vscode.workspace.getConfiguration('flutterSupabaseSecurityScanner');
  const includeSuggestions = config.get<boolean>('includeSuggestions', true);
  const disabledRules = config.get<string[]>('disabledRules', []) ?? [];

  statusBar.text = '$(sync~spin) Scanning…';
  statusBar.show();

  try {
    const report = await vscode.window.withProgress(
      {
        location: vscode.ProgressLocation.Notification,
        title: 'Flutter Supabase Security Scanner',
        cancellable: true,
      },
      async (progress, token): Promise<ProjectScanReport> => {
        const scanner = new ProjectScanner({ includeSuggestions, disabledRules });
        const reports: ProjectScanReport[] = [];

        for (let i = 0; i < workspaceFolders.length; i++) {
          if (token.isCancellationRequested) { break; }
          const folder = workspaceFolders[i];
          const label = workspaceFolders.length > 1
            ? `Scanning ${folder.name} (${i + 1}/${workspaceFolders.length})…`
            : 'Analyzing project files…';
          progress.report({ message: label });

          // Each folder gets its own scan; results are merged below.
          // Per-folder errors do not abort the full scan.
          try {
            const folderPrefix = workspaceFolders.length > 1 ? `${folder.name}: ` : '';
            const r = await scanner.scan(folder.uri.fsPath, (_phase, detail) => {
              if (token.isCancellationRequested) { return; }
              progress.report({ message: `${folderPrefix}${detail}` });
            });
            reports.push(r);
          } catch (err) {
            const message = err instanceof Error ? err.message : String(err);
            vscode.window.showWarningMessage(
              `Flutter Supabase Security Scanner: skipped "${folder.name}" — ${message}`,
            );
          }
        }

        if (reports.length === 0) {
          // Fall back to an empty report shape so downstream code doesn't crash.
          return await scanner.scan(workspaceFolders[0].uri.fsPath);
        }

        return mergeReports(reports);
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
        `Flutter Supabase Security Scanner: No issues found. Scanned ${files} files in ${duration}ms.`
      );
    } else {
      statusBar.text = `$(warning) ${issues} issue${issues !== 1 ? 's' : ''}`;
      const msg = `Flutter Supabase Security Scanner: Found ${issues} issue${issues !== 1 ? 's' : ''}` +
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
    vscode.window.showErrorMessage(`Flutter Supabase Security Scanner scan failed: ${message}`);
  }
}
