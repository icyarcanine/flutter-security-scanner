import * as vscode from 'vscode';
import { ProjectScanner, ProjectScanReport } from '../scanner/scanner';
import { DiagnosticsProvider } from '../diagnostics/diagnosticsProvider';
import { PanelProvider } from '../webview/panelProvider';

/**
 * One-click "Run Security Checks" command.
 *
 * This is the primary surface new developers should hit. It runs every rule
 * the extension knows about against the open workspace, drops the results
 * into the diagnostics gutter and the report panel, and pops a single
 * notification with a severity breakdown plus action buttons.
 *
 * It deliberately reuses the same scanner that `scanWorkspace` calls so the
 * two entry points can never drift apart.
 */
export async function runSecurityChecks(
  diagnostics: DiagnosticsProvider,
  statusBar: vscode.StatusBarItem,
): Promise<void> {
  const workspaceFolders = vscode.workspace.workspaceFolders;
  if (!workspaceFolders || workspaceFolders.length === 0) {
    vscode.window.showWarningMessage(
      'Flutter Supabase Security Scanner: open a folder first, then run the security checks.',
    );
    return;
  }

  const rootPath = workspaceFolders[0].uri.fsPath;
  const config = vscode.workspace.getConfiguration('flutterSupabaseSecurityScanner');
  const includeSuggestions = config.get<boolean>('includeSuggestions', true);

  statusBar.text = '$(sync~spin) Scanning…';
  statusBar.tooltip = 'Flutter Supabase Security Scanner: scanning workspace…';
  statusBar.show();

  let report: ProjectScanReport;
  try {
    report = await vscode.window.withProgress(
      {
        location: vscode.ProgressLocation.Notification,
        title: 'Flutter Supabase Security Scanner — Running security checks',
        cancellable: false,
      },
      async (progress) => {
        progress.report({ message: 'Loading project files…' });
        const scanner = new ProjectScanner(includeSuggestions);
        const result = await scanner.scan(rootPath);
        progress.report({
          message: `Analyzed ${result.totalFiles} files in ${result.scanDurationMs} ms.`,
        });
        return result;
      },
    );
  } catch (err) {
    statusBar.text = '$(shield) Scan';
    statusBar.tooltip = 'Flutter Supabase Security Scanner: Run Security Checks';
    const message = err instanceof Error ? err.message : String(err);
    void vscode.window.showErrorMessage(
      `Flutter Supabase Security Scanner: scan failed — ${message}`,
    );
    return;
  }

  diagnostics.updateDiagnostics(report);
  PanelProvider.showReport(report);

  _updateStatusBar(statusBar, report);
  await _showSummaryNotification(report);
}

/**
 * Re-paint the status bar item to reflect the latest scan result. The text
 * stays compact (status bar real estate is precious) but the tooltip carries
 * the full breakdown.
 */
function _updateStatusBar(
  statusBar: vscode.StatusBarItem,
  report: ProjectScanReport,
): void {
  const issues = report.issueCount;
  const high = report.highCount;
  const medium = report.mediumCount;
  const low = report.lowCount;
  const suggestions = report.suggestionCount;

  if (issues === 0 && suggestions === 0) {
    statusBar.text = '$(shield) Clean';
    statusBar.tooltip =
      `Flutter Supabase Security Scanner: scanned ${report.totalFiles} files in ${report.scanDurationMs} ms — no issues found.\nClick to re-run.`;
    statusBar.backgroundColor = undefined;
  } else if (high > 0) {
    statusBar.text = `$(error) ${issues} issue${issues === 1 ? '' : 's'}`;
    statusBar.tooltip =
      `Flutter Supabase Security Scanner: ${high} high, ${medium} medium, ${low} low across ${report.totalFiles} files.\nClick to re-run.`;
    statusBar.backgroundColor = new vscode.ThemeColor(
      'statusBarItem.errorBackground',
    );
  } else if (medium > 0) {
    statusBar.text = `$(warning) ${issues} issue${issues === 1 ? '' : 's'}`;
    statusBar.tooltip =
      `Flutter Supabase Security Scanner: ${medium} medium, ${low} low across ${report.totalFiles} files.\nClick to re-run.`;
    statusBar.backgroundColor = new vscode.ThemeColor(
      'statusBarItem.warningBackground',
    );
  } else {
    statusBar.text = `$(info) ${issues + suggestions} item${issues + suggestions === 1 ? '' : 's'}`;
    statusBar.tooltip =
      `Flutter Supabase Security Scanner: ${low} low-severity findings, ${suggestions} suggestions across ${report.totalFiles} files.\nClick to re-run.`;
    statusBar.backgroundColor = undefined;
  }
}

/**
 * Pops the post-scan notification. Keeps the noise floor low: one toast,
 * with action buttons that take the developer somewhere useful.
 */
async function _showSummaryNotification(
  report: ProjectScanReport,
): Promise<void> {
  const issues = report.issueCount;
  const suggestions = report.suggestionCount;
  const high = report.highCount;
  const medium = report.mediumCount;
  const low = report.lowCount;
  const stats = `${report.totalFiles} files in ${report.scanDurationMs} ms`;

  if (issues === 0 && suggestions === 0) {
    void vscode.window.showInformationMessage(
      `Flutter Supabase Security Scanner: clean bill of health. Scanned ${stats}.`,
    );
    return;
  }

  // Build a compact severity breakdown.
  const parts: string[] = [];
  if (high > 0) {
    parts.push(`${high} high`);
  }
  if (medium > 0) {
    parts.push(`${medium} medium`);
  }
  if (low > 0) {
    parts.push(`${low} low`);
  }
  if (suggestions > 0) {
    parts.push(`${suggestions} suggestion${suggestions === 1 ? '' : 's'}`);
  }
  const breakdown = parts.length > 0 ? parts.join(', ') : `${issues} item${issues === 1 ? '' : 's'}`;

  const summary = `Flutter Supabase Security Scanner: ${breakdown}. Scanned ${stats}.`;

  const action = high > 0
    ? await vscode.window.showErrorMessage(summary, 'View Report', 'Open Problems')
    : await vscode.window.showWarningMessage(summary, 'View Report', 'Open Problems');

  if (action === 'View Report') {
    PanelProvider.showReport(report);
  } else if (action === 'Open Problems') {
    void vscode.commands.executeCommand('workbench.actions.view.problems');
  }
}
