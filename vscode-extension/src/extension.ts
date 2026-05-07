import * as vscode from 'vscode';
import { DiagnosticsProvider } from './diagnostics/diagnosticsProvider';
import { scanWorkspace } from './commands/scanWorkspace';
import { scanFile } from './commands/scanFile';
import { PanelProvider } from './webview/panelProvider';
import { SastCodeActionProvider } from './codeActions';

export function activate(context: vscode.ExtensionContext) {
  try {
    // Initialize providers
    const diagnostics = new DiagnosticsProvider();
    PanelProvider.initialize(context);
    context.subscriptions.push(diagnostics);

    // Status bar item (stable API, works across all VS Code forks)
    const statusBar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
    statusBar.command = 'flutter-supabase-helper.scanWorkspace';
    statusBar.text = '$(shield) Scan';
    statusBar.tooltip = 'Flutter Supabase Helper: Scan Workspace';
    context.subscriptions.push(statusBar);

    // Register commands
    context.subscriptions.push(
      vscode.commands.registerCommand('flutter-supabase-helper.scanWorkspace', () =>
        scanWorkspace(diagnostics, statusBar)
      ),
      vscode.commands.registerCommand('flutter-supabase-helper.scanFile', () =>
        scanFile(diagnostics)
      )
    );

    // Register code action provider for all supported languages
    const supportedLanguages = [
      { language: 'javascript' },
      { language: 'typescript' },
      { language: 'typescriptreact' },
      { language: 'javascriptreact' },
      { language: 'dart' },
      { language: 'python' },
      { language: 'go' },
      { language: 'java' },
    ];

    try {
      const codeActionProvider = new SastCodeActionProvider();
      context.subscriptions.push(
        vscode.languages.registerCodeActionsProvider(
          supportedLanguages,
          codeActionProvider,
          { providedCodeActionKinds: SastCodeActionProvider.providedCodeActionKinds }
        )
      );
    } catch {
      // If code actions registration fails (unlikely but possible in forks), continue without them
      console.error('[SAST] Code actions unavailable in this editor — quick fixes disabled.');
    }

    // Show status bar if workspace is open
    if (vscode.workspace.workspaceFolders && vscode.workspace.workspaceFolders.length > 0) {
      statusBar.show();

      // Auto-scan on open if configured
      const config = vscode.workspace.getConfiguration('flutterSupabaseHelper');
      if (config.get<boolean>('autoScanOnOpen', true)) {
        // Accept any project type (not just Flutter)
        vscode.workspace.findFiles(
          '{**/pubspec.yaml,**/package.json,**/requirements.txt,**/go.mod,**/pom.xml}',
          '{**/node_modules/**,**/dist/**,**/build/**}',
          1
        ).then((uris) => {
          if (uris.length > 0) {
            vscode.commands.executeCommand('flutter-supabase-helper.scanWorkspace');
          }
        });
      }
    }

    // Show status bar when switching to any supported language. Must mirror
    // the language list registered for code actions (`supportedLanguages`
    // above) so React TSX/JSX files don't silently lose the entry point.
    const STATUS_BAR_LANGUAGES = new Set([
      'dart', 'javascript', 'javascriptreact', 'typescript', 'typescriptreact',
      'python', 'go', 'java',
    ]);
    context.subscriptions.push(
      vscode.window.onDidChangeActiveTextEditor(editor => {
        if (editor && STATUS_BAR_LANGUAGES.has(editor.document.languageId)) {
          statusBar.show();
        }
      })
    );

    // ── On-save incremental scan ───────────────────────────────────────────
    // Re-scan the workspace whenever a supported file is saved. Debounced so
    // a flurry of saves coalesces into one scan. Disabled by default to
    // avoid surprising users; opt in via setting.
    let pendingTimeout: NodeJS.Timeout | undefined;
    context.subscriptions.push(
      vscode.workspace.onDidSaveTextDocument(doc => {
        if (!STATUS_BAR_LANGUAGES.has(doc.languageId)) { return; }
        const cfg = vscode.workspace.getConfiguration('flutterSupabaseHelper');
        if (!cfg.get<boolean>('scanOnSave', false)) { return; }
        if (pendingTimeout) { clearTimeout(pendingTimeout); }
        // 750 ms debounce: batches rapid sequential saves; small enough to
        // feel live for a single edit-save cycle.
        pendingTimeout = setTimeout(() => {
          vscode.commands.executeCommand('flutter-supabase-helper.scanWorkspace');
        }, 750);
      }),
    );

  } catch (err) {
    console.error('[SAST] Extension activation failed:', err);
    // Don't re-throw — let the editor handle partial activation gracefully
  }
}

export function deactivate() {
  try {
    PanelProvider.close();
  } catch {
    // Ignore cleanup errors
  }
}
