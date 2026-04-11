import * as vscode from 'vscode';

/**
 * Provides quick-fix code actions for SAST findings.
 * Uses only stable VS Code APIs — works in VS Code and Antigravity.
 */
export class SastCodeActionProvider implements vscode.CodeActionProvider {
  static readonly providedCodeActionKinds = [vscode.CodeActionKind.QuickFix];

  provideCodeActions(
    document: vscode.TextDocument,
    range: vscode.Range,
    context: vscode.CodeActionContext,
  ): vscode.CodeAction[] {
    const actions: vscode.CodeAction[] = [];

    for (const diag of context.diagnostics) {
      if (diag.source !== 'Flutter Supabase Helper') continue;

      // Inline suppression action (always available)
      actions.push(this._createSuppressionAction(document, diag));

      // Rule-specific quick fixes
      const code = typeof diag.code === 'string' ? diag.code : String(diag.code ?? '');

      switch (code) {
        case 'injection-flaw':
          actions.push(...this._injectionFixes(document, diag));
          break;
        case 'unsafe-eval':
          actions.push(...this._evalFixes(document, diag));
          break;
        case 'xss-flaw':
          actions.push(...this._xssFixes(document, diag));
          break;
      }
    }

    return actions;
  }

  // ── Suppression Action ──────────────────────────

  private _createSuppressionAction(document: vscode.TextDocument, diag: vscode.Diagnostic): vscode.CodeAction {
    const code = typeof diag.code === 'string' ? diag.code : String(diag.code ?? '');
    const action = new vscode.CodeAction(
      `Suppress: sast-ignore ${code}`,
      vscode.CodeActionKind.QuickFix,
    );

    const lineNum = diag.range.start.line;
    const lineText = document.lineAt(Math.max(0, lineNum)).text;
    const indent = lineText.match(/^(\s*)/)?.[1] ?? '';

    const commentPrefix = this._commentPrefix(document.languageId);
    const suppressionComment = `${indent}${commentPrefix} sast-ignore ${code}\n`;

    const edit = new vscode.WorkspaceEdit();
    edit.insert(document.uri, new vscode.Position(lineNum, 0), suppressionComment);
    action.edit = edit;
    action.diagnostics = [diag];
    action.isPreferred = false;

    return action;
  }

  // ── Injection Fixes ─────────────────────────────

  private _injectionFixes(document: vscode.TextDocument, diag: vscode.Diagnostic): vscode.CodeAction[] {
    const actions: vscode.CodeAction[] = [];
    const lineNum = diag.range.start.line;
    const lineText = document.lineAt(lineNum).text;

    // Suggest parameterized query
    if (/\.query\s*\(/.test(lineText) && /\+/.test(lineText)) {
      const action = new vscode.CodeAction(
        'Use parameterized query instead of string concatenation',
        vscode.CodeActionKind.QuickFix,
      );
      action.diagnostics = [diag];
      action.isPreferred = true;

      // We can't reliably auto-edit arbitrary SQL, so add a helpful comment
      const indent = lineText.match(/^(\s*)/)?.[1] ?? '';
      const edit = new vscode.WorkspaceEdit();
      edit.insert(
        document.uri,
        new vscode.Position(lineNum, 0),
        `${indent}// TODO: Replace string concatenation with parameterized query:\n${indent}// db.query("SELECT * FROM table WHERE id = $1", [id])\n`,
      );
      action.edit = edit;
      actions.push(action);
    }

    return actions;
  }

  // ── Eval Fixes ──────────────────────────────────

  private _evalFixes(document: vscode.TextDocument, diag: vscode.Diagnostic): vscode.CodeAction[] {
    const actions: vscode.CodeAction[] = [];
    const lineNum = diag.range.start.line;
    const lineText = document.lineAt(lineNum).text;

    if (/\beval\s*\(/.test(lineText)) {
      const action = new vscode.CodeAction(
        'Replace eval() with JSON.parse() or safer alternative',
        vscode.CodeActionKind.QuickFix,
      );
      action.diagnostics = [diag];
      action.isPreferred = true;

      const indent = lineText.match(/^(\s*)/)?.[1] ?? '';
      const edit = new vscode.WorkspaceEdit();
      edit.insert(
        document.uri,
        new vscode.Position(lineNum, 0),
        `${indent}// TODO: Replace eval() with JSON.parse() or a safe expression parser\n`,
      );
      action.edit = edit;
      actions.push(action);
    }

    return actions;
  }

  // ── XSS Fixes ───────────────────────────────────

  private _xssFixes(document: vscode.TextDocument, diag: vscode.Diagnostic): vscode.CodeAction[] {
    const actions: vscode.CodeAction[] = [];
    const lineNum = diag.range.start.line;
    const lineText = document.lineAt(lineNum).text;

    if (/\.innerHTML\s*=/.test(lineText)) {
      const action = new vscode.CodeAction(
        'Replace innerHTML with textContent or DOMPurify',
        vscode.CodeActionKind.QuickFix,
      );
      action.diagnostics = [diag];
      action.isPreferred = true;

      const edit = new vscode.WorkspaceEdit();
      const replaced = lineText.replace(/\.innerHTML\s*=/, '.textContent =');
      edit.replace(
        document.uri,
        new vscode.Range(lineNum, 0, lineNum, lineText.length),
        replaced,
      );
      action.edit = edit;
      actions.push(action);
    }

    return actions;
  }

  // ── Helpers ─────────────────────────────────────

  private _commentPrefix(languageId: string): string {
    switch (languageId) {
      case 'python': return '#';
      case 'dart':
      case 'javascript':
      case 'typescript':
      case 'typescriptreact':
      case 'javascriptreact':
      case 'java':
      case 'go':
      default:
        return '//';
    }
  }
}
