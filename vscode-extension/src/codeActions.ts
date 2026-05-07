import * as vscode from 'vscode';

/**
 * Provides quick-fix code actions for SAST findings.
 * Uses only stable VS Code APIs — works in VS Code and Antigravity.
 */
export class SastCodeActionProvider implements vscode.CodeActionProvider {
  static readonly providedCodeActionKinds = [vscode.CodeActionKind.QuickFix];

  provideCodeActions(
    document: vscode.TextDocument,
    _range: vscode.Range,
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
        case 'xss-flaw':
          actions.push(...this._xssFixes(document, diag));
          break;
        case 'insecure-random':
          actions.push(...this._insecureRandomFixes(document, diag));
          break;
        case 'insecure-cookie':
          actions.push(...this._insecureCookieFixes(document, diag));
          break;
        case 'jwt-misuse':
          actions.push(...this._jwtMisuseFixes(document, diag));
          break;
        // Note: `unsafe-eval` has no rule-specific quick-fix because no safe
        // automatic rewrite of eval() exists. Users still get the
        // suppression action above.
      }
    }

    return actions;
  }

  // ── Insecure-random autofix ─────────────────────
  // `Math.random()` → `crypto.randomUUID()` for clear identifier-shaped use,
  // else `crypto.randomBytes(16).toString('hex')`. Browsers should use
  // `crypto.getRandomValues`; the rule's heuristic targets server-side code
  // primarily, so the Node-style fix is the default.

  private _insecureRandomFixes(document: vscode.TextDocument, diag: vscode.Diagnostic): vscode.CodeAction[] {
    const actions: vscode.CodeAction[] = [];
    const lineNum = diag.range.start.line;
    const lineText = document.lineAt(lineNum).text;

    if (!/Math\.random\s*\(\s*\)/.test(lineText)) { return actions; }

    // If they're chaining .toString(36).slice(...) it's clearly an ID — use randomUUID.
    const looksLikeId = /\.toString\s*\(\s*36\s*\)|\.slice\s*\(/.test(lineText);
    const replacement = looksLikeId
      ? 'crypto.randomUUID()'
      : `crypto.randomBytes(16).toString('hex')`;

    const action = new vscode.CodeAction(
      `Replace Math.random() with ${replacement}`,
      vscode.CodeActionKind.QuickFix,
    );
    action.diagnostics = [diag];
    action.isPreferred = true;

    // Replace ONLY the Math.random() call; rest of the line untouched.
    const matchIdx = lineText.search(/Math\.random\s*\(\s*\)/);
    const matchEnd = lineText.indexOf(')', matchIdx) + 1;
    const edit = new vscode.WorkspaceEdit();
    edit.replace(
      document.uri,
      new vscode.Range(lineNum, matchIdx, lineNum, matchEnd),
      replacement,
    );
    action.edit = edit;
    actions.push(action);

    return actions;
  }

  // ── Insecure-cookie autofix ─────────────────────
  // Toggle the bad value to its secure counterpart.

  private _insecureCookieFixes(document: vscode.TextDocument, diag: vscode.Diagnostic): vscode.CodeAction[] {
    const actions: vscode.CodeAction[] = [];
    const lineNum = diag.range.start.line;
    const lineText = document.lineAt(lineNum).text;

    const flips: Array<{ from: RegExp; to: string; label: string }> = [
      { from: /\bhttpOnly\s*:\s*false\b/, to: 'httpOnly: true', label: 'Set httpOnly: true' },
      { from: /\bsecure\s*:\s*false\b/,   to: 'secure: true',   label: 'Set secure: true' },
    ];
    for (const { from, to, label } of flips) {
      const idx = lineText.search(from);
      if (idx === -1) { continue; }
      const matchText = lineText.match(from)![0];
      const action = new vscode.CodeAction(label, vscode.CodeActionKind.QuickFix);
      action.diagnostics = [diag];
      action.isPreferred = true;
      const edit = new vscode.WorkspaceEdit();
      edit.replace(
        document.uri,
        new vscode.Range(lineNum, idx, lineNum, idx + matchText.length),
        to,
      );
      action.edit = edit;
      actions.push(action);
    }
    return actions;
  }

  // ── JWT misuse autofix ──────────────────────────

  private _jwtMisuseFixes(document: vscode.TextDocument, diag: vscode.Diagnostic): vscode.CodeAction[] {
    const actions: vscode.CodeAction[] = [];
    const lineNum = diag.range.start.line;
    const lineText = document.lineAt(lineNum).text;

    // jwt.decode has no safe automatic rewrite — verify(token, secret, {...})
    // requires a secret the user must supply, and we can't synthesize one.
    // The rule's `fix` field (shown in the diagnostic and webview) already
    // explains the recommended replacement; we don't offer a placeholder
    // quick-fix here.

    // algorithms: ['none'] → ['HS256'] (HS256 is the safer default).
    const noneMatch = lineText.match(/algorithms\s*:\s*\[\s*['"]none['"]\s*\]/);
    if (noneMatch) {
      const idx = lineText.indexOf(noneMatch[0]);
      const action = new vscode.CodeAction(
        `Replace algorithms: ['none'] with algorithms: ['HS256']`,
        vscode.CodeActionKind.QuickFix,
      );
      action.diagnostics = [diag];
      action.isPreferred = true;
      const edit = new vscode.WorkspaceEdit();
      edit.replace(
        document.uri,
        new vscode.Range(lineNum, idx, lineNum, idx + noneMatch[0].length),
        `algorithms: ['HS256']`,
      );
      action.edit = edit;
      actions.push(action);
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

    // Real autofix for the simple shape:
    //   xxx.query("…" + ident)  →  xxx.query("…?", [ident])
    // Only matches when there's exactly one concat slot — anything more
    // complex bails out and the rule's `fix` text guides the user manually.
    const simpleConcat = lineText.match(
      /(\.\s*(?:query|execute|rawQuery)\s*\(\s*)(['"])([^'"]*?)\2\s*\+\s*([A-Za-z_$][A-Za-z0-9_$.]*)\s*\)/,
    );
    if (simpleConcat) {
      const [whole, openCall, quote, sqlText, ident] = simpleConcat;
      const idx = lineText.indexOf(whole);
      const action = new vscode.CodeAction(
        'Convert to parameterized query',
        vscode.CodeActionKind.QuickFix,
      );
      action.diagnostics = [diag];
      action.isPreferred = true;
      const replacement = `${openCall}${quote}${sqlText}?${quote}, [${ident}])`;
      const edit = new vscode.WorkspaceEdit();
      edit.replace(
        document.uri,
        new vscode.Range(lineNum, idx, lineNum, idx + whole.length),
        replacement,
      );
      action.edit = edit;
      actions.push(action);
      return actions;
    }

    // Complex SQL concatenation (multiple operands, function calls, etc.)
    // is not auto-rewriteable without changing semantics. The rule's `fix`
    // text already explains the parameterized-query pattern; no quick-fix
    // is offered here.
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
