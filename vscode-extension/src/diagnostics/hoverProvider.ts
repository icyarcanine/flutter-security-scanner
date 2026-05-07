import * as vscode from 'vscode';
import { Finding, FindingSeverity, FindingConfidence } from '../models/finding';
import { DiagnosticsProvider } from './diagnosticsProvider';

/**
 * §IN-16 — Explanation hover provider.
 *
 * When the user hovers over a flagged line, show a richer card than the
 * built-in diagnostic tooltip: rule name + severity badge, the message,
 * the recommended fix, optional risk explanation, and CWE links pointing
 * to the official MITRE pages.
 *
 * The provider doesn't run any analysis itself — it consults the
 * `DiagnosticsProvider`'s in-memory finding index that's already built
 * during `updateDiagnostics()`. That keeps hover output perfectly in sync
 * with the squiggle the user is hovering and avoids an extra scan path.
 */
export class FindingHoverProvider implements vscode.HoverProvider {
  constructor(private readonly _diagnostics: DiagnosticsProvider) {}

  provideHover(
    document: vscode.TextDocument,
    position: vscode.Position,
  ): vscode.ProviderResult<vscode.Hover> {
    const findings = this._diagnostics.findingsAtLine(document.uri, position.line);
    if (findings.length === 0) return undefined;

    const md = new vscode.MarkdownString(undefined, true);
    md.isTrusted = true;
    md.supportHtml = false;
    for (const finding of findings) {
      md.appendMarkdown(this._renderFinding(finding));
      md.appendMarkdown('\n\n---\n\n');
    }
    return new vscode.Hover(md);
  }

  private _renderFinding(f: Finding): string {
    const sev = this._severityBadge(f.severity);
    const conf = this._confidenceBadge(f.confidence);
    const lines: string[] = [];
    lines.push(`### ${sev} \`${f.code}\` ${conf}`);
    lines.push('');
    lines.push(f.message.replace(/\n/g, '  \n'));
    if (f.risk) {
      lines.push('');
      lines.push(`**Risk** — ${f.risk}`);
    }
    if (f.fix) {
      lines.push('');
      lines.push(`**Fix** — ${f.fix}`);
    }
    const cweList = this._cweLinks(f);
    if (cweList) {
      lines.push('');
      lines.push(`**CWE** — ${cweList}`);
    }
    return lines.join('\n');
  }

  private _severityBadge(s?: FindingSeverity): string {
    switch (s) {
      case FindingSeverity.high: return '$(error) HIGH';
      case FindingSeverity.medium: return '$(warning) MEDIUM';
      case FindingSeverity.low: return '$(info) LOW';
      default: return '$(circle-outline) NOTE';
    }
  }

  private _confidenceBadge(c?: FindingConfidence | string): string {
    if (c === FindingConfidence.high || c === 'high') return '· _high confidence_';
    if (c === FindingConfidence.medium || c === 'medium') return '· _medium confidence_';
    if (c === FindingConfidence.low || c === 'low') return '· _low confidence — review_';
    return '';
  }

  private _cweLinks(f: Finding): string | null {
    const raw = (f as Finding & { cwe?: string | string[] }).cwe;
    if (!raw) return null;
    const ids = Array.isArray(raw) ? raw : [raw];
    if (ids.length === 0) return null;
    return ids
      .map(id => {
        const numeric = id.replace(/^CWE-/i, '');
        return `[${id}](https://cwe.mitre.org/data/definitions/${numeric}.html)`;
      })
      .join(', ');
  }
}
