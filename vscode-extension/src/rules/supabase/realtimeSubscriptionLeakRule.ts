import { Rule, RuleStage } from '../rule';
import { Finding, FindingSeverity, FindingCategory, FindingConfidence, DetectionMethod } from '../../models/finding';
import { ProjectContext } from '../../scanner/projectContext';
import { stripLineComment } from '../ruleHelpers';

/**
 * Supabase Realtime subscription leak detector (QW-34 / SF-25).
 *
 * A subscribed channel should be cleaned up by `unsubscribe()` or
 * `supabase.removeChannel(...)` when the widget/component/controller is
 * disposed. This rule flags the high-signal shape where the subscription is
 * stored in a local variable but never cleaned up in the same file.
 */
export class RealtimeSubscriptionLeakRule implements Rule {
  readonly code = 'realtime-subscription-leak';
  readonly stage = RuleStage.fast;

  private static readonly _ASSIGNED_SUBSCRIBE =
    /\b(?:final|var|const|let)?\s*(?:[A-Za-z_<>,?\s]+\s+)?([A-Za-z_$][\w$]*)\s*=\s*(?:await\s*)?[\s\S]{0,260}?\.subscribe\s*\(/g;

  evaluate(context: ProjectContext): Finding[] {
    const findings: Finding[] = [];
    for (const file of context.files) {
      if (!/\.(?:dart|js|jsx|ts|tsx|mjs|cjs)$/i.test(file.name)) { continue; }
      if (!/\.subscribe\s*\(/.test(file.content) || !/\.channel\s*\(/.test(file.content)) { continue; }

      RealtimeSubscriptionLeakRule._ASSIGNED_SUBSCRIBE.lastIndex = 0;
      let m: RegExpExecArray | null;
      while ((m = RealtimeSubscriptionLeakRule._ASSIGNED_SUBSCRIBE.exec(file.content)) !== null) {
        const name = m[1] ?? '';
        if (!name || !/sub|channel|room|feed/i.test(name)) { continue; }
        const line = file.lineForOffset(m.index);
        if (this._isCommentLine(file.lines[line - 1] ?? '')) { continue; }
        if (this._hasCleanup(file.content, name)) { continue; }
        findings.push(new Finding({
          category: FindingCategory.supabase,
          code: this.code,
          severity: FindingSeverity.medium,
          confidence: FindingConfidence.medium,
          detectionMethod: DetectionMethod.regex,
          message: `Realtime subscription \`${name}\` is not cleaned up in this file.`,
          fix: 'Call `unsubscribe()` / `supabase.removeChannel(...)` from dispose, unmount, or the matching cleanup callback.',
          risk: 'Forgotten realtime subscriptions keep sockets and callbacks alive, leaking memory and continuing to receive row changes after the UI no longer needs them.',
          filePath: file.relativePath,
          line,
          cwe: 'CWE-772',
        }));
      }
    }
    return findings;
  }

  private _hasCleanup(content: string, name: string): boolean {
    const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const cleanup = new RegExp(
      String.raw`\b${escaped}\s*\.\s*unsubscribe\s*\(|\bremoveChannel\s*\(\s*${escaped}\b|\bremoveSubscription\s*\(\s*${escaped}\b`,
      'i',
    );
    return cleanup.test(content);
  }

  private _isCommentLine(line: string): boolean {
    return stripLineComment(line).trim().length === 0 && line.trimStart().startsWith('//');
  }
}
