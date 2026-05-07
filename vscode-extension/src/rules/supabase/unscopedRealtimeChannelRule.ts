import { Rule, RuleStage } from '../rule';
import { Finding, FindingSeverity, FindingCategory, FindingConfidence, DetectionMethod } from '../../models/finding';
import { ProjectContext } from '../../scanner/projectContext';
import { stripLineComment } from '../ruleHelpers';

/**
 * Supabase Realtime scope detector (QW-33 / SF-2, CWE-639).
 *
 * Realtime channels named like `public:posts` are commonly used for Postgres
 * change feeds. Without an ownership filter in the channel/on/subscribe chain,
 * every subscribed client can observe rows outside their tenant/user scope.
 */
export class UnscopedRealtimeChannelRule implements Rule {
  readonly code = 'unscoped-realtime-channel';
  readonly stage = RuleStage.fast;

  private static readonly _CHANNEL = /\.channel\s*\(\s*['"]([^'"]+)['"]/g;

  evaluate(context: ProjectContext): Finding[] {
    const findings: Finding[] = [];
    for (const file of context.files) {
      if (!/\.(?:dart|js|jsx|ts|tsx|mjs|cjs)$/i.test(file.name)) { continue; }
      if (!/\.channel\s*\(/.test(file.content) || !/\.subscribe\s*\(/.test(file.content)) { continue; }

      UnscopedRealtimeChannelRule._CHANNEL.lastIndex = 0;
      let m: RegExpExecArray | null;
      while ((m = UnscopedRealtimeChannelRule._CHANNEL.exec(file.content)) !== null) {
        const channel = m[1] ?? '';
        if (!/^[A-Za-z_][\w-]*:[A-Za-z_][\w-]*$/.test(channel)) { continue; }
        const snippet = this._statementWindow(file.content, m.index);
        if (!/\.subscribe\s*\(/.test(snippet)) { continue; }
        if (this._hasOwnershipFilter(snippet)) { continue; }

        findings.push(new Finding({
          category: FindingCategory.supabase,
          code: this.code,
          severity: FindingSeverity.high,
          confidence: FindingConfidence.medium,
          detectionMethod: DetectionMethod.regex,
          message: `Realtime channel \`${channel}\` appears unscoped.`,
          fix: 'Add an ownership filter to the realtime subscription, for example `.eq("user_id", userId)` or the Supabase `filter: "user_id=eq.<uid>"` equivalent, and keep RLS enabled server-side.',
          risk: 'Unscoped realtime feeds can leak other users\' row changes to any client subscribed to the channel.',
          filePath: file.relativePath,
          line: file.lineForOffset(m.index),
          cwe: 'CWE-639',
        }));
      }
    }
    return findings;
  }

  private _statementWindow(content: string, start: number): string {
    const before = Math.max(0, content.lastIndexOf(';', start - 1));
    let end = content.indexOf(';', start);
    if (end === -1) { end = Math.min(content.length, start + 1600); }
    return stripLineComment(content.slice(before, end + 1));
  }

  private _hasOwnershipFilter(snippet: string): boolean {
    return /\.eq\s*\(\s*['"](?:user_id|owner_id|profile_id|tenant_id|account_id|organization_id|org_id)['"]/i.test(snippet) ||
      /\bfilter\s*:\s*['"][^'"]*(?:user_id|owner_id|profile_id|tenant_id|account_id|organization_id|org_id)\s*=/.test(snippet) ||
      /\bcolumn\s*:\s*['"](?:user_id|owner_id|profile_id|tenant_id|account_id|organization_id|org_id)['"]/i.test(snippet) ||
      /\bauth\s*\.\s*uid\s*\(/i.test(snippet);
  }
}
