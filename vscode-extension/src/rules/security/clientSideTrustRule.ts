import { Rule, RuleStage } from '../rule';
import { Finding, FindingSeverity, FindingCategory, FindingConfidence } from '../../models/finding';
import { ProjectContext } from '../../scanner/projectContext';

export class ClientSideTrustRule implements Rule {
  readonly code = 'client-side-trust';
  readonly stage = RuleStage.fast;

  evaluate(context: ProjectContext): Finding[] {
    const findings: Finding[] = [];
    for (const access of context.tableAccesses) {
      if (!access.usesClientProvidedUserId) { continue; }
      findings.push(new Finding({
        severity: FindingSeverity.medium,
        confidence: FindingConfidence.medium,
        category: FindingCategory.security,
        code: this.code,
        message: 'Supabase query relies on a client-provided user identifier',
        fix: 'Do not trust route params or caller-provided `userId` values for authorization. Enforce ownership with RLS and only use `currentUser.id` as a convenience filter.',
        risk: 'Trusting client-provided user IDs for authorization allows malicious users to spoof actions or access data on behalf of others.',
        filePath: access.file.relativePath,
        line: access.line,
      }));
    }
    return findings;
  }
}
