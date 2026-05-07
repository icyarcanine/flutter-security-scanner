import { Rule, RuleStage } from '../rule';
import { Finding, FindingSeverity, FindingCategory, FindingConfidence, DetectionMethod } from '../../models/finding';
import { ProjectContext } from '../../scanner/projectContext';
import { stripLineComment } from '../ruleHelpers';

/**
 * Information exposure through caught exceptions (§QW-43 / §RC-18, CWE-209).
 *
 * Sending the raw error object — and especially `err.stack` — back to the
 * user reveals filesystem paths, library versions, ORM internals, prepared
 * SQL strings, and (in JS) line/column references that map straight to
 * source. Attackers reconnaissance the stack trace to chain into the next
 * vuln. A safe handler logs the error server-side and returns an opaque
 * error code or a generic "Internal server error" body.
 *
 * Pattern shapes covered:
 *   - `res.send(err.stack)` / `res.send(err.message)` / `res.send(err)`
 *   - `res.json({ error: err.stack | err })`
 *   - `res.status(500).send(err)` / `.json(err)`
 *   - `reply.send(err)` (Fastify) / `ctx.body = err` (Koa) / `next(err)` is OK.
 *
 * `err.message` alone is graded MEDIUM — it's sometimes legitimate (a
 * validation error reflected back). Stack / full-error are HIGH.
 */
export class ErrorInfoDisclosureRule implements Rule {
  readonly code = 'error-info-disclosure';
  readonly stage = RuleStage.fast;

  // Catch-clause var names we treat as "the error" — common conventions.
  private static readonly _ERROR_VAR = '(?:err|error|e|exception|ex)';

  // Match `<sender>(<value>)` where sender is a recognised response
  // method and value contains the error variable. Keep the capture
  // permissive; we narrow the sub-shape (stack vs message vs raw) below.
  private static readonly _SEND_CALL = new RegExp(
    String.raw`\b(?:res|reply|response)\b(?:\.[\w]+\([^)]*\))?\s*\.\s*(?:send|json|end|write)\s*\(([^)]*)\)`,
    'g',
  );

  // Koa-style assignment: `ctx.body = err.stack`
  private static readonly _CTX_ASSIGN = new RegExp(
    String.raw`\bctx\s*\.\s*body\s*=\s*([^;]+)`,
    'g',
  );

  evaluate(context: ProjectContext): Finding[] {
    const findings: Finding[] = [];
    const errVar = ErrorInfoDisclosureRule._ERROR_VAR;
    const stackRe = new RegExp(String.raw`\b${errVar}\s*\.\s*stack\b`);
    const messageRe = new RegExp(String.raw`\b${errVar}\s*\.\s*message\b`);
    // "raw" sends — bare `res.send(err)` or `res.json({ ...err })`.
    const rawRe = new RegExp(
      String.raw`(?:^|[^.\w])${errVar}\s*[,)}]|\.\.\.\s*${errVar}\b|:\s*${errVar}\s*[,}]`,
    );

    for (const file of context.files) {
      if (!/\.(?:js|jsx|ts|tsx|mjs|cjs)$/i.test(file.name)) { continue; }
      if (!/\b(?:res|reply|response|ctx)\b/.test(file.content)) { continue; }

      for (let i = 0; i < file.lines.length; i++) {
        const raw = stripLineComment(file.lines[i]);
        if (!raw) { continue; }

        for (const re of [ErrorInfoDisclosureRule._SEND_CALL, ErrorInfoDisclosureRule._CTX_ASSIGN]) {
          re.lastIndex = 0;
          let m: RegExpExecArray | null;
          while ((m = re.exec(raw)) !== null) {
            const arg = m[1] ?? '';
            if (stackRe.test(arg)) {
              findings.push(this._make(file.relativePath, i + 1, 'stack', FindingSeverity.high));
            } else if (rawRe.test(arg)) {
              // Raw error object — we don't know what consumers will see; treat as HIGH.
              findings.push(this._make(file.relativePath, i + 1, 'raw', FindingSeverity.high));
            } else if (messageRe.test(arg)) {
              findings.push(this._make(file.relativePath, i + 1, 'message', FindingSeverity.medium));
            }
          }
        }
      }
    }
    return findings;
  }

  private _make(filePath: string, line: number, kind: 'stack' | 'raw' | 'message', severity: FindingSeverity): Finding {
    let message: string;
    let fix: string;
    let risk: string;
    switch (kind) {
      case 'stack':
        message = 'Error stack trace returned in the HTTP response.';
        fix = 'Log the stack server-side; respond with a generic message and a correlation ID. Never echo `err.stack` to clients.';
        risk = 'Stack traces leak filesystem paths, dependency versions, prepared SQL strings, and line refs that attackers chain into the next exploit.';
        break;
      case 'raw':
        message = 'Raw error object returned in the HTTP response.';
        fix = 'Wrap responses in a generic shape (e.g. `{ error: "Internal server error", id: <uuid> }`). Don\'t spread or pass the caught error object directly.';
        risk = 'Default JSON serialization of an Error object includes the message and (in some runtimes) the stack — equivalent to the leak above.';
        break;
      case 'message':
        message = 'Error message returned in the HTTP response.';
        fix = 'Some validation messages are safe; runtime/internal error messages typically aren\'t. Whitelist known-safe messages and bucket the rest as "Internal server error".';
        risk = 'Internal error messages frequently leak schema details, ORM strings, and module paths.';
        break;
    }
    return new Finding({
      category: FindingCategory.security,
      code: this.code,
      severity,
      confidence: FindingConfidence.high,
      detectionMethod: DetectionMethod.regex,
      message,
      fix,
      risk,
      filePath,
      line,
      cwe: 'CWE-209',
    });
  }
}
