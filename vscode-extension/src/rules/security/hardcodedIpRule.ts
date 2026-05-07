import { Rule, RuleStage } from '../rule';
import { Finding, FindingSeverity, FindingCategory, FindingConfidence, DetectionMethod } from '../../models/finding';
import { ProjectContext } from '../../scanner/projectContext';
import { stripLineComment } from '../ruleHelpers';

/**
 * Flag hardcoded public-IP literals (§QW-4 / §RC-58).
 *
 * The goal isn't "no IPs anywhere" — local-dev IPs (127.0.0.1, RFC1918
 * ranges, link-local, multicast) are routinely useful and would drown a real
 * finding in noise. We flag literals that look like *public* IPv4/IPv6
 * addresses, since a public IP wired into source typically means a fragile
 * deploy-time secret leaked into the repo.
 *
 * Restricted to text source files. Comments are stripped per-line before
 * matching (see `_stripLineComment`) so example IPs in docstrings don't fire.
 */
export class HardcodedIpRule implements Rule {
  readonly code = 'hardcoded-ip';
  readonly stage = RuleStage.fast;

  // IPv4: four octets 0–255 not preceded/followed by another digit (so we
  // don't catch the leading/trailing portion of a longer numeric run like a
  // version string, MAC address fragment, or hash).
  private static readonly _IPV4 =
    /(?<![\d.])((?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})(?![\d.])/g;

  // IPv6 prefilter — permissive "looks-IPv6-shaped" capture: a run of
  // hex / colon characters that includes at least one colon and isn't
  // surrounded by a word char. We re-validate each match structurally in
  // `_parseIPv6` (handles `::` zero-run elision properly), so the regex's
  // job is just "find candidate substrings to test."
  private static readonly _IPV6 =
    /(?<![\w:])([0-9a-fA-F:]+:[0-9a-fA-F:]+)(?![\w:])/g;

  evaluate(context: ProjectContext): Finding[] {
    const findings: Finding[] = [];

    for (const file of context.files) {
      // Limit to languages where IPs are likely written in code. Skip docs
      // (`.md`, `.txt`) which routinely show example IPs, and config files
      // (`.yaml`, `.json`) where IPs are deliberate per-environment values
      // that should be flagged by a different rule (env-leak / secrets).
      if (!HardcodedIpRule._isTextSource(file.name)) { continue; }

      const lines = file.lines;
      for (let i = 0; i < lines.length; i++) {
        const stripped = HardcodedIpRule._stripLineComment(lines[i], file.name);
        if (!stripped) { continue; }

        for (const match of HardcodedIpRule._matchAll(stripped, HardcodedIpRule._IPV4)) {
          const ip = match[1];
          if (HardcodedIpRule._isPublicIPv4(ip)) {
            findings.push(HardcodedIpRule._finding(file.relativePath, i + 1, ip, 'IPv4'));
          }
        }
        for (const match of HardcodedIpRule._matchAll(stripped, HardcodedIpRule._IPV6)) {
          const ip = match[1];
          if (HardcodedIpRule._parseIPv6(ip) && HardcodedIpRule._isPublicIPv6(ip)) {
            findings.push(HardcodedIpRule._finding(file.relativePath, i + 1, ip, 'IPv6'));
          }
        }
      }
    }
    return findings;
  }

  // ─── Helpers ──────────────────────────────────────────────────────────────

  private static _finding(filePath: string, line: number, ip: string, kind: 'IPv4' | 'IPv6'): Finding {
    return new Finding({
      category: FindingCategory.security,
      code: 'hardcoded-ip',
      severity: FindingSeverity.low,
      confidence: FindingConfidence.medium,
      detectionMethod: DetectionMethod.regex,
      message: `Hardcoded public ${kind} address \`${ip}\` in source.`,
      fix: 'Move host/IP values into configuration (env var, .fshrc.yaml, deploy config). Hardcoded production endpoints are brittle and tend to leak when repos are open-sourced.',
      risk: 'Hardcoded production endpoints make rotation hard and frequently leak as part of public repositories.',
      filePath,
      line,
      cwe: 'CWE-547',
    });
  }

  private static _isTextSource(name: string): boolean {
    const lower = name.toLowerCase();
    return /\.(?:js|jsx|ts|tsx|mjs|cjs|dart|py|go|java|rb|rs|sh|bash|zsh|env|conf|cfg|ini|toml|properties|gradle|kts)$/.test(lower);
  }

  private static _stripLineComment(line: string, filename: string): string {
    const lower = filename.toLowerCase();
    const token = /\.(?:py|sh|bash|zsh|conf|cfg|ini|toml|properties|env)$/.test(lower) ? '#' : '//';
    return stripLineComment(line, token);
  }

  private static *_matchAll(input: string, regex: RegExp): IterableIterator<RegExpMatchArray> {
    regex.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = regex.exec(input)) !== null) { yield m; }
  }

  /**
   * True iff `ip` is a public-internet IPv4 — not loopback, link-local,
   * multicast, broadcast, RFC 1918, RFC 6598 (CGNAT), or documentation
   * (RFC 5737). The aim is to flag what would actually be a leaked
   * production endpoint, not local-dev clutter.
   */
  private static _isPublicIPv4(ip: string): boolean {
    const parts = ip.split('.').map(p => parseInt(p, 10));
    if (parts.length !== 4 || parts.some(p => isNaN(p) || p < 0 || p > 255)) { return false; }
    const [a, b] = parts;

    if (a === 0) { return false; }                       // 0.0.0.0/8
    if (a === 10) { return false; }                      // RFC 1918
    if (a === 127) { return false; }                     // loopback
    if (a === 169 && b === 254) { return false; }        // link-local
    if (a === 172 && b >= 16 && b <= 31) { return false; } // RFC 1918
    if (a === 192 && b === 168) { return false; }        // RFC 1918
    if (a === 100 && b >= 64 && b <= 127) { return false; } // RFC 6598 CGNAT
    if (a === 192 && b === 0 && (parts[2] === 0 || parts[2] === 2)) { return false; } // doc / TEST-NET-1
    if (a === 198 && (b === 18 || b === 19)) { return false; } // benchmark
    if (a === 198 && b === 51 && parts[2] === 100) { return false; } // TEST-NET-2
    if (a === 203 && b === 0 && parts[2] === 113) { return false; } // TEST-NET-3
    if (a >= 224) { return false; }                      // multicast / reserved / broadcast
    return true;
  }

  /**
   * Validate an IPv6 candidate. Accepts `::`-elision and 1–4 hex digits per
   * group. Returns true when the candidate is a structurally-valid IPv6 of
   * exactly 8 groups (counting elision). False for things like a single
   * `colon-separated word`, MAC-shaped strings, or version-style hex runs.
   */
  private static _parseIPv6(ip: string): boolean {
    // At least one colon required by the prefilter, but reject all-colon junk.
    if (!/[0-9a-fA-F]/.test(ip)) { return false; }
    const elisionCount = (ip.match(/::/g) ?? []).length;
    if (elisionCount > 1) { return false; }

    let leftPart: string, rightPart: string;
    if (elisionCount === 1) {
      [leftPart, rightPart] = ip.split('::', 2);
    } else {
      leftPart = ip;
      rightPart = '';
    }

    const left = leftPart === '' ? [] : leftPart.split(':');
    const right = rightPart === '' ? [] : rightPart.split(':');
    const groups = [...left, ...right];
    for (const g of groups) {
      if (g === '' || g.length > 4 || !/^[0-9a-fA-F]+$/.test(g)) { return false; }
    }
    if (elisionCount === 0) {
      return groups.length === 8;
    }
    // With one `::` elision the explicit groups must be < 8 (since the
    // elision must contribute ≥1 group). Exactly 8 explicit groups with
    // `::` is invalid.
    return groups.length < 8 && groups.length >= 1;
  }

  /**
   * True iff `ip` parses as IPv6 and is not loopback (`::1`), unspecified
   * (`::`), link-local (`fe80::/10`), unique-local (`fc00::/7`), or
   * documentation (`2001:db8::/32`). Cheap byte-prefix checks rather than a
   * full RFC 5952 parse.
   */
  private static _isPublicIPv6(ip: string): boolean {
    const lowered = ip.toLowerCase();
    if (lowered === '::' || lowered === '::1') { return false; }
    if (lowered.startsWith('fe8') || lowered.startsWith('fe9') ||
        lowered.startsWith('fea') || lowered.startsWith('feb')) { return false; } // fe80::/10
    if (lowered.startsWith('fc') || lowered.startsWith('fd')) { return false; }   // fc00::/7
    if (lowered.startsWith('2001:db8')) { return false; }                          // doc range
    if (lowered.startsWith('ff')) { return false; }                                // multicast

    // Ignore obviously non-IPv6 captures (the regex is lenient): require at
    // least one colon and at least 4 chars.
    if (!lowered.includes(':') || lowered.length < 4) { return false; }
    return true;
  }
}
