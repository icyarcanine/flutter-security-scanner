import { Rule, RuleStage } from '../rule';
import { Finding, FindingSeverity, FindingCategory, FindingConfidence, DetectionMethod } from '../../models/finding';
import { ProjectContext } from '../../scanner/projectContext';

/**
 * Tabnabbing / reverse-tabnabbing flag (§QW-6 / §RC-13, CWE-1022).
 *
 * Three shapes considered, each with a `rel` / feature-list escape hatch
 * recognised so the rule doesn't flag mitigated code:
 *
 *   1. JSX/HTML anchor tags: `<a target="_blank" rel="noopener noreferrer">`
 *      is fine; without `rel` (or with a `rel` that doesn't include
 *      `noopener` / `noreferrer`) the destination keeps a live
 *      `window.opener` reference and can navigate the parent.
 *   2. `window.open(url, '_blank')` without a `'noopener,noreferrer'` token
 *      in the third "windowFeatures" argument.
 *   3. `Linking.openURL` / `Linking.openInNewTab` and similar — out of
 *      scope for this rule.
 *
 * Rule fires per match. We don't try to parse HTML — a regex over source
 * lines is the right tool here, since tabnabbing is fundamentally a textual
 * pattern on string-literal markup.
 */
export class TabnabbingRule implements Rule {
  readonly code = 'tabnabbing';
  readonly stage = RuleStage.fast;

  // Regexes are compiled once at class init.

  /** Anchor tag opening — captures the entire start tag for `rel` inspection. */
  private static readonly _ANCHOR_OPEN =
    /<a\b[^>]*?\btarget\s*=\s*['"]_blank['"][^>]*>/gi;

  /** `window.open(url, '_blank' | "_blank", features?)` — captures features arg. */
  private static readonly _WINDOW_OPEN =
    /\bwindow\s*\.\s*open\s*\(\s*[^,)]+,\s*['"]_blank['"]\s*(?:,\s*([^)]*))?\)/gi;

  /** A `rel="…"` attribute value extractor. */
  private static readonly _REL_ATTR = /\brel\s*=\s*['"]([^'"]*)['"]/i;

  evaluate(context: ProjectContext): Finding[] {
    const findings: Finding[] = [];
    for (const file of context.files) {
      // Limit to source / template formats where these shapes appear.
      if (!/\.(?:html|htm|js|jsx|ts|tsx|mjs|cjs|vue|svelte|astro)$/i.test(file.name)) { continue; }
      if (!/_blank/i.test(file.content)) { continue; }

      // Reset stateful regex flags before each pass — `g` regexes carry
      // `lastIndex` across calls.
      TabnabbingRule._ANCHOR_OPEN.lastIndex = 0;
      TabnabbingRule._WINDOW_OPEN.lastIndex = 0;

      let m: RegExpExecArray | null;
      while ((m = TabnabbingRule._ANCHOR_OPEN.exec(file.content)) !== null) {
        const tag = m[0];
        const rel = TabnabbingRule._REL_ATTR.exec(tag)?.[1] ?? '';
        if (TabnabbingRule._relIsSafe(rel)) { continue; }
        findings.push(this._anchorFinding(file, m.index, rel));
      }
      while ((m = TabnabbingRule._WINDOW_OPEN.exec(file.content)) !== null) {
        const features = m[1] ?? '';
        if (TabnabbingRule._featuresAreSafe(features)) { continue; }
        findings.push(this._windowOpenFinding(file, m.index));
      }
    }
    return findings;
  }

  private _anchorFinding(file: { relativePath: string; lineForOffset: (n: number) => number }, offset: number, rel: string): Finding {
    return new Finding({
      category: FindingCategory.security,
      code: this.code,
      severity: FindingSeverity.medium,
      confidence: FindingConfidence.high,
      detectionMethod: DetectionMethod.regex,
      message: rel
        ? `<a target="_blank"> with rel="${rel}" missing noopener/noreferrer (tabnabbing risk).`
        : `<a target="_blank"> without rel="noopener noreferrer" (tabnabbing risk).`,
      fix: 'Add rel="noopener noreferrer" to the anchor tag. `noopener` blocks window.opener; `noreferrer` also blocks the Referer header.',
      risk: 'A malicious destination can navigate the parent tab to a phishing page via window.opener — the original "tabnabbing" attack.',
      filePath: file.relativePath,
      line: file.lineForOffset(offset),
      cwe: 'CWE-1022',
    });
  }

  private _windowOpenFinding(file: { relativePath: string; lineForOffset: (n: number) => number }, offset: number): Finding {
    return new Finding({
      category: FindingCategory.security,
      code: this.code,
      severity: FindingSeverity.medium,
      confidence: FindingConfidence.high,
      detectionMethod: DetectionMethod.regex,
      message: 'window.open(url, "_blank") missing "noopener,noreferrer" features (tabnabbing risk).',
      fix: 'Pass "noopener,noreferrer" as the third argument: window.open(url, "_blank", "noopener,noreferrer"). Or, post-open, set the returned window.opener = null.',
      risk: 'Without noopener, the opened tab can navigate the original via window.opener — used in phishing flows.',
      filePath: file.relativePath,
      line: file.lineForOffset(offset),
      cwe: 'CWE-1022',
    });
  }

  private static _relIsSafe(rel: string): boolean {
    const tokens = rel.toLowerCase().split(/\s+/).filter(Boolean);
    return tokens.includes('noopener') || tokens.includes('noreferrer');
  }

  private static _featuresAreSafe(features: string): boolean {
    return /\bnoopener\b|\bnoreferrer\b/i.test(features);
  }
}
