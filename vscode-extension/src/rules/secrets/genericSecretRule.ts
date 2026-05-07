import { Rule, RuleStage } from '../rule';
import { Finding, FindingSeverity, FindingCategory, FindingConfidence, DetectionMethod } from '../../models/finding';
import { ProjectContext } from '../../scanner/projectContext';
import { isHighEntropySecret } from '../../utils/shannon';
import { isNonProductionPath, looksLikePlaceholderSecret } from '../../noise';

/** File names that should never be scanned for entropy secrets (lock files, generated manifests). */
const ENTROPY_SKIP_NAMES = new Set([
  'package-lock.json',
  'yarn.lock',
  'pnpm-lock.yaml',
  'composer.lock',
  'Gemfile.lock',
  'Pipfile.lock',
  'poetry.lock',
  'go.sum',
  'Cargo.lock',
  'pubspec.lock',
  'packages.lock.json',
]);

/** File extensions that should never be scanned for entropy secrets. */
const ENTROPY_SKIP_EXTENSIONS = new Set([
  '.pdf', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.woff', '.woff2', '.ttf', '.eot',
  '.zip', '.tar', '.gz', '.bz2', '.7z', '.jar', '.war', '.ear',
  '.map', '.min.js', '.min.css',
  '.md', '.txt', '.rst', '.adoc', // documentation
]);

/** Path segments indicating test/fixture/example data — entropy findings here are typically mock values. */
const TEST_PATH_PATTERN = /(?:^|\/)(test|tests|__tests__|spec|specs|fixtures|fixture|mocks|mock|examples?|e2e|testdata|test-data|__mocks__|__fixtures__)(?:\/|$)/i;

export class GenericSecretRule implements Rule {
  readonly code = 'generic-secret';
  readonly stage = RuleStage.fast;

  evaluate(context: ProjectContext): Finding[] {
    const findings: Finding[] = [];

    // Targeted regex patterns — these are specific enough to run on all files.
    //
    // Vendor-specific shapes are pinned to known prefixes (`sk_live_`,
    // `xoxb-`, etc.) so confidence stays HIGH for these; generic shapes
    // (bearer-keyed, JWT) remain LOW and rely on the entropy pass to
    // confirm. New providers are cheap to add — append a new entry.
    const patterns = [
      { regex: /AKIA[0-9A-Z]{16}/g, type: 'AWS Access Key', confidence: FindingConfidence.low },
      { regex: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g, type: 'Private Key', confidence: FindingConfidence.low },
      { regex: /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g, type: 'JWT Token', confidence: FindingConfidence.low },

      // ── Vendor-specific token shapes (§QW-9 / §RC-21) ───────────────────
      // Stripe live/test live, restricted, and publishable keys.
      // The publishable variant (`pk_live_...`) is technically not a secret
      // but is treated the same — it identifies the merchant account and
      // pairs with stolen secret keys.
      { regex: /\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{24,}/g, type: 'Stripe API Key', confidence: FindingConfidence.high },

      // Twilio account / API key SIDs and auth tokens. Account SID is `AC` +
      // 32 hex; API Key is `SK` + 32 hex. Both leak the account when paired
      // with a token; flag conservatively.
      { regex: /\b(?:AC|SK)[0-9a-fA-F]{32}\b/g, type: 'Twilio SID', confidence: FindingConfidence.high },

      // SendGrid v3 API keys: `SG.<22-char-id>.<43-char-secret>`. Use ranges
      // so future SendGrid token-format tweaks don't silently un-detect.
      { regex: /\bSG\.[A-Za-z0-9_-]{16,32}\.[A-Za-z0-9_-]{32,80}\b/g, type: 'SendGrid API Key', confidence: FindingConfidence.high },

      // OpenAI keys, both legacy and project-scoped 2024+ variants.
      { regex: /\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}/g, type: 'OpenAI API Key', confidence: FindingConfidence.high },

      // Anthropic API keys: `sk-ant-api03-...` (current shape).
      { regex: /\bsk-ant(?:-api\d+)?-[A-Za-z0-9_-]{40,}/g, type: 'Anthropic API Key', confidence: FindingConfidence.high },

      // GitHub fine-grained / classic tokens.
      { regex: /\bgh[pousr]_[A-Za-z0-9]{36,255}\b/g, type: 'GitHub Token', confidence: FindingConfidence.high },

      // Slack bot, user, and webhook tokens.
      { regex: /\bxox[baprs]-[A-Za-z0-9-]{10,}/g, type: 'Slack Token', confidence: FindingConfidence.high },

      // Generic catch-all — kept LOW because the prefix is too common.
      { regex: /(?:bearer|token|apikey|api_key|secret|password)["'\s:=]+["'][A-Za-z0-9_.\-]{20,}["']/gi, type: 'Targeted API Key', confidence: FindingConfidence.low }
    ];

    // Extraction pattern for Shannon entropy — only simple string literals
    const literalPattern = /(["'])((?:(?!\1).)*?)\1/g;

    for (const file of context.files) {
      const isBinary = this._isBinaryOrSkipped(file.extension);

      // Targeted patterns run on all text files (they're specific enough)
      if (!isBinary) {
        for (const p of patterns) {
          let match: RegExpExecArray | null;
          p.regex.lastIndex = 0;
          while ((match = p.regex.exec(file.content)) !== null) {
            if (looksLikePlaceholderSecret(match[0], file.relativePath)) {
              continue;
            }
            findings.push(new Finding({
              category: FindingCategory.secrets,
              code: this.code,
              severity: FindingSeverity.high,
              confidence: p.confidence,
              detectionMethod: DetectionMethod.regex,
              message: `Found potentially hardcoded ${p.type}`,
              fix: `Move this ${p.type} to Environment Variables or a secure vault.`,
              risk: 'Hardcoded secrets can be extracted from source code and binaries, leading to complete system compromise.',
              filePath: file.relativePath,
              line: file.lineForOffset(match.index),
              cwe: 'CWE-798',
            }));
          }
        }
      }

      // Entropy scan — skip noise-generating files entirely
      if (isBinary) continue;
      if (this._isEntropySkippedFile(file.name, file.relativePath)) continue;

      literalPattern.lastIndex = 0;
      let litMatch: RegExpExecArray | null;
      while ((litMatch = literalPattern.exec(file.content)) !== null) {
        const potentialSecret = litMatch[2];
        if (looksLikePlaceholderSecret(potentialSecret, file.relativePath)) {
          continue;
        }
        if (isHighEntropySecret(potentialSecret)) {
          findings.push(new Finding({
            category: FindingCategory.secrets,
            code: 'high-entropy-secret',
            severity: FindingSeverity.medium,
            confidence: FindingConfidence.low,
            detectionMethod: DetectionMethod.entropy,
            message: `Found high entropy string literal (Shannon Entropy >= 4.5)`,
            fix: `Verify if this string is a secret. If so, move it to env variables.`,
            risk: 'High entropy strings often indicate hardcoded cryptographic keys or secrets.',
            filePath: file.relativePath,
            line: file.lineForOffset(litMatch.index),
            cwe: 'CWE-798',
          }));
        }
      }
    }

    return findings;
  }

  private _isBinaryOrSkipped(ext: string): boolean {
    return ENTROPY_SKIP_EXTENSIONS.has(ext);
  }

  private _isEntropySkippedFile(name: string, relPath: string): boolean {
    // Lock files
    if (ENTROPY_SKIP_NAMES.has(name)) return true;

    // Minified files
    if (name.endsWith('.min.js') || name.endsWith('.min.css')) return true;

    // Test/fixture/example paths — entropy secrets here are almost always mock data
    if (TEST_PATH_PATTERN.test(relPath) || isNonProductionPath(relPath)) return true;

    // Generated/config files that contain hashes but not secrets
    if (name === '.npmrc' || name === '.yarnrc' || name === '.yarnrc.yml') return true;

    return false;
  }
}
