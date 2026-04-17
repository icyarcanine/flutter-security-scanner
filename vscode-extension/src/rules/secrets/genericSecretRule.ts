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

    // Targeted regex patterns — these are specific enough to run on all files
    const patterns = [
      { regex: /AKIA[0-9A-Z]{16}/g, type: 'AWS Access Key', confidence: FindingConfidence.low },
      { regex: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g, type: 'Private Key', confidence: FindingConfidence.low },
      { regex: /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g, type: 'JWT Token', confidence: FindingConfidence.low },
      { regex: /(?:bearer|token|apikey|api_key|secret|password)["'\s:=]+["'][A-Za-z0-9_.\-]{20,}["']/gi, type: 'Targeted API Key', confidence: FindingConfidence.low }
    ];

    // Extraction pattern for Shannon entropy — only simple string literals
    const literalPattern = /(["'])((?:(?!\1).)*?)\1/g;

    for (const file of context.files) {
      const isBinary = this._isBinaryOrSkipped(file.name, file.extension);

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
              line: file.lineForOffset(match.index)
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
            line: file.lineForOffset(litMatch.index)
          }));
        }
      }
    }

    return findings;
  }

  private _isBinaryOrSkipped(name: string, ext: string): boolean {
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
