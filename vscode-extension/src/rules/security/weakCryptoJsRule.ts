import { Rule, RuleStage } from '../rule';
import { Finding, FindingSeverity, FindingCategory, FindingConfidence, DetectionMethod } from '../../models/finding';
import { ProjectContext } from '../../scanner/projectContext';
import { stripLineComment } from '../ruleHelpers';

/**
 * Weak cryptography on the JS/TS side (§QW-8 / §RC-20, CWE-327).
 *
 * Mirrors the Dart-side `weak-crypto` rule for the JS family. Catches the
 * usual broken primitives that show up in client-side and Node code:
 *
 *   - `crypto.createHash('md5'|'sha1')` / `'rsa-sha1'` etc.
 *   - `crypto.createHmac('sha1', …)` / `'md5'`
 *   - `crypto.createCipheriv('des'|'des-ede'|'rc4'|'aes-*-ecb', …)`
 *   - `CryptoJS.MD5(...)` / `CryptoJS.SHA1(...)` / `CryptoJS.mode.ECB`
 *   - `crypto.subtle.digest('SHA-1'|'MD5', …)` (browser SubtleCrypto)
 *
 * Each pattern is checked per-line with comment-stripping.
 */
export class WeakCryptoJsRule implements Rule {
  readonly code = 'weak-crypto-js';
  readonly stage = RuleStage.fast;

  private static readonly _CHECKS: Array<{
    pattern: RegExp;
    message: string;
    fix: string;
    risk: string;
    severity: FindingSeverity;
  }> = [
    {
      pattern: /\bcrypto\s*\.\s*createHash\s*\(\s*['"](?:md5|md4|md2)['"]/i,
      message: 'Weak hash algorithm via crypto.createHash("md5"|"md4"|"md2").',
      fix: 'Use SHA-256 or SHA-512 for integrity checks. For password hashing use bcrypt / scrypt / argon2 (via @node-rs/argon2 or similar).',
      risk: 'MD5 collisions are computable in seconds; the family is unsafe for any security purpose.',
      severity: FindingSeverity.high,
    },
    {
      pattern: /\bcrypto\s*\.\s*createHash\s*\(\s*['"](?:sha1|rsa-sha1)['"]/i,
      message: 'Weak hash algorithm via crypto.createHash("sha1"|"rsa-sha1").',
      fix: 'Use SHA-256 / SHA-512. For HMAC, use SHA-256 + a randomly-generated key.',
      risk: 'SHA-1 has demonstrated collision attacks (SHAttered) and is deprecated for security.',
      severity: FindingSeverity.medium,
    },
    {
      pattern: /\bcrypto\s*\.\s*createHmac\s*\(\s*['"](?:md5|sha1)['"]/i,
      message: 'HMAC built on a weak hash (MD5 / SHA-1).',
      fix: 'Use HMAC-SHA-256 or HMAC-SHA-512.',
      risk: 'HMAC inherits the weakness of its underlying hash; HMAC-MD5 / HMAC-SHA1 are no longer recommended.',
      severity: FindingSeverity.medium,
    },
    {
      pattern: /\bcrypto\s*\.\s*createCipheriv\s*\(\s*['"](?:[a-z0-9-]*ecb[a-z0-9-]*)['"]/i,
      message: 'AES / cipher in ECB mode (no diffusion).',
      fix: 'Use GCM (`aes-256-gcm`) or CTR/CBC + HMAC. ECB encrypts identical blocks identically, leaking patterns.',
      risk: 'ECB mode reveals plaintext block patterns in ciphertext (the famous "ECB penguin").',
      severity: FindingSeverity.high,
    },
    {
      // §QW-32 / §RC-44 — `crypto.createCipher(algo, password)` is the
      // deprecated Node API. It does NOT take an IV and uses
      // `EVP_BytesToKey` for KDF, which is broken (low-entropy, no salt).
      // Even with `aes-256-cbc` as the algo, this is insecure. Same for
      // `createDecipher` and `pbkdf2` with too-few iterations.
      pattern: /\bcrypto\s*\.\s*createDecipher(?!iv)\s*\(|\bcrypto\s*\.\s*createCipher(?!iv)\s*\(/,
      message: 'Deprecated crypto.createCipher / createDecipher — uses EVP_BytesToKey KDF (no salt, low entropy).',
      fix: 'Use createCipheriv / createDecipheriv with a random IV and a proper KDF (scrypt, pbkdf2 with ≥100k iterations, or argon2).',
      risk: 'createCipher derives the key from a password without a salt; rainbow-table style attacks recover the key cheaply.',
      severity: FindingSeverity.high,
    },
    {
      pattern: /\bcrypto\s*\.\s*createCipheriv\s*\(\s*['"](?:des(?:-ede)?(?:-cbc)?|rc4|3des|bf-cbc|blowfish)['"]/i,
      message: 'Deprecated cipher algorithm (DES / 3DES / RC4 / Blowfish).',
      fix: 'Use AES-GCM (256-bit). DES is broken, 3DES is being retired, RC4 has well-known biases, Blowfish has small block size.',
      risk: 'These ciphers have either been broken outright or have known statistical weaknesses; modern attackers exploit them at low cost.',
      severity: FindingSeverity.high,
    },
    {
      pattern: /\bCryptoJS\s*\.\s*(?:MD5|SHA1|MD4|MD2)\s*\(/,
      message: 'CryptoJS using a weak hash (MD5 / SHA-1 / MD4 / MD2).',
      fix: 'Use CryptoJS.SHA256 / SHA512, or move to the Node `crypto` module.',
      risk: 'Same hash weaknesses as the Node core APIs — not safe for integrity-critical use.',
      severity: FindingSeverity.medium,
    },
    {
      pattern: /\bCryptoJS\s*\.\s*mode\s*\.\s*ECB\b/,
      message: 'CryptoJS encryption in ECB mode.',
      fix: 'Use CryptoJS.mode.GCM or .CBC with a random IV plus HMAC for authentication.',
      risk: 'ECB mode leaks plaintext patterns through the ciphertext.',
      severity: FindingSeverity.high,
    },
    {
      pattern: /\bcrypto\s*\.\s*subtle\s*\.\s*digest\s*\(\s*['"](?:SHA-1|MD5)['"]/i,
      message: 'SubtleCrypto.digest with a weak hash.',
      fix: 'Use "SHA-256" or "SHA-384". The SHA-1 / MD5 entries exist for legacy interop only.',
      risk: 'SHA-1 / MD5 in SubtleCrypto are kept for compatibility; using them for security purposes inherits the underlying weaknesses.',
      severity: FindingSeverity.medium,
    },
    {
      // §QW-29 / §RC-48 — explicit pinning to deprecated TLS / SSL
      // protocols. `secureProtocol: 'TLSv1_method'`, `'SSLv3_method'`,
      // `'TLSv1_1_method'` are all broken or deprecated. Same for the
      // `minVersion: 'TLSv1'` / `'TLSv1.1'` variant.
      pattern: /\b(?:secureProtocol|minVersion)\s*:\s*['"](?:SSLv\d|TLSv1(?:_method|_0|\.0)?|TLSv1[._]1(?:_method)?|TLSv1_1_method)['"]/i,
      message: 'TLS/SSL pinned to a deprecated protocol (SSLv3, TLSv1.0, TLSv1.1).',
      fix: 'Drop the option entirely (Node negotiates TLSv1.2+) or set `minVersion: "TLSv1.2"` / `"TLSv1.3"`. `secureProtocol` is itself deprecated since Node 12.',
      risk: 'BEAST, POODLE, FREAK and other attacks rely on these protocols; modern stacks should refuse them.',
      severity: FindingSeverity.high,
    },
  ];

  evaluate(context: ProjectContext): Finding[] {
    const findings: Finding[] = [];
    for (const file of context.files) {
      if (!/\.(?:js|jsx|ts|tsx|mjs|cjs)$/i.test(file.name)) { continue; }
      // Cheap content gate. If none of these substrings appear, skip the
      // per-line per-pattern walk entirely.
      if (!/\bcrypto\b|\bCryptoJS\b|\bsecureProtocol\b|\bminVersion\b/.test(file.content)) { continue; }

      for (let i = 0; i < file.lines.length; i++) {
        const line = stripLineComment(file.lines[i]);
        if (!line) { continue; }
        for (const check of WeakCryptoJsRule._CHECKS) {
          if (!check.pattern.test(line)) { continue; }
          findings.push(new Finding({
            category: FindingCategory.security,
            code: this.code,
            severity: check.severity,
            confidence: FindingConfidence.high,
            detectionMethod: DetectionMethod.regex,
            message: check.message,
            fix: check.fix,
            risk: check.risk,
            filePath: file.relativePath,
            line: i + 1,
            cwe: 'CWE-327',
          }));
          // One finding per line is enough — multiple checks on the same
          // line usually point at the same call.
          break;
        }
      }
    }
    return findings;
  }
}
