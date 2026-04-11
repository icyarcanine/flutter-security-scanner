export function calculateShannonEntropy(str: string): number {
  if (!str || str.length === 0) return 0;

  const charCounts = new Map<string, number>();
  for (let i = 0; i < str.length; i++) {
    const char = str[i];
    charCounts.set(char, (charCounts.get(char) || 0) + 1);
  }

  let entropy = 0;
  const len = str.length;
  for (const count of charCounts.values()) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }

  return entropy;
}

/**
 * Returns true if the string looks like it could be a hardcoded secret based on entropy.
 *
 * This is intentionally conservative to reduce false positives. The following are filtered out:
 * - Strings < 20 or > 200 chars
 * - Pure hex strings (hashes, UUIDs, checksums)
 * - Base64 JWT fragments
 * - Strings with whitespace or natural-language patterns
 * - Strings containing interpolation markers (${ or %s or {})
 * - Strings with too many punctuation/structural chars (URLs, paths, format strings)
 */
export function isHighEntropySecret(str: string): boolean {
  if (!str || str.length < 20 || str.length > 200) return false;

  // Pure hex — hashes, UUIDs, checksums, binary blobs
  if (/^[a-f0-9]+$/i.test(str)) {
    return false;
  }

  // Contains whitespace → natural language, not a secret
  if (/\s/.test(str)) {
    return false;
  }

  // Contains interpolation markers → template string, not a secret
  if (/\$\{|%[sdifr]|\{[0-9]}|\{\{/.test(str)) {
    return false;
  }

  // URL-like patterns are not secrets
  if (/^https?:\/\//i.test(str)) {
    return false;
  }

  // Path-like strings
  if (/^[./\\]/.test(str) || str.includes('/../')) {
    return false;
  }

  // HTML/XML tags or template markup — regex patterns, Thymeleaf, Jinja, etc.
  if (/<[a-zA-Z]|<\/[a-zA-Z]/.test(str)) {
    return false;
  }

  // Regex patterns (high backslash density)
  const backslashCount = (str.match(/\\/g) || []).length;
  if (backslashCount >= 3) {
    return false;
  }

  // Strings that look like CSS selectors, XPath, or query patterns
  if (/^[#.\[]/.test(str) || /\[\^/.test(str)) {
    return false;
  }

  // Common Base64/JWT noise
  if (isCommonBase64Noise(str)) {
    return false;
  }

  // SRI-hash format (sha256-..., sha384-..., sha512-...)
  if (/^sha(?:256|384|512)-/.test(str)) {
    return false;
  }

  // npm integrity hashes (base64 after sha prefix)
  if (/^sha\d+-[A-Za-z0-9+/=]+$/.test(str)) {
    return false;
  }

  // Must contain a mix of character classes to look like a real secret
  // Pure alphanumeric with no mixed case or digits mixed with letters → unlikely secret
  const hasUpper = /[A-Z]/.test(str);
  const hasLower = /[a-z]/.test(str);
  const hasDigit = /[0-9]/.test(str);
  const hasSpecial = /[^A-Za-z0-9]/.test(str);
  const classCount = [hasUpper, hasLower, hasDigit, hasSpecial].filter(Boolean).length;
  if (classCount < 2) {
    return false;
  }

  return calculateShannonEntropy(str) >= 4.5;
}

function isCommonBase64Noise(str: string): boolean {
  const normalized = str.replace(/-/g, '+').replace(/_/g, '/');

  // JWT headers and claim fragments
  if (/^eyJ(?:hbGci|0eXAi|raWQi|0eXBl|zdWIi|pc3Mi|hdWQi)/.test(str)) {
    return true;
  }

  // Standalone JWT-like base64url segments
  if (/^[A-Za-z0-9_-]+={0,2}$/.test(str) && str.length % 4 !== 1) {
    try {
      const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, '=');
      const decoded = Buffer.from(padded, 'base64').toString('utf8').trim();
      if (/^\{[\s\S]*\}$/.test(decoded) &&
        /"(alg|typ|kid|iss|sub|aud|exp|iat)"\s*:/.test(decoded)) {
        return true;
      }
    } catch {
      return false;
    }
  }

  return false;
}
