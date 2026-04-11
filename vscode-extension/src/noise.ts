import { Finding, FindingConfidence, FindingSeverity } from './models/finding';

const NON_PRODUCTION_SEGMENT_PATTERN =
  /(?:^|\/)(?:test|tests|__tests__|spec|specs|fixtures?|__fixtures__|mocks?|__mocks__|examples?|samples?|demos?|docs?|documentation|e2e|integration_test|testdata|test-data)(?:\/|$)/i;

const PLACEHOLDER_SECRET_PATTERN =
  /(?:example|sample|dummy|fake|mock|test|placeholder|changeme|change_me|replace-me|replace_me|not.?a.?secret|your[-_]?|xxx|deadbeef|akiaiosfodnn7example)/i;

const LOW_SIGNAL_SECRET_CODES = new Set(['generic-secret', 'high-entropy-secret']);

export function isNonProductionPath(filePath: string | undefined): boolean {
  return filePath != null && NON_PRODUCTION_SEGMENT_PATTERN.test(filePath);
}

export function looksLikePlaceholderSecret(value: string, filePath?: string): boolean {
  const combined = `${filePath ?? ''}\n${value}`;
  if (PLACEHOLDER_SECRET_PATTERN.test(combined)) {
    return true;
  }

  const normalized = value.toLowerCase();
  if (/^(?:x+|0+|1+|a+|z+)$/.test(normalized) && normalized.length >= 16) {
    return true;
  }
  if (/^(?:password|secret|token|apikey|api_key|bearer)[-_]?(?:test|mock|fake|example|dummy)/i.test(normalized)) {
    return true;
  }

  return false;
}

export function applyNonProductionNoiseReduction(findings: Finding[]): Finding[] {
  const adjusted: Finding[] = [];

  for (const finding of findings) {
    if (!isNonProductionPath(finding.filePath)) {
      adjusted.push(finding);
      continue;
    }

    if (finding.confidence === FindingConfidence.low || LOW_SIGNAL_SECRET_CODES.has(finding.code)) {
      continue;
    }

    adjusted.push(cloneFinding(finding, {
      severity: downgradeSeverity(finding.severity),
      confidence: downgradeConfidence(finding.confidence),
    }));
  }

  return adjusted;
}

function downgradeSeverity(severity: FindingSeverity | undefined): FindingSeverity | undefined {
  switch (severity) {
    case FindingSeverity.high:
      return FindingSeverity.medium;
    case FindingSeverity.medium:
      return FindingSeverity.low;
    default:
      return severity;
  }
}

function downgradeConfidence(confidence: FindingConfidence | undefined): FindingConfidence | undefined {
  switch (confidence) {
    case FindingConfidence.high:
      return FindingConfidence.medium;
    case FindingConfidence.medium:
      return FindingConfidence.low;
    default:
      return confidence;
  }
}

function cloneFinding(finding: Finding, overrides: {
  severity?: FindingSeverity;
  confidence?: FindingConfidence;
}): Finding {
  return new Finding({
    category: finding.category,
    code: finding.code,
    message: finding.message,
    fix: finding.fix,
    risk: finding.risk,
    severity: overrides.severity ?? finding.severity,
    confidence: overrides.confidence ?? finding.confidence,
    filePath: finding.filePath,
    line: finding.line,
    astUsed: finding.astUsed,
  });
}
