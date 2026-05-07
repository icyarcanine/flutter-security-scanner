/**
 * SARIF 2.1.0 serializer for SAST findings.
 *
 * GitHub Code Scanning, GitLab, Azure DevOps, and most enterprise SAST
 * dashboards consume SARIF. This is the single biggest enterprise unlock for
 * the tool — without it the JSON is unusable in standard CI pipelines.
 *
 * Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
 *
 * The serializer is dependency-free (no `sarif` npm package) and produces a
 * minimal valid log: tool/driver/rules/results with optional taxonomies.
 */
import * as path from 'path';
import { FindingSeverity } from '../models/finding';
import { ProjectScanReport } from '../scanner/scanner';

const TOOL_NAME = 'flutter-supabase-helper';
const TOOL_VERSION = '1.0.0';
const TOOL_INFORMATION_URI = 'https://github.com/flutter-supabase-helper/sast';

interface SarifMessage { text: string; }
interface SarifArtifactLocation { uri: string; uriBaseId?: string; }
interface SarifRegion {
  startLine: number; startColumn?: number; endLine?: number; endColumn?: number;
  /**
   * SARIF 2.1.0 §3.30.13 / §3.11.2 — embed the source text at the region.
   * GitHub Code Scanning renders this as the snippet next to each result.
   */
  snippet?: SarifMessage;
}
interface SarifLocation {
  physicalLocation: {
    artifactLocation: SarifArtifactLocation;
    region: SarifRegion;
    /**
     * Wider region (typically ±2 lines) carrying its own snippet so a
     * reviewer can see the surrounding context without opening the file.
     */
    contextRegion?: SarifRegion;
  };
}
interface SarifThreadFlowLocation {
  location: SarifLocation;
}
interface SarifThreadFlow { locations: SarifThreadFlowLocation[]; }
interface SarifCodeFlow { threadFlows: SarifThreadFlow[]; }

interface SarifResult {
  ruleId: string;
  level: 'error' | 'warning' | 'note' | 'none';
  message: SarifMessage;
  locations: SarifLocation[];
  /** SARIF code-flow chain: source → propagation → sink. */
  codeFlows?: SarifCodeFlow[];
  partialFingerprints?: Record<string, string>;
  properties?: Record<string, unknown>;
}
interface SarifReportingDescriptor {
  id: string;
  name?: string;
  shortDescription?: SarifMessage;
  fullDescription?: SarifMessage;
  helpUri?: string;
  defaultConfiguration?: { level: 'error' | 'warning' | 'note' };
  properties?: { tags?: string[]; precision?: 'high' | 'medium' | 'low'; cwe?: string[] };
}
interface SarifRun {
  tool: {
    driver: {
      name: string; version: string; informationUri: string;
      rules: SarifReportingDescriptor[];
    };
  };
  results: SarifResult[];
  originalUriBaseIds?: Record<string, { uri: string }>;
}
export interface SarifLog {
  $schema: string;
  version: '2.1.0';
  runs: SarifRun[];
}

function severityToLevel(s?: FindingSeverity): 'error' | 'warning' | 'note' {
  switch (s) {
    case FindingSeverity.high: return 'error';
    case FindingSeverity.medium: return 'warning';
    case FindingSeverity.low: return 'note';
    default: return 'note';
  }
}

/**
 * Cap embedded snippets so SARIF logs don't balloon on minified files. A
 * GitHub-rendered snippet maxes out around a few hundred chars in practice.
 */
const MAX_SNIPPET_LINE_CHARS = 320;

function clampLine(line: string): string {
  if (line.length <= MAX_SNIPPET_LINE_CHARS) { return line; }
  return line.slice(0, MAX_SNIPPET_LINE_CHARS) + '…';
}

/**
 * Build region.snippet (just the offending line) and contextRegion (the line
 * plus ±2 lines, with its own snippet). Returns `undefined` when the file is
 * not in the scan corpus or the line number is out of range.
 */
function buildSnippets(
  fileLines: string[] | undefined,
  startLine: number,
  endLine: number | undefined,
): { snippet: SarifMessage; contextRegion: SarifRegion } | undefined {
  if (!fileLines || fileLines.length === 0) { return undefined; }
  const lo = Math.max(1, startLine);
  const hi = Math.max(lo, endLine ?? startLine);
  if (lo > fileLines.length) { return undefined; }
  const primary = fileLines.slice(lo - 1, Math.min(hi, fileLines.length))
    .map(clampLine).join('\n');
  const ctxStart = Math.max(1, lo - 2);
  const ctxEnd = Math.min(fileLines.length, hi + 2);
  const contextText = fileLines.slice(ctxStart - 1, ctxEnd).map(clampLine).join('\n');
  return {
    snippet: { text: primary },
    contextRegion: { startLine: ctxStart, endLine: ctxEnd, snippet: { text: contextText } },
  };
}

function pathToUri(filePath: string, rootPath: string): string {
  // Prefer relative paths anchored to %SRCROOT% so the SARIF log is portable
  // across machines. If the path is already relative, leave it alone; if
  // absolute, make it relative to `rootPath` when possible.
  if (path.isAbsolute(filePath)) {
    const rel = path.relative(rootPath, filePath);
    if (!rel.startsWith('..') && !path.isAbsolute(rel)) {
      return rel.split(path.sep).join('/');
    }
    // Outside the root — emit a file:// URI.
    return `file://${filePath.split(path.sep).join('/')}`;
  }
  return filePath.split(path.sep).join('/');
}

/**
 * Build a SARIF 2.1.0 log from a ProjectScanReport.
 * Findings without a filePath are skipped (SARIF requires a location).
 */
export function toSarif(report: ProjectScanReport, rootPath: string): SarifLog {
  const ruleMap = new Map<string, SarifReportingDescriptor>();
  // CWE accumulator per rule: a single rule (e.g. `injection-flaw`) can emit
  // findings spanning many CWEs (CWE-89 SQL, CWE-78 cmd, CWE-918 SSRF, etc.).
  // The SARIF reportingDescriptor.properties.cwe should reflect ALL of them
  // so compliance dashboards filtering by CWE see every finding the rule
  // produces — not just whichever happened to come first.
  const ruleCwes = new Map<string, Set<string>>();
  const results: SarifResult[] = [];

  // Lookup table for snippet extraction. Keyed by relativePath because that's
  // what `pathToUri` will produce when paths are inside the root. A finding
  // whose absolute path is outside the root won't get a snippet — callers
  // already accept SARIF results without snippets for that case.
  const fileByRelative = new Map<string, string[]>();
  for (const file of report.context.files) {
    fileByRelative.set(file.relativePath.split(path.sep).join('/'), file.lines);
  }

  for (const finding of report.findings) {
    if (!finding.filePath) { continue; }

    // Lazily build per-rule descriptor (CWE list filled in below at end of loop).
    if (!ruleMap.has(finding.code)) {
      ruleMap.set(finding.code, {
        id: finding.code,
        name: finding.code,
        shortDescription: { text: finding.message.split('\n')[0].slice(0, 120) },
        fullDescription: { text: finding.fix },
        helpUri: `${TOOL_INFORMATION_URI}#${finding.code}`,
        defaultConfiguration: { level: severityToLevel(finding.severity) },
        properties: {
          tags: ['security'],
          precision:
            finding.confidence === 'high' ? 'high' :
            finding.confidence === 'medium' ? 'medium' : 'low',
        },
      });
    }
    if (finding.cwe) {
      const set = ruleCwes.get(finding.code) ?? new Set<string>();
      const cwes = Array.isArray(finding.cwe) ? finding.cwe : [finding.cwe];
      for (const c of cwes) { set.add(c); }
      ruleCwes.set(finding.code, set);
    }

    const startLine = finding.line ?? 1;
    const region: SarifRegion = { startLine };
    if (finding.column != null) { region.startColumn = finding.column; }
    if (finding.endLine != null) { region.endLine = finding.endLine; }
    if (finding.endColumn != null) { region.endColumn = finding.endColumn; }

    const findingRelative = pathToUri(finding.filePath, rootPath);
    const snippets = buildSnippets(
      fileByRelative.get(findingRelative),
      startLine,
      finding.endLine ?? undefined,
    );
    if (snippets) { region.snippet = snippets.snippet; }

    // SARIF codeFlows from finding.pathSteps (when present).
    let codeFlows: SarifCodeFlow[] | undefined;
    if (finding.pathSteps && finding.pathSteps.length > 0) {
      const flowLocations: SarifThreadFlowLocation[] = finding.pathSteps.map(step => {
        const stepUri = pathToUri(step.filePath ?? finding.filePath!, rootPath);
        const stepRegion: SarifRegion = {
          startLine: step.line,
          ...(step.column != null ? { startColumn: step.column } : {}),
        };
        const stepSnippets = buildSnippets(fileByRelative.get(stepUri), step.line, undefined);
        if (stepSnippets) { stepRegion.snippet = stepSnippets.snippet; }
        return {
          location: {
            physicalLocation: {
              artifactLocation: { uri: stepUri, uriBaseId: 'SRCROOT' },
              region: stepRegion,
              ...(stepSnippets ? { contextRegion: stepSnippets.contextRegion } : {}),
            },
          },
        };
      });
      codeFlows = [{ threadFlows: [{ locations: flowLocations }] }];
    }

    results.push({
      ruleId: finding.code,
      level: severityToLevel(finding.severity),
      message: { text: finding.message },
      locations: [{
        physicalLocation: {
          artifactLocation: { uri: findingRelative, uriBaseId: 'SRCROOT' },
          region,
          ...(snippets ? { contextRegion: snippets.contextRegion } : {}),
        },
      }],
      ...(codeFlows ? { codeFlows } : {}),
      // Used by GitHub Code Scanning to dedupe across runs even when line numbers shift.
      partialFingerprints: {
        primaryLocationLineHash: `${finding.code}:${findingRelative}:${startLine}`,
      },
      properties: {
        confidence: finding.confidence,
        category: finding.category,
        astUsed: finding.astUsed,
        risk: finding.risk,
        fix: finding.fix,
      },
    });
  }

  // Now that every result has been processed, fold the accumulated CWE
  // sets into each rule descriptor. Sorting keeps SARIF output stable
  // across runs (test fixtures and diffs).
  for (const [ruleId, cweSet] of ruleCwes) {
    const desc = ruleMap.get(ruleId);
    if (!desc) { continue; }
    const cwes = Array.from(cweSet).sort();
    if (cwes.length > 0) {
      desc.properties = {
        ...desc.properties,
        tags: [...(desc.properties?.tags ?? ['security']), 'external/cwe'],
        cwe: cwes,
      };
    }
  }

  return {
    $schema: 'https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json',
    version: '2.1.0',
    runs: [{
      tool: {
        driver: {
          name: TOOL_NAME,
          version: TOOL_VERSION,
          informationUri: TOOL_INFORMATION_URI,
          rules: Array.from(ruleMap.values()),
        },
      },
      results,
      originalUriBaseIds: { SRCROOT: { uri: `file://${rootPath.split(path.sep).join('/')}/` } },
    }],
  };
}
