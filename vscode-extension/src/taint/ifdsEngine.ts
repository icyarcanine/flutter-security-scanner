/**
 * @deprecated Superseded by the Rust engine sidecar (`engine-cli`) once the
 * runtime is available. Kept as the fallback path for unsupported platforms,
 * missing binaries, and test fixtures that intentionally exercise the legacy
 * TypeScript IFDS implementation. New taint rules should be authored as
 * Semgrep YAML in `vscode-extension/rules/`, not by editing this engine.
 *
 * IFDS taint engine orchestrator.
 *
 * Takes a set of parsed Dart files, builds a single CodeGraph spanning all of
 * them (so ICFG edges can cross files), runs the IFDS solver, and emits
 * Finding[] for each sink reached by a tainted argument.
 *
 * Per-file errors are isolated: a parse anomaly in one file logs a warning
 * and skips that file, rather than killing the whole scan.
 */

import { ScannedFile } from '../scanner/scannedFile';
import { Finding, FindingCategory, FindingConfidence, FindingSeverity, DetectionMethod } from '../models/finding';
import { CodeGraph, locKey } from '../models/graph';
import { IfdsGraphBuilder, DEFAULT_BUILDER_CONFIG, BuilderConfig } from './ifdsBuilder';
import { IfdsSolver } from './ifdsSolver';

export interface IfdsEngineOptions {
  config?: BuilderConfig;
  /** Called when a single file fails to build; default: console.error. */
  onFileError?: (path: string, err: Error) => void;
}

export class IfdsEngine {
  private readonly config: BuilderConfig;
  private readonly onFileError: (path: string, err: Error) => void;

  constructor(opts: IfdsEngineOptions = {}) {
    this.config = opts.config ?? DEFAULT_BUILDER_CONFIG;
    this.onFileError = opts.onFileError ?? ((path, err) => {
      console.error(`[SAST] IFDS builder skipped ${path}: ${err.message}`);
    });
  }

  public analyze(files: ScannedFile[]): Finding[] {
    const graph = new CodeGraph();
    const builder = new IfdsGraphBuilder(graph, this.config);
    for (const f of files) {
      if (!f.isDart || !f.astNode) { continue; }
      try {
        builder.addDartFile(f.relativePath, f.astNode);
      } catch (e) {
        this.onFileError(f.relativePath, e as Error);
      }
    }
    if (graph.procedures.size === 0) { return []; }

    const solver = new IfdsSolver(graph);
    let reach;
    try {
      reach = solver.solve();
    } catch (e) {
      console.error(`[SAST] IFDS solver failed: ${(e as Error).message}`);
      return [];
    }

    // Index reach by node id for fast lookup. Use locKey for fact identity so
    // the match against sink arg Locs is exact.
    const factsAt = new Map<number, Set<string>>();
    for (const r of reach) {
      if (r.fact.kind !== 'loc') { continue; }
      const key = locKey(r.fact.loc);
      let set = factsAt.get(r.node);
      if (!set) { set = new Set(); factsAt.set(r.node, set); }
      set.add(key);
    }

    const findings: Finding[] = [];
    const reported = new Set<string>();
    for (const [nodeId, stmt] of graph.statements.entries()) {
      if (stmt.kind !== 'sink') { continue; }
      const tainted = factsAt.get(nodeId);
      if (!tainted || tainted.size === 0) { continue; }
      const node = graph.nodes[nodeId];
      const filePath = graph.filePath(node.fileId);
      const line = stmt.line;
      for (const arg of stmt.args) {
        const k = locKey(arg);
        if (!tainted.has(k)) { continue; }
        const dedupKey = `${filePath}|${line}|${stmt.name}|${k}`;
        if (reported.has(dedupKey)) { continue; }
        reported.add(dedupKey);
        findings.push(new Finding({
          category: FindingCategory.security,
          code: 'ifds-taint',
          severity: FindingSeverity.high,
          confidence: FindingConfidence.high,
          detectionMethod: DetectionMethod.taint,
          filePath,
          line,
          message: `Tainted value flows into sink \`${stmt.name}\` (IFDS)`,
          fix: `Sanitize or parameterize the argument passed to \`${stmt.name}\` before invocation.`,
          astUsed: true,
        }));
        break;
      }
    }
    return findings;
  }
}
