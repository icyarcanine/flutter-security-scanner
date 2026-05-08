import { spawn } from 'child_process';
import * as path from 'path';
import { Finding, FindingSeverity } from '../models/finding';

export interface RustEngineOptions {
  binaryPath: string;
  projectRoot: string;
  ruleFiles: string[];
  timeoutMs?: number;
}

export interface RustEngineResult {
  findings: Finding[];
  durationMs: number;
  warnings: string[];
}

interface RawRustFinding {
  file: string;
  line: number;
  col: number;
  rule_id: string;
  severity: string;
  message: string;
}

interface RunResult {
  findings: Finding[];
  warnings: string[];
}

export async function runRustEngine(opts: RustEngineOptions): Promise<RustEngineResult> {
  const findings: Finding[] = [];
  const warnings: string[] = [];
  const start = Date.now();
  const timeoutMs = opts.timeoutMs ?? 30_000;

  for (const ruleFile of opts.ruleFiles) {
    const result = await runOne(opts.binaryPath, opts.projectRoot, ruleFile, timeoutMs);
    findings.push(...result.findings);
    warnings.push(...result.warnings);
  }

  return { findings, durationMs: Date.now() - start, warnings };
}

function runOne(
  binaryPath: string,
  projectRoot: string,
  ruleFile: string,
  timeoutMs: number,
): Promise<RunResult> {
  return new Promise((resolve, reject) => {
    const proc = spawn(binaryPath, [projectRoot, '--rules', ruleFile, '--format', 'json'], {
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    let settled = false;

    const timer = setTimeout(() => {
      settled = true;
      proc.kill('SIGKILL');
      reject(new Error(`engine-cli timeout after ${timeoutMs}ms on rule ${ruleFile}`));
    }, timeoutMs);

    proc.stdout.on('data', data => { stdout += data.toString(); });
    proc.stderr.on('data', data => { stderr += data.toString(); });
    proc.on('error', err => {
      if (settled) { return; }
      settled = true;
      clearTimeout(timer);
      reject(err);
    });
    proc.on('close', code => {
      if (settled) { return; }
      settled = true;
      clearTimeout(timer);
      if (code !== 0) {
        reject(new Error(`engine-cli exited ${code}: ${stderr.trim()}`));
        return;
      }

      try {
        const raw = JSON.parse(stdout) as RawRustFinding[];
        const warnings = stderr
          .split('\n')
          .map(line => line.trim())
          .filter(line => line.length > 0 && /\b(?:warn|warning|error)\b/i.test(line));
        const findings = raw.map(item => Finding.fromRustEngine({
          filePath: toProjectRelativePath(projectRoot, item.file),
          line: item.line,
          column: item.col,
          ruleCode: item.rule_id,
          message: item.message,
          severity: mapSeverity(item.severity),
        }));
        resolve({ findings, warnings });
      } catch (err) {
        reject(new Error(
          `engine-cli output parse failed: ${(err as Error).message}\nstdout: ${stdout.slice(0, 500)}`,
        ));
      }
    });
  });
}

function mapSeverity(severity: string): FindingSeverity {
  switch (severity.toUpperCase()) {
    case 'ERROR':
    case 'CRITICAL':
    case 'HIGH':
      return FindingSeverity.high;
    case 'WARNING':
    case 'MEDIUM':
      return FindingSeverity.medium;
    default:
      return FindingSeverity.low;
  }
}

function toProjectRelativePath(projectRoot: string, filePath: string): string {
  const relative = path.relative(projectRoot, filePath);
  if (relative.length === 0 || relative.startsWith('..') || path.isAbsolute(relative)) {
    return filePath;
  }
  return relative.split(path.sep).join('/');
}
