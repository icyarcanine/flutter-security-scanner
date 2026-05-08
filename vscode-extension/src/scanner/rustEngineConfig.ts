import * as fs from 'fs';
import * as path from 'path';
import { resolveEngineBinary } from './engineResolver';

export const BUILTIN_RUST_ENGINE_RULES = [
  'rules/dart-sql-injection.yaml',
  'rules/dart-command-injection.yaml',
];

export interface RustEngineRuntime {
  binaryPath: string;
  ruleFiles: string[];
  warnings: string[];
}

export function extensionRoot(): string {
  // Works in both source (`src/scanner`) and compiled (`out/scanner`) layouts.
  return path.resolve(__dirname, '..', '..');
}

export function resolveRustEngineRuntime(workspaceRoot: string): RustEngineRuntime | null {
  const root = extensionRoot();
  const resolution = resolveEngineBinary({ extensionPath: root, workspaceRoot });
  if (resolution.status !== 'found' || !resolution.path) {
    return null;
  }

  const warnings: string[] = [];
  const ruleFiles = BUILTIN_RUST_ENGINE_RULES
    .map(rel => path.join(root, rel))
    .filter(rulePath => {
      if (fs.existsSync(rulePath)) {
        return true;
      }
      warnings.push(`Rust engine rule file missing: ${rulePath}`);
      return false;
    });

  if (ruleFiles.length === 0) {
    return null;
  }

  return { binaryPath: resolution.path, ruleFiles, warnings };
}

export function rustEngineCanRun(workspaceRoot: string): boolean {
  return resolveRustEngineRuntime(workspaceRoot) != null;
}
