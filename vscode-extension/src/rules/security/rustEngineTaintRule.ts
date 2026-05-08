import { Rule, RuleStage } from '../rule';
import { Finding } from '../../models/finding';
import { ProjectContext } from '../../scanner/projectContext';
import { resolveRustEngineRuntime } from '../../scanner/rustEngineConfig';
import { runRustEngine } from '../../scanner/rustEngine';

export class RustEngineTaintRule implements Rule {
  readonly code = 'rust-engine-taint';
  readonly stage = RuleStage.taint;

  async evaluate(context: ProjectContext): Promise<Finding[]> {
    const runtime = resolveRustEngineRuntime(context.rootPath);
    if (!runtime) {
      return [];
    }

    for (const warning of runtime.warnings) {
      console.error(`[SAST] ${warning}`);
    }

    const result = await runRustEngine({
      binaryPath: runtime.binaryPath,
      projectRoot: context.rootPath,
      ruleFiles: runtime.ruleFiles,
      timeoutMs: 30_000,
    });

    for (const warning of result.warnings) {
      console.error(`[SAST][engine-cli] ${warning}`);
    }

    return result.findings;
  }
}
