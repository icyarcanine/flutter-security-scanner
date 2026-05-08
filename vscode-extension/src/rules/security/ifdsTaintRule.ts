import { Rule, RuleStage } from '../rule';
import { Finding } from '../../models/finding';
import { ProjectContext } from '../../scanner/projectContext';
import { IfdsEngine } from '../../taint/ifdsEngine';
import { rustEngineCanRun } from '../../scanner/rustEngineConfig';

/**
 * Stage 3 (taint) rule that runs the IFDS solver over all parsed Dart files.
 * Complementary to InjectionRule's simpler intra-file tracker — this one is
 * inter-procedural and context-sensitive via procedure summaries.
 */
export class IfdsTaintRule implements Rule {
  readonly code = 'ifds-taint';
  readonly stage = RuleStage.taint;

  async evaluate(context: ProjectContext): Promise<Finding[]> {
    if (rustEngineCanRun(context.rootPath)) {
      return [];
    }

    const dartFiles = context.files.filter(f => f.isDart);
    if (dartFiles.length === 0) { return []; }
    // Force AST parsing for every Dart file before handing to the engine.
    for (const f of dartFiles) {
      await context.getAst(f);
    }
    const withAst = dartFiles.filter(f => f.astNode);
    if (withAst.length === 0) { return []; }
    const engine = new IfdsEngine();
    return engine.analyze(withAst);
  }
}
