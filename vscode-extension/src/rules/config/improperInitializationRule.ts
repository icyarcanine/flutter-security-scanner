import { Rule, RuleStage } from '../rule';
import { Finding, FindingSeverity, FindingCategory, FindingConfidence, DetectionMethod } from '../../models/finding';
import { ProjectContext } from '../../scanner/projectContext';
import { firstReferenceFor } from '../ruleHelpers';

export class ImproperInitializationRule implements Rule {
  readonly code = 'improper-initialization';
  readonly stage = RuleStage.fast;

  evaluate(context: ProjectContext): Finding[] {
    if (!context.usesSupabaseFlutter || context.hasSupabaseInitialize) { return []; }

    const candidates = [
      ...context.appDartFiles,
      ...(context.pubspecFile ? [context.pubspecFile] : []),
    ];
    const reference = firstReferenceFor(context, 'supabase_flutter', candidates);

    return [new Finding({
      severity: FindingSeverity.medium,
      confidence: FindingConfidence.high,
      detectionMethod: DetectionMethod.structural,
      category: FindingCategory.config,
      code: this.code,
      message: 'supabase_flutter is used but Supabase.initialize(...) was not found',
      fix: 'Call `Supabase.initialize(...)` before `runApp()` so auth persistence and the shared client are configured once.',
      risk: 'Without proper initialization, auth state cannot be restored and the client may throw exceptions.',
      filePath: reference?.file.relativePath ?? context.pubspecFile?.relativePath,
      line: reference?.line,
    })];
  }
}
