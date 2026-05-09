import '../../models/finding.dart';
import '../../models/project_context.dart';
import '../../rule.dart';
import '../rule_helpers.dart';

class ImproperInitializationRule extends Rule {
  const ImproperInitializationRule();

  @override
  String get code => 'improper-initialization';

  @override
  List<Finding> evaluate(ProjectContext context) {
    // Only flag if supabase_flutter is actually imported or used in Dart code,
    // not merely listed as a dependency in pubspec.yaml.
    final hasSupabaseImport = context.appDartFiles.any(
      (f) => RegExp(
        r'''package:supabase_flutter/supabase_flutter\.dart''',
      ).hasMatch(f.content),
    );
    final hasSupabaseUsage = context.usesSupabaseFlutter ||
        context.appDartFiles.any(
          (f) => RegExp(
            r'''\bSupabase\.(instance|initialize)\b|\bsupabase\.(from|storage|auth|rpc)\b|\.storage\.from\(|\.auth\.(currentUser|currentSession)\b''',
            caseSensitive: false,
          ).hasMatch(f.content),
        );
    if ((!hasSupabaseImport && !hasSupabaseUsage) ||
        context.hasSupabaseInitialize) {
      return const [];
    }

    final reference = firstReferenceFor(
      context,
      'supabase_flutter',
      files: [
        ...context.appDartFiles,
        if (context.pubspecFile != null) context.pubspecFile!,
      ],
    );
    return [
      Finding(
        severity: FindingSeverity.medium,
        confidence: FindingConfidence.high,
        category: FindingCategory.config,
        code: code,
        message:
            'supabase_flutter is used but Supabase.initialize(...) was not found',
        fix:
            'Call `Supabase.initialize(...)` before `runApp()` so auth persistence and the shared client are configured once.',
        risk:
            'Without proper initialization, auth state cannot be restored and the client may throw exceptions.',
        filePath:
            reference?.file.relativePath ?? context.pubspecFile?.relativePath,
        line: reference?.line,
      ),
    ];
  }
}
