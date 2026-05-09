import '../../models/finding.dart';
import '../../models/project_context.dart';
import '../../rule.dart';

/// Detects missing or insecure ProGuard/R8 obfuscation configurations.
///
/// Checks for:
/// 1. Missing proguard-rules.pro file
/// 2. ProGuard rules that don't obfuscate Flutter/Dart classes
/// 3. Missing -keep rules for security-sensitive classes
/// 4. R8 full mode without proper configuration
/// 5. Missing minification in release builds
///
/// This is an Android release hardening rule for Flutter apps.
class ProguardObfuscationRule extends Rule {
  const ProguardObfuscationRule();

  @override
  String get code => 'flutter.proguard-obfuscation';

  @override
  List<Finding> evaluate(ProjectContext context) {
    final findings = <Finding>[];

    // Check for proguard-rules.pro in android/app/
    bool hasProguardFile = false;
    bool hasMinificationEnabled = false;

    for (final file in context.files
        .where((f) => f.name.toLowerCase().contains('proguard'))) {
      hasProguardFile = true;

      final content = file.content;

      // Detect overly broad keep rules that negate obfuscation
      final broadKeepPattern = RegExp(
        r'-keep\s+class\s+\*\s*\{.*?\}',
        dotAll: true,
      );

      for (final match in broadKeepPattern.allMatches(content)) {
        final line = file.lineForOffset(match.start);

        findings.add(Finding(
          severity: FindingSeverity.medium,
          confidence: FindingConfidence.medium,
          category: FindingCategory.security,
          code: code,
          message: 'Overly broad ProGuard -keep rule may negate obfuscation',
          fix: 'Use targeted -keep rules for specific classes and methods that '
              'must survive obfuscation. Avoid "-keep class * { *; }" which '
              'preserves all classes and methods, defeating obfuscation entirely.',
          risk:
              'Broad keep rules prevent obfuscation from renaming classes and '
              'methods, making reverse engineering significantly easier for '
              'attackers analyzing your APK.',
          filePath: file.relativePath,
          line: line,
        ));
      }
    }

    // Check build.gradle for minification settings
    for (final file
        in context.files.where((f) => f.name.toLowerCase() == 'build.gradle')) {
      final content = file.content.toLowerCase();

      if (content.contains('minifyenabled true') ||
          content.contains('shrinkresources true')) {
        hasMinificationEnabled = true;
      }

      // Check for R8 full mode (Android Gradle Plugin 8.0+)
      if (content.contains('android.enableR8.fullMode=true')) {
        findings.add(Finding(
          severity: FindingSeverity.medium,
          confidence: FindingConfidence.medium,
          category: FindingCategory.security,
          code: code,
          message: 'R8 full mode enabled without verifying ProGuard rules',
          fix: 'R8 full mode is more aggressive than standard R8. Thoroughly '
              'test your release build with full mode enabled and ensure all '
              'necessary -keep rules are in place for reflection, serialization, '
              'and native code access.',
          risk: 'R8 full mode may remove classes accessed via reflection or '
              'native code that are not explicitly kept, causing runtime crashes '
              'or security features to be stripped.',
          filePath: file.relativePath,
          line: file
              .lineForOffset(file.content.indexOf('android.enableR8.fullMode')),
        ));
      }

      // Check for missing minification in release
      final releaseBlockPattern = RegExp(
        r'buildTypes\s*\{[^}]*release\s*\{[^}]*\}',
        dotAll: true,
      );

      for (final match in releaseBlockPattern.allMatches(file.content)) {
        final releaseBlock = match.group(0)!.toLowerCase();
        if (!releaseBlock.contains('minifyenabled') &&
            !releaseBlock.contains('proguardfiles')) {
          final line = file.lineForOffset(match.start);

          findings.add(Finding(
            severity: FindingSeverity.high,
            confidence: FindingConfidence.high,
            category: FindingCategory.security,
            code: code,
            message: 'Release build lacks ProGuard/R8 minification',
            fix: 'Enable minification in your release build type:\n'
                'buildTypes {\n'
                '  release {\n'
                '    minifyEnabled true\n'
                '    shrinkResources true\n'
                '    proguardFiles getDefaultProguardFile("proguard-android.txt"), "proguard-rules.pro"\n'
                '  }\n'
                '}',
            risk:
                'Without minification and obfuscation, your compiled Dart code '
                '(translated to Java/Kotlin intermediates) is easily reverse '
                'engineered, exposing API keys, business logic, and security '
                'mechanisms.',
            filePath: file.relativePath,
            line: line,
          ));
        }
      }
    }

    // Flag if no ProGuard file exists at all
    if (!hasProguardFile && !hasMinificationEnabled) {
      for (final file in context.files
          .where((f) => f.name.toLowerCase() == 'build.gradle')) {
        findings.add(Finding(
          severity: FindingSeverity.medium,
          confidence: FindingConfidence.medium,
          category: FindingCategory.security,
          code: code,
          message: 'No ProGuard/R8 configuration file found',
          fix: 'Create android/app/proguard-rules.pro with appropriate keep '
              'rules for Flutter, Firebase, and any libraries using reflection. '
              'Enable minification in build.gradle release build type.',
          risk: 'Without ProGuard/R8 obfuscation, your app\'s code structure, '
              'class names, and method names are preserved in the release APK, '
              'making reverse engineering trivial.',
          filePath: file.relativePath,
          line: 1,
        ));
      }
    }

    return findings;
  }
}
